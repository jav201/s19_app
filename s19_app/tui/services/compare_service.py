"""
Headless comparison service — s19_app batch-09, increment I2 (HLR-002 / HLR-003).

This module is the **service seam** of the image comparison mode (US-006): it
resolves two comparison sources — an in-project variant (by id, via
``ProjectVariantSet``) and/or an external file path (via ``resolve_input_path``)
— parses each image fresh through the headless ``load_service`` loaders, calls
the I1 engine :func:`s19_app.compare.diff_mem_maps` to classify the byte runs,
computes per-image artifact-usage notes against the project's at-most-one A2L
and at-most-one MAC, and assembles the §6.2 C-9 :class:`ComparisonResult`.

It never reuses the TUI's current ``LoadedFile`` snapshot (it parses fresh,
mirroring ``variant_execution_service._execute_one_variant``) and never raises
for an unresolvable path or a failed parse: every per-source failure is captured
as a diagnostic on a refused result (LLR-002.3 / LLR-002.5, the LLR-006.4
isolation boundary precedent).

This module imports no Textual symbol (LLR-002.1) — it sits in the service
layer beside ``load_service`` / ``variant_execution_service`` / ``report_service``
and is consumed by ``app.py`` only (increment I4). The engine is injected
(default :func:`s19_app.compare.diff_mem_maps`) so callers and tests can
substitute it.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from ...compare import (
    ComparisonResult,
    DiffRun,
    DiffStats,
    ImageRef,
    diff_mem_maps,
)
from ...core import S19File
from ...hexfile import IntelHexFile
from ...range_index import address_in_sorted_ranges, build_sorted_range_index
from ..models import LoadedFile, ProjectVariantSet
from .a2l_service import enrich_tags_and_render
from .load_service import build_loaded_hex, build_loaded_s19

#: Image-source discriminators (mirrors ``ImageRef.source_kind``, ``compare.py``).
SOURCE_PROJECT_VARIANT = "project-variant"
SOURCE_EXTERNAL = "external"

#: Per-artifact coverage statuses (D-3 mechanical semantics).
ARTIFACT_USED = "used"
ARTIFACT_UNUSED = "unused"
ARTIFACT_ABSENT = "absent"

#: Per-image usage summary tokens (LLR-003.3).
SUMMARY_BOTH = "both"
SUMMARY_ONE_A2L = "one (a2l)"
SUMMARY_ONE_MAC = "one (mac)"
SUMMARY_NONE = "none"

#: Type of the injectable diff engine (the I1 ``diff_mem_maps`` signature).
DiffEngine = Callable[
    [Dict[int, int], Dict[int, int]], Tuple[List[DiffRun], DiffStats]
]


@dataclass(slots=True)
class ImageSource:
    """
    Summary:
        One requested comparison source — either an in-project variant
        (resolved by id through ``ProjectVariantSet``) or an external file
        path (resolved through ``resolve_input_path``) — the service's input
        for one side of the comparison (LLR-002.2 / LLR-002.3 / LLR-002.4).

    Args:
        kind (str): :data:`SOURCE_PROJECT_VARIANT` or :data:`SOURCE_EXTERNAL`.
        variant_id (Optional[str]): The project ``variant_id`` when ``kind`` is
            :data:`SOURCE_PROJECT_VARIANT`; ``None`` for an external source.
        raw_path (Optional[str]): The operator-typed path when ``kind`` is
            :data:`SOURCE_EXTERNAL`; ``None`` for a project variant.
        label (Optional[str]): Optional operator-facing display name; defaults
            to the variant id or the path basename when omitted.

    Returns:
        None: Dataclass container.

    Data Flow:
        - Built by the TUI (increment I4) from the inline selection surface;
          consumed by :func:`compare_images`.

    Dependencies:
        Used by:
            - compare_images
    """

    kind: str
    variant_id: Optional[str] = None
    raw_path: Optional[str] = None
    label: Optional[str] = None


@dataclass(slots=True)
class ArtifactNote:
    """
    Summary:
        One image's coverage note against one artifact (A2L or MAC) — the
        per-artifact element of the §6.2 C-9 ``notes`` field (HLR-003 / D-3).

    Args:
        status (str): :data:`ARTIFACT_USED` (coverage >= 1), :data:`ARTIFACT_UNUSED`
            (artifact present, coverage 0), or :data:`ARTIFACT_ABSENT` (no such
            artifact in the project / no project).
        covered (int): Count of artifact addresses falling inside the image's
            mapped ranges (LLR-003.2); ``0`` when the artifact is absent.
        total (int): Count of artifact records carrying an integer address;
            ``0`` when the artifact is absent.

    Returns:
        None: Dataclass container.

    Dependencies:
        Used by:
            - ArtifactUsage
    """

    status: str
    covered: int = 0
    total: int = 0


@dataclass(slots=True)
class ArtifactUsage:
    """
    Summary:
        One compared image's full artifact-usage note — its A2L note, its MAC
        note, and the derived ``both``/``one (a2l)``/``one (mac)``/``none``
        summary (HLR-003 / LLR-003.3). One of these objects is stored per image
        in :attr:`ComparisonResult.notes`.

    Args:
        a2l (ArtifactNote): The image's coverage note against the project A2L.
        mac (ArtifactNote): The image's coverage note against the project MAC.
        summary (str): One of :data:`SUMMARY_BOTH`, :data:`SUMMARY_ONE_A2L`,
            :data:`SUMMARY_ONE_MAC`, :data:`SUMMARY_NONE` (LLR-003.3).

    Returns:
        None: Dataclass container.

    Dependencies:
        Uses:
            - ArtifactNote
        Used by:
            - compare_images (stored on ComparisonResult.notes)
    """

    a2l: ArtifactNote
    mac: ArtifactNote
    summary: str


# Loader callables matching the load_service signatures, injected so tests can
# substitute a failing parser without touching disk (LLR-002.5).
S19Loader = Callable[[Path], LoadedFile]
HexLoader = Callable[[Path], LoadedFile]


def _default_load_s19(path: Path) -> LoadedFile:
    """Parse an S19 image fresh into a ``LoadedFile`` (the LLR-002.2 loader)."""
    return build_loaded_s19(path, S19File(str(path)), None, None)


def _default_load_hex(path: Path) -> LoadedFile:
    """Parse an Intel HEX image fresh into a ``LoadedFile`` (the LLR-002.2 loader)."""
    return build_loaded_hex(path, IntelHexFile(str(path)), None, None)


def _resolve_source(
    source: ImageSource,
    *,
    variant_set: Optional[ProjectVariantSet],
    base_dir: Path,
    resolver: Callable[[Path, Path], Optional[Path]],
) -> Tuple[Optional[Path], str, Optional[str], Optional[str], List[str]]:
    """
    Summary:
        Resolve one :class:`ImageSource` to an on-disk path plus the image's
        identity metadata, returning a diagnostic instead of raising when the
        source cannot be resolved (LLR-002.2 / LLR-002.3 / LLR-002.4).

    Args:
        source (ImageSource): The requested source.
        variant_set (Optional[ProjectVariantSet]): The active project's variant
            inventory; required to resolve a :data:`SOURCE_PROJECT_VARIANT`.
        base_dir (Path): Base directory passed to the external-path resolver.
        resolver (Callable[[Path, Path], Optional[Path]]): The external-path
            resolver (``resolve_input_path``), injected for testability.

    Returns:
        Tuple[Optional[Path], str, Optional[str], Optional[str], List[str]]:
        ``(path, file_type, variant_id, label, diagnostics)``. ``path`` is
        ``None`` when resolution failed, and ``diagnostics`` then carries the
        reason naming the offending input.

    Data Flow:
        - Project variant: look the id up in ``variant_set.variants``; carry its
          ``file_type`` and ``path``.
        - External: ``resolver(Path(raw_path), base_dir)``; ``None`` -> refusal
          diagnostic naming the raw input; suffix decides ``file_type``.

    Dependencies:
        Uses:
            - resolve_input_path (injected)
        Used by:
            - compare_images
    """
    if source.kind == SOURCE_PROJECT_VARIANT:
        if variant_set is None:
            return None, "", None, None, [
                f"No active project: cannot resolve variant {source.variant_id!r}."
            ]
        for variant in variant_set.variants:
            if variant.variant_id == source.variant_id:
                label = source.label or variant.variant_id
                return variant.path, variant.file_type, variant.variant_id, label, []
        return None, "", None, None, [
            f"Unknown project variant {source.variant_id!r}."
        ]

    if source.kind == SOURCE_EXTERNAL:
        raw = source.raw_path or ""
        resolved = resolver(Path(raw), base_dir) if raw else None
        if resolved is None:
            return None, "", None, None, [
                f"Could not resolve external image path: {raw}"
            ]
        file_type = "hex" if resolved.suffix.lower() in (".hex", ".ihex") else "s19"
        label = source.label or resolved.name
        return resolved, file_type, None, label, []

    return None, "", None, None, [f"Unknown image source kind {source.kind!r}."]


def _load_image(
    path: Path,
    file_type: str,
    *,
    load_s19: S19Loader,
    load_hex: HexLoader,
) -> LoadedFile:
    """
    Summary:
        Parse one resolved image fresh through the injected loaders,
        discriminated by ``file_type`` (LLR-002.2). Raised exceptions propagate
        to :func:`compare_images`, which converts them to a refused result
        (LLR-002.5).

    Args:
        path (Path): Resolved image path.
        file_type (str): ``"s19"`` or ``"hex"``.
        load_s19 (S19Loader): S19 loader (default :func:`_default_load_s19`).
        load_hex (HexLoader): HEX loader (default :func:`_default_load_hex`).

    Returns:
        LoadedFile: The fresh snapshot whose ``mem_map`` / ``ranges`` the
        comparison consumes.

    Dependencies:
        Used by:
            - compare_images
    """
    if file_type == "hex":
        return load_hex(path)
    return load_s19(path)


def _coverage_count(
    addresses: Sequence[int], ranges: List[Tuple[int, int]]
) -> int:
    """
    Summary:
        Count how many of ``addresses`` fall inside ``ranges`` using the
        binary-search membership primitive, never a linear scan (LLR-003.2).

    Args:
        addresses (Sequence[int]): Integer artifact addresses.
        ranges (List[Tuple[int, int]]): The image's contiguous mapped ranges.

    Returns:
        int: Number of addresses contained by some range.

    Dependencies:
        Uses:
            - build_sorted_range_index / address_in_sorted_ranges
        Used by:
            - _artifact_note
    """
    index = build_sorted_range_index(ranges)
    return sum(1 for addr in addresses if address_in_sorted_ranges(addr, index))


def _a2l_addresses(a2l_data: Optional[dict], mem_map: Dict[int, int]) -> List[int]:
    """Integer addresses of the enriched A2L tags (``tag['address']``, a2l.py:984)."""
    if not a2l_data:
        return []
    tags, _ = enrich_tags_and_render(a2l_data, mem_map)
    return [
        tag["address"]
        for tag in tags
        if isinstance(tag.get("address"), int)
    ]


def _mac_addresses(mac_records: Optional[Sequence[dict]]) -> List[int]:
    """Integer addresses of the MAC records (``record['address']``, mac.py:91)."""
    if not mac_records:
        return []
    return [
        record["address"]
        for record in mac_records
        if isinstance(record.get("address"), int)
    ]


def _artifact_note(
    present: bool, addresses: Sequence[int], ranges: List[Tuple[int, int]]
) -> ArtifactNote:
    """
    Summary:
        Build one image's :class:`ArtifactNote` for one artifact: ``absent``
        when the artifact is not present, else the coverage count and a
        ``used``/``unused`` status by the coverage >= 1 rule (D-3 / LLR-003.2).

    Args:
        present (bool): Whether the project supplies this artifact.
        addresses (Sequence[int]): The artifact's integer addresses.
        ranges (List[Tuple[int, int]]): The image's mapped ranges.

    Returns:
        ArtifactNote: The per-artifact note.

    Dependencies:
        Uses:
            - _coverage_count
        Used by:
            - _build_usage
    """
    if not present:
        return ArtifactNote(status=ARTIFACT_ABSENT, covered=0, total=0)
    total = len(addresses)
    covered = _coverage_count(addresses, ranges)
    status = ARTIFACT_USED if covered >= 1 else ARTIFACT_UNUSED
    return ArtifactNote(status=status, covered=covered, total=total)


def _summarize(a2l: ArtifactNote, mac: ArtifactNote) -> str:
    """
    Summary:
        Derive a per-image usage summary from its two artifact notes by the
        coverage >= 1 rule: ``both`` / ``one (a2l)`` / ``one (mac)`` / ``none``
        (LLR-003.3).

    Args:
        a2l (ArtifactNote): The image's A2L note.
        mac (ArtifactNote): The image's MAC note.

    Returns:
        str: One of the :data:`SUMMARY_BOTH` / :data:`SUMMARY_ONE_A2L` /
        :data:`SUMMARY_ONE_MAC` / :data:`SUMMARY_NONE` tokens.

    Dependencies:
        Used by:
            - _build_usage
    """
    a2l_used = a2l.status == ARTIFACT_USED
    mac_used = mac.status == ARTIFACT_USED
    if a2l_used and mac_used:
        return SUMMARY_BOTH
    if a2l_used:
        return SUMMARY_ONE_A2L
    if mac_used:
        return SUMMARY_ONE_MAC
    return SUMMARY_NONE


def _build_usage(
    ranges: List[Tuple[int, int]],
    *,
    a2l_present: bool,
    a2l_addresses: Sequence[int],
    mac_present: bool,
    mac_addresses: Sequence[int],
) -> ArtifactUsage:
    """
    Summary:
        Assemble one image's full :class:`ArtifactUsage` (both artifact notes +
        the derived summary) against the shared artifact context (HLR-003).

    Args:
        ranges (List[Tuple[int, int]]): The image's mapped ranges.
        a2l_present (bool): Whether the project supplies an A2L.
        a2l_addresses (Sequence[int]): A2L tag addresses.
        mac_present (bool): Whether the project supplies a MAC.
        mac_addresses (Sequence[int]): MAC record addresses.

    Returns:
        ArtifactUsage: The image's usage note.

    Dependencies:
        Uses:
            - _artifact_note / _summarize
        Used by:
            - compare_images
    """
    a2l_note = _artifact_note(a2l_present, a2l_addresses, ranges)
    mac_note = _artifact_note(mac_present, mac_addresses, ranges)
    return ArtifactUsage(a2l=a2l_note, mac=mac_note, summary=_summarize(a2l_note, mac_note))


def _refused(diagnostics: List[str]) -> ComparisonResult:
    """
    Summary:
        Build a refused :class:`ComparisonResult` carrying ``diagnostics`` and
        no runs — the LLR-002.3 / LLR-002.5 refusal shape.

    Args:
        diagnostics (List[str]): The reasons the comparison was refused.

    Returns:
        ComparisonResult: ``refused=True`` with empty runs and zero stats.

    Dependencies:
        Used by:
            - compare_images
    """
    empty_stats = DiffStats(
        run_counts={"changed": 0, "only_a": 0, "only_b": 0},
        byte_counts={"changed": 0, "only_a": 0, "only_b": 0},
    )
    placeholder = ImageRef(label="", path=None, source_kind="")
    return ComparisonResult(
        image_a=placeholder,
        image_b=placeholder,
        runs=[],
        stats=empty_stats,
        notes={},
        diagnostics=list(diagnostics),
        refused=True,
    )


def compare_images(
    source_a: ImageSource,
    source_b: ImageSource,
    *,
    variant_set: Optional[ProjectVariantSet] = None,
    base_dir: Optional[Path] = None,
    a2l_data: Optional[dict] = None,
    mac_records: Optional[Sequence[dict]] = None,
    a2l_present: Optional[bool] = None,
    mac_present: Optional[bool] = None,
    engine: DiffEngine = diff_mem_maps,
    resolver: Callable[[Path, Path], Optional[Path]] = None,  # type: ignore[assignment]
    load_s19: S19Loader = _default_load_s19,
    load_hex: HexLoader = _default_load_hex,
) -> ComparisonResult:
    """
    Summary:
        Resolve and parse two comparison sources fresh, classify their byte
        runs through the injected engine, compute per-image artifact-usage
        notes against the shared A2L/MAC context, and assemble the §6.2 C-9
        :class:`ComparisonResult` (HLR-002 / HLR-003). Never reuses the TUI
        snapshot and never raises for an unresolvable path or a failed parse —
        every failure becomes a refused result (LLR-002.3 / LLR-002.5).

    Args:
        source_a (ImageSource): Requested source for image A.
        source_b (ImageSource): Requested source for image B.
        variant_set (Optional[ProjectVariantSet]): Active project's variant
            inventory; required to resolve project-variant sources.
        base_dir (Optional[Path]): Base directory for external-path resolution;
            defaults to ``Path.cwd()`` (the read-side ``resolve_input_path``
            convention, workspace.py:469-483).
        a2l_data (Optional[dict]): Parsed project A2L payload (the shared
            context, applied to every image — LLR-003.1), or ``None``.
        mac_records (Optional[Sequence[dict]]): Parsed project MAC records, or
            ``None``.
        a2l_present (Optional[bool]): Whether the project supplies an A2L;
            defaults to ``a2l_data is not None`` (LLR-003.4 absent handling).
        mac_present (Optional[bool]): Whether the project supplies a MAC;
            defaults to ``mac_records is not None``.
        engine (DiffEngine): The diff engine; defaults to
            :func:`s19_app.compare.diff_mem_maps`.
        resolver (Callable[[Path, Path], Optional[Path]]): External-path
            resolver; defaults to ``resolve_input_path`` (workspace.py:469).
        load_s19 (S19Loader): S19 loader; defaults to :func:`_default_load_s19`.
        load_hex (HexLoader): HEX loader; defaults to :func:`_default_load_hex`.

    Returns:
        ComparisonResult: The complete C-9 object on success (``refused=False``),
        or a refused result carrying diagnostics when either source cannot be
        resolved or parsed.

    Data Flow:
        - Resolve each source (:func:`_resolve_source`); any unresolved source
          short-circuits to a refused result naming the input (LLR-002.3).
        - Parse each resolved image fresh (:func:`_load_image`) inside a single
          try/except; any parse exception short-circuits to a refused result
          carrying the exception text (LLR-002.5).
        - Diff the two memory maps via ``engine`` (LLR-001.2 output).
        - Compute per-image artifact-usage notes (:func:`_build_usage`) against
          the shared A2L tag / MAC record addresses (LLR-003.x).
        - Assemble the C-9 :class:`ComparisonResult`.

    Dependencies:
        Uses:
            - _resolve_source / _load_image / _build_usage
            - diff_mem_maps (injected as ``engine``)
            - _a2l_addresses / _mac_addresses
        Used by:
            - s19_app.tui.app.S19TuiApp (increment I4)

    Example:
        >>> # see tests/test_compare_service.py for executable usage
    """
    if resolver is None:
        from ..workspace import resolve_input_path

        resolver = resolve_input_path
    if base_dir is None:
        base_dir = Path.cwd()
    if a2l_present is None:
        a2l_present = a2l_data is not None
    if mac_present is None:
        mac_present = mac_records is not None

    path_a, type_a, vid_a, label_a, diag_a = _resolve_source(
        source_a, variant_set=variant_set, base_dir=base_dir, resolver=resolver
    )
    path_b, type_b, vid_b, label_b, diag_b = _resolve_source(
        source_b, variant_set=variant_set, base_dir=base_dir, resolver=resolver
    )
    resolution_diagnostics = diag_a + diag_b
    if path_a is None or path_b is None:
        return _refused(resolution_diagnostics)

    try:
        loaded_a = _load_image(path_a, type_a, load_s19=load_s19, load_hex=load_hex)
        loaded_b = _load_image(path_b, type_b, load_s19=load_s19, load_hex=load_hex)
    except Exception as exc:  # noqa: BLE001 — LLR-002.5 isolation boundary
        return _refused([f"{type(exc).__name__}: {exc}"])

    runs, stats = engine(loaded_a.mem_map, loaded_b.mem_map)

    mac_addrs = _mac_addresses(mac_records)
    usage_a = _build_usage(
        loaded_a.ranges,
        a2l_present=a2l_present,
        a2l_addresses=_a2l_addresses(a2l_data, loaded_a.mem_map),
        mac_present=mac_present,
        mac_addresses=mac_addrs,
    )
    usage_b = _build_usage(
        loaded_b.ranges,
        a2l_present=a2l_present,
        a2l_addresses=_a2l_addresses(a2l_data, loaded_b.mem_map),
        mac_present=mac_present,
        mac_addresses=mac_addrs,
    )

    image_a = ImageRef(
        label=label_a or "",
        path=str(path_a),
        source_kind=source_a.kind,
        variant_id=vid_a,
        parse_error_count=len(loaded_a.errors),
    )
    image_b = ImageRef(
        label=label_b or "",
        path=str(path_b),
        source_kind=source_b.kind,
        variant_id=vid_b,
        parse_error_count=len(loaded_b.errors),
    )

    return ComparisonResult(
        image_a=image_a,
        image_b=image_b,
        runs=runs,
        stats=stats,
        notes={"image_a": usage_a, "image_b": usage_b},
        diagnostics=[],
        refused=False,
    )
