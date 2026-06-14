"""
Headless byte-run comparison engine — s19_app batch-09, increment I1 (HLR-001).

This module is the **pure-data core** of the image comparison mode (US-006):
the canonical result vocabulary (:class:`ImageRef`, :class:`DiffRun`,
:class:`DiffStats`, :class:`ComparisonResult` — the §6.2 C-9 field set) and the
diff function :func:`diff_mem_maps`, which classifies two sparse memory maps
(``Dict[int, int]``) into maximal contiguous difference runs.

A run is a half-open address span ``[start, end)`` whose every address shares
one classification (LLR-001.2):

- ``changed`` — mapped in both A and B, bytes differ;
- ``only_a`` — mapped in A only;
- ``only_b`` — mapped in B only.

Addresses mapped in both with equal bytes produce no run. Runs are emitted in
ascending-start order; two adjacent addresses share a run iff they have the
same classification, so a classification change always forces a boundary
(LLR-001.2 adjacency rule).

The diff is a single ascending walk over the sorted union of both maps' keys
(the measured-fine approach, probe P-15) — ``range_index`` is the binary-search
membership primitive for range-level summarization elsewhere, not needed for
this byte-level walk.

This module imports stdlib only: no Textual, no parser class — it consumes
already-built memory maps (LLR-001.1). The comparison service
(``tui/services/compare_service.py``, increment I2) is the producer of every
field except ``runs``/``stats`` and the loader of the maps this engine
compares.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

#: Classification token — address mapped in both maps, bytes differ.
KIND_CHANGED = "changed"

#: Classification token — address mapped in map A only.
KIND_ONLY_A = "only_a"

#: Classification token — address mapped in map B only.
KIND_ONLY_B = "only_b"

#: The full classification domain in its canonical order. Every
#: :attr:`DiffStats.run_counts` / :attr:`DiffStats.byte_counts` dict carries
#: exactly these keys, all present even when zero, so consumer tables never
#: branch on a missing key (the ``DISPOSITION_DOMAIN`` precedent,
#: ``changes/model.py:292``).
DIFF_KIND_DOMAIN = (KIND_CHANGED, KIND_ONLY_A, KIND_ONLY_B)


@dataclass(slots=True)
class ImageRef:
    """
    Summary:
        Identity of one compared image — the §6.2 C-9 image-reference field
        produced by the comparison service (increment I2), defined here as the
        dataclass home of the comparison result vocabulary.

    Args:
        label (str): Operator-facing display name for the image.
        path (Optional[str]): The resolved on-disk path the image was parsed
            from; ``None`` only when no path applies.
        source_kind (str): How the image entered the comparison —
            ``"project-variant"`` for an in-project variant, ``"external"``
            for an operator-typed path.
        variant_id (Optional[str]): The project variant identifier when
            ``source_kind`` is ``"project-variant"``; ``None`` for an external
            image.
        parse_error_count (int): Number of per-line/per-file parse errors the
            loader collected for this image; ``0`` for a clean parse.

    Returns:
        None: Dataclass container.

    Data Flow:
        - Built by ``compare_service`` (increment I2) from a
          ``VariantDescriptor`` or a resolved external path; consumed by the
          diff report header (LLR-004.3) and the TUI header/status
          (LLR-005.2).

    Dependencies:
        Used by:
            - ComparisonResult
            - tui.services.compare_service (increment I2)
    """

    label: str
    path: Optional[str]
    source_kind: str
    variant_id: Optional[str] = None
    parse_error_count: int = 0


@dataclass(slots=True)
class DiffRun:
    """
    Summary:
        One maximal contiguous difference run — the §6.2 C-9 run element
        produced by :func:`diff_mem_maps` (LLR-001.2).

    Args:
        start (int): Inclusive start address of the run.
        end (int): Exclusive end address of the run; ``end - start`` is the
            run length in bytes (always ``>= 1``).
        kind (str): One token of :data:`DIFF_KIND_DOMAIN` — every address in
            ``[start, end)`` shares this classification.

    Returns:
        None: Dataclass container.

    Data Flow:
        - Emitted by :func:`diff_mem_maps` in ascending ``start`` order; two
          adjacent addresses of the same ``kind`` are merged into one run, a
          ``kind`` change forces a boundary (LLR-001.2).
        - Consumed by the report run table + hex windows (LLR-004.3) and the
          TUI run list (LLR-005.2).

    Dependencies:
        Used by:
            - ComparisonResult
            - diff_mem_maps

    Example:
        >>> DiffRun(0x100, 0x104, KIND_CHANGED).length
        4
    """

    start: int
    end: int
    kind: str

    @property
    def length(self) -> int:
        """
        Summary:
            Return this run's byte length — ``end - start`` (LLR-001.4).

        Returns:
            int: The number of addresses the run covers, always ``>= 1``.
        """
        return self.end - self.start


@dataclass(slots=True)
class DiffStats:
    """
    Summary:
        Per-classification run and byte counts for one comparison — the §6.2
        C-9 statistics field produced by :func:`diff_mem_maps` (LLR-001.4).

    Args:
        run_counts (dict[str, int]): Number of runs of each
            :data:`DIFF_KIND_DOMAIN` kind — all three keys always present,
            even when zero.
        byte_counts (dict[str, int]): Total byte length of all runs of each
            kind — all three keys always present. By construction
            ``byte_counts[kind]`` equals the sum of ``run.length`` over every
            run of that kind (LLR-001.4).

    Returns:
        None: Dataclass container.

    Data Flow:
        - Built by :func:`diff_mem_maps` alongside the run list; consumed by
          the report stats table (LLR-004.3) and the TUI summary (LLR-005.2).

    Dependencies:
        Used by:
            - ComparisonResult
            - diff_mem_maps
    """

    run_counts: Dict[str, int]
    byte_counts: Dict[str, int]


@dataclass(slots=True)
class ComparisonResult:
    """
    Summary:
        The §6.2 C-9 canonical comparison-result contract: the two image
        references, the classified runs, the statistics, the per-image
        artifact-usage notes, the diagnostics, and the refused flag. The
        engine (this module) produces ``runs`` and ``stats``; the comparison
        service (increment I2) produces every other field and assembles the
        whole object.

    Args:
        image_a (ImageRef): Identity of image A.
        image_b (ImageRef): Identity of image B.
        runs (list[DiffRun]): The classified difference runs in ascending
            start order — produced by :func:`diff_mem_maps`.
        stats (DiffStats): Per-classification run/byte counts — produced by
            :func:`diff_mem_maps`.
        notes (dict): Per-image artifact-usage notes (HLR-003) — produced by
            the service (increment I2); empty by default at engine level.
        diagnostics (list[str]): Human-readable diagnostics; non-empty for a
            refused comparison — produced by the service (increments I2..).
        refused (bool): ``True`` when the comparison could not be assembled
            (unresolvable path, parse failure, fewer than two valid images);
            a refused result carries no runs — set by the service.

    Returns:
        None: Dataclass container.

    Data Flow:
        - The engine builds ``runs``/``stats`` via :func:`diff_mem_maps`; the
          service (I2) fills ``image_a``/``image_b``/``notes``/``diagnostics``
          /``refused`` and returns the complete object to the TUI and report
          layers.

    Dependencies:
        Uses:
            - ImageRef / DiffRun / DiffStats
        Used by:
            - tui.services.compare_service (increment I2)
            - tui.services.diff_report_service (increment I3)
    """

    image_a: ImageRef
    image_b: ImageRef
    runs: List[DiffRun]
    stats: DiffStats
    notes: dict = field(default_factory=dict)
    diagnostics: List[str] = field(default_factory=list)
    refused: bool = False


def _classify_address(
    addr: int, map_a: Dict[int, int], map_b: Dict[int, int]
) -> Optional[str]:
    """
    Summary:
        Classify one address against both maps, returning its
        :data:`DIFF_KIND_DOMAIN` token or ``None`` when it produces no run
        (mapped in both with equal bytes) — the per-address primitive the
        run-merging walk and the brute-force test oracle both rely on.

    Args:
        addr (int): The address to classify.
        map_a (dict[int, int]): Memory map A.
        map_b (dict[int, int]): Memory map B.

    Returns:
        Optional[str]: ``KIND_CHANGED`` / ``KIND_ONLY_A`` / ``KIND_ONLY_B``,
        or ``None`` when ``addr`` is mapped in both with equal bytes (LLR-001.2
        "no equal-byte address lies in any run").

    Data Flow:
        - Tests membership in A and B; on dual membership compares the bytes.

    Dependencies:
        Used by:
            - diff_mem_maps
    """
    in_a = addr in map_a
    in_b = addr in map_b
    if in_a and in_b:
        if map_a[addr] != map_b[addr]:
            return KIND_CHANGED
        return None
    if in_a:
        return KIND_ONLY_A
    return KIND_ONLY_B


def diff_mem_maps(
    map_a: Dict[int, int], map_b: Dict[int, int]
) -> tuple[List[DiffRun], DiffStats]:
    """
    Summary:
        Compute the complete, deterministic set of maximal contiguous
        difference runs between two sparse memory maps, with per-classification
        statistics (HLR-001 / LLR-001.2 / LLR-001.3 / LLR-001.4).

    Args:
        map_a (dict[int, int]): Memory map A (address → byte 0-255).
        map_b (dict[int, int]): Memory map B (address → byte 0-255).

    Returns:
        tuple[list[DiffRun], DiffStats]: The runs in ascending start order
        (two adjacent addresses share a run iff same classification; equal-byte
        addresses produce no run) and the per-kind run/byte counts. Identical
        maps (including two empty maps) yield an empty run list and all-zero
        stats.

    Data Flow:
        - Walk the sorted union of both maps' keys once.
        - Classify each key; extend the open run when the address is contiguous
          with the same kind, else close it and open a new one.
        - Accumulate per-kind run and byte counts as runs close.

    Dependencies:
        Uses:
            - _classify_address
            - DiffRun / DiffStats
        Used by:
            - tui.services.compare_service (increment I2)

    Example:
        >>> runs, stats = diff_mem_maps({0: 1}, {0: 2})
        >>> runs
        [DiffRun(start=0, end=1, kind='changed')]
        >>> stats.byte_counts['changed']
        1
    """
    run_counts: Dict[str, int] = {kind: 0 for kind in DIFF_KIND_DOMAIN}
    byte_counts: Dict[str, int] = {kind: 0 for kind in DIFF_KIND_DOMAIN}
    runs: List[DiffRun] = []

    sorted_addresses = sorted(map_a.keys() | map_b.keys())

    open_start: Optional[int] = None
    open_kind: Optional[str] = None
    open_prev: int = 0

    def close_run() -> None:
        if open_kind is None or open_start is None:
            return
        end = open_prev + 1
        runs.append(DiffRun(open_start, end, open_kind))
        run_counts[open_kind] += 1
        byte_counts[open_kind] += end - open_start

    for addr in sorted_addresses:
        kind = _classify_address(addr, map_a, map_b)
        if kind is None:
            close_run()
            open_start = None
            open_kind = None
            continue
        if (
            open_kind == kind
            and open_start is not None
            and addr == open_prev + 1
        ):
            open_prev = addr
            continue
        close_run()
        open_start = addr
        open_kind = kind
        open_prev = addr

    close_run()

    stats = DiffStats(run_counts=run_counts, byte_counts=byte_counts)
    return runs, stats
