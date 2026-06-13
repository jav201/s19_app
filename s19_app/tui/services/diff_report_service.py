"""
Markdown diff-report generator — s19_app batch-09, increment I3 (HLR-004).

Headless service: :func:`generate_diff_report` writes one Markdown **diff
report** describing a completed image comparison — the §6.2 C-9
:class:`ComparisonResult` produced by ``compare_service`` (increment I2),
plus the two compared memory maps the engine diffed. The report contains, in
order (LLR-004.3): a header (both image identities and source kinds, the
artifact-usage notes, the generation UTC instant, the tool version), a
statistics table (per-classification run/byte counts), a run table (start,
end, length, classification, best-effort symbol annotation — LLR-004.4), and
per-run bounded hex windows of image A and image B rendered through the
plain-string ``hexview.render_hex_view``.

This module **reuses** the batch-07 report conventions as a PATTERN (D-5): it
imports ``REPORTS_DIR_NAME`` / ``REPORT_TIMESTAMP_FORMAT`` /
``REPORT_MAX_TOTAL_BYTES`` and ``compute_hexdump_windows`` from
``report_service`` and the plain ``render_hex_view`` from ``hexview``, but it
does **not** edit ``report_service`` at all. In particular it owns its own
listing scheme — :data:`DIFF_REPORT_FILENAME_REGEX` + :func:`list_diff_reports`
(LLR-004.2, G-4) — leaving the shared ``REPORT_FILENAME_REGEX`` and
``list_project_reports`` byte-for-byte untouched.

Destination resolution (LLR-004.6, G-5 + G-8 + M-4, security):

- While a project is active the report is written into
  ``<project_dir>/reports/`` inside the gitignored ``.s19tool/`` tree
  (LLR-004.1, unchanged).
- While no project is active the destination is ALWAYS an operator-supplied
  directory — there is **no** implicit ``Downloads`` (or other) default. The
  supplied path is normalized via ``Path(operator_input).expanduser()
  .resolve()`` (which collapses ``..`` segments and resolves symbolic
  components — escape-prevention is normalize-then-confirm, not a textual
  scan; a relative path resolves against the app cwd) and the resolved path
  is required to be an existing directory (``dest.is_dir()``). An empty,
  invalid, or non-existent-directory path is REFUSED: no file is written and
  a diagnostic naming the rejected input is returned, raising no exception.
  ``sanitize_project_name`` is deliberately NOT used — it is a single-token
  name cleaner, structurally incapable of validating a directory path (M-4).

Both branches apply the SAME no-silent-overwrite collision discipline in the
resolved directory (LLR-004.1 / M-5): a zero-padded ``-NN`` counter,
``FileExistsError`` after 99, never an overwrite. The filename is generated
wholly by this module from the UTC timestamp — no operator-supplied string
forms any component of the filename.

Confidentiality (F-S-07, LLR-004.5): diff reports carry raw memory bytes.
This module performs NO logging at all — so report body content can never
reach the rotating log — and its tests use synthetic in-memory fixtures /
public example data exclusively.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from ...compare import (
    DIFF_KIND_DOMAIN,
    KIND_CHANGED,
    KIND_ONLY_A,
    KIND_ONLY_B,
    ComparisonResult,
    DiffRun,
)
from ...range_index import address_in_sorted_ranges, build_sorted_range_index
from ...version import __version__
from ..hexview import HEX_WIDTH, MAX_HEX_ROWS, render_hex_view
from .report_service import (
    REPORT_CONTEXT_BYTES_DEFAULT,
    REPORT_MAX_TOTAL_BYTES,
    REPORT_TIMESTAMP_FORMAT,
    REPORTS_DIR_NAME,
    compute_hexdump_windows,
)

#: Self-contained diff-report filename regex (LLR-004.2, G-4). Owned HERE so
#: the shared ``report_service.REPORT_FILENAME_REGEX`` is never edited; it
#: matches exactly the LLR-004.1 ``<UTC %Y%m%dT%H%M%SZ>(-NN)?-diff-report.md``
#: scheme.
DIFF_REPORT_FILENAME_REGEX = re.compile(
    r"^\d{8}T\d{6}Z(-\d{2})?-diff-report\.md$"
)

#: Maximum runs whose hex windows are dumped per report (LLR-004.3). Sized to
#: mirror the ``REPORT_MAX_REGIONS_PER_VARIANT=128`` precedent
#: (``report_service.py:72``); the run TABLE always lists every run, the cap
#: only bounds the (expensive) per-run hex windows.
DIFF_REPORT_MAX_RUN_DUMPS = 128

#: Injectable UTC clock type (the ``report_service`` ``now_fn`` / B-4 pattern).
NowFn = Callable[[], datetime]


def _default_now() -> datetime:
    """
    Summary:
        Return the current UTC time — the default ``now_fn`` clock (mirrors
        ``report_service._default_now``).

    Returns:
        datetime: Timezone-aware ``datetime.now(timezone.utc)``.

    Dependencies:
        Used by:
            - generate_diff_report
    """
    return datetime.now(timezone.utc)


@dataclass(slots=True)
class DiffReportResult:
    """
    Summary:
        Outcome of one diff-report generation request — the written path on
        success, or a diagnostic-bearing refusal when the no-project
        destination failed validation (LLR-004.6). Generation never raises for
        a bad destination; it returns this object.

    Args:
        path (Optional[Path]): The written report file when ``written`` is
            ``True``; ``None`` on refusal.
        written (bool): ``True`` when exactly one file was written.
        diagnostics (List[str]): Human-readable reasons; non-empty only on
            refusal, naming the rejected input (LLR-004.6).

    Returns:
        None: Dataclass container.

    Data Flow:
        - Built by :func:`generate_diff_report`; consumed by the TUI report
          trigger (increment I4, LLR-005.4) and the tests.

    Dependencies:
        Used by:
            - generate_diff_report
            - s19_app.tui.app.S19TuiApp (increment I4)
    """

    path: Optional[Path] = None
    written: bool = False
    diagnostics: List[str] = field(default_factory=list)


def _diff_report_filename(dest_dir: Path, timestamp: datetime) -> str:
    """
    Summary:
        Build the diff-report filename for ``timestamp``, resolving a
        same-second collision with a zero-padded two-digit counter
        (LLR-004.1 / M-5: ``<ts>-diff-report.md``, then
        ``<ts>-01-diff-report.md`` .. ``<ts>-99-diff-report.md``) — the
        ``report_service._report_filename`` pattern with the diff kind suffix,
        applied unchanged in both the project and no-project destinations.

    Args:
        dest_dir (Path): The resolved destination directory.
        timestamp (datetime): The (UTC) generation instant from the injectable
            clock.

    Returns:
        str: A filename matching :data:`DIFF_REPORT_FILENAME_REGEX` that does
        not yet exist inside ``dest_dir``.

    Raises:
        FileExistsError: When the base name and all 99 counter slots for this
            second are taken — never a silent overwrite (M-5).

    Data Flow:
        - Format the UTC timestamp, probe the un-suffixed base name, then
          ``-01`` .. ``-99`` in order; first free slot wins.

    Dependencies:
        Used by:
            - generate_diff_report
    """
    base = timestamp.strftime(REPORT_TIMESTAMP_FORMAT)
    candidate = f"{base}-diff-report.md"
    if not (dest_dir / candidate).exists():
        return candidate
    for counter in range(1, 100):
        candidate = f"{base}-{counter:02d}-diff-report.md"
        if not (dest_dir / candidate).exists():
            return candidate
    raise FileExistsError(
        f"100 diff reports already exist for second {base} - refusing to "
        f"overwrite an existing report"
    )


def list_diff_reports(directory: Path) -> List[Path]:
    """
    Summary:
        List ``*.md`` diff reports in ``directory`` newest-first (LLR-004.2,
        G-4) — files matching :data:`DIFF_REPORT_FILENAME_REGEX` sort by the
        parsed key ``(timestamp, NN)`` descending, with a missing ``-NN``
        counter sorting as ``00``; non-matching ``.md`` files list LAST,
        unsorted-as-found. Owned here so ``report_service.list_project_reports``
        is never edited.

    Args:
        directory (Path): The directory holding the diff reports — a project's
            ``reports/`` directory or an operator-supplied destination.

    Returns:
        List[Path]: Diff-report paths, newest first, foreign ``.md`` files at
        the end. Empty when ``directory`` does not exist or holds no matching
        file.

    Data Flow:
        - The parsed sort key is REQUIRED inside a same-second collision group:
          raw filename-descending would put the un-suffixed base AFTER its
          ``-NN`` siblings, but the base is the group's FIRST (oldest) report —
          ``NN=00`` keys it correctly (the ``list_project_reports`` precedent).

    Dependencies:
        Uses:
            - DIFF_REPORT_FILENAME_REGEX
        Used by:
            - tests/test_diff_report_service.py

    Example:
        >>> list_diff_reports(Path("missing"))
        []
    """
    directory = Path(directory)
    if not directory.is_dir():
        return []
    timestamp_length = len("00000000T000000Z")
    keyed: List[Tuple[Tuple[str, int], Path]] = []
    foreign: List[Path] = []
    for path in directory.iterdir():
        if not path.is_file() or path.suffix.lower() != ".md":
            continue
        match = DIFF_REPORT_FILENAME_REGEX.match(path.name)
        if match is None:
            foreign.append(path)
            continue
        counter = int(match.group(1)[1:]) if match.group(1) else 0
        keyed.append(((path.name[:timestamp_length], counter), path))
    keyed.sort(key=lambda item: item[0], reverse=True)
    return [path for _key, path in keyed] + foreign


def _resolve_destination(
    project_dir: Optional[Path], dest_input: Optional[str]
) -> Tuple[Optional[Path], List[str]]:
    """
    Summary:
        Resolve and validate the report's destination directory (LLR-004.6,
        G-8 + M-4). While a project is active the destination is
        ``<project_dir>/reports/`` (created on demand) inside ``.s19tool/``;
        while no project is active it is the operator-supplied directory,
        normalized via ``Path(operator_input).expanduser().resolve()`` and
        required to be an existing directory — there is NO implicit default.

    Args:
        project_dir (Optional[Path]): The active project work area, or ``None``
            when no project is active.
        dest_input (Optional[str]): The operator-supplied destination directory
            (the no-project branch); ignored when ``project_dir`` is given.

    Returns:
        Tuple[Optional[Path], List[str]]: ``(dest_dir, diagnostics)``.
        ``dest_dir`` is ``None`` when the no-project path failed validation,
        and ``diagnostics`` then names the rejected input.

    Data Flow:
        - Project branch: ``project_dir / REPORTS_DIR_NAME``, ``mkdir`` on
          demand; never refuses (the dir lives under the gitignored tree).
        - No-project branch: empty input -> refuse; else
          ``Path(dest_input).expanduser().resolve()`` (collapses ``..`` +
          symlinks; a relative path resolves against the app cwd) -> require
          ``dest.is_dir()`` else refuse naming the input. The single-token
          name cleaner is deliberately NOT used (M-4 — it cannot validate a
          path; see the module docstring).

    Dependencies:
        Used by:
            - generate_diff_report
    """
    if project_dir is not None:
        dest_dir = Path(project_dir) / REPORTS_DIR_NAME
        dest_dir.mkdir(parents=True, exist_ok=True)
        return dest_dir, []

    raw = (dest_input or "").strip()
    if not raw:
        return None, [
            "No destination directory supplied for a no-project diff report - "
            "refusing to write (no implicit default)."
        ]
    resolved = Path(raw).expanduser().resolve()
    if not resolved.is_dir():
        return None, [
            f"Destination is not an existing directory: {raw!r} "
            f"(resolved to {resolved}) - refusing to write."
        ]
    return resolved, []


def _kind_label(kind: str) -> str:
    """Map a :data:`DIFF_KIND_DOMAIN` token to its display label."""
    return {
        KIND_CHANGED: "changed",
        KIND_ONLY_A: "only in A",
        KIND_ONLY_B: "only in B",
    }.get(kind, kind)


def _artifact_addresses_with_names(
    artifact_data: object, address_key: str = "address", name_key: str = "name"
) -> List[Tuple[int, str]]:
    """
    Summary:
        Extract ``(address, name)`` pairs from a list of artifact records that
        carry an integer address — the membership input for best-effort run
        annotation (LLR-004.4). Accepts MAC records (``record['address']`` /
        ``record['name']``, mac.py) and enriched A2L tags
        (``tag['address']`` / ``tag['name']``, a2l.py).

    Args:
        artifact_data (object): A sequence of record dicts, or ``None``.
        address_key (str): The integer-address key on each record.
        name_key (str): The symbol-name key on each record.

    Returns:
        List[Tuple[int, str]]: One pair per record carrying an int address;
        empty when no artifact context exists (non-gating — LLR-004.4).

    Dependencies:
        Used by:
            - _annotate_run
    """
    if not artifact_data:
        return []
    pairs: List[Tuple[int, str]] = []
    for record in artifact_data:
        if not isinstance(record, dict):
            continue
        addr = record.get(address_key)
        if isinstance(addr, int):
            name = record.get(name_key)
            pairs.append((addr, str(name) if name is not None else "?"))
    return pairs


def _annotate_run(
    run: DiffRun, symbol_addresses: Sequence[Tuple[int, str]]
) -> str:
    """
    Summary:
        Best-effort, non-gating annotation of one run with the names of every
        artifact symbol whose address falls inside ``[run.start, run.end)``
        (LLR-004.4, G-2). A run that intersects no symbol — or any run when no
        artifact context exists — annotates as ``-`` and is still reported as a
        raw binary run.

    Args:
        run (DiffRun): The differing run to annotate.
        symbol_addresses (Sequence[Tuple[int, str]]): ``(address, name)`` pairs
            from the shared A2L tags and MAC records; empty when no context.

    Returns:
        str: A comma-separated symbol-name list, or ``-`` when the run
        intersects no symbol.

    Data Flow:
        - Membership uses ``address_in_sorted_ranges`` over a one-range index
          built from the run (``range_index.py``), per LLR-004.4; the
          annotation never alters or gates the binary run.

    Dependencies:
        Uses:
            - build_sorted_range_index / address_in_sorted_ranges
        Used by:
            - _run_table_lines
    """
    if not symbol_addresses:
        return "-"
    index = build_sorted_range_index([(run.start, run.end)])
    names = [
        name
        for addr, name in symbol_addresses
        if address_in_sorted_ranges(addr, index)
    ]
    return ", ".join(names) if names else "-"


def _image_line(label: str, image) -> str:
    """Render one image-identity header bullet (label, source, path, errors)."""
    variant = f" variant={image.variant_id}" if image.variant_id else ""
    return (
        f"- Image {label}: {image.label or '(unnamed)'} "
        f"[{image.source_kind}{variant}] path=`{image.path}` "
        f"parse-errors={image.parse_error_count}"
    )


def _usage_line(label: str, usage) -> str:
    """Render one image's artifact-usage header bullet from its ArtifactUsage."""
    if usage is None:
        return f"- Image {label} artifacts: none"

    def _note(note) -> str:
        if note.status == "absent":
            return "absent"
        return f"{note.status} ({note.covered}/{note.total})"

    return (
        f"- Image {label} artifacts: summary={usage.summary}; "
        f"a2l={_note(usage.a2l)}; mac={_note(usage.mac)}"
    )


def _header_lines(
    comparison: ComparisonResult, generated_at: datetime
) -> List[str]:
    """
    Summary:
        Build the report header (LLR-004.3): the two image identities/sources,
        the per-image artifact-usage notes, the generation UTC instant, and the
        tool version.

    Args:
        comparison (ComparisonResult): The completed comparison.
        generated_at (datetime): The clock's generation instant.

    Returns:
        List[str]: Markdown lines, trailing blank included.

    Dependencies:
        Used by:
            - generate_diff_report
    """
    return [
        "# Diff report",
        "",
        f"- Generated (UTC): {generated_at.isoformat()}",
        f"- Tool version: {__version__}",
        _image_line("A", comparison.image_a),
        _image_line("B", comparison.image_b),
        _usage_line("A", comparison.notes.get("image_a")),
        _usage_line("B", comparison.notes.get("image_b")),
        "",
    ]


def _stats_lines(comparison: ComparisonResult) -> List[str]:
    """
    Summary:
        Build the statistics table (LLR-004.3): per-classification run count
        and byte count over the canonical :data:`DIFF_KIND_DOMAIN` order.

    Args:
        comparison (ComparisonResult): The completed comparison.

    Returns:
        List[str]: Markdown lines, trailing blank included.

    Dependencies:
        Used by:
            - generate_diff_report
    """
    stats = comparison.stats
    lines = [
        "## Statistics",
        "",
        "| Classification | Runs | Bytes |",
        "|---|---|---|",
    ]
    for kind in DIFF_KIND_DOMAIN:
        lines.append(
            f"| {_kind_label(kind)} "
            f"| {stats.run_counts.get(kind, 0)} "
            f"| {stats.byte_counts.get(kind, 0)} |"
        )
    lines.append("")
    return lines


def _run_table_lines(
    comparison: ComparisonResult, symbol_addresses: Sequence[Tuple[int, str]]
) -> List[str]:
    """
    Summary:
        Build the run table (LLR-004.3 / LLR-004.4): one row per run with
        start, end, length, classification, and best-effort symbol annotation.
        Every run is listed (no cap on the table — the cap bounds only the hex
        windows).

    Args:
        comparison (ComparisonResult): The completed comparison.
        symbol_addresses (Sequence[Tuple[int, str]]): Shared artifact
            ``(address, name)`` pairs; empty when no context (annotation ``-``).

    Returns:
        List[str]: Markdown lines, trailing blank included.

    Dependencies:
        Uses:
            - _annotate_run
        Used by:
            - generate_diff_report
    """
    lines = ["## Runs", ""]
    if not comparison.runs:
        lines.extend(["No differing runs - the images are identical.", ""])
        return lines
    lines.extend(
        [
            "| Start | End | Length | Classification | Symbols |",
            "|---|---|---|---|---|",
        ]
    )
    for run in comparison.runs:
        lines.append(
            f"| 0x{run.start:08X} | 0x{run.end:08X} | {run.length} "
            f"| {_kind_label(run.kind)} "
            f"| {_annotate_run(run, symbol_addresses)} |"
        )
    lines.append("")
    return lines


def _hex_windows_lines(
    comparison: ComparisonResult,
    mem_map_a: Dict[int, int],
    mem_map_b: Dict[int, int],
    context_bytes: int,
    run_dump_cap: int,
    budget_limit: int,
) -> List[str]:
    """
    Summary:
        Build per-run bounded hex windows for image A and image B (LLR-004.3),
        rendered through the plain ``render_hex_view`` over windows from
        ``compute_hexdump_windows``, enforcing both the run-dump cap and the
        whole-document byte budget with explicit ``TRUNCATED`` markers stating
        the exact omitted counts — never a silent cut.

    Args:
        comparison (ComparisonResult): The completed comparison.
        mem_map_a (Dict[int, int]): Image A's memory map.
        mem_map_b (Dict[int, int]): Image B's memory map.
        context_bytes (int): ± surrounding bytes per run window.
        run_dump_cap (int): Maximum runs whose windows are dumped.
        budget_limit (int): Whole-document byte budget (read at call time so
            tests can shrink it).

    Returns:
        List[str]: Markdown lines, trailing blank included.

    Data Flow:
        - Runs over the cap -> keep the first cap-many in document order, emit
          the run-cap TRUNCATED marker stating the exact omitted count.
        - Per kept run: one merged window per image (clamped at each image's
          top); a block that no longer fits the budget is omitted and counted,
          ending in the byte-budget TRUNCATED marker.

    Dependencies:
        Uses:
            - compute_hexdump_windows / render_hex_view
        Used by:
            - generate_diff_report
    """
    out: List[str] = ["## Hex windows", ""]
    used = sum(len(line.encode("utf-8")) + 1 for line in out)

    runs = comparison.runs
    if not runs:
        out.extend(["No differing runs to dump.", ""])
        return out
    if not mem_map_a and not mem_map_b:
        out.extend(["Memory maps unavailable - hex windows omitted.", ""])
        return out

    total_runs = len(runs)
    if total_runs > run_dump_cap:
        omitted = total_runs - run_dump_cap
        runs = runs[:run_dump_cap]
        out.extend(
            [
                f"> TRUNCATED: {omitted} of {total_runs} run hex windows "
                f"omitted (cap: {run_dump_cap} runs per report).",
                "",
            ]
        )

    top_a = max(mem_map_a) + 1 if mem_map_a else 0
    top_b = max(mem_map_b) + 1 if mem_map_b else 0
    omitted_blocks = 0

    def _block(mem_map: Dict[int, int], low: int, high: int, who: str) -> List[str]:
        row_bases = list(range(low, high, HEX_WIDTH))
        rendered = render_hex_view(mem_map, row_bases=row_bases, max_rows=MAX_HEX_ROWS)
        return [
            f"Image {who} window 0x{low:08X}-0x{high:08X}:",
            "",
            "```text",
            *rendered.splitlines(),
            "```",
            "",
        ]

    for run in runs:
        out.append(
            f"### Run 0x{run.start:08X}-0x{run.end:08X} ({_kind_label(run.kind)})"
        )
        out.append("")
        used += sum(len(line.encode("utf-8")) + 1 for line in out[-2:])
        for who, mem_map, top in (("A", mem_map_a, top_a), ("B", mem_map_b, top_b)):
            for low, high in compute_hexdump_windows(
                [(run.start, run.end)], context_bytes, top
            ):
                block = _block(mem_map, low, high, who)
                cost = sum(len(line.encode("utf-8")) + 1 for line in block)
                if used + cost > budget_limit:
                    omitted_blocks += 1
                    continue
                out.extend(block)
                used += cost

    if omitted_blocks:
        out.extend(
            [
                f"> TRUNCATED: {omitted_blocks} hex window block(s) omitted "
                f"(report size cap: {budget_limit} bytes).",
                "",
            ]
        )
    return out


def generate_diff_report(
    comparison: ComparisonResult,
    *,
    mem_map_a: Dict[int, int],
    mem_map_b: Dict[int, int],
    project_dir: Optional[Path] = None,
    dest_input: Optional[str] = None,
    a2l_records: Optional[Sequence[dict]] = None,
    mac_records: Optional[Sequence[dict]] = None,
    context_bytes: int = REPORT_CONTEXT_BYTES_DEFAULT,
    run_dump_cap: int = DIFF_REPORT_MAX_RUN_DUMPS,
    budget_limit: int = REPORT_MAX_TOTAL_BYTES,
    now_fn: Optional[NowFn] = None,
) -> DiffReportResult:
    """
    Summary:
        Generate one Markdown diff report for a completed comparison (HLR-004)
        and return a :class:`DiffReportResult` carrying the written path, or a
        diagnostic-bearing refusal when the no-project destination fails
        validation (LLR-004.6). Headless; performs no logging (LLR-004.5).

    Args:
        comparison (ComparisonResult): The §6.2 C-9 result from
            ``compare_service`` (increment I2). A refused comparison is still
            reportable (its run table states the images are identical / empty).
        mem_map_a (Dict[int, int]): Image A's memory map (the engine input);
            the hex-window source for image A.
        mem_map_b (Dict[int, int]): Image B's memory map; the hex-window source
            for image B.
        project_dir (Optional[Path]): The active project work area — when given
            the report is written to ``<project_dir>/reports/`` inside
            ``.s19tool/`` (LLR-004.1).
        dest_input (Optional[str]): The operator-supplied destination directory
            for the no-project branch (LLR-004.6, G-8). Required when
            ``project_dir`` is ``None``; ignored otherwise. There is NO
            implicit default.
        a2l_records (Optional[Sequence[dict]]): Enriched A2L tags for
            best-effort run annotation (LLR-004.4); ``None`` -> no A2L
            annotation (non-gating).
        mac_records (Optional[Sequence[dict]]): MAC records for best-effort run
            annotation; ``None`` -> no MAC annotation (non-gating).
        context_bytes (int): ± surrounding bytes per run hex window.
        run_dump_cap (int): Maximum runs whose hex windows are dumped
            (LLR-004.3 cap).
        budget_limit (int): Whole-document byte budget (LLR-004.3) — defaults
            to :data:`REPORT_MAX_TOTAL_BYTES`; tests shrink it to force the
            byte-budget TRUNCATED marker.
        now_fn (Optional[NowFn]): Injectable UTC clock; ``None`` resolves to
            ``datetime.now(timezone.utc)``.

    Returns:
        DiffReportResult: ``written=True`` with the path on success, or
        ``written=False`` with diagnostics naming the rejected no-project
        destination (LLR-004.6). Never raises for a bad destination.

    Raises:
        FileExistsError: When 100 diff reports already exist for the same
            second in the resolved directory — never a silent overwrite (M-5).

    Data Flow:
        - Resolve the destination (:func:`_resolve_destination`): project ->
          ``reports/`` under ``.s19tool/``; no-project -> validate the
          operator directory, refusing (no write) on an empty/invalid/missing
          path (LLR-004.6).
        - Build the filename with the no-silent-overwrite collision counter
          (:func:`_diff_report_filename`, M-5) in the resolved directory.
        - Emit header -> stats -> run table (best-effort annotation) -> per-run
          hex windows (caps + TRUNCATED markers), then write once.

    Dependencies:
        Uses:
            - _resolve_destination / _diff_report_filename
            - _header_lines / _stats_lines / _run_table_lines / _hex_windows_lines
        Used by:
            - s19_app.tui.app.S19TuiApp (increment I4)
            - tests/test_diff_report_service.py

    Example:
        >>> # see tests/test_diff_report_service.py for executable usage
    """
    dest_dir, diagnostics = _resolve_destination(project_dir, dest_input)
    if dest_dir is None:
        return DiffReportResult(path=None, written=False, diagnostics=diagnostics)

    clock = now_fn if now_fn is not None else _default_now
    generated_at = clock()
    filename = _diff_report_filename(dest_dir, generated_at)

    symbol_addresses = _artifact_addresses_with_names(
        a2l_records
    ) + _artifact_addresses_with_names(mac_records)

    lines: List[str] = []
    lines.extend(_header_lines(comparison, generated_at))
    lines.extend(_stats_lines(comparison))
    lines.extend(_run_table_lines(comparison, symbol_addresses))
    lines.extend(
        _hex_windows_lines(
            comparison,
            mem_map_a,
            mem_map_b,
            context_bytes,
            run_dump_cap,
            budget_limit,
        )
    )

    target = dest_dir / filename
    target.write_text("\n".join(lines), encoding="utf-8")
    return DiffReportResult(path=target, written=True, diagnostics=[])
