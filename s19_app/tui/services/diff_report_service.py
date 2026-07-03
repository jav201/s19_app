"""
Diff-report generator (Markdown + self-contained HTML) — s19_app batch-09,
increment I3 (HLR-004).

Headless service producing a COMPLETE diff report for a finished image
comparison in two output formats:

- :func:`generate_diff_report` writes one **Markdown** diff report.
- :func:`generate_diff_report_html` writes one **self-contained HTML** diff
  report (inline CSS only, every embedded value ``html.escape``-d, no
  ``<script>`` / external resource / CDN / network).

Both consume the §6.2 C-9 :class:`ComparisonResult` produced by
``compare_service`` (increment I2) plus the two memory maps the engine diffed.
Each report contains, in order (LLR-004.3 / LLR-004.7): a header (both image
identities and source kinds, the artifact-usage notes, the generation UTC
instant, the tool version), a statistics table (per-classification run/byte
counts), a run table (start, end, length, classification, best-effort symbol
annotation — LLR-004.4), and per-run bounded hex windows of image A and image B
rendered through the plain-string ``hexview.render_hex_view``. In the Markdown
report each ``changed`` run additionally renders as a fenced ```diff block with
image A's bytes as ``-`` lines and image B's bytes as ``+`` lines; the HTML
report colours the three run kinds with inline CSS.

**Completeness (G-9, I3 gate, BINDING):** the WRITTEN files are COMPLETE —
every run present, no per-report run cap, no ``REPORT_MAX_TOTAL_BYTES`` byte
truncation, and no ``TRUNCATED`` marker anywhere. The batch-07 display caps
(``REPORT_MAX_TOTAL_BYTES``, the per-report run-dump cap) bound only the TUI
DISPLAY render path (relocated to increment I4 / LLR-005.2); they never bound
these files.

This module **reuses** the batch-07 report conventions as a PATTERN (D-5): it
imports ``REPORTS_DIR_NAME`` / ``REPORT_TIMESTAMP_FORMAT`` /
``REPORT_CONTEXT_BYTES_DEFAULT`` and ``compute_hexdump_windows`` from
``report_service`` and the plain ``render_hex_view`` from ``hexview``, but it
does **not** edit ``report_service`` at all. In particular it owns its own
filename schemes — :data:`DIFF_REPORT_FILENAME_REGEX` /
:data:`DIFF_REPORT_HTML_FILENAME_REGEX` + :func:`list_diff_reports`
(LLR-004.2 / LLR-004.7, G-4) — leaving the shared ``REPORT_FILENAME_REGEX`` and
``list_project_reports`` byte-for-byte untouched.

Destination resolution (LLR-004.6, G-5 + G-8 + M-4, security) — shared by both
formats:

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

Both branches and both formats apply the SAME no-silent-overwrite collision
discipline in the resolved directory (LLR-004.1 / M-5): a zero-padded ``-NN``
counter, ``FileExistsError`` after 99, never an overwrite. The filename is
generated wholly by this module from the UTC timestamp — no operator-supplied
string forms any component of the filename.

Confidentiality (F-S-07, LLR-004.5): diff reports carry raw memory bytes.
This module performs NO logging at all — so report body content can never
reach the rotating log — and its tests use synthetic in-memory fixtures /
public example data exclusively.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Dict, List, Optional, Sequence, Tuple

from ...compare import (
    DIFF_KIND_DOMAIN,
    KIND_CHANGED,
    KIND_ONLY_A,
    KIND_ONLY_B,
    ComparisonResult,
    DiffRun,
)

if TYPE_CHECKING:  # pragma: no cover - typing-only, keeps runtime imports flat
    from ..changes.model import ChangeSummaryEntry
from ...range_index import address_in_sorted_ranges, build_sorted_range_index
from ...version import __version__
from ..hexview import HEX_WIDTH, MAX_HEX_ROWS, render_hex_view
from .report_service import (
    REPORT_CONTEXT_BYTES_DEFAULT,
    REPORT_TIMESTAMP_FORMAT,
    REPORTS_DIR_NAME,
    compute_hexdump_windows,
)

#: Self-contained Markdown diff-report filename regex (LLR-004.2, G-4). Owned
#: HERE so the shared ``report_service.REPORT_FILENAME_REGEX`` is never edited;
#: it matches exactly the LLR-004.1
#: ``<UTC %Y%m%dT%H%M%SZ>(-NN)?-diff-report.md`` scheme.
DIFF_REPORT_FILENAME_REGEX = re.compile(
    r"^\d{8}T\d{6}Z(-\d{2})?-diff-report\.md$"
)

#: Self-contained HTML diff-report filename regex (LLR-004.7, G-4). Sibling of
#: :data:`DIFF_REPORT_FILENAME_REGEX` for the
#: ``<UTC %Y%m%dT%H%M%SZ>(-NN)?-diff-report.html`` scheme; the shared
#: ``report_service.REPORT_FILENAME_REGEX`` is NOT edited.
DIFF_REPORT_HTML_FILENAME_REGEX = re.compile(
    r"^\d{8}T\d{6}Z(-\d{2})?-diff-report\.html$"
)

#: Inline-CSS colours distinguishing the three run kinds in the HTML export
#: (LLR-004.7). Self-contained named CSS colours — no external font/resource.
_HTML_KIND_COLOUR = {
    KIND_CHANGED: "#b58900",   # amber — present in both, byte differs
    KIND_ONLY_A: "#dc322f",    # red   — mapped in A only
    KIND_ONLY_B: "#268bd2",    # blue  — mapped in B only
}

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
            - generate_diff_report_html
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
        - Built by :func:`generate_diff_report` / :func:`generate_diff_report_html`;
          consumed by the TUI report trigger (increment I4, LLR-005.4) and the
          tests.

    Dependencies:
        Used by:
            - generate_diff_report
            - generate_diff_report_html
            - s19_app.tui.app.S19TuiApp (increment I4)
    """

    path: Optional[Path] = None
    written: bool = False
    diagnostics: List[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class BeforeAfterProvenance:
    """
    Summary:
        The before/after provenance block for a save-back report (LLR-038.1,
        batch-24) — the identities the report header names so the written file
        proves WHICH original image was compared against WHICH saved patched
        image, when the change document was applied, and where that document
        came from.

    Args:
        original_path (Path): The ORIGINAL loaded image on disk
            (``LoadedFile.path``) — the report's "before" side.
        saved_path (Path): The SAVED patched image — the actual post-dedup
            written path (``ChangeSummary.saved_path``), the "after" side.
        applied_at_utc (str): ISO-8601 UTC apply instant
            (``ChangeSummary.timestamp_utc``).
        change_doc_path (Optional[Path]): The change document the applied
            entries came from (``ChangeSummary.source_path``); ``None`` for a
            programmatically composed document.

    Returns:
        None: Frozen dataclass container.

    Data Flow:
        - Built by the before/after composer (LLR-038.2, increment I4) from
          ``LoadedFile`` + ``ChangeService.last_summary``; consumed by
          :func:`generate_diff_report` / :func:`generate_diff_report_html`
          which render it into the written header section.

    Dependencies:
        Used by:
            - generate_diff_report
            - generate_diff_report_html
            - s19_app.tui.services.before_after_service (increment I4)
    """

    original_path: Path
    saved_path: Path
    applied_at_utc: str
    change_doc_path: Optional[Path] = None


def _strip_ctl(value: object) -> str:
    """
    Summary:
        Strip control characters (``ord < 0x20`` — which covers the
        row-breaking ``\\n``/``\\r`` — plus ``0x7F``) from one parsed-artifact
        value (S-F2, LLR-038.1). Shared by the Markdown cell pipeline and the
        two before/after HTML helpers so a ctl-bearing symbol renders
        identically in BOTH written formats (increment-3 review
        recommendation); ``_esc`` escapes markup but does not strip.

    Args:
        value (object): The raw value (symbol, path, entry field); rendered
            via ``str()``.

    Returns:
        str: The text with every control character removed.

    Dependencies:
        Used by:
            - _md_cell
            - _html_provenance
            - _html_linkage
    """
    return "".join(
        ch for ch in str(value) if ord(ch) >= 0x20 and ord(ch) != 0x7F
    )


def _md_cell(value: object) -> str:
    """
    Summary:
        Sanitize one parsed-artifact value for embedding in a Markdown table
        cell (S-F2, LLR-038.1): strip control characters via
        :func:`_strip_ctl` and escape ``|`` so a pipe-bearing A2L/MAC symbol
        cannot break the table structure.

    Args:
        value (object): The raw value (symbol, path, entry field); rendered
            via ``str()``.

    Returns:
        str: The cell-safe text — no control characters, every ``|`` escaped
        as ``\\|``.

    Dependencies:
        Uses:
            - _strip_ctl
        Used by:
            - _provenance_lines
            - _linkage_table_lines
    """
    return _strip_ctl(value).replace("|", "\\|")


def _bytes_cell(values: Optional[Sequence[int]]) -> str:
    """
    Summary:
        Render an entry's before/after byte run for a linkage-table cell.
        ``None`` (a create-into-hole entry — no prior bytes were read) renders
        the explicit marker, never fabricated bytes (LLR-038.1).

    Args:
        values (Optional[Sequence[int]]): ``ChangeSummaryEntry.before_bytes``
            / ``after_bytes``; ``None`` only for the before side of a
            non-``applied`` or hole-creating entry.

    Returns:
        str: Space-separated uppercase hex bytes, ``(none - created into
        hole)`` for ``None``, or ``-`` for an empty run.

    Dependencies:
        Used by:
            - _linkage_table_lines
            - _html_linkage
    """
    if values is None:
        return "(none - created into hole)"
    return " ".join(f"{b:02X}" for b in values) or "-"


def _provenance_lines(provenance: BeforeAfterProvenance) -> List[str]:
    """
    Summary:
        Build the Markdown before/after provenance header section
        (LLR-038.1): original path, saved (post-dedup) path, apply instant,
        and change-document origin. Values pass :func:`_md_cell` (S-F2).

    Args:
        provenance (BeforeAfterProvenance): The composer-built identities.

    Returns:
        List[str]: Markdown lines, trailing blank included.

    Dependencies:
        Uses:
            - _md_cell
        Used by:
            - generate_diff_report
    """
    doc = (
        f"`{_md_cell(provenance.change_doc_path)}`"
        if provenance.change_doc_path is not None
        else "(in-memory document)"
    )
    return [
        "## Before/after provenance",
        "",
        f"- Original image (before): `{_md_cell(provenance.original_path)}`",
        f"- Saved patched image (after): `{_md_cell(provenance.saved_path)}`",
        f"- Applied (UTC): {_md_cell(provenance.applied_at_utc)}",
        f"- Change document: {doc}",
        "",
    ]


def _linkage_table_lines(
    entries: Sequence["ChangeSummaryEntry"],
) -> List[str]:
    """
    Summary:
        Build the Markdown per-entry change-linkage table (LLR-038.1): one row
        per summary entry — ALL dispositions, not only ``applied`` — with the
        addressed range, disposition, linkage classification/symbol, and the
        before/after byte runs. Every parsed-artifact value passes
        :func:`_md_cell` (S-F2); a ``before_bytes=None`` entry renders the
        explicit no-prior-bytes marker (never fabricated bytes).

    Args:
        entries (Sequence[ChangeSummaryEntry]): ``ChangeSummary.entries`` in
            document order; may be empty.

    Returns:
        List[str]: Markdown lines, trailing blank included; the empty case
        states ``No entries.``

    Dependencies:
        Uses:
            - _md_cell / _bytes_cell
        Used by:
            - generate_diff_report
    """
    lines = ["## Change-entry linkage", ""]
    if not entries:
        lines.extend(["No entries.", ""])
        return lines
    lines.extend(
        [
            "| # | Type | Start | End | Disposition | Linkage | Symbol "
            "| Before | After |",
            "|---|---|---|---|---|---|---|---|---|",
        ]
    )
    for index, entry in enumerate(entries, start=1):
        symbol = (
            _md_cell(entry.linkage_symbol)
            if entry.linkage_symbol is not None
            else "-"
        )
        lines.append(
            f"| {index} | {_md_cell(entry.entry_type)} "
            f"| 0x{entry.address_start:08X} | 0x{entry.address_end:08X} "
            f"| {_md_cell(entry.disposition)} | {_md_cell(entry.linkage)} "
            f"| {symbol} "
            f"| {_md_cell(_bytes_cell(entry.before_bytes))} "
            f"| {_md_cell(_bytes_cell(entry.after_bytes))} |"
        )
    lines.append("")
    return lines


def _diff_report_filename(
    dest_dir: Path, timestamp: datetime, suffix: str, stem: str = "diff-report"
) -> str:
    """
    Summary:
        Build a diff-report filename for ``timestamp`` with the given file
        ``suffix`` (``.md`` or ``.html``), resolving a same-second collision
        with a zero-padded two-digit counter (LLR-004.1 / M-5:
        ``<ts>-diff-report<suffix>``, then ``<ts>-01-diff-report<suffix>`` ..
        ``<ts>-99-diff-report<suffix>``) — the
        ``report_service._report_filename`` pattern with the diff kind suffix,
        applied unchanged in both the project and no-project destinations and
        for both output formats.

    Args:
        dest_dir (Path): The resolved destination directory.
        timestamp (datetime): The (UTC) generation instant from the injectable
            clock.
        suffix (str): The file extension including the dot — ``".md"`` for the
            Markdown report, ``".html"`` for the HTML report.
        stem (str): The filename kind stem between the counter and the suffix
            (LLR-038.1) — default ``"diff-report"`` (unchanged scheme); the
            before/after composer (I4) passes its own stem.

    Returns:
        str: A filename matching :data:`DIFF_REPORT_FILENAME_REGEX` (``.md``)
        or :data:`DIFF_REPORT_HTML_FILENAME_REGEX` (``.html``) that does not
        yet exist inside ``dest_dir``.

    Raises:
        FileExistsError: When the base name and all 99 counter slots for this
            second are taken — never a silent overwrite (M-5).

    Data Flow:
        - Format the UTC timestamp, probe the un-suffixed base name, then
          ``-01`` .. ``-99`` in order; first free slot wins.

    Dependencies:
        Used by:
            - generate_diff_report
            - generate_diff_report_html
    """
    base = timestamp.strftime(REPORT_TIMESTAMP_FORMAT)
    candidate = f"{base}-{stem}{suffix}"
    if not (dest_dir / candidate).exists():
        return candidate
    for counter in range(1, 100):
        candidate = f"{base}-{counter:02d}-{stem}{suffix}"
        if not (dest_dir / candidate).exists():
            return candidate
    raise FileExistsError(
        f"100 diff reports already exist for second {base}{suffix} - refusing "
        f"to overwrite an existing report"
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
            - generate_diff_report_html
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
            - _html_run_rows
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
        Every run is listed.

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


def _window_rows(mem_map: Dict[int, int], low: int, high: int) -> List[str]:
    """
    Summary:
        Render the plain-string hex+ASCII rows for the window ``[low, high)`` of
        ``mem_map`` via ``hexview.render_hex_view`` (LLR-004.3) — the shared
        row source for the Markdown ```text / ```diff blocks and the HTML
        ``<pre>`` windows.

    Args:
        mem_map (Dict[int, int]): The image memory map to render.
        low (int): Inclusive window start (row-aligned by the caller).
        high (int): Exclusive window end.

    Returns:
        List[str]: One string per rendered row (header + hex lines).

    Dependencies:
        Uses:
            - render_hex_view
        Used by:
            - _hex_windows_lines
            - _diff_block_lines
            - _html_hex_windows
    """
    row_bases = list(range(low, high, HEX_WIDTH))
    rendered = render_hex_view(mem_map, row_bases=row_bases, max_rows=MAX_HEX_ROWS)
    return rendered.splitlines()


def _diff_block_lines(
    run: DiffRun,
    mem_map_a: Dict[int, int],
    mem_map_b: Dict[int, int],
    context_bytes: int,
    top_a: int,
    top_b: int,
) -> List[str]:
    """
    Summary:
        Build the fenced ```diff block for one ``changed`` run (LLR-004.3):
        image A's window rows as ``-``-prefixed lines, image B's window rows as
        ``+``-prefixed lines, so the block renders red/green on
        GitHub/VS Code/Obsidian and degrades to plain text elsewhere.

    Args:
        run (DiffRun): The ``changed`` run.
        mem_map_a (Dict[int, int]): Image A's memory map.
        mem_map_b (Dict[int, int]): Image B's memory map.
        context_bytes (int): ± surrounding bytes per run window.
        top_a (int): One-past-the-last mapped address of A (window clamp).
        top_b (int): One-past-the-last mapped address of B (window clamp).

    Returns:
        List[str]: Markdown lines for the ```diff block, trailing blank
        included.

    Dependencies:
        Uses:
            - compute_hexdump_windows / _window_rows
        Used by:
            - _hex_windows_lines
    """
    out: List[str] = ["```diff"]
    for low, high in compute_hexdump_windows([(run.start, run.end)], context_bytes, top_a):
        for row in _window_rows(mem_map_a, low, high):
            out.append(f"-{row}")
    for low, high in compute_hexdump_windows([(run.start, run.end)], context_bytes, top_b):
        for row in _window_rows(mem_map_b, low, high):
            out.append(f"+{row}")
    out.extend(["```", ""])
    return out


def _hex_windows_lines(
    comparison: ComparisonResult,
    mem_map_a: Dict[int, int],
    mem_map_b: Dict[int, int],
    context_bytes: int,
) -> List[str]:
    """
    Summary:
        Build per-run bounded hex windows for image A and image B (LLR-004.3),
        rendered through the plain ``render_hex_view`` over windows from
        ``compute_hexdump_windows``. The written file is COMPLETE (G-9): every
        run is dumped, there is no run cap, no byte budget, and no ``TRUNCATED``
        marker. Each ``changed`` run additionally carries a fenced ```diff
        block (A bytes as ``-`` lines, B bytes as ``+`` lines).

    Args:
        comparison (ComparisonResult): The completed comparison.
        mem_map_a (Dict[int, int]): Image A's memory map.
        mem_map_b (Dict[int, int]): Image B's memory map.
        context_bytes (int): ± surrounding bytes per run window.

    Returns:
        List[str]: Markdown lines, trailing blank included.

    Data Flow:
        - Per run: a ```text window per image (clamped at each image's top);
          a ``changed`` run additionally emits a ```diff block via
          :func:`_diff_block_lines`. No omission, no marker (G-9).

    Dependencies:
        Uses:
            - compute_hexdump_windows / _window_rows / _diff_block_lines
        Used by:
            - generate_diff_report
    """
    out: List[str] = ["## Hex windows", ""]

    runs = comparison.runs
    if not runs:
        out.extend(["No differing runs to dump.", ""])
        return out
    if not mem_map_a and not mem_map_b:
        out.extend(["Memory maps unavailable - hex windows omitted.", ""])
        return out

    top_a = max(mem_map_a) + 1 if mem_map_a else 0
    top_b = max(mem_map_b) + 1 if mem_map_b else 0

    def _block(mem_map: Dict[int, int], low: int, high: int, who: str) -> List[str]:
        return [
            f"Image {who} window 0x{low:08X}-0x{high:08X}:",
            "",
            "```text",
            *_window_rows(mem_map, low, high),
            "```",
            "",
        ]

    for run in runs:
        out.append(
            f"### Run 0x{run.start:08X}-0x{run.end:08X} ({_kind_label(run.kind)})"
        )
        out.append("")
        if run.kind == KIND_CHANGED:
            out.extend(
                _diff_block_lines(
                    run, mem_map_a, mem_map_b, context_bytes, top_a, top_b
                )
            )
        for who, mem_map, top in (("A", mem_map_a, top_a), ("B", mem_map_b, top_b)):
            for low, high in compute_hexdump_windows(
                [(run.start, run.end)], context_bytes, top
            ):
                out.extend(_block(mem_map, low, high, who))

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
    now_fn: Optional[NowFn] = None,
    provenance: Optional[BeforeAfterProvenance] = None,
    linkage_entries: Optional[Sequence["ChangeSummaryEntry"]] = None,
    filename_stem: Optional[str] = None,
) -> DiffReportResult:
    """
    Summary:
        Generate one COMPLETE Markdown diff report for a completed comparison
        (HLR-004 / LLR-004.3) and return a :class:`DiffReportResult` carrying
        the written path, or a diagnostic-bearing refusal when the no-project
        destination fails validation (LLR-004.6). The written file is complete
        — every run present, no cap, no byte truncation, no ``TRUNCATED`` marker
        (G-9). Headless; performs no logging (LLR-004.5).

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
        now_fn (Optional[NowFn]): Injectable UTC clock; ``None`` resolves to
            ``datetime.now(timezone.utc)``.
        provenance (Optional[BeforeAfterProvenance]): The before/after
            save-back identities (LLR-038.1, batch-24); when given a
            ``## Before/after provenance`` section renders after the header.
            When omitted the written output is BYTE-IDENTICAL to the
            pre-batch-24 behavior.
        linkage_entries (Optional[Sequence[ChangeSummaryEntry]]): The applied
            summary's per-entry records (LLR-038.1); when given (even empty)
            a ``## Change-entry linkage`` table renders after the provenance
            slot — cells ``_md_cell``-sanitized (S-F2), ``before_bytes=None``
            as an explicit marker. Omitted -> no section, output unchanged.
        filename_stem (Optional[str]): Filename kind-stem override
            (LLR-038.1) for the before/after composer's own scheme (I4);
            ``None`` keeps the ``diff-report`` scheme unchanged.

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
        - Emit header -> optional provenance/linkage sections (LLR-038.1) ->
          stats -> run table (best-effort annotation) -> per-run hex windows +
          ```diff cue, then write once (COMPLETE — G-9).

    Dependencies:
        Uses:
            - _resolve_destination / _diff_report_filename
            - _header_lines / _provenance_lines / _linkage_table_lines
            - _stats_lines / _run_table_lines / _hex_windows_lines
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
    filename = _diff_report_filename(
        dest_dir,
        generated_at,
        ".md",
        stem=filename_stem if filename_stem is not None else "diff-report",
    )

    symbol_addresses = _artifact_addresses_with_names(
        a2l_records
    ) + _artifact_addresses_with_names(mac_records)

    lines: List[str] = []
    lines.extend(_header_lines(comparison, generated_at))
    if provenance is not None:
        lines.extend(_provenance_lines(provenance))
    if linkage_entries is not None:
        lines.extend(_linkage_table_lines(linkage_entries))
    lines.extend(_stats_lines(comparison))
    lines.extend(_run_table_lines(comparison, symbol_addresses))
    lines.extend(
        _hex_windows_lines(comparison, mem_map_a, mem_map_b, context_bytes)
    )

    target = dest_dir / filename
    target.write_text("\n".join(lines), encoding="utf-8")
    return DiffReportResult(path=target, written=True, diagnostics=[])


# ---------------------------------------------------------------------------
# HTML export (LLR-004.7, G-9) — self-contained, html.escape-d, no script /
# external resource; COMPLETE (no cap / truncation).
# ---------------------------------------------------------------------------


def _esc(value: object) -> str:
    """Escape ``value`` for safe HTML embedding via stdlib ``html.escape``."""
    return html.escape(str(value), quote=True)


def _html_header(comparison: ComparisonResult, generated_at: datetime) -> List[str]:
    """
    Summary:
        Build the HTML header block (LLR-004.7): image identities/sources,
        per-image artifact-usage notes, the UTC instant, and the tool version —
        every embedded value ``html.escape``-d.

    Args:
        comparison (ComparisonResult): The completed comparison.
        generated_at (datetime): The clock's generation instant.

    Returns:
        List[str]: HTML lines.

    Dependencies:
        Uses:
            - _esc
        Used by:
            - generate_diff_report_html
    """

    def _img(label: str, image) -> str:
        variant = f" variant={image.variant_id}" if image.variant_id else ""
        return (
            f"<li>Image {label}: {_esc(image.label or '(unnamed)')} "
            f"[{_esc(image.source_kind)}{_esc(variant)}] "
            f"path=<code>{_esc(image.path)}</code> "
            f"parse-errors={_esc(image.parse_error_count)}</li>"
        )

    def _usage(label: str, usage) -> str:
        if usage is None:
            return f"<li>Image {label} artifacts: none</li>"

        def _note(note) -> str:
            if note.status == "absent":
                return "absent"
            return f"{_esc(note.status)} ({_esc(note.covered)}/{_esc(note.total)})"

        return (
            f"<li>Image {label} artifacts: summary={_esc(usage.summary)}; "
            f"a2l={_note(usage.a2l)}; mac={_note(usage.mac)}</li>"
        )

    return [
        "<h1>Diff report</h1>",
        "<ul>",
        f"<li>Generated (UTC): {_esc(generated_at.isoformat())}</li>",
        f"<li>Tool version: {_esc(__version__)}</li>",
        _img("A", comparison.image_a),
        _img("B", comparison.image_b),
        _usage("A", comparison.notes.get("image_a")),
        _usage("B", comparison.notes.get("image_b")),
        "</ul>",
    ]


def _html_provenance(provenance: BeforeAfterProvenance) -> List[str]:
    """
    Summary:
        Build the HTML before/after provenance section (LLR-038.1) — the
        Markdown :func:`_provenance_lines` mirror, every embedded value
        ctl-stripped via :func:`_strip_ctl` (md/html pair consistency) then
        ``html.escape``-d via :func:`_esc`.

    Args:
        provenance (BeforeAfterProvenance): The composer-built identities.

    Returns:
        List[str]: HTML lines.

    Dependencies:
        Uses:
            - _esc / _strip_ctl
        Used by:
            - generate_diff_report_html
    """
    doc = (
        f"<code>{_esc(_strip_ctl(provenance.change_doc_path))}</code>"
        if provenance.change_doc_path is not None
        else "(in-memory document)"
    )
    return [
        "<h2>Before/after provenance</h2>",
        "<ul>",
        f"<li>Original image (before): "
        f"<code>{_esc(_strip_ctl(provenance.original_path))}</code></li>",
        f"<li>Saved patched image (after): "
        f"<code>{_esc(_strip_ctl(provenance.saved_path))}</code></li>",
        f"<li>Applied (UTC): {_esc(_strip_ctl(provenance.applied_at_utc))}</li>",
        f"<li>Change document: {doc}</li>",
        "</ul>",
    ]


def _html_linkage(entries: Sequence["ChangeSummaryEntry"]) -> List[str]:
    """
    Summary:
        Build the HTML per-entry change-linkage table (LLR-038.1) — the
        Markdown :func:`_linkage_table_lines` mirror: one row per summary
        entry (all dispositions), values ctl-stripped via :func:`_strip_ctl`
        (md/html pair consistency) then ``html.escape``-d via :func:`_esc`,
        ``before_bytes=None`` rendered as the explicit no-prior-bytes marker.

    Args:
        entries (Sequence[ChangeSummaryEntry]): ``ChangeSummary.entries`` in
            document order; may be empty.

    Returns:
        List[str]: HTML lines; the empty case states ``No entries.``

    Dependencies:
        Uses:
            - _esc / _strip_ctl / _bytes_cell
        Used by:
            - generate_diff_report_html
    """
    lines = ["<h2>Change-entry linkage</h2>"]
    if not entries:
        lines.append("<p>No entries.</p>")
        return lines
    lines.extend(
        [
            "<table>",
            "<tr><th>#</th><th>Type</th><th>Start</th><th>End</th>"
            "<th>Disposition</th><th>Linkage</th><th>Symbol</th>"
            "<th>Before</th><th>After</th></tr>",
        ]
    )
    for index, entry in enumerate(entries, start=1):
        symbol = (
            _esc(_strip_ctl(entry.linkage_symbol))
            if entry.linkage_symbol is not None
            else "-"
        )
        lines.append(
            f"<tr><td>{index}</td><td>{_esc(_strip_ctl(entry.entry_type))}</td>"
            f"<td>0x{entry.address_start:08X}</td>"
            f"<td>0x{entry.address_end:08X}</td>"
            f"<td>{_esc(_strip_ctl(entry.disposition))}</td>"
            f"<td>{_esc(_strip_ctl(entry.linkage))}</td>"
            f"<td>{symbol}</td>"
            f"<td>{_esc(_bytes_cell(entry.before_bytes))}</td>"
            f"<td>{_esc(_bytes_cell(entry.after_bytes))}</td></tr>"
        )
    lines.append("</table>")
    return lines


def _html_stats(comparison: ComparisonResult) -> List[str]:
    """Build the HTML statistics table (LLR-004.7), values escaped."""
    stats = comparison.stats
    lines = [
        "<h2>Statistics</h2>",
        "<table>",
        "<tr><th>Classification</th><th>Runs</th><th>Bytes</th></tr>",
    ]
    for kind in DIFF_KIND_DOMAIN:
        colour = _HTML_KIND_COLOUR.get(kind, "#000000")
        lines.append(
            f'<tr><td style="color:{colour}">{_esc(_kind_label(kind))}</td>'
            f"<td>{_esc(stats.run_counts.get(kind, 0))}</td>"
            f"<td>{_esc(stats.byte_counts.get(kind, 0))}</td></tr>"
        )
    lines.append("</table>")
    return lines


def _html_run_rows(
    comparison: ComparisonResult, symbol_addresses: Sequence[Tuple[int, str]]
) -> List[str]:
    """
    Summary:
        Build the HTML run table (LLR-004.7 / LLR-004.4): one row per run with
        start, end, length, classification (coloured by inline CSS per kind),
        and best-effort symbol annotation. Every run is listed; all values
        ``html.escape``-d.

    Args:
        comparison (ComparisonResult): The completed comparison.
        symbol_addresses (Sequence[Tuple[int, str]]): Shared artifact
            ``(address, name)`` pairs; empty when no context (annotation ``-``).

    Returns:
        List[str]: HTML lines.

    Dependencies:
        Uses:
            - _annotate_run / _esc
        Used by:
            - generate_diff_report_html
    """
    lines = ["<h2>Runs</h2>"]
    if not comparison.runs:
        lines.append("<p>No differing runs - the images are identical.</p>")
        return lines
    lines.extend(
        [
            "<table>",
            "<tr><th>Start</th><th>End</th><th>Length</th>"
            "<th>Classification</th><th>Symbols</th></tr>",
        ]
    )
    for run in comparison.runs:
        colour = _HTML_KIND_COLOUR.get(run.kind, "#000000")
        lines.append(
            f"<tr><td>0x{run.start:08X}</td><td>0x{run.end:08X}</td>"
            f"<td>{_esc(run.length)}</td>"
            f'<td style="color:{colour}">{_esc(_kind_label(run.kind))}</td>'
            f"<td>{_esc(_annotate_run(run, symbol_addresses))}</td></tr>"
        )
    lines.append("</table>")
    return lines


def _html_hex_windows(
    comparison: ComparisonResult,
    mem_map_a: Dict[int, int],
    mem_map_b: Dict[int, int],
    context_bytes: int,
) -> List[str]:
    """
    Summary:
        Build the HTML per-run hex windows for image A and image B (LLR-004.7).
        COMPLETE (G-9): every run dumped, no cap / byte budget / ``TRUNCATED``
        marker. Each window is an escaped ``<pre>`` block coloured by the run
        kind via inline CSS.

    Args:
        comparison (ComparisonResult): The completed comparison.
        mem_map_a (Dict[int, int]): Image A's memory map.
        mem_map_b (Dict[int, int]): Image B's memory map.
        context_bytes (int): ± surrounding bytes per run window.

    Returns:
        List[str]: HTML lines.

    Dependencies:
        Uses:
            - compute_hexdump_windows / _window_rows / _esc
        Used by:
            - generate_diff_report_html
    """
    lines = ["<h2>Hex windows</h2>"]
    runs = comparison.runs
    if not runs:
        lines.append("<p>No differing runs to dump.</p>")
        return lines
    if not mem_map_a and not mem_map_b:
        lines.append("<p>Memory maps unavailable - hex windows omitted.</p>")
        return lines

    top_a = max(mem_map_a) + 1 if mem_map_a else 0
    top_b = max(mem_map_b) + 1 if mem_map_b else 0

    for run in runs:
        colour = _HTML_KIND_COLOUR.get(run.kind, "#000000")
        lines.append(
            f'<h3 style="color:{colour}">'
            f"Run 0x{run.start:08X}-0x{run.end:08X} "
            f"({_esc(_kind_label(run.kind))})</h3>"
        )
        for who, mem_map, top in (("A", mem_map_a, top_a), ("B", mem_map_b, top_b)):
            for low, high in compute_hexdump_windows(
                [(run.start, run.end)], context_bytes, top
            ):
                body = "\n".join(_window_rows(mem_map, low, high))
                lines.append(
                    f"<p>Image {who} window 0x{low:08X}-0x{high:08X}:</p>"
                )
                lines.append(
                    f'<pre style="color:{colour}">{_esc(body)}</pre>'
                )
    return lines


def generate_diff_report_html(
    comparison: ComparisonResult,
    *,
    mem_map_a: Dict[int, int],
    mem_map_b: Dict[int, int],
    project_dir: Optional[Path] = None,
    dest_input: Optional[str] = None,
    a2l_records: Optional[Sequence[dict]] = None,
    mac_records: Optional[Sequence[dict]] = None,
    context_bytes: int = REPORT_CONTEXT_BYTES_DEFAULT,
    now_fn: Optional[NowFn] = None,
    provenance: Optional[BeforeAfterProvenance] = None,
    linkage_entries: Optional[Sequence["ChangeSummaryEntry"]] = None,
    filename_stem: Optional[str] = None,
) -> DiffReportResult:
    """
    Summary:
        Generate one COMPLETE, self-contained HTML diff report for a completed
        comparison (HLR-004 / LLR-004.7) and return a :class:`DiffReportResult`.
        The HTML carries the same content as the Markdown report (identities,
        artifact-usage notes, statistics, run table with best-effort
        annotation, per-run hex windows for A and B), uses inline CSS ONLY with
        the three run kinds in distinct colours, escapes every embedded value
        via ``html.escape``, and contains NO ``<script>`` / external resource /
        font / CDN / network reference. The written file is COMPLETE — no cap,
        no byte truncation, no ``TRUNCATED`` marker (G-9). Headless; performs no
        logging (LLR-004.5).

    Args:
        comparison (ComparisonResult): The §6.2 C-9 result from
            ``compare_service`` (increment I2).
        mem_map_a (Dict[int, int]): Image A's memory map; the hex-window source.
        mem_map_b (Dict[int, int]): Image B's memory map; the hex-window source.
        project_dir (Optional[Path]): Active project work area — report written
            to ``<project_dir>/reports/`` inside ``.s19tool/`` (LLR-004.1).
        dest_input (Optional[str]): Operator-supplied destination directory for
            the no-project branch (LLR-004.6, G-8). Required when ``project_dir``
            is ``None``; ignored otherwise. There is NO implicit default.
        a2l_records (Optional[Sequence[dict]]): Enriched A2L tags for best-effort
            run annotation (LLR-004.4); ``None`` -> no A2L annotation.
        mac_records (Optional[Sequence[dict]]): MAC records for best-effort run
            annotation; ``None`` -> no MAC annotation.
        context_bytes (int): ± surrounding bytes per run hex window.
        now_fn (Optional[NowFn]): Injectable UTC clock; ``None`` resolves to
            ``datetime.now(timezone.utc)``.
        provenance (Optional[BeforeAfterProvenance]): The before/after
            save-back identities (LLR-038.1, batch-24); when given a
            ``Before/after provenance`` section renders after the header,
            values ``_esc``-d. Omitted -> output BYTE-IDENTICAL to the
            pre-batch-24 behavior.
        linkage_entries (Optional[Sequence[ChangeSummaryEntry]]): The applied
            summary's per-entry records (LLR-038.1); when given (even empty)
            a ``Change-entry linkage`` table renders after the provenance
            slot, values ``_esc``-d, ``before_bytes=None`` as an explicit
            marker. Omitted -> no section, output unchanged.
        filename_stem (Optional[str]): Filename kind-stem override
            (LLR-038.1); ``None`` keeps the ``diff-report`` scheme unchanged.

    Returns:
        DiffReportResult: ``written=True`` with the ``.html`` path on success,
        or ``written=False`` with diagnostics naming the rejected no-project
        destination (LLR-004.6). Never raises for a bad destination.

    Raises:
        FileExistsError: When 100 HTML diff reports already exist for the same
            second in the resolved directory — never a silent overwrite (M-5).

    Data Flow:
        - Same destination resolution (:func:`_resolve_destination`) and
          collision counter (:func:`_diff_report_filename`, ``.html`` suffix)
          as the Markdown report.
        - Emit a self-contained ``<html>`` document: inline ``<style>`` ->
          escaped header / stats / run table / hex windows, then write once
          (COMPLETE — G-9).

    Dependencies:
        Uses:
            - _resolve_destination / _diff_report_filename
            - _html_header / _html_provenance / _html_linkage
            - _html_stats / _html_run_rows / _html_hex_windows
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
    filename = _diff_report_filename(
        dest_dir,
        generated_at,
        ".html",
        stem=filename_stem if filename_stem is not None else "diff-report",
    )

    symbol_addresses = _artifact_addresses_with_names(
        a2l_records
    ) + _artifact_addresses_with_names(mac_records)

    style = (
        "body{font-family:monospace;background:#fdf6e3;color:#073642;}"
        "table{border-collapse:collapse;}"
        "th,td{border:1px solid #93a1a1;padding:2px 6px;text-align:left;}"
        "pre{border:1px solid #93a1a1;padding:6px;overflow:auto;}"
    )

    lines: List[str] = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        "<title>Diff report</title>",
        f"<style>{style}</style>",
        "</head>",
        "<body>",
    ]
    lines.extend(_html_header(comparison, generated_at))
    if provenance is not None:
        lines.extend(_html_provenance(provenance))
    if linkage_entries is not None:
        lines.extend(_html_linkage(linkage_entries))
    lines.extend(_html_stats(comparison))
    lines.extend(_html_run_rows(comparison, symbol_addresses))
    lines.extend(_html_hex_windows(comparison, mem_map_a, mem_map_b, context_bytes))
    lines.extend(["</body>", "</html>"])

    target = dest_dir / filename
    target.write_text("\n".join(lines), encoding="utf-8")
    return DiffReportResult(path=target, written=True, diagnostics=[])
