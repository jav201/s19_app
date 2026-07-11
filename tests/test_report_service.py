"""Batch-07 E7 — Markdown project-report generator (HLR-007).

Coverage map:

- LLR-007.4 content — ``test_full_report_content``: every section class
  (a)-(d) asserted by heading on a 2-variant fixture; per-modification rows
  exact; declaration-error subsection present; ``saved_path`` listed; the
  (e) appendix is absent when no cap fired (it is asserted present in the
  cap tests).
- LLR-007.5 — ``test_filename_regex_and_same_second_collision``: injected
  fixed clock → base name then ``-01`` counter, both matching the pinned
  regex ``^\\d{8}T\\d{6}Z(-\\d{2})?-report\\.md$``.
- LLR-007.2 + F-Q-06 — ``test_window_math_*``: pure window math including
  the two MANDATORY edge fixtures (region at address 0, region at the
  image top) and the overlap/adjacency merge; report-level row-address
  assertions for both edges.
- F-S-05 — ``test_context_bytes_out_of_domain_rejected``: out-of-domain
  ``context_bytes`` raises one explicit ``ValueError`` (never clamped);
  the 0 and MAX boundaries are accepted.
- LLR-007.6 — ``test_region_cap_marker_exact_omitted_count`` and
  ``test_total_bytes_cap_marker``: each cap firing writes the explicit
  in-document TRUNCATED marker with the exact omitted count plus a
  truncation-appendix entry.
- LLR-007.7 — ``test_reports_dir_created_on_demand_stays_neutral``:
  generation creates ``reports/`` and ``validate_project_files`` still
  validates the project (extends the E5a neutrality test).
- LLR-008.4 pattern / F-Q-07 — ``test_generation_is_headless_no_app``:
  ``App.__init__`` monkeypatched to raise; generation still succeeds.
- LLR-007.3/007.8 inspections — ``test_inspection_no_forbidden_symbols``:
  the service source contains no Rich-renderer symbol, no parser class
  name, and no Textual import.
- LLR-007.8 transport — ``test_execution_capture_feeds_report_end_to_end``:
  ``capture_mem_maps=True`` pins each variant's post-change map onto its
  ``VariantExecutionResult`` and the generated hexdump shows the patched
  byte; capture off → ``mem_map is None``.
- LLR-007.6 measurement (slow) — ``test_measure_report_caps_on_large_s19``:
  generates reports from the ``make_large_s19`` fixture at default and
  max context; prints the measured sizes/times for the review packet.

Confidentiality (F-S-07): every fixture below is a synthetic in-memory
byte run or a ``tests/conftest.py`` generator product — never operator
firmware.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Sequence

import pytest

from s19_app.tui.changes.model import (
    CHECK_AGGREGATE_KEYS,
    DISPOSITION_DOMAIN,
    ChangeSummary,
    ChangeSummaryEntry,
    CheckRunEntry,
    CheckRunResult,
)
from s19_app.tui.legend import LEGEND_TABLE
from s19_app.tui.models import ProjectVariantSet, VariantDescriptor
from s19_app.tui.services.report_addendum import DeclaredRegion
from s19_app.tui.services.report_filter import (
    parse_report_filter,
    resolve_report_filter,
)
from s19_app.tui.services import report_service
from s19_app.tui.services.report_service import (
    REPORT_CONTEXT_BYTES_MAX,
    REPORT_FILENAME_REGEX,
    REPORT_MAX_REGIONS_PER_VARIANT,
    REPORT_MAX_TOTAL_BYTES,
    ReportOptions,
    compute_hexdump_windows,
    generate_project_report,
)
from s19_app.tui.services.variant_execution_service import (
    SCOPE_ALL,
    VariantExecutionResult,
    execute_variant_plan,
    plan_variant_executions,
)
from s19_app.tui.workspace import build_variant_set, validate_project_files
from s19_app.validation.model import ValidationIssue, ValidationSeverity

FIXED_NOW = datetime(2026, 6, 10, 12, 0, 0, tzinfo=timezone.utc)


def _fixed_clock() -> datetime:
    return FIXED_NOW


def _counts(applied: int = 0) -> dict[str, int]:
    counts = {token: 0 for token in DISPOSITION_DOMAIN}
    counts["applied"] = applied
    return counts


def _aggregates(passed: int = 0, failed: int = 0, uncheckable: int = 0) -> dict[str, int]:
    values = dict(zip(CHECK_AGGREGATE_KEYS, (passed, failed, uncheckable)))
    return {key: values[key] for key in CHECK_AGGREGATE_KEYS}


def _applied_entry(
    start: int,
    before: Sequence[int],
    after: Sequence[int],
    linkage: str = "standalone",
    symbol: Optional[str] = None,
) -> ChangeSummaryEntry:
    return ChangeSummaryEntry(
        entry_type="bytes",
        address_start=start,
        address_end=start + len(after),
        before_bytes=tuple(before),
        after_bytes=tuple(after),
        disposition="applied",
        linkage=linkage,
        linkage_symbol=symbol,
    )


def _summary(
    entries: Sequence[ChangeSummaryEntry],
    *,
    source: str = "chg.json",
    issues: Sequence[ValidationIssue] = (),
    saved_path: Optional[Path] = None,
    variant_id: Optional[str] = None,
) -> ChangeSummary:
    applied = sum(1 for entry in entries if entry.disposition == "applied")
    return ChangeSummary(
        source_path=Path(source),
        kind="change",
        encoding="utf-8",
        value_mode="text",
        timestamp_utc="2026-06-10T11:00:00+00:00",
        variant_id=variant_id,
        counts=_counts(applied),
        entries=list(entries),
        issues=list(issues),
        saved_path=saved_path,
    )


def _check(
    entries: Sequence[CheckRunEntry],
    *,
    source: str = "chk.json",
    issues: Sequence[ValidationIssue] = (),
) -> CheckRunResult:
    passed = sum(1 for entry in entries if entry.result == "pass")
    failed = sum(1 for entry in entries if entry.result == "fail")
    uncheckable = sum(1 for entry in entries if entry.result == "uncheckable")
    return CheckRunResult(
        source_path=Path(source),
        timestamp_utc="2026-06-10T11:00:00+00:00",
        variant_id=None,
        aggregates=_aggregates(passed, failed, uncheckable),
        entries=list(entries),
        issues=list(issues),
    )


def _variant_set(*ids: str) -> ProjectVariantSet:
    descriptors = tuple(
        VariantDescriptor(variant_id=vid, path=Path(f"{vid}.s19"), file_type="s19")
        for vid in ids
    )
    return ProjectVariantSet(
        project_name="proj", variants=descriptors, active_id=ids[0]
    )


def _issue(code: str, message: str) -> ValidationIssue:
    return ValidationIssue(
        code=code,
        severity=ValidationSeverity.ERROR,
        message=message,
        artifact="changes",
    )


# ---------------------------------------------------------------------------
# LLR-007.4 — full-content generation on a 2-variant fixture
# ---------------------------------------------------------------------------


def test_full_report_content(tmp_path: Path) -> None:
    """All (a)-(d) section classes by heading; exact rows; saved_path.

    Intent: LLR-007.4 — the report carries header, inventory, overview,
    and the per-variant sections (modified files incl. ``saved_path``,
    exact per-modification rows, declaration errors, checklists,
    hexdumps) in the mandated order; (e) is absent when no cap fired.
    """
    mem_map = {addr: 0x55 for addr in range(0xFC0, 0x1060)}
    summary = _summary(
        [
            _applied_entry(0x1000, (0x01, 0x02), (0xAA, 0xBB), "mac-linked", "SYM_A"),
            _applied_entry(0x1010, (0x03, 0x04), (0xCC, 0xDD)),
        ],
        source="chg_a.json",
        issues=[_issue("CHG-COLLISION", "entries at 0x2000 and 0x2001 collide")],
        saved_path=Path("a-patched.s19"),
        variant_id="a",
    )
    check = _check(
        [
            CheckRunEntry("bytes", 0x1000, 0x1002, (0xAA, 0xBB), (0xAA, 0xBB), "pass", "standalone", None),
            CheckRunEntry("bytes", 0x1010, 0x1012, (0xEE, 0xEE), (0xCC, 0xDD), "fail", "a2l-linked", "TAG_B"),
        ],
        source="chk_a.json",
        issues=[_issue("CHG-ADDRESS-SYNTAX", "entry 3 address is malformed")],
    )
    results = [
        VariantExecutionResult(
            variant_id="a",
            status="ok",
            change_summaries=[summary],
            check_results=[check],
            mem_map=mem_map,
        ),
        VariantExecutionResult(variant_id="b", status="ok"),
    ]

    path = generate_project_report(
        tmp_path,
        results,
        ReportOptions(),
        variant_set=_variant_set("a", "b"),
        now_fn=_fixed_clock,
    )
    text = path.read_text(encoding="utf-8")

    # (a) header
    assert "# Project report: proj" in text
    assert f"- Generated (UTC): {FIXED_NOW.isoformat()}" in text
    assert "- Tool version: " in text
    assert "- Context bytes: 64" in text
    assert "- Execution mode: batch" in text
    assert "- Assignment source: default" in text
    # (b) inventory
    assert "## Variant inventory" in text
    assert "| a | a.s19 | s19 | yes |" in text
    assert "| b | b.s19 | s19 | no |" in text
    # (c) overview
    assert "## Consolidated overview" in text
    assert "| a | ok | 2 | 1 | 1 | 0 |" in text
    assert "| b | ok | 0 | 0 | 0 | 0 |" in text
    # (d) per-variant sections
    assert "## Variant: a" in text
    assert "## Variant: b" in text
    assert "### Modified files" in text
    assert "- chg_a.json (applied entries: 2) - saved as `a-patched.s19`" in text
    assert "### Modifications" in text
    assert "| 0x00001000 | 2 | 01 02 | AA BB | mac-linked | SYM_A |" in text
    assert "| 0x00001010 | 2 | 03 04 | CC DD | standalone | - |" in text
    assert "### Declaration errors" in text
    assert "- [CHG-COLLISION] error: entries at 0x2000 and 0x2001 collide" in text
    assert "- [CHG-ADDRESS-SYNTAX] error: entry 3 address is malformed" in text
    assert "### Checklists" in text
    assert "#### Checklist: chk_a.json" in text
    assert "Passed: 1 - Failed: 1 - Uncheckable: 0" in text
    assert "| 0x00001000 | 2 | AA BB | AA BB | pass |" in text
    assert "| 0x00001010 | 2 | EE EE | CC DD | fail |" in text
    # (d) hexdumps: both ±64 windows merge into one block
    assert "### Memory regions" in text
    assert "Window 0x00000FC0-0x00001060:" in text
    assert text.count("Window 0x") == 1
    # variant b has no execution payloads
    assert "No files were modified for this variant." in text
    assert "No change entries were executed for this variant." in text
    assert "No checklists were executed for this variant." in text
    assert "No modified regions." in text
    # (e) appendix only when a cap fired
    assert "## Truncation appendix" not in text
    assert "TRUNCATED" not in text


# ---------------------------------------------------------------------------
# LLR-007.5 — filename scheme + same-second collision
# ---------------------------------------------------------------------------


def test_filename_regex_and_same_second_collision(tmp_path: Path) -> None:
    """Injected fixed clock → base name, then zero-padded -01 counter.

    Intent: LLR-007.5 / F-Q-05 — one authoritative regex; a same-second
    collision inserts ``-NN`` before the suffix instead of overwriting.
    """
    options = ReportOptions()
    vset = _variant_set("a")
    results = [VariantExecutionResult(variant_id="a", status="ok")]

    first = generate_project_report(
        tmp_path, results, options, variant_set=vset, now_fn=_fixed_clock
    )
    second = generate_project_report(
        tmp_path, results, options, variant_set=vset, now_fn=_fixed_clock
    )

    assert first.name == "20260610T120000Z-report.md"
    assert second.name == "20260610T120000Z-01-report.md"
    assert REPORT_FILENAME_REGEX.match(first.name)
    assert REPORT_FILENAME_REGEX.match(second.name)
    assert first.parent == tmp_path / "reports"


# ---------------------------------------------------------------------------
# LLR-007.2 + F-Q-06 — window math: edges and merge
# ---------------------------------------------------------------------------


def test_window_math_region_at_address_zero() -> None:
    """MANDATORY edge fixture 1: the lower bound clamps at 0.

    Intent: F-Q-06 — ``align16(start - c)`` may go negative; the window
    must clamp at address 0, never underflow.
    """
    assert compute_hexdump_windows([(0x0, 0x4)], 64, 0x41) == [(0x0, 0x50)]


def test_window_math_region_at_image_top() -> None:
    """MANDATORY edge fixture 2: the upper bound clamps at align16_up(top).

    Intent: F-Q-06 — a region ending within ``context_bytes`` of the
    highest mapped address clamps at the aligned image top instead of
    dumping all-gap rows past it.
    """
    # image: highest mapped address 0x1009 → exclusive top 0x100A
    assert compute_hexdump_windows([(0x1000, 0x1004)], 64, 0x100A) == [
        (0xFC0, 0x1010)
    ]


def test_window_math_adjacent_windows_merge() -> None:
    """Two regions 16 bytes apart yield exactly one merged block.

    Intent: F-Q-06 merge rule — overlapping or touching row ranges merge
    so each row is dumped once; disjoint windows stay separate.
    """
    assert compute_hexdump_windows(
        [(0x100, 0x104), (0x114, 0x118)], 0, 0x200
    ) == [(0x100, 0x120)]
    assert compute_hexdump_windows(
        [(0x100, 0x104), (0x180, 0x184)], 0, 0x200
    ) == [(0x100, 0x110), (0x180, 0x190)]


def test_report_level_edge_windows(tmp_path: Path) -> None:
    """Both edge fixtures asserted on the generated document rows.

    Intent: LLR-007.2 — the rendered hexdump's first/last row addresses
    honor the clamped window bounds.
    """
    # region at address 0
    mem_low = {addr: 0x11 for addr in range(0x0, 0x41)}
    result_low = VariantExecutionResult(
        variant_id="a",
        status="ok",
        change_summaries=[_summary([_applied_entry(0x0, (0x00, 0x00, 0x00, 0x00), (0x10, 0x11, 0x12, 0x13))])],
        mem_map=mem_low,
    )
    path = generate_project_report(
        tmp_path, [result_low], ReportOptions(), variant_set=_variant_set("a"),
        now_fn=_fixed_clock,
    )
    text = path.read_text(encoding="utf-8")
    assert "Window 0x00000000-0x00000050:" in text
    assert "\n0x00000000  " in text

    # region at the image top (highest mapped address 0x1009)
    mem_top = {addr: 0x22 for addr in range(0x1000, 0x100A)}
    result_top = VariantExecutionResult(
        variant_id="a",
        status="ok",
        change_summaries=[_summary([_applied_entry(0x1000, (0x22, 0x22, 0x22, 0x22), (0x30, 0x31, 0x32, 0x33))])],
        mem_map=mem_top,
    )
    path2 = generate_project_report(
        tmp_path, [result_top], ReportOptions(), variant_set=_variant_set("a"),
        now_fn=lambda: datetime(2026, 6, 10, 12, 0, 1, tzinfo=timezone.utc),
    )
    text2 = path2.read_text(encoding="utf-8")
    assert "Window 0x00000FC0-0x00001010:" in text2
    assert "0x00001000  " in text2
    assert "0x00001010  " not in text2  # nothing past the aligned image top


# ---------------------------------------------------------------------------
# F-S-05 — context_bytes domain
# ---------------------------------------------------------------------------


def test_context_bytes_out_of_domain_rejected() -> None:
    """Out-of-domain context_bytes is ONE explicit error, never clamped.

    Intent: F-S-05 — the domain is 0..REPORT_CONTEXT_BYTES_MAX; values
    outside raise at construction so a report can never silently shrink
    or inflate its windows.
    """
    with pytest.raises(ValueError, match="not clamped"):
        ReportOptions(context_bytes=-1)
    with pytest.raises(ValueError, match="not clamped"):
        ReportOptions(context_bytes=REPORT_CONTEXT_BYTES_MAX + 1)
    assert ReportOptions(context_bytes=0).context_bytes == 0
    assert (
        ReportOptions(context_bytes=REPORT_CONTEXT_BYTES_MAX).context_bytes
        == REPORT_CONTEXT_BYTES_MAX
    )
    with pytest.raises(ValueError, match="execution_mode"):
        ReportOptions(execution_mode="everything")
    with pytest.raises(ValueError, match="assignment_source"):
        ReportOptions(assignment_source="guess")


# ---------------------------------------------------------------------------
# LLR-007.6 — cap firing markers with exact omitted counts
# ---------------------------------------------------------------------------


def test_region_cap_marker_exact_omitted_count(tmp_path: Path) -> None:
    """130 modified regions → marker states exactly 2 omitted + appendix.

    Intent: LLR-007.6 — a regions-per-variant cap firing is an explicit
    in-document marker with the exact omitted count, plus a truncation-
    appendix entry; never a silent cut.
    """
    total = REPORT_MAX_REGIONS_PER_VARIANT + 2
    entries = [
        _applied_entry(0x1000 + index * 0x100, (0x00,), (0xAA,))
        for index in range(total)
    ]
    mem_map = {entry.address_start: 0xAA for entry in entries}
    result = VariantExecutionResult(
        variant_id="a",
        status="ok",
        change_summaries=[_summary(entries)],
        mem_map=mem_map,
    )

    path = generate_project_report(
        tmp_path,
        [result],
        ReportOptions(context_bytes=0),
        variant_set=_variant_set("a"),
        now_fn=_fixed_clock,
    )
    text = path.read_text(encoding="utf-8")

    marker = (
        f"> TRUNCATED: 2 of {total} modified regions omitted "
        f"(cap: {REPORT_MAX_REGIONS_PER_VARIANT} regions per variant)."
    )
    assert marker in text
    assert "## Truncation appendix" in text
    assert (
        f"- Variant 'a': 2 of {total} modified regions omitted "
        f"(cap: {REPORT_MAX_REGIONS_PER_VARIANT} regions per variant)."
    ) in text
    assert text.count("Window 0x") == REPORT_MAX_REGIONS_PER_VARIANT


def test_total_bytes_cap_marker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A shrunken byte budget omits all blocks with the exact count.

    Intent: LLR-007.6 — the whole-document byte cap fires at hexdump-block
    granularity with an explicit marker and appendix entry.
    """
    monkeypatch.setattr(report_service, "REPORT_MAX_TOTAL_BYTES", 10)
    entries = [
        _applied_entry(0x1000 + index * 0x1000, (0x00,), (0xAA,))
        for index in range(3)
    ]
    mem_map = {entry.address_start: 0xAA for entry in entries}
    result = VariantExecutionResult(
        variant_id="a",
        status="ok",
        change_summaries=[_summary(entries)],
        mem_map=mem_map,
    )

    path = generate_project_report(
        tmp_path,
        [result],
        ReportOptions(context_bytes=0),
        variant_set=_variant_set("a"),
        now_fn=_fixed_clock,
    )
    text = path.read_text(encoding="utf-8")

    assert (
        "> TRUNCATED: 3 hexdump block(s) omitted "
        "(report size cap: 10 bytes)." in text
    )
    assert "## Truncation appendix" in text
    assert "Window 0x" not in text


# ---------------------------------------------------------------------------
# LLR-007.7 — reports/ created on demand, storage-neutral
# ---------------------------------------------------------------------------


def test_reports_dir_created_on_demand_stays_neutral(tmp_path: Path) -> None:
    """Generation creates reports/ and the project still validates.

    Intent: LLR-007.7 — the on-demand ``reports/`` tree never registers
    as project data (extends the E5a neutrality regression).
    """
    project_dir = tmp_path / ".s19tool" / "workarea" / "proj"
    project_dir.mkdir(parents=True)
    (project_dir / "fw.s19").write_text(
        "S107100001020304DE\nS9030000FC\n", encoding="utf-8"
    )
    assert not (project_dir / "reports").exists()

    path = generate_project_report(
        project_dir,
        [VariantExecutionResult(variant_id="fw", status="ok")],
        ReportOptions(),
        variant_set=_variant_set("fw"),
        now_fn=_fixed_clock,
    )

    assert path.parent == project_dir / "reports"
    data_files, a2l_files, error = validate_project_files(project_dir)
    assert error is None
    assert [item.name for item in data_files] == ["fw.s19"]
    assert a2l_files == []


# ---------------------------------------------------------------------------
# F-Q-07 pattern — headless guarantee
# ---------------------------------------------------------------------------


def test_generation_is_headless_no_app(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Report generation constructs no Textual App.

    Intent: LLR-008.4 / F-Q-07 — ``App.__init__`` is monkeypatched to
    raise for the duration of the call; generation must still succeed.
    """
    import textual.app

    def _boom(self, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        raise AssertionError("a Textual App was constructed during report generation")

    monkeypatch.setattr(textual.app.App, "__init__", _boom)

    path = generate_project_report(
        tmp_path,
        [VariantExecutionResult(variant_id="a", status="ok")],
        ReportOptions(),
        variant_set=_variant_set("a"),
        now_fn=_fixed_clock,
    )
    assert path.exists()


# ---------------------------------------------------------------------------
# LLR-007.3 / 007.8 — source inspections (F-Q-19)
# ---------------------------------------------------------------------------


def test_inspection_no_forbidden_symbols() -> None:
    """No Rich renderer, no parser classes, no Textual import.

    Intent: LLR-007.3 (plain-string renderer only) and LLR-007.8
    (before-values never re-parsed) verified statically against the
    service source.
    """
    source = Path(report_service.__file__).read_text(encoding="utf-8")
    assert "render_hex_view_text" not in source
    assert "S19File" not in source
    assert "IntelHexFile" not in source
    assert "import textual" not in source
    assert "from textual" not in source
    assert "from ..hexview import" in source
    assert "render_hex_view" in source


# ---------------------------------------------------------------------------
# LLR-007.8 — mem_map transport from the E6 execution layer
# ---------------------------------------------------------------------------


def test_execution_capture_feeds_report_end_to_end(tmp_path: Path) -> None:
    """capture_mem_maps=True pins post-change maps; report dumps them.

    Intent: LLR-007.8 — the report's hexdump input is each variant's
    post-change memory map riding ``VariantExecutionResult.mem_map``
    (additive E7 field); the patched byte appears in the generated dump.
    Capture off keeps ``mem_map`` ``None`` (LLR-006.3 profile preserved).
    """
    import json

    project_dir = tmp_path / ".s19tool" / "workarea" / "proj"
    project_dir.mkdir(parents=True)
    (project_dir / "fw.s19").write_text(
        "S107100001020304DE\nS9030000FC\n", encoding="utf-8"
    )
    change_path = project_dir / "chg.json"
    change_path.write_text(
        json.dumps(
            {
                "format": "s19app-changeset",
                "version": "2.0",
                "kind": "change",
                "encoding": "utf-8",
                "value_mode": "text",
                "entries": [
                    {"type": "bytes", "address": "0x1000", "bytes": "AA"}
                ],
            }
        ),
        encoding="utf-8",
    )
    data_files, _a2l, error = validate_project_files(project_dir)
    assert error is None
    vset = build_variant_set("proj", data_files)
    plan = plan_variant_executions(
        vset, None, scope=SCOPE_ALL, fallback_batch=[change_path]
    )

    plain = execute_variant_plan(plan, project_dir)
    assert plain[0].mem_map is None

    captured = execute_variant_plan(plan, project_dir, capture_mem_maps=True)
    assert captured[0].mem_map is not None
    assert captured[0].mem_map[0x1000] == 0xAA  # post-change value

    path = generate_project_report(
        project_dir,
        captured,
        ReportOptions(context_bytes=0),
        variant_set=vset,
        now_fn=_fixed_clock,
    )
    text = path.read_text(encoding="utf-8")
    assert "0x00001000  AA 02 03 04" in text


# ---------------------------------------------------------------------------
# LLR-007.6 measurement — slow, value verification per regime
# ---------------------------------------------------------------------------


@pytest.mark.slow
def test_measure_report_caps_on_large_s19(tmp_path: Path, large_s19: Path) -> None:
    """Measure report size/time on the large fixture (007.6 verification).

    Intent: LLR-007.6 — ``REPORT_MAX_*`` are ``assumed — verify
    per-regime``; this measures the default-context and max-context
    regimes against the 200-range × 4 KB ``make_large_s19`` image and
    prints the numbers consumed by the E7 review packet.
    """
    from s19_app.core import S19File as _Parser
    from s19_app.tui.services.load_service import build_loaded_s19

    loaded = build_loaded_s19(large_s19, _Parser(str(large_s19)), None, None)
    starts = sorted(start for start, _end in loaded.ranges)
    entries = [
        _applied_entry(start, (0x00, 0x00), (0xAA, 0xBB))
        for start in starts[:REPORT_MAX_REGIONS_PER_VARIANT]
    ]
    result = VariantExecutionResult(
        variant_id="stress",
        status="ok",
        change_summaries=[_summary(entries)],
        mem_map=loaded.mem_map,
    )
    vset = _variant_set("stress")

    for label, context in (("default", 64), ("max", REPORT_CONTEXT_BYTES_MAX)):
        started = time.perf_counter()
        path = generate_project_report(
            tmp_path / label,
            [result],
            ReportOptions(context_bytes=context),
            variant_set=vset,
            now_fn=_fixed_clock,
        )
        elapsed = time.perf_counter() - started
        size = path.stat().st_size
        text = path.read_text(encoding="utf-8")
        fired = "yes" if "report size cap" in text else "no"
        print(
            f"[007.6 measurement] context={label}({context}): "
            f"size={size} bytes, time={elapsed:.3f}s, "
            f"byte-cap fired={fired}, budget={REPORT_MAX_TOTAL_BYTES}"
        )
        assert size > 0
        # the document never silently exceeds budget by more than marker text
        if fired == "no":
            assert size <= REPORT_MAX_TOTAL_BYTES


# ---------------------------------------------------------------------------
# US-022 (batch-18) — classification legend in the generated report
# ---------------------------------------------------------------------------


def _legend_report_text(tmp_path: Path, **opts: object) -> str:
    """Generate a minimal one-variant report and return its text."""
    results = [VariantExecutionResult(variant_id="a", status="ok")]
    path = generate_project_report(
        tmp_path,
        results,
        ReportOptions(**opts),  # type: ignore[arg-type]
        variant_set=_variant_set("a"),
    )
    return path.read_text(encoding="utf-8")


def test_report_includes_legend_with_documented_rows(tmp_path: Path) -> None:
    """AT-022a — black-box: the produced report file carries the legend.

    Intent: observe the US-022 outcome through the SHIPPED surface
    (``generate_project_report`` → the report file on disk). Asserts the
    colour→MEANING pairing per row (m2 fold) — the documented meaning text
    of every ``LEGEND_TABLE`` row must appear, so a blank-meaning or
    colour-token-only legend fails. Single-source coupling: the expectation
    reads ``LEGEND_TABLE``, so the table and the report move together.
    """
    text = _legend_report_text(tmp_path)
    assert "## Legend" in text
    for artifact, rows in LEGEND_TABLE.items():
        assert f"### {artifact}" in text, f"missing legend heading for {artifact}"
        for classification, (_colour, meaning) in rows.items():
            assert classification in text, f"missing {artifact} row {classification!r}"
            assert meaning in text, f"missing meaning for {artifact}/{classification}"


def test_report_omits_legend_when_disabled(tmp_path: Path) -> None:
    """AT-022b — negative: ``include_legend=False`` removes the section.

    Proves present/absent discrimination — the legend is gated, not an
    always-on string. A representative documented meaning is absent too.
    """
    text = _legend_report_text(tmp_path, include_legend=False)
    assert "## Legend" not in text
    sample_meaning = LEGEND_TABLE["MAC"]["Orange"][1]
    assert sample_meaning not in text


def test_legend_lines_renders_shared_table() -> None:
    """TC-022.1 — ``_legend_lines`` renders every ``LEGEND_TABLE`` row.

    White-box: the helper reads the shared table (single source, not a
    duplicated literal) and opens with the ``## Legend`` heading.
    """
    blob = "\n".join(report_service._legend_lines())
    assert blob.startswith("## Legend")
    for rows in LEGEND_TABLE.values():
        for _classification, (_colour, meaning) in rows.items():
            assert meaning in blob


def test_include_legend_default_true_and_validated() -> None:
    """TC-022.2 — ``include_legend`` defaults True and is domain-validated.

    Matches the file's strict-validation contract (one explicit
    ``ValueError`` per field, never a silent coercion).
    """
    assert ReportOptions().include_legend is True
    assert ReportOptions(include_legend=False).include_legend is False
    with pytest.raises(ValueError):
        ReportOptions(include_legend="yes")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# US-020d (batch-19) — issue rendering enrichment (LLR-025.1 / HLR-025)
# ---------------------------------------------------------------------------


def _enriched_issue(
    message: str,
    *,
    address: Optional[int] = None,
    symbol: Optional[str] = None,
    related: Sequence[str] = (),
) -> ValidationIssue:
    """A ValidationIssue carrying the optional address/symbol/related fields."""
    return ValidationIssue(
        code="X-ENRICH",
        severity=ValidationSeverity.ERROR,
        message=message,
        artifact="changes",
        symbol=symbol,
        address=address,
        related_artifacts=list(related),
    )


def _report_with_issue(tmp_path: Path, issue: ValidationIssue) -> str:
    """Generate a one-variant report whose change-summary carries ``issue``."""
    summary = _summary([], issues=[issue], variant_id="a")
    results = [
        VariantExecutionResult(
            variant_id="a", status="ok", change_summaries=[summary]
        )
    ]
    path = generate_project_report(
        tmp_path, results, ReportOptions(), variant_set=_variant_set("a"),
    )
    return path.read_text(encoding="utf-8")


def _issue_line(text: str, needle: str) -> str:
    """The single report line carrying ``needle`` (the issue's message)."""
    return next(line for line in text.splitlines() if needle in line)


def test_report_issue_line_shows_address_symbol_related(tmp_path: Path) -> None:
    """AT-025a — black-box: a rendered issue carrying address/symbol/related
    shows all three through the produced report file (HLR-025).

    Intent: the report's Declaration-errors line is enriched beyond
    code/severity/message. Observed through `generate_project_report` → the
    report file on disk; asserts the content, not mere presence.
    """
    issue = _enriched_issue(
        "enriched issue", address=0x80040000, symbol="CAL_MAP", related=["a2l", "mac"]
    )
    line = _issue_line(_report_with_issue(tmp_path, issue), "enriched issue")
    assert "@ 0x80040000" in line
    assert "symbol=CAL_MAP" in line
    assert "related=a2l,mac" in line


def test_report_issue_without_address_has_no_hex(tmp_path: Path) -> None:
    """AT-025b — negative: an issue with no address shows no `@0x` (nor empty
    `symbol=`/`related=`), proving present/absent discrimination (C-10)."""
    issue = _enriched_issue("bare issue")  # address/symbol None, related empty
    line = _issue_line(_report_with_issue(tmp_path, issue), "bare issue")
    assert "@ 0x" not in line
    assert "symbol=" not in line
    assert "related=" not in line


def test_report_issue_address_zero_renders(tmp_path: Path) -> None:
    """TC-025.1 — boundary: `address == 0` renders `@ 0x0` (not suppressed by
    a truthiness test on the address)."""
    line = _issue_line(
        _report_with_issue(tmp_path, _enriched_issue("zero addr", address=0)),
        "zero addr",
    )
    assert "@ 0x0" in line


# ---------------------------------------------------------------------------
# US-020c (batch-19) — declared-region report addendum (LLR-024.2 / HLR-024)
# ---------------------------------------------------------------------------


def _report_with_regions(
    tmp_path: Path,
    regions: Sequence[DeclaredRegion],
    summary: ChangeSummary,
) -> str:
    """Generate a one-variant report carrying ``summary`` + declared regions."""
    results = [
        VariantExecutionResult(
            variant_id="a", status="ok", change_summaries=[summary]
        )
    ]
    path = generate_project_report(
        tmp_path,
        results,
        ReportOptions(declared_regions=tuple(regions)),
        variant_set=_variant_set("a"),
    )
    return path.read_text(encoding="utf-8")


def test_addendum_lists_region_with_mods_and_issues(tmp_path: Path) -> None:
    """AT-024a — black-box: the report addendum lists a declared region and the
    modifications + issues whose address falls inside it (through the file)."""
    region = DeclaredRegion("calzone", 0x1000, 0x10FF)
    summary = _summary(
        [_applied_entry(0x1000, (0x01,), (0xAA,))],
        issues=[_enriched_issue("inside issue", address=0x1050)],
        variant_id="a",
    )
    text = _report_with_regions(tmp_path, [region], summary)
    assert "## Addendum: declared regions" in text
    assert "calzone" in text
    assert "modification @ 0x1000" in text
    assert "issue [X-ENRICH] @ 0x1050" in text


def test_addendum_region_with_no_hits_shows_none(tmp_path: Path) -> None:
    """AT-024b — boundary: a declared region with nothing inside renders an
    explicit 'None.' under its sub-heading."""
    region = DeclaredRegion("empty_zone", 0x9000, 0x90FF)
    summary = _summary([_applied_entry(0x1000, (0x01,), (0xAA,))], variant_id="a")
    addendum = _report_with_regions(tmp_path, [region], summary).split(
        "## Addendum: declared regions", 1
    )[1]
    assert "empty_zone" in addendum
    assert "None." in addendum
    assert "0x1000" not in addendum  # the out-of-region modification is not listed


def test_addendum_membership_inclusive_at_bounds(tmp_path: Path) -> None:
    """TC-024.4 — inclusive [start,end]: a modification at exactly start and at
    exactly end is in-region; one past end is excluded (architect-M1)."""
    region = DeclaredRegion("edge", 0x2000, 0x2010)
    summary = _summary(
        [
            _applied_entry(0x2000, (0x01,), (0xAA,)),  # at start (inclusive)
            _applied_entry(0x2010, (0x01,), (0xBB,)),  # at end (inclusive)
            _applied_entry(0x2011, (0x01,), (0xCC,)),  # just past end (excluded)
        ],
        variant_id="a",
    )
    addendum = _report_with_regions(tmp_path, [region], summary).split(
        "## Addendum", 1
    )[1]
    assert "modification @ 0x2000" in addendum
    assert "modification @ 0x2010" in addendum
    assert "0x2011" not in addendum


def test_addendum_and_issue_render_use_same_address(tmp_path: Path) -> None:
    """TC-S3 — single-source anti-drift: an issue's address appears in BOTH the
    enriched Declaration-errors line (LLR-025.1) and the addendum membership
    (LLR-024.2); both read the same ``ValidationIssue.address``."""
    region = DeclaredRegion("zone", 0x3000, 0x30FF)
    summary = _summary(
        [], issues=[_enriched_issue("shared issue", address=0x3040)], variant_id="a"
    )
    text = _report_with_regions(tmp_path, [region], summary)
    assert "shared issue @ 0x3040" in text  # enriched declaration-errors (LLR-025.1)
    assert "issue [X-ENRICH] @ 0x3040" in text  # addendum membership (LLR-024.2)


# ---------------------------------------------------------------------------
# US-037 (batch-26) — per-variant entropy section in the project report
# (HLR-037 / LLR-037.1..037.3). The known-profile image is the AT-035c mixed
# image: a 256-byte constant ``0x00`` run (→ constant/padding, H=0.0) plus a
# 256-byte 0..255 permutation run (→ high/random, H=8.0), separated by a gap.
# ---------------------------------------------------------------------------

# Mixed known-entropy image: constant run + max-entropy run + unmapped gap.
_ENTROPY_CONST_BASE = 0x3000
_ENTROPY_RANDOM_BASE = 0x4000
_ENTROPY_MIXED_MEM_MAP = {
    **{_ENTROPY_CONST_BASE + i: 0x00 for i in range(256)},
    **{_ENTROPY_RANDOM_BASE + i: i for i in range(256)},
}


def _entropy_captured_result(
    project_dir: Path,
) -> "tuple[VariantExecutionResult, ProjectVariantSet]":
    """Run the SHIPPED variant chain over the mixed image with capture on.

    Builds the AT-035c mixed image on disk via ``emit_s19_from_mem_map``,
    loads + executes it through the real variant-execution chain with
    ``capture_mem_maps=True`` so the returned ``VariantExecutionResult.mem_map``
    is populated by the shipped plumbing (QR-4) — NOT hand-set on the fixture.
    The change is a no-op single byte re-write of an already-present value, so
    the captured post-change ``mem_map`` equals the mixed image.
    """
    import json

    from s19_app.tui.changes.io import emit_s19_from_mem_map

    ranges = [
        (_ENTROPY_CONST_BASE, _ENTROPY_CONST_BASE + 256),
        (_ENTROPY_RANDOM_BASE, _ENTROPY_RANDOM_BASE + 256),
    ]
    project_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "fw.s19").write_text(
        emit_s19_from_mem_map(_ENTROPY_MIXED_MEM_MAP, ranges), encoding="utf-8"
    )
    change_path = project_dir / "chg.json"
    change_path.write_text(
        json.dumps(
            {
                "format": "s19app-changeset",
                "version": "2.0",
                "kind": "change",
                "encoding": "utf-8",
                "value_mode": "text",
                # re-write an existing byte to its own value: no image change,
                # so the captured post-change map == the mixed image.
                "entries": [
                    {"type": "bytes", "address": hex(_ENTROPY_CONST_BASE), "bytes": "00"}
                ],
            }
        ),
        encoding="utf-8",
    )
    data_files, _a2l, error = validate_project_files(project_dir)
    assert error is None
    vset = build_variant_set("proj", data_files)
    plan = plan_variant_executions(
        vset, None, scope=SCOPE_ALL, fallback_batch=[change_path]
    )
    captured = execute_variant_plan(plan, project_dir, capture_mem_maps=True)
    return captured[0], vset


def test_report_contains_entropy_section_on_disk(tmp_path: Path) -> None:
    """AT-037a — GATE (C-12 output-then-consume): the WRITTEN report file
    carries the per-variant entropy section with the expected band lines.

    Intent (LLR-037.2 + LLR-037.3): drive the shipped report handler over a
    variant whose ``mem_map`` was populated by the real execution chain with
    ``capture_mem_maps=True`` (precondition-asserted non-empty BEFORE
    generating — QR-4, proves the capture plumbing not just the formatter),
    then RE-READ the file at the path the handler wrote (``report_service``
    ``:1163``) and assert the ``### Entropy`` heading plus a ``constant/padding``
    band line AND a ``high/random`` band line are present. Not a direct
    ``_entropy_lines`` call, not a glob-reconstruct.
    """
    project_dir = tmp_path / ".s19tool" / "workarea" / "proj"
    result, vset = _entropy_captured_result(project_dir)

    # Precondition (QR-4): the shipped chain populated mem_map end-to-end.
    assert result.mem_map, "capture_mem_maps=True must populate result.mem_map"
    assert result.mem_map[_ENTROPY_CONST_BASE] == 0x00
    assert result.mem_map[_ENTROPY_RANDOM_BASE + 255] == 255

    path = generate_project_report(
        project_dir,
        [result],
        ReportOptions(context_bytes=0),
        variant_set=vset,
        now_fn=_fixed_clock,
    )
    text = path.read_text(encoding="utf-8")

    # Scope to this variant's block (single variant here).
    assert "## Variant:" in text
    variant_block = text.split("## Variant:", 1)[1]
    assert "### Entropy" in variant_block
    assert "**constant/padding**" in variant_block  # the 0x00 run
    assert "**high/random**" in variant_block  # the 0..255 permutation run


def test_report_omits_entropy_when_disabled_byte_identical(tmp_path: Path) -> None:
    """AT-037b — branch-completeness (per-branch C-10): ``include_entropy=False``
    removes the section and yields a report byte-for-byte identical to the
    pre-feature baseline — i.e. the flag suppresses ONLY the entropy block and
    adds zero incidental drift elsewhere.

    The US-037 counterfactual is carried by AT-037a (absent-on-pre-fix-tree);
    AT-037b proves the flag is a pure suppressor. The load-bearing assert takes
    the ``include_entropy=True`` report, removes EXACTLY the entropy block the
    shipped builder emits for the variant (``_entropy_lines(result)``, joined
    verbatim), and asserts the remainder equals the ``include_entropy=False``
    report BYTE-FOR-BYTE. That block is the only thing the flag adds, so
    on-minus-block == off proves the off-branch reproduces the pre-feature
    bytes with no drift in any surrounding section. Both reports use a fixed
    clock + fixed filename so nothing else can differ.
    """
    project_dir = tmp_path / ".s19tool" / "workarea" / "proj"
    result, vset = _entropy_captured_result(project_dir)
    assert result.mem_map  # capture precondition

    def _gen(dest: Path, *, include_entropy: bool) -> bytes:
        path = generate_project_report(
            dest,
            [result],
            ReportOptions(context_bytes=0, include_entropy=include_entropy),
            variant_set=vset,
            now_fn=_fixed_clock,
        )
        return path.read_bytes()

    off_bytes = _gen(tmp_path / "off", include_entropy=False)
    reference_bytes = _gen(tmp_path / "ref", include_entropy=False)
    on_bytes = _gen(tmp_path / "on", include_entropy=True)
    on_text = on_bytes.decode("utf-8")
    off_text = off_bytes.decode("utf-8")

    # Section absent when disabled.
    assert "### Entropy" not in off_text
    # Present when enabled (discriminates present/absent, not vacuous).
    assert "### Entropy" in on_text

    # The EXACT block the shipped builder emits for this variant. The report
    # is written with the platform newline (CRLF on Windows), so join with the
    # newline the written file actually uses — matched to the on-disk bytes.
    newline = "\r\n" if b"\r\n" in on_bytes else "\n"
    entropy_block = newline.join(report_service._entropy_lines(result))
    assert entropy_block in on_text  # precise block, not a fuzzy heading match

    # generate_project_report appends the block to the flat line list, so on
    # disk it is preceded by one separator joining it to the prior line. Strip
    # that leading separator with the block so removal leaves no doubled gap.
    on_minus_block = on_text.replace(newline + entropy_block, "", 1)

    # LOAD-BEARING: on-minus-entropy-block == off, byte-for-byte. Proves the
    # flag adds ONLY the entropy block and zero incidental drift elsewhere.
    assert on_minus_block == off_text

    # Determinism guard (kept): two disabled generations are byte-identical.
    assert off_bytes == reference_bytes


def test_entropy_lines_shape_direct_call() -> None:
    """TC-037.1 — GUARD (NOT the gate): ``_entropy_lines(result)`` returns the
    documented markdown shape (``### Entropy`` heading + per-band count bullets)
    for a variant with a known mixed mem_map. Consumer-contract only; the C-12
    gate re-reads the written file (AT-037a).
    """
    result = VariantExecutionResult(
        variant_id="v", status="ok", mem_map=dict(_ENTROPY_MIXED_MEM_MAP)
    )
    lines = report_service._entropy_lines(result)
    assert lines[0] == "### Entropy"
    blob = "\n".join(lines)
    # Two full windows → one constant/padding + one high/random bullet.
    assert "- **constant/padding**: 1 window(s)" in blob
    assert "- **high/random**: 1 window(s)" in blob
    # Band-summary only — no raw byte values dumped by this builder.
    assert "0x00" not in blob.lower() or "0x" not in blob  # no address/byte dump


def test_entropy_lines_empty_mem_map_no_crash() -> None:
    """TC-037.1 (edge) / LLR-037.2 — a variant with no mapped bytes returns the
    heading plus a 'no data' line, never a crash."""
    for mem_map in (None, {}):
        result = VariantExecutionResult(
            variant_id="v", status="ok", mem_map=mem_map
        )
        lines = report_service._entropy_lines(result)
        assert lines[0] == "### Entropy"
        assert any("not computed" in line for line in lines)


def test_include_entropy_default_true_and_validated() -> None:
    """TC-037.2 — ``include_entropy`` defaults True and is domain-validated
    (one explicit ``ValueError``, never coerced — mirrors ``include_legend``).
    """
    assert ReportOptions().include_entropy is True
    assert ReportOptions(include_entropy=False).include_entropy is False
    with pytest.raises(ValueError):
        ReportOptions(include_entropy="x")  # type: ignore[arg-type]


def test_include_entropy_false_not_emitted(tmp_path: Path) -> None:
    """TC-037.2 — with ``include_entropy=False`` the entropy heading is not
    emitted into the produced file (option gates emission)."""
    project_dir = tmp_path / ".s19tool" / "workarea" / "proj"
    result, vset = _entropy_captured_result(project_dir)
    path = generate_project_report(
        project_dir,
        [result],
        ReportOptions(context_bytes=0, include_entropy=False),
        variant_set=vset,
        now_fn=_fixed_clock,
    )
    assert "### Entropy" not in path.read_text(encoding="utf-8")


def test_entropy_section_charged_against_budget(tmp_path: Path) -> None:
    """TC-037.3 — the entropy section is routed through the budget-charged
    ``emit`` helper: enabling it grows the produced file (the lines land in the
    budgeted ``lines`` list like the header/legend/overview sections), i.e. no
    unbudgeted side-channel. Observed as a strict size increase of the written
    file when the only differing option is ``include_entropy``.
    """
    project_dir = tmp_path / ".s19tool" / "workarea" / "proj"
    result, vset = _entropy_captured_result(project_dir)

    def _size(dest: Path, *, include_entropy: bool) -> int:
        path = generate_project_report(
            dest,
            [result],
            ReportOptions(context_bytes=0, include_entropy=include_entropy),
            variant_set=vset,
            now_fn=_fixed_clock,
        )
        return path.stat().st_size

    off = _size(tmp_path / "off", include_entropy=False)
    on = _size(tmp_path / "on", include_entropy=True)
    assert on > off  # section lands in the budgeted line list


def test_entropy_section_confidentiality_no_raw_bytes_or_logging(
    tmp_path: Path,
) -> None:
    """TC-037.4 — confidentiality: the entropy section reports bands/counts only
    (no raw byte values beyond what the hexdump already emits); the report lands
    ONLY under the gitignored ``reports/`` tree; the module adds no new logging.
    """
    project_dir = tmp_path / ".s19tool" / "workarea" / "proj"
    result, vset = _entropy_captured_result(project_dir)
    path = generate_project_report(
        project_dir,
        [result],
        ReportOptions(context_bytes=0),
        variant_set=vset,
        now_fn=_fixed_clock,
    )
    # Report lands under the gitignored reports/ tree (F-S-07).
    assert path.parent.name == report_service.REPORTS_DIR_NAME

    # The entropy builder emits band summary lines only — no raw byte dump.
    entropy_block = "\n".join(report_service._entropy_lines(result))
    assert "constant/padding" in entropy_block
    # No hex byte pairs / address rows in the band summary itself.
    assert "0x" not in entropy_block

    # The module performs no logging at all (F-S-07 confidentiality contract).
    source = Path(report_service.__file__).read_text(encoding="utf-8")
    assert "import logging" not in source
    assert "getLogger" not in source


# ---------------------------------------------------------------------------
# batch-33 TC-051.5 (report half) — blocked runs keep the Checklists table
# rendering: {0,0,N} with enumerated rows, and the zero-entry {0,0,0}
# envelope-fault boundary renders an empty table without fault.
# ---------------------------------------------------------------------------


def test_tc051_5_blocked_runs_render_checklists(tmp_path: Path) -> None:
    blocked_with_rows = CheckRunResult(
        source_path=Path("blocked.json"),
        timestamp_utc="2026-07-09T00:00:00+00:00",
        variant_id=None,
        aggregates=_aggregates(0, 0, 2),
        entries=[
            CheckRunEntry(
                "bytes", 0x100, 0x102, (0xAA, 0xBB), None, "uncheckable",
                "standalone", None, reason_code="doc-kind",
                reason="run blocked [doc-kind]",
            ),
            CheckRunEntry(
                "bytes", 0x104, 0x105, (0xCC,), None, "uncheckable",
                "standalone", None, reason_code="doc-kind",
                reason="run blocked [doc-kind]",
            ),
        ],
        run_blocked_reason_code="doc-kind",
        run_blocked_reason="this is a change-set (kind 'change'), not a "
        "check-set — Run checks needs kind 'check'",
    )
    zero_entry_blocked = CheckRunResult(
        source_path=Path("envelope.json"),
        timestamp_utc="2026-07-09T00:00:00+00:00",
        variant_id=None,
        aggregates=_aggregates(0, 0, 0),
        run_blocked_reason_code="doc-fault",
        run_blocked_reason="document carries 1 error-severity declaration "
        "fault(s) [MF-BAD-STRUCTURE] — fix the document before running "
        "checks",
    )
    results = [
        VariantExecutionResult(
            variant_id="a",
            status="ok",
            check_results=[blocked_with_rows, zero_entry_blocked],
        ),
    ]
    path = generate_project_report(
        tmp_path,
        results,
        ReportOptions(),
        variant_set=_variant_set("a"),
        now_fn=_fixed_clock,
    )
    text = path.read_text(encoding="utf-8")
    assert "Checklists" in text
    # {0,0,N}: the blocked run's aggregates line + both enumerated rows.
    assert "Passed: 0 - Failed: 0 - Uncheckable: 2" in text
    assert text.count("| uncheckable |") == 2
    # The zero-entry {0,0,0} envelope-fault boundary renders its header +
    # aggregates line with an empty table, without fault.
    assert "#### Checklist: envelope.json" in text
    assert "Passed: 0 - Failed: 0 - Uncheckable: 0" in text


# ---------------------------------------------------------------------------
# Batch-35 Inc-3 — TC-314 / TC-315: filtered project-report surfaces
# (LLR-055.1 / LLR-055.2 / LLR-054.3)
# ---------------------------------------------------------------------------


def _resolved_matcher(filter_json: str, name: str = "tc314-filter.json"):
    """Parse ``filter_json`` and resolve it into a named matcher.

    Resolution runs with EMPTY artifact record lists — TC-314 exercises the
    branch (a)/(b) item semantics through the report surfaces; branch (c)
    record extents are TC-310 territory (test_report_filter.py). The
    ``source_name`` kwarg is the Inc-3 declared-field promotion (Inc-2
    review handoff): the audit header must render this exact name.
    """
    parsed, errors = parse_report_filter(filter_json)
    assert not errors, f"fixture filter must parse cleanly, got {errors}"
    return resolve_report_filter(parsed, [], [], source_name=name)


_TC314_FILTER_JSON = (
    '{"format": "s19app-report-filter", "version": "1.0",'
    ' "include": {"symbols": ["CAL_*"],'
    ' "addresses": [{"start": "0x1000", "end": "0x1002"}]}}'
)

_TC314_ZERO_MATCH_JSON = (
    '{"format": "s19app-report-filter", "version": "1.0",'
    ' "include": {"symbols": [],'
    ' "addresses": [{"start": "0x9000", "end": "0x9010"}]}}'
)


def _tc314_results() -> list[VariantExecutionResult]:
    """The TC-314 two-entry / three-check fixture (LLR-055.2 boundaries).

    Modifications: E1 at [0x1000,0x1002) matches the filter RANGE; E2 at
    [0x2000,0x2002) matches nothing. Checklist rows: C1 at [0x1000,0x1002)
    matches by range; C2 at [0x0FFE,0x1000) ends EXACTLY at the filter
    range start — end-exclusive semantics say NO match; C3 carries
    ``linkage_symbol="CAL_TEMP"`` with its range outside every filter
    range — the F-02 symbol branch must still match it.
    """
    mem_map = {addr: 0x55 for addr in range(0x1000, 0x1010)}
    mem_map.update({addr: 0x66 for addr in range(0x2000, 0x2010)})
    summary = _summary(
        [
            _applied_entry(0x1000, (0x01, 0x02), (0xAA, 0xBB), "mac-linked", "SYM_A"),
            _applied_entry(0x2000, (0x03, 0x04), (0xCC, 0xDD)),
        ],
        variant_id="a",
    )
    check = _check(
        [
            CheckRunEntry(
                "bytes", 0x1000, 0x1002, (0xAA, 0xBB), (0xAA, 0xBB),
                "pass", "standalone", None,
            ),
            CheckRunEntry(
                "bytes", 0x0FFE, 0x1000, (0x11, 0x22), (0x33, 0x44),
                "fail", "standalone", None,
            ),
            CheckRunEntry(
                "bytes", 0x3000, 0x3002, (0x01, 0x02), (0x01, 0x02),
                "pass", "a2l-linked", "CAL_TEMP",
            ),
        ]
    )
    return [
        VariantExecutionResult(
            variant_id="a",
            status="ok",
            change_summaries=[summary],
            check_results=[check],
            mem_map=mem_map,
        )
    ]


def test_tc314_filtered_sections_and_audit_header(tmp_path: Path) -> None:
    """TC-314 — LLR-055.2 (a)/(b)/(c) + LLR-054.3 header position/counts.

    Intent: a filter matching one of two modification entries restricts
    ALL THREE filtered surfaces (Modifications rows, Checklists rows,
    Memory-regions hexdump windows) to matching items only, under an
    audit header that (S-F6) is the FIRST block after the report title
    and whose per-section shown+hidden equals the pre-filter count.
    Boundary pins: a check row whose range ENDS exactly at a filter
    range start does NOT match (end-exclusive); a check row matched ONLY
    by its ``linkage_symbol`` glob (range outside every filter range)
    DOES match (F-02 branch).
    """
    matcher = _resolved_matcher(_TC314_FILTER_JSON)
    path = generate_project_report(
        tmp_path,
        _tc314_results(),
        ReportOptions(context_bytes=0, report_filter=matcher),
        variant_set=_variant_set("a"),
        now_fn=_fixed_clock,
    )
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()

    # Audit header: FIRST block after the title (S-F6), fixed format.
    assert lines[0] == "# Project report: proj"
    assert lines[1] == ""
    assert lines[2] == "## Report filter applied", (
        "TC-314: the audit header must be the first block after the title"
    )
    assert "- Filter file: tc314-filter.json" in text
    assert "- Modifications rows: shown 1 of 2 (hidden 1)" in text
    assert "- Checklist rows: shown 2 of 3 (hidden 1)" in text
    assert "- Applied regions: shown 1 of 2 (hidden 1)" in text

    # Modifications: matched row present, unmatched absent.
    assert "| 0x00001000 | 2 | 01 02 | AA BB | mac-linked | SYM_A |" in text
    assert "| 0x00002000" not in text, (
        "TC-314: the unmatched modification row must be absent"
    )

    # Checklists: range-matched row present; end-exclusive boundary row
    # absent; symbol-matched (F-02) row present despite its range.
    assert "| 0x00001000 | 2 | AA BB | AA BB | pass |" in text
    assert "| 0x00000FFE" not in text, (
        "TC-314: a check row ending exactly at a filter range start must "
        "NOT match (end-exclusive semantics)"
    )
    assert "| 0x00003000 | 2 | 01 02 | 01 02 | pass |" in text, (
        "TC-314: a check row matched only by linkage_symbol glob must "
        "still render (F-02 branch)"
    )

    # Memory regions: only the matched region seeds a window (D-5
    # filter-before-window); the unmatched region's window is absent.
    assert "Window 0x00001000-0x00001010:" in text
    assert "Window 0x00002000" not in text
    assert text.count("Window 0x") == 1

    # Whole sections stay complete (D-2): inventory + overview untouched.
    assert "## Variant inventory" in text
    assert "## Consolidated overview" in text


def test_tc314_zero_match_notice_report_still_written(tmp_path: Path) -> None:
    """TC-314 — LLR-054.3 zero-match: notice bodies, report on disk.

    Intent: a VALID filter matching zero items still writes the report
    (D-3 — never a silently empty/missing file); each filtered section's
    body is replaced by the loud ``filter matched 0 of N items`` notice
    with N = that section's pre-filter count; the audit header shows
    ``shown 0``.
    """
    matcher = _resolved_matcher(_TC314_ZERO_MATCH_JSON, "zero.json")
    path = generate_project_report(
        tmp_path,
        _tc314_results(),
        ReportOptions(context_bytes=0, report_filter=matcher),
        variant_set=_variant_set("a"),
        now_fn=_fixed_clock,
    )
    assert path.is_file() and path.stat().st_size > 0, (
        "TC-314: a zero-match filter must still write a non-empty report"
    )
    text = path.read_text(encoding="utf-8")
    assert "- Filter file: zero.json" in text
    assert "- Modifications rows: shown 0 of 2 (hidden 2)" in text
    assert "- Checklist rows: shown 0 of 3 (hidden 3)" in text
    assert "- Applied regions: shown 0 of 2 (hidden 2)" in text
    # Section bodies replaced by the notice (mods + regions share N=2).
    assert text.count("filter matched 0 of 2 items") == 2
    assert text.count("filter matched 0 of 3 items") == 1
    # No filtered row or window leaks through.
    assert "| 0x00001000" not in text
    assert "| 0x00002000" not in text
    assert "Window 0x" not in text


def test_tc314_unfiltered_output_identical_with_and_without_kwarg(
    tmp_path: Path,
) -> None:
    """TC-314 — LLR-055.3 direct arm: no-kwarg == report_filter=None bytes.

    Intent: the unfiltered path takes NO new code path — options built
    without the ``report_filter`` kwarg and with an explicit ``None``
    produce byte-identical reports (the golden AT-055b guards the
    base-revision identity; this is the cheap in-tree equality arm).
    """
    dir_a = tmp_path / "a"
    dir_b = tmp_path / "b"
    results = _tc314_results()
    vset = _variant_set("a")
    path_a = generate_project_report(
        dir_a, results, ReportOptions(context_bytes=0),
        variant_set=vset, now_fn=_fixed_clock,
    )
    path_b = generate_project_report(
        dir_b, results, ReportOptions(context_bytes=0, report_filter=None),
        variant_set=vset, now_fn=_fixed_clock,
    )
    text_a = path_a.read_bytes()
    assert text_a == path_b.read_bytes(), (
        "TC-314: report_filter=None must be byte-identical to the "
        "kwarg-absent construction"
    )
    assert b"Report filter applied" not in text_a, (
        "TC-314: an UNFILTERED report must carry no audit header"
    )


def test_tc315_report_filter_option_type_validation(tmp_path: Path) -> None:
    """TC-315 — LLR-055.1: wrong-type report_filter → exactly one ValueError.

    Intent: the frozen-dataclass one-fault pattern extends to the new
    field — a non-matcher value is REJECTED at construction (never
    coerced), ``None`` (the default) and a real resolved matcher are
    both accepted.
    """
    with pytest.raises(ValueError, match="report_filter"):
        ReportOptions(report_filter="bogus")
    with pytest.raises(ValueError, match="report_filter"):
        ReportOptions(report_filter=42)
    # None default + explicit None + a real matcher are all valid.
    assert ReportOptions().report_filter is None
    assert ReportOptions(report_filter=None).report_filter is None
    matcher = _resolved_matcher(_TC314_FILTER_JSON)
    assert ReportOptions(report_filter=matcher).report_filter is matcher
