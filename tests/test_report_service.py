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
