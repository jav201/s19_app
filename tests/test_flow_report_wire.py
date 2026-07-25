"""FB-P1b (batch-60) flow-run report generation — run_flow wire tests (Inc-2).

Layer-B integration ATs driving the SHIPPED `run_flow` seam: a report-bearing
flow must write a real file under `<project>/reports/`, and that file must be
visible to the shipped consumer (`report_service.list_project_reports`) — the
C-12 output-then-consume shape, observing the handler-produced artifact.

Each AT pins one operator decision so the opposite implementation goes RED:
D-1 (AT-006 no block ⇒ no report), D-2 (AT-005 positional), D-3 (AT-002 the
shipped list sees it), D-4 (AT-007 N independent reports), D-6 (AT-009 an
ABORTED run still writes — the decision that was unimplementable before AMD-3).
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from s19_app.tui.screens import _hardened_markdown_parser
from s19_app.tui.services import flow_report_service as frs
from s19_app.tui.services.flow_execution_service import run_flow
from s19_app.tui.services.flow_model import (
    BLOCK_STATUS_ERROR,
    BLOCK_STATUS_OK,
    BLOCK_STATUS_SKIPPED,
    CrcBlock,
    Flow,
    FlowContext,
    ReportBlock,
    SourceBlock,
    WriteOutBlock,
)
from s19_app.tui.services.report_service import (
    REPORT_FILENAME_REGEX,
    list_project_reports,
)
from tests.test_flow_execution_service import _S19_CLEAN, _make_project


def _reports(project: Path) -> list:
    d = project / "reports"
    return sorted(d.glob("*.md")) if d.is_dir() else []


def _read(path: Path) -> str:
    """UTF-8 read — the report is written UTF-8 and this box defaults to cp1252."""
    return path.read_text(encoding="utf-8")


def _rendered(path: Path) -> str:
    """The report as the READER sees it — markdown escapes resolved.

    Block kinds carry underscores (``write_out``) which `_md_safe` escapes to
    ``WRITE\\_OUT`` in the source; asserting on the rendered text is both the
    user-facing claim and immune to escape-set changes.
    """
    from markdown_it import MarkdownIt

    return MarkdownIt("gfm-like").render(_read(path))


@pytest.fixture
def project(tmp_path: Path) -> Path:
    return _make_project(tmp_path, {"prg.s19": _S19_CLEAN})


# --------------------------------------------------------------------------- #
# AT-001 — a report-bearing flow writes a report naming every executed block
# --------------------------------------------------------------------------- #

def test_at001_report_written_naming_every_executed_block(project: Path) -> None:
    before = set(_reports(project))
    flow = Flow(name="nightly", blocks=[
        SourceBlock("prg.s19"), WriteOutBlock("out.s19"), ReportBlock(),
    ])
    result = run_flow(flow, FlowContext(project_dir=project))

    new = set(_reports(project)) - before
    assert len(new) == 1, "exactly one NEW report"       # m-1: new, not total
    report_path = new.pop()
    assert report_path.stat().st_size > 0
    text = _read(report_path)

    # Row count DERIVED from the run, not a hardcoded number (C-31).
    reported = [br for br in result.block_results if br.kind != "report"]
    body_rows = [ln for ln in text.splitlines()
                 if ln.startswith("| ") and not ln.startswith("| # ")
                 and not ln.startswith("|---")]
    assert len(body_rows) == len(reported)
    rendered = _rendered(report_path)
    for br in reported:
        assert br.kind.upper() in rendered

    # The block result names the file (this is what the panel ledger shows).
    report_block = result.block_results[-1]
    assert report_block.status == BLOCK_STATUS_OK
    assert report_path.name in report_block.summary


# --------------------------------------------------------------------------- #
# AT-002 — the shipped reports list surfaces it (D-3) [C-12 output-then-consume]
# --------------------------------------------------------------------------- #

def test_at002_flow_report_is_listed_by_the_shipped_consumer(project: Path) -> None:
    run_flow(Flow(name="n", blocks=[SourceBlock("prg.s19"), ReportBlock()]),
             FlowContext(project_dir=project))
    written = _reports(project)[0]
    # The CONSUMER, over the artifact the handler produced.
    assert written in list_project_reports(project)
    assert REPORT_FILENAME_REGEX.match(written.name), written.name


def test_at002b_report_renders_inert_through_the_shipped_viewer_parser(
    project: Path,
) -> None:
    """The FULL C-12 loop (AMD-14 m-7, final-gate M-3): drive the report the
    handler wrote through the parser the SHIPPED viewer actually uses. This is
    the assert that would have caught the original escape-set/sink mismatch —
    `list_project_reports` alone only proves the file is visible, not safe.

    Hostile text arrives the way it really would: through a block ref.
    """
    hostile = "www.evil.com ~~VOID~~ http://evil.example <b>x</b>"
    run_flow(
        Flow(name=hostile, blocks=[SourceBlock("prg.s19"), ReportBlock()]),
        FlowContext(project_dir=project),
    )
    written = _reports(project)[0]
    rendered = _hardened_markdown_parser().render(_read(written))

    assert "<a href" not in rendered     # no live link, any linkify family
    assert "<s>" not in rendered         # no strikethrough forgery
    assert "<b>x</b>" not in rendered    # no raw HTML
    assert "<table" in rendered          # the ledger still renders


# --------------------------------------------------------------------------- #
# AT-005 — positional: the report covers blocks BEFORE it only (D-2)
# --------------------------------------------------------------------------- #

def test_at005_report_covers_only_blocks_before_it(project: Path) -> None:
    flow = Flow(name="n", blocks=[
        SourceBlock("prg.s19"), ReportBlock(), WriteOutBlock("late.s19"),
    ])
    run_flow(flow, FlowContext(project_dir=project))
    rendered = _rendered(_reports(project)[0])
    assert "SOURCE" in rendered
    # The kind is `write_out`, so `kind.upper()` is WRITE_OUT — asserting the
    # HYPHEN form would be vacuous (it can never appear). Proven by mutation at
    # the final gate: leaking a future row left the hyphen assert GREEN.
    assert "WRITE_OUT" not in rendered   # executed AFTER the report


# --------------------------------------------------------------------------- #
# AT-006 — no REPORT block ⇒ no report written (D-1 explicit trigger)
# --------------------------------------------------------------------------- #

def test_at006_no_report_block_writes_nothing(project: Path) -> None:
    before = list_project_reports(project)
    run_flow(Flow(name="n", blocks=[SourceBlock("prg.s19"), WriteOutBlock("o.s19")]),
             FlowContext(project_dir=project))
    assert _reports(project) == []
    assert list_project_reports(project) == before


# --------------------------------------------------------------------------- #
# AT-007 — N report blocks: independent, positional, non-overwriting (D-4)
# --------------------------------------------------------------------------- #

def test_at007_two_report_blocks_write_two_distinct_positional_reports(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    frozen = datetime(2026, 7, 24, 22, 40, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(frs, "_default_now", lambda: frozen)

    flow = Flow(name="n", blocks=[
        SourceBlock("prg.s19"), ReportBlock(), WriteOutBlock("o.s19"), ReportBlock(),
    ])
    run_flow(flow, FlowContext(project_dir=project))

    reports = _reports(project)
    assert len(reports) == 2, "same-second collision must not overwrite"
    # `_report_filename` resolves a same-second collision as <ts>-01-report.md.
    # Select by NAME, not by sort order: "-01-report.md" sorts BEFORE the
    # un-suffixed base name, so the alphabetical order is the reverse of the
    # write order.
    base = [p for p in reports if "-01-report" not in p.name]
    suffixed = [p for p in reports if "-01-report" in p.name]
    assert len(base) == 1 and len(suffixed) == 1          # _report_filename reuse
    first_path, second_path = base[0], suffixed[0]

    first, second = (_read(first_path), _read(second_path))
    assert first != second                                # not one composition twice

    def rows(text: str) -> list:
        return [ln for ln in text.splitlines()
                if ln.startswith("| ") and not ln.startswith("| # ")
                and not ln.startswith("|---")]

    assert len(rows(second)) > len(rows(first))           # positional growth (D-2)
    assert rows(second)[:len(rows(first))] == rows(first)  # prefix
    # AMD-11: a report is NOT an image output — report#1 is not in #2's Written
    # files (it appears only as report#1's own ledger row, which is the summary).
    written_section = second.split("## Written files")[1]
    assert first_path.name not in written_section


# --------------------------------------------------------------------------- #
# AT-008 — a write failure degrades, never aborts (LLR-003.1, AMD-12)
# --------------------------------------------------------------------------- #

def test_at008_report_write_failure_degrades_without_aborting(project: Path) -> None:
    # A REAL, portable failure (no mock): a regular FILE named `reports` makes
    # the production mkdir(parents=True, exist_ok=True) raise on any platform.
    (project / "reports").write_text("not a directory", encoding="utf-8")

    flow = Flow(name="n", blocks=[
        SourceBlock("prg.s19"), ReportBlock(), WriteOutBlock("after.s19"),
    ])
    result = run_flow(flow, FlowContext(project_dir=project))

    report_block = result.block_results[1]
    assert report_block.status == BLOCK_STATUS_ERROR
    assert report_block.diagnostics and ":" in report_block.diagnostics[0]  # names the type

    # NOT aborted: the block after the failed report still ran and produced output.
    after = result.block_results[2]
    assert after.status == BLOCK_STATUS_OK
    assert (project / "after.s19").exists()
    # A failed write can never read CLEAN — the error block degrades the rollup.
    assert result.status != "ok"


def test_tc011b_exhausted_collision_slots_degrade_through_the_same_path(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AMD-12's second degrade path (final-gate M-2): `_report_filename` raises
    FileExistsError once all 99 same-second slots are taken. It must degrade like
    any other write failure — recorded, not fatal."""
    frozen = datetime(2026, 7, 24, 22, 40, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(frs, "_default_now", lambda: frozen)

    reports = project / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    stamp = frozen.strftime("%Y%m%dT%H%M%SZ")
    (reports / f"{stamp}-report.md").write_text("x", encoding="utf-8")
    for n in range(1, 100):
        (reports / f"{stamp}-{n:02d}-report.md").write_text("x", encoding="utf-8")

    result = run_flow(
        Flow(name="n", blocks=[SourceBlock("prg.s19"), ReportBlock(),
                               WriteOutBlock("after.s19")]),
        FlowContext(project_dir=project),
    )
    report_block = result.block_results[1]
    assert report_block.status == BLOCK_STATUS_ERROR
    assert "FileExistsError" in report_block.diagnostics[0]
    # Never fatal: the following block still ran.
    assert result.block_results[2].status == BLOCK_STATUS_OK
    assert (project / "after.s19").exists()


def test_hostile_flow_name_cannot_influence_the_report_path(project: Path) -> None:
    """AMD-14/m-5: the filename is timestamp-derived and the directory is a code
    constant, so a traversal-shaped flow NAME can only ever reach report CONTENT."""
    run_flow(
        Flow(name="../../evil", blocks=[SourceBlock("prg.s19"), ReportBlock()]),
        FlowContext(project_dir=project),
    )
    written = _reports(project)
    assert len(written) == 1
    assert written[0].parent == project / "reports"
    assert REPORT_FILENAME_REGEX.match(written[0].name), written[0].name
    assert not (project.parent.parent / "evil").exists()


# --------------------------------------------------------------------------- #
# AT-009 — an ABORTED run still writes a FAILED report (D-6, AMD-3)
# --------------------------------------------------------------------------- #

def test_at009_aborted_run_still_writes_a_failed_report(project: Path) -> None:
    flow = Flow(name="n", blocks=[
        SourceBlock("missing.s19"),   # unresolvable → aborts the image
        WriteOutBlock("never.s19"),   # skipped
        ReportBlock(),                # EXEMPT from the skip (AMD-3)
        WriteOutBlock("also_never.s19"),
    ])
    result = run_flow(flow, FlowContext(project_dir=project))

    reports = _reports(project)
    assert len(reports) == 1, "the run that broke is the one you need a record of"
    text = _read(reports[0])
    rendered = _rendered(reports[0])
    assert "**Status:** FAILED" in text          # keyed on the real aborted flag
    assert "SOURCE" in rendered and "WRITE_OUT" in rendered
    assert "skipped" in text                      # the skipped block is in the ledger

    # The report does NOT clear `aborted`: the block after it still skips.
    assert result.block_results[2].status == BLOCK_STATUS_OK      # the report itself
    assert result.block_results[3].status == BLOCK_STATUS_SKIPPED
    assert not (project / "also_never.s19").exists()


# --------------------------------------------------------------------------- #
# AT-010 — footprint sources: pre-CRC asymmetry + growth (AMD-9)
# --------------------------------------------------------------------------- #

def test_at010_footprint_reads_the_live_threaded_ranges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """report#1 (pre-CRC) has NO 'Before CRC' line and a real Final footprint —
    an implementation reading `result.image_ranges` would emit '(none)' here,
    because that field is only assigned AFTER the block loop."""
    # Reuse the batch-52 CRC fixture helper; output 0x2000 is OUTSIDE the loaded
    # [0x1000,0x1004) window, so the CRC GROWS the image — which is exactly the
    # before/after footprint this AT measures.
    from tests.test_flow_crc_block import _crc_config

    project = _make_project(tmp_path, {
        "prg.s19": _S19_CLEAN,
        "crc.json": _crc_config(output_address="0x2000"),
    })
    frozen = datetime(2026, 7, 24, 22, 40, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(frs, "_default_now", lambda: frozen)

    flow = Flow(name="n", blocks=[
        SourceBlock("prg.s19"), ReportBlock(), CrcBlock("crc.json"), ReportBlock(),
    ])
    run_flow(flow, FlowContext(project_dir=project))

    reports = _reports(project)
    assert len(reports) == 2
    # Select by name (the "-01-" file is the SECOND written but sorts first).
    pre = _read([p for p in reports if "-01-report" not in p.name][0])
    post = _read([p for p in reports if "-01-report" in p.name][0])

    # report#1, before any CRC: no Before-CRC line, but a REAL footprint —
    # reading `result.image_ranges` here would render "(none)" (AMD-9).
    assert "Before CRC" not in pre
    assert "**Final:** (none)" not in pre
    assert "0x" in pre

    # report#2, after the CRC: the Before-CRC line appears and the image grew.
    assert "Before CRC" in post

    def final_total(text: str) -> int:
        """The byte total from the '**Final:** … (N bytes)' line."""
        tail = text.split("**Final:**")[1]
        return int(tail.split("(")[1].split("bytes")[0].replace(",", "").strip())

    assert final_total(post) > final_total(pre)
