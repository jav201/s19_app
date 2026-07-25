"""FB-P1b (batch-60) flow-run report generation — UI surface tests (Inc-3).

- **AT-004** (C-32 painted result): after a report-bearing run, the panel's
  Pipeline Ledger shows the WRITTEN REPORT PATH. Read off the REPORT block's own
  ``.flow-node-summary`` Static (scoped, not a substring search of the pane).
- **AT-011** (§6.5 AMD-13, the ENFORCING markup control): the report viewer's
  Markdown widget is built with a hardened parser (linkify OFF, raw HTML OFF,
  tables ON) and ``open_links=False``. The composer's ``_md_safe`` is the
  best-effort half that travels with the ``.md``; this is the half that holds no
  matter what text reaches the renderer.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from textual.widgets import Button, Markdown

from s19_app.tui.app import S19TuiApp
from s19_app.tui.screens import ReportViewerScreen, _hardened_markdown_parser
from s19_app.tui.screens_directionb import FlowBuilderPanel
from s19_app.tui.services.flow_model import ReportBlock, SourceBlock
from tests.test_flow_execution_service import _S19_CLEAN, _make_project


# --------------------------------------------------------------------------- #
# AT-004 — the written report path is visible in the painted ledger (D-5, C-32)
# --------------------------------------------------------------------------- #

def test_at004_ledger_shows_the_written_report_path(tmp_path: Path) -> None:
    project = _make_project(tmp_path, {"prg.s19": _S19_CLEAN})

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            app.current_project_dir = project
            await pilot.press("8")
            await pilot.pause()
            panel = app.query_one("#flow_panel", FlowBuilderPanel)
            panel._blocks = [SourceBlock("prg.s19"), ReportBlock()]
            app.query_one("#flow_run", Button).press()   # the REAL Run button
            await pilot.pause()
            await pilot.pause()
            summaries = [
                s.render().plain
                for s in app.query("#flow_result .flow-node-summary")
            ]
            return summaries

    summaries = asyncio.run(_drive())
    # Scoped to the REPORT node's own summary line — the one that names the file.
    report_lines = [s for s in summaries if "reports/" in s]
    assert len(report_lines) == 1, summaries
    assert report_lines[0].endswith("-report.md"), report_lines[0]

    # The named file really exists (the ledger is not advertising a phantom).
    written = (project / "reports" / report_lines[0].split("reports/")[1]).resolve()
    assert written.is_file() and written.stat().st_size > 0


# --------------------------------------------------------------------------- #
# AT-011 — the report viewer's parser is hardened (AMD-13 enforcing control)
# --------------------------------------------------------------------------- #

def test_at011_hardened_parser_kills_links_and_raw_html_keeps_tables() -> None:
    md = _hardened_markdown_parser()
    assert md.options.get("linkify") is False
    assert md.options.get("html") is False
    assert md.options.get("maxNesting") is not None   # defaults not clobbered

    rendered = md.render(
        "| h |\n|---|\n| see http://evil.example and <b>bold</b> |"
    )
    assert "<a href" not in rendered      # no live link, whatever the text
    assert "<b>bold</b>" not in rendered  # raw HTML inert
    assert "<table" in rendered           # reports are table-heavy — still works


def test_at011_report_viewer_uses_the_hardened_parser(tmp_path: Path) -> None:
    """The widget is actually CONSTRUCTED with it — the factory existing is not
    enough. Counterfactual: drop `parser_factory=` from the construction and this
    goes RED."""

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            app.push_screen(ReportViewerScreen("proj", [], []))
            await pilot.pause()
            widget = app.screen.query_one("#report_markdown", Markdown)
            return widget._parser_factory, widget._open_links

    factory, open_links = asyncio.run(_drive())
    assert factory is _hardened_markdown_parser
    assert open_links is False           # links stay non-navigable too
