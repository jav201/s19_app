"""Report viewer + TUI generation trigger tests (batch-07 E8 — HLR-008).

Coverage map (TC-045..TC-049):

- LLR-008.2 — ``test_view_reports_no_project_neutral_status``: the
  key-bound ``action_view_reports`` (NOT a 9th rail item) bails with one
  neutral status line when no project is active and pushes no screen; the
  command palette carries the entry (the E5b parity-by-construction path).
- LLR-008.3 / F-Q-05 — ``test_list_project_reports_order`` (unit) and
  ``test_report_viewer_lists_newest_first`` (pilot): newest-first by the
  parsed ``(timestamp, NN)`` key descending including one same-second
  collision group (``-02``, ``-01``, base — the base sorts as ``NN=00``),
  foreign ``.md`` files last, non-``.md`` entries excluded.
- LLR-008.1 / F-S-06 — ``test_select_renders_markdown_open_links_false``:
  selecting a report renders it through ``textual.widgets.Markdown`` with
  ``_open_links`` pinned ``False`` (render-only, no link opening);
  ``test_oversized_report_refused``: a file over the viewer cap shows the
  neutral too-large message and is never rendered.
- LLR-008.3 — ``test_empty_reports_dir_empty_state``: an empty ``reports/``
  directory shows the neutral empty-state text instead of a list.
- LLR-008.5 — ``test_execution_report_retains_results``: an execution run
  retains ``(project_dir, scope, assignment_source, results)`` app-side;
  ``test_generate_trigger_calls_service_and_drops_results``: the Generate
  flow collects ``context_bytes``, hands the RETAINED
  ``capture_mem_maps=True`` results to ``generate_project_report``
  verbatim, shows the resulting path in the status line, and DROPS the
  retained snapshot (and its mem_maps — the E7 risk item) afterwards.

Harness: the ``App.run_test()`` pilot pattern of ``tests/test_tui_app.py``
/ ``tests/test_tui_variants.py``. Fixture data is synthetic / public-only
(F-S-07).
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import List

from textual.widgets import Button, Label, ListView, Markdown

import s19_app.tui.app as app_module
import s19_app.tui.screens as screens_module
from s19_app.tui.app import S19TuiApp
from s19_app.tui.screens import ReportViewerScreen
from s19_app.tui.services.report_service import list_project_reports
from s19_app.tui.services.variant_execution_service import (
    VariantExecutionResult,
)

# Minimal valid S19 image (checksum verified against s19_app.core.S19File).
S19_A = "S107100001020304DE\nS9030000FC\n"

#: Report fixture names — one newer file plus a same-second collision
#: group (base, -01, -02) and one foreign .md (F-Q-05 / LLR-008.3).
TS_OLD = "20260101T000000Z"
TS_NEW = "20260102T000000Z"
EXPECTED_ORDER = [
    f"{TS_NEW}-report.md",
    f"{TS_OLD}-02-report.md",
    f"{TS_OLD}-01-report.md",
    f"{TS_OLD}-report.md",
    "notes.md",
]


def _make_project(app: S19TuiApp, name: str, files: dict[str, str]) -> Path:
    """Create ``.s19tool/workarea/<name>/`` with the given text files."""
    project_dir = app.workarea / name
    project_dir.mkdir(parents=True, exist_ok=True)
    for filename, content in files.items():
        (project_dir / filename).write_text(content, encoding="utf-8")
    return project_dir


def _make_reports(project_dir: Path, names: List[str]) -> Path:
    """Create ``reports/`` under the project with one stub .md per name."""
    reports_dir = project_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    for name in names:
        (reports_dir / name).write_text(f"# Report {name}\n", encoding="utf-8")
    return reports_dir


async def _flush(pilot, count: int = 12) -> None:
    """Pump the event loop so deferred screen/message work runs."""
    for _ in range(count):
        await pilot.pause()


# ---------------------------------------------------------------------------
# LLR-008.2 — neutral status without a project; palette entry exists
# ---------------------------------------------------------------------------


def test_view_reports_no_project_neutral_status(tmp_path: Path) -> None:
    """No active project: one neutral status line, no screen pushed.

    Intent: LLR-008.2 — reports are reached via the key-bound
    ``action_view_reports`` (palette-listed like every binding), never a
    9th rail item; without a project the action degrades to a neutral
    status message instead of an empty modal or a crash.
    """

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            stack_before = len(app.screen_stack)
            app.action_view_reports()
            await _flush(pilot)
            palette_actions = {
                entry.action for entry in app._build_palette_entries()
            }
            return (
                len(app.screen_stack) - stack_before,
                list(app.log_lines),
                palette_actions,
            )

    pushed, log_lines, palette_actions = asyncio.run(_drive())
    assert pushed == 0, "no modal must open without an active project"
    assert any("no active project" in line for line in log_lines), log_lines
    assert "view_reports" in palette_actions, (
        "the view_reports action must surface in the command palette"
    )


# ---------------------------------------------------------------------------
# LLR-008.3 / F-Q-05 — listing order (unit + pilot)
# ---------------------------------------------------------------------------


def test_list_project_reports_order(tmp_path: Path) -> None:
    """Parsed-key descending order incl. the same-second collision group.

    Intent: LLR-008.3 / F-Q-05 — inside a same-second group the
    un-suffixed base sorts as ``NN=00`` so descending order reads ``-02``,
    ``-01``, base (raw filename-descending would misplace the base);
    foreign ``.md`` files list last; non-``.md`` entries never appear.
    """
    project_dir = tmp_path / "proj"
    _make_reports(project_dir, EXPECTED_ORDER)
    (project_dir / "reports" / "data.txt").write_text("x", encoding="utf-8")

    listed = [path.name for path in list_project_reports(project_dir)]

    assert listed == EXPECTED_ORDER, listed
    assert list_project_reports(tmp_path / "missing") == []


def test_report_viewer_lists_newest_first(tmp_path: Path) -> None:
    """The modal's ListView mirrors the LLR-008.3 newest-first order.

    Intent: LLR-008.3 — the viewer renders the service listing verbatim
    (selection later resolves by index, so the displayed order IS the
    contract the operator acts on).
    """

    async def _drive() -> list:
        app = S19TuiApp(base_dir=tmp_path)
        project_dir = _make_project(app, "proj", {"a.s19": S19_A})
        _make_reports(project_dir, EXPECTED_ORDER)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.current_project = "proj"
            app.action_view_reports()
            await _flush(pilot)
            screen = app.screen_stack[-1]
            assert isinstance(screen, ReportViewerScreen)
            items = screen.query_one("#report_list", ListView).children
            return [str(item.query_one(Label).content) for item in items]

    labels = asyncio.run(_drive())
    assert labels == EXPECTED_ORDER, labels


# ---------------------------------------------------------------------------
# LLR-008.1 / F-S-06 — render-only Markdown, open_links pinned False
# ---------------------------------------------------------------------------


def test_select_renders_markdown_open_links_false(tmp_path: Path) -> None:
    """Selecting a report renders it; the widget never opens links.

    Intent: LLR-008.1 + F-S-06 — the viewer is render-only: the mounted
    ``Markdown`` is constructed with ``open_links=False`` (else a clicked
    link would open the system browser on Textual 8.2.5) and no
    ``Markdown.LinkClicked`` handler exists on the screen or the app.
    """

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        project_dir = _make_project(app, "proj", {"a.s19": S19_A})
        report = (
            _make_reports(project_dir, [f"{TS_NEW}-report.md"])
            / f"{TS_NEW}-report.md"
        )
        report.write_text(
            "# E8 Fixture\n\n[link](https://example.invalid/)\n",
            encoding="utf-8",
        )
        async with app.run_test() as pilot:
            await pilot.pause()
            app.current_project = "proj"
            app.action_view_reports()
            await _flush(pilot)
            screen = app.screen_stack[-1]
            await pilot.press("enter")
            await _flush(pilot)
            markdown = screen.query_one("#report_markdown", Markdown)
            has_link_handler = hasattr(
                screen, "on_markdown_link_clicked"
            ) or hasattr(app, "on_markdown_link_clicked")
            return (
                markdown._open_links,
                markdown.source,
                screen.selected_path,
                report,
                has_link_handler,
            )

    open_links, source, selected, report, has_link_handler = asyncio.run(_drive())
    assert open_links is False, "F-S-06: Markdown must be open_links=False"
    assert "E8 Fixture" in source
    assert selected == report
    assert not has_link_handler, (
        "F-S-06: no Markdown.LinkClicked handler may be registered"
    )


def test_oversized_report_refused(tmp_path: Path, monkeypatch) -> None:
    """A report over the viewer cap shows the neutral too-large message.

    Intent: LLR-008.1 + F-S-06 — the cap is probed BEFORE reading, the
    refusal text is neutral (no content excerpt), and nothing of the file
    is rendered past the cap.
    """
    monkeypatch.setattr(screens_module, "VIEWER_SIZE_CAP_BYTES", 16)

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        project_dir = _make_project(app, "proj", {"a.s19": S19_A})
        report = (
            _make_reports(project_dir, [f"{TS_NEW}-report.md"])
            / f"{TS_NEW}-report.md"
        )
        report.write_text("# secret-ish body " + "A" * 100, encoding="utf-8")
        async with app.run_test() as pilot:
            await pilot.pause()
            app.current_project = "proj"
            app.action_view_reports()
            await _flush(pilot)
            screen = app.screen_stack[-1]
            await pilot.press("enter")
            await _flush(pilot)
            markdown = screen.query_one("#report_markdown", Markdown)
            return markdown.source, screen.selected_path

    source, selected = asyncio.run(_drive())
    assert source == ReportViewerScreen.TOO_LARGE_TEXT
    assert "secret-ish" not in source
    assert selected is None, "a refused file is not a selected/rendered one"


# ---------------------------------------------------------------------------
# LLR-008.3 — neutral empty state for an empty reports/ directory
# ---------------------------------------------------------------------------


def test_empty_reports_dir_empty_state(tmp_path: Path) -> None:
    """An empty ``reports/`` shows the neutral empty-state, not a list.

    Intent: LLR-008.3 — the no-reports case degrades to one neutral
    static panel (the ``EmptyStatePanel`` pattern), never an empty
    ``ListView`` or an error.
    """

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        project_dir = _make_project(app, "proj", {"a.s19": S19_A})
        (project_dir / "reports").mkdir()
        async with app.run_test() as pilot:
            await pilot.pause()
            app.current_project = "proj"
            app.action_view_reports()
            await _flush(pilot)
            screen = app.screen_stack[-1]
            assert isinstance(screen, ReportViewerScreen)
            empty = screen.query("#report_empty_state")
            lists = screen.query("#report_list")
            text = str(empty.first().render()) if empty else ""
            return len(empty), len(lists), text

    empty_count, list_count, text = asyncio.run(_drive())
    assert empty_count == 1
    assert list_count == 0
    assert text == ReportViewerScreen.EMPTY_TEXT


# ---------------------------------------------------------------------------
# LLR-008.5 — retention on execution, generation trigger, drop after
# ---------------------------------------------------------------------------


def _fake_results() -> List[VariantExecutionResult]:
    """One ok-status result carrying a captured (non-None) mem_map."""
    return [
        VariantExecutionResult(
            variant_id="a",
            status="ok",
            mem_map={0x1000: 0x01, 0x1001: 0x02},
        )
    ]


def test_execution_report_retains_results(tmp_path: Path) -> None:
    """An execution run retains its snapshot for later generation.

    Intent: LLR-008.5 wiring — ``_report_execution_results`` (the E6
    UI-thread sink, now fed ``capture_mem_maps=True`` results) pins
    ``(project_dir, scope, assignment_source, results)`` app-side so
    "generate from last execution" needs no re-run.
    """

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        project_dir = _make_project(app, "proj", {"a.s19": S19_A})
        results = _fake_results()
        async with app.run_test() as pilot:
            await pilot.pause()
            assert app._last_execution is None
            app._report_execution_results(
                project_dir, "active", "default", results, []
            )
            await pilot.pause()
            return app._last_execution, project_dir, results

    retained, project_dir, results = asyncio.run(_drive())
    assert retained == (project_dir, "active", "default", results)
    assert retained[3][0].mem_map is not None


def test_generate_trigger_calls_service_and_drops_results(
    tmp_path: Path, monkeypatch
) -> None:
    """Generate: collect context_bytes, call the service, drop retention.

    Intent: LLR-008.5 — the dialog's ``context_bytes`` reaches
    ``ReportOptions`` unclamped, the RETAINED ``capture_mem_maps=True``
    results are handed to ``generate_project_report`` verbatim (no
    re-assembly in ``app.py``), the status line shows the resulting path,
    and the retained snapshot (with its mem_maps) is dropped afterwards —
    the E7 risk closure.
    """
    captured: dict = {}

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        _make_project(app, "proj", {"a.s19": S19_A})
        async with app.run_test() as pilot:
            await pilot.pause()
            app._handle_load_project("proj")
            await _flush(pilot)
            await app.workers.wait_for_complete()
            await _flush(pilot)
            project_dir = app._active_project_dir()
            assert project_dir is not None
            results = _fake_results()
            app._last_execution = (project_dir, "all", "default", results)

            fake_path = project_dir / "reports" / "x-report.md"

            def _fake_generate(p_dir, p_results, p_options, *, variant_set):
                captured["project_dir"] = p_dir
                captured["results"] = p_results
                captured["options"] = p_options
                captured["variant_set"] = variant_set
                return fake_path

            monkeypatch.setattr(
                app_module, "generate_project_report", _fake_generate
            )
            app.action_view_reports()
            await _flush(pilot)
            screen = app.screen_stack[-1]
            screen.query_one("#report_context_bytes").value = "32"
            screen.query_one("#report_generate", Button).press()
            await _flush(pilot)
            await app.workers.wait_for_complete()
            await _flush(pilot)
            return (
                project_dir,
                results,
                app._last_execution,
                list(app.log_lines),
                app._variant_set,
            )

    project_dir, results, retained_after, log_lines, variant_set = asyncio.run(
        _drive()
    )
    assert captured["project_dir"] == project_dir
    assert captured["results"] is results, (
        "the retained last-execution results must be passed verbatim"
    )
    assert captured["results"][0].mem_map is not None, (
        "generation must consume capture_mem_maps=True results"
    )
    assert captured["options"].context_bytes == 32
    assert captured["options"].execution_mode == "batch"
    assert captured["options"].assignment_source == "default"
    assert captured["variant_set"] is variant_set
    assert retained_after is None, (
        "the retained results (and their mem_maps) must be dropped "
        "after generation"
    )
    assert any("x-report.md" in line for line in log_lines), log_lines
