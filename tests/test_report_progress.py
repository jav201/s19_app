"""N5 — report-generation progress feedback on the persistent #progress_bar.

The file load path already drives the bar (10/50/100); report generation did
NOT — the off-thread worker left the bar at its prior value. These tests drive
the REAL report surface (reusing the report-seam harness) and assert the bar
now moves to 100 on success and resets to 0 on failure.

RED pre-fix: without the N5 `set_progress` seams a generated report leaves the
bar at its default 0 (never 100), and a failed report leaves it mid-fill.

Batch-91 contract adoption (HLR-122):
# TC-644 — this module pins the report logging/progress/off-thread behaviors (LLR-122.5).
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from textual.widgets import Button, ProgressBar

from s19_app.tui.app import S19TuiApp
from s19_app.tui.screens import ReportViewerScreen

from tests.test_tui_report_seam import (
    _flush,
    _generate_through_surface,
    _make_report_project,
)


def _bar_progress(app: S19TuiApp) -> float:
    return app.query_one("#progress_bar", ProgressBar).progress


async def _load_project(app: S19TuiApp, pilot) -> None:
    _make_report_project(app, "proj")
    await pilot.pause()
    app._handle_load_project("proj")
    await _flush(pilot)
    await app.workers.wait_for_complete()
    await _flush(pilot)


# ---------------------------------------------------------------------------
# AC-2 / AC-3 — a real report drives the bar to 100
# ---------------------------------------------------------------------------

def test_report_generation_drives_progress_bar_then_clears_it(tmp_path: Path, monkeypatch) -> None:
    """Inc 12a re-pin (census A1; LLR-176.1k, A12-53 / A12-77): a real
    report still DRIVES the bar — it moves off 0 while the report runs (the
    ``Write the report`` step, 50) — and the end now CLEARS it: progress 0
    of 100 and the report named on the last status-log line. The old pin
    (the bar left at 100) encoded the stale-100 defect HLR-176c removes.

    History: named ``test_report_generation_drives_progress_bar_to_100``
    until Inc 12a E5 (CR12a-3); TC-644 is re-bound to this name."""
    seen: list = []
    original = S19TuiApp.set_progress

    def _spy(self, value, message=None):
        seen.append(value)
        return original(self, value, message)

    monkeypatch.setattr(S19TuiApp, "set_progress", _spy)

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await _load_project(app, pilot)
            seen.clear()
            await _generate_through_surface(app, pilot)
            bar = app.query_one("#progress_bar", ProgressBar)
            return bar.progress, bar.total, app.log_lines[-1]

    progress, total, last = asyncio.run(_drive())
    assert any(0 < value < 100 for value in seen), (
        f"AC-2/3: the report must move the bar while it runs; sequence: {seen}"
    )
    assert (progress, total) == (0, 100), (
        f"LLR-176.1k: a completed report must leave the bar cleared; got {progress}/{total}"
    )
    assert last.startswith("Report: ") and last.endswith(".md"), last


# ---------------------------------------------------------------------------
# AC-4 — a failed report resets the bar to 0 (never stuck mid-fill)
# ---------------------------------------------------------------------------

def test_failed_report_resets_progress_bar_to_zero(
    tmp_path: Path, monkeypatch
) -> None:
    def _boom(*args, **kwargs):
        raise RuntimeError("synthetic report failure")

    # Patch the symbol the worker calls so generation crashes in-worker.
    monkeypatch.setattr("s19_app.tui.app.deps.generate_project_report", _boom)

    async def _drive() -> tuple[float, bool]:
        app = S19TuiApp(base_dir=tmp_path)
        crashed = False
        async with app.run_test() as pilot:
            await _load_project(app, pilot)
            try:
                await _generate_through_surface(app, pilot)
            except Exception:  # noqa: BLE001 - the app must not surface a crash
                crashed = True
            return _bar_progress(app), crashed

    progress, crashed = asyncio.run(_drive())
    assert progress == 0, "AC-4: a failed report must reset #progress_bar to 0"
    assert not crashed, "AC-4: the worker must isolate the failure (no raise)"


# ---------------------------------------------------------------------------
# AC-1 — kickoff shows in-progress before the worker completes
# ---------------------------------------------------------------------------

def test_kickoff_sets_bar_in_progress_before_worker(tmp_path: Path) -> None:
    """Inc 12a re-pin (census A2; A12-75, LLR-176.1 / LLR-176.1a): the
    kickoff must already show the report as in progress before the worker
    runs. That is now the progress line in ``#status_text``
    (``<glyph> Generating the project report  ·  step 1/2 Prepare the
    results  ·  00:0x``) with the bar at 0 (the begin clears it); the old
    ``0 < p < 100`` read the constant 15 the seam removed. The stubbed run
    stays open until the app exits (risk R-7)."""
    import re

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await _load_project(app, pilot)
            # Stub the worker so it never runs — the kickoff progress must
            # already be visible (in-progress) from _trigger_generate_report.
            app._start_generate_report_worker = lambda *a, **k: None
            app.action_view_reports()
            await _flush(pilot)
            screen = app.screen_stack[-1]
            assert isinstance(screen, ReportViewerScreen)
            screen.query_one("#report_generate", Button).press()
            await _flush(pilot)
            return _bar_progress(app), str(app.query_one("#status_text").render())

    progress, line = asyncio.run(_drive())
    pattern = (
        "^[⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏] Generating the project report"
        "  ·  step 1/2 Prepare the results  ·  00:0[0-9]$"
    )
    assert re.match(pattern, line), f"AC-1: kickoff must paint the progress line, got {line!r}"
    assert progress == 0, f"LLR-176.1a: the begin sets the bar to 0, got {progress}"


# ---------------------------------------------------------------------------
# AC-3 (unit) — _finish_generate_report completes the bar
# ---------------------------------------------------------------------------

def test_finish_generate_report_clears_bar(tmp_path: Path) -> None:
    """Inc 12a re-pin (census A3; A12-77, interfaces S-m / Q-1): the finish
    handler now ends the report run whose generation it is given — a run is
    begun first (as the kickoff does), the bar set mid-way, and the finish
    clears the bar (LLR-176.1k) and names the report on the last log line.

    History: named ``test_finish_generate_report_completes_bar`` until
    Inc 12a E5 (CR12a-3); TC-644 is re-bound to this name."""

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            gen = app.begin_busy("report", "x", ("a", "b"))
            app.set_progress(40)  # mid-way, as if a report were running
            app._finish_generate_report(Path("proj") / "reports" / "r.md", gen)
            await pilot.pause()
            return _bar_progress(app), app.log_lines[-1]

    assert asyncio.run(_drive()) == (0, "Report: reports/r.md")
