"""N5 — report-generation progress feedback on the persistent #progress_bar.

The file load path already drives the bar (10/50/100); report generation did
NOT — the off-thread worker left the bar at its prior value. These tests drive
the REAL report surface (reusing the report-seam harness) and assert the bar
now moves to 100 on success and resets to 0 on failure.

RED pre-fix: without the N5 `set_progress` seams a generated report leaves the
bar at its default 0 (never 100), and a failed report leaves it mid-fill.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from textual.widgets import Button, ProgressBar

from s19_app.tui.app import S19TuiApp
from s19_app.tui.screens import ReportViewerScreen

from test_tui_report_seam import (
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

def test_report_generation_drives_progress_bar_to_100(tmp_path: Path) -> None:
    async def _drive() -> float:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await _load_project(app, pilot)
            await _generate_through_surface(app, pilot)
            return _bar_progress(app)

    assert asyncio.run(_drive()) == 100, (
        "AC-2/3: a completed report must leave #progress_bar at 100"
    )


# ---------------------------------------------------------------------------
# AC-4 — a failed report resets the bar to 0 (never stuck mid-fill)
# ---------------------------------------------------------------------------

def test_failed_report_resets_progress_bar_to_zero(
    tmp_path: Path, monkeypatch
) -> None:
    def _boom(*args, **kwargs):
        raise RuntimeError("synthetic report failure")

    # Patch the symbol the worker calls so generation crashes in-worker.
    monkeypatch.setattr("s19_app.tui.app.generate_project_report", _boom)

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
    async def _drive() -> float:
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
            return _bar_progress(app)

    progress = asyncio.run(_drive())
    assert 0 < progress < 100, (
        f"AC-1: kickoff must show in-progress (0<p<100), got {progress}"
    )


# ---------------------------------------------------------------------------
# AC-3 (unit) — _finish_generate_report completes the bar
# ---------------------------------------------------------------------------

def test_finish_generate_report_completes_bar(tmp_path: Path) -> None:
    async def _drive() -> float:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.set_progress(40)  # mid-way, as if a report were running
            app._finish_generate_report(Path("proj") / "reports" / "r.md")
            await pilot.pause()
            return _bar_progress(app)

    assert asyncio.run(_drive()) == 100
