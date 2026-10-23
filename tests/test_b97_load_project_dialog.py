"""batch-97 Inc-9 — the Load project dialog loads the project the user picks.

R-TUI-013 (batch-01): the user picks a saved project from a list and the app
loads it. Code-Wire UI audit 2026-10-23, CW-U-1: the dialog dismissed with
``str(Label)`` (Textual 8.2.8 ``Label`` has no ``.text``), so every pick
reached ``_handle_load_project`` as ``"Label()"`` and the status said
``Project not found: Label()``. No test pressed ``#project_ok``, so the dialog
never loaded a project and nothing failed. (``enter`` on the list still does
nothing: in Textual 8.2.8 a click on a ListItem also posts ``Selected``, so
loading on ``Selected`` would load on a single click. Routed to the
Load+projects prototype round.)

These tests drive the real dialog end to end: pick ``proj_b``, which is not the
first entry (so a fallback to the first entry cannot pass), and check the
app's project state.
"""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

from textual.widgets import ListView

from s19_app.tui.app import S19TuiApp
from s19_app.tui.screens import LoadProjectScreen

_FIRMWARE = Path(__file__).resolve().parents[1] / "examples" / "case_01_basic_valid" / "firmware.s19"


def _make_projects(app: S19TuiApp) -> None:
    for name in ("proj_a", "proj_b"):
        project_dir = app.workarea / name
        project_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(_FIRMWARE, project_dir / "firmware.s19")


async def _pick_second_project(tmp_path: Path) -> "tuple[str | None, str, str]":
    app = S19TuiApp(base_dir=tmp_path)
    async with app.run_test(size=(120, 40)) as pilot:
        _make_projects(app)
        await pilot.pause()
        app.action_load_project()
        await pilot.pause()
        assert isinstance(app.screen, LoadProjectScreen), "p must open the project list"
        list_view = app.screen.query_one("#project_list", ListView)
        list_view.focus()
        list_view.index = app.screen.projects.index("proj_b")
        await pilot.pause()
        await pilot.click("#project_ok")
        for _ in range(40):
            await pilot.pause(0.05)
            if app.current_project is not None:
                break
        status = str(app.query_one("#status_text").render())
        return app.current_project, str(app.screen.__class__.__name__), status


def test_load_project_button_loads_the_picked_project(tmp_path: Path) -> None:
    project, screen, status = asyncio.run(_pick_second_project(tmp_path))
    assert project == "proj_b", f"Load must open the highlighted project; got {project!r} (status: {status!r})"
    assert screen != "LoadProjectScreen", "the dialog must close after Load"
