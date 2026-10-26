"""Batch-99 HLR-162: the project and work-area pickers load by name.

TC-B99-34 (LLR-162.1) — the Workarea Files list stores each file name on its
``ListItem`` (the Inc-9 dialog-fix idiom, here ``item.data``) and
``_load_from_item`` reads that stored name — never ``str(Label)`` (CW-U-1:
Textual 8.2.8 ``Label`` has no ``.text`` and ``str(Label)`` is ``"Label()"``).
Boundary: a name with a space (``a b.s19``).

TC-B99-35 (LLR-162.2) — ``list_projects`` omits every name in the closed set
``RESERVED_WORKAREA_HOMES`` (the test imports the tuple), so a reserved home
such as ``patches`` can never present as a project. Boundary: only reserved
homes present -> the list is empty.

TC-B99-36 (LLR-162.3) — the Workarea Files list (``refresh_files``) reads the
regular files of the load folder (``workarea/temp``, where every file load
copies into), never the work-area root and never the ``.staging`` subfolder;
``_load_from_item`` resolves the picked name against that same folder.
Boundary: no file loaded yet -> the list is empty.

AT-B99-13 (US-151) — black-box Textual pilot, real keys and clicks only: with
projects ``P1``, ``P2`` and the ``patches`` home present, the Load project
dialog lists ``P1`` and ``P2`` only, and three pick paths (keyboard highlight
+ ``#project_ok``; click the item + ``#project_ok``; keyboard highlight +
focus ``#project_ok`` + ``enter``) each load ``P2`` with the status naming it.
After a file load the Workarea Files list shows that file and picking it loads
it. Empty boundary: with no project, pressing Load loads nothing and the
current file stays loaded.
"""
from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

from textual.widgets import Label, ListItem, ListView

from s19_app.tui.app import S19TuiApp
from s19_app.tui.screens import LoadProjectScreen

ROOT = Path(__file__).resolve().parents[1]
CASE01 = ROOT / "examples" / "case_01_basic_valid" / "firmware.s19"


def _status_text(app: S19TuiApp) -> str:
    """The painted newest status line (the ``#log_line_4`` label)."""
    return str(app.query_one("#log_line_4", Label).render())


def _line3_text(app: S19TuiApp) -> str:
    """The second-newest painted status line (the ``#log_line_3`` label)."""
    return str(app.query_one("#log_line_3", Label).render())


def _file_status_text(app: S19TuiApp) -> str:
    """The painted durable file-state line (the ``#status_text`` label)."""
    return str(app.query_one("#status_text", Label).render())


def _files_list_names(app: S19TuiApp) -> list:
    """The painted names of the Workarea Files list items."""
    return [
        str(item.query_one(Label).render())
        for item in app.query_one("#files_list", ListView).query(ListItem)
    ]


def _project_list_names(app: S19TuiApp) -> list:
    """The painted names of the Load project dialog items."""
    return [
        str(item.query_one(Label).render())
        for item in app.screen.query("#project_list ListItem")
    ]


async def _wait_for(pilot, predicate, description: str, attempts: int = 100):
    for _ in range(attempts):
        await pilot.pause()
        if predicate():
            return
    raise AssertionError(f"did not settle: {description}")


async def _load_file_through_dialog(pilot, app: S19TuiApp, src: Path) -> None:
    """Drive the Load file dialog (rail key ``l``) and wait for the load."""
    await pilot.press("l")
    for _ in range(6):
        await pilot.pause()
    assert await pilot.click("#load_path"), "click missed #load_path"
    await pilot.press(*str(src))
    assert await pilot.click("#load_ok"), "click missed #load_ok"
    await _wait_for(
        pilot,
        lambda: f"Loaded {src.name}" in _status_text(app),
        f"load status line naming {src.name}",
    )


def _pick_files_item(app: S19TuiApp, name: str) -> ListItem:
    """The painted Workarea Files item carrying exactly ``name``."""
    return next(
        item
        for item in app.query_one("#files_list", ListView).query(ListItem)
        if str(item.query_one(Label).render()) == name
    )


async def _pick_files_item_and_wait_load(pilot, app: S19TuiApp, name: str) -> None:
    """Click the named Workarea Files item and wait for the RE-load.

    The picked file is already the loaded one, so the painted ``#log_line_4``
    text repeats; a fresh load is observable as that same line being PUSHED
    into ``#log_line_3`` (``set_status`` rotates the log).
    """
    previous = _status_text(app)
    assert f"Loaded {name}" in previous, previous
    item = _pick_files_item(app, name)
    await pilot.click(item)
    await _wait_for(
        pilot,
        lambda: _line3_text(app) == previous,
        f"the list pick re-loads {name}",
    )
    assert f"Loaded {name}" in _file_status_text(app), _file_status_text(app)


# --------------------------------------------------------------------------- #
# TC-B99-34 — LLR-162.1: _load_from_item reads the item's stored name
# --------------------------------------------------------------------------- #


def test_tc_b99_34_pick_loads_the_picked_file_name(tmp_path):
    """Picking ``a.s19`` — boundary: ``a b.s19``, a name with a space — in
    the Workarea Files list loads that file (the painted status re-push)."""

    async def _drive(name: str) -> None:
        src = tmp_path / name
        shutil.copy(CASE01, src)
        app = S19TuiApp(base_dir=tmp_path / f"app_{name.replace(' ', '_').replace('.', '_')}")
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await _load_file_through_dialog(pilot, app, src)
            assert _files_list_names(app) == [name], _files_list_names(app)
            await _pick_files_item_and_wait_load(pilot, app, name)

    asyncio.run(_drive("a.s19"))
    asyncio.run(_drive("a b.s19"))


# --------------------------------------------------------------------------- #
# TC-B99-35 — LLR-162.2: reserved homes are not projects
# --------------------------------------------------------------------------- #


def test_tc_b99_35_reserved_homes_are_not_projects(tmp_path):
    """With P1, P2 and every RESERVED_WORKAREA_HOMES name present, the
    project list holds P1 and P2 only; reserved-only -> empty list."""
    from s19_app.tui.workspace import RESERVED_WORKAREA_HOMES

    app = S19TuiApp(base_dir=tmp_path)
    for name in ("P1", "P2", *RESERVED_WORKAREA_HOMES):
        (app.workarea / name).mkdir(parents=True, exist_ok=True)

    assert sorted(app.list_projects()) == ["P1", "P2"]

    for name in ("P1", "P2"):
        shutil.rmtree(app.workarea / name)
    assert app.list_projects() == []


# --------------------------------------------------------------------------- #
# TC-B99-36 — LLR-162.3: the Workarea Files list reads the load folder
# --------------------------------------------------------------------------- #


def test_tc_b99_36_workarea_files_reads_the_load_folder(tmp_path):
    """No file loaded -> the list is empty. After one file load the list
    holds exactly that file (no .staging artefact), and picking it loads it."""

    async def _drive() -> None:
        src = tmp_path / "one.s19"
        shutil.copy(CASE01, src)
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            # Empty boundary: the load folder holds only the .staging home.
            assert _files_list_names(app) == [], _files_list_names(app)
            await _load_file_through_dialog(pilot, app, src)
            names = _files_list_names(app)
            assert names == ["one.s19"], names
            assert not any(".staging" in n for n in names), names
            await _pick_files_item_and_wait_load(pilot, app, "one.s19")

    asyncio.run(_drive())


# --------------------------------------------------------------------------- #
# AT-B99-13 — US-151: black-box pilot through the TUI
# --------------------------------------------------------------------------- #


def _make_project(app: S19TuiApp, name: str) -> None:
    project_dir = app.workarea / name
    project_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(CASE01, project_dir / "firmware.s19")


async def _open_load_project_dialog(pilot, app: S19TuiApp) -> None:
    await pilot.press("p")
    await _wait_for(
        pilot,
        lambda: isinstance(app.screen, LoadProjectScreen),
        "the Load project dialog",
    )


def _project_item(app: S19TuiApp, name: str) -> ListItem:
    return next(
        item
        for item in app.screen.query("#project_list ListItem")
        if str(item.query_one(Label).render()) == name
    )


def test_at_b99_13_project_and_file_pickers_load_by_name(tmp_path):
    """1. The dialog lists P1 and P2 only (the ``patches`` home is present).
    2. Three pick paths each load P2 and the status names P2.
    3. After a file load, the Workarea Files list shows that file, and
       picking it loads it.
    4. Empty boundary: with no project, pressing Load loads nothing and the
       current file stays loaded.
    """
    src = tmp_path / "a.s19"
    shutil.copy(CASE01, src)

    async def _dialog_lists_projects_only() -> None:
        app = S19TuiApp(base_dir=tmp_path / "case1")
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            _make_project(app, "P1")
            _make_project(app, "P2")
            await pilot.pause()
            await _open_load_project_dialog(pilot, app)
            names = sorted(_project_list_names(app))
            assert names == ["P1", "P2"], names

    async def _pick_path_highlight_then_ok() -> None:
        app = S19TuiApp(base_dir=tmp_path / "case2")
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            _make_project(app, "P1")
            _make_project(app, "P2")
            await pilot.pause()
            await _open_load_project_dialog(pilot, app)
            # Keyboard highlight: focus the list by clicking the P1 row,
            # move the highlight to P2 with the Down key.
            row = _project_item(app, "P1")
            await pilot.click(row)
            await pilot.press("down")
            await pilot.pause()
            assert await pilot.click("#project_ok"), "click missed #project_ok"
            await _wait_for(
                pilot,
                lambda: "Loaded project 'P2'" in _status_text(app),
                "the status naming P2 (keyboard highlight + Load)",
            )

    async def _pick_path_click_then_ok() -> None:
        app = S19TuiApp(base_dir=tmp_path / "case3")
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            _make_project(app, "P1")
            _make_project(app, "P2")
            await pilot.pause()
            await _open_load_project_dialog(pilot, app)
            row = _project_item(app, "P2")
            await pilot.click(row)
            await pilot.pause()
            assert await pilot.click("#project_ok"), "click missed #project_ok"
            await _wait_for(
                pilot,
                lambda: "Loaded project 'P2'" in _status_text(app),
                "the status naming P2 (click + Load)",
            )

    async def _pick_path_highlight_focus_enter() -> None:
        app = S19TuiApp(base_dir=tmp_path / "case4")
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            _make_project(app, "P1")
            _make_project(app, "P2")
            await pilot.pause()
            await _open_load_project_dialog(pilot, app)
            row = _project_item(app, "P1")
            await pilot.click(row)
            await pilot.press("down")
            await pilot.pause()
            await pilot.press("tab")
            await pilot.pause()
            await pilot.press("enter")
            await _wait_for(
                pilot,
                lambda: "Loaded project 'P2'" in _status_text(app),
                "the status naming P2 (keyboard highlight + focus Load + enter)",
            )

    async def _file_pick_after_load() -> None:
        app = S19TuiApp(base_dir=tmp_path / "case5")
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await _load_file_through_dialog(pilot, app, src)
            names = _files_list_names(app)
            assert names == ["a.s19"], names
            await _pick_files_item_and_wait_load(pilot, app, "a.s19")

    async def _empty_boundary_no_project() -> None:
        app = S19TuiApp(base_dir=tmp_path / "case6")
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await _load_file_through_dialog(pilot, app, src)
            loaded_status = _file_status_text(app)
            assert "a.s19" in loaded_status, loaded_status
            # No project exists (only reserved homes): pressing Load loads
            # nothing and the current file stays loaded. The load left the
            # Segment Split window holding focus (it binds ``p`` for its own
            # pad cycle), so the drive uses the shipped "Load project (p)"
            # button — a real click on the rail surface.
            await pilot.press("1")
            for _ in range(6):
                await pilot.pause()
            assert await pilot.click(
                "#ws_load_project_button"
            ), "click missed #ws_load_project_button"
            await _wait_for(
                pilot,
                lambda: "No saved projects found." in _status_text(app),
                "the no-projects status line",
            )
            assert not isinstance(app.screen, LoadProjectScreen), (
                "the dialog must not open with no project"
            )
            assert "a.s19" in _file_status_text(app), _file_status_text(app)

    asyncio.run(_dialog_lists_projects_only())
    asyncio.run(_pick_path_highlight_then_ok())
    asyncio.run(_pick_path_click_then_ok())
    asyncio.run(_pick_path_highlight_focus_enter())
    asyncio.run(_file_pick_after_load())
    asyncio.run(_empty_boundary_no_project())
