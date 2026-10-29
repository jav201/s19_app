"""Batch 100 — Increment 4: after a load the focus lands where you can work (HLR-166).

White-box TCs:

- TC-B100-12 (LLR-166.1): the per-window focus-target table is declared
  per window and asserted 1:1 against the window registry (one target per
  window, every target focusable — ``Screen.set_focus`` silently ignores
  a ``can_focus=False`` widget — and ``Input`` / ``TextArea`` never
  named; the registry census arm asserts all of it, so a window added
  without a target, a dropped window, an unfocusable target or a
  text-input target fails the census). The three load tails (Load file,
  Load project, Workarea Files pick) re-home the focus off a zero-area,
  hidden-window or STALE text-input widget onto the active window's target
  and then ``p`` opens the Load project dialog; an image load with EVERY
  registry window active lands on that window's target (or the
  empty-state fallback) and ``p`` reaches the dialog — except the Map
  window, where the landing is batch-77 LLR-116.5's auto-selected region
  row (LED .58 (a)) and ``down`` walks it (HLR-115); a healthy focus
  (visible, non-input) is NOT moved; a STALE text input (in a hidden
  window, or of area 0) IS re-homed, while a VISIBLE Find input in the
  active window keeps the focus and its typed text (LED .58 (c)); the
  persistent chrome's palette input is never taken; an empty-state target
  falls back to the window's first visible, focusable, non-text widget; a
  modal keeps its focus while a load finishes and the default screen's
  focus is judged, never the modal's; the landing is synchronous
  ``Screen.set_focus``, not ``Widget.focus()``.
  A load while the Split / Join / Export window is displayed lands on its
  table (the window's declared target). The modal-close arms (panel,
  dialog, question) are Inc 6 / Inc 9b / Inc 10 — not written here.
- TC-B100-13 (LLR-166.2): the A2L load tail applies the same rule, with the
  boundary arm of an A2L-only load (no image loaded).

Black-box AT:

- AT-B100-04 (HLR-166): through the shipped surface — the command palette
  (``ctrl+k``), a rail key and the real Load dialogs — after a project load
  and after a file load the focused widget has a non-zero painted region, is
  never a text input, and ``p``, ``k`` and ``t`` each reach their screen.
  Runs at 118x54 and 220x60 with notifications on. The base defect (P-16)
  is behavioural: the hidden Split/Join table holds the focus (region area
  0) and ``p`` never reaches the Load project dialog.
"""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

import pytest
from textual.widgets import Input, Label, ListItem, ListView, TextArea

from s19_app.tui.app import S19TuiApp
from s19_app.tui.screens import (
    LegendScreen,
    LoadFileScreen,
    LoadProjectScreen,
    ReportViewerScreen,
)
from s19_app.tui.screens_directionb import MemoryMapPanel, RegionRow
from s19_app.tui.workspace import WORKAREA_DIRNAME, WORKAREA_SUBDIR, WORKAREA_TEMP

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"
CASE01_DIR = EXAMPLES_DIR / "case_01_basic_valid"
CASE02_DIR = EXAMPLES_DIR / "case_02_gaps_and_patch_targets"
P1_NAME = "P1"

# ---------------------------------------------------------------------------
# Drivers and readers
# ---------------------------------------------------------------------------


async def _wait_for(pilot, predicate, description: str, attempts: int = 150) -> None:
    for _ in range(attempts):
        if predicate():
            return
        await pilot.pause()
    raise AssertionError(f"timed out waiting for {description}")


async def _flush(pilot, count: int = 12) -> None:
    for _ in range(count):
        await pilot.pause()


def _status_text(app: S19TuiApp) -> str:
    return str(app.query_one("#log_line_4", Label).render())


def _file_status_text(app: S19TuiApp) -> str:
    """The painted durable file-state line (the ``#status_text`` label)."""
    return str(app.query_one("#status_text", Label).render())


def _workarea(base: Path) -> Path:
    return base / WORKAREA_DIRNAME / WORKAREA_SUBDIR


def _seed_project_p1(workarea: Path) -> Path:
    """P1 — the case_01 project: S19 + MAC + A2L (enabler E4)."""
    project_dir = workarea / P1_NAME
    project_dir.mkdir(parents=True, exist_ok=True)
    for name in ("firmware.s19", "firmware.mac", "firmware.a2l"):
        shutil.copy2(CASE01_DIR / name, project_dir / name)
    return project_dir


async def _hide_split_join_window(
    app: S19TuiApp, pilot, return_key: str = "1"
) -> None:
    """Open the Split / Join / Export window, then switch back with a rail
    key: the window hides and no healthy focus remains (Textual clears the
    hidden table's focus). The load itself re-focuses the hidden table
    through ``watch_current_file`` — that stolen, zero-area focus is the
    executed P-16 shape this arm's oracle catches."""
    app.action_open_split_join_export()
    await _wait_for(
        pilot,
        lambda: app.focused is not None and app.focused.id == "sje_table",
        "the Split / Join / Export table focused",
    )
    await pilot.press(return_key)
    await _flush(pilot)


def _assert_focus_is_the_target(app: S19TuiApp, target_id: str) -> None:
    """The HLR-166 painted oracle: the focused widget is the window's
    declared target, has a non-zero region, and is never a text input."""
    focused = app.focused
    assert focused is not None, "the focus must land somewhere"
    assert focused.id == target_id, (
        f"the focus must land on the window's target #{target_id} "
        f"(got {type(focused).__name__}#{focused.id}, region {focused.region})"
    )
    assert focused.region.area > 0, (
        f"the focused target must paint a non-zero region (got {focused.region})"
    )
    assert not isinstance(focused, (Input, TextArea)), (
        f"the focused target must never be a text input (got {type(focused).__name__})"
    )


def _focus_is_settled_on(app: S19TuiApp, target_id: str) -> bool:
    focused = app.focused
    return (
        focused is not None
        and focused.id == target_id
        and focused.region.area > 0
        and not isinstance(focused, (Input, TextArea))
    )


async def _wait_for_focus_on_target(pilot, app: S19TuiApp, target_id: str) -> None:
    """Poll the painted focus until the load's queued steps have drained and
    the focus has SETTLED on the window's target, then assert it stays: the
    durable status line is painted synchronously while the load's
    ``call_later`` chain is still pending, so a single read can observe a
    transitional (stolen) focus. Only the settled state is the oracle. The
    timeout names the last painted focus — at base that is the P-16 line
    (``_SegTable#sje_table, region Region(0, 0, 0, 0)``)."""
    for _ in range(150):
        if _focus_is_settled_on(app, target_id):
            # The stays window covers the deferred render hooks that run
            # right after a load tail. On the Map window that hook is the
            # LLR-116.5 selection-follow, whose landing is the region row
            # itself — a different oracle, see _wait_for_map_row_landing —
            # so on every other window the settled focus cannot be
            # destabilized after this point.
            await _flush(pilot, 10)
            _assert_focus_is_the_target(app, target_id)
            return
        await pilot.pause()
    focused = app.focused
    raise AssertionError(
        f"timed out waiting for the focus to settle on the window's target "
        f"#{target_id} (painted region non-zero, never a text input); "
        f"last painted focus: "
        f"{type(focused).__name__ if focused is not None else None}"
        f"#{getattr(focused, 'id', None)}, "
        f"region {getattr(focused, 'region', None)}"
    )


def _focus_is_settled_on_map_row(app: S19TuiApp) -> bool:
    """LLR-116.5's landing (LED .58 (a)): the focus sits on a live region
    row whose start equals the panel's resolved selection, with a non-zero
    painted region. The row is the Map window's focus target — HLR-166's
    "named widget" ledger line for Map names the selected region row, an
    id-less widget by design."""
    focused = app.focused
    if focused is None or not isinstance(focused, RegionRow):
        return False
    if focused.region.area <= 0:
        return False
    panel = app.query_one("#memory_map_panel", MemoryMapPanel)
    return focused.region_start == panel._selected_cell_start


async def _wait_for_map_row_landing(pilot, app: S19TuiApp) -> None:
    """Poll the painted focus until the load's queued steps have drained and
    the focus has SETTLED on LLR-116.5's auto-selected region row, then
    assert it stays. The re-home tail may land on the declared target (the
    panel) first; the panel's selection-follow hook runs AFTER the tail and
    moves the focus onto the resolved row — the settled state is the only
    oracle. The timeout names the last painted focus: on the fix-pass-1
    tree it is `MemoryMapPanel#memory_map_panel` (the re-assertion the
    reviewer's map arrow probe caught)."""
    for _ in range(150):
        if _focus_is_settled_on_map_row(app):
            await _flush(pilot, 10)
            assert _focus_is_settled_on_map_row(app), (
                "the LLR-116.5 landing must hold through the stays window"
            )
            return
        await pilot.pause()
    focused = app.focused
    raise AssertionError(
        "timed out waiting for the LLR-116.5 landing: the focus on the "
        "auto-selected region row (region_start = the panel's resolved "
        f"selection); last painted focus: "
        f"{type(focused).__name__ if focused is not None else None}"
        f"#{getattr(focused, 'id', None)}, "
        f"region {getattr(focused, 'region', None)}"
    )


async def _assert_p_opens_the_project_dialog(app: S19TuiApp, pilot) -> None:
    """After the focus lands, the app's single-key bindings reach their
    actions: ``p`` opens the Load project dialog (the P-16 decisive line)."""
    await pilot.press("p")
    await _wait_for(
        pilot,
        lambda: isinstance(app.screen, LoadProjectScreen),
        "the Load project dialog (the `p` binding reached its action)",
    )
    assert await pilot.click("#project_cancel"), "click missed #project_cancel"
    await _wait_for(
        pilot,
        lambda: not isinstance(app.screen, LoadProjectScreen),
        "the Load project dialog closed",
    )


# ---------------------------------------------------------------------------
# TC-B100-12 — the focus-target table and the load tails (LLR-166.1)
# ---------------------------------------------------------------------------


def test_tc_b100_12_focus_target_table_matches_the_window_registry(
    tmp_path: Path,
) -> None:
    """The table is declared per window and asserted 1:1 against the
    window registry, both directions: exactly one focusable target per
    window (the 12 rail windows of ``SCREEN_CONTAINER_IDS`` plus the
    palette-only Split / Join / Export window), unique ids, and no target
    naming an ``Input`` / ``TextArea``. A window dropped from the table,
    an unfocusable target, or a text-input target fails THIS arm (the
    declared mutations), never a downstream re-home arm: a
    ``can_focus=False`` target is a silent no-op for ``Screen.set_focus``
    (P-16 survives invisibly), so focusability is part of the census."""
    expected = set(S19TuiApp.SCREEN_CONTAINER_IDS) | {"split_join"}
    targets = S19TuiApp._FOCUS_TARGETS
    assert set(targets) == expected, (
        f"one focus target per window, no more, no fewer: "
        f"missing {sorted(expected - set(targets))}, "
        f"extra {sorted(set(targets) - expected)}"
    )
    assert len(set(targets.values())) == len(targets), (
        "each window's target must be its own widget id"
    )

    async def _drive() -> None:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            for window_key, target_id in targets.items():
                widget = app.query_one(f"#{target_id}")
                assert widget.can_focus, (
                    f"the {window_key} window's target #{target_id} is not "
                    f"focusable; Screen.set_focus silently ignores it and "
                    f"the single keys die on that window (CW-U-2)"
                )
                assert not isinstance(widget, (Input, TextArea)), (
                    f"the {window_key} window's target #{target_id} names a "
                    f"text input ({type(widget).__name__}); a typed key must "
                    f"reach the app's bindings (CW-U-2)"
                )

    asyncio.run(_drive())


def test_tc_b100_12_load_file_tail_rehomes_focus(tmp_path: Path) -> None:
    """Load file (the dialog route's tail): with the focus on the hidden
    Split / Join table, the load tail re-homes it onto the workspace
    window's target and ``p`` reaches the Load project dialog. Base RED
    (P-16): ``focused region area: 0`` and ``p`` stays on Screen."""

    async def _drive() -> None:
        app = S19TuiApp(base_dir=tmp_path)
        # A project in the work area is what the `p` binding's dialog lists;
        # the arm loads a LOOSE file over it.
        _seed_project_p1(app.workarea)
        async with app.run_test() as pilot:
            await pilot.pause()
            await _hide_split_join_window(app, pilot)
            app.load_from_path(CASE01_DIR / "firmware.s19")
            await app.workers.wait_for_complete()
            await _wait_for(
                pilot,
                lambda: _file_status_text(app).startswith("Loaded "),
                "the durable file-state line",
            )
            await _wait_for_focus_on_target(pilot, app, "files_list")
            await _assert_p_opens_the_project_dialog(app, pilot)

    asyncio.run(_drive())


def test_tc_b100_12_load_project_tail_rehomes_focus(tmp_path: Path) -> None:
    """Load project: the project install runs the same tail and re-homes
    the focus the same way (base RED: the hidden table keeps the focus)."""

    async def _drive() -> None:
        app = S19TuiApp(base_dir=tmp_path)
        _seed_project_p1(app.workarea)
        async with app.run_test() as pilot:
            await pilot.pause()
            await _hide_split_join_window(app, pilot)
            app._handle_load_project(P1_NAME)
            await _flush(pilot)
            await _wait_for(
                pilot,
                lambda: f"Loaded project '{P1_NAME}'" in _status_text(app),
                f"the status naming the loaded project {P1_NAME}",
            )
            await _wait_for_focus_on_target(pilot, app, "files_list")
            await _assert_p_opens_the_project_dialog(app, pilot)

    asyncio.run(_drive())


def test_tc_b100_12_workarea_files_pick_rehomes_focus(tmp_path: Path) -> None:
    """Workarea Files pick: selecting a temp file in the workspace list
    re-homes the focus too — the third load path of LLR-166.1."""

    async def _drive() -> None:
        app = S19TuiApp(base_dir=tmp_path)
        _seed_project_p1(app.workarea)
        temp_dir = app.workarea / WORKAREA_TEMP
        temp_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(CASE01_DIR / "firmware.s19", temp_dir / "firmware.s19")
        async with app.run_test() as pilot:
            await pilot.pause()
            app.refresh_files()
            await _flush(pilot)
            await _hide_split_join_window(app, pilot)
            item = next(
                list_item
                for list_item in app.query_one("#files_list", ListView).query(
                    ListItem
                )
                if getattr(list_item, "data", None) == "firmware.s19"
            )
            app._load_from_item(item)
            await _wait_for(
                pilot,
                lambda: _file_status_text(app).startswith("Loaded "),
                "the durable file-state line",
            )
            await _wait_for_focus_on_target(pilot, app, "files_list")
            await _assert_p_opens_the_project_dialog(app, pilot)

    asyncio.run(_drive())


def test_tc_b100_12_rehome_lands_on_the_active_windows_target(
    tmp_path: Path,
) -> None:
    """The re-home lands on the ACTIVE window's target: with the MAC screen
    displayed and the focus on its records table, a load whose
    ``watch_current_file`` refresh steals the focus onto the hidden
    Split / Join table must end with the focus back on the MAC table —
    the same visible, non-input widget — never on another window's
    target."""

    async def _drive() -> None:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("3")  # MAC rail screen
            await _flush(pilot)
            app.query_one("#mac_records_list").focus()
            await _flush(pilot)
            assert app.focused is not None and app.focused.id == "mac_records_list"
            assert app.focused.region.area > 0
            app.load_selected_file(CASE01_DIR / "firmware.s19")
            await _flush(pilot)
            await _wait_for(
                pilot,
                lambda: _file_status_text(app).startswith("Loaded "),
                "the durable file-state line",
            )
            await _wait_for_focus_on_target(pilot, app, "mac_records_list")

    asyncio.run(_drive())


def test_tc_b100_12_split_join_window_target_is_its_table(tmp_path: Path) -> None:
    """Boundary: a load while the Split / Join / Export window is displayed
    keeps the focus on the window's own target — its range table, with a
    non-zero region — and the window keeps owning its single keys: ``p``
    pads there (LLR-135) instead of opening the Load project dialog, which
    stays a rail-window key."""

    async def _drive() -> None:
        app = S19TuiApp(base_dir=tmp_path)
        _seed_project_p1(app.workarea)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(CASE01_DIR / "firmware.s19")
            await _flush(pilot)
            await _wait_for(
                pilot,
                lambda: _file_status_text(app).startswith("Loaded "),
                "the durable file-state line",
            )
            app.action_open_split_join_export()
            await _wait_for(
                pilot,
                lambda: _focus_is_settled_on(app, "sje_table"),
                "the Split / Join / Export table focused with a non-zero "
                "painted region",
            )
            app.load_selected_file(CASE02_DIR / "firmware.s19")
            await _flush(pilot)
            await _wait_for(
                pilot,
                lambda: _file_status_text(app).startswith("Loaded "),
                "the durable file-state line of the second load",
            )
            await _wait_for_focus_on_target(pilot, app, "sje_table")
            # The window owns `p` while it holds the focus: the Load project
            # dialog must NOT open, and the focus stays on the table.
            await pilot.press("p")
            await _flush(pilot)
            assert not isinstance(app.screen, LoadProjectScreen), (
                "`p` on the Split / Join table pads there; the Load project "
                "dialog is a rail-window key (LLR-135)"
            )
            _assert_focus_is_the_target(app, "sje_table")

    asyncio.run(_drive())


@pytest.mark.parametrize("window_key", list(S19TuiApp.SCREEN_CONTAINER_IDS))
def test_tc_b100_12_every_window_load_lands_on_its_target(
    tmp_path: Path, window_key: str
) -> None:
    """EVERY window of the registry, not only the four the first pass
    drove: with the window active, an image load re-homes the focus onto
    the window's declared target (or the empty-state fallback) with a
    non-zero region, and ``p`` reaches the Load project dialog. The Map
    param pins LLR-116.5's landing instead (LED .58 (a)): the focus ends
    on the auto-selected region row whose start is the panel's resolved
    selection, and ``p`` reaches the dialog from there. The Diff and Map
    windows fail this on the pre-fix-pass-1 tree (P-16 itself: the
    hidden Split / Join table keeps the focus, or an unfocusable
    container swallows it silently)."""

    async def _drive() -> None:
        app = S19TuiApp(base_dir=tmp_path)
        _seed_project_p1(app.workarea)
        async with app.run_test() as pilot:
            await pilot.pause()
            # The executed P-16 shape: the load's ``watch_current_file``
            # steal re-focuses the hidden Split / Join table; the tail must
            # re-home onto the ACTIVE window's target.
            await _hide_split_join_window(app, pilot)
            app.action_show_screen(window_key)
            await _flush(pilot)
            app.load_selected_file(CASE01_DIR / "firmware.s19")
            await _flush(pilot)
            await _wait_for(
                pilot,
                lambda: _file_status_text(app).startswith("Loaded "),
                "the durable file-state line",
            )
            if window_key == "map":
                # LED .58 (a): on Map the landing is the LLR-116.5
                # auto-selected region row, not the declared target; the
                # panel stays the declared/empty-state target only.
                await _wait_for_map_row_landing(pilot, app)
            else:
                target_id = S19TuiApp._FOCUS_TARGETS[window_key]
                await _wait_for_focus_on_target(pilot, app, target_id)
            await _assert_p_opens_the_project_dialog(app, pilot)

    asyncio.run(_drive())


def test_tc_b100_12_map_load_keeps_the_region_row_and_down_walks_it(
    tmp_path: Path,
) -> None:
    """Black-box (LED .58 (a), HLR-115): the Map window shown with a rail
    key, a file load driven through the real Load file dialog, then
    ``down`` pressed at the keyboard — the focus stays on LLR-116.5's
    auto-selected region row and each ``down`` walks it to the next row.
    RED on the fix-pass-1 tree, whose re-assertion re-landed the focus on
    ``#memory_map_panel``, where ``down`` does nothing (the reviewer's
    map arrow probe)."""

    async def _drive() -> None:
        app = S19TuiApp(base_dir=tmp_path)
        _seed_project_p1(app.workarea)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("4")  # the Map rail screen
            await _flush(pilot)
            # case_02 merges enough runs for two `down` steps (the
            # reviewer's probe shape); case_01 has too few rows.
            await _load_file_through_dialog(
                pilot, app, CASE02_DIR / "firmware.s19"
            )
            await _wait_for_map_row_landing(pilot, app)
            first_start = app.focused.region_start
            await pilot.press("down")
            await _wait_for(
                pilot,
                lambda: (
                    isinstance(app.focused, RegionRow)
                    and app.focused.region.area > 0
                    and app.focused.region_start > first_start
                ),
                "the `down` key to walk the focus to the next region row",
            )
            second_start = app.focused.region_start
            await pilot.press("down")
            await _wait_for(
                pilot,
                lambda: (
                    isinstance(app.focused, RegionRow)
                    and app.focused.region.area > 0
                    and app.focused.region_start > second_start
                ),
                "the second `down` to walk to the next region row",
            )

    asyncio.run(_drive())


def test_tc_b100_12_hidden_map_row_is_rehomed(tmp_path: Path) -> None:
    """Review R3-1: a region row left holding the focus in a HIDDEN Map
    window is stale like any other widget and IS re-homed. With an image
    loaded the Map window lands the focus on LLR-116.5's row; a rail key
    hides the Map but the row keeps the focus (area 0) and still swallows
    ``up`` / ``down`` / ``enter``; an A2L load then runs its tail and the
    focus must land on the Workspace target. RED with a ``RegionRow``
    exemption in ``_focus_needs_rehome``: the focus stays on the hidden
    row."""

    async def _drive() -> None:
        app = S19TuiApp(base_dir=tmp_path)
        _seed_project_p1(app.workarea)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(CASE01_DIR / "firmware.s19")
            await _flush(pilot)
            await _wait_for(
                pilot,
                lambda: _file_status_text(app).startswith("Loaded "),
                "the durable file-state line",
            )
            await pilot.press("4")  # the Map rail screen
            await _flush(pilot)
            await _wait_for_map_row_landing(pilot, app)
            await pilot.press("1")  # the Workspace rail screen; Map hides
            await _flush(pilot)
            # The precondition the finding names: the hidden row still
            # holds the focus with no painted region.
            assert isinstance(app.focused, RegionRow), app.focused
            assert app.focused.region.area == 0
            app.load_a2l_from_path(CASE01_DIR / "firmware.a2l")
            await _flush(pilot)
            await _wait_for(
                pilot,
                lambda: "A2L loaded:" in _status_text(app),
                "the A2L loaded status",
            )
            await _wait_for_focus_on_target(pilot, app, "files_list")
            await _assert_p_opens_the_project_dialog(app, pilot)

    asyncio.run(_drive())


def test_tc_b100_12_healthy_focus_is_not_moved(tmp_path: Path) -> None:
    """The healthy-focus early return, in the shape that actually exercises
    it: an image is loaded on Workspace, the operator's focus sits on a
    visible, non-target, non-text widget (``#hex_scroll``), and an A2L
    load runs its tail WITHOUT a ``current_file`` change — nothing steals
    the focus first, so the early return is what keeps it. Mutant R1
    (always re-home) moves it onto ``files_list`` and goes RED here."""

    async def _drive() -> None:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(CASE01_DIR / "firmware.s19")
            await _flush(pilot)
            await _wait_for(
                pilot,
                lambda: _file_status_text(app).startswith("Loaded "),
                "the durable file-state line",
            )
            app.query_one("#hex_scroll").focus()
            await _flush(pilot)
            assert app.focused is not None and app.focused.id == "hex_scroll"
            assert app.focused.region.area > 0
            app.load_a2l_from_path(CASE01_DIR / "firmware.a2l")
            await _flush(pilot)
            await _wait_for(
                pilot,
                lambda: "A2L loaded:" in _status_text(app),
                "the A2L loaded status",
            )
            # The tail — and the deferred render hooks behind it — have
            # drained; a healthy focus must not have moved.
            await _flush(pilot, 10)
            assert app.focused is not None and app.focused.id == "hex_scroll", (
                f"a healthy focus must not be moved (got {app.focused!r})"
            )

    asyncio.run(_drive())


def test_tc_b100_12_stale_text_input_in_a_content_window_is_rehomed(
    tmp_path: Path,
) -> None:
    """LED .58 (c), the stale half: a text input the load left STALE — in
    a hidden window — IS re-homed. With an image loaded, the operator's
    focus sits in the A2L window's Find field ``#a2l_tag_find_input``; the
    A2L window is then hidden by a workspace switch (Textual clears the
    hidden window's focus when the hide processes, so the arm re-installs
    the stale input focus directly — the same ``set_focus`` shape the
    synchronous arm uses) and an A2L load runs its tail — nothing steals
    the focus first — so the predicate's stale clauses are what move it
    onto the active window's target; ``p`` then opens the Load project
    dialog. Base RED: no re-home exists, the focus stays on the hidden
    input."""

    async def _drive() -> None:
        app = S19TuiApp(base_dir=tmp_path)
        _seed_project_p1(app.workarea)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(CASE01_DIR / "firmware.s19")
            await _flush(pilot)
            await _wait_for(
                pilot,
                lambda: _file_status_text(app).startswith("Loaded "),
                "the durable file-state line",
            )
            await pilot.press("2")  # the A2L rail screen
            await _flush(pilot)
            app.query_one("#a2l_tag_find_input", Input).focus()
            await _flush(pilot)
            assert app.focused is not None and app.focused.id == (
                "a2l_tag_find_input"
            )
            assert app.focused.region.area > 0
            app.action_show_screen("workspace")  # the A2L window hides
            await _flush(pilot)
            # Re-install the stale input focus: the clause's shape is an
            # input that HOLDS the focus while sitting in a hidden window.
            # ``set_focus`` takes it because ``focusable`` consults
            # ``visible``, not ``display`` (the batch-93 guard in
            # ``_apply_auto_selection``).
            stale_input = app.query_one("#a2l_tag_find_input", Input)
            app.default_screen.set_focus(stale_input)
            assert app.default_screen.focused is stale_input
            app.load_a2l_from_path(CASE01_DIR / "firmware.a2l")
            await _flush(pilot)
            await _wait_for(
                pilot,
                lambda: "A2L loaded:" in _status_text(app),
                "the A2L loaded status",
            )
            await _wait_for_focus_on_target(pilot, app, "files_list")
            await _assert_p_opens_the_project_dialog(app, pilot)

    asyncio.run(_drive())


def test_tc_b100_12_visible_find_input_keeps_its_focus(tmp_path: Path) -> None:
    """LED .58 (c), the visible half: a VISIBLE text input in the ACTIVE
    window is where the operator is typing — it keeps the focus AND its
    typed text across a load tail (the A2L tail steals nothing first):
    the next typed key is text in the field, not a command. RED on the
    fix-pass-1 tree, whose text clause took every content-window input."""

    async def _drive() -> None:
        app = S19TuiApp(base_dir=tmp_path)
        _seed_project_p1(app.workarea)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(CASE01_DIR / "firmware.s19")
            await _flush(pilot)
            await _wait_for(
                pilot,
                lambda: _file_status_text(app).startswith("Loaded "),
                "the durable file-state line",
            )
            app.query_one("#search_input", Input).focus()
            await _flush(pilot)
            assert app.focused is not None and app.focused.id == "search_input"
            assert app.focused.region.area > 0
            await pilot.press(*"abc")
            await _flush(pilot)
            assert app.query_one("#search_input", Input).value == "abc"
            app.load_a2l_from_path(CASE01_DIR / "firmware.a2l")
            await _flush(pilot)
            await _wait_for(
                pilot,
                lambda: "A2L loaded:" in _status_text(app),
                "the A2L loaded status",
            )
            # The tail and the deferred render hooks behind it have run.
            await _flush(pilot, 10)
            find_input = app.query_one("#search_input", Input)
            assert app.focused is not None and app.focused.id == "search_input", (
                f"a visible Find input keeps the focus while a load finishes "
                f"(got {app.focused!r})"
            )
            assert find_input.value == "abc", (
                f"the typed text stays in the field (got {find_input.value!r})"
            )
            await pilot.press("z")
            await _flush(pilot)
            assert find_input.value == "abcz", (
                "the next typed key is text in the field, not a command "
                f"(got {find_input.value!r})"
            )
            assert type(app.screen).__name__ == "Screen", (
                "typing must not have dispatched a command / opened a screen "
                f"(got {type(app.screen).__name__})"
            )

    asyncio.run(_drive())


def test_tc_b100_12_empty_state_target_falls_back(tmp_path: Path) -> None:
    """LED .57 (b): in a bare session the Workspace window shows its empty
    state and the declared target ``#files_list`` paints no region. An
    A2L-only load that finds a bad focus lands on the window's first
    visible, focusable, non-text widget — the Workspace window's help
    chip — instead of an invisible widget, and ``p`` still reaches the
    Load project dialog."""

    async def _drive() -> None:
        app = S19TuiApp(base_dir=tmp_path)
        _seed_project_p1(app.workarea)
        async with app.run_test() as pilot:
            await pilot.pause()
            await _hide_split_join_window(app, pilot)
            assert app.query_one("#files_list").region.area == 0, (
                "the precondition: a bare session shows the empty state and "
                "the declared target paints no region"
            )
            app.load_a2l_from_path(CASE01_DIR / "firmware.a2l")
            await _flush(pilot)
            await _wait_for(
                pilot,
                lambda: "A2L loaded:" in _status_text(app),
                "the A2L loaded status",
            )
            await _wait_for_focus_on_target(pilot, app, "window_help_workspace")
            await _assert_p_opens_the_project_dialog(app, pilot)

    asyncio.run(_drive())


def test_tc_b100_12_palette_input_is_never_taken(tmp_path: Path) -> None:
    """LED .57 (c): while the operator types in the command palette, a
    load that finishes re-homes nothing — the visible, persistent-chrome
    ``#palette_input`` keeps the focus and the typed text stays in the
    field: the next key is text, not a command."""

    async def _drive() -> None:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(CASE01_DIR / "firmware.s19")
            await _flush(pilot)
            await _wait_for(
                pilot,
                lambda: _file_status_text(app).startswith("Loaded "),
                "the durable file-state line",
            )
            await pilot.press("ctrl+k")
            await _wait_for(
                pilot,
                lambda: app.focused is not None and app.focused.id == "palette_input",
                "the palette filter input focused",
            )
            await pilot.press(*"Spl")
            await _flush(pilot)
            app.load_a2l_from_path(CASE01_DIR / "firmware.a2l")
            await _flush(pilot)
            await _wait_for(
                pilot,
                lambda: "A2L loaded:" in _status_text(app),
                "the A2L loaded status",
            )
            # The tail — and the deferred render hooks behind it — have run.
            await _flush(pilot, 10)
            palette_input = app.query_one("#palette_input", Input)
            assert app.focused is not None and app.focused.id == "palette_input", (
                f"the palette input keeps the focus while a load finishes "
                f"(got {app.focused!r})"
            )
            assert palette_input.value == "Spl", (
                f"the typed text stays in the field (got {palette_input.value!r})"
            )
            await pilot.press("i")
            await _flush(pilot)
            assert palette_input.value == "Spli", (
                "the next typed key is text in the field, not a command "
                f"(got {palette_input.value!r})"
            )
            assert type(app.screen).__name__ == "Screen", (
                "typing must not have dispatched a command / opened a screen "
                f"(got {type(app.screen).__name__})"
            )

    asyncio.run(_drive())


def test_tc_b100_12_modal_keeps_its_focus_while_a_load_finishes(
    tmp_path: Path,
) -> None:
    """LED .57 (d): the rule reads ``default_screen.focused`` — never
    ``self.focused`` — so a widget inside an open modal is never judged
    or moved: the Load file dialog keeps ``#load_path``, and the default
    screen's healthy focus (``#hex_scroll``) is not re-homed behind the
    modal either."""

    async def _drive() -> None:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(CASE01_DIR / "firmware.s19")
            await _flush(pilot)
            await _wait_for(
                pilot,
                lambda: _file_status_text(app).startswith("Loaded "),
                "the durable file-state line",
            )
            app.query_one("#hex_scroll").focus()
            await _flush(pilot)
            assert app.default_screen.focused is not None
            assert app.default_screen.focused.id == "hex_scroll"
            await pilot.press("l")
            await _wait_for(
                pilot,
                lambda: isinstance(app.screen, LoadFileScreen),
                "the Load file dialog",
            )
            assert await pilot.click("#load_path"), "click missed #load_path"
            await _flush(pilot)
            assert app.focused is not None and app.focused.id == "load_path"
            app.load_a2l_from_path(CASE01_DIR / "firmware.a2l")
            await _flush(pilot)
            await _wait_for(
                pilot,
                lambda: "A2L loaded:" in _status_text(app),
                "the A2L loaded status",
            )
            # The tail — and the deferred render hooks behind it — have run.
            await _flush(pilot, 10)
            assert isinstance(app.screen, LoadFileScreen), (
                "the modal stays open while a load finishes"
            )
            assert app.focused is not None and app.focused.id == "load_path", (
                f"the modal keeps its focus (got {app.focused!r})"
            )
            assert app.default_screen.focused is not None, (
                "the default screen's focus is judged, never the modal's"
            )
            assert app.default_screen.focused.id == "hex_scroll", (
                f"a healthy default-screen focus is not re-homed behind the "
                f"modal (got {app.default_screen.focused!r})"
            )

    asyncio.run(_drive())


def test_tc_b100_12_bad_default_focus_is_rehomed_behind_a_modal(
    tmp_path: Path,
) -> None:
    """LED .57 (d), the re-home side: with a modal open, the rule judges
    the DEFAULT screen's focus — a bad default-screen focus (the hidden
    Split / Join table) is re-homed onto the window's target BEHIND the
    modal, which keeps its own focus. Mutant LD (the rule reads
    ``self.focused``) judges the modal's widget instead and goes RED."""

    async def _drive() -> None:
        app = S19TuiApp(base_dir=tmp_path)
        _seed_project_p1(app.workarea)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(CASE01_DIR / "firmware.s19")
            await _flush(pilot)
            await _wait_for(
                pilot,
                lambda: _file_status_text(app).startswith("Loaded "),
                "the durable file-state line",
            )
            await pilot.press("p")
            await _wait_for(
                pilot,
                lambda: isinstance(app.screen, LoadProjectScreen),
                "the Load project dialog",
            )
            await _flush(pilot)
            modal_focused = app.focused
            assert modal_focused is not None, "the modal holds a focus"
            # Install the P-16 shape on the default screen, behind the modal.
            hidden_table = app.query_one("#sje_table")
            app.default_screen.set_focus(hidden_table)
            assert app.default_screen.focused is hidden_table
            app.load_a2l_from_path(CASE01_DIR / "firmware.a2l")
            await _flush(pilot)
            await _wait_for(
                pilot,
                lambda: "A2L loaded:" in _status_text(app),
                "the A2L loaded status",
            )
            # The tail — and the deferred render hooks behind it — have run.
            await _flush(pilot, 10)
            assert app.focused is modal_focused, (
                f"the modal keeps its focus (got {app.focused!r})"
            )
            assert app.default_screen.focused is not None, (
                "the default screen's focus is judged, never the modal's"
            )
            assert app.default_screen.focused.id == "files_list", (
                f"a bad default-screen focus is re-homed behind the modal "
                f"(got {app.default_screen.focused!r})"
            )

    asyncio.run(_drive())


def test_tc_b100_12_rehome_lands_synchronously(tmp_path: Path) -> None:
    """The landing is a synchronous ``Screen.set_focus``, not
    ``Widget.focus()`` (which only queues a ``call_later`` the callbacks
    behind the tail would then override): calling the re-home moves the
    focus NOW, with no pause for the queue to drain. Mutant R5
    (``target.focus()``) goes RED here."""

    async def _drive() -> None:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(CASE01_DIR / "firmware.s19")
            await _flush(pilot)
            await _wait_for(
                pilot,
                lambda: _file_status_text(app).startswith("Loaded "),
                "the durable file-state line",
            )
            # The P-16 shape, installed directly: the hidden Split / Join
            # table holds the focus (a zero-area region).
            hidden_table = app.query_one("#sje_table")
            app.default_screen.set_focus(hidden_table)
            assert app.focused is hidden_table
            assert app.focused.region.area == 0
            app._rehome_focus_after_load()
            assert app.focused is app.query_one("#files_list"), (
                f"the re-home must land synchronously (got {app.focused!r})"
            )
            assert app.focused.region.area > 0

    asyncio.run(_drive())


# ---------------------------------------------------------------------------
# TC-B100-13 — the A2L load tail re-homes the focus (LLR-166.2)
# ---------------------------------------------------------------------------


def test_tc_b100_13_a2l_tail_rehomes_focus(tmp_path: Path) -> None:
    """The A2L load tail applies the LLR-166.1 rule: with the focus on the
    hidden Split / Join table, an A2L load re-homes it onto the window's
    target and ``p`` reaches the Load project dialog."""

    async def _drive() -> None:
        app = S19TuiApp(base_dir=tmp_path)
        _seed_project_p1(app.workarea)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.load_selected_file(CASE01_DIR / "firmware.s19")
            await _flush(pilot)
            await _wait_for(
                pilot,
                lambda: _file_status_text(app).startswith("Loaded "),
                "the durable file-state line",
            )
            await _hide_split_join_window(app, pilot)
            app.load_a2l_from_path(CASE01_DIR / "firmware.a2l")
            await _flush(pilot)
            await _wait_for(
                pilot,
                lambda: "A2L loaded:" in _status_text(app),
                "the A2L loaded status",
            )
            await _wait_for_focus_on_target(pilot, app, "files_list")
            await _assert_p_opens_the_project_dialog(app, pilot)

    asyncio.run(_drive())


def test_tc_b100_13_a2l_only_load_with_no_image(tmp_path: Path) -> None:
    """Boundary: an A2L load with NO image loaded still re-homes the focus.
    The A2L rail screen owns no empty state, so its table is the visible
    target even in a bare session."""

    async def _drive() -> None:
        app = S19TuiApp(base_dir=tmp_path)
        _seed_project_p1(app.workarea)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("2")  # A2L rail screen
            await _flush(pilot)
            await _hide_split_join_window(app, pilot, return_key="2")
            app.load_a2l_from_path(CASE01_DIR / "firmware.a2l")
            await _flush(pilot)
            await _wait_for(
                pilot,
                lambda: "A2L loaded:" in _status_text(app),
                "the A2L loaded status",
            )
            await _wait_for_focus_on_target(pilot, app, "a2l_tags_list")
            await _assert_p_opens_the_project_dialog(app, pilot)

    asyncio.run(_drive())


# ---------------------------------------------------------------------------
# AT-B100-04 — HLR-166 through the shipped surface (black-box)
# ---------------------------------------------------------------------------


async def _open_split_join_via_palette(pilot, app: S19TuiApp) -> None:
    """Open the Split / Join / Export window black-box: ``ctrl+k`` opens the
    command palette, the typed name filters it to one entry, ``enter``
    dispatches it (the palette closes itself on dispatch)."""
    await pilot.press("ctrl+k")
    await _wait_for(
        pilot,
        lambda: app.focused is not None and app.focused.id == "palette_input",
        "the palette filter input focused",
    )
    await pilot.press(*"Split / Join / Export")
    await _wait_for(
        pilot,
        lambda: "Split / Join / Export"
        in app.query_one("#command_bar").visible_palette_labels(),
        "the palette listing the Split / Join / Export entry",
    )
    await pilot.press("enter")
    await _wait_for(
        pilot,
        lambda: app.focused is not None and app.focused.id == "sje_table",
        "the Split / Join / Export window open with its table focused",
    )


async def _load_project_through_dialog(pilot, app: S19TuiApp, name: str) -> None:
    """Drive the Load project dialog (rail key ``p``) and wait for the load."""
    await pilot.press("p")
    await _wait_for(
        pilot,
        lambda: isinstance(app.screen, LoadProjectScreen),
        "the Load project dialog",
    )
    row = next(
        item
        for item in app.screen.query("#project_list ListItem")
        if str(item.query_one(Label).render()) == name
    )
    await pilot.click(row)
    assert await pilot.click("#project_ok"), "click missed #project_ok"
    await _wait_for(
        pilot,
        lambda: f"Loaded project '{name}'" in _status_text(app),
        f"the status naming the loaded project {name}",
    )


async def _load_file_through_dialog(pilot, app: S19TuiApp, src: Path) -> None:
    """Drive the Load file dialog (rail key ``l``) and wait for the load.
    The settle condition is the DURABLE ``#status_text`` file-state line
    plus the dialog being closed — both painted, both observable."""
    await pilot.press("l")
    await _wait_for(
        pilot,
        lambda: isinstance(app.screen, LoadFileScreen),
        "the Load file dialog",
    )
    assert await pilot.click("#load_path"), "click missed #load_path"
    await pilot.press("ctrl+a")
    await pilot.press("delete")
    await pilot.press(*str(src))
    assert await pilot.click("#load_ok"), "click missed #load_ok"
    await _wait_for(
        pilot,
        lambda: not isinstance(app.screen, LoadFileScreen)
        and _file_status_text(app).startswith("Loaded "),
        f"the durable load line after loading {src.name}",
    )


@pytest.mark.parametrize("size", [(118, 54), (220, 60)])
def test_at_b100_04_focus_lands_and_single_keys_reach_their_screens(
    tmp_path: Path, size: tuple
) -> None:
    """HLR-166 black-box: after a project load and after a file load the
    focused widget is a named, visible, non-text widget (observed through
    the painted region — never a private attribute), and the single-key
    bindings reach their actions: ``p`` opens the Load project dialog,
    ``k`` opens the Legend, ``t`` opens the report viewer. Base RED (P-16):
    the hidden Split / Join table holds the focus and ``p`` stays on
    Screen."""
    base = tmp_path / "app"
    # A distinct image for the second load (a different byte content under
    # the same stem would collide with the project's variant id).
    src02 = tmp_path / "sources" / "case02" / "firmware.s19"
    src02.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(CASE02_DIR / "firmware.s19", src02)

    async def _drive() -> None:
        app = S19TuiApp(base_dir=base)
        _seed_project_p1(app.workarea)
        async with app.run_test(size=size, notifications=True) as pilot:
            await pilot.pause()
            # The P-16 shape, built through the shipped surface: the
            # palette-first Split / Join / Export window opens and takes the
            # focus onto its table; a rail key hides the window and the
            # table keeps the focus.
            await _open_split_join_via_palette(pilot, app)
            await pilot.press("1")
            await _flush(pilot)

            # Route 1 — Load project through its dialog.
            await _load_project_through_dialog(pilot, app, P1_NAME)
            await _wait_for_focus_on_target(pilot, app, "files_list")
            await _assert_p_opens_the_project_dialog(app, pilot)

            # The other single-key surfaces reach their screens too.
            await pilot.press("k")
            await _wait_for(
                pilot,
                lambda: isinstance(app.screen, LegendScreen),
                "the Legend screen (the `k` binding reached its action)",
            )
            await pilot.press("escape")
            await _wait_for(
                pilot,
                lambda: not isinstance(app.screen, LegendScreen),
                "the Legend screen closed",
            )
            await pilot.press("t")
            await _wait_for(
                pilot,
                lambda: isinstance(app.screen, ReportViewerScreen),
                "the report viewer (the `t` binding reached its action)",
            )
            assert await pilot.click("#report_close"), "click missed #report_close"
            await _wait_for(
                pilot,
                lambda: not isinstance(app.screen, ReportViewerScreen),
                "the report viewer closed",
            )

            # Route 2 — Load file through its dialog: the same focus landing.
            await _load_file_through_dialog(pilot, app, src02)
            await _wait_for_focus_on_target(pilot, app, "files_list")
            await _assert_p_opens_the_project_dialog(app, pilot)

    asyncio.run(_drive())
