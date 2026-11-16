"""Batch-103 Inc 9 E4 (tester T9b): the bench's keys and focus - R-PE-BENCH.40 ... .49.

Widget ``ArrayBenchSheet`` (``bench_sheet.py``: B23 BINDINGS and ``check_action``, B24 ``action_edit``, B25 ... B27,
B29 ``_on_formula_escape``, B28 ``action_stage_record``). Cases: ``inc-9/02-test-cases-W.md``. The real app under
Pilot at 118x54; every key is a ``pilot.press``; the app's own bindings are replaced by counters so a key that
falls through to the app is SEEN (R-PE-BENCH.44, .49), never inferred.

Controls: 44 / 49 are one pair - the same key with the bench focused runs 0 app actions (44), with the bench
not focused runs 1 (49); a binding with no ``check_action`` fails one of the two.
"""
from __future__ import annotations

import pytest

from s19_app.tui.app import S19TuiApp
from tests.support.b103_inc9_b import EX
from tests.support.b103_inc9_w import (  # noqa: F401  (defc_dir is a fixture used by name)
    DISPLAY, INPUT, MAP, VB, apply_tool, body_text, defc_dir, entries_of, has_values, need, open_bench, pick,
    run, sheet_of, st, wait_for,
)

#: The three app bindings the tool keys shadow. pageup / pagedown are left out on purpose: the panel is a
#: ScrollableContainer whose own pageup / pagedown bindings answer before the app's, so off the bench those keys
#: scroll the panel and never reach ``page_*_context``; a count of 0 there would not be a defect.
APP_ACTIONS = {"s": "save_project", "d": "a2l_describe_tag", "p": "load_project"}


def count_app_actions(monkeypatch) -> dict:
    """Replace the app actions the tool keys shadow by counters: a key that reaches the app is counted."""
    counts = {name: 0 for name in APP_ACTIONS.values()}
    for name in counts:
        def stand_in(self, *args, _name=name):
            counts[_name] += 1
        monkeypatch.setattr(S19TuiApp, f"action_{name}", stand_in)
    return counts


def focused_id(app):
    return getattr(app.focused, "id", None)


# ------------------------------------------------------------------ R-PE-BENCH.40


def test_r_pe_bench_40_1_enter_on_a_map_row_gives_the_bench_the_focus(tmp_path, defc_dir):
    """MAP_DEF_0001 + Enter: the bench holds the focus, the cursor marker `▸` stands before cell (0,0)'s text."""

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await pick(pilot, sheet, MAP)
        await wait_for(pilot, lambda: has_values(sheet, MAP), "the values of MAP_DEF_0001")
        control = "▸" in body_text(app)
        await pilot.press("enter")
        await pilot.pause()
        return control, st(sheet, MAP).focus, focused_id(app), body_text(app)

    control, focus, focused, painted = run(tmp_path, defc_dir, body)
    assert control is False, "the marker is shown before the bench has the focus"
    assert focus is True and focused == "patch_sheet_body"
    marked = [line for line in painted.splitlines() if "▸" in line]
    assert len(marked) == 1 and str(EX.MAP[0]) in marked[0], marked


def test_r_pe_bench_40_2_enter_on_a_number_row_focuses_the_formula_input(tmp_path, defc_dir):
    """A number row keeps Inc 8's R-PE-DEF.46: Enter gives the formula input the focus, no bench focus."""

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await pick(pilot, sheet, DISPLAY)
        await pilot.press("enter")
        await pilot.pause()
        state = st(sheet, DISPLAY)
        return focused_id(app), bool(state is not None and state.focus), "▸" in body_text(app)

    focused, bench_focus, marker = run(tmp_path, defc_dir, body)
    assert focused == "patch_sheet_input" and bench_focus is False and marker is False


# ------------------------------------------------------------------ R-PE-BENCH.44 (+ .49's other half)


@pytest.mark.parametrize("key", ["s", "d", "p", "i", "m"])
def test_r_pe_bench_44_a_tool_key_selects_its_tool_and_the_app_does_not_run(tmp_path, defc_dir, monkeypatch, key):
    """44/1 `s` Set · 44/2 `d` +Δ · 44/3 `p` ×% · 44/4 `i` Interpolate · 44/5 `m` Smooth. The app's `save_project`
    (`s`), `a2l_describe_tag` (`d`) and `load_project` (`p`) run 0 times while the bench has the focus."""
    counts = count_app_actions(monkeypatch)
    other = "d" if key == "s" else "s"

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await open_bench(pilot, sheet, MAP)
        await pilot.press(other)  # a tool other than the one under test, so a "no change" cannot pass
        await pilot.pause()
        before = st(sheet, MAP).tool
        await pilot.press(key)
        await pilot.pause()
        return before, st(sheet, MAP).tool

    before, after = run(tmp_path, defc_dir, body)
    assert before == other and after == key
    assert counts == {name: 0 for name in counts}, counts


# ------------------------------------------------------------------ R-PE-BENCH.45, .46, .47


def test_r_pe_bench_45_1_enter_on_the_bench_moves_the_focus_to_the_op_input(tmp_path, defc_dir):
    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await open_bench(pilot, sheet, MAP)
        await pilot.press("enter")
        await pilot.pause()
        return focused_id(app)

    assert run(tmp_path, defc_dir, body) == "patch_sheet_input"


def test_r_pe_bench_46_1_escape_on_the_bench_returns_to_the_rows_and_up_selects_the_row_above(tmp_path, defc_dir):
    """Escape: bench focus off, the body holds the focus (the screen does not go back), then `up` moves the row."""

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        names = [row.name for row in sheet.rows]
        target = next(name for name in (MAP, VB) if names.index(name) > 0)
        await open_bench(pilot, sheet, target)
        await pilot.press("escape")
        await pilot.pause()
        shown = (st(sheet, target).focus, focused_id(app))
        await pilot.press("up")
        await pilot.pause()
        return shown, names[names.index(target) - 1], sheet.selected_name

    (focus, focused), above, selected = run(tmp_path, defc_dir, body)
    assert focus is False and focused == "patch_sheet_body"
    assert selected == above


def test_r_pe_bench_47_1_escape_in_the_op_input_returns_to_the_bench_and_keeps_the_operand(tmp_path, defc_dir):
    """Control: Inc 8's R-PE-DEF.48 (focus to the rows, text cleared) is the number row's behaviour (49/2)."""

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await open_bench(pilot, sheet, MAP)
        await pilot.press("d", "enter")
        await pilot.pause()
        need(sheet, INPUT).value = "100"
        await pilot.pause()
        await pilot.press("escape")
        await pilot.pause()
        return focused_id(app), st(sheet, MAP).focus, need(sheet, INPUT).value

    focused, focus, operand = run(tmp_path, defc_dir, body)
    assert focused == "patch_sheet_body" and focus is True
    assert operand == "100"


# ------------------------------------------------------------------ R-PE-BENCH.48


async def vb_with_a_set_edit(pilot, sheet, *, back: bool):
    """VAL_BLK_DEF_0001 selected, Set `10` applied on (0,0); the focus ends on the bench or in the op input."""
    await open_bench(pilot, sheet, VB)
    await apply_tool(pilot, sheet, "s", "10", back=back)
    await wait_for(pilot, lambda: dict(st(sheet, VB).edit) == {(0, 0): "10"}, "the Set edit of (0,0)")


@pytest.mark.parametrize("origin", ["the bench", "the op input"])
def test_r_pe_bench_48_alt_s_asks_for_the_record_stage_from_the_bench_and_from_the_op_input(tmp_path, defc_dir, origin):
    """48/1 from the bench, 48/2 from the op input: one bytes entry for the whole record appears; control: the
    entries are empty before the key."""

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await vb_with_a_set_edit(pilot, sheet, back=origin == "the bench")
        where = focused_id(app)
        before = entries_of(app)
        await pilot.press("alt+s")
        await wait_for(pilot, lambda: len(entries_of(app)) == 1, "the staged record", 60)
        return where, before, entries_of(app)

    where, before, after = run(tmp_path, defc_dir, body)
    assert where == ("patch_sheet_body" if origin == "the bench" else "patch_sheet_input")
    assert before == [] and len(after) == 1 and len(after[0][1]) == 12


# ------------------------------------------------------------------ R-PE-BENCH.49


@pytest.mark.parametrize("key", list(APP_ACTIONS))
@pytest.mark.parametrize("row", [DISPLAY, MAP])
def test_r_pe_bench_49_1_off_the_bench_the_keys_reach_the_app(tmp_path, defc_dir, monkeypatch, row, key):
    """49/1: DISPLAY_0001 selected, the body focused, `s` -> the app's save_project runs once. The same for `d` and
    `p` and for a bench row the bench does not yet have the focus on (check_action False)."""
    counts = count_app_actions(monkeypatch)

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await pick(pilot, sheet, row)
        sheet.query_one("#patch_sheet_body").focus()
        await pilot.pause()
        await pilot.press(key)
        await pilot.pause()
        state = st(sheet, row)
        return bool(state is not None and state.focus)

    focus = run(tmp_path, defc_dir, body)
    assert focus is False
    assert counts[APP_ACTIONS[key]] == 1, counts


def test_r_pe_bench_49_2_escape_on_a_number_row_keeps_inc_8s_behaviour(tmp_path, defc_dir):
    """Escape in the formula input of a number row: the text is cleared, the focus goes to the rows (R-PE-DEF.48)."""

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await pick(pilot, sheet, DISPLAY)
        await pilot.press("enter")
        await pilot.pause()
        need(sheet, INPUT).value = "26"
        await pilot.pause()
        typed = DISPLAY in sheet.pending
        await pilot.press("escape")
        await pilot.pause()
        return typed, DISPLAY in sheet.pending, focused_id(app)

    typed, pending, focused = run(tmp_path, defc_dir, body)
    assert typed is True, "control: the typed text was pending before Escape"
    assert pending is False and focused == "patch_sheet_body"
