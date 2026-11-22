"""Batch-103 Inc 8 E4, group P - the panel feeds the staging sheet (P5, P6, P10', P11).

Cases: ``02-test-cases-P.md`` (R-PE-DEF.10, .11, .18, .49, .62).  A2L and image load through the
app's own loaders; the sheet's rows are read off the painted ``#patch_sheet_body``; the picker's
state is read through its public properties.  Expected names come from the picker's own
``visible_params`` (never retyped); expected Current values come from the DEFC objects
(DISPLAY_0001 raw 0x011F with factor 0.5 -> 143.5, EX-R12's 287 with factor 1.0).
"""
from __future__ import annotations

import sys

sys.path.insert(0, ".")
import s19_app

print(f"S19_APP_UNDER_TEST={s19_app.__file__}", flush=True)

import pytest
from textual.widgets import Input, TextArea

from s19_app.tui.a2l_parse import parse_a2l_file
from tests.support.b100_workers import settle_workers
from tests.support.b103_inc8_p import (
    ENUM_RENAMED,
    FACTOR_ONE,
    SIZE,
    body_rows,
    build_defc,
    build_defc_variant,
    build_many_names_a2l,
    click_visible,
    drive,
    names_of,
    need,
    row_of,
    selected_name,
    settle,
    show_tab,
)

CURRENT_143_5 = "143.5"
CURRENT_287 = "287"
STAGED_NEW = "25.5"
STAGED_BYTES = "00 33"  # EX-S1: DISPLAY_0001 25.5 -> raw 51 -> 00 33


@pytest.fixture(scope="module")
def defc(tmp_path_factory):
    return build_defc(tmp_path_factory.mktemp("inc8_p_wiring_defc"))


def _loaded(defc_dir):
    return dict(a2l=defc_dir / "definitions.a2l", image=defc_dir / "definitions.s19")


async def _until(pilot, predicate, what: str, rounds: int = 60) -> None:
    for _ in range(rounds):
        await pilot.pause()
        if predicate():
            return
    raise AssertionError(f"timed out waiting for {what}")


def _picker(panel):
    return panel._a2l_picker


async def _set_filter(pilot, panel, text: str) -> None:
    need(panel, "#patch_param_filter", Input).value = text
    await settle(pilot, 6)


# --------------------------------------------------------------------------- #
# R-PE-DEF.10 - one sheet row per parameter of the shown page, in page order
# --------------------------------------------------------------------------- #


def test_r_pe_def_10_1_a_population_gives_one_row_per_visible_parameter_in_order(defc, tmp_path):
    async def body(app, pilot, panel):
        names = names_of(_picker(panel).visible_params)
        assert len(names) == 8, names
        rows = body_rows(app)
        first_lines = [next(i for i, line in enumerate(rows) if name in line) for name in names]
        assert first_lines == sorted(first_lines), f"rows are not in page order: {first_lines}"

    drive(tmp_path, SIZE, body, **_loaded(defc))


def test_r_pe_def_10_2_a_filter_shows_only_the_matching_rows(defc, tmp_path):
    async def body(app, pilot, panel):
        await _set_filter(pilot, panel, "MASK")
        names = names_of(_picker(panel).visible_params)
        assert names and all("MASK" in name for name in names), names
        text = "\n".join(body_rows(app))
        for name in names:
            assert name in text, f"{name} missing from {text}"
        for gone in ("DISPLAY_0001", "ENUM_0001"):
            assert gone not in text, f"{gone} must be filtered out of the sheet"

    drive(tmp_path, SIZE, body, **_loaded(defc))


def test_r_pe_def_10_3_a_page_turn_of_a_201_name_list_shows_the_one_row_of_page_2(tmp_path):
    a2l = tmp_path / "many.a2l"
    all_names = build_many_names_a2l(a2l, 201)

    async def body(app, pilot, panel):
        first_page = names_of(_picker(panel).visible_params)
        assert len(first_page) == 200
        (last_name,) = sorted(set(all_names) - set(first_page))
        assert await pilot.click("#patch_param_page_next_button")
        await _until(pilot, lambda: names_of(_picker(panel).visible_params) == [last_name], "page 2")
        await settle(pilot)
        text = "\n".join(body_rows(app))
        assert last_name in text
        assert first_page[0] not in text and first_page[-1] not in text, "page 1 rows must be gone"

    drive(tmp_path, SIZE, body, a2l=a2l)


# --------------------------------------------------------------------------- #
# R-PE-DEF.11 - rows come from the picker's population, not from a new describe
# --------------------------------------------------------------------------- #


def _spy_describes(monkeypatch) -> list[str]:
    calls: list[str] = []
    for module in list(sys.modules.values()):
        if not getattr(module, "__name__", "").startswith("s19_app"):
            continue
        for attr in ("describe_definitions", "describe_definition"):
            original = getattr(module, attr, None)
            if callable(original):

                def counted(*args, _original=original, _attr=attr, **kwargs):
                    calls.append(_attr)
                    return _original(*args, **kwargs)

                monkeypatch.setattr(module, attr, counted)
    return calls


def _spy_context_describes(monkeypatch) -> list[tuple]:
    """The names of every ``describe_in_context`` call, in call order."""
    calls: list[tuple] = []
    for module in list(sys.modules.values()):
        if not getattr(module, "__name__", "").startswith("s19_app"):
            continue
        original = getattr(module, "describe_in_context", None)
        if callable(original):

            def counted(names, context, _original=original):
                names = list(names)
                calls.append(tuple(names))
                return _original(names, context)

            monkeypatch.setattr(module, "describe_in_context", counted)
    return calls


def test_r_pe_def_11_2_a_page_turn_and_a_filter_change_describe_nothing(tmp_path, monkeypatch):
    """R-PE-DEF.11.2: a page turn and a filter change build the sheet rows with 0 full
    describes and exactly 1 context describe per new page, holding that page's names."""
    a2l = tmp_path / "many.a2l"
    build_many_names_a2l(a2l, 201)

    async def body(app, pilot, panel):
        calls = _spy_describes(monkeypatch)
        in_context = _spy_context_describes(monkeypatch)
        assert await pilot.click("#patch_param_page_next_button")
        await settle(pilot, 8)
        page_two = tuple(names_of(_picker(panel).visible_params))
        await _set_filter(pilot, panel, "PNAME_00")
        filtered = tuple(names_of(_picker(panel).visible_params))
        assert filtered, "the filter must still list rows"
        assert calls == [], f"a page change described {calls}"
        assert page_two and filtered != page_two
        assert in_context == [page_two, filtered], (in_context, page_two, filtered)
        assert any("PNAME_00" in line for line in body_rows(app)), "the sheet did repaint"

    drive(tmp_path, SIZE, body, a2l=a2l)


def test_r_pe_def_11_1_an_a2l_reload_changing_enum_text_shows_the_new_text(defc, tmp_path):
    reloaded = build_defc_variant(defc, tmp_path / "enum_renamed.a2l", *ENUM_RENAMED)

    async def body(app, pilot, panel):
        assert "IDLE" in row_of(app, "ENUM_0001")
        app.load_a2l_from_path(reloaded)
        await settle_workers(pilot)
        await _until(pilot, lambda: "SLEEPING" in row_of(app, "ENUM_0001"), "the reloaded enum text")
        assert "IDLE" not in row_of(app, "ENUM_0001")

    drive(tmp_path, SIZE, body, **_loaded(defc))


def test_r_pe_def_11_3_the_apps_a2l_swapped_before_the_picker_repopulates_does_not_leak_into_rows(defc, tmp_path):
    """PARTIAL: the app's payload is swapped by assignment (the window before repopulation); the
    repopulation itself runs through the app's own A2L loader."""
    swapped = build_defc_variant(defc, tmp_path / "factor_one.a2l", *FACTOR_ONE)

    async def body(app, pilot, panel):
        assert CURRENT_143_5 in row_of(app, "DISPLAY_0001")
        app.current_a2l_data = parse_a2l_file(swapped)
        await _set_filter(pilot, panel, "")
        await _set_filter(pilot, panel, "DISPLAY")
        line = row_of(app, "DISPLAY_0001")
        assert CURRENT_143_5 in line and CURRENT_287 not in line, line
        app.load_a2l_from_path(swapped)
        await settle_workers(pilot)
        await _until(pilot, lambda: CURRENT_287 in row_of(app, "DISPLAY_0001"), "the repopulated Current")

    drive(tmp_path, SIZE, body, **_loaded(defc))


# --------------------------------------------------------------------------- #
# R-PE-DEF.18 - set_image_mem_map reaches the sheet
# --------------------------------------------------------------------------- #


def test_r_pe_def_18_1_no_image_shows_dashes_in_current(defc, tmp_path):
    async def body(app, pilot, panel):
        line = row_of(app, "DISPLAY_0001")
        assert "--" in line and CURRENT_143_5 not in line, line

    drive(tmp_path, SIZE, body, a2l=defc / "definitions.a2l")


def test_r_pe_def_18_2_unloading_the_image_repaints_current_as_dashes(defc, tmp_path):
    async def body(app, pilot, panel):
        assert CURRENT_143_5 in row_of(app, "DISPLAY_0001")
        panel.set_image_mem_map(None)  # the call the app's unload path makes
        await settle(pilot, 6)
        line = row_of(app, "DISPLAY_0001")
        assert "--" in line and CURRENT_143_5 not in line, line

    drive(tmp_path, SIZE, body, **_loaded(defc))


# --------------------------------------------------------------------------- #
# R-PE-DEF.49 - the sheet's selection moves the picker's highlight
# --------------------------------------------------------------------------- #


def test_r_pe_def_49_1_selecting_row_3_highlights_that_parameter(defc, tmp_path):
    async def body(app, pilot, panel):
        names = names_of(_picker(panel).visible_params)
        need(panel, "#patch_sheet_body").focus()
        await pilot.press("down", "down")
        await settle(pilot)
        assert selected_name(need(panel, "#patch_sheet")) == names[2]
        assert _picker(panel).highlighted_parameter["name"] == names[2]

    drive(tmp_path, SIZE, body, **_loaded(defc))


def test_r_pe_def_49_2_a_page_turn_highlights_row_1_of_the_new_page(tmp_path):
    a2l = tmp_path / "many.a2l"
    build_many_names_a2l(a2l, 201)

    async def body(app, pilot, panel):
        need(panel, "#patch_sheet_body").focus()
        await pilot.press("down", "down", "down")
        await settle(pilot)
        assert await pilot.click("#patch_param_page_next_button")
        await _until(pilot, lambda: len(_picker(panel).visible_params) == 1, "page 2")
        await settle(pilot)
        names = names_of(_picker(panel).visible_params)
        assert selected_name(need(panel, "#patch_sheet")) == names[0]
        assert _picker(panel).highlighted_parameter["name"] == names[0]

    drive(tmp_path, SIZE, body, a2l=a2l)


# --------------------------------------------------------------------------- #
# R-PE-DEF.62 - a document change repaints the staged state from the overlay
# --------------------------------------------------------------------------- #


def mark_cell(line: str) -> str:
    """Cell 2 of the mark column (CTX-PE-DEF `mark`): `●` staged. The Limits ruler paints its own `●` at the
    current value on every row with limits (R-PE-DEF.21), so `"●" in line` cannot tell staged from unstaged
    (E4 integration, test side)."""
    return line[1:2]


def test_r_pe_def_62_1_a_staged_entry_marks_its_row_and_undo_clears_it(defc, tmp_path):
    async def body(app, pilot, panel):
        before = row_of(app, "DISPLAY_0001")
        assert mark_cell(before) != "●" and STAGED_NEW not in before, before
        app._change_service.add_entry("0x00800020", "", STAGED_BYTES)
        app._refresh_patch_history_view()
        await settle(pilot, 6)
        staged = row_of(app, "DISPLAY_0001")
        assert mark_cell(staged) == "●" and STAGED_NEW in staged, staged
        app._change_service.undo()
        app._refresh_patch_history_view()
        await settle(pilot, 6)
        undone = row_of(app, "DISPLAY_0001")
        assert mark_cell(undone) != "●" and STAGED_NEW not in undone, undone

    drive(tmp_path, SIZE, body, **_loaded(defc))


def test_r_pe_def_62_3_parse_pasted_with_a_display_entry_marks_the_row(defc, tmp_path):
    document = (
        '{"format": "s19app-changeset", "version": "2.0", "kind": "change", "encoding": "utf-8", '
        '"value_mode": "text", "entries": [{"type": "bytes", "address": "0x00800020", '
        f'"bytes": "{STAGED_BYTES}"' "}]}"
    )

    async def body(app, pilot, panel):
        assert mark_cell(row_of(app, "DISPLAY_0001")) != "●"
        await show_tab(pilot, "patch_tab_json")
        need(panel, "#patch_paste_text", TextArea).text = document
        await settle(pilot)
        assert await click_visible(pilot, "#patch_paste_parse_button")
        await _until(pilot, lambda: len(app._change_service.document.entries) == 1, "the parsed document")
        await settle(pilot, 6)
        staged = row_of(app, "DISPLAY_0001")
        assert mark_cell(staged) == "●" and STAGED_NEW in staged, staged

    drive(tmp_path, SIZE, body, **_loaded(defc))
