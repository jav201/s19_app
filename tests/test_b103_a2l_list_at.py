"""Inc 7 G-T-AT: black-box acceptance of the A2L list of labels (batch-103, E4 tester T7).

Cases: ``.dev-flow/2026-11-05-batch-103/inc-7/02-test-cases-AT.md`` (10 cases over 4
acceptance tests). Each drives the real app on case 08 (seed 20260001, ``firmware.s19``
then ``firmware.a2l``) at 118x54 unless named, through keys and the terminal's paste
message; no clipboard is read or written. Expected values are computed from the shipped
parser and matcher, case 08's tags and the oracle of ``tests/support/b103_label_list.py``.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from textual.widgets import Button, DataTable, Input, Static, TextArea

from s19_app.tui.a2l_parameter_picker import parse_parameter_list
from s19_app.tui.services.label_match import build_label_index, rank
from tests.support import b100_projects as projects
from tests.support.b100_workers import settle_workers
from tests.support.b103_clipboard import terminal_paste
from tests.support.b103_label_list import (
    G2L_JOINED,
    G2L_NAMES,
    G2L_TEXT,
    build_case08,
    case_names,
    flush,
    oracle_counts,
    oracle_missing,
    oracle_ribbon,
    oracle_rows,
    plain,
    run_a2l,
    settle,
    static_text,
    table_labels,
    table_rows,
    tag_by_name,
)
from tests.support.timing import wait_until

LIST_COLUMNS = ["#", "Tag", "Status", "Kind", "Address", "Len", "Physical", "Unit", "Limits"]


@pytest.fixture(scope="module")
def case08(tmp_path_factory) -> Path:
    return build_case08(tmp_path_factory.mktemp("i7_at_case08"))


@pytest.fixture(scope="module")
def names(case08) -> list:
    return case_names(case08)


def box_of(app) -> Input:
    return app.query_one("#a2l_tags_filter_input", Input)


def modal_of(app):
    import s19_app.tui.a2l_label_list as mod

    return app.screen if isinstance(app.screen, mod.LabelListPasteModal) else None


async def paste_list(app, pilot) -> None:
    box_of(app).focus()
    await pilot.pause()
    await terminal_paste(app, G2L_TEXT)
    await flush(app, pilot)


async def open_window(app, pilot):
    app.query_one("#a2l_tags_list", DataTable).focus()
    await pilot.press("alt+p")
    await wait_until(pilot, lambda: modal_of(app) is not None, "the paste window opened")
    await settle(pilot, 4)
    return modal_of(app)


def test_at_b103_i7_1_list_mode_from_paste(case08, names, tmp_path) -> None:
    """AT-B103-I7-1/1: the G2 list posted into the filter box -> list mode, 12 rows, counts, missing line."""
    async def sc(app, pilot):
        await paste_list(app, pilot)
        chips = static_text(app.query_one("#a2l_list_chips", Static)).split("\n")
        return {
            "value": box_of(app).value, "tag": static_text(app.query_one("#a2l_filter_mode_tag")),
            "labels": table_labels(app), "rows": table_rows(app), "chips": chips,
            "missing": static_text(app.query_one("#a2l_list_missing", Static)),
            "summary": static_text(app.query_one("#a2l_tags_summary")),
        }

    out = run_a2l(tmp_path, case08, sc)
    rows = oracle_rows(G2L_NAMES, set(names))
    assert out["value"] == G2L_JOINED and out["tag"] == "LIST" and out["labels"] == LIST_COLUMNS
    assert [r[1][2:] for r in out["rows"]] == G2L_NAMES and out["summary"] == "LIST  rows 1-12 / 12 in pasted order"
    glyph = {"found": "● ", "missing": "✗ ", "duplicate": "= "}
    assert [r[1][:2] for r in out["rows"]] == [glyph[x[2]] for x in rows]
    assert out["chips"][0] == " LIST   " + oracle_counts(rows) and out["missing"] == oracle_missing(rows)
    assert out["chips"][1].startswith("order " + oracle_ribbon(rows, 80))


def test_at_b103_i7_1_jump_from_list(case08, tmp_path) -> None:
    """AT-B103-I7-1/2: then down, down, enter in the table -> ``Tag at 0x...`` of the third name."""
    async def sc(app, pilot):
        log = projects.StatusLog(app)
        await paste_list(app, pilot)
        app.query_one("#a2l_tags_list", DataTable).focus()
        await pilot.pause()
        await pilot.press("down", "down", "enter")
        await settle(pilot, 6)
        return log.messages, f"Tag at 0x{tag_by_name(app)[G2L_NAMES[2]]['address']:08X}"

    messages, want = run_a2l(tmp_path, case08, sc)
    assert want in messages


def test_at_b103_i7_1_esc_back_to_text(case08, names, tmp_path) -> None:
    """AT-B103-I7-1/3: then Esc in the filter box -> the filter is empty, text mode, every tag shown."""
    async def sc(app, pilot):
        await paste_list(app, pilot)
        box_of(app).focus()
        await pilot.press("escape")
        await flush(app, pilot)
        return box_of(app).value, static_text(app.query_one("#a2l_filter_mode_tag")), static_text(
            app.query_one("#a2l_tags_summary"))

    value, tag, text = run_a2l(tmp_path, case08, sc)
    assert value == "" and tag == "FILTER" and f"/ {len(names)}" in text


def test_at_b103_i7_2_window_live_status(case08, names, tmp_path) -> None:
    """AT-B103-I7-2/1: alt+p, the G2 list pasted into the text area -> counts, preview, missing and similar lines."""
    async def sc(app, pilot):
        modal = await open_window(app, pilot)
        focus = app.focused.id if app.focused else None
        await terminal_paste(app, G2L_TEXT)
        await pilot.pause(0.3)
        await settle_workers(pilot)
        await settle(pilot, 6)
        table = modal.query_one("#a2l_list_preview", DataTable)
        return {
            # the ribbon is its own line under the counts (built id ``#a2l_list_ribbon``; I7, P-087 c)
            "focus": focus, "counts": static_text(modal.query_one("#a2l_list_counts"))
            + "\n" + static_text(modal.query_one("#a2l_list_ribbon")),
            "rows": [[plain(c) for c in table.get_row_at(i)] for i in range(table.row_count)],
            "missing": static_text(modal.query_one("#a2l_list_missing")),
            "similar": static_text(modal.query_one("#a2l_list_similar")),
            "text": modal.query_one("#a2l_list_text", TextArea).text,
        }

    out = run_a2l(tmp_path, case08, sc)
    rows = oracle_rows(G2L_NAMES, set(names))
    assert out["focus"] == "a2l_list_text" and parse_parameter_list(out["text"]) == G2L_NAMES
    assert oracle_counts(rows) in out["counts"] and "order " + oracle_ribbon(rows, 50) in out["counts"]
    assert len(out["rows"]) == 12 and out["rows"][6][:3] == ["7", "✗ MAP_0024", "not in A2L"]
    assert out["missing"] == oracle_missing(rows)
    assert "  similar to #7 MAP_0024: none (digits must match exactly)" in out["similar"]
    assert "  similar to #11 CURVE_0071: none (digits must match exactly)" in out["similar"]


async def _type_add(app, pilot, modal, text: str) -> None:
    modal.query_one("#a2l_list_add", Input).focus()
    await pilot.pause()
    await pilot.press(*["space" if ch == " " else ch for ch in text])
    await pilot.pause(0.3)
    await settle_workers(pilot)
    await settle(pilot, 4)


def test_at_b103_i7_2_add_from_dropdown(case08, names, tmp_path) -> None:
    """AT-B103-I7-2/2: ``0042 val`` on the add line, enter -> the chosen name is appended (13 names)."""
    async def sc(app, pilot):
        modal = await open_window(app, pilot)
        await terminal_paste(app, G2L_TEXT)
        await pilot.pause(0.3)
        await _type_add(app, pilot, modal, "0042 val")
        await pilot.press("enter")
        await settle(pilot, 4)
        return modal.query_one("#a2l_list_text", TextArea).text

    text = run_a2l(tmp_path, case08, sc)
    chosen = rank("0042 val", build_label_index(names), 20)[0].name
    assert parse_parameter_list(text) == G2L_NAMES + [chosen] and len(parse_parameter_list(text)) == 13


def test_at_b103_i7_2_apply_to_viewer(case08, names, tmp_path) -> None:
    """AT-B103-I7-2/3: alt+f -> the window closes and the viewer shows 13 rows in list mode."""
    async def sc(app, pilot):
        modal = await open_window(app, pilot)
        await terminal_paste(app, G2L_TEXT)
        await pilot.pause(0.3)
        await _type_add(app, pilot, modal, "0042 val")
        await pilot.press("enter")
        await settle(pilot, 4)
        await pilot.press("alt+f")
        await settle(pilot, 6)
        await flush(app, pilot)
        return (modal_of(app), static_text(app.query_one("#a2l_filter_mode_tag")), len(table_rows(app)),
                static_text(app.query_one("#a2l_tags_summary")))

    window, tag, n_rows, text = run_a2l(tmp_path, case08, sc)
    assert window is None and tag == "LIST" and n_rows == 13 and "/ 13" in text


def _type_in_filter(app, pilot, text: str):
    box_of(app).focus()
    return pilot.press(*text)


async def _dropdown(app, pilot, text: str) -> list:
    await _type_in_filter(app, pilot, text)
    await pilot.pause(0.3)
    await settle_workers(pilot)
    box = app.query_one("#a2l_filter_suggest")
    await wait_until(pilot, lambda: box.is_open, "the dropdown opened", timeout=15)
    return static_text(box).split("\n")


def test_at_b103_i7_3_dropdown_typo(case08, tmp_path) -> None:
    """AT-B103-I7-3/1: ``cuvre_00`` typed -> ``8 of 20+ similar names``, row 1 ``CURVE_0001 ... fuzzy · 1 edit``."""
    async def sc(app, pilot):
        return await _dropdown(app, pilot, "cuvre_00")

    lines = run_a2l(tmp_path, case08, sc)
    assert lines[0] == "8 of 20+ similar names" and lines[1].startswith("▸ CURVE_0001")
    assert lines[1].rstrip().endswith("fuzzy · 1 edit")


def test_at_b103_i7_3_tab_completes(case08, names, tmp_path) -> None:
    """AT-B103-I7-3/2: down, tab -> the box holds ``CURVE_0002`` and the viewer shows 1 row."""
    async def sc(app, pilot):
        await _dropdown(app, pilot, "cuvre_00")
        await pilot.press("down", "tab")
        await flush(app, pilot)
        return box_of(app).value, len(app._a2l_filtered_tags), table_rows(app)

    value, n, rows = run_a2l(tmp_path, case08, sc)
    assert value == "CURVE_0002" and n == 1 and rows[0][2].endswith("CURVE_0002")  # text-mode columns: Address, Length, Tag (I7)


async def _applied_and_jumped(app, pilot) -> dict:
    await paste_list(app, pilot)
    app._jump_to_tag_by_data(tag_by_name(app)[G2L_NAMES[2]])
    await settle(pilot, 10)
    regions = {i: app.query_one(i).region for i in (
        "#a2l_tags_pane", "#a2l_hex_pane", "#a2l_detail_card", "#alt_hex_scroll")}
    view = app.query_one("#alt_hex_view")
    lines = [strip.text.rstrip() for strip in view.render_lines(view.region.reset_offset)]
    return {"regions": regions, "width": view.content_region.width,
            "rows": [x for x in lines if x.startswith("  0x")],
            "classes": set(app.query_one("#a2l_panes").classes)}


def test_at_b103_i7_4_layout_118(case08, tmp_path) -> None:
    """AT-B103-I7-4/1: the G2 list applied, jump to #3 at 118x54 -> every hex row whole (R-A2L-LIST.080)."""
    out = run_a2l(tmp_path, case08, _applied_and_jumped, size=(118, 54))
    r = out["regions"]
    assert r["#a2l_hex_pane"].height == 14 and r["#a2l_hex_pane"].y >= r["#a2l_tags_pane"].bottom
    assert out["width"] >= 81 and out["rows"] and all(len(x) >= 81 and x.endswith("|") for x in out["rows"])


def test_at_b103_i7_4_layout_220(case08, tmp_path) -> None:
    """AT-B103-I7-4/2: the same at 220x60 -> the 90-column hex pane right of the tags pane, card <= 8 lines."""
    out = run_a2l(tmp_path, case08, _applied_and_jumped, size=(220, 60))
    r = out["regions"]
    assert "-wide" in out["classes"] and r["#a2l_hex_pane"].width == 90
    assert r["#a2l_hex_pane"].x >= r["#a2l_tags_pane"].right
    assert r["#a2l_detail_card"].height <= 8 and r["#a2l_detail_card"].bottom <= r["#alt_hex_scroll"].y
    assert out["rows"] and all(x.endswith("|") for x in out["rows"])
