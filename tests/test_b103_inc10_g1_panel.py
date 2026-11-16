"""Batch-103 Inc 10, E4 group G1 (panel and dock): where the save-back prompt sits and what its controls do.

Cases: ``inc-10/02-test-cases.md`` rows R-CHG-003.1/1..9, R-PE-EXPORT.1/1..2, R-TUI-063.1/1..4 and
R-PE-EXPORT.2/1..11 (placement).  The prompt's controls (Format, Width, names, R-TUI-064) are in
``test_b103_inc10_g1_controls.py``; the written-file cases are in ``test_b103_inc10_g2_write.py``.

The shipped route: the real app under Pilot, the Load dialog, the entry boxes, ``Apply loaded changes`` and the
prompt's own chips.  Every position is read from the compositor (``region``, ``get_widget_at``), never counted.
RED on base ``439860c4``: the prompt lives inside ``#patch_win_json`` (0x0 unless the JSON tab shows), there is
no dock, no Format control and no apply line.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from tests.support import b103_inc10 as t

DOC_ORDER = ("patch_identity_ribbon", "patch_filter_row", "patch_sheet_win", "patch_inspector",
             "patch_doc_file_row", "patch_doc_controls")
ORDER_HIDDEN = DOC_ORDER + ("patch_legend",)
ORDER_SHOWN = DOC_ORDER + ("patch_saveback_row", "patch_legend")
TAB_BY_NAME = {"script": "patch_tab_script", "inspector": "patch_tab_inspector",
               "json": "patch_tab_json", "checks": "patch_tab_checks"}


applied = t.run_applied


def loaded(tmp_path: Path, size, source: str, body):
    """``source`` loaded and the Patch Editor open, no apply, then ``body``."""
    return t.run_loaded(tmp_path, size, source, body)


async def format_press(pilot) -> None:
    await t.press_button(pilot, "#patch_saveback_format_button")


# ------------------------------------------------------------------ R-CHG-003.1: the prompt, whichever tab


CHG_1 = [
    ("R-CHG-003.1/1", t.SIZE, "inspector"), ("R-CHG-003.1/2", t.SIZE, "json"),
    ("R-CHG-003.1/3", t.SIZE, "checks"), ("R-CHG-003.1/4", t.SIZE, "script"),
    ("R-CHG-003.1/5", t.WIDE, "inspector"), ("R-CHG-003.1/6", t.WIDE, "json"),
    ("R-CHG-003.1/7", t.WIDE, "checks"), ("R-CHG-003.1/8", t.WIDE, "script"),
]


@pytest.mark.parametrize("case,size,tab", CHG_1, ids=[c[0] for c in CHG_1])
def test_r_chg_003_1_the_prompt_is_shown_whichever_tab_was_shown(tmp_path, case, size, tab):
    """R-CHG-003.1/1..8: after Apply from each tab the prompt and ``Write file`` are shown at their place and
    the shown tab is still the one shown before Apply (D-1 A).  Negative control: the prompt kept inside the
    JSON tab (the base) -> 6 of the 8 cases RED."""
    chip = TAB_BY_NAME[tab]

    async def body(app, pilot):
        return (t.row_at_its_place(app, t.need(app.screen, "#patch_saveback_row")),
                t.at_its_place(app, t.need(app.screen, "#patch_saveback_confirm_button")),
                t.current_pane(app))

    dialog = case in ("R-CHG-003.1/1", "R-CHG-003.1/5")  # the Inspector cases load through the Load dialog
    row, confirm, pane = applied(tmp_path, size, "firmware.s19", chip, body, dialog=dialog)
    assert row == [] and confirm == [], (case, row, confirm)
    assert pane == t.TAB_PANES[chip], (case, "the shown tab changed", pane)


def test_r_chg_003_1_9_the_prompt_is_shown_after_an_apply_on_an_intel_hex_image(tmp_path):
    """R-CHG-003.1/9: Applied HEX from the Inspector tab at 118x54 -> prompt and ``Write file`` shown at their
    place.  Negative control: the prompt hidden by ``#patch_win_json`` (base, B) -> RED."""

    async def body(app, pilot):
        return (t.row_at_its_place(app, t.need(app.screen, "#patch_saveback_row")),
                t.at_its_place(app, t.need(app.screen, "#patch_saveback_confirm_button")))

    row, confirm = applied(tmp_path, t.SIZE, "firmware.hex", "patch_tab_inspector", body)
    assert row == [] and confirm == [], (row, confirm)


# ------------------------------------------------------------------ R-PE-EXPORT.1 and R-TUI-063.1


@pytest.mark.parametrize("case,size", [("R-PE-EXPORT.1/1", t.SIZE), ("R-PE-EXPORT.1/2", t.WIDE)],
                         ids=["R-PE-EXPORT.1/1", "R-PE-EXPORT.1/2"])
def test_r_pe_export_1_the_prompt_sits_between_the_document_row_and_the_legend(tmp_path, case, size):
    """R-PE-EXPORT.1/1,/2: prompt top row below the document row's row, bottom row above the legend's row,
    x and width equal the document row's.  Negative control: the prompt inside the inspector (base) -> RED."""

    async def body(app, pilot):
        prompt = t.need(app.screen, "#patch_saveback_row").region
        doc = t.need(app.screen, "#patch_doc_controls").region
        legend = t.need(app.screen, "#patch_legend").region
        return prompt, doc, legend

    prompt, doc, legend = applied(tmp_path, size, "firmware.s19", "patch_tab_inspector", body)
    assert prompt.y > doc.y, (case, "prompt top row is not below the document row", prompt, doc)
    assert prompt.bottom - 1 < legend.y, (case, "prompt bottom row is not above the legend", prompt, legend)
    assert (prompt.x, prompt.width) == (doc.x, doc.width), (case, prompt, doc)


TOP_ROWS = [("R-TUI-063.1/1", t.SIZE, False), ("R-TUI-063.1/2", t.SIZE, True),
            ("R-TUI-063.1/3", t.WIDE, False), ("R-TUI-063.1/4", t.WIDE, True)]


@pytest.mark.parametrize("case,size,with_prompt", TOP_ROWS, ids=[c[0] for c in TOP_ROWS])
def test_r_tui_063_1_the_patch_editor_top_to_bottom_order(tmp_path, case, size, with_prompt):
    """R-TUI-063.1/1..4: the shown parts' top rows strictly increase: ribbon, filter row, staging sheet,
    landing pane, file row, document row, [prompt], legend.  Negative control: the prompt docked under the
    legend -> /2 and /4 RED."""
    order = ORDER_SHOWN if with_prompt else ORDER_HIDDEN

    async def body(app, pilot):
        return t.top_rows(app, order), t.prompt_is_shown(app)

    if with_prompt:
        rows, prompt = applied(tmp_path, size, "firmware.s19", "patch_tab_inspector", body)
    else:
        rows, prompt = loaded(tmp_path, size, "firmware.s19", body)
    assert prompt is with_prompt, (case, "prompt shown state", prompt)
    assert rows == sorted(set(rows)), (case, dict(zip(order, rows)))


# ------------------------------------------------------------------ R-PE-EXPORT.2: no scrolling


CTRL_S19 = ("patch_saveback_name_input", "patch_saveback_format_button", "patch_saveback_width_button",
            "patch_saveback_confirm_button", "patch_saveback_decline_button")
CTRL_HEX = tuple(i for i in CTRL_S19 if i != "patch_saveback_width_button")
EXPORT_2 = [("R-PE-EXPORT.2/1", t.SIZE, "inspector", "firmware.s19"), ("R-PE-EXPORT.2/2", t.SIZE, "json", "firmware.s19"),
            ("R-PE-EXPORT.2/3", t.SIZE, "checks", "firmware.s19"), ("R-PE-EXPORT.2/4", t.SIZE, "script", "firmware.s19"),
            ("R-PE-EXPORT.2/5", t.WIDE, "inspector", "firmware.s19"), ("R-PE-EXPORT.2/6", t.WIDE, "json", "firmware.s19"),
            ("R-PE-EXPORT.2/7", t.WIDE, "checks", "firmware.s19"), ("R-PE-EXPORT.2/8", t.WIDE, "script", "firmware.s19"),
            ("R-PE-EXPORT.2/9", t.SIZE, "inspector", "firmware.hex"), ("R-PE-EXPORT.2/10", t.WIDE, "inspector", "firmware.hex")]


@pytest.mark.parametrize("case,size,tab,source", EXPORT_2, ids=[c[0] for c in EXPORT_2])
def test_r_pe_export_2_every_prompt_control_is_on_screen_without_scrolling(tmp_path, case, size, tab, source):
    """R-PE-EXPORT.2/1..10: name box, Format, Width (S19 only), ``Write file``, ``Don't save`` inside the
    screen and every scroll offset of the Patch Editor at 0.  Negative control: the prompt mounted after the
    legend with the panel's height unchanged -> controls past the last row -> RED."""
    ids = CTRL_S19 if source.endswith(".s19") else CTRL_HEX

    async def body(app, pilot):
        bad = [r for i in ids for r in t.at_its_place(app, t.need(app.screen, f"#{i}"))]
        return bad, t.scroll_offsets(t.panel_of(app))

    bad, offsets = applied(tmp_path, size, source, TAB_BY_NAME[tab], body)
    assert bad == [], (case, bad)
    assert offsets == [], (case, "scroll offsets not at 0", offsets)


def test_r_pe_export_2_11_the_largest_dock_fits_and_its_height_is_recorded(tmp_path, capsys):
    """R-PE-EXPORT.2/11 (118x54): prompt and before/after control both shown (``Write file``, then Apply
    again): every control inside the screen, every scroll offset 0; the dock's height is printed as
    ``DOCK-HEIGHT`` (expected 4 = Inc 8's stand-in; more than 4 is finding F-R8-1, not a failure here).
    Negative control: no dock at all (base) -> the ids are missing -> RED."""

    async def body(app, pilot):
        await t.write_file(pilot, app)
        await t.press_apply(pilot, app)
        ids = CTRL_S19 + ("patch_before_after_button",)
        bad = [r for i in ids for r in t.at_its_place(app, t.need(app.screen, f"#{i}"))]
        dock = t.need(app.screen, "#patch_export_dock")
        return bad, t.scroll_offsets(t.panel_of(app)), dock.region.height

    bad, offsets, height = applied(tmp_path, t.SIZE, "firmware.s19", "patch_tab_inspector", body)
    print(f"DOCK-HEIGHT 118x54 = {height} rows (expected 4; F-R8-1 if more)")
    assert bad == [] and offsets == [], (bad, offsets)
    assert height >= 1


def test_r_pe_export_2_11_dock_height_at_220x60_is_recorded(tmp_path):
    """R-PE-EXPORT.2/11 (second size, brief: record at 118x54 and 220x60): same scene at 220x60; the height
    is printed as ``DOCK-HEIGHT`` and the controls are inside the screen.  Negative control as above."""

    async def body(app, pilot):
        await t.write_file(pilot, app)
        await t.press_apply(pilot, app)
        ids = CTRL_S19 + ("patch_before_after_button",)
        bad = [r for i in ids for r in t.at_its_place(app, t.need(app.screen, f"#{i}"))]
        return bad, t.need(app.screen, "#patch_export_dock").region.height

    bad, height = applied(tmp_path, t.WIDE, "firmware.s19", "patch_tab_inspector", body)
    print(f"DOCK-HEIGHT 220x60 = {height} rows (expected 4; F-R8-1 if more)")
    assert bad == [], bad
