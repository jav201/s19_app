"""Batch-103 Inc 8 E4, group P - the Patch Editor's regions, filter row, focus colour and tabs.

Cases: ``.dev-flow/2026-11-05-batch-103/inc-8/02-test-cases-P.md`` (rows R-TUI-063.1/3/4/6,
R-PE-DEF.1.1/1.2/2/3/4/74, R-PICKER-CORRECT.011/020).  Every test opens the real Patch
Editor through ``S19TuiApp`` under Pilot and reads region geometry, painted state and
border colours; none counts a position by hand.  The only stand-ins: the 4-row dock yielded
inside ``_compose_doc_controls`` (Inc 10's dock does not exist yet, R-PE-DEF.1.1/3 and
.74/2) and the ``-bench`` class set by the test (Inc 9's sheet sets it, R-PE-DEF.1.2).
"""
from __future__ import annotations

import sys

sys.path.insert(0, ".")
import s19_app

print(f"S19_APP_UNDER_TEST={s19_app.__file__}", flush=True)

import pytest
from textual.errors import NoWidget
from textual.widgets import ContentSwitcher, Static

from tests.b97_probes import is_displayed
from tests.support.b103_inc8_p import (
    MIN_SIZE,
    REGION_IDS,
    SIZE,
    STANDIN_DOCK_ID,
    STANDIN_DOCK_ROWS,
    WIDE,
    build_defc,
    click_visible,
    drive,
    need,
    settle,
    show_tab,
    tcss_colour,
)

SIZES = [pytest.param(SIZE, id="118x54"), pytest.param(WIDE, id="220x60")]


def _regions(panel):
    return {rid: need(panel, f"#{rid}") for rid in REGION_IDS}


def _with_standin_dock(monkeypatch):
    """Yield a 4-row stand-in after the document row, from inside ``_compose_doc_controls`` (I-8.3)."""
    from s19_app.tui.screens_directionb.patch_editor.actions import ActionsMixin

    original = ActionsMixin._compose_doc_controls

    def composed(self):
        yield from original(self)
        dock = Static("dock stand-in", id=STANDIN_DOCK_ID)
        dock.styles.height = STANDIN_DOCK_ROWS
        yield dock

    monkeypatch.setattr(ActionsMixin, "_compose_doc_controls", composed)


# --------------------------------------------------------------------------- #
# R-TUI-063.1 - the seven regions, top to bottom
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("size", SIZES)
def test_r_tui_063_1_the_seven_regions_run_top_to_bottom(tmp_path, size):
    async def body(app, pilot, panel):
        regions = _regions(panel)
        ys = [regions[rid].region.y for rid in REGION_IDS]
        assert all(regions[rid].region.height > 0 for rid in REGION_IDS), {r: regions[r].region for r in REGION_IDS}
        assert ys == sorted(set(ys)), f"the regions are not strictly increasing in {REGION_IDS}: {ys}"

    drive(tmp_path, size, body)


def test_r_tui_063_1_the_sheet_is_composed_by_the_panel(tmp_path):
    from s19_app.tui.screens_directionb.patch_editor.sheet import StagingSheet

    async def body(app, pilot, panel):
        sheet = need(panel, "#patch_sheet", StagingSheet)
        assert sheet.id == "patch_sheet"
        assert panel._sheet is sheet
        assert need(panel, "#patch_sheet_win") in sheet.ancestors

    drive(tmp_path, SIZE, body)


def test_r_tui_063_1_the_old_beside_layout_ids_are_gone(tmp_path):
    async def body(app, pilot, panel):
        assert len(panel.query("#patch_main")) == 0, "#patch_main must leave (D-1)"
        assert len(panel.query("#patch_win_a2l")) == 0, "#patch_win_a2l must leave (D-1)"
        assert len(panel.query("#patch_tab_a2l")) == 0, "the A2L chip must leave (R-TUI-063.3)"

    drive(tmp_path, SIZE, body)


def test_r_tui_063_1_the_sheet_window_subtitle_names_its_keys(tmp_path):
    async def body(app, pilot, panel):
        win = need(panel, "#patch_sheet_win")
        assert win.border_title == "STAGING SHEET", win.border_title
        # Inc 9's integrator appends ' · arrays open the bench' (E3A-15): the Inc 8 text is the prefix.
        assert (win.border_subtitle or "").startswith("enter edit · ↑↓ row"), win.border_subtitle

    drive(tmp_path, SIZE, body)


# --------------------------------------------------------------------------- #
# R-PE-DEF.1.1 / .1.2 / .74 - heights
# --------------------------------------------------------------------------- #


def _sheet_equation(panel, extra_ids=()):
    regions = _regions(panel)
    others = [regions[rid] for rid in REGION_IDS if rid != "patch_sheet_win"]
    others += [need(panel, f"#{rid}") for rid in extra_ids]
    taken = sum(widget.region.height for widget in others)
    return regions["patch_sheet_win"].region.height, panel.content_region.height - taken, regions


@pytest.mark.parametrize("size", SIZES)
def test_r_pe_def_1_1_the_landing_pane_has_9_rows_and_the_sheet_takes_the_rest(tmp_path, size):
    async def body(app, pilot, panel):
        sheet_h, expected, regions = _sheet_equation(panel)
        assert regions["patch_inspector"].region.height == 9, regions["patch_inspector"].region
        assert sheet_h == expected, f"sheet {sheet_h} != panel - the other regions {expected}"

    drive(tmp_path, size, body)


def test_r_pe_def_1_1_with_a_4_row_dock_the_sheet_is_the_panel_minus_the_other_seven(tmp_path, monkeypatch):
    async def body(app, pilot, panel):
        dock = need(panel, f"#{STANDIN_DOCK_ID}")
        controls = need(panel, "#patch_doc_controls")
        legend = need(panel, "#patch_legend")
        assert controls.region.y < dock.region.y < legend.region.y, "the dock lies between the document row and the legend"
        sheet_h, expected, regions = _sheet_equation(panel, extra_ids=(STANDIN_DOCK_ID,))
        assert dock.region.height == STANDIN_DOCK_ROWS
        assert regions["patch_inspector"].region.height == 9
        assert sheet_h == expected, f"sheet {sheet_h} != panel - the other seven {expected}"

    drive(tmp_path, SIZE, body, patch=lambda: _with_standin_dock(monkeypatch))


def test_r_pe_def_1_2_a_bench_gives_the_landing_pane_6_rows_and_the_sheet_the_3(tmp_path):
    """PARTIAL: Inc 9's sheet sets the ``-bench`` class; the test sets it."""

    async def body(app, pilot, panel):
        before_sheet = need(panel, "#patch_sheet_win").region.height
        assert need(panel, "#patch_inspector").region.height == 9
        panel.add_class("-bench")
        await settle(pilot)
        assert need(panel, "#patch_inspector").region.height == 6
        assert need(panel, "#patch_sheet_win").region.height - before_sheet == 3

    drive(tmp_path, SIZE, body)


def test_r_pe_def_74_the_sheet_window_has_at_least_12_rows_at_80x24(tmp_path):
    async def body(app, pilot, panel):
        assert need(panel, "#patch_sheet_win").region.height >= 12, need(panel, "#patch_sheet_win").region

    drive(tmp_path, MIN_SIZE, body)


def test_r_pe_def_74_the_sheet_window_has_at_least_12_rows_with_the_4_row_dock(tmp_path, monkeypatch):
    async def body(app, pilot, panel):
        assert need(panel, f"#{STANDIN_DOCK_ID}").region.height == STANDIN_DOCK_ROWS
        assert need(panel, "#patch_sheet_win").region.height >= 12

    drive(tmp_path, SIZE, body, patch=lambda: _with_standin_dock(monkeypatch))


# --------------------------------------------------------------------------- #
# R-PE-DEF.2, R-PICKER-CORRECT.011 / .020 - the filter row
# --------------------------------------------------------------------------- #

FILTER_ROW_CONTROLS = (
    "patch_param_filter",
    "patch_param_status",
    "patch_param_page_prev_button",
    "patch_param_page_label",
    "patch_param_page_next_button",
    "patch_param_include_button",
    "patch_param_bulk_button",
)


@pytest.fixture(scope="module")
def defc_dir(tmp_path_factory):
    return build_defc(tmp_path_factory.mktemp("inc8_p_layout_defc"))


def test_r_pe_def_2_the_seven_controls_sit_on_the_filter_row_and_the_table_is_hidden(tmp_path, defc_dir):
    # E4 integration, test side: with no A2L the count line is hidden by design (R-B102-SEL-002, both empty
    # states), so the seven controls can all hold a region only over a populated picker: DEFC's A2L.
    async def body(app, pilot, panel):
        row = need(panel, "#patch_filter_row")
        for control_id in FILTER_ROW_CONTROLS:
            widget = need(panel, f"#{control_id}")
            assert widget.region.area > 0, f"{control_id} has no region"
            assert row.region.y <= widget.region.y < row.region.y + row.region.height, (
                f"{control_id} at y={widget.region.y} is off the filter row {row.region}"
            )
        assert not is_displayed(need(panel, "#patch_param_table")), "the picker table must not be displayed"

    drive(tmp_path, SIZE, body, a2l=defc_dir / "definitions.a2l")


def test_r_picker_correct_011_the_include_and_add_list_controls_are_on_the_filter_row(tmp_path):
    async def body(app, pilot, panel):
        row = need(panel, "#patch_filter_row")
        for control_id in ("patch_param_include_button", "patch_param_bulk_button"):
            widget = need(panel, f"#{control_id}")
            assert row in widget.ancestors, control_id
            assert widget.region.area > 0

    drive(tmp_path, SIZE, body)


def test_r_picker_correct_011_every_picker_id_is_unique_with_both_editors_mounted(tmp_path):
    async def body(app, pilot, panel):
        ids = [w.id for w in app.query("*") if w.id]
        patch_ids = [i for i in ids if i.startswith("patch_param_")]
        check_ids = [i for i in ids if i.startswith("check_param_")]
        assert patch_ids and check_ids, "both pick-mode editors must be mounted"
        for family in (patch_ids, check_ids):
            dups = sorted({i for i in family if family.count(i) > 1})
            assert not dups, f"duplicate ids: {dups}"
        assert "patch_param_bulk_button" in patch_ids

    drive(tmp_path, SIZE, body)


@pytest.mark.parametrize("size", [pytest.param(MIN_SIZE, id="80x24"), pytest.param(SIZE, id="118x54")])
def test_r_picker_correct_020_filter_row_use_row_and_status_stay_inside_the_panel(tmp_path, size):
    async def body(app, pilot, panel):
        await show_tab(pilot, "patch_tab_inspector")
        need(panel, "#patch_param_use_button").press()  # no A2L: paints the use-status line
        await settle(pilot)
        for selector in ("#patch_filter_row", "#patch_param_use_row", "#patch_param_use_status"):
            widget = need(panel, selector)
            region = widget.region
            assert region.area > 0, f"{selector} has no region: {region}"
            assert panel.region.x <= region.x and region.right <= panel.region.right, (
                f"{selector} overflows the panel horizontally: {region} vs {panel.region}"
            )

    drive(tmp_path, size, body)


# --------------------------------------------------------------------------- #
# R-PE-DEF.3 - the Use row lives in the Inspector tab
# --------------------------------------------------------------------------- #


def test_r_pe_def_3_use_row_and_status_are_under_the_entry_form_in_the_inspector(tmp_path):
    async def body(app, pilot, panel):
        await show_tab(pilot, "patch_tab_inspector")
        pane = need(panel, "#patch_pane_inspector")
        bytes_input = need(panel, "#patch_entry_bytes_input")
        for selector in ("#patch_param_use_row", "#patch_param_use_button", "#patch_param_use_status"):
            widget = need(panel, selector)
            assert pane in widget.ancestors, f"{selector} is not inside #patch_pane_inspector"
        assert need(panel, "#patch_param_use_row").region.y > bytes_input.region.y

    drive(tmp_path, SIZE, body)


# --------------------------------------------------------------------------- #
# R-PE-DEF.4 - focus accent
# --------------------------------------------------------------------------- #


def test_r_pe_def_4_focus_on_the_sheet_paints_the_accent_border(tmp_path):
    async def body(app, pilot, panel):
        win = need(panel, "#patch_sheet_win")
        need(panel, "#patch_sheet_body").focus()
        await settle(pilot)
        assert win.styles.border_top[1].hex.lower() == tcss_colour("accent-calm")

    drive(tmp_path, SIZE, body)


def test_r_pe_def_4_focus_in_the_file_row_paints_the_rule_border(tmp_path):
    async def body(app, pilot, panel):
        win = need(panel, "#patch_sheet_win")
        need(panel, "#patch_sheet_body").focus()
        await settle(pilot)
        need(panel, "#patch_doc_path_input").focus()
        await settle(pilot)
        assert win.styles.border_top[1].hex.lower() == tcss_colour("rule")

    drive(tmp_path, SIZE, body)


# --------------------------------------------------------------------------- #
# R-TUI-063.3 / .4 / .6 - the landing pane's tabs and title
# --------------------------------------------------------------------------- #

TAB_PANES = (
    ("patch_tab_script", "patch_win_script"),
    ("patch_tab_inspector", "patch_pane_inspector"),
    ("patch_tab_json", "patch_win_json"),
    ("patch_tab_checks", "patch_win_checks"),
)


def test_r_tui_063_3_the_chips_are_patch_script_inspector_json_checks(tmp_path):
    async def body(app, pilot, panel):
        bar = need(panel, "#patch_tabs")
        chips = [w for w in bar.children if "tab-chip" in w.classes]
        assert [str(chip.label) for chip in chips] == ["Patch script", "Inspector", "JSON", "Checks"]
        assert [chip.id for chip in chips] == [chip_id for chip_id, _ in TAB_PANES]

    drive(tmp_path, SIZE, body)


def test_r_tui_063_4_the_ledger_pane_shows_first_with_its_chip_selected(tmp_path):
    async def body(app, pilot, panel):
        assert need(panel, "#patch_tab_switcher", ContentSwitcher).current == "patch_win_script"
        assert is_displayed(need(panel, "#patch_win_script"))
        assert "chip-selected" in need(panel, "#patch_tab_script").classes
        for chip_id, _ in TAB_PANES[1:]:
            assert "chip-selected" not in need(panel, f"#{chip_id}").classes

    drive(tmp_path, SIZE, body)


@pytest.mark.parametrize("chip_id,pane_id", TAB_PANES)
def test_r_tui_063_6_every_shown_tab_titles_the_landing_pane_lands_in(tmp_path, chip_id, pane_id):
    async def body(app, pilot, panel):
        await show_tab(pilot, chip_id)
        assert need(panel, "#patch_tab_switcher", ContentSwitcher).current == pane_id
        assert need(panel, "#patch_inspector").border_title == "LANDS IN"

    drive(tmp_path, SIZE, body)


# --------------------------------------------------------------------------- #
# F-I10-1 - the Inspector pane's widgets against the rows below LANDS IN
# --------------------------------------------------------------------------- #
#
# The Inspector tab scrolls inside LANDS IN's 6 content rows (R-PE-DEF.1.1; E3R1 E3A-09,
# V-1).  ``widget.region`` of a widget scrolled below the fold still names cells of the file
# and document rows, so a bare ``pilot.click`` on it lands on Validate; what the operator
# sees and clicks is the compositor's visible region, which these tests read.

INSPECTOR_SIZES = [
    pytest.param(SIZE, id="118x54"),
    pytest.param(WIDE, id="220x60"),
    pytest.param(MIN_SIZE, id="80x24"),
]


def _painted(app):
    """{widget: visible region} of every widget the compositor paints, with a non-empty region."""
    seen = {}
    for widget in app.screen.query("*"):
        try:
            region = app.screen.find_widget(widget).visible_region
        except NoWidget:
            continue
        if region.area:
            seen[widget] = region
    return seen


def _assert_no_shared_cell(app, pane, where: str) -> int:
    """No painted Inspector widget shares a cell with another painted widget that is not its
    ancestor or descendant; each lies inside the pane and owns the cell at its centre."""
    painted = _painted(app)
    pane_seen = painted[pane]
    inside = [w for w in painted if pane in w.ancestors]
    for widget in inside:
        region = painted[widget]
        assert pane_seen.contains_region(region), f"{where}: #{widget.id} {region} leaves the pane {pane_seen}"
        for other, other_region in painted.items():
            if other is widget or other in widget.ancestors or widget in other.ancestors:
                continue
            shared = region.intersection(other_region)
            assert not shared.area, (
                f"{where}: {type(widget).__name__}#{widget.id} {region} and "
                f"{type(other).__name__}#{other.id} {other_region} share {shared}"
            )
        hit = app.get_widget_at(*region.center)[0]
        assert hit is widget or widget in hit.ancestors, (
            f"{where}: the cell at #{widget.id}'s painted centre belongs to {type(hit).__name__}#{hit.id}"
        )
    return len(inside)


@pytest.mark.parametrize("size", INSPECTOR_SIZES)
def test_r_pe_def_1_1_inspector_widgets_share_no_painted_cell_at_the_top_and_the_end(tmp_path, defc_dir, size):
    async def body(app, pilot, panel):
        await show_tab(pilot, "patch_tab_inspector")
        pane = need(panel, "#patch_pane_inspector")
        pane.scroll_home(animate=False)
        pane.scroll_visible(animate=False)  # at 80x24 the panel scrolls to the pane (R-TUI-064.3)
        await settle(pilot)
        top =_assert_no_shared_cell(app, pane, f"{size} top")
        pane.scroll_end(animate=False)
        await settle(pilot)
        end = _assert_no_shared_cell(app, pane, f"{size} end")
        assert top and end, f"{size}: no Inspector widget painted (top {top}, end {end})"

    drive(tmp_path, size, body, a2l=defc_dir / "definitions.a2l", image=defc_dir / "definitions.s19")


@pytest.mark.parametrize("size", INSPECTOR_SIZES)
def test_r_pe_021_a_click_on_the_painted_add_adds_the_entry_and_never_validates(tmp_path, defc_dir, size):
    async def body(app, pilot, panel):
        await show_tab(pilot, "patch_tab_inspector")
        for selector, text in (("#patch_entry_address_input", "0x800021"), ("#patch_entry_bytes_input", "11")):
            assert await click_visible(pilot, selector), f"{size}: click missed {selector}"
            await pilot.press(*text)
        add = need(panel, "#patch_entry_add_button")
        add.scroll_visible(animate=False)
        await settle(pilot)
        seen = app.screen.find_widget(add).visible_region
        assert seen.area, f"{size}: Add is not painted after scrolling the Inspector pane"
        assert await pilot.click(offset=seen.center), f"{size}: the click at {seen.center} reached no widget"
        for _ in range(60):
            await pilot.pause()
            if app._change_service.document.entries:
                break
        statuses = list(app.log_lines)
        assert statuses[-1] == "Patch Editor: entry added.", f"{size}: last status {statuses[-1]!r}"
        assert not [line for line in statuses if line.startswith("Validate:")], f"{size}: Validate ran: {statuses}"
        assert [(e.address, bytes(e.encoded_bytes)) for e in app._change_service.document.entries] == [
            (0x800021, b"\x11")
        ]

    drive(tmp_path, size, body, a2l=defc_dir / "definitions.a2l", image=defc_dir / "definitions.s19")
