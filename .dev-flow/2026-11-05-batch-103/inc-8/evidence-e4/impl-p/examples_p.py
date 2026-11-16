"""Inc 8 E4 impl-p: the group P nodes' graph examples, run against the real tree.

Run from the tree root on the Linux runner, isolated env:  python -B examples_p.py <scratch>
Output: one `KEY = value` line per fact.
"""
from __future__ import annotations

import asyncio
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, ".")
import s19_app  # noqa: E402

print("s19_app.__file__ =", s19_app.__file__)

from textual.containers import Container  # noqa: E402
from textual.widgets import Static  # noqa: E402

import s19_app.tui.a2l_definition as a2l_definition  # noqa: E402
import s19_app.tui.a2l_parameter_picker as picker_mod  # noqa: E402
from s19_app.tui.app import S19TuiApp  # noqa: E402
from s19_app.tui.screens_directionb.patch_editor import actions as actions_mod  # noqa: E402
from s19_app.tui.screens_directionb.patch_editor.sheet import StagingSheet  # noqa: E402
from s19_app.tui.services.change_service import ChangeEntryRow  # noqa: E402
from tests.b97_fixtures import PE_IDS_9C7BEAF  # noqa: E402
from tests.b97_probes import is_displayed  # noqa: E402
from tests.support.b100_workers import settle_workers  # noqa: E402

S = Path(sys.argv[1])
DEFC = S / "defc"
if not DEFC.exists():
    subprocess.run(
        [sys.executable, "-B", "tools/synth/make_release_case.py", "--case", "definitions", "--out", str(DEFC)],
        check=True,
    )

REGIONS = (
    "#patch_identity_ribbon", "#patch_filter_row", "#patch_sheet_win", "#patch_inspector",
    "#patch_doc_file_row", "#patch_doc_controls", "#patch_legend",
)
FILTER_ROW = (
    "#patch_param_filter", "#patch_param_status", "#patch_param_page_prev_button",
    "#patch_param_page_label", "#patch_param_page_next_button", "#patch_param_include_button",
    "#patch_param_bulk_button",
)


def show(key: str, value) -> None:
    print(f"{key} = {value}")


async def pause(pilot, n: int = 3) -> None:
    for _ in range(n):
        await pilot.pause()


def run(size, body, *, a2l: bool = True, dock: bool = False):
    async def drive():
        original = actions_mod.ActionsMixin._compose_doc_controls
        if dock:  # EX-L7: a 4-row stand-in for Inc 10's dock, yielded inside the document controls (I-8.3)
            def with_dock(self):
                yield from original(self)
                stand_in = Static("dock", id="zq_dock_stand_in")
                stand_in.styles.height = 4
                yield stand_in
            actions_mod.ActionsMixin._compose_doc_controls = with_dock
        try:
            app = S19TuiApp(base_dir=S / f"app-{body.__name__}-{size[0]}x{size[1]}{'-dock' if dock else ''}")
            async with app.run_test(size=size) as pilot:
                await pilot.pause()
                if a2l:
                    app.load_a2l_from_path(DEFC / "definitions.a2l", copy=False)
                    await settle_workers(pilot)
                    app.load_from_path(DEFC / "definitions.s19")
                    await settle_workers(pilot)
                app.action_show_screen("patch")
                await pause(pilot)
                panel = app.query_one("#patch_editor_panel")
                await body(app, pilot, panel, f"{size[0]}x{size[1]}{'.dock' if dock else ''}")
        finally:
            actions_mod.ActionsMixin._compose_doc_controls = original
    asyncio.run(drive())


async def layout(app, pilot, panel, tag):
    """EX-L1 / EX-L7 / EX-L9 (LayoutMixin.compose, styles.tcss)."""
    regions = list(REGIONS) + (["#zq_dock_stand_in"] if panel.query("#zq_dock_stand_in") else [])
    order = list(REGIONS[:6]) + (["#zq_dock_stand_in"] if len(regions) == 8 else []) + ["#patch_legend"]
    ys = [panel.query_one(sel).region.y for sel in order]
    show(f"EX-L1.{tag}.order", [s.lstrip("#") for s in order])
    show(f"EX-L1.{tag}.region_y", ys)
    show(f"EX-L1.{tag}.strictly_increasing", all(a < b for a, b in zip(ys, ys[1:])))
    heights = {sel.lstrip("#"): panel.query_one(sel).outer_size.height for sel in regions}
    show(f"EX-L1.{tag}.heights", heights)
    virtual = panel.virtual_size.height
    others = sum(h for name, h in heights.items() if name != "patch_sheet_win")
    show(f"EX-L1.{tag}.panel_content_h", panel.content_region.height)
    show(f"EX-L1.{tag}.panel_virtual_h", virtual)
    show(f"EX-L1.{tag}.sheet_eq_panel_minus_others", heights["patch_sheet_win"] == panel.content_region.height - others)
    show(f"EX-L1.{tag}.sheet_ge_12", heights["patch_sheet_win"] >= 12)
    win = panel.query_one("#patch_sheet_win")
    show(f"EX-L1.{tag}.sheet_border_title", repr(str(win.border_title)))
    show(f"EX-L1.{tag}.sheet_border_subtitle", repr(str(win.border_subtitle)))
    show(f"EX-L1.{tag}.sheet_widget", (type(panel._sheet).__name__, panel._sheet.id, panel._sheet.parent.id))
    if tag == "118x54":
        panel.add_class("-bench")  # EX-L8: the bench state Inc 9's sheet sets
        await pause(pilot)
        show("EX-L8.118x54.lands_in_h", panel.query_one("#patch_inspector").outer_size.height)
        show("EX-L8.118x54.sheet_h", panel.query_one("#patch_sheet_win").outer_size.height)
        panel.remove_class("-bench")
        await pause(pilot)
        show("EX-L8.118x54.after_remove.lands_in_h", panel.query_one("#patch_inspector").outer_size.height)
        ids = {panel.id} | {w.id for w in panel.query("*") if w.id}
        show("LAW.PE_IDS_9C7BEAF.missing", sorted(PE_IDS_9C7BEAF - ids))
        show("LAW.left_ids_present", sorted({"patch_main", "patch_win_a2l", "patch_tab_a2l"} & ids))
        containers = [i for i in sorted(PE_IDS_9C7BEAF) if i.startswith("patch_win_") or i in (
            "patch_saveback_row", "patch_before_after_row", "patch_checks_results")]
        show("LAW.container_types", {i: isinstance(app.query_one(f"#{i}"), Container) for i in containers})


async def tabs(app, pilot, panel, tag):
    """EX-L2 (_TABS, _show_tab, compose) and EX-L3 (_refresh_inspector_subtitle, note_staged)."""
    inspector = panel.query_one("#patch_inspector")
    switcher = panel.query_one("#patch_tab_switcher")
    show("EX-L2.chip_labels", [str(panel.query_one(f"#{t[0]}").label) for t in panel._TABS])
    show("EX-L2.initial_pane", switcher.current)
    show("EX-L2.initial_selected_chip", [t[0] for t in panel._TABS if panel.query_one(f"#{t[0]}").has_class("chip-selected")])
    for chip, _l, _p, _t in panel._TABS:
        panel._show_tab(chip)
        await pause(pilot, 2)
        show(f"EX-L2.{chip}", (switcher.current, str(inspector.border_title)))
    panel._show_tab("patch_tab_script")
    await pause(pilot, 2)
    show("EX-L3.0_entries.subtitle", repr(str(inspector.border_subtitle)))
    rows = [
        ChangeEntryRow(kind_text="bytes", address_text=f"0x{a:08X}", value_text="00", status_text="ok",
                       linkage_text="-", address=a, encoded_bytes=(0,))
        for a in (0x810000, 0x810001, 0x810002)
    ]
    panel.refresh_entries(rows[:1])
    await pause(pilot, 2)
    show("EX-L3.1_entry.subtitle", repr(str(inspector.border_subtitle)))
    panel.refresh_entries(rows)
    await pause(pilot, 2)
    show("EX-L3.3_entries.subtitle", repr(str(inspector.border_subtitle)))
    panel._show_tab("patch_tab_inspector")
    panel.note_staged("ZZ_NOT_ON_PAGE")
    await pause(pilot, 2)
    show("EX-L3.3_entries_dirty_inspector.subtitle", repr(str(inspector.border_subtitle)))
    panel._show_tab("patch_tab_json")
    await pause(pilot, 2)
    show("EX-L3.json.subtitle", repr(str(inspector.border_subtitle)))
    panel._show_tab("patch_tab_script")
    panel.mark_saved()
    await pause(pilot, 2)
    show("EX-L3.after_mark_saved.subtitle", repr(str(inspector.border_subtitle)))


async def filter_row(app, pilot, panel, tag):
    """EX-L4 (_compose_filter_row, _compose_use_row) and EX-L5 (containment)."""
    row = panel.query_one("#patch_filter_row")
    edge = panel.region.right
    for sel in FILTER_ROW:
        w = panel.query_one(sel)
        show(f"EX-L5.{tag}.{sel.lstrip('#')}", (w.region.y == row.region.y, w.region.width, w.region.right <= edge))
    status = panel.query_one("#patch_param_status")
    status.update("200 of 13990 shown — refine filter.")  # the longest count line a 13,990-tag A2L paints
    await pause(pilot)
    for sel in FILTER_ROW:
        w = panel.query_one(sel)
        show(f"EX-L5.{tag}.long_status.{sel.lstrip('#')}", (w.region.y == row.region.y, w.region.width, w.region.right <= edge))
    show(f"EX-L4.{tag}.table_displayed", is_displayed(panel.query_one("#patch_param_table")))
    show(f"EX-L4.{tag}.full_name_displayed", is_displayed(panel.query_one("#patch_param_full_name_line")))
    show(f"EX-L4.{tag}.picker_in_filter_row", panel._a2l_picker.parent.id)
    panel._show_tab("patch_tab_inspector")
    panel._paint_a2l_use_status("No parameter highlighted.")
    await pause(pilot)
    pane = panel.query_one("#patch_pane_inspector")
    use_row = panel.query_one("#patch_param_use_row")
    use_status = panel.query_one("#patch_param_use_status")
    bytes_input = panel.query_one("#patch_entry_bytes_input")
    show(f"EX-L4.{tag}.use_row_in_inspector", pane in use_row.ancestors and pane in use_status.ancestors)
    show(f"EX-L4.{tag}.use_row_below_bytes", (use_row.virtual_region.y > bytes_input.virtual_region.y))
    for widget in (use_row, use_status):
        widget.scroll_visible(animate=False)
        await pause(pilot)
        show(f"EX-L5.{tag}.{widget.id}", (widget.region.width > 0, widget.region.height > 0, widget.region.right <= edge))


async def sheet_wiring(app, pilot, panel, tag):
    """EX-R1 / EX-R2 (view-changed), EX-K1 (selection), EX-S1 / EX-S10 (note_staged),
    EX-S1 (refresh_entries), EX-R6 / EX-M1 (set_image_mem_map)."""
    picker = panel._a2l_picker
    sheet = panel._sheet
    calls = []
    original_show_page = StagingSheet.show_page

    def spy_show_page(self, names, definitions, a2l_data, image):
        calls.append((list(names), definitions is picker.definitions, a2l_data is picker.definitions_source))
        return original_show_page(self, names, definitions, a2l_data, image)

    describes = []
    original_describe = a2l_definition.describe_definitions

    def spy_describe(*args, **kwargs):
        describes.append(1)
        return original_describe(*args, **kwargs)

    StagingSheet.show_page = spy_show_page
    picker_mod.describe_definitions = spy_describe
    a2l_definition.describe_definitions = spy_describe
    try:
        panel.query_one("#patch_param_filter").value = "MASK"
        for _ in range(40):
            await pilot.pause(0.05)
            if picker.visible_params == ["MASK_BIT_0001", "MASK_FIELD_0001"] and calls:
                break
        await pause(pilot)
        show("EX-R1.visible_params", picker.visible_params)
        show("EX-R1.last_show_page", calls[-1] if calls else None)
        show("EX-R1.sheet_rows", [r.name for r in sheet.rows])
        show("EX-R2.describe_calls_on_filter", len(describes))
        sheet.query_one("#patch_sheet_body").focus()
        await pause(pilot)
        await pilot.press("down")
        await pause(pilot)
        show("EX-K1.sheet_selected", sheet.selected_name)
        show("EX-K1.highlighted_parameter", (picker.highlighted_parameter or {}).get("name"))
        await pilot.press("up")
        await pause(pilot)
        show("EX-K1.after_up.highlighted_parameter", (picker.highlighted_parameter or {}).get("name"))
        panel.query_one("#patch_param_filter").value = "0001"
        for _ in range(40):
            await pilot.pause(0.05)
            if "DISPLAY_0001" in picker.visible_params and len(sheet.rows) > 2:
                break
        await pause(pilot)
        show("EX-R2.describe_calls_after_second_filter", len(describes))
        names = [r.name for r in sheet.rows]
        show("EX-S1.page_rows", names)
        mem = dict(app.current_file.mem_map) if app.current_file is not None else None
        show("EX-S1.image_word_0x800020", None if mem is None else (hex(mem.get(0x800020, -1)), hex(mem.get(0x800021, -1))))
        # P5 refresh_entries -> set_document
        row = ChangeEntryRow(kind_text="bytes", address_text="0x00800020", value_text="00 33", status_text="ok",
                             linkage_text="-", address=0x800020, encoded_bytes=(0x00, 0x33))
        panel.refresh_entries([row])
        await pause(pilot)
        staged = {r.name: r.is_staged for r in sheet.rows}
        show("EX-S1.refresh_entries.DISPLAY_0001_staged", staged.get("DISPLAY_0001"))
        show("EX-S1.refresh_entries.others_staged", sorted(n for n, s in staged.items() if s and n != "DISPLAY_0001"))
        panel.refresh_entries([])
        await pause(pilot)
        show("EX-R62.undo_like_empty.DISPLAY_0001_staged", {r.name: r.is_staged for r in sheet.rows}.get("DISPLAY_0001"))
        # P7 note_staged
        display_index = names.index("DISPLAY_0001")
        sheet._select(display_index)
        await pause(pilot)
        panel._dirty = False
        panel.note_staged("DISPLAY_0001")
        await pause(pilot)
        show("EX-S1.note_staged.dirty", panel.is_dirty)
        show("EX-S1.note_staged.selected", (sheet.selected_name, names[min(len(names) - 1, display_index + 1)]))
        sheet._select(0)
        await pause(pilot)
        panel._dirty = False
        panel.note_staged("DISPLAY_0001", advance=False)
        await pause(pilot)
        show("EX-S10.note_staged_no_advance", (panel.is_dirty, sheet.selected))
        # P6 set_image_mem_map
        panel.set_image_mem_map(None)
        await pause(pilot)
        body = str(sheet.query_one("#patch_sheet_body").render())
        line = next((ln for ln in body.splitlines() if "DISPLAY_0001" in ln), "")
        show("EX-R6.no_image.DISPLAY_0001_line_has_--", "--" in line)
        show("EX-R6.no_image.DISPLAY_0001_current", sheet.rows[display_index].current)
        if mem is not None:
            image = dict(mem)
            image[0x800010], image[0x800011] = 0x1A, 0xE6
            row = ChangeEntryRow(kind_text="bytes", address_text="0x00800010", value_text="1F F7", status_text="ok",
                                 linkage_text="-", address=0x800010, encoded_bytes=(0x1F, 0xF7))
            panel.refresh_entries([row])
            panel.set_image_mem_map(image)
            await pause(pilot)
            staged = {r.name: r.is_staged for r in sheet.rows}
            show("EX-M1.MASK_BIT_0001_staged", staged.get("MASK_BIT_0001"))
            show("EX-M1.MASK_FIELD_0001_staged", staged.get("MASK_FIELD_0001"))
            show("EX-M1.sheet_image_is_new_map", sheet._image is image)
    finally:
        StagingSheet.show_page = original_show_page
        picker_mod.describe_definitions = original_describe
        a2l_definition.describe_definitions = original_describe


async def focus_colours(app, pilot, panel, tag):
    """EX-L6 (styles.tcss #patch_sheet_win:focus-within)."""
    win = panel.query_one("#patch_sheet_win")
    panel.query_one("#patch_sheet_body").focus()
    await pause(pilot)
    show("EX-L6.sheet_focus.border_top", (win.styles.border_top[0], win.styles.border_top[1].hex))
    panel.query_one("#patch_doc_path_input").focus()
    await pause(pilot)
    show("EX-L6.file_row_focus.border_top", (win.styles.border_top[0], win.styles.border_top[1].hex))


if __name__ == "__main__":
    which = sys.argv[2:] or ["layout", "tabs", "filter", "sheet", "focus"]
    if "layout" in which:
        for size in ((118, 54), (220, 60), (80, 24)):
            run(size, layout)
        run((118, 54), layout, dock=True)
    if "tabs" in which:
        run((118, 54), tabs, a2l=False)
    if "filter" in which:
        for size in ((80, 24), (118, 54)):
            run(size, filter_row)
    if "sheet" in which:
        run((118, 54), sheet_wiring)
    if "focus" in which:
        run((118, 54), focus_colours)
    print("EXAMPLES_DONE")
