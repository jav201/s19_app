# Inc 8 E4 — implementer `impl-p` (group P, panel wiring)

Model claude-opus-5-5. Tree `b103-inc8` (shared, disjoint files). Base `d5d48685`; built on S1 `6c6134b6`, S2 `c6e3f7c4`, A `fdf7738e`. Times in `steps.log` (from `date`).

## Commits
- `894bb3db` batch-103 Inc 8 E4 group P: staging sheet over LANDS IN, filter row, sheet wiring — `patch_editor/layout.py`, `panel.py`, `a2l_picker.py`, `styles.tcss` (patch section only). 0 CR in the staged diff.
- this record + `evidence-e4/impl-p/` + `steps.log` (next commit).

## What is done (nodes of `codewire/graph-inc8.md`, E3R1/E3R2 rows override)
| Node | Where | Done |
|---|---|---|
| P1 `_TABS` | `panel.py` | Patch script / Inspector / JSON / Checks, every title `LANDS IN`; the A2L tuple left |
| P2 `__init__` | `panel.py` | `self._sheet = StagingSheet(id="patch_sheet")` after the picker |
| P3 `_show_tab` | `panel.py` | the `patch_win_a2l` measure branch left |
| P4 `_refresh_inspector_subtitle` | `panel.py` | Patch script and Inspector → the ledger subtitle (read from `#patch_win_script`, where the entries mixin writes it); JSON `v2 schema`; Checks its run state |
| P5 `refresh_entries` | `panel.py` (override) | `super()`, then `self._sheet.set_document([(row.address, tuple(row.encoded_bytes)) …], self._mem_map)` |
| P6 `set_image_mem_map` | `panel.py` | also `self._sheet.set_document(current entries, mem_map)` |
| P7' `note_staged(name, advance=True)` | `panel.py` | dirty writer w6 (`_dirty = True`, `_refresh_dirty_indicator()`); `advance` → `select_after(name)` |
| P8' `compose` | `layout.py` | ribbon; `#patch_filter_row`; `#patch_sheet_win` (title `STAGING SHEET`, subtitle `enter edit · ↑↓ row`) holding `self._sheet`; `#patch_inspector` (LANDS IN) with the four chips over `#patch_tab_switcher` (initial `patch_win_script`): `#patch_win_script` (ledger), `#patch_pane_inspector` (entry form, Use row, tally), `#patch_win_json`, `#patch_win_checks`; file row; `self._compose_doc_controls()` once, before the legend (I-8.3, unchanged call); legend. `#patch_main`, `#patch_win_a2l` left |
| P9 `_compose_filter_row` / `_compose_use_row` | `a2l_picker.py` | rename + split; ids and classes unchanged |
| P10' view-changed | `a2l_picker.py` | `show_page(visible_params, picker.definitions, picker.definitions_source, self._mem_map)` — no describe |
| P11 `_on_staging_sheet_selection_changed` | `a2l_picker.py` | `move_cursor(row=index)` on `#patch_param_table`; a name off the page moves nothing |
| P12 / P12' `styles.tcss` | patch section | see "Stylesheet shape" |

## Examples (run on `<runner>`, isolated env, HOME basename `<runner-home>`)
Command (from the shipped tree root, scratch `S=~/work/zq-e4-8-impl-p`):
`env -i PATH=/usr/bin:/bin HOME=$S/home/<runner-home> XDG_CONFIG_HOME=$S/x/config XDG_CACHE_HOME=$S/x/cache XDG_DATA_HOME=$S/x/data LOCALAPPDATA=$S/x/data TMPDIR=$S/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 PYTHONPATH=. timeout 300 ~/miniconda3/envs/s19ci/bin/python -B $S/examples_p.py $S/ex < /dev/null`
Script `evidence-e4/impl-p/examples_p.py` (DEFC from `make_release_case.py --case definitions`; real `S19TuiApp.run_test(size=…)`); full output `evidence-e4/impl-p/examples_p-transcript.txt` (exit 0, `uptime` load 4.51 at its top; no timing is decided). The lines below are pasted from it.

```text
s19_app.__file__ = ~/work/zq-e4-8-impl-p/tree/s19_app/__init__.py
EX-L1.118x54.region_y = [4, 5, 6, 31, 40, 41, 42]
EX-L1.118x54.strictly_increasing = True
EX-L1.118x54.heights = {'patch_identity_ribbon': 1, 'patch_filter_row': 1, 'patch_sheet_win': 25, 'patch_inspector': 9, 'patch_doc_file_row': 1, 'patch_doc_controls': 1, 'patch_legend': 1}
EX-L1.118x54.sheet_eq_panel_minus_others = True
EX-L1.118x54.sheet_border_title = 'STAGING SHEET'
EX-L1.118x54.sheet_border_subtitle = 'enter edit · ↑↓ row'
EX-L1.118x54.sheet_widget = ('StagingSheet', 'patch_sheet', 'patch_sheet_win')
EX-L8.118x54.lands_in_h = 6
EX-L8.118x54.sheet_h = 28
EX-L8.118x54.after_remove.lands_in_h = 9
LAW.PE_IDS_9C7BEAF.missing = []
LAW.left_ids_present = []
EX-L1.220x60.region_y = [4, 5, 6, 37, 46, 47, 48]
EX-L1.220x60.strictly_increasing = True
EX-L1.220x60.heights = {'patch_identity_ribbon': 1, 'patch_filter_row': 1, 'patch_sheet_win': 31, 'patch_inspector': 9, 'patch_doc_file_row': 1, 'patch_doc_controls': 1, 'patch_legend': 1}
EX-L1.220x60.sheet_eq_panel_minus_others = True
EX-L1.80x24.heights = {…, 'patch_sheet_win': 12, 'patch_inspector': 9, …}
EX-L1.80x24.panel_content_h = 9
EX-L1.80x24.panel_virtual_h = 26
EX-L1.80x24.sheet_ge_12 = True
EX-L1.118x54.dock.order = ['patch_identity_ribbon', 'patch_filter_row', 'patch_sheet_win', 'patch_inspector', 'patch_doc_file_row', 'patch_doc_controls', 'zq_dock_stand_in', 'patch_legend']
EX-L1.118x54.dock.region_y = [4, 5, 6, 27, 36, 37, 38, 42]
EX-L1.118x54.dock.heights = {…, 'patch_sheet_win': 21, …, 'zq_dock_stand_in': 4}
EX-L1.118x54.dock.sheet_eq_panel_minus_others = True
EX-L1.118x54.dock.sheet_ge_12 = True
EX-L2.chip_labels = ['Patch script', 'Inspector', 'JSON', 'Checks']
EX-L2.initial_pane = patch_win_script
EX-L2.initial_selected_chip = ['patch_tab_script']
EX-L2.patch_tab_script = ('patch_win_script', 'LANDS IN')
EX-L2.patch_tab_inspector = ('patch_pane_inspector', 'LANDS IN')
EX-L2.patch_tab_json = ('patch_win_json', 'LANDS IN')
EX-L2.patch_tab_checks = ('patch_win_checks', 'LANDS IN')
EX-L3.0_entries.subtitle = '0 entries'
EX-L3.1_entry.subtitle = '1 entry'
EX-L3.3_entries.subtitle = '3 entries'
EX-L3.3_entries_dirty_inspector.subtitle = '3 entries ●'
EX-L3.json.subtitle = 'v2 schema'
EX-L3.after_mark_saved.subtitle = '3 entries'
EX-L5.80x24.long_status.patch_param_filter = (True, 8, True)      # (on the filter row's y, width, inside the panel)
EX-L5.80x24.long_status.patch_param_status = (True, 21, True)
EX-L5.80x24.long_status.patch_param_page_prev_button = (True, 4, True)
EX-L5.80x24.long_status.patch_param_page_label = (True, 10, True)
EX-L5.80x24.long_status.patch_param_page_next_button = (True, 4, True)
EX-L5.80x24.long_status.patch_param_include_button = (True, 6, True)
EX-L5.80x24.long_status.patch_param_bulk_button = (True, 10, True)
EX-L4.80x24.table_displayed = False
EX-L4.80x24.full_name_displayed = False
EX-L4.80x24.picker_in_filter_row = patch_filter_row
EX-L4.80x24.use_row_in_inspector = True
EX-L4.80x24.use_row_below_bytes = True
EX-L5.80x24.patch_param_use_row = (True, True, True)
EX-L5.80x24.patch_param_use_status = (True, True, True)
EX-L5.118x54.long_status.patch_param_filter = (True, 31, True)
EX-L5.118x54.long_status.patch_param_status = (True, 33, True)
EX-L4.118x54.use_row_in_inspector = True
EX-L4.118x54.use_row_below_bytes = True
EX-R1.visible_params = ['MASK_BIT_0001', 'MASK_FIELD_0001']
EX-R1.last_show_page = (['MASK_BIT_0001', 'MASK_FIELD_0001'], True, True)   # (names, definitions is picker.definitions, a2l_data is picker.definitions_source)
EX-R1.sheet_rows = ['MASK_BIT_0001', 'MASK_FIELD_0001']
EX-R2.describe_calls_on_filter = 0
EX-K1.sheet_selected = MASK_FIELD_0001
EX-K1.highlighted_parameter = MASK_FIELD_0001
EX-K1.after_up.highlighted_parameter = MASK_BIT_0001
EX-R2.describe_calls_after_second_filter = 0
EX-S1.page_rows = ['ENUM_0001', 'MASK_BIT_0001', 'MASK_FIELD_0001', 'DISPLAY_0001', 'CURVE_DEF_0001', 'MAP_DEF_0001', 'VAL_BLK_DEF_0001']
EX-S1.refresh_entries.DISPLAY_0001_staged = True
EX-S1.refresh_entries.others_staged = []
EX-R62.undo_like_empty.DISPLAY_0001_staged = False
EX-S1.note_staged.dirty = True
EX-S1.note_staged.selected = ('CURVE_DEF_0001', 'CURVE_DEF_0001')   # (selected, the row after DISPLAY_0001)
EX-S10.note_staged_no_advance = (True, 0)
EX-R6.no_image.DISPLAY_0001_line_has_-- = True
EX-M1.MASK_BIT_0001_staged = True
EX-M1.MASK_FIELD_0001_staged = True
EX-M1.sheet_image_is_new_map = True
EX-L6.sheet_focus.border_top = ('round', '#91ABEC')
EX-L6.file_row_focus.border_top = ('round', '#1B233A')
EXAMPLES_DONE
exit=0
```

| Example | Node | Verdict |
|---|---|---|
| EX-L1 118×54, 220×60 (seven regions strictly increasing; LANDS IN 9; sheet = panel − others) | P8', P12 | held |
| EX-L1 subtitle / title, `_sheet` StagingSheet `patch_sheet` | P8', P2 | held |
| EX-L7 4-row stand-in dock inside `_compose_doc_controls` (between the document row and the legend; sheet = panel − the other seven; ≥ 12) | P8' (I-8.3) | held |
| EX-L8 `-bench` → LANDS IN 6, sheet +3 | P12' | held |
| EX-L9 80×24 sheet window ≥ 12 (panel scrolls: content 9, virtual 26) | P12' | held |
| EX-L2 chips, initial pane, `_show_tab` titles | P1, P3, P8' | held |
| EX-L3 0/1/3 entries, `3 entries ●` on Inspector, `v2 schema` on JSON | P4, P7' | held (+ the clear after `mark_saved`) |
| EX-L4 filter row (table and full-name hidden), Use row in `#patch_pane_inspector` below the Bytes input | P9 | held |
| EX-L5 80×24 / 118×54 containment, incl. the longest count line `200 of 13990 shown — refine filter.` | P12 | held |
| EX-L6 accent `#91ABEC` with the sheet focused, rule colour with the file row focused | P12 | held |
| EX-R1 filter `MASK` → `show_page(names, picker.definitions, picker.definitions_source, …)` | P10' | held |
| EX-R2 0 describes on filter changes | P10' | held for two filter changes; **a page turn could not run** (DEFC holds 7 names, one page; the tester's software_a / 201-name case) |
| EX-K1 sheet selection → `highlighted_parameter` | P11 | held (down and up) |
| EX-S1 `refresh_entries([row 0x800020 00 33])` → DISPLAY_0001 staged only; empty doc → unstaged | P5 | held |
| EX-S7 Parse pasted → `●` | P5 | **could not run** here: an app Parse-pasted scenario (case R-PE-DEF.62/3, tester); the override sits under every refresh site, so it needs no new call site |
| EX-R6 no image → `--`; EX-M1 new image word `1A E6` → MASK_BIT and MASK_FIELD staged | P6 | held |
| EX-S1 / EX-S10 `note_staged` (advance / no advance) | P7' | held |

## Stylesheet shape (for the tester who retargets `tests/test_b97_flow_execution.py:2088-2100`)
The Inc 8 edits inside the b514b07 prefix are expressed by **four entries**, added after the db1a8f7 entries and before the `startswith` assertion (that assertion is not edited). Checked by `evidence-e4/impl-p/css_law_probe.py`, a scratch copy of the law with the four entries spliced in (transcript `css_law_probe-transcript.txt`):
```text
-- control: HEAD sheet, the law as committed
LAW.without = PASS
-- Inc 8 sheet, the law as committed (expected FAIL)
LAW.without = FAIL: every rule shipped at b514b07 is byte-equal; Inc-6 only appends
-- Inc 8 sheet, the law + proposed Inc 8 supersessions
LAW.with = PASS
-- HEAD sheet, the law + proposed Inc 8 supersessions (expected FAIL: they name Inc 8 text)
LAW.with = FAIL: Inc 8 block
```
1. `supersede(old, INC8_REGION_BEFORE, INC8_REGION_AFTER, …)`: the contiguous region from `#patch_editor_panel #patch_main {` through `#patch_editor_panel #patch_win_script:focus-within,` becomes the `#patch_sheet_win` rule (`height: 1fr; min-height: 12;` + border), the borderless `#patch_win_script`, the 9-row full-width `#patch_inspector`, and `#patch_sheet_win:focus-within,` (exact strings in the probe).
2. `supersede(old, "#patch_editor_panel #patch_win_checks,\n#patch_editor_panel #patch_win_a2l {\n    height: 100%;", "#patch_editor_panel #patch_win_checks {\n    height: 100%;", …)`.
3. `inc8 = inserted("/* --- Filter row and bench state (batch-103 Inc 8", "#patch_editor_panel.-bench #patch_inspector", …)` then `supersede(old, "/* batch-97 flow_builder", inc8 + "/* batch-97 flow_builder", …)`.
4. The `.ce-row` / `.ce-label` re-scope (`#patch_win_a2l` → `#patch_filter_row`) lies inside db1a8f7's inserted block, which the law reads from the sheet: no entry needed.
TC-B97-04's two scope tests pass on the tree (below).

## Other runs (single files, `-n 2`, `timeout 300`)
- `tests/test_b97_patch_editor.py::test_tc_b97_04_patch_rules_scoped_and_check_rule_untouched`, `::test_tc_b97_04_no_unscoped_patch_rule_in_the_whole_stylesheet`, `::test_tc_b97_04_e3_pairs_absent`: 3 passed. `::test_tc_b97_01_shipped_ids_and_container_types` (PE_IDS law, both sizes): 2 passed.
- Informational, not mine to fix (E1 §5 retarget list): `tests/test_b97_patch_editor.py` + `tests/test_tui_patch_layout.py` → 22 failed, 25 passed (179 s). Failed: TC-B97-02 ledger_grows ×2, 05 paste_heading, 39 strip_follows_the_highlight, 39 long_entry…resize, 40 labelled_form ×2, 40 capped_strip ×2, 60 every_control ×3, 41 keyboard_order, AT-B97-01, 02, 17; `test_at063a`, `at063b`, `at064a`, `at064b`, `at064c`, `tc46_1`. Six reasons read: all pin the old two-column layout (the Inspector as the first tab, the ledger beside it, all ledger rows visible at once, the ledger in the focus chain while the JSON tab is shown). The other 13 files of the list were not run.

## Deviations (each in my files)
- D-P1 `PatchEditorPanel._refresh_dirty_indicator` override (not a graph node): `super()`, then `_refresh_inspector_subtitle()`, so LANDS IN follows every dirty writer (w1 … w6), not only the refresh path; without it `mark_saved` left `3 entries ●` on the pane (EX-L3 `after_mark_saved`).
- D-P2 `_apply_layout`: the ledger width falls back to the landing pane's content width while another tab hides the ledger (the borderless ledger fills the pane), so a resize on the Inspector tab still re-derives the strip's bytes per row. Before Inc 8 the ledger was always shown.
- D-P3 `_sheet_entries(rows)` static helper, shared by P5 and P6.
- D-P4 Selector spelling: the graph's `PatchEditorPanel.-bench #patch_inspector` and `#patch_sheet_win { min-height: 12; }` are written `#patch_editor_panel.-bench #patch_inspector` and `#patch_editor_panel #patch_sheet_win`: TC-B97-04 requires the `#patch_editor_panel` root, and a type+class+id selector loses to the section's two-id `#patch_inspector` rule (the bench rule would never apply).
- D-P5 Three filter-row rules not in the graph: filter input `min-width: 8`, count line `max-width: 30%` (the picker sets the status width `auto` inline), `#patch_param_controls { width: auto; }` (the unscoped `.patch-docked-row` gives it 100%). Needed for R-PICKER-CORRECT.020 at 80 columns with the longest count line (held).
- D-P6 LANDS IN gains `border-subtitle-color: DGRAY` (the ledger subtitle's colour, now on the pane; `v2 schema` turns DGRAY too). Visible: V-1.
- D-P7 `#patch_win_script` keeps its `border_title` assignment (`PATCH SCRIPT`); with no border it is not painted (R-TUI-063.7 retired). Kept to keep the diff small.

## Findings
- F-P1 (visible, V-1): the before→after strip (Inspector tab) and the ledger (Patch script tab) are no longer on screen together, so "the strip follows the ledger highlight" (TC-B97-39, AT-B97-17) needs a tab switch. A consequence of D-1 A, not a code defect; judge it with V-1.
- F-P2: the dirty-writer census is now six (w6 `note_staged`); any law that counts the C-15.1 writers takes w6 (tester).
- F-P3 (backlog, usa/difiere/borra): `A2lPickerMixin._apply_a2l_layout` is now inert (the picker table is hidden, width 0, it returns at once) but still called from three sites; candidate for the batch-end census.
- No interface change is proposed. I-8.3 holds: `compose` calls `self._compose_doc_controls()` once, after the file row and before the legend (EX-L7).

## Open gaps
- Real Windows Terminal captures (V-1, V-2, V-10) were not taken (HT-10 needs the operator's approved round).
- EX-R2's page turn and EX-S7 (see above) are the tester's cases.
