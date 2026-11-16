# Inc 8 — E1 slice: the files and functions to change, counted and mapped

Base `91d5ae56`; every line number is "as of `91d5ae56`". Rows: `01-requirements.md`. The slice follows the recommended options of `E1-rulings.md` §3 (D-1 A … D-8 A). Callers: Code-Wire `v3.1.0-8-gb6cd30d` (`git -C C:\Users\<user>\Github\code-wire describe --tags`), core only — `tools/codewire_marks.py` then `tools/codewire_extract.py` on a throwaway one-commit copy of `git archive 91d5ae56 s19_app` outside every work tree (`evidence-e1/cw-census.sh`, context graph `evidence-e1/cw-census-graph.md`, output `evidence-e1/cw-census-extract.json`, `cw-census-diff-report.md`, transcript `cw-census-transcript.txt`: 28 marks, 12 calls, 10 findings, exit 1). The 10 findings are type spellings of the context graph (`object` for a union, `list` for `list[ChangeEntryRow]`), expected: the census graph carries no prototype. Callers inside textual 8.2.8 (compose, message dispatch, bindings) are outside the extractor; they are read (R).

## 1. Groups and files (D-5 A: three groups, 8 source files, none over 4)

| Group | Files | Rows |
|---|---|---|
| **S — the sheet (new modules)** | new `s19_app/tui/definition_sheet.py` (pure: rich `Text` and I-2 only, no textual); new `s19_app/tui/screens_directionb/patch_editor/sheet.py` (the `StagingSheet` widget); `s19_app/tui/a2l_parameter_picker.py` (one read-only attribute, E3R1 E3A-04) | R-PE-DEF.5 … .7, .10 … .49, .70 … .72, .75 … .82 (E3R1) |
| **P — panel wiring** | `screens_directionb/patch_editor/layout.py`, `panel.py`, `a2l_picker.py`; `s19_app/tui/styles.tcss` (the `/* batch-97 patch_editor */` section) | R-TUI-063.1, .3, .4, .6, R-PE-041, R-PE-DEF.1.1, .1.2, .2 … .4, .49, .74, R-PICKER-CORRECT.011, .020, R-PE-034 (writer) |
| **A — staging (service and app) and help** | `s19_app/tui/services/change_service.py`; `s19_app/tui/app/patch.py`; `s19_app/tui/window_help.py` (E3R1 E3A-06) | R-PE-DEF.50 … .64, .73, .83 … .87, R-PE-034, R-PE-035, R-PE-110 |

**Totals (after E3R1):** 2 new modules, 8 changed files; 10 source files in 3 groups (S 3, P 4, A 3); at E4, S runs as S1 (`definition_sheet.py`, 19 nodes) and S2 (`sheet.py` + `a2l_parameter_picker.py`, 11 nodes). `a2l_parameter_picker.py` is Inc 7's file: S2's edit is one attribute in `set_parameters`; whichever of Inc 7 and Inc 8 merges second rebases (DF-10). E1 totals were 8 files (S 2, P 4, A 2). The PLAN guessed 4 files (`screens_directionb.py`, a new editor module, `change_service.py`, `app.py`); the package split of `91d5ae56` spreads the Patch Editor over several modules, and the pure model is kept apart from the widget so its 30-odd cell rules are tested without Textual. **Not changed:** `patch_editor/entries.py`, `document.py`, `checks.py`, `actions.py` (Inc 10's), `shared.py`; `a2l_definition.py` (I-2, read only); `changes/*`. (E1 listed `a2l_parameter_picker.py` here; the E3A-04 ruling moves one attribute into it.)

Function count: 34 slice entries (S 19, P 12, A 3) — 25 new, 9 changed (P9's rename and split counted once, as changed); a few entries hold two or three small functions under one contract (§2). Graph estimate: 34 prototype nodes + about 12 context nodes, under the cap of about 40 prototype nodes (`codewire/graph-inc8.md` "Node count"). **E2 count: 42 nodes** (one per function, the entries' small helpers and `action_edit` counted apart), 2 over the cap: `E1-rulings.md` D-9.

## 2. Function map

### Group S — `s19_app/tui/definition_sheet.py` (new, pure)

| # | Function | Change | Rows |
|---|---|---|---|
| S1 | `SheetWidths` (NamedTuple: mark, name, kind, current, new, unit, limits, delta) and `sheet_widths(width: int) -> SheetWidths` | new | R-PE-DEF.6, .7 |
| S2 | `StagedOverlay(Mapping[int, int])`: `__init__(image, entries)`, `__getitem__`, `__iter__`, `__len__` — image + entries' bytes in document order; `entries` = `(address, bytes)` pairs | new; also used by group A (interface I-8.1) | R-PE-DEF.51, .62 |
| S3 | `row_kind(definition) -> str` (`number`, `bit mask`, `enum`, `text`, `none`) and `kind_word(definition) -> str` | new | R-PE-DEF.16, .36 |
| S4 | `SheetRow` (frozen dataclass: name, definition, kind, current, staged) and `build_row(definition, a2l_data, image, overlay) -> SheetRow` | new | R-PE-DEF.17 … .19, .23, .62 |
| S5 | `value_text(row_kind, decoded) -> str` | new | R-PE-DEF.17 … .19, .23, .24 |
| S6 | `Preview` (frozen dataclass: result, decoded) and `preview(definition, a2l_data, text, overlay) -> Preview` | new | R-PE-DEF.24, .25, .40, .51 |
| S7 | `delta_text(row, value, staged) -> str` and `short_number(x) -> str` | new | R-PE-DEF.21, .26, .27 |
| S8 | `limits_cell(row, value, width) -> Text` | new | R-PE-DEF.21 |
| S9 | `header_line(widths) -> Text` and `row_line(row, widths, selected, pending, preview) -> Text` | new | R-PE-DEF.5, .15 … .28 |
| S10 | `detail_lines(row, preview, width) -> list[Text]` with the dispatch table `_DETAIL_BY_KIND` and the helpers `_definition_line`, `_enum_options`, `_bit_strip`, `_text_rows` | new | R-PE-DEF.30 … .35 |
| S11 | `formula_label(row_kind) -> str` and `formula_tail(row, preview, width) -> Text` | new | R-PE-DEF.36, .37, .40, .41 |
| S12 | `plain(text) -> str`, `name_echo(text) -> str`, `clip(text, width) -> str` | new | R-PE-DEF.15, .70 … .72 |

### Group S — `s19_app/tui/screens_directionb/patch_editor/sheet.py` (new widget)

| # | Function | Change | Rows |
|---|---|---|---|
| S13 | `StagingSheet(Vertical)` with `BINDINGS` (up, down, enter, left, right) and messages `StageRequested(name, text)`, `SelectionChanged(name)` | new | R-PE-DEF.45 … .47 |
| S14 | `StagingSheet.compose` (body `Static`, focusable; formula bar: name `Label`, label `Label`, `OsClipboardInput(max_length=4096)`, tail `Static`) | new | R-PE-DEF.37, .42 |
| S15 | `StagingSheet.show_page(names, a2l_data, image)` — one `describe_definitions(names, a2l_data)` per call, rows rebuilt, selection kept by name else row 0 | new | R-PE-DEF.10 … .14 |
| S16 | `StagingSheet.set_document(entries, image)` — rebuilds the overlay and every row's staged state | new | R-PE-DEF.18, .23, .62 |
| S17 | `StagingSheet.action_move`, `action_edit`, `action_choose`, `select_next`, `selected_name` | new | R-PE-DEF.45 … .47, .49, .60 |
| S18 | `StagingSheet.on_input_changed`, `on_input_submitted`, `_on_formula_escape` (Escape in the input) | new | R-PE-DEF.24, .25, .39, .40, .48, .50 |
| S19 | `StagingSheet._paint` (body, formula bar; widths from the sheet's content region) | new | R-PE-DEF.5 … .7, .30, .41 |

### Group P — panel wiring

| # | Function | File:line (base) | Change | Rows |
|---|---|---|---|---|
| P1 | `PatchEditorPanel._TABS` | `panel.py:110-115` | changed: `("patch_tab_script", "Patch script", "patch_win_script", "LANDS IN")`, Inspector, JSON, Checks, every title `LANDS IN`; the A2L tuple leaves | R-TUI-063.3, .6 |
| P2 | `PatchEditorPanel.__init__` | `panel.py:468-529` | changed: builds `self._sheet = StagingSheet(id="patch_sheet")` beside `self._a2l_picker` | R-TUI-063.1 |
| P3 | `PatchEditorPanel._show_tab` | `panel.py:711-728` | changed: the `patch_win_a2l` measure branch (`:719-722`) leaves; the title stays `LANDS IN` | R-TUI-063.6 |
| P4 | `PatchEditorPanel._refresh_inspector_subtitle` | `panel.py:623-635` | changed: Patch script and Inspector tabs → the ledger subtitle; JSON → `v2 schema`; Checks → its run state | R-PE-041 |
| P5 | `PatchEditorPanel.refresh_entries` (override, new in `panel.py`) | — | new: `super().refresh_entries(...)`, then `self._sheet.set_document(rows' (address, encoded_bytes), self._mem_map)` | R-PE-DEF.62 |
| P6 | `PatchEditorPanel.set_image_mem_map` | `panel.py:673-681` | changed: also `self._sheet.set_document(..., mem_map)` | R-PE-DEF.18 |
| P7 | `PatchEditorPanel.note_staged` (new) | — | new: dirty writer **w6** (sets `_dirty`, repaints the indicator) and `self._sheet.select_next()` | R-PE-034, R-PE-DEF.60 |
| P8 | `LayoutMixin.compose` | `layout.py:17-86` | changed: ribbon; filter row (`self._compose_filter_row()`); the sheet window (`#patch_sheet_win`, `self._sheet`); the landing pane `#patch_inspector` with the four chips over `#patch_tab_switcher` (`#patch_win_script` holding the ledger; `#patch_pane_inspector` + the Use row; `#patch_win_json`; `#patch_win_checks`); file row; `self._compose_doc_controls()` (Inc 10's dock rides inside it, D-8); legend. `#patch_main` and `#patch_win_a2l` leave; every other shipped id keeps its type | R-TUI-063.1, .3, .4, R-PE-DEF.1 … .3 |
| P9 | `A2lPickerMixin._compose_a2l_tab` → `_compose_filter_row` (renamed) and `_compose_use_row` (new, split from it) | `a2l_picker.py:221-242` | changed: the picker goes to the filter row; the Use row and status line to the Inspector pane | R-PE-DEF.2, .3 |
| P10 | `A2lPickerMixin._on_a2l_parameter_picker_view_changed` | `a2l_picker.py:209-219` | changed: + `self._sheet.show_page(self._a2l_picker.visible_params, app.current_a2l_data, self._mem_map)` | R-PE-DEF.10, .11 |
| P11 | `A2lPickerMixin._on_staging_sheet_selection_changed` (new) | — | new: moves the picker table's cursor to the named row (`highlighted_parameter` then names it) | R-PE-DEF.49 |
| P12 | `styles.tcss` patch_editor section | `:1105-` | changed: new rules for `#patch_sheet_win` (`1fr`, accent on `:focus-within`), the filter row (`height: 1`, picker table hidden), `#patch_inspector` (`height: 9`, full width); the ledger beside-inspector rules (`#patch_main`) and A2L-tab rules leave | R-PE-DEF.1, .2, .4, R-TUI-064.1 … .3 |

### Group A — staging

| # | Function | File:line (base) | Change | Rows |
|---|---|---|---|---|
| A1 | `ChangeService.stage_definition(definition, a2l_data, text, image) -> ChangeActionResult` (new) | `change_service.py`, after `add_symbol_entry` (`:1253-1329`) | new: overlay = `StagedOverlay(image, entries)`; `encode_definition(..., overlay)`; refusal → result not ok; else `_stage_encoded` | R-PE-DEF.50, .51, .56, .57, .59 |
| A2 | `ChangeService._stage_encoded(name, encoded) -> ChangeActionResult` (new; **the Inc 9 seam**) | same | new: equal span → replace bytes, keep symbol; no intersect → append `ChangeEntry("bytes", address, data, symbol=name)`; partial → refuse; `_push_history` before the write | R-PE-DEF.52 … .55, .58, .61 |
| A3 | `PatchMixin.on_staging_sheet_stage_requested(event)` (new) | `app/patch.py`, beside `on_patch_editor_panel_action_requested` (`:94-317`) | new: no A2L → R-PE-DEF.63 status; `describe_definition(event.name, current_a2l_data)`; `stage_definition(..., image)`; `_report_change_result`; on ok `panel.note_staged()`; `_refresh_patch_history_view()` | R-PE-DEF.57 … .64, .73, R-PE-035 |

### E3R1 changes to the map (E3 rulings and the accepted Inc 9 items; nodes in `codewire/graph-inc8.md`)

| # | Function | Group | Change | Rows |
|---|---|---|---|---|
| S3' | `row_kind`; new `KindOps` (NamedTuple), `_KIND_OPS`, `_FALLBACK_OPS`, `ops_for(kind)` replace `_DETAIL_BY_KIND`, `_EDITABLE_KINDS`, `_FORMULA_LABELS` and `formula_label` (I-8.5) | S1 | E3A-02, Inc 9 K-1 … K-3 | R-PE-DEF.17, .23, .36, .37, .75 |
| S4' | `build_row`, `value_text(row, decoded)` dispatch through `ops_for` | S1 | E3A-02 | R-PE-DEF.17 … .19, .23, .75 |
| S7' / S8' | `delta_text`, `limits_cell`: no division while upper ≤ lower | S1 | E3S-05 | R-PE-DEF.76, .77 |
| S9' | `row_line`: clip in cells; `KindOps.cells` when given | S1 | E3A-12, Inc 9 K-2 | R-PE-DEF.7 |
| S10' | `detail_lines(row, preview, width, state, room)`: the layout word when named; text rows ≤ 4 and the cut line | S1 | Inc 9 K-1, C-6; E3S-04 | R-PE-DEF.31, .35, .79 |
| S20 | new `row_window(selected, top, visible, detail)` | S1 | E3A-01 | R-PE-DEF.81 |
| S21 | new `formula_fill(row, pending)`: the row fill, "" without an editor, ≤ 4,096 characters | S1 | E3A-11, E3S-04 | R-PE-DEF.24, .38, .39, .78, .80 |
| S15' | `StagingSheet.show_page(names, definitions, a2l_data, image)`: 0 describes; the page A2L stored for `set_document` and the preview (E3R2, E3A-13) | S2 | E3A-04 | R-PE-DEF.10 … .14 |
| S17' | `select_next()` → `select_after(name)`; `action_move` keeps the row window; `states`, child ids and `_paint()` pinned as I-8.4 | S2 | E3A-07, E3A-01, Inc 9 C-2 | R-PE-DEF.60, .81, .82 |
| S19' | `_paint`: row window, `formula_fill`, the bar's labels as `Text`, `KindOps.bar` when given | S2 | E3A-01, E3S-07, Inc 9 K-3 | R-PE-DEF.70, .78, .81 |
| S22 | `A2LParameterPicker.set_parameters` (`a2l_parameter_picker.py:568`): keeps its describe as `definitions` | S2 | E3A-04 | R-PE-DEF.11 |
| P7' | `PatchEditorPanel.note_staged(name, advance=True)` | P | E3A-07, Inc 9 C-8 | R-PE-DEF.60 |
| P8' | `LayoutMixin.compose`: the sheet subtitle `enter edit · ↑↓ row`; Inc 9's integrator appends ` · arrays open the bench` (E3R2, E3A-15) | P | Inc 9 C-4 split (provisional) | R-PE-DEF.1.1 |
| P10' | `_on_a2l_parameter_picker_view_changed`: passes the picker's `definitions` | P | E3A-04 | R-PE-DEF.10, .11 |
| P12' | `styles.tcss`: `#patch_sheet_win { min-height: 12; }`; `PatchEditorPanel.-bench #patch_inspector { height: 6; }` | P | E3A-05 b, E3A-09, Inc 9 C-5 (provisional) | R-PE-DEF.1.2, .74 |
| A1' | `stage_definition`: the source view; notices in `ChangeActionResult.notices` (new field, default `()`) | A | E3S-01, E3A-10 | R-PE-DEF.51, .59 |
| A2' | `_stage_encoded(name, encoded, shown)`: replaces the entry with a bytes entry | A | E3A-03, E3S-02 | R-PE-DEF.52, .54, .58 |
| A3' | `on_staging_sheet_stage_requested`: `_refuse_if_busy()` first; `_strip_source_map`; prints `notices`; `note_staged(event.name)` | A | E3S-03, E3S-01, E3A-10, E3A-07, Inc 9 E-2 | R-PE-110, R-PE-DEF.51, .59, .60 |
| A4 | `WINDOW_HELP_SECTIONS["patch"]` (`window_help.py:61-136`) | A | E3A-06 | R-PE-DEF.83 … .87 |

E3R1 callers (Code-Wire extractor on the changed existing functions, `evidence-e1/cw-e3r1-*`): `A2LParameterPicker.set_parameters` ← `check_editor.py:223`, `patch_editor/a2l_picker.py:40` (C); `section_body_text` ← `window_help.py:712` (C); `PatchMixin._strip_source_map` ← `app/patch.py:293`, `:571`, `:1537` (C); `PatchMixin._report_change_result` ← 8 sites in `app/patch.py` (C); `ShellMixin._refuse_if_busy` ← 2 sites (C; 9 ambiguous name resolutions), 20 by grep (R), the Patch gate at `app/patch.py:145`.

## 3. Callers read (rule 8: read before you write)

From `evidence-e1/cw-census-extract.json` (C), with the sites the extractor files as top-level read back to their function (R):
- `LayoutMixin.compose` ← textual compose only (R). `_compose_a2l_tab` ← `layout.py:75` only (R) — P9's rename has one caller, P8.
- `A2lPickerMixin._on_a2l_parameter_picker_view_changed` → `_apply_a2l_layout` (`a2l_picker.py:221`, C); it is called by message dispatch only (R). P10 adds one call.
- `A2lPickerMixin._use_highlighted_parameter` ← `actions.py:94` (the `Use parameter` button branch of `on_button_pressed`, R). Unchanged: it reads `highlighted_parameter`, which P11 keeps in step with the sheet.
- `A2lPickerMixin.set_a2l_parameters` ← `app/patch.py:1613` (`_prefill_patch_editor`, C) and `app/checks_diff.py:101` (C; that site is the Check Editor's `CheckEditorPanel.set_a2l_parameters` filed under the same name, R). Unchanged; the population posts `ViewChanged`, which reaches P10.
- `PatchEditorPanel.__init__` ← `app/compose_screens.py:540` (C).
- `PatchEditorPanel.set_image_mem_map` ← `app/loaded_state.py:407` (C, the unload path).
- `PatchEditorPanel._refresh_inspector_subtitle` ← `_show_tab` (`panel.py:728`, C), `on_mount` (`:622`, C; the site lies in `_set_window_subtitle` `:588-621`, R).
- `EntriesMixin.refresh_entries` ← `app/loaded_state.py:675`, `app/patch.py:289` (action tail), `:568` (`_refresh_patch_history_view`, C), `:1534` (`_patch_editor_load_tail`, R), `app/project_load.py:1029`, and `panel.py:698` (`on_mount`'s self-call, R). P5's override is reached by all six; it adds no call site.
- `ChangeService.add_symbol_entry` → `_entry_index` (`:1315`), `_push_history` (`:1323`) (C). **No product caller** (R: only `tests/test_b97_patch_editor.py`, `tests/test_changes_symbol_entries.py`); A1 does not call it (its encode is the pre-I-2 `encode_physical_to_raw_bytes`, which I-2 forbids for masked objects, graph-inc2 "Inc 8 and Inc 9 … never call `a2l.encode_physical_to_raw_bytes`"). Kept (usa/difiere/borra: deferred to the batch-end census, PENDING note in `E1-rulings.md` §6).
- `ChangeService._push_history` ← 6 sites (`:1248`, `:1365`, `:1395`, `:1524`, `:1587`, `:1652`, C); A2 adds one.
- `ChangeService.rows` ← the five refresh sites above (C). Unchanged; `ChangeEntryRow.address` and `.encoded_bytes` (`change_service.py:373-441`) carry what P5 hands the sheet.
- `PatchMixin._refresh_patch_history_view` ← `:726` (undo), `:761` (redo), `:1000` (per-entry JSON edit) (C, R). A3 adds one.
- `PatchMixin._report_change_result` ← 8 sites (C). A3 adds one.
- I-2: `describe_definitions` ← `a2l_parameter_picker.py:609` (C); `describe_definition` → `describe_definitions` (`a2l_definition.py:608`). S15 and A3 add one call each. `encode_definition` and `decode_definition` have no product consumer yet (C: only I-2-internal sites); S4, S6 and A1 are the first.

Tests that pin today's layout (E4 retargets them; tests are not capped): 15 files name `patch_tab_a2l`, `patch_win_a2l`, `patch_tab_inspector`, `INSPECTOR` or `PATCH SCRIPT` (25 lines for the A2L tab ids alone; `grep -rln` list in `E1-rulings.md` §5), and two snapshot baselines `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[patch-comfortable-{120x30,80x24}].svg`.

## 4. Inc 9 seam

Inc 9 (CURVE / MAP / VAL_BLK as pe_C benches inside this sheet) **adds** and does not rewrite. Whether 8 and 9 can be built in parallel depends only on the list below.

**Re-pinned at E3R1** (ruling E3A-02 option 1, and Inc 9's `E1-rulings.md` §4 items the orchestrator accepted: C-2, K-1, K-2, K-3, C-6, C-8, C-9, E-2, and C-4, C-5 provisionally). The E1 text of this section (three tables) is superseded.

**Inc 9 extends (adds new functions, or adds keys to the one table Inc 8 pins):**
- `definition_sheet._KIND_OPS` (I-8.5): Inc 9 adds the keys `"array"`, `"curve"`, `"map"` → `KindOps` entries whose callables live in a **new** module (e.g. `s19_app/tui/definition_bench.py`). The table, `ops_for` and `_FALLBACK_OPS` are Inc 8's; adding keys is the only edit. The optional fields `cells` and `bar` (K-2, K-3) carry the bench's cells and formula bar; `detail(row, preview, width, state, room)` (K-1) its bench lines.
- `StagingSheet` (`sheet.py`): Inc 9 subclasses it (`ArrayBenchSheet`, Inc 9 D-1 A) and overrides only the I-8.4 overridable methods (`action_edit`, `action_move`, `action_choose`, `_on_formula_escape`, `show_page`, `set_document`, each calling `super()` off its rows), adds its bindings and workers, keeps per-row state in `states`, repaints only through `_paint()`, and addresses `#patch_sheet_body` / `#patch_sheet_input`. The subclass is constructed in `PatchEditorPanel.__init__` by Inc 9's integrator after Inc 8 merges (Inc 9 C-1: no Inc 8 change).
- `ChangeService`: Inc 9 adds `stage_values(definition, a2l_data, edit, image)` that calls I-2 `encode_values` over `StagedOverlay` and hands the result to **`_stage_encoded(name, encoded, shown)`** with its own `shown` (I-8.2). Inc 8 keeps the template `staged as <shown>`; Inc 9 rewords R-PE-BENCH.72 (Inc 9 C-7: no Inc 8 change).
- `app/patch.py`: Inc 9 adds its record-stage handler. It begins with `ShellMixin._refuse_if_busy()` and passes the source view (the I-8.2 stage seam, E-2, E-1) and reports with `note_staged(name, advance=False)` (C-8).
- `layout.py` (E3R2, E3A-15): Inc 9's integrator appends ` · arrays open the bench` to the sheet subtitle after the merge (one string).
- `StagingSheet.show_page(names, definitions, a2l_data, image)` (E3R2, E3A-13): an override passes the page A2L on to `super()`; Inc 9's decodes use the stored payload, never `app.current_a2l_data`.
- `styles.tcss`: Inc 9 adds rules for the bench. Inc 8 owns the `-bench` rule `PatchEditorPanel.-bench #patch_inspector { height: 6; }` (R-PE-DEF.1.2) and `#patch_sheet_win { min-height: 12; }` (R-PE-DEF.74); Inc 9's sheet sets the `-bench` class on its panel ancestor.

**Inc 9 must not touch:** `StagedOverlay`, `ops_for`, `_FALLBACK_OPS`, `build_row`, `value_text`, `preview`, `delta_text`, `limits_cell`, `row_line`, `header_line`, `sheet_widths`, `row_window`, `formula_fill`, `plain`, `name_echo`, `clip`, `_definition_line` (the definition line is the bench's first detail line too; it paints a named record layout since E3R1, C-6), `StagingSheet.on_input_submitted`, `select_after`, `_paint`, `ChangeService.stage_definition`, `_stage_encoded`, `PatchMixin.on_staging_sheet_stage_requested`, and every group P function.

**Shared points that are not disjoint (1 line):** the three `_KIND_OPS` keys in `definition_sheet.py`. **Build 8 and 9 in parallel at E4**, with Inc 9's keys applied by the integrator after Inc 8 merges (owned by Inc 9's group). Everything else Inc 9 writes is in new functions, a subclass or new modules.

## 5. Inc 10 shared points (PROPOSED interface I-8.3, `E1-rulings.md` D-8)

Inc 10 owns `patch_editor/actions.py` (the apply/save bar). Inc 8 does not edit it. The points where the two meet:
1. **Where Inc 10's export dock is composed.** `LayoutMixin.compose` (Inc 8) calls `self._compose_doc_controls()` exactly once, after the file row and before the legend — as it does today (`layout.py:77`). Inc 10 yields its dock **from inside** `ActionsMixin._compose_doc_controls` (`actions.py:563`), after the document row. Then Inc 10 needs no edit of `layout.py`. Inc 10's E1 slice was written against `e07fb00` and names `compose`; after the split this is the point it should use.
2. **`R-TUI-063.1`.** Inc 8 writes the order (… landing pane, file row, document row, legend); Inc 10's R-2 inserts "the save-back prompt while it is shown" between the document row and the legend. The two edits compose; the batch-end canon fold takes Inc 8's text with Inc 10's insertion.
3. **`styles.tcss`.** Inc 8 adds a new block and removes the `#patch_main` / A2L-tab rules; Inc 10 edits the save-back rules (`:2998`, `:3011`, `:3146-3149`, `:3159-3167` as of `e07fb00`). Disjoint hunks; the integrator merges.
4. **`#patch_win_json`.** Inc 8 keeps it as a landing-pane tab, unchanged inside; Inc 10 moves the save-back row and the before/after control out of it.
5. **`PatchEditorPanel.__init__`.** Both add one attribute (Inc 8 `_sheet`, Inc 10 `_saveback_format`): adjacent lines, a trivial merge.

**E3 ruling E3A-05 (recorded at E3R1).** Inc 8 owns I-8.3: the dock is yielded from `ActionsMixin._compose_doc_controls` in `actions.py`, after `#patch_doc_controls`. **Inc 10's re-map (PENDING P-020) must consume I-8.3 and must not rely on `#patch_main`**: after Inc 8 the region that yields rows is `#patch_sheet_win`, with `min-height: 12` (R-PE-DEF.74). R-PE-DEF.1.1 counts the other shown regions, the dock included, and has a case with a 4-row stand-in dock. Inc 10's tab list follows R-TUI-063.3 as merged (Patch script, Inspector, JSON, Checks). The two increments merge in either order; whichever merges second rebases and owns the retarget of the shared test files (`test_tui_patch_layout.py`, `test_b97_patch_editor.py`, `test_tui_patch_editor_v2.py`). Inc 10's records are not edited here; the orchestrator carries this into P-020.
