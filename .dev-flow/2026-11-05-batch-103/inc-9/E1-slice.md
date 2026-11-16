# Inc 9 — E1 slice: the files and functions to add or change, counted and mapped

Base `593d56a4`; every line number is "as of `593d56a4`". Rows: `01-requirements.md`. The slice follows the recommended options of `E1-rulings.md` §3 (D-1 A … D-11 A) and the Inc 8 changes of §4. Callers: Code-Wire `v3.1.0-8-gb6cd30d` (`git -C C:\Users\<user>\Github\code-wire describe --tags`), core only — `tools/codewire_marks.py` then `tools/codewire_extract.py` on a throwaway one-commit copy of `git archive 593d56a4 s19_app` outside every work tree (`evidence-e1/cw-census.sh`, context graph `evidence-e1/cw-census-graph.md`, output `evidence-e1/cw-census-extract.json`, `cw-census-diff-report.md`, transcript `cw-census-transcript.txt`: 12 marks, 6 calls, 6 findings, exit 1; the 6 findings are the context graph's loose signatures — it carries no prototype). **Inc 8's final design (E3R1 `d9f93b47`, E3R2 `de4f462f`, E3 closed `d5d48685`; `../inc-8/E3-rulings.md`) is the seam; Inc 9's E3R1 rewrote every dependency to its final form (`E3-rulings.md` §E3R1 corrections).** **Inc 8 is designed, not built:** its nodes have no code at the base, so their callers are read from `../inc-8/codewire/graph-inc8.md` (G) and the textual dispatch is read (R).

## 1. Groups and files (D-11 A: three groups, none over 4 files)

| Group | Files | Rows |
|---|---|---|
| **B — the bench (new modules)** | new `s19_app/tui/definition_bench.py` (pure model: grid, cursor, window, tools, edit, row cells; I-2 and the standard library only); new `s19_app/tui/definition_bench_view.py` (pure render: rich `Text` lines); new `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py` (`ArrayBenchSheet(StagingSheet)`, the workers) | R-PE-BENCH.3 … .7, .9 … .67, .90 … .93 (the `-bench` class for Inc 8's R-PE-DEF.1.2) |
| **A9 — staging (added functions in Inc 8 files)** | `s19_app/tui/services/change_service.py` (+ `stage_record`); `s19_app/tui/app/patch.py` (+ the record-stage handler) | R-PE-BENCH.70 … .83 |
| **I — integration lines (Inc 8 files, after Inc 8 merges)** | `screens_directionb/patch_editor/panel.py` (C-1); `screens_directionb/patch_editor/layout.py` (C-4: the clause ` · arrays open the bench`). Both are **named exceptions** to the seam rule "Inc 9 may only add functions, modules and I-8.5 keys" (E3R1, E3A-08), one line each, owned by Inc 9's integrator. The `-bench` CSS rule is Inc 8's (P12'); the `_KIND_OPS` keys come from B23's `register_bench_kinds()`. | R-PE-BENCH.1, the seam |

**Totals (after E3R1):** 3 new modules, 4 changed Inc 8 files (A9 2 with added functions, I 2 with one line each), in 3 groups (B 3, A9 2, I 2). The PLAN guessed 2 (an editor widget module, `screens_directionb.py`); the package split and Inc 8's design spread the editor over several modules, and the pure model and render are kept apart from the widget so the ~40 cell and tool rules are tested without Textual. **Not changed:** `patch_editor/actions.py` (Inc 10's), `entries.py`, `document.py`, `checks.py`, `a2l_picker.py`, `shared.py`; `a2l_definition.py` (I-2, read only); `a2l_parameter_picker.py`; `changes/*`; every Inc 8 function outside §4 of the rulings.

**Build order (D-11 A):** group B's two pure modules can be built in parallel with Inc 8's E4 (they import I-2 and Inc 8's pure `definition_sheet.py` helpers only — **their tests need Inc 8's `definition_sheet.py`**, so they run once it exists on the E4 branch); `bench_sheet.py`, group A9 and group I subclass or call Inc 8 code and build on Inc 8's merged branch. **E3R1 (E3A-10):** B1 and B2 start only after Inc 8's E4 integrator confirms the Inc 8 data names they read (listed in `codewire/graph-inc9.md` §Interfaces, "Inc 8 names Inc 9 reads"), or the orchestrator pins them in I-8.5 as read-only data.

## 2. Function map

Counts (after E3R2, against Inc 8's final records): **46 new functions** (45 after E3R1; E3R2 added `ArrayBenchSheet.record_done`, R2-01) — group B 44 (15 model, 9 render, 20 widget; an entry that names two functions counts two) and group A9 2 — and **2 changed Inc 8 functions** (C-1, C-4; the named exceptions). E3R1 added `bench_mark` (E3A-05), `ArrayBenchSheet.check_action` (E3A-09) and `ArrayBenchSheet.record_staged` (E3A-03), renamed `stage_values` to `stage_record` (E3A-03), folded `_record_stage_done` into the record-stage handler (E3A-03, E3S-03), and dropped the Inc 8 nodes I4 and I6 (E3A-08). Graph: 48 prototype nodes after E3R2, one per function (D-10). Each entry is tagged with its split side (9a *see* / 9b *edit*, D-10 B).

### Group B — `s19_app/tui/definition_bench.py` (new, pure)

| # | Function | Side | Rows |
|---|---|---|---|
| B1 | `Grid` (frozen dataclass: mode `chart`/`grid`, nx, ny, count) and `bench_grid(definition) -> Grid` | 9a | R-PE-BENCH.30, .31 |
| B2 | `BenchValues` (compact: `array('d')` numbers, texts only for text elements, a no-value set) and `BenchValues.from_decoded(decoded) -> BenchValues` | 9a | R-PE-BENCH.14, .26 |
| B3 | `BenchState` (frozen dataclass: cursor, anchor, tool, edit, undo, window origin, … — the full field list in the graph; no `room`, which is `KindOps.detail`'s 5th argument, E3A-01) and `move_cursor(state, grid, dx, dy, extend) -> BenchState` | 9b | R-PE-BENCH.41, .42 |
| B4 | `page_cursor(state, grid, rows, direction) -> BenchState` | 9a | R-PE-BENCH.43 |
| B5 | `window_for(state, grid, rows_shown, cols_shown) -> tuple[int, int]` | 9a | R-PE-BENCH.36 |
| B6 | `selection_cells(state, grid) -> list[tuple]` (positions in element order) | 9b | R-PE-BENCH.50 … .56 |
| B7 | `where_text(state, grid) -> str` | 9b | R-PE-BENCH.42, .50 |
| B8 | `parse_operand(text) -> float \| None` | 9b | R-PE-BENCH.62 |
| B9 | `apply_tool(definition, state, grid, values, operand) -> BenchState \| str` (a status text on refusal) | 9b | R-PE-BENCH.51 … .56, .58, .63 … .65 |
| B10 | `result_text(definition, value) -> str` | 9b | R-PE-BENCH.57 |
| B11 | `undo(state) -> BenchState \| str` | 9b | R-PE-BENCH.59, .61 |
| B12 | `bench_cells(row, state, widths) -> tuple[Text, Text, Text, Text, Text]` — the `KindOps.cells` entry (K-2, pinned in Inc 8 I-8.5): Kind, Current, New, Limits, Δ | 9a | R-PE-BENCH.10 … .17, .19 |
| B12a | `bench_mark(row, state) -> str` — the `KindOps.mark` entry (the additive I-8.5 field of E3A-05, entering Inc 8 at its E4): `◆` while the state's bench edit is not empty, `●` while the row is staged, else a space | 9b | R-PE-BENCH.18, .79 |
| B13 | `summary_strip(values, grid, width) -> Text` | 9a | R-PE-BENCH.11, .19 |
| B13a | `bench_preview(definition, a2l_data, text, overlay) -> Preview` — the `KindOps.preview` entry: a `Preview` with no result (the bench previews off the thread, B33) | 9b | R-PE-BENCH.66 |

### Group B — `s19_app/tui/definition_bench_view.py` (new, pure)

| # | Function | Side | Rows |
|---|---|---|---|
| B14 | `bench_detail(row, preview, width, state, room) -> list[Text]` — the `KindOps.detail` entry (K-1 as pinned in Inc 8 I-8.5: `room` is the 5th argument): definition line (Inc 8's pinned `_FALLBACK_OPS.detail(row, None, width, None, 1)[0]`, E3A-10), canvas or the decoding line, window line, legend, tool row, bytes line, cut to `room`; under the bench minimum width the definition line only | 9a | R-PE-BENCH.3, .5, .7, .21 |
| B15 | `grid_canvas(definition, grid, values, staged, state, width, room) -> list[Text]` | 9a | R-PE-BENCH.31 |
| B16 | `chart_canvas(definition, grid, values, staged, state, width, room) -> list[Text]` | 9a | R-PE-BENCH.30 |
| B17 | `axis_labels(definition, decoded_axes, grid) -> tuple[list[str], list[str]]` | 9a | R-PE-BENCH.32, .33 |
| B18 | `legend_line(definition, grid, values, state) -> Text` | 9a | R-PE-BENCH.34 |
| B19 | `tool_row(tool) -> Text` | 9b | R-PE-BENCH.35 |
| B20 | `window_line(grid, origin, rows_shown, cols_shown) -> Text \| None` | 9a | R-PE-BENCH.37 |
| B21 | `bytes_line(definition, runs, preview, width) -> Text` (E3R1, E3S-06: formats the diff runs stored at `_job_done`; was `image_record`) | 9b | R-PE-BENCH.29, .38, .39 |
| B22 | `op_line(row, state, width) -> tuple[str, Text]` — the name with its `<where>` and the tail; reaches the formula bar through K-3 (the `KindOps.bar` field pinned in Inc 8 I-8.5) | 9b | R-PE-BENCH.50, .66, .93 |

### Group B — `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py` (new widget)

| # | Function | Side | Rows |
|---|---|---|---|
| B23 | `ArrayBenchSheet(StagingSheet)`: `BINDINGS` (shift+arrows, pageup, pagedown, s, d, p, i, m, u, escape, alt+s) and `check_action(action, parameters)`, which returns False for `cursor`, `page`, `tool`, `leave_bench` unless the selected row's state has the bench focus, and for `stage_record` unless the bench or a bench row's op input has the focus, so Textual skips the binding and the key reaches the app (E3A-09); messages `BenchApplyRequested(name, text)`, `RecordStageRequested(name, definition, count, outcome, generation)` (E3A-03); and `register_bench_kinds()` — sets the three `_KIND_OPS` entries at import, by assignment only (idempotent, E3A-14) | 9b | R-PE-BENCH.42 … .49, the seam |
| B23a | `bench_submit(name, text) -> Message` — the `KindOps.submit` entry: `BenchApplyRequested(name, text)` | 9b | R-PE-BENCH.51 |
| B24 | `ArrayBenchSheet.action_edit` (override: bench row → bench focus; else `super()`) | 9b | R-PE-BENCH.40 |
| B25 | `ArrayBenchSheet.action_move`, `action_choose` (overrides: in bench focus → `move_cursor`; else `super()`) | 9b | R-PE-BENCH.41 |
| B26 | `ArrayBenchSheet.action_cursor(dx, dy)` (shift+arrows) and `action_page(direction)` | 9b | R-PE-BENCH.42, .43 |
| B27 | `ArrayBenchSheet.action_tool(key)` (`s d p i m`; `u` undoes) and `action_leave_bench` (Escape) | 9b | R-PE-BENCH.44, .46, .59, .61 |
| B28 | `ArrayBenchSheet.action_stage_record` (still decoding → .27; empty edit → .75; else a "record" bench job, B33) | 9b | R-PE-BENCH.48, .75, .27, .82 |
| B29 | `ArrayBenchSheet.on_array_bench_sheet_bench_apply_requested` (the tool apply, then the preview job) and `_on_formula_escape` (override: bench row → bench focus; else `super()`) | 9b | R-PE-BENCH.47, .51, .27 |
| B30 | `ArrayBenchSheet.on_staging_sheet_selection_changed` (its own message: a row already selected keeps its state; else the bench state of the lifetime rule (E3A-11) and the decode job; a deselected row of more than 4,096 elements drops its values; `-bench` on the panel ancestor) | 9a | R-PE-BENCH.3, .9, .20, .26, Inc 8 R-PE-DEF.1.2 |
| B31 | `ArrayBenchSheet.show_page(names, definitions, a2l_data, image)` (override with Inc 8's final signature, all four passed to `super()`, E3A-02; then the page summary jobs) | 9a | R-PE-BENCH.9, .12, .13, .23, .24 |
| B32 | `ArrayBenchSheet.set_document` (override: `super()`, the sheet generation +1 (E3S-04; a view counter beside it for page and selection), then the selected row's decode and the staged jobs for the page rows whose span holds an entry byte) | 9a | R-PE-BENCH.25, .78 |
| B33 | `ArrayBenchSheet._run_job(kind, name, generation, …)` — the one bench worker (E3S-03): decode, summary, staged, preview and record jobs, at most one running, with the page A2L `self.a2l_data` (E3A-02); E3R2 (E3S-06): the worker also computes the whole-object work of its result (diff runs, finite lo/hi, strip, `axis_labels`) and posts it with the result | 9a | R-PE-BENCH.20, .23, .25, .28, .29, .66, .82 |
| B34 | `ArrayBenchSheet._job_done(kind, name, generation, result, derived)` — on the UI thread, assignment only (E3R2, E3S-06): a stale job is dropped (a record job: the R-PE-BENCH.78 status) and the next job starts; a fresh record result posts `RecordStageRequested(…, edit)` and starts nothing until `record_done` (E3R2, R2-01); else the result and its derived work are assigned and the next waiting job starts | 9a | R-PE-BENCH.21, .22, .24, .29, .66, .78 |
| B35 | `ArrayBenchSheet.record_staged(name, edit)` — after a record stage wrote the document, clears the row's bench edit and undo stack only while the edit still equals the staged `edit` (E3R2, R2-02) | 9b | R-PE-BENCH.79 |
| B36 | `ArrayBenchSheet.record_done(name)` — new at E3R2 (R2-01): called by A2 on every branch, after the write or a refusal; resumes the bench worker, so the next record job's snapshot and generation follow the write | 9b | R-PE-BENCH.28, .70 |

### Group A9 — staging (added functions in Inc 8 files)

| # | Function | File | Side | Rows |
|---|---|---|---|---|
| A1 | `ChangeService.stage_record(name, encoded, count) -> ChangeActionResult` (new, E3R1 E3A-03, replaces E1's `stage_values`; the UI thread only: `_stage_encoded(name, encoded, shown=f"{count} {word}")` (I-8.2) plus the notices of R-PE-BENCH.73 in `ChangeActionResult.notices`; no encode, no image) | `services/change_service.py`, after Inc 8's `stage_definition` | 9b | R-PE-BENCH.70, .72, .73, .80, .81 |
| A2 | `PatchMixin.on_array_bench_sheet_record_stage_requested(event)` (new; the UI thread, after the bench's record job: `_refuse_if_busy()` (the I-8.2 stage seam; checked when the encode ends, E3S-04), no A2L, the generation still the sheet's, the re-describe compared with `Definition ==` (E3A-02), a refused encode, then `stage_record`, `_report_change_result`, `note_staged(name, advance=False)` (C-8), `sheet.record_staged(name, event.edit)`, `_refresh_patch_history_view`; every branch ends with `sheet.record_done(name)` (E3R2, R2-01, R2-02). E3R1 folds E1's `_record_stage_done` into it) | `app/patch.py`, beside Inc 8's `on_staging_sheet_stage_requested` | 9b | R-PE-BENCH.6, .74, .76 … .80, .83 |

### Changed Inc 8 functions (the two named exceptions, E3R1 E3A-08)

| # | Function (Inc 8 node) | Change | C |
|---|---|---|---|
| I1 | `PatchEditorPanel.__init__` | builds `ArrayBenchSheet` | C-1 |
| I3 | `LayoutMixin.compose` | appends ` · arrays open the bench` to Inc 8's `enter edit · ↑↓ row` (C-4 split by Inc 8 E3R2 E3A-15) | C-4 |

Each is one line, applied by Inc 9's integrator after Inc 8 merges, and is a sanctioned exception to the seam rule "Inc 9 may only add functions, modules and I-8.5 keys" (`E1-rulings.md` §E3R1 corrections). Made by Inc 8 and no longer Inc 9 changes (E3A-08): `row_kind` / `_KIND_OPS` (C-3), `_stage_encoded(name, encoded, shown)` (C-7), the layout word in the definition line (C-6, Inc 8 S10' `detail_lines`; E1's node I4 removed), `note_staged(name, advance)` (C-8, Inc 8 P7'; E1's node I6 removed), and the `-bench` CSS rule (C-5, Inc 8 P12'; Inc 9's sheet only sets the class). The `KindOps` fields K-1 (`detail(row, preview, width, state, room)`), K-2 (`cells`), K-3 (`bar`) are pinned in Inc 8's I-8.5; the field `mark` (E3A-05) enters Inc 8 at its E4 integration (one optional field and one call site in `row_line`, recorded in Inc 8's records by the orchestrator). Interface additions, not Inc 9 nodes.

The `_KIND_OPS` keys are set by B23's `register_bench_kinds()`.

## 3. Callers read (rule 8: read before you write)

From `evidence-e1/cw-census-extract.json` (C), with sites the extractor files as top-level read back to their function (R), and Inc 8's designed callers from its graph (G):
- **I-2 `decode_values`, `encode_values`, `element_name`:** no product caller at the base (C: only I-2-internal sites, `encode_values` → `decode_values` `a2l_definition.py:4291`). B2/B33 (the record encode included, E3R1) and B7 are the first product callers. `display_text` is called by `decode_values` (C) and by B10's oracle only through I-2's rule; Inc 9 calls it for value texts it builds.
- **`describe_definition`** → `describe_definitions` (`a2l_definition.py:608`, C); product callers: Inc 8's `on_staging_sheet_stage_requested` (G). A2 adds one (the re-describe of R-PE-BENCH.77).
- **`describe_definitions`** ← `A2LParameterPicker.set_parameters` (`a2l_parameter_picker.py:608`, C); since Inc 8's E3R1 (E3A-04) the sheet's page definitions come from that population describe, and since its E3R2 (E3A-13) with the page A2L it used (`A2LParameterPicker.definitions_source`). B31 calls `super().show_page(names, definitions, a2l_data, image)` and adds no describe.
- **`PatchEditorPanel.__init__`** ← `app/compose_screens.py:540` (C). I1 changes the class it builds; no caller changes.
- **`ChangeService._push_history`** ← 7 sites (`change_service.py:1247`, `:1321`, `:1363`, `:1393`, `:1522`, `:1585`, `:1650`, C) and Inc 8's `_stage_encoded` (G). A1 reaches it through `_stage_encoded` only.
- **`PatchMixin._report_change_result`** ← `on_patch_editor_panel_action_requested` (`app/patch.py:193`, `:214`, `:250`, `:262`, `:1499`, C), `:417`, `:862`, `:987` (R) and Inc 8's handler (G). A2 adds one.
- **`PatchMixin._refresh_patch_history_view`** ← `:727` (undo), `:762` (redo), `:1001` (per-entry JSON edit) (C, R) and Inc 8's handler (G). A2 adds one.
- **Inc 8's `StagingSheet` methods** (G, no code): `show_page(names, definitions, a2l_data, image)` ← `A2lPickerMixin._on_a2l_parameter_picker_view_changed` (4 positional arguments, Inc 8 E3R2); `set_document` ← `PatchEditorPanel.refresh_entries` and `.set_image_mem_map`; `select_after(name)` ← `note_staged`; `action_*` ← textual bindings; `on_input_*` ← textual dispatch. B24 … B32 override the overridable ones of I-8.4; every caller keeps calling the same name, and the overrides call `super()` for every row that is not a bench row.
- **Inc 8's `_stage_encoded(name, encoded, shown)`** ← Inc 8's `stage_definition` (G). A1 adds one; its signature is Inc 8's (C-7), unchanged by Inc 9.
- **Inc 8's `note_staged(name, advance)`** ← Inc 8's `on_staging_sheet_stage_requested` (G). A2 adds one with `advance=False`.
- **App bindings Inc 9 shadows while the bench has the focus** (R `app/core.py:164-235`): `s` (save_project), `d` (a2l_describe_tag), `p` (load_project), `pageup` / `pagedown` (page_*_context) — all without priority, so a focused widget's binding wins; the priority ones (`ctrl+k`, `ctrl+d`, `ctrl+l`, `ctrl+s`) stay live. Off the bench, B23's `check_action` turns the bench bindings off, so these keys reach the app (E3R1, E3A-09, R-PE-BENCH.49).

Tests that pin today's behaviour: none of Inc 9's rows changes a behaviour that exists at the base. Inc 8's own records already retarget its curve no-editor case (R-PE-DEF.36, C-9) and its next-row move to formula-bar stages (R-PE-DEF.60, C-8).

## 4. What Inc 9 does not touch

Inc 8's "must not touch" list (`../inc-8/E1-slice.md` §4, final): `StagedOverlay`, `ops_for`, `_FALLBACK_OPS`, `build_row`, `value_text`, `preview`, `delta_text`, `limits_cell`, `row_line`, `header_line`, `sheet_widths`, `row_window`, `formula_fill`, `plain`, `name_echo`, `clip`, `_definition_line`, `StagingSheet.on_input_submitted`, `select_after`, `_paint`, `ChangeService.stage_definition`, `_stage_encoded`, `PatchMixin.on_staging_sheet_stage_requested`, and every group P function except the two named exceptions I1 and I3. Inc 9 calls Inc 8's pieces `_FALLBACK_OPS.detail` (the definition line), `plain`, `name_echo` and `short_number` and never redefines them; the data names it reads are listed, with their types, in `codewire/graph-inc9.md` §Interfaces (E3A-10).

## 5. E4 addenda (E3R1: the MINOR findings of E3, ruled to E4)

- **E3A-12:** add `status: str | None` to `BenchState` for a refusal's text and keep `job` for the job kind; `apply_tool` (B9) and `undo` (B11) return one form, `BenchState`, never `BenchState | str`.
- **E3A-13:** every timing AT (R-PE-BENCH.20/1, .82/1, R-PE-DEF.12's page paint through R-PE-BENCH.23/2, and the new .29/1) is decided on a quiet host, with `uptime` recorded beside the median; a loaded run is a record, not a verdict (HT-08).
- **E3S-07:** add the masked-array case (a UWORD VAL_BLK `MATRIX_DIM 2` with `BIT_MASK 0x0FF0`, a raw equal-span entry, Apply then Remove, a bench Set on (0,) and a record stage → the bits outside the mask equal the source view's; negative control: the live map → the applied bits return). In the record-stage handler (A2), refuse when `encoded.address != definition.address` or `len(encoded.data) != definition.byte_length`, with the status `Patch Editor: <name echo> encoded outside its span — nothing staged.` and a mutant case.
- **E3S-08:** A2, the apply handler `on_array_bench_sheet_bench_apply_requested` and `_run_job` log nothing of the operand, the edit or the values (at most the object name echo and the job kind); a `caplog` case: an apply and a stage of operand `12345` → `12345` is in no log record.
- **E3A-14, E3S-09:** no action (E3A-14's idempotent registration is already in B23).
- **R2-03 (E3R2):** `record_staged` and `record_done` are no-ops for a name with no state (a page turn during a held record encode drops the row's state; the record job is not dropped). Case: a page turn during a held record encode → staged, no exception.
- **R2-04 (E3R2):** `set_document` requests the selected row's current decode only when the image argument changed (an image push), and its staged decode only when the row's span holds or held an entry byte. After the operator's own record stage of LARGE, no current decode is queued (efficiency only; memory stays bounded by the one worker).
