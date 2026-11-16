# Inc 10 — E1 slice: the files and functions to change, counted and mapped

Base `e07fb00`. **Rebased at E2 (2026-11-12) to `287b9dc3`** (branch `b103-inc10` = `batch-103` with batch-101 Inc 9 / 10a / 12 merged, batch-103 Inc 6 and Inc 1b's E5 work): §2 and §3 give each line as `e07fb00` → `287b9dc3`; §5 is the rebase census and its meaning check. Rows: `01-requirements.md`. The slice follows the ruled options — D-1 A (docked bar) and D-2 A (start from the loaded image's format) by the operator at G2, the rest by the orchestrator — D-3 A (Width hidden, place kept), D-4 A (apply line, notice only when nothing applied), D-5 A (the before/after control moves with the prompt), D-6 A (open code changes stay open); §4 gives the delta of the options not chosen. Callers: Code-Wire v3.1.0 (`git -C C:\Users\<user>\Github\code-wire describe --tags` = `v3.1.0`), `codewire_extract.py` on a throwaway copy of `e07fb00`'s `s19_app/` with `# node:` marks (never in a work tree), the method of Inc 1b's census: `evidence-e1/cw-callers-census.py`, its context graph `evidence-e1/cw-callers-census-graph.md` and its output `evidence-e1/cw-callers-census-transcript.txt` (sites mapped back to `e07fb00` lines; the 14 `graph_examples_missing` findings and the one `output_type_mismatch` on the `SaveBackDecision` constructor node are expected — the context graph carries no examples and gives constructors no return type). Callers inside textual 8.2.8 (compose, message dispatch) are outside the repo and the extractor; they are read (R).

**Re-mapped (relevo-8, 2026-11-13) to `a95d0ea9`** (`b103-pe-split`: batch-modular `2dbd7d5a` + the `patch_editor` mixin split). §1, §2, §3 and §6 now give each function's module and lines at `a95d0ea9`; the `e07fb00` and `287b9dc3` lines they replaced, the census and the scope changes are §7. §4 and §5 are kept as written (history).

## 1. Summary

At `a95d0ea9` (re-map, §7). Paths are under `s19_app/tui/`; `patch_editor/` = `screens_directionb/patch_editor/`.

| File | Functions | Rows |
|---|---|---|
| `patch_editor/panel.py` (`PatchEditorPanel`) | changed: `__init__`, `SaveBackDecision.__init__`; new: the constant `SAVEBACK_FORMATS` | R-PE-EXPORT.7, .8, .9, .14, R-HEX-SAVE-001.1, R-HEX-VERIFY-001.1 |
| `patch_editor/actions.py` (`ActionsMixin`) | changed: `_compose_action_bar`, `_compose_doc_controls` (the dock, I-8.3), `on_button_pressed`, `show_save_prompt`; new: `_set_saveback_format` | R-CHG-003.1, R-PE-EXPORT.1, .2, .4, .7 … .15, R-TUI-063.1, R-TUI-049.1, R-S19-WIDTH-001.1 |
| `app/patch.py` (`PatchMixin`) | changed: `on_patch_editor_panel_action_requested` (the `apply_doc` arm and, since E3-1, the `add_entry`, `edit_entry`, `remove_entry` arms), `on_patch_editor_panel_save_back_decision`, `_apply_entry_json_edit` (E3-1) | R-CHG-003.1, R-PE-EXPORT.3 … .7, R-HEX-SAVE-001.1, .2, R-S19-SAVE-REUSE-001.1, R-S19-S0HEADER-001.1 … .3, R-S19-EMIT.11, R-PE-EXPORT.16, R-HEX-VERIFY-001.1, R-PE-EXPORT.17 |
| `styles.tcss` | changed: the save-back rules of the `/* batch-97 patch_editor */` section (`:2998`, `:3011`, `:3146-3152`, `:3159-3167`), one new rule for the dock container | R-PE-EXPORT.1, .2, .12, R-TUI-063.1, R-TUI-064.1, .2, .4 |
| `changes/io.py` (E3-2) | changed: `emit_intel_hex_from_mem_map` (the row loop, `:1996-2004`) | R-HEX-EMIT-001.11 (and R-HEX-EMIT-001.3, R-S19-SAVE-REUSE-001.1, R-PE-EXPORT.16 hold) |
| `changes/apply.py` (`_SAVE_BACK_EMITTERS`, `:103-106`) | **no change** (read; as at E1) | R-HEX-SAVE-001.1, .2, R-S19-SAVE-REUSE-001.1, R-PE-EXPORT.16 (read) |
| `patch_editor/layout.py` (`LayoutMixin.compose`) | **no change** (read): Inc 8 is its one writer (I-8.3 (a)) | R-TUI-063.1 (read) |

**Totals at `a95d0ea9` (re-map): 5 source files** — G1 `panel.py`, `actions.py`, `styles.tcss` (3, cap 4 per group), G2 `app/patch.py`, G3 `changes/io.py` — where E3 counted 4 (`screens_directionb.py` became two files of the package). 10 changed functions (`compose`'s design now lands in two helpers), 1 new function, 1 new class constant, ~4 CSS rules. Graph: 22 nodes (10 changed, 1 new, 11 context; `codewire/graph-inc10.md`). The 4-file cap of the skill is per worker group (dev-flow E0), and no group exceeds it.

The E1 and E3 totals (3, then 4 files, at `e07fb00` / `287b9dc3`) are in the history of this file and §7.

## 2. Function map

Lines at `a95d0ea9`; the `e07fb00` → `287b9dc3` lines of E1 and E2 are in §7.

| # | Function | File:line (`a95d0ea9`) | Change | Rows |
|---|---|---|---|---|
| 1 | `PatchEditorPanel.SAVEBACK_FORMATS` (new constant) | `panel.py`, beside `SAVEBACK_WIDTHS` (`:246`) | `(("s19", "S19", ".s19"), ("hex", "Intel HEX", ".hex"))`: the output formats in press order, their names and format suffixes; spelled locally, as `SAVEBACK_WIDTHS` is, so the view imports nothing from the engine | R-PE-EXPORT.8, .9, .14 |
| 2 | `PatchEditorPanel.__init__(self) -> None` | `panel.py:468-529` | **changed**: one attribute `_saveback_format: str` beside `_saveback_width` (`:496-499`), `"s19"` until a prompt sets it | R-PE-EXPORT.7, .8 |
| 3 | `PatchEditorPanel.SaveBackDecision.__init__(self, filename: Optional[str], bytes_per_line: int = 32) -> None` | `panel.py:332-337` (the class `:309-337`) | **changed** (I-10.2, E3-5): + `output_format: Optional[str] = None` (`"s19"` or `"hex"` on a confirm); the decline keeps `None` | R-HEX-SAVE-001.1, R-HEX-VERIFY-001.1 |
| 4a | `ActionsMixin._compose_action_bar(self) -> ComposeResult` | `actions.py:477-561` (called by `LayoutMixin.compose` inside `#patch_win_json`, `layout.py:67`) | **changed**: `#patch_saveback_row` (`:517-545`) and `#patch_before_after_row` (`:546-561`) leave it; the history strip, Undo/Redo and the execute row stay | R-CHG-003.1, R-TUI-049.1 |
| 4b | `ActionsMixin._compose_doc_controls(self) -> ComposeResult` | `actions.py:563-575` (called once by `LayoutMixin.compose`, `layout.py:77`, after the file row, before the legend) | **changed** (I-8.3 (a)): after `#patch_doc_controls` (`:565-575`), one `Container(id="patch_export_dock")` holding the two moved blocks, every shipped id and its `Container` type kept. The row gains the apply line (a `Static`, `markup=False`, empty) and the Format control (a `Button` labelled `Format: S19`) before the Width control; the name box, Width, `Write file`, `Don't save` keep their ids and labels | R-CHG-003.1, R-PE-EXPORT.1, .2, .4, .9, R-TUI-063.1, R-TUI-049.1 |
| 5 | `ActionsMixin.on_button_pressed(self, event: Button.Pressed) -> None` | `actions.py:64-226` | **changed**: a branch for the Format control → #6 (selector state only, no message, the Width idiom `:96-109`); the confirm branch (`:110-118`) adds `output_format=self._saveback_format` | R-PE-EXPORT.8, R-HEX-SAVE-001.1 |
| 6 | `ActionsMixin._set_saveback_format(self, output_format: str, rename: bool) -> None` (new; E2-1) | `actions.py`, after `show_save_prompt` | sets the format; relabels the Format control; shows the Width control for S19 and hides it for Intel HEX with its place kept (`visibility`, not `display`); when `rename`, replaces a final `.s19` / `.hex` (any case, with trailing whitespace, E3-6) of `#patch_saveback_name_input` with the new format suffix; keeps `_saveback_width` | R-PE-EXPORT.7 … .15 |
| 7 | `ActionsMixin.show_save_prompt(self, suggestion: str) -> None` | `actions.py:280-301` | **changed signature** (I-10.1): `show_save_prompt(self, suggestion: str, *, output_format: str, apply_line: str) -> None` — fills the name box (unchanged), resets the width to 32 (unchanged), `_set_saveback_format(output_format, rename=False)`, writes `apply_line` as a literal `Text` into the apply line, un-hides the row (unchanged) | R-CHG-003.1, R-PE-EXPORT.4, .7, .9 … .11, R-S19-WIDTH-001.1, R-HEX-VERIFY-002.3 |
| 8 | `PatchMixin.on_patch_editor_panel_action_requested(self, event) -> None` | `app/patch.py:94-316`; the `apply_doc` arm `:214-240`, the entry arms `:159-174` | **changed**: applied > 0 on an `s19` / `hex` image → `panel.show_save_prompt(f"{variant_id}-patched{suffix}", output_format=loaded.file_type, apply_line=<R-PE-EXPORT.4 text>)` (`:236`); applied == 0 → `panel.hide_save_prompt()` and one `notify(<R-PE-EXPORT.5 text>, title="Nothing applied", severity="warning")`; the status line unchanged; D8-17's unreachable `else` (`:237-240`) stays (D-6 A). E3-1: the `add_entry`, `edit_entry`, `remove_entry` arms call `panel.hide_save_prompt()` after the service call returns | R-CHG-003.1, R-PE-EXPORT.3 … .7, R-PE-EXPORT.17 |
| 9 | `PatchMixin.on_patch_editor_panel_save_back_decision(self, event) -> None` | `app/patch.py:318-456`; the write `:386-401` | **changed** (the write only): the kind is `event.output_format` when the loaded image is `s19` or `hex`, else the loaded kind; no fallback (E3-5); the S0 policy unchanged for an S19 output (`:389`) and `None` for Intel HEX; `source_kind=` (`:399`) takes that kind, which `ChangeService.save_patched` (`:394`) hands to both the write and the verify (`change_service.py:2624` → `:2444-2454`, `:2469`) | R-HEX-SAVE-001.1, .2, R-S19-SAVE-REUSE-001.1, R-S19-S0HEADER-001.1 … .3, R-S19-EMIT.11, R-PE-EXPORT.16, R-HEX-VERIFY-001.1 |
| 10 | `PatchMixin._apply_entry_json_edit(self, index: int, edited: Optional[str]) -> None` (E3-1) | `app/patch.py:937-999` | **changed**: `panel.hide_save_prompt()` after `_report_change_result` when the per-entry edit's result is ok | R-PE-EXPORT.17 |
| 11 | `emit_intel_hex_from_mem_map(mem_map, ranges) -> str` (E3-2) | `changes/io.py:1934-2006`, row loop `:1996-2004` (file identical to `287b9dc3`) | **changed** (about two lines): each row ends at `min(row_start + 16, end, (row_start \| 0xFFFF) + 1)` and the next row starts at the last row's end; signature unchanged (I-10.6) | R-HEX-EMIT-001.11 |
| — | `styles.tcss` save-back rules | `:2998`, `:3011`, `:3146-3152`, `:3159-3167` (file identical to `287b9dc3`) | **changed**: the selectors follow the moved rows; `#patch_saveback_buttons` becomes one row in the dock; one rule gives the dock `height: auto`; the region that yields the rows (`#patch_main` here, `#patch_sheet_win` after Inc 8) is not edited | R-PE-EXPORT.1, .2, .12, R-TUI-063.1, R-TUI-064.1, .2, .4 |

## 3. Callers read (rule 8: read before you write)

At `a95d0ea9`: the census `evidence-remap/i10-remap-census-transcript.txt` (call sites with their enclosing def, by `ast`) and the Code-Wire extractor `evidence-remap/i10-remap-extract-transcript.txt` (C). Every caller of E1 and E2 is the same call in its new module (§7); none was added or lost by the split.
- `show_save_prompt` ← `app/patch.py:236` only (the apply arm, #8). #7's new arguments have one caller to update (and the test `tests/test_tui_patch_layout.py:594`).
- `hide_save_prompt` (`actions.py:303-310`, unchanged) ← `app/patch.py:378` (the save-back decision) and `:527` (`_hide_replaced_document_controls`, `:498-527`, whose callers are `:190` parse-paste, `:724` `action_patch_undo`, `:759` `action_patch_redo`, `:1493` `_patch_editor_load`, `app/project_load.py:1045` `_reset_project_session`, `app/loaded_state.py:689` `_apply_prepared_load`). #8 and #10 add calls. After Inc 8, its stage handler is one more entry change (§7, F-R8-3).
- `_show_tab` (`panel.py:711-723`) ← `actions.py:88` (the tab chips). Unchanged.
- `SaveBackDecision(...)` ← `actions.py:112-117` (confirm) and `:121` (decline).
- `ChangeService.save_patched` ← `app/patch.py:394` only (#9). `ChangeService.emit_and_verify` ← `change_service.py:2624` (`save_patched`) only.
- `save_patched_image` ← `change_service.py:2444` (`emit_and_verify`), `app/save_commit.py:805` (`_save_project_files`, through `deps.`), `flow_execution_service.py:727` (`run_flow`), `variant_execution_service.py:2584` (`_execute_one_variant`). None changes.
- `render_patched_image` ← `apply.py:795` (`save_patched_image`), `app/save_plan.py:1145` (`_decide_project_image`, through `deps.`, `source_kind=loaded.file_type`). Unchanged.
- `_synth_s0_header_from_filename` (`app/patch.py:61-89`) ← `app/patch.py:389` only (#9).
- `PatchEditorPanel.__init__` ← `app/compose_screens.py:540` (`_compose_screen_patch`). `_compose_action_bar` ← `layout.py:67`; `_compose_doc_controls` ← `layout.py:77`; `LayoutMixin.compose`, `on_button_pressed` and the two `on_patch_editor_panel_*` handlers: toolkit compose and message dispatch (R).

Context nodes for E2 (read, not changed): `LayoutMixin.compose` (`layout.py:17-83`), `hide_save_prompt`, `show_before_after_prompt` (`actions.py:312-327`), `hide_before_after_prompt` (`actions.py:329-343`), `_hide_replaced_document_controls` (`app/patch.py:498-527`), `ChangeService.save_patched` (`change_service.py:2481`), `ChangeService.emit_and_verify` (`:2375`), `save_patched_image` (`apply.py:686`), `verify_written_image` (`changes/verify.py:119`), `_synth_s0_header_from_filename` (`app/patch.py:61-89`).

Tests that pin today's home of the prompt (E4 moves them; tests are not capped): `tests/test_b97_patch_editor.py:1419-1427` (and `CONTAINER_IDS` `:53-61`), `tests/test_tui_patch_layout.py:190-197` and AT-064c `:715-730`, `tests/test_tui_patch_editor_v2.py:302`, `:574`, `tests/test_b100_active_variant.py:1064`; `tests/b97_fixtures.py:95-120` (the frozen id set: Inc 10 removes no id). These three shared files are also Inc 8's (I-8.3 (e)): whichever increment merges second owns their retarget.

## 4. Delta of the other options (not chosen: G2 picked D-1 A and D-2 A; the orchestrator D-3 A and D-6 A; kept for the record)

- **D-1 B (Inspector card + switch):** #4 mounts the row at the top of `#patch_pane_inspector` instead of the dock; #8 also calls `_show_tab("patch_tab_inspector")` (one more caller of `_show_tab`); the CSS keeps the two-row grid (41 columns); R-TUI-063.1 unchanged. Same file count.
- **D-1 C (dialog):** a new `ModalScreen` class in `screens_directionb.py` (not `screens.py`, §7 of the rulings) with its `BINDINGS` (Escape, and the shown keys), `compose`, actions; #8 pushes it; #5's confirm and decline move into it; the before/after control still needs the dock of A (D-5). +1 class, +3–4 functions; same 3 files.
- **D-2 B (always ask):** #7 sets no format; #9 refuses a `None` format with the status of R-PE-EXPORT.18; #6 starts from "none". +0 functions.
- **D-3 B (disabled):** #6 sets `disabled` instead of `visibility`. **D-3 C (collapsed):** `display`; R-PE-EXPORT.12 dropped.
- **D-6 B:** #9 also keeps the source's S0 data at width 16 (D8-27) and builds the synthesized header from the written name (D8-28 — that name is known only after the placement, so the S0 is re-derived after `save_patched_image` picks a numbered name; E2 must check whether the write needs the name before it renders). **D-6 C:** + `changes/io.py` (`emit_s19_from_mem_map` gains a terminator address), `changes/apply.py`, `services/change_service.py` → 5 or 6 source files: over the cap, a split.

## 5. Rebase to `287b9dc3` (E2, 2026-11-12)

Census: `codewire/evidence-e2/i10e2-rebase-census.py` (read only: `git archive` of both commits into a scratch folder, `ast` per function, a regex for the call sites), transcript `codewire/evidence-e2/i10e2-rebase-census-transcript.txt`. Every line of §2 and §3 above was re-located from it.

**Files.** `styles.tcss`, `changes/apply.py`, `changes/verify.py`, `services/change_service.py` and `services/variant_execution_service.py` are byte-identical at both commits. `screens_directionb.py` changed (+45 lines above the save-back methods: batch-103 Inc 6's picker, batch-101 Inc 12's `CheckEditorPanel`), `app.py` changed (+378 lines above the Patch Editor handlers, from batch-101 Inc 9 / 10a / 12 and batch-103 Inc 1b's E5), `flow_execution_service.py` changed (`run_chain_set`, outside the slice; `run_flow` and its WRITE-OUT call at `:727` are identical).

**Meaning check.** Of the 8 slice functions and 21 context functions and callers, 25 have an identical AST at both commits. The four that differ:

| Function | What changed (and by whom) | Meaning for Inc 10 |
|---|---|---|
| `PatchEditorPanel.__init__` (#2) | the A2L picker built in `mode="pick"` with the include and bulk buttons (batch-103 Inc 6, R-PICKER-CORRECT.011) | none for the save-back attributes (`_saveback_width` moved one line, `:4839-4842`); #2's change is still one added attribute |
| `PatchEditorPanel.compose` (#4) | the A2L tab's `Use parameter` status gets `height: 3` and wraps (Inc 6); a comment | **layout only**: the A2L tab now holds the pick-mode picker with include and bulk controls and a 3-row status, so it needs more of `#patch_main`'s rows than at `e07fb00`. The dock takes 3 or 4 rows from `#patch_main` while shown; E1's census of `#patch_main` (35 rows at 118×54, 41 at 220×60) and of the A2L tab ran on `e07fb00`. Not a contract change; R-PE-EXPORT.2/4 and /8 (the A2L tab) must be measured on this base (E2 finding E2-4) |
| `S19TuiApp._reset_project_session` (a caller of `_hide_replaced_document_controls`) | resets the hex view-row memo (batch-101 Inc 10a, CR-1) | none: the call that hides the prompt (`:14714`) is unchanged |
| `S19TuiApp._apply_prepared_load` (a caller of `_hide_replaced_document_controls`) | rejects a stale bundle before any mutation and returns `bool`; `publish_a2l` (batch-101 Inc 9 / 10a) | none: a rejected bundle installs no image, so the prompt stays as it was, as when no load ran; an accepted one with a new image dict still hides it (`:19658-19659`) |

The functions Inc 10 changes — `on_button_pressed`, `show_save_prompt`, `SaveBackDecision.__init__`, `on_patch_editor_panel_action_requested`, `on_patch_editor_panel_save_back_decision` — and the engine path (`save_patched` → `emit_and_verify` → `save_patched_image` → `render_patched_image`, `verify_written_image`) have the same AST as at `e07fb00`: E1's reading of them holds. **No function body changed meaning for this increment.** One E1 caller claim was wrong at both commits and is corrected in §3 (`emit_and_verify` has no caller in `app.py`).

**Cap.** Still 3 source files (`screens_directionb.py`, `app.py`, `styles.tcss`); `changes/apply.py` is read only.

**Tests that pin the prompt's home** (§3's list, E4): unchanged at `287b9dc3` except `tests/b97_fixtures.py` (batch-101 Inc 12 dropped a Check Editor id; `PE_IDS_9C7BEAF` is untouched and is checked as a subset, `tests/test_b97_patch_editor.py:206-207`). Added at E2: `tests/test_tui_patch_layout.py:594` calls `show_save_prompt("out.s19")` with one argument (the signature changes, I-10.1), and `tests/test_before_after_report.py:1149`, `:1273` read `#patch_before_after_row` by id (they keep working wherever the row sits).

## 6. E3 correction (2026-11-12, `E3-rulings.md`)

**Files and groups for E4.** At E3, 4 source files (cap 4); re-mapped to `a95d0ea9` (§7), 5 source files in the same three groups, each group within the cap of 4 and each file with one owner group:

| Group | Files | Nodes |
|---|---|---|
| G1 panel | `s19_app/tui/screens_directionb/patch_editor/panel.py`, `s19_app/tui/screens_directionb/patch_editor/actions.py`, `s19_app/tui/styles.tcss` (re-map: `screens_directionb.py` became the package) | as at E2, with `compose`'s part now `ActionsMixin._compose_action_bar` and `_compose_doc_controls` (I-8.3) (`SaveBackDecision.__init__` loses the `"s19"` default, E3-5; `_set_saveback_format`'s rule takes trailing whitespace, E3-6) |
| G2 app | `s19_app/tui/app/patch.py` (re-map: `PatchMixin`) | `on_patch_editor_panel_action_requested` (`apply_doc` arm + the three entry arms, E3-1), `on_patch_editor_panel_save_back_decision` (no fallback, E3-5), `_apply_entry_json_edit` (E3-1) |
| G3 engine | `s19_app/tui/changes/io.py` | `emit_intel_hex_from_mem_map` (E3-2) |

**Callers read for the two new changed functions (rule 8; R, `git grep` at `287b9dc3`; re-mapped to `a95d0ea9` by the census, same calls).**
- `emit_intel_hex_from_mem_map` ← `render_patched_image` through `_SAVE_BACK_EMITTERS["hex"]` (`apply.py:105`, called `:682`; itself called by `save_patched_image` `:795` and `_decide_project_image` `app/save_plan.py:1145`), `segment_ops.emit_image` (`segment_ops.py:507`). Its output changes only for a range whose 16-byte rows from the range start would cross a 64 KiB boundary; so Save project, the flow WRITE-OUT and segment split / join write correct records there too (none of them is changed). Tests that call it (E4 runs them; G3): `tests/test_hex_emit.py` (`test_ela_record_emitted_per_upper16_change` uses 0x0001FFF0, 16-aligned: unchanged), `tests/test_segment_ops.py`, `tests/test_changes_apply.py`, `tests/test_verify_on_save.py`, `tests/test_b102_a2l_refresh.py`, `tests/test_tui_patch_editor_v2.py`.
- `PatchMixin._apply_entry_json_edit` ← the dismiss callback of `EntryJsonScreen`, pushed by `on_patch_editor_panel_entry_edit_json_requested` (`app/patch.py:930-934`) only.
- The three entry arms are the only callers of `ChangeService.add_entry`, `edit_entry`, `remove_entry` in `s19_app/` (`app/patch.py:160`, `:166`, `:172`); the A2L bulk add changes no document (`patch_editor/a2l_picker.py:120`, `A2lPickerMixin._on_bulk_add_closed`); the whole-document Edit JSON re-enters through `parse_paste`, which already hides the prompt (`app/patch.py:190`). After Inc 8, its stage handler (`PatchMixin.on_staging_sheet_stage_requested`, through `ChangeService._stage_encoded`) also adds or replaces an entry: §7, F-R8-3.

**Tests that may assume the prompt survives an entry change (E4, G2's tester).** The prompt now hides on Add, Edit, Remove and a per-entry JSON edit. Shipped files that both drive the prompt and change entries, to be read at E4 for a `Write file` after an entry change with no new Apply (R, `grep`): `tests/test_tui_patch_editor_v2.py`, `tests/test_b99_editor_image.py`, `tests/test_b100_save_image.py`, `tests/test_b100_load_question.py`, `tests/test_b101_designer_writes.py`, `tests/test_b101_patch_lifecycle.py`, `tests/test_b97_patch_editor.py`, `tests/test_tui_patch_layout.py`, and the others the grep lists (`test_b100_active_variant.py`, `test_b100_workers.py`, `test_b101_inplace_views.py`, `test_b99_*`, `test_before_after_report.py`). Such a test changes with this row; it is not a regression.

## 7. Re-map to a95d0ea9 (relevo-8)

**Base.** `a95d0ea9` = `b103-pe-split` tip: batch-modular `2dbd7d5a` (the `S19TuiApp` methods moved into `app/*.py` mixins) plus the `patch_editor` split (the `PatchEditorPanel` methods moved into `screens_directionb/patch_editor/*.py` mixins). The two Inc 10 record commits made on `287b9dc3` (E2 `23cfa1f5`, E3 `4a02073a`) were rebased onto it (`git rebase --onto a95d0ea9 287b9dc3 b103-inc10`; both touched only `.dev-flow/`; the E1 records were already identical at both bases).

**Evidence** (`evidence-remap/`, read only, throwaway trees outside every work tree, stdlib Python on the operator's PC: `ast` and `git archive` only, no test, no product import):
- `i10-remap-census.py` + transcript: each slice and context function located by qualname at both commits, with AST equality; the moved prompt blocks; every call site at `a95d0ea9` with its enclosing def; byte identity of the files the slice reads.
- `i10-remap-map.py` + transcript: each cited `287b9dc3` line mapped by its enclosing def and offset, with a check that the line's text is the same (the ruled exceptions are at the end of the transcript).
- `i10-remap-extract.sh` + transcript: the Code-Wire extractor (marks only in a throwaway clone at `a95d0ea9`) and the lint on the re-mapped graph.

**Census results.** Every function of the slice and of its context has the same AST at `a95d0ea9` as at `287b9dc3`, in its new module — except `PatchEditorPanel.compose`, which batch-modular split into `LayoutMixin.compose` and compose helpers; the three blocks Inc 10 cites (`#patch_saveback_row`, `#patch_before_after_row`, `#patch_doc_controls`) have the same AST inside `ActionsMixin._compose_action_bar` and `ActionsMixin._compose_doc_controls`. Three callers of the engine outside the slice changed only by batch-modular's `deps.` indirection (`_save_project_files`, `_decide_project_image`, `_activate_project_file`; same calls and arguments). `changes/io.py`, `changes/apply.py`, `changes/verify.py`, `services/change_service.py`, `flow_execution_service.py`, `variant_execution_service.py`, `segment_ops.py`, `hexfile.py` and `styles.tcss` are byte-identical. **No function body changed meaning for this increment.**

### 7.1 Old → new (moved verbatim: 8 of the 9 existing slice functions — all but `emit_intel_hex_from_mem_map` — and 5 of the 10 context nodes, 13 of the 20 E3 nodes; the new constant and the new function follow their class into `panel.py` and `actions.py`; the engine stays where it was)

`sdb` = `screens_directionb.py`, `pe/` = `screens_directionb/patch_editor/`, `app/` = `s19_app/tui/app/`. "same" = same AST.

| Slice # / node | `e07fb00` (E1) | `287b9dc3` (E2, E3) | `a95d0ea9` (re-map) | AST |
|---|---|---|---|---|
| #1 `SAVEBACK_WIDTHS` (beside it the new `SAVEBACK_FORMATS`) | `sdb:4585-4589` | `sdb:4589` | `PatchEditorPanel.SAVEBACK_WIDTHS`, `pe/panel.py:246` | same |
| #2 `PatchEditorPanel.__init__` (`_saveback_width`) | `sdb:4811-4871` (`:4838-4841`) | `sdb:4811-4872` (`:4839-4842`) | `PatchEditorPanel.__init__`, `pe/panel.py:468-529` (`:496-499`) | same |
| #3 `SaveBackDecision.__init__` (class) | `sdb:4675-4680` (`:4652-4680`) | same | `pe/panel.py:332-337` (`:309-337`) | same |
| #4 `PatchEditorPanel.compose` | `sdb:4930-5284` | `sdb:4931-5287` | split: `LayoutMixin.compose`, `pe/layout.py:17-83` (context, not edited, I-8.3); #4a `ActionsMixin._compose_action_bar`, `pe/actions.py:477-561`; #4b `ActionsMixin._compose_doc_controls`, `pe/actions.py:563-575` | DIFF (split) |
| — `#patch_saveback_row` block | `sdb:5114-5142` | `sdb:5115-5143` (block `:5118-5143`) | `pe/actions.py:517-545` (block `:520-545`), in #4a | same |
| — `#patch_before_after_row` block | `sdb:5143-5158` | `sdb:5144-5159` (block `:5145-5159`) | `pe/actions.py:546-561` (block `:547-561`), in #4a | same |
| — `#patch_doc_controls` block | `sdb:5268-5278` | `sdb:5271-5281` | `pe/actions.py:565-575`, in #4b | same |
| — `#patch_legend` | `sdb:5279-5284` | `sdb:5282-5287` | `pe/layout.py:78-83` | — |
| — compose docstring rule (ids keep `Container`) | `sdb:4939-4942` | `sdb:4940-4943` | `pe/layout.py:26-29` | — |
| #5 `on_button_pressed` (tabs; Width; confirm; decline) | `sdb:5896-6058` | `sdb:5941-6103` (`:5965`; `:5973-5986`; `:5987-5995`; `:5996-5999`) | `ActionsMixin.on_button_pressed`, `pe/actions.py:64-226` (`:88`; `:96-109`; `:110-118`; `:119-122`) | same |
| #6 `_set_saveback_format` (new) | — | after `show_save_prompt` | `ActionsMixin._set_saveback_format`, `pe/actions.py`, after `show_save_prompt` | — |
| #7 `show_save_prompt` | `sdb:6448-6469` | `sdb:6493-6514` | `ActionsMixin.show_save_prompt`, `pe/actions.py:280-301` | same |
| #8 `on_patch_editor_panel_action_requested` (apply arm; its prompt call; D8-17 `else`; entry arms) | `app.py:4734-4956` (`:4854-4880`; `:4876`; `:4877-4880`; —) | `app.py:5112-5334` (`:5232-5258`; `:5254`; `:5255-5258`; `:5177-5192`) | `PatchMixin.…`, `app/patch.py:94-316` (`:214-240`; `:236`; `:237-240`; `:159-174`) | same |
| #9 `on_patch_editor_panel_save_back_decision` (write; S0; `save_patched`; `source_kind`; hide; before/after) | `app.py:4958-5096` (`:5026-5041`; `:5029`; `:5034`; `:5039`; `:5018`; —) | `app.py:5336-5474` (`:5404-5419`; `:5407`; `:5412`; `:5417`; `:5396`; `:5457`) | `PatchMixin.…`, `app/patch.py:318-456` (`:386-401`; `:389`; `:394`; `:399`; `:378`; `:439`) | same |
| #10 `_apply_entry_json_edit` (E3-1) | — | `app.py:5990-6052` | `PatchMixin._apply_entry_json_edit`, `app/patch.py:937-999` | same |
| #11 `emit_intel_hex_from_mem_map` (E3-2) | — | `changes/io.py:1934-2006` | same lines (file identical) | same |
| CSS save-back rules | `styles.tcss:2998`, `:3011`, `:3146-3149`, `:3159-3167` | same | same (file identical) | — |
| ctx `hide_save_prompt` | `sdb:6471-6478` | `sdb:6516-6523` | `ActionsMixin.hide_save_prompt`, `pe/actions.py:303-310` | same |
| ctx `show_before_after_prompt` | `sdb:6480` | `sdb:6525-6540` | `pe/actions.py:312-327` | same |
| ctx `hide_before_after_prompt` | `sdb:6497` | `sdb:6542-6556` | `pe/actions.py:329-343` | same |
| ctx `_show_tab` | `sdb:5637` | `sdb:5682-5694` | `PatchEditorPanel._show_tab`, `pe/panel.py:711-723` | same |
| ctx `_hide_replaced_document_controls` | `app.py:5173-5202` | `app.py:5551-5580` | `PatchMixin.…`, `app/patch.py:498-527` | same |
| ctx `_synth_s0_header_from_filename` | `app.py:662-690` | `app.py:708-736` | module level, `app/patch.py:61-89` | same |
| caller `_compose_screen_patch` (`PatchEditorPanel()`) | `app.py:4686` | `app.py:5064` | `ComposeScreensMixin._compose_screen_patch`, `app/compose_screens.py:540` | same |
| caller parse-paste → `_hide_replaced_document_controls` | `app.py:4830` | `app.py:5208` | `app/patch.py:190` | same |
| caller `action_patch_undo` / `action_patch_redo` | `app.py:5399` / `:5434` | `app.py:5777` / `:5812` | `app/patch.py:724` / `:759` | same |
| caller `_patch_editor_load` | `app.py:7529`, call `:7546` | `app.py:7907`, call `:7924` | `PatchMixin._patch_editor_load`, `app/patch.py:1476`, call `:1493` | same |
| caller `_reset_project_session` | `app.py:14007` | `app.py:14714` | `ProjectLoadMixin.…`, `app/project_load.py:1045` | same |
| caller `_apply_prepared_load` | `app.py:18565` | `app.py:19658-19659` | `LoadedStateMixin.…`, `app/loaded_state.py:688-689` | same |
| caller `on_patch_editor_panel_entry_edit_json_requested` (pushes the dismiss callback) | — | `app.py:5983-5987` | `app/patch.py:930-934` | same |
| caller `_save_project_files` (`save_patched_image`; `verify_written_image`) | `app.py:12536` | `app.py:13217`; `:13229` | `SaveCommitMixin.…`, `app/save_commit.py:805`; `:817` | DIFF (`deps.` only) |
| caller `_decide_project_image` (`render_patched_image`) | `app.py:13264` | `app.py:13945` | `SavePlanMixin.…`, `app/save_plan.py:1145` | DIFF (`deps.` only) |
| `_activate_project_file` (E2-6) | — | `app.py:16149` | `ProjectsMixin.…`, `app/projects.py:1068` | DIFF (`deps.` only) |
| Inc 6's `Use parameter` status (E2-4) | — | `sdb:5235-5236` | `pe/a2l_picker.py:239-240` (`_compose_a2l_tab`) | — |
| A2L bulk add (E3 C-1) | — | `sdb:5485` | `pe/a2l_picker.py:120` (`A2lPickerMixin._on_bulk_add_closed`) | same |
| the docstring E2 cited for `emit_and_verify` | `app.py:6117` (at both) | `app.py:6117` | `app/patch.py:1064` (`_surface_verify_result`) | same |
| inspector tab chips | `sdb:4453-4458` | — | `PatchEditorPanel._TABS`, `pe/panel.py:110-115` | — |
| engine context (`save_patched`, `emit_and_verify`, `save_patched_image`, `render_patched_image`, `verify_written_image`) | as cited | as cited | same lines (files identical) | same |
| tests | — | `tests/test_b97_patch_editor.py:52-60`, `:206-207`, `:1418-1426` | `:53-61`, `:207-208`, `:1419-1427` (P3a added one import line at `:28`); every other cited test file is identical | — |

Any other line that E1-rulings, E2-rulings or E3-rulings cite inside one of these functions maps by the same offset (the function moved verbatim); `i10-remap-map.py` does it and checks the text.

### 7.2 Changes of scope

- **Files: 4 → 5 source files, same three groups.** `screens_directionb.py` is now `patch_editor/panel.py` (constant, `__init__`, `SaveBackDecision`) and `patch_editor/actions.py` (the compose helpers, the button handler, the prompt methods); G1 holds 3 files (cap 4), G2 `app/patch.py`, G3 `changes/io.py`. No function entered or left the slice.
- **`compose` → two helpers, `layout.py` untouched.** E2's one changed node `PatchEditorPanel.compose` is now two changed nodes, `ActionsMixin._compose_action_bar` (the two blocks leave) and `ActionsMixin._compose_doc_controls` (the dock is yielded after `#patch_doc_controls`, Inc 8's I-8.3 (a)), plus one context node, `LayoutMixin.compose`, which Inc 10 never edits (Inc 8 is its one writer). Changed functions 9 → 10; graph 20 → 22 nodes.
- **The region that yields the dock's rows** is `#patch_main` at `a95d0ea9` and `#patch_sheet_win` (`min-height: 12`) after Inc 8 (I-8.3 (b)); Inc 10 edits neither rule. The tab list follows R-TUI-063.3 on the E4 base (I-8.3 (d)).
- **Requirement rows**: no sentence, id or new row; four thresholds or statuses (R-CHG-003.1, R-TUI-063.1, R-PE-EXPORT.2, R-PE-EXPORT.17) and the *inspector tabs* definition, with reasons in `E1-rulings.md`, "Re-map to a95d0ea9 (relevo-8)". Cases 128 → 130 (R-PE-EXPORT.2/11, R-PE-EXPORT.17/5).
- **Shared with Inc 8 (D-8 A / I-8.3)**: `panel.py` (Inc 8 edits `_TABS`, `__init__`, `_show_tab`, …; one adjacent attribute line in `__init__`), `styles.tcss` (disjoint blocks), `app/patch.py` (Inc 8 adds `on_staging_sheet_stage_requested`; Inc 10 edits three other functions), and the test files of I-8.3 (e). `actions.py`: Inc 10 only. `layout.py`: Inc 8 only.

### 7.3 I-8.3 fit (dock height against Inc 8's stand-in)

Inc 10's dock (`#patch_export_dock`, `height: auto`, no frame) at 118×54 and 220×60, from the graph's layout entity (D: the rows' CSS heights; measured at E4 by R-PE-EXPORT.2/11):

| State | Rows shown in the dock | Height |
|---|---|---|
| no apply yet, or after `Don't save` / an entry change / a load | none | 0 |
| after an apply (the prompt) | apply line (1: 85 to ~94 cells inside 112 at 118 columns), name row (1), buttons row (1) | 3 |
| after `Write file` | the before/after row (1, E2-13) | 1 |
| after `Write file`, then Apply again (prompt and before/after both shown: an apply never hides the before/after row) | 3 + 1 | **4** |

**Verdict: fits.** Inc 10's largest dock is 4 rows, equal to the 4-row stand-in of Inc 8's R-PE-DEF.1.1/3 and R-PE-DEF.74/2; no mismatch at either size. Derived margin (D, from E1's census at `e07fb00`: `#patch_main` 35 rows at 118×54): after Inc 8 the same 35 rows hold the filter row (1), the landing pane (9) and the sheet window, so the sheet keeps 35 − 1 − 9 − 4 = 21 ≥ 12 rows with the largest dock. Not covered by either stand-in, and so a note for both increments, not a mismatch: under 118 columns the apply line wraps (5 rows), and the open operator items O-1 (B′ text with a file name), O-3 (a format line) and O-5 (a frame) would make the dock 5 to 6 rows (§7.4).

### 7.4 Findings of the re-map (for the orchestrator; Inc 8's records are not edited here)

- **F-R8-1 (fit, both increments; no action).** §7.3. Inc 10's R-PE-EXPORT.2/11 measures the 4-row dock and records its height; if E4 measures more than 4, Inc 8's R-PE-DEF.1.1/3 and R-PE-DEF.74/2 need the larger stand-in.
- **F-R8-2 (dock placement, both; resolved).** I-8.3 (a) says "yielded inside `_compose_doc_controls`, after `#patch_doc_controls`"; Inc 8's R-PE-DEF.1.1 wording says "a 4-row stand-in for Inc 10's export dock yielded inside the document controls". Inc 10 reads both as: the dock is a sibling yielded by the helper right after the `#patch_doc_controls` row (Inc 8's example EX-L7: "it lies between the document row and the legend"), never a child of `#patch_doc_controls` (a `height: 1` horizontal row, `styles.tcss:3190-3195`). Inc 8's text could say "yielded by `_compose_doc_controls`" to remove the reading (MINOR, Inc 8's records).
- **F-R8-3 (a stage is an entry change; both increments; open).** Inc 8's stage handler (`PatchMixin.on_staging_sheet_stage_requested`, Inc 8 slice A3) appends or replaces an entry through `ChangeService._stage_encoded` (I-8.2). R-PE-EXPORT.17 ("When the operator adds, edits or removes an entry, the system shall hide the save-back prompt") covers it, and E3-rulings §5 already noted that it binds any new entry path; Inc 8's records (A3, I-8.2) do not call `hide_save_prompt`. Without it, a stage after Apply leaves `Write file` and the stale apply line shown: the E3-1 defect again. Ruling proposed: whichever of Inc 8 and Inc 10 merges second adds `panel.hide_save_prompt()` on an ok stage (`app/patch.py`, a G2 / Inc 8 group A edit) and its test R-PE-EXPORT.17/5 (I-8.3 (e)). Needs the orchestrator to carry it into Inc 8's records.
- **F-R8-4 (shared files; resolved by I-8.3 (e)).** `panel.py`, `styles.tcss`, `app/patch.py` and three test files are edited by both increments in disjoint hunks (one adjacent line in `PatchEditorPanel.__init__`); the second to merge rebases and owns the test retarget.
- **F-R8-5 (Code-Wire after the split; method note for every increment on the package; open).** The extractor resolves `self.m()` only to a method of the enclosing class (`codewire_extract.py:574`), so a call between two mixins of one class (here `LayoutMixin.compose` → `ActionsMixin._compose_doc_controls`, `layout.py:77`) never appears in its report. Inc 10's two such edges are read (R, census); Inc 8's and Inc 9's graphs on the package share the blind spot. Graph note R8-G4.

### 7.5 Can Inc 10 E4 start right after Inc 8 merges?

**Yes, with three mechanical steps first** (records only, about one short pass): (1) rebase `b103-inc10` (records only, so no product conflict) onto the tip that holds Inc 8; (2) re-run `evidence-remap/i10-remap-census.py` and `i10-remap-extract.sh` against that tip — expected: `LayoutMixin.compose` and `PatchEditorPanel.__init__` / `_show_tab` / `_TABS` DIFF (Inc 8's), every Inc 10 node otherwise same, `_compose_doc_controls` still called once after the file row; (3) apply the "Inc 8 in the E4 base" forms already written (the tab names, R-TUI-063.1's merged text, R-PE-EXPORT.17/5 with the hide of F-R8-3 if Inc 8 did not add it). Nothing in Inc 10's design waits on Inc 8 beyond that. E4 could also start before Inc 8 merges (either order is allowed), but Inc 8's four implementers are writing `panel.py`, `styles.tcss` and `app/patch.py` now, so starting after it merges keeps one writer per file (DF-10) and leaves only one set of forms to test.

## 8. Prep onto Inc 8 final (relevo-10)

**Base.** `b103-inc10` was rebased onto `b103-inc8` tip `7ac47dc5` (E5 PASS-WITH-NOTES): `git rebase --onto 7ac47dc5 a95d0ea9 b103-inc10`, 8 record-only commits, no conflict. `git diff 7ac47dc5..HEAD --stat -- s19_app tests` is empty (no product or test file differs from Inc 8's tip). Evidence (read only, `ast` and `git show`/`git archive`, scratch outside every work tree, nothing from `s19_app` imported, so no runner was needed): `evidence-remap/i10-prep-census-transcript.txt` (the re-map census, `287b9dc3` against `7ac47dc5`), `i10-prep-offsets.py` + `-offsets-transcript.txt` (per-function offsets `a95d0ea9` against `7ac47dc5`), `i10-prep-extract-transcript.txt` (the extractor and the lint on the updated graph).

**Census result.** Every Inc 10 slice node has the same AST as at `a95d0ea9`; only its line moved. DIFF, all Inc 8's and none an Inc 10 node: `LayoutMixin.compose` (`layout.py:17-87`, Inc 8's regions; `_compose_action_bar` still yielded inside `#patch_win_json` at `:77`, `_compose_doc_controls` still called once at `:81`, right after `_compose_file_row` at `:80`, before the legend), `PatchEditorPanel.__init__` (`panel.py:470-535`), `PatchEditorPanel._show_tab` (`:763-771`), `PatchEditorPanel._TABS` (`:112-117`: Patch script, Inspector, JSON, Checks). Files that differ and are not slice nodes: `services/change_service.py` (+131 lines, Inc 8's `stage_definition` / `_stage_encoded`; `save_patched` and `emit_and_verify` same AST, now `:2612-2765` and `:2506-2610`) and `styles.tcss` (Inc 8's disjoint blocks; Inc 10's save-back rules moved +4 lines, e.g. `#patch_saveback_name_input` at `:3002`; `#patch_doc_file_row, #patch_doc_controls { height: 1 }` unchanged at `:3196`). New in Inc 8, outside the slice: `StagingSheet` (`sheet.py`), `definition_sheet.py`. **No other DIFF.** Offsets: `actions.py`, `compose_screens.py`, `project_load.py`, `loaded_state.py` +0; `panel.py` +2; `app/patch.py` +4 (`on_patch_editor_panel_action_requested`, `_synth_s0_header_from_filename`) and +60 (every function after `on_staging_sheet_stage_requested`); `change_service.py` +131.

**I-8.3 fit (§7.3) re-checked: holds.** Inc 8's final R-PE-DEF.1.1/3 and R-PE-DEF.74/2 (`tests/test_b103_inc8_p_layout.py:130`, `:165`) wrap `ActionsMixin._compose_doc_controls` to yield a `STANDIN_DOCK_ROWS = 4` sibling after the document row (`tests/support/b103_inc8_p.py:43`), so between `#patch_doc_controls` and the legend, the place of Inc 10's dock. Inc 10's largest dock is 4 rows. Not run here (D, no runner): Inc 8 reports those tests; E4 measures R-PE-EXPORT.2/11.

**Forms applied (R10-1, `E1-rulings.md`).** Tab names (Patch script, Inspector, JSON, Checks; A2L cases now use Patch script), R-TUI-063.1's merged sentence, R-PE-EXPORT.17 at 5/5; the "when Inc 8 is in the E4 base" qualifiers dropped in `01-requirements.md`, `02-test-cases.md`, `codewire/graph-inc10.md`. No id added; cases stay 130.

**F-R8-3 outcome (ruling P-043).** `git grep hide_save_prompt` at `7ac47dc5`: Inc 8's `PatchMixin.on_staging_sheet_stage_requested` (`app/patch.py:322-376`) does not call it. So Inc 10 E4 wires `panel.hide_save_prompt()` on an ok stage there, with test R-PE-EXPORT.17/5. Added as node 23 of the graph (changed, G2), with two edges and the coverage row.

**Graph after the prep.** 23 nodes (11 changed, 1 new, 11 context), 13 entities, 40 edges; lint `not read=0`, exit 0. Extractor: run 1 (22 baseline nodes) 3 drifts = the PROPOSED I-10.1 / I-10.2 inputs (expected), run 2 + `_set_saveback_format` without a mark (expected); the cross-mixin blind spot R8-G4 is unchanged.

**E4 groups (one owner each; 5 source files; Inc 8 is merged, so no file is shared with another writer now).**

| Group | Files | Functions (12 edits: 11 changed + 1 new) |
|---|---|---|
| G1 panel | `patch_editor/panel.py`, `patch_editor/actions.py`, `styles.tcss` (3, cap 4) | `PatchEditorPanel.__init__`, `PatchEditorPanel.SaveBackDecision.__init__`, the constant `SAVEBACK_FORMATS`; `ActionsMixin._compose_action_bar`, `_compose_doc_controls`, `on_button_pressed`, `_set_saveback_format` (new), `show_save_prompt`; the dock's CSS |
| G2 app | `app/patch.py` (1) | `PatchMixin.on_patch_editor_panel_action_requested`, `on_patch_editor_panel_save_back_decision`, `_apply_entry_json_edit`, **`on_staging_sheet_stage_requested`** (one added call) |
| G3 engine | `changes/io.py` (1) | `emit_intel_hex_from_mem_map` (the row loop) |

Tests (not capped): `tests/test_b103_pe_export_prompt.py` (G-T1, with R-PE-EXPORT.17/5) and `tests/test_b103_pe_export_write.py` (G-T2), plus the retarget of the shipped pins named in §6 and in I-8.3 (e) (`tests/test_b97_patch_editor.py`, `tests/test_tui_patch_layout.py:594` and the others); Inc 10 owns that retarget now. Inc 10 E4 starts from `7ac47dc5`.

