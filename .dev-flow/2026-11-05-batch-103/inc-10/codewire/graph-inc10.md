# Code-Wire graph — Inc 10 (Patch Editor: apply visibly, export the changed image), batch-103

Stage E2 of the design-first flow (dev-flow skill, Code-Wire v3.2.0 = `b6cd30d`), corrected at E3 (2026-11-12, `../E3-rulings.md`: E3-1, E3-2, E3-5, E3-6; the changes are listed under "E3 correction" in Findings). Graph only: no stub, mark or declaration in any work tree; the extractor's marks went only into a throwaway clone (`evidence-e2/i10e2-extract.sh`). Base `287b9dc3` on `b103-inc10` (`batch-103` with batch-101 Inc 9 / 10a / 12, batch-103 Inc 6 and Inc 1b's E5 work). Requirements `../01-requirements.md` (29 active rows: R-PE-EXPORT.1 … .17 and R-HEX-EMIT-001.11 new, 11 changed; 15 cited rows), cases `../02-test-cases.md` (128 cases + AT-I10-1 … 3), rulings `../E1-rulings.md` (D-1 A and D-2 A by the operator at G2, section "G2 verdict applied"; D-3 … D-7 by the orchestrator), slice `../E1-slice.md` (rebased to `287b9dc3`, its §5). **Re-mapped (relevo-8, 2026-11-13) to `a95d0ea9`** (`b103-pe-split`: batch-modular `2dbd7d5a` + the `patch_editor` mixin split): every node's module and every line below is `a95d0ea9`'s; the old → new table and the scope changes are `../E1-slice.md` §7, the row changes `../E1-rulings.md` "Re-map to a95d0ea9 (relevo-8)"; census `../evidence-remap/`. Every slice function moved verbatim (same AST) except `compose`, which batch-modular split into helpers; Inc 10's dock now lands in `ActionsMixin._compose_doc_controls` (I-8.3 of Inc 8, ruling E3A-05).

How to read it:
- One file holds the baseline and the prototype. Every node's `func:` starts with **unchanged**, **changed** (then "was: … / now: …", the baseline first) or **new**. Context nodes (unchanged) are here because the design depends on what they do.
- Sources of the examples: the case ids of `../02-test-cases.md` (the expected result of the case is the example); **C** = E1's census transcripts on <runner> (`../evidence-e1/i10e1_layout_census_transcript.txt`, `../evidence-e1/i10e1_convert_census_transcript.txt`); **D** = derived at E2 from C plus this design's row count, to be measured at E4 (no runner ran at E2: finding E2-4); **R** = read in the code at `287b9dc3` (E2, E3) and re-read at `a95d0ea9` (re-map); **X** = the extractor, `evidence-e2/i10e2-extract-transcript.txt` (E2) and `../evidence-remap/i10-remap-extract-transcript.txt` (re-map, at `a95d0ea9`).
- Fixtures (case01, the HEX twin, Applied case01 (tab T), Applied HEX (tab T), the conversion sources, the work area) are `../02-test-cases.md`'s.
- Line numbers: the baseline table and the group/interface rows are `7ac47dc5`'s (relevo-10 prep, Inc 8 final); the `file:line` cited inside a node's `func:` are `a95d0ea9`'s (re-map; `287b9dc3`'s at E2 and E3) and move by the per-function offsets of `../E1-slice.md` §8 (`../evidence-remap/i10-prep-offsets-transcript.txt`: +4 for `on_patch_editor_panel_action_requested` and `_synth_s0_header_from_filename`, +60 for the other `app/patch.py` nodes, +2 in `panel.py`, 0 in `actions.py`). Node names are the defining class's (`ActionsMixin`, `PatchMixin`, …): the panel and the app reach them through their mixin bases, so a caller still writes `panel.show_save_prompt(...)`.
- Fixture *x64u* (E3-2): `../data/x64u.s19`, `../data/x64u.hex` (also the expected HEX output), `../data/x64u-base-emitter.hex` (the base loop's output), script `../data/x64u_make.py`.

### Groups for E4 (file ownership) and interfaces — pinned here, changed only by an orchestrator ruling

| Group | Files | Owns |
|---|---|---|
| G1 panel | `s19_app/tui/screens_directionb/patch_editor/panel.py`, `s19_app/tui/screens_directionb/patch_editor/actions.py`, `s19_app/tui/styles.tcss` (re-map: `screens_directionb.py` became the `patch_editor` package; 3 files, cap 4) | nodes `PatchEditorPanel.__init__`, `PatchEditorPanel.SaveBackDecision.__init__`, `ActionsMixin._compose_action_bar`, `ActionsMixin._compose_doc_controls` (re-map: the dock lands in `_compose_doc_controls`, I-8.3; `LayoutMixin.compose` is Inc 8's, never edited here), `ActionsMixin.on_button_pressed`, `ActionsMixin._set_saveback_format` (new), `ActionsMixin.show_save_prompt`; the class constant `SAVEBACK_FORMATS`; the docstrings of `_compose_action_bar` and `_compose_doc_controls` (the prompt's home), `show_save_prompt`, `SaveBackDecision`, `PatchEditorPanel` (class); every `styles.tcss` edit (entity `[Interface: export dock layout]`) |
| G2 app | `s19_app/tui/app/patch.py` (re-map: `app.py` became the `app` package; the three handlers live in `PatchMixin`) | nodes `PatchMixin.on_patch_editor_panel_action_requested` (the `apply_doc` arm; since E3-1 also the `add_entry`, `edit_entry`, `remove_entry` arms), `PatchMixin.on_patch_editor_panel_save_back_decision`, `PatchMixin._apply_entry_json_edit` (E3-1), `PatchMixin.on_staging_sheet_stage_requested` (relevo-10, F-R8-3: one added call, `panel.hide_save_prompt()` on an ok stage); their docstrings |
| G3 engine (E3-2) | `s19_app/tui/changes/io.py` | node `emit_intel_hex_from_mem_map` (the row loop) and its docstring (Data Flow: rows end at the next 64 KiB boundary) |
| G-T1 prompt tests | new `tests/test_b103_pe_export_prompt.py`; the moved pins (finding E2-10) | cases of R-CHG-003.1, R-PE-EXPORT.1 … .15, R-PE-EXPORT.17, R-TUI-063.1, R-TUI-049.1, R-TUI-064.1/.2/.4, R-HEX-VERIFY-002.3, R-S19-WIDTH-001.1/.2, R-CHG-003.2/.5, AT-I10-1 … 3 |
| G-T2 write tests | new `tests/test_b103_pe_export_write.py` | cases of R-HEX-EMIT-001.11 (E3-2), R-HEX-SAVE-001.1/.2, R-S19-SAVE-REUSE-001.1, R-PE-EXPORT.16, R-S19-S0HEADER-001.1 … .3, R-S19-EMIT.3/.4/.5/.11, R-HEX-EMIT-001.2/.3, R-HEX-VERIFY-001.1, R-HEX-VERIFY-002.1, R-IMG-WRITE.2 |

| Interface | Pinned form | Producer → consumers |
|---|---|---|
| I-10.1 the prompt's show (PROPOSED change of an existing signature) | `PatchEditorPanel.show_save_prompt(self, suggestion: str, *, output_format: str, apply_line: str) -> None`, defined in `ActionsMixin` (`actions.py:280-301`); `output_format` is `"s19"` or `"hex"`; `apply_line` is painted as a literal `Text` (no markup) | G1 → G2 (the `apply_doc` arm, `app/patch.py:236`, the only caller); `tests/test_tui_patch_layout.py:594` (E2-10) |
| I-10.2 the decision message (PROPOSED change; default dropped at E3, E3-5) | `PatchEditorPanel.SaveBackDecision(filename: Optional[str], bytes_per_line: int = 32, output_format: Optional[str] = None)`; a confirm carries the panel's `_saveback_format` (always `"s19"` or `"hex"`); a decline is `SaveBackDecision(None)`, its `output_format` `None` and never read; no `"s19"` default (as I-10.1, E2-2): a confirm built without the format reaches the engine as `None` and is refused, never written as S19 | G1 → G2 (`on_patch_editor_panel_save_back_decision`) |
| I-10.3 the prompt's hide (unchanged) | `PatchEditorPanel.hide_save_prompt(self) -> None`, defined in `ActionsMixin` (`actions.py:303-310`) | G1 → G2 (save-back handler, `_hide_replaced_document_controls`, the new zero-apply call in the `apply_doc` arm, and the stage handler's ok path, relevo-10) |
| I-10.4 the dock ids | new `Container(id="patch_export_dock")` yielded by `ActionsMixin._compose_doc_controls` right after `#patch_doc_controls` (Inc 8 I-8.3 (a); never from `#patch_main`, never by an edit of `layout.py`), so it sits between the document row and `#patch_legend` as a child of `#patch_editor_panel`, holding `#patch_saveback_row` then `#patch_before_after_row`; new ids `#patch_saveback_apply_line` (`Static`) and `#patch_saveback_format_button` (`Button`); every shipped id kept with its type (`PE_IDS_9C7BEAF` is a subset check, `tests/test_b97_patch_editor.py:207-208`) | G1 → G-T1; batch-103 Inc 8 (I-8.3: R-PE-DEF.1.1 counts the dock among "the other shown regions", case /3 with a 4-row stand-in; R-TUI-063.1 merged form; the dock is at most 4 rows at 118×54 and 220×60, re-map fit) |
| I-10.5 the output-format values | `"s19"` / `"hex"` — the engine's kind strings (`changes/apply.py:103-106`); names `S19` / `Intel HEX`; suffixes `.s19` / `.hex`; spelled locally in `PatchEditorPanel.SAVEBACK_FORMATS` (the panel imports nothing from the engine, as `SAVEBACK_WIDTHS`) | G1 → G2 (the value on I-10.2) → the engine (unchanged) |
| I-10.6 the Intel HEX emitter (E3-2; signature unchanged) | `emit_intel_hex_from_mem_map(mem_map: dict[int, int], ranges: list[tuple[int, int]]) -> str`; output contract: every type-00 record holds at most 16 data bytes and ends at or before the next 64 KiB boundary (R-HEX-EMIT-001.1, .11); its output changes only for a range whose 16-byte rows from the range start would cross a boundary (e.g. *x64u*); every other image's text is unchanged | G3 → `render_patched_image` (save-back, Save project, flow WRITE-OUT; unchanged), `segment_ops.emit_image` (`segment_ops.py:507`, unchanged) |
| PLAN I-1 … I-5 | n/a — no clipboard, definition model, matcher, A2L refresh or label-list parser in this slice | — |

Shared-file edits and their one owner: `patch_editor/panel.py` and `patch_editor/actions.py` only G1 (no other group edits them); `app/patch.py` only G2; `styles.tcss` only G1; `changes/io.py` only G3 (E3-2). No source file is edited by two groups. Docstrings that name the prompt's home outside these nodes: `ActionsMixin.hide_before_after_prompt`'s "Used by" list is unchanged; none other (R at `a95d0ea9`, `git grep "patch_win_json\|patch_saveback_row"` in `s19_app/`: `LayoutMixin.compose`'s docstring names the ids only to say they keep their `Container` type, still true, so `layout.py` needs no edit; `_compose_action_bar`'s one-line docstring names the rows it yields and changes with that node). **Files shared with other increments (re-map):** Inc 8 also edits `patch_editor/panel.py` (`_TABS`, `__init__`, `_show_tab`, …), `styles.tcss` (its new block; the `#patch_main` rules leave) and `app/patch.py` (its new `on_staging_sheet_stage_requested`), in hunks disjoint from Inc 10's except one adjacent attribute line in `__init__` (Inc 8 I-8.3 point 5); `patch_editor/actions.py` and `layout.py` have one writer each (Inc 10, Inc 8; I-8.3).

### Baseline: the existing functions in scope at `a95d0ea9` and their real callers (re-map, relevo-8; X: `../evidence-remap/i10-remap-extract-transcript.txt`, the extractor on a throwaway clone at `a95d0ea9`; lines and call sites from the census `../evidence-remap/i10-remap-census-transcript.txt` (`ast`, `git archive`); R where the call is a textual dispatch; the `287b9dc3` lines of E2 and E3 are in `../E1-slice.md` §7)

| Function | `file:line` | Real callers (`file:line` of the call) | Here |
|---|---|---|---|
| `PatchEditorPanel.__init__` | `patch_editor/panel.py:470-535` | `ComposeScreensMixin._compose_screen_patch` (`app/compose_screens.py:540`) | changed |
| `PatchEditorPanel.SaveBackDecision.__init__` | `patch_editor/panel.py:334-339` | `ActionsMixin.on_button_pressed` (`actions.py:113`, `:121`) | changed |
| `LayoutMixin.compose` | `patch_editor/layout.py:17-87` | textual compose (R) | context (Inc 8 is its one writer, I-8.3; DIFF vs `a95d0ea9`: Inc 8's regions) |
| `ActionsMixin._compose_action_bar` | `patch_editor/actions.py:477-561` | `LayoutMixin.compose` (`layout.py:77`, inside `#patch_win_json`) | changed |
| `ActionsMixin._compose_doc_controls` | `patch_editor/actions.py:563-575` | `LayoutMixin.compose` (`layout.py:81`, after the file row, before the legend) | changed |
| `ActionsMixin.on_button_pressed` | `patch_editor/actions.py:64-226` | textual `Button.Pressed` dispatch (R) | changed |
| `ActionsMixin.show_save_prompt` | `patch_editor/actions.py:280-301` | `PatchMixin.on_patch_editor_panel_action_requested` (`app/patch.py:240`) | changed |
| `ActionsMixin.hide_save_prompt` | `patch_editor/actions.py:303-310` | `on_patch_editor_panel_save_back_decision` (`app/patch.py:438`), `_hide_replaced_document_controls` (`:587`) | context |
| `ActionsMixin.show_before_after_prompt` | `patch_editor/actions.py:312-327` | `on_patch_editor_panel_save_back_decision` (`app/patch.py:499`) | context |
| `ActionsMixin.hide_before_after_prompt` | `patch_editor/actions.py:329-343` | `on_patch_editor_panel_action_requested` (`app/patch.py:183`), `_hide_replaced_document_controls` (`:586`) | context |
| `PatchMixin.on_patch_editor_panel_action_requested` | `app/patch.py:98-320` (`apply_doc` arm `:218-244`; entry arms `:163-178`) | textual message dispatch (R) | changed |
| `PatchMixin.on_patch_editor_panel_save_back_decision` | `app/patch.py:378-516` (the write `:446-461`) | textual message dispatch (R) | changed |
| `PatchMixin._hide_replaced_document_controls` | `app/patch.py:558-587` | `on_patch_editor_panel_action_requested` (`:194`, parse-paste), `action_patch_undo` (`:784`), `action_patch_redo` (`:819`), `_patch_editor_load` (`:1553`), `ProjectLoadMixin._reset_project_session` (`app/project_load.py:1045`), `LoadedStateMixin._apply_prepared_load` (`app/loaded_state.py:689`) | context |
| `PatchMixin._apply_entry_json_edit` | `app/patch.py:997-1059` | the `EntryJsonScreen` dismiss callback pushed by `on_patch_editor_panel_entry_edit_json_requested` (`app/patch.py:990-994`) | changed (E3-1) |
| `PatchMixin.on_staging_sheet_stage_requested` | `app/patch.py:322-376` | textual message dispatch of `StagingSheet.StageRequested` (R) | changed (F-R8-3) |
| `_synth_s0_header_from_filename` | `app/patch.py:65-93` | `on_patch_editor_panel_save_back_decision` (`:449`) | context |
| `ChangeService.save_patched` | `services/change_service.py:2612-2765` | `on_patch_editor_panel_save_back_decision` (`app/patch.py:454`) | context |
| `ChangeService.emit_and_verify` | `services/change_service.py:2506-2610` | `ChangeService.save_patched` (`:2755`) only | context |
| `save_patched_image` | `changes/apply.py:686-874` | `emit_and_verify` (`change_service.py:2575`), `SaveCommitMixin._save_project_files` (`app/save_commit.py:805`, through `deps.`), `run_flow` (`flow_execution_service.py:727`), `_execute_one_variant` (`variant_execution_service.py:2584`) | context |
| `render_patched_image` | `changes/apply.py:629-683` | `save_patched_image` (`apply.py:795`), `SavePlanMixin._decide_project_image` (`app/save_plan.py:1145`, through `deps.`) | context |
| `emit_intel_hex_from_mem_map` | `changes/io.py:1934-2006` (row loop `:1996-2004`) | `render_patched_image` through `_SAVE_BACK_EMITTERS["hex"]` (`apply.py:105`, called `:682`), `segment_ops.emit_image` (`segment_ops.py:507`) | changed (E3-2) |
| `verify_written_image` | `changes/verify.py:119-171` | `emit_and_verify` (`change_service.py:2600`); also, outside this flow and unchanged, `_save_project_files` (`app/save_commit.py:817`, through `deps.`), `operations/crc.py:1524`, `run_flow` (`flow_execution_service.py:746`) | context |

The engine files (`changes/io.py`, `changes/apply.py`, `changes/verify.py`, `services/change_service.py`, `flow_execution_service.py`, `variant_execution_service.py`, `segment_ops.py`, `hexfile.py`) and `styles.tcss` are byte-identical at `287b9dc3` and `a95d0ea9` (census), so their lines are unchanged. Three callers of the engine changed AST only by batch-modular's `deps.` indirection (`_save_project_files`, `_decide_project_image`, `_activate_project_file`): same calls, same arguments (`source_kind=request.image.file_type` / `loaded.file_type`).

## Nodes

PatchEditorPanel.__init__
req: R-PE-EXPORT.7, R-PE-EXPORT.8
in: none
out: PatchEditorPanel panel
func: changed. was: sets `_saveback_width = SAVEBACK_WIDTHS[0]` (32) among the panel's attributes (`panel.py:496-499`); no output format. / now: also `_saveback_format: str = SAVEBACK_FORMATS[0][0]` (`"s19"`) beside it, a placeholder until `show_save_prompt` sets the loaded image's format; the class gains `SAVEBACK_FORMATS = (("s19", "S19", ".s19"), ("hex", "Intel HEX", ".hex"))` beside `SAVEBACK_WIDTHS` (`panel.py:246`). Every other attribute (batch-103 Inc 6's pick-mode picker included) unchanged.
module: s19_app/tui/screens_directionb/patch_editor/panel.py
modify: [Data: PatchEditorPanel._saveback_format] (replace)
examples: (R) a new panel → `_saveback_format` `"s19"`, `_saveback_width` `32`; `#patch_saveback_row` has the class `hidden`
examples: (holds, `tests/test_b97_patch_editor.py:206-207`) every id of `PE_IDS_9C7BEAF` (`66`) still resolves in the mounted panel

PatchEditorPanel.SaveBackDecision.__init__
req: R-HEX-SAVE-001.1, R-HEX-VERIFY-001.1, R-PE-EXPORT.8
in: Optional[str] filename; int bytes_per_line = 32; Optional[str] output_format = None
out: SaveBackDecision message
func: changed (I-10.2). was: carries `filename` and `bytes_per_line` (`panel.py:332-337`). / now: also `output_format` (`"s19"` or `"hex"`), set from `_saveback_format` on a confirm; no `"s19"` default (E3-5): it defaults to `None`, which a decline keeps (`SaveBackDecision(None)`, never read) and which a confirm built without it carries to the engine's refusal. Still a separate message class, so the routed action set is unchanged.
module: s19_app/tui/screens_directionb/patch_editor/panel.py
examples: (R-PE-EXPORT.8/1) Applied case01, Format pressed once, `Write file` → filename `firmware-patched.hex`, bytes_per_line `32`, output_format `"hex"` → the written file's first line starts with `:`
examples: (R-PE-EXPORT.8/2) Format pressed twice, `Write file` → output_format `"s19"` → first line starts with `S0`
examples: (R-CHG-003.2/1) `Don't save` → filename `None` → status `Patch Editor: save-back declined`, no new file in the work area
examples: (neg, E3-5) a confirm built as `SaveBackDecision("firmware-patched.hex")` (no format) on Applied case01 → output_format `None` → no file written, the `CHG-HEX-SAVE-UNSUPPORTED` refusal; with E2's `"s19"` default it would have written S19 text as `firmware-patched.hex.s19` (the silent conversion E3-5 removes)

LayoutMixin.compose
req: R-TUI-063.1
in: none
out: ComposeResult result
func: unchanged (`patch_editor/layout.py:17-83`; re-map: E2's `PatchEditorPanel.compose` node, `screens_directionb.py:4931-5287` at `287b9dc3`, was split by batch-modular into this function and its helpers). Yields the ribbon, `#patch_main` (inside it `#patch_win_json`, whose content includes `yield from self._compose_action_bar()`, `:64-67`), the file row (`:76`), `yield from self._compose_doc_controls()` once (`:77`), then `#patch_legend` (`:78-83`). Inc 10 edits nothing here: Inc 8 is this function's one writer (I-8.3 (a); Inc 8 replaces `#patch_main` with the filter row, `#patch_sheet_win` and the landing pane, and keeps the `_compose_doc_controls` call after the file row and before the legend). Its docstring says each `patch_saveback_row` / `patch_before_after_row` id keeps its `Container` type, which stays true.
module: s19_app/tui/screens_directionb/patch_editor/layout.py
examples: (R, `a95d0ea9`) the shown tab's content holds `#patch_win_json`'s action bar; `_compose_doc_controls` is called once, after `#patch_doc_file_row`, before `#patch_legend`
examples: (holds after Inc 8, I-8.3 (a), Inc 8 EX-L7) a 4-row stand-in yielded by `_compose_doc_controls` lies between the document row and the legend

ActionsMixin._compose_action_bar
req: R-CHG-003.1, R-TUI-049.1
in: none
out: ComposeResult result
func: changed. was: yields, inside `#patch_win_json` (the caller's context), the history strip and Undo/Redo (`actions.py:482-493`), `#patch_execute_row` (`:494-516`), then `#patch_saveback_row` (`:517-545`: the row `Save patched image as:` + `#patch_saveback_name_input`, then `#patch_saveback_buttons` = Width, `Write file`, `Don't save`) and `#patch_before_after_row` (`:546-561`), so both are hidden with the JSON tab whenever another tab is shown (C, `e07fb00`: region 0×0 in 6 of 8 tab cases). / now: the two save-back blocks leave (they move to `_compose_doc_controls`, below); the history strip, Undo/Redo and the execute row stay, unchanged. The one-line docstring drops "save-back and before/after rows".
module: s19_app/tui/screens_directionb/patch_editor/actions.py
examples: (R-CHG-003.1/1, neg) the two blocks left here (the base) → the prompt inside `#patch_win_json`: 0×0 from the Inspector, Checks and A2L tabs (C) → R-CHG-003.1/1 RED
examples: (holds) `#patch_history_strip`, `#patch_history_controls`, `#patch_execute_row` still children of `#patch_win_json` (`tests/test_b97_patch_editor.py` homes, state A/B)

ActionsMixin._compose_doc_controls
req: R-CHG-003.1, R-PE-EXPORT.1, R-PE-EXPORT.2, R-PE-EXPORT.4, R-PE-EXPORT.9, R-PE-EXPORT.11, R-TUI-063.1, R-TUI-049.1, R-TUI-064.1, R-TUI-064.2, R-TUI-064.4
in: none
out: ComposeResult result
func: changed (I-8.3 (a): Inc 10's dock is yielded here, never from `#patch_main`, never by editing `layout.py`). was: yields `#patch_doc_controls` only (`actions.py:565-575`: Validate, Apply loaded changes, Save). / now: after that row, one `Container(id="patch_export_dock")` (I-10.4) holding `#patch_saveback_row` then `#patch_before_after_row`, both moved from `_compose_action_bar` with their ids, `Container` types, classes and the `hidden` start. `#patch_saveback_row` holds, top to bottom: the apply line `Static("", id="patch_saveback_apply_line", markup=False)`; the name row (label and input unchanged); `#patch_saveback_buttons` in one row: `Button("Format: S19", id="patch_saveback_format_button", classes="patch-chip")`, then Width, `Write file`, `Don't save` (ids, labels, classes unchanged). `#patch_before_after_row` keeps its label and button. The dock holds nothing else and has no frame or title (O-5). The docstring names the dock ("the Validate / Apply / Save row, then the export dock").
module: s19_app/tui/screens_directionb/patch_editor/actions.py
examples: (R-CHG-003.1/1 … /8) Applied case01 with each of the four tabs shown (the tab chips of R-TUI-063.3 on the E4 base), at 118×54 and 220×60 → `#patch_saveback_row` and `#patch_saveback_confirm_button` are shown widgets (every ancestor displayed: the dock is a child of `#patch_editor_panel`, outside the tab switcher), the shown tab is still the one shown before Apply (base: 0×0 in the three tabs other than JSON, C)
examples: (R-CHG-003.1/9) Applied HEX (Inspector) at 118×54 → `Write file` shown at its place
examples: (R-PE-EXPORT.1/1, D) 118×54, prompt shown → `#patch_doc_controls` y `38`, `#patch_saveback_row` y `39` … `41` (3 rows), `#patch_legend` y `42`; the row's x and width equal `#patch_doc_controls`'s (base C, prompt hidden: document row y `41`, legend y `42`); the 3 rows come from the region that yields rows: `#patch_main` at `a95d0ea9`, `#patch_sheet_win` after Inc 8 (I-8.3 (b))
examples: (R-TUI-063.1/2, D) the same → the top rows of ribbon, `#patch_main` (y `5`), file row (y `37`), document row, prompt, legend strictly increase; after Inc 8 the merged form: ribbon, filter row, staging sheet, landing pane, file row, document row, prompt, legend
examples: (R-TUI-063.1/1, holds C) prompt hidden → the dock takes `0` rows: file row y `40`, document row y `41`, legend y `42`
examples: (I-8.3 fit, D; R-PE-EXPORT.2/11) the dock's height at 118×54 and 220×60: `0` rows (nothing shown), `3` (the prompt: apply line, name row, buttons row), `1` (the before/after row alone, after `Write file`), `4` (both: `Write file`, then Apply again, which shows the prompt while the before/after row stays) — never more than Inc 8's 4-row stand-in (R-PE-DEF.1.1/3, R-PE-DEF.74/2)
examples: (R-PE-EXPORT.2/1 … /10) every control of the prompt inside the screen with every scroll offset `0`, from each tab, both sizes (base: 0×0, C)
examples: (R-TUI-064.4/1) the Format control, Width, `Write file`, `Don't save` each `1` row high (chips)
examples: (R-TUI-064.2/1, D) the buttons row is about `65` cells and the apply line `85` cells with one-digit counts, inside the `112` content columns of the dock at 118×54 → no painted row wider than `116` cells
examples: (neg, R-TUI-063.1) the dock yielded before `#patch_doc_controls` → R-TUI-063.1/2 RED; a dock yielded by an edit of `LayoutMixin.compose` → not RED by any row, but refused by I-8.3 (one writer of `layout.py`)

ActionsMixin.on_button_pressed
req: R-PE-EXPORT.8, R-HEX-SAVE-001.1
in: Button.Pressed event
out: None
func: changed. was: tab chips → `_show_tab` (`actions.py:88`); the Width branch cycles `_saveback_width` and relabels, no message (`:96-109`); the confirm branch posts `SaveBackDecision(<name box>, bytes_per_line=_saveback_width)` (`:110-118`); the decline posts `SaveBackDecision(None)` (`:119-122`). / now: one new branch before the Width branch: `patch_saveback_format_button` → `event.stop()` and `self._set_saveback_format(<the other of "s19" and "hex">, rename=True)`; no message (selector state, the Width idiom). The confirm branch adds `output_format=self._saveback_format`. Every other branch unchanged.
module: s19_app/tui/screens_directionb/patch_editor/actions.py
examples: (R-PE-EXPORT.8/1) `_saveback_format` `"s19"`, Format pressed → `_saveback_format` `"hex"`, label `Format: Intel HEX`; no message posted
examples: (R-PE-EXPORT.8/2) pressed again → `"s19"`, label `Format: S19`
examples: (R-HEX-SAVE-001.1/2) Applied case01, Format, `Write file` → the decision carries output_format `"hex"` → `firmware-patched.hex` in the work area, first line starts with `:`
examples: (neg, R-PE-EXPORT.8) a Format branch that changes nothing → R-PE-EXPORT.8/1 RED; a confirm without `output_format` (`None`, E3-5) → no file, R-HEX-SAVE-001.1/2 RED

ActionsMixin._set_saveback_format
req: R-PE-EXPORT.7, R-PE-EXPORT.8, R-PE-EXPORT.9, R-PE-EXPORT.10, R-PE-EXPORT.11, R-PE-EXPORT.12, R-PE-EXPORT.13, R-PE-EXPORT.14, R-PE-EXPORT.15
in: str output_format; bool rename
out: None
func: new (E1's `_switch_saveback_format`, generalised, E2-1). Sets `_saveback_format`; labels `#patch_saveback_format_button` `Format: <name>` from `SAVEBACK_FORMATS`; sets `#patch_saveback_width_button`'s `styles.visibility` to `visible` for S19 and `hidden` for Intel HEX — its place kept (never `display`), so no neighbour moves (R-PE-EXPORT.12; a hidden widget is not painted and not in the focus chain: textual 8.2.8 `Widget.focusable` requires `visible`, R); keeps `_saveback_width` and the Width label. When `rename` is true, a final `.s19` or `.hex` of the name box text, in any letter case and together with any whitespace after it, becomes the new format suffix (`re.compile(r"\.(s19|hex)\s*\Z", re.IGNORECASE)`: `\s` on a `str` is the whitespace `str.strip()` removes, so the box agrees with the engine, which strips the typed name before its suffix rule, `apply.py:923`, E3-6); any other text stays as typed. `show_save_prompt` calls it with `rename=False` (the suggestion already ends with its suffix); the Format press with `rename=True`.
module: s19_app/tui/screens_directionb/patch_editor/actions.py
modify: [Data: PatchEditorPanel._saveback_format] (replace)
examples: (R-PE-EXPORT.14/1) name `firmware-patched.s19`, `"hex"`, rename → name `firmware-patched.hex`, label `Format: Intel HEX`, Width not painted
examples: (R-PE-EXPORT.14/2) name `MyImage.S19`, `"hex"`, rename → `MyImage.hex`
examples: (R-PE-EXPORT.14/3) name `a.hex`, `"s19"`, rename → `a.s19`, Width shown `Width: 32 bytes/line`
examples: (R-PE-EXPORT.14/4, E3-6) name `firmware-patched.s19 ` (a trailing space), `"hex"`, rename → `firmware-patched.hex`; `Write file` → written `firmware-patched.hex`
examples: (R-PE-EXPORT.15/1) name `release_v2`, `"hex"`, rename → `release_v2` (the write then makes `release_v2.hex`, R-HEX-SAVE-001.2)
examples: (R-PE-EXPORT.15/2) name `x.bin`, `"hex"`, rename → `x.bin` (written `x.bin.hex`)
examples: (R-PE-EXPORT.13/1) width `16`, `"hex"` then `"s19"` → `Width: 16 bytes/line`; `Write file` writes S3 records of at most `16` data bytes
examples: (R-PE-EXPORT.10/1, /2) `"hex"` → a click at the Width chip's place leaves the width `32` and the name box unchanged; Tab through the prompt never focuses it
examples: (R-PE-EXPORT.12/1 … /4) `"s19"` → `"hex"` → `"s19"` at 118×54 and 220×60 → the regions of `Write file` and `Don't save` equal before and after each press (the Format chip has the fixed width of `Format: Intel HEX`, E2-3)
examples: (neg) px_A's rule (any final extension replaced) → `x.bin` becomes `x.hex`, R-PE-EXPORT.15/2 RED; E2's rule `\.(s19|hex)\Z` (no trailing whitespace) → `firmware-patched.s19 ` kept, written `firmware-patched.s19.hex`, R-PE-EXPORT.14/4 RED; `display = False` for Intel HEX → `Write file` moves left by the Width chip's width, R-PE-EXPORT.12/1 RED; the Format chip at `width: auto` → `Write file` moves `6` cells (`S19` → `Intel HEX`), R-PE-EXPORT.12/1 RED

ActionsMixin.show_save_prompt
req: R-CHG-003.1, R-PE-EXPORT.4, R-PE-EXPORT.7, R-PE-EXPORT.9, R-PE-EXPORT.10, R-PE-EXPORT.11, R-S19-WIDTH-001.1, R-HEX-VERIFY-002.3
in: str suggestion; str output_format; str apply_line
out: None
func: changed (I-10.1). was: fills the name box with `suggestion`, resets the width to 32 and relabels Width, removes `hidden` from `#patch_saveback_row` (`actions.py:280-301`). / now: in this order: the name box (unchanged); the width reset (unchanged); `self._set_saveback_format(output_format, rename=False)` — each prompt starts from the given format whatever the last one showed; `#patch_saveback_apply_line` updated with `Text(apply_line)` (a literal, never markup; the line holds only counts, no file-derived text); remove `hidden` (unchanged). `output_format` and `apply_line` are keyword-only and required (E2-2).
module: s19_app/tui/screens_directionb/patch_editor/actions.py
modify: [Data: PatchEditorPanel._saveback_format] (replace)
examples: (R-PE-EXPORT.7/1, R-HEX-VERIFY-002.3/1) `firmware-patched.s19`, output_format `"s19"` → Format `S19`, name `firmware-patched.s19`, `Width: 32 bytes/line`
examples: (R-PE-EXPORT.7/2, R-HEX-VERIFY-002.3/2, R-PE-EXPORT.10/1) `firmware-patched.hex`, `"hex"` → Format `Intel HEX`, name `firmware-patched.hex`, Width not painted
examples: (R-PE-EXPORT.7/3) after Format (Intel HEX) and `Don't save`, Apply again with `"s19"` → Format `S19`, name `firmware-patched.s19`
examples: (R-PE-EXPORT.4/1) apply_line `Apply: 1 applied, 0 skipped, 0 blocked · changed in memory only — Write file saves it` → painted exactly so
examples: (R-S19-WIDTH-001.1/1) Width pressed (16), `Don't save`, Apply → `Width: 32 bytes/line`
examples: (neg, R-PE-EXPORT.7) the format kept from the last prompt → R-PE-EXPORT.7/3 RED

PatchMixin.on_patch_editor_panel_action_requested
req: R-CHG-003.1, R-PE-EXPORT.3, R-PE-EXPORT.4, R-PE-EXPORT.5, R-PE-EXPORT.6, R-PE-EXPORT.7, R-PE-EXPORT.17
in: PatchEditorPanel.ActionRequested event
out: None
func: changed (the `apply_doc` arm only, `app/patch.py:214-240`). was: status `Apply: <a> applied, <s> skipped, <b> blocked`; applied > 0 on an S19 or Intel HEX image → `panel.show_save_prompt(f"{variant_id}-patched{suffix}")`, the suffix from `loaded.file_type`; applied = 0 → nothing more (an earlier prompt stays shown, C); no notice either way. / now: `apply_text = f"Apply: {a} applied, {s} skipped, {b} blocked"` once; `set_status(apply_text)` unchanged; applied > 0 on `s19` / `hex` → `panel.show_save_prompt(f"{variant_id}-patched{suffix}", output_format=loaded.file_type, apply_line=f"{apply_text} · changed in memory only — Write file saves it")`; applied = 0, with or without an image → `panel.hide_save_prompt()` then `self.notify(apply_text, title="Nothing applied", severity="warning")`; no notice when applied > 0. The before/after control is not touched by an apply. The unreachable `<kind> save-back not supported` branch stays (D-6 A). E3-1: the `add_entry`, `edit_entry` and `remove_entry` arms (`:159-174`) each call `panel.hide_save_prompt()` right after the service call returns, before their status; a change the service refuses (`ValueError` / `KeyError`, caught at the arm's `except`) skips it and leaves the prompt as it was (the document did not change; no row asks either way). The before/after control is not touched by an entry change (it reports the last save, not the document). Every other arm unchanged.
module: s19_app/tui/app/patch.py
examples: (R-PE-EXPORT.4/1, R-PE-EXPORT.6/1) Applied case01 → apply_line `Apply: 1 applied, 0 skipped, 0 blocked · changed in memory only — Write file saves it`, output_format `"s19"`, `0` notices
examples: (R-PE-EXPORT.4/2) entries 0x8000007C `DE AD`, 0x80000040 `11`, 0x00000010 `AA` → `Apply: 2 applied, 1 skipped, 0 blocked · changed in memory only — Write file saves it`
examples: (R-PE-EXPORT.4/3) after /1, 0x80000040 `11` added, Apply → `Apply: 2 applied, 0 skipped, 0 blocked · changed in memory only — Write file saves it`
examples: (R-PE-EXPORT.6/2, R-PE-EXPORT.7/2) Applied HEX → output_format `"hex"`, suggestion `firmware-patched.hex`, `0` notices
examples: (R-PE-EXPORT.3/1, /2, R-PE-EXPORT.5/2) prompt shown, the entry replaced by 0x00000010 `AA`, Apply → status `Apply: 0 applied, 1 skipped, 0 blocked`; the prompt not a shown widget; one warning notice titled `Nothing applied` with the text `Apply: 0 applied, 1 skipped, 0 blocked`; the byte at 0x8000007C back to 0x3C (base: prompt still shown, 0 notices, C)
examples: (R-PE-EXPORT.3/3, R-PE-EXPORT.5/3) 0x8000007C `DE AD BE EF` and 0x8000007D `00` (a collision), Apply → the prompt hidden; notice `Nothing applied` / `Apply: 0 applied, 0 skipped, 2 blocked`
examples: (R-PE-EXPORT.5/1) no image loaded, 0x100 `AA`, Apply → notice `Nothing applied` / `Apply: 0 applied, 1 skipped, 0 blocked`
examples: (R-PE-EXPORT.17/1) Applied case01 (Inspector), 0x80000040 `11`, Add → status `Patch Editor: entry added.`; the prompt not a shown widget
examples: (R-PE-EXPORT.17/2) Applied case01, 0x8000007C bytes `CA FE BA BE`, Edit → `Patch Editor: entry updated.`; the prompt not a shown widget
examples: (R-PE-EXPORT.17/3) Applied case01, 0x8000007C, Remove → `Patch Editor: entry removed.`; the prompt not a shown widget (base: still shown, and `Write file` writes a copy of the source as `firmware-patched.s19`, E3-1)
examples: (neg) `information` instead of `warning` → R-PE-EXPORT.5/1 RED; no `hide_save_prompt()` on a zero apply (the base) → R-PE-EXPORT.3/1 RED; an information notice on success → R-PE-EXPORT.6/1 RED; `apply_line` from the first apply kept → R-PE-EXPORT.4/3 RED; the hide left out of the `add_entry` / `edit_entry` / `remove_entry` arm → R-PE-EXPORT.17/1 / /2 / /3 RED

PatchMixin.on_patch_editor_panel_save_back_decision
req: R-HEX-SAVE-001.1, R-HEX-SAVE-001.2, R-S19-SAVE-REUSE-001.1, R-PE-EXPORT.16, R-S19-S0HEADER-001.1, R-S19-S0HEADER-001.2, R-S19-S0HEADER-001.3, R-S19-EMIT.11, R-HEX-VERIFY-001.1, R-TUI-049.1
in: PatchEditorPanel.SaveBackDecision event
out: None
func: changed (`app/patch.py:386-401` only). was: `source_kind=loaded.file_type` (`:399`); S0: width 32 → `loaded.source_s0_header or _synth_s0_header_from_filename(event.filename)`, width 16 → `None`. / now: `kind = event.output_format` when `loaded.file_type` is in `("s19", "hex")`, else `loaded.file_type` (so the engine's refusal R-CHG-003.16 of any other image stands, `apply.py:795-813`). No fallback (E3-5, replaces E2-14's): an `event.output_format` outside the engine's emitter table, `None` included, is passed on as `kind`, and the engine refuses it with its existing `CHG-HEX-SAVE-UNSUPPORTED` issue (R-CHG-003.16's refusal: no file written, the prompt already hidden, the refusal reported as any engine refusal is); the handler never substitutes the loaded kind for a bad value. Unreachable from the panel, which sends only `SAVEBACK_FORMATS` values (I-10.5); S0: `kind == "s19"` at width 32 → as before (an Intel HEX source has no `source_s0_header`, so the written name, C); otherwise `None` (the HEX emitter takes no S0, `apply.py:674-682`); `source_kind=kind`, which `ChangeService.save_patched` hands to the write and the verify alike (`change_service.py:2624` → `:2444-2454`, `:2469`). Busy refusal, hide, decline, destination, project activation, verify surfacing, the before/after control and its offer unchanged.
module: s19_app/tui/app/patch.py
examples: (R-HEX-SAVE-001.1/1, R-HEX-VERIFY-001.1/1) case01, output `"s19"` → `firmware-patched.s19`, first line starts with `S0`; status `Saved + verified: firmware-patched.s19 — 1 entry applied before this save (0x8000007C)`
examples: (R-HEX-SAVE-001.1/2, R-HEX-VERIFY-001.1/2, R-HEX-VERIFY-002.1/1) case01, output `"hex"`, name `firmware-patched.hex` → `firmware-patched.hex`, first line `:0200000480007A`; status `Saved + verified: firmware-patched.hex — 1 entry applied before this save (0x8000007C)`
examples: (R-HEX-SAVE-001.1/4, R-HEX-VERIFY-002.1/2, R-S19-S0HEADER-001.2/1) the HEX twin, output `"s19"`, width 32, name `firmware-patched.s19` → first line an S0 whose data is `firmware-patched.s19`; status `Saved + verified: firmware-patched.s19 — 1 entry applied before this save (0x8000007C)`
examples: (R-S19-S0HEADER-001.1/1) case01, `"s19"`, width 32 → S0 data `CASE01_BASIC` (C)
examples: (R-S19-S0HEADER-001.3/1, AT-I10-2) the HEX twin, `"s19"`, width 16 → first line `S0030000FC`, data records `S3` of at most `16` data bytes, terminator `S7`
examples: (R-S19-SAVE-REUSE-001.1/1, /2) case01, `"hex"`, width 32 or 16 → no type-00 record holds more than `16` data bytes (C: max_data `16`)
examples: (R-PE-EXPORT.15/1) name `release_v2`, `"hex"` → written `release_v2.hex`
examples: (R-TUI-049.1/3) Applied case01 (Checks), `Write file` → `Write before/after report` a shown widget (the dock), its centre hits itself
examples: (E3-5, unit guard) the loaded kind `"s19"`, a confirm with output_format `None` or `"bin"` → no file in the work area, one `CHG-HEX-SAVE-UNSUPPORTED` issue; never an S19 file
examples: (R-S19-EMIT.11/2, conflict, D8-29 open by D-6 A) case01, `"s19"` → terminator `S7` with address `0x00000000` (C), not the source's 0x80000000; no test in this increment
examples: (neg, R-HEX-SAVE-001.1) `source_kind=loaded.file_type` (the base) with name `firmware-patched.hex` → the engine writes S19 text under `firmware-patched.hex.s19` (C: the suffix rule) → R-HEX-SAVE-001.1/2 RED; the write in the output format but the verify with the loaded kind → `Verify MISMATCH` (C: 8/8 `mismatch`) → R-HEX-VERIFY-001.1/2 RED

PatchMixin._apply_entry_json_edit
req: R-PE-EXPORT.17
in: int index; Optional[str] edited
out: None
func: changed (E3-1; `app/patch.py:937-999`). was: busy refusal; `None` (Cancel) → return; `edit_entry_json(index, edited, a2l_context=…)`, `_report_change_result`, the R-TUI-058.9 line, `_refresh_patch_history_view()`; the save-back prompt untouched. / now: when the edit's result is ok, `self.query_one("#patch_editor_panel", PatchEditorPanel).hide_save_prompt()` right after `_report_change_result` (an edit that replaced the entry changed the document); a refused edit (result not ok: the document is unchanged) and Cancel leave the prompt as it was. Everything else unchanged. The whole-document Edit JSON needs no change: it re-enters through `parse_paste`, which already hides the prompt (`_hide_replaced_document_controls`, `:190`).
module: s19_app/tui/app/patch.py
examples: (R-PE-EXPORT.17/4) a pasted change-set with 0x8000007C `DE AD BE EF`, Apply (prompt shown), entry 0's JSON confirmed with bytes `CA FE BA BE` → the prompt not a shown widget (base: still shown, R)
examples: (neg, R-PE-EXPORT.17) no hide in this path → R-PE-EXPORT.17/4 RED

PatchMixin.on_staging_sheet_stage_requested
req: R-PE-EXPORT.17
in: StagingSheet.StageRequested event
out: None
func: changed (F-R8-3, ruled by the orchestrator P-043; relevo-10, `app/patch.py:322-376` at `7ac47dc5`). was: Inc 8's stage handler: busy refusal; no A2L → the `nothing staged` status; else `describe_definition` fresh, `ChangeService.stage_definition` over `_strip_source_map`, `_report_change_result`, one status line per notice; ok → `panel.note_staged(event.name)`; always `_refresh_patch_history_view()`; the save-back prompt untouched (R: no `hide_save_prompt` anywhere in it). / now: when the result is ok, `panel.hide_save_prompt()` right beside `panel.note_staged(event.name)` (a stage appended or replaced an entry through `ChangeService._stage_encoded`: the document changed); a refused stage (result not ok), the busy refusal and the no-A2L return leave the prompt as it was. Everything else unchanged.
module: s19_app/tui/app/patch.py
examples: (R-PE-EXPORT.17/5) Applied case01 (Inspector), prompt shown, a value staged from Inc 8's staging sheet (the stage handler's result ok) → the prompt not a shown widget (base `7ac47dc5`: still shown, R)
examples: (neg, R-PE-EXPORT.17) no hide in this path → R-PE-EXPORT.17/5 RED

emit_intel_hex_from_mem_map
req: R-HEX-EMIT-001.11, R-HEX-EMIT-001.3, R-S19-SAVE-REUSE-001.1, R-PE-EXPORT.16
in: dict[int, int] mem_map; list[tuple[int, int]] ranges
out: str result
func: changed (E3-2; the row loop `changes/io.py:1997-2004` only, about two lines; signature unchanged, I-10.6). was: `for row_start in range(start, end, 16)`, `row_end = min(row_start + 16, end)`: rows of 16 bytes from the range start, the type-04 word from the row's start only, so a range that starts off a 16-byte boundary and spans 0x00010000 yields a data record that crosses it (`:10FFF800…` for *x64u*). / now: each row ends at `min(row_start + 16, end, (row_start | 0xFFFF) + 1)` and the next row starts where the last ended (a `while row_start < end` walk, not the fixed 16-step `range`, which would skip the bytes after a short row); the type-04 rule, the record format, the order and the EOF are unchanged. Output changes only where a 16-byte row from the range start would cross a 64 KiB boundary; a 16-aligned range (case01, case00, s2src, *x64*) gives the same text as before. The docstring's Data Flow names the boundary.
module: s19_app/tui/changes/io.py
examples: (R-HEX-EMIT-001.11/1, /2) *x64u* (32 bytes `00` … `1F` at 0x0000FFF8) → `:020000040000FA`, `:08FFF8000001020304050607E5`, `:020000040001F9`, `:1000000008090A0B0C0D0E0F1011121314151617F8`, `:0800100018191A1B1C1D1E1F0C`, `:00000001FF` (`../data/x64u.hex`, script `../data/x64u_make.py`)
examples: (R-HEX-EMIT-001.3/2, holds) *x64* (36 bytes at 0x0000FFF0) → 2 type-04 records, rows meet the boundary at a record edge; text unchanged by the fix
examples: (R-IMG-WRITE.2) *x64u* written and read back by the system's reader → the source image, `0` diagnostics
examples: (neg, R-HEX-EMIT-001.11) the base loop → `:10FFF800000102030405060708090A0B0C0D0E0F81` (offset 0xFFF8 + 16 > 0x10000, `../data/x64u-base-emitter.hex`) → /1 RED; the cap added inside the fixed `range(start, end, 16)` → rows 0xFFF8 (8 bytes) then 0x10008: the bytes at 0x00010000 … 0x00010007 never written → /1 RED and the verify `mismatch`

ActionsMixin.hide_save_prompt
req: R-PE-EXPORT.3, R-PE-EXPORT.17, R-CHG-003.2, R-CHG-003.5
in: none
out: None
func: unchanged (`actions.py:303-310`): adds `hidden` to `#patch_saveback_row`, found by id wherever it sits. Its new callers are the zero-apply path of the `apply_doc` arm, the `add_entry` / `edit_entry` / `remove_entry` arms, `_apply_entry_json_edit` (I-10.3; these two since E3-1) and `on_staging_sheet_stage_requested` (relevo-10, F-R8-3).
module: s19_app/tui/screens_directionb/patch_editor/actions.py
examples: (R-CHG-003.5/1) Applied case01 (Checks), `Write file` → the prompt not a shown widget; one new file in the work area
examples: (R-CHG-003.2/1) Applied case01 (Inspector), `Don't save` → the prompt not a shown widget; status `Patch Editor: save-back declined`
examples: (R-PE-EXPORT.17/5, Inc 8 in the base; F-R8-3) Applied case01, a value staged from Inc 8's staging sheet (its stage handler returns ok) → the prompt not a shown widget; the hide is wired in `PatchMixin.on_staging_sheet_stage_requested` (node above, G2)

ActionsMixin.show_before_after_prompt
req: R-TUI-049.1
in: none
out: None
func: unchanged (`actions.py:312-327`): removes `hidden` from `#patch_before_after_row`, found by id; with the row in the dock it is shown from every tab.
module: s19_app/tui/screens_directionb/patch_editor/actions.py
examples: (R-TUI-049.1/1 … /4) `Write file` from each of the four tabs at 118×54 → `Write before/after report` shown at its place (base: inside `#patch_win_json`, shown only from the JSON tab)

ActionsMixin.hide_before_after_prompt
req: R-TUI-049.1
in: none
out: None
func: unchanged (`actions.py:329-343`): adds `hidden` to `#patch_before_after_row` on a new document or image (clear-on-context).
module: s19_app/tui/screens_directionb/patch_editor/actions.py
examples: (holds, `tests/test_before_after_report.py:1273`) the row starts hidden and is hidden again by a document load

PatchMixin._hide_replaced_document_controls
req: R-PE-EXPORT.3
in: PatchEditorPanel panel
out: None
func: unchanged (`app/patch.py:498-527`): `hide_before_after_prompt()` then `hide_save_prompt()` when a document or image is replaced; both rows are found by id, so the dock changes nothing here.
module: s19_app/tui/app/patch.py
examples: (holds, Inc 6 R-TUI-049.3.1) prompt shown, a new image loaded → both rows not shown widgets

_synth_s0_header_from_filename
req: R-S19-S0HEADER-001.2
in: str filename
out: bytes result
func: unchanged (`app/patch.py:61-89`): the typed name, non-ASCII removed, cut to 252 bytes, as S0 header data.
module: s19_app/tui/app/patch.py
examples: (R-S19-S0HEADER-001.2/2, C) `s19_sample-patched.s19` → S0 data `s19_sample-patched.s19`

ChangeService.save_patched
req: R-HEX-SAVE-001.1, R-HEX-VERIFY-001.1
in: Dict[int, int] mem_map; Sequence[Tuple[int, int]] ranges; Path dest_dir; str filename; str source_kind; int bytes_per_line = 32; bytes | None s0_header = None; Optional[Path] source_image_path = None; Optional[Sequence[dict]] mac_records = None; Optional[Sequence[dict]] a2l_tags = None; Optional[Path] workarea_root = None
out: ChangeActionResult result
func: unchanged (`services/change_service.py:2481-2634`): re-derives the image from the whole document and calls `emit_and_verify` with the same `source_kind` (`:2624`).
module: s19_app/tui/services/change_service.py
examples: (R-HEX-VERIFY-001.1/5, C) the 8 conversion sources × S19 w32, S19 w16, Intel HEX w32, Intel HEX w16, `source_kind` = the output format → `32` of `32` verified

ChangeService.emit_and_verify
req: R-HEX-VERIFY-001.1
in: Dict[int, int] image; Sequence[Tuple[int, int]] ranges; Path dest_dir; str filename; str source_kind; int bytes_per_line = 32; bytes | None s0_header = None; Optional[Path] source_image_path = None; Optional[ChangeSummary] summary = None; Optional[Path] workarea_root = None; Optional[Callable[[PlacementResult], None]] on_placed = None
out: ChangeActionResult result
func: unchanged (`:2375-2479`): writes with `save_patched_image(source_kind=source_kind)` (`:2444`) and reads back with `verify_written_image(path, image, source_kind)` (`:2469`): one kind for both.
module: s19_app/tui/services/change_service.py
examples: (R-HEX-VERIFY-001.1/5 neg, C) a file read with the other format's reader → `mismatch`, 8 of 8

save_patched_image
req: R-HEX-SAVE-001.2
in: Dict[int, int] mem_map; Sequence[Tuple[int, int]] ranges; Path dest_dir; str filename; str source_kind; int bytes_per_line = 32; bytes | None s0_header = None; Optional[Path] workarea_root = None; Optional[Callable[[PlacementResult], None]] on_placed = None
out: Tuple[Optional[Path], List[ValidationIssue]] result
func: unchanged (`changes/apply.py:686-874`): sanitizes the name, adds the suffix of `source_kind` when missing in any letter case, places the file (destination unchanged).
module: s19_app/tui/changes/apply.py
modify: [I/O: patched image file] (replace)
examples: (R-HEX-SAVE-001.2/1 … /4, C) `firmware-patched.s19` as `"hex"` → `firmware-patched.s19.hex`; `firmware-patched.HEX` as `"hex"` → `firmware-patched.HEX`; `firmware-patched` as `"hex"` → `firmware-patched.hex`; `firmware-patched.hex` as `"s19"` → `firmware-patched.hex.s19`

render_patched_image
req: R-S19-SAVE-REUSE-001.1, R-PE-EXPORT.16, R-HEX-EMIT-001.11
in: Dict[int, int] mem_map; Sequence[Tuple[int, int]] ranges; str source_kind; int bytes_per_line = 32; bytes | None s0_header = None
out: Optional[bytes] result
func: unchanged (`changes/apply.py:629-683`): picks the emitter by `source_kind`; only the S19 branch takes the width and the S0; an unknown kind (`None` included) → `None`, which `save_patched_image` turns into the `CHG-HEX-SAVE-UNSUPPORTED` refusal (`apply.py:795-812`).
module: s19_app/tui/changes/apply.py
examples: (R-PE-EXPORT.16/1, C) case00 as `"hex"`, width 32 → record types `00` (16), `01` (1), `04` (1) only; no S0 data and no terminator address carried
examples: (R-HEX-EMIT-001.2/1, C) case01 as `"hex"` → first line `:0200000480007A`

verify_written_image
req: R-HEX-VERIFY-001.1, R-IMG-WRITE.2
in: Path written_path; Dict[int, int] intended_mem_map; str file_type
out: VerifyResult result
func: unchanged (`changes/verify.py:119-171`): `file_type` selects the reader; an empty diff → verified.
module: s19_app/tui/changes/verify.py
examples: (R-IMG-WRITE.2/1, C) every one of the 32 conversions → read back equal to the source image, `0` diagnostics

## Entities

[Data: PatchEditorPanel._saveback_format]
in: str
desc: the output format the save-back prompt shows and a confirm carries: `"s19"` or `"hex"` (I-10.5).

[Data: PatchEditorPanel._saveback_width]
in: int
desc: the S19 data bytes per line, 32 or 16; reset to 32 by every prompt; kept across a format change (R-PE-EXPORT.13).

[Data: PatchEditorPanel.SAVEBACK_FORMATS]
desc: `(("s19", "S19", ".s19"), ("hex", "Intel HEX", ".hex"))`: the output formats in press order, their names and their format suffixes.

[Data: LoadedFile.file_type]
in: str
desc: the loaded image's kind, `s19`, `hex` or another; sets the first output format (R-PE-EXPORT.7) and gates the save-back (R-CHG-003.16).

[Interface: export dock]
desc: `#patch_export_dock` under the document row: the apply line, the name box, the Format control, Width (S19 only), `Write file`, `Don't save`; after a save, `Before/after report available:` and `Write before/after report` (I-10.4).
offers: (R-PE-EXPORT.8/1) "Format: S19" → ActionsMixin.on_button_pressed
offers: (R-HEX-SAVE-001.1/2) "Write file" → ActionsMixin.on_button_pressed

[Interface: export dock layout]
desc: `styles.tcss`, the batch-97 patch_editor section (G1): a new rule `#patch_editor_panel #patch_export_dock { width: 100%; height: auto; padding: 0; }` (no horizontal padding, so the prompt's region equals the document row's, R-PE-EXPORT.1; no `patch-docked-group` class on the dock); `#patch_saveback_row` and `#patch_before_after_row` get `padding: 0 1` (split out of the shared rule at `:3146-3152`, which keeps `padding: 0` for the history strip, the execute row and the checks controls); `#patch_saveback_buttons` becomes `layout: horizontal; height: 1` (the two-row grid at `:3159-3167` and its "41-cell pane" comment go); `#patch_saveback_format_button` gets a fixed width equal to the chip width of `Format: Intel HEX` (E2-3); `#patch_saveback_apply_line` `height: auto` (one row at 118 columns, wraps when narrower); `#patch_before_after_row` `layout: horizontal; height: 1`. The region that yields the dock's rows is `#patch_main` (`height: 1fr; min-height: 12`, `styles.tcss:2890-2893`) at `a95d0ea9` and `#patch_sheet_win` (`min-height: 12`, Inc 8 R-PE-DEF.74) after Inc 8 (I-8.3 (b)); Inc 10 edits neither rule, and Inc 8 removes the `#patch_main` rules in a hunk disjoint from these.

[Interface: status line]
desc: the app's status region; the apply's line `Apply: <a> applied, <s> skipped, <b> blocked` (R-CHG-002.16), unchanged and still its last writer.

[Interface: notices]
desc: textual toasts; the `Nothing applied` warning (R-PE-EXPORT.5); none on a successful apply (R-PE-EXPORT.6).

[I/O: patched image file]
desc: the file a save-back writes in the open project's folder or the work area (R-CHG-003.8, unchanged), in the output format.

[Outside: Apply loaded changes]
desc: the operator presses `Apply loaded changes` in the document row, from any inspector tab.

[Outside: Format press]
desc: the operator clicks the Format control (no key: O-4).

[Outside: Write file press]
desc: the operator clicks `Write file`.

[Outside: entry change]
desc: the operator adds, edits or removes an entry: Add, Edit or Remove in the entry form, or Confirm in the per-entry Edit JSON popup (E3-1); also a value staged from the staging sheet (Inc 8 `PatchMixin.on_staging_sheet_stage_requested`, which appends or replaces an entry: finding F-R8-3; Inc 10 wires its hide, relevo-10).

## Edges

[Outside: Apply loaded changes] ──▶ PatchMixin.on_patch_editor_panel_action_requested
when: action `apply_doc`
[Data: LoadedFile.file_type] ──▶ PatchMixin.on_patch_editor_panel_action_requested
PatchMixin.on_patch_editor_panel_action_requested ──▶ ActionsMixin.show_save_prompt
when: at least one applied entry on an S19 or Intel HEX image
PatchMixin.on_patch_editor_panel_action_requested ──▶ ActionsMixin.hide_save_prompt
when: no applied entry
PatchMixin.on_patch_editor_panel_action_requested ──▶ [Interface: notices]
when: no applied entry
PatchMixin.on_patch_editor_panel_action_requested ──▶ [Interface: status line]
ActionsMixin.show_save_prompt ──▶ ActionsMixin._set_saveback_format
ActionsMixin.show_save_prompt ──▶ [Interface: export dock]
[Outside: Format press] ──▶ ActionsMixin.on_button_pressed
ActionsMixin.on_button_pressed ──▶ ActionsMixin._set_saveback_format
when: the button is `#patch_saveback_format_button`
[Data: PatchEditorPanel.SAVEBACK_FORMATS] ──▶ ActionsMixin._set_saveback_format
ActionsMixin._set_saveback_format ──▶ [Data: PatchEditorPanel._saveback_format]
ActionsMixin._set_saveback_format ──▶ [Interface: export dock]
[Outside: Write file press] ──▶ ActionsMixin.on_button_pressed
[Data: PatchEditorPanel._saveback_format] ──▶ ActionsMixin.on_button_pressed
when: `Write file` is pressed (the value rides `SaveBackDecision.output_format`)
[Data: PatchEditorPanel._saveback_width] ──▶ ActionsMixin.on_button_pressed
when: `Write file` is pressed
ActionsMixin.on_button_pressed ──▶ PatchMixin.on_patch_editor_panel_save_back_decision
when: `Write file` or `Don't save` (a `SaveBackDecision` message)
[Data: LoadedFile.file_type] ──▶ PatchMixin.on_patch_editor_panel_save_back_decision
PatchMixin.on_patch_editor_panel_save_back_decision ──▶ ActionsMixin.hide_save_prompt
PatchMixin.on_patch_editor_panel_save_back_decision ──▶ _synth_s0_header_from_filename
when: output S19 at width 32 and the source has no S0 data
PatchMixin.on_patch_editor_panel_save_back_decision ──▶ ChangeService.save_patched
ChangeService.save_patched ──▶ ChangeService.emit_and_verify
ChangeService.emit_and_verify ──▶ save_patched_image
save_patched_image ──▶ render_patched_image
save_patched_image ──▶ [I/O: patched image file]
ChangeService.emit_and_verify ──▶ verify_written_image
[I/O: patched image file] ──▶ verify_written_image
PatchMixin.on_patch_editor_panel_save_back_decision ──▶ ActionsMixin.show_before_after_prompt
when: the save succeeded
PatchMixin._hide_replaced_document_controls ──▶ ActionsMixin.hide_before_after_prompt
PatchMixin._hide_replaced_document_controls ──▶ ActionsMixin.hide_save_prompt
ActionsMixin._compose_doc_controls ──▶ [Interface: export dock]
LayoutMixin.compose ──▶ ActionsMixin._compose_doc_controls
when: once, after the file row and before the legend (I-8.3 (a))
LayoutMixin.compose ──▶ ActionsMixin._compose_action_bar
when: inside `#patch_win_json`
[Outside: entry change] ──▶ PatchMixin.on_patch_editor_panel_action_requested
when: action `add_entry`, `edit_entry` or `remove_entry`
PatchMixin.on_patch_editor_panel_action_requested ──▶ ActionsMixin.hide_save_prompt
when: an entry is added, edited or removed
[Outside: entry change] ──▶ PatchMixin._apply_entry_json_edit
when: Confirm in the per-entry Edit JSON popup
PatchMixin._apply_entry_json_edit ──▶ ActionsMixin.hide_save_prompt
when: the per-entry edit is ok
[Outside: entry change] ──▶ PatchMixin.on_staging_sheet_stage_requested
when: a formula staged from the staging sheet (Inc 8)
PatchMixin.on_staging_sheet_stage_requested ──▶ ActionsMixin.hide_save_prompt
when: the stage is ok
render_patched_image ──▶ emit_intel_hex_from_mem_map
when: the kind is `hex`

## Findings

> E2-1 (interpretation). E1's new function `_switch_saveback_format(self)` (sets the other format) is designed as `_set_saveback_format(self, output_format, rename)`: the one writer of the format, its label and the Width visibility, called by `show_save_prompt` (`rename=False`) and by the Format press (`rename=True`). Two writers would let R-PE-EXPORT.9 / .10 / .11 hold after a press and fail after a new prompt, or the reverse. Still one new function; no row changes.
> E2-2 (interpretation). `show_save_prompt`'s two new inputs are keyword-only and have no default (I-10.1): a default `"s19"` would let a caller show an Intel HEX image's prompt as S19 and pass R-PE-EXPORT.7/1 while failing /2. Cost: the one test that calls it, `tests/test_tui_patch_layout.py:594`, passes them at E4 (E2-10).
> E2-3 (design gap in E1's slice, closed here). The Format chip's label changes length (`Format: S19`, 11 cells; `Format: Intel HEX`, 17), so with `width: auto` before Width it would move `Write file` and `Don't save` by 6 cells on every press — R-PE-EXPORT.12 RED. The chip gets the fixed width of its longest label plus the Button's line-pad (19 cells; E4 integration note below, E5 wording fix) (entity `[Interface: export dock layout]`). The alternative, the Format chip after `Don't save`, was rejected: it reads after the commit button and splits the two selectors.
> E2-4 (for E3 and E4: no measurement at E2). No runner ran in this stage (the operator's PC runs no tests; no runner probe was briefed). The y positions of R-PE-EXPORT.1/1 and R-TUI-063.1/2 are derived (D) from E1's census at `e07fb00` plus the dock's 3 rows. Since then batch-103 Inc 6 made the A2L tab taller (pick-mode picker with include and bulk controls, a 3-row status, `screens_directionb.py:5235-5236`): whether the A2L tab still fits `#patch_main` minus 3 or 4 rows without scrolling the Patch Editor (R-PE-EXPORT.2/4, /8) is unmeasured. `#patch_main`'s `min-height: 12` keeps the dock on screen either way at 118×54 (35 − 4 = 31 rows ≥ 12, C); a pane that needs more rows scrolls inside itself. E4's G-T1 measures it first; E3 may ask for a probe.
> E2-5 (design detail). The dock carries no `patch-docked-group` class and has `padding: 0`, so `#patch_saveback_row`'s region equals `#patch_doc_controls`'s (both `width: 100%` of the panel), as R-PE-EXPORT.1's threshold reads it; the two rows inside get `padding: 0 1` so their text starts in the column of the document row's first chip.
> E2-6 (for E3: consequences of a converted file outside the prompt, R; no row changes). (a) A save into an open project activates the written file as the project's variant (`_activate_project_file`, `app.py:16149`): after an S19 → Intel HEX export the project holds a `.hex` variant beside the `.s19` source; `validate_project_files` takes both (`workspace.py:2160`). (b) The before/after report re-reads both sides by suffix (`before_after_service.py:176-178`), so a converted file is read with its own reader. (c) Save project afterwards still emits the loaded image's format (`_decide_project_image`, `app.py:13945`, out of scope: E1 §1). (d) The verified status names the file, not its folder (E1 D-7 backlog note).
> E2-7 (for E3; no row asks). At sizes under 118 × 54 the Patch Editor scrolls (R-TUI-064.1's floor), so after Apply the dock can sit below the fold, displayed but outside the screen; R-CHG-003.1's thresholds are 118×54 and 220×60. Whether `show_save_prompt` should also scroll the dock into view (one call, `scroll_visible`) needs a row; not added at E2.
> E2-8 (security lens, for E3). New inputs: none from outside the program. The output format crosses one boundary (panel → app message) and is checked against `("s19", "hex")` before it reaches the engine; any other value falls back to the loaded kind, and the engine refuses any kind outside its emitter table (`render_patched_image` → `None`, R-CHG-003.16). The name box's suffix replacement edits operator text only at its end and the written name still passes the existing sanitizer (F-S-01, `save_patched_image`). The destination rule, the placement and the verify are unchanged. The apply line and the notice hold only integers from the apply's counts — no file name (B′ would paint the loaded file's name and engage R-PE-005; O-1).
> E2-9 (overlaps). Inc 1b (merged into this base) does not touch `screens_directionb.py` and edits other `app.py` regions. Inc 6 (merged) changed `__init__` and `compose` outside the save-back parts (E1-slice §5, E2-4). Inc 8 and Inc 9 (W2, not started) will edit `PatchEditorPanel.compose` (the pe-mix staging sheet): they start from I-10.4 and keep R-PE-EXPORT.1 / R-TUI-063.1. Batch-101 Inc 12 (merged): no dialog, key or action here, so R-DLG.14 and R-SHELL-KEYS.3 are untouched.
> E2-10 (E4 work: tests that change; R, `git grep` at `287b9dc3`). Re-home `#patch_saveback_row` / `#patch_before_after_row` from `#patch_win_json` to `#patch_export_dock`: `tests/test_b97_patch_editor.py:1418-1426` (and the `CONTAINER_IDS` list `:52-60`, types kept), `tests/test_tui_patch_layout.py:190-197` and AT-064c `:715-730` ("siblings of the JSON window body"); pass the new arguments at `tests/test_tui_patch_layout.py:594`; replace the `hidden`-class reads with shown-widget reads at `tests/test_tui_patch_editor_v2.py:302`, `:574` and `tests/test_b100_active_variant.py:1064` (they pass on base while the operator sees nothing). `tests/test_before_after_report.py:1149`, `:1273` read the row by id and keep working.
> E2-11 (size). 18 nodes — changed 7, new 1, context 10 — 12 entities, 31 edges; 3 source files (`screens_directionb.py`, `app.py`, `styles.tcss`). 8 module nodes change: one agent designed it (no split); E4 splits by file (G1, G2).

### E3 correction (2026-11-12; rulings `../E3-rulings.md`)

> E3-1 → R-PE-EXPORT.17: the `add_entry` / `edit_entry` / `remove_entry` arms of `on_patch_editor_panel_action_requested` and the changed node `PatchMixin._apply_entry_json_edit` call `hide_save_prompt` (owner G2; edges "when: an entry is added, edited or removed" and "when: the per-entry edit is ok"). The fourth path (per-entry Edit JSON) was found at the correction: it edits an entry and did not hide the prompt (R, `app.py:5990-6052`). R-PE-EXPORT.3's cases now re-show the prompt through I-10.1 before the zero apply.
> E3-2 → R-HEX-EMIT-001.11: node `emit_intel_hex_from_mem_map` changed (owner G3 = `changes/io.py`, the 4th source file; interface I-10.6). The reviewer's one-line cap (`row_end` capped inside the `range(start, end, 16)` loop) would skip the 8 bytes after the short row; the node says the next row starts where the last ended. Third-party tool interop (objcopy, srec_cat) is not verified here: an E5 runner check.
> E3-5 → I-10.2 has no `"s19"` default; E2-14's silent fallback is gone: a bad or missing output format reaches the engine and is refused (`CHG-HEX-SAVE-UNSUPPORTED`), stated in node `on_patch_editor_panel_save_back_decision`.
> E3-6 → R-PE-EXPORT.14 / .15 reworded; `_set_saveback_format`'s rule takes trailing whitespace (`\s*\Z`); case R-PE-EXPORT.14/4.
> Size after E3: 20 nodes — changed 9, new 1, context 10 — 13 entities, 36 edges; 4 source files (`screens_directionb.py`, `app.py`, `styles.tcss`, `changes/io.py`), one owner group each (G1, G2, G1, G3).

### Re-map to a95d0ea9 (relevo-8, 2026-11-13; `../E1-slice.md` §7, `../E1-rulings.md` "Re-map to a95d0ea9 (relevo-8)")

> R8-G1 (modules). 13 of the 20 E3 nodes moved module verbatim (same AST, census), and the one new node lands in a new module too: `PatchEditorPanel.__init__` and `SaveBackDecision.__init__` to `panel.py`; `on_button_pressed`, `show_save_prompt`, `hide_save_prompt`, `show_before_after_prompt`, `hide_before_after_prompt` and the new `_set_saveback_format` to `patch_editor/actions.py` (`ActionsMixin`); the three app handlers, `_hide_replaced_document_controls` and `_synth_s0_header_from_filename` to `app/patch.py` (`PatchMixin`, module level). The engine nodes stay (files identical).
> R8-G2 (I-8.3). E2's `PatchEditorPanel.compose` node is now `ActionsMixin._compose_action_bar` (changed: the two prompt blocks leave) and `ActionsMixin._compose_doc_controls` (changed: the dock is yielded after `#patch_doc_controls`), with `LayoutMixin.compose` as a context node that Inc 10 never edits (Inc 8 is `layout.py`'s one writer). The dock is at most 4 rows at 118×54 and 220×60 (`_compose_doc_controls`'s example), equal to Inc 8's stand-in.
> R8-G3 (extractor list, `../evidence-remap/i10-remap-extract-transcript.txt`, ruled). Run 1 (21 baseline nodes, 21 marks): 3 drifts, all the PROPOSED I-10.1 / I-10.2 inputs — **expected**, as at E2. Run 2: the same plus `ActionsMixin._set_saveback_format` without a mark — **expected** (the one new node). Call sites in the report are the marked clone's lines, a few below the census's. `on_patch_editor_panel_action_requested → _hide_replaced_document_controls` at the clone's `patch.py:1498` and `→ save_patched_image` at `variant_execution_service.py:2584` — **misattributions** (the nearest marked node; the real callers are `_patch_editor_load` and `_execute_one_variant`, as E2 ruled). Top-level sites (`compose_screens.py:540`, the dismiss lambda at the clone's `patch.py:936`, undo / redo, `segment_ops.py:507`, `save_plan.py:1145`, `save_commit.py:805`, `:817`, `flow_execution_service.py:727`, `:746`, `operations/crc.py:1524`) — **the census's callers**, none new. 36 ambiguous resolutions — names shared by several defs (`__init__`, `on_button_pressed`, …); every edge the report lists was checked against the census.
> R8-G4 (a blind spot of the extractor after the split; method note for every increment graphed on the package). `LayoutMixin.compose → ActionsMixin._compose_action_bar` / `_compose_doc_controls` is not in the report: the extractor resolves `self.m()` only to a method of the enclosing class (`codewire_extract.py:574`), and the split puts caller and callee in different mixins of one class. The two edges are R (census: `layout.py:67`, `:77`). Any cross-mixin `self.` call of the package is invisible to X in the same way; Inc 8's and Inc 9's graphs on the package have the same limit (finding F-R8-5 for the orchestrator; not a defect of Inc 10's design).
> Size after the re-map: 22 nodes — changed 10, new 1, context 11 — 13 entities, 38 edges; lint `not read=0`, exit 0. 5 source files (`panel.py`, `actions.py`, `styles.tcss` = G1; `app/patch.py` = G2; `changes/io.py` = G3), one owner group each.

### Prep onto Inc 8 final (relevo-10, 2026-11-14; `../E1-slice.md` §8)

> R10-G1 (base). `b103-inc10` rebased onto `b103-inc8` tip `7ac47dc5` (E5 PASS-WITH-NOTES); records only, `git diff 7ac47dc5..HEAD --stat -- s19_app tests` empty. Every Inc 10 node has the same AST as at `a95d0ea9` (offsets only); Inc 8's DIFFs are context: `LayoutMixin.compose`, `PatchEditorPanel.__init__` / `_show_tab` / `_TABS`.
> R10-G2 (F-R8-3, ruled P-043). Inc 8 did not add the hide: `PatchMixin.on_staging_sheet_stage_requested` (`app/patch.py:322-376`) never calls `hide_save_prompt` (R, `git grep` at `7ac47dc5`). It is now node 23 of this graph, changed, group G2, with edges `[Outside: entry change] ──▶ it` and `it ──▶ ActionsMixin.hide_save_prompt`; case R-PE-EXPORT.17/5.
> R10-G3 (extractor, `../evidence-remap/i10-prep-extract-transcript.txt`). Same result as at `a95d0ea9`: run 1 (22 baseline nodes) the 3 expected drifts (PROPOSED I-10.1 / I-10.2); run 2 + `_set_saveback_format` without a mark; lint exit 0. Cross-mixin blind spot R8-G4 unchanged: `LayoutMixin.compose → _compose_action_bar` (`layout.py:77`) and `→ _compose_doc_controls` (`layout.py:81`, once, after `_compose_file_row` at `:80`) are R.
> Size after the prep: 23 nodes — changed 11, new 1, context 11 — 13 entities, 40 edges; lint `not read=0`, exit 0. 5 source files (`panel.py`, `actions.py`, `styles.tcss` = G1; `app/patch.py` = G2; `changes/io.py` = G3), one owner group each.

### Coverage (every requirement and case → node and example)
| Requirement or case | Nodes | Examples (source) |
|---|---|---|
| R-CHG-003.1 | `_compose_doc_controls`, `_compose_action_bar`, `show_save_prompt`, `on_patch_editor_panel_action_requested` | /1 … /8 the four tabs at both sizes, /9 Intel HEX (cases; base C) |
| R-PE-EXPORT.1 | `_compose_doc_controls` (+ `[Interface: export dock layout]`) | /1 (D: rows 38, 39–41, 42), /2 (as /1 at 220×60) |
| R-TUI-063.1 | `_compose_doc_controls` | /1, /3 prompt hidden (C), /2, /4 prompt shown (D) |
| R-PE-EXPORT.2 | `_compose_doc_controls` | /1 … /10 (cases; the A2L tab unmeasured on this base, E2-4), /11 the 4-row dock (re-map, I-8.3 fit) |
| R-TUI-049.1 | `_compose_doc_controls`, `show_before_after_prompt`, `on_patch_editor_panel_save_back_decision` | /1 … /4 from each tab |
| R-PE-EXPORT.3 | `on_patch_editor_panel_action_requested`, `hide_save_prompt`, `_hide_replaced_document_controls`, `show_save_prompt` (re-show, I-10.1) | /1, /2 (base C), /3; each re-shows the prompt through I-10.1 after its entry change (E3-1) |
| R-PE-EXPORT.17 | `on_patch_editor_panel_action_requested`, `_apply_entry_json_edit`, `on_staging_sheet_stage_requested`, `hide_save_prompt` | /1 Add, /2 Edit, /3 Remove, /4 per-entry Edit JSON (E3-1); /5 a stage from Inc 8's staging sheet (Inc 8 is in the base; F-R8-3) |
| R-PE-EXPORT.4 | `on_patch_editor_panel_action_requested`, `show_save_prompt`, `_compose_doc_controls` | /1, /2, /3 (text A′, O-1) |
| R-PE-EXPORT.5 | `on_patch_editor_panel_action_requested` | /1 no image, /2 outside, /3 blocked |
| R-PE-EXPORT.6 | `on_patch_editor_panel_action_requested` | /1 S19, /2 Intel HEX (0 notices) |
| R-PE-EXPORT.7 | `show_save_prompt`, `_set_saveback_format`, `on_patch_editor_panel_action_requested`, `__init__` | /1 `S19`, /2 `Intel HEX`, /3 reset after `Don't save` |
| R-PE-EXPORT.8 | `on_button_pressed`, `_set_saveback_format`, `SaveBackDecision.__init__` | /1 → `:`, /2 → `S0` |
| R-PE-EXPORT.9 | `_set_saveback_format`, `_compose_doc_controls` | /1 `S19`, /2 `Intel HEX` |
| R-PE-EXPORT.10 | `_set_saveback_format`, `show_save_prompt` | /1 HEX image, /2 after a switch (not painted, no focus, click inert) |
| R-PE-EXPORT.11 | `_set_saveback_format`, `_compose_doc_controls` | /1 `Width: 32 bytes/line`, /2 after HEX → S19 |
| R-PE-EXPORT.12 | `_set_saveback_format` (+ layout) | /1 … /4 regions equal (E2-3) |
| R-PE-EXPORT.13 | `_set_saveback_format` | /1 width 16 kept |
| R-PE-EXPORT.14 | `_set_saveback_format` | /1 `.s19` → `.hex`, /2 `MyImage.S19` → `MyImage.hex`, /3 `a.hex` → `a.s19`, /4 `firmware-patched.s19 ` → `firmware-patched.hex` (E3-6) |
| R-PE-EXPORT.15 | `_set_saveback_format`, `on_patch_editor_panel_save_back_decision` | /1 `release_v2` → written `release_v2.hex`, /2 `x.bin` → `x.bin.hex` |
| R-HEX-SAVE-001.1 | `on_patch_editor_panel_save_back_decision`, `on_button_pressed`, `SaveBackDecision.__init__` | /1 … /4 the four directions |
| R-HEX-SAVE-001.2 | `save_patched_image` | /1 … /4 (C) |
| R-S19-SAVE-REUSE-001.1 | `on_patch_editor_panel_save_back_decision`, `render_patched_image` | /1 … /4 (C: ≤ 16 bytes) |
| R-PE-EXPORT.16 | `render_patched_image`, `on_patch_editor_panel_save_back_decision` | /1 … /8 (C: types 00, 01, 04) |
| R-S19-S0HEADER-001.1 | `on_patch_editor_panel_save_back_decision` | /1 `CASE01_BASIC`, /2 `Debug\stm8s003.sm8` (C); /3 `conflict` (D8-27) |
| R-S19-S0HEADER-001.2 | `on_patch_editor_panel_save_back_decision`, `_synth_s0_header_from_filename` | /1 … /4 the written name (C); /5 `conflict` (D8-28) |
| R-S19-S0HEADER-001.3 | `on_patch_editor_panel_save_back_decision` | /1 … /4 `S0030000FC` (C) |
| R-S19-EMIT.11 | `on_patch_editor_panel_save_back_decision` | /1, /2 `conflict` (D8-29): address 0 today (C) |
| R-HEX-VERIFY-001.1 | `on_patch_editor_panel_save_back_decision`, `ChangeService.save_patched`, `ChangeService.emit_and_verify`, `verify_written_image` | /1 … /4 statuses, /5 32/32 and the 8/8 negative (C) |
| R-HEX-VERIFY-002.3 | `show_save_prompt`, `on_patch_editor_panel_action_requested` | /1 `firmware-patched.s19`, /2 `firmware-patched.hex` |
| R-S19-WIDTH-001.1 | `show_save_prompt` | /1 reset to 32 |
| R-S19-WIDTH-001.2 | `on_button_pressed` (Width branch, unchanged) | /1 32 → 16 → 32 in the dock |
| R-CHG-003.2 | `hide_save_prompt`, `on_patch_editor_panel_save_back_decision` | /1 from the Inspector tab |
| R-CHG-003.5 | `hide_save_prompt` | /1 from the Checks tab |
| R-HEX-VERIFY-002.1 | `on_patch_editor_panel_save_back_decision` | /1 S19 → Intel HEX, /2 Intel HEX → S19 |
| R-S19-EMIT.3, .4, .5 | `render_patched_image` | S1 / S9, S2 / S8 (2 cases), S3 / S7 (C) |
| R-HEX-EMIT-001.2, .3 | `render_patched_image`, `emit_intel_hex_from_mem_map` | `:0200000480007A`; 2 type-04 records (2 cases) (C) |
| R-HEX-EMIT-001.11 | `emit_intel_hex_from_mem_map`, `render_patched_image` | /1 *x64u* S19 source, /2 its HEX twin → `../data/x64u.hex` line for line (E3-2) |
| R-IMG-WRITE.2 | `verify_written_image` | 32/32 equal, 0 diagnostics (C) |
| R-TUI-064.1 | `_compose_doc_controls` | /1, /2 Validate, Apply, Save on screen with the prompt shown |
| R-TUI-064.2 | `_compose_doc_controls` | /1 ≤ 116 cells (D: ~65 and 85), /2 ≤ 218 |
| R-TUI-064.4 | `_compose_doc_controls` | /1 four chips of height 1 |
| AT-I10-1 | `_compose_doc_controls`, `on_patch_editor_panel_action_requested`, `on_button_pressed`, `_set_saveback_format`, `on_patch_editor_panel_save_back_decision` | the chain of examples R-PE-EXPORT.4/1 → .14/1 → R-HEX-SAVE-001.1/2 → R-HEX-VERIFY-001.1/2 |
| AT-I10-2 | the same nodes | R-PE-EXPORT.7/2 → .11/2 → R-S19-S0HEADER-001.3/1 (`S0030000FC`, S3 ≤ 16, `S7`) |
| AT-I10-3 | `on_patch_editor_panel_action_requested`, `hide_save_prompt` | R-PE-EXPORT.17/3 (Remove hides the prompt) and .5/2 (notice, prompt still hidden, byte 0x3C) |

> Every active row of `../01-requirements.md`, every cited row with cases and every AT has at least one concrete example; the four `conflict` cases (R-S19-S0HEADER-001.1/3, .2/5, R-S19-EMIT.11/1, /2) have their base value as the example and no test here (D-6 A).

## E4 integration amendment (I10, P-022 ruling; appended, nothing above rewritten)

The P-022 ruling folds D8-28 and BL-I10-E3-8 into Inc 10 (DF-04 a: a defect against R-S19-S0HEADER-001.2, "the written file name"). The fix changes three context nodes and adds one; no interface I-10.x or I-8.x changes (the new keyword is optional, default `None`, and every other caller of the three nodes passes nothing new).

- `PatchMixin.on_patch_editor_panel_save_back_decision` (changed again): S0 at width 32 as S19 → `s0_header = loaded.source_s0_header or None`; when that is `None`, `s0_header_from_name = _synth_s0_header_from_filename` (the rule, passed as a value, not called here). Width 16 / Intel HEX → both `None`. Edge `──▶ _synth_s0_header_from_filename` becomes "passes the rule to `ChangeService.save_patched`".
- `ChangeService.save_patched`, `ChangeService.emit_and_verify` (changed: signature): `+ Optional[Callable[[str], bytes]] s0_header_from_name = None`, forwarded unchanged.
- `save_patched_image` (changed): `+ s0_header_from_name`; for an `"s19"` source, after the destination guard and before staging, the payload is re-rendered by `_render_named_by_landing`. req: + R-S19-S0HEADER-001.2.
- `_render_named_by_landing` (new, `changes/apply.py`): header from the current name → `render_patched_image` → `predict_placement(payload, size, dest_dir, safe_name)` (the placement's own rule, `workspace.py`) → stop when the landing name equals the header's name, else take the landing name; at most 3 rounds. New edges: `save_patched_image ──▶ _render_named_by_landing`, `_render_named_by_landing ──▶ render_patched_image`, `_render_named_by_landing ──▶ predict_placement`.
- `_synth_s0_header_from_filename` (unchanged body): now applied to the landing name (bare, suffix forced, numbered), never to the typed text.

examples: (R-S19-S0HEADER-001.2/5, D8-28) the HEX twin, `"s19"`, width 32, typed `firmware-patched.s19`, a different file already holding that name → written `firmware-patched_1.s19`, S0 data `firmware-patched_1.s19`; the other file unchanged
examples: (R-S19-S0HEADER-001.2/5, BL-I10-E3-8) typed `C:\Users\<user>\Desktop\fw.s19` or `~/fw.s19` → written `fw.s19`, S0 data `fw.s19`, no byte of the account folder in the file; typed `C:\Users\<user>\Desktop\fw` → `fw.s19` / `fw.s19`; typed `…\fw_é.s19` → written `fw_é.s19`, S0 data `fw_.s19`
examples: (neg) the header built from the typed text (the code before the fix) → all five RED (`E4-integration.md`)

Known limit (not a defect of the rule): a file created by another process between the prediction and the placement can make the landing name differ from the header's; the same window LLR-163.7 documents for the save plan.

E4 integration note on E2-3 (appended): "the fixed width of its longest label" is 19 cells in the code, not 17: Textual 8.2.8's `Button` paints its label with `line-pad: 1` on each side, so at width 17 the label `Format: Intel HEX` wrapped and only `Format: Intel` was painted (R-PE-EXPORT.7/2, .9/2, .8/1, AT-I10-1, AT-I10-2 RED at the first GREEN run). `styles.tcss` `#patch_saveback_format_button { width: 19; }` (commit `9d78a652`).
