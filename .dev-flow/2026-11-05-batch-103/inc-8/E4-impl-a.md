# Inc 8 E4 - group A (staging and help), hand-back

Implementer `impl-a`, claude-sonnet-5-5. Commit `fdf7738e` (code). Files: `s19_app/tui/services/change_service.py`, `s19_app/tui/app/patch.py`, `s19_app/tui/window_help.py`.

## Done
- `ChangeActionResult.notices: tuple[str, ...] = ()` (A1').
- `ChangeService.stage_definition(definition, a2l_data, text, image)` (A1/A1'): `StagedOverlay(image, entries)`, `encode_definition`, refusal -> `Patch Editor: <message>`, else `_stage_encoded(name, encoded, shown)`; `shown` = decode over the new overlay; encode notices -> `notices` as `Patch Editor: <notice>`.
- `ChangeService._stage_encoded(name, encoded, shown)` (I-8.2, A2/A2'): partial overlap -> refuse, no history; equal span -> `_push_history`, replace with a bytes entry keeping the old symbol; none -> `_push_history`, append bytes entry with symbol `name`; message through `name_echo` for name and shown.
- `PatchMixin.on_staging_sheet_stage_requested` (A3/A3'): `_refuse_if_busy()` first; no A2L -> `nothing staged` status; fresh `describe_definition`; `stage_definition(..., _strip_source_map(current_file))`; `_report_change_result`; one `set_status` per notice; ok -> `panel.note_staged(event.name)`; always `_refresh_patch_history_view()`. `StagingSheet` imported under `TYPE_CHECKING` only.
- `WINDOW_HELP_SECTIONS["patch"]` (A4): new step 1, `Patch script`, `STAGING SHEET`, `new =`, `field =`, `text =`; the `A2L` line leaves; Filter/Prev/Next name the filter row's list; `Use parameter` names the Inspector tab and the selected row.

## Run (rtx, isolated env, load 1.33; `s19_app.__file__` printed as the scratch tree's `s19_app/__init__.py`)
Scratch script outside the repo. `definition_sheet.py` was NOT yet committed when I ran, so the scratch tree used a stand-in (`StagedOverlay`, `name_echo`: ~15 lines, scratch only, not in the repo). Results with the stand-in are therefore **held against the stand-in**; re-run once S1 lands.
- EX-S1/P1 held: entry `0x800020 (0,51)` symbol DISPLAY_0001, message `Patch Editor: DISPLAY_0001 staged as 25.5 (2 B at 0x800020).`, undo +1.
- EX-S5 held: second stage -> 1 entry `(0,60)`, undo 2.
- ENUM `RUN` held: `(2,)` at 0x800000, `staged as RUN (1 B at 0x800000)`.
- EX-O1 held: FIELD 255 `(31,247)` then BIT 0 -> `(31,246)`, symbol MASK_FIELD_0001.
- EX-P7, EX-P3 held: ok False, `Patch Editor: DISPLAY_0001: 250 is outside the extended limits -50..200` / `'abc' is not a number`, no entry, undo 0.
- EX-D4 held for the notice (`notices == ('Patch Editor: DISPLAY_0001: 175 is outside the limits -40..150 and inside the extended limits -50..200',)`, issues `[]`); the stage line read `staged as 175.0`, see finding 1.
- EX-O3 held (source-view case, emulated by Remove between the stages): entry `(26,230)` = `1A E6`.
- EX-F1 held: ok False, `Patch Editor: DISPLAY_0001 overlaps the entry at 0x800021 - remove that entry first.` (em dash), entries unchanged, undo 0.
- EX-S8 held: V171 string entry replaced by one bytes entry, value None, serialized text holds `"type": "bytes"`. (Round trip through reload not run.)
- EX-S9 held: message holds 256 x `x` + `...` (U+2026) before ` (2 B`.
- EX-HL1 held: lines `Patch script`, `STAGING SHEET`, `new =`, `field =`, `text =`, `Use parameter` exist; no `A2L` key; `Inspector` and `selected row` in `Use parameter`, `A2L tab` not; `entries` in `Patch script`; `STAGING SHEET` holds `↑↓ enter ←→ esc`; no banned phrase in the body.
- **Could not run** (need app + `StagingSheet` + `PatchEditorPanel.note_staged`, not committed): handler examples EX-B1, EX-F2, EX-F3, the handler forms of EX-S1/EX-D4/EX-P3, R-PE-DEF.60/.62/.64/.73, TC-B97-32 (full Patch help law with the app).
- Only `ast.parse` ran on the PC; no pytest run (no tests in group A).

## Findings / deviations
1. EX-D4 handler example says `staged as 175`; the node text and R-PE-DEF.58 say `<text>` is the staged value's **decoded** text, which for DISPLAY_0001 (decimals 1) is `175.0`; likewise a typed `30` shows `30.0`. I followed the requirement and node text; the example's `175` was never computed (not in the pilot transcript). Needs an orchestrator ruling or a wording fix of EX-D4.
2. Graph `stage_definition` func says `shown = the decode over the new overlay's text`; on a decode Refusal (cannot happen after a successful encode, defensive) I fall back to the typed text.
3. Commit `fdf7738e` lacks the Co-Authored-By trailer (tree shared; no amend).
4. `window_help.py`: the old `A2L tab` text is gone from the Patch section only; other sections still say it (not mine).
5. `add_symbol_entry` untouched (kept, per E1 slice).
