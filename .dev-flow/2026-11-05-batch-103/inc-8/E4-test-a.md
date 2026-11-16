# Inc 8 E4 — tester `test-a` (group A: staging and help)

Evidence states: `executed` = run on the runner and read from one complete run's output; `planned` = written, not run against the product; `not-run` = could not be run here.

## Tests on disk (real paths; cases in `02-test-cases-A.md`, 48 cases)
| File | Tests | Drives |
|---|---|---|
| `tests/test_b103_inc8_a1_service.py` | 23 (22 + control) | `ChangeService.stage_definition`, `_stage_encoded` (I-8.2), `notices`, history, serialize/parse round trip |
| `tests/test_b103_inc8_a2_app.py` | 23 (22 + control) | real Pilot app: `StagingSheet.StageRequested` -> `on_staging_sheet_stage_requested`, dirty flag, status log, `note_staged`, painted sheet rows |
| `tests/test_b103_inc8_a3_help.py` | 9 (8 + control) | `WINDOW_HELP_SECTIONS["patch"]` parsed as TC-B97-32 does |
| `tests/b103_inc8_a_support.py` | fixtures | DEFC through the shipped CLI, V171 hand image, moved-address A2L |

## Results (state)
- **Help (R-PE-DEF.83 … .87): RED on base `d5d48685`, executed.** 8 failed, 1 passed (the control). Transcript with `s19_app.__file__` at the top: `evidence-e4/test-a-red-help-base.txt`. GREEN: `not-run` (needs group A's `window_help.py`, not in this tree).
- **Service (A1, A2, A1', A2'): new functions, no RED claimed** (`evidence-e4/test-a-base-service.txt`: 22 AttributeError, the control passes). GREEN: `not-run`.
- **App (A3, A3', note_staged, sheet mark): `executed` on base only up to the missing `#patch_sheet`** (22 of 23 fail with `#patch_sheet: expected exactly 1 widget, found 0`, so the A2L/image load, the panel and the picker page of every test run; `test_r_pe_def_62_3` fails earlier at the missing `stage_definition` while building its pasted document). GREEN: `not-run`; the sheet and handler are in other groups' trees.
- **Logic check, not GREEN evidence:** the service tests pass 23/23 against a scratch reference of I-8.2 written from the spec only, and the help tests 9/9 against a scratch reference help body (`evidence-e4/test-a-logic-check-reference.txt`). This shows the assertions can pass for a spec-conformant implementation; it says nothing about the product. The scratch references live only on the runner scratch and are deleted.
- trace_check (id regexes `R-PE-DEF.5[0-9]`, `.6[0-4]`, `.73`, `.8[3-7]`, `R-PE-034`, `R-PE-035`, `R-PE-110`): `24 active requirements match --ids, checks run: CASE, TEST, 0 gap(s)`; `evidence-e4/test-a-trace_check.txt`.
- Negative controls (one per file): service — pre-I-2 `add_symbol_entry` cannot give the masked word (passes on base); help — the parser misses absent lines / stale phrases (passes on base); app — with `_refuse_if_busy` bypassed the stage lands (needs the merged tree). In-test controls: R-PE-DEF.51/3 stages over the live map and gets `1F F6` instead of `1A E6`.
- Host load at the run: `uptime` load average 5.3 (the timing is not a result of any test).

## Deviations and findings
- F-1 (spec): requirement text says `history_depths()["undo"]`; the shipped keys are `back`, `forward`, `bound`. Tests use `back`. Row wording only.
- F-2 (interface): `PatchEditorPanel.is_dirty` is a property on base, not a method. Tests read `panel.is_dirty`.
- F-3: `R-PE-DEF.83/2` is read as also forbidding a help line labelled `A2L` (the A2L tab line); step texts `Filter`/`Prev`/`Next` that say `A2L PARAMETERS` must also be rewritten. If the implementer keeps an `A2L` line for another purpose, say so; the case then needs a ruling.
- F-4: `R-PE-DEF.58/3` is partial (the `shown` text is handed straight to `_stage_encoded`; a widened-A2L route was not built). `R-PE-DEF.62/4` is partial (`panel.set_image_mem_map`, not a file load).
- Image/overlay assumptions pinned from I-8.4: `StagingSheet.selected_name`, `#patch_sheet`, `#patch_sheet_body`, `StageRequested(name, text)`, `note_staged(name, advance=)`; tests fail loudly on a missing id.

## Open gaps
- R-PE-DEF.72/1 (300-character name in the overlap status): group S's row, not covered here.
- GREEN of every group-A test is `not-run` in this tree; the orchestrator's merged run supplies it.
- Source-map strip (E3S-01) is verified by outcome (`1A E6` after Apply + Remove), not by call inspection.
