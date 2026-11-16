# Inc 10 E4 — integrator I10 record

Integrator I10 (claude-opus-5-5), sole writer of `b103-inc10`. Brief `brief-I10-inc10-integrator.md` (relevo-11); rulings PENDING P-022, P-062, P-068. Base for RED: `439860c4`. Runner `<runner>`, scratch `~/work/zq-e4-10-int/` (deleted at the end, explicit list), HT-02 environment (HOME basename `<runner-home>`, `timeout 300`, `-n` ≤ 2, `-p no:cacheprovider`), `s19_app.__file__` the first line of every transcript. Transcripts: `evidence-e4-int/logs/` (sanitised: `~`, `<user>`, PP-03). Load average 2 to 8 during the runs (other workers on `<runner>`); nothing here is a timing result (HT-08).

## State / next step

STATE: done. GREEN except 8 shipped nodes at F-I10-1 (Inc 8, waits for an Inc 8 fix) and 3 pre-existing base failures (AT-B99-02, AT-076a, R-DOC-CANON.4). Next: orchestrator ruling on F-I10-1; mutant worker.

## Commits (no push)

| Step | Commit | What | Side |
|---|---|---|---|
| 1 | `0cef665e` | `git merge --no-ff b103-inc10-tests` (T10 `23968298`); `steps.log` conflict kept in time order (T10 start 04:22Z, C10 done 04:32Z, T10 done 04:51Z) | — |
| 5 | `be8fd66c` | S0 header from the written file name (P-022, BL-I10-E3-8, D8-28) + case R-S19-S0HEADER-001.2/5 | code + test |
| 3 | `c003c851` | R-CHG-003.1 reads the prompt row as a container | test |
| 3 | `9d78a652` | Format chip width 19 (R-PE-EXPORT.9) | code |
| 5 | `598148c4` | graph amendment (appended) + R-S19-S0HEADER-001.2 status | records |
| 3 | `2c38e935` | shipped tests: `output_format` on the confirm (I-10.2), Inspector chip before the entry (R-TUI-063.3) | test |
| — | `bb1f55ef` | id-registry scan bound 329 → 336 (law TC-607) | test |
| 7, 8 | `9066c4cc` + the closing commit | this record, the fold (Tests / Coverage / Result of 130 rows, `evidence-e4-int/fold_cases.py`), evidence, R-PE-EXPORT.9 status | records |

Source files changed by the integrator: `changes/apply.py`, `services/change_service.py`, `app/patch.py`, `styles.tcss` (4, at the cap). Two of them (`apply.py`, `change_service.py`) are outside the Inc 10 slice of 5 files: the P-022 ruling needs the written name, which only the engine's placement knows (E1-slice D-6 B already said so). The slice grows to 7 files; declared here, not split.

## 1. Failures and fixes (cause · side · requirement)

| # | Failure (first GREEN run, tree = merge + privacy fix) | Cause | Side | Requirement |
|---|---|---|---|---|
| I-1 | R-S19-S0HEADER-001.2/5 (5 nodes) RED before the fix: S0 data = the typed text (`C:\Users\<user>\Desktop\fw.s19`, `~/fw.s19`, `…\fw`, `firmware-patched.s19` for a file written as `firmware-patched_1.s19`) | the handler passed `event.filename` (typed) to `_synth_s0_header_from_filename` | code | R-S19-S0HEADER-001.2 ("the written file name"); BL-I10-E3-8, D8-28 |
| I-2 | R-CHG-003.1/1..9 (9 nodes): `patch_saveback_row: the widget at its centre is OsClipboardInput(id='patch_saveback_name_input')` | the test applied the control rule "the widget at its centre is the control itself" to the prompt ROW, whose centre is always one of its own children | test | R-CHG-003.1 asks the prompt to be a shown widget and `Write file` to be at its place; the row is now at its place when its centre is the row or one of its descendants (`row_at_its_place`); `Write file` keeps the strict rule — not weakened |
| I-3 | R-PE-EXPORT.7/2, .9/2, .8/1, AT-I10-1, AT-I10-2 (5 nodes): painted `Format: Intel` | `#patch_saveback_format_button { width: 17 }` = the label's length, but Textual 8.2.8's `Button` has `line-pad: 1` each side → 15 cells, the label wraps, `HEX` is not painted | code (CSS) | R-PE-EXPORT.9 (the format's name shown on the control); width 19 keeps R-PE-EXPORT.12 (fixed width) |
| I-4 | R-PE-EXPORT.17/5: `can't open file …/tools/synth/make_release_case.py` | my scratch tree lacked `tools/` (the DEFC fixture is built by the shipped CLI) | harness (mine) | — ; re-run with `tools/`: GREEN, base RED `the prompt is still a shown widget after a stage` |
| I-5 | `test_b100_active_variant` 17 nodes (TC-B100-19, -20, -71 save-back arms, …): `firmware_1.s19 was not placed`, `project.json was not rewritten` | the shipped tests post `SaveBackDecision(name, 32)` without `output_format`; since E3-5 (I-10.2: no default, no fallback) the handler passes `None` as the kind and the engine refuses (`CHG-HEX-SAVE-UNSUPPORTED`) | test | I-10.2 / E3-5; R-HEX-SAVE-001.1. Same construction in `test_b100_load_question` (TC-B100-44), `test_b100_save_image` (TC-B100-14, -15, -58, -69), `test_b100_workers` (TC-B100-53 ×2): all six sites now pass `output_format="s19"` (the loaded image's format, what the panel sends). Not in T10's static scan (it looked for an entry change before `Write file`) |
| I-6 | AT-B100-06 ×4, AT-B100-20 inc8a ×2, AT-B99-08, TC-B99-22: `click missed #patch_entry_address_input` | the pane lands on Patch script since Inc 8 final (R-TUI-063.3); the entry boxes are in the Inspector pane | test | R-TUI-063.3; the tests now press the Inspector chip first (as AT-I10-1 does, F-T10-1). They then stop at I-7 |
| I-7 | the same 8 nodes after I-6: `click missed #patch_entry_bytes_input` | **Inc 8 layout defect, present on the base `439860c4`:** in the Inspector pane the bytes box and the `Add` button are painted under the document row — at 118×54, 160×54 and 220×60 the widget at the centre of `#patch_entry_bytes_input` is `#patch_doc_path_input` and at the centre of `#patch_entry_add_button` it is `#patch_doc_validate_button` (`evidence-e4-int/probe_entry_boxes.py`, identical on base and on this tree). A mouse click on `Add` presses `Validate` | code, Inc 8 (not fixed here: Inc 8 files and I-8.x are read-only for Inc 10) | R-TUI-063.1 / R-TUI-064 family of Inc 8 (operator-visible); **finding F-I10-1 for the orchestrator**. The 8 nodes stay RED, "waits for the Inc 8 fix". T10's helpers type the boxes by assignment, so T10's own nodes do not see it |

Pre-existing, outside the run list, same cause as I-6/I-7: `tests/test_b99_s0.py::test_at_b99_02_save_back_excludes_s0` fails on base `439860c4` and here at `click missed #patch_entry_address_input` (not changed by me; for the Inc 8 retarget list).

## 2. Rulings applied (P-068)

- **P-022 / BL-I10-E3-8 (HIGH) + D8-28 — done.** The handler no longer builds the header: at width 32 as S19 with no source S0 data it passes the rule `_synth_s0_header_from_filename` as `s0_header_from_name`; `ChangeService.save_patched` → `emit_and_verify` → `save_patched_image` forward it; after the destination guard `save_patched_image` re-renders through `_render_named_by_landing`: header from the current name → render → `predict_placement` (the placement's own rule) → repeat until the landing name equals the header's (≤ 3 rounds; 2 suffice for a fresh, numbered or reused landing). The header is therefore the bare written name (suffix forced, numbered on a collision), non-ASCII removed, ≤ 252 bytes. RED → GREEN: `test_b103_inc10_s0_written_name.py` 5 nodes — on the pre-fix tree 5 failed (`b'C:\\Users\\<user>\\Desktop\\fw.s19' == b'fw.s19'`, `b'firmware-patched.s19' == b'firmware-patched_1.s19'`, …), on base 5 failed (`SaveBackDecision` takes no `output_format`), GREEN 5 passed. Case R-S19-S0HEADER-001.2/5 written and marked covered (`partial`: the confirm message is posted, like T10's S0 cases). Known limit: a file created by another process between prediction and placement can make the two names differ (the LLR-163.7 window). Graph: appended amendment in `codewire/graph-inc10.md`.
- **F-T10-1 — applied.** AT-I10-1 stays as T10 wrote it (one Inspector chip press before the entry); the "default Inspector tab" wording goes on the wording list (DF-04 b).
- **F-T10-2 — kept.** I-10.1 is a real product route to a prompt shown with an entry not applied before the save: an Apply that applies one entry and skips another calls `show_save_prompt(…, output_format=…, apply_line=…)` (`app/patch.py` apply arm, `counts["applied"] > 0`), the skipped entry stays outside the applied set, and `Write file` names it. Executed (`evidence-e4-int/probe_f_t10_2_route.py`, run on this tree): `Apply: 1 applied, 1 skipped, 0 blocked`, prompt shown `True`, `Saved + verified: firmware-patched.s19 — 1 entry applied before this save (0x8000007C); includes 1 entry not applied before this save (0x00000010)`. So T10's handler-level guard in AT-B99-08 / TC-B99-22 stays. Note: those two nodes are RED at I-7 (Inc 8), before they reach the guard.
- **F-T10-3 — accepted** as described (base RED at "still offered, not hidden").
- **R-S19-S0HEADER-001.1/3, R-S19-EMIT.11/1, /2 — stay `conflict`** (D-6 A). Open, owed by D8-27 (.1/3: the source's S0 data at width 16) and D8-29 (EMIT.11: the terminator address); not implemented; for the batch-close backlog (P-026).
- **R-PE-EXPORT.17/5 (the ok path of the stage hide)** — covered by T10's `test_r_pe_export_17_5_a_stage_from_the_staging_sheet_hides_the_prompt` (A2L + DEFC image, DISPLAY_0001 staged with `25.5` through the sheet; asserts the document gained the staged entry AND the prompt is hidden): GREEN here, RED on base at `the prompt is still a shown widget after a stage`.

## 3. Results

Final GREEN on the exact tree `2c38e935` (`git archive`, `evidence-e4-int/final.sh`; transcripts `logs/final-*.txt`; load 9 to 11). RED on base `439860c4` with the same tests (`logs/red-base-*.txt`).

| File | RED on base | GREEN (final) |
|---|---|---|
| `test_b103_inc10_g1_panel.py` | 25 F / 2 P (the 2: R-TUI-063.1/1, /3, T10's GREEN-on-base by design) | **27 passed** |
| `test_b103_inc10_g1_controls.py` | 24 F | **24 passed** |
| `test_b103_inc10_g2_arms.py` | 21 F / 2 P (R-PE-EXPORT.6/1, /2 by design); 17/5 re-run with `tools/`: F at `the prompt is still a shown widget after a stage` | **23 passed** |
| `test_b103_inc10_g2_write.py` | 21 F | **21 passed** |
| `test_b103_inc10_g3_engine.py` | 2 F (R-HEX-EMIT-001.11/1, /2) / 22 P (characterisation, by design) | **24 passed** |
| `test_b103_inc10_s0_written_name.py` (new) | 5 F (no `output_format`); pre-fix tree `0cef665e`: 5 F at the typed text | **5 passed** |
| `test_b97_patch_editor.py` | retarget nodes RED (TC-B97-60 ×3) | **38 passed** (292 s at load 10: close to `timeout 300`) |
| `test_tui_patch_layout.py` | AT-064c RED | **9 passed** |
| `test_tui_patch_editor_v2.py` | 2 retarget nodes RED | **52 passed** |
| `test_b100_active_variant.py` | 6 retarget nodes RED | `-k tc_b100`: **61 passed, 2 skipped**; `-k "not tc_b100"`: 4 passed, 1 skipped, **6 failed** = AT-B100-06 ×4, AT-B100-20 inc8a ×2 at F-I10-1 (I-7) |
| `test_b99_editor_image.py` | AT-B99-08, TC-B99-22 RED | 6 passed, **2 failed** = AT-B99-08, TC-B99-22 at F-I10-1 (I-7) |
| shipped save-back arms (I-5) + `test_changes_apply.py` + `test_b99_s0.py` | — | 52 passed, 1 skipped, **1 failed** = `test_b99_s0.py::test_at_b99_02` (RED on base too, landing pane) |
| `test_tui_patch_chips.py` (CSS chips) | 1 F / 3 P | 3 passed, **1 failed** = `test_at076a_docked_buttons_are_grouped_chips` (entry chip height 0 at 80×24): identical on base, Inc 8, not touched |
| R-PE-EXPORT.2/11 dock height (`-s`) | — | `DOCK-HEIGHT 118x54 = 4 rows`, `220x60 = 4 rows` (≤ 4: F-R8-1 does not occur) |

Shared retarget nodes on base (`logs/red-base-shared-nodes.txt`): 14 failed, as T10 recorded.

Graph examples (C10's G3 check as a script, `evidence-e4-int/i10_graph_examples.py`): this tree EX1 x64u line for line True, EX2 two type-04 / rows 16-16-4 True, EX3 no crossing True, EX4 docstring True → ALL HELD; base EX1 False, EX3 False → FAILED.

F-T10-2 route probe (`probe_f_t10_2_route.py`): 1 passed (output in §2). Entry-box probe (`probe_entry_boxes.py`): identical on base and here (F-I10-1).

Law guards (exact clone from a bundle of `main` + `b103-inc10`, `logs/laws-*.txt`): `test_engine_unchanged.py`, `test_deps_seam_law.py`, `test_no_private_tokens.py`, `test_tui_directionb.py -k tc031` (3) GREEN; `test_id_registry.py::test_tc607…` RED 336 ≠ 329 → bound bumped in `bb1f55ef` (the seven Inc 10 modules; the guard's own instruction), GREEN after; `test_requirements_canon.py::test_canon_rows_hold_the_obligation_word_once` RED on base `439860c4` too (REQUIREMENTS.md rows R-A2L-DEF.153, R-PICKER-CORRECT.004, .008 hold `shall` twice): pre-existing, not Inc 10. `test_no_private_tokens.py` re-run on the final record commit: see the last line of this section.

Final law re-run on `fa27bbb2` (the closing record commit, same clone): `test_no_private_tokens.py`, `test_id_registry.py`, `test_engine_unchanged.py`, `test_deps_seam_law.py` → 21 passed.

Token scan of `git diff 439860c4`, the commit messages and `inc-10/` (PP-02 patterns and the redaction needles, counted, never printed): 0 hits.

## 4. Inc 10 wording list (for PENDING; nothing rewritten in place)

1. `01-requirements.md` line 113 and `02-test-cases.md` AT-I10-1 ("the Inspector tab (the default)"): at Inc 8 final the landing pane is Patch script (R-TUI-063.3); the ATs press the Inspector chip once before the entry (F-T10-1, DF-04 b).
2. `02-test-cases.md` R-CHG-003.1/1..9 expected result "the prompt and `Write file` are shown at their place": the requirement asks the prompt to be a shown widget and only `Write file` to be at its place; say "the prompt a shown widget (its centre painted by the prompt), `Write file` at its place".
3. `codewire/graph-inc10.md` E2-3 "the fixed width of its longest label": 19 cells = the label plus the Button's line-pad (note appended in the graph).
4. `02-test-cases.md` R-S19-S0HEADER-001.2/5 "(base: the typed name — D8-28, open; D-6)" and the header sentence on the four `conflict` cases: three remain (D8-27, D8-29); D8-28 closed here.
5. `E4-impl.md` U2 "chip width 17 = len(\"Format: Intel HEX\")" verified the label attribute, not the painted text.

## 5. trace_check

```
$ python <skill>/trace_check.py --req .dev-flow/2026-11-05-batch-103/inc-10/01-requirements.md --base 439860c4 --src s19_app
EVID   no 04-validation.md beside .dev-flow/2026-11-05-batch-103/inc-10/01-requirements.md
trace_check: 3 US, 44 active requirements (0 withdrawn), checks run: US, CASE, TEST, SLICE, EVID, 1 gap(s)
```
- EVID: expected before E5 (card rule 4).
- The first run here had two SLICE gaps more: `changes/apply.py` (the privacy fix; now named in R-S19-S0HEADER-001.2's status) and `styles.tcss` (C10's dock rules and the integrator's Format width; now named in R-PE-EXPORT.9's status). Both were real trace gaps of the records (code changed, no requirement naming it), fixed forward by appending to the status column, nothing rewritten.
- CASE/TEST: 0 gaps; the three `conflict` cases are expected (D-6 A).

## 6. Open items

- **F-I10-1 (Inc 8, operator-visible):** Inspector pane bytes box and `Add` painted under the document row at 118×54, 160×54, 220×60 (base too). 8 shipped nodes RED until fixed (I-7). Needs an Inc 8 fix and an orchestrator ruling.
- `test_b99_s0.py::test_at_b99_02_save_back_excludes_s0`: RED on base and here (landing pane, then I-7).
- R-S19-S0HEADER-001.1/3, R-S19-EMIT.11/1, /2: `conflict`, owed by D8-27 / D8-29.
- O-1…O-6 (P-021) untouched.

## For the mutant worker (≤ 3 lines)

1. New mutants: `_render_named_by_landing` returning the first render (header = sanitized typed name) → `test_b103_inc10_s0_written_name.py::…numbered…` RED; handler passing `event.filename` to the rule → the 4 typed-path params RED.
2. The Format chip width is CSS: a mutant `width: 17` turns R-PE-EXPORT.7/2, .9/2 RED (painted `Format: Intel`).
3. Ship `tools/` with the tree (R-PE-EXPORT.17/5 builds DEFC through `tools/synth/make_release_case.py`); `test_b100_active_variant.py` needs two runs (`-k tc_b100` / `-k "not tc_b100"`) to stay under `timeout 300`.

## Before E5 (relevo-11)

Writer P10b (claude-sonnet-5-5), sole writer of `b103-inc10`. Runner `<runner>`, scratch `~/work/zq-p10b/` (HT-02 environment, HOME basename `<runner-home>`, `timeout 300`, `-n 2`, `-p no:cacheprovider`; `s19_app.__file__` the first line of every transcript). Host load (HT-08): 8.2 at the start (other workers), 1.9 to 5.3 during the Inc 10 / Inc 8 files, 3 to 5 during the law run (it overlapped the Inc 8 files); nothing here is a timing result. Source files changed: 0. No push.

Commits: `16d93b56` merge · `a2339249` D-F8-2 · `be426c84` dock docstring.

1. **Merge.** `git merge --no-ff b103-inc8` (tip `6c4fd21f`): merged with no conflict (`16d93b56`); records only, no product code came in.
2. **D-F8-2 (P-075), test-only.**
   - `tests/test_b99_editor_image.py`: the two `_type` helpers and the five `#patch_entry_add_button` clicks use `click_visible` (import from `tests.support.b103_inc8_p`).
   - `tests/test_b100_active_variant.py`: the Address, Bytes and Add clicks of `_add_and_apply_through_the_panel` use `click_visible`; `_script_border` reads `#patch_inspector`'s region.
   - No assertion changed.
3. **Dock test (P-076).** `test_the_largest_dock_is_four_rows_high_with_one_chip_row` kept; only its docstring now says it pins the approved graph's I-8.3 budget (4-row dock, F-R8-1 fit), which keeps R-PE-EXPORT.2 and R-TUI-064.1 true at 118x54, and that it is not requirement text.

| 8 nodes | Before (relevo-10 record) | After (this tree) |
|---|---|---|
| AT-B100-06 ×4 (`-k "not tc_b100"`) | FAILED `click missed #patch_entry_bytes_input` | passed |
| AT-B100-20 inc8a ×2 | FAILED (same click, then `_script_border`) | passed |
| AT-B99-08, TC-B99-22 | FAILED (same click) | passed |

Counts (rtx, one run per file; `-k` splits for b100):

| File | Result |
|---|---|
| `test_b103_inc10_g1_controls` / `g1_panel` / `g2_arms` / `g2_write` / `g3_engine` / `mu_survivors` / `s0_written_name` | 24 / 27 / 23 / 21 / 24 / 4 / 5 passed |
| `test_b97_patch_editor` | 38 passed |
| `test_tui_patch_layout` | 9 passed |
| `test_tui_patch_editor_v2` | 52 passed |
| `test_b100_active_variant -k tc_b100` | 61 passed, 2 skipped |
| `test_b100_active_variant -k "not tc_b100"` | 10 passed, 1 skipped |
| `test_b99_editor_image` + `test_b99_s0` | 13 passed, **1 failed** = AT-B99-02 (expected; fails on base too) |
| `test_b103_inc8_*` (14 files) | 377 passed (a1 23, a2 23, a3 9, at_help 2, at 11, p_layout 31, p_ledger 10, p_wiring 12, s1_detail 43, s1 118, s2_picker_definitions 6, s2_sheet_formula 27, s2_sheet_keys 21, s2_sheet_rows 35) |
| Laws (exact clone of `be426c84`, local `main` from `origin/main`): docs_canon, b101_doc_hygiene, b101_help_legend_docs, no_private_tokens, filename_markup_safety, report_markup_safety, id_registry, deps_seam_law, engine_unchanged, requirements_canon, suite_hygiene | 380 passed, **5 failed** (below) |

`test_tui_patch_chips.py` (AT-076a, expected failure) was not run: **not-run**.

Law failures (R-DOC-CANON.4 is the first; the other four are **unexpected**, none is caused by the two edits above, none was fixed here):

| Node | Cause | Owner |
|---|---|---|
| `test_requirements_canon::test_canon_rows_hold_the_obligation_word_once` | R-DOC-CANON.4, expected (P-026) | — |
| `test_id_registry::test_tc607_scanned_corpus_matches_the_declared_bound` | 337 test modules vs `EXPECTED_SCANNED_TEST_FILES = 336`: MU10's `test_b103_inc10_mu_survivors.py` (`7e6c062e`) was added without the bump (`git ls-tree d68aa3ac tests` already counts 337) | Inc 10 (test-only bump, as `bb1f55ef`) |
| `test_filename_markup_safety::test_at_s3_dynamic_notify_sites_pass_markup_false` | `s19_app/tui/app/patch.py:263` (`self.notify(apply_text, title="Nothing applied", …)`) passes dynamic text without `markup=False`; the call is in the Inc 10 diff of `app/patch.py` | **Inc 10 product code**; a markup sink, so security-relevant |
| `test_suite_hygiene::test_r_tst_154_155_inc15_arms_wait_through_settled` | `test_tui_patch_editor_v2.py::test_save_back_prompt` has a `for _ in range(6): await pilot.pause()` loop added by T10 (`23968298`), which R-TST-154/155 forbid | Inc 10 test (use `settled`) |
| `test_suite_hygiene::test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses` | Inc 10's own unpushed records and evidence hold the HOME basename, `/home/<user>` and `C:\Users\<user>` forms (`inc-10/E4-impl.md`, `E4-integration.md`, `E4-mutants.md`, `codewire/graph-inc10.md`, `evidence-e4-int/{run.sh,runpy.sh,logs/red-*.txt}`, `evidence-e4-mut/{mu.py,run.sh}`) | Inc 10: redact forward (P-050 O-2), not done here |

## Law fixes (relevo-11)

Writer L10 (claude-sonnet-5-5), sole writer of `b103-inc10`; ruling P-078. Runner `<runner>`, scratch `~/work/zq-l10/` (HT-02 environment, HOME basename `<runner-home>`, `timeout 300`, `-n 2`, `-p no:cacheprovider`; `s19_app.__file__` the first line of every transcript; laws on exact clones of the bundle). Host load (HT-08): 1.8 to 2.7 around the runs; nothing here is a timing result. No push.

Commits: `82dffbad` id_registry · `1d526d32` markup=False + node · `c086f33d` pause loop · `486d0064` redaction.

| # | Law node | RED (base `76915963`) | GREEN (fix) |
|---|---|---|---|
| 1 | `test_id_registry::test_tc607_scanned_corpus_matches_the_declared_bound` | 337 modules vs bound 336 (`git ls-files tests` over `*.py`: 337) | bound 337, comment line added as `bb1f55ef` did |
| 2 | `test_filename_markup_safety::test_at_s3_dynamic_notify_sites_pass_markup_false` | FAILED (`app/patch.py` `Nothing applied` notify) | `markup=False` on the notify; new node `test_b103_inc10_g2_arms.py::test_the_nothing_applied_notice_is_shown_literally_for_a_markup_file_name` RED on base (`markup=True`), GREEN |
| 3 | `test_suite_hygiene::test_r_tst_154_155_inc15_arms_wait_through_settled` | FAILED (`range(6)` loop in `test_save_back_prompt`) | the loop is `wait_until(pilot, lambda: shown_widget(prompt), …, pause_first=True)` from `tests/support/timing.py`; assertions unchanged. `settled` was not added because the law pins the arm's `settled` count to table D |
| 4 | `test_suite_hygiene::test_r_tst_070_2_…` | FAILED, 9 own files (none reachable from `origin/main` or `origin/batch-modular`) | records and two logs rewritten to `<runner-home>`, `~`, `C:\Users\<user>`; four scripts read `RUNNER_HOME_NAME` (comment added); inherited files untouched |

Notes:
- Fix 2: the apply line carries only counts, no file name, so the node asserts the flag (`markup=False`) while an image named with an opening `[bold]` tag is loaded. A name cannot hold the closing `[/]` (slash), so the literal `[bold]x[/]` form is not constructible.
- Fix 3: the same T10 pause loop in `_apply_via` (`test_tui_patch_editor_v2.py`, an arm the law does not watch) was left as is.
- Fix 4: the redaction is a script outside the repo that rewrites the six record files; the four scripts (`evidence-e4-int/run.sh`, `runpy.sh`, `evidence-e4-mut/run.sh`, `mu.py`) now need `RUNNER_HOME_NAME` exported before use; the recorded transcripts were produced with the old literal.

| Run (final clone of `486d0064`) | Result |
|---|---|
| Laws: docs_canon, b101_doc_hygiene, b101_help_legend_docs, no_private_tokens, filename_markup_safety, report_markup_safety, id_registry, deps_seam_law, engine_unchanged, requirements_canon, suite_hygiene | 381 passed, 3 skipped, **1 failed** = R-DOC-CANON.4 (expected, P-026) |
| `test_b103_inc10_g1_controls` + `g1_panel` | 51 passed |
| `test_b103_inc10_g2_arms` + `g2_write` | 45 passed |
| `test_b103_inc10_g3_engine` + `mu_survivors` + `s0_written_name` | 33 passed |
| `test_tui_patch_editor_v2` (shared file of `test_save_back_prompt`) | 52 passed |

AT-B99-02 was not in this set (`test_b99_editor_image` not run): **not-run**. A first attempt of the Inc 10 files in one run hit `timeout 300`; split into the four runs above.
