# Inc 9b E4 — integration record

## Scope, revisions and verdict

Inc 9b implements the staging-sheet busy cue and the stepped record-stage write/refresh over merged base `e4485817`. The design is 13 requirements, 36 cases, 17 graph nodes and four source files: `bench_sheet.py`, `definition_bench_view.py`, `app/patch.py` and `patch_editor/panel.py`. The independent W, S and AT test lanes and their RED evidence were merged at `658df8fa`; integration then landed the scheduler/design rulings (`19fc3123`), the painted-result timing correction (`fe5ecff4`), the in-place-write token fix (`c19503f0`) and the law/test hygiene corrections (`97c97573`). The local integration candidate is `97c97573`.

The final functional recheck passes all **40 new nodes**: W **22/22**, S **8/8** and AT **10/10**. These are the 36 specified cases plus the W oracle control, the synchronous-refresh regression and two deterministic scheduler contracts. The selected Inc 8b, Inc 8 and Inc 9 regression files are green, except for the Inc 9 `26_2` timeout that also occurs on `e4485817`. Caller failures and the remaining law failures are base-identical or inherited as itemized below. Q9b measurement, M9b mutation and E5 validation are not claimed by this record.

Evidence below is under `.dev-flow/2026-11-05-batch-103/inc-9b/`; the remote copies are cited by their sanitized repository homes, `evidence-e4/i9b/extended/` (65 transcripts) and `evidence-e4/i9b/recheck/` (eight files). The extended tip transcripts have HEAD `c19503f0`, whose product code is unchanged by `97c97573`. The recheck clone also has HEAD `c19503f0`, with the five candidate-owned files from `97c97573` copied over it: `E4-roster.md`, `test_id_registry.py`, and the three `test_b103_inc9b_*.py` files. `recheck/copied-paths.txt` preserves that list; local/remote hashes matched before and after the run. Thus the recheck exercises the candidate product and test content without misstating the clone's Git HEAD.

## Merge and design rulings integrated

- `658df8fa` has parents `6b7f1287` and `f95556e9` and joins the W/S implementation line to the recovered W tests, S tests, AT tests, hand-backs and base-RED evidence. The three new test files are `tests/test_b103_inc9b_w.py`, `_s.py` and `_at.py`.
- Pilot P1 falsified the original scheduler assumption: `call_after_refresh` produced no intervening paint and no key handling in 6/6 arms; `set_timer(0, …)` stopped after step 1 in 3/3; `set_timer(0.02, …)` still left the key until the chain end in 3/3. `set_timer(0.1, …)` handled the key between steps and painted a changed title in every gap in 3/3. The implementation therefore uses `STEP_GAP_S = 0.1`, never `call_after_refresh` or a zero timer (`E4-pilots.md`, `evidence-e4/pilots/out/p1.txt`, `p1-run1.txt`).
- Pilot P2/P3 fixed the other platform contracts: the busy colour comes from `Style.parse(EDIT).color`; idle restoration clears all four inline border edges and refreshes the painted window; title room is window width minus four. `ArrayBenchSheet.on_mount` deliberately does not call `super()`, because Textual's MRO dispatch already runs `StagingSheet.on_mount` once. Group S extracted `_patch_refresh_tail`, kept all existing synchronous callers synchronous, and skips the remaining timers when the panel is gone (`E4-C9b-W.md`, `E4-C9b-S.md`, `codewire/graph-inc9b.md`).

## New W, S and AT results

| Group | Final result | Coverage represented | Evidence |
|---|---:|---|---|
| W | **22 passed**, rc=0 | 21 case nodes plus the `.95/0` painted-cue oracle control | `evidence-e4/i9b/recheck/test_b103_inc9b_w.txt` |
| S | **8 passed**, rc=0 | five case nodes, the R-PE-DEF.62 / LLR-081.3 synchronous regression, and two scheduler contracts | `evidence-e4/i9b/recheck/test_b103_inc9b_s.txt` |
| AT | **10 collected; 10 separate processes passed**, every node rc=0 | all ten black-box cases | `evidence-e4/i9b/recheck/test_b103_inc9b_at.txt`, `summary.tsv` |

The AT recheck includes the required painted/timing observations: `.94/1-3` cue latencies 0.259 / 0.226 / 0.305 s against 0.5 s; `.97/3` median/max gaps 0.098 / 0.135 s against 0.2 / 0.5 s; `.98/1` maximum write-to-leave gap 0.387 s against 0.5 s; `.99/1` key handling 0.281 s against 1.0 s; and `.100/3`, `.101/2`, `.101/5` idle latencies 0.029 / 0.016 / 0.107 s against 0.3 s. The recheck's AT load moved from 1.08 at collection to 0.98 at the end; W moved from 1.65 to 0.84. These are the recorded final passes, not a substitute for Q9b's dedicated quiet, repeated measurements.

### R-PE-BENCH.102/1: test-side paint timing correction

The first real W run was **21 passed, 1 failed**: `.102/1` reported idle 0.310 s after the key against the unchanged 0.3 s bound (`evidence-e4/i9b/w.txt`). Instrumentation then separated product painting from Pilot's return: the idle compositor paints occurred about 0.103 / 0.106 / 0.153 s after the key while the old assertion observed Pilot at 0.353 / 0.355 / 0.439 s (`probe102.txt`). This was a test-side measurement defect, not a product timing failure.

`fe5ecff4` changed the test to timestamp the actual idle paint through the compositor refresh hook; it did not loosen the threshold or change product code. The corrected node passed three consecutive runs (`w102-fixed.txt`), the whole W file passed 22/22 (`w-fixed.txt`), and the candidate recheck again passed 22/22.

### R-PE-BENCH.106 and deterministic scheduler gates

The S tests now hold the second refresh timer without blocking the UI, perform Undo or Apply, assert that exactly one callback was captured, invoke it explicitly, and compare the settled ledger/JSON/sheet digest with a full synchronous refresh. This makes the interleaving deterministic instead of depending on whether the write happens to paint before the action.

That gate exposed a real Apply defect. Before the fix, `.106/2` was RED in both the full S file (**1 failed, 7 passed**) and the isolated pair (**1 failed, 1 passed, 6 deselected**): the token before and after Apply was unchanged (`s-token-red.txt`, `s-token-pair-red.txt`). Apply mutates `current_file.mem_map` in place, so document identity, history depths and `id(current_file)` could not see it. `c19503f0` adds the monotonic `_image_write_generation`, increments it in `_note_image_bytes_written`, and includes it in `_patch_document_token`. The isolated Undo/Apply pair then passed **2/2**, the S file passed **8/8**, and the candidate recheck repeated **8/8** (`s-pair-green.txt`, `s-green.txt`, `recheck/test_b103_inc9b_s.txt`).

Two additional deterministic S nodes cover the integration rulings that a later-step exception re-raises only after `on_done` runs once, and that a missing panel skips the tail while still releasing exactly once (`tests/test_b103_inc9b_s.py`, scheduler-contract section). Together with the held `.106` timers, these gates make later-step release, stale-state skipping and teardown independently testable without wall-clock sleeps deciding the interleaving.

## Inc 8b, Inc 8 and Inc 9 regression results

Every result in the following tables comes from the named file in `evidence-e4/i9b/extended/`; all tip transcripts there have product HEAD `c19503f0`.

| Inc 8b file suffix | Passed |
|---|---:|
| `tip-test_b103_inc8b_at.txt` | 13 |
| `tip-test_b103_inc8b_bw.txt` | 32 |
| `tip-test_b103_inc8b_s1.txt` | 98 |
| `tip-test_b103_inc8b_s2.txt` | 38 |
| **Total** | **181 passed, 0 failed** |

| Inc 8 file suffix | Passed |
|---|---:|
| `tip-test_b103_inc8_a1_service.txt` | 23 |
| `tip-test_b103_inc8_a2_app.txt` | 23 |
| `tip-test_b103_inc8_a3_help.txt` | 9 |
| `tip-test_b103_inc8_at.txt` | 11 |
| `tip-test_b103_inc8_at_help.txt` | 2 |
| `tip-test_b103_inc8_p_layout.txt` | 31 |
| `tip-test_b103_inc8_p_ledger.txt` | 10 |
| `tip-test_b103_inc8_p_wiring.txt` | 12 |
| `tip-test_b103_inc8_s1.txt` | 122 |
| `tip-test_b103_inc8_s1_detail.txt` | 43 |
| `tip-test_b103_inc8_s2_picker_definitions.txt` | 6 |
| `tip-test_b103_inc8_s2_sheet_formula.txt` | 27 |
| `tip-test_b103_inc8_s2_sheet_keys.txt` | 22 |
| `tip-test_b103_inc8_s2_sheet_rows.txt` | 35 |
| **Total** | **376 passed, 0 failed** |

| Inc 9 file suffix | Passed |
|---|---:|
| `tip-test_b103_inc9_a9.txt` | 29 |
| `tip-test_b103_inc9_b_canvas.txt` | 42 |
| `tip-test_b103_inc9_b_cells.txt` | 40 |
| `tip-test_b103_inc9_b_detail.txt` | 54 |
| `tip-test_b103_inc9_b_model.txt` | 20 |
| `tip-test_b103_inc9_b_tools.txt` | 59 |
| `tip-test_b103_inc9_i.txt` | 3 |
| `tip-test_b103_inc9_ob_json_view.txt` | 2 |
| `tip-test_b103_inc9_w_keys.txt` | 19 |
| `tip-test_b103_inc9_w_mutants.txt` | 29 |
| `tip-test_b103_inc9_w_select.txt` | 14 |
| `tip-test_b103_inc9_w_stage.txt` | 11 |
| **Total for these files** | **322 passed, 0 failed** |

`extended/w_jobs.txt` collected ten `test_b103_inc9_w_jobs.py` nodes and ran each in its own process. Nine passed: `20_1`, `20_2`, `20_3`, `23_2`, `28_1`, `28_2`, `29_1`, `29_2` and `82_1`. Their reported timing margins include `20_1` 0.153/0.500 s, `23_2` 0.008/0.500 s, `29_1` 0.174/0.500 s, `29_2` 0.617/1.000 s and `82_1` 0.700/1.000 s. `26_2` reached the 300 s timeout, rc=124, with no pytest failure summary.

The same `26_2` node also reached the 300 s timeout, rc=124, on clean base `e4485817` (`extended/base-w_jobs-26_2.txt`). It is therefore a base-matching timeout, not evidence of a new Inc 9b regression; it is not counted as a pass.

## Caller comparison against the current base

The caller set was run at the extended tip and, except for `test_tui_patch_big.py`, at clean `e4485817`. The failing node names and pass/fail counts match base exactly:

| Caller file | Base `e4485817` | Extended tip | Base-matching failure |
|---|---|---|---|
| `test_tui_patch_big.py` | not run | **24 passed** | none observed |
| `test_tui_patch_card.py` | 25 passed, 1 failed | 25 passed, 1 failed | `test_tc080_2_c7_purity_probe` |
| `test_tui_patch_editor_b94.py` | 16 passed, 1 failed | 16 passed, 1 failed | `test_at_b94_03_expanded_editor_primary_surface` |
| `test_tui_patch_json.py` | 14 passed, 3 failed | 14 passed, 3 failed | `test_ac1_editor_fills_json_window_when_room_exists`, `test_ac3_fill_does_not_leak_to_sibling_windows`, `test_ac5_gauge_stays_above_editor` |

Evidence: `extended/tip-test_tui_patch_{big,card,editor_b94,json}.txt` and `extended/base-test_tui_patch_{card,editor_b94,json}.txt`. The card failure is the existing panel-to-app purity probe; the B94 failure is the existing 120x30 table visibility assertion; the JSON failures are the existing editor/gauge geometry assertions. No new caller failure appears in this selected comparison. This is not a claim that a full repository suite was run.

## Law comparison and corrections

Thirteen law files were run on both clean base `e4485817` and the extended tip. On base they totalled **442 passed, 3 failed, 1 skipped**; on the extended tip, **438 passed, 7 failed, 1 skipped**. The four additional tip failures were Inc 9b record/test hygiene defects, not product regressions.

- Unchanged green on both sides: `test_b101_doc_hygiene.py` 45; `test_b101_help_legend_docs.py` 71; `test_b97_key_bar.py` 38; `test_deps_seam_law.py` 6; `test_docs_canon.py` 2; `test_filename_markup_safety.py` 2; `test_report_markup_safety.py` 166. `test_engine_unchanged.py` was 1 skipped on both sides.
- Base-identical red on both sides: `test_address_census.py` 22 passed, 1 failed (`test_at_b83_08_tree_holds_no_assembled_selectors`); `test_requirements_canon.py` 10 passed, 1 failed (the existing three double-`shall` canon rows); and `test_suite_hygiene.py` 66 passed, 1 failed (the inherited Inc 8b home-path evidence). See `extended/law-{base,tip}-test_{address_census,requirements_canon,suite_hygiene}.txt`.
- `test_no_private_tokens.py` moved from base 2 passed to extended-tip 1 passed, 1 failed because the roster still held real Windows profile paths. `97c97573` redacts those paths; final recheck is **2 passed** (`extended/law-tip-test_no_private_tokens.txt`, `recheck/test_no_private_tokens.txt`).
- `test_id_registry.py` moved from base 12 passed to extended-tip 11 passed, 1 failed: the measured corpus was 352 modules while the declared bound was still 349. `97c97573` changes the bound to 352 for exactly the three new Inc 9b test modules; final recheck is **12 passed** (`extended/law-tip-test_id_registry.txt`, `recheck/test_id_registry.txt`).
- The extended-tip suite-hygiene run had two additional failures beyond the inherited redaction failure: 23 timing arms lacked direct `serial_timing` markers, and five upper-bound assertions lacked `report_margin`. `97c97573` corrects those 23 markers and five reports. The final recheck is **66 passed, 1 failed**; only the four inherited Inc 8b home-path hits remain. Those inherited records were not altered (`extended/law-tip-test_suite_hygiene.txt`, `recheck/test_suite_hygiene.txt`).

The final recheck of the three corrected law files plus the new W/S/AT files therefore totals **120 passed, 1 failed** (`recheck/summary.tsv`). The other ten law files were not rerun after the law-only candidate commit; their base/tip results above are the extended-run evidence.

## Trace check

Run on the candidate with the required merged base and source root:

```text
python -I -B C:/Users/<user>/.claude/skills/dev-flow/trace_check.py --req .dev-flow/2026-11-05-batch-103/inc-9b/01-requirements.md --base e4485817 --src s19_app
EVID   no 04-validation.md beside .dev-flow/2026-11-05-batch-103/inc-9b/01-requirements.md
trace_check: 1 US, 13 active requirements (0 withdrawn), checks run: US, CASE, TEST, SLICE, EVID, 1 gap(s)
```

Only the expected EVID gap remains because E5 has not yet written `04-validation.md`; the command's exit status is 1 for that single expected gap. No validation record is created here.

## Lines for the next workers

- **Q9b:** on the quiet runner (1-minute load < 1 before every timing run), execute the E1-slice §5 K1–K6 scenarios (a)–(d), ten runs each, and the §6 base-`e4485817` versus candidate comparison: `20_1`, `29_1`, `29_2`, `82_1`, five runs each per side, plus the FX9c per-step probe; record p50/max and the unchanged thresholds in `E4-measure-o-e.md` before proposing any operator decision.
- **M9b:** run every E1 negative control and the integration controls on copies under HT-09: stale first-step serialization, `call_after_refresh` chaining, removal/ignoring of the write-generation token or increment, mount-once/double-`super()` dispatch, and later-step raise/panel-gone release with `on_done` exactly once; report KILLED / CRASH / SURVIVED / BAD and rule every survivor.
- **E5:** capture real idle and busy paints, including hostile/cut names at 80/118/220 and the stepped record stage; perform the code/security review, and carry BL-9b-1 cancellation, BL-9b-2 other refresh sites, O-A, the base-identical caller/law failures and the inherited Inc 8b redaction failure into explicit dispositions/backlog without rewriting inherited evidence.
