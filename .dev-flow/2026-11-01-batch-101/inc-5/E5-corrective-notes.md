# Inc 5 — E5 corrective notes (C-1 … C-11)

Batch 2026-11-01-batch-101, increment 5, stage E5 corrective pass (Opus). Branch `b101-inc5`, start head `6256ef4`, base `c2cba35`. Rulings: `E5-rulings.md`. Inputs: `E5-code-review.md`, `E5-security.md`, `E5-coverage-audit.md`, `E4-integration-notes.md`. Not touched: `E5-mutants.md` and `../evidence/inc-5/mut-*.txt` (the DeepSeek battery at `8fc3cd3` owns them).

## 1. Sites, enumerated before the first edit

Mutant ids: the DeepSeek battery owns M1 … M24. This pass adds M25 … M30. **M25 is the ruling's id** (C-2: the demoted row leaves out its expected bytes = the audit's proposed "M28"); the audit's proposed M25 … M27 become M26 … M28 here.

| Ruling | Site(s) | Kind |
|---|---|---|
| C-1 | `02-test-cases.md`: every case row's Tests / Coverage / Result columns to the audited values (`E5-coverage-audit.md` §2, §3 C-1, C-3, C-4, C-5, C-6, C-8, R-1 … R-6), then moved again where C-2, C-3, C-4, C-5, C-6 and C-10 change the evidence; header **Drive** sentence (R-2); Tests cells name the files (R-3); stale header/footer sentences dropped (R-4); `windows: not_run` (R-5); evidence note (R-6) | records |
| C-2 | `tests/test_b101_check_spec_keep.py` `relayout_and_write` (056/1 … /3) and `test_r_chked_025_3_…` scenario: `apply_bytes(… v1.address, PATCH_BYTE)` between `open_session` and `pick_spec`; `01-requirements.md` R-CHKED-056 Threshold precondition (and R-CHKED-025/3 through "as R-CHKED-056/1"); `02-test-cases.md` 056/1 … /3, 025/3 Preconditions; mutant **M25** (`_demote_moved_spec_params` appends `(spec[0], label, spec[1], None)`) → expected RED C 056_1, 056_2, 056_3, 025_3 | test + records + mutant |
| C-3 | `tests/test_b101_designer_writes.py` 002.5/3 (above `_apply`), /4 (above `_save_back`), /6 (above `_apply`), /7 (above `_save_back`), /8 (above the second `_apply`): `before = designer_recomputes()` moves above the trigger | test |
| C-4 | four black-box ATs through keys and clicks (`E5-coverage-audit.md` §6): AT-I5-1 (Add, Write by click; return by keys and the Load dialog), AT-I5-2 (apply by key `6` and clicks, pick by keys, Write and Validate by click), AT-I5-3 (moved A2L by the Load dialog, Write by click), AT-I5-4 (save-back confirm reached by keys: focus + `tab` + `enter`); `02-test-cases.md` names them in the Tests cells of the cases they drive; the other cases keep the audited "drive partial" marks | tests + records |
| C-5 | Check Editor cases (27 + the new ones) run 3/3 on the final tree: the GREEN run and two more runs of `test_b101_check_spec_keep.py` + the symbol-reads node; cited in the Result column | runs + records |
| C-6 | deciding cases: (1) 056 bytes clause = C-2; (2) R-CHKED-041.2/4 "in entry order" (spec `VALUE_0002` then `VALUE_0001` → included `[VALUE_0002, VALUE_0001]`, Fields lines in that order); (3) R-CRC-PREVIEW-002.5/9 a save-back that raises after it adopted the re-derived bytes ends the app with that error (E5-S2 ruled "no action"; the case pins it; control **M30**: the handler swallows the error → RED); (4) R-CHKED-010/4 a parameter included in this session that a new A2L moves stays included at its new address. Mutants: **M26** 010/1 (`_prefill_check_editor` clears the picks first), **M27** 025/1 (a session field's expected bytes = `bytes(size)`), **M28** 027/1 (a field without image bytes declared as zeros instead of left out) | tests + records + mutants |
| C-7 | `s19_app/tui/app.py` `_check_items_to_document` Summary (`:7300-7310`) and `on_check_editor_panel_action_requested` Summary (`:7366`) | source (docstrings) |
| C-8 | `docs/user-guide/ch10-check-editor.md:86-87`: delete "A spec with `symbol` entries (`demo_check.chk.json`) is refused the same way as in the Patch Editor (F-01)." | doc |
| C-9 | F6: `s19_app/tui/crc_designer_view.py` `note_image_bytes_written` gains `Data Flow`; `s19_app/tui/screens_directionb.py:7233` `_spec_bytes` annotated `dict[str, tuple[int, int, Optional[tuple[int, ...]]]]`. F5: no change | source |
| C-10 | (a) `01-requirements.md`: Definition *in-place write* and *validation results* (new), row **R-CHKED-057** (strict EARS event form), story coverage; (b) `02-test-cases.md`: R-CHKED-057/1 (apply), /2 (save-back), /3 (Save project commit); (c) `codewire/graph-inc5.md`: `_note_image_bytes_written` changed (two queries, two delegates), new node `CheckEditorPanel.clear_check_results` (I-5), interface row; (d) `E1-slice.md`: #1 changed, #18 new; (e) tests RED on base `c2cba35` for the stale `-> pass`; (f) code: `app.py` `_note_image_bytes_written` also calls `CheckEditorPanel.clear_check_results` (independent query; no focus move, no tab switch, no `refresh_window`); `screens_directionb.py` new public `CheckEditorPanel.clear_check_results`; (g) GREEN; mutant **M29** (the helper does not call `clear_check_results`) → RED C 057_1, D 057_2, 057_3 | design-gap fix |
| C-11 | `E1-rulings.md` §6 "Backlog rows opened": add the R2-1 row (the Check Editor's Write and Validate run the collision rule; Write refuses through LLR-148.9's path) | records |

Source files touched by this pass: `app.py` (C-7, C-10), `crc_designer_view.py` (C-9), `screens_directionb.py` (C-9, C-10) — the increment's 3 of 4; no new source file.

## 2. Decisions taken in this pass

- **E-1 (C-10 scope).** The ruling folds only the in-place writes (hook #1). E5-S1's other triggers (an image load, a spec pick, an A2L load, a collector change) also leave verdict rows that judged another state; they are not in the ruling and go to the backlog (§3), so R-CHKED-057's text names in-place writes only.
- **E-2 (C-10 cleared state).** "Cleared" = the mount state: 0 verdict rows and the status line `Validate compares fields to the image` (`CheckEditorPanel._STATUS_HINT`, the text the card shows when it opens). No new text, so no prototype round (E5-S1 option (a)). The clear neither switches the card's tab nor moves the focus (unlike `refresh_check_results`, which shows the Fields tab).
- **E-3 (C-10 independence).** The helper queries the CRC Designer and the Check Editor separately; a missing panel skips only its own notice.

## 3. Backlog rows opened by this pass

- Clear (or mark out of date) the Check Editor's verdict rows on the other changes E5-S1 lists: an image load or unload, a spec pick, an A2L load, an include/exclude and a memory-row add/remove. Not ruled into Inc 5 (C-10 folds the in-place writes only). (E5-S1 remainder.)

## 4. Done per ruling

| Ruling | State | How |
|---|---|---|
| C-1 | done | `02-test-cases.md`: audited values applied (header Drive sentence R-2, **D**/**C** file names R-3, stale sentences dropped R-4, `windows not_run` R-5, evidence note R-6), then the marks moved again by C-2 … C-6, C-10 (§6) |
| C-2 | done | `relayout_and_write` and 025/3 apply `0x0` = `93` before the pick; R-CHKED-056 threshold and negative control amended; M25 KILLED 5/5 |
| C-3 | done | 002.5/3, /4, /6, /7, /8 take the recompute count before the trigger |
| C-4 | done | AT-I5-1 … AT-I5-3 (`C`), AT-I5-4 (`D`, the save-back confirm by `tab` + `enter`: the keys reach it at 160×54, so tester 1's clip note is not a product finding); all GREEN, all RED on base |
| C-5 | done | Check Editor cases 3/3 on the final tree: e5c-02, e5c-03, e5c-04 |
| C-6 | done | 041.2/4, 010/4 (RED on base), 002.5/9 (standing guard; M30 KILLED); M26, M27, M28 KILLED |
| C-7 | done | `app.py` `_check_items_to_document` Summary, `on_check_editor_panel_action_requested` Summary |
| C-8 | done | the F-01 sentence removed from guide §10.8; the batch-end doc list (Inc 14 D-8) can drop `ch10` from its F-01 items |
| C-9 | done | `Data Flow` on `note_image_bytes_written`; `_spec_bytes` element type |
| C-10 | done | R-CHKED-057 (row below), Definitions *in-place write* and *validation results*, cases 057/1 … /3, graph node `clear_check_results` + I-5, slice #18; RED on base 3/3 (stale `validation complete` and `-> pass`); GREEN; M29 KILLED 3/3 |
| C-11 | done | `E1-rulings.md` §6 R2-1 row (and the E5-S1 remainder row, §3) |

**R-CHKED-057** (E): When the system makes an in-place write to the loaded image, the system shall clear the Check Editor's validation results. Cleared = 0 verdict rows and the status line `Validate compares fields to the image`; threshold 3/3 per alternative (apply, save-back, Save project commit); negative control: the hook not telling the Check Editor → the stale `validation complete` / `-> pass` row → RED.

## 5. Runs (LAN host 2, Python 3.11.18; transcripts `../evidence/inc-5/`)

GREEN tree: `c2cba35` + the increment staged; subtrees `s19_app` `397a3b2`, `tests` `2dad0b4`, `docs` `172ff6f` = this commit's (checked locally before the commit). `s19_app.__file__` = the run's tree in every transcript.

| Run | Scope | Result |
|---|---|---|
| e5c-02 | GREEN: `D`, `C`, `test_b101_symbol_reads.py`, `-n 8 -m "not serial_timing"` | **68 passed** (5:35) |
| e5c-01 | RED on base: pristine `c2cba35` copy + the two test files; the 10 E5 nodes | **9 failed, 1 passed** (002.5/9, the declared standing guard); each failure an assertion on the targeted defect |
| e5c-03, e5c-04 | Check Editor cases, runs 2 and 3 of 3 (`C` + the symbol-reads node 9) | **33 passed**, **33 passed** |
| e5c-05 … e5c-10 | mutants M25 … M30 in a copy of the GREEN tree (each transcript ends with the `diff` showing the mutant in place) | **6/6 KILLED** (§ below) |
| e5c-11 | law guards `test_address_census`, `test_suite_hygiene`, `test_id_registry`, `test_engine_unchanged` + `test_docs_canon` (the guide changed) | **103 passed** |
| e5c-12 | `-m serial_timing`, serial, over `D`, `C`, `test_b101_symbol_reads.py` | **2 passed** (symbol-reads timing nodes; `D` and `C` have none) |

| Mutant | Operation | Expected RED | Result |
|---|---|---|---|
| M25 (C-2) | `_demote_moved_spec_params` appends the row with `None` bytes | C 056_1, 056_2, 056_3, 025_3 (+ AT-I5-3) | **KILLED 5/5**: `0x0` written as `93`, not `6C` |
| M26 (C-6, 010/1) | `_prefill_check_editor` clears the picks first | C 010_1 | **KILLED**: picks `[]` |
| M27 (C-6, 025/1) | a session field's expected bytes are zeros | C 025_1 | **KILLED**: `VALUE_0003` entry `00 00 00 00` |
| M28 (C-6, 027/1) | a field without image bytes declared as zeros | C 027_1 | **KILLED**: `wrote out.chk.json (2 fields …)`, no `outside the loaded image` status |
| M29 (C-10) | the helper does not call `clear_check_results` | C 057_1, D 057_2, 057_3 | **KILLED 3/3**: stale `validation complete` / `-> pass` |
| M30 (C-6, 002.5/9) | the save-back handler swallows the error | D 002_5_9 | **KILLED**: "the save-back error was swallowed; the app runs on" |

Not run here: the full suite (batch end); Windows (operator rule); the M1 … M24 battery (DeepSeek, `E5-mutants.md`, not touched). `EXPECTED_SCANNED_TEST_FILES` unchanged (no new test file).

Observation for the orchestrator: my wait for host 2's idle state matched its own `pgrep` command line, so e5c-02 may have overlapped the tail of the orchestrator's serial re-run of `test_b97_flow_execution.py::test_tc_b97_55_…` (3 loops) by a few minutes; if that node's timing result matters, re-read it with this in mind.

Teardown: host-2 worktree `s19_i5c`, the RED and mutant copies and the `i5c-` helpers removed; `git worktree list` shows no `s19_i5c` entry. (A first `worktree add` landed under `s19_app/` by a relative path and was removed at once with `worktree remove`; nothing else was touched.)

## 6. Marks totals (final)

40 cases (34 + 6 at E5): **36 covered, 4 partial** (002.5/6 and 002.5/9: fault injected; 041.3/5 and 041.3/6: panel seam); 0 gap. Tests marks (strongest node per case, counted from the record): full 23 (incl. the cases an AT node drives black box), full (output) with drive partial 13, partial 4. Results: the 30 Check Editor cases in `C` verified 3/3 runs (e5c-02, -03, -04); the 10 in `D` verified (e5c-02, 3 fresh apps per node); windows not_run. `trace_check.py` on the increment: one gap, EVID (`04-validation.md`, written at E5 close).
