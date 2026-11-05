# Inc 8 — validation (E5)

**Verdict: PASS-WITH-NOTES.** The CRC model now follows the parametric model (the `reverse` init fix, D13-20), the CRC config errors name their field, a Designer template is refused by name, and a later block reads this run's external-step copy and says so. The two code-review blockers (F1, F2) are closed and re-reviewed. No HIGH or MAJOR is open; the MINOR and INFO notes are routed (§Not run / owed). Branch `b101-inc8`, head `dff4304` plus the uncommitted re-review and re-audit sections and these records. Windows host only (win32, Python 3.11.15); no Linux run exists. Evidence states in the tables: `executed` unless marked.

## Runs

Transcripts are under `.dev-flow/2026-11-01-batch-101/evidence/inc-8/` (call it `ev/`).

| Run | Result | Evidence |
|---|---|---|
| RED on base: the tester's two files on base `e266395` | **64 failed, 18 passed in 40.33 s** (the 18 are the design's holds-on-base positive controls) | `ev/red-01-tester-base.txt` |
| int-01: the two files as delivered, on the merged tree (`499d15d` + origin/main `f11b3f4`) | **22 failed, 60 passed in 43.79 s** (8 in the tests, 14 in design examples that contradicted canon rows; 0 source fixes) | `ev/int-01-new-tests-first.txt` |
| int-02: the same files on the pre-merge commit `499d15d` | **22 failed, 60 passed in 43.46 s** (the same 22: none comes from the merge) | `ev/int-02-new-tests-premerge.txt` |
| int-03: the corrected files on `origin/main` `f11b3f4` (RED on base) | **64 failed, 18 passed in 46.25 s** | `ev/int-03-red-on-main.txt` |
| int-04: 51 files one by one (touched modules and their importers, the guards, the two new files) | **1218 passed, 1 skipped, 0 failed** | `ev/int-04-tree-touched-and-neighbours.txt` |
| impl-smoke: the implementer's smoke transcript | recorded, no pass count (probes of the new reasons) | `ev/impl-smoke.txt` |
| mut-00-base: control run for the mutants (unmutated copy, both files) | **82 passed in 26.57 s** | `ev/mut-00-base.txt` |
| mut-M01 … M19 (20 mutants; M10 shares M06's run) | all **KILLED**: 1 to 26 failed per mutant, none survived; per-node table in `E5-mutants.md` | `ev/mut-M01.txt` … `ev/mut-M19.txt` |
| e5c-01: F1 and F2 tests on the delivered code (RED) | **3 failed, 1 passed in 166.01 s** (14/4 passes on either order) | `ev/e5c-01-red-f1-f2.txt` |
| e5c-02: the same four tests after the fix (GREEN) | **4 passed in 24.36 s** | `ev/e5c-02-green-f1-f2.txt` |
| e5c-03: the two Inc 8 test files after the corrective pass | **97 passed in 54.37 s** | `ev/e5c-03-new-files.txt` |
| e5c-04: 47 files that import `crc`, `crc_config`, `flow_execution_service`, `flow_model` or `flow_report_service`, one run per file | **1189 passed, 1 failed** (sum of the 47 per-file lines): `tests/test_b97_flow_execution.py::test_tc_b97_55_input_queued_during_a_run_starts_no_second_run` ("2 `run_chain_set` calls for one Run") | `ev/e5c-04-touched-module-importers.txt` |
| e5c-06: that file again, whole | **75 passed in 438.18 s**; the failure did not reproduce. The node also passed 3/3 alone (not saved as a transcript; stated in `E5-corrective-notes.md` §5). Recorded as a flaky pass, not hidden: a timing arm like `tc_b97_64` that overlapped another session's test load | `ev/e5c-06-rerun-b97-flow-execution.txt` |
| e5c-05: the law guards of the repo (`test_id_registry`, `test_engine_unchanged`, `test_requirements_canon`, `test_tui_directionb -k test_tc031`) | **27 passed, 181 deselected in 6.61 s** | `ev/e5c-05-law-guards.txt` |

## Mutant score

**20/20 KILLED**, 0 survivors, 0 N/A (`E5-mutants.md`). Each mutant ran against a detached copy of `e455a07` with both test files (82 cases then); every file restored byte-exact (`git diff --quiet` true after each). M13 and M19 are broad (26 and 23 failures); the sharper single-purpose kills are M14, M17, M09, M11 and M05. The mutants were not re-run on the corrective head (§Not run).

## Reviews

- **E3 design:** `architect` round 1 **FAIL** (A-1, A-2 MAJOR; A-3 … A-8 MINOR) and `security-reviewer` round 1 **FAIL** (S-1, S-2 MAJOR; S-3 … S-8 MINOR), both on records `5aac5c9`. Round 2 (`E3-r2.md`, architect): **PASS-WITH-NOTES**, A-1, A-2, S-1, S-2 closed; four new MINOR (N-1 … N-4), ruled and handed to E4 as addenda. The slice stays at 4 source files.
- **E5 code review:** `code-reviewer` **FAIL, BLOCK-UNTIL F1 (MAJOR: a deeply nested number field crashed the Operations dialog) and F2 (check order of the external step differed from R-FLOW-EXT.14)** → re-review of F1 and F2 on the corrected diff: **PASS** (RED on the old code, GREEN on head, probes found 0 escapes). F3 … F7 are MINOR or NIT and routed. `E5-code-review.md` §Re-review.
- **E5 security:** `security-reviewer` **PASS-WITH-NOTES**, no HIGH or MEDIUM. S8-1, S8-2 LOW (to Inc 9), S8-3, S8-4 INFO (backlog). `E5-security.md`.
- **Coverage audit** (`qa-reviewer`, ran nothing): first audit found 79 of 82 coverage cells wrong as they stood and 11 marks full → partial; re-audit of the 45 changed or new cases, final **99 cases: 96 covered, 3 partial, 0 gap, 0 conflict**; all 101 cited node ids collect. The 3 partial: 9/15, 12/10, FLOW-CRC.4/4. `E5-coverage-audit.md` §Re-audit.

## Not run / owed

- **No Linux run** of `tests/test_b101_flow_ext_copy.py` and `tests/test_b101_crc_model_and_reasons.py`; 9/10, 9/15 and 12/10 skip off Windows by design. **Full suite**: owed at the batch end; Inc 8 ran touched-module importers only (47 + 51 files).
- **Partial cases:** 9/15 (arm (b) cannot reach the rebind while a junction back into the project is accepted, S8-2; S-4 is carried by arm (a)); 12/10 (exact summary pinned, the lane failure line is not observed, Windows only); FLOW-CRC.4/4 (the shipped parser returns at most one error, so the three-error join is reachable only through an injected parser; reword the row or keep the join as defence).
- **Routed:** S8-1 and S8-2 to Inc 9 (D15-18); S8-3, S8-4, F5 … F7, the 9/15 Linux non-link arm, the 9/11 name check, the stack-depth bands of 001.11/9 and /10, the black-box ATs A-2 … A-7 with the 9/7 hardening, 14/4 vs 14/5, and the `tc_b97_55` flake are rows in `.dev-flow/BACKLOG-CODE.md`.
- **Records owed to the requirements session:** thresholds "8/8" of R-CRC-CONFIG-001.10 and .11 (now 11 and 14 cases); the R-FLOW-CRC.4 three-error wording.
- **Release note:** `release-note-crc.md` (CRC init with `reverse`) is a tracked batch-end deliverable (ruling S-8).
- At close, `trace_check.py --req inc-8/01-requirements.md inc-8/E1-slice.md --tests tests --base main --src s19_app` reported `trace_check: 4 US, 18 active requirements (0 withdrawn), 0 gap(s)`. The first run, with `01-requirements.md` alone and no `--tests`, reported 3 gaps: SLICE `crc_config.py` and `flow_model.py` (named by the E1 slice, which maps every changed function to its requirement, and now passed as a requirement file) and TEST R-FLOW-CRC.1 (the existing `test_at123_crc_computed_and_injected_at_output_address` carried no requirement id; the orchestrator added a one-line docstring naming R-FLOW-CRC.1 — `tests/test_flow_crc_block.py` + `tests/test_id_registry.py` 24 passed after the edit). The flow validator (`--brief`) reported `4 block · 753 notice`; the 4 blocks are the V20 atlas copies, owned by the orchestrator.
