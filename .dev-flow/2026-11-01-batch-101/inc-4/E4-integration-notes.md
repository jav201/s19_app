# Inc 4 — E4 integration notes

Batch 2026-11-01-batch-101, increment 4, branch `b101-inc4` (base `b7b77c4`). Integrator: Opus. Inputs: the DeepSeek v4 Pro implementation (3 units, `E4-impl-notes-{core,variant,app}.md`) and the Sonnet independent tests (`E4-tester-notes.md`), committed as found in `906d022`.

## 1. Verdict

**GREEN on the LAN Linux host**, with two failures that are not caused by Inc 4 and that the base shows too (section 3). Every test of the new file `tests/test_b101_symbol_reads.py` passes, its `serial_timing` nodes included. The re-pinned `tests/test_tui_patch_editor_v2.py`, `tests/test_checks_engine.py`, `tests/test_id_registry.py`, `tests/test_suite_hygiene.py`, every test file that imports `changes.io`, `change_service` or `variant_execution_service` or drives one of the six session-read handlers (101 files, from a grep), and the law guards (`test_engine_unchanged`, `test_requirements_canon`, `test_id_registry`, `test_tui_directionb`, `test_changes_schema`) pass as well. All 22 cases are `verified (linux, …)` in `02-test-cases.md`.

Where it ran: `<HOME>/work/s19_i4`, a detached worktree of `origin/main` `7add3d63` (a descendant of `b7b77c4` that differs only in `.dev-flow/` records) with `git diff b7b77c4` of the local worktree applied on top. Interpreter: `s19ci` Python 3.11. Each transcript prints `s19_app.__file__` first, which is that worktree. Transcripts are in `.dev-flow/2026-11-01-batch-101/evidence/inc-4/int-NN.txt`, redacted to `<HOME>` / `<USER>`.

## 2. Runs and counts

| Transcript | What | Result |
|---|---|---|
| int-01 … int-20 | lane 1: `-n 8 -m "not serial_timing"` over the 101-file GREEN set in 20 chunks (5 files each). Chunks were needed because the host has 8 cores and was shared with three other agents' runs (load 7–19, `int-load.txt`). One 101-file run would have passed the 2400 s timeout. | 3036 passed, 11 failed, 97 skipped, 1 xfailed (3145 nodes) |
| int-21 | guards and the new file after fix F-1 (test rename) | 126 passed, 1 failed (F-3, found here) |
| int-22 | the 7 lane-1 failures that are not Inc 4's, run serially on the Inc 4 tree | 19 passed, 1 failed (`tc1802`, environment) |
| int-23 | the same 7 failures on a clean `origin/main` worktree (no Inc 4 diff) | 18 passed, 2 failed (`tc1802`, and one `b100_65` node under load) |
| int-24 | `test_requirements_canon`, `test_id_registry` after fix F-3 | 23 passed |
| int-25 | `serial_timing` lane over the GREEN set on a **loaded** host (load 12) | 10 failed, 43 passed. **Invalid as a measurement**: 9 of the failures are b100 timing nodes that Inc 4 does not touch. Kept as a record only. |
| int-26 | `serial_timing` lane over the GREEN set on a **quiet** host (load 1.28, no other pytest running) | 53 passed, 2 skipped, 0 failed |
| int-27 | `serial_timing` nodes of `tests/test_b101_symbol_reads.py` with the OR-2 bound (fix F-4) | see section 5 |
| int-28 | final: the new file, `test_suite_hygiene`, `test_id_registry`, `test_requirements_canon`, `test_checks_engine`, `test_tui_patch_editor_v2`, `test_engine_unchanged`, after every edit | see section 5 |

The `-n 8` lane gives no per-file node counts in `-q` mode. The new file collects 24 nodes (18 functions, `E4-tester-notes.md` §1): 22 run in lane 1 and 2 are `serial_timing`. The 22 passed in int-03, int-21 and int-28, and the 2 timing nodes in int-26 and int-27.

## 3. Failures and causes

| Id | Failure | Cause | Action |
|---|---|---|---|
| F-1 | `test_id_registry` G1, `test_at280_*`, `test_at281_*`: "AT-1000 carried by `…_symbol_read_at_1000_entries_…` is not in the registry" (int-09) | **The test names were wrong.** The registry grammar reads `_at_<digits>` in a test name as an `AT-*` id, so `…_at_1000_entries…` names an id that does not exist. The design does not mandate that spelling: E1 says "the tail may change at E4". | Renamed the two timing tests to `…_of_1000_entries_by_220040_tags…`, and the tests column of `02-test-cases.md` with them. No assertion changed. |
| F-2 | `test_tc607_*` scanned-file count (expected) | One new test module. | `EXPECTED_SCANNED_TEST_FILES` 250 → 251, the count the guard measured (OR-3). It passes in int-09, int-24 and int-28. |
| F-3 | `test_requirements_canon::test_review_files_name_only_existing_tests` (R-DOC-CANON.10): `test_headless_project_run` is cited by `CODE-CHANGES.md:222` (int-12), then by `S9-ears-strict.md:26` and `:288` (int-21) | **Seam SR-1.** D-1 deletes the test, but two review files still cite it in code spans, and the canon guard refuses a citation of a test that does not exist. | Smallest fix that does not weaken the guard: `CODE-CHANGES.md` D9-7 marked `done (batch-101 Inc 4)` (forwarded by A-8 "at integration"), and both D9-7 texts and the S9 R-CHK-001 note reworded to "the headless project-run test of `tests/test_checks_engine.py` … (both deleted in batch-101 Inc 4)", without the dead name. `docs/requirements/history/` keeps the old name. It is outside the guard's scan and is history. |
| F-4 | R-CHG-SYM.13/3 bound | **The test asserted a bound the design does not set.** It allowed 2 × 1.0 s. OR-2 sets 2 × the measured addition with a 1.0 s ceiling. | Bound set to `timing_bound(1.0)`. The measurement is 0.622 s, so 2 × 0.622 = 1.244 s and the ceiling governs. Docstring states OR-2. |
| L-1 | `test_b100_active_variant::test_tc_b100_19_*` ×2 (int-01), `test_b100_save_dialog::test_tc_b100_65_*` / `_66_*` ×4 (int-02): "save-back outcome" / "Save project ab did not land" | **Host load**: the pilot's wait ran out at load 17–19. These are save paths, not symbol reads. | Re-run serially (int-22): all 6 pass. On the base (int-23) one of them fails under load too. Not Inc 4. |
| E-1 | `test_changes_file_notation_help::test_tc1802_nine_md_sections_intact_tenth_section_added` | **Environment**: the test reads `prototypes/cambios_10_12_2026/help_sections.md`. That path is excluded by the main checkout's `.git/info/exclude` and is absent from every clean clone. | Fails the same on the base (int-23). It belongs to the backlog, not to Inc 4. |
| T-1 | int-25: 9 b100 timing nodes plus R-CHG-SYM.13/3 over their bounds | Measured at load 12 on 8 cores. | Re-measured on a quiet host (int-26): 0 failures. |

No source failure: every failure above is a test-name or record seam, load, or the environment. The implementation matched the design in every run.

## 4. Changes the integrator made

- **Source (slice files only):**
  - `s19_app/tui/changes/io.py` `_parse_entries`: the lazy index is keyed on an `index_built` flag instead of `symbol_index is None`. With no declared A2L, `_symbol_name_index` returns `None`, so the implementer's check called it again for every symbol entry. The graph says "once per read" (node `_parse_entries`, E3 A-2), so this was a deviation from the design. Behaviour is unchanged; the call count is now at most 1 in every case.
  - `s19_app/tui/services/change_service.py`: three trailing blank lines at end of file, left by the deletion, removed.
- **Tests:**
  - `tests/test_checks_engine.py`: `test_headless_project_run`, its `run_checks_for_project` import and the `PUBLIC_EXAMPLES` constant only it used are deleted (D-1 / A-1 / OR-3). The module docstring's TC-023 bullet and the section header are reworded.
  - `tests/test_b101_symbol_reads.py`: F-1 renames and the F-4 bound.
  - `tests/test_id_registry.py`: F-2.
- **Registry:** `AT-TC-REGISTRY.jsonl` TC-023 `nodes` lost `tests/test_checks_engine.py::test_headless_project_run`, and 10 nodes remain (OR-3). The seed `statement` text, which is provenance, is untouched.
- **Records:** `CODE-CHANGES.md` D9-7 done and `S9-ears-strict.md` R-CHK-001 / D9-7 notes (F-3). `02-test-cases.md` gets the R-CHG-SYM.12/2 precondition (OR-1), the F-1 test names, and the Coverage and Result columns.

File count: 4 source files in the increment (`app.py`, `io.py`, `change_service.py`, `variant_execution_service.py`), within the cap.

## 5. Measured timings (LAN Linux host, quiet: load 1.28, no other pytest)

| Measure | int-26 | Bound | Note |
|---|---|---|---|
| R-CHG-SYM.13/1: `parse_change_document`, 1 000 symbol entries × 220 040 tags, 5 runs | 0.183, 0.185, 0.185, 0.186, 0.186 s; index built 1× per run | 1.0 s (≥ 5 × measured; margin 81 %) | Below the 0.5 s stop rule, so no re-ruling is needed. The tester's rehearsal measured 0.18–0.19 s. |
| R-CHG-SYM.13/3: whole-document Edit JSON confirm, 1 000 entries × 220 040 tags | 1.040 s without symbols, 1.662 s with symbols, so resolution adds **0.622 s** | 1.0 s (OR-2: min(2 × 0.622, 1.0); margin 38 %) | The ~1 s row rendering is out of scope (OR-2). |
| Loaded-host record (int-25, load 12) | 0.518–0.668 s read; 2.439 s added | — | Not a measurement; shows the host-load sensitivity. |

int-27 and int-28 results: see the addendum at the end of this file.

## 6. Orchestrator rulings applied

- **OR-1** (R-CHG-SYM.12/2): attaching an A2L with a project open copies it into the project folder. The precondition is "no A2L file in the project folder at run time", so removing the copy after the attach is accepted. The case's precondition and inputs in `02-test-cases.md` are reworded. The test is unchanged.
- **OR-2** (R-CHG-SYM.13/3): the bound covers the cost symbol resolution adds (with symbols minus without), at 2 × the measured addition with a 1.0 s ceiling, on the LAN host. The row rendering is out of scope. Applied as F-4.
- **OR-3** (D-1 / A-1): `test_headless_project_run` and its import deleted. TC-023 `nodes` lost that node and the other 10 stay. `EXPECTED_SCANNED_TEST_FILES` re-measured at 251. The removal pulled in seam SR-1 (F-3).
- **OR-4** (tester read the implementer's in-progress call-site edits early, declared in `E4-tester-notes.md` §5.7): recorded. Check: I reviewed the tests against the cases rather than against the code. Each test drives the surface its case names, asserts the painted lines, files or call counts that the case's expected result states, and keeps the case's negative control. R-CHG-SYM.12/2 matches OR-1, and R-CHG-SYM.13/3 asserted a bound wider than the design until F-4. No assertion depends on an implementation detail that the design does not name: `_symbol_name_index` is the graph's node and the call counter is the row's primary oracle. Finding: the tests are faithful to the cases.

## 7. Seam rulings

- **SR-1 (F-3).** D-1's deletion versus canon guard R-DOC-CANON.10. The design forwarded the CODE-CHANGES edit to the requirements session (E1 §4, A-8 "marked done at integration"). The guard makes it this increment's work, because the test cannot be deleted while a review file names it. Smallest fix: reword the three citations without the dead name and mark D9-7 done. The requirements session should confirm the wording.
- **SR-2 (F-1).** Test names must not contain `_at_<digits>`, or the registry reads an `AT-*` id. Recorded for later testers (backlog suggestion: say so in the test-naming note of the flow).

## 8. Left for E5

- Mutants M-1 … M-15 (the table in `02-test-cases.md`; the tester notes name the test each should turn RED). M-10 / M-15 now also cover the no-context path, because the `index_built` flag makes the count ≤ 1 there.
- Trace: `trace_check` with the 22 cases now `verified` (6 TEST gaps closed). EVID gap for E5.
- Forwarded, not done here: BACKLOG T-03 closed as superseded by D9-7, T-02 open after Inc 4 (D-4), the S4-1 link/reparse row (Inc 9), the stale `run_checks_for_project` docstring mention in `s19_app/tui/changes/check.py:278` (outside the slice), Inc 14 docs (ch08 §8.2, ch10, ch17, DOSSIER F-01; S4-8).
- Backlog: `tc1802` depends on an excluded, untracked prototype file (E-1). The b100 save and save-dialog pilot waits flake under host load (L-1).
- Inc 5: R-CHG-SYM.9/5 counts 3 `#check_mem_table` rows, and the R-CHG-SYM.11/3 report assertion reads the Markdown Modifications layout. Both re-pin if Inc 5 changes them (tester notes §5.4, §5.5).

## Addendum — final runs (quiet host)

- **int-27** (load 0.78): `-s -m serial_timing tests/test_b101_symbol_reads.py`, 2 passed. R-CHG-SYM.13/1 read 0.174, 0.176, 0.180, 0.180, 0.186 s (bound 1.0 s, margin ≥ 81 %), index built 1× per run. R-CHG-SYM.13/3 confirm 1.017 s without symbols, 1.412 s with them, so resolution adds 0.395 s (bound 1.0 s, margin 60 %).
- **int-28** (load 0.89): `-n 8 -m "not serial_timing"` over the new file, `test_suite_hygiene`, `test_id_registry`, `test_requirements_canon`, `test_checks_engine`, `test_tui_patch_editor_v2`, `test_engine_unchanged`. **179 passed**, 0 failed, on the final tree (every integrator edit applied; diff hash checked against the local worktree before each run).
- Addition measured twice on a quiet host: 0.622 s (int-26) and 0.395 s (int-27). The OR-2 bound uses the larger, and 2 × 0.622 > 1.0 s, so the 1.0 s ceiling governs.
- Remote-tree check (orchestrator notice on shared scratchpad scripts): before trusting the runs, the remote tree's `git diff` was compared with the synced diff. The two were identical apart from `steps.log`, which the host's ignore rules hide. After each re-sync, file md5s of the source files and the new test file matched the local worktree. The helper scripts now carry the `i4int_` prefix.
