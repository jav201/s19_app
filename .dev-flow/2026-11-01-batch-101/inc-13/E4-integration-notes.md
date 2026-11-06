# Inc 13 - E4 integration notes

Integrator: orchestrator-spawned E4 integrator (model opus). Branch `b101-inc13`, base `b7b77c4`. E4 work committed as found in `38e31bf` (DeepSeek v4 Pro implementers, 3 units; Sonnet independent tester). Every test run on LAN Linux host 2 (16 cores), env `s19ci` (Python 3.11.18, pytest-xdist 3.8.0, textual 8.2.8), in a detached worktree at `origin/main` `f9f3cb09` (it contains `b7b77c4` and has no `s19_app/` or `tests/` drift from it) plus `git diff b7b77c4 -- s19_app tests` of the branch. `s19_app.__file__` printed at the head of every transcript points into that worktree. The worktree was removed at the end. Nothing ran on the Windows PC.

## Verdict

**GREEN.** One product-side finding (E4-F1) is outside the slice and is handed to E5. Case R-SEG-PREV.7/1 is `blocked` on it.

## Transcripts (`../evidence/inc-13/`)

| File | What | Result |
|---|---|---|
| `int-lane1-r1.txt` | lane 1 (`-n 12 -m "not serial_timing"`), the whole GREEN set, before the fixes | 3 failed, 801 passed, 16 skipped |
| `int-probe-r1.txt` | the three run-1 failures alone, after the fixes | 14 passed |
| `int-lane1-r2.txt` | lane 1 again, after the fixes | **804 passed, 16 skipped**, 0 failed |
| `int-ast-r1.txt` | the D-2 AST check and its control, `-rA` | 2 PASSED (not skipped, N-5) |
| `int-serial-r1..r3.txt` | serial lane (`-m serial_timing`), the 4 perf nodes, run alone, 3 times | 4 passed, each run; 0 bounds under 20 % margin |

The GREEN set: the 3 new test files; `tests/test_crc_designer_view.py` (whole module); `tests/test_crc_kernel.py`; `tests/test_b101_crc_model_and_reasons.py` (Inc 8); every test module that imports `crc_designer_view`, `segment_split_view` or `crc_kernel` (grep: `test_b100_reuse`, `test_b101_flow_ext_copy`, `test_b97_key_bar`, `test_b99_export`, `test_b99_staging`, `test_crc_designer_model`, `test_crc_job_upconvert`, `test_import_census`, `test_project_gather`, `test_segment_split_window`, `test_tui_patch_json`, `test_universal_paste`); `tests/test_id_registry.py`; `tests/test_suite_hygiene.py`; the law guards named in the repository's `CLAUDE.md` (`test_engine_unchanged.py`, `test_tui_directionb.py` with its `test_tc031_*` nodes, `test_requirements_canon.py`, `test_id_registry.py`). There is no `AGENTS.md`. The 16 skips are outside the slice: a run of the slice modules with `-rs` (219 passed) showed no skip.

## Measured times (serial lane, 3 runs, QC-TM `report_margin`)

| Case | Bound | Run 1 | Run 2 | Run 3 | Worst margin |
|---|---|---|---|---|---|
| R-CRC-PREVIEW-002.2/1 (Join gaps change, F-23 CRC scene) | 3.0 s | 1.246 s | 1.225 s | 1.210 s | 58.5 % |
| R-CRC-PREVIEW-002.3/1 (template load) | 3.0 s | 0.798 s | 0.843 s | 0.849 s | 71.7 % |
| R-CRC-PREVIEW-002.4/1 (Ranges edit, after the quiet time) | 3.0 s | 1.008 s | 1.001 s | 1.003 s | 66.4 % |
| R-SEG-PREV.20/1 (`g` in the F-23 Split/Join scene) | 2.5 s | 0.699 s | 0.683 s | 0.674 s | 72.0 % |

Base, from the tester's RED run (host load 9-12), in the table's order: 28.4 s, 531.7 s, 60.3 s, 198.9 s (002.3 = 531.7 s, 002.4 = 60.3 s per `red-01-tester-base.txt`; the two middle values were swapped here and corrected at the E5 corrective pass, C-6). Host load at the start of each serial run: 5.64 / 3.73 / 2.73 (1-minute average, still falling after my own parallel run that ended about 30 s before). No other pytest was running when I checked at the end. Other worktrees on that host belong to other sessions, so concurrent use during the serial runs cannot be ruled out. The three runs agree within 4 %. The case text asks for 5/5 runs (M-3); the orchestrator asked for 3/3 at E4. The remaining runs are owed at E5.

## Failures and causes (run 1)

1. `test_id_registry.py::test_tc607_scanned_corpus_matches_the_declared_bound`: scanned 256, declared 250. **Cause:** the increment adds 6 scanned modules (3 test files and 3 support modules: `b101_designer.py`, `b101_demo_image.py`, `b101_inc13_reference.py`); the tester left the bump to the integrator. **Fix:** `EXPECTED_SCANNED_TEST_FILES` 250 -> 256, measured, with the history comment.
2. `test_b101_designer_recompute.py::test_r_crc_preview_002_1_image_set_cleared_replaced`: `IndexError` in the step (c) predicate. **Cause (the test, not the design):** after the image is replaced, the preview is still the one-line empty-state note until the 150 ms quiet time ends. That pending state is what the design specifies (R-CRC-DESIGNER-001.2.2/2: an image change is a pending change). The predicate indexed `split("\n")[1]` and raised on that state, so the wait aborted instead of polling. **Fix:** the predicate is `split("\n")[1:2] == ["concat: 0x<crc>"]`. The expected line 2 is still checked exactly. Nothing is weakened: the case passes only when the recomputed line appears.
3. `test_b97_key_bar.py::test_tc_b97_69_page_keys_do_nothing_where_disabled`: `did not settle: A2L loaded` under `-n 12`. **Cause: not established.** It passed alone (`int-probe-r1`) and in the full lane run 2. The node loads an A2L and its wait timed out. It does not touch the Designer's text-edit path, but the new `current_file` watcher does run on an image load, so the link to this increment is not excluded. Recorded for E5 (item 3). No change was made.

## OR-1 (R-SEG-PREV.20/1 and R-SEG-PREV.7/1, the state line in the F-23 Split/Join scene)

- **Canon:** R-SEG-PREV.7: *If the planned export has a conflict byte, then ... `⚠ <size> would clobber source — abort on export`*. R-SEG-PREV.8: *If the planned export has a guard file **and no conflict byte**, then ... `⚠ GUARD ...`*. The canon therefore puts the clobber line ahead of the GUARD chip whenever a conflict byte exists.
- **Scene:** `gap_conflict(...)` of the scene is > 0 (asserted by the arm), and the guard fires (span 9.20 MiB, fill above 50 %).
- **Code:** `SplitJoinWindow._state_text` (`s19_app/tui/segment_split_view.py`, shipped since batch-95 `42b7bf4`) checks `plan.guard` before `plan.conflicts`, so it paints `⚠ GUARD  9.20 MiB span — e will ask`. The export action itself refuses on conflicts before it reaches the guard gate (LLR-136.4), which matches the canon's priority. Only the state line inverts it.
- **Ruling:** the case is right and the product deviates from canon. The GUARD chip is the shipped state, but the canon does not describe it for this scene. This is **finding E4-F1** for E5. `_state_text` is not a node of this increment's slice, so no product code was changed. The case text stays as written. R-SEG-PREV.7/1 is `blocked`. R-SEG-PREV.20/1 passes for the timing and the stats line, and its state-line assertion pins the shipped GUARD chip, so the defect fix will flip it on purpose. The arm's comment and docstring now say this (comment-only edit in `tests/test_b101_inc13_perf.py`; no assertion changed).

## OR-2 (the extra waits in `test_three_warn_conditions_through_view`)

Accepted. That node also sets Pad byte `""` (a text edit) before its first read, a site that `E1-slice.md` §3 omits. The tester's inserted snapshot and wait are the allowed D-2 pattern. The AST check strips them like the other sites and passes on the whole module (`int-ast-r1.txt`), so no change to the check was needed.

## Seam rulings

- **SR-1 (records lag the binding E3 round-2 addendum).** The cap is 16777216 (E3 round 2: "Row 001.11 text and its case use 16777216"). The code, the tests and the designer implementation notes use 16777216, but `01-requirements.md` (the Coverage-cap definition, row R-CRC-PREVIEW-001.11, and row 001.12 (b)) and `02-test-cases.md` (cases 001.11/1 and 001.12/1) still read 67108864 / `0x00000000-0x04000001`. **Smallest fix:** these records now read 16777216 / `0x00000000-0x01000001` (coverage size 16777217), and the cost note uses the round-2 arithmetic. `codewire/graph-inc13.md` still carries the old examples (lines 43-45, 192-193, 215, 231-233). It is the E2 artifact and stays as reviewed; the addendum supersedes it (E5 item 4).
- No design-vs-code contradiction was found in the three slice files. No product code changed at integration.

## Changes made at integration

- `tests/test_id_registry.py`: bound 250 -> 256 (failure 1).
- `tests/test_b101_designer_recompute.py`: one predicate (failure 2).
- `tests/test_b101_inc13_perf.py`: OR-1 comment and docstring only.
- `01-requirements.md`, `02-test-cases.md`: SR-1. `02-test-cases.md` also has its Coverage and Result columns filled.
- Evidence `int-*.txt`, with home paths and account names redacted to `<HOME>` / `<USER>`.

## Counts

39 cases: 38 pass, of which 3 are timing cases (3/3; 5/5 owed) and 1 is partial (R-SEG-PREV.20/1); 1 is blocked (R-SEG-PREV.7/1); 0 fail. Lane 1: 804 passed, 16 skipped. Serial: 4 nodes × 3 runs. AST check: 2 passed.

## Items for E5

1. **E4-F1:** the `_state_text` priority (GUARD before conflict) contradicts R-SEG-PREV.7 / .8. Route it to a slice that owns the state line. When it is fixed, flip the R-SEG-PREV.20/1 state-line assertion to the clobber line and close R-SEG-PREV.7/1.
2. Mutants M-1 … M-25 on the implemented tree (the tester ran only the base-source mutants), and the 5/5 QC-TM runs (M-3) for the four timing cases.
3. `test_tc_b97_69_page_keys_do_nothing_where_disabled`: a one-off "A2L loaded did not settle" under `-n 12` (lane 1 run 1). Re-run it in the full battery and decide whether it is a flake or is linked to the new `current_file` watcher.
4. `codewire/graph-inc13.md` cap examples are superseded by the E3 round-2 addendum (SR-1). Fold them into the canon with 16777216.
5. Tester ambiguity 3: confirm that a dropdown change stops a pending on-display timer (E1-D2) on the implemented tree.
