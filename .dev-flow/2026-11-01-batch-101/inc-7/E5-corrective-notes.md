# Inc 7 — E5 corrective pass (rulings C-1 … C-8)

Batch 2026-11-01-batch-101, increment 7, branch `b101-inc7` (head `90ea8ae` + this pass). Agent: E5 corrective, model Opus. Inputs: `E5-rulings.md` (binding), `E5-code-review.md`, `E5-security.md`, `E5-coverage-audit.md`, `E5-mutants.md`, `01-requirements.md`, `02-test-cases.md`, `E3-rulings.md`, `E4-integration-notes.md`, `codewire/graph-inc7.md`.

**Outcome: all eight rulings done.** One source file changed (`diff_report_service.py`, C-1); the other three source files of the increment are untouched by this pass. Cases 52 → 60, all `covered`. Mutants 28/28 killed after the pass (M22 now killed). Final runs green except the known `test_at_056e_a2b_diff_report_byte_identical_despite_selection`. The routed items are in `.dev-flow/BACKLOG-CODE.md` (4 bullets).

## 1. Ruling → change

| Ruling | Change | Files | Tests (new / changed) | Case ids |
|---|---|---|---|---|
| C-1 (S5-1) | The staging file is `<name>.<16 random hex>.part` (`secrets.token_hex(8)`), still created exclusively in the report folder; nothing else in `_write_report` changes. Recorded as a design-gap fix (`01-requirements.md` §E5; CTX-DIFFREPORT `file write` term; graph I-6 and node `_write_report`; `E3-rulings.md` A-2 / N-1 marked superseded in part; `E1-slice.md` row 4). No `R-*` row text changes. The LLR-155.3 placement census stays GREEN (`test_tc_b99_13_no_final_name_replace_outside_placement`, Windows and Linux); its comment names the new staging name. | `s19_app/tui/services/diff_report_service.py`; `tests/test_b99_staging.py` (comment) | new `test_r_cmp_005_16_5_planted_link_at_part_name_is_not_followed`; changed `test_r_cmp_005_16_3_stale_part_file_is_not_touched` (see §5) | R-CMP-005.16/4, /5 |
| C-2 (M22) | A pipe planted in every `_md_cell` field (linkage Type, Disposition, Linkage; flow disposition; refusal code; Applied (UTC)); exact rows, structural pipe counts, the bullet and the line. Kills M22. | — | new `test_r_before_after_report_001_22_2_pipe_in_vocabulary_cells_stays_escaped` | R-BEFORE-AFTER-REPORT-001.22/2 |
| C-3 | Cases and tests for: the loaded MAC through key `b`; the status after a failed write (.16/3); the before/after failure status (.17/3); image B's path; the N-1 node cited in its own row (.16/4). | — | new `test_r_before_after_report_001_35_3_bkey_loaded_mac_is_used`, `test_r_cmp_005_16_3_report_control_failed_write_status[-diff-report.md]` / `[-diff-report.html]`, `test_r_cmp_005_16_3_bkey_failed_write_status`, `test_r_cmp_005_17_3_bkey_html_failure_status[raise]` / `[refuse]`, `test_r_cmp_004_9_2_5_image_b_path_text` | .35/3, .24/5, R-CMP-005.16/3, /4, R-CMP-005.17/3, R-CMP-004.9.2/5 |
| C-4 (R-1 … R-3) | Black-box through keys with the pilot, each asserting the painted status exactly: R-1 key `b` with a MAC file loaded through the app's own MAC loader (`_load_mac_file` + `_merge_mac_with_existing_primary`); R-2 key `7`, Compare and Report by `enter`, the Markdown and then the HTML write failing half way (panel status equality and the status-log line); R-3 key `b` with the HTML generator raising and refusing. None is `partial`: every route has keys. The painted text is read from `#log_line_1 … 4` (and `#diff_status`); the written-pair line of R-1 is compared cut to the 120-column log width, the product's own cap. | — | the C-3 nodes above; helper `_drive_bkey_texts` gains `mac_text` and returns the painted lines and the `reports/` listing | as C-3 |
| C-5 | R-4: `test_at_b94_18_hostile_names_render_literally` now pins the whole flow Image A line (`- Image A: source\.out [flow] …`, no double backslash). R-6: mutants M24 (composer drops the MAC from `compare_images`) and M25 (drops `mac_records` from the generator kwargs) kill .35/1 and .24/2 on an output difference. | — | changed `test_at_b94_18_hostile_names_render_literally` (assertion added) | R-CMP-004.9.1/9, .35/1, .24/2 |
| C-6 | `test_r_cmp_004_14_2` compares `row[:58]` and the whole hex part before the ASCII column (was `row[:10]`); the case's Expected is not reworded. | — | changed `test_r_cmp_004_14_2_html_and_markdown_agree` | R-CMP-004.14/2 |
| C-7 | `test_r_cmp_005_17_1` asserts `reports/` exists before it asserts the folder is empty. | — | changed `test_r_cmp_005_17_1_ab_html_failure_removes_markdown` | R-CMP-005.17/1 |
| C-8 | `02-test-cases.md` repaired per the audit change table C-1 … C-8 and the rows above (labels, node sets, 8 new rows, Result from the final run, count note, mutant rows M20 … M27); `E1-slice.md` §4 lists the SR-1 census node and every node this pass touched. | records | — | all |

Source budget: 1 of the 4 increment source files touched by this pass. Test functions renamed or deleted: 0. Assertions removed: one, by ruling (§5).

## 2. RED / GREEN

| Step | Platform | Tree | Result | Transcript |
|---|---|---|---|---|
| C-1 RED | Windows | head `90ea8ae` source (`diff_report_service.py` restored from `HEAD` for the run, then the fix copied back; `git diff` checked both ways) + the E5 tests | **2 failed**: `16_5` `AssertionError: the planted link was followed` (the link target `elsewhere.txt` was created); `16_3` `FileExistsError` on the stale `<name>.part` | `evidence/inc-7/e5c-red-c1-windows.txt` |
| C-1 GREEN | Windows | fix applied | 5 passed (`16_1`, `16_2`, `16_3`, `16_4`, `16_5`) | `e5c-green-c1-windows.txt` |
| C-1 final | Windows | final tree | 6 passed (the five + the LLR-155.3 census node) | `e5c-final-windows-c1.txt` |
| C-2 RED | Linux | final tree with M22 applied | the new node **fails** (the linkage row holds the raw `by` + pipe + `tes`); C-2 cannot be RED on the current tree, because head still escapes the pipe — the RED the ruling asks for is the kill of M22 | `e5c-mut-M22.txt` |
| C-2 GREEN | Linux | final tree | passes (case-node run) | `e5c-final-case-nodes.txt` |

## 3. Final runs (redacted; `s19_app.__file__` printed first in each)

Per the orchestrator's addendum, only the Windows-specific C-1 arm ran on Windows; everything else ran on the LAN Linux host, in a separate detached worktree of the host's clone (merge base `9f9f6af` + the `b101-inc7` working-tree diff of `s19_app` and `tests`). **Deviation:** the addendum said to check out a probe branch in the host's main clone; that clone's working tree was in use by another integration's running pytest, so a separate worktree was used instead to leave it untouched. One pytest at a time on each host.

| Run | Platform | Scope | Result | Transcript |
|---|---|---|---|---|
| A | Linux, `-n 8 -m "not serial_timing"` | touched test files; every test file naming `diff_report_service` / `before_after_service`; `test_b99_staging.py`; `test_suite_hygiene.py`; `test_id_registry.py`; law guards `test_engine_unchanged.py`, `test_requirements_canon.py` (22 files) | 603 passed, 1 failed: the known `test_at_056e_a2b_diff_report_byte_identical_despite_selection` | `e5c-final-linux-a.txt` |
| B | Linux, `-m serial_timing` | same 22 files | 2 passed, 604 deselected | `e5c-final-linux-b-serial.txt` |
| C | Linux | `tests/test_tui_directionb.py -k tc031` (engine-frozen guard) | 3 passed | `e5c-final-linux-c-tc031.txt` |
| D | Linux, `-rA` | guards, counted by measurement | 119 passed: `test_id_registry.py` 12, `test_suite_hygiene.py` 64, `test_b99_staging.py` 31 (LLR-155.3 node `test_tc_b99_13_no_final_name_replace_outside_placement` PASSED), `test_engine_unchanged.py` 1, `test_requirements_canon.py` 11 | `e5c-final-linux-d-guards.txt` |
| E | Linux, `-W error::DeprecationWarning` | `test_before_after_report.py` after a one-character fix (`CAL\_A` written as `"CAL\\_A"`; the string value is the same, only the invalid-escape warning that run B reported goes away) | 34 passed | `e5c-final-linux-e-before-after.txt` |
| Cases | Linux, `-rA` | the 66 distinct nodes cited in `02-test-cases.md` | 66 passed | `e5c-final-case-nodes.txt` |
| C-1 | Windows | §2 | 6 passed | `e5c-final-windows-c1.txt` |

Known failures: `test_at_056e…` failed as expected; `test_at_b78_03` (palette freeze) is in none of these files; `test_tc024_report_trigger_surfaces_paths` passed in run A (no rerun needed).

## 4. Counts

- Cases: **60** (52 + 8 new): R-CMP-005.16/3, /4, /5; R-CMP-005.17/3; R-BEFORE-AFTER-REPORT-001.35/3, .24/5, .22/2; R-CMP-004.9.2/5.
- Coverage: **60 covered, 0 partial, 0 gap** (audit: 51 / 1 / 0 before the pass; .24/4 and .14/6 up by the audit, .14/2 back to covered by C-6).
- Cited nodes: **66** distinct (57 + 9 new; two new tests are parametrized into two nodes each), 66/66 passed.
- Mutants: **28 / 28 killed** (run 1: 23 / 24; M22 re-run killed; new M24, M25, M26, M27 killed). See `E5-mutants.md` §E5 corrective re-run.

## 5. Things to know

- **One assertion was removed, by ruling.** `test_r_cmp_005_16_3_stale_part_file_is_not_touched` asserted `FileExistsError` from a stale `<name>.part`. C-1 makes the staging name unpredictable, so the stale file no longer collides and nothing is raised. The test now asserts the report is written whole beside the stale file, which keeps its bytes, and that the folder holds exactly those two files. The N-1 guarantee it protects (a `.part` this write did not create is never touched) is unchanged. The requirement records log it as a design-gap fix.
- `test_r_cmp_005_16_5` skips with a reason where a symbolic link cannot be created. On this Windows host it ran (it did not skip). A directory junction was not tried (a junction targets a folder; the ruling and the finding name a link).
- The `\\?\` long-path prefix that Windows returns from `os.readlink` is stripped before the link-target comparison (first GREEN attempt failed on that test-side detail; the product passed).
- The MAC for R-1 is loaded through the app's own MAC parser and merge, not seeded. The A2L is still seeded as a payload (the audit's accepted precondition for the existing key-`b` cases).

## 6. What I could not do, or did not do

- The re-reviews the rulings name (security reviewer on C-1; coverage auditor on the changed and added cases) are not mine and have not run.
- No Linux RED for C-1 on the unfixed tree as a separate step: M27 (the fix reverted) is that proof on Linux (`FileExistsError`, since Linux `O_EXCL` refuses the link); the Windows RED in §2 is the one the finding describes.
- The full suite was not run (out of scope for this pass).
- A `%LOCALAPPDATA%\s19_app` folder exists on the Windows host with files dated before this pass started (07:57–07:58 local); this pass did not create or change it (every run used the isolated `LOCALAPPDATA`). Nothing touched the clipboard.
- The LAN host's temporary worktree used for these runs is removed at the end of the pass (`git worktree remove`).
