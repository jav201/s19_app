# Inc 7 - E5 mutant run (independent tester)

Tree: commit `90ea8ae` (branch `b101-inc7`), mutated only in a detached copy (removed at the end). Interpreter `s19env` (Windows). Env: `NO_COLOR` unset, `PYTHONUTF8=1`, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONIOENCODING=utf-8`, `PYTHONPATH=.`, isolated `LOCALAPPDATA`, own `--basetemp`; one pytest at a time, 900 s cap each. Each transcript's first line prints `s19_app.__file__` (it is the copy). After every mutant the file was restored byte-exact and `git diff --quiet` was clean (24/24 restore checks True). Source files mutated: `diff_report_service.py`, `before_after_service.py`, `app.py`, `flow_execution_service.py` (no other product file).

Mutant source: the "Negative control" column of `01-requirements.md`, the M1-M19 table of `02-test-cases.md`, `E3-rulings.md` (S-1, S-2, S-3, S-7), `E4-tester-notes.md` / `E4-integration-notes.md` section 8. M20-M23 are added from requirement negative controls that had no M-number (R-CMP-004.5, R-.21 one-file, R-.22, R-CMP-004.9.2 (a)).

## Score

**23 killed / (23 killed + 1 survived) = 95.8 %** (24 mutants; 0 N/A). Survivor: M22.

## Table

Transcripts are in `.dev-flow/2026-11-01-batch-101/evidence/inc-7/` (redacted: `<HOME>`, `<USER>`, `<COPY>`).

| Id | Requirement | Mutation | Test(s) run | Result | Transcript |
|---|---|---|---|---|---|
| M1 | R-CMP-004.14 | `_window_rows` back to `render_hex_view(..., max_rows=MAX_HEX_ROWS)` | 004.14/1, /3, /4 (diff service); /5 (before-after) | KILLED, 4/4 red (512-row cap) | mut-M1.txt |
| M2 | R-CMP-004.14 | `_window_rows` via `render_hex_view(..., max_rows=len(row_bases))` | 004.14/3, /4 | KILLED, 2/2 red (65536-byte cap) | mut-M2.txt |
| M3 | R-BEFORE-AFTER-REPORT-001.32/.33/.34 | title constant `Diff report` in both generators | 001_32_1, 001_33_1, 001_34_1 | KILLED, 3/3 red | mut-M3.txt |
| M4 | R-CMP-004.1 | title `Before/after report` for every report | `test_r_cmp_004_1_1_diff_report_keeps_its_title` | KILLED | mut-M4.txt |
| M5 | R-CMP-004.1 | title chosen by `linkage_entries is not None` | `test_r_cmp_004_1_2_title_follows_provenance_only` | KILLED | mut-M5.txt |
| M6 | R-BEFORE-AFTER-REPORT-001.35 | composer drops `a2l_data` from `compare_images` | 001_35_1 | KILLED | mut-M6.txt |
| M7 | R-CMP-003.2 | app forwards `loaded.mac_records` unconditionally | `test_r_cmp_003_2_1_bkey_no_mac_is_absent` | KILLED | mut-M7.txt |
| M8 | R-BEFORE-AFTER-REPORT-001.24 | composer drops `a2l_records` from the generator kwargs | 001_24_1, 001_24_3 | KILLED, 2/2 red | mut-M8.txt |
| M9 | R-CMP-004.9.1 | Runs Symbols cell written raw | 004_9_1_3; 001_24_1 | KILLED, 2/2 red | mut-M9.txt |
| M10 | R-CMP-004.15 / R-.21 | HTML sinks (from `_html_header` down) left on a C0-only strip | 004_15_1; 001_21_2; `test_tc_038_3_...md_and_html_pair` | KILLED, 3/3 red (rerun by node id; first run mixed `-k` and deselected two nodes, superseded) | mut-M10.txt |
| M11 | R-CMP-004.9.2 | `_image_line` path through `_md_text` | 004_9_2_4; `test_at_054b_...golden` | KILLED, 2/2 red (9_2_4 on the path text; 054b on the host-path guard of the golden canonicalizer, see note 2) | mut-M11.txt |
| M12 | R-CMP-004.9.1/9 | `flow_execution_service` keeps its pre-escape (`md_safe` / `md_code`) | `test_tc_b94_24_...`; `test_at_b94_18_...` | KILLED by `test_at_b94_18` only (double-escaped `[red]`); `test_tc_b94_24` stays green (note 3) | mut-M12.txt |
| M13 | R-CMP-004.8 | `_md_text` used for the image label in `_html_header` | 004_8_1 | KILLED | mut-M13.txt |
| M14 | R-CMP-004.9.1/5 | `flow_change_census_complete` compares through `_md_cell` while emission uses `_md_text` | 004_9_1_5; `test_tc717_...` | KILLED, 2/2 red | mut-M14.txt |
| M15 | R-CMP-004.9.1/10 | refusal message left on `_md_cell` | 004_9_1_10; 004_9_1_11 | KILLED, 2/2 red | mut-M15.txt |
| M16 | R-CMP-005.16 | `_write_report` writes the final name directly | 005_16_1, 005_16_2; 005_16_4 | KILLED, 3/3 red | mut-M16.txt |
| M17a | R-CMP-005.17/2 | composer keeps the Markdown file after an HTML failure/refusal | 005_17_2 | KILLED | mut-M17a.txt |
| M17b | R-CMP-005.17/1 | A-to-B worker `_drop_orphan_md` made a no-op | 005_17_1 | KILLED | mut-M17b.txt |
| M18 | R-BEFORE-AFTER-REPORT-001.11 | reason left at `(screen 7)` | 001_11_1, 001_11_2 | KILLED, 2/2 red | mut-M18.txt |
| M19 | R-CMP-004.14/7 | `_window_rows` writes `chr(b)` for every b >= 0x20 | 004_14_7 | KILLED | mut-M19.txt |
| M20 | R-CMP-004.5 | symbol membership by extent (an A2L tag's `length` expands to every covered address) | 004_5_1; `test_symbol_annotation_only_intersecting_run` | KILLED by 004_5_1; the second node stays green (note 4) | mut-M20.txt |
| M21 | R-BEFORE-AFTER-REPORT-001.21 | HTML linkage symbol written from the raw value (one file keeps the control char) | `test_tc_038_3_...md_and_html_pair` | KILLED | mut-M21.txt |
| M22 | R-BEFORE-AFTER-REPORT-001.22 | `_md_cell` stops escaping `\|` | `test_pipe_bearing_symbol_md_escaped_html_intact` | **SURVIVED** (1 passed) | mut-M22.txt |
| M23 | R-CMP-004.9.2 | `_md_path` returns the raw path (backtick not replaced) | 004_9_2_1, 004_9_2_2 | KILLED, 2/2 red | mut-M23.txt |

All kills were read from the transcripts: each failing node is an assertion on the mutated behaviour (no collection or import error; exit code 1 everywhere, none 2/4).

## Survivor

**M22 (`_md_cell` without the `|` escape): real gap, not equivalent.** The named test plants its hostile pipe in the linkage *Symbol* cell, which is written by `_md_text` (`md_safe`), not by `_md_cell`; so removing the pipe escape from `_md_cell` changes nothing it can see. A broader run (`mut-M22b.txt`: both whole test files, `test_diff_report_service.py` + `test_before_after_report.py`, 97 passed) also stays green, so no existing node pins it. Missing assertion: a pipe (or `\|` pair) in a field that still goes through `_md_cell` (linkage Type, Disposition, Linkage; flow disposition; refusal code; Applied (UTC)) must stay inside its table cell (row keeps its column count). Those fields are system vocabulary today, so the exposure is defense-in-depth, but the code comment and docstring claim the guarantee. Route: `software-dev` / tester to add one case (not done here: this unit only measures).

## Notes

1. M10 mutates every `_strip_ctl(` call from `_html_header` onward (HTML helpers) to a C0-only removal; the Markdown side stays on the shared visible-text path, matching the control's wording.
2. M11 on Windows: the golden test dies on the repo's host-path canonicalizer guard (a `C:\` path now appears doubled/escaped), not on a content diff. The kill is real but 9_2_4 is the precise oracle.
3. M12: `test_tc_b94_24_a2b_report_states_each_inputs_provenance` passes with the pre-escape restored, so it does not detect a double escape; `test_at_b94_18_hostile_names_render_literally` is the only node that does. The case row lists both as covering 9.1/9; only one is sensitive.
4. M20: `test_symbol_annotation_only_intersecting_run` also stays green under extent semantics (its tag does not straddle the run); only 004_5_1 pins address-versus-extent.
5. Limits: Windows only; A-6 (4 MiB timing) and the Linux battery are not part of this unit. The mutation of `app.py` M17b and M7 ran through the shipped key `b` / Report-control surfaces as the named tests do.

## E5 corrective re-run (2026-11-05, rulings C-2, C-3, C-5, C-1)

Run by the E5 corrective agent on the **LAN Linux host** (Python 3.11, `s19ci`), in a separate detached git worktree of the host's clone at the merge base `9f9f6af` with the `b101-inc7` working-tree diff applied (never the local worktree, never the host's main checkout, which another integration was using). Each mutant: one anchor replaced exactly once (`occurrences 1` in the transcript), the named tests run, the file restored from a byte copy and `cmp` clean (5/5). Env: `NO_COLOR` unset, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONPATH=.`; one pytest at a time. Transcripts (redacted): `evidence/inc-7/e5c-mut-*.txt`.

| Id | Requirement | Mutation | Test(s) run | Result | Transcript |
|---|---|---|---|---|---|
| M22 (re-run) | R-BEFORE-AFTER-REPORT-001.22 | `_md_cell` stops escaping `\|` | `test_r_before_after_report_001_22_2_pipe_in_vocabulary_cells_stays_escaped` (new, C-2); `test_pipe_bearing_symbol_md_escaped_html_intact` | **KILLED** by the new node (the linkage row reads `by\|tes`… raw); the old node stays green, as in run 1 | e5c-mut-M22.txt |
| M24 | R-BEFORE-AFTER-REPORT-001.35 (MAC half) | composer drops `mac_records` from `compare_images` | `test_r_before_after_report_001_35_1_…` ; `test_r_before_after_report_001_35_3_bkey_loaded_mac_is_used` (new) | **KILLED**, 2/2 red on the artifact line (`mac=absent` where `mac=used (1/1)` / `(1/2)` is expected), an output difference, not a `TypeError` | e5c-mut-M24.txt |
| M25 | R-BEFORE-AFTER-REPORT-001.24 (MAC name) | composer drops `mac_records` from the generator kwargs | `test_r_before_after_report_001_24_2_…`; `…_001_35_3_…` | **KILLED**, 2/2 red on the Symbols cell (`CAL\_A` alone) | e5c-mut-M25.txt |
| M26 | R-BEFORE-AFTER-REPORT-001.35 / .24 (key `b`) | the app never forwards the loaded MAC (`report_mac_records = None`) | `…_001_35_3_bkey_loaded_mac_is_used`; `test_r_cmp_003_2_1_bkey_no_mac_is_absent` | **KILLED** by `.35/3`; `003_2_1` stays green (correct: it is the no-MAC arm) | e5c-mut-M26.txt |
| M27 | R-CMP-005.16 (C-1) | `_write_report` back to the fixed `<name>.part` staging name | `test_r_cmp_005_16_3_stale_part_file_is_not_touched`; `test_r_cmp_005_16_5_planted_link_at_part_name_is_not_followed` | **KILLED**, 2/2 red (`FileExistsError` on Linux, where `O_EXCL` refuses the link; on Windows the same tree followed the link: `e5c-red-c1-windows.txt`) | e5c-mut-M27.txt |

**Score after the corrective pass: 28 killed / 28 = 100 %** (run 1: 23 of 24 with M22 survived; M22 re-run killed; M24–M27 new, all killed). The audit's owed proofs are closed: `.35/1` MAC half by M24 and `.24/2` by M25, each failing on an output difference.

## Close addendum (2026-11-05)

Two controls added by the E5 close for RA-1/RA-2, run on the LAN Linux host: **M28** fixes the staging name to `<name>.tmp.part` -> KILLED by `test_r_cmp_005_16_6_staging_name_is_random_per_write` (1 failed, 3 passed); **M29** unlinks every `*.part` on a failed write -> KILLED by `test_r_cmp_005_16_4_stale_part_file_survives_failed_write`. Transcripts: `evidence/inc-7/e5d-*.txt`. Score: 30/30 killed.
