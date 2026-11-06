# Inc 11 — E5 mutation check (A2L validation and parsing)

Stage E5 of the design-first flow (batch-101 Inc 11). Operator rule: every run on
the LAN Linux host 2 (Python 3.11.18, Textual 8.2.8, pytest-xdist), own detached
worktree `<HOME>/work/s19_m11` at `origin/main` with the branch diff
(`b7b77c4..688ca2b`) applied uncommitted. Nothing ran on the operator's Windows
PC. Interpreter `~/miniconda3/envs/s19ci/bin/python`; `s19_app.__file__` resolved
to `<HOME>/work/s19_m11/s19_app/__init__.py` in every run.

## Method

- **Mutant table** = the *Negative control* column of every active row of
  `01-requirements.md` (28 rows; R-A2L-036.2, .4, .9, .13 each name two controls),
  plus the controls named in `E1-rulings.md`, `E3-rulings.md` and
  `E4-integration-notes.md` (all of them already folded into the same column, no
  additional ones). Total 32 mutants.
- **Mutated files only** `s19_app/validation/rules.py`, `s19_app/tui/issues_view.py`,
  `s19_app/tui/a2l.py`, `s19_app/tui/app.py` (the four Inc-11 source files).
- **Per mutant**: apply the edit in `<HOME>/work/s19_m11` (one at a time), run the
  test nodes the case rows of `02-test-cases.md` cite for that row, then restore and
  verify the sha256 of the four files equals the branch baseline recorded before the
  mutant (the four `d3fd8691…`/`e99d9e15…`/`f543a58e…`/`c3197405…` hashes below).
  `git diff --quiet` against the base is intentionally not used (the worktree HEAD is
  `origin/main`; the branch diff is applied, not committed).
- **Result**: KILLED = a cited test went RED for the mutant's reason; SURVIVED = all
  cited tests stayed GREEN. Transcripts are redacted (home/account/host/IP replaced
  with `<HOME>`/`<USER>`/`LAN Linux host 2`/`<IP>`).

Branch baseline sha256 (before every mutant, verified after every restore):

| file | sha256 |
|---|---|
| `s19_app/validation/rules.py` | `d3fd869193b6a207040d67c75cdc3d03b88115a9938715732131759640081130` |
| `s19_app/tui/issues_view.py` | `f543a58ecc7274d03adf3dd95a6c670187242ad6225ebbcf5206236012c1dd3a` |
| `s19_app/tui/a2l.py` | `e99d9e15da3f31160046889300ac41f0741ca917166ecea18da6f27c0d9f89a8` |
| `s19_app/tui/app.py` | `c3197405780f9d871045c8ba3e6684681d6eb95eaa912b2e995a664d208d9fe3` |

## Table

| id | requirement | mutation | tests | result | transcript |
|---|---|---|---|---|---|
| R-VAL-032.1 | unknown non-ASAM block outside IF_DATA → one WARNING `A2L_UNRECOGNIZED_BLOCK`, exact message + line | skip the check for every nested section (a "top level only" walker) | `test_b101_a2l_blocks_and_segments.py::test_r_val_032_1_unknown_block_warns_nested`, `::test_r_val_032_1_unknown_block_warns` | KILLED | `evidence/inc-11/mut-032-1.txt` |
| R-VAL-032.2 | an ASAM block name raises no issue | drop `AXIS_DESCR` from the recognized names | `test_b101_a2l_blocks_and_segments.py::test_r_val_032_2_asam_block_names_raise_nothing`, `tests/test_synth_release_case.py::test_a2l_zero_issues` | KILLED | `evidence/inc-11/mut-032-2.txt` |
| R-VAL-032.3 | a section inside IF_DATA raises no issue | treat only direct children of IF_DATA as inside | `test_b101_a2l_blocks_and_segments.py::test_r_val_032_3_inside_if_data_raises_nothing`, `::test_r_val_032_3_software_a_raises_no_unrecognized_block`, `::test_r_val_032_3_v171_one_line_if_data` | KILLED | `evidence/inc-11/mut-032-3.txt` |
| R-TUI-042b.1 | group issues by severity ERROR → WARNING → INFO | re-introduce a presentation remap of `A2L_UNRECOGNIZED_BLOCK` to INFO | `test_b101_issues_severity_view.py::test_r_tui_042b_1_unrecognized_block_rows_stay_warnings`, `::test_r_tui_042b_1_groups_ordered_whatever_the_list_order` | KILLED | `evidence/inc-11/mut-042b-1.txt` |
| R-TUI-042b.2 | group header counts its severity over the whole filtered list | re-introduce the count triage (WARNING → INFO) | `test_b101_issues_severity_view.py::test_r_tui_042b_2_headers_count_issue_severity` | KILLED | `evidence/inc-11/mut-042b-2.txt` |
| R-TUI-042b.4 | issue row painted in its severity colour | as R-TUI-042b.1 (remap → row is `sev-info`) | `test_b101_issues_severity_view.py::test_r_tui_042b_4_unrecognized_block_rows_paint_warning` | KILLED | `evidence/inc-11/mut-042b-4.txt` |
| R-TUI-042b.6 | no text between a group header and its first row | restore the justification note after the header | `test_b101_issues_severity_view.py::test_r_tui_042b_6_no_note_under_group_header` | KILLED | `evidence/inc-11/mut-042b-6.txt` |
| R-TUI-025.2 | severity strip counts the whole issue list | re-introduce the count triage (Warnings 1, Info 3) | `test_b101_issues_severity_view.py::test_r_tui_025_2_strip_and_summary_count_issue_severity` | KILLED | `evidence/inc-11/mut-025-2.txt` |
| R-TUI-025.6 | Warnings filter shows only WARNING issues | as R-TUI-042b.1 (remap → Warnings view shows an INFO header) | `test_b101_issues_severity_view.py::test_r_tui_025_6_warnings_filter_shows_warning_group_only` | KILLED | `evidence/inc-11/mut-025-6.txt` |
| R-TUI-042b.5 | filtered list ordered by severity rank across pages | page the unsorted list (base line) | `test_b101_issues_severity_view.py::test_r_tui_042b_5_list_ordered_by_severity_across_pages`, `::test_r_tui_042b_5_order_is_stable_within_severity` | KILLED | `evidence/inc-11/mut-042b-5.txt` |
| R-A2L-036.1 | first record word is the segment's name | take the first word of the `/begin` line only (base) | `test_b101_a2l_blocks_and_segments.py::test_r_a2l_036_name_first_record_line_software_a`, `::test_r_a2l_036_all_on_begin_line` | KILLED | `evidence/inc-11/mut-036-1.txt` |
| R-A2L-036.2 | address word (Number ≥ 0) + next Number > 0 → base | read a Number with `int(w, 0)` (so `0400` is not a Number) | `test_b101_a2l_blocks_and_segments.py::test_r_a2l_036_2_leading_zero_decimal` | KILLED | `evidence/inc-11/mut-036-2a.txt` |
| R-A2L-036.2 | (same row) | take the fourth word of the first line of 5+ words (base, positional) | `test_b101_a2l_blocks_and_segments.py::test_r_a2l_036_name_first_record_line_software_a`, `::test_r_a2l_036_release_demo_segments` | KILLED | `evidence/inc-11/mut-036-2b.txt` |
| R-A2L-036.3 | word after the address word is the size | take the word after the size (the offset) | `tests/test_a2l_enriched.py::test_tc682_quoted_demo_a2l_segments_parse_to_full_rows`, `test_b101_a2l_blocks_and_segments.py::test_r_a2l_036_release_demo_segments` | KILLED | `evidence/inc-11/mut-036-3.txt` |
| R-A2L-036.4 | broken record → no base and no size | scan on for the next two adjacent Numbers (the E1 rule) | `test_b101_a2l_blocks_and_segments.py::test_r_a2l_036_4_no_base` | KILLED | `evidence/inc-11/mut-036-4a.txt` |
| R-A2L-036.4 | (same row) | accept a single Number as the base | `test_b101_a2l_blocks_and_segments.py::test_r_a2l_036_4_no_base` | KILLED | `evidence/inc-11/mut-036-4b.txt` |
| R-A2L-036.6 | word after the size is the offset | take the offset from the sixth word of the line (base) | `test_b101_a2l_blocks_and_segments.py::test_r_a2l_036_name_first_record_line_software_a`, `tests/test_a2l_enriched.py::test_tc682_quoted_names_and_the_offset_field` | KILLED | `evidence/inc-11/mut-036-6.txt` |
| R-A2L-036.7 | no record words → no name | fall back to the text `UNKNOWN` (base) | `test_b101_a2l_blocks_and_segments.py::test_r_a2l_036_7_empty_segment_has_no_name` | KILLED | `evidence/inc-11/mut-036-7.txt` |
| R-A2L-036.8 | last program-type word before the base | take the first program-type word after the name | `test_b101_a2l_blocks_and_segments.py::test_r_a2l_036_8_last_program_type_word_wins` | KILLED | `evidence/inc-11/mut-036-8.txt` |
| R-A2L-036.9 | last memory-type word before the base | take the first memory-type word after the name | `test_b101_a2l_blocks_and_segments.py::test_r_a2l_036_9_last_memory_type_word_wins` | KILLED | `evidence/inc-11/mut-036-9a.txt` |
| R-A2L-036.9 | (same row) | take the word two before the base (positional) | `test_b101_a2l_blocks_and_segments.py::test_r_a2l_036_release_demo_segments`, `::test_r_a2l_036_9_last_memory_type_word_wins` | KILLED | `evidence/inc-11/mut-036-9b.txt` |
| R-A2L-036.10 | no program-type word → no program type | take the first word after the name as the program type | `test_b101_a2l_blocks_and_segments.py::test_r_a2l_036_10_no_program_type_case_07` | KILLED | `evidence/inc-11/mut-036-10.txt` |
| R-A2L-036.11 | no memory-type word → no memory type | as R-A2L-036.10 → memory type `INTERN` | `test_b101_a2l_blocks_and_segments.py::test_r_a2l_036_11_no_memory_type` | KILLED | `evidence/inc-11/mut-036-11.txt` |
| R-A2L-036.12 | no base → no program type and no memory type | keep the words found anyway (`DATA` / `FLASH`) | `test_b101_a2l_blocks_and_segments.py::test_r_a2l_036_12_no_base_no_types` | KILLED | `evidence/inc-11/mut-036-12.txt` |
| R-A2L-036.13 | base + size > 2^32 → no base and no size | drop the bound | `test_b101_a2l_blocks_and_segments.py::test_r_a2l_036_13_end_above_4_gib` | KILLED | `evidence/inc-11/mut-036-13a.txt` |
| R-A2L-036.13 | (same row) | compare with "at least 2^32" (reject sum == 2^32) | `test_b101_a2l_blocks_and_segments.py::test_r_a2l_036_13_end_above_4_gib` | KILLED | `evidence/inc-11/mut-036-13b.txt` |
| R-A2L-034 | tag memory region from the holding segment | the base segment reader (462 `unknown`) | `test_b101_a2l_blocks_and_segments.py::test_r_a2l_034_release_demo_tags_are_flash`, `::test_r_a2l_034_case_07_regions` | KILLED | `evidence/inc-11/mut-034.txt` |
| R-SEG-SRC.6 | a2l source lists one row per usable segment | the base segment reader (`a2l(0)`) | `test_b101_issues_severity_view.py::test_r_seg_src_6_software_a_rows` | KILLED | `evidence/inc-11/mut-seg-src-6.txt` |
| R-A2L-120 | no-axis point x = its index from 0 | count from 1 | `tests/test_a2l_curve_description.py::test_tc1820_curve_description_no_axis_pts_linear` | KILLED | `evidence/inc-11/mut-120.txt` |
| R-A2L-121 | index note once, above the table header | emit the line per point | `test_b101_a2l_blocks_and_segments.py::test_r_a2l_121_index_note_once_above_header`, `::test_r_a2l_121_no_line_without_points` | KILLED | `evidence/inc-11/mut-121.txt` |
| R-A2L-122 | point rows carry no note | keep the per-row suffix (base) | `test_b101_a2l_blocks_and_segments.py::test_r_a2l_122_rows_carry_no_note` | KILLED | `evidence/inc-11/mut-122.txt` |
| R-A2L-123 | mixed case keeps the per-row suffix | emit R-A2L-121's line for any missing axis value | `test_b101_a2l_blocks_and_segments.py::test_r_a2l_123_mixed_points_keep_row_note` | KILLED | `evidence/inc-11/mut-123.txt` |

## Score

**32 / 32 KILLED — 0 SURVIVED.** Mutation score 32/32.

Every negative control was detected by the case-row test(s) it targets: the RED
assertion in each transcript fails for the mutant's own reason (e.g. `mut-036-4a`
shows `S1b` gaining base −1 under the E1 adjacent-pair scan; `mut-120` shows x
values 1,2,3 instead of 0,1,2; `mut-seg-src-6` shows `a2l(0)` instead of
`a2l(3)`; `mut-042b-1` shows the `PAGE` row remapped under INFO). No survivor
line is needed: there are no equivalent mutants and no real gaps — each row's
negative control has a dedicated, non-vacuous assertion that turns RED for it.

## Clean-up

The remote worktree `<HOME>/work/s19_m11` was removed after the last run
(`git worktree remove --force`); `<HOME>/work/s19_app` and the other agents'
worktrees (including `<HOME>/work/s19_i13`) were not touched. Helper scripts
(`m11_mutate.py` on the remote `/tmp`, `m11_*` local scratch) are outside the
repository.
