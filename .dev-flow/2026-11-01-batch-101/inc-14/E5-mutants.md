# Inc 14 — E5 mutant table (DeepSeek)

Batch 2026-11-01-batch-101, increment 14. Mutations of the product texts only:
`s19_app/tui/window_help.py`, `s19_app/tui/legend.py`, `README.md`,
`SECURITY.md`, `CHANGELOG.md`, `docs/user-guide/*.md`. One mutation at a time:
apply → run the test node(s) the case rows of `02-test-cases.md` cite → restore
(byte-exact backup copy, sha256 before/after verified equal).

Runs on the LAN Linux host only (operator rule), conda env `s19ci`, Python
3.11.18, in a detached worktree at `origin/main` with the branch diff
(`git diff b7b77c4 0bbb2c6`) applied; every transcript prints `s19_app.__file__`
first (the worktree's own copy) and ends `PYTEST_RC=` plus `RESTORE_OK`.
`prototypes/cambios_10_12_2026/help_sections.md` was not touched. Nothing ran
on the Windows PC. No commit was made.

Mutant set = the "Negative control" column of every row of
`01-requirements.md`, plus the controls named in `E1-rulings.md`,
`E3-rulings.md`, `E5-rulings.md` and `E5-corrective-notes.md` (see §3).

## 1. Table

| id | requirement | mutation | tests | result | transcript |
|---|---|---|---|---|---|
| M01 | R-WHELP.12 (a) | restore base A2L step 1 (`section tree`) | `test_b101_help_legend_docs.py::test_r_whelp_12_3_no_stale_claim` | KILLED | `evidence/inc-14/mut-01.txt` |
| M02 | R-WHELP.12 (a) | add a step quoting `` `h` `` to the Checks section | `test_b101_help_legend_docs.py::test_r_whelp_12_1_quoted_keys_act_on_the_window` | KILLED | `evidence/inc-14/mut-02.txt` |
| M03 | R-WHELP.12 (a) | add ``,`` to a Checks step (bound, inert off Workspace) | `test_b101_help_legend_docs.py::test_r_whelp_12_1_quoted_keys_act_on_the_window` | KILLED | `evidence/inc-14/mut-03.txt` |
| M04 | R-WHELP.13 | restore base Workspace step 5 (`folders.html board`) | `test_b101_help_legend_docs.py::test_r_whelp_13_1_no_reference_to_unopenable_things` | KILLED | `evidence/inc-14/mut-04.txt` |
| M05 | R-WHELP.13 | restore ` (LLR-003.7)` in Flow Builder step 1 | `test_b101_help_legend_docs.py::test_r_whelp_13_1_no_reference_to_unopenable_things` | KILLED | `evidence/inc-14/mut-05.txt` |
| M06 | R-WHELP.14 | restore `**Pass / Fail / Uncheck**` in the Checks section | `test_b101_help_legend_docs.py::test_r_whelp_14_1_no_markdown_marks` | KILLED | `evidence/inc-14/mut-06.txt` |
| M07 | R-WHELP.7 (b) | store a step starting with a number | `test_window_usage_help.py::test_tc707_numbering_generated_sequential` | KILLED | `evidence/inc-14/mut-07.txt` |
| M08 | R-WHELP.7 (c) | drop one step (the last Checks step) | `test_window_usage_help.py::test_tc707_numbering_generated_sequential` | KILLED | `evidence/inc-14/mut-08.txt` |
| M09 | R-WHELP.18 | restore base step 6 (`*.md` + `*.html` pair) | `test_b101_help_legend_docs.py::test_r_whelp_18_1_reports_step_names_one_markdown_file` | KILLED | `evidence/inc-14/mut-09.txt` |
| M10 | R-WHELP.19 | restore base step 4 (`pre-fills from the loaded A2L`) | `test_b101_help_legend_docs.py::test_r_whelp_19_1_reports_step_names_saved_regions` | KILLED | `evidence/inc-14/mut-10.txt` |
| M11 | R-WHELP.20 | restore base step 2 (`find (/) to jump to a name`) | `test_b101_help_legend_docs.py::test_r_whelp_20_1_a2l_step_names_the_ascii_search` | KILLED | `evidence/inc-14/mut-11.txt` |
| M12 | R-WHELP.21 | restore base step 1 (`a project file, or browse to one`) | `test_b101_help_legend_docs.py::test_r_whelp_21_1_split_step_names_the_loaded_image` | KILLED | `evidence/inc-14/mut-12.txt` |
| M13 | R-WHELP.22 | restore base step 6 (`the naming pattern. The sample filename updates live`) | `test_b101_help_legend_docs.py::test_r_whelp_22_1_split_step_names_the_file_names` | KILLED | `evidence/inc-14/mut-13.txt` |
| M14 | R-WHELP.23 | restore base step 2 (`Grouped view clusters failures by reason`) | `test_b101_help_legend_docs.py::test_r_whelp_23_1_checks_step_names_outcome_groups` | KILLED | `evidence/inc-14/mut-14.txt` |
| M15 | R-WHELP.24 | restore base step 3 (`over the image's real ranges`) | `test_b101_help_legend_docs.py::test_r_whelp_24_1_crc_step_names_typed_ranges` | KILLED | `evidence/inc-14/mut-15.txt` |
| M16 | R-WHELP.25 | restore base step 12 (`the CRC configuration a CRC block stamps`) | `test_b101_help_legend_docs.py::test_r_whelp_25_1_crc_template_line_names_a_crc_config` | KILLED | `evidence/inc-14/mut-16.txt` |
| M17 | R-WHELP.26 | delete the clause (`a template the CRC Designer saves is not a CRC config and is refused`) | `test_b101_help_legend_docs.py::test_r_whelp_26_1_flow_help_says_designer_template_refused` | KILLED | `evidence/inc-14/mut-17.txt` |
| M18 | R-TUI-062.10.1 | restore the base key line | `test_b101_help_legend_docs.py::test_r_tui_062_10_1_1_map_key_line_text` | KILLED | `evidence/inc-14/mut-18.txt` |
| M19 | R-TUI-062.10.1 | make Enter post `chain=2` (open hex) with the new line kept | — | N/A (behaviour mutant in `screens_directionb.py`, outside the product-text slice) | — |
| M20 | R-LEGEND-011 | restore `↵ opens hex` in the region-row field line | `test_b101_help_legend_docs.py::test_r_legend_011_1_region_row_field_line` | KILLED | `evidence/inc-14/mut-20.txt` |
| M21 | R-DOC-README.2 | delete the `### Check Editor` section | `test_b101_help_legend_docs.py::test_r_doc_readme_2_1_one_section_per_window` | KILLED | `evidence/inc-14/mut-21.txt` |
| M22 | R-DOC-README.3 | delete the `` `c` `` row | `test_b101_help_legend_docs.py::test_r_doc_readme_3_1_every_ctx_key_listed` | KILLED | `evidence/inc-14/mut-22.txt` |
| M23 | R-DOC-README.3 | add a row for an unbound key `` `h` `` | `test_docs_canon.py::test_at285_every_readme_named_key_exists_in_the_seat` | KILLED | `evidence/inc-14/mut-23.txt` |
| M24 | R-DOC-README.3 | `ENABLE_COMMAND_PALETTE=False` (monkeypatch) with the README `Ctrl+P` row kept | — | N/A (code-side control; exercised as the in-test negative control inside `test_at285`, not a product-text mutation) | — |
| M25 | R-DOC-README.4 | restore "ten single-context screens" | `test_b101_help_legend_docs.py::test_r_doc_readme_4_1_no_stale_claim` | KILLED | `evidence/inc-14/mut-25.txt` |
| M26 | R-DOC-README.4 | restore the `project.toml` bullet | `test_b101_help_legend_docs.py::test_r_doc_readme_4_1_no_stale_claim` | KILLED | `evidence/inc-14/mut-26.txt` |
| M27 | R-DOC-SECURITY.1 | delete `SECURITY.md` | `test_b101_help_legend_docs.py::test_r_doc_security_1_1_policy_names_private_path` | KILLED | `evidence/inc-14/mut-27.txt` |
| M28 | R-DOC-SECURITY.2 | delete the supported-versions table | `test_b101_help_legend_docs.py::test_r_doc_security_2_1_supported_versions` | KILLED | `evidence/inc-14/mut-28.txt` |
| M29 | R-DOC-RELNOTE.1 | write `0x18026B2A` as the 1.0.0 value | `test_b101_help_legend_docs.py::test_r_doc_relnote_1_1_crc_change_stated` | KILLED | `evidence/inc-14/mut-29.txt` |
| M30 | R-DOC-RELNOTE.2 | write the init unreversed in the remedy | `test_b101_help_legend_docs.py::test_r_doc_relnote_2_1_remedy_stated` | KILLED | `evidence/inc-14/mut-30.txt` |
| M31 | R-DOC-RELNOTE.3 | write `Diff report` as the before/after title | `test_b101_help_legend_docs.py::test_r_doc_relnote_3_1_before_after_report_stated` | KILLED | `evidence/inc-14/mut-31.txt` |
| M32 | R-DOC-RELNOTE.4 | write "the first copy" | `test_b101_help_legend_docs.py::test_r_doc_relnote_4_1_external_copy_stated` | KILLED | `evidence/inc-14/mut-32.txt` |
| M33 | R-DOC-RELNOTE.5 | delete the search consequence | `test_b101_help_legend_docs.py::test_r_doc_relnote_5_1_markdown_escaping_stated` | KILLED | `evidence/inc-14/mut-33.txt` |
| M34 | R-DOC-RELNOTE.5 | write "names and paths carry a backslash" | `test_b101_help_legend_docs.py::test_r_doc_relnote_5_1_markdown_escaping_stated` | KILLED | `evidence/inc-14/mut-34.txt` |
| M35 | R-DOC-RELNOTE.6 | write "limited to 512 rows" as the 1.0.0 behaviour | `test_b101_help_legend_docs.py::test_r_doc_relnote_6_1_whole_hex_windows_stated` | KILLED | `evidence/inc-14/mut-35.txt` |
| M36 | R-DOC-RELNOTE.6 | write "earlier versions cut each window at 512 rows" | `test_b101_help_legend_docs.py::test_r_doc_relnote_6_1_whole_hex_windows_stated` | KILLED | `evidence/inc-14/mut-36.txt` |
| M37 | R-DOC-RELNOTE.7 | write "the folder is created again" | `test_b101_help_legend_docs.py::test_r_doc_relnote_7_1_deleted_project_folder_stated` | KILLED | `evidence/inc-14/mut-37.txt` |
| M38 | R-DOC-RELNOTE.8 | delete the remedy | `test_b101_help_legend_docs.py::test_r_doc_relnote_8_1_climbing_path_refusal_stated` | KILLED | `evidence/inc-14/mut-38.txt` |
| M39 | R-DOC-RELNOTE.9 | write "against the working directory" as the 1.0.0 behaviour | `test_b101_help_legend_docs.py::test_r_doc_relnote_9_1_relative_output_under_project_stated` | KILLED | `evidence/inc-14/mut-39.txt` |
| M40 | R-DOC-RELNOTE.10 | write "the reports keep the typed ref" | `test_b101_help_legend_docs.py::test_r_doc_relnote_10_1_reports_name_the_copy_stated` | KILLED | `evidence/inc-14/mut-40.txt` |
| M41 | R-DOC-RELNOTE.11 | write the earlier reason `'reverse'` as the 1.0.0 text | `test_b101_help_legend_docs.py::test_r_doc_relnote_11_1_crc_config_reasons_stated` | KILLED | `evidence/inc-14/mut-41.txt` |
| M42 | R-DOC-RELNOTE.12 | delete the Markdown-file consequence | `test_b101_help_legend_docs.py::test_r_doc_relnote_12_1_failed_write_leaves_nothing_stated` | KILLED | `evidence/inc-14/mut-42.txt` |
| M43 | R-DOC-RELNOTE.13 | write "control characters are removed" | `test_b101_help_legend_docs.py::test_r_doc_relnote_13_1_visible_replacements_stated` | KILLED | `evidence/inc-14/mut-43.txt` |
| M44 | R-DOC-RELNOTE.14 | delete "safe to delete" | `test_b101_help_legend_docs.py::test_r_doc_relnote_14_1_part_file_safe_to_delete_stated` | KILLED | `evidence/inc-14/mut-44.txt` |
| M45 | R-DOC-GUIDE.1 | restore `CRC config is structurally invalid: 'reverse'` in ch17.5 | `test_b101_help_legend_docs.py::test_r_doc_guide_1_passages_describe_1_0_0[passage-4]` | KILLED | `evidence/inc-14/mut-45.txt` |
| M46 | R-DOC-GUIDE.2 | mark F-43 (a limitation, deferred) | `test_b101_help_legend_docs.py::test_r_doc_guide_2_2_no_other_row_marked` | KILLED | `evidence/inc-14/mut-46.txt` |
| M47 | R-DOC-GUIDE.2 | mark F-45 without a supersession of the pinned set | `test_b101_help_legend_docs.py::test_r_doc_guide_2_2_no_other_row_marked` | KILLED | `evidence/inc-14/mut-47.txt` |

## 2. Score

- **KILLED 45 / 45 runnable product-text mutants** — every mutation the
  negative-control column names is caught by the test(s) its case row cites.
- **SURVIVED 0.** No equivalent mutant: there is no missing assertion, and no
  real gap to name.
- **N/A 2** (M19, M24): controls that are not product-text mutations — M19 is a
  behaviour change in `screens_directionb.py`, M24 is a code-side flag already
  exercised by the in-test negative control of `test_at285`. Neither can be
  expressed as an edit to the six product-text files.

## 3. Controls named in the ruling files

- **E5 C-1** ("prove with a mutant that moves a control to another window"): the
  two mutants named there — `app.py:3659` Checks `Hex Peek` → `Peek`, and
  `app.py:8064` A2L Explorer `Goto` → `Go` — were already proven RED at E5 and
  recorded in `evidence/inc-14/e5c-c1-mutants-red-then-green.txt`
  (`E5-corrective-notes.md` §3). They are source-code mutants, not product-text
  mutants, so they are N/A for this table (already proven).
- **In-test negative controls** (E5-corrective-notes §2 and E5-rulings C-6/C-7:
  `Filter tags` not in Checks, `Goto`/`Save`/`Run checks` not found in a longer
  label, `workarea\splits\` where `workarea\patches\` belongs, the README
  Operations name swap, the RELNOTE.1 paraphrase, the GUIDE.1/9 bullet move, the
  SECURITY fallback/address hits, the C-7 dropped-step body): these are
  assertions inside the tests themselves (the detector is run against a broken
  copy in-test), not mutations of the product text, so they are N/A here; they
  ran as part of every `int-07` pass and are covered by the M06/M17/M27 rows
  where a matching product-text mutation exists.
- **E1-rulings / E3-rulings**: no product-text negative control beyond the
  table's "Negative control" column (E3 A-5's palette control is M24, above).
