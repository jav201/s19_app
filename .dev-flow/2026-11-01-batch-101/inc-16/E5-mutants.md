# Inc 16 — E5 mutant table (negative controls)

One unit: the mutant table of batch-101 Inc 16 (documentation hygiene). Every row is the
**negative control** of a requirement row of `01-requirements.md` (the 32 rows; R-DOC-DEV.2
carries two controls, so 33), plus the two controls of `E4-integration-notes.md` int-04 that a
row does not already name (M-2 "an option where the file goes" and M-4 `EXPECTED_SCANNED_TEST_FILES`,
the TC-607 bound). A mutant re-introduces the defect its row forbids into the docs — one at a
time — and the guard named by the row's cases goes RED with an assertion that names the defect.

**Baseline** (before any mutant): `tests/test_b101_doc_hygiene.py` + `tests/test_docs_canon.py`
GREEN — **46 passed, 0 failed**.

**Setup**: every run on the LAN Linux host, interpreter `s19ci` Python 3.11. A detached worktree at
`c2cba356` (base `c2cba35`) had the increment applied as one binary diff and staged; each mutant
ran in its own detached worktree with the same staged diff re-applied and `git add -A` (the guards
read the git index). One pytest at a time (no `-n`). Each transcript in
`evidence/inc-16/mut-NN.txt` prints the commit, the index tree and `s19_app.__file__`.

## Table

| Id | Row | Mutation | Guard node | Result | First assertion line |
|---|---|---|---|---|---|
| mut-01 | R-DOC-REF.1 | restore `s19_app/tui/hexview.py` at `PROJECT_RULES.md:135` | `test_r_doc_ref_1_1_named_paths_exist` | KILLED | `1 unmarked repository paths that do not exist:` |
| mut-02 | R-DOC-REF.2 | keep the `README.md:465` link to the deleted `docs/diagrams/architecture.md` | `test_r_doc_ref_2_1_relative_links_resolve` | KILLED | `1 broken links:` |
| mut-03 | R-DOC-REF.3 | restore `` `prototypes/cambios_10_12_2026` `` in the `project_gather_service.py` docstring | `test_r_doc_ref_3_2_no_prototypes_path` | KILLED | `1 paths in the removed design-probe folder:` |
| mut-04 | R-DOC-REF.4 | restore `` Both `/dev-flow` (Phase 0 input, Phase 6 close) and `/fast-dev-flow` `` at `docs/engineering-rules.md:11` | `test_r_doc_ref_4_1_retired_workflow_named_only_as_retired` | KILLED | `1 unmarked mentions of the retired workflow:` |
| mut-05 | R-DOC-REF.5 | add `s19tool firmware.s19 info` to `CLAUDE.md` | `test_at285_no_live_cdfx_or_s19tool_console_script_token` | KILLED | `live CDFX / s19tool-console-script tokens:` |
| mut-06 | R-DOC-REF.6 | restore `` `cdfx/` package `` in the architecture row of `docs/README.md` | `test_at285_no_live_cdfx_or_s19tool_console_script_token` | KILLED | `live CDFX / s19tool-console-script tokens:` |
| mut-07 | R-DOC-README.4 | keep the diagrams row with the file deleted | `test_r_doc_readme_4_2_linked_documents_exist` | KILLED | `README links to files the tree does not hold: ['docs/diagrams/architecture.md']` |
| mut-08 | R-DOC-DEV.1 | add `` - `s19tool` → `s19_app.cli:main` `` back | `test_r_doc_dev_1_1_claude_lists_declared_console_scripts` | KILLED | `CLAUDE.md lists ['s19tool', 's19tui'], pyproject declares ['s19tui']` |
| mut-09 | R-DOC-DEV.2 | write one example as `s19tool firmware.s19 verify` | `test_r_doc_dev_2_1_cli_examples_run_the_module` | KILLED | `CLI example lines that do not run the module as `<command> <file>` with a defined sub-command:` |
| mut-10 | R-DOC-DEV.2 | write one example as `python -m s19_app.cli firmware.s19 verify` | `test_r_doc_dev_2_1_cli_examples_run_the_module` | KILLED | `CLI example lines that do not run the module as `<command> <file>` with a defined sub-command:` |
| mut-11 | R-DOC-DEV.3 | delete `main` from the CI sentence | `test_r_doc_dev_3_1_ci_sentence_matches_the_workflow` | KILLED | `CI sentence must name both `main` and `main-tui`` |
| mut-12 | R-DOC-DEV.4 | restore `` `s19_app/tui/hexview.py` `` in `CLAUDE.md`'s docstring-baseline line | `test_r_doc_dev_4_1_no_tui_hexview_path` | KILLED | `still name tui/hexview.py: ['CLAUDE.md']` |
| mut-13 | R-DOC-DEV.5 | restore `~5k-line` | `test_r_doc_dev_5_1_claude_states_no_module_size` | KILLED | `module sizes in CLAUDE.md:` |
| mut-14 | R-DOC-DEV.6 | restore `` `s19_app/tui/workspace.py:508` `` | `test_r_doc_dev_6_1_claude_cites_no_line_numbers` | KILLED | `file:line citations in CLAUDE.md:` |
| mut-15 | R-DOC-DEV.7 | restore `Canonical history: memory project_devflow_control_lineage.md.` | `test_r_doc_dev_7_1_rules_cite_no_memory_file` | KILLED | `a personal memory file is still cited` |
| mut-16 | R-DOC-DEV.8 | delete the `markdown-it-py>=3` line | `test_r_doc_dev_8_1_requirements_txt_equals_runtime_dependencies` | KILLED | `requirements.txt ['rich>=13.0', 'textual>=8.2.8,<9'] != pyproject [...]` |
| mut-17 | R-DOC-DEV.9 | delete the `engineering-rules.md` link | `test_r_doc_dev_9_1_docs_index_links_every_entry` | KILLED | `docs/README.md does not link 1 of 12 entries: ['docs/engineering-rules.md']` |
| mut-18 | R-DOC-DEV.10 | restore `- **Tests:** 762 pass / 3 xfailed / 2 skipped` | `test_r_doc_dev_10_1_docs_index_states_no_project_state` | KILLED | `a test tally remains` |
| mut-19 | R-DOC-DEV.11 | delete `Check Editor` from §3 | `test_r_doc_dev_11_1_overview_names_every_window` | KILLED | `overview section 3 does not name: ['Check Editor']` |
| mut-20 | R-DOC-DEV.12 | restore "ten single-context screens" at `docs/overview.md:16` | `test_r_doc_dev_12_1_rail_counted_as_twelve` | KILLED | `rail line with another count, docs/overview.md:16: ...` |
| mut-21 | R-DOC-DEV.13 | restore "Roughly **2760 tests**" | `test_r_doc_dev_13_1_no_test_count` | KILLED | `test counts remain:` |
| mut-22 | R-DOC-DEV.14 | restore the base Operations bullet | `test_r_doc_dev_14_1_overview_names_placeholder_operations` | KILLED | `the overview still says the Operations modal executes the placeholder operations` |
| mut-23 | R-DOC-DEV.15 | delete the `case_08_release_demo` entry | `test_r_doc_dev_15_1_manifest_lists_every_case` | KILLED | `MANIFEST.md does not name 1 of 15 case folders: ['case_08_release_demo']` |
| mut-24 | R-DOC-ARCH.1 | delete the `tools` row | `test_r_doc_arch_1_1_module_table_covers_python_folders` | KILLED | `Python folders without a module prefix: ['tools']` |
| mut-25 | R-DOC-ARCH.2 | restore the `prototypes` row | `test_r_doc_arch_2_1_no_empty_module_prefix` | KILLED | `module prefixes that match no tracked file: ['prototypes']` |
| mut-26 | R-DOC-ARCH.3 | restore the batch-100 interface block | `test_r_doc_arch_3_1_no_amendment_note`, `test_r_doc_arch_3_2_no_batch_declaration_heading`, `test_r_doc_arch_3_3_no_batch_interface_amendment` | KILLED | `per-batch declarations remain:` (3_3; 3_1 and 3_2 stay green) |
| mut-27 | R-DOC-ARCH.4 | delete the `render/format.py` no-`s19_app.tui`-import fact | `test_r_doc_arch_4_1_submodules_declared` | KILLED | `s19_app/render/format.py: Must-not-import cell does not name s19_app.tui` |
| mut-28 | R-DOC-ARCH.5 | delete the `B100-I16` (`derived_from`) row | `test_r_doc_arch_5_1_one_interfaces_table` | KILLED | `1 contracts missing from the first column: ['B100-I16']` |
| mut-29 | R-DOC-ARCH.6 | restore "capped at ≤ 5 files" | `test_r_doc_arch_6_1_increment_cap_is_four_source_files` | KILLED | `section 9 does not state the 4-source-file cap` |
| mut-30 | R-DOC-ARCHIVE.1 | copy `PENDIENTES-batch96.md` back to the root | `test_r_doc_archive_1_1_notes_only_in_the_archive` | KILLED | `still tracked at the earlier path: ['PENDIENTES-batch96.md']` |
| mut-31 | R-DOC-ARCHIVE.2 | drop the batch-99 table from the archive | E5-T ARCHIVE.2/1 (git diff transcript) | KILLED | `E5 check ARCHIVE.2/1 RED - removed section-10/11 lines missing from the archive` |
| mut-32 | R-DOC-ARCHIVE.3 | restore `examples/case_00_public/s19_sample.txt` | `test_r_doc_archive_3_4_no_unused_example_txt` | KILLED | `assert ['examples/case_00_public/s19_sample.txt'] == []` |
| mut-33 | R-DOC-ARCHIVE.4 | restore the base text of `PENDIENTES-batch96.md:3` in the archived copy | `test_r_doc_archive_4_1_archive_holds_no_local_identity` | KILLED | `local identities in the archive folder:` |
| mut-34 | E4 int-04 M-2 | an option where the file goes (`python -m s19_app.cli dump --start ...`) | `test_r_doc_dev_2_1_cli_examples_run_the_module` | KILLED | `CLI example lines that do not run the module as `<command> <file>` with a defined sub-command:` |
| mut-35 | E4 int-04 M-4 | `EXPECTED_SCANNED_TEST_FILES = 262` | `test_tc607_scanned_corpus_matches_the_declared_bound` | KILLED | `the guard scanned 263 test modules, not the declared 262. ...` |

## Verdict

**35 of 35 killed** — every negative control re-introduced its defect and turned its guard RED with
an assertion naming the defect; no row was skipped silently. The row whose control the integrator
had already run (`E4-integration-notes.md` int-04) was re-run anyway. The two E4-only controls
(M-2, M-4) were also run. Transcripts: `evidence/inc-16/mut-01.txt` … `mut-35.txt`, each printing
the base commit and `s19_app.__file__` (paths redacted: `<HOME>/<USER>`, drive paths `<DRIVE>:`).
