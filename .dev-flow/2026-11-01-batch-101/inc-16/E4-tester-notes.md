# Inc 16 — E4 tester notes

Independent E4 tester, increment 16 (documentation hygiene), batch `2026-11-01-batch-101`. Base revision `c2cba35` (the LAN Linux host 2 worktree was `git worktree add --detach … m4fix-main`, HEAD `c2cba356f254cf85ba8c0e05b47b5103baf2d733`). Written from `01-requirements.md`, `02-test-cases.md`, `E1-slice.md` §3, `E1-rulings.md` (with the E4 addenda), `E3-rulings.md` and the round-2 notes N-1 … N-3 of `E3-architect.md`; not from the implementers' output (their worktree was read only for a smoke run, §5).

Evidence state: `executed` (RED on base, one complete run). Nothing here is `approved`.

## 1. Files

| File | Change |
|---|---|
| `tests/test_b101_doc_hygiene.py` | new; 44 tests, text and `git ls-files` only, no import of `s19_app`; guard probes built from parts |
| `tests/test_docs_canon.py::test_at285_no_live_cdfx_or_s19tool_console_script_token` | same node name; scope from 3 files to every repository document; `_HISTORIC` gains `retired`, `moved`; `_S19TOOL_OK` gains `.s19tool\`, `s19tool.egg-info`, `pip <verb> s19tool`; instrument block of 9 lines |

Evidence: `.dev-flow/2026-11-01-batch-101/evidence/inc-16/red-01-tester-base.txt` (one run: the RED capture, the base counts, the derived-tree run, the oracle controls). Remote helper scripts (`i16t-measure.py`, `i16t-synth.py`, `i16t-mutants.py`, `i16t-archive-probe.py`, `i16t-red.sh`) lived in the remote worktree and were removed with it; their output is in the transcript.

## 2. Case → test → result on base

RED = fails on `c2cba35` for the reason the row names. PASS = passes on base (reason in §3).

| Case | Test (all in `tests/test_b101_doc_hygiene.py` unless noted) | On base |
|---|---|---|
| R-DOC-REF.1/1 | `test_r_doc_ref_1_1_named_paths_exist` | RED (22 tokens + 11 inside the retired folder, §4 F-1) |
| R-DOC-REF.1/2 | `test_r_doc_ref_1_2_path_scan_reports_a_missing_path` | PASS (instrument) |
| R-DOC-REF.2/1 | `test_r_doc_ref_2_1_relative_links_resolve` | RED only through the retired folder (5 broken links inside it); PASS on the derived tree: standing property, base 0 of 249 as the row says |
| R-DOC-REF.2/2 | `test_r_doc_ref_2_2_no_link_to_the_diagrams_file` | RED (5 links) |
| R-DOC-REF.3/1 | `test_r_doc_ref_3_1_no_fast_dev_flow_path` | RED (4 test comments + the folder's own text) |
| R-DOC-REF.3/2 | `test_r_doc_ref_3_2_no_prototypes_path` | RED (the 11 lines of the row + 1 in the retired folder) |
| R-DOC-REF.3/3 | `test_r_doc_ref_3_3_exemptions_are_by_file_and_text` | PASS (instrument; the 3 exempt lines exist on base) |
| R-DOC-REF.4/1 | `test_r_doc_ref_4_1_retired_workflow_named_only_as_retired` | RED (the 10 lines + the folder's own text) |
| R-DOC-REF.4/2 | `test_r_doc_ref_4_2_exempt_lines_skipped` | PASS (instrument) |
| R-DOC-REF.5/1, 5/2, 6/1 | `tests/test_docs_canon.py::test_at285_no_live_cdfx_or_s19tool_console_script_token` (5/2 = its instrument block) | RED (7 `s19tool` lines, 27 CDFX lines) |
| R-DOC-README.4/4 | `test_r_doc_ref_2_2_no_link_to_the_diagrams_file` (full); Inc 14's `test_r_doc_readme_4_2_linked_documents_exist` not run by me (partial) | RED |
| R-DOC-DEV.1/1 | `test_r_doc_dev_1_1_claude_lists_declared_console_scripts` | RED (`s19tool` listed) |
| R-DOC-DEV.2/1 | `test_r_doc_dev_2_1_cli_examples_run_the_module` | RED (4 examples start `s19tool`) |
| R-DOC-DEV.3/1 | `test_r_doc_dev_3_1_ci_sentence_matches_the_workflow` | RED (sentence names only `main-tui`) |
| R-DOC-DEV.4/1 | `test_r_doc_dev_4_1_no_tui_hexview_path` | RED (CLAUDE.md, PROJECT_RULES.md) |
| R-DOC-DEV.4/2 | `test_r_doc_dev_4_2_hex_renderer_named_at_render` | RED (0/3) |
| R-DOC-DEV.5/1 | `test_r_doc_dev_5_1_claude_states_no_module_size` | RED (`:56`, `:68`) |
| R-DOC-DEV.6/1 | `test_r_doc_dev_6_1_claude_cites_no_line_numbers` | RED (2 citations on `:12`) |
| R-DOC-DEV.7/1 | `test_r_doc_dev_7_1_rules_cite_no_memory_file` | RED |
| R-DOC-DEV.8/1 | `test_r_doc_dev_8_1_requirements_txt_equals_runtime_dependencies` | RED (1/3) |
| R-DOC-DEV.9/1 | `test_r_doc_dev_9_1_docs_index_links_every_entry` | RED (7 of 14 entries unlinked; 14 because the tree still holds `docs/diagrams` and `docs/crc-algorithm-designer`) |
| R-DOC-DEV.9/2 | `test_r_doc_dev_9_2_index_rule_follows_the_tree` | PASS (instrument) |
| R-DOC-DEV.10/1 | `test_r_doc_dev_10_1_docs_index_states_no_project_state` | RED |
| R-DOC-DEV.11/1 | `test_r_doc_dev_11_1_overview_names_every_window` | RED (9/13) |
| R-DOC-DEV.12/1 | `test_r_doc_dev_12_1_rail_counted_as_twelve` | RED (K 1/2 and the count lines; all problems listed in one message) |
| R-DOC-DEV.12/2 | `test_r_doc_dev_12_2_predicates_on_fixed_lines` | PASS (instrument) |
| R-DOC-DEV.13/1 | `test_r_doc_dev_13_1_no_test_count` | RED (2 lines) |
| R-DOC-DEV.14/1 | `test_r_doc_dev_14_1_overview_names_placeholder_operations` | RED |
| R-DOC-DEV.15/1 | `test_r_doc_dev_15_1_manifest_lists_every_case` | RED (7/15 named; 8 missing is the 15 − 7 of the row) |
| R-DOC-ARCH.1/1 | `test_r_doc_arch_1_1_module_table_covers_python_folders` | PASS (standing, the row says base 5/5) |
| R-DOC-ARCH.1/2 | not mine (E5-T) | — |
| R-DOC-ARCH.2/1 | `test_r_doc_arch_2_1_no_empty_module_prefix` | RED (`prototypes`) |
| R-DOC-ARCH.3/1, 3/2, 3/3 | `test_r_doc_arch_3_1_no_amendment_note`, `…_3_2_no_batch_declaration_heading`, `…_3_3_no_batch_interface_amendment` | RED (4 notes; 7 headings; 5 paragraphs + `none frozen yet` + 2 `(planned`; all equal the row's base counts) |
| R-DOC-ARCH.4/1 | `test_r_doc_arch_4_1_submodules_declared` | RED (0 sub-module tables) |
| R-DOC-ARCH.4/2 | `test_r_doc_arch_4_2_no_broken_import_rule_restated` | RED (`never called directly`) |
| R-DOC-ARCH.5/1, 5/2 | `test_r_doc_arch_5_1_one_interfaces_table`, `…_5_2_rail_saved_files_and_frozen_cells` | RED (6 tables in §11) |
| R-DOC-ARCH.6/1 | `test_r_doc_arch_6_1_increment_cap_is_four_source_files` | RED |
| R-DOC-ARCHIVE.1/1 | `test_r_doc_archive_1_1_notes_only_in_the_archive` | RED |
| R-DOC-ARCHIVE.1/2, 2/1, 2/2 | not mine (E5-T) | — |
| R-DOC-ARCHIVE.3/1 … 3/4 | `test_r_doc_archive_3_1_no_fast_dev_flow_folder`, `…_3_2_no_diagrams_file`, `…_3_3_no_req_crc_in_package`, `…_3_4_no_unused_example_txt` | RED (33; 1; 1; 2) |
| R-DOC-ARCHIVE.4/1 | `test_r_doc_archive_4_1_archive_holds_no_local_identity` | RED by emptiness (§4 F-4) |
| R-DOC-ARCHIVE.4/2 | `test_r_doc_archive_4_2_scan_reports_a_local_path` | PASS (instrument) |

Counts: 44 tests in the new file + the widened node = 45 run; 38 RED, 7 PASS on base. 48 of the 52 cases are covered by a test on disk (ARCH.1/2, ARCHIVE.1/2, 2/1, 2/2 stay E5 transcripts; README.4/4's G14 half was not part of my run).

## 3. Why the 7 pass on base

Five test the guard's own instrument on synthetic input (REF.1/2, REF.3/3, REF.4/2, DEV.9/2, ARCHIVE.4/2) and DEV.12/2 tests two fixed predicates. They cannot be RED on base by construction, so each was given an oracle control instead: 13 mutants of the instrument (removal marks never match, every path exists, `::name` kept, nothing exempt, exemption ignores the file, ignores the line number, count word list without `ten`/`10`, key-range pattern without `twelve`, index rule ignoring the tree, cloud-drive form dropped, profile pattern dropped, drive rule too wide, module-size pattern without commas) were each run against the relevant test: 14 of 14 kills, 0 survivors, in the transcript (§D). The first run had two survivors (a key-range pattern that did not need `twelve`, and a size pattern whose instrument probe matched on a substring); both tests were strengthened and the mutants now die. REF.3/3 and REF.4/2 also require that every exempt line still exists in its file and is caught when the exemption is switched off, so an exemption cannot go vacuous.

ARCH.1/1 is a standing property (row: base 5/5); it guards the deletion of a module-table row. The mutant "delete the `tools` row" fails it on the synthetic fixture.

## 4. Findings (not silently changed)

- **F-1 — base counts vs the guards' corpus.** CTX-DOCHYG excludes the 33 `.fast-dev-flow/` files from the base counts, but a guard that scans every tracked document also scans them while they are tracked. On the untouched base REF.1/1 reports 33 tokens (22 + 11), REF.2/1 5 broken links, REF.3/1 16, REF.3/2 12 and REF.4/1 82. With the folder excluded the scanners reproduce the rows exactly: 56 documents, 22 unmarked missing paths (same list as REF.1/1), 249 links with 0 broken, 4 and 11 retired-folder lines, 10 retired-workflow lines, 7 `s19tool` lines and 27 CDFX lines (transcript §B). A derived tree (base plus the R2 removal, §C) shows REF.2/1 and ARCHIVE.3/1 passing and the rest RED. No change needed; the guards follow the definition literally, so a re-added folder is caught.
- **F-2 — REF.6 differs from the old AT-285 behaviour.** The old arm skipped a line for either a removal mark or an s19tool shape before looking for CDFX, so `docs/README.md:3` ("distribution name `s19tool` … CDFX …") passed. REF.6 says only a removal mark excuses CDFX, and the 27-line base count only reproduces that way (25 otherwise). The widened node excuses CDFX by removal mark only and s19tool by removal mark or shape. This changes what the node accepts; the instrument block holds a control line for it.
- **F-3 — DEV.5 regex hazard.** `\d[\d,]*(\.\d+)?k?[- ](lines?|LOC)\b` also matches prose such as "3, lines" (digit, comma, space, word). No base line does. Left as written; the instrument asserts the match text for `21,138 lines` is the whole token.
- **F-4 — ARCHIVE.4/1 is RED on base by emptiness, not by the hit.** The archive folder does not exist on base, so the test fails with "archive files not tracked, nothing to scan" (a scan over zero files must not pass). The scanner itself was pointed at the four base sources (transcript §E): 1 hit (`PENDIENTES-batch96.md`, the drive-letter cloud-folder form), 0, 0, 0, as the row states.
- **F-5 — tests read the git index.** A new file counts once `git add`ed (the architecture archive, the moved notes); a removed file stops counting when `git rm` stages it. An unstaged archive file makes ARCHIVE.1/1 and ARCHIVE.4/1 RED. Text of a file listed but absent from the working tree is skipped.
- **F-6 — integration.** `tests/test_id_registry.py::EXPECTED_SCANNED_TEST_FILES` (262 at base) goes +1 for the new file (E1-slice §3 already says so). I could not run that test.
- **F-7 — interpretations I had to choose** (each is one line in the test file; say if the record meant otherwise): DEV.1 reads list items of the arrow form `` `name` → `module:func` ``; DEV.2 finds the block by a comment starting `# CLI examples` (the implementers' wording is `# CLI examples (module-only; no console script)`) and needs at least 4 lines; DEV.3 takes the one paragraph that names `.github/workflows/tui-ci.yml`, the branches from the workflow's top-level `on:` block and the markers `-m "not serial_timing"` and `-m serial_timing` as text; DEV.4/2 identifies the hex-renderer bullet by `hexview` plus one of `render_hex_view_text`, `find_string_in_mem`, `MAX_HEX_BYTES`; ARCH.5/2 accepts a `Frozen?` cell that is exactly `no` (markup stripped) or contains the `batch_id`; ARCH.5/1 matches each source tag as a whole token (N-2) and a second table in §11 fails; the rail-count predicate runs on the line with backtick spans removed (N-3), so tags and `§` citations must stay in code spans on rail lines; DEV.12/2 has a fifth fixed line (`**ten** rail screens, keys …`) that shows `twelve` is part of K.
- **F-8 — ARCH.4/2 citations.** The flow_screens module docstring cites `docs/architecture.md §10`; the test resolves each cited section by regex, not by line number, and passes when there is no citation (as the row allows).

## 5. GREEN-side evidence and its limit

No GREEN tree existed during my run, so the pass paths were exercised two ways, both on the remote host: (a) 68 synthetic cases (`i16t-synth.py`): a green document set and one mutant per negative control of the rows (delete the `tools` row, delete `B100-I1`, `B97-I-1`, `B99-I2`, `B99-I2a`, `B100-I2` from the interface table, add a second table, a `.py:<line>` citation, a `ten` back on a rail line, `Frozen? yes`, a `NEW` word in the sub-module table, and so on): 68 of 68 judged as expected; (b) two smoke runs on snapshots of the implementers' in-progress worktree, copied to a scratch repository on the remote host. The first (documents of two units edited, `docs/architecture.md` not yet) passed 28 of 45; its reds were architecture, archive-file or retired-link items still to do, plus one real test bug (the CLI-examples marker was too strict for `# CLI examples (module-only; no console script)`), now fixed. The second, later snapshot passed 43 of 45; the two reds were the architecture archive file not yet created (ARCHIVE.4/1 needs it tracked) and a scratch file `_tmp_splice.py` at the repository root that still names a `prototypes/` path in its text (REF.3/2 reads every tracked text file, so the scratch file must be removed or kept out of the index before E5). This is not a GREEN run of the finished increment; that is E5's run on the final tree.

## 6. Limits

- Nothing ran on this Windows PC except `py_compile`; two text rewrites of my own files used a short local Python edit script (no test, no import of the project).
- Not covered by a test of mine: ARCH.1/2, ARCHIVE.1/2, ARCHIVE.2/1, ARCHIVE.2/2 (E5 transcripts, as the case table says); Inc 14's `test_r_doc_readme_4_2_linked_documents_exist` was not run.
- The suites `tests/test_suite_hygiene.py`, `tests/test_id_registry.py` and the batch-folder redaction gate were not run against the new file or this note; I wrote neither a home path, an account or host name nor an address into either.
- The ARCHIVE.4 scan copies no pattern: it evaluates `_REDACTION_PATTERNS` and `_PLACEHOLDER` from the source text of `tests/test_suite_hygiene.py` with `ast`, so a change there changes the scan (and a rename of those two names makes the test fail loudly).
- Cleanup: the remote worktree, the snapshot directory and the archive were removed after the run.
