# Inc 14 — E5 corrective notes

Batch 2026-11-01-batch-101, increment 14, stage E5, corrective pass. Model: Opus. Branch `b101-inc14`, head `7d37efa` plus this pass.
Inputs: `E5-rulings.md` (C-1 … C-9), `E5-code-review.md` (F1 … F8), `E5-security.md` (E5-1 … E5-4), `E5-coverage-audit.md`, `01-requirements.md`, `02-test-cases.md`, `codewire/graph-inc14.md`, `E3-rulings.md`, `E4-integration-notes.md`.
Every test ran on the LAN Linux host (operator rule): conda env `s19ci`, Python 3.11.18, a detached worktree at `origin/main` `f9f3cb0` with the branch diff (`git diff b7b77c4`) applied, and `s19_app.__file__` printed first (the worktree's own copy). `origin/main` moved from `b7b77c4` to `f9f3cb0`; between the two, only `.dev-flow/`, `prototypes/` (archived out of the tree) and `.gitignore` changed, and nothing under `s19_app/`, `tests/` or the documents. Nothing ran on the Windows PC.

## 1. Verdict

**All nine rulings are done. The final runs are GREEN** (§4). C-1 was proven RED with two mutants before it went GREEN. The product texts changed only where C-8 names them, and each change is mirrored in its graph node.

## 2. Ruling → change

| Ruling | Change | Where |
|---|---|---|
| C-1 (F1, R-WHELP.12/2) | Each rail window is now read from its own container (`app.query_one(f"#{SCREEN_CONTAINER_IDS[w]}")`); the Reports dialog and the Split / Join / Export window were already scoped. A control must be a **whole label**: `_label_names` drops a leading icon, a trailing colon, a trailing parenthesis, and a field line's value two spaces after its label (`NAMING  ‹stem›…`). The prefix rule is gone, so `Goto 0xADDR` no longer stands for `Goto`, `Load path` for `Load`, or `Load / Save` for `Save`. New negative controls: `Filter tags` is not found in Checks; `Goto`, `Save` and `Run checks` are not found in a longer label. Proof: §3. | `tests/test_b101_help_legend_docs.py` (`_label_names`, `_control_found`, `test_r_whelp_12_2_named_controls_exist`) |
| C-2, 13/2 | `_FOLDER_MAP` maps each (section, backslash code span) to its constants in order (12 spans, e.g. `workarea\patches\` → `WORKAREA_SUBDIR`, `WORKAREA_PATCHES`). `_folder_mapping_defects` reports unmapped spans, map entries no section writes, and a value mismatch. Negative control: `workarea\splits\` where `workarea\patches\` belongs → reported. **full** | same file |
| C-2, README.4/3 | `_operations_claim_defects` needs the graph's two whole sentences: the one that names `crc` says it checks or writes CRCs, and the one that says "not implemented" names exactly `extract` and `split_by_segment`. Two negative controls swap the names. `split_by_segment` is also run (placeholder note). **full** | same file |
| C-2, RELNOTE.1/1 | The text under `#### What changed` and under `#### Am I affected?` is compared, whitespace-normalised, with the two parts of `inc-8/release-note-crc.md`, pinned verbatim in the test. Negative control: a paraphrase that keeps every old fragment is reported. **full** | same file |
| C-2, GUIDE.1/9 | New `test_r_doc_guide_1_9_named_bullets_hold_the_1_0_0_phrases`: `a2l=used` in the 21.1 **Header** bullet and `from the loaded A2L and MAC` in the **Runs** bullet. Negative control: the phrase taken out of its bullet is reported. **full** (the passage-9 arm stays, marked partial) | same file |
| C-3 (SR-1) | The capture note follows graph I-5, `(capture taken before 1.0.0` then `:` and what the capture shows, in: R-DOC-GUIDE.1 threshold (`01-requirements.md`), E1 ruling D-5 (`E1-rulings.md`), cases R-DOC-GUIDE.1/1, /4, /7, /8. Case R-WHELP.12/1 says 8 sections, with N-1 in its inputs. | records |
| C-4 | The Result column keeps the flow's values: `verified (linux, int-07)` (transcript `evidence/inc-14/e5c-int-07-*.txt`), `failed` (R-DOC-SECURITY.1/2), and `not_run` (the two not-testable cases). The audit's `executed` was not adopted. The three supporting files `test_tui_checks_view.py`, `test_map_click_chain.py` and `test_b100_load_question.py` ran in int-07. | `02-test-cases.md`; §4 |
| C-5 | 21/2 cites `tests/test_segment_split_window.py::test_default_tab_is_ranges_with_and_without_an_a2l`; 011/2 cites `tests/test_legend_map_sheet.py::test_tc680_sheet_no_wrapped_lines[80x24]`. The image-load cases (12/2, 20/2, 21/2, 22/2, 011/1, 011/2, and the new 7/2) say in the Tests column that `load_selected_file` has no product caller and reaches the same `_parse_loaded_file` / `_apply_loaded_file` as the load worker (`app.py:17756`, `:17775`, `:18430`). The audit's precondition corrections are applied too: the fixtures of 12/2, 18/2, 19/2 and 19/3, the 12/4 tie node, and the action route of 062.10.1/1. | `02-test-cases.md` |
| C-6 | The nine uncovered clauses, one by one: see §5. | tests, `02-test-cases.md` |
| C-7 | New black-box `test_r_whelp_7_2_question_mark_paints_the_approved_copy`. For A2L Explorer, Workspace, Checks, CRC Designer, Flow Builder, Split / Join / Export and Reports (opened by `t`): focus a widget of the window that takes no typed text and is not the chip, press `?`, and compare the painted title and `#window_help_body` with the numbered approved copy, and `#window_help_keys` with the window's keys block. Observed: key lines are painted for 4 windows and absent for CRC Designer, Flow Builder and Reports (`WINDOW_KEYS` holds no entry for them); that set is pinned. New `test_r_tui_062_10_1_3_k_paints_the_map_keys_line`: Image F, `4`, `k`; the Map keys box equals Legend copy I14. `F1`: n/a, since no binding exists (grep). | same file |
| C-8 | **F2:** DOSSIER F-28 Kind → `defect, live · fixed in 1.0.0: the block names the cause when it refuses a Designer template; it does not read Designer templates`. `test_r_doc_guide_2_1` pins that exact ending for F-28 (stricter than `endswith("fixed in 1.0.0")`), and 2/2 is unchanged. The graph DOSSIER node and the Fixed-mark definition carry the supersession. **F3:** CHANGELOG → `(a tab, a carriage return or a line feed each as one space)`; 13/1 pins it and the old wording as absent; graph node `### Reports` (e) updated. **F4:** one spelling, `^K`: the README key-bar sentence (`README.md:131` after the rewrap; `:128` before) now reads `` `^K` Palette · `^D` Density · `^L` Load · `^S` Save project · … · `^P` palette ``, as the help steps, the README tables (`Ctrl+K`) and the requirement Definitions write it; graph README block (3) updated. **F5:** stale docstrings refreshed (`test_window_usage_help.py` module docstring, the seat counts 8 → 9, the boundary test's docstring and message), plus E5-2: the G module docstring lists SECURITY.md only under its hold-out group (three tests). **F6:** the vacuous control in `test_tc1802_nine_md_sections_intact_tenth_section_added` now runs a detector, `_key_census_defects`, on a home missing `a2l` and on one with an extra key; the thin guide /7 pin is covered by the new beside-the-capture test (1/12). **F7:** the 11 new README paragraph lines are wrapped at 80 columns like the rest of the file (flattened text verified equal; no line starts a list, heading or table). **F8:** E3 N-2 says three tests and the README row, and keeps `readme_4_2`. **E5-4:** `E3-security.md` and `E4-integration-notes.md` (and case 1/2) cite `evidence/inc-14/gh-pvr.txt`. | `docs/user-guide/DOSSIER.md`, `CHANGELOG.md`, `README.md`, graph, tests, records |
| C-9 | The branch keeps `SECURITY.md`, its three `test_r_doc_security_*` tests and the README row. After the F7 rewrap, the row sits at **`README.md:468`** (it was `:429`). `test_r_doc_readme_4_2` stays. One arm was added inside `test_r_doc_security_1_1` (no-fallback, C-6), so the group is still three tests. To record in 04-validation at merge. | — |

### Decision recorded: F4 spelling
The key bar paints the global keys in lower case (`^k`; Textual's `get_key_display`, pinned by `test_b97_key_bar.py`). The help copy writes `^L` / `^S` / `^K`, in rewritten and unchanged sections alike (Patch, Map and changes-file notation have done so since before Inc 14), and the requirement Definitions and K(w) use the same form. I picked `^K` and changed only the README sentence. The other choice, lower-casing the help, would change unchanged sections, Help copy I14, the support copy and the K(w) definition, which is wider than C-8. **Left open:** the README sentence now quotes the bar's keys in upper case, while the bar paints lower case. The guide outside this slice (`ch01:30-31`, `ch14:4,19,117`, `ch19:33,45,52`, `DOSSIER:767`) keeps the bar's lower case. That is for the batch-end doc pass.

## 3. C-1 transcript (RED with its mutant, then GREEN)

`evidence/inc-14/e5c-c1-mutants-red-then-green.txt`. `test_zz_c1_old_probe.py` is the test file as committed at `7d37efa`, a temporary copy in the remote worktree only, removed afterwards.

| Mutant | Strengthened test | Pre-E5 test |
|---|---|---|
| M1 `app.py:3659`: the Checks Hex Peek pane is titled `Peek` (Hex Peek is then painted by Issues only) | **FAILED**: `named controls not painted by their window: [('checks', 'Hex Peek')]` | passed |
| M2 `app.py:8064`: the A2L Explorer `Goto` button reads `Go` (`Goto 0xADDR` stays; `Goto` stays on Workspace and MAC) | **FAILED**: `[('a2l', 'Goto')]` | passed |
| both reverted (`app.py` diff empty) | **passed** | — |

## 4. Final runs (LAN Linux host, `-n 4`)

Command form: `env -u NO_COLOR PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. timeout 2400 python -m pytest -q -p no:cacheprovider --basetemp /tmp/pytest-s19c14 -n 4 -rfEs …`, with `s19_app.__file__` printed first in each transcript (redacted).

| Run | Set | Result | Transcript (`evidence/inc-14/`) |
|---|---|---|---|
| int-07 | the new file G; the re-bodied `test_window_usage_help.py`, `test_changes_file_notation_help.py`, `test_docs_canon.py`, `test_id_registry.py`; `test_suite_hygiene.py`; the law guards of the repo's `CLAUDE.md` (`test_engine_unchanged.py`, `test_tui_directionb.py` incl. `test_tc031_*`, `test_requirements_canon.py`, `test_id_registry.py`; the repo has no `AGENTS.md`); the three C-4 supporting files `test_tui_checks_view.py`, `test_map_click_chain.py`, `test_b100_load_question.py`; `test_b101_flow_ext_copy.py` (R-WHELP.26/2) | **1 failed**, 502 passed, 4 skipped | `e5c-int-07-inc14-reworked-guards-supporting.txt` |
| int-07b | `test_suite_hygiene.py`, after the record fix | **65 passed** | `e5c-int-07b-hygiene-rerun-after-record-fix.txt` |
| int-08 | importers of `window_help` / `legend`, group B: `test_b100_focus.py`, `test_b100_load_dialog.py`, `test_b97_{check_editor,chips_help,flow_builder,flow_execution,key_bar,patch_editor,width}.py`, `test_b99_bytes_field.py` | **670 passed**, 10 skipped | `e5c-int-08-importers-b97-b99-b100.txt` |
| int-09 | importers, group C: `test_legend_{map_sheet,n8,two_pane,scope_and_logwidth}.py`, `test_tui_legend.py`, `test_report_service.py`, `test_segment_split_window.py`, `test_tui_diff_screen.py`, `test_tui_report_seam.py`, `test_tui_theme.py` | **274 passed** | `e5c-int-09-importers-legend-report-split.txt` |

- **The int-07 failure** was `test_suite_hygiene.py::test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses`, with the hit `inc-14/E5-security.md: user-profile path` (line 53 quoted the shared Windows Public profile path of the demo folder). It was a record leak, not a test or product defect, and the record is the thing that was wrong. The line now names the folder without the path. The guard passed in int-07b. No assertion changed. The saved int-07 transcript quoted the same path in the failure message, so it is redacted there (`<Public-profile-path, redacted>`, 2 places). After all evidence was saved, the guard node was run once more over the final batch folder: 1 passed. That last run was executed, but its transcript was not saved.
- **Skips, itemised (`-rs`):** int-07 has 4, all Windows-only arms (`test_b100_load_question.py:2017`, and `test_b101_flow_ext_copy.py:563`, `:796`, `:1268`). int-08 has 10, Windows-only arms in `test_b100_load_dialog.py`. None is an Inc 14 node.
- **Every test importing `window_help` or `legend`** (grep over `tests/`) ran: int-07 (G, `test_window_usage_help.py`, `test_changes_file_notation_help.py`, `test_tui_directionb.py`), int-08 and int-09. `test_tui_snapshot.py` was not in the set: its SVG cases need `pytest-textual-snapshot`, which `s19ci` lacks (E4 §5, `not-run`).
- All 74 case results are read from int-07 (every `full` node is in it and passed). Supporting nodes passed in int-07 and int-09.

## 5. C-6: the nine clauses

| # | Clause (audit §4) | Outcome |
|---|---|---|
| 1 | R-WHELP.7 event row: title and key lines of an opened help window | new case R-WHELP.7/2 → `test_r_whelp_7_2_question_mark_paints_the_approved_copy` (C-7) |
| 2 | R-DOC-SECURITY.1: no public-issue fallback | new case R-DOC-SECURITY.1/3 → an arm in `test_r_doc_security_1_1_…` (`_fallback_hits`, two negative controls; the hold-out group stays three tests) |
| 3 | R-DOC-SECURITY.2: ships with 1.0.0 | new case R-DOC-SECURITY.2/2, **not-testable**: a release fact (the tree is at `1.0.0rc1`, and `pyproject.toml` packages `s19_app*` only); batch-end evidence with the `gh api` re-check (E5-3) |
| 4 | R-DOC-RELNOTE.6: the HTML window cut, and no claim that the changed pane was cut | case 6/1 extended → `test_r_doc_relnote_6_1_…` pins the whole earlier-cut sentence; `changed pane` and `every HTML window` absent |
| 5 | R-DOC-RELNOTE.7: the full status line | case 7/1 extended → `test_r_doc_relnote_7_1_…` pins the whole line |
| 6 | R-DOC-RELNOTE.8: no text on how the climb could be used | new case R-DOC-RELNOTE.8/2, **not-testable** as a scan (a meaning, not a phrase list); reviewed by the E5 security review, S-2 verified |
| 7 | R-DOC-RELNOTE.1: the two paragraphs verbatim | C-2 (1/1 full) |
| 8 | R-DOC-GUIDE.1: the note beside each named capture, I-5 continuation | new case R-DOC-GUIDE.1/12 → `test_r_doc_guide_1_12_capture_notes_beside_their_captures` (the block after each capture up to the next image or heading; two negative controls) |
| 9 | R-WHELP.12 (b): window scope | C-1 (12/2 full) |

## 6. Counts

- **Cases: 74** (69 + 5 new: R-WHELP.7/2, R-DOC-SECURITY.1/3, R-DOC-SECURITY.2/2, R-DOC-RELNOTE.8/2, R-DOC-GUIDE.1/12). By story: help 27, legend 4, README 7, security 5, release notes 17, guide 14.
- **Coverage: 71 `covered`, 3 `not-testable`, 0 `partial`, 0 `gap`.** The audit's 5 partials are now full: 12/2 (C-1), and 13/2, README.4/3, RELNOTE.1/1 and GUIDE.1/9 (C-2). Its 4 conflicts are covered (C-3).
- **Result: 71 `verified (linux, int-07)`, 1 `failed` (R-DOC-SECURITY.1/2, the setting is off), 2 `not_run`.**
- **Tests:** 5 new test functions in G (`test_r_whelp_7_2_…`, `test_r_tui_062_10_1_3_…`, `test_r_doc_guide_1_9_…`, `test_r_doc_guide_1_12_…`, and the C-2 arms inside existing tests). No test function was renamed or deleted, and no assertion was weakened: every change adds an assertion, or replaces a match with a stricter one (C-1 whole label, F-28 exact ending).

## 7. Files changed in this pass

- Tests: `tests/test_b101_help_legend_docs.py`, `tests/test_window_usage_help.py` (docstrings), `tests/test_changes_file_notation_help.py` (F6).
- Product texts (C-8 only): `docs/user-guide/DOSSIER.md` (F-28), `CHANGELOG.md` (CRLF wording), `README.md` (key spelling, rewrap).
- Records: `01-requirements.md`, `02-test-cases.md`, `E1-rulings.md` (D-5), `E3-rulings.md` (N-2), `E3-security.md` and `E4-integration-notes.md` (E5-4), `codewire/graph-inc14.md` (DOSSIER, CHANGELOG (e), README (3)), this file, `steps.log`; evidence `evidence/inc-14/e5c-*.txt`.
- No source file under `s19_app/` changed. `prototypes/cambios_10_12_2026/help_sections.md` was not touched.

## 8. Incident (stated, not hidden)

The session scratchpad is shared with other agents. My first sync helper (`scratchpad/sync.sh`) was overwritten by the Inc 11 agent's script of the same name, and I ran it twice before I saw that. Each run did `git reset --hard` plus `git clean -fdq -- s19_app tests` in the Inc 11 agent's remote worktree, and then applied the local Inc 11 diff. That is what its own sync does. Still, a mutant or a run in flight there may have been disturbed. I reported this to the orchestrator at once and changed nothing else there. From then on, my helpers used unique `c14e5_*` names. The first C-1 mutant attempt ran against the unsynced, pre-E5 test (both arms green). It was discarded and re-run after a verified sync (§3).

## 9. Left open

- The SECURITY.md group (C-9 / E5-1): the orchestrator removes it at merge if `gh api` still reads `{"enabled":false}`. Record it in 04-validation.
- The F4 spelling outside the slice (§2): batch-end doc pass.
- The mutant table (DeepSeek) and a re-audit of the changed cases come after this pass (`E5-rulings.md`).
- SVG snapshot tests: `not-run` (`pytest-textual-snapshot` is not installed in `s19ci`; E4 §5).
