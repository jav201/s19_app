# Inc 6 — E5 corrective notes (C-1 … C-12)

Batch 2026-11-01-batch-101, increment 6, stage E5 corrective pass (Opus). Branch `b101-inc6`, start head `56593a3`, base `98d94d7` (origin/main). Rulings: `E5-rulings.md`. Inputs: `E5-code-review.md`, `E5-security.md`, `E5-coverage-audit.md`, `E5-mutants.md`, `E4-integration-notes.md`. The DeepSeek battery owns M1 … M42 and their transcripts (`../evidence/inc-6/mut-*.txt`); this pass adds **M43** (C-7) and **M44** (C-9) and its own transcripts `../evidence/inc-6/e5c-NN.txt`.

## 1. Sites, enumerated before the first edit

L = `tests/test_b101_patch_lifecycle.py`, H = `tests/test_b101_document_homes.py`.

| Ruling | Site(s) | Kind |
|---|---|---|
| C-1 | `02-test-cases.md`: every row's Tests / Coverage / Result to the audited values (`E5-coverage-audit.md` §3, §4), then moved again where C-3, C-4, C-5, C-7, C-9 change the evidence; H rows cite `e5c` runs (int-07 superseded by this pass's runs of the final file); `windows: not_run` on the rows with no Windows-only arm, and the C-12 result on the 10 rows that have one; the mutant transcript of each row's negative control cited (`mut-NN`, `e5c-NN`); header sentence on evidence | records |
| C-2 | `E5-mutants.md`: a ruling section recording M10, M35 as equivalent under every buildable route and M27 as the expected E3A-16 survivor; score restated; the `_reset_project_session` calls stay (no source change) | records |
| C-3 | L: a `open_project_by_dialog` helper (`p`, the row, Load; answers `y` to the replace question; closes the Load-result panel) used by `_replace_scenario` (`project`, cases 049.3.1/4, 3.2/4) and `_end_run` (`project`, CHK-PE-009/3, -010/2, -011/2, -012/2); `_save_project_keeps` through `sd.save_through_dialog` (`ctrl+s`, 049.3.1/9, 3.2/9); `008_subtitle[revert]` and `_end_run` (`add`) press Add / Remove on the Inspector tab and return to Checks before each read (CHK-PE-008/3, 009/4); `014_glyph_after_save_back` presses Write file on the JSON tab and returns to Checks (CHK-PE-014/1). H: `001_3_pick_keeps_spelling` saves through `ctrl+s` (001.3/4). `02-test-cases.md` Inputs of these 12 cases name the route | tests + records |
| C-4 | H `001_3_pick[library]`: ribbon name segment exact (001.3/3). `tests/test_tui_patch_editor_v2.py::test_at030a_dropdown_lists_and_loads_selected_change_file`: waits for the pick's document, asserts the document source `workarea/patches/<name>` exactly and the option list exactly (001.3/2, 001.1/4). `tests/test_tui_check_chain_b94.py::test_tc_b94_15_dropdown_population`: painted labels and option values exactly and in order (DIFF-CHK.1/2; the case's fixture amended to the node's three files) | tests + records |
| C-5 | L `test_r_tui_049_3_2_prompt_hidden`: the `img-patched*.s19` assertion and its docstring clause removed (no shipped route reaches the confirm while the prompt is hidden: Write file is the prompt's own confirm button, `#patch_saveback_confirm_button`); `02-test-cases.md` 049.3.2/1 and /8 Expected results lose "no file written" | test + records |
| C-6 | `docs/user-guide/ch08-patch-editor.md` §8.9 sentence (`:102`) and capture notes beside `ch08-09-` and `ch08-20-`; `tests/test_b101_help_legend_docs.py` `_CAPTURES_BEFORE` gains the two captures by named supersession (4 → 6). Docstrings: `app.py` `on_patch_editor_panel_change_file_selected` (Summary, Data Flow, Uses), `on_check_editor_panel_spec_file_selected` (Summary), `on_ab_diff_panel_check_file_selected` (Summary), `on_patch_editor_panel_save_back_decision` (the offer sentence); `screens_directionb.py` `PatchEditorPanel.set_change_files` Args and `AbDiffPanel.set_check_files` Args. Same class, same files, declared extension: the three panel message docstrings that still say "app.py re-resolves … under the patches folder" (`screens_directionb.py:4731`, `:6164`, `:8307`) and `_check_select_options` Args (`:8710`) | source (comments only) + docs + test |
| C-7 | `app.py` `_resolve_listed_file`: the name `.` is refused with `..`; its docstring; graph node `_resolve_listed_file` func text; H `001_4_refused[unknown-folder]` gains `patches/.`; `02-test-cases.md` 001.4/3 Inputs; mutant **M43** (drop `"."` from the refusal) → expected RED H `001_4_refused[unknown-folder]` | source + test + records + mutant |
| C-9 | Design gap. Records first: `01-requirements.md` gains **R-CHKED-032** (the canon's Write-status row, `REQUIREMENTS.md:3441`) amended: `When a spec is written, the system shall show the status Check Editor: wrote <listed name> (<n> fields, kind=check).` with `<listed name>` = the written file's value in the Spec list (`checks/<name>` in a project, `<name>` without one); `E1-rulings.md` §2 row; `02-test-cases.md` cases R-CHKED-032/1 … /4; graph node `on_check_editor_panel_action_requested` (func, examples) and the trace paragraph. Then H: new node `test_r_chked_032_write_status_names_the_home[project, no-project, collision]`, `031_write_home[after-library-pick]` asserts the new exact text (032/3), `040_spec_list[after-write]` sign updated; RED on a pristine `98d94d7` copy with only the new tests. Then `app.py` write arm (status built from `_spec_homes()[0][0]` + `path.name`); GREEN. Mutant **M44** (status back to `path.name`) → expected RED 032[project], 032[collision], 031[after-library-pick] | records + test + source + mutant |
| C-8 | No change. F5 (duplicated scan loop and refusal text) and F6 (double ledger render per Apply; load-tail comment) recorded here, §3 | records |
| C-10 | `E1-rulings.md` §1 backlog: (j) a dangling `workarea/patches` link ends the app on Check Editor Write (`FileExistsError` from `ensure_workarea`, `workspace.py:141`, through `changes/io.py:1648`); nothing is written; outside the slice | records |
| C-11 | No action; E5-6 is backlog item (g) | — |
| C-12 | Windows run of the 10 junction / file-link arms once each (`E5-coverage-audit.md` §4 "Windows not_run named"), isolated app-state folders, no clipboard; results into `02-test-cases.md` | run + records |

## 2. Decisions taken in this pass

- **E-1 (C-9 "the Write row").** The canon keeps the Write placement (R-CHKED-031) and the Write status (R-CHKED-032) in two rows. The status text belongs in R-CHKED-032, so that row is the one amended and brought into the increment; R-CHKED-031 keeps its text. One `shall` per row holds.
- **E-2 (C-9 listed form).** The status prints the home prefix the Spec list uses (`_spec_homes()[0][0]`: `checks/` in a project, empty without one) before the written file's name, so the status, the Spec list and the file on disk name the same thing; on a collision the claimed `_N` name follows the prefix.
- **E-3 (C-5).** The option "an arm that presses Write file" has no operator route: Write file is the prompt's own confirm button, hidden with the prompt. The clause leaves the cases.
- **E-4 (C-4, DIFF-CHK.1/2 fixture).** `test_tc_b94_15` keeps its three-file fixture (a check spec, a patch file, an unreadable spec); the case's Preconditions and Expected result are amended to that fixture, which asserts the same requirement threshold (the common folder's names, exactly and in order) over a wider set than W alone.

## 3. Recorded, not changed (C-8)

- F5: `_scan_patch_change_files` / `_scan_spec_files` share a four-line loop; the Patch Editor refusal f-string is spelled twice in the pick handler. Cosmetic.
- F6: every Apply renders the ledger twice (hook tail + the apply arm's own tail); the load-tail comment "a load replaces the document" also covers the hook. No behaviour impact; a graph change would be owed to skip it.

## 4. Runs

LAN Linux host 2, Python 3.11.18, detached worktree `<HOME>/work/s19_i6c` at origin/main `98d94d7` with `git diff --binary origin/main -- s19_app tests docs README.md` of this pass's working tree applied: staged tree **`2dedfdeb…`**, equal to the tree recomputed locally with a scratch index (origin/main + the same diff). Every transcript prints the base commit, the staged tree and `s19_app.__file__` (the worktree, or the mutant copy). `-n 10 -m "not serial_timing"` unless stated. Transcripts in `../evidence/inc-6/`.

| Run | Scope | Result |
|---|---|---|
| `e5c-01` | pristine `98d94d7` copy with only the two new test files (staged tree `10edb677…`): the 18 nodes this pass rewrote or added (L: 049.3.1/4, 3.2/4, /9 ×2, CHK-PE-008/3, 009/3, 009/4, 010/2, 011/2, 012/2, 014/1; H: 001.3/3, 001.3/4, 001.4/3, 031/3, 032 ×3) | **15 failed, 3 passed** — every failure behavioural (C-9: `'Check Editor: wrote s1.chk.json …' != 'Check Editor: wrote checks/s1.chk.json …'`; lists without the `library/` and project values; the hide and the Checks tab not reset after `p`, Add on the Inspector tab or Write file); the 3 passes are the declared standing guards (049.3.1/9, 3.2/9, 032/2) |
| `e5c-02` | the two new files whole, `test_before_after_report.py`, `test_tui_checks_screen.py`, `test_b101_symbol_reads.py`, `test_tui_check_editor.py`, and the changed nodes `test_at030a_dropdown_lists_and_loads_selected_change_file`, `test_tc_b94_15_dropdown_population` | **158 passed** (2:44), 0 skipped |
| `e5c-03` | law guards: `test_address_census`, `test_suite_hygiene`, `test_id_registry`, `test_engine_unchanged`, `test_docs_canon`, `test_b101_doc_hygiene`, `test_b101_help_legend_docs` | **218 passed** (1:19) |
| `e5c-04` | the 20 rewritten or added key/dialog nodes, three times | **20 passed ×3** (3/3) |
| `e5c-05` | M43 in a copy (C-7) | KILLED: H `001_4_refused[unknown-folder]` RED on the `patches/.` refusal |
| `e5c-06` | M44 in a copy (C-9) | KILLED: 032[project], 032[collision], 031[after-library-pick] RED on the status text; 032[no-project] GREEN (unchanged arm) |
| `e5c-07` | serial lane `-m serial_timing -p no:xdist` over the 10 touched test files | **2 passed**, 294 deselected; `QC-TM: 10 bounds, 0 under 20 % margin` |
| `e5c-08` | **Windows PC** (C-12, Windows-only-arm rule): the 10 junction / file-link arms once each (001.3/4, 001.4/1, /2, /4, /5, CHKED-034/1, -044/1, /2, DIFF-CHK.5/1, /2); `LOCALAPPDATA`, `APPDATA`, `TEMP`, `TMP` = a fresh scratch folder; no clipboard; `NO_COLOR` unset; one process (`import s19_app` + `pytest.main`) | **10 passed** (0:46), 0 skipped: the file links were created (no privilege skip) and the folder links ran as junctions |

`trace_check.py --req …/inc-6/01-requirements.md --base 98d94d7 --src s19_app` (imports no `s19_app`): 4 US, 28 active requirements, 1 gap — EVID only (no `04-validation.md` yet; it follows the re-audit).

Teardown: the remote worktrees `s19_i6c`, `s19_i6c_base`, the mutant copy and every `i6c-` helper were removed (`git worktree list`: 0 `i6c` entries; `~/work`: 0 `i6c` entries); the Windows scratch folder and the local `i6c` helpers were deleted. Nothing else that imports `s19_app` ran on the Windows PC (the local checks were `py_compile` and git plumbing).

Not run: the full suite and the QC-BC set (batch end); the DeepSeek mutants M1 … M42 against the re-driven nodes (they ran on the nodes before this pass; the re-driven nodes carry their base RED in `e5c-01`; the batch-end battery re-runs the table).

## 5. Final marks

85 cases (81 + R-CHKED-032/1 … /4): **85 `covered`, 0 `partial`, 0 `gap`**. Node marks: every row has a `full` node; 2 secondary `partial` marks remain (`…_11_1_no_project_reason_exact_text`, service composer; `test_at_038a…`, body re-keyed). Results: 85 `verified (linux)`; Windows: 10 `verified (e5c-08)`, 75 `not_run` (no Windows-only arm). Controls: 64 rows with a killed mutant, 6 rows with an equivalent (M10 ×2, M35 ×4), 1 expected survivor with an effective control (R-CHKS-009/2: M27, M28), 14 standing guards or double-defended arms with no isolating mutant (R-DIFF-CHK.3/1 among them: its E1 control has no mutant).
