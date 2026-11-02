# Inc 12a — E4 integration notes (progress indicator, labels, backlog sweep)

Stage E4, integration step. Inputs read: `E4-impl-notes.md` (3 declared deviations), `E4-tester-notes.md`, `codewire/interfaces-12a.md`, `codewire/proto-12a-indicator.md`, `codewire/proto-12a-sweep.md`, `E3-rulings.md` (round 1 and the round-2 addenda), `E1-requirements-draft.md` (LLR-176.1r, LLR-176.2b). Worktree `<HOME>/Github/s19_app-b100-inc12a`, branch `b100-inc12a` at `051f586` plus the uncommitted Inc 12a change. Evidence states use the seven words only.

Abbreviations: `B` = `tests/test_b100_busy.py`, `LD` = `tests/test_b100_load_dialog.py`, `AN` = `tests/test_b100_announce.py`, `RP` = `tests/test_report_progress.py`, `SR` = `tests/test_b100_session_reset.py`, `R` = `tests/test_b100_recents.py`. Transcripts are under `.dev-flow/2026-10-26-batch-100/evidence/inc-12a/`.

## Result

The new tests and the re-pinned nodes are GREEN (`green-01-new.txt`, `green-02-repinned.txt`). The guards run is **failed** on exactly one node: `tests/test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors`. That failure is inherited from the base and lies outside this step's edit scope (F-8). One source change was made (SR-12a-2, in `app.py`), plus the deviation-3 docstrings. Test-side fixes: F-1…F-5 and F-7 (below), and ruling D-1. None of them weakens an oracle; F-3 and F-4 make the outcome check stricter.

## Failures met

The first diagnostic run was split over 4 parallel shards: TC-B100-50 (`int-diag-A-busy50.txt`), TC-B100-51 + AT-B100-17 (`int-diag-B-busy51.txt`), the other new arms (`int-diag-C-new-other.txt`) and the re-pinned nodes (`int-diag-D-repinned.txt`). These are diagnostic transcripts. Their `# pytest exit code` footer reads `0` for a run that failed, because of a bug in the wrapper (it echoed `$?` after another `echo`). The wrapper was fixed before the evidence runs; read each diagnostic's own summary line, not its footer. The test-id-registry guard was also run alone once (4.8 s, not kept: `1 failed, 12 passed`, F-7 below).

F-8 surfaced in the guards evidence run. Each failure is judged against the graph and the requirements.

| # | Node | Cause | Who is wrong | Fix |
|---|---|---|---|---|
| F-1 | `B::test_tc_b100_51_action_table_names_the_seven_long_actions` | `sum(len(row.steps)) == 19`, the test asserted 18. | **Test, inherited from a graph slip.** The fixed table (interfaces S-c, ruling Q-5) has step counts `3, 3, 4, 4, 2, 2, 1`, which add up to 19. proto-12a-indicator A12-27 (`:53`) and X-5 (`:558`) say "(18 names)". The code holds the confirmed 19 names. | `== 19`, and the docstring names the slip. Seam ruling **SR-12a-1**. |
| F-2 | `LD::test_tc_b100_66_progress_lines_carry_no_decision_id` | 19 painted progress lines, the test asserted 18. | **Test** (same arithmetic as F-1: 7 begins + 12 later steps = 19). | `len(painted) == 19`; the docstring says 19 lines, 19 step names, 26 texts. The decision-id oracle is unchanged. |
| F-3 | `B::test_tc_b100_51_diff_report_ends_once_and_logs_its_outcome[written]` | `added[-1]` was the full outcome; the test expected it clipped to `max(50, width)`. | **Test.** `log` is `tests/support/b100_projects.StatusLog`, which records every `set_status` message in full. The width clip is applied later, in `_append_log_line`. The code writes exactly the outcome (A12-58). | The test compares the whole outcome. This is stricter, not weaker: a dropped path tail now fails. |
| F-4 | `B::test_tc_b100_51_before_after_ends_once_and_logs_its_outcome[written]` | Same as F-3. | **Test.** | Same fix; the docstring says "in full". |
| F-5 | `B::test_tc_b100_50_names_paint_literally_through_load_from_path[bidi override]` | The progress lines held 0 U+202E. The assertion also scanned the file-state line `Loaded fw‮gpj.s19 (S19 only)` (painted at the last end) and the outcome `Loaded fw‮gpj.s19`, and both held U+202E. | **Test** (it asserts more than the requirement). LLR-176.1r and A12-24 bound the progress line: "→ `⠋ Loading fwgpj.s19 · …`, with 0 U+202E characters". The file-state line comes from `_apply_prepared_load` → `set_file_status`, and its text is unchanged from base. The file-load outcome `Loaded <name>` is fixed by Q-3. Both go through `safe_text` only, which removes ESC/C0 (S12a-02) but not bidi controls, exactly as on base. | The U+202E check reads the progress lines only. The finding stays visible as observation **O-12a-1** below. It is not a 12a regression. |
| F-6 | `RP::test_kickoff_sets_bar_in_progress_before_worker` (re-pin A2) | `NoMatches: No nodes match '#status_text' on Screen(id='_default')`, raised from `_busy_tick` at app exit. The test stubs the worker, so the report run stays open until `run_test` exits (risk R-7). The 0.1 s timer then ticked after the default screen's widgets were removed. | **Graph wrong (R-7), code fixed.** proto-12a-indicator R-7 says "Textual stops every timer at exit". Executed: it does not stop the timer before the status bar is gone. In production this is a quit while a worker runs, for example a long file load: the tick would raise at shutdown. | **Code, smallest fix, seam ruling SR-12a-2.** `_busy_tick` returns when `query_one_optional("#status_text", Label)` is `None` (`app.py:19944`–`:19948`). No other path changes. Negative control executed: the pre-fix tree is this mutant (M-37), RED in `int-diag-D-repinned.txt`. |
| F-7 | `tests/test_id_registry.py::test_tc607_scanned_corpus_matches_the_declared_bound` | `the guard scanned 234 test modules, not the declared 233`. | **Test** (legitimate growth: the tester added `tests/test_b100_busy.py`; same as Inc 7, 8a, 9b, 10 and 11). | `EXPECTED_SCANNED_TEST_FILES` 233 → 234, with a history line and a docstring line. Measured by the guard. |
| F-8 | `tests/test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors` (guards run) | `address arguments outside {literal, name, fstring} appeared: s19_app/tui/screens.py:407 other:IfExp`. The selector is `"#load_list" if self._mode == "list" else "#load_path"` in the Load dialog, from Inc 9b (`741cc07`). | **Neither 12a code nor 12a test: inherited.** `screens.py` is untouched by Inc 12a. The same node FAILS on the untouched base `051f586` (`evidence/inc-12a/int-census-on-base.txt`: `1 failed in 7.37s`, same message). | **Not fixed** (outside the `app.py` / `styles.tcss` edit scope; Inc 11's E5 pass is editing `screens.py` now). Routed to the orchestrator: two literal `query_one` calls in `screens.py`, or an Inc 11/E5 or batch-end fix. |

After the fixes, the 6 F-1…F-6 nodes were run again together: `12 passed, 1 skipped in 34.38s` (`int-diag-E-refail.txt`, diagnostic; the skip is the ESC/BEL arm).

Two evidence attempts of the new-test run did not count:

- `green-01-new-run1-130arm-notrun.txt`: `111 passed, 2 skipped`. **Not counted as passing evidence.** The second skip is the 130-character arm: "the volume refuses this name (reported not run)". The `--basetemp` path (`…\int12a\bt\green01\n2\`) plus 130 characters exceeds MAX_PATH (`LongPathsEnabled = 0`). The same arm PASSED in `int-diag-A-busy50.txt`, whose basetemp is shorter. The wrapper's basetemp was then shortened to `…\int12a\b\<label>`.
- `green-01-new-run2-setup-error.txt`: `1 skipped, 112 errors in 3.49s`. **Failed (environment).** The new basetemp parent folder did not exist yet. pytest raised `FileNotFoundError` at setup and ran no test. The folder was created.

`green-01-new.txt` is the third run, and it is complete.

## Orchestrator rulings on the tester's ambiguities (bind; recorded here)

- **D-1:** `tests/test_tui_diff_screen.py::test_at_b78_32_app_bindings_block_is_untouched` is fixed completely. The two missing frozen rows `('c', 'confirm_attention', 'Confirm', False)` and `('d', 'a2l_describe_tag', 'Describe tag', False)` are added, and `_B79_COMMITTED_APP_BINDING_COUNT` goes from 40 to 42. Each change has a history line naming batch-100 Inc 12a. The node is **GREEN** in `green-02-repinned.txt` and leaves the known-CI-failure list.
- **D-2:** follow the design. A report never writes 100. The E1 §D.3 sentence is corrected at close.
- **D-3:** follow the design. Not asserted.
- **D-4, D-5, D-7, D-8:** accepted as the tester wrote them.
- **D-6:** S12a-03 wins. The pick re-check runs inside `go`, after the Inc 10 question (`app.py:15099`–`:15130`; `R::test_tc_b100_39_pick_rechecks_the_entry_after_the_question` GREEN). Interfaces S-i is corrected at close.
- **A12-51** (the manifest-mismatch tail of Save project) has no test. Declared, owed at the batch-end battery (mutant rows M-69 / M-70).
- Inc 11's E5 corrective pass (on `b100-inc11`) was not ported here. It arrives by merge before Inc 12a's E5.

## Deviation dispositions (implementer, `E4-impl-notes.md`)

| # | Deviation | Disposition |
|---|---|---|
| 1 | The `project.json` lstat not-regular arm paints the `unreadable` pair, not the sweep graph's `not a project` pair | **Accept.** The base text of that arm is `could not be read — check that the folder can be opened, then load again.` (the `-w` diff shows the old literal). The same graph says "every painted text is unchanged character for character" (S-k). `LD::test_tc_b100_64_project_json_that_is_not_a_regular_file_is_refused` pins `could not be read` (guards run, GREEN). The graph line `proto-12a-sweep.md:178` is wrong. Seam ruling **SR-12a-3**. |
| 2 | `_handle_load_project` success: `set_file_status` before `end_busy` (base painted the summary first) | **Accept. This is not a deviation.** proto-12a-indicator step (8) (`:422`) orders it this way. A12-42 and A12-70 depend on it (`AN::test_tc_b100_56_…` GREEN). |
| 3 | The worker docstrings miss the new `gen` argument | **Corrected** (ruling rule 3). `gen` is added to the `Args` of the 4 workers (`_start_before_after_worker`, `_start_generate_report_worker`, `_start_diff_report_worker`, `_start_load_worker`) and of the 2 main-thread end sites that took the same new parameter (`_finish_generate_report`, `_handle_load_error`). Docstring only. |
| 4 | "No other deviations"; `begin_busy` has 1 call site | **Confirmed.** `B::test_tc_b100_50_begin_busy_is_called_only_from_the_one_label_helper` and `B::test_tc_b100_51_only_the_seam_sets_the_bar` are GREEN. |

Implementer open questions: the `_busy` `SNAPSHOT_EXCLUSIONS` entry was added by the tester (re-pin A8; `SR::test_tc_b100_09_…` GREEN). The 29 SVG snapshots were **not** regenerated (CI workflow `snapshot-regen.yml` only); `tests/test_tui_snapshot.py::test_tc016s_density_layout_snapshot` for those 29 cells is `not-run` here and expected to drift until the regen.

## Seam rulings to confirm

- **SR-12a-1 (graph arithmetic; test changed).** The action table has 19 step names (`3 + 3 + 4 + 4 + 2 + 2 + 1`), not 18. Text fix at close: proto-12a-indicator A12-27 (`:53`) and X-5 (`:558`); any TC-B100-66 threshold text that says 18 / 25.
- **SR-12a-2 (graph wrong; code changed).** R-7's "Textual stops every timer at exit" does not hold. The busy timer can tick after the status bar is removed, while a run is still open at quit. `_busy_tick` paints nothing when `#status_text` is absent. Proposed text: replace R-7 with this rule, and add the quit-with-an-open-run arm to LLR-176.1e/.1f (or leave it to 12b's quit-after-end check, A12a-07). Alternative for the orchestrator: stop the timer in an `on_unmount`. It was not chosen, because the tick could still fire between widget removal and unmount.
- **SR-12a-3 (graph wrong; deviation 1 kept).** Both arms of the `project.json` lstat gate (`OSError` and not-regular) paint the `unreadable` pair, as on base. Text fix at close: `proto-12a-sweep.md:178` says `unreadable`.
- **O-12a-1 (observation, not a ruling; no change).** A bidi control (U+202E) in a file name still reaches `#status_text` through the file-state line `Loaded <name> (S19 only)` and the status log through the file-load outcome `Loaded <name>`. Both go through `safe_text` only, as on base. LLR-176.1r covers the progress line only. Route: `security-reviewer` at E5, or BACKLOG-CODE (to scrub the file-state / file-load outcome name through `painted_names`, the way A12a-03 does for the A2L outcome).

## Final pass counts

Each count is read from one complete run's own summary line. green-01 ran alone; green-02 and the guards ran in parallel. No timing arm failed in any run. Every transcript prints `s19_app.__file__` = `<HOME>\Github\s19_app-b100-inc12a\s19_app\__init__.py` at its top, and ends with `real %LOCALAPPDATA%\s19_app exists: no`.

| Run | Transcript | Result | State |
|---|---|---|---|
| New tests (`tests/test_b100_busy.py` whole, plus the new arms in `test_b100_load_dialog.py` (3), `test_b100_announce.py` (1) and `test_b100_recents.py` (11 functions); 113 ids) | `evidence/inc-12a/green-01-new.txt` | `112 passed, 1 skipped in 371.46s` | executed; the skip is the ESC/BEL arm, `not-run` on Windows, never passed (S12a-R2-3). Earlier attempts: `green-01-new-run1-130arm-notrun.txt` (`111 passed, 2 skipped`: the 130-character arm was `not-run` (MAX_PATH), so the run is not counted) and `green-01-new-run2-setup-error.txt` (`112 errors`: environment, **failed**) |
| Re-pinned nodes (19 functions, 22 ids; with green-01, the same 135 ids as `red-01-vs-base.txt`) | `evidence/inc-12a/green-02-repinned.txt` | `22 passed in 148.13s` | executed |
| Guards (`test_id_registry.py`, `test_b99_staging.py`, `test_engine_unchanged.py`, `test_address_census.py`, `test_b100_load_question.py`, `test_b100_load_dialog.py`, plus the 4 `test_b100_save_dialog.py` functions that touch or drive `_commit_project_save`: `test_tc_b100_47_one_preparation_ast_census`, `test_tc_b100_65_save_executes_the_painted_plan`, `test_tc_b100_65_merge_names_the_active_variant_it_sets`, `test_at_b100_21_painted_plan_is_the_saved_tree`; 300 ids) | `evidence/inc-12a/guards-01.txt` | `1 failed, 295 passed, 4 skipped in 1533.53s` | **failed**: 1 node, inherited from the base (F-8). The 4 skips are `test_b100_load_dialog.py:377` "the volume refuses this name (reported not run)" (MAX_PATH), `not-run`, never passed, the same 4 as Inc 9b and Inc 11 |


Not run, by the operator override of 2026-10-31: whole touched modules, the full suite, the 29 SVG snapshot cells (`not-run`, owed to the batch-end battery / CI regen). Mutation: only M-37 is `executed` (RED before SR-12a-2); the other rows of `E4-mutant-candidates.md` are `planned`.

## Source sha256[:16] (post-integration, working-tree bytes)

| File | sha256[:16] | Edited at E4 |
|---|---|---|
| `s19_app/tui/app.py` | `ed0ee69584332172` | yes: SR-12a-2 guard in `_busy_tick`; `gen` in 6 docstrings |
| `s19_app/tui/styles.tcss` | `f7b4f75911b296a4` | no |

Source files touched by this step: 1 (`app.py`), within the 2-file set. Test files touched by this step: `tests/test_b100_busy.py` (F-1, F-3, F-4, F-5), `tests/test_b100_load_dialog.py` (F-2), `tests/test_tui_diff_screen.py` (D-1), `tests/test_id_registry.py` (F-7). Line endings: both sources stay CRLF with 0 bare LF (checked by byte count); the edited test files keep their CRLF.

## Orchestrator rulings on the seam rulings (E4 close)

| Id | Ruling |
|---|---|
| SR-12a-1 | **Accept.** 19 step names; text fixes at close (A12-27, X-5, TC-B100-66). |
| SR-12a-2 | **Accept** the `_busy_tick` guard (`query_one_optional` → return); R-7 is corrected at close. |
| SR-12a-3 | **Accept.** Both arms of the `project.json` lstat gate paint the `unreadable` pair, as on base; proto-12a-sweep :178 corrected at close. |
| F-8 | **Already fixed** on b100-inc11 (Inc 11 corrective CI9b-1, 24f779f); it reaches this branch with the merge of b100-inc11. |
| O-12a-1 | **Route to the E5 security review** (U+202E reaches the file-state line and the `Loaded <name>` outcome through `safe_text` only, as on base). |
