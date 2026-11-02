# Code Review — Increment 021 (batch-100 Inc 12a, stage E5)

**Verdict: PASS-WITH-NOTES**: 0 HIGH · 0 MAJOR · 2 MINOR · 1 NIT. No finding blocks the increment.

Reviewer role: code-reviewer (correctness, simplicity, reuse, conformance to the approved design and to the file conventions). I worked on my own and reviewed read-only. The source tree was not edited.

## Scope reviewed

- Tree `<HOME>/Github/s19_app-b100-inc12a`, branch `b100-inc12a` at `71376a3`. That commit merges `b100-inc11` at `7ac9674`. The working-tree `s19_app/` matches HEAD.
- Diff: `git diff b100-inc11..b100-inc12a -- s19_app tests`. That is 16 files. `git diff -w` on the source is `app.py` +654/-174 and `styles.tcss` +8. I read the whole `-w` source diff, plus the seam functions in the merged tree (`app.py:19833`–`:20096`) and the full post-merge bodies of `_commit_project_save` (`:11197`–`:12031`), `_handle_load_project` (`:13326`–`:13472`), `load_from_path`, `load_a2l_from_path`, `_load_workarea_file` and the 4 workers.
- Tests: I read the new tests in `tests/test_b100_busy.py` (exception rule, action table, census, AST rules) and the re-pins in `test_report_progress.py` and `test_tui_app.py`, and sampled the sweep tests in `test_b100_recents.py`. I did not review the other test files line by line.
- Design checked against: `inc-12a/codewire/interfaces-12a.md` (fixed, Q-1…Q-7), `proto-12a-indicator.md` (the Save step list at `:436`–`:455`), `E2-rulings.md` (P-3), `E3-rulings.md` (rounds 1 and 2), `E4-impl-notes.md`, and `E4-integration-notes.md` (SR-12a-1…3, D-1…D-8).

## Findings

| Id | Sev | Tag | Where | Defect | Evidence | Fix |
|---|---|---|---|---|---|---|
| CR12a-1 | MINOR | design-gap | `app.py:11858`–`:12021` (the `tail` list), `:12030`–`:12031` (the `finally`); design `proto-12a-indicator.md:447`–`:448` (steps 7–8) | **A raise after the save is committed logs `Saving project <name> failed`, and the `Saved project to …` line is lost.** Step 7 collects the whole committed tail into `tail` and paints it only at the end. That end comes after the document re-bind and the Patch Editor panel block (`:11920`–`:12010`), which run after `project.json` is on disk. If anything in that block raises, the `finally` ends the run with `<label> failed`, even though the save is done (R2-3: it is not rolled back). On base, `Saved project to …` was painted before that block. Scenario: case_01 `firmware.s19` loaded, Save `S4`, and `_save_clears_panel_flag` (`:11990`) raises. The log gains `['Project saved + manifest verified', 'Saving project S4 failed']`, `S4/project.json` exists, and no `Saved project to …` line is written. At 12a the re-raise ends the app, so the cost is one misleading line and one lost line. It matters more once 12b keeps the app running. | Probe **executed**: `rev12a-code-reviewer/probe2.py` printed `log since: ['Project saved + manifest verified', 'Saving project S4 failed']`, `project.json on disk: True` | Smallest option: declare it in the batch risks and in 12b's seam notes. Behavioural option: set a local `failure_text` once the manifest write returns, for example `f"Saved project to {project_dir} — finishing the save failed"`. The `finally` then calls `end_busy("save_project", gen, failure_text)` when it is set, and `_busy_fail` otherwise. One local, no new seam function. |
| CR12a-2 | MINOR | design-gap | `_commit_project_save`: the 10 abort exits `:11326`, `:11352`, `:11432`, `:11458`, `:11493`, `:11670`, `:11746`, `:11763`, `:11783`, `:11801` | **Only 1 of the 10 hand-converted Save abort exits has a test that pins its own outcome.** Each exit swapped its `set_status(<text>)` for `end_busy("save_project", gen, <text>)` by hand. If one were reverted, or a future arm used `set_status`, the run would stay open until the `finally`. The log would then end with an extra `Saving project <name> failed` after the rollback notes, and the arm's own text would no longer be the outcome. The Inc 12a tests reach the `except OSError` placement arm (`test_tc_b100_51_save_project_ends_once_on_a_placement_failure`, `place_into_workarea` raising ENOSPC) and the SEC-7 raise. The CENSUS AST test (`tests/test_b100_busy.py:1494`) counts only the 24 baseline `set_progress` sites, and Save had none. LLR-176.2c asks for one failure arm per action, so the design threshold is met; the gap is in the design. | By reading: all 10 exits are converted now (the count matches the 10 `set_status` + `return` pairs of `b100-inc11`'s body). Whether an Inc 11 save test would catch a reverted arm through its log assertions is **not-run** (left to the mutant runner) | Add one AST rule to `test_b100_busy.py`: inside `_commit_project_save`, every `return` statement after the begin has an `end_busy("save_project", …)` call earlier in the same block. Or parametrize the placement-failure test over the arms that are cheap to force (`validate_project_files` error, `WorkareaContainmentError`, `WorkareaPlacementError`). |
| CR12a-3 | NIT | impl | `tests/test_report_progress.py::test_report_generation_drives_progress_bar_then_clears_it`, `::test_finish_generate_report_clears_bar` (named drives_progress_bar_to_100 / finish_generate_report_completes_bar when reviewed; renamed by CR12a-3, note added at close) | Both test names still say the bar ends at 100. The re-pinned assertions now require `(0, 100)` at the end (D-2: a report never writes 100). The docstrings explain that the id is kept for traceability, but someone who reads only a failing node id gets the old meaning. | By reading | Leave the ids as they are and add `# id kept; the bar is now cleared at the end` next to each `def`. Or rename both at the batch-end census, if renames are allowed there. |

## Checked and fine

All by reading unless marked as a probe.

- **Every exit of the 7 actions reaches exactly one effective end (S12a-06 / S12a-R2-2).**
  - The 4 workers (`_start_load_worker`, `_start_generate_report_worker`, `_start_diff_report_worker`, `_start_before_after_worker`) each wrap their body in `try … except BaseException: call_from_thread(_busy_fail, key, gen); raise`, with one normal end on each success and refusal exit. No `finally` crosses threads after a success.
  - The file-load kickoff `load_from_path` uses `except BaseException` and not `finally`, which is correct because the worker owns the success end. `copied.stat()` now runs before the worker starts (A12a-08).
  - The main-thread actions (`load_a2l_from_path`, `_handle_load_project`, `_commit_project_save`) end on every `return` and use `finally: _busy_fail(...)`, which does nothing after an effective end. I traced every `return` after each begin: A2L 1, project 1, Save 10. Each one is preceded by its `end_busy`.
  - The SEC-7 `except Exception: _abort_save; raise` arm and the `mkdir` OSError, which sits outside the inner try, both end through the `finally`.
- **Generation and the final log line (A12a-04).** `end_busy` writes a non-empty outcome before the generation check. `_busy_fail` checks the generation first, so a replaced run never logs a `failed` line. Probe **executed** (`probe1.py`): a stale `end_busy("file_load", g1, "old outcome")` returned `False`, logged the line and left the indicator unchanged.
- **Two actions overlapping.**
  - The newest run is shown. A step from a hidden run stores its state and paints nothing.
  - A restart moves its key to the end of `runs`.
  - A non-last end hands back to the newest remaining run, with its stored step, fraction and own elapsed time. Only the last end stops the timer, removes `-busy`, sets the bar to 0 and paints `file_state`.
  - Probe **executed** (`probe1.py`, synthetic runs): `restart moved last: ['report', 'file_load']`, and the hand-back painted `⠋ F2 · step 1/3 c · 00:00`. The last end painted the stored `FS`, with the timer `None`.
- **One stored file-state line (A12a-06).** `set_file_status` always stores `safe_text(str(message)).plain` and paints only when `runs` is empty. It has 2 callers (`_apply_prepared_load`, `_handle_load_project`). The project load stores the project line before its end (deviation 2 is accepted and matches step 8). Nothing else writes `#status_text`: grep finds only `_paint_status_text` and the class add / remove.
- **Widgets written on the main thread only.**
  - Every worker-side `step_busy`, `end_busy`, `_busy_fail`, `_handle_load_error`, `_finish_generate_report` and `panel.set_status` call goes through `call_from_thread`.
  - The nested `report_failed` posts its end. `_log_report_event` writes only to the logger.
  - No worker reads `self._busy`; the generation is passed as a required keyword-only argument (Q-1).
  - Probe **executed**: with a `ModalScreen` on top, `set_progress`, `step_busy`, `set_status` and `end_busy` all succeed, because `App.query_one` resolves through `default_screen`. A worker that ends while a modal is open does not crash.
- **SR-12a-2.** The `_busy_tick` guard (`query_one_optional("#status_text") is None` → return) sits after the empty-runs check, changes no other path, and `query_one_optional` exists in Textual 8.2.8 (`dom.py:1544`).
- **Merge with Inc 11.** The merge hunks `d7b427d..71376a3` are exactly the hunks of Inc 11's corrective pass `051f586..b100-inc11`: the `_SaveSession.image_generation`, router, prepare and session changes. None of them is inside `_commit_project_save`'s body. `git diff b100-inc11..b100-inc12a` shows only the Inc 12a edits in that function.
  - Steps 2, 3 and 4 sit where the design puts them: first statement of the rollback `try`, just before `gather_project_artifacts`, and just before `manifest_previous`.
  - Node `test_tc_b100_51_save_project_reports_its_phases_as_steps` **executed** on the merged tree: `1 passed in 3.85s`.
- **The seam against the fixed interfaces.**
  - `begin_busy`: generation bump, frame reset only when idle, restart, first paint at `00:00`, bar 0, `-busy`, one timer.
  - `step_busy`: clamps `n`, clamps the fraction with `total <= 0` giving 0.0, never lets the fraction fall within a step, and paints and sets the bar only when the run is shown.
  - `_busy_line`: minutes are not capped.
  - `_busy_begin_action`: the one `painted_names` site, and the only caller of `begin_busy` (S12a-04, AST test).
  - The table's 7 rows and 19 step names are confirmed (SR-12a-1).
  - The one CSS rule carries `color: $accent-calm; text-wrap: nowrap;`, as ruled in E2 G-A P-3.
- **Placement of the begins (S-n, A12a-02, A12a-09).** Every refusal paints before its begin. The project begin sits right before `build_variant_set`. `Parse the A2L` is stepped only when the project has an A2L. The report kickoffs leave nothing that can raise between the begin and the dispatch (F-10).
- **One worker group per busy key (S12a-05).** The groups `load`, `generate_report`, `diff_report` and `before_after_report` each serve one key. No other code cancels these groups.
- **G-B sweep.**
  - Labels: `Load` / `Load` / `Projects`. The `#ws_load_project_button` text is unchanged, and no other `"Load file"` literal is painted.
  - `list_projects` drops the platform gate for names that end in a dot or a space.
  - `refresh_files` filters through `recent_kind`, the same comprehension the Load dialog uses (S-h sanctions this).
  - `_listed_project_name` is the one match, and its `OSError` reaches each caller's existing mapping.
  - `_typed_load_route` catches `(OSError, ValueError, RuntimeError)`, which is not narrower than ruled.
  - The 6 project refusals read `_TYPED_REFUSAL_TOKENS` and their text is the same character for character (I checked the table values at `app.py:300`–`:313`). SR-12a-3 is applied.
  - The pick re-check runs inside `go`, after the question (D-6 / S12a-03). The vanish probe falls through on `OSError` (S12a-R2-1). A non-regular entry, a reparse point or a failed `lstat` fails closed. The cap is read through the module when the pick is checked.
- **Tests encode intent.** The new nodes name their requirement, their reason and a negative control. They spy on the seam only to count begins and ends, and they read `#status_text`, the bar, the log and the timers. The exception-rule nodes also check that the exception is re-raised. The EACCES / ENAMETOOLONG arms make the widened catch RED-able.
- **Conventions.** New public functions carry the Summary / Args / Returns / Dependencies docstring sections. The source keeps CRLF on every line (`app.py` 20107/20107, `styles.tcss` 3772/3772).

## Evidence checklist

- ✓ Diff read in full: `-w` source diff, 1576 lines. Merged bodies read at `app.py:11197`–`:12031`, `:13326`–`:13472`, `:14800`–`:14997`, `:15183`–`:15237`, `:17608`–`:17737`, `:19833`–`:20096`.
- ✓ Correctness pass: edge cases, empty values and error paths. Exits traced per action. Probes `probe1.py` and `probe2.py` executed.
- ✓ Simplicity pass: one attribute, one table, one label helper. No premature abstraction found.
- ✓ Reuse and duplication checked: `_listed_project_name` replaces 2 copies. The `recent_kind` comprehension is duplicated once, which the design sanctions (S-h).
- ✓ Tests reviewed for intent: CR12a-2 (a coverage gap) and CR12a-3 (names).
- ✓ Verdict explicit: PASS-WITH-NOTES. No HIGH is open.

## Evidence states

- Probe `probe1.py` (seam behaviour under a modal, overlap, restart, a stale end): **executed**.
- Probe `probe2.py` (raise after the commit in Save): **executed**. It reproduced CR12a-1.
- Node `tests/test_b100_busy.py::test_tc_b100_51_save_project_reports_its_phases_as_steps` on the merged tree: **executed**, passed.
- Whether an Inc 11 test catches a reverted Save abort arm (CR12a-2): **not-run**.
- Full suite and whole modules: **not-run**. The brief forbids them because the host is busy.

Probe files are in `<HOME>/AppData/Local/Temp/claude/C--Users-<USER>-clde/a8feab43-c248-4ccb-86cf-122b894659b2/scratchpad/rev12a-code-reviewer/`.

## Text for the packet's 4b `Independent review` cell

`code-reviewer` · PASS-WITH-NOTES (0 HIGH · 0 MAJOR · 2 MINOR · 1 NIT) · no HIGH raised. CR12a-1: a raise after the save is committed logs `Saving project <name> failed` and loses the `Saved project to …` line (design step 7). Declare it, or switch the failure text once the manifest is written. CR12a-2: 9 of the 10 Save abort exits have no test that pins their own outcome; add an AST rule or arms. CR12a-3: two re-pinned test names still say the bar ends at 100.
