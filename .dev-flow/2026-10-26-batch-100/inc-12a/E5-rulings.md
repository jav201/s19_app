# Inc 12a — E5 rulings

Inputs: review-increment-021.md (code-reviewer, PASS-WITH-NOTES: 2 MINOR, 1 NIT); security-increment-021.md (security-reviewer, PASS-WITH-NOTES: 1 MAJOR, 1 MINOR, 2 NIT); mutation summary (survivors added by the orchestrator when it lands). No re-review: nothing blocked.

| Id | Sev | Tag | Ruling | Done in |
|---|---|---|---|---|
| SE5-12a-1 | MAJOR | design-gap | **Fix.** `_append_log_line` writes `safe_text(message).plain.strip()`, so no log line can carry ESC/C0 from any caller. The LLR-176.1r ESC test asserts on `app.log_lines` (not only `StatusLog` / `#status_text`), and gains an arm that runs on Windows by patching `_format_coexistence_status` to return a name with ESC/BEL (as rev12a-security/probe_esc_log.py does). RED on 71376a3. | corrective |
| SE5-12a-2 | MINOR | design-gap | **Fix the outcome (= O-12a-1).** The 12a outcome line is `f"Loaded {painted_names([path.name])}"`, as A12a-03 does for the A2L outcome; the bidi arm re-adds the outcome assertion. **Backlog** the file-state line (`_format_coexistence_status`, base text, 4 returns) → batch-end / BACKLOG-CODE. | corrective + BACKLOG-CODE |
| SE5-12a-3 | NIT | design-gap | **Fix.** `_listed_project_name` returns the exact listed name first, then the first case-insensitive match. Add an arm (folders `Proj` and `proj` both listed → picking `proj` loads `proj`; skipif the volume is case-insensitive and cannot hold both). | corrective |
| SE5-12a-4 | NIT | design-gap | **Route → Inc 12b** (the loaders' use-time `resolve_input_path` without `try`, after the question; 12b moves these routes onto workers whose failure arm ends the action). | Inc 12b integration |
| CR12a-1 | MINOR | design-gap | **Route → Inc 12b.** A raise after the manifest is on disk logs `Saving project <name> failed` and drops `Saved project to …`. At 12a the re-raise ends the app. Inc 12b's Save worker composes the committed tail on the main thread (S12b-03); its integration must make a post-commit failure keep the committed line. | Inc 12b integration |
| CR12a-2 | MINOR | design-gap | **Decided by the mutants.** If any of the 10 Save abort-exit mutants survives, add one AST rule: in `_commit_project_save`, every `return` after the begin is preceded by an `end_busy` (or arms per exit). | corrective (if survivors) |
| CR12a-3 | NIT | impl | **Fix.** Rename the two re-pinned tests in test_report_progress.py so the names say the bar is cleared at the end (keep a history line). | corrective |

## Done (E5 corrective pass; detail in `E5-corrective-notes.md`)

- **SE5-12a-1** — `app.py:19862`–`:19864` (`_append_log_line` scrubs through `safe_text`). Arms: new `test_b100_busy.py::test_tc_b100_50_control_bytes_never_reach_the_status_log` (runs on Windows; RED on 71376a3, GREEN); `ESC and BEL` arm now asserts on `app.log_lines` + `#log_line_1..4` (Linux only; not-run here).
- **SE5-12a-2** — `app.py:17702` (outcome `Loaded {painted_names([path.name])}`). Arm: `bidi override` arm of `test_tc_b100_50_names_paint_literally_through_load_from_path` asserts the outcome `Loaded fwgpj.s19` (RED, GREEN). File-state line → `.dev-flow/BACKLOG-CODE.md:1612`.
- **SE5-12a-3** — `app.py:13682`–`:13687` (exact listed name first). Arms: `test_b100_recents.py::test_tc_b100_38_one_project_match_prefers_the_exact_listed_name` (RED, GREEN) and `::test_tc_b100_38_picking_proj_loads_proj_when_proj_differs_by_case` (skips on case-insensitive volumes; RED and GREEN executed on a case-sensitive scratch folder).
- **CR12a-3** — `test_report_progress.py:49` `test_report_generation_drives_progress_bar_then_clears_it`, `:157` `test_finish_generate_report_clears_bar` (History lines kept; TC-644 re-bound in `AT-TC-REGISTRY.jsonl`). Rename: no RED owed; GREEN.
- **MERGE-12a-1** (coordinator row: 2 failures in `green-03-merged.txt`) — `tests/test_b100_save_dialog.py:3792`–`:3797`: `test_tc_b100_65_a_load_landing_under_the_dialog_rebuilds_the_session` called `_start_load_worker(loaded)` without the keyword-only `gen` that 12a added, so it raised `TypeError`. Re-pinned to `gen = app._busy_begin_action("file_load", loaded.name)` + `_start_load_worker(loaded, gen=gen)`, which is the hand-off `load_from_path` makes. The arm still proves the same thing. Re-pin: no RED owed. GREEN `[same_ranges]` + `[other_ranges]`: 2 passed (`evidence/inc-12a/green-06-merge-repin.txt`).

### Round 2 — mutation survivors (evidence/inc-12a/mutation-summary.md: 86 killed / 22 survived)

Each kill was proved by applying the mutant to the scratch copy `scratchpad/corr12a/mutk` (never the worktree), running the killing node(s), and restoring the file by sha. Transcripts: `evidence/inc-12a/mut-r2-M-NN.txt`. Source unchanged in round 2; tests only.

- **MUT12a-CR12a-2 (M-69, M-70)** — AST rule `test_b100_busy.py:2462` `test_tc_b100_51_every_save_abort_return_ends_its_run_first` (helper `_commit_save_body_returns` `:2421`): every `return` after the begin in `_commit_project_save` has an `end_busy("save_project", …)` earlier in its own block (10 today). Behavioural arm `:2479` `test_tc_b100_51_save_validation_abort_ends_with_its_own_line` drives the validation-error abort exit. RED proofs: M-69b (that exit's `end_busy` line removed) → AST rule FAILED, listing `(11335, False)`. M-69 (`end_busy` → `set_status`) → both arms FAILED; the extra end is `Saving project S5 failed`. M-70 (`tail[0]`) is KILLED by the existing `test_b100_save_guards.py::test_tc_b100_07_manifest_mismatch_is_the_newest_status_line` (the mutation run never ran that node).
- **MUT12a-M-09** — `:2284` `test_tc_b100_50_a_restarted_key_becomes_the_newest_run`. KILLED (the restarted report's step stays hidden).
- **MUT12a-M-20** — `:2315` `test_tc_b100_50_a_falling_amount_never_lowers_the_bar`. KILLED (`[50, 20, 80]`).
- **MUT12a-M-28** — `:2335` `test_tc_b100_50_ending_a_middle_run_shows_the_newest_remaining`. KILLED (the oldest run, R, is shown).
- **MUT12a-M-31** — `:2361` `test_tc_b100_50_a_begin_after_the_last_end_starts_one_timer`. KILLED (0 running timers).
- **MUT12a-M-44** — observable, so not equivalent: a restarted key's stale `_busy_fail` logs `Loading b.s19 failed`. Arm `:2394` `test_tc_b100_50_a_stale_failure_logs_nothing`. KILLED.
- **MUT12a-M-79** — no new arm needed. The existing `test_tc_b100_51_file_load_ends_once_on_success` (it loads `x.txt`) KILLS it with `refused_begins == 1`; the mutation run had named only the containment-refusal node. The listed-row half of LLR-172.4f is M-94 (KILLED).
- **MUT12a-M-82** — AST check `:2520` `test_tc_b100_51_file_load_reads_the_copy_size_before_the_worker` (one function, `load_from_path`). KILLED.
- **MUT12a-M-89** — `:2549` `test_tc_b100_51_file_load_into_an_open_project_ends_after_the_sync`, with project P open. KILLED (`Loaded other.s19` lands before the sync lines).
- **MUT12a-M-101** — `test_b100_recents.py:3918` `test_tc_b100_39_pick_of_a_vanished_entry_asks_nothing`. KILLED (a question opens for the vanished file). Note: the mutant is the PRE-question look. By design (F-11 / 9b B88) a vanished entry loads nothing *silently*, both before and after the question, so this arm pins "no question, 0 lines". It does not pin a refusal line: that would change the ruled behaviour.
- **MUT12a-M-102** — `:3965` `test_tc_b100_39_pick_survives_an_error_at_the_first_look` (OSError at the first lstat only → the file loads). KILLED.
- **MUT12a-M-105** — `:4017` `test_tc_b100_39_pick_of_a_reparse_point_file_is_refused` (`_is_reparse_point` True on a regular file → refused). KILLED.
- **Accepted as equivalent:** M-08, M-17, M-19, M-36, M-58, M-77, M-86, for the reasons in mutation-summary.md. **Not-run here, accepted:** M-25 and M-48 (the ESC/BEL arm, Linux CI only, S12a-R2-3).

| MUT12a-M-101 (orchestrator) | **Accept the corrective reading.** The surviving mutant was the pre-question check; the design (F-11 / 9b B88) says a vanished pick loads nothing silently. The arm pins "no question, 0 status lines, 0 parses". No source change. | — |
