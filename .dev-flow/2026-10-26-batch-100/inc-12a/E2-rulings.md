# Inc 12a — E2 orchestrator rulings (after the baseline)

| Id | Ruling | Design effect |
|---|---|---|
| Q-1 … Q-7, outcome | As in `codewire/interfaces-12a.md` §Orchestrator rulings. | interfaces fixed |
| §D.3 re-pins | The progress re-pins are the census rows A (11), B (6 + 29 SVG) and C (1), not E1's single row. Correct §D.3. | scope / tester |
| Diff report | The diff report gains one status-log line at its end. It is added to HLR-176c's 14-arm threshold. | draft |
| B5 | Rationale corrected: 9b keeps the A2L copy (A9b-05). The pick-time re-check matters mainly for data files. It is a status line after the dialog closes, never a `#load_reason` token, because the 9b verdict makes no filesystem call for a work-area choice. | draft LLR-172.6b/.6c text |
| LLR-172.5i | Only the relative NUL arm is RED on base. Keep the absolute arms as regression arms and say so. | draft |
| B9 | Close it as not a defect; the problem's real name is `no digests saved`. | scope |
| Census not executed | Reads of `#status_text` while a worker runs are owed at E4 (tester) or the batch-end battery. | tester note |
| G-B P-B1 | **Accept.** Keep the trick of making `app.py` see `os.name` as `posix`, so the Linux arm of LLR-172.4e runs on Windows. Drop the "not run on Windows" declaration. | tester |
| G-B P-B2 | **Accept.** LLR-173.2m's threshold no longer claims that `q Quit` returns at 80 columns (measured: it does not). | draft |
| G-B P-B3 | **Accept: leave them.** The two 9b dialog literals stay outside LLR-172.5k's census (Q-7). | — |
| G-B P-B4 | **Accept.** Re-pin all three rows of `test_at_b78_32`. Record that it was RED on base before 12a (a known CI failure). | tester; packet |
| G-A P-1 | **Accept** the two private helpers `_busy_fail(key, gen)` and `_paint_status_text`. They are internal; the fixed seam is unchanged. | G-A |
| G-A P-2 | **Accept.** HLR-176b's threshold reads "50 at the step's start, then 62, 75, 87, 100", matching LLR-176.1c. | draft |
| G-A P-3 | **Accept.** The one rule is `#workspace_status_bar #status_text.-busy { color: $accent-calm; text-wrap: nowrap; }`, so LLR-176.1's 200-character line shows `…`. | interfaces Q-6 text |
| G-A P-4 | **Accept.** When an action ends while another runs, its `final_line` becomes the pending text, so LLR-178.2 holds (A12-70 becomes a pass). | G-A |
| G-A P-5 | **Accept.** Re-pin `test_tui_app.py::test_save_project_writes_under_workarea` inside `run_test`. | census |
| G-A P-6 | **Accept.** A begin from idle resets the spinner frame to 0. | G-A |
| G-A P-7 | **Accept.** S-e's wording: `load_from_path`'s guard is `except BaseException` plus re-raise, not `finally`. | interfaces S-e |
| 80×24 | **Declared risk.** At 80×24 the elapsed time can fall off a long line. | risks |
