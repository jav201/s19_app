# Inc 12b — E2 orchestrator rulings (after the baseline)

| Id | Ruling | Design effect |
|---|---|---|
| Q-a1 … Q-h1, 12a carry-overs | As in `codewire/interfaces-12b.md` §Orchestrator rulings. | interfaces fixed |
| Census | The real figures are 184 direct call sites in 26 files and 1 no-app test (`test_tui_app.py:85`), plus the 4 sync helpers (50 tests behind them). Correct E1. | scope; tester |
| Vacuous timing | Only `test_b100_document.py::test_tc_b100_30_…under_one_second` becomes vacuous. Re-pin it to measure from trigger to outcome with polling, as `test_b100_active_variant.py:687` does. | tester |
| LLR-177.3e | The threshold includes `save_doc` and `execute_scope`, which the guard refuses too. | draft |
| Base commit writes | `_report_filter_path`, `_variant_set` and `current_file.variant_id` are written inside the rollback `try`, and the manifest writer reads `_variant_set` back. G-B must carry all of them through the immutable request and the main-thread commit, not only the verify result. | G-B |
| Re-pins missed by E1 | `_abort_save`'s `_variant_set` AST pin, `test_no_new_parse_loaded_file_call_sites`, the manifest-writer pins, and the one-argument `parse_a2l_file` fakes are added to the re-pin list. | scope; tester |
| Groups for the prototypes | Two agents. P-1 is G-A + G-B in app.py (project load and Save worker). P-2 is G-C + G-D (A2L attach, busy refusal and its 17 + 4 entry points, quit; a2l.py's progress callback). Seams between them are listed by id. | E2 |
| P2-1 | **Accept.** Remove `_finish_session_action`, `_fail_session_action` and `final_line` from interfaces S-c/S-g. End sites call `end_busy` / `_busy_fail` directly as their last statement, and the quit check lives inside `end_busy` (12a A12a-06/07 bind). | interfaces (E3 design-fix) |
| P2-2 | **Accept.** Add a keyword-only `sync_project: bool = True` to `_start_load_worker`; the work-area pick passes False, so LLR-177.1k holds. | interfaces; G-C |
| P2-3 | **Accept.** Add a private, empty `_QuitQuestionScreen(ConfirmQuestionScreen)` subclass in app.py. | G-C |
| P2-4 | **Accept: one distinct group per busy key, not exclusive.** The busy refusal already prevents a second run, and no canceller owes an `end_busy`. This supersedes the 12a S12a-05 wording for 12b. P-1 does the same. | interfaces; P-1 |
| P2-5 | **Accept.** The two JSON-editor results and the two `LoadGuardScreen` accept paths also run the busy check. JSON the user typed is dropped with the busy line shown. | G-C; draft LLR-177.3e |
| P2-6 | **Accept.** `_confirm_then_load` re-checks busy just before its deferred `go`. | G-C |
| P2-7 | **Accept.** A busy refusal in `load_from_path` leaves `_pending_variant_id` untouched. | G-C |
| P2-8 | **Accept as a note** on AT-B100-17 / LLR-177.5: the bar holds during tag extraction while the spinner and elapsed time keep moving. | draft |
| P2-9 | **Accept.** A failed A2L attach does not record a recent, because recording moves to the install handler. | G-C; draft note |
| P2-10 | **Accept.** The A2L project sync and the focus re-home come before the A2L end. | G-C |
| P-1 PR-1 | **Accept.** `SaveOutcome.toast` becomes `(title, text)`. | interfaces |
| P-1 PR-2 | **Accept.** Add `SaveOutcome.recorded_document`. | interfaces |
| P-1 PR-3 | **Accept.** Drop `SaveOutcome.unrecorded`. | interfaces |
| P-1 PR-4/8 | **Accept** (= P2-1): no `final_line`; end sites call `end_busy` / `_busy_fail` directly. | interfaces |
| P-1 PR-5 | **Accept.** S-d's worker guard is `except BaseException` + re-raise. | interfaces |
| P-1 PR-6 | **Accept.** Retire `_load_a2l_data_with_cache` now and re-pin its 1 test. `load_selected_file` goes to backlog: 88 test calls, and no product caller after 12b. | G-A; backlog |
| P-1 PR-7 / P-2 X12b-06 | **The out-list form wins:** `_parse_loaded_file(…, *, a2l_cache_out=None)`. A tuple return would break 12a's patches and 9 direct test calls. P-2 aligns at the E3 design-fix. | interfaces; P-2 |
| P-1 PR-10 | **Accept.** LLR-177.1f's threshold adds "`current_file.variant_id` equals the opened variant". The worker stamps `image.variant_id` before the merge (F-1). | draft; G-A |
| Worker exclusivity | **P2-4 governs:** one distinct, non-exclusive group per busy key for all three workers. P-1 aligns at the E3 design-fix. | interfaces; P-1 |
