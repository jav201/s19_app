# Inc 11 — E2 orchestrator rulings (after the baseline)

| Id | Ruling | Design effect |
|---|---|---|
| Q-1 … Q-6, split, guard | As in `codewire/interfaces-11.md` §Orchestrator rulings. | interfaces fixed |
| LLR-175.1n | **Withdraw** it and its token row (ruling Q11: prefer removal). It cannot be reached: a MAC-only session's entries are `skipped-outside`, never blocked. A save that says nothing about skipped entries goes to backlog (Inc 12a sweep). | draft (Retired entry), scope |
| Direct calls | The count is 56 call lines plus 1 call by reference. Correct E1. | scope |
| Prefill re-pins | AT-B100-02's `a b` arm and AT-B100-03 are re-pinned because of the prefill (Q7). Census rows D (9 acceptance drives, they wait for the recompute) and C (`test_tc304`, `test_tc306`) are re-pinned to wait one recompute. Re-pin B (`test_b99_staging` ×6) and A (3 constructor tests). TC-B100-07 is re-pinned because the commit moves. TC-B100-09 is re-pinned for `_save_session`. | scope test notes; tester |
| Modal count | Eight modals carry `#load_dialog`, not five. Text fix. | text |
| G-B P-1 | **Accept.** Add `_SaveSession.inventory: Optional[ProjectInventory] = None` and a keyword-only `inventory=None` on `_plan_project_save`. | interfaces (orchestrator edit at E3 design-fix) |
| G-B P-2 | **Accept the sentinel.** An explicit `save_as_source=_UNSET` default replaces the implicit convention, which keeps one meaning per argument. | interfaces |
| G-B P-3 | **Accept: a second app attribute, `_save_confirmed: Optional[_PreparedSave]`.** TC-B100-09 classifies it. | interfaces |
| G-B P-4 | **Accept.** `_PreparedSave.active_variant: Optional[str] = None`. | interfaces |
| G-B P-5 | **Accept as a new unwanted LLR,** numbered by the design-fix: a work area that cannot be listed paints the LLR-175.1g token pair inside the dialog and does not crash. | draft |
| G-B P-6 | **Accept.** Re-pin the LLR-175.4g and LLR-175.4j arms to a top-level file of the open project. | draft |
| G-B F-4 | **Backlog** (Inc 12a sweep): the file-backed document's landing is not checked at commit. | backlog note |
| G-B Q10 follow-ons | **Accepted** as designed: the 3 edits in the commit half. | — |
| G-A P-GA11-1 | **Accept the TYPE_CHECKING import** of `project_gather_service`. **Reject `import time`:** the 150 ms recompute is a debounce on `set_timer`, where each keystroke resets the timer. It needs no clock and adds no module, so TC-B100-64 is unchanged. The threshold "20 keystrokes → ≤ 3 recomputes" holds with a debounce. | G-A |
| G-A P-GA11-2 | **Accept.** LLR-175.4h's negative control becomes "both `#save_summary` and `#save_box` unbounded → `#save_ok` off screen", and the threshold reads "fully visible". | draft |
| G-A P-GA11-3 | **Accept.** S-h's fixed text reads: `confirm` keeps the painted plan object, so the router's `is` check holds. | interfaces |
| G-A P-GA11-4 | **The one scrub stays in G-B** (`painted_names`); G-A paints literally, with markup off and `Text` prompts. No double scrub. | — |
| R-GA11-3 | **Declared.** The jump from 2 to 300 rows takes about 360 ms to mount. E5 measures it, and a row pool local to `_paint` is the fix only if a test arm needs that jump inside 300 ms. | risks |
| Parent folder | E3 confirms that G-B builds the target as work area / folder name and never from a resolved or re-cased parent. | E3 check |
