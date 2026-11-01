# Inc 9b — E2 orchestrator rulings (operator review of Q2/Q8, and E2 findings)

Operator, 2026-10-31: Q2 → **remove problems from the project preview**; Q8 → **defer the labels to Inc 12a** (as ruled). The operator delegates every further 9b–12b decision to the orchestrator's recommendation ("decisions: take them with your recommendations").

| Id | Ruling | Design effect |
|---|---|---|
| Q2 (operator) | The project preview shows no problems: no `check_project_files` and no image hashing on a highlight. Problems are still shown by the Load-result panel after Enter (HLR-178). | Remove LLR-173.6g. If every remaining preview step (variant set, manifest, damaged check, install set, sub-folders) reads only metadata and the bounded `project.json`, then the project preview is synchronous like the other kinds: remove the worker `_project_preview_worker`, LLR-173.6h (worker) and LLR-173.6j (150 ms rest timer); keep the generation check in `show_preview` (cheap, and robust to a re-entrant `deliver`). If any step reads image contents, drop that step from the preview instead of keeping a worker. The design-fix agent verifies this against the code and records which branch applied. |
| PSC-1 | **Accept**: `s19_app/tui/__init__.py` is the 4th source file (at the cap of 4). Remove the two re-exports and export `LoadDialog` and `LoadChoice`. | slice + cap table |
| F-1 | **Retire LLR-171.2e**, superseded by LLR-173.4a (Q7): an empty folder is no longer a listed project. Re-pin TC-B100-32 `[no project.json]` to the new behaviour (not listed; typed → `not a project`). Re-pin the other 4 census tests the same way. | LLR-171.2e marked retired with a pointer to LLR-173.4a; ledger names both |
| F-2 | **Accept LLR-173.4m**: If the project list cannot be read, then the dialog shows the `could not be read` token line in the projects section and the other sections still load. | new LLR |
| F-12 | **Accept as a 9b fix** (pre-existing, MAJOR candidate, in the router 9b owns): new LLR-173.1g. If the picked project cannot be read (`OSError`), then the system paints 1 status line with `could not be read`, keeps the session unchanged, and does not crash. | new LLR + test arm |
| B-2 (baseline surprise 2) | G1 `_load_workarea_file` must not reuse `_load_from_item`'s A2L branch that calls `copy_into_workarea`: a pick from the work area loads in place, with 0 copies (LLR-173.1b). | G-B node G1 |
| B-3 (baseline surprise 3) | Five modals share `id="load_dialog"`. The new dialog's outer container is **`#load_box`**, and C1 targets only `#load_box`. The other modals keep `#load_dialog` unchanged. | interfaces + G-A C1 |
| P-1, P-2, P-3, V-1, H-1 | **Confirmed** as written in `proto-9b-app.md` (lines ~406–416), except that P-2 falls away if Q2's synchronous branch applies. Added to `interfaces-9b.md`. | interfaces |
| `_closed` clash (G-A probe) | Confirmed: the attribute is `_dismissed`. | as drafted |
