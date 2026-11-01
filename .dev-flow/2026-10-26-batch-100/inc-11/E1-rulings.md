# Inc 11 — E1 orchestrator rulings

The operator delegated every 9b–12b decision to the orchestrator's recommendation (2026-10-31). Rule applied: remove a feature rather than guard it, and stay within the 4-file cap.

| Id | Ruling | Why |
|---|---|---|
| Q1 | **As recommended.** Remove the digest worker, the `computing…` rows and the early `alt+s`. The digests run once per open, after the first frame. The 2 s budget stays as a measured threshold. | P11-1 measures the case_06 A2L digest at 26.1 ms, so a worker guards a cost that does not exist. Removing it is the prefer-removal rule. |
| Q2 | **As recommended.** "The save runs on a worker with real progress" moves to Inc 12a+12b. | The busy seam lands in 12a, so it cannot be built at 11. |
| Q3 | **As recommended.** Add `SaveProjectScreen` to the 9b `check_action` guard. Inc 10 adds its question screen to the same guard. | One condition per modal that 9b–11 own. Guarding every modal could change flow-screen keys that no requirement covers. Revisit at 12a if a third copy appears. |
| Q4 | **As recommended.** Keep the per-variant assignment rows (HLR-017). | Removing them would retire a shipped feature that no verdict item asked to remove. |
| Q5 | **As recommended.** A refused Save is painted in the dialog only, and AT-B100-02 is re-pinned to read `#save_where`. | The verdict surface (pc_B) keeps the reason next to the field the user must change. |
| Q6 | **As recommended.** A Save pressed while the summary is out of date keeps the dialog open and repaints it with `the summary changed` / `check it, then save again`. | HLR-175 says the dialog shows exactly what the save will do, so saving a plan nobody saw breaks that statement. |
| Q7 | **As recommended.** Prefill the open project's name, selected. | This is pc_B. |
| Q8 | **As recommended.** `enter` in the name field saves, behind the same checks. | |
| Q9 | **As recommended.** With nothing loaded, Save project opens no dialog and paints one status line. | Removes a dialog that can only refuse. |
| Q10 | **Accept.** Fix the F5 remainder at Inc 11 and add `project_gather_service.py` as the 4th source file, at the cap. R2-2 closes through the one preparation function. | Today the plan can say `new changes.json` while the save writes `changes_1.json`. That breaks HLR-175 on the very surface Inc 11 ships. |
| Q11 | **As recommended,** all four alignments. For "image kind with no emitter", the E2 probe decides: if it cannot be reached, remove the row instead of adding a next step. | Token table hygiene, and prefer removal. |

**Size watch.** Inc 11 is the largest increment left: 52 requirements, and the guard-and-plan half of `_handle_save_dialog` (about 440 lines) moves into `_prepare_project_save`. E2 runs as two groups:
- G-A: `screens.py` + `styles.tcss`;
- G-B: `app.py` + `project_gather_service.py`.

LLR-175.4l (58 direct test calls kept green) is the guard on the split.

**Sequencing.** E2 starts after 9b's E3 settles `check_action`, and after Inc 10's E2 fixes its edits to the same function.
