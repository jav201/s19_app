# Inc 10 — E1 orchestrator rulings

The operator has delegated all 9b–12b decisions to the orchestrator's recommendation (2026-10-31: "decisions: take them with your recommendations"). The rule applied to every question: remove a feature rather than guard it, and stay within the 4-file cap.

| Id | Ruling | Why |
|---|---|---|
| Q1 | **As recommended.** A project load leaves the Flow Builder as it is, and the question says the flow "has unsaved changes". | The probe shows the builder survives a project load, so the old "lost" wording was false. Clearing the builder would add a behaviour and a requirement for no verdict item. |
| Q2 | **As recommended.** Remove the interim `Closed the Patch Editor document (N entries)…` line and re-pin its tests. | The question replaces it, and the line was false for a saved document. |
| Q3 | **As recommended.** Cancel paints 0 status lines. | HLR-174c's threshold already says so. The dialog closing is the feedback. |
| Q4 | **As recommended.** `ctrl+l/s/k/d` do nothing while the question is open: one more screen type in the 9b `check_action` guard (LLR-174.2h). | This is the same exposure 9b closed for the Load dialog. One condition in a file Inc 10 owns. |
| Q5 | **As recommended.** The panel `v` route gets a TC arm that forces the unsaved state. AT-B100-15 covers the three routes reachable by keys. | That route is unreachable by keys (probe: D = False after a project load). An AT cannot reach it, but a forced-state TC still proves the guard. |
| Q6 | **As recommended.** Add a public `PatchEditorPanel.is_dirty` property in `screens_directionb.py`. Move the private read at `app.py` `_handle_save_dialog` (`panel._dirty`) to it (LLR-174.1c). | Closes P-43. With `screens_directionb.py`, `screens.py`, `app.py` and `styles.tcss`, the slice is 4 files, at the cap. |
| Q7 | **As recommended.** Unload over a patched image is out of scope. Open a BACKLOG-CODE row at the Inc 10 close, with target Inc 12a's backlog sweep. | HLR-174 names load routes, and unload is not one. |
| Q8 | **As recommended.** The Flow Execution panel's unsaved flow sets are out of scope. Open a backlog row as for Q7. | Same reason as Q7. |

**Sequencing.** E2 runs after 9b's E3 settles `interfaces-9b.md`, because Inc 10 hooks into the 9b router `_handle_load_dialog` and `_load_workarea_file`. The baseline is drawn from main (`8947666`) plus the 9b interfaces. Inc 10's prototype groups are G-A (`screens.py` question modal, `styles.tcss`, `screens_directionb.py` `is_dirty`) and G-B (`app.py`).
