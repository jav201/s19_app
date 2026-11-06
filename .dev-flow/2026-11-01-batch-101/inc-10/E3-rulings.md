# Inc 10 — E3 rulings (orchestrator, 2026-11-06)

Round 1: `E3-architect.md` **FAIL** (1 HIGH, 3 MAJOR, 10 MINOR); `E3-security.md` **FAIL — BLOCK-UNTIL S-1, S-2, S-3** (3 HIGH, 2 MAJOR, 3 MINOR). Both probed on the LAN host at `98d94d7`.

## Split (skill E0: split along boundaries the user can see)

With the new rows the findings require, Inc 10 outgrows one focused pass (23 rows → ~30, 19 functions → ~28, 71 cases → ~90). It is split in two, both in `app.py` and served serially (10a, then 10b):

- **Inc 10a — navigation, unload state and focus:** F-07, D4-6, F-13, D5-27, D5-19, F-14, D6-21, SE5-12a-2, and the findings A10-01 … A10-03, A10-05 … A10-07, A10-10, A10-11, A10-13, S-2, S-3, S-4, S-5.
- **Inc 10b — what is painted stays current after an in-place write:** the D-4 rows (A2L explorer value column, a displayed Split/Join window), S-1 (main, A2L and MAC hex panes), A10-04, A10-08, A10-09, A10-12, A10-14, S-7, S-8. It goes through Inc 5's in-place-write hook (extended by Inc 6) and never calls `refresh_window`.

The records keep Inc 10's folder for 10a; 10b gets its own folder `inc-10b/` with the rows, cases, slice and graph moved there (ids unchanged).

## Rulings

| Finding | Part | Ruling | Why |
|---|---|---|---|
| A10-01 (HIGH) = S-4 (MAJOR) | 10a | Accept: the focus lands after the shown window is laid out, and only if the focus has not moved since the key; R-SHELL-FOCUS.3 gains "or is removed"; same rule in #13 (c). | The target has no screen area before the refresh; the probe lands on the rail item 4/4. |
| S-2 (HIGH) | 10a | **Withdraw ruling D-5.** After a primary unload, Save project writes no unloaded image into the project and the load question does not name it; the spine is MAC-only without the old path. New row + negative case. | The probe shows the unloaded image written into the project — a wrong saved file. |
| S-3 (HIGH) | 10a | Accept: negative cases for a hidden window's action (`a e` on a hidden Workspace; Enter on a hidden Patch Editor button after a rail key), and `check_action` refuses while the owning window is hidden. | The base writes 4 split files from a hidden window. |
| S-5 (MAJOR) | 10a | Accept: `set_file_status` strips format (Cf) characters from every painted file-derived name, so the project-load line is covered too. | U+202E still reaches the status text by that path. |
| A10-02, A10-03 (MAJOR) | 10a | Accept: the page-floor clamp is kept only where the rows say so (near the image end the target row is still shown as the row states); start indices count the rows the renderer shows, MAC records outside the image included; A2L/MAC jumps snap to a present row; a failed go-to keeps the viewport. | The rows must match what the renderer paints. |
| S-1 (HIGH) | 10b | Accept: new row — after an in-place write the main, A2L and MAC hex panes re-render with their window and marker kept. | The probe paints FF where the image holds AA; after the A2L fix its Raw cell and its own hex pane would disagree. |
| A10-04 (MAJOR) | 10b | Accept: the A2L repaint keeps the cursor row and scroll (no table clear); the summary index reset repaints (S-8); R-A2L-049 holds with a value filter. | The probe resets cursor/scroll 40/30 → 0/0. |
| S-7, A10-09 | 10b | Accept: an armed export confirm is disarmed by an in-place write. | A confirm armed before a write would export bytes the operator did not see. |
| A10-08, A10-12, A10-14 | 10b | Fold: notices appended after Inc 6's early `return`; measure the A2L refresh cost on a large A2L (QC-TM); retire the stale `conflict` coverage. | One-line edits or a measured bound. |
| A10-05 … A10-07, A10-10, A10-11, A10-13 | 10a | Fold: first row shown first; the project-load line's raw names and the 120-char clip recorded; MAC diagnostics kept on a primary unload; every planned test waits on product state; the census of 69 test files of non-key callers; an 80×24 case. | Minors. |
| S-6 | — | Backlog: Cf characters in the Loaded panel, the save line and the log. | Outside both slices. |

Correction: one Opus design pass (it splits the records and writes new rows — E1/E2-level work); then round 2 per part (architect + security, only the blocking findings).

## Round 2 (2026-11-06)

Architect: **10a PASS-WITH-NOTES, 10b PASS-WITH-NOTES** (A10-01 … A10-04 closed; sizes 10a 3 files / 36 nodes / 26 rows, 10b 2 files / 17 nodes / 10 rows). Security: **10b PASS**; **10a FAIL** on one new MAJOR (R2-1). Rulings:

- **SR2-1 (MAJOR, 10a):** accept — `action_export` of Split/Join refuses while its window is hidden (the Enter on the EXPORT button bypasses `check_action`); new case R-SEG-OPEN.7/4. Security re-checks only this.
- **SR2-2 (MINOR, 10a):** case R-SHELL-FOCUS.2/6 is built so the synchronous focus clear decides it (the landing must not run first); E4 addendum with AR2-3.
- **AR2-1 … AR2-6 (MINOR, 10a):** fold — test `focus is not trigger` (Textual moves focus synchronously in `_prune`); stamp each landing with its switch so a stale one cannot fall back to the rail item; case /6 rebuilt to fail reliably; re-showing the shown window does not move focus; a load or MAC change re-anchors the window (widens D4-14); main-view marker clause gains "not None", view rows sorted once.
- **AR2-7 (MINOR, 10b):** fold in inc-10b — the A2L repaint uses `update_width=True` where a value can widen, and imports `Coordinate`.
- **Interfaces:** name the shared `segment_split_view.py` in both parts' interface lists.

Correction: DeepSeek v4 Pro, targeted edits only (the operator's 2026-11-06 reminder: DeepSeek where pertinent; Opus reviews behind it). Then the security reviewer re-checks SR2-1.

## Round 3 (2026-11-06)

Security re-check: SR2-1 and SR2-2 **closed** (`action_export` is the only caller of the write; its hidden-window guard covers the `e` key, Enter or click on EXPORT and the key-bar token). New **R3-1 (MAJOR, case only):** R-SEG-OPEN.7/4 could not fail (no row ticked, so the base stops at "nothing selected"). Fixed by the orchestrator in `02-test-cases.md`: the precondition ticks every row with `a` and asserts the ticks before the trigger. No design change. **E3 closed for 10a and 10b.**
