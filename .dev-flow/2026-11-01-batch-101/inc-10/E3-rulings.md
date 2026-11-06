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
