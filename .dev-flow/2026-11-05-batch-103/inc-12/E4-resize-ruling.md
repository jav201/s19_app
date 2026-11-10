# Inc 12 — resize implementation ruling

Orchestrator: Kimi, 2026-11-09. No requirement or interface changes.

## Evidence

The in-place resize path was not deterministic. Across repeated 220→80→220 runs, the stored Tag cell was correct while `render_line` intermittently retained the old narrow form. `DataTable._render_cell` independently returned the full new text, proving the defect was in the composed-line path rather than the expected string or the name-width formula.

The runner summary was measured, not guessed: 5/10 then 4/10 failures, with stored and painted state captured. `DataTable.notify_style_update()` alone did not eliminate it.

## Ruling

When `_fit_a2l_tag_cells` finds a Tag cell different from the measured width, rebuild the page through `update_a2l_tags_view` and restore cursor and scroll, using the already measured E2 approach. Keep in-place `_repaint_a2l_tag_cells` for image writes and for cache invalidation after those writes. The requirements, I-12.1 cell tuple, name-width formula and no-new-app-state contract are unchanged. Row highlight events are an accepted cost of the rebuild; cursor position and the detail card's tag must remain correct.

## Verification

`evidence-e4-resize-rebuild-x10.txt`: **10/10 passed** on the same base. The full 112-node suite and the 20-arm mutant table run on commit `25dd5661` and are recorded separately.
