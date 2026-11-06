# Inc 10b — E1 rulings (split from Inc 10 at E3)

History: Inc 10 was split at E3 (`../inc-10/E3-rulings.md`, split section). The E1 decisions that 10b inherits are in `../inc-10/E1-rulings.md`: §3 (D-4 (a) and (b) reproduced), §5 D-4 (repaint at the write) and D-6 (Split / Join re-plans only while displayed), and the orchestrator's D-4 check ruling. The E3 rulings 10b applies are S-1, A10-04, S-8, S-7 / A10-09, A10-08, A10-12 (`../inc-10/E3-rulings.md`). A10-14, which that table lists under 10b, concerns case R-SHELL-FOCUS.2/4 and is applied in Inc 10a, where the case lives.

## 1. Scope and what the operator can notice

In: D-4 (a) A2L tag table values, D-4 (b) a displayed Split / Join preview, E3 S-1 (main, A2L and MAC hex panes), A10-04 (table position kept), S-7 / A10-09 (confirm disarmed). Moved from Inc 10 with ids and text unchanged: US-FRESH-3 (widened), R-A2L-048, R-A2L-049 (threshold amended), R-SEG-PREV.21, R-SEG-PREV.22, cases R-A2L-048/1–3, R-A2L-049/1, R-SEG-PREV.21/1–2, R-SEG-PREV.22/1. Case R-SEG-OPEN.6/3 (a write while Split / Join is hidden) stays in Inc 10a with its row; it is re-run at 10b's E5.

No layout changes. What changes on screen after an apply, a save-back or a Save project commit: the A2L Raw / Physical cells show the written values with the table's scroll, cursor and listed tags unchanged (with a Raw or Physical filter, a row whose new value no longer matches stays listed until the filter is edited); the three hex panes show the written bytes with their window, scroll and `> ` marker unchanged; a displayed Split / Join preview re-plans; an armed export confirm is disarmed (`— e will ask`).

## 2. Changes to canon rows (forwarded to the requirements session)

| Id | Change | Reason |
|---|---|---|
| R-A2L-049 | new at Inc 10; threshold amended (first shown row defined; filter on Raw included) | E3 A10-04 |
| New: R-A2L-105, R-A2L-106, R-TUI-004.7, R-TUI-004.8, R-TUI-004.9, R-SEG-EXP.15 | new; ids grepped free in `REQUIREMENTS.md`, `docs/`, `s19w/review` and every `inc-*` record of this batch on its branch (b101-inc2 … b101-inc16, b101-canon, b101-p0) | E3 S-1, A10-04, S-7 / A10-09. R-A2L-050 is taken (conversion status), so the table rows take 105, 106 beside the row-selection block (R-A2L-100 … 104) |
| Definitions | CTX-A2L: *first shown row*; CTX-HEX: *shown window*; *in-place write* scope also covers S4 | rows cite them |

## 3. Decisions

- **D-10b-1 — the tag table is repainted in place, not cleared (A10-04).** Alternatives: (a) clear and refill, then restore the cursor (`move_cursor`) and the scroll (`scroll_to`) — two restores that must follow the async table refresh, and a `RowHighlighted` that re-shows the card; (b) **chosen:** update the shown page's cells in place (`DataTable.update_cell_at`) and re-point the row keys to the recomputed tags; no `clear()`, so the cursor, the scroll and the card stay. Consequence: the shown tags are the same tags in the same order (R-A2L-106); the filter is not re-run at a write, only on its next edit.
- **D-10b-2 — the hex panes re-render from their kept window (S-1).** The main view renders without a focus (10a's single clamp keeps `_hex_window_start`, A10-02); the A2L and MAC views render with `start_row` = the index of their first shown row in the view rows (I-3); no scroll reset, no marker change. A hidden view is re-rendered too (one page of a Static), so the next show is current.
- **D-10b-3 — S-8: the A2L summary is repainted after the recompute; no row.** `_compute_a2l_enriched_tags` sets `_a2l_summary_start = 0`; every writer sets 0 (`app.py:13543`, `:18190`, `:19698`, `:19729`) and no key changes it, and the summary lines read no byte value (`a2l.py:3675-3684`, R-A2L-077's fields). `_update_a2l_summary_buffer()` is called after the recompute so the stored lines and `#a2l_view` agree; no observable change, so no requirement.
- **D-10b-4 — the confirm is disarmed by every in-place write (S-7 / A10-09).** While displayed the notice runs `_bump()` (disarm and one sync, the window's own idiom for every state change, R-SEG-EXP.8 … .11); while hidden it clears the arm only (the next open re-syncs, D-6). Reason: a confirm given against other bytes must not carry to the next `e`.
- **D-10b-5 — the hook keeps running after a missing Check Editor (A10-08).** Inc 6's body ends with `except Exception: return` around the Check Editor query; 10b switches that block to the `checks = None` idiom the CRC Designer block uses, so the three notices appended after it always run. Agreed through the shared-interface rule: Inc 6 merges first, 10b's E4 writes on main after it.
- **D-10b-6 — the A2L refresh cost is measured, not assumed (A10-12).** QC-TM-10b-1 (`02-test-cases.md`) on the largest synth A2L, LAN host, against 1 s; the fallback (recompute on the A2L Explorer's show) is ruled at E4 only if the bound fails.
