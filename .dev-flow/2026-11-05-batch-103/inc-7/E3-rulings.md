# Inc 7 — E3 rulings (orchestrator)

Orchestrator claude-opus-5-5, 2026-11-13 (time in `steps.log`, from `date`). The E3 verdicts in `E3-architect.md` and `E3-security.md` are both FAIL: 1 HIGH and 9 MAJOR. One correction pass (E3R1) applies the rulings below to `01-requirements.md`, `02-test-cases-*.md`, `E1-slice.md`, `codewire/graph-inc7.md` and `E1-rulings.md`. The same reviewer then re-reviews only the corrected parts.

## HIGH

**E3A-01 (Box A of the clipboard suite).** Accepted, with an owner and an order different from the reviewer's proposal.
- Inc 7 changes R-PASTE.1 (listed in its changed canon rows), so moving the clipboard suite's Box A from the filter box to `#a2l_tag_find_input` is **Inc 7's E4 retarget**, not an Inc 1b task.
- Each retargeted node cites the changed row.
- **Order constraint (DF-10):** Inc 7's E4 starts only after `b103-inc1b` is final, meaning its WinCI rounds are closed (PENDING P-001 / P-002). Inc 7 then builds on that final tree, and no two writers touch the Inc 1a/1b test files at the same time.
- Record the full list of the 13 affected nodes in `E1-slice.md`'s E4 retarget list.
- The WinCI re-run at Inc 7 E5 (already ruled) covers Box A on Windows.

## MAJOR: all accepted, fixed as the reviewer proposed, with these choices
- **E3A-02:** remove the back-reference, or exclude it from equality (`field(compare=False, repr=False)`). Add a case that compares two equal entries.
- **E3A-03:** complete I-7 so G-L and G-V can be built in parallel: the filter box's constructor and its dropdown link, the app method, `LabelListApplied` with its fields, and the pane ids. Re-pin it.
- **E3A-04:** the ranker keeps one token per *request key*, not per consumer, so the 10 "similar" requests do not cancel each other. Keep the bound from D-8.
- **E3A-05:** every worker callback, held request and debounce gets the R-COPY.26 teardown guard: drop the work when the app is not running, and raise no error. Add one robustness row per entry point (the same family as PENDING P-002), plus cases.
- **E3A-07:** keep the `id()` mapping valid in list mode, or change the write route to a stable key. Keep R-A2L-049/105 green.
- **E3A-08:** after an unload, the viewer clears its rows (R-TUI-068.3 wins: approved canon).
- **E3A-10:** the D-2 layout gets a fallback below 118×54. At the 80×24 floor, rows stay visible (the pre-Inc-7 stacking or a reduced hex pane). This is visible: it is added to the capture verdicts (DF-09).
- **E3A-11:** add R-TUI-069.7, and list the E4 retargets (the tc019 tests and the 6 A2L SVG snapshots). Snapshots are regenerated only by the canonical CI (HT-09).
- **E3S-01:** cap the paste window's preview rows, with a visible `+<k> more` line, and move the rebuild off the UI thread or debounce it. Add the hostile 32,768-row case.

## MEDIUM: fix in E3R1
E3A-06, E3A-09 (add the two attributes to the session census), E3A-12 (`_take_paste` makes a list only in the list-capable fields, per D-3), E3S-02 (cap the echoed text), E3S-03 (pin where the hook sits relative to `restrict`), E3S-04.

## MINOR / LOW
- Fix in E3R1 when the fix is a row or case text: E3A-13, E3A-14, E3S-05, E3S-06 (also replace bidi controls in `display_text`).
- Otherwise, add a backlog line in `E1-rulings.md` §7 (E3A-15). The orchestrator copies it to PENDING.

## Unchanged
- The provisional visible decisions (DF-09).
- The size cap. If E3R1 goes past about 95 requirements or 48 nodes, stop and report the split point.
