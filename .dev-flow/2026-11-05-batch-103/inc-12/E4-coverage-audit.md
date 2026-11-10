# Inc 12 — independent E4 coverage audit

Read-only audit by an independent Kimi explore agent of `674d6752`, before integrated RED/GREEN. The inventory is 34 automated cases and 112 pytest nodes; AT-B103-I12-2 remains the operator gate.

Initial verdict: **REJECT the all-full claim.** Twenty-four nodes need correction or downgrade. No product defect is asserted by the coverage findings.

1. R-TUI-042a.2/1,/2 did not check every visible adjacent cell pair.
2. R-TUI-042a.5/1–/9 and AT-B103-I12-1 used stored Tag-cell text plus x/length, not the exact painted `render_line` span.
3. R-TUI-042a.6/1,/2 used `timing_bound(1.0)`, which can relax CI to 2 s against the hard 1 s requirement.
4. R-TUI-042a.8/1 read `card.render().plain` instead of the painted Name line and continuations.
5. R-TUI-042a.7.1/.7.2 injected dicts through a stand-in event instead of real A2L loading, and the screen-output absence checks lacked a positive painted-value control.

All five corrections, plus the previously known real-file-route defect, were accepted in `E4-review-rulings.md` and routed to the independent tester. A second re-audit rejected the on-screen blank-Tag skip, partial-cell gap omission and missing 220-column paint checks; the diagnostic run also exposed callback, PAGE64/PAGE64W, display-identifier and limit-scroll fixture faults. Tester commit `047d0a66` closed the complete set. Final independent static re-audit: **PASS for the all-full coverage claim**, with no execution claim. Executed RED/GREEN status is recorded separately in `04-validation.md` after the final runs.

A later M2 run found one more vacuity: the scrolled Address/Length check accepted a completely off-screen cell as success, so `fixed_columns=0` survived 40/40. The new `require_visible` arm fails that state. The independent re-audit confirms the fix kills the absence without weakening the other cases; 41 nodes passed. Its executed M2 retry is recorded separately in `04-validation.md`.
