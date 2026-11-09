# Inc 12 — E4 pre-integration review rulings

Orchestrator: Kimi, 2026-11-09. These findings precede the integrated RED/GREEN run; none changes a requirement, threshold or pinned interface.

## Product review

- **Accept MEDIUM impl — raw-name preprocessing.** `_build_a2l_table_cells` used `.replace("\n", " ").strip()` before R-TUI-042a.6's projection, deleting characters that must paint as U+FFFD. Remove the preprocessing. Add a discriminating arm to R-TUI-042a.6/3: raw `A ` at width 2 gives `✓ A�`. Closed for re-review by commit `2e441e16` and the corresponding tester commit.
- **Accept LOW impl — stale docstrings.** Correct the three dependency/behavior descriptions in `_compose_screen_a2l`, `update_a2l_tags_view` and `_repaint_a2l_tag_cells`. Closed by `2e441e16`.
- **Security pre-review:** PASS-WITH-NOTES, read-only. Its executed checks remain owed by the suite and mutants.

## Independent coverage audit

The audit rejects the initial all-full claim. Every correction below is accepted; do not downgrade a case merely to avoid the work.

1. **R-TUI-042a.2/1,/2:** assert the gap for every visible adjacent painted cell span, not only Address/Length and the four named glued strings.
2. **R-TUI-042a.5/1–/9 and AT-B103-I12-1 (HIGH):** read the visible Tag span from `render_line`, assert exact painted text (including `…` and suffix) and its endpoint. Stored cell length plus x is not a painted-result oracle.
3. **R-TUI-042a.6/1,/2:** assert the requirement's hard `< 1.0 s` per call. `timing_bound(1.0)` can relax CI to 2 s and is not the conformance oracle.
4. **R-TUI-042a.8/1:** prove the full name from the painted Name line and its painted continuations, not `card.render().plain`.
5. **R-TUI-042a.7.1/.7.2:** replace the stand-in event/dict route with real synthetic A2L files loaded through the real app. Prove each target projected value is actually painted before asserting that hostile introducers are absent from screen output; scroll to the limits as required. This is both a full-route and a positive-visibility correction.

The tester owns all corrections and the ledger. Linux RED/GREEN runs decide execution status only after these corrections land.

## Capture-driver review

Tracked-file scenarios must load `prg.s19` before the A2L; otherwise the CURVE before/after Raw/Physical comparison is vacuous. Sidecar reports must not contain checkout/account paths. Accepted and routed to the mechanical capture lane.
