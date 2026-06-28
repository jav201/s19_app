# PLAN.md — batch-17 (living compendium)

> Updated at every gate/checkpoint. Mirror of `state.json` for humans. BLUF first.

## Where we are
**Phase 0 — story intake & refinement (awaiting DoR gate).** RC-1 PASS off `origin/main 963142c`; branch `claude/batch-17`. Three candidate stories investigated (parallel Explore + git archaeology). One scope decision owed before Phase 1.

## Objective
Three previously-deferred features under FULL /dev-flow rigor (operator: "not the first time we try to fix them" → prior-attempt archaeology done up front).

## Prior-attempt archaeology (the operator's headline concern)
- **US-018 (#9):** NOT a failed fix — an **overlooked pane**. Batches 05/06 gave the MAC (`a222907`) and A2L hex panes `min-width: 82` so a full 16-byte+ASCII row fits; `#ws_center` (workspace) was never given the floor. The fix is proven; the workspace was missed.
- **US-019 (CRC width):** No prior attempt — net-new (emerged this session from the #7 draft-time finding). The 16/32 threading pattern is proven in US-015 (Patch Editor).
- **US-020 (#10):** No prior attempt / nothing reverted. The issues list + `ReportViewerScreen` shipped (batch-07 `b1cde0c`); the hex-pane / addendum / report-merge parts are net-new.

## Per-story status (Phase-0 INVEST + DoR)
| Story | What | INVEST verdict | Class | Size |
|-------|------|----------------|-------|------|
| US-018 (#9) | workspace `#ws_center` `min-width` so 16B+ASCII fits one line | clear outcome, proven fix, observable (pane width ≥82) | **READY** | XS (1 css + 1 test) |
| US-019 (CRC width) | operator-selected 16/32 on the CRC save (ConfirmWriteScreen selector → write_crc_image) | clear outcome, mirrors US-015, observable (written .s19 record width) | **READY** | S–M (~3-4 files) |
| US-020 (#10) | issues-report viewer: right hex pane + enhanced list + addendum input (declared mem locs) + report integration | too large + addendum net-new with design Qs | **REFINE/SPLIT** | L (4 sub-stories) |

## Surfaces (Phase-0 substrate map; all OUTSIDE engine-frozen)
- **US-018:** `s19_app/tui/styles.tcss:193` `#ws_center` (add `min-width`, mirror `#mac_hex_pane` styles.tcss:287). Test pattern: `tests/test_tui_mac_layout.py::test_mac_hex_pane_width_at_wide_terminal`. Hex row needs 81 cols (hexview.py:401-434).
- **US-019:** `screens.py:671` ConfirmWriteScreen (+ selector), `screens.py:1323` `_on_confirm_write`, `screens.py:1380` `_run_crc_write_worker`, `crc.py:790/879` `write_crc_image` (+ `bytes_per_line` kwarg). Mirror `screens_directionb.py:614/718/732` (Patch Editor width button + SaveBackDecision). Update `tests/test_crc_operation.py::test_crc_write_emits_32_byte_records` (keep 32 default + add 16 path).
- **US-020:** `app.py:1124-1178/4848-4939` issues screen+table, `screens.py:472-669` ReportViewerScreen, `hexview.render_hex_view_text` (reuse), `color_policy.py:5-11`, `report_service.py` (addendum integration). Addendum = NET-NEW data model + form + persistence.

## US-020 split (proposed)
- **US-020a** — right-side hex pane on the issues view (row select → hex at issue address). Low risk, reuse renderer.
- **US-020b** — enhanced issues list (expose ValidationIssue fields / severity badge / related artifacts). Low.
- **US-020c** — report-addendum input (operator-declared memory locations): NET-NEW data model + input form + persistence. Needs design + operator clarification on "declared memory locations" semantics.
- **US-020d** — issues→report integration (issues + addenda section in generated report). Depends on US-020c.

## Open decision (DoR gate) — owed before Phase 1
**Batch scope.** US-018 + US-019 are READY and small. US-020 is large + part net-new (addendum) + needs design. Options at the gate: (A) this batch = US-018 + US-019 + US-020a/b (the READY parts), defer US-020c/d (addendum) to its own batch w/ a design spike; (B) all of US-020 here (longer batch, addendum design inline); (C) US-018 + US-019 only, US-020 entirely its own batch.

## Roadmap / increment sketch (pending gate)
- US-018: 1 increment (css + test).
- US-019: ~2 increments (selector UI + threading; test parametrization).
- US-020a/b: ~2 increments. US-020c/d: own batch (recommended).

## Conventions honored
RC-1 (held), engine-frozen set off-limits, two-layer AT/TC + C-10/C-12, draft-time verification (this archaeology), per-batch subdir, ≤5 files/increment, commits/PRs on approval.

## Risks / watch
- US-019 changes the CRC ConfirmWriteScreen contract → the existing fixed-32 lock-AT must be re-pointed to "default 32 + selectable 16" (not deleted).
- US-020 addendum "declared memory locations" semantics UNCLEAR → must clarify before deriving (else mis-capture, the exact two-layer failure mode).
- Batch breadth: 3 stories incl. one large; risk of an over-long batch → the split decision mitigates.

## Test ledger
Baseline (origin/main 963142c): full non-slow 883 passed. (Per-increment deltas tracked here.)

## Decision log (mirror)
- 2026-06-26 — batch-17 initialized; Phase-0 archaeology done; awaiting DoR gate (scope decision on US-020).
