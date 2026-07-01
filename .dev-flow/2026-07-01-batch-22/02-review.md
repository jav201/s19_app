# 02 — Cross-agent review — batch-22 (#8 US-030 4-pane split + US-031 snapshots)

> Phase 2. architect ∥ qa (security inline N/A — pure layout reparent + CSS + tests; no new data/IO/external-write/auth surface; all widget ids preserved).
> **Outcome: 0 blockers. architect PROCEED · qa PROCEED.** 1 major (R1, a false-premise correction) + 5 minors, all folded body-first. §6.4 audits them.

## Verdicts
| Reviewer | Verdict | Blocker | Major | Minor |
|---|---|---|---|---|
| architect | PROCEED | 0 | 1 (R1) | 2 |
| qa-reviewer | PROCEED | 0 | 0 | 3 |
| security | N/A (inline) | — | — | — |

## The headline (architect MAJOR-R1) — false-premise correction, no design change
The Phase-1 spec claimed Textual `Horizontal` **wraps** the Change-file 5-button row to ~2 lines at ~35 cols (the C-13.1 rung-2 "free" recovery). **It doesn't** — `Horizontal` lays children on one line and clips overflow (`#patch_doc_controls` = `width:100%; height:auto`, `styles.tcss:654`). Left as-written, that pane would **clip its rightmost buttons at 80 cols** and the fallback ladder would be a no-op. **Fold:** rung-2 is now an EXPLICIT `#patch_doc_controls { layout: grid; grid-size: 3 }` button-grid (LLR-033.3b) — deterministic 2-row button flow, version-stable, CSS-only. The 2×2 layout itself is unchanged; only the tightest pane's button-row mechanism. AT-033a's `region.right ≤ host` catches a clip if it's wrong.

## architect — other findings
- **Pane mapping COMPLETE:** all 12 physical compose yields (:614-714) land in exactly one pane/span, nothing dropped or doubled (the checks pane correctly gathers the 4 non-contiguous check yields). ✓
- **Census RE-VERIFIED:** only one structural test query on the patch tree (`#patch_checks_results > Static` :785 — survives via LLR-033.5); all 20+ others id-addressed; no compose-order/nesting assertion. R4 LOW-risk accurate. ✓
- **minor (grid rows):** `grid-size: 2 3` + `grid-rows: 1fr 1fr auto` gives the `column-span:2` save-back child a declared home (auto row, zero-height while hidden). Folded.
- **minor (snapshot):** Phase-3 confirm `patch` only in `_SCAFFOLD_CELLS` not `_RESTYLED_CELLS`. Folded to R3.
- `should`-misuse PASS, frozen PASS, increment order sound.

## qa — findings (all folded)
- **MINOR-1 (the substantive):** `2 distinct x × 2 distinct y` is sound vs the stated counterfactuals but an **L-shape** (3 panes) could satisfy it — tightened LLR-034.1 to assert each row-band has EXACTLY 2 panes + each col-band EXACTLY 2.
- **MINOR-2:** budget divisor = `content_region.width` (interior). Aligned.
- **MINOR-3:** HLR-033.3 (per-pane scroll) had no check — added a TC asserting each pane `overflow_y == "auto"`.
- **Key checks PASS:** AT-033c genuinely drives `request_action`→observable effect (not id-exists-only); the **no-fabricated-snapshot-pass** discipline is clean (local gate = geometry AT; AT-034 `xfail`-until-CI; the correct existing `patch-comfortable-120x30` xfail cell is the one reconciled).

## Two-layer review (blocker gate) — PASS
Every US has a black-box AT (geometry AT-033a/b/c through the shipped patch screen; snapshot AT-034); every output-producing req names its deliverable + Pilot/snap_compare oracle; both traceability chains present; ATs assert real geometry numbers, not internal symbols.

## Fold disposition
All 6 findings applied body-first to `01-requirements.md` (§3.x, §4 LLR-033.3/.3b/.4 + LLR-034.1, §5.2 TCs, §6.3 R1/R2/R3) + audited in §6.4. 3 Phase-3 verify-at-render items (button-grid pixel @80, span render, snapshot-cell membership). No blocker → no iterate-to-refine.
