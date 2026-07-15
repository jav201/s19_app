# s19_app — Project Engineering Rules

Project- and stack-specific gates for the Textual TUI + pytest-textual-snapshot stack. These
are the s19_app-scoped counterparts to the portable controls in the global /dev-flow command —
relocated here so the workflow command stays language- and framework-agnostic. Consulted during
every /dev-flow batch alongside the general controls. Canonical history: memory
project_devflow_control_lineage.md.

## C-13 — geometry-budget / reuse-transfer check (Phase 1)
A pattern proven in one container is NOT verified for another: when a spec reuses a
layout/sizing/capacity pattern that works in container A for a different container B (a
`min-width` floor, a fixed column count, a fan-out width, a buffer size), VERIFY it against B's
actual budget at draft time — compute B's available space minus its fixed siblings vs the
element's required footprint — rather than assuming the A-proven value transfers. State the
budget arithmetic (or a measurement probe) in the spec, or flag `assumed — measure in Phase N`.
(Origin: batch-17 US-018 — the MAC `min-width: 82` hex floor, proven in a TWO-pane layout, pushed
the right context pane off-screen in the THREE-pane Workspace at 120 cols: 22 + 82 + 40 = 144 > 96
body; caught only by Phase-3 measurement → forced an iterate-to-refine.)

## C-13.1 — deficit-matched fallback selection (Phase 1, extends C-13)
When a geometry check is flagged `assumed — measure` AND a fallback ladder is pre-committed, do
NOT order the ladder by escalation cost (cheapest rung first). Tag each rung with the deficit
RANGE it can recover (label-trim ≈3–6 cols; inline overflow/scroll ≈ a row's worth; key-binding /
off-row affordance ≈ unbounded), estimate the container's deficit at the tightest supported regime
(Σ fixed/auto sibling footprints − available content width — the same arithmetic C-13 mandates),
and pre-select the LOWEST rung whose recovery ≥ the estimated deficit. A rung whose recovery is
smaller than the estimated deficit is struck at draft time, not bikeshedded at the gate. (Origin:
batch-18 US-023 — the A2L `#a2l_tags_filters` row already overflowed its half-width pane with 9
widgets; a 10th "Legend" button rendered off-screen at 80 AND 120 cols by ~67–85 cols, but the
pre-committed PRIMARY fallback "shorten the label" recovers only ~3 cols and was never viable; the
LAST-RESORT key-binding was the only rung that fit.)

## C-22 — per-cell snapshot-drift prediction (Phase 3)
When a spec predicts which snapshot/baseline cells an increment will drift, reason PER-CELL (name
each cell and WHY it drifts) or state the count as an explicit UPPER BOUND under a `strict=False`
envelope — never a flat exact count. A cell can render the change below a scroll fold and NOT
drift, so an exact prediction over-counts and confuses the gate. (Origin: batch-33 and batch-35
each predicted 2 drifting cells but observed 1 — the second rendered below the pane fold; the
`strict=False` marks absorbed the mismatch harmlessly, but the prediction should have been per-cell.)

## C-23 — geometry-claim measurement discipline (Phase 1, extends C-13/C-13.1)
A spec claim about RENDERED layout size (pane/row/column height or width, an element's
visible-line count, a fold position) MUST be established by a PILOT MEASUREMENT
(`App.run_test(size=...)`, read the real `region`/`content_region` at the target width) — NEVER by
CSS `fr`-fraction arithmetic, which cannot see ancestor constraints (a sibling capping the shell
height, a `1fr` starved by a fixed neighbour). Measure at the tightest supported regime AND the
comfortable one. Any ILLUSTRATIVE value in a spec (a candidate CSS weight vector, a sample size)
MUST be labelled non-normative, and Phase 3 MUST re-measure the WHOLE pane budget (every sibling in
the container), not just the target widget — an illustrative weight that fits the target can starve
a sibling off-screen. (Origin: batch-36 F-01 — Phase-1 fr-math estimated ~9 rows/pane, rendered ~5
@80x24 (4.5× off — the shell was height-capped by a sibling), surfaced only at the Phase-2 re-measure.)

## C-28 — shared-chrome binding-drift snapshot census (Phase 3, extends C-22)
When an increment adds, removes, or changes an App-level `Binding(…, show=True)` — or any
shared-chrome element rendered on EVERY screen (Footer, Header, activity rail) — the
snapshot-drift census MUST reason about and mark EVERY snapshot cell that renders that chrome, not
only the feature's own screen cells. Per-cell (per C-22): a chrome element the footer truncates at
narrow widths won't drift those cells, so mark by the widths that actually render it. Catch it at
the INCREMENT snapshot step, not the Phase-4 full-suite run. (Origin: batch-45 F-1 — retiring the
entropy modal removed the footer-visible `e`/Entropy `Binding(show=True)`; the Footer renders on
every screen, so 18 wide-cell tc016s snapshots drifted, but the increment handling marked only the
2 map cells — surfaced only at the Phase-4 full-suite run. Test-only fix, no shipped defect.)
