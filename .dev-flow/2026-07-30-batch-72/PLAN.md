# PLAN — batch 2026-07-30-batch-72 — P1 design-defect implementation (CRC B + Legend B)

## Where we are
**Phase 1 DRAFTED, awaiting-gate.** Phase 0 complete. This batch was PREPARED by the
prototyping session (the one that ran `/tui-design` → PR #164 and got the operator's
variant verdict); a DIFFERENT session executes it to term. Nothing is implemented.

## Objective
Ship the operator-decided redesigns: **CRC Designer Variant B** (paired Reflection row,
KAT demoted to a `Self-test` row under Check, Warnings owns the hero right column,
Select height capped) and **Legend modal Variant B** (two-pane: card ∥ colour key,
key-first stack at the floor). Route: **full `/dev-flow`** (operator invoked it).

## Status per phase
| Phase | Status | Artifact |
|---|---|---|
| 0 — intake | ✅ done (this prep) | §2.6 of 01-requirements.md; RC-1 verified at `6ba0680` |
| 1 — requirements | 📝 DRAFTED → **awaiting-gate** | `.dev-flow/2026-07-30-batch-72/01-requirements.md` |
| 2 — cross-review | not-started | — |
| 3 — implementation | not-started | suggested cut below |
| 4 — validation | not-started | — |
| 5 — postmortem | not-started | — |
| 6 — docs + PR | not-started | — |

## Kickoff protocol for the EXECUTING session (do these before anything)
1. **RC-1 again**: `git fetch`; branch off the CURRENT `origin/main` tip. Verify PR
   [#164](https://github.com/jav201/s19_app/pull/164) (prototypes + this batch prep)
   MERGED first — this scaffold rides on it. Verify flow currency (C-45 PULL) vs
   `~/.claude/docs/FLOW-VERSION.md`.
2. **Re-read `state.json`** before editing (last-writer-wins; parallel batch-65 may
   have moved it). Confirm `batch_id` is still `2026-07-30-batch-72` and the number is
   still collision-free (`git ls-remote --heads origin | grep batch-72`).
3. **ASK the operator the two kickoff questions** (authorization is per-batch, NEVER
   inherited — `feedback_standing_auth_per_batch`): autonomy + merge authority; and the
   decision-recording acknowledgement. **NOT asked in the prep session on purpose.**
4. **Present the Phase-1 gate**: paste 01-requirements.md §2.7 + §3 inline; get the
   operator's `approve` — including the **P-8 open decision** (floor stacking key-first,
   PROPOSED default).
5. Re-run the ID census (AT-213..218, TC-510..519 reserved — a parallel batch may have
   consumed ids since 2026-07-30).

## Suggested Phase-3 increment cut (re-derive after Phase 2 per C-21)
- **Inc-1 — Legend B** (`screens.py` + `styles.tcss` + new AT file): the cheapest
  surface (P-3: not snapshot-captured), no cross-dependency. ATs 216/217/218.
- **Inc-2 — CRC B compose** (`crc_designer_view.py` + `styles.tcss`): pair row +
  Self-test row + hero change + Select cap. ATs 213/215.
- **Inc-3 — Guards** (test-only): AT-214 G-1 sweep + its RED counterfactual on old CSS
  (C-40 transcript), REQUIREMENTS.md rows + §6.5 amendment for the batch-59 lineage.

## Key decisions log
| Date | Decision | Source |
|---|---|---|
| 2026-07-30 | CRC = Variant B; Legend = Variant B | operator, verbatim in 01-requirements §6.2 |
| 2026-07-30 | KAT **demoted**, not removed (Gate-2 resolved by the B pick) | operator via variant choice |
| 2026-07-30 | ONE batch, both stories, full `/dev-flow` | operator invoked `/dev-flow`; both stories drift zero snapshots (P-2/P-3) so the two-batch split lost its rationale |
| 2026-07-30 | Floor stacking key-first = PROPOSED, confirm at gate | P-8 UNDECIDABLE |
| 2026-07-30 | Backlog premise "CRC snapshot cells drift" is FALSE | executed probe, §2.7 P-2 |

## Risks / watch-items
- `state.json` concurrency (batch-65 in flight, last-writer-wins).
- 32 tests in `test_crc_designer_view.py` = CRC blast radius; 3 legend test files
  (P-6). Reverse-grep again per increment (C-26).
- Prototype code is throwaway — REWRITE compose per PROJECT_RULES.md docstring/type
  conventions; do not copy `VariantB` verbatim.
- If ANY snapshot test fails during this batch, a premise was wrong — STOP, no casual
  regen (01-requirements §5.3.6).

## Out-of-scope carries (already in the canonical backlog, lane A)
- Legend variants for `map`/`a2l`/`issues` views were not shot-captured (runnable live).
- The four 2026-07-28 backlog bullets get reconciled at THIS batch's close: bullets 1
  (switches), 2 (KAT), 3 (design pass) close; bullet 4 (Legend) closes; the
  BACKLOG-PROCESS companion item (why `/tui-design` missed these) stays in lane B.

## Test ledger
Base at prep: 2358 collected (batch-71 close). This batch: +6 AT nodes + TCs (ledger
`post = base − D + A` reconciled at each gate; deletions expected 0 unless
`_switch_row` orphan-removal drops a TC).

## Prototype teardown (batch-close obligation)
DELETE `prototypes/crc_designer.p1.*`, `legend_p1.*`, `p1_design_defects.*`,
`p1_review_build.py`, `p1-design-defects-review.html`, `crc_p1.variant_*.svg`,
`crc_p1.shipped.*.svg`, `legend_p1.*.svg` once both stories merge (absorb-then-delete).
