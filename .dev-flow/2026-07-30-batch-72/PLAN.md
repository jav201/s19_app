# PLAN — batch 2026-07-30-batch-72 — P1 design-defect implementation (CRC B + Legend B)

## Where we are
**Phase 1 APPROVED (2026-07-30) → Phase 2 cross-agent review in progress.** Phase 0
complete. This batch was PREPARED by the prototyping session (the one that ran
`/tui-design` → PR #164 and got the operator's variant verdict); the EXECUTING session
took it over at the Phase-1 gate and carries it to term under **full autonomy + merge
authority**. Nothing is implemented yet.

**Kickoff record (executing session, 2026-07-30).**
- **RC-1 RE-VERIFIED**: `origin/main` tip = `31d87d0` (PR #164 squash, MERGED) = `HEAD`
  = merge-base of `claude/batch-72-design-defect-634a67`. Collision re-check
  `git ls-remote --heads origin | grep batch-72` → **0 hits**.
- **flow: `2026.07.28-rev1` (hash verified)** — `~/.claude` 0 commits behind
  `origin/main`; aggregate `sha256` = `0127a2767ff11c8a`, matching `FLOW-VERSION.md`
  exactly (C-45 PULL discharged).
- **Authorization (per-batch, asked and answered)**: Q1 = *"Full autonomy + merge"* —
  the agent self-approves remaining gates, opens the PR, and merges **only** after the
  final independent PR-level `qa-reviewer` pass over the whole diff vs `main` comes back
  clean; a HIGH finding blocks the merge and returns to the operator. Q2 = *"Acknowledged"*.
- **P-8 RESOLVED**: operator confirmed *"Stack, key first"* — the PROPOSED default was
  confirmed, not overridden.

## Objective
Ship the operator-decided redesigns: **CRC Designer Variant B** (paired Reflection row,
KAT demoted to a `Self-test` row under Check, Warnings owns the hero right column,
Select height capped) and **Legend modal Variant B** (two-pane: card ∥ colour key,
key-first stack at the floor). Route: **full `/dev-flow`** (operator invoked it).

## Status per phase
| Phase | Status | Artifact |
|---|---|---|
| 0 — intake | ✅ done (prep) + RC-1 **re-verified at `31d87d0`** by the executing session | §2.6 of 01-requirements.md |
| 1 — requirements | ✅ **APPROVED by the operator 2026-07-30** (0 iterations) | `.dev-flow/2026-07-30-batch-72/01-requirements.md` |
| 2 — cross-review | 🔄 in-progress (architect ∥ qa-reviewer ∥ security-reviewer) | `.dev-flow/2026-07-30-batch-72/02-review.md` |
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
| 2026-07-30 | Backlog premise "CRC snapshot cells drift" is FALSE | executed probe, §2.7 P-2 |
| 2026-07-30 | **P-8 CONFIRMED — floor stacking = key first** | operator at the Phase-1 gate; PROPOSED default confirmed, not overridden |
| 2026-07-30 | **Standing auth GRANTED — full autonomy + merge** | operator kickoff Q1; merge still gated on a clean final PR-level qa pass |
| 2026-07-30 | **Phase-1 gate APPROVED** (Coverage ✅ · Evidence ✅ · Certainty gap = P-8, dispositioned by the answer) | operator; 0 Phase-1 iterations |

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
