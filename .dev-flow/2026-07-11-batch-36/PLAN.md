# PLAN — 2026-07-11-batch-36 (living compendium)

> BLUF: three operator-requested UI/hygiene stories + a stale-backlog refresh. Fully
> supervised run (operator approves every gate + merges). RC-1 clean @ `7df60dd`.

## Where we are
- **Phase 0 — Story intake**, `awaiting-gate` (Definition of Ready).
- Rollover: batch-35 merged (PRs #64/#65 on `main`) + vault-synced 2026-07-11. This
  worktree's prior `state.json` `awaiting-sync` flag was a stale local snapshot; retired
  with this rollover.

## Objective
Reduce Patch Editor clutter + fix the cramped paste box (B-22), document the Workspace
hex-view colors in the legend (B-24), and relocate/prune test-input fixtures to shrink the
repo (B-23) — plus refresh the 8-batch-stale `.dev-flow/BACKLOG.md`.

## Batch-kickoff authorization (operator, 2026-07-11 — AskUserQuestion)
- **Run mode: "Approve every gate".** FULLY SUPERVISED. The agent stops at every phase gate
  AND every Phase-3 increment for explicit operator approval before advancing. NO autonomy.
- **Merge: operator merges.** No self-merge. Agent stops at "PR opened, CI green".
- **Decision-recording:** every agent-taken decision (design defaults, review folds) is
  recorded in this PLAN's decision log + `state.json.decisions_log` + `05-postmortem.md`,
  carried to the vault at `/dev-flow-sync`.
- **Per-batch rule (feedback_standing_auth_per_batch):** this authorization is batch-36-only
  and is NEVER carried to batch-37; re-ask at the next kickoff.

## Stories (Phase-0 candidates — see 01-requirements.md §2.6)
| US | Backlog | Title | Priority | Class |
|----|---------|-------|----------|-------|
| US-058 | B-22 | Patch Editor: readable paste box + uncluttered controls | P1 (primary driver) | READY* |
| US-059 | B-24 | Workspace hex-view color legend | P2 | READY |
| US-060 | B-23 | Relocate test inputs to examples/ + prune heavy A2Ls | P2 (hygiene) | READY* |

\* mechanism/file-selection deferred to Phase 1 (correct per two-layer model — the story
states the WHAT). Non-US chore: refresh `.dev-flow/BACKLOG.md` (Phase-6 docs deliverable).

## Roadmap (increment plan — provisional, set firm at Phase 2)
- Inc-1: US-058 Patch Editor layout (screens_directionb.py + styles.tcss + snapshot cells).
- Inc-2: US-059 hex legend (legend.py + LegendScreen in screens.py + report_service legend + test).
- Inc-3: US-060 relocate `tmp/stress_smoke/` → `examples/`; prune heavy A2Ls; adjust example
  smoke/gif tests; keep bare-minimum real-vendor coverage.
- Docs: refresh BACKLOG.md + REQUIREMENTS.md rows.

## Key decisions
- D-1 (prune, operator 2026-07-11): delete unnecessary heavy files BUT retain a bare-minimum
  real-vendor large-A2L fixture; the (possibly slimmed) stress tests MUST still cover the same
  functional requirements — no coverage regression. Candidate: keep 36M top-level
  `case_06_large_nested_a2l`, delete the 54M `professional_validation` slow duplicate + drop
  `pv__case_06_large_nested_a2l` slow case. To confirm in Phase 1.
- D-2 (B-22 mechanism): 3-column reflow vs. taller dedicated paste pane — NOT locked at
  Phase 0; Phase-1 architect measures (C-13 geometry-budget at 80 cols) and picks.

## Risks / watch-items
- **C-13 geometry budget:** 3 columns at 80 cols is tight (host content ~70 cols @80). Measure
  before locking; deficit-matched fallback (C-13.1).
- **B-23 test cascade:** deleting example fixtures touches test_examples_smoke.py +
  test_examples_pilot_gifs.py + possibly snapshot/gif baselines. Location-move census (C-14).
- **Destructive deletes:** tracked-file removal approved per-increment at the gate; git history
  size is NOT reclaimed without a separate history-rewrite (out of scope).
- **B-24 markup safety (C-17):** legend rows are static in-repo text (no file-derived input) —
  low risk; still route report-output surface through security-reviewer at Phase 2.

## Conventions honored
Engine-frozen set OFF-LIMITS (color_policy.py etc. — legend lives in the non-frozen legend.py).
≤5 files/increment. Black-box AT per story shown RED pre-change. Snapshot regen canonical-CI-only.

## Out-of-scope carries
Git history rewrite; B-11..B-19 (batch-37); Bookmarks dead scaffold; hygiene carries (S-F7,
canonical_report_bytes consolidation, __setattr__ retire, P-1/P-2/P-3).

## Test ledger
Base (tip 7df60dd): TBD at Phase-3 entry (batch-35 close was 1335 passed). post = base − D + A.

## Decision log
- 2026-07-11 Phase 0 kickoff: authorization recorded (approve-every-gate; operator merges).
  Scope = US-058/059/060 + BACKLOG refresh. Prune decision D-1 recorded. Awaiting DoR gate.
