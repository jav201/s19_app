# PLAN — 2026-07-11-batch-37 (living compendium)

> BLUF: 4 P2 backlog stories (B-11..B-14). Run mode **Autonomous + self-merge** (operator grant,
> re-asked after plan crafted). RC-1 clean @ `978a900`. Fresh branch `claude/batch-37-p2-b11-b14`.

## Where we are
- **Phase 0 — Story intake**, autonomous. Proceeding to Phase 1.

## Objective
Ship the P2 backlog set: a persistent before/after-report surface (B-11), entropy viewer
pagination+sort (B-12) and legend+clickable strip (B-13), and patch-editor refresh + a JSON
popup change-set editor (B-14).

## Batch-kickoff authorization (operator, 2026-07-11, re-asked after plan)
- **Run mode: Autonomous + self-merge.** Agent runs all gates autonomously (full packets
  presented in-conversation, self-approved with axis check); merges after CI green + a FINAL
  PR-level qa-reviewer pass over the whole diff comes back clean. HIGH finding blocks → operator.
- **Guardrails:** full suite + engine-frozen guards + code-review GREEN before PR; snapshot regen
  canonical-CI-only; new controls proposed-not-encoded (ask first); all decisions recorded.
- **Per-batch rule:** batch-37-only; re-ask at batch-38.
- **Return to operator on:** HIGH final-QA finding, genuine operator-only decision, or completion.

## Stories (Phase-0 candidates — see 01-requirements.md §2.6)
| US | Backlog | Title | Seam | Class |
|----|---------|-------|------|-------|
| US-061 | B-11 | Persistent before/after-report surface | app.py:1749,1795 transient notify | READY |
| US-062 | B-12 | Entropy viewer pagination + sort | screens.py:585 caps, EntropyViewerScreen | READY |
| US-063 | B-13 | Entropy band legend + clickable strip | screens.py:676 strip Static | READY (C-13) |
| US-064 | B-14 | Patch refresh + JSON popup editor | screens_directionb.py:1977 #patch_paste_text | READY (may split) |

## Roadmap (increment sketch — firm at Phase 2)
- Inc-1 US-061 · Inc-2 US-062 · Inc-3 US-063 · Inc-4 US-064a refresh · Inc-5 US-064b JSON popup.

## Key decisions
- (none yet — Phase 0)

## Risks / watch-items
- **C-23 (new):** entropy legend + sort/page controls + JSON popup carry geometry → PILOT-MEASURE
  the modal budgets, never fr-estimate.
- **Snapshot drift:** entropy + patch cells → xfail(strict=False), canonical-CI regen post-merge.
- **B-14 JSON popup** = new modal screen (the batch-36 F-01 deferred big-editor). Moderate.
- **Engine-frozen:** untouched (entropy = entropy_service TUI-side; patch = TUI-side).
- **C-24 (new):** sweep report byte-identity goldens if any report-content source changes (B-11
  touches the report TRIGGER, not content — low risk, still sweep).

## Conventions honored
Engine-frozen set OFF-LIMITS. ≤5 files/increment. Black-box AT per story shown RED pre-change.
Snapshot regen canonical-CI-only. C-10/C-12/C-18 AT discipline. C-23 pilot-measure geometry.

## Out-of-scope carries
B-16..B-19 (P3), Bookmarks scaffold, hygiene (S-F7, canonical_report_bytes consolidation,
__setattr__ retire, P-1/P-2/P-3), B-17 A2L>32-bit warning.

## Test ledger
Base (978a900): TBD at Phase-3 entry (batch-36 close was 1370, less TC-321 retired in #67 = ~1369).

## Decision log
- 2026-07-11 Phase 0 kickoff: scope = B-11..B-14; run mode autonomous+self-merge. RC-1 @ 978a900.
  4 stories READY. Proceeding to Phase 1 autonomously.
