# Post-mortem — s19_app — Batch 2026-07-18-batch-49

**Batch:** Issues Report MID visual upgrade (US-082) + new dedicated CHECKS rail screen (US-083). Full `/dev-flow`, autonomous through self-merge under a final PR-QA gate.

## Metrics
| Phase | Iterations | Notes |
|---|---|---|
| 0 intake | 0 | 2 stories READY first pass; ALREADY-SHIPPED check clean |
| 1 requirements | 0 | 3 HLR / 20 LLR / pinned AT registry (082a-f, 083a-b, 084a-g) |
| 2 review | 1 | 0 blockers, 3 major + 9 minor, all folded (no iterate) |
| 3 implementation | 0 (4 increments) | Inc-1 HIGH F1→fixed; Inc-2 MED F1→fixed; Inc-3 caught pre-existing Inc-1 escape; Inc-4 AMD-1/AMD-2 |
| 4 validation | 0 | 1570 passed; 21 snapshot-only drift (expected) |
- **Test delta:** +26 (Inc-1 +10, Inc-2 +5, Inc-3 +5, Inc-4 +6); 0 deletions. Base 1565 → 1570 passed (− 21 expected snapshot drift, +26 new).
- **Findings closed:** Phase-2 12/12 folded; 3 code-review findings fixed (Inc-1 F1 HIGH, Inc-2 F1 MED, +1 escaped pre-existing defect); 2 fail-loud spec amendments (AMD-1, AMD-2). Engine-frozen diffs: 0 throughout.

## What worked
- **Recon-first.** Two parallel Explore agents pinned the CHECKS data-source verdict (`last_check_result`, not load-time) + the 5-site rail checklist BEFORE any requirement — the whole "read-only mirror + honest empty state" design fell out of that and never needed rework.
- **Pinned AT registry before Phase 2 (C-21 / batch-48 lesson).** The two Phase-1 agents used divergent AT schemes; pinning one canonical registry up front prevented the batch-48 numbering-divergence trap.
- **C-31/C-10/C-12 discipline caught circular oracles at review, not in prod.** Phase-2 qa flagged AT-082a as circular (aggregate compare against the view's own counters) → hardened to an independent per-slot `Counter` oracle with an asymmetric 3/1/2 fixture. AT-082f/084g hardened to `.plain` verbatim + `spans==[]` with dual-token payloads.
- **Fixture reuse.** The existing `test_tui_patch_checks_strip.py` run-checks driver (real `#patch_checks_run_button`, `_ASYMMETRIC_ENTRIES`) made the C-12 through-surface ATs cheap and honest — no new fixture invented.
- **Fail-loud amendments.** `software-dev` surfaced two genuine spec inconsistencies mid-implementation (CheckDisplayRow 5th field AMD-1; the `0x102`-can't-render AMD-2) instead of silently coding around them — Rule 7/12 working as designed.
- **The code-review gate earned its keep.** It caught the Inc-1 F1 None-guard (a real crash on 3 pre-existing tests) that the dev's green new-file-only run hid.

## What didn't — process failures + root causes
1. **A delegated code-review sub-agent HUNG for ~10.5 hours** with no completion signal; the orchestrator waited passively and only re-engaged when the operator flagged it. **Root cause:** relied on the harness completion-notification alone; the earlier byte-size liveness monitor is invalid here (subagent transcript `.output` files stay 0 bytes). **Corrective action taken:** stopped the agent, reviewed Inc-3/Inc-4 inline, and switched to **active polling** (`TaskOutput block=true` + re-poll + source-mtime liveness) for the remaining critical-path agents. **→ candidate control C-33 (see below).**
2. **Two defects escaped increment gates via PARTIAL test runs** — Inc-1's F1 (only the new file + `-k` subsets ran, not `test_tui_app.py`) and the pre-existing markup-guard tripped by an Inc-1 docstring (only caught when Inc-3 ran the FULL `test_tui_directionb.py`). **Root cause:** increments touching TUI render code did not run the full cross-cutting guard host (`test_tui_directionb.py` carries the markup/rail/footer census guards). The C-19 partial-run trap recurred in a render-specific form. **→ candidate control (project engineering-rules, see below).**

## Scope
No scope drift. Both stories delivered exactly as specced (MID Issues; read-only CHECKS mirror). One clean mid-flight re-cut (moved `update_checks_view` Inc-4→Inc-3 for dependency-cleanliness, C-21) — recorded, no rework. The CHECKS screen stayed read-only (no run-trigger added), honoring the "mirror" decision.

## Candidate controls (operator AskUserQuestion required before encoding — feedback_devflow_control_encode_approval)
- **C-33 (GLOBAL / project-agnostic) — critical-path sub-agent liveness.** When an orchestrator dispatches a sub-agent whose result gates the next step, it MUST actively confirm liveness (poll `TaskOutput block=true` + a progress signal such as touched-file mtime) rather than rely on a completion-notification alone — a hung agent never notifies, and a transcript-byte-size monitor is invalid when transcript files don't grow. Origin: this batch's 10.5h code-review hang.
- **CAND (STACK-SPECIFIC / project `docs/engineering-rules.md`) — render-increment full-guard-host run.** An increment that changes any TUI render module MUST run the FULL `test_tui_directionb.py` (the cross-cutting markup/rail/footer/count census guards live there), not a `-k` subset — the C-19 partial-run trap has a render-specific instance (Inc-1's markup-guard escape). Extends C-19.

## Items for next batch / carries
- **Closeout (this batch):** canonical-CI snapshot regen of the 21 `test_tc016s` cells (rail + Issues strip); optional density-matrix extension with `checks` cells; the `test_tc081_4` binding sanction is already applied.
- **LOW cosmetic:** stale "eight"/"1..8" prose in ~7 test docstrings (`test_tui_directionb.py` + `test_loadfilescreen_input.py:61`).
- **Backlog (unrelated, still open):** P-1b A2L CURVE/MAP sizing; P-2 re-freeze a2l.py; universal paste; Issues filter/sort (Issues screen now upgraded but filters unchanged).
