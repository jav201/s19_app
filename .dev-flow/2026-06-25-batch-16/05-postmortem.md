# Post-mortem — s19_app — Batch 2026-06-25-batch-16 (US-017 / GAP #2)

> Phase 5 artifact. Co-authors: `architect` + `qa-reviewer`.

## 🔑 At a glance
- **Outcome:** closed clean — PASS, 0 defects, 0 blocker fails. **batch-11 SCOPE-1 closed at the shipped surface.**
- **Scope:** US-017 — per-variant `assignments` + project-wide `batch` assigned at project save, persisted to `project.json`, proven through the save handler.
- **Increments:** 2 (Inc1 payload+handler threading; Inc2 the assignment UI). **0 engine-frozen edits AND `manifest_writer.py`/`variant_execution_service.py` edit-free** — the entire change was surface-wiring on a sound substrate.
- **Ledger:** 922 → 933 (Inc1 +7 / Inc2 +3 / Phase-4 e2e +1). Full suite **900 passed / 0 failed**.
- **Iterations:** {0:1,1:1,2:1,3:1,4:1}. Findings: 0 blocker / 4 major / 9 minor (all folded iter-2); code-review 2/2 APPROVE (no HIGH/MED); security MANDATORY granted.

## Top 3 lessons
1. **G-3 — a SCOPE-1-shaped gap inside the batch that closes SCOPE-1.** The first-cut consumer-pickup AT (AT-017.2) wrote `project.json` *directly* and exercised only the unchanged consumer — it never drove the shipped handler. The batch whose whole purpose was to close "tested via direct-kwargs, not the shipped surface" nearly shipped its own acceptance test the same way. Phase-4 validation flagged it honestly (didn't bury it to keep the gate green); the operator iterated; a true e2e AT (handler save → re-read the *handler-written* `project.json` → `plan_variant_executions` → exact tuple) was added. Root cause: the **output-then-consume test asymmetry** — a same-values direct write is a white-box pickup test wearing a black-box AT's clothes, and it's always cheaper to author and still passes.
2. **The A-5 / surface-reachability diagnosis was right and is *proven* right.** 0 substrate edits (`git diff` empty over both consumer files) is the falsifiable receipt: the capability existed since batch-11; only the operator-reachable path to it did not. The cost profile was almost entirely test-authoring — the economic signature of a wiring fix, not a build.
3. **The pre-code controls fired.** RC-1 base-currency gate (first real use) confirmed `origin/main`=b734c19 and cut fresh — the batch-14 stale-base precondition was checked and held (preventive; not yet battle-tested against a live reject). The consumer-input-contract control surfaced **D-KEY** (variant_id = stem *except on stem-collision* → full filename) at Phase 2, caught by *both* architect and qa before a line keyed off `Path.stem`.

## What worked
- Engine-frozen + substrate invariant held end-to-end (0/0 edits); the feature lived entirely in `app.py`/`screens.py`/`styles.tcss` + tests.
- Security treated as MANDATORY: AT-017.4 asserts a *positive* refusal (notice surfaced + `project.json` not written) through the shipped handler, not just the writer's unit gate.
- Counterfactual actually run (production reverted → 4 handler ATs RED → restored clean), not asserted.
- D-NEWPROJ design fork resolved without a load-pipeline refactor (`action_save_project` already had the variant set in scope).
- Phase-4 honesty: validation contradicted its own spec enumeration (AT-017.2 was GREEN pre-fix, not RED as §5.3 listed) and surfaced it as G-3 rather than rationalizing.

## What didn't / scope drift
- **G-3 producer-bypassing AT** (above) — the headline near-miss; legitimate iterate-to-refine, not debt.
- **TypeError-RED counterfactual is weak** — the 4 handler ATs go RED pre-fix via a missing-kwarg `TypeError` (constructor-shape), not a behavioral assertion. Adequate here (post-fix assertions are exact-tuple/deep-equal, value-discriminating) but the value-sensitivity was *inferred*, not asserted.
- **AT-017.5 (D-KEY collision) was a Phase-2 rescue**, not a first-cut AT — the boundary catalog has to be applied deliberately; AT authors default to the happy path.
- No true scope drift otherwise (5 files, all in the wiring layer).

## Root causes
- **G-3:** output-then-consume stories admit two passing shortcuts (producer output without a consumer; consumer over a hand-written artifact). The seam — "does the consumer pick up what the *handler* produced?" — is exactly the surface-reachability property the SCOPE-1 line defends.
- **Original gap:** batch-11 shipped the engine half (writer/verifier/consumer kwargs) and deferred the surface half — a stop-at-boundary that left a capability no operator path could reach.

## Metrics
| Dimension | Value |
|---|---|
| Test ledger | 922 → 933 (+7 / +3 / +1), reconciles to `--collect-only` |
| Engine-frozen edits | 0 |
| Substrate edits (manifest_writer / variant_execution_service) | 0 (falsifiable proof of the A-5 diagnosis) |
| Iterations/phase | {0:1,1:1,2:1,3:1,4:1} |
| Findings | 0 blocker / 4 major / 9 minor (all folded iter-2); security MANDATORY granted |
| Code review | 2/2 APPROVE (Inc1 2 LOW / Inc2 2 LOW); 0 HIGH/MED |
| Full suite | 900 passed / 0 failed (933 collected) |

## Carries / next-batch items (reconciled with BACKLOG.md)
**Closed:** GAP #2 / US-017 — DONE (SCOPE-1 closed, counterfactually proven).
**NEW control — C-12 / QC-1 (propose folding into the dev-flow C-10 family, global `~/.claude`):** *output-then-consume AT discipline* — for any story whose deliverable is later consumed, the black-box AT MUST observe the consumer over the **handler-produced** artifact in one chain (drive shipped handler → re-read what it wrote → feed the unmodified consumer → assert exact outcome); a direct-write fixture is a *consumer-contract guard* kept in addition, never the gate. The same rule would have failed the first-cut AT-017.2 at authoring time instead of Phase-4. (Extends C-10: C-10 bans default-value-reliant pilots; C-12 bans producer-bypassing pilots.)
**QC-2:** when a counterfactual RED is shape-based (`TypeError`), the validation artifact must carry an explicit line confirming the *post-fix* assertion is value-discriminating.
**QC-3:** apply the boundary catalog (empty · boundary · invalid · error) as a pre-Phase-3 checkbox so boundary ATs (like the collision case) are authored up front, not rescued in review.
**QC-4:** keep AT and TC independent — the G-3 fix correctly added an AT without weakening a TC; preserve that separation.
**Standing:** C-9 (hex-window compare AT), CRC-width AT, **C-7/4a** app.py ruff F401 (NOT introduced — own micro-PR), C-6 (retire TC-230/231 ids), N-2 / obsidian_synced flip ride-along, and `/dev-flow-sync` after merge.
