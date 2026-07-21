# 05 — Post-mortem · batch-56 (alignment-aware padding sizing)

> Co-authored view (architect + qa lenses), orchestrator-synthesized under the autonomy grant. BLUF-first.

## BLUF
batch-56 shipped alignment-aware CURVE/MAP sizing in one clean PR-A: `_record_layout_full_span` now models ASAM `ALIGNMENT_*` inter-component padding via a cumulative-offset walk, closing batch-55's code-review F1 (blanket force-`None`) WITHOUT perturbing any packed layout (demo 25/51/12/None byte-identical). 2 US / 2 HLR / 8 LLR / 11 gate ATs, all green; 0 HIGH across 3 Phase-2 reviewers + the increment code-review; 0 new snapshot drift. One real security bug (zero/negative-alignment div-by-zero) was caught at Phase-2 by the security-reviewer and designed out before implementation.

## What worked
- **Resume-from-parked was clean.** Phase-0/1 artifacts (WIP `741e86e`, Phase-1 only, no code) recovered onto a fresh branch off the current `origin/main` tip; RC-1 re-run confirmed the feature still unshipped. Zero rework — the parked spec was sound and directly usable.
- **C-35 draft-time execution paid off twice.** The Phase-1 probe had already executed the alignment math over a synthetic fixture + the real demo, so Phase-3 oracles matched on the first pass (none adjusted). The demo's "no body `ALIGNMENT_*`" fact (probe-confirmed) is what made "0 expected drift" a hard prediction that held.
- **The two-doc split surfaced real reconciliation, not noise.** 01-requirements and 01b-qa-catalog disagreed on id ranges, primary fixture (8/7 vs 16/13), test-file, and R-C. Phase-2 folded them into one canonical registry; the multi-class 16/13 fixture (exercises 2 alignment classes, R-C-independent) is a strictly stronger gate oracle than the single-class 8/7.
- **Security-at-Phase-2 caught a bug the spec missed.** `ALIGNMENT_WORD 0` → `align_up(o,0)` → `o % 0` ZeroDivisionError, uncaught by the `(ValueError, TypeError)` clause. Designed out as two `shall`s (collector non-positive fail-close + `align_up` `a<=1` short-circuit) BEFORE any code — the AT-122 hostile-value test and TC-146 guard now pin it.

## What didn't (watch-items)
- **Two Phase-1 docs with independent id/oracle authorship is a recurring reconciliation tax.** Both were internally sound but assigned the SAME id (AT-113) two oracles. Cost one Phase-2 fold cycle. Not a defect (the fold is designed for exactly this), but a lighter-weight convention (one doc owns ids, the other references) would remove the friction. Candidate carry, not a control.
- **The 19-cell snapshot drift is a cross-batch debt that keeps surfacing in every gate run.** It is NOT batch-56's, but it forces a 19-cell "is this mine?" analysis every batch until the canonical-CI regen lands. Closing it (BACKLOG TOP) would clean the gate signal.

## Scope drift
None. Stayed inside `_record_layout_full_span` + one helper + one map + the unfreeze + tests + prose. MOD_COMMON honoring was explicitly deferred (RISK-1, operator ruling); R-C trailing-pad explicitly rejected (reading i). No speculative abstraction.

## Metrics
- Iterations/phase: Ph2 = 1 (single fold), Ph3 = 0 (increment code-review APPROVE first pass), Ph4 = 0. No phase hit the soft cap.
- Findings: Phase-2 3 blockers (all reconciliation) + ~6 major (1 real security, rest coverage/reachability) + minors — ALL closed in the fold. Increment code-review: 0 HIGH/0 MED, 1 LOW (accepted). Open: 0.
- Tests: +17 new (alignment suite) + 0 net supersede (2 assertions re-valued). Gate suite 1794 passed.
- Files: PR-A = 6 (a2l.py + 2 tests + 2 guards + REQUIREMENTS.md) across 3 increments, each ≤5. PR-B = 2 (guards).

## Items proposed for the next batch / carries
1. **PR-B re-freeze** (post-merge, guard-files-only): re-insert `a2l.py` into both `_ENGINE_PATHS`; TC-153/AT-121; `git diff main -- a2l.py` empty.
2. **RISK-1 MOD_COMMON follow-up** (deferred, reversible): honor module-wide `ALIGNMENT_*` defaults — needs a non-demo alignment oracle fixture. Only when a real MOD_COMMON-aligned corpus surfaces.
3. **batch-58+59 snapshot-regen** (canonical-CI ONLY): the 19 tc016s cells — regen via `snapshot-regen.yml`, local `--snapshot-update` forbidden.
4. **P-3 (A2L) reason-string precision** — still blocked by frozen tc032.
5. **Convention candidate (not a control):** when Phase-1 splits into a spec doc + a qa catalog, have ONE own the AT/TC ids and the other reference — removes the Phase-2 id-reconciliation tax seen here.

## Decisions taken autonomously (not asked — per the grant)
- Phase-2 gate self-approved after the fold (all blockers were unambiguous reconciliations); Phase-3/4 gates self-approved on green + code-review APPROVE.
- Canonical fold choices: multi-class 16/13 primary fixture; NEW `test_a2l_alignment_sizing.py` (increments re-cut to keep ≤5/inc); AT-122 merging sec-M3+qa-M4; R-C=17 (operator's no-trailing ruling); MOD_COMMON=26 as AT-114's named RED.
- 04-validation.md written inline (reconciliation of already-collected gate + review evidence) rather than via a fresh qa sub-agent — a token-economy call under the autonomy grant; evidence is fully cited and re-runnable.
- All recorded in `state.json.decisions_log` + PLAN.md + here; carried to the vault at `/dev-flow-sync`.
