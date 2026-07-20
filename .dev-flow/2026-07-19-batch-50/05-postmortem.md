# 05 — Post-mortem · batch-50 (a2l.py F841 cleanup + re-freeze)

**BLUF:** The batch's real value was the **Phase-2 draft-time-execution catch**: running the A2L parser over the real fixture (not just reading the code) revealed that P-1b's headline acceptance was unrealizable on multi-line A2L — *before* a single line of P-1b was implemented. The V-model gate did its job: P-1b was descoped by operator decision, F841 shipped clean (1593 passed, 0 failed, independent APPROVE), and P-2 re-freeze is correctly sequenced to post-merge PR-B. What shipped is small; what was *prevented* (a wasted safety-critical parser increment that fires on nothing) was the win.

*(Authored by the orchestrator — a 2-file batch does not warrant dispatching architect+qa co-authors; recorded as an autonomous efficiency decision.)*

## What worked
- **Draft-time EXECUTION over the real input caught a spec-vs-reality collision.** At Phase 2 the orchestrator ran `parse_a2l_file(ASAP2_Demo_V161.a2l)` and found 49/50 CHARACTERISTICs parse `char_type=None` — the parser only reads single-line headers; the demo is multi-line. Pure code-reading (even the architect's first pass) only partially surfaced this; execution nailed it. This is the batch's central lesson (candidate control below).
- **The Phase-2 gate + escalation worked as designed.** Two blockers → surfaced to the operator with three concrete options + tradeoffs → clean descope, not a forced half-ship.
- **Correct sequencing held.** F841 first (a2l.py legitimately unfrozen), P-2 re-freeze as a guard-files-only post-merge PR-B — the "edits first, re-freeze last" constraint was mechanically validated (guard diffs vs `main`).
- **Clean single increment.** F841: 1-line dead-store delete + a non-vacuous behavioral sentinel (AT-094) routed to a non-frozen sibling; independent `code-reviewer` APPROVE with every pinned literal re-derived. C-34 full guard-host run (174 passed) caught no escape.
- **Rich P-1b analysis preserved** (`01-requirements.md §7` + `02-review.md`) as a verified future-batch seed — the position-index insight, the real oracle values (25 B / 51 B not 146), the multi-line prerequisite, the C-31/C-12 AT corrections — so the future batch starts from ground truth, not a re-derivation.

## What didn't / friction
- **P-1b's requirement was written against an assumed parser capability that doesn't exist.** Phase 1 cited the demo fixture (`ASAP2_Demo_V161.a2l:3321`) as the acceptance surface as if it would parse — a draft-time-verification gap. Had the parser been *executed* over the fixture at Phase 1 (not just read alongside it), the collision would have surfaced one gate earlier, before the full triple-review spend on a to-be-descoped story.
- **The nominal batch ("finish the A2L length work", 3 items) delivered 2.** Not scope creep — a scope *reduction* forced by a discovered pre-existing limitation. Honest, but the "finish" framing was optimistic given P-1's own silent no-op on multi-line files was never surfaced before.

## Scope drift
None (bad sense). Scope was REDUCED via a documented operator AskUserQuestion decision (defer P-1b), with §6.5 Before/After recorded and the analysis retained. No silent scope change.

## Metrics
- **Iterations/phase:** 0 / 0 / **1** / 0 / 0 (the single Phase-2 iterate = the P-1b descope).
- **Tests:** +2 (`test_a2l_f841_cleanup.py`: TC-094 + AT-094); −0. Gate: **1593 passed, 0 failed**, 2 skipped, 3 xfailed; 29 snapshots no drift.
- **Findings:** Phase-2 = 2 blockers + 8 majors + ~7 minors (ALL on P-1b, retired with the descope) + 0 security blocker/major. Inc-1 code-review = 0 findings.
- **Engine-frozen diffs:** 0 (a2l.py sanctioned-unfrozen; re-freeze is PR-B).
- **Un-asked decisions (recorded):** P-2→follow-up-PR ruling; P-1b scope lock (operator); Phase-0/1/3/4 gate self-approvals; postmortem self-authoring. All in `state.json.decisions_log` + PLAN.

## Root cause (the Phase-2 iterate)
P-1b was specced from **reading** the parser + fixture separately; the single-line-header assumption in `parse_characteristic_header` (`a2l.py:324-330`) vs the multi-line demo file is an *interaction* invisible to reading either in isolation. Root cause = a draft-time-verification method gap: the existing "verify claims against disk/execution" rule was satisfied by citing the fixture's existence, not by executing the pipeline over it.

## Items proposed for the next batch(es)
1. **P-2 re-freeze PR-B** (this batch's closeout) — guard-files-only, off merged main.
2. **Future P-1b batch** — multi-line CHARACTERISTIC/AXIS_DESCR header parsing FIRST (the real prerequisite), THEN the inline-axis length summer. Seed: `01-requirements.md §7`. Consider whether P-1 (scalar VALUE) also warrants the multi-line fix (it silently no-ops on the demo too).
3. **Batch-49 `/dev-flow-sync`** — still pending, independent carry.

## Candidate control (for operator ruling at the Phase-5 gate)
**Draft-time EXECUTION of the target transform over the real input** — when a requirement's acceptance asserts that a *specific real input* produces *specific parsed/derived output* through a transform (parser, extractor, pipeline), the Phase-1/2 draft-time verification MUST **run the transform over that input** and confirm the fields exist, not merely read the transform's code and the input file separately. Reading both in isolation misses their *interaction* (here: single-line-header parser vs multi-line file → 49/50 fields `None`). General/portable → extends the batches-05-11 draft-time-verification rule and the C-15 / C-15.1 (writer-census) family from "probe the state's writers" to "execute the producer over the real input." Classify: portable requirements-verification discipline → **global `dev-flow.md`** (not stack-specific). Pending operator AskUserQuestion before encoding.
