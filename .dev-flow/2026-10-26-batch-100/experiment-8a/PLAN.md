# Experiment — Inc 8a run as a design-first pipeline

**Question:** does moving design defects to a code-free review (requirements → Code-Wire prototype → architect/security review) and running implementation and test design in parallel cut the wall time of an increment, without losing what the gates found?

**Baseline:** Inc 7, `baseline-inc7-timing.md` (687 min wall incl. the census tail; 2 corrective passes; 6 full-census launches; 8 MAJOR/HIGH-class findings, all found on code). Measured with `timing.py` (same script for 8a).

**Subject:** Inc 8a — the active change document is recorded and reopened (M-2, D4; PLAN.md roadmap row; LED .61 positive arm of TC-B100-70 and the panel `mark_saved`; LED .63 plan rows for the document and the merge; B-06 / A-15 arms owed at 8a). Sources: `app`, `manifest_writer`, `variant_execution_service`, `project_gather_service` (cap 4).

## Steps (one line in `steps.log` per step: `<UTC start> <UTC end> <step> <agents> <outcome>`)

| Step | Who (model) | Output | Done when |
|---|---|---|---|
| E1 Requirements | 1 agent (Opus) | the Inc 8a LLRs checked against EARS and ISO/IEC/IEEE 29148, fixed in place in `01-requirements.md`, one ledger entry | each 8a LLR has one EARS form, a measurable threshold and a negative control |
| E2 Prototype | 1 agent per file-ownership group, only if the slice has more than ~8 nodes (Opus) | Code-Wire graph of the 8a slice: changed and new functions with examples from the LLRs; new functions as stubs with marks; extractor report (real callers) on main | the extractor exits 0 on the stubbed tree; every LLR has at least one example |
| E3 PDR | architect + security reviewer, in parallel (Opus) | findings on the graph, stubs and callers; iterate until no MAJOR | no open MAJOR/HIGH |
| E4 Build | implementer(s) by file ownership (Opus) ∥ tester (Opus) writing tests from the graph examples, RED on main | code + tests | tests GREEN on the tree, RED behavioural on main |
| E5 Change validation | targeted tests (touched modules + importers of changed functions), mutants of the new arms only; code-reviewer + security-reviewer on code (Opus) | review records | no open MAJOR/HIGH |
| E6 Full validation | one reverse census, split in 2 processes, once; guards; corrective passes (Sonnet) re-run only what they touch | census + guards transcripts | known failures only |

Close as usual (records, merge, push, CI).

## Rules for the run

- No source or scope change while a census runs; late items go in before it starts.
- Corrective passes and mechanical work on Sonnet (memory rule, provisional).
- Nothing new is added to the flow during the run; anything that looks missing is written as an observation for the comparison.

## What is compared with Inc 7

1. Wall time (total and per step), and time agents sat idle on background runs.
2. Where each MAJOR/HIGH finding was caught: E3 (no code) vs E5/E6 (code).
3. Number of corrective passes and full-census launches.
4. Size, to normalise: LLRs in scope, source lines changed, tests added.

Inc 8a is smaller than Inc 7, so wall time alone does not decide; per-LLR time and where the findings were caught do.
