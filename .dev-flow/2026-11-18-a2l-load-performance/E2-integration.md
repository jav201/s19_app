# E2 integration record

E1 commit: `85e68957`. Code-Wire: v3.2.0, commit `b6cd30d62bf46abbe2f9375e8c04b296f1eeaf05`. This stage contains graph prototypes only; no product implementation or functional result is claimed.

## Integrated graphs

| Increment | Graph | Nodes | Requirements/examples | Lint |
|---|---|---:|---|---|
| Inc1 | `inc-1/codewire/graph-inc1.md` | 4 functions | 10 requirements; 21 alternatives | 0 unread |
| Inc2 | `inc-2/codewire/graph-inc2.md` | 7 functions; 12 entities | 10 requirements; 33 alternatives; 43 example links | 0 unread |
| Inc3 | `inc-3/codewire/graph-inc3.md` | 12 functions plus S1 data entity | 10 requirements; 29 cases; 89 integrated graph examples | 0 unread |

Inc3 also retains the three owner graphs and an integration check with a known-bad missing-node control. Its 13 implementation nodes and four-SOURCE boundary reconcile with E1. Inc2's graph validator reports four discriminating self-test failures, including rejection of the old request-bound producer signature. Inc1's four-node slice and all caller mappings remain unchanged.

## Interface rulings applied

`interfaces.md` is the single conductor-owned contract. The following proposals were accepted and integrated rather than left for implementers:

- Inc2 A3 has one route-neutral, explicit-input signature used by direct attach and Inc3.
- A7/A8 field names, snapshot preflight authority, shallow cache-list conversion and absent/mismatched picker behavior are fixed.
- Inc3's `PreparedLoad`, `ProjectLoadRequest` and `PreparedProjectLoad` handoff fields and current-counter preflight rules are fixed.
- Existing busy/progress and terminal outcome are control transitions, not A2L result installation.
- R-A2L-REFRESH.047 now distinguishes changed content from generation movement caused by reinstalling unchanged content. Changed content must publish under a newer generation; unchanged source bytes remain identical; the existing writer/reset stages may increment generations. This resolves CW-I3-F-05 and E2-P-03 without changing product behavior.

No open design/interface finding remains in the integrated Inc3 graph. E3 review is still required; a clean lint is not design approval.

## Evidence and limits

- Inc1: `inc-1/E2-report.md` and `inc-1/evidence-e2/lint-graph-inc1.txt`.
- Inc2: `inc-2/E2-report.md`, `evidence-e2/codewire-lint.txt`, `structural-validation.txt` and baseline extraction.
- Inc3: `inc-3/E2-integration.md`, the three owner reports and `inc-3/evidence-e2/integrated/integration-check.txt` plus integrated lint.
- No product/test/canon edit exists. No real application load, timing PASS, memory PASS, functional mutant result or clipboard action is claimed.
- Layered extraction against a future implemented Inc1/Inc2 tree remains an integration obligation; no such tree is claimed at this stage.

## Next stage

Run one independent design/security E3 review per increment in parallel. Reviewers consume the requirements, graph, interfaces and real callers. Any BLOCKER/MAJOR returns to the owning records for targeted correction and re-review before E4.
