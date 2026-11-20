# E1 integration record

Base product commit: `f44e8bc4266b6dead6ff24adef71fdb0b7b0154c`; E0 commit: `d658dfeaa336dea54b99001b52df52fa1fd434d0`. This is a requirements-stage record, not a product validation verdict.

## Integrated increments

| Increment | New requirements | Planned alternatives | Planned ATs | SOURCE budget | E1 outcome |
|---|---:|---:|---:|---:|---|
| Inc 1 — occupancy index | R-A2L-DEF.156 through .165 (10) | 21 + 10 preserved-regression links | 3 | 1 source; 4 delta nodes | Integrated after mechanical-audit corrections |
| Inc 2 — responsive direct attach | R-A2L-REFRESH.029 through .038 (10) | 33 | 3 | 4 source; 7 function nodes + 4 data contracts | Integrated after mechanical-audit corrections |
| Inc 3 — prepared-load parity | R-A2L-REFRESH.039 through .048 (10) | 29 | covered by the route ledger | 4 source; 13 implementation nodes | Integrated after mechanical-audit corrections; depends on the frozen Inc 2 interface |

Total: 30 new requirements, 83 planned requirement alternatives, 6 explicitly allocated Inc1/Inc2 ATs, and 10 preserved-regression links. Inc3's 29 alternatives include its route acceptance coverage. No case result was inferred from this planning count.

The conductor accepts the documented Inc 1 index direction and Inc 2 option-A adapter/data contracts, including `_accepted_a2l_picker_snapshots`, for E2 elaboration and E3 review. This is not approval to implement before E3 closes.

## Mechanical audits and dispositions

DeepSeek was actually invoked through `pi` 1.5.0 using `deepseek-flash`, low thinking and read-only tools. Three scoped audits completed:

- `evidence/deepseek-e1-audit-inc1.txt`: 12 findings/observations; threshold assertions, watchdog protocol, AT coverage, full-case oracle independence/protocol and ownership were corrected or verified against the cited generated census. Dispositions are in `inc-1/E1-rulings.md`.
- `evidence/deepseek-e1-audit-inc2.txt`: 8 findings; exact keys, >1 s holds, summary-failure arm, full/partial accounting, snapshot attribute, mismatch arms and trace granularity were corrected. Dispositions are in `inc-2/E1-rulings.md`.
- `evidence/deepseek-e1-audit-inc3.txt`: 5 findings; baseline composition, project-without-MAC arms, collected-node wording, total-load budgets and L1 route mapping were corrected or explained. Dispositions are in `inc-3/E1-rulings.md`.

Qwen CLI 0.27.4 was actually invoked read-only for the initial censuses, a combined retry and three scoped retries. The initial runs stopped at the eight-tool budget; the combined/scoped retries exhausted their wall-clock limits. No substantive census or audit was returned. Unmodified outputs are in each increment's `evidence-e1/qwen-census.txt` and root `evidence/qwen-*.txt`. No finding is attributed to Qwen.

## Verification at E1

- Inc 1 final validator: PASS for 12 audit fixes and 10 regression links; linked existing nodes resolve. Its regenerated baseline is observational only.
- Inc 2 structural validator: PASS; 10 requirements, 33 alternatives, 3 ATs, 34 planned collected nodes, 4 SOURCE; known-bad controls are RED.
- Inc 3 structural validator: PASS; 10 requirements, 29 alternatives (16 normal, 4 performance, 9 robustness), 4 SOURCE; generated RED controls and baseline extraction are retained.
- Root traces regenerated at integration: `evidence/trace-inc1-e1.txt`, `trace-inc2-e1.txt`, `trace-inc3-e1.txt`.
- Each trace has zero US, CASE or SLICE gaps. The remaining gaps are exactly the ten future TEST links per increment and the future E5 `04-validation.md`; exit 1 is expected at E1 and is not an E5 result.
- Code-Wire baselines have zero unread lines. Inc3 baseline comprises 9 changed functions plus 3 context functions; dataclasses are outside the function extractor.
- `git diff` over `s19_app`, `tests` and `REQUIREMENTS.md` is empty. No product or product-test edit exists.
- Personal-path scan over the batch found zero `C:/Users`, `C:\\Users`, `/c/Users` or `/home/<account>` forms after redaction at generation.

## Next stage

E2 authors graph deltas only. Inc1 and Inc2 may proceed in parallel on disjoint record directories. Inc3 may prepare its baseline and review dependencies, but its final delta waits for the Inc2 interface to be frozen. No source implementation begins before the applicable E3 review closes with no open BLOCKER/MAJOR and the conductor authorizes E4.
