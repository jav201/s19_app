# INC 1 — E4 build and test record

Base: `905e9b99` (E3 close). Slice: 4 nodes in `s19_app/tui/a2l_definition.py`. Implementer: DeepSeek v4 Pro lane G1 (Hermes subagent). Independent tester: DeepSeek v4 Pro lane G-T-I1 (Hermes subagent). Integration, verification, negative controls and rulings: the conductor.

## RED on base

The tester wrote `tests/test_alp_a2l_occupancy.py` (15 nodes), `tests/test_alp_a2l_occupancy_perf.py` (8 collected nodes) and `tests/test_alp_a2l_occupancy_at.py` (3 nodes) from the E1/E3 ledger, then executed them against base `905e9b99` with zero product edits: 26/26 collected nodes RED.

- `evidence-e4/red-occupancy.txt` — 15 failed, exit 1 (0.94 s)
- `evidence-e4/red-occupancy-perf.txt` — 8 failed, exit 1 (17.25 s); the disjoint arms measured the quadratic base directly: 999,000 checks at 1,000 names and 15,996,000 at 4,000, against bounds of 20,000 / 100,000
- `evidence-e4/red-occupancy-at.txt` — 3 failed, exit 1 (18.34 s)

## GREEN on the integrated tree

`describe_definitions` now builds one central occupancy interval index per request (`_build_occupancy_index`), resolves each addressed result's own position, and advances through `_occupancy_candidates` position-ordered tree traversal in `_shared_with`. The legacy global scan and page gather/sort are gone. Public signatures and result shapes unchanged.

Executed on the integrated tree (s19env Python 3.11.15):

| Suite | Result | Evidence |
|---|---|---|
| occupancy (15 nodes) | 15 passed, exit 0 | `evidence-e4/green-occupancy.txt` (regenerated after the source-arm fix) |
| occupancy perf (8 nodes) | 8 passed, exit 0 | `evidence-e4/green-occupancy-perf.txt`; conductor re-run `evidence-e4/verify-perf.txt`: 8 passed in 204.8 s |
| acceptance (3 nodes) | 3 passed, exit 0 | `evidence-e4/green-occupancy-at.txt`; conductor re-run: 18 passed in 139.2 s |
| Regression: R-A2L-DEF.138/.139 nodes | 25 passed | `evidence-e4/regression-inc1.txt` |
| Regression: .140 family (arrays write) | 64 passed | `evidence-e4/regression-inc1.txt` |
| Regression: full test_b103_a2l_definition.py | 310 passed | `evidence-e4/regression-inc1.txt` |
| Regression: picker suites (b103_picker_model, inc8 picker, b102 parameter picker) | 60 passed | `evidence-e4/regression-inc1.txt` |
| Smoke: public describe over case_06 (220,040 tags, 0 parse errors) | no exception, shared_with resolved | `evidence-e4/regression-inc1.txt` |

Executed thresholds on the E1 reference host (this machine):

- R-A2L-DEF.162 (index build): median 0.158 s ≤ 2.5 s
- R-A2L-DEF.163 (all 220,040 resolutions): median 1.103–1.173 s ≤ 18.0 s, 0 oracle differences
- R-A2L-DEF.164 (traced peak): ≤ 64 MiB, 0 page-expansion records
- R-A2L-DEF.165 (public describe of all names): median 12.848 s ≤ 30.0 s; AT-ALP-I1-1 13.183 s
- R-A2L-DEF.158: both parametrizations at 1,000/4,000 with checks ≤ bounds and exactly 1 construction

## Negative controls — mutant run

`evidence-e4/mutant_runner.py` applies each planned E1 negative control as a real source mutant in a copy of the tree and runs the discriminating node. Transcript: `evidence-e4/mutant-run.txt`.

13/14 mutants KILLED on the first pass. One survivor is a ruled finding:

- **E4-INC1-F1 — the no-gather/no-sort source arm was vacuous.** `_assert_no_gather_sort` inspected the monkeypatched test wrapper instead of the product function, so the planned gather-without-sort control survived with a green test. Ruling: test-only fix — the arm now receives the unpatched function captured before instrumentation. Re-run of the same mutant: KILLED. The unmutated tree stays 15/15 green after the fix.

Final score: **14/14 KILLED, 0 unruled survivors**.

## Trace

`trace_check.py` on the increment: US/CASE/SLICE/TEST gaps 0; only the EVID gap for the future `04-validation.md` remains (E5 deliverable).

## Not run at E4

- TUI acceptance: not commissioned for Inc 1 (no visual/interaction change; acceptance is at the public describe/encode route).
- E5 validation record, full-suite run, canon fold: batch-end obligations.
