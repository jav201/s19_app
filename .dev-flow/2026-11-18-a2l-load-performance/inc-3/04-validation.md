# INC 3 — 04 validation record (E5)

Verdict: PASS. The prepared-load routes (image+A2L, project pair ±MAC, A2L-only) are implemented with pre-reset preflight and one final publication, after two executed design returns (D-14 budget re-calibration, D-15 superseded-arm ruling). See `E4-report.md`.

## Runs and evidence (all executed on this host, Python 3.11.15 / s19env)

- RED on base: `evidence-e4/red-inc3-parity.txt` (35), `red-inc3-perf.txt` (4); behavioral smoke without guards confirmed route-level RED (0 producer calls, fallback instead of failure, acceptance instead of superseded).
- GREEN integrated: `green-inc3-parity-fixed.txt` (35/35) + conductor re-run `verify-parity.txt` (35 passed, 514 s); `green-inc3-perf-fixed.txt` (4/4 with the D-14 budget: 12 serial case_06 runs, median ≤80 s, run <100 s, responsiveness clauses intact); `inc2-regression-fixed.txt` (Inc 2 suite 37/37 on the Inc 3 tree).
- Regressions: b103 refresh 102 passed (pre-existing .005 flake reproduced on base); b100 workers 79 passed (2 pre-existing base failures + 1 order/timing flake, 3/3 isolated). None deterministic-new.
- Mutants: `evidence-e4/mutant-run.txt` + `mutant-run-ruled.txt` (runner `mutant_runner.py`) — 13/13 KILLED after two ruled mutant re-shapes (039 producer-bypass targeted all five arms; 048-l1 mutant disables both L1 guards).

## Reviews

Independent code/security review of the batch: `../evidence/e5-review.txt`.
Verdict: SIN BLOCKERS; the two MAJORs (D-13 gc re-enable on install-exception
paths) were ruled covered with executed evidence — the worker-side
`except BaseException` handlers re-enable the collector after
`call_from_thread` re-raises UI-thread exceptions; two new permanent arms
lock the invariant (test_r038_install_exception_reenables_gc,
test_r043_install_exception_reenables_gc, both green). Four MINOR findings
go to the backlog. Nothing open against this increment's slice.

## Not run

- E5 full-suite run: batch-end obligation, executed there.

## Trace

`trace_check.py --req inc-3/01-requirements.md --base f44e8bc4 --src s19_app`: US/CASE/TEST gaps 0; SLICE clean; remaining gaps are `a2l_definition.py` (Inc 1's file, closed at batch end) and EVID, closed by this file.
