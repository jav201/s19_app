# INC 2 — 04 validation record (E5)

Verdict: PASS. The direct-attach snapshot route is implemented and proven responsive through post-parse preparation, after three executed design returns (D-11 capture bound, D-12 refresh window, D-13 generational-GC fix). See `E4-report.md`.

## Runs and evidence (all executed on this host, Python 3.11.15 / s19env)

- RED on base: `evidence-e4/red-inc2-attach.txt` (37/37 RED, 100.8 s), `red-inc2-existing.txt` (edited suites neutral on base, 64 passed).
- GREEN integrated: `evidence-e4/chunk1.txt` (17) + `chunk2.txt` (20) = 37/37, 0 failures, sequential chunks; the three full-suite attempts produced one load-fatigue flake each, fixed test-side (sampler poll 20→50 ms, confirm-modal polling) and each node verified green in isolation.
- Regressions: `regression-inc2-a` (72 passed), `regression-inc2-b` (190 passed, 1 xfailed, 5 failed — all classified pre-existing or load flakes; none deterministic-new).
- D-13 evidence: `probe-d13-mechanism.txt` (plain ticker peak 1.125 s vs 0.406 s with the collector disabled), probes d12b–d12f.
- Mutants: `evidence-e4/mutant-run.txt` + `mutant-run-ruled.txt` (runner `mutant_runner.py`) — 13/13 KILLED after three ruled test/mutant fixes (census covered the D-13 `_inner` helper; .031 observes the key at refresh entry; 036-drop-cache mutant repositioned pre-refresh).

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

- E5 full-suite run and canon fold: batch-end obligations, executed there.

## Trace

`trace_check.py --req inc-2/01-requirements.md --base f44e8bc4 --src s19_app`: US/CASE/TEST gaps 0; SLICE clean after naming the two adapters in the requirements file; remaining gaps are `a2l_definition.py` (Inc 1's file, closed at batch end) and EVID, closed by this file.
