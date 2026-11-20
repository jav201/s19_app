# INC 1 — 04 validation record (E5)

Verdict: PASS. The central occupancy index is implemented, proven RED→GREEN with executed thresholds, and every negative-control mutant is KILLED. See `E4-report.md` for the stage detail.

## Runs and evidence (all executed on this host, Python 3.11.15 / s19env)

- RED on base: `evidence-e4/red-occupancy.txt` (15), `red-occupancy-perf.txt` (8, quadratic base measured: 999,000 / 15,996,000 checks), `red-occupancy-at.txt` (3).
- GREEN integrated: `evidence-e4/green-occupancy.txt` (15, regenerated after the source-arm fix), `green-occupancy-perf.txt` + conductor re-run `verify-perf.txt` (8 passed in 204.8 s), `green-occupancy-at.txt` (3; conductor re-run 18 passed in 139.2 s), `regression-inc1.txt` (459 regression nodes).
- Executed thresholds: index build median 0.158 s (≤2.5 s); all 220,040 resolutions 1.103–1.173 s (≤18 s, 0 oracle differences); public describe 12.848 s (≤30 s); traced peak within 64 MiB, 0 page-expansion records.
- Mutants: `evidence-e4/mutant-run.txt` (runner `mutant_runner.py`) — 14/14 KILLED after one ruled test fix (the no-gather/no-sort source arm inspected the monkeypatched wrapper; fixed and re-run KILLED).

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

- TUI acceptance: not commissioned for Inc 1 (no visual change; acceptance is at the public describe/encode route).
- Full-suite run and canon fold: batch-end obligations, executed there.

## Trace

`trace_check.py --req inc-1/01-requirements.md --base f44e8bc4 --src s19_app`: US/CASE/TEST/SLICE gaps 0; EVID gap closed by this file.
