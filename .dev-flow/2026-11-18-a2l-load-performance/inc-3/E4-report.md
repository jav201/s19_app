# INC 3 — E4 build and test record

Base: `ceac08cf` (E4 Inc2 close). Slice: 4 source files (`shared.py` S1, `file_load.py` F1–F6, `project_load.py` P1–P5, `loaded_state.py` L1), 13 nodes per the integrated graph and I-ALP-3. Implementer lane: DeepSeek v4 Pro (Hermes subagent, hit its iteration cap — work verified below). Independent tester lane and repair lane: DeepSeek v4 Pro (Hermes subagents). Rulings D-14/D-15, integration, mutant runs and verification: the conductor.

## RED on base

Tester lane executed 39/39 RED against base `ceac08cf` (35 parity + 4 performance; fast seam guards; behavioral smoke without guards confirmed the route-level RED: 0 producer calls on base, `.043` falls back with "Loaded img2.s19", `.048` accepts instead of superseding). Evidence: `red-inc3-parity.txt`, `red-inc3-perf.txt`.

## GREEN on the integrated tree

- Parity: **35/35** — implementer lane `green-inc3-parity.txt` (28/35 before the test-defect fixes), repair lane `green-inc3-parity-fixed.txt` (35/35), conductor re-run `verify-parity.txt` (35 passed, 514 s).
- Performance: **4/4** with the D-14 recalibrated budget — `green-inc3-perf-fixed.txt` (12 serial case_06 runs; median ≤80 s, every run <100 s; timer 50 ms/100 ms, ≥3 ticks in the 0.20 s gate, four named phases, one producer call per load all passing).
- Inc 2 suite on the Inc 3 tree: **37/37** — `inc2-regression-fixed.txt` after the D-15 amendment of `.037/4`.
- Regressions: b103 refresh 102 passed with the pre-existing `.005` flake (reproduced on base); b100 workers 79 passed with the two pre-existing base failures and one order/timing flake (passes 3/3 isolated). Classified in the implementer's `conflicts.md`; none is a new deterministic regression.

## Design returns and rulings (E1-rulings §6)

- **D-14** — the E1 total-duration budgets (median 45 s / run 60 s) came from unexecuted oracle inputs and are unattainable with the frozen I-ALP-2.2 producer (executed medians 62.7–71.5 s: parse 15.2 s, preparation 37.5–51.1 s, install/publication 9.8–12.1 s). Ruling: thresholds amended to median ≤80 s / run <100 s on the E1 host; the responsiveness clauses (timer, ticks, phases, one producer call) unchanged; the negative holds move to 105 s. Requirements and ledger amended in place.
- **D-15** — the Inc 2 `.037/4` adapter-mismatch arm contradicted I-ALP-3 (replacement-with-fresh-snapshot vs invalidation-to-empty on the same prepared routes). Ruling: I-ALP-3 wins; the arm's route variants now assert replacement semantics and the adapter mismatch→empty→describe guard is covered by a directly constructed mismatch state.

## Negative controls — mutant run

`evidence-e4/mutant_runner.py` (11 mutants, transcripts `mutant-run.txt` + `mutant-run-ruled.txt`). 10/11 KILLED first pass; the two ruled re-runs:

- **E4-INC3-F1** — the 039-bypass-producer mutant targeted only arm /1 (direct attach, which does not traverse `_prepare_load_payload`) and its first shape crashed. Ruled mutant reshaped and re-run against all five arms: KILLED.
- **E4-INC3-F2** — the image-route stale arms reject through TWO L1 guards (legacy/snapshot agreement + live comparison); the first mutant disabled only one. Ruled mutant disables both: KILLED (arms /1, /2).

Final: **13/13 KILLED, 0 unruled survivors**.

## Trace

`trace_check.py` on the increment: US/CASE/TEST gaps 0; SLICE clean for the four owned files (named in the requirements file); remaining gaps are `a2l_definition.py` (Inc 1's file, closed at batch end) and the EVID gap for the future `04-validation.md` (E5).

## Not run at E4

- E5 validation record, full-suite run, canon fold: batch-end obligations.
