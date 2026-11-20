# INC 2 — E4 build and test record

Base: `7402840c` (E4 Inc1 close). Slice: 4 source files (`file_load.py`, `a2l_parameter_picker.py`, `check_editor.py`, `patch_editor/a2l_picker.py`), nodes A1–A7, P1, C1, PA1 per the E2 graph and I-ALP-2.1…2.4. Implementer lane: DeepSeek v4 Pro (Hermes subagent). Independent tester lane: DeepSeek v4 Pro (Hermes subagent), with a second repair lane. Integration, verification, rulings, mutant runs and the D-13 product fix: the conductor.

## RED on base

The tester wrote `tests/test_alp_inc2_a2l_attach.py` (37 collected nodes) and retargeted `tests/test_b103_picker_model.py` and `tests/test_b100_session_reset.py`, then executed against base `7402840c`: 37/37 RED (evidence `red-inc2-attach.txt`, exit 1, 100.8 s; the two edited files stayed green on base, 64 passed, `red-inc2-existing.txt`).

## GREEN on the integrated tree

Executed evidence: `chunk1.txt` (17 passed) + `chunk2.txt` (20 passed) = **37/37, 0 failures** in two sequential chunks (the three full-suite attempts each produced one load-fatigue flake in a different node; each such node passed in isolation, 11–21 s, and the flakes were fixed test-side: sampler poll 20→50 ms (E4-INC2-F2), confirm-modal polling in `_load_image` (E4-INC2-F3)).

Regression evidence: `regression-inc2-a` (picker model + session reset + legacy constructors: 72 passed) and `regression-inc2-b` (refresh, workers, progress suites: 190 passed, 1 xfailed, 5 failed — every failure classified: `test_tc_b100_54…[a2l_size]` and `test_tc_b100_53_reset_runs_after_the_worker` fail pre-existing on base (stash-verified by the implementer); `every_a2l_attach_route` and `test_r005…[/4]` are pre-existing flakes verified on both sides; `test_r014_same_path[/1]` failed once with "Load dialog did not open" under 52-minute-suite load and passes 2/2 in isolation (same modal-latency class as E4-INC2-F3). No new deterministic regression.)

## Design returns and product fix (E1-rulings §9, D-11…D-13)

- **D-11**: the frozen main-thread image capture (I-ALP-2.1) cannot meet a 1.0 s key bound (measured 1.84 s on the 1M image). Ruling: `.033/6` re-scoped — busy progress visible during capture, latencies recorded individually, keys never wait for parse/preparation, mutation control intact. Requirements and ledger amended in place.
- **D-12**: the preserved common refresh blocks the loop by design (HLR-176, measured 2.5–3.6 s on case_06). Ruling: `.034/3` and AT-I2-2 sampling windows end at refresh entry; the preserved-refresh gap is recorded unasserted. Requirements and ledger amended in place.
- **D-13**: executed probes (d12b–d12f, `probe-d13-mechanism.txt`) isolated the real blocker: mid-run generational collections hold the GIL for 1.1–2.2 s during case_06 parse and preparation (plain ticker peak 1.125 s vs 0.406 s with the collector off, describes ~20 % faster). Product fix within the slice: the attach worker runs GC-disabled; `_install_attached_a2l` re-enables and collects once AFTER the preserved refresh (D-12 territory); failure and superseded-reject paths re-enable immediately. The two case_06 arms turned GREEN (2/2, 181 s). Inc 3 consumers of the snapshot must re-enable after their preserved refresh (recorded in the E4 report for Inc 3).

## Negative controls — mutant run

`evidence-e4/mutant_runner.py` applies each planned negative control as a real source mutant in a tree copy; transcripts `mutant-run.txt` (first pass) and `mutant-run-ruled.txt` (ruled re-runs).

10/13 KILLED on the first pass; three survivors were ruled test/mutant defects, fixed and re-run KILLED:

- **E4-INC2-F4** — the .030 census listed only two worker/helper nodes; the D-13 split added `_prepare_a2l_attach_snapshot_inner`, so a forbidden read in the producer body went undetected. Test fix: census covers all three nodes.
- **E4-INC2-F5** — .031 asserted the enrichment key after the outcome, where the recompute-on-mismatch path had repaired it; the frozen contract installs the key before the common refresh. Test fix: the key is recorded at every refresh entry and the final entry must already be the expected key.
- **E4-INC2-F6** — the 036-drop-cache mutant dropped the key after the refresh (mutant placement defect). Runner fix: drop before the refresh.

Final: **13/13 KILLED, 0 unruled survivors**.

## Trace

`trace_check.py` on the increment: US/CASE/TEST gaps 0; SLICE clean for the four owned files after naming the two adapters in the requirements file; remaining gaps are `a2l_definition.py` (Inc 1's file, named in Inc 1's requirements — closed at batch end) and the EVID gap for the future `04-validation.md` (E5).

## Not run at E4

- E5 validation record, full-suite run, canon fold: batch-end obligations.
- Inc 3 prepared-load routes: the next increment, on this completed tree.
