# Inc 9 E4 - tester `T9b`, widget + group A9 + group I

Model claude-sonnet-5-5. Tests tree `b103-inc9-tests` (base `30819c7e`, no product edit). Cases: `02-test-cases-W.md`. Files: `tests/test_b103_inc9_w_keys.py`, `_w_select.py`, `_w_jobs.py`, `_w_stage.py`, `tests/test_b103_inc9_a9.py`, `tests/test_b103_inc9_i.py`, support `tests/support/b103_inc9_w.py`. The implementation (`bench_sheet.py`, `stage_record`, the handler, C-1 / C-4) was never read.

## Evidence states

- RED on base `30819c7e`: **executed** (transcripts below). Only the group I tests are a RED for a behaviour reason. Everything else is RED because the code under test does not exist on base (`ModuleNotFoundError: ...bench_sheet`, `AttributeError: 'ChangeService' object has no attribute 'stage_record'`): an absence RED, which proves no behaviour (card rule 5).
- GREEN: **not-run** (the implementation is another tree).
- Behaviour of every test except the instrument control: **planned**.
- Instrument control `test_control_the_gate_counts_nests_and_holds_without_changing_a_result`: **executed** on base, see below.
- Timing / memory nodes (`serial_timing`): **not-run** against any implementation; verdict only on a quiet host (HT-08). Host load at every RED run is in the transcript header.
- `approved`: not mine.

## Coverage

See `02-test-cases-W.md`: 67 widget / A9 / I cases of `02-test-cases.md` (the cases the file lists with no test name, less the three group B rows 16/1-3 that group B's tests already cover), all with a test; 12 are PARTIAL (reason per row), the rest full. Uncovered: the E4 addendum E3S-07 masked-array case (not a case row).

## Findings (requirement vs what a test can pin), one line each

- **F-1 (R-PE-BENCH.52/1, .15/3, .30/3, .70/3, EX-C1):** the literal "points 1 and 3" cannot be reached by one apply (a selection is a rectangle, an apply replaces, P-054 F-2). 70/3 stages points 1..3 instead (W-1, W-2).
- **F-2 (R-PE-BENCH.79/2, EX-Q2):** the graph's E2 `{(0,0), (1,1)}` is a merge; under replace the newer edit is `{(1,1): -18.8}` only. The test follows the ruling.
- **F-3 (R-PE-BENCH.77/3, EX-F7):** the pair "factor 0.5 / 1.0" belongs to CM_DEF_LIN; VAL_BLK_DEF_0001 uses CM_DEF_FINE (0.05), so the test uses 0.05 (page) and 0.025 (loaded).
- **F-4 (R-PE-BENCH.49):** page up / page down off the bench are answered by `PatchEditorPanel` (a `ScrollableContainer`) before the app's `page_*_context`; the requirement's list of keys that keep "the meaning they have without a bench" is true for `s d p` as app actions, and for page keys it is the panel scroll. The test asserts `s d p` only. Requirement owner: word the page keys.
- **F-5 (R-PE-BENCH.20 .. .29, .82):** the LARGE ATs need a 1 MiB S19 image (about 2.4 MB of text); built by `big_case`; run time per node 20-60 s.
- **F-6 (laws):** the integrator must raise `EXPECTED_SCANNED_TEST_FILES` of `test_id_registry` by 7 (six new test files and one support module here); the records of this tester name no host, account or HOME basename (the Inc 9 O-1 trap).

## Transcripts

RED runs: runner scratch under `~/work/zq-e4-9-t9b/` (deleted at the end), HT-02 env, `-n 2`, `timeout 300`, `s19_app.__file__` printed first (it is the scratch tree's `s19_app/__init__.py`), `< /dev/null`. Tree = `git archive 30819c7e` + the new test files.

Per file, from each run's own output (`red2-*` = the first full run, `red3-*` = rerun of the three files edited afterwards; every transcript's first line after the load header is `~/work/zq-e4-9-t9b/tree/s19_app/__init__.py`; host load 3-10 at the runs, no timing decided):

| File | Run | Result | Why RED |
|---|---|---|---|
| `test_b103_inc9_i.py` | red2-i | 3 failed  | **behaviour**: `'enter edit · ↑↓ row' == 'enter edit · ↑↓ row · arrays open the bench'` (x2) and the sheet class is not `ArrayBenchSheet` |
| `test_b103_inc9_a9.py` | red2-a9 | 29 failed | absence: `AttributeError: 'ChangeService' object has no attribute 'stage_record'` (7 service tests); `ModuleNotFoundError ... bench_sheet` (22 handler tests, at `sheet_of`) |
| `test_b103_inc9_w_keys.py` | red3-w_keys | 19 failed | absence: `ModuleNotFoundError ... bench_sheet` |
| `test_b103_inc9_w_select.py` | red3-w_select | 12 failed, **1 passed** | absence (`ModuleNotFoundError` / `ImportError ... bench_sheet`); the one pass is the instrument control |
| `test_b103_inc9_w_stage.py` | red2-w_stage | 10 failed | absence |
| `test_b103_inc9_w_jobs.py` | red2-w_jobs | 10 failed | absence (after loading each LARGE case, 6-10 s per node) |

84 items in all: 83 RED, 1 control GREEN. **An absence RED proves nothing about behaviour** (neither does the import RED of the new widget module: it is expected). For A9 there is no existing Inc 8 path that exercises a new function, so a behaviour RED on base is impossible; the vacuous-check suspicion is answered inside the tests (a "before" control or a negative control in each, listed in `02-test-cases-W.md`) and by the integrator's GREEN plus mutants. The group I tests are the only ones RED for a behaviour reason.

Control, executed on base (red3-control): `test_control_the_gate_counts_nests_and_holds_without_changing_a_result` **1 passed in 1.44s**: the I-2 wrapper replaces the function, counts a main-thread call as such, does not count the decode inside `encode_values` as a second job, holds a thread until released and returns the same result.

`trace_check` (PC, `python -I -B <skill>/trace_check.py --req .dev-flow/2026-11-05-batch-103/inc-9/01-requirements.md --tests tests --ids R-PE-BENCH.1 .3 .6 .9 .20 .22 ... .29 .40 ... .49 .51 .66 .70 ... .83 .92`, 40 ids written out): `trace_check: 40 active requirements match --ids, checks run: CASE, TEST, 0 gap(s)` (name-level only).

Static: AST ok for all seven files, 0 CR, no helper over 40 lines (AST scan).

## Gaps and limits

- No test ran against an implementation: a wrong reading of an interface (names read from `states[name]`: `cursor`, `tool`, `edit`, `undo`, `focus`, `values`, `staged`, `preview`; `sheet.rows`, `sheet.pending`) shows as RED at the integrator and is mine to repair.
- LARGE-size and timing claims: written, not run. BIG (70,000 elements) stands for LARGE in 22, 27, 28/1 (partial).
- 73/1, 73/2 use stand-in notices; 78/2 uses the panel's image push in place of the Apply action; 24/1 turns the page by `show_page`.
- Scratch deleted: rtx `~/work/zq-e4-9-t9b`; local `/tmp/t9b_*.sh`.
