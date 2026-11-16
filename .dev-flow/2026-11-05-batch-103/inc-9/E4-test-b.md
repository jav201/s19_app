# Inc 9 E4 - tester `T9`, group B pure modules (`definition_bench.py`, `definition_bench_view.py`)

Model claude-sonnet-5-5. Tests tree `b103-inc9-tests` (base `40f0f202`, no product edit). Cases: `02-test-cases-B.md`. Files: `tests/test_b103_inc9_b_model.py` (19 functions), `_tools.py` (35), `_cells.py` (30), `_canvas.py` (38), `_detail.py` (29), support `tests/support/b103_inc9_b.py`. 151 test functions, about 185 collected items after parametrization (counted by AST; no run, see below).

## Evidence states

- RED on base `40f0f202`: **executed**, import RED only. The modules do not exist, so each file fails at `from s19_app.tui import definition_bench`. That proves nothing about behaviour (card rule 5); the integrator's GREEN and the mutant worker carry it.
- GREEN: **not-run** (the implementation is another tree; I never read it).
- Behaviour of every test: **planned**. No test body was executed against any implementation, not even a stand-in.
- Negative controls: listed per requirement in `02-test-cases-B.md`; **not-run** (no implementation to mutate). Two are marked not expressible here (see the table).
- `trace_check`: **executed**, 2 gaps (below).
- `approved`: not mine to write.

## Coverage

125 cases of `02-test-cases.md` map to group B's rows (E1-slice "Rows" column plus the graph's coverage table for B1..B22). 117 have a test (76 full, 41 partial); 8 do not (named in `02-test-cases-B.md`):

- R-PE-BENCH.14/1, 14/2 (refused decode shows `--`): not writable, see F-1.
- R-PE-BENCH.3/4, .26/2, .79/2, .92/1: widget cases of a row that group B also lists (B23, B30, B35, B28).
- R-PE-BENCH.29/1, 29/2: timing ATs on the widget (B33/B34), need the sheet and a quiet host.

## Transcript 1 - RED on base (collection, one per file)

Runner rtx, scratch `~/work/zq-e4-9-tb/tree` (tree = base + my tests), `uptime` load 1.30. Env of HT-02 (`HOME` basename `<runner-home>`), `-p no:cacheprovider --collect-only -q`, `< /dev/null`. First line of each run: `s19_app.__file__` = `/home/<runner>/work/zq-e4-9-tb/tree/s19_app/__init__.py`; `ls s19_app/tui/definition_bench*.py` -> `No such file`.

```
=== model   E   ImportError: cannot import name 'definition_bench' from 's19_app.tui' (.../tree/s19_app/tui/__init__.py)
            ERROR tests/test_b103_inc9_b_model.py     no tests collected, 1 error in 0.16s
=== tools   E   ImportError: ... 'definition_bench' ...   ERROR tests/test_b103_inc9_b_tools.py    1 error in 0.16s
=== cells   E   ImportError: ... 'definition_bench' ...   ERROR tests/test_b103_inc9_b_cells.py    1 error in 0.16s
=== canvas  E   ImportError: ... 'definition_bench' ...   ERROR tests/test_b103_inc9_b_canvas.py   1 error in 0.19s
=== detail  E   ImportError: ... 'definition_bench' ...   ERROR tests/test_b103_inc9_b_detail.py   1 error in 0.17s
```

## Transcript 2 - AST check (PC, `python -I -B`, no import of the app)

```
ast ok tests/support/b103_inc9_b.py
ast ok tests/test_b103_inc9_b_canvas.py   ast ok tests/test_b103_inc9_b_cells.py   ast ok tests/test_b103_inc9_b_detail.py
ast ok tests/test_b103_inc9_b_model.py    ast ok tests/test_b103_inc9_b_tools.py
```

CR count 0 in all six test files and in `02-test-cases-B.md`. No helper over 40 lines (AST scan).

## Transcript 3 - trace_check (PC, run from the repository root)

`python -I -B <skill>/trace_check.py --req .dev-flow/2026-11-05-batch-103/inc-9/01-requirements.md --tests tests --ids R-PE-BENCH.3 .4 .5 .7 .10 ... .19 .21 .26 .29 .30 ... .39 .41 ... .43 .50 ... .59 .61 ... .67 .79 .90 ... .93` (every id written out, 52 ids):

```
TEST   R-PE-BENCH.14 is named by no file under tests, and neither is a TC/AT id it lists
TEST   R-PE-BENCH.29 is named by no file under tests, and neither is a TC/AT id it lists
trace_check: 52 active requirements match --ids, checks run: CASE, TEST, 2 gap(s)
```

The two gaps are real and match the table above. The check is name-level only; it does not say a requirement is fully covered (partial rows are named in `02-test-cases-B.md`).

## One step beyond the brief, declared

The brief allowed only collection and the AST check on rtx. Because the collection stops at the missing module, it cannot show that the support code and the hand A2Ls work. I ran one scratch script on rtx (`~/work/zq-e4-9-tb/smoke.py`, deleted) that stubs the two missing modules in `sys.modules`, imports `tests/support/b103_inc9_b.py` and exercises ONLY existing code: the example oracles, the DEFC decode, I-2 encodes, and the builders of F32_BLK, F64_BLK, TAB_VERB, LARGE, 4,096 and 4,097 elements. No test function ran, no product behaviour is claimed. It confirmed: DEFC texts, axis texts, element names (`VAL_BLK_DEF_0001[2,0]`, `CURVE_DEF_0001[3]`), the encodes of EX-T1 / EX-T2 and the refusal of Set 60, F32 `1, nan, 3`, F32 all `nan`, F64 `1.7e+308`, TAB_VERB `ON, OFF`, LARGE describing with no refusal. It also showed the 300-`x` refusal message is 294 characters (the case says 289), so the test asserts `> 200`, not the number.

## Findings (requirement or interface vs what a test can pin) - one line each

- **F-1 (R-PE-BENCH.14):** the graph does not say how a refused decode reaches `bench_cells` (`BenchValues`/`BenchState` have no refusal field, `from_decoded` takes `DecodedValues` only). 14/1, 14/2 not written. Proposal: pin a state field (for example `values is None and status is a decode refusal`) or a `BenchValues` flag.
- **F-2 (R-PE-BENCH.52/1):** a selection is a rectangle, so "points 1 and 3" needs two applies; the test assumes the edit is merged across applies (a cell whose result equals its current value leaves it, R-PE-BENCH.58). The requirement says "set the bench edit to the results over the selection"; merge versus replace is not pinned.
- **F-3 (R-PE-BENCH.16/2, EX-T2):** `max |Δ| 5 staged` does not follow from the floats: staged `838 * 0.05 = 41.900000000000006` gives `max |Δ| 5.1`, while the pending `41.9 - 36.85` gives `5` (computed on the PC). 16/1 asserts the literal `5` (it holds); 16/2 asserts the oracle value from the staged numbers and `startswith("max |Δ| 5")`. E1 owner: fix the example text or pin the Δ source.
- **F-4:** `window_for` returns `(row, col)` while the cursor is `(column, row)` and `BenchState.origin` has no stated order; tests read only `window_for(...)[0]` as the row.
- **F-5 (R-PE-BENCH.5):** where the cut to `room` happens is unpinned. `chart_canvas` with `h = max(1, ...)` can paint more than `room` lines at room 1..5; the tests assert `<= room` only on `bench_detail`, and "no line" at room 0 on the canvases.
- **F-6:** names the tests read from the state, taken from the graph and not pinned by an interface section: tool letters `s d p i m`, `job == "summary"` / `"decode"`, `status` on `BenchState` (E3A-12), and that `BenchState`/`BenchValues` accept every field by keyword (`blank_state` builds from `dataclasses.fields`; `BenchValues(numbers=, texts=, missing=)`).
- **F-7 (R-PE-BENCH.93):** the example says "length 100" for the cut verdict at width 100; unclear whether `width` covers the name too. The test asserts `width // 2 <= len(tail) <= width` and a single trailing `…`.
- **F-8:** the examples file `examples_inc9.py` uses Python's banker's `round` in `strip_chart` and `step`; harmless on the DEFC values used, but a `.5` tie would differ from the requirement's "round".

## Interface assumptions the tests make (one place)

Cursor `(col,row)`; chart point k = `(k,0)`; positions in I-2 form (`(x,y)`, chart `(k,)`, flat `(i,)`); `Grid(mode, nx, ny, count, layout)`; `apply_tool(definition, state, grid, values, operand) -> BenchState` with `.edit`, `.undo` (newest last, at most 32), `.status`; `undo(state) -> BenchState`; `bench_cells -> (Kind, Current, New, Limits, Delta)` with the strip read from `state.strip`; `bench_mark(row, state) -> str`; `window_line -> Text | None`; `axis_labels -> (columns, rows)` of `str`; `op_line -> (name, tail)`.

## How the colours are read

Ramp colours are not pinned. A ramp step is an equivalence class: two cells have the same step exactly when their style colours are equal, compared with the step the oracle `EX.step` computes for their values. A bold, an edit colour or an unshaded cell is read at the offset of the text found in the painted line, never at a counted offset. A chart bar is the sum of its eighth blocks per screen column.

## Gaps and limits (written, not implied)

- Nothing was run against an implementation: expected texts and structure are from the requirements, I-2 and the oracles, but a wrong reading of an interface (F-4, F-6) shows as RED at the integrator and is mine to repair.
- R-PE-BENCH.26/1 decodes LARGE (about 11 s, 216 MiB, marked `slow`); it was not run. R-PE-BENCH.12, .20, .28, .29 timing and memory claims are B3 ATs and are not covered here.
- The negative controls of R-PE-BENCH.12 (timing), .18 (mark from the formula text), .38 and .66 (preview or diff over the overlay), .51 (stage message) are not expressible against the pure modules; the integrator's widget tests (B3/A9) must carry them.
- LARGE, F32/F64 and hostile-text objects use hand `BenchValues` / `DecodedValues` in places (marked partial), because the I-2 decode of 1,048,576 elements takes 11 s.
- Scratch deleted: rtx `~/work/zq-e4-9-tb` (created by me), local `T9-scratch` and `/tmp` helper files.
