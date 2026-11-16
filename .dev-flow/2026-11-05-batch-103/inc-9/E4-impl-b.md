# Inc 9 E4 group B (pure modules) - implementer hand-back

Conductor: Sonnet (claude-sonnet-5-5) driving `deepseek/deepseek-v4-pro` through `opencode run`, one fresh session per unit. Base `40f0f202`. Files: `s19_app/tui/definition_bench.py`, `s19_app/tui/definition_bench_view.py` (only these two). No tests written (tester branch owns them). No push.

## Units

| Unit | Rows | DeepSeek outcome | Commit | Verification |
|---|---|---|---|---|
| U1 | B1-B5 (Grid, BenchValues(+from_decoded), BenchState, bench_grid, move_cursor, page_cursor, window_for) | delivered | `230d7f2c` | 21 of 21 held |
| U2 | B6-B11 (selection_cells, where_text, parse_operand, apply_tool, result_text, undo) | delivered; `apply_tool` was 56 lines, split into `_set_edit` / `_precheck` by the conductor (fixed by conductor, behaviour identical) | `252c7bf1` | 42 of 42 held (re-run after the split) |
| U3 | B12, B12a, B13, B13a (bench_cells, bench_mark, summary_strip, bench_preview) + shared helpers `finite_range`, `ramp_step`, `ramp_style` | delivered | `b8680ec3` | 30 of 31 held; the 1 miss is an Inc 8 defect, see F-1 |
| U4 | B14-B18 (bench_detail, grid_canvas, chart_canvas, axis_labels, legend_line) | delivered with 1 defect fixed by the conductor: `Text(_fit(...))` (rich `Text` of a `Text`, `AttributeError`) in `grid_canvas` | `da60740e` | 29 of 29 held |
| U5 | B19-B22 (tool_row, window_line, bytes_line, op_line) | delivered | (this commit) | 27 of 27 held |

Re-run of U1-U5 checks on the final tree: see the transcripts below (host load: `uptime` 2.15 at the end; none of the checks is a timing check).

## Findings and deviations

- **F-1 (Inc 8 defect vs. CTX-PE-DEF, blocks one example).** Inc 8's `short_number(-1000)` returns `-1k` and `short_number(1000)` returns `1k` (`.3g` drops the zeros). CTX "short number" and EX-G10 / R-PE-BENCH.17 want 3 significant digits: `1.00k`, `-1.00k`. `bench_cells` calls Inc 8's `short_number` as pinned (Inc 9 must not redefine it), so MAP's Limits cell reads `-1k … 1k` where EX-A2 says `-1.00k … 1.00k`. Needs an orchestrator ruling: fix Inc 8's `short_number` (a defect against the approved design, DF-04 a) or correct EX-A2 / EX-G10. `-890`, `843`, `7.08k`, `58.1k`, `65.5k` are unaffected.
- **F-2 (spec conflict, example wins).** CTX "result" says `v` is the shown value (pending, else staged, else current), but EX-K5 (Set `10` then +Δ `5` gives `41.9` = 36.85 + 5) and R-PE-BENCH.51 ("set the bench edit to the current tool's results over the selection") need the arithmetic base to be the CURRENT value and the new edit to REPLACE the old one (the old edit goes to undo). Implemented as the examples say. The ×% / +Δ on a cell that already holds a pending edit therefore ignores the pending value.
- **D-1** `move_cursor` / `page_cursor` leave `origin` unchanged (the graph says "origin from window_for", but the signature has no shown sizes); the widget calls `window_for` with the real sizes.
- **D-2** `BenchValues.texts` is parallel to `numbers` (`""` for number elements, `None` when no text element), not "only the text elements".
- **D-3** `BenchState.status` added (E3A-12); `apply_tool` and `undo` always return a `BenchState`.
- **D-4** Shared helpers added to `definition_bench.py`, not in the graph: `finite_range`, `ramp_step`, `ramp_style` (public; the widget's worker can use `finite_range` for the stored lo/hi), plus private helpers (model: `_is_number`, `_row_width`, `_position_of`, `_element_index`, `_current_text`, `_refuse`, `_finish_apply`, `_tool_results`, `_set_edit`, `_precheck`, `_max_delta`, `_max_staged_delta`, `_delta_text`; view: the `_grid_*`, `_chart_*`, `_fit`, `_cut`, `_eighths`, `_block`, `_canvas_labels`, `_shown_value`, `_axis_point_labels`, `_TOOL_ROW` family).
- **D-5** Chart columns are contiguous (no gap); column width follows EX-G7 (`64` points at W 118 gives width 1), the plan prose gave 6.
- **D-6** Ramp colours, edit colour and the canvas line layout (header line of column labels; chart = value line, bars, base line, tick line) are conductor decisions where the CTX is silent; they need the capture verdict (HT-10), not a test.
- All 11 functions of `definition_bench.py` and the render functions are <= 40 lines (`ast` check); 0 CR; no private tokens (grep for the operator, host and address needles: 0 hits).

## Pasted outputs (rtx, HT-02 environment, `s19_app.__file__` under `~/work/zq-e4-9-<id>/tree`)

Each transcript is the output of a check script that asserts the graph examples named in its labels (`EX-...`) against the DEFC case (seed 20260001) built by `tools/synth/make_release_case.py --case definitions`. The scripts live in the conductor's scratch (deleted); the labels name the examples.

### U1
```text
s19_app.__file__ = ~/work/zq-e4-9-c9/tree/s19_app/__init__.py
HELD EX-A3 grid
HELD EX-A2 grid
HELD EX-A1 grid
HELD EX-G12 LARGE
HELD EX-A1 numbers
HELD EX-A1 missing
HELD EX-R11 missing
HELD array d
HELD K2 right
HELD K2 down
HELD K2 shift
HELD K2 left edge
HELD frozen
HELD defaults
HELD H5 page
HELD H5 page back
HELD page clamp
HELD H5 window
HELD W3 window
HELD A2 window
HELD pagedown origin
SUMMARY held=21 failed=0
```

### U2
```text
s19_app.__file__ = ~/work/zq-e4-9-c9/tree/s19_app/__init__.py
HELD sel M2
HELD sel C1
HELD sel reversed
HELD sel flat
HELD where M2
HELD where K2
HELD where C1
HELD where C1..3
HELD where G8
HELD operand
HELD T1
HELD T2
HELD T2 undo pushed
HELD T3
HELD T4
HELD T5
HELD G11
HELD M2
HELD M2 +0
HELD A1 +0
HELD H8 abc
HELD N3
HELD interp 1
HELD smooth 2
HELD R11 texts
HELD R11 refused
HELD N1 nan
HELD N4
HELD C1 set
HELD G9 12.045
HELD G9 34.325
HELD G9 26.533
HELD G9 572.5
HELD G9 -572.5
HELD G9 0.30000000000000004
HELD K5 u1
HELD K5 u2
HELD K5 u3
HELD K5 cap
HELD K5 32nd -> apply 1
HELD K5 33rd
HELD return types
SUMMARY held=42 failed=0
```

### U3
```text
s19_app.__file__ = ~/work/zq-e4-9-c9/tree/s19_app/__init__.py
HELD A2 kind
DID-NOT-HOLD A2 limits got '-1k … 1k' want '-1.00k … 1.00k'
HELD A3 kind
HELD A3 limits
HELD A3 no state current
HELD G1 strip
HELD G1 current
HELD T2 new
HELD T2 delta
HELD C1 new
HELD staged delta
HELD no edit new
HELD H5 large
HELD H6 running
HELD R6 refused
HELD R8 no limits
HELD refused delta
HELD mark T2
HELD mark staged
HELD mark staged+edit
HELD mark T9
HELD mark none state
HELD G2 map text
HELD G2 map steps
HELD G2 vb steps
HELD G13
HELD N1 strip
HELD finite_range
HELD finite_range none
HELD ramp_step
HELD preview
SUMMARY held=30 failed=1
```

### U4
```text
s19_app.__file__ = ~/work/zq-e4-9-c9/tree/s19_app/__init__.py
HELD A2 labels
HELD A3 labels
HELD A1 labels
HELD G12 labels
HELD R10 labels
HELD G3 -890 step0
HELD G3 843 step11
HELD room
HELD A1 rows
HELD T2 edited
HELD no room
HELD W2 w12
HELD W2 w10 no exc
HELD G6 15 cols
HELD H1 literal
HELD G4 legend
HELD G5 legend
HELD G5 tail
HELD A3 chart labels
HELD A3 chart room
HELD C1 edited
HELD N2 ?
HELD W3 room3
HELD chart room0
HELD H5 decoding
HELD W2 w10
HELD W2 w0
HELD W3 room1
HELD W3 room0
SUMMARY held=29 failed=0
```

### U5
```text
s19_app.__file__ = ~/work/zq-e4-9-c9/tree/s19_app/__init__.py
HELD tool row
HELD K4 s
HELD K4 d
HELD H5 window
HELD A2 window
HELD chart window
HELD A1 bytes
HELD T1 bytes
HELD T2 bytes
HELD T7 bytes
HELD H7 w76
HELD H7 w114
HELD running
HELD M2 name
HELD M2 tail
HELD C1 name
HELD C1 tail
HELD T2 verdict
HELD C2 verdict
HELD H3
HELD notices
HELD W1 w76
HELD W1 w114
HELD A1 first line
HELD A1 last line
HELD detail room
HELD map detail has tool row
SUMMARY held=27 failed=0
```

