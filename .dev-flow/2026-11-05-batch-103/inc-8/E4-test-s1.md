# Inc 8 E4 — tester `test-s1` (group S1: `s19_app/tui/definition_sheet.py`)

Model claude-sonnet-5-5. Tests tree `b103-inc8-tests` (base `d5d48685`). Cases: `02-test-cases-S1.md`. Tests: `tests/test_b103_inc8_s1.py` (61 + 1 AST purity), `tests/test_b103_inc8_s1_detail.py` (35), support `tests/support/b103_inc8_s1.py` (examples loader, DEFC and V171 fixtures, lazy `SpanImage`, cell reader). 97 test functions, 137 collected items after parametrization.

## Evidence states

- RED on base: **n/a — the module does not exist on base** (card rule 5). Collection on base fails with ImportError only (below): `executed`.
- GREEN: **not-run** against the real implementation (the integrator merges it later). Against a tester-written stand-in (scratch, never committed): 137 passed, `executed`. That run proves the tests agree with my reading of the spec, not with the implementers' code.
- Negative controls (one per file): `executed`, below.
- trace_check: `executed`, 0 gaps.

## Transcript 1 — base: collect fails with ImportError only

Runner rtx, scratch `~/work/zq-e4-8-test-s1/tree` (base product tree + my tests), `env -i … HOME=…/<runner-home> … -n 2`, `uptime` load 3.84.

```
/home/<runner>/work/zq-e4-8-test-s1/tree/s19_app/__init__.py        <- s19_app.__file__
tests/test_b103_inc8_s1.py:25: in <module>
    from s19_app.tui import definition_sheet as ds
E   ImportError: cannot import name 'definition_sheet' from 's19_app.tui' (…/tree/s19_app/tui/__init__.py)
tests/test_b103_inc8_s1_detail.py:21: in <module>
    from s19_app.tui import definition_sheet as ds
E   ImportError: cannot import name 'definition_sheet' from 's19_app.tui' (…/tree/s19_app/tui/__init__.py)
ERROR tests/test_b103_inc8_s1.py
ERROR tests/test_b103_inc8_s1_detail.py
2 errors in 1.74s
```

## Transcript 2 — GREEN against the tester stand-in (scratch only)

Same environment; stand-in `definition_sheet.py` written by me from the E3R2 spec, copied into the scratch tree only. Command: `pytest -p no:cacheprovider -n 2 tests/test_b103_inc8_s1.py tests/test_b103_inc8_s1_detail.py -q`.

```
137 passed in 1.51s
```

Running it found three bugs in my own tests (a padded-cell cell_len, a track search that assumed `├` survives a left-end mark, and a stand-in crash); all fixed before this run.

## Transcript 3 — negative controls (stand-in, one wrong value per file)

- File 1, `S1_MUTANT=widths` (`sheet_widths` swaps Current and New): `12 failed, 82 passed` — `test_r_pe_def_6_widths_follow_the_examples_of_every_class[80…220]` (10) and `test_r_pe_def_5_header_labels_start_where_the_widths_put_them[96,118]` … RED.
- File 2, `S1_MUTANT=overlay` (preview encoded over the bare image, the requirement's own negative control for R-PE-DEF.51): `2 failed, 41 passed` — `test_r_pe_def_51_the_second_masked_field_is_encoded_over_the_first_staged_one`, `test_r_pe_def_51_the_reverse_order_gives_the_same_word` RED.

## trace_check

`python -I -B trace_check.py --req .dev-flow/2026-11-05-batch-103/inc-8/01-requirements.md --tests tests --ids R-PE-DEF.5 .6 .7 .15…28 .31…41 .51 .62 .70 .71 .72 .75 .76 .77 .81 .88` (glob ids; a regex is not accepted):

```
trace_check: 38 active requirements match --ids, checks run: CASE, TEST, 0 gap(s)
```

## Findings (interfaces the graph does not pin)

1. `SheetRow` fields are unpinned beyond E1-slice's `(name, definition, kind, current, staged)`; the tests read only `row.current` (a `Decoded`; `row.current.stored` in the R-PE-DEF.40/1 expectation) and everything else through `row_line`. If the implementers name it differently, one test fails with AttributeError.
2. `Preview` is read as `.result` (Encoded|Refusal) and `.decoded` (Decoded|None), from E1-slice S6.
3. `delta_text(row, value, staged)`: `value` is ambiguous (a physical number, a `Decoded`, or a `Preview`; EX lists a `Refusal`). Proposal: pin it in I-8.5 or graph node `delta_text`. Tested only through `row_line`.
4. `limits_cell(row, value, width)` is tested with `value` a number or None (as the examples read).
5. `build_row` with `image=None` must hand I-2 an empty Mapping (I-2 raises TypeError on None); R-PE-DEF.18/1 pins this.
6. Text rows read the image: `detail_lines` gets no image argument, so the row must carry its span bytes; not tested as a design, only by outcome.

## Gaps

R-PE-DEF.24/3 and every widget, timing, group A/P row listed in `02-test-cases-S1.md` § "Not covered". R-PE-DEF.12 timing is not asserted (HT-08); the bounded-work claim is shown by the lazy-image lookup count (< 1000 for a 1 MiB span). Real-implementation GREEN is pending the merge. Scratch deleted (rtx `~/work/zq-e4-8-test-s1`, local scratch).
