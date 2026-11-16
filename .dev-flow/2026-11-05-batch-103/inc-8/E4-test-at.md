# Inc 8 E4 - AT tester record (`test-at`)

Model claude-sonnet-5-5. Tests tree `b103-inc8-tests` (base `d5d48685`; product tree = base, no Inc 8 code). Cases: `02-test-cases-AT.md`. Tests: `tests/test_b103_inc8_at.py` (11 nodes incl. 1 reader control), `tests/test_b103_inc8_at_help.py` (2 nodes: AT-6 + its control).

## State of evidence

| Item | State |
|---|---|
| RED on base `d5d48685` | executed (below): 11 new-path nodes fail, each on a named assertion (`#patch_sheet_body: the staging sheet is not mounted`, or the old help step 1). The 2 controls pass on base on purpose. |
| GREEN on the implementers' tree | not-run: testers never read or run the implementers' tree; the orchestrator runs these 13 nodes there. |
| Windows-only pilots | not-run (manual items M-1 to M-3). |
| Mutants against the product | planned only (no product to mutate here). |

## RED transcript (base tree as cwd; one complete run)

Command (from the base tree root, `S` = my scratch, env per HT-02/HT-03; host load on the first line of the output):

`env -i PATH=/usr/bin:/bin HOME=$S/home/<runner-home> XDG_CONFIG_HOME=$S/x/config XDG_CACHE_HOME=$S/x/cache XDG_DATA_HOME=$S/x/data TMPDIR=$S/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 PYTHONPATH=. timeout 300 python -m pytest -p no:cacheprovider -n 2 tests/test_b103_inc8_at.py tests/test_b103_inc8_at_help.py -q --tb=line -rA`

```text
cwd=~/work/zq-e4-8-test-at/base
 15:26:40 up 1 day, 15 min,  7 users,  load average: 4.98, 3.55, 2.20
~/work/zq-e4-8-test-at/base/s19_app/__init__.py
bringing up nodes...
bringing up nodes...

.FFFFFFFFFFF.                                                            [100%]
=================================== FAILURES ===================================
~/work/zq-e4-8-test-at/base/tests/test_b103_inc8_at.py:278: AssertionError: #patch_sheet_body: the staging sheet is not mounted in the Patch Editor
~/work/zq-e4-8-test-at/base/tests/test_b103_inc8_at.py:278: AssertionError: #patch_sheet_body: the staging sheet is not mounted in the Patch Editor
~/work/zq-e4-8-test-at/base/tests/test_b103_inc8_at.py:278: AssertionError: #patch_sheet_body: the staging sheet is not mounted in the Patch Editor
~/work/zq-e4-8-test-at/base/tests/test_b103_inc8_at.py:278: AssertionError: #patch_sheet_body: the staging sheet is not mounted in the Patch Editor
~/work/zq-e4-8-test-at/base/tests/test_b103_inc8_at.py:278: AssertionError: #patch_sheet_body: the staging sheet is not mounted in the Patch Editor
~/work/zq-e4-8-test-at/base/tests/test_b103_inc8_at.py:278: AssertionError: #patch_sheet_body: the staging sheet is not mounted in the Patch Editor
~/work/zq-e4-8-test-at/base/tests/test_b103_inc8_at.py:278: AssertionError: #patch_sheet_body: the staging sheet is not mounted in the Patch Editor
~/work/zq-e4-8-test-at/base/tests/test_b103_inc8_at.py:142: AssertionError: did not settle: the sheet is composed
~/work/zq-e4-8-test-at/base/tests/test_b103_inc8_at.py:148: AssertionError: #patch_sheet_body: expected exactly 1 widget, found 0
~/work/zq-e4-8-test-at/base/tests/test_b103_inc8_at.py:278: AssertionError: #patch_sheet_body: the staging sheet is not mounted in the Patch Editor
~/work/zq-e4-8-test-at/base/tests/test_b103_inc8_at_help.py:89: AssertionError: Edit a change-set: the PATCH SCRIPT ledger on the left lists its entries; the inspector on the right shows the highlighted entry and holds the Inspector, JSON, Checks and A2L tabs. Load an S19/HEX image first (`^L`) to see the bytes an entry replaces.
==================================== PASSES ====================================
=========================== short test summary info ============================
PASSED tests/test_b103_inc8_at.py::test_reader_control_parse_rows_reads_marks_names_and_skips_header_and_detail
PASSED tests/test_b103_inc8_at_help.py::test_at_b103_i8_6_control_other_windows_help_has_no_sheet_line
FAILED tests/test_b103_inc8_at.py::test_at_b103_i8_2_escape_in_the_formula_input_stays_in_the_sheet
FAILED tests/test_b103_inc8_at.py::test_at_b103_i8_1_filter_page_row_formula_stage_advances_and_marks_dirty
FAILED tests/test_b103_inc8_at.py::test_at_b103_i8_4_paste_over_4096_characters_is_refused
FAILED tests/test_b103_inc8_at.py::test_at_b103_i8_3_arrow_keys_select_rows_and_choose_enum_entries
FAILED tests/test_b103_inc8_at.py::test_at_b103_i8_5b_a2l_unloaded_before_enter_stages_nothing
FAILED tests/test_b103_inc8_at.py::test_at_b103_i8_7_refused_formula_stages_nothing
FAILED tests/test_b103_inc8_at.py::test_at_b103_i8_8_two_masked_fields_stage_over_the_overlay[bit_then_field]
FAILED tests/test_b103_inc8_at.py::test_at_b103_i8_5a_no_a2l_shows_the_load_line
FAILED tests/test_b103_inc8_at.py::test_at_b103_i8_9_filter_matching_nothing_shows_the_line
FAILED tests/test_b103_inc8_at.py::test_at_b103_i8_8_two_masked_fields_stage_over_the_overlay[field_then_bit]
FAILED tests/test_b103_inc8_at_help.py::test_at_b103_i8_6_help_window_shows_the_new_rows
11 failed, 2 passed in 43.49s
```

## trace_check (from the repository root)

`python <skill>/trace_check.py --req .dev-flow/2026-11-05-batch-103/inc-8/01-requirements.md --tests tests --ids R-PE-DEF.10 R-PE-DEF.13 R-PE-DEF.14 R-PE-DEF.22 R-PE-DEF.23 R-PE-DEF.27 R-PE-DEF.40 R-PE-DEF.42 R-PE-DEF.45 R-PE-DEF.46 R-PE-DEF.47 R-PE-DEF.48 R-PE-DEF.50 R-PE-DEF.51 R-PE-DEF.52 R-PE-DEF.53 R-PE-DEF.54 R-PE-DEF.56 R-PE-DEF.57 R-PE-DEF.58 R-PE-DEF.60 R-PE-DEF.63 R-PE-DEF.82 R-PE-DEF.83 R-PE-DEF.84 R-PE-DEF.85 R-PE-DEF.86 R-PE-DEF.87 R-PE-034 R-PE-035 R-PE-041`

```text
trace_check: 31 active requirements match --ids, checks run: CASE, TEST, 0 gap(s)
```

## Manual items for the operator (Windows-only, E1-rulings section 5 "Inputs to pilot at E4")

- **M-1** Real Windows Terminal key delivery: up/down/enter/left/right reach the focusable sheet body (R-PE-DEF.45 to .47). The AT drives Textual's pilot on Linux.
- **M-2** Real Windows Terminal bracketed paste longer than 4,096 characters into the formula input leaves the text unchanged (R-PE-DEF.42). AT-4 posts an `events.Paste`.
- **M-3** Escape in the formula input reaches the widget and is not the screen's back action (R-PE-DEF.48). AT-2 covers the Linux pilot (focus on the body, same screen stack, still shown).

## Mutant plan (state `planned`, none run)

| Mutant of the product | Expected RED |
|---|---|
| stage handler writes nothing / writes the image bytes | AT-1, AT-3, AT-8 (entry vs model) |
| `select_after` not called | AT-1 (advance); AT-3 stays on the row |
| Escape not bound in the input (or the screen's back action wins) | AT-2 |
| `max_length` removed from the formula input | AT-4 |
| enum right/left sets the stored value (`2`) as text | AT-3 (input text vs the table's text) |
| stage encodes over the image instead of the overlay | AT-8 (first staged field reverts) |
| refusal still writes / sets dirty | AT-7 |
| help step 1 unchanged | AT-6 |

## Findings and open gaps

1. **Spec tension, marks.** R-PE-DEF.22 (`▶` selected), .23 (`●` staged) and .24 (`◆` pending) share one mark column; the selected row is also the pending row while the operator types. AT-2 therefore reads "pending" through the New column text and its absence, not through `◆`. Needs a ruling if `◆` must show on the selected pending row.
2. **AT-5b reachability.** R-PE-DEF.63 asks for a refusal when the A2L is unloaded between selection and Enter; R-PE-DEF.14 repaints the sheet with the load line on unload. The test re-focuses the input and presses Enter. If the product disables the input on that repaint, AT-5b fails and the pair needs a ruling.
3. **Widget ids not pinned.** I-8.4 pins `#patch_sheet`, `#patch_sheet_body` and `#patch_sheet_input` but not the formula bar; the ATs read every leaf static-like widget under `#patch_sheet` for the tail. Proposal: pin the bar's id in I-8.4.
4. **Reader assumptions** (unverifiable here, hence the reader control node): the body's plain text holds one row per line starting with its mark glyph, names clipped with `…`; the ledger subtitle is a border subtitle inside `#patch_editor_panel`; statuses go through `S19TuiApp.set_status`.
5. **Tab route.** The ATs reach the sheet with Tab from the filter input (bounded at 25 presses).
6. Not covered by the ATs: `02-test-cases-AT.md`, section "Uncovered by the ATs".
