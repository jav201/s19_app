# Inc 15 — E1 slice: every file and function to change, counted and mapped

Base `c2cba35`. **0 files under `s19_app/`** (source cap 0 of 4). Line numbers are at the base. Sibling arms of D-1 are not in this slice until the orchestrator rules (`E1-rulings.md` §4).

## 1. Summary

| Group | File | Functions / entries | Rows |
|---|---|---|---|
| TC-331 arm | `tests/test_tui_patch_editor_v2.py` | 1 changed test function, `test_tc331_disable_guard_predicate_tracks_source_path` (`:3501-3553`): 2 waits added; the module imports `settled` from `tests.b97_probes` | R-TST-150, 151, 154, 155 |
| TC-B94-27 arm | `tests/test_tui_flow_execution_b94.py` | 1 changed test function, `test_tc_b94_27_lane_binding_isolation_and_noop` (`:480-543`): a call recorder around the panel's bind step + 2 waits; the module imports `settled` from `tests.b97_probes`. The shared `_bind` helper (`:166-168`, 8 callers) is **not** changed | R-TST-152, 153, 154, 155 |
| Static check of the waits | `tests/test_suite_hygiene.py` (Inc 2's guard host) | 1 new test, proposed name `test_r_tst_154_155_inc15_arms_wait_through_settled` (AST over the two functions above) | R-TST-154, 155 |
| Conventions [D-3] | `docs/engineering-rules.md` | rule 7 added after rule 2's list (`:196-206`), "Six rules" → "Seven rules"; `tests/test_suite_hygiene.py`: `_CONVENTION_RULES` (`:83`) gains `R-TST-158`, and the parametrize list of `test_r_tst_007_conventions_hold_each_test_rule` (`:631-634`) gains `"R-TST-158"` | R-TST-158 |
| Runs (no file) | Windows host, LAN Linux host | 20 serial runs per node on Windows; 3 serial runs + the parallel lane on Linux; the held-handler probe on Linux | R-TST-156, 157; thresholds of 150 … 153 |

**Totals:** 4 files (0 product, 3 test files, 1 doc), 2 changed test functions, 1 new test function, 1 new parameter of an existing test, 1 convention sentence. No new test file, so TC-607's scanned-file count does not change. Graph (E2): about 6 nodes, under the 8-node split limit.

## 2. Changes per function

### `test_tc331_disable_guard_predicate_tracks_source_path` (R-TST-150, 151)

| Point | Base | Change | Wait predicate (signal) | Description |
|---|---|---|---|---|
| after `panel.request_action("load_doc")` (`:3534-3535`) | one `await pilot.pause()` | `await settled(pilot, <predicate>, <D1>)` | the change document's `source_path` is set and its name is `f.json` | D1 |
| after `_seed_via_paste(app, paste)` (`:3538-3539`) | one `await pilot.pause()` | `await settled(pilot, <predicate>, <D2>)` | the change document has no `source_path` and holds the pasted entry (one entry, address `0x9`) | D2 |

The asserted values stay the product's: `button.disabled` read after each wait (`:3536`, `:3540`). The predicates read the document, never the button, so the guard mutant of R-TST-150 (b) turns the arm RED at once instead of at the wait's bound. The document replacement and the guard are set in the same synchronous handler (`s19_app/tui/app.py:4733`, the `load_doc` / `parse_paste` branches `:4811-4834`, the guard `:4928`), so no read can fall between them.

### `test_tc_b94_27_lane_binding_isolation_and_noop` (R-TST-152, 153)

| Point | Base | Change | Wait predicate (signal) | Description |
|---|---|---|---|---|
| after the 2 imports, before the first `_bind` (`:500`) | — | wrap `panel._rebind` with a recorder that appends one item per call and then calls the real step (instance attribute; `FlowExecutionPanel.on_button_pressed` calls `self._rebind`, `s19_app/tui/flow_screens.py:4390-4392`) | — | — |
| after `_bind(app, 0, 0, "base.s19")` (`:502-503`) | one `await pilot.pause()` | `await settled(pilot, <predicate>, <D3>)` | the recorder holds 1 call | D3 |
| after `_bind(app, 0, 0, "variant_b.hex")` (`:507-508`) | one `await pilot.pause()` | `await settled(pilot, <predicate>, <D4>)` | the recorder holds 2 calls | D4 |

The recorder counts only; the asserted values stay the product's (`panel.lane_bindings`, `#fx_in_1_0`, `panel.lane_paint_plain(1)`). The recorder makes the no-op arm non-vacuous (R-TST-152): its `{}` is read after the press was handled.

### `tests/test_suite_hygiene.py` — new static test (R-TST-154, 155)

Parses `tests/test_tui_patch_editor_v2.py` and `tests/test_tui_flow_execution_b94.py`; in each of the two functions above: exactly 2 calls of `settled` with the table-D description string constants in order (D1, D2 / D3, D4), 0 `for … in range(…)` loops around `pilot.pause()`, 0 calls of the module-local `_settled` (`tests/test_tui_patch_editor_v2.py:3011`, an attempts-counted loop Inc 2 left out of scope).

## 3. Requirement → change map

| Row | Changed function or run |
|---|---|
| R-TST-150, 151 | `test_tc331_disable_guard_predicate_tracks_source_path` |
| R-TST-152, 153 | `test_tc_b94_27_lane_binding_isolation_and_noop` |
| R-TST-154, 155 | the two functions above + `test_r_tst_154_155_inc15_arms_wait_through_settled` |
| R-TST-156 | Windows run, no file |
| R-TST-157 | Linux runs, no file |
| R-TST-158 | `docs/engineering-rules.md` rule 7; `_CONVENTION_RULES`; `test_r_tst_007_conventions_hold_each_test_rule` parameter |

## 4. Overlap

- `s19_app/tui/app.py`, `s19_app/tui/screens_directionb.py`: **none** (0 product files). The serial Inc 5 → 6 → 9 → 10 → 12 chain is unaffected at the source level.
- Read points the chain may move: Inc 6 (Patch Editor document lifecycle) — `ChangeService.document.source_path` and the `load_doc` / `parse_paste` branches that D1 and D2 rely on, and possibly `tests/test_tui_patch_editor_v2.py` itself; Inc 9 (`flow_screens.py`) — `FlowExecutionPanel._rebind`, which the D3/D4 recorder wraps.
- `tests/test_suite_hygiene.py` and `docs/engineering-rules.md` are Inc 2's files; any increment adding a convention edits the same list (textual merge only).

## 5. E4 owes (from the thresholds)

- RED on base, deterministic: run each arm's base form under the held-handler probe (`evidence-e1/probes/i15_guard.py`, `I15_HOLD=patch_action` / `fx_bind`, 1.5 s) → RED; the new form under the same probe → GREEN 3/3. Run the probe from outside the worktree (it patches at session start; no file in the tree changes).
- The vacuity control of R-TST-152: product mutant (the same-ref early return in `_rebind`, `s19_app/tui/flow_screens.py:4417-4418`, removed) **with** the `fx_bind` hold → the new form RED, the base form GREEN (mutant runs in a copy of the tree, never in the worktree).
- The product mutants of R-TST-150 (b), 151 (b), 153 (b).
- The Windows serial runs of R-TST-156 under the operator's isolation rules (`probes/i15-run.sh`).
- Each changed arm's docstring cites its R-TST ids. `trace_check.py` at E1 (`--req inc-15/01-requirements.md --base c2cba35 --src s19_app`): US and CASE hold; TEST gaps for R-TST-154, 155, 158 (their tests are E4's) and no `04-validation.md` (E5's) — 4 gaps, all owed by later stages.
