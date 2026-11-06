# Inc 15 — E1 slice: every file and function to change, counted and mapped

Base `c2cba35`. **0 files under `s19_app/`** (source cap 0 of 4). Line numbers are at the base. The D-1 sibling arms (ruled yes) are in this slice since E3 round 1 (E3 F1); every E3 change is tagged with its finding id.

## 1. Summary

| Group | File | Functions / entries | Rows |
|---|---|---|---|
| TC-331 arm | `tests/test_tui_patch_editor_v2.py` | 1 changed test function, `test_tc331_disable_guard_predicate_tracks_source_path` (`:3501-3553`): 2 waits added; the module imports `settled` from `tests.b97_probes` | R-TST-150, 151, 154, 155, 163 |
| TC-B94-27 arm | `tests/test_tui_flow_execution_b94.py` | 1 changed test function, `test_tc_b94_27_lane_binding_isolation_and_noop` (`:480-543`): a call recorder around the panel's bind step + 2 waits; the module imports `settled` from `tests.b97_probes`. The shared `_bind` helper (`:166-168`, 8 callers) is **not** changed | R-TST-152, 153, 154, 155, 163 |
| AT-030c arm [D-1] | `tests/test_tui_patch_editor_v2.py` | 1 changed test function, `test_at030c_directly_dropped_file_is_listed_and_loadable` (`:1555-1598`): 1 wait added (E3 F1) | R-TST-159, 154, 155, 163 |
| TC-051 save-back arm [D-1] | `tests/test_tui_patch_editor_v2.py` | 1 changed test function, `test_save_back_prompt` (`:529-646`): 3 wait sites, one in the nested helper `_apply`, one after Don't save, one in the nested helper `_confirm_with` (13 waits at run time with D1 … D5) (E3 F1) | R-TST-160, 161, 162, 154, 155, 163 |
| Static check of the waits | `tests/test_suite_hygiene.py` (Inc 2's guard host) | 1 new test, proposed name `test_r_tst_154_155_inc15_arms_wait_through_settled` (AST over the four functions above, keyed on the eight static wait sites of table D; its docstring cites R-TST-154, R-TST-155, R-TST-163) | R-TST-154, 155, 163 |
| Conventions [D-3] | `docs/engineering-rules.md` | rule 7 added after rule 2's list (`:196-206`), "Six rules" → "Seven rules"; `tests/test_suite_hygiene.py`: `_CONVENTION_RULES` (`:83`) gains `R-TST-158`, and the parametrize list of `test_r_tst_007_conventions_hold_each_test_rule` (`:631-634`) gains `"R-TST-158"` | R-TST-158 |
| Runs (no file) | Windows host, LAN Linux host | 20 serial runs per node (4 nodes) on Windows; 3 serial runs + the parallel lane on Linux; the held-handler probes and the forced-never runs of R-TST-154 on Linux | R-TST-154, 156, 157; thresholds of 150 … 153, 159 … 162 |

**Totals:** 4 files (0 product, 3 test files, 1 doc), 4 changed test functions, 1 new test function, 1 new parameter of an existing test, 1 convention sentence. No new test file, so TC-607's scanned-file count does not change. E2 Code-Wire graph: not applicable, tests-only (`codewire/graph-inc15.md`, E3 F10).

## 2. Changes per function

### `test_tc331_disable_guard_predicate_tracks_source_path` (R-TST-150, 151)

| Point | Base | Change | Wait predicate (signal) | Description |
|---|---|---|---|---|
| after `panel.request_action("load_doc")` (`:3534-3535`) | one `await pilot.pause()` | `await settled(pilot, <predicate>, <D1>)` | the change document's `source_path` is set and its name is `f.json` | D1 |
| after `_seed_via_paste(app, paste)` (`:3538-3539`) | one `await pilot.pause()` | `await settled(pilot, <predicate>, <D2>)` | the change document has no `source_path` (D1 already showed a file-backed document; no entry-address check, which would tie D2 to the entry shape Inc 6 owns, E3 F8) | D2 |

The asserted values stay the product's: `button.disabled` read after each wait (`:3536`, `:3540`). The predicates read the document, never the button, so the guard mutants of R-TST-150 (b) and R-TST-151 (b) turn the arm RED at once instead of at the wait's bound. The document replacement and the guard are set in the same synchronous handler (`s19_app/tui/app.py:4733`, the `load_doc` / `parse_paste` branches `:4811-4834`), so no read can fall between them. The Edit JSON guard has three writers (E3 F2): `:7191` in `_patch_editor_load_tail` (a load runs it), `:4929` at the end of the action handler (a load and a paste both run it) and `:5170` (history path, not used here). Hence 150 (b) removes both load-path writers (`:7191`, `:4929`) → RED at the load step, and 151 (b) removes `:4929` only → RED at the paste step, while the load tail still guards the load.

### `test_tc_b94_27_lane_binding_isolation_and_noop` (R-TST-152, 153)

| Point | Base | Change | Wait predicate (signal) | Description |
|---|---|---|---|---|
| after the 2 imports, before the first `_bind` (`:500`) | — | wrap `panel._rebind` with a recorder (instance attribute; `FlowExecutionPanel.on_button_pressed` calls `self._rebind`, `s19_app/tui/flow_screens.py:4390-4392`). The install reads `panel._rebind` first, so a rename fails at install with `AttributeError`; the wrapper passes `*args, **kwargs` to the real step, so a signature change of Inc 9 still works, and appends one item **after** the real step returns (E3 F5) | — | — |
| after `_bind(app, 0, 0, "base.s19")` (`:502-503`) | one `await pilot.pause()` | `await settled(pilot, <predicate>, <D3>)` | the recorder holds 1 call | D3 |
| after `_bind(app, 0, 0, "variant_b.hex")` (`:507-508`) | one `await pilot.pause()` | `await settled(pilot, <predicate>, <D4>)` | the recorder holds 2 calls | D4 |

The recorder counts only; the asserted values stay the product's (`panel.lane_bindings`, `#fx_in_1_0`, `panel.lane_paint_plain(1)`). The recorder makes the no-op arm non-vacuous (R-TST-152): its `{}` is read after the press was handled.

### `test_at030c_directly_dropped_file_is_listed_and_loadable` (R-TST-159) (E3 F1)

| Point | Base | Change | Wait predicate (signal) | Description |
|---|---|---|---|---|
| after `select.value = "dropped.json"` (`:1583-1584`) | one `await pilot.pause()` | `await settled(pilot, <predicate>, <D5>)` | the change document's `source_path` is set and its name is `dropped.json` (the pick reaches the app as `Select.Changed` → the panel's `ChangeFileSelected` → `on_patch_editor_panel_change_file_selected`, `s19_app/tui/app.py:7054` → `_patch_editor_load`, `:7127`) | D5 |

The asserted value stays the product's: the first entry address read after the wait (`0x300`). The fresh app's document has no source path, so D5 cannot hold before the pick is handled.

### `test_save_back_prompt` (R-TST-160, 161, 162) (E3 F1)

| Point | Base | Change | Wait predicate (signal) | Description |
|---|---|---|---|---|
| after `panel.request_action("add_entry")` (`:558-559`) | one `await pilot.pause()` | **no change**: nothing is read before the first apply, both actions travel one message path in order, and D6 can hold only after an apply with ≥ 1 applied entry | — | — |
| in `_apply`, after `panel.request_action("apply_doc")` (`:562-563`) | one `await pilot.pause()` | `await settled(pilot, <predicate>, <D6>)` | `#patch_saveback_row` has no `hidden` class (`show_save_prompt`, `s19_app/tui/screens_directionb.py:6465`, from the apply branch `app.py:4868`) | D6 |
| after the `#patch_saveback_decline_button` `.press()` (`:574-575`) | one `await pilot.pause()` | `await settled(pilot, <predicate>, <D7>)` | `#patch_saveback_row` has the `hidden` class (`hide_save_prompt`, called first in the decision handler, `app.py:5002`) | D7 |
| in `_confirm_with`, after the `#patch_saveback_confirm_button` `.press()` (`:590-593`) | one `await pilot.pause()` | `await settled(pilot, <predicate>, <D8>)` | as D7 | D8 |

`prompt` (the `#patch_saveback_row` container) is already queried before `_apply` runs (`:565`), so the predicates read the queried widget. No wait can hold early: the row is composed hidden (`screens_directionb.py:5114`), each D7 / D8 wait leaves it hidden before the next `_apply`, and each D6 wait leaves it shown before the next answer. The decision handler hides the row before its decline return and before the save, in one synchronous call, so a read after D7 / D8 sees the save's outcome. The asserted values stay the product's (`prompt.has_class`, `name_input.value`, `last_summary.saved_path`, the work-area files). A prompt that never shows now fails at D6 with its description instead of at `prompt_shown`. Each wait is one static site with a constant description, however often its helper runs (E3 F1 (c)).

### `tests/test_suite_hygiene.py` — new static test (R-TST-154, 155, 163)

Parses `tests/test_tui_patch_editor_v2.py` and `tests/test_tui_flow_execution_b94.py` and checks the eight static wait sites of table D (`01-requirements.md`), keyed on (module, function, nested helper or none, trigger, description):
- per function, the count of `settled` calls equals its table-D sites: 2 (TC-331), 2 (TC-B94-27), 1 (AT-030c), 3 (TC-051: one in `_apply`, one in the body, one in `_confirm_with`);
- each site's description argument is the table-D string constant, verbatim and in order; an f-string or any non-constant fails (E3 F1 (c));
- each site's `settled` statement directly follows its trigger statement in the same block (E3 F4, R-TST-163);
- 0 `for … in range(…)` loops around `pilot.pause()` and 0 calls of the module-local `_settled` (`tests/test_tui_patch_editor_v2.py:3011`, an attempts-counted loop Inc 2 left out of scope) in the four functions;
- a function or helper not found by name fails the test, never skips it.

Scope (E3 F3): the check pins these eight sites only and stops no one-pause read elsewhere; new and changed arms are bound by the R-TST-158 sentence, and the existing sites are the D-6 census backlog row (`E1-rulings.md` §4), which also records that a trigger wrapped in a helper (`_seed_via_paste`, `_bind`, `_apply`, `_confirm_with`) escapes a pattern census.

## 3. Requirement → change map

| Row | Changed function or run |
|---|---|
| R-TST-150, 151 | `test_tc331_disable_guard_predicate_tracks_source_path` |
| R-TST-152, 153 | `test_tc_b94_27_lane_binding_isolation_and_noop` |
| R-TST-159 | `test_at030c_directly_dropped_file_is_listed_and_loadable` |
| R-TST-160, 161, 162 | `test_save_back_prompt` (its helpers `_apply`, `_confirm_with`) |
| R-TST-154, 155, 163 | the four functions above + `test_r_tst_154_155_inc15_arms_wait_through_settled`; R-TST-154's behavioural half is a Linux run, no file |
| R-TST-156 | Windows run, no file |
| R-TST-157 | Linux runs, no file |
| R-TST-158 | `docs/engineering-rules.md` rule 7; `_CONVENTION_RULES`; `test_r_tst_007_conventions_hold_each_test_rule` parameter |

## 4. Overlap

- `s19_app/tui/app.py`, `s19_app/tui/screens_directionb.py`: **none** (0 product files). The serial Inc 5 → 6 → 9 → 10 → 12 chain is unaffected at the source level.
- Read points the chain may move: Inc 6 (Patch Editor document lifecycle) — `ChangeService.document.source_path` and the `load_doc` / `parse_paste` branches that D1 and D2 rely on, the dropdown load path (`on_patch_editor_panel_change_file_selected` → `_patch_editor_load`) that D5 relies on, the save-back prompt row `#patch_saveback_row` and its `hidden` class (`show_save_prompt` / `hide_save_prompt`, the decision handler's hide-first order) that D6 … D8 rely on (E3 F1), and possibly `tests/test_tui_patch_editor_v2.py` itself; Inc 9 (`flow_screens.py`) — `FlowExecutionPanel._rebind`, which the D3/D4 recorder wraps.
- `tests/test_suite_hygiene.py` and `docs/engineering-rules.md` are Inc 2's files; any increment adding a convention edits the same list (textual merge only).

## 5. E4 owes (from the thresholds)

- RED on base, deterministic: run each arm's base form under its held-handler probe → RED; the new form under the same probe → GREEN 3/3. One hold per wait (E3 F1, F2): D1 `patch_action`; D2 `patch_action` + `I15_HOLD_ACTION=parse_paste`; D3, D4 `fx_bind`; D5 `change_file`; D6 `patch_action` + `I15_HOLD_ACTION=apply_doc`; D7 `save_back` + `I15_HOLD_ACTION=decline`; D8 `save_back` + `I15_HOLD_ACTION=confirm`. `fx_bind` is in `evidence-e1/probes/i15_guard.py`; the others are in `evidence-e3/probes/i15c_guard.py` (run by `i15c-run.sh` / `i15c-holds.sh`), and E4 may merge the two probes into one with the same mode names. The base halves for D2, D5 … D8 already ran at E3 (RED 2/2 each, `evidence-e3/lin/`). Run the probes from outside the worktree (they patch at session start; no file in the tree changes).
- Hold/recorder layering (E3 F5): the `fx_bind` hold defers `FlowExecutionPanel.on_button_pressed` at class level, **above** the instance recorder on `_rebind`. Never hold `_rebind` itself: the recorder would count the scheduling call while the real step has not run, and the RED would be vacuous.
- The vacuity control of R-TST-152: product mutant (the same-ref early return in `_rebind`, `s19_app/tui/flow_screens.py:4417-4418`, removed) **with** the `fx_bind` hold → the new form RED at the no-op assertion; the base form's no-op assertion passes and it fails later, at `after_a` (E3 F6) (mutant runs in a copy of the tree, never in the worktree).
- The vacuity controls of R-TST-161 (b) (decline saves, `app.py:5003-5005`, with `save_back`/`decline`) and R-TST-162 (b) (reserved-name refusal removed, `s19_app/tui/changes/apply.py:934-940`, with `save_back`/`confirm`; **LAN Linux host only**): compare the failing assertions, new form at the no-op assertion, base form earlier.
- The product mutants of R-TST-150 (b) (`app.py:7191` and `:4929` removed), 151 (b) (`:4929` only) and 153 (b) (E3 F2).
- The behavioural half of R-TST-154 (E3 F9): in a copy of the tree, force one site's predicate never to hold (short `timeout`), one site per run, 8 runs; the transcript quotes the 8 `did not settle: <description>` texts. This is also R-TST-157's negative control.
- The Windows serial runs of R-TST-156 (4 nodes) under the operator's isolation rules (`probes/i15-run.sh`).
- `docs/engineering-rules.md`: the R-TST-158 sentence as rule 7 after rule 6, "Six rules" → "Seven rules", with its own Origin line, e.g. `(Origin: batch-101 Inc 15 — four arms read after one pause and failed on the Windows host; R-TST-158. Existing one-pause reads are a census backlog row.)` (E3 F7).
- Each changed arm's docstring cites its R-TST ids. `trace_check.py` at E1 (`--req inc-15/01-requirements.md --base c2cba35 --src s19_app`): US and CASE hold; TEST gaps for R-TST-154, 155, 158 (their tests are E4's) and no `04-validation.md` (E5's) — 4 gaps, all owed by later stages. After E3 round 1 the same run adds R-TST-163's TEST gap (its static test is E4's), 5 gaps.
