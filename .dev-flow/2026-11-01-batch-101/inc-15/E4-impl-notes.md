# Inc 15 — E4 implementation notes (tests-only)

Branch `b101-inc15`. Base `c2cba35`. Scope: the eight table-D waits (D1 … D8),
the bind-step call recorder, the static guard, and the R-TST-158 conventions
sentence, exactly as `01-requirements.md`, `E1-slice.md` (incl. §5) and the E3
rulings (F1, F4, F5, F7, N1) specify. 0 files under `s19_app/` changed.

## Files changed

### tests/test_tui_patch_editor_v2.py

- Module import: `from tests.b97_probes import settled` (new).
- `test_save_back_prompt`
  - nested `_apply`: one `await pilot.pause()` → `await settled(..., "TC-051: the apply showed the save-back prompt")` — wait **D6**, row **R-TST-160** (also subject of R-TST-154/155/163).
  - `_drive` body (decline): one pause → `await settled(..., "TC-051: the decline hid the save-back prompt")` — wait **D7**, row **R-TST-161**.
  - nested `_confirm_with`: one pause → `await settled(..., "TC-051: the confirm hid the save-back prompt")` — wait **D8**, row **R-TST-162**.
  - docstring now cites R-TST-160, 161, 162, 154, 155, 163.
- `test_at030c_directly_dropped_file_is_listed_and_loadable`
  - `_drive` body: one pause → `await settled(...)` directly after `select.value = "dropped.json"` — wait **D5**, row **R-TST-159**.
  - docstring now cites R-TST-159, 154, 155, 163.
- `test_tc331_disable_guard_predicate_tracks_source_path`
  - load: one pause → `await settled(...)` after `panel.request_action("load_doc")` — wait **D1**, row **R-TST-150**.
  - paste: one pause → `await settled(...)` after `_seed_via_paste(app, paste)` — wait **D2**, row **R-TST-151**.
  - docstring now cites R-TST-150, 151, 154, 155, 163.

### tests/test_tui_flow_execution_b94.py

- Module import: `from tests.b97_probes import settled` (new).
- `test_tc_b94_27_lane_binding_isolation_and_noop`
  - Added a call recorder around `panel._rebind` (instance attribute): the
    install reads `panel._rebind` first (a rename fails at install with
    `AttributeError`), the wrapper passes `*args, **kwargs` to the real step,
    and appends one item **after** the real step returns (E3 F5). It never
    defers/holds `_rebind`; the held-handler hold sits at
    `FlowExecutionPanel.on_button_pressed` class level, above the recorder.
  - D3: one pause → `await settled(..., "TC-B94-27: the panel handled the Bind to the same ref")` after `_bind(app, 0, 0, "base.s19")` — row **R-TST-152**.
  - D4: one pause → `await settled(..., "TC-B94-27: the panel handled the Bind to variant_b.hex")` after `_bind(app, 0, 0, "variant_b.hex")` — row **R-TST-153**.
  - docstring now cites R-TST-152, 153, 154, 155, 163.

### tests/test_suite_hygiene.py

- `_CONVENTION_RULES`: added the `"R-TST-158"` entry (the sentence, verbatim).
- `test_r_tst_007_conventions_hold_each_test_rule` parametrize list: added
  `"R-TST-158"`.
- New helpers: `_arm_function`, `_nested_def`, `_drive_body`,
  `_settled_description`, `_calls_named`, `_pause_loops`.
- New test `test_r_tst_154_155_inc15_arms_wait_through_settled` (AST over the
  four arms, keyed on the eight static wait sites of table D):
  - R-TST-154: each site's description argument is the table-D string
    constant, verbatim and in order (a non-constant fails).
  - R-TST-155: each arm's `settled` count equals its table-D sites (2 / 2 / 1
    / 3); 0 `for … in range(…)` pause loops and 0 module-local `_settled` in
    the four functions.
  - R-TST-163: each `settled` statement is the statement directly after its
    trigger in the same block; a missing arm or helper fails, never skips.

### docs/engineering-rules.md

- "Six rules" → "Seven rules".
- Added rule 7 (Handled press) after rule 6: the R-TST-158 sentence verbatim,
  with its own Origin line citing batch-101 Inc 15 and R-TST-158.

## Implementation details (not deviations)

- Wait predicates (as the records' "Wait predicate (signal)" columns specify):
  - D1/D2/D5 read `app._change_service.document.source_path` (`.name` ==
    `f.json` / `dropped.json`, or `is None` for D2); never the button.
  - D3/D4 read the recorder counter (`len(rebind_calls) >= 1` / `>= 2`).
  - D6 reads `not prompt.has_class("hidden")`; D7/D8 read
    `prompt.has_class("hidden")` on the pre-queried `#patch_saveback_row`
    container. No wait can hold early (the row is composed hidden; D6/D7/D8
    alternate).
- N1 (`_drive` as the arm's body): `_drive_body` descends into the single
  `async with app.run_test(…)` block inside `_drive` — that block is where the
  trigger and wait statements live — and treats its body as the arm's body for
  D1 … D5 and D7. `_apply` / `_confirm_with` are found nested inside `_drive`
  and use their own bodies for D6 / D8.

## Deviations from the records

None. The four nodes keep their names, no assertion's expected value changed,
and no product code under `s19_app/` was touched.

## Verification

- `python -m py_compile` on the three edited test files
  (`tests/test_tui_patch_editor_v2.py`, `tests/test_tui_flow_execution_b94.py`,
  `tests/test_suite_hygiene.py`): **OK**.
- A text-only AST replication of the guard's checks (no `s19_app` import, no
  pytest run) over the edited tree: **8/8 sites pass** (descriptions verbatim,
  position directly after each trigger, per-arm `settled` counts 2/2/1/3, no
  range-counted pause loop, no module-local `_settled`).
- Line endings preserved (CRLF) on all four edited files.
- The R-TST-158 sentence is present verbatim in `docs/engineering-rules.md`
  and matches the `_CONVENTION_RULES["R-TST-158"]` entry; the section count
  reads "Seven rules".
