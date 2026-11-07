# Inc 12 E4 tester (G-T2) - notes

Node file: `tests/test_b101_shown_widgets.py`, 2 nodes. RED run: base `6f1743c1` (origin/main), LAN Linux host 2, prefix `s19_i12t2`, `-n 4 --dist loadfile`, transcript `.dev-flow/2026-11-01-batch-101/evidence/inc-12/red-01-g-t2-base.txt` (redacted, grep-checked). Summary line: `1 failed, 1 passed in 12.47s`. State: executed (RED on base for the walk; the acceptance node is a declared standing guard). Remote worktree and helper removed. The edited existing nodes (below) were NOT run: the implementers' source edits are in flight in the worktree and the brief forbids running pytest on this PC (state: not-run, for G-T2's existing-node edits; they run at E5).

## How the nodes read and drive

- Both nodes open the app at 118x54 and load the demo A2L through the shared `open_check_editor` (the app's own loader, then `action_show_screen("check_editor")`).
- Walk: the window is `#screen_check_editor` (the window, its header, its panel). `_Walk.collect` takes, after every state, the window plus all its descendants that carry an id, keyed by widget identity (`id(widget)`; the walk holds each widget so keys are not reused). "Shown" is stated in the fixture docstring: `tests.b97_probes.is_displayed` (display on the widget and every ancestor up to the screen); `visibility` and region size are not read. States: opened (Fields pane shown alone), then the three tab chips pressed in turn (`Button.press()` on `#check_tab_fields`, `#check_tab_json`, `#check_tab_addendum`), each state waiting through `settled` for its pane to be the only pane shown and its chip marked (so a state cannot be a copy of another). Asserts, in order: the states list, population >= 45, the Addendum state shows `#check_addendum_preview`, and `never_shown() == []` (the message lists the ids).
- AT-I12-3 (Check Editor half): `1` (leave to the Workspace, asserted left), `=` (asserted shown), bounded `tab` (150 presses, named failure) until `#check_tab_addendum` has the focus, `enter`; asserts the Fields pane was the one shown before, then only the Addendum pane is shown, the chip is marked, and `#check_addendum_preview` paints text starting `## Checks` (read from the composited rows). No fixed sleeps, no clipboard, nothing set on widgets.
- Measured population (diagnostic, base): 52 widgets with an id over the four states, 1 never shown (`check_preview_toggle_button`); after the removal the expected count is 51. The row's "47" counts the panel's ids; the window adds the window, header and chip ids. The node's floor is the row's 45.

## Cases -> nodes, RED on base

| Case | Node | Base result and the reason |
|---|---|---|
| R-CHKED-058/1 | `tests/test_b101_shown_widgets.py::test_r_chked_058_1_every_check_editor_widget_is_shown_in_a_state` | RED, for the right reason: `AssertionError: mounted and never shown: ['check_preview_toggle_button']` (the hidden `Addendum preview` button); the earlier clauses (states, population 52 >= 45, addendum preview shown) pass on base. |
| AT-I12-3 (Check Editor half) | `tests/test_b101_shown_widgets.py::test_at_i12_3_addendum_tab_by_keys` | passes on base (declared standing guard; the case states "holds on base, R"). |

Trace ids: the docstrings name R-CHKED-058, R-CHKED-021, AT-I12-3, US-I12-2; node names follow the proposed `test_r_chked_058_1_...` and `test_at_i12_3_...` unchanged (the AT name is `test_at_i12_3_addendum_tab_by_keys`, as proposed).

## Existing-test edits (E1-slice §5, Check Editor removal) - applied, not run

- `tests/b97_fixtures.py`: `check_preview_toggle_button` dropped from `CE_IDS_9C7BEAF`; guard `len == 36` -> `== 35`; the comment above the literal says 30 of 9c7beaf plus the five picker/bulk ids.
- `tests/test_b97_check_editor.py::test_tc_b97_61_every_control_displayed_in_its_home`: the toggle's query and `toggle_displayed` (return and unpack), the "mounted, not displayed" assertion and the `typed - {...}` subtraction are gone (`typed` is the shipped set, `len == 16 and typed <= column`); docstring reworded to name no removed id and to point at R-CHKED-058/1. `::test_tc_b97_08_census_rows_and_one_docked_row`: `len == 35`, docstring 36 -> 35.
- `tests/test_tui_directionb.py` (TC-011): the docstring sentence "retained legacy-alias methods" and the comment above `view_action_aliases` ("also retained on S19TuiApp") reworded: the rail `show_screen` actions are the path; no removed name spelled. The `hasattr(S19TuiApp, f"action_{action}")` arm is left unedited (slice: passes unchanged; unused).
- `grep -rnw check_preview_toggle_button tests` -> no line (I-3 holds for the Check Editor id). Line endings of edited files kept CRLF as in the working tree.

## Standing guards (pass on base) and why each still has a failure mode

- `test_at_i12_3_addendum_tab_by_keys`: fails if the Addendum chip leaves the focus chain (the bounded `tab` loop raises), if `enter` stops switching the pane, if the preview does not paint `## Checks` first, or if Inc 12 removes the handler branch and breaks the tab by mistake. It cannot catch the hidden button (that is the walk's job).

## Findings for the integrator

1. Ownership: `E1-slice.md` §5/§6 gives the `test_tui_directionb.py` TC-011 docstring/comment to G-T1 (moved at E3); my brief gave it to G-T2. I edited it (one docstring sentence, one comment, disjoint hunks). G-T1 must not repeat it; if G-T1 already planned it, drop one.
2. Population number: the walk counts 52 (base) / 51 (after) over the whole window, not the row's 48/47 (panel ids only). Threshold >= 45 holds either way; the row/case text could say "window" to match (CTX-SHELL).
3. Base for RED is origin/main `6f1743c1` as the brief says; the host's local `main` of `~/work/s19_app` was at `09b4808a` before the fetch, so I fetched and used `origin/main` (`6f1743c1`).
4. The existing-node edits and the new file are untested against the implementers' tree (in flight); E5 runs them. Expected after the change: walk and AT green, TC-B97-08/61 green with 35 ids.
