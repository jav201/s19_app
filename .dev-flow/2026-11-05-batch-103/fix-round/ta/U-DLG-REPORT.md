# Unit U-DLG — R-DLG.2: Escape in the seven dialogs that ignore it

- HEAD: 03d3594bcb49c3149bdeb210362a61fba9a55523
- Start: 2026-11-19 16:05:39 CST
- Common: frontB/FB-common.md + units2/TA2-common.md + unit brief U-DLG (product code)

## Row record

| row | file:function | change (one line) | negative-control mutation (file:line, one line) | command | RED line under mutation | GREEN result after change | OPEN? |
|---|---|---|---|---|---|---|---|
| R-DLG.2 | s19_app/tui/screens.py: EntryJsonScreen/SaveFlowScreen/LoadFlowScreen/ConfirmDiscardScreen/SelectVariantScreen/ConfirmWriteScreen (action_cancel), OperationsScreen (action_close_operations); tests/test_b101_reach_and_reports_escape.py (test_r_dlg_2_13/14); REQUIREMENTS.md CTX-DIALOG | Add escape Binding + action_cancel/action_close_operations sharing the Cancel/Close branch (branch body now calls it); flip 7 CTX-DIALOG "Esc today" cells no→yes | s19_app/tui/screens.py: delete SaveFlowScreen `BINDINGS = [Binding("escape", "cancel", "Cancel", show=False)]` line | FB-common env line, -n 0, nodes test_r_dlg_2_13 + test_r_dlg_2_14 | `AssertionError: did not settle: SaveFlowScreen closes by escape; stack ['Screen', 'SaveFlowScreen']` / `AssertionError: did not settle: Save flow closes on Escape; stack ['Screen', 'SaveFlowScreen']` | 8 passed (test_r_dlg_2_13 x7 + test_r_dlg_2_14) | |

### Step log

- N0 (baseline, before any change): `--collect-only -q tests` -> 9827 tests collected.
- Step 2 (tests first, unchanged product): appended the R-DLG.2 block; new nodes RED as expected — `8 failed in 121.18s`, all 7 `test_r_dlg_2_13[...]` cases fail at `did not settle: <Class> closes by escape` (button half of each case passes) plus `test_r_dlg_2_14` at `did not settle: Save flow closes on Escape; stack ['Screen', 'SaveFlowScreen']`. OperationsScreen composed fine with the synthetic LoadedFile (no fallback needed).
- Step 3 (product): 7 classes got comment + BINDINGS + action method + one-line branch body; `git diff` shows only those four changes per class. `Binding` already imported (screens.py:14).
- Step 4 (canon context): 7 CTX-DIALOG cells flipped `no`→`yes` (`Select variant (project '<name>'):`, `Save flow as:`, `Load flow:`, `Discard unsaved flow edits?`, `Edit entry JSON:`, `Write the computed CRC(s) into a new …`, `Operations:`); `project has no` (Reports focus note) untouched.
- Step 5: new nodes -> 8 passed (41.16s); existing `test_r_dlg_2_*` nodes -> 12 passed, 14 deselected (95.30s).
- Step 6 (negative control): copy `../scratch/nc-R-DLG.2` with SaveFlowScreen BINDINGS deleted -> `2 failed, 6 passed` ([SaveFlowScreen] + test_r_dlg_2_14 RED, other 6 GREEN). RED lines above. Copy deleted.
- Step 7 (after): N0 -> 9835 tests collected; new nodes -> 8 passed (36.48s).

## Deviations

None. Code matched the brief at every step; the fixed diagnosis (seven dialogs without an escape binding) held.

## Open questions

None.

## Final

```
$ git diff --stat
 REQUIREMENTS.md                             |  14 +--
 s19_app/tui/screens.py                      |  69 ++++++++++++--
 tests/test_b101_reach_and_reports_escape.py | 136 ++++++++++++++++++++++++++++
 3 files changed, 202 insertions(+), 17 deletions(-)
$ git diff | grep -c $'\r'
0
```

Final run of the unit's nodes (test_r_dlg_2_13_escape_does_what_cancel_does x7 + test_r_dlg_2_14_escape_in_save_flow_saves_nothing): `8 passed`.

UNIT_DONE U-DLG
