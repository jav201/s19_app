# Batch-103 G3 — lane D (`b103-g3-oracles`)

Base: `21ec06b2e668b76ec62e76b9c3c6eb7cf971f2b1`.
Scope: only the five assigned test files; no product, requirement, golden, or other-lane edits.

## Known RED regressions after the fix

`known-final-junit.xml`: 14 collected, 14 passed, 0 failed, 0 errors, 0 skipped.

- `test_b97_flow_execution.py`: 6/6 passed.
- `test_window_usage_help.py`: 1/1 passed.
- `test_b100_session_reset.py`: 3/3 passed.
- `test_tui_commandbar.py`: 2/2 passed.
- `test_tui_diff_screen.py`: 2/2 passed.

This includes every lane-D nodeid in `repro-residual/regressions.txt` and all 14 failing nodes for the assigned files extracted from the supplied full-suite JUnit.

## Corrections

- Flow Execution: all local `run_lanes` calls now pass through the deferred-attention paint wait; the direct Run path uses the same bounded wait.
- CSS: exact Inc7 A2L and Inc10 export-dock supersessions; the original `startswith` and byte comparisons remain unchanged.
- Window help: approved Inc8 Patch pin is 49 steps; negative controls remain unchanged.
- Session reset: current prepared-load install seam; classified `_right_gesture`; historical census includes the approved Inc7 and Inc1b additions while the Inc12b delta remains exactly `_quit_pending`.
- Palette/bindings: canonical `help_quit` to `quit` palette projection, Inc12a live palette deltas, and the approved q binding row.
- Diff reports: both worker waits use `settle_workers`, including the refusal control.

## Full assigned files

`full-files-final-junit.xml`: 231 collected, 231 passed, 0 failed, 0 errors, 0 skipped; exit 0; 1636.954 seconds.

- `test_b97_flow_execution.py`: 75/75 passed.
- `test_window_usage_help.py`: 38/38 passed.
- `test_b100_session_reset.py`: 20/20 passed.
- `test_tui_commandbar.py`: 45/45 passed.
- `test_tui_diff_screen.py`: 53/53 passed.

No assigned failure remains. The existing in-file negative/mutation controls were included in these complete runs. The first aggregate attempt reached `test_tui_commandbar.py` without a printed failure but was aborted by the runner's 1200-second limit before producing JUnit. It is not counted as a test verdict; the complete run was repeated without that runner limit.

Supplementary external Quit controls (`test_b103_copy_quit_dialog.py`, R-COPY.24/1 and /2): 2 collected, 0 passed, 2 setup errors. Both refused to run because the required local environment explicitly unsets the clipboard/CI guards. No clipboard was opened and no guard was changed; these are not functional failures of the assigned files.

## Static checks

- `git diff --check`: PASS.
- Ruff over the five files: 4 pre-existing findings on untouched lines (two F401, one F541, one F841); no unrelated cleanup performed.

All raw logs, JUnit files, temporary directories, and isolated homes live outside the clone under the lane's local output directory. This committed RESULT is redacted and contains no home paths or account names.
