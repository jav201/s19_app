# CHECK U-DLG

- unit: U-DLG
- tree: ~/work/zq-ta/U-DLG/repo
- HEAD sha: 03d3594bcb49c3149bdeb210362a61fba9a55523
- start time: 2026-11-19 16:17:48 CST

## Step 1 — Diff hygiene
Command: `cp -a ~/work/zq-ta/U-DLG/repo ~/work/zq-ta/chk-U-DLG && cd ~/work/zq-ta/chk-U-DLG && git diff > ../chk-U-DLG.diff`

- Files changed: `REQUIREMENTS.md`, `s19_app/tui/screens.py`, `tests/test_b101_reach_and_reports_escape.py` — all within the brief's "Files (exactly 3)".
- `git diff --stat`: `3 files changed, 202 insertions(+), 17 deletions(-)`.
- CR count (`tr -cd '\r' < ../chk-U-DLG.diff | wc -c`): **0**.
- Added `skip`/`skipif`/`xfail`/`sleep(` lines: **0** (`grep -nE '^\+.*(skip|skipif|xfail|sleep\()'` → none).
- Removed `def test_` names: **0** (`grep -nE '^-def test_'` → none); the test file diff has no `-` lines (append only).
- `Binding` import present at `s19_app/tui/screens.py:14` (as the brief requires).

## Step 2 — GREEN vs base
Base clone: `git clone ~/work/zq-fb/fb.bundle ~/work/zq-ta/chk-U-DLG-base` → HEAD `03d3594b` (branch b103-fix-round), clean.

Base transcript (reproduced): copied the worker's appended test file onto the base product (unchanged) and ran the new nodes:
```
$ ... pytest -q -n 0 tests/test_b101_reach_and_reports_escape.py::test_r_dlg_2_13_escape_does_what_cancel_does tests/test_b101_reach_and_reports_escape.py::test_r_dlg_2_14_escape_in_save_flow_saves_nothing
8 failed in 110.01s (0:01:50)
```
Base-RED nodes: all 7 `test_r_dlg_2_13[...]` cases + `test_r_dlg_2_14`.

On the copy (product fixed), same command → **8 passed in 33.47s** (every base-RED node now GREEN).

Existing `test_r_dlg_2_*` nodes (1–12), same `-n 0`:
```
... pytest -q -n 0 -k "test_r_dlg_2_ and not test_r_dlg_2_13 and not test_r_dlg_2_14" tests/test_b101_reach_and_reports_escape.py
12 passed, 14 deselected in 70.81s (0:01:10)
```
No node that passed at base fails now.

Regression files named by the brief (constructors), `-n 4`:
```
tests/test_tui_flow_persistence_ui.py tests/test_tui_variants.py tests/test_tui_crc_surface.py tests/test_b100_load_question.py tests/test_tui_patch_editor_v2.py tests/test_tui_operations_view.py
146 passed, 1 skipped in 268.16s (0:04:28)
```

## Step 3 — Negative controls
Second copy `~/work/zq-ta/chk-U-DLG-nc`; mutation (worker's): delete the `SaveFlowScreen` `BINDINGS = [Binding("escape", "cancel", "Cancel", show=False)]` line (`s19_app/tui/screens.py:1433`).

Affected nodes, run only those:
```
$ ... pytest -q -n 0 "tests/test_b101_reach_and_reports_escape.py::test_r_dlg_2_13_escape_does_what_cancel_does[SaveFlowScreen]" tests/test_b101_reach_and_reports_escape.py::test_r_dlg_2_14_escape_in_save_flow_saves_nothing
2 failed in 28.33s
```
RED lines:
- `E   AssertionError: did not settle: SaveFlowScreen closes by escape; stack ['Screen', 'SaveFlowScreen']` (tests/support/timing.py:66)
- `E   AssertionError: did not settle: Save flow closes on Escape; stack ['Screen', 'SaveFlowScreen']` (tests/support/timing.py:66)

Full 8-node run under the mutation (surgical check): `2 failed, 6 passed in 51.45s` (only `[SaveFlowScreen]` + `test_r_dlg_2_14` RED; the other 6 cases GREEN). Both controls stayed RED ⇒ no MECH-NO-GO.

## Step 4 — Laws
```
$ ... pytest -q -n 0 tests/test_suite_hygiene.py tests/test_requirements_canon.py tests/test_id_registry.py tests/test_address_census.py tests/test_import_census.py tests/test_no_private_tokens.py
116 passed, 2 skipped in 408.80s (0:06:48)
```
All six GREEN (matches the 03d3594b expectation). No RED.

## Step 5 — Worker claims (5 re-verified)
1. "N0 baseline = 9827; after = 9835 (+8)" — TRUE. `--collect-only -q tests` on base (original test file): `9827 tests collected`; on copy: `9835 tests collected`.
2. "git diff --stat: 3 files, +202/−17; CR count 0" — TRUE (reproduced exactly).
3. "Step 2 new nodes RED on unchanged product = 8 failed (7 `did not settle: <Class> closes by escape` + Save-flow case)" — TRUE (base reproduction: `8 failed`).
4. "Step 5 new nodes → 8 passed; existing `test_r_dlg_2_*` → 12 passed, 14 deselected" — TRUE (`8 passed`; `12 passed, 14 deselected`).
5. "Negative control (delete SaveFlowScreen BINDINGS) → 2 failed, 6 passed with RED `did not settle: SaveFlowScreen closes by escape` / `Save flow closes on Escape`" — TRUE (`2 failed, 6 passed`; exact RED lines reproduced).

## Step 6 — Diff saved
`cp ~/work/zq-ta/chk-U-DLG.diff ~/work/zq-ta/U-DLG/CHECK.diff`

CHECK_DONE U-DLG MECH-GO

## Orchestrator intent review (Opus, relevo-21)
GO. Seven dialogs that ignored Escape (CTX-DIALOG "Esc today = no": Select variant, Save flow, Load flow, Discard unsaved flow edits, Edit entry JSON, Confirm write, Operations) get a screen binding whose action is the same method the Cancel/Close button now calls, so the two paths cannot drift (batch-101 Inc 12 ruling D-7 A, the ChangeSetJsonScreen idiom); dismiss values are unchanged (`None`, `False`, `ConfirmWriteResult(False, width)`), log lines move into the shared method. Checked: no Cancel/Close button is ever disabled in `screens.py`, so Escape bypasses no guard. Tests: `test_r_dlg_2_13` (7 cases: Escape closes like the button) and `test_r_dlg_2_14` (Escape in Save flow saves nothing), 8 RED before / GREEN after; binding removed -> RED. The design asked for an extra independent Sonnet tester on U-DLG (MD-09); decided (DF-02) that this Opus review plus the DeepSeek CHK-ds cover MD-09's "independent tester or Opus reviewer": the change is seven identical bindings, each pinned by a pilot test.
