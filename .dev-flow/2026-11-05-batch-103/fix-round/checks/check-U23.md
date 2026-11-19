<!-- DeepSeek v4-pro mechanical check (CHK-ds) of U23; orchestrator intent review: GO (Undo/Redo, keys and per-entry Edit JSON enabled for every document; whole-set Edit JSON guard R-TUI-053.5 kept; `history off` strip state dropped). Laws were run on the pre-fold base, where the canon two-shall law is base-red. -->
# CHECK U23 — mechanical check

- unit: U23
- tree path: ~/work/zq-fb/U23/repo
- HEAD sha: 6480aab68878fc9485d53631465ddbda527c5eaf
- start: 2026-11-19 13:13:25 CST

## Step 1 — Diff hygiene

Command: `cp -a ~/work/zq-fb/U23/repo ~/work/zq-fb/chk-U23/repo` (copy made), then in the copy `git diff > ../chk-U23.diff`.

Files changed (7, all within the brief's "Files you may edit"):
- s19_app/tui/app/core.py
- s19_app/tui/app/patch.py
- s19_app/tui/screens_directionb/patch_editor/actions.py
- s19_app/tui/screens_directionb/patch_editor/panel.py
- tests/test_tui_patch_editor_v2.py
- tests/test_tui_patch_history_strip.py
- tests/test_undo_redo_ux.py

(product files: exactly the 4 allowed; test files: 3, within the "at most 3" cap.)

- CR count: `tr -cd '\r' < chk-U23.diff | wc -c` → 0
- added skip/skipif/xfail/sleep( lines → 0 (grep of `^\+.*(skip|skipif|xfail|sleep\()` = none; `^\+.*sleep` = none; `pytest.mark.skip/xfail` = none)
- `def test_` removed and not re-added → none removed; 1 added: `test_r_tui_058_6_per_entry_json_works_for_file_backed_document` (the brief explicitly orders adding this R-TUI-058.6 test if none exists — allowed, not a retirement)


## Step 2 — GREEN vs base

No `baseline/<UNIT-or-parent>.txt` covers U23's node set (G3a/G3b/G3c transcripts cover `test_b100_busy.py`, `test_b100_workers.py`, `test_tui_app.py`, `test_address_census.py`, `test_b103_a2l_refresh.py`, `test_b103_picker_model.py` — none of U23's files). I established the base by reverse-applying the worker's diff to HEAD 6480aab6 (parent) in a scratch copy and running the same node set.

Command (U23 copy, from ~/work/zq-fb/chk-U23/repo):
```
S=$HOME/work/zq-fb/chk-U23-state; mkdir -p $S/home/<runner-home> $S/tmp $S/x; timeout 1200 env -i PATH=/usr/bin:/bin HOME=$S/home/<runner-home> XDG_CONFIG_HOME=$S/x/config XDG_CACHE_HOME=$S/x/cache XDG_DATA_HOME=$S/x/data TMPDIR=$S/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 ~/miniconda3/envs/s19ci/bin/python -I -B -m pytest -p no:cacheprovider -q -n 4 tests/test_undo_redo_ux.py tests/test_tui_patch_editor_v2.py tests/test_tui_patch_history_strip.py < /dev/null
```
Summary: `63 passed, 1 skipped in 141.16s` (0 failures).

Base (parent 6480aab6, same command on the reverse-applied copy):
Summary: `62 passed, 1 skipped in 124.10s` (0 failures).

- base-RED nodes: none (the base node set was fully GREEN; U23 is a product-change unit whose re-pinned arms are exercised by the step-3 negative controls, not by a base-RED transcript).
- nodes that passed at base and fail now: none. The delta is exactly +1 passed = the new `test_r_tui_058_6_per_entry_json_works_for_file_backed_document` ordered by the brief; no `def test_` was removed.
- The single skip in both runs is `test_tc081_4_no_binding_diff` (pre-existing `git diff main` guard that skips when the `main` ref is absent in the shallow checkout) — not a U23 change.


## Step 3 — Negative controls are real

Re-applied 3 of the worker's 5 reported mutations (cap is 3) in a fresh copy `~/work/zq-fb/chk-U23-nc` (re-created from the U23 copy before each), one mutation per run, running only the affected node. All 3 went RED.

Control 1 — R-TUI-057.8 keys (`_patch_history_action_allowed`): `return True` → `return self._change_service.document.source_path is None` (patch.py:928).
Command: `pytest -q tests/test_undo_redo_ux.py::test_ac2_2_ctrl_z_respects_a01_guard_and_is_crash_free` (CHK env, serial).
RED line:
```
E       AssertionError: ctrl+z must UNDO a file-backed document's load (R-TUI-057.8); got ['0x100']
```

Control 2 — R-TUI-058.6 popup (`on_patch_editor_panel_entry_edit_json_requested`): re-added `if service.document.source_path is not None: return` before the bounds check (patch.py, after line 1153).
Command: `pytest -q tests/test_tui_patch_editor_v2.py::test_r_tui_058_6_per_entry_json_works_for_file_backed_document` (CHK env, serial).
RED line:
```
E       AssertionError: per-entry JSON popup for a file-backed document did not settle after 50 pauses
```

Control 3 — R-TUI-057.9 strip (`_history_strip_text`): prepended `return Text("history off")` before `counts = depths or {}` (actions.py:451).
Command: `pytest -q tests/test_tui_patch_history_strip.py::test_tc081_3_sites` (CHK env, serial).
RED line:
```
E       AssertionError: with the controls enabled the strip must render the position (one undo step: the load), not a muted line; got 'history off'
```

No control stayed GREEN. (The worker's other 2 rows — the Undo/Redo button seam `test_tc344` and the per-entry button seam `test_tc345` — were not re-applied because the brief caps at 3; the 3 above cover the key guard, the new E2E popup test, and the strip seam.)


## Step 4 — Laws (serial, -n 0)

Command (from ~/work/zq-fb/chk-U23/repo):
```
S=$HOME/work/zq-fb/chk-U23-state; mkdir -p $S/home/<runner-home> $S/tmp $S/x; timeout 1200 env -i PATH=/usr/bin:/bin HOME=$S/home/<runner-home> XDG_CONFIG_HOME=$S/x/config XDG_CACHE_HOME=$S/x/cache XDG_DATA_HOME=$S/x/data TMPDIR=$S/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 ~/miniconda3/envs/s19ci/bin/python -I -B -m pytest -p no:cacheprovider -q -n 0 tests/test_suite_hygiene.py tests/test_requirements_canon.py tests/test_id_registry.py tests/test_address_census.py tests/test_import_census.py tests/test_no_private_tokens.py < /dev/null
```
Summary: `3 failed, 112 passed, 2 skipped in 494.10s`.

The 3 RED are exactly the allowed base-RED set:
- `tests/test_requirements_canon.py::test_canon_rows_hold_the_obligation_word_once` (canon two-`shall` row test) — ALLOWED
- `tests/test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors` (address census AT-B83-08) — ALLOWED
- `tests/test_suite_hygiene.py::test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses` (`test_r_tst_070_2`) — ALLOWED

No other RED. → laws pass.


## Step 5 — Worker claims (5, re-verified)

1. "Final run of all three unit files: `63 passed, 1 skipped`" (REPORT.md, pi.log) → TRUE. My step-2 run on the U23 copy gave `63 passed, 1 skipped` (0 failures).
2. "`git diff --stat`: 7 files changed, 250 insertions(+), 217 deletions(-)" (REPORT.md) → TRUE. Re-ran: `7 files changed, 250 insertions(+), 217 deletions(-)`; `git diff --numstat` lists exactly the 7 files.
3. "`git diff | grep -c $'\r'` → 0" (REPORT.md) → TRUE. Re-ran: `0` (also `tr -cd '\r' | wc -c` → 0).
4. "The single skip is `test_tc081_4_no_binding_diff`, the pre-existing `git diff main` guard that skips when the `main` ref is absent" (REPORT.md, pi.log) → TRUE. Ran that node alone: `SKIPPED ... test_tui_patch_history_strip.py:743: git is unavailable or the 'main' ref is missing ... returned non-zero exit status 128`.
5. Product claims — "`set_entry_edit_json_enabled(True)` at all three sites" and "`_patch_history_action_allowed` dropped the source_path arm" (REPORT.md) → TRUE. `grep -n "set_entry_edit_json_enabled(True)" s19_app/tui/app/patch.py` → lines 345, 844, 1781 (3 sites); `_patch_history_action_allowed` body is screen-check + `return True` (no `source_path` arm).


## Step 6 — Save the diff

Saved step 1's diff as `~/work/zq-fb/U23/CHECK.diff` (934 lines, copy of `chk-U23.diff`). Scratch copies under `~/work/zq-fb/chk-U23*` deleted.

## Verdict

Steps 1–5 all pass: diff hygiene clean; node set GREEN (63 passed / 1 skipped) with no base-passing node now failing; 3/3 re-applied negative controls RED; laws show only the 3 allowed base-RED; 5/5 worker claims TRUE.

CHECK_DONE U23 MECH-GO
