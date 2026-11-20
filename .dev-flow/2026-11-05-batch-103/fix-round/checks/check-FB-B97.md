# CHECK — Unit FB-B97

unit: FB-B97
tree path: ~/work/zq-fb/FB-B97/repo
HEAD sha: a79614220ba35a3c904d395e31a541f10fba258e
start time: Fri Nov 20 02:11:49 AM CST 2026

---

## Step 1 — Diff hygiene

Command:
```
cp -a ~/work/zq-fb/FB-B97/repo ~/work/zq-fb/chk-FB-B97
cd ~/work/zq-fb/chk-FB-B97 && git diff > ../chk-FB-B97.diff
```

- HEAD in copy: `a79614220ba35a3c904d395e31a541f10fba258e` (matches unit tree).
- Files changed: `tests/test_b97_key_bar.py` (only). This is exactly the brief's "Files you may edit".
- CR count (`tr -cd '\r' < ../chk-FB-B97.diff | wc -c`): `0`.
- Added `skip`/`skipif`/`xfail`/`sleep(` lines: none (grep over `^+` lines → empty).
- `def test_` names removed: none (grep over `^-` lines → empty). Node-id set unchanged (see step 2 collect-only).
- `git diff --stat`: `tests/test_b97_key_bar.py | 41 +++++++++++++++++++++++++----------------` — 1 file changed, 25 insertions(+), 16 deletions(-).

PASS.

## Step 2 — GREEN vs base

Node set run on the copy (exact commands):

```
S=$HOME/work/zq-fb/chk-FB-B97-state; mkdir -p $S/home/<runner-home> $S/tmp $S/x; timeout 1200 env -i PATH=/usr/bin:/bin HOME=$S/home/<runner-home> XDG_CONFIG_HOME=$S/x/config XDG_CACHE_HOME=$S/x/cache XDG_DATA_HOME=$S/x/data TMPDIR=$S/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 ~/miniconda3/envs/s19ci/bin/python -I -B -m pytest -p no:cacheprovider -q -n 0 tests/test_b97_key_bar.py::test_tc_b97_69_dimmed_entries_follow_their_condition tests/test_b97_key_bar.py::test_tc_b97_72_clicks_run_the_action_and_type_nothing < /dev/null
```
→ `2 passed in 15.64s`

```
S=$HOME/work/zq-fb/chk-FB-B97-state; mkdir -p $S/home/<runner-home> $S/tmp $S/x; timeout 1200 env -i PATH=/usr/bin:/bin HOME=$S/home/<runner-home> XDG_CONFIG_HOME=$S/x/config XDG_CACHE_HOME=$S/x/cache XDG_DATA_HOME=$S/x/data TMPDIR=$S/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 ~/miniconda3/envs/s19ci/bin/python -I -B -m pytest -p no:cacheprovider -q -n 4 tests/test_b97_key_bar.py < /dev/null
```
→ `38 passed in 125.47s (0:02:05)`

Base transcript: no `baseline/<UNIT-or-parent>.txt` exists for `test_b97_key_bar.py` (baseline/ holds only G-series transcripts for other files; `grep -rl key_bar baseline/` → empty). So I generated the base result from the base clone `~/work/zq-fb/base` (= 3afebf90).

Collect-only node-id sets are identical (38 nodes both sides; `diff` → "identical node id sets").

Base clone run of the same file (`-n 4`): `1 failed, 37 passed in 170.87s` — the single failure is `tests/test_b97_key_bar.py::test_tc_b97_69_page_keys_do_nothing_where_disabled` with `AssertionError: did not settle: A2L loaded` (a parallel-only timing flake). Re-run of that one node `-n 0`: `1 passed in 34.53s` — so it is not a deterministic base RED, and it PASSES on the work tree now.

- Base-RED nodes (deterministic): none. The only base `-n 4` failure is a timing flake (passes serially at base and passes on the work tree).
- Nodes that passed at base and fail now: none (work tree `-n 4` = `38 passed`).

PASS.

## Step 3 — Negative controls are real

Second copy `~/work/zq-fb/chk-FB-B97-nc` from the same tree. Three mutations re-applied from REPORT.md (two worker rows + the orchestrator's at_b97_26 control):

1. Row-1 control (tc_b97_69) — in `s19_app/tui/app/patch.py::_patch_history_action_allowed`, `return True` → `return self._change_service.document.source_path is None` (restores the old file-backed dim guard; faithful to `git show f7973d8f`).
   Run `-n 0` the affected node → RED:
   ```
   E   assert (True, True) == (False, False)
   tests/test_b97_key_bar.py:868: AssertionError
   1 failed in 6.76s
   ```

2. Orchestrator control (at_b97_26) — same `_patch_history_action_allowed` mutation.
   Run `-n 0` the affected node → RED:
   ```
   E   assert (True, True) == (False, False)
   tests/test_b97_key_bar.py:1588: AssertionError
   1 failed in 9.47s
   ```

3. Row-2 control (tc_b97_72) — in `s19_app/tui/app/navigation.py::key_condition`, the `has_variants` arm `return self._variant_set is not None and bool(self._variant_set.variants)` → `return True` (token lit).
   Run `-n 0` the affected node → RED:
   ```
   E   assert (False,) == (True,)
   tests/test_b97_key_bar.py:1283: AssertionError
   1 failed in 4.84s
   ```

All three controls go RED at the expected assertion. No control stayed GREEN.

PASS.

## Step 4 — Laws

Command (serial, from the copy root):
```
S=$HOME/work/zq-fb/chk-FB-B97-state; mkdir -p $S/home/<runner-home> $S/tmp $S/x; timeout 1200 env -i PATH=/usr/bin:/bin HOME=$S/home/<runner-home> XDG_CONFIG_HOME=$S/x/config XDG_CACHE_HOME=$S/x/cache XDG_DATA_HOME=$S/x/data TMPDIR=$S/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 ~/miniconda3/envs/s19ci/bin/python -I -B -m pytest -p no:cacheprovider -q -n 0 tests/test_suite_hygiene.py tests/test_requirements_canon.py tests/test_id_registry.py tests/test_address_census.py tests/test_import_census.py tests/test_no_private_tokens.py < /dev/null
```
→ `118 passed in 418.19s (0:06:58)`

No RED at all (not even the allowed base RED set). PASS.

## Step 5 — Worker claims

1. Claim: HEAD sha = `a79614220ba35a3c904d395e31a541f10fba258e` (REPORT header).
   Verify: `git rev-parse HEAD` in the copy → `a79614220ba35a3c904d395e31a541f10fba258e`. TRUE.

2. Claim: only `tests/test_b97_key_bar.py` was modified (pi.log).
   Verify: `git status --short` in the copy → ` M tests/test_b97_key_bar.py` (nothing else). TRUE.

3. Claim: nc-1 RED line `E   assert (True, True) == (False, False)` (REPORT row 1).
   Verify: reproduced in step 3 control 1. TRUE.

4. Claim: nc-2 RED line `E   assert (False,) == (True,)` (REPORT row 2).
   Verify: reproduced in step 3 control 3. TRUE.

5. Claim: final two-node `-n 0` run → `2 passed` (REPORT "Final two-node run").
   Verify: step 2 `-n 0` → `2 passed in 15.64s`. TRUE (timing differs trivially; count matches).

6. Claim: diff stat `25 insertions(+), 16 deletions(-)`, CR `0` (REPORT orchestrator section).
   Verify: step 1 `git diff --stat` → `25 insertions(+), 16 deletions(-)`; CR count → `0`. TRUE.

All verified claims TRUE.

## Step 6 — Save the diff

```
cp ~/work/zq-fb/chk-FB-B97.diff ~/work/zq-fb/FB-B97/CHECK.diff
```
Saved (identical to step 1's diff; CR count 0).

---

## Verdict

Steps 1–5 all pass. The single base-side `-n 4` failure (`test_tc_b97_69_page_keys_do_nothing_where_disabled`, "did not settle: A2L loaded") is a parallel-only timing flake at base that passes serially at base and passes on the work tree; it is unrelated to this unit's re-pin.

CHECK_DONE FB-B97 MECH-GO

## Orchestrator note on step 2 (Opus, relevo-25)
HT-07: the base-side `-n 4` failure of `test_tc_b97_69_page_keys_do_nothing_where_disabled` ("did not settle: A2L loaded") is one parallel failure that passes serially; it is recorded as load-sensitive, not called flaky (no N ≥ 10 measurement). It is not in this unit's diff and passed on the work tree.

## Orchestrator intent review (Opus, relevo-25)
GO. All three nodes change only the expectation that D10-23 superseded (R-TUI-057.8: Undo, Redo and their keys enabled for every document; product commit f7973d8f). No other arm, wait or oracle moves (TR-01).
- Row 1 (tc_b97_69): the file-backed arm now expects `^z ^y` lit (`(False, False)`); the docstring cites R-TUI-057.8 / D10-23. The image, unload and variant dim arms are unchanged. Control: the old file-backed guard restored in `patch.py::_patch_history_action_allowed` → RED.
- Row 2 (tc_b97_72): `^z Undo` can no longer serve as the dimmed token, so the dimmed-click arm clicks `v Select variant` (no variant set loaded), with a new pre-click assert that it is dimmed. The oracle is the same: the screen stays `patch`, the change document is unchanged, exactly one bell. The pre-click assert keeps the arm from passing on a lit token that happens to do nothing. Control: the `has_variants` condition forced lit → the pre-click assert RED.
- Orchestrator fix (worker open question 1): `test_at_b97_26_keys_only_help_and_hidden_view` carried the same superseded file-backed expectation (FAILS on a7961422, PASSES on main 3afebf90). Re-pinned the same way (assert, docstring clause, one comment). Its paste arm already expected the keys lit. Control: the old guard → RED. The three nodes `-n 0` → 3 passed (rtx).
- Residual (recorded): AT-B97-26 and TC-B97-69 no longer show a dimmed→lit flip for Undo/Redo, because the approved design has no such flip any more. TC-B97-69 still covers the flip mechanism through its image and variant arms.
