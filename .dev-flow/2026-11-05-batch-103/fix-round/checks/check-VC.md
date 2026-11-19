# CHECK — VC2 (mechanical, DeepSeek v4-pro)

- unit: VC2
- tree: ~/work/zq-fb/VC2/repo
- HEAD sha: c46ac1950ee34275b88019e91b8bbd7bffc2f7e0
- start: 2026-11-19T19:54:17Z

## Step 1 — Diff hygiene
`cp -a ~/work/zq-fb/VC2/repo ~/work/zq-fb/chk-VC2` ; in the copy `git diff > ~/work/zq-fb/chk-VC2.diff` (59 lines).
- Files changed: `REQUIREMENTS.md`, `s19_app/tui/definition_sheet.py`, `tests/test_b103_inc8b_s2.py`.
  - Allowed by brief: `REQUIREMENTS.md`, `tests/test_b103_inc8b_s2.py`.
  - `s19_app/tui/definition_sheet.py` is the inherited `../VC.diff` product change (brief says apply it first and keep it as is); verified byte-identical to `~/work/zq-fb/VC2/VC.diff`.
- CR count (`tr -cd '\r' < diff | wc -c`) = 0.
- Added `skip`/`skipif`/`xfail`/`sleep(` lines = 0.
- `def test_` names removed = 0; added = 1 (`test_r_pe_def_97_12_the_card_is_on_the_expanded_ground`, the new node the brief orders).

## Step 2 — GREEN vs base (node set run on copy ~/work/zq-fb/chk-VC2)
Commands (each from the copy root, isolated env as the brief's one-liner, `S=~/work/zq-fb/chk-VC2-state`):
- new test `-n 0`: `... -m pytest -p no:cacheprovider -q -n 0 tests/test_b103_inc8b_s2.py::test_r_pe_def_97_12_the_card_is_on_the_expanded_ground` → `1 passed in 0.17s`
- canon laws `-n 0`: `tests/test_requirements_canon.py tests/test_id_registry.py` → `23 passed in 8.24s`
- `tests/test_b103_inc8b_s2.py -n 4` → `39 passed in 1.74s`
- `tests/test_b103_inc8b_*.py tests/test_b103_inc8_s1_detail.py -n 4` → `225 passed in 198.53s`

Base transcript comparison:
- The only base transcript covering any node-set file is `~/work/zq-fb/baseline/G1.txt`, which ran `tests/test_b103_inc8b_at.py` (part of the `inc8b_*.py` glob) at base 3afebf90. It shows **0 FAILED** in `test_b103_inc8b_at.py` (all its nodes PASSED).
- `~/work/zq-fb/baseline/` has **no transcript** for `test_b103_inc8b_s1.py`, `test_b103_inc8b_s2.py`, `test_b103_inc8b_bw.py` or `test_b103_inc8_s1_detail.py` (none of them appear in any G-unit baseline). So there is no recorded base-RED list for those four files.
- Base-RED nodes in this node set: **none** (from the available transcript).
- Nodes that passed at base and fail now: **none** (the full glob is `225 passed`, 0 failed).

Combined node count matches the worker's final run: 23 (canon laws) + 225 (glob) = 248.

## Step 3 — Negative control (copy ~/work/zq-fb/chk-VC2-nc)
Mutation (from REPORT.md row 2): in `s19_app/tui/definition_sheet.py` re-add `DEPTH_PANEL` to the `insight_style` import and set `_CARD_GROUND = DEPTH_PANEL` (restores #0f1525).
Command: `... -m pytest -p no:cacheprovider -q -n 0 tests/test_b103_inc8b_s2.py::test_r_pe_def_97_12_the_card_is_on_the_expanded_ground` (isolated env).
Result: `1 failed in 0.22s`.
RED assertion line:
```
E           AssertionError: ('  ┊ │ bit     15 14 13 12 │ 11 10  9  8 │  7  6  5  4 │  3  2  1  0 │ hex   │  ...', {'#0f1525'})
E           assert {'#0f1525'} == {'#1b233a'}
```
Control goes RED as claimed. PASS.

## Step 4 — Laws (serial, `-n 0`, on copy ~/work/zq-fb/chk-VC2)
Command: `... -m pytest -p no:cacheprovider -q -n 0 tests/test_suite_hygiene.py tests/test_requirements_canon.py tests/test_id_registry.py tests/test_address_census.py tests/test_import_census.py tests/test_no_private_tokens.py`
Result: `2 failed, 113 passed, 2 skipped in 421.24s`.
- FAILED `test_suite_hygiene.py::test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses` → allowed RED at base.
- FAILED `test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors` → allowed RED at base.
- `test_requirements_canon.py::test_canon_rows_hold_the_obligation_word_once` (the canon two-shall row test) is now GREEN (was the third allowed RED at base) — a change brought by the fix-round tip, not a new RED.
No other RED. PASS.

## Step 5 — Worker claims (5 re-verified)
1. HEAD sha = `c46ac1950ee34275b88019e91b8bbd7bffc2f7e0` (REPORT header). `git rev-parse HEAD` in the copy → `c46ac1950ee34275b88019e91b8bbd7bffc2f7e0`. **TRUE**
2. Row 1 canon laws `-n 0 tests/test_requirements_canon.py tests/test_id_registry.py` → 23 passed (worker: 23 passed). My run → `23 passed in 8.24s`. **TRUE**
3. Row 2 node set: new test `1 passed`; file `39 passed`; glob `225 passed` (worker: same). My runs → `1 passed in 0.17s`, `39 passed in 1.74s`, `225 passed in 198.53s`. **TRUE**
4. Negative-control RED line `assert {'#0f1525'} == {'#1b233a'}` (worker's REPORT row 2). My nc run → identical line. **TRUE**
5. `git diff --stat` = 3 files, `16 insertions(+), 3 deletions(-)` and CR count 0 (worker final checks). Copy → `REQUIREMENTS.md | 2 +-`, `definition_sheet.py | 4 ++--`, `test_b103_inc8b_s2.py | 13 ++++` = `3 files changed, 16 insertions(+), 3 deletions(-)`; `git diff | grep -c $'\r'` → 0. **TRUE**

Final-run sum cross-check: 23 (canon laws) + 225 (glob) = 248, matching the worker's `248 passed` final combined run.

CHECK_DONE VC2 MECH-GO
