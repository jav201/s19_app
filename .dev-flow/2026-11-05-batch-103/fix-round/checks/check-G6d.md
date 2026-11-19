# CHECK G6d

- Unit: G6d
- Tree path: ~/work/zq-fb/G6d/repo
- HEAD sha: 2a8ab75f2fcff5d939eba00372ecf11ea4dda886
- Start time: 2026-11-19 15:43:35 CST

## Step 1 — Diff hygiene

Command: `cp -a G6d/repo chk-G6d` ; in the copy `git diff > ../chk-G6d.diff`.

Files changed (git diff --name-only):
```
REQUIREMENTS.md
s19_app/tui/a2l_label_list.py
s19_app/tui/app/a2l_view.py
s19_app/tui/styles.tcss
tests/test_b103_a2l_list_view.py
```
All 5 are within the brief's "Files you may edit". ✓

- CR count (`tr -cd '\r' < diff | wc -c`): 0 ✓
- Added `skip`/`skipif`/`xfail`/`sleep(` lines: none ✓
- `def test_` removed and not re-added: none ✓
- `def test_` added: `test_r_a2l_list_092_3`, `test_r_a2l_list_093_1`, `test_r_a2l_list_093_2` (3 new, as the brief orders) ✓

## Step 2 — GREEN vs base

Note: no `baseline/G6d.txt` or `baseline/G6.txt` exists on this host (checked `baseline/`). The base-RED state for this unit is recorded in the worker's `REPORT.md` ("Base outcome") and the unit brief's "First run the five new nodes ... 092_3 and 093_1 must be RED there".

Command (`-n 0`, 12 nodes, from the copy root):
```
S=$HOME/work/zq-fb/chk-G6d-state; ... ~/miniconda3/envs/s19ci/bin/python -I -B -m pytest -p no:cacheprovider -q tests/test_b103_a2l_list_view.py::test_r_a2l_list_092_1 ::test_r_a2l_list_092_2 ::test_r_a2l_list_092_3 ::test_r_a2l_list_093_1 ::test_r_a2l_list_093_2 ::test_r_a2l_list_090_1 ::test_r_a2l_list_083_1 ::test_r_a2l_list_083_2 ::test_r_a2l_list_083_3 ::test_r_a2l_list_016_1 ::test_r_a2l_list_016_2 tests/test_b99_a2l_encode.py::test_at_b99_09_a2l_window_physical_column < /dev/null
```
Result: `12 passed in 221.47s`.

Base-RED nodes and their result now:
- `test_r_a2l_list_092_3` — RED at base (`assert 0 >= 1`); now PASS ✓
- `test_r_a2l_list_093_1` — RED at base (`assert True is False`); now PASS ✓

Nodes that passed at base and fail now: none (all 12 pass). ✓

## Step 3 — Negative controls are real

All three briefed mutations re-applied in a fresh `~/work/zq-fb/chk-G6d-nc` copy, each running only its affected node.

1. NC-1 — removed `#a2l_panes.-tiny.-list #a2l_tags_summary { display: none; }` from `s19_app/tui/styles.tcss`.
   - `::test_r_a2l_list_092_3` → `E       AssertionError: assert 0 >= 1` (RED) ✓
   - `::test_r_a2l_list_093_1` → `E       assert True is False` (RED) ✓
2. NC-2 — `panes.first().add_class("-list")` only when `names is not None`, never removed (a2l_view.py).
   - `::test_r_a2l_list_093_2` → `E       AssertionError: assert ('FILTER' == 'FILTER' ... and not True)` (RED) ✓
3. NC-3 — `TINY_BELOW_HEIGHT = 9` (a2l_label_list.py:76).
   - `::test_r_a2l_list_092_3` → `E       AssertionError: assert 0 >= 1` (RED) ✓

No control stayed GREEN. ✓

## Step 4 — Laws (serial, `-n 0`)

Command:
```
S=$HOME/work/zq-fb/chk-G6d-state; ... ~/miniconda3/envs/s19ci/bin/python -I -B -m pytest -p no:cacheprovider -q -n 0 tests/test_suite_hygiene.py tests/test_requirements_canon.py tests/test_id_registry.py tests/test_address_census.py tests/test_import_census.py tests/test_no_private_tokens.py < /dev/null
```
Result: `116 passed, 2 skipped in 405.86s` (0 failed).

The 2 skips are pre-existing environment skips, not added by this unit:
- `tests/test_suite_hygiene.py:864: the workflow's base version is not available in this checkout`
- `tests/test_suite_hygiene.py:1434: no merge-base with main in this checkout`

No RED at all. The three base-allowed RED (canon two-shall row test, address census `test_at_b83_08…`, `test_r_tst_070_2`) all pass here. No other RED → not a MECH-NO-GO. ✓

## Step 5 — Worker claims (5 re-verified)

1. HEAD sha `2a8ab75f2fcff5d939eba00372ecf11ea4dda886` (short `2a8ab75f`). → TRUE. `git rev-parse HEAD` in the copy prints `2a8ab75f2fcff5d939eba00372ecf11ea4dda886`.
2. `git diff --stat` = 5 files changed, 60 insertions(+), 4 deletions(-); and `git diff | grep -c $'\r'` = 0. → TRUE. Re-ran: stat is byte-identical (60 insertions, 4 deletions, 5 files); CR count = 0.
3. 12-node set (`-n 0`, timeout) = `12 passed`. → TRUE. Re-run gave `12 passed in 221.47s` (worker: 224.21s — timing varies, count matches).
4. `tests/test_requirements_canon.py` + `tests/test_address_census.py` (`-n 0`) = `34 passed`. → TRUE. Re-run gave `34 passed in 44.83s` (worker: 42.49s).
5. Whole `tests/test_b103_a2l_list_view.py` (`-n 4`) = `122 passed`. → TRUE. Re-run gave `122 passed in 474.93s` (worker: 399.80s).

Also re-verified (cheap): `git show HEAD:REQUIREMENTS.md | grep -n "R-A2L-LIST.093"` → not found (exit 1), i.e. the `.093` id did not exist pre-edit; and the three pre-edit canon "current" lines are byte-equal to the brief's Row-4 texts. The step-3 NC RED lines match the worker's recorded RED lines exactly.

## Step 6 — Save the diff

Copied step 1's diff to `~/work/zq-fb/G6d/CHECK.diff` (sha256 `6c0015d16b86001d531ba79c7c2e2cc73463e37025da6abbe404cccf1a417cd1`, 9351 bytes, identical to the working copy's `git diff`).

## Verdict

Steps 1–5 all pass → MECH-GO.

CHECK_DONE G6d MECH-GO

## Orchestrator intent review (relevo-20 GO, P-195; recorded by relevo-21)
GO. The diff implements operator card I = A exactly: list mode below 10 body rows hides the position line (`#a2l_panes.-tiny.-list #a2l_tags_summary { display: none; }`), so at 80×24 (body 9) a tag row paints; text mode is unchanged (`-list` is set only while `names is not None`, and 093_2 proves clearing the list removes it). Canon: R-A2L-LIST.016 now holds from body 10, .092 extends to body 9, new .093 states the hiding; the counts stay on the first chips line, so no information is lost. Base RED for 092_3 / 093_1, controls RED for all three new nodes.
