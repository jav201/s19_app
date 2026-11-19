# CHECK G6c — mechanical check

unit: G6c
tree: ~/work/zq-fb/G6c/repo
HEAD sha: c579fa463f733313ff67760c04ad76052cec9db5
start: Thu Nov 19 02:28:33 PM CST 2026

## Step 1 — Diff hygiene
Command: `cp -a ~/work/zq-fb/G6c/repo ~/work/zq-fb/chk-G6c`; in the copy `git diff > ../chk-G6c.diff`.

Files changed (must be within brief's "Files you may edit" + check-scope total):
- REQUIREMENTS.md
- s19_app/tui/a2l_label_list.py
- s19_app/tui/styles.tcss
- tests/test_b103_a2l_list_view.py
- tests/test_b99_a2l_encode.py
→ all 5 are within the allowed set {s19_app/tui/a2l_label_list.py, s19_app/tui/styles.tcss, REQUIREMENTS.md, tests/test_b99_a2l_encode.py, tests/test_b103_a2l_list_view.py}. OK.

CR count: `tr -cd '\r' < chk-G6c.diff | wc -c` → 0. OK.
Added skip/skipif/xfail/sleep( lines: none. OK.
`def test_` names removed and not re-added: none (no `^-.*def test_` lines). OK.
Added `def test_` names: test_r_a2l_list_092_1, test_r_a2l_list_092_2, test_r_a2l_list_090_1 (these are the brief-ordered renames of the uncommitted 091_1/091_2 plus G6b's 090_1; no 091_1/091_2 remain in the tree — grep confirms 0 hits). OK.

## Step 2 — GREEN vs base
Note: no base transcript exists for G6/G6b/G6c (baseline/ has G1,G3a,G3b,G3c,G3cF,G4,G5a,G5b,G7,G9,laws — none for this unit). Per the check-scope note the base-RED node is `test_at_b99_09_a2l_window_physical_column` after G6's new assertion. Ran the brief's node set on the copy:

- `-n 0` canon: `tests/test_requirements_canon.py` → `11 passed in 0.37s`
- `-n 0` 6 nodes (092_1, 092_2, 090_1, 083_1, 083_2, 083_3) → `6 passed in 105.63s`
- `-n 0` `tests/test_b99_a2l_encode.py::test_at_b99_09_a2l_window_physical_column` → `1 passed in 46.20s`
- `-n 4` whole `tests/test_b103_a2l_list_view.py` → `119 passed in 385.97s`

Base-RED node and its result now: `test_at_b99_09_a2l_window_physical_column` (RED at base after G6's assertion, per G6-REPORT §4) → now **1 passed**. OK.
Any node that passed at base and fails now: none (all nodes in the set are GREEN now). OK.

## Step 3 — Negative controls are real (3 controls, one per unit; RED lines pasted)
All three controls applied in fresh copies of the pristine `~/work/zq-fb/chk-G6c`, running only the affected node:

1. G6b control → G6c `092_2`: `TIGHT_BELOW_HEIGHT = 15` → `12` in `s19_app/tui/a2l_label_list.py:71`.
   RED: `E   AssertionError: assert 0 >= 1` (test_r_a2l_list_092_2) → `1 failed`. OK.
2. G6 control → `test_at_b99_09`: removed all three `-tight` rules from `styles.tcss` (544–555).
   RED: `E   AssertionError: no tag row paints at (80, 24): table region Region(x=7, y=13, width=38, height=1)` → `1 failed`. OK.
3. G6c control → `092_1`: removed `#a2l_panes.-tight #a2l_tags_title { display: none; }` (styles.tcss 548–550).
   RED: `E   AssertionError: assert 0 >= 1` (test_r_a2l_list_092_1) → `1 failed`. OK.

No control stayed GREEN. OK.

## Step 4 — Laws (serial, -n 0)
`tests/test_suite_hygiene.py tests/test_requirements_canon.py tests/test_id_registry.py tests/test_address_census.py tests/test_import_census.py tests/test_no_private_tokens.py`
→ `2 failed, 113 passed, 2 skipped in 397.05s`
RED nodes:
- `tests/test_suite_hygiene.py::test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses` (allowed: test_r_tst_070_2)
- `tests/test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors` (allowed: test_at_b83_08…)

Canon two-shall row test (`test_requirements_canon.py::test_canon_rows_hold_the_obligation_word_once`) is now GREEN (was RED at base; the unit's canon rows fixed it). The 2 skipped are pre-existing checkout-conditional `pytest.skip` guards (same "2 skipped" as base laws.txt); no skip lines were added in the diff. No other RED. OK.

## Step 5 — Worker claims (5 re-verified)
1. Claim: `test_requirements_canon.py` → `11 passed`. Re-verified: `11 passed in 0.37s`. TRUE.
2. Claim: 6-node `-n 0` run → `6 passed`. Re-verified: `6 passed in 105.63s`. TRUE.
3. Claim: whole `tests/test_b103_a2l_list_view.py` `-n 4` → `119 passed`. Re-verified: `119 passed in 385.97s` (count matches; wall-clock differs trivially). TRUE.
4. Claim: `git diff | grep -c $'\r'` = 0. Re-verified: CR count 0. TRUE.
5. Claim: negative control #1 RED line `E AssertionError: assert 0 >= 1` for 092_2 under `TIGHT_BELOW_HEIGHT = 12`. Re-verified: exact match. TRUE.

## Step 6 — Diff saved
`CHECK.diff` written as a copy of step 1's diff (5 files, 81 insertions, CR 0).
CHECK_DONE G6c MECH-GO
