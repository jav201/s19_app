# CHECK — G3cF (mechanical check)

- Unit: G3cF
- Tree: ~/work/zq-fb/G3cF/repo
- HEAD sha: f1cca49f3bc0a32ec2e9bb970fbf01dca700e0f8
- Start time: 2026-11-19 14:07:45 CST

## Step 1 — Diff hygiene

Command:
```
cp -a ~/work/zq-fb/G3cF/repo ~/work/zq-fb/chk-G3cF
cd ~/work/zq-fb/chk-G3cF && git diff > ../chk-G3cF.diff
```

- Files changed (must be within brief's "Files you may edit"):
  - tests/test_b101_reach_and_reports_escape.py
  - tests/test_b103_a2l_refresh.py
  - tests/test_b103_picker_model.py
  → all three are in the allowed list. OK.
- CR count: `tr -cd '\r' < ../chk-G3cF.diff | wc -c` = 0. OK.
- Added `skip`/`skipif`/`xfail`/`sleep(` lines: NONE. OK.
- `def test_` removed and not re-added: NONE (no removed, no added). OK.

Step 1 = PASS.

## Step 2 — GREEN vs base

Base RED transcript ~/work/zq-fb/baseline/G3c.txt: 2 failed, 169 passed (171 collected).
Base-RED nodes:
- tests/test_b101_reach_and_reports_escape.py::test_r_shell_keys_3_1_every_action_has_a_reach — base RED
- tests/test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors — base RED

Commands (env per CHK-BRIEF, from the copy's root ~/work/zq-fb/chk-G3cF):
```
S=$HOME/work/zq-fb/chk-G3cF-state; mkdir -p $S~ $S/tmp $S/x; timeout 1200 env -i PATH=/usr/bin:/bin HOME=$S~ XDG_CONFIG_HOME=$S/x/config XDG_CACHE_HOME=$S/x/cache XDG_DATA_HOME=$S/x/data TMPDIR=$S/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 ~/miniconda3/envs/s19ci/bin/python -I -B -m pytest -p no:cacheprovider -q -n 0 tests/test_b101_reach_and_reports_escape.py::test_r_shell_keys_3_1_every_action_has_a_reach < /dev/null
```
Result: `1 passed in 6.12s` → base-RED row-1 node now GREEN.

```
... -q -n 0 tests/test_address_census.py < /dev/null
```
Result: `23 passed in 50.24s` → base-RED test_at_b83_08 now GREEN (whole file green).

```
... -q -n 4 tests/test_b103_a2l_refresh.py tests/test_b103_picker_model.py < /dev/null
```
Result: `147 passed in 677.06s`.

Summary: every base-RED node now GREEN; no node that passed at base now fails (two files = 147 passed, same count as base).

Step 2 = PASS.

## Step 3 — Negative controls are real

Control 1 (row-1 rename, per worker REPORT.md): in copy ~/work/zq-fb/chk-G3cF-nc, gave the renamed mutant a real reach by adding to `_DEAD_ACTIONS`:
```
class _Reacher(App):
    BINDINGS = [Binding("z", "unbound_card_probe", "Z")]
```
Command (row-1 node, -n 0): `... -q -n 0 tests/test_b101_reach_and_reports_escape.py::test_r_shell_keys_3_1_every_action_has_a_reach < /dev/null`
Result RED:
```
E       AssertionError: assert ['_DeadAlone....nd_nxt_probe'] == ['PlainCard.a...nd_nxt_probe']
E         At index 0 diff: '_DeadAlone.action_dead_mac_alias' != 'PlainCard.action_unbound_card_probe'
tests/test_b101_reach_and_reports_escape.py:571: AssertionError
1 failed in 4.08s
```
Control is real (goes RED, not GREEN). OK.

Control 2 (census rewrite, per brief negative control #2): in copy ~/work/zq-fb/chk-G3cF-nc2, reverted the two b103 files to HEAD (`git show HEAD:<file>` into the copy), ran only the affected node:
`... -q -n 0 tests/test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors < /dev/null`
Result RED:
```
E       AssertionError: address arguments outside {literal, name, fstring} appeared: tests/test_b103_a2l_refresh.py:218 other:IfExp, tests/test_b103_a2l_refresh.py:282 other:IfExp, tests/test_b103_picker_model.py:94 other:IfExp, tests/test_b103_picker_model.py:186 other:Subscript, tests/test_b103_picker_model.py:197 other:Subscript, tests/test_b103_picker_model.py:191 other:Subscript, tests/test_b103_picker_model.py:671 other:IfExp, tests/test_b103_picker_model.py:738 other:IfExp
tests/test_address_census.py:309: AssertionError
1 failed in 15.23s
```
(line numbers 671/738 vs base 664/731 are a later-commit line shift; same sites.) Control is real. OK.

Step 3 = PASS.

## Step 4 — Laws

Command (serial -n 0):
```
... -q -n 0 tests/test_suite_hygiene.py tests/test_requirements_canon.py tests/test_id_registry.py tests/test_address_census.py tests/test_import_census.py tests/test_no_private_tokens.py < /dev/null
```
Result: `116 passed, 2 skipped in 428.35s (0:07:08)` — 0 failed.

Allowed RED at base (canon two-shall row, address census test_at_b83_08, test_r_tst_070_2) are all GREEN on this tree (070_2 fixed by fix-round commit 511379df; canon + census green). No other RED.

Step 4 = PASS.

## Step 5 — Worker claims

1. "os_clipboard_input.py OsClipboardInput._on_mouse_down (def line 993) refs action_copy; source at :1011 `await self.action_copy()`" — TRUE. Verified: `grep -n` shows `993: async def _on_mouse_down(...)` and `1011: await self.action_copy()`.

2. "git log -S'await self.action_copy()' -- os_clipboard_input.py → 3dc52a95 2026-11-07 batch-103 Inc 1a E4: clipboard core" — TRUE. Verified: same output.

3. "git grep -c unbound_card_probe -- s19_app = 0 hits" — TRUE. Verified: `git grep -n "unbound_card_probe" -- s19_app` → 0 hits (no product code uses the new mutant name).

4. "row-1 node (-n 0): 1 passed (~6.2s)" — TRUE. Re-run: `1 passed in 6.12s`.

5. "Negative control (add a reach to the mutant) → row-1 node RED at test_b101_reach_and_reports_escape.py:571" — TRUE. Re-applied in chk-G3cF-nc; RED at `:571 AssertionError`, `At index 0 diff: '_DeadAlone.action_dead_mac_alias' != 'PlainCard.action_unbound_card_probe'`.

Bonus (out-of-scope observation in REPORT): "whole test_b101 file (-n 4): 1 failed (test_at_i12_2…), not caused by this unit" — NOT reproducible on this tree: re-ran the single node alone (`1 passed in 15.42s`) and the whole file (`18 passed in 44.29s`). No failure present now; direction is favorable and the file is outside the brief's node set.

Step 5 = PASS (5 core claims all TRUE).

## Step 6 — Save the diff

Copied step 1's diff to ~/work/zq-fb/G3cF/CHECK.diff (114 lines).

## Verdict

Steps 1–5 all PASS.

CHECK_DONE G3cF MECH-GO
