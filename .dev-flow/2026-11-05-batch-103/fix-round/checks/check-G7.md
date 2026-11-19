# CHECK G7d

Unit: G7d
Tree: ~/work/zq-fb/G7d/repo
HEAD sha: b5ca5b7277e3a0aa9683e50fdd71ebb578ee7d80
Start time: Thu Nov 19 01:45:54 PM CST 2026

## Step 1 — Diff hygiene

Command:
```
cp -a ~/work/zq-fb/G7d/repo ~/work/zq-fb/chk-G7d
cd ~/work/zq-fb/chk-G7d && git diff > ~/work/zq-fb/chk-G7d.diff
```

Diff stat (base 3afebf90 → working tree):
```
 s19_app/tui/window_help.py   | 13 ++++++++-----
 tests/test_b97_chips_help.py | 36 ++++++++++++++++++++++++++++++++++--
 2 files changed, 42 insertions(+), 7 deletions(-)
```

Files changed relative to base: `s19_app/tui/window_help.py`, `tests/test_b97_chips_help.py`.
- The brief's "Files you may edit" is `tests/test_b97_chips_help.py` only. The `window_help.py` delta is G7b's pre-existing change (inherited; the brief says "Keep both changes"). G7d's own edits are confined to `tests/test_b97_chips_help.py`, confirmed by diffing G7c's tree vs G7d's tree (only `tests/test_b97_chips_help.py` differs; `window_help.py` identical to G7c's).

CR count: `git diff | tr -cd '\r' | wc -c` → 0.

Added `skip`/`skipif`/`xfail`/`sleep(` lines: none. (`grep -E '^\+' | grep -E 'skip|skipif|xfail|sleep\('` matched only a comment line containing the word "skips" — not a pytest marker.)

`def test_` names removed and not re-added: none (`grep -E '^-.*def test_'` → empty; `grep -E '^\+.*def test_'` → empty).

## Step 2 — GREEN vs base

Base RED (from ~/work/zq-fb/baseline/G7.txt): `test_tc_b97_32_patch_help_names_every_label` (RED `['', 'Format']`), `test_at_b97_14_help_chip_opens_a_body_covering_the_screen[patch]` (RED `['Format']`).

Command (brief's node set, `-n 0`, from copy root):
```
S=$HOME/work/zq-fb/chk-G7d-state; mkdir -p $S~ $S/tmp $S/x; timeout 1200 env -i PATH=/usr/bin:/bin HOME=$S~ XDG_CONFIG_HOME=$S/x/config XDG_CACHE_HOME=$S/x/cache XDG_DATA_HOME=$S/x/data TMPDIR=$S/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 ~/miniconda3/envs/s19ci/bin/python -I -B -m pytest -p no:cacheprovider -q -n 0 tests/test_b97_chips_help.py::test_tc_b97_32_patch_help_names_every_label tests/test_b97_chips_help.py::test_at_b97_14_help_chip_opens_a_body_covering_the_screen < /dev/null
```
Summary: `5 passed in 54.70s`.

Base-RED nodes now:
- `test_tc_b97_32_patch_help_names_every_label` → PASS (was RED `['', 'Format']`).
- `test_at_b97_14_help_chip_opens_a_body_covering_the_screen[patch]` → PASS (was RED `['Format']`); the other 3 screen_keys (check_editor/flow/flow_execution) also PASS.

Node passed at base and failing now: none.

Whole file (`-n 4`, brief's second node line):
```
... -m pytest -p no:cacheprovider -q -n 4 tests/test_b97_chips_help.py < /dev/null
```
Summary: `79 passed in 162.90s`.

## Step 3 — Negative controls are real

Second copy `~/work/zq-fb/chk-G7d-nc`; each mutation run on only the affected node `tests/test_b97_chips_help.py::test_tc_b97_32_patch_help_names_every_label` (`-n 0`).

NC(1) — worker REPORT.md: entries.py:297 `("Address", "patch_entry_address_input", "0x100")` → `("", "patch_entry_address_input", "")`.
```
sed -i 's/("Address", "patch_entry_address_input", "0x100")/("", "patch_entry_address_input", "")/' s19_app/tui/screens_directionb/patch_editor/entries.py
```
RED line:
```
E   AssertionError: labels with no `label — effect` line: ['']
1 failed in 11.14s
```

NC(2) — worker REPORT.md: `_ROW_LABELLED_INPUTS = frozenset({"patch_sheet_input"})` → `frozenset()`.
```
sed -i 's/_ROW_LABELLED_INPUTS = frozenset({"patch_sheet_input"})/_ROW_LABELLED_INPUTS = frozenset()/' tests/test_b97_chips_help.py
```
RED line:
```
E   AssertionError: labels with no `label — effect` line: ['']
1 failed in 10.64s
```

NC(3) — worker REPORT.md (G7c chevron control): a2l_parameter_picker.py:734 `">" if compact else "Next"` → `"»" if compact else "Next"`.
```
sed -i 's/">" if compact else "Next",/"»" if compact else "Next",/' s19_app/tui/a2l_parameter_picker.py
```
RED line:
```
E   AssertionError: labels with no `label — effect` line: ['']
1 failed in 10.53s
```

All three controls go RED with `['']`. No control stays GREEN.

## Step 4 — Laws

Command (serial `-n 0`, from copy root):
```
S=$HOME/work/zq-fb/chk-G7d-state; mkdir -p $S~ $S/tmp $S/x; timeout 1200 env -i PATH=/usr/bin:/bin HOME=$S~ XDG_CONFIG_HOME=$S/x/config XDG_CACHE_HOME=$S/x/cache XDG_DATA_HOME=$S/x/data TMPDIR=$S/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 ~/miniconda3/envs/s19ci/bin/python -I -B -m pytest -p no:cacheprovider -q -n 0 tests/test_suite_hygiene.py tests/test_requirements_canon.py tests/test_id_registry.py tests/test_address_census.py tests/test_import_census.py tests/test_no_private_tokens.py < /dev/null
```
Summary: `2 failed, 113 passed, 2 skipped in 481.07s`.

RED nodes:
- `tests/test_suite_hygiene.py::test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses` — allowed.
- `tests/test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors` — allowed.

(The canon two-shall row test `test_canon_rows_hold_the_obligation_word_once` now PASSES; REQUIREMENTS.md was already fixed upstream of this unit.) No other RED. → step 4 OK.

## Step 5 — Worker claims (5 re-verified)

1. CLAIM (REPORT.md header): HEAD `b5ca5b7277e3a0aa9683e50fdd71ebb578ee7d80`. → TRUE (`git rev-parse HEAD` in ~/work/zq-fb/G7d/repo = b5ca5b7277e3a0aa9683e50fdd71ebb578ee7d80).

2. CLAIM (REPORT.md): final run of the two base nodes (`-n 0`) is `5 passed`. → TRUE (step 2: `5 passed in 54.70s`).

3. CLAIM (REPORT.md): whole file (`-n 4`) is `79 passed`. → TRUE (step 2: `79 passed in 162.90s`; timing slightly lower than the reported 181.63s, count matches).

4. CLAIM (REPORT.md / pi.log): `git diff | grep -c $'\r'` → 0. → TRUE (step 1: CR count 0).

5. CLAIM (REPORT.md row 1 + docstring): the A2L-loaded verifier of `new =` / `field =` / `text =` is `test_r_pe_def_37_n_the_bar_shows_the_row_name_and_its_kind_label` in `tests/test_b103_inc8_s2_sheet_formula.py`. → TRUE (that def exists at line 62; its parametrize rows are `("defc","DISPLAY_0001","new =")`, `("defc","ENUM_0001","new =")`, `("defc","MASK_FIELD_0001","field =")`, `("v171",V171_ASCII,"text =")` and line 71 asserts `bar_label(sheet) == label`).

Bonus verifications: the `_ROW_LABELLED_INPUTS` comment's REQUIREMENTS.md citations are accurate (line 4946 "staging sheet" + "the formula bar on its last line" at 4950; line 5007 "row fill"; lines 5092-5093 "formula bar … `new =` / `field =` / `text =`"); the help lines exist in `s19_app/tui/window_help.py` at 75/77/79; `patch_sheet_input` is created at sheet.py:133 with no adjacent `Label`.

## Step 6 — Diff saved

Copied step 1's diff to `~/work/zq-fb/G7d/CHECK.diff` (98 lines).

## Verdict

Steps 1–5 all pass.

CHECK_DONE G7d MECH-GO
