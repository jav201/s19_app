# CHECK REC2

- unit: REC2
- tree: ~/work/zq-fb/REC2/repo
- HEAD sha: c46ac1950ee34275b88019e91b8bbd7bffc2f7e0
- start: 2026-11-19T19:36:50Z

## Step 1 — Diff hygiene

Command:
```
cp -a ~/work/zq-fb/REC2/repo ~/work/zq-fb/chk-REC2
cd ~/work/zq-fb/chk-REC2 && git diff > ~/work/zq-fb/chk-REC2.diff
```

Files changed (all within the brief's "Files you may edit" + REC's two kept record files):
1. .dev-flow/2026-11-05-batch-103/evidence/full-suite/RESULT.md  (REC row 2, kept)
2. .dev-flow/2026-11-05-batch-103/fix-round/RECORD.md           (REC row 2, kept)
3. .dev-flow/2026-11-05-batch-103/fix-round/briefs/FB-common.md (record redaction fix)
4. .dev-flow/2026-11-05-batch-103/fix-round/checks/check-G3a.md (record redaction fix)
5. tests/test_suite_hygiene.py                                  (REC row 1 design: 3 additions + 1 new test)

Checks:
- CR count: `tr -cd '\r' < ~/work/zq-fb/chk-REC2.diff | wc -c` = 0
- added skip/skipif/xfail/sleep( lines: 0 (the only grep hit is the prose line in check-G3a.md — the redaction fix itself, not test code)
- `def test_` removed and not re-added: none
- `def test_` added: 1 (`test_r_tst_070_2_reviewed_exemptions_stay_narrow`) — a new negative-control test, not a re-add

RESULT: PASS
## Step 2 — GREEN vs base

Brief node set (`-n 0`, same as the unit):
- `tests/test_suite_hygiene.py -k "070"`
- `tests/test_suite_hygiene.py` (whole)

Commands (CHK env, 1200s timeout):
```
S=$HOME/work/zq-fb/chk-REC2-state; mkdir -p $S~ $S/tmp $S/x; timeout 1200 env -i PATH=/usr/bin:/bin HOME=$S~ XDG_CONFIG_HOME=$S/x/config XDG_CACHE_HOME=$S/x/cache XDG_DATA_HOME=$S/x/data TMPDIR=$S/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 ~/miniconda3/envs/s19ci/bin/python -I -B -m pytest -p no:cacheprovider -q tests/test_suite_hygiene.py -k "070" < /dev/null
```
→ `3 passed, 65 deselected in 20.58s`

```
... -m pytest -p no:cacheprovider -q tests/test_suite_hygiene.py < /dev/null
```
→ `66 passed, 2 skipped in 339.89s` (EXIT=0; completes under the 1200s CHK timeout, so not a TIMEOUT)

Base-RED nodes (from ~/work/zq-fb/baseline/laws.txt, base 3afebf90) in this unit's file:
- `test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses`: base FAILED → now PASSED (GREEN)
- (the other two base-RED laws — canon two-shall and address-census at_b83_08 — are outside REC2's node set; re-checked in Step 4)

Node passed at base and failing now: none (whole file: 66 passed, 2 skipped, 0 failed; base hygiene had only 070_2 RED, the rest passed).

RESULT: PASS
## Step 3 — Negative controls are real

Second copy: `~/work/zq-fb/chk-REC2-nc` (fresh `cp -a` of the checked copy for each control). Affected node: `tests/test_suite_hygiene.py::test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses`.

Control A (worker row 2 — delete the three test additions):
```
cp -a ~/work/zq-fb/chk-REC2 ~/work/zq-fb/chk-REC2-nc
cd ~/work/zq-fb/chk-REC2-nc && git show HEAD:tests/test_suite_hygiene.py > tests/test_suite_hygiene.py   # test file back to HEAD c46ac195, record fixes kept
... pytest -q tests/test_suite_hygiene.py::test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses
```
RED assertion line (first hit):
```
E         evidence/full-suite/b103-g3-recents/RESULT: posix home path outside the runner image: ~
```

Control B (worker row 1 — restore the runner-home basename in FB-common.md):
```
cp -a ~/work/zq-fb/chk-REC2 ~/work/zq-fb/chk-REC2-nc
cd ~/work/zq-fb/chk-REC2-nc && sed -i 's|<runner-home>|<runner-home-basename-restored>|g' .dev-flow/2026-11-05-batch-103/fix-round/briefs/FB-common.md   # test additions kept
... pytest -q tests/test_suite_hygiene.py::test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses
```
RED assertion line (first hit):
```
E         fix-round/briefs/FB-common.md: posix home path outside the runner image: ~<runner-home>
```
(note: the actual restored basename and `~<basename>` are spelled as `<runner-home>` per the privacy rule; the mutation really restored it and the law really named it.)

Both controls go RED on the affected node. RESULT: PASS
## Step 4 — Laws

Command (serial `-n 0`, CHK env, 1200s timeout):
```
S=$HOME/work/zq-fb/chk-REC2-state; mkdir -p $S~ $S/tmp $S/x; timeout 1200 env -i PATH=/usr/bin:/bin HOME=$S~ XDG_CONFIG_HOME=$S/x/config XDG_CACHE_HOME=$S/x/cache XDG_DATA_HOME=$S/x/data TMPDIR=$S/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 ~/miniconda3/envs/s19ci/bin/python -I -B -m pytest -p no:cacheprovider -q -n 0 tests/test_suite_hygiene.py tests/test_requirements_canon.py tests/test_id_registry.py tests/test_address_census.py tests/test_import_census.py tests/test_no_private_tokens.py < /dev/null
```

Summary:
```
FAILED tests/test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors
1 failed, 115 passed, 2 skipped in 424.28s
```

RED nodes now:
- `tests/test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors` — RED (allowed: address census `test_at_b83_08…`)

The other two allowed-at-base REDs are now GREEN:
- `test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses` (fixed by this unit)
- `test_requirements_canon.py::test_canon_rows_hold_the_obligation_word_once` (canon two-shall; GREEN after the fix round)

Any other RED: none. RESULT: PASS
## Step 5 — Worker claims

1. "FB-common.md: runner-home basename → `<runner-home>` in both segments; nothing else changed" — TRUE. `grep -c '<runner-home>'` = 2, `grep -c '<original-basename>'` = 0; diff shows exactly the one command line changed.
2. "check-G3a.md: `no sleep~ tokens` → `no sleep, home-path or LAN tokens`" — TRUE. new prose count 1, old prose count 0; diff shows exactly that one line.
3. "three additions in tests/test_suite_hygiene.py + test_r_tst_070_2_reviewed_exemptions_stay_narrow" — TRUE. `_PLACEHOLDER` gains `redacted_[a-z_]+` (line 1918), `_PUBLIC_RUNNER` (1924), `_REVIEWED_NOT_ACCOUNTS = frozenset({"end","python"})` (1929), `_is_placeholder` fullmatch hook (1968), per-label skip (2018), new test (2105).
4. "`-k "070"` → 3 passed, 65 deselected" — TRUE. I reproduced `3 passed, 65 deselected in 20.58s` (worker: 20.44s).
5. "Negative controls both RED with the claimed first hits" — TRUE. Control A (drop the 3 additions) → RED first hit `evidence/full-suite/b103-g3-recents/RESULT: posix home path outside the runner image: ~`; Control B (restore basename) → RED first hit `fix-round/briefs/FB-common.md: posix home path outside the runner image: ~<runner-home>`.

Note on the whole-file claim: the worker recorded the whole `test_suite_hygiene.py` as TIMEOUT at 300s. Under the CHK 1200s timeout it completes: `66 passed, 2 skipped in 339.89s` (EXIT=0). So the 300s timeout is a runtime artifact, not a regression; the file is GREEN (see Step 2).

RESULT: PASS (all 5 TRUE)
## Step 6 — Save the diff

Saved step 1's diff as `~/work/zq-fb/REC2/CHECK.diff` (141 lines, identical copy of the copy's `git diff`).

CHECK_DONE REC2 MECH-GO
