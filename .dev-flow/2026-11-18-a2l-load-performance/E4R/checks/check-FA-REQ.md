# CHECK — mechanical check of unit FA-REQ

- unit: FA-REQ
- tree: ~/work/zq-fa/FA-REQ/repo
- HEAD sha: 25161a00eb1b38df08ffd238c2a5769954c2de6b
- start time: Thu Nov 19 03:40:50 PM CST 2026

## Step 1 — Diff hygiene

Command: `cp -a ~/work/zq-fa/FA-REQ/repo ~/work/zq-fa/chk-FA-REQ`; in the copy `git diff HEAD > ../chk-FA-REQ.diff`
(Note: the brief's literal `git diff` captures only the unstaged REQUIREMENTS.md; `git diff HEAD` additionally captures the 3 staged new E4R files, so the hygiene checks below cover all 4 changed files.)

Files changed (from `grep '^diff --git'`):
- `.dev-flow/2026-11-18-a2l-load-performance/E4R/01-requirements.md` (new) — allowed
- `.dev-flow/2026-11-18-a2l-load-performance/E4R/02-test-cases.md` (new) — allowed
- `.dev-flow/2026-11-18-a2l-load-performance/E4R/E4R-rulings.md` (new) — allowed
- `REQUIREMENTS.md` — allowed

All changed files are within the brief's "Files you may edit". No `tests/` file touched (grep count = 0).

- CR count: `tr -cd '\r' < diff | wc -c` = 0 (PASS)
- added `skip`/`skipif`/`xfail`/`sleep(` lines = 0 (PASS)
- `def test_` names removed and not re-added = none (no `-def test_` lines, no `+def test_` lines) (PASS)


## Step 2 — GREEN vs base

Node set (from unit brief; `-n 0`): `tests/test_requirements_canon.py tests/test_id_registry.py`.

Command (run from copy root ~/work/zq-fa/chk-FA-REQ):
`S=$HOME/work/zq-fa/chk-FA-REQ-state; mkdir -p $S/home/<runner-home> $S/tmp $S/x; timeout 1200 env -i PATH=/usr/bin:/bin HOME=$S/home/<runner-home> XDG_CONFIG_HOME=$S/x/config XDG_CACHE_HOME=$S/x/cache XDG_DATA_HOME=$S/x/data TMPDIR=$S/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 /data/miniconda3/envs/s19ci/bin/python -I -B -m pytest -p no:cacheprovider -q -n 0 tests/test_requirements_canon.py tests/test_id_registry.py < /dev/null`

Summary: `1 failed, 22 passed in 8.39s`.

Base-RED nodes in this set and result now:
- `test_requirements_canon.py::test_canon_rows_hold_the_obligation_word_once` → still RED with the SAME 3 base offenders only (R-A2L-DEF.153 @1373, R-PICKER-CORRECT.004 @4249, R-PICKER-CORRECT.008 @4253; line shift +8 vs base 4241/4245 matches the 8 inserted rows). No new offender. (allowed RED)

Nodes that passed at base and fail now: none (`test_id_registry.py` passes; total 22 passed).

Also confirmed `../scratch/canon_eq.py` (run against the original tree, byte-identical to the copy) prints `diffs=0`.

## Step 3 — Negative controls are real

Second copy: `cp -a ~/work/zq-fa/chk-FA-REQ ~/work/zq-fa/chk-FA-REQ-nc`.

Control A (row 4 — canon sentence drift): added a second `shall` to the canon `.049` sentence in `REQUIREMENTS.md`:
`...the system shall acknowledge each operator key shall within 1.0 second...`
Run the affected proof node (canon_eq.py, adjusted to point at the nc copy) → RED:
```
DIFF R-A2L-REFRESH.049
  canon: 'While a direct A2L attach captures its request snapshot on the UI thread, the system shall acknowledge each operator key shall within 1.0 second of its delivery to the application.'
  e4r  : 'While a direct A2L attach captures its request snapshot on the UI thread, the system shall acknowledge each operator key within 1.0 second of its delivery to the application.'
diffs=1
exit=1
```

Control B (row 5 — reference-host wording): reverted `.162` `on the reference host` → `on the E1 reference host`. Run the affected check → RED:
`grep -c 'E1 reference host' REQUIREMENTS.md` = `1` (the fixed tree holds 0).

Both controls go RED → real.

Known-hole confirmation (matches CHK-BRIEF note): on the nc copy (both mutations applied), the law node `tests/test_requirements_canon.py::test_canon_rows_hold_the_obligation_word_once` still reports ONLY the 3 base offenders and does NOT name `.049` or `.162` — the blank lines after R-A2L-REFRESH.028 and R-A2L-DEF.155 hide rows below them from the canon parser. This is pre-existing (present at base HEAD), not introduced by the unit; per the CHK-BRIEF, those rows are checked with the unit's own proof script (canon_eq.py), which does go RED.


## Step 4 — Laws (serial, -n 0)

Command (run from copy root ~/work/zq-fa/chk-FA-REQ):
`S=$HOME/work/zq-fa/chk-FA-REQ-state; mkdir -p $S/home/<runner-home> $S/tmp $S/x; timeout 1200 env -i PATH=/usr/bin:/bin HOME=$S/home/<runner-home> XDG_CONFIG_HOME=$S/x/config XDG_CACHE_HOME=$S/x/cache XDG_DATA_HOME=$S/x/data TMPDIR=$S/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 /data/miniconda3/envs/s19ci/bin/python -I -B -m pytest -p no:cacheprovider -q -n 0 tests/test_suite_hygiene.py tests/test_requirements_canon.py tests/test_id_registry.py tests/test_address_census.py tests/test_import_census.py tests/test_no_private_tokens.py < /dev/null`

Summary: `6 failed, 109 passed, 2 skipped in 438.64s` — identical to base (base: 6 failed, 109 passed, 2 skipped).

The 6 failures are exactly the base-RED allowed set:
- tests/test_suite_hygiene.py::test_r_tst_002_every_timing_arm_carries_serial_timing
- tests/test_suite_hygiene.py::test_r_tst_040_041_every_upper_timing_bound_is_reported
- tests/test_suite_hygiene.py::test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses
- tests/test_requirements_canon.py::test_canon_rows_hold_the_obligation_word_once (offenders: R-A2L-DEF.153 @1373, R-PICKER-CORRECT.004 @4249, R-PICKER-CORRECT.008 @4253 — same 3 base offenders, no new offender)
- tests/test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors
- tests/test_no_private_tokens.py::test_no_tracked_file_holds_a_private_token (same offender list as base)

No other RED, no new offender inside an allowed RED. PASS.

## Step 5 — Worker claims re-verified

1. **"canon_eq.py → diffs=0"** (row-4 proof). Re-ran `~/work/zq-fa/FA-REQ/scratch/canon_eq.py` against the tree (copy byte-identical to it): prints `diffs=0`, exit 0. TRUE.

2. **"Laws (test_requirements_canon + test_id_registry) → 1 failed, 22 passed, single failure = R-DOC-CANON.4 with exactly the 3 base offenders"**. Re-ran on the copy: `1 failed, 22 passed in 8.39s`; the one failure lists R-A2L-DEF.153 / R-PICKER-CORRECT.004 / R-PICKER-CORRECT.008 only. TRUE.

3. **"Row 5: `git grep -c 'E1 reference host' REQUIREMENTS.md` = 0"**. Re-ran `grep -c 'E1 reference host' REQUIREMENTS.md` on the copy = 0. TRUE.

4. **"Blank-line hole: parse_canon REFRESH ids stop at .028 and DEF ids stop at .155; .049/.162/.166 invisible"**. Re-ran `tests.test_requirements_canon._rows()` on the copy: R-A2L-REFRESH.029/.049/.053 present=False (REFRESH last=.028), R-A2L-DEF.156/.162/.166/.168 present=False (DEF last=.155); total rows 3317 (matches the law's "3317 checked"). TRUE.

5. **"HT-03: with `-I`, `s19_app.__file__` resolves to a stale editable install, not `./s19_app`"**. Re-ran with the exact env block: with `-I` → `<runner-home>/work/s19_app/s19_app/__init__.py`; without `-I` → `<copy>/s19_app/__init__.py`. TRUE.

Additional observations (not defects):
- Row 1 proof "14 requirement sentences each hold `shall` exactly once": re-verified on the E4R table — all 14 rows print `shall=1`. TRUE.
- The report's `git diff --stat` shows "1 file changed, 18 insertions(+), 10 deletions(-)". Re-running `git diff --stat` on the tree actually reports 4 files (REQUIREMENTS.md 28 = 18 ins/10 del, plus the 3 E4R files as intent-to-add via `git add -N`); the REQUIREMENTS.md numbers are exact. The E4R files are currently in "intent to add" index state (empty blob), not strictly "untracked" as the report's parenthetical says. Reporting nuance only; the changed-file set is correct and fully within the allowed list.
- Amended/added rows: diff confirms 6 amended (.033/.034/.037/.040/.041/.042) + 8 added (.049-.053, .166-.168) + 4 wording-only (.162-.165) — matches the report.

## Step 6 — Save the diff

`cp ~/work/zq-fa/chk-FA-REQ.diff ~/work/zq-fa/FA-REQ/CHECK.diff` (copy of step 1's diff).

CHECK_DONE FA-REQ MECH-GO

## Orchestrator intent review (relevo-20)
GO with two follow-ups. The transcription matches the brief (`canon_eq.py` diffs=0; Q1 = A applied: .040–.042 and .050 in the Requirements table, .050 with the A sentence and the "until installation is dispatched" window). Orchestrator edit at integration: the slice row for `s19_app/tui/app/shared.py` still held the brief's placeholder; it now names R-A2L-REFRESH.039 (the `PreparedLoad.a2l_preparation` handoff, inc-3 `E1-slice.md` S1). Follow-ups: (1) blank lines in `REQUIREMENTS.md` after R-A2L-REFRESH.028 and R-A2L-DEF.155 (present at 25161a00) end the canon parser's table early, so the canon laws never see R-A2L-REFRESH.029–.053 or R-A2L-DEF.156–.168 — fixed forward in the next commit (FA-REQb); (2) on the lab host, `import s19_app` under `python -I` outside pytest resolves to a stale editable install; pytest is unaffected (`pyproject.toml` `pythonpath = ["."]` puts the tree first), so any non-pytest probe must put `.` first on `sys.path` (HT-03).
