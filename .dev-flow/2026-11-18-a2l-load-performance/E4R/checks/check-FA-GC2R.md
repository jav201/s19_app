# CHECK FA-GC2R — mechanical check (DeepSeek v4-pro)

- Unit: FA-GC2R
- Tree: `~/work/zq-fa/FA-GC2R/repo` (branch `work`, HEAD `02049233257ab2b75b6ac1085edc9005b3e11e8e` = 02049233)
- Base clone: `~/work/zq-fa/base-alp` (25161a00)
- Base transcript: `~/work/zq-fa/briefs/laws-base-alp.txt` (six laws at 25161a00)
- Start: 2026-11-19 20:58:50 CST
- Host: <host> (shared rtx lab host, not the timing reference)

---
## Step 1 — Diff hygiene

Command:
```
cp -a ~/work/zq-fa/FA-GC2R/repo ~/work/zq-fa/chk-FA-GC2R
cd ~/work/zq-fa/chk-FA-GC2R && git diff > ../chk-FA-GC2R.diff
```

- Files changed (all within the brief's "Files you may edit"):
  - `s19_app/tui/app/file_load.py`
  - `s19_app/tui/app/loaded_state.py`
  - `s19_app/tui/app/project_load.py`
  - `tests/test_alp_inc2_a2l_attach.py`
  - `tests/test_alp_inc3_snapshot_parity.py`
- CR count: `tr -cd '\r' < ../chk-FA-GC2R.diff | wc -c` → `0` ✓
- Added `skip`/`skipif`/`xfail`/`sleep(` lines: `git diff | grep -E '^\+.*\b(skip|skipif|xfail|sleep)\s*\('` → none ✓
- `def test_` removed and not re-added:
  - Removed: `test_r_a2l_refresh_052_case06_no_mainthread_gc_pause` (ordered retirement, brief row 4) — name ABSENT from `tests/` ✓
  - No other test names removed or re-added ✓
- Diff stat: 5 files changed, 83 insertions(+), 98 deletions(-)

STEP 1: PASS

---
## Step 2 — GREEN vs base

HT-03 (env with `.` on sys.path, mirroring pyproject `pythonpath=["."]`): `s19_app.__file__ = ~/work/zq-fa/chk-FA-GC2R/s19_app/__init__.py` (inside the tree) ✓.
(Note: without `.` on the path, `import s19_app` under `-I` resolves to a stale editable `s19tool` install at `~/work/s19_app/s19_app`; pytest does NOT hit that path because `pythonpath=["."]` prepends the tree root.)

Node set results (brief's node set, same `-n`):

| command | result |
|---|---|
| `-n 0` serial set (r038 install exception, r043_*, .051 arms, .052 spy arms, .053) | `14 passed in 318.81s` ✓ |
| `-n 4 -m "not serial_timing and not slow" tests/test_alp_inc2_a2l_attach.py` | `32 passed in 265.47s` ✓ |
| `-n 4 -m "not serial_timing and not slow" tests/test_alp_inc3_snapshot_parity.py` | `39 passed in 173.52s` ✓ |
| `-n 4 tests/test_b100_busy.py -k "a2l_deferred_install_raise"` | `1 passed in 5.04s` ✓ |
| `-n 4 tests/test_b100_session_reset.py` | `20 passed in 40.88s` ✓ |
| `-n 0 tests/test_suite_hygiene.py -k "040 or 041 or 002"` | `9 passed, 58 deselected in 151.50s` ✓ |

Base-RED nodes (from base transcript, the six law failures) are not part of this unit node set; they are re-run in Step 4. No unit node that passed at base fails now. No failures of any kind.

STEP 2: PASS

---
## Step 3 — Negative controls are real

Second copy `~/work/zq-fa/chk-FA-GC2R-nc` (fresh `cp -a` from the clean check copy per control). Three mutations re-applied, each run on its affected node only:

1. **Row 1** — removed `gc.enable()` in `file_load.py` `_install_attached_a2l` `except BaseException:` → `test_r038_install_exception_reenables_gc` RED:
   ```
   E   AssertionError: R-A2L-REFRESH.051: the cycle collector stayed disabled after the install exception: [False]
   tests/test_alp_inc2_a2l_attach.py:2490: AssertionError
   ```
2. **Row 3(i)** — double `gc.collect()` at the attach site (`file_load.py`) → `.052` attach arm RED (`2 > 1`):
   ```
   E   AssertionError: R-A2L-REFRESH.052: the attach install ran more than one full gc.collect() from a product module: [('s19_app.tui.app.file_load', <…>), ('s19_app.tui.app.file_load', <…>)]
   tests/test_alp_inc2_a2l_attach.py:2672: AssertionError
   ```
3. **Row 2/3(ii)** — deleted the attach site's `self.logger.info(...)` (`file_load.py`) → `.052` attach arm RED (`1 != 0`):
   ```
   E   AssertionError: R-A2L-REFRESH.052/.054: the attach install's full collections are not one-to-one with the logged GC lines: collects=[('s19_app.tui.app.file_load', <…>)] logs=[]
   tests/test_alp_inc2_a2l_attach.py:2676: AssertionError
   ```

All three controls stay RED under their mutation. No control stayed GREEN.

STEP 3: PASS

---
## Step 4 — Laws

Command (serial `-n 0`, `-rfE --tb=line`, full six law files) → summary:

```
4 failed, 111 passed, 2 skipped in 427.30s
FAILED tests/test_suite_hygiene.py::test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses
FAILED tests/test_requirements_canon.py::test_canon_rows_hold_the_obligation_word_once
FAILED tests/test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors
FAILED tests/test_no_private_tokens.py::test_no_tracked_file_holds_a_private_token
```

Against the allowed-RED list:
- `test_r_tst_002_every_timing_arm_carries_serial_timing` — base RED → **now GREEN** (was RED at base only from timing-arm census; fixed by earlier committed units + this unit's row-4 retirement) ✓
- `test_r_tst_040_041_every_upper_timing_bound_is_reported` — base RED → **now GREEN** (base offender `tests/test_alp_inc2_a2l_attach.py:609` was inside the retired case_06 pause test) ✓
- `test_r_tst_070_2_...` — still RED, allowed. Offenders all in inherited `evidence/full-suite/...`; none reference the unit's 5 files (grep confirmed) ✓
- `test_canon_rows_hold_the_obligation_word_once` — still RED, allowed. Offenders exactly the base set: `R-A2L-DEF.153`, `R-PICKER-CORRECT.004`, `R-PICKER-CORRECT.008` (3 offending, 3356 checked). No new offender (no R-A2L-REFRESH.052/.054 or R-A2L-DEF.162–168 among them) ✓
- `test_at_b83_08_tree_holds_no_assembled_selectors` — still RED, allowed. Current offenders: `tests/test_b103_a2l_refresh.py` and `tests/test_b103_picker_model.py` (IfExp/Subscript). None are in this unit's files. (Base additionally listed `tests/test_alp_inc2_a2l_attach.py:408`; that offender was removed by earlier committed units at 02049233, not by this unit's uncommitted diff — the worker's diff only touches lines 2609+.) No new offender from this unit ✓
- `test_no_tracked_file_holds_a_private_token` — still RED, allowed. Offender list identical to base (all `.dev-flow/2026-11-18-a2l-load-performance/inc-1/evidence-e4/...` inherited evidence). None in the unit's files ✓

Known hole check: no blank line follows R-A2L-REFRESH.028 (line 1470) or R-A2L-DEF.155 (line 1375) in this tree; rows .052/.054 (lines 1494/1496) and .162–.168 (lines 1382–1388) are contiguous and each holds `shall` exactly once, so the canon law sees them (3356 checked) and they are not offenders. ✓

STEP 4: PASS

---
## Step 5 — Worker claims

(`pi.log` holds only `PI_EXIT=124` — the worker's 2700 s timeout, consistent with the report-only RBRIEF. Claims below come from REPORT.md.)

1. **HEAD sha `02049233257ab2b75b6ac1085edc9005b3e11e8e`** — re-verified: `git rev-parse HEAD` → `02049233257ab2b75b6ac1085edc9005b3e11e8e`. **TRUE**
2. **Row 4 retirement: `--collect-only -q -m slow tests/test_alp_inc2_a2l_attach.py` lists only 3 slow nodes and no pause arm** — re-verified: `test_r033_key_latency[case06-full-processing]`, `test_r034_progress_throughout[case06-full-processing]`, `test_at_alp_i2_2_case06_keys_and_progress` → `3/45 tests collected (42 deselected)`. Pause arm absent. **TRUE**
3. **Row 2: three install sites log a timed GC with route attach/image/project** — re-verified: `file_load.py:1224` route `"attach"`, `loaded_state.py:893` route `"image"`, `project_load.py:1825` route `"project"`, all using the same `"A2L load GC: route=%s unreachable=%d seconds=%.3f"` format. **TRUE**
4. **Row 3: re-pinned assertions** — re-verified in both files: `assert len(product_collects) <= 1` (inc2:2672, inc3:908), `assert len(product_collects) == len(gc_log_lines)` (inc2:2676, inc3:912), `assert gc_log_lines and all(args and args[0] == "attach"/arm …)` (inc2:2681, inc3:917). Test names and parametrize ids unchanged. **TRUE**
5. **Row 5: `.053` unchanged and GREEN** — re-verified: `tests/test_alp_inc2_a2l_attach.py::test_r_a2l_refresh_053_reloads_do_not_accumulate_objects` → `1 passed in 50.30s` (REPORT.md said 48.86 s; shared-host variance, not a FAIL). **TRUE**

Full-file run counts from REPORT.md re-confirmed in Step 2: inc2 `32 passed`, parity `39 passed`, busy `1 passed`, session_reset `20 passed`, census `9 passed, 58 deselected` — all match.

STEP 5: PASS

---
## Step 6 — Save the diff

`~/work/zq-fa/FA-GC2R/CHECK.diff` written (copy of step 1's diff): 295 lines, CR count `0`.

## Verdict

Steps 1–5 all PASS. Diff hygiene clean (only the 5 allowed files, 0 CR, no skip/skipif/xfail/sleep, only the ordered retirement removed); unit node set fully GREEN; three negative controls each RED under their mutation; laws show only the four allowed base REDs with no new offender from this unit; five worker claims re-verified TRUE.

CHECK_DONE FA-GC2R MECH-GO

## Orchestrator intent review (Opus, relevo-23)
GO. Operator D-GC = A as designed (GC-REDESIGN §4 option (d); R5-F3, R5-F5). The worker timed out with a complete 5-file diff; it was frozen and a report-only session (MD-06) wrote the evidence without editing the tree (diff md5 unchanged).
- Product: each of the three install sites keeps its one `gc.collect()` after `_refresh_a2l_dependent_views()` (call not moved), times it and logs `A2L load GC: route=<attach|image|project> unreachable=<n> seconds=<s>` on the `s19tui` logger (R-A2L-REFRESH.054). No `gc.freeze()` anywhere; the workers' `gc.disable()` is unchanged. Row 1 (attach `except` re-enable) was already in the tree from FA-GC2 row 4; its control is RED again here.
- Tests: the three `.052` arms keep their names and ids and assert at most one product collection, collections one-to-one with log lines, and the arm's route on every line. The `gc_log_lines and …` clause also requires one line to exist, so the route check cannot pass vacuously on an empty list; under the conftest GC hygiene every install runs its collection, so this pins today's design (one collection), which the requirement allows. Controls: double collect → `2 > 1`; per-site log deleted → `1 != 0` on that route.
- Row 4: `test_r_a2l_refresh_052_case06_no_mainthread_gc_pause` deleted; TR-01: its requirement text was superseded by operator D-GC = A (FA-REQ3, 459e03f3). Its timing-census key `R-A2L-REFRESH.052-case06-gc` lived only in the test, so no registry row is left behind.
- Row 5: `.053` GREEN unchanged; the stop rule did not fire.
- Orchestrator change at integration (comment-only, recorded here): the worker's two-line D-13 comments ran to about 140 columns (file maxima 122–137) and dropped `loaded_state.py`'s note that project bundle stages pass `publish_a2l=False` and P5 re-enables after its own final refresh (the brief's two-line instruction caused it). The integrated diff rewraps the three comments at about 78 columns and restores that note; code lines are byte-identical to the checked tree (`diffs/FA-GC2R.frozen.diff` is the worker's original).
