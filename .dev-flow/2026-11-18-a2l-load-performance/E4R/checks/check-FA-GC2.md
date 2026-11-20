# CHECK — FA-GC2

- Unit: FA-GC2
- Tree path: ~/work/zq-fa/FA-GC2/repo
- HEAD sha: dd961400379cf70bbc06558218c0e3e151616107
- Start: 2026-11-19 18:27:52 CST
- Checker: DeepSeek v4-pro (mechanical check; I did not write this unit)

---

## Step 1 — Diff hygiene

Command: `cp -a ~/work/zq-fa/FA-GC2/repo ~/work/zq-fa/chk-FA-GC2`; in the copy `git diff > ../chk-FA-GC2.diff`.

- Files changed: `s19_app/tui/app/file_load.py` (1 file, +4 / -0).
  - Within the brief's "Files you may edit" (`file_load.py`, `loaded_state.py`, `project_load.py`). ✓
- CR count: `tr -cd '\r' < diff | wc -c` = 0. ✓
- Added `skip`/`skipif`/`xfail`/`sleep(` lines: 0. ✓
- `def test_` names removed and not re-added: 0. ✓
- New `def test_` added: 0. ✓

---

## Step 2 — GREEN vs base

Node set run on the copy `~/work/zq-fa/chk-FA-GC2` (check env, timeout 1200):

1. `-n 0` on r038, r043, the .051/.052/.053 arms (not the slow arm):
```
pytest -q -n 0 tests/test_alp_inc2_a2l_attach.py::test_r038_install_exception_reenables_gc \
  tests/test_alp_inc3_snapshot_parity.py::test_r043_install_exception_reenables_gc \
  tests/test_alp_inc2_a2l_attach.py::test_r_a2l_refresh_051_attach_outcomes_gc_enabled \
  tests/test_alp_inc3_snapshot_parity.py::test_r_a2l_refresh_051_project_success_gc_enabled \
  tests/test_alp_inc2_a2l_attach.py::test_r_a2l_refresh_052_install_runs_no_full_collection \
  tests/test_alp_inc3_snapshot_parity.py::test_r_a2l_refresh_052_install_runs_no_full_collection \
  tests/test_alp_inc2_a2l_attach.py::test_r_a2l_refresh_053_reloads_do_not_accumulate_objects
```
→ `3 failed, 7 passed in 258.19s`

2. `-n 4 -m "not serial_timing and not slow"` on both files:
→ `4 failed, 67 passed in 408.86s`

3. `-n 4 tests/test_b100_busy.py -k "a2l_deferred_install_raise"` → `1 passed in 5.85s`
   `-n 4 tests/test_b100_session_reset.py` → `20 passed in 50.47s`

Base-RED nodes (at FA-GC2 start, per FA-GC2T REPORT) → result now:
- `test_r038_install_exception_reenables_gc` : RED → **GREEN** (row 4 re-enable). ✓
- `test_r_a2l_refresh_052_install_runs_no_full_collection[attach]` : RED → RED (rows 1–3 reverted per stop rule; expected). ✓
- `[R-A2L-REFRESH.052/1]` (image) : RED → RED (reverted; expected). ✓
- `[R-A2L-REFRESH.052/2]` (project) : RED → RED (reverted; expected). ✓
- `test_r037_picker_snapshot_reuse[adapter-mismatch]` : RED → RED (pre-existing, unrelated to this unit; documented by FA-GC2T). ✓

Nodes that passed at base and fail now: **none**. ✓
(The 052 arms stay RED by design of the stop rule; they are not regressions — the freeze that would have fixed them was correctly reverted.)

---

## Step 3 — Negative controls are real

The worker STOPPED before running negative controls (rows 1–3 reverted; row 4 kept). The only live mutation is row 4 (re-enable GC in the `_install_attached_a2l` `except BaseException:` branch).

Control (brief's row-4 mutation, in a second copy `~/work/zq-fa/chk-FA-GC2-nc`): remove the re-enable → run only the affected node.

Command:
```
pytest -q -n 0 tests/test_alp_inc2_a2l_attach.py::test_r038_install_exception_reenables_gc
```
RED assertion line (control stays GREEN = MECH-NO-GO; here it goes RED):
```
E   AssertionError: R-A2L-REFRESH.051: the cycle collector stayed disabled after the install exception: [False]
tests/test_alp_inc2_a2l_attach.py:2463: AssertionError
1 failed in 40.12s
```
✓ Control is real.

For rows 1–3 (reverted), the brief's negative control is "restore gc.collect()" → the 052 arms go RED. That state is already the checked tree (rows 1–3 reverted), and step 2 shows the 052 attach/image/project arms RED with the `gc.collect()` from the product module — i.e. the control holds. ✓

---

## Step 4 — Laws

Command:
```
pytest -q -n 0 -rfE tests/test_suite_hygiene.py tests/test_requirements_canon.py \
  tests/test_id_registry.py tests/test_address_census.py tests/test_import_census.py \
  tests/test_no_private_tokens.py
```
→ `5 failed, 110 passed, 2 skipped in 422.17s`

Failed (all in the allowed-RED-at-base list):
- `test_suite_hygiene.py::test_r_tst_002_every_timing_arm_carries_serial_timing` — allowed.
  Offender now: `serial_timing on a test that is not a timing arm: tests/test_alp_inc2_a2l_attach.py::test_r_a2l_refresh_052_case06_no_mainthread_gc_pause` (a FA-GC2T test; not touched by FA-GC2).
- `test_suite_hygiene.py::test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses` — allowed. Offenders are inherited `.dev-flow/.../evidence/...` files; not FA-GC2.
- `test_requirements_canon.py::test_canon_rows_hold_the_obligation_word_once` — allowed. Offenders are exactly the base ones: `R-A2L-DEF.153`, `R-PICKER-CORRECT.004`, `R-PICKER-CORRECT.008`. No new offender. ✓
- `test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors` — allowed. Offenders are `tests/test_b103_*` files; not FA-GC2.
- `test_no_private_tokens.py::test_no_tracked_file_holds_a_private_token` — allowed. Offenders are `.dev-flow/...` files; not FA-GC2.

No other RED, and no new offender caused by this unit: FA-GC2's whole diff is 4 lines in `s19_app/tui/app/file_load.py` (2 comment lines + `if not gc.isenabled(): gc.enable()`), which adds no token, no home path/LAN address, no selector, no requirement row, and no test marker. Verified that `grep s19_app/tui/app` in the law output returns nothing, and that the checked copy differs from the FA-GC2-base copy (row 4 reverted) only in `file_load.py`. ✓

---

## Step 5 — Worker claims (5, re-verified)

1. "HEAD = dd961400 (coincide)" — **TRUE**. `git rev-parse HEAD` = `dd961400379cf70bbc06558218c0e3e151616107`.
2. "walk = None presente en a2l_definition.py:734" — **TRUE**. `grep -n "walk = None" s19_app/tui/a2l_definition.py` → `734:    walk = None ...`.
3. "Python s19ci resuelve s19_app dentro de ./s19_app" — **TRUE**. Under the check env a tree-local test prints `s19_app.__file__ = ~/work/zq-fa/chk-FA-GC2/s19_app/__init__.py` (inside `./s19_app`).
4. "git diff --stat: s19_app/tui/app/file_load.py | 4 ++++ (solo fila 4); CR count 0" — **TRUE**. Step 1 confirms 1 file, +4/-0, CR=0.
5. Row-6 stop rule: "test_r_a2l_refresh_053 ... RED ... counts=[307625, 339873, 371808, 403721, 435478]" — **TRUE**. Re-applied `gc.freeze()` at the 3 install sites (file_load.py:1222, loaded_state.py:893, project_load.py:1824) with `walk = None` present and ran the node:
```
E   AssertionError: R-A2L-REFRESH.053: load 4 retained 405320 objects > 1.10 x load 2 (339944); counts=[307719, 339944, 371881, 405320, 437083]
```
(Counts are GC-non-deterministic but match the worker's magnitude and conclusion: ~32k objects leaked per reload into the permanent generation.)

---

## Step 6 — Diff saved

`cp ~/work/zq-fa/chk-FA-GC2.diff ~/work/zq-fa/FA-GC2/CHECK.diff` (15 lines; same as step 1).

---

## Verdict

Steps 1–5 all pass. The unit STOPPED via its brief's row-6 stop rule (freeze would leak the cycle-forming A2L payload); rows 1–3 and 5 are reverted cleanly, row 4 (re-enable GC on the attach install-exception path) is kept, is GREEN, and its negative control is real. Laws show no new offender from this unit.

CHECK_DONE FA-GC2 MECH-GO

## Orchestrator intent review (Opus, relevo-22)
GO for the partial unit. The worker followed the stop rule: with `gc.freeze()` at the three install sites, `.053` went RED (~32k tracked objects retained per reload; census = Textual UI objects), so rows 1–3 and 5 were reverted and freeze is not adopted (FA-DESIGN §3.4). The diff keeps row 4 only: `_install_attached_a2l`'s `except BaseException:` re-enables GC before `_busy_fail`, which makes r038 (R-A2L-REFRESH.051) GREEN and is needed under every GC option. The Opus diagnosis (`frontA\GC-REDESIGN.md`, not committed) confirms the mechanism: the payload is acyclic after FA-GC1; Textual discards UI state through cycles (LRU rings left by `clear()`, self-caching strips, a compositor closure, removed widgets), and frozen objects never leave them. The remaining .052 work waits for the operator decision D-GC (FA-GC2R).
