# CHECK — FA-C7 (mechanical check)

- Unit: FA-C7
- Tree path: `~/work/zq-fa/FA-C7/repo`
- HEAD sha: `ec8e7bd419208a5c891d35a965d5d091b561c52c` (verified `git rev-parse HEAD`)
- Start time: 2026-11-19 17:01 CST
- Checker host: `<host>` (16-core CachyOS lab host, shared load)

Verdict target: steps 1–5 must all pass for MECH-GO.

---

## Step 1 — Diff hygiene

Command:
```
cp -a ~/work/zq-fa/FA-C7/repo ~/work/zq-fa/chk-FA-C7
cd ~/work/zq-fa/chk-FA-C7 && git diff > ../chk-FA-C7.diff
```

Result (`git diff --stat`):
```
 s19_app/tui/app/patch.py                           | 60 +++++++++++++++++++-
 .../screens_directionb/patch_editor/a2l_picker.py  | 65 +++++++++-------------
 2 files changed, 82 insertions(+), 43 deletions(-)
```

- Files changed: exactly 2, both within the brief's "Files you may edit" (`s19_app/tui/app/patch.py`, `s19_app/tui/screens_directionb/patch_editor/a2l_picker.py`). PASS.
- CR count: `tr -cd '\r' < ../chk-FA-C7.diff | wc -c` → `0`. PASS.
- Added `skip`/`skipif`/`xfail`/`sleep(` lines: `git diff | grep -nE "^\+.*(skip|skipif|xfail|sleep\(|pytest\.mark|reruns|flaky)"` → (none). PASS.
- `def test_` names removed and not re-added: `git diff | grep -E "^[-+]def test_"` → (none); no test file is touched. PASS.

---

## Step 2 — GREEN vs base

Ran the brief's node set on the copy with the exact env one-liner (from the copy's root).

Command A (`-n 0`):
```
-n 0 tests/test_tui_patch_card.py::test_tc080_2_c7_purity_probe tests/test_tui_patch_checks_strip.py::test_tc078_2_aggregates_param tests/test_tui_patch_history_strip.py::test_tc081_2_strip
```
Summary: `1 failed, 2 passed in 2.70s`
- `test_tc080_2_c7_purity_probe` → PASSED
- `test_tc078_2_aggregates_param` → PASSED
- `test_tc081_2_strip` → FAILED (expected RED until FA-C7b: MRO arm `_history_strip_text` missing from `vars(PatchEditorPanel)`)

Command B (`-k r037 -n 0`):
```
-n 0 tests/test_alp_inc2_a2l_attach.py -k r037
```
Summary: `1 failed, 4 passed, 33 deselected in 102.15s`
- Failed node: `test_r037_picker_snapshot_reuse[adapter-mismatch]` (expected RED until FA-C7b, patch half).

Command C (`-n 4`, 4 files):
```
-n 4 tests/test_b102_bulk_add.py tests/test_b103_picker_editor.py tests/test_b103_picker_model.py tests/test_import_census.py
```
Summary: `1 failed, 90 passed in 125.15s`
- Failed node: `test_b103_picker_model.py::test_r017_2_hostile_unit_is_replaced_literally` (expected RED until FA-C7b, patch arm).

Base-RED nodes (from the six-law base transcript `~/work/zq-fa/briefs/laws-base-alp.txt` at 25161a00) and their results now — re-checked in Step 4; all 6 remain RED, none recovered, and no base-GREEN node now fails (109 passed, 2 skipped again). The 3 unit-node failures above are exactly the brief's "Expected RED until FA-C7b" list; every other node in the node set is GREEN. PASS.

---

## Step 3 — Negative controls are real

Second copy `~/work/zq-fa/chk-FA-C7-nc` (copy of the already-modified tree). Ran only the affected node: `tests/test_tui_patch_card.py::test_tc080_2_c7_purity_probe`.

NC-1 (re-add the `:43` read, per REPORT row 1): in `a2l_picker.py` mounted `else` branch, added
```python
a2l_data = getattr(self.app, "current_a2l_data", None)
```
Summary: `1 failed in 0.19s`
```
E   AssertionError: PatchEditorPanel reaches self.app at 1 site(s) — the card must be fed by parameter, not by reaching for the app
tests/test_tui_patch_card.py:784: AssertionError
```
→ RED. PASS.

NC-2 (re-add the `:45` read, per REPORT row 3): in `a2l_picker.py` mounted `else` branch, added
```python
_ = getattr(self.app, "_accepted_a2l_picker_snapshots", {})
```
Summary: `1 failed in 0.19s`
```
E   AssertionError: PatchEditorPanel reaches self.app at 1 site(s) — the card must be fed by parameter, not by reaching for the app
tests/test_tui_patch_card.py:784: AssertionError
```
→ RED. PASS.

(Row 2's negative control is deferred to FA-C7b by the brief itself — today's `.037` arms call the panel directly, so they cannot see the caller; the brief orders the `-k r037` result instead, reported in Step 2.) Both re-applyable controls stay RED; no control stayed GREEN.

---

## Step 4 — Laws (serial, `-n 0`)

Command:
```
-n 0 tests/test_suite_hygiene.py tests/test_requirements_canon.py tests/test_id_registry.py tests/test_address_census.py tests/test_import_census.py tests/test_no_private_tokens.py
```
Summary: `6 failed, 109 passed, 2 skipped in 413.69s`

Failed (all in the allowed base-RED list, none other):
```
FAILED tests/test_suite_hygiene.py::test_r_tst_002_every_timing_arm_carries_serial_timing
FAILED tests/test_suite_hygiene.py::test_r_tst_040_041_every_upper_timing_bound_is_reported
FAILED tests/test_suite_hygiene.py::test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses
FAILED tests/test_requirements_canon.py::test_canon_rows_hold_the_obligation_word_once
FAILED tests/test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors
FAILED tests/test_no_private_tokens.py::test_no_tracked_file_holds_a_private_token
```

Offender comparison (no new offender inside any allowed RED):
- `test_r_tst_002`: same 5 lines as base (test_at_alp_i2_2_case06_keys_and_progress, test_r033_key_latency, test_r_a2l_def_158_1, test_r_a2l_def_158_2, test_r_a2l_def_164_1).
- `test_r_tst_040_041`: same single offender `tests/test_alp_inc2_a2l_attach.py:609`.
- `test_r_tst_070_2`: same evidence offenders as base (b103-g3-recents/RESULT, b103-g3-ui-a junit/logs, b103-g3-ui-a/test_b100_*.junit.xml, local-runs). The RESULT file is byte-identical to base (`diff -q` → identical); the base transcript shows the same hit as `~` because the orchestrator's committed transcript redacted the home-path token, not because the token changed.
- `test_canon_rows_hold_the_obligation_word_once`: `3 offending (3355 checked)` — offenders are exactly the base set `R-A2L-DEF.153`, `R-PICKER-CORRECT.004`, `R-PICKER-CORRECT.008` (base: `3 offending (3317 checked)`). Checked count rose only because REQUIREMENTS.md grew between 25161a00 and ec8e7bd4; no new offender.
- `test_at_b83_08_tree_holds_no_assembled_selectors`: same offender list as base (test_alp_inc2_a2l_attach.py:408; test_b103_a2l_refresh.py:218/282; test_b103_picker_model.py:94/186/191/197/680/747).
- `test_no_tracked_file_holds_a_private_token`: same `.dev-flow/2026-11-18-a2l-load-performance/...` offender list as base.

Known hole: at base 25161a00 there are blank lines in REQUIREMENTS.md after R-A2L-DEF.155 and R-A2L-REFRESH.028 that hide the rows below from the canon law. In the unit tree (ec8e7bd4) those blank lines are absent (rows are contiguous), so the canon law now sees the rows; the newly-visible E4R rows (R-A2L-DEF.162–.168, R-A2L-REFRESH.033/.034/.037/.040–.042/.049–.053) each hold the obligation word exactly once (verified by direct grep of REQUIREMENTS.md), so no hidden offender is masked. No new RED. PASS.

---

## Step 5 — Worker claims (5 re-verified)

1. REPORT header `HEAD: ec8e7bd4…` → `git rev-parse HEAD` prints `ec8e7bd419208a5c891d35a965d5d091b561c52c`. TRUE.
2. REPORT `git diff --stat` = 2 files, 82 insertions, 43 deletions → re-derived identically. TRUE.
3. REPORT `grep -c $'\r'` on diff = 0 → re-derived `0`. TRUE.
4. REPORT final run `-n 0` 3 nodes → `1 failed, 2 passed` → re-run gives `1 failed, 2 passed` (failure = test_tc081_2_strip). TRUE.
5. REPORT final run `-k r037 -n 0` → `1 failed, 4 passed, 33 deselected` → re-run gives the same; the arm that changes outcome is `adapter-mismatch`. TRUE.
6. (extra) REPORT `-n 4` 4 files → `1 failed, 90 passed` → re-run gives the same; failure = `test_r017_2_hostile_unit_is_replaced_literally`. TRUE.
7. (extra) REPORT HT-03 note: bare `python -I -B -c "import s19_app"` resolves to the editable install `~/work/s19_app/...`; with `sys.path.insert(0, '.')` (what `pyproject.toml` `pythonpath = ["."]` does for pytest) `s19_app.__file__` resolves to `<tree>/s19_app/__init__.py`. Re-verified, and independently proven by Step 3: mutating the tree copy's `a2l_picker.py` flips the probe GREEN→RED, so pytest imports the tree. TRUE.

All claims TRUE.

---

## Step 6 — Saved diff

Saved step 1's diff to `~/work/zq-fa/FA-C7/CHECK.diff` (207 lines, `git diff` output of the two product files).

---

## Cleanup

Deleted scratch copies `~/work/zq-fa/chk-FA-C7/`, `~/work/zq-fa/chk-FA-C7-nc/`, `~/work/zq-fa/chk-FA-C7.diff`, and state dir `~/work/zq-fa/chk-FA-C7-state/` after saving CHECK.diff.

## Verdict

Steps 1–5 all pass; no new RED, no new offender, both negative controls real.

CHECK_DONE FA-C7 MECH-GO

## Orchestrator intent review (Opus, relevo-22)
GO. C-7 (LLR-078.2) as designed: the panel's four `self.app` reaches are gone. Design 1: G2's app handler `on_a2l_parameter_picker_bulk_add_requested` is ported verbatim (same docstring and body as `frontB\diffs\G2.diff`), the panel's bulk handler and `_open_parameter_bulk_add` are removed, `BulkParameterAddScreen` is now imported by `patch.py` only. Design 2: the I-ALP-2.3 adapter sits in `_prefill_patch_editor` with the four ordered branches of ruling R3 (unmounted → legacy call with no data and no mapping read; signature and A2L-source match → prepared definitions; present but mismatched → the whole mapping is emptied before the fallback populate; absent → `a2l_data` only). Design 3: the panel only forwards (unmounted → `a2l_data=None`, ignoring `prepared_definitions`). The other `set_a2l_parameters` caller (`checks_diff.py:101`) belongs to the Check panel, not this mixin. Signature differs from G2 only by the extra keyword `prepared_definitions=None` (alp-only), which keeps the later merge mechanical. The three REDs the worker lists are exactly the brief's "expected RED until FA-C7b" (MRO strip arm, `r017_2` patch arm, the `.037` `adapter-mismatch` patch half that calls the panel directly).
