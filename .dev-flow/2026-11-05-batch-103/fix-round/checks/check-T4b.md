# CHECK T4b — mechanical check

- Unit: T4b
- Tree path: ~/work/zq-ta/T4b/repo
- HEAD sha: 03d3594bcb49c3149bdeb210362a61fba9a55523
- Start time: 2026-11-19 16:04:29 CST


## Step 1 — Diff hygiene
- Command: `cp -a ~/work/zq-ta/T4b/repo ~/work/zq-ta/chk-T4b`; in the copy `git diff > ../chk-T4b.diff`.
- Files changed (3, all within the brief's "Files you may edit"):
  - `REQUIREMENTS.md` (by hand)
  - `tests/test_tui_services.py` (apply_recite)
  - `tests/test_verify_on_save.py` (apply_recite)
- CR count: `tr -cd '\r' < chk-T4b.diff | wc -c` = **0**.
- Added `skip`/`skipif`/`xfail`/`sleep(` lines: **0**.
- `def test_` names removed: **none**. Added: **none**.
- Diff is 3 canon row lines + 3 `Traces:` docstring lines (matches brief's "For the checker").

## Step 2 — GREEN vs base
- Command (copy): `... python -I -B -m pytest -p no:cacheprovider -q tests/test_tui_services.py::test_build_validation_report_keeps_explicit_empty_enriched_tags tests/test_tui_services.py::test_build_validation_report_falls_back_to_raw_tags_when_enriched_is_none tests/test_verify_on_save.py::test_unsupported_file_type_raises` → **3 passed in 0.06s**.
- Base transcript (clone of ~/work/zq-fb/fb.bundle at 03d3594b, clean tree): same 3 nodes → **3 passed in 0.06s**.
- Base-RED nodes: **none** (all 3 were GREEN at base).
- Nodes that passed at base and fail now: **none**.

## Step 3 — Negative controls are real
Copy: `~/work/zq-ta/chk-T4b-nc` (copy of the edited tree). Each mutation applied alone, only the affected node run, then product file restored by `cp` from the edited copy (no git writes).

1. R-VAL-055 — `s19_app/tui/services/validation_service.py:301` → `tags_for_validation = a2l_enriched_tags or (a2l_data or {}).get("tags", [])`
   - node `tests/test_tui_services.py::test_build_validation_report_keeps_explicit_empty_enriched_tags`
   - RED: `E       AssertionError: assert [{'address': ...name': 'RAW'}] == []` (1 failed)
2. R-VAL-056 — `s19_app/tui/services/validation_service.py:299` → `tags_for_validation = []`
   - node `tests/test_tui_services.py::test_build_validation_report_falls_back_to_raw_tags_when_enriched_is_none`
   - RED: `E       AssertionError: assert [] == [{'address': ...name': 'RAW'}]` (1 failed)
3. R-HEX-VERIFY-001.7 — `s19_app/tui/changes/verify.py:116` → `return {}`
   - node `tests/test_verify_on_save.py::test_unsupported_file_type_raises`
   - RED: `E       Failed: DID NOT RAISE <class 'ValueError'>` (1 failed)

Canon-row lint (on the edited copy):
`grep -E '^\| (R-VAL-055|R-VAL-056|R-HEX-VERIFY-001\.7) \|' REQUIREMENTS.md > rows.md; python -I -B ../in/lint_rows.py rows.md`
→ `ok  R-VAL-055`, `ok  R-VAL-056`, `ok  R-HEX-VERIFY-001.7`, `bad: 0`; each id as row start `^| <id> |` count = **1**.

All three controls went RED (none stayed GREEN).

## Step 4 — Laws
Command (copy root, serial): `... python -I -B -m pytest -p no:cacheprovider -q -n 0 tests/test_suite_hygiene.py tests/test_requirements_canon.py tests/test_id_registry.py tests/test_address_census.py tests/test_import_census.py tests/test_no_private_tokens.py`
→ **116 passed, 2 skipped** (matches base). No RED.

## Step 5 — Worker claims (5 re-verified)
1. Tool regression = 11 passed, with 19 `def test_` lines of which 8 are fixture-string text → **TRUE**. Re-ran: `11 passed in 0.55s`; `grep -c '^def test_' ../in/test_apply_recite.py` = 19; collect-only = 11.
2. N0 (collect-only) = 9827 before and after → **TRUE**. Re-ran on edited copy: `9827 tests collected`.
3. reverse_trace before/after → **TRUE**. Re-ran: before (base) `tests: 6959 {'O': 1560, 'K?': 620, 'S': 1215, 'K': 3294, 'X': 268, 'U': 2}`; after (copy) `tests: 6959 {'O': 1560, 'K?': 621, 'S': 1215, 'K': 3296, 'X': 265, 'U': 2}`.
4. apply_recite dry-run `ADD rows: 3 (applied=3, already=0)`, `files: 2` → **TRUE**. Re-ran dry-run on base + worker REQUIREMENTS.md: `ADD rows: 3 (applied=3, already=0)` / `files: 2`.
5. None of the 3 tests in class X after (R-VAL-055→K, R-VAL-056→K, R-HEX-VERIFY-001.7→K?) → **TRUE**. TA2-matrix classes: `K`, `K`, `K? (mixed:active+retired)`; none `X`.

## Step 6 — Save the diff
`~/work/zq-ta/T4b/CHECK.diff` = copy of step 1's diff (see below).

CHECK_DONE T4b MECH-GO

## Orchestrator intent review (Opus, relevo-21)
GO. Three product rows in their modules (R-VAL-055/.056 after R-VAL-018 in S3.1; R-HEX-VERIFY-001.7 after .6 in S8.8), verbatim; each `Traces:` line sits in the test the brief maps (empty enriched list = the boundary case of .055; `None` = the fallback of .056; the unsupported-format `ValueError` = .007). Docstrings only. Design choice kept (DF-02): these guards verify shipped functions (`validation_service.py`, `changes/verify.py`), so S3/S8 rows describe them better than S0 process rows.
