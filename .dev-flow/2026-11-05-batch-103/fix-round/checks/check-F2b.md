# CHECK — F2b (mechanical check)

- unit: F2b
- tree: ~/work/zq-ta/F2b/repo
- HEAD sha: 03d3594bcb49c3149bdeb210362a61fba9a55523
- start: Thu Nov 19 16:19:07 CST 2026

## Step 1 — Diff hygiene
Command: `cp -a ~/work/zq-ta/F2b/repo ~/work/zq-ta/chk-F2b`; in the copy `git diff > ../chk-F2b.diff`.

Files changed (7) — all within the brief's "Files you may edit":
- REQUIREMENTS.md (row 2, by hand) ✓
- tests/test_b102_parameter_picker.py (row 3, by hand append) ✓
- tests/test_b103_a2l_definition_arrays_write.py (apply_recite) ✓
- tests/test_b102_bulk_add.py (apply_recite) ✓
- tests/test_b102_a2l_refresh.py (apply_recite) ✓
- tests/test_suite_hygiene.py (apply_recite) ✓
- tests/test_b97_flow_execution.py (apply_recite) ✓

- CR count: `tr -cd '\r' < chk-F2b.diff | wc -c` → `0` ✓
- added skip/skipif/xfail/sleep( lines → `(none)` ✓
- removed `def test_` → `(none)` ✓
- added `def test_` → 2 (the row-3 tests, ordered by the brief) ✓

## Step 2 — GREEN vs base
Node set (13 map nodes + 2 new tests; the a2l_refresh node is parametrized ×2 → 16 instances), serial `-n 0`.
- On the copy (HEAD 03d3594b + worker edits): `16 passed in 115.12s` ✓
- On the base clone (clean 03d3594b): the 13 map nodes → `14 passed in 108.07s` (the 2 new tests do not exist at base) ✓

Base-RED nodes: none (the unit adds traces/tests; it fixes no RED node — all 13 map nodes were GREEN at base).
Nodes that passed at base and fail now: none (all 16 GREEN on the copy). ✓

## Step 3 — Negative controls are real (second copy ~/work/zq-ta/chk-F2b-nc)
NC-d (row 3): `s19_app/tui/a2l_parameter_picker.py:921` → `page = names[start : start + self._page_size - 1]`.
Run: 2 new nodes → `2 failed in 16.58s`.
- test 1: `E   AssertionError: (199, 50)` / `E   assert (199, 50) == (200, 50)` ✓
- test 2: `E   AssertionError: did not settle: the first page shows 200 rows` ✓

NC-b (row 1): `s19_app/tui/screens.py:1049` → `if summary["not_found"] and summary["included"]:`.
Run: `tests/test_b102_bulk_add.py::test_tc_b102_bulk_03_unique_name_counts` → `1 failed in 4.21s`.
- `E   AssertionError: Included 0 · already included 0 · not found 1` (missing `— first missing: Gamma`) ✓

NC-c (row 2): one-row map `new_ids=R-DOC-ARCHIVE.2` → `apply_recite.py` dry run:
- `recite: non-canon new_ids: 1=R-DOC-ARCHIVE.2`, exit 2 ✓

All three controls go RED (or exit 2) — no control stayed GREEN. ✓

## Step 4 — Laws (serial -n 0)
Command: the six law files on the copy.
`tests/test_suite_hygiene.py tests/test_requirements_canon.py tests/test_id_registry.py tests/test_address_census.py tests/test_import_census.py tests/test_no_private_tokens.py`
Result: `116 passed, 2 skipped in 421.68s (0:07:01)`, exit 0. Matches base (116 passed, 2 skipped). ✓

## Step 5 — Worker claims (5 re-verified)
1. **CR count 0** (`git diff | grep -c $'\r'` on the copy) → `0` (grep exit 1). TRUE.
2. **collect-only = 9829** (`python -I -B -m pytest -p no:cacheprovider --collect-only -q tests`) → `9829 tests collected in 19.95s` (= N0 9827 + 2). TRUE.
3. **trace_check after = 3 TEST gaps** (`python -I -B ../in/trace_check.py --req REQUIREMENTS.md --ids $(cat ../in/f2b-fold-ids.txt)`) → 3 TEST lines (`R-TST-009`, `R-TUI-062.10.2`, `R-TUI-062.10.3`) + 1 CASE, summary `4 gap(s)`, exit 1. TRUE.
4. **Tool regression 11 passed** (`pytest -q ../in/test_apply_recite.py`) → `11 passed in 0.45s`. TRUE (deviation 1 re-confirmed: 11 real pytest functions, not 19).
5. **reverse_trace after oracle** (`python -I -B ../in/reverse_trace.py --repo . --out …/rt-after --tmp …/rt-tmp --ta2`) → `tests: 6961 {'O': 1558, 'K?': 620, 'S': 1215, 'K': 3298, 'X': 268, 'U': 2}` (O 1558 / X 268 / U 2 all match). TRUE.

## Step 6 — Save the diff
`CHECK.diff` = copy of step 1's `chk-F2b.diff` (9965 bytes, byte-identical), saved to `~/work/zq-ta/F2b/CHECK.diff`.

## Verdict
Steps 1–5 all pass. MECH-GO.

CHECK_DONE F2b MECH-GO

## Orchestrator intent review (Opus, relevo-21)
GO. (1) R-DOC-ARCHIVE.2 leaves the canon per DF-04 and TR-01's logic: batch-101 ruled it increment-local (Inc 16 E1-rulings D-1) and verified it there; it becomes a retired note in S0.10 in the canon's own form (as R-TUI-029.5); 0 tests cite it. (2) Thirteen `Traces:` lines name already-verified folded rows on the tests that verify them (split children such as R-B102-BULK-005.3, ids hidden in names such as `test_r_tst_043_045_…`), docstrings only. (3) R-CHKED-001 gets a verification test (250 synthetic parameters on 200-row pages: each shown exactly once) and a black-box validation test (a loaded 250-CHARACTERISTIC A2L, paged through from the rail). Oracle met: `trace_check` TEST gaps over the 292 folded rows 20 -> 3 (R-TST-009 = release-gate measurement, D-15; R-TUI-062.10.2/.3 = U-MM, waiting for Q-MM); reverse_trace `tests 6961 · O 1558`.
