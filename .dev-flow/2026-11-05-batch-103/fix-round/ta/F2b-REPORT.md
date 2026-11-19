# F2b — test cases for the rows the fold integrated

- unit: F2b
- HEAD sha: 03d3594bcb49c3149bdeb210362a61fba9a55523 (branch `work`)
- start: Thu Nov 19 04:16:24 PM CST 2026
- brief files: `frontB/FB-common.md`, `units2/TA2-common.md`, `units2/F2b` (the unit brief)

| row | file:function | change (one line) | negative-control mutation (file:line, one line) | command | RED line under mutation | GREEN result after change | OPEN? |
|---|---|---|---|---|---|---|---|
| 1 | 5 test files, docstrings only (13 tests) | add `Traces:` lines mapping 16 fold rows to their verifying tests via `apply_recite.py --apply` (13 ADD rows, 5 files) | NC-b: `s19_app/tui/screens.py:1049` `if summary["not_found"]:` → `if summary["not_found"] and summary["included"]:` (NC-a: rerun `--apply` → 13 already, diff unchanged) | `apply_recite.py --repo . --map ../in/F2b-map.tsv --apply`; pytest 14 nodes | `E   AssertionError: Included 0 · already included 0 · not found 1` (assert `'Included 0 ·…· not found 1' == 'Included 0 ·…issing: Gamma'` on `test_tc_b102_bulk_03_unique_name_counts`) | 14 passed (all 13 map nodes, incl. `test_tc_b102_a2l_04_…` ×2 params) | no |
| 2 | REQUIREMENTS.md (S0.10) | delete the `\| R-DOC-ARCHIVE.2 \|` row and insert its retired note after `\| R-DOC-ARCHIVE.4 \|` | NC-c: one-row map `new_ids=R-DOC-ARCHIVE.2` → `apply_recite.py` dry run exits 2 | `apply_recite.py --repo . --map ../scratch/nc-c-map.tsv` (dry) | `recite: non-canon new_ids: 1=R-DOC-ARCHIVE.2` (exit 2) | `trace_check.py --req REQUIREMENTS.md --ids R-DOC-ARCHIVE.2` → exit 2, no match; row no longer a canon row | no |
| 3 | tests/test_b102_parameter_picker.py::test_r_chked_001_1/2 (+ `_ledger_names`, `_names_on_both_pages`) | append two R-CHKED-001 tests (verification + validation, 250 params over two 200-row pages) plus two helpers | NC-d: `s19_app/tui/a2l_parameter_picker.py:921` `page = names[start : start + self._page_size]` → `… - 1]` | pytest 2 nodes | test 1: `E   AssertionError: (199, 50)` / `E   assert (199, 50) == (200, 50)`; test 2: `E   AssertionError: did not settle: the first page shows 200 rows` | 2 passed | no |

## Deviations

1. **Tool regression count (11 vs 19).** The brief says `pytest -q ../in/test_apply_recite.py` → "19 passed (the 19 `def test_` of the repo file at 2a8ab75f)". The staged copy (identical to the repo copy at `.dev-flow/2026-11-05-batch-103/fix-round/ta/test_apply_recite.py`) defines **20** `def test_`, of which **9** are synthetic test bodies embedded inside the `TEST_F` string literal and only **11** are real pytest functions (`test_t1` … `test_t11`). The run reports `11 passed in 0.65s` (all 11 real tests pass; none fail). Evidence:
   - `grep -c 'def test_' ../in/test_apply_recite.py` → `20`
   - `diff ../in/test_apply_recite.py repo/.dev-flow/2026-11-05-batch-103/fix-round/ta/test_apply_recite.py` → identical
   - `pytest -q ../in/test_apply_recite.py` → `11 passed in 0.65s`

2. **reverse_trace "before" K/K? split differs from the brief's base count.** Brief base at 2a8ab75f: `{'K': 3293, 'K?': 621, 'S': 1215, 'O': 1560, 'X': 268, 'U': 2}`. Measured on this host at 03d3594b: `{'K': 3294, 'K?': 620, 'S': 1215, 'O': 1560, 'X': 268, 'U': 2}`. Total `tests: 6959` matches in both; only one test flips between the K and K? buckets (host classification variance). The "after" oracle values all match (see below).

3. **Planted control (checker), recorded.** On the unit tree `trace_check.py --req REQUIREMENTS.md --ids R-DOC-ARCHIVE.2` exits 2 (`trace_check: no active requirement matches --ids R-DOC-ARCHIVE.2`). On a scratch copy with the `| R-DOC-ARCHIVE.2 |` row restored, the same command exits 1 and prints `TEST   R-DOC-ARCHIVE.2 is named by no file under tests, and neither is a TC/AT id it lists` — i.e. the retired note is not a row and the restored row re-opens the TEST gap.

## Open questions

- None blocking. The K/K? one-test drift in the reverse_trace "before" snapshot (deviation 2) is host-measurement variance; the total and the oracle O/X/U values agree, so no action.

## Oracle and end

- `trace_check.py --req REQUIREMENTS.md --ids $(cat ../in/f2b-fold-ids.txt)` after: TEST lines = 3 (`R-TST-009`, `R-TUI-062.10.2`, `R-TUI-062.10.3`), plus the one CASE line; summary `4 gap(s)`. Before was 20 TEST lines (+1 CASE). ✓
- `reverse_trace.py --ta2` after: `tests: 6961 {'O': 1558, 'K?': 620, 'S': 1215, 'K': 3298, 'X': 268, 'U': 2}`. Oracle `tests: 6961`, `O 1558`, `X 268`, `U 2` all match. ✓
- `--collect-only -q tests`: `9829 tests collected` (= N0 9827 + 2). ✓

`git diff --stat`:

```text
 REQUIREMENTS.md                                |  3 +-
 tests/test_b102_a2l_refresh.py                 |  1 +
 tests/test_b102_bulk_add.py                    | 14 ++++++
 tests/test_b102_parameter_picker.py            | 59 ++++++++++++++++++++++++++
 tests/test_b103_a2l_definition_arrays_write.py |  1 +
 tests/test_b97_flow_execution.py               |  2 +
 tests/test_suite_hygiene.py                    |  3 ++
 7 files changed, 82 insertions(+), 1 deletion(-)
```

`git diff | grep -c $'\r'` → `0` (no CR bytes).

Final run of the unit's nodes (13 map nodes + 2 new, serial `-n 0`):

```text
16 passed in 125.35s (0:02:05)
```

UNIT_DONE F2b
