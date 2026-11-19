<!-- DeepSeek v4-pro mechanical check (CHK-ds) of G1+G1b; intent review by the orchestrator: generator change = MATRIX_DIM line only; digests re-pinned with the proof that the content diff is MATRIX_DIM lines alone. -->
# CHECK G1b — mechanical check of unit G1b

- unit: G1b
- tree: ~/work/zq-fb/G1b/repo
- HEAD sha: 3afebf904d8676624b2b23a412d597beb14432fb
- start time: Thu Nov 19 12:45:31 PM CST 2026

## Step 1 — Diff hygiene

Files changed (git diff --stat):
```
 tests/test_b103_a2l_definition.py    |  2 ++
 tests/test_b103_synth_definitions.py | 22 ++++++++++++++++------
 tools/synth/make_release_case.py     |  3 +++
 3 files changed, 21 insertions(+), 6 deletions(-)
```
- `tests/test_b103_a2l_definition.py` and `tests/test_b103_synth_definitions.py` are within "Files you may edit".
- `tools/synth/make_release_case.py` is G1's uncommitted held generator change (3-line MATRIX_DIM 128 addition); the brief explicitly requires it to be present and says "do not change it". It is NOT a G1b edit (verified: it matches G1's change, only 3 added lines).

CR count (`tr -cd '\r' < chk-G1b.diff | wc -c`): 0
Added skip/skipif/xfail/sleep( lines: 0
`def test_` names removed: none
`def test_` names added: none

## Step 2 — GREEN vs base

Commands (from the copy's root `~/work/zq-fb/chk-G1b`), checker env (timeout 1200):

1. `tests/test_b103_synth_definitions.py` (`-n 4`, slow 10 MiB included):
   summary: `17 passed in 26.10s`  (EXIT=0)
2. `tests/test_b103_a2l_definition.py -k "case08 or pin"` (`-n 4`):
   summary: `8 passed in 19.45s`  (EXIT=0)
3. G1 failing set (`-n 4`, with the i12 node and the inplace_views deselect):
   summary: `20 passed in 254.37s`  (EXIT=0)

Base-RED nodes (from `~/work/zq-fb/baseline/G1.txt`, parent unit G1) and result now:
| base-RED node | result now |
|---|---|
| tests/test_synth_release_case.py::test_a2l_zero_issues | PASSED |
| tests/test_synth_release_case.py::test_addresses_inside_image | PASSED |
| tests/test_synth_release_case.py::test_a2l_issues_reported | PASSED |
| tests/test_b101_reach_and_reports_escape.py::test_at_i12_2_rail_keys_and_issue_peek_after_the_aliases_go | PASSED |
| tests/test_b101_inc11_acceptance.py::test_at_i11_2_faulty_demo_errors_first | PASSED |
| tests/test_b101_inc11_acceptance.py::test_at_i11_1_clean_demo_issues_without_standard_blocks | PASSED |
| tests/test_b101_inplace_views.py::test_qc_tm_10b_1_a2l_refresh_cost_on_the_largest_a2l | DESELECTED (out of G1b node set, per brief) |

Nodes that passed at base and fail now: none (all 45 collected nodes in the 3 node sets pass).

## Step 3 — Negative controls are real

Second copy `~/work/zq-fb/chk-G1b-nc`. Worker's mutation (from REPORT.md): revert the generator change — remove the added `MATRIX_DIM` line at `tools/synth/make_release_case.py` (~line 650), i.e. restore HEAD's generator. Then run only the affected re-pinned nodes.

Affected node 1 — `tests/test_b103_synth_definitions.py::test_r_a2l_def_59_1_case08_at_1_mib_equals_its_pin`:
```
E       AssertionError: assert {'README.txt'...3d2ac79', ...} == {'README.txt'...3d2ac79', ...}
E         Differing items:
E         {'firmware_issues.a2l': 'bb1522da…'} != {'firmware_issues.a2l': 'af66a17e…'}
E         {'firmware.a2l': '34900db0…'} != {'firmware.a2l': '85893ad9…'}
```
`1 failed in 1.16s` — RED (control is real).

Affected node 2 — `tests/test_b103_synth_definitions.py::test_r_a2l_def_59_2_case08_at_10_mib_equals_its_pin`:
```
E         Differing items:
E         {'firmware_issues.a2l': '6f936293…'} != {'firmware_issues.a2l': 'fedea56b…'}
E         {'firmware.a2l': '42ca7d40…'} != {'firmware.a2l': 'c1d194c2…'}
```
`1 failed in 4.78s` — RED (control is real).

No control stayed GREEN.

## Step 4 — Laws

Command (serial `-n 0`, checker env, from copy root):
```
tests/test_suite_hygiene.py tests/test_requirements_canon.py tests/test_id_registry.py
tests/test_address_census.py tests/test_import_census.py tests/test_no_private_tokens.py
```
summary line: `3 failed, 112 passed, 2 skipped in 416.32s`  (EXIT=1)

The 3 RED are exactly the allowed base-RED nodes:
- tests/test_suite_hygiene.py::test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses  (allowed)
- tests/test_requirements_canon.py::test_canon_rows_hold_the_obligation_word_once  (allowed "canon two-shall row test")
- tests/test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors  (allowed)

No other RED. All remaining law nodes pass (112 passed, 2 skipped).

## Step 5 — Worker claims (re-verified)

1. Claim: "git diff confirms exactly the 3-line MATRIX_DIM 128 addition from G1 is present in tools/synth/make_release_case.py (uncommitted), nothing else."
   → TRUE. `git diff tools/synth/make_release_case.py` = 3 added lines (the MATRIX_DIM append), 0 removals.

2. Claim: "diff -r of old-generator vs current-generator case_08 shows only firmware.a2l and firmware_issues.a2l differ; 60 additions each, every one MATRIX_DIM 128."
   → TRUE. Verified at 1 MiB and 10 MiB (seed 20260001): diff -r lists only those 2 files; `grep -c '^>       MATRIX_DIM 128'` = 60 per file (×2 files ×2 sizes); no other added/removed lines.

3. Claim: "Re-pinned digests = current-generator values (1 MiB: firmware.a2l 85893ad9…, firmware_issues.a2l af66a17e…; 10 MiB: c1d194c2…, fedea56b…)."
   → TRUE. Recomputed SHA-256 (CRLF→LF) from the current generator:
     1 MiB firmware.a2l = 85893ad913701952f5ce500ed1beca17c7822eee497efd5e668c4f098cfc803c
     1 MiB firmware_issues.a2l = af66a17e7cc0a9fd5bd858fc5261ee470db870b69dfc4fd7f0821b20c596e93e
     10 MiB firmware.a2l = c1d194c256a99e09aece0cdec5ef4d860ecb29fa881b9a5f5b6f2e63b2f98f88
     10 MiB firmware_issues.a2l = fedea56b264640204623370aa350a6163ce57a32785bbc707e3ea8d4cc1cd74f
     All match the pins.

4. Claim: "OBJECT_LIST_DIGEST_1MIB recomputed on the current tree = 71252ba6…a6fdec (unchanged)."
   → TRUE. Recomputed = 71252ba6f06af28c6979ab634e3ee0f5aaff9d25a7bb55d49d467d0403a6fdec (equals pin).

5. Claim: "Final run: test_b103_synth_definitions.py 17 passed; test_b103_a2l_definition.py -k 'case08 or pin' 8 passed; G1 failing set 20 passed."
   → TRUE. Re-verified in step 2: 17 passed / 8 passed / 20 passed.

Observation (timing): worker reported the G1 failing set took 322.82s (> timeout 300) and listed it as a deviation. My checker run finished the same set in 254.37s (< 300s). Timing is machine-load dependent; the substantive claim (all 20 pass) holds.

## Step 6 — Diff saved
`~/work/zq-fb/G1b/CHECK.diff` = copy of step 1's diff (96 lines, CR count 0).

## Verdict
Steps 1–5 all pass → MECH-GO.

CHECK_DONE G1b MECH-GO
