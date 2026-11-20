# CHECK FB-PP04 — mechanical check (DeepSeek v4-pro)

unit: FB-PP04
tree: ~/work/zq-fb/FB-PP04/repo
HEAD sha: d309c753fbbde2b792d92a5025878e7569711cf5
start: Thu Nov 19 22:33:17 CST 2026

## Step 1 — Diff hygiene

Command:
```
cp -a ~/work/zq-fb/FB-PP04/repo ~/work/zq-fb/chk-FB-PP04
cd ~/work/zq-fb/chk-FB-PP04 && git diff > ../chk-FB-PP04.diff
```

Files changed (must be within the brief's "Files you may edit" = REQUIREMENTS.md, tests/test_b101_doc_hygiene.py, tests/test_b101_designer_recompute.py):
```
 REQUIREMENTS.md                       |   2 +-
 tests/test_b101_designer_recompute.py | 124 ++++++++++++++++++++++++++++++----
 tests/test_b101_doc_hygiene.py        |   4 +-
 3 files changed, 116 insertions(+), 14 deletions(-)
```
=> all 3 within the allowed list. PASS.

CR count: `tr -cd '\r' < chk-FB-PP04.diff | wc -c` = 0. PASS.

Added `skip`/`skipif`/`xfail`/`sleep(` lines: 0 real markers. The only `skip` hit is inside a docstring sentence ("A skip is NOT a pass (N-5)") and `async def test_a():` hits are string-literal snippets `_D2_DOC_BASE`/`_D2_DOC_HEAD`, not test functions. PASS.

`def test_` names removed and not re-added: none removed. Added: `test_inc13_d2_check_ignores_docstring_only_changes` (the one new unit case the brief orders in row 2). PASS.

## Step 2 — GREEN vs base

Base RED reference: the PP-04 triage `~/work/zq-fb/pp04.log` reproduced the diagnosis on branch b103-fix-round @ d309c753 (4 nodes RED) and on main @ 3afebf90 (all 14 GREEN). No dedicated `baseline/FB-PP04.txt` transcript exists; the 4 RED nodes below are the unit's base-RED set from the fixed diagnosis.

Commands (from the copy root, CHK-BRIEF env line; `S=~/work/zq-fb/chk-FB-PP04-state`):
```
-n 0 tests/test_b101_doc_hygiene.py::test_r_doc_ref_3_1_no_fast_dev_flow_path ::test_r_doc_ref_3_2_no_prototypes_path ::test_r_doc_ref_4_1_retired_workflow_named_only_as_retired tests/test_b101_designer_recompute.py::test_inc13_d2_touched_nodes_differ_from_base_only_by_the_waits
  -> 4 passed in 2.01s
```

Base-RED node -> result now:
| base-RED node | result now |
|---|---|
| test_r_doc_ref_3_1_no_fast_dev_flow_path | PASS |
| test_r_doc_ref_3_2_no_prototypes_path | PASS |
| test_r_doc_ref_4_1_retired_workflow_named_only_as_retired | PASS |
| test_inc13_d2_touched_nodes_differ_from_base_only_by_the_waits | PASS |

Full node set (same `-n` as brief):
```
-n 4 tests/test_b101_doc_hygiene.py tests/test_b101_designer_recompute.py
  -> 101 passed in 118.11s (0:01:58)
-n 0 tests/test_b101_doc_hygiene.py -k "doc_ref_3 or doc_ref_4"
  -> 5 passed, 40 deselected in 1.86s
-n 0 tests/test_b101_designer_recompute.py -k "d2"
  -> 4 passed, 52 deselected in 0.24s
-n 0 tests/test_requirements_canon.py tests/test_id_registry.py
  -> 23 passed in 7.74s
```

Nodes GREEN at base that now fail: none (101 passed, no failures across the two unit files). PASS.

## Step 3 — Negative controls are real

Second copy `~/work/zq-fb/chk-FB-PP04-nc` (copy of chk-FB-PP04). Re-applied the worker's two REPORT.md negative-control mutations.

Row 1 mutation: `tests/test_b101_doc_hygiene.py` `_is_text_file_path` — dropped the REQUIREMENTS.md clause, reverted to `return not rel.startswith((".dev-flow/", "docs/requirements/"))`.

Command:
```
-n 0 tests/test_b101_doc_hygiene.py::test_r_doc_ref_3_1_no_fast_dev_flow_path ::test_r_doc_ref_3_2_no_prototypes_path ::test_r_doc_ref_4_1_retired_workflow_named_only_as_retired
```
RED assertion lines:
```
E   AssertionError: 4 paths in the retired workflow folder:        (3_1)
E   AssertionError: 4 paths in the removed design-probe folder:    (3_2)
E   AssertionError: 4 unmarked mentions of the retired workflow:   (4_1)
3 failed in 1.96s
```
Control is RED. PASS.

Row 2 mutation: `tests/test_b101_designer_recompute.py` `_strip_first_docstring` — made a no-op (`return body`).

Command:
```
-n 0 tests/test_b101_designer_recompute.py::test_inc13_d2_touched_nodes_differ_from_base_only_by_the_waits ::test_inc13_d2_check_ignores_docstring_only_changes
```
RED assertion lines:
```
E   AssertionError: changes beyond the inserted waits: changed at head: def test_save_check_mismatch_warns_but_still_writes; changed at head: def test_store_width_too_small_warns_live
E   assert ["missing at ...: def test_a'] == []
2 failed in 0.29s
```
Control is RED. PASS.

## Step 4 — Laws (serial)

Command (copy root, `-n 0`, --tb=short):
```
tests/test_suite_hygiene.py tests/test_requirements_canon.py tests/test_id_registry.py tests/test_address_census.py tests/test_import_census.py tests/test_no_private_tokens.py
```
Result:
```
118 passed in 405.82s (0:06:45)
EXIT=0
```
FAILED/ERROR lines: 0.

Allowed RED at base (from baseline/laws.txt @ 3afebf90): canon two-shall row test (`test_canon_rows_hold_the_obligation_word_once`), address census `test_at_b83_08_tree_holds_no_assembled_selectors`, `test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses`. On this copy all three are now GREEN and there is no other RED. PASS.

## Step 5 — Worker claims (5 re-verified)

1. REPORT "Final checks" diff stat: `3 files changed, 116 insertions(+), 14 deletions(-)`. → Re-verified `git diff --stat` on the copy: identical. TRUE.
2. REPORT "Final checks" `git diff | grep -c $'\r'` = 0. → Re-verified: 0. TRUE.
3. REPORT/pi.log final run `-n 4 tests/test_b101_doc_hygiene.py tests/test_b101_designer_recompute.py` = 101 passed. → Re-verified: `101 passed in 118.11s (0:01:58)`, EXIT=0. TRUE.
4. REPORT "Canon/id_registry (-n 0): 23 passed". → Re-verified: `23 passed in 7.74s`, EXIT=0. TRUE.
5. REPORT row 2 negative-control RED line: `changes beyond the inserted waits: changed at head: def test_save_check_mismatch_warns_but_still_writes; changed at head: def test_store_width_too_small_warns_live`. → Re-verified under mutation in the nc copy: exact match. TRUE.

(Extra, also TRUE: `-k "doc_ref_3 or doc_ref_4"` = 5 passed, `-k "d2"` = 4 passed, row 1 negative control = 3 RED with the three reported assertion lines.)

## Step 6 — Save the diff

`~/work/zq-fb/FB-PP04/CHECK.diff` saved as a copy of step 1's diff (199 lines, CR=0).

## Verdict

Steps 1–5 all pass.

CHECK_DONE FB-PP04 MECH-GO

## Orchestrator intent review (Opus, relevo-23)
GO. Both rows restore the scope each rule had before the fix round, and neither loosens a behaviour check.
- Row 1 (R-DOC-REF.3/.4): the CTX term "tracked text file" now excepts `REQUIREMENTS.md`, worded like the sibling term "repository document". Only R-DOC-REF.3 and .4 use the term. Before b5ca5b72, the definitions that must spell the retired paths lived in `.dev-flow/…/inc-16/01-requirements.md`, which these rows never scanned; the canon fold moved them into `REQUIREMENTS.md`. `_is_text_file_path` follows the definition (one clause plus a comment citing it). The EXEMPT table and its counts are unchanged. Control: drop the clause → 3_1, 3_2, 4_1 RED again.
- Row 2 (D-2 arm): docstrings are stripped from the module, class and function bodies on both sides before the comparison, alongside the existing wait-stripping. Every other statement still compares exactly. The new case shows a docstring-only pair gives no drift and that one changed `return` still names `helper`. Control: no-op transformer → the real-file arm RED again on U1's two re-cited docstrings (7c4fb817, TR-02).
- Residual (recorded): the D-2 arm still compares the whole of `tests/test_crc_designer_view.py` against the merge-base with main, so any later behaviour edit to that file on a branch turns it RED until the merge. That is the arm's documented design ("after the merge … passes trivially"), not this unit's to change.
