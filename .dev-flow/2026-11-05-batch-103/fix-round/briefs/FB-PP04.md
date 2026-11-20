# Unit FB-PP04 — two Front B regressions found by PR #214's CI (PP-04) [deepseek-v4-pro · medium]

Tree: `b103-fix-round` at **`d309c753`** (HEAD check mandatory). No agent edits `~/.claude/skills`.

## Fixed diagnosis (orchestrator, relevo-23; reproduced serially on this host: both RED at d309c753, GREEN at main 3afebf90)
1. `tests/test_b101_doc_hygiene.py::test_r_doc_ref_3_1_no_fast_dev_flow_path`, `::test_r_doc_ref_3_2_no_prototypes_path`, `::test_r_doc_ref_4_1_retired_workflow_named_only_as_retired` are RED: they report `REQUIREMENTS.md` lines 137–177. Cause: commit b5ca5b72 (canon fold) moved batch-101's CTX definitions block (it defines "retired folder", "retired-folder path" and the EXEMPT table, so it must spell those paths) from `.dev-flow/…/inc-16/01-requirements.md`, which the rows never scanned, into `REQUIREMENTS.md`, which they scan. "tracked text file" is used only by R-DOC-REF.3 and .4; the sibling term "repository document" already excepts `REQUIREMENTS.md` ("S0.3 owns it").
2. `tests/test_b101_designer_recompute.py::test_inc13_d2_touched_nodes_differ_from_base_only_by_the_waits` is RED: "changed at head: def test_save_check_mismatch_warns_but_still_writes; changed at head: def test_store_width_too_small_warns_live". Cause: TA U1 (7c4fb817) re-cited those two docstrings to active canon rows (TR-02); the arm compares whole statements, docstrings included, against the merge-base with main. Decision D-2 (batch-101 Inc 13) restricts behaviour changes to inserted waits; a docstring is not behaviour.

## Files you may edit
`REQUIREMENTS.md`, `tests/test_b101_doc_hygiene.py`, `tests/test_b101_designer_recompute.py`.

## Rows
| row | change | negative control (scratch copy) → RED |
|---|---|---|
| 1 | `REQUIREMENTS.md` line ~134, the CTX term "tracked text file": add `REQUIREMENTS.md` to its exceptions, worded like "repository document" (e.g. "…outside .dev-flow/ and docs/requirements/, and other than REQUIREMENTS.md (S0.3 owns it)."). Keep the fixed-width layout of that block. In `tests/test_b101_doc_hygiene.py`, `_is_text_file_path` also returns False for `"REQUIREMENTS.md"`; its docstring or a one-line comment cites the CTX term. Do not touch the EXEMPT table or the counts in `test_r_doc_ref_3_3`/`4_2`. | drop the `REQUIREMENTS.md` clause from `_is_text_file_path` → `test_r_doc_ref_3_1`, `3_2`, `4_1` RED |
| 2 | `tests/test_b101_designer_recompute.py`: before comparing, remove the docstring (the first statement when it is a string constant `Expr`) from the body of the module and of every `FunctionDef`, `AsyncFunctionDef` and `ClassDef`, in both base and head (a small `ast.NodeTransformer`, applied where `_StripInsertedWaits` is applied). Every other statement still compares exactly. Update the test's docstring: docstrings are excluded because they are not behaviour (D-2); later re-cites (TR-02) are allowed. Add one unit case next to the existing `_D2_BASE` cases: a docstring-only change gives no drift, and the same function with one changed non-wait statement still gives `changed at head`. | make the transformer a no-op → the real-file arm RED again (the two U1 docstrings) and the new docstring-only case RED |

## Nodes you may run (`timeout 300`)
- `-n 0`: the four RED nodes above; `tests/test_b101_doc_hygiene.py -k "doc_ref_3 or doc_ref_4"`; `tests/test_b101_designer_recompute.py -k "d2"`;
- `-n 4`: `tests/test_b101_doc_hygiene.py tests/test_b101_designer_recompute.py`;
- `-n 0`: `tests/test_requirements_canon.py tests/test_id_registry.py` (the canon still parses; your edit is in a definitions block, not a row).
