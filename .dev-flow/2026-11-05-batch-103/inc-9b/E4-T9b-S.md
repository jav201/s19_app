# Inc 9b E4 - T9b-S hand-back (tester, Sonnet)

File: `tests/test_b103_inc9b_s.py` (6 nodes). Base: `bcb22640` (P9b tip, no Inc 9b code). Runner: rtx, HT-02 env, `-n 2`, `timeout 300`, `s19_app.__file__` = `<runner>/work/zq-e4-9b-t9bs/tree/s19_app/__init__.py`, `uptime` load 1.88 (not a timing run; none of these nodes is timing-decided here).
Command: `pytest -p no:cacheprovider -n 2 -q -rf -v tests/test_b103_inc9b_s.py` -> `5 failed, 1 passed in 33.43s` (one complete run).

| Node | Case | RED on base | Kind |
|---|---|---|---|
| `test_r_pe_bench_98_2_the_stepped_stage_writes_the_base_bytes_and_yields_between_write_and_refresh` | R-PE-BENCH.98/2 | `AssertionError: the ledger already held 1 row(s) when the entry appeared: the write and the refresh ran in one call` (bytes check (a) passes first) | assertion (behaviour absent: stepping) |
| `test_r_pe_bench_101_3_..._a2l_unloaded_returns_to_the_idle_look` | R-PE-BENCH.101/3 | `did not settle within 5 s: the busy cue stage VAL_BLK_DEF_0001 on the painted border` | assertion on precondition (cue absent); the 0.3 s idle bound is never reached on base |
| `test_r_pe_bench_101_4_..._session_action_returns_to_the_idle_look` | R-PE-BENCH.101/4 | same | same |
| `test_r_pe_bench_106_1_an_undo_between_two_refresh_steps_...` | R-PE-BENCH.106/1 | `the Undo was not between steps: the ledger was already refreshed when the entry appeared` | assertion (stepping absent) |
| `test_r_pe_bench_106_2_an_apply_between_two_refresh_steps_...` | R-PE-BENCH.106/2 | same, for Apply | assertion (stepping absent) |
| `test_r_pe_def_62_and_llr_081_3_the_synchronous_refresh_callers_repaint_in_the_same_call` | regression R-PE-DEF.62 / LLR-081.3 | passes on base (guard of existing behaviour) | GREEN on base, by design |

0 failures by import error. Coverage: 5 of 5 S cases + the regression; none uncovered by a node.
Holes: (1) the final-state oracle of .106/1-2 (settled digest == full refresh digest) needs GREEN to run; the "later steps keep the first step's serialization" mutant is the integrator's/mutant worker's to confirm. (2) Regression covers `_refresh_patch_history_view` (Undo, Redo buttons) synchronously; the other callers (`app/patch.py` action_requested, change_file_selected, `loaded_state.py:675`, `project_load.py:1029`, `panel.py:750`) are not driven. (3) The `call_after_refresh` negative control for .98/.99 is not run (needs product code). (4) .101/3-4 idle latency is measured from the app's `set_status` stamp to the first painted idle top border at 0.01 s polling; load-sensitive, the 0.3 s bound is the case's. (5) `undo`/`redo` button `disabled` is driven by the document source, not the depths, so it is not asserted.
Assumptions to confirm at GREEN: the idle look = row text has `STAGING SHEET`, no `BUSY`, corner fg != `Style.parse(EDIT).color`; the cue title holds `BUSY` and `stage <name>`.
