# CHK G3a — verdict: GO-WITH-NOTES

| # | Check | Evidence |
|---|-------|----------|
| 1 | Diff hygiene | `diffs/G3a.diff`: files=1 (`tests/test_b100_busy.py`, allowed), CR=0, skipadd=0, defs removed-not-readded: none, no sleep/home/LAN tokens. |
| 2 | Intent | Row 1: raise injection `_apply_loaded_file` -> `_apply_prepared_load` (seam `_install_prepared_project` calls; except at project_load.py:1690-1691); assertion unchanged. Rows 2/3: census `load_a2l_from_path` -> `_start_a2l_load`, `_start_load_worker` -> `_complete_prepared_load`; counts (24/17) and asserts unchanged. No loosening. Note: `_seam_events` now also unwraps `call_after_refresh` (small broadening of the AST helper; needed for deferred end_busy; counts still match). |
| 3 | GREEN | 3 nodes `-n 0`: `3 passed in 10.28s`; base had 3 FAILED. Whole file `-n 4`: `117 passed in 199.00s` (worker's 1 flake `test_at_b100_17...` did not recur). No GREEN turned RED. |
| 4 | Negative controls (re-applied both) | Row 1: `_busy_fail` -> `raise` at project_load.py:1691 -> `AssertionError: [] == ['Loading project P failed']`. Rows 2+3: `_busy_begin_action("a2l_load",..)` at file_load.py:787 -> `gen = 1` -> both RED (`[('_start_a2l_load','begin','a2l_load',None,...)]`). |
| 5 | Laws (6 files, serial) | `3 failed, 112 passed, 2 skipped`: only `test_r_tst_070_2`, canon two-shall, address census = identical to laws.txt base-red set (all allowed for G3a). No other law RED. |
| 6 | Worker claims | Verified: HEAD/branch diff stat 14+/12-, CR=0, mutation lines (1691, 787), RED lines for rows 1-3, 3 passed, scratch/ empty. False claims: none. REPORT.md was complete (not thin). |

Notes: (a) the `_start_load_worker` -> `_complete_prepared_load` end re-pin (CENSUS) is not covered by either named negative control (the controls hit begin a2l_load and project fail); it is unmutated-tested. (b) pre-existing docstring "24 sites in 12 functions" vs 14 functions left as is (worker flagged). Copies on rtx deleted.
