# Unit FA-GC2R — one install collection kept and logged [deepseek-v4-pro · medium]

Tree: `alp-e4r` at **`02049233`** (= 459e03f3, which holds the operator D-GC = A rows (FA-REQ3: R-A2L-REFRESH.052 amended, .054 new), + the unchecked FA-C7b diff committed locally while its report and check run; speculative, P-202 O2) (HEAD check mandatory). Rules: `FB-common.md` + `FA-common-rtx.md` (this unit runs on rtx). No agent edits `~/.claude/skills`.

## Fixed design (GC-REDESIGN §4 option (d); operator D-GC = A; R5-F3, R5-F5; freeze rejected)
- `gc.freeze()` is NOT used anywhere: it keeps Textual UI cycles alive and turns R-A2L-REFRESH.053 RED (1.288 > 1.10). The workers' `gc.disable()` (`file_load.py:929`, `:1063`) stays as it is.
- Each of the three install sites keeps exactly one `gc.collect()`, after `_refresh_a2l_dependent_views()`, and now times and logs it.
- Requirement text (in your tree, `REQUIREMENTS.md`): R-A2L-REFRESH.052 "When a direct A2L attach, image load or project load installs its result, the system shall run at most one full cyclic garbage collection." R-A2L-REFRESH.054 "When the system completes an install's full cyclic garbage collection, the system shall log the collection's duration in seconds."

## Files you may edit
`s19_app/tui/app/file_load.py`, `s19_app/tui/app/loaded_state.py`, `s19_app/tui/app/project_load.py`, `tests/test_alp_inc2_a2l_attach.py`, `tests/test_alp_inc3_snapshot_parity.py`.

## Rows
| row | change | negative control (scratch copy) → RED node |
|---|---|---|
| 1 | Already in your tree (FA-GC2 row 4): `file_load.py` `_install_attached_a2l` `except BaseException:` (~1249-1254) re-enables GC before `self._busy_fail("a2l_load", gen)`. Do not change it; run its control only. | remove the `gc.enable()` there → `test_r038_install_exception_reenables_gc` RED |
| 2 | At `file_load.py` ~1221-1223, `loaded_state.py` ~892-894, `project_load.py` ~1823-1825: inside the existing `if not gc.isenabled():`, replace `gc.collect()` + `gc.enable()` with: `gc_started = time.perf_counter()`; `unreachable = gc.collect()`; `gc.enable()`; `self.logger.info("A2L load GC: route=%s unreachable=%d seconds=%.3f", "<route>", unreachable, time.perf_counter() - gc_started)` with `<route>` = `attach` (file_load), `image` (loaded_state), `project` (project_load). `gc` and `time` are already imported in all three modules; `self.logger` is the `s19tui` logger. Rewrite the D-13 comment above each site in two lines: the one deliberate full collection of the load's garbage, after the preserved refresh, logged (R-A2L-REFRESH.052/.054); freeze rejected (GC-REDESIGN, R-A2L-REFRESH.053). Do not move the call. | per site: delete that site's `self.logger.info(...)` → the matching arm of row 3 RED |
| 3 | Re-pin `test_r_a2l_refresh_052_install_runs_no_full_collection` (attach arm in the inc2 file; `[image, project]` arms in the parity file; keep test names and parametrize ids). Keep the `gc.collect` spy. Add a spy on `app.logger.info` (the `s19tui` logger has `propagate=False`, so `caplog` cannot see it) that records the messages starting with `"A2L load GC:"` and their route argument. Assert: `len(product_collects) <= 1`; `len(product_collects) == len(gc_log_lines)`; every logged route equals the arm. Docstrings cite the amended R-A2L-REFRESH.052 and the new .054 (E4R, operator D-GC = A); failure messages name the row they check. | (i) at the site, call `gc.collect()` twice → RED (`2 > 1`); (ii) row 2's log deletion → RED (`1 != 0`) |
| 4 | Delete `test_r_a2l_refresh_052_case06_no_mainthread_gc_pause` from the inc2 file (its 0.25 s bound came from the superseded `.052` text). Remove imports or helpers that only it used (check with grep; keep anything else uses). Write in REPORT.md: "retired, TR-01: superseded by amended R-A2L-REFRESH.052 (operator D-GC = A)". | n/a (deletion; `--collect-only -q -m slow tests/test_alp_inc2_a2l_attach.py` must not list it) |
| 5 | **Stop rule.** Run `test_r_a2l_refresh_053_reloads_do_not_accumulate_objects` unchanged. If it is RED, STOP: write its counts and the `collections.Counter(type(o).__name__ for o in gc.get_objects())` growth between loads 2 and 5 (top 15) to REPORT.md, and end with `UNIT_DONE FA-GC2R STOPPED`. Do not loosen it. | — |

## Nodes you may run (`timeout 300`)
- `-n 0`: `test_r038_install_exception_reenables_gc`, the `test_r043_*` nodes, the R-A2L-REFRESH.051 arms, the `.052` spy arms (rows 2–3, both files), `.053`;
- `-n 4 -m "not serial_timing and not slow"` on `tests/test_alp_inc2_a2l_attach.py`, then separately on `tests/test_alp_inc3_snapshot_parity.py` (their combined run exceeded 300 s before);
- `-n 4`: `tests/test_b100_busy.py -k "a2l_deferred_install_raise"` and `tests/test_b100_session_reset.py` (regression);
- `-n 0`: `tests/test_suite_hygiene.py -k "040 or 041 or 002"` (timing/marker census after the deletion).
- Never run a `slow` node.

## Known REDs that are not yours
None expected in your nodes once FA-C7b's diff is in the tree. If a `.037` adapter arm or a picker-model node is RED, report it and go on (it belongs to FA-C7b).

## Orchestrator after integration (quiet laptop; not the worker)
- Attach case_06 once; record the `A2L load GC: … seconds=` line as information (about 1.07 s expected; not a gate).
- G8 (`test_qc_tm_10b_1`) is re-measured ×3 (before: 1.80 s against 1.0 s, P-216); FA-DESIGN §3.10's freeze hypothesis is withdrawn.
