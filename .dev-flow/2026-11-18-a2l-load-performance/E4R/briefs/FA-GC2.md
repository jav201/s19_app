# Unit FA-GC2 — freeze instead of a UI-thread full collection; GC re-enabled on every attach end [deepseek-v4-pro · high; Opus diff review]

Tree: `alp-e4r` at **`<sha after FA-GC2T integrated and the orchestrator's RED run of the case_06 pause arm>`** (HEAD check mandatory). Rules: `FB-common.md` + `FA-common-laptop.md`. No agent edits `~/.claude/skills`.

## Fixed design (DX-F3 candidate (a)+(b), R5-F3, R5-F5; FA-DESIGN §3.4)
- (a) `walk = None` is already in the tree (FA-GC1). Check with `grep -n "walk = None" s19_app/tui/a2l_definition.py`; if it is absent, STOP.
- (b) At the three install sites, `gc.collect(); gc.enable()` becomes `gc.freeze(); gc.enable()`.
  - Freeze moves the surviving heap (the loaded payload) to the permanent generation, so later collections do not traverse it. DX measured 0.0000 s, with a worst later pause of 0.2 ms.
  - The workers' `gc.disable()` (`file_load.py:929`, `:1063` at 1dd52089) stays as it is.
- The attach install's `except BaseException:` branch re-enables GC before `_busy_fail`.

## Files you may edit
`s19_app/tui/app/file_load.py`, `s19_app/tui/app/loaded_state.py`, `s19_app/tui/app/project_load.py`.

## Rows
| row | change | negative control (scratch copy) → RED node |
|---|---|---|
| 1 | `file_load.py` `_install_attached_a2l` (~1222-1223 at 1dd52089): `if not gc.isenabled(): gc.freeze(); gc.enable()`. Rewrite the D-13 comment accurately: the old one claims "never inside the commissioned window". | restore `gc.collect()` → `test_r_a2l_refresh_052_install_runs_no_full_collection[attach]` |
| 2 | `loaded_state.py` (~892-894): the same change. | restore → `[image]` arm |
| 3 | `project_load.py` (~1823-1825): the same change. | restore → `[project]` arm |
| 4 | `_install_attached_a2l` `except BaseException:` (~1249-1251 at 1dd52089): `if not gc.isenabled(): gc.enable()` before `self._busy_fail(...)`. | remove it → `test_r038_install_exception_reenables_gc` |
| 5 | At each of the three sites, one `self.logger.info("A2L load GC: frozen=%d seconds=%.3f", gc.get_freeze_count(), elapsed)` around the freeze (R5-F5: the pause is now recorded). Match the style of the neighbouring log lines. | n/a (log only; show the line in a test log excerpt) |
| 6 | **Stop rule.** Run `test_r_a2l_refresh_053_reloads_do_not_accumulate_objects`. If it is RED with `walk = None` present, the parse payload holds cycles and freeze would leak. STOP: revert rows 1–3 in your tree, write a census to REPORT.md (types of the objects that grow per reload: `collections.Counter(type(o).__name__ for o in gc.get_objects())` diff between loads 2 and 5, top 15) and end with `UNIT_DONE FA-GC2 STOPPED`. | — |

## Nodes you may run (`timeout 300`)
- `-n 0`: r038, r043, the R-A2L-REFRESH.051/.052/.053 arms of FA-GC2T (not the `slow` one);
- `-n 4 -m "not serial_timing and not slow"` on `tests/test_alp_inc2_a2l_attach.py tests/test_alp_inc3_snapshot_parity.py`;
- `tests/test_b100_busy.py -k "a2l_deferred_install_raise"` and `tests/test_b100_session_reset.py` (regression; `-n 4`).

## Orchestrator after integration (quiet laptop)
- Run the `slow` pause arm (expect GREEN).
- Run the case_06 attach with RSS sampled over 5 reloads (record maxrss).
- Re-measure G8 `test_qc_tm_10b_1` ×3.
- Opus reviews the diff for the process-global effects of freeze.
