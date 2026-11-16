# Inc 9 E4 group B widget + A9 + I - implementer hand-back

Conductor: Sonnet (claude-sonnet-5-5) driving `deepseek/deepseek-v4-pro` through `opencode run`, one fresh session per unit. Base `30819c7e`. Files: `screens_directionb/patch_editor/bench_sheet.py` (new), `services/change_service.py`, `app/patch.py` (A9), `patch_editor/panel.py`, `patch_editor/layout.py` (I). No tests written. No push.

## Units

| Unit | Functions | DeepSeek outcome | Commit | Verification (rtx, HT-02 env, `s19_app.__file__` under `~/work/zq-e4-9-c9b/tree`) |
|---|---|---|---|---|
| U1 | class, BINDINGS, 2 messages, `__init__`, `_status`, `_state_for`, `_bench_row`, `check_action`, `bench_submit`, `register_bench_kinds` | delivered; fixed by conductor: the registered `editable` was a lambda (not idempotent as an object) -> module function `_editable` | 4bacb1a7 | 8 of 8 held (EX-A3, I1, K7, K4, submit) |
| U2 | `_enqueue`, `_start_next`, `_run_job`, `_job_done`, `_assign_result`, `_derive` | delivered with 3 defects fixed by conductor: `dict.popitem(last=False)` (TypeError); `self._running` collides with Textual's `MessagePump._running` (renamed `_active_job`; the job never started); `op_line` crashes on a bench row with no state (added `_paint` override creating the selected bench row's state) | 36acb17f | 18 of 18 held (summary, decode, preview Encoded / Refusal, record hold and Q1 order, F5 stale record, H6 stale summary) |
| U3 | `_bench_geometry`, `_reveal`, `action_edit/move/choose/cursor` | delivered | c3fb3bed | 14 of 14 held with U4 (K1, K2, K4, K5, page) |
| U4 | `action_page`, `action_leave_bench`, `_on_formula_escape`, `action_tool`, `_edit_changed`, apply handler | delivered | aabb98fe | 9 of 9 held (T1 edit, preview, T7 refusal, undo, tool) |
| U5 | `action_stage_record`, `record_staged`, `record_done`, selection, `show_page`, `set_document`, `_holds_entry` | delivered with 2 defects fixed by conductor: the selected row's "staged" request was wiped by the page-list rebuild (plan error, mine); a row whose staged decode merely equals its current counted as staged (`_staged_differs`, EX-F4 wants MAP 0 decodes) | 272daad6 | 18 of 18 held (A1, H5, L2, B1, F4, T1, Q2, R2-03, 75) |
| U6 | A1 `ChangeService.stage_record`, A2 record-stage handler (+ `_stage_bench_record`) | delivered | ac0d0562 | covered by the end-to-end run below |
| I | `PatchEditorPanel.__init__` (C-1), `LayoutMixin.compose` (C-4) | done by the conductor (two one-line edits) | 19804154 | end-to-end run |

End-to-end (`v7`, the real `S19TuiApp` on the DEFC case at 118x54): sheet is an `ArrayBenchSheet`, subtitle `enter edit · ↑↓ row · arrays open the bench`, MAP_DEF_0001 selected -> panel class `-bench`, values decoded; Enter -> bench focus; right, down -> cursor (1,1) and `▸-890` painted at (1,1); Enter -> op input; `100` + Enter -> edit of 1 cell, preview `Encoded`; alt+s -> 1 new entry, undo depth +1, status `Patch Editor: MAP_DEF_0001 staged as 1 value (32 B at 0x800070).`, bench edit cleared, `is_staged`, worker released: 16 of 16 held. Host load 3 at the run (no timing check was made; R-PE-BENCH.20/.28/.29/.82 timing and memory ATs are not run).

## Findings

- **F-W1 (Inc 8 seam defect, needs a ruling; not fixed: `sheet.py` is on the must-not-touch list).** `StagingSheet._paint` calls `row_line(item, widths, shown, pending, preview)` without the 6th argument `state`, so `KindOps.cells` and `KindOps.mark` always receive `None` for a bench row: the Current strip, the New count, Δ and the `◆` / `●` mark never show in the row (the end-to-end paint shows `12 values` for a decoded MAP). R-PE-BENCH.10 … .19 need `self.states.get(item.name)` passed as the 6th argument (one line in `sheet.py` `_paint`). Inc 8 tests cannot catch it (no kind with `cells` at its base).
- **F-W2 (Inc 9-internal).** `op_line` (view, owned by M9) assumes a non-None state; the widget guarantees one through its `_paint` override. A `state is None` guard in `op_line` would be safer.

## Deviations (orchestrator rulings P-061: all ACCEPTED)

1. Staleness keys: page jobs ("summary", "staged") are stale on a page or document change (`_pages`, `generation`); selected-row jobs ("decode", "preview") on a selection or document change (`_view`, `generation`); a record job on `generation` only. The graph's single counter would drop page summaries on every cursor move. Graph wording fix goes on the Inc 9 wording list.
2. `_slot` holds up to two requests of the selected row (one decode, one preview).
3. `_bench_geometry` imports `_chart_geometry`, `_grid_geometry`, `_grid_rows_shown` (private) from `definition_bench_view` (MINOR; the integrator should promote them to public names; the view file is M9's).
4. `state.preview = "encoding"` is the in-flight marker (`bytes_line` already renders it).
5. Added, not in the graph: `_status`, `_state_for`, `_bench_row`, `_edit_changed`, `_assign_result`, `_derive`, `_start_next`, `_enqueue`, `_bench_geometry`, `_reveal`, `_holds_entry`, `_staged_differs`, `_paint` (override), `_editable`, `_stage_bench_record` (A9 helper). All <= 40 lines.
6. A "summary" job dropped only because of a document change is requeued; a "decode" in flight at `set_document` is requeued.
7. The `_run_job` worker is `@work(thread=True, group="bench")`; an unexpected exception posts `result None` (treated as "no result").
8. E3S-07 span refusal and the busy / A2L / generation / changed-A2L order are in `_stage_bench_record`; nothing of the operand, edit or values is logged.

## Not run

Timing and memory ATs (R-PE-BENCH.20, .26, .28, .29, .82, LARGE), the E3S-08 `caplog` case, the masked-array case (E3S-07 first half), the key pilot on Windows Terminal (shift+arrows, alt+s, pageup/pagedown reach the widget: shown only under Textual Pilot). Tests of the widget belong to the tester branch.
