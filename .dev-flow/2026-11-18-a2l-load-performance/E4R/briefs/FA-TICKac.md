# Unit FA-TICKac — load workers get a fixed description; the project worker runs with the collector disabled [deepseek-v4-pro · medium]

Tree: `alp-e4r` at **`b5bc470b`** (FA-D11b integrated) (HEAD check mandatory). Rules: `FB-common.md` + `FA-common-rtx.md` (this unit runs on rtx). No agent edits `~/.claude/skills`.

## Fixed diagnosis (FA-TICK report, measured on the quiet reference host; facts re-grepped at b5bc470b, HT-13)
- **(a) Admission stall.** Textual 8.2.8 `work()` (`textual/_work_decorator.py:127-138`) builds a debug description by calling `repr()` on every positional and keyword argument when `description=` is not given. The three load workers carry no `description=`:
  - `s19_app/tui/app/file_load.py:919` `@work(thread=True, group="a2l_load")` on `_a2l_attach_worker(self, request: A2LAttachRequest)`;
  - `s19_app/tui/app/file_load.py:1861` `@work(thread=True, exclusive=True, group="load")` on `_start_load_worker(self, path, a2l_files=None, *, gen, sync_project=True, context: Optional[FileLoadRequest] = None)`;
  - `s19_app/tui/app/project_load.py:1419` `@work(thread=True, group="project_load")` on `_project_load_worker(self, request: ProjectLoadRequest)`.
  - The request dataclasses (`A2LAttachRequest` file_load.py:46, `FileLoadRequest` :123, `ProjectLoadRequest` project_load.py:85) are `@dataclass(frozen=True)` with the generated `__repr__`. `FileLoadRequest` carries the whole parsed A2L payload, so on the case_06 image route the UI thread spends 3.6–4.0 s in that `repr` before the worker starts.
- **(c) Worker GC.** `_a2l_attach_worker` calls `gc.disable()` at entry (file_load.py:929, D-13). `_project_load_worker` (project_load.py:1420) does not: its A2L parse and payload run with the collector enabled, until `_prepare_a2l_attach_snapshot` disables it (file_load.py:1063). On case_06 that is 9–11 gen2 collections of 0.07–0.55 s on the worker thread, each one holding the GIL and starving the UI tick.
  - Outcomes that re-enable the collector today: worker failure (project_load.py:1429, :1436), superseded (`_reject_superseded`, :1699), install success (:1822-1825, the one logged collection), install exception (:1871).
  - **Gap once (c) disables at entry:** the refusal outcome `_on_project_loaded` (:1639-1642, `prepared.refusal is not None` → `end_busy` → `return`) re-enables nothing. Today GC is never disabled before a refusal; after (c) it is.

## Requirement rows (in your tree, `REQUIREMENTS.md`)
- R-A2L-REFRESH.040 / .041 (image+A2L and project load total duration on the reference host): the admission `repr` is part of every such load's total.
- R-A2L-REFRESH.049 (attach keys acknowledged while the request snapshot is captured on the UI thread): the attach worker is admitted on the UI thread right after the capture.
- R-A2L-REFRESH.050 (each due 50 ms UI tick no more than 100 ms late during post-parse preparation).
- R-A2L-REFRESH.051: "When a direct A2L attach, image load or project load ends with any outcome, the system shall leave the cyclic garbage collector enabled."

## Files you may edit
`s19_app/tui/app/file_load.py`, `s19_app/tui/app/project_load.py`, `tests/test_alp_inc3_snapshot_parity.py`, `tests/test_alp_inc2_a2l_attach.py`.

## Rows
| row | change | negative control (scratch copy) → RED node |
|---|---|---|
| 1 | Add `description=` to the three decorators, fixed strings: `"A2L attach worker"` (file_load.py:919), `"file load worker"` (:1861), `"project load worker"` (project_load.py:1419). Keep every other decorator argument. One comment line above each: the fixed description keeps Textual from calling `repr()` on the request (which carries the parsed A2L) on the UI thread. | per site: drop that site's `description=` → the matching arm of row 2 RED |
| 2 | New tests (ordered here):<br>- in `tests/test_alp_inc3_snapshot_parity.py`: `test_r_a2l_refresh_040_load_workers_never_repr_their_request`, parametrized `["image", "project"]`, `ids=["R-A2L-REFRESH.040/2", "R-A2L-REFRESH.041/3"]`. `image`: load `img1`, `_typed_attach` the old A2L, then `_drive_typed_no_assert(app, pilot, img2)` (the image+A2L route, as `test_r043_install_exception_reenables_gc` drives it). `project`: `_seed_project3(app.workarea, "proj_a", a2l=old, image=img1)` + `_load_project`.<br>- in `tests/test_alp_inc2_a2l_attach.py`: `test_r_a2l_refresh_049_attach_worker_never_reprs_its_request` (one `_typed_attach`).<br>- Oracle: before the load, `monkeypatch.setattr(<RequestClass>, "__repr__", counting_repr)` on `FileLoadRequest`, `A2LAttachRequest` and `ProjectLoadRequest` (import them from `s19_app.tui.app.file_load` / `project_load`); `counting_repr` appends the class name and returns a short constant. After the success outcome: the list is `[]`, and the load reached its success outcome (assert it the way the neighbouring tests do). Failure messages name the row (R-A2L-REFRESH.040 / .041 / .049) and say the worker admission rendered the request. | row 1's control |
| 3 | In `_project_load_worker`, call `gc.disable()` as the first statement of the body (before the outer `try:`), as `_a2l_attach_worker` does at file_load.py:929. Replace the D-13 comment block of the attach worker's style above it: the whole project worker (parse, payload, preparation) runs with the cycle collector disabled; every outcome re-enables it (R-A2L-REFRESH.050/.051). | remove that `gc.disable()` → row 5 RED |
| 4 | In `_on_project_loaded`, the refusal branch (`if prepared.refusal is not None:`): add `if not gc.isenabled(): gc.enable()` before `self.end_busy(...)`, with a one-line D-13 comment. | remove it → row 6 `refusal` arm RED |
| 5 | New test in the parity file: `test_r_a2l_refresh_050_project_worker_runs_no_collection` (not parametrized). Append a `gc.callbacks` hook (removed in `finally`) that records `threading.current_thread().name` for every `"start"` phase. Project load as in row 2 `project`. Assert: no recorded collection ran on a thread other than the main thread between submit and the outcome. (The install's one logged collection runs on the main thread and is allowed.) Docstring cites R-A2L-REFRESH.050 and D-13. | row 3's control: RED (the worker collects at least once while it parses) |
| 6 | New test in the parity file: `test_r_a2l_refresh_051_project_outcomes_gc_enabled`, parametrized `["refusal", "worker-failure", "superseded"]`, `ids=[f"R-A2L-REFRESH.051/{i}" for i in range(4, 7)]`. `refusal`: a project whose only file is an unreadable A2L, or no supported file (the "No supported files in project" outcome; see `tests/test_b100_busy.py:1936-1989` for a fixture). `worker-failure`: monkeypatch `app._prepare_project_load` to raise `ValueError`. `superseded`: `_arm_stale_producer(monkeypatch, a2l_delta=1)` (the parity file's helper). After the outcome: `gc.isenabled()` is True. | row 4's control (refusal arm) |

## Nodes you may run (`timeout 300`, `-n 0` unless said)
- the new nodes of rows 2, 5, 6;
- `test_r_a2l_refresh_051_project_success_gc_enabled`, `test_r043_install_exception_reenables_gc`, the `test_r043_*`, `test_r048_*` and `test_r_a2l_refresh_052_*` nodes of the parity file; `test_r_a2l_refresh_051_attach_outcomes_gc_enabled`, `test_r038_install_exception_reenables_gc` of the inc2 file;
- `-n 4 -m "not serial_timing and not slow"` on `tests/test_alp_inc3_snapshot_parity.py`, then separately on `tests/test_alp_inc2_a2l_attach.py`;
- `-n 4`: `tests/test_b100_busy.py tests/test_b100_load_question.py tests/test_b100_session_reset.py` (regression: busy/outcome lines of the three routes).
- Never run a `slow` node.

## Known REDs that are not yours
None expected in your nodes. Report any RED and go on.
