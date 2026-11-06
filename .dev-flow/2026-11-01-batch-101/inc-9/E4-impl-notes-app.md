# Inc 9 — E4 implementation notes (G2 app and Builder)

Batch 2026-11-01-batch-101, increment 9. Implementer G2 app and Builder (E4). Files touched: `s19_app/tui/app.py`, `s19_app/tui/flow_screens.py`, `docs/user-guide/ch18-flow-execution.md`, `docs/user-guide/DOSSIER.md`.

## 1. Functions changed

| File | Function | Graph node | Change |
|---|---|---|---|
| `s19_app/tui/app.py` | `S19TuiApp.on_flow_execution_panel_external_step_confirmed` | same name | `mode="sequential"` → `mode=CHAIN_RUN_CONFIRM_RERUN` (I-1); the constant imported locally beside `ChainSpec` and `run_chain_set`. Nothing else changed. |
| `s19_app/tui/app.py` | `S19TuiApp.on_flow_builder_panel_save_requested` (nested `_do_save`) | same name | `save_flow_json(event.flow, raw_name, project_dir, workarea_root=self.workarea)` inside `try`; `except WorkareaContainmentError` → `self.set_status("Flow not saved - the project's flows folder is a link or is outside the work area.")` and return, without `mark_saved` (I-2, I-3). |
| `s19_app/tui/app.py` | `S19TuiApp.on_flow_execution_panel_save_requested` | same name | `save_chain_set(chain_set, event.raw_name, project_dir, workarea_root=self.workarea)` inside `try`; `except WorkareaContainmentError` → `self.set_status("Chain set not saved - the project's flowsets folder is a link or is outside the work area.")` and return, without `mark_saved` and without `_prefill_flow_execution_sets()` (I-2, I-3). |
| `s19_app/tui/flow_screens.py` | module docstring | `[Doc: flow_screens module docstring]` | Rewrote the two sentences to the measured edges (A16-4, D-8): the panels post messages and never call the executor; the module reads `services/flow_model` (block and flow data types and constants) and `services/flow_persistence_service` (wire serializer and loader for copy and paste, and the unsafe-ref finding code); no `docs/architecture.md` section is cited for an import rule. |
| `docs/user-guide/ch18-flow-execution.md` | — (doc) | not a code node | The confirm's report "records the mode as *sequential* (finding F-45)" → "records the mode as *confirm re-run*". |
| `docs/user-guide/DOSSIER.md` | — (doc) | not a code node | Rows F-45 and F-46 marked `· fixed in 1.0.0`. |

No other `app.py` change and no module-level change: `WorkareaContainmentError` was already imported at module level, and `CHAIN_RUN_CONFIRM_RERUN` is imported locally inside the confirm handler.

## 2. Deviations from the graph (each with its reason) — none

## 3. Open questions for the integrator

- DOSSIER rows F-45 and F-46 are now marked `fixed in 1.0.0`. The integrator must extend the pinned set `_FIXED` in `tests/test_b101_help_legend_docs.py` with `"F-45"` and `"F-46"` (its count assertion `len(_FIXED) == 11` becomes `13`), as the group brief directs (I do not edit that test).

## 4. Checks

Command (run once per edited source file; the two docs files are Markdown and not byte-compiled):

```
<HOME>/anaconda3/envs/s19env/python.exe -m py_compile s19_app/tui/app.py
<HOME>/anaconda3/envs/s19env/python.exe -m py_compile s19_app/tui/flow_screens.py
```

Output: each command exited 0 with no stdout/stderr (compile clean).
