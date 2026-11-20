# Inc 2 — E1 slice: exact source and function census

Base `f44e8bc4266b6dead6ff24adef71fdb0b7b0154c`; E0 has no product/test/canon diff. Static census: `evidence-e1/direct-census.txt`. Requirements: `01-requirements.md`. Decisions/interfaces: `E1-rulings.md`. Baseline graph: `codewire/baseline.md`.

**Exact total: 4 SOURCE files, 7 function nodes (6 changed + 1 new), 4 data-contract classes (2 changed + 2 new), 0 stylesheets.** This reaches but does not exceed the cap. It cannot be cut responsibly by hiding app lookup inside the picker (E1-rulings D-1 B); adding app-prefill edits would exceed the cap and requires return to E0 rather than an unrecorded expansion.

## 1. Files and single owners

| Owner group | Source file | State | Function/data nodes |
|---|---|---|---|
| G-A (attach pipeline) | `s19_app/tui/app/file_load.py` | changed | 3 changed functions + 1 new function; 2 changed frozen dataclasses + 2 new frozen dataclasses |
| G-P (shared picker population) | `s19_app/tui/a2l_parameter_picker.py` | changed | 1 changed function |
| G-C (Check adapter) | `s19_app/tui/screens_directionb/check_editor.py` | changed | 1 changed function |
| G-PA (Patch adapter) | `s19_app/tui/screens_directionb/patch_editor/a2l_picker.py` | changed | 1 changed function |

Every shared edit has exactly one owner. Groups may be combined for capacity but may never write one another's files. Tests are not SOURCE and remain uncapped; each must map to a planned case.

## 2. Exact implementation slice

| Node | Function/data contract | File:base line | State | Requirements |
|---|---|---|---|---|
| A1 | `FileLoadMixin._start_a2l_load` | `file_load.py:728-804` | changed | R-A2L-REFRESH.030, .032, .033, .034 |
| A2 | `FileLoadMixin._a2l_attach_worker` | `file_load.py:806-841` (decorator included) | changed | R-A2L-REFRESH.029, .030, .033, .034, .037, .038 |
| A3 | `FileLoadMixin._prepare_a2l_attach_snapshot` | new beside A2 | new | R-A2L-REFRESH.029, .030, .036, .037, .038 |
| A4 | `FileLoadMixin._install_attached_a2l` | `file_load.py:848-916` | changed | R-A2L-REFRESH.031, .032, .035, .036, .037 |
| A5 | `A2LAttachRequest` | `file_load.py:42-53` | changed frozen data contract | R-A2L-REFRESH.030, .032 |
| A6 | `A2LAttachResult` | `file_load.py:56-64` | changed frozen data contract | R-A2L-REFRESH.029, .031, .032, .038 |
| A7 | `A2LAttachSnapshot` | new beside A5/A6 | new frozen data contract | R-A2L-REFRESH.029, .030, .031, .032, .036, .037 |
| A8 | `A2LPickerSnapshot` | new beside A5/A6 | new frozen data contract | R-A2L-REFRESH.029, .030, .037 |
| P1 | `A2LParameterPicker.set_parameters` | `a2l_parameter_picker.py:590-665` | changed | R-A2L-REFRESH.037; preserved R-PICKER-CORRECT.018/.019 |
| C1 | `CheckEditorPanel.set_a2l_parameters` | `check_editor.py:201-234` | changed | R-A2L-REFRESH.037; preserved R-A2L-REFRESH.012 |
| PA1 | `A2lPickerMixin.set_a2l_parameters` | `patch_editor/a2l_picker.py:25-45` | changed | R-A2L-REFRESH.037; preserved R-A2L-REFRESH.013 |

### Function behavior boundaries

- **A1** preserves all admission, recent, busy and sync decisions; after beginning the busy run it captures the expected pair and independent read-only image-map copy into A5, then starts exactly one existing worker. No widget mutation moves into the worker.
- **A2** preserves copy/parse/progress/failure boundaries and calls A3 after parsing. It dispatches one A6 carrying A7. No widget or live app-state read is added.
- **A3** is the only new preparation orchestration: call the existing enrichment/summary service once, derive the existing enrichment key and measurable names, call bulk describe independently for `check` and `patch`, and pack read-only generation-bound containers. It does not query mounted state and does not paint.
- **A4** performs preflight before any existing install side effect. A mismatch returns through the exact superseded outcome; a match preserves the current install order, uses `_replace_current_a2l`, installs A7's caches and `_accepted_a2l_picker_snapshots`, then runs the existing common refresh and outcome tail. A legacy A6 with `preparation=None` retains its current test-only compatibility path.
- **P1** adds one keyword-only optional prepared-definitions input. An equal non-`None` signature returns before consuming it; a real population consumes a supplied map without describing and otherwise retains today's direct-call behavior. `definitions`/`definitions_source` still describe the last real population.
- **C1/PA1** first check `is_mounted`; an unmounted panel keeps the legacy `a2l_data=None` call with omitted prepared definitions and performs no `self.app` read, mapping read or invalidation, preserving snapshot identity until mount. Mounted adapters read `_accepted_a2l_picker_snapshots` as a read-only `Mapping[str, A2LPickerSnapshot]`, select their own `check`/`patch` entry and pass it only on exact A2L-source identity and full-signature match. On either mismatch they replace the attribute on UI with an empty read-only mapping before using the existing route describe. They keep every existing document, selection, layout and preview side effect.

## 3. Read-only dependencies and unchanged context

| Symbol | Base location | Why no edit |
|---|---|---|
| `FileLoadMixin._on_a2l_attached` | `file_load.py:843-846` | Existing step-3 + deferred-install boundary already has the required thread/order role. |
| `FileLoadMixin._on_a2l_attach_failed` | `file_load.py:918-935` | Existing exception destination and exact failure text are reused by .038; its `request.copy` Workarea Files refresh at `:927-929` remains obligatory and may list the new copy, while current image and A2L-dependent state/views stay unchanged. |
| `A2lViewMixin._replace_current_a2l` | `a2l_view.py:732-769` | Existing single A2L writer and generation bump remain unchanged. |
| `A2lViewMixin._compute_a2l_enriched_tags` | `a2l_view.py:771-818` | Existing exact key match returns installed caches; no enrichment on main for an accepted direct snapshot. |
| `A2lViewMixin._refresh_a2l_dependent_views` | `a2l_view.py:1191-1261` | Existing sole common-refresh fan-out remains unchanged and UI-owned. |
| `A2lViewMixin.update_a2l_view` | `a2l_view.py:1263-1332` | Consumes installed caches and existing ranker/table seams; no contract edit. |
| `ChecksDiffMixin._prefill_check_editor` / `PatchMixin._prefill_patch_editor` | `checks_diff.py:79-101`; `patch.py:1841-1860` | Existing measurable-row and signature contracts already feed the adapters. |
| `describe_definitions` / `describe_definition` | `a2l_definition.py:588-879` | Public signatures and semantics preserved; Inc 1 owns its future index. |
| `enrich_tags_and_render` and its `render_a2l_view` summary seam | `services/a2l_service.py:10-27` | Existing pure worker-safe enrichment/summary path is reused unchanged; .038/2 injects at the summary renderer after real enrichment without editing the service. |
| `_BUSY_ACTIONS`, `step_busy`, `_progress_forwarder` | `app/shell.py:28-62,234-290,553-583` | Existing labels, timer and byte-progress bounds satisfy the design without edits. |
| `LoadedFile` | `models.py:10-73` | No type change; A1 copies only the needed map and never replaces the live object. |

## 4. Complete reverse census of changed functions

Source: executed AST census over every `s19_app/**/*.py` plus direct reads for callback-passing edges. Counts below are product-source call sites at the base, not guessed test coverage.

| Changed node | Real callers / consumers |
|---|---|
| A1 `_start_a2l_load` | Ordinary direct route `file_load.py:625`; confirmed project replacement `file_load.py:713`. Both construct the same request/worker path. |
| A2 `_a2l_attach_worker` | Started only by A1 at `file_load.py:801`; Textual `@work(thread=True, group="a2l_load")` supplies execution. |
| A3 `_prepare_a2l_attach_snapshot` | New; sole planned caller A2. No other route may call it silently in Inc 2. |
| A4 `_install_attached_a2l` | Callback passed by `_on_a2l_attached` through `call_after_refresh` at `file_load.py:846`; the AST's 0 syntactic calls are not an absence. Legacy direct test callers are separately retained in `tests/test_b102_a2l_refresh.py:200-203,393-420`. |
| P1 `set_parameters` | Check adapter `check_editor.py:223`; Patch adapter `patch_editor/a2l_picker.py:42`. Direct unit/test uses retain existing behavior. |
| C1 `CheckEditorPanel.set_a2l_parameters` | `_prefill_check_editor` at `checks_diff.py:101`; its product callers are common refresh `a2l_view.py:1251`, screen activation `checks_diff.py:233` and navigation `navigation.py:203`. |
| PA1 `A2lPickerMixin.set_a2l_parameters` | `_prefill_patch_editor` at `patch.py:1860`; its product callers are common refresh `a2l_view.py:1252` and navigation `navigation.py:198`. |
| A5/A6 data contracts | A5 constructed only by A1 in product; A6 constructed only by A2 in product. Existing direct constructors in `tests/test_b102_a2l_refresh.py` use the defaulted compatibility arm. |
| A7/A8 data contracts | A7 produced only by A3/consumed by A4; A8 produced only by A3/consumed by C1/PA1/P1 through `_accepted_a2l_picker_snapshots`, a read-only `Mapping[str, A2LPickerSnapshot]` invalidated on generation/signature or source mismatch. |

Related unchanged calls that constrain the design: `_replace_current_a2l` has five product sites (`direct-census.txt:34`); `_compute_a2l_enriched_tags` has twelve (`:35`); common refresh has four transition callers (`:36`); enrichment has six product sites (`:43`). Inc 2 changes none of those owners or routes.

## 5. Test ownership and retarget list (E4 only)

| Test file | Planned state | Cases / reason |
|---|---|---|
| `tests/test_alp_inc2_a2l_attach.py` | new | All 34 new requirement alternatives and 3 AT items from `02-test-cases.md`; no file is created at E1/E3. |
| `tests/test_b103_picker_model.py` | changed | Extend the shared describe spy to the real worker binding as well as existing picker/definition bindings; keep all four .018 and both .019 alternatives discriminating. |
| `tests/test_b100_session_reset.py` | changed | Declare `_accepted_a2l_picker_snapshots` in the session census as a read-only mapping reference replaced on accepted direct attach, emptied on mounted generation/signature/source mismatch and left untouched by unmounted calls. |
| `tests/test_b103_picker_editor.py` | caller reference/re-run | Read the existing unmounted Check caller at `:846-870` for .037/5; preserve its legacy `a2l_data=None` behavior and add no edit here unless E4's independent test plan requires a regression pin. |
| `tests/test_b100_workers.py` | re-run only | Existing route, key, byte-progress and `case_06` nodes; the slow large node is not run in E1. |
| `tests/test_b100_a2l_progress.py` | re-run only | Existing byte-progress/parser-equivalence arms. |
| `tests/test_b103_a2l_refresh.py` | re-run only | Preserved refresh/generation/thread/stale-load alternatives. |
| `tests/test_b102_a2l_refresh.py` | re-run only | Legacy constructors/default compatibility and existing direct-refresh behavior. |
| `tests/test_b103_inc8_s2_picker_definitions.py` | re-run only | Definition/source identity, equal-signature no-op and changed-generation replacement. |
| `tests/test_b103_inc8_s2_sheet_rows.py` and other picker consumers selected by E4 census | re-run only | Zero describes on filter/page and exact current sheet formats. |

E4 must print collected node IDs and per-arm verdicts, assert the expected arm count before execution and paste every negative-control verdict separately. An unresolving planned node, an empty parameter set or a spy watching only the old call site is RED/BAD, never a pass.

## 6. Exclusions and return-to-E0 triggers

No edit is planned in `s19_app/tui/app/a2l_view.py`, `checks_diff.py`, `patch.py`, `mac_view.py`, `loaded_state.py`, `project_load.py`, `core.py`, `shell.py`, `models.py`, `a2l_definition.py`, `a2l.py`, any service, any stylesheet or any interface re-export file.

If implementation requires any of those files, a second app-global snapshot channel, per-page describes or more than four SOURCE files, E1's slice is falsified: stop and return to E0. Do not exceed the budget by absorbing an adapter into an unrelated file or by moving UI work into the worker.
