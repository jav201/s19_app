# Increment I3 (FINAL) — TUI operations view (HLR-004 / LLR-004.1–004.4) — Phase 3 close

Batch: 2026-06-11-batch-08 · Agent: software-dev · Date: 2026-06-11
Predecessors: I1 (operations package, commit 0b1999e), I2 (`run_operation` service, commit 601b576).

## 1. What changed

The HLR-004 operations view closes Phase 3: a new `OperationsScreen` modal (the `SelectVariantScreen` ListView/index-resolution pattern + `ReportViewerScreen` result-area shape) lists the registry's three operations `(operation_id, title)` in registry order, executes the selected one EXCLUSIVELY through `operation_service.run_operation` synchronously on the UI thread (LLR-004.4 — no `@work`), and presents the `OperationResult`'s `status` + `notes` in `#operation_result_status` plus the hex render of `result.output.mem_map` in `#operation_result_hex` using the LLR-004.3 PINNED argument tuple (`focus_address=None, row_bases=None, highlight=None, mac_highlight_addresses=None, max_rows=MAX_HEX_ROWS`). `S19TuiApp` gains the `Binding("x", "operations_view", "Operations", show=False)` and an orchestration-only `action_operations_view` (no-file guard → one status line, no screen, no service; otherwise enumerate options via `list_operation_ids`/`get_operation` and push the modal with `self.current_file`). The rail is untouched (8 items, LLR-004.1). Three pilot tests (TC-010/011/012) land in `tests/test_tui_operations_view.py`.

## 2. Files modified (4 — within the ≤5 cap; matches the C-5 increment-3 plan)

| File | Change | Purpose |
|------|--------|---------|
| `s19_app/tui/screens.py` | +158 lines (appended class + 3 imports) | `OperationsScreen`: list/select/execute/show-result modal; calls `operation_service.run_operation` (module-attribute lookup, seam-patchable); pinned hex render; registry `KeyError` → app status line, never a crash |
| `s19_app/tui/app.py` | +46 lines | `OperationsScreen` + `operations` imports, `x` binding (after `t`), `action_operations_view` with the no-file guard idiom; no operation/render logic, no `@work` |
| `s19_app/tui/styles.tcss` | +29 lines | `#operations_dialog` / `#operations_list` / `#operation_result_status` / `#operation_result_hex_scroll` block next to the report-viewer block; Calm Dark tokens only, no new hue |
| `tests/test_tui_operations_view.py` | NEW, 288 lines, 3 test functions | TC-010 (listing + binding + no-file guard, 7 assertions), TC-011 (placeholder result + `operation_resolver` seam stub observed, 5 assertions), TC-012 (live widget `.plain` vs independent pinned-args baseline, 4 assertions) |

`s19_app/tui/services/__init__.py` NOT touched (the C-5 conditional 11th file was not needed — screens import `from .services import operation_service` directly).

## 3. How to test

```bash
python -m pytest -q tests/test_tui_operations_view.py        # TC-010..TC-012
python -m pytest -q tests/test_operations.py                  # I1/I2 regression
python -m pytest -q tests/test_tui_variants.py tests/test_tui_report_view.py tests/test_tui_patch_editor_v2.py
python -m pytest -q -m "not slow"                             # lean suite
python -m pytest -q --collect-only                            # 733 pinned
# Manual demo: s19tui --load examples/case_00_public/prg.s19 → press x →
# select an operation → Execute → status: placeholder + unchanged image.
```

## 4. Test results (executed 2026-06-11 on this worktree)

1. `python -m pytest -q tests/test_tui_operations_view.py` → **3 passed** (0 failures, 0 skips).
2. `python -m pytest -q tests/test_operations.py` → **8 passed** (regression green).
3. TUI stack guard (`test_tui_variants.py` + `test_tui_report_view.py` + `test_tui_patch_editor_v2.py`) → **24 passed**.
4. Lean suite `pytest -q -m "not slow"` → **681 passed, 0 failures** (678 + 3). *(result recorded at packet finalization — see §verification in the increment report)*
5. `python -m pytest -q --collect-only` → **733 collected** (= §5.3 pinned 722 + N=11; ledger 730 → 733).
6. `git diff --stat s19_app/tui/rail.py` → **empty** (rail stays at 8 items, LLR-004.1).
7. Probes, all 0 hits / exit 1 on the I1/I2 targets (`s19_app/tui/operations/` + `s19_app/tui/services/operation_service.py`): TC-008 widened textual/reverse-import probe → 0 hits; P11 filesystem probe → 0 hits; P8 `\.execute\(` on `app.py` + `screens.py` → 0 hits (the view never calls an operation directly).
8. AST guard `tests/test_tui_variants.py::test_no_new_parse_loaded_file_call_sites` → **1 passed** (zero new `_parse_loaded_file` call sites; the view path parses nothing).

Coverage-claim check (functions confirmed on disk in `tests/test_tui_operations_view.py`): `test_operations_view_lists_registry_ids` (TC-010 → LLR-004.1 + the LLR-004.2 guard), `test_operations_view_executes_via_service` (TC-011 → LLR-004.2), `test_operations_view_result_hex_render_matches_baseline` (TC-012 → LLR-004.3). LLR-004.4 is inspection-validated: the `action_operations_view`/`_execute_selected` diff carries no `@work` decorator and registers no worker group (0 `@work` on the HLR-004 paths).

## 5. Risks

- **LLR-004.2 mechanism note (deviation, surfaced loudly):** the LLR statement names "the app's dismiss callback" as the `run_operation` invocation site; per the I3 task spec ("app.py orchestration-only — NO operation logic, NO render logic; the modal owns its content", widget ids pinned inside the screen) execution lives in `OperationsScreen._execute_selected`, still exclusively through the `run_operation` seam. All LLR-004.2 numeric thresholds and both inspection probes (P8 0 hits, seam-substitution observed) pass under this shape. Flag for the Phase-4 reviewer to ratify the wording.
- The synchronous UI-thread execution (LLR-004.4) is INVALIDATED the moment a placeholder gains real logic — the fill-in batch must migrate to the `execute_scope` worker pattern (risk R-6 carried forward).
- Test TC-010 presses the literal key `x`; any future widget that consumes plain `x` while focused on the main screen would shadow the binding (same exposure as the existing `t`/`v` bindings).
- `OperationsScreen` reads `self.app.set_status` on the defensive `KeyError` branch (structurally unreachable — options come from the registry); untyped `App` attribute access, runtime-safe, not test-covered by design (no TC names it).

## 6. Pending items

None — Phase 3 closes with I3. Ledger: collection 730 → 733 (all 11 batch node ids of §5.3 collected; no helper tests added beyond the pinned N=11).

## 7. Suggested next task

Phase 4 validation: re-run the §5.3 batch acceptance set on the merged tree (full `pytest -q -m "not slow"`, collection 733, TC-008/P8/P11 probes on the final tree, LLR-004.4 no-`@work` diff inspection) and write `04-validation.md`.
