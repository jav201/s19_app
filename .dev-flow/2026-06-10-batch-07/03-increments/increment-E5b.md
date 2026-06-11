# Increment E5b — variant-selector TUI — batch-07

**Date:** 2026-06-10 · **LLRs:** 005.4, 005.5, 005.6-partial (+ 2 E5a findings reworked) · **TCs:** TC-028..TC-030

## 1. What changed
- **`screens.py`**: NEW `SelectVariantScreen(ModalScreen[Optional[str]])` (LoadProjectScreen pattern; selection by list index).
- **`app.py`**: `action_select_variant` (keybound `v`, in command palette) + `_handle_select_variant`; app-level `_variant_set: ProjectVariantSet` built on project load; label `«project»:«variant» (i/N)` when N>1 (plain for single-variant — back-compat); `_handle_load_project` activates the FIRST variant in deterministic order (manifest override = E6); **variant_id stamping**: `_pending_variant_id` set on the main thread by the dispatching handler, consumed once in `_apply_prepared_load` (main thread) — worker signatures untouched, `exclusive=True group="load"` guarantees single in-flight, cleared on every failure path; MAC-merge carries variant_id from the existing primary. **E5a findings reworked:** cross-suffix save guard retired (2nd primary = variant addition, status names it); `_sync_loaded_file_to_project` appends 2nd S19/HEX as a new active variant with a status line (re-append guarded by stamped variant_id on activation reloads).
- **`styles.tcss`**: `#variant_list` joined to the `#project_list` rule.
- **Duplicate-stem display**: falls back to full filename (display-only; id model = E6).
- **Tests**: `test_tui_variants.py` (NEW, 8 pilots/AST) incl. the LLR-005.4 zero-new-call-sites inspection.

## 2. Files
4 (within cap): app.py, screens.py, styles.tcss, test_tui_variants.py.

## 3. Results (orchestrator-verified)
- `test_tui_variants.py`: `8 passed` (re-run independently) · guards `78 passed, 1 xfailed` · palette/keymap guards `111 passed` (agent) · **Lean: `638 passed / 0 failed`** — ledger exact 630 + 8 = 638 ✓ (orchestrator re-run) · `_parse_loaded_file(` call sites: the 2 pre-existing + definition only ✓ (LLR-005.4).

## 4. Risks
- Variant switches accumulate `_<N>` temp copies in `workarea/temp` (transient by design, cosmetic).
- MAC-only save into a primary-holding project can label a variant while a MAC renders — edge deferred to E6 manifest `active_variant`.
- Duplicate-stem `active_id` ambiguity stands (E6 decision).
- styles.tcss "three modals" prose slightly stale — left per surgical rule (Phase-6 doc sweep).
- No project-unload exists; `_variant_set` replaced on next load (pre-existing app shape).

## 5. Deviations
None.

## 6. Pending
E6: manifest (active_variant override + assignments), duplicate-id model, execute_scope routing, batch/per-variant execution.

## 7. Next
E6 — `project.json` + `variant_execution_service` (LLR-006.1..006.6).
