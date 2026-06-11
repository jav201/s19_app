# Increment E6 — manifest + batch/per-variant execution — batch-07

**Date:** 2026-06-10 · **LLRs:** 006.1–006.6 complete, 005.6 completed, 002.7-headless · **TCs:** TC-031..TC-036

## 1. What changed
- **`services/variant_execution_service.py`** (NEW, ~870 L, no Textual): capped + project-contained `project.json` manifest read (LLR-006.1 + F-S-03: paths resolved against the project dir ONLY; escape/absolute/reparse → 1 ERROR + skip; manifest absent → batch-all default); deterministic execution plan (006.2); isolated per-variant loop — fresh parse per variant via `build_loaded_s19/hex`, sequential (006.3); `VariantExecutionResult {variant_id, status, change_summaries[], check_results[], diagnostics}` with `len(results)==N` always (006.4); engines consumed kind-discriminated with `variant_id` stamps (006.5); headless save-back `<variant_id>-patched.s19` (002.7, dedup via engine; HEX → diagnostic per D-1).
- **`app.py`**: `execute_scope` = 9th routed action (F-A-15 — set now "exactly 9 at E6"); `@work(thread=True)` worker + `call_from_thread` per-variant status lines (F-Q-18 observable); manifest `active_variant` override on project load with warn+fallback (005.6 complete); collision-safe id resolution at save/sync.
- **`screens_directionb.py`**: scope cycler {active variant | all variants | per assignment} + Execute button (`ActionRequested.scope_text` additive).
- **`workspace.py`**: duplicate-stem rule ratified — colliding stems → full-filename `variant_id`s (in `build_variant_set`).
- **Tests:** `test_variant_execution.py` (NEW, 11) + contract-mandated pins updated (8→9 action set; duplicate-stem ids).

## 2. Files
7 (≤6 + the two contract-mandated test-pin updates — surfaced, not hidden).

## 3. Results (orchestrator-verified)
- `test_variant_execution.py`: `11 passed` · targeted re-run (execution+panel+variants): `27 passed` · stack regression `51 passed` (agent) · **Lean: `649 passed / 0 failed`** — ledger exact 638 + 11 = 649 ✓ (orchestrator re-run) · no-Textual: 0 ✓.

## 4. Design choices (documented per contract)
Manifest io lives in the service (primary consumer; keeps workspace surface narrow) · results carry LISTS per variant (batch+assignments can map N files to one variant) · batch-mode save-back automatic when `applied>0` on S19 variants (no prompt in batch — engine dedups `-patched_1` on re-runs).

## 5. Risks / open
- **Manifest is READ-ONLY this batch** — operators author `project.json` by hand; a writer (e.g. persisting `active_variant` on switch) is a small follow-up → E8 candidate or batch-08.
- Reparse-point guard shared but not symlink-exercised on Windows CI (helper covered by workspace tests).
- Manifest-absent fallback executes the loaded document only if saved to disk (in-memory unsaved → clear status message).
- Snapshot patch cell still xfail pending CI regen (will bake the new controls in when regenerated).

## 6. Deviations
File-cap 7 vs ≤6 (mandated pins). Otherwise none.

## 7. Next
E7 — report generator (`services/report_service.py`, LLR-007.1–007.8) consuming `VariantExecutionResult`.
