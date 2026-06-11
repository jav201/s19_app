# Increment E7 — Markdown project-report generator — batch-07

**Date:** 2026-06-10 · **LLRs:** 007.1–007.8 complete (+F-S-05/F-S-07) · **TCs:** TC-037..TC-044

## 1. What changed
- **`services/report_service.py`** (NEW, headless, no logging in module): `generate_project_report(project_dir, variant_results, options, *, variant_set, now_fn)`; domain-validated `ReportOptions` (context 0..4096, explicit error never silent clamp — F-S-05); window math `compute_hexdump_windows` with 0-clamp + image-top clamp + overlap/adjacency merge (F-Q-06, both edge fixtures tested); hexdumps via the headless `render_hex_view` only (F-Q-19 inspection enforced by a permanent test); filename `<UTC ts>(-NN zero-padded)?-report.md` with injectable clock (F-Q-05); both `REPORT_MAX_*` caps with exact-omitted-count `TRUNCATED` markers + appendix; content (a)–(e) incl. execution-mode/source header (F-A-17), variant inventory, consolidated overview, per-variant modified-files (`saved_path`), modification tables, **declaration-error subsection** (`ChangeSummary.issues` + `CheckRunResult.issues` — B-2 chain complete), checklist tables, hexdumps. F-S-07 honored (raw bytes only under gitignored `.s19tool/`, never logged, public fixtures only).
- **`variant_execution_service.py`**: additive `mem_map: Optional[dict] = None` on `VariantExecutionResult`, populated only with the opt-in `capture_mem_maps=True` (post-change by construction; default False preserves the 006.3 memory profile).
- **Tests:** `test_report_service.py` (NEW, 14 = 13 lean + 1 slow measurement).

## 2. Files
3 of ≤5. (`version.py` already had `__version__`; conftest untouched.)

## 3. Results (orchestrator-verified)
- `test_report_service.py` + execution regression: `25 passed` (independent) · consumers `34 passed` (agent) · **Lean: `662 passed / 0 failed`** — ledger exact 649 + 13 = 662, +1 slow → deselected 19→20 ✓ (orchestrator re-run) · inspections: 0 forbidden imports ✓.
- **007.6 measurement (env rule, executed):** large_s19 (200 ranges × 4 KB, 128 regions): default context → 106,848 bytes / 0.011 s; max context → 70,013 bytes (windows merge, then `MAX_HEX_ROWS` bounds) — **both constants HOLD**, no adjustment; cap fires with explicit marker as designed.

## 4. Conflict surfaced & resolved
The increment contract's window upper clamp vs LLR-007.2's unclamped wording — implemented the clamped form (reconciles both; gap convention covers partial last rows). **Phase-4/6: align LLR-007.2 wording.**

## 5. Risks
Byte budget enforced at hexdump-block granularity (tables may overshoot by ~hundreds of bytes — explicit-over-silent, documented) · `capture_mem_maps=True` retains N maps — E8 must drop results post-generation · per-modification table has the 6 contract columns; blocked/skipped show `before='-'` (disposition column = operator option at E8).

## 6. Deviations
None beyond the surfaced window-clamp reconciliation.

## 7. Next
E8 — `ReportViewerScreen` (open_links=False, size-capped, ts-descending) + `action_view_reports` + generation trigger (context_bytes dialog → service with capture_mem_maps=True, results dropped after).
