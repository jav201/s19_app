# Increment E8 — report viewer + generation trigger (FINAL) — batch-07

**Date:** 2026-06-10 · **LLRs:** 008.1–008.5 complete · **TCs:** TC-045..TC-049

## 1. What changed
- **`screens.py`**: NEW `ReportViewerScreen(ModalScreen[None])` — `textual.widgets.Markdown` constructed **`open_links=False`** (F-S-06, pinned in code AND test), no `LinkClicked` handler, render-only; `VIEWER_SIZE_CAP_BYTES = 2 × REPORT_MAX_TOTAL_BYTES` refusal with neutral message; ts-descending listing with empty states (no project / empty `reports/`).
- **`app.py`**: `action_view_reports` keybound **`t`** (command-palette surfaced; rail untouched — stays exactly 8 items per LLR-008.2, verified by empty diff on `rail.py`); generation trigger collects `context_bytes` (64 prefilled) → `generate_project_report(capture_mem_maps=True)` → status shows the path → **`_last_execution` retention**: replaced on each execution, consumed+dropped (set to `None`) after generation (E7 risk closed); no report-assembly logic in app.py.
- **`report_service.py`** (small, justified): `EXECUTION_SCOPE_TO_REPORT_MODE` mapping so the execution-scope vocabulary never leaks into app.py (F-A-17 wiring).
- **`styles.tcss`**: viewer css.
- **Tests:** `test_tui_report_view.py` (NEW, 8 pilots) — incl. the `_open_links is False` pin, oversized-refusal, results-dropped assertion.

## 2. Files
5 (within cap).

## 3. Results (orchestrator-verified)
- `test_tui_report_view.py`: `8 passed` · stack regression `41 passed` · **Lean: `670 passed / 0 failed`** — ledger exact 662 + 8 = 670 ✓ · `rail.py` diff empty ✓.

## 4. Design choices
Viewer cap = 2× the report byte budget (any self-generated report fits; foreign oversized .md refused) · generation consumes the LAST execution's results when present, else prompts to execute first (minimal coherent flow) · keybinding `t` (v/r taken).

## 5. Risks
Foreign `.md` files in `reports/` are listed (by design — the dir is operator space); rendered safely (no links, size-capped).

## 6. Deviations
None.

## 7. Phase-3 status
**ALL 10 INCREMENTS COMPLETE.** Cumulative: lean 670/0 vs 638 pre-batch baseline shape (ledger chain E1..E8 exact at every gate). → Phase 4 validation.
