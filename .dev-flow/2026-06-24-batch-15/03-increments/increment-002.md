# Increment 2 — Production fix (US-016, LLR-016.1)

> Phase 3, batch-15. 1 production file (`s19_app/tui/app.py`, +51/-13). AT-016.2 flipped RED→GREEN.

## 1. What changed
Fixed the silent false-verdict bug in `on_ab_diff_panel_compare_requested`. When one compared image is a non-empty file that parses to an empty memory map (all-malformed records; collect-don't-abort, no raise → `compare_images` does not refuse), the handler previously rendered an unconditional `sev-ok`. Now `_diff_load_maps` detects the per-side load failure and the handler surfaces a plain-text `sev-error` diagnostic naming the failed side.

## 2. Files modified
- `s19_app/tui/app.py` (+51/-13). Two edits:
  - `_diff_load_maps`: return `tuple[dict, dict]` → `tuple[dict, dict, list[str]]` (out-of-band `failed_sides`); inner `_source_has_content(image)` helper (`Path(image.path).stat().st_size > 0`, OSError→False); predicate `not mem_map and _source_has_content(image)` → append `image.label`. Docstring updated (Summary/Returns/Data Flow).
  - caller: conditional status — `failed_sides` → `set_status("Compare failed: {labels} loaded no image (file has content but no valid records).", "sev-error")`, else the original `sev-ok` line. `render_comparison` still called; `self._diff_last_result = result` unconditional.

## 3. How to test
- `python -m pytest tests/test_tui_diff_compare_realpath.py -v` (4 ATs).
- `python -m pytest tests/test_tui_diff_screen.py -q` (regression).
- `python -m pytest tests/ -k "diff or compare or report" -q` (ripple).
- `python -m pytest tests/test_engine_unchanged.py tests/test_tui_directionb.py -k "tc031 or engine" -q` (frozen guards).

## 4. Test results
- **4 ATs GREEN** (AT-016.2 flipped RED→GREEN: now `sev-error` naming `degenerate.s19`; AT-016.1/.3/.4 stay green).
- diff-screen **6 pass**; frozen guards **7 pass**; broad diff/compare/report ripple **103 pass / 1 skip** (report path untouched).
- Orchestrator independently reproduced: 4 ATs / 6 diff-screen / 7 frozen guards all green; `git diff --stat` only `app.py`; ruff 6 errors ALL pre-existing (lines 27/37-39/107/7105, outside the ~2130-2225 touched region; tracked in MEMORY.md as app.py F401/F402 cleanup) — **0 new ruff errors**.
- **code-reviewer: APPROVE-WITH-NITS** (0 HIGH / 0 MED / 2 LOW). All 6 rule-ons PASS: predicate correctness + over-correction guards; out-of-band carrier (verified `_diff_load_maps` has exactly 1 call site; report handler reads `panel.mem_map_a/b`, not this return); plain-text diagnostic (`#diff_status markup=False`); names the side (`image.label`=basename); conventions; no regression (`_diff_last_result` unconditional, maps unchanged to `render_comparison`).

## 5. Risks
- **LOW (in-spec, accepted):** a whitespace-only file (size>0, empty map) is flagged `sev-error` — but it genuinely has no valid records, so the diagnostic is honest (code-reviewer concurred; no special-case).
- **LOW (cosmetic):** the Data Flow doc line says appended "by its `image.label`" while the code has a defensive (unreachable for a flagged side) `or str(image.path)` fallback. No change.
- The maps payload is byte-identical to before; report path independent → low ripple risk (confirmed by the 103-test pass).

## 6. Pending items
- Inc 3 (traceability close, LLR-016.2): update `REQUIREMENTS.md` R-* row + finalize `01-requirements.md`.
- Pre-existing `app.py` ruff F401/F402 (6 errors, unrelated) — out of scope; already tracked in MEMORY.md as a standalone cleanup.

## 7. Suggested next task
Inc 3 — traceability close (REQUIREMENTS.md R-* row + dev-flow finalize), then Phase 4 validation (run both layers, capture the AT-016.2 pre-fix RED vs post-fix GREEN contrast as escaped-bug evidence).

## Ledger
collection 898 (D0 / A0 this increment — no new tests; AT-016.2 flipped RED→GREEN). Pending full-suite authoritative run at Phase 4.
