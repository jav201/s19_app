# Increment E3b — cfdx retirement enactment — batch-07

**Date:** 2026-06-10 · **LLR:** 003.3 (+ §6.6 enactment) · approved budget exception (~20-25 envelope, deletions-dominated)

## 1. What changed
- **Deleted:** the entire `s19_app/tui/cdfx/` package (11 modules) + `services/cdfx_service.py` (via `git rm`), after migrating `memory_display.py` → `changes/display.py` (public names preserved — F-Q-09). 15 whole test files deleted (10 cdfx + patch_editor + patch_containment + unified_changeset + unified_export + cdfx_unchanged).
- **Relocated:** the TC-027 engine-unchanged guard → `tests/test_engine_unchanged.py` (the §5.3-named survivor).
- **Enacted §6.6** across `test_memory_*`, `test_unified_*`, `test_tui_memory_patch.py`, directionb strays, snapshot patch cell (xfail `strict=False`, baseline regen = CI-env-only), `conftest.py` (param-half factories retired; memory/unified factories evolved to v2; NEW `change_document_factory`/`make_change_file`).
- **Folded** E3a `DEFAULT_CSS` → `styles.tcss` (retired-id rules removed).
- **Probe self-tested (B-3):** pre-delete **164** hits (probe proven live) → post-delete **0**. `git ls-files s19_app/tui/cdfx/` → empty.

## 2. Files
45 total: 27 deletions + 1 rename + 16 modified + 1 new (`+1,518 / −16,212`). Non-deletion edit set = 17–18 files, inside the envelope; total >25 only because the enumerated delete set alone is 27 (surfaced, not assumed).

## 3. How to test
Probe + `git ls-files` + `python -m pytest -q -m "not slow"` + new-stack suites + `--collect-only -q`.

## 4. Results (agent verbatim + orchestrator re-verified)
- Lean: `611 passed, 29 skipped, 19 deselected, 3 xfailed in 157.12s` — **0 failures** (orchestrator re-run pending in background at packet-write time; confirmed at gate).
- New-stack regression: `89 passed` (orchestrator re-run: `89 passed in 5.85s` ✓). Probe 0 ✓, cdfx empty ✓, collection **915 → 662** ✓ (orchestrator: 662 ✓).
- **Ledger:** −253 = −229 RETIRE − 1 D3-resolved − 23 folds; +1 relocation. R (REWRITE returning) = 28 of 50; 22 folded with named targets (full per-file table in the Phase-3 transcript and §6.6 ledger note).

## 5. Row-level findings for operator ratification
1. **6 §6.6 rows re-dispositioned** (SURVIVES → intent-preserving REWRITE): `test_memory_validate.py:113/:128/:140/:166/:178/:217` asserted `MEMV-OUTSIDE`/`MEMV-PARTIAL` WARNINGs that v2 eliminated by design (containment became apply *dispositions*, not issues — LLR-001.6/002.2). Enacted per the §6.6 vocabulary note; flagged per the STOP rule. Conversely D2 row `:260` survived unmodified.
2. **One production edit beyond deletions:** `changes/io.py` containment-failure message now names the exception type — required by the surviving S57-02 test; the alternative (loosening the assertion) is forbidden by CLAUDE.md rule 9.
3. `test_unified_changeset/export.py` carried 6 REWRITE rows but the work order said whole-file delete — enacted as **folds with named targets** (e.g. save-back containment → `test_changes_apply.py` adversarial cases + `test_tui_patch_editor_v2.py::test_save_back_prompt`).

## 6. Pending
CI-env baseline regen for `patch-comfortable-120x30` (then drop xfail) · Phase-6: REQUIREMENTS.md §8–9 supersession + LLR-002.7 HEX wording · Phase-4: F-Q-14 equation vs CI collected count.

## 7. Next
E4 — real check engine (`changes/check.py`) into the E3a `check_runner` seam.
