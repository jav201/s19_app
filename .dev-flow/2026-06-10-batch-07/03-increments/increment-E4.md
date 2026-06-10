# Increment E4 — check engine — batch-07

**Date:** 2026-06-10 · **LLRs:** 004.1–004.5 (complete) · **TCs:** TC-020..TC-024

## 1. What changed
- **`changes/check.py`** (NEW, 209 L): `run_check_document` — pure, no Textual; gate = apply-gate mirror (document ERROR or `kind≠"check"` → no comparisons, all entries uncheckable, issues carried — design choice documented in the module docstring per the spec's flag request); per-entry pass/fail/uncheckable per LLR-004.2; linkage via the SHARED classifier from `apply.py` (no duplication).
- **`changes/model.py`**: `CheckRunResult` canonical C-6 (incl. `issues` — B-2 carrier — `variant_id`, injectable `now_fn`, deterministic `to_dict()`).
- **`services/change_service.py`**: real engine injected into the E3a seam (`CHG-CHECKS-PENDING` gone); `run_checks_for_project(check_path, image_path, mac_path?, a2l_path?) -> CheckRunResult` lives here (service-level per LLR-004.4 wording), reusing `build_loaded_s19/hex`.
- **Tests:** `test_checks_engine.py` (NEW, 441 L — schema-shared incl. colliding-expectations ERROR per D-3; 2-1-2 + no-image all-uncheckable + mem_map immutability; ≥10-field shape + fixed-clock double-run; headless project run on `examples/case_00_public/prg.s19` with subprocess/static no-Textual probe per F-Q-07); TC-024 in `test_tui_patch_editor_v2.py` re-pinned from stub to the real 2-1-2 engine run; `test_change_service.py` seam tests updated.

## 2. Files
6 (4 planned + `model.py` anticipated + `test_change_service.py` seam update).

## 3. How to test
`python -m pytest -q tests/test_checks_engine.py tests/test_tui_patch_editor_v2.py tests/test_change_service.py` + engine regression + lean.

## 4. Results (orchestrator-verified)
- Targeted: `31 passed in 5.96s` · Engine regression: `65 passed` · Lean: **`618 passed / 0 failed`** — ledger exact 611 + 7 = 618 ✓ · No-Textual grep: 0.

## 5. Risks
- Check-gate semantics (apply mirror) was a designed-and-flagged choice, accepted at this gate.

## 6. Deviations
None beyond the flagged gate-semantics choice.

## 7. Next
E5a — multi-variant workspace + models (`validate_project_files` relaxation + `VariantDescriptor`/`ProjectVariantSet` + backward compat).
