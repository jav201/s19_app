# Increment E3a — consolidated v2 Patch Editor + change_service — batch-07

**Date:** 2026-06-10 · **LLRs:** 003.1, 003.2, 003.4 (service half), 003.5, 002.7-UI, 002.8-UI, 004.5 (display, engine-seamed) · **TCs:** TC-015, TC-016, TC-019, TC-024, TC-051-UI, TC-052

## 1. What changed
- **`services/change_service.py`** (NEW, no Textual): v2 `ChangeDocument` lifecycle — both-kind add/edit/remove, load/validate (collision + containment), apply (+ `save_patched_image`, stamps `saved_path`), v2 save, `check_runner` seam for E4 (`CHG-CHECKS-PENDING` status until E4 injects the real engine), table rows, TUI-input grammar helpers.
- **`screens_directionb.py`**: `PatchEditorPanel` rewritten to ONE section — entries DataTable (Kind/Address/Value/Status/Linkage), both-kind inputs, Load/Validate/Apply/Save/Run-checks under the 6 NEW `patch_doc_*` ids; persistent declaration-fault area (002.8); inline post-apply save prompt with editable `<variant_id>-patched.s19` suggestion (002.7); severity-classed check display (004.5, pass→`sev-ok`). Retired widgets gone. New CSS in `DEFAULT_CSS` (E3b folds to styles.tcss).
- **`app.py`**: router → exactly the 8-action `PATCH_ACTIONS_V2` set; retired actions → status error, no crash; `_report_cdfx_result`→`_report_change_result`; export-result reporting + `CdfxService` usage removed; save-back confirm rides a separate `SaveBackDecision` message (keeps the routed set at 8 — F-A-15; E6 extends to 9 via `execute_scope`).
- **Tests:** `test_tui_patch_editor_v2.py` (8) + `test_change_service.py` (16).

## 2. Files
5: change_service.py (new), screens_directionb.py, app.py, 2 new test files. cdfx/ + cdfx_service.py untouched (E3b deletes).

## 3. How to test
`python -m pytest -q tests/test_tui_patch_editor_v2.py tests/test_change_service.py` + engine regression + (E3b restores the old-suite green).

## 4. Results (verbatim)
- New suites: `24 passed in 5.24s` · Engine regression: `65 passed in 0.59s` · app/services sanity: `66 passed, 1 xfailed`.
- **Interim reds (expected, unmodified per contract):** old patch suites `30 failed, 18 passed`; directionb `5 failed, 96 passed`.
- **§6.6 prediction diff (orchestrator):** all 35 reds (patch_editor 14, containment 4, memory_patch 12, directionb strays 5) are predicted RETIRE/REWRITE rows — incl. the D3 row (`scrolls_to_reach_export_button`), now resolved by measurement (export button retired). Remaining RETIRE rows stay green only because their `cdfx/` modules still exist — they fall at E3b exactly as the table models. **35/35 predicted → disposition table validated at interim state.**
- No-Textual grep on change_service.py: 0.

## 5. Risks
- **Deviation (judgment call, flagged):** for HEX images the "prompt shall state HEX unsupported" was implemented as a status-line message instead of a dead prompt — Phase-6 doc reconciliation of LLR-002.7 wording (or revert at gate).
- Hex viewer not re-rendered after apply (no E3a LLR demands it); operator re-navigates to see patched bytes — candidate UX touch-up for E3b/E7.
- Status lines truncate at 50 chars; full text stays in `result.issues`.

## 6. Pending
E3b: deletions + disposition enactment + import re-pointing + `DEFAULT_CSS`→styles.tcss + self-tested retirement probe. E4: real check engine into the seam.

## 7. Next
E3b (the approved ~20-25-file budget exception).
