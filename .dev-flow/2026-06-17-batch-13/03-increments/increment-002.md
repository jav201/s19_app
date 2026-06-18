# Increment 002 — US-014 data layer (LLR-014.1 + LLR-014.2)

**Status:** awaiting gate. **Files:** 3 (≤5). **Tests:** +5. **code-reviewer:** APPROVE-WITH-NITS (0 HIGH / 0 MED / 1 LOW pre-existing). **Ledger:** 886 → 891 (+5 EXACT).

## 1. What changed
- **`changes/io.py`** — added `parse_change_document(text) -> ChangeDocument` (string seam): re-homes the **same** 3-exception catch (`json.JSONDecodeError`, `RecursionError`, `UnicodeDecodeError`) around `json.loads`, emitting `MF-JSON-PARSE` (**F-A-01, the Phase-2 major**); sets `source_path=None`; never raises. `read_change_document` refactored to **delegate** (resolve + size-cap + read stay; decode + interpretation move to the seam; re-stamps `source_path=resolved`). Added `DUMMY_CHANGESET_TEXT` (FAKE, kind=change, no trailing newline). Both added to `__all__`.
- **`services/change_service.py`** — added `load_text(text) -> ChangeActionResult` mirroring `load`; direct-module import of `parse_change_document` (matches existing `from ..changes.check import` style). No write code.
- **`tests/test_changes_schema.py`** — TC-206 (dummy parses), TC-207 (parity, **narrowed** oracle entries+`{code}`, asserts source_path divergence), TC-209 (malformed → `MF-JSON-PARSE`), TC-210 (delegation `call_count==1`), TC-211 (changeset tripwire).

## 2. Mapping to LLRs
- LLR-014.1 → TC-206, TC-211. LLR-014.2 → TC-207, TC-209, TC-210.

## 3. How to test
```
pytest -q tests/test_changes_schema.py
pytest -q tests/test_change_service.py tests/test_changes_apply.py tests/test_engine_unchanged.py
ruff check s19_app/tui/changes/io.py s19_app/tui/services/change_service.py
```

## 4. Test results
- `test_changes_schema.py`: **38 passed** (33 existing + 5 new) — existing `read_change_document` tests pass → refactor fidelity confirmed.
- Regression (service/apply/containment/linkage/patch-editor + frozen guard): 61 + 10 passed; broader related scope 226 passed.
- Collection: 886 → **891** (+5 EXACT). ruff: clean except one **pre-existing** `F401` (`typing.List` in change_service.py:38, identical on `febd843`; left surgical).

## 5. Independent review
**code-reviewer: APPROVE-WITH-NITS** · 0 HIGH / 0 MED / 1 LOW. All 9 rule-ons PASS: F-A-01 catch re-homed verbatim; delegation-not-duplication (TC-210 pins `call_count==1`); `source_path=None`/re-stamp correct & tested; parity oracle genuinely narrowed; no new write surface; bytes-vs-str ruled acceptable (docstring documents it); F401 confirmed pre-existing; frozen set untouched. LOW = the pre-existing F401, correctly left.

## 6. Write-surface verification (F-S-03, orchestrator)
Against the **correct** baseline `febd843` (NOT the stale local `main` ref `ec453a2`): `apply.py`/`verify.py`/`workspace.py` = **empty diff**; `io.py` changed only in the parse seam (`emit_s19_from_mem_map` body untouched). **0 new write paths.** Spec LLR-014.3 updated to pin `<BASE>=febd843` so the Phase-4 gate doesn't trip on the stale ref.

## 7. Pending / next
Inc 3 — US-014 UI wiring: `screens_directionb.py` (paste TextArea + `ActionRequested.paste_text`) + `app.py` (`parse_paste` in `PATCH_ACTIONS_V2` + router + fix stale :938 docstring) + `test_tui_patch_editor_v2.py` (TC-205/208 + action-set REUSE-extend). `DUMMY_CHANGESET_TEXT` + `load_text` are exported and ready.
