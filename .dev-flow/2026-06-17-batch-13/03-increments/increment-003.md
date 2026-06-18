# Increment 003 — US-014 UI wiring (LLR-014.1 UI / LLR-014.2 route / LLR-014.3 apply reuse)

**Status:** awaiting gate (LAST impl increment — completes Phase 3). **Files:** 3 (≤5). **Tests:** +2. **code-reviewer:** APPROVE (0 HIGH / 0 MED / 2 LOW). **Ledger:** 891 → 893 (+2 EXACT).

## 1. What changed
- **`screens_directionb.py`** — `PatchEditorPanel.compose` gains a paste `TextArea` (`#patch_paste_text`) pre-loaded with `DUMMY_CHANGESET_TEXT` (does NOT replace the change-file path Input) + a "Parse pasted" button (`#patch_paste_parse_button`). `ActionRequested.paste_text: str = ""` added (additive default) + docstring Args updated. The button posts `ActionRequested(action="parse_paste", paste_text=<TextArea text>)`.
- **`app.py`** — `"parse_paste"` added to `PATCH_ACTIONS_V2` (9 → 10); router `parse_paste` branch calls `ChangeService.load_text(event.paste_text)` → `_report_change_result` (reads ONLY `paste_text`; no new write/apply code). Stale `:938` docstring truth-fixed (Patch Editor IS wired).
- **`tests/test_tui_patch_editor_v2.py`** — TC-205 (mount: paste TextArea pre-loaded, rstrip tolerance), TC-208 (drive `parse_paste` THROUGH the router → `service.document` replaced, then drive EXISTING `apply_doc` → identical apply outcome + **save-back prompt name identity** paste-vs-file, the F-A-06 oracle). Action-set assertion REUSE-extended 9 → 10 (renamed `..._exactly_ten_...`).

## 2. Mapping to LLRs
- LLR-014.1 (UI half) → TC-205. LLR-014.2 (route) → TC-208 + action-set REUSE-extend. LLR-014.3 (apply reuse) → TC-208 apply + save-back parity.

## 3. How to test
```
pytest -q tests/test_tui_patch_editor_v2.py
git diff febd843 -- s19_app/tui/changes/apply.py s19_app/tui/changes/verify.py s19_app/tui/workspace.py   # MUST be empty
ruff check s19_app/tui/screens_directionb.py s19_app/tui/app.py tests/test_tui_patch_editor_v2.py
```

## 4. Test results
- `test_tui_patch_editor_v2.py`: **13 passed** (post F1-fold). Regression (service/schema/apply/directionb): 179 passed.
- Frozen guards: `test_engine_unchanged.py` 1 passed; `test_tui_directionb.py -k tc031` 3 passed.
- Write-surface gate vs `febd843`: **empty** (0 new write paths).
- Collection: 891 → **893** (+2 EXACT). ruff: changed files clean; app.py 6 pre-existing F40x (6 before = 6 after, untouched — left surgical).

## 5. Independent review
**code-reviewer: APPROVE** · 0 HIGH / 0 MED / 2 LOW. All 8 rule-ons PASS: additive contract (every existing `ActionRequested(...)` valid); router reads only `paste_text`, mirrors `load_doc`, collect-don't-abort; `PATCH_ACTIONS_V2` exact 10; **no new write surface** (diff vs `febd843` = 0); TC-208 a genuine F-A-06 oracle (save-back name driven by `variant_id`, not `source_path`); docstring truth-fix prose-only; frozen set untouched. Security: concurs **advisory** (0 new write surface). LOWs: F1 (stale "nine" comment) **folded**; F2 (pre-existing app.py F40x, count corrected to 6) left surgical.

## 6. Risks
- Paste row has no dedicated `.tcss` (default Textual layout) — functionally correct (tests assert via `run_test`); live terminal visual not inspected.
- TC-208 asserts save-back prompt + entries + name identity; the actual file write/verify is unchanged shipped code (covered by existing TC-051) — intentional per LLR-014.3 (no new write surface).

## 7. Phase 3 status
**COMPLETE on Inc-3 approval.** 3 increments (Inc1 US-013 / Inc2 US-014 data / Inc3 US-014 UI). Full feature: load CRC config from file; paste a change-document (dummy pre-loaded) → parse → existing apply/contained-emit/verify/save-back. Ledger 879 → 893 (+14: Inc1 +7, Inc2 +5, Inc3 +2). Next: Phase 4 validation.
