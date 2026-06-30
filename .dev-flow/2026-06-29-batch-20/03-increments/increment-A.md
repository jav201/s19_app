# Increment A — HLR-027 (D-1 SAVE)

> Declared regions persist to `project.json` on project-save. Capture = Option A (on Generate). 2 files. **code-reviewer: APPROVE-WITH-NITS** (0 HIGH/MED).

## 1. What changed
New single-source-of-truth `self._declared_regions` on `S19TuiApp`, populated when `GenerateRequested` fires (Option-A capture), threaded through `_handle_save_dialog` → `_write_and_verify_manifest` → existing `write_project_manifest(declared_regions=)`. Empty ⇒ serializer omits the key (byte-identical back-compat). `SaveProjectPayload` untouched.

## 2. Files modified (2 of ≤5)
- `s19_app/tui/app.py` (production)
- `tests/test_tui_report_seam.py` (6 new tests)

| LLR | Landing |
|---|---|
| LLR-027.1 state decl | `app.py:713` `self._declared_regions: Tuple[DeclaredRegion, ...] = ()` |
| LLR-027.2 capture on Generate | `app.py:1899` (before dispatch at :1900) |
| LLR-027.3 save → write_and_verify | `app.py:3791` `declared_regions=self._declared_regions` |
| LLR-027.4 param | `app.py:3802` `declared_regions: Sequence[DeclaredRegion] = ()` |
| LLR-027.4 forward (C-P3c write-only) | `app.py:3867` → `write_project_manifest`; `verify_written_manifest` (:3880) NOT threaded |

## 3. How to test
```
python -m pytest tests/test_tui_report_seam.py -q
python -m pytest -q -m "not slow"
python -m ruff check s19_app/tui/app.py tests/test_tui_report_seam.py
```

## 4. Test results
- New tests green: AT-027a (exact 2-tuple persisted), AT-027b (typed-not-generated ⇒ `()`), AT-027c (key absent + legacy loads), TC-027.1/.2/.3 — `test_tui_report_seam.py` 6→12 passed.
- Full non-slow: **958 → 964 collected (+6)**; 932 passed / 29 skipped / 3 xfailed / 0 failed. No regression.
- **Counterfactual RED (QC-2):** dropping the `write_project_manifest` forward ⇒ AT-027a `AssertionError: oracle returned () ≠ (DeclaredRegion('bootblk',4096,4351), DeclaredRegion('cal',32768,33023))`. Value-discriminating. Restored → re-green.
- ruff clean. Frozen-engine diff **0** (verified). manifest_writer/variant_execution_service/report_addendum untouched.

## 5. Independent review
- **code-reviewer: APPROVE-WITH-NITS.** Correctness CLEAN (capture-before-dispatch, C-P3c honored, no read-before-init, empty-key back-compat). Test-intent STRONG (exact tuple, real surfaces, non-vacuous counterfactual confirmed). 1 LOW (F1): `write_project_manifest` docstring Args missing `declared_regions` — **pre-existing in a frozen/substrate file**, correctly NOT touched here; flagged for the owning batch's doc pass.
- **Security:** no new surface — persisted name is scrubbed at `DeclaredRegion.__post_init__` (Phase-2 GRANT Q1). No re-review needed.

## 6. Risks
- Back-compat drift guarded by AT-027c + TC-027.3 (attribute defaults `()`, only assigned from `tuple(message.declared_regions)`; no sentinel).

## 7. Pending / next
- **Increment B (HLR-028 LOAD):** consume `self._declared_regions` — capture from manifest in `_handle_load_project` + seed the TextArea on dialog open. Closes the round-trip.
