# Increment I1a — Neutral operation-input contract + `OperationResult` widening

**LLRs:** LLR-005.1 (neutral `OperationInput` + both call-sites migrated), LLR-005.2 (`OperationResult` widening). **TCs:** TC-108, TC-109. **No CRC compute** (that is I1b).

## 1. What changed
Resolved the batch-08 deferred framework contract (C-7 item c / R-2 / R-3). Introduced a neutral `OperationInput` dataclass (`mem_map`, `ranges`, `input_path`, `variant_id`, `file_type`) with a `from_loaded(LoadedFile)` adapter; retyped `Operation.execute` to accept `OperationInput` instead of `LoadedFile`; migrated **both** real call-sites (`run_operation` service + the `OperationsScreen` execute handler) to build the neutral input via `from_loaded` — atomically, so the type change keeps the tree green. Widened `OperationResult` with a trailing `crc_regions: Optional[list[CrcRegionResult]] = None` (+ the `CrcRegionResult` dataclass), keeping the 7 original fields and the closed `STATUS_DOMAIN` unchanged; `to_dict` serializes `crc_regions` (list-of-dicts when present, `None` when absent).

`OperationInput` deliberately drops `row_bases`/`range_validity`/`errors`/`a2l_*`, so a placeholder `output` (still a non-optional `LoadedFile`) is rebuilt over the same `mem_map`/`ranges` rather than being the same object — identity-passthrough tests were rebased to value-equality, matching the F-Q-02 check-path contract (`output.mem_map == input.mem_map`).

## 2. Files modified (5 named + 1 forced reconciliation)
- `s19_app/tui/operations/model.py` — `OperationInput`+`from_loaded`, `CrcRegionResult`, `OperationResult` widen, `to_dict`, `Operation.execute` retyped.
- `s19_app/tui/services/operation_service.py` — `run_operation` builds `OperationInput.from_loaded` internally (signature unchanged).
- `s19_app/tui/screens.py` — one call-site (`:636`) + import; 2 stale docstrings (`:520`/`:603`) updated (review F1).
- `s19_app/tui/operations/placeholders.py` — 3 placeholder `execute` retyped; `_placeholder_result` rebuilds the `LoadedFile` output.
- `tests/test_operations.py` — adapted TC-001/002/003/004/007; added TC-108, TC-109 (+F2 None-branch determinism assert).
- **(deviation)** `tests/test_tui_operations_view.py` — forced stub reconciliation (the contract change broke its two `execute` stubs); kept the tree green. code-reviewer ruled it JUSTIFIED — pure mechanical, intent preserved.

## 3. How to test
```
python -m pytest -q tests/test_operations.py
python -m pytest -q -m "not slow"
ruff check <changed .py files>
```

## 4. Test results
- `tests/test_operations.py`: 10 passed (+2 TC-108/109).
- `pytest -q -m "not slow"`: 788 passed, 29 skipped, 3 xfailed (exit 0).
- `pytest -q` (full): 809 passed, 29 skipped, 3 xfailed (exit 0).
- `ruff check`: all clean.
- **Ledger:** lean 786→788, full 807→809, collection 839→841 (D=0, A=2, EXACT).

## 5. Independent review (code-reviewer)
**APPROVE-WITH-NITS, 0 HIGH.** Ruled SOUND: the atomic two-site migration and the identity→value-equality change (only `output.path`/`file_type`/`mem_map` are read off an operation result; the dropped fields are dead on that path). 2 LOW findings (F1 stale docstrings, F2 None-branch determinism) folded by the orchestrator. No security concern (no write path in this increment).

## 6. Risks
- The 6th-file deviation (test reconciliation) exceeds the ≤5 cap; unavoidable under the atomic green-tree mandate. Flagged + reviewer-cleared.
- `output` value-equality is a real loosening vs prior object-identity; intended per F-Q-02.
- Placeholder `output` now carries empty `row_bases`/`range_validity`/`errors`; inert (no consumer reads them off operation output today).

## 7. Pending / next
- I1b — CRC compute engine + co-located doc, headless (3 files): `operations/crc.py`, `operations/requirements/REQ-crc.md` (C-7), `tests/test_crc_engine.py` (LLR-001.1/.2/.3, LLR-005.3).
- `operations/__init__.py` does not re-export `OperationInput`/`CrcRegionResult` (tests import from `.model`); optional facade follow-up.
