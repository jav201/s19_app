# Increment 001 — US-013: CRC config from file (HLR-013)

**Status:** awaiting gate. **Files:** 4 (≤5). **Tests:** +7. **code-reviewer:** APPROVE (0 HIGH / 0 MED / 2 LOW). **Ledger:** 879 → 886 (+7 EXACT).

## 1. What changed
- **`s19_app/tui/operations/crc_config.py`** — added `read_crc_config_text(raw_path, base_dir, size_probe=None) -> tuple[Optional[str], list[str]]` (resolve + size-cap-before-read + `read_text`, raw text, no parse, collect-don't-abort never raises). `read_crc_config` refactored to **delegate** to it (extract-method; behavior + fault messages preserved exactly; `parse_crc_config` still called once on success).
- **`s19_app/tui/screens.py`** — CRC branch gains `#operation_config_path` `Input` + `#operation_config_load` `Button`; both added to `_sync_config_visibility` (CRC-row-only display); new `_load_config_from_path` handler: success replaces `#operation_config` text, fault surfaces on `#operation_result_status` + editor unchanged, empty-path surfaces a message; never auto-runs the check.
- **`tests/test_crc_config.py`** — TC-202 (4 unit cases).
- **`tests/test_tui_crc_surface.py`** — TC-201 (widgets + display toggle), TC-203 (through-handler byte-equal load), TC-204 (faults + dummy-stays + empty-path message).

## 2. Mapping to LLRs
- LLR-013.1 → TC-201. LLR-013.2 → TC-202 (unit) + TC-203 (integration). LLR-013.3 → TC-204.

## 3. How to test
```
pytest -q tests/test_crc_config.py tests/test_tui_crc_surface.py
ruff check s19_app/tui/operations/crc_config.py s19_app/tui/screens.py tests/test_crc_config.py tests/test_tui_crc_surface.py
```

## 4. Test results
- HLR-013 bundle: **24 passed** (post F1-fold; orchestrator-re-run, 40.5s).
- Regression (`test_crc_operation.py` + `test_operations.py`): 23 passed. Frozen guard (`test_engine_unchanged.py`): 1 passed.
- `ruff check`: clean. Collection: 879 → **886** (+7 EXACT).

## 5. code-reviewer verdict
APPROVE · 0 HIGH / 0 MED / 2 LOW. All 7 rule-ons PASS: refactor fidelity preserved; cap-before-read confirmed (crc_config.py:296 before :303); collect-don't-abort (3 exits + OSError catch); no auto-run; tests non-vacuous (TC-202 mock `assert_not_called`, TC-203 byte-equality, TC-204 before==after; over-cap mock ruled **sound**); conventions clean; frozen set untouched.
- **F1 (LOW) FOLDED:** empty-path test now asserts the `"enter a config file path"` message (LLR-013.3 surface compliance).
- **F2 (LOW) LEFT:** `assert raw_text is not None` (type-narrowing, convention parity; unreachable-by-construction).

## 6. Risks
- New widgets have no custom CSS (default Textual layout) — functionally correct (tests assert `.display`); visual polish unspecified by any LLR, deferred.

## 7. Pending / next
- Inc 2 — US-014 data layer: `parse_change_document` + `DUMMY_CHANGESET_TEXT` + reader-delegates refactor + `ChangeService.load_text` + TC-206/207/209/210/211. Awaiting Inc-1 gate approval.
