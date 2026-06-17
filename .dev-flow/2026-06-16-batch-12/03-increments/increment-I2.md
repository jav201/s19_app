# Increment I2 — CRC config sourcing + check/compare (headless)

**LLRs:** LLR-004.1 (external JSON config reader), LLR-002.1 (read stored 4-byte LE), LLR-002.2 (compare + per-region payload, non-mutating). **TCs:** TC-113/114 + config failure modes; TC-111/112 + missing + multi-region. **Headless** (no TUI, no OperationResult assembly — those are I3). Implemented in 2 narrated sub-steps (A config, B check).

## 1. What changed
- **Sub-step A — config:** `crc_config.py` — `CrcRegion`/`CrcConfig` dataclasses + `read_crc_config(raw_path, base_dir, size_probe)` → `(CrcConfig|None, [errors])`. Resolves via `resolve_input_path`, enforces `READ_SIZE_CAP_BYTES` BEFORE reading, parses JSON (hex via `int(s,16)`, rejects `bool`-as-int), and on ANY data fault returns `(None,[one error])` — never raises (mirrors `read_change_document`). `examples/crc_config.example.json` dummy (fake values).
- **Sub-step B — check:** in `crc.py` — `read_stored_crc_le(op_input, output_address)` (4-byte LE read; any of the 4 addresses absent → `None`, no KeyError) + `check_regions(op_input, config)` (per region: compute via the I1b engine using config params, read stored, build `CrcRegionResult{output_address, computed_crc, stored_value, matched, written=False}`; `matched` = True/False/None tri-state). Non-mutating.

## 2. Files modified (5 = 3 + 2, all ≤5)
- `s19_app/tui/operations/crc_config.py` (NEW), `examples/crc_config.example.json` (NEW), `tests/test_crc_config.py` (NEW)
- `s19_app/tui/operations/crc.py` (EDIT — +`read_stored_crc_le` +`check_regions`), `tests/test_crc_operation.py` (NEW)

## 3. How to test
```
python -m pytest -q tests/test_crc_config.py tests/test_crc_operation.py tests/test_crc_engine.py
python -m pytest -q -m "not slow"
ruff check s19_app/tui/operations/crc_config.py s19_app/tui/operations/crc.py tests/test_crc_config.py tests/test_crc_operation.py
```

## 4. Test results
- I2 tests: 10 passed (6 config + 4 check); engine regression 9 passed.
- `pytest -q -m "not slow"`: **807 passed**, 29 skipped, 3 xfailed (exit 0) — orchestrator re-ran (205s).
- ruff clean.
- **Ledger:** lean 797→803 (Step A +6) →807 (Step B +4) = **+10**; collection 850→860; D=0.

## 5. Independent review (code-reviewer) — CLEAN, 0 findings
All three mandatory rule-ons passed: (a) collect-don't-abort holds — every config-fault path traced returns `(None,[error])`, no escaping exception (incl. an `OSError`-on-read catch + a `bool`-as-int guard); (b) `read_stored_crc_le` is KeyError-safe (full-span presence guard before indexing, correct 4-address span); (c) TC-111 is non-vacuous (stored = `encode_le32(independently-computed)`, asserts both `computed_crc == oracle` and `matched is True`). Size cap enforced before read (deterministic over-cap test via `SizeProbe` seam, no 256MB fixture). F-S-02 read-only/uncontained/size-capped, no write path. CLEAN — OK to advance.

## 6. Risks
- F-S-02 config read uncontained-by-design (accepted, read-only, size-capped). No write path in I2.
- §5.2 TC-111/112 named `test_crc_check.py`; implemented in `test_crc_operation.py` (matches the increment plan + LLR-002.2). Reconciled in §5.2 now; provisional-until-Phase-3 per V-5.
- `check_regions` recomputes even with no stored value (payload always carries `computed_crc`) — intentional, pure read.

## 7. Pending / next
- **I3** — the wiring + TUI surface. This is where `CrcOperation.execute` becomes REAL (consumes `check_regions`, assembles `OperationResult` with `crc_regions`, `status="ok"`), replacing the placeholder — which touches `placeholders.py`/`registry.py`/`test_operations.py` AND adds the config text widget + per-region result rows + worker-thread (R-6). That is >5 files, so **I3 will be split (I3a wiring / I3b TUI surface)** — I will finalize the split at the I2 gate and update PLAN.md §2.
