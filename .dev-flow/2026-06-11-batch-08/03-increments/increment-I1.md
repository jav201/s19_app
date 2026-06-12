# Increment I1 — Operations package (batch 2026-06-11-batch-08, Phase 3)

Implements LLR-001.1, LLR-001.2, LLR-001.3, LLR-001.4, LLR-002.1, LLR-002.2, LLR-002.3 (TC-001..TC-006 + TC-009).

## 1. What changed

Created the NEW `s19_app/tui/operations/` package (§6.2 C-5): the `Operation` ABC with the Phase-2 M-1 `execute(loaded: LoadedFile, *, now_fn: Optional[Callable[[], datetime]] = None) -> OperationResult` signature, the §6.2 C-2 canonical 7-field `OperationResult` dataclass with `STATUS_DOMAIN` validation (`ValueError` outside `{"placeholder", "ok", "error"}`) and a deterministic size-bounded `to_dict()` (output serialized as exactly `{path, file_type, byte_count}`, never `mem_map` — m-7 disclosure guard), the three identity-passthrough placeholders (`crc`, `extract`, `split_by_segment`, each emitting exactly one `"placeholder: <operation_id> not yet implemented"` note), and the deterministic static-literal registry (`list_operation_ids()` / `get_operation()`, loud `KeyError` naming the unknown id verbatim). Plus the 7-test unit file covering TC-001..TC-006 + TC-009 with the spec's per-LLR assertion counts. No I/O, no parsing, zero Textual imports anywhere in the package. No existing file was modified.

## 2. Files modified (all NEW)

| File | Lines | Purpose |
|---|---|---|
| `s19_app/tui/operations/__init__.py` | 29 | Re-export facade (`changes/__init__.py` style): `Operation`, `OperationResult`, `STATUS_DOMAIN`, the 3 placeholder classes, `get_operation`, `list_operation_ids`. |
| `s19_app/tui/operations/model.py` | 261 | `Operation` ABC (abstract `describe` + `execute`), `OperationResult` dataclass (`__post_init__` domain check, deterministic `to_dict()`), `STATUS_DOMAIN` frozenset. |
| `s19_app/tui/operations/placeholders.py` | 291 | `CrcOperation` / `ExtractOperation` / `SplitBySegmentOperation`; shared private `_placeholder_result` builder with the `changes/apply.py:297` clock-seam idiom. |
| `s19_app/tui/operations/registry.py` | 75 | Static literal `_REGISTRY` dict (one screen, LLR-002.2 acceptance), `list_operation_ids()`, `get_operation()` with verbatim-id `KeyError`. |
| `tests/test_operations.py` | 212 | TC-001..TC-006 + TC-009; module docstring maps each test to its TC/LLR id (test_checks_engine.py style); S19 fixture = real parse of `examples/case_00_public/prg.s19` via `S19File` + `build_loaded_s19`; HEX fixture = inline records to `tmp_path` via `IntelHexFile` + `build_loaded_hex` (B-1, `tests/test_hexfile.py` idiom). |

5 files — within the cap. TC-007 (`test_run_operation_service`) deliberately NOT written: it rides increment I2 with `services/operation_service.py`.

## 3. How to test

```bash
python -m pytest -q tests/test_operations.py
python -m pytest -q tests/test_changes_apply.py tests/test_checks_engine.py
python -m pytest -q -m "not slow"
python -m pytest -q --collect-only          # last line: expected 729
rg -n "^\s*(from|import)\s+textual" s19_app/tui/operations/                      # expect 0 hits
rg -n "^\s*(from|import)\s+textual|^\s*from\s+(s19_app\.tui\.|\.{1,2})(app|screens)\b\s*import|^\s*from\s+(s19_app\.tui|\.{1,2})\s+import\s+.*\b(app|screens)\b|^\s*import\s+s19_app\.tui\.(app|screens)\b" s19_app/tui/operations/   # §5.1 P8b widened form; expect 0 hits
```

## 4. Test results (executed 2026-06-11, this worktree)

1. `python -m pytest -q tests/test_operations.py` → **7 passed in 0.46s** (0 failed, 0 skipped).
2. `python -m pytest -q tests/test_changes_apply.py tests/test_checks_engine.py` → **23 passed in 0.50s**.
3. `python -m pytest -q -m "not slow"` → **677 passed, 29 skipped, 20 deselected, 3 xfailed in 171.51s** — 0 failures. Ledger: batch-07 close lean-green was 670 passed; 670 + 7 = 677. ✓
4. `python -m pytest -q --collect-only` → **729 tests collected** (pre-state baseline 722 + 7 = 729). ✓ (§5.3 pins 733 for the FULL batch — the remaining +4 are TC-007 at I2 and TC-010..TC-012 at I3.)
5. No-textual probe on `s19_app/tui/operations/` → **0 hits, exit 1**. ✓
6. §5.1 P8b widened reverse-import probe on `s19_app/tui/operations/` → **0 hits, exit 1**. ✓ (Probes run via bash `rg`; `rg` is not on the PowerShell PATH in this environment.)

Coverage-claim check: `test_operation_result_schema`, `test_identity_passthrough_s19`, `test_identity_passthrough_hex`, `test_placeholders_registered`, `test_registry_deterministic_order`, `test_unknown_operation_raises`, `test_operation_interface` all exist on disk in `tests/test_operations.py` → LLR-001.1/001.2/001.3/001.4/002.1/002.2/002.3 covered.

Assertion-count thresholds: TC-001 = 11 (7 field-presence + 1 fixed-clock equality + 1 ValueError + 2 disclosure ≥ the 11 required); TC-002/TC-003 = 15 each via `_assert_identity_passthrough` (3 identity + 9 equality + 3 status; each adds 1 fixture-sanity `file_type` assert on top); TC-004 = 6; TC-005 = 5; TC-006 = 2; TC-009 = 11 (≥6 required: 3×id + 3×title + 3×describe + 1 uniqueness + 1 TypeError).

## 5. Risks

- TC-002/TC-003 share `_assert_identity_passthrough`; a future edit weakening it weakens both LLRs at once (mitigated by the per-test fixture-kind sanity asserts).
- `STATUS_DOMAIN` is a `frozenset` (matches the spec's set-literal spelling) whereas the `DISPOSITION_DOMAIN` precedent is an ordered tuple; status has no canonical-order consumer, so order is irrelevant — flagged in case the reviewer prefers strict precedent conformance.
- `Operation.describe` is abstract alongside `execute`; the spec only mandates ABC rejection for missing `execute` — a subclass missing only `describe` also raises `TypeError`, which is stricter, not looser.
- P11 (filesystem-call probe) is scheduled for Phase 4 over the package + service; not yet run here (service does not exist yet). Manual reading: the package contains no `open(`/`write_*`/`mkdir`/`shutil` calls.

## 6. Pending items

- **I2:** `s19_app/tui/services/operation_service.py` (`run_operation` + injectable registry seam) + TC-007 in `tests/test_operations.py` (re-opens the 729 → 730 collection count); conditional `services/__init__.py` export line (C-5).
- **I3:** TUI view — `OperationsScreen` in `screens.py`, binding/action/callback in `app.py`, `styles.tcss`, `tests/test_tui_operations_view.py` (TC-010..TC-012; collection → 733).
- Phase-4: re-run P11 and the P8b probe including `services/operation_service.py`; LLR-004.4 no-`@work` diff inspection.

## 7. Suggested next task

Increment I2: `s19_app/tui/services/operation_service.py` with `run_operation(operation_id, loaded, *, now_fn=None)` forwarding `now_fn` unchanged, propagating the LLR-002.3 `KeyError`, with the `check_runner`-style injectable registry seam (`change_service.py:342` precedent) + TC-007 appended to `tests/test_operations.py` (2 files).
