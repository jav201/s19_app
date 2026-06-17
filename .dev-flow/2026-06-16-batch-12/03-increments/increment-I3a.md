# Increment I3a — Wire CrcOperation to be REAL (Path A)

**LLR:** LLR-002.2 (check path returns `status="ok"`, populates `crc_regions`, non-mutating — the OperationResult-assembly half). **Design (operator-locked):** config arrives as an `execute` keyword. **Scope:** 7 files (operator granted the ≤5 exception — the blast radius of making crc real spans the facade re-export + the TUI test's hardcoded placeholder expectations).

## 1. What changed
`CrcOperation` moved from `placeholders.py` into `crc.py` (its engine home — sets the pattern for future fill-ins) and became real:
- `execute(op_input, *, now_fn=None, config=None)` — `config` is an additive keyword on the base `(op_input, *, now_fn)` signature (Liskov-safe; generic callers pass `config=None`).
- `config is None` → `status="ok"`, `crc_regions=None`, note `"CRC: no config supplied — nothing to check"`.
- `config` supplied → `crc_regions=check_regions(op_input, config)`, `status="ok"`, summary note `"CRC: N region(s): M matched, K mismatched, J no-stored-value"` (tri-state `is True/is False/is None` counting — avoids the `0 == False` trap).
- `output` = fresh `LoadedFile` over the input snapshot (UNCHANGED, F-Q-02). `STATUS_DOMAIN` untouched; match/mismatch rides only `crc_regions[].matched`.

## 2. Files modified (7 — ≤5 exception approved)
`crc.py` (real CrcOperation + `_summarize_check`), `placeholders.py` (removed CrcOperation), `registry.py` (import from `.crc`), `operations/__init__.py` (re-export from `.crc`), `tests/test_operations.py` (crc status→ok, branched), `tests/test_crc_operation.py` (+2 execute tests), `tests/test_tui_operations_view.py` (TC-011/012 crc assertions→ok).

## 3. How to test
```
python -m pytest -q tests/test_operations.py tests/test_crc_operation.py tests/test_tui_operations_view.py tests/test_crc_engine.py tests/test_crc_config.py
python -m pytest -q -m "not slow"
ruff check <the 7 files>
```

## 4. Test results
- Targeted: 36 passed.
- `pytest -q -m "not slow"`: **809 passed**, 29 skipped, 3 xfailed (exit 0) — orchestrator re-ran (213s).
- ruff clean. **Ledger: 807→809 (+2: 2 execute tests); collection 860→862.** Frozen-engine guards green.

## 5. Independent review (code-reviewer) — CLEAN, 0 HIGH/MEDIUM
All 3 rule-ons passed: (a) no-config `status="ok"` is the existing token + unambiguous note (sound); (b) TC-002/011/012 updates PRESERVED intent (branched, not weakened; TC-012 hex baseline legitimately unchanged since check doesn't mutate); (c) removal/facade rewire clean — no dangling `placeholders.CrcOperation` importer, `_REGISTRY` order + `list_operation_ids()` unchanged. New `test_execute_with_config_populates_crc_regions` is non-vacuous (independent oracle + complement mismatch + explicit matched-flag asserts). 2 LOW notes carried (below).

## 6. Risks / carries
- **F-L1 (LOW → carry to I3b design):** a no-config run reports `status="ok"`; when the config-supply UI lands (I3b), the surface MUST distinguish "no config provided" from "checked, all matched" so green isn't misread as a passed check.
- **F-L2 (LOW, optional):** the base `Operation.execute` ABC docstring doesn't mention the per-operation `config` seam (discoverability only; not touched — model.py out of I3a scope).

## 7. Pending / next
- **I3b** — TUI surface (LLR-004.2 config text widget with dummy pre-fill + LLR-002.4 per-region result rows + LLR-002.3 worker-thread R-6); this is where `read_crc_config` is wired so the operator points at a config and the check actually runs through the TUI. Honor F-L1 (distinguish no-config from all-matched).
