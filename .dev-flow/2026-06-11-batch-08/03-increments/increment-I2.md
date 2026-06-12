# Increment I2 — Operation service seam (batch 2026-06-11-batch-08, Phase 3)

Implements LLR-003.1 (TC-007) and the service half of LLR-003.2 (headless / no-reverse-import guarantee on `operation_service.py`; the view half lands at I3).

## 1. What changed

Created the NEW `s19_app/tui/services/operation_service.py` with the headless entry point `run_operation(operation_id: str, loaded: LoadedFile, *, now_fn: Optional[Callable[[], datetime]] = None) -> OperationResult` (LLR-003.1): resolution goes through the module-level injectable seam `operation_resolver` (default = the real `operations.registry.get_operation`, mirroring the `check_runner` seam precedent at `s19_app/tui/services/change_service.py:342`), `now_fn` is forwarded unchanged to the operation's keyword-only `execute` clock parameter (the single-delivery-route clause), and the LLR-002.3 `KeyError` propagates unchanged — no fallback, no fuzzy match. The module performs no I/O, writes nothing to disk, performs no parsing, and imports no Textual / `app` / `screens` modules. Appended TC-007 (`test_run_operation_service`) to `tests/test_operations.py` and updated its module-docstring TC map; the existing 7 tests are untouched. `s19_app/tui/services/__init__.py` was NOT modified (see §2).

## 2. Files modified

| File | Lines | Purpose |
|---|---|---|
| `s19_app/tui/services/operation_service.py` (NEW) | 91 | `run_operation` service entry point + module-level `operation_resolver` seam (LLR-003.1); headless by contract (LLR-003.2). |
| `tests/test_operations.py` (MODIFIED, 212 → 264) | 264 | TC-007 `test_run_operation_service` appended; docstring TC map gains the TC-007 bullet; imports gain `operation_service` (seam monkeypatch target) + `run_operation`. |

2 files — within the cap. **Conditional 11th file (`services/__init__.py`, Phase-2 m-4): NOT needed.** The file is a 1-line docstring with zero re-exports; every existing service (`load_service`, `change_service`, …) is imported by its module path, never through the package facade, so adding an export line would invent a new convention (engineering rule 11). Left untouched.

## 3. How to test

```bash
python -m pytest -q tests/test_operations.py
python -m pytest -q tests/test_tui_services.py tests/test_change_service.py
python -m pytest -q -m "not slow"
python -m pytest -q --collect-only          # last line: expected 730
rg -n "^\s*(from|import)\s+textual" s19_app/tui/operations/ s19_app/tui/services/operation_service.py                                  # expect 0 hits
rg -n "^\s*(from|import)\s+textual|^\s*from\s+(s19_app\.tui\.|\.{1,2})(app|screens)\b\s*import|^\s*from\s+(s19_app\.tui|\.{1,2})\s+import\s+.*\b(app|screens)\b|^\s*import\s+s19_app\.tui\.(app|screens)\b" s19_app/tui/operations/ s19_app/tui/services/operation_service.py   # §5.1 P8b widened; expect 0 hits
rg -n "open\(|write_text|write_bytes|mkdir|shutil|os\.remove|emit_s19_from_mem_map" s19_app/tui/operations/ s19_app/tui/services/operation_service.py   # §5.1 P11; expect 0 hits
```

## 4. Test results (executed 2026-06-11, this worktree)

1. `python -m pytest -q tests/test_operations.py` → **8 passed in 0.41s** (0 failed, 0 skipped). ✓
2. `python -m pytest -q tests/test_tui_services.py tests/test_change_service.py` → **21 passed in 0.41s** (both files exist; services regression guard green). ✓
3. `python -m pytest -q -m "not slow"` → **678 passed, 29 skipped, 20 deselected, 3 xfailed in 169.58s** — 0 failures. Ledger: I1 lean-green 677 + 1 (TC-007) = 678. ✓
4. `python -m pytest -q --collect-only` → **730 tests collected** (I1 baseline 729 + 1 = 730). ✓ (§5.3 full-batch pin 733; remaining +3 are TC-010..TC-012 at I3.)
5. No-textual probe on `s19_app/tui/operations/` + `s19_app/tui/services/operation_service.py` → **0 hits, exit 1**. ✓
6. §5.1 P8b widened reverse-import probe on the same targets → **0 hits, exit 1**. ✓
7. §5.1 P11 filesystem-call probe (`open\(|write_text|write_bytes|mkdir|shutil|os\.remove|emit_s19_from_mem_map`) on the same targets → **0 hits, exit 1**. ✓ (Probes run via bash `rg`, as at I1.)

Coverage-claim check: `def test_run_operation_service` confirmed on disk at `tests/test_operations.py:198` → LLR-003.1 covered. LLR-003.2 service half structurally verified by probes 5–6; final whole-target re-run stays scheduled for Phase 4 (after I3 creates the view consumers).

Assertion-count threshold (TC-007, ≥5 required): 8 executed — 3× `isinstance(result, OperationResult)` + 3× `operation_id` match (valid-id 3/3, counts as the spec's 3), 2× unknown-id `KeyError` (raises + verbatim id, spec's 1/1), 2× seam substitution (stub notes observed + `now_fn` forwarded as the same object, spec's 1/1 plus the forwarding clause made explicit).

## 5. Risks

- The seam is a module-level binding (`operation_resolver`), matching the spec's "module-level or parameter seam" wording; it is process-global, so a test that substitutes it without `monkeypatch` (which auto-restores) could leak into later tests. TC-007 uses `monkeypatch.setattr` — no leak.
- `run_operation` reads `operation_resolver` as a module global at call time; if a future refactor moves it into a `from … import operation_resolver` local binding, seam substitution silently stops working. TC-007's stub assertion would catch that regression.
- The stub in TC-007 returns `status="ok"` (exercising a second domain token); it intentionally does not test placeholder semantics — those stay owned by TC-002..TC-004.

## 6. Pending items

- **I3:** TUI view — `OperationsScreen` in `screens.py`, `x` binding/action/dismiss-callback in `app.py`, `styles.tcss` rules, `tests/test_tui_operations_view.py` (TC-010..TC-012; collection → 733).
- Phase-4: re-run P8b + P11 over the final whole target set; P8 (`\.execute\(` in `app.py`/`screens.py`) after I3; LLR-004.4 no-`@work` diff inspection.

## 7. Suggested next task

Increment I3: the HLR-004 operations view — `OperationsScreen` (`SelectVariantScreen` pattern, caller-supplied `(operation_id, title)` pairs), `Binding("x", "operations_view", "Operations", show=False)` + no-file guard + `run_operation` dismiss callback in `app.py`, `#operation_result_hex` widget rendering via the LLR-004.3 pinned `render_hex_view_text` tuple, `styles.tcss` block, and `tests/test_tui_operations_view.py` with TC-010..TC-012 (5 files).
