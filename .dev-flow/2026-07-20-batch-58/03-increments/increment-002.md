# Increment 002 — E5 template-loader facade (LLR-E5.1/E5.2)

**Gate: APPROVED (self, autonomous)** · review STREAMLINED (zero-logic re-export facade; orchestrator self-verified logic-free + identity tests) · 2026-07-21

## 1. What changed
New `s19_app/tui/operations/crc_template.py` — a thin re-export facade (a2l-facade convention) over the template loader already shipped in `crc_designer_model.py`. Re-exports `read_template`/`parse_template`/`emit_template`/`CrcTemplate` + `READ_SIZE_CAP_BYTES`/`SizeProbe` by **object identity**; ZERO parsing/validation/read logic (verified — file is imports + `__all__` only). Mirrors `crc_config.py` collect-don't-abort posture; no untrusted-loader posture re-invented.

## 2. Files modified (frozen census: 0 frozen diffs)
- `s19_app/tui/operations/crc_template.py` — NEW (39 lines, facade)
- `tests/test_crc_template_loader.py` — NEW (6 tests)
- `crc_designer_model.py` NOT edited (source of truth). `git status --porcelain` = only the 2 new files. `test_engine_unchanged.py` green.

## 3. How to test
```
python -m pytest -q tests/test_crc_template_loader.py
python -m pytest -q tests/test_engine_unchanged.py
python -m ruff check s19_app/tui/operations/crc_template.py tests/test_crc_template_loader.py
```

## 4. Test results
- RED (C-20, net-new via move-aside not stash): `ImportError: cannot import name 'crc_template'` exit 2; file restored + verified.
- GREEN: `6 passed` exit 0. Ruff: All checks passed. Engine guard: 1 passed.
- Coverage: object-identity for all 6 re-exports (E5.1); collect-don't-abort through facade `read_template` for malformed JSON / over-cap (injectable size_probe) / non-object / missing-field → each `(None,[1 error])` never raises; valid → `(CrcTemplate,[])` (E5.2, AT-CRC-DSN-015).

## 5. Risks
Very low — import-only, no behavior. Identity test is a rename tripwire if the loader ever drifts a symbol.

## 6. Pending
None. Template round-trip AT-CRC-DSN-012 belongs to E6/view increments.

## 7. Suggested next
Inc-3 — E6 `parse_job` flat up-convert branch + `emit_job` (`crc_designer_model.py`, non-frozen); `tests/test_crc_job_upconvert.py`. Pre-state: `parse_job(DUMMY_CONFIG_TEXT)`→1 error; `emit_job` absent.

## Review streamlining note (recorded decision)
A full independent code-reviewer agent was skipped for THIS increment only, because the deliverable is a pure object-identity re-export with zero logic; the orchestrator read the file (logic-free confirmed) and the identity+fault-guard tests. All subsequent increments with real logic get the full code-reviewer pass.
