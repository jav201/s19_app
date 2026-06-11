# Increment E1 — `changes/` package core (v2 format + reader/validator) — batch-07

**Date:** 2026-06-10 · **Agent:** software-dev (orchestrator-verified) · **LLRs:** 001.1–001.5, 001.7, 001.8 · **TCs:** TC-001..005, 007, 008

## 1. What changed
- **`s19_app/tui/changes/model.py`** (254 L): `ChangeEntry` (string/bytes kinds, `addressed_range` from ENCODED byte length — `cdfx/memory.py` semantics migrated), `ChangeDocument` (5 metadata fields + entries + issues), `MemoryStatus` (migrated verbatim; cdfx original untouched — E3b deletes).
- **`s19_app/tui/changes/io.py`** (1,284 L): `read_change_document` — `resolve_input_path`, size cap pre-`json.load`, MF-* spellings as local constants, 10 `CHG-*` codes, **v1 detection precedes generic format validation** (F-A-03), **text-encoding allowlist** via `_is_text_encoding` (F-S-02), **pre-encode raw-length guard** (F-S-04), broadened encode-failure coverage (UnicodeEncodeError/ValueError/TypeError/LookupError), metadata-fatal → 0 entries (F-A-16); `write_change_document` — staged containment via `copy_into_workarea`, canonical `0x` string addresses. Strict wire grammar (two-hex-digit tokens; `^0x[0-9A-Fa-f]+$`).
- **`s19_app/tui/changes/validate.py`** (124 L): target-range derivation + intra-file collision (intersect OR identical address → 1 ERROR `CHG-COLLISION` per colliding entry, addresses-only messages per C-9).
- **`s19_app/tui/changes/__init__.py`** (81 L): minimal re-export facade (approved pattern; 6th physical file, reported).
- **Tests:** `test_changes_schema.py` (506 L) + `test_changes_collision.py` (189 L) — incl. `zlib_codec` allowlist rejection, `codes=[1114112]`, no-raw-bytes assertion, pre-encode-no-attempt case, v1 fixture → exactly 1 `CHG-V1-FORMAT` + 0 `CHG-FORMAT`, 6 collision geometries + 3-chain + multi-byte-encoding collision.

## 2. Files
6 physical (5 budget + facade): `changes/{__init__,model,io,validate}.py`, `tests/test_changes_{schema,collision}.py`.

## 3. How to test
`python -m pytest -q tests/test_changes_schema.py tests/test_changes_collision.py` · full: `python -m pytest -q -m "not slow"`

## 4. Results (verbatim, orchestrator-verified)
- New suites: `42 passed in 0.52s` (re-run independently).
- Lean: `817 passed, 29 skipped, 19 deselected, 3 xfailed in 231.60s` — **0 failures**; reconciliation exact: 775 + 42 = 817 ✓ (named-check ledger: R=0, ΣN_i=42 so far).
- No-Textual grep over `changes/`: 0 hits. Diff confined: only the 6 new files (+ dev-flow docs).

## 5. Risks
- `MF-*` constants duplicated locally (by design — E3b deletes `unified_io.py`; spellings asserted identical by tests).
- cdfx package untouched and still green (E3b owns deletions).

## 6. Deviations
None. All spec details implementable as written.

## 7. Next
E2 — apply engine + `ChangeSummary` + linkage + S19 save-back emitter (`changes/apply.py`, `emit_s19_from_mem_map` in `io.py`, `tests/test_changes_apply.py`, `test_changes_linkage.py`, `test_changes_containment.py` ≈ 5 files).
