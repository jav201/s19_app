# Increment E2 — apply engine + ChangeSummary + linkage + S19 save-back — batch-07

**Date:** 2026-06-10 · **Agent:** software-dev (orchestrator-verified) · **LLRs:** 001.6, 002.1–002.6, engine halves of 002.7/002.8 · **TCs:** TC-006, TC-009..014, TC-051-engine

## 1. What changed
- **`changes/apply.py`** (NEW, 779 L): `classify_containment` (LLR-001.6 — MemoryStatus vs ranges via sorted-range primitives; no-image → UNVALIDATED_NO_IMAGE, no issues); `apply_change_document` (pure function — ERROR/kind-gate → all-`blocked` zero-write; INSIDE-only writes with before-capture; mutates only applied ranges; linkage standalone/mac/a2l/both + `linkage_symbol` via `range_index` primitives); `save_patched_image` (S19-only per D-1 — F-S-01 sanitizer: bare name, forced extension, Windows reserved basenames CON/PRN/AUX/NUL/COM1-9/LPT1-9 + trailing dot/space → MF-WRITE-CONTAINMENT; staged write via `copy_into_workarea`; `source_kind != "s19"` refused with clear issue → None).
- **`changes/model.py`** (extended): `ChangeSummary` per canonical C-6 — summary `{source_path, kind, encoding, value_mode, timestamp_utc, variant_id, counts incl. blocked, saved_path, issues}`, per-entry `{entry_type, address_start, address_end, before_bytes, after_bytes, disposition, linkage, linkage_symbol}`; deterministic `to_dict()`; injectable `now_fn` (B-4).
- **`changes/io.py`** (extended): `emit_s19_from_mem_map` — structurally valid S19 emitter (address-width records + checksums + terminator); acceptance = emitted text re-parses via `S19File` to a mem_map equal to input.
- **Tests:** `test_changes_apply.py` (403 L), `test_changes_linkage.py`, `test_changes_containment.py` — incl. serialization-determinism + fixed-clock double-apply on deep copies (B-4), 3 adversarial filenames, HEX refusal, both-linked-OUTSIDE-still-skipped, 5 containment cases.

## 2. Files
5 budget: `apply.py` (new), `io.py`/`model.py` (+`__init__.py` facade re-exports) extended, 3 new test files.

## 3. How to test
`python -m pytest -q tests/test_changes_apply.py tests/test_changes_linkage.py tests/test_changes_containment.py` · regression: the E1 suites · full lean.

## 4. Results (verbatim, orchestrator-verified)
- E2 suites: `23 passed in 0.47s` · E1 regression: `42 passed in 0.62s`
- Lean: `840 passed, 29 skipped, 19 deselected, 3 xfailed in 191.69s` — **0 failures**; ledger exact: 817 + 23 = 840 ✓ (ΣN_i = 65)
- No-Textual grep: 0 · diff confined to the 5 files ✓

## 5. Risks
- The S19 emitter is new code on a critical output path; its re-parse acceptance test mitigates, and E2E coverage grows in E6/E7.
- TUI halves of 002.7 (prompt) / 002.8 (panel visibility) deliberately deferred to E3a — tracked.

## 6. Deviations
None. core.py untouched (emitter needed no parser change).

## 7. Next
E3a — consolidated v2 Patch Editor panel + `change_service.py` (UI half of 002.7/002.8, LLR-003.1/.2/.4 partial; ≤5 code files).
