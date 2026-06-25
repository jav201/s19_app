# Increment 2 — Backend save-flow threading (US-015)

**Batch:** 2026-06-23-batch-14 · **Branch:** claude/batch-14-us015 · **Status:** awaiting gate · **Not committed.**
**LLR:** LLR-015.3 (backend half). **Dispositions:** C1 (S19-branch-only dispatch), F-A-05 (two-hop threading). **Inc3 = selector UI + preserve/synthesize S0 policy + pilot AT (deferred).**

## 1. What changed
Threaded `bytes_per_line=32` + `s0_header=None` through the backend S19 save path, **S19-branch-only** at the polymorphic dispatch (C1) so the Intel-HEX emitter is called exactly as before. No UI, no header policy (Inc3).

## 2. Files modified (4; ≤5)
- `s19_app/tui/changes/apply.py` — `save_patched_image` +2 params; kwargs passed to `emit(...)` only under `source_kind=="s19"` (`:701`); HEX branch unchanged.
- `s19_app/tui/services/change_service.py` — `save_patched` +2 params, forwarded (two-hop F-A-05).
- `s19_app/tui/services/variant_execution_service.py` — `:711` call passes `bytes_per_line=32`.
- `tests/test_changes_apply.py` — TC-219 (save_patched_image S19 thread), TC-220 (through change_service two-hop), TC-220b (HEX unaffected — real TypeError guard).

## 3. How to test
`pytest tests/test_changes_apply.py -q` · `pytest tests/test_engine_unchanged.py -q` · `pytest tests/test_change_service.py tests/test_manifest_verify.py tests/test_checks_engine.py -q` · `ruff check <changed>`.

## 4. Test results
test_changes_apply.py **41 passed** (+3); engine-frozen guard 1 passed (0 diffs); call-site consumers 29 passed. Ledger **916 → 919 (+3)**. Spot-check: diff = 4 files (0 frozen); C1 branch at apply.py:701; TC-219/220/220b on disk.

## 5. Risks / notes
- **C1 closed:** code-reviewer + TC-220b prove the HEX save-back path is unaffected (the leaked-kwarg case would `TypeError` outside the try/except and fail the test).
- **Pre-existing ruff F401** `typing.List` `change_service.py:38` — confirmed on the unmodified tree (batch-15 carry C-7), NOT introduced; left surgical (backlog).
- DATA-record-map oracle (Amendment B) used in TC-219.

## 6. Pending
- **Inc3:** {16,32} selector UI (`screens_directionb.py`) + wire the operator choice from `app.py:1428` (currently silent default-32, F1 LOW) + preserve/synthesize S0 policy (source `s0_header` from `LoadedFile.source_s0_header`) + **C3 pilot AT-015.1** through the selector widget. C2 (CRC→32) needs no code (inherits default); document in A-5.

## 7. Independent review
code-reviewer: **APPROVE-WITH-NITS** (0 HIGH / 0 MED / 2 LOW: F1 app.py caller silent-default-32 [expected, Inc3 carry]; F2 explicit-32 redundant [leave]). C1 closed = YES. No security surface (threading only, write still via secured path).

## Gate
0 HIGH; awaiting operator approval to commit Inc2 + advance to Inc3 (final increment).
