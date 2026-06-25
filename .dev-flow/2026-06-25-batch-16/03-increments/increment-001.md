# Increment 1 — Payload + handler threading + round-trip/collision/escape ATs (US-017)

**Batch:** 2026-06-25-batch-16 · **Branch:** claude/batch-16-gap2 · **Status:** awaiting gate · **Not committed.**
**LLRs:** 017.1 (payload), 017.2 (handler threading), 017.4 (round-trip + consumer pickup). **Inc 2 = the assignment UI (LLR-017.3).**

## 1. What changed
Closed batch-11 SCOPE-1 at the shipped surface: the project save now persists per-variant `assignments` + project-wide `batch` through `_handle_save_dialog`. `SaveProjectPayload` gained `batch`/`assignments` (frozen-dataclass `field` defaults); `_write_and_verify_manifest` gained `*, batch, assignments` threaded from the payload into BOTH `write_project_manifest` AND `verify_written_manifest` (R1). No UI (Inc 2) — payload populated programmatically in the pilots.

## 2. Files (4; ≤5)
`s19_app/tui/screens.py` (payload), `s19_app/tui/app.py` (handler threading), `tests/test_tui_manifest_save.py` (AT-017.1/.3/.4/.5 + TC-301/302/303), `tests/test_variant_execution.py` (AT-017.2 + collision-id guard).

## 3. How to test
`pytest tests/test_tui_manifest_save.py tests/test_variant_execution.py -q` · counterfactual: `git stash push -- s19_app/tui/app.py` → 4 handler ATs RED → `git stash pop` → green · `ruff check s19_app/tui/screens.py s19_app/tui/app.py`.

## 4. Test results
Targeted **22 passed**; full suite **897 passed / 0 failed**; collection **922 → 929 (+7)**. Counterfactual captured (AT-017.1/.4/.5 + TC-302/303 RED pre-fix; AT-017.3 is a no-regression guard, AT-017.2 writes its own manifest). Coverage-claim: all nodes verified on disk (at017_1/3/4/5, tc301, tc302_303, at017_2, + `test_duplicate_stem_ids_become_filenames`). screens.py ruff clean; app.py only the pre-existing C-7 F401/F402 (not introduced).

## 5. Verification (mine + code-reviewer)
- code-reviewer **APPROVE-WITH-NITS** (0 HIGH/0 MED/2 LOW). **R1 correct = YES** (TC-302/303 asserts write-intent == verify-intent), **D-KEY collision non-vacuous = YES** (AT-017.5 seeds `fw.s19`+`fw.hex` → keys by full filename `fw.hex`; would fail on `Path.stem`), **counterfactual genuine = YES** (independently reverted threading → exactly 4 ATs RED).
- My spot-check: diff = 4 files (0 frozen/substrate — `manifest_writer.py`/`variant_execution_service.py` UNCHANGED), nodes on disk, 929 collected.
- 2 LOW nits (F1 unrestored monkeypatch — pre-existing convention; F2 a redundant weak assertion line in AT-017.4 that doesn't affect its verdict) — non-blocking.

## 6. Pending
Inc 2 — `SaveProjectScreen` per-variant assignment UI (workarea-restricted) + `action_save_project` wiring + TC-304/305/306. Depends on these payload fields.

## Gate
0 HIGH; awaiting operator approval to commit Inc 1 + advance to Inc 2.
