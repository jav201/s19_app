# Increment 001 — R-DOC-CANON · the strict-EARS requirements canon

Flow: dev-flow-v3-beta (operator ruling 2026-11-01). Records live in `.dev-flow/2026-11-01-batch-101/inc-1/`: `01-requirements.md` (US-101.1, R-DOC-CANON.1 … .11), `02-graph.md`, `rulings.md` (R-1 … R-10), `02-test-cases.md`, `04-validation.md`, `steps.log`, `evidence/`. Branch `b101-canon` from `e273181`.

## 1. What changed
- `REQUIREMENTS.md` is now the strict-EARS canon: 2623 rows `| Id | Form | Requirement |` in modules S0 … S17, each module with its context notes; the reading rules E1–E7 at the top.
- The earlier canon is kept byte for byte at `docs/requirements/history/REQUIREMENTS-legacy-e273181.md` (`-text`); the review that produced the new one (decisions, "Code today" snapshot, backlog `CODE-CHANGES.md`, reconciliation log) is in `docs/requirements/review/`.
- New guard `tests/test_requirements_canon.py` (11 tests, one per R-DOC-CANON row).
- Registry guards: G4 and TC-603 retired (the strict canon has no `- Validation:` lines; G4's refutation clause), AT-281's G4 arm, TC-609's anchor check, `g4_exempt_anchors` and AT-286's census removed; TC-497 retired; TC-607's count measured at 239.
- Docs that described the old format corrected; G4 marked retired in the registry spec and tools.

## 2. Files modified
See `git diff --stat e273181..b101-canon`. Source (non-test, non-doc): `tools/counterfactual_id_registry.py`, `tools/id_registry.py` (comment), `tools/seed_id_registry.py` (comment). No product file under `s19_app/`.

## 3. How to test
From the repo root: `env -u NO_COLOR PYTHONPATH=. python -m pytest -q tests/test_requirements_canon.py tests/test_id_registry.py tests/test_batch91_registry_hygiene.py tests/test_report_addendum_bound.py tests/test_tui_patch_json.py tests/test_engine_unchanged.py`.

## 4. Test results
Guard RED 11/11 on `e273181`, GREEN 11/11; mutants 20/20 RED; integration 85 passed, 2 failed — both pre-existing on `e273181` (golden `Tool version: 0.1.0` vs `1.0.0rc1`); `trace_check.py` 0 gaps. Details in `inc-1/04-validation.md`.

## 5. Risks
- G4's role (registry liveness of ids cited by the canon) is only partly covered until the test-case records' guard lands (R-3).
- The review's "Code today" column is a snapshot as of `e273181` and goes stale.
- Windows only; Ubuntu CI not run. The `-text` attribute makes the history file LF on every checkout.

## 6. Pending
- **Operator:** ruling R-3 reverses review decision D0-8 (keep G4, update its anchors) — confirm at the batch gate.
- Batch owner: the two pre-existing golden failures (`Tool version`), `.dev-flow/_derived/ATLAS-IFC.md` regeneration.
- The test-case records and their status document: a later increment of this batch.

## 7. Suggested next task
Merge `b101-canon` as batch-101's first increment, rebase the defect increments onto it (re-measure `EXPECTED_SCANNED_TEST_FILES` if they add test files), then the test-case increment.
