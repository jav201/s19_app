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

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

Digests: SHA-256 of the bytes at the cited path, taken 2026-11-02. The eight transcripts live in `inc-1/evidence/`; the batch-level home `artifact_homes.evidence` declares (`repo:.dev-flow/2026-11-01-batch-101/evidence/`) does not cover the increment folders, so the paths below are the stored ones. The committed blobs are LF (`core.autocrlf=true`; `inc-1/evidence/` carries no `-text` attribute) and the stored bytes are CRLF — it is the bytes at the path that are hashed, per C-59's "the 64-hex digest of the bytes AT THAT PATH".

| Evidence artifact | Path — under `.dev-flow/2026-11-01-batch-101/inc-1/evidence/` | SHA-256 |
|---|---|---|
| red-base.txt | .dev-flow/2026-11-01-batch-101/inc-1/evidence/red-base.txt | 8c55feda82f02d2023ad7e5577cac4acce0e736040361e79721fe22714cf7562 |
| green-mirror.txt | .dev-flow/2026-11-01-batch-101/inc-1/evidence/green-mirror.txt | bc95a723701b5ad99e9609b8402b8d3e4a47527a741400d520d275f404f2be27 |
| mutants.txt | .dev-flow/2026-11-01-batch-101/inc-1/evidence/mutants.txt | dcd3f605a153dff73ff09cb531b3d8e4969350582209d8d4bba0a8822918a941 |
| mutants-r2.txt | .dev-flow/2026-11-01-batch-101/inc-1/evidence/mutants-r2.txt | 8489db27a2c682fe63915677ba505df3cb62b42c5f0523b15efa90b1580bd2a2 |
| integration-r1.txt | .dev-flow/2026-11-01-batch-101/inc-1/evidence/integration-r1.txt | 2973de94e2c13dd565c682b41a1b382297025793252f1a8a629209542bd15f8b |
| integration-r2.txt | .dev-flow/2026-11-01-batch-101/inc-1/evidence/integration-r2.txt | aca9f67839bf6b795337a7dd510123c37a48c15c0dcc1b20e17535c2317f3fea |
| law-guards.txt | .dev-flow/2026-11-01-batch-101/inc-1/evidence/law-guards.txt | 84e0eed98ec19324a3df0de6397f3383390b1f80a178e943c0a12ab064d5d12f |
| trace-check.txt | .dev-flow/2026-11-01-batch-101/inc-1/evidence/trace-check.txt | 51f9db62bb0df144496d667403ae8b9b21a4994c18c6478e3c0d614bc18003e0 |

| Field | Value |
|---|---|
| **Evidence files** | 8 transcripts, each cited with the digest of its stored bytes; they sit in `inc-1/evidence/`, outside the batch-level home `artifact_homes.evidence` declares — the home row predates the increment-record layout |

## 4b · Independent review — the lens the author cannot be

| Field | Value |
|---|---|
| **Independent review** | `code-reviewer` · **PASS-WITH-NOTES** — 0 HIGH · 4 MINOR (F1 rows outside a module unchecked · F2 two bare S0.2 ranges · F3 the AT-281 statement · F4 the D0-8 status), all four fixed in the E5 corrective pass · notes F6, F7, F8, F9 — fixed · F5 routed to the operator as ruling R-3 (retires G4, reversing review decision D0-8; G4's object no longer exists and its refutation clause prescribes G3-only) — `inc-1/04-validation.md` §Reviews · `inc-1/rulings.md` R-3. `security-reviewer` · **PASS-WITH-NOTES** — 0 HIGH / 0 MAJOR / 0 MINOR · F1 the absolute paths in evidence rewritten to placeholders by script · F2 the compensation for G4 is partial (R-3 records it) · F3 the `-text` attribute is no risk · F4 the evidence file that held failures renamed `integration-r1.txt` — `inc-1/04-validation.md` §Reviews. **Design reviews (E3, code-free):** `architect` round 1 **FAIL** (4 MAJOR) → round 2: 3 pass, MAJOR-4 fixed by the orchestrator (the S0 citations written in full; the probe reads 473/0) · `security-reviewer` **PASS-WITH-NOTES** — rulings R-1 … R-10 in `inc-1/rulings.md`. **There WAS a re-review (E3 round 2), because the design review blocked** on the 4 MAJORs. |

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
