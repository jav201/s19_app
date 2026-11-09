# Increment 001 — R-DOC-CANON · the strict-EARS requirements canon

Flow: dev-flow-v3-beta (operator ruling 2026-11-01). Records live in `.dev-flow/2026-11-01-batch-101/inc-1/`: `01-requirements.md` (US-101.1, R-DOC-CANON.1 … .11), `02-graph.md`, `rulings.md` (R-1 … R-10), `02-test-cases.md`, `04-validation.md`, `steps.log`, `evidence/`. Branch `b101-canon` from `e273181`.

## 1. What changed
- `REQUIREMENTS.md` is now the strict-EARS canon: 2623 rows `| Id | Form | Requirement |` in modules S0 … S17, each module with its context notes; the reading rules E1–E7 at the top.
- The earlier canon is kept byte for byte at `docs/requirements/history/REQUIREMENTS-legacy-e273181.md` (`-text`); the review that produced the new one (decisions, "Code today" snapshot, backlog `CODE-CHANGES.md`, reconciliation log) is in `docs/requirements/review/`.
- New guard `tests/test_requirements_canon.py` (11 tests, one per R-DOC-CANON row).
- Registry guards: G4 and TC-603 retired (the strict canon has no `- Validation:` lines; G4's refutation clause), AT-281's G4 arm, TC-609's anchor check, `g4_exempt_anchors` and AT-286's census removed; TC-497 retired; TC-607's count measured at 239.
- Docs that described the old format corrected; G4 marked retired in the registry spec and tools.

## 2. Files modified

Committed: `git diff --stat e273181..HEAD` plus the operator/batch-102 commits that landed on `main` after `base_ref` (charged to this batch's diff by the un-re-stamped `base_ref`). **SOURCE files: 0 / 4** under `s19_app/`.

| File | Kind | Traces to | Change |
|---|---|---|---|
| `.gitattributes` | config | US-101.1 | `docs/requirements/history/** -text` (ruling R-6) |
| `docs/requirements/history/REQUIREMENTS-legacy-e273181.md` | doc |  | the earlier canon moved here byte-for-byte (git rename, `-text`) |
| `docs/requirements/review/README.md` | doc |  | the strict-EARS review published as rationale (its "Code today" column is a snapshot as of e273181) |
| `docs/requirements/review/RECONCILE-570b4b5.md` | doc |  | the strict-EARS review published as rationale (its "Code today" column is a snapshot as of e273181) |
| `docs/requirements/review/S0-ears-strict.md` | doc |  | the strict-EARS review published as rationale (its "Code today" column is a snapshot as of e273181) |
| `docs/requirements/review/S1-ears-strict.md` | doc |  | the strict-EARS review published as rationale (its "Code today" column is a snapshot as of e273181) |
| `docs/requirements/review/S2-ears-strict.md` | doc |  | the strict-EARS review published as rationale (its "Code today" column is a snapshot as of e273181) |
| `docs/requirements/review/S3-ears-strict.md` | doc |  | the strict-EARS review published as rationale (its "Code today" column is a snapshot as of e273181) |
| `docs/requirements/review/S4-ears-strict.md` | doc |  | the strict-EARS review published as rationale (its "Code today" column is a snapshot as of e273181) |
| `docs/requirements/review/S5-ears-strict.md` | doc |  | the strict-EARS review published as rationale (its "Code today" column is a snapshot as of e273181) |
| `docs/requirements/review/S6-ears-strict.md` | doc |  | the strict-EARS review published as rationale (its "Code today" column is a snapshot as of e273181) |
| `docs/requirements/review/S7-ears-strict.md` | doc |  | the strict-EARS review published as rationale (its "Code today" column is a snapshot as of e273181) |
| `docs/requirements/review/S8-ears-strict.md` | doc |  | the strict-EARS review published as rationale (its "Code today" column is a snapshot as of e273181) |
| `docs/requirements/review/S10-ears-strict.md` | doc |  | the strict-EARS review published as rationale (its "Code today" column is a snapshot as of e273181) |
| `docs/requirements/review/S11-ears-strict.md` | doc |  | the strict-EARS review published as rationale (its "Code today" column is a snapshot as of e273181) |
| `docs/requirements/review/S12-ears-strict.md` | doc |  | the strict-EARS review published as rationale (its "Code today" column is a snapshot as of e273181) |
| `docs/requirements/review/S13-ears-strict.md` | doc |  | the strict-EARS review published as rationale (its "Code today" column is a snapshot as of e273181) |
| `docs/requirements/review/S14-ears-strict.md` | doc |  | the strict-EARS review published as rationale (its "Code today" column is a snapshot as of e273181) |
| `docs/requirements/review/S15-ears-strict.md` | doc |  | the strict-EARS review published as rationale (its "Code today" column is a snapshot as of e273181) |
| `docs/requirements/review/S16-ears-strict.md` | doc |  | the strict-EARS review published as rationale (its "Code today" column is a snapshot as of e273181) |
| `docs/requirements/review/S17-ears-strict.md` | doc |  | the strict-EARS review published as rationale (its "Code today" column is a snapshot as of e273181) |
| `tests/test_requirements_canon.py` | test | US-101.1 | new guard: one test per R-DOC-CANON.1 … .11 row + a shared row parser |
| `tests/test_batch91_registry_hygiene.py` | test | US-101.1 | `test_at286_no_declared_id_is_absent_from_the_registry` removed (ruling R-3) |
| `tests/test_tui_patch_json.py` | test | US-101.1 | one failure-message string re-pointed to the new canon (ruling R-4) |
| `tools/counterfactual_id_registry.py` | source | US-101.1 | G4 retired, TC-603/TC-497 retired, AT-281 G4 arm and TC-609 anchor check removed, `g4_exempt_anchors` and AT-286 census removed, `EXPECTED_SCANNED_TEST_FILES` measured (rulings R-2, R-3, R-7) |
| `tools/id_registry.py` | source | US-101.1 | comment only — G4 retired and the registry spec reworded (ruling R-3) |
| `tools/seed_id_registry.py` | source | US-101.1 | comment only — G4 retired (ruling R-3) |
| `.gitignore` | config | US-101.1 | `/prototypes/` ignore rule (operator 2026-11-05) |
| `prototypes/NOTES.md` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/abdiff_baseline.132w.svg` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/abdiff_variant_A.132w.svg` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/abdiff_variant_B.132w.svg` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/abdiff_variant_C.132w.svg` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/cmdbar_a2bdiff.HANDOFF.md` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/cmdbar_a2bdiff.NOTES.md` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/cmdbar_a2bdiff.prototype.html` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/cmdbar_a2bdiff.tui_prototype.py` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/cmdbar_baseline.120w.svg` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/cmdbar_variant_A.120w.svg` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/cmdbar_variant_B.120w.svg` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/cmdbar_variant_C.120w.svg` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/crc_designer.b59.inapp_prototype.py` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/crc_designer.blocks.excalidraw` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/crc_designer.blocks.png` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/crc_designer.flow.excalidraw` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/crc_designer.flow.png` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/crc_designer.prototype.py` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/crc_designer.screen.prototype.html` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/fb_p1_flow_persistence.DECISIONS.md` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/fb_p1_flow_persistence.NOTES.md` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/fb_p1_flow_persistence.artifact.html` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/fb_p1_flow_persistence.mockup.py` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/fb_p1_flow_persistence.prototype.py` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/fb_p1_flow_persistence.viz.html` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/fb_p1b_report.NOTES.md` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/fb_p1b_report.example.md` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/fb_p1b_report.prototype.py` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/flow_builder.NOTES.md` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/flow_builder.prototype.py` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/flow_builder.screen.prototype.html` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/legend_n8.INVENTORY.md` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/legend_n8.NOTES.md` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/legend_n8.kimi.NOTES.md` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/legend_n8.kimi.prototype.py` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/legend_n8.kimi_prompt.txt` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/legend_n8.prototype.py` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/legend_n8.variant_A.120w.svg` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/legend_n8.variant_A.80w.svg` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/legend_n8.variant_B.120w.svg` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/legend_n8.variant_B.80w.svg` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/legend_n8.variant_C.120w.svg` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/legend_n8.variant_C.80w.svg` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/legend_n8.variant_kimi.a2l.svg` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/legend_n8.variant_kimi.issues.svg` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/legend_n8.variant_kimi.mac.svg` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/legend_n8.variant_kimi.memory_map.svg` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/legend_n8.variant_kimi.workspace.svg` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/memmap_redesign.proposals.html` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/memmap_variant_a.HANDOFF.md` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/memmap_variant_a.prototype.py` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/memmap_variant_a.variant_A.120w.svg` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/memmap_variant_a.variant_B.120w.svg` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/memmap_variant_a.variant_C.120w.svg` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/screen_upgrades.HANDOFF-PLAN.md` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/screen_upgrades.NOTES.md` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/screen_upgrades.prototype.py` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/unload_state.NOTES.md` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/unload_state.prototype.py` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `prototypes/view-enhancements.prototype.html` | doc |  | `git rm` — archived to the operator's drive backup (2026-11-05); prototypes/ is ignored |
| `tests/test_loadfilescreen_input.py` | test | US-101.1 | redaction (operator decision 2026-11-02): the local account folder redacted |
| `tools/e13/capture.ps1` | source | US-101.1 | redaction (operator decision 2026-11-02): the local account folder redacted |
| `s19_app/tui/a2l_parameter_picker.py` | source | US-101.1 | added by batch-102; rebase-brought (batch-102 hot-fixes merged to main after base_ref) — charged to this batch's diff by the un-re-stamped base_ref |
| `s19_app/tui/capped_text_area.py` | source | US-101.1 | changed by batch-102; rebase-brought (batch-102 hot-fixes merged to main after base_ref) — charged to this batch's diff by the un-re-stamped base_ref |
| `s19_app/tui/os_clipboard_input.py` | source | US-101.1 | changed by batch-102; rebase-brought (batch-102 hot-fixes merged to main after base_ref) — charged to this batch's diff by the un-re-stamped base_ref |
| `s19_app/tui/styles.tcss` | config | US-101.1 | changed by batch-102; rebase-brought (batch-102 hot-fixes merged to main after base_ref) — charged to this batch's diff by the un-re-stamped base_ref |
| `s19_app/tui/workspace.py` | source | US-101.1 | changed by batch-102; rebase-brought (batch-102 hot-fixes merged to main after base_ref) — charged to this batch's diff by the un-re-stamped base_ref |
| `tests/test_b100_load_dialog.py` | test | US-101.1 | changed by batch-102; rebase-brought (batch-102 hot-fixes merged to main after base_ref) — charged to this batch's diff by the un-re-stamped base_ref |
| `tests/test_b102_a2l_refresh.py` | test | US-101.1 | added by batch-102; rebase-brought (batch-102 hot-fixes merged to main after base_ref) — charged to this batch's diff by the un-re-stamped base_ref |
| `tests/test_b102_bulk_add.py` | test | US-101.1 | added by batch-102; rebase-brought (batch-102 hot-fixes merged to main after base_ref) — charged to this batch's diff by the un-re-stamped base_ref |
| `tests/test_b102_clipboard.py` | test | US-101.1 | added by batch-102; rebase-brought (batch-102 hot-fixes merged to main after base_ref) — charged to this batch's diff by the un-re-stamped base_ref |
| `tests/test_b102_flow_block_edit.py` | test | US-101.1 | added by batch-102; rebase-brought (batch-102 hot-fixes merged to main after base_ref) — charged to this batch's diff by the un-re-stamped base_ref |
| `tests/test_b102_parameter_picker.py` | test | US-101.1 | added by batch-102; rebase-brought (batch-102 hot-fixes merged to main after base_ref) — charged to this batch's diff by the un-re-stamped base_ref |
| `tests/test_b102_patch_picker.py` | test | US-101.1 | added by batch-102; rebase-brought (batch-102 hot-fixes merged to main after base_ref) — charged to this batch's diff by the un-re-stamped base_ref |
| `tests/test_b97_width.py` | test | US-101.1 | changed by batch-102; rebase-brought (batch-102 hot-fixes merged to main after base_ref) — charged to this batch's diff by the un-re-stamped base_ref |
| `tests/test_capped_text_area.py` | test | US-101.1 | changed by batch-102; rebase-brought (batch-102 hot-fixes merged to main after base_ref) — charged to this batch's diff by the un-re-stamped base_ref |
| `tests/test_import_census.py` | test | US-101.1 | changed by batch-102; rebase-brought (batch-102 hot-fixes merged to main after base_ref) — charged to this batch's diff by the un-re-stamped base_ref |
| `tests/test_tui_patch_card.py` | test | US-101.1 | changed by batch-102; rebase-brought (batch-102 hot-fixes merged to main after base_ref) — charged to this batch's diff by the un-re-stamped base_ref |
| `tests/test_tui_patch_chips.py` | test | US-101.1 | changed by batch-102; rebase-brought (batch-102 hot-fixes merged to main after base_ref) — charged to this batch's diff by the un-re-stamped base_ref |


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
