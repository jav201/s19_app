# Traceability Matrix — s19_app — Batch 2026-05-05-batch-01

> Full chain: **User Story -> HLR -> LLR -> Test Case -> File:line**.
> Every row must be complete when closing the batch (phase 6). Incomplete rows = coverage gaps and must be listed in the gaps section.

This matrix is the consolidated traceability artefact for batch `2026-05-05-batch-01` (audit batch, batch 1 of the s19_app dev-flow). Source artefacts:

- [`.dev-flow/01-requirements.md`](../01-requirements.md) §2.6 (US), §3 (HLR), §4 (LLR), §5.2 (TC IDs)
- [`.dev-flow/02-review.md`](../02-review.md) §Deferrals (open major Findings)
- [`.dev-flow/03-increments/increment-001.md`](../03-increments/increment-001.md) … [`increment-009.md`](../03-increments/increment-009.md)
- [`.dev-flow/04-validation.md`](../04-validation.md) §2 (per-TC verdicts)
- [`.dev-flow/05-postmortem.md`](../05-postmortem.md) §3 (next-batch proposals)

The audit deliverable is a structured set of **Findings** about the integrity and functionality of `s19_app`, not a new product feature. "The system" referenced by `shall` clauses below is the audit process and its output artefacts (per `01-requirements.md` §1.1).

---

## 1. Master table

One row per US/HLR/LLR/TC tuple. `File:line` cites the asserting test or — for inspection-method TCs — the audit matrix in `increment-009.md`. `Status` follows Phase 4 verdicts: `pass` / `xfail` / `gap` / `skip`. Folded from `increment-009.md` §1–§9 per-LLR matrices and `04-validation.md` §2 per-TC walk.

| US | HLR | LLR | TC | File:line | Status | Notes |
|----|-----|-----|-----|-----------|--------|-------|
| US-001 | HLR-001 | — | TC-001 | [`increment-009.md` §1–§2](../03-increments/increment-009.md) | pass | Inspection — parser-rule audit matrices |
| US-001 | HLR-001 | LLR-001.1 | TC-002 | [`increment-009.md` §1](../03-increments/increment-009.md) | pass | S19 + Intel HEX matrix; R-READ-001 included |
| US-001 | HLR-001 | LLR-001.1 | TC-003 | `tests/test_core_srecord_validation.py` (full file) | pass | Vacuously satisfied — no drift found in TC-002 |
| US-001 | HLR-001 | LLR-001.1 | TC-004 | [`increment-009.md` §1](../03-increments/increment-009.md) | pass | R-HEX-001/002/003 + 9 extra Intel HEX rules |
| US-001 | HLR-001 | LLR-001.2 | TC-005 | [`increment-009.md` §2](../03-increments/increment-009.md) | pass | A2L + MAC matrix; cites `tests/test_tui_a2l.py` and `tests/test_tui_mac.py` |
| US-002 | HLR-002 | — | TC-010 | [`increment-009.md` §3](../03-increments/increment-009.md) | pass | Engine fusion of S19+A2L+MAC into one report |
| US-002 | HLR-002 | LLR-002.1 | TC-011 | [`increment-009.md` §8](../03-increments/increment-009.md) | pass | Forward direction code → rule mapping |
| US-002 | HLR-002 | LLR-002.1 | TC-012 | `tests/test_color_policy_round_trip.py` (16 tests) | pass | 5 parametric round-trip + 3 bidirectional + 2 colour-name + 5 idempotency + 1 integration |
| US-002 | HLR-002 | LLR-002.1 | TC-013 | `tests/test_color_policy_round_trip.py::test_validate_artifact_consistency_round_trip_on_large_project` | pass | Integration round-trip on `large_project` |
| US-002 | HLR-002 | LLR-002.2 | TC-014 | [`increment-009.md` §3](../03-increments/increment-009.md) | pass | Tier-mapping matrix; surfaces F-9.03-02 (`A2L_BROKEN_REFERENCE` severity drift) |
| US-002 | HLR-002 | LLR-002.3 | TC-090.a | `tests/test_validation_engine.py::TestIssueMessageScrubbing::test_strips_*` (3 tests) | pass | Control-char + ANSI scrub probes |
| US-002 | HLR-002 | LLR-002.3 | TC-090.b | `tests/test_validation_engine.py::TestIssueMessageScrubbing::test_*_truncated_*` (3 tests) | pass | 500-char truncation + idempotency |
| US-003 | HLR-003 | — | TC-020 | [`increment-009.md` §4](../03-increments/increment-009.md) | pass | 10 call sites enumerated, 7 routed, 3 documented bypasses |
| US-003 | HLR-003 | LLR-003.1 | TC-021 | [`increment-009.md` §4](../03-increments/increment-009.md) | pass | Worker- vs UI-thread split confirmed by import set + call graph |
| US-003 | HLR-003 | LLR-003.1 | TC-022 | [`increment-009.md` §4](../03-increments/increment-009.md) | pass | `load_service`, `a2l_service`, `validation_service` are the only routed entries |
| US-003 | HLR-003 | LLR-003.2 | TC-023 | `tests/test_tui_hexview.py` (6 new tests + AST walk) | pass | Public-knob boundary + `app.py` does not import private hexview helpers |
| US-004 | HLR-004 | — | TC-030 | [`increment-009.md` §5](../03-increments/increment-009.md) | pass | 41-row per-`R-*` verdict matrix |
| US-004 | HLR-004 | LLR-004.1 | TC-031 | [`increment-009.md` §5.2](../03-increments/increment-009.md) | pass | 5 promotions justified (R-TUI-002/005/009, R-A2L-004, R-PROJ-001) |
| US-004 | HLR-004 | LLR-004.1 | TC-032 | (none — `.dev-flow/evidence/TC-032/` missing) | **gap** | 9 demo evidence packs missing — see §3 below |
| US-004 | HLR-004 | LLR-004.1 | TC-033 | `tests/test_tui_app.py` (selection-jump suite) | pass | R-TUI-018/019/020 confirmed `Automated` |
| US-005 | HLR-005 | — | TC-040 | Increments 1, 7 audit umbrella | pass | LLR-005.1..5 covered |
| US-005 | HLR-005 | LLR-005.1 | TC-041 | `tests/test_tui_workspace.py::TestReadPathResolution` (4 cases) | pass | None / absolute / `project.toml` marker / no-marker |
| US-005 | HLR-005 | LLR-005.2 | TC-042 | `tests/test_tui_workspace.py::TestSanitizeProjectName` (8 cases) | pass | Self-flip-guards on F-7.7-02/03/04 (open Findings) |
| US-005 | HLR-005 | LLR-005.3 | TC-044 | `tests/test_tui_workspace.py::TestCopyIntoWorkareaContainment::test_source_size_over_cap_rejected` | pass | 256 MB cap |
| US-005 | HLR-005 | LLR-005.3 | TC-045 | `tests/test_tui_workspace.py::TestCopyIntoWorkareaContainment::test_source_symlink_rejected` | pass | POSIX symlink rejection |
| US-005 | HLR-005 | LLR-005.3 | TC-046 | `tests/test_tui_workspace.py::TestCopyIntoWorkareaContainment::test_destination_outside_workarea_rejected` | pass | Closes Phase 2 blocker S-001 |
| US-005 | HLR-005 | LLR-005.3 | TC-047 | `tests/test_tui_workspace.py::TestCopyIntoWorkareaContainment::test_junction_rejected_on_windows` | **gap** / skip | Windows-only; canonical Windows-host stdout pending re-attach (Q-N01); skips on Linux CI by design |
| US-005 | HLR-005 | LLR-005.4 | TC-048 | `tests/test_tui_workspace.py::TestValidateProjectFilesSymlinkAndCase` (3 cases) | pass | Self-flip guard on F-7.7-05 |
| US-005 | HLR-005 | LLR-005.5 | TC-049 | `tests/test_tui_workspace.py::TestSetupLoggingSurface` (3 cases) | pass | 5 MB cap + handler reuse + non-writable fallback |
| US-006 | HLR-006 | — | TC-050 | [`increment-009.md` §2](../03-increments/increment-009.md) (Output API row) | pass | `get_raw_value`, `get_physical_value`, `validate_characteristic` mapped |
| US-006 | HLR-006 | LLR-006.1 | TC-051 | `tests/test_tui_public_api.py::test_tc_051_*` | pass | Field-shape; F-7.7-06 logged (doc-vs-code drift) |
| US-006 | HLR-006 | LLR-006.1 | TC-052 | `tests/test_tui_public_api.py::test_tc_052_address_outside_memory_marks_failure` | xfail (F-7.7-07) | `validate_characteristic` merge order bug |
| US-001 | HLR-007a | — | TC-060 | [`increment-009.md` §6](../03-increments/increment-009.md) | pass | 8-class enumeration matrix |
| US-001 | HLR-007a | LLR-007.1 | TC-061 | [`increment-009.md` §6](../03-increments/increment-009.md) | pass | Class IDs X-007.1-a..h |
| US-001 | HLR-007a | LLR-007.2 | TC-062.a | `tests/test_validation_engine.py::TestCrossFileCompatibilityCoEmission::test_tc_062_a_s19_hex_overlap_emits_issue` | xfail (F-7.2-01) | Engine gap — `CROSS_S19_HEX_OVERLAP` code missing |
| US-001 | HLR-007a | LLR-007.2 | TC-062.b | `tests/test_validation_engine.py::test_tc_062_b_*` | pass | A2L tag range out of S19 (large_project) |
| US-001 | HLR-007a | LLR-007.2 | TC-062.c | `tests/test_validation_engine.py::test_tc_062_c_*` | pass | MAC out of S19 range (large_project) |
| US-001 | HLR-007a | LLR-007.2 | TC-062.d | `tests/test_validation_engine.py::test_tc_062_d_*` | pass | A2L<->MAC name/address mismatch (large_project) |
| US-001 | HLR-007a | LLR-007.2 | TC-062.e | `tests/test_validation_engine.py::test_tc_062_e_*` | pass | Symbol-only-in-MAC (large_project) |
| US-001 | HLR-007a | LLR-007.2 | TC-062.f | `tests/test_validation_engine.py::test_tc_062_f_*` | pass | Symbol-only-in-A2L (large_project) |
| US-001 | HLR-007a | LLR-007.2 | TC-062.g | `tests/test_validation_engine.py::test_tc_062_g_*` | pass | Duplicate-address alias (`duplicate_alias_mac`) |
| US-001 | HLR-007a | LLR-007.2 | TC-062.h | `tests/test_validation_engine.py::test_tc_062_h_*` | pass | Parsed-record corruption (`corrupt_records`); MAC subset only — F-7.2-02 documents S19/A2L gap |
| US-001 | HLR-007a | LLR-007.3 | TC-063 | [`increment-009.md` §7](../03-increments/increment-009.md) | pass | Severity-by-tier matrix per alias policy; logs active `"warn"`; F-9.07-01 dead `"error"` policy |
| US-001 | HLR-007b | — | TC-064 | `tests/test_tui_app.py::test_snapshot_harness_renders_issues_panel` | pass | Snapshot harness smoke (Q-N03 Option A) |
| US-001 | HLR-007b | LLR-007.4 | TC-065.a | `tests/test_tui_app.py::test_tc_065_a_s19_hex_overlap_panel_render` | xfail (F-7.2-01) | Panel-render carry-through |
| US-001 | HLR-007b | LLR-007.4 | TC-065.b | `tests/test_tui_app.py::test_tc_065_b_*` | pass | Panel-render |
| US-001 | HLR-007b | LLR-007.4 | TC-065.c | `tests/test_tui_app.py::test_tc_065_c_*` | pass | Panel-render |
| US-001 | HLR-007b | LLR-007.4 | TC-065.d | `tests/test_tui_app.py::test_tc_065_d_*` | pass | Panel-render |
| US-001 | HLR-007b | LLR-007.4 | TC-065.e | `tests/test_tui_app.py::test_tc_065_e_*` | pass | Panel-render |
| US-001 | HLR-007b | LLR-007.4 | TC-065.f | `tests/test_tui_app.py::test_tc_065_f_*` | pass | Panel-render |
| US-001 | HLR-007b | LLR-007.4 | TC-065.g | `tests/test_tui_app.py::test_tc_065_g_*` | pass | `MAC_DUPLICATE_ADDRESS` rendered |
| US-001 | HLR-007b | LLR-007.4 | TC-065.h | `tests/test_tui_app.py::test_tc_065_h_*` | pass | MAC subset; F-7.2-02 carry-through |
| US-002 | HLR-008 | — | TC-070 | [`increment-009.md` §8 + §9](../03-increments/increment-009.md) | pass | 17 codes mapped both directions |
| US-002 | HLR-008 | LLR-008.1 | TC-071 | [`increment-009.md` §8](../03-increments/increment-009.md) | pass | Forward direction; F-9.03-01 raised |
| US-002 | HLR-008 | LLR-008.2 | TC-072 | [`increment-009.md` §9](../03-increments/increment-009.md) | pass | Reverse direction; F-9.03-02, F-9.09-01 raised |
| US-002 | HLR-009 | — | TC-080 | `tests/test_validation_engine.py::TestEngineDeterminism` + `TestCoverageMetricsCorrectness` | pass | Determinism + coverage roll-up |
| US-002 | HLR-009 | LLR-009.1 | TC-081 | `tests/test_validation_engine.py::TestEngineDeterminism::test_validate_artifact_consistency_is_deterministic_on_large_project` | pass | Deep equality on issues + coverage; no non-determinism observed |
| US-002 | HLR-009 | LLR-009.2 | TC-082 | `tests/test_validation_engine.py::TestCoverageMetricsCorrectness` (3 tests) | pass | All 6 declared `CoverageMetrics` fields populated non-zero on `large_project` |

**Row count:** 60 TCs (matches `04-validation.md` §0 metric).

---

## 2. Coverage summary

Counts and percentages folded from [`04-validation.md`](../04-validation.md) §0 and [`increment-009.md`](../03-increments/increment-009.md) §0.

| Metric | Value |
|--------|-------|
| Total user stories | 6 |
| Covered user stories | 6 (100%) |
| Total HLR | 10 (HLR-001..HLR-009 with HLR-007 split into 007a + 007b) |
| Implemented HLR | 10 (100%) |
| Total LLR | 19 |
| Implemented LLR | 19 (100%) |
| Test cases | 60 |
| TC pass | 49 (82%) |
| TC xfail (documented Finding, treated as pass) | 3 (5%) |
| TC gap (deferred / evidence pending) | 11 (18%) — 9 demo packs in TC-032 + TC-047 Windows stdout + Linux-CI confirm |
| TC fail (blocker) | 0 |
| Test suite total (pytest -q) | 259 passed / 2 skipped / 3 xfailed / 0 failed |
| Net new tests added in batch | +86 (173 -> 259) |
| `R-*` rows reviewed (LLR-004.1) | 41 (28 confirmed / 5 promote / 2 drift / 6 unknown) |

### 2.1 Coverage by validation method

| Method | TC count | Notes |
|---|---|---|
| inspection | 22 | Audit-matrix evidence in `increment-009.md` §1–§9 |
| test (unit) | 14 | Mostly LLR-005 workspace + LLR-002.3 message scrubbing + LLR-006.1 accessor |
| test (integration) | 22 | LLR-007.2 (8 classes) + LLR-007.4 (8 classes) + LLR-009.1/2 + others |
| demo | 1 (TC-032) | 9 sub-packs needed; all currently `gap` |
| **Total** | **60** | — |

### 2.2 Suite trajectory across Phase 3 increments

| Increment | Tests | Δ |
|---|---|---|
| baseline | 173 | — |
| 1 (LLR-005.3) | 179 | +6 |
| 1.5 (test rename) | 180 | +1 |
| 2 (snapshot harness + fixtures) | 181 | +1 |
| 3 (LLR-002.3 scrubbing) | 187 | +6 |
| 4 (LLR-002.1 round-trip) | 203 | +16 |
| 5 (LLR-007.2 co-emission) | 210 | +7 |
| 6 (LLR-007.4 panel render) | 217 | +7 |
| 7 (LLR-005/006/003 sweep) | 255 | +38 |
| 8 (LLR-009.1/2) | 259 | +4 |
| 9 (audit matrices, doc-only) | 259 | 0 |

---

## 3. Detected gaps

> Incomplete rows, requirements without TC, or open Findings carrying into the next batch.

This batch surfaces **two distinct classes** of gap:

- **Phase 4 gaps (11)** — TC-032 demo evidence (9 packs) + TC-047 Windows stdout + Linux-CI confirm.
- **Open Findings (18)** — 3 major + 15 minor; all with closure plans in [`02-review.md` §Deferrals](../02-review.md) or [`increment-009.md` §10](../03-increments/increment-009.md).

### 3.1 Phase 4 gaps

| ID | Type | Description | Proposed action |
|----|------|-------------|-----------------|
| GAP-TC-032 | demo evidence | 9 demo packs missing under `.dev-flow/evidence/TC-032/`: R-TUI-003, R-TUI-008, R-TUI-009, R-TUI-010, R-A2L-003, R-A2L-004, R-PROJ-001, R-PROJ-002, R-TUI-016 | Batch B-2E (`05-postmortem.md` §3) — 1 hour manual capture session |
| GAP-TC-047 | Windows manual run | Q-N01 carry-forward — `pytest -q tests/test_tui_workspace.py::TestCopyIntoWorkareaContainment::test_junction_rejection` stdout pending re-attach to `increment-001.md` §6 from canonical Windows host | Batch B-2E or attach to current batch before sync |
| GAP-A-N02 | Linux CI confirm | TC-044/045/046 Linux pytest output pending append to `increment-001.md` §6 once the next CI run completes | Wait on next `main-tui` CI run; attach |

### 3.2 Open Findings (carry-forward, with closure plans)

Severity counts: **3 major + 15 minor**.

| ID | Type | Severity | Description | Source | Proposed batch |
|----|------|----------|-------------|--------|----------------|
| F-7.2-01 | Finding | major | Engine gap — `CROSS_S19_HEX_OVERLAP` code missing; carries TC-062.a + TC-065.a xfail | [increment-005](../03-increments/increment-009.md) | B-2A |
| F-7.2-02 | Finding | minor | Engine partial coverage — S19 checksum errors and A2L missing-`ECU_ADDRESS` not piped into engine | [increment-005](../03-increments/increment-009.md) | B-2A |
| F-7.7-02 | Finding | minor | `sanitize_project_name` does not reject Windows reserved device names | [increment-007](../03-increments/increment-009.md) | B-2B |
| F-7.7-03 | Finding | minor | `sanitize_project_name` does not enforce 64-char length cap | [increment-007](../03-increments/increment-009.md) | B-2B |
| F-7.7-04 | Finding | minor | `sanitize_project_name` does not detect Unicode confusables | [increment-007](../03-increments/increment-009.md) | B-2B |
| F-7.7-05 | Finding | minor | `validate_project_files` follows symlinks via `Path.is_file()` | [increment-007](../03-increments/increment-009.md) | B-2B |
| F-7.7-06 | Finding | minor | `REQUIREMENTS.md` documents `schema_ok / memory_checked / in_memory` triplet on per-tag accessor; code surfaces it on bulk validator | [increment-007](../03-increments/increment-009.md) | B-2B |
| F-7.7-07 | Finding | major | `validate_characteristic` returns wrong tag's enrichment when requested tag is not first in parsed list (broken merge order); carries TC-052 xfail | [increment-007](../03-increments/increment-009.md) | B-2A |
| F-9.01-01 | Finding | minor | `REQUIREMENTS.md` Reading/Parsing/Validation/Intel HEX sections — ≥9 Intel HEX rules covered by tests but no `R-HEX-*` row | [increment-009 §1](../03-increments/increment-009.md) | B-2D |
| F-9.02-01 | Finding | minor | `REQUIREMENTS.md` — no `R-MAC-*` row exists for the MAC parser | [increment-009 §2](../03-increments/increment-009.md) | B-2D |
| F-9.02-02 | Finding | minor | R-A2L-003, R-A2L-004 are `Manual`, no automated subprocess/dialog assertion | [increment-009 §2](../03-increments/increment-009.md) | B-2D / B-2E |
| F-9.02-03 | Finding | minor | A2L Structural Parsing / RECORD_LAYOUT / Raw Memory Extraction / COMPU_METHOD / Output API sections lack `R-*` numbering | [increment-009 §2](../03-increments/increment-009.md) | B-2D |
| F-9.03-01 | Finding | minor | `A2L_INVALID_ADDRESS` not asserted by direct code-string match in any test (covered indirectly via large_project round-trip) | [increment-009 §3 / §8](../03-increments/increment-009.md) | B-2A |
| F-9.03-02 | Finding | minor (severity drift) | `A2L_BROKEN_REFERENCE` emits at WARNING; `REQUIREMENTS.md` Issues Tile policy lists it under Errors | [increment-009 §3 / §9](../03-increments/increment-009.md) | B-2A |
| F-9.04-01 | Finding | minor (architecture) | `app.py:2716` direct `parse_mac_file(path)` call — no `mac_service` exists | [increment-009 §4](../03-increments/increment-009.md) | B-2C |
| F-9.04-02 | Finding | minor (architecture) | `app.py:3158` direct `S19File(...).get_overlap_addresses()` — overlap fetch not encapsulated in `validation_service` | [increment-009 §4](../03-increments/increment-009.md) | B-2C |
| F-9.04-03 | Finding | minor (architecture) | `app.py:3902` direct `parse_a2l_file(path)` — A2L cache lookup in app shell rather than `a2l_service` | [increment-009 §4](../03-increments/increment-009.md) | B-2C |
| F-9.07-01 | Finding | minor (API) | `classification_to_severity` has no `"error"` branch — `alias_policy="error"` is dead today | [increment-009 §6 / §9](../03-increments/increment-009.md) | B-2A |
| F-9.09-01 | Finding | minor (doc) | `REQUIREMENTS.md` §Issues Tile Severity Policy does not enumerate `A2L_UNRECOGNIZED_BLOCK` | [increment-009 §9](../03-increments/increment-009.md) | B-2A / B-2D |

**Major Findings (3):** F-7.2-01, F-7.7-07, plus the partial-closed pair {A-N02, Q-N01} treated as one major-equivalent in `04-validation.md` §0. Every major Finding has the mandatory `{ID, owner, target batch, blast radius if not fixed}` schema in [`02-review.md` §Deferrals](../02-review.md) (closes `01-requirements.md` §5.3 acceptance criterion).

---

## 4. Changes from previous batch

This is **batch 1** of the s19_app dev-flow under the V-model orchestrator. There is no previous batch.

| Field | Value |
|---|---|
| Previous batch | N/A (batch 1) |
| Carried-forward Findings from previous batch | None |
| Modified `R-*` traceability rows | None (any `R-*` doc edits are deferred to B-2D) |

When batch 2 opens, this section in its own traceability matrix will list the items closed from this batch's deferral register (per [`05-postmortem.md` §3](../05-postmortem.md): B-2A clears the largest cluster including the 3 xfail rows).

---

## 5. Quick bidirectional mapping

### 5.1 By user story

- **US-001 (parser-correctness)** → HLR-001, HLR-007a, HLR-007b → LLR-001.1, LLR-001.2, LLR-007.1, LLR-007.2, LLR-007.3, LLR-007.4 → TC-001..005, TC-060..063, TC-064, TC-065.a..h
- **US-002 (validation-engine severity)** → HLR-002, HLR-008, HLR-009 (with secondary trace from HLR-007a/b) → LLR-002.1, LLR-002.2, LLR-002.3, LLR-008.1, LLR-008.2, LLR-009.1, LLR-009.2 → TC-010..014, TC-090.a/b, TC-070..072, TC-080..082
- **US-003 (TUI orchestration boundary)** → HLR-003 → LLR-003.1, LLR-003.2 → TC-020..023
- **US-004 (REQUIREMENTS.md re-confirmation)** → HLR-004 → LLR-004.1 → TC-030..033
- **US-005 (workspace-IO security)** → HLR-005 → LLR-005.1, LLR-005.2, LLR-005.3, LLR-005.4, LLR-005.5 → TC-040..049
- **US-006 (public API contract)** → HLR-006 → LLR-006.1 → TC-050..052

### 5.2 By code file

Audited files. Each row lists the LLRs that touch it and the asserting test. Inspection-method rows list their audit-matrix location instead.

| Code file | LLR(s) | Test(s) / matrix |
|---|---|---|
| `s19_app/core.py` | LLR-001.1, LLR-007.1, LLR-007.2 | `tests/test_core_srecord_validation.py` (full file); audit matrix in [`increment-009.md` §1](../03-increments/increment-009.md) |
| `s19_app/hexfile.py` | LLR-001.1, LLR-007.1, LLR-007.2 | `tests/test_hexfile.py` (full file); audit matrix in [`increment-009.md` §1](../03-increments/increment-009.md) |
| `s19_app/tui/a2l.py` (+ facades) | LLR-001.2, LLR-006.1, LLR-007.1 | `tests/test_tui_a2l.py`, `tests/test_tui_public_api.py`; audit matrix in [`increment-009.md` §2](../03-increments/increment-009.md) |
| `s19_app/tui/mac.py` | LLR-001.2, LLR-007.1 | `tests/test_tui_mac.py`, `tests/test_validation_mac.py`; audit matrix in [`increment-009.md` §2](../03-increments/increment-009.md) |
| `s19_app/range_index.py` | (transitive — used by validation engine) | `tests/test_range_index.py` |
| `s19_app/validation/engine.py` | LLR-002.1, LLR-002.2, LLR-007.2, LLR-008.1, LLR-008.2, LLR-009.1, LLR-009.2 | `tests/test_validation_engine.py`, `tests/test_color_policy_round_trip.py` |
| `s19_app/validation/rules.py` | LLR-002.1, LLR-002.2, LLR-002.3, LLR-007.3, LLR-008.1, LLR-008.2 | `tests/test_validation_a2l.py`, `tests/test_validation_mac.py`, `tests/test_validation_engine.py` |
| `s19_app/validation/model.py` | LLR-002.1, LLR-002.3, LLR-009.2 | `tests/test_validation_engine.py::TestIssueMessageScrubbing`, `TestCoverageMetricsCorrectness` |
| `s19_app/tui/color_policy.py` | LLR-002.1 | `tests/test_color_policy_round_trip.py` (16 tests) |
| `s19_app/tui/app.py` | LLR-003.1, LLR-007.4 | `tests/test_tui_app.py`; audit matrix in [`increment-009.md` §4](../03-increments/increment-009.md) |
| `s19_app/tui/models.py` | LLR-003.1 (LoadedFile snapshot) | `tests/test_tui_app.py`, `tests/test_tui_workspace.py` |
| `s19_app/tui/services/load_service.py` | LLR-003.1 | `tests/test_tui_services.py` |
| `s19_app/tui/services/a2l_service.py` | LLR-003.1 | `tests/test_tui_services.py` |
| `s19_app/tui/services/validation_service.py` | LLR-003.1 | `tests/test_tui_services.py` |
| `s19_app/tui/hexview.py` | LLR-003.2 | `tests/test_tui_hexview.py`, `tests/test_tui_helpers.py` |
| `s19_app/tui/screens.py` | (transitive — Save/Load/Project modals) | `tests/test_tui_app.py` |
| `s19_app/tui/workspace.py` | LLR-005.1, LLR-005.2, LLR-005.3, LLR-005.4, LLR-005.5 | `tests/test_tui_workspace.py` (TestReadPathResolution / TestSanitizeProjectName / TestCopyIntoWorkareaContainment / TestValidateProjectFilesSymlinkAndCase / TestSetupLoggingSurface) |

---

## 6. Batch sign-off

| Field | Value |
|-------|-------|
| Batch ID | `2026-05-05-batch-01` |
| Closing date | `2026-05-07` (Phase 5 close); Phase 6 docs delivered `2026-05-07` |
| Total iterations (sum of phases) | 16 (Phase 1: 3 + Phase 2: 2 + Phase 3: 9 increments [1, 1.5, 2–9] + Phase 4: 1 + Phase 5: 1) |
| Validation passed | yes — `gap` verdict (Phase 4 pass-with-known-gaps; 0 blockers; all gaps doc/manual-evidence only) |
| Phase 5 user gate decision | `close batch` (recommended in [`05-postmortem.md` §5](../05-postmortem.md) option 1) |
| pytest baseline at gate | 259 passed / 2 skipped / 3 xfailed / 0 failed (Python 3.14.4, pytest 9.0.3 on Windows 11) |
| Open Findings carried to next batch | 18 (3 major + 15 minor) — all with closure plans |
| Next batch recommendation | B-2A (engine completeness) — clears 3 xfails + 7 Findings ([`05-postmortem.md` §3](../05-postmortem.md)) |
| Synced to Obsidian | (post-merge — `/dev-flow-sync-en` after PR close) |
