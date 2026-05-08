# Increment 5 — engine-side cross-file co-emission for the 8 incompatibility classes (LLR-007.2 / TC-062.a..h)

**Phase:** 3 — Implementation
**Increment:** 5 of N
**Date:** 2026-05-05
**Branch:** `claude/lucid-margulis-a63fd4`
**LLR target:**
- **LLR-007.2** — engine-side error + report co-emission. For each cross-file incompatibility class, verify that `validate_artifact_consistency` emits a `ValidationIssue` with the severity mandated by `REQUIREMENTS.md` Issues Tile Severity Policy AND that the issue is populated into the returned `ValidationReport.issues` list.
- Lays groundwork (per-class evidence table in §6) for **LLR-007.1** (class-enumeration audit, inspection) and **LLR-007.3** (severity matrix per active alias policy, inspection) — those LLRs consume this matrix in their inspection-method TCs in a later increment.
- Pre-condition closures from earlier increments referenced for traceability: **R-7** (snapshot infra; closed in increment 2), **Q-N04** (fixture-build allocation; closed in increment 2).

## 1. What changed

Extended `tests/test_validation_engine.py` with `class TestCrossFileCompatibilityCoEmission` containing **8 tests** (one per cross-file incompatibility class, TC-062.a through TC-062.h). Each test:

1. Loads the appropriate fixture (`overlap_s19_hex`, `large_project`, `duplicate_alias_mac`, or `corrupt_records`) introduced in increment 2.
2. Wires the parsers (`S19File`, `parse_a2l_file`, `parse_mac_file`) into the engine using a small static helper `_engine_inputs_from_paths` that mirrors how `tui/services/validation_service.build_validation_report` feeds parser output into `validate_artifact_consistency`. The helper is test-local (no production-code change).
3. Calls `validate_artifact_consistency(...)` directly and asserts both:
   - the expected `ValidationIssue.code` is present in `report.issues`, and
   - every matching issue carries the severity mandated by `REQUIREMENTS.md` Issues Tile Severity Policy under the **active alias policy = `"warn"` (engine default)**.
4. Each test method begins with a `# TC-062.X` comment naming its TC ID.

**Per-class evidence (resulting from running these 8 tests):**

| TC | Class | Fixture | `ValidationIssue.code` | Severity | Result |
|---|---|---|---|---|---|
| TC-062.a | S19/HEX overlap | `overlap_s19_hex` | *gap — no engine code; recommend `CROSS_S19_HEX_OVERLAP` at WARNING* | n/a | **xfail** (LLR-007.1 gap; Finding F-7.2-01) |
| TC-062.b | A2L tag range out of S19 range | `large_project` | `CROSS_A2L_S19_OUT_OF_RANGE` | WARNING | **pass** |
| TC-062.c | MAC address out of S19 range | `large_project` | `CROSS_MAC_S19_OUT_OF_RANGE` | WARNING | **pass** |
| TC-062.d | A2L↔MAC same-name address mismatch | `large_project` | `TRIPLE_NAME_ADDRESS_MISMATCH` | ERROR | **pass** |
| TC-062.e | symbol-only-in-MAC | `large_project` | `CROSS_MAC_ONLY_SYMBOL` | WARNING | **pass** |
| TC-062.f | symbol-only-in-A2L | `large_project` | `CROSS_A2L_ONLY_SYMBOL` | WARNING | **pass** |
| TC-062.g | duplicate-address alias | `duplicate_alias_mac` | `MAC_DUPLICATE_ADDRESS` (`classification="alias candidate"`) | WARNING (under `alias_policy="warn"`) | **pass** |
| TC-062.h | parsed-record corruption | `corrupt_records` | `MAC_PARSE_ERROR` | ERROR | **pass** (partial coverage; Finding F-7.2-02) |

**Active alias policy at audit time:** `validate_artifact_consistency(... alias_policy="warn" ...)` — confirmed by inspection of `s19_app/validation/engine.py:27`. Under this policy, the duplicate-alias class is classified as `alias candidate` (per `s19_app/validation/rules.py::classify_mac_duplicate_group`) and surfaces at WARNING tier. This is what LLR-007.3 records as the active configuration. **The same fixture under `alias_policy="error"` would surface at ERROR tier** — that branch is enumerated for LLR-007.3 in the per-class table below but is not exercised by code in this increment.

**Confirmed unchanged from `CLAUDE.md`:** `CROSS_MAC_S19_OUT_OF_RANGE` and `TRIPLE_NAME_ADDRESS_MISMATCH` are still the canonical codes; both are produced by the engine and asserted by tests. No rename.

## 2. Files modified

| File | Change |
|---|---|
| `tests/test_validation_engine.py` | EXTENDED. New `class TestCrossFileCompatibilityCoEmission` with 8 tests + a static helper `_engine_inputs_from_paths`; three new imports at the top (`pytest`, `S19File`, `parse_a2l_file`, `parse_mac_file`). ~150 LOC added. No changes to existing tests. |
| `.dev-flow/03-increments/increment-005.md` | NEW. This review packet. |

File count: **2** (well within the ≤5 cap; aim of "test extension + packet, no product change" met).

**Not modified:** `s19_app/validation/*` (per increment scope — Findings only, no rule fix), `tests/conftest.py` (per increment scope — fixtures from increment 2 used as-is).

## 3. How to test

```bash
pytest -q tests/
```

Targeted run for the new class:

```bash
pytest -v tests/test_validation_engine.py::TestCrossFileCompatibilityCoEmission
```

Single-class run example (TC-062.g):

```bash
pytest -v tests/test_validation_engine.py::TestCrossFileCompatibilityCoEmission::test_tc_062_g_duplicate_address_alias_emits_issue
```

## 4. Test results

**Full suite:**
```
210 passed, 2 skipped, 1 xfailed in 16.03s
```

Breakdown:
- 203 pre-existing tests still pass (no regression from increments 1, 1.5, 2, 3, 4).
- 7 new tests pass (TC-062.b/c/d/e/f/g/h).
- 1 new test xfails as designed (TC-062.a — LLR-007.1 gap, Finding F-7.2-01).
- 2 skipped tests are pre-existing (TC-047 junction-rejection POSIX skip + the other pre-existing skip; unchanged from increment 4 baseline).

**Targeted run (`TestCrossFileCompatibilityCoEmission`):**
```
test_tc_062_a_s19_hex_overlap_emits_issue            XFAIL
test_tc_062_b_a2l_range_out_of_s19_emits_issue       PASSED
test_tc_062_c_mac_address_out_of_s19_emits_issue     PASSED
test_tc_062_d_a2l_mac_name_address_mismatch_emits_issue PASSED
test_tc_062_e_symbol_only_in_mac_emits_issue         PASSED
test_tc_062_f_symbol_only_in_a2l_emits_issue         PASSED
test_tc_062_g_duplicate_address_alias_emits_issue    PASSED
test_tc_062_h_parsed_record_corruption_emits_issue   PASSED

7 passed, 1 xfailed in 9.24s
```

No xpass (no test that was expected to fail unexpectedly passed).

## 5. Risks

- **Findings logged in this increment** (both filed against `s19_app/validation/`, no fix in this increment per scope rule):

  - **F-7.2-01 (LLR-007.1 + LLR-007.2 gap, severity: major)** — The S19/HEX overlap class (TC-062.a) has no engine support. `validate_artifact_consistency` accepts a single `s19_ranges` list and an `overlapped_addresses` set scoped to **intra-S19** overlaps only. There is no `ValidationIssue.code` for "S19 and HEX disagree on the same address" and no rule that consumes both an S19 image and a HEX image side by side. **Recommended fix (later batch):** add a `CROSS_S19_HEX_OVERLAP` code at WARNING tier in `s19_app/validation/model.py`-adjacent constants and a rule in `s19_app/validation/rules.py` (or a new helper) that takes the two memory maps and emits one issue per overlapping address window. Today the test is `xfail(strict=False)` so the absence is visible in pytest output rather than silently skipped.

  - **F-7.2-02 (LLR-007.2 partial coverage for TC-062.h, severity: minor)** — Parsed-record corruption is collected at the parser layer for all three artefact types but only **MAC** corruption reaches the engine. Specifically:
    - S19: `S19File.get_errors()` collects the checksum-mismatch error but `validate_artifact_consistency` is not given an S19-errors hook, so the engine emits no issue for the corrupted S19 record.
    - A2L: when `ECU_ADDRESS` is omitted from a CHARACTERISTIC block, the parser produces a tag with `address=None`. The engine path `if not isinstance(addr, int): continue` (engine.py:117) silently skips it — no `A2L_INVALID_ADDRESS` is emitted because the address is `None` (parser fallback) rather than a non-int sentinel.
    - MAC: `MAC_PARSE_ERROR` is correctly emitted at ERROR tier — this is what TC-062.h asserts.
    **Recommended fix (later batch):** either pipe `S19File.get_errors()` and similar into the engine (new kwarg + new codes `S19_PARSE_ERROR`, `S19_CHECKSUM_MISMATCH`), or document that parser-layer corruption findings are surfaced separately (in which case LLR-007.2 needs to be reworded so "engine-side co-emit" only covers the MAC subset). The TC currently passes by asserting MAC alone; this is the narrowest engine-visible slice of the class.

- **xfail strictness:** TC-062.a uses `strict=False` (the pytest default). If a future engine change adds the missing `CROSS_S19_HEX_OVERLAP` code, the test will pass and become an `xpass` rather than break the suite — this is intentional and surfaces the gap closure naturally. When the gap is closed, the `xfail` decorator should be removed in the same change.

- **Severity for `MAC_DUPLICATE_ADDRESS` is alias-policy-dependent.** The TC-062.g test asserts WARNING under the engine default `alias_policy="warn"`. If the project changes the default to `"error"` (or wires an alias-policy override into the TUI), TC-062.g must be updated; this is exactly the kind of policy-shift LLR-007.3 is designed to catch on the inspection side. The matrix in §6 enumerates both severities so the audit-time configuration is unambiguous.

- **No new dependencies introduced.** No production-code changes. No fixture changes.

## 6. Pending items

### Per-class evidence table (consumed by LLR-007.1 inspection + LLR-007.3 severity matrix)

The table below is the durable artefact this increment hands forward. LLR-007.1 (class enumeration audit, TC-061) and LLR-007.3 (severity matrix per alias policy, TC-063) are both inspection-method LLRs whose audit matrix is built directly from this row set. Increment 9 (or wherever those inspection TCs land in the Phase 3 / Phase 4 plan) consumes this directly.

| TC | Class | Fixture | `ValidationIssue.code` | Severity (alias_policy="warn" — active) | Severity (alias_policy="error") | Engine rule (file:line) | Result |
|---|---|---|---|---|---|---|---|
| TC-062.a | S19/HEX overlap | `overlap_s19_hex` | **gap** — recommend `CROSS_S19_HEX_OVERLAP` | recommend WARNING | recommend WARNING | n/a (no rule) | **xfail** (Finding F-7.2-01) |
| TC-062.b | A2L tag range out of S19 range | `large_project` | `CROSS_A2L_S19_OUT_OF_RANGE` | WARNING | WARNING | `engine.py:128` | pass |
| TC-062.c | MAC address out of S19 range | `large_project` | `CROSS_MAC_S19_OUT_OF_RANGE` | WARNING | WARNING | `engine.py:90` | pass |
| TC-062.d | A2L↔MAC same-name address mismatch | `large_project` | `TRIPLE_NAME_ADDRESS_MISMATCH` | ERROR | ERROR | `engine.py:163` | pass |
| TC-062.e | symbol-only-in-MAC | `large_project` | `CROSS_MAC_ONLY_SYMBOL` | WARNING | WARNING | `engine.py:177` | pass |
| TC-062.f | symbol-only-in-A2L | `large_project` | `CROSS_A2L_ONLY_SYMBOL` | WARNING | WARNING | `engine.py:188` | pass |
| TC-062.g | duplicate-address alias | `duplicate_alias_mac` | `MAC_DUPLICATE_ADDRESS` (`classification="alias candidate"`) | **WARNING** | ERROR | `rules.py:377` (severity via `classification_to_severity`) | pass |
| TC-062.h | parsed-record corruption | `corrupt_records` | `MAC_PARSE_ERROR` (engine-visible subset only) | ERROR | ERROR | `rules.py:318` | pass (partial; Finding F-7.2-02) |

**Active alias policy at audit time:** `"warn"` (engine default per `validate_artifact_consistency` signature in `s19_app/validation/engine.py:27`). Recorded per LLR-007.3 acceptance criterion *"Active alias policy at audit time is logged in the audit packet."*

### Closures referenced by this increment
- **R-7** (Phase 1 risk — Textual snapshot infra) — closed in increment 2; mentioned here only because increment 6 (suggested next task) consumes it for HLR-007b panel-render.
- **Q-N04** (fixture-build allocation between increments 2 and 3+) — closed in increment 2 by landing the three new builders (`make_overlap_s19_hex`, `make_duplicate_alias_mac`, `make_corrupt_records`) and their fixtures in `tests/conftest.py`. This increment is the first downstream consumer of all three.
- **Public-contract codes confirmed unchanged from `CLAUDE.md`:** `CROSS_MAC_S19_OUT_OF_RANGE` (engine.py:90), `TRIPLE_NAME_ADDRESS_MISMATCH` (engine.py:163). Closes the corresponding traceability check in §1.4 of the requirements doc (constraint: "Issue codes referenced by tests are public contract").

### Items not closed in this increment (deferred per scope rules)
- F-7.2-01 (TC-062.a engine-rule gap) — defer to a follow-up batch where engine changes are in scope. Logged here as a `major`-severity Finding.
- F-7.2-02 (TC-062.h S19/A2L corruption not piped to engine) — defer to the same follow-up. Logged here as a `minor`-severity Finding (the MAC subset is engine-visible and asserted).
- The full LLR-007.1 enumeration audit (TC-061, inspection) and LLR-007.3 severity matrix (TC-063, inspection) are inspection-method TCs; the audit matrix above is the data they will consume, but the matrices need to be folded into the official Phase 3 audit packet for those TCs in their own increment.

## 7. Suggested next task

**Increment 6 — panel-render snapshot tests for the 8 classes (LLR-007.4 / TC-064 / TC-065).**

The natural follow-on. Use the same 8 fixtures + class mapping established in this increment, drive `S19TuiApp` headlessly via the Textual snapshot infrastructure landed in increment 2 (R-7 closure), and assert that for each class the corresponding `ValidationIssue` is **visibly rendered** in the Issues panel widget tree. This locks the engine→panel co-render contract and detects any silent filter between `validate_artifact_consistency` (now covered) and the rendered panel (HLR-007b).

Constraints carried forward:
- ≤5 files (likely just `tests/test_tui_app.py` extension + this packet's successor).
- TC-062.a stays `xfail` until the engine gap is closed in a separate batch — the panel-render snapshot for that class will also xfail because there is no issue to render.
- Re-use the per-class evidence table from §6 above as the parametrise table for TC-065.
