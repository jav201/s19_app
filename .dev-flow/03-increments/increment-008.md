# Increment 8 — engine determinism + CoverageMetrics correctness (LLR-009.1, 009.2)

**Phase:** 3 — Implementation
**Increment:** 8 of N (final code-test increment of the audit batch)
**Date:** 2026-05-05
**Branch:** `claude/lucid-margulis-a63fd4`
**LLR targets:**
- **LLR-009.1** — `validate_artifact_consistency` repeat-run determinism on `large_project` (TC-081).
- **LLR-009.2** — `CoverageMetrics` field-presence + non-zero count audit on non-empty input + zero-baseline on empty input (TC-082).

This is a **test-only** increment. No `s19_app/` source changed. **No new Findings raised** — both LLRs pass cleanly on the current engine.

## 1. What changed

`tests/test_validation_engine.py` extended with two new test classes (4 new tests). The increment promotes the §6.3 R-5 inspection-only closure ("`make_large_*` use `seed=0` defaults, therefore `large_project` is deterministic") to an automated assertion, and audits the `CoverageMetrics` dataclass-vs-engine field coverage.

### TC-081 — `class TestEngineDeterminism` (LLR-009.1)
Single test `test_validate_artifact_consistency_is_deterministic_on_large_project`:
- Runs `validate_artifact_consistency(...)` twice on the `large_project` fixture (S19 + A2L + MAC, all `seed=0`).
- Asserts `report1.issues == report2.issues` — deep equality including order, per LLR-009.1 statement ("differ in content or order").
- Asserts `report1.coverage == report2.coverage` — every `CoverageMetrics` field equal.
- A new module-level helper `_engine_inputs_from_large_project(paths)` mirrors the existing `TestCrossFileCompatibilityCoEmission._engine_inputs_from_paths` wiring (parses S19/A2L/MAC, builds the engine kwargs dict). Kept test-local; does not depend on `validation_service.build_validation_report`.

**Result: PASS.** No determinism violation observed. The engine is a pure function over its inputs, and the fixture seed is honored. No `blocker` Finding raised.

### TC-082 — `class TestCoverageMetricsCorrectness` (LLR-009.2)
Three tests:
1. `test_coverage_metrics_fields_populated_on_large_project` — uses `dataclasses.fields(CoverageMetrics)` to enumerate every declared field and asserts each one is present on `report.coverage` AND non-zero on the populated `large_project` input. All 6 declared fields (`mac_total`, `mac_in_s19`, `a2l_total`, `a2l_in_s19`, `a2l_mac_intersection`, `a2l_mac_address_matches`) populate non-zero — engine.py covers the full model.py contract.
2. `test_coverage_metrics_zero_on_empty_input` — empty parser outputs (no S19 ranges, no A2L data, no MAC records) yield zero on every declared field and an empty issues list. Documents the empty-input baseline per LLR-009.2 acceptance.
3. `test_coverage_metrics_no_undeclared_fields_on_engine_output` — defensive: confirms `CoverageMetrics.__slots__` matches the declared field set, catching the case where a future engine commit synthesises an undeclared attribute.

**Result: PASS on all three.** No `CoverageMetrics` field gap. No Finding raised.

### Imports
`tests/test_validation_engine.py` header gains `import dataclasses` and adds `CoverageMetrics` to the existing `from s19_app.validation.model import ...` line.

## 2. Files modified

| File | Purpose |
|------|---------|
| `tests/test_validation_engine.py` | Add `import dataclasses`, add `CoverageMetrics` to model imports, add module-level `_engine_inputs_from_large_project` helper, add `TestEngineDeterminism` (1 test, TC-081), add `TestCoverageMetricsCorrectness` (3 tests, TC-082). |
| `.dev-flow/03-increments/increment-008.md` | This review packet. |

**File count: 2.** Within ≤5 cap.

## 3. How to test

```bash
# Just the new TCs
pytest -q tests/test_validation_engine.py::TestEngineDeterminism tests/test_validation_engine.py::TestCoverageMetricsCorrectness

# Full suite — must show 259 passed (was 255 baseline) / 0 failed / 2 skipped / 3 xfailed
pytest -q tests/
```

## 4. Test results

### New TCs only
```
============================= test session starts =============================
platform win32 -- Python 3.14.4, pytest-9.0.3, pluggy-1.6.0
collected 4 items

tests\test_validation_engine.py ....                                     [100%]

============================== 4 passed in 6.71s ==============================
```

### Full suite (post-increment)
```
......ss................................................................ [ 27%]
.......................................................x................ [ 54%]
....................................................x................... [ 81%]
...............................x................                         [100%]
259 passed, 2 skipped, 3 xfailed in 60.70s (0:01:00)
```

**Baseline (pre-increment):** 255 passed / 2 skipped / 3 xfailed / 0 failed.
**Post-increment:** 259 passed / 2 skipped / 3 xfailed / 0 failed.
**Delta:** +4 passed, no regressions.

## 5. Risks

- **No determinism failure observed** — TC-081 passed on first attempt. Per §5.3 acceptance, a non-determinism would have been a `blocker` Finding triggering an immediate stop. None raised, so no escalation.
- **No CoverageMetrics field gap** — every field declared in `model.py` is populated by `engine.py` (see `CoverageMetrics.__slots__` audit in TC-082 test 3 and the explicit `metrics.X += 1` lines in `engine.py` lines 84, 86, 121, 124, 155, 159).
- **Helper duplication.** `_engine_inputs_from_large_project` and `TestCrossFileCompatibilityCoEmission._engine_inputs_from_paths` share most of their wiring. They were kept separate because the new helper takes a `dict` (from `large_project`) while the existing one takes three keyword paths (and returns kwargs even when each path is `None`, for single-artifact tests). A future increment could DRY them, but in scope it's clearer to keep them distinct.
- **`__slots__`-vs-`__dict__` shape check.** `CoverageMetrics` is a `@dataclass(slots=True)`, so it has `__slots__` (a tuple) but no `__dict__`. TC-082 test 3 reads `getattr(report.coverage, "__slots__", declared)` — the fallback to `declared` is intentional so the test does not fail if a future refactor turns slots off; the assertion is still meaningful as long as slots are present, which they are today.
- **Determinism check is a single fixture.** TC-081 asserts determinism only for `large_project`. A pathological non-deterministic engine could in principle hide behind a single seed. This is acceptable per LLR-009.1 — the LLR explicitly names `large_project` as the input and §6.3 R-5 already established `seed=0` is the contract.

## 6. Pending items

### Closures
- **§6.3 R-5 — closed.** Iteration 3 closed it by inspection of `tests/conftest.py`; this increment promotes that closure to an executable assertion (TC-081). R-5 may now be marked `confirmed` in the audit deliverable.
- **HLR-009 — closed.** Both child LLRs covered:
  - LLR-009.1 — `Automated` via TC-081 (`tests/test_validation_engine.py::TestEngineDeterminism`).
  - LLR-009.2 — `Automated` via TC-082 (`tests/test_validation_engine.py::TestCoverageMetricsCorrectness`); the inspection portion ("each declared field referenced and non-zero on `large_project`") is folded into the test via `dataclasses.fields(CoverageMetrics)` enumeration.
  HLR-009 is now ✅ for the audit deliverable.

### Carry-through (open Findings from prior increments)
- **F-7.2-01** — `sanitize_project_name` does not enforce Windows reserved name set (`CON`, `PRN`, `AUX`, `NUL`, `COMn`, `LPTn`). Severity: **major** (Windows write surface). Source: increment 7 §5. Status: **deferred**, picked up by `architect`/`software-dev` in a follow-up batch.
- **F-7.2-02** — `sanitize_project_name` does not enforce 64-char cap and does not normalise Unicode confusables. Severity: **major**. Source: increment 7 §5. Status: **deferred**.
- **F-7.7-02..07** — six Findings against `s19_app/tui/workspace.py` (4) and `s19_app/tui/a2l.py` (2) raised in increment 7. Status: **deferred**, see increment 7 §5 for fix recommendations.

### Findings raised THIS increment
**None.** Both LLRs pass without observation.

## 7. Suggested next task

**Increment 9 — consolidated inspection-method audit matrices.**

Documentation-only increment. Produce `.dev-flow/03-increments/increment-009.md` containing the audit matrices that LLRs whose primary validation method is `inspection` still owe. Per §5.1, each inspection-method TC produces an audit matrix with columns `R-* (or class) | implementing symbol | asserting test | verdict | finding ID (if any)`.

Inspection-method LLRs to consolidate (cross-checked against §4 and §5.2):
- LLR-001.1 — parser layered structure.
- LLR-001.2 — `S19File` / `IntelHexFile` non-aborting error collection.
- LLR-002.2 — severity colour map round-trip (codes → severities → CSS classes).
- LLR-003.1 — `app.py` is orchestration-only, feature logic in `tui/services/`.
- LLR-004.1 — `LoadedFile` snapshot contract + worker/UI thread split.
- LLR-007.1 — engine rule reverse-direction matrix (rule fn → emitted code → severity vs. Issues Tile policy).
- LLR-007.3 — A2L tag enrichment audit.
- LLR-008.1 — `range_index` and `address_in_sorted_ranges` correctness across hex view + engine consumers.
- LLR-008.2 — public hex-view constants vs. consumer call sites.
- (LLR-009.2 inspection portion not test-covered here — already folded into TC-082; matrix entry only.)

**No code or test changes.** Output is a single markdown file (the audit matrices and any Findings discovered while compiling them, filed per §5.3). Estimated 9 matrices.

After increment 9, Phase 3 closes. Phase 4 (validation gate against §5.3 acceptance criteria) is then the next gate.
