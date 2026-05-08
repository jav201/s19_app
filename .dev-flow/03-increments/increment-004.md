# Increment 4 — severity round-trip + bidirectional `SEVERITY_CLASS_MAP` invariant + colour-name set as contract (LLR-002.1)

**Phase:** 3 — Implementation
**Increment:** 4 of N
**Date:** 2026-05-05
**Branch:** `claude/lucid-margulis-a63fd4`
**LLR target:**
- LLR-002.1 — `ValidationIssue.code → ValidationSeverity → css_class_for_severity` round-trip, bidirectional `SEVERITY_CLASS_MAP` invariant, colour-name set `{Red, Orange, Green, White, Grey}` as contract.
- Closes Phase 1 risk **R-3** (severity colour string contract was previously verified by inspection only — now verified by parametrised unit test plus integration probe on `large_project`).
- TC-012 (parametrised round-trip) and TC-013 (integration on `large_project`) per §5.2 of `01-requirements.md`.

## 1. What changed

Added `tests/test_color_policy_round_trip.py` (NEW) with **16 tests** that lock the LLR-002.1 contract:

- **Forward round-trip (TC-012)** — parametrised over every `ValidationSeverity` member (5 cases: `ERROR`, `WARNING`, `INFO`, `OK`, `NEUTRAL`). For each, asserts `css_class_for_severity(severity)`:
  1. returns a non-empty `str`,
  2. is a member of the documented CSS-class value set (`sev-error`, `sev-warning`, `sev-info`, `sev-ok`, `sev-neutral`),
  3. matches the documented severity → CSS-class table exactly. A drift on any one severity = Finding per LLR-002.1.
- **Bidirectional invariant** — three tests:
  - every `ValidationSeverity` member has exactly one entry in `SEVERITY_CLASS_MAP` (no silent drops),
  - every key in `SEVERITY_CLASS_MAP` is a defined `ValidationSeverity` member (no orphans),
  - every map value is unique (no two severities collide on the same CSS class).
- **Colour-name set as contract** — two tests:
  - the documented severity → colour mapping (`ERROR→red`, `WARNING→orange`, `OK→green`, `INFO→white`, `NEUTRAL→grey`) covers exactly the `REQUIREMENTS.md` colour set `{red, orange, green, white, grey}`,
  - every `ValidationSeverity` has an entry in the colour table (any new severity must be added to the contract).
- **Idempotency** — parametrised over every severity; `css_class_for_severity` returns the same value on repeated calls.
- **Integration round-trip on `large_project` (TC-013)** — runs `S19File`, `parse_a2l_file`, `parse_mac_file` against the `large_project` fixture, calls `validate_artifact_consistency`, then asserts every emitted `(code, severity, css_class)` triple satisfies the round-trip. Per LLR-002.1, this test does NOT enumerate `validation/rules.py` itself — it only checks the round-trip given whatever codes the engine produces (rule→code mapping is owned by LLR-008.2, increment 6+).

**Documented bridge between CSS-class names and `REQUIREMENTS.md` colours.** The CSS classes in `color_policy.py` are semantic (`sev-error`, `sev-warning`, …) rather than colour names (`sev-red`, `sev-orange`, …). Per the increment instructions, the test file documents the bridge in two module-level dicts (`EXPECTED_CSS_BY_SEVERITY`, `EXPECTED_COLOR_BY_SEVERITY`) and asserts the CSS-class set with the colour-name set as the contract sitting behind it. This was the recommended path for the "different naming convention" branch in the LLR-002.1 acceptance criteria.

**No divergence found.** The bidirectional invariant and the round-trip both pass on the first run — `color_policy.py` is fully consistent with `validation/model.py::ValidationSeverity` (5 members ↔ 5 entries, no orphans, no silent drops). File 2 (`color_policy.py`) was therefore NOT modified.

## 2. Files modified

| File | Change |
|---|---|
| `tests/test_color_policy_round_trip.py` | NEW. 16 parametrised + invariant tests for LLR-002.1. ~210 LOC including module docstring, imports, two contract tables, and the integration test. Uses the existing `large_project` fixture from `tests/conftest.py`; no new fixture introduced. |
| `.dev-flow/03-increments/increment-004.md` | This review packet. |

File count: **2** (well within the ≤5 cap; aim of "1 test file + packet, no product change" met).

## 3. How to test

```bash
pytest -q tests/
```

Targeted run for the new file:

```bash
pytest -v tests/test_color_policy_round_trip.py
```

Just the parametrised round-trip cases:

```bash
pytest -v tests/test_color_policy_round_trip.py::test_severity_round_trips_to_documented_css_class
```

Integration probe alone:

```bash
pytest -v tests/test_color_policy_round_trip.py::test_validate_artifact_consistency_round_trip_on_large_project
```

## 4. Test results

Run on Windows 11 / Python 3.11 / pytest:

```
$ python -m pytest -q tests/test_color_policy_round_trip.py
................                                                         [100%]
16 passed in 1.87s
```

```
$ python -m pytest -q tests/
......ss................................................................ [ 35%]
........................................................................ [ 70%]
.............................................................           [100%]
203 passed, 2 skipped in 6.37s
```

- **203 passed** (was 187 after increment 3; net **+16** from this increment's new test file).
- **2 skipped** (unchanged — the pre-existing TC-047 NTFS-junction probe on non-Windows runners and the other pre-existing skip).
- **0 failed.**
- No previously-passing test required modification.

Test breakdown for `tests/test_color_policy_round_trip.py`:

| Test | Count | Notes |
|---|---|---|
| `test_severity_round_trips_to_documented_css_class` | 5 (parametrised over `ERROR/WARNING/INFO/OK/NEUTRAL`) | TC-012 forward direction. |
| `test_every_validation_severity_has_exactly_one_map_entry` | 1 | Bidirectional invariant — no silent drops. |
| `test_every_map_key_is_a_defined_validation_severity` | 1 | Bidirectional invariant — no orphan keys. |
| `test_severity_class_map_values_are_unique` | 1 | No two severities share a CSS class. |
| `test_colour_name_set_matches_requirements_contract` | 1 | `{red, orange, green, white, grey}` = `REQUIREMENTS.md` set. |
| `test_every_validation_severity_has_a_documented_colour` | 1 | Contract completeness. |
| `test_css_class_for_severity_is_idempotent` | 5 (parametrised over each severity) | Determinism sanity. |
| `test_validate_artifact_consistency_round_trip_on_large_project` | 1 | TC-013 integration on `large_project`. |
| **Total** | **16** | All passing. |

## 5. Risks

- **No divergence found.** The contract holds today (5 ↔ 5, all four invariants green). Risk going forward is that a future change to `ValidationSeverity` (adding a member, renaming a member) without a matching update to `SEVERITY_CLASS_MAP` and to the test's `EXPECTED_CSS_BY_SEVERITY` / `EXPECTED_COLOR_BY_SEVERITY` tables will fail the bidirectional invariant test. This is the intended failure mode — the test catches drift early.
- **CSS-class naming convention.** The CSS classes are semantic (`sev-error`) rather than colour-named (`sev-red`). The test asserts both the actual CSS scheme and the colour-name contract via the documented `EXPECTED_COLOR_BY_SEVERITY` bridge. If the codebase ever switches to colour-named classes (e.g. as part of a TUI theme refactor), this bridge table is the single update point — change it once and the assertions retarget. This is documented in the test file's module docstring.
- **`large_project` integration test depends on the fixture producing non-zero issues.** The integration test asserts `report.issues` is non-empty before checking the round-trip, so a future change that makes `large_project` "all clean" would fail loudly with a clear message rather than silently degrade to a no-op. This is also the failure mode the existing `test_snapshot_harness_renders_issues_panel` assumes (see `test_tui_app.py` ~line 1786).
- **Rule→code mapping intentionally not duplicated.** Per LLR-002.1 acceptance criteria, this increment does NOT verify "every code in `model.py` is emitted by a rule" or "every rule emits the right severity per `REQUIREMENTS.md` Issues Tile Severity Policy". Those contracts belong to LLR-008.1 / LLR-008.2 in a later increment. Folding them in here would be scope creep and was explicitly forbidden by the increment instructions. Drift in those layers will not be caught by this increment's tests; that's by design.

## 6. Pending items

- **R-3 closure.** Phase 1 open risk R-3 — *"Severity colour string contract verified by inspection, not tests today"* — is **closed by this increment**. The contract is now verified by parametrised unit test (TC-012) and integration round-trip on `large_project` (TC-013). The risk row in `01-requirements.md` §6.3 already reads as closed (`Severity colour string contract is now verified by parametrised unit test in LLR-002.1, including the bidirectional invariant`); no document edit needed.
- **A-N04 doc-edit pending (carried over from increment 3).** Iter-2 minor A-N04 asked for `TC-090` to be renumbered into the LLR-002.x block (suggested `TC-015`). After increment 3's Q-N02 split into `TC-090.a` / `TC-090.b`, the rename is still open as a doc-only minor. This increment does not touch `01-requirements.md` §5.2; the renumber-to-`TC-015` suggestion remains a doc-only fold-in, scheduled for either:
  - a **Phase 1 light iteration** before Phase 4 (preferred — keeps requirements doc clean ahead of validation), OR
  - a **Phase 6 docs** consolidation alongside the other doc-only minors.
  
  Test code in `tests/test_validation_engine.py` and `tests/test_color_policy_round_trip.py` carries TC-090.a/b/TC-012/TC-013 IDs as comments; if §5.2 is later renumbered, those comments are a one-line update.
- **LLR-008.1 / LLR-008.2 — rule completeness audit (forward + reverse direction matrices).** Not in this increment's scope. They are the next major work item: forward direction (every code in `model.py` → emitting rule in `rules.py` → asserting test) and reverse direction (every rule → emitted codes → severity vs. `REQUIREMENTS.md` Issues Tile Severity Policy). Suggested as the next increment.
- **TC-014 — Issues-panel `Errors` / `Warnings` / `Optional info` mapping (LLR-002.2).** Inspection-method TC; can be folded with the LLR-008.x increment since it shares the rule→severity scan.

## 7. Suggested next task

**Increment 5 — LLR-008.1 / LLR-008.2 rule completeness audit matrices.** Build the forward (code → rule → test) and reverse (rule → code → severity) audit matrices in a new increment-005 packet under `.dev-flow/03-increments/`. This will:

1. Enumerate every `ValidationIssue.code` constant emitted by `rules.py` and `engine.py` (read both files).
2. Map each code to its emitting rule function and its asserting test (grep `tests/` for each code string).
3. Confirm the assigned `ValidationSeverity` matches the `REQUIREMENTS.md` Issues Tile Severity Policy tier.
4. Flag any dead code (no emitting rule), untested code (no asserting test), or severity divergence as Findings.

Most of the work is matrix-building (markdown tables) plus possibly a thin parametrised test to lock the codes-emitted-by-engine set as a contract — does not need new product code. Touches `.dev-flow/03-increments/increment-005.md` plus optionally one new test file. Well within the ≤5-files cap.

**Alternative — fold-in of `01-requirements.md` doc edits (A-N04 + Q-N02 § 5.2 renumber).** Pure documentation, ≤1 file, can be combined with Phase 6 docs or run as a quick Phase 1 light iteration. Lower priority than the LLR-008 audit matrices.
