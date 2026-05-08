# Functionality — s19_app — 2026-05-05-batch-01

**Audience:** future engineer, QA reviewer, security reviewer, or technical stakeholder who did not run the dev-flow but needs to understand what this audit batch produced and how to continue from it.

**Purpose:** describe (a) what `s19_app` is, (b) what the audit batch delivered, (c) how the audit deliverable interacts with the existing test suite, (d) how to run and read the suite, (e) where the open Findings live, and (f) what the next batches should pick up.

**Scope:** this document is **not** the requirements specification (that is [`01-requirements.md`](../01-requirements.md)) and **not** the per-test verdict register (that is [`04-validation.md`](../04-validation.md) and the [traceability matrix](traceability-matrix.md)). It is the orientation document that lets a new reader navigate those artefacts.

---

## 1. What `s19_app` is

`s19_app` (distribution name `s19tool`, see [`pyproject.toml`](../../pyproject.toml)) is an offline desktop tool for parsing, validating, and visualising automotive memory artefacts. It has two entry points:

- **`s19tool`** — Rich-formatted CLI (`s19_app.cli:main`) with subcommands `info`, `verify`, `dump`, `patch-hex`. (Out of scope for this audit batch — see `01-requirements.md` §1.2 deferral.)
- **`s19tui`** — Textual TUI (`s19_app.tui:main`) for interactive exploration of S-record / Intel HEX / A2L / MAC files plus cross-artefact validation.

The system's three-layer architecture (per [`CLAUDE.md`](../../CLAUDE.md)):

1. **Parsers** — `s19_app/core.py` (S19), `s19_app/hexfile.py` (Intel HEX), `s19_app/tui/a2l.py` (A2L characteristic / measurement metadata), `s19_app/tui/mac.py` (MAC `TAG=hexaddr` symbol files). All four collect per-record errors without aborting the load — that contract is asserted by the parser-correctness audit (HLR-001).
2. **Range / validation engine** — `s19_app/range_index.py` (binary-search membership primitive), `s19_app/validation/engine.py` (`validate_artifact_consistency` fuses S19+A2L+MAC into a single `ValidationReport`), `s19_app/validation/rules.py` (per-artefact rules), `s19_app/validation/model.py` (`ValidationIssue`, `ValidationSeverity`, `CoverageMetrics`). Severity flows through `s19_app/tui/color_policy.py::SEVERITY_CLASS_MAP` to the TUI's `sev-*` CSS classes.
3. **TUI services + view** — `s19_app/tui/services/` (`load_service`, `a2l_service`, `validation_service`) keep `s19_app/tui/app.py::S19TuiApp` orchestration-only; `s19_app/tui/models.py::LoadedFile` is the worker→UI thread snapshot; `s19_app/tui/hexview.py` produces all hex/ASCII output; `s19_app/tui/workspace.py` owns the `.s19tool/` workarea and rotating log.

Refer to the architecture diagram in [`diagrams/architecture.md`](diagrams/architecture.md) for the visual call-graph.

---

## 2. What the audit batch produced

Batch `2026-05-05-batch-01` ran the V-model dev-flow against `s19_app` with the objective *"review the integrity and functionality of the application using the dev-flow process and specialized agents."* The batch is an **audit batch** — the deliverable is a structured set of Findings about the existing codebase, not a new product feature. (See [`01-requirements.md`](../01-requirements.md) §1.1.)

### 2.1 Headline outputs

| Output | Count | Where |
|---|---|---|
| User stories drafted | 6 (US-001..US-006) | [`01-requirements.md`](../01-requirements.md) §2.6 |
| HLRs drafted | 10 (HLR-001..HLR-009 with HLR-007 split into 007a/007b) | [`01-requirements.md`](../01-requirements.md) §3 |
| LLRs drafted | 19 | [`01-requirements.md`](../01-requirements.md) §4 |
| TCs evaluated | 60 | [`01-requirements.md`](../01-requirements.md) §5.2; verdicts in [`04-validation.md`](../04-validation.md) §2 |
| Automated LLRs (test method) | 17 | LLR-002.1, 002.3, 003.2, 005.1–005.5, 006.1, 007.2, 007.4, 009.1, 009.2 + audit-deliverable LLRs |
| Inspection-method audit matrices | 9 | [`increment-009.md`](../03-increments/increment-009.md) §1–§9 |
| Net new tests added | +86 (suite 173 → 259) | [`05-postmortem.md`](../05-postmortem.md) §0; trajectory in [traceability-matrix §2.2](traceability-matrix.md) |
| `R-*` traceability rows reviewed | 41 (28 confirmed / 5 promote / 2 drift / 6 unknown) | [`increment-009.md` §5](../03-increments/increment-009.md) |
| Open Findings carried forward | 18 (3 major + 15 minor) | [`02-review.md` §Deferrals](../02-review.md), [`increment-009.md` §10](../03-increments/increment-009.md) |
| Phase 2 security blockers closed inline | 2 (S-001 destination containment, S-002 symlink/junction follow-through in `copy_into_workarea`) | Increment 1 (LLR-005.3) |

### 2.2 What the 17 automated LLRs assert

Each automated LLR is locked by one or more pytest test classes. A new reader can run the suite and read the verdict from the test names directly. Highlights:

- **LLR-002.1 — severity round-trip** (`tests/test_color_policy_round_trip.py`, 16 tests): every `ValidationIssue.code` → `ValidationSeverity` → `css_class_for_severity` → CSS class round-trips correctly; the colour-name set `{Red, Orange, Green, White, Grey}` is part of the asserted contract; `SEVERITY_CLASS_MAP` is a strict superset of `ValidationSeverity` (bidirectional invariant).
- **LLR-002.3 — issue-message scrubbing** (`tests/test_validation_engine.py::TestIssueMessageScrubbing`): every `ValidationIssue.message` strips control characters (`\n`, `\r`, `\t`, ANSI `\x1b[...]`) and truncates to 500 characters. Closes the log-injection vector S-005.
- **LLR-005.1–LLR-005.5 — workspace IO** (`tests/test_tui_workspace.py`): read-path resolution precedence; project-name sanitisation (full Windows reserved-name set, traversal vectors, NUL bytes — with self-flip-guards on F-7.7-02/03/04 for the items not yet enforced); `copy_into_workarea` write-path containment + symlink rejection + 256 MB cap (this last one is the **product-behaviour change** that closed S-001 / S-002 — see `01-requirements.md` §6.3 R-6); `validate_project_files` symlink + case-collision + cardinality; rotating log handler with 5 MB cap and non-writable fallback.
- **LLR-007.2 — engine cross-file co-emission** (`tests/test_validation_engine.py::TestCrossFileCompatibilityCoEmission`): for each of 8 documented cross-file incompatibility classes (X-007.1-a..h), the engine emits a `ValidationIssue` of the correct severity AND populates it into the returned `ValidationReport.issues` list. Class `a` (S19/HEX overlap) is `xfail` — engine gap F-7.2-01.
- **LLR-007.4 — panel-render snapshot** (`tests/test_tui_app.py::TestCrossFileCompatibilityPanelRender`): for each class, the `ValidationIssue` actually appears in the rendered Issues panel widget tree under `App.run_test()`. Decouples engine emission from rendering — closes review finding A-003.
- **LLR-009.1 — engine determinism** (`tests/test_validation_engine.py::TestEngineDeterminism`): two runs of `validate_artifact_consistency` on `large_project` return deep-equal `ValidationReport.issues` and `CoverageMetrics`. No non-determinism observed.

### 2.3 What the 9 inspection matrices add

Inspection-method LLRs cannot be locked by a single executable test — they describe a property of the codebase that is established by walking source files and citing the symbol + asserting test for each `R-*` rule or class. Those walks are the audit matrices in [`increment-009.md`](../03-increments/increment-009.md):

| § | LLR | Scope |
|---|---|---|
| §1 | LLR-001.1 | S-record + Intel HEX rule coverage matrix (R-READ-001, R-PARSE-001..005, R-VAL-001/002, R-HEX-001..003 + 9 extra Intel HEX rules) |
| §2 | LLR-001.2 | A2L + MAC parser rule coverage matrix (R-A2L-001..007 + structural-parsing prose-only rules) |
| §3 | LLR-002.2 | Issues-panel classification (Errors / Warnings / Optional info tier mapping) |
| §4 | LLR-003.1 | `app.py` parsing/validation call-site enumeration (10 sites: 7 routed via services, 3 documented bypasses → F-9.04-01/02/03) |
| §5 | LLR-004.1 | Per-`R-*` verdict report (41 rows) |
| §6 | LLR-007.1 | Cross-file class enumeration (X-007.1-a..h with fixture, code, severity by alias policy) |
| §7 | LLR-007.3 | Severity-by-tier matrix per active alias policy (`"warn"` is the engine default) |
| §8 | LLR-008.1 | Forward direction: every `ValidationIssue.code` literal → emitting rule → asserting test |
| §9 | LLR-008.2 | Reverse direction: every rule function → emitted code(s) → severity vs. policy |

A "matrix row with verdict `confirmed` and no Finding ID" is the positive case (audited, no issue). A row with `verdict: drift` or a Finding ID is grep-able as a CI regression check (see qa-reviewer recommendation in [`05-postmortem.md` §2.B](../05-postmortem.md)).

### 2.4 The 18 open Findings

Three majors and fifteen minors carry forward. The full register with `{ID, severity, source, owner, target batch, blast radius if not fixed}` is in:

- [`02-review.md` §Deferrals](../02-review.md) for Phase-2-surfaced majors (F-7.2-01, F-7.7-07, F-7.7-02..06, F-7.2-02).
- [`increment-009.md` §10](../03-increments/increment-009.md) for Phase-3-surfaced Findings (F-9.01-01, F-9.02-01..03, F-9.03-01/02, F-9.04-01..03, F-9.07-01, F-9.09-01).

The traceability matrix in [`traceability-matrix.md` §3.2](traceability-matrix.md) lists all 18 with one-line descriptions and the proposed follow-up batch.

---

## 3. How the audit interacts with the existing test suite

The audit did NOT reorganise the suite. New tests were added under `tests/` next to existing ones, reusing the deterministic fixtures already defined in [`tests/conftest.py`](../../tests/conftest.py).

### 3.1 Three test-design patterns introduced (or reinforced)

#### (a) Documented `xfail(strict=False)` carrying a Finding ID

Used on TC-062.a, TC-065.a (both carry F-7.2-01) and TC-052 (carries F-7.7-07). Each `xfail` decorator includes the Finding ID and a one-line product fix recommendation in the `reason` argument. The test will:

- **Stay green** as `xfail` while the gap exists.
- **Promote to `xpass`** automatically when the product fix lands and the engine emits the missing code (or returns the right tag).
- **Never block the suite** in either state.

`strict=False` was the deliberate choice — `strict=True` would risk a false `xpass` if the engine partially emitted the right symbol but with the wrong severity. See [`05-postmortem.md` §1.F.2](../05-postmortem.md) for the architectural rationale.

#### (b) Self-flip-guard tests

Used in TC-042 (`TestSanitizeProjectName`) and TC-048 (`TestValidateProjectFilesSymlinkAndCase`). These tests ship as **green** assertions of the *de-facto* behaviour and contain a comment naming the Finding (F-7.7-02..05). When the product is fixed and the de-facto behaviour changes, the assertion will flip and the test will go **red** — at which point the developer fixes the Finding, updates the assertion to the new expected behaviour, and the green is the closure tripwire.

This is appropriate where the contract is defensible-but-loose (a sanitiser that does not yet reject Windows reserved names is not a bug per se — the LLR's stricter contract is a Finding, not a regression). The pattern is cheaper than maintaining 4 separate `xfail` rows.

#### (c) Audit-matrix-as-evidence

The 9 matrices in [`increment-009.md`](../03-increments/increment-009.md) §1–§9 are markdown tables, not executable tests. They are the unit of evidence for inspection-method TCs. Each matrix has a stable column shape:

```
| `R-*` (or class) | implementing symbol | asserting test | verdict | finding ID (if any) |
```

A `verdict: drift` row is grep-able. The qa-reviewer's recommendation in [`05-postmortem.md` §2.B](../05-postmortem.md) is:

```bash
grep -E "verdict.*drift" .dev-flow/03-increments/increment-009.md
```

as a pre-merge regression check on future batches.

### 3.2 The `large_project` fixture

[`tests/conftest.py`](../../tests/conftest.py) exposes `large_s19`, `large_a2l`, `large_mac`, and `large_project` fixtures via deterministic generators (`make_large_s19`, `make_large_a2l`, `make_large_mac`, all `seed=0` by default). These were used as-is by every cross-file test in increments 5/6/8, and are the reason TC-081 (engine determinism) passed first try without re-seeding noise.

Three new per-class fixtures were added to `tests/conftest.py` in increment 2:

- `make_overlap_s19_hex` — for TC-062.a / TC-065.a (S19/HEX cross-image overlap)
- `make_duplicate_alias_mac` — for TC-062.g / TC-065.g (duplicate-address alias)
- `make_corrupt_records` — for TC-062.h / TC-065.h (parsed-record corruption)

These live under `tests/conftest.py` (not under a `tests/fixtures/` subtree — see `01-requirements.md` LLR-007.2 doc-vs-code drift noted in [`05-postmortem.md` §1.B](../05-postmortem.md); the conftest-builder convention from `CLAUDE.md` won).

### 3.3 New test file added in this batch

- [`tests/test_color_policy_round_trip.py`](../../tests/test_color_policy_round_trip.py) — 16 parametric tests added in increment 4 (Phase 3). Locks LLR-002.1: every `ValidationIssue.code` → `ValidationSeverity` → CSS class round-trip is correct; bidirectional `SEVERITY_CLASS_MAP` invariant; colour-name set `{Red, Orange, Green, White, Grey}` is asserted; idempotency of `css_class_for_severity` on repeated calls; integration on `large_project`.

### 3.4 Existing files modified

Per `git status` at gate time, the audit touched these existing test files:

- `tests/conftest.py` (added 3 per-class fixture builders + the snapshot harness in increment 2)
- `tests/test_tui_app.py` (snapshot-harness smoke + `TestCrossFileCompatibilityPanelRender` class with 8 tests in increment 6)
- `tests/test_tui_helpers.py` (existing test renamed in increment 1.5 — see [`05-postmortem.md` §1.B](../05-postmortem.md))
- `tests/test_tui_hexview.py` (6 new tests + AST walk in increment 7)
- `tests/test_tui_public_api.py` (TC-051/052 expansion in increment 7)
- `tests/test_tui_workspace.py` (5 new test classes in increments 1 and 7)
- `tests/test_validation_engine.py` (`TestCrossFileCompatibilityCoEmission` + `TestIssueMessageScrubbing` + `TestEngineDeterminism` + `TestCoverageMetricsCorrectness` across increments 3, 5, 8)

The single product source change (the LLR-005.3 increment) touched `s19_app/tui/workspace.py` only — bounded to ≤1 file per the open-risk gate `01-requirements.md` §6.3 R-6.

---

## 4. How to run the suite and read the verdicts

### 4.1 Standard run

```bash
pip install -e .
pytest -q tests/
```

Expected on Python 3.11+:

```
259 passed, 2 skipped, 3 xfailed in ~66s
```

(Actual numbers from [`04-validation.md` §1](../04-validation.md) on Python 3.14.4 + pytest 9.0.3.)

### 4.2 Reading each verdict

| Verdict | What it means | What you should do |
|---|---|---|
| **`pass` (`.`)** | Test asserts a contract that holds today. | Nothing — green is good. |
| **`xfail` (`x`)** | Test documents a known product gap; carries a Finding ID in its `reason`. The product is broken in a way that has been recorded. | Read the Finding (cross-ref to [`02-review.md` §Deferrals](../02-review.md) or [`increment-009.md` §10](../03-increments/increment-009.md)). Don't try to "fix" the test — the right fix is the product change, after which the test will go `xpass` and the `xfail` decorator can be removed. |
| **`xpass` (unexpected pass) (`X`)** | An `xfail` test passed unexpectedly — the underlying gap was likely closed. **No `xpass` observed in this batch.** | Remove the `xfail` decorator on the test, verify the Finding is closed, update [`02-review.md` §Deferrals](../02-review.md). |
| **`skip` (`s`)** | Platform-conditional test (e.g. NTFS junction probe `pytest.mark.skipif(not Windows)`). | If your platform matches, run manually. Currently TC-047 needs Windows. |
| **`gap`** | Not a pytest verdict — this is a Phase 4 audit verdict. Means the TC has no executable test (it's a demo or inspection method) and the required evidence (`.png`, `transcript.md`, audit matrix) is not yet on disk. | See [`04-validation.md` §2](../04-validation.md) for the gap list; see [`05-postmortem.md` §3](../05-postmortem.md) for the closure batch (B-2E for demo gaps). |
| **`fail`** | Would be a Phase 4 blocker. **None observed** in this batch. | Iterate Phase 3. |

### 4.3 Other command flags

```bash
# Skip the slow stress tests (registered under the "slow" marker in pyproject.toml)
pytest -q -m "not slow"

# Run a single test file or test
pytest tests/test_color_policy_round_trip.py
pytest tests/test_validation_engine.py::TestEngineDeterminism

# Regenerate the large stress fixtures outside pytest
python tests/generate_large_samples.py

# Launch the TUI (for the demo-method TCs that the audit cannot fully automate)
s19tui
s19tui --load examples/case_00_public/prg.s19
```

CI (`.github/workflows/tui-ci.yml`) runs `pytest -q` on Python 3.11 against pushes/PRs to `main-tui`.

---

## 5. Where the audit Findings live

Three locations, in priority order:

1. **[`02-review.md` §Deferrals](../02-review.md)** — open major-severity Findings with the mandatory `{ID, owner, target batch, blast radius if not fixed}` schema. This is the authoritative register for Phase 4 gate purposes (`01-requirements.md` §5.3 acceptance criterion). 7 entries: A-N02, Q-N01, F-7.2-01, F-7.2-02, F-7.7-07, F-7.7-02..06.
2. **[`increment-009.md` §10](../03-increments/increment-009.md)** — Findings raised by the Phase 3 inspection matrices (mostly minor / doc). 10 entries: F-9.01-01, F-9.02-01..03, F-9.03-01/02, F-9.04-01..03, F-9.07-01, F-9.09-01.
3. **[`traceability-matrix.md` §3.2](traceability-matrix.md)** — consolidated list of all 18 with one-line descriptions and the proposed follow-up batch (B-2A..E).

Findings raised but closed inline during Phase 3 (e.g. S-005 message scrubbing, R-3 colour-name set lock, R-7 snapshot harness) are not in the open register; they are documented in the [`increment-NNN.md`](../03-increments/) review packet that closed them.

---

## 6. What to do next — the 5 follow-up batches

[`05-postmortem.md` §3](../05-postmortem.md) consolidates the architect and qa-reviewer recommendations into 5 follow-up batches. Suggested execution order: B-2A first (clears xfails + largest cluster), then B-2B + B-2C in parallel, then B-2D + B-2E as the closing doc/evidence sweep.

| Batch | Closes | Owner | Increments | Priority |
|---|---|---|---|---|
| **B-2A — Engine completeness** | F-7.2-01, F-7.2-02, F-7.7-07, F-9.07-01, F-9.03-01, F-9.03-02, F-9.09-01 | software-dev (qa-reviewer + security-reviewer review) | 5–6 | high (clears all 3 xfails + 7 Findings) |
| **B-2B — Workspace hardening** | F-7.7-02, F-7.7-03, F-7.7-04, F-7.7-05, F-7.7-06 | software-dev | 2–3 | high (closes 5 Findings; self-flip tests already in place) |
| **B-2C — Service-layer symmetry** | F-9.04-01, F-9.04-02, F-9.04-03 | software-dev | 1–2 | medium (refactor; no new product behaviour) |
| **B-2D — REQUIREMENTS.md numbering** | F-9.01-01, F-9.02-01..03, F-9.09-01 (overlap with B-2A acceptable) | docs-writer | 1 | medium (doc-only) |
| **B-2E — Demo evidence + test promotions + drift remediation** | TC-032 (9 packs), TC-047 Windows stdout (Q-N01), 5 R-* `promote`, 2 R-* `drift` | docs-writer + Javier | 1 | medium (closes Phase 4 gaps; ~1 hour manual + doc edit) |

**Concrete first steps for B-2A** (highest-priority closure):

1. Add `CROSS_S19_HEX_OVERLAP` constant to `s19_app/validation/model.py` (or wherever issue codes are centralised).
2. Add a rule in `s19_app/validation/rules.py` that consumes both memory maps (S19 + Intel HEX) and emits one `ValidationIssue` per overlapping address window, severity WARNING.
3. Wire the rule into `s19_app/validation/engine.py::validate_artifact_consistency`.
4. Remove the `xfail(strict=False, reason="F-7.2-01 ...")` decorator from `tests/test_validation_engine.py::test_tc_062_a_*` and `tests/test_tui_app.py::test_tc_065_a_*`.
5. The **two tests should now pass**. If they do, mark F-7.2-01 closed in [`02-review.md` §Deferrals](../02-review.md) and add the closure to the next batch's traceability matrix §4.

The single one-line fix for F-7.7-07 is independent and equally high-value — see [`02-review.md` §Deferrals](../02-review.md) entry F-7.7-07 for the spread-order detail in `s19_app/tui/a2l.py:~1223`.

---

## 7. Process learnings to carry into batch 2

From [`05-postmortem.md` §4](../05-postmortem.md), seven items the next batch should treat as defaults:

1. **Mandatory "surface enumeration" before LLR drafting.** For any HLR that names a module, enumerate its public functions and external call sites first. (Would have prevented Phase 1 iter 3 in this batch.)
2. **`pytest.xfail(strict=False)` + Finding ID** is the documented pattern for surfacing pre-existing product gaps without breaking CI.
3. **Self-flip-guard tests** are appropriate for defensible-but-loose contracts. Document them with the Finding ID inline.
4. **Audit-matrix-as-evidence** with grep-able `verdict: drift` rows enables CI regression checks on inspection-method LLRs.
5. **Lighter doc-Finding schema** for the F-9.* style (no `owner` / `target batch` fields when it's always Phase 6 docs).
6. **`partial-closed` verdict** for the dev-flow vocabulary (currently a partial closure is awkwardly encoded as "open major with documented closure step").
7. **Demo-method TCs in audit batches** — relax to `Manual + scheduled` rather than `gap` to avoid concentrating Phase 4 gap-verdicts on evidence capture.

---

## 8. Quick links

| Need | File |
|---|---|
| What was required | [`.dev-flow/01-requirements.md`](../01-requirements.md) |
| What review found | [`.dev-flow/02-review.md`](../02-review.md) (and §Deferrals for open majors) |
| Per-increment changes | [`.dev-flow/03-increments/increment-001.md`](../03-increments/increment-001.md) … [`increment-009.md`](../03-increments/increment-009.md) |
| Per-TC pass/fail | [`.dev-flow/04-validation.md`](../04-validation.md) §2 |
| Architect + qa retrospective + next batches | [`.dev-flow/05-postmortem.md`](../05-postmortem.md) |
| US/HLR/LLR/TC/file:line traceability | [traceability-matrix.md](traceability-matrix.md) |
| Architecture + dev-flow + Finding-flow diagrams | [diagrams/architecture.md](diagrams/architecture.md) |

---

## 9. Assumptions, risks, next steps (audit deliverable view)

**Assumptions baked into the deliverable:**

- `REQUIREMENTS.md` `R-*` rows are authoritative for the audit's compliance checks; any contradiction with the §"new product requirements" prose section becomes a Finding (e.g. F-9.03-02 severity drift on `A2L_BROKEN_REFERENCE`).
- The pytest baseline at gate time (259 / 2 / 3 / 0) is reproducible on Python 3.11 — the canonical CI version. Local runs on 3.14 produced the same numbers.
- The `large_project` fixture is deterministic (`seed=0` defaults verified by inspection of `tests/conftest.py`); LLR-009.1 determinism passes are not artefacts of fixture-level coincidence.

**Risks if the next batch does not start within ~3 months:**

- F-7.7-07 (`validate_characteristic` merge order) is a public-API data-correctness bug. Any caller that requests a tag other than the first parsed tag silently gets the WRONG tag's enrichment. One-line fix; high blast radius if it ships unfixed.
- F-7.2-01 (engine S19/HEX cross-image overlap missing) means a project loading both an S19 and an Intel HEX with disagreeing data at the same address loads with no warning surface. The user has no indicator. Medium-effort fix; medium blast radius.

**Next steps:**

- Immediate: `git push` the worktree branch and merge to `main-tui` (or whichever branch the team uses; this batch lives on `claude/lucid-margulis-a63fd4`). Run `/dev-flow-sync-en` to upload `.dev-flow/` to the Obsidian vault under `02 - Conocimiento/Dev Flow Batches/`.
- Short term (within ~2 weeks): open batch 2 starting with B-2A. The deferral register in [`02-review.md` §Deferrals](../02-review.md) is the requirements seed.
- Medium term: schedule the demo-evidence capture session (B-2E, ~1 hour manual) so the 9 missing TC-032 packs don't become stale.
