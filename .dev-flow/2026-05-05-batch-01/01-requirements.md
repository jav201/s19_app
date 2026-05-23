# Requirements Document — s19_app — Batch 2026-05-05-batch-01

> **Strict normative convention — IEEE 830 + EARS**
> - `shall` = normative, binding, verifiable requirement. **Only** inside HLR / LLR statements.
> - `should` = informative / explanatory text, **NOT binding**. **Only** outside HLR / LLR statements (rationale, description, context).
> - Any use of `should` inside an HLR / LLR statement is a **writing error** and will be flagged as a blocker in phase 2.
> - `may` = optional. `will` = future declaration or fact about an external actor.

---

## 1. Introduction

### 1.1 Purpose
This document specifies the requirements for **batch 2026-05-05-batch-01** of the `s19_app` project. The batch is an **audit / review batch**: its deliverable is a structured set of Findings about the integrity and functionality of the existing codebase, not a new product feature. "The system" specified by HLR/LLR statements below is therefore **the audit process and its output artefacts**, not the application under audit.

### 1.2 Scope
**In scope:**
- Parser layer: `s19_app/core.py`, `s19_app/hexfile.py`, `s19_app/tui/a2l.py` (and its facades), `s19_app/tui/mac.py`.
- Range/validation engine: `s19_app/range_index.py`, `s19_app/validation/engine.py`, `s19_app/validation/rules.py`, `s19_app/validation/model.py`, `s19_app/tui/color_policy.py`.
- TUI orchestration: `s19_app/tui/app.py`, `s19_app/tui/models.py`, `s19_app/tui/services/`, `s19_app/tui/hexview.py`, `s19_app/tui/screens.py`.
- Workspace IO: `s19_app/tui/workspace.py`.
- Existing test suite under `tests/` and the `R-*` traceability rows in `REQUIREMENTS.md`.

**Out of scope:**
- New product features beyond what is needed to (a) promote a `Manual`/`Partial` row to `Automated`, or (b) close a security blocker that requires a new product behaviour (file-size cap, symlink rejection — these are tracked in §6.3 R-6).
- Refactors that exceed the ≤5-files-per-increment rule from `CLAUDE.md`.
- Edits to the Obsidian vault (handled by `/dev-flow-sync-en` after batch close).
- CI configuration changes.
- **`s19_app/cli.py` and the four CLI subcommands (`info`, `verify`, `dump`, `patch-hex`)** — deferred to a follow-up batch (closes review finding A-005).

### 1.3 Definitions, acronyms, abbreviations
| Term | Definition |
|------|------------|
| HLR | High-Level Requirement (one EARS statement per atomic capability) |
| LLR | Low-Level Requirement (verifiable property at implementation level) |
| TC | Test Case identifier (`TC-NNN`) |
| US | User Story (`US-NNN`) in Connextra format |
| EARS | Easy Approach to Requirements Syntax |
| `R-*` | Existing requirement row in `REQUIREMENTS.md` |
| Audit verdict | One of `confirmed`, `promote`, `demote`, `drift` for an `R-*` row |
| Drift | Linked code or test no longer matches the asserted requirement |
| Severity round-trip | `ValidationIssue.code → ValidationSeverity → css_class_for_severity → CSS class` |
| **Finding** | A row in the audit deliverable with fields `{ID, Target file/symbol or section, Observation, Severity (blocker/major/minor), Recommended fix}`. Every "audit shall record a Finding" obligation in HLR/LLR Statements produces one or more Finding rows in the corresponding LLR's audit matrix. Findings are persisted in `.dev-flow/03-increments/increment-NNN.md` review packets and surfaced in `.dev-flow/04-validation.md` and `.dev-flow/02-review.md` §Deferrals. |
| Audit matrix | The markdown table produced by an inspection-method TC, with columns `R-* (or class) | implementing symbol | asserting test | verdict (confirmed / promote / drift / unknown) | finding ID (if any)`. A row with verdict `confirmed` and no finding ID is the positive case (audited, no issue). |
| Deferral | A `major`-severity Finding logged in `.dev-flow/02-review.md` §Deferrals with fields `{ID, owner, target batch, blast radius if not fixed}`. |

### 1.4 References
- `CLAUDE.md` (project root) — architecture and conventions.
- `REQUIREMENTS.md` (project root) — `R-*` traceability rows.
- `PROJECT_RULES.md` (project root) — docstring/typing/granularity rules.
- `pyproject.toml` — entry points, pytest markers.
- `tests/conftest.py` — deterministic fixtures (`large_s19`, `large_a2l`, `large_mac`, `large_project`).
- `~/.claude/templates/dev-flow/req-template-en.md` — this document's template.
- `.dev-flow/02-review.md` — Phase 2 review packet that drove this iteration 3.

### 1.5 Document overview
Section 2 frames the audit context. Section 2.6 lists the source user stories. Section 3 contains the HLR set. Section 4 decomposes each HLR into LLRs. Section 5 defines the validation strategy and batch acceptance criteria. Section 6 is reserved for appendices.

---

## 2. Overall description

### 2.1 Product perspective
`s19_app` is an offline desktop tool with two entry points (`s19tool` CLI, `s19tui` Textual TUI) that parses, validates, and visualises automotive memory artefacts (S-record, Intel HEX, A2L, MAC). This batch does not change product behaviour materially — it confirms behaviour against the documented contract, identifies drift, and adds the minimum new product behaviour required to close two security blockers (write-path containment + symlink rejection in `copy_into_workarea`; see HLR-005 / LLR-005.3).

### 2.2 Product functions (audited in this batch)
- Loading and parsing of S19, Intel HEX, A2L, and MAC files with per-record error collection.
- Cross-artifact validation that emits `ValidationIssue` entries with stable codes and severities.
- TUI rendering with severity-driven row colouring and an Issues panel.
- Project workspace under `.s19tool/` with rotating log and sanitised project folders.

### 2.3 User characteristics
The audit consumers are: (a) the GRNDIA engineering lead, (b) a QA reviewer, (c) a security reviewer, (d) a docs author preparing the next release. All are technical and familiar with Python / Textual.

### 2.4 Constraints
- Python 3.11 target, pytest test runner (per CI workflow).
- ≤5 files per implementation increment (`CLAUDE.md` working-method rule).
- Severity colour names (`Red`, `Orange`, `Green`, `White`, `Grey`) are part of the public contract per LLR-002.1; renames are out of scope for this batch and would be picked up as a Finding if attempted within scope.
- Issue codes referenced by tests (e.g. `CROSS_MAC_S19_OUT_OF_RANGE`, `TRIPLE_NAME_ADDRESS_MISMATCH`) are public contract.

### 2.5 Assumptions and dependencies
- `REQUIREMENTS.md` is the authoritative product-requirement source; the audit treats its `R-*` rows as ground truth for contract claims, even where the in-document validation status is stale.
- Existing fixtures in `tests/conftest.py` are sufficient for any new automated TC introduced by this batch except for the three cross-file incompatibility classes that require new per-class fixtures (see LLR-007.2 acceptance criteria); no new large-file generators will be created.
- `tests/conftest.py` seeds `make_large_s19`, `make_large_a2l`, and `make_large_mac` deterministically (`seed=0` defaults), so LLR-009.1 determinism check produces no fixture-level false positives. **Verified at iteration 3 by inspection of `tests/conftest.py`.**
- CI passes on `main-tui` at the start of the batch (verified by reading `.github/workflows/tui-ci.yml`); a failing baseline halts the audit.
- DoS-class pathological inputs to the parsers (e.g. an Intel HEX file with sparse single-byte fills across the full 32-bit address space) are out of scope for this offline-desktop threat model. They are noted in §6.3 R-8 for follow-up.

### 2.6 Source user stories

> Connextra format. Each US gets a unique ID `US-NNN` and traces to one or more HLRs.

| ID | User Story | Source |
|----|------------|--------|
| US-001 | As an engineering lead, I want a structural audit of the binary-format parsers (S19, Intel HEX, A2L, MAC), so that I can trust the application correctly accepts/rejects records and never silently corrupts a memory map. Additionally, when corrupted records or cross-artefact incompatibilities make the loaded files mutually inconsistent, an error and a written report are raised so that the conflict is visible and actionable to the operator. | Batch objective (`/dev-flow-init-en`) + iteration 2 user input |
| US-002 | As an engineering lead, I want the cross-artifact validation engine (`validation/engine.py` + `rules.py` + `model.py`) reviewed against the severity policies in `REQUIREMENTS.md`, so that A2L/MAC row colouring and the Issues panel match the documented contract. | Batch objective |
| US-003 | As an engineering lead, I want `s19_app/tui/app.py` audited so that the worker-thread parsing vs. UI-thread rendering split (per `CLAUDE.md`) is preserved and feature logic flows through `tui/services/`, not into the app shell. | Batch objective |
| US-004 | As a QA lead, I want every `R-*` requirement re-confirmed against its declared `Automated`/`Partial`/`Manual` status, so that we know which rows can be promoted, which have drifted, and which lack tests. | Batch objective + `REQUIREMENTS.md` |
| US-005 | As a security reviewer, I want the workspace-IO surface (`workspace.py`, project save/load, log rotation, `resolve_input_path` / `find_repo_root`, `sanitize_project_name`) audited, so that we have assurance against path traversal, destructive writes outside `.s19tool/`, and unbounded log growth. | Batch objective + `R-TUI-001` / `R-TUI-015` |
| US-006 | As a docs author, I want the public API surface (`get_raw_value`, `get_physical_value`, `validate_characteristic`, severity colour map, decode/conversion-status fields) confirmed against `REQUIREMENTS.md`, so that downstream consumers can rely on stable accessor contracts. | Batch objective + `REQUIREMENTS.md` §Output API |

---

## 3. High-level requirements (HLR)

### HLR-001 — Parser-correctness audit findings
- **Traceability:** US-001
- **Statement:** The parser-correctness audit shall produce a Finding (per §1.3) for every S-record, Intel HEX, A2L, and MAC validation rule documented in `REQUIREMENTS.md` (R-READ-001, R-PARSE-*, R-VAL-*, R-HEX-*, R-A2L-001/005, MAC parse rules) that is unimplemented, partially implemented, or under-tested in `s19_app/core.py`, `s19_app/hexfile.py`, `s19_app/tui/a2l.py`, and `s19_app/tui/mac.py`.
- **Rationale (informative):** The four parsers feed every downstream layer. The audit must cross-walk each documented parsing/validation rule against the implementing function and its test, otherwise silent regressions in record acceptance or memory-map composition can corrupt the entire validation chain.
- **Validation:** inspection
- **Priority:** high

### HLR-002 — Validation-engine severity-policy audit findings
- **Traceability:** US-002
- **Statement:** When the validation-engine review identifies a severity classification or issue code in `s19_app/validation/engine.py`, `s19_app/validation/rules.py`, or `s19_app/validation/model.py` that diverges from the A2L/MAC/Issues severity policies in `REQUIREMENTS.md`, the audit shall record a Finding (per §1.3) citing the specific `ValidationIssue.code` and the affected colour class in `s19_app/tui/color_policy.py::SEVERITY_CLASS_MAP`.
- **Rationale (informative):** Severity is the contract that drives row colouring and the Issues panel. A drift between `ValidationSeverity` and `css_class_for_severity` produces incorrect operator decisions in the field; capturing each divergence by code keeps remediation actionable.
- **Validation:** inspection
- **Priority:** high

### HLR-003 — TUI orchestration boundary audit findings
- **Traceability:** US-003
- **Statement:** The TUI orchestration audit shall record a Finding (per §1.3) for every code path in `s19_app/tui/app.py` that performs parsing, enrichment, or validation work outside of `s19_app/tui/services/load_service.py`, `a2l_service.py`, or `validation_service.py`, and for every renderer that reads or mutates state off the `LoadedFile` snapshot defined in `s19_app/tui/models.py`.
- **Rationale (informative):** The `CLAUDE.md` contract requires `app.py` to remain orchestration-only and renderers to stay on the UI thread reading from `LoadedFile`. Drift here breaks the worker-thread / UI-thread split and reintroduces parse logic into the app shell, which is the exact decomposition risk `PROJECT_RULES.md` flags for `app.py`.
- **Validation:** inspection
- **Priority:** medium

### HLR-004 — Requirements traceability re-confirmation report
- **Traceability:** US-004
- **Statement:** The traceability re-confirmation shall, for every `R-*` requirement in `REQUIREMENTS.md`, emit a verdict (`confirmed`, `promote`, `demote`, or `drift`) and the supporting evidence (implementing file/function and asserting test name), and shall record a Finding (per §1.3) for every `R-*` whose declared `Automated`/`Partial`/`Manual` status no longer corresponds to the present-day code or test.
- **Rationale (informative):** `REQUIREMENTS.md` is the audit's single source of compliance truth. Without a per-row verdict the document quietly decays; `Manual` rows that gained automation never get promoted, and `Automated` rows whose tests were renamed silently regress to fiction.
- **Validation:** inspection
- **Priority:** high

### HLR-005 — Workspace-IO security audit findings (umbrella)
- **Traceability:** US-005
- **Statement:** The workspace-IO security audit shall produce a Finding (per §1.3) for every code path in `s19_app/tui/workspace.py` where any of the following is reachable from user input: (a) read-path resolution that returns a path outside the documented search precedence (`resolve_input_path`, `find_repo_root`); (b) project-name sanitisation that lets a path separator, NUL byte, drive letter, Windows reserved device name, Unicode confusable, or over-cap length survive (`sanitize_project_name`); (c) write-path operation that lands a file outside `.s19tool/workarea/`, follows a symbolic link or NTFS reparse point, or accepts a source larger than the documented size cap (`copy_into_workarea`); (d) project-folder validation that accepts a symlinked or junctioned entry as a real file or breaches the documented cardinality (`validate_project_files`); (e) logging-surface failure where a non-writable `.s19tool/logs/` directory causes silent loss of log data instead of a clean error or fallback (`setup_logging`).
- **Rationale (informative):** `workspace.py` is the only module that legitimately writes to the user's filesystem. Iteration 2 conflated read-path resolution with write-path containment in a single LLR; iteration 3 separates them into LLR-005.1 (read), LLR-005.2 (sanitisation), LLR-005.3 (write), LLR-005.4 (project-folder validation), and LLR-005.5 (logging) so each surface has a deterministic pass/fail criterion. Two security blockers from Phase 2 (S-001 destination-containment, S-002 symlink/junction follow-through) close in this restructure.
- **Validation:** inspection
- **Priority:** high

### HLR-006 — Public API contract confirmation report
- **Traceability:** US-006
- **Statement:** The public-API confirmation shall verify, for each accessor named in `REQUIREMENTS.md` §Output API (`get_raw_value`, `get_physical_value`, `validate_characteristic`) and each documented payload field (`raw_value`, `decode_error`, `physical_value`, `conversion_status`, `conversion_error`, `schema_ok`, `memory_checked`, `in_memory`), that the implementation in `s19_app/tui/a2l.py` exposes the field with the documented type, default, and error semantics. The severity-colour-map invariant is asserted under LLR-002.1 (single source of truth) and is not duplicated here.
- **Rationale (informative):** Downstream consumers and the TUI renderers both depend on these accessors and field names being stable. An accessor whose error semantics drifted (for example a missing `conversion_status`) silently breaks the Issues panel and any external integration without producing a parse error.
- **Validation:** inspection
- **Priority:** medium

### HLR-007a — Cross-file artefact compatibility (engine-side emit)
- **Traceability:** US-001 (with secondary trace to US-002)
- **Statement:** If the loaded combination of S19/HEX, A2L, and MAC artefacts contains a documented cross-file incompatibility class (S19/HEX overlapping ranges, A2L tag range out of S19 range, MAC address out of S19 range, A2L↔MAC same-name address mismatch, symbol-only-in-MAC, symbol-only-in-A2L, duplicate-address alias warning, or a parsed record marked corrupted by `s19_app/core.py` / `s19_app/hexfile.py` / `s19_app/tui/mac.py` / `s19_app/tui/a2l.py`), then the audit shall record a Finding (per §1.3) for each class confirming whether `s19_app/validation/engine.py::validate_artifact_consistency` emits a `ValidationIssue` with the severity mandated by `REQUIREMENTS.md` Issues Tile Severity Policy AND populates that issue into the returned `ValidationReport.issues` list.
- **Rationale (informative):** US-001 makes it explicit that incompatibility must surface as both an error (severity `ERROR` or `WARNING` per the policy tier) and a written report entry (a persisted `ValidationIssue` the operator can read). This HLR locks the engine-side obligation. Rendering on the panel is split into HLR-007b so a test that asserts only emit + populate cannot hide a render-side filter (Phase 2 finding A-003).
- **Validation:** inspection
- **Priority:** high

### HLR-007b — Cross-file artefact compatibility (panel-render)
- **Traceability:** US-001 (with secondary trace to US-002, US-003)
- **Statement:** When the Issues panel in `s19_app/tui/app.py` consumes a `ValidationReport.issues` list produced by HLR-007a, the audit shall record a Finding (per §1.3) for any incompatibility class whose issue is not visibly rendered in the panel during a TUI run, where "visibly rendered" is verified by a Textual snapshot test against the rendered widget tree.
- **Rationale (informative):** An issue that is emitted by the engine but filtered out at render time defeats the user-facing contract. Locking the rendering side independently lets the Phase 4 validator detect engine/panel disagreement; locking it together with HLR-007a hides it.
- **Validation:** test (integration)
- **Priority:** high

### HLR-008 — Validation rule completeness audit findings
- **Traceability:** US-002
- **Statement:** The validation rule completeness audit shall confirm that every `ValidationIssue.code` constant defined in `s19_app/validation/model.py` is emitted by at least one rule function in `s19_app/validation/rules.py` and asserted by at least one test under `tests/`, and shall record a Finding (per §1.3) for any code that is dead (never emitted), untested (never asserted), or whose emitting rule's assigned severity diverges from `REQUIREMENTS.md` Issues Tile Severity Policy.
- **Rationale (informative):** Issue codes are the public contract referenced by both tests and downstream consumers. A code that exists but is never produced is dead surface; a code that is produced but never asserted is invisible regression risk; a code emitted at the wrong severity miscolours a TUI row in production. Explicitly auditing forward (code → rule → test) and reverse (rule → code → severity) directions is what makes the validation engine "robust" in the sense the user requested.
- **Validation:** inspection
- **Priority:** high

### HLR-009 — Validation engine determinism and coverage-metrics correctness
- **Traceability:** US-002
- **Statement:** The validation engine determinism audit shall verify that `s19_app/validation/engine.py::validate_artifact_consistency`, when invoked twice on the same input artefact set, produces a `ValidationReport` whose `issues` list (by content and order) and `coverage` `CoverageMetrics` are equal, and shall record a Finding (per §1.3) for any non-deterministic ordering, any missing `CoverageMetrics` field versus the dataclass declaration in `model.py`, or any zero-count metric whose corresponding artefact was non-empty.
- **Rationale (informative):** Determinism is implicit in the engine's contract — tests assert on issue codes and the Issues panel renders sorted output. Hidden non-determinism (dict ordering, set iteration in rule scans) makes those tests flaky and the TUI inconsistent across runs. `CoverageMetrics` is also a public field consumed by the docs report; zero counts on a non-empty input mask real coverage.
- **Validation:** test (integration)
- **Priority:** medium

---

## 4. Low-level requirements (LLR)

### LLR-001.1 — S-record and Intel HEX rule coverage matrix
- **Traceability:** HLR-001
- **Statement:** The audit shall produce an audit matrix (per §1.3) mapping each rule in R-READ-001, R-PARSE-001 through R-PARSE-005, R-VAL-001, R-VAL-002, and R-HEX-001 through R-HEX-003 to the implementing symbol in `s19_app/core.py` (`SRecord.__init__`, `SRecord._validate`, `SRecord._calculate_checksum`, `S19File._load`) or `s19_app/hexfile.py` (`IntelHexFile._load`), and to the asserting test in `tests/test_core_srecord_validation.py` or `tests/test_hexfile.py`.
- **Validation:** inspection
- **Acceptance criteria (informative):**
  - Every `R-READ-001`, `R-PARSE-*`, `R-VAL-*`, and `R-HEX-*` row appears in the matrix exactly once.
  - Each cell cites a specific function and a specific `def test_*` name, or marks the gap.
  - Sparse-map and `errors`-collection invariants from the `core.py` header comment are explicitly checked.

### LLR-001.2 — A2L and MAC parser rule coverage matrix
- **Traceability:** HLR-001
- **Statement:** The audit shall produce an audit matrix (per §1.3) mapping each documented A2L parsing/extraction obligation (R-A2L-001, R-A2L-005, indexed maps `record_layouts_by_name` / `compu_methods_by_name` / `compu_tabs_by_name`, and the byte-order precedence chain) and each MAC parsing obligation (`TAG=hexaddr` line shape, name validity, hex address validity) to the implementing symbol in `s19_app/tui/a2l.py` or `s19_app/tui/mac.py` and to the asserting test in `tests/test_tui_a2l.py` or `tests/test_tui_mac.py`.
- **Validation:** inspection
- **Acceptance criteria (informative):**
  - The four facade modules (`a2l_parse.py`, `a2l_extract.py`, `a2l_render.py`, `a2l_validate.py`) are confirmed as re-export-only.
  - The byte-order precedence chain (tag → layout → existing tag endian → little-endian default) is verified end to end.
  - Each gap is reported as a Finding with severity and a recommended test name.

### LLR-002.1 — Severity round-trip (parametrised unit test)
- **Traceability:** HLR-002
- **Statement:** The audit shall verify, by parametrised unit test, for every `ValidationIssue.code` produced by `s19_app/validation/rules.py`, that its `ValidationSeverity` round-trips through `s19_app/tui/color_policy.py::css_class_for_severity` to the colour class mandated by `REQUIREMENTS.md` §A2L/MAC severity (`Red`, `Orange`, `Green`, `White`, `Grey`), and shall additionally verify the bidirectional invariant: every `ValidationSeverity` member maps to exactly one `SEVERITY_CLASS_MAP` entry AND every `SEVERITY_CLASS_MAP` key is a defined `ValidationSeverity` member.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - Every issue code emitted by `validate_artifact_consistency` is enumerated with its severity and resulting CSS class.
  - The colour-name set `{Red, Orange, Green, White, Grey}` is part of the asserted contract; any rename produces a Finding.
  - The colour-class column extends the rule→code→severity matrix from LLR-008.2; do NOT duplicate the rule mapping here — link by reference.
  - Severity colour map keys are confirmed to be a strict superset of `ValidationSeverity` members (this assertion was previously in LLR-006.1 and is consolidated here).
  - Tests live in `tests/test_color_policy_round_trip.py` (new) or as a parametrised section of `tests/test_validation_engine.py`.

### LLR-002.2 — Issues-panel classification audit
- **Traceability:** HLR-002
- **Statement:** The audit shall confirm that each item listed in `REQUIREMENTS.md` §Issues Tile Severity Policy under `Errors`, `Warnings`, and `Optional info` is produced by `s19_app/validation/engine.py::validate_artifact_consistency` with the matching severity, or shall record a Finding (per §1.3) naming the missing rule.
- **Validation:** inspection
- **Acceptance criteria (informative):**
  - All `Errors`-tier items (MAC parse error, empty name, invalid address, A2L↔MAC mismatch, etc.) map to an `ERROR`-severity issue code.
  - `Warnings`-tier items (out-of-range, overlap ambiguity, symbol-only-in-X, alias warning) map to a `WARNING`-severity code.
  - `Optional info`-tier items map to an `INFO`-severity code and do not appear under Errors/Warnings counters.
  - The `CoverageMetrics` field is confirmed populated for every successful run.
  - LLR-002.1 records divergence on a code C ⇒ LLR-008.2 must also record divergence on the same code; mismatch is itself a Finding (cross-LLR consistency check from review finding A-004).

### LLR-002.3 — Issue-message scrubbing and length cap
- **Traceability:** HLR-002 (with secondary trace to HLR-007a, HLR-008)
- **Statement:** The audit shall verify that `ValidationIssue.message` values produced by every rule in `s19_app/validation/rules.py` strip control characters (`\n`, `\r`, `\t`, ANSI escape sequences `\x1b[...]`) and truncate to a maximum of 500 characters before being passed to `ValidationIssue`, and shall record a Finding (per §1.3) for any rule that emits a message violating these constraints.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - Probes against malformed MAC symbol names containing `\n` and ANSI sequences (log-injection vector).
  - Probes against an A2L tag name longer than 500 chars (panel-disruption vector).
  - Tests live in `tests/test_validation_engine.py` under a new `class TestIssueMessageScrubbing`.

### LLR-003.1 — `app.py` parsing and validation call-site enumeration
- **Traceability:** HLR-003
- **Statement:** The audit shall enumerate every call inside `s19_app/tui/app.py` to a parser, validation engine, or A2L/MAC enrichment routine that bypasses `s19_app/tui/services/load_service.py::build_loaded_s19`, `build_loaded_hex`, `a2l_service.enrich_tags_and_render`, or `validation_service.build_validation_report`, and shall classify each enumerated call site as `routed via services/` or `bypass — Finding-NNN`.
- **Validation:** inspection
- **Acceptance criteria (informative):**
  - The call graph from `S19TuiApp._parse_loaded_file` and `_apply_loaded_file` is documented.
  - Each bypass is recorded with file, method, and line range.
  - The worker-thread vs. UI-thread split is confirmed: renderers (`update_*`) read from `LoadedFile` and do not invoke parsers.
  - **Pass = enumeration is complete.** Closing bypass Findings is tracked under `.dev-flow/02-review.md` §Deferrals, not as a Phase 2 gate fail (per review finding Q-005).

### LLR-003.2 — Hex-view rendering invariants audit
- **Traceability:** HLR-003
- **Statement:** The audit shall confirm that the constants `MAX_HEX_BYTES`, `MAX_HEX_ROWS`, `FOCUS_CONTEXT_ROWS`, `HEX_WIDTH`, and `SEARCH_ENCODING` exported from `s19_app/tui/__init__.py` are the only knobs governing `s19_app/tui/hexview.py::render_hex_view_text`, `find_string_in_mem`, and `_collect_hex_rows`, and that no caller in `app.py` reaches into private helpers.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - Truncation and focus-context behaviour is exercised via the existing `tests/test_tui_helpers.py` and `tests/test_tui_hexview.py` cases.
  - Any direct use of private helpers from `app.py` is recorded as a Finding.

### LLR-004.1 — Per-`R-*` verdict report
- **Traceability:** HLR-004
- **Statement:** The audit shall, for every `R-*` row in `REQUIREMENTS.md`, emit a verdict (`confirmed`, `promote`, `demote`, or `drift`) and the supporting evidence (implementing symbol path and test name), and shall record a Finding (per §1.3) for every `R-*` whose declared `Automated`/`Partial`/`Manual` status no longer corresponds to a passing test.
- **Validation:** inspection
- **Acceptance criteria (informative):**
  - Promotion candidates explicitly cite the new test that justifies upgrade from `Manual` or `Partial` to `Automated`.
  - Drift entries cite the broken or renamed test reference.
  - The report covers all `R-READ`, `R-PARSE`, `R-VAL`, `R-HEX`, `R-TUI`, `R-A2L`, `R-PROJ`, and `R-DOC` requirements, including the newer `R-TUI-018` / `R-TUI-019` / `R-TUI-020` rows (review finding A-009).
  - A per-`R-*` mini sub-table is produced under this LLR with one row per `R-*` ID → its TC ID (TC-031, TC-032, or TC-033) (review finding Q-007).

### LLR-005.1 — Read-path resolution audit
- **Traceability:** HLR-005
- **Statement:** The audit shall enumerate every reachable input to `s19_app/tui/workspace.py::resolve_input_path` and `find_repo_root`, and shall record a Finding (per §1.3) for any path returned by these functions that does not satisfy the documented search precedence (app cwd, then nearest ancestor directory containing `pyproject.toml` or `project.toml`, then `None`).
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - `resolve_input_path` precedence is asserted against `tmp_path` fixtures.
  - `find_repo_root` is asserted to return the nearest ancestor containing `pyproject.toml` or `project.toml`, or `None`.
  - The audit explicitly does NOT require the read path to be contained inside `.s19tool/workarea/` — it is a search path, not a write target. Containment of the workarea write target is asserted in LLR-005.3 (closes review blocker S-001 routing error).

### LLR-005.2 — Project-name sanitisation audit
- **Traceability:** HLR-005
- **Statement:** The audit shall verify that `s19_app/tui/workspace.py::sanitize_project_name` rejects (returns `None`) every input that, after cleaning, equals a Windows reserved device name (case-insensitive: `CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`, with or without an extension such as `CON.s19`), exceeds 64 characters, contains a NUL byte, or contains a Unicode confusable character used in path-context attacks (per Unicode TR36), and shall record a Finding (per §1.3) for any input that survives sanitisation while violating one of these constraints.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - Traversal vectors (`..`, absolute paths, UNC paths `\\server\share`, drive letters `C:\foo`) collapse to empty (current behaviour) or yield `None`.
  - Reserved device names list above is exhaustively probed.
  - 64-character length cap is asserted.
  - Tests live in `tests/test_tui_workspace.py`.

### LLR-005.3 — Write-path containment, symlink rejection, and size cap (closes blockers S-001, S-002)
- **Traceability:** HLR-005
- **Statement:** The audit shall verify that `s19_app/tui/workspace.py::copy_into_workarea`, before writing, resolves both `source` and `destination` to absolute paths and rejects (raises an exception or returns without writing) when (a) the resolved `destination` is not contained inside `<base_dir>/.s19tool/workarea/` per `Path.is_relative_to`, (b) either resolved path traverses a symbolic link or NTFS reparse point, or (c) the resolved `source` file size exceeds the documented cap (recommended default: 256 MB), and shall record a Finding (per §1.3) for any reachable call site that bypasses these checks.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - Containment probe: a hand-crafted `destination` outside `.s19tool/workarea/` is rejected.
  - Symlink probe: a `tmp_path`-rooted symbolic-link source is rejected (POSIX + Windows where supported).
  - Junction probe: a `mklink /J` directory junction is detected (Windows-only; skip on POSIX with `pytest.mark.skipif`).
  - File-size probe: a 257 MB source is rejected.
  - Tests live in `tests/test_tui_workspace.py` under a new `class TestCopyIntoWorkareaContainment`.
  - **Note (product behaviour change):** these checks may not exist in `copy_into_workarea` today; closing this LLR may require a Phase 3 implementation increment that adds them. See §6.3 R-6.

### LLR-005.4 — Project-folder validation audit (symlink + case-collision)
- **Traceability:** HLR-005
- **Statement:** The audit shall verify that `s19_app/tui/workspace.py::validate_project_files` rejects directory entries whose `Path.is_symlink()` is true or whose Windows file attributes indicate a reparse point, treats filenames that differ only in case (`prj.S19` vs. `prj.s19`) as collisions on case-insensitive filesystems, and continues to enforce the cardinality constraint of at most one `.s19`/`.hex` and at most one `.a2l` and at most one `.mac` per project (R-TUI-014), and shall record a Finding (per §1.3) for any divergence.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - Symlink/junction rejection probed.
  - Case-only collision treated as collision (promoted from informative to normative per review finding S-007).
  - Cardinality boundary tests retained from `tests/test_tui_helpers.py`.

### LLR-005.5 — Logging surface audit (rotation cap + non-writable fallback)
- **Traceability:** HLR-005
- **Statement:** The audit shall verify that `s19_app/tui/workspace.py::setup_logging` produces a single `RotatingFileHandler` at `.s19tool/logs/s19tui.log` with a 5 MB cap (R-TUI-015), reuses the handler across repeated calls for the same path, and either raises a clean exception or falls back to a non-file handler when the log directory is non-writable, and shall record a Finding (per §1.3) for silent failure or for a missing rotation cap.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - 5 MB cap and `backupCount` are asserted from the `RotatingFileHandler` configuration.
  - Handler reuse asserted (existing test in `tests/test_tui_workspace.py`).
  - Non-writable directory probed by `chmod` (POSIX) or by mocking the file-handler open call (Windows).
  - Silent failure (Exception swallowed without logging or fallback) is treated as a Finding.

### LLR-006.1 — Accessor-contract confirmation
- **Traceability:** HLR-006
- **Statement:** The audit shall confirm that `get_raw_value(name)`, `get_physical_value(name)`, and `validate_characteristic(name)` in `s19_app/tui/a2l.py` each return both a value payload and a status/error metadata field, and shall record a Finding (per §1.3) for any accessor missing one of `decode_error`, `conversion_status`, `conversion_error`, or the `schema_ok` / `memory_checked` / `in_memory` triplet.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - Each accessor is exercised against an A2L tag with successful decode, a failing decode, and an unsupported `COMPU_METHOD` (e.g. `FORM` without safe eval).
  - The unit-display precedence (explicit `UNIT` then `COMPU_METHOD` body unit) is confirmed.
  - The severity-colour-map invariant moved to LLR-002.1 (single source of truth; do not duplicate here per review finding A-006).

### LLR-007.1 — Cross-file incompatibility class enumeration
- **Traceability:** HLR-007a
- **Statement:** The audit shall enumerate each cross-artefact incompatibility class named in `REQUIREMENTS.md` §Issues Tile Severity Policy (S19/HEX overlap, A2L range out of S19 range, MAC out of S19 range, A2L↔MAC same-name address mismatch, symbol-only-in-MAC, symbol-only-in-A2L, duplicate-address alias warning, parsed-record corruption from `core.py` / `hexfile.py` / `tui/mac.py` / `tui/a2l.py`) and shall map each class to either an existing `ValidationIssue.code` in `s19_app/validation/model.py` or a coverage gap with a recommended issue-code name.
- **Validation:** inspection
- **Acceptance criteria (informative):**
  - Every class in `REQUIREMENTS.md` Issues Tile Severity Policy appears in the audit matrix exactly once.
  - For each class with a matching code, both the rule function in `validation/rules.py` and the asserting test are cited.
  - For each class without a matching code, a recommended `ValidationIssue.code` name and severity tier are proposed in the Finding.

### LLR-007.2 — Engine-side error + report co-emission (per-class fixtures)
- **Traceability:** HLR-007a
- **Statement:** For each cross-file incompatibility class confirmed in LLR-007.1, the audit shall verify, on a triggering input set, that `s19_app/validation/engine.py::validate_artifact_consistency` emits a `ValidationIssue` with the severity mandated by `REQUIREMENTS.md` AND that this issue appears in the returned `ValidationReport.issues` list, and shall record a Finding (per §1.3) when only one of the two is present.
- **Validation:** test (integration)
- **Acceptance criteria (informative):**
  - One TC per incompatibility class (TC-062.a through TC-062.h, see §5.2). The class → fixture mapping is:
    - **TC-062.a** S19/HEX overlap → fixture `tests/fixtures/overlap_s19_hex/` (to be added in Phase 3).
    - **TC-062.b** A2L tag range out of S19 range → reuse `large_project` (covered).
    - **TC-062.c** MAC address out of S19 range → reuse `large_project` (covered).
    - **TC-062.d** A2L↔MAC same-name address mismatch → reuse `large_project` (covered).
    - **TC-062.e** symbol-only-in-MAC → reuse `large_project` (covered).
    - **TC-062.f** symbol-only-in-A2L → reuse `large_project` (covered).
    - **TC-062.g** duplicate-address alias → fixture `tests/fixtures/duplicate_alias_mac/` (to be added in Phase 3).
    - **TC-062.h** parsed-record corruption → fixture `tests/fixtures/corrupt_records/` (to be added in Phase 3).
  - Tests live in `tests/test_validation_engine.py` under `class TestCrossFileCompatibilityCoEmission`.
  - Each test asserts both the issue code and the presence of the issue in the returned report payload.

### LLR-007.3 — Severity matrix for incompatibility classes (alias-policy aware)
- **Traceability:** HLR-007a
- **Statement:** The audit shall confirm that the `ValidationSeverity` assigned to each cross-file incompatibility class matches `REQUIREMENTS.md` Issues Tile Severity Policy (`Errors` tier → `ERROR`, `Warnings` tier → `WARNING`, `Optional info` tier → `INFO`), recording the active alias-policy configuration at audit time and verifying only that configuration's expected severities; for classes that support both policies (duplicate-address alias under warning vs. error), both expected severities are enumerated in the audit matrix, and shall record a Finding (per §1.3) for any class whose emitted severity diverges from the policy under the active configuration.
- **Validation:** inspection
- **Acceptance criteria (informative):**
  - Active alias policy at audit time is logged in the audit packet (closes review finding A-007).
  - Codes supporting both policies have both rows in the matrix.
  - Severity divergences filed as Findings.

### LLR-007.4 — Panel-render audit (Textual snapshot)
- **Traceability:** HLR-007b
- **Statement:** For each cross-file incompatibility class confirmed in LLR-007.2, the audit shall verify that the corresponding `ValidationIssue` appears in the Issues panel widget tree of `S19TuiApp` during a Textual snapshot test, and shall record a Finding (per §1.3) for any class whose issue is silently filtered between engine emit and panel render.
- **Validation:** test (integration)
- **Acceptance criteria (informative):**
  - Snapshot test under `tests/test_tui_app.py` invokes `S19TuiApp` headlessly (using the existing Textual test harness, or `App.run_test()` if the harness is added in Phase 3).
  - Test parameterised over the same eight classes as LLR-007.2.
  - **Note:** if the existing `tests/test_tui_app.py` does not yet have snapshot infrastructure, increment 1 of Phase 3 must add it (see §6.3 R-7).

### LLR-008.1 — Forward direction (code → rule → test)
- **Traceability:** HLR-008
- **Statement:** The audit shall produce a forward-direction audit matrix (per §1.3) mapping every `ValidationIssue.code` constant in `s19_app/validation/model.py` to the emitting rule function in `s19_app/validation/rules.py` and to the asserting test name under `tests/`, and shall record a Finding (per §1.3) for any code with no rule (dead code) or no asserting test (untested code).
- **Validation:** inspection
- **Acceptance criteria (informative):**
  - Every `ValidationIssue.code` constant appears in the matrix exactly once.
  - Each cell cites a rule function name and a `def test_*` name, or marks the gap as `dead` / `untested`.
  - Codes referenced by tests (e.g. `CROSS_MAC_S19_OUT_OF_RANGE`, `TRIPLE_NAME_ADDRESS_MISMATCH`) are confirmed present and unchanged.

### LLR-008.2 — Reverse direction (rule → code → severity)
- **Traceability:** HLR-008
- **Statement:** The audit shall produce a reverse-direction audit matrix (per §1.3) mapping every rule function in `s19_app/validation/rules.py` to the issue codes it emits and the severity assigned, and shall record a Finding (per §1.3) for any rule that emits a code with severity differing from what `REQUIREMENTS.md` Issues Tile Severity Policy mandates for the corresponding class.
- **Validation:** inspection
- **Acceptance criteria (informative):**
  - Every rule function in `validation/rules.py` appears in the matrix.
  - Each cell cites the emitted code(s) and the assigned `ValidationSeverity`.
  - Severity divergences are filed with a recommended fix (rule code change vs. doc clarification).

### LLR-009.1 — Determinism check on `large_project`
- **Traceability:** HLR-009
- **Statement:** The audit shall invoke `s19_app/validation/engine.py::validate_artifact_consistency` twice on the `large_project` fixture from `tests/conftest.py` and shall record a Finding (per §1.3) if the two `ValidationReport.issues` lists differ in content or order, or if any `CoverageMetrics` field differs between the two runs.
- **Validation:** test (integration)
- **Acceptance criteria (informative):**
  - A new test (or extension of an existing test in `tests/test_validation_engine.py`) is added under TC-081.
  - The test compares both runs by deep equality.
  - Pre-condition: `tests/conftest.py::make_large_s19/a2l/mac` are confirmed seeded (`seed=0` defaults in `large_*` fixtures); verified by code inspection of `tests/conftest.py` (closes review finding Q-008).
  - Any non-determinism is treated as a `blocker`-severity Finding.

### LLR-009.2 — Coverage metrics population
- **Traceability:** HLR-009
- **Statement:** The audit shall confirm that the `CoverageMetrics` produced by `validate_artifact_consistency` for a successful run with a non-empty input set has non-zero counts for each loaded artefact type (S19/HEX, A2L, MAC), and shall record a Finding (per §1.3) for any zero-count field whose corresponding artefact was non-empty or for any missing field versus the dataclass declaration in `s19_app/validation/model.py`.
- **Validation:** inspection
- **Acceptance criteria (informative):**
  - Each `CoverageMetrics` field declared in `model.py` is referenced and non-zero on the `large_project` fixture.
  - Empty-input case is documented as a baseline (zero counts expected).
  - Any field added in `model.py` after this batch but not populated by `engine.py` is filed as a follow-up gap.

---

## 5. Validation strategy

### 5.1 Methods

This batch is an **audit** of an existing codebase, so the validation methods are weighted accordingly.

**Inspection** is the dominant method. Auditors read source files (`s19_app/core.py`, `s19_app/hexfile.py`, `s19_app/tui/a2l.py`, `s19_app/tui/mac.py`, `s19_app/validation/engine.py`, `s19_app/validation/rules.py`, `s19_app/validation/model.py`, `s19_app/tui/workspace.py`, `s19_app/tui/app.py`, `s19_app/tui/services/`) and compare them against the `R-*` rows of `REQUIREMENTS.md`, the severity colour rules, the public-API field contracts, and the architectural boundaries declared in `CLAUDE.md`.

**Inspection deliverable shape (MANDATORY).** Each inspection-method TC produces an audit matrix in the corresponding LLR section of `.dev-flow/03-increments/increment-NNN.md` with columns:

| `R-* (or class)` | implementing symbol | asserting test | verdict | finding ID (if any) |

where `verdict ∈ {confirmed, promote, demote, drift, unknown}`. A row with verdict `confirmed` and no finding ID is the positive case (audited, no issue). The matrix is the unit of evidence for inspection-method TCs; without a matrix the row cannot pass the Phase 4 gate (closes review finding Q-001 / A-002).

**Analysis** is used where direct test execution is impractical or where the reasoning chain replaces a check. Examples in this batch: log rotation behaviour under sustained churn (`R-TUI-015`), worker-thread vs. UI-thread separation in `_parse_loaded_file` / `_apply_loaded_file`. Each analysis row records its reasoning chain in the audit packet under the LLR's audit matrix.

**Test (integration / unit)** applies when the audit deliverable is a *new* automated check that promotes a `Manual` or `Partial` row in `REQUIREMENTS.md` to `Automated` or that closes a security blocker. New tests are added under `tests/` and reuse the deterministic fixtures `large_s19`, `large_a2l`, `large_mac`, and `large_project` from `tests/conftest.py`. Three new per-class fixtures (LLR-007.2 TC-062.a/g/h) live under `tests/fixtures/` and are introduced in Phase 3.

**Demo** is used sparingly and only for TUI-visible behaviour (`R-TUI-003`, `R-TUI-008`, `R-TUI-009`, `R-TUI-010`, `R-A2L-003`, `R-A2L-004`, `R-PROJ-001`, `R-PROJ-002`, `R-TUI-016`) where automated coverage is not feasible within batch scope.

**Demo capture-artefact contract (MANDATORY).** Each demo-method TC produces (a) a `.png` screen capture filed under `.dev-flow/evidence/<TC-NNN>/` and (b) a one-paragraph transcript stating the steps run and the observed pass/fail signed by the demo runner. A demo row without both artefacts cannot pass the Phase 4 gate (closes review finding Q-004).

### 5.2 Coverage table

| Requirement | Method | Test Case ID | Notes |
|---|---|---|---|
| HLR-001 | inspection | TC-001 | Cross-read `core.py`, `hexfile.py`, `tui/a2l.py`, `tui/mac.py` against R-READ / R-PARSE / R-VAL / R-HEX / R-A2L rows. |
| LLR-001.1 | inspection | TC-002 | S19 record-type address-length and checksum rules in `SRecord.__init__`; includes R-READ-001. |
| LLR-001.1 | test (unit) | TC-003 | Add coverage for any drift found vs. existing `tests/test_core_srecord_validation.py`. |
| LLR-001.1 | inspection | TC-004 | Intel HEX `:02` / `:04` / `:03` / `:05` handling (`IntelHexFile._load`). |
| LLR-001.2 | inspection | TC-005 | A2L facade re-export check + byte-order precedence chain; cite `tests/test_tui_a2l.py` and `tests/test_tui_mac.py`. |
| HLR-002 | inspection | TC-010 | `validation/engine.py::validate_artifact_consistency` fuses S19+A2L+MAC into one `ValidationReport`. |
| LLR-002.1 | inspection | TC-011 | Confirm every issue code in `validation/model.py` is referenced by a rule in `validation/rules.py`. |
| LLR-002.1 | test (unit) | TC-012 | Parametrised round-trip test in `tests/test_color_policy_round_trip.py`: builds the table from `validation/model.py` + `color_policy.SEVERITY_CLASS_MAP`; asserts bidirectional invariant and colour-name set. |
| LLR-002.1 | test (integration) | TC-013 | If any divergence found in TC-011/TC-012, add an integration test in `tests/test_validation_engine.py` using `large_project`. |
| LLR-002.2 | inspection | TC-014 | Issues-panel `Errors` / `Warnings` / `Optional info` mapping to severity codes; cross-LLR consistency check vs. LLR-008.2. |
| LLR-002.3 | test (unit) | TC-090 | Issue-message control-char strip + 500-char truncation probe in `tests/test_validation_engine.py`. |
| HLR-003 | inspection | TC-020 | `S19TuiApp` orchestration-only contract; logic in `tui/services/`. |
| LLR-003.1 | inspection | TC-021 | `_parse_loaded_file` (worker) vs. `_apply_loaded_file` (UI thread) split in `tui/app.py`. |
| LLR-003.1 | inspection | TC-022 | `load_service`, `a2l_service`, `validation_service` are the only entry points called from `app.py` for parse/enrich/validate. |
| LLR-003.2 | test (unit) | TC-023 | Hex-view constants and private-helper boundary. |
| HLR-004 | inspection | TC-030 | Walk every `R-*` row in `REQUIREMENTS.md`; mark Confirmed / Promote / Demote / Drift; emit per-`R-*` mini sub-table. |
| LLR-004.1 | test (unit) | TC-031 | Promote `R-TUI-001`, `R-TUI-002`, `R-TUI-011`, `R-TUI-012`, `R-TUI-013`, `R-A2L-002`, `R-TUI-017`, `R-A2L-006` from `Partial` to `Automated` where stable. |
| LLR-004.1 | demo | TC-032 | `R-TUI-003`, `R-TUI-008`, `R-TUI-009`, `R-TUI-010`, `R-A2L-003`, `R-A2L-004`, `R-PROJ-001`, `R-PROJ-002`, `R-TUI-016` remain manual; capture `.png` + transcript per §5.1 Demo. |
| LLR-004.1 | inspection | TC-033 | Confirm `R-TUI-018` / `R-TUI-019` / `R-TUI-020` still pass on `pytest -q` (currently `Automated`). |
| HLR-005 | inspection | TC-040 | `workspace.py` umbrella audit linking to LLR-005.1..5. |
| LLR-005.1 | test (unit) | TC-041 | Read-path resolution probes in `tests/test_tui_workspace.py` (precedence: app cwd → repo root → None). |
| LLR-005.2 | test (unit) | TC-042 | Sanitisation probes: traversal vectors, full Windows reserved-name set (`CON, PRN, AUX, NUL, COM1..9, LPT1..9`, with extension), 64-char cap, NUL byte, Unicode confusables. |
| LLR-005.3 | test (unit) | TC-044 | File-size cap probe (256 MB) on `copy_into_workarea`. |
| LLR-005.3 | test (unit) | TC-045 | Symlink rejection on `copy_into_workarea` source/destination (POSIX + Windows). |
| LLR-005.3 | test (unit) | TC-046 | Destination-containment probe (`Path.is_relative_to(.s19tool/workarea/)`). Closes blocker S-001. |
| LLR-005.3 | test (unit) | TC-047 | Junction rejection (Windows-only; `pytest.mark.skipif`). Closes blocker S-002. |
| LLR-005.4 | test (unit) | TC-048 | Symlink/junction rejection in `validate_project_files`; case-only collision (`prj.S19` vs. `prj.s19`); cardinality. |
| LLR-005.5 | test (unit) | TC-049 | Non-writable log dir → clean error or fallback (no silent failure); 5 MB cap; handler reuse. |
| HLR-006 | inspection | TC-050 | Public symbols: `get_raw_value`, `get_physical_value`, `validate_characteristic`. |
| LLR-006.1 | inspection | TC-051 | Decode/conversion fields (`raw_value`, `decode_error`, `physical_value`, `conversion_status`, `conversion_error`) match `REQUIREMENTS.md`. |
| LLR-006.1 | test (unit) | TC-052 | Lock public-API field shape via `tests/test_tui_public_api.py` extension. |
| HLR-007a | inspection | TC-060 | Cross-file incompatibility class walk through `engine.py`. |
| HLR-007b | test (integration) | TC-064 | Panel-render snapshot for each class via `tests/test_tui_app.py` (snapshot infra added in Phase 3 increment 1). |
| LLR-007.1 | inspection | TC-061 | Class → existing `ValidationIssue.code` mapping; gaps recorded with recommended code names. |
| LLR-007.2 | test (integration) | TC-062.a | S19/HEX overlap → new fixture `tests/fixtures/overlap_s19_hex/`. |
| LLR-007.2 | test (integration) | TC-062.b | A2L tag range out of S19 range → reuse `large_project`. |
| LLR-007.2 | test (integration) | TC-062.c | MAC address out of S19 range → reuse `large_project`. |
| LLR-007.2 | test (integration) | TC-062.d | A2L↔MAC same-name address mismatch → reuse `large_project`. |
| LLR-007.2 | test (integration) | TC-062.e | symbol-only-in-MAC → reuse `large_project`. |
| LLR-007.2 | test (integration) | TC-062.f | symbol-only-in-A2L → reuse `large_project`. |
| LLR-007.2 | test (integration) | TC-062.g | duplicate-address alias → new fixture `tests/fixtures/duplicate_alias_mac/`. |
| LLR-007.2 | test (integration) | TC-062.h | parsed-record corruption → new fixture `tests/fixtures/corrupt_records/`. |
| LLR-007.3 | inspection | TC-063 | Severity matrix vs. `REQUIREMENTS.md` Issues Tile Severity Policy; record active alias policy. |
| LLR-007.4 | test (integration) | TC-065 | Per-class panel-render snapshot (extends TC-064 with parametrisation over the eight classes). |
| HLR-008 | inspection | TC-070 | Validation rule completeness audit (forward + reverse). |
| LLR-008.1 | inspection | TC-071 | Forward direction audit matrix: code → rule → test; record dead/untested codes. |
| LLR-008.2 | inspection | TC-072 | Reverse direction audit matrix: rule → code → severity; record severity divergences. |
| HLR-009 | test (integration) | TC-080 | Engine determinism + `CoverageMetrics` correctness audit. |
| LLR-009.1 | test (integration) | TC-081 | Repeat-run determinism on `large_project`; new test in `tests/test_validation_engine.py`. |
| LLR-009.2 | inspection | TC-082 | `CoverageMetrics` non-zero on non-empty input; field-presence check vs. `model.py`. |

### 5.3 Batch acceptance criteria

- 100% of `R-*` rows in `REQUIREMENTS.md` re-confirmed; each marked `confirmed`, `promote` (`Manual` / `Partial` → `Automated`), `demote`, or `drift` with rationale.
- Every severity-classification rule (A2L colour, MAC colour, Issues panel `Errors` / `Warnings` / `Optional info`) traced to a concrete `ValidationIssue.code` in `validation/model.py`, or filed as an explicit Finding (per §1.3) in the audit packet.
- All new tests added in this batch use the existing deterministic fixtures from `tests/conftest.py` (`large_s19`, `large_a2l`, `large_mac`, `large_project`) except for the three per-class fixtures introduced under `tests/fixtures/` for LLR-007.2 TC-062.a/g/h.
- TUI orchestration boundary audit completed: every parse/enrich/validate call site in `tui/app.py` is enumerated and classified as `routed via services/` or `bypass — Finding-NNN`. **Pass = enumeration is complete.** Closing bypass Findings is tracked under `.dev-flow/02-review.md` §Deferrals (closes review finding Q-005).
- Workspace-IO audit records explicit pass/fail per check for: read-path precedence (LLR-005.1), project-name sanitisation (LLR-005.2), write-path containment + symlink/junction rejection + 256 MB size cap (LLR-005.3), project-folder validation including case-only collision (LLR-005.4), and rotating-log behaviour including non-writable fallback (LLR-005.5).
- Public API contract review records explicit pass/fail for `get_raw_value`, `get_physical_value`, `validate_characteristic`, and the decode/conversion status fields. The severity-colour-map invariant is asserted under LLR-002.1, not LLR-006.1.
- `pytest -q` passes on Python 3.11 with all newly added or modified tests.
- **Zero `blocker`-severity Findings open at the gate.** Every `major`-severity Finding is logged in `.dev-flow/02-review.md` §Deferrals with fields `{ID, owner, target batch, blast radius if not fixed}` (closes review finding Q-006).
- Audit packet delivered using GRNDIA's `review-packet` 7-section format.
- Cross-file incompatibility classes (per `REQUIREMENTS.md` Issues Tile Severity Policy) are each mapped to either an existing `ValidationIssue.code` or filed as a coverage gap with a recommended code name; for every class that maps to an existing code, the audit records pass/fail for the engine-side error + report co-emission contract (LLR-007.2) AND the panel-render contract (LLR-007.4).
- Validation rule completeness verified in both directions: zero codes are dead (no emitting rule), zero codes are untested (no asserting test), and zero rules emit a code with severity divergent from `REQUIREMENTS.md` (LLR-008.1, LLR-008.2).
- `validate_artifact_consistency` determinism verified by a repeated run on the `large_project` fixture; any non-determinism is a `blocker` Finding (LLR-009.1). `CoverageMetrics` populated and non-zero on every non-empty input (LLR-009.2).
- **Issue-message scrubbing verified:** control-character strip and 500-character truncation enforced in every rule emission (LLR-002.3).
- **Workspace-IO write-path containment verified:** `copy_into_workarea` rejects destinations outside `.s19tool/workarea/`, sources or destinations crossing symbolic links / NTFS junctions, and sources exceeding the 256 MB cap (LLR-005.3). Closes Phase 2 blockers S-001, S-002.
- **Cross-file incompatibility per-class fixtures present** in `tests/fixtures/` for the three classes not covered by `large_project` (overlap, duplicate-alias, corrupt-records) (LLR-007.2).

---

## 6. Appendices (optional)

### 6.1 Extended glossary
*(Reserved.)*

### 6.2 Relevant design decisions
- The audit is framed with "the system" = the audit process and its outputs. This avoids the awkward fit of writing `shall` clauses about an existing application as if it were a new system, while still producing testable EARS statements.
- Promotion of `Manual` / `Partial` rows to `Automated` is in scope only where a stable test can be added within the ≤5-files-per-increment rule. Larger refactors are deferred to follow-up batches.
- The `Finding` schema (§1.3) is the single source of truth for "shall record a finding" obligations across all HLR/LLR Statements. Two prior reviewers using different schemas was the dominant phase-2 review observation; centralising it removes that risk.
- HLR-007 was split into HLR-007a (engine emit + populate) and HLR-007b (panel render) so that an engine-side test cannot hide a render-side filter.
- The two security blockers from Phase 2 (S-001 destination containment, S-002 symlink/junction follow-through) are closed by LLR-005.3. Closing them may require a Phase 3 implementation increment that adds the actual checks to `copy_into_workarea` — this is product-behaviour change and is bounded by §6.3 R-6.

### 6.3 Open risks
- **R-1** — `s19_app/tui/app.py` is ~5k LOC. Even an inspection pass at this size risks missing parse-bypass call sites; LLR-003.1 mitigates with an explicit call-graph enumeration, and Phase 2 review finding Q-005 was closed by reframing pass = enumeration complete (not absence of bypass).
- **R-2** — `REQUIREMENTS.md` mixes the new product-requirements section with the older `R-*` traceability section. The audit treats both as authoritative; any contradiction between them becomes a Finding.
- **R-3** — Severity colour string contract (`Red`, `Orange`, `Green`, `White`, `Grey`) is now verified by parametrised unit test in LLR-002.1, including the bidirectional invariant.
- **R-4** — The cross-file incompatibility class enumeration in HLR-007a / LLR-007.1 is anchored on `REQUIREMENTS.md` Issues Tile Severity Policy. If the document omits a class that is implemented in code, the audit will not catch the omission; this is mitigated by the bidirectional rule-completeness sweep in HLR-008 (every emitted code → traced back to a documented class or filed as an undocumented-code Finding).
- **R-5** — *(closed at iteration 3)* Determinism check (LLR-009.1) requires running `validate_artifact_consistency` against `large_project`. **Verified deterministic via inspection of `tests/conftest.py` (`make_large_s19/a2l/mac` use `seed=0` defaults).** Promoted from open risk to verified pre-condition (closes review finding Q-008).
- **R-6** — LLR-005.3 mandates write-path containment, symlink/junction rejection, and a 256 MB size cap on `copy_into_workarea`. These checks may not exist in the implementation today. Closing this LLR may therefore require a Phase 3 implementation increment that adds the actual product-behaviour checks before the audit TC can pass. The increment is bounded to `s19_app/tui/workspace.py` only (≤1 file) and is the highest-priority Phase 3 item.
- **R-7** — HLR-007b panel-render audit (LLR-007.4 / TC-064 / TC-065) depends on a Textual snapshot framework. If the existing `tests/test_tui_app.py` does not yet have snapshot infrastructure, increment 1 of Phase 3 must add it (e.g. `App.run_test()` with a query against the Issues panel widget). This is bounded to the test file plus a new conftest helper if needed.
- **R-8** — DoS-class pathological parser inputs (e.g. an Intel HEX file with sparse single-byte fills across the full 32-bit address space causing the sparse map to balloon) are out of scope per §2.5. Acknowledged as future-batch material; not a finding for this batch.
