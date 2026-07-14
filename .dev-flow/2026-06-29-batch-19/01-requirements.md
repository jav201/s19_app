# Requirements Document — s19_app — Batch 2026-06-29-batch-19

> **Artifact language**
> This template is the canonical **English scaffold**. Generate the artifact in the batch's development language (`state.json` `language`). For Spanish batches, translate the section headers and guidance and use `deberá` as the normative keyword (≡ `shall`). The normative RULES in this preamble are **language-independent** and enforced regardless of artifact language.

> **Strict normative convention — IEEE 830 + EARS**
> - `shall` / `deberá` = normative, binding, verifiable requirement. **Only** inside HLR / LLR statements.
> - `should` / `debería` = informative / explanatory text, **NOT binding**. **Only** outside HLR / LLR statements (rationale, description, context).
> - Any modal `should` / `debería` inside an HLR / LLR statement is a **writing error** and will be flagged as a blocker in phase 2.
> - `may` = optional. `will` = future declaration or fact about an external actor.

> **Verifiability rule — captured at draft, not at phase-2 gate**
> (Root cause of the batch-02 + batch-03 post-mortems: both batches forced a phase-1 iteration for the same reason — `test`/`analysis` validation labels without a named executed verification and a numeric pass threshold. The corrective action is baked into the template.)
>
> Every requirement labelled `test` or `analysis` **must** carry TWO fields on its line:
> - **Executed verification:** what EXACTLY runs / is inspected (e.g. `npm run typecheck`, `vitest run path/to/file.test.ts -t TC-001`, `signature-diff inspection vs main`). Without this the method is not executable.
> - **Numeric pass threshold:** the quantitative pass criterion (e.g. `0 errors`, `peak post-limiter ≤ −6 dBFS`, `RMS error < 0.01`, `LLR coverage ≥ 100 %`). Without this the result is not objective.
>
> For `demo` (perceptual): describe the observable procedure + the named qualitative criterion.
> For `inspection` (structural): name the file / commit / section to inspect + the observable condition.
>
> **Any `test`/`analysis` LLR missing these two fields is a phase-2 blocker.**

> **Parent-HLR re-read rule — captured at the Phase-1 reconciliation gate**
> (Root cause of the batch-06 A-B1 + batch-07 A-03 + batch-08 A-01-cluster post-mortems: THREE consecutive batches relaxed an LLR threshold or claimed a promotion during reconciliation without propagating the change up to the parent HLR / into the LLR body, leaving §6.4 asserting things the §3/§4 body didn't reflect. Adding this rule as prose at batch-07 closeout did NOT prevent the batch-08 recurrence — because a rule that says "re-read" with no required output silently degrades to "I thought about it." The corrective action is to mandate an ARTIFACT, not a process step.)
>
> **Any time an LLR's `Numeric pass threshold` or `Statement` changes at the Phase-1 reconciliation gate — or an LLR is added/promoted/removed — the §6.4 reconciliation log MUST contain a per-decision audit table** with one row per changed decision and these columns: `Decision ID | What changed | Parent HLR re-read? (which HLR + what changed there, or "no change required" + why) | Body edit landed? (the §3/§4 line that now reflects it)`.
>
> **Body-first ordering is mandatory:** write the §3/§4 HLR/LLR body edit FIRST, then write the §6.4 audit row that points at it. Never write a §6.4 claim before the body line it describes exists. This eliminates the "claimed but missing" failure mode that recurred in batch-06/07/08.
>
> **Two phase-2 blockers enforce this:** (a) any HLR threshold contradicting its decomposed LLRs; (b) any §6.4 audit row whose "Body edit landed?" column points at a §3/§4 line that does not exist (a reviewer greps for it). Both are mechanically checkable.

> **Testing-strategy-vs-ADR rule — captured at draft, not at phase-3 boundary**
> (Root cause of the batch-06 F-6 / Phase-3 infrastructure correction: every `test (...)` label was labelled against a testing stack — JSDOM + Testing Library — that didn't exist in the repo and was explicitly rejected by ADR-0002. The software-dev agent correctly stopped at the boundary, but the gap should be caught in Phase 1.)
>
> **Every `test (...)` validation label MUST be cross-checked against the project's testing-strategy ADR and the actual `package.json` / `requirements.txt`** before locking the LLR. If the labelled runtime isn't installed and isn't the strategy-ratified path, that's a phase-2 blocker.

> **LLR symbol-citation rule — captured at draft, not at the phase-3 boundary**
> (Root cause of the batch-05 F-A-01 blocker + three Phase-3 doc deviations: LLRs named specific private fields/methods — `_alt_hex_window_start`, `_mac_hex_window_start`, `_on_mac_records_row_highlighted`, `current_file.sorted_ranges` — and a layout constant (`width: 78`) that were inferred from plausible symmetry, NOT from observed code. The fabricated paging fields were caught by the independent Phase-2 re-review before any code was written; the other three survived to Phase 3 and surfaced only at implementation time. The common failure mode is "named a symbol that looks like it should exist." A rule that says "verify" with no required artifact silently degrades to "I assumed," so this mandates a CITATION, not a process step.)
>
> **Any LLR (or its Acceptance criteria / Executed verification) that names a concrete code symbol — a private field, method, function, class, or widget id — MUST cite a grep-verified `file:line` for that symbol at draft time.** If the symbol does not yet exist (it will be created by the increment), it MUST be explicitly flagged `NEW — created in Phase 3` so the reviewer does not expect to find it. Layout-geometry / magic-number constants (pane widths, row counts, byte offsets) MUST either cite a measured value with the measurement method, or be flagged `assumed — verify in Phase 3`.
>
> **Two phase-2 blockers enforce this:** (a) any LLR that names a symbol without a `file:line` citation and without a `NEW` flag (a reviewer greps for the symbol; if it neither exists nor is flagged NEW, block); (b) any layout/magic-number constant asserted as fact without a measurement citation or an `assumed` flag. Both are mechanically checkable by grep.

> **Environmental-measurement citation rule — extends the LLR symbol-citation rule.** Any constant describing the runtime or layout **environment** — container/parent widths, derived geometry (e.g. `body_w`, pane shares), responsive breakpoints and transition points, timing/latency budgets, platform or CI environment values — MUST cite, at draft time: **(a) WHERE it was measured** (the probe or test `file:line`, or the exact `App.run_test(size=...)` / command invocation), **AND (b) the REGIME/CONDITIONS under which the measurement holds** (terminal-size band, CSS class state, rail/panel visibility, platform, dataset size). A measurement applied **outside its measured regime** MUST be re-measured in that regime or flagged `assumed — verify per-regime`. **Derived numbers inherit the flag**: any cell count, threshold, or transition point computed from an environmental constant is not a fact until the underlying measurement is regime-valid, and must cite the constant it derives from. **Phase-2 blocker classes:** (a) an environmental constant asserted as fact whose citation lacks its measurement conditions; (b) a constant or its derivatives applied in a regime other than the one cited. (Origin: batch-06 B-1.)

> **Probe self-test rule — captured from batch-07 B-3/B-4.** Any executable verification artifact written into an HLR/LLR — a grep/rg probe, a regex, a pytest node id, a determinism/equality procedure, an inspection command — MUST be EXECUTED at draft time against the current tree, with its **expected pre-state result recorded next to the spec** (e.g. "probe run 2026-06-10: 164 hits pre-retirement; pass condition = 0 post"). A probe that cannot demonstrate a non-trivial pre-state — hits today for a future-absence check, a failing-then-passing pair for a behavioral check, both sides exercised for an equality — is unproven and shall be flagged `unexecuted — verify in Phase 2`. **Phase-2 blocker classes:** (a) a verification command recorded without executed pre-state evidence; (b) a verification whose pre-state execution contradicts its claimed semantics. (Origin: batch-07 B-3 — a BRE grep returning 0 on a tree known to contain 164 hits — and B-4 — a double-apply equality no correct implementation could satisfy.)

> **Contract-touch rule — captured from batch-07 B-1/B-2.** A cross-cutting interface contract (canonical field set, producer/consumer table) is reconciled at merge but **invalidated by any subsequent edit to any LLR it cites** — including gate-decision insertions, which are the most likely to add fields and the least likely to be reconciled. Any post-draft edit touching a producer or consumer LLR re-opens the contract as a mandatory checklist row: the editor shall re-run the identity check (field-set equality across every producer and consumer enumeration) and record the re-run in that edit's audit-table row. An edit that adds a field to one side without the recorded re-run is a Phase-2 blocker. (Origin: batch-07 B-1/B-2 — LLR-002.7/002.8 added `saved_path`/`issues` hours after the C-6 contract was drafted.)

> **AC-artifact citation rule — extends the LLR symbol-citation rule.** Any data artifact named in an HLR/LLR **Acceptance criteria** line — a test fixture, example file, directory, or data path — is citation surface, same as a code symbol: it MUST carry either an EXECUTED existence probe recorded at draft time (e.g. `Glob examples/**/*.hex → N files, <date>`) or an explicit `NEW — created in Phase 3` flag with the artifact counted in the increment file budget. **Phase-2 blocker:** an AC-named artifact with neither an executed existence probe nor a NEW flag. (Origin: batch-08 B-1 — an acceptance criterion demanded "a real `.hex` example from `examples/`" on a tree measured to contain zero `.hex` files; found independently by two reviewers because the rule's wording covered only symbols.)

> **Probe-regime rule — extends the probe self-test rule.** A probe's positive control MUST exercise the same syntactic/structural REGIME as the protected targets (import depth, package level, file class, CSS state, platform), and the ledger entry MUST state that regime next to the recorded execution. If the target does not exist yet, the control runs on a synthetic in-regime fixture created at the exact target location/depth and deleted after (the batch-08 `_b2_scratch` pattern: scratch package at target depth → probe hits all violation forms → negative control on a known-legitimate module → scratch removed). An out-of-regime control does not discharge the probe self-test rule — it is recorded `superseded-pending` until an in-regime control exists. **Phase-2 blocker classes:** (a) a probe whose positive control's regime differs from the target regime; (b) a ledger entry that omits the control's regime. (Origin: batch-08 B-2 — a reverse-import probe whose executed control ran at single-dot import depth while the protected targets lived one package level deeper, where the natural violation form was two-dot relative and escaped the regex on the SOLE verification of its LLR.)

> **Supersession-census-completeness rule — captured from batch-09 Lesson 1, reframed at batch-10.** When a batch supersedes scaffold/placeholder behavior OR adds/moves a module OR edits an existing file, the Phase-1 supersession census MUST account for ALL guard families that the change can break, not only the named behavioral-placeholder one: (a) **behavioral-placeholder guards** — deferral/placeholder/"not-yet" assertions; (b) **structural / placement / allowlist guards** — package-shape invariants (e.g. `rg -n 'glob\(.\*\.py.\)|listdir|iterdir|allowlist|_root_modules' tests/`); (c) **AST-composition guards** (e.g. `rg -n 'ast\.|\.body|calls\s*<=' tests/`); (d) **engine-frozen / no-diff-vs-main guards** (e.g. `rg -n '_ENGINE_PATHS|no_diff_vs_main|engine_modules_unchanged' tests/`). The predicted-red set is incomplete until all run; any guard whose invariant the change violates is added with its disposition at Phase 1, not discovered at the increment gate. (Origin: batch-09 — two package-root placement guards escaped a placeholder-only census; batch-10 — a 4th family, the engine-frozen guards that git-freeze `core.py`/`hexfile.py`/`range_index.py`/`validation/`/`tui/a2l.py`/`tui/mac.py`/`tui/color_policy.py`, was MISSED even after the b09 widening and broke the emitter's `hexfile.py` placement at the I1 gate, forcing the R2 relocation to `tui/changes/io.py`.)

> **Census = completeness PRINCIPLE, not a grep checklist (A-1, batch-10).** The family list above is a starting set, NOT an exhaustive enumeration — "grep these N patterns" is structurally blind to any guard whose pattern isn't listed. The census MUST be run **change-first**: take the batch's planned new/moved/edited file list and, for EACH file, check it against EVERY test that asserts on a file PATH / module STRUCTURE / import GRAPH / git-DIFF (key on the CATEGORY of assertion, not the specific pattern). A guard that fires on a planned file is a Phase-1 finding, before code. **Corollary — new-symbol-into-existing-file probe (A-3):** any LLR adding a NEW symbol to an EXISTING module MUST cite a draft-time probe proving that file is not frozen/allowlisted against the edit. (Origin: batch-10 — the emitter into the frozen `hexfile.py`.)

> **Ban the "VERIFIED COMPLETE" census stamp (A-2, batch-10).** A census/completeness claim MUST NOT be stamped "VERIFIED COMPLETE" by re-running the known families — re-running an incomplete checklist cannot detect that the checklist is incomplete. A completeness verdict must EITHER show why no (N+1)th family exists (the enumeration of the whole structural-guard surface), OR be downgraded to "best-effort + gate-confirmed." **The increment GATE — running the actual moved/edited file against the real suite — is the completeness guarantee; the census is a Phase-1 cost-reduction heuristic that catches it cheaply, not a proof.** (Origin: batch-10 — Phase-2 certified the census "VERIFIED COMPLETE (re-ran all 3 grep families)"; "all 3" was the bug, and the 4th family broke at the I1 gate.)

> **Phase-4 supersession-completeness inspection (V-3, batch-09).** The Phase-4 validation matrix MUST include a row that greps the WHOLE class of superseded placeholder constants/markers and asserts every surviving reference is a NEGATIVE assertion (absence), not a live dependency — e.g. confirm the only surviving `#diff_deferral_notice` reference is `not bool(...)` and the removed constants survive solely inside a "they're gone" guard. A by-hand confirmation is insufficient; promote it to a standing matrix row.

> **Provisional-identifier scope rule (V-5, batch-09).** The `provisional until Phase 3` flag (batch-08 A-3) covers EVERY implementer-owned identifier in an Executed-verification line — the test FILE path AND the `-k` selector AND the pytest node id — not only node ids. A pinned-but-wrong file name or `-k` token produces a false "test missing" signal at the validation gate exactly as a pinned node id does. Spec convention: "Executed-verification file paths, `-k` selectors, and node ids are all provisional-until-Phase-3; the implemented names are reconciled from the real tree at Phase 4." (Origin: batch-09 DEV-1 — the spec pinned `tests/test_diff_report.py`; the implementer chose `test_diff_report_service.py`, producing a Phase-6 rename-reconciliation chore.)

> **Purity-probe form rule (V-4, batch-09).** An import-purity probe MUST match import statements, not the bare token — use `rg -n "import <pkg>|from <pkg>|<Pkg>"`, never substring `rg -c "<pkg>"` (which matches the word in docstrings/prose and yields a benign-but-noisy false positive that must then be hand-resolved). (Origin: batch-09 DEV-5 — `rg -c "textual"` matched the word "textual" in a module docstring.)

> **Story-dimension coverage / surface-reachability rule (A-5, batch-11).** Coverage must reach the SHIPPED surface, not only a service's direct API. (a) For each input dimension named in a source user story, ≥1 TC MUST exercise it through the shipped surface (the handler/UI call-site), not only via direct service kwargs. (b) When a handler wires a writer/service that accepts dimensions the handler defaults empty, decompose a COMPOSITION LLR for that wiring or record the dimension out-of-scope explicitly. (c) Phase-4 carries a standing surface-reachability matrix row: handler call-site kwargs vs service signature vs story dimensions. (Origin: batch-11 SCOPE-1 — a manifest writer fully tested via direct kwargs while the save handler passed empty batch/assignments, so the shipped artifact carried only `active_variant`; 23/23 TCs + full suite passed because coverage was keyed on the writer's API, not the user's story.)

> **Two-layer validation rule — black-box behavioral acceptance + white-box functional (headline, non-negotiable).** A user story is a user-verified OUTCOME / observable behavior (the WHAT), validated black-box through the shipped surface; HLR/LLR are the internal workings (the HOW), validated white-box by functional TCs. **No story is "done" until a black-box test (`AT-NNN`) observes its user-verified outcome through the shipped surface, with boundary + negative evidence — independent of the white-box `TC-NNN` that validate the HLR/LLR mechanism. A green white-box suite that never observes the behavior is not acceptance.** Every output-producing requirement MUST name its concrete deliverable and how it is observed (file at path + non-empty + required content; or rendered screen element). **Dual traceability is mandatory** (§5.2): behavioral `US → AT-NNN → observed outcome` AND functional `US → HLR → LLR → TC-NNN`; a requirement with only one chain is incomplete. Layer B is the `test (pilot)` / e2e / artifact-on-disk idiom (automated), **not `demo`**; `AT-NNN` ids are provisional-until-Phase-3 per the **Provisional-identifier scope rule (V-5)** and reconciled at Phase 4. **Phase-2 blocker classes:** (a) a story with no `AT`; (b) an output-producing requirement that doesn't name its observable deliverable + observation method; (c) an incomplete traceability chain (either side); (d) an "acceptance" test that references an internal symbol (not genuinely black-box). (Origin: a project-report story whose white-box TCs — `test_full_report_content`, builders, window math — passed green while the report was never produced as a user-facing output; batch-14.)

---

## 1. Introduction

### 1.1 Purpose
*(Informative text. Describes the document's objective.)*

### 1.2 Scope
*(What this batch covers and what it does NOT cover.)*

### 1.3 Definitions, acronyms, abbreviations
| Term | Definition |
|------|------------|
| | |

### 1.4 References
*(Related documents, standards, external tickets.)*

### 1.5 Document overview
*(How this document is structured.)*

---

## 2. Overall description

### 2.1 Product perspective
*(How the change fits into the larger system.)*

### 2.2 Product functions
*(High-level list of functional capabilities.)*

### 2.3 User characteristics
*(Roles, permissions, expected experience levels.)*

### 2.4 Constraints
- **Engine-frozen set OFF-LIMITS** (read-only): `core.py`, `hexfile.py`, `range_index.py`, `validation/` (incl. `model.py::ValidationIssue`), `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`. The addendum/issue work consumes `ValidationIssue` fields; it never edits the model.
- ≤5 files/increment; two-layer AT+TC; commits/PRs on operator approval; `/dev-flow` full rigor.
- New code follows the repo docstring (Summary→…→Dependencies) + type-hint conventions; `ReportOptions` keeps its strict per-field `__post_init__` validation.

### 2.5 Assumptions and dependencies
*(All disk-verified in the Phase-0 spike; if any fails, the batch is invalidated.)*
- `ValidationIssue` carries `address: Optional[int]`, `symbol`, `related_artifacts` (`validation/model.py:126/125/128`).
- The report emits sections via `emit(_<section>_lines(...))` in `generate_project_report`; `_declaration_error_lines` already renders issues (code/severity/message only).
- `project.json` is written by `manifest_writer.serialize_manifest`/`write_project_manifest` and read by `variant_execution_service.read_project_manifest` — both outside the frozen set.
- `ReportViewerScreen` is the report-generation surface (`Context bytes` input + Generate → `GenerateRequested` → `ReportOptions`).
- An issue whose `address` is `None` is simply not region-attributable (acceptable; not all findings are address-bearing).

### 2.6 Source user stories

> Connextra format: **"As a `<role>`, I want `<goal>`, so that `<benefit>`"**. Each US gets a unique ID `US-NNN` and must be traceable to one or more HLRs.
> **Phase 0 — Definition of Ready (INVEST):** every story is refined and classified before it can be derived into HLR (Phase 1). Only `READY` stories proceed.

| ID | User Story | Source | DoR status |
|----|------------|--------|------------|
| US-020c | As an operator generating a project report, I want to declare named memory regions (name + start/end address) and have the report carry an **addendum** that lists them and, per region, cross-references the modifications and validation issues whose address falls inside, so that I can verify what happened in the regions I care about. | backlog #10 / batch-17 DoR deferral | **READY** |
| US-020d | As an operator reading the report's issues, I want each issue to show its address, symbol and related artifacts (not just code/severity/message), and declared regions to list the issues within them, so that issues are actionable and tied to the regions I declared. | backlog #10 / batch-17 DoR deferral | **READY** |

#### Refinement log (one block per story)

**US-020c — declared-region report addendum (Expected-zone, DoR pick A)**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ (4 increments) · T ✓
- **Functionality (V, N):** user = report reader/operator · outcome = the generated report contains an addendum listing each declared region and, per region, the modifications + validation issues whose address ∈ [start, end] · why = verify "what happened in the regions I care about" offline · out of scope = changing the validation engine / `ValidationIssue` model (frozen); the TUI issues screen (shipped batch-17 US-020a/b); diff/entropy reports (#12).
- **Feasibility (E, S):** path = NEW `DeclaredRegion(name,start,end)` model + `report_service._addendum_lines` (gated by `ReportOptions.declared_regions`) + `ReportViewerScreen` input + `project.json` persistence (manifest writer). Echoes `CrcRegion(start,end)`. dependencies = `ValidationIssue.address` (frozen, read-only), the report emit pipeline, the manifest envelope — all disk-verified in the Phase-0 spike. fits one batch? = yes, **4 increments**.
- **Evaluability (T):** "When the operator declares a region and generates a report, the report addendum lists that region and the modifications/issues inside it" — observed by reading the generated report file + driving `ReportViewerScreen` (AT-024a/b/c) + the persist→reload roundtrip (AT-026a).
- **Open questions (resolved at DoR):** semantics = **A Expected-zone** (operator pick); persistence = **in-scope** (operator pick). Addendum placement in report order → Phase-3 detail (project-level section after the per-variant blocks).
- **Classification:** `READY`.

**US-020d — issues→report enrichment + region cross-reference (DoR scope: Both)**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):** user = report reader · outcome = each rendered issue shows address/symbol/related_artifacts (when present); declared regions list the issues inside them · why = issues become actionable + tied to declared regions · out of scope = editing the frozen `ValidationIssue` model; the TUI issues screen.
- **Feasibility (E, S):** path = (d-i) augment `report_service._declaration_error_lines` to render the optional fields (the section ALREADY exists, renders only code/severity/message — Phase-0 verified report_service.py:~700); (d-ii) the per-region issue cross-ref lives in US-020c's `_addendum_lines`. fits one batch? = yes; d-i is the smallest independent increment (Inc1).
- **Evaluability (T):** "When the report renders an issue carrying an address/symbol/related, the operator sees those fields" — observed by reading the generated report (AT-025a) + the negative (issue without an address shows no `@0x`, AT-025b).
- **Open questions:** none (semantics + scope resolved at DoR).
- **Classification:** `READY`.

---

## 3. High-level requirements (HLR)

> Each HLR is an EARS statement. Allowed patterns:
>
> - **Ubiquitous:** `The <system> shall <response>.`
> - **Event-driven:** `When <trigger>, the <system> shall <response>.`
> - **State-driven:** `While <state>, the <system> shall <response>.`
> - **Optional feature:** `Where <feature is included>, the <system> shall <response>.`
> - **Unwanted behavior:** `If <unwanted condition>, then the <system> shall <response>.`
> - **Complex:** combinations of the above.

### HLR-024 — Declared-region report addendum
- **Traceability:** US-020c
- **Statement:** When the operator generates a project report with one or more declared memory regions, the system shall emit an addendum section that lists each declared region (`name`, `start`, `end`) and, for each region, the modification entries and the validation issues whose address falls within `[start, end]`.
- **Rationale (informative):** makes the report answer "what happened in the regions I declared?" — derived from the report's existing modification + issue data, cross-referenced by address; no new validation logic.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_report_service.py -k addendum` + `tests/test_report_addendum.py`
- **Numeric pass threshold:** report text contains the addendum header + a row for every declared region; each region lists exactly the modifications/issues whose address ∈ `[start, end]` and no others (0 mis-attributed); a region with no hits renders an explicit "none".
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** the generated report contains an addendum listing the declared regions and the modifications/issues inside each.
  - **Shipped surface:** `generate_project_report` (report_service.py) → `reports/<ts>-report.md`; declared via `ReportViewerScreen`.
  - **Deliverable + observation:** report file — non-empty, text contains the addendum header + each region + correct per-region membership.
  - **Acceptance test(s):** `AT-024a` (addendum present + cross-ref content asserted — C-10) + `AT-024b` (region with zero hits → "none" boundary) + `AT-024c` (region declared through `ReportViewerScreen` → appears in the produced report — C-12 output-then-consume).
  - **Boundary catalog (QC-3):** ☑ empty (0 regions → no addendum; region with 0 hits → "none") · ☑ boundary (issue/modification at exactly `start` and at `end` — inclusive) · ☑ invalid (`start > end` or `start < 0` rejected at model construction — LLR-024.1) · ☑ error (malformed region input in the dialog → rejected, not crash — LLR-024.3) · ☑ injection (region `name` with newline / markdown / ANSI → stored scrubbed via `_scrub_issue_message`, rendered inert in the report — LLR-024.1, security-F1).

### HLR-025 — Issue rendering enrichment
- **Traceability:** US-020d
- **Statement:** When the report renders a validation issue, the system shall include the issue's address (hexadecimal, when present), symbol (when set), and related artifacts (when non-empty), in addition to its code, severity, and message.
- **Rationale (informative):** the report's "Declaration errors" section already lists issues but drops the address/symbol/related fields that `ValidationIssue` carries (and that batch-17 US-020b surfaced in the TUI) — making report issues actionable.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_report_service.py -k issue_fields`
- **Numeric pass threshold:** an issue carrying address/symbol/related → all three present in its rendered line; an issue lacking them → none of the optional fragments shown (no empty `@0x` / `symbol=` / `related=`).
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** a rendered issue line shows `@ 0x<addr>`, its symbol, and its related artifacts when the issue carries them.
  - **Shipped surface:** `generate_project_report` → report file (the "Declaration errors" section).
  - **Deliverable + observation:** report file — issue line contains the documented optional fields.
  - **Acceptance test(s):** `AT-025a` (enriched issue line content) + `AT-025b` (negative: issue without an address → no `@0x`, proving present/absent discrimination).
  - **Boundary catalog (QC-3):** ☑ empty (issue with no optional fields → bare line) · ☑ boundary (`address == 0` → `@ 0x0` rendered, not suppressed) · ☐ invalid N/A (consume-only of a frozen, validated model) · ☐ error N/A (pure rendering of present fields).

### HLR-026 — Declared-region persistence
- **Traceability:** US-020c
- **Statement:** When the operator declares memory regions, the system shall persist them in the project manifest (`project.json`) and load them on project read, and a manifest written before this field existed shall read back as zero declared regions (back-compatible).
- **Rationale (informative):** declared regions are a per-project intent that should survive across report generations, following the existing `project.json` envelope pattern.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_manifest_writer.py -k declared_regions`
- **Numeric pass threshold:** declare → serialize → read roundtrip returns the same region set; a manifest with no `declared_regions` key reads back exactly 0 regions; a malformed region entry emits a `ValidationIssue` and does not abort the read (collect-don't-abort).
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** regions declared and saved are present after a project reload.
  - **Shipped surface:** `manifest_writer.write_project_manifest` → `project.json`; `variant_execution_service.read_project_manifest`.
  - **Deliverable + observation:** `project.json` on disk carries the regions; the read path returns them.
  - **Acceptance test(s):** `AT-026a` (declare → persist → reload roundtrip — observes the **`project.json` file on disk** carries the `declared_regions` array AND the read path returns the same regions; artifact-on-disk black-box, not a pure service-API roundtrip — qa-F4).
  - **Boundary catalog (QC-3):** ☑ empty (absent key → 0 regions; back-compat) · ☑ boundary (0 declared regions → key absent or empty) · ☑ invalid (malformed entry → `ValidationIssue`, not crash) · ☐ error N/A (atomic write path unchanged).

---

## 4. Low-level requirements (LLR)

> Each LLR decomposes an HLR into a verifiable property at the implementation level.
> Same EARS regime. ID format: `LLR-<HLR>.<M>`.

### LLR-025.1 — Issue-field enrichment in the report `[Inc1]`
- **Traceability:** HLR-025
- **Statement:** `report_service._declaration_error_lines` shall render, per issue, `@ 0x{address:X}` when `address is not None`, `symbol={symbol}` when `symbol` is set, and `related={related_artifacts}` when non-empty — appended to the existing `[{code}] {severity}: {message}` line.
- **Target file:** `s19_app/tui/services/report_service.py` (`_declaration_error_lines`, verified `:~700`; OUTSIDE frozen). Reads `ValidationIssue.address/.symbol/.related_artifacts` (`validation/model.py:126/125/128`, FROZEN — read-only).
- **Validation:** `test (unit)`.
- **Executed verification:** `pytest tests/test_report_service.py -k issue_fields`.
- **Numeric pass threshold:** issue with all optional fields → all three fragments present; issue with none → bare line, no empty `@0x`/`symbol=`/`related=`; `address==0` → `@ 0x0` present.
- **Acceptance criteria (informative):** rendering reads the live `ValidationIssue` fields (no duplicated literal).

### LLR-024.1 — `DeclaredRegion` model `[NEW — Inc2]`
- **Traceability:** HLR-024, HLR-026 (shared substrate)
- **Statement:** A new module `s19_app/tui/services/report_addendum.py` shall expose `DeclaredRegion(name: str, start: int, end: int)` — a frozen dataclass validating, with one explicit `ValueError` per invalid field (never a silent clamp): `name` non-empty; `start >= 0`; `start <= end`. The constructor shall **scrub + length-cap `name`** by reusing `validation.model._scrub_issue_message` (strips control/ANSI chars + caps length, cap ≈80) BEFORE the value is stored, so the same sanitization the codebase already applies to `issue.message` applies to the region name before it reaches the report or `project.json` (security-F1). Membership is the **inclusive** predicate `start <= addr <= end` — NOTE: distinct from `CrcRegion`'s half-open `[start, end)`; the §3 (HLR-024) boundary catalog is authoritative (architect-M1).
- **Target file:** `s19_app/tui/services/report_addendum.py` (NEW; OUTSIDE frozen set). Reuses `validation.model._scrub_issue_message` (frozen module — imported read-only); structure modelled on `CrcRegion` (`tui/operations/crc_config.py:61`) but bounds convention differs (inclusive vs half-open).
- **Validation:** `test (unit)`.
- **Executed verification:** `pytest tests/test_report_addendum.py -k region_model`.
- **Numeric pass threshold:** `start>end` raises `ValueError`; `start<0` raises `ValueError`; empty `name` raises `ValueError`; a `name` carrying newline/markdown/ANSI is stored scrubbed and ≤ the cap; membership true at exactly `start` and exactly `end` (inclusive).
- **Acceptance criteria (informative):** importable from `s19_app.tui.services.report_addendum`, from no frozen module; name sanitization reuses the existing `_scrub_issue_message` primitive (single source, not re-invented).

### LLR-024.2 — Addendum emitter + ReportOptions field `[Inc2]`
- **Traceability:** HLR-024 (cross-ref part = HLR-025 / d-ii)
- **Statement:** `report_service` shall provide `_addendum_lines(regions, variant_results)` rendering a region table and, per region, the modifications and the validation issues whose `address ∈ [start, end]` (aggregated across variants); `generate_project_report` shall emit it gated by a new `ReportOptions.declared_regions: tuple[DeclaredRegion, ...] = ()`.
- **Target file:** `report_service.py` (`generate_project_report` emit pipeline ~`:960`; `ReportOptions` `:141`, frozen+slots — defaulted field, validate in `__post_init__` per file convention). NEW: `_addendum_lines`, `ReportOptions.declared_regions` — **contract-touch logged §6.4**.
- **Validation:** `test (unit + integration)`.
- **Executed verification:** `pytest tests/test_report_service.py -k addendum`.
- **Numeric pass threshold:** non-empty `declared_regions` → addendum with each region + exact per-region membership (0 mis-attributed; inclusive bounds); empty → no addendum section; a non-`DeclaredRegion` element in `declared_regions` → one explicit `ValueError` from `ReportOptions.__post_init__` (architect-F5, matches the F-S-05 no-silent-clamp convention).
- **Acceptance criteria (informative):** per-region issue membership reads the **same** `ValidationIssue.address` that LLR-025.1 renders — there is no second address source (this is the single-source invariant **TC-S3** guards, qa-F1); membership computed from modification addresses + `ValidationIssue.address`; changing a region changes the report (no duplicated literal).

### LLR-024.3 — `ReportViewerScreen` region input + dispatch `[Inc3]`
- **Traceability:** HLR-024
- **Statement:** `ReportViewerScreen` shall provide a declared-region input (name/start/end rows) carried on the `GenerateRequested` message; `app.py`'s report-generation worker shall thread it into `ReportOptions.declared_regions`.
- **Target file:** `s19_app/tui/screens.py` (`ReportViewerScreen` `:~542`, `GenerateRequested` message); `s19_app/tui/app.py` (`_start_generate_report_worker` builds `ReportOptions` `:~2014`). NEW widget ids (`#report_region_*`), NEW `GenerateRequested` field — contract-touch §6.4. OUTSIDE frozen.
- **Validation:** `test (pilot)` + `analysis` (C-13 geometry).
- **Executed verification:** `pytest tests/test_tui_report_addendum.py -k 'input or open'`; `App.run_test(size=(80,N))`/`(120,N)` on `ReportViewerScreen`.
- **Numeric pass threshold:** regions entered in the dialog appear in the produced report (3/3 representative); the region-input row fits 80 & 120 cols (0 clipped — **C-13 `assumed — measure`; C-13.1 fallback if the dialog row overflows**).
- **Acceptance criteria (informative):** the input is the shipped surface for AT-024c (no direct `ReportOptions` construction in the AT).

### LLR-026.1 — `project.json` persistence `[Inc4]`
- **Traceability:** HLR-026
- **Statement:** `manifest_writer.serialize_manifest` shall include an optional `declared_regions` array (each `{name,start,end}`) in the envelope; `variant_execution_service.read_project_manifest` shall parse it back (absent key → empty tuple), emitting a `ValidationIssue` for a malformed entry without aborting the read.
- **Target file:** `s19_app/tui/services/manifest_writer.py` (`serialize_manifest` `:224`, `write_project_manifest` `:370`); `s19_app/tui/services/variant_execution_service.py` (`read_project_manifest` `:293`). OUTSIDE frozen. Additive optional key — no `schema_version` bump required (confirm at Phase 3).
- **Validation:** `test (integration)`.
- **Executed verification:** `pytest tests/test_manifest_writer.py -k declared_regions`.
- **Numeric pass threshold:** declare→serialize→read roundtrip equality; absent key → 0 regions; malformed entry → `ValidationIssue` emitted, read completes.
- **Acceptance criteria (informative):** the atomic `os.replace` write path (LLR-002.2) is unchanged; existing manifests round-trip unchanged.

---

## 5. Validation strategy

### 5.1 Methods

> **Two layers** (per the Two-layer validation rule). Every batch declares BOTH:
> - **Layer A — white-box / functional (`TC-NNN`):** validates the HLR/LLR mechanism (the HOW). Methods: `test`, `inspection`, `analysis`.
> - **Layer B — black-box / behavioral acceptance (`AT-NNN`):** validates the user story's outcome through the shipped surface (the WHAT). Method: `acceptance`.

- **Test (Layer A · white-box):** automated execution (unit / integration / e2e). Default for LLR. **Every `test` LLR must name the exact executed verification and the numeric pass threshold — otherwise it is not executable.**
- **Inspection (Layer A · white-box):** static review of code or document. Useful for structural requirements. Name the file / commit / section + the observable condition.
- **Analysis (Layer A · white-box):** formal or quantitative reasoning (performance, complexity, security). **Every `analysis` LLR must name the executed calculation (with input values) and the numeric pass threshold — otherwise it is not executable.**
- **Acceptance (Layer B · black-box):** exercise the system as the user — Textual Pilot e2e (`App.run_test()`), CLI invocation, or artifact-on-disk inspection — and assert the story's outcome through the SHIPPED surface with representative + boundary + negative evidence + the actual deliverable observed. Marked `AT-NNN` (distinct from white-box `TC-NNN`). This is the `test (pilot)` form, NOT `demo`. Required for every user story; an output-producing story's `AT` must FAIL if the output is silently absent.
- **Demo (auxiliary · perceptual):** observed execution of behavior; qualitative UX check. Describe the observable procedure + the named qualitative criterion. NOT a substitute for an automated `AT`.

> Reminder from the batch-02 + batch-03 post-mortems: the absence of an executed verification + numeric pass threshold on `test`/`analysis` requirements was the recurring root cause of forced phase-1 iteration. Capture at draft time, not at the phase-2 gate.

### 5.2 Dual-traceability table

> A requirement is complete only when BOTH chains exist (per the Two-layer validation rule).

**Behavioral chain (black-box) — per user story:**

| US | Observable outcome | Shipped surface | Acceptance test (`AT-NNN`) | Observed? |
|----|--------------------|-----------------|----------------------------|-----------|
| US-020c | report addendum lists declared regions + cross-refs mods/issues inside | `generate_project_report` → report file; `ReportViewerScreen` | AT-024a + AT-024b (boundary, zero-hit) + AT-024c (input→report) + AT-026a (persist→reload) | pending Phase 3 |
| US-020d | report issue lines show address/symbol/related | `generate_project_report` → report file | AT-025a + AT-025b (negative, no address) | pending Phase 3 |

**Functional chain (white-box) — per requirement:**

| Requirement | Method | Test Case (`TC-NNN`) | Notes |
|-------------|--------|----------------------|-------|
| HLR-024 | test (pilot+unit) | TC-024.1 (addendum content) + TC-024.2 (per-region membership, inclusive bounds) | |
| LLR-024.1 (DeclaredRegion) | test (unit) | TC-024.3 (model validation: start>end, empty name, membership) | NEW |
| LLR-024.2 (_addendum_lines) | test (unit+integration) | TC-024.4 (region table + cross-ref) | contract-touch ReportOptions |
| LLR-024.3 (input + dispatch) | test (pilot) + analysis | TC-024.5 (input→report) + TC-024.6 (C-13 geometry 80/120) | C-13 |
| HLR-025 / LLR-025.1 (issue fields) | test (unit) | TC-025.1 (enriched line) | |
| HLR-026 / LLR-026.1 (persistence) | test (integration) | TC-026.1 (roundtrip) + TC-026.2 (back-compat absent key) | |
| LLR-024.2 single-source invariant (issue render ↔ addendum cross-ref) | inspection/unit | TC-S3 (both read `ValidationIssue.address`; no divergent membership) | anti-drift; owned by LLR-024.2 acceptance criteria (qa-F1) |

*(All `AT-NNN`/`TC-NNN` + test file paths provisional-until-Phase-3 per V-5.)*

### 5.3 Batch acceptance criteria
- 100% of LLRs (5) covered by ≥1 passing TC; every US (2) covered by ≥1 passing `AT` observing its outcome through the shipped surface, with boundary + negative evidence (AT-024b zero-hit, AT-025b no-address).
- 0 blocker fails in Phase-4 validation; signed-balance test ledger reconciles.
- **0 engine-frozen edits** — `validation/model.py` (`ValidationIssue`) + `color_policy.py` consumed read-only; `git diff` over the frozen set = 0.
- Each AT shown RED under a value-discriminating counterfactual (QC-2).
- Each increment ≤5 files; full non-slow suite green at every increment gate.

---

## 6. Appendices (optional)

### 6.1 Extended glossary
- **Declared region:** an operator-supplied `(name, start, end)` memory range of interest, declared for a report (DoR pick A — Expected-zone).
- **Addendum:** the project-level report section listing declared regions + their cross-referenced modifications/issues.

### 6.2 Relevant design decisions
- DoR: semantics = **A Expected-zone**; US-020d scope = **Both**; persistence = **in-scope** (all operator picks, 2026-06-29).
- `DeclaredRegion` is NEW and lives OUTSIDE the frozen set (`tui/services/report_addendum.py`), modelled on `CrcRegion`. `ValidationIssue` (frozen) is read-only.
- Increment order ships the smallest independent win first (US-020d enrichment, Inc1).

### 6.3 Open risks
- **Addendum placement** in report order (project-level section — proposed after the per-variant blocks, before the truncation appendix) — Phase-3 detail; affects no requirement.
- **C-13 geometry (LLR-024.3):** the `ReportViewerScreen` region-input row budget at 80 cols is `assumed — measure` in Phase 3; C-13.1 deficit-matched fallback if it overflows.
- **Manifest back-compat (LLR-026.1):** additive optional `declared_regions` key — confirm at Phase 3 that no `schema_version` bump is needed and old manifests round-trip unchanged.
- **Cross-variant aggregation:** declared regions are project-level; per-region membership aggregates modifications/issues across all variants — confirm the aggregation reads each variant's data once.

### 6.4 Phase-1 reconciliation log

**Reconciliation event: Phase-2 cross-review folds (2026-06-29).** Per the parent-HLR re-read rule, every LLR threshold/statement change at this gate is audited (body edit landed FIRST, then this row).

| Decision ID | What changed | Parent HLR re-read? | Body edit landed? |
|-------------|--------------|---------------------|-------------------|
| SEC-F1 (MED) | LLR-024.1: `name` scrubbed + length-capped via `_scrub_issue_message` before render/persist | HLR-024 — added the "injection" boundary to its QC-3 catalog (name with newline/markdown/ANSI → inert) | §4 LLR-024.1 Statement + threshold; §3 HLR-024 boundary catalog |
| architect-M1 (major) | LLR-024.1: inclusive `[start,end]` made explicit, distinct from `CrcRegion` half-open | HLR-024 — boundary catalog "at exactly start and end, inclusive" already authoritative; no statement change | §4 LLR-024.1 Statement + threshold |
| sec-F3 (low) | LLR-024.1: `start >= 0` validation added | HLR-024 — boundary "invalid" widened to `start>end OR start<0`; no change required | §4 LLR-024.1 threshold; §3 HLR-024 boundary |
| architect-F5 (minor) | LLR-024.2: non-`DeclaredRegion` element → `ValueError` from `ReportOptions.__post_init__` | HLR-024 — no statement change (validation detail at the LLR boundary) | §4 LLR-024.2 threshold |
| qa-F1 (minor) | LLR-024.2: anti-drift acceptance criterion (membership reads the same `ValidationIssue.address` as LLR-025.1) — gives TC-S3 an owning LLR | HLR-024 — no change | §4 LLR-024.2 acceptance criteria |
| qa-F4 (minor) | AT-026a: observe the on-disk `project.json` (artifact-on-disk), not a pure service roundtrip | HLR-026 — §-acceptance already named both observations; AT line tightened to match | §3 HLR-026 acceptance test line |
| m1 (minor) | `CrcRegion` path corrected to `tui/operations/crc_config.py:61` | n/a (citation fix) | §4 LLR-024.1 target |

**Contract-touch identity re-run (per the contract-touch rule).** Three contracts gain an optional field; producer/consumer enumeration re-checked at draft:
| Contract | New field | Producers | Consumers | Identity check |
|----------|-----------|-----------|-----------|----------------|
| `ReportOptions` | `declared_regions: tuple[DeclaredRegion,...] = ()` | `app.py` report worker (~:2014) | `generate_project_report` → `_addendum_lines` | OK — one producer, one consumer; `__post_init__` validates (architect-F5) |
| `GenerateRequested` msg | region payload | `ReportViewerScreen` (screens.py:737) | `on_report_viewer_screen_generate_requested` (app.py:1862) — **sole consumer, architect-verified** | OK — no orphan consumer |
| `project.json` envelope | optional `declared_regions` key | `manifest_writer.serialize_manifest` | `variant_execution_service.read_project_manifest` (absent → empty) | OK — additive; envelope guard is a superset check (architect-F3), no `schema_version` bump; **Phase-3: update serializer docstring to name the 5th key** |

### 6.5 Requirement amendments (Before / After · Deleted / New)
*(Used by `iterate-to-refine` (Phase 1 from a Phase-4 black-box failure) and by Phase-3 spec amendments. One block per amendment: **Before → After** text · **Deleted / New** tokens · parent-HLR re-read result · the re-derived HLR/LLR + their `TC`/`AT`. Never silently edit a locked requirement.)*
