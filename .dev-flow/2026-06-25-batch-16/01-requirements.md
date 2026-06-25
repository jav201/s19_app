# Requirements Document — s19_app — Batch 2026-06-25-batch-16

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
*(Technological, regulatory, business.)*

### 2.5 Assumptions and dependencies
*(What we take for granted. If an assumption fails, the batch is invalidated.)*

### 2.6 Source user stories

> Connextra format: **"As a `<role>`, I want `<goal>`, so that `<benefit>`"**. Each US gets a unique ID `US-NNN` and must be traceable to one or more HLRs.
> **Phase 0 — Definition of Ready (INVEST):** every story is refined and classified before it can be derived into HLR (Phase 1). Only `READY` stories proceed.

| ID | User Story | Source | DoR status |
|----|------------|--------|------------|
| US-017 | As an engineer saving a multi-variant project, I want to assign per-variant change/check files at save time, so that the saved manifest carries those assignments and variant-execution applies the right files to each variant (instead of the save persisting only `active_variant`). | GAP #2 / batch-11 SCOPE-1 follow-up | READY |

#### Refinement log (one block per story)

**US-017 — Per-variant file-assignment at project save (close batch-11 SCOPE-1)**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ~ (UI surface is the sizing variable) · T ✓
- **Functionality (V, N):** user = engineer saving a multi-variant project · outcome = assign per-variant change/check files (and optionally project-wide batch files) so they persist in `project.json` and variant-execution applies them · why = today the save writes only `active_variant` (`app.py:3687` passes no `batch`/`assignments`) and there is no assignment UI, so per-variant files can't be saved through the shipped surface · out of scope = changing the manifest schema, the execution semantics (consumer `plan_variant_executions` is unchanged), or assigning the PRIMARY image (that's the existing variant copy).
- **Feasibility (E, S):** path = extend the save surface to collect per-variant assignments → thread into `write_project_manifest(..., batch=, assignments=)` (`tui/services/manifest_writer.py:370`, already supports the kwargs + `_reject_unsafe_entry` security gate) + `verify_written_manifest` → reuse `SelectVariantScreen` (`screens.py:233`) list pattern. dependencies = none new; all surfaces outside the frozen set. fits one batch? = yes (likely 2 increments: payload+save-threading, then the assignment UI). **consumer-input-contract:** persisted shape must round-trip to what `plan_variant_executions` reads — `manifest.assignments: dict[variant_id, list[Path]]`, `batch: list[Path]` (`tui/services/variant_execution_service.py:159/586-605`).
- **Evaluability (T) — behavioral, black-box:** "When the operator assigns ≥1 per-variant file and saves, the user observes `project.json` on disk carrying non-empty `assignments[variant_id]` that re-reads (`verify_written_manifest`, 0 drift) AND is picked up by `plan_variant_executions`." This is the AT that closes SCOPE-1 — it must drive the **shipped save handler**, not the writer's direct kwargs.
- **Resolved scoping decisions (operator, 2026-06-25):**
  1. **Surface** = extend `SaveProjectScreen` with per-variant assignment rows (assign at save time) — smallest path closing SCOPE-1; the save modal gains a per-variant section.
  2. **Scope** = persist BOTH `assignments` (per-variant) AND project-wide `batch`.
  3. **File source** = restrict assignable files to those already in the project workarea (project-relative — satisfies the `_reject_unsafe_entry` security gate cleanly; pick-from-list UX, no external-copy handling).
- **Classification:** `READY` — story, implementation path, black-box acceptance, and the 3 scoping decisions are all settled; substrate verified outside the frozen set.

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

### HLR-017 — Multi-variant project save persists per-variant assignments + project-wide batch
- **Traceability:** US-017
- **Statement:** When the operator saves a multi-variant project through the save dialog, the system shall persist into `project.json` a project-wide `batch` list and a per-variant `assignments` map (keyed by `variant_id`) alongside `active_variant`; it shall restrict every `batch`/`assignments` entry to a project-relative path inside the project work-area, refusing — without writing `project.json` — any absolute or escaping entry; it shall verify-on-write that the re-read manifest reproduces `active_variant`/`batch`/`assignments` with zero drift; and the persisted entries shall be consumable by `plan_variant_executions`. Where the operator makes no selection, the system shall write empty `batch`/`assignments` (preserving today's active-variant-only save).
- **Rationale (informative):** Closes batch-11 SCOPE-1 — the writer/verifier/consumer already support `batch`/`assignments` (`tui/services/manifest_writer.py:370`/`:580`, `tui/services/variant_execution_service.py:526`), but the save handler (`app.py:3687`/`:3701`) passes neither and there is no assignment UI, so per-variant files cannot be saved through the shipped surface; the existing tests exercise the kwargs only directly (`test_manifest_verify.py:76`), which is the SCOPE-1 hole.
- **Validation:** test (pilot) + test
- **Executed verification:** `pytest tests/test_tui_manifest_save.py tests/test_variant_execution.py -k "us017 or assignment or batch"` — pilot-drives `_handle_save_dialog`, reads `project.json` off disk, asserts round-trip + consumer pickup.
- **Numeric pass threshold:** on-disk `assignments[vid]`/`batch` deep-equal the assigned files (resolved); 0 verify drift; consumer plan non-empty for the assigned variant; every AT-017.* RED on the pre-feature tree.
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** a saved `project.json` carrying the operator's per-variant `assignments` + project-wide `batch`, applied by variant-execution.
  - **Shipped surface:** the save dialog → `_handle_save_dialog` → `_write_and_verify_manifest` (Textual `run_test()` pilot).
  - **Deliverable + observation:** `project.json` on disk (exists; `assignments[vid]`/`batch` non-empty + exact; re-reads at 0 drift via `read_project_manifest`/`verify_written_manifest`) + the execution plan from `plan_variant_executions`.
  - **Acceptance test(s) — each names its pre-fix RED mode (C2/F-Q-01):**
    - **AT-017.1** persist + round-trip (on-disk `assignments[vid]`/`batch` exact, re-read 0-drift). RED pre-fix: handler passes no kwargs → on-disk empty.
    - **AT-017.2** consumer pickup — `plan_variant_executions` plan tuple **exactly equals** `batch + assignments[vid]` (C3/F-Q-03 — exact, not "non-empty"). RED pre-fix: empty manifest → plan tuple `()`.
    - **AT-017.3** zero-selection no-regression (empty `batch`/`assignments`, `active_variant` preserved). This is a NO-REGRESSION guard, not a counterfactual (already empty pre-fix).
    - **AT-017.4** escape refused — asserts a POSITIVE refusal observable (a surfaced refusal notice/status from the handler) AND `project.json` is NOT written / unchanged (F-S-02), NOT merely "no escaping entry". RED pre-fix: the handler ignores assignments, so the refusal path never fires → the refusal notice cannot appear.
    - **AT-017.5** stem-collision (`fw.s19`+`fw.hex`) — the assignment round-trips and is picked up under the FULL-FILENAME id (D-KEY). RED pre-fix: empty manifest.

---

## 4. Low-level requirements (LLR)

> Each LLR decomposes an HLR into a verifiable property at the implementation level.
> Same EARS regime. ID format: `LLR-<HLR>.<M>`.

> **Symbol key:** `file:line` = grep-verified on `b734c19`; **NEW** = created in Phase 3. Anchor drift note: variant model is `tui/models.py:61/86` (NOT `tui/services/models.py`). Provisional TC/AT ids reconciled Phase 4 (V-5).

### LLR-017.1 — `SaveProjectPayload` carries the composition
- **Traceability:** HLR-017
- **Statement:** `SaveProjectPayload` shall carry NEW `batch` (project-relative path strings) and `assignments` (`variant_id` → project-relative path strings) fields, defaulting empty so the zero-selection save **re-reads identically to** today's active-variant-only save (F-Q-05 — the reader tolerates absent keys; not a byte-identity claim).
- **Symbols:** `SaveProjectPayload` `screens.py:77-82` (frozen dataclass → use `field(default_factory=...)` for the mutable defaults); construction site `screens.py:188`. **NEW fields.**
- **Validation:** test (unit)
- **Executed verification:** `pytest tests/test_tui_manifest_save.py -k tc301`
- **Numeric pass threshold:** payload deep-equals constructed values (`payload.assignments == {...}`, `payload.batch == [...]`); omitted ⇒ empty.
- **Acceptance criteria:** assignment keys are `variant_id` (filename stem), not raw filenames (see LLR-017.4 contract).

### LLR-017.2 — Save handler threads the composition into write + verify
- **Traceability:** HLR-017
- **Statement:** The save handler shall pass the payload's `batch`/`assignments` into BOTH `write_project_manifest(...)` AND `verify_written_manifest(...)` (identical values, or verify reports spurious drift).
- **Symbols:** `_handle_save_dialog` (def `app.py:3552`) holds the payload and at the `app.py:3644` call site invokes `_write_and_verify_manifest` (`app.py:3648`); write call `app.py:3687`, verify call `app.py:3701` (both currently pass NO batch/assignments). Add a **NEW** keyword param `*, batch, assignments` to `_write_and_verify_manifest` (**NEW — created in Phase 3**), threaded explicitly from the payload (NOT hidden `self` state); update the `:3644` call site to pass both.
- **Validation:** test (integration) + inspection
- **Executed verification:** `pytest tests/test_tui_manifest_save.py -k "tc302 or tc303"` + grep `app.py:3687/3701` for `batch=`/`assignments=`.
- **Numeric pass threshold:** both call-sites receive `batch=<payload.batch>` + `assignments=<payload.assignments>`; 2/2 threaded, 0 bare calls.
- **Acceptance criteria:** write-intent and verify-intent are the SAME object/values (no drift from mismatched intent).

### LLR-017.3 — `SaveProjectScreen` per-variant assignment UI (workarea-restricted, existing-project scope)
- **Traceability:** HLR-017
- **Statement:** `SaveProjectScreen` shall collect, for a re-saved existing multi-variant project, per-variant assignment files and a project-wide batch list, offering ONLY project-relative `.json` change/check documents enumerated from the project dir; it shall pass these as project-relative strings into the payload (no pre-resolution to absolute).
- **Symbols:** `SaveProjectScreen` `screens.py:125`; reuse the index-based list pattern `SelectVariantScreen` `screens.py:233-304`; trigger `action_save_project` `app.py:2636-2644`. **NEW UI rows.** **Scope decision D-NEWPROJ (below):** the assignment UI targets RE-SAVING an existing project (variants known); a brand-new project save writes empty `batch`/`assignments` (HLR-017 zero-selection) because the variant set does not exist until after the primary image is copied (`app.py:3617-3619`).
- **Validation:** test (pilot)
- **Executed verification:** `pytest tests/test_tui_manifest_save.py -k "tc304 or tc305 or tc306"` — the pilot MUST construct a multi-variant `_variant_set` BEFORE `action_save_project` (F-Q-06 / D-NEWPROJ timing), else the screen has no variant rows to render.
- **Numeric pass threshold:** collected payload equals typed inputs; an escaping/absolute selection persists 0 escaping entries + surfaces a refusal; empty fields ⇒ `batch==[]`/`assignments=={}`, no crash.
- **Acceptance criteria:** the screen offers only project-relative filenames; **each assignment key is sourced from `ProjectVariantSet.variants[*].variant_id`, never recomputed as `Path.stem`** (D-KEY collision, F-A-01/F-Q-02); the writer's `_reject_unsafe_entry` (`tui/services/manifest_writer.py:178`) remains the sole path-safety authority (UI restriction is convenience, not the security boundary).

### LLR-017.4 — Reader-as-oracle round-trip + consumer pickup (the AT spine)
- **Traceability:** HLR-017
- **Statement:** A save through the shipped handler shall produce a `project.json` whose `read_project_manifest` re-read reproduces `batch`/`assignments` (resolved) with `issues == []`, and `plan_variant_executions(variant_set, manifest, scope="all")` shall yield, for an assigned variant, `tuple(batch) + tuple(assignments[variant_id])`.
- **Symbols:** `read_project_manifest`/`verify_written_manifest` (`tui/services/manifest_writer.py`/`tui/services/variant_execution_service.py`); consumer `plan_variant_executions` `tui/services/variant_execution_service.py:526` (reads `:586-604`). **consumer-input-contract (LOAD-BEARING):** persisted `assignments` keys MUST be `variant_id` = filename **stem** (`models.py:68`, `workspace.py:399-400`), because the consumer does `assignments.get(variant_id)` (`:599`/`:602`); a filename key ⇒ silent drop. Persisted shape = JSON `{vid: [relpath]}` / `[relpath]`; reader resolves to absolute `Path` inside the project.
- **Validation:** test (pilot)
- **Executed verification:** `pytest tests/test_tui_manifest_save.py -k "at017" ` + `pytest tests/test_variant_execution.py -k pickup`
- **Numeric pass threshold:** on-disk round-trip 0 drift; plan files tuple exact-equals `batch + assignments[vid]` (resolved, LLR-006.2 order).
- **Acceptance criteria:** the AT drives the SHIPPED save handler (pilot), NOT `write_project_manifest` direct kwargs (that is the existing insufficient `test_manifest_verify.py:76` coverage).

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

> TC-301..312 / AT-017.1..4 (no collision with batch-14 TC-212..226). Provisional-until-Phase-3 (V-5).

| US | Observable outcome | Shipped surface | Acceptance test (`AT-NNN`) | Observed? |
|----|--------------------|-----------------|----------------------------|-----------|
| US-017 | `project.json` carries assigned `assignments[vid]` + `batch`, re-reads 0-drift | save dialog → `_handle_save_dialog` (pilot) | **AT-017.1** | on-disk |
| US-017 | plan tuple **exactly equals** `batch + assignments[vid]` for the assigned variant | `plan_variant_executions` over the disk-read manifest | **AT-017.2** | exact tuple |
| US-017 | zero-selection save re-reads identically to active-variant-only (no regression) | save handler, empty payload | **AT-017.3** | on-disk empty |
| US-017 | escaping assignment → POSITIVE refusal surfaced + `project.json` not written | save handler + `_reject_unsafe_entry` | **AT-017.4** | refusal + no-file |
| US-017 | stem-collision (`fw.s19`+`fw.hex`) assignment round-trips + picked up under full-filename id | save handler → consumer | **AT-017.5** | on-disk + plan |

**Functional chain (white-box) — per requirement:**

| Requirement | Method | Test Case (`TC-NNN`) | Notes |
|-------------|--------|----------------------|-------|
| HLR-017 | test (pilot) | AT-017.1, AT-017.2 (+TC-301, TC-309) | rollup |
| LLR-017.1 | test (unit) | TC-301 | payload carries assignments/batch |
| LLR-017.2 | test (integration) + inspection | TC-302, TC-303 | both write+verify call-sites threaded |
| LLR-017.3 | test (pilot) | TC-304, TC-305 (escape), TC-306 (empty) | screen collect, workarea-restricted |
| LLR-017.4 | test (pilot) | AT-017.1..5 (+TC-307/308/309/310-collision) | round-trip + consumer pickup + stem-collision |

### 5.3 Batch acceptance criteria
1. 100% of LLR-017.* covered by ≥1 passing TC; every test row has Executed-verification + numeric threshold.
2. **AT-017.1/.2/.4/.5 PASS post-fix AND are RED on the pre-feature tree `b734c19`** (per-AT failure mode named in §3; AT-017.4 asserts the POSITIVE refusal observable + no-file, NOT "absence of a bad entry"; AT-017.3 is a no-regression guard, not a counterfactual). An AT green pre-fix for the wrong reason is vacuous and blocks the gate.
3. Through-the-shipped-handler round-trip: on-disk `assignments[vid]`/`batch` deep-equal the assigned files (resolved), 0 verify drift.
4. Consumer pickup: `plan_variant_executions` plan tuple **exactly equals** `batch + assignments[vid]` (resolved, LLR-006.2 order) for the assigned variant (exact-tuple, not "non-empty").
5. Zero-selection no-regression: empty payload ⇒ on-disk `batch==[]`/`assignments=={}`, save succeeds; existing `test_tui_manifest_save.py` + `test_manifest_verify.py` stay green.
6. Security: an absolute/escaping assignment is refused through the handler (no `project.json` escaping entry), surfaced not crashed.
7. 0 engine-frozen edits; dual traceability complete (both chains) for US-017.
8. Stem-collision (AT-017.5): an assignment to a colliding variant (`fw.s19`+`fw.hex`) round-trips AND is picked up under the **full-filename** id (D-KEY); the UI sources keys from `variant_id`, never `Path.stem`.

---

## 6. Appendices (optional)

### 6.1 Extended glossary
| Term | Definition |
|---|---|
| `batch` | Project-wide change/check files applied to every in-scope variant (`manifest.batch: list[Path]`). |
| `assignments` | Per-variant change/check files, keyed by `variant_id` (`dict[str, list[Path]]`). |
| `variant_id` | A variant's id = filename **stem** (e.g. `fw_a`), OR the full filename on stem-collision (`tui/workspace.py:399-403`); the consumer's assignment key. |

### 6.2 Relevant design decisions
- **D-SCOPING (operator):** extend `SaveProjectScreen` (at-save-time) · persist BOTH `assignments` + `batch` · assignable files restricted to project-workarea (project-relative).
- **D-NEWPROJ (architect rec — confirm at gate):** the assignment UI (LLR-017.3) targets **re-saving an existing** multi-variant project (variants known). A brand-new project save opens the dialog before the variant set exists (`app.py:3617-3619`), so it writes empty `batch`/`assignments` (the HLR-017 zero-selection path). This keeps Inc 1 (payload + handler threading + ATs, populated programmatically) independent of UI timing.
- **D-KEY (load-bearing contract — corrected F-A-01/F-Q-02):** `assignments` keys are the variant's actual `VariantDescriptor.variant_id`, which is the filename **stem** EXCEPT on stem-collision (`fw.s19`+`fw.hex`), where each colliding id is the **full filename** (`tui/workspace.py:399-403`, the E6 duplicate-id rule). The UI (LLR-017.3) MUST read each key from `ProjectVariantSet.variants[*].variant_id`, NEVER recompute `Path.stem`. The consumer does `assignments.get(variant_id)` (`tui/services/variant_execution_service.py:599/602`); a wrong key silently drops the assignment. Exercised by **AT-017.5** (stem-collision round-trip).
- **D-SEC:** the payload stores project-relative strings (no pre-resolution to absolute); the writer's `_reject_unsafe_entry` (`tui/services/manifest_writer.py:178`) is the sole path-safety authority. New output surface → Phase-2 security-reviewer mandatory.

### 6.3 Open risks
- **R1** (med) — write-intent vs verify-intent must be identical or `verify_written_manifest` reports spurious drift (LLR-017.2).
- **R2** (med→mitigated by D-KEY) — wrong assignment-map key (filename vs stem) → silent consumer drop; AT-017.2 (consumer pickup) catches it.
- **R3** (low) — D-NEWPROJ UI timing; mitigated by scoping UI to existing-project re-save + Inc-1/Inc-2 split.

### 6.4 Change-first supersession census
Planned files ALL outside the engine-frozen set (`core.py`/`hexfile.py`/`range_index.py`/`validation/`/`tui/a2l.py`/`tui/mac.py`/`tui/color_policy.py`): `tui/screens.py` (payload + UI), `tui/app.py` (handler threading) + tests `test_tui_manifest_save.py`, `test_variant_execution.py`. `tui/services/manifest_writer.py` + `tui/services/variant_execution_service.py` are READ-ONLY substrate (already carry the contract) — flag if Phase 3 finds otherwise. Best-effort + gate-confirmed.

### 6.5 Increment decomposition (≤5 files each)
- **Inc 1 — Persist + thread + round-trip AT (the SCOPE-1 closure, load-bearing):** `tui/screens.py` (SaveProjectPayload +fields), `tui/app.py` (thread into write+verify), `tests/test_tui_manifest_save.py` (AT-017.1/.3/.4 + TC-301/302/303), `tests/test_variant_execution.py` (AT-017.2 consumer pickup). ≤5. Payload populated programmatically in the pilot → closes SCOPE-1 without the UI.
- **Inc 2 — The assignment UI:** `tui/screens.py` (SaveProjectScreen per-variant rows, workarea-restricted), `tui/app.py` (`action_save_project` passes variant ids + candidate files), `tui/styles.tcss` (rows, if needed), `tests/test_tui_manifest_save.py` (TC-304/305/306 screen-collect). ≤5. Depends on Inc 1's payload fields.

### 6.6 Phase-1 reconciliation log
Baseline **922 collected** (re-measured on `b734c19`). Anchor drift recorded: variant model `tui/models.py:61/86`.

**Iteration 2 (Phase-2 fold — 0 blocker / 4 major / 9 minor, all reviewer-prescribed; no HLR/LLR statement re-derivation):**

| Decision | What changed | Parent HLR-017 re-read? | Body edit landed? |
|---|---|---|---|
| C1 (F-A-01/F-Q-02) | D-KEY corrected for stem-collision (`variant_id` = stem OR full filename); UI sources key from `variant_id`; +AT-017.5 | re-read — no change (HLR-017 already says "keyed by `variant_id`"; the correction sharpens what `variant_id` IS) | §6.2 D-KEY · §6.1 glossary · LLR-017.3 AC · §3 AT-017.5 · §5.2/§5.3 |
| C2 (F-Q-01) | AT-017.4 asserts POSITIVE refusal observable + no-file; per-AT pre-fix modes | re-read — no change (acceptance sharpened) | §3 Acceptance block · §5.2 AT-017.4 row · §5.3 #2 |
| C3 (F-Q-03) | AT-017.2 exact-tuple `batch + assignments[vid]` | re-read — no change | §3 AT-017.2 · §5.2 row · §5.3 #4 |
| C4 (F-A-02) | `tui/services/` prefix on all writer/consumer citations | n/a | global (7+6 citations) |
| minors | F-A-03 (`_handle_save_dialog` def :3552) · F-A-04 (ctor :188) · F-A-06 (renumber amendments §6.7) · F-Q-04 (`_write_and_verify_manifest` NEW `*,batch,assignments`) · F-Q-05 ("re-reads identically" not byte-identical) · F-Q-06 (pilot multi-variant precondition) · F-S-02/04 (no-file-on-refusal + symlink TC folded into AT-017.4) | — | LLR-017.1/.2/.3 · §3 |

Provisional (V-5) owed at Phase 4: TC-301..312 / AT-017.1..5 → real `def test_*` nodes; confirm `tui/services/manifest_writer.py`/`tui/services/variant_execution_service.py` stay edit-free.

### 6.7 Requirement amendments (Before / After · Deleted / New)
*(Used by `iterate-to-refine` (Phase 1 from a Phase-4 black-box failure) and by Phase-3 spec amendments. One block per amendment: **Before → After** text · **Deleted / New** tokens · parent-HLR re-read result · the re-derived HLR/LLR + their `TC`/`AT`. Never silently edit a locked requirement.)*
