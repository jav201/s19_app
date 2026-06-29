# Requirements Document — s19_app — Batch 2026-06-26-batch-18

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
| US-022 | As an operator reading a generated report, I want a classification legend (the colour key for A2L / MAC / Issues rows) in the report, so that I can interpret row colours without external docs. | backlog #11 Q1 (drafted batch-14 Phase-0) | **READY** |
| US-023 | As an operator on a colour-coded view (A2L / MAC / Issues), I want a "Legend" button that opens the classification key, so that I can see what each row colour means in-app. | backlog #11 Q2 | **READY** |

#### Refinement log (one block per story)

**US-022 — Q1: classification legend in the generated report**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):** user = report reader · outcome = the generated project report includes a legend section mapping each row colour → meaning for A2L, MAC, Issues (per REQUIREMENTS.md §3) · why = self-contained report interpretability · out of scope = changing row-colour LOGIC; the diff-report's separate run-kind colours (changed/only_a/only_b).
- **Feasibility (E, S):** path = a NEW shared module `s19_app/tui/legend.py` holding `LEGEND_TABLE` (mirrors REQUIREMENTS.md §3 + `color_policy.SEVERITY_CLASS_MAP`), consumed by a `_legend_lines` helper in `report_service.py` (+ `ReportOptions.include_legend=True`). **CONSTRAINT: the shared table must NOT live in `color_policy.py` (engine-frozen) — hence `legend.py`.** fits one batch? = yes (S-M).
- **Evaluability (T):** "When the operator generates a project report, the report text contains a legend section with the documented colour→meaning rows (e.g. 'Red — schema/structural failure', 'Green — memory-checked + present')" — observed by reading the generated report (extends `tests/test_report_service.py`).
- **Open questions:** include the diff-report run-kind colours too? (lean: out of scope). Confirm module name `legend.py`.
- **Classification:** `READY`.

**US-023 — Q2: in-app per-view Legend button + modal**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):** user = operator on a colour-coded view · outcome = a "Legend" button on the A2L explorer, MAC view, and Issues screen opens a `LegendScreen` modal rendering the classification key · why = in-context interpretation · out of scope = changing the views' data/colouring; different per-view legends.
- **Feasibility (E, S):** path = a `LegendScreen(ModalScreen)` reading the SAME `legend.py::LEGEND_TABLE` (single source with Q1) + a `#*_legend_button` on `#screen_a2l` / `#screen_mac` / `#screen_issues` → `push_screen`. depends on US-022's module. fits one batch? = yes (M; 3 views + 1 modal).
- **Evaluability (T):** "When the operator presses the Legend button on a colour-coded view, a modal opens containing the classification rows (colour + meaning) for that view's artifact" — Pilot drives the button per view, asserts modal content. C-13: verify each view's button row has geometry budget + the modal fits 80/120-col regimes.
- **Open questions:** one shared modal (all 3 tables) vs per-view filtered — lean: one modal, all tables (single source, simplest). Modal vs inline panel — lean: modal (established pattern; avoids per-view layout/C-13 pressure).
- **Classification:** `READY` (resolve one-modal-vs-filtered + button-geometry in Phase 1).

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

### HLR-022 — Classification legend in the generated report
- **Traceability:** US-022
- **Statement:** When the operator generates a project report, the system shall include a classification-legend section mapping each row-colour classification (A2L, MAC, Issues) to its documented meaning.
- **Rationale (informative):** makes a colour-coded report self-interpretable offline; content derived from the single documented source, never re-invented.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_report_service.py -k legend` (+ `tests/test_tui_legend.py` for the shared table).
- **Numeric pass threshold:** generated report text contains the legend section + every `LEGEND_TABLE` row (≥5 colour→meaning rows: Red/Green/White/Grey + MAC Orange); 0 missing.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** the generated report contains a legend with each colour → meaning for A2L/MAC/Issues (e.g. "Red — schema/structural failure", "Green — memory-checked + present", "Orange — MAC warning: overlap/alias/symbol-only").
  - **Shipped surface:** `generate_project_report` (report_service.py:913) → `reports/<ts>-report.md`.
  - **Deliverable + observation:** report file — non-empty, text contains the legend header + every row from `legend.py::LEGEND_TABLE`.
  - **Acceptance test(s):** `AT-022a` (legend present, content asserted — C-10) + `AT-022b` (negative: `include_legend=False` → absent, proves present/absent discrimination).
  - **Boundary catalog (QC-3):** ☑ empty (report with zero findings still carries the STATIC legend) · ☑ boundary (`include_legend` on/off) · ☐ invalid N/A (legend is static, no user input feeds it) · ☐ error N/A (unconditional static text).

### HLR-023 — In-app Legend button + classification modal
- **Traceability:** US-023
- **Statement:** When the operator presses the Legend button on a colour-coded view (A2L, MAC, or Issues), the system shall open a modal displaying the classification key (colour + meaning) for all three artifacts.
- **Rationale (informative):** in-context interpretation; one shared modal (all three tables) keeps a single source and avoids three per-view layout variants.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_tui_legend.py` (Pilot per view + modal content + C-13 geometry).
- **Numeric pass threshold:** on each of the 3 views the button opens `LegendScreen` with the documented rows; 3/3 views; modal renders fully at 80 and 120 cols; 0 clipped.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** pressing Legend on any of the three views opens a modal listing the A2L/MAC/Issues classification rows.
  - **Shipped surface:** `#a2l_legend_button` / `#mac_legend_button` / `#issues_legend_button` → `on_button_pressed` → `push_screen(LegendScreen())`.
  - **Deliverable + observation:** rendered `LegendScreen` modal containing the rows from `legend.py::LEGEND_TABLE`.
  - **Acceptance test(s):** `AT-023a/b/c` (per-view open + content, C-10), `AT-023d` (dismiss), `AT-023e` (C-13: button reachable + modal fits at 80 cols), `AT-023f` (empty: no file loaded → static legend still shows).
  - **Boundary catalog (QC-3):** ☑ empty (no data loaded → static legend still shows) · ☑ boundary (80-col narrow regime — C-13 measurement) · ☐ invalid N/A (button takes no input) · ☑ error (dismiss/close removes the modal; a per-view missing button fails that view's AT).

> **C-13 (geometry-budget) — the one real risk:** the A2L view's button row `#a2l_tags_filters` (app.py:2390-2401) already holds **9 widgets**; a 10th (Legend) button at 80 cols is plausibly tight. LLR-023.3 requires MEASURING this per-regime in Phase 3 (`assumed — measure`), NOT assuming. Pre-agreed fallback if 80-col fails: move A2L Legend to a key-binding / overflow, or shorten an existing A2L button label. (MAC=2, Issues=3 widgets → ample budget.)

---

## 4. Low-level requirements (LLR)

> Each LLR decomposes an HLR into a verifiable property at the implementation level.
> Same EARS regime. ID format: `LLR-<HLR>.<M>`.

### LLR-022.1 — Shared legend data module (single source) `[NEW — Phase 3]`
- **Traceability:** HLR-022, HLR-023 (shared substrate)
- **Statement:** The new module `s19_app/tui/legend.py` shall expose `LEGEND_TABLE` — artifact (A2L/MAC/Issues) → `{classification: (colour-name, meaning)}` rows — mirroring `REQUIREMENTS.md` §3 + `color_policy.SEVERITY_CLASS_MAP`, and shall NOT be defined in `color_policy.py` (engine-frozen).
- **Target file:** `s19_app/tui/legend.py` (NEW; OUTSIDE frozen set).
- **Validation:** `test (unit)` + `inspection` (frozen-diff).
- **Executed verification:** `pytest tests/test_tui_legend.py -k table` + `git diff --stat origin/main -- s19_app/tui/color_policy.py` (= 0 lines). **Frozen guard (MAJOR-1 fix):** `color_policy.py` is frozen by `tests/test_tui_directionb.py::_ENGINE_PATHS` (≈line 3745), re-asserted by `test_tui_theme.py::test_tc_013a` + `test_color_policy_round_trip.py` — NOT by `test_engine_unchanged.py` (which omits it). Keep the directionb guard green.
- **Numeric pass threshold:** table has all 3 artifacts; A2L={Red,Green,White,Grey}, MAC={Red,Orange,Green,White,Grey}, Issues={Errors,Warnings,Optional}; `color_policy.py` diff = 0; `test_tui_directionb.py` frozen guard GREEN.
- **Acceptance criteria (informative):** importable from `s19_app.tui.legend`, from no frozen module; every severity in `SEVERITY_CLASS_MAP` represented (anti-drift).

### LLR-022.2 — Report legend section emitter
- **Traceability:** HLR-022
- **Statement:** `report_service.py` shall provide `_legend_lines(...)` rendering `LEGEND_TABLE` as a Markdown legend, and `generate_project_report` shall emit it gated by a new `ReportOptions.include_legend: bool = True`.
- **Target file:** `s19_app/tui/services/report_service.py` (`generate_project_report` :913, `ReportOptions` :141; OUTSIDE frozen). NEW: `_legend_lines`, `ReportOptions.include_legend` (extend `__post_init__` if needed — contract-touch, §6.4).
- **Validation:** `test (unit + integration)`.
- **Executed verification:** `pytest tests/test_report_service.py -k legend`.
- **Numeric pass threshold:** `include_legend=True` → report text contains the legend + every `LEGEND_TABLE` row; `False` → absent; reads the table (not a literal copy — single-source coupling).
- **Acceptance criteria (informative):** changing `LEGEND_TABLE` changes the report (no duplicated literal).

### LLR-023.1 — `LegendScreen` modal `[NEW — Phase 3, screens.py]`
- **Traceability:** HLR-023
- **Statement:** A new `LegendScreen(ModalScreen[None])` in `screens.py` shall render every `LEGEND_TABLE` row (artifact, colour, meaning) read-only with a Close button, following the `ModalScreen` pattern (`ReportViewerScreen` screens.py:472 analog; `modal-dialog`/`modal-buttons` classes).
- **Target file:** `s19_app/tui/screens.py` (NEW class; OUTSIDE frozen).
- **Validation:** `test (pilot)`.
- **Executed verification:** `pytest tests/test_tui_legend.py -k modal_content`.
- **Numeric pass threshold:** modal mounts with all 3 artifact tables' rows; Close dismisses; reads `LEGEND_TABLE` (no duplicated literal in screens.py).
- **Acceptance criteria (informative):** identical content regardless of which view opened it (shared, not filtered).

### LLR-023.2 — Legend button on the three views + dispatch
- **Traceability:** HLR-023
- **Statement:** `app.py` shall add a `Legend` `Button` to each of `#a2l_tags_filters` / `#mac_page_controls` / `#validation_issues_filters`, and `on_button_pressed` shall route each id to `push_screen(LegendScreen())`.
- **Target file:** `s19_app/tui/app.py` (compose at :2400 / :2474 / :1169; dispatch `on_button_pressed` :7433 [corrected from :7481]; OUTSIDE frozen). NEW ids `#a2l_legend_button` / `#mac_legend_button` / `#issues_legend_button`.
- **Validation:** `test (pilot)`.
- **Executed verification:** `pytest tests/test_tui_legend.py -k 'button or open'`.
- **Numeric pass threshold:** Pilot presses each view's button → `LegendScreen` on the stack (3/3); no existing button behaviour changes.

### LLR-023.3 — Geometry budget (C-13) `[draft-time measurement → Phase 3]`
- **Traceability:** HLR-023
- **Statement:** Phase 3 shall VERIFY BY MEASUREMENT that adding one `Legend` button fits each view's button row at 80-col and 120-col regimes AND the `LegendScreen` modal fits both, re-measuring rather than assuming.
- **Target file:** measurement over `app.py` views (no new prod file); the A2L row (`#a2l_tags_filters`, 9 widgets at app.py:2390-2401) is the tightest — `assumed — measure at 80 cols`.
- **Validation:** `analysis` (geometry) + `inspection` (snapshot).
- **Executed verification:** `App.run_test(size=(80, N))` + `(120, N)` rendering each view + opening the modal; compare regenerated SVG snapshots in canonical CI.
- **Numeric pass threshold:** at 80 & 120 cols: 0 Legend button clipped/overflowed (operational: the button's rendered region is within its container's content width AND its label text is fully present); modal fully within the terminal (no horizontal clip). **Fallback DECIDED (pre-committed, not bikeshedded at the gate):** if the A2L row overflows at 80 cols → PRIMARY = shorten the A2L Legend control to a compact glyph/short label (e.g. "Key") within the existing row; LAST RESORT = a key-binding + overflow. (MAC/Issues rows have budget — full "Legend" label.)

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
| US-022 | report contains legend (colour→meaning, A2L/MAC/Issues) | `generate_project_report` → `reports/<ts>-report.md` | AT-022a + AT-022b (negative) | pending Phase 3 |
| US-023 | Legend button on each view opens modal with the classification key | `#*_legend_button` → `LegendScreen` | AT-023a/b/c + .d (dismiss) + .e (C-13 80-col) + .f (empty) | pending |

**Functional chain (white-box) — per requirement:**

| Requirement | Method | Test Case (`TC-NNN`) | Notes |
|-------------|--------|----------------------|-------|
| LLR-022.1 (shared `legend.py`) | test (unit) + inspection | TC-S1 (covers SEVERITY_CLASS_MAP) + TC-frozen-diff | single source; color_policy.py diff=0 |
| LLR-022.2 (report emitter) | test (unit+integration) | TC-022.1 (_legend_lines) + TC-022.2 (include_legend gate) | |
| LLR-023.1 (LegendScreen) | test (pilot) | TC-023.1 | reads LEGEND_TABLE, no literal copy |
| LLR-023.2 (buttons + dispatch) | test (pilot) | TC-023.2 | 3/3 views open the modal |
| LLR-023.3 (C-13 geometry) | analysis + inspection | TC-023.3 | 80 & 120 col; A2L row is the tight one |
| Single-source anti-drift | inspection/unit | TC-S2 (report rows == modal rows) | prevents Q1/Q2 divergence |

*(All `AT-NNN`/`TC-NNN` + test file paths provisional-until-Phase-3 per V-5.)*

### 5.3 Batch acceptance criteria
- *(e.g.: 100% of LLRs covered by at least one TC with pass result.)*
- *(e.g.: 0 blocker fails in validation.)*
- *(e.g.: test coverage >= X% where applicable.)*
- *(e.g.: no requirement without an assigned validation method.)*
- *(e.g.: every user story has ≥1 passing `AT-NNN` black-box acceptance test observing its outcome through the shipped surface — with boundary + negative evidence.)*

---

## 6. Appendices (optional)

### 6.1 Extended glossary
### 6.2 Relevant design decisions
### 6.3 Open risks
### 6.4 Phase-1 reconciliation log
*(Per the parent-HLR re-read rule. One audit table per reconciliation event: `Decision ID | What changed | Parent HLR re-read? | Body edit landed?`.)*

### 6.5 Requirement amendments (Before / After · Deleted / New)
*(Used by `iterate-to-refine` (Phase 1 from a Phase-4 black-box failure) and by Phase-3 spec amendments. One block per amendment: **Before → After** text · **Deleted / New** tokens · parent-HLR re-read result · the re-derived HLR/LLR + their `TC`/`AT`. Never silently edit a locked requirement.)*

#### A1 (Phase-3 Inc2, 2026-06-28) — A2L Legend affordance: button → key binding (C-13 measurement-driven)

**Trigger:** C-13 draft-time MEASUREMENT (LLR-023.3) at Phase-3 implementation. `App.run_test(size=(80,30))` and `(120,30)` over `#screen_a2l` with `prg.s19` loaded showed the A2L Legend button rendered at x=147 (80 cols) / x=165 (120 cols) — **off-screen at BOTH regimes**, because `#a2l_tags_filters` (`layout: horizontal`, two `1fr` inputs + 7 buttons) already overflows its half-width left pane (region width ≈38 at 80, ≈50 at 120) before any addition. The pre-committed PRIMARY fallback (shorten the label to "Key", ~3 cols) cannot recover a ~67–85 col overflow, so the LAST-RESORT (key binding) is taken. MAC (`#mac_page_controls`, btn right=23/41) and Issues (`#validation_issues_filters`, btn right=69/87) measured fully on-screen at both regimes → keep their visible buttons. Operator ratified the key-binding resolution (AskUserQuestion, 2026-06-28).

**LLR-023.2 — Before → After:**
- Before: "`app.py` shall add a `Legend` `Button` to each of `#a2l_tags_filters` / `#mac_page_controls` / `#validation_issues_filters`, and `on_button_pressed` shall route each id to `push_screen(LegendScreen())`."
- After: "`app.py` shall add a `Legend` `Button` to `#mac_page_controls` and `#validation_issues_filters`; for the A2L view (whose filter row has no geometry budget — C-13/A1) it shall instead bind key `k` (`Binding('k','show_legend','Legend',show=True)`). A new `action_show_legend()` shall `push_screen(LegendScreen())`; `on_button_pressed` routes the two button ids to it, and the `k` binding invokes it directly."
- **Deleted token:** `#a2l_legend_button`. **New tokens:** `action_show_legend`, the `k` binding.

**LLR-023.3 — Before → After (fallback realised):** the pre-decided fallback ladder fires at its LAST RESORT. After: "A2L exposes the legend via the `k` key (no button in the overflowing filter row); MAC/Issues retain the full 'Legend' button (measured on-screen at 80 & 120)."

**Parent-HLR re-read (HLR-023):** statement unchanged — "When the operator presses the Legend button on a colour-coded view … the system shall open a modal …". A key binding is a press affordance on the A2L view; the user-observable outcome (open the modal from each of the three views) is preserved. **No HLR body change required.**

**AT/TC re-derivation:** AT-023a now observes A2L via `pilot.press("k")` (black-box, the shipped affordance) instead of a button press; AT-023e additionally asserts A2L exposes **zero** `#a2l_legend_button` at 80 cols (the C-13 resolution is itself acceptance-checked); TC-023.2 asserts the MAC/Issues buttons present + A2L button absent. AT-023b/c/d/f and TC-023.1/TC-S2 unchanged in intent.
