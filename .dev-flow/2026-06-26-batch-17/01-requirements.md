# Requirements Document — s19_app — Batch 2026-06-26-batch-17

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
| US-018 | As an operator inspecting firmware in the Workspace, I want the hex column to show all 16 bytes + their ASCII decode on one line, so that I can read a full hex row without wrapping/truncation. | backlog #9 (deferred); session 2026-06-26 | **READY** |
| US-019 | As an operator saving a CRC-injected image, I want to choose the S19 record width (16 or 32 bytes), so that the written `.s19` matches what my downstream tool expects. | backlog (session-emergent from #7 draft-time finding) | **READY** |
| US-020a | As an operator reviewing validation issues, I want a hex pane beside the issues list showing the bytes at the selected issue's address, so that I can see the offending memory in context. | backlog #10 (split a) | **READY** |
| US-020b | As an operator triaging issues, I want the issues list to surface more of each issue's detail (severity badge, related artifacts), so that I can assess an issue without opening it. | backlog #10 (split b) | **READY** |
| US-020c | (report-addendum input — declared memory locations) | backlog #10 (split c) | **OUT** — deferred to own batch + design spike (DoR decision 2026-06-26); net-new data model + semantics unresolved |
| US-020d | (issues→report integration) | backlog #10 (split d) | **OUT** — deferred (depends on US-020c) |

#### Refinement log (one block per story)

**US-018 — Workspace hex column fits a full row**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):** user = firmware inspector in the Workspace view · outcome = full 16-byte + ASCII hex row visible on one line (no wrap/truncate) at a usable terminal width · why = readability parity with MAC/A2L panes · out of scope = changing HEX_WIDTH, the render format, or other panes.
- **Feasibility (E, S):** path = add a `min-width` floor to `#ws_center` (styles.tcss:193) mirroring `#mac_hex_pane` (styles.tcss:287, `min-width: 82`), accounting for `.db-pane` padding; hex row needs 81 cols (hexview.py:401-434). dependencies/unknowns = none (proven fix in batches 05/06). fits one batch? = yes (XS).
- **Evaluability (T):** "When the Workspace is shown at ≥120 cols, the `#ws_center` hex pane's rendered region width is ≥82 (a full row fits)" — observed via Pilot `region.width`, mirroring `tests/test_tui_mac_layout.py::test_mac_hex_pane_width_at_wide_terminal`.
- **Open questions:** exact floor value (82 vs 84 w/ padding) — resolve in Phase 1 from measured `.db-pane` padding.
- **Classification:** `READY`.

**US-019 — Operator-selected CRC save width**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):** user = operator writing a CRC-injected image · outcome = the written `.s19` uses the width (16 or 32) the operator picked at the CRC write-confirm · why = downstream-tool interop (same need US-015 served for the Patch Editor) · out of scope = changing the CRC algorithm/config; the S0-header policy beyond mirroring US-015's.
- **Feasibility (E, S):** path = add a width-cycle selector to `ConfirmWriteScreen` (screens.py:671) mirroring the Patch Editor's `#patch_saveback_width_button` / `SAVEBACK_WIDTHS=(32,16)` (screens_directionb.py:614/718/732); thread `bytes_per_line` through `_on_confirm_write` (1323) → `_run_crc_write_worker` (1380) → `write_crc_image` (crc.py:790) → `emit_s19_from_mem_map` (879). width as kwarg, no data-model change. dependencies = none. fits one batch? = yes (~3-4 files, likely 2 increments).
- **Evaluability (T):** "When the operator selects 16-byte width and confirms the CRC write, the written `.s19`'s data records are 16 bytes wide" + "default (unchanged selector) stays 32" — observed by reading the written file back (extends `tests/test_crc_operation.py::test_crc_write_emits_32_byte_records`; C-10: drive the NON-default 16 value).
- **Open questions:** does the selector default to 32 (preserve current contract) — yes, per C-10 keep default + add non-default path. S0-header policy on the CRC path (US-015 synthesizes S0 for 32, None for 16) — confirm applicability in Phase 1.
- **Classification:** `READY`.

**US-020a — Hex pane on the issues view**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):** user = operator reviewing validation issues · outcome = selecting an issue row renders the bytes at that issue's address in a hex pane beside the list · why = see offending memory in context · out of scope = the addendum (US-020c) and report integration (US-020d).
- **Feasibility (E, S):** path = add a `Static` hex pane to the issues screen (app.py:1124-1178) + wire row-selection to `render_hex_view_text` at the issue's `address`, reusing the `#diff_hex_a` pattern (screens_directionb.py:1134/1387). dependencies = issues have an `address` field (ValidationIssue, validation/model.py — frozen-read only). fits one batch? = yes.
- **Evaluability (T):** "When the operator selects an issue row that has an address, the issues hex pane renders the bytes at that address" — Pilot drives row selection, asserts the pane content (the bytes), C-10 content assertion; boundary: an issue with no address → pane shows a clear no-address state, not stale bytes.
- **Open questions:** issues without an address (cross-artifact issues) — define the no-address pane state in Phase 1.
- **Classification:** `READY`.

**US-020b — Enhanced issues list**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):** user = operator triaging issues · outcome = the issues list surfaces more per-issue detail (e.g. related-artifacts, clearer severity rendering) from existing `ValidationIssue` fields · why = assess without drilling in · out of scope = new validation logic; new issue data (render existing fields only).
- **Feasibility (E, S):** path = extend the issues DataTable population (app.py:4848-4939 / cell format 476-519) to expose existing `ValidationIssue.related_artifacts` / severity via `color_policy.SEVERITY_CLASS_MAP`. dependencies = none beyond existing fields. fits one batch? = yes.
- **Evaluability (T):** "When an issue carries related artifacts, the issues list row shows them" — Pilot asserts the rendered row content for a fixture issue with related_artifacts; severity rendering observed via the row's class/markup.
- **Open questions:** which exact fields to surface (related_artifacts only, or also `details`) — narrow in Phase 1 to avoid scope creep.
- **Classification:** `READY` (scope to existing-field exposure; resist adding new columns beyond what's derivable).

**US-020c / US-020d — DEFERRED (OUT)**
- Report-addendum input (operator-declared memory locations) + issues→report integration. Net-new data model + persistence + unresolved "declared memory locations" semantics → own batch with a design spike (DoR decision 2026-06-26). Logged to `.dev-flow/BACKLOG.md`. Not derived here.

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

### HLR-018 — Workspace center pane floors at a full-row width
- **Traceability:** US-018
- **Statement:** When the Workspace renders the hex view, the system shall lay out a full hex row (marker + address + 16 bytes + ASCII gutter) on one line without wrapping — content-sizing the hex view and providing a horizontal scrollbar when the pane is narrower than a row — while keeping all three Workspace panes visible. *(Approach revised Phase-3 §6.5 A2; was a `#ws_center min-width` floor.)*
- **Rationale (informative):** the row currently wraps because `#hex_view` (a `Static`) reflows to the ~30-cell pane. The MAC/A2L `min-width: 82` mirror does NOT transfer — the 3-pane Workspace (fixed left 22 + right 40) can't fit `left + 82 + right` at a 120-col terminal, so a floor pushes the right context pane off-screen (the likely cause of prior failed attempts). Content-sizing + the existing scroll container keeps the row on one line AND all panes visible. No render/`HEX_WIDTH` change.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_tui_workspace_layout.py` (NEW file), mirroring the Pilot `.region` idiom of `tests/test_tui_mac_layout.py`.
- **Numeric pass threshold:** at `App.run_test(size=(120,30))` with a file loaded, `#hex_view.region.width ≥ 81` AND `#hex_scroll.virtual_size.width ≥ 81` (row on one line + scrollable); `#ws_right` right-edge ≤ screen width (all panes visible). RED pre-fix: `#hex_view` width ~28 (wrapped).
- **Priority:** medium
- **Acceptance (black-box) — the WHAT:**
  - **Observable outcome:** the Workspace hex column shows 16 bytes + ASCII decode on one line (scroll horizontally to reach the rest at narrow widths); the right context pane stays visible.
  - **Shipped surface:** Workspace screen `#hex_view` / `#hex_scroll` inside `#ws_center` (app.py:1086-1101), via Pilot `App.run_test(size=(120,30))`.
  - **Deliverable + observation:** rendered element — `#hex_view.region.width` (content) ≥81 AND `#hex_scroll.virtual_size.width` ≥81 (horizontally scrollable); `#ws_right` within the viewport.
  - **Acceptance test(s):** `AT-018` — RED on the pre-fix tree (hex view wraps to ~28; counterfactual captured). Asserts the row is on one line + scrollable + all panes visible (C-9: a wrapped/clipped row fails).
  - **Boundary catalog (QC-3):** ☑ boundary (80-col narrow regime → one line + scroll still holds, no crash) · ☑ guard (right context pane stays on-screen — the rejected min-width approach fails this) · ☐ empty N/A (no-file render shows the empty-state, panes hidden — covered by the load precondition) · ☐ invalid N/A (no input dimension) · ☐ error N/A (CSS-only, no I/O path).

### HLR-019 — CRC write honours the operator-selected record width
- **Traceability:** US-019
- **Statement:** When the operator confirms a CRC-injected write after selecting a record width of 16 or 32 bytes, the system shall emit the modified `.s19` with data records of the selected width; and where the operator makes no selection, the system shall default to 32-byte records.
- **Rationale (informative):** Mirrors US-015's Patch-Editor 16/32 selector (`SAVEBACK_WIDTHS=(32,16)`, screens_directionb.py:424); the CRC path calls `emit_s19_from_mem_map(working_mem, working_ranges)` with no `bytes_per_line` (crc.py:879) so it always rides the default 32 (io.py:1412). Same interop need.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_crc_operation.py -k crc_write` (extends `test_crc_write_emits_32_byte_records`) + `pytest tests/test_tui_crc_surface.py -k width` (provisional-until-Phase-3, V-5).
- **Numeric pass threshold:** selected-16 → `max(record_widths)==16` AND `32 not in record_widths`; default → `max==32`. `0` records exceed the selected width.
- **Priority:** medium
- **Acceptance (black-box) — the WHAT:**
  - **Observable outcome:** picking "16 bytes/line" at the CRC write-confirm and confirming yields a `.s19` with 16-byte records; no selection stays 32.
  - **Shipped surface:** OperationsScreen CRC flow → `ConfirmWriteScreen` (screens.py:671) → `_on_confirm_write` (1323) → `_run_crc_write_worker` (1380) → `write_crc_image` (crc.py:790), via Pilot.
  - **Deliverable + observation:** file under `.s19tool/workarea/crc/` — read back, per-record data-byte widths inspected.
  - **Acceptance test(s):** `AT-019a` (default 32, re-points the existing lock) + `AT-019b` (C-10: cycles selector to NON-default 16 through the confirm surface; C-12: reads the HANDLER-PRODUCED file, never a direct `write_crc_image(bytes_per_line=16)`). RED on `main` (path emits 32 today).
  - **Boundary catalog (QC-3):** ☑ boundary (both enum endpoints 16 & 32 — the C-10 per-branch ATs) · ☑ negative (write declined → no file, screens.py:1354-1356 preserved) · ☑ error (write-fault collect-don't-abort still holds with the width threaded — re-run test_write_outside_workarea) · ☐ invalid N/A (closed cycle over (32,16), no free-text width).

### HLR-020 — Selecting an issue renders its address bytes in an on-screen hex pane
- **Traceability:** US-020a
- **Statement:** When the operator selects a validation-issue row carrying an address, the system shall render the bytes at that address in a hex pane on the Issues screen beside the issues list; and if the selected issue carries no address, the system shall display a defined no-address state in that pane rather than stale bytes.
- **Rationale (informative):** the row-select handler already updates other screens' hex views (app.py:4795-4799) but none is visible on the Issues screen. Reuses the `#diff_hex_a` idiom (Static + `render_hex_view_text`, screens_directionb.py:1134/1387).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_tui_issues_view.py` (NEW; provisional-until-Phase-3, V-5).
- **Numeric pass threshold:** addressed selection → pane content contains the `0x%08X` focus-row + ≥1 byte group for the issue address; no-address selection → pane content == the defined placeholder AND 0 carried-over bytes.
- **Priority:** medium
- **Acceptance (black-box) — the WHAT:**
  - **Observable outcome:** selecting an addressed issue shows its bytes beside the list; an address-less issue shows a placeholder, not the previous bytes.
  - **Shipped surface:** Issues screen `#screen_issues` (app.py:1124-1178) + the new hex `Static`, driven via Pilot row-selection through `on_data_table_row_selected` (app.py:4395-4442).
  - **Deliverable + observation:** rendered element — the new issues hex Static's content.
  - **Acceptance test(s):** `AT-020a` — selects an addressed and an address-less issue; asserts pane CONTENT (bytes vs placeholder). Fails on absent pane or stale bytes.
  - **Boundary catalog (QC-3):** ☑ empty (no issues → pane inert/empty) · ☑ boundary (address-less issue → placeholder, no stale bytes) · ☑ error (address in an unloaded gap → renderer no-data state, no crash) · ☐ invalid N/A (selection constrained to existing rows).

### HLR-021 — Issues list surfaces an issue's related artifacts
- **Traceability:** US-020b
- **Statement:** Where a validation issue carries related artifacts, the system shall display them in the issues-list row.
- **Rationale (informative):** the DataTable already shows severity (styled, app.py:518) + artifact; the genuine gap is `ValidationIssue.related_artifacts` (validation/model.py:128), not currently shown. Scope deliberately narrowed to related-artifacts exposure (severity badge already shipped) to resist scope creep. No new validation logic.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_tui_issues_view.py -k related_artifacts` + a pure-function `tests/test_tui_app.py -k issues_payload` (provisional-until-Phase-3, V-5).
- **Numeric pass threshold:** issue with `related_artifacts=["a2l","mac"]` → row contains both tokens; empty list → `-` marker. `0` rows blank-where-populated.
- **Priority:** low
- **Acceptance (black-box) — the WHAT:**
  - **Observable outcome:** an issue with related artifacts shows them in its row; one without shows an empty marker.
  - **Shipped surface:** issues DataTable `#validation_issues_list` via `update_validation_issues_view` / `precompute_issue_datatable_payload` (app.py:476-519/4848), via Pilot.
  - **Deliverable + observation:** rendered element — the DataTable row cells.
  - **Acceptance test(s):** `AT-021` — fixture with one artifacts-bearing + one bare issue; asserts row CONTENT (C-10: the actual tokens). Fails if related artifacts silently dropped.
  - **Boundary catalog (QC-3):** ☑ boundary (artifacts present → shown) · ☑ empty (empty list → `-`, no crash) · ☐ invalid N/A (typed list[str]) · ☐ error N/A (pure render).

> **Contract-touch (recorded for §6.4 at reconciliation):** (a) HLR-019 — the selector-width producer ↔ `emit_s19_from_mem_map(bytes_per_line=)` consumer identity; carry mechanism = **Option C** (`ConfirmWriteScreen` cycles `_crc_saveback_width` and dismisses with a width-bearing result consumed by `_on_confirm_write` :1323) — see §6.5 amendment A1. (b) HLR-021 — the issues cell tuple widens 7→8; the formatter (app.py:507-516), the column add (app.py:2568-2576), the `use_precomputed` branch (app.py:4919-4928), the 7-tuple docstring (app.py:488) AND the `_populate_issues_datatable` docstring (app.py:4957, docstring-only) must all move together.

---

## 4. Low-level requirements (LLR)

> Each LLR decomposes an HLR into a verifiable property at the implementation level.
> Same EARS regime. ID format: `LLR-<HLR>.<M>`.

### LLR-018.1 — `#hex_view` content-sizes so the row stays on one line (§6.5 A2)
- **Traceability:** HLR-018
- **Statement:** The `#hex_view` rule in `styles.tcss` shall declare `width: auto` so the hex view sizes to its content (one full ~81-cell row) instead of wrapping to the pane, and the existing `#hex_scroll { overflow: auto }` (styles.tcss:370) shall provide a horizontal scrollbar when `#ws_center` is narrower than a row — keeping the row on one line and all three Workspace panes visible. (Supersedes the rejected `#ws_center { min-width: 82 }` floor — see §6.5 amendment A2.)
- **Target file:** `s19_app/tui/styles.tcss` (NEW `#hex_view` rule near :370; OUTSIDE frozen set).
- **Validation:** `test (integration)` — Pilot content-width + scrollable-width probe with a loaded file.
- **Executed verification:** `pytest tests/test_tui_workspace_layout.py` (AT-018 + guard + boundary).
- **Numeric pass threshold:** at 120×30 (file loaded) `#hex_view.region.width ≥ 81` AND `#hex_scroll.virtual_size.width ≥ 81` (row on one line + horizontally scrollable); `#ws_right` edge ≤ screen width (all panes visible); holds in the narrow (80-col) regime. RED pre-fix: `#hex_view` width ~28 (wrapped).
- **Acceptance criteria (informative):** pane widths (`#ws_left`/`#ws_center`/`#ws_right`) unchanged by the fix; no `min-width` floor introduced.

### LLR-019.1 — Width-cycle selector on the CRC confirm flow
- **Traceability:** HLR-019
- **Statement:** The CRC write-confirm flow shall present an operator-cyclable width selector over `(32, 16)` defaulting to 32, mirroring `#patch_saveback_width_button` (screens_directionb.py:614-616/718-731), and shall carry the chosen width to `_on_confirm_write`.
- **Target file:** `s19_app/tui/screens.py` (`ConfirmWriteScreen` :671 + its consumer `_on_confirm_write` :1323; OUTSIDE frozen set). NEW symbols (`NEW — created in Phase 3`): a width-button id + a `_crc_saveback_width` state attr ON `ConfirmWriteScreen` + a **width-bearing dismiss result** — **Option C** (the truest US-015 mirror): `ConfirmWriteScreen` cycles its own `_crc_saveback_width` and dismisses with a width-carrying result (a custom `ConfirmWriteDecision(confirmed: bool, bytes_per_line: int)` message OR a `(confirmed, bytes_per_line)` tuple — pick one in Phase 3), which `_on_confirm_write` consumes. (Option B "read foreign screen state" is INFEASIBLE — `_on_confirm_write` runs on `OperationsScreen` after the modal is dismissed and cannot reach the modal instance; see §6.5 amendment A1.) Reuse the proven `(32,16)` cycle value.
- **Validation:** `test (integration)` — Pilot cycles the selector + confirms.
- **Executed verification:** `pytest tests/test_tui_crc_surface.py -k width_selector` (provisional-until-Phase-3, V-5).
- **Numeric pass threshold:** 1 cycle flips 32→16 (label updates); 2 cycles → 32; the declined path still writes 0 files (screens.py:1354-1356 unchanged).
- **Acceptance criteria (informative):** label reads the current width; default before any cycle is 32 (preserves the current contract).

### LLR-019.2 — Thread the selected width through to the emitter
- **Traceability:** HLR-019
- **Statement:** The system shall thread the selected width as `bytes_per_line` from `_on_confirm_write` (screens.py:1323) → `_run_crc_write_worker` (screens.py:1380) → `write_crc_image` (crc.py:790) → `emit_s19_from_mem_map(..., bytes_per_line=<selected>)` (crc.py:879), keeping `s0_header=None` on the CRC path (US-015's S0 synthesis is out of scope per US-019).
- **Target files:** `s19_app/tui/screens.py` (`_on_confirm_write`, `_run_crc_write_worker`) + `s19_app/tui/operations/crc.py` (`write_crc_image` add `bytes_per_line: int = 32` kwarg; pass at the :879 emit). Both OUTSIDE frozen set. **`io.py` NOT edited** — the kwarg already exists (io.py:1412). NEW params flagged `NEW — created in Phase 3`.
- **Validation:** `test (unit + integration)`.
- **Executed verification:** `pytest tests/test_crc_operation.py -k "crc_write and (16 or 32)"` (extends :474; provisional-until-Phase-3, V-5).
- **Numeric pass threshold:** `write_crc_image(..., bytes_per_line=16)` → file max-record-width 16; default call → 32; `0` records exceed requested width on each path.
- **Acceptance criteria (informative):** original `mem_map`/`ranges` never mutated; containment/dedup/verify path (crc.py:861-882) unchanged apart from the width passthrough.

### LLR-020.1 — Issues hex pane in the screen compose tree
- **Traceability:** HLR-020
- **Statement:** The `#screen_issues` compose tree (app.py:1159-1177) shall include a hex `Static` (markup off) beside `#validation_issues_list`, laid out as a horizontal split mirroring `#diff_columns` (screens_directionb.py:1132-1137), preserving the existing filter/summary/empty-state subtree.
- **Target file:** `s19_app/tui/app.py` (`_compose_screen_issues`) + a layout rule in `styles.tcss`. OUTSIDE frozen set. NEW: `#issues_hex_pane` id (`NEW — created in Phase 3`).
- **Validation:** `test (integration)` — Pilot queries the widget within `#screen_issues`.
- **Executed verification:** `pytest tests/test_tui_issues_view.py -k pane_present` (provisional-until-Phase-3, V-5).
- **Numeric pass threshold:** `query_one("#issues_hex_pane", Static)` resolves inside `#screen_issues` (exactly 1 present); existing `#issues_content`/filter/summary preserved.
- **Acceptance criteria (informative):** no renderer/filter/paging logic touched (additive).

### LLR-020.2 — Render bytes at the selected issue address (with no-address state)
- **Traceability:** HLR-020
- **Statement:** When `on_data_table_row_selected` resolves a `validation_issues_list` row (app.py:4433), the system shall update `#issues_hex_pane` via `render_hex_view_text` (hexview.py:324) focused at the selected `ValidationIssue.address` (validation/model.py:126); when `address is None` it shall set the defined placeholder `"(issue has no address — nothing to show)"` and clear any prior bytes.
- **Target file:** `s19_app/tui/app.py` — the render site is `_jump_to_validation_issue_object` (:4771-4809, where the existing 3 cross-screen hex updates live at :4797-4799 [F-2]); the `on_data_table_row_selected` dispatcher (:4433) only routes and stays UNTOUCHED. OUTSIDE frozen set. `render_hex_view_text` reused. NOTE: the existing helper does nothing when `address is None`, so the no-address placeholder + clear-prior-bytes is genuinely net-new behavior here.
- **Validation:** `test (integration)` — Pilot selects addressed + address-less rows; asserts pane content.
- **Executed verification:** `pytest tests/test_tui_issues_view.py -k "address or no_address"` (provisional-until-Phase-3, V-5).
- **Numeric pass threshold:** addressed → pane contains the `0x%08X` row for the address (≥1 byte group); address-less → pane == placeholder AND 0 carried-over rows.
- **Acceptance criteria (informative):** the 3 pre-existing cross-screen hex updates (app.py:4797-4799) remain unchanged (additive).

### LLR-021.1 — Add related-artifacts to the issues cell row + column
- **Traceability:** HLR-021
- **Statement:** The issues cell-format (`precompute_issue_datatable_payload`, app.py:476-519) shall emit the issue's `related_artifacts` (validation/model.py:128) as a cell (`", ".join`, `-` empty marker), and the issues DataTable column set (app.py:2568-2576) shall add a matching "Related" column header; the summary/paging path (app.py:4848-4939), the `issue:<index>` row_key scheme (app.py:4979) and `_severity_style` (app.py:518) shall be unchanged.
- **Target file:** `s19_app/tui/app.py` (cell format :507-516 + column add :2568-2576 + the `use_precomputed` branch :4919-4928 + the 7-tuple docstring :488 → 8 + the `_populate_issues_datatable` docstring :4957 [docstring-only, m2]). OUTSIDE frozen set. Contract-touch identity check (tuple width 8 == column count 8) recorded in §6.4.
- **Validation:** `test (integration + unit)`.
- **Executed verification:** `pytest tests/test_tui_issues_view.py -k related_artifacts` (AT) + `pytest tests/test_tui_app.py -k issues_payload` (pure-function TC) (provisional-until-Phase-3, V-5).
- **Numeric pass threshold:** issue with `related_artifacts=["mac","s19"]` → Related cell contains both; empty list → `-`; cell-tuple width == DataTable column count (8==8).
- **Acceptance criteria (informative):** severity styling + row_key index map untouched; the parallel cell/style arrays stay index-aligned (a no-artifacts issue must not show another's artifacts).

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
| US-018 | full 16B+ASCII hex row on one line at ≥120 cols | Workspace `#ws_center` | AT-018 | pending Phase 3 |
| US-019 | written `.s19` uses the selected 16/32 record width | CRC ConfirmWrite flow → emitted file | AT-019a (32 default) · AT-019b (16, C-10/C-12) | pending |
| US-020a | selected issue's bytes shown in on-screen pane | Issues `#screen_issues` hex pane | AT-020a | pending |
| US-020b | related artifacts shown in issues row | Issues `#validation_issues_list` | AT-021 | pending |

**Functional chain (white-box) — per requirement:**

| Requirement | Method | Test Case (`TC-NNN`) | Notes |
|-------------|--------|----------------------|-------|
| HLR-018 / LLR-018.1 | test (integration) | TC-018.1 | Pilot region-width + proportional-layout probe |
| HLR-019 / LLR-019.1 | test (integration) | TC-019.2 | selector state machine (cycle 32↔16) |
| HLR-019 / LLR-019.2 | test (unit+integration) | TC-019.1 | `write_crc_image(bytes_per_line=)` honours width |
| HLR-020 / LLR-020.1 | test (integration) | TC-020a.0 | hex pane present in `#screen_issues` |
| HLR-020 / LLR-020.2 | test (integration) | TC-020a.1 | render bytes at address / no-address state |
| HLR-021 / LLR-021.1 | test (unit+integration) | TC-021.1 | payload emits related-artifacts cell + style aligned |

*(All `AT-NNN`/`TC-NNN` ids + test file paths provisional-until-Phase-3 per V-5, reconciled at Phase 4.)*

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

| Decision ID | What changed | Parent HLR re-read? | Body edit landed? |
|-------------|--------------|---------------------|-------------------|
| Phase-2 fold | M1 (LLR-019.1 carry → Option C) + m2 (LLR-021.1 +app.py:4957) + F-2 (LLR-020.2 → `_jump_to_validation_issue_object`) | yes — HLR-019/020/021 statements unchanged (only LLR mechanism detail refined) | yes (§4 LLR-019.1/020.2/021.1 + §3 contract-touch note) |

### 6.5 Requirement amendments (Before / After · Deleted / New)
*(Used by `iterate-to-refine` (Phase 1 from a Phase-4 black-box failure) and by Phase-3 spec amendments. One block per amendment: **Before → After** text · **Deleted / New** tokens · parent-HLR re-read result · the re-derived HLR/LLR + their `TC`/`AT`. Never silently edit a locked requirement.)*

**Amendment A1 — LLR-019.1 CRC width carry mechanism (Phase-2 major M1, architect).**
- **Before:** "NEW symbols: a width-button id + a `_crc_saveback_width` state attr (**Option B** — screen state, not a widened modal result)."
- **After:** "NEW symbols: a width-button id + `_crc_saveback_width` ON `ConfirmWriteScreen` + a **width-bearing dismiss result** (**Option C**): the modal cycles its own width and dismisses with a `ConfirmWriteDecision(confirmed, bytes_per_line)` message OR `(confirmed, bytes_per_line)` tuple, consumed by `_on_confirm_write` (:1323)."
- **Deleted:** Option B (read-foreign-screen-state) — INFEASIBLE: `_on_confirm_write` runs on `OperationsScreen` after the modal is dismissed and cannot reach the `ConfirmWriteScreen` instance.
- **New:** `ConfirmWriteDecision` carry (message or 2-tuple). The exact form (custom message vs tuple dismiss) is a Phase-3 implementation choice; both keep blast radius to `screens.py`.
- **Parent-HLR re-read:** HLR-019 statement is UNCHANGED (it says "the system shall emit … the selected width" — a behavior, agnostic to carry mechanism). Only the LLR-019.1 mechanism detail changed. AT-019a/AT-019b and TC-019.1/.2 are UNCHANGED (they observe the written file / selector state, not the carry plumbing).
- **Why:** architect Phase-2 M1; a self-modifying carry mechanism that can't actually deliver the width would have stalled Phase 3 at the boundary.

**Amendment A2 — US-018/HLR-018/LLR-018.1 approach: `min-width` floor → no-wrap + horizontal scroll (Phase-3 `iterate-to-refine`, operator-approved).**
- **Before:** HLR-018 "constrain `#ws_center` to a minimum width sufficient to render one full hex row"; LLR-018.1 "declare a `min-width` floor (target 82, mirroring `#mac_hex_pane`)". AT-018 = `#ws_center.region.width ≥ 82`.
- **After:** HLR-018 "render a full hex row on one line without wrapping, keeping all three Workspace panes visible"; LLR-018.1 = `#hex_view { width: auto }` so the hex view sizes to its content (~81 cells) and `#hex_scroll`'s existing `overflow: auto` provides a horizontal scrollbar. AT-018 = `#hex_view.region.width ≥ 81` AND `#hex_scroll.virtual_size.width ≥ 81` (row on one line + scrollable) + the panes-visible guard (`#ws_right` edge within the viewport).
- **Deleted:** the `min-width: 82` floor on `#ws_center` — PROVEN WRONG by Phase-3 measurement: the Workspace is a THREE-pane layout with two fixed sides (left 22 + right 40 = 62), so at a 120-col terminal (body 96) a floored center=82 forces 22+82+40=144 and pushes `#ws_right` off-screen (measured: right edge 79..119 at 120 ok pre-fix, but min-width:82 put center at 82 overflowing the 96 body → right clipped/off-screen). This is almost certainly why prior attempts didn't stick (operator: "not the first time we try to fix them"). The MAC `min-width:82` mirror does NOT transfer (MAC has 2 panes; records shrinks).
- **New:** `#hex_view { width: auto }` (1 CSS rule). Root cause was `#hex_view` (a `Static`) wrapping the 81-cell row to the ~30-cell pane; content-sizing it + the existing scroll container keeps the row on one line, all panes visible.
- **Parent-HLR re-read:** US-018 (the user story — "16 bytes + ASCII on one line, no wrap/truncate") is UNCHANGED and is in fact better served by A2 (on one line, scrollable) than by the floor (which only fit at terminals ≥~168 and broke the context pane). Only the HLR/LLR mechanism + AT observation changed.
- **Re-derived nodes:** AT-018 re-pointed to `#hex_view`/`#hex_scroll` content+virtual width (RED pre-fix captured: hex_view width 28 wrapped vs 81 post-fix; counterfactual run). TC-018.1 → the panes-visible guard. Tests in `tests/test_tui_workspace_layout.py`.
- **Evidence:** measured at 120/160/200 cols (right pane off-screen under min-width:82; on one line + scrollable + all panes visible under width:auto); full non-slow suite 886/0 (no snapshot/render regression).
