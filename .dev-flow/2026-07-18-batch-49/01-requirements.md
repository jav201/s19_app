# Requirements Document — s19_app — Batch 2026-07-18-batch-49

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
>
> **State-lifetime provenance rule (batch-24).** When a story CONSUMES state captured earlier by another flow (a retained summary, a cached result, a stamped path), the spec MUST state that state's LIFETIME story — who writes it, what invalidates/clears it, what happens if the world changed since capture (file reloaded, project switched) — and bind consumption to provenance (a recorded link to what the state was derived FROM, refused on mismatch). A consume-only story gets no new-write-surface security pass by default, so this is the spec-layer net. (Origin: batch-24 B-2 — `last_summary` survived project switches with no source-image field; the specced before/after report would pair project B's file with project A's patch, and every then-specced AT passed over it. Fix: `source_image_path` stamp + refusal class + a cross-project refusal AT.)

---

## 1. Introduction

### 1.1 Purpose
This document specifies batch-49 of the s19tool TUI: a **MID visual-insight upgrade to the existing Issues Report screen** and a **new dedicated CHECKS rail screen**. Both are read-only presentation surfaces over already-computed data; no parsing/validation/engine logic changes.

### 1.2 Scope
**In scope:** (a) Issues Report screen — a severity-distribution strip, leading severity glyphs on group headers, border-titled panes, and a colored summary line, matching the batch-47 Workspace/A2L/MAC "insight layer" cohort idiom. (b) A new `Checks` screen on the activity rail (key `9`) that renders `_change_service.last_check_result` grouped fail→uncheckable→pass with colors, a pass/fail/uncheckable aggregate strip, a hex peek on row-select, and honest empty states.
**Out of scope:** any change to check/validation engine logic; computing checks on file load (checks remain operator-triggered in the Patch Editor); the Patch Editor CHECKS window (already shipped batch-48); Issues filter/sort BIG-tier controls; Flow Builder; a2l.py re-freeze (separate item); raising the 120-col layout caps.

### 1.3 Definitions, acronyms, abbreviations
| Term | Definition |
|------|------------|
| Issues Report | The `#screen_issues` rail screen rendering `_validation_issues` grouped by severity. |
| CHECKS screen | NEW `#screen_checks` rail screen rendering `_change_service.last_check_result`. |
| `CheckRunResult` | The complete carrier of a check run: `aggregates` + per-entry `CheckRunEntry` + doc `issues` (`s19_app/tui/changes/model.py:683`). |
| `CheckRunEntry` | One checked entry: `address_start/end`, `expected_bytes`, `actual_bytes`, `result` (pass/fail/uncheckable), `linkage_symbol`, `reason` (`model.py:620`). |
| MID tier | Cumulative insight tier = EASY (markup/colors/border-titles) + micro-visuals inside existing panes (per `screen_upgrades.NOTES.md`). |
| C-17 | Markup-safety control: file-derived text rendered via `safe_text`/`markup=False`, never markup-parsed. |
| Insight cohort | Batch-47 screens (Workspace/A2L/MAC/Map/Patch) sharing `insight_style.py` idioms. |

### 1.4 References
- `prototypes/screen_upgrades.HANDOFF-PLAN.md` (cohort design + technical map); `prototypes/screen_upgrades.NOTES.md` (tier definitions).
- `s19_app/CLAUDE.md` (architecture, engine-frozen set, severity conventions); REQUIREMENTS.md (R-TUI-* rows; highest existing = R-TUI-081 → batch-49 starts R-TUI-082).
- `docs/engineering-rules.md` controls C-13/C-22/C-23/C-28/C-29 (stack-specific; consulted Phase-1/3) — **note: not present as a tracked file in this tree; the controls are carried in the dev-flow control-lineage memory and applied from there.**
- Recon maps (this batch): CHECKS data-model/lifecycle; Issues-screen internals + rail-registration checklist.

### 1.5 Document overview
§2 overall description + source stories (Phase-0). §3 HLR, §4 LLR, §5 dual-traceability validation strategy (Phase-1). §6 appendices (decisions, risks, reconciliation, amendments).

---

## 2. Overall description

### 2.1 Product perspective
s19tool is a Textual TUI over an engine-frozen parsing/validation core. `S19TuiApp` (`s19_app/tui/app.py`) is orchestration-only; feature logic lives in `tui/services/`. This batch adds one presentational widget module (`checks_view.py`, parallel to `issues_view.py`), extends `insight_style.py` (non-frozen batch-47 helper module) and `styles.tcss`, appends one rail entry, and adds render/wiring methods to `app.py`. No engine-frozen file is touched.

### 2.2 Product functions
1. Issues Report screen surfaces the severity distribution at a glance (colored strip + glyphs + titled panes) without changing its data or paging.
2. A dedicated Checks screen presents the last check run grouped by outcome with colors, aggregate counts, a hex peek, and honest empty states, reachable from the rail on key `9`.

### 2.3 User characteristics
Firmware/calibration engineers reviewing S19/HEX images against A2L/MAC metadata and change/check documents in a terminal; comfortable with keyboard navigation (rail keys 1–9); read-only consumers of these two screens.

### 2.4 Constraints
- **Engine-frozen set OFF-LIMITS** (`core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/mac.py`, `tui/color_policy.py`) + the frozen TEST files — C-27 dual-guard every increment. `tui/a2l.py` is out of scope.
- Severity→color MUST flow through `css_class_for_severity` / `SEVERITY_CLASS_MAP` (no hard-coded hex in logic).
- All file-derived text (issue code/symbol/message; check `linkage_symbol`/`reason`/blocked-reason; `ValidationIssue.symbol`) rendered C-17-safe (`markup=False`/`safe_text`).
- Snapshot SVG baselines regen in canonical CI only (`snapshot-regen.yml`, textual==8.2.8) — never local.
- Layout budgets honored at 80×24 and 120×30 (C-23/C-29 two-axis measurement for any new sizing).

### 2.5 Assumptions and dependencies
- **A1:** `_change_service.last_check_result` is the sole source of check data and is `None` until the Patch Editor `run_checks` action runs; reset on undo/redo. (Verified: `change_service.py:420/1419/571/603`.) If false, the CHECKS empty-state semantics are wrong → batch invalidated.
- **A2:** Check result→severity→color reuses `_CHECK_RESULT_SEVERITY` (pass→OK, fail→ERROR, uncheckable→WARNING) + `css_class_for_severity` (`change_service.py:78`, `color_policy.py:17`).
- **A3:** The rail routing (`SCREEN_CONTAINER_IDS` + `action_show_screen` + `BINDINGS`) and command-palette/help-panel/footer auto-derive a new screen from a single `Binding`. (Verified via recon PART C.)
- **A4:** Existing check fixtures (an S19 image + a `kind:"check"` change document) exist for the black-box AT that drives `run_checks` then observes the Checks screen. *(assumed — verify exact fixture paths in Phase 1.)*

### 2.6 Source user stories

> Connextra format. Each US gets a unique ID and traces to ≥1 HLR. **Phase 0 — Definition of Ready (INVEST):** only `READY` stories proceed to Phase 1.

| ID | User Story | Source | DoR status |
|----|------------|--------|------------|
| US-082 | As a firmware engineer reviewing an image, I want the Issues Report screen to surface the severity distribution at a glance (a colored counts strip, severity glyphs, titled panes), so that I can gauge the error/warning/info balance without reading every row. | Operator 2026-07-18 ("issues report") + screen-upgrades cohort (Issues was PARKED, now MID) | READY |
| US-083 | As a firmware engineer who has run patch checks, I want a dedicated Checks screen on the rail that shows check results grouped by fail/uncheckable/pass with colors, an aggregate strip and a hex peek, so that I can review verification outcomes in one focused place instead of only the Patch Editor's compact window. | Operator 2026-07-18 ("checks report") | READY |

#### Refinement log (one block per story)

**US-082 — Issues Report MID visual-insight upgrade**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):** user = engineer on the Issues screen · outcome = at-a-glance severity distribution (colored `Errors N / Warnings M / Info K` strip with proportional micro-bars + threshold colors; leading severity glyph on each group header; border-titled panes; colored summary counts) · why = the screen today is a dense grouped list with a plain summary line — the balance of severities is not visible without scanning · out of scope = paging/filter behavior (unchanged), row data content, any engine change, zebra on the non-DataTable grouped list (rows are `Horizontal` widgets — a structural change, deferred).
- **Feasibility (E, S):** implementation path = render-only. New module-level `build_issues_severity_strip(...) -> Text` helper (in `insight_style.py` or `issues_view.py`) reusing `microbar`/`threshold_style`; a new `Static(id="issues_severity_strip")` in `_compose_screen_issues` (`app.py:1716`) populated by `update_validation_issues_view` (`app.py:6931`); a leading glyph appended in `IssueGroupHeader.__init__` (`issues_view.py:103`); `.border_title`/`.border_subtitle` + `.db-pane` on the Issues panes; colored summary via `label_value`. dependencies = `insight_style.py` (non-frozen), `css_class_for_severity`. fits one batch? = yes (1 increment).
- **Evaluability (T) — behavioral, black-box:** "When a file with ≥1 error and ≥1 warning is loaded and the Issues screen is shown, the user observes a severity strip whose Errors/Warnings/Info counts equal the `_validation_issues` counts and whose micro-bars are non-empty, and each group header shows its severity glyph." → `AT-082*`.
- **Open questions:** none blocking. (Strip placement — above the groups, inside `#issues_content` — settled by cohort precedent.)
- **Classification:** `READY` — render-only, cohort-analogous, data source already on-screen.

**US-083 — Dedicated CHECKS rail screen**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ~ (largest story; one screen, cohesive) · T ✓
- **Functionality (V, N):** user = engineer who ran patch checks · outcome = a `Checks` rail screen (key `9`) that, after a check run, lists `CheckRunEntry` records grouped fail→uncheckable→pass, colored via `css_class_for_severity`, with a pass/fail/uncheckable aggregate strip and a hex peek on row-select; before any run shows a "no check run yet" note; with no file shows the empty-state panel · why = check outcomes today live only in the Patch Editor's compact `#patch_win_checks` window, mixed with editing chrome — no focused review surface · out of scope = computing checks on load (inherent: no expected-bytes without a check document), triggering runs from this screen (read-only mirror), filter buttons (deferred), the Patch Editor window (unchanged).
- **Feasibility (E, S):** implementation path = new presentational `checks_view.py` (`GroupedChecksPanel`/`CheckRow`/`CheckGroupHeader`, parallel to `issues_view.py`) consuming `last_check_result.entries`; rail registration 5 sites (recon PART C: `RAIL_ENTRIES` append key 9, `SCREEN_CONTAINER_IDS`, a `9` `Binding`, `compose` insertion, new `_compose_screen_checks`); a new `update_checks_view()` + `_update_checks_hex_pane()` on `app.py` reading `_change_service.last_check_result`, wired at load / post-`run_checks` (`app.py:2085`) / undo-redo (`app.py:2329`) / screen-activation; a pass/fail/uncheckable strip via a `build_checks_aggregate_strip(...)` helper; empty-state via `_EMPTY_STATE_SCREENS`. dependencies = `change_service` accessors (`check_aggregates()`, entries), `css_class_for_severity`, `render_hex_view_text`. fits one batch? = yes but multi-increment (rail+compose; panel+render; wiring+hex; empty states).
- **Evaluability (T) — behavioral, black-box:** "When a file + a check document are loaded and checks are run, then pressing `9` shows the Checks screen listing the entries grouped by outcome with counts matching `check_aggregates()`; selecting a fail row updates the hex peek to bytes at that entry's address." + "When a file is loaded but no checks have run, the Checks screen shows the 'no check run yet' note." + "When no file is loaded, the Checks screen shows the empty-state panel." → `AT-083*`.
- **Open questions:** exact glyph/label for the rail entry (`☑`/`C`, "Checks") — cosmetic, settle in Phase 1; whether to reuse `check_rows()` text or read `entries` directly (read `entries` for grouping + hex-peek address — settle in Phase 1 LLR).
- **Classification:** `READY` — data source + render path + rail mechanism all verified in recon; no unknown feasibility.

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

> **Canonical AT registry (pinned by the orchestrator before Phase 2 — C-21 / batch-48 anti-divergence).** HLR-082 → AT-082a…f · HLR-083 → AT-083a…b · HLR-084 → AT-084a…g. **Gate-blocking ATs:** AT-082a, AT-082c, AT-082f, AT-083a, AT-084a, AT-084b, AT-084c, AT-084g. All AT/TC ids provisional-until-Phase-3 (V-5). REQUIREMENTS.md rows: HLR-082→R-TUI-082, HLR-083→R-TUI-083, HLR-084→R-TUI-084.

### HLR-082 — Issues Report MID visual-insight layer (render-only)
- **Traceability:** US-082 → HLR-082 → AT-082a…f → R-TUI-082
- **Statement (EARS · State-driven):** While the Issues Report screen (`#screen_issues`) is displaying a computed validation-issue list, the TUI **shall** present (a) a severity-distribution strip showing Errors N / Warnings M / Info K with proportional micro-bars and severity colours above the grouped list, (b) a leading severity glyph on each group header, (c) author-composed border titles/subtitles on the Issues list and hex panes, and (d) a severity-coloured summary line, while leaving the underlying issue data, grouping, paging, and filtering unchanged.
- **Rationale (informative):** the Issues screen opens with a flat grouped list and a plain-text summary (`app.py:6986-6996`); severity balance is not visible at a glance. Same insight pattern batch-47 applied to five screens (`insight_style.py`, `build_mac_coverage_strip`).
- **Validation:** `test` (Textual Pilot + white-box widget assertions) + `inspection` (CSS class / no hard-coded hex).
- **Executed verification:** `pytest -q tests/test_tui_issues_view.py tests/test_tui_directionb.py` + canonical-CI snapshot regen.
- **Numeric pass threshold:** AT-082a…f + TC-082.1…5 pass; 0 regressions in existing Issues paging/filter tests; `.plain` of `#validation_issues_summary` byte-identical to today.
- **Priority:** medium.
- **Acceptance (black-box):**
  - **Observable outcome:** a file with ≥1 error/warning/info renders a strip `Errors N`/`Warnings M`/`Info K` with each micro-bar proportional to its share, each group header prefixed with a severity glyph, panes border-titled, summary colour-classed.
  - **Shipped surface:** `#screen_issues` (rail key `5`).
  - **Deliverable + observation:** load mixed-severity image → `5` → read strip counts + bar widths + header glyphs + pane border titles + summary spans.
  - **Acceptance test(s):** AT-082a (**GATE**, C-31 — inject an **asymmetric 3 error / 1 warning / 2 info** distribution [all-distinct, never symmetric], render, and assert each strip slot equals the count re-derived **independently** by bucketing `_validation_issues` per `ValidationSeverity` [`Counter(i.severity for i in app._validation_issues)`], per-slot — NOT an aggregate compare against the view's own `error_count`/`warning_count`/`info_count`; a label/slot swap must go RED) · AT-082b (bar present iff count>0; drives the 0-arm) · AT-082c (leading severity glyph per group header, **GATE**) · AT-082d (colour-classed summary line, spans match palette) · AT-082e (zero-issues boundary, no div-by-zero) · AT-082f (**GATE**, C-17 — payload `code="[bold]X[/]"` + `message="[link=http://x]click[/link] [/nope]"`; assert the rendered cell `.plain == payload verbatim` **AND** no injected link/bold/OSC-8 span [`spans==[]` on the file-derived cell] **AND** no `MarkupError` — crash-free alone insufficient).
  - **Boundary catalog:** ☑ empty (AT-082e: 0 issues → 0/0/0, empty bars) · ☑ boundary (AT-082b single-severity 0-arm; TC-082.2 2-digit-count strip width) · ☑ invalid (AT-082f hostile markup) · ☑ error — N/A (render-only, no I/O on the strip path; load errors are the loader's contract, out of scope).

### HLR-083 — CHECKS rail screen + activity-rail navigation
- **Traceability:** US-083 → HLR-083 → AT-083a…b → R-TUI-083
- **Statement (EARS · Event-driven):** When the operator selects the Checks rail entry (key `9`) or the `Checks` command-palette command, the TUI **shall** activate a dedicated read-only Checks screen (`#screen_checks`) as the ninth activity-rail screen, hide the other eight screens, and move the rail's single active marker to the Checks entry.
- **Rationale (informative):** check results are today reachable only inside the Patch Editor checks window (`refresh_check_results`, `screens_directionb.py:4716`); no dedicated review surface. Mirrors the Issues Report promotion pattern (`_compose_screen_issues`, `app.py:1716`).
- **Validation:** `test` (navigation + rail-activation white-box) + `inspection` (rail tuple / bindings).
- **Executed verification:** `pytest -q tests/test_tui_directionb.py` + the batch's checks-navigation test.
- **Numeric pass threshold:** AT-083a…b + TC-083.1…6 pass; the updated rail-count/screen-count assertions (`== 9`) + `EXPECTED_RAIL` fixture pass.
- **Priority:** medium-high (unlocks HLR-084; touches the shared rail tuple).
- **Acceptance (black-box):**
  - **Observable outcome:** pressing `9` (or `Checks` from the palette/`?` help panel) shows `#screen_checks`, hides the other eight, and highlights the Checks rail item; pressing another rail key hides `#screen_checks` again.
  - **Shipped surface:** activity rail (`rail.py`) + `#screen_checks`.
  - **Deliverable + observation:** `s19tui` → `9` → Checks visible + rail marker on Checks → `5` → Checks hidden, Issues shown.
  - **Acceptance test(s):** AT-083a (key `9` AND palette command both activate `#screen_checks`, hide others, set the rail marker — **GATE**, C-10: asserts the active screen *changed* off default) · AT-083b (activating any other screen hides `#screen_checks`).
  - **Boundary catalog:** ☑ empty (press `9` with no file → screen still activates, EmptyStatePanel per HLR-084) · ☑ boundary (rail now 9 items; `1`–`9` keymap consistent) · ☑ invalid (unknown screen key ignored — existing `action_show_screen` guard `app.py:4927`) · ☑ error (key `0` remains unbound — no off-by-one into a 10th screen).

### HLR-084 — CHECKS screen render, hex peek, aggregate strip, empty states
- **Traceability:** US-083 → HLR-084 → AT-084a…g → R-TUI-084
- **Statement (EARS · State-driven + Unwanted):** While the Checks screen is active and a check run exists (`_change_service.last_check_result` is not None), the TUI **shall** render the run's entries as a read-only list grouped fail → uncheckable → pass, each row coloured through `css_class_for_severity`, above a pass/fail/uncheckable aggregate strip, and when an entry row is selected **shall** show a focused hex+ASCII window around that entry's `address_start`. If no file is loaded, then the TUI **shall** show the empty-state panel; if a file is loaded but no check has run, then the TUI **shall** show a "no check run yet" note instead of a blank or zeroed list.
- **Rationale (informative):** `last_check_result` is the sole check-run state (`change_service.py:420/1419`), reset on undo/redo (`:571/:603`). Pure read-only mirror; grouping + address peek require reading `CheckRunEntry` (`model.py:671-680`), which the flat `check_rows()` (`change_service.py:1499`) does not expose — a new grouped accessor is needed.
- **Validation:** `test` (white-box grouped render + hex pane + empty-state; output-then-consume for the accessor) + `inspection` (result→severity colour map).
- **Executed verification:** `pytest -q tests/test_tui_checks_view.py tests/test_tui_checks_screen.py tests/test_tui_patch_checks_strip.py`.
- **Numeric pass threshold:** AT-084a…g + TC-084.1…9 pass; strip clears to all-zero on undo/redo.
- **Priority:** medium-high.
- **Acceptance (black-box):**
  - **Observable outcome:** after a check run, the Checks screen lists entries grouped fail→uncheckable→pass with severity colours; the aggregate strip shows P/F/U counts with a proportional bar; selecting a fail row shows that address's bytes in the hex pane; undo clears both; file-but-no-run reads "no check run yet"; no-file shows the EmptyStatePanel.
  - **Shipped surface:** `#screen_checks` (`#checks_grouped`, `#checks_aggregate_strip`, `#checks_hex_pane`, `#checks_content`).
  - **Deliverable + observation:** load image → Patch Editor → run checks (real `#patch_checks_run_button`) → `9` → read grouped list + strip → select a fail row → read hex pane → undo → observe cleared state.
  - **Acceptance test(s):** AT-084a (post-run grouped fail→uncheckable→pass, correct colours — **GATE**, C-12 through-surface via the real `#patch_checks_run_button`) · AT-084b (aggregate strip counts == `check_aggregates()` recomputed live, first assert fixture integrity `{"passed":2,"failed":1,"uncheckable":3}` — **GATE**, C-31) · AT-084c (fail-row select renders the entry's **address** `0x102` in `#checks_hex_pane` — the image is all-`0x00` so the address row, not the byte value, is the discriminator; assert the `0x102` address label appears — **GATE**, C-12) · AT-084d (no-file → EmptyStatePanel) · AT-084e (file + no-run → "no check run yet" note, distinct from a real 0/0/0 run) · AT-084f (undo/redo clears list + strip) · AT-084g (**GATE**, C-17 — payload `linkage_symbol`/`reason` = `[bold]X[/]` + `[link=file:///etc]` + `[/nope]` + ANSI; assert `.plain == payload verbatim` AND `spans==[]` on the file-derived cell AND no `MarkupError`/OSC-8 escape).
  - **Boundary catalog:** ☑ empty (AT-084d no-file; AT-084e no-run; 0-entry run → all-zero strip honest degradation) · ☑ boundary (uncheckable-only run → single group; uncheckable entry `actual_bytes=None` → hex window shows address, no actual bytes) · ☑ invalid (AT-084g hostile markup) · ☑ error (row-select on unmounted/headless tree = safe no-op, mirrors `_update_issues_hex_pane` guard `app.py:6835`; undo after run resets `last_check_result` → TC-084.7).

---

## 4. Low-level requirements (LLR)

> Each LLR decomposes an HLR into a verifiable property at the implementation level.
> Same EARS regime. ID format: `LLR-<HLR>.<M>`.

> Citation legend: `file:line` = grep-verified against the main repo root. `NEW` = created in Phase 3. C-26 touched-symbol(s) declared per LLR for the Phase-2/3 reverse-grep. No LLR edits an engine-frozen file (verified — §6.3 R-1).

#### HLR-082 (Issues MID) — files: `tui/issues_view.py`, `tui/app.py`, `tui/styles.tcss`

**LLR-082.1 — severity-distribution strip helper (NEW).**
- **Traceability:** HLR-082
- **Statement:** A NEW module-level `build_issues_severity_strip(error: int, warning: int, info: int) -> Text` in `issues_view.py` **shall** build a `rich.text.Text` (constructor/append + `microbar`, `insight_style.py:216`) showing the three counts with per-severity fixed colours (ERROR=`RED` `insight_style.py:51`, WARNING=`YELLOW` :49, INFO=`CYAN` :61) and each bar fraction = count/total (total 0 → empty bars, no division). Mirrors `build_mac_coverage_strip` (`services/validation_service.py:28-78`).
- **Validation:** `test (unit)`. **Executed verification:** `pytest tests/test_tui_issues_view.py -k severity_strip`. **Numeric pass threshold:** counts exact; bar filled-cells monotone in fraction; total=0 → 0 filled, no exception. *(MIN-4: the strip's severity set is bounded by `SEVERITY_ORDER` (`issues_view.py:55`, ERROR/WARNING/INFO); TC-082.1 asserts one strip slot per `SEVERITY_ORDER` member so a future 4th issue-severity is not silently dropped.)*
- **Touched (C-26):** NEW `build_issues_severity_strip`.

**LLR-082.2 — mount + drive the strip in `#screen_issues`.**
- **Traceability:** HLR-082
- **Statement:** `_compose_screen_issues` (`app.py:1716-1779`) **shall** mount `Static(id="issues_severity_strip", markup=False)` inside `#issues_content` above the `#issues_columns` container (id at `app.py:1768`), and `update_validation_issues_view` (`app.py:6931`) **shall** update it from the already-computed `error_count`/`warning_count`/`info_count` (`app.py:6975-6977`) via `build_issues_severity_strip`.
- **Validation:** `test (integration)` (Pilot query `#issues_severity_strip`). **Executed verification:** AT-082a. **Numeric pass threshold:** strip present iff `#issues_content` visible; counts == view counts.
- **Touched (C-26):** `_compose_screen_issues`, `update_validation_issues_view`; NEW id `#issues_severity_strip`.

**LLR-082.3 — leading severity glyph on group headers.**
- **Traceability:** HLR-082
- **Statement:** `IssueGroupHeader.__init__` (`issues_view.py:103-112`) **shall** prepend an author-controlled glyph from a NEW closed map `_SEVERITY_GLYPH: Dict[ValidationSeverity, str]` (ERROR `✗` / WARNING `⚠` / INFO `•`) into the `safe_text(f"{glyph} {label}  ({count})")` composition; glyphs are author constants (never file-derived).
- **Validation:** `test (unit)` (`IssueGroupHeader(...).plain` starts with the mapped glyph). **Executed verification:** AT-082c. **Numeric pass threshold:** one glyph per `SEVERITY_ORDER` member (`issues_view.py:55`).
- **Touched (C-26):** `IssueGroupHeader.__init__`, NEW `_SEVERITY_GLYPH`. Reverse-grep tests asserting the header's exact plain string.

**LLR-082.4 — border titles/subtitles on Issues panes.**
- **Traceability:** HLR-082
- **Statement:** author-composed `border_title`/`border_subtitle` **shall** be set on `#issues_list_stack` (`app.py:1765`) and `#issues_hex_pane` (`app.py:1767`) (e.g. "Issues"/"Hex Peek"), following the `_WINDOW_BORDER_TITLES` assignment precedent (`screens_directionb.py:3547-3549`), with a matching border rule in `styles.tcss`. Tokens are author constants (C-17: never file-derived).
- **Validation:** `inspection` (`widget.border_title` equality + CSS border rule present). **Executed verification:** TC-082.4 (inspection) + snapshot. **Numeric pass threshold:** exact author string; border visible.
- **Touched (C-26):** `#issues_list_stack`, `#issues_hex_pane` (compose + CSS).

**LLR-082.5 — severity-coloured summary line.**
- **Traceability:** HLR-082
- **Statement:** `update_validation_issues_view` (`app.py:6986-6996`) **shall** set `#validation_issues_summary` to a `rich.text.Text` whose `errors=`/`warnings=`/`info=` tokens carry RED/YELLOW/CYAN styles (constructor+append, never `Text.from_markup`); the **plain** content **shall** remain byte-identical to today.
- **Validation:** `test (unit)` (`.plain` unchanged; spans carry expected styles). **Executed verification:** AT-082d + TC-082.4. **Numeric pass threshold:** `.plain` byte-identical; ≥1 styled span per present severity.
- **Touched (C-26):** `update_validation_issues_view`, `#validation_issues_summary` (reverse-grep — confirm existing summary tests read `.plain`/renderable, not `isinstance str`; §6.3 R-5).

**LLR-082.6 — C-17 markup safety (Issues new surfaces).**
- **Traceability:** HLR-082
- **Statement:** every new Issues surface (strip, header glyph, coloured summary, border titles) **shall** be composed as `rich.text.Text` (constructor/append/`safe_text`), never `Text.from_markup`, and **shall** carry only ints + author constants (no `issue.symbol`/`.message`/`.code` reaches the strip/glyph/summary/border).
- **Validation:** `test` (hostile-input AT). **Executed verification:** AT-082f. **Numeric pass threshold:** literal render, no `MarkupError`, spans limited to author styles.
- **Touched (C-26):** cross-cutting over LLR-082.1-.5.

#### HLR-083 (CHECKS screen + rail nav) — files: `tui/rail.py`, `tui/app.py`, `tui/styles.tcss`, `tests/test_tui_directionb.py`

**LLR-083.1 — register the Checks rail entry.**
- **Traceability:** HLR-083
- **Statement:** `RAIL_ENTRIES` (`rail.py:78-87`) **shall** append `RailEntry("checks", <glyph>, <ascii>, "Checks")` as the 9th entry (1-based position = keymap `9`; glyph `☑` / ascii `C` — `✓` avoided, collides with `GLYPH_PASS`); the stale "eight"/"Bookmarks"/keys-1-8 docstrings (`rail.py:8-9,74-77,181`) **shall** be corrected.
- **Validation:** `test` + `inspection`. **Executed verification:** `pytest tests/test_tui_directionb.py` (updated `== 9` + `EXPECTED_RAIL`); AT-083a. **Numeric pass threshold:** `RAIL_ENTRIES[8].key == "checks"`; 9 items render.
- **Touched (C-26):** `RAIL_ENTRIES` — **BREAKS** `test_tui_directionb.py`: `EXPECTED_RAIL` def :449 · `positions==[1..8]` :488 · `== 8` :698/:741/:779/:881 · key-routing :493 · digit-strings :506/:513 → all updated to 9 (`[1..9]`, `"123456789"`) in THIS increment (§6.3 R-2, architect-verified set).

**LLR-083.2 — screen-container mapping.**
- **Traceability:** HLR-083
- **Statement:** `SCREEN_CONTAINER_IDS` (`app.py:4829-4838`) **shall** gain `"checks": "screen_checks"`.
- **Validation:** `test` (`action_show_screen("checks")` resolves). **Executed verification:** AT-083a. **Numeric pass threshold:** map has 9 entries.
- **Touched (C-26):** `SCREEN_CONTAINER_IDS`.

**LLR-083.3 — key binding + palette/help propagation.**
- **Traceability:** HLR-083
- **Statement:** `BINDINGS` (`app.py:1053-1060`) **shall** gain `Binding("9", "show_screen('checks')", "Checks", show=False)` after the `8` binding; this auto-adds the palette entry (`_build_palette_entries`, `app.py:4845-4886`) and the `?` help-panel entry.
- **Validation:** `test` (press `9` activates; palette contains "Checks"). **Executed verification:** AT-083a. **Numeric pass threshold:** both paths reach `#screen_checks`.
- **Touched (C-26):** `BINDINGS`.

**LLR-083.4 — compose the screen into the body.**
- **Traceability:** HLR-083
- **Statement:** `compose` (`app.py:1570-1584`) **shall** add `self._compose_screen_checks(),` into `#workspace_body` after `_compose_screen_flow()`.
- **Validation:** `test` (`#screen_checks` mounted, `.hidden` at startup). **Executed verification:** TC-083.4. **Numeric pass threshold:** present + hidden at startup.
- **Touched (C-26):** `compose`.

**LLR-083.5 — `_compose_screen_checks` scaffold (NEW).**
- **Traceability:** HLR-083
- **Statement:** a NEW `_compose_screen_checks(self) -> Container` (modelled on `_compose_screen_issues`, `app.py:1716-1779`) **shall** return `Container(id="screen_checks", classes="db-screen hidden")` holding `Label("Checks", classes="db-screen-title")`, a `#checks_content` container (`Static(id="checks_aggregate_strip", markup=False)`, then `#checks_columns` = `GroupedChecksPanel(id="checks_grouped")` + `Static(id="checks_hex_pane", markup=False)`), and an `EmptyStatePanel()`.
- **Validation:** `test` (all ids queryable). **Executed verification:** TC-083.4, AT-084*. **Numeric pass threshold:** full subtree present.
- **Touched (C-26):** NEW `_compose_screen_checks`; NEW ids `#screen_checks`, `#checks_content`, `#checks_aggregate_strip`, `#checks_columns`, `#checks_grouped`, `#checks_hex_pane`.

**LLR-083.6 — navigation refresh hook.**
- **Traceability:** HLR-083
- **Statement:** `action_show_screen` (`app.py:4937-4942`, after `_apply_empty_state()`) **shall** add `elif screen_key == "checks": self.update_checks_view()` so the read-only mirror is rebuilt lazily on entry (checks never change on file load → no load-pipeline hook, a deliberate simplification).
- **Validation:** `test` (navigating to checks calls `update_checks_view`). **Executed verification:** AT-084a. **Numeric pass threshold:** view reflects `last_check_result` on entry.
- **Touched (C-26):** `action_show_screen`.

#### HLR-084 (CHECKS render/hex/aggregate/empty) — files: `tui/checks_view.py` (NEW), `tui/services/change_service.py`, `tui/app.py`, `tui/styles.tcss`

**LLR-084.1 — `checks_view.py` widgets (NEW file).**
- **Traceability:** HLR-084
- **Statement:** a NEW `s19_app/tui/checks_view.py` (mirroring `issues_view.py`) **shall** define `CheckGroupHeader(Static)`, `CheckRow(Horizontal)` (`can_focus=True`, `Selected(Message)` carrying `address: Optional[int]`), and `GroupedChecksPanel(ScrollableContainer)` with `render_groups(rows, group_counts, ...)`, group order fail → uncheckable → pass (NEW `CHECK_GROUP_ORDER` over `ValidationSeverity` ERROR/WARNING/OK), colour via `css_class_for_severity` (frozen — read-only import), every cell via `safe_text` (imported from `screens_directionb`, cf. `issues_view.py:38`), reusing a `_GROUP_DISPLAY_MAX`-style mount cap.
- **Validation:** `test (unit)` (render assertions both fixture sizes). **Executed verification:** TC-084.1, AT-084a. **Numeric pass threshold:** groups fail→uncheckable→pass; colours match `_CHECK_RESULT_SEVERITY` (`change_service.py:78-82`).
- **Touched (C-26):** NEW file + symbols.

**LLR-084.2 — grouped display-row accessor (NEW).**
- **Traceability:** HLR-084
- **Statement:** `ChangeService` (`change_service.py`, near `check_rows` :1499) **shall** gain `check_display_rows(self) -> list[CheckDisplayRow]` returning a NEW `@dataclass CheckDisplayRow(result: str, address: Optional[int], text: str, css_class: str, linkage_symbol: Optional[str] = None)` (beside `CheckResultRow`, `:331-355`; the 5th optional field carries the file-derived linkage name to its own cell — see §6.5 AMD-1), reading `last_check_result.entries` (`model.py:745`) — `address_start` (`:672`), `result` (`:676`) → severity via `_CHECK_RESULT_SEVERITY` (`:78`) → `css_class_for_severity`; returns `[]` when `last_check_result is None` (mirror `:1526-1527`). **`text` field composition (pinned for the C-17 audit, MIN-2):** author-domain address range `f"0x{address_start:X}-0x{address_end-1:X}"` + expected/actual byte hex (ints) + `f" -> {result}"` + file-derived `reason` **iff present** (uncheckable rows) — the `reason` token is the sole file-derived member of `text` and rides LLR-084.8's `safe_text`; all other members are ints/author constants. `linkage_symbol` (file-derived) rendered in its own cell, not folded into `text`.
- **Validation:** `test (unit)` (output-then-consume: unit-test rows, then feed to `GroupedChecksPanel`). **Executed verification:** TC-084.2. **Numeric pass threshold:** one row per entry, address preserved, `[]` when no run.
- **Touched (C-26):** NEW `check_display_rows`, NEW `CheckDisplayRow` (`change_service.py` non-frozen service layer).

**LLR-084.3 — `update_checks_view` driver (NEW).**
- **Traceability:** HLR-084
- **Statement:** a NEW `update_checks_view(self) -> None` on `app.py` **shall** guard `not self.screen_stack`/absent `#checks_grouped` (mirror `app.py:7039-7043`), read `self._change_service.check_display_rows()` + `check_aggregates()` (`change_service.py:1455`), group counts by result, call `GroupedChecksPanel.render_groups(...)` and update `#checks_aggregate_strip`; when rows empty AND a file is loaded, render the "no check run yet" note (LLR-084.6).
- **Validation:** `test` (after a run the panel holds grouped rows). **Executed verification:** AT-084a/084b/084e. **Numeric pass threshold:** rows == entries; note shown when empty+file.
- **Touched (C-26):** NEW `update_checks_view`.

**LLR-084.4 — CHECKS aggregate strip (NEW helper).**
- **Traceability:** HLR-084
- **Statement:** a NEW `build_checks_aggregate_strip(aggregates: Mapping[str, int]) -> Text` (in `checks_view.py`) **shall** build a P/F/U count line + `microbar(passed/total, cells, style=GREEN)`, mirroring `PatchEditorPanel._check_strip_text` (`screens_directionb.py:4680-4714`) and reusing the `_CHECK_STRIP_BAR_CELLS = 8` scale (`:2564`); fed from `check_aggregates()` (all-zero when `last_check_result is None`, `:1494-1495`) so it clears by riding the existing reset.
- **Validation:** `test (unit)`. **Executed verification:** AT-084b. **Numeric pass threshold:** strip counts == `check_aggregates()`; all-zero after undo.
- **Touched (C-26):** NEW `build_checks_aggregate_strip`; `#checks_aggregate_strip`.

**LLR-084.5 — hex peek on row-select.**
- **Traceability:** HLR-084
- **Statement:** NEW `on_check_row_selected(self, event: CheckRow.Selected)` → `_update_checks_hex_pane(self, address: Optional[int])` on `app.py` **shall** mirror `on_issue_row_selected`/`_update_issues_hex_pane` (`app.py:6804-6850`): guard `not self.screen_stack`; query `#checks_hex_pane`; on non-int address or no `current_file` show a placeholder; else `render_hex_view_text(self.current_file.mem_map, address, row_bases, None)`.
- **Validation:** `test` (row-select updates pane; headless = no-op). **Executed verification:** AT-084c. **Numeric pass threshold:** correct address window; safe no-op unmounted.
- **Touched (C-26):** NEW `on_check_row_selected`, `_update_checks_hex_pane`; `#checks_hex_pane`.

**LLR-084.6 — empty states.**
- **Traceability:** HLR-084
- **Statement:** `_EMPTY_STATE_SCREENS` (`app.py:4972-4976`) **shall** gain `("screen_checks", "checks_content")` (no-file → `EmptyStatePanel`, hide `#checks_content`, via `_apply_empty_state` `:4978-5018`); and `GroupedChecksPanel` **shall** render a NEW author-constant `NO_RUN_TEXT = "No check run yet — run checks from the Patch Editor."` (cf. `GroupedIssuesPanel.EMPTY_TEXT`, `issues_view.py:258`) for the file-loaded-but-no-run state.
- **Validation:** `test` (3 distinct states). **Executed verification:** AT-084d, AT-084e. **Numeric pass threshold:** no-file → EmptyStatePanel; file+no-run → note; post-run → rows.
- **Touched (C-26):** `_EMPTY_STATE_SCREENS`; NEW `GroupedChecksPanel.NO_RUN_TEXT`.

**LLR-084.7 — run/undo/redo refresh wiring.**
- **Traceability:** HLR-084
- **Statement:** after the post-run `panel.refresh_check_results(...)` (`app.py:2085-2089`) and at the undo/redo clear site (`app.py:2329-2331`), `self.update_checks_view()` **shall** be called so the CHECKS screen and the Patch panel read one state; the strip/list clear by riding `last_check_result`'s existing reset (`change_service.py:571/603`).
- **Validation:** `test` (run → populated; undo → cleared, no stale rows — the batch-38 Inc-4 F1 shape must not recur). **Executed verification:** AT-084f, TC-084.7. **Numeric pass threshold:** no stale rows/strip after undo.
- **Touched (C-26):** two `app.py` call sites.

**LLR-084.8 — C-17 markup safety (CHECKS surfaces).**
- **Traceability:** HLR-084
- **Statement:** `CheckRunEntry.linkage_symbol` (`model.py:678`), `CheckRunEntry.reason` (`model.py:680`), `CheckRunResult.run_blocked_reason` (`:751`), and any `ValidationIssue.symbol` (unscrubbed) reaching a `checks_view` cell **shall** render via `safe_text`/`markup=False`; the aggregate strip + glyphs carry only ints/author constants. *(MIN-1: `reason` added to the enumeration — although `check.py:352-390` currently composes `reason` from author-domain codes+hex only, the render defense is named so a future file-derived interpolation is already covered.)*
- **Validation:** `test` (hostile-input AT). **Executed verification:** AT-084g. **Numeric pass threshold:** literal render, no `MarkupError`, no OSC-8 escape, `spans == []` on file-derived cells.
- **Touched (C-26):** cross-cutting over LLR-084.1-.6.

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

**Behavioral chain (black-box) — per user story:** (AT ids provisional-until-Phase-3, V-5. Reuse drivers: Issues `tests/test_tui_issues_view.py:59-62`; run-checks `tests/test_tui_patch_checks_strip.py` `_open_patch_with_paste`/`_run_checks`/`_ASYMMETRIC_ENTRIES` 2 pass/1 fail@0x102/3 uncheckable.)

| US | Observable outcome | Shipped surface | AT (`GATE`?) | Observed? |
|----|--------------------|-----------------|--------------|-----------|
| US-082 | severity strip counts == `_validation_issues` counts + proportional bars | `#screen_issues` / `#issues_severity_strip` | AT-082a **GATE** | ☐ |
| US-082 | micro-bar present iff count>0 (0-arm) | `#issues_severity_strip` | AT-082b | ☐ |
| US-082 | leading severity glyph per group header | `#validation_issues_groups` | AT-082c **GATE** | ☐ |
| US-082 | colour-classed summary line | `#validation_issues_summary` | AT-082d | ☐ |
| US-082 | zero-issues → 0/0/0, empty bars, no crash | `#screen_issues` | AT-082e | ☐ |
| US-082 | hostile issue `symbol`/`message`/`code` renders literal | `#validation_issues_groups` | AT-082f **GATE** (C-17) | ☐ |
| US-083 | key `9` + palette activate `#screen_checks`, hide others, set rail marker | rail + `#screen_checks` | AT-083a **GATE** (C-10) | ☐ |
| US-083 | activating another screen hides `#screen_checks` | rail | AT-083b | ☐ |
| US-083 | post-run grouped fail→uncheckable→pass, correct colours | `#checks_grouped` (via real `#patch_checks_run_button`) | AT-084a **GATE** (C-12) | ☐ |
| US-083 | aggregate strip counts == `check_aggregates()` | `#checks_aggregate_strip` | AT-084b **GATE** (C-31) | ☐ |
| US-083 | fail-row select shows bytes at `address_start` | `#checks_hex_pane` | AT-084c **GATE** (C-12) | ☐ |
| US-083 | no-file → EmptyStatePanel | `#screen_checks` | AT-084d | ☐ |
| US-083 | file + no-run → "no check run yet" note (≠ 0/0/0) | `#screen_checks` | AT-084e | ☐ |
| US-083 | undo/redo clears list + strip | `#screen_checks` | AT-084f | ☐ |
| US-083 | hostile `linkage_symbol`/`reason` renders literal | `#checks_grouped` | AT-084g **GATE** (C-17) | ☐ |

**Functional chain (white-box) — per requirement:**

| Requirement | Method | Test Case (`TC-NNN`) | Notes |
|-------------|--------|----------------------|-------|
| HLR-082 | test (pilot) | AT-082a…f | screen-level behavioral |
| LLR-082.1 | test (unit) | TC-082.1 | strip helper counts + bar math |
| LLR-082.2 | test (integration) | TC-082.2 | strip mount/drive; 2-digit-count width analysis |
| LLR-082.3 | test (unit) | TC-082.3 | glyph map per severity |
| LLR-082.4 | inspection | TC-082.4 | border-title + summary CSS class / no hard-coded hex |
| LLR-082.5 | test (unit) | TC-082.4 | summary `.plain` unchanged + styled spans |
| LLR-082.6 | test (pilot) | AT-082f | C-17 hostile-input |
| HLR-083 | test (pilot) | AT-083a, AT-083b | rail nav |
| LLR-083.1 | test/inspection | TC-083.1 | rail 9th entry + `EXPECTED_RAIL`/`== 9` updates (C-26) |
| LLR-083.2 | test | TC-083.2 | `SCREEN_CONTAINER_IDS` 9 entries |
| LLR-083.3 | test | TC-083.3 | binding `9` + palette |
| LLR-083.4 | test | TC-083.4 | compose mounts `#screen_checks` hidden |
| LLR-083.5 | test | TC-083.4 | scaffold ids present |
| LLR-083.6 | test | TC-083.5 | nav refresh hook |
| HLR-084 | test (pilot) | AT-084a…g | screen render/hex/empty |
| LLR-084.1 | test (unit) | TC-084.1 | grouped panel order + colours |
| LLR-084.2 | test (unit) | TC-084.2 | `check_display_rows` address preserved, `[]` when None |
| LLR-084.3 | test | TC-084.3 | `update_checks_view` groups + counts |
| LLR-084.4 | test (unit) | TC-084.4 | aggregate strip == `check_aggregates()`; 0 after undo |
| LLR-084.5 | test | TC-084.5 | hex peek address resolution + headless no-op |
| LLR-084.6 | test | TC-084.6 | 3 distinct empty/run states |
| LLR-084.7 | test | TC-084.7 | run/undo/redo refresh, no stale rows |
| LLR-084.8 | test (pilot) | AT-084g | C-17 hostile-input |
| (consumer guard) | test | TC-084.9 | direct `last_check_result` injection — IN ADDITION to AT-084a, never the gate (C-12) |
| LLR-084.1 (DoS) | test/analysis | TC-084.10 | mounted `CheckRow` count ≤ the `_GROUP_DISPLAY_MAX`-style cap for an oversized run (>cap entries); cap constant cited (MIN-3) |
| LLR-084.5 (boundary) | test | TC-084.11 | select an **uncheckable** row (`0x9000`, outside image, `actual_bytes=None`) → hex pane shows the address window/placeholder, no crash (MIN-6) |

### 5.3 Batch acceptance criteria
- 100% of LLRs (082.1-.6, 083.1-.6, 084.1-.8) covered by ≥1 passing `TC-NNN`.
- Every user story has ≥1 passing `AT-NNN` observing its outcome through the shipped surface, with boundary + negative evidence; all 8 gate-blocking ATs (082a, 082c, 082f, 083a, 084a, 084b, 084c, 084g) pass.
- 0 engine-frozen diffs (source AND test) — C-27 dual-guard green (`test_engine_unchanged.py`/`test_tc031`, `test_tc032`).
- Full gate suite `pytest -q -m "not slow"` green (baseline count measured at Phase-3 entry); no cross-increment regression (C-26 reverse-census clean).
- Snapshot baselines regenerated in canonical CI only; no local regen.
- 0 modal `should`/`may` inside any HLR/LLR statement.

---

## 6. Appendices (optional)

### 6.1 Extended glossary
See §1.3.

### 6.2 Relevant design decisions
- **D-1 CHECKS data source = read-only mirror of `last_check_result`** (option 1 of the recon verdict). Checks are not computed on load — the honest empty state is "no check run yet". Rejected: compute-on-open (needs a loaded check document; adds behavior) and a `_check_results` app mirror (redundant with the service singleton).
- **D-2 Grouped display accessor on the service, not `entries` read in `app.py`.** New `check_display_rows()` + `CheckDisplayRow` keeps `app.py` thin and the widget engine-free (CLAUDE.md "prefer extending a service"); the flat `check_rows()` lacks address + grouping.
- **D-3 Rail append at key `9`** (order …flow, checks) — avoids renumbering keys 6-8 (muscle memory + test churn). Accepts a large one-time snapshot regen (C-30 sequenced in its own increment).
- **D-4 Lazy nav-refresh** for the CHECKS screen (no load-pipeline hook) — checks state never changes on file load, only on run/undo/redo, which already have refresh sites.
- **D-5 Rail glyph `☑`/ascii `C`** — `✓` avoided (collides with `GLYPH_PASS`). Cosmetic; may be retuned in a `tui-design` pass.

### 6.3 Open risks
- **R-1 (verified clear):** no engine-frozen file touched. All CHECKS data lives in `changes/model.py` + `services/change_service.py` (both non-frozen); only `css_class_for_severity`/`_CHECK_RESULT_SEVERITY` are read. ✓
- **R-2 (C-26 collision, MUST handle in Inc-3) — census (architect-verified complete set):** breaking assertions in `test_tui_directionb.py`: `EXPECTED_RAIL` **definition** to extend to 9 entries at **:449**; `positions == [1,2,3,4,5,6,7,8]` in `test_tc001_rail_composes_eight_ordered_items` at **:488** (HARD-FAILS at 9 — the census's original omission, now included); `== 8` count assertions at **:698/:741/:779/:881**; key-routing at **:493**. Non-breaking-but-must-extend for key-`9` coverage: the digit-strings `zip("12345678", …)` at **:506/:513** → `"123456789"` (zip truncates → silent key-9 coverage hole otherwise). All updated to 9 in Inc-3; the full-suite gate is the completeness backstop (A-2). Confirmed safe: `IssueGroupHeader` tests read `.severity_label`/`.issue_count` attrs (not the rendered string) and the summary test (:2215) is renderable-based.
- **R-3 (verify Inc-1):** `#validation_issues_summary` becomes a `Text` (was `str`) — confirm summary tests assert `.plain`/renderable, not `isinstance(..., str)`; adjust if any type-assert.
- **R-4 (styles):** `border_title` renders only with a CSS border — add border rules for `#issues_list_stack`/`#issues_hex_pane` + CHECKS ids in `styles.tcss` (`s19_app/tui/styles.tcss`).
- **R-5 (snapshot churn, C-30):** the 9th rail item redraws the rail on every screen's snapshot → large baseline delta; sequence the rail change (Inc-3) discretely; regen canonical-CI only.
- **R-6 (empty-state distinctness):** empty-state-2 (`last_check_result is None`) MUST render visibly distinct from a real 0/0/0 run (AT-084d/084e) — do not conflate `None` with an all-zero aggregate.
- **R-7 (non-blocking):** `EmptyStatePanel` has fixed `id="empty_state_panel"` but `_apply_empty_state` queries it scoped per-screen (`app.py:5012`) — a second instance in `#screen_checks` is safe (never siblings); noted so Phase-2 doesn't flag a duplicate-id false positive.
- **R-8 (assumption):** all CHECKS reads assume the single `ChangeService` at `app.py:1176`; consistent with existing `check_rows()`/`check_aggregates()` call sites.

### 6.4 Phase-1 reconciliation log
| Decision ID | What changed | Parent HLR re-read? | Body edit landed? |
|---|---|---|---|
| REC-1 | Pinned canonical AT registry: qa folded CHECKS ATs under US-083 (083a-f); architect split HLR-083/084. Reconciled to HLR-083→AT-083a/b (nav) + HLR-084→AT-084a-g (render/hex/aggregate/empty/C-17). | HLR-083/084 re-read — nav vs render split is cleaner; both Acceptance blocks updated. | §3 HLR-083 Acceptance (AT-083a/b), HLR-084 Acceptance (AT-084a-g); §5.2 behavioral table. |
| REC-2 | qa's AT-083b (post-run grouped+aggregate) split into AT-084a (grouping/colour) + AT-084b (aggregate strip) for one-node-per-AT (C-18). | HLR-084 — no threshold change. | §3 HLR-084 Acceptance; §5.2 rows. |
| REC-3 | Phase-2 folds (0 blockers, 3 major + 9 minor): AT-082a asymmetric+independent oracle (MAJ-1); AT-082f/AT-084g plain-verbatim+`spans==[]`+dual-token payload (MAJ-2); R-2 census + LLR-083.1 add `:488`/`:506`/`:513`/`:449` (MAJ-3); LLR-084.8 `+reason` (MIN-1); LLR-084.2 `text` field pin (MIN-2); TC-084.10 mount cap (MIN-3); LLR-082.1 `SEVERITY_ORDER` note (MIN-4); AT-084c address discriminator (MIN-5); TC-084.11 uncheckable hex (MIN-6); cosmetic cites `:103`/`:1768`/TC-082.4 (MIN-7/8/9). | No HLR threshold changed — all folds tighten AT/LLR precision, not requirement intent; HLR-082/083/084 statements unchanged. | §3 HLR-082/084 Acceptance; §4 LLR-082.1/082.2/082.4/083.1/084.2/084.8; §5.2 TC-084.10/.11; §6.3 R-2. |

### 6.5 Requirement amendments (Before / After · Deleted / New)

**AMD-1 (Inc-2, 2026-07-18) — `CheckDisplayRow` gains a 5th optional field.**
- **Before:** `CheckDisplayRow(result, address, text, css_class)` (4 fields) — but LLR-084.2/084.1 also required `linkage_symbol` "carried separately for its own cell" and the C-17 seed asserts the linkage payload renders verbatim. Inconsistent: nothing carried linkage to the widget.
- **After:** `CheckDisplayRow(result, address, text, css_class, linkage_symbol: Optional[str] = None)` — 5th field, **optional/backward-compatible** (the 4 pinned positional fields unchanged; `CheckDisplayRow(result, address, text, css_class)` still constructs).
- **New:** field `linkage_symbol` on `CheckDisplayRow`. **Deleted:** none.
- **Parent-HLR re-read:** HLR-084 statement unchanged (it already requires the file-derived `linkage_symbol` render C-17-safe, LLR-084.8) — no threshold change; the amendment removes an internal LLR self-contradiction, it does not change requirement intent.
- **Re-derived TC/AT:** TC-084.2 (accessor) now also asserts `.linkage_symbol` round-trips; the widget-level C-17 seed (Inc-2) + AT-084g (Inc-4) cover its safe render. Surfaced by `software-dev` per Rule 7/12 (fail-loud), ratified by orchestrator.

**AMD-2 (Inc-4, 2026-07-18) — AT-084c discriminator = the 16-byte-aligned base, not the literal `0x102`.**
- **Before:** AT-084c asserts `"102"`/`"0x00000102"` appears in `#checks_hex_pane`.
- **After:** AT-084c asserts the aligned row label `"0x00000100"` appears (the fail entry `0x102` renders inside the row labelled by its 16-byte-aligned base `0x100`). `render_hex_view_text` labels rows by their aligned base, so `0x102` is never emitted as text (verified empirically by `software-dev`, Rule 7/12).
- **New:** the discriminator token `0x00000100`. **Deleted:** the `0x102`-literal expectation.
- **Parent-HLR re-read:** HLR-084 statement unchanged ("a focused hex+ASCII window around that entry's `address_start`") — the aligned base IS that window's label; no intent change. The discriminator is not weaker: it is present only when the address resolves to the `0x102` neighbourhood and absent on the placeholder/no-op RED state (counterfactual captured), and **TC-084.11 cross-checks** that selecting the `0x9000` uncheckable row instead yields `0x00009000` — so the pair proves the pane reflects the SELECTED row's address, not a fixed window.
- **Re-derived TC/AT:** AT-084c (`0x00000100`) + TC-084.11 (`0x00009000`) — the two together are the address-discrimination oracle.
