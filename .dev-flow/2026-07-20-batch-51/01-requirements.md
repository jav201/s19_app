# Requirements Document — s19_app — Batch 2026-07-20-batch-51

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
Specify batch-51 of the Flow Builder: the first slice of the operator-specified pipeline over the
shipped tracer (`SOURCE → PATCH → WRITE-OUT`). This batch adds (a) a **LOAD** behaviour on the SOURCE
block that surfaces image-integrity findings as advisory WARN notices without aborting the chain,
(b) a read-only **CHECK** block with per-block gating under a chain-never-blocked invariant, (c) a
whole-flow **`completed-with-issues`** (amber) status distinct from `failed`, and (d) the Direction A
"Pipeline Ledger" render of the Flow Builder screen. The document is normative (IEEE 830 + EARS) and
drives Phase-2 review, Phase-3 implementation, and Phase-4 validation.

### 1.2 Scope
**Covers:** integrity notices on load (US-085); a CHECK block that reports address presence/absence
and passes the image through unchanged (US-086); the `notices` block status, the
`completed-with-issues` flow status, and the flow-status roll-up (US-087); the vertical block-node
"Pipeline Ledger" render with per-block status gutter, block separators, twin memory ribbon, and a
CLEAN/ISSUES/FAILED banner (US-088). All new code lives in `flow_model.py`,
`flow_execution_service.py`, `screens_directionb.py`, `app.py`, `styles.tcss`, and new test files.
**Does NOT cover** (see §2.4): the CRC block (batch-52), `flow.json` persistence + external-file
import + variant reuse (batch-53), and any edit to a frozen engine module.

### 1.3 Definitions, acronyms, abbreviations
| Term | Definition |
|------|------------|
| Flow / block | An ordered list of typed blocks (`SourceBlock`/`PatchBlock`/`WriteOutBlock`/`CheckBlock`) executed by `run_flow` over a working `(mem_map, ranges)` pair. |
| Working image | The `(mem_map, ranges)` pair threaded through the blocks; seeded by SOURCE, mutated by PATCH, read (never mutated) by CHECK, emitted by WRITE-OUT. |
| Notice (WARN finding) | An advisory, non-aborting finding attached to a block; does not break the working image or halt the chain. |
| STOP | An image-breaking failure (unresolvable/unopenable image, failed patch, failed write) → block `error`, chain aborts, downstream `skipped`. |
| Advisory vs gate (CHECK) | `advisory` (default): a CHECK finding never changes any status beyond informational. `block-own-op`: an INVALID CHECK OPERATION marks **only the CHECK block itself** `error` — the CHAIN is never blocked either way. |
| CLEAN / ISSUES / FAILED | Flow outcomes `ok` / `completed-with-issues` (amber) / `error`. ISSUES = output produced + ≥1 advisory + image intact; FAILED = image broken (no/partial output). |
| Twin memory ribbon | A fixed-width cell strip rendering the working image's address footprint, with a `before` row for contrast. |
| `sev-*` | The frozen CSS severity classes (`.sev-ok/.sev-warning/.sev-error/.sev-neutral`, `styles.tcss:529-545`); the render maps block/flow status onto them (never edits `color_policy.py`). |

### 1.4 References
- `PLAN.md` (this batch) · `prototypes/flow_builder.NOTES.md` (operator decisions 2026-07-19) ·
  `prototypes/flow_builder.prototype.py` (state model) · `prototypes/flow_builder.screen.prototype.html`
  (Direction A) · `.fast-dev-flow/ADR-flow-builder-tracer.md` (§2 state model, §5 rail-8 wiring, §7 CRC seam — OUT).
- REQUIREMENTS.md (`R-TUI-059` tracer baseline; highest existing id `R-TUI-084`).
- Reused non-frozen seams: `run_check_document` (`s19_app/tui/changes/check.py:194`),
  `build_loaded_s19/hex` (`s19_app/tui/services/load_service.py:18/89`), `read_change_document`
  (imported at `flow_execution_service.py:34`).

### 1.5 Document overview
§2 gives the product context, constraints, and the four READY source stories (US-085..088). §3 states
the high-level requirements `R-TUI-085..088` (one per story) with black-box Acceptance blocks. §4
decomposes them into low-level requirements `LLR-085.*..088.*`. §5 gives the dual-traceability tables
(behavioral `US→AT`, functional `US→HLR→LLR→TC`) and the batch acceptance criteria. §6 carries the
reconciliation log, design decisions, and open risks.

---

## 2. Overall description

### 2.1 Product perspective
The Flow Builder is rail-8 of the S19 TUI (`S19TuiApp`). The shipped tracer (`R-TUI-059`, batch-44)
composes `SOURCE→PATCH→WRITE-OUT` blocks; `flow_execution_service.run_flow` (`flow_execution_service.py:59`)
threads a working `(mem_map, ranges)` pair through them with collect-don't-abort, per-block isolation,
and `len(block_results) == len(flow.blocks)`. Batch-51 extends that keel: the SOURCE load step gains
notice-emission, a new CHECK block reuses the read-only `run_check_document` engine, the status model
gains `notices`/`completed-with-issues`, and the `FlowBuilderPanel` (`screens_directionb.py:2075`)
render is upgraded to Direction A. The app already wires Run → `run_flow` → `render_result`
(`app.py:1958-1976`).

### 2.2 Product functions
- **F1 — LOAD integrity notices:** on SOURCE load, surface parser-collected per-record `errors` as
  advisory WARN notices; `notices` block status; chain continues. Unopenable image = STOP.
- **F2 — CHECK block (read-only):** resolve + read a check document, run `run_check_document` against
  the working image WITHOUT mutating it, attach the report, pass the image through unchanged; per-block
  gating flag (`advisory` default | `block-own-op`) affecting ONLY the CHECK block's own status.
- **F3 — status model + roll-up:** `BLOCK_STATUS_NOTICES` + `FLOW_STATUS_ISSUES`
  (`completed-with-issues`); three-way flow roll-up FAILED / ISSUES / CLEAN; the token rides the
  `FlowRunResult.status` carrier consumed by any report/summary.
- **F4 — Direction A render:** vertical block-node pipeline, per-block status gutter (`sev-*`), block
  separators (`$rule`), twin memory ribbon, CLEAN/ISSUES/FAILED banner; markup-safe throughout.

### 2.3 User characteristics
Single role: the **flow author / engineer** (embedded-firmware technician) already using the TUI. No
new permission surface. Expected to read the pipeline top-to-bottom and decide themselves whether a
warned image is acceptable — the tool informs, it does not gate (operator's "notify, don't block").

### 2.4 Constraints
- **FROZEN — do NOT edit** (C-27 dual-guard, re-frozen batch-50 PR #100): `core.py`, `hexfile.py`,
  `range_index.py`, `validation/`, `tui/mac.py`, `tui/color_policy.py`, `tui/a2l.py`, and the frozen
  TEST files. Batch-51 code lives ONLY in `services/flow_model.py`,
  `services/flow_execution_service.py`, `screens_directionb.py`, `app.py`, `styles.tcss` + new
  files/tests — none frozen. Frozen modules are **read** (`S19File.get_errors`/`IntelHexFile.get_errors`,
  the `.sev-*` classes) but never edited.
- **≤5 files per increment.** No abstraction not derivable from an approved LLR.
- **C-17 markup-safety:** CHECK reports + LOAD integrity messages carry file-derived strings → render
  `markup=False` / `safe_text`; an AT drives a hostile bracket/ANSI payload (AT-088b).
- **`sev-*` classes are frozen** (`color_policy.py`) — the render only USES `.sev-ok/.sev-warning/`
  `.sev-error/.sev-neutral`; the status→class map lives in `screens_directionb.py` (not the frozen file).
- **Snapshot drift** (project C-22/C-28/C-30): the Direction A render changes `#screen_flow` cells →
  expect drift → **canonical-CI regen follow-up** (local regen FORBIDDEN). Rail unchanged (Flow = rail-8).
- **Geometry** (project C-13/C-23/C-29): the ribbon + node columns MUST be pilot-measured in the real
  boxed panel at 80×24 AND wider; do NOT inherit the HTML prototype's width budget (C-16).
- **OUT of scope:** CRC block (batch-52); `flow.json` save/load + external-file→import + variant reuse
  (batch-53); PKI binary-region extraction · CRC-as-sub-flow · multi-image scope (backlog).

### 2.5 Assumptions and dependencies
- **A1 (verified):** `build_loaded_s19/hex` return a `LoadedFile` whose `.errors` is the parser's
  per-record error list (`load_service.py:76` `s19.get_errors()`; `:116` `hex_file.get_errors()`), and
  `S19File.get_errors()`/`IntelHexFile.get_errors()` return `List[dict]` with keys `line`/`segment`/`error`
  (`core.py:369-374`, `hexfile.py:173-174`). Parsers collect-don't-abort — assumption holds.
- **A2 (verified):** `run_check_document(document, mem_map, ranges, mac_records, a2l_tags, *, now_fn,
  variant_id) -> CheckRunResult` is pure and does NOT mutate `mem_map` (`check.py:194`, contract at
  `check.py:210/223`). `CheckRunResult.aggregates` has keys `passed`/`failed`/`uncheckable`
  (`model.py:571,744`). `read_change_document(str(path), project_dir)` is already imported
  (`flow_execution_service.py:34`).
- **A3 (verified):** the `FlowBuilderPanel.render_result` seam (`screens_directionb.py:2187`) already
  renders every dynamic string via `safe_text` + `markup=False` (`:2147,2153,2161,2193,2197`); the app
  wires Run → `run_flow` → `render_result` (`app.py:1958-1976`), passing `FlowContext(project_dir=...)`
  only (mac_records/a2l_data default `None` — CHECK linkage classification is informative-only, so a
  `None` context is acceptable for batch-51).
- **A4 (assumption — batch scope):** there is NO separate flow-run **report file** artifact in the
  codebase; `run_flow` returns only `written_paths` (the WRITE-OUT files). Therefore "any generated
  report/summary" in US-087 resolves to (a) the machine-readable `FlowRunResult.status` token carrier,
  and (b) the rendered CLEAN/ISSUES/FAILED banner (US-088). If a flow-report **file** is later added,
  it inherits the same token by construction. Flagged so Phase-2 does not expect a report-file deliverable.
- **A5 (verified):** the `$rule` divider token (`styles.tcss:30`) exists and is already used for borders
  — LLR-088.3's separator tone is a fact, not an assumption.

### 2.6 Source user stories

> Connextra format: **"As a `<role>`, I want `<goal>`, so that `<benefit>`"**. Each US gets a unique ID `US-NNN` and must be traceable to one or more HLRs.
> **Phase 0 — Definition of Ready (INVEST):** every story is refined and classified before it can be derived into HLR (Phase 1). Only `READY` stories proceed.

| ID | User Story | Source | DoR status |
|----|------------|--------|------------|
| US-085 | As an engineer composing a flow, I want a **LOAD** block that surfaces image-integrity findings as advisory notices without aborting the flow, so that I'm informed of a suspect image but decide myself whether to proceed. | operator 2026-07-19 + prototype | **READY** |
| US-086 | As an engineer, I want a read-only **CHECK** block (address-list) that reports which addresses are present in the working image and passes the image through unchanged, so that I can verify coverage mid-flow without altering the artifact. | operator 2026-07-19 + prototype | **READY** |
| US-087 | As an engineer, I want a flow-level outcome of **CLEAN / ISSUES / FAILED** where ISSUES ("completed-with-issues") means output was produced *with* advisories (distinct from FAILED = no/broken output), reflected in any generated report, so that I can tell "shipped with warnings" from "did not ship". | operator 2026-07-19 + prototype | **READY** |
| US-088 | As an engineer, I want the Flow Builder screen to render the flow as a **vertical block-node pipeline** with a per-block status gutter, block separators, and a **twin memory ribbon**, so that I read each block as a discrete object and see the working image's footprint at a glance. | operator 2026-07-19 + prototype (Direction A) | **READY** |

#### Refinement log (one block per story)

**US-085 — LOAD integrity-notices (notify, don't block)**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):** user = flow author · outcome = a LOAD block for an image with integrity issues (bad checksum lines, out-of-order records) shows those as **WARN notices** and the flow still runs; only an unresolvable/unopenable image is a **STOP** that breaks the image and skips downstream · why = the operator's "notify, don't block" — the load informs, it does not gate subsequent blocks · out of scope = external-file→import (batch-53), CRC.
- **Feasibility (E, S):** path = extend `SourceBlock`→LOAD in `flow_model.py` + surface `S19File/IntelHexFile` per-record `errors` (already collected by the parsers) as `Finding(WARN)` in `flow_execution_service.py`; add the `notices` block status · dependencies = `build_loaded_s19/hex` (load_service, not frozen); the parsers already collect-don't-abort · fits one batch = yes (Inc-1).
- **Evaluability (T):** When a flow with a LOAD block over an integrity-flagged image is run through the shipped Run surface, the user observes the block status = `notices` with the WARN finding text, and downstream blocks still execute (→ `AT-085a`); when the image is unresolvable, the block status = `error`/STOP and downstream = `skipped` (→ `AT-085b`).
- **Open questions:** none blocking. (Which parser errors map to WARN vs STOP is an LLR detail — Phase 1.)
- **Classification:** **READY**.

**US-086 — CHECK block (read-only, pass-through, per-block gating)**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):** user = flow author · outcome = a CHECK block (address-list json) produces a present/absent **report** and passes the working image through **unchanged** to downstream; a CHECK finding is **advisory** (chain continues) by default; a per-block **gating flag** can mark the *block itself* blocked when *its own operation* is invalid (e.g. unreadable check-doc) — **the CHAIN is never blocked** · why = verify coverage mid-flow without mutating the artifact · out of scope = CRC, gating that halts the whole chain.
- **Feasibility (E, S):** path = new `CheckBlock` in `flow_model.py`; reuse `run_check_document` (`tui/changes/check.py:194`, not frozen) in `flow_execution_service.py`; image passes through (read-only shape from ADR §2) · dependencies = `run_check_document` signature (verify at draft time, C-15) · fits one batch = yes (Inc-1).
- **Evaluability (T):** When a flow LOAD→CHECK→WRITE-OUT is run, the user observes a check report (present/absent counts) AND the WRITE-OUT still produces the same image bytes as without the CHECK (pass-through) (→ `AT-086a`); when the check-doc is unreadable, the CHECK block is marked errored but downstream WRITE-OUT **still runs** (image intact) (→ `AT-086b`, the abort-asymmetry).
- **Open questions:** exact per-block gating vocabulary surfaced to the user — Phase 1 must spec it with maximum clarity (operator emphasis: highly user-visible).
- **Classification:** **READY**.

**US-087 — status model + completed-with-issues (amber)**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):** user = flow author · outcome = whole-flow status is **CLEAN** (all ok) / **ISSUES** = *completed-with-issues* (output produced + ≥1 advisory) / **FAILED** (image broken → no/partial output); the amber ISSUES outcome **appears in any generated report** · why = distinguish "shipped with warnings" from "did not ship" · out of scope = report-format redesign.
- **Feasibility (E, S):** path = add `FLOW_STATUS_ISSUES`/`completed-with-issues` + `BLOCK_STATUS_NOTICES` to `flow_model.py`; roll-up logic in `flow_execution_service.py` (notices present + no image-break → ISSUES) · dependencies = US-085/086 produce the notices · fits one batch = yes (Inc-1) + surfaced by US-088 (Inc-2).
- **Evaluability (T):** When a flow that produces output but carries advisories is run, the flow status = `completed-with-issues` (amber), distinct from a broken-image run = `failed` (→ `AT-087a`); a fully clean run = `ok`/CLEAN (→ `AT-087b`, boundary).
- **Open questions:** none. (Report-text wording is an LLR detail.)
- **Classification:** **READY**.

**US-088 — Direction A "Pipeline Ledger" UI**
- **INVEST:** I ✓ (depends on US-085..087 data) · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):** user = flow author · outcome = `#screen_flow` renders the flow as a **vertical block-node pipeline** (one row per block, flow order) with a per-block **status gutter** (`sev-*` colored ok/notices/error/skipped), **block separators** (Rule between blocks), and a **twin memory ribbon** (working image footprint; `before` row for contrast), plus a flow-status banner CLEAN/ISSUES/FAILED · why = read each block as a discrete object + see the image footprint · out of scope = CRC ribbon-growth, Save/Load controls.
- **Feasibility (E, S):** path = extend `FlowBuilderPanel` (`screens_directionb.py:2075`) render (it already uses `safe_text`); add CHECK/LOAD to the add dropdown; `styles.tcss` sep/ribbon/banner classes · dependencies = the Inc-1 `FlowRunResult` shape; geometry pilot-measure at 80×24 (C-13/C-23); prototype interactions are HTML-only (C-16 — verify in Textual) · fits one batch = yes (Inc-2).
- **Evaluability (T):** When a flow is run through the shipped panel, the rendered screen shows one node per block with the correct `sev-*` status class, a separator between blocks, the ribbon, and the CLEAN/ISSUES/FAILED banner matching the run (→ `AT-088a`); a hostile file-derived check/notice string renders literally (no markup parse / style leak) (→ `AT-088b`, C-17).
- **Open questions:** exact ribbon cell budget at 80×24 — pilot-measure in Phase 3 (R-5).
- **Classification:** **READY**.

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

### R-TUI-085 (HLR) — LOAD integrity notices (notify, don't block)
- **Traceability:** US-085
- **Statement:** When a SOURCE (LOAD) block loads an image whose parser collected per-record load
  errors, the system shall record each as a **WARN-severity Finding** on the block, set the block
  status to `notices`, and continue executing downstream blocks with the working image intact. **If**
  the source image is unresolvable or unopenable, **then** the system shall set the block status to
  `error` (STOP), leave the working image unset, and mark every downstream block `skipped`.
- **Rationale (informative):** the operator's "notify, don't block" — the load informs the author of a
  suspect image (bad checksum lines, out-of-order records) but does not gate subsequent blocks; only a
  genuinely absent/unreadable image can break the chain (there is no image to thread).
- **Validation:** `test`
- **Executed verification:** `pytest -q tests/test_flow_execution_service.py -k "notices or load_integrity"`
  (headless engine) **and** the black-box `AT-085a`/`AT-085b` pilot (§5.2).
- **Numeric pass threshold:** all selected TCs pass (exit 0); AT-085a asserts SOURCE `status=="notices"`
  with ≥1 WARN finding **and** downstream block executed; AT-085b asserts SOURCE `status=="error"` and
  every downstream `status=="skipped"`.
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** running a flow whose SOURCE targets an integrity-flagged image shows that
    block as `notices` with the warning text, and downstream blocks still run and still produce their
    output; an unresolvable image shows the block errored and every downstream block skipped.
  - **Shipped surface:** `FlowBuilderPanel` Run → `S19TuiApp.on_flow_builder_panel_run_requested`
    (`app.py:1958`) → `run_flow` → `render_result` (`screens_directionb.py:2187`).
  - **Deliverable + observation:** the rendered `#flow_result`/pipeline shows the SOURCE node status
    class + notice text (rendered element); for the STOP case the WRITE-OUT produces **no** file
    (`FlowRunResult.written_paths` empty) and the node reads `skipped`.
  - **Acceptance test(s):** `AT-085a` (notices + downstream runs), `AT-085b` (STOP + downstream skipped).
    Both drive the shipped panel/handler, assert the observed outcome, reference no internal symbol,
    and FAIL if notices are silently dropped or the chain silently aborts.
  - **Boundary catalog (QC-3):** ☑ empty (image with zero errors → `ok`, no notices — AT-087b/TC) · ☑
    boundary (exactly one parser error → `notices` with one finding — TC-085.x) · ☑ invalid (many
    errors → notices, chain still runs — AT-085a) · ☑ error (unresolvable/unopenable image → STOP,
    downstream skipped — AT-085b).

### R-TUI-086 (HLR) — CHECK block (read-only, per-block gating, chain-never-blocked)
- **Traceability:** US-086
- **Statement:** When a CHECK block runs, the system shall resolve and read its referenced check
  document, execute `run_check_document` against the working image **without mutating** `mem_map` or
  `ranges`, attach the resulting report (present/absent aggregates) to the block, and thread the
  **unchanged** working image to downstream blocks. While the block's gating flag is `advisory`
  (default), a check finding shall not change any status beyond informational. While the flag is
  `block-own-op`, an invalid CHECK operation (an unresolvable or unreadable check document) shall mark
  **only the CHECK block itself** `error`. **In all cases the CHAIN shall never be aborted by a CHECK
  block** — downstream blocks shall always execute and the working image shall remain intact.
- **Rationale (informative):** verify coverage mid-flow without mutating the artifact ("output None,
  pass s19 along"). The gating flag captures the real "patch → verify → then write" intent while the
  operator's non-negotiable invariant — the chain is never blocked — is preserved: a block may mark
  *itself* blocked, never the chain. These rules are highly user-visible, so they are specified with
  maximum clarity (LLR-086.4).
- **Validation:** `test`
- **Executed verification:** `pytest -q tests/test_flow_execution_service.py -k "check"` (headless) +
  the black-box `AT-086a`/`AT-086b` pilot.
- **Numeric pass threshold:** all selected TCs pass (exit 0); AT-086a asserts the CHECK report is
  present AND the WRITE-OUT bytes are byte-identical to a run WITHOUT the CHECK block (pass-through);
  AT-086b asserts an unreadable check-doc marks the CHECK block `error` while the downstream WRITE-OUT
  still runs and still produces its file (image intact).
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** a `LOAD→CHECK→WRITE-OUT` flow shows a CHECK node with present/absent
    counts, and the written image is identical to the same flow without the CHECK; when the check-doc
    is unreadable the CHECK node reads errored but the WRITE-OUT node still produces its file.
  - **Shipped surface:** `FlowBuilderPanel` Run → `run_flow` → `render_result` (as R-TUI-085).
  - **Deliverable + observation:** the WRITE-OUT file under the work area (path in
    `FlowRunResult.written_paths`, non-empty, byte-equal across the with/without-CHECK runs) + the
    rendered CHECK node showing its aggregate counts / errored state.
  - **Acceptance test(s):** `AT-086a` (pass-through + report present), `AT-086b` (abort-asymmetry:
    CHECK own-op error, downstream still runs), **`AT-086c` (gating `block` non-default — the
    hidden-chain-kill guard, added Phase-1 per qa audit)**. Drive the shipped surface; FAIL if the
    CHECK mutates the image or if a CHECK failure silently aborts the chain.
  - **`AT-086c` (Coverage — the gating flag's non-default value drives an OBSERVABLE change, C-10 + R-3):**
    run the SAME flow with an **unreadable/unresolvable check-doc** (per LLR-086.4/086.5 the ONLY input on
    which the gating flag changes the CHECK block's status) **twice** through the shipped Run surface —
    once with `gating = CHECK_GATING_ADVISORY` (default), once with `gating = CHECK_GATING_BLOCK_OWN`
    (the real non-default token; NOT a phantom `"block"`). Assert: **(a)** the CHECK `BlockResult.status`
    **differs** between the two runs — `notices` under advisory vs `error` (→ `sev-error`, not a phantom
    "blocked" token) under block-own-op — which proves *driving the flag* caused the change (an impl that
    ignored the flag shows the SAME status both times → RED); **(b)** in BOTH runs the downstream
    WRITE-OUT **produces its file** (observable: `written_paths` non-empty) — the chain is never blocked.
    (`aborted` stays `False` in both — internal; asserted via the observable file-produced, not the field.)
    **Why AT-086b is insufficient:** it pins only the block-own-op→`error` branch on one input, so it
    cannot show the change was *caused by the flag* — it never drives the advisory baseline on the same
    input. Owner increment: **Inc-1** (engine gating); the distinct `sev-error` render asserted by AT-088a
    in Inc-2. (Entries-absent-but-readable is DROPPED from this AT — per LLR-086.4 it does not flip the
    status under either gating.)
  - **Boundary catalog (QC-3):** ☑ empty (check-doc with zero entries → report with all-zero
    aggregates, pass-through — TC-086.x) · ☑ boundary (all entries present → `passed>0,failed==0` —
    TC) · ☑ invalid (some entries absent → `failed>0`, advisory, chain runs — AT-086a variant) · ☑
    error (unresolvable/unreadable check-doc → CHECK `error` under `block-own-op`, chain runs —
    AT-086b) · ☑ **gating flag observable (SAME unreadable-doc: advisory→`notices` vs block-own-op→`error`,
    status differs, chain runs in both — AT-086c).**

### R-TUI-087 (HLR) — status model + completed-with-issues (amber)
- **Traceability:** US-087
- **Statement:** When a flow finishes, the system shall classify the whole-flow outcome as **FAILED**
  (`error`) if the working image was broken by an aborting LOAD/PATCH/WRITE-OUT failure; else as
  **ISSUES** (`completed-with-issues`) if output was produced with ≥1 advisory (a `notices` block, a
  non-aborting block `error`, a WARN finding, or a CHECK report with `failed > 0`); else as **CLEAN**
  (`ok`). The system shall carry the resulting token in `FlowRunResult.status` so that any generated
  report or summary reflects the amber ISSUES outcome distinctly from `failed`.
- **Rationale (informative):** distinguish "shipped with warnings" from "did not ship". The current
  two-way roll-up (`flow_execution_service.py:210-213`) collapses any block error to `error`; with the
  CHECK block's non-aborting error path that would wrongly flag a flow FAILED though it produced output
  — hence the three-way classifier.
- **Validation:** `test`
- **Executed verification:** `pytest -q tests/test_flow_execution_service.py -k "status_rollup or issues"`
  + black-box `AT-087a`/`AT-087b`.
- **Numeric pass threshold:** all selected TCs pass (exit 0); AT-087a asserts a run that produces
  output with advisories → `status=="completed-with-issues"` (distinct from a broken-image run →
  `"error"`); AT-087b asserts a fully clean run → `status=="ok"`.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** after a run, the author sees CLEAN / ISSUES / FAILED; ISSUES appears when
    output was produced with advisories, and is visibly different from FAILED (no/broken output).
  - **Shipped surface:** `FlowRunResult.status` (machine-readable) surfaced through the
    `render_result` banner (US-088). Per A4 there is no separate report **file**.
  - **Deliverable + observation:** the `FlowRunResult.status` token == `completed-with-issues` for the
    ISSUES case (asserted directly) AND the rendered banner text reads ISSUES (rendered element).
  - **Acceptance test(s):** `AT-087a` (ISSUES vs FAILED distinction), `AT-087b` (CLEAN boundary).
    FAIL if an advisory run is reported `ok` or `failed`.
  - **Boundary catalog (QC-3):** ☑ empty (empty flow / no blocks → `ok`, no advisories — TC) · ☑
    boundary (output produced + exactly one advisory → ISSUES — AT-087a) · ☑ invalid N/A (status is
    derived, not user-input — the inputs are covered by US-085/086) · ☑ error (aborting failure →
    FAILED, distinct from ISSUES — AT-087a negative side).

### R-TUI-088 (HLR) — Direction A "Pipeline Ledger" render
- **Traceability:** US-088
- **Statement:** When the Flow Builder panel renders a run result, the system shall display the flow
  as a **vertical block-node pipeline** (one node per block in flow order) with a per-block **status
  gutter** styled by the block-status→`sev-*` class map (`ok→sev-ok`, `notices→sev-warning`,
  `error→sev-error`, `skipped→sev-neutral`), a **horizontal separator** between nodes (a `Rule`/border
  of tone `$rule`), a **single memory ribbon** rendering the working image's address footprint (from
  `FlowRunResult.image_ranges`; the `before`/twin row is deferred to batch-52 per AMD-1), and a
  **flow-status banner** reading CLEAN / ISSUES / FAILED matching
  `FlowRunResult.status`. **If** any rendered string is file-derived (block refs, notice/check text,
  written paths), **then** the system shall render it markup-safe (`safe_text` / `markup=False`) so a
  hostile payload cannot inject markup or leak styling.
- **Rationale (informative):** the author reads each block as a discrete object and sees the image
  footprint at a glance; the banner makes the amber ISSUES outcome legible. Direction A was
  operator-chosen from the prototype.
- **Validation:** `test`
- **Executed verification:** Textual Pilot snapshot/interaction tests
  `pytest -q tests/test_flow_builder_render.py` (or the reconciled name) at 80×24 and a wider regime +
  `AT-088a`/`AT-088b`.
- **Numeric pass threshold:** all selected TCs pass (exit 0); AT-088a asserts one node per block with
  the correct `sev-*` class, a separator between nodes, a ribbon, and a banner matching the run;
  AT-088b asserts a hostile bracket/ANSI file-derived string renders literally (`Text.plain` verbatim,
  no injected span / no style leak).
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** the rendered `#screen_flow` shows the pipeline vertically, each node
    carrying its status colour, separators between nodes, the single memory ribbon, and the
    CLEAN/ISSUES/FAILED banner; a `[bold]`/ANSI-laden check/notice string appears as literal text.
  - **Shipped surface:** `FlowBuilderPanel.render_result` (`screens_directionb.py:2187`) driven via
    `App.run_test()` Pilot through the real Run button.
  - **Deliverable + observation:** the rendered screen (Pilot query of the node/gutter/ribbon/banner
    widgets + their `sev-*` classes and `Text.plain`).
  - **Acceptance test(s):** `AT-088a` (full Direction-A structure over a real run), `AT-088b` (C-17
    hostile payload rendered literally). FAIL if a node's status class is wrong or a payload parses.
  - **Boundary catalog (QC-3):** ☑ empty (no blocks / no run yet → empty-state text, no crash — TC) ·
    ☑ boundary (single-block flow → one node, no dangling separator — TC) · ☑ invalid (hostile
    file-derived string → rendered literally — AT-088b) · ☑ error (FAILED run → banner reads FAILED,
    skipped nodes `sev-neutral` — AT-088a variant). Ribbon cell budget at 80×24 is `assumed — verify
    per-regime in Phase 3` (R-5).

---

## 4. Low-level requirements (LLR)

> Each LLR decomposes an HLR into a verifiable property at the implementation level.
> Same EARS regime. ID format: `LLR-<HLR>.<M>`.

> **Symbol-citation note.** All `file:line` citations below were grep-verified against the worktree
> tree on 2026-07-20. Symbols to be created in Phase 3 are flagged `NEW`. Test file paths, `-k`
> selectors, and node ids are provisional-until-Phase-3 (V-5) and reconciled at Phase 4.

#### R-TUI-085 decomposition — LOAD integrity notices

### LLR-085.1 — Finding type + `notices` block status token
- **Traceability:** R-TUI-085
- **Statement:** The `flow_model` module shall define `BLOCK_STATUS_NOTICES = "notices"` (alongside the
  existing block-status tokens at `flow_model.py:32-35`), a frozen `Finding` dataclass with fields
  `severity: str` and `message: str`, a severity constant `FINDING_WARN = "warn"`, and shall add a
  `findings: List[Finding] = field(default_factory=list)` field to `BlockResult` (`flow_model.py:124`).
- **Validation:** `test (unit)`
- **Executed verification:** `pytest -q tests/test_flow_model.py -k "finding or notices"`
- **Numeric pass threshold:** exit 0; `BlockResult(...).findings == []` by default and a
  `Finding(FINDING_WARN, "x")` round-trips its fields.
- **Acceptance criteria:**
  - `BLOCK_STATUS_NOTICES`, `Finding`, `FINDING_WARN` are importable from `flow_model` (all `NEW`).
  - `BlockResult` gains `findings` without breaking `len(block_results)==len(flow.blocks)` (existing invariant).

### LLR-085.2 — Surface parser errors as WARN notices on SOURCE load
- **Traceability:** R-TUI-085
- **Statement:** When a `SourceBlock` loads successfully but the `LoadedFile.errors` list is non-empty,
  `run_flow` shall append one `Finding(FINDING_WARN, <message>)` per error to the SOURCE `BlockResult`
  (message derived from the error dict's `error`/`line` keys — `core.py:372`) and set that
  `BlockResult.status = BLOCK_STATUS_NOTICES` instead of `BLOCK_STATUS_OK`, WITHOUT setting `aborted`.
- **Validation:** `test (integration)`
- **Executed verification:** `pytest -q tests/test_flow_execution_service.py -k "load_integrity_notices"`
- **Numeric pass threshold:** exit 0; over a fixture image with ≥1 parser error, the SOURCE
  `BlockResult.status == "notices"`, `len(findings) == len(loaded.errors) ≥ 1`, and every downstream
  block ran (`status != "skipped"`).
- **Acceptance criteria:**
  - `loaded.errors` is read at the SOURCE-ok path (`flow_execution_service.py:126-139`); `mem_map`/
    `ranges` are still threaded downstream (image intact).
  - A zero-error image keeps `status == "ok"` with `findings == []` (boundary).

### LLR-085.3 — STOP / abort-asymmetry on an unresolvable image
- **Traceability:** R-TUI-085
- **Statement:** If a `SourceBlock`'s ref is unresolvable/missing (`_resolve_manifest_entry` returns
  `None` or the path does not exist — `flow_execution_service.py:115-120`) or `build_loaded_*` raises
  (the F5 boundary at `flow_execution_service.py:203-208`), then `run_flow` shall record the SOURCE
  `BlockResult` `status = BLOCK_STATUS_ERROR`, set `aborted = True`, leave `mem_map`/`ranges` unset,
  and every downstream block shall be `BLOCK_STATUS_SKIPPED`.
- **Validation:** `test (integration)`
- **Executed verification:** `pytest -q tests/test_flow_execution_service.py -k "source_stop_skips_downstream"`
- **Numeric pass threshold:** exit 0; SOURCE `status == "error"`, all downstream `status == "skipped"`,
  `written_paths == []`.
- **Acceptance criteria:**
  - The existing error path (`flow_execution_service.py:116`) is unchanged in shape; only the
    non-error notices path (LLR-085.2) is added — STOP behaviour is a regression guard.

#### R-TUI-086 decomposition — CHECK block

### LLR-086.1 — `CheckBlock` dataclass + gating vocabulary
- **Traceability:** R-TUI-086
- **Statement:** The `flow_model` module shall define `BLOCK_CHECK = "check"` (a `kind` discriminator
  alongside `flow_model.py:23-25`), a frozen `CheckBlock` dataclass with fields `check_doc_ref: str`,
  `gating: str = CHECK_GATING_ADVISORY`, and `kind: str = BLOCK_CHECK` (modelled on `PatchBlock`,
  `flow_model.py:57-68`), the gating constants `CHECK_GATING_ADVISORY = "advisory"` and
  `CHECK_GATING_BLOCK_OWN = "block-own-op"`, and shall add `CheckBlock` to the `FlowBlock` union
  (`flow_model.py:89`). All `NEW`.
- **Validation:** `test (unit)`
- **Executed verification:** `pytest -q tests/test_flow_model.py -k "check_block"`
- **Numeric pass threshold:** exit 0; `CheckBlock("d.json").gating == "advisory"` and
  `CheckBlock("d.json", gating=CHECK_GATING_BLOCK_OWN).kind == "check"`.
- **Acceptance criteria:**
  - `CheckBlock` is frozen + JSON-serialisable by shape (mirrors the other blocks for batch-53 persistence).

### LLR-086.2 — CHECK execution branch (read-only, report attached)
- **Traceability:** R-TUI-086
- **Statement:** When `run_flow` encounters a `CheckBlock` with a threaded working image, it shall
  resolve `check_doc_ref` via `_resolve_manifest_entry` (`flow_execution_service.py:149`), read it via
  `read_change_document` (imported `flow_execution_service.py:34`), execute
  `run_check_document(document, mem_map, ranges, ctx.mac_records, a2l_tags)` (`check.py:194`), and store
  the returned `CheckRunResult.aggregates` counts on the CHECK `BlockResult.summary` (e.g.
  `"passed=P failed=F uncheckable=U"`) — without reassigning `mem_map` or `ranges`.
- **Validation:** `test (integration)`
- **Executed verification:** `pytest -q tests/test_flow_execution_service.py -k "check_reports_counts"`
- **Numeric pass threshold:** exit 0; the CHECK `BlockResult.summary` contains the three aggregate
  counts; `mem_map`/`ranges` object identity is unchanged after the CHECK branch.
- **Acceptance criteria:**
  - The CHECK branch is inserted before the `else` unknown-kind guard (`flow_execution_service.py:198`).
  - `run_check_document` is called read-only (per its `check.py:210/223` contract) — no write to `mem_map`.

### LLR-086.3 — Read-only pass-through invariant
- **Traceability:** R-TUI-086
- **Statement:** After a `CheckBlock` executes, the working `(mem_map, ranges)` threaded to downstream
  blocks shall be byte-for-byte identical to the pair before the CHECK block, such that a downstream
  `WriteOutBlock` produces an identical file whether or not the CHECK block is present.
- **Validation:** `test (integration)`
- **Executed verification:** `pytest -q tests/test_flow_execution_service.py -k "check_passthrough_bytes"`
- **Numeric pass threshold:** exit 0; the WRITE-OUT file bytes for `LOAD→CHECK→WRITE-OUT` equal those
  for `LOAD→WRITE-OUT` (same input) — assert full byte equality.
- **Acceptance criteria:**
  - This is the black-box AT-086a mechanism; the TC asserts it white-box on the two written files.

### LLR-086.4 — Chain-never-blocked invariant + per-block gating (maximum clarity)
- **Traceability:** R-TUI-086
- **Statement:** A `CheckBlock` shall **never** set `aborted = True` — regardless of its gating flag or
  check outcome, `run_flow` shall continue to execute every downstream block and shall keep the working
  image intact. The gating flag shall affect ONLY the CHECK block's own `BlockResult.status`: under
  `CHECK_GATING_ADVISORY` the block is `ok` (or `notices` if the report carries `failed > 0`,
  informational) even when entries fail; under `CHECK_GATING_BLOCK_OWN` the block is set
  `BLOCK_STATUS_ERROR` **only** when its own operation is invalid (an unresolvable or unreadable check
  document), and even then `aborted` stays `False`.
- **Validation:** `test (integration)`
- **Executed verification:** `pytest -q tests/test_flow_execution_service.py -k "check_never_aborts_chain"`
- **Numeric pass threshold:** exit 0; across four cases — {advisory|block-own-op} × {failing entries |
  unreadable doc} — a downstream WRITE-OUT ALWAYS runs (`written_paths` non-empty) and `aborted` is
  never `True`; only the CHECK block's own status differs per the matrix above.
- **The 4-case gating matrix (tabulated — "maximum clarity", the ONE gating truth table):**

  | gating \ trigger | readable doc, entries fail | unreadable/unresolvable doc (own-op invalid) |
  |------------------|----------------------------|-----------------------------------------------|
  | `advisory` (default) | `notices` (`ok` if `failed==0`) · chain runs | `notices` (advisory "could not check") · chain runs |
  | `block-own-op` (non-default) | `notices` (`ok` if `failed==0`) — entries-fail is NOT own-op failure · chain runs | **`error`** (→ `sev-error`) · chain runs |

  In **all four** cells `aborted == False` and the downstream WRITE-OUT runs. The gating flag changes the
  CHECK block's own status **only in the bottom-right cell** (unreadable doc under `block-own-op` → `error`
  vs `advisory` → `notices`) — that single differing cell is what `AT-086c` drives and asserts. There is
  **no** distinct "blocked" status token; block-own-op resolves to `BLOCK_STATUS_ERROR`.
- **Acceptance criteria:**
  - The abort-asymmetry vs LOAD/PATCH (which DO set `aborted`, LLR-085.3) is explicit and tested.
  - No code path lets a CHECK finding reach the `aborted = True` assignment (`flow_execution_service.py:208`).

### LLR-086.5 — STOP-free CHECK error path (unreadable check-doc)
- **Traceability:** R-TUI-086
- **Statement:** If a `CheckBlock`'s `check_doc_ref` is unresolvable/unreadable, then under
  `CHECK_GATING_BLOCK_OWN` `run_flow` shall mark the CHECK `BlockResult` `error` with a diagnostic,
  under `CHECK_GATING_ADVISORY` shall mark it `notices` with an advisory finding, and in **both** cases
  shall leave `aborted == False` and continue downstream with the image intact.
- **Validation:** `test (integration)`
- **Executed verification:** `pytest -q tests/test_flow_execution_service.py -k "check_doc_unreadable"`
- **Numeric pass threshold:** exit 0; the downstream WRITE-OUT file is still produced in both gating
  modes; the CHECK status is `error` (block-own-op) or `notices` (advisory) accordingly.
- **Acceptance criteria:**
  - Mirrors AT-086b; distinguishes the CHECK error (non-aborting) from the SOURCE error (aborting).

#### R-TUI-087 decomposition — status model + roll-up

### LLR-087.1 — `completed-with-issues` flow-status token
- **Traceability:** R-TUI-087
- **Statement:** The `flow_model` module shall define `FLOW_STATUS_ISSUES = "completed-with-issues"`
  alongside the flow-status tokens at `flow_model.py:37-39`. `NEW`.
- **Validation:** `test (unit)`
- **Executed verification:** `pytest -q tests/test_flow_model.py -k "flow_status_issues"`
- **Numeric pass threshold:** exit 0; the token is importable and distinct from `FLOW_STATUS_OK`/`FLOW_STATUS_ERROR`.
- **Acceptance criteria:** value is exactly the string `"completed-with-issues"` (the amber contract).

### LLR-087.2 — Three-way flow-status roll-up
- **Traceability:** R-TUI-087
- **Statement:** At the end of `run_flow`, the two-way roll-up (`flow_execution_service.py:210-213`)
  shall be replaced by a three-way classifier: (a) if `aborted` is `True` → `FLOW_STATUS_ERROR`
  (FAILED, image broken); else (b) if any `BlockResult.status in {BLOCK_STATUS_NOTICES,
  BLOCK_STATUS_ERROR}` OR any `BlockResult.findings` is non-empty → `FLOW_STATUS_ISSUES`
  (completed-with-issues, output produced with advisories); else (c) `FLOW_STATUS_OK` (CLEAN).
- **Validation:** `test (integration)`
- **Executed verification:** `pytest -q tests/test_flow_execution_service.py -k "status_rollup"`
- **Numeric pass threshold:** exit 0; three fixtures map to `ok`, `completed-with-issues`, and `error`
  respectively; a non-aborting CHECK `error` yields `completed-with-issues` (NOT `error`).
- **Acceptance criteria:**
  - Because CHECK errors never set `aborted` (LLR-086.4), branch (b) correctly reaches ISSUES rather
    than the old `any(status==error)→error` collapse.
  - A LOAD/PATCH abort still reaches FAILED via branch (a) (regression guard).

### LLR-087.3 — Amber outcome carried into any report/summary
- **Traceability:** R-TUI-087
- **Statement:** The `completed-with-issues` outcome shall be carried on `FlowRunResult.status` (the
  single machine-readable carrier consumed by any summary/report producer) and shall be rendered
  distinctly from `failed` by the panel banner (LLR-088.5). Per A4 there is no separate flow-report
  **file** in batch-51; this LLR binds the token to the carrier + banner, not to a file artifact.
- **Validation:** `inspection`
- **Executed verification:** inspect `flow_execution_service.run_flow` return + `render_result` banner
  mapping (LLR-088.5) — confirm the `completed-with-issues` token reaches the banner text.
- **Numeric pass threshold:** the token appears in exactly one carrier (`FlowRunResult.status`) and one
  render mapping (banner), with no `failed`/`issues` conflation.
- **Acceptance criteria:** AT-087a observes the token through the banner; there is no other status sink.

#### R-TUI-088 decomposition — Direction A render

### LLR-088.1 — Block-status → `sev-*` class map
- **Traceability:** R-TUI-088
- **Statement:** The `screens_directionb` module shall define a status→class mapping
  `{"ok": "sev-ok", "notices": "sev-warning", "error": "sev-error", "skipped": "sev-neutral"}` (`NEW`,
  in `screens_directionb.py`, NOT in the frozen `color_policy.py`), used to style each block node's
  status gutter with the existing frozen classes (`styles.tcss:529-545`).
- **Validation:** `test (unit)`
- **Executed verification:** `pytest -q tests/test_flow_builder_render.py -k "status_class_map"`
- **Numeric pass threshold:** exit 0; every `BLOCK_STATUS_*` token maps to an existing `.sev-*` class;
  no unmapped status.
- **Acceptance criteria:** the map lives outside the frozen file (0 diff to `color_policy.py`).

### LLR-088.2 — Vertical block-node pipeline render
- **Traceability:** R-TUI-088
- **Statement:** `FlowBuilderPanel.render_result` (`screens_directionb.py:2187`) shall render one node
  per `BlockResult` in flow order, each showing its label (markup-safe) and a status gutter styled by
  the LLR-088.1 map, replacing the current flat text list.
- **Validation:** `test (e2e)`
- **Executed verification:** `pytest -q tests/test_flow_builder_render.py -k "vertical_nodes"` via `App.run_test()`.
- **Numeric pass threshold:** exit 0; node count == `len(block_results)`; each node carries the correct
  `sev-*` class for its status.
- **Acceptance criteria:** drives the real Run button; asserts through the Pilot query (AT-088a mechanism).

### LLR-088.3 — Block separators (`Rule`/border, tone `$rule`)
- **Traceability:** R-TUI-088
- **Statement:** The render shall place a horizontal separator (a `Rule` widget or a `border`/`border-top`
  of tone `$rule`, per `styles.tcss:30`/`:393`) between consecutive block nodes, and shall NOT place a
  trailing separator after the last node.
- **Validation:** `test (e2e)`
- **Executed verification:** `pytest -q tests/test_flow_builder_render.py -k "separators"`
- **Numeric pass threshold:** exit 0; for N blocks there are exactly N−1 separators (single-block →
  zero — boundary).
- **Acceptance criteria:** `$rule` token is verified to exist (`styles.tcss:30`) — not assumed.

### LLR-088.4 — Memory ribbon (single, batch-51 — twin deferred to batch-52 per AMD-1)
- **Traceability:** R-TUI-088
- **Statement:** The render shall include a fixed-width **memory ribbon** — a single cell strip encoding
  the working image's final `ranges` footprint — sized to fit the real boxed panel at 80×24 and wider.
  The ribbon reads its footprint from a NEW additive `FlowRunResult.image_ranges: List[Tuple[int,int]]`
  field (populated with the final `ranges` at the end of `run_flow`; additive per §6.3 R-6). **The
  second `before` row (the "twin") is DEFERRED to batch-52** (AMD-1 / §6.5): without a range-growing
  block (CRC = batch-52) a `before` row is identical to the image row by construction, so rendering two
  identical bars would mislead; the `before_ranges` carrier + the twin land with CRC.
- **Validation:** `test (e2e)` + geometry pilot-measurement.
- **Executed verification:** `pytest -q tests/test_flow_builder_render.py -k "ribbon"` at
  `App.run_test(size=(80,24))` AND a wider regime; ribbon cell budget measured in-panel per C-29 (both
  axes, both regimes).
- **Numeric pass threshold:** exit 0; the ribbon renders within the measured container width at both
  regimes with no horizontal overflow.
- **Acceptance criteria:** the ribbon cell budget is `assumed — verify per-regime in Phase 3` (R-5); it
  MUST be measured in the mounted panel, NOT inherited from the HTML prototype's ~96/150-col budget (C-16).

### LLR-088.5 — Flow-status banner CLEAN / ISSUES / FAILED
- **Traceability:** R-TUI-087, R-TUI-088
- **Statement:** The render shall show a flow-status banner whose text is CLEAN / ISSUES / FAILED and
  whose class is `sev-ok` / `sev-warning` / `sev-error` for `FlowRunResult.status ==`
  `ok` / `completed-with-issues` / `error` respectively.
- **Validation:** `test (e2e)`
- **Executed verification:** `pytest -q tests/test_flow_builder_render.py -k "status_banner"`
- **Numeric pass threshold:** exit 0; each of the three status tokens maps to the correct banner text +
  `sev-*` class (three cases).
- **Acceptance criteria:** the amber ISSUES banner is visibly distinct from FAILED (AT-087a observation surface).

### LLR-088.6 — Markup-safety on file-derived strings (C-17)
- **Traceability:** R-TUI-088
- **Statement:** **Every** file-derived string rendered by the NEW Pipeline-Ledger path shall be rendered
  via `safe_text`/`markup=False`, preserving the panel's existing discipline
  (`screens_directionb.py:2147,2153,2161,2193,2197`), such that a hostile bracket/ANSI payload renders
  literally with no injected span and no style leak. The file-derived sink set is **not hand-enumerated**:
  it is the set of every dynamic string the new render appends from run-derived data — at minimum the block
  **ref label** (`_flow_block_label`), each **notice/finding message** (`Finding.message`, from parser
  `error`/`line` text), each **`BlockResult.diagnostic`**, the **CHECK report/aggregate text**, and each
  **written path** (`str(path)`). (The banner text CLEAN/ISSUES/FAILED and the ribbon are derived from the
  status enum + `ranges` integers — NOT file-derived, per security-review F1 — and are correctly out of the
  sweep.)
- **Validation:** `test (e2e)`
- **Executed verification:** `pytest -q tests/test_flow_builder_render.py -k "hostile_payload_literal"`
- **Numeric pass threshold:** exit 0; for **each** new file-derived sink (enumerated by grepping every
  `safe_text(...)` / dynamic-append call site in the new render path — NOT a single representative node),
  a value rendered from a `"[bold red]…\x1b[31m…"` payload has `Text.plain` equal to the verbatim payload
  AND its markup spans list is empty. The sink set the test iterates MUST be code-derived (C-31) or carry a
  companion assertion that it covers every `safe_text` call site in the new path.
- **Acceptance criteria:** this is AT-088b; assert `plain` verbatim AND `spans == []` **per sink** (crash-only
  is insufficient; a single-node test that leaves another sink unswept is the exact batch-33/43/48
  markup-sink-sweep miss). At minimum: the finding-message node AND the CHECK-report node AND a diagnostic
  are each hostile-tested.

### LLR-088.7 — CHECK/LOAD in the add dropdown
- **Traceability:** R-TUI-086, R-TUI-088
- **Statement:** The panel's block-kind dropdown `_KIND_OPTIONS` (`screens_directionb.py:2105`) shall
  offer a CHECK option (`BLOCK_CHECK`), and `_make_flow_block` (`screens_directionb.py:2047`) shall
  build a `CheckBlock` from the (kind, ref) selection; the SOURCE option shall be relabelled/handled as
  LOAD without changing its `BLOCK_SOURCE` discriminator (preserving the batch-53 JSON tag).
- **Validation:** `test (e2e)`
- **Executed verification:** `pytest -q tests/test_flow_builder_render.py -k "add_check_block"`
- **Numeric pass threshold:** exit 0; selecting CHECK + a ref + Add appends a `CheckBlock`; the SOURCE
  discriminator string is unchanged (`"source"`).
- **Acceptance criteria:** `_make_flow_block` gains a `BLOCK_CHECK` branch; the `FlowBlock` union import
  in `screens_directionb.py` includes `CheckBlock`.

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
| US-085 | Integrity-flagged image → SOURCE `notices` + warning text, downstream still runs | Panel Run → `run_flow` → `render_result` | AT-085a | pending Phase-3 |
| US-085 | Unresolvable image → SOURCE `error`/STOP, downstream `skipped`, no file written | Panel Run → `run_flow` → `render_result` | AT-085b | pending Phase-3 |
| US-086 | CHECK report present + WRITE-OUT bytes identical with/without CHECK (pass-through) | Panel Run → `run_flow` → written file | AT-086a | pending Phase-3 |
| US-086 | Unreadable check-doc → CHECK `error`, WRITE-OUT still produces file (image intact) | Panel Run → `run_flow` → `render_result` | AT-086b | pending Phase-3 |
| US-086 | SAME unreadable-doc under advisory (→`notices`) vs block-own-op (→`error`): status differs + WRITE-OUT produces in both | Panel Run → `run_flow` → `render_result` | AT-086c | pending Phase-3 |
| US-087 | Output + advisories → `completed-with-issues` (amber), distinct from `failed` | `FlowRunResult.status` via the CLEAN/ISSUES/FAILED banner (drive+observe per AT-088a / LLR-088.5) | AT-087a (+ AT-088a banner observer) | pending Phase-3 |
| US-087 | Fully clean run → `ok`/CLEAN (boundary) | `FlowRunResult.status` via banner (AT-088a/LLR-088.5) | AT-087b | pending Phase-3 |
| US-088 | Vertical nodes + `sev-*` gutter + separators + ribbon + CLEAN/ISSUES/FAILED banner | `render_result` via `App.run_test()` | AT-088a | pending Phase-3 |
| US-088 | Hostile file-derived string renders literally (`plain` verbatim, `spans==[]`) | `render_result` via `App.run_test()` | AT-088b | pending Phase-3 |

**Functional chain (white-box) — per requirement:**

| Requirement | Method | Test Case (`TC-NNN`) | Notes |
|-------------|--------|----------------------|-------|
| R-TUI-085 | test (pilot) | AT-085a, AT-085b | HLR-level acceptance mirror |
| LLR-085.1 | test (unit) | TC-085.1 | Finding/`notices` token |
| LLR-085.2 | test (integration) | TC-085.2 | parser errors → WARN notices, chain runs |
| LLR-085.3 | test (integration) | TC-085.3 | STOP → downstream skipped |
| R-TUI-086 | test (pilot) | AT-086a, AT-086b, AT-086c | HLR-level acceptance mirror (AT-086c = gating-block guard) |
| LLR-086.1 | test (unit) | TC-086.1 | `CheckBlock` + gating vocab |
| LLR-086.2 | test (integration) | TC-086.2 | CHECK executes, report attached |
| LLR-086.3 | test (integration) | TC-086.3 | pass-through byte equality |
| LLR-086.4 | test (integration) | TC-086.4 | chain-never-blocked 4-case matrix |
| LLR-086.5 | test (integration) | TC-086.5 | unreadable check-doc, non-aborting |
| R-TUI-087 | test (pilot) | AT-087a, AT-087b | HLR-level acceptance mirror |
| LLR-087.1 | test (unit) | TC-087.1 | `completed-with-issues` token |
| LLR-087.2 | test (integration) | TC-087.2 | three-way roll-up |
| LLR-087.3 | inspection | TC-087.3 | token carrier + banner, single sink |
| R-TUI-088 | test (pilot) | AT-088a, AT-088b | HLR-level acceptance mirror |
| LLR-088.1 | test (unit) | TC-088.1 | status→`sev-*` map |
| LLR-088.2 | test (e2e) | TC-088.2 | vertical nodes |
| LLR-088.3 | test (e2e) | TC-088.3 | N−1 separators |
| LLR-088.4 | test (e2e) | TC-088.4 | ribbon at 80×24 + wider |
| LLR-088.5 | test (e2e) | TC-088.5 | banner text + class |
| LLR-088.6 | test (e2e) | TC-088.6 | hostile payload literal (`spans==[]`) |
| LLR-088.7 | test (e2e) | TC-088.7 | CHECK in dropdown + `_make_flow_block` |

> Test file paths, `-k` selectors, and `TC-NNN`/`AT-NNN` node ids above are provisional-until-Phase-3
> (V-5) and reconciled from the real tree at Phase 4. New test files: `tests/test_flow_model.py`
> (extend if present), `tests/test_flow_execution_service.py`, `tests/test_flow_builder_render.py`.

### 5.3 Batch acceptance criteria
- Every LLR (`LLR-085.*..088.*`) is covered by ≥1 passing `TC` with a recorded pass result.
- Every user story (US-085..088) has ≥1 passing `AT-NNN` observing its outcome through the shipped
  panel/handler surface, with boundary + negative evidence (per the QC-3 catalogs).
- 0 blocker fails in Phase-4 validation; 0 engine-frozen diffs (C-27 dual-guard) — the only edited
  files are `flow_model.py`, `flow_execution_service.py`, `screens_directionb.py`, `app.py`,
  `styles.tcss`, and new test files.
- No requirement without an assigned validation method + (for `test`/`analysis`) an executed
  verification and numeric pass threshold.
- The C-17 hostile-payload AT (AT-088b) passes: file-derived strings render literally (`plain`
  verbatim, `spans == []`).
- Snapshot drift on `#screen_flow` is expected and reconciled via a canonical-CI regen follow-up (local
  regen forbidden); the non-snapshot suite is green before merge.

---

## 6. Appendices (optional)

### 6.1 Extended glossary
See §1.3. Additional: **abort-asymmetry** — LOAD/PATCH/WRITE-OUT failures set `aborted=True` (image
broken → downstream skipped); a CHECK failure never sets `aborted` (image intact → downstream runs).

### 6.2 Relevant design decisions
- **D1 — LOAD is the SOURCE block's load behaviour, not a new discriminator.** The `notices` emission
  is added to the existing `SourceBlock` execution; the `BLOCK_SOURCE = "source"` JSON tag is preserved
  so batch-53 persistence is unaffected. The UI may display "Load", but the model kind stays `source`.
  (Prototype `flow_builder.NOTES.md` calls this "SOURCE→LOAD".)
- **D2 — Findings vs diagnostics kept separate.** `BlockResult.diagnostics` remains the hard-failure
  text; the new `findings: List[Finding]` carries advisory WARN notices. This mirrors the prototype's
  WARN/STOP severity split and keeps the roll-up predicate simple (notices/findings ⇒ ISSUES, aborts ⇒
  FAILED).
- **D3 — `aborted` is the single image-broken signal for the roll-up.** Because CHECK errors never set
  `aborted`, the three-way classifier reads `aborted` for FAILED and block statuses/findings for ISSUES
  — no second flag needed.
- **D4 — status→`sev-*` map lives in `screens_directionb.py`.** `color_policy.py` is frozen; the flow
  render does not route through `SEVERITY_CLASS_MAP` (which keys on `ValidationSeverity`), it maps block
  status → existing `.sev-*` class directly. 0 diff to the frozen file.
- **D5 — "report/summary" = the status token + banner (A4).** No flow-report file exists; US-087's
  "any generated report" is bound to `FlowRunResult.status` (carrier) + the banner (US-088). Recorded so
  Phase-2 does not expect a file deliverable.
- **D6 — `None` FlowContext for CHECK linkage is acceptable.** The app wires
  `FlowContext(project_dir=...)` only (`app.py:1975`); `run_check_document`'s `mac_records`/`a2l_tags`
  drive informative-only linkage classification, so `None` yields unclassified linkage without blocking
  the check. Wiring project MAC/A2L into the context is a possible later refinement, out of scope here.

### 6.3 Open risks
- **R-1 (C-17 untrusted-render):** CHECK/LOAD strings are file-derived → LLR-088.6 + AT-088b (hostile
  payload, assert `plain` verbatim AND `spans==[]`). Mitigated; the panel already uses `safe_text`.
- **R-2 (snapshot drift):** Direction A changes `#screen_flow` cells → canonical-CI regen follow-up
  (local regen forbidden). Expected, not a defect.
- **R-3 (highly user-visible gating):** the advisory-vs-gate distinction must be crisp — LLR-086.4
  specs the chain-never-blocked invariant with maximum clarity and a 4-case test matrix; no hidden
  chain-kill path.
- **R-4 (`run_check_document` reuse):** signature/return shape VERIFIED at draft (`check.py:194`,
  `model.py:684`, aggregates keys `model.py:571`) — closed.
- **R-5 (80×24 geometry):** the ribbon + node columns are `assumed — verify per-regime in Phase 3`
  (LLR-088.4); pilot-measure both axes in the mounted boxed panel (C-29); do not inherit the HTML
  prototype's width budget (C-16).
- **R-6 (contract-touch):** `BlockResult` gains `findings` and `CheckBlock` joins the `FlowBlock`
  union — any consumer enumerating block kinds or `BlockResult` fields (the render, `render_result`)
  must be reconciled; tracked by LLR-088.2/088.7. No cross-cutting canonical-field contract is broken
  (the `FlowRunResult` shape is additive).

### 6.4 Phase-1 reconciliation log
One reconciliation event at the Phase-1 gate: the qa-reviewer's AT-audit (parallel Phase-1 agent,
`_qa-validation-methods.md`) surfaced a Coverage gap and a mis-assumed artifact. Body-edit-first audit:

| Decision ID | What changed | Parent HLR re-read? | Body edit landed? |
|-------------|--------------|---------------------|-------------------|
| REC-1 | **AT-086c ADDED** — the gating flag's non-default `block` value was untested (AT-086a=advisory, AT-086b=unreadable-doc are different mechanisms); a gating=`block`-skips-downstream mis-impl would pass green (the forbidden hidden chain-kill, R-3). | R-TUI-086 re-read: no statement change — LLR-086.4's 4-case chain-never-blocked matrix already covers gating; the gap was a missing *acceptance node*, not a missing requirement. | §3 R-TUI-086 Acceptance (AT-086c block + boundary-catalog gating row) + §5.2 table row + §5 method table (AT-086a/b/c). Owner: Inc-1 (engine) + Inc-2 (distinct render). |
| REC-2 | **qa's proposed AT-087c (re-read a report *file*) SUPERSEDED, not added** — architect A4/D5 established there is no flow-report file (`run_flow` returns only `FlowRunResult.status` + `written_paths`). The "outcome appears in any generated report" clause binds to the status token + banner. | R-TUI-087 re-read: no change — AT-087a already observes the `completed-with-issues` token through the shipped banner surface; no file deliverable to observe. | §2.5-A4 + §6.2-D5 (already present); no new AT. Recorded here so the Phase-2 review does not re-flag a "missing report-file AT". |
| REC-3 | **D1 adopted autonomously** (LOAD = SOURCE block's load behaviour, not a new `kind`; preserves `"source"` JSON tag for batch-53). Flagged by architect as "worth an operator confirm". | R-TUI-085 re-read: no change — LLR-085.x already specs notices on the existing SOURCE load path. | §6.2-D1. **Operator-awareness flag:** reversible; if the operator expected a distinct LOAD block *type*, revisit before Inc-1. Adopted as a sound default under the autonomy grant. |

**Phase-2 iterate (both cross-reviews converged — architect B-1/M-1, qa B1/M1, security F2):**

| Decision ID | What changed | Parent HLR re-read? | Body edit landed? |
|-------------|--------------|---------------------|-------------------|
| REC-4 | **AT-086c REAUTHORED (blocker fix)** — the Phase-1 fold (REC-1) drove a phantom gating value `"block"` and a phantom `"blocked"` status, and triggered on entries-absent, which false-fails a correct impl (LLR-086.4: entries-fail does not flip status). Rewrote AT-086c to drive the SAME unreadable-doc input under BOTH `CHECK_GATING_ADVISORY` and `CHECK_GATING_BLOCK_OWN` (real tokens), asserting the status DIFFERS (`notices` vs `error`) + WRITE-OUT produces in both — the true C-10 observed-change; entries-absent dropped. | R-TUI-086 re-read: statement unchanged; the defect was in the acceptance node, not the requirement. LLR-086.1 gating tokens (`advisory`/`block-own-op`) and status set (`ok/notices/error/skipped`) are the source of truth AT-086c now matches. | §3 R-TUI-086 AT-086c body + boundary-catalog row + §5.2 table row (all now "SAME unreadable-doc, advisory→notices vs block-own-op→error"). |
| REC-5 | **LLR-086.4 gating matrix TABULATED (major M-1 fix)** — the threshold said "per the matrix above" but only prose existed; 3 of 4 cells collapse to `notices`, which is what let REC-1 mis-author AT-086c. Added the explicit 4-cell truth table ({advisory\|block-own-op} × {entries-fail\|unreadable}) with the resulting status; the single differing cell (block-own-op × unreadable → `error`) is what AT-086c drives. | R-TUI-086 re-read: no statement change — the matrix makes explicit what LLR-086.4/086.5 already implied. | LLR-086.4 new "4-case gating matrix" table. |
| REC-6 | **LLR-088.6 / AT-088b markup-sink sweep WIDENED (major M1/F2 fix)** — was hand-enumerated (4 examples) and hostile-tested "a node/notice"; omitted `BlockResult.diagnostic` and could leave a sink unswept (the batch-33/43/48 pattern). Now requires the sink set be CODE-DERIVED (grep every `safe_text`/dynamic-append site in the new render path) and each sink hostile-tested `plain`-verbatim + `spans==[]` (C-31); banner/ribbon correctly excluded as non-file-derived (security F1). | R-TUI-088 re-read: no statement change — the universal "every file-derived string" bar was already correct; only its operationalization was narrowed and is now un-narrowed. | LLR-088.6 statement + threshold + acceptance. |
| REC-7 | **Minors folded/noted** — qa m2: US-087 §5.2 to cross-ref AT-088a as the banner observer (folded). qa m1 (AT-086a fixture: derive an absent address from OUTSIDE the seeded ranges), qa m3 (AT-085a exactly-one-error boundary), qa m4 + architect m-1 off-by-one citations + provisional test-file name `test_flow_execution_service.py` vs existing `test_flow_execution.py` → all Phase-3/Phase-4-reconcile notes (V-5). | n/a (no requirement change) | §5.2 US-087 rows (banner cross-ref); rest are Phase-3 AT-authoring / Phase-4 reconciliation notes. |

### 6.5 Requirement amendments (Before / After · Deleted / New)
*(Used by `iterate-to-refine` (Phase 1 from a Phase-4 black-box failure) and by Phase-3 spec amendments. One block per amendment: **Before → After** text · **Deleted / New** tokens · parent-HLR re-read result · the re-derived HLR/LLR + their `TC`/`AT`. Never silently edit a locked requirement.)*

**AMD-1 (2026-07-20, Phase-3 Inc-2 — ribbon data-carrier + twin→single, operator-awareness flag).**
Surfaced by the Inc-2 software-dev before writing code: LLR-088.4's "twin memory ribbon" (a) had NO
data source — the Inc-1 `FlowRunResult` carries only a range *count* in a summary string, not address
extents; and (b) the "twin" (before + image rows) is meaningless in batch-51 because no block grows the
range set (CRC = batch-52) → the two rows would be byte-identical, misleading.
- **Before:** LLR-088.4 "a fixed-width **twin memory ribbon** … the working image's `ranges` footprint
  plus a `before` row for contrast."
- **After:** LLR-088.4 "a single **memory ribbon** encoding the working image's final `ranges`
  footprint," reading from a **NEW** additive `FlowRunResult.image_ranges: List[Tuple[int,int]]`
  (populated at the end of `run_flow`; additive per §6.3 R-6 — re-opens the two Inc-1 engine files
  additively, default-empty, with the full Inc-1 suite + frozen dual-guard re-run to prove 0 regression).
- **Deleted:** the `before` row / twin from batch-51.  **New:** `FlowRunResult.image_ranges` field;
  batch-52 carry — the `before_ranges` carrier + the twin (before-vs-after) land with CRC, where growth
  makes them meaningful (the operator's "watch it grow" signature is inherently a CRC/batch-52 payoff).
- **Parent-HLR re-read (R-TUI-088):** no statement change — R-TUI-088 requires "the working image's
  footprint" rendered; a single honest ribbon satisfies it. AT-088a's ribbon assertion changes from
  "twin rows" to "the single image ribbon renders within the measured width, no overflow".
- **Re-derived TC/AT:** AT-088a (ribbon = single strip from `image_ranges`, geometry pilot-measured);
  a new TC on `image_ranges` population (engine, added to the Inc-1 test file). File count stays ≤5
  (flow_model.py, flow_execution_service.py, screens_directionb.py, styles.tcss, test_flow_builder_render.py).
- **⚠ Operator-awareness flag:** this defers the *twin*/growth ribbon — the signature element you liked
  — to batch-52 (CRC), rendering a single footprint ribbon now. Reversible; adopted as the honest call
  under the autonomy grant (two identical bars now would misrepresent). Redirect if you want the twin
  forced earlier (would require pulling a range-growing block forward).
