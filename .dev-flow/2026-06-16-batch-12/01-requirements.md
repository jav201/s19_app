# Requirements Document — s19_app — Batch 2026-06-16-batch-12

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

---

## 1. Introduction

### 1.1 Purpose
This document specifies, at HLR (IEEE 830 + EARS) and LLR level, the requirements for **batch-12 (CRC_F2)** — the first concrete *operation* fill-in of the `s19_app` operations framework that batch-08 scaffolded. It derives binding requirements from the two READY user stories US-011 (CRC32 region **check** — compute + compare, non-mutating) and US-012 (CRC32 **inject** + modified-S19 emit + verify, operator-confirmed), and records the design decisions, the change-first guard census, and the draft-time-verified reuse anchors that the implementation (Phase 3) builds on.

### 1.2 Scope

**In scope.**
- A parameterized CRC32 compute engine over one or more configured memory ranges of a loaded S19 (incl. S3/32-bit), default convention = zlib/PKZIP CRC-32.
- A **non-mutating check**: compute per region, read the 4-byte little-endian value stored at each range's output address, compare, report match/mismatch (US-011).
- An **operator-confirmed inject**: write each computed CRC as 4-byte little-endian into its output address (extending the image when the address falls in a gap), re-emit a modified S19, verify the write with the reader-as-oracle, and surface the result in the report (US-012).
- **Config externalization**: all CRC parameters and the range/output-address geometry sourced from an operator-supplied JSON file resolved via `resolve_input_path`; a TUI text surface pre-filled with DUMMY values for format guidance.
- Two framework contract changes the fill-in forces: a **neutral input contract** replacing the `execute(loaded: LoadedFile, …)` hard binding (C-7 / R-2), and a **widened `OperationResult`** carrying the per-region CRC payload (R-3).
- A co-located **`s19_app/tui/operations/requirements/REQ-crc.md`** capturing the operation-level requirements (C-7 first-fill-in mandate); app docs reference it, do not inline it.

**Out of scope.**
- The CLI `ops` subcommand (`cli.py`) — deferred at batch-08; this batch is **TUI-only**.
- Non-S19 input formats (HEX/MAC as CRC inputs).
- Any change to the frozen parse/validate engine (`core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`); reuse of those modules is **import-only**.
- Committing real per-firmware config values (poly/init/ranges/output-addresses) to the repo — repo carries only a dummy template + synthetic fixtures.

### 1.3 Definitions, acronyms, abbreviations
| Term | Definition |
|------|------------|
| CRC32 / CRC-32 | 32-bit cyclic redundancy check. The batch default convention is zlib/PKZIP CRC-32: polynomial `0x04C11DB7`, init `0xFFFFFFFF`, `refin=true`, `refout=true`, xorout `0xFFFFFFFF` (equivalent to Python `zlib.crc32`). All parameters are OPEN via config; the default is what the dummy template and fixtures use. |
| reverse flag | The single boolean config field requesting standard reflected-input/reflected-output (`refin`/`refout`) CRC semantics; `true` = zlib/PKZIP convention. |
| output address | The memory address at which a region's computed CRC is stored (check) or written (inject). One per CRC region. |
| 4-byte LE | The fixed (non-parameterized) storage codec for a CRC at its output address: four bytes, little-endian. `crc & 0xFF` at `addr`, `(crc >> 8) & 0xFF` at `addr+1`, etc. |
| region / CRC region | One configured `(start, end)` address range whose bytes are CRC'd, paired with one output address. |
| segment | A maximal contiguous run of present addresses inside the CRC regions (`current == previous + 1`); segments are concatenated, CRC state is NOT reset between them (FR8). |
| write-into-gap | When an output address falls outside any loaded range; the inject path EXTENDS `mem_map` + `ranges` to include the 4 CRC bytes rather than rejecting. |
| neutral input contract | The replacement for `Operation.execute(loaded: LoadedFile, …)`: an operation receives `mem_map` + `ranges` + metadata (a small input object), decoupling operations from the Textual-side `LoadedFile` (C-7 / R-2). |
| reader-as-oracle | Verification idiom: re-read a just-written image with the production parser (`S19File`) and diff against the intended `mem_map` (`verify_written_image` / `VerifyResult`). |
| frozen / engine-frozen | The git-diff-vs-`main` guard set (`test_engine_unchanged.py`, `test_tui_directionb.py::test_tc031_*`) that forbids edits to the parse/validate engine modules. |
| R-2 / R-3 / R-6 | Batch-08 deferred-risk ids: R-2 = neutral input contract decoupling; R-3 = `OperationResult` widening for real payloads; R-6 = side-effectful write migrates to worker-thread + per-execution confirmation + sanitized paths. |
| C-7 | Batch-08 decision: CRC is the first operations fill-in; mandates co-located `REQ-crc.md` and resolving the deferred contract. |

### 1.4 References
- `.dev-flow/2026-06-16-batch-12/01-requirements.md` §2.6 — source user stories US-011/US-012 + operator FR1-FR9 verbatim draft + Phase-0 gate disposition (this file).
- Batch-08 artifacts (operations framework scaffold): `s19_app/tui/operations/{model,registry,placeholders}.py`, `s19_app/tui/services/operation_service.py`, `s19_app/tui/screens.py::OperationsScreen`.
- `REQUIREMENTS.md` — repo-wide `R-*` requirements traceability (to be updated to reference `REQ-crc.md` and the new behavior in Phase 6).
- `CLAUDE.md` (project) — engine-frozen guard set; operations-module conventions; thread-split / service-extension rules.
- IEEE 830-1998 (requirements form); EARS (Mavin et al.) patterns.
- zlib `crc32` / PKZIP CRC-32 specification (default CRC convention).

### 1.5 Document overview
§2 (pre-instantiated) carries the overall description and the two READY stories with their Phase-0 dispositions. §3 states five HLRs (CRC compute engine; region check + compare + report; inject + emit + verify; config sourcing + TUI surface; neutral input contract + `OperationResult` widening). §4 decomposes each into LLRs ordered along the 3-increment dependency chain (I1 → I2 → I3). §5 (validation strategy) is owned by qa-reviewer and intentionally left for merge. §6 carries the glossary, the design decisions (contract shapes, config schema, CRC param set, 4-byte LE codec, write-into-gap mechanism, REQ-crc.md plan, R-6 mechanism), the open risks (incl. the contract-decoupling SPIKE fallback), the change-first census, and the Phase-1 evidence checklist.

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
| US-011 | As a calibration/firmware engineer, I want to compute a CRC32-IEEE over one or more configured memory ranges of an S19 (incl. S3/32-bit) and compare it against the value currently stored at each range's output address, so that I can verify whether the file's CRC fields are already correct **without modifying the file**. | Operator FR draft 2026-06-16 (FR1-FR8, FR9 stage 1) | READY |
| US-012 | As a calibration/firmware engineer, I want to inject the computed CRC32 into each range's output address and emit a modified S19, so that I can produce a corrected firmware image with valid CRC fields, surfaced in the s19_app report. | Operator FR draft 2026-06-16 (FR6, FR9 stage 2) | READY |

> **Provisional split (Phase-0 to confirm):** the operator draft describes ONE operation with a TWO-STAGE finalization (FR9): stage 1 = compute + compare (non-mutating, the default "check"), stage 2 = operator-confirmed inject + modified-S19 emit. Modeled here as US-011 (check) + US-012 (write) pending the INVEST "Small / Independent" call — may collapse to one story or stay split. **A-4 carry:** CRC compute/emit must NOT land in frozen `core.py`/`hexfile.py`; this is the named census stress-test.

#### Source draft (operator FR1-FR9, verbatim — 2026-06-16)

**CRC_F2** (custom name, adjustable)

- **FR1 Input support:** accept Motorola S19; support S3 records (32-bit addresses); require one or more hex memory ranges to CRC; require one or more output hex addresses to store the result (each range has an output address); require a polynomial hex value; require an init hex value; require a reverse boolean flag (reverse bit order before the CRC operation); require a final-XOR value.
- **FR2 Address ordering:** sort data by ascending address → deterministic CRC behavior.
- **FR3 Region filtering:** accept configurable address ranges; include only bytes within CRC regions.
- **FR4 Segment reconstruction:** detect contiguous memory blocks; split segments on any gap; contiguity rule `current == previous + 1`.
- **FR5 CRC computation:** CRC32 IEEE; process concatenated segments; process bytes in ascending address order.
- **FR6 Output:** return CRC value per region; optionally inject into memory (default true, but the operation also serves as a check without modifying the file — analogous to existing memory-region checks: confirm whether the file already has the CRC computed and saved into the corresponding memory).
- **FR7 Gap handling:** do not insert any bytes for gaps.
- **FR8 Segment chaining:** process segments sequentially using the same CRC state (`crc = init; for segment: crc = update(segment, crc)`); CRC shall not reset between segments.
- **FR9 Finalization:** apply final XOR; the final CRC computation has TWO stages — (1) compare the calculated CRC against the value in the specified memory region, then (2) ask the operator to write the output into the specified memory region; the tool shall output a modified S19 containing the CRC fields. This is part of the report generated by s19_app.

#### Refinement log (one block per story — filled in Phase 0)

**US-011 — CRC32 region check (compute + compare, non-mutating)** — **READY**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):** user = calibration/firmware engineer · outcome = per-region CRC32 computed and compared against the 4-byte little-endian value stored at each output address, reported as match/mismatch, file untouched · why = confirm CRC fields are already correct with zero mutation risk · out of scope = writing/emitting (US-012), CLI surface (deferred per batch-08), non-S19 formats.
- **Feasibility (E, S):** implementation path KNOWN (architect verdict, Phase 0) — parameterized CRC engine (default = zlib refin/refout) in NEW `tui/operations/crc.py`, clearing the frozen set; FR2/FR4 from `S19File.ranges` + `mem_map`; FR3 via `range_index`; FR8 segment-chained loop · dependencies = increment-1 neutral input contract (C-7/R-2) + config sourcing · fits one batch? = yes, as increment 2.
- **Evaluability (T):** AC = "Given a config with range(s) + output-addr(s) + poly/init/reverse/xorout, when the operation runs over a loaded S19, the tool shall compute CRC32 per region and report, per output address, whether the stored 4-byte little-endian value matches the computed CRC — without modifying the file."
- **Resolved (Phase 0 Q&A):** reverse = standard refin/refout (zlib); params OPEN via external config (not in repo); stored value = 4-byte little-endian (fixed); surface = TUI-only; config = JSON file via `resolve_input_path` + TUI text view/edit pre-filled with dummy values for format guidance.
- **Classification:** **READY** — proceeds to Phase 1. (Gated only by the increment-1 contract decoupling planned IN this batch; Phase-1 change-first census must certify frozen-set clearance.)

**US-012 — CRC32 inject + modified-S19 emit (operator-confirmed)** — **READY**
- **INVEST:** I ~ (depends on US-011) · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):** user = same · outcome = on operator confirmation, write each computed CRC as 4-byte little-endian into its output address (extending `mem_map`+`ranges` when the address falls in a gap), re-emit a modified S19 via `emit_s19_from_mem_map`, verify via reader-as-oracle, surface in the report · why = produce a corrected firmware image with valid CRC fields · out of scope = the check logic (US-011), CLI surface.
- **Feasibility (E, S):** path KNOWN — reuse `emit_s19_from_mem_map` (tui/changes/io.py) + `verify_written_image`/`VerifyResult` (tui/changes/verify.py, reader-as-oracle 4th use); R-6 MANDATORY: worker-thread (`execute_scope`) + per-execution operator confirmation + sanitized output paths (security-reviewer at sign-off) · dependencies = US-011 · fits one batch? = yes, as increment 3.
- **Evaluability (T):** AC = "Given a verified computed CRC and operator confirmation, when the write executes, the tool shall set the 4-byte little-endian CRC at each output address (extending the image if needed), emit a structurally valid modified S19, and the re-read of that S19 shall match the intended mem_map; the result is surfaced in the report. Without confirmation, no file is written."
- **Resolved (Phase 0 Q&A):** write-into-gap = extend `mem_map`+`ranges`; 4-byte little-endian; TUI-only; two-stage confirm (FR9).
- **Classification:** **READY** — proceeds to Phase 1, ordered AFTER US-011. R-6 worker-thread + confirmation + security review are mandatory inheritances.

---

#### Phase 0 gate disposition (Definition of Ready)

**Both stories READY.** No story classified REFINE/SPIKE/OUT. Cross-cutting decisions locked:

- **Decomposition (architect-recommended, 3 increments on the batch-08 seam pattern):**
  1. **I1 — neutral input contract + config sourcing + CRC compute core (headless).** Resolve the deferred `execute(loaded: LoadedFile, …)` decoupling (C-7 item c / R-2) to a neutral input (mem_map + ranges + metadata); widen `OperationResult` for the per-region CRC payload (R-3); implement the parameterized CRC engine; CREATE co-located `s19_app/tui/operations/requirements/REQ-crc.md` (C-7 mandate) referenced from app docs. Pure compute, no I/O.
  2. **I2 — US-011 check + report + config surface.** Wire compute through `run_operation`/`OperationsScreen`; read the stored 4-byte LE value per output address; compare; surface per-region match/mismatch in the report; TUI text view/edit of the JSON config with dummy values; migrate to the `execute_scope` thread-worker (R-6).
  3. **I3 — US-012 inject + emit + verify.** Mutate mem_map (extend ranges on gap); `emit_s19_from_mem_map`; contained-workarea write; `verify_written_image` reader-as-oracle; two-stage operator confirmation (R-6 + security-reviewer).
- **C-7 first-fill-in obligations honored:** REQ-crc.md co-located; app docs (REQUIREMENTS.md, this 01-requirements) reference it, do not inline; neutral input contract decided in I1.
- **A-4 census stress-test (named):** all planned new/edited files (`operations/crc.py`, `operation_service.py`, `screens.py`, `app.py`, `operations/model.py`, config reader) touch ZERO frozen path; reuse of `emit_s19_from_mem_map`/`verify_written_image`/`range_index` is import-only. Phase-1 change-first census to certify at the gate (not by re-running a known checklist).
- **Flagged risk (with fallback):** if the contract decoupling proves deeper than expected at I1 draft (forces touching every `LoadedFile` renderer), split it into a standalone SPIKE and ship CRC against `LoadedFile` as-is. Fallback, not the plan.
- **Config-in-repo guard:** real per-firmware config values never committed; repo carries only a dummy/example template (fake values) + synthetic test fixtures.

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

> **HLR set rationale.** Five HLRs, 18 LLRs (after the Phase-2 iter-2 register: +LLR-002.4/002.5/003.5 for the F-A-01 dual surfaces). Each HLR maps to a coherent verification surface; HLR-005 (framework contract) is ordered FIRST in the dependency chain (it is increment I1a's deliverable and every other HLR consumes it) but numbered last so the capability HLRs read top-to-bottom by story. Increment mapping (revised, see §4 ordering note): HLR-005 = I1a; HLR-001 = I1b; HLR-004 = I2–I3; HLR-002 = I2–I4 (check engine → view → report); HLR-003 = I5. The split keeps the pure-compute core (HLR-001, headless) separate from the I/O-and-confirmation write path (HLR-003, R-6 worker-thread), the highest-risk surface, and the persistent-report wiring (HLR-002/003 surface b) in its own increment.

### HLR-001 — CRC32 compute engine (parameterized, headless)
- **Traceability:** US-011 (also consumed by US-012)
- **Statement:** When invoked with a memory map, a set of CRC regions, and a CRC parameter set, the system shall, for each region, sort the in-region bytes by ascending address, reconstruct contiguous segments (splitting on any gap, contiguity rule `current == previous + 1`), process the concatenated segments through a single non-resetting CRC32 state (`crc = init`; per segment `crc = update(segment, crc)`), apply the configured final XOR, and return one computed CRC value per region — performing no I/O, no parsing, and no mutation of the input.
- **Rationale (informative):** FR1–FR5, FR7, FR8 describe a deterministic pure function; isolating it as a headless engine makes it exhaustively unit-testable against `zlib.crc32` oracles and reusable by both the check (US-011) and inject (US-012) paths. Segment chaining without reset and gap-skip (no bytes inserted for gaps) are explicit operator requirements (FR7/FR8).
- **Validation:** `test (unit)`
- **Executed verification:** `pytest -q tests/test_crc_engine.py` (NEW — created in Phase 3), asserting computed CRC equals a `zlib.crc32`-derived oracle for single-segment, multi-segment-with-gap, and multi-region fixtures; plus a determinism re-run equality.
- **Numeric pass threshold:** 100% of engine TCs pass; computed CRC == oracle for every fixture (exact 32-bit equality); 0 mutations of the input `mem_map` (identity/copy assertion).
- **Priority:** high

### HLR-002 — CRC region check: compare against stored value + report (non-mutating)
- **Traceability:** US-011
- **Statement:** When the CRC operation runs in its default (check) mode over a loaded S19, the system shall, for each configured region, read the 4-byte little-endian value stored at that region's output address, compare it to the CRC computed by HLR-001, and report per output address whether the stored value matches the computed value — without modifying the loaded file or writing any file.
- **Rationale (informative):** FR6/FR9-stage-1: the operation primarily serves as a check (analogous to existing memory-region checks) confirming whether the file already carries a correct CRC. Zero mutation is the safety guarantee that makes the default mode risk-free.
- **Validation:** `test (integration)` + `demo`
- **Executed verification:** `pytest -q tests/test_crc_operation.py` (NEW — created in Phase 3) for the compute→read-stored→compare→report path over fixtures with a matching CRC, a mismatching CRC, and a missing output address; `demo` = launch `s19tui`, load a fixture S19 + CRC config, run the CRC operation, observe per-region match/mismatch lines in the result surface.
- **Numeric pass threshold:** 100% of check TCs pass; for every region the reported match flag equals (`stored_4LE == computed_crc`); 0 bytes of the loaded `mem_map` changed (pre/post equality); demo shows one report line per region with the correct match/mismatch verdict.
- **Priority:** high

### HLR-003 — CRC inject + modified-S19 emit + verify (operator-confirmed)
- **Traceability:** US-012
- **Statement:** When the operator confirms the write stage after a check, the system shall write each computed CRC as a 4-byte little-endian value at its output address — extending `mem_map` and `ranges` to include the 4 bytes when the output address falls outside every loaded range — emit a structurally valid modified S19 from the resulting memory map into the contained work area, re-read that S19 with the production parser and confirm it equals the intended memory map, and surface the write/verify outcome in the report; and if the operator does not confirm, then the system shall write no file.
- **Rationale (informative):** FR6/FR9-stage-2: the write is the optional, operator-gated finalization. Reusing `emit_s19_from_mem_map` + `verify_written_image` (reader-as-oracle) inherits the proven save/verify discipline; the two-stage confirm + worker-thread + sanitized output path are the R-6 mandatory inheritances for a side-effectful operation.
- **Validation:** `test (integration)` + `demo`
- **Executed verification:** `pytest -q tests/test_crc_operation.py` (NEW) for: inject-then-reread round-trip equality; write-into-gap range extension; no-confirmation→no-file; emit re-parses with 0 load errors. `demo` = run the operation in `s19tui`, confirm the write, observe the verified modified-S19 path and the verify-OK line in the report.
- **Numeric pass threshold:** 100% of inject TCs pass; re-read `mem_map` == intended `mem_map` (0 diff runs from `verify_written_image`, `status == "verified"`); emitted S19 re-parses with 0 errors; no-confirmation path writes 0 files (filesystem assertion); gap extension adds exactly 4 addresses per gapped output.
- **Priority:** high

### HLR-004 — CRC config sourcing (external JSON) + TUI text surface
- **Traceability:** US-011, US-012
- **Statement:** When the operator supplies a CRC config file path, the system shall resolve it via `resolve_input_path` (an absolute path is returned verbatim; only a relative path triggers the cwd/base/repo-root walk — see LLR-004.1 containment posture) under the `READ_SIZE_CAP_BYTES` size cap, parse the JSON into a typed config (regions with `(start, end)` + output address, polynomial, init, reverse flag, final-XOR), and present the config in the TUI as editable text pre-filled with dummy values for format guidance; and if the path is unresolvable or the JSON is structurally invalid, then the system shall report the failure as a collected error and run no CRC computation.
- **Rationale (informative):** Real per-firmware CRC parameters must never live in the repo; sourcing them from an operator-supplied file (the `read_change_document` pattern) keeps them out of version control while the dummy-pre-filled text surface gives format guidance. Collect-don't-abort on a bad config matches the parser-layer contract.
- **Validation:** `test (unit)` + `demo`
- **Executed verification:** `pytest -q tests/test_crc_config.py` (NEW — created in Phase 3) for: valid dummy template parses to the expected dataclass; unresolvable path → one collected error, no compute; malformed JSON → one collected error, no compute; the in-repo dummy template file exists and parses. `demo` = open the CRC config surface in `s19tui`, observe dummy values pre-filled, edit a field, run.
- **Numeric pass threshold:** 100% of config TCs pass; valid template → fully-populated config object (all required fields non-null); each failure mode → exactly 1 collected error and 0 CRC computations; dummy template parse exit 0.
- **Priority:** high

### HLR-005 — Neutral input contract + `OperationResult` widening (framework)
- **Traceability:** US-011, US-012 (resolves batch-08 C-7 / R-2 / R-3)
- **Statement:** The operations framework shall provide a neutral operation input that carries `mem_map`, `ranges`, and identifying metadata (replacing the `execute(loaded: LoadedFile, …)` binding so an operation does not depend on the Textual-side `LoadedFile`), and `OperationResult` shall be widened with a structured per-region CRC payload field while preserving its existing 7-field contract and closed `STATUS_DOMAIN` for all current callers.
- **Rationale (informative):** Batch-08 deferred the contract decoupling (C-7 item c / R-2) and the result-payload widening (R-3) until the first real operation needed them; CRC is that operation. Keeping the existing `OperationResult` fields and status domain intact preserves the three placeholder operations and their tests (no engine-frozen or guard breakage).
- **Validation:** `test (unit)` + `inspection`
- **Executed verification:** `pytest -q tests/test_operations.py` (EXISTING — `tests/test_operations.py`) must stay green after the widening; `pytest -q tests/test_crc_engine.py` exercises the engine through the neutral input; `inspection` = `OperationResult` retains its 7 canonical fields + the new optional payload field, `STATUS_DOMAIN` unchanged.
- **Numeric pass threshold:** existing `tests/test_operations.py` 100% pass post-change (0 regressions); neutral input carries `mem_map` + `ranges` (field presence assertion); `OperationResult` field count == 7 + 1 new optional field; `STATUS_DOMAIN == {"placeholder","ok","error"}` unchanged.
- **Priority:** high

---

## 4. Low-level requirements (LLR)

> Each LLR decomposes an HLR into a verifiable property at the implementation level.
> Same EARS regime. ID format: `LLR-<HLR>.<M>`.

> **Ordering & increment plan (revised at Phase-1 iter-2, F-A-03 — each increment ≤5 files per the CLAUDE.md hard rule).** The original 3-increment plan put I1 at ≥7 files; it is split, and the F-A-01 "both surfaces" decision adds a report-service increment. Six increments, dependency-ordered and acyclic:
> - **I1a — neutral contract, ATOMIC (5 files):** `model.py` (`OperationInput` NEW + `OperationResult` widen + `CrcRegionResult`), `operation_service.py` (`run_operation:91` call-site builds the neutral input), `screens.py` (the `:636` direct call-site builds the neutral input — migrated TOGETHER so `execute`'s type change leaves the tree green; verified at Phase-3 prep these are the ONLY two real `execute` call-sites), `placeholders.py` (adapt the 3 placeholder `execute` signatures; `registry.py` unchanged — it only instantiates), `tests/test_operations.py` (adapt via `OperationInput.from_loaded`). → LLR-005.1/.2.
> - **I1b — CRC engine + co-located doc, headless (3 files):** `operations/crc.py` (NEW, compute core), `operations/requirements/REQ-crc.md` (NEW co-located doc — C-7; lands here, where the operation first becomes real, rather than in I1a to keep I1a's atomic call-site migration at 5), `tests/test_crc_engine.py` (NEW). → LLR-001.1/.2/.3, LLR-005.3.
> - **I2 — config sourcing + check, headless (5 files):** `operations/crc_config.py` (NEW reader) or config in `crc.py`, `examples/crc_config.example.json` (NEW dummy), `crc.py` (check/compare + read-stored), `tests/test_crc_config.py` (NEW), `tests/test_crc_operation.py` (NEW). → LLR-004.1, LLR-002.1/.2.
> - **I3 — TUI surface: config text + op-result view + worker-thread (3 files):** `screens.py` (config text widget + per-region result rows), `app.py` (`@work(thread=True)` migration), `tests/test_tui_crc_surface.py` (NEW pilot). → LLR-004.2, LLR-002.3, LLR-002.4(view).
> - **I4 — persistent report integration (≤3 files):** `report_service.py` (NEW CRC report section consuming `crc_regions`), `tests/test_report_crc.py` (NEW), `app.py` (wire op result → report, if needed). → LLR-002.5(report), LLR-003.5(report).
> - **I5 — inject + emit + verify + two-stage confirm (5 files):** `crc.py` (inject), `screens.py` (confirm modal), `app.py` (confirm + emit wiring), `tests/test_crc_operation.py` (inject/emit/verify), `tests/test_tui_crc_surface.py` (confirm pilot). → LLR-003.1/.2/.3/.4.
>
> Every test FILE path / `-k` selector / node id named below is **provisional-until-Phase-3** (V-5); implemented names are reconciled from the real tree at Phase 4. Symbols flagged `NEW — created in Phase 3` do not yet exist; symbols with a `file:line` citation were grep-verified at draft time (2026-06-16, re-verified at iter-2).

---

#### HLR-005 — Neutral input contract + `OperationResult` widening (increment I1a, FIRST)

### LLR-005.1 — Neutral operation input object
- **Traceability:** HLR-005
- **Statement:** The operations package shall define a neutral input dataclass (e.g. `OperationInput`, `NEW — created in Phase 3`) carrying at minimum `mem_map: dict[int, int]`, `ranges: list[tuple[int, int]]`, and identifying metadata (`input_path: Optional[Path]`, `variant_id: Optional[str]`, `file_type: str`); `Operation.execute` shall accept this neutral input instead of a `LoadedFile`; and the service entry point `run_operation` (`operation_service.py:38`, `run_operation(operation_id, loaded, *, now_fn)`) shall construct the neutral input and pass it to `execute`, so BOTH the service path and the direct `OperationsScreen` call-site are migrated off the `LoadedFile` binding.
- **Validation:** `test (unit)`
- **Executed verification:** `pytest -q tests/test_operations.py` (EXISTING: `tests/test_operations.py`) adapted + a new construction test asserting the neutral input exposes `mem_map`/`ranges`/metadata; verify `LoadedFile` fields map cleanly (`models.py:39-52` — `file_type`, `mem_map`, `ranges`, `range_validity`, `row_bases`, `a2l_path`, `variant_id`).
- **Numeric pass threshold:** neutral input exposes `mem_map` + `ranges` + 3 metadata fields (5 fields min, presence assertion); `tests/test_operations.py` 100% pass after adaptation (0 regressions).
- **Acceptance criteria (informative):**
  - **Two migrated surfaces (F-A-02):** (1) the service `run_operation` (`operation_service.py:38`) builds an `OperationInput` from its `loaded` arg before calling `execute`; (2) the direct call-site `OperationsScreen` (`screens.py:636`, currently `operation.execute(self.loaded, now_fn=None)`) builds the neutral input from `self.loaded`. `operation_service.py` is a DEFINITE edit (not "maybe").
  - **Test reconciliation (chosen mechanism):** a `LoadedFile → OperationInput` adapter (e.g. `OperationInput.from_loaded(loaded)`) is provided so existing `tests/test_operations.py` calls that pass a `LoadedFile` keep working with a one-line wrap; the 3 placeholder operations' `execute` bodies change signature only (they ignore the input today). No operation method signature references `LoadedFile` directly; `LoadedFile` reuse is at the adapter/construction site only.

### LLR-005.2 — `OperationResult` widened with per-region CRC payload (contract-touch)
- **Traceability:** HLR-005
- **Statement:** `OperationResult` (`s19_app/tui/operations/model.py:27`) shall gain one optional structured field carrying the per-region CRC payload (e.g. `crc_regions: Optional[list[CrcRegionResult]] = None`, `NEW`), defaulting to `None` so existing producers (the three placeholders, `placeholders.py:63`) construct unchanged, and `STATUS_DOMAIN` (`model.py:23`) shall remain `{"placeholder","ok","error"}` unchanged.
- **Validation:** `test (unit)` + `inspection`
- **Executed verification:** `pytest -q tests/test_operations.py` (EXISTING) green post-change; `inspection` of `model.py` confirming the 7 canonical fields (`operation_id`, `status`, `input_path`, `variant_id`, `output`, `notes`, `timestamp_utc` — `model.py:94-100`) are unchanged and the new field is optional with a default.
- **Numeric pass threshold:** `tests/test_operations.py` 100% pass (0 regressions); `OperationResult` = 7 original fields + 1 optional new field (field-count assertion); `STATUS_DOMAIN` unchanged (equality assertion); `to_dict()` (`model.py:122`) still serializes deterministically and the new field is represented when present.
- **Acceptance criteria (informative):**
  - **Contract-touch note (batch-07 B-1/B-2 rule):** this LLR adds a field to `OperationResult`. The §6.2 producer/consumer identity table is the canonical field set; any later edit adding another result field re-opens that table for a re-run. Recorded producers: CRC operation (`status="ok"/"error"`), the 3 placeholders (`status="placeholder"`, payload `None`). Recorded consumers: `OperationsScreen` result surface (`screens.py:637-650`), the report service, `to_dict()`.
  - `CrcRegionResult` (`NEW`) carries: `output_address: int`, `computed_crc: int`, `stored_value: Optional[int]`, `matched: Optional[bool]`, `written: bool`.
  - **`OperationResult.output` contract for the CRC op (F-Q-02):** `output` stays the existing non-optional `LoadedFile` (`model.py:98`) — NOT widened optional. The CRC op populates it as: **check path** → the input snapshot UNCHANGED (a `LoadedFile` over the same `mem_map`, so the consumer's `render_hex_view_text(result.output.mem_map, …)` at `screens.py:642-644` keeps working and renders the unmodified image); **inject path** → a `LoadedFile` over the INJECTED `mem_map` (so the rendered hex shows the written CRC bytes). TC-115 asserts `output.mem_map == input.mem_map` (check); TC-125 asserts `output.mem_map` carries the 4 injected LE bytes at each output address.

### LLR-005.3 — Co-located `REQ-crc.md` operation requirements doc
- **Traceability:** HLR-005 (C-7 mandate)
- **Statement:** The batch shall create `s19_app/tui/operations/requirements/REQ-crc.md` (`NEW — created in Phase 3`) capturing the CRC operation's own HLR/LLR-level requirements; app-level docs (`REQUIREMENTS.md`, this 01-requirements) shall reference it and shall not inline the operation requirements.
- **Validation:** `inspection`
- **Executed verification:** `inspection` — `Glob s19_app/tui/operations/requirements/REQ-crc.md` returns the file (probe at draft 2026-06-16: directory `s19_app/tui/operations/requirements/` does NOT yet exist — `Glob s19_app/tui/operations/**` returned only `__init__.py`, `model.py`, `placeholders.py`, `registry.py`; so this is genuinely `NEW`, counted in the increment file budget); `REQUIREMENTS.md` contains a reference line pointing at it.
- **Numeric pass threshold:** file exists (1 file); `REQUIREMENTS.md` reference present (≥1 grep hit for `REQ-crc.md`); 0 operation-level requirements inlined into app docs.
- **Acceptance criteria (informative):**
  - The doc follows the operations-module convention (per-operation HLR/LLR live WITH the module, MEMORY note `project_operations_module_conventions`).

---

#### HLR-001 — CRC32 compute engine (increment I1b, after the contract)

### LLR-001.1 — Parameterized CRC32 core with segment chaining
- **Traceability:** HLR-001
- **Statement:** The CRC engine module (`s19_app/tui/operations/crc.py`, `NEW — created in Phase 3`) shall implement a function computing a CRC32 over an ordered byte stream parameterized by polynomial, init, reverse (reflected in/out) flag, and final-XOR, such that with the default params (poly `0x04C11DB7`, init `0xFFFFFFFF`, reverse `true`, xorout `0xFFFFFFFF`) the result equals `zlib.crc32` over the same bytes.
- **Validation:** `test (unit)`
- **Executed verification:** `pytest -q tests/test_crc_engine.py` (`NEW`) comparing the engine output to `zlib.crc32(bytes)` for ≥3 byte vectors (empty, short, multi-KB); a non-default-param vector against an independently computed reference.
- **Numeric pass threshold:** engine output == `zlib.crc32` reference for every default-param vector (exact 32-bit equality); non-default-param vector matches its reference; 100% of engine TCs pass.
- **Acceptance criteria (informative):**
  - Pure function — no I/O, no Textual import, no `mem_map` mutation.
  - The reverse flag selects standard refin/refout semantics (zlib convention when `true`).

### LLR-001.2 — Region byte assembly: sort, filter, segment-split, chain
- **Traceability:** HLR-001
- **Statement:** The engine shall, for each region `(start, end)`, select only present `mem_map` addresses within the region, order them ascending (FR2), split into contiguous segments on any gap (`current == previous + 1`, FR4), insert no bytes for gaps (FR7), and feed the concatenated segments through one non-resetting CRC state (`crc = init`; per segment `crc = update(segment, crc)`, FR8) before the final XOR (FR9-apply).
- **Validation:** `test (unit)`
- **Executed verification:** `pytest -q tests/test_crc_engine.py` (`NEW`): a fixture with two segments separated by a gap yields the SAME CRC as the gap-free concatenation of those segment bytes (proving no-reset + no-gap-bytes); membership filtering uses `range_index` primitives (`build_sorted_range_index` `range_index.py:9`, `address_in_sorted_ranges` `range_index.py:39`) — import-only reuse of the frozen module.
- **Numeric pass threshold:** gapped-two-segment CRC == concatenated-bytes CRC (exact equality); 0 bytes emitted for gap addresses (byte-count assertion); 100% pass.
- **Acceptance criteria (informative):**
  - `range_index` reuse is import-only; no edit to `range_index.py` (engine-frozen).

### LLR-001.3 — Per-region computed CRC payload (no mutation)
- **Traceability:** HLR-001
- **Statement:** The engine entry point shall accept the neutral input (LLR-005.1) plus the parsed config and return one computed CRC per configured region without mutating the input `mem_map` or `ranges`.
- **Validation:** `test (unit)`
- **Executed verification:** `pytest -q tests/test_crc_engine.py` (`NEW`): a multi-region fixture returns one CRC per region in config order; a pre/post deep-equality assertion on the input `mem_map` confirms zero mutation.
- **Numeric pass threshold:** returned CRC count == region count; input `mem_map` byte-for-byte equal pre/post (0 changed addresses); 100% pass.
- **Acceptance criteria (informative):**
  - Output ordering follows config region order (deterministic).

---

#### HLR-004 — CRC config sourcing + TUI text surface (increments I2–I3)

### LLR-004.1 — External JSON config reader (resolve + parse + collect)
- **Traceability:** HLR-004
- **Statement:** A config reader (in `s19_app/tui/operations/crc.py` or a sibling `crc_config.py`, `NEW`) shall resolve the operator-supplied path via `resolve_input_path` (`workspace.py:469`), enforce the `READ_SIZE_CAP_BYTES` size cap before reading (`io.py:192`, the same 256 MB cap `read_change_document` applies — over-cap → one collected error, no read), parse the JSON into a typed `CrcConfig` dataclass (`NEW`: `regions: list[CrcRegion]`, each `start`/`end`/`output_address`; `polynomial: int`; `init: int`; `reverse: bool`; `final_xor: int`), and on an unresolvable/over-cap path or invalid JSON record exactly one collected error and return no config — never raising on a data-quality fault (the `read_change_document` collect-don't-abort contract, `io.py:266-303`).
- **Containment posture (F-S-02, accepted, NOT a defect):** `resolve_input_path` (`workspace.py:471-473`) returns an existing ABSOLUTE path VERBATIM — containment (cwd/base_dir/repo-root walk) applies only to the RELATIVE branch (`:474-482`). This config read is therefore **uncontained by design**, at parity with `read_change_document` (`io.py:266`): accepted because it is a read-only, operator-supplied JSON parsed into a typed config and never written back, size-capped, collect-don't-abort. Work-area containment of the config FILE is explicitly a NEW out-of-scope requirement (recorded in REQ-crc.md / D-7). The earlier "(cwd + repo-root walk)" framing was inaccurate and is corrected here and in HLR-004.
- **Validation:** `test (unit)`
- **Executed verification:** `pytest -q tests/test_crc_config.py` (`NEW`): valid dummy template → populated `CrcConfig`; nonexistent path → 1 error, `None` config (`resolve_input_path` returns `None` on unresolvable, `workspace.py:483`); malformed JSON → 1 error, `None` config.
- **Numeric pass threshold:** valid template → all required fields non-null; each failure mode → exactly 1 collected error AND 0 CRC computations; 100% pass.
- **Acceptance criteria (informative):**
  - **AC-artifact (batch-08 B-1 rule):** the in-repo dummy/example template `examples/crc_config.example.json` (`NEW — created in Phase 3`, counted in file budget) — draft-time probe `Glob examples/**/crc*.json` 2026-06-16 → 0 files, confirming it must be created. The synthetic test fixtures referencing it are also `NEW`.
  - The template carries DUMMY values only (fake poly/init/ranges/output-addresses); no real per-firmware values committed.

### LLR-004.2 — TUI editable text config surface (dummy pre-fill)
- **Traceability:** HLR-004
- **Statement:** The CRC operation surface shall present the config as editable text pre-filled with the dummy template values for format guidance, route the edited/loaded config through LLR-004.1, and surface a config-load error as a status/notice without running the CRC computation.
- **Validation:** `demo` + `test (integration)`
- **Executed verification:** `demo` — launch `s19tui`, open the CRC operation, observe dummy values pre-filled, edit a field, run, observe the computation uses the edited values; `pytest -q tests/test_crc_operation.py` (`NEW`) covering the config-error→no-compute path through the surface (story-dimension reachability, A-5: exercised through the call-site, not only the reader API).
- **Numeric pass threshold:** demo shows dummy pre-fill + edit-takes-effect; config-error path surfaces 1 notice and runs 0 computations; integration TC passes.
- **Acceptance criteria (informative):**
  - The surface lives in `screens.py` / `app.py` (UI state only); parse/compute lives in the service/engine (thread-split + service-extension rule). `screens.py`/`app.py` structural shape is **gate-confirm at increment** (A-2).

---

#### HLR-002 — CRC region check + compare + report (increments I2–I4)

### LLR-002.1 — Read stored 4-byte LE value at each output address
- **Traceability:** HLR-002
- **Statement:** The check path shall read the 4-byte little-endian value at each region's output address from `mem_map` (`value = mem_map[a] | mem_map[a+1]<<8 | mem_map[a+2]<<16 | mem_map[a+3]<<24`), and if any of the four addresses is absent from `mem_map`, then it shall report that output address as "no stored value" rather than raising.
- **Validation:** `test (unit)`
- **Executed verification:** `pytest -q tests/test_crc_operation.py` (`NEW`): a fixture with a full 4-byte stored value decodes to the expected int; a fixture missing the high byte reports "no stored value" with no exception.
- **Numeric pass threshold:** decoded value == expected LE int (exact); missing-address case → "no stored value" verdict, 0 exceptions; 100% pass.
- **Acceptance criteria (informative):**
  - 4-byte LE codec is FIXED (not parameterized) per the locked decision.

### LLR-002.2 — Compare + per-region report payload (non-mutating)
- **Traceability:** HLR-002
- **Statement:** The check path shall, for each region, compare the computed CRC (HLR-001) to the stored 4-byte LE value (LLR-002.1), populate the `OperationResult.crc_regions` payload (LLR-005.2) with `output_address`, `computed_crc`, `stored_value`, `matched`, return `status="ok"`, and shall not modify the loaded `mem_map`.
- **Validation:** `test (integration)`
- **Executed verification:** `pytest -q tests/test_crc_operation.py` (`NEW`): matching fixture → `matched=True`; mismatching fixture → `matched=False`; pre/post `mem_map` equality → 0 mutation; result rendered in the `OperationsScreen` surface (`screens.py:637-650` consumer).
- **Numeric pass threshold:** `matched` flag == (`stored == computed`) for every region; input `mem_map` unchanged (0 changed addresses); `status == "ok"`; 100% pass.
- **Acceptance criteria (informative):**
  - The populated `crc_regions` payload feeds BOTH surfaces (F-A-01): the operations-result view (LLR-002.4) AND the persistent project report (LLR-002.5). This LLR only PRODUCES the payload (headless); rendering is those two LLRs.
  - **Plain-text messaging (F-S-04):** any per-region or config-error line interpolating a resolved path / reader-issue string is emitted as PLAIN text (no Rich markup), mirroring `app.py:3606`.

### LLR-002.3 — Check execution migrates to worker-thread (R-6, no UI-thread compute)
- **Traceability:** HLR-002 (R-6 inheritance)
- **Statement:** The CRC operation's execution shall run on a Textual thread-worker (the `@work(thread=True, …)` `execute_scope` precedent, `app.py:1599`) rather than synchronously on the UI thread, with status/result marshalled back to the UI thread via `call_from_thread`.
- **Validation:** `inspection` + `test (integration)`
- **Executed verification:** `inspection` — the CRC execution path is decorated `@work(thread=True, …)` (the current call-site `screens.py:636` runs `operation.execute(...)` SYNCHRONOUSLY on the UI thread — confirmed at draft, this is the R-6 gap being closed); `pytest -q tests/test_crc_operation.py` exercises the headless service path off-thread-equivalently (the service is thread-agnostic and unit-tested directly).
- **Numeric pass threshold:** the CRC execute path carries the `@work(thread=True)` decorator (grep/inspection, 1 hit); headless service TC passes; UI-thread synchronous compute removed (0 hits for synchronous `operation.execute` in the CRC path post-change).
- **Acceptance criteria (informative):**
  - `app.py`/`screens.py` worker wiring shape is **gate-confirm at increment** (A-2 / structural).

### LLR-002.4 — Render per-region CRC results in the operations-result view (surface 1 of 2)
- **Traceability:** HLR-002 (F-A-01 surface a)
- **Statement:** The operations-result view (`screens.py`, current consumer `:637-650`) shall render one row per `crc_regions` entry showing the output address, computed CRC, stored value, and match/mismatch verdict, so the operator sees the check outcome immediately after running the operation.
- **Validation:** `test (e2e pilot)`
- **Executed verification:** `pytest -q tests/test_tui_crc_surface.py` (`NEW`): an `App.run_test()` pilot runs the CRC check through `OperationsScreen` → `run_operation` and asserts the per-region rows (incl. a mismatch row) appear in the result surface — the THROUGH-HANDLER reachability proof (A-5), not a direct service read.
- **Numeric pass threshold:** one rendered row per region; the mismatch row shows the mismatch verdict; pilot reaches the rows via the handler call-site (not the service kwargs); 100% pass.
- **Acceptance criteria (informative):**
  - View rendering only (UI state); the payload comes from LLR-002.2. `screens.py` row-rendering shape is **gate-confirm at increment** (A-2). Increment I3.

### LLR-002.5 — Render per-region CRC results in the persistent project report (surface 2 of 2)
- **Traceability:** HLR-002 (F-A-01 surface b)
- **Statement:** The project report generated by `report_service.py` (`generate_project_report`, `report_service.py:913`) shall include a CRC section rendering each `crc_regions` entry (output address, computed CRC, stored value, match/mismatch), so the check outcome is captured in the persistent report.
- **Validation:** `test (integration)`
- **Executed verification:** `pytest -q tests/test_report_crc.py` (`NEW`): a report generated with a CRC result containing match + mismatch regions contains the CRC section with the correct per-region verdicts.
- **Numeric pass threshold:** report text contains one CRC line per region with the correct verdict; absent a CRC result the section is omitted (no empty section); 100% pass.
- **Acceptance criteria (informative):**
  - **NEW integration (F-A-01):** `report_service.py` does NOT consume `OperationResult` today (it renders `VariantExecutionResult`-based project reports, grep-confirmed `report_service.py:913/577/619`); wiring a CRC section fed by `crc_regions` is net-new. The exact seam (a new `_crc_section_lines(...)` helper + a call site in `generate_project_report`, and how the CRC `OperationResult` reaches the report generator) is **gate-confirm at increment I4**. `report_service.py` is NOT in either frozen set.
  - Plain-text path interpolation (F-S-04) applies here too.

---

#### HLR-003 — CRC inject + emit + verify (increment I5)

### LLR-003.1 — Inject 4-byte LE CRC with write-into-gap range extension
- **Traceability:** HLR-003
- **Statement:** The inject path shall write each computed CRC as 4 little-endian bytes at its output address into a COPY of the `mem_map`, and if an output address falls outside every loaded range, then it shall extend the working `mem_map` and `ranges` to include the 4 new addresses (so `emit_s19_from_mem_map` finds every claimed address), without mutating the originally loaded snapshot.
- **Validation:** `test (unit)`
- **Executed verification:** `pytest -q tests/test_crc_operation.py` (`NEW`): in-range output → 4 bytes set in the working copy; gapped output → `ranges` gains a range covering the 4 addresses and `mem_map` gains exactly 4 keys; original snapshot `mem_map` unchanged.
- **Numeric pass threshold:** 4 LE bytes correctly placed per output (exact byte values); gap case adds exactly 4 `mem_map` keys + covering range; original snapshot 0 mutations; 100% pass.
- **Acceptance criteria (informative):**
  - The 4-byte LE write is the inverse of the LLR-002.1 read; same fixed codec.
  - Guards against the `emit_s19_from_mem_map` `KeyError` (`io.py:1331`) on a range claiming an absent address — extension ensures every range address is present.
  - **Range merge/order (F-A-06, closes RK-6):** the working `ranges` shall be kept SORTED and non-overlapping after extension (a gap-output range is merged into an adjacent range if contiguous, else inserted in ascending-start order). Record ordering in the emitted S19 follows `ranges` order (`io.py:1336`); the re-parse-equality oracle (LLR-003.2) is order-INSENSITIVE (mem_map compare), so it cannot catch a mis-ordered-but-equivalent emit — RK-6 is therefore closed by this sorted-merge requirement plus reasoning, not by the oracle. A unit assertion on the post-extension `ranges` (sorted, non-overlapping) is the executable check.

### LLR-003.2 — Emit modified S19 via `emit_s19_from_mem_map` into contained work area
- **Traceability:** HLR-003
- **Statement:** The emit path shall serialize the injected `mem_map` + `ranges` to S19 text via `emit_s19_from_mem_map` (`io.py:1300`, signature `(mem_map, ranges) -> str`) and place it into the contained work area through the SAME containment seam batch-11 uses (F-S-01) — staged under `.s19tool/workarea/temp/` then placed via `copy_into_workarea` (`workspace.py:215`), OR with the resolved target validated by `_find_workarea_root` + `is_relative_to(workarea_root)` + `_path_traverses_reparse_point` (`workspace.py:278-291`); and if the resolved target fails containment, then the system shall record a collected finding and write no file (collect-don't-abort).
- **Validation:** `test (integration)`
- **Executed verification:** `pytest -q tests/test_crc_operation.py` (`NEW`): emitted text re-parses via `S19File` to a `mem_map` equal to the injected map with 0 load errors (the `emit_s19_from_mem_map` acceptance contract, `io.py:1339-1341`); the RESOLVED output path satisfies `resolved.is_relative_to(workarea_root)` (mirroring `tests/test_unified_write.py:297`), NOT a string-prefix check; a target outside the work area yields 1 collected finding and 0 files.
- **Numeric pass threshold:** re-parsed `mem_map` == injected `mem_map` (exact); 0 S19 load errors; `resolved.is_relative_to(workarea_root)` True for the in-area case; escaping target → 1 finding + 0 files; 100% pass.
- **Acceptance criteria (informative):**
  - `emit_s19_from_mem_map` reuse is import-only from `tui/changes/io.py` (NOT frozen `hexfile.py`); the containment helpers (`copy_into_workarea` / `_find_workarea_root` / `is_relative_to` / `_path_traverses_reparse_point`) are import-only reuse of `workspace.py` (not frozen).
  - **No overwrite (F-S-03):** the emit shall not clobber an existing work-area artifact — name-dedup on collision per `copy_into_workarea` (`workspace.py:300`). Routing the place-step through `copy_into_workarea` inherits this for free.

### LLR-003.3 — Verify the written image (reader-as-oracle)
- **Traceability:** HLR-003
- **Statement:** After the write, the verify path shall call `verify_written_image(written_path, intended_mem_map, "s19")` (`verify.py:119`) where `intended_mem_map` is the INJECTED working copy that was emitted (not the original snapshot, not the re-parsed map — F-Q-05), and surface `VerifyResult.status` (`verify.STATUS_VERIFIED == "verified"`, `verify.py:28`) — quiet on `verified`, loud (naming the path + drift) on `mismatch` — into the report.
- **Validation:** `test (integration)`
- **Executed verification:** `pytest -q tests/test_crc_operation.py` (`NEW`): a clean write → `status == verify.STATUS_VERIFIED` ("verified"), `runs == []`; a deliberately corrupted write → `status == "mismatch"` with non-empty `runs` (this negative case guards against a tautological self-compare).
- **Numeric pass threshold:** clean write → `"verified"` + 0 diff runs; corrupted write → `"mismatch"` + ≥1 run; 100% pass.
- **Acceptance criteria (informative):**
  - 4th reader-as-oracle reuse; `verify_written_image` / `VerifyResult` import-only from `tui/changes/verify.py`.
  - **`intended_mem_map` identity (F-Q-05):** it is the same injected `mem_map` object handed to `emit_s19_from_mem_map`, so a `verified` result proves the write/re-read round-trip, not a self-comparison.
  - **Plain-text messaging (F-S-04):** verify-mismatch / write-refusal messages that interpolate the resolved output path or a reader-issue string shall pass it as PLAIN text (no Rich-markup interpolation), mirroring `_surface_manifest_verify_result` (`app.py:3606`). The 5 MB rotating log's existing path-logging posture (`app.py:3590`) is the accepted one (no secret/credential surface in a firmware CRC tool).

### LLR-003.4 — Two-stage operator confirmation gates the write (R-6)
- **Traceability:** HLR-003 (FR9 two-stage, R-6 inheritance)
- **Statement:** The write stage shall execute only after an explicit per-execution operator confirmation following the check (stage 1 = check/compare, stage 2 = confirm→write), and if the operator does not confirm, then the system shall write no file and leave the loaded snapshot unchanged.
- **Validation:** `test (integration)` + `demo`
- **Executed verification:** `pytest -q tests/test_crc_operation.py` (`NEW`): confirmation=False → 0 files written (filesystem assertion), snapshot unchanged; confirmation=True → file written + verified. `demo` — run in `s19tui`, decline the confirm (no file), then accept (file appears + verify-OK).
- **Numeric pass threshold:** no-confirm path writes 0 files AND 0 snapshot mutations; confirm path writes 1 verified file; 100% pass; demo shows both branches.
- **Acceptance criteria (informative):**
  - Confirmation + worker-thread + sanitized path are the R-6 mandatory inheritances; security-reviewer sign-off required before merge (write path + operator-supplied config path + emitted output path).
  - The confirmation modal shape in `screens.py`/`app.py` is **gate-confirm at increment** (A-2).

### LLR-003.5 — Render the inject/emit/verify outcome in the persistent project report (surface 2 of 2)
- **Traceability:** HLR-003 (F-A-01 surface b)
- **Statement:** The project report generated by `report_service.py` shall include, for a confirmed write, the emitted modified-S19 path, the per-region written CRC values, and the verify verdict (`verified`/`mismatch`), so the write outcome is captured in the persistent report; and if no write was confirmed, then the report shall record the check-only outcome without a write section.
- **Validation:** `test (integration)`
- **Executed verification:** `pytest -q tests/test_report_crc.py` (`NEW`): a report from a confirmed-write CRC result contains the emitted path + verify verdict; a check-only result contains no write section.
- **Numeric pass threshold:** confirmed-write report contains the path + `verified`/`mismatch` verdict; check-only report has 0 write-section lines; 100% pass.
- **Acceptance criteria (informative):**
  - Same NEW `report_service.py` integration as LLR-002.5 (increment I4); paths interpolated as PLAIN text (F-S-04).

---

## 5. Validation strategy

> Authored by qa-reviewer (Phase 1). Method discipline (batch-02/03 root-cause rule): every `test`/`analysis` requirement names its executed verification + numeric pass threshold at draft time. TC ids are a promise of a real node (verbatim-node-id discipline) and are **provisional until Phase 3** (V-5: file path + `-k` selector + node id all reconcile from the real tree at Phase 4).

### 5.1 Methods

| Area (FR / US) | Method | Justification |
|---|---|---|
| **CRC engine correctness** (FR5, FR9 final-XOR) | `test (unit)` + `analysis` | A self-consistent CRC can be wrong in lockstep with its own test. Method = `test` against a **known-answer vector** — IEEE/zlib CRC-32 of `b"123456789"` = `0xCBF43926` — plus `analysis` that the default params (poly `0x04C11DB7`, init/xorout `0xFFFFFFFF`, refin/refout) reproduce that constant. Anchor that the engine is *really* CRC-32, not just internally consistent. |
| **Segment reconstruction & chaining** (FR4, FR7, FR8) | `test (unit)` | Contiguity (`current == previous + 1`), gap-splitting, no-gap-bytes-inserted, single-CRC-state-across-segments are deterministic. Chaining fixture needs a gap whose chained CRC ≠ CRC of either segment alone, so the test fails if a future edit resets state (Rule 9). |
| **Address ordering** (FR2) | `test (unit)` | Feed descending order; assert CRC equals ascending-order CRC. |
| **Region filtering** (FR3) | `test (unit)` | `range_index` membership; assert out-of-region bytes never enter the digest. |
| **4-byte LE codec** (US-011/US-012 stored-value contract) | `test (unit)` | Encode→decode round-trip of a known u32 to/from little-endian. |
| **Compare / check semantics** (FR6, US-011) | `test (unit/integration)` | Match AND mismatch are observable boolean outcomes against a synthetic image. |
| **Inject + emit + reader-as-oracle** (FR6, FR9 stage 2, US-012) | `test (integration)` | mutate `mem_map` → `emit_s19_from_mem_map` → re-read via `verify_written_image` → assert re-read matches intent. 4th reuse of reader-as-oracle; oracle is executable. |
| **Write-into-gap extends ranges** (US-012) | `test (unit)` | Assert `mem_map` AND `ranges` both grow when the output address lands in a gap. |
| **No write without confirmation** (FR9 two-stage, R-6) | `test (integration)` | Negative test: drive write path without confirmation; assert no file emitted. |
| **Config sourcing from JSON** | `test (integration)` + `inspection` | `test`: load params from **synthetic** JSON via `resolve_input_path`. `inspection`: confirm no real per-firmware config committed (dummy template + synthetic fixtures only). |
| **Config-never-in-repo guard** | `inspection` | Static tree review: name the dummy template, assert fake values, zero real config. Negative `test` companion: suite needs no real config to pass. |
| **TUI surface reachability** (TUI-only) | `test (e2e pilot)` + `demo` | `test`: `App.run_test()` pilot drives `crc` through `OperationsScreen`→`run_operation`, asserting the result reaches the report surface (A-5: exercise the SHIPPED handler, not only service kwargs). `demo`: operator observes per-region match/mismatch + modified-S19 confirmation. |
| **REQ-crc.md co-location** (C-7) | `inspection` | Confirm `s19_app/tui/operations/requirements/REQ-crc.md` exists (NEW, I1) and app docs reference rather than inline. |
| **Frozen-set clearance** (A-4 census) | `inspection` | Confirm no planned file diffs a frozen engine path; `_ENGINE_PATHS` guards are the executable backstop. |

> **Load-bearing threshold:** TC-101 must assert `crc32(b"123456789", default_config) == 0xCBF43926`. Without it the engine is only proven self-consistent. Oracle round-trip (TC-123) asserts `VerifyResult.status == verify.STATUS_VERIFIED` (`"verified"`, `verify.py:28`) and empty diff `runs` (match the real `verify.py` return type, not a hand-rolled `mem_map ==`).

### 5.2 Coverage table

| TC ID | Story / AC | Inc | Intent (the WHY) | Provisional node (NEW unless cited) |
|---|---|---|---|---|
| **TC-101** | FR5 / FR9 | I1b | **KAT anchor** — default config reproduces CRC-32 of `b"123456789"` → `0xCBF43926`. | `tests/test_crc_engine.py::test_known_answer_vector` (NEW) |
| TC-102 | FR8 | I1b | Segment chaining — two gap-separated segments, ONE CRC state; chained CRC ≠ either alone (fails if state resets). | `tests/test_crc_engine.py::test_segment_chaining_does_not_reset_state` (NEW) |
| TC-103 | FR4 / FR7 | I1b | Gap-splitting inserts NO bytes; gap bytes never enter the digest. | `tests/test_crc_engine.py::test_gap_splits_segments_no_inserted_bytes` (NEW) |
| TC-104 | FR2 | I1b | Ascending-address ordering — descending input yields ascending CRC. | `tests/test_crc_engine.py::test_ascending_address_ordering` (NEW) |
| TC-105 | FR3 | I1b | Region filtering — only in-range bytes enter the digest. | `tests/test_crc_engine.py::test_region_filter_excludes_out_of_range` (NEW) |
| TC-106 | FR9 / FR1 params | I1b | Parameterization WIRED — non-default poly/init/reverse/xorout changes the digest vs the default (proves params are real inputs). **NOT a correctness anchor:** absolute correctness of a non-zlib convention is RK-3-deferred to an operator-sourced reference vector (see §5.5 flag 4, §6.3 RK-3). NOT in §5.3 gating set. | `tests/test_crc_engine.py::test_config_params_change_result` (NEW) |
| TC-107 | US-011 stored-value | I1b | 4-byte LE codec round-trip. | `tests/test_crc_engine.py::test_le_codec_roundtrip` (NEW) |
| **TC-108** | LLR-005.1 | I1a | Neutral `OperationInput` exposes `mem_map`+`ranges`+metadata; `from_loaded` adapter maps `LoadedFile` cleanly. | `tests/test_operations.py::test_operation_input_exposes_mem_map_ranges_metadata` (NEW) |
| **TC-109** | LLR-005.2 | I1a | `OperationResult` widened: field count == 7+1 optional; `STATUS_DOMAIN` unchanged; `to_dict` deterministic + represents the new field when present. | `tests/test_operations.py::test_operation_result_widened_field_count_and_status_domain` (NEW) |
| **TC-116** | LLR-002.3 | I3 | `inspection` — CRC execute path carries `@work(thread=True)`; 0 synchronous `operation.execute` in the CRC path. | `tests/test_tui_crc_surface.py` / inspection (NEW) |
| **TC-117** | LLR-002.5 (report, F-A-01) | I4 | Persistent report contains a CRC section with per-region match/mismatch verdicts; omitted when no CRC result. | `tests/test_report_crc.py::test_report_contains_crc_check_section` (NEW) |
| **TC-126** | LLR-003.5 (report, F-A-01) | I4 | Confirmed-write report contains emitted path + verify verdict; check-only report has no write section. | `tests/test_report_crc.py::test_report_contains_crc_write_section` (NEW) |
| **TC-111** | US-011 AC (match) | I2 | Compare MATCH — stored 4-byte LE == computed → match, file untouched (assert input unchanged). | `tests/test_crc_operation.py::test_check_reports_match_nonmutating` (impl) |
| TC-112 | US-011 AC (mismatch) | I2 | Compare MISMATCH per output address; file untouched. | `tests/test_crc_operation.py::test_check_reports_mismatch` (impl) |
| TC-113 | config sourcing | I2 | Params loaded from **synthetic** JSON via `resolve_input_path`. | `tests/test_crc_config.py::test_params_loaded_from_synthetic_json` (NEW) |
| TC-114 | config-never-in-repo | I2 | **NEGATIVE (concrete, F-Q-07)** — `Glob examples/**/crc*.json` returns ONLY `crc_config.example.json` AND it parses with the documented dummy hex; fails if any real config is ever committed. Also satisfies the LLR-004.1 AC-artifact probe. | `tests/test_crc_config.py::test_no_real_config_required` (NEW) |
| **TC-115** | US-011 surface (A-5) | I2 | **Surface reachability** — pilot runs `crc` through `OperationsScreen`→`run_operation`; result reaches report (not only service return). | `tests/test_tui_crc_surface.py::test_crc_check_reaches_report_via_handler` (NEW) |
| **TC-121** | US-012 AC (inject) | I3 | Inject — computed CRC written as 4-byte LE at each output address. | `tests/test_crc_inject.py::test_inject_writes_le_at_output_address` (NEW) |
| TC-122 | US-012 (write-into-gap) | I3 | Write-into-gap EXTENDS both `mem_map` and `ranges`. | `tests/test_crc_inject.py::test_inject_into_gap_extends_ranges` (NEW) |
| **TC-123** | US-012 AC (oracle) | I3 | **Reader-as-oracle** — inject → emit → re-read via `verify_written_image` → `VerifyResult.status == VERIFIED`, empty diff. | `tests/test_crc_emit.py::test_modified_s19_reread_matches_intent` (NEW) |
| TC-124 | US-012 / FR9 two-stage | I3 | **No write without confirmation** — write path without confirmation emits no file. | `tests/test_crc_emit.py::test_no_write_without_confirmation` (NEW) |
| TC-125 | US-012 surface (A-5) | I3 | **Surface reachability** — pilot drives inject+emit through the confirmation surface; modified-S19 result reaches report. | `tests/test_tui_crc_surface.py::test_crc_inject_reaches_report_via_handler` (NEW) |
| TC-131 | C-7 mandate | I1b | `inspection` — `REQ-crc.md` co-located; app docs reference, not inline. | inspection — `s19_app/tui/operations/requirements/REQ-crc.md` (NEW) |
| TC-132 | A-4 census | I1b | `inspection` — planned files diff zero frozen path; `_ENGINE_PATHS` guards green. | `tests/test_engine_unchanged.py` (existing backstop) |

### 5.3 Batch acceptance criteria

- **Per-requirement validation passing:** 100% of LLRs covered by ≥1 TC with a recorded pass result; every `test`/`analysis` LLR carries its executed verification + numeric pass threshold.
- **KAT anchor green (gating):** TC-101 passes — `crc32(b"123456789", default_config) == 0xCBF43926`. A green suite with TC-101 absent does NOT satisfy the bar.
- **Reader-as-oracle round-trip green:** TC-123 — `VerifyResult.status == VERIFIED`, empty diff runs.
- **Surface reachability green:** TC-115 + TC-125 exercise the SHIPPED TUI handler call-site, not only `run_operation` kwargs (A-5).
- **Confirmation gate green:** TC-124 — no file emitted without operator confirmation (R-6).
- **Config hygiene:** TC-114 passes with zero real config in the tree; inspection TC-131/dummy-template confirms only dummy + synthetic committed.
- **Frozen-set clearance:** `pytest -q` green including `tests/test_engine_unchanged.py` and `tests/test_tui_directionb.py::test_tc031_*` — no diff vs `main` on any frozen engine path (A-4).
- **Full suite green:** `pytest -q` exits 0; `pytest -q -m "not slow"` also green.
- **No requirement without an assigned validation method**, and §6.4 reconciliation ledger reconciled.

### 5.4 Surface-reachability matrix (A-5 control — NEW this batch)

One row per input dimension named in US-011/US-012, confirming ≥1 TC exercises it **through the TUI handler call-site**, not only via direct kwargs (batch-11 SCOPE-1 lesson).

| Input dimension | Direct-service TC | Through-handler TC (A-5) | Status |
|---|---|---|---|
| Configured CRC range(s) | TC-105 | TC-115 | covered |
| Output address(es) | TC-111/TC-121 | TC-115, TC-125 | covered |
| Poly / init / reverse / xorout params | TC-106, TC-113 | TC-115 | covered — but **TC-106 proves params-WIRED only**; non-default CRC correctness is RK-3-deferred (F-A-07) |
| Stored 4-byte LE value (check) | TC-111/TC-112 | TC-115 | covered |
| Inject + modified-S19 emit | TC-121/TC-123 | TC-125 | covered |
| Operator confirmation (two-stage) | TC-124 | TC-125 | covered |
| Result in operations-result view (F-A-01 surface a) | — | TC-115 / LLR-002.4 | covered |
| Result in persistent project report (F-A-01 surface b) | TC-117/TC-126 | (report is non-interactive; integration TC) | covered |

> **TC-125 confirm must be pilot-driven (F-Q-06):** TC-125's confirmation interaction shall be driven through the Textual pilot (`pilot.press`/widget interaction), NOT by calling the write service with a `confirm=True` kwarg — otherwise it collapses into the headless TC-124 and the through-handler row is mislabeled. TC-124 (headless boolean) stays the no-confirm assertion.
>
> **Composition-LLR rule (A-5 part b):** if the handler wires the engine but defaults any dimension empty (e.g. hardcodes params instead of threading config-surface values), a COMPOSITION LLR for that wiring is required, or the dimension recorded out-of-scope explicitly. TC-115/TC-125 are the executable proof the wiring is not defaulted.

### 5.5 Testability flags (raised by qa — reconciled against the LLRs in §6.7)

1. **FR9 non-confirmation observable** — US-012 LLR must state what is observable when confirmation is withheld (no file at output path AND/OR a result token), else TC-124 cannot assert a pass.
2. **`OperationResult.status` domain vs check-vs-write** — `STATUS_DOMAIN = {"placeholder","ok","error"}` (`model.py:23`) has no match/mismatch token; the R-3 widening must decide whether match/mismatch rides a structured field or a status extension (changes TC-111/TC-112 assertions).
3. **Per-region CRC payload shape** — R-3 widening must define the per-region result (list of `{range, output_address, computed_crc, stored_value, match}`?) before TC-111/112/115 pin assertions.
4. **Variant known-answer for reverse=false** — TC-106 needs a documented variant vector, not a self-consistency check.
5. **Config schema unstated** — field names, range/output-address pairing, dummy-template path; dummy template is `NEW` (count in file budget); synthetic fixture via a `conftest.py` builder, not an ad-hoc literal.
6. **Oracle equality granularity** — TC-123 asserts `VerifyResult.status == VERIFIED` + empty `runs`, matching `verify.py:35`, not a hand-rolled `mem_map ==`.

**qa symbol verification (grep-confirmed):** `OperationResult`/`STATUS_DOMAIN` `model.py:27`/`:23`; `run_operation(operation_id, loaded, *, now_fn)` `operation_service.py:38`; `crc` placeholder `registry.py:15` + `placeholders.py:92`; `OperationsScreen` `screens.py:484`; `execute_scope` worker `app.py:1543`/`:1599` (`@work(thread=True)`); `emit_s19_from_mem_map` `io.py:1300`; `verify_written_image`/`VerifyResult` `verify.py:119`/`:35`; `resolve_input_path` `workspace.py:469`; `REQ-crc.md` absent → NEW in I1.

---

## 6. Appendices

### 6.1 Extended glossary
See §1.3 for the primary glossary. Additional draft-time-verified anchor symbols (grep-verified 2026-06-16):

| Symbol | Location | Role for this batch |
|--------|----------|--------------------|
| `OperationResult` | `s19_app/tui/operations/model.py:27` | Result envelope widened by LLR-005.2 (7 fields `model.py:94-100`; `STATUS_DOMAIN` `model.py:23`; `to_dict` `model.py:122`). |
| `Operation.execute` | `s19_app/tui/operations/model.py:228` (`@abstractmethod` at `:227`) | Signature `execute(self, loaded: LoadedFile, *, now_fn=…)` — the `LoadedFile` binding LLR-005.1 replaces (F-A-05 citation fix). |
| `run_operation` | `s19_app/tui/services/operation_service.py:38` | `run_operation(operation_id, loaded, *, now_fn)` — the service path also migrated to build `OperationInput` (F-A-02). |
| `generate_project_report` | `s19_app/tui/services/report_service.py:913` | Persistent project report (today `VariantExecutionResult`-based; does NOT consume `OperationResult` — F-A-01 adds a CRC section). |
| `run_operation` | `s19_app/tui/services/operation_service.py:38` | Headless service seam; CRC routes through it. |
| `OperationsScreen.<execute>` | `s19_app/tui/screens.py:636` | Call-site currently runs `operation.execute(self.loaded, now_fn=None)` **synchronously on the UI thread** — the R-6 gap LLR-002.3 closes. |
| `emit_s19_from_mem_map` | `s19_app/tui/changes/io.py:1300` | `(mem_map, ranges) -> str`; `KeyError` on a range claiming an absent address (`io.py:1331`); re-parse-equality acceptance contract (`io.py:1339`). |
| `read_change_document` | `s19_app/tui/changes/io.py:266` | Config-read precedent: `resolve_input_path` + `base_dir` + size probe, collect-don't-abort (`io.py:300-303`). |
| `verify_written_image` / `VerifyResult` | `s19_app/tui/changes/verify.py:119` / `:35` | Reader-as-oracle; `status` ∈ {verified, mismatch}, `runs`, `stats`, `written_path`. |
| `resolve_input_path` | `s19_app/tui/workspace.py:469` | cwd + repo-root walk; returns `None` on unresolvable (`workspace.py:483`). |
| `build_sorted_range_index` / `address_in_sorted_ranges` / `range_in_sorted_ranges` | `s19_app/range_index.py:9` / `:39` / `:71` | Membership primitives (FROZEN — import-only). |
| `_start_execute_scope_worker` | `s19_app/tui/app.py:1599` | `@work(thread=True, exclusive=True, group="execute_scope")` — R-6 worker-thread precedent. |
| `_write_and_verify_manifest` | `s19_app/tui/app.py:3539` | write→verify→surface orchestration precedent (R-6 write-and-verify). |
| `LoadedFile` | `s19_app/tui/models.py:9` | Fields `file_type`/`mem_map`/`row_bases`/`ranges`/`range_validity`/`a2l_path`/`variant_id` (`models.py:39-52`) — source for the neutral input. |

### 6.2 Relevant design decisions

**D-1 — Neutral operation input shape (C-7 / R-2).** Introduce `OperationInput` (`NEW`, dataclass in `operations/model.py` or a sibling) with `mem_map: dict[int,int]`, `ranges: list[tuple[int,int]]`, `input_path: Optional[Path]`, `variant_id: Optional[str]`, `file_type: str`. `Operation.execute(input: OperationInput, *, now_fn=…)` replaces the `LoadedFile` binding. Construction happens in TWO migrated places (F-A-02): the service `run_operation` (`operation_service.py:38`) AND the direct `OperationsScreen` call-site (`screens.py:636`), both via an `OperationInput.from_loaded(loaded)` adapter — the only places `LoadedFile` is referenced. Rationale: minimal field set sufficient for CRC (compute needs `mem_map`+`ranges`; report needs the metadata); avoids dragging `row_bases`/`range_validity`/`a2l_*` into the headless operation. Reversible: the adapter localizes the coupling; existing `tests/test_operations.py` calls keep working through `from_loaded`.

**D-2 — `OperationResult` widening + producer/consumer identity table (R-3, C-9-style).** Add `crc_regions: Optional[list[CrcRegionResult]] = None` (default `None`). `CrcRegionResult` (`NEW`): `output_address: int`, `computed_crc: int`, `stored_value: Optional[int]`, `matched: Optional[bool]`, `written: bool`. Canonical field set of `OperationResult` after this batch = `{operation_id, status, input_path, variant_id, output, notes, timestamp_utc, crc_regions}` (7 original + 1 new optional).

| Field | CRC op producer | Placeholder producers | Consumer: `OperationsScreen` (`screens.py:637-650`) | Consumer: `report_service` (NEW wiring) | Consumer: `to_dict` (`model.py:122`) |
|-------|-----------------|----------------------|-----------------------------------------|--------------------------|-----------------------|
| 7 original fields | sets all | sets all (status=`placeholder`) | reads `status`,`notes`,`output.mem_map` | reads all (NEW) | serializes all |
| `crc_regions` | populated (check & inject) | `None` | renders per-region lines (LLR-002.4) | renders CRC section (LLR-002.5/003.5, **NEW** — does not consume `OperationResult` today) | serialized when present |
| `output` (`LoadedFile`, non-optional) | check → input snapshot unchanged; inject → `LoadedFile` over injected map (F-Q-02) | echoes input | `render_hex_view_text(output.mem_map)` | — | n/a |

**Contract-touch rule (batch-07 B-1/B-2):** this table is the canonical set; any later edit adding a result field re-opens it for a field-set-equality re-run recorded in that edit's §6.4 audit row.

**D-3 — CRC config schema (external JSON + dummy template).** `CrcConfig` dataclass (`NEW`): `regions: list[CrcRegion]`, `polynomial: int`, `init: int`, `reverse: bool`, `final_xor: int`; `CrcRegion`: `start: int`, `end: int`, `output_address: int`. JSON shape (DUMMY values, the in-repo `examples/crc_config.example.json`):

```json
{
  "polynomial": "0x04C11DB7",
  "init": "0xFFFFFFFF",
  "reverse": true,
  "final_xor": "0xFFFFFFFF",
  "regions": [
    { "start": "0x00010000", "end": "0x00020000", "output_address": "0x0001FFFC" },
    { "start": "0x00020000", "end": "0x00030000", "output_address": "0x0002FFFC" }
  ]
}
```
Hex strings parsed to int (`int(s, 16)`); `end` is the half-open upper bound (matches `LoadedFile.ranges` `(start, end)` convention). All values here are FAKE format guidance — real per-firmware values are operator-supplied at runtime and never committed.

**D-4 — CRC engine param set.** Default = zlib/PKZIP CRC-32: poly `0x04C11DB7`, init `0xFFFFFFFF`, `reverse=true` (refin+refout), xorout `0xFFFFFFFF` — equivalent to `zlib.crc32`, the unit-test oracle (LLR-001.1). All four params are config-driven; `reverse` selects standard reflected-in/reflected-out semantics. Implementation may use `zlib.crc32` directly for the default path and a table/bitwise loop for non-default params (Phase-3 implementer's call; the oracle test pins correctness either way).

**D-5 — 4-byte LE codec (FIXED).** Stored/written CRC at an output address = 4 bytes little-endian: byte `i` at `addr+i` = `(crc >> (8*i)) & 0xFF`. NOT parameterized. Read (LLR-002.1) and write (LLR-003.1) are exact inverses. **Scope clarification (F-A-04):** the "OPEN params" claim (FR1 / D-3) covers the CRC ALGORITHM parameters only (poly/init/reverse/xorout); the storage codec (width=4, little-endian) is fixed and NOT config-driven. No contradiction.

**D-6 — Write-into-gap extension mechanism.** Inject works on a COPY of `mem_map`/`ranges`. For an output address `a` with none of `a..a+3` in a loaded range: add keys `a..a+3` to the working `mem_map` and add/merge a covering range so every address `emit_s19_from_mem_map` will read is present (guards its `KeyError`, `io.py:1331`). **Ranges are kept SORTED and non-overlapping after extension (F-A-06, LLR-003.1):** a contiguous gap-output range is merged into its neighbour, else inserted in ascending-start order. Record ordering follows `ranges` (`io.py:1336`); since the re-parse-equality oracle is order-insensitive, this sorted-merge requirement (with a unit assertion on the post-extension `ranges`) is what closes RK-6, not the oracle. The original loaded snapshot is never mutated; the modified S19 is a new artifact.

**D-7 — REQ-crc.md plan.** Create `s19_app/tui/operations/requirements/REQ-crc.md` (directory `NEW` — confirmed absent at draft). It holds the operation-level HLR/LLR for CRC; `REQUIREMENTS.md` and this 01-requirements reference it (no inlining), honoring the operations-module convention.

**D-8 — R-6 mechanism (side-effectful write).** Three inherited controls: (a) **worker-thread** — CRC execution decorated `@work(thread=True, …)` like `_start_execute_scope_worker` (`app.py:1599`), replacing the synchronous UI-thread `operation.execute` at `screens.py:636`; (b) **per-execution operator confirmation** — two-stage (check, then confirm→write); no-confirm writes nothing; (c) **contained output path (F-S-01, concrete seam)** — the emit is staged under `.s19tool/workarea/temp/` and placed via `copy_into_workarea` (`workspace.py:215`), or the resolved target is validated by `_find_workarea_root` + `is_relative_to(workarea_root)` + `_path_traverses_reparse_point` (`workspace.py:278-291`); a target failing containment writes no file (collect-don't-abort). Name-dedup on collision (no overwrite, F-S-03). Following `_write_and_verify_manifest`'s contained-write discipline (`app.py:3539`). **Config READ posture (F-S-02):** the operator config path is uncontained-by-design (parity with `read_change_document`), size-capped (`READ_SIZE_CAP_BYTES`, `io.py:192`), collect-don't-abort. security-reviewer sign-off required before merge (I5).

### 6.3 Open risks

| ID | Risk | Likelihood | Impact | Mitigation / fallback |
|----|------|-----------|--------|----------------------|
| RK-1 | **Contract decoupling deeper than expected (R-2).** The realistic ripple (F-A-02) is the `run_operation` service path + `tests/test_operations.py`, NOT renderers (the adapter localizes `LoadedFile`). | Medium | Medium (blows the I1a budget) | **SPIKE fallback (re-aimed, F-A-03):** if at I1a draft migrating `run_operation` + `test_operations.py` off `LoadedFile` proves deeper than a localized `from_loaded` adapter, split it into a standalone SPIKE and ship CRC against `LoadedFile` as-is. Fallback, NOT the plan. I1 is already split into I1a/I1b to respect the ≤5-file rule. |
| RK-2 | **`app.py`/`screens.py` structural surface** (worker wiring, confirm modal, config text widget) larger than estimated; the 3 placeholder ops + their tests regress. | Medium | Medium | Service-extension rule (logic in service/engine, UI state only in app/screens); `tests/test_operations.py` is the regression net; structural items marked **gate-confirm at increment** (A-2), not census-stamped. |
| RK-3 | **CRC param correctness for non-default configs** (a hand-rolled bitwise loop diverges from a real device's CRC). | Medium | High (wrong verdict) | Pin the default to `zlib.crc32` oracle (LLR-001.1); add a non-default reference vector; flag that non-zlib device conventions need a device-sourced reference vector before trust — `assumed — verify with operator fixture in Phase 3/4`. |
| RK-4 | **Endianness/width assumption** (operator device stores CRC big-endian or at a width ≠ 4). | Low | High | Locked decision fixes 4-byte LE; if a device differs this is a NEW requirement, out of scope. Documented in REQ-crc.md. |
| RK-5 | **Security: operator-supplied config path + emitted output path.** | Low | High | **Write (F-S-01):** emit placed via `copy_into_workarea` / validated by `is_relative_to(workarea_root)` + `_path_traverses_reparse_point` (`workspace.py:278-291`), containment-fail → no file. **Read (F-S-02):** config path uncontained-by-design (parity `read_change_document`), size-capped (`READ_SIZE_CAP_BYTES`), collect-don't-abort. security-reviewer sign-off mandatory at I5 (R-6). |
| RK-6 | **Write-into-gap range merge** produces overlapping/out-of-order ranges. | Low | Medium | Unit-test the post-extension `ranges` are SORTED + non-overlapping (LLR-003.1, D-6). NOTE (F-A-06): emit re-parse-equality (LLR-003.2) is order-INSENSITIVE and CANNOT catch a mis-ordered-but-equivalent emit — the sorted-merge assertion is what closes this, not the oracle. |

### 6.4 Phase-1 reconciliation log
*(Per the parent-HLR re-read rule. One audit table per reconciliation event: `Decision ID | What changed | Parent HLR re-read? | Body edit landed?`.)*

**Iteration 2 (2026-06-16) — applying the Phase-2 review register (8 majors + 11 minors). Body edits landed FIRST; this table points at them.**

| Finding(s) | What changed | Parent HLR re-read? | Body edit landed (section) |
|---|---|---|---|
| F-A-01 (both surfaces) | Added LLR-002.4 (op-result view) + LLR-002.5 + LLR-003.5 (report_service); `report_service.py` added to file budget + census + §6.1; D-2 consumer table flags it NEW; TC-117/TC-126 added; surface matrix rows added. | HLR-002 ✓ (now spans I2–I4), HLR-003 ✓ (I5) | §4 LLR-002.4/.5, LLR-003.5; §5.2; §5.4; §6.1; §6.2 D-2; §6.5 |
| F-A-02 | LLR-005.1 migrates `run_operation` (operation_service.py promoted to definite E) + `from_loaded` adapter for test reconciliation. | HLR-005 ✓ | §4 LLR-005.1; §6.1; §6.2 D-1 |
| F-A-03 | I1 split into I1a/I1b; 6-increment plan, each ≤5 files; RK-1 SPIKE trigger re-aimed. | HLR-001/005 ✓ | §4 ordering note; §6.3 RK-1; §6.5 |
| F-Q-01 | TC-108 (LLR-005.1), TC-109 (LLR-005.2), TC-116 (LLR-002.3) added to §5.2. | HLR-005/002 ✓ | §5.2 |
| F-Q-02 | `OperationResult.output` contract stated (check=input snapshot; inject=injected map); TC-115/125 assert it. | HLR-005 ✓ | §4 LLR-005.2; §6.2 D-2 |
| F-Q-03 | TC-106 reworded to "params-wired" (not a correctness anchor); RK-3 deferral confirmed; kept out of §5.3 gating. | HLR-001 ✓ | §5.2; §5.4 |
| F-S-01 | LLR-003.2 bound to `copy_into_workarea`/`is_relative_to(workarea_root)` containment; resolved-path threshold. | HLR-003 ✓ | §4 LLR-003.2; §6.2 D-8; §6.3 RK-5 |
| F-S-02 | LLR-004.1 + HLR-004 corrected: `resolve_input_path` uncontained-by-design + `READ_SIZE_CAP_BYTES` cap + collect-don't-abort. | HLR-004 ✓ | §3 HLR-004; §4 LLR-004.1; §6.2 D-8; §6.3 RK-5 |
| F-A-04/05/06/07 | D-5 scope note; `model.py:227→:228`; D-6/LLR-003.1 sorted-merge + RK-6 note; §5.4 params RK-3 caveat. | HLR-001/003 ✓ | §6.1; §6.2 D-5/D-6; §4 LLR-003.1; §5.4 |
| F-Q-04/05/06/07 | `STATUS_VERIFIED` normalized; `intended_mem_map`=injected copy; TC-125 pilot-driven note; TC-114 concrete assertion. | HLR-003/002 ✓ | §5.1; §4 LLR-003.3; §5.4; §5.2 |
| F-S-03/04/05 | No-overwrite dedup (LLR-003.2); plain-text messaging (LLR-002.2/003.3); RK-5 mitigation updated. | HLR-003/002 ✓ | §4 LLR-003.2/.3, LLR-002.2; §6.3 RK-5 |

All 19 findings CLOSED. 0 remain open. (F-Q-03/RK-3's non-default-vector residual stays a deliberate, flagged "assumed — verify in Phase 3/4" data dependency, not an open finding.)

---

### 6.5 Change-first census (A-1 / A-2 / A-4) — best-effort + gate-confirmed

Run change-first: each planned new/edited file checked against EVERY guard family that keys on file PATH / module STRUCTURE / import GRAPH / git-DIFF. **Not stamped "VERIFIED COMPLETE"** (A-2) — the increment gate (real suite on the real files) is the completeness guarantee; this census is the cheap Phase-1 heuristic.

**Planned file list (new = N, edited = E):**

| File | N/E | Frozen-set member? | Guard disposition |
|------|-----|--------------------|-------------------|
| `s19_app/tui/operations/crc.py` | N | **No** (engine-frozen set = `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py` — `test_engine_unchanged.py:120-127` [6, no color_policy] + `test_tui_directionb.py:3738-3745` [7, incl. color_policy]) | New module, no guard fires. |
| `s19_app/tui/operations/crc_config.py` (or config in `crc.py`) | N | No | New module. |
| `s19_app/tui/operations/requirements/REQ-crc.md` | N | No (doc; dir absent at draft) | New file, counted in budget. |
| `s19_app/tui/operations/model.py` | E | No | **A-3 new-symbol-into-existing-file probe:** `model.py` is NOT in either frozen `_ENGINE_PATHS` list (grep-verified `test_engine_unchanged.py:120-127`, `test_tui_directionb.py:3738-3745` — neither lists `operations/model.py`); the operations package is the batch-08 fill-in seam, explicitly designed for this edit. Adding `crc_regions` (optional, default `None`) is structurally additive; `tests/test_operations.py` is the regression net. |
| `s19_app/tui/operations/registry.py` | E (maybe) | No | If `CrcOperation` body moves out of `placeholders.py`, registry import line updates. Not frozen. |
| `s19_app/tui/operations/placeholders.py` | E (maybe) | No | `CrcOperation` becomes real (or moves to `crc.py`). Not frozen. `tests/test_operations.py` regression net. |
| `s19_app/tui/services/operation_service.py` | **E (definite, F-A-02)** | No | `run_operation` migrates to build/forward the neutral `OperationInput`. Not frozen. |
| `s19_app/tui/services/report_service.py` | **E (F-A-01)** | No | NEW CRC report section consuming `crc_regions` (does not consume `OperationResult` today; `generate_project_report` `:913` is `VariantExecutionResult`-based). Not in either frozen list. Section shape gate-confirm at I4. |
| `s19_app/tui/screens.py` | E | No | Call-site adapter + config text surface + confirm modal. **Structural — gate-confirm at increment** (A-2). Not frozen. |
| `s19_app/tui/app.py` | E | No | Worker-thread wiring (R-6). **Structural — gate-confirm at increment** (A-2). Not frozen. |
| `examples/crc_config.example.json` | N | No | Dummy template. AC-artifact (LLR-004.1); probe 2026-06-16 → 0 existing. |
| `tests/test_crc_engine.py`, `tests/test_crc_operation.py`, `tests/test_crc_config.py`, `tests/test_tui_crc_surface.py`, `tests/test_report_crc.py` | N | No | New tests (engine, operation, config, TUI-surface pilot, report). |
| `REQUIREMENTS.md` | E | No | Add `REQ-crc.md` reference + R-* status. Not frozen. |

**Guard-family pass (change-first):**
- **(a) behavioral-placeholder guards** — the CRC placeholder assertions in `tests/test_operations.py` (`CrcOperation` returns `status="placeholder"`, identity passthrough) WILL change when `CrcOperation` becomes real. **Disposition:** this is the intended fill-in (batch-08 §6.1 "fill-in batch replaces exactly one placeholder body"); those specific placeholder TCs are updated in Phase 3. **Predicted-red at I1/I2, by design.**
- **(b) structural / placement / allowlist guards** — operations package has no `glob('*.py')`/allowlist root-shape guard that the new `crc.py`/`crc_config.py` violate (no such guard found keyed on the operations package). Gate-confirm.
- **(c) AST-composition guards** — none found asserting on operations-module AST/call-count. Gate-confirm.
- **(d) engine-frozen / no-diff-vs-main guards** — `test_engine_unchanged.py` (6 paths) + `test_tui_directionb.py::test_tc031_*` (7 paths incl. `color_policy.py`). **EVERY planned file is OUTSIDE both frozen sets** (verified against the literal lists). Reuse of `range_index` / `core` (via `S19File` re-parse) / `hexfile` is **import-only**. **A-4 stress-test result: CLEAR** — CRC abuts `core.py`/`hexfile.py` conceptually but touches neither; the emitter is `tui/changes/io.py` (batch-10 relocation), the parser is read-only via `S19File`.

**Census verdict: best-effort + gate-confirmed.** No (N+1)th family enumerated as proven-absent; the structural items (`app.py`, `screens.py`, `registry.py`, `placeholders.py`, and the iter-2-added `report_service.py`) are **gate-confirm at increment**. The increment gate is the completeness guarantee. **Iter-2 re-run (F-A-01):** the newly added `report_service.py` is in `s19_app/tui/services/` — outside BOTH frozen lists (`test_engine_unchanged.py:120-127` [6] + `test_tui_directionb.py:3738-3745` [7]); it consumes `crc_regions` (import-only), no frozen edit. A-4 stress-test stays CLEAR.

---

### 6.6 Phase-1 gate evidence checklist

| # | Item | ✓/✗ | Evidence |
|---|------|-----|----------|
| 1 | Every HLR traces to US-011 or US-012 | ✓ | HLR-001/002→US-011; HLR-003→US-012; HLR-004/005→both (§3). |
| 2 | Every LLR traces to a parent HLR | ✓ | LLR-NNN.M Traceability lines all name an HLR (§4). |
| 3 | `shall` only in HLR/LLR statements; no `should` inside a statement | ✓ | Statements use `shall`; `should`/rationale confined to informative lines (self-checked §3/§4). |
| 4 | EARS patterns used | ✓ | Event-driven ("When…"), Ubiquitous, Unwanted ("if…then…") across HLR-001..005 + LLRs. |
| 5 | Every `test`/`analysis` requirement has executed-verification + numeric threshold | ✓ | Each HLR/LLR carries both fields (§3/§4). |
| 6 | Named code symbols carry `file:line` or `NEW` flag | ✓ | Anchors cited (§6.1 table); new symbols flagged `NEW — created in Phase 3` (§4). |
| 7 | AC-named data artifacts have an existence probe or `NEW` flag | ✓ | `examples/crc_config.example.json` probe 2026-06-16 → 0 files, flagged NEW (LLR-004.1); `REQ-crc.md` dir probe → absent, NEW (LLR-005.3). |
| 8 | Reuse anchors re-verified against current code (not trusted blind) | ✓ | All Phase-0 anchors re-grepped 2026-06-16 (§6.1 with real line numbers). |
| 9 | Change-first census run against all guard families | ✓ | §6.5 per-file × family table; A-4 stress-test CLEAR. |
| 10 | Census NOT stamped "VERIFIED COMPLETE"; structural items gate-confirm | ✓ | §6.5 verdict = "best-effort + gate-confirmed"; `app.py`/`screens.py` marked gate-confirm. |
| 11 | Contract-touch (`OperationResult` widening) recorded with producer/consumer table | ✓ | §6.2 D-2 identity table + contract-touch note. |
| 12 | R-6 mechanism specified (worker-thread + confirmation + sanitized path) | ✓ | §6.2 D-8; LLR-002.3 / LLR-003.4. |
| 13 | Open risks listed incl. SPIKE fallback | ✓ | §6.3 RK-1..RK-6; RK-1 = contract-decoupling SPIKE fallback. |
| 14 | Provisional-identifier flag on test file/`-k`/node-id (V-5) | ✓ | §4 ordering note: all test paths/selectors/node-ids provisional-until-Phase-3. |
| 15 | `test (...)` runtime cross-checked vs testing strategy | ✓ | All TCs are `pytest` (the repo's only test runner; `pyproject.toml` + `tests/` use pytest) — no foreign runtime introduced. |
| 16 | Synchronous-UI-thread CRC execution gap confirmed (R-6 justified) | ✓ | `screens.py:636` runs `operation.execute(self.loaded, now_fn=None)` synchronously — verified at draft. |
| 17 | Phase-2 review register (8 major + 11 minor) applied; §6.4 audit table present | ✓ | §6.4 iter-2 audit (11 cluster rows, all 19 findings CLOSED); F-A-01 both-surfaces wired (LLR-002.4/.5/003.5 + report_service.py in census); I1→I1a/I1b split (6 increments ≤5 files each, §4 ordering note). |
| 18 | Each increment ≤5 files (CLAUDE.md hard rule) post-split | ✓ | §4 ordering note: I1a=5 (atomic `execute` call-site migration — both real call-sites verified at Phase-3 prep), I1b=3 (engine + REQ-crc.md doc), I2=5, I3=3, I4=≤3, I5=5. |

### 6.7 qa testability-flag reconciliation (Phase 1 cross-author)

The qa-reviewer raised 6 testability flags (§5.5). Each is reconciled against the architect's LLRs/decisions below. 5 of 6 fully resolved in the draft; 1 carries an honest "assumed" flag.

| qa flag (§5.5) | Disposition | Where resolved |
|---|---|---|
| 1 — FR9 non-confirmation observable | **RESOLVED** — the observable is "0 files written AND loaded snapshot unchanged". | LLR-003.4 statement + threshold ("no-confirm path writes 0 files AND 0 snapshot mutations"). TC-124 asserts on it. |
| 2 — `OperationResult.status` domain for match/mismatch | **RESOLVED (decision made):** `STATUS_DOMAIN` stays `{"placeholder","ok","error"}` UNCHANGED; match/mismatch rides the structured field `crc_regions[].matched`, status stays `"ok"`. | D-2 + LLR-005.2 + LLR-002.2. TC-111/TC-112 assert on `matched`, not status. |
| 3 — per-region payload shape | **RESOLVED** — `CrcRegionResult{output_address, computed_crc, stored_value, matched, written}`. | D-2 / LLR-005.2. |
| 4 — variant known-answer for reverse=false / non-default | **PARTIAL — honest "assumed":** LLR-001.1 requires a non-default-param vector against an INDEPENDENTLY computed reference (not self-consistency), but a real non-zlib *device* convention needs an operator-sourced reference vector. | LLR-001.1 threshold + RK-3 (`assumed — verify with operator fixture in Phase 3/4`). TC-106 maps here; its exact reference vector is provisional until the Phase-3 fixture exists. |
| 5 — config schema + dummy template + fixture builder | **RESOLVED** — `CrcConfig`/`CrcRegion` fields defined; dummy `examples/crc_config.example.json` is `NEW` and counted in the file budget; synthetic fixtures are `NEW`. (Whether the synthetic fixture is a `conftest.py` builder vs a test-local helper is a Phase-3 implementer's call, consistent with the stress-fixtures convention.) | D-3 + LLR-004.1 (incl. the AC-artifact probe). |
| 6 — oracle equality granularity | **RESOLVED** — TC-123/LLR-003.3 assert `VerifyResult.status == "verified"` + `runs == []`, matching the real `verify.py:35` return type, not a hand-rolled `mem_map ==`. | LLR-003.3 + §5.2 TC-123. |

**Net:** 0 open testability blockers carried into Phase 2; flag 4's residual is a known data-dependency (RK-3), correctly surfaced rather than hidden.
