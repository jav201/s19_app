# Requirements Document — s19_app — Batch 2026-06-23-batch-14

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
Specify batch-14: two data-fidelity / correctness improvements surfaced by functional testing on 2026-06-23. **US-015** gives the S19 emitter a 16/32 data-bytes-per-record selector (default 32) plus an S0 header in 32-byte mode. **US-016** fixes the A↔B compare reporting a false "no diff" for genuinely-different absolute-path inputs, and hardens the test suite at the shipped surface so this class of bug cannot escape again.

### 1.2 Scope
**In scope:** parametrized S19 emission (`emit_s19_from_mem_map`, `tui/changes/io.py`) wired through the TUI save flows (patch-editor save-back + project save); A↔B compare load-path correctness (`app.py::_diff_load_maps`) + a through-the-handler regression test.
**Out of scope (this batch):** CLI format flags; forcing S1/S2 record type (type stays auto-by-max-address); arbitrary bytes-per-line values other than 16/32; the two legend features (Q1/Q2) and all other Cluster 2/3/4 items (→ batch-15+); rewriting the compare UI or `resolve_input_path`'s absolute-path-not-found branch beyond surfacing the diagnostic.

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
- **Engine-frozen set** (git-frozen by `_ENGINE_PATHS` guards): `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`. New/changed emission + compare-load code must live **outside** this set. `emit_s19_from_mem_map` is in `tui/changes/io.py` (outside) ✓; the compare load fix targets `tui/app.py` (outside) ✓. `core.py::S19File` is the frozen READER — if header capture needs reader changes, it must happen at a load seam outside `core.py` (verify Phase 1).
- **≤5 files per increment**; review packet per increment; independent `code-reviewer` before each gate.
- **Default flip blast-radius:** changing the emitter default from 16→32 bytes/line touches every test asserting exact 16-byte emission — must be enumerated and budgeted in Phase 1 (b12 facade/test blast-radius control).

### 2.5 Assumptions and dependencies
- **[assumed — verify Phase 1]** `S19File` retains/exposes the original S0 header bytes needed for US-015 header preservation. If not, capture at the load seam (outside frozen `core.py`) or synthesize a minimal populated header.
- **[assumed — verify Phase 1]** `_diff_load_maps` (`app.py:2151`) is the swallowing point producing the false "no diff"; confirmed by repro before the fix (US-016 diagnose step).
- Worktree is off `main` which already includes batch-13 (PRs #18/#19); suite baseline must be **re-measured** at Phase 1 (do not assume 893).

### 2.6 Source user stories

> Connextra format: **"As a `<role>`, I want `<goal>`, so that `<benefit>`"**. Each US gets a unique ID `US-NNN` and must be traceable to one or more HLRs.
> **Phase 0 — Definition of Ready (INVEST):** every story is refined and classified before it can be derived into HLR (Phase 1). Only `READY` stories proceed.

| ID | User Story | Source | DoR status |
|----|------------|--------|------------|
| US-015 | As a firmware engineer saving a patched variant, I want to choose 16- or 32-data-byte S19 records (defaulting to 32) and emit a populated S0 header in 32-byte mode, so that downstream flashing/diff tools that require the wider record + header accept our output. | Functional testing 2026-06-23 (Q4.1/4.2/4.3) | READY |
| US-016 | As a firmware engineer comparing two images by absolute path in the A↔B view, I want the compare to reflect genuine byte differences (incl. a patched variant), so that I can trust it instead of seeing a false "no diff". | Functional testing 2026-06-23 (Part B) | READY |

**Carried to batch-15+ (not derived here):** Q1 report red-flag legend; Q2 in-app per-view legend; US-A workspace columns; US-B/C/D patch-editor overhaul; US-H issues hex pane + report addendum; US-J before/after reports; US-I entropy viewer; US-K A2L-color/issues-report reconcile. Classification tables for the legend batch were drafted in this batch's Phase-0 conversation and are ready input.

#### Refinement log (one block per story)

**US-015 — S19 output format selector (16/32 BPL) + S0 header**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ~ (header-capture seam adds a little) · T ✓
- **Functionality (V, N):** user = engineer saving a patched variant via the TUI · outcome = on save, choose 16 or 32 data-bytes-per-record (**default 32**) and, in 32-byte mode, write a populated S0 header instead of the current empty `S0`/0x03 · why = downstream flashing/diff tools (e.g. HxD/"hexview", flashers) may require the wider record and/or a header to accept the file · out of scope = CLI flags, forcing S1/S2 (record type stays auto-by-max-address, `io.py:1463`), BPL values ≠ {16,32}, preserving non-S0 metadata.
- **Feasibility (E, S):** path = parametrize `emit_s19_from_mem_map` (`tui/changes/io.py:1409`, outside engine-frozen set) with `bytes_per_line ∈ {16,32}` default 32 (the hardcoded 16 is the `range(start,end,16)` step at `io.py:1473`) + an optional header payload (current empty `S0` at `io.py:1471`); thread the choice from the two TUI save flows — patch-editor save-back (`changes/apply.py::save_patched_image`) and project save. · **consumer-input-contract (b12 control):** `emit_s19_from_mem_map(mem_map, ranges)` today takes no format args — both call-sites (`save_patched_image`, project save) must pass the new param. · dependencies/unknowns = (a) **[assumed — verify Phase 1]** does `S19File` expose the source S0 header for preservation, or must we capture it at the load seam / synthesize? (b) **[assumed — verify Phase 1]** test blast-radius of the 16→32 default flip — enumerate every test asserting 16-byte emission (e.g. `tests/test_changes_apply.py::test_emit_s19_reparses_to_equal_mem_map`). · fits one batch? = yes.
- **Evaluability (T):** "When the operator selects 32-byte output and saves a patched image, the emitted S19 shall contain S3 data records of ≤32 data bytes each AND a non-empty S0 header, and shall re-parse (frozen `S19File` reader-as-oracle) to a memory map byte-equal to the patched map." 16-byte mode preserves current behavior.
- **Open questions:** header content when no source header is available — preserve captured source `S0` if present, else synthesize a minimal populated header? → **resolved direction:** preserve-if-captured-else-minimal; confirm capture feasibility at Phase 1.
- **Classification:** `READY` — default (32), surface (TUI save flows), and value set ({16,32}) are decided; header-capture is a Phase-1 feasibility verify, not a story blocker.

**US-016 — A↔B compare false "no diff" fix + regression hardening**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):** user = engineer comparing two S19/variant files by absolute path in the A↔B view · outcome = the compare reflects real byte differences (the patched bytes) in BOTH the run list and the hex windows; a load/parse failure surfaces a diagnostic rather than rendering an empty no-diff · why = `_diff_load_maps` (`app.py:2151-2182`) re-loads both files for the hex windows and **silently returns `{}` on parse failure** → two empty maps → `diff_mem_maps` reports zero runs (`compare.py:272`) · out of scope = new compare UI; reworking `resolve_input_path`'s absolute-path-not-found branch (`workspace.py:474`) beyond surfacing the error.
- **Feasibility (E, S):** path = (1) **diagnose** with a synthetic patched-variant fixture driven **through the shipped `CompareRequested` handler** (`app.py::on_ab_diff_panel_compare_requested:2083`) incl. absolute paths, to confirm the swallow point; (2) stop `_diff_load_maps` returning `{}` on failure — surface the diagnostic instead; (3) add a regression TC at the shipped surface that **fails pre-fix**. · **consumer-input-contract:** `on_ab_diff_panel_compare_requested` consumes `CompareRequested(path_a, path_b, base_dir)` → `compare_images` → `diff_mem_maps`. · dependencies/unknowns = none new. · fits one batch? = yes.
- **Evaluability (T):** "When two genuinely-different S19 files are compared via the shipped A↔B handler (incl. absolute paths), the system shall report ≥1 differing run AND render the differing bytes; a parse/load failure shall surface a diagnostic, not an empty no-diff. The regression TC shall fail on the pre-fix tree and pass post-fix."
- **Open questions:** repro corpus — **synthetic fixture (decided)**, which doubles as the regression fixture; operator may additionally supply the two real file paths to confirm.
- **Classification:** `READY` — root-cause hypotheses ranked (Part B), fix is diagnose-then-correct in Phase 3 Inc 1, synthetic repro decided.

> **Process carry (Part B → dev-flow directive):** this bug escaped because the diff *engine* (`diff_mem_maps`) is tested but the *shipped* load path (`_diff_load_maps`) is not — same class as batch-11 SCOPE-1. Disposition: extend the Phase-4 surface-reachability matrix to require compare's resolve+reload be exercised through-handler, and add a `/dev-flow` directive — "a bug that escaped tests ships with a test at the *shipped surface* that fails pre-fix." The command edit is **global config (outside this repo)**, flagged when made.

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

### HLR-015 — Selectable S19 data-byte width with populated S0 header
- **Traceability:** US-015
- **Statement:** Where the operator saves an S19 image through a TUI save flow, the system shall emit the image at either 16 or 32 data bytes per record (default 32), and while 32-byte mode is selected the emitted file shall carry a populated S0 header (the preserved source S0 when present, else a synthesized minimal S0), such that the emitted image re-parses to a memory map byte-equal to the input.
- **Rationale (informative):** Downstream flashing/diff tools may require 32-byte records and/or a header; the current emitter is hardcoded to 16-byte rows (`tui/changes/io.py:1473`) and a data-free S0 (`io.py:1471`). The S0 payload is already retained by the frozen reader (`core.py:226` `S19File.records`; `core.py:145` `SRecord.data`; `core.py:352-364` `print_header`), so preservation reads it at the load seam — no frozen-file edit.
- **Validation:** test + analysis
- **Executed verification:** `pytest tests/test_changes_apply.py -k "bytes_per_line or s0_header or reparses"` — emit at bpl∈{16,32}, re-parse via `S19File`, assert mem_map equality + record-width + populated-S0-in-32-mode + empty-S0-16-mode + negative control.
- **Numeric pass threshold:** 100% of emitted data records ≤ N bytes (N∈{16,32}); 0 reader errors on re-parse; mem_map delta = 0 bytes; ≥1 populated S0 in 32-byte mode; corrupted-write negative control detected.
- **Priority:** high

### HLR-016 — A↔B compare reflects genuine byte differences for absolute-path inputs
> **⚠ SATISFIED-BY-BATCH-15 — OUT OF BATCH-14 SCOPE.** Shipped in main `9169130` (PR #20, `REQUIREMENTS.md §20`, `R-DIFF-LOADFAIL-001`). HLR-016 / LLR-016.1–.3 / AT-016.* below are retained for traceability only and are NOT reviewed or implemented in batch-14. The hex-pane content coverage gap is backlog **C-9**. Batch-14 live scope = **US-015 only** (Inc1 + Inc2).
- **Traceability:** US-016
- **Statement:** When two images selected by absolute path differ, the A↔B compare shall report the genuine differing byte runs and render the differing bytes; and if an image fails to load, then the system shall surface a diagnostic rather than silently presenting an empty ("no diff") result.
- **Rationale (informative):** `_diff_load_maps` (`tui/app.py:2151`) re-loads both files for the hex windows and swallows every exception into `{}` (`app.py:2181-2182` `except Exception: return {}`), so a load failure renders as a false "no diff". The diff engine (`compare.py:272`) and `compare_service.compare_images` (`compare_service.py:547-552`) are already correct — the defect is display-side. The bug escaped because every existing handler test monkeypatches `compare_images` or calls `render_comparison` directly (`test_tui_diff_screen.py:96,:168`), never driving the real parse+reload path.
- **Validation:** test (e2e + integration)
- **Executed verification:** `pytest tests/test_tui_diff_screen.py tests/test_compare_service.py -k "absolute_path or load_failure or regression"` — a regression TC drives the shipped `on_ab_diff_panel_compare_requested` handler with two genuinely-different on-disk files and asserts ≥1 `changed` run; the same TC must fail on the pre-fix tree.
- **Numeric pass threshold:** ≥1 reported `changed` run for inputs with ≥1 differing byte; 0 false "no-diff" for non-identical inputs; load failure → exactly 1 surfaced diagnostic, 0 silent empty maps; regression TC red pre-fix / green post-fix.
- **Priority:** high

### Acceptance (black-box) — per story (the WHAT, observed through the shipped surface)

> Layer B of the two-layer validation model: `AT-NNN` ↔ user story, asserted automatically through the real surface (TUI save flow / A↔B view), distinct from the white-box `TC-NNN` ↔ LLR. AT ids are provisional-until-Phase-3 (V-5).

**US-015 acceptance**
- **AT-015.1 — operator saves a 32-byte variant.** When the operator saves a patched variant through the TUI save flow with 32-byte output selected, the user observes a file at the chosen save path that (a) contains S3 data records of ≤32 data bytes, (b) carries a **non-empty S0 header**, and (c) re-parses via `S19File` to a memory map byte-equal to the in-app patched map. *Deliverable: the saved `.s19` file (exists, non-empty, content as stated).*
- **AT-015.2 — cross-format data integrity (D2 safety net, verification-only).** Round-tripping a memory image preserves it byte-for-byte in every direction at the new default: S19→emit(32)→re-parse = map-equal; HEX-source→emit S19(32)→re-parse = map-equal; S19-source→`emit_intel_hex_from_mem_map`→re-parse = map-equal. *0 byte delta, 0 reader errors, all directions. The Intel-HEX emitter (`io.py:1533`, `HEX_DATA_BYTES_PER_RECORD=16` `io.py:1530`) is NOT modified — this AT only proves the S19 width change does not corrupt cross-format conversion.*
- **AT-015.3 — 16-byte back-compat observable.** When 16-byte output is selected, the saved file's framing is byte-identical to pre-change behavior. *Deliverable: the saved file matches the legacy fixture.*

**US-016 acceptance**
- **AT-016.1 — operator sees a real diff.** When the operator compares two genuinely-different files by absolute path in the A↔B view (real `CompareRequested` handler), the view shows `Runs: ≥1` with a `changed` run and renders the differing bytes. *Realized by TC-224 (e2e); must fail on the pre-fix tree.*
- **AT-016.2 — load failure is visible, not silent.** When one compared path fails to load, the view surfaces a diagnostic rather than a clean "no diff". *Realized by TC-222/TC-225.*

---

## 4. Low-level requirements (LLR)

> Each LLR decomposes an HLR into a verifiable property at the implementation level.
> Same EARS regime. ID format: `LLR-<HLR>.<M>`.

> **Symbol-citation key:** `file:line` = grep-verified at draft; **NEW** = created in Phase 3; **CHANGED** = additive edit to an existing symbol (default-preserving). Provisional test paths/`-k`/node ids reconciled at Phase 4 (V-5).

### LLR-015.1 — Parametrize the emitter with `bytes_per_line ∈ {16,32}`, default 32
- **Traceability:** HLR-015
- **Statement:** The S19 emitter `emit_s19_from_mem_map` shall accept a NEW keyword `bytes_per_line: int` constrained to `{16, 32}` defaulting to 32, replacing the hardcoded 16-byte row step, and shall raise `ValueError` for any other value.
- **Symbols:** `emit_s19_from_mem_map` `tui/changes/io.py:1409` (CHANGED sig, NEW param `bytes_per_line`); hardcode site `io.py:1473` (`range(row_start, row_end, 16)`). Consumer-input-contract — existing call-sites pass positional `(mem_map, ranges)`: `apply.py:687`, `crc.py:879` (both back-compatible via default).
- **Validation:** test (unit)
- **Executed verification:** `pytest tests/test_changes_apply.py -k "tc212 or tc213 or tc214"` *(provisional path; fold-in if no test_changes_io.py)*
- **Numeric pass threshold:** default emit → ≥1 data line >16 bytes AND all ≤32; `bytes_per_line=16` → all ≤16; `bytes_per_line∈{0,24,64}` → `ValueError`, 0 lines emitted.
- **Acceptance criteria:**
  - Default (omitted) packs 32 data bytes/record; byte-count field consistent with payload.
  - 16-byte mode is byte-identical to pre-change framing for a fixed fixture.

### LLR-015.2 — Populated S0 header in 32-byte mode (preserve-or-synthesize)
- **Traceability:** HLR-015
- **Statement:** The emitter shall accept a NEW optional `s0_header: bytes | None = None`; when provided it shall emit `_s19_record("S0", 2, 0, tuple(s0_header))`; while 32-byte mode is selected with no captured header it shall synthesize a minimal S0 from the output name; while 16-byte mode is selected it shall keep the empty S0 for back-compat.
- **Symbols:** empty-S0 site `io.py:1471`; record builder `_s19_record` `io.py:1481`; NEW param `s0_header`. Capture source = `S19File.records` scan `type=='S0'` → `record.data` (`core.py:145`,`:356-359`), read-only; capture seam = NEW field on `LoadedFile` (`tui/models.py`) populated in `build_loaded_s19` (`tui/services/load_service.py`) — both NEW, both outside frozen set.
- **Validation:** test (unit + integration)
- **Executed verification:** `pytest tests/test_changes_apply.py -k "tc215"`
- **Numeric pass threshold:** 32-byte emit → S0 data field len > 0 AND re-parse adds 0 addresses to mem_map AND `get_errors()==[]`; 16-byte emit → S0 data field empty.
- **Acceptance criteria:**
  - Populated S0 is semantically inert (no memory-map contribution).
  - Source S0 preserved when present; synthesized minimal S0 when absent (e.g. Intel-HEX source, or S19 with no S0).

### LLR-015.3 — Thread the selector + header through the two TUI save flows
- **Traceability:** HLR-015
- **Statement:** The patch-editor save-back flow and the project save flow shall each expose a NEW {16,32} selector (default 32) and pass the chosen width + captured header through to the emitter.
- **Symbols:** `save_patched_image` `tui/changes/apply.py:574` (dispatch `_SAVE_BACK_EMITTERS` `apply.py:100`, emit `apply.py:687`) — CHANGED sig; save UI `tui/screens_directionb.py` (`SaveBackDecision` `:707`); `change_service.save_patched_image` call `change_service.py:904` — CHANGED; `variant_execution_service.py:711` — CHANGED. Selector control = NEW. Scope guard: TUI save flows only; record TYPE auto-by-max-address (`io.py:1463`) untouched.
- **Validation:** test (integration)
- **Executed verification:** `pytest tests/test_changes_apply.py -k "tc219 or tc220"` *(through the save call-sites, A-5)*
- **Numeric pass threshold:** `save_patched_image(..., bytes_per_line=32)` writes 32-byte rows + re-parses byte-equal; default (omitted) ⇒ 32; project save likewise.
- **Acceptance criteria:**
  - Both save call-sites honor the selector (not only the bare emitter) — partial threading fails TC-220.

### LLR-015.4 — Reader-as-oracle acceptance + negative control
- **Traceability:** HLR-015
- **Statement:** The batch shall include NEW tests that re-read every emitted image via the frozen `S19File` reader and assert byte-equality to the intended map for both widths, plus a negative control proving a corrupted write is detected.
- **Symbols:** oracle = `core.S19File` re-parse (`core.py:218`); precedent `test_emit_s19_reparses_to_equal_mem_map` `tests/test_changes_apply.py:283`. NEW tests.
- **Validation:** test (integration)
- **Executed verification:** `pytest tests/test_changes_apply.py -k "tc216 or tc217 or tc218"`
- **Numeric pass threshold:** 32-byte + 16-byte emit each re-parse byte-equal (delta 0, 0 errors); corrupted write → re-parsed map ≠ intended (assert inequality) OR errors ≠ [].
- **Acceptance criteria:**
  - The oracle is non-vacuous (negative control TC-218 fails if a corrupt write is NOT detected).

### LLR-016.1 — `_diff_load_maps` surfaces a load failure instead of returning `{}`
- **Traceability:** HLR-016
- **Statement:** If an image fails to load during the hex-window re-load, then `_diff_load_maps` shall surface a diagnostic (distinguishing "failed to load" from "loaded empty") rather than returning an empty map presented as a clean compare.
- **Symbols:** `_diff_load_maps` `tui/app.py:2151`; swallow site `app.py:2181-2182` (`except Exception: return {}`) — FIX; surfacing channel = panel `set_status(..., "sev-error")` (`screens_directionb.py:1123`).
- **Validation:** test (unit)
- **Executed verification:** `pytest tests/test_tui_diff_screen.py -k "tc222"`
- **Numeric pass threshold:** unreadable/parse-failing image → non-empty diagnostic surfaced AND no `(0 runs, empty map)` success render.
- **Acceptance criteria:**
  - Load failure no longer silently collapses to "no diff".

### LLR-016.2 — Compare shows ≥1 real diff run + bytes for absolute-path inputs
- **Traceability:** HLR-016
- **Statement:** When two genuinely-different files are supplied as absolute paths, the compare shall return `refused=False` with ≥1 `changed` run and reloaded maps that differ.
- **Symbols:** `compare.diff_mem_maps` `compare.py:272` (already correct: classifies `changed/only_a/only_b` `:260-269`); `compare_images` parses fresh per side `compare_service.py:547-552`; `CompareRequested(variant_a,path_a,variant_b,path_b)` `screens_directionb.py:996-1005`; resolve via `resolve_input_path` `workspace.py:469-483` (returns candidate directly when it `exists()` — distinct absolute paths do not collapse). **Likely no production change beyond LLR-016.1** — primarily verification; flag any real defect the regression exposes.
- **Validation:** test (integration)
- **Executed verification:** `pytest tests/test_compare_service.py -k "tc223"` *(real resolver, no `resolver=` stub)*
- **Numeric pass threshold:** absolute-path differing inputs → `refused False`, ≥1 `changed` run, `mem_map_a != mem_map_b`.
- **Acceptance criteria:**
  - The real absolute-path resolve path (not a stub) yields a true diff.

### LLR-016.3 — Regression through the SHIPPED `CompareRequested` handler (fails pre-fix)
- **Traceability:** HLR-016
- **Statement:** The batch shall add a NEW regression TC that drives `on_ab_diff_panel_compare_requested` via the real `#diff_compare_button` (no `compare_images` monkeypatch) with two genuinely-different on-disk files, and that test shall fail on the pre-fix tree.
- **Symbols:** handler `on_ab_diff_panel_compare_requested` `tui/app.py:2083`; driver = `app.run_test` pilot pressing `#diff_compare_button`; gap = `test_tc021` spy `test_tui_diff_screen.py:96`, `test_tc022` direct `render_comparison` `:108` (neither parses real files). NEW test.
- **Validation:** test (e2e)
- **Executed verification:** `pytest tests/test_tui_diff_screen.py -k "tc224"`; plus a pre-fix run capturing the false "no diff" as gate evidence.
- **Numeric pass threshold:** post-fix → `Runs: ≥1` + a `changed` run + `sev-ok`; pre-fix → assert FAILS (false no-diff / swallowed load).
- **Acceptance criteria:**
  - The pre-fix-fail contrast is demonstrated (output attached at Phase 4), not merely claimed.
  - A companion case (TC-225) confirms a genuinely-unresolvable path still refuses with a diagnostic and 0 exceptions (no over-correction).

---

## 5. Validation strategy

### 5.1 Methods
- **Test:** automated execution (unit / integration / e2e). Default for LLR. **Every `test` LLR must name the exact executed verification and the numeric pass threshold — otherwise it is not executable.**
- **Demo:** observed execution of behavior. Useful for UX-oriented HLRs. Describe the observable procedure + the named qualitative criterion.
- **Inspection:** static review of code or document. Useful for structural requirements. Name the file / commit / section + the observable condition.
- **Analysis:** formal or quantitative reasoning (performance, complexity, security). **Every `analysis` LLR must name the executed calculation (with input values) and the numeric pass threshold — otherwise it is not executable.**

> Reminder from the batch-02 + batch-03 post-mortems: the absence of an executed verification + numeric pass threshold on `test`/`analysis` requirements was the recurring root cause of forced phase-1 iteration. Capture at draft time, not at the phase-2 gate.

### 5.2 Coverage table

> **Dual traceability (two-layer model):** behavioral `US → AT-NNN → observed outcome` AND functional `US → HLR → LLR → TC-NNN`. White-box TC-212…TC-226; black-box AT-015.1/.2/.3 + AT-016.1/.2. No collision with batch-13 (TC-201..211). All paths/`-k`/node ids + AT/TC ids are **provisional-until-Phase-3** (V-5); reconciled at Phase 4.

**Layer B — behavioral acceptance (AT ↔ US):**

| AT | Story | Observed outcome (shipped surface) | Realizing node **[PROV]** | Pass threshold |
|---|---|---|---|---|
| AT-015.1 | US-015 | 32-byte variant saved via TUI: file has ≤32-byte S3 records + non-empty S0 + re-parses byte-equal | TC-219/TC-220 (save call-sites) | file exists, S0 len>0, map delta 0 |
| AT-015.2 | US-015 | cross-format round-trip integrity (S19↔reparse, HEX→S19, S19→HEX) | **TC-226** | 0 byte delta + 0 errors, all directions |
| AT-015.3 | US-015 | 16-byte save byte-identical to legacy framing | TC-213/TC-217 | byte-identical fixture |
| AT-016.1 | US-016 | A↔B view shows ≥1 changed run + bytes for abs-path diff | **TC-224** (fails pre-fix) | Runs≥1, changed run, sev-ok |
| AT-016.2 | US-016 | load failure surfaces a diagnostic, not "no diff" | TC-222/TC-225 | non-empty diagnostic, 0 silent empty |

**Layer A — functional (TC ↔ LLR):**

| Requirement | Method | TC ids | Executed verification **[PROV]** | Numeric pass threshold |
|---|---|---|---|---|
| LLR-015.1 | test (unit) | TC-212, TC-213, TC-214 | `pytest tests/test_changes_apply.py -k "tc212 or tc213 or tc214"` | default ≤32 & ≥1 line >16; 16-mode ≤16 byte-identical; invalid→ValueError, 0 lines |
| LLR-015.2 | test (unit+int) | TC-215 | `-k tc215` | 32-mode S0 data len>0, +0 addresses, 0 errors; 16-mode S0 empty |
| LLR-015.4 | test (integration) | TC-216, TC-217, **TC-218 (neg ctrl)**, **TC-226 (cross-format)** | `-k "tc216 or tc217 or tc218 or tc226"` | 32 & 16 emit re-parse byte-equal (delta 0); corrupt write detected; S19↔HEX cross-format round-trip map-equal all directions |
| LLR-015.3 | test (integration) | TC-219, TC-220 | `-k "tc219 or tc220"` | both save call-sites emit 32 by default + re-parse byte-equal |
| LLR-015.x | inspection | TC-221 | `pytest tests/test_engine_unchanged.py tests/test_tui_directionb.py -k engine_unchanged` | 0 diffs vs main in `_ENGINE_PATHS` |
| LLR-016.1 | test (unit) | TC-222 | `pytest tests/test_tui_diff_screen.py -k tc222` | load failure → non-empty diagnostic, 0 silent empty render |
| LLR-016.2 | test (integration) | TC-223 | `pytest tests/test_compare_service.py -k tc223` | abs-path differing → refused False, ≥1 changed run, maps differ |
| LLR-016.3 | test (e2e) | **TC-224 (fails pre-fix)**, TC-225 | `pytest tests/test_tui_diff_screen.py -k "tc224 or tc225"` | post-fix Runs≥1 + changed + sev-ok; pre-fix FAILS; unresolvable still refuses, 0 exceptions |

### 5.3 Batch acceptance criteria
1. 100% of LLR-015.* / LLR-016.* covered by ≥1 passing TC; every test row has an EV node + numeric threshold.
2. `pytest -q` green post-fix; 0 blocker fails; `pytest -q -m "not slow"` green.
3. **TC-224 fails on the pre-fix tree and passes post-fix** (a TC-224 that passes pre-fix is itself a defect that blocks the gate).
4. Reader-as-oracle holds: 32-byte (TC-216) + 16-byte (TC-217) re-parse byte-equal; negative control TC-218 detects a corrupted write.
5. 16-byte mode byte-identical to pre-change framing (TC-213).
6. 32-byte S0 populated yet inert: non-empty data, 0 map addresses (TC-215).
7. Both save call-sites threaded (TC-219 + TC-220); default = 32.
8. Frozen-engine guard 0 diffs (TC-221).
9. No US-016 over-correction: unresolvable inputs still refuse with a diagnostic, 0 exceptions (TC-225).
10. **Dual traceability complete:** every story has BOTH a passing AT-<n> (Layer B) and its LLR→TC-<n> chain (Layer A).
11. **Cross-format data integrity (D2):** TC-226 shows 0 byte delta + 0 errors round-tripping S19↔re-parse, HEX→S19, and S19→HEX at the 32-byte default (the Intel-HEX emitter itself is unchanged).

### 5.4 A-5 surface-reachability matrix (standing Phase-4 row)
| Story | Input dimension | Shipped surface (call-site) | Service signature reached | Through-surface TC |
|---|---|---|---|---|
| US-015 | bytes_per_line 16/32 — save-back | patch-editor save-back → `save_patched_image` | `emit_s19_from_mem_map(..., bytes_per_line=)` | TC-219 |
| US-015 | bytes_per_line — project save | project-save flow → `save_patched_image` | same emitter kwarg | TC-220 |
| US-015 | populated S0 default-on (32) | both save call-sites | emitter S0 branch | TC-219/220 assert S0 non-empty |
| US-016 | absolute-path inputs A/B | `on_ab_diff_panel_compare_requested` via `#diff_compare_button` (`run_test`) | `compare_images` real resolve (no stub) | TC-224 |
| US-016 | load/parse failure on reload | handler → `_diff_load_maps` | reload surfaces, not `→ {}` | TC-224 / TC-225 |

---

## 6. Appendices

### 6.1 Extended glossary
| Term | Definition |
|---|---|
| BPL | Bytes-per-line: data bytes per S-record (the selector value, {16,32}). |
| S0 header | Optional S-record header (module name/comment); inert to the memory map. |
| Reader-as-oracle | Re-read an emitted image via the frozen `S19File` and diff vs the intended map. |

### 6.2 Relevant design decisions
- **D1 — Header preservation strategy:** preserve captured source S0 when present, else synthesize a minimal S0 (32-byte mode); 16-byte mode keeps the empty S0. `S19File.records` already exposes the source S0 (`core.py:226`/`:145`/`:352`) — capture at the `load_service` seam onto a NEW `LoadedFile` field; thread the header into the emitter as a NEW `s0_header` param (it is NOT derivable from `mem_map`). **No frozen-file edit.**
  - **D1 cosmetic confirmation (operator question, confirmed):** the S0 header is **purely cosmetic for data integrity** — it is the optional header/comment record (module name/text) and contributes **zero bytes to the memory map** (the reader never folds S0 data into the image; re-parse adds 0 addresses — asserted by TC-215/AT-015.2). Setting/changing it cannot alter the firmware payload. The only reason to populate it is that some downstream tools *display or key on* the label; it never changes the flashed data. So an operator-set "default header on every S19" (a future user change, out of this batch) is safe by construction.
- **D2 — Default flip is safe:** B2 enumeration found **0 tests** asserting a 16-byte S19 *row width*; every S19 test checks record *type* or re-parses for mem_map equality (invariant under a width flip). The only 16-byte-max assertion is the Intel-HEX emitter (`test_hex_emit.py:83`), out of scope.
- **D3 — US-016 is display-side:** the diff engine + service are already correct; the fix is `_diff_load_maps` surfacing instead of swallowing. LLR-016.2 may need no production change beyond LLR-016.1.

### 6.3 Open risks
- **R1** (low) — header synthesis content when no source S0 (use sanitized output filename); confirm format in Inc1.
- **R2** (low→cleared by D2) — default-flip back-compat; no 16-byte-row test exists.
- **R3** (med) — LLR-016.3 must demonstrably fail pre-fix; capture the pre-fix run output as Phase-4 evidence (do not merely assert).
- **R4** (process) — `/dev-flow` directive edit (escaped-bug → shipped-surface regression) is GLOBAL CONFIG outside the repo; flag at the commit.

### 6.4 Change-first supersession census
All planned files are OUTSIDE the engine-frozen set (`core.py`/`hexfile.py`/`range_index.py`/`validation/`/`tui/a2l.py`/`tui/mac.py`/`tui/color_policy.py`; guards `test_engine_unchanged.py:120-127` + `test_tui_directionb.py::test_tc031_*`). Planned edits: `tui/changes/io.py`, `tui/changes/apply.py`, `tui/models.py`, `tui/services/load_service.py`, `tui/screens_directionb.py`, `tui/services/change_service.py`, `tui/services/variant_execution_service.py`, `tui/app.py` + tests `test_changes_apply.py`, `test_tui_diff_screen.py`, `test_compare_service.py` (`test_hex_emit.py` optional). The S0 capture **reads** `S19File.records` only — no write to `core.py`. Census disposition: best-effort + gate-confirmed (the increment gate is the completeness guarantee).

### 6.5 Increment decomposition (≤5 files each)
- **Inc 1 — Emitter width + populated-S0 data layer:** `tui/changes/io.py` (bpl + s0_header params), `tui/models.py` (NEW LoadedFile S0 field), `tui/services/load_service.py` (capture S0), `tests/test_changes_apply.py` (TC-212..218), `tests/test_hex_emit.py` (optional S19 width — foldable). → ≤5 files. No deps.
- **Inc 2 — Save-flow wiring + selector UI:** `tui/changes/apply.py`, `tui/screens_directionb.py` (selector UI), `tui/services/change_service.py`, `tui/services/variant_execution_service.py`, tests (TC-219/220). → 5 files. Depends on Inc 1.
- **Inc 3 — Compare fix + regression:** `tui/app.py` (`_diff_load_maps` fix), `tests/test_tui_diff_screen.py` (TC-222/224/225), `tests/test_compare_service.py` (TC-223); `tui/services/compare_service.py` only if Inc-3 red test exposes a service defect. → 2-4 files. Independent of Inc 1/2.

### 6.6 Phase-1 reconciliation log
Baseline: **894 collected** (re-measured this phase, `pytest --collect-only`).

**Iteration 1 (first draft):** No locked LLR thresholds changed — no audit rows owed.

**Iteration 2 (two-layer-model fold + operator comments):** triggered by the updated `/dev-flow` process (new "Two-layer validation model" section mandating per-story black-box `AT-NNN` acceptance blocks) + operator D1/D2 comments. Net-new, no HLR/LLR statement or threshold altered, no LLR added/removed:

| Decision ID | What changed | Parent HLR re-read? | Body edit landed? |
|---|---|---|---|
| J-1 | Added §3 Acceptance (black-box) blocks AT-015.1/.2/.3 + AT-016.1/.2 | HLR-015/016 re-read — no change required (AT restates the existing observable outcome at the behavior level; LLR decomposition unchanged) | §3 "Acceptance (black-box)" subsection |
| J-2 | Added TC-226 cross-format integrity (D2) under LLR-015.4 | HLR-015 re-read — no change (TC-226 strengthens the existing reader-as-oracle threshold; emitter signature unchanged) | §5.2 Layer A LLR-015.4 row + §5.3 item 11 |
| J-3 | D1 cosmetic confirmation (operator question) | HLR-015 re-read — no change (S0 already specified inert; confirmation is informative) | §6.2 D1 sub-bullet |

Provisional reconciliations owed at Phase 4: (a) test file paths — TC-212..218/226 assumed `test_changes_apply.py` (fold if no `test_changes_io.py`); (b) all `-k`/node ids + AT-<n> → real `def test_*` names (V-5 now covers AT ids per the updated process); (c) TC-222 assertion channel pending LLR-016.1's surfacing mechanism (locked as panel `sev-error`); (d) TC-224 pre-fix-fail output captured as evidence; (e) AT-<n> ↔ realizing-node map reconciled (AT-015.1→TC-219/220, AT-015.2→TC-226, AT-015.3→TC-213/217, AT-016.1→TC-224, AT-016.2→TC-222/225).

### 6.5b Phase-3 spec amendments (Inc 1)

> Per the §6.5 requirement-amendment convention (Before/After + Deleted/New, never silent), recorded during Inc 1 implementation on 2026-06-24.

**Amendment A — C4 S0 length bound (NEW acceptance threshold on LLR-015.2).**
Origin: review disposition C4 / F-S-02 (`02-review.md`). The S0 data length must not overflow the single-byte `byte_count` field (`_s19_record` renders `byte_count` as `{:02X}`, `io.py:1519`).

- **Parent HLR-015 re-read result:** *no change required.* HLR-015's statement constrains the populated S0 to be re-parseable and inert; a length bound that prevents a malformed (un-parseable) S0 is a refinement of "populated S0 header," not a new behavior. The decomposition (LLR-015.1/.2/.4) is unchanged.
- **LLR-015.2 — Before:** `s0_header: bytes | None = None`; when provided emit `_s19_record("S0", 2, 0, tuple(s0_header))` — no length constraint stated.
- **LLR-015.2 — After (New):** additionally, `len(s0_header) <= 252`; an over-long header raises `ValueError` before any record is emitted (the byte_count field is `address_length(2) + len(data) + 1`, so `len(data) <= 252` keeps `byte_count <= 255`).
- **Deleted:** nothing.
- **New numeric threshold:** `len(s0_header) > 252 → ValueError`, 0 records emitted; `len == 252` accepted and re-parses with 0 reader errors. Covered by `test_c4_overlong_s0_header_raises`.

**Amendment B — S0-inertness premise correction (CORRECTS LLR-015.2 / §6.2 D1 threshold).**
Origin: implementation discovery, Inc 1. **This is a premise error in the spec, surfaced loudly rather than silently worked around.**

- **Finding:** the frozen reader's `S19File.get_memory_map` (`core.py:485-494`) folds **every** record's data into the map by `record.address + offset`, with **no record-type filter** — including the S0 header at address 0. A populated S0 of N bytes therefore adds keys `0..N-1` to `get_memory_map()`. The spec's §6.2 D1 claim ("the reader never folds S0 data into the image; re-parse adds 0 addresses") and LLR-015.2's threshold ("re-parse adds 0 addresses to mem_map") are **false against the actual frozen reader.** (Verified: `case_01_basic_valid/firmware.s19`, 12-byte S0 → `get_memory_map()` contains keys 0..11.)
- **Why it does not break the feature:** the S0 sits at address 0; a real firmware payload sits at high addresses (≥0x100 for S1, 0x80001000+ for S3). The folded S0 bytes never collide with the payload, so the **firmware data records are unchanged** — which is the integrity property HLR-015 actually cares about ("re-parses to a memory map byte-equal to the input" for the *image data*). Downstream flashers ignore S0; `print_header` is the only S0 consumer.
- **Parent HLR-015 re-read result:** *statement still holds, threshold wording corrected.* HLR-015's "byte-equal to the input" is satisfied at the data-record level. The verifiable property is restated against the data-record map, not the full `get_memory_map`.
- **LLR-015.2 — Before (numeric pass threshold):** "32-byte emit → S0 data field len > 0 AND re-parse adds 0 addresses to mem_map AND `get_errors()==[]`."
- **LLR-015.2 — After (numeric pass threshold):** "32-byte emit → S0 data field len > 0 AND the re-parsed **data-record map** (S1/S2/S3 records only) is byte-equal to the input map AND `get_errors()==[]`. (The full `get_memory_map` additionally carries the inert S0 bytes at low addresses; this is reader behavior, out of emitter scope.)"
- **§6.2 D1 — Before:** "the reader never folds S0 data into the image; re-parse adds 0 addresses."
- **§6.2 D1 — After:** "the reader folds ALL record data including S0 (`core.py:485`); the S0 at address 0 does not collide with the high-address payload, so the firmware **data records** are unchanged. S0-inertness is asserted against the data-record map."
- **Deleted:** the unconditional "+0 addresses to mem_map" claim.
- **Test impact:** TC-215 + the C4 boundary case assert inertness via a `_data_record_map` helper (S1/S2/S3 only), with the correction documented inline. AT-015.2 (TC-226) is unaffected — it round-trips an all-data-record image with the default empty S0, so the full-map equality still holds there.
- **Carry to Inc 2 / Phase 4:** AT-015.1's "re-parses byte-equal to the in-app patched map" must use the data-record-map oracle (or emit with the captured source S0 only, accepting the inert low-address keys). Flag for the Inc 2 save-flow tests and the §5.2 AT-015.2 / §5.3 item-6/11 thresholds.
