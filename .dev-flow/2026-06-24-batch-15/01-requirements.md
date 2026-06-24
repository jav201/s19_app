# Requirements Document — s19_app — Batch 2026-06-24-batch-15

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

> **Batch-15 framing.** This batch closes the black-box acceptance gap from the 2026-06-23 audit (memory `project_blackbox_gap_audit`). The two candidate stories were specced in **batch-14** (worktree `inspiring-payne-8d5395`, `.dev-flow/2026-06-23-batch-14/01-requirements.md`) but batch-14's **code was never committed and Phase 4 never ran**. The story ids US-015 / US-016 are carried from batch-14 to preserve traceability. **Phase-0 disk verification (below) corrects the audit's premise: the two stories are NOT the same class.**

| ID | User Story | Source | DoR status |
|----|------------|--------|------------|
| US-016 | As a firmware engineer comparing two images, I want the A↔B compare to report the genuine differing byte runs (or, when an image can't be loaded, a visible diagnostic) instead of a silent "no diff", so that I never mistake a load failure for a clean compare. | batch-14 US-016 (functional testing 2026-06-23); audit gap #1 | **READY** |
| US-015 | As a firmware engineer saving a patched variant, I want to choose 16- or 32-data-byte S19 records (default 32) and emit a populated S0 header in 32-byte mode, so that downstream flashing/diff tools that require the wider record + header accept our output. | batch-14 US-015 (functional testing 2026-06-23, Q4.x); audit gap #1 | **OUT (deferred)** |

#### Refinement log (one block per story)

**US-016 — A↔B compare reflects genuine byte differences / surfaces load failures**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):** user = firmware engineer on the A↔B Diff screen · outcome = comparing two genuinely-different on-disk images reports ≥1 differing byte run with `sev-ok`; comparing where an image fails to load surfaces a diagnostic (`sev-error`) rather than a silent empty "no diff" · why = a false "no diff" can ship a wrong firmware decision · out of scope = rewriting the compare UI or `resolve_input_path`'s absolute-path-not-found branch beyond surfacing the diagnostic.
- **Feasibility (E, S):** implementation path = KNOWN. The compare feature is **shipped in `main`**; the run classification (`compare.diff_mem_maps`) + `compare_service.compare_images` are already correct (verified `compare_service.py:547-552` parses each side fresh and diffs the real maps). Batch-14 root-caused the escaped bug to the **display-side** `_diff_load_maps` swallowing every load exception into `{}` ([app.py:2181-2182](s19_app/tui/app.py:2181)), which renders a load failure as a clean "no diff". The gap is purely that **no test drives the real `#diff_compare_button` → `compare_images` path** — every existing diff test monkeypatches `compare_images` with a fake (`test_tui_diff_screen.py:96`) or calls `render_comparison` directly. · dependencies/unknowns = whether the "two valid different files → ≥1 changed run" assertion already passes on `main` (runs come from the correct service, so it may) vs the "load-failure → diagnostic" assertion which should FAIL pre-fix (the swallow). The retro AT resolves this empirically in Phase 3/4. · fits one batch? = **yes** (1 retro AT, ≤1 small display-side fix in `_diff_load_maps`; engine-frozen set untouched).
- **Evaluability (T) — behavioral, black-box:** ✓ "When the operator sets two absolute paths to genuinely-different on-disk S19 files and presses `#diff_compare_button` (real service, no monkeypatch), the panel renders ≥1 `changed` run and a `sev-ok` status." AND "When an image fails to load, the panel shows a `sev-error` diagnostic, not a silent 0-run clean compare." Both become `AT-NNN` in Phase 1. Verified the surface is drivable: `#diff_path_a`/`#diff_path_b` Inputs + Select-on-external-sentinel → `CompareRequested(variant_a=None, path_a, …)` ([screens_directionb.py:1171](s19_app/tui/screens_directionb.py:1171)); `resolve_input_path` returns an absolute path directly when it `exists()` ([workspace.py:472](s19_app/tui/workspace.py:472)), so two tmp files resolve.
- **Open questions:** none blocking. (Empirical: which of the two black-box criteria fails pre-fix — captured as gate evidence in Phase 4.)
- **Classification:** **READY** — genuine escaped-bug closure matching the batch theme; clear shipped surface; observable outcome with boundary + negative cases.

---

**US-015 — Selectable 16/32 S19 record width + populated S0 header**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✗ (see below) · T ✓
- **Functionality (V, N):** user = engineer saving a patched variant via the TUI · outcome = on save, choose 16 or 32 data-bytes-per-record (default 32) and, in 32-byte mode, write a populated S0 header instead of the current empty `S0` · why = downstream flashing/diff tools may require the wider record and/or a header · out of scope = CLI flags, forcing S1/S2 (record type stays auto-by-max-address), BPL ∉ {16,32}.
- **Feasibility (E, S):** implementation path = KNOWN but this is **net-new feature work, not acceptance closure**. Phase-0 disk verification: the emitter `emit_s19_from_mem_map` is **hardcoded to 16-byte rows** (`range(start, end, 16)`, [io.py:1473](s19_app/tui/changes/io.py:1473)) and emits an **empty, data-free S0** (`_s19_record("S0", 2, 0, ())`, [io.py:1471](s19_app/tui/changes/io.py:1471)). There is **no 16/32 selector and no populated-S0 path anywhere** in the tree (grep: only `HEX_DATA_BYTES_PER_RECORD=16` for the Intel-HEX emitter). batch-14's LLR-015.1–.4 require: a NEW `bytes_per_line` param + NEW `s0_header` param on the emitter; a NEW S0-capture seam on `LoadedFile`/`load_service`; threading a NEW {16,32} selector through **two** save flows (`save_patched_image` + project-save) and a NEW UI control; **and flipping the emitter default 16→32**, which changes existing save behavior and has back-compat blast radius on existing round-trip tests/snapshots. · dependencies/unknowns = the default-flip blast radius (how many existing tests assume 16-byte framing); whether `LoadedFile` must carry the source S0 (a NEW field). · fits one batch? = as a *feature* yes, but it is **larger than a retro-AT** and is **not an escaped bug** (it was never built, never shipped, has no white-box tests to "escape"). · **S = ✗:** materially bigger than US-016 and a different class of work.
- **Evaluability (T) — behavioral, black-box:** the AC is testable ("save in 32-byte mode → emitted S19 has data records >16/≤32 bytes + non-empty S0, re-parses byte-equal via frozen `S19File`"), BUT a *behavioral* AT requires a **shipped surface that doesn't exist yet** (the {16,32} selector). So the story cannot be observed black-box until the feature is built — i.e. its "AT fails pre-fix" fails because the feature is **absent**, not because of a defect.
- **Open questions (the scope decision — operator's call at the DoR gate):** (1) Does batch-15 **build** US-015 as forward feature work (per batch-14 LLR-015.1–.4, incl. the 16→32 default flip), or (2) **defer** it to its own forward-feature batch and keep batch-15 a clean escaped-bug closure (US-016 only)? Building it stretches batch-15 beyond "retroactive acceptance closure" and carries the default-flip blast radius.
- **Classification:** **OUT (deferred)** — premise corrected: US-015 is unbuilt feature work, not an escaped-bug acceptance gap. **Operator decision at the Phase-0 DoR gate (2026-06-24): defer.** US-015 will be run as its own forward-feature `/dev-flow` batch later (it carries the 16→32 default-flip blast radius and a new UI surface, warranting its own V-model run). NOT derived into HLR in batch-15. batch-14's full LLR-015.1–.4 spec is preserved in `.dev-flow/2026-06-23-batch-14/01-requirements.md` as the starting point for that future batch.

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

### HLR-016 — A↔B compare reports genuine diffs or a visible load diagnostic, never a silent "no diff"
- **Traceability:** US-016
- **Statement:**
  - **When** the operator requests an A↔B compare of two images selected by absolute path through the `#diff_compare_button` surface **and** both images load to a usable memory map, the system **shall** report the genuine differing byte runs returned by the comparison engine and render the differing bytes in the hex windows.
  - **If** an A↔B compare is requested **and** either image fails to load to a usable memory map (the file resolves but its re-parse for the hex windows raises, or it yields an empty/degenerate map for a non-empty source path), then the system **shall** surface a `sev-error` load diagnostic on `#diff_status` identifying the affected side, rather than presenting a `sev-ok` status (whether "0 runs" or runs derived from a partially-loaded pair, e.g. `only_a`/`only_b`) or blank hex windows with no explanation. *(F-A-01: the false-verdict outcome is run-count-agnostic — a one-side-degenerate input still yields `only_b` runs + `sev-ok`.)*
- **Rationale (informative):** The defect class is *silent failure indistinguishable from success* — a firmware engineer must be able to trust a "clean compare" verdict. The comparison engine (`compare.diff_mem_maps`, run classification consumed at [compare_service.py:552](s19_app/tui/services/compare_service.py:552)) is already correct and unchanged; the fix locus is the display-side `_diff_load_maps` ([app.py:2151](s19_app/tui/app.py:2151)) plus its caller's unconditional `sev-ok` ([app.py:2144-2148](s19_app/tui/app.py:2144)) — both **outside** the engine-frozen set. This is a verdict-honesty requirement, not an engine change.
- **Validation:** test (pilot, black-box) + test (unit/integration, white-box) + inspection
- **Executed verification:** `pytest -q tests/test_tui_diff_compare_realpath.py` (AT-016.1/.2/.3/.4) **and** `pytest -q tests/test_tui_diff_screen.py` (white-box TC-230/231) **and** `pytest -q` (full suite + frozen guards). *(test file paths provisional-until-Phase-3, V-5.)*
- **Numeric pass threshold:** 4/4 ATs GREEN post-fix; **AT-016.2 RED pre-fix (≥1 captured failing run as gate evidence)**; full suite 0 failed / 0 errored; engine-frozen guards pass.
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):** driven through the real surface (type two absolute paths into `#diff_path_a`/`#diff_path_b`; Selects default to the external sentinel → external path used; press `#diff_compare_button`; observe `#diff_status` + `#diff_range_list`). **No `compare_images` monkeypatch.**

  | AT (provisional) | Stimulus through shipped surface | Observable outcome (primary oracle on `#diff_status`) | Pre-fix |
  |---|---|---|---|
  | **AT-016.1** (regression lock) | Two genuinely-different, well-formed on-disk S19 by absolute path → press `#diff_compare_button` | `#diff_range_list` ≥1 `changed` run; `#diff_status.has_class('sev-ok')`; 0 exceptions | **GREEN** (runs/sev-ok from the correct service, independent of the swallow — locks regression; see R-1) |
  | **AT-016.2** (escaped-bug — the genuine proof) | **Exactly one** side = a non-empty source file whose every S-record is malformed → re-parses to an **empty map without raising** (F-A-04 predicate); other side well-formed → press `#diff_compare_button` | **Primary oracle (F-Q-01):** `#diff_status.has_class('sev-error') is True` AND the diagnostic names the failed side. **Mandatory pre-condition (F-Q-03):** the test asserts `result.refused is False` (the bug is reached through the silent *display* path, not the already-correct refusal branch). | **RED** — pre-fix `result.refused is False`, `#diff_status` renders `sev-ok` (with `only_b` runs from the partially-loaded pair, F-A-02), `has_class('sev-error') is False`; the swallow blanks the window with no diagnostic |
  | **AT-016.3** (no over-correction — raise path) | One side an unresolvable / genuinely-unreadable path that **raises** → press `#diff_compare_button` | `#diff_status` refusal diagnostic (`sev-error`); 0 unhandled exceptions; screen keeps running | **GREEN** (existing `result.refused` branch, [app.py:2127-2132](s19_app/tui/app.py:2127)) — guards the fix doesn't break the already-correct raise path |
  | **AT-016.4** (no over-correction — legit-empty valid, F-Q-05) | One side a **valid** image that legitimately maps few/zero bytes (well-formed records, not all-malformed); other side well-formed → press `#diff_compare_button` | `#diff_status` is **NOT** `sev-error`; the compare proceeds normally (`sev-ok` with the genuine runs) | **GREEN** — guards R-3: the fix must NOT flag a legitimately-empty valid image as a load failure |

  - **Shipped surface:** `AbDiffPanel` (`s19_app/tui/screens_directionb.py`) — `#diff_compare_button` ([:1076](s19_app/tui/screens_directionb.py:1076)), `#diff_status` widget ([:1086-1088](s19_app/tui/screens_directionb.py:1086), constructed `markup=False`), `#diff_range_list` ([:1091](s19_app/tui/screens_directionb.py:1091)). *(F-A-03: `:1123` is the `set_status` method def, not the widget.)*
  - **Deliverable + observation:** the `#diff_status` severity class (`sev-ok` vs `sev-error`) + the `#diff_range_list` run rows — observed through the Pilot, FAILS if the diagnostic is silently absent.
  - **The genuine pre-fix-RED criterion is AT-016.2,** pinned to a single oracle: pre-fix `#diff_status.has_class('sev-error') is False` (with `result.refused is False`) / post-fix `is True`. AT-016.1 is a regression lock (green by design — R-1); AT-016.3/.4 guard over-correction. Empirically confirmed in Phase 3 (write AT → run on main → capture red).

---

## 4. Low-level requirements (LLR)

> Each LLR decomposes an HLR into a verifiable property at the implementation level.
> Same EARS regime. ID format: `LLR-<HLR>.<M>`.

> **Symbol-citation key:** `file:line` = grep-verified at draft; **NEW** = created in Phase 3. AT-/TC- ids provisional-until-Phase-3 (V-5).

### LLR-016.1 — Detect + surface a load-failure / degenerate-map condition instead of a silent empty map *(the one real production change)*
- **Traceability:** HLR-016
- **Statement:** The display-side re-parse path that feeds the hex windows (`S19TuiApp._diff_load_maps`, [app.py:2151](s19_app/tui/app.py:2151)) **shall** distinguish "failed to load" (re-parse raised, **or** re-parse produced an empty/degenerate memory map for a side whose source path was non-empty) from "legitimately loaded but empty", and **shall** cause a `sev-error` diagnostic to be set on the panel status (`AbDiffPanel.set_status`, [screens_directionb.py:1123](s19_app/tui/screens_directionb.py:1123)) identifying the affected side, instead of returning `{}` silently (current swallow at [app.py:2173-2182](s19_app/tui/app.py:2173)).
- **Symbols:** swallow site `app.py:2181-2182` (`except Exception: return {}`); caller's unconditional `sev-ok` `app.py:2144-2148` (must become conditional); `set_status` def `screens_directionb.py:1123`; carrier (status tuple / typed local sentinel / `(ok, maps)` pair) = **NEW — created in Phase 3**.
- **Validation:** test (unit, white-box) + the black-box AT-016.2.
- **Executed verification:** `pytest -q tests/test_tui_diff_screen.py -k "diff_load_maps_surfaces_error"` (TC-230) + `pytest -q tests/test_tui_diff_compare_realpath.py -k "load_failure"` (AT-016.2).
- **Numeric pass threshold:** TC-230 → a load-failure side produces a `sev-error` status naming the side AND 0 paths reach the status line as a silent `sev-ok` `{}`; AT-016.2 → RED pre-fix / GREEN post-fix (1/1).
- **Acceptance criteria (informative):**
  - The two sub-cases are both caught: (a) constructor **raises** (currently swallowed `app.py:2181`); (b) constructor does **not** raise but yields an empty map for a non-empty source path.
  - **Degenerate predicate (F-A-04):** "load failure" = *source file has > 0 non-blank lines AND the loaded map is empty* (equivalently `S19File.records == []` while file bytes > 0). Note an **S0-only file is NOT empty** — `get_memory_map` includes S0 data bytes ([core.py:489-494](s19_app/core.py:489)); the genuinely-degenerate input is **all-records-rejected** (`records == []`). This predicate (not emptiness alone) guards the legitimately-empty valid image (R-3 / AT-016.4).
  - **Out-of-band carrier (F-A-05 / R-5):** the load-failure signal **shall** be carried out-of-band (a per-side status/sentinel consumed by the compare handler), **not** by mutating the `(mem_map_a, mem_map_b)` tuple that `_diff_load_maps` also returns to the report path (`on_ab_diff_panel_report_requested`, [app.py:2186](s19_app/tui/app.py:2186)). If the return shape changes, Inc 2 updates both call sites in the same increment (still ≤5 files).
  - **Plain-text diagnostic (F-S-03):** the side / path / parser-error text **shall** be passed to `set_status` as PLAIN text (relying on `#diff_status` `markup=False`, [screens_directionb.py:1088](s19_app/tui/screens_directionb.py:1088)); the implementer shall NOT interpolate it into Rich markup nor flip the widget to `markup=True`. Phase-3 inspection confirms `#diff_status` stays `markup=False`.

### LLR-016.2 — Genuine diff still reports ≥1 real run + renders differing bytes *(verification-dominant)*
- **Traceability:** HLR-016
- **Statement:** When both images load to non-empty maps and genuinely differ, the A↔B compare **shall** continue to report ≥1 `changed` run via `result.runs` (engine `compare.diff_mem_maps`, surfaced at [app.py:2134](s19_app/tui/app.py:2134),[:2144-2148](s19_app/tui/app.py:2144)) and render the differing bytes through `AbDiffPanel.render_comparison`, with `#diff_status` `sev-ok`.
- **Symbols:** engine/service path already correct, **not edited** this batch (`compare_service.py:546-552`); verification only.
- **Validation:** test (integration, white-box) + the black-box AT-016.1.
- **Executed verification:** `pytest -q tests/test_tui_diff_screen.py -k "result_runs_render"` (TC-231) + `pytest -q tests/test_tui_diff_compare_realpath.py -k "two_different_files"` (AT-016.1).
- **Numeric pass threshold:** TC-231 / AT-016.1 → ≥1 rendered `changed` run for two on-disk S19 known to differ; `#diff_status` `sev-ok` with rendered run count `== len(result.runs)`. *(May be GREEN pre-fix — R-1; recorded as a lock, not as fix-evidence.)*
- **Acceptance criteria (informative):**
  - **Fixture diff-shape (F-Q-04):** Phase 3 records the fixture's exact expected run count so the lock is reproducible (e.g. A vs B differ in exactly N byte runs → assert N rows in `#diff_range_list`); the `== len(result.runs)` equality keeps it self-checking.
  - If the new regression (LLR-016.3) exposes a real defect in the genuine-diff path, it is promoted to a production change here and recorded as a §6.5 amendment.

### LLR-016.3 — Real end-to-end regression test drives the unfaked compare path
- **Traceability:** HLR-016
- **Statement:** The batch **shall** add a regression test that drives `on_ab_diff_panel_compare_requested` ([app.py:2083](s19_app/tui/app.py:2083)) through the real `#diff_compare_button` with **no** `compare_images` monkeypatch (closing the gap at [test_tui_diff_screen.py:95-96](tests/test_tui_diff_screen.py:95)), exercising the real on-disk parse via `resolve_input_path` ([tui/workspace.py:469](s19_app/tui/workspace.py:469)), covering AT-016.1 (different files → ≥1 `changed` + `sev-ok`), AT-016.2 (one degenerate side → `sev-error`, **RED pre-fix**, with `result.refused is False`), AT-016.3 (unresolvable/raising path → refusal diagnostic + 0 unhandled exceptions), AT-016.4 (legit-empty valid → NOT `sev-error`).
- **Symbols:** driver = `app.run_test` Pilot pressing `#diff_compare_button`; gap = spy `test_tui_diff_screen.py:96` + direct `render_comparison`; well-formed fixtures = `tests/conftest.py` `make_large_s19`/`large_s19`; degenerate fixture = **inline `tmp_path` write (F-A-08)** — a 2–3-line all-malformed-S-record string (synthetic, F-S-04), NOT an `examples/` asset. Test file `tests/test_tui_diff_compare_realpath.py` = **NEW** (or extend `test_tui_diff_screen.py`; reconciled Phase 3). All `-k` selectors below are **provisional-until-Phase-3 (V-5).**
- **Validation:** test (e2e, black-box).
- **Executed verification:** `pytest -q tests/test_tui_diff_compare_realpath.py` + a pre-fix run capturing AT-016.2 RED as gate evidence.
- **Numeric pass threshold:** post-fix 4/4 ATs GREEN; pre-fix AT-016.2 asserts FAIL via the pinned oracle (`#diff_status.has_class('sev-error') is False` AND `result.refused is False`); 0 `compare_images` monkeypatch in the AT (inspection).
- **Acceptance criteria (informative):**
  - The pre-fix-fail contrast is *demonstrated* (output attached at Phase 4), not merely claimed.
  - **Reachability gate (R-2, sharpened F-Q-02):** the candidate degenerate construction is a non-empty source file that re-parses to an empty/degenerate map on the display side **without raising** (all-error-line S19 → `records == []`), paired against a well-formed file; the gate is CLEARED when, **pre-fix**, the test observes `result.refused is False` AND `#diff_status` is NOT `sev-error` (the silent bug) and, **post-fix**, observes `sev-error`. **If no construction yields display-side-empty-without-raise while `compare_images` stays non-refused** (e.g. every degenerate input instead makes the service refuse), the headline defect is unreachable through the surface → **halt and escalate to the operator** (premise-correction), do not invent a fix.

---

## 5. Validation strategy

### 5.1 Methods
- **Test:** automated execution (unit / integration / e2e). Default for LLR. **Every `test` LLR must name the exact executed verification and the numeric pass threshold — otherwise it is not executable.**
- **Demo:** observed execution of behavior. Useful for UX-oriented HLRs. Describe the observable procedure + the named qualitative criterion.
- **Inspection:** static review of code or document. Useful for structural requirements. Name the file / commit / section + the observable condition.
- **Analysis:** formal or quantitative reasoning (performance, complexity, security). **Every `analysis` LLR must name the executed calculation (with input values) and the numeric pass threshold — otherwise it is not executable.**
- **Acceptance (black-box):** exercise the system as the user — Textual Pilot e2e (`App.run_test()`), CLI invocation, or artifact-on-disk inspection — and assert the story's outcome through the SHIPPED surface with representative + boundary + negative evidence + the actual deliverable observed. Marked `AT-NNN` (distinct from white-box `TC-NNN`). This is the `test (pilot)` form, NOT `demo`. Required for every user story; an output-producing story's `AT` must FAIL if the output is silently absent.

> Reminder from the batch-02 + batch-03 post-mortems: the absence of an executed verification + numeric pass threshold on `test`/`analysis` requirements was the recurring root cause of forced phase-1 iteration. Capture at draft time, not at the phase-2 gate.

### 5.2 Dual-traceability table

> A requirement is complete only when BOTH chains exist (per the Two-layer validation rule).

**Behavioral chain (black-box) — per user story:**

| US | Observable outcome | Shipped surface | Acceptance test (`AT-NNN`) | Observed? |
|----|--------------------|-----------------|----------------------------|-----------|
| US-016 | Two genuinely-different on-disk S19 (absolute paths) → ≥1 `changed` run in `#diff_range_list` + `#diff_status` `sev-ok` | `AbDiffPanel` (`#diff_path_a/b`, `#diff_compare_button`, `#diff_range_list`, `#diff_status`) | **AT-016.1** (regression lock) | Phase 4 |
| US-016 | An image that **fails to load** → `#diff_status` `sev-error` diagnostic, NOT a silent 0-run clean render | same | **AT-016.2** (escaped-bug — RED pre-fix) | Phase 4 |
| US-016 | A genuinely-unresolvable / raising path → refuses with a `sev-error` diagnostic + 0 raised exceptions | same | **AT-016.3** (negative/boundary — raise path) | Phase 4 |
| US-016 | A **valid** image that legitimately maps few/zero bytes → NOT `sev-error`; compare proceeds | same | **AT-016.4** (negative — over-correction guard, F-Q-05) | Phase 4 |

**Functional chain (white-box) — per requirement:**

| Requirement | Method | Test Case (`TC-NNN`) | Notes |
|-------------|--------|----------------------|-------|
| HLR-016 | test (pilot) | AT-016.1/.2/.3/.4 | observed black-box through the shipped surface |
| LLR-016.1 | test (unit) | TC-230 | `_diff_load_maps` + caller surface a `sev-error` instead of silent `{}` |
| LLR-016.2 | test (integration) | TC-231 | genuine `result.runs` propagate to `#diff_range_list` (verification-dominant; may be green pre-fix per R-1) |
| LLR-016.3 | test (e2e) | AT-016.1/.2/.3/.4 | **deliberate exception (F-A-06/F-Q-06):** LLR-016.3 is the acceptance-test artifact itself; its functional verification is the "no `compare_images` monkeypatch" inspection, not a separate white-box TC |

> ids chosen to avoid collision with batch-13 (TC-201..211) and batch-14's planned band (TC-212..225): AT band **AT-016.1/.2/.3/.4**, white-box **TC-230/231**. All ids + all `-k` selectors provisional-until-Phase-3 (V-5), reconciled at Phase 4.

### 5.3 Batch acceptance criteria
- All 4 ATs GREEN post-fix (AT-016.1/.2/.3/.4) on the merge tree.
- **Escaped-bug evidence captured:** AT-016.2 demonstrated RED on the pre-fix tree (pinned oracle: `#diff_status.has_class('sev-error') is False` AND `result.refused is False`), failing run attached as Phase-4 evidence. *If AT-016.2 passes pre-fix, the fix is unproven and the gate FAILS — re-derive the failing input before proceeding.*
- No monkeypatch escape: inspection confirms no AT stubs `compare_images`; AT-016.2 drives the real on-disk parse.
- White-box TC-230/231 pass.
- No regression: `pytest -q` full suite 0 failed / 0 errored; engine-frozen guards (`tests/test_engine_unchanged.py`, `tests/test_tui_directionb.py::test_tc031_*`) still pass.
- The **R-2 reachability item** is answered before implementation is declared done (the bug is reproducible through the surface per the sharpened gate, or the batch halts and escalates).

---

## 6. Appendices (optional)

### 6.1 Extended glossary
- **Escaped bug:** a defect the white-box suite missed because no test observed the user-facing deliverable through the shipped surface.
- **Degenerate map:** an empty/near-empty `mem_map` produced without the parser raising (the collect-don't-abort contract of the frozen reader), so `compare_images` does not refuse.

### 6.2 Relevant design decisions

| # | Decision | Rationale |
|---|---|---|
| D-1 | Fix lives in `_diff_load_maps` + its caller, never in the parsers. | Engine-frozen guards freeze `core.py`/`hexfile.py`/`validation/`/etc; `_diff_load_maps` ([app.py:2151](s19_app/tui/app.py:2151)) is outside the set and is the swallow locus. |
| D-2 | **The honesty fix is detection + surfacing, not "stop swallowing."** | Confirmed on disk: a genuine *raise* already routes to `compare_images._refused` ([compare_service.py:546-550](s19_app/tui/services/compare_service.py:546)) → existing `sev-error` branch ([app.py:2127-2132](s19_app/tui/app.py:2127)). The silent case is the *non-raising empty/degenerate map*, which `compare_images` does **not** refuse — so merely un-swallowing the `except` would not fix the headline case; the fix must detect the degenerate-map condition and override the unconditional `sev-ok` ([app.py:2144-2148](s19_app/tui/app.py:2144)). **This refines batch-14's LLR-016.1, whose "stop swallowing" framing would not have fixed the headline case.** |
| D-3 | Drive the black-box AT through `#diff_compare_button` with the real service. | Every existing diff test fakes `compare_images` ([test_tui_diff_screen.py:96](tests/test_tui_diff_screen.py:96)) — precisely why the defect escaped. |
| D-4 | Identify the failing side in the diagnostic. | "A load failure occurred" is not actionable; `_diff_load_maps` already loads sides separately, so per-side attribution is cheap. |
| D-5 | One production file (`app.py`) + tests; no engine / `compare_service` / `screens_directionb` widget changes. | `set_status` already accepts a severity class; the panel surface suffices as-is. |

### 6.3 Open risks

| ID | Risk | Severity | Mitigation / Phase-3 action |
|---|---|---|---|
| **R-1** | AT-016.1 (genuine-diff → ≥1 run + sev-ok) likely **passes pre-fix** — runs + `sev-ok` come from the correct service, independent of the swallowed `_diff_load_maps`. If it were the only black-box criterion, no AT would be red pre-fix and the gate would be satisfied by a test that proves nothing. | **High (gate-critical)** | The genuine pre-fix-RED criterion is **AT-016.2**. Phase 3 MUST write AT-016.2, run on `main`, capture RED, attach as gate evidence. AT-016.1 is explicitly a regression-lock. |
| **R-2** | **The exact load-failure mode reaching `_diff_load_maps` while `compare_images` SUCCEEDS is an open empirical question.** A *raised* exception makes `compare_images` refuse → fix moot for that path. Only a *non-raising empty/degenerate map* slips through to a silent `sev-ok`. It is not yet proven such an input is producible through the surface (note: empty-vs-nonempty would yield `only_X` runs, not 0 — the true 0-run "no diff" needs both sides to collapse to equal/empty). | **High** | Phase 3 Increment 1 (TDD red-first) constructs the degenerate fixture empirically and confirms on `main` that the screen renders a silent clean compare BEFORE asserting the AT. **If no such input exists, the headline defect is unreachable through the surface → halt and escalate (premise-correction); do not invent a fix.** |
| **R-3** | Over-correction: flagging a *legitimately empty but valid* image as a load failure → false `sev-error`. | Medium | LLR-016.1 conditions the failure signal on *non-empty source path → empty map*, not emptiness alone; AT-016.3 guards the refusal path. |
| **R-4** | `set_status` severity-class contract assumed stable (`sev-error` round-trips through `css_class_for_severity`). | Low | Verify the class string in Phase 3 against `color_policy.py::SEVERITY_CLASS_MAP` (frozen — read-only). |
| **R-5** | `_diff_load_maps` also feeds the report generator ([app.py:2186](s19_app/tui/app.py:2186) via `render_comparison`/report). Changing its return shape could ripple to `on_ab_diff_panel_report_requested`. | Medium | Prefer a carrier that does not change the `(mem_map_a, mem_map_b)` tuple, or update both call sites in the same increment; census flags `app.py`. |

#### Change-first census — files this batch touches (all OUTSIDE the engine-frozen set)

| File | Role | Edit type | Frozen? |
|---|---|---|---|
| `s19_app/tui/app.py` | `_diff_load_maps` (`:2151`) + caller status logic (`:2144-2148`) | Production edit (LLR-016.1) | **NO** ✅ (absent from `_ENGINE_PATHS`) |
| `tests/test_tui_diff_compare_realpath.py` (NEW) or `tests/test_tui_diff_screen.py` (extend) | Real-service regression ATs (LLR-016.3) + white-box TC-230/231 | Test add | **NO** ✅ |
| degenerate fixture = **inline `tmp_path` write** in the test (F-A-08) | Drives AT-016.2 | (no separate file) | **NO** ✅ |
| `REQUIREMENTS.md` | R-* traceability row for the new behavior/test | Doc edit | **NO** ✅ |
| `.dev-flow/2026-06-24-batch-15/*` | dev-flow artifacts | Doc add | **NO** ✅ |

**Frozen set NOT touched:** `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`, plus `compare_service.py` (service) and `screens_directionb.py` (widget) — read-only this batch.

#### Proposed increment decomposition (≤5 files each; TDD red-first)

- **Inc 1 — Red regression (LLR-016.3; AT-016.2 RED on main first).** Files: `tests/test_tui_diff_compare_realpath.py` (NEW) with the degenerate fixture written inline via `tmp_path`. **Exit:** AT-016.2 RED on pre-fix `main` per the pinned oracle (`#diff_status` not `sev-error` AND `result.refused is False`, captured); AT-016.1 + AT-016.3 + AT-016.4 GREEN. *If Inc 1 cannot produce a non-raising empty-map input that keeps `compare_images` non-refused (R-2) → halt + escalate, do NOT proceed to Inc 2.*
- **Inc 2 — Production fix (LLR-016.1).** Files: `s19_app/tui/app.py` (`_diff_load_maps` + caller; if the load-failure carrier changes the return shape, this increment also touches `on_ab_diff_panel_report_requested` in the same file per F-A-05/R-5). **Exit:** AT-016.2 flips GREEN; AT-016.1/.3/.4 stay GREEN; `pytest -q` green; frozen guards pass; `#diff_status` still `markup=False`.
- **Inc 3 — Traceability close (LLR-016.2).** Files: `REQUIREMENTS.md` + `.dev-flow/2026-06-24-batch-15/01-requirements.md` finalize. **Exit:** R-* row updated; any genuine LLR-016.2 defect recorded as a §6.5 amendment.

### 6.4 Phase-1 reconciliation log
*(Per the parent-HLR re-read rule. One audit table per reconciliation event: `Decision ID | What changed | Parent HLR re-read? | Body edit landed?`.)*

**Iteration 2 (2026-06-24) — fold of the Phase-2 register (0 blocker / 5 major / 15 minor).** Body-first: §3/§4/§5 ACs edited first, then this audit. No re-derivation, no design change; all edits are the reviewers' own prescriptions.

| Decision ID | What changed | Parent HLR re-read? | Body edit landed? |
|---|---|---|---|
| J-1 (F-A-01) | HLR-016 clause 2 outcome made run-count-agnostic (`only_a/b` partial-load case, not just "0 runs") | Yes — HLR-016 still holds; refinement is at the outcome-wording level, no LLR re-derivation | §3 Statement |
| J-2 (F-A-02 / F-Q-01 / F-Q-03) | AT-016.2 pinned to one oracle (`#diff_status.has_class('sev-error')` False pre / True post) + **mandatory `result.refused is False` pre-condition** (prevents collapse into AT-016.3) + one-side-degenerate disambiguation | Yes — strengthens HLR-016 Acceptance; no statement change | §3 AT table + §5.3 |
| J-3 (F-A-04 / F-A-05 / F-S-03) | LLR-016.1 ACs: degenerate predicate (`records==[]`, S0-only NOT empty), out-of-band carrier (no maps-tuple mutation; report path), plain-text diagnostic (`markup=False`) | Yes — LLR-016.1 statement unchanged; ACs added | §4 LLR-016.1 |
| J-4 (F-Q-05) | NEW **AT-016.4** (legitimately-empty valid image → NOT `sev-error`) added as over-correction guard | Yes — additive AT under HLR-016; no statement change | §3 AT table + §5.2 + §5.3 |
| J-5 (minors F-A-03/06/07/08, F-Q-04/07, F-S-04) | citation fix (`#diff_status` :1086), LLR-016.3 functional-cell note, inline `tmp_path` fixture pin, fixture diff-shape note, `-k` provisional umbrella, synthetic-fixture note | n/a — doc-tidy, no requirement change | §3/§4/§5/§6 |

**Inter-batch supersession note (F-A-07):** The D-2 root-cause refinement ("detect the non-raising degenerate map + override the unconditional `sev-ok`", superseding batch-14's "stop swallowing in `_diff_load_maps`") is a **NEW derivation**, not an amendment — batch-14's code never landed and its spec was never locked/committed, so there is nothing to amend (no §6.5 block owed). Recorded here for traceability.

**Phase-4 provisional-id reconciliation (V-5, 2026-06-24).** Validation reconciled the provisional ids against the real collected nodes:

| Provisional id | Reconciled to | Note |
|---|---|---|
| AT-016.1/.2/.3/.4 | the 4 real functions in `tests/test_tui_diff_compare_realpath.py` | all GREEN post-fix; AT-016.2 RED pre-fix captured (§04-validation §2) |
| TC-230 (LLR-016.1 white-box unit) | **subsumed by AT-016.2** | no separate white-box test created; AT-016.2 drives the real `_diff_load_maps` predicate + caller branch with real inputs (no mock) — the mechanism IS exercised. Deliberate reconciliation (04-validation §3), consistent with LLR-016.3's existing AT mapping. |
| TC-231 (LLR-016.2 integration) | **subsumed by AT-016.1** | verification-only LLR (engine unchanged); AT-016.1 drives real `result.runs` → `#diff_range_list`. |

The §5.2 functional table's TC-230/231 cells are retained as the historical provisional plan; the live coverage is the subsuming ATs. No orphan ids.

### 6.5 Requirement amendments (Before / After · Deleted / New)
*(Used by `iterate-to-refine` (Phase 1 from a Phase-4 black-box failure) and by Phase-3 spec amendments. One block per amendment: **Before → After** text · **Deleted / New** tokens · parent-HLR re-read result · the re-derived HLR/LLR + their `TC`/`AT`. Never silently edit a locked requirement.)*
