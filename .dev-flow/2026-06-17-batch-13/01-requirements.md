# Requirements Document — s19_app — Batch 2026-06-17-batch-13

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
This document derives the HLR (IEEE 830 + EARS) and LLR for batch-13 from the two READY user stories US-013 and US-014 (§2.6). It is the Phase-1 requirements artifact of the V-model: it states scope, fixes the requirement IDs, records the change-first census and increment decomposition, and carries the assumptions/risks the later phases verify. §1, §3, §4, §6 are owned by the architect; §5 (validation strategy) is owned by qa-reviewer and is written separately.

### 1.2 Scope

**In scope (two existing-substrate TUI surfaces — no new engine math):**

- **US-013 — CRC config from file.** Add a path `Input` + "Load config" `Button` to the CRC branch of `OperationsScreen` ([screens.py:657-683](../../s19_app/tui/screens.py)) that reads a `.json` config file's RAW TEXT into the editable `#operation_config` `TextArea` ([screens.py:668](../../s19_app/tui/screens.py)), reusing the existing resolve + size-cap read contract (`resolve_input_path` + `READ_SIZE_CAP_BYTES`). The dummy `DUMMY_CONFIG_TEXT` ([crc_config.py:47](../../s19_app/tui/operations/crc_config.py)) stays pre-loaded as fallback. Load errors surface and DO NOT run the check (collect-don't-abort). The CRC run path is unchanged: it still parses the editor text on Execute via `parse_crc_config(text)` ([crc_config.py:242](../../s19_app/tui/operations/crc_config.py), consumed at [screens.py:838-840](../../s19_app/tui/screens.py)).

- **US-014 — Paste change-document (+ dummy) in the Patch Editor.** Add a paste `TextArea` pre-loaded with a DUMMY `s19app-changeset` (kind=change, FAKE values) plus a control that parses the pasted text into the owned `ChangeService` document, at CRC-surface parity. The parsed document feeds the EXISTING apply / containment / verify / save-back path unchanged.

**Out of scope (DO NOT re-specify — already SHIPPED, Phase-0 disk verification):**

- The Patch Editor's shipped load-from-file (`ChangeService.load` → `read_change_document` [io.py:266](../../s19_app/tui/changes/io.py)), apply (`ChangeService.apply`), INSIDE/PARTIAL/OUTSIDE containment, contained emit (`emit_s19_from_mem_map` [io.py:1300](../../s19_app/tui/changes/io.py) via `copy_into_workarea`), and `verify_written_image` reader-as-oracle. US-014 introduces NO new write surface.
- The two-stage write modal and a worker-thread for the write (operator-DEFERRED).
- CLI (`s19tool`) config-load / paste (TUI-only this batch).
- Changing the CRC engine, CRC params, or auto-running the check on config load.

**Surgical truth-fix (not an LLR feature):** the stale docstring at [app.py:938](../../s19_app/tui/app.py) ("Screen 6 (Patch Editor) is an inert before/after view shell … neither wires patch or diff logic") describes a state that no longer exists — the live `PatchEditorPanel` + `ChangeService` + handlers fully wire the change flow. This batch corrects that docstring as a surgical truth-fix. It is recorded here so a reviewer expects the edit; it carries no `shall` and is not decomposed as a requirement.

### 1.3 Definitions, acronyms, abbreviations
| Term | Definition |
|------|------------|
| CRC surface | The `OperationsScreen` CRC branch ([screens.py:657-683](../../s19_app/tui/screens.py)): operations list + editable `#operation_config` `TextArea` + Execute / Write CRC / Close. |
| Patch Editor | The `PatchEditorPanel` rail screen ([screens_directionb.py:325](../../s19_app/tui/screens_directionb.py)) driving the v2 `s19app-changeset` change flow. |
| `s19app-changeset` | The v2 change-file format id (`FORMAT_ID` [io.py:106](../../s19_app/tui/changes/io.py)), version `2.0`; `kind ∈ {change, check}` ([io.py:119](../../s19_app/tui/changes/io.py)). |
| collect-don't-abort | The reader/parser contract: every data-quality fault is a collected error/`ValidationIssue`; the function returns and NEVER raises. |
| consumer-input-contract | The batch-12 control: an LLR wiring a producer to an existing consumer must cite the consumer's REAL input type at `file:line`. |
| frozen-engine set | The git-frozen parsing/validation modules guarded against diff vs `main` (see §6.2). |
| `READ_SIZE_CAP_BYTES` | The shared pre-read size cap ([io.py:192](../../s19_app/tui/changes/io.py), `= DEFAULT_COPY_SIZE_CAP_BYTES`); imported by `crc_config.py` ([crc_config.py:32](../../s19_app/tui/operations/crc_config.py)). |
| `PATCH_ACTIONS_V2` | The fixed Patch Editor action set ([app.py:126-138](../../s19_app/tui/app.py)), asserted exactly in [test_tui_patch_editor_v2.py:184](../../tests/test_tui_patch_editor_v2.py). |

### 1.4 References
- `01-requirements.md` §2.6 — refined stories US-013 / US-014, INVEST/DoR, acceptance criteria (this document).
- `PLAN.md` — batch-13 living plan: Phase-0 headline finding, risks R-A/R-B/R-C, b12 conventions.
- IEEE 830 (SRS) + EARS (Easy Approach to Requirements Syntax) — HLR/LLR statement grammar.
- batch-12 close artifacts — origin of the consumer-input-contract and facade/test-blast-radius controls (J-3 mis-binding).

### 1.5 Document overview
§2 (overall description + source stories) is pre-written. §3 states the two HLRs (EARS). §4 decomposes them into LLRs (EARS) with consumer-input-contract citations. §5 (qa-reviewer) holds the validation strategy. §6 carries assumptions/dependencies, risks (RK-*), the change-first census (A-1/A-2 + frozen-set check + facade/test blast-radius), the increment decomposition (≤5 files each), and the Phase-1 reconciliation log.

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
| US-013 | As a firmware operator using the CRC surface, I want to load the CRC config JSON from a file (not only paste it), so that I can run a CRC check against a real on-disk config without hand-copying it into the editor. | batch-13 brief (operator) | **READY** |
| US-014 | As a firmware operator using the Patch Editor, I want to paste a whole `s19app-changeset` (kind=change) JSON document into an editable field pre-loaded with a dummy reference, so that I can drive a multi-entry patch from a pasted document the same way the CRC surface lets me paste a config — instead of only typing entries field-by-field or loading from a file path. | batch-13 brief (operator), re-scoped at Phase-0 gate | **READY** |

> **Phase-0 premise correction (load-bearing).** The brief framed US-014 as "wire the inert Patch Editor (#screen_patch, app.py ~:938 — SHELL INERTE)". Disk verification contradicts this: the Patch Editor is a **fully-wired, shipped** change flow. The "inert shell" wording is a **stale docstring** at `app.py:938` ("inert before/after view shell … neither wires patch or diff logic"), not the live code. The live `PatchEditorPanel` ([screens_directionb.py:325](../../s19_app/tui/screens_directionb.py)) + `ChangeService` ([services/change_service.py:284](../../s19_app/tui/services/change_service.py)) + `app.py` handlers ([app.py:1247](../../s19_app/tui/app.py)) already deliver: load-from-file, apply (INSIDE/PARTIAL/OUTSIDE via `classify_containment`), emit via `emit_s19_from_mem_map`, **contained** write via `copy_into_workarea` (no arbitrary path, no clobber — [changes/apply.py:586-635](../../s19_app/tui/changes/apply.py)), and `verify_written_image` reader-as-oracle ([change_service.py:867](../../s19_app/tui/services/change_service.py)). Operator decision at the Phase-0 gate: **"Trim to the real gap"** — US-014 reduces to the one genuinely-missing ergonomic (paste-full-changeset + dummy pre-load, CRC parity). The shipped load/apply/verify/save-back is left intact. The stale `app.py:938` docstring will be corrected as a surgical truth-fix.

#### Refinement log (one block per story)

**US-013 — CRC config from file in the CRC surface**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):** user = firmware operator on the CRC OperationsScreen · outcome = a path `Input` + "Load config" `Button` that ingests a `.json` config into the editable `#operation_config` TextArea via the existing `crc_config.read_crc_config(path)` substrate (`resolve_input_path` + `READ_SIZE_CAP_BYTES` size-cap-before-read + collect-don't-abort) · why = run a real on-disk config without re-typing/pasting it · out of scope = CLI (`s19tool`) config-load (TUI-only); changing the CRC engine/params; auto-running the check on load.
- **Feasibility (E, S):** implementation path = add the two controls to the CRC branch of OperationsScreen ([screens.py:667-677](../../s19_app/tui/screens.py)); on press, resolve + size-cap + read the file's raw text into the TextArea, reusing the **already-existing** `read_crc_config` path-contract; run still flows through the existing parse-on-run (`parse_crc_config`) so the editor stays the single source of truth. **Consumer-input-contract (b12 control):** the consumer is the CRC run path, which today reads `#operation_config` TextArea text → `parse_crc_config(text: str)` ([crc_config.py:242](../../s19_app/tui/operations/crc_config.py)); `read_crc_config(path, base_dir)` ([crc_config.py:156](../../s19_app/tui/operations/crc_config.py)) returns `(Optional[CrcConfig], list[str])`, NOT raw text — Phase-1 must reconcile "populate the editable TextArea" (needs raw text) with "use read_crc_config" (returns parsed). · dependencies/unknowns = the read-raw-text-vs-use-parsed reconciliation (Phase-1 architect; default leaning = read raw text into the TextArea via resolve_input_path + READ_SIZE_CAP_BYTES, keep parse-on-run). · fits one batch? = yes, 1 increment, ≤3 files (screens.py + a test + optional dummy fixture).
- **Evaluability (T):** AC-1 "When the operator types a valid `.json` config path and presses Load config, the system shall replace the `#operation_config` TextArea contents with the file's text." AC-2 "When the path is irresolvable / the JSON is invalid / the file is over `READ_SIZE_CAP_BYTES`, the system shall surface the error and shall not run the CRC check (collect-don't-abort)." AC-3 "When no file is loaded, the system shall keep `DUMMY_CONFIG_TEXT` pre-loaded as the editable reference."
- **Open questions:** (resolved at gate) one Phase-1 design nuance only (raw-text vs parsed ingestion); not a DoR blocker.
- **Classification:** `READY` — proceeds to Phase 1.

**US-014 — Paste a full change-document (+ dummy) in the Patch Editor**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓  (after Phase-0 re-scope; the original framing was NOT ready — premise false)
- **Functionality (V, N):** user = firmware operator on the Patch Editor (#screen_patch) · outcome = an editable field pre-loaded with a DUMMY `s19app-changeset` (kind=change, FAKE values) into which the operator can paste a whole change-document, plus a control that parses that pasted text into the owned `ChangeService` document (collect-don't-abort) — then the **existing** apply / before-after / INSIDE-PARTIAL-OUTSIDE / two-confirm-and-write path takes over unchanged · why = drive a multi-entry patch from a pasted document, at CRC-surface parity, without typing entries one field at a time · out of scope (re-scope boundary — DO NOT re-implement) = the shipped load-from-file, apply, emit, `copy_into_workarea` containment, and `verify_written_image` reader-as-oracle; replacing the existing inline save-back with a two-stage modal (operator deferred); a worker-thread for the write (deferred); CLI.
- **Feasibility (E, S):** implementation path = add a paste TextArea + `DUMMY_CHANGESET_TEXT` to `PatchEditorPanel` ([screens_directionb.py:325](../../s19_app/tui/screens_directionb.py)) and a text→document parse entry analogous to CRC's `parse_crc_config`. **Consumer-input-contract (b12 control):** the existing file path uses `ChangeService.load(path_text, base_dir)` → `read_change_document(path_text, base_dir)` ([io.py](../../s19_app/tui/changes/io.py)). **Phase-1 MUST verify (assumed — verify in Phase 1):** whether `changes/io.py` exposes a parse-from-**string** entry (analogous to `parse_crc_config(text)`) or whether one must be added in the (non-frozen) `changes` family; cite `read_change_document`'s real signature `file:line` before wiring. · dependencies/unknowns = the text-parse seam existence (above). · fits one batch? = yes, small; ≤5 files (panel + service text-parse + app.py action wiring + dummy + tests). **Facade/test blast-radius (b12 control):** Phase 1 must budget the `PatchEditorPanel.ActionRequested` action-set change (PATCH_ACTIONS_V2 is a fixed 9-action set asserted in tests — adding a `parse_pasted` action touches the panel, app.py routing, and any test hardcoding the action set).
- **Evaluability (T):** AC-1 "When the Patch Editor mounts, the system shall pre-load an editable field with a dummy `s19app-changeset` (kind=change, FAKE values) as a format reference." AC-2 "When the operator pastes a valid change-document and triggers parse, the system shall replace the owned change document with the parsed entries (collect-don't-abort: malformed input surfaces faults and does not crash)." AC-3 "When the parsed document is applied and the operator confirms the write, the system shall persist the patched S19 through the existing contained-emit + verify path (no new write surface introduced)."
- **Open questions:** (resolved at gate) re-scope to the ergonomic gap only; security relevance is input-parse (operator-pasted JSON), not a new write surface — the write is unchanged shipped code with existing containment+verify. Phase 2 will confirm whether `security-reviewer` sign-off is mandatory (write-path) or advisory (input-parse only); flagged honestly, not assumed.
- **Classification:** `READY` — proceeds to Phase 1 at the trimmed scope.

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

> **Final ID map (qa §5 must reconcile against this):**
> - **HLR-013** ← US-013. LLR: LLR-013.1, LLR-013.2, LLR-013.3. (3 LLR)
> - **HLR-014** ← US-014. LLR: LLR-014.1, LLR-014.2, LLR-014.3. (3 LLR)
> - **Totals: 2 HLR, 6 LLR.** No LLR added/removed/promoted at reconciliation (see §6.4).

### HLR-013 — CRC config file-load surface
- **Traceability:** US-013
- **Statement:** Where the CRC operation is the selected operation on the `OperationsScreen`, when the operator supplies a config file path and triggers a load, the system shall ingest the file's raw text into the editable `#operation_config` `TextArea` under the existing resolve + size-cap read contract, and if the path is unresolvable, over the size cap, or otherwise unreadable, then the system shall surface the fault and shall not modify the editor contents nor run the CRC check.
- **Rationale (informative):** The operator should be able to run a CRC check against a real on-disk config without hand-copying it into the editor, at parity with how the editor is already the single source of truth on Execute. Reusing the shipped `read_crc_config` substrate (`resolve_input_path` + `READ_SIZE_CAP_BYTES`) keeps the read-path contract and the collect-don't-abort guarantee identical to the file readers already in the tree, and leaves the CRC engine and parse-on-run path untouched.
- **Validation:** test
- **Executed verification:** `pytest -q tests/test_tui_crc_surface.py` (CRC config-load TUI surface cases) + `pytest -q tests/test_crc_config.py -k read_crc_config_text` (the raw-text reader unit seam, **F-Q-06**) + `signature/inspection diff vs main` confirming the CRC run path still consumes `parse_crc_config(TextArea.text)` unchanged. Provisional file/`-k`/node ids, reconciled at Phase 4.
- **Numeric pass threshold:** all new CRC config-load TCs pass (exit 0); 0 regressions in the existing `OperationsScreen` CRC suite; a load fault leaves `#operation_config` unchanged AND runs 0 CRC checks.
- **Priority:** high

### HLR-014 — Patch Editor paste-changeset surface
- **Traceability:** US-014
- **Statement:** While the Patch Editor is mounted, the system shall present an editable field pre-loaded with a dummy `s19app-changeset` (kind=change, FAKE values) as a format reference; when the operator pastes a change-document and triggers a parse, the system shall parse the pasted text into the owned `ChangeService` change document under collect-don't-abort and feed it to the existing apply / containment / verify / save-back path unchanged; and if the pasted text is malformed, then the system shall surface the collected findings and shall not crash nor introduce any new write surface.
- **Rationale (informative):** The operator should be able to drive a multi-entry patch from a pasted document, at CRC-surface parity, instead of typing entries field-by-field or only loading from a path. The shipped load/apply/emit/contained-write/verify path is intentionally reused without modification; the only genuine delta is the paste field, the dummy pre-load, and a text→document parse seam analogous to `parse_crc_config(text)`.
- **Validation:** test
- **Executed verification:** `pytest -q tests/test_tui_patch_editor_v2.py` (paste/parse cases + the `PATCH_ACTIONS_V2` set assertion at [test_tui_patch_editor_v2.py:184](../../tests/test_tui_patch_editor_v2.py)) + `pytest -q tests/test_changes_schema.py` (text-parse seam vs file-read parity — provisional node ids, reconciled at Phase 4).
- **Numeric pass threshold:** all new paste/parse TCs pass (exit 0); the `PATCH_ACTIONS_V2` assertion passes with the extended set; a parsed-from-string valid document yields the SAME `ChangeDocument` (entries + issue codes) as the equivalent file read; malformed paste surfaces ≥1 collected finding and 0 crashes.
- **Priority:** high

---

## 4. Low-level requirements (LLR)

> Each LLR decomposes an HLR into a verifiable property at the implementation level.
> Same EARS regime. ID format: `LLR-<HLR>.<M>`.

> **Symbol-citation legend.** Every named symbol carries a grep-verified `file:line`, or `NEW — created in Phase 3` when the increment creates it. Executed-verification file paths / `-k` selectors / node ids are **provisional-until-Phase-3** (V-5, b09); reconciled from the real tree at Phase 4.

#### HLR-013 → LLR

### LLR-013.1 — CRC config path Input + Load button placement
- **Traceability:** HLR-013
- **Statement:** The CRC branch of `OperationsScreen.compose` shall yield a config-path `Input` and a "Load config" `Button`, displayed only while the CRC operation is highlighted, alongside the existing `#operation_config` `TextArea`.
- **Validation:** test (integration)
- **Executed verification:** `pytest -q tests/test_tui_crc_surface.py -k crc_config_load` (provisional id) driving an `App.run_test()` that highlights the CRC row and asserts the two new widgets exist and are displayed; and asserts they are hidden when a non-CRC operation is highlighted (parity with `_sync_config_visibility` [screens.py:742-772](../../s19_app/tui/screens.py)).
- **Numeric pass threshold:** exit 0; both new widgets present + displayed on the CRC row; both hidden off the CRC row (display toggled with the existing `#operation_config` / `#operation_config_label`).
- **Acceptance criteria (informative):**
  - The new widget ids are `NEW — created in Phase 3` (e.g. a config-path `Input` and "Load config" `Button`); they extend the `compose` tree at [screens.py:657-683](../../s19_app/tui/screens.py) and are toggled by `_sync_config_visibility` [screens.py:742-772](../../s19_app/tui/screens.py).
  - No change to the Execute / Write CRC / Close buttons ([screens.py:675-677](../../s19_app/tui/screens.py)).

### LLR-013.2 — Resolve + size-cap + read raw text into the TextArea (collect-don't-abort)
- **Traceability:** HLR-013
- **Statement:** When the "Load config" button is pressed with a non-empty path, the system shall resolve the path through `resolve_input_path` ([workspace.py:469](../../s19_app/tui/workspace.py)), enforce the `READ_SIZE_CAP_BYTES` cap before reading ([io.py:192](../../s19_app/tui/changes/io.py)), read the file's RAW text, and replace the `#operation_config` `TextArea` contents with that text; on success it shall NOT parse, validate, or run the CRC check.
- **Validation:** test (integration)
- **Executed verification:** `pytest -q tests/test_tui_crc_surface.py -k crc_config_load_ok` (provisional id) loading a valid synthetic config fixture and asserting `#operation_config` `.text` equals the file text; plus a unit case on the raw-text reader seam over a fixture path.
- **Numeric pass threshold:** exit 0; `#operation_config.text` byte-equals the loaded file text; `parse_crc_config` is NOT called on load; 0 CRC checks run.
- **Acceptance criteria (informative):**
  - **Consumer-input-contract (b12):** the load PRODUCES raw text into `#operation_config`; the existing CRC RUN CONSUMER is `parse_crc_config(text: str)` ([crc_config.py:242](../../s19_app/tui/operations/crc_config.py)), reading `#operation_config` `.text` at [screens.py:838-840](../../s19_app/tui/screens.py). The producer's output type (str) MUST match the consumer's input type (str) — verified equal. `read_crc_config` ([crc_config.py:156](../../s19_app/tui/operations/crc_config.py)) returns `tuple[Optional[CrcConfig], list[str]]` (PARSED, not text) — it is therefore NOT the load seam; the load needs RAW text.
  - **Seam decision (resolves the §2.6 assumed item):** add a `NEW — created in Phase 3` raw-text reader `read_crc_config_text(raw_path, base_dir, size_probe=None) -> tuple[Optional[str], list[str]]` to `crc_config.py` (NON-frozen) that performs resolve + size-cap + `read_text` and returns the raw text WITHOUT parsing — i.e. the body of `read_crc_config` [crc_config.py:217-237](../../s19_app/tui/operations/crc_config.py) minus the final `parse_crc_config` delegation at [crc_config.py:239](../../s19_app/tui/operations/crc_config.py). This keeps the editor the single source of truth and parse-on-run unchanged.
  - `READ_SIZE_CAP_BYTES` is enforced BEFORE `read_text` via an injectable `size_probe`, mirroring `read_crc_config` [crc_config.py:222-232](../../s19_app/tui/operations/crc_config.py).

### LLR-013.3 — Load fault surfaces + no check run; dummy stays when no file
- **Traceability:** HLR-013
- **Statement:** If the load path is empty, unresolvable, over the size cap, or unreadable, then the system shall surface the collected error on the operations status surface and shall leave the `#operation_config` `TextArea` unchanged and run no CRC check; and while no file has been loaded, the system shall keep `DUMMY_CONFIG_TEXT` ([crc_config.py:47](../../s19_app/tui/operations/crc_config.py)) as the pre-loaded editable reference.
- **Validation:** test (integration)
- **Executed verification:** `pytest -q tests/test_tui_crc_surface.py -k crc_config_load_fault` (provisional id) driving an unresolvable path AND an over-cap `size_probe`, asserting an error string surfaces, `#operation_config.text` is unchanged, and no CRC region rows render; plus a mount case asserting the initial `#operation_config.text == DUMMY_CONFIG_TEXT`.
- **Numeric pass threshold:** exit 0; each fault yields exactly 1 surfaced error and 0 CRC checks; editor text unchanged on fault; on mount `#operation_config.text == DUMMY_CONFIG_TEXT`.
- **Acceptance criteria (informative):**
  - The raw-text reader returns `(None, [one error string])` on any fault (collect-don't-abort), matching `read_crc_config`'s `tuple[Optional[CrcConfig], list[str]]` failure shape ([crc_config.py:180-185](../../s19_app/tui/operations/crc_config.py)).
  - The dummy pre-load is already shipped (`TextArea(DUMMY_CONFIG_TEXT, id="operation_config")` [screens.py:668](../../s19_app/tui/screens.py)) — this LLR asserts it is preserved, not newly added.

#### HLR-014 → LLR

### LLR-014.1 — DUMMY_CHANGESET_TEXT pre-loaded editable reference
- **Traceability:** HLR-014
- **Statement:** When the `PatchEditorPanel` is composed, the system shall yield an editable paste `TextArea` pre-loaded with `DUMMY_CHANGESET_TEXT` — a syntactically valid `s19app-changeset` (kind=change) carrying FAKE values only.
- **Validation:** test (integration)
- **Executed verification:** `pytest -q tests/test_tui_patch_editor_v2.py -k dummy_changeset_preload` (TC-205) asserting the paste `TextArea` exists on mount and its text equals `DUMMY_CHANGESET_TEXT`; `pytest -q tests/test_changes_schema.py -k dummy_changeset_parses` (TC-206) asserting `DUMMY_CHANGESET_TEXT` parses cleanly through the text-parse seam (LLR-014.2) with `kind == "change"` and 0 ERROR findings; `pytest -q tests/test_changes_schema.py -k no_changeset_under_examples` (TC-211 tripwire, **F-S-04**) asserting `examples/**/*changeset*.json` is EMPTY (provisional ids).
- **Numeric pass threshold:** exit 0; paste `TextArea.text == DUMMY_CHANGESET_TEXT` on mount; `DUMMY_CHANGESET_TEXT` parses with `kind == "change"`, ≥1 entry, 0 ERROR `ValidationIssue`; `list(examples.glob("**/*changeset*.json")) == []`.
- **Acceptance criteria (informative):**
  - `DUMMY_CHANGESET_TEXT` is `NEW — created in Phase 3` in the `changes` family (e.g. `changes/io.py` next to `FORMAT_ID` [io.py:106](../../s19_app/tui/changes/io.py)), FAKE values only — JSON-never-in-repo rule (no real per-firmware values; not under `examples/`). Exported in `__all__` (see LLR-014.2, **F-A-02**).
  - **TextArea mount round-trip (F-Q-07, `assumed — verify in Phase 3`):** Textual's `TextArea` may normalize a trailing newline on init. Either author `DUMMY_CHANGESET_TEXT` WITHOUT a trailing newline, OR the mount assertion (TC-205) compares with `.rstrip("\n")` tolerance. (The CRC side already ships this pattern at [screens.py:668](../../s19_app/tui/screens.py), so the risk is low.)
  - **Changeset tripwire (F-S-04):** mirroring the CRC tripwire TC-114 ([test_crc_config.py:95-110](../../tests/test_crc_config.py)), TC-211 asserts no `*changeset*.json` is ever committed under `examples/` — so the FAKE `DUMMY_CHANGESET_TEXT` cannot later leak in as a real-looking file. Homed to `test_changes_schema.py` (already in Inc 2 — no new file).
  - The paste `TextArea` id is `NEW — created in Phase 3` on `PatchEditorPanel` ([screens_directionb.py:325](../../s19_app/tui/screens_directionb.py)); it does NOT replace the existing change-file path `Input` (the shipped load-from-file stays).

### LLR-014.2 — Paste TextArea text→document parse seam (collect-don't-abort)
- **Traceability:** HLR-014
- **Statement:** When the operator triggers the `parse_paste` action (`NEW — created in Phase 3`), the panel shall post a `PatchEditorPanel.ActionRequested` carrying the paste text, and `app.py` shall route it to `ChangeService`, which shall parse the text into a `ChangeDocument` via a string-input parse seam under collect-don't-abort, replacing the owned document; a malformed paste shall yield a document carrying the collected findings (including `MF-JSON-PARSE` on a JSON-decode failure) and shall not raise.
- **Validation:** test (integration) + test (unit)
- **Executed verification:** `pytest -q tests/test_changes_schema.py -k parse_from_string` (parity: parse-from-string vs file-read; TC-207) + `pytest -q tests/test_changes_schema.py -k parse_malformed_json` (malformed string → `MF-JSON-PARSE`; TC-209, **F-A-01**) + `pytest -q tests/test_changes_schema.py -k read_delegates_to_parse` (delegation guard; TC-210, **F-Q-01**) + `pytest -q tests/test_tui_patch_editor_v2.py -k paste_parse_routes` (the `parse_paste` action routes to the service; TC-208) (provisional ids).
- **Numeric pass threshold:** exit 0; a valid JSON parsed via string yields a `ChangeDocument` whose **`entries` and issue-code set** equal the equivalent `read_change_document` file read (narrowed oracle — see AC, **F-Q-04**); a malformed JSON string yields exactly the `MF-JSON-PARSE` code (collect-don't-abort) and 0 raises; `read_change_document(path)` invokes the patched `parse_change_document` exactly once (`call_count == 1`).
- **Acceptance criteria (informative):**
  - **Consumer-input-contract (b12) + seam decision (resolves the §2.6 / R-A assumed item):** `changes/io.py` exposes NO parse-from-string entry today — `read_change_document(path_text: str, base_dir: Path, ...)` ([io.py:266-270](../../s19_app/tui/changes/io.py)) is PATH-based and couples resolve + size-cap + `json.load(handle)` ([io.py:416](../../s19_app/tui/changes/io.py)) with the dict-interpretation pipeline ([io.py:414-458](../../s19_app/tui/changes/io.py)). A `NEW — created in Phase 3` `parse_change_document(text: str) -> ChangeDocument` MUST be ADDED to `changes/io.py` (NON-frozen), factoring out the post-`json.load` interpretation ([io.py:414-458](../../s19_app/tui/changes/io.py): top-level guard, `_is_v1_document`, `_metadata_issues`, `_document_metadata`, `_parse_entries`, `collision_issues`) and replacing the file-handle `json.load` with `json.loads(text)`. `read_change_document` is refactored to delegate to it after resolve + size-cap + read. Add **both** `parse_change_document` **and** `DUMMY_CHANGESET_TEXT` to `__all__` ([io.py:66-98](../../s19_app/tui/changes/io.py)) — `DUMMY_CHANGESET_TEXT` is consumed cross-module by Inc 3 (**F-A-02**).
  - **MF-JSON-PARSE preservation (F-A-01, major):** the current `MF-JSON-PARSE` guarantee lives in the `try/except` that wraps `json.load(handle)` catching `json.JSONDecodeError`, `RecursionError`, and `UnicodeDecodeError` ([io.py:390-411](../../s19_app/tui/changes/io.py)). When the seam moves to `json.loads(text)`, `parse_change_document` MUST re-home that **same three-exception catch** so a malformed paste still emits `MF-JSON-PARSE` (the code LLR-014.2's threshold names). A dedicated malformed-string TC (TC-209) asserts the code — the valid-parity TC alone is NOT sufficient.
  - **Delegation guard (F-Q-01):** behavioral parity can pass while a parallel copy drifts. TC-210 uses `unittest.mock.patch` on `parse_change_document` and asserts `read_change_document(path)` invokes it exactly once with the file text (`call_count == 1`) — pinning the refactor as **delegation**, not duplication.
  - **Parity oracle precision (F-Q-04, F-A-06):** `ChangeDocument` is `@dataclass(slots=True)` (full structural `__eq__`) and carries a `source_path` field set to the resolved path on a file read ([io.py:357,457](../../s19_app/tui/changes/io.py)); a string seam has no path, so `parse_change_document` shall set `source_path=None`. A whole-document `==` would therefore FAIL a correct impl. The parity oracle (TC-207) MUST compare `doc.entries` and `{issue.code for issue in doc.issues}` ONLY — not whole-document equality. (Phase-3: confirm the exact `ChangeDocument` field set; if other path-coupled fields exist, exclude them too.)
  - **Consumer contract on the service side:** `ChangeService.load(path_text, base_dir)` ([change_service.py:580](../../s19_app/tui/services/change_service.py)) consumes a PATH and calls `read_change_document(path_text.strip(), base_dir)` ([change_service.py:614](../../s19_app/tui/services/change_service.py)), then `self.document = document` ([change_service.py:615](../../s19_app/tui/services/change_service.py)). The paste path needs a sibling `NEW — created in Phase 3` `ChangeService.load_text(text: str) -> ChangeActionResult` that calls `parse_change_document(text)` and does the SAME `self.document = ...` + `last_summary = None` + error-count + `ChangeActionResult` shaping as `load` ([change_service.py:614-630](../../s19_app/tui/services/change_service.py)) — feeding the EXISTING apply path with NO new write surface.
  - **`ActionRequested` field + action-token contract (b12, F-A-03/F-A-04/F-Q-02/F-Q-05):** add a `NEW — created in Phase 3` field `paste_text: str = ""` to `PatchEditorPanel.ActionRequested.__init__` ([screens_directionb.py:445-460](../../s19_app/tui/screens_directionb.py)) with an empty default (additive — E3a/E6 constructions stay valid), AND update the `ActionRequested` docstring Args list to document `paste_text` (PROJECT_RULES docstring discipline, mirroring how `scope_text` is documented at [screens_directionb.py:435-438](../../s19_app/tui/screens_directionb.py)). The new action token literal is **`parse_paste`** (`NEW`); it extends `PATCH_ACTIONS_V2` ([app.py:126-138](../../s19_app/tui/app.py)) from 9 to 10. The `test_action_routing_pins_exactly_nine_v2_actions` assertion ([test_tui_patch_editor_v2.py:184](../../tests/test_tui_patch_editor_v2.py)) is a **REUSE-extend** (existing node, expected frozenset edited 9→10) — NOT a new TC.

### LLR-014.3 — Parsed document feeds the existing apply/containment path (no re-spec of shipped write)
- **Traceability:** HLR-014
- **Statement:** After a paste is parsed into the owned document, the system shall make that document drive the EXISTING apply / INSIDE-PARTIAL-OUTSIDE / contained-emit / verify / save-back path unchanged, introducing no new write surface.
- **Validation:** test (integration)
- **Executed verification:** `pytest -q tests/test_tui_patch_editor_v2.py -k paste_then_apply` (provisional id): parse a valid paste, then drive the EXISTING `apply_doc` action and assert the same observable apply outcome as a file-loaded document — entries applied AND **save-back prompt state** (the prompt is shown for S19 and its pre-filled name matches), exercising save-back not just entries (**F-A-06**). PLUS the standing write-surface inspection (**F-Q-03 / F-S-03**): `git diff <BASE> -- s19_app/tui/changes/apply.py s19_app/tui/changes/verify.py s19_app/tui/workspace.py` MUST be empty, and within the two files Inc 2 does edit, the `emit_s19_from_mem_map` ([io.py:1300](../../s19_app/tui/changes/io.py)) and `save_patched` ([change_service.py:807](../../s19_app/tui/services/change_service.py)) symbol bodies MUST be unchanged vs `<BASE>`. **BASELINE (Phase-3 Inc-2 correction):** `<BASE>` = the batch-13 branch point **`febd843`** (the PR #17 merge = real `origin/main` tip), NOT the stale local `main` ref (`ec453a2`, pre-batch-09). `git diff main` against the stale local ref falsely shows batch-09..12 write-path work (apply.py/verify.py) and would FAIL the gate spuriously — use `git diff febd843` (or `git merge-base HEAD origin/main`).
- **Numeric pass threshold:** exit 0; a paste-parsed document and an equivalent file-loaded document produce IDENTICAL apply outcomes (entries applied + save-back prompt state); `git diff <BASE>` (=`febd843`) on `apply.py`/`verify.py`/`workspace.py` = **0 changed lines**, and `emit_s19_from_mem_map`/`save_patched` symbol bodies = **0 changed lines** (0 new write code paths). This is a HARD Phase-4 gate row (standing, not a one-time hand check). **Verified empty at Inc 2 vs `febd843`.**
- **Acceptance criteria (informative):**
  - **Consumer-input-contract (b12):** the apply consumer is `ChangeService.apply(...)` ([change_service.py:741](../../s19_app/tui/services/change_service.py)) operating on `self.document` — set identically by `load` and the new `load_text`. The paste path therefore reuses the EXISTING `apply_doc` routing at [app.py:1328-1336](../../s19_app/tui/app.py); NO new apply/emit/write code.
  - **Save-back parity vs `source_path` (F-A-06):** because `parse_change_document` sets `source_path=None` (LLR-014.2), the save-back prompt MUST NOT default its target name off `document.source_path` (Phase-3 confirm the prompt name derives from the loaded image's `variant_id`, [app.py:1347-1350](../../s19_app/tui/app.py), not the change-document path) — else a paste-parsed apply would diverge from a file-loaded one. The apply-parity TC asserts the prompt name is identical for both.
  - The shipped containment (`copy_into_workarea`), contained emit (`emit_s19_from_mem_map` [io.py:1300](../../s19_app/tui/changes/io.py)), and `verify_written_image` reader-as-oracle are reused verbatim — NOT re-specified here (§1.2 out-of-scope).

---

## 5. Validation strategy

### 5.1 Methods
- **Test:** automated execution (unit / integration / e2e). Default for LLR. **Every `test` LLR must name the exact executed verification and the numeric pass threshold — otherwise it is not executable.**
- **Demo:** observed execution of behavior. Useful for UX-oriented HLRs. Describe the observable procedure + the named qualitative criterion.
- **Inspection:** static review of code or document. Useful for structural requirements. Name the file / commit / section + the observable condition.
- **Analysis:** formal or quantitative reasoning (performance, complexity, security). **Every `analysis` LLR must name the executed calculation (with input values) and the numeric pass threshold — otherwise it is not executable.**

> Reminder from the batch-02 + batch-03 post-mortems: the absence of an executed verification + numeric pass threshold on `test`/`analysis` requirements was the recurring root cause of forced phase-1 iteration. Capture at draft time, not at the phase-2 gate.

### 5.2 Coverage table

> **Provisional-identifier scope (V-5, b09):** every test FILE path, `-k` selector, and node id below is provisional-until-Phase-3 and reconciled from the real tree at Phase 4. **NEW** marks a TC whose test body does not exist yet (authored in Phase 3); **REUSE** marks an existing test node extended/asserted-against. **Testing-strategy reconciliation (b06 F-6):** all `test` labels target **pytest + Textual `App.run_test()` pilots** — confirmed present (`tests/test_tui_crc_surface.py`, `tests/test_tui_patch_editor_v2.py`, `tests/test_changes_schema.py`, `tests/test_crc_config.py` all exist; no JSDOM/vitest in tree).

| Requirement | Method | Executed verification | Numeric pass threshold | Provisional TC id(s) |
|-------------|--------|------------------------|-------------------------|----------------------|
| **HLR-013** | test (integration) | `pytest -q tests/test_tui_crc_surface.py -k crc_config_load` + `pytest -q tests/test_crc_config.py -k read_crc_config_text` + inspection diff vs `main` confirming the CRC run path still consumes `parse_crc_config(TextArea.text)` unchanged | All new CRC config-load TCs pass (exit 0); 0 regressions in the existing CRC suite (`test_tui_crc_surface.py` + `test_crc_operation.py` + `test_operations.py`); a load fault leaves `#operation_config` unchanged AND runs 0 CRC checks | TC-201, TC-202, TC-203, TC-204 (all NEW) |
| **LLR-013.1** — path Input + Load button placement | test (integration) | `pytest -q tests/test_tui_crc_surface.py -k crc_config_load_widgets` — `App.run_test()` pilot opens `OperationsScreen`, highlights the CRC row, asserts the NEW config-path `Input` + "Load config" `Button` exist + `.display==True`; on a non-CRC row asserts both `.display==False` (parity with `_sync_config_visibility` [screens.py:742-772](../../s19_app/tui/screens.py)) | exit 0; both new widgets present + displayed on CRC row; both hidden off CRC row | **TC-201 (NEW)** |
| **LLR-013.2** — resolve+size-cap+read raw text into TextArea | test (unit) + test (integration) | unit: `pytest -q tests/test_crc_config.py -k read_crc_config_text` over a synthetic fixture path, asserts return `(raw_text, [])` and `parse_crc_config` NOT invoked. integration: `pytest -q tests/test_tui_crc_surface.py -k crc_config_load_ok` — pilot types a valid synthetic path, presses Load config **through the `on_button_pressed` handler [screens.py:774](../../s19_app/tui/screens.py)**, asserts `#operation_config.text` byte-equals the file text | exit 0; `read_crc_config_text` returns raw str (no parse); `#operation_config.text` byte-equals loaded file text; `parse_crc_config` NOT called on load; 0 CRC checks run | **TC-202 (NEW, unit)**, **TC-203 (NEW, integration)** |
| **LLR-013.3** — load fault surfaces + no check run; dummy stays | test (integration) | `pytest -q tests/test_tui_crc_surface.py -k crc_config_load_fault` — pilot drives (a) an unresolvable path and (b) an over-cap `size_probe` through the Load handler, asserts exactly 1 error on `#operation_result_status`, `#operation_config.text` unchanged, 0 CRC region rows; plus a mount case asserting initial `#operation_config.text == DUMMY_CONFIG_TEXT` | exit 0; each fault → exactly 1 surfaced error + 0 CRC checks; editor text unchanged on fault; on mount `#operation_config.text == DUMMY_CONFIG_TEXT` | **TC-204 (NEW)** |
| **HLR-014** | test (integration) | `pytest -q tests/test_tui_patch_editor_v2.py -k "dummy_changeset or paste_parse or paste_then_apply"` + `pytest -q tests/test_changes_schema.py -k "parse_from_string or parse_malformed_json or read_delegates_to_parse or no_changeset_under_examples"` + the `PATCH_ACTIONS_V2` set assertion (REUSE-extend, [test_tui_patch_editor_v2.py:184](../../tests/test_tui_patch_editor_v2.py)) | All new paste/parse TCs pass (exit 0); `PATCH_ACTIONS_V2` assertion passes with the extended 10-token set; a parsed-from-string valid doc has `entries` + issue-code set EQUAL to the equivalent file read (narrowed oracle, F-Q-04); malformed paste surfaces `MF-JSON-PARSE` + 0 crashes; `read_change_document` delegates to `parse_change_document` (`call_count==1`) | TC-205..208 (NEW) + TC-209 malformed (NEW) + TC-210 delegation (NEW) + TC-211 tripwire (NEW); action-set assertion REUSE-extend |
| **LLR-014.1** — `DUMMY_CHANGESET_TEXT` pre-loaded editable reference | test (integration) + test (unit) | integration: `pytest -q tests/test_tui_patch_editor_v2.py -k dummy_changeset_preload` — pilot asserts the NEW paste `TextArea` exists on mount and `.text == DUMMY_CHANGESET_TEXT`. unit: `pytest -q tests/test_changes_schema.py -k dummy_changeset_parses` asserts `DUMMY_CHANGESET_TEXT` parses through `parse_change_document` with `kind=="change"`, ≥1 entry, 0 ERROR `ValidationIssue` | exit 0; paste `TextArea.text == DUMMY_CHANGESET_TEXT` on mount (`.rstrip("\n")` tolerance, F-Q-07); `DUMMY_CHANGESET_TEXT` parses `kind=="change"`, ≥1 entry, 0 ERROR issues; `examples/**/*changeset*.json` EMPTY | **TC-205 (NEW, integration)**, **TC-206 (NEW, unit)**, **TC-211 (NEW, tripwire — F-S-04)** |
| **LLR-014.2** — paste text→document parse seam (collect-don't-abort) | test (unit) + test (integration) | unit/parity: `pytest -q tests/test_changes_schema.py -k parse_from_string` — `parse_change_document(text)` vs `read_change_document(path)` over the SAME JSON yield equal `ChangeDocument` (entries + issue codes); malformed string → ≥1 `ValidationIssue`, 0 raises. integration/route: `pytest -q tests/test_tui_patch_editor_v2.py -k paste_parse_routes` — pilot triggers the parse action, asserts `ActionRequested` carries `paste_text` and `app.py` routes to `ChangeService.load_text` (assert `service.document` replaced) | exit 0; string-parsed valid doc has `entries` + `{issue.code}` EQUAL to file-read (narrowed, NOT whole-doc `==`); malformed string → `MF-JSON-PARSE` + 0 raises; `read_change_document` delegates (`call_count==1`); `parse_paste` action routes through the handler and replaces `service.document` | **TC-207 (NEW, parity)**, **TC-208 (NEW, route)**, **TC-209 (NEW, malformed→MF-JSON-PARSE, F-A-01)**, **TC-210 (NEW, delegation guard, F-Q-01)** |
| **LLR-014.3** — parsed doc feeds existing apply/containment path | test (integration) + inspection | `pytest -q tests/test_tui_patch_editor_v2.py -k paste_then_apply` — pilot parses a valid paste, drives the EXISTING `apply_doc` action [app.py:1328](../../s19_app/tui/app.py), asserts the same apply outcome as a file-loaded doc **incl. save-back prompt name** (F-A-06); inspection (STANDING Phase-4 row, F-Q-03/F-S-03): `git diff main -- s19_app/tui/changes/apply.py s19_app/tui/changes/verify.py s19_app/tui/workspace.py` empty + `emit_s19_from_mem_map`/`save_patched` symbol bodies unchanged | exit 0; paste-parsed doc and file-loaded doc produce IDENTICAL apply outcomes + save-back prompt name; `git diff main` on apply.py/verify.py/workspace.py = **0 lines**; emit/save_patched symbols = **0 changed lines** | **TC-208 (apply+save-back assertion, NEW) + diff-vs-main STANDING gate row** |

**Reconciliation note (V-5):** the CRC TUI surface cases are homed to **`tests/test_tui_crc_surface.py`** and the `read_crc_config_text` unit seam to **`tests/test_crc_config.py`** — §3/§4 aligned. This re-home is a provisional-identifier reconciliation (no §6.4 row). NOTE: the Phase-2 iter-2 fold DID change LLR-014.1/.2/.3 thresholds + LLR-014.2 statement — those owe §6.4 audit rows J-1/J-2/J-3 (see §6.4). TC count is now TC-201..211 (added TC-209 malformed, TC-210 delegation, TC-211 tripwire).

### 5.2.1 Surface-reachability matrix (A-5 — batch-11 SCOPE-1 control)

> Each story input dimension is exercised **through the shipped handler call-site**, not only via direct service kwargs. Handlers grep-verified.

| # | Dimension (US story) | Shipped surface (handler `file:line`) | Covering TC | Through-handler? |
|---|----------------------|----------------------------------------|-------------|------------------|
| US-013-a | Valid config path → `#operation_config` populated | `OperationsScreen.on_button_pressed` Load branch — screens.py:774 (NEW `elif`) | TC-203 | **Y** |
| US-013-b | Invalid/irresolvable/over-cap → error + no check | same handler — screens.py:774 | TC-204 | **Y** |
| US-013-c | No-file → dummy stays | `OperationsScreen.compose` mount — screens.py:668 | TC-204 (mount) | **Y** |
| US-014-a | Patch Editor mount → dummy pre-loaded | `PatchEditorPanel.compose` — screens_directionb.py:325 (NEW paste `TextArea`) | TC-205 | **Y** |
| US-014-b | Paste valid → parse via panel action → document | `ActionRequested(paste_text)` → router app.py:1301 (NEW `elif` → `load_text`) | TC-208 | **Y** |
| US-014-c | Paste malformed → collect-don't-abort surfaces faults | same router — app.py:1301 → `_report_change_result` | TC-207 + TC-208 | **Y** |
| US-014-d | Parsed doc → existing apply path reachable | `apply_doc` router — app.py:1328 (UNCHANGED) | TC-208 (apply assert) | **Y** |

All 7 dimensions **Y (through-handler)** — the SCOPE-1 failure mode (testing the writer API while the handler passes empty fields) is structurally excluded; TC-207 additionally pins service-level parse-parity so the through-handler path cannot silently diverge.

### 5.2.2 Testability verdict per LLR
All 6 LLRs **READY** — each yields ≥1 mechanically-checkable observable AC (LLR-013.1 widget presence/display; .2 byte-equal text + no-parse; .3 exactly-1-error + unchanged editor; LLR-014.1 mount text == dummy; .2 string==file parity + ≥1-issue-on-malformed; .3 apply-parity + 0-new-write-paths). Two non-blocking Phase-3/4 caveats: (1) assert `read_change_document` **delegates** to `parse_change_document` (structural, not just behavioral parity); (2) carry "0 new write code paths" as a standing Phase-4 diff-vs-`main` matrix row.

### 5.3 Batch acceptance criteria
- LLR coverage ≥ 100% (6/6 LLRs covered by ≥1 passing TC).
- 0 regressions in the CRC `OperationsScreen` suite and the Patch Editor v2 suite.
- Full suite passes at no worse than the Phase-1 baseline (879 collected, V-7; re-confirm at Phase 4).
- `PATCH_ACTIONS_V2` assertion passes with the extended action set (facade/test blast-radius discharged).
- Parse-parity invariant holds: string-parse and file-read produce equal `entries` + issue-code set for identical JSON (narrowed oracle, F-Q-04).
- Refactor-fidelity invariants (Phase-2 C1): malformed paste emits `MF-JSON-PARSE` (F-A-01); `read_change_document` delegates to `parse_change_document` (`call_count==1`, F-Q-01); `parse_change_document` sets `source_path=None` and save-back prompt name is path-independent (F-A-06).
- 0 new write code paths introduced by US-014 — HARD standing gate: `git diff main -- apply.py verify.py workspace.py` = 0 lines + `emit_s19_from_mem_map`/`save_patched` symbol bodies = 0 changed lines (F-Q-03/F-S-03).
- Changeset tripwire: `examples/**/*changeset*.json` is empty (F-S-04).
- No requirement without an assigned validation method; 0 blocker fails in validation.

---

## 6. Appendices

### 6.1 Assumptions and dependencies

| # | Assumption / dependency | State | Evidence |
|---|-------------------------|-------|----------|
| A-D1 | The CRC run path consumes `#operation_config.text` via `parse_crc_config(text)` on Execute, unchanged by US-013. | **verified** | [screens.py:838-840](../../s19_app/tui/screens.py); parse-on-run preserved. |
| A-D2 | `resolve_input_path` + `READ_SIZE_CAP_BYTES` are reusable read primitives outside the frozen set. | **verified** | [workspace.py:469](../../s19_app/tui/workspace.py); [io.py:192](../../s19_app/tui/changes/io.py) (`crc_config.py:32` already imports the cap). |
| A-D3 | `changes/io.py` has NO parse-from-string entry; `read_change_document` is path-based and reads a file handle. | **verified — SETTLED (R-A)** | [io.py:266-270](../../s19_app/tui/changes/io.py) signature; `json.load(handle)` at [io.py:393](../../s19_app/tui/changes/io.py). Resolution: ADD `parse_change_document(text)` (LLR-014.2). |
| A-D4 | US-013 ingestion is RAW TEXT (not parsed config). | **verified — SETTLED** | `read_crc_config` returns parsed `tuple[Optional[CrcConfig], list[str]]` [crc_config.py:156-160](../../s19_app/tui/operations/crc_config.py); editor needs str. Resolution: ADD `read_crc_config_text` raw-text reader (LLR-013.2). |
| A-D5 | `PATCH_ACTIONS_V2` is a fixed set asserted exactly in one test; adding an action is a multi-file contract touch. | **verified** | [app.py:126-138](../../s19_app/tui/app.py); assertion [test_tui_patch_editor_v2.py:184](../../tests/test_tui_patch_editor_v2.py). |
| A-D6 | The shipped Patch Editor write/apply/verify path is intact and reused; US-014 adds no write surface. | **verified** | `ChangeService.load/apply/save_patched` [change_service.py:580/741/807](../../s19_app/tui/services/change_service.py); apply routing [app.py:1328-1336](../../s19_app/tui/app.py). |
| A-D7 | All planned files are OUTSIDE both frozen-engine guard lists. | **verified** | See §6.2 census; guards at [test_engine_unchanged.py:120-127](../../tests/test_engine_unchanged.py) (6 paths) + [test_tui_directionb.py:3738-3746](../../tests/test_tui_directionb.py) (7 paths incl `color_policy.py`). |
| A-D8 | `app.py:938` docstring is stale (describes an inert Patch Editor that no longer exists). | **verified** | [app.py:938-940](../../s19_app/tui/app.py) text vs live wired panel; surgical truth-fix (§1.2). |

**Open `assumed — verify in Phase N` items remaining:** NONE blocking. Both §2.6 assumed items are SETTLED above (A-D3 → R-A; A-D4). Carry-forward to later phases (not requirement-blocking): (a) whether `security-reviewer` sign-off on US-014 is mandatory or advisory — **verify in Phase 2** (input-parse only, no new write surface; flagged honestly per §2.6); (b) the provisional Executed-verification file/`-k`/node ids in §3/§4 — **reconciled in Phase 4** (V-5 b09 provisional-identifier scope rule).

### 6.2 Relevant design decisions — change-first census, frozen-set check, facade/test blast-radius

**Census method (A-1, b10): change-first, keyed on assertion CATEGORY, not a grep checklist.** Each planned new/edited file is checked against every test asserting on a file PATH / module STRUCTURE / import GRAPH / git-DIFF. The increment GATE (running the real edited files vs the suite) is the completeness guarantee; this census is the Phase-1 cost-reduction heuristic (A-2: NOT stamped "VERIFIED COMPLETE" — best-effort + gate-confirmed).

**Frozen-engine set (re-verified both guard ranges):** `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py` ([test_engine_unchanged.py:120-127](../../tests/test_engine_unchanged.py), 6 paths) + `tui/color_policy.py` ([test_tui_directionb.py:3738-3746](../../tests/test_tui_directionb.py), 7 paths). **No planned file intersects either list** (confirmed below).

| Planned file | NEW / EDIT | In frozen set? | Structural / diff / import / path guard that could fire? |
|--------------|-----------|----------------|----------------------------------------------------------|
| `s19_app/tui/screens.py` | EDIT | NO | No path/diff guard freezes it; it is a TUI surface module. New widget ids in `compose`. |
| `s19_app/tui/operations/crc_config.py` | EDIT (+`read_crc_config_text`) | NO | NON-frozen; new-symbol-into-existing-file probe (A-3): grep `_ENGINE_PATHS` for `crc_config` → 0 hits in both guard lists. |
| `s19_app/tui/screens_directionb.py` | EDIT (paste `TextArea` + `ActionRequested.paste_text`) | NO | NON-frozen TUI surface. `ActionRequested` is a producer/consumer contract — Contract-touch rule: new field additive with default. |
| `s19_app/tui/app.py` | EDIT (`PATCH_ACTIONS_V2` + router branch) | NO | NON-frozen orchestration module. Action-set is asserted by a HARDCODED test (below). |
| `s19_app/tui/changes/io.py` | EDIT (+`parse_change_document`, refactor `read_change_document`) | NO | NON-frozen `changes` family (batch-10 placed the HEX emitter here precisely because it is the non-frozen home next to the reader). A-3 probe: `io.py` is NOT in `_ENGINE_PATHS`. |
| `s19_app/tui/services/change_service.py` | EDIT (+`load_text`) | NO | NON-frozen service module. |
| `tests/test_tui_crc_surface.py` | EDIT (new CRC config-load TCs) | NO | Test file. |
| `tests/test_tui_patch_editor_v2.py` | EDIT (action-set assertion + paste/parse TCs) | NO | Test file; the `PATCH_ACTIONS_V2` assertion MUST be updated (facade/test blast-radius below). |
| `tests/test_changes_schema.py` | EDIT (parse-from-string parity TCs) | NO | Test file. |

**Facade / test blast-radius budgeting (b12 control).** Adding the paste/parse action is a FIXED-SET touch spanning four edit points — all counted in Increment 3's ≤5-file budget:
1. `PATCH_ACTIONS_V2` definition — [app.py:126-138](../../s19_app/tui/app.py) (add the new action token).
2. Router branch — [app.py:1301-1336](../../s19_app/tui/app.py) (new `elif` calling `ChangeService.load_text`).
3. `PatchEditorPanel.ActionRequested` action enum/docstring + new `paste_text` field — [screens_directionb.py:413-460](../../s19_app/tui/screens_directionb.py).
4. The hardcoded action-set assertion — [test_tui_patch_editor_v2.py:184-196](../../tests/test_tui_patch_editor_v2.py) (extend the asserted `frozenset`).
   There are NO facade re-exports for these symbols (`PATCH_ACTIONS_V2` and `ActionRequested` are imported directly, not via `__init__` facades — grep showed the only consumers are `app.py`, `screens_directionb.py`, and the one test). `parse_change_document` DOES need a one-line `__all__` add in `changes/io.py` [io.py:66-98](../../s19_app/tui/changes/io.py) — counted in Increment 2.

### 6.3 Increment decomposition (≤5 files each)

> Supervised incremental: each increment is plan → approve → implement → review packet → stop. Ordered so the parse seams (data layer) land before the UI wiring that consumes them.

**Increment 1 — US-013 CRC config file-load (HLR-013, all 3 LLR).** ≤3 files.
1. `s19_app/tui/operations/crc_config.py` — add `read_crc_config_text(raw_path, base_dir, size_probe=None) -> tuple[Optional[str], list[str]]` (resolve + size-cap + raw `read_text`, no parse).
2. `s19_app/tui/screens.py` — add config-path `Input` + "Load config" `Button` to the CRC `compose` branch; toggle in `_sync_config_visibility`; on press call `read_crc_config_text`, replace `#operation_config.text` on success, surface error + no-run on fault.
3. `tests/test_tui_crc_surface.py` — CRC config-load TCs (LLR-013.1/.2/.3).
   *Blast-radius:* no facade/fixed-set touch. JSON-never-in-repo: synthetic in-test config fixture (FAKE values), NOT under `examples/`, respects the `examples/**/crc*.json` tripwire (TC-114).

**Increment 2 — US-014 data layer: text-parse seam (LLR-014.1 dummy + LLR-014.2 seam, data half).** ≤3 files.
1. `s19_app/tui/changes/io.py` — add `parse_change_document(text: str) -> ChangeDocument` (factor out [io.py:414-458](../../s19_app/tui/changes/io.py); `json.loads` instead of `json.load(handle)`); refactor `read_change_document` to delegate after resolve+cap+read; add `DUMMY_CHANGESET_TEXT` (FAKE values); add both to `__all__`.
2. `s19_app/tui/services/change_service.py` — add `ChangeService.load_text(text) -> ChangeActionResult` mirroring `load` ([change_service.py:614-630](../../s19_app/tui/services/change_service.py)).
3. `tests/test_changes_schema.py` — parse-from-string vs file-read parity TCs (LLR-014.2) + `DUMMY_CHANGESET_TEXT` validity (LLR-014.1).
   *Blast-radius:* one `__all__` add (counted). No fixed-set touch yet.

**Increment 3 — US-014 UI wiring: paste action (LLR-014.1 panel + LLR-014.2 routing + LLR-014.3 apply reuse).** ≤4 files.
1. `s19_app/tui/screens_directionb.py` — add paste `TextArea` pre-loaded with `DUMMY_CHANGESET_TEXT`; add a parse control posting `ActionRequested` with the NEW `paste_text` field.
2. `s19_app/tui/app.py` — add the new action token to `PATCH_ACTIONS_V2`; add the router `elif` calling `ChangeService.load_text`; correct the stale [app.py:938](../../s19_app/tui/app.py) docstring (surgical truth-fix).
3. `tests/test_tui_patch_editor_v2.py` — extend the `PATCH_ACTIONS_V2` assertion; add paste→parse→apply TCs (LLR-014.2/.3).
   *Blast-radius (b12, all 4 fixed-set edit points within budget):* `PATCH_ACTIONS_V2` def (app.py), router (app.py), `ActionRequested` field (screens_directionb.py), hardcoded assertion (test). 3 files total — within ≤5.

### 6.4 Phase-1 reconciliation log

**Phase-1 draft (iter 1):** no LLR threshold/statement changed; HLR/LLR id map matches the brief 1:1 (HLR-013/HLR-014, 3 LLR each); no LLR added/promoted/removed. The two §2.6 "assumed" seams resolved into acceptance-criteria detail (add `read_crc_config_text`; add `parse_change_document`) — not threshold changes. Body-first satisfied.

**Phase-1 iter 2 (Phase-2 fold of 0 blocker / 1 major / 16 minor):** three LLRs had `Statement`/`Numeric pass threshold` edits to fold the Phase-2 findings (Clusters C1-C5). Per the parent-HLR re-read rule, body edits landed in §3/§4/§5 FIRST; the audit rows below point at them. No LLR added/promoted/removed; the id map is unchanged (still 2 HLR / 6 LLR / now TC-201..211).

| Decision ID | What changed | Parent HLR re-read? | Body edit landed? |
|-------------|--------------|---------------------|-------------------|
| J-1 (F-A-01 major + F-Q-01/F-Q-04/F-A-06) | **LLR-014.2 Statement + threshold.** Statement now names the `parse_paste` action token and the `MF-JSON-PARSE` malformed-paste guarantee. Threshold narrowed the parity oracle to `entries` + `{issue.code}` (not whole-doc `==`, because `parse_change_document` sets `source_path=None`), added the `MF-JSON-PARSE` code on malformed, and the delegation `call_count==1`. | **HLR-014 re-read — no change required.** HLR-014 ("parse the pasted text into the owned `ChangeService` change document") is unchanged; J-1 refines the LLR seam fidelity, not the HLR's normative claim or any HLR threshold. | LLR-014.2 §4 Statement + Numeric-pass-threshold + ACs (MF-JSON-PARSE preservation / delegation guard / parity-oracle precision / action-token); §5.2 LLR-014.2 row + TC-209/TC-210. |
| J-2 (F-S-04, F-Q-07) | **LLR-014.1 threshold.** Added the changeset tripwire condition `list(examples.glob("**/*changeset*.json")) == []` and the `.rstrip("\n")` mount tolerance. | **HLR-014 re-read — no change required.** A repo-hygiene tripwire + a TextArea round-trip tolerance; neither touches HLR-014's claim or threshold. | LLR-014.1 §4 Numeric-pass-threshold + ACs (tripwire / mount round-trip); §5.2 LLR-014.1 row + TC-211. |
| J-3 (F-Q-03 + F-S-03) | **LLR-014.3 threshold.** Made "0 new write paths" executable: explicit `git diff main -- apply.py verify.py workspace.py` = 0 lines + `emit_s19_from_mem_map`/`save_patched` symbol-body = 0 changed lines, elevated to a HARD standing Phase-4 row; added save-back prompt-name parity. | **HLR-014 re-read — no change required.** HLR-014 + LLR-014.3 statement already assert "no new write surface"; J-3 makes the existing claim mechanically checkable, not a new threshold on the HLR. | LLR-014.3 §4 Executed-verification + Numeric-pass-threshold + AC (save-back parity); §5.2 LLR-014.3 row. |

**Provisional-id reconciliation (NOT a §6.4 row — V-5):** HLR-013 §3 Executed-verification gained `tests/test_crc_config.py -k read_crc_config_text` (F-Q-06) for §3↔§5 alignment; `json.load` cite corrected io.py:393→416 (line-drift). Neither is a threshold/statement change.

**HLR-threshold-vs-LLR contradiction check (Phase-2 blocker class a):** none — HLR-014's validation threshold (entries+issue-code parity, extended action set, MF-JSON-PARSE) is consistent with its decomposed LLRs after the fold.

### 6.5 Phase-3 spec amendments (before / after · deleted / new)

> Operator convention (batch-13): every requirement edit made DURING an increment is recorded here with explicit **Before → After** text and **Deleted / New** tokens, not silently edited. One block per amendment. Body-first: the §3/§4 line is edited first, then this record points at it.

**Amendment A-1 — LLR-014.3 F-S-03 write-surface gate baseline (discovered Phase-3 Inc 2).**
- **Trigger:** while verifying "0 new write paths," found the worktree's local `main` ref is STALE (`ec453a2`, pre-batch-09). `git diff main` against it falsely shows batch-09..12 write-path work (`apply.py` +108/−41, `verify.py` +171). The real batch-13 base is `febd843` (parent of the first batch-13 commit `9ab8d3e` = the PR #17 merge = `origin/main` tip).
- **Affected requirement:** LLR-014.3 — Executed verification + Numeric pass threshold (§4).
- **Before:** `git diff main -- s19_app/tui/changes/apply.py s19_app/tui/changes/verify.py s19_app/tui/workspace.py` MUST be empty … unchanged vs `main`; threshold `git diff main` on those files = **0 changed lines**.
- **After:** `git diff <BASE> -- …` MUST be empty … unchanged vs `<BASE>`; threshold `git diff <BASE>` (=`febd843`) = **0 changed lines**. **Verified empty at Inc 2 vs `febd843`.**
- **Deleted:** the bare/ambiguous baseline token `main` (4 occurrences in LLR-014.3) — it resolved to the stale local ref.
- **New:** explicit `<BASE> = febd843` definition (PR #17 merge / real `origin/main` tip), the stale-ref rationale, and the `git merge-base HEAD origin/main` fallback; plus the "Verified empty at Inc 2" evidence stamp.
- **Parent HLR re-read?** HLR-014 + LLR-014.3 **Statement** ("no new write surface") UNCHANGED — this corrects only the BASELINE the mechanical gate diffs against (a provisional-identifier correction; the numeric threshold value, 0 changed lines, is unchanged). No parent edit required.
- **Body edit landed?** LLR-014.3 §4 Executed-verification + Numeric-pass-threshold (the `<BASE>=febd843` lines).
