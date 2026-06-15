# Requirements Document — s19_app — Batch 2026-06-14-batch-11

> **Strict normative convention — IEEE 830 + EARS**
> - `shall` = normative, binding, verifiable requirement. **Only** inside HLR / LLR statements.
> - `should` = informative / explanatory text, **NOT binding**. **Only** outside HLR / LLR statements (rationale, description, context).
> - Any use of `should` inside an HLR / LLR statement is a **writing error** and will be flagged as a blocker in phase 2.
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

---

## 1. Introduction

### 1.1 Purpose
This document specifies the requirements for batch-11 of s19_app: giving the tool the ability to **WRITE** the per-project manifest `project.json` (it is read-only today) and to **verify-check** the written manifest by re-reading it and comparing the re-read parse against the intended composition — mirroring the batch-10 verify-on-save discipline for firmware images.

### 1.2 Scope
**In scope:**
- A headless manifest serializer that converts an in-memory project composition (`ProjectVariantSet` + the manifest's project-wide `batch`/`assignments` lists + `active_variant`) into the canonical `project.json` envelope that the existing reader `read_project_manifest` (`s19_app/tui/services/variant_execution_service.py:293`) parses back without findings.
- A containment-checked WRITE of that manifest into `.s19tool/workarea/<project>/project.json`: stage to `temp/`, reuse `copy_into_workarea`'s containment CHECKS (`workspace.py:278`–`:291`), then atomically `os.replace` at the fixed name (D-3 locked mechanism) — following the staged-write discipline of `write_change_document` (`s19_app/tui/changes/io.py:1167`) but NOT its dedup-on-collision placement.
- A dedicated manifest verify-on-write check: re-read the written `project.json` via the existing reader, compare the re-read `ProjectManifest` against the intended manifest dict, and report drift as a result object modeled on `VerifyResult` (`s19_app/tui/changes/verify.py:34`) but NOT reusing `diff_mem_maps` (a manifest is a JSON dict, not a mem_map).
- TUI wiring of the write + verify on the project-save surface (gate-confirmable — see §6.3).

**Out of scope (informative):**
- Changing the manifest *reader* or its schema contract — the reader (`read_project_manifest`) is the oracle; the writer round-trips against it (the batch-10 emitter↔`IntelHexFile` precedent).
- CLI surface (batch-10 was TUI-only; this batch follows that, gate-confirmable §6.3).
- The CRC first-operation fill-in (still QUEUED per §2.6 scope notes).
- Editing any git-frozen engine module (`core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`).

### 1.3 Definitions, acronyms, abbreviations
| Term | Definition |
|------|------------|
| Manifest | The per-project `project.json` file at `.s19tool/workarea/<project>/project.json` (`PROJECT_MANIFEST_NAME`, `variant_execution_service.py:84`). |
| Manifest envelope | The canonical key set the reader accepts: `schema_version`, `active_variant`, `batch` (array of project-relative path strings), `assignments` (object: variant_id → array of project-relative path strings). Derived from `read_project_manifest` (`variant_execution_service.py:395-461`). |
| `ProjectManifest` | The parsed manifest dataclass (`variant_execution_service.py:158`): `schema_version`, `active_variant`, `batch: list[Path]`, `assignments: dict[str, list[Path]]`, `issues`. |
| `ProjectVariantSet` | The in-memory ordered variant inventory + active id (`s19_app/tui/models.py:80`). |
| Round-trip fidelity | The writer's output, fed back through `read_project_manifest`, yields a `ProjectManifest` with the same `active_variant` / `batch` / `assignments` (compared in the **canonical comparison form**, below) and ZERO `issues`. |
| Canonical comparison form (C-1) | The ONE representation in which intended-vs-re-read equality is asserted: the intended `batch` / `assignments` entries are RESOLVED against the same `project_root` (via `_resolve_manifest_entry` semantics, `variant_execution_service.py:203`/`:235`/`:290`) BEFORE comparison, yielding resolved-absolute `Path`s — matching the established reader-side idiom `tests/test_variant_execution.py:163` (`assert manifest.batch == [(project_dir / "doc.json").resolve()]`). `active_variant` is compared as the raw string the reader keeps. Defined once in C-1 (§6.2 / §2.4); every equality threshold inherits it. |
| Verify-on-write | Re-read the just-written `project.json` and compare the parse against the intended composition (the batch-10 verify-on-save pattern, JSON variant). |
| Containment | The `.s19tool/workarea/` staged-write + `copy_into_workarea` reparse-point/path-escape/size guard (`workspace.py:215`). |

### 1.4 References
- `read_project_manifest` (manifest reader / oracle): `s19_app/tui/services/variant_execution_service.py:293`.
- `ProjectManifest` dataclass + envelope keys: `variant_execution_service.py:158`, `:395-461`.
- `_resolve_manifest_entry` (per-entry containment, `MANIFEST-PATH-ESCAPE`): `variant_execution_service.py:203`.
- `VerifyResult` / `verify_written_image` (verify-on-save substrate): `s19_app/tui/changes/verify.py:34`, `:119`.
- `write_change_document` (staged containment write precedent): `s19_app/tui/changes/io.py:1167`.
- `copy_into_workarea` / `ensure_workarea` / `WorkareaContainmentError`: `s19_app/tui/workspace.py:215`, `:41`, `:28`.
- `build_variant_set` / `ProjectVariantSet` / `VariantDescriptor`: `workspace.py:376`, `models.py:80`, `models.py:55`.
- Engine-frozen guards: `tests/test_engine_unchanged.py:120`, `tests/test_tui_directionb.py:3738`.
- Batch-10 requirements (verify-on-save lineage): `.dev-flow/2026-06-13-batch-10/01-requirements.md`.

### 1.5 Document overview
§2 frames the change in the existing system. §3 states the 4 HLRs (write, verify, containment, TUI surface). §4 decomposes them into 14 LLRs with grep-cited symbols (LLR-001.5 is the security input-gate added at the Phase-1 iteration). §5 is the validation strategy with the re-measured collection baseline (816). §6 holds design decisions, the manifest producer/consumer contract, risks, gate-confirmables, and the change-first census result.

---

## 2. Overall description

### 2.1 Product perspective
Today `project.json` is **read-only**: `read_project_manifest` (`variant_execution_service.py:293`) parses it through a capped, collect-don't-abort path, and the manifest must be hand-authored. The batch-06/E6 execution layer consumes it (active variant override + `batch`/`assignments` file mapping); `app.py` only ever *reads* it (`app.py:1578`, `:1844`, `:3556`). This batch adds the missing WRITE side and an integrity check on the write, completing the read↔write symmetry that batch-10 established for firmware images (write image → re-read → diff). The writer sits in the parsing→service→TUI architecture as a **service-layer** capability beside the manifest reader, callable from `app.py` without widening the surface — the same rationale the reader cites for living in `variant_execution_service.py` (`:6-9`).

### 2.2 Product functions
- **F1 — Serialize composition to envelope.** Convert a `ProjectVariantSet` + `active_variant` + project-wide `batch` list + per-variant `assignments` into a JSON-serializable dict matching the canonical envelope the reader accepts.
- **F2 — Write the manifest, contained.** Write that dict to `.s19tool/workarea/<project>/project.json` through the staged-write + `copy_into_workarea` containment discipline; report a containment/IO failure as a collected finding (no uncaught exception).
- **F3 — Verify-on-write.** Re-read the written file via `read_project_manifest` and compare the parse against the intended composition; report verified / mismatch with the specific drifting keys, AND surface any reader `issues` on the re-read (a write that the reader rejects is a mismatch).
- **F4 — TUI surface.** Trigger F1→F2→F3 from the project-save flow and surface the verify outcome (gate-confirmable §6.3).

### 2.3 User characteristics
Single role: the s19tool **operator** (TUI user) composing/maintaining a project. No new permissions. The writer is headless and reusable by future non-TUI callers, but the only surface in this batch is the TUI.

### 2.4 Constraints
- **C-1 Round-trip-to-reader (oracle) + canonical comparison form.** The writer's output is correct iff `read_project_manifest` reads it back with the intended `active_variant`/`batch`/`assignments` and ZERO `issues`. The reader is the schema source of truth; no separate schema is formalized (§6.2 D-2). **Comparison representation (normative, pinned here once for the whole document):** every intended-vs-re-read equality — the HLR-001 threshold, the glossary "Round-trip fidelity", LLR-001.3, LLR-003.1, and the verify step — is asserted in ONE canonical form: the intended `batch`/`assignments` path entries are RESOLVED against the same `project_root` (via `_resolve_manifest_entry` semantics, `variant_execution_service.py:203`; the relative→absolute transform at `:235` for `batch` and the assignments loop at `:271`–`:290`) BEFORE comparison, so both sides are resolved-absolute `Path`s — matching the established reader-side idiom `tests/test_variant_execution.py:163` (`assert manifest.batch == [(project_dir / "doc.json").resolve()]`). `active_variant` is compared as the raw string the reader keeps (`:404-405`). Comparing the writer's relative POSIX strings directly against the reader's resolved `Path`s is FORBIDDEN (it is either unpassable or vacuous). Every equality threshold below inherits this clause by reference.
- **C-2 Containment.** The write MUST land only inside `.s19tool/workarea/<project>/` and MUST reuse the existing `copy_into_workarea` containment (reparse-point + path-escape + size guard, `workspace.py:215`). No bytes outside the work area.
- **C-3 Headless writer.** The serializer + verify logic MUST be stdlib + sibling-engine only — no `textual` import — so it stays reusable and testable headless (the `verify.py:11` precedent; `test_no_textual_in_static_import_graph`, `test_checks_engine.py:400`).
- **C-4 Engine-frozen.** No planned file may be in the frozen set (`test_engine_unchanged.py:120`, `test_tui_directionb.py:3738`). Verified §6.3 census.
- **C-5 Collect-don't-abort.** Every failure mode (containment, IO, parse drift) is a returned finding, mirroring the reader's contract (`variant_execution_service.py:319`).
- **C-6 No package-root module.** No NEW module at the `s19_app/` package root (guards `test_tui_directionb.py:3201`, `:3575`). New code lives under `s19_app/tui/` subpackages.

### 2.5 Assumptions and dependencies
- **A-1.** The reader `read_project_manifest` and the `ProjectManifest` envelope are stable and remain the oracle — they are NOT modified this batch (frozen-adjacent; if the reader schema changes mid-batch, the round-trip target shifts and the batch is invalidated).
- **A-2.** `copy_into_workarea` (`workspace.py:215`) and `ensure_workarea` (`workspace.py:41`) remain the containment primitives; the staged-write pattern of `write_change_document` (`io.py:1167`) is the template.
- **A-3.** A `ProjectVariantSet` for the project is available in memory at save time (`build_variant_set`, `workspace.py:376`) — variant ids and the active id come from it, NOT re-derived.
- **A-4.** `active_variant` written equals `ProjectVariantSet.active_id` (a `variant_id`), so a round-tripped read yields the same string (the reader keeps `active_variant` as a raw string, `variant_execution_service.py:404-405`).
- **A-5 (gate-confirmable).** The project-save TUI flow is the intended trigger; the exact widget/handler is confirmed in Phase 3 (§6.3).

### 2.6 Source user stories

> Connextra format: **"As a `<role>`, I want `<goal>`, so that `<benefit>`"**.
> Each US gets a unique ID `US-NNN` and must be traceable to one or more HLRs.

| ID | User Story | Source |
|----|------------|--------|
| US-010 | As an s19tool operator, I want the tool to WRITE the project manifest (`project.json`) — not only read it — so that a project's variant/A2L/MAC composition and active-variant selection can be created and updated from the tool instead of hand-authored, and the written manifest can be verify-checked (re-read → compared against intent) the way batch-10 verifies written images. | Operator, batch-11 core (2026-06-14). Closes the batch-06/E6 gap: `project.json` is read-only today (hand-authored). Reuses the batch-10 verify-on-save substrate (`verify_written_image` pattern) as the manifest-write integrity check. |

> **Scope notes (informative):** the CRC first-operation fill-in stays QUEUED pending the operator's CRC definition (postponed b08→b10→b11). Optional E2E pilot / perf-knee test remain queued. Numbering: US-006..US-009 consumed by batches 08–10; this batch takes US-010.

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

### HLR-001 — Serialize project composition to the canonical manifest envelope
- **Traceability:** US-010
- **Statement:** When the system is asked to persist a project composition, the system shall serialize the project's `active_variant`, project-wide `batch` list, and per-variant `assignments` into a JSON object whose key set and value shapes are exactly those that `read_project_manifest` parses back without producing any `ValidationIssue`.
- **Rationale (informative):** The reader is the oracle; round-trip fidelity to it (not a separately formalized schema) is the correctness criterion, exactly as the batch-10 emitter round-trips against `IntelHexFile`.
- **Validation:** `test`
- **Executed verification:** `python -m pytest -q tests/test_manifest_writer.py::test_roundtrip_equals_intent_in_canonical_form` (IMPLEMENTED) — round-trip assertion: serialize → `read_project_manifest` → assert `issues == []` and parsed fields equal intended.
- **Numeric pass threshold:** re-read `ProjectManifest.issues` count == 0 AND `active_variant`/`batch`/`assignments` equality == 100% over the round-trip cases, where equality is asserted in the **C-1 canonical comparison form** (intended entries resolved against `project_root` via `_resolve_manifest_entry` before comparison; `active_variant` compared as raw string).
- **Priority:** high

### HLR-002 — Write the manifest into the contained work area
- **Traceability:** US-010
- **Statement:** When the serialized manifest is written, the system shall place `project.json` only inside `.s19tool/workarea/<project>/` using the existing `copy_into_workarea` containment discipline, and if the write target fails containment or IO, then the system shall return a finding rather than raise.
- **Rationale (informative):** The manifest is a project file like any other write the tool emits; it must obey the same reparse-point / path-escape / size guards and collect-don't-abort contract as `write_change_document`.
- **Validation:** `test`
- **Executed verification:** `python -m pytest -q tests/test_manifest_writer.py::test_destination_outside_workarea_returns_finding` (IMPLEMENTED; the `-k containment` selector was provisional) — assert written path `is_relative_to` the workarea root; assert a path-escape / reparse target yields a finding and `None` path, no exception.
- **Numeric pass threshold:** written-path-inside-workarea == True for all valid cases; uncaught exceptions on rejected targets == 0; findings produced on rejected targets ≥ 1.
- **Priority:** high

### HLR-003 — Verify the written manifest against intent (verify-on-write)
- **Traceability:** US-010
- **Statement:** When a manifest has been written, the system shall re-read `project.json` via `read_project_manifest` and compare the re-read `active_variant`/`batch`/`assignments` (and the re-read `issues`) against the intended composition, returning a verified outcome iff the re-read parse equals intent with zero reader issues, and a mismatch outcome naming the drifting keys otherwise.
- **Rationale (informative):** This is the JSON analogue of batch-10's `verify_written_image` (write → re-read → diff). A manifest is a dict, not a mem_map, so the comparison is key-wise equality, NOT `diff_mem_maps` (§6.2 D-1).
- **Validation:** `test`
- **Executed verification:** `python -m pytest -q tests/test_manifest_verify.py::test_faithful_write_verifies tests/test_manifest_verify.py::test_tampered_active_variant_mismatches_naming_the_key` (IMPLEMENTED) — happy-path verified; a corrupted/tampered written file yields mismatch naming the drifted key(s).
- **Numeric pass threshold:** verified outcome on a faithful write == True; mismatch outcome enumerates ≥ 1 drifting key on a tampered write; 0 false-verified on tampered inputs.
- **Priority:** high

### HLR-004 — Surface manifest write + verify in the TUI project-save flow
- **Traceability:** US-010
- **Statement:** Where the project-save surface is triggered, the system shall invoke the serialize→write→verify pipeline for the active project and surface the verify outcome (verified, or mismatch naming the drift) to the operator without blocking the existing save behavior.
- **Rationale (informative):** Batch-10 surfaced verify-on-save quietly on success and loudly on mismatch; the manifest write reuses that surfacing shape. Exact widget/handler is gate-confirmable (§6.3).
- **Validation:** `demo`
- **Executed verification:** N/A (demo) — observable procedure: in the TUI, save a project; observe `project.json` is written under the project dir and the verify status (verified / mismatch text) is shown.
- **Numeric pass threshold:** N/A (demo) — qualitative criterion: a saved project produces a reader-valid `project.json` and the operator sees a verified status; a deliberately tampered file shows a mismatch notice naming the key.
- **Priority:** medium

---

## 4. Low-level requirements (LLR)

> Each LLR decomposes an HLR into a verifiable property at the implementation level.
> Same EARS regime. ID format: `LLR-<HLR>.<M>`.

> **Symbol-citation key for this section:** every concrete symbol carries either a grep-verified `file:line` (exists today) or `NEW — created in Phase 3`. Test FILE paths, `-k` selectors, and node ids are `provisional until Phase 3` (V-5). New module home (subject to §6.3 gate, default `s19_app/tui/services/manifest_writer.py` for serialize+verify, with the WRITE helper as a thin reuse of `io.py` write discipline): `NEW — created in Phase 3`.

#### HLR-001 — serialization

### LLR-001.1 — Build the manifest envelope dict from a `ProjectVariantSet`
- **Traceability:** HLR-001
- **Statement:** The manifest serializer shall produce a `dict` with keys `schema_version`, `active_variant`, `batch`, `assignments` — and shall emit JSON only via the stdlib `json` encoder (`json.dumps`), never by string assembly — where `active_variant` is `ProjectVariantSet.active_id` (`models.py:102`), `batch` is the project-wide change/check file list as project-relative POSIX path strings, and `assignments` maps each `variant_id` to its project-relative file-string list.
- **Validation:** `test (unit)`
- **Executed verification:** `python -m pytest -q tests/test_manifest_writer.py::test_envelope_keys_and_active_variant` (IMPLEMENTED; `-k envelope_keys` was provisional).
- **Numeric pass threshold:** produced dict top-level keys ⊇ {`schema_version`,`active_variant`,`batch`,`assignments`}; `active_variant` == input `active_id`; assert exit code 0.
- **Acceptance criteria (informative):**
  - `serialize_manifest` is `NEW — created in Phase 3`.
  - The dict is JSON-serializable (`json.dumps` succeeds).
  - `active_id is None` (empty project) → `active_variant` is `null` in JSON, which the reader maps to `None` (`variant_execution_service.py:405`).

### LLR-001.2 — Paths serialized project-relative, forward-slash, so the reader resolves them in-project
- **Traceability:** HLR-001
- **Statement:** The serializer shall write every `batch`/`assignments` entry as a project-relative path string using forward slashes, such that `_resolve_manifest_entry` (`variant_execution_service.py:203`) resolves it inside the project root with NO `MANIFEST-PATH-ESCAPE` finding.
- **Validation:** `test (unit)`
- **Executed verification:** `python -m pytest -q tests/test_manifest_writer.py::test_relative_paths_resolve_with_no_escape tests/test_manifest_writer.py::test_windows_backslashes_normalized_to_forward_slash` (IMPLEMENTED; `-k relative_paths` was provisional).
- **Numeric pass threshold:** for every emitted entry, `_resolve_manifest_entry(project_root, entry, ...)` returns a non-`None` Path and appends 0 issues; count of `MANIFEST-PATH-ESCAPE` over round-trip == 0.
- **Acceptance criteria (informative):**
  - Absolute paths are NEVER emitted (the reader rejects them, `variant_execution_service.py:261`).
  - Windows back-slashes are normalized to `/` before emission (POSIX form round-trips on both OS).

### LLR-001.3 — Round-trip fidelity: written dict re-reads to an issue-free `ProjectManifest` equal to intent
- **Traceability:** HLR-001
- **Statement:** When the serialized dict is written and re-read by `read_project_manifest` (`variant_execution_service.py:293`), the resulting `ProjectManifest.issues` shall be empty and its `active_variant`, `batch`, and `assignments` shall equal the intended composition in the C-1 canonical comparison form (intended entries resolved against the same `project_root` via `_resolve_manifest_entry`, `variant_execution_service.py:235`/`:290`, so both sides are resolved-absolute `Path`s; `active_variant` compared as raw string).
- **Validation:** `test (integration)`
- **Executed verification:** `python -m pytest -q tests/test_manifest_writer.py::test_roundtrip_equals_intent_in_canonical_form tests/test_manifest_writer.py::test_roundtrip_schema_version_survives` (IMPLEMENTED; `-k roundtrip` was provisional) — serialize → write to a tmp project dir → `read_project_manifest` → assert equality (C-1 canonical form: resolve the intended entries against the tmp project dir, the `test_variant_execution.py:163` idiom) + empty issues.
- **Numeric pass threshold:** `len(ProjectManifest.issues) == 0`; intended-vs-reread equality over (`active_variant`,`batch`,`assignments`) == 100% in the C-1 canonical comparison form.
- **Acceptance criteria (informative):**
  - `schema_version` survives the round-trip as the same int/str the reader keeps (`variant_execution_service.py:395-403`).
  - The test fixture project dir is `NEW — created in Phase 3` (built in-test via tmp_path, not from `examples/`).

### LLR-001.4 — Deterministic output (same composition → byte-identical JSON)
- **Traceability:** HLR-001
- **Statement:** The serializer shall produce byte-identical output for two calls over the same composition (stable key order, stable list order matching the variant/manifest order), so a no-change re-save is a no-op and the verify step is deterministic.
- **Validation:** `test (unit)`
- **Executed verification:** `python -m pytest -q tests/test_manifest_writer.py::test_deterministic_byte_identical_output` (IMPLEMENTED; `-k deterministic` was provisional) — serialize twice, assert byte-equal.
- **Numeric pass threshold:** `serialize(c) == serialize(c)` byte equality == True over the determinism cases.
- **Acceptance criteria (informative):**
  - List order follows `ProjectVariantSet.variants` order (already deterministic `(name.lower(), name)`, `workspace.py:431-434`) and manifest `batch` insertion order.

### LLR-001.5 — Serializer REFUSES absolute / project-escaping path entries up front (security input gate)
- **Traceability:** HLR-001 (security input-validation gate; serialize step)
- **Statement:** If any `batch` or `assignments` path entry in the in-memory composition is absolute, or resolves outside `project_root`, then the serializer shall refuse the whole operation — returning `(None, [finding])` and writing NOTHING — applying the SAME rejection predicate the reader uses (`_resolve_manifest_entry`'s absolute check at `variant_execution_service.py:261` and the project-escape check at `:271`–`:290`), rather than emitting a string the reader would later silently skip.
- **Validation:** `test (unit)`
- **Executed verification:** `python -m pytest -q tests/test_manifest_writer.py::test_refuse_escape_and_absolute_entries_writes_nothing tests/test_manifest_writer.py::test_clean_composition_passes_the_gate tests/test_manifest_writer.py::test_refusal_emits_no_file_when_caller_would_write` (IMPLEMENTED; `-k refuse_escape` was provisional) — tamper the in-memory composition with `../../x` (and, separately, an absolute path) → assert the serializer returns `(None, [finding])`, the finding names the offending entry, and NO file is written.
- **Numeric pass threshold:** on a tampered composition (escaping `../../x` OR absolute entry) the serializer returns path == None AND findings ≥ 1 AND files written == 0; on a clean composition findings == 0 and serialization proceeds.
- **Acceptance criteria (informative):**
  - The refusal reuses the reader's rejection predicate (no second, divergent path-safety implementation); the finding code constant (e.g. `MANIFEST_WRITE_ESCAPE`) is `NEW — created in Phase 3`.
  - The refusal adds NO key to the manifest envelope (the C-9 contract field set is unchanged — see §6.2.1 identity re-run).
  - TC for this LLR lands in `tests/test_manifest_writer.py` (the writer test file) and is also surfaced as the HLR-002-side write-refusal case (no bytes written).

#### HLR-002 — contained write

### LLR-002.1 — Stage-then-ATOMICALLY-REPLACE the manifest at the fixed name (NOT via `copy_into_workarea`'s dedup body)
- **Traceability:** HLR-002
- **Statement:** The manifest writer shall stage the serialized bytes under `.s19tool/workarea/temp/`, validate the final destination `project_dir / "project.json"` with the SAME containment CHECKS that `copy_into_workarea` applies (`_find_workarea_root` + `is_relative_to(workarea_root)` + `_path_traverses_reparse_point`, `workspace.py:278`–`:291`), and then perform an ATOMIC `os.replace(staged, project_dir / "project.json")` so a re-save overwrites the existing manifest in place at the fixed name; it shall NOT route the manifest through `copy_into_workarea`'s copy-with-dedup function body (`workspace.py:300`–`:311`, which appends `_<N>` on collision and would produce `project_1.json` — invisible to the reader that opens only `project_dir / PROJECT_MANIFEST_NAME`, `variant_execution_service.py:344`), and shall remove the staged temp file afterward.
- **Validation:** `test (integration)`
- **Executed verification:** `python -m pytest -q tests/test_manifest_writer.py::test_two_saves_leave_exactly_one_manifest_second_wins tests/test_manifest_writer.py::test_write_places_manifest_and_reads_back` (IMPLEMENTED; `-k staged_place` was provisional) — save twice into the same project dir; assert exactly one `project.json` exists (no `project_1.json`) and its content is the 2nd save's.
- **Numeric pass threshold:** returned path exists and `is_relative_to` the workarea root == True; written file `.name == "project.json"` == True; after two saves the project dir contains exactly ONE `project.json` and ZERO `project_1.json` files; staged temp file removed after call == True; assert exit code 0.
- **Acceptance criteria (informative):**
  - `write_project_manifest` is `NEW — created in Phase 3`.
  - `ensure_workarea` (`workspace.py:41`) is called before staging.
  - `os.replace` is stdlib and atomic on same-filesystem renames (POSIX + Windows); staging under the same `.s19tool/workarea/` tree keeps source and destination on one filesystem, so the replace is atomic — see D-3 (locked mechanism).
  - A containment-check seam (the reused `_find_workarea_root` / `is_relative_to` / `_path_traverses_reparse_point` checks) is exercised against the destination before the replace; tests without symlink privilege use an in-workarea destination so the checks pass naturally.

### LLR-002.2 — Manifest name is fixed to `project.json` and cannot escape via the name
- **Traceability:** HLR-002
- **Statement:** The writer shall write under the fixed name `project.json` (`PROJECT_MANIFEST_NAME`, `variant_execution_service.py:84`) placed directly in the project directory via the atomic same-name replace of LLR-002.1, never honoring a caller-supplied path component in the name and never dedup-suffixing on re-save.
- **Validation:** `test (unit)`
- **Executed verification:** `python -m pytest -q tests/test_manifest_writer.py::test_fixed_name_and_staged_temp_removed tests/test_manifest_writer.py::test_two_saves_leave_exactly_one_manifest_second_wins` (IMPLEMENTED; `-k fixed_name` was provisional) — save twice; assert exactly one `project.json` (no `project_1.json`) and `read_project_manifest` returns the 2nd save's content.
- **Numeric pass threshold:** written file `.name == "project.json"` == True; after two saves exactly ONE `project.json` exists in the project dir AND ZERO `project_1.json`; the re-read `read_project_manifest` reflects the 2nd save (its `active_variant`/`batch`/`assignments` equal the 2nd composition in C-1 canonical form); no directory traversal in the resulting path.
- **Acceptance criteria (informative):**
  - The target project directory must be a `.s19tool/workarea/<project>/` directory (so the reader will later find it, `variant_execution_service.py:344`).
  - Because the name is fixed and the placement is an atomic `os.replace`, a re-save overwrites the prior `project.json` in place (NOT dedup-suffixed) — see §6.3 R-3 and D-3.

### LLR-002.3 — Containment / reparse / IO failure returns a finding, never raises
- **Traceability:** HLR-002
- **Statement:** If the destination containment check raises `WorkareaContainmentError` (`workspace.py:28`) or the staged-write / atomic `os.replace` raises an `OSError`, then the writer shall return `(None, [finding])` with one WARNING-or-ERROR `ValidationIssue`, mirroring the `MF_WRITE_CONTAINMENT` (`io.py:1248`, value `"MF-WRITE-CONTAINMENT"`) collect-don't-abort behavior of `write_change_document` (`io.py:1245-1255`).
- **Validation:** `test (integration)`
- **Executed verification:** `python -m pytest -q tests/test_manifest_writer.py::test_destination_outside_workarea_returns_finding tests/test_manifest_writer.py::test_refused_serialize_short_circuits_without_writing` (IMPLEMENTED; `-k write_failure` was provisional) — destination outside the workarea / refused serialize yields a finding; assert `(None, issues)` with ≥1 finding and no propagated exception.
- **Numeric pass threshold:** propagated exceptions == 0; findings on failure ≥ 1; returned path == None on failure.
- **Acceptance criteria (informative):**
  - The finding code constant (e.g. `MANIFEST_WRITE_CONTAINMENT`) is `NEW — created in Phase 3`.

#### HLR-003 — verify-on-write

### LLR-003.1 — Re-read the written manifest and compare key-wise against intent
- **Traceability:** HLR-003
- **Statement:** The manifest verify function shall re-read the written manifest via `read_project_manifest` (`variant_execution_service.py:293`) addressed by the CANONICAL `project_dir / PROJECT_MANIFEST_NAME` (`variant_execution_service.py:84`/`:344`) — NOT the path the write helper returns — and compare the re-read `active_variant`, `batch`, and `assignments` against the intended composition in the C-1 canonical comparison form (intended entries resolved against the same `project_root`), returning a result whose status is verified iff all three are equal AND the re-read `issues` list is empty.
- **Validation:** `test (integration)`
- **Executed verification:** `python -m pytest -q tests/test_manifest_verify.py::test_faithful_write_verifies tests/test_manifest_verify.py::test_verify_reads_canonical_name_not_a_stray_suffixed_file` (IMPLEMENTED; `-k verified` was provisional).
- **Numeric pass threshold:** faithful write → status verified == True (equality in the C-1 canonical comparison form); re-read `issues` honored (non-empty issues → status mismatch); assert exit code 0.
- **Acceptance criteria (informative):**
  - `verify_written_manifest` is `NEW — created in Phase 3`.
  - The re-read is addressed by the canonical fixed name, so a stray dedup-suffixed file (which LLR-002.1 now precludes) could never produce a false verify against a stale manifest.
  - The comparison is key-wise dict equality in the C-1 canonical form, NOT `diff_mem_maps` (§6.2 D-1; `diff_mem_maps` lives at `compare.py:272` and operates on `Dict[int,int]`, not a manifest).

### LLR-003.2 — Mismatch result enumerates the drifting keys
- **Traceability:** HLR-003
- **Statement:** When the re-read manifest differs from intent, the verify function shall return a mismatch status carrying the names of the keys that drifted (`active_variant` and/or `batch` and/or `assignments`) and/or the re-read reader `issues`, so a consumer can name what failed.
- **Validation:** `test (integration)`
- **Executed verification:** `python -m pytest -q tests/test_manifest_verify.py::test_tampered_active_variant_mismatches_naming_the_key` (IMPLEMENTED; `-k mismatch` was provisional) — tamper the written file (e.g. flip `active_variant`), assert mismatch + the tampered key named.
- **Numeric pass threshold:** on a single-key tamper, drifting-key list == exactly that key (1 element); false-verified count on tampered inputs == 0.
- **Acceptance criteria (informative):**
  - The result type (e.g. `ManifestVerifyResult` with `status` + `drift` + `issues` + `written_path`) is `NEW — created in Phase 3`, modeled on `VerifyResult` (`verify.py:34`) shape but NOT reusing `DiffRun`/`DiffStats`.
  - Status constants (e.g. `MANIFEST_VERIFIED` / `MANIFEST_MISMATCH`) `NEW — created in Phase 3`, mirroring `STATUS_VERIFIED`/`STATUS_MISMATCH` (`verify.py:28`,`:31`).

### LLR-003.3 — A reader-rejected write is a mismatch, not a verified result
- **Traceability:** HLR-003
- **Statement:** If the re-read `read_project_manifest` returns a `ProjectManifest` carrying any `issues` (size cap, JSON parse, bad structure, path escape — `variant_execution_service.py:357-461`), then the verify function shall classify the outcome as mismatch and include those issues in the result.
- **Validation:** `test (integration)`
- **Executed verification:** `python -m pytest -q tests/test_manifest_verify.py::test_reader_issues_force_mismatch_even_if_surviving_keys_match` (IMPLEMENTED; `-k reader_issue` was provisional) — write a file the reader flags (e.g. an entry that escapes), assert mismatch carrying the `MANIFEST-*` issue.
- **Numeric pass threshold:** re-read issues ≥ 1 → status mismatch == True; the result's issue list length == re-read issue count.
- **Acceptance criteria (informative):**
  - This closes the gap where a write "succeeds" (file lands) but the reader can't use it — surfacing it as mismatch.
  - The reader's `MANIFEST_SIZE_CAP` rejection (`MANIFEST_SIZE_CAP_BYTES` = 256 MB, `variant_execution_service.py:88`/`:357`) is one of the re-read `issues` already classified here as mismatch — no separate requirement; the round-trip claim holds.

#### HLR-004 — TUI surface

### LLR-004.1 — Project-save invokes serialize→write→verify and stores the outcome
- **Traceability:** HLR-004
- **Statement:** Where the operator triggers project save, the app shall call the serialize→write→verify pipeline for the active project and retain the `ManifestVerifyResult` for surfacing, without changing the existing project file-copy save behavior.
- **Validation:** `inspection`
- **Executed verification:** Inspect the project-save handler in `s19_app/tui/app.py` (IMPLEMENTED: `_handle_save_dialog` → `_write_and_verify_manifest` at `app.py:3539`, calling `write_project_manifest` `app.py:3578` + `verify_written_manifest` `app.py:3592`; covered by `tests/test_tui_manifest_save.py::test_project_save_writes_and_verifies_manifest`) for a call into `write_project_manifest` + `verify_written_manifest`. Observable condition: the handler invokes both and binds the result.
- **Numeric pass threshold:** N/A (inspection) — condition: pipeline call present in the save handler; pre-existing save behavior unchanged (existing save tests still pass).
- **Acceptance criteria (informative):**
  - The exact handler/method name is `provisional until Phase 3` (V-5) — do not pin a method name here.

### LLR-004.2 — Verify outcome surfaced: quiet on verified, named drift on mismatch
- **Traceability:** HLR-004
- **Statement:** When the manifest verify completes, the TUI shall present a concise verified indication on success and, on mismatch, a notice naming the drifting key(s) / reader issue(s), reusing the severity/colour convention (`color_policy.SEVERITY_CLASS_MAP`, frozen) for the mismatch class.
- **Validation:** `demo`
- **Executed verification:** N/A (demo) — save a project (observe verified status); tamper `project.json` and re-run verify path (observe mismatch notice naming the key).
- **Numeric pass threshold:** N/A (demo) — qualitative: verified state visible on a clean save; mismatch notice names ≥1 key on tamper.
- **Acceptance criteria (informative):**
  - `color_policy.py` is FROZEN — this LLR only *consumes* `SEVERITY_CLASS_MAP`, never edits it.
  - Re-read reader-issue messages (`issue.message`) are presented as PLAIN text — no Rich-markup interpolation of the attacker-influenceable message string into a markup-parsed widget (escape or render literally), so a crafted path/issue text cannot inject markup.
  - Surfacing widget id `provisional until Phase 3` (V-5).

### LLR-004.3 — The serializer/verify modules import no `textual` (headless)
- **Traceability:** HLR-004
- **Statement:** The serialize + write + verify modules shall import neither `textual` nor any `textual.*` submodule, AND shall not configure or emit logging (no `import logging` / `getLogger`), keeping the manifest write logic headless, side-effect-quiet, and reusable (the `verify.py` precedent — headless and no-logging, F-S-07).
- **Validation:** `test (integration)`
- **Executed verification:** `rg -n "import textual|from textual" s19_app/tui/services/manifest_writer.py` (IMPLEMENTED module) → expect 0 matches; encoded as `tests/test_tui_manifest_save.py::test_manifest_writer_module_is_headless` (also asserts no `logging` import); the static-import-graph walk (`test_no_textual_in_static_import_graph`, `test_checks_engine.py`) stays green (the new module is not reachable from a textual-importing root).
- **Numeric pass threshold:** `import textual|from textual` matches in the new modules == 0; `getLogger|import logging` matches in the new modules == 0. **Probe self-test (V-4 form):** run `rg -n "import textual|from textual" s19_app/tui/changes/verify.py` today → **executed 2026-06-14: 0 hits** (regime: existing headless sibling, single-package `s19_app/tui/changes/`; confirms the import-statement form returns 0 on a known-headless module — positive baseline). No-logging probe: `rg -n "getLogger|import logging" s19_app/tui/changes/verify.py` → **executed 2026-06-14: 0 hits** (same regime; the headless verify sibling carries no logging — positive baseline for the new modules' no-logging contract). Negative control: `rg -n "import textual|from textual" s19_app/tui/app.py` → **executed 2026-06-14: ≥1** (textual app, e.g. `app.py:10-12`); for no-logging, `rg -n "getLogger|import logging" s19_app/tui/services/validation_service.py` → **executed 2026-06-14: ≥1** (a known-logging sibling service — `app.py` itself does NOT call `logging`, so the logging negative control uses a service module that does). The new module lives one level over (`tui/services/`) — same import-depth regime as existing headless `services/change_service.py`.
- **Acceptance criteria (informative):**
  - Matches the `verify.py` headless + no-logging contract (F-S-07 precedent); the probe uses import-statement form, never bare-token substring (V-4).

---

## 5. Validation strategy

### 5.1 Methods
- **Test:** automated execution (unit / integration / e2e). Default for LLR. **Every `test` LLR must name the exact executed verification and the numeric pass threshold — otherwise it is not executable.**
- **Demo:** observed execution of behavior. Useful for UX-oriented HLRs. Describe the observable procedure + the named qualitative criterion.
- **Inspection:** static review of code or document. Useful for structural requirements. Name the file / commit / section + the observable condition.
- **Analysis:** formal or quantitative reasoning (performance, complexity, security). **Every `analysis` LLR must name the executed calculation (with input values) and the numeric pass threshold — otherwise it is not executable.**

> Reminder from the batch-02 + batch-03 post-mortems: the absence of an executed verification + numeric pass threshold on `test`/`analysis` requirements was the recurring root cause of forced phase-1 iteration. Capture at draft time, not at the phase-2 gate.

### 5.2 Coverage table

> Test-case ids are spec-pinned; the test FILE paths / `-k` selectors / node ids are `provisional until Phase 3` (V-5) and reconciled from the real tree at Phase 4.
>
> **[Phase-6 reconciliation per 04-validation DEV-1]:** the §3/§4 Executed-verification `-k` selectors and the I4 test FILE have been reconciled to the real implemented node ids on disk — I1/I2 in `tests/test_manifest_writer.py`, I3 in `tests/test_manifest_verify.py`, and the TUI surface (HLR-004) in `tests/test_tui_manifest_save.py` (the spec's provisional `tests/test_manifest_writer.py` for the TUI demo was implemented under the dedicated TUI test file). The provisional `-k` tokens (`envelope_keys`, `roundtrip`, `staged_place`, `verified`, `mismatch`, `reader_issue`, …) are not the implemented function names; each Executed-verification line above now cites the real node id. All 23 nodes collect (see §5.3.1).

| Requirement | Method | Test Case ID | Notes |
|-------------|--------|--------------|-------|
| HLR-001 | test | TC-001 | round-trip to reader, issues==0 |
| HLR-002 | test | TC-002 | contained write + collect-don't-abort |
| HLR-003 | test | TC-003 | verify-on-write verified/mismatch |
| HLR-004 | demo | TC-D1 | TUI save → write+verify surfaced |
| LLR-001.1 | test (unit) | TC-001a | envelope keys + active_variant |
| LLR-001.2 | test (unit) | TC-001b | project-relative POSIX paths, 0 escapes |
| LLR-001.3 | test (integration) | TC-001c | round-trip equality, issues==0 |
| LLR-001.4 | test (unit) | TC-001d | byte-deterministic output |
| LLR-001.5 | test (unit) | TC-001e | refuse absolute/escaping entry → (None, finding), no file written (M-3 security gate) |
| LLR-002.1 | test (integration) | TC-002a | staged + atomic os.replace at fixed name; two saves → one project.json |
| LLR-002.2 | test (unit) | TC-002b | fixed name `project.json`, no traversal |
| LLR-002.3 | test (integration) | TC-002c | failure → (None, finding), no raise |
| LLR-003.1 | test (integration) | TC-003a | re-read + key-wise compare |
| LLR-003.2 | test (integration) | TC-003b | mismatch names drifting key(s) |
| LLR-003.3 | test (integration) | TC-003c | reader-rejected write → mismatch |
| LLR-004.1 | inspection | TC-004a | save handler calls pipeline |
| LLR-004.2 | demo | TC-D1 | verified quiet / mismatch named |
| LLR-004.3 | test (integration) | TC-004b | no textual import (V-4 probe) |

### 5.3 Batch acceptance criteria
- 100% of LLRs covered by ≥1 TC with a pass result.
- Round-trip fidelity: every serialize→read case yields `ProjectManifest.issues == []` and field equality == 100%.
- 0 uncaught exceptions on rejected write targets; ≥1 finding produced per rejection.
- 0 false-verified outcomes on tampered manifests.
- 0 `textual` imports in the new headless modules (V-4 probe).
- 0 modifications to any engine-frozen file (`test_engine_unchanged.py::test_tc027_*`, `test_tui_directionb.py::test_tc031_*` stay green).
- No new module at the `s19_app/` package root (root-module guards stay green).

#### 5.3.1 Collection baseline reconciliation (re-measured)
- **Measured baseline:** `python -m pytest -q --collect-only` last line = **`816 tests collected in 0.69s`** (executed 2026-06-14; the prompt's "do not assume 816" check — measured value is in fact 816).
- **Deletions (D):** 0 (no test removed).
- **Additions (A):** **23** (ACTUAL, reconciled at Phase 4). Three new test files: `tests/test_manifest_writer.py` (15 nodes — I1 serialize: 10, I2 write: 5), `tests/test_manifest_verify.py` (4 nodes — I3 verify), and `tests/test_tui_manifest_save.py` (4 nodes — I4 TUI surface). [Phase-6 reconciliation per 04-validation DEV-2: the spec predicted A ≈ 13–17; the ACTUAL is 23 (+6 over the upper bound), driven by multiple AC-level assertion tests per TC — over-coverage, not a shortfall.]
- **Signed balance (reconciled):** `post = base − D + A = 816 − 0 + 23 = `**`839`**. Measured `python -m pytest -q --collect-only` last line at Phase 4 = **`839 tests collected`** (D=0; all 3 new files absent on `origin/main`). The Phase-1 prediction was **829–833**; the ACTUAL is **839** (see the DEV-2 note on the Additions line above).

---

## 6. Appendices

### 6.1 Extended glossary
See §1.3. Additional: **drift** = a key whose re-read value differs from the intended value; **oracle** = the existing reader `read_project_manifest` against which the writer's correctness is defined.

### 6.2 Relevant design decisions

**D-1 — Dedicated manifest verify, NOT a generalized mem_map verify (recommended).**
The batch-10 `verify_written_image` (`verify.py:119`) diffs two `Dict[int,int]` mem_maps via `diff_mem_maps` (`compare.py:272`). A manifest is a JSON dict with heterogeneous values (`active_variant: str`, `batch: list[Path]`, `assignments: dict`), not an address→byte map. Forcing a mem_map abstraction onto JSON would be a mis-fit (no notion of contiguous runs, no `DiffRun`/`DiffStats` meaning). **Recommendation: a small dedicated `verify_written_manifest` + `ManifestVerifyResult`**, mirroring `verify.py`'s *shape and purpose* (write→re-read→classify, `STATUS_VERIFIED`/`STATUS_MISMATCH` analogues, `written_path` stamp) but with key-wise dict comparison and reader-`issues` honoring. This is the cleaner, lower-coupling choice and matches the prompt's bias. *(Alternative (b) — generalize verify.py into a protocol over "re-read + diff" — was considered and rejected: it would widen the frozen-adjacent verify surface for a single new consumer, violating simplicity-first.)*

**D-2 — Schema source of truth = round-trip fidelity to the reader (recommended).**
The reader `read_project_manifest` already defines the accepted envelope (`schema_version`, `active_variant`, `batch`, `assignments`) and all its tolerances (`variant_execution_service.py:395-461`). The writer infers the schema FROM the reader: "write what the reader reads back cleanly." This is exactly the batch-10 emitter↔`IntelHexFile` precedent — no separate schema doc to drift. *(Alternative — formalize a JSON Schema — rejected: a second source of truth that can disagree with the reader; the reader stays the single oracle.)*

**D-3 — Writer home + LOCKED placement mechanism = atomic same-name replace reusing the containment CHECKS (the 7th locked gate decision).**
*Home (NEW, default, placement-home still gate-confirmable §6.3):* the reader lives in `variant_execution_service.py` and explicitly justifies the service-layer home (`:6-9`). The writer is the symmetric counterpart at `s19_app/tui/services/manifest_writer.py`. Placing it in `tui/services/` keeps it headless (C-3), out of the frozen set (C-4), out of the `s19_app/` package root (C-6), and importable by `app.py` without widening the workspace surface. *(Alternative homes: `workspace.py` — rejected, it would bloat the path-resolution module; `changes/io.py` — plausible since the write discipline lives there, but `io.py` is change/check-document-centric, so a service module is cleaner.)*
*Placement MECHANISM (LOCKED, no longer open — M-2 resolution):* the writer shall stage the serialized bytes under `.s19tool/workarea/temp/`, REUSE `copy_into_workarea`'s containment CHECKS against the destination (`_find_workarea_root` + `is_relative_to(workarea_root)` + `_path_traverses_reparse_point`, `workspace.py:278`–`:291`), then perform an ATOMIC `os.replace(staged, project_dir / "project.json")`. It shall NOT route the manifest through `copy_into_workarea`'s copy-with-dedup function body (`workspace.py:300`–`:311`), which appends `_<N>` on collision and would produce `project_1.json` — invisible to the reader (`variant_execution_service.py:344`) and the silent-divergence security hazard M-1/F-S-02 identified. *(Alternative — call `copy_into_workarea` directly — REJECTED: its dedup body breaks the fixed-name overwrite contract and the verify oracle. This is now a locked decision, not a Phase-3 gate choice, so LLR-002.1 + the I2 increment are unambiguous.)*

**D-4 — Surface = TUI-only (recommended, gate-confirmable).**
Batch-10 was TUI-only (CLI deferred/unmaintained). US-010 names the operator/TUI. No CLI requirement this batch. Gate-confirmable §6.3.

#### 6.2.1 Manifest contract (canonical key set, producer ↔ consumer)
Per the contract-touch rule: the canonical written↔read key set and its producer/consumer enumeration.

**Canonical key set:** `{ schema_version, active_variant, batch, assignments }`.

| Key | Producer (writer, NEW) | Consumer (reader, exists) | Value shape |
|-----|------------------------|---------------------------|-------------|
| `schema_version` | `serialize_manifest` (NEW) | `read_project_manifest` (`variant_execution_service.py:395`) | int \| str \| null |
| `active_variant` | `serialize_manifest` (NEW) ← `ProjectVariantSet.active_id` (`models.py:102`) | `read_project_manifest` (`:404-405`) | str \| null |
| `batch` | `serialize_manifest` (NEW) | `read_project_manifest` (`:414-429`) via `_resolve_manifest_entry` (`:203`), relative→absolute resolution at `:235` (the transform B-1 turns on) | array of project-relative path strings; consumer yields resolved-absolute `Path`s |
| `assignments` | `serialize_manifest` (NEW) | `read_project_manifest` (`:431-461`) via `_resolve_manifest_entry` (`:203`), per-entry resolution loop at `:271`–`:290` | object: variant_id → array of project-relative path strings; consumer yields resolved-absolute `Path`s |

**Identity check (executed at draft):** producer key set `{schema_version, active_variant, batch, assignments}` == consumer key set parsed by the reader (`payload.get("schema_version"|"active_variant"|"batch"|"assignments")`, `variant_execution_service.py:395,404,415,432`). Field-set equality holds.

**Contract-touch re-run (Phase-1 iteration, 2026-06-15):** the M-3 fix added NEW LLR-001.5 (the serializer's absolute/escape REFUSAL gate) — a producer-side LLR. Per the contract-touch rule it re-opens this identity row. Re-ran the field-set identity: LLR-001.5 is a pre-emission INPUT-VALIDATION gate (refuse → `(None, finding)`, write nothing); it adds NO key to the emitted envelope. Producer key set remains `{schema_version, active_variant, batch, assignments}` (4); consumer key set remains the same 4. **Re-run result: 4 == 4, no drift.** Recorded in the §6.4 audit table (row J-4).

### 6.3 Open risks, gate-confirmables, and the change-first census

#### 6.3.1 Risks
- **R-1 (operational).** The reader tolerates a faulted manifest by returning empty `batch`/`assignments` with issues (collect-don't-abort). If verify only checks field equality and not the `issues` list, a write the reader silently degrades would falsely "verify." **Mitigation:** LLR-003.3 makes any re-read `issues` a mismatch.
- **R-2 (data correctness).** `assignments` keys are `variant_id`s; if the writer emits a `variant_id` that no variant owns, the reader still stores it (it does not validate variant existence at read, `variant_execution_service.py:441-461`). **Mitigation:** the serializer sources ids from the `ProjectVariantSet` (LLR-001.1); a stale id is an upstream composition bug, flagged but out of scope.
- **R-3 (overwrite).** Fixed name `project.json` means a re-save overwrites the prior manifest in place with no dedup-suffix (unlike change docs). This is correct (a project has exactly one manifest). The placement is an ATOMIC `os.replace` of a fully-staged temp file onto the fixed name (LLR-002.1, D-3): the destination is never observed half-written, so the earlier "one-way write with no backup" worry is RETIRED by atomicity — a crash mid-write leaves either the old manifest or the new one intact, never a truncated file. **Mitigation:** atomic same-name replace + verify-on-write (which catches a corrupted/escaping write immediately and re-reads by the canonical fixed name, never a stale suffixed file). A retained timestamped backup is a POSSIBLE future hardening, NOT a requirement this batch.
- **R-4 (lock-in / coupling).** The writer hard-couples to the reader's current key tolerances. If the reader schema evolves, the writer must follow. **Accepted:** this is the deliberate single-oracle design (D-2); reversible (the writer is one new module).
- **R-5 (privacy).** `project.json` contains file PATHS and variant ids only — no firmware bytes. The verify result carries key names / issues, never image bytes (the `verify.py` no-raw-bytes precedent). No new data-handling concern.

#### 6.3.2 Gate-confirmables (resolve at Phase-2/3 gate)
1. **Writer module home** — default `s19_app/tui/services/manifest_writer.py` (D-3); confirm vs `changes/io.py`.
2. **Surface** — TUI-only (D-4); confirm no CLI requirement.
3. **Verify approach** — dedicated `ManifestVerifyResult` (D-1, approach (a)); confirm not generalizing `verify.py`.
4. **Schema source** — round-trip-to-reader (D-2); confirm no formal schema.
5. **TUI save handler / widget** — exact handler + surfacing widget id (LLR-004.1/004.2) `provisional until Phase 3`.
6. **`schema_version` value written** — what literal the writer emits (the reader accepts any int/str; pick a stable value, e.g. `1`) — confirm at Phase 3.
7. **Placement mechanism — LOCKED (no longer open).** Stage to `temp/` → reuse `copy_into_workarea`'s containment CHECKS (`workspace.py:278`–`:291`) → atomic `os.replace` at the fixed `project.json` name; NOT `copy_into_workarea`'s dedup body (`:300`–`:311`). Resolved at the Phase-1 iteration (M-2); listed here for completeness as a decided item, not a pending one. See D-3 + LLR-002.1.

#### 6.3.3 Change-first supersession census (A-1 — best-effort + gate-confirmed, NOT stamped complete)
Per A-1/A-2/A-3: keyed on the CATEGORY of guard assertion, run change-first over the planned file list. Census is a Phase-1 cost-reduction heuristic; the **increment gate (running the moved/edited file against the real suite) is the completeness guarantee.** This census is **NOT stamped "VERIFIED COMPLETE."**

**Planned new/edited files (Phase 3, ≤5/increment):**
- (NEW) `s19_app/tui/services/manifest_writer.py` — serialize + write + verify.
- (NEW) `tests/test_manifest_writer.py`, `tests/test_manifest_verify.py`.
- (EDIT) `s19_app/tui/app.py` — wire save handler (HLR-004).
- (EDIT, possible) `s19_app/tui/services/__init__.py` and/or `REQUIREMENTS.md` — exports + traceability.

| Planned file | Guard family | Probe (executed 2026-06-14) | Verdict |
|--------------|--------------|------------------------------|---------|
| `tui/services/manifest_writer.py` (NEW) | (d) engine-frozen / no-diff-vs-main | `_ENGINE_PATHS` resolved = {core, hexfile, range_index, validation, tui/a2l, tui/mac, tui/color_policy} (`test_engine_unchanged.py:120`, `test_tui_directionb.py:3738`); `tui/services/` ∉ frozen set | NOT frozen — OK |
| `tui/services/manifest_writer.py` (NEW) | (b) structural / placement / allowlist | root-module guards check `Path(s19_app.__file__).parent.glob("*.py")` ONLY (`test_tui_directionb.py:3201`, `:3575`); a file under `tui/services/` is not a `s19_app/` root module | not at package root — OK |
| `tui/services/manifest_writer.py` (NEW) | (c) AST-composition | `rg ast\.` guards target specific modules (commandbar, compare_service, checks_engine, directionb); none assert on `tui/services/manifest_writer.py` | not targeted — OK |
| `tui/services/manifest_writer.py` (NEW) | (a) behavioral-placeholder | `rg -n "deferred|placeholder|not.yet|NotImplemented" tests/` — no placeholder guard names a manifest-writer (read-only-today is a doc statement, not a guarded placeholder) | no placeholder to supersede — OK |
| `tui/services/manifest_writer.py` (NEW) | no-textual import graph | `test_no_textual_in_static_import_graph` roots = {`changes.check`, `services.change_service`} (`test_checks_engine.py:416`); new module only walked if reachable from those roots. Designed headless regardless (LLR-004.3). | OK if headless; add root if needed |
| `tui/app.py` (EDIT) | (d) engine-frozen | `app.py` ∉ `_ENGINE_PATHS` | NOT frozen — OK |
| `tui/app.py` (EDIT) | AST/structure guards on app.py | `test_tui_directionb.py` greps app.py source for several composition invariants — an editor must re-run the suite at the gate | gate-confirm at increment |
| `tests/test_manifest_*.py` (NEW) | none | new test files add nodes; no guard forbids new test files | OK |

**New-symbol-into-existing-file probe (A-3):** the only EXISTING file edited with new *symbols* is `app.py` (a pipeline call) — `app.py` is NOT frozen (`git diff --name-only main -- <frozen set>` returned empty 2026-06-14; `app.py` ∉ frozen set). No new symbol is added to any frozen module. **No planned new symbol targets a frozen/allowlisted file.**

**Completeness note (A-2):** this census ran the four named families change-first plus the no-textual graph guard. It is **NOT stamped complete** — an (N+1)th structural guard could exist that no listed pattern surfaces. The verdict is **"best-effort + gate-confirmed"**: the I-gate running the actual edited files against the full 816-node suite is the completeness guarantee.

### 6.4 Phase-1 reconciliation log

**Phase-1 ITERATION 2 (2026-06-15) — applying the Phase-2 fix register (B-1, M-1/M-2, M-3, m-1..m-7).** The initial draft had no reconciliation change; this iteration edits statements/thresholds and adds one LLR, so the per-decision audit table below is mandatory (parent-HLR re-read rule). Body-first ordering observed: every §3/§4 body edit landed BEFORE its audit row was written; each "Body edit landed?" cell points at a line that now exists.

| Decision ID | What changed | Parent HLR re-read? (which HLR + what changed, or "no change required" + why) | Body edit landed? (§3/§4 line) |
|-------------|--------------|------------------------------------------------------------------------------|--------------------------------|
| J-1 (B-1) | Pinned ONE canonical comparison representation (intent resolved against `project_root` via `_resolve_manifest_entry`; `active_variant` raw string) and made every equality threshold inherit it. | HLR-001 re-read: its threshold now names the canonical form; the HLR Statement's "without producing any `ValidationIssue`" is unchanged (the comparison form is a threshold-level clarification, not a new normative response). HLR-003 re-read: LLR-003.1 (its decomposition) inherits the same form; HLR-003 Statement "compare ... against the intended composition" unchanged in intent, sharpened in the LLR. | C-1 (§2.4) canonical-form clause; glossary "Canonical comparison form (C-1)" (§1.3); HLR-001 Numeric pass threshold (§3); LLR-001.3 Statement + verification + threshold (§4); LLR-003.1 Statement + threshold (§4). |
| J-2 (M-1+M-2) | Retired the `copy_into_workarea`-dedup placement; LOCKED stage→containment-checks→atomic `os.replace` at the fixed name as the 7th gate decision; fixed the two-saves-one-file threshold; verify re-reads by canonical fixed name. | HLR-002 re-read: Statement says "place `project.json` only inside `.s19tool/workarea/<project>/` using the existing `copy_into_workarea` containment discipline" — re-read and judged STILL TRUE under the fix (the containment CHECKS of `copy_into_workarea` are reused; only its dedup placement body is not), so no HLR Statement edit required; the binding "contained + collect-don't-abort" response is unchanged. HLR-003 re-read: re-read-by-canonical-name strengthens "re-read `project.json`" without changing the HLR response. | LLR-002.1 (retitled + Statement + verification + threshold + AC); LLR-002.2 (Statement + verification + threshold + AC); LLR-002.3 (Statement symbol alignment); LLR-003.1 (canonical-name re-read); D-3 (§6.2 locked mechanism); §6.3.2 item 7 (locked); R-3 (§6.3.1 rewrite); §1.2 scope bullet. |
| J-3 (M-3) | Added NEW LLR-001.5: serializer REFUSES absolute / project-escaping entries up front (return `(None, finding)`, write nothing), reusing the reader's rejection predicate; added TC-001e. | HLR-001 re-read: this is a NEW decomposed LLR under HLR-001. HLR-001 Statement says the system "shall serialize ... into a JSON object whose key set and value shapes are exactly those that `read_project_manifest` parses back without producing any `ValidationIssue`" — re-read and judged to ALREADY entail refusing entries the reader would flag (an entry that produces a `MANIFEST-PATH-ESCAPE` issue violates "parses back without any ValidationIssue"); LLR-001.5 makes that entailment an explicit input gate, so no HLR Statement edit required (consistent decomposition, not a new HLR response). | LLR-001.5 (§4, NEW, full statement/verification/threshold/AC); §5.2 coverage row LLR-001.5 → TC-001e; §1.5 overview (14 LLRs). |
| J-4 (M-3 contract-touch) | C-9 manifest-contract identity re-run because M-3 touched a producer LLR. | No HLR threshold change. Contract-touch rule, not parent-HLR rule: LLR-001.5 adds no envelope key → producer 4 == consumer 4, no drift. | §6.2.1 "Contract-touch re-run (Phase-1 iteration, 2026-06-15)" paragraph. |
| J-5 (count) | LLR count 13 → 14 (LLR-001.5 added); signed-balance additions 12–16 → 13–17; predicted post-collection 828–832 → 829–833. | No HLR threshold change (an LLR was ADDED, not a threshold relaxed). The added-LLR branch of the parent-HLR re-read rule is discharged by J-3's HLR-001 re-read (the LLR's parent). | §1.5 overview (14 LLRs); §5.2 coverage table (LLR-001.5 row); §5.3.1 additions + signed balance. |
| J-6 (minors m-1..m-7) | Citation/spelling/AC alignments: m-1 `models.py:101`→`:102` (2 line-numbered sites); m-2 resolution anchors `:235`/`:290` on contract rows; m-3 `MF_WRITE_CONTAINMENT` (`io.py:1248`); m-4 size-cap-is-an-issue note; m-5 plain-text issue rendering; m-6 no-logging LLR/AC + probe; m-7 stdlib-`json`-encoder promoted to LLR-001.1 Statement. | No HLR threshold or Statement change (minors are sub-LLR citation/AC corrections). No parent-HLR re-read required. | LLR-001.1 (m-1, m-7); §6.2.1 contract table (m-1, m-2); LLR-002.3 (m-3); LLR-003.3 AC (m-4); LLR-004.2 AC (m-5); LLR-004.3 Statement + threshold + AC (m-6). |

**Contract-touch checklist row:** M-3's producer-LLR edit re-opened the C-9 manifest contract; the identity re-run (4 == 4, no key added) is recorded in §6.2.1 and as J-4 above (body-first: the §6.2.1 re-run paragraph landed before this row).

#### 6.4.1 Phase-3 increment plan sketch (≤5 files each)
- **I1 — Serializer + refusal gate (HLR-001).** NEW `tui/services/manifest_writer.py` (`serialize_manifest`, refusal predicate reusing `_resolve_manifest_entry` semantics) + `tests/test_manifest_writer.py` (TC-001a..e, incl. TC-001e the LLR-001.5 refusal). Round-trip against `read_project_manifest`. (2 files)
- **I2 — Contained write (HLR-002).** Extend `manifest_writer.py` (`write_project_manifest`, `MANIFEST_WRITE_CONTAINMENT`) + write tests in `test_manifest_writer.py` (TC-002a..c). Stage to `temp/` → reuse `copy_into_workarea` containment CHECKS (`workspace.py:278`–`:291`) → atomic `os.replace` at the fixed name (D-3 locked); NOT the dedup body. (1-2 files)
- **I3 — Verify-on-write (HLR-003).** Extend `manifest_writer.py` (`verify_written_manifest`, `ManifestVerifyResult`, status constants) + NEW `tests/test_manifest_verify.py` (TC-003a..c). (2 files)
- **I4 — TUI surface (HLR-004).** EDIT `app.py` save handler + verify surfacing; possible `services/__init__.py` export; `REQUIREMENTS.md` traceability. Demo TC-D1 + inspection TC-004a + textual-graph TC-004b. (≤3 files)

### 6.5 `shall`/`should` self-check (re-run at Phase-1 ITERATION 2, 2026-06-15)
Executed `rg -n "\bshould\b"` over the whole doc after the fix-register edits: **0 occurrences of `should` inside any §3/§4 HLR/LLR Statement** (the 6 hits are all in the normative header rationale and in this §6.5 note — permitted informative prose). All normative statements (incl. the NEW LLR-001.5) use `shall`. Mojibake re-check (the double-encoded em-dash sentinel) returns 0 outside this self-check note; file written UTF-8 no-BOM. Count consistency re-checked: §1.5 / §5.2 coverage table / §5.3.1 all reflect 4 HLR + 14 LLR. Self-check: PASS.
