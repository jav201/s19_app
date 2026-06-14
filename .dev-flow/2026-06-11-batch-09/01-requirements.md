# Requirements Document — s19_app — Batch 2026-06-11-batch-09

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

---

## 1. Introduction

### 1.1 Purpose
This document specifies the requirements for batch **2026-06-11-batch-09** of `s19_app`: the **image comparison mode (US-006)** — a diff of two HEX/S19 images (in-project variants and/or external files), with per-image artifact-usage notes against the project's shared A2L/MAC, a complete diff report in two formats (Markdown + self-contained HTML), and the completion of the existing A↔B Diff rail placeholder screen.

### 1.2 Scope
**In scope:**
- A headless byte-run diff engine over two sparse memory maps (`Dict[int, int]`), classifying differing addresses into contiguous runs (`changed` / `only-in-A` / `only-in-B`) with summary statistics.
- A headless comparison service that loads two images by fresh parse — in-project variants from `ProjectVariantSet` and/or external files via `resolve_input_path` — and assembles a self-contained comparison result.
- Per-image artifact-usage notes against the active project's (at most one) A2L and (at most one) MAC: mechanical coverage counts and a `both / one / none` summary.
- A complete **diff report** in two formats — Markdown and self-contained HTML — written into the existing project `reports/` directory, reusing the batch-07 report conventions for naming (UTC timestamp filename, collision counter, plain hex renderer) and listed by the existing `ReportViewerScreen`. The persisted files are COMPLETE (no byte budget / TRUNCATED markers on the file — those caps are relocated to the TUI display path, G-9); changed runs carry a format-appropriate visual cue (Markdown ```diff, HTML inline-CSS colour).
- Completion of the A↔B Diff screen: replacing the static `AbDiffPanel` placeholder (`screens_directionb.py:849`) with real comparison output (run list + bounded hex windows for A and B) and a comparison-request flow.

**Out of scope (registered, not silently dropped):**
- **N-way (N>2) comparison.** Feasibility finding in §6.2 D-1 — feasible at the engine level, deferred for surface cost. The US-006 "N-way if feasible" clause is answered, not ignored.
- Side-by-side synchronized-scroll visual diff in the TUI (the report is the authoritative deliverable; the TUI shows the run list + per-run bounded windows).
- HEX save-back, editing, or patching from the diff screen (read-only mode).
- Comparison of MAC/A2L artifacts themselves (only S19/HEX images are compared; artifacts provide annotation context).

### 1.3 Definitions, acronyms, abbreviations
| Term | Definition |
|------|------------|
| Image | One S19 or Intel HEX firmware file, parsed to a sparse `Dict[int, int]` memory map (`models.py:9` `LoadedFile.mem_map`). |
| Run | A maximal contiguous half-open address range `[start, end)` whose every address has the same diff classification. |
| Classification | One of `changed` (present in both, byte differs), `only_a` (mapped in A only), `only_b` (mapped in B only). Addresses present in both with equal bytes produce no run. |
| Artifact context | The active project's at-most-one A2L and at-most-one MAC (cardinality enforced by `validate_project_files`, `workspace.py:321`). |
| Artifact-usage note | Per (image, artifact): the count of artifact addresses falling inside the image's mapped ranges, plus the derived `used`/`unused`/`absent` status (§6.2 D-3). |
| Diff report | The complete artifact pair (Markdown + self-contained HTML, G-9) written under `<project>/reports/` (or the no-project operator destination, LLR-004.6), sibling of the batch-07 project report. |
| In-project variant | An S19/HEX image enumerated by `ProjectVariantSet` (`models.py:81`). |
| External image | An image resolved from an operator-typed path via `resolve_input_path` (`workspace.py:469`). |

### 1.4 References
- `CLAUDE.md` (architecture map; severity/colour conventions).
- `REQUIREMENTS.md` (R-* traceability registry — to be updated at Phase 6).
- Batch-07 artifacts: multi-variant model (LLR-005.x), variant execution (LLR-006.x), project report (LLR-007.x), report viewer (LLR-008.x).
- Batch-08 artifacts: operations module conventions; post-mortem rules A-3 (provisional node ids), A-4/V-2 (behavior+service-route in LLRs, UI mechanisms in ACs), B-1 (AC-artifact citation), B-2 (probe regime).
- Persistent memory `project_us006_hex_compare_mode.md` (story registration; the `screens_directionb.py:~1334` anchor recorded there is **stale** — re-verified at `:849`, probe P-06).

### 1.5 Document overview
§2 describes the product context and the source user story. §3 holds 5 HLRs; §4 decomposes them into 26 LLRs (24 at draft + LLR-004.6 added at Phase-1 iteration 2, G-5 + LLR-004.7 added at Phase-1 iteration 4, G-9; heading count re-verified by `grep -n '### LLR-'` → 26 = 5+6+4+7+4). §5 defines the validation strategy and coverage. §6 records design decisions (D-1..D-8), the C-9 result contract, risks (R-1..R-10), gate-confirmables (G-1..G-9), the probe ledger, and the reconciliation log (§6.4, populated at iterations 2-4).

---

## 2. Overall description

### 2.1 Product perspective
`s19tool` already has every ingredient of a comparison mode except the comparison itself:

- **Surface exists:** the activity rail carries a `diff` entry (`rail.py:85` — `RailEntry("diff", "⏚", "D", "A2B Diff")`, one of the 8 entries at `rail.py:78`; **no new rail entry is needed**). It routes via `SCREEN_CONTAINER_IDS["diff"] = "screen_diff"` (`app.py:2421`) through `action_show_screen` (`app.py:2473`) to `_compose_screen_diff` (`app.py:1868`), which mounts `AbDiffPanel` (`screens_directionb.py:849`) — today a static three-column placeholder (`#diff_range_list` / `#diff_hex_a` / `#diff_hex_b`, `screens_directionb.py:935-937`) with a visible deferral notice (`DEFERRAL_TEXT`, `screens_directionb.py:882`). Batch-04's LLR-012.3/012.4 (placeholder-only) are **superseded** by this batch.
- **Candidates exist:** batch-07's multi-variant model enumerates in-project images (`ProjectVariantSet`, `models.py:81`; `build_variant_set`, `workspace.py:376`); external files resolve via `resolve_input_path` (`workspace.py:469`).
- **Headless-load precedent exists:** `_execute_one_variant` (`variant_execution_service.py:608`) parses images fresh via `build_loaded_s19`/`build_loaded_hex` (`load_service.py:17`/`:44`, used at `variant_execution_service.py:671-678`) without touching the TUI snapshot.
- **Membership primitive exists:** `build_sorted_range_index` / `address_in_sorted_ranges` (`range_index.py:9`/`:39`).
- **Report infrastructure exists:** `report_service.py` (dir `REPORTS_DIR_NAME` `:110`, filename regex `:106`, collision counter `_report_filename` `:355`, byte budget `REPORT_MAX_TOTAL_BYTES` `:79`, window math `compute_hexdump_windows` `:232`, plain renderer `render_hex_view` `hexview.py:294`) and `ReportViewerScreen` (`screens.py:285`).

What does **not** exist anywhere: run-extraction diff logic. Probe P-08: every `mem_map ==` in `tests/` (11 hits) is whole-map equality — the engine is genuinely new.

### 2.2 Product functions
1. Compare two images (project variant and/or external file) into classified byte runs + statistics.
2. Annotate each image with artifact-usage notes against the project's A2L/MAC (`both / one / none` + coverage counts).
3. Generate a complete diff report in two formats (Markdown + self-contained HTML) under the project's `reports/` directory, listed in the existing report viewer.
4. Display the comparison in the A↔B Diff screen: run list, per-run bounded hex windows for A and B, status/diagnostics.

### 2.3 User characteristics
Single role: the **s19tool operator** (firmware/calibration engineer), keyboard-driven TUI user, familiar with hex dumps, S19/HEX records, and A2L/MAC symbol files. No permission tiers.

### 2.4 Constraints
- Python 3.11 / pytest (CI `tui-ci.yml` runs `pytest -q`); Textual for TUI; no new runtime dependencies.
- Engine and services import no Textual (batch-07/08 layering precedent); view code consumes services only.
- Rendering caps are binding for the TUI DISPLAY path: `MAX_HEX_BYTES=65536`, `HEX_WIDTH=16`, `FOCUS_CONTEXT_ROWS=64`, `MAX_HEX_ROWS=512` (`hexview.py:19-22`); the display run-dump budget `REPORT_MAX_TOTAL_BYTES=2_097_152` (`report_service.py:79`) bounds the on-screen diff (LLR-005.2), NOT the persisted report files, which are complete (G-9).
- Confidentiality (F-S-07 precedent, `report_service.py:32-36`): diff reports carry raw memory bytes — written only under the gitignored `.s19tool/` tree, no logging of report body.
- Workflow: ≤5 files per increment; supervised gates.

### 2.5 Assumptions and dependencies
- A-1: The batch-07 multi-variant + report stack (LLR-005/006/007/008) is merged and stable on this branch (verified: all cited symbols grep-hit, probe ledger §6.5).
- A-2: At most one A2L and one MAC per project (`validate_project_files`, `workspace.py:321`) — the artifact-context definition (D-3) depends on this cardinality. If a future batch relaxes it, HLR-003 must be revisited.
- A-3: `examples/` contains **zero** `.hex` files (probe P-03, executed) — every HEX-image test uses synthetic in-memory fixtures or a `NEW` fixture counted in the increment budget; no AC names a real `.hex` example file.
- A-4: Memory maps of realistic images fit comfortably in RAM two-at-a-time (the variant-execution layer already holds one full map per variant sequentially; `make_large_s19`, `tests/conftest.py:70`, is the stress regime).

### 2.6 Source user stories

> Connextra format: **"As a `<role>`, I want `<goal>`, so that `<benefit>`"**.
> Each US gets a unique ID `US-NNN` and must be traceable to one or more HLRs.

| ID | User Story | Source |
|----|------------|--------|
| US-006 | As an s19tool operator, I want a comparison mode for two or more HEX/S19 images — whether they belong to the current project or are external files — that share (or are checked against) the same A2L/MAC artifacts, with an explicit note of which artifacts each image uses (both / one / none), generating a diff report of the differences between the images; N-way comparison if feasible. | Operator, registered 2026-06-10 at the batch-07 Phase-1 gate (persistent memory `project_us006_hex_compare_mode.md`); selected as batch-09 scope 2026-06-11 ("Adelante con la opción B"). Natural surface candidate noted at registration: the A↔B Diff rail placeholder (`screens_directionb.py`, anchor re-verified at draft: `AbDiffPanel` at `:849`, NOT `~:1334` — the memory anchor was stale, probe P-06). |

> **Numbering note (informative):** US-006 was reserved for this story when batch-08 took US-007 (placeholder operations). The reservation is now consumed; numbering stays consistent with the registration order.

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

### HLR-001 — Byte-run comparison engine
- **Traceability:** US-006
- **Statement:** When given two sparse memory maps, the system shall compute the complete, deterministic set of maximal contiguous difference runs — each classified as `changed`, `only_a`, or `only_b` — together with per-classification run and byte counts, in a headless module importable without Textual.
- **Rationale (informative):** The diff is the core deliverable; every downstream surface (report, TUI) consumes the same engine output. Headlessness follows the `range_index.py` / batch-07-engine precedent.
- **Validation:** test
- **Executed verification:** `pytest tests/test_compare_engine.py -q` (implemented in Phase 3; 11 tests collect — node ids reconciled to the real implemented set in the LLR-001.x lines below). [Phase-6 reconciliation per 04-validation DEV-2: provisional framing resolved against the implemented node ids.]
- **Numeric pass threshold:** exit code 0; 0 failures across TC-001..TC-006
- **Priority:** high

### HLR-002 — Comparison sources and service seam
- **Traceability:** US-006
- **Statement:** When the operator requests a comparison naming two images — each either an in-project variant or an external file path — the system shall load each image by a fresh headless parse and assemble a self-contained comparison result through a service layer, never reusing the TUI's current `LoadedFile` snapshot and never raising an unhandled exception for an unresolvable path or a failed parse.
- **Rationale (informative):** Mirrors the batch-07 E6 execution layer (`_execute_one_variant`, `variant_execution_service.py:608`): fresh parse, error isolation, service seam consumed by the view.
- **Validation:** test
- **Executed verification:** `pytest tests/test_compare_service.py -q` (implemented in Phase 3; 12 tests collect — node ids reconciled in the LLR-002.x lines below). [Phase-6 reconciliation per 04-validation DEV-2: provisional framing resolved against the implemented node ids.]
- **Numeric pass threshold:** exit code 0; 0 failures across TC-007..TC-011
- **Priority:** high

### HLR-003 — Artifact-usage notes
- **Traceability:** US-006
- **Statement:** When a comparison result is assembled while a project supplies an artifact context (at most one A2L and at most one MAC), the system shall record, for each compared image and each artifact, the mechanical coverage count (artifact addresses falling inside the image's mapped ranges) and a derived per-image usage summary of `both`, `one (a2l)`, `one (mac)`, or `none`; if no artifact context exists, then the system shall record every artifact status as `absent` and the summary as `none` without failing.
- **Rationale (informative):** The story demands an "explicit note of which artifacts each image uses". §6.2 D-3 defines the minimal mechanical semantics (coverage ≥ 1 ⇒ used) and flags alternatives gate-confirmable.
- **Validation:** test
- **Executed verification:** `pytest tests/test_compare_service.py -q -k "artifact_context or coverage or usage_summary or absent"` (TC-012..TC-015 co-located in `tests/test_compare_service.py`). [Phase-6 reconciliation per 04-validation DEV-2: provisional `-k artifact` replaced with the real node-id selector for the artifact-note TCs.]
- **Numeric pass threshold:** exit code 0; 0 failures across TC-012..TC-015
- **Priority:** high

### HLR-004 — Diff report (Markdown + HTML)
- **Traceability:** US-006
- **Statement:** When the operator requests a diff report for a completed comparison, the system shall write a complete diff report in two output formats — one Markdown file and one self-contained HTML file — following the batch-07 report conventions for naming and destination (UTC-timestamp filename with collision counter and no silent overwrite, plain-string hex renderer), each written file containing the COMPLETE comparison with no run cap, no byte truncation, and no `TRUNCATED` markers in the file; each file shall contain the image identities and sources, the artifact-usage notes, the run statistics, the classified run table with best-effort symbol annotation, and bounded hex windows from both images, with changed runs rendered using a format-appropriate visual cue (Markdown fenced ```diff blocks with A bytes as `-` lines and B bytes as `+` lines; HTML inline-CSS colour distinguishing changed / only-A / only-B); the HTML file shall be self-contained with inline CSS only, every embedded value escaped via `html.escape`, and no `<script>`, external resource, font, CDN, or network reference; resolving the destination as follows: while a project is active, into that project's existing `reports/` directory; while no project is active, into an operator-supplied destination directory (there is no implicit default — G-8); and the system shall, before any write to an operator-supplied destination, normalize and validate that directory and write no file if validation fails.
- **Rationale (informative):** Reuse over reinvention (§6.2 D-5): the `reports/` dir, naming, window math and the viewer already exist (`report_service.py`, `screens.py:285`). G-9 (operator, at the I3 gate 2026-06-12, BINDING) corrects an earlier framing error: the PERSISTED report is the authoritative deliverable and must be COMPLETE — the batch-07 caps (`REPORT_MAX_TOTAL_BYTES`, the per-report run-dump cap) were wrongly treating the FILE as bounded; they are RE-LOCATED to the TUI DISPLAY render path only (I4 / LLR-005.x), bounding what the screen shows, never what is written. Both exports therefore carry human-factors visual cues (Markdown fenced ```diff for GitHub/VS Code/Obsidian red-green rendering, degrading to plain text elsewhere; HTML inline-CSS colour) because not every operator opens HTML. The HTML export is a SECOND output format of the same `ComparisonResult` (C-9 unchanged) and is hardened against content injection (`html.escape` on all embedded addresses/bytes/paths; no `<script>`/external resource/CDN/network). PDF is DROPPED from scope (dormant note: if ever revived use `fpdf2`, not weasyprint). G-5 (operator, 2026-06-11) overturns the original refusal: the no-project case now resolves a destination. G-8 (operator, 2026-06-11, BINDING) sharpens this to **solo-prompt — no implicit Downloads default**: the operator is always prompted, and an empty/invalid/non-existent-directory path is REFUSED (no file written). Because that path can lie OUTSIDE the gitignored `.s19tool/` tree, the write is gated by directory validation (LLR-004.6, normalize-via-`resolve()` → require existing dir → tool-generated filename) and tracked by risk R-9 for the Phase-2 security-reviewer.
- **Validation:** test
- **Executed verification:** `pytest tests/test_diff_report_service.py -q` (the report-test file was implemented as `tests/test_diff_report_service.py`, matching the `_service` module-under-test naming convention; 20 tests collect). [Phase-6 reconciliation per 04-validation DEV-1: `test_diff_report.py` → `test_diff_report_service.py`, grep-verified on disk; the old filename does not exist.]
- **Numeric pass threshold:** exit code 0; 0 failures across TC-016..TC-020, TC-025, TC-026..TC-028 (complete-export, Markdown ```diff cue, HTML complete+safe)
- **Priority:** high

### HLR-005 — A↔B Diff screen completion
- **Traceability:** US-006
- **Statement:** When a comparison completes, the A↔B Diff screen shall replace its static placeholder content with the real comparison output — the classified run list and, for a selected run, bounded hex windows of image A and image B — routing all comparison and report computation exclusively through the service layer; if a comparison request fails (unresolvable path, parse failure, fewer than two valid images), then the system shall surface the failure in the status line and keep running.
- **Rationale (informative):** Completes the existing surface (rail entry `rail.py:85`, container routing `app.py:2421`, panel `screens_directionb.py:849`) instead of adding a new one. Per the batch-08 A-4/V-2 lesson, LLR statements pin behavior + service route; concrete UI mechanisms live in acceptance criteria flagged `assumed — verify in Phase 3`.
- **Validation:** test + demo
- **Executed verification:** `pytest tests/test_tui_diff_screen.py -q` (implemented in Phase 3; 6 tests collect — node ids reconciled in the LLR-005.x lines below). [Phase-6 reconciliation per 04-validation DEV-2: provisional framing resolved against the implemented node ids.]
- **Numeric pass threshold:** exit code 0; 0 failures across TC-021..TC-024, TC-029 (relocated display-cap truncation, G-9)
- **Priority:** high

---

## 4. Low-level requirements (LLR)

> Each LLR decomposes an HLR into a verifiable property at the implementation level.
> Same EARS regime. ID format: `LLR-<HLR>.<M>`.

### LLR-001.1 — Engine module purity
- **Traceability:** HLR-001
- **Statement:** The comparison engine module `s19_app/compare.py` (`NEW — created in Phase 3`) shall import neither Textual nor any parser class (`S19File`, `core.py`; `IntelHexFile`, `hexfile.py`), consuming only already-built memory maps.
- **Validation:** inspection
- **Executed verification:** `rg -c "import textual|from textual|Textual|S19File|IntelHexFile" s19_app/compare.py` after Phase 3. Probe P-10 executed at draft on the in-regime stand-in `s19_app/range_index.py` (same regime: package-root headless module) → 0 hits; positive control: same pattern on `s19_app/tui/screens_directionb.py` → hits (`from textual...` at `:47-48`). [Phase-6 reconciliation per 04-validation DEV-5 (V-4 fix): the bare substring `textual` is tightened to `import textual|from textual|Textual` so the probe cannot match the word "textual" appearing in prose/comments — Phase-4 §2.1 showed the bare substring yielded a false-positive prose hit in `diff_report_service.py`.]
- **Numeric pass threshold:** 0 hits.
- **Acceptance criteria (informative):**
  - Module sits at package root beside `range_index.py` (the layering precedent).

### LLR-001.2 — Run classification and merging
- **Traceability:** HLR-001
- **Statement:** The engine's diff function (`diff_mem_maps`, `NEW — created in Phase 3`) shall emit, for two memory maps A and B, half-open runs ordered by ascending start address such that: every address mapped in both with differing bytes lies in exactly one `changed` run; every address mapped only in A lies in exactly one `only_a` run; every address mapped only in B lies in exactly one `only_b` run; no address mapped in both with equal bytes lies in any run; and two adjacent addresses share a run if and only if they have the same classification.
- **Validation:** test (unit)
- **Executed verification:** `pytest tests/test_compare_engine.py -q -k "classification or adjacency or boundary"` — TC-001 (`test_classification_set_equality`, `test_classification_set_equality_random`), TC-002 (`test_adjacency_merge_same_kind_merges`, `test_adjacency_change_forces_boundary`), TC-003 (`test_boundary_cases`). [Phase-6 reconciliation per 04-validation DEV-2: provisional `-k "classification or merge"` replaced with the real node-id selector from 04-validation §1.]
- **Numeric pass threshold:** exit code 0; for each fixture, reconstructed per-address classification from runs equals the brute-force per-address classification (set equality, 0 mismatches).
- **Acceptance criteria:**
  - **Per-TC property ownership (m-4 — each TC owns a distinct property so Phase 3 cannot collapse three into one assertion):**
    - **TC-001 — classification set-equality:** the per-address classification reconstructed from the emitted runs equals the brute-force per-address classification (set equality, 0 mismatches).
    - **TC-002 — adjacency-merge:** two adjacent addresses share a run iff they have the same classification (asserts both directions: same-kind adjacency merges into one run; a classification change forces a run boundary).
    - **TC-003 — boundary cases:** run at address 0; touching runs of different kinds; single-byte runs; interleaved gaps.
  - Fixtures are synthetic in-memory dicts (no file artifacts needed).

### LLR-001.3 — Determinism and identity
- **Traceability:** HLR-001
- **Statement:** The engine shall return an empty run list when both maps are identical (including both empty), and shall return identical output for repeated calls over the same inputs.
- **Validation:** test (unit)
- **Executed verification:** `pytest tests/test_compare_engine.py -q -k "identity or determinism"` — TC-004 (`test_identity_empty_and_equal`, `test_determinism_repeated_calls`). [Phase-6 reconciliation per 04-validation DEV-2: provisional selector confirmed to match the real node ids; no rename needed.]
- **Numeric pass threshold:** exit code 0; identical-input double-call outputs compare equal (`==`), identity case yields exactly 0 runs.

### LLR-001.4 — Statistics consistency
- **Traceability:** HLR-001
- **Statement:** The engine shall emit per-classification statistics (run count and byte count for each of `changed`, `only_a`, `only_b`) such that each byte count equals the sum of the lengths of that classification's runs.
- **Validation:** test (unit)
- **Executed verification:** `pytest tests/test_compare_engine.py -q -k "stats or symmetry"` — TC-005 (`test_stats_byte_count_equals_run_lengths`, `test_stats_run_counts_match`, `test_symmetry_swap_only_a_only_b`). [Phase-6 reconciliation per 04-validation DEV-2: provisional `-k stats` widened to the real node-id selector (the symmetry test also lands under TC-005 per 04-validation §1).]
- **Numeric pass threshold:** exit code 0; for every fixture, `byte_count[kind] == sum(end - start for runs of kind)` with 0 mismatches.

### LLR-001.5 — Large-image performance
- **Traceability:** HLR-001
- **Statement:** The engine shall complete a diff of two large-fixture-sized memory maps (maps derived from `make_large_s19`, `tests/conftest.py:70`, with a mutated copy) within the slow-marker smoke budget.
- **Validation:** test (slow)
- **Executed verification:** `pytest tests/test_compare_engine.py -q -k large_image_perf` — TC-006 (`test_large_image_perf`, carrying `@pytest.mark.slow`). [Phase-6 reconciliation per 04-validation DEV-4: TC-006 was validated IN-FILE (file-scoped run, MEASURED 1.39s < 2.0s budget), NOT via the spec's provisional `-m slow -k large` selection — the `@pytest.mark.slow` marker is honoured only when an `-m` filter is applied at suite level, so the file-scoped run collects and runs it directly. CI slow-suite (ubuntu/Python 3.11) timing remains the orchestrator's confirmation.] Registered under the `slow` marker per `pyproject.toml` convention.
- **Numeric pass threshold:** diff compute (excluding parse) on the default `make_large_s19` pair completes in ≤ 2.0 s. Grounding: MEASURED 2026-06-11 (probe P-15) — full key-union classify walk 201.7 ms + dict-eq 9.1 ms + sort 4.7 ms on 819,206 mapped bytes per image (regime: Win 11 Pro 10.0.26200, Python 3.14.4, OneDrive-synced worktree, single run, `perf_counter`); the 2.0 s budget is ~10× headroom. CI-regime validity flagged `assumed — verify per-regime` (CI = ubuntu/Python 3.11): confirmed at Phase 4 from the slow-suite timing. The test carries `@pytest.mark.slow` because it parses 2 large files end-to-end (parse dominates: ~165-172 ms/file measured, same probe).
- **Acceptance criteria:**
  - Fixture: `make_large_s19` generator output (probe: symbol grep-verified at `tests/conftest.py:70`, executed 2026-06-11) — reused, not a new ad-hoc builder.

### LLR-002.1 — Service module purity and seam
- **Traceability:** HLR-002
- **Statement:** The comparison service module `s19_app/tui/services/compare_service.py` (`NEW — created in Phase 3`) shall import no Textual symbol and shall expose the comparison entry point as an injectable function consumed by the app, following the `load_service`/`variant_execution_service` seam pattern (`load_service.py:17`, `variant_execution_service.py:608`).
- **Validation:** inspection
- **Executed verification:** `rg -c "import textual|from textual|Textual" s19_app/tui/services/compare_service.py` after Phase 3. In-regime pre-state control (probe P-11 regime: `s19_app/tui/services/` module file): `rg -c "import textual|from textual|Textual" s19_app/tui/services/report_service.py` → 0 executed 2026-06-11; positive control `rg -n "from textual" s19_app/tui/screens_directionb.py` → hits at `:47-48`. [Phase-6 reconciliation per 04-validation DEV-5 (V-4 fix): the bare substring `textual` is tightened to `import textual|from textual|Textual` so the probe matches only real imports/usages, not the word "textual" in a prose comment — Phase-4 §2.1 recorded that `diff_report_service.py` returned a benign prose false-positive under the bare substring.]
- **Numeric pass threshold:** 0 hits.

### LLR-002.2 — Fresh parse of in-project variants
- **Traceability:** HLR-002
- **Statement:** When a comparison names an in-project variant, the service shall resolve it through the project's `ProjectVariantSet` (`models.py:81`) and parse its image fresh via `build_loaded_s19` / `build_loaded_hex` (`load_service.py:17`/`:44`), discriminated by `VariantDescriptor.file_type` (`models.py:77` — the field declaration; `:56` is the class line, re-cited per m-1), never reading the TUI's current snapshot.
- **Validation:** test (integration)
- **Executed verification:** `pytest tests/test_compare_service.py -q -k "variant_pair"` — TC-007 (`test_variant_pair_matches_engine`, `test_variant_pair_reports_real_diff`). [Phase-6 reconciliation per 04-validation DEV-2: provisional `-k variant` replaced with the real `-k variant_pair` node-id selector.]
- **Numeric pass threshold:** exit code 0; comparing two project variants yields run output equal to the engine's output over independently-parsed maps (0 mismatches).
- **Acceptance criteria:**
  - Fixture: a temp project directory holding two S19 variants built from example content (existence probe P-12 executed 2026-06-11: `examples/case_00_public/` contains `prg.s19` + `s19_sample.s19`, two S19 images in one directory; `Glob examples/**/*.s19` → 16 files, probe P-02).

### LLR-002.3 — External path resolution
- **Traceability:** HLR-002
- **Statement:** When a comparison names an external file path, the service shall resolve it via `resolve_input_path` (`workspace.py:469`); if resolution returns `None`, then the service shall return a refused comparison carrying an explicit diagnostic naming the unresolved input, raising no exception.
- **Validation:** test (unit)
- **Executed verification:** `pytest tests/test_compare_service.py -q -k "external"` — TC-008 (`test_external_unresolvable_returns_refused`, `test_external_resolved_pair`). [Phase-6 reconciliation per 04-validation DEV-2: provisional `-k external` confirmed to match the real node ids.]
- **Numeric pass threshold:** exit code 0; unresolvable-path case returns a result object (not an exception) with ≥ 1 diagnostic containing the input string.

### LLR-002.4 — Mixed sources
- **Traceability:** HLR-002
- **Statement:** The service shall accept any pairing of sources — variant + variant, variant + external, external + external — and record each image's source kind and identity (path; `variant_id` when in-project) in the comparison result.
- **Validation:** test (integration)
- **Executed verification:** `pytest tests/test_compare_service.py -q -k "mixed_source"` — TC-009 (`test_mixed_source_pairings_record_identity`). [Phase-6 reconciliation per 04-validation DEV-2: provisional `-k mixed` replaced with the real `-k mixed_source` node-id selector.]
- **Numeric pass threshold:** exit code 0; all three pairings produce results whose image metadata fields match the requested sources (0 mismatches).

### LLR-002.5 — Parse-failure isolation
- **Traceability:** HLR-002
- **Statement:** If parsing either image raises an exception, then the service shall capture it as a diagnostic on a refused comparison result and shall not propagate the exception, mirroring the LLR-006.4 isolation boundary (`variant_execution_service.py:729-732`).
- **Validation:** test (unit)
- **Executed verification:** `pytest tests/test_compare_service.py -q -k "parse_failure"` — TC-010 (`test_parse_failure_isolated_to_refused`). [Phase-6 reconciliation per 04-validation DEV-2: provisional `-k parse_failure` confirmed to match the real node id.]
- **Numeric pass threshold:** exit code 0; a deliberately unreadable input yields a refused result with ≥ 1 diagnostic carrying the exception text, and the test observes no raised exception.

### LLR-002.6 — Comparison result contract (C-9)
- **Traceability:** HLR-002
- **Statement:** The service shall return a comparison result object exposing exactly the C-9 canonical field set of §6.2 (image references, runs, statistics, artifact-usage notes, diagnostics, refused flag), with the engine producing `runs`/`stats` and the service producing the remainder.
- **Validation:** test (unit) + inspection
- **Executed verification:** `pytest tests/test_compare_service.py -q -k "c9_contract"` — TC-011 (`test_result_field_set_matches_c9_contract`); inspection of the C-9 table in §6.2 vs the dataclass definitions (Phase-4: `dataclasses.fields == {image_a,image_b,runs,stats,notes,diagnostics,refused}`, 0 missing / 0 extra). [Phase-6 reconciliation per 04-validation DEV-2: provisional `-k contract` replaced with the real `-k c9_contract` node-id selector.]
- **Numeric pass threshold:** exit code 0; field-set equality between the dataclass and the C-9 enumeration (0 missing, 0 extra).

### LLR-003.1 — Artifact context definition
- **Traceability:** HLR-003
- **Statement:** The service shall take the comparison's artifact context exclusively from the active project's artifact files as constrained by `validate_project_files` (`workspace.py:321` — at most one MAC, at most one A2L), applying the same context to every compared image including external ones.
- **Validation:** test (integration)
- **Executed verification:** `pytest tests/test_compare_service.py -q -k "artifact_context"` — TC-012 (`test_artifact_context_applies_to_external`). [Phase-6 reconciliation per 04-validation DEV-2: provisional `-k artifact_context` confirmed to match the real node id.]
- **Numeric pass threshold:** exit code 0; an external image compared inside a project with one A2L+one MAC receives notes for both artifacts (2 of 2 artifacts noted).
- **Acceptance criteria:**
  - Fixture: temp project with one S19 + one A2L + one MAC modeled on `examples/case_01_basic_valid/` (existence probe P-12 executed 2026-06-11: directory holds `firmware.s19`, `firmware.a2l`, `firmware.mac`).

### LLR-003.2 — Coverage computation
- **Traceability:** HLR-003
- **Statement:** For each (image, artifact) pair, the service shall compute the coverage count as the number of artifact records carrying an integer address — MAC records' `record["address"]` (`mac.py:91`), A2L tags' `tag["address"]` from the enriched tags of `enrich_tags_and_render` (`a2l_service.py:10`; address populated at `a2l.py:984`) — that satisfy `address_in_sorted_ranges` (`range_index.py:39`) against the image's range index built by `build_sorted_range_index` (`range_index.py:9`), never by linear scan.
- **Validation:** test (unit)
- **Executed verification:** `pytest tests/test_compare_service.py -q -k "coverage_counts"` — TC-013 (`test_coverage_counts_match_hand_computed`). [Phase-6 reconciliation per 04-validation DEV-2: provisional `-k coverage` replaced with the real `-k coverage_counts` node-id selector.]
- **Numeric pass threshold:** exit code 0; computed counts equal hand-computed expected counts on a fixture with known in-range/out-of-range addresses (0 mismatches).

### LLR-003.3 — Usage summary derivation
- **Traceability:** HLR-003
- **Statement:** The service shall derive each image's usage summary as `both` when both artifacts exist and each has coverage ≥ 1 for that image, `one (a2l)` / `one (mac)` when exactly one artifact satisfies that condition, and `none` otherwise.
- **Validation:** test (unit)
- **Executed verification:** `pytest tests/test_compare_service.py -q -k "usage_summary"` — TC-014 (`test_usage_summary_all_four_outcomes`). [Phase-6 reconciliation per 04-validation DEV-2: provisional `-k usage_summary` confirmed to match the real node id.]
- **Numeric pass threshold:** exit code 0; all four summary outcomes exercised, 4 of 4 produced correctly.

### LLR-003.4 — Absent artifacts
- **Traceability:** HLR-003
- **Statement:** If the project supplies no A2L and/or no MAC (or no project is active), then the service shall record the missing artifact's status as `absent` with no coverage count, derive the summary accordingly, and complete the comparison without error.
- **Validation:** test (unit)
- **Executed verification:** `pytest tests/test_compare_service.py -q -k "absent_artifacts"` — TC-015 (`test_absent_artifacts_summary_none`). [Phase-6 reconciliation per 04-validation DEV-2: provisional `-k absent` replaced with the real `-k absent_artifacts` node-id selector.]
- **Numeric pass threshold:** exit code 0; no-artifact comparison completes with summary `none` and 0 exceptions.

### LLR-004.1 — Report destination and filename
- **Traceability:** HLR-004
- **Statement:** The diff-report generator (`generate_diff_report` in `s19_app/tui/services/diff_report_service.py`, both `NEW — created in Phase 3`) shall write the report into `<project>/reports/` (`REPORTS_DIR_NAME`, `report_service.py:110`, created on demand) under the name `<UTC %Y%m%dT%H%M%SZ>-diff-report.md` (timestamp format `REPORT_TIMESTAMP_FORMAT`, `report_service.py:103`) with the batch-07 collision behavior — zero-padded `-NN` counter, `FileExistsError` after 99, never a silent overwrite (pattern: `_report_filename`, `report_service.py:355`).
- **Validation:** test (unit)
- **Executed verification:** `pytest tests/test_diff_report_service.py -q -k "filename_scheme or collision_never_overwrites"` — TC-016 (`test_filename_scheme_and_same_second_collision`, `test_collision_never_overwrites_existing_file`). [Phase-6 reconciliation per 04-validation DEV-1 + DEV-2: filename renamed and the provisional `-k filename` selector replaced with the real implemented node ids from 04-validation §1.]
- **Numeric pass threshold:** exit code 0; same-second double generation yields two distinct files (base + `-01`), 0 overwrites.

### LLR-004.2 — Diff-report listing (self-contained, no shared-contract edit)
- **Traceability:** HLR-004
- **Statement:** The diff-report module shall own a self-contained newest-first listing of diff reports — a `DIFF_REPORT_FILENAME_REGEX` and a `list_diff_reports` function (both `NEW — created in Phase 3`, in `diff_report_service.py`) matching exactly the `<UTC %Y%m%dT%H%M%SZ>(-NN)?-diff-report.md` scheme of LLR-004.1 — and shall NOT edit `REPORT_FILENAME_REGEX` (`report_service.py:106`) or `list_project_reports` (`report_service.py:398`); existing project-report listing behavior remains byte-for-byte unchanged.
- **Rationale (informative, G-4):** Operator overturned D-5's shared-regex generalization in favour of a separate diff-report listing scheme. Owning the regex inside `diff_report_service` removes the cross-cutting contract touch entirely: the `report_service` regex and its 3 tested consumers (probe P-09) are not modified, so there is no backward-compatibility blast radius to defend.
- **Validation:** test (unit)
- **Executed verification:** `pytest tests/test_diff_report_service.py -q -k "self_contained_listing or report_service_regex_unedited"` — TC-017 (`test_self_contained_listing_newest_first`, `test_report_service_regex_unedited`); plus a NON-edit regression guard `pytest tests/test_report_service.py -q` (14 passed) confirming the unmodified `REPORT_FILENAME_REGEX` still passes (probe P-09 recorded its 3 hits; this run proved they were NOT touched). [Phase-6 reconciliation per 04-validation DEV-1 + DEV-2: filename renamed; provisional `-k listing` replaced with the real node ids.]
- **Numeric pass threshold:** exit code 0 on both files; the diff listing returns diff reports newest-first; `test_report_service.py` passes with 0 changes to its assertions (NON-edit confirmed).
- **Acceptance criteria:**
  - **No contract touch:** the shared `REPORT_FILENAME_REGEX` is NOT edited (G-4); the §6.4 audit records the retired contract edit and the P-09 blast radius now justifies a NON-edit.
  - `DIFF_REPORT_FILENAME_REGEX` is `NEW — created in Phase 3` (no pre-existing symbol; grep would not hit it today).

### LLR-004.3 — Report content (complete Markdown file)
- **Traceability:** HLR-004
- **Statement:** The Markdown diff report file shall contain, in order: a header (both image identities and source kinds, artifact-usage notes, generation UTC instant, tool version), a statistics table (run/byte counts per classification), a run table (start, end, length, classification, best-effort symbol annotation per LLR-004.4), and per-run hex windows for image A and image B rendered through the plain-string `render_hex_view` (`hexview.py:294`) over windows computed by `compute_hexdump_windows` (`report_service.py:232`); each `changed` run shall additionally be rendered as a fenced ```diff block in which image A's bytes appear as `-`-prefixed lines and image B's bytes as `+`-prefixed lines (so the block renders red/green on GitHub/VS Code/Obsidian and degrades to plain text elsewhere); and the written file shall be COMPLETE — every run present, no per-report run cap, no `REPORT_MAX_TOTAL_BYTES` byte truncation, and no `TRUNCATED` marker anywhere in the file. (The batch-07 caps `REPORT_MAX_TOTAL_BYTES` (`report_service.py:79`) and the per-report run-dump cap bound only the TUI DISPLAY render path, relocated to I4 — see LLR-005.2; they never bound this file. G-9, I3 gate.)
- **Validation:** test (integration)
- **Executed verification:** `pytest tests/test_diff_report_service.py -q -k "sections_present or markdown_file_is_complete or changed_run_emits_diff or generation_is_deterministic"` — TC-018 (`test_report_sections_present_in_order`, `test_generation_is_deterministic_fixed_clock`), TC-026 (`test_markdown_file_is_complete_no_truncation`), TC-027 (`test_changed_run_emits_diff_fenced_block`). [Phase-6 reconciliation per 04-validation DEV-1 + DEV-2: filename renamed; provisional `-k "content or markdown"` replaced with the real node ids covering the TC-018/026/027 property split.]
- **Numeric pass threshold:** exit code 0; all four sections present in order (TC-018); each `changed` run emits a ```diff fenced block carrying ≥ 1 `-` line and ≥ 1 `+` line (TC-027); the rendered file for a large planted-diff fixture contains 0 `TRUNCATED` markers and every planted run is present (TC-026).
- **Acceptance criteria:**
  - Best-effort A2L/MAC annotation (LLR-004.4, G-2) remains non-gating: a run with no shared symbol is still emitted as a raw binary run.
  - **Per-TC property ownership (m-4):** TC-018 = section presence + order; TC-026 = complete-export (large planted diff ⇒ ALL runs present in the written Markdown file, 0 `TRUNCATED` markers); TC-027 = Markdown ```diff cue (a `changed` run emits a fenced ```diff block with A bytes as `-` lines and B bytes as `+` lines).

### LLR-004.4 — Symbol annotation (best-effort, non-gating)
- **Traceability:** HLR-004
- **Statement:** Where a shared artifact context exists, the run table shall annotate each differing run on a best-effort basis with the names of A2L tags and MAC symbols whose addresses fall inside the run (membership via `range_in_sorted_ranges` / `address_in_sorted_ranges`, `range_index.py`); the annotation shall never gate or alter the binary run extraction — a run that intersects no shared symbol, or any run when no artifact context exists, shall still be reported as a raw binary run rendered with `-`.
- **Rationale (informative, G-2 verbatim-spirit):** The function prioritizes hex-vs-hex comparison; where a differing address relates to A2L and/or MAC content the report documents the difference AND what it represents when possible, giving certainty on the binaries plus an extended change report — whether the change was intentional or not is engineering's judgment to audit, the tool only reports. Annotation is therefore additive context, never a precondition for the diff.
- **Validation:** test (unit)
- **Executed verification:** `pytest tests/test_diff_report_service.py -q -k "symbol_annotation or annotation_absent"` — TC-019 (`test_symbol_annotation_only_intersecting_run`, `test_annotation_absent_without_context`). [Phase-6 reconciliation per 04-validation DEV-1 + DEV-2: filename renamed; provisional `-k annotation` replaced with the real node ids.]
- **Numeric pass threshold:** exit code 0; a fixture with a known symbol inside a run and one outside annotates exactly the inside symbol (1 of 1, 0 false positives).

### LLR-004.5 — Confidentiality (no logging of report bytes)
- **Traceability:** HLR-004
- **Statement:** The diff-report module shall perform no logging of the report body or memory bytes (the F-S-07 precedent, `report_service.py:32-36`); while a project is active the report shall be written under the project work area inside the gitignored `.s19tool/` tree, and while no project is active the report shall be written only to the LLR-004.6-resolved destination after that destination passes validation.
- **Validation:** test (unit) + inspection
- **Executed verification:** `pytest tests/test_diff_report_service.py -q -k "no_logging"` — TC-020 (`test_module_performs_no_logging`); inspection `rg -c "getLogger|import logging" s19_app/tui/services/diff_report_service.py` (Phase-4 result: 0 hits). Probe P-11 executed 2026-06-11 in the target regime (`s19_app/tui/services/` module): `report_service.py` → 0 hits (pre-state precedent); positive control `workspace.py:60` (`logging.getLogger("s19tui")`), same package. [Phase-6 reconciliation per 04-validation DEV-1 + DEV-2: filename renamed; provisional `-k confidential` replaced with the real node id `test_module_performs_no_logging`.]
- **Numeric pass threshold:** test exit code 0; inspection 0 hits; the no-project success path writes exactly 1 file to the resolved destination and 0 log records of report content.

### LLR-004.6 — No-project destination resolution and path validation (G-5 + G-8)
- **Traceability:** HLR-004
- **Statement:** When a diff report is requested while no project is active, the generator shall ALWAYS take the destination from an operator-supplied directory path — there is NO implicit Downloads (or other) default; before writing, it shall normalize the supplied path via `Path(operator_input).expanduser().resolve()` (which collapses `..` segments and resolves symbolic components, so escape-prevention is normalize-then-confirm, not a textual scan) and require the resolved path to be an existing directory (`dest.is_dir()`); if the supplied path is empty, invalid, or not an existing directory, then it shall write no file and return an explicit diagnostic naming the rejected input, raising no exception; on a valid directory it shall write `dest / <tool-generated filename>` where the filename is the LLR-004.1 `<UTC %Y%m%dT%H%M%SZ>(-NN)?-diff-report.md` value produced wholly by the diff-report module (no operator-supplied string forms any component of the filename), applying the SAME LLR-004.1 collision discipline in the resolved directory — zero-padded `-NN` counter, `FileExistsError` after 99, never a silent overwrite.
- **Rationale (informative, G-5 + G-8):** Operator decision G-5 (2026-06-11): no-project reports resolve a destination rather than refusing. Operator decision G-8 (2026-06-11, BINDING at the Phase-2 gate): **solo-prompt — NO implicit Downloads default.** The operator is always prompted for a destination; an operator-typed path is auditable, a guessed one is not. This DROPS the original `Path.home()/"Downloads"` fallback entirely, which also makes the cross-platform Downloads-resolution concern moot (probe P-18 / G-8-original become historical — see ledger). Because this writes firmware-derived bytes OUTSIDE the gitignored `.s19tool/` tree, the write surface re-opens the batch-07 F-S-01 path-validation class and risk R-4 — encoded here as binding acceptance criteria and surfaced as risk R-9 for the Phase-2 security-reviewer. The unconfined no-project write has NO base directory (the operator names the directory directly); a relative operator path is resolved against the **app current working directory** (the base passed to `resolve()` via `Path.cwd()`), matching the read-side precedent `resolve_input_path` which `.expanduser()`s + resolves against the app cwd (`workspace.py:469-483`); the repo root (`find_repo_root`, `workspace.py:457`) is NOT used as the base, because a write destination is not constrained to live under the repo.
- **Validation:** test (unit) + inspection
- **Executed verification:** `pytest tests/test_diff_report_service.py -q -k "no_project"` — TC-025 (`test_no_project_valid_directory_writes_one_file`, `test_no_project_empty_path_refused` [parametrized empty + whitespace], `test_no_project_nonexistent_dir_refused`, `test_no_project_collision_no_overwrite`, `test_no_sanitize_project_name_in_validator`); inspection: the destination-resolver `_resolve_destination` (`diff_report_service.py:287`) reviewed against the §6.4 F-10/F-11/F-12 security notes (Phase-4 §2.6: project-active ⇒ `<project>/reports/`; no-project empty ⇒ refuse no-implicit-default; else `Path(raw).expanduser().resolve()` → `is_dir()` else refuse). [Phase-6 reconciliation per 04-validation DEV-1 + DEV-2: filename renamed; provisional `-k destination` replaced with the real `-k no_project` family.]
- **Numeric pass threshold:** exit code 0; (a) operator directory given + existing ⇒ exactly 1 file written there with a tool-generated filename; (b) empty / invalid / non-existent-directory path ⇒ 0 files written and ≥ 1 diagnostic naming the rejected input, 0 raised exceptions (there is NO Downloads-default branch to test); (c) collision sub-case — a target filename pre-created in the valid destination ⇒ a `-01` sibling is produced and the pre-existing file is byte-unchanged (0 overwrites).
- **Acceptance criteria:**
  - **Directory-validation algorithm (grep-verified precedent 2026-06-11):** the validator is a `NEW — created in Phase 3` function in `diff_report_service.py` implementing exactly: (1) `Path(operator_input).expanduser().resolve()` (collapses `..` + symlinks); (2) require `dest.is_dir()` else REFUSE with a diagnostic naming the input; (3) write `dest / <tool-generated filename>` (LLR-004.1 scheme). It does NOT reuse `sanitize_project_name` (`workspace.py:315`) — that function strips every non-`[alnum_-]` character from a SINGLE name token (it turns a path like `C:\Users\jjgh8\out` into `CUsersjjgh8out`) and is structurally incapable of validating a directory path; that citation is therefore DROPPED from this LLR. The resolve-against-cwd idiom mirrors `resolve_input_path` (`workspace.py:469-483`), but that helper is NOT reused for the write side because it returns only *existing read* inputs (`None` for non-existent) and is unsuitable for a *write* destination.
  - **No-silent-overwrite binding (M-5):** the no-project write reuses the LLR-004.1 collision counter unchanged in the resolved destination directory; it never overwrites an existing file (TC-025 sub-case (c) asserts the `-01` sibling + the untouched original).
  - **No operator string in the filename:** the operator supplies only the destination DIRECTORY; the filename component is generated wholly by the module (LLR-004.1 scheme), so no operator-controlled bytes reach the filename.
  - **No implicit default (G-8):** there is NO `Path.home()/"Downloads"` (or any other) fallback. The original Downloads default was DROPPED at the Phase-2 gate per operator decision G-8; an empty/invalid/non-existent-directory path is REFUSED (no file written, diagnostic returned). The cross-platform Downloads-resolution concern is therefore moot (see probe P-18, annotated historical).
  - **Project-active path unchanged:** when a project IS active the destination remains `<project>/reports/` (LLR-004.1) inside `.s19tool/`; this LLR governs only the no-project branch.

### LLR-004.7 — Self-contained HTML export (G-9)
- **Traceability:** HLR-004
- **Statement:** The diff-report generator shall ALSO produce a complete, self-contained HTML diff report (`generate_diff_report` or a sibling renderer in `diff_report_service.py`, `NEW — created in Phase 3`) carrying the same content as the Markdown file (image identities and sources, artifact-usage notes, statistics, the classified run table with best-effort symbol annotation, per-run hex windows for A and B) with inline CSS only and changed / only-A / only-B runs rendered in visually distinct inline-CSS colour; every embedded value — addresses, bytes, source paths, diagnostics — shall be escaped via `html.escape` (stdlib `html`); the HTML shall contain no `<script>`, no external resource, font, CDN, stylesheet link, or network reference of any kind; the written HTML file shall be COMPLETE (no run cap, no byte truncation, no `TRUNCATED` marker — same as LLR-004.3); it shall be named under its own `DIFF_REPORT_HTML_FILENAME_REGEX` (`NEW — created in Phase 3`, in `diff_report_service.py`) with the `<UTC %Y%m%dT%H%M%SZ>(-NN)?-diff-report.html` scheme, NOT editing the shared `REPORT_FILENAME_REGEX` (`report_service.py:106`, G-4); it shall reuse the LLR-004.1 collision discipline (zero-padded `-NN`, `FileExistsError` after 99, never a silent overwrite, M-5), the LLR-004.5 no-logging-of-report-body rule (F-S-07), and the LLR-004.6 no-project destination machinery (operator-prompt-only, `Path(...).expanduser().resolve()` → require `dest.is_dir()` else REFUSE, no implicit Downloads default per G-8, no operator string in the filename component).
- **Validation:** test (integration) + inspection
- **Executed verification:** `pytest tests/test_diff_report_service.py -q -k "html"` — TC-028 (`test_html_export_complete_and_safe`, `test_html_escapes_embedded_payload`, `test_html_filename_scheme_and_collision`). [Phase-6 reconciliation per 04-validation DEV-1 + DEV-2: filename renamed; provisional `-k html` confirmed to match all three real `test_html_*` node ids.] inspection probe (HTML-safety, P-19 regime): `rg -c '<script|https?://|@import|src=|url\(' <generated .html>` after Phase 3 → 0 hits, and an `html.escape` round-trip check that an escapable payload (e.g. a `<` in a path or byte cell) appears as `&lt;` in the output. Probe P-19 EXECUTED 2026-06-12 in the target regime (`s19_app/tui/services/` service-layer `.html`): synthetic in-regime positive control (scratch `.html` at target depth containing `<script src="https://...">` + `@import url(...)`) → 2 hits; negative control on the real `report_service.py` → 0 hits; scratch removed (batch-08 `_b2_scratch` pattern). `html.escape` stdlib availability confirmed (`html.escape('<a href="x">&')` → `&lt;a href=&quot;x&quot;&gt;&amp;`).
- **Numeric pass threshold:** exit code 0; the generated HTML contains 0 `<script>` occurrences, 0 external-resource matches (`<script|https?://|@import|src=|url\(` → 0), ≥ 1 inline-CSS colour rule or `style=` attribute distinguishing the three run kinds, an escapable payload round-trips as its `html.escape` form, and a large planted-diff fixture produces 0 `TRUNCATED` markers in the HTML (completeness).
- **Acceptance criteria:**
  - `DIFF_REPORT_HTML_FILENAME_REGEX` and the `.html` filename scheme are `NEW — created in Phase 3` (no pre-existing symbol; grep would not hit them today); the shared `REPORT_FILENAME_REGEX` is NOT edited (G-4).
  - PDF is OUT of scope (dormant note: `fpdf2` if ever revived, never weasyprint).

### LLR-005.1 — Service-only routing
- **Traceability:** HLR-005
- **Statement:** When the operator submits a comparison request from the A↔B Diff screen, `S19TuiApp` shall obtain the comparison result exclusively by calling the comparison service entry point (`compare_service`, `NEW — created in Phase 3`), and shall obtain the diff report exclusively via the diff-report generator — the app shall compute no run classification, no coverage count, and no report content itself.
- **Validation:** test (integration) + inspection
- **Executed verification:** `pytest tests/test_tui_diff_screen.py -q -k "tc021"` — TC-021 (`test_tc021_compare_routes_through_service`); inspection: the diff-handling methods in `app.py` contain no diff/coverage arithmetic (Phase-4 §2.8: `rg -n "diff_mem_maps" s19_app/tui/app.py s19_app/tui/screens_directionb.py` → 0; the app imports + calls `compare_images` `app.py:2009`). [Phase-6 reconciliation per 04-validation DEV-2: provisional `-k routing` replaced with the real `-k tc021` node-id selector.]
- **Numeric pass threshold:** exit code 0; a monkeypatched service entry point is invoked exactly 1 time per request and the rendered output reflects its injected result.
- **Acceptance criteria (UI mechanisms — `assumed — verify in Phase 3`):**
  - **Selection surface is INLINE within the diff screen, not a modal (G-6 DECIDED, operator preference 2026-06-11).** The image-pair selection (prefilled variant list from `ProjectVariantSet` + external-path entry) is composed inline inside the A↔B Diff panel rather than pushed as a separate modal screen. Per the batch-08 A-4/V-2 rule the statement pins only behavior + service route (LLR-005.1 body); this AC pins the inline-vs-modal choice, while the exact inline widget mechanism (which inputs/lists, layout) remains `assumed — verify in Phase 3`.

### LLR-005.2 — Placeholder replacement and result rendering
- **Traceability:** HLR-005
- **Statement:** When a comparison result is available, the A↔B Diff screen shall render the classified run list in the range-list column and, for the selected run, bounded hex windows of image A and image B in the remaining columns — each window respecting the `hexview` caps (`MAX_HEX_ROWS=512`, `FOCUS_CONTEXT_ROWS=64`, `hexview.py:21-22`) — and shall bound the on-screen run dump by the relocated display caps (the per-report run-dump cap and `REPORT_MAX_TOTAL_BYTES`-equivalent budget, `report_service.py:79`, RE-LOCATED here from the file path per G-9 / LLR-004.3 — these bound only what the screen shows, never the persisted report files); and the static placeholder constants of `AbDiffPanel` shall no longer be rendered.
- **Validation:** test (integration) + inspection
- **Executed verification:** `pytest tests/test_tui_diff_screen.py -q -k "tc022 or tc029"` — TC-022 (`test_tc022_render_shows_runs_and_hex_windows`, rendering) + TC-029 (`test_tc029_display_caps_bound_on_screen_runs` — the render path truncates an over-cap comparison to the relocated display caps while the persisted file from TC-026 stays complete). [Phase-6 reconciliation per 04-validation DEV-2: provisional `-k "render or display_cap"` replaced with the real `-k "tc022 or tc029"` node-id selector.] inspection probe (named-constant probe, P-07 revised): `rg -n '_RANGE_LIST_PLACEHOLDER|_HEX_A_PLACEHOLDER|_HEX_B_PLACEHOLDER|DEFERRAL_TEXT' s19_app/tui/screens_directionb.py` — EXECUTED 2026-06-11, pre-state **8 line-hits** across the 4 named diff constants (defs `:882`/`:888`/`:894`/`:900` + composed usages `:929`/`:935`/`:936`/`:937`); regime: literal rg over the named file, AbDiffPanel block `:849-939`. The whole-file `rg -c "PLACEHOLDER"` is NOT used as the pass-probe because it never reaches 0 — 3 unrelated survivors stay (docstring `:23`, Bookmarks `PLACEHOLDER_TEXT` `:315`, Bookmarks usage `:322` — verified present today and out of the AbDiffPanel block).
- **Numeric pass threshold:** exit code 0; post-Phase-3 the named-constant probe `rg -n '_RANGE_LIST_PLACEHOLDER|_HEX_A_PLACEHOLDER|_HEX_B_PLACEHOLDER|DEFERRAL_TEXT' s19_app/tui/screens_directionb.py` yields **0** hits (the 4 diff constants removed or no longer composed); the 3 whole-file survivors at `:23`/`:315`/`:322` are unrelated and expected to remain.
- **Acceptance criteria (UI mechanisms — `assumed — verify in Phase 3`):**
  - Column widget ids `#diff_range_list` / `#diff_hex_a` / `#diff_hex_b` (`screens_directionb.py:935-937`) are reused where practical.
  - **Relocated display caps (G-9):** the on-screen render path DOES truncate to the relocated caps; this is exercised by TC-029 (an over-cap comparison shows a bounded display while the persisted file stays complete, TC-026). The cap constants live with the render path (`assumed — verify in Phase 3`: precedent `REPORT_MAX_REGIONS_PER_VARIANT=128`, `report_service.py:72`; `REPORT_MAX_TOTAL_BYTES`, `report_service.py:79`).

### LLR-005.3 — Failure surfacing
- **Traceability:** HLR-005
- **Statement:** If a comparison request is refused (unresolvable path, parse failure, fewer than two valid images), then the app shall display the refusal diagnostic in the status line and shall remain running with the diff screen in its pre-request state.
- **Validation:** test (integration)
- **Executed verification:** `pytest tests/test_tui_diff_screen.py -q -k "tc023"` — TC-023 (`test_tc023_refused_compare_surfaces_diagnostic`), via the `App.run_test()` pilot pattern used by `tests/test_tui_app.py`. [Phase-6 reconciliation per 04-validation DEV-2: provisional `-k failure` replaced with the real `-k tc023` node-id selector.]
- **Numeric pass threshold:** exit code 0; the pilot observes a status message containing the diagnostic and 0 unhandled exceptions.

### LLR-005.4 — Report trigger feedback
- **Traceability:** HLR-005
- **Statement:** When the operator triggers diff-report generation from the diff screen and generation succeeds, the app shall display the written report's full destination path(s) in the status line (both the Markdown and HTML files per LLR-004.3 / LLR-004.7); if generation is refused (LLR-004.6 invalid-destination case), then the app shall display the refusal diagnostic instead and the screen shall remain running.
- **Validation:** test (integration)
- **Executed verification:** `pytest tests/test_tui_diff_screen.py -q -k "tc024"` — TC-024 (`test_tc024_report_trigger_surfaces_paths`, `test_tc024_report_trigger_invalid_dest_refused`). [Phase-6 reconciliation per 04-validation DEV-2: provisional `-k report_trigger` replaced with the real `-k tc024` node-id selector.]
- **Numeric pass threshold:** exit code 0; success-path status contains a filename matching `DIFF_REPORT_FILENAME_REGEX` (LLR-004.2) and one matching `DIFF_REPORT_HTML_FILENAME_REGEX` (LLR-004.7); invalid-destination path writes 0 files and the status carries the diagnostic.

---

## 5. Validation strategy

### 5.1 Methods
- **Test:** automated execution (unit / integration / e2e). Default for LLR. **Every `test` LLR must name the exact executed verification and the numeric pass threshold — otherwise it is not executable.** Runtime: `pytest` (ratified path; CI `.github/workflows/tui-ci.yml` runs `pytest -q` on Python 3.11). Textual integration tests use the `App.run_test()` pilot pattern already present in `tests/test_tui_app.py`. All Phase-3 pytest node ids above are **provisional until Phase 3** (batch-08 A-3).
- **Demo:** observed execution of behavior. HLR-005 demo: launch `s19tui` with a project containing ≥ 2 variants, open the diff screen (press `7`, the diff rail position, or the rail `D` shortcut — the literal rail label is `"A2B Diff"`, `rail.py:85`), run a comparison, observe run list + hex windows + report status. Qualitative criterion: no placeholder text visible; differing bytes locatable in both columns.
- **Inspection:** static review of code or document. Used for module purity (LLR-001.1, LLR-002.1), no-logging (LLR-004.5), placeholder removal (LLR-005.2), C-9 field-set identity (LLR-002.6).
- **Analysis:** not used this batch (the performance claim is a `test (slow)` with a measured budget, LLR-001.5).

> Reminder from the batch-02 + batch-03 post-mortems: the absence of an executed verification + numeric pass threshold on `test`/`analysis` requirements was the recurring root cause of forced phase-1 iteration. Capture at draft time, not at the phase-2 gate.

### 5.2 Coverage table

| Requirement | Method | Test Case ID | Notes |
|-------------|--------|--------------|-------|
| HLR-001 | test | TC-001..TC-006 | engine file `tests/test_compare_engine.py` (NEW) |
| LLR-001.1 | inspection | — | rg purity probe (P-10 regime) |
| LLR-001.2 | test (unit) | TC-001, TC-002, TC-003 | distinct properties (m-4): TC-001 = classification set-equality (per-address reconstruction == brute force); TC-002 = adjacency-merge (same-kind adjacent addresses share a run iff same classification); TC-003 = boundary cases (run at addr 0, touching runs of different kinds, single-byte runs, interleaved gaps) |
| LLR-001.3 | test (unit) | TC-004 | identity + determinism |
| LLR-001.4 | test (unit) | TC-005 | stats consistency |
| LLR-001.5 | test (slow) | TC-006 | `make_large_s19` regime; budget provisional |
| HLR-002 | test | TC-007..TC-011 | service file `tests/test_compare_service.py` (NEW) |
| LLR-002.1 | inspection | — | rg purity probe (P-11 regime) |
| LLR-002.2 | test (integration) | TC-007 | fresh parse, variant pair |
| LLR-002.3 | test (unit) | TC-008 | unresolvable external path |
| LLR-002.4 | test (integration) | TC-009 | three source pairings |
| LLR-002.5 | test (unit) | TC-010 | parse-failure isolation |
| LLR-002.6 | test (unit) + inspection | TC-011 | C-9 field-set identity |
| HLR-003 | test | TC-012..TC-015 | artifact notes |
| LLR-003.1 | test (integration) | TC-012 | context from project cardinality |
| LLR-003.2 | test (unit) | TC-013 | coverage via range_index |
| LLR-003.3 | test (unit) | TC-014 | both/one/none derivation |
| LLR-003.4 | test (unit) | TC-015 | absent artifacts |
| HLR-004 | test | TC-016..TC-020, TC-025, TC-026..TC-028 | report file `tests/test_diff_report_service.py` (NEW) [Phase-6 reconciliation per 04-validation DEV-1] |
| LLR-004.1 | test (unit) | TC-016 | filename + collision |
| LLR-004.2 | test (unit) | TC-017 | self-contained diff listing; report_service NON-edit regression (P-09) |
| LLR-004.3 | test (integration) | TC-018, TC-026, TC-027 | complete Markdown file; TC-018 = sections+order, TC-026 = complete-export (0 TRUNCATED, all runs), TC-027 = ```diff cue (`-`/`+`) |
| LLR-004.4 | test (unit) | TC-019 | symbol annotation |
| LLR-004.5 | test (unit) + inspection | TC-020 | confidentiality; no-logging probe |
| LLR-004.6 | test (unit) + inspection | TC-025 | no-project destination + directory validation (G-5+G-8, solo-prompt no default); R-9 |
| LLR-004.7 | test (integration) + inspection | TC-028 | self-contained HTML export (G-9); html.escape + 0 script/external (P-19 regime); complete |
| HLR-005 | test + demo | TC-021..TC-024, TC-029 | TUI file `tests/test_tui_diff_screen.py` (NEW) |
| LLR-005.1 | test (integration) + inspection | TC-021 | service-only routing |
| LLR-005.2 | test (integration) + inspection | TC-022, TC-029 | rendering; placeholder probe P-07 (pre-state 8); TC-029 = relocated display-cap truncation (G-9, file stays complete) |
| LLR-005.3 | test (integration) | TC-023 | failure surfacing, run_test pilot |
| LLR-005.4 | test (integration) | TC-024 | report trigger feedback |

### 5.3 Batch acceptance criteria
- 100 % of LLRs covered by ≥ 1 TC or an executed inspection probe (26 of 26 — table above; 26 = the `grep -n '### LLR-'` heading count, LLR-004.6 added at iteration 2 → TC-025, LLR-004.7 added at iteration 4 → TC-028).
- 0 blocker fails in Phase-4 validation; `pytest -q` exit code 0.
- **Suite-count reconciliation (measured baseline + signed balance, not additive):** `python -m pytest -q --collect-only` last line at draft, executed 2026-06-11 in this worktree (full suite, no marker filter): **`733 tests collected in 0.51s`** (probe P-01). Post-batch collection is reconciled as a **signed balance off the measured 733**: `post_count = 733 − D + A`, where **D** = the count of placeholder-pinned test functions DELETED (drawn from the corrected R-8 census: the TC-027 family + `test_tc028_every_scaffold_screen_activates_without_error`, minus any rewritten-in-place which contribute 0 to D), and **A** = net-new test functions added (the new diff TCs implemented + any test rewritten under a new name). No additivity is assumed: a rewrite-in-place adds 0 to both D and A; a delete-and-replace adds 1 to D and 1 to A. **D and A are reconciled in Phase 4** against the I4 increment packet's disposition table (the packet states, per pinned test, rewrite-in-place vs delete-and-replace vs delete). The criterion hangs off the MEASURED 733 (probe P-01), never off a planned TC count.
- 0 occurrences of `should` inside any §3/§4 Statement (self-check executed at draft — see §6.5).
- No requirement without an assigned validation method.
- `pytest tests/test_report_service.py -q` passes with its `REPORT_FILENAME_REGEX` assertions UNCHANGED — G-4 retired the generalization, so this runs as a NON-edit regression guard confirming the shared regex was not touched (0 regressions; probe P-09's 3 hits remain).

---

## 6. Appendices

### 6.1 Extended glossary
See §1.3. Additional: **refused comparison** — a `ComparisonResult` whose `refused` flag is set and whose `diagnostics` explain why; it carries no runs.

### 6.2 Relevant design decisions

#### D-1 — Scope shape: 2-way core; N-way deferred (feasibility = finding, not guess)
**Finding:** N-way is mechanically feasible at the engine level — the run extraction is a single scan over the sorted union of map keys, which generalizes to a per-image presence/value vector. The cost is NOT in the scan; it is in the surface: (a) the existing screen is structurally two-sided (three columns A/B, `screens_directionb.py:934-938`); (b) the run-classification vocabulary for N images is the product space of presence patterns (2^N−1) × value partitions, which explodes the report's run table and the colour policy; (c) no current operator workflow yields a third candidate beyond "pick another variant".
**Decision:** N=2 this batch. The engine's run model carries per-side payloads so adding sides later changes no run identity. N-way registered as a follow-up story at the gate. **Gate-confirmable G-1.**

#### D-2 — Diff granularity: byte runs core, symbol annotation as in-batch enrichment
Byte-level contiguous runs are the core (LLR-001.2). Symbol-level annotation (run → A2L tag / MAC symbol names) is included this batch but ONLY in the report (LLR-004.4), because all machinery exists (`enrich_tags_and_render` `a2l_service.py:10`; `range_index.py`); the TUI run list does not carry symbols this batch. **Gate-confirmable G-2** (cut candidate if Phase-3 budget tightens: dropping LLR-004.4 removes one LLR + one TC and no other requirement depends on it).

#### D-3 — Artifact-usage note semantics (mechanical definition)
Per (image, artifact): `covered = |{records with int address inside the image's ranges}|` (LLR-003.2); status `used` iff covered ≥ 1, else `unused`; `absent` when the project supplies no such artifact. Per-image summary `both` / `one (a2l)` / `one (mac)` / `none` (LLR-003.3). The report prints both the status and the raw `covered/total` counts so the operator can judge weak coverage. **Alternatives (gate-confirmable G-3):** (a) project-membership-only (no address check — cheaper, less meaningful for externals); (b) threshold-based (`covered/total ≥ X %` — needs a defensible X; none exists today). Recommendation: coverage ≥ 1, because it is the only definition that is simultaneously mechanical, meaningful for external images, and threshold-free.

#### D-4 — Comparison sources: both in-project variants and external files this batch
The story names both explicitly; both code paths already exist (`ProjectVariantSet` enumeration; `resolve_input_path`). Staging externals out would save only LLR-002.3/002.4 — not worth splitting the story.

#### D-5 — Report: reuse `report_service` conventions in a NEW `diff_report_service` module
Reused as PATTERN (copied/parameterized, not contract-edited): `REPORTS_DIR_NAME` (`report_service.py:110`), `REPORT_TIMESTAMP_FORMAT` (`:103`), collision-counter pattern (`_report_filename` `:355` — re-implemented with the diff kind suffix), `REPORT_MAX_TOTAL_BYTES` (`:79`), `compute_hexdump_windows` (`:232`, public), plain `render_hex_view` (`hexview.py:294`). NEW module rather than extending `generate_project_report`, because the diff report's input is a `ComparisonResult`, not `VariantExecutionResult`s — fusing them would couple two unrelated producers.
**G-4 DECIDED (overturns the original D-5 shared-regex plan):** the diff report gets its OWN listing/filename scheme — `DIFF_REPORT_FILENAME_REGEX` + `list_diff_reports` owned by `diff_report_service` (LLR-004.2) — and `REPORT_FILENAME_REGEX` (`:106`) / `list_project_reports` (`:398`) are NOT edited. This RETIRES the one shared-contract edit; the probe P-09 blast radius (3 hits `tests/test_report_service.py:66,301,302`) now justifies a NON-edit (those assertions stay untouched and serve as the regression guard). The C-9 contract-touch surface for the report regex is closed (see §6.4 F-2). Operator rationale: a self-contained diff listing is preferred over coupling the diff scheme into the project-report regex.

#### D-6 — Surface: complete the existing placeholder; add nothing to the rail
Facts established: the rail ALREADY holds the diff entry (`rail.py:85`, 8 entries — batch-08 kept the rail at 8; no new entry); routing exists end-to-end (`app.py:2421` → `action_show_screen` `app.py:2473` → `_compose_screen_diff` `app.py:1868` → `AbDiffPanel` `screens_directionb.py:849`). Minimal completion = replace `AbDiffPanel` internals + add the comparison-request flow; no `push_screen` for the main panel (the show/hide container mechanism, `app.py:2512-2521`, stays).

#### D-7 — Engine placement: package-root `s19_app/compare.py` + service seam
Engine at package root beside `range_index.py` (pure, no Textual, no parser imports — LLR-001.1), consumed by `s19_app/tui/services/compare_service.py` (loads images, computes notes, assembles C-9 — LLR-002.1), consumed by `app.py` only through the service (LLR-005.1). This is the batch-07/08 engine/service/view precedent. Per batch-08 A-4/V-2: LLRs pin behavior + service route; UI mechanisms are ACs flagged `assumed — verify in Phase 3`.

#### D-8 — No-project diff report: resolve a destination (G-5 DECIDED — overturns the original refusal; G-8 DECIDED — solo-prompt, no implicit default)
A comparison can run with no active project (two externals). **Original plan (refuse) is overturned by the operator (G-5, 2026-06-11):** when no project is active the diff report is written to an operator-supplied destination directory. **G-8 (operator, 2026-06-11, BINDING) sharpens this: solo-prompt — NO implicit Downloads (or other) default.** The operator is always prompted for a destination directory; if the supplied path is empty, invalid, or not an existing directory, the write is REFUSED (no file written, diagnostic returned). The original `Path.home()/"Downloads"` fallback is DROPPED; the cross-platform Downloads concern is moot. When a project IS active, reports still go to `<project>/reports/` inside `.s19tool/` (LLR-004.1, unchanged). The no-project branch is specified by LLR-004.6 (directory resolution + validation) and surfaced to the TUI by LLR-005.4.
**Security obligation (binding):** the no-project destination can lie OUTSIDE the gitignored `.s19tool/` tree, so firmware-derived report bytes are written to operator-controlled disk. LLR-004.6 makes the write conditional on directory validation — `Path(operator_input).expanduser().resolve()` (collapses `..`+symlinks) → require `dest.is_dir()` → write `dest / <tool-generated filename>` (no operator string in the filename). `sanitize_project_name` (`workspace.py:315`) is NOT used: it is a single-token name cleaner, structurally incapable of validating a path (M-4). Risk R-9 routes this write surface to the Phase-2 security-reviewer. (Project-loaded vs not is the architect's split interpretation of the operator's "ask for path" wording, recorded in §6.4 F-3 / F-12.)

#### C-9 — Comparison result contract (producer/consumer table — contract-touch rule applies)

Canonical field set of `ComparisonResult` (all symbols `NEW — created in Phase 3`):

| Field | Type | Producer | Consumers |
|---|---|---|---|
| `image_a`, `image_b` | `ImageRef` (label, path, source kind `project-variant`/`external`, optional `variant_id`, parse-error count) | `compare_service` | diff report header (LLR-004.3); TUI status/header (LLR-005.2); tests |
| `runs` | `list[DiffRun]` (start, end, kind ∈ {`changed`,`only_a`,`only_b`}) | engine `diff_mem_maps` (`s19_app/compare.py`) | report run table + hex windows (LLR-004.3); TUI run list (LLR-005.2); tests |
| `stats` | `DiffStats` (per-kind run count + byte count) | engine | report stats table (LLR-004.3); TUI summary (LLR-005.2); tests |
| `notes` | per-image artifact-usage notes (per-artifact status + covered/total; summary token) | `compare_service` (HLR-003) | report header (LLR-004.3); TUI (LLR-005.2); tests |
| `diagnostics` | `list[str]` | `compare_service` | TUI status line (LLR-005.3); report (informative); tests |
| `refused` | `bool` | `compare_service` | TUI (LLR-005.3); report generator guard; tests |

Any post-draft edit to LLR-001.2/001.4/002.x/003.x/004.3/005.2 re-opens this table per the contract-touch rule.

#### Phase-3 increment plan (sketch; each ≤ 5 files)
| Inc | Content | Files (est.) |
|---|---|---|
| I1 | Engine: `s19_app/compare.py` + `tests/test_compare_engine.py` (LLR-001.1..001.5) | 2 |
| I2 | Service: `s19_app/tui/services/compare_service.py` + `tests/test_compare_service.py` (LLR-002.x, 003.x) | 2 |
| I3 | Report: `s19_app/tui/services/diff_report_service.py` (own filename + `DIFF_REPORT_FILENAME_REGEX` + `DIFF_REPORT_HTML_FILENAME_REGEX` + `list_diff_reports` + complete Markdown renderer with ```diff cue + complete self-contained HTML renderer with `html.escape`+inline CSS + no-project destination resolver/validator, LLR-004.1..004.7) + `tests/test_diff_report_service.py` [Phase-6 reconciliation per 04-validation DEV-1: implemented as `_service`]. `report_service.py` is NOT edited (G-4); `tests/test_report_service.py` runs read-only as the NON-edit regression guard. (LLR-004.x) | 2 edited (+1 read-only regression run) |
| I4 | TUI: `screens_directionb.py` (AbDiffPanel + INLINE selection surface, G-6) + `app.py` (wiring) + `tests/test_tui_diff_screen.py` (LLR-005.x). Inline selector removes the separate-modal file the draft anticipated. | 3 |
| I5 | Close: `REQUIREMENTS.md` R-* update + batch artifacts | 2 |

Estimated total: ~11-12 edited files, 5 increments (G-4 dropped the `report_service.py` edit; G-6 inline dropped the separate selection-modal file; G-5 destination logic folds into the existing `diff_report_service.py`, adding no file). Every increment ≤ 5 files.

### 6.3 Open risks

| ID | Risk | Mitigation |
|---|---|---|
| R-1 | `app.py` (~5k lines, flagged for decomposition by PROJECT_RULES.md) grows further at I4. | Wiring-only additions; all logic in services (LLR-005.1 inspection enforces). |
| ~~R-2~~ | ~~`REPORT_FILENAME_REGEX` generalization breaks an untested consumer.~~ **RETIRED (G-4, 2026-06-11):** the generalization is overturned; diff reports use a self-contained `DIFF_REPORT_FILENAME_REGEX` (LLR-004.2) and the shared regex is NOT edited. The P-09 blast radius (3 hits) now backs a NON-edit; `test_report_service.py` runs only as an unchanged-semantics regression guard. See §6.4 F-2. |
| R-3 | Diff of two large images blows memory/time in CI. | MEASURED LOW (probe P-15): full classify walk 201.7 ms on the default large pair locally; LLR-001.5 budget ≤ 2.0 s w/ ~10× headroom, CI regime confirmed at Phase 4; precedent: E6 already holds full maps per variant. |
| R-8 | **Placeholder-pinned tests stay silently green or break confusingly.** Corrected census (M-2, probe P-16 re-run 2026-06-11, line ranges grep-verified): (1) `tests/test_tui_directionb.py:3383-3487` — TC-027 family (three-column placeholder, static rows, no-second-file-load, panel-holds-no-data), 4 functions; (2) `:3628-3666` — `test_tc028_every_scaffold_screen_activates_without_error`, which asserts `#diff_deferral_notice` PRESENT at `:3656` (it pins the `DEFERRAL_TEXT` LLR-005.2 removes and sits OUTSIDE the TC-027 range). **Corrected predicted-red set = 5** (4 TC-027 + this TC-028 activation test), not the originally-named 4. The AST guard `test_tc028_diff_renderer_invokes_no_diff_logic` (`:3605`, assertion `:3622` `calls <= {Container, Label, AbDiffPanel}`) is NOT in the breaking set: if the rewritten `_compose_screen_diff` still constructs only `AbDiffPanel` (the panel gains real content internally, but the compose method adds no new top-level call name), the guard stays GREEN — so it is a no-touch, not a predicted red. | These tests shall be SUPERSEDED/REWRITTEN at the I4 increment gate with their disposition recorded in the increment packet (they may not silently remain green against the placeholder, and their red state pre-rewrite must match the corrected 5-test predicted set — batch-07 §6.6 discipline at micro scale). Disposition for `test_tc028_every_scaffold_screen_activates_without_error`: rewrite the deferral-marker clause (`:3656` `#diff_deferral_notice` assertion) to assert the new panel surface, OR remove that clause while keeping the activation-without-error sweep for the other rail screens. Suite-count reconciliation (§5.3, signed balance `733 − D + A`) reconciles each test's rewrite-in-place vs delete-and-replace at Phase 4. **ADDENDUM (discovered at the I1 gate 2026-06-11, escaped the Phase-1/2 census — a DIFFERENT guard class than the diff-placeholder tests): two package-root module-placement guards `test_tc028_no_new_processing_module_added_outside_view_layer` (`:3174`) and `..._inc10` (`:3534`) pin `s19_app/` to a 7-module batch-04 allowlist (LLR-012.4); D-7's `compare.py` engine at the package root overturns them. RESOLVED AT I1 by the conflict rule (HLR-001/D-7 supersedes the batch-04 invariant): `compare.py` added to both allowlists with a supersession comment, preserving each guard's value for any OTHER unexpected root module. Ratified at the I1 gate; both pass post-edit. This is the I1 analogue of the §6.6 micro-supersession discipline — recorded so Phase 4/5 know the census had two surfaces, not one.** **CLOSEOUT [Phase-6 reconciliation per 04-validation DEV-3]: the predicted-red count of 5 was CONFIRMED at Phase 4; disposition resolved as a 3+2 split — 3 delete-and-replace (`test_tc027_ab_diff_columns_carry_static_placeholder_rows`, `test_tc027_ab_diff_panel_holds_no_loaded_file_data`, `test_tc027_ab_diff_states_diff_deferred_and_has_no_second_file_load`, each contributing 1 to D and 1 to A) + 2 rewrite-in-place (`test_tc027_ab_diff_renders_three_columns` body inverted; `test_tc028_every_scaffold_screen_activates_without_error` deferral clause inverted to assert `#diff_deferral_notice` ABSENT — each contributing 0/0). This feeds the §5.3 signed balance `782 = 733 − 3 + 52` (04-validation §3). The AST guard `test_tc028_diff_renderer_invokes_no_diff_logic` stayed GREEN as predicted (compose still constructs only `AbDiffPanel`).** |
| R-4 | Diff reports leak confidential bytes outside `.s19tool/`. | LLR-004.5 (gitignored tree only, no logging) — F-S-07 discipline inherited; applies to BOTH the Markdown (LLR-004.3) and HTML (LLR-004.7) files. The reports are now COMPLETE (no file truncation, G-9) — the byte caps that previously appeared to bound the file are TUI-display-only (LLR-005.2), so completeness does not widen the confidentiality surface beyond the existing gitignored/no-logging + no-project-validation (R-9) controls. |
| R-5 | Selection UI scope-creeps (file pickers, history). | UI mechanism deliberately unpinned (ACs `assumed — verify in Phase 3`); minimal modal per `screens.py` precedent; report scope creep at the boundary. |
| R-6 | Stale batch-04 references: LLR-012.3/012.4 described the placeholder as permanent-until-deferred. | §2.1 records the supersession; Phase 6 updates `REQUIREMENTS.md` rows. |
| R-7 | Zero `.hex` examples (probe P-03) tempts an AC to fabricate one. | A-3 assumption + AC-artifact rule: HEX tests use synthetic fixtures; any new on-disk `.hex` fixture is `NEW` and budget-counted. |
| **R-10** | **HTML export content-injection surface (G-9, LLR-004.7).** The new self-contained HTML diff report embeds firmware-derived content (addresses, bytes, source paths, diagnostics) into HTML markup; an unescaped `<`/`>`/`&`/quote in a path or byte cell could break out of the intended context. | LLR-004.7 binds `html.escape` (stdlib) on EVERY embedded value, inline CSS only, and forbids `<script>`/external resource/font/CDN/network — verified by the P-19-regime probe `rg -c '<script\|https?://\|@import\|src=\|url\(' <html>` → 0 plus an `html.escape` round-trip assertion (TC-028). Static output only (no JS, no live DOM); **ROUTED to the Phase-2 security-reviewer** alongside R-9 as the second out-of-`.s19tool/` artifact format. |
| **R-9** | **Out-of-workarea write surface (G-5 + G-8).** The no-project diff report (LLR-004.6) writes firmware-derived bytes to an operator-supplied directory — OUTSIDE the gitignored `.s19tool/` tree, re-opening risk R-4 and the batch-07 F-S-01 path-validation class. Failure modes: a directory escaping the intended location (mitigated by normalize-then-confirm); writing over an existing file outside the work area. **The Downloads-default failure mode is REMOVED — G-8 dropped the implicit default, so cross-platform Downloads resolution is no longer a risk surface.** | LLR-004.6 binds directory validation before any write: `Path(operator_input).expanduser().resolve()` (collapses `..`+symlinks) → require `dest.is_dir()` else REFUSE with diagnostic → write `dest / <tool-generated filename>` (no operator string in the filename component) + the batch-07 collision counter applied in the resolved dir (no silent overwrite, LLR-004.1, bound by M-5). `sanitize_project_name` is NOT cited (it is a name-token cleaner, not a path validator — M-4). **ROUTED EXPLICITLY to the Phase-2 security-reviewer** for the out-of-workarea write surface. See §6.4 F-10/F-11/F-12. |

**Gate-confirmables (RESOLVED at the Phase-1 gate, operator 2026-06-11; see §6.4 audit):**
- **G-1 DECIDED — 2-way only; N-way deferred (D-1).** Operator rationale: pair-wise comparison is preferable to compromising functionality and tool response time; multi-file workflows exist but pair-wise is the right scope. Confirmation only — no body change.
- **G-2 DECIDED — symbol annotation IN scope, sharpened best-effort/non-gating (D-2, LLR-004.4).** Operator rationale: prioritize hex-vs-hex, but where a differing address relates to A2L/MAC content document the difference AND what it represents when possible (certainty on binaries + extended change report; auditing intent is engineering's, the tool only reports). Annotation never blocks the binary diff.
- **G-3 DECIDED — coverage ≥ 1 semantics kept (D-3).** Operator note: priority is the binary difference; A2L/MAC assumed unchanged (same project). Confirmation only — no body change.
- **G-4 DECIDED — separate diff-report listing; shared-regex generalization RETIRED (D-5, LLR-004.2).** Own `DIFF_REPORT_FILENAME_REGEX` + `list_diff_reports`; `REPORT_FILENAME_REGEX` NOT edited. Retires the only shared-contract touch (R-2 retired; P-09 now backs a NON-edit).
- **G-5 DECIDED — no-project report resolves a destination (D-8, LLR-004.6).** Operator: "ask for path." Architect split: project-active ⇒ `<project>/reports/` (unchanged); no-project ⇒ operator-supplied directory. Refined by G-8 (below). Security: directory-validation gate + R-9 to the Phase-2 security-reviewer.
- **G-6 DECIDED — INLINE selector (D-7 / LLR-005.1 AC).** Operator preference (no deeper criterion): selection surface is inline within the diff screen, not a modal; exact inline widget mechanism stays `assumed — verify in Phase 3`.
- **G-7** LLR-001.5 performance budget — RESOLVED BY MEASUREMENT (qa probe P-15, 2026-06-11): ≤ 2.0 s diff compute, ~10× headroom over the measured 201.7 ms walk; CI-regime confirmation rides Phase 4. No operator decision needed unless a tighter/looser budget is wanted.

**G-9 RESOLVED at the I3 gate (operator, 2026-06-12, BINDING):**
- **G-9 DECIDED — complete report file + dual-format export (Markdown + HTML); caps relocated to TUI display; PDF dropped (HLR-004, LLR-004.3, LLR-004.7, LLR-005.2).** The persisted diff report is the authoritative deliverable and MUST be COMPLETE — no run cap, no byte truncation, no `TRUNCATED` marker in the file. The batch-07 caps (`REPORT_MAX_TOTAL_BYTES`, the per-report run-dump cap) were wrongly treating the FILE as bounded; they are RE-LOCATED to the TUI DISPLAY render path only (LLR-005.2, I4). Both exports carry human-factors visual cues (Markdown fenced ```diff with A=`-`/B=`+`; HTML inline-CSS colour). A NEW self-contained HTML export is added (LLR-004.7): inline CSS only, `html.escape` on all embedded content, no `<script>`/external resource/CDN/network, own `DIFF_REPORT_HTML_FILENAME_REGEX` (shared `REPORT_FILENAME_REGEX` NOT edited, G-4). PDF is DROPPED (dormant note: `fpdf2` if ever revived, never weasyprint). TUI Rich-colour distinction (changed/only-A/only-B in the panel) stays an I4 concern. Applied throughout: HLR-004, LLR-004.3, LLR-004.7, LLR-005.2, R-4, new R-10, probe ledger P-19, §6.4 F-18..F-21.

**G-8 RESOLVED at the Phase-2 gate (operator, 2026-06-11, BINDING):**
- **G-8 DECIDED — solo-prompt; NO implicit Downloads default (D-8, LLR-004.6).** The no-project diff report is ALWAYS written to an operator-supplied destination directory; there is NO `Path.home()/"Downloads"` (or other) fallback. An empty/invalid/non-existent-directory path is REFUSED (no file written, diagnostic returned). Operator rationale: an operator-typed path is auditable; a guessed one is not. This DROPS the original Downloads default, which makes the cross-platform Downloads-resolution concern (the original G-8 open question) MOOT — probe P-18 is annotated historical. Applied throughout: HLR-004, LLR-004.6, D-8, R-9, the probe ledger (P-18), and TC-025 (the Downloads branch is removed; branches are now valid-directory / empty-or-invalid-refused / collision-no-overwrite).

### 6.4 Reconciliation log

**Phase-1 ITERATION 2 — operator gate decisions applied 2026-06-11 (body-first; each row's "Body edit landed?" cites the §3/§4 line that now exists).**

| Decision ID | What changed | Parent HLR re-read? (which HLR + what changed, or "no change required" + why) | Body edit landed? (the §3/§4 line that now reflects it) |
|---|---|---|---|
| F-1 (G-2) | Sharpened symbol annotation to best-effort + explicitly non-gating; annotation never blocks/alters binary run extraction; raw binary run reported when no shared symbol/context. | HLR-004 re-read: statement already says "classified run table with symbol annotation" — changed "symbol annotation" → "best-effort symbol annotation" to match the sharpened LLR; no threshold change. | LLR-004.4 retitled "Symbol annotation (best-effort, non-gating)"; new non-gating Statement + G-2 rationale. HLR-004 statement now reads "best-effort symbol annotation". |
| F-2 (G-4) | RETIRED the shared `REPORT_FILENAME_REGEX` generalization; diff reports get a self-contained `DIFF_REPORT_FILENAME_REGEX` + `list_diff_reports` owned by `diff_report_service`; `report_service` regex/listing NOT edited. Contract-touch RETIRED → recorded as a NON-edit; P-09 blast radius (3 hits) now justifies leaving them untouched (regression guard only). | HLR-004 re-read: no threshold change required — the HLR never named the regex; it requires "UTC-timestamp filename with collision counter", satisfied by LLR-004.1's own scheme. No HLR body change. | LLR-004.2 rewritten "Diff-report listing (self-contained, no shared-contract edit)"; D-5 updated with "G-4 DECIDED"; R-2 struck through as RETIRED. |
| F-3 (G-5) | OVERTURNED no-project refusal (old D-8). Added destination resolution: project-active ⇒ `<project>/reports/` (unchanged); no-project ⇒ operator path else `Path.home()/"Downloads"`. Added path-validation gate before any out-of-workarea write. New LLR-004.6, new risk R-9, new TC-025. Architect split interpretation of "ask for path or use Downloads" recorded. | HLR-004 re-read: statement CHANGED — removed "if no project is active … refuse … write no file"; added the project-active-vs-not destination resolution + "validate and resolve that path and write no file if validation fails". HLR-004 numeric threshold extended to include TC-025. | NEW LLR-004.6 "No-project destination resolution and path validation (G-5)"; LLR-004.5 retitled (no longer carries the refusal); D-8 rewritten "G-5 DECIDED"; R-9 added; HLR-004 statement + threshold updated; LLR-005.4 updated (path feedback, invalid-destination branch). |
| F-4 (G-6) | Pinned the selection surface as INLINE within the diff screen (not a modal); exact inline widget mechanism stays `assumed — verify in Phase 3`. | HLR-005 re-read: no change required — HLR-005 deliberately pins only behavior + service route (A-4/V-2 rule); UI shape lives in the AC, so the HLR statement is unaffected. | LLR-005.1 AC rewritten: "Selection surface is INLINE … not a modal (G-6 DECIDED)". |
| F-5 (G-1) | Confirmation only — 2-way scope unchanged; rationale recorded. | HLR-001/002 re-read: no change required — already specify two memory maps / two images; D-1 already defers N-way. | No §3/§4 body edit (confirmation). Rationale recorded in D-1 footer (G-1 DECIDED) and gate-confirmables block. |
| F-6 (G-3) | Confirmation only — coverage ≥ 1 semantics unchanged; rationale recorded. | HLR-003 re-read: no change required — coverage ≥ 1 ⇒ used is already the HLR-003 / LLR-003.2/003.3 semantics. | No §3/§4 body edit (confirmation). Rationale recorded in D-3 / gate-confirmables block (G-3 DECIDED). |

**Contract-touch re-check (C-9 field-set identity — mandatory because F-3 touched producer/consumer LLRs LLR-004.5/004.6/005.4):**
- Re-ran the field-set equality check across the C-9 `ComparisonResult` table vs every producer/consumer enumeration. **Result: UNCHANGED — 0 fields added, 0 removed.** G-5's destination + validation are arguments/return-side of `generate_diff_report` (a path string in, a destination path / diagnostic out via existing `diagnostics`); they do NOT add a field to `ComparisonResult`. The destination path is a report-generation concern, not part of the comparison result contract. G-4's retirement removed a `report_service` regex edit, which was never a `ComparisonResult` field. **C-9 producer/consumer table requires no edit.**
- F-1 (G-2) touches LLR-004.4 (a `notes`/`runs` consumer): best-effort annotation reads existing `runs` + `notes` fields, adds none. No C-9 change.

**Phase-1 ITERATION 3 — Phase-2 fix register + operator decision G-8 applied 2026-06-11 (body-first; each row's "Body edit landed?" cites the §3/§4 line that now exists).** Series continues F-7.. (NOT a fresh G-series — operator gate-confirmables already occupy G-1..G-8, so continuing F-* avoids ID collision).

| Decision ID | What changed | Parent HLR re-read? (which HLR + what changed, or "no change required" + why) | Body edit landed? (the §3/§4 line that now reflects it) |
|---|---|---|---|
| F-7 (M-1) | Corrected the LLR count 22 → 25 (heading count `grep -n '### LLR-'` = 25 = 5+6+4+6+4; draft baseline = 24, +1 LLR-004.6 = 25); §5.3 "22 of 22" → "25 of 25". | No HLR re-read needed — pure count-integrity fix, no threshold/statement change to any HLR; the 5-HLR / 25-LLR shape is unchanged. | §1.5 "decomposes them into 25 LLRs (24 at draft + LLR-004.6…)"; §5.3 first bullet "25 of 25". |
| F-8 (M-3) | Rewrote §5.3 suite-count reconciliation from additive `≥ 733 + N` to signed balance `post_count = 733 − D + A` (D = placeholder tests deleted, A = net-new functions; rewrite-in-place = 0/0), reconciled at Phase 4 against the I4 disposition table; hung off the MEASURED 733 (P-01). | HLR re-read: none — §5.3 is a batch-acceptance criterion, not an HLR; no requirement statement/threshold changed. | §5.3 third bullet "Suite-count reconciliation (measured baseline + signed balance…) `post_count = 733 − D + A`". |
| F-9 (M-2) | Extended R-8 + P-16 census to add `test_tc028_every_scaffold_screen_activates_without_error` (`:3628-3666`, asserts `#diff_deferral_notice` `:3656`); corrected predicted-red set 4 → 5; recorded the AST guard (`:3605`, `calls <= {Container,Label,AbDiffPanel}`) stays GREEN if `_compose_screen_diff` still only constructs `AbDiffPanel` (NOT in breaking set). Grep-verified line ranges. | HLR re-read: none — R-8 is a risk row, P-16 a probe; no HLR/LLR statement or threshold changed. The 5-test set is a Phase-4 reconciliation input, not a requirement. | §6.3 R-8 row (corrected census, 5-test predicted-red, AST-guard-green distinction + per-test disposition); §6.5 P-16 row (extended census). |
| F-10 (M-4, security) | Removed the `sanitize_project_name` path-validation citation from LLR-004.6 (it is a single-token name cleaner: `C:\Users\jjgh8\out` → `CUsersjjgh8out`, structurally not a path validator). Replaced with the concrete algorithm: `Path(operator_input).expanduser().resolve()` (collapses `..`+symlinks) → require `dest.is_dir()` else REFUSE → write `dest / <tool-generated filename>` (no operator string in the filename). `find_repo_root` dropped as the base (write dest not repo-confined); cwd is the relative-path base, mirroring `resolve_input_path` (`workspace.py:469-483`). | HLR-004 re-read: statement CHANGED — "validate and resolve that path" sharpened to "normalize and validate that directory"; the no-default wording also lands per F-12. No numeric-threshold change beyond F-12. | LLR-004.6 Statement + "Directory-validation algorithm" AC (rewritten, drops `sanitize_project_name`/`find_repo_root`, adds resolve→is_dir→tool-filename); D-8 security obligation rewritten; R-9 mitigation rewritten; HLR-004 statement "normalize and validate that directory". |
| F-11 (M-5, security) | Bound the LLR-004.1 collision counter / no-silent-overwrite guarantee into LLR-004.6 explicitly (no-project write uses the same collision discipline in the resolved dir, never overwrites). Added TC-025 sub-case (c): pre-create the target filename ⇒ a `-01` sibling is produced and the original is byte-untouched (0 overwrites). | HLR-004 re-read: no statement change required — HLR-004 already mandates "collision counter and no silent overwrite"; binding it to the no-project branch is an LLR-level tightening within the existing HLR guarantee. | LLR-004.6 Statement ("applying the SAME LLR-004.1 collision discipline… never a silent overwrite") + "No-silent-overwrite binding (M-5)" AC + numeric-threshold sub-case (c). |
| F-12 (M-6 / G-8, operator) | Applied operator decision G-8 (solo-prompt; NO implicit Downloads default). Removed `Path.home()/"Downloads"` fallback throughout; empty/invalid/non-existent-dir ⇒ REFUSE. Dropped the Downloads branch from TC-025 (now valid-dir / empty-or-invalid-refused / collision); annotated P-18 historical; G-8 moved from open question to RESOLVED. | HLR-004 re-read: statement CHANGED — removed "or, when none is supplied, the OS user Downloads directory"; now "an operator-supplied destination directory (there is no implicit default — G-8)". No numeric-threshold count change (TC-025 still the one new TC; its branches re-shaped, not added). | HLR-004 statement (no implicit default); LLR-004.6 Statement + "No implicit default (G-8)" AC + numeric threshold (b)/(c); D-8 retitled "G-8 DECIDED"; R-9 (Downloads failure mode removed); G-5/G-8 gate-confirmables rewritten (G-8 RESOLVED); P-18 historical. |
| F-13 (m-1) | Re-cited `VariantDescriptor.file_type` → `models.py:77` (field line; `:56` is the class line). Grep-verified. | No HLR re-read — citation correction only. | LLR-002.2 Statement "`VariantDescriptor.file_type` (`models.py:77` … `:56` is the class line)". |
| F-14 (m-2) | Where the rail label string matters, used the literal "A2B Diff" (`rail.py:85`, grep-verified); kept "A↔B" in prose only; demo step adds "(or rail `D` shortcut)" + literal label. | No HLR re-read — terminology/citation alignment; no statement/threshold change. | §5.1 Demo bullet (literal `"A2B Diff"` `rail.py:85` + rail `D` shortcut). Prose "A↔B" left intact in §1.1/§1.2/§2.2/HLR-005 (not string-asserting). |
| F-15 (m-3) | Replaced LLR-005.2's whole-file `rg -c PLACEHOLDER` pass-probe with the named-constant probe (`_RANGE_LIST_PLACEHOLDER\|_HEX_A_PLACEHOLDER\|_HEX_B_PLACEHOLDER\|DEFERRAL_TEXT` → 0 post-Phase-3). EXECUTED now: pre-state 8 line-hits across the 4 constants; verified the 3 whole-file survivors (`:23`/`:315`/`:322`, Bookmarks/docstring) persist. | No HLR re-read — probe-precision fix; the LLR property (placeholder no longer rendered) is unchanged. | LLR-005.2 Executed verification + numeric threshold (named-constant probe, pre-state 8, target 0); §6.5 P-07 row revised. |
| F-16 (m-4) | Split LLR-001.2 so TC-001/002/003 each own a distinct property: TC-001 classification set-equality, TC-002 adjacency-merge, TC-003 boundary cases (per the AC). | No HLR re-read — decomposition-clarity fix within the existing LLR-001.2 statement; no threshold change (set-equality threshold preserved). | LLR-001.2 "Per-TC property ownership (m-4)" AC; §5.2 LLR-001.2 row (distinct-property Notes). |
| F-17 (m-5) | Reframed LLR-004.6's "reject path traversal" to the concrete invariant: normalize via `resolve()` (already collapses `..`) → require existing dir → no operator string in the filename; defined the relative-operator-path base as the **app cwd** (cite `resolve_input_path` `workspace.py:469-483`), NOT repo root. | HLR-004 re-read: subsumed by F-10/F-12 statement change ("normalize and validate that directory"). | LLR-004.6 Statement + Rationale (cwd base, resolve()-collapses-traversal) + "Directory-validation algorithm" AC. |

**Contract-touch re-check C-9 (ITERATION 3 — mandatory because M-5/F-11 touched producer LLR-004.6, a producer of the report path/diagnostic):**
- Re-ran the field-set identity check across the C-9 `ComparisonResult` table vs every producer/consumer enumeration. **Result: UNCHANGED — 0 fields added, 0 removed.** The M-5 collision-binding adds NO `ComparisonResult` field: collision handling, the resolved destination, and the no-overwrite guarantee are all arguments/return-side of `generate_diff_report` (directory in; written-path or diagnostic out via the existing `diagnostics` channel), not part of the comparison result contract. The M-4 algorithm change and the G-8 default-removal are likewise report-generation concerns, not result fields. The canonical field set remains {`image_a`/`image_b`, `runs`, `stats`, `notes`, `diagnostics`, `refused`} = 6. **C-9 producer/consumer table requires no edit.**

**Phase-1 ITERATION 4 — I3-gate operator decisions (complete report file + HTML export + PDF dropped + cap relocation) applied 2026-06-12 (body-first; each row's "Body edit landed?" cites the §3/§4 line that now exists). Series continues F-18..; new gate decision tagged G-9 (next free G after G-8).**

| Decision ID | What changed | Parent HLR re-read? (which HLR + what changed, or "no change required" + why) | Body edit landed? (the §3/§4 line that now reflects it) |
|---|---|---|---|
| F-18 (G-9) | Amended LLR-004.3: the report FILE is COMPLETE — removed the file-level per-report run-cap, the `REPORT_MAX_TOTAL_BYTES` byte-truncation, and the in-file `TRUNCATED`-marker language from the file requirement; stated those caps are TUI-display-only, relocated to I4 (LLR-005.2). Added the Markdown ```diff fenced-block cue for `changed` runs (A bytes `-`, B bytes `+`). Kept best-effort A2L/MAC annotation (G-2, non-gating). | HLR-004 re-read: statement CHANGED — was "whole-document byte budget with explicit TRUNCATED markers"; now "each written file … COMPLETE … no run cap, no byte truncation, and no `TRUNCATED` marker", plus the format-appropriate visual cue (Markdown ```diff). Numeric threshold extended (TC-026/TC-027). | LLR-004.3 retitled "Report content (complete Markdown file)"; Statement rewritten (complete file + ```diff cue + caps-are-display-only pointer to LLR-005.2); "Per-TC property ownership (m-4)" AC (TC-018/026/027). HLR-004 statement (complete file + visual cue). |
| F-19 (G-9) | Added NEW LLR-004.7 — self-contained HTML export: same content as Markdown, inline CSS only, changed/only-A/only-B distinct colour, `html.escape` (stdlib) on ALL embedded values, NO `<script>`/external resource/font/CDN/network, COMPLETE file, own `DIFF_REPORT_HTML_FILENAME_REGEX` (NEW) + `.html`, reusing the LLR-004.1 collision + LLR-004.5 no-logging + LLR-004.6 no-project-destination machinery; shared `REPORT_FILENAME_REGEX` NOT edited (G-4). LLR count 25 → 26 (M-1). | HLR-004 re-read: statement CHANGED — was "Markdown diff report" only; now "two output formats — one Markdown file and one self-contained HTML file" with the HTML safety constraints; title "Diff report (Markdown + HTML)". Threshold extended (TC-028). | NEW LLR-004.7 "Self-contained HTML export (G-9)" (full statement, P-19 probe, threshold, ACs). HLR-004 title + statement (two formats + HTML hardening). §1.5 "26 LLRs … 5+6+4+7+4". §5.3 "26 of 26". §5.2 LLR-004.7 row + HLR-004 row. |
| F-20 (G-9) | Relocated the display caps: removed the file-bounding caps from the file requirement (F-18) and re-located them to the TUI DISPLAY render path (LLR-005.2) — they bound only what the screen shows, never the persisted files. Updated R-4 (completeness does not widen the confidentiality surface; caps are display-only). R-3 left unchanged (it is an engine memory/time risk, never referenced file truncation). | HLR-005 re-read: statement unchanged at the HLR level (it already pins "bounded hex windows … routing through the service layer"); the cap relocation is an LLR-level addition (LLR-005.2) consistent with the existing HLR bound-windows guarantee — no HLR threshold/statement change. | LLR-005.2 Statement (relocated display caps, "never the persisted report files") + "Relocated display caps (G-9)" AC (TC-029) + Executed verification/threshold (TC-029). R-4 mitigation rewritten (caps display-only, completeness scoped). HLR-005 threshold (TC-029). §5.2 LLR-005.2 + HLR-005 rows. |
| F-21 (G-9) | Recorded HLR-004 statement change (title + Markdown→Markdown+HTML + complete-file guarantee) as its own audit row per the parent-HLR re-read rule; recorded the new R-10 (HTML content-injection surface, routed to the Phase-2 security-reviewer) and PDF-dropped dormant note. | HLR-004 IS the changed parent — re-read and rewritten (title "Diff report (Markdown + HTML)"; statement now mandates a complete file in two formats with the HTML `html.escape`/no-script/no-external constraints); rationale records the cap relocation, the two visual cues, and PDF-dropped (`fpdf2` if ever). | HLR-004 title + statement + rationale (G-9 paragraph: complete file, caps relocated to I4, two visual cues, HTML second format, PDF dropped). R-10 added. |

**Contract-touch re-check C-9 (ITERATION 4 — mandatory because F-18/F-19/F-20 touched consumer LLRs LLR-004.3, the new LLR-004.7, and LLR-005.2):**
- Re-ran the field-set identity check across the C-9 `ComparisonResult` table vs every producer/consumer enumeration. **Result: UNCHANGED — 0 fields added, 0 removed.** The HTML export (LLR-004.7) is another OUTPUT FORMAT of the SAME `ComparisonResult`: like the Markdown renderer it is arg/return of the report function (a `ComparisonResult` + destination in; written `.html` path or diagnostic out via the existing `diagnostics` channel). It reads the existing `image_a`/`image_b`/`runs`/`stats`/`notes`/`diagnostics`/`refused` fields and adds none. The complete-file guarantee (F-18) and the cap relocation to the display path (F-20) are render-side concerns, not result fields. The canonical field set remains {`image_a`/`image_b`, `runs`, `stats`, `notes`, `diagnostics`, `refused`} = 6. **C-9 producer/consumer table requires no edit.**

### 6.5 Probe ledger (all EXECUTED 2026-06-11, worktree `claude/competent-clarke-1e8940`, branch `claude/batch-09`, Windows)

| ID | Probe (exact invocation) | Recorded pre-state | Regime | Positive control (in-regime) |
|---|---|---|---|---|
| P-01 | `python -m pytest -q --collect-only` (last line) | `733 tests collected in 0.51s` | full suite, no marker filter, repo venv Python, this worktree | n/a — direct measurement |
| P-02 | `Glob examples/**/*.s19` | 16 files | recursive glob from worktree root | self (16 hits = positive) |
| P-03 | `Glob examples/**/*.hex` | **0 files** | identical glob form/root as P-02 | P-02 (sibling extension, same directory tree, 16 hits) — confirms batch-08 B-1 |
| P-04 | `rg -n '"diff"' s19_app/tui/app.py` | 1 hit: `app.py:2421` (`"diff": "screen_diff"`) | literal rg over named file | self (hit) |
| P-05 | `rg -n 'RAIL_ENTRIES\|diff' s19_app/tui/rail.py` | diff entry exists: `rail.py:85`; RAIL_ENTRIES at `:78` (8 entries) | rg over named file | self (hit) — **no new rail entry needed** |
| P-06 | `rg -n 'AbDiffPanel' s19_app/tui/screens_directionb.py s19_app/tui/app.py` | class at `screens_directionb.py:849`; imported `app.py:58`, composed `app.py:1897` | rg over named files | self (hits); memory anchor `~:1334` confirmed STALE |
| P-07 | (revised m-3) named-constant probe `rg -n '_RANGE_LIST_PLACEHOLDER\|_HEX_A_PLACEHOLDER\|_HEX_B_PLACEHOLDER\|DEFERRAL_TEXT' s19_app/tui/screens_directionb.py` | **8 line-hits** across the 4 named diff constants (defs `:882`/`:888`/`:894`/`:900` + composed usages `:929`/`:935`/`:936`/`:937`). Companion whole-file `rg -c 'PLACEHOLDER'` = **15** but is NOT the pass-probe (3 unrelated survivors at `:23`/`:315`/`:322` never reach 0). | literal rg, file-level; AbDiffPanel block `:849-939` | self (8 > 0) — pass condition post-Phase-3: **0** hits of the named-constant probe (LLR-005.2); the 3 whole-file survivors are expected to remain |
| P-08 | `rg -n 'mem_map ==' tests/` | 11 hits — all whole-map equality assertions | rg over tests tree | self (hits) — confirms no run-extraction diff exists today (engine genuinely NEW) |
| P-09 | `rg -n 'REPORT_FILENAME_REGEX' tests/` | 3 hits: `tests/test_report_service.py:66,301,302` | rg over tests tree | self (hits) — LLR-004.2 contract-touch blast radius |
| P-10 | `rg -c 'textual\|S19File\|IntelHexFile' s19_app/range_index.py` | 0 hits | **target regime of NEW `s19_app/compare.py`**: package-root headless module file | positive control: same pattern on `s19_app/tui/screens_directionb.py` → hits (`from textual` at `:47-48`) |
| P-11 | `rg -c 'getLogger' s19_app/tui/services/report_service.py` | 0 hits (no-logging precedent) | **target regime of NEW `diff_report_service.py`**: `s19_app/tui/services/` module file | positive control: `rg -n 'getLogger' s19_app/tui/workspace.py` → `workspace.py:60` (same package) |
| P-12 | `ls examples/case_00_public/ examples/case_01_basic_valid/` | `case_00_public` holds `prg.s19` + `s19_sample.s19` (two S19s, one dir); `case_01_basic_valid` holds `firmware.s19` + `firmware.a2l` + `firmware.mac` (full triple) | directory listing, worktree | self (listings non-empty) — AC fixture-existence evidence for LLR-002.2 / LLR-003.1 |
| P-13 | `rg -n 'should' .dev-flow/2026-06-11-batch-09/01-requirements.md` scoped to §3/§4 Statement lines | 0 `should` inside any HLR/LLR Statement (all remaining `should` occurrences sit in the normative header's quoted rules and informative prose) | literal rg over this document at draft close | positive control: the header itself contains `should` (rule prose), proving the probe matches |
| P-14 | `python -m pytest -q -m "not slow" --collect-only` (last line) — qa-reviewer | `713/733 tests collected (20 deselected)` | lean filter, same env as P-01 | P-01 (733 full = superset). NOTE: batch-08 close recorded 681 lean / 701 full PASSED — pass-vs-collect delta (~20-32) is platform skips + deselects; **Phase 4 must establish the actual passed/skipped split, not assume 681/701** |
| P-15 | Timed perf probe (scratch `_qa_perf_probe.py`, deleted after) — qa-reviewer: parse 2× default `make_large_s19` (200 ranges × 4096 B, file 2,406,438 B, 819,206 mapped bytes/image), then dict-eq + full key-union classify walk + sort | parse 165-172 ms/file; `get_memory_map()`×2 94.8 ms; dict-eq equal 9.06 ms / unequal 0.00 ms; **classify walk 201.7 ms** (819,209-key union); sort 4.7 ms. Correctness cross-check: planted 5 changed + 3 only-in-B reported EXACTLY | Win 11 Pro 10.0.26200, Python 3.14.4, OneDrive-synced worktree, single run, `perf_counter`, no warmup | self (planted-set exactness = the probe's own positive control). **Fixture caveat (executed finding):** planted addresses MUST be sampled from `sorted(mem_map)` — arbitrary offsets land in generator gaps (`gap_bytes=0x100` between ranges → KeyError) |
| P-16 | `rg -n` census of placeholder-pinned tests in `tests/test_tui_directionb.py` — qa-reviewer, **extended M-2 (2026-06-11, line ranges grep-verified)** | TC-027 family at `:3383-3487` (4 functions: three-column placeholder, static rows, no-second-file-load, panel-holds-no-data) + `test_tc028_every_scaffold_screen_activates_without_error` at `:3628-3666` asserting `#diff_deferral_notice` PRESENT at `:3656` (pins `DEFERRAL_TEXT`, OUTSIDE the TC-027 range) ⇒ **corrected predicted-red set = 5**. The AST guard `test_tc028_diff_renderer_invokes_no_diff_logic` (`:3605`, assertion `:3622` `calls <= {Container, Label, AbDiffPanel}`) is verified to stay GREEN if the rewritten `_compose_screen_diff` still constructs only `AbDiffPanel` — NOT in the breaking set. | rg over the named test file | self (hits) — feeds risk R-8: supersession enacted + dispositioned at the I4 gate |
| P-17 | `Grep "def (sanitize_project_name\|resolve_input_path\|find_repo_root)" s19_app/tui/workspace.py` (iteration 2, G-5 helper citations) | `sanitize_project_name` `:315`, `find_repo_root` `:457`, `resolve_input_path` `:469` | rg over named file | self (3 hits) — backs LLR-004.6 ACs; `resolve_input_path` body read `:469-483` confirms it returns only *existing read* paths (unsuitable as a write-dest validator) |
| P-18 | `Grep "Path\.home\|Downloads" s19_app/` (iteration 2, G-5 Downloads default) | **0 hits** | recursive rg over the package | **HISTORICAL (G-8, 2026-06-11):** the Downloads default this probe backed was DROPPED at the Phase-2 gate (solo-prompt, no implicit default — LLR-004.6). The probe stands as recorded but its target (`Path.home()/"Downloads"`) is no longer specified, so the cross-platform Downloads concern (original gate-confirmable G-8) is MOOT. Retained for audit trail; not a live verification. |
| P-19 | (iteration 4, G-9 HTML-safety) (a) `python -c "import html; print(html.escape('<a href=\"x\">&'))"`; (b) external-resource grep `rg -c '<script\|https?://\|@import\|src=\|url\(' <file>` | (a) `html.escape` stdlib present → `&lt;a href=&quot;x&quot;&gt;&amp;`; (b) on real `s19_app/tui/services/report_service.py` → **0 hits** (clean pre-state) | EXECUTED 2026-06-12, target regime = `s19_app/tui/services/` service-layer module/`.html` (depth of NEW `diff_report_service.py` HTML output) | **IN-REGIME synthetic positive control** (batch-08 `_b2_scratch` pattern): scratch `s19_app/tui/services/_p19_scratch.html` at target depth containing `<script src="https://cdn.example.com/x.js">` + `@import url("https://…")` → **2 hits**; negative control on real `report_service.py` → 0 hits; scratch removed. Backs LLR-004.7 / R-10 (post-Phase-3 pass = 0 hits on the generated `.html`). |
