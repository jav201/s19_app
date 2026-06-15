# Requirements Document — s19_app — Batch 2026-06-13-batch-10

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
This document specifies the requirements for batch-10 of `s19_app`: an **Intel HEX writer** (US-008) and a **verify-on-save** check (US-009) for the Textual TUI. The repository can *read* Intel HEX (`s19_app/hexfile.py::IntelHexFile`) but cannot *write* it — only Motorola S19 emission exists (`s19_app/tui/changes/io.py::emit_s19_from_mem_map`, line 1298). This batch closes that asymmetry and adds post-write certainty by re-reading the written file and diffing it against the intended memory map with the batch-09 compare engine (`s19_app/compare.py::diff_mem_maps`, line 272).

### 1.2 Scope
**In scope (TUI only):**
- A headless, pure `mem_map -> Intel HEX text` emitter (US-008), symmetric to the existing S19 emitter, supporting Intel HEX data records (type 0x00), extended-linear-address records (type 0x04) for addresses above 0xFFFF, and the EOF record (type 0x01), each with the Intel HEX two's-complement-of-the-sum checksum.
- Extending the TUI save-back path (`save_patched_image` / `ChangeService.save_patched`) so a HEX-loaded image (`LoadedFile.file_type == "hex"`) can be persisted as Intel HEX — retiring the current `CHG-HEX-SAVE-UNSUPPORTED` refusal (`apply.py:86`).
- A verify-on-save check (US-009): after a write, re-read the written file with its format's parser and diff the re-read memory map against the intended memory map via `compare.py::diff_mem_maps`; surface a quiet pass indicator and a loud notice/report only on mismatch.
- Folded hygiene: N-3 (`load_buttons` widget-id reuse across six modal screens, `screens.py:82,132,191,257,393,556`) and the `OperationsScreen._execute_selected` `except KeyError` scoping (`screens.py:617-622`) — both fold into the TUI-touching increment.

**Out of scope (NOT this batch):** the CLI (operator: unmaintained, deferred — zero CLI LLRs); the `project.json` manifest writer; E2E pilot / perf-knee test; the CRC first-operation fill-in (postponed by operator 2026-06-13); **variant-execution HEX persist** — the `variant_execution_service.py:724-728` branch that currently appends "HEX save-back not supported this batch" remains REFUSED this batch (US-008's HEX save-back lands only on the interactive save-back path of A3; the variant-batch persist path is not rewired here).

### 1.3 Definitions, acronyms, abbreviations
| Term | Definition |
|------|------------|
| Intel HEX | ASCII firmware format; records `:LLAAAATT[DD..]CC` with two's-complement-of-sum checksum. Record types used here: 0x00 data, 0x01 EOF, 0x04 extended linear address (ELA). Read by `IntelHexFile` (`hexfile.py:20`). |
| ELA record | Extended Linear Address (type 0x04): sets the upper 16 bits of the 32-bit address; emitted whenever the active upper-16 changes (`hexfile.py:118-134` is the reader half). |
| S19 / S-record | Motorola firmware format; the format the repo already emits (`emit_s19_from_mem_map`, `io.py:1298`). |
| mem_map | Sparse `Dict[int, int]` address→byte map; the canonical image representation produced by every parser and consumed by every emitter. |
| verify-on-save | Re-read the just-written file and diff its mem_map against the intended mem_map; the certainty check of US-009. |
| diff run | A maximal contiguous address span sharing one classification (`changed`/`only_a`/`only_b`); the `DiffRun` of `compare.py:100`. |
| save-back | The post-apply persist flow: `PatchEditorPanel.SaveBackDecision` (`screens_directionb.py:462`) → `app.py:1364` → `ChangeService.save_patched` (`change_service.py:806`) → `save_patched_image` (`apply.py:558`). |

### 1.4 References
- `CLAUDE.md` (project), `PROJECT_RULES.md`, `REQUIREMENTS.md` (R-* traceability).
- batch-09 `.dev-flow/2026-06-11-batch-09/01-requirements.md` — compare engine (R-CMP-001), P-15 perf measurement (line 249), diff-report service.
- batch-07 D-1 / F-A-05: the S19-only save-back decision this batch supersedes for HEX.
- IEEE 830 + EARS normative header (this document, lines 3–50).

### 1.5 Document overview
§2 overall description and the source user stories (US-008/US-009). §3 high-level requirements. §4 low-level requirements (TUI only). §5 validation strategy + measured collection-baseline reconciliation. §6 design decisions (incl. the two delegated decisions D-A, D-B), risks, gate-confirmables, the cross-cutting contract, and the Phase-3 increment plan.

---

## 2. Overall description

### 2.1 Product perspective
The system has three layers (parsers → range/validation engine → TUI services + view). This batch adds one **emitter** at the parsing/format layer (mirroring `emit_s19_from_mem_map`) and one **verify-on-save** step in the **service** layer (`change_service` / `apply`), surfacing through the existing save-back UI in `app.py`. It is the **first downstream consumer of the batch-09 `compare.py` engine** outside the comparison feature: US-009 calls `diff_mem_maps` to diff intended-vs-reread maps. No new rail entry, no new screen — the work extends the existing save-back surface (`PatchEditorPanel.SaveBackDecision`, `screens_directionb.py:462`).

### 2.2 Product functions
1. Serialize a `mem_map` (+ ranges) into structurally valid Intel HEX text — data records, ELA records above 0xFFFF, EOF record, correct per-record checksum (US-008).
2. Persist a HEX-loaded image as Intel HEX through the save-back path, retiring the `CHG-HEX-SAVE-UNSUPPORTED` refusal for HEX sources (US-008).
3. After any write, re-read the file with its format parser and diff the re-read map against the intended map; report a quiet pass and a loud mismatch (US-009).
4. Hygiene: de-collide the `load_buttons` widget id across modal screens; tighten the `OperationsScreen` `except KeyError` so it only catches the registry-lookup miss it documents.

### 2.3 User characteristics
Single role: the **s19tool operator** — a firmware/calibration engineer using the TUI to load, inspect, patch, and persist S19/HEX images. Expert in the file formats; expects faithful round-trips and explicit failure surfacing (collect-don't-abort), not silent clobbers. CLI users are explicitly out of focus this batch.

### 2.4 Constraints
- **Headless-purity (hard).** The HEX emitter and the verify step are reached transitively from `services/change_service.py`, which is guarded by `tests/test_checks_engine.py::test_no_textual_in_static_import_graph` (line 400) — a static import-graph walk that fails if ANY reachable `s19_app` source imports `textual`/`textual.*`. The emitter MUST import stdlib only (the `compare.py` precedent, headless since `compare.py:27`).
- **No new third-party deps.** `tests/test_tui_directionb.py::test_tc028_processing_libs_absent_from_pyproject` (line 3583) forbids `bincopy`/`pya2l`/`crcmod`. The Intel HEX writer is hand-rolled (the S19 emitter precedent), not a library.
- **No silent overwrite.** Writes go through `workspace.copy_into_workarea` (`workspace.py:215`), which dedup-suffixes name collisions — preserve this (the `save_patched_image` contract, `apply.py:672`).
- **Containment.** Save targets must lie inside a `.s19tool/workarea/` tree (`MF-WRITE-CONTAINMENT`, `apply.py:658`). Preserve.
- **Package-root allowlist (census, see §6.3 R-10-CENSUS).** `tests/test_tui_directionb.py` lines 3191 & 3565 allowlist exactly 8 root modules; a new package-root module trips both — bears directly on D-A.

### 2.5 Assumptions and dependencies
- **A1 — compare.py is stable and reusable as-is.** `diff_mem_maps(map_a, map_b) -> (List[DiffRun], DiffStats)` (`compare.py:272`) is pure over two `Dict[int, int]` and needs no change for US-009. *If false (engine signature changes), US-009 LLRs are invalidated.*
- **A2 — IntelHexFile is the canonical re-read path for HEX.** `IntelHexFile(path).memory` (`hexfile.py:25`) + `.get_errors()` (line 173) re-read a written HEX file; `S19File(path).get_memory_map()` does the same for S19. The verify step re-reads with the parser matching the just-written format.
- **A3 — The save-back path is the only persist surface this batch touches.** `app.py:1364` → `change_service.save_patched` (`change_service.py:806`) → `save_patched_image` (`apply.py:558`). No other write entry point is in scope.
- **A4 — `LoadedFile.file_type` discriminates `"s19"`/`"hex"`/`"mac"`** (`models.py:17,39`) and is the source for choosing the emitter and the re-read parser.
- **A5 — examples/ contains zero `.hex` files** (`Glob examples/**/*.hex → 0 files, 2026-06-14`; 16 `.s19` present). Any HEX fixture an AC needs is created by the round-trip itself or flagged `NEW`. *(batch-08 B-1 trap.)*
- **Dependency:** the batch-09 compare engine merged on `claude/batch-09` (this worktree's branch).

### 2.6 Source user stories

> Connextra format: **"As a `<role>`, I want `<goal>`, so that `<benefit>`"**.
> Each US gets a unique ID `US-NNN` and must be traceable to one or more HLRs.

| ID | User Story | Source |
|----|------------|--------|
| US-008 | As an s19tool operator, I want to save a loaded/edited image to an Intel HEX file (the format the repo cannot currently write — only S19 emission exists), so that HEX images can be persisted, not just read. | Operator, batch-10 core (2026-06-13). Closes the batch-07 D-1 / F-A-05 gap (no Intel HEX writer in `hexfile.py`). |
| US-009 | As an s19tool operator, I want a verify-on-save check that, after writing an image, re-reads the written file and diffs it against the intended memory map (reusing the batch-09 `compare.py` engine), so that I have certainty the persisted file faithfully represents what I meant to save — and a report/notice if it does not. | Operator, batch-10 core (2026-06-13). First downstream consumer of the batch-09 compare engine (post-mortem A-7 / batch-10 slate). |

> **Scope notes (informative):** Hygiene N-3 (`load_buttons` widget-id reuse in `OperationsScreen`) + the `OperationsScreen._execute_selected` `except KeyError` scoping are folded into whichever increment touches the TUI. **Queued, NOT in this batch:** the `project.json` manifest writer; optional E2E pilot / perf-knee test. **Postponed by operator decision (2026-06-13):** the CRC first-operation fill-in — deferred to a later batch, not batch-10. Numbering: US-006 (batch-09) and US-007 (batch-08) are consumed; this batch takes US-008/US-009.

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

### HLR-001 — Intel HEX emitter (headless, pure)
- **Traceability:** US-008
- **Statement:** When given a memory map and its contiguous ranges, the system shall serialize them into structurally valid Intel HEX text — data records (type 0x00), extended-linear-address records (type 0x04) whenever the active upper-16 address changes, and a terminating EOF record (type 0x01) — such that re-parsing the emitted text via `s19_app.hexfile.IntelHexFile` reconstructs a memory map equal to the input with zero load errors.
- **Rationale (informative):** The repo can read Intel HEX but cannot write it (`hexfile.py` has no writer; grep `def (write|emit|save|dump|serialize|from_mem)` in `hexfile.py` → 0 hits, 2026-06-14). This is the symmetric counterpart to `emit_s19_from_mem_map` (`io.py:1298`). Round-trip equality is the same acceptance contract the S19 emitter uses (its Data Flow "Acceptance contract" line, `io.py:1337-1339`).
- **Validation:** test
- **Executed verification:** `pytest tests/test_hex_emit.py -q` *(implemented: 7 functions / 10 nodes — see §5.2; node-id map per 04-validation §1)* [Phase-6 reconciliation per 04-validation DEV-2: provisional flag retired — `tests/test_hex_emit.py` exists on disk with the listed nodes]; the round-trip property `IntelHexFile(write(emit(mem))).memory == mem` over hand-built and large generated maps.
- **Numeric pass threshold:** exit code 0; round-trip mem_map equality holds for 100 % of cases incl. an address span > 0xFFFF that forces ≥ 1 ELA record; 0 `IntelHexFile` load errors on every emitted file.
- **Priority:** high

### HLR-002 — HEX save-back (retire the HEX-unsupported refusal)
- **Traceability:** US-008
- **Statement:** When the operator confirms a save-back for an image whose `LoadedFile.file_type` is `"hex"`, the system shall persist the post-apply image as Intel HEX text into the active project work area through the existing containment + no-silent-overwrite machinery, instead of refusing with `CHG-HEX-SAVE-UNSUPPORTED`.
- **Rationale (informative):** The current `save_patched_image` refuses any non-`"s19"` source (`apply.py:636-646`). US-008 makes HEX a first-class persist format. Containment (`MF-WRITE-CONTAINMENT`, `apply.py:658`) and dedup-on-collision (`copy_into_workarea`, `workspace.py:215`) are reused unchanged.
- **Validation:** test
- **Executed verification:** `pytest tests/test_changes_apply.py -q` (implemented nodes `test_hex_save_writes_hex_file_that_reparses_to_post_apply_map`, `test_hex_save_forces_hex_suffix_when_name_lacks_it`, `test_s19_save_still_forces_s19_suffix`, `test_hex_save_adversarial_filenames_contained_or_refused`) [Phase-6 reconciliation per 04-validation DEV-1/DEV-2: provisional `-k "hex_save"` replaced with the real implemented node ids, all grep-verified on disk]; assert a HEX-loaded image writes a `.hex` file inside `.s19tool/workarea/` and the file re-reads to the intended map.
- **Numeric pass threshold:** exit code 0; a `"hex"` source produces exactly one written `.hex` file with 0 refusal issues; a containment violation still produces 0 writes + 1 `MF-WRITE-CONTAINMENT` issue.
- **Priority:** high

### HLR-003 — Verify-on-save (re-read + diff via compare.py)
- **Traceability:** US-009
- **Statement:** When a save-back has written a file, the system shall re-read the written file with the parser matching its format, diff the re-read memory map against the intended memory map using `s19_app.compare.diff_mem_maps`, and return a verify result that is `verified` when the diff is empty and `mismatch` (carrying the diff runs/stats) otherwise.
- **Rationale (informative):** Closes the certainty gap: an emitter bug, a truncation, or a checksum error would otherwise persist silently. The diff is cheap relative to the parse (P-15: diff-only ~215 ms vs full re-read ~165–172 ms/file on an 819 K-byte image, batch-09 01-requirements.md:249), so verifying every save is affordable. First downstream use of the compare engine.
- **Validation:** test
- **Executed verification:** `pytest tests/test_verify_on_save.py -q` (implemented nodes `test_identity_write_is_verified`, `test_mutated_byte_is_mismatch_changed`, `test_dropped_byte_is_mismatch_only_a`, `test_unsupported_file_type_raises`, `test_written_path_is_stamped`) [Phase-6 reconciliation per 04-validation DEV-3: provisional flag retired — file exists on disk with the listed nodes]; a faithful write yields an empty diff (`verified`); a deliberately corrupted re-read yields a non-empty diff (`mismatch`) with the corrupted run present.
- **Numeric pass threshold:** exit code 0; faithful write → `run_counts` all zero and status `verified`; one-byte MUTATION (wrong value, same address) → `len(runs)==1 and runs[0].kind=="changed" and runs[0].length==1` (property read; `DiffRun` fields are `(start,end,kind)` at `compare.py:100`, `length` is the read-only `@property` at `compare.py:138` — NOT a constructor field) and status `mismatch`.
- **Priority:** high

### HLR-004 — Mismatch surfacing (quiet pass, loud mismatch)
- **Traceability:** US-009
- **Statement:** While a save-back completes, the system shall surface a concise "saved + verified" status line on a clean verify and, on a verify mismatch, shall surface a prominent notice naming the file and the mismatch summary (run/byte counts), without aborting the save the operator already requested.
- **Rationale (informative):** Hybrid trigger (D-B option 3): verify always runs, but only a mismatch interrupts the operator's attention. The file is still written (collect-don't-abort) so the operator can inspect it; the notice tells them not to trust it. Reuse of the batch-09 `diff_report_service` for an on-disk mismatch report is evaluated in §6.2 D-B and deferred (informative).
- **Validation:** demo
- **Executed verification:** observe the TUI save-back under (a) a faithful write and (b) an injected emitter fault: confirm (a) shows a single "saved + verified" line and no modal/notice, (b) shows a prominent mismatch notice naming the file + run/byte counts.
- **Numeric pass threshold (qualitative criterion for `demo`):** clean save shows the verified status and NO mismatch notice; faulty save shows the mismatch notice with the file name and non-zero run count, and the file still exists on disk.
- **Priority:** medium

### HLR-005 — Folded TUI hygiene (N-3 + KeyError scoping)
- **Traceability:** US-008, US-009 *(folds into the TUI-touching increment per the scope note)*
- **Statement:** Where the batch touches the TUI modal screens, the system shall give each modal's button row a screen-unique widget id (eliminating the `load_buttons` id reused across six screens) and shall scope the `OperationsScreen._execute_selected` `except KeyError` to only the `run_operation` registry-lookup miss it documents, so a `KeyError` raised inside operation execution is not silently swallowed.
- **Rationale (informative):** The `load_buttons` id appears on six distinct screens (`screens.py:82,132,191,257,393,556`); Textual widget ids should be unique within a screen and the duplication risks cross-screen query ambiguity. The `except KeyError` at `screens.py:619` wraps the whole `run_operation` call (`screens.py:617-622`), so a `KeyError` from inside the operation's own logic would be misreported as "unknown operation".
- **Validation:** inspection
- **Executed verification:** inspect `screens.py` after the change — `rg -n 'id="load_buttons"' s19_app/tui/screens.py` returns the per-screen unique ids (0 remaining literal `load_buttons` duplicates across screens), and `_execute_selected` narrows the `try` to the registry resolution only.
- **Numeric pass threshold (observable condition for `inspection`):** 0 occurrences of a `load_buttons` id shared by two screens; the `except KeyError` guards only the registry-lookup expression.
- **Priority:** low

---

## 4. Low-level requirements (LLR)

> Each LLR decomposes an HLR into a verifiable property at the implementation level.
> Same EARS regime. ID format: `LLR-<HLR>.<M>`.

> **Symbol-citation key for this batch:**
> - `emit_intel_hex_from_mem_map` — **NEW — created in Phase 3** (the HEX emitter; D-A places it in `s19_app/tui/changes/io.py`, next to `emit_s19_from_mem_map` — REVERSED from hexfile.py after the engine-frozen blocker, see §6.2 D-A).
> - `_intel_hex_record` / `_emit_ela_record` — **NEW — created in Phase 3** (private record builders, mirroring `_s19_record` at `io.py:1370`).
> - `verify_written_image` — **NEW — created in Phase 3** (the verify-on-save helper).
> - `VerifyResult` — **NEW — created in Phase 3** (the verify outcome dataclass; §6.2 contract C-10).
> - Existing, grep-verified: `emit_s19_from_mem_map` (`io.py:1298`); `save_patched_image` (`apply.py:558`); `CHG_HEX_SAVE_UNSUPPORTED` (`apply.py:86`); `IntelHexFile` (`hexfile.py:20`), `.memory` (`hexfile.py:25`), `.get_ranges` (`hexfile.py:176`), `.get_errors` (`hexfile.py:173`); `S19File.get_memory_map` (referenced `test_compare_service.py:142`); `diff_mem_maps` (`compare.py:272`), `DiffRun` class (`compare.py:100`; `.length` `@property` `compare.py:138`), `DiffStats` class (`compare.py:150`), `DIFF_KIND_DOMAIN` (`compare.py:53`); `ChangeService.save_patched` (`change_service.py:806`); `copy_into_workarea` (`workspace.py:215`); `LoadedFile.file_type` (`models.py:39`); `OperationsScreen._execute_selected` (`screens.py:577`); `operation_resolver` seam (`operation_service.py:35`); `_sanitize_s19_filename` (`apply.py:691`); `IntelHexFile.records` (`hexfile.py:23`), `HexRecord.record_type` (`hexfile.py:12`; parsed `hexfile.py:45`, type-0x04 branch `hexfile.py:118`).

### LLR-001.1 — Emitter purity and signature
- **Traceability:** HLR-001
- **Statement:** The `emit_intel_hex_from_mem_map(mem_map: dict[int, int], ranges: list[tuple[int, int]]) -> str` function *(NEW — created in Phase 3, placed in `s19_app/tui/changes/io.py` per D-A, next to `emit_s19_from_mem_map`)* shall import no Textual symbol and shall consume only the passed memory map and ranges, returning Intel HEX text with no I/O side effect.
- **Validation:** test (unit)
- **Executed verification:** `pytest tests/test_checks_engine.py::test_no_textual_in_static_import_graph` *(existing, `test_checks_engine.py:400`)* + a new AST/`rg` purity assertion on `io.py` using the V-4 form `rg -n "import textual|from textual" s19_app/tui/changes/io.py` *(probe P-1, see ledger §6.3)*.
- **Numeric pass threshold:** exit code 0; `rg "import textual|from textual" s19_app/tui/changes/io.py` → 0 matches; the static-import-graph walk reports 0 offenders.
- **Acceptance criteria (informative):**
  - The function signature mirrors `emit_s19_from_mem_map` (`io.py:1298`): `(mem_map, ranges) -> str`.
  - `io.py` remains free of any `textual` import *(probe P-1 pre-state: 0 matches today, `s19_app/tui/changes/io.py` — executed 2026-06-14; whole-file regime, same as the prior hexfile.py probe, valid because io.py imports no textual at all)*.

### LLR-001.2 — Data records, 16 bytes/row, correct checksum
- **Traceability:** HLR-001
- **Statement:** The emitter shall emit type-0x00 data records covering every address in `ranges`, ≤ 16 data bytes per record, each record carrying the Intel HEX checksum equal to the two's complement of the low byte of `(byte_count + addr_hi + addr_lo + record_type + sum(data))`.
- **Validation:** test (unit)
- **Executed verification:** `pytest tests/test_hex_emit.py::test_data_records_max_16_bytes_and_checksum -q` [Phase-6 reconciliation per 04-validation DEV-2: provisional `-k "data_record or checksum"` replaced with the real node id, grep-verified at `tests/test_hex_emit.py:83`]; re-parse each emitted file with `IntelHexFile` and assert 0 checksum errors via `.get_errors()`.
- **Numeric pass threshold:** exit code 0; `IntelHexFile(...).get_errors()` is empty for every emitted file; no data record exceeds 16 data bytes.
- **Acceptance criteria (informative):**
  - The checksum formula matches the reader's verification at `hexfile.py:66-74` (a record the emitter writes re-reads as `valid`).

### LLR-001.3 — Extended-linear-address records above 0xFFFF
- **Traceability:** HLR-001
- **Statement:** The emitter shall emit a type-0x04 extended-linear-address record carrying the upper-16 bits whenever the active upper-16 of the next data record's address differs from the currently established upper-16 (including the first data record above 0xFFFF), so that every emitted data address re-reads at its intended 32-bit address.
- **Validation:** test (unit)
- **Executed verification:** `pytest tests/test_hex_emit.py::test_ela_high_address_roundtrip tests/test_hex_emit.py::test_ela_record_emitted_per_upper16_change -q` [Phase-6 reconciliation per 04-validation DEV-2: provisional `-k "ela or extended or above_64k"` replaced with the two real node ids, grep-verified at `tests/test_hex_emit.py:103,121`]; emit a map spanning `0x8003_0000..0x8004_0010`, assert `IntelHexFile(...).memory` equals the input map, AND assert the ELA-record count via the parser oracle (NOT a string scan): `sum(1 for r in IntelHexFile(written).records if r.record_type == 0x04) >= 1` (`IntelHexFile.records` `hexfile.py:23`, `HexRecord.record_type` `hexfile.py:12`, the type-0x04 reader branch `hexfile.py:118`).
- **Numeric pass threshold:** exit code 0; `sum(r.record_type==0x04 for r in IntelHexFile(written).records) >= 1` for the > 0xFFFF span; re-read mem_map equality 100 %.
- **Acceptance criteria (informative):**
  - The reader half this round-trips against is `hexfile.py:118-134` (type-0x04 handling).

### LLR-001.4 — EOF record and round-trip equality
- **Traceability:** HLR-001
- **Statement:** The emitter shall terminate the output with exactly one type-0x01 EOF record (`:00000001FF`), and the complete emitted text, written to a file and re-parsed by `IntelHexFile`, shall reconstruct a memory map equal to the input mem_map.
- **Validation:** test (unit)
- **Executed verification:** `pytest tests/test_hex_emit.py::test_empty_mem_map_emits_eof_only tests/test_hex_emit.py::test_output_terminates_with_single_eof tests/test_hex_emit.py::test_public_example_roundtrips_as_hex -q` [Phase-6 reconciliation per 04-validation DEV-2: provisional `-k "roundtrip or eof"` replaced with the three real node ids, grep-verified at `tests/test_hex_emit.py:138,150,161`]; round-trip over hand-built maps and the public-example-derived map.
- **Numeric pass threshold:** exit code 0; output ends with one EOF record; `IntelHexFile(written).memory == input_mem` for 100 % of cases; 0 load errors.
- **Acceptance criteria (informative):**
  - Mirrors the S19 emitter's round-trip acceptance contract (its Data Flow "Acceptance contract" line, `io.py:1337-1339`).
  - Empty input (`{}`, `[]`) emits just the EOF record and re-reads to `{}`.

### LLR-002.1 — HEX branch in the save engine
- **Traceability:** HLR-002
- **Statement:** `save_patched_image` (`apply.py:558`) shall, when `source_kind == "hex"`, serialize the image with `emit_intel_hex_from_mem_map`, force a `.hex` suffix on the sanitized filename, stage and place it via the existing `copy_into_workarea` containment path, and return the written path with zero refusal issues.
- **Validation:** test (integration)
- **Executed verification:** `pytest tests/test_changes_apply.py::test_hex_save_writes_hex_file_that_reparses_to_post_apply_map tests/test_changes_apply.py::test_hex_save_forces_hex_suffix_when_name_lacks_it tests/test_changes_apply.py::test_s19_save_still_forces_s19_suffix tests/test_changes_apply.py::test_hex_save_adversarial_filenames_contained_or_refused -q` [Phase-6 reconciliation per 04-validation DEV-1: provisional `-k "hex_save"` replaced with the real node ids, grep-verified at `tests/test_changes_apply.py:424,453,472,499`]; assert a `"hex"` source writes one `.hex` file under `.s19tool/workarea/` and re-reads to the intended map.
- **Numeric pass threshold:** exit code 0; exactly one `.hex` file written; 0 issues of code `CHG-HEX-SAVE-UNSUPPORTED` for a `"hex"` source.
- **Acceptance criteria (informative):**
  - The `.s19` path for `source_kind == "s19"` is unchanged, AND `save_patched_image`'s 2-tuple return `(Optional[Path], List[ValidationIssue])` (`apply.py:564`) is PRESERVED unchanged — so the existing `test_changes_apply.py::test_save_back*` 2-tuple unpack sites (`tests/test_changes_apply.py:330,376,394`, all `saved_path, issues = save_patched_image(...)`) stay green with no edit. The `VerifyResult` rides the separate C-10 carrier, not a widened tuple.
  - Filename sanitization stays in ONE place: the single `_sanitize_s19_filename` (`apply.py:691`) gains a parametric `suffix` argument (default `.s19`, passed `.hex` on the HEX branch) — the traversal / reserved-device-name / trailing-dot rejection rules remain unforked in that one function (F-S-01); it still rejects reserved/empty names for `.hex` too.

### LLR-002.2 — Retire CHG-HEX-SAVE-UNSUPPORTED for HEX sources
- **Traceability:** HLR-002
- **Statement:** `save_patched_image` shall no longer emit a `CHG-HEX-SAVE-UNSUPPORTED` issue for a `source_kind` of `"hex"`; the issue code shall remain defined and shall continue to refuse any source that is neither `"s19"` nor `"hex"` (e.g. `"mac"`).
- **Validation:** test (integration)
- **Executed verification:** `pytest tests/test_changes_apply.py::test_save_back_unsupported_source_refused_with_clear_issue -q` [Phase-6 reconciliation per 04-validation DEV-1: provisional `-k "hex_save or unsupported_source"` replaced with the real node id, grep-verified at `tests/test_changes_apply.py:395` (the existing TC-006 test, extended this batch to cover both the retired-for-hex and still-refused-for-mac paths)]; a `"hex"` source → 0 such issues; a `"mac"` source → exactly 1 such issue + 0 writes.
- **Numeric pass threshold:** exit code 0; `"hex"` → 0 `CHG-HEX-SAVE-UNSUPPORTED`; `"mac"` → 1 `CHG-HEX-SAVE-UNSUPPORTED` + 0 files.
- **Acceptance criteria (informative):**
  - `CHG_HEX_SAVE_UNSUPPORTED` (`apply.py:86`) stays in `__all__` (no contract removal); its message updates to name the still-unsupported sources.

### LLR-002.3 — Format selection by file_type in the save-back surface
- **Traceability:** HLR-002
- **Statement:** The save-back flow (`app.py:1364` → `change_service.save_patched`, `change_service.py:806`) shall pass `source_kind=loaded.file_type` and shall suggest a default filename whose suffix matches the loaded format (`.hex` for a `"hex"` image, `.s19` for an `"s19"` image).
- **Validation:** test (integration)
- **Executed verification:** `pytest tests/test_tui_patch_editor_v2.py::test_save_back_suggestion_is_format_aware -q` [Phase-6 reconciliation per 04-validation DEV-4: provisional `tests/test_change_service.py -k "hex_suffix or save_patched_hex"` replaced — the format-aware-suffix coverage was realized at the TUI save-back layer (`tests/test_tui_patch_editor_v2.py:731`, grep-verified), NOT the service layer; the LLR-002.3 threshold is unchanged and still met. The service-layer `test_change_service.py` nodes added this batch instead cover the verify-result carrier (`test_hex_save_stamps_verified_result_on_summary` :242, `test_refused_save_leaves_verify_result_none` :271)]; assert the suggested filename suffix tracks the loaded format.
- **Numeric pass threshold:** exit code 0; a `"hex"` image's suggested name ends `.hex`; an `"s19"` image's ends `.s19`.
- **Acceptance criteria (informative):**
  - Today's suggestion is hard-coded `"{variant_id}-patched.s19"` (`app.py:1341`); this LLR makes the suffix format-aware.

### LLR-003.1 — verify_written_image re-reads with the format parser
- **Traceability:** HLR-003
- **Statement:** A new `verify_written_image(written_path, intended_mem_map, file_type) -> VerifyResult` helper *(NEW — created in Phase 3)* shall re-read `written_path` with `IntelHexFile` when `file_type == "hex"` and with `S19File` when `file_type == "s19"`, build the re-read memory map (`.memory` / `.get_memory_map()`), and import no Textual symbol.
- **Validation:** test (unit)
- **Executed verification:** `pytest tests/test_verify_on_save.py::test_identity_write_is_verified tests/test_verify_on_save.py::test_unsupported_file_type_raises -q` [Phase-6 reconciliation per 04-validation DEV-3: provisional `-k "reread or parser_selection"` replaced with the real node ids, grep-verified at `tests/test_verify_on_save.py:82,135`] + V-4 purity probe `rg -n "import textual|from textual" s19_app/tui/changes/verify.py` *(probe P-2, verify module home resolved to `s19_app/tui/changes/verify.py`)*.
- **Numeric pass threshold:** exit code 0; correct parser selected per `file_type`; 0 Textual imports in the verify module.
- **Acceptance criteria (informative):**
  - `IntelHexFile(path).memory` (`hexfile.py:25`) and `S19File(path).get_memory_map()` are the two re-read sources.

### LLR-003.2 — Diff via compare.py, classify the outcome
- **Traceability:** HLR-003
- **Statement:** `verify_written_image` shall compute `runs, stats = diff_mem_maps(intended_mem_map, reread_mem_map)` (`compare.py:272`) and set `VerifyResult.status` to `"verified"` when `runs` is empty and `"mismatch"` otherwise, carrying `runs` and `stats` on the result.
- **Validation:** test (unit)
- **Executed verification:** `pytest tests/test_verify_on_save.py::test_mutated_byte_is_mismatch_changed tests/test_verify_on_save.py::test_dropped_byte_is_mismatch_only_a -q` [Phase-6 reconciliation per 04-validation DEV-3: provisional `-k "verified or mismatch"` replaced with the real node ids, grep-verified at `tests/test_verify_on_save.py:96,115`]; faithful map pair → empty runs → `verified`; a one-byte-MUTATED reread (same address, wrong value) → one `changed` run → `mismatch`.
- **Numeric pass threshold:** exit code 0; faithful → `len(runs) == 0` and status `verified`; one-byte MUTATION → `len(runs)==1 and runs[0].kind=="changed" and runs[0].length==1` (property read on `DiffRun.length` at `compare.py:138`; `DiffRun` is constructed `(start,end,kind)` at `compare.py:100` — `length` is NOT a constructor argument) and status `mismatch`.
- **Acceptance criteria (informative):**
  - `intended` is map A, `reread` is map B, so a byte the file failed to persist (DROPPED, not mutated) appears as `only_a` — a meaningful direction for the operator, and a SEPARATE fault model from the mutation case above (a dropped byte yields one `only_a` run, a mutated byte yields one `changed` run; the asserted run kind matches the planted fault per Rule 9).

### LLR-003.3 — Verify is wired into the save engine, collect-don't-abort
- **Traceability:** HLR-003
- **Statement:** When `save_patched_image` has written a file, the save-back handler shall call `verify_written_image` on the written path and obtain a `VerifyResult` via a SEPARATE channel that PRESERVES `save_patched_image`'s existing 2-tuple return `(Optional[Path], List[ValidationIssue])` UNCHANGED (the `VerifyResult` is carried on the result/summary object the callers already read — see §6.2 contract C-10, back-compatible carrier); a `mismatch` shall NOT delete or suppress the written file (collect-don't-abort).
- **Validation:** test (integration)
- **Executed verification:** `pytest tests/test_changes_apply.py::test_verify_written_hex_image_is_verified tests/test_changes_apply.py::test_verify_on_dropped_byte_is_mismatch_file_kept -q` and `pytest tests/test_change_service.py::test_hex_save_stamps_verified_result_on_summary -q` [Phase-6 reconciliation per 04-validation DEV-1/DEV-4: provisional `-k "verify_on_save"` replaced with the real node ids, grep-verified at `tests/test_changes_apply.py:530,549` and `tests/test_change_service.py:242` (the `last_summary.verify_result` carrier landed in the service test)]; inject an emitter that DROPS a byte and assert (i) the file still exists, (ii) status is `mismatch`, and (iii) the diff is exactly one `only_a` run of length 1 (a dropped byte is absent from the reread map B, so it classifies `only_a` per `diff_mem_maps`, NOT `changed` — the asserted kind matches the planted fault, Rule 9).
- **Numeric pass threshold:** exit code 0; on the injected DROP fault the file exists on disk AND status is `mismatch` AND `len(runs)==1 and runs[0].kind=="only_a" and runs[0].length==1`; on a faithful write status is `verified` and the file exists; `save_patched_image`'s 2-tuple return is unchanged (0 fields added to the tuple).
- **Acceptance criteria (informative):**
  - `save_patched_image`'s return shape is PRESERVED at `(Optional[Path], List[ValidationIssue])` (`apply.py:564`); the `VerifyResult` reaches the TUI via the separate carrier of §6.2 contract C-10 (0-site blast radius). See the C-10 producer/consumer table for the carrier.

### LLR-004.1 — Quiet pass status line
- **Traceability:** HLR-004
- **Statement:** When a save-back returns a `verified` result, the TUI (`app.py` save-back handler, `app.py:1364`) shall surface a single concise status line stating the file was saved and verified, and shall NOT raise a modal or mismatch notice.
- **Validation:** demo
- **Executed verification:** drive the TUI save-back on a faithful write; observe the status path. Test-realized as `pytest tests/test_tui_patch_editor_v2.py::test_verify_quiet_pass_on_faithful_hex_save -q` [Phase-6 reconciliation per 04-validation DEV-3: the demo was realized as an automated `App.run_test()` pilot, grep-verified at `tests/test_tui_patch_editor_v2.py:761`].
- **Numeric pass threshold (qualitative for `demo`):** exactly one "saved + verified" status line; no mismatch notice/modal appears.
- **Acceptance criteria (informative):**
  - Reuses the existing `_report_change_result` status path (`app.py:1415`).

### LLR-004.2 — Loud mismatch notice
- **Traceability:** HLR-004
- **Statement:** When a save-back returns a `mismatch` result, the TUI shall surface a prominent notice naming the written file and the mismatch summary (per-kind run and byte counts from `VerifyResult.stats`), while leaving the written file in place.
- **Validation:** demo
- **Executed verification:** drive the TUI save-back with an injected emitter fault; observe the notice content. Test-realized as `pytest tests/test_tui_patch_editor_v2.py::test_verify_loud_mismatch_notice -q` [Phase-6 reconciliation per 04-validation DEV-3: the demo was realized as an automated `App.run_test()` pilot, grep-verified at `tests/test_tui_patch_editor_v2.py:808`].
- **Numeric pass threshold (qualitative for `demo`):** the notice names the file and shows a non-zero run/byte count; the file remains on disk.
- **Acceptance criteria (informative):**
  - The summary text is built from `DiffStats.run_counts`/`byte_counts` over `DIFF_KIND_DOMAIN` (`compare.py:53`).

### LLR-005.1 — Per-screen unique modal button-row ids
- **Traceability:** HLR-005
- **Statement:** Each modal screen in `screens.py` shall give its button-row container a screen-unique widget id, eliminating the `load_buttons` id shared across the six screens at `screens.py:82,132,191,257,393,556`.
- **Validation:** inspection
- **Executed verification:** `rg -n 'id="load_buttons"' s19_app/tui/screens.py` after the change *(probe P-3, pre-state recorded §6.3)*; confirm no id value is shared by two screens.
- **Numeric pass threshold (observable for `inspection`):** 0 widget ids shared across two screens (the count of duplicate `load_buttons` literals drops from 6-shared to 0-shared); CSS rule `#load_buttons` (`styles.tcss:698`) updated or generalized to a class so styling is preserved.
- **Acceptance criteria (informative):**
  - The styling that `#load_buttons` provides (`styles.tcss:698`) is preserved (e.g. moved to a shared `.modal-buttons` class, already present at `screens.py:557`).

### LLR-005.2 — Narrow the OperationsScreen KeyError scope
- **Traceability:** HLR-005
- **Statement:** `OperationsScreen._execute_selected` (`screens.py:577`) shall call the module-level resolver seam `operation_service.operation_resolver` (`operation_service.py:35`) INSIDE a narrow `try`/`except KeyError` to resolve the operation id (the resolver raises `KeyError` on a registry miss), and shall call the resolved operation's `.execute(...)` OUTSIDE that `try`, so a `KeyError` raised inside `.execute(...)` propagates rather than being reported as "unknown operation". (The current code wraps the whole `operation_service.run_operation(operation_id, self.loaded)` call at `screens.py:618` in the catch — `run_operation` does BOTH resolve and execute (`operation_service.py:90`), so the catch cannot be narrowed without splitting resolve from execute via `operation_resolver`.)
- **Validation:** test (unit)
- **Executed verification:** `pytest tests/test_tui_operations_view.py::test_execute_internal_keyerror_not_masked_as_unknown_operation -q` [Phase-6 reconciliation per 04-validation DEV-1: provisional `tests/test_operations.py -k "keyerror_scope or unknown_operation"` replaced — the test was realized as a TUI-view pilot at `tests/test_tui_operations_view.py:296` (grep-verified), not in `test_operations.py`]; monkeypatch `operation_service.operation_resolver` (`operation_service.py:35`) — (a) to raise `KeyError` (simulating a registry miss) → asserts a status message + no crash; (b) to return a stub operation whose `.execute(...)` raises `KeyError` → asserts that error is NOT masked as "unknown operation" (proving the narrow scope excludes execute).
- **Numeric pass threshold:** exit code 0; resolver `KeyError` (miss) → 1 status message + 0 crash; an `.execute(...)`-internal `KeyError` → propagates (not reported as "unknown operation").
- **Acceptance criteria (informative):**
  - The documented intent ("a registry `KeyError` becomes an app status-line message", `screens.py:601`) is preserved; only the catch scope tightens to the `operation_resolver` resolution.

---

## 5. Validation strategy

### 5.1 Methods
- **Test:** automated execution (unit / integration / e2e). Default for LLR. **Every `test` LLR must name the exact executed verification and the numeric pass threshold — otherwise it is not executable.**
- **Demo:** observed execution of behavior. Useful for UX-oriented HLRs. Describe the observable procedure + the named qualitative criterion.
- **Inspection:** static review of code or document. Useful for structural requirements. Name the file / commit / section + the observable condition.
- **Analysis:** formal or quantitative reasoning (performance, complexity, security). **Every `analysis` LLR must name the executed calculation (with input values) and the numeric pass threshold — otherwise it is not executable.**

> Reminder from the batch-02 + batch-03 post-mortems: the absence of an executed verification + numeric pass threshold on `test`/`analysis` requirements was the recurring root cause of forced phase-1 iteration. Capture at draft time, not at the phase-2 gate.

### 5.2 Coverage table
*(Phase-1 TC ids were provisional per V-5. [Phase-6 reconciliation per 04-validation DEV-1..6: the "Implemented node id" column below records the real on-disk node names; the spec TC ids are retained for traceability. Mapping authority: 04-validation §1.])*

| Requirement | Method | TC (spec) | Implemented node id (on disk) | Notes |
|-------------|--------|-----------|-------------------------------|-------|
| HLR-001 | test | TC-001..TC-004 | `test_hex_emit.py` (7 fns / 10 nodes) | round-trip via `IntelHexFile` |
| LLR-001.1 | test (unit) | TC-001 | `test_low_address_roundtrip` | emitter purity (P-1) + signature |
| LLR-001.2 | test (unit) | TC-002 | `test_data_records_max_16_bytes_and_checksum` | data records + checksum |
| LLR-001.3 | test (unit) | TC-003 | `test_ela_high_address_roundtrip`, `test_ela_record_emitted_per_upper16_change` | ELA above 0xFFFF |
| LLR-001.4 | test (unit) | TC-004 | `test_empty_mem_map_emits_eof_only`, `test_output_terminates_with_single_eof`, `test_public_example_roundtrips_as_hex` | EOF + round-trip equality |
| HLR-002 | test | TC-005..TC-007 | `test_changes_apply.py` + `test_tui_patch_editor_v2.py` | HEX save-back |
| LLR-002.1 | test (integration) | TC-005 | `test_hex_save_writes_hex_file_that_reparses_to_post_apply_map`, `test_hex_save_forces_hex_suffix_when_name_lacks_it`, `test_s19_save_still_forces_s19_suffix`, `test_hex_save_adversarial_filenames_contained_or_refused` | HEX branch in `save_patched_image` |
| LLR-002.2 | test (integration) | TC-006 | `test_save_back_unsupported_source_refused_with_clear_issue` | retire refusal for hex; keep for mac |
| LLR-002.3 | test (integration) | TC-007 | `test_save_back_suggestion_is_format_aware` (TUI layer — DEV-4 coverage shift) | format-aware suffix in save-back |
| HLR-003 | test | TC-008..TC-010 | `test_verify_on_save.py` + `test_changes_apply.py` + `test_change_service.py` | verify-on-save |
| LLR-003.1 | test (unit) | TC-008 | `test_identity_write_is_verified`, `test_unsupported_file_type_raises` | parser selection + purity (P-2) |
| LLR-003.2 | test (unit) | TC-009 | `test_mutated_byte_is_mismatch_changed`, `test_dropped_byte_is_mismatch_only_a` | diff + classify outcome |
| LLR-003.3 | test (integration) | TC-010 | `test_verify_written_hex_image_is_verified`, `test_verify_on_dropped_byte_is_mismatch_file_kept`, `test_hex_save_stamps_verified_result_on_summary` | wired in, collect-don't-abort |
| HLR-004 | demo (test-realized) | TC-011a/b | `test_tui_patch_editor_v2.py` | quiet pass / loud mismatch |
| LLR-004.1 | demo (test-realized) | TC-011a | `test_verify_quiet_pass_on_faithful_hex_save` | verified status line |
| LLR-004.2 | demo (test-realized) | TC-011b | `test_verify_loud_mismatch_notice` | mismatch notice |
| HLR-005 | inspection | TC-012, TC-013 | `test_tui_operations_view.py` | folded hygiene |
| LLR-005.1 | inspection | TC-012 | `test_operations_button_row_has_screen_unique_id` | unique modal button ids (P-3) |
| LLR-005.2 | test (unit) | TC-013 | `test_execute_internal_keyerror_not_masked_as_unknown_operation` (in `test_tui_operations_view.py`, DEV-1) | KeyError scope |

> **[Phase-6 reconciliation per 04-validation DEV-5: in-file TC-label drift.]** The implemented test-module docstrings carry older engine-numbering TC labels that lag this spec table: `tests/test_tui_operations_view.py` docstring reads "TC-010..TC-012" and `tests/test_changes_apply.py` header reads "TC-009..TC-013". **The §5.2 table above is the authoritative TC↔node mapping** (TC-001..TC-013, aligned to 04-validation §1); where a test docstring's TC label disagrees, the §5.2 id governs. This is a cosmetic in-file-docstring lag, not a coverage gap (those test files are owned by the implementation increments, not this spec).

### 5.3 Batch acceptance criteria — reconciled to the MEASURED collection baseline
- **MEASURED baseline:** `python -m pytest -q --collect-only` last line = **782 tests collected** (2026-06-14, this worktree; regime: Win 11 Pro 10.0.26200, Python 3.14.x, OneDrive-synced worktree).
- After Phase 3, collection shall be **782 + N_new**, where `N_new` is the count of new test nodes added across `tests/test_hex_emit.py` (NEW), `tests/test_verify_on_save.py` (NEW), and new nodes in `tests/test_changes_apply.py` / `tests/test_change_service.py` / `tests/test_tui_operations_view.py` / `tests/test_tui_patch_editor_v2.py`. **Signed-balance form: `collected_after == 782 − D + N_new`, with `D = 0` this batch** (no test node is deleted or renamed away — all changes are additive; the M-1 back-compatible carrier means even the existing `test_save_back*` 2-tuple unpacks are NOT modified, so no node is lost). [Phase-6 reconciliation per 04-validation DEV-1/DEV-4: the implemented test homes are `test_tui_operations_view.py` (KeyError scope) and `test_tui_patch_editor_v2.py` (suffix + TUI demos), not the provisional `test_operations.py` / `test_change_service.py`; 04-validation §3 measured `N_new = 34` → `collected_after = 816`.]
- 100 % of LLRs covered by ≥ 1 TC with a pass result; 0 blocker fails.
- 0 `test`/`analysis` LLR without both an Executed verification and a Numeric pass threshold (self-checked: all `test` LLRs above carry both).
- The two package-root allowlist guards (`test_tui_directionb.py` lines 3191, 3565) remain GREEN — D-A keeps the package root at exactly 8 modules (see §6.3 R-10-CENSUS).
- The headless-purity guard (`test_no_textual_in_static_import_graph`, `test_checks_engine.py:400`) remains GREEN with the new emitter + verify modules on the reachable graph.

---

## 6. Appendices

### 6.1 Extended glossary
See §1.3. Additional: **headless** = imports no `textual`; verified by the static import-graph guard (`test_checks_engine.py:400`) and per-module V-4 `rg` probes.

### 6.2 Relevant design decisions

#### Cross-cutting contract C-10 — `VerifyResult` (producer/consumer table)
*(Contract-touch rule: any later edit to a producer/consumer LLR re-opens this table for a field-set identity re-run, recorded in that edit's audit row.)*

`VerifyResult` *(NEW — created in Phase 3)* canonical field set: `status: str` (`"verified"` | `"mismatch"`), `runs: list[DiffRun]`, `stats: DiffStats`, `written_path: Optional[Path]`.

| Field | Producer | Consumers |
|-------|----------|-----------|
| `status` | LLR-003.2 (`verify_written_image`) | LLR-003.3 (engine), LLR-004.1/004.2 (TUI) |
| `runs` | LLR-003.2 | LLR-004.2 (mismatch summary) |
| `stats` | LLR-003.2 | LLR-004.2 (run/byte counts) |
| `written_path` | LLR-003.3 (save-back handler stamps the written path onto the summary-borne `VerifyResult`) | LLR-004.1/004.2 (notice names the file) |

`save_patched_image` return shape (C-10 touch — M-1 PINNED to the back-compatible carrier): the 2-tuple `(Optional[Path], List[ValidationIssue])` (`apply.py:564`) is **PRESERVED UNCHANGED — 0 fields added to the tuple.** The `VerifyResult` is delivered via a SEPARATE channel: the save-back handler invokes `verify_written_image(...)` after the save and attaches the result to the existing summary object the callers already read (`ChangeService.last_summary`, the same object `change_service.py:847` stamps `saved_path` onto). **Blast radius = 0 sites:** the 5 measured 2-tuple unpack sites — 2 production (`change_service.py:845`, `variant_execution_service.py:711`) + 3 test (`tests/test_changes_apply.py:330,376,394`) — are all `(path/saved_path, issues) = save_patched_image(...)` and remain valid verbatim. **Producer LLR-003.3 (handler stamps `VerifyResult` onto the summary); consumers LLR-004.1/004.2 (TUI reads the summary's `VerifyResult`).** The field set above is fixed; the carrier is now PINNED (no longer gate-open — G-3 narrows to the `verify_written_image`/`VerifyResult` module home only).

#### D-A — HEX emitter location → **RESOLVED option (c): place the writer in `s19_app/tui/changes/io.py`, next to `emit_s19_from_mem_map` (emission-purpose cohesion).** *(REVERSAL of the original G-1/D-A recommendation (a) `hexfile.py`, forced by the I1 engine-frozen blocker — operator decision R2, 2026-06-14.)*

**Reversal record (binding, 2026-06-14):** The I1 software-dev placed the emitter in `hexfile.py` per the original (a) recommendation. That tripped a FOURTH guard family the Phase-1/2 census did NOT enumerate — the **engine-frozen / no-diff-vs-main** guards (`test_engine_unchanged.py::test_tc027_engine_modules_unchanged_vs_main` and `test_tui_directionb.py::test_tc031_engine_modules_have_no_diff_vs_main` / `..._no_name_only_diff_vs_main`), whose `_ENGINE_PATHS` freeze `hexfile.py` (among other parsing-layer modules) against ANY git diff vs `main`. (a)'s "trips zero guards" premise was therefore FALSE. See §6.3 R-10-ENGINE-FROZEN for the 4th-guard-family finding. The operator's resolution (R2) is literally *"simétrico a `emit_s19_from_mem_map`"* — co-locate with the S19 emitter, which lives in `io.py`.

**Options re-evaluated under the corrected census:**
- **(a) `hexfile.py` (format-cohesion). REJECTED — un-writable.** `hexfile.py` is in `_ENGINE_PATHS` (both `test_engine_unchanged.py:122` and `test_tui_directionb.py:3740`); any edit trips three engine-frozen guards (tc027 + tc031 diff + tc031 name-only). Writing the emitter here would require eroding a deliberate cross-batch read-only-engine invariant — not acceptable for a purely organizational gain. `hexfile.py` stays the READER only.
- **(b) new `s19_app/hexemit.py` (strict read/write separation).** Still adds a package-root module → trips BOTH allowlist guards (`test_tui_directionb.py:3191,3565`). Rejected as before (change surface + allowlist edits).
- **(c) `tui/changes/io.py` (emission-purpose cohesion). RESOLVED.** Co-locates with `emit_s19_from_mem_map` (`io.py:1298`) — all firmware **emission** logic in one module is the clean purpose-division. `io.py` is NOT in any `_ENGINE_PATHS` and is NOT a package-root module → **zero guards tripped** (engine-frozen contract intact, allowlists untouched). Headless: P-1 pre-state on `io.py` is 0 `textual` imports (executed 2026-06-14).

**Recommendation & rationale (tied to constraints):** **(c).** The engine-frozen read-only contract makes `hexfile.py` un-writable without breaking an invariant the project deliberately enforces; the package-root allowlist makes a new root module (b) costly. (c) — symmetric to the existing S19 emitter — is the only placement that satisfies emission-purpose cohesion AND trips zero guards (engine-frozen + allowlist + purity all GREEN). Testability is unchanged: the function is a pure `(mem_map, ranges) -> str` headless symbol, unit-testable in isolation. `hexfile.py` remains the round-trip oracle (reader half) only. **Gate-confirmable G-1 RESOLVED to (c) by operator R2.** `emit_intel_hex_from_mem_map` is flagged **NEW — created in Phase 3**.

#### D-B — verify-on-save trigger → **RECOMMEND option (3): hybrid (automatic, quiet pass, loud mismatch).**
| Option | Cost | Failure mode | UX surface |
|--------|------|--------------|------------|
| **(1) Automatic, always shown** | one re-read+diff per save (~165–172 ms re-read + ~215 ms diff on an 819 K-byte image, P-15 @ batch-09 01-req.md:249; sub-second). | Verify-noise: operator habituates to a "verified" banner and stops reading it; on a real mismatch the banner is ignored. | A result panel/modal on every save. |
| **(2) Explicit (operator triggers)** | save stays fast; verify cost paid only on demand. | Operator forgets to verify → the certainty the US asks for is not delivered by default; the feature is opt-in and easy to skip. | A separate "Verify" action/button. |
| **(3) Hybrid: auto verify, quiet pass, loud mismatch** | same as (1) — sub-second, always paid. | Lowest: certainty is always delivered (verify always runs) but attention is spent only when it matters (mismatch). Residual: a quiet pass could be overlooked, but that is the *correct* signal (nothing wrong). | Status line on pass; prominent notice/modal only on mismatch. |

**Recommendation & rationale:** **(3) hybrid.** "Verify-on-save" semantically couples to the save action, so it should run automatically (rules out 2). The diff is cheap relative to the parse the save already triggers (P-15), so always-verify is affordable (rules out the cost objection to 1). Interrupting on every save (1) trains the operator to ignore the signal; interrupting only on mismatch (3) preserves the signal's salience. **Gate-confirmable G-2:** the operator confirms (3) and the exact mismatch surface (status-line + notice vs. modal). **Deferred (informative):** reusing the batch-09 `diff_report_service.generate_diff_report` (`diff_report_service.py:720`) to write an on-disk mismatch report is *feasible* — it already takes a `ComparisonResult` + two mem_maps and writes a complete Markdown/HTML report — but it requires assembling a `ComparisonResult` (image refs, notes), which is heavier than the inline summary HLR-004 needs. Recommend the inline `DiffStats` summary this batch; flag the on-disk report as a clean follow-up (gate-confirmable G-4).

#### Phase-3 increment plan (≤ 5 files each)
- **I1 — HEX emitter (HLR-001).** Files: `s19_app/tui/changes/io.py` (add `emit_intel_hex_from_mem_map` + private record builders, next to `emit_s19_from_mem_map` — D-A=(c) per R2; `hexfile.py` is NOT touched, it stays the frozen reader/oracle), `tests/test_hex_emit.py` (NEW), `REQUIREMENTS.md` (R-* row). *(3 files — well under the 5-file cap.)*
- **I2 — verify-on-save engine (HLR-003).** Files: new verify helper module OR `s19_app/tui/changes/apply.py` (add `verify_written_image` + `VerifyResult`), `tests/test_verify_on_save.py` (NEW), `tests/test_changes_apply.py` (verify wiring), `REQUIREMENTS.md`. *(≤ 4 files. Verify-module home is G-3.)*
- **I3 — HEX save-back + retire refusal (HLR-002).** Files: `s19_app/tui/changes/apply.py` (HEX branch, retire refusal, parametric-`suffix` sanitizer), `s19_app/tui/services/change_service.py` (call `verify_written_image` post-save, stamp the `VerifyResult` onto `last_summary` — the back-compatible C-10 carrier; `save_patched_image`'s 2-tuple return is NOT changed, so no caller/test unpack edits), `tests/test_changes_apply.py`, `tests/test_change_service.py`. *(4 files; `variant_execution_service.py` is NOT in this budget — M-1: its 2-tuple unpack is unchanged and variant-execution HEX persist stays refused, §1.2.)*
- **I4 — TUI surfacing + folded hygiene (HLR-004 + HLR-005).** Files: `s19_app/tui/app.py` (quiet/loud surface, format-aware suffix), `s19_app/tui/screens.py` (unique button ids + KeyError scope), `s19_app/tui/styles.tcss` (CSS class), `tests/test_operations.py`, `tests/test_tui_*.py`. *(≤ 5 files.)*

> If census predicts a guard trip (§6.3), the allowlist edit folds into the increment that introduces the new module — but D-A=(c) avoids this entirely. [Phase-6 reconciliation per 04-validation DEV-6: option-letter corrected (a)→(c) — the placement resolved to `tui/changes/io.py` (option c) per H-5; `io.py` is neither package-root nor engine-frozen, so it trips zero guards.]

### 6.3 Open risks, gate-confirmables, probe ledger

#### Risks
- **R-10-CENSUS (package-root allowlist, predicted-red set) — now LOW under the resolved D-A=(c).** The two package-root allowlist guards `test_tui_directionb.py::test_tc028_no_new_processing_module_added_outside_view_layer` (line ~3174, allowlist at 3191) and `::test_tc028_no_new_processing_module_added_outside_view_layer_inc10` (line 3550, allowlist at 3565) each `assert (package_root.glob("*.py") names) - {8-module allowlist} == set()`. **Predicted-red only if a NEW package-root module is added (the old option b).** **Disposition:** D-A resolved to (c) `tui/changes/io.py`, which is NOT a package-root module → both stay GREEN, no allowlist edit. *(Behavioral-placeholder + `calls <=` AST guards: greped `tests/` for `calls <=` / placeholder / `NotImplementedError` — the placeholder guards (`test_operations.py`) target the three operation placeholders, not the save/emit path.)* **CAVEAT — this census was INCOMPLETE:** it enumerated package-root-allowlist + behavioral-placeholder + AST-composition families but MISSED the engine-frozen / no-diff-vs-`main` family that froze `hexfile.py` and broke the original D-A=(a). See R-10-ENGINE-FROZEN below — that gap, not this allowlist, was the I1 blocker.
- **R-10-PURITY — MEDIUM.** The new emitter + verify code is reachable from `change_service` and is walked by `test_no_textual_in_static_import_graph` (`test_checks_engine.py:400`). **Predicted-red if the new code imports `textual`.** Disposition: emitter is pure `(mem_map, ranges) -> str` (no UI); verify helper takes maps + paths (no UI); both stay stdlib-only (the `compare.py` precedent). Per-module V-4 probes P-1/P-2 enforce.
- **R-10-NOHEXFIXTURE — MEDIUM.** examples/ has 0 `.hex` files (A5). An AC demanding a real `.hex` example would be unsatisfiable (batch-08 B-1). Disposition: every HEX test builds its fixture by round-trip (emit → write → re-read) or marks it `NEW`; no AC above references a pre-existing `.hex`.
- **R-10-CONTRACT — LOW (downgraded from MEDIUM after M-1).** Wiring verify originally risked changing `save_patched_image`'s return shape (C-10). The complete unpack census is **5 sites**: 2 production (`change_service.py:845`, `variant_execution_service.py:711`) + 3 test (`tests/test_changes_apply.py:330,376,394`), all `(path, issues) = save_patched_image(...)`. **Disposition (M-1 PINNED): the 2-tuple is PRESERVED unchanged; the `VerifyResult` rides a separate carrier (the `ChangeService` summary).** Blast radius → 0 sites; no caller edit, no test edit. `variant_execution_service.py` is removed from any I3 budget concern (it neither needs the VerifyResult this batch nor changes its unpack). See §6.2 C-10.
- **R-10-HYGIENE-CSS — LOW.** De-colliding `load_buttons` ids must not lose the `#load_buttons` CSS (`styles.tcss:698`). Disposition: migrate styling to the existing `.modal-buttons` class (`screens.py:557`) before removing the shared id.
- **R-10-CHECKSUM-DIRECTION — LOW.** Intel HEX checksum is two's-complement-of-sum; S19 is one's-complement. Disposition: LLR-001.2 pins the Intel formula and round-trips against the reader's own verification (`hexfile.py:66-74`) — the reader is the oracle.
- **R-10-ENGINE-FROZEN (4th-guard-family — census-completeness gap) — REALIZED at I1, now CLOSED.** The Phase-1/2 supersession-census enumerated three guard families (behavioral-placeholder; structural/placement/package-root-allowlist; AST-composition `calls <=`) but did NOT enumerate the **engine-frozen / no-diff-vs-`main`** family, which freezes every `_ENGINE_PATHS` module — including `hexfile.py` — against ANY git diff vs `main`. This gap made D-A=(a)'s "trips zero guards" premise false: the I1 emitter placed in `hexfile.py` tripped `test_engine_unchanged.py::test_tc027_engine_modules_unchanged_vs_main`, `test_tui_directionb.py::test_tc031_engine_modules_have_no_diff_vs_main`, and `..._no_name_only_diff_vs_main`. **Census grep (executed 2026-06-14, this worktree):** `rg -n "_ENGINE_PATHS|no_diff_vs_main|engine_modules_unchanged" tests/` → 10 hits across `tests/test_engine_unchanged.py` + `tests/test_tui_directionb.py`. **Frozen module set (union of both `_ENGINE_PATHS`):** `s19_app/core.py`, `s19_app/hexfile.py`, `s19_app/range_index.py`, `s19_app/validation/`, `s19_app/tui/a2l.py`, `s19_app/tui/mac.py`, `s19_app/tui/color_policy.py` (regime: `git diff --name-only main` / `--stat main`, line-ending + `__pycache__` aware). **`s19_app/tui/changes/io.py` is NOT in either list — confirmed not frozen.** **Disposition (operator R2):** relocate the emitter to `io.py` (D-A=(c)) → `hexfile.py` untouched, engine-frozen contract intact, zero guards tripped. **This rule's OWN gap is a batch-10 post-mortem feeder:** the V-3 supersession-census-completeness greps must be extended to enumerate the engine-frozen family — add `rg -n "_ENGINE_PATHS|no_diff_vs_main|engine_modules_unchanged" tests/` to the census probe set so a future placement decision into a frozen module is caught at Phase 1, not Phase 3.

#### Gate-confirmables
- **G-1 (D-A): RESOLVED 2026-06-14 → `tui/changes/io.py` (option c), by operator R2.** Original recommendation (a) `hexfile.py` was REVERSED after I1 hit the engine-frozen blocker (`hexfile.py` ∈ `_ENGINE_PATHS`). io.py trips zero guards. See §6.2 D-A reversal record + §6.3 R-10-ENGINE-FROZEN.
- **G-2 (D-B):** verify-on-save trigger — recommend hybrid (3). Confirm + confirm the mismatch surface (status-line + notice vs. modal).
- **G-3:** `verify_written_image` / `VerifyResult` module home (new module vs. `apply.py`). *(The `save_patched_image` return-shape carrier is no longer gate-open — M-1 PINNED the back-compatible carrier: 2-tuple preserved, VerifyResult on the summary. See §6.2 C-10.)*
- **G-4:** whether a verify mismatch also writes an on-disk report via `diff_report_service` (deferred recommendation: no this batch).

#### Probe ledger (EXECUTED at draft, with pre-state + regime per V-4 / probe-regime rule)
| ID | Probe (V-4 form where purity) | Pre-state (executed 2026-06-14) | Regime | Pass condition |
|----|-------------------------------|----------------------------------|--------|----------------|
| P-1 | `rg -n "import textual\|from textual" s19_app/tui/changes/io.py` | **0 matches** (clean today, executed 2026-06-14; was originally probed on `hexfile.py` — retargeted to io.py under R2) | `tui/changes/` package module, whole-file purity; same module the future emitter is added to (next to `emit_s19_from_mem_map`) — in-regime; io.py imports no textual at all, so the whole-file probe is valid | 0 matches post-emitter |
| P-2 | `rg -n "import textual\|from textual" <verify module>` | **N/A — module NEW**; positive control deferred. Run on the verify module's actual location at I2 (in-regime, batch-08 `_b2_scratch` pattern if needed). | verify module (home G-3) | 0 matches post-impl; recorded `superseded-pending` until in-regime control runs in Phase 2/3 |
| P-3 | `rg -c 'id="load_buttons"' s19_app/tui/screens.py` | **6 matches** (six screens share the id) | TUI modal screens | 0 cross-screen-shared ids post-change |
| P-4 | `def (write\|emit\|save\|dump\|serialize\|from_mem)` in `hexfile.py` | **0 matches** (no writer in the reader module — negative confirmed) | package-root format module (reader/oracle) | hexfile.py stays reader-only post-batch (still 0 — it is engine-frozen, R-10-ENGINE-FROZEN); the writer this batch ADDS lives in `io.py` instead → post-batch `rg "def emit_intel_hex_from_mem_map" s19_app/tui/changes/io.py` ≥ 1 |
| P-5 | package-root `*.py` names | **8 modules** = `{__init__, cli, compare, core, hexfile, range_index, utils, version}` (matches both allowlists exactly) | package root | unchanged at 8 under D-A=(c) — io.py is not package-root [Phase-6 reconciliation per 04-validation DEV-6: (a)→(c)] |
| P-6 | `python -m pytest -q --collect-only` last line | **782 tests collected** | full suite, this worktree | `782 + N_new` post-Phase-3, no regression |

> **P-2 note:** recorded `superseded-pending` per the probe-regime rule — the verify module does not exist yet, so its in-regime positive control runs at the target location in Phase 2/3 (synthetic in-regime fixture if needed). All other probes are in-regime and executed.

#### shall/should self-check
- `should` inside any HLR/LLR **Statement**: greped — **0** (all `should` uses are in Rationale/informative/risk prose, which is permitted).
- Every `test`/`analysis` HLR/LLR carries Executed verification + Numeric pass threshold: **yes** (self-verified across §3/§4).
- Every named code symbol: grep-cited `file:line` OR flagged `NEW — created in Phase 3`: **yes** (symbol-citation key, top of §4).
- AC-named artifacts: the only data artifacts referenced are NEW test files (flagged) and the round-trip fixtures (built in-test); examples/ `.hex` absence recorded (A5, R-10-NOHEXFIXTURE).

### 6.4 Phase-1 ITERATION-2 reconciliation log (Phase-2 fix register applied 2026-06-14)

> Body-first ordering observed: every §3/§4 body line below was edited BEFORE its audit row was written. Columns per the normative header: `Decision ID | What changed | Parent-HLR re-read? | Body edit landed?`. Letter series: **H** (gate-confirmables already use G; no prior F/H series in this doc). All four majors are spec-substance restatements against grep-verified code — NO design change, NO new operator decision (M-1's carrier was the G-3 recommendation delegated to the orchestrator, now pinned).

| Decision ID | What changed | Parent-HLR re-read? (which HLR + what changed there, or "no change required" + why) | Body edit landed? (the §3/§4 line that now reflects it) |
|---|---|---|---|
| H-1 (M-1) | C-10 carrier PINNED to back-compatible: `save_patched_image` 2-tuple `(Optional[Path], List[ValidationIssue])` PRESERVED unchanged; `VerifyResult` rides `ChangeService.last_summary`. 5-site unpack census recorded (2 prod + 3 test). Blast radius → 0. | **HLR-002** re-read: statement says "persist … through the existing containment + no-silent-overwrite machinery" — unaffected by the return carrier; no HLR-002 threshold change. **HLR-003** re-read: statement says "return a verify result" — still true (returned via the summary carrier, not the tuple); no threshold change. No HLR threshold contradicts the pinned carrier. | LLR-002.1 AC ("…2-tuple return…is PRESERVED…test_save_back* …stay green"); LLR-003.3 Statement + AC ("…2-tuple return…UNCHANGED…separate channel…0 fields added"); §6.2 C-10 carrier paragraph + `written_path` row. |
| H-2 (M-2) | Threshold `DiffRun(kind="changed", length=1)` (not constructible) → property-read form `len(runs)==1 and runs[0].kind=="changed" and runs[0].length==1`. `DiffRun` fields `(start,end,kind)` `compare.py:100`; `length` `@property` `compare.py:138`. | **HLR-003** re-read: its Numeric pass threshold carried the same impossible construct → CHANGED in lockstep to the property-read form (propagated up, not left contradicting). | HLR-003 Numeric pass threshold; LLR-003.2 Numeric pass threshold + Executed verification. |
| H-3 (M-3) | LLR-005.2 "narrow the existing `try`" (not implementable — `run_operation` does resolve+execute) → call module-level seam `operation_resolver` (`operation_service.py:35`) inside the narrow `try`, `.execute(...)` outside. TC-013 monkeypatches `operation_resolver`. | **HLR-005** re-read: statement says "scope the `except KeyError` to only the `run_operation` registry-lookup miss" — intent unchanged; the LLR now names the real mechanism (resolver seam) that realizes that intent. No HLR threshold change required (the observable condition is identical). | LLR-005.2 Statement + Executed verification + Numeric pass threshold + AC. |
| H-4 (M-4) | Fault-model conflation resolved: MUTATED byte → one `changed` run (LLR-003.2); DROPPED byte → one `only_a` run (LLR-003.3). Asserted kind now matches the planted fault (Rule 9). | **HLR-003** re-read: threshold now reads "one-byte MUTATION → one `changed` run" (single, consistent fault model at the HLR); the drop case lives only at LLR-003.3 with its own `only_a` expectation — no HLR-level contradiction. | HLR-003 Numeric pass threshold (mutation→changed); LLR-003.2 (mutation→changed) + AC (drop→only_a, separate model); LLR-003.3 Statement + Executed verification + Numeric pass threshold (drop→only_a). |

> **ITERATION-3 (mid-Phase-3, I1-gate blocker) — operator decision R2, 2026-06-14.** Unlike H-1..H-4 (spec restatements, no design change), H-5 records a genuine **location REVERSAL** of the G-1/D-A decision, forced by the I1 engine-frozen blocker. No HLR/LLR count change (5 HLR / 14 LLR preserved); no contract field change (C-10 untouched).

| H-5 (R2) | **D-A / G-1 location REVERSED: HEX emitter moves from `s19_app/hexfile.py` (option a) to `s19_app/tui/changes/io.py` (option c), next to `emit_s19_from_mem_map`.** Cause: `hexfile.py` ∈ `_ENGINE_PATHS` → I1 placement tripped a 4th guard family (engine-frozen / no-diff-vs-`main`: tc027 + tc031-diff + tc031-name-only) that the Phase-1/2 census did NOT enumerate. io.py is not frozen and not package-root → zero guards tripped; hexfile.py returns to untouched (reader/oracle only). Census grep executed (`rg "_ENGINE_PATHS\|no_diff_vs_main\|engine_modules_unchanged" tests/` → 10 hits; frozen set confirmed; io.py confirmed absent). P-1 purity probe retargeted to io.py (pre-state 0 matches, executed 2026-06-14). | **HLR-001** re-read: its Statement names NO file location — it specifies the function behavior ("serialize … such that re-parsing via `s19_app.hexfile.IntelHexFile` reconstructs …"); the only `hexfile.py` reference in HLR-001 is the **reader** oracle (`IntelHexFile`), which is unchanged. **No HLR-001 threshold or statement change required** — the location lived only in the §4 LLR-001.1 body / glossary / §6.2 D-A / §6 increment plan, not the parent HLR. | LLR-001.1 Statement ("placed in `s19_app/tui/changes/io.py` per D-A") + Executed verification + Numeric pass threshold (rg target → io.py) + AC ("io.py remains free of any textual import"); §4 symbol-citation glossary line ("D-A places it in `s19_app/tui/changes/io.py`"); §6.2 D-A reversal record (option c RESOLVED); §6.3 R-10-ENGINE-FROZEN risk + G-1 RESOLVED + probe-ledger P-1 (io.py) + P-4 (writer→io.py); §6 increment plan I1 file list (io.py replaces hexfile.py). |

**Contract-touch re-run (C-10, mandated because M-1 edited producer LLR-003.3 + consumer-side AC):** field-set identity re-run 2026-06-14 across all producer/consumer enumerations — canonical set `{status, runs, stats, written_path}`; producer LLR-003.2 (status/runs/stats) + LLR-003.3 (written_path); consumers LLR-004.1/004.2 (all four). **Field set unchanged — 0 fields added to the `VerifyResult`.** Tuple identity re-run: `save_patched_image` return is `(Optional[Path], List[ValidationIssue])` before and after — **0 fields added to the tuple** (the VerifyResult is NOT in the tuple; it is on the summary). C-10 contract identity HOLDS.

**Contract-touch re-run for ITERATION-3 (H-5):** the H-5 edit touched LLR-001.1 (emitter location only), which is NOT a C-10 producer or consumer. The emitter signature `emit_intel_hex_from_mem_map(mem_map, ranges) -> str` is UNCHANGED by the relocation (file moved, signature identical). No producer/consumer LLR contract field changed, so C-10 is NOT re-opened by H-5 — **no re-run required; C-10 untouched.** (Recorded explicitly per the Contract-touch rule: an edit that does not touch a producer/consumer LLR's fields does not re-open the contract.)

**Minor folds (no threshold/statement change → no audit row required, recorded for traceability):** m-1 `DiffRun`/`DiffStats` `:99/:149`→`:100/:150` (+ `.length` `:138`); m-2 `save_patched_image` return `apply.py:565`→`:564` (C-10); m-3 `io.py:1337`→`io.py:1337-1339` (Data Flow line range, ×2); m-4 §5.2 spans (HLR-003→TC-008..TC-010, HLR-004→TC-011a/b); m-5 LLR-001.3 oracle pinned to `IntelHexFile(written).records` + `record_type==0x04`; m-6 §5.3 signed-balance `782 − 0 + N_new` (D=0); m-7 LLR-002.1 parametric `suffix` on single `_sanitize_s19_filename` (`apply.py:691`); m-8 §1.2 out-of-scope note for variant-execution HEX persist (`variant_execution_service.py:724-728`).

> **Probe-regime / AC-artifact note for this iteration:** the one new probe-bearing assertion added (LLR-005.2 TC-013 monkeypatch of `operation_resolver`, `operation_service.py:35`) targets an EXISTING module-level seam (grep-verified, in-regime — module-level import depth matches the test's import of `operation_service`); no new AC-named data artifact was introduced (TC-013 uses a stub operation built in-test, not a fixture file). V-5: all new/changed spec-pinned test FILE paths + node ids (`tests/test_verify_on_save.py`, `tests/test_operations.py -k ...`) remain flagged provisional-until-Phase-3.
