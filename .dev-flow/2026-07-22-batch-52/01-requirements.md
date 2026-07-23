# Requirements Document — s19_app — Batch batch-52 (Flow Builder CRC block)

> **Artifact language:** English. Normative keyword `shall` is used **only** inside HLR/LLR statements. `should` appears only in informative prose, never as a modal inside an HLR/LLR statement.

---

## 1. Introduction

### 1.1 Purpose

This document specifies the requirements for **batch-52**: a template-driven **CRC block** in the Flow Builder's ordered pipeline (`SOURCE → PATCH → CRC → WRITE-OUT/CHECK`). The CRC block computes a CRC over the **working, post-patch** image using a JSON template config, injects the CRC bytes at the config's output address, **grows** the working `(mem_map, ranges)` when the output window lies outside the loaded ranges, and threads the extended image forward to downstream blocks. It is the successor to the batch-51 CHECK block and the fourth typed block in the flow pipeline.

### 1.2 Scope

**In scope**

- A new `CrcBlock` typed block (`config_ref`) + a `BLOCK_CRC` discriminator in `flow_model.py`.
- A CRC branch in `flow_execution_service.py::run_flow` that: resolves the untrusted `config_ref` through the existing containment guard, parses+validates the config, computes the CRC over the threaded post-patch image, injects the CRC, threads the extended image forward, and rolls its outcome into the block/flow status.
- **Reuse** (no fork, no refactor) of the frozen-in-spirit CRC kernel: `parse_crc_config`, `check_regions`, `inject_crcs`, and the `OperationInput`/`CrcRegionResult` model.
- CRC ordering guidance: a CRC block placed before any PATCH block emits a **non-blocking** WARN notice.
- Fail-close safety: a malformed config OR an out-of-project/escaping `config_ref` errors the block, breaks the image, skips downstream, and never raises.
- UI: a CRC option in the Flow Builder add-block dropdown; a rendered CRC node with post-run status.
- UI signature: a before/after memory ribbon that visibly grows when CRC extends the image.
- Carried polish: F3 (hide the gating control for non-CHECK blocks) and G-1 (empty-flow render TC).

**Out of scope**

- Editing the CRC kernel (`crc.py`, `crc_config.py`) or the CRC Designer view (batch-58/59). The two CRC surfaces are reconciled by **sharing** the kernel, not by changing it.
- `flow.json` persistence of the CRC block (deferred to batch-53).
- Any change to the engine-frozen parsing/validation modules.
- Multi-image / multi-CRC scope.

### 1.3 Definitions, acronyms, abbreviations

| Term | Definition |
|------|------------|
| Flow block | A typed, frozen dataclass in `flow_model.py` describing one pipeline stage. |
| Working image | The `(mem_map, ranges)` pair threaded through `run_flow`, seeded by SOURCE and mutated by PATCH. |
| Post-patch image | The working image AFTER all upstream PATCH blocks have mutated it — the input the CRC block computes over. |
| CRC template config | A JSON file under `.s19tool/templates/` parsed by `parse_crc_config` (shared with the batch-58 CRC Designer). |
| `config_ref` | The CRC block's PROJECT-RELATIVE reference to a template config file; an untrusted input. |
| Grow / extend | Adding `output_bytes` keys to `mem_map` and a covering range to `ranges` when the CRC output window is outside every loaded range. |
| Containment guard | `_resolve_manifest_entry` — the F1 manifest guard set (absolute / escape-project-root / reparse-point rejection). |
| Fail-close | A block error that breaks the image, skips downstream, sets flow status `error`, and never crashes `run_flow`. |
| Twin ribbon | The Direction-A before/after memory ribbon rendering both the pre-CRC and post-CRC footprints. |

### 1.4 References

- `CLAUDE.md` — project layout, engine-frozen guard set, severity/colour conventions.
- `REQUIREMENTS.md` — `R-*` traceability register (ids through HLR/LLR-088, AT-122, TC-345 at draft).
- Batch-51 spec (`.dev-flow/2026-07-20-batch-51/01-requirements.md`) — CHECK block; §6.5 AMD-1 (`image_ranges` ribbon carry); global control **C-36**.
- Batch-57/58/59 (`project_crc_algorithm_designer.md`) — CRC kernel (`crc.py`, `crc_config.py`) + preview-only CRC Designer.
- `.fast-dev-flow/ADR-flow-builder-tracer.md` — Flow Builder tracer ADR (§7 the CRC-into-loop seam).

### 1.5 Document overview

§2 gives the overall description and the source user stories (§2.6) with a per-story refinement log. §3 states the HLRs (with black-box Acceptance blocks). §4 decomposes them into LLRs. §5 gives the two-layer validation strategy and dual-traceability tables. §6 holds design decisions, open risks, the Phase-1 reconciliation log (§6.4), and the amendments section (§6.5, empty at draft).

---

## 2. Overall description

### 2.1 Product perspective

The Flow Builder (rail-8, Direction-A TUI) composes an ordered list of typed blocks that `flow_execution_service.py::run_flow` (line 66) executes by threading a working `(mem_map, ranges)` pair. Batch-51 shipped the CHECK block and the amber `completed-with-issues` status. This batch adds the CRC block — the **first block that grows the image** — sitting between PATCH and WRITE-OUT/CHECK. The `run_flow` tail already carries the working footprint into `result.image_ranges` (line 315-316), and its own comment (line 313-314) names batch-52 as the point where the image first grows: *"this is the SOURCE footprint until the batch-52 CRC block first grows the image."*

### 2.2 Product functions

1. Model a CRC block (`config_ref`) as a typed flow block.
2. Execute the CRC block: resolve → parse → compute over post-patch image → inject → thread extended image forward.
3. Grow the working image when the CRC output window is outside loaded ranges.
4. Emit a non-blocking WARN when CRC precedes PATCH.
5. Fail-close on a hostile/malformed config.
6. Surface the block in the add-block dropdown and render its node + status.
7. Render a before/after twin ribbon showing image growth.

### 2.3 User characteristics

Single role: an **engineer** building/running a finalization flow in the TUI. Familiar with S19/HEX images, CRC finalization, and change/check documents. No new permissions; all file access stays inside `.s19tool/workarea/<project>/` and `.s19tool/templates/`.

### 2.4 Constraints

- **Engine-frozen set is OFF-LIMITS:** `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`, plus the frozen test files. **None of the batch-52 targets are in the frozen set** — the CRC block lives in `flow_model.py` + `flow_execution_service.py` (services) and `screens_directionb.py` (view); the CRC kernel (`crc.py`, `crc_config.py`) is reused unchanged, not edited.
- **CRC kernel reuse, no fork:** `parse_crc_config` (`crc_config.py:385`), `check_regions` (`crc.py:757`), `inject_crcs` (`crc.py:1081`) are shared verbatim; the block MUST NOT re-implement CRC math or config parsing.
- **≤5 files per increment.**
- **Collect-don't-abort:** `run_flow` never raises (per-block isolation, `flow_execution_service.py:290-295`); a block failure is recorded, not thrown.
- **Every behavioral change ships a black-box `AT-NNN`** shown RED before the fix.
- **Reuse the containment guard verbatim:** `_resolve_manifest_entry` (imported `flow_execution_service.py:63`); never fork the resolution/containment logic.
- **security_required = TRUE:** `config_ref` is an untrusted file path → guarded by containment + `parse_crc_config` validation.

### 2.5 Assumptions and dependencies

- **A-1:** The threaded `mem_map`/`ranges` inside `run_flow` already reflect all upstream PATCH mutations at the point the CRC block runs (PATCH mutates in place, `flow_execution_service.py:190-192`). If false, the CRC would be computed over an un-patched image and US-C52-1's premise fails.
- **A-2:** `inject_crcs` builds a working copy and never mutates its input `mem_map`/`ranges`, and grows `ranges` via `_extend_ranges` (kept sorted, non-overlapping) — verified: `crc.py:1081` docstring lines 1092-1098.
- **A-3:** `check_regions` computes `computed_crc` unconditionally, even when no stored CRC value is present (fresh finalization) — verified from the prompt's disk facts + `crc.py:757` docstring.
- **A-4:** The batch-58 CRC Designer already writes JSON templates to `.s19tool/templates/` that `parse_crc_config` reads; the CRC block's `config_ref` points at such a file. No new template infra is created.
- **A-5:** `save_patched_image` (WRITE-OUT sink) emits from whatever `(mem_map, ranges)` it is handed, so a grown image is emitted correctly by the existing WRITE-OUT block (`flow_execution_service.py:211-215`).
- **Dependency:** `OperationInput` (`operations/model.py:27`), `CrcRegionResult` (`operations/model.py:131`), `CrcConfig`.

### 2.6 Source user stories

> Connextra format. Each story is `READY` (Definition-of-Ready satisfied) before derivation.

| ID | User Story | Source | DoR status |
|----|------------|--------|------------|
| US-C52-1 | As an engineer building a flow, I want a CRC block that computes and injects a CRC over the working post-patch image using a template config, so I can automate CRC finalization in a saved, reusable flow. | Operator batch-52 brief; MEMORY.md batch-51 "Next: batch-52 = CRC block" | READY |
| US-C52-2 | As an engineer, I want the CRC block to GROW the image's address space when the CRC output lands outside loaded ranges, so downstream WRITE-OUT/CHECK see the extended image. | Operator batch-52 brief; ADR §7 CRC-into-loop seam | READY |
| US-C52-3 | As an engineer, I want CRC ordering guidance (PATCH→CRC; a CRC before any PATCH emits a non-blocking WARN notice), so I don't silently CRC an un-patched image. | Operator batch-52 brief | READY |
| US-C52-4 | As an engineer, I want an invalid/unsafe CRC config to fail the block SAFELY — the block errors, the image breaks, downstream is skipped, the run never crashes — so a bad or hostile template can't corrupt the run. | Operator batch-52 brief; security_required | READY |
| US-C52-5 | As an engineer, I want to add a CRC block from the Flow Builder and see its node + status, so I can compose it visually. | Operator batch-52 brief | READY |
| US-C52-6 | As an engineer, I want a before/after memory ribbon that visibly GROWS when CRC extends the image, so I can see the address-space growth. | Operator batch-52 brief; §6.5 AMD-1 twin ribbon | READY |

#### Refinement log

**US-C52-1 — CRC compute + inject over post-patch image**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):** user = engineer · outcome = a written file carries the computed CRC bytes at the config's output address after `SOURCE→PATCH→CRC→WRITE-OUT` · why = automate finalization in a reusable flow · out of scope = CRC math (reused), config authoring (Designer), persistence (batch-53).
- **Feasibility (E, S):** path = new `CrcBlock`/`BLOCK_CRC` + a CRC branch in `run_flow` calling `check_regions` then `inject_crcs`, threading the returned working map/ranges forward · dependencies = CRC kernel + `OperationInput` · fits one batch? = yes (Inc-1).
- **Evaluability (T):** When a flow `SOURCE→PATCH→CRC→WRITE-OUT` runs with a valid config, the engineer observes the written file containing the computed CRC bytes at the config output address (→ **AT-123**).
- **Open questions:** none blocking.
- **Classification:** `READY`.

**US-C52-2 — grow image address space**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** user = engineer · outcome = `FlowRunResult.image_ranges` / the written file's ranges include the new CRC window that was absent from the SOURCE image · why = downstream sees the extended image · out of scope = merge/overlap semantics beyond `_extend_ranges`.
- **Feasibility:** path = `inject_crcs` already grows via `_extend_ranges`; `run_flow` reassigns the threaded `mem_map`/`ranges` to the returned working copy so the tail `image_ranges` (line 315-316) reflects growth · fits one batch? = yes (Inc-1).
- **Evaluability:** When CRC output lies outside loaded ranges, the engineer observes `image_ranges` (and the written ranges) contain the new window (→ **AT-124**).
- **Open questions:** none.
- **Classification:** `READY`.

**US-C52-3 — CRC ordering guidance (non-blocking)**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** user = engineer · outcome = a CRC-before-PATCH flow produces a WARN finding + flow status `completed-with-issues` but STILL runs · why = don't silently CRC an un-patched image · out of scope = auto-reordering; hard-blocking.
- **Feasibility:** path = detect a CRC block index earlier than any PATCH index → attach `Finding(FINDING_WARN, …)` + `BLOCK_STATUS_NOTICES`; the existing status roll-up (`flow_execution_service.py:300-308`) resolves `completed-with-issues` from a notices/finding, non-aborting · fits one batch? = yes (Inc-1).
- **Evaluability:** When CRC precedes PATCH, the engineer observes a WARN finding + `completed-with-issues`, and the flow still runs to completion (→ **AT-125**).
- **Open questions:** does "before any PATCH" mean "no PATCH exists at all" too? Decision: a CRC in a flow with NO PATCH block also warns (nothing was patched). Recorded as LLR-091.1 scope.
- **Classification:** `READY`.

**US-C52-4 — fail-close on invalid/unsafe config**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** user = engineer · outcome = a CRC block with a malformed config OR an out-of-project/escaping `config_ref` → that block is `BLOCK_STATUS_ERROR`, downstream `SKIPPED`, flow status `error`, and `run_flow` returns a well-formed result and never raises · why = a hostile/bad template can't corrupt the run · out of scope = repairing configs; partial-injection recovery.
- **Feasibility:** path = resolve `config_ref` via `_resolve_manifest_entry` (rejects absolute/escape/reparse) then `parse_crc_config` (errors → `None`); either failure routes to `_record_error` (aborts) · fits one batch? = yes (Inc-1).
- **Evaluability:** two black-box tests — malformed config (→ **AT-126**) and containment triad (absolute/escape/reparse) (→ **AT-127**) — each asserting block error + downstream skipped + flow error + no exception.
- **Open questions:** none.
- **Classification:** `READY`.

**US-C52-5 — add + render CRC block (UI)**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** user = engineer · outcome = the add-block dropdown lists CRC; adding one renders a CRC node; after Run its status/message shows · why = compose the block visually · out of scope = config picker UI (a text `config_ref` field suffices for this batch).
- **Feasibility:** path = extend `_KIND_OPTIONS` (`screens_directionb.py:2603`) with a CRC entry + the block-add/render path in `FlowBuilderPanel` (`screens_directionb.py:2571`) · fits one batch? = yes (Inc-2).
- **Evaluability:** In `App.run_test()`, the engineer observes CRC in the dropdown, a CRC node after add, and a status/message after Run (→ **AT-128**).
- **Open questions:** none.
- **Classification:** `READY`.

**US-C52-6 — before/after twin ribbon (UI signature)**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** user = engineer · outcome = the Direction-A ribbon renders a before footprint and an after footprint that is visibly larger when CRC grew the ranges · why = see the address-space growth · out of scope = per-byte diff; animation.
- **Feasibility:** path = extend the ribbon render (`_memory_ribbon_text` `screens_directionb.py:2522`, `_ribbon_caption` `:2561`) to draw a before (pre-CRC footprint) alongside the after (`result.image_ranges`) · fits one batch? = yes (Inc-3).
- **Evaluability:** When CRC grows the image, the engineer observes a before ribbon and a larger after ribbon (→ **AT-129**).
- **Open questions:** where does the "before" footprint come from? Decision: `run_flow` records the pre-CRC footprint on the result (a new field, see LLR-094.1) so the view is not re-deriving it. NEW field flagged.
- **Classification:** `READY`.

---

## 3. High-level requirements (HLR)

### HLR-089 — CRC block computes and injects a CRC over the working post-patch image
- **Traceability:** US-C52-1
- **Statement:** When a `CrcBlock` executes in a flow with a valid resolved config, the system shall compute the CRC over the current threaded (post-patch) working image via the shared CRC kernel, inject the computed CRC bytes at the config's output address, and thread the resulting image forward to downstream blocks.
- **Rationale (informative):** Finalization must run over the patched image; `check_regions` computes `computed_crc` even with no stored value, so a fresh finalization is well-defined.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_flow_execution_service.py -k "crc_inject"` (file/`-k` provisional-until-Phase-3) + an artifact-on-disk read of the written file at the config output address.
- **Numeric pass threshold:** exit 0; written bytes at `output_address` equal the little-endian `computed_crc` (`output_bytes` wide), byte-exact.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** the file written by a `SOURCE→PATCH→CRC→WRITE-OUT` run contains the computed CRC bytes at the config's output address.
  - **Shipped surface:** `run_flow(flow, ctx)` → the WRITE-OUT file under `.s19tool/workarea/<project>/`.
  - **Deliverable + observation:** the written S19/HEX file at its path, re-read into a mem_map; assert `output_bytes` little-endian CRC present at `output_address`.
  - **Acceptance test(s):** `AT-123`
  - **Boundary catalog (QC-3):** ☑ empty (no CRC targets → block ok/notices, no write of CRC — covered by AT/TC) ☑ boundary (output window exactly at a range edge — TC-349) ☑ invalid (malformed config — HLR-092/AT-126) ☑ error (escaping ref — HLR-092/AT-127).

### HLR-090 — CRC block grows the image address space when the output window is outside loaded ranges
- **Traceability:** US-C52-2
- **Statement:** When a `CrcBlock` injects a CRC whose output window falls outside every loaded range, the system shall grow the working `(mem_map, ranges)` to cover the output window and shall carry the grown footprint into `FlowRunResult.image_ranges` and to downstream WRITE-OUT/CHECK blocks.
- **Rationale (informative):** A CRC appended past the loaded image extends the artifact; downstream stages and the ribbon must see the extended footprint.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_flow_execution_service.py -k "crc_grow"` (provisional) — assert `image_ranges` and the written ranges include the new CRC window absent from the SOURCE image.
- **Numeric pass threshold:** exit 0; the CRC window `[output_address, output_address+N)` is a member of `result.image_ranges` and NOT a member of the SOURCE `ranges`.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** `FlowRunResult.image_ranges` (and the written file's ranges) include the new CRC window that was absent from the SOURCE image.
  - **Shipped surface:** `run_flow(flow, ctx)` → `result.image_ranges` + the WRITE-OUT file.
  - **Deliverable + observation:** `result.image_ranges` list + the re-read written file's contiguous ranges; assert the CRC window is present in both and absent from the SOURCE footprint.
  - **Acceptance test(s):** `AT-124`
  - **Boundary catalog (QC-3):** ☑ empty (output inside loaded ranges → no growth, image_ranges unchanged — TC-350) ☑ boundary (output abutting a range edge → merge, still sorted non-overlapping — TC-349) ☑ invalid (N/A — growth path unreached on a bad config) ☐ error (N/A — a grown image is not an error path).

### HLR-091 — CRC ordering guidance: a CRC before any PATCH emits a non-blocking WARN
- **Traceability:** US-C52-3
- **Statement:** If a `CrcBlock` is positioned before any `PatchBlock` in the flow (or the flow has no `PatchBlock`), then the system shall attach a WARN finding to the CRC block, mark it `BLOCK_STATUS_NOTICES`, and resolve the flow status to `completed-with-issues` without aborting the run.
- **Rationale (informative):** CRC-ing an un-patched image is usually a mistake; the guidance is advisory, not a hard block (collect-don't-abort).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_flow_execution_service.py -k "crc_order_warn"` (provisional).
- **Numeric pass threshold:** exit 0; the CRC `BlockResult.findings` contains a `FINDING_WARN`, its status is `BLOCK_STATUS_NOTICES`, `result.status == FLOW_STATUS_ISSUES`, and `len(block_results) == len(flow.blocks)` (no abort).
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** a flow with CRC before PATCH produces a WARN finding + flow status `completed-with-issues`, and still runs to completion.
  - **Shipped surface:** `run_flow(flow, ctx)` → `result.status` + the CRC `BlockResult`.
  - **Deliverable + observation:** the `FlowRunResult` object; assert WARN finding present, block `notices`, flow `completed-with-issues`, all blocks executed.
  - **Acceptance test(s):** `AT-125`
  - **Boundary catalog (QC-3):** ☑ empty (CRC-only flow, no PATCH → warns — LLR-091.1) ☑ boundary (CRC immediately after PATCH → no warn — TC-352) ☐ invalid (N/A — ordering is independent of config validity) ☐ error (N/A — non-blocking by definition).

### HLR-092 — CRC config safety: fail-close on a malformed or unsafe config_ref  *(security)*
- **Traceability:** US-C52-4
- **Statement:** If a `CrcBlock`'s `config_ref` fails containment resolution (absolute path, escape-project-root, or reparse-point) OR the referenced config is malformed (parse errors), then the system shall mark that block `BLOCK_STATUS_ERROR`, leave the working image un-injected, skip all downstream blocks as `BLOCK_STATUS_SKIPPED`, resolve the flow status to `error`, and return a well-formed `FlowRunResult` without raising.
- **Rationale (informative):** The `config_ref` is untrusted; the batch reuses the exact F1 manifest containment guard and the kernel's config validation so a hostile template cannot open out-of-project files or corrupt the run.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_flow_execution_service.py -k "crc_fail_close or crc_containment"` (provisional).
- **Numeric pass threshold:** exit 0; for every hostile/malformed case: CRC block `status == BLOCK_STATUS_ERROR`, downstream blocks `status == BLOCK_STATUS_SKIPPED`, `result.status == FLOW_STATUS_ERROR`, no exception propagates, and (containment cases) the target file is never opened.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** a malformed config OR an out-of-project/escaping `config_ref` → the CRC block errors, downstream is skipped, flow status is `error`, and the run returns normally (never crashes).
  - **Shipped surface:** `run_flow(flow, ctx)` → `result.status` + `result.block_results`.
  - **Deliverable + observation:** the `FlowRunResult`; assert the error/skip/error triad and that `run_flow` returned (no raised exception). For containment, assert the resolver rejected before any file open.
  - **Acceptance test(s):** `AT-126` (malformed), `AT-127` (containment triad: absolute, escape, reparse)
  - **Boundary catalog (QC-3):** ☑ empty (empty/zero-byte config file → parse errors → block error — AT-126) ☑ boundary (config with valid syntax but no targets → ok, not an error — distinct from malformed, TC-346) ☑ invalid (malformed JSON / schema errors — AT-126) ☑ error (absolute / `..` escape / reparse-point ref — AT-127).

### HLR-093 — Flow Builder surfaces and renders a CRC block
- **Traceability:** US-C52-5
- **Statement:** When the engineer opens the Flow Builder add-block dropdown, the system shall list a CRC option, and when a CRC block is added and the flow is run, the system shall render a CRC node and display its post-run status/message.
- **Rationale (informative):** The block must be composable and observable in the TUI, matching the CHECK block's UX.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_tui_directionb.py -k "crc_node"` (provisional) via `App.run_test()` Pilot.
- **Numeric pass threshold:** exit 0; the dropdown options include the CRC entry; after add the panel contains a CRC node; after Run the node shows the CRC block's status text.
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** the add-block dropdown lists CRC; adding renders a CRC node; after Run its status/message shows.
  - **Shipped surface:** `FlowBuilderPanel` (`screens_directionb.py:2571`) in `App.run_test()`.
  - **Deliverable + observation:** the rendered panel tree; assert the CRC option label present, a CRC node widget present after add, and a status string after Run.
  - **Acceptance test(s):** `AT-128`
  - **Boundary catalog (QC-3):** ☑ empty (empty flow renders without error — G-1 / TC-358) ☑ boundary (a CRC node adjacent to CHECK/WRITE-OUT nodes renders distinctly — TC-357) ☐ invalid (N/A — dropdown values are fixed) ☐ error (a CRC block that errored shows its error message — covered via AT-126 surface).

### HLR-094 — Before/after twin ribbon shows image growth
- **Traceability:** US-C52-6
- **Statement:** When a flow run's CRC block grows the working image, the system shall render a before/after memory ribbon whose after footprint is visibly larger than its before footprint; and the system shall hide the per-block gating control for non-CHECK blocks.
- **Rationale (informative):** The growth is the batch's visible signature; the gating control is CHECK-only (F3 carry) and must not appear on a CRC/other node.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_tui_directionb.py -k "twin_ribbon or gating_hidden"` (provisional) via `App.run_test()` + `_memory_ribbon_text` unit assertions.
- **Numeric pass threshold:** exit 0; the after ribbon's filled-cell count > the before ribbon's when CRC grew the ranges; the gating control is absent for a non-CHECK selected kind.
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** the ribbon renders a before footprint and an after footprint that is visibly larger when CRC grew the image.
  - **Shipped surface:** `FlowBuilderPanel` ribbon render (`_memory_ribbon_text` `:2522` / `_ribbon_caption` `:2561`).
  - **Deliverable + observation:** the rendered before + after ribbon `Text`; assert after filled-cell count strictly greater than before when grown, equal when not.
  - **Acceptance test(s):** `AT-129`
  - **Boundary catalog (QC-3):** ☑ empty (empty flow / no image → both ribbons render an empty/neutral strip, no crash — G-1 / TC-358) ☑ boundary (CRC ran but did not grow → after == before — TC-360) ☐ invalid (N/A) ☐ error (errored flow → after ribbon reflects last intact footprint — TC-360).

---

## 4. Low-level requirements (LLR)

### LLR-089.1 — CrcBlock dataclass + BLOCK_CRC discriminator
- **Traceability:** HLR-089
- **Statement:** `flow_model.py` shall define `BLOCK_CRC = "crc"` and a frozen dataclass `CrcBlock(config_ref: str, kind: str = BLOCK_CRC)`, and shall add `CrcBlock` to the `FlowBlock` union.
- **Symbols:** `BLOCK_CRC` — **NEW, created in Phase 3** (siblings at `flow_model.py:23-26`); `CrcBlock` — **NEW** (sibling dataclasses `flow_model.py:78-144`); `FlowBlock` union at `flow_model.py:148` (edited to add `CrcBlock`).
- **Validation:** `test (unit)`
- **Executed verification:** `pytest tests/test_flow_execution_service.py -k "crc_block_model"` (provisional).
- **Numeric pass threshold:** exit 0; `CrcBlock(config_ref="x").kind == "crc"` and `CrcBlock` is a member of `FlowBlock`.
- **Acceptance criteria:** `config_ref` is documented as a PROJECT-RELATIVE ref resolved through the containment guard (mirrors `SourceBlock.image_ref` doc at `flow_model.py:83-85`).

### LLR-089.2 — CRC branch in run_flow computes over the threaded post-patch image
- **Traceability:** HLR-089
- **Statement:** When `run_flow` encounters an `isinstance(block, CrcBlock)` with a resolved+valid config and a non-`None` threaded `mem_map`/`ranges`, the system shall build an `OperationInput(mem_map, ranges, …)` from the CURRENT threaded image, call `check_regions(op_input, config)`, and thus compute the CRC over the post-patch image.
- **Symbols:** CRC branch — **NEW** `elif` in `run_flow` alongside the PATCH/WRITE-OUT/CHECK branches (`flow_execution_service.py:171-289`); `OperationInput` (`operations/model.py:27`); `check_regions` (`crc.py:757`).
- **Validation:** `test (integration)`
- **Executed verification:** `pytest tests/test_flow_execution_service.py -k "crc_inject"` (provisional).
- **Numeric pass threshold:** exit 0; the `computed_crc` matches an independently computed CRC over the post-patch mem_map at the configured target.
- **Acceptance criteria:** the `mem_map` handed to `OperationInput` is the same object mutated by any upstream PATCH branch (post-patch), not the raw SOURCE map.

### LLR-089.3 — Inject via the shared kernel and thread the working copy forward
- **Traceability:** HLR-089
- **Statement:** After computing regions, the system shall call `inject_crcs(op_input, crc_regions)` and shall reassign the threaded `mem_map` and `ranges` to the returned working `mem_map`/`ranges`, so all downstream blocks operate on the CRC-injected image.
- **Symbols:** `inject_crcs` (`crc.py:1081`, returns `(working_mem_map, working_ranges, written_regions)`); the threaded `mem_map`/`ranges` locals (`flow_execution_service.py:107-108`, reassigned like `142-143`).
- **Validation:** `test (integration)`
- **Executed verification:** `pytest tests/test_flow_execution_service.py -k "crc_thread_forward"` (provisional).
- **Numeric pass threshold:** exit 0; a downstream WRITE-OUT emits the injected CRC bytes; the original SOURCE `mem_map` object is never mutated (working-copy contract, `crc.py:1092-1093`).
- **Acceptance criteria:** `check_regions` computes `computed_crc` unconditionally (no stored value required — `crc.py:757`), so a fresh finalization injects a well-defined CRC.

### LLR-089.4 — CRC BlockResult status + summary
- **Traceability:** HLR-089
- **Statement:** On a successful CRC injection the system shall append a `BlockResult(index, "crc", BLOCK_STATUS_OK, <summary>)` whose `summary` field summarises the injected region count and output address(es); it shall use `BLOCK_STATUS_NOTICES` (not error) when the ordering WARN of LLR-091.1 applies.
- **Symbols:** `BlockResult` (`flow_model.py`, `BlockResult(index, kind, status, summary, findings)` — the human-readable field is `summary`, not `message`; R-D3); `BLOCK_STATUS_OK` (`flow_model.py:41`), `BLOCK_STATUS_NOTICES` (`flow_model.py:46`).
- **Validation:** `test (unit)`
- **Executed verification:** `pytest tests/test_flow_execution_service.py -k "crc_block_result"` (provisional).
- **Numeric pass threshold:** exit 0; on success `status == BLOCK_STATUS_OK` and the message names the injected region count.
- **Acceptance criteria:** message text is int/count-derived, never echoing raw file content (C-9).

### LLR-090.1 — Grow working ranges when the output window is outside loaded ranges
- **Traceability:** HLR-090
- **Statement:** Where `inject_crcs` returns working `ranges` grown to cover an output window outside the loaded ranges, the system shall thread those grown `ranges` forward unchanged (kept sorted, non-overlapping by `_extend_ranges`) and shall not re-sort or re-merge them itself.
- **Symbols:** `_extend_ranges` (internal to `crc.py`, invoked by `inject_crcs` — `crc.py:1097`); the threaded `ranges` local (`flow_execution_service.py:108`).
- **Validation:** `test (integration)`
- **Executed verification:** `pytest tests/test_flow_execution_service.py -k "crc_grow"` (provisional).
- **Numeric pass threshold:** exit 0; after CRC, `ranges` contain `[output_address, output_address+N)`; ranges remain sorted and non-overlapping.
- **Acceptance criteria:** growth is only added when the window is outside every loaded range; an in-range output leaves range count unchanged.

### LLR-090.2 — Grown footprint reaches image_ranges and downstream blocks
- **Traceability:** HLR-090
- **Statement:** After a CRC block grows the image, the system shall ensure `run_flow`'s tail assignment `result.image_ranges = [(int(start), int(end)) for start, end in ranges]` reflects the grown `ranges`, and downstream WRITE-OUT/CHECK read the grown `(mem_map, ranges)`.
- **Symbols:** the tail `image_ranges` assignment (`flow_execution_service.py:315-316`) — reuse; its guiding comment (`:310-314`) explicitly anticipates batch-52 growth.
- **Validation:** `test (integration)`
- **Executed verification:** `pytest tests/test_flow_execution_service.py -k "crc_image_ranges"` (provisional).
- **Numeric pass threshold:** exit 0; `result.image_ranges` includes the CRC window; a downstream CHECK over the CRC window reports it present.
- **Acceptance criteria:** no edit to the tail assignment is required beyond the threaded `ranges` now being the grown ones (the comment at `:313-314` documents the intent).

### LLR-091.1 — Detect CRC-before-PATCH and attach a non-blocking WARN
- **Traceability:** HLR-091
- **Statement:** If the CRC block's index is less than the index of the first `PatchBlock` in the flow, or the flow contains no `PatchBlock`, then the system shall append a `Finding(FINDING_WARN, <ordering message>)` to the CRC `BlockResult` and set its status to `BLOCK_STATUS_NOTICES`, and shall NOT set `aborted`.
- **Symbols:** `Finding` (`flow_model.py:64`), `FINDING_WARN` (`flow_model.py:61`), `PatchBlock` (`flow_model.py:94`); the `aborted` local (`flow_execution_service.py:111`) — must remain unset on this path.
- **Validation:** `test (unit)`
- **Executed verification:** `pytest tests/test_flow_execution_service.py -k "crc_order_warn"` (provisional).
- **Numeric pass threshold:** exit 0; WARN finding present, block `notices`, `aborted` is `False`, all downstream blocks still execute.
- **Acceptance criteria:** the ordering check reads the static block list (indices), not runtime state; message names the ordering issue in plain text.

### LLR-091.2 — Flow status resolves to completed-with-issues on the ordering WARN
- **Traceability:** HLR-091
- **Statement:** The system shall rely on the existing three-way roll-up so that a CRC `BLOCK_STATUS_NOTICES` / WARN finding (with no `aborted`) resolves `result.status` to `FLOW_STATUS_ISSUES`.
- **Symbols:** status roll-up (`flow_execution_service.py:300-308`) — reuse; `FLOW_STATUS_ISSUES` (`flow_model.py:54`).
- **Validation:** `test (integration)`
- **Executed verification:** `pytest tests/test_flow_execution_service.py -k "crc_order_status"` (provisional).
- **Numeric pass threshold:** exit 0; `result.status == FLOW_STATUS_ISSUES` for a CRC-before-PATCH flow that otherwise runs clean.
- **Acceptance criteria:** no new status token; the roll-up branch (`:302-306`) already keys on `findings` and `BLOCK_STATUS_NOTICES`.

### LLR-092.1 — config_ref containment via the reused manifest guard
- **Traceability:** HLR-092
- **Statement:** Before opening a CRC config, the system shall resolve `config_ref` through `_resolve_manifest_entry(ctx.project_dir, block.config_ref, "CrcBlock.config_ref", issues)`; if it returns `None` or a non-existent path, the system shall call `_record_error(...)` (setting `aborted`) and shall NOT open any file.
- **Symbols:** `_resolve_manifest_entry` (imported `flow_execution_service.py:63`) — reuse verbatim; `_record_error` (`flow_execution_service.py:368`) — reuse; mirrors the SOURCE containment path (`flow_execution_service.py:124-133`).
- **Validation:** `test (unit)`
- **Executed verification:** `pytest tests/test_flow_execution_service.py -k "crc_containment"` (provisional) with absolute, `..`-escape, and reparse-point `config_ref` fixtures.
- **Numeric pass threshold:** exit 0; each hostile ref → CRC block `BLOCK_STATUS_ERROR`, `aborted` set, and no `open`/read of the target occurs (asserted via a non-existent/quarantined target).
- **Acceptance criteria:** the resolution/containment logic is NOT forked or re-implemented — the same helper the SOURCE/PATCH/CHECK blocks use.

### LLR-092.2 — Malformed config fails the block closed
- **Traceability:** HLR-092
- **Statement:** When the resolved config text is parsed via `parse_crc_config(text)` and returns `(None, errors)` with a non-empty `errors` list, the system shall call `_record_error(...)` with a message derived from the errors, leave the working image un-injected, and set `aborted`.
- **Symbols:** `parse_crc_config` (`crc_config.py:385`) — reuse; `_record_error` (`flow_execution_service.py:368`).
- **Validation:** `test (unit)`
- **Executed verification:** `pytest tests/test_flow_execution_service.py -k "crc_malformed"` (provisional) with a malformed JSON fixture and an empty-file fixture.
- **Numeric pass threshold:** exit 0; malformed config → CRC block `BLOCK_STATUS_ERROR`, image un-injected (mem_map unchanged from pre-CRC), `aborted` set.
- **Acceptance criteria:** the error message is diagnostic-derived, not the raw file body (C-9); no CRC bytes are written on this path.

### LLR-092.3 — Downstream skip, flow error, and no-raise on CRC failure
- **Traceability:** HLR-092
- **Statement:** When the CRC block sets `aborted`, the system shall record each subsequent block as `BLOCK_STATUS_SKIPPED`, resolve `result.status` to `FLOW_STATUS_ERROR`, and shall return a well-formed `FlowRunResult` (`len(block_results) == len(flow.blocks)`) without raising; any unexpected exception in the CRC branch shall be caught by the per-block isolation handler.
- **Symbols:** downstream-skip loop (`flow_execution_service.py:115-120`) — reuse; abort→`FLOW_STATUS_ERROR` (`:300-301`); per-block isolation `except` (`:290-295`) — reuse.
- **Validation:** `test (integration)`
- **Executed verification:** `pytest tests/test_flow_execution_service.py -k "crc_fail_close"` (provisional).
- **Numeric pass threshold:** exit 0; for every failure case `len(block_results) == len(flow.blocks)`, downstream blocks `SKIPPED`, `result.status == FLOW_STATUS_ERROR`, and `run_flow` returns (no exception).
- **Acceptance criteria:** the run is well-formed even when the CRC kernel itself raises on a pathological config (the outer `except` at `:290-295` catches it).

### LLR-093.1 — CRC option in the add-block dropdown
- **Traceability:** HLR-093
- **Statement:** `FlowBuilderPanel` shall include a CRC entry `("CRC (template)", BLOCK_CRC)` in its `_KIND_OPTIONS` list.
- **Symbols:** `_KIND_OPTIONS` (`screens_directionb.py:2603`) — edited to add the CRC tuple; `BLOCK_CRC` (NEW, LLR-089.1); `FlowBuilderPanel` (`screens_directionb.py:2571`).
- **Validation:** `test (unit)`
- **Executed verification:** `pytest tests/test_tui_directionb.py -k "crc_dropdown"` (provisional).
- **Numeric pass threshold:** exit 0; `_KIND_OPTIONS` contains a tuple whose value is `BLOCK_CRC`.
- **Acceptance criteria:** the label is human-readable and distinct from the CHECK/WRITE-OUT labels.

### LLR-093.2 — Add + render a CRC node and its post-run status
- **Traceability:** HLR-093
- **Statement:** When a CRC block is added with a `config_ref` and the flow is run, `FlowBuilderPanel` shall render a CRC node showing its `config_ref` and, after Run, its `BlockResult` status/message.
- **Symbols:** the block-add + node-render path in `FlowBuilderPanel` (`screens_directionb.py:2571`); the Add path that reads kind/gating (`screens_directionb.py:2448` `if kind == BLOCK_CHECK` region) — extended for CRC's `config_ref`.
- **Validation:** `test (e2e)`
- **Executed verification:** `pytest tests/test_tui_directionb.py -k "crc_node"` (provisional) via `App.run_test()`.
- **Numeric pass threshold:** exit 0; after add a CRC node is present; after Run the node shows the CRC status text.
- **Acceptance criteria:** a CRC block reads a text `config_ref` field (no config-picker required this batch); the gating control is NOT shown for CRC (see LLR-094.3).

### LLR-094.1 — Record a pre-CRC footprint and render the before/after twin ribbon
- **Traceability:** HLR-094
- **Statement:** `run_flow` shall record the pre-CRC image footprint on the result (a new `pre_crc_ranges` field, defaulting to the SOURCE footprint), and `FlowBuilderPanel` shall render a before ribbon from that field and an after ribbon from `result.image_ranges`.
- **Symbols:** `pre_crc_ranges` on `FlowRunResult` — **NEW field, created in Phase 3** (additive, mirrors `image_ranges` per §6.5 AMD-1 / LLR-088.4); `_memory_ribbon_text` (`screens_directionb.py:2522`) and `_ribbon_caption` (`:2561`) — reused for both ribbons; existing single-ribbon render at `screens_directionb.py:2773-2782`.
- **Validation:** `test (unit)`
- **Executed verification:** `pytest tests/test_tui_directionb.py -k "twin_ribbon"` (provisional) + `_memory_ribbon_text` unit assertions on cell counts.
- **Numeric pass threshold:** exit 0; when CRC grew the ranges, the after ribbon's filled-cell count > the before ribbon's; when it did not, they are equal.
- **Acceptance criteria:** `pre_crc_ranges` is additive (empty when no image loaded); the view does not re-derive the pre-CRC footprint itself.

### LLR-094.2 — After ribbon reflects growth; equal when unchanged
- **Traceability:** HLR-094
- **Statement:** The before/after ribbon render shall show a strictly larger after footprint only when `result.image_ranges` covers more address space than `pre_crc_ranges`, and shall show equal footprints otherwise.
- **Symbols:** ribbon render block (`screens_directionb.py:2773-2782`) — extended to a twin; `_ribbon_caption` (`:2561`) reports both extents.
- **Validation:** `test (integration)`
- **Executed verification:** `pytest tests/test_tui_directionb.py -k "twin_ribbon_grow"` (provisional).
- **Numeric pass threshold:** exit 0; grown → after cells > before cells; not grown → after cells == before cells.
- **Acceptance criteria:** an errored flow renders the last intact footprint on the after ribbon (no crash).

### LLR-094.3 — Hide the gating control for non-CHECK blocks (F3 carry)
- **Traceability:** HLR-094
- **Statement:** `FlowBuilderPanel` shall render the per-block gating control only when the selected block kind is `BLOCK_CHECK`, and shall hide it for `BLOCK_SOURCE`, `BLOCK_PATCH`, `BLOCK_WRITE_OUT`, and `BLOCK_CRC`.
- **Symbols:** `_GATING_OPTIONS` (`screens_directionb.py:2613`) + the Add path `if kind == BLOCK_CHECK` (`screens_directionb.py:2448`); the gating control widget in `FlowBuilderPanel`.
- **Validation:** `test (e2e)`
- **Executed verification:** `pytest tests/test_tui_directionb.py -k "gating_hidden"` (provisional) via `App.run_test()`.
- **Numeric pass threshold:** exit 0; the gating control is present when kind == CHECK and absent for every other kind, including CRC.
- **Acceptance criteria:** the batch-51 CHECK gating behaviour is unchanged; only visibility for non-CHECK kinds is corrected.

---

## 5. Validation strategy

### 5.1 Methods

- **Test (Layer A · white-box, `TC-NNN`):** pytest unit/integration/e2e. Engine TCs exercise `run_flow` in-process; UI TCs use Textual `App.run_test()` Pilot. Every `test` LLR names its executed verification (`pytest … -k …`) and numeric threshold above.
- **Acceptance (Layer B · black-box, `AT-NNN`):** engine ATs drive `run_flow` and inspect the `FlowRunResult` and the written artifact-on-disk; UI ATs drive `FlowBuilderPanel` through `App.run_test()`. Each asserts the story outcome through the shipped surface with boundary + negative evidence.
- **Probe pre-state (RED-before-fix):** at draft, `BLOCK_CRC` / `CrcBlock` do not exist, so no CRC flow can be constructed — every `AT-123..129` fails at construction/import today (recorded RED). After Inc-1/2/3 each turns GREEN. This is the expected pre-state per the probe self-test rule.
- **Test-runtime check:** all TCs run under the repo's existing `pytest` (the project's ratified runner per `CLAUDE.md` / `pyproject.toml`); no new test framework is introduced.

### 5.2 Dual-traceability table

**Behavioral chain (black-box) — per user story**

| US | Observable outcome | Shipped surface | Acceptance test (`AT-NNN`) | Observed? |
|----|--------------------|-----------------|----------------------------|-----------|
| US-C52-1 | Written file has computed CRC bytes at config output address | `run_flow` → WRITE-OUT file | AT-123 | Phase 4 |
| US-C52-2 | `image_ranges` / written ranges include the new CRC window absent from SOURCE | `run_flow` → `image_ranges` + file | AT-124 | Phase 4 |
| US-C52-3 | CRC-before-PATCH → WARN + `completed-with-issues`, still runs | `run_flow` → `result.status` + BlockResult | AT-125 | Phase 4 |
| US-C52-4 | Malformed config → block error, downstream skipped, flow error, no raise | `run_flow` → `result` | AT-126 | Phase 4 |
| US-C52-4 | Unsafe `config_ref` (absolute/escape/reparse) → block error, file never opened, no raise | `run_flow` → `result` | AT-127 | Phase 4 |
| US-C52-5 | Dropdown lists CRC; CRC node renders; post-run status shows | `FlowBuilderPanel` (Pilot) | AT-128 | Phase 4 |
| US-C52-6 | Before ribbon + visibly larger after ribbon when CRC grew image | `FlowBuilderPanel` ribbon | AT-129 | Phase 4 |

**Functional chain (white-box) — per requirement**

| Requirement | Method | Test Case (`TC-NNN`) | Notes |
|-------------|--------|----------------------|-------|
| HLR-089 | test (integration) | TC-346, TC-347 | model + compute/inject over post-patch |
| LLR-089.1 | test (unit) | TC-346 | CrcBlock/BLOCK_CRC/union |
| LLR-089.2 | test (integration) | TC-347 | check_regions over post-patch mem_map |
| LLR-089.3 | test (integration) | TC-348 | inject + thread working copy forward |
| LLR-089.4 | test (unit) | TC-348 | BlockResult status/message |
| HLR-090 | test (integration) | TC-349, TC-350 | grow + image_ranges |
| LLR-090.1 | test (integration) | TC-349 | grow via _extend_ranges (boundary/abut) |
| LLR-090.2 | test (integration) | TC-350 | image_ranges + downstream sees window |
| HLR-091 | test (integration) | TC-351, TC-352 | ordering WARN + status |
| LLR-091.1 | test (unit) | TC-351 | WARN finding, non-aborting, CRC-only flow |
| LLR-091.2 | test (integration) | TC-352 | completed-with-issues; PATCH→CRC no warn |
| HLR-092 | test (integration) | TC-353, TC-354, TC-355 | fail-close triad |
| LLR-092.1 | test (unit) | TC-353 | containment: absolute/escape/reparse, no open |
| LLR-092.2 | test (unit) | TC-354 | malformed/empty config → error, un-injected |
| LLR-092.3 | test (integration) | TC-355 | downstream skipped + flow error + no raise |
| HLR-093 | test (e2e) | TC-356, TC-357, TC-358 | dropdown + node + empty-flow (G-1) |
| LLR-093.1 | test (unit) | TC-356 | CRC in _KIND_OPTIONS |
| LLR-093.2 | test (e2e) | TC-357 | add + render node + post-run status |
| HLR-094 | test (integration) | TC-359, TC-360, TC-361 | twin ribbon + gating hide |
| LLR-094.1 | test (unit) | TC-359 | pre_crc_ranges + twin render |
| LLR-094.2 | test (integration) | TC-360 | after>before when grown; equal otherwise |
| LLR-094.3 | test (e2e) | TC-361 | gating hidden for non-CHECK (F3) |
| — (G-1) | test (e2e) | TC-358 | empty-flow renders without crash |

### 5.3 Batch acceptance criteria

- 100% of LLR-089.x..094.x covered by ≥1 passing `TC`.
- Every user story (US-C52-1..6) has ≥1 passing `AT-NNN` observing its outcome through the shipped surface with boundary + negative evidence.
- 0 blocker fails; `run_flow` never raises across all fail-close cases (`AT-126`, `AT-127`, TC-355).
- No edit to any engine-frozen module; the frozen-guard tests (`tests/test_engine_unchanged.py`, `tests/test_tui_directionb.py::test_tc031_*`) stay green.
- The CRC kernel (`crc.py`, `crc_config.py`) is byte-unchanged (reuse-only); a diff-vs-`main` on those files is empty.
- Each increment ≤5 files.

---

## 6. Appendices

### 6.1 Extended glossary

See §1.3. Additionally: **pre_crc_ranges** — a new additive `FlowRunResult` field carrying the working footprint captured immediately before the first CRC growth, used only for the before ribbon.

### 6.2 Relevant design decisions

- **DD-1 — Reuse, don't fork the CRC kernel.** The block calls `parse_crc_config` + `check_regions` + `inject_crcs` directly. This reconciles the two CRC surfaces: the batch-58 CRC Designer stays **preview-only** (`written=False`, never writes), while the flow block **writes** by consuming `inject_crcs`'s working copy and letting the downstream WRITE-OUT emit it. Both read the same templates from `.s19tool/templates/`.
- **DD-2 — Growth lives in the kernel.** `inject_crcs` already grows ranges via `_extend_ranges`; `run_flow` merely threads the returned working copy forward, so the image-growth invariant (sorted, non-overlapping) is not re-implemented in the service.
- **DD-3 — Advisory ordering, not hard block.** CRC-before-PATCH is a WARN (`notices`), consistent with the collect-don't-abort contract and batch-51's amber `completed-with-issues`.
- **DD-4 — Containment reuse.** `config_ref` uses the exact `_resolve_manifest_entry` guard the SOURCE/PATCH/CHECK refs use; no new resolution surface is introduced (a consume-of-untrusted-file story gets no new-write-surface pass — batch-24 state-lifetime rule satisfied because the config is validated pre-use and never persisted here).
- **DD-5 — Text config_ref field.** No config-picker UI this batch; a text `config_ref` is sufficient and keeps Inc-2 within budget.

### 6.3 Open risks

- **R-1 — Pre-CRC footprint provenance.** `pre_crc_ranges` must be captured at the right point (immediately before the first CRC growth, defaulting to SOURCE). If captured too late (after growth) the before ribbon equals the after ribbon and US-C52-6 is unobservable. Mitigation: LLR-094.1 pins the capture point; TC-360 asserts after>before when grown.
- **R-2 — Multiple CRC blocks in one flow.** The spec targets a single growth event for the ribbon; a second CRC block that grows again would not be reflected by a single before/after pair. Scope decision: one before/after pair (first-to-last footprint); documented, not multi-step. Reversible.
- **R-3 — Config with no targets vs malformed.** A syntactically valid config with zero targets is `ok` (nothing to inject), NOT an error — distinct from malformed. TC-346/TC-354 separate the two; a conflation would wrongly error a valid empty config.
- **R-4 — Kernel raises on a pathological (in-range but degenerate) config.** Covered by the per-block isolation `except` (`flow_execution_service.py:290-295`); LLR-092.3 asserts no-raise even here.

### 6.4 Phase-1 reconciliation log

**Two-artifact reconciliation (2026-07-22).** `01-requirements.md` (this doc, architect-authored) and `01b-qa-catalog.md` (qa-reviewer-authored) were produced in parallel and diverged on id scheme + AT granularity. Reconciled by the orchestrator (the architect fold subagent died to a weekly usage limit mid-fold; reconciliation completed inline). Decisions:

- **R-D1 — Authoritative id scheme = THIS doc (AT-123..129 / TC-346..361 / HLR-LLR-089..094).** The qa-catalog independently numbered AT-130..140 / TC-350..363; those are **SUPERSEDED**. Rationale: this is the integrated requirements doc with the full US→HLR→LLR→TC/AT traceability matrix (§5.2); re-keying it is higher-churn/higher-error than re-keying the catalog, especially under the active usage-limit constraint. This is a deliberate deviation from the batch-56 "qa-catalog authoritative" precedent, recorded for operator visibility. Story→AT map is unchanged (US-C52-1→AT-123 … US-C52-6→AT-129; US-C52-4→AT-126 malformed + AT-127 containment). Phase-3 test authoring uses THIS doc's ids; the qa-catalog is retained as the detailed **test-design reference** (its per-branch decomposition feeds the C-10 coverage below).
- **R-D2 — C-10 branch coverage folded in (from the qa-catalog).** Each single-id AT covering an A/B policy MUST assert BOTH branches as distinct cases (not a new top-level id): **AT-124** (growth) covers grow (output outside ranges) AND no-grow (output inside ranges → footprint unchanged); **AT-125** (ordering) covers CRC-after-PATCH (no warn) AND CRC-before-PATCH (WARN, still runs). US-C52-4 is already two ids (AT-126/127). This preserves the qa-catalog's per-branch intent within this doc's id space.
- **R-D3 — Field-name correction (qa concern #5).** The engine field is `BlockResult(index, kind, status, summary, findings)` — the human-readable field is **`summary`**, not `message`; findings are `Finding(severity, message)`. LLR-089.4's "status/message" reads **status/summary**. (Applied.)
- **R-D4 — Containment explicit (qa concern #1).** The flow CRC block's `config_ref` is CONTAINED via the reused `_resolve_manifest_entry` guard (LLR-092.1, DD-4). The standalone CRC Designer's "uncontained-by-design (F-S-02)" note applies ONLY to that separate screen; it does NOT apply to the flow block. AT-127 (containment triad) is therefore achievable.
- **R-D5 — Failure-semantics split confirmed (qa concern #4).** Malformed / absent / uncontained `config_ref` = **ABORTING** (block → `BLOCK_STATUS_ERROR` via `_record_error`, image breaks, downstream SKIPPED, flow status `error`, `run_flow` never raises) — HLR-092. Wrong ORDERING (CRC before any PATCH) = **NON-aborting WARN** (`Finding(FINDING_WARN, …)`, flow `completed-with-issues`, block still runs) — HLR-091. The two are separate HLRs.
- **R-D6 — Ordering-WARN stable substring (qa concern #2).** LLR-091.1's WARN message shall contain the stable substring **`"CRC before PATCH"`** (tests bind to it).
- **R-D7 — R-1 / R-2 resolved.** `pre_crc_ranges` is captured immediately before the FIRST CRC growth (= SOURCE footprint; PATCH mutates in place and does not grow). No CRC → `pre_crc_ranges == image_ranges` (before == after). One before/after pair per flow (R-2 accepted, reversible).

| Decision ID | What changed | Parent HLR re-read? | Body edit landed? |
|-------------|--------------|---------------------|-------------------|
| R-D1 | Authoritative id scheme = this doc; qa-catalog AT-130-140/TC-350-363 superseded | n/a (id-only) | §6.4 |
| R-D2 | C-10 branch coverage folded onto AT-124/125 | HLR-090/091 | §6.4 (test-design note) |
| R-D3 | `message` → `summary` field name | HLR-089 | LLR-089.4 |
| R-D4 | config_ref containment explicit (flow block ≠ standalone F-S-02) | HLR-092 | §6.4 / DD-4 |
| R-D5 | fail-close ABORT vs ordering WARN split | HLR-091/092 | §6.4 |
| R-D6 | WARN stable substring `"CRC before PATCH"` | HLR-091 | LLR-091.1 |
| R-D7 | pre_crc_ranges capture point + single pair | HLR-094 | LLR-094.1 |

### 6.5 Requirement amendments (Before / After · Deleted / New)

**None — no locked requirement was amended, deleted, or added in this batch.**

The Phase-3 shared-axis ribbon decision (rendering before+after over a COMMON
48-cell `window` so "after cells > before cells" holds under growth) was an
**implementation detail of LLR-094.1**, not a requirement change — recorded as a
design note in `PLAN.md` (2026-07-23) and `05-postmortem.md`, both of which state
"§6.5 stays empty — no locked requirement changed". The `AMD-1` references
elsewhere in this file point to **batch-51's** `image_ranges`-ribbon amendment
(carried forward as context), not a batch-52 amendment.

*(Filled 2026-07-23 during the N6/N7 fast-flow: the artifact-completeness
pre-commit hook flags a section left with only template guidance; this records
the already-documented fact that batch-52 had no amendment. No requirement
content changed — batch-52 is merged.)*
