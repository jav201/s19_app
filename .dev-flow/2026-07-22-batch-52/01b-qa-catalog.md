# 01b — QA Catalog — batch-52 Flow Builder CRC block

**Batch:** 2026-07-22-batch-52 · Flow Builder **CRC block**
**Owner:** qa-reviewer (this file is the AUTHORITATIVE source for AT-NNN + TC-NNN ids and validation methods)
**Parallel doc:** architect owns `01-requirements.md` (US / HLR / LLR). LLR ids referenced below are **provisional** (`LLR-089.x`+) and coordinate with the architect's `090+` block — the architect's file is authoritative for the final LLR text; this catalog owns the test ids.
**Language:** English.

---

## 0. Scope restated (one sentence)

A template-driven **CRC block** in the ordered Flow Builder pipeline (`SOURCE → PATCH → CRC → WRITE-OUT/CHECK`) that computes a CRC over the **working post-patch image** from a JSON config, injects the CRC bytes, **grows** `(mem_map, ranges)` when the output window lies outside loaded ranges, and threads the extended image forward — surfaced in the Direction-A panel (dropdown add, node render, before/after ribbon).

**Primary user goal:** *the user can add a CRC step to a flow that stamps a correct CRC into the patched image and (when needed) extends the image to hold it, seeing the growth in the pipeline ribbon.*

## 1. Id allocation (collision-checked)

- **Highest existing on disk:** `AT-122` (batch-56), `TC-345` (repo-wide, `tests/`).
- **This batch — ATs:** `AT-130 .. AT-140` (11). Range `AT-123..129` deliberately skipped as a clean gap; `AT-130+` is unambiguously free (verified: no `AT-1[23][0-9]` in md/py except 120-122).
- **This batch — TCs:** `TC-350 .. TC-363` (14). `TC-346..349` skipped as a gap; `TC-350+` free (verified: max `tcNNN` in `tests/` = 345).

## 2. Disk-verified anchors (what the catalog is grounded on)

| Fact | Location |
|---|---|
| `run_flow(flow, ctx)` threads `mem_map/ranges`, never raises, per-block `except` (F5); `_record_error` sets `aborted` → downstream `SKIPPED`; three-way rollup `ok`/`completed-with-issues`/`error` | `s19_app/tui/services/flow_execution_service.py:66-317` |
| `_resolve_manifest_entry` is the **F1 containment guard** (absolute / escape-root / reparse-point triad) applied to every ref before open | same file `:124`, `:179`, `:239` |
| `BlockResult(index, kind, status, summary, diagnostics, findings)` — note the field is **`summary`** (not `message`) + `diagnostics: list[str]` + `findings: list[Finding]` | `flow_model.py:183-204` |
| `FlowRunResult(status, block_results, written_paths, diagnostics, image_ranges)` — `image_ranges` currently carries the **final** footprint; a **`before` footprint is an explicit batch-52 carry** (docstring `:226`) | `flow_model.py:207-233` |
| `CrcBlock(config_ref)` to be **added** to the `FlowBlock` union (`FlowBlock = Union[SourceBlock, PatchBlock, WriteOutBlock, CheckBlock]` today) | `flow_model.py:148` |
| Engine (frozen-eligible but `crc.py` is **NOT** in `_ENGINE_PATHS`): `check_regions(op_input, config) -> list[CrcRegionResult]` (computed_crc/output_address/output_bytes); `inject_crcs(op_input, regions) -> (mem, ranges, written)` grows ranges via `_extend_ranges` when output is outside loaded ranges; `parse_crc_config(text) -> (config|None, errors)` collect-don't-abort | `s19_app/tui/operations/crc.py:757,1081,1033` · `crc_config.py:385` |
| `OperationInput(mem_map, ranges, input_path, variant_id, file_type)` | `operations/model.py` |
| Config shape (`DUMMY_CONFIG_TEXT`): `{polynomial, init, reverse, final_xor, regions:[{start,end,output_address}], groups:[...]}` | `crc_config.py:47-67` |
| **Frozen source** (`_ENGINE_PATHS`): `core.py, hexfile.py, range_index.py, validation/, tui/a2l.py, tui/mac.py`. `crc.py`, `flow_model.py`, `flow_execution_service.py`, `screens_directionb.py` are **editable** for batch-52. **No test file is frozen** (guard is over source paths; `test_engine_unchanged.py` / `test_tui_directionb.py::test_tc031_*` are the guards themselves). | `tests/test_engine_unchanged.py:120-130` |

## 3. Target test files (C-27: new tests in NON-frozen files)

| File | New/extend | Holds |
|---|---|---|
| **`tests/test_flow_crc_block.py`** | **NEW** | Headless engine + security ATs/TCs (AT-130..137, TC-350..358, TC-361 engine arm). Reuses `_make_project` / `_S19_CLEAN` / `_check_doc` imported from `tests/test_flow_execution_service.py` (the established pattern that file already exports). |
| **`tests/test_flow_crc_surface.py`** | **NEW** | UI ATs/TCs (AT-138..140, TC-359, TC-360 F3, TC-361 render arm, TC-362, TC-363). Imports the Pilot helpers `_run_in_panel` / `_nodes` / `_seps` and `_make_project` from `tests/test_flow_builder_render.py` (module-level defs, importable) — keeps the large existing file untouched (surgical). *Alternative:* extend `test_flow_builder_render.py` directly (also non-frozen) if the team prefers colocated UI tests. |

Rationale for a new UI file over editing `test_flow_builder_render.py`: minimises diff to a 536-line file and keeps the CRC surface tests discoverable as a unit; the reusable pilot scaffold is imported, not duplicated.

---

## 4. Acceptance criteria (AT — black-box, through the shipped surface)

Every AT below drives a **shipped surface** (`run_flow` engine or the mounted `FlowBuilderPanel` via Pilot), observes an **externally-visible artifact** (a re-read written file, `FlowRunResult` fields, a rendered node/ribbon/banner), and names its **RED counterfactual** (the pre-batch-52 absence that makes it fail).

### AT-130 — CRC computed + injected over the post-patch image, observed in the WRITTEN file
- **Story:** US-C52-1 · **Type:** integration (headless)
- **Shipped surface:** `run_flow(Flow[SOURCE, PATCH, CRC(config_ref), WRITE-OUT])`, then **re-read the written `.s19`** from `result.written_paths[0]`.
- **Given** a project with a clean S19, a change-doc that patches bytes inside a CRC region, and a CRC config whose `output_address` sits inside a loaded range,
  **When** the flow runs and the WRITE-OUT file is re-read into a `mem_map`,
  **Then** the 4 little-endian bytes at `output_address` decode (`decode_le32`) to the CRC the **frozen engine** independently computes over the **post-patch** bytes.
- **Observable assertion (C-12 output-then-consume):** oracle = run a twin `SOURCE→PATCH→WRITE-OUT` flow (no CRC), re-read its file to get the post-patch `mem_map`, build `OperationInput`, call `check_regions(op_input, config)[0].computed_crc`; assert `decode_le32(written_bytes[output_address:+4]) == computed_crc`. The oracle uses the frozen `crc.py` directly, never the flow-CRC wiring under test.
- **RED counterfactual:** pre-batch-52 there is no `CrcBlock` in the `FlowBlock` union and no CRC branch in `run_flow`; the block is either unknown (`_record_error` → no bytes stamped) or the output address holds nothing → `decode_le32` sees absent bytes / wrong value.
- **Target:** `tests/test_flow_crc_block.py`

### AT-131 — CRC covers PATCHED bytes, not the pre-patch image (position of CRC in the pipeline is load-bearing)
- **Story:** US-C52-1 (discriminating observation) · **Type:** integration
- **Shipped surface:** two real flows: (a) `SOURCE→PATCH→CRC→WRITE-OUT`, (b) `SOURCE→CRC→WRITE-OUT` over the **same** source + config (no patch).
- **Given** a patch that changes at least one byte inside the CRC region,
  **When** both flows run and both written files are re-read,
  **Then** the stored CRC in (a) differs from (b) — proving the CRC digested the post-patch image, not the seed.
- **Observable assertion:** `decode_le32(a_bytes@out) != decode_le32(b_bytes@out)`, and (a) equals the post-patch engine oracle from AT-130.
- **RED counterfactual:** an impl that computes the CRC over the SOURCE snapshot (before threading the patched map) makes (a)==(b) → RED. Guards the "over the working post-patch image" clause specifically.
- **Target:** `tests/test_flow_crc_block.py`

### AT-132 — address-space GROWTH: output outside source ranges extends the image (observed in result AND file)
- **Story:** US-C52-2 (grow branch) · **Type:** integration
- **Shipped surface:** `run_flow(Flow[SOURCE, CRC(config_out_outside), WRITE-OUT])` + re-read written file.
- **Given** a config whose `output_address` window lies **outside** every SOURCE range,
  **When** the flow runs,
  **Then** `FlowRunResult.image_ranges` covers an address in `[output_address, output_address+4)` that was **absent** from the SOURCE footprint, AND the re-read written file contains present bytes at those 4 addresses.
- **Observable assertion (C-31 derive the set):** compute `source_footprint = set of addrs in build_loaded_s19(source).ranges`; `new_addrs = set(range(output_address, output_address+4)) - source_footprint`; assert `new_addrs` is non-empty AND every addr in `new_addrs` is contained by some interval in `result.image_ranges` AND present in the re-read written `mem_map`. Do **not** hand-list the window — derive it by diffing footprints.
- **RED counterfactual:** without the CRC branch reassigning `working ranges` from `inject_crcs`, `result.image_ranges` stays the SOURCE footprint and WRITE-OUT either omits the window or `emit_s19_from_mem_map` raises `KeyError` — the growth is unobservable → RED.
- **Target:** `tests/test_flow_crc_block.py`

### AT-133 — GROWTH boundary: output INSIDE loaded ranges → no growth
- **Story:** US-C52-2 (no-grow branch, C-10 both-branches) · **Type:** integration
- **Shipped surface:** same as AT-132 with `output_address` **inside** a SOURCE range.
- **Given** a config whose output window is fully inside the loaded image,
  **When** the flow runs,
  **Then** `result.image_ranges` equals the SOURCE footprint (no new interval), and the written file's address set equals the source's (bytes at `output_address` are overwritten in place, not added).
- **Observable assertion:** `set(covered addresses of result.image_ranges) == source_footprint`; the count of present addresses in the re-read file is unchanged vs a no-CRC twin.
- **RED counterfactual:** an impl that unconditionally extends ranges (even for an in-range output) would add a spurious interval / duplicate coverage → the equality fails. Pairs with AT-132 to pin the branch condition.
- **Target:** `tests/test_flow_crc_block.py`

### AT-134 — ordering WARN: CRC-before-PATCH is a non-blocking advisory, block STILL runs
- **Story:** US-C52-3 (warn branch) · **Type:** integration
- **Shipped surface:** `run_flow(Flow[SOURCE, CRC, PATCH, WRITE-OUT])` (CRC precedes PATCH).
- **Given** a flow whose CRC block sits before a PATCH block,
  **When** it runs,
  **Then** the CRC `BlockResult` carries a `Finding(FINDING_WARN, …)` whose text signals the ordering concern, the flow status is `completed-with-issues`, the CRC block status is **not** `error`, and the downstream WRITE-OUT **still produced its file** (chain not blocked).
- **Observable assertion:** `crc_block.findings` non-empty AND `crc_block.findings[0].severity == FINDING_WARN` AND ordering keyword present in the message (assert on a **stable substring** the architect fixes, e.g. `"before"` / `"PATCH"` — see §7 testability note); `result.status == FLOW_STATUS_ISSUES`; `crc_block.status in {ok, notices}` (not error); `len(result.written_paths) == 1`.
- **RED counterfactual:** no ordering heuristic exists pre-batch-52 → no WARN finding, status would be `ok` → RED on both the finding and the status.
- **Target:** `tests/test_flow_crc_block.py`

### AT-135 — ordering WARN boundary: CRC-after-PATCH emits NO ordering warning
- **Story:** US-C52-3 (no-warn branch, C-10) · **Type:** integration
- **Shipped surface:** `run_flow(Flow[SOURCE, PATCH, CRC, WRITE-OUT])`.
- **Given** the canonical `SOURCE→PATCH→CRC→WRITE-OUT` order,
  **When** it runs,
  **Then** the CRC block carries **no ordering WARN finding**, and (absent any other advisory) the flow status is `ok`.
- **Observable assertion:** no finding on the CRC block matches the ordering substring; `result.status == FLOW_STATUS_OK` for a clean image + in-range output. Contrasts directly with AT-134 (same fixtures, block order flipped) so the warn is proven to be **order-driven**, not always-on.
- **RED counterfactual:** an impl that always emits the ordering warning (or never distinguishes order) makes AT-134 and AT-135 indistinguishable → one goes RED.
- **Target:** `tests/test_flow_crc_block.py`

### AT-136 — fail-close: malformed config aborts the block, skips downstream, fails the flow, never raises
- **Story:** US-C52-4a (negative control) · **Type:** integration (security)
- **Shipped surface:** `run_flow(Flow[SOURCE, CRC(bad_config_ref), WRITE-OUT])` where `bad_config_ref` points at a project-relative file containing malformed JSON (`{ not json`).
- **Given** a resolvable-but-malformed CRC config,
  **When** the flow runs,
  **Then** `run_flow` **returns** (no exception), the CRC block status is `BLOCK_STATUS_ERROR`, the downstream WRITE-OUT is `BLOCK_STATUS_SKIPPED`, the flow status is `FLOW_STATUS_ERROR`, and **no file was written** (`result.written_paths == []`).
- **Observable assertion:** the call completes normally; `block_results[1].status == BLOCK_STATUS_ERROR`; `block_results[2].status == BLOCK_STATUS_SKIPPED`; `result.status == FLOW_STATUS_ERROR`; `result.written_paths == []`. (`parse_crc_config` returns `(None, [err])` → the CRC branch must treat "no config" as an aborting error like PATCH's unresolved-doc path.)
- **RED counterfactual:** with no CRC branch the block is unknown or (if wired naively) a malformed config raises out of `run_flow`, violating the never-raises contract, or lets WRITE-OUT run with an unstamped image → RED.
- **Target:** `tests/test_flow_crc_block.py`

### AT-137 — fail-close: a config_ref escaping the project is refused, the config file is NEVER opened
- **Story:** US-C52-4b (containment negative control) · **Type:** integration (security)
- **Shipped surface:** `run_flow` with a `CrcBlock` whose `config_ref` is, in turn, (i) an absolute path, (ii) a `..`-traversal escaping the project dir, (iii) a reparse-point/symlink out of the project (skip cleanly if the OS/test env cannot create one).
- **Given** a hostile `config_ref` for each escape vector,
  **When** the flow runs,
  **Then** the CRC block is `BLOCK_STATUS_ERROR` with a containment diagnostic, the flow is `FLOW_STATUS_ERROR`, downstream is `SKIPPED`, and the escaping target file is **never read**.
- **Observable assertion (C-31 derive the vector set + prove no-open):** parametrize over the three vectors from a single list (not three copy-pasted tests). To prove "never opened", place a **sentinel valid config at the escape target** and assert its CRC bytes do **not** appear in any output (the block errored before reading), plus `written_paths == []`. Assert the diagnostic mentions containment/inside-the-project.
- **RED counterfactual:** if the CRC block reads its config via the uncontained `read_crc_config`/`resolve_input_path` seam (which is "uncontained-by-design, F-S-02" for the standalone operation) instead of the flow's `_resolve_manifest_entry` F1 guard, the escaping file **would** be opened and its CRC could reach output → RED. This AT is the guard that forces the flow block onto the containment path. **(See §7 testability note — architect must confirm F1 applies to `config_ref`.)**
- **Target:** `tests/test_flow_crc_block.py`

### AT-138 — UI: CRC in the add-block dropdown, node renders, status shows after Run
- **Story:** US-C52-5 · **Type:** E2E (Textual Pilot)
- **Shipped surface:** mounted `S19TuiApp`, rail-8 `#screen_flow`; drive the **real** `#flow_kind` Select to the CRC value (non-default — SOURCE is default), set `#flow_ref` to a valid config filename, press the real `#flow_add` Button, press the real `#flow_run` Button.
- **Given** the Flow Builder panel with a project set,
  **When** the operator selects CRC from the dropdown, adds the block, and runs,
  **Then** a CRC node renders in `#flow_result` and carries a `sev-*` status class after the run.
- **Observable assertion (C-10 non-default drive + assert the change):** before add, assert the panel has no CRC block; after add, `panel._blocks` contains a `CrcBlock`; after Run, a `.flow-node` whose kind is CRC renders and its gutter carries a class in `{sev-ok, sev-warning, sev-error, sev-neutral}`. Assert the dropdown actually **offers** CRC: `BLOCK_CRC in {kind for _, kind in FlowBuilderPanel._KIND_OPTIONS}`.
- **RED counterfactual:** pre-batch-52 `_KIND_OPTIONS` has no CRC entry (setting the Select to CRC is a no-op/invalid) and `_flow_block_label`/`_make_flow_block` don't know CRC → no node, or a `"?"` label → RED.
- **Target:** `tests/test_flow_crc_surface.py`

### AT-139 — UI signature: the before/after ribbon GROWS when CRC extends the image
- **Story:** US-C52-6 (grow branch) · **Type:** E2E (Pilot)
- **Shipped surface:** run a `SOURCE→CRC(out-outside)→WRITE-OUT` flow through the panel; query the rendered ribbon(s) in `#flow_result`.
- **Given** a flow where the CRC output window lies outside the loaded ranges,
  **When** the panel renders the completed run,
  **Then** it renders a **before** footprint AND an **after** footprint, and the after footprint is **visibly larger** (more filled cells / an extended span) than the before.
- **Observable assertion (C-31 derive growth from the two footprints):** obtain the two ribbon strings from the rendered before/after ribbon widgets (or from the `FlowRunResult` before/after fields the ribbon is built from); assert `filled_cells(after) > filled_cells(before)` OR `max_addr(after_ranges) > max_addr(before_ranges)`. Derive the comparison from the actual footprints, do not assert a hard-coded cell count.
- **RED counterfactual:** `FlowRunResult` today carries only one `image_ranges` (the final footprint) and the panel renders a single ribbon — there is no before footprint to compare, so a two-ribbon growth assertion cannot even find its widgets → RED. Forces the new `before`-footprint carry + twin-ribbon render.
- **Target:** `tests/test_flow_crc_surface.py`

### AT-140 — UI signature boundary: no-growth flow renders before == after
- **Story:** US-C52-6 (no-grow branch, C-10) · **Type:** E2E (Pilot)
- **Shipped surface:** run a `SOURCE→CRC(out-inside)→WRITE-OUT` flow through the panel.
- **Given** a flow whose CRC output is in-range (no growth),
  **When** the panel renders,
  **Then** the before and after footprints are identical (the ribbon shows no extension).
- **Observable assertion:** `filled_cells(after) == filled_cells(before)` AND `after_ranges == before_ranges`. Pairs with AT-139 so the growth cue is proven to track real growth, not to always fire.
- **RED counterfactual:** a ribbon that always renders a "grew" delta (or renders after != before by construction) fails the equality → RED.
- **Target:** `tests/test_flow_crc_surface.py`

---

## 5. White-box functional cases (TC — mechanism-level, LLR-traced)

LLR ids are **provisional** (`LLR-089.x`+), pending the architect's `01-requirements.md`. Each TC names the mechanism it pins.

| TC | Provisional LLR | Asserts (mechanism) | Target |
|---|---|---|---|
| **TC-350** | LLR-089.1 (model) | `CrcBlock(config_ref)` is a frozen dataclass with `kind == "crc"`, `config_ref` stored verbatim; added to the `FlowBlock` union; JSON-serialisable by shape (no non-serialisable field) so batch-53 `flow.json` needs no model change. | `test_flow_crc_block.py` |
| **TC-351** | LLR-090.1 (compute over threaded map) | The CRC branch calls `check_regions` over the **working** `mem_map` threaded from the preceding PATCH (not the SOURCE snapshot); the `computed_crc` recorded equals the frozen-engine oracle over the post-patch bytes. | `test_flow_crc_block.py` |
| **TC-352** | LLR-090.2 (thread the injected image) | After the CRC branch, `run_flow`'s working `(mem_map, ranges)` are the **reassigned** outputs of `inject_crcs` (a fresh dict/list — original SOURCE map not mutated); a downstream WRITE-OUT serialises the injected map. | `test_flow_crc_block.py` |
| **TC-353** | LLR-090.3 (footprint after growth) | `FlowRunResult.image_ranges` reflects the **grown** footprint after a range-extending CRC (additive per §6.3 R-6); for an in-range CRC it equals the SOURCE footprint. | `test_flow_crc_block.py` |
| **TC-354** | LLR-091.1 (before-footprint carrier) | `FlowRunResult` gains a `before`-footprint field (name per architect) that carries the pre-CRC (SOURCE) footprint; for a grow flow it differs from `image_ranges`, for a no-grow flow it equals it; empty when no image loaded. | `test_flow_crc_block.py` |
| **TC-355** | LLR-092.1 (abort path) | A malformed/`None`-parsed config drives the CRC branch through `_record_error` → `aborted = True` → CRC block `BLOCK_STATUS_ERROR` and every downstream block `BLOCK_STATUS_SKIPPED`; `len(block_results) == len(flow.blocks)`. | `test_flow_crc_block.py` |
| **TC-356** | LLR-092.2 (containment on config_ref) | `config_ref` is resolved through `_resolve_manifest_entry` before any open; absolute / `..`-escape / reparse-point refs each return `None` → CRC block error with a containment diagnostic, config never read. Parametrized over the triad (single derived list). | `test_flow_crc_block.py` |
| **TC-357** | LLR-093.1 (ordering heuristic) | The ordering check emits exactly one `Finding(FINDING_WARN, …)` on the CRC block iff a PATCH block appears **after** the CRC block in `flow.blocks`; emits none when all PATCH blocks precede it; the finding is **non-aborting** (`aborted` stays False, image threaded). | `test_flow_crc_block.py` |
| **TC-358** | LLR-093.2 (rollup with CRC) | Three-way rollup including CRC: aborting CRC error → `FLOW_STATUS_ERROR`; a CRC ordering-WARN (or CRC `notices`) with output produced → `FLOW_STATUS_ISSUES`; a clean CRC → `FLOW_STATUS_OK`. | `test_flow_crc_block.py` |
| **TC-359** | LLR-094.1 (dropdown + factory + label) | `FlowBuilderPanel._KIND_OPTIONS` contains a CRC `(label, kind)` with `kind == BLOCK_CRC`; `_make_flow_block(BLOCK_CRC, ref)` returns a `CrcBlock(config_ref=ref)`; `_flow_block_label(CrcBlock(...))` starts with `"CRC"` (was `"?"` for an unknown kind). | `test_flow_crc_surface.py` |
| **TC-360** | LLR-094.2 (F3 gating-hide) | The `#flow_gating` selector is present/enabled **iff** the selected kind is CHECK. **C-31:** iterate the FULL kind set `{source, patch, crc, write_out, check}` derived from `_KIND_OPTIONS` (not hand-listed) and assert gating-visible ⇔ `kind == check`; in particular a CRC selection hides gating. | `test_flow_crc_surface.py` |
| **TC-361** | LLR-089.2 (G-1 empty flow) | `run_flow(Flow(name, blocks=[]))` returns `status == FLOW_STATUS_OK`, `block_results == []`, `written_paths == []`, `image_ranges == []` (no crash); `panel.render_result(<empty result>)` renders 0 `.flow-node` and 0 `.flow-sep` without raising. | engine arm → `test_flow_crc_block.py`; render arm → `test_flow_crc_surface.py` |
| **TC-362** | LLR-091.2 (twin-ribbon render) | The panel renders two ribbon widgets (before + after) built from the before/after footprints; `_memory_ribbon_text(before)` vs `(after)` differ in filled-cell count for a grow run and are identical for a no-grow run; both are int-derived (`spans == []`, no markup sink). | `test_flow_crc_surface.py` |
| **TC-363** | LLR-094.3 (sink census incl. CRC) | The CRC node's summary/finding render sinks participate in the `render_result` C-31 sink-completeness census (every `# SINK:` marker exercised, every `safe_text(...)` call marked, no unwrapped file-derived `Static(...)`); a hostile-payload finding on a CRC block renders `plain` verbatim with `spans == []`. *May fold into the existing `AT-088b` guard if that census already covers the shared render path — verify at implementation.* | `test_flow_crc_surface.py` |

---

## 6. Coverage census (default set — cuts justified)

| Default case | Covered by | Note |
|---|---|---|
| Golden path | AT-130, AT-138 | headless + UI |
| Alternative valid path | AT-131 (post-patch vs pre-patch), AT-133 (in-range output) | |
| Empty / null / zero input | TC-361 (empty flow, G-1) | |
| Boundary input | AT-133 / AT-140 (in-range = no-growth boundary), AT-135 (canonical order boundary) | |
| Invalid input | AT-136 (malformed config) | |
| Unauthenticated / wrong-role | **N/A — cut** | No auth model in the TUI; the security surface here is **path containment**, covered by AT-137 / TC-356 instead. |
| Network / error state | **N/A — cut** | Fully local, no network; the analogue "error state" (write/parse fault, collect-don't-abort) is AT-136 + `run_flow` never-raises. |
| Regression on adjacent feature | AT-135 (existing PATCH ordering), TC-361 render arm (existing panel render on empty), and the **regression checklist** below | |

## 7. Testability concerns / open questions for the architect (must resolve in `01-requirements.md`)

1. **Containment path for `config_ref` (blocks AT-137 / TC-356).** The standalone CRC config read (`read_crc_config` / `resolve_input_path`) is documented **"uncontained-by-design (F-S-02)"** (`crc_config.py:22`). But every existing FLOW block (`SourceBlock`/`PatchBlock`/`CheckBlock`) resolves its ref through the **F1 `_resolve_manifest_entry` containment guard** before open. These two conventions conflict. **The batch-52 requirement must state that the flow CRC block resolves `config_ref` through the F1 containment guard** (i.e. NOT the uncontained standalone read) — otherwise AT-137's "config never opened" is not achievable and the escape is real. Flag surfaced per Engineering Rule 7 (surface conflicts, don't average).
2. **Ordering-WARN message text (AT-134 / AT-135 / TC-357).** The exact WARN string is an impl/architect decision. The catalog asserts on a **stable substring** (proposed: contains `"PATCH"` and a before/after word). The architect must fix the canonical wording in an LLR so the substring assertion is stable and not brittle.
3. **`before`-footprint field name (AT-139 / AT-140 / TC-354 / TC-362).** `FlowRunResult` needs a new pre-CRC footprint carrier; its field name (`image_ranges_before`? `before_ranges`?) is the architect's to name. Tests will bind to whatever the LLR fixes.
4. **CRC block failure semantics — aborting vs advisory.** This catalog assumes: malformed/absent config = **aborting** error (like PATCH), while wrong **ordering** = **non-aborting** WARN. Confirm this split in the LLRs (AT-136 vs AT-134 depend on it).
5. **`BlockResult` field name.** The engine field is **`summary`** (not `message` as the task brief said); findings are `Finding(severity, message)`. Catalog uses the real names — confirm no rename.

## 8. Regression checklist (existing flows the CRC block could break — test these too)

- [ ] `SOURCE→PATCH→WRITE-OUT` (no CRC) still byte-identical to pre-batch-52 — a twin-flow oracle is used by AT-130/131, so any regression surfaces there; add an explicit `test_no_crc_flow_unchanged` if the engine diff touches the shared threading loop.
- [ ] `SOURCE→CHECK→WRITE-OUT` pass-through unchanged (`test_at086a` in `test_flow_execution_service.py` must still pass — CRC branch must not alter the CHECK/read-only path).
- [ ] `image_ranges` for non-CRC flows still equals the SOURCE footprint (`test_tc088_image_ranges_carries_final_footprint` must stay green).
- [ ] Direction-A panel single-block / N-node / N-1-separator invariants (`test_at088a_*`) unaffected by the new node kind.
- [ ] The `render_result` markup-safety sink census (`test_at088b_*`) still passes with the CRC sinks added (see TC-363).
- [ ] `_KIND_OPTIONS` / `_make_flow_block` / `_flow_block_label` still handle SOURCE (as "Load"), PATCH, WRITE-OUT, CHECK (`test_tc088_7_*`, `test_flow_block_label_covers_check`) after CRC is inserted.
- [ ] Frozen engine unchanged: `tests/test_engine_unchanged.py::test_tc027_*` green (batch-52 must not touch `core.py/hexfile.py/range_index.py/validation/a2l.py/mac.py`; `crc.py` edits, if any, are allowed — it is NOT in `_ENGINE_PATHS`).

## 9. Exit criteria

- All AT-130..140 pass through the shipped surface (engine + Pilot).
- All TC-350..363 pass.
- Regression checklist §8 fully green (no pre-existing flow/panel test regressed).
- `run_flow` never raises for any batch-52 fixture (malformed config, escaping ref, empty flow, mis-ordered CRC).
- No real firmware CRC values, no real paths/PII in fixtures — synthetic S19 + dummy config only.
- §7 open questions resolved in `01-requirements.md` before implementation gate.

---

## 10. Evidence checklist (qa-reviewer self-audit)

- [x] Acceptance criteria use Given/When/Then — §4 (AT-130..140).
- [x] Test cases have explicit Expected, not vague "works" — every AT states the observable assertion + oracle; every TC states the mechanism asserted.
- [x] Edge cases include empty (TC-361 G-1), boundary (AT-133/AT-135/AT-140 in-range & canonical-order), invalid (AT-136 malformed), error (AT-136 abort/skip, `never-raises`).
- [x] Regression checklist exists — §8.
- [x] Exit criteria stated — §9.
- [x] No real PII / secrets — synthetic `_S19_CLEAN` fixtures + `DUMMY_CONFIG_TEXT`-shaped configs; §9 pins this.
- [x] Test-results columns left **blank** — this is a catalog; no run claimed (nothing here asserts "passed"). No test was executed by qa.
- [x] **Layer B (black-box):** every output-producing story observed through the SHIPPED surface — US-C52-1 re-reads the WRITTEN file (AT-130/131); US-C52-2 observes `FlowRunResult` + file (AT-132/133); US-C52-5/6 drive the mounted panel (AT-138/139/140). Boundary + negative evidence: AT-133/135/140 (boundary), AT-136/137 (negative).
- [x] **Bidirectional surface-reachability:** every INPUT dimension (config template, block order, output-address placement, escape vector, dropdown kind) AND every OUTPUT/deliverable (written CRC bytes, grown ranges, ribbon, node status, flow status) is exercised through the `run_flow`/panel handler, not only the frozen `crc.py` API.
- [x] **No unfilled template:** no `<...>` placeholders or empty required rows remain; every AT/TC is concrete. LLR ids are explicitly marked provisional (coordination with the architect), not blank.
- [x] **C-10** called out: AT-133/135/140 (both branches per policy), AT-138 (non-default dropdown drive + assert change), AT-137 (parametrized vectors).
- [x] **C-12** called out: AT-130/131 re-read the handler-written file and feed it to the engine oracle.
- [x] **C-31** called out: AT-132 (derive new-window set by footprint diff), AT-137 (derive vector set + prove no-open via sentinel), AT-139 (derive growth from footprints), TC-360 (iterate full kind set), TC-363 (sink census).
- [x] **RED counterfactual** named for every AT — §4.
- [x] Frozen test-file discipline (C-27): all new tests land in NEW non-frozen files (`test_flow_crc_block.py`, `test_flow_crc_surface.py`); no edit to `_ENGINE_PATHS` sources or the freeze-guard tests.
