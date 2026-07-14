# ADR — Flow Builder (tracer slice, batch-44)

**Status:** Proposed (design pass; implementation flow — /dev-flow vs /fast-dev-flow — decided after).
**Date:** 2026-07-13. **Author:** system-design pass.
**Context anchor:** rail item 8 ("Bookmarks", dropped) repurposed into a functional-block **Flow Builder**.

---

## 1. Decision (BLUF)

Build the Flow Builder as **an ordered list of typed blocks executed by a thin, Textual-free `flow_execution_service`** that **reuses the existing ops** (`apply_change_document`, `run_check_document`, `emit_*`/`save_patched_image`, `build_loaded_*`) and **mirrors the proven state model** of `variant_execution_service._execute_one_variant`: a working `(mem_map, ranges)` pair threaded through the blocks, mutated in place by transform blocks and sunk by write blocks, with **collect-don't-abort** isolation. Do **not** reuse `_execute_one_variant` itself (it is coupled to the variant/manifest model); mirror its discipline over an **explicit block list**.

The **batch-44 tracer** is the narrowest runnable vertical: `SOURCE → PATCH → WRITE-OUT`, run from the rail-8 UI, producing an on-disk file + a renderable run result. **Persistence (flow.json), CHECK, and CRC are deliberately excluded** from batch-44 (see §7 roadmap).

---

## 2. The state model (why this is mostly reuse)

`_execute_one_variant` (`variant_execution_service.py:682`) already IS a mini-pipeline. The threaded state is `(mem_map: dict[int,int], ranges: list[(start,end)])` plus read-only context `(mac_records, a2l_tags, variant_id, project_dir, source_kind)`. Ops fall into three shapes:

| Shape | Op | Effect on `mem_map` |
|-------|-----|---------------------|
| **Seed** | `build_loaded_s19/hex(path,…) -> LoadedFile` | produces `.mem_map` / `.ranges` (+ `source_s0_header`) |
| **Transform (mutate-in-place)** | `apply_change_document(doc, mem_map, ranges, …) -> ChangeSummary` | mutates `mem_map` at applied entries |
| **Read** | `run_check_document(doc, mem_map, ranges, …) -> CheckRunResult` | none (read-only) |
| **Sink** | `emit_s19_from_mem_map(mem_map, ranges,…) -> str` · `save_patched_image(mem_map, ranges, dest, name, source_kind=…) -> (Path?, issues)` | none |

This is a clean functional-block vocabulary already. The Flow Builder generalizes "a variant's fixed change-file list" → "an explicit typed-block list."

---

## 3. High-level design

```
                       flow_execution_service.run_flow(flow, ctx)  [Textual-free service]
 rail-8 UI                         │
 FlowBuilderPanel  ── Run ──▶  FlowRunState{ mem_map, ranges, s0_header, ctx, block_results[] }
 (#screen_flow)                    │
   dropdown-add blocks             ├─ SourceBlock   → build_loaded_s19/hex → seed mem_map/ranges
   ordered block list             ├─ PatchBlock    → apply_change_document(mem_map,…) [mutates]
   [Run] button                   └─ WriteOutBlock → emit_*/save_patched_image → written Path
        ▲                              │
        └──── render FlowRunResult ◀────┘  (per-block status + diagnostics + written paths)
```

- **`flow_execution_service`** (new, `services/flow_execution_service.py`): pure service, no Textual (constraint C-7). `run_flow(flow: Flow, ctx: FlowContext) -> FlowRunResult`.
- **`FlowBuilderPanel`** (new widget in `screens_directionb.py`, modeled on `PatchEditorPanel`): the rail-8 surface.

### 3.1 Typed-block model (new, `services/flow_model.py` or `tui/flow/model.py`)

Frozen, JSON-serializable dataclasses with a `kind` discriminator (mirrors the change-document `kind` pattern):

```
FlowBlock (base)   kind: str
  SourceBlock      image_ref: str            # a project variant image (resolved against project_dir)
  PatchBlock       change_doc_ref: str       # a change document (parse_change_document seam)
  WriteOutBlock    output_name: str; fmt: "s19" | "hex"
Flow               name: str; blocks: list[FlowBlock]; schema_version: int
```

Batch-44 needs only these three. `CheckBlock` / `CrcBlock` are added later (§7). The base + discriminator make the vocabulary open for extension.

### 3.2 FlowRunResult (mirrors VariantExecutionResult)

```
BlockResult   index:int; kind:str; status:"ok"|"error"|"skipped"; summary:str; diagnostics:[str]
FlowRunResult status:"ok"|"error"; block_results:[BlockResult]; written_paths:[Path]; diagnostics:[str]
```
`len(block_results) == len(flow.blocks)` always; one failing block sets `error` + a diagnostic and stops the chain (a broken source can't feed a patch) — but the result is always well-formed (collect-don't-abort, never raises), exactly like `VariantExecutionResult`.

---

## 4. Reuse vs build

| Concern | Decision |
|---------|----------|
| Op engines (patch/check/emit/save/load) | **REUSE verbatim** — all pure, mem_map-based, non-frozen |
| State-threading discipline (mutate-in-place, collect-don't-abort, isolation) | **MIRROR** `_execute_one_variant` |
| `_execute_one_variant` itself | **DO NOT reuse** — variant/manifest-coupled (variant_id, fixed file list, `<id>-patched.s19` naming) |
| Block vocabulary + run loop | **BUILD** thin `flow_execution_service` + `flow_model` |
| Rail-8 screen | **BUILD** `FlowBuilderPanel` + `#screen_flow` (data-driven routing, no `action_show_screen` change) |
| Persistence | **BUILD later** (batch-45), reusing `manifest_writer`/`read_project_manifest` discipline |

---

## 5. Rail-8 UI wiring (exact)

1. `rail.py:86`: replace `RailEntry("bookmarks","✶","*","Bookmarks")` → `RailEntry("flow","<glyph>","<ascii>","Flow Builder")`. **Recommend keeping key `"bookmarks"`** internally to avoid touching `SCREEN_CONTAINER_IDS`, OR rename to `"flow"` and update `app.py:4414` `SCREEN_CONTAINER_IDS` + `_compose_screen_*`. (Rename is cleaner; one dict entry.)
2. `app.py:4414`: `"flow": "screen_flow"`.
3. `_compose_screen_flow()` in `app.py` (copy `_compose_screen_bookmarks`, `app.py:1527`): `Container(Label("Flow Builder", classes="db-screen-title"), FlowBuilderPanel(), id="screen_flow", classes="db-screen hidden")`, slotted into `#workspace_body` (`app.py:1285`).
4. `FlowBuilderPanel` (`screens_directionb.py`, model on `PatchEditorPanel:1596`, a `ScrollableContainer`): a **dropdown** (`Select`) to add a block by kind, an **ordered block list** (add/remove/reorder), a **Run** button, and a **result pane**. Honor the `width-narrow` (<120) / `density-compact` reflow classes; do not measure columns.
5. Routing is data-driven — `action_show_screen` toggles `.hidden`, no new handler.

---

## 6. Persistence shape (batch-45, designed now)

- `flow.json` (or `flows/<name>.json`) in `.s19tool/workarea/<project>/` — `.json` is ignored by `validate_project_files`, so it's compatible with the "≤1 MAC, ≤1 A2L, N images" cardinality.
- **Reader** mirrors `read_project_manifest`: 256 MB pre-parse size cap (injectable probe), catch `JSONDecodeError|RecursionError|UnicodeDecodeError|OSError`, top-level-object guard, collect-don't-abort → faulted → empty flow, never raise.
- **Every embedded ref** (`SourceBlock.image_ref`, `PatchBlock.change_doc_ref`, `WriteOutBlock.output_name`) resolved through the **existing `_resolve_manifest_entry` predicate** (absolute / escape-project-root / reparse-point triad) — never fork it.
- **Writer** reuses `manifest_writer`'s pattern: temp/ stage → `_check_destination_contained` → atomic `os.replace` onto a fixed name.

---

## 7. The CRC seam — the real architectural risk (batch-46+)

CRC does **not** fit the uniform mutate-in-place block shape, for three concrete reasons (`operations/crc.py`):

1. **It reads the whole post-patch image**, not a fixed byte run (`check_regions:663`) → hard ordering constraint: `PATCH → CRC` always, never the reverse.
2. **It writes a computed CRC back at `output_address` and may GROW the image** — `inject_crcs:987` adds keys to a *working* `mem_map` and extends `ranges` via `_extend_ranges:1001` when the output window is outside every loaded range. So CRC mutates the **address space**, not just bytes at fixed addresses — it changes what "the current image" means for any downstream block.
3. **It owns its own emit+stage+place+verify internally and is S19-only** — `write_crc_image(op_input, config, …) -> CrcWriteResult` takes an `OperationInput`+`CrcConfig` and produces a file; it does **not** accept a pre-built `mem_map`/`ranges` nor hand bytes back for a later WRITE-OUT block.

**Design implication (decide before batch-46, not now):** to compose CRC into the shared-`mem_map` chain, either (a) **split** `write_crc_image` into a pure `inject_crcs`-style stage that returns the extended `(mem_map, ranges)` (composes as a transform block) + the shared WRITE-OUT block, or (b) **special-case CRC as a terminal image-producing block** that ends the chain. Recommendation: (a) — it keeps the block model uniform and lets `CRC → WRITE-OUT` and `CRC → CHECK` compose. This is the "CRC-into-loop" seam; the tracer excludes it precisely so the block contract is proven on the easy blocks first.

---

## 8. Security / untrusted-input

- **Batch-44 (run-only, no flow.json):** the untrusted surfaces are the change-document JSON (already hardened — `parse_change_document`: 256 MB cap, 3-exception catch, zero-entry-on-fault) and any **block labels/notes** shown in the panel → render `markup=False` / `rich.markup.escape` (the batch-27/43 lesson). The source image is already-loaded project data. **No new untrusted-file loader** → modest security surface.
- **Batch-45 (persistence):** `flow.json` is a new untrusted-file surface — the loader MUST replicate the six manifest guards (§6) and **reuse, not fork**, `_resolve_manifest_entry`. This is where the security rigor concentrates.

---

## 9. Increment / boundary plan

**Batch-44 tracer (source → patch → write-out, run-only):**
- **Inc-1 — engine (headless, no UI):** `flow_model` (SourceBlock/PatchBlock/WriteOutBlock/Flow) + `flow_execution_service.run_flow` threading `(mem_map, ranges)` via `build_loaded_*` → `apply_change_document` → `emit_*`/`save_patched_image`. Unit-tested end-to-end headless: a Flow + project S19 + change doc → the output file is written and `FlowRunResult` reports per-block status. **This is the tracer's keel — fully testable without Textual.**
- **Inc-2 — rail-8 UI:** repurpose rail item 8 → `#screen_flow` + `FlowBuilderPanel` (dropdown-add, ordered list, Run) wired to `run_flow`; render `FlowRunResult`. Pilot ATs. Drop `BookmarksPlaceholder`.
- **(Boundary — STOP here for batch-44.)** No persistence, no check/CRC, no multi-image scope.

**Roadmap (later batches):**
- **b-45** flow persistence (flow.json load/save, security-focused).
- **b-46** CHECK block + CRC block (the §7 seam — the real design work).
- **b-47** multi-image scope + report fusion.
- **b-48** polish (reorder UX, validation, no-data states).

---

## 10. Trade-offs / what I'd revisit

- **In-place mutation vs immutable fold.** Reusing the mutate-in-place ops means a block can't be "replayed" without re-seeding from SOURCE. Acceptable (mirrors the shipped engine); revisit only if a future "branch/compare" block needs snapshots.
- **Block-list vs DAG.** A linear ordered list (not a graph) is right for the tracer and likely forever (the ops are a linear transform chain). Revisit only if multi-output/branching flows appear.
- **Where `flow_model` lives.** `services/flow_model.py` (beside `variant_execution_service`) keeps it Textual-free and importable by the service; the panel imports it too. Alternative `tui/flow/` package if the vocabulary grows.
- **Flow recommendation for batch-44:** run-only tracer (no flow.json) has a **modest** security surface and reuses proven ops → a good **/fast-dev-flow** candidate. If persistence is folded into batch-44, the untrusted-file loader argues for **/dev-flow**. Recommend: **fast-flow batch-44 (run-only) + a separate persistence batch-45**; decision deferred to operator.
