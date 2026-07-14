# fast-dev-flow spec — batch 44 — Flow Builder tracer slice (source→patch→write-out, run-only)

- **Status:** closed 2026-07-14 (AC-1..5 green; full gate `1373 passed / 2 skipped / 23 xfailed / 11 xpassed / 0 failed`; RED-first for AC-1 + AC-4; security-reviewer pass F1/F2/F4/F5 mitigated; C-27 dual-guard clean; 0 frozen diffs; autonomous + self-merge). **Follow-up: canonical-CI snapshot regen PR retires the 20 rail-drift xfails.**
- **Created:** 2026-07-13
- **Branch:** `claude/batch-44-flow-builder-tracer` @ `fa4b118` (= origin/main tip; RC-1 clean, merge-base == origin/main)
- **Route:** /fast-dev-flow (operator-chosen: run-only tracer; persistence split to batch-45). Design: `.fast-dev-flow/ADR-flow-builder-tracer.md`.
- **Run mode / merge:** TBD at Phase-A gate. Decisions → MEMORY.md at close.
- **security_required:** TRUE — the new `flow_execution_service` consumes untrusted change-document content (via the already-hardened `parse_change_document`/`read_change_document`) and the new rail-8 panel renders block labels/refs (must be markup-safe). NO new untrusted-file loader (flow persistence is batch-45). Modest surface — established patterns only.

## 1. Objective

Ship the narrowest runnable Flow Builder vertical: compose an ordered list of typed blocks **SOURCE → PATCH → WRITE-OUT**, run it from rail item 8, and produce observable output (a written S19/HEX file + a renderable run result). Reuse the existing ops + the `_execute_one_variant` state model; **no persistence, no CHECK/CRC, no multi-image** (see ADR §7/§9). All work in NON-frozen modules.

## 2. User stories

- **US-44a (headless engine):** As a developer, I want a Textual-free `flow_execution_service.run_flow(flow, ctx)` that threads `(mem_map, ranges)` through the ordered blocks (seed via `build_loaded_*`, patch via `apply_change_document`, sink via `emit_*`/`save_patched_image`) and returns a well-formed `FlowRunResult`, so the block model is proven independent of the UI.
- **US-44b (rail-8 UI):** As an operator, I want a Flow Builder screen on rail item 8 where I add Source/Patch/WriteOut blocks from a dropdown into an ordered list and press Run to execute the flow and see per-block status + the written file, so I can chain operations without editing files by hand.

## 3. Acceptance criteria (observable)

- **AC-1 (engine happy path — RED-first):** Given a `Flow` = [`SourceBlock`(a project S19), `PatchBlock`(a project change-doc that applies ≥1 byte at a known address), `WriteOutBlock`(name.s19, fmt="s19")] and a `FlowContext`(project_dir), `run_flow` writes `name.s19` into the workarea with the patched byte present, and returns `FlowRunResult(status="ok")` with **3** `block_results` all `"ok"` and `written_paths == [that file]`. RED: `flow_model`/`run_flow` do not exist.
- **AC-2 (isolation / collect-don't-abort):** A `Flow` whose `SourceBlock` references a missing/invalid image yields `FlowRunResult(status="error")` with `len(block_results) == len(flow.blocks)` (source=`error`, downstream=`skipped`), **no exception raised**, and **no output file written** — mirroring `VariantExecutionResult` (LLR-006.4).
- **AC-3 (write-out format):** A `WriteOutBlock` with `fmt="hex"` emits Intel HEX (`emit_intel_hex_from_mem_map`) and `fmt="s19"` emits S19 (`save_patched_image`/`emit_s19_from_mem_map`); asserted by the written file round-tripping through `IntelHexFile`/`S19File` respectively.
- **AC-4 (rail-8 UI — RED-first):** Rail item 8 shows "Flow Builder"; `#screen_flow` lets a user add Source/Patch/WriteOut blocks via the dropdown into an ordered list, and Run executes `run_flow` and renders the `FlowRunResult` (per-block status chips + the written path). Pilot AT drives add→add→add→Run and reads the result pane. RED: rail-8 is the "Bookmarks - coming soon" placeholder; `#screen_flow` absent.
- **AC-5 (markup-safe labels):** A block referencing a change-doc / output whose name carries hostile markup (`evil[red]`) renders **literally** in the block list and result pane (`markup=False` / `safe_text`) — no `MarkupError`, no style leak (the batch-27/43 class).

## 4. Validation strategy

RED-first: AC-1 (headless `run_flow` end-to-end over a tmp project — reuse `test_variant_execution`'s `_make_project`/`_write_v2_document` helpers) and AC-4 (Pilot over `#screen_flow`) shown failing pre-code. AC-2/AC-3 headless unit. AC-5 markup-safety AT. Full gate `pytest -q -m "not slow"` + C-27 dual-guard each increment (no frozen file touched — new services + rail/app/screens_directionb, all non-frozen; ops in `changes/` reused, not modified). Coverage-claim discipline: confirm each named test exists on disk before closing.

## 5. Non-goals (OUT — deferred per ADR §9)

- **Persistence** (flow.json load/save) → batch-45 (the untrusted-file loader + its manifest-guard replication).
- **CHECK / CRC blocks** → batch-46 (the CRC-into-loop seam, ADR §7).
- **Multi-image scope / report fusion** → batch-47.
- Reorder/validation UX polish, no-data-state refinement → batch-48.
- Any engine-frozen module (ops in `apply.py`/`io.py`/`check.py` are REUSED, never edited).

## 6. Detected security flags

- [x] **Input / attack surface** — untrusted change-doc content flows through the new `flow_execution_service` (via `parse_change_document`/`read_change_document`, already hardened); block labels/refs render in the new panel (must be `markup=False`/`safe_text`). File-refs (`SourceBlock.image_ref`, `PatchBlock.change_doc_ref`) resolve against `project_dir` — reuse the `_resolve_manifest_entry` containment guard (defense-in-depth), never a bespoke path resolver.
- **`security_required: true`.** No NEW untrusted-file loader (persistence deferred), no auth/secret/network. Risk = markup injection via a block label (mitigate: markup-safe render) + path escape via a file-ref (mitigate: reuse `_resolve_manifest_entry`). security-reviewer mini-pass on the new service's untrusted-input handling before code.

## 7. Increment plan (≤5 files each, 2 increments)

1. **Inc-1 — headless engine (US-44a; AC-1/AC-2/AC-3):** `s19_app/tui/services/flow_model.py` (frozen `FlowBlock`/`SourceBlock`/`PatchBlock`/`WriteOutBlock`/`Flow` + `FlowContext`/`BlockResult`/`FlowRunResult`) + `s19_app/tui/services/flow_execution_service.py` (`run_flow`, Textual-free, threads `(mem_map, ranges)`, reuses `build_loaded_*`/`apply_change_document`/`emit_*`/`save_patched_image`, resolves file-refs via `_resolve_manifest_entry`, collect-don't-abort) + `tests/test_flow_execution.py`. = 3 files.
2. **Inc-2 — rail-8 UI (US-44b; AC-4/AC-5):** `s19_app/tui/rail.py` (`RailEntry` "bookmarks"→"flow"/"Flow Builder"), `s19_app/tui/app.py` (`SCREEN_CONTAINER_IDS` + `_compose_screen_flow`), `s19_app/tui/screens_directionb.py` (`FlowBuilderPanel`: dropdown-add, ordered block list, Run, result pane; drop `BookmarksPlaceholder`), `tests/test_tui_directionb.py` (or a new `test_tui_flow.py`). = 4 files. Then update REQUIREMENTS.md (new R-TUI-059 Flow Builder tracer).

(2 increments; the tracer keel is Inc-1 — fully testable headless.)

## 8. Batch status

| Field | Value |
|-------|-------|
| Current phase | closed |
| Started | 2026-07-13 |
| Closed | 2026-07-14 |
| Promoted to /dev-flow | no |
| Notes | RC-1 clean; ADR banked; persistence → b-45; snapshot regen follow-up pending |

## 9. Close

### What changed
Shipped the Flow Builder tracer (R-TUI-059): rail item 8 (dropped "Bookmarks") now composes + runs an ordered typed-block pipeline **SOURCE → PATCH → WRITE-OUT**. New Textual-free `flow_execution_service.run_flow` threads `(mem_map, ranges)` through the blocks (reusing `build_loaded_*`/`apply_change_document`/`save_patched_image`, mirroring `_execute_one_variant` isolation); new `flow_model` typed blocks; new rail-8 `FlowBuilderPanel` (dropdown-add + Run) → `RunRequested` → app runs over `_active_project_dir()` and renders `FlowRunResult`. No frozen module touched (ops reused).

### How it was tested
- Full gate: **1373 passed / 2 skipped / 23 xfailed / 11 xpassed / 0 failed** (+4 net tests).
- Inc-1 engine (`test_flow_execution.py`): AC-1 happy path (patched byte in written file), AC-2 isolation, F1 path-escape blocked, AC-3 hex+s19. Inc-2 UI (`test_tui_directionb.py`): AC-4 add→Run→result (RED-first), rail-key-8, AC-5 markup-safe.
- C-27 dual-guard clean; ruff clean; the rail/census/commandbar tests updated for the rename.

### Open risks / pending
- **Snapshot regen follow-up:** the rail-8 relabel drifts 20 `tc016s`/`tc036s` cells → `xfail(strict=False)` via `_batch44_drift_marks`. A canonical-CI regen PR (snapshot-regen.yml, textual==8.2.8) retires the marks post-merge (the batch-36/37/38 pattern). 11 cells xpassed (didn't drift) — harmless under strict=False.
- **Scope note:** Inc-2 touched 6 code files (vs the ≤5 guideline) — the rail rename rippled into `test_tui_commandbar.py` + rail-census updates. Surfaced, not silent.
- Run is synchronous on the UI thread (fine for the tracer's small images; worker-ize in polish).

### Security flags — handling
`security_required: true`. security-reviewer pre-code pass: **F1** (containment) — `run_flow` resolves every file-ref via `_resolve_manifest_entry` before any open; **F2** — write-out only via `save_patched_image(source_kind=fmt)`; **F4** — all panel sinks via `safe_text`; **F5** — per-block isolation. All applied + locked (path-escape AT, markup-safe AT). No residual.

### Suggested commit message
```
feat(tui): batch-44 — Flow Builder tracer (source→patch→write-out, rail-8) (R-TUI-059)
```
