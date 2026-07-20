# Functionality — s19_app — Batch 2026-07-20-batch-51 (Flow Builder)

> **Artifact language:** English (`state.json` `language = en`).
> Phase-6 artifact. Owner: `docs-writer`. Audience: technical stakeholder (engineer / tech lead).

## 🔑 At a glance (read first)

- **What this batch added:** the first real slice of the operator's Flow Builder pipeline on top of the
  shipped tracer (`SOURCE → PATCH → WRITE-OUT`). Blocks now run under a **notify-don't-block** model,
  a read-only **CHECK** block was added, the run reports a three-way **CLEAN / ISSUES / FAILED** outcome,
  and the screen renders a vertical **"Pipeline Ledger"**.
- **Capabilities:**
  - **LOAD integrity notices** — a suspect image (bad-checksum lines, out-of-order records) surfaces as
    advisory WARN notices; the flow keeps running. Only an unopenable image stops the chain.
  - **CHECK block (read-only)** — reports address present/absent counts against the working image and
    passes the image through byte-for-byte unchanged; a per-block gating flag can mark the CHECK block
    itself errored **without ever blocking the chain**.
  - **`completed-with-issues` (amber) status** — "shipped with warnings" is now distinct from "did not
    ship" (FAILED).
  - **Direction-A Pipeline Ledger render** — one node per block, a `sev-*` status gutter, separators, a
    single memory ribbon, and a CLEAN/ISSUES/FAILED banner.
- **How to reach it:** TUI rail-8 (Flow Builder) — compose blocks with the kind dropdown + ref input +
  **Add**, press **Run**. Engine entry point: `flow_execution_service.run_flow(flow, ctx)`.

> **Scope guardrail:** 0 engine-frozen modules edited (C-27 dual-guard clean). All new code lives in
> `flow_model.py`, `flow_execution_service.py`, `screens_directionb.py`, `styles.tcss` + new tests
> (`app.py` untouched — the existing Run → `run_flow` → `render_result` wiring was already correct).

---

## Detail (reference)

### The block pipeline (LOAD → PATCH → CHECK → WRITE-OUT)

`run_flow` executes an ordered `Flow` of typed blocks, threading a single working `(mem_map, ranges)`
image pair through them and collecting one `BlockResult` per block (`len(block_results) ==
len(flow.blocks)` always; the function never raises — per-block `except` isolation, F5).

| Block | Role in the working image | On failure |
|-------|---------------------------|------------|
| **LOAD** (`SourceBlock`, kind stays `"source"`) | **Seeds** `mem_map`/`ranges` via `build_loaded_s19/hex`. Parser-collected per-record `errors` become advisory WARN `Finding`s → block status `notices` (image still threaded). | Unresolvable / unopenable image = **STOP**: block `error`, `aborted=True`, image left unset. |
| **PATCH** (`PatchBlock`) | **Mutates** `mem_map` in place via `apply_change_document`. | Unresolved doc / apply failure = **STOP** (`aborted=True`). |
| **CHECK** (`CheckBlock`, NEW) | **Reads only** — runs `run_check_document` against the working image, attaches `passed=/failed=/uncheckable=` counts to the block summary, and threads the image through **unchanged** (never reassigns `mem_map`/`ranges`). | **Never aborts the chain** — see below. |
| **WRITE-OUT** (`WriteOutBlock`) | **Sinks** the working image to a file under the work area via `save_patched_image` (F-S-01 sanitiser + containment). | Write failure = **STOP** (`aborted=True`). |

Every file ref (image / change-doc / check-doc) is resolved through the manifest containment guard
`_resolve_manifest_entry` before any file is opened (batch-44 security F1 — unchanged).

### The notify-don't-block model

This is the operator's headline invariant — the tool **informs**, it does not **gate**.

1. **LOAD integrity notices (advisory).** When `LoadedFile.errors` is non-empty, `run_flow` appends one
   `Finding(FINDING_WARN, …)` per error to the SOURCE `BlockResult` and sets its status to
   `notices` — **without** setting `aborted`. The image is still threaded downstream, so the author sees
   the warning and decides for themselves whether the image is acceptable. A zero-error load stays `ok`.
   Finding messages are C-9-safe: `"line <n>: <error text>"` — the raw file-line content is never echoed.

2. **CHECK read-only pass-through.** A CHECK block runs the check engine against the working image but
   never reassigns it, so a downstream WRITE-OUT produces byte-identical output whether or not the CHECK
   block is present (asserted byte-for-byte by AT-086a).

3. **The chain-never-blocked invariant.** A CHECK block **never** sets `aborted = True` — regardless of
   gating flag or outcome. The whole CHECK branch body (read → run → aggregate → build result) runs
   under an inner `except` that routes ANY exception to the non-aborting own-op recorder, so it can never
   reach the outer `aborted = True` handler (made *structural*, not contract-conditional, by TC-086.6).

4. **Per-block gating — advisory vs block-own-op.** The gating flag affects **only the CHECK block's own
   status**, never the chain. This is the one gating truth table (LLR-086.4):

   | gating \ trigger | readable doc, entries fail | unreadable / unresolvable doc (own-op invalid) |
   |------------------|----------------------------|------------------------------------------------|
   | `advisory` (default) | `notices` (`ok` if `failed==0`) · chain runs | `notices` (advisory "could not check") · chain runs |
   | `block-own-op` | `notices` (`ok` if `failed==0`) — entries-fail is not an own-op failure · chain runs | **`error`** (→ `sev-error`) · chain runs |

   In **all four** cells `aborted == False` and the downstream WRITE-OUT still produces its file. The
   flag changes the block's own status only in the bottom-right cell — that single differing cell is what
   AT-086c drives (SAME unreadable doc under advisory→`notices` vs block-own-op→`error`, status differs,
   file produced in both). There is **no** separate "blocked" token; block-own-op resolves to
   `error`.

This contrasts with the **abort-asymmetry**: LOAD / PATCH / WRITE-OUT failures DO set `aborted` (image
broken → downstream `skipped`); a CHECK failure never does (image intact → downstream runs).

### The three-way flow status (completed-with-issues)

At the end of `run_flow` a three-way classifier (replacing the old two-way collapse) sets
`FlowRunResult.status`:

1. **FAILED** (`error`) — `aborted` is `True` (an image-breaking LOAD/PATCH/WRITE-OUT STOP). Keys on
   `aborted` **alone**.
2. **ISSUES** (`completed-with-issues`, amber) — else, if any block is `notices`/`error` **or** carries
   any `Finding`. Output was produced *with advisories*. Because CHECK errors never set `aborted`, a
   non-aborting CHECK `error` correctly lands here, not in FAILED.
3. **CLEAN** (`ok`) — else, every block clean.

The amber ISSUES token is the machine-readable contract carried on the single `FlowRunResult.status`
carrier (there is no separate flow-report *file* in this batch — A4); it is surfaced to the author only
through the render banner (below). This is what lets an engineer tell "shipped with warnings" from
"did not ship".

### The Direction-A "Pipeline Ledger" render

`FlowBuilderPanel.render_result` paints the `#flow_result` pane by mounting, top to bottom:

- **A flow-status banner** — `CLEAN` / `ISSUES` / `FAILED` text with class `sev-ok` / `sev-warning` /
  `sev-error`, from `FlowRunResult.status`. Enum-derived (not file-derived), so out of the markup sweep.
- **One vertical node per block**, in flow order, each with:
  - a **status gutter** — a glyph (`● ◈ ✖ ○`) + the block kind + status, styled by the block-status →
    `sev-*` class map (`ok→sev-ok`, `notices→sev-warning`, `error→sev-error`, `skipped→sev-neutral`).
    The map lives in `screens_directionb.py`, **not** the frozen `color_policy.py` (0 diff).
  - the block **summary**, each **finding message**, and each **diagnostic** — every one rendered in its
    own `Static(safe_text(...), markup=False)`.
- **N−1 separators** — a bordered `flow-sep` between consecutive nodes, none trailing (single-block → 0).
- **A single memory ribbon** — a fixed 48-cell strip encoding the working image's final address
  footprint from `FlowRunResult.image_ranges`, plus an int-derived caption (range count + hex extents).
  Geometry MEASURED in the mounted panel (48 cells clears the 80×24 content-width floor of 70 by 22
  cols; also verified at 120×30 / 160×40 — no horizontal overflow).
- **Written-path lines** — one `safe_text` `Static` per produced file.

**Markup safety (C-17).** All **5** file-derived sinks — the block **ref label** (`_flow_block_label`,
in the composed-blocks list), the **summary**, each **finding message**, each **diagnostic**, and each
**written path** — are rendered `markup=False` via `safe_text`, so a hostile bracket/ANSI payload renders
literally (`Text.plain` verbatim AND `spans == []`). AT-088b enforces this per-sink and adds a 3-layer
AST completeness guard (marker==tested, `safe_text`-call-count==markers, and no `Static(...)` passes a
file-derived value without `safe_text`), closing the recurring batch-33/43/48 markup-sink-sweep miss.
The banner and ribbon are enum/int-derived and correctly excluded from the sweep.

### What is deferred

| Deferred | To batch | Why |
|----------|----------|-----|
| CRC block + the **twin ribbon** (`before` row) + `before_ranges` carrier | **batch-52** (AMD-1) | No block grows the range set yet, so a `before` row would be byte-identical to the image row and mislead. The twin lands with CRC, where growth makes the "watch it grow" contrast meaningful. |
| `flow.json` persistence + external-file import + variant reuse | **batch-53** | Out of scope; the block dataclasses are already JSON-serialisable by shape so persistence needs no model change. |
| `#flow_gating` visibility polish (hide/disable when kind ≠ CHECK) | batch-52 polish | Cosmetic (Inc-2 F3). |
| Empty / no-run render boundary TC (G-1) | Phase-3 follow-up | Non-blocking; underlying pieces are unit-proven. |

### Components / modules touched

| Module | Role in this batch |
|--------|--------------------|
| `s19_app/tui/services/flow_model.py` | Pure data: `CheckBlock` + gating constants, `BLOCK_STATUS_NOTICES`, `FLOW_STATUS_ISSUES`, `Finding`/`FINDING_WARN`, `BlockResult.findings`, `FlowRunResult.image_ranges` (all additive) |
| `s19_app/tui/services/flow_execution_service.py` | `run_flow`: LOAD notice emission, CHECK read-only branch (chain-never-blocked), three-way roll-up, `image_ranges` carrier |
| `s19_app/tui/screens_directionb.py` | `FlowBuilderPanel.render_result` Direction-A ledger; status→`sev-*`/glyph/banner maps; `_memory_ribbon_text`/`_ribbon_caption`; CHECK+LOAD dropdown + `#flow_gating` Select wired to `_make_flow_block` |
| `s19_app/tui/styles.tcss` | Flow-scoped classes (`flow-banner`, `flow-node`, `flow-sep`, `flow-ribbon`, …); colour flows through the frozen `.sev-*` |
| `tests/test_flow_model.py`, `tests/test_flow_execution_service.py`, `tests/test_flow_builder_render.py` | +30 nodes (unit / integration / Pilot e2e) |

### Usage / examples

```text
# In the TUI (rail-8 Flow Builder):
#   1. Kind dropdown → "Load (image)"  · ref → prg.s19        · Add
#   2. Kind dropdown → "Check"         · ref → coverage.json  · gating → advisory | block-own-op · Add
#   3. Kind dropdown → "Write-out"     · ref → out.s19        · Add
#   4. Run  → the Pipeline Ledger paints: banner + 3 nodes + separators + ribbon + written path
```

```python
# Engine entry point (headless):
from s19_app.tui.services.flow_model import Flow, SourceBlock, CheckBlock, WriteOutBlock, FlowContext
from s19_app.tui.services.flow_execution_service import run_flow

flow = Flow("demo", [SourceBlock("prg.s19"), CheckBlock("coverage.json"), WriteOutBlock("out.s19")])
result = run_flow(flow, FlowContext(project_dir=project_dir))
result.status          # "ok" | "completed-with-issues" | "error"
result.written_paths   # [Path(.../out.s19)]  — byte-identical with or without the CHECK block
result.image_ranges    # final (start, end) footprint, consumed by the memory ribbon
```

### Diagrams

- `diagrams/block-pipeline-dataflow.mmd` — the block data flow (`run_flow` threading `mem_map`/`ranges`
  → `FlowRunResult`).
- `diagrams/panel-run-sequence.mmd` — sequence: Panel Run → `run_flow` → `render_result`.
- `diagrams/flow-status-classifier.mmd` — the 3-way flow-status classifier (aborted→FAILED /
  notices→ISSUES / clean→CLEAN).

### Evidence checklist — docs-writer

| Item | ✓/✗ | Evidence |
|------|-----|----------|
| Audience + purpose declared at top | ✓ | "Audience: technical stakeholder"; §At a glance states purpose |
| Structure follows template | ✓ | Mirrors the `06-docs/functionality.md` skeleton (At-a-glance → Detail → modules → usage → diagrams → evidence) |
| Code/CLI snippets actually run | ✓ | Engine snippet mirrors `run_flow` signature (`flow_execution_service.py:66`) + `FlowContext`/block dataclasses (`flow_model.py:66-181`); TUI steps mirror `_KIND_OPTIONS`/`#flow_gating` (`screens_directionb.py:2237,2319`). Not independently re-executed here — behavior verified by the 1623-pass gate run. |
| Assumptions listed | ✓ | Notify-don't-block invariant, A4 (no report file), AMD-1 single-ribbon rationale all stated |
| Risks / limitations called out | ✓ | "What is deferred" table (CRC/twin, persistence, gating polish, G-1) |
| Next steps stated | ✓ | batch-52 (CRC + twin) / batch-53 (persistence) in the deferred table |
| Diagrams where flow is non-trivial | ✓ | 3 mermaid diagrams under `diagrams/` |
| No invented APIs / versions / metrics | ✓ | Every symbol/line cited from the shipped source (`flow_model.py`, `flow_execution_service.py`, `screens_directionb.py`); geometry numbers from Inc-2 measured table (`screens_directionb.py:2139-2150`) |
