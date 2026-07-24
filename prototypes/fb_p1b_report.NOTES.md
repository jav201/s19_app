# FB-P1b prototype — flow-run report GENERATION · NOTES + decisions

**What it is.** batch-53 shipped the `ReportBlock` as model+persist+no-op. FB-P1b makes a
report-bearing flow actually **generate report content**. Generation is a pure,
deterministic **compose-from-`FlowRunResult`** — no model judgment (rule 5).

Artifacts:
- `fb_p1b_report.prototype.py` — runnable composer (`compose_flow_report`) + a realistic
  LOAD→PATCH→CRC→WRITE-OUT sample that includes a HOSTILE `change_doc_ref` to prove
  markup-safety. Dependency-free; `PYTHONIOENCODING=utf-8 python prototypes/fb_p1b_report.prototype.py`.
- `fb_p1b_report.example.md` — the to-scale rendered report the prototype emits.

## Confirmed decisions (operator, kickoff 2026-07-24)
- **Explicit trigger.** A report is generated ONLY when the flow contains a `ReportBlock`
  (honors the batch-53 shipped model; NOT implicit-always).
- **Positional.** The block reports the run state UP TO its position (blocks executed
  before it + the threaded image footprint at that point). A flow with REPORT last — the
  typical shape — captures the whole pipeline. The report's `Status` is therefore a
  *provisional* rollup of blocks-so-far (the flow-level rollup is only final after the
  last block).
- **Autonomy:** autónomo + self-merge, plan+prototype-first (this prototype is the gate).
- **Prototype-first** (this doc).

## Report layout (see example.md)
1. **Header** — flow name (markup-safe) · generated timestamp · provisional status
   (CLEAN / COMPLETED WITH ISSUES / FAILED) · block count.
2. **Pipeline ledger** — one table row per block: `# · BLOCK · <glyph> status · summary`.
   Glyphs are the enum-derived `●/◈/✖/○` (never file-derived).
3. **Findings** — per-block, `[KIND #n] (severity) message`, every field markup-safe.
4. **Image footprint** — `Before CRC` (when a CRC block grew the image) + `Final` ranges
   with byte totals — the Flow Builder before/after signature.
5. **Written files** — the `written_paths`.

## Security (C-17 — the load-bearing surface)
The report embeds file-derived strings (block summaries, finding messages, written paths,
the flow name). Rendered later in a Markdown widget (`ReportViewerScreen`), so a hostile
`change_doc_ref` could otherwise inject a table break (`|`), a heading (`#`), a code span
(`` ` ``), a link (`[..]`), or emphasis. `_md_safe` escapes all of these + strips control
bytes + collapses newlines to one line per cell. The example's hostile ref
`calib[bad].json | # INJECTED ` `` `code` `` ` <script>` renders **fully inert**
(prototype self-check asserts no live table break / code span survives). This also closes
the batch-53 **qa M-3 carry** (a static `from_markup`/markup-safety guard now has a concrete
home) — the report composer is the new markup sink to sweep + test.

## Landing map (provisional — Phase 3)
- **New composer** `report_service`-adjacent (Textual-free, C-7): a `compose_flow_report`
  taking the run state — likely a new small module (or a function in a new
  `flow_report_service.py`) rather than bending the 1250-line `report_service.py`
  (`VariantExecutionResult`-keyed, wrong input type).
- **Write seam:** reuse the `reports/` dir + `<ts>-report.md` filename convention
  (`report_service._report_filename` / `list_project_reports`) so `ReportViewerScreen`
  surfaces flow reports with NO new viewer. Write via the work-area write path (contained).
- **Wire point:** the `ReportBlock` branch in `flow_execution_service.run_flow`
  (`flow_execution_service.py:378`) — replace the no-op: compose from `result.block_results`
  so-far + threaded `(mem_map, ranges)` + `ctx.project_dir`, write, and emit a `BlockResult`
  whose summary carries the written report path (status stays `OK`). `flow_execution_service.py`
  is NON-frozen (batch-52 precedent).
- **Clock:** injectable (mirror `report_service._default_now`) so tests are deterministic.

## Open questions for the spec gate
- **OQ-1** filename: reuse `<ts>-report.md` verbatim (flow + project reports interleave in
  one `reports/` list) vs a `<ts>-flow-report.md` variant (distinguishable in the viewer)?
- **OQ-2** multiple ReportBlocks in one flow — allowed (each writes its own positional
  report) or collapse to one? (Prototype allows N; each is independent.)
- **OQ-3** should the written report path also surface in the panel's `render_result`
  ledger (a "wrote report → reports/<ts>-report.md" line), or only in the report itself?
- **OQ-4** empty/aborted run before the report block — still write a (mostly-empty) report,
  or skip with a notice?
