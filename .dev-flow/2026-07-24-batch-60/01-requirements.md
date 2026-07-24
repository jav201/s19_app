# 01 — Requirements · batch-60 (FB-P1b: flow-run report GENERATION)

**BLUF:** batch-53 shipped the `ReportBlock` as model+persist+**no-op**. FB-P1b makes a
report-bearing flow **generate report content**: a pure `compose_flow_report` over the run
state already assembled in `FlowRunResult`, written to the project `reports/` dir under the
existing `<ts>-report.md` convention so the shipped viewer surfaces it with no new UI.

## §1 Scope + operator decisions (kickoff 2026-07-24, prototype-approved)
- **D-1 Explicit trigger.** A report is generated ONLY when the flow contains a
  `ReportBlock`. NOT implicit-always. (Honors the batch-53 shipped model.)
- **D-2 Positional.** The block reports the run state UP TO its position (blocks executed
  before it + the threaded image footprint at that point). REPORT-last captures the whole
  pipeline. The report's status is therefore a **provisional** rollup of blocks-so-far.
- **D-3 (OQ-1) Filename reuse.** `<ts>-report.md` verbatim — the flow report matches
  `REPORT_FILENAME_REGEX` (`report_service.py:110`) so `list_project_reports`
  (`:455`) + `ReportViewerScreen` surface it with **no viewer change**.
- **D-4 (OQ-2) N report blocks allowed** — each writes its own positional report.
- **D-5 (OQ-3)** the written report path surfaces in the panel ledger (`render_result`).
- **D-6 (OQ-4)** an aborted/empty run still writes a report (honest record).
- Authorization: **AUTONOMOUS + self-merge**, plan+prototype-first **satisfied**
  (prototype approved: "aprobado, arranca autónomo con esos defaults").

## §2 Verified anchors (draft-time, file:line)
- `flow_execution_service.py:378-387` — the `ReportBlock` no-op branch to REPLACE. Module is
  **NOT frozen** (batch-52 precedent). `run_flow` builds `result.block_results` incrementally.
- `flow_model.py:256-287` — `FlowRunResult` carries `status`, `block_results`,
  `written_paths`, `image_ranges`, `pre_crc_ranges`; `BlockResult` (`:232-252`) carries
  `index/kind/status/summary/diagnostics/findings`.
- `report_service.py:107` `REPORT_TIMESTAMP_FORMAT="%Y%m%dT%H%M%SZ"` · `:110`
  `REPORT_FILENAME_REGEX` · `:412` `_report_filename` (collision-resolving, raises
  `FileExistsError` after 99 slots — never a silent overwrite) · `:455`
  `list_project_reports` · `:1557` injectable `now_fn` clock · `:1560` `mkdir(parents=True,
  exist_ok=True)` · `:1613` `write_text(..., encoding="utf-8")`.
- **Reuse-not-fork:** `_report_filename` is imported, not reimplemented (same convention as
  batch-53 importing the private `_resolve_manifest_entry`).
- **Frozen set OFF-LIMITS** (untouched): `core.py`, `hexfile.py`, `range_index.py`,
  `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`.

## §3 User stories
| US | Statement | Source | Status |
|----|-----------|--------|--------|
| US-001 | As an operator, when my flow includes a REPORT block, I want a markdown report of the run written to the project so I have a durable record of what the pipeline did. | D2/FB-P1b | READY |
| US-002 | As an operator, I want the flow report to appear in the existing reports list/viewer, so I read it where I already read project reports. | D-3 | READY |
| US-003 | As a security-conscious operator, I want file-derived text in the report to be inert, so a hostile change-doc name cannot forge report structure. | C-17 | READY |

**Evaluability (black-box):**
- US-001 → "After running a flow ending in REPORT, a `reports/<ts>-report.md` exists, is
  non-empty, and names every executed block." → **AT-001**.
- US-002 → "`list_project_reports(project_dir)` includes the flow report." → **AT-002**.
- US-003 → "A hostile block ref renders escaped; no live markdown structure." → **AT-003**.

## §4 High-level requirements
- **HLR-001 Compose.** The system shall compose a deterministic markdown report from the
  run state up to the report block.
- **HLR-002 Write.** The system shall write that report into the project `reports/` dir
  under the shipped filename convention, without overwriting an existing report.
- **HLR-003 Surface.** The block result shall carry the written path, and the panel ledger
  shall show it.

## §5 Low-level requirements
### LLR-001.1 — `compose_flow_report` (pure)
- **Statement:** `flow_report_service.compose_flow_report(state, generated_at) -> str`
  **NEW** shall return markdown with, in order: a `# Flow report — <name>` header block
  (generated timestamp, provisional status label, block count), a **Pipeline ledger** table
  (one row per `BlockResult`: index+1, KIND, status glyph + token, summary), a **Findings**
  section (per block, `[KIND #n] (severity) message`) omitted when there are none, an
  **Image footprint** section (`Before CRC` only when `pre_crc_ranges` is non-empty, plus
  `Final`, each with byte totals), and a **Written files** list (`(none)` when empty).
- **Validation:** `test (unit)` · **Threshold:** golden-structure match for a 4-block run;
  every `BlockResult` appears exactly once; `0` missing sections.

### LLR-001.2 — provisional status rollup
- **Statement:** The report's status shall mirror `run_flow`'s three-way rule over the
  blocks reported so far: FAILED when a block aborted the image, COMPLETED WITH ISSUES when
  any block is `notices`/`error` or carries findings, else CLEAN.
- **Validation:** `test (unit)` · **Threshold:** the 3 states each render their label; `0`
  misclassifications.

### LLR-001.3 — `_md_safe` markdown neutralisation (C-17)
- **Statement:** Every file-derived string entering the report (flow name, block summary,
  finding message, written path, block kind) shall pass through `_md_safe` **NEW**, which
  escapes `\ ` `` ` `` `| * _ [ ] < > #`, strips control bytes, and collapses newlines/tabs
  to spaces, returning `(empty)` for a blank result.
- **Validation:** `test (unit)` + `test (integration)` · **Threshold:** a hostile ref
  containing a table break, heading, code span, link and `<script>` yields **0** live
  markdown structures; a benign ref round-trips readable.

### LLR-002.1 — `write_flow_report` under `reports/`
- **Statement:** `flow_report_service.write_flow_report(state, project_dir, now_fn=None)`
  **NEW** shall `mkdir(parents=True, exist_ok=True)` the `reports/` dir, pick the filename
  via the **imported** `report_service._report_filename` (collision-resolving), write UTF-8,
  and return the `Path`. The clock is injectable (`now_fn`) for deterministic tests.
- **Validation:** `test (integration)` · **Threshold:** file exists, non-empty, name matches
  `REPORT_FILENAME_REGEX`; a second report in the same second gets the `-01` suffix; `0`
  overwrites of an existing report.

### LLR-003.1 — `run_flow` REPORT branch generates
- **Statement:** The `ReportBlock` branch (`flow_execution_service.py:378`) shall replace
  the no-op: build the state from `result.block_results` so far + the threaded
  `(image_ranges, pre_crc_ranges, written_paths)` + `flow.name`, call `write_flow_report`
  against `ctx.project_dir`, and emit `BLOCK_STATUS_OK` with summary
  `wrote reports/<filename>`; the threaded `(mem_map, ranges)` pass forward UNCHANGED.
  A write failure shall emit `BLOCK_STATUS_ERROR` with a diagnostic and **shall not abort**
  the flow (a report is a record, not an operation on the image).
- **Validation:** `test (integration)` · **Threshold:** report-bearing flow → file on disk +
  summary names it; rollup unchanged vs the same flow without the report block; write
  failure → error block, image intact, flow not aborted.

### LLR-003.2 — panel ledger shows the report path (D-5)
- **Statement:** `render_result` shall render the REPORT block's summary line like any other
  block (markup-safe), so the written path is visible in the ledger.
- **Validation:** `test (e2e pilot)` · **Threshold:** the painted ledger contains
  `reports/` + the filename; `0` markup spans injected.

## §6 Decisions / open questions
All four kickoff OQs resolved as D-3..D-6 above (operator-approved defaults). No open
questions carried into Phase 2.

## §6.6 Ledger — draft-time verification
Every anchor in §2 was read on disk at draft time (`flow_execution_service.py:378-387`,
`flow_model.py:232-287`, `report_service.py:107/110/412/455/1557/1560/1613`). No
`assumed —` markers remain. The `ReportBlock` no-op is confirmed still in place (RC-1
already-shipped grep: report generation is greenfield).

## §7 Traceability
| US | HLR | LLR | AT |
|----|-----|-----|----|
| US-001 | HLR-001, HLR-002 | LLR-001.1, LLR-001.2, LLR-002.1, LLR-003.1 | AT-001 |
| US-002 | HLR-002 | LLR-002.1 | AT-002 |
| US-003 | HLR-001 | LLR-001.3 | AT-003 |
| — | HLR-003 | LLR-003.2 | AT-004 |

## Evidence checklist
- [x] Anchors verified on disk with file:line — §2 / §6.6.
- [x] Every US has a black-box evaluability statement + owning AT — §3.
- [x] Every LLR has validation type + numeric threshold — §5.
- [x] Frozen-file set named and excluded — §2.
- [x] Operator decisions recorded (D-1..D-6) — §1.
- [x] Open questions resolved before Phase 2 — §6.
