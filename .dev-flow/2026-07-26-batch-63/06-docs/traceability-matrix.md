# batch-63 — traceability matrix

**Scope:** D3 only (`R-TUI-097`). D1 (`R-TUI-095`) and D2 (`R-TUI-096`) were returned to
`.dev-flow/BACKLOG.md` at the Phase-2 re-gate and are **not** part of this batch's coverage.

Merged: PR #139, squash `c473152`.

## Dual traceability — both chains complete, zero gaps

### Behavioural (black-box): US → AT → observed outcome

| US | AT | shipped surface driven | outcome observed | node |
|---|---|---|---|---|
| US-B63-D3 | AT-172 | `generate_project_report` | the bytes on disk follow the encoder | `test_report_document_bytes.py::test_at172_replacing_the_encoder_changes_what_the_project_report_writes` |
| US-B63-D3 | AT-172 | `generate_project_report` | file == `document_bytes` of its own text | `…::test_at172b_the_unpatched_report_is_exactly_the_encoder_output` |
| US-B63-D3 | AT-173 | `write_flow_report` | the bytes on disk follow the encoder | `test_flow_report_service.py::test_at173_replacing_the_encoder_changes_what_write_flow_report_writes` |
| US-B63-D3 | AT-173 | `write_flow_report` | file == encoder output for the composed report | `test_flow_report_service.py::test_at173b_flow_report_bytes_equal_the_encoder_output` |
| US-B63-D3 | AT-174 **(PIN)** | `_line_bytes` | the `+1`/line charge holds | `…::test_at174_line_bytes_charges_one_byte_per_line` |
| US-B63-D3 | AT-174 **(PIN)** | `_line_bytes` | partition-invariance holds | `…::test_at174b_line_bytes_is_partition_invariant` |
| US-B63-D3 | AT-193 | the service package | no budget-sharing module writes in text mode | `…::test_at193_no_accounting_module_writes_in_text_mode` |
| US-B63-D3 | AT-193b | the census detector | the detector can fire on every offending spelling | `…::test_at193b_the_text_mode_detector_can_actually_fire` |
| US-B63-D3 | AT-175 | `generate_project_report` | no `\r` on a CRLF host (**not a merge-gate check**) | `…::test_at175_written_report_carries_no_cr_on_a_crlf_host` |

### Functional (white-box): HLR → LLR → TC → node

| HLR | LLR | TC | node |
|---|---|---|---|
| HLR-102 | LLR-102.1 one encoder; both writers on it | TC-470 | `test_at172_…` |
| HLR-102 | LLR-102.1 flow writer on the seam | TC-472 | `test_at173_…` |
| HLR-102 | LLR-102.1 no text-mode writer shares the budget | TC-476 | `test_at193_…` |
| HLR-102 | LLR-102.1 the census detector can fire | TC-477 | `test_at193b_…` |
| HLR-102 | LLR-102.2 `_line_bytes` unchanged (`+1`/line) | TC-473 | `test_at174_…` |
| HLR-102 | LLR-102.2 partition-invariance; redefinition prohibited | TC-474 | `test_at174b_…` |
| HLR-102 | LLR-102.3 platform-independent file size | TC-471 | `test_at172b_…` |
| HLR-102 | LLR-102.3 flow bytes == encoder output | TC-475 | `test_at173b_…` |
| HLR-102 | LLR-102.3 Windows behaviour | TC-478 | `test_at175_…` |
| HLR-102 | LLR-102.4 golden neutrality | TC-479 | 29 snapshot cells + the 6-file derived observer set |

**Coverage:** US 1/1 ready, 1/1 covered. LLR 4/4 = **100 %**. Orphan nodes: 0. Phantom ids: 0.

## Superseded ids

`01b-qa-catalog-rescoped.md` §4's semantics for `TC-467..479` are **retired** — every id in
`TC-470..479` binds a different observable there, and `TC-467..469` have no shipped node. The live
definitions are the table above and `04-validation-rescoped.md` §2b.

## What this batch does NOT cover

`AT-164..171` (D1/D2) are withdrawn from batch-63. `M-2` and the report's resident-memory axis are
closed by neither `R-TUI-097` nor anything else in this batch — both are carried in
`.dev-flow/BACKLOG.md` with their measurements.
