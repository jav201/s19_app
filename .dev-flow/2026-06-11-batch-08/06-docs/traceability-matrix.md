# Traceability Matrix — s19_app — Batch 2026-06-11-batch-08

> Full chain: **User Story → HLR → LLR → Test Case → File:line**.
> Every row must be complete when closing the batch (phase 6). Incomplete rows = coverage gaps and must be listed in the gaps section.
>
> Sources: `01-requirements.md` (iteration 3), `04-validation.md` (Phase-4 report, verdict PASS-WITH-NOTES, gate-approved).
> All `file:line` anchors below were grep-verified against the current tree (HEAD = 34fc43a on base ec453a2) on 2026-06-11.
> Pilot-test node ids use the **IMPLEMENTED** names (Phase-4 DEV-1 resolution — see gaps §3); the §4-pinned spec names are superseded by the concurrent Phase-6 amendment of `01-requirements.md`.

---

## 1. Master table

| US | HLR | LLR | TC | File:line | Status | Notes |
|----|-----|-----|-----|-----------|--------|-------|
| US-007 | HLR-001 | LLR-001.1 | TC-009 | Impl: `s19_app/tui/operations/model.py:177` (`Operation` ABC), `:209` (`describe`), `:228` (`execute` signature with kw-only `now_fn`). Test: `tests/test_operations.py:243` (`test_operation_interface`) | pass | 11 assertions ≥ threshold 6 (04-validation §1) |
| US-007 | HLR-001 | LLR-001.2 | TC-001 | Impl: `s19_app/tui/operations/model.py:23` (`STATUS_DOMAIN`), `:27` (`OperationResult`, 7 canonical C-2 fields), `:116-119` (closed-domain `ValueError`), `:122` (`to_dict`, size-bounded output summary). Test: `tests/test_operations.py:122` (`test_operation_result_schema`) | pass | 11/11 incl. the 2 m-7 disclosure assertions |
| US-007 | HLR-001 | LLR-001.3 | TC-002 | Impl: `s19_app/tui/operations/placeholders.py:64-69` (shared identity-result builder; note format at `:69`). Test: `tests/test_operations.py:153` (`test_identity_passthrough_s19`; shared helper `_assert_identity_passthrough` at `:106`) | pass | 15/15 — identity, status, mem_map/ranges/errors unmutated × 3 placeholders |
| US-007 | HLR-001 | LLR-001.4 | TC-003 | Impl: same passthrough path (`placeholders.py:64-69`) over a HEX-built snapshot (`s19_app/tui/services/load_service.py:44` `build_loaded_hex`). Test: `tests/test_operations.py:160` (`test_identity_passthrough_hex`) | pass | 15/15; tmp_path inline-HEX idiom per the E-1 acceptance criterion |
| US-007 | HLR-002 | LLR-002.1 | TC-004 | Impl: `s19_app/tui/operations/placeholders.py:74` (`CrcOperation`), `:147` (`ExtractOperation`), `:220` (`SplitBySegmentOperation`); ids at `:92`, `:165`, `:239`. Test: `tests/test_operations.py:167` (`test_placeholders_registered`) | pass | 6/6 — exact class resolution + exact note format |
| US-007 | HLR-002 | LLR-002.2 | TC-005 | Impl: `s19_app/tui/operations/registry.py:14` (static `_REGISTRY` literal dict), `:21` (`list_operation_ids`), `:44` (`get_operation`). Test: `tests/test_operations.py:183` (`test_registry_deterministic_order`) | pass | 5/5 — fixed order `["crc", "extract", "split_by_segment"]` |
| US-007 | HLR-002 | LLR-002.3 | TC-006 | Impl: `s19_app/tui/operations/registry.py:74` (`raise KeyError(f"unknown operation id: {operation_id}")`). Test: `tests/test_operations.py:191` (`test_unknown_operation_raises`) | pass | 2/2 — KeyError with verbatim id, no fallback |
| US-007 | HLR-003 | LLR-003.1 | TC-007 + probe P11 | Impl: `s19_app/tui/services/operation_service.py:38` (`run_operation`), `:35` (injectable `operation_resolver` seam, default `registry.get_operation`). Test: `tests/test_operations.py:198` (`test_run_operation_service`). Inspection: P11 filesystem-call probe → 0 hits (04-validation §2.3) | pass | 10 assertions (exceeds formula of 5 — note N-1); no-I/O AC structurally checked |
| US-007 | HLR-003 | LLR-003.2 | TC-008 (inspection) | Targets: `s19_app/tui/operations/*.py` + `s19_app/tui/services/operation_service.py`. Widened reverse-import + textual-import probe → 0 hits, exit 1 (04-validation §2.1-2.2) | pass | Headless guarantee: view imports the service, never the reverse |
| US-007 | HLR-004 | LLR-004.1 | TC-010 | Impl: `s19_app/tui/screens.py:484` (`OperationsScreen` modal), `s19_app/tui/app.py:502` (`Binding("x", "operations_view", "Operations", show=False)`), `app.py:2314` (`action_operations_view`), `app.py:2348-2351` (options pre-computed via `list_operation_ids()`/`get_operation(...).title`). Test: `tests/test_tui_operations_view.py:80` (`test_operations_view_lists_registry_ids`) | pass | 7 ≥ 5 assertions; also hosts the LLR-004.2 no-file guard assertions (note N-2) |
| US-007 | HLR-004 | LLR-004.2 | TC-011 + probe P8 | Impl: `s19_app/tui/screens.py:618` (sole `run_operation` call, inside `_execute_selected` at `:577`), `:611-615` (selection by list index), `:619-622` (`KeyError` → status line, no crash); no-file guard `s19_app/tui/app.py:2344-2347`. Test: `tests/test_tui_operations_view.py:141` (`test_operations_view_executes_via_service`). Inspection: P8 `\.execute\(` probe on `app.py`/`screens.py` → 0 hits | pass | Execution locus is modal-internal, not an app dismiss callback — DEV-2 supersession (gaps §3) |
| US-007 | HLR-004 | LLR-004.3 | TC-012 | Impl: `s19_app/tui/screens.py:628-635` (`render_hex_view_text` with EXACTLY the pinned argument tuple, `max_rows=MAX_HEX_ROWS`), `:636` (update of `#operation_result_hex`, widget declared `:550`; status widget `:548`). Renderer: `s19_app/tui/hexview.py:324`; `MAX_HEX_ROWS = 512` at `hexview.py:22`. Test: `tests/test_tui_operations_view.py:235` (`test_operations_view_result_hex_render_matches_baseline`) | pass | 4 ≥ 3; live-widget `.plain` equals independent pinned-args baseline (non-vacuous end-to-end identity demo) |
| US-007 | HLR-004 | LLR-004.4 | inspection (no-`@work`) | Impl: `s19_app/tui/app.py:2314` (`action_operations_view`, no `@work` decorator), `s19_app/tui/screens.py:577` (`_execute_selected`, plain synchronous method). Inspection: 0 `@work` decorators on HLR-004 paths (04-validation §2.5) | pass | Valid ONLY under the placeholder no-I/O/no-parse guarantee; R-6 mandates worker migration at fill-in |

Supporting contract anchors (shared by multiple rows, grep-verified): `LoadedFile` — `s19_app/tui/models.py:9`; `build_loaded_s19` — `s19_app/tui/services/load_service.py:17`.

---

## 2. Coverage summary

| Metric | Value |
|--------|-------|
| Total user stories | 1 (US-007) |
| Covered user stories | 1 (100%) |
| Total HLR | 4 |
| Implemented HLR | 4 (100%) |
| Total LLR | 13 |
| Implemented LLR | 13 (100%) |
| Test cases | 12 (TC-001..TC-012; TC-008 is an inspection probe, LLR-004.4 is inspection-only without a TC id) |
| TC pass | 12 (11 executed pytest nodes + TC-008 probe at 0 hits; all inspections pass — 04-validation §1) |
| TC fail | 0 |
| TC pending | 0 |

Suite-level: 733 collected = 722 baseline + 11 new (8 unit + 3 pilot), reconciliation exact; lean gate 681 passed / 0 failures; full suite 701 passed / 0 failures (04-validation §2.10, §3 criterion 3-4).

---

## 3. Detected gaps

> Incomplete rows, requirements without TC, or TCs without code mapping.

| ID | Type | Description | Proposed action |
|----|------|-------------|-----------------|
| DEV-1 | Doc-vs-code drift (test node names) | The 3 pilot tests were implemented as `test_operations_view_lists_registry_ids` / `test_operations_view_executes_via_service` / `test_operations_view_result_hex_render_matches_baseline`, not the §4-pinned spec names. Behavior fully covered and passing under the implemented names. | **RESOLVED in Phase 6** — doc supersession: `01-requirements.md` §4/§5.3 node ids amended to the implemented names (concurrent Phase-6 amendment, orchestrator-assigned per the Phase-4 gate disposition). This matrix already uses the implemented names. |
| DEV-2 | Doc-vs-code drift (execution locus) | LLR-004.2's text named the app's `push_screen(..., callback)` dismiss-callback pattern; the implementation executes inside the modal (`screens.py:618`, `_execute_selected`) with no callback. The normative core (execution exclusively through the LLR-003.1 service; P8 0 hits; KeyError → status line; no-file guard) holds and is verified. | **RESOLVED in Phase 6** — doc supersession: LLR-004.2 mechanism clause reworded to the modal-internal execution actually built (concurrent Phase-6 amendment, same gate disposition). |
| N-3 | Hygiene (cosmetic, carried) | `OperationsScreen` button container reuses widget id `load_buttons` (`s19_app/tui/screens.py:556`) — id borrowed from the Load screen's naming. Textual-legal (unique within the screen), no LLR pins it. | **CARRIED** — rename candidate for a future hygiene pass; logged at the Phase-4 gate, no action this batch. |

Recorded-no-action notes (not gaps): N-1 — TC-007 has 10 assertions vs the formula's 5 (all mandated elements present, excess only); N-2 — the LLR-004.2 no-file guard is asserted inside TC-010 rather than TC-011 (same file, all elements asserted and passing).

---

## 4. Changes from previous batch

| Type | Item | Detail |
|------|------|--------|
| new | US-007 | Placeholder operations story (batch-08 init). US-006 (hex compare) remains queued, NOT in this batch. |
| new | HLR-001..HLR-003 + LLR-001.1..003.2 | Operation abstraction (`Operation` ABC + `OperationResult` envelope), 3 placeholders, deterministic registry, headless `run_operation` service — NEW package `s19_app/tui/operations/` + `s19_app/tui/services/operation_service.py`. |
| new | HLR-004 + LLR-004.1..004.4 | TUI operations view — added at the Phase-1 gate iteration 2 (G-1 REVERSED by operator, §6.2 C-4). `OperationsScreen` + `x` binding. |
| modified | LLR-003.2 / TC-008 probe | Widened at iteration 3 (review B-2 + m-10): relative/module-object import forms, `^\s*` anchors, regime-correct controls (P8b). |
| modified | LLR-001.1/001.2/003.1 signatures | Iteration 3 (M-1/m-7): kw-only `now_fn` clock seam pinned end-to-end; disclosure assertions added to TC-001; C-2 field-set identity re-run 7=7=7=7. |
| new | Probe P11 | Filesystem-call inspection over the operations package + service (iteration 3, review m-6) — structural backing for the LLR-003.1 no-I/O criterion. |
| closed | Batch-07 DEV-8 precedent applied | Phase-4 doc-drift findings (DEV-1/DEV-2) routed to Phase-6 supersession instead of code churn — same disposition pattern as batch-07. |

---

## 5. Quick bidirectional mapping

### 5.1 By user story
- **US-007** → HLR-001, HLR-002, HLR-003, HLR-004 → LLR-001.1..001.4, LLR-002.1..002.3, LLR-003.1..003.2, LLR-004.1..004.4 → TC-001..TC-012 (+ LLR-004.4 no-`@work` inspection)

### 5.2 By code file
- `s19_app/tui/operations/model.py` → LLR-001.1, LLR-001.2 → TC-009, TC-001
- `s19_app/tui/operations/placeholders.py` → LLR-001.3, LLR-001.4, LLR-002.1 → TC-002, TC-003, TC-004
- `s19_app/tui/operations/registry.py` → LLR-002.2, LLR-002.3 → TC-005, TC-006
- `s19_app/tui/services/operation_service.py` → LLR-003.1, LLR-003.2 → TC-007, TC-008 (probe)
- `s19_app/tui/screens.py` (`OperationsScreen`) → LLR-004.1, LLR-004.2, LLR-004.3, LLR-004.4 → TC-010, TC-011, TC-012
- `s19_app/tui/app.py` (binding + action + guard) → LLR-004.1, LLR-004.2, LLR-004.4 → TC-010, TC-011
- `tests/test_operations.py` → TC-001..TC-007, TC-009 (8 unit nodes)
- `tests/test_tui_operations_view.py` → TC-010..TC-012 (3 pilot nodes)

---

## 6. Batch sign-off

| Field | Value |
|-------|-------|
| Batch ID | `2026-06-11-batch-08` |
| Closing date | `2026-06-11` |
| Total iterations (sum of phases) | 10 (P1: 3 · P2: 1 · P3: 3 · P4: 1 · P5: 1 · P6: 1) |
| Validation passed | yes (Phase-4 PASS-WITH-NOTES, gate-approved; lean 681/0, full 701/0) |
| Synced to Obsidian | no (pending — run dev-flow-sync after commit/push/merge) |
