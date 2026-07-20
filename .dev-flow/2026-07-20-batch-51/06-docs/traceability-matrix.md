# Traceability Matrix — s19_app — Batch 2026-07-20-batch-51 (Flow Builder)

> **Artifact language:** English (`state.json` `language = en`).
> **Source of node names:** every `TC-NNN`/`AT-NNN` below is reconciled to the REAL on-disk pytest
> node name from `04-validation.md` (Phase-4, V-5). All rows green — validation verdict **PASS**
> (17/17 LLRs · 9/9 ATs · 0 blocker fails · 0 engine-frozen diffs).
>
> Two chains per story (Two-layer validation rule) — a story is complete only when BOTH exist:
> - **Functional (white-box):** US → HLR → LLR → `TC` → real node.
> - **Behavioral (black-box):** US → `AT` → observed outcome through the shipped surface.

Test-file key: **M** = `tests/test_flow_model.py` · **E** = `tests/test_flow_execution_service.py` ·
**R** = `tests/test_flow_builder_render.py`. All nodes are members of the single gate-suite run
(`pytest -q -m "not slow"` → **1623 passed, 0 failed**, 29 snapshots 0 drift).

---

## 1. Master table — functional chain (white-box)

| US | HLR | LLR | TC | On-disk node (reconciled) | File | Status |
|----|-----|-----|-----|---------------------------|------|--------|
| US-085 | R-TUI-085 | LLR-085.1 (Finding + `notices` token) | TC-085.1 | `test_tc085_1_finding_and_notices_token` | M | pass |
| US-085 | R-TUI-085 | LLR-085.2 (parser errors → WARN notices, chain runs) | TC-085.2 | `test_tc085_2_zero_error_image_stays_ok` (boundary) · `test_tc085_3_findings_count_matches_load_errors` (1-per-error) · `test_at085a_load_notices_downstream_runs` | E | pass |
| US-085 | R-TUI-085 | LLR-085.3 (STOP / abort-asymmetry) | TC-085.3 | `test_at085b_unresolvable_source_stops_and_skips` | E | pass |
| US-086 | R-TUI-086 | LLR-086.1 (`CheckBlock` + gating vocab, frozen) | TC-086.1 | `test_tc086_1_check_block_and_gating_vocab` · `test_tc086_1_check_block_is_frozen` | M | pass |
| US-086 | R-TUI-086 | LLR-086.2 (CHECK executes, report attached, image intact) | TC-086.2 | `test_tc086_2_check_reports_counts_image_intact` | E | pass |
| US-086 | R-TUI-086 | LLR-086.3 (pass-through byte-equality) | TC-086.3 | `test_at086a_check_passthrough_bytes_identical` | E | pass |
| US-086 | R-TUI-086 | LLR-086.4 (chain-never-blocked 4-case matrix) | TC-086.4 | `test_tc086_4_chain_never_blocked_matrix` · `test_tc086_6_check_body_exception_never_aborts_chain` (structural, widened-try) | E | pass |
| US-086 | R-TUI-086 | LLR-086.5 (unreadable check-doc, non-aborting both modes) | TC-086.5 | `test_tc086_5_unreadable_check_doc_non_aborting` | E | pass |
| US-087 | R-TUI-087 | LLR-087.1 (`completed-with-issues` token) | TC-087.1 | `test_tc087_1_flow_status_issues_token` | M | pass |
| US-087 | R-TUI-087 | LLR-087.2 (three-way roll-up) | TC-087.2 | `test_tc087_2_three_way_rollup` | E | pass |
| US-087 | R-TUI-087 | LLR-087.3 (token carrier + banner, single sink — *inspection*) | TC-087.3 | carrier `FlowRunResult.status` via `test_at087a_issues_distinct_from_failed` (E); banner sink via `test_at085a_notices_load_shows_warning_gutter` + `test_at088a_pipeline_ledger_structure_all_three_banners` (R) | E+R | pass |
| US-088 | R-TUI-088 | LLR-088.1 (status→`sev-*` map, outside frozen file) | TC-088.1 | `test_tc088_1_status_class_map_covers_every_status` | R | pass |
| US-088 | R-TUI-088 | LLR-088.2 (vertical nodes, count derived) | TC-088.2 | `test_at088a_pipeline_ledger_structure_all_three_banners` (`node_count == len(block_results)`) | R | pass |
| US-088 | R-TUI-088 | LLR-088.3 (N−1 separators, no trailing) | TC-088.3 | `test_at088a_pipeline_ledger_structure_all_three_banners` (N−1) · `test_at088a_single_block_has_no_dangling_separator` (0 for single) | R | pass |
| US-088 | R-TUI-088 | LLR-088.4 (single ribbon, geometry measured — AMD-1) | TC-088.4 | `test_tc088_4_ribbon_encodes_footprint` · `test_ribbon_geometry_measured_no_overflow` (80×24 & 120×30, MEASURED) · engine carrier `test_tc088_image_ranges_carries_final_footprint` (E) | R+E | pass |
| US-088 | R-TUI-088 | LLR-088.5 (banner text + `sev-*` class) | TC-088.5 | `test_at088a_pipeline_ledger_structure_all_three_banners` (CLEAN/ISSUES/FAILED × sev-ok/warning/error) | R | pass |
| US-088 | R-TUI-088 | LLR-088.6 (markup-safety per sink, C-17) | TC-088.6 | `test_at088b_every_render_sink_renders_hostile_literally` · `test_at088b_check_ref_label_renders_literally` | R | pass |
| US-088 | R-TUI-088 | LLR-088.7 (CHECK/LOAD dropdown + `_make_flow_block` + gating setter) | TC-088.7 | `test_tc088_7_dropdown_offers_check_and_load_keeps_source_tag` · `test_at088_gating_selector_appends_block_own_op_check` · `test_flow_block_label_covers_check` | R | pass |

**Layer A: 17/17 LLRs → ≥1 real on-disk node, all inside the 1623-pass gate run. No LLR without a mapped node; no mapped node is a phantom (all collected via `pytest --collect-only`).**

## 1b. Behavioral chain (black-box)

> Per user story: the acceptance test that observes the outcome through the shipped surface. Each AT
> maps to EXACTLY ONE distinct node driving the whole named chain (C-18 one-node realization — 0
> "satisfied in parts"). Shipped surface = the `run_flow` handler and/or the real
> `#flow_run` / `#flow_add` panel buttons → `render_result`.

| US | AT | On-disk node driving the whole chain | Shipped surface | Observed outcome / deliverable | Status |
|----|----|--------------------------------------|-----------------|--------------------------------|--------|
| US-085 | AT-085a | `test_at085a_load_notices_downstream_runs` (+ render observer `test_at085a_notices_load_shows_warning_gutter`) | `run_flow`; re-observed via `#flow_run` → `render_result` | SOURCE `notices` + ≥1 WARN finding (C-9 message pinned) + downstream ran + file produced; sev-warning gutter + banner ISSUES | pass |
| US-085 | AT-085b | `test_at085b_unresolvable_source_stops_and_skips` | `run_flow`; FAILED banner via `test_at088a` | SOURCE `error`/STOP + downstream `skipped` + `written_paths == []` | pass |
| US-086 | AT-086a | `test_at086a_check_passthrough_bytes_identical` | `run_flow` → written file on disk | Byte-equal WRITE-OUT with/without CHECK + report present (`passed=/failed=/uncheckable=`) | pass |
| US-086 | AT-086b | `test_at086b_unreadable_check_doc_block_own_op_downstream_runs` | `run_flow` | CHECK `error` (block-own-op) + downstream WRITE-OUT still produces file | pass |
| US-086 | AT-086c | `test_at086c_gating_flag_drives_observable_status_change` | `run_flow` | SAME unreadable doc: advisory→`notices` vs block-own-op→`error` (status **differs**) + BOTH produce file — **non-vacuous confirmed** | pass |
| US-087 | AT-087a | `test_at087a_issues_distinct_from_failed` (banner via `test_at088a` ISSUES + `test_at085a`) | `run_flow`; banner via `render_result` | Output+advisories → `completed-with-issues` (file produced) vs broken → `error` (no file), asserts distinct | pass |
| US-087 | AT-087b | `test_at087b_clean_run_is_ok` (banner via `test_at088a` CLEAN) | `run_flow`; banner via `render_result` | Fully clean run → `ok` (CLEAN boundary) | pass |
| US-088 | AT-088a | `test_at088a_pipeline_ledger_structure_all_three_banners` | real `#flow_run` → `run_flow` → `render_result` (Pilot) | one node/block + N−1 seps + per-node `sev-*` + ribbon×1 + banner text/class, driven CLEAN/ISSUES/FAILED | pass |
| US-088 | AT-088b | `test_at088b_every_render_sink_renders_hostile_literally` (+ `test_at088b_check_ref_label_renders_literally` via `#flow_add`) | `render_result` (Pilot) | 5 file-derived sinks: per-sink `plain` verbatim AND `spans == []`; 3-layer AST completeness guard — **non-vacuous markup-sweep confirmed** | pass |

**Layer B: all 9 ATs one-node-realized through the shipped surface, boundary + negative evidence present. GREEN.**

---

## 2. Coverage summary

| Metric | Value |
|--------|-------|
| Total user stories | 4 (US-085..088) |
| Covered user stories | 4 (100%) |
| Total HLR | 4 (R-TUI-085..088) |
| Implemented HLR | 4 (100%) |
| Total LLR | 17 (LLR-085.1..088.7) |
| Implemented LLR | 17 (100%) |
| White-box test cases (TC) | 17 LLR-mapped (30 new nodes: M 4 + E 15 + R 11) |
| Black-box acceptance tests (AT) | 9 (all one-node-realized) |
| TC/AT pass | all (members of the 1623-pass run) |
| TC/AT fail | 0 |
| TC/AT pending | 0 |
| Engine-frozen diffs (C-27 dual-guard) | 0 |
| Snapshot drift | 0 (no baseline navigates into `#screen_flow`) |

---

## 3. Detected gaps

| ID | Type | Description | Proposed action |
|----|------|-------------|-----------------|
| — | — | **No traceability gap.** Every US → HLR → LLR → TC and every US → AT is complete and green. | — |
| G-1 | non-blocking (boundary-TC, not an AT) | The R-TUI-088 QC-3 "empty (no blocks / no run yet → empty-state text, no crash)" boundary has no dedicated render node. `test_at088a_single_block_has_no_dangling_separator` covers the single-block boundary; a zero-block / pre-run render through `render_result` is not directly exercised. This is a boundary TC (mapped to "TC", not one of the 9 named ATs), so it does **not** fall under the two-layer blocker rule — all 9 ATs are observed. Underlying pieces are unit-proven (`_memory_ribbon_text([]).plain == ""`; roll-up over no blocks = `ok`). | Phase-3 follow-up TC (`render_result` over `FlowRunResult(status=ok, block_results=[], image_ranges=[])` → 0 nodes, 0 seps, empty ribbon, CLEAN/empty-state banner, no crash). Does NOT force iterate. Log as a carry. |

---

## 4. Changes from previous batch (batch-50 → batch-51)

| Type | Item | Detail |
|------|------|--------|
| new | US-085..088 / R-TUI-085..088 | Four new stories/HLRs (LOAD notices · CHECK block · status model · Direction-A render) |
| new | LLR-085.1..088.7 | 17 new low-level requirements |
| new | `flow_model` symbols | `BLOCK_CHECK`, `CheckBlock`, `CHECK_GATING_ADVISORY/_BLOCK_OWN`, `BLOCK_STATUS_NOTICES`, `FLOW_STATUS_ISSUES`, `Finding`, `FINDING_WARN`, `BlockResult.findings`, `FlowRunResult.image_ranges` |
| modified | `flow_execution_service.run_flow` | LOAD notice emission; CHECK branch (read-only, chain-never-blocked); two-way → three-way roll-up; `image_ranges` carrier |
| modified | `screens_directionb.FlowBuilderPanel.render_result` | flat text list → Direction-A Pipeline Ledger (banner + nodes + gutter + separators + single ribbon) |
| new | test files | `tests/test_flow_model.py`, `tests/test_flow_execution_service.py`, `tests/test_flow_builder_render.py` (+30 nodes) |
| kept | `tests/test_flow_execution.py` | 4 batch-44 tracer guards retained, green, disjoint node set (no orphan) |
| deferred | twin ribbon (before/after row) + CRC block | → batch-52 (see AMD-1) |
| deferred | `flow.json` persistence + external import + variant reuse | → batch-53 |

---

## 5. Quick bidirectional mapping

### 5.1 By user story
- **US-085** → R-TUI-085 → LLR-085.1, LLR-085.2, LLR-085.3 → TC-085.1/.2/.3 + AT-085a/AT-085b
- **US-086** → R-TUI-086 → LLR-086.1..086.5 → TC-086.1/.2/.3/.4/.5 + AT-086a/AT-086b/AT-086c
- **US-087** → R-TUI-087 → LLR-087.1, LLR-087.2, LLR-087.3 → TC-087.1/.2/.3 + AT-087a/AT-087b
- **US-088** → R-TUI-088 → LLR-088.1..088.7 → TC-088.1..088.7 + AT-088a/AT-088b

### 5.2 By code file
- `s19_app/tui/services/flow_model.py` → LLR-085.1, LLR-086.1, LLR-087.1, LLR-088.4 (`image_ranges`) → M nodes
- `s19_app/tui/services/flow_execution_service.py` → LLR-085.2/.3, LLR-086.2/.3/.4/.5, LLR-087.2, LLR-088.4 (carrier populate) → E nodes
- `s19_app/tui/screens_directionb.py` → LLR-088.1/.2/.3/.4/.5/.6/.7, LLR-087.3 (banner sink) → R nodes
- `s19_app/tui/styles.tcss` → flow-scoped classes; colour flows through frozen `.sev-*` (0 diff to `color_policy.py`)

---

## 6. AMD-1 note — single ribbon now, twin → batch-52

LLR-088.4 was amended at Phase-3 Inc-2 (§6.5 **AMD-1**). The originally-specced **twin memory ribbon**
(a `before` row alongside the image row) was reduced to a **single memory ribbon**:

- **Reason:** in batch-51 no block grows the range set (the first range-growing block is CRC, which is
  batch-52). A `before` row would be **byte-identical** to the image row by construction — rendering two
  identical bars would misrepresent the image as unchanged-with-contrast. A single honest footprint
  ribbon satisfies R-TUI-088's "the working image's footprint" requirement.
- **What shipped:** one ribbon strip fed by the NEW additive `FlowRunResult.image_ranges` field
  (populated with the final `ranges` at the end of `run_flow`; empty when no image loaded). Geometry
  MEASURED in the mounted panel (48 cells clears the 80×24 content-width floor of 70 by 22 cols — no
  overflow), not inherited from the HTML prototype.
- **Deferred to batch-52 (CRC):** the `before_ranges` carrier and the twin (before-vs-after) row, where
  range growth makes the contrast meaningful (the operator's "watch it grow" signature). AT-088a's
  ribbon assertion accordingly checks "single image ribbon renders within the measured width, no
  overflow" rather than "twin rows".
- **Parent-HLR re-read (R-TUI-088):** no statement change — a single ribbon satisfies the footprint
  requirement. Operator-awareness flag recorded in §6.5; reversible.

---

## 7. Batch sign-off

| Field | Value |
|-------|-------|
| Batch ID | `2026-07-20-batch-51` |
| Closing date | 2026-07-20 |
| Total LLRs / ATs | 17 / 9 — all green |
| Validation passed | yes (Phase-4 verdict PASS; 1623 passed, 0 failed, 0 frozen diff, 0 snapshot drift) |
| Engine-frozen diffs | 0 (C-27 dual-guard) |
| Traceability gaps | none (G-1 is a non-blocking boundary-TC carry, not a traceability gap) |
| Synced to Obsidian | pending (`/dev-flow-sync` post-merge) |
