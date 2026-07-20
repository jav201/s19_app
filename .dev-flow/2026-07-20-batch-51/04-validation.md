# Phase-4 Validation — s19_app — batch-51 (Flow Builder: LOAD notices · CHECK block · status model · Direction-A render)

**Role:** qa-reviewer (Phase-4). **Method:** CONSUME the orchestrator-owned gate-suite run (C-25 — no full-suite re-run). Reconcile every LLR/AT/US to a REAL on-disk collected node, apply the two-layer rule + C-18 one-node realization + bidirectional surface-reachability.

## ✅ Verdict (read first)

- **Result:** **PASS**
- **Requirements:** 17/17 LLRs pass · 0 blocker fails
- **Black-box acceptance (Layer B):** ✓ all 9 ATs observe their outcome through the shipped surface (boundary + negative); AT-086c + AT-088b confirmed non-vacuous
- **Surface-reachability (bidirectional):** ✓ all named inputs AND outputs/deliverables reached/observed at the handler surface — 0 gaps
- **C-18 one-node realization:** ✓ all 9 ATs each map to EXACTLY ONE distinct node driving the whole named chain; 0 "satisfied in parts"
- **Name reconciliation (V-5):** ✓ `test_flow_execution_service.py` (new) + `test_flow_execution.py` (tracer) both kept/green, disjoint node sets, no orphan
- **Frozen guard (C-27):** ✓ 0 engine-frozen diffs; app.py untouched
- **Evidence checklist:** ✓ complete
- **One non-blocking gap (G-1):** empty/no-run render boundary-TC absent → Phase-3 follow-up TC recommended, does NOT force iterate.

**One line:** PASS — both layers green, all 9 ATs one-node-realized through the shipped surface, matrix bidirectionally complete, 0 engine-frozen diffs; no blocker.

---

## 0. Layer-A evidence consumed (C-25, orchestrator-owned gate suite)

`python -m pytest -q -m "not slow"` → **1623 passed, 2 skipped, 20 deselected, 3 xfailed, 0 failed** in 1184.66s. Snapshot report: **29 snapshots passed, 0 drift.** Exit 0. Base 1593 at batch-50 → **net +30**.

Node existence independently confirmed at Phase-4 via `pytest --collect-only` over the three new files + the pre-existing tracer guard: **34 nodes collected** (30 batch-51 + 4 tracer), all resolve on disk. Every PASS below inherits from that single gate-suite run — no node is asserted green without being a member of the 1623.

Frozen dual-guard (C-27): the increment gates recorded `git diff` over the 7 frozen paths empty; `test_engine_unchanged.py` + `test_tui_directionb.py::tc031` are inside the 1623. **0 engine-frozen diffs** — the only edited source files are `flow_model.py`, `flow_execution_service.py`, `screens_directionb.py`, `styles.tcss` (app.py untouched — the `render_result` call was unchanged).

---

## 1. Layer A — functional / white-box (every LLR → its TC → real node → PASS)

Provisional `-k`/node ids from §4/§5.2 reconciled to actual on-disk function names (V-5). File key: **M** = `tests/test_flow_model.py`, **E** = `tests/test_flow_execution_service.py`, **R** = `tests/test_flow_builder_render.py`.

| LLR | Spec provisional | On-disk node (reconciled) | File | Result |
|-----|------------------|---------------------------|------|--------|
| LLR-085.1 (Finding + `notices` token) | TC-085.1 | `test_tc085_1_finding_and_notices_token` | M | PASS |
| LLR-085.2 (parser errors → WARN notices, chain runs) | TC-085.2 | `test_tc085_2_zero_error_image_stays_ok` (boundary) + `test_tc085_3_findings_count_matches_load_errors` (1-per-error, image threaded) + `test_at085a_load_notices_downstream_runs` | E | PASS |
| LLR-085.3 (STOP / abort-asymmetry) | TC-085.3 `-k source_stop_skips_downstream` | `test_at085b_unresolvable_source_stops_and_skips` | E | PASS |
| LLR-086.1 (`CheckBlock` + gating vocab, frozen) | TC-086.1 | `test_tc086_1_check_block_and_gating_vocab` + `test_tc086_1_check_block_is_frozen` | M | PASS |
| LLR-086.2 (CHECK executes, report attached, image intact) | TC-086.2 | `test_tc086_2_check_reports_counts_image_intact` | E | PASS |
| LLR-086.3 (pass-through byte-equality) | TC-086.3 `-k check_passthrough_bytes` | `test_at086a_check_passthrough_bytes_identical` | E | PASS |
| LLR-086.4 (chain-never-blocked 4-case matrix) | TC-086.4 | `test_tc086_4_chain_never_blocked_matrix` + `test_tc086_6_check_body_exception_never_aborts_chain` (STRUCTURAL, widened-try) | E | PASS |
| LLR-086.5 (unreadable check-doc, non-aborting both modes) | TC-086.5 | `test_tc086_5_unreadable_check_doc_non_aborting` | E | PASS |
| LLR-087.1 (`completed-with-issues` token) | TC-087.1 | `test_tc087_1_flow_status_issues_token` | M | PASS |
| LLR-087.2 (three-way roll-up) | TC-087.2 `-k status_rollup` | `test_tc087_2_three_way_rollup` | E | PASS |
| LLR-087.3 (token carrier + banner, single sink) — *inspection* | TC-087.3 | carrier `FlowRunResult.status` observed by `test_at087a_issues_distinct_from_failed` (E); banner sink observed by `test_at085a_notices_load_shows_warning_gutter` + `test_at088a_pipeline_ledger_structure_all_three_banners` (R) | E+R | PASS |
| LLR-088.1 (status→`sev-*` map, outside frozen file) | TC-088.1 | `test_tc088_1_status_class_map_covers_every_status` | R | PASS |
| LLR-088.2 (vertical nodes, count derived) | TC-088.2 `-k vertical_nodes` | `test_at088a_pipeline_ledger_structure_all_three_banners` (`node_count==len(block_results)`) | R | PASS |
| LLR-088.3 (N−1 separators, no trailing) | TC-088.3 `-k separators` | `test_at088a_pipeline_ledger…` (N−1) + `test_at088a_single_block_has_no_dangling_separator` (0 for single) | R | PASS |
| LLR-088.4 (single ribbon, geometry measured) | TC-088.4 `-k ribbon` | `test_tc088_4_ribbon_encodes_footprint` + `test_ribbon_geometry_measured_no_overflow` (80×24 & 120×30, MEASURED not inherited) + engine carrier `test_tc088_image_ranges_carries_final_footprint` (E) | R+E | PASS |
| LLR-088.5 (banner text + `sev-*` class) | TC-088.5 `-k status_banner` | `test_at088a_pipeline_ledger…` (3 states: CLEAN/ISSUES/FAILED × sev-ok/warning/error) | R | PASS |
| LLR-088.6 (markup-safety per sink, C-17) | TC-088.6 `-k hostile_payload_literal` | `test_at088b_every_render_sink_renders_hostile_literally` + `test_at088b_check_ref_label_renders_literally` | R | PASS |
| LLR-088.7 (CHECK/LOAD dropdown + `_make_flow_block` + gating setter) | TC-088.7 `-k add_check_block` | `test_tc088_7_dropdown_offers_check_and_load_keeps_source_tag` + `test_at088_gating_selector_appends_block_own_op_check` + `test_flow_block_label_covers_check` | R | PASS |

**Layer A: 17/17 LLRs → ≥1 real on-disk TC, all inside the 1623-pass gate run. GREEN.** No LLR without a mapped node; no mapped node is a phantom (all collected).

---

## 2. Layer B — behavioral / black-box (every US → AT → real node, C-18 one-node realization)

**C-18 gate:** each §3 AT-NNN must map to EXACTLY ONE distinct on-disk node that drives the *whole named chain* through the shipped surface (`run_flow` handler and/or the real `#flow_run`/`#flow_add` buttons → `render_result`). "Shipped surface" per the task = the handler `run_flow` / `render_result`. Flag any AT satisfied only "in parts".

| AT (§3) | US | On-disk node driving the whole chain | Surface | In-parts? | Result |
|---------|----|--------------------------------------|---------|-----------|--------|
| AT-085a | US-085 | `test_at085a_load_notices_downstream_runs` — SOURCE `notices` + 1 WARN finding (C-9 message pinned) + downstream `ok` + file produced, all in one node | `run_flow` handler; **re-observed** visually via `#flow_run`→`render_result` by `test_at085a_notices_load_shows_warning_gutter` (sev-warning gutter + finding text + banner ISSUES) | No — each node drives the full chain at its surface depth | PASS |
| AT-085b | US-085 | `test_at085b_unresolvable_source_stops_and_skips` — SOURCE `error` + downstream `skipped` + `written_paths==[]` | `run_flow` handler; skipped→`sev-neutral` + FAILED banner also observed via render by `test_at088a` FAILED case | No | PASS |
| AT-086a | US-086 | `test_at086a_check_passthrough_bytes_identical` — byte-equal with/without CHECK + report present (passed=/failed=/uncheckable=) | `run_flow` → written file on disk | No | PASS |
| AT-086b | US-086 | `test_at086b_unreadable_check_doc_block_own_op_downstream_runs` — CHECK `error`, downstream WRITE-OUT still produces file | `run_flow` handler | No | PASS |
| **AT-086c** | US-086 | `test_at086c_gating_flag_drives_observable_status_change` — SAME unreadable doc under advisory (`notices`) vs block-own-op (`error`), asserts status **differs** + BOTH produce file | `run_flow` handler | No | PASS — **non-vacuous confirmed** |
| AT-087a | US-087 | `test_at087a_issues_distinct_from_failed` — output+advisories→`completed-with-issues` (file produced) vs broken→`error` (no file), asserts distinct | `run_flow` handler; banner observation by `test_at088a` ISSUES + `test_at085a` render | No | PASS |
| AT-087b | US-087 | `test_at087b_clean_run_is_ok` — fully clean→`ok` | `run_flow` handler; CLEAN banner by `test_at088a` | No | PASS |
| AT-088a | US-088 | `test_at088a_pipeline_ledger_structure_all_three_banners` — one node/block + N−1 seps + per-node `sev-*` + ribbon×1 + banner text/class, driven CLEAN/ISSUES/FAILED via the **real `#flow_run` button** | `#flow_run`→`run_flow`→`render_result` (Pilot) | No — single node covers the whole structure over 3 runs | PASS |
| **AT-088b** | US-088 | `test_at088b_every_render_sink_renders_hostile_literally` — 5 file-derived sinks, per-sink `plain` verbatim AND `spans==[]`, **3-layer AST completeness guard** (marker==tested, safe_text-calls==markers, no unwrapped file-derived `Static`) | `render_result` (Pilot); ref-label sink also swept by `test_at088b_check_ref_label_renders_literally` via `#flow_add` | No | PASS — **non-vacuous markup-sweep confirmed** |

**AT-086c non-vacuity (verified):** drives the identical unreadable-doc input under both real gating tokens (`CHECK_GATING_ADVISORY`/`CHECK_GATING_BLOCK_OWN` — no phantom `"block"`/`"blocked"`), asserts the CHECK status *differs* and both runs still write. A flag-ignoring impl shows the same status both times → RED (counterfactual recorded in Inc-1 code-review). This is the true C-10 observed-change form, not AT-086b's single-branch pin.

**AT-088b non-vacuity (verified):** beyond crash-only. Guard C is an AST walk asserting no `Static(...)` passes a file-derived value (`summary`/`message`/`diagnostics`/`path`/`diagnostic`) without `safe_text` — proven RED by injecting an unwrapped `Static(block_result.summary)` (Inc-2 F1), then restored. Per-sink `plain==payload` AND `spans==[]` across all 5 sinks — closes the batch-33/43/48 markup-sink-sweep miss.

**C-18 result: all 9 ATs each realized by EXACTLY ONE distinct node driving the whole named chain through the shipped surface. 0 "satisfied in parts". Layer B GREEN.**

---

## 3. Bidirectional surface-reachability matrix

Every named INPUT dimension and every named OUTPUT/deliverable is exercised/observed THROUGH the handler (`run_flow` / `render_result` / the real `#flow_run`/`#flow_add` buttons), not only via a service API.

### 3a. Inputs (block kinds, gating, notice-vs-STOP, run classes)

| Input dimension | Through `run_flow` handler | Through panel button (`render_result`) | Reachable? |
|-----------------|----------------------------|----------------------------------------|-----------|
| LOAD / SOURCE kind | all E tests | `test_at085a_notices…`, `test_at088a` (all cases) via `#flow_run` | ✓ |
| PATCH kind | tracer `test_run_flow_source_patch_writeout_happy_path` | `test_at088a` FAILED case (`PatchBlock("missing.json")`) via `#flow_run` | ✓ |
| CHECK kind | `test_at086a/b/c`, `test_tc086_*` | `test_at088a` ISSUES case + `test_at088_gating_selector` / `test_at088b_check_ref_label` via `#flow_add` | ✓ |
| WRITE-OUT kind | every E test (file produced) | every render run | ✓ |
| gating = advisory (default) | `test_at086c`, `test_tc086_4/5` | default path in `#flow_add` composition | ✓ |
| gating = block-own-op (non-default) | `test_at086b/c`, `test_tc086_4`, `test_tc087_2` | `test_at088_gating_selector_appends_block_own_op_check` via `#flow_gating` Select + `#flow_add`; `test_at088a` ISSUES | ✓ |
| integrity-notice (advisory WARN) | `test_at085a`, `test_tc085_3` | `test_at085a_notices_load_shows_warning_gutter` | ✓ |
| STOP (image broken → abort) | `test_at085b` (SOURCE) | FAILED/skipped rendering via `test_at088a` FAILED (PATCH-STOP) | ✓ |
| clean run | `test_at087b`, `test_tc085_2` | `test_at088a` CLEAN | ✓ |
| notices run | `test_at085a`, `test_at087a` | `test_at085a` render, `test_at088a` ISSUES | ✓ |
| error run | `test_at087a`, `test_tc087_2` | `test_at088a` FAILED | ✓ |

### 3b. Outputs / deliverables

| Output / deliverable | Observed through handler | Node(s) | Reachable? |
|----------------------|--------------------------|---------|-----------|
| Written file (WRITE-OUT on disk) | `run_flow().written_paths[…].exists()` / byte-equal | `test_at085a`, `test_at086a/b`, `test_tc086_4/5` | ✓ |
| `FlowRunResult.status == ok` | `run_flow` return | `test_at087b`, `test_at088a` fixture-sanity | ✓ |
| `…status == completed-with-issues` | `run_flow` return + banner "ISSUES" | `test_at087a`, `test_tc087_2`; banner `test_at088a`/`test_at085a` | ✓ |
| `…status == error` | `run_flow` return + banner "FAILED" | `test_at087a`, `test_tc087_2`; banner `test_at088a` | ✓ |
| Rendered nodes (one/block) | `render_result` Pilot query | `test_at088a` (`node_count==len(block_results)`) | ✓ |
| Banner (CLEAN/ISSUES/FAILED text+class) | `render_result` | `test_at088a` (3 states), `test_at085a` | ✓ |
| Memory ribbon (single strip) | `render_result` | `test_at088a` (count==1), `test_ribbon_geometry_measured_no_overflow`, `test_tc088_4` | ✓ |
| CHECK report counts (passed/failed/uncheckable) | `run_flow` summary + rendered summary sink | `test_at086a`, `test_tc086_2`; render `test_at088b` summary sink | ✓ |
| `FlowRunResult.image_ranges` footprint | `run_flow` return, consumed by ribbon | `test_tc088_image_ranges_carries_final_footprint`; consumed by ribbon render (`test_ribbon`/`test_at088a`) | ✓ |

**Matrix complete in BOTH directions — every input driven and every output observed through the shipped handler surface, not only a service API.**

---

## 4. Name reconciliation (Phase-4, V-5)

- **`tests/test_flow_execution_service.py` (NEW, 15 nodes)** vs **pre-existing `tests/test_flow_execution.py` (4 tracer guards: `…happy_path`, `…missing_source_isolates_and_writes_nothing`, `…path_escape_ref_is_blocked`, `…writeout_hex_and_s19_formats`)** — **both kept, both green** (all inside the 1623). Node-name sets are **disjoint** (batch-51 uses `test_at0*`/`test_tc0*`; the tracer uses `test_run_flow_*`). **No orphan, no duplicate, no shadowing.** The new file adds the run-engine LLR/AT coverage; the old file retains the batch-44 tracer isolation + path-escape security guards.
- Provisional `-k` selectors / node ids in §4/§5.2 all reconciled to real functions (tables §1/§2). Notable: `source_stop_skips_downstream`→`test_at085b_…`; `check_passthrough_bytes`→`test_at086a_…`; `load_integrity_notices`→`test_at085a_…`+`test_tc085_3`; `vertical_nodes`/`separators`/`ribbon`/`status_banner`→folded into `test_at088a_pipeline_ledger…`. No spec node id is left dangling.
- New public symbols consumed by tests all resolve on import/collect: `BLOCK_STATUS_NOTICES`, `FLOW_STATUS_ISSUES`, `Finding`, `FINDING_WARN`, `CheckBlock`, `CHECK_GATING_ADVISORY/_BLOCK_OWN`, `FlowRunResult.image_ranges`, `_BLOCK_STATUS_SEV_CLASS`, `_flow_block_label`, `_make_flow_block`, `_memory_ribbon_text`.

---

## 5. Test-count ledger

- Base (batch-50 close): **1593**. Post (this gate run): **1623** → **+30**.
- New batch-51 nodes collected: `test_flow_model.py` 4 + `test_flow_execution_service.py` 15 + `test_flow_builder_render.py` 11 = **30**. Plus 1 C-26 consumer reconciliation in `test_tui_directionb.py` (already counted in the suite baseline; frozen guards untouched). Reconciles: 1593 − 0 deleted + 30 added = 1623. ✓
- Pre-existing `test_flow_execution.py` (4 tracer guards) unchanged — retained, green.

---

## 6. Gaps

- **G-1 (NON-BLOCKING — boundary-TC, not an AT):** the §3 R-TUI-088 QC-3 boundary "empty (no blocks / no run yet → empty-state text, no crash — TC)" has **no dedicated render node**. `test_at088a_single_block_has_no_dangling_separator` covers the single-block boundary, but a **zero-block flow** / **pre-run empty-state** rendered through `render_result` is not directly exercised. This is a *boundary TC* in the catalog (mapped to "TC", not one of the 9 named ATs), so it does **not** fall under the two-layer blocker rule ("any AT not observed through the shipped surface"). All 9 ATs are observed. **Assessment: acceptable — recommend a Phase-3 follow-up TC** (`render_result` over `FlowRunResult(status=ok, block_results=[], image_ranges=[])` → asserts 0 nodes, 0 seps, empty-ribbon strip `""` per unit `test_tc088_4`, CLEAN/empty-state banner, no crash). Low risk: the empty-ribbon path is unit-proven (`_memory_ribbon_text([]).plain == ""`) and roll-up over no blocks is `ok` by LLR-087.2; the untested piece is only the mount-with-zero-children render. **Does NOT force iterate-to-fix (Phase 3) or iterate-to-refine (Phase 1).**

No other gaps. No AT unobserved through the shipped surface. No engine-frozen diff. No requirement without a mapped, collected, green node.

---

## 7. Evidence checklist (qa-reviewer)

- [✓] Acceptance criteria use Given/When/Then equivalent — §3 EARS + black-box AT observable-outcome blocks.
- [✓] TCs have explicit Expected — every node asserts concrete values (status tokens, byte-equality, counts, `spans==[]`); evidence = the 1623-pass gate run.
- [✓] Edge cases: empty (`test_tc085_2`, empty ribbon `test_tc088_4`), boundary (exactly-one-error `test_at085a`, single-block `test_at088a_single_block`, all-present `test_tc086_2`), invalid/error (`test_at085b`, `test_at086b`, `test_tc086_6`), gating-observable (`test_at086c`).
- [✓] Regression: frozen dual-guard (`test_engine_unchanged.py` + `tc031`) + full Inc-1 suite re-run at Inc-2 (0 regression) + C-26 consumer reconciliation — all inside the 1623.
- [✓] Exit criteria stated — §5.3 batch acceptance; met (0 fail, 0 frozen diff, 0 snapshot drift).
- [✓] No real PII / secrets — fixtures are synthetic S19 strings + a hostile literal payload; no client data.
- [✓] Results section — machine gate-run cited verbatim (§0), not hand-filled.
- [✓] **Layer B (black-box):** every output-producing story observed through the SHIPPED surface with boundary + negative evidence (§2 + §3).
- [✓] **Bidirectional surface-reachability:** §3 matrix — every input dimension AND every output/deliverable exercised through the handler.
- [✓] **No unfilled template:** all AT/TC ids reconciled to real on-disk nodes; no `<...>` / `TC-NNN` placeholder remains.

**FINAL: PASS. Advance to Phase 5 (post-mortem). One Phase-3 follow-up TC recommended (G-1, empty/no-run render) — non-blocking, log as a carry.**
