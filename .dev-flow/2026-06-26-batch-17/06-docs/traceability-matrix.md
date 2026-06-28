# Traceability Matrix — s19_app — Batch 2026-06-26-batch-17

> **Artifact language:** English (batch development language).

> Two chains (per the Two-layer validation rule) — a story is complete only when BOTH exist:
> - **Functional (white-box):** User Story → HLR → LLR → `TC-NNN` → File:line.
> - **Behavioral (black-box):** User Story → `AT-NNN` → observed outcome through the shipped surface.
>
> All node names below are the **Phase-4-reconciled real names** (V-5: file paths, `-k` selectors, and node ids were provisional-until-Phase-3 and are reconciled here from the shipped tree). No provisional id appears as a live node.

> **Scope note:** US-020c (report-addendum input — declared memory locations) and US-020d (issues→report integration) were classified `OUT` at the Phase-0 DoR gate (net-new data model + unresolved semantics; deferred to their own batch with a design spike, logged in `.dev-flow/BACKLOG.md`). They are intentionally absent from this matrix.

---

## 1. Master table — functional chain (white-box)

| US | HLR | LLR | TC | File:line | Status | Notes |
|----|-----|-----|-----|-----------|--------|-------|
| US-018 | HLR-018 | LLR-018.1 | `test_tui_workspace_layout.py::test_ws_all_three_panes_stay_visible` | `s19_app/tui/styles.tcss:381` (`#hex_view { width: auto }`) | pass | Panes-visible guard (`#ws_right` within viewport). |
| US-018 | HLR-018 | LLR-018.1 | `test_tui_workspace_layout.py::test_ws_hex_one_line_holds_in_narrow_regime` | `s19_app/tui/styles.tcss:370` (`#hex_scroll { overflow: auto }`) | pass | Narrow (80-col) regime boundary: one line + scroll still holds. |
| US-019 | HLR-019 | LLR-019.1 (selector) | `test_tui_crc_surface.py::test_confirm_write_width_selector_cycles` (TC-019.2) | `s19_app/tui/screens.py:759` (cycle on `ConfirmWriteScreen`) | pass | Selector state machine 32↔16; default 32 before any cycle. |
| US-019 | HLR-019 | LLR-019.2 (threading) | `test_crc_operation.py::test_crc_write_emits_16_byte_records_when_selected` (TC-019.1) | `s19_app/tui/operations/crc.py:884` (`emit_s19_from_mem_map(..., bytes_per_line=)`) | pass | Non-default 16 path (C-10). |
| US-019 | HLR-019 | LLR-019.2 (threading) | `test_crc_operation.py::test_crc_write_emits_32_byte_records` | `s19_app/tui/operations/crc.py:796` (`bytes_per_line: int = 32` default) | pass | Default 32 lock, re-pointed (not deleted). |
| US-020a | HLR-020 | LLR-020.1 (pane present) | `test_tui_issues_view.py::test_at020a_issue_hex_pane_shows_bytes_and_clears_on_no_address` | `s19_app/tui/app.py:1128` (`_compose_screen_issues` → `#issues_hex_pane`) | pass | Single AT subsumes pane-present TC-020a.0. |
| US-020a | HLR-020 | LLR-020.2 (render at address) | `test_tui_issues_view.py::test_at020a_issue_hex_pane_shows_bytes_and_clears_on_no_address` | `s19_app/tui/app.py:4784` (`_update_issues_hex_pane`) | pass | Addressed → bytes; no-address → placeholder + cleared bytes. |
| US-020b | HLR-021 | LLR-021.1 (related cell) | `test_tui_issues_view.py::test_tc021_precompute_payload_emits_related_cell` (TC-021.1) | `s19_app/tui/app.py:509` (`related = ", ".join(...)`) | pass | Related cell emitted; `-` empty marker. |
| US-020b | HLR-021 | LLR-021.1 (column count) | `test_tui_app.py::test_precompute_issue_datatable_payload_emits_eight_columns_and_styles` | `s19_app/tui/app.py:475` (`precompute_issue_datatable_payload`) | pass | 8-tuple width == DataTable column count; styles index-aligned. |

## 1b. Behavioral chain (black-box)

> Per user story: the acceptance test that observes the outcome through the shipped surface. Every AT was shown RED under a counterfactual (non-vacuous), with boundary + negative evidence (Phase-4 `04-validation.md`).

| US | Acceptance test (`AT-NNN`) | Shipped surface | Observed outcome / deliverable | Status |
|----|----------------------------|-----------------|--------------------------------|--------|
| US-018 | `test_tui_workspace_layout.py::test_ws_hex_row_on_one_line_and_scrollable` (AT-018) | Workspace screen `#hex_view` / `#hex_scroll` inside `#ws_center` (Pilot `App.run_test(size=(120,30))`) | `#hex_view` content width ≥81 AND `#hex_scroll` virtual width ≥81 (full 16B+ASCII row on one line, horizontally scrollable); `#ws_right` within viewport | pass |
| US-019 | `test_tui_crc_surface.py::test_crc_write_honours_selected_16_width_through_confirm` (AT-019b) | Write CRC → `ConfirmWriteScreen` → `_on_confirm_write` → `_run_crc_write_worker` → `write_crc_image` (Pilot) | HANDLER-PRODUCED `.s19` under `.s19tool/workarea/crc/`, read back: data records 16 bytes wide (C-12: never a direct `write_crc_image(bytes_per_line=16)`) | pass |
| US-019 | `test_crc_operation.py::test_crc_write_emits_32_byte_records` (AT-019a) | Same CRC flow, no selection | Written `.s19` stays 32-byte default | pass |
| US-020a | `test_tui_issues_view.py::test_at020a_issue_hex_pane_shows_bytes_and_clears_on_no_address` (AT-020a) | Issues screen DataTable row-select (Pilot) through `on_data_table_row_selected` | `#issues_hex_pane` content: bytes at the selected issue's address; address-less issue → placeholder, not stale bytes | pass |
| US-020b | `test_tui_issues_view.py::test_at021_issues_list_shows_related_artifacts` (AT-021) | Issues DataTable `#validation_issues_list` cells (Pilot) | Related cell shows `a2l, mac` for an artifacts-bearing issue; `-` for a bare issue | pass |

---

## 2. Coverage summary

| Metric | Value |
|--------|-------|
| Total user stories (in scope) | 4 (US-018, US-019, US-020a, US-020b) |
| Covered user stories | 4 (100%) |
| Total HLR | 4 (HLR-018, HLR-019, HLR-020, HLR-021) |
| Implemented HLR | 4 (100%) |
| Total LLR | 6 (LLR-018.1, LLR-019.1, LLR-019.2, LLR-020.1, LLR-020.2, LLR-021.1) |
| Implemented LLR | 6/6 (100%) |
| Test cases (TC, white-box) | 6 distinct nodes |
| AT (black-box) | 5 (AT-018, AT-019a, AT-019b, AT-020a, AT-021) |
| TC pass | all |
| TC fail | 0 |
| TC pending | 0 |
| Orphans (either chain) | 0 |

> Both chains complete for every in-scope story; 0 orphans.

---

## 3. Detected gaps

| ID | Type | Description | Proposed action |
|----|------|-------------|-----------------|
| G-1 | process (snapshot) | SVG snapshot cells (`test_tc016s` workspace + issues density layouts) are CI-gated/skipped locally; US-018 (`#hex_view`) + US-020a/b (issues split + Related column) change those layouts → baselines likely need regeneration. | Regenerate baselines ONLY in the canonical CI env (never locally — memory `reference_snapshot_regen_env`); the PR's `tui-ci` is the authoritative check. Watch the PR CI. |

> No requirement-coverage gaps and no failing TCs. The single recorded gap is a process item (snapshot baseline regeneration).

---

## 4. Changes from previous batch

| Type | Item | Detail |
|------|------|--------|
| new | HLR-018 / LLR-018.1 | Workspace `#hex_view { width: auto }` so the full 16B+ASCII hex row stays on one line (horizontal scroll on narrow terminals). |
| new | HLR-019 / LLR-019.1, LLR-019.2 | Operator-selectable CRC record width (16/32, default 32) threaded to the emitter. |
| new | HLR-020 / LLR-020.1, LLR-020.2 | Issues-screen hex pane rendering the bytes at the selected issue's address (placeholder for address-less issues). |
| new | HLR-021 / LLR-021.1 | Related column on the issues list showing each issue's related artifacts. |
| modified | `test_crc_operation.py::test_crc_write_emits_32_byte_records` | Re-pointed (rewrite-in-place, net 0) as the AT-019a default-32 lock; not deleted. |
| modified | `test_tui_app.py::test_precompute_issue_datatable_payload_emits_eight_columns_and_styles` | Cell tuple widened 7→8 (Related column added); contract-touch identity check (tuple width 8 == column count 8). |
| amendment | A1 (Phase-2 M1) | LLR-019.1 carry mechanism: Option B (read-foreign-screen-state, INFEASIBLE) → Option C (`ConfirmWriteScreen` cycles its own width and dismisses with a width-bearing result). Shipped as `ConfirmWriteResult(confirmed, bytes_per_line)` (screens.py:672). |
| amendment | A2 (Phase-3 iterate-to-refine) | US-018 approach changed: rejected `#ws_center { min-width: 82 }` floor (pushed `#ws_right` off-screen — the likely cause of prior failed attempts) → `#hex_view { width: auto }` + existing `#hex_scroll { overflow: auto }` horizontal scroll. AT-018 re-observed on `#hex_view`/`#hex_scroll` content+virtual width. |
| deferred | US-020c, US-020d | OUT at DoR; own batch + design spike. Not in this matrix. |

---

## 5. Quick bidirectional mapping

### 5.1 By user story
- **US-018** → HLR-018 → LLR-018.1 → AT-018 + guard `test_ws_all_three_panes_stay_visible` + boundary `test_ws_hex_one_line_holds_in_narrow_regime`
- **US-019** → HLR-019 → LLR-019.1 (TC-019.2 selector), LLR-019.2 (TC-019.1 threading) → AT-019a (default 32) + AT-019b (selected 16)
- **US-020a** → HLR-020 → LLR-020.1 (pane), LLR-020.2 (render) → AT-020a
- **US-020b** → HLR-021 → LLR-021.1 → AT-021 + TC-021.1 + `test_precompute_issue_datatable_payload_emits_eight_columns_and_styles`

### 5.2 By code file
- `s19_app/tui/styles.tcss` → LLR-018.1 → AT-018 (+ guards)
- `s19_app/tui/screens.py` (`ConfirmWriteScreen`/`ConfirmWriteResult`/`_on_confirm_write`/`_run_crc_write_worker`) → LLR-019.1, LLR-019.2 → TC-019.2, AT-019b
- `s19_app/tui/operations/crc.py` (`write_crc_image`) → LLR-019.2 → TC-019.1, AT-019a/b
- `s19_app/tui/app.py` (`_compose_screen_issues`, `_update_issues_hex_pane`) → LLR-020.1, LLR-020.2 → AT-020a
- `s19_app/tui/app.py` (`precompute_issue_datatable_payload`) → LLR-021.1 → TC-021.1, AT-021, `test_precompute_..._eight_columns_and_styles`

---

## 6. Batch sign-off

| Field | Value |
|-------|-------|
| Batch ID | 2026-06-26-batch-17 |
| Closing date | 2026-06-27 |
| Total iterations (sum of phases) | Phase-1 reconciliation (1) + Phase-3 iterate-to-refine A2 (1) |
| Validation passed | yes (Phase 4: 4 HLR / 6 LLR / 4 US on both layers; 0 blocker fails; ledger 883 − 0 + 9 = 892) |
| Synced to Obsidian | no (pending PR merge → run /dev-flow-sync) |
