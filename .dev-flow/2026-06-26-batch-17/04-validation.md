# Validation — s19_app — Batch 2026-06-26-batch-17

> Phase 4 artifact. Two-layer validation (Layer A white-box `TC` + Layer B black-box `AT`), bidirectional surface-reachability, V-5 id reconciliation, signed-balance test ledger. Most evidence was produced inline during Phase 3 (per-increment counterfactual REDs + independent `code-reviewer` + full-suite greens); this consolidates it.

## ✅ Verdict (read first)

- **Result:** **PASS** — 4 HLR / 7 LLR / 4 US all covered on BOTH layers; 0 blocker fails.
- **Requirements:** 4/4 stories pass · 0 blocker fails · 0 defects.
- **Black-box acceptance (Layer B):** ✓ every story's `AT` observes its outcome through the SHIPPED surface, each shown RED under a counterfactual (non-vacuous), with boundary + negative evidence.
- **Surface-reachability (bidirectional):** ✓ all named inputs (width selection, issue-row selection) AND outputs (written `.s19` record width, hex-pane content, Related cell) reached/observed at the surface.
- **Supersession inspection:** ✓ no live dependency on a removed approach (the rejected `#ws_center min-width:82` was never committed; the fixed-32 CRC lock re-pointed, not orphaned).
- **Test ledger:** ✓ reconciles — `883 − 0 + 9 = 892`.
- **Engine-frozen:** ✓ 0 edits to the frozen set; `io.py` not edited (kwarg pre-existed).
- **Evidence checklist (qa):** ✓ complete.

---

## Detail (reference)

### Layer A — functional (white-box): per-requirement results

| Req | Method | Real test node (V-5) | Result |
|-----|--------|----------------------|--------|
| LLR-018.1 | test (integration) | `test_tui_workspace_layout.py::test_ws_all_three_panes_stay_visible` + `::test_ws_hex_one_line_holds_in_narrow_regime` | pass |
| LLR-019.1 (selector) | test (integration) | `test_tui_crc_surface.py::test_confirm_write_width_selector_cycles` (TC-019.2) | pass |
| LLR-019.2 (threading) | test (unit) | `test_crc_operation.py::test_crc_write_emits_16_byte_records_when_selected` (TC-019.1) + `::test_crc_write_emits_32_byte_records` (default) | pass |
| LLR-020.1/.2 | test (integration) | `test_tui_issues_view.py::test_at020a_issue_hex_pane_shows_bytes_and_clears_on_no_address` (pane present + render, subsumes TC-020a.1) | pass |
| LLR-021.1 | test (unit) | `test_tui_issues_view.py::test_tc021_precompute_payload_emits_related_cell` (TC-021.1) + `test_tui_app.py::test_precompute_issue_datatable_payload_emits_eight_columns_and_styles` | pass |

### Layer B — behavioral (black-box) acceptance

| US | AT (real node) | Surface driven | Deliverable observed | repr·bound·neg | Result |
|----|----------------|----------------|----------------------|----------------|--------|
| US-018 | `test_ws_hex_row_on_one_line_and_scrollable` | Workspace screen (Pilot) | `#hex_view` content width ≥81 + `#hex_scroll` virtual ≥81 (one line, scrollable) | ✓·✓·✓ | pass |
| US-019 | `test_crc_write_honours_selected_16_width_through_confirm` (AT-019b) + `test_crc_write_emits_32_byte_records` (AT-019a) | Write CRC → ConfirmWriteScreen → worker | written `.s19` record width (16 selected / 32 default) | ✓·✓·✓ | pass |
| US-020a | `test_at020a_issue_hex_pane_shows_bytes_and_clears_on_no_address` | Issues screen DataTable row-select (Pilot) | `#issues_hex_pane` content (bytes / placeholder) | ✓·✓·✓ | pass |
| US-020b | `test_at021_issues_list_shows_related_artifacts` | Issues DataTable cells (Pilot) | row Related cell (`a2l, mac` / `-`) | ✓·✓·✓ | pass |

### Counterfactual / escaped-bug evidence (QC-2: value-discriminating)

| AT | Pre-fix run (RED evidence) | Pre-fix RED kind | Post-fix value-discriminating? (QC-2) | Post-fix |
|----|---------------------------|------------------|----------------------------------------|----------|
| AT-018 | remove `#hex_view {width:auto}` → `#hex_view` width 28 (wrapped) < 81 | value | yes — asserts ≥81 content + ≥81 virtual (a clipped 28 fails on value) | pass |
| AT-019b | worker hardcoded `bytes_per_line=32` → `widths=[32,8,4]` | value | yes — `16 in widths`, `32 not in widths`, `max==16` (16 vs 32 value) | pass |
| AT-020a | remove `_update_issues_hex_pane` call → `pane=''` | presence (empty) | yes — post-fix asserts the `0x00001000` row + bytes `AB`/`CD` (specific values), not mere non-empty | pass |
| AT-021 | `related="-"` (ignore field) → Related cell `-` not `a2l, mac` | value | yes — asserts exact `a2l, mac` at column index 3, and `-` for the bare issue | pass |

### Bidirectional surface-reachability matrix

| Direction | Dimension / deliverable | Reached/observed at surface? | Node |
|-----------|-------------------------|------------------------------|------|
| input | CRC record-width selection (16) | yes — cycled on ConfirmWriteScreen | AT-019b |
| output | written `.s19` record width | yes — read back off disk | AT-019b / TC-019.1 |
| input | issue-row selection (addressed / no-address) | yes — DataTable cursor+Enter | AT-020a |
| output | `#issues_hex_pane` bytes / placeholder | yes — pane `.render()` | AT-020a |
| output | issues Related cell | yes — `get_row_at(...)[3]` | AT-021 |
| output | workspace hex row one-line + scroll | yes — `#hex_view`/`#hex_scroll` geometry | AT-018 |

### Signed-balance test ledger

| base | − D | + A | = post | actual collected (non-slow passed) | reconciles? |
|------|-----|-----|--------|------------------------------------|-------------|
| 883 | 0 | 9 | 892 | 892 | yes |

> +9 = US-018 ×3, US-019 ×3 (TC-019.1, TC-019.2, AT-019b), US-020a ×1, US-020b ×2 (AT-021, TC-021.1). Re-pointed/renamed nodes (`test_crc_write_emits_32_byte_records`, `..._emits_eight_columns_and_styles`) are rewrites-in-place (net 0), not D/A.

### Gaps detected

| ID | Gap | Severity | Action |
|----|-----|----------|--------|
| G-1 | SVG snapshot cells (`test_tc016s` workspace + issues density layouts) are CI-gated/skipped locally; US-018 (`#hex_view`) + US-020a/b (issues `#issues_columns` split + Related column) change those layouts → baselines likely need regeneration. | minor (process) | The PR's `tui-ci` is the authoritative check; regenerate baselines ONLY in the canonical CI env (never locally — memory `reference_snapshot_regen_env`). Watch the PR CI. |

### Evidence checklist (qa)
- [x] Both layers executed; every LLR has a TC node, every US an AT node, all on disk + GREEN.
- [x] Every AT drives the shipped surface (Pilot / on-disk artifact), references no internal symbol in assertions.
- [x] Every AT shown RED under a counterfactual (non-vacuous); QC-2 value-discrimination confirmed per AT.
- [x] Bidirectional reachability: inputs AND outputs observed at the surface.
- [x] Test ledger reconciles (883→892).
- [x] 0 engine-frozen edits; full non-slow suite 892 passed / 0 failed; ruff clean.
- [x] One process gap (G-1 snapshot CI) recorded, not hidden.
