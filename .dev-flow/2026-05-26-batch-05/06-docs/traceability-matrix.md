# Traceability Matrix — s19_app — Batch 2026-05-26-batch-05

> Full chain: **User Story → HLR → LLR → Test Case → Test file/function → Validation status → R-\* living-requirement ID**.
> Every row is complete; there are **0 coverage gaps** (all 14 LLRs map to ≥1 passing TC).
> Validation status is taken verbatim from `04-validation.md` (Phase 4, `qa-reviewer`, HEAD `de0e742`, lean suite **772 passed / 0 failed**, 3 new suites **25 passed / 0 failed**).
> The batch-05 living-requirement IDs (`R-TUI-038/039/040`) are being appended to `REQUIREMENTS.md` by a parallel agent; this matrix references them so the batch artifact links to the living doc.

---

## 1. Master table

| US | HLR | LLR | TC | Test file → function | Status | R-* |
|----|-----|-----|-----|----------------------|--------|-----|
| US-001 | HLR-001 | LLR-001.1 | TC-001 | `tests/test_tui_search_pagination.py::test_main_hex_pagination_clears_search_anchor` | pass | R-TUI-038 |
| US-001 | HLR-001 | LLR-001.2 | TC-002 | `tests/test_tui_search_pagination.py::test_search_after_pagination_resumes_from_visible_address` | pass | R-TUI-038 |
| US-001 | HLR-001 | LLR-001.2 | TC-002b | `tests/test_tui_search_pagination.py::test_search_after_pagination_miss_round_trip` | pass | R-TUI-038 |
| US-001 | HLR-001 | LLR-001.2 | TC-002c | `tests/test_tui_search_pagination.py::test_search_empty_row_bases_fallback` | pass | R-TUI-038 |
| US-001 | HLR-001 | LLR-001.3 | TC-003 | `tests/test_tui_search_pagination.py::test_alt_tag_selection_clears_search_anchor` | pass | R-TUI-038 |
| US-001 | HLR-001 | LLR-001.4 | TC-003b | `tests/test_tui_search_pagination.py::test_mac_record_selection_clears_search_anchor` | pass | R-TUI-038 |
| US-002 | HLR-002 | LLR-002.1 | TC-004 | `tests/test_tui_mac_layout.py::test_mac_hex_pane_width_at_wide_terminal` | pass | R-TUI-039 |
| US-002 | HLR-002 | LLR-002.2 | TC-005 | `tests/test_tui_mac_layout.py::test_mac_hex_scroll_fills_pane_height` | pass | R-TUI-039 |
| US-002 | HLR-002 | LLR-002.3 | TC-006 | `tests/test_tui_mac_layout.py::test_mac_hex_pane_narrow_regime_unchanged` | pass | R-TUI-039 |
| US-002 | HLR-002 | LLR-002.4 | TC-013 | `tests/test_tui_mac_layout.py::test_mac_records_pane_positive_width_at_wide_terminal` | pass | R-TUI-039 |
| US-003 | HLR-003 | LLR-003.1 | TC-007 | `tests/test_tui_goto_marker.py::test_handle_goto_out_of_range_sets_status_and_does_not_move_view` | pass | R-TUI-040 |
| US-003 | HLR-003 | LLR-003.2 | TC-008 | `tests/test_tui_goto_marker.py::test_handle_goto_valid_hit_sets_focus_address` | pass | R-TUI-040 |
| US-003 | HLR-003 | LLR-003.3 | TC-009a | `tests/test_tui_goto_marker.py::test_render_hex_view_text_focus_row_marker_present_on_match` | pass | R-TUI-040 |
| US-003 | HLR-003 | LLR-003.3 | TC-009b | `tests/test_tui_goto_marker.py::test_render_hex_view_text_focus_row_marker_absent_when_unset` | pass | R-TUI-040 |
| US-003 | HLR-003 | LLR-003.4 | TC-010 (main) | `tests/test_tui_goto_marker.py::test_goto_focus_marker_forwarded_main` | pass | R-TUI-040 |
| US-003 | HLR-003 | LLR-003.4 | TC-010 (alt) | `tests/test_tui_goto_marker.py::test_goto_focus_marker_forwarded_alt` | pass | R-TUI-040 |
| US-003 | HLR-003 | LLR-003.4 | TC-010 (mac) | `tests/test_tui_goto_marker.py::test_goto_focus_marker_forwarded_mac` | pass | R-TUI-040 |
| US-003 | HLR-003 | LLR-003.5 | TC-011 (alt out-of-range) | `tests/test_tui_goto_marker.py::test_handle_goto_alt_out_of_range` | pass | R-TUI-040 |
| US-003 | HLR-003 | LLR-003.5 | TC-011 (alt focus) | `tests/test_tui_goto_marker.py::test_handle_goto_alt_focus` | pass | R-TUI-040 |
| US-003 | HLR-003 | LLR-003.5 | TC-011 (mac out-of-range) | `tests/test_tui_goto_marker.py::test_handle_goto_mac_out_of_range` | pass | R-TUI-040 |
| US-003 | HLR-003 | LLR-003.5 | TC-011 (mac focus) | `tests/test_tui_goto_marker.py::test_handle_goto_mac_focus` | pass | R-TUI-040 |
| US-003 | HLR-003 | LLR-003.6 | TC-012 (main) | `tests/test_tui_goto_marker.py::test_goto_focus_cleared_main_triggers` | pass | R-TUI-040 |
| US-003 | HLR-003 | LLR-003.6 | TC-012 (alt) | `tests/test_tui_goto_marker.py::test_goto_focus_cleared_alt_triggers` | pass | R-TUI-040 |
| US-003 | HLR-003 | LLR-003.6 | TC-012 (mac) | `tests/test_tui_goto_marker.py::test_goto_focus_cleared_mac_triggers` | pass | R-TUI-040 |
| US-003 | HLR-003 | LLR-003.6 | TC-012 (tab-switch control) | `tests/test_tui_goto_marker.py::test_goto_focus_not_cleared_on_tab_switch` | pass | R-TUI-040 |

---

## 2. Coverage summary

| Metric | Value |
|--------|-------|
| Total user stories | 3 (US-001, US-002, US-003) |
| Covered user stories | 3 (100%) |
| Total HLR | 3 |
| Implemented HLR | 3 (100%) |
| Total LLR | 14 |
| Implemented LLR | 14 (100%) |
| Distinct test cases (TC-IDs) | 13 logical TCs (TC-001, 002, 002b, 002c, 003, 003b, 004, 005, 006, 007, 008, 009a, 009b, 010, 011, 012, 013) |
| Test functions exercising them | 25 (6 search-pagination + 4 mac-layout + 15 goto-marker) |
| TC pass | 25 (100%) |
| TC fail | 0 |
| TC pending | 0 |

> The 25 new-suite test functions correspond to the §5.2 TC matrix: several TC-IDs fan out to more than one pytest function (LLR-001.2 → TC-002/002b/002c; LLR-003.3 → TC-009a/009b; LLR-003.4 → TC-010 ×3; LLR-003.5 → TC-011 ×4; LLR-003.6 → TC-012 ×4). All are green.

---

## 3. Detected gaps

> No incomplete rows, no requirement without a TC, no TC without a passing code mapping.

| ID | Type | Description | Proposed action |
|----|------|-------------|-----------------|
| — | — | **No gaps.** All 14 LLRs map to ≥1 passing TC. | — |

### 3.1 Non-gap items carried forward (informational, not coverage gaps)

These are explicitly out-of-scope decisions recorded in Phase 4 §5 and the Inc-3 packet — they do not break the chain above:

| Item | Status | Disposition |
|------|--------|-------------|
| `_jump_to_validation_issue_by_index` is not in the LLR-003.6 focus-clear trigger set | by design | Not enumerated by LLR-003.6; adding it would be scope creep. Phase-6 review may add a future LLR. |
| `render_hex_view` (the non-`Text` `str` variant) left untouched | by design | Off the goto path; adding the param would be unused speculative code. |
| Python 3.11 CI confirmation | outstanding | Local validation ran on 3.14.4 (version-independent behavior). Confirm the 3.11 CI job is green on the PR before merge. |

---

## 4. Changes from previous batch (batch-04 → batch-05)

| Type | Item | Detail |
|------|------|--------|
| new | HLR-001 / R-TUI-038 | Hex-search resumes from current page after pagination (US-001). |
| new | HLR-002 / R-TUI-039 | MAC hex pane shows a full hex row at ≥120 columns (US-002). |
| new | HLR-003 / R-TUI-040 | Goto gives explicit feedback + a non-color row marker (US-003). |
| new | LLR-001.1 .. 001.4, LLR-002.1 .. 002.4, LLR-003.1 .. 003.6 | 14 LLRs decomposed from the 3 HLRs. |
| modified | `tests/test_tui_directionb.py::test_tc021_mac_two_panes_fixed_regime` | Fixed-band assertion 38–42 → 80–84 to track the `#mac_hex_pane` 40→82 widening (Inc-2). |
| reconciled (Phase 6) | LLR-001.4 | Entry-point name `_on_mac_records_row_highlighted` → `_jump_to_mac_address` (wording only; behavior was always correct). |
| reconciled (Phase 6) | LLR-003.1 | `current_file.sorted_ranges` → `_get_range_index(self.current_file)` + `address_in_sorted_ranges(addr, range_index)`; `LoadedFile` has `ranges`, not `sorted_ranges`. |
| reconciled (Phase 6) | HLR-002 / LLR-002.2 / TC-005 | Literal `scroll.height == pane.height` → "scroll fills the remaining vertical space and is the tallest child of the pane" (structural invariant; pane stacks title + controls above the scroll). |

---

## 5. Quick bidirectional mapping

### 5.1 By user story
- **US-001** → HLR-001 → LLR-001.1, LLR-001.2, LLR-001.3, LLR-001.4 → TC-001, TC-002, TC-002b, TC-002c, TC-003, TC-003b → R-TUI-038
- **US-002** → HLR-002 → LLR-002.1, LLR-002.2, LLR-002.3, LLR-002.4 → TC-004, TC-005, TC-006, TC-013 → R-TUI-039
- **US-003** → HLR-003 → LLR-003.1, LLR-003.2, LLR-003.3, LLR-003.4, LLR-003.5, LLR-003.6 → TC-007, TC-008, TC-009a, TC-009b, TC-010, TC-011, TC-012 → R-TUI-040

### 5.2 By code file (production)
- `s19_app/tui/app.py` → LLR-001.1, 001.2, 001.3, 001.4 (`_first_visible_hex_address` @5861; anchor-clear in `action_hex_page_next/prev`, `_jump_to_tag_by_data`, `_handle_a2l_tag_find_next`, `_jump_to_mac_address` @3192; resume seed in `_handle_search`/`_handle_search_alt`/`_handle_search_mac`), LLR-003.1, 003.2, 003.4, 003.5, 003.6 (`_apply_goto` @5918; `_get_range_index` @3603 + `address_in_sorted_ranges`; `_handle_goto*`; `update_*_hex_view` forwarding; focus-clear triggers)
- `s19_app/tui/hexview.py` → LLR-003.3 (`render_hex_view_text` @324, keyword-only `focus_row_marker_address`)
- `s19_app/tui/styles.tcss` → LLR-002.1 (`#mac_hex_pane { width: 82 }`), LLR-002.2 (`#mac_hex_scroll { height: 100%; overflow: auto }`), LLR-002.3 (`width-narrow` selectors byte-identical), LLR-002.4 (records pane stays ≥1 cell)

### 5.3 By test file
- `tests/test_tui_search_pagination.py` (6) → LLR-001.1, 001.2, 001.3, 001.4
- `tests/test_tui_mac_layout.py` (4) → LLR-002.1, 002.2, 002.3, 002.4
- `tests/test_tui_goto_marker.py` (15) → LLR-003.1, 003.2, 003.3, 003.4, 003.5, 003.6
- `tests/test_tui_directionb.py::test_tc021_mac_two_panes_fixed_regime` (modified) → regression pin for LLR-002.1

---

## 6. Batch sign-off

| Field | Value |
|-------|-------|
| Batch ID | 2026-05-26-batch-05 |
| Closing date | 2026-05-28 |
| HEAD commit (validated) | `de0e742` |
| Total LLRs / covered | 14 / 14 (100%) |
| Total TCs / pass | 25 test functions / 25 pass (0 fail, 0 pending) |
| Validation verdict (Phase 4) | PASS-WITH-NOTES (3 doc-debt items, all reconciled in Phase 6) |
| Validation passed | yes |
| Living-requirement IDs | R-TUI-038, R-TUI-039, R-TUI-040 (appended to `REQUIREMENTS.md` by parallel agent) |
| Python (local validation) | 3.14.4 — version-independent behavior; **3.11 CI is the authoritative pre-merge gate** |
| Synced to Obsidian | no (pending dev-flow-sync after PR merge) |
