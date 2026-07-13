# Traceability Matrix — s19_app — Batch 2026-07-12-batch-38

> **Artifact language:** English (`state.json.language = en`).

> Two chains (Two-layer validation rule) — a story is complete only when BOTH exist:
> - **Functional (white-box):** User Story → HLR (R-TUI id) → LLR → `TC-NNN` → File:line.
> - **Behavioral (black-box):** User Story → `AT-NNN` → observed outcome through the shipped surface.
> Node names are byte-identical to `04-validation.md` §1/§2. Gate run consumed: **1377 passed / 2 skipped / 20 deselected / 5 xfailed / 0 failed (exit 0)**; every AT and TC reconciled to a distinct GREEN on-disk node.

---

## 1. Master table — functional chain (white-box)

| US | HLR (R-TUI) | LLR | TC | On-disk node (file::function:line) | Status | Notes |
|----|-------------|-----|-----|-------------------------------------|--------|-------|
| US-065 | HLR-065 (R-TUI-054) | LLR-065.1 | TC-332 | `tests/test_tui_directionb.py::test_tc332_change_doc_copy_pins_verbatim:7528` | pass | Section-title copy → `screens_directionb.py:1854` `"Change document (JSON)"` (drops `v2`) |
| US-065 | HLR-065 (R-TUI-054) | LLR-065.2 | TC-332 | `tests/test_tui_directionb.py::test_tc332_change_doc_copy_pins_verbatim:7528` | pass | Free-path placeholder copy → `screens_directionb.py:1904`; id `#patch_doc_path_input` preserved |
| US-066 | HLR-066 (R-TUI-055) | LLR-066.1 | TC-333 | `tests/test_validation_service_supplemental.py::test_tc_333_oversized_address_producer_emits_named_warning:652` | pass | Producer `supplemental_a2l_oversized_address_issues` → `validation_service.py:111`; code `A2L_ADDRESS_EXCEEDS_32BIT` `:179` |
| US-066 | HLR-066 (R-TUI-055) | LLR-066.2 | TC-334 | `tests/test_validation_service_supplemental.py::test_tc_334_oversized_warning_merges_in_both_branches_and_colours:672` | pass | Merge into MAC-only + primary-backed branches of `build_validation_report`; colour round-trips `css_class_for_severity` |
| US-066 | HLR-066 (R-TUI-055) | LLR-066.3 | TC-335 | `tests/test_validation_service_supplemental.py::test_tc_335_oversized_address_boundary_and_non_int:719` | pass | Boundary `0xFFFFFFFF` (no warn) / `0x100000000` (warn) / `None`/str (no warn); markup-safe via existing `issues_view.py` `safe_text` |
| US-067 | HLR-067 (R-TUI-056) | LLR-067.1 | TC-336 | `tests/test_tui_variants.py::test_tc336_tc337_help_message_pushes_modal_with_content:498` | pass | Info button `#patch_variant_info_button` → `screens_directionb.py:2098` (always rendered with the selector) |
| US-067 | HLR-067 (R-TUI-056) | LLR-067.2 | TC-337 | `tests/test_tui_variants.py::test_tc336_tc337_help_message_pushes_modal_with_content:498` | pass | Co-located node: real-click routing → `PatchEditorPanel.VariantHelpRequested` → app push |
| US-067 | HLR-067 (R-TUI-056) | LLR-067.3 | TC-337 | `tests/test_tui_variants.py::test_tc336_tc337_help_message_pushes_modal_with_content:498` | pass | Help-text tokens (content) — `VariantHelpScreen` → `screens.py:355` |
| US-068a | HLR-068a (R-TUI-057) | LLR-068a.1 | TC-338 | `tests/test_change_service.py::test_tc338_history_bounded_and_deep_copy_no_alias:657` | pass | Bounded deep-copy snapshotting, `_HISTORY_MAX=20` → `change_service.py:92`; no-alias asserted |
| US-068a | HLR-068a (R-TUI-057) | LLR-068a.2 | TC-339 | `tests/test_change_service.py::test_tc339_undo_redo_restore_semantics_and_empty_noop:692` | pass | `undo()` `:445` / `redo()` `:474` restore semantics + empty-stack no-op |
| US-068a | HLR-068a (R-TUI-057) | LLR-068a.3 | TC-340 | folded into `test_tc338_history_bounded_and_deep_copy_no_alias:657` + `test_tc339_undo_redo_restore_semantics_and_empty_noop:692` | pass | Button wiring exercised black-box by AT-068a; bound + empty no-op asserted inside TC-338/TC-339 (per §5.2 mapping) |
| US-068a | HLR-068a (R-TUI-057) | LLR-068a.4 | TC-344 | `tests/test_tui_patch_editor_v2.py::test_tc344_undo_redo_disabled_for_file_backed_document:3201` | pass | A-01 guard: Undo/Redo disabled iff `source_path is not None` (`set_undo_redo_enabled` → `screens_directionb.py:2607`) |
| US-068b | HLR-068b (R-TUI-058) | LLR-068b.1 | TC-341 | `tests/test_tui_patch_editor_v2.py::test_tc341_entry_seed_json_is_single_entry_scoped_to_index:3296` | pass | Distinct control `#patch_entry_edit_json_button` → `screens_directionb.py:1971`; selection-scoped |
| US-068b | HLR-068b (R-TUI-058) | LLR-068b.2 | TC-342 | `tests/test_tui_patch_editor_v2.py::test_tc342_edit_entry_json_mutates_only_the_selected_index:3325` | pass | `EntryJsonScreen` → `screens.py:255`, seeded with a single entry's JSON |
| US-068b | HLR-068b (R-TUI-058) | LLR-068b.3 | TC-343 | `tests/test_tui_patch_editor_v2.py::test_tc343_edit_entry_json_rejects_malformed_without_mutation:3356` | pass | `edit_entry_json` → `change_service.py:738` via validated `parse_change_document`; malformed → no mutation |
| US-068b | HLR-068b (R-TUI-058) | LLR-068b.4 | TC-345 | `tests/test_tui_patch_editor_v2.py::test_tc345_entry_edit_json_disabled_for_file_backed_document:3499` | pass | A-01 guard: per-entry control disabled iff `source_path is not None` (`set_entry_edit_json_enabled` → `screens_directionb.py:2633`) |

**No `fail` / `pending` rows. No incomplete row.**

## 1b. Behavioral chain (black-box)

> One AT per outcome, each observed through the shipped surface via Textual Pilot; C-18: one AT → exactly one on-disk node.

| US | Acceptance test (`AT-NNN`) | On-disk node (file::function:line) | Shipped surface | Observed outcome / deliverable | Status |
|----|----------------------------|-------------------------------------|-----------------|--------------------------------|--------|
| US-065 | AT-065a | `tests/test_tui_directionb.py::test_at065a_change_doc_label_reads_as_dropdown_alternative:7492` | `PatchEditorPanel` section title + `#patch_doc_path_input` placeholder | Rendered title `"Change document (JSON)"` + placeholder verbatim; `v2` absent from both | pass |
| US-066 | AT-066a | `tests/test_tui_a2l_issue_recolor.py::test_at_066a_oversized_a2l_address_warns_naming_tag:532` | `GroupedIssuesPanel` (WARNING group) | One `A2L_ADDRESS_EXCEEDS_32BIT` WARNING `IssueRow` naming tag `BIG_TAG`; sibling `0xFFFFFFFF` = no warning | pass |
| US-066 | AT-066b | `tests/test_tui_a2l_issue_recolor.py::test_at_066b_oversized_hostile_tag_name_renders_safely:446` | `GroupedIssuesPanel` rendered message | Markup brackets render verbatim, ANSI neutralized, 0 `MarkupError` (C-17) | pass |
| US-067 | AT-067a | `tests/test_tui_variants.py::test_at067a_variant_info_button_opens_help_modal:435` | info button + `VariantHelpScreen` modal | Real `pilot.click` → `app.screen` is `VariantHelpScreen`; body carries the 3 explanation tokens; dismiss returns to prior screen (C-16) | pass |
| US-068a | AT-068a | `tests/test_tui_patch_editor_v2.py::test_at068a_undo_redo_roundtrip_through_surface:3121` | Undo/Redo buttons → `#patch_doc_entries_table` | Real Undo/Redo clicks restore then re-apply entries byte/field-for-field; empty-history no-op (C-16; A-01 branch in TC-344) | pass |
| US-068b | AT-068b | `tests/test_tui_patch_editor_v2.py::test_at068b_per_entry_json_popup_edits_only_selected_entry:3396` | `#patch_entry_edit_json_button` → `EntryJsonScreen` → entries table | Single-entry-seed popup; Confirm edits only entry *i*, siblings byte-identical (C-16; A-01 branch in TC-345) | pass |

---

## 2. Coverage summary

| Metric | Value |
|--------|-------|
| Total user stories | 5 (US-065, US-066, US-067, US-068a, US-068b) |
| Covered user stories | 5 (100%) |
| Total HLR | 5 (R-TUI-054 … R-TUI-058) |
| Implemented HLR | 5 (100%) |
| Total LLR | 16 |
| Implemented LLR | 16 (100%) |
| Test cases (TC) | 14 (TC-332 … TC-345) |
| TC pass | 14 |
| TC fail | 0 |
| TC pending | 0 |
| Acceptance tests (AT) | 6 (AT-065a, 066a, 066b, 067a, 068a, 068b) |
| AT pass | 6 |

> **Node-count note (§5.2 mapping, mirrored from 04-validation §2):** TC-332 covers the LLR-065.1/.2 copy pair in one node; TC-337 is co-located with TC-336 in `test_tc336_tc337_…`; TC-340 (history bound + empty no-op) is asserted inside TC-338/TC-339 rather than a standalone node. Every LLR still retains ≥1 GREEN TC — this is a node-consolidation, not a coverage gap.

---

## 3. Detected gaps

**None.** Every US has a complete functional chain (HLR→LLR→TC→node) AND a behavioral row (AT→surface→outcome). 16/16 LLR covered by a GREEN TC; 5/5 US covered by a GREEN AT observing the outcome through the shipped surface with boundary + negative evidence. 0 engine-frozen SOURCE diffs + 0 engine-frozen TEST diffs vs `main`.

| ID | Type | Description | Proposed action |
|----|------|-------------|-----------------|
| — | — | No gaps | — |

**Non-gating carries (not coverage gaps):**
- Canonical-CI snapshot regen for the 2 `patch` xfail cells (`patch-comfortable-80x24` / `120x30`, `xfail(strict=False)`) — follow-up PR, #67/#69 precedent (C-22, canonical-CI only). Behavioral correctness of the UI change is proven GREEN by AT-065a/067a/068a/068b.
- L1: uncapped native paste on the new `#entry_json_text` TextArea — batch-39 hygiene carry (per 02-review security), not a batch-38 defect.

---

## 4. Changes from previous batch

| Type | Item | Detail |
|------|------|--------|
| new | HLR-065 (R-TUI-054) | Change-set free-path label clarity |
| new | HLR-066 (R-TUI-055) | Defensive WARNING `A2L_ADDRESS_EXCEEDS_32BIT` for A2L address > 0xFFFFFFFF |
| new | HLR-067 (R-TUI-056) | Variant-selector info/help popup |
| new | HLR-068a (R-TUI-057) | Patch-editor change-set undo/redo |
| new | HLR-068b (R-TUI-058) | Per-entry JSON edit popup |
| numbering | TC scheme | TC-001…TC-019 (Phase-1 draft) DELETED; adopted TC-332…TC-345 on the qa scheme (batch-37 ended at TC-331) |
| closed | B-16, B-17, B-18, B-19 | P3 backlog items shipped as US-065 / 066 / 067 / (068a+068b) |

---

## 5. Quick bidirectional mapping

### 5.1 By user story
- **US-065** → HLR-065 → LLR-065.1, LLR-065.2 → TC-332 · **AT-065a**
- **US-066** → HLR-066 → LLR-066.1, LLR-066.2, LLR-066.3 → TC-333, TC-334, TC-335 · **AT-066a, AT-066b**
- **US-067** → HLR-067 → LLR-067.1, LLR-067.2, LLR-067.3 → TC-336, TC-337 · **AT-067a**
- **US-068a** → HLR-068a → LLR-068a.1, LLR-068a.2, LLR-068a.3, LLR-068a.4 → TC-338, TC-339, TC-340(folded), TC-344 · **AT-068a**
- **US-068b** → HLR-068b → LLR-068b.1, LLR-068b.2, LLR-068b.3, LLR-068b.4 → TC-341, TC-342, TC-343, TC-345 · **AT-068b**

### 5.2 By code file (all NON-frozen)
- `s19_app/tui/screens_directionb.py` → LLR-065.1, LLR-065.2, LLR-067.1, LLR-067.2, LLR-068a.3, LLR-068a.4, LLR-068b.1, LLR-068b.4
- `s19_app/tui/services/validation_service.py` → LLR-066.1, LLR-066.2, LLR-066.3 (producer)
- `s19_app/tui/services/change_service.py` → LLR-068a.1, LLR-068a.2, LLR-068b.3
- `s19_app/tui/screens.py` → LLR-067.3 (`VariantHelpScreen`), LLR-068b.2 (`EntryJsonScreen`)
- `s19_app/tui/app.py` → LLR-067.2, LLR-068a.3, LLR-068a.4, LLR-068b.3, LLR-068b.4 (handlers + push)
- `s19_app/tui/issues_view.py` → LLR-066.3 render surface (reused, unchanged — `safe_text`)

---

## 6. Batch sign-off

| Field | Value |
|-------|-------|
| Batch ID | 2026-07-12-batch-38 |
| Closing date | 2026-07-12 |
| Total iterations (sum of phases) | 8 (`{0:1, 1:1, 2:2, 3:1, 4:1, 5:1, 6:0}`) |
| Validation passed | yes (gate PASS — 1377 passed / 0 failed / exit 0) |
| Synced to Obsidian | no (pending `/dev-flow-sync`) |
