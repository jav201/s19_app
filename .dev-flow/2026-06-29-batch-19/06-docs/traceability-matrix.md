# Traceability Matrix — s19_app — Batch 2026-06-29-batch-19

> Dual chains (Two-layer rule): functional US→HLR→LLR→`TC`→file:line, behavioral US→`AT`→outcome. All ids reconciled to real on-disk nodes (V-5). Feature #10 — issues-report addendum + issue enrichment.

## 1. Functional chain (white-box)

| US | HLR | LLR | TC (real node) | File:line | Status |
|----|-----|-----|----------------|-----------|--------|
| US-020d | HLR-025 | LLR-025.1 (issue enrichment) | `test_report_service.py::test_report_issue_line_shows_address_symbol_related`, `::test_report_issue_address_zero_renders` | `report_service.py::_declaration_error_lines` (~:712) | pass |
| US-020c | HLR-024 | LLR-024.1 (`DeclaredRegion`) | `test_report_addendum.py` ×5 (membership / bad-bounds / empty-name / scrub / cap) | `report_addendum.py::DeclaredRegion:30` | pass |
| US-020c | HLR-024 | LLR-024.2 (`_addendum_lines`) | `test_report_service.py::test_addendum_lists_region_with_mods_and_issues`, `::test_addendum_membership_inclusive_at_bounds` | `report_service.py::_addendum_lines:977`, `ReportOptions.declared_regions:198` | pass |
| US-020c | HLR-024 | LLR-024.3 (dialog input) | `test_tui_report_seam.py::test_parse_declared_regions_handles_hex_dec_and_skips_malformed`, `::test_report_dialog_with_region_input_fits_80_and_120_cols` | `screens.py::_parse_declared_regions:543`, `GenerateRequested.declared_regions:652`; `app.py` 4-hop → `ReportOptions` build | pass |
| US-020c | HLR-026 | LLR-026.1 (persistence) | `test_manifest_writer.py::test_serialize_omits_declared_regions_key_when_empty`, `::test_read_absent_key_empty_and_malformed_collected` | `manifest_writer.py::serialize_manifest`, `variant_execution_service.py::_parse_manifest_declared_regions:295` + `ProjectManifest.declared_regions:201` | pass |
| (shared) | HLR-024/025 | single-source | `test_report_service.py::test_addendum_and_issue_render_use_same_address` (TC-S3) | `_addendum_lines` ↔ `_declaration_error_lines` (both read `ValidationIssue.address`) | pass |

## 1b. Behavioral chain (black-box)

| US | Acceptance test (real node) | Shipped surface | Observed outcome | Status |
|----|-----------------------------|-----------------|------------------|--------|
| US-020d | `test_report_issue_line_shows_address_symbol_related` (AT-025a) | `generate_project_report` → report file | issue line shows address/symbol/related | pass |
| US-020d | `test_report_issue_without_address_has_no_hex` (AT-025b, negative) | same | no `@0x` when no address | pass |
| US-020c | `test_addendum_lists_region_with_mods_and_issues` (AT-024a) | `generate_project_report` → report file | addendum lists region + mods/issues inside | pass |
| US-020c | `test_addendum_region_with_no_hits_shows_none` (AT-024b, boundary) | same | "None." for a zero-hit region | pass |
| US-020c | `test_declared_region_in_dialog_reaches_report_addendum` (AT-024c) | `ReportViewerScreen` → produced report file | typed region in the addendum (C-12) | pass |
| US-020c | `test_declared_regions_roundtrip_and_on_disk` (AT-026a) | `serialize/write_project_manifest` → `project.json`; `read_project_manifest` | on-disk project.json carries regions + read returns them (qa-F4) | pass |

## 2. Coverage summary
| Metric | Value |
|--------|-------|
| User stories | 2 / 2 (100%) |
| HLR | 3 / 3 (100%) |
| LLR | 5 / 5 (100%) |
| AT | 6 pass / 0 fail |
| TC | 12 pass / 0 fail (TC-024.3 ×5, TC-024.4/.5/.6, TC-025.1, TC-026.1/.2, TC-S3) |
| Orphans | 0 |

## 3. Detected gaps
| ID | Type | Description | Action |
|----|------|-------------|--------|
| G-1 | lint (pre-existing) | unused `import pytest` in test_manifest_writer.py (on main) | separate sweep |
| D-1 | deferred feature | UI auto-wire regions↔manifest (HLR-026 follow-on) | BACKLOG |
| D-2 | deferred UX | malformed-line on-screen feedback (Inc3) | BACKLOG |

## 4. Changes from previous batch
| Type | Item | Detail |
|------|------|--------|
| new | `report_addendum.py` (`DeclaredRegion`) | model + name scrub |
| new | `_addendum_lines`, `_parse_declared_regions`, `_parse_manifest_declared_regions` | render / dialog parse / manifest parse |
| modified | `report_service.py` / `screens.py` / `app.py` / `manifest_writer.py` / `variant_execution_service.py` / `styles.tcss` | enrichment, dialog input, threading, persistence |
| reflected | §6.4 Phase-2 folds | security-F1 scrub, architect-M1 inclusive bounds, contract-touch |

## 5. Quick mapping
- **US-020d** → HLR-025 → LLR-025.1 → AT-025a/b, TC-025.1
- **US-020c** → HLR-024 (LLR-024.1/.2/.3) + HLR-026 (LLR-026.1) → AT-024a/b/c + AT-026a, TC-024.3–.6 / TC-026.1/.2 + TC-S3

## 6. Batch sign-off
| Field | Value |
|-------|-------|
| Batch ID | `2026-06-29-batch-19` |
| Closing date | 2026-06-29 (pending commit/PR + sync) |
| Validation passed | yes (Phase 4 PASS) |
| Synced to Obsidian | no (pending PR merge) |
