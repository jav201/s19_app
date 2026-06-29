# Functionality — s19_app — Batch 2026-06-29-batch-19

> Phase 6 artifact. Audience: technical stakeholder / maintainer. Feature #10 — issues-report addendum + issue enrichment.

## 🔑 At a glance
Two report improvements: (US-020d) the report's validation issues now show their **address, symbol, and related artifacts**, not just code/severity/message; and (US-020c) the operator can **declare named memory regions** that the report cross-references — listing, per region, the modifications and issues whose address falls inside it. Declared regions can persist in the project manifest.

## Operator walkthrough

### Richer issues in the report (US-020d)
- Generate a report as before. Each issue line in **Declaration errors** now appends `@ 0x<addr>`, `symbol=<sym>`, and `related=<a,b>` whenever the issue carries them (nothing extra shown when it doesn't).

### Declared-region addendum (US-020c)
- Open **Reports** (`t`), and in the report dialog use the **"Declared regions (name,start,end per line)"** input. Type one region per line, e.g.:
  ```
  cal_map,0x80040000,0x800400FF
  bootloader,0x0,0x3FFF
  ```
  `start`/`end` accept hex (`0x…`) or decimal. Blank/malformed lines are skipped.
- Press **Generate new report**. The report gains an **"Addendum: declared regions"** section: each region (inclusive `[start,end]`) lists the modifications and validation issues whose address falls inside it, across all variants; a region with nothing inside shows **"None."**.
- The region **name is sanitized** (control chars / ANSI stripped, length-capped) so it can't corrupt the report you forward to a client.

### Persistence (US-020c, service layer)
- Declared regions can be saved into `project.json` (an optional `declared_regions` array) and reloaded by the manifest reader. *Note:* this batch ships the persistence **mechanism**; auto-saving the dialog's regions on project-save and pre-filling them on load is a deliberate **follow-on** (BACKLOG), so today regions are entered per report-generation.

## Maintainer seams

| Concern | Where | Notes |
|---------|-------|-------|
| **Declared-region model** | `report_addendum.py::DeclaredRegion` (`:30`) | `(name,start,end)`, inclusive `[start,end]` (NOT half-open like `CrcRegion`); name scrubbed+capped via `_scrub_issue_message` at construction (security-F1, single source). |
| **Report addendum render** | `report_service.py::_addendum_lines` (`:977`), gated by `ReportOptions.declared_regions` (`:198`) | aggregates across variants; reads modification `address_start` + `ValidationIssue.address` — the SAME address the issue renderer reads (anti-drift, TC-S3). |
| **Issue enrichment** | `report_service.py::_declaration_error_lines` (~`:712`) | appends the optional fields only when present; `address==0` → `@ 0x0`. |
| **Dialog input** | `screens.py::_parse_declared_regions` (`:543`) + `ReportViewerScreen` TextArea; `GenerateRequested.declared_regions` (`:652`) | `int(x,0)` hex/dec; malformed lines skip-don't-abort. C-13 measured (fits 80 & 120). |
| **Threading** | `app.py` `GenerateRequested → _trigger_generate_report → _start_generate_report_worker → ReportOptions` | 4 hops, all default `()` (back-compat). |
| **Persistence** | `manifest_writer.py::serialize_manifest`/`write_project_manifest` (optional key when non-empty) + `variant_execution_service.py::_parse_manifest_declared_regions` (`:295`) → `ProjectManifest.declared_regions` (`:201`) | additive key, no `schema_version` bump; absent→empty, malformed→`ValidationIssue` (collect-don't-abort); read-path re-scrubs the name. |

## Validation
Full non-slow suite 926 passed / 0 failed; 0 engine-frozen edits (`ValidationIssue`/`_scrub_issue_message` read-only). No SVG snapshot regen (report dialog not in the matrix). C-13 measured PASS (no fallback).
