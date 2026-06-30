# Traceability Matrix — s19_app — Batch 2026-06-29-batch-20

> **Artifact language:** English (development language for this batch).
>
> Two chains (per the Two-layer validation rule) — a story is complete only when BOTH exist:
> - **Functional (white-box):** User Story → HLR → LLR → `TC-NNN` → File:line.
> - **Behavioral (black-box):** User Story → `AT-NNN` → observed outcome through the shipped surface.
>
> Scope: feature #10 follow-on D-1/D-2 — wire the batch-19 declared-region **serialization layer** to the UI. D-1 = round-trip declared regions through the Reports dialog → project SAVE → project.json → project LOAD → dialog pre-fill. D-2 = surface a count-only skip notice for malformed/invalid region lines. The batch-19 manifest reader/writer and `DeclaredRegion` model are consumed **read-only** (frozen-engine diff = 0).
>
> All nodes below are the **real on-disk test names** in `tests/test_tui_report_seam.py`. Every node PASS. Zero gaps, zero orphans.

---

## 1. Master table — functional chain (white-box)

| US | HLR | LLR | TC | File:line | Status | Notes |
|----|-----|-----|-----|-----------|--------|-------|
| US-024 | HLR-027 | LLR-027.1 | TC-027.1 (`test_save_threads_declared_regions_to_writer`) | `s19_app/tui/app.py:3791` (`_handle_save_dialog`) → `:3802` / `:3867` (`_write_and_verify_manifest` → `write_project_manifest(declared_regions=)`) | pass | Save threads captured state to writer; verify leg deliberately NOT threaded. |
| US-024 | HLR-027 | LLR-027.2 | TC-027.1 (`test_save_threads_declared_regions_to_writer`) | `s19_app/tui/app.py:713` (init) · `:1899`/`:1908` (`GenerateRequested` handler captures into `self._declared_regions`) | pass | Capture-on-Generate; typed-but-not-generated is not state. |
| US-024 | HLR-027 | LLR-027.3 | TC-027.2 (`test_write_and_verify_manifest_accepts_declared_regions_default`) | `s19_app/tui/app.py:3867` (`write_project_manifest(declared_regions=)` default param) | pass | Save path accepts the new kwarg without breaking the no-region default. |
| US-024 | HLR-027 | LLR-027.4 | TC-027.3 (`test_empty_regions_omits_key`) | reused `manifest_writer.serialize_manifest` (key omitted when empty) | pass | Back-compat: empty ⇒ `declared_regions` key absent. |
| US-024 | HLR-028 | LLR-028.1 | TC-028.1 (`test_load_sets_declared_regions_state`) | `s19_app/tui/app.py:3977` (`_handle_load_project`: adopt `manifest.declared_regions`, `else ()` reset) | pass | Load seeds app state; `else ()` prevents cross-load leak. |
| US-024 | HLR-028 | LLR-028.2 | TC-028.2 (`test_seed_format_is_parser_inverse`) | `s19_app/tui/screens.py:691`–`698`/`703`–`708` (`ReportViewerScreen.compose` seeds `#report_declared_regions` TextArea) · `:667`/`:676` (`__init__` accepts regions) | pass | Dialog pre-fills from app state; seed format is the inverse of `_parse_declared_regions`. |
| US-024 | HLR-028 | LLR-028.3 | TC-028.2 (`test_seed_format_is_parser_inverse`) | `s19_app/tui/app.py:1874` (`action_view_reports` passes `declared_regions=self._declared_regions`) | pass | App→screen hand-off of the seed. |
| US-025 | HLR-029 | LLR-029.1 | TC-029.1 (`test_parse_returns_skip_count`) | `s19_app/tui/screens.py:543` (`_parse_declared_regions` returns `(regions, skipped)`; 2 mutually-exclusive count sites; blank excluded) | pass | Count is malformed (field count) XOR invalid (parse/ctor) per line. |
| US-025 | HLR-029 | LLR-029.2 | TC-029.2 (`test_zero_skip_suppresses_notify`) | `s19_app/tui/screens.py:807`–`813` (`on_button_pressed`: `if skipped >= 1: notify(...)`) | pass | Zero skips ⇒ no toast (no noise on clean input). |
| US-025 | HLR-029 | LLR-029.3 | TC-029.2 (`test_zero_skip_suppresses_notify`) | `s19_app/tui/screens.py:810`–`813` (count-only `self.notify(f"{skipped} region line(s) skipped")`, no line text) | pass | Count-only message; offending line text never interpolated (pre-scrub leak guard). |
| US-025 | HLR-029 | LLR-029.1 | TC-024.5 (`test_parse_declared_regions_handles_hex_dec_and_skips_malformed`, batch-19 TC rewritten) | `s19_app/tui/screens.py:543` (`_parse_declared_regions` hex/dec accept + malformed skip) | pass | Batch-19 TC rewritten for the new `(regions, skipped)` return shape. |

## 1b. Behavioral chain (black-box)

> Per user story: the acceptance test that observes the outcome through the shipped surface. All in `tests/test_tui_report_seam.py`.

| US | Acceptance test (`AT-NNN`) | Shipped surface | Observed outcome / deliverable | Status |
|----|----------------------------|-----------------|--------------------------------|--------|
| US-024 | AT-027a (`test_save_persists_declared_regions`) | Reports dialog → project SAVE → `project.json` | Generated-then-saved regions appear in the on-disk `project.json` `declared_regions` array | pass |
| US-024 | AT-027b (`test_typed_but_not_generated_not_saved`) | Reports dialog → project SAVE | A region typed but never Generated is NOT persisted (capture-on-Generate) | pass |
| US-024 | AT-027c (`test_save_without_regions_byte_identical`) | project SAVE | A save with no regions produces a byte-identical `project.json` (key omitted, back-compat) | pass |
| US-024 | **AT-028a — C-12 through-surface GATE** (`test_load_prefills_declared_regions`) | project LOAD → reopen Reports dialog | Regions written by SAVE are observed back through the dialog TextArea on the next LOAD — full round-trip over the shipped seam, not a same-values direct write | pass |
| US-024 | **AT-028b — consumer guard** (`test_load_seed_guard`) | project LOAD (legacy / no-key project) | A no-key project loads with empty regions and no leak of a prior project's regions into the dialog | pass |
| US-025 | AT-029a (`test_skipped_malformed_line_counted`) | Reports dialog → Generate | A malformed line (wrong field count) raises the skip count surfaced to the operator | pass |
| US-025 | AT-029b (`test_skipped_invalid_line_counted`) | Reports dialog → Generate | An invalid line (bad int / failed `DeclaredRegion`) raises the skip count | pass |
| US-025 | AT-029c (`test_skipped_count_excludes_blank`) | Reports dialog → Generate | Blank / whitespace-only lines are excluded from the skip count (intentional spacing) | pass |
| US-025 | AT-029d (`test_all_valid_no_skip_message`) | Reports dialog → Generate | All-valid input emits no skip notice | pass |

---

## 2. Coverage summary

| Metric | Value |
|--------|-------|
| Total user stories | 2 (US-024, US-025) |
| Covered user stories | 2 (100%) |
| Total HLR | 3 (HLR-027, HLR-028, HLR-029) |
| Implemented HLR | 3 (100%) |
| Total LLR | 10 |
| Implemented LLR | 10 (100%) |
| Test cases (TC) | 7 functional + 1 rewritten batch-19 TC (TC-024.5) |
| Acceptance tests (AT) | 9 behavioral |
| TC pass | 8 |
| TC fail | 0 |
| TC pending | 0 |
| AT pass | 9 |
| AT fail | 0 |
| Test ledger | 958 → 974 (+16); full non-slow run 942 passed / 0 failed |
| Frozen-engine diff | 0 |

---

## 3. Detected gaps

> None. Every functional row has a complete US → HLR → LLR → TC chain and every story has a behavioral AT row. No requirement is without a TC; no TC is without a code mapping.

| ID | Type | Description | Proposed action |
|----|------|-------------|-----------------|
| — | — | No gaps. | — |

Out-of-scope (explicitly deferred to BACKLOG, not gaps):
- Comma-in-region-name edge: the `name,start,end` line format is comma-delimited, so a region name containing a comma is not representable. Scoped out — the construction-time scrub still neutralizes injection content regardless.
- On-screen per-line feedback (which line was skipped) beyond the count-only notice — deliberately count-only to avoid echoing pre-scrub operator text into the toast.

---

## 4. Changes from previous batch

| Type | Item | Detail |
|------|------|--------|
| new | HLR-027 / LLR-027.1–027.4 | D-1 save side: capture-on-Generate + thread regions to `write_project_manifest`. |
| new | HLR-028 / LLR-028.1–028.3 | D-1 load side: adopt manifest regions into app state + seed the dialog TextArea. |
| new | HLR-029 / LLR-029.1–029.3 | D-2 malformed-line count-only skip notice. |
| modified | batch-19 TC-024.5 (`test_parse_declared_regions_handles_hex_dec_and_skips_malformed`) | Rewritten for the new `_parse_declared_regions` `(regions, skipped)` return shape. |
| reused (read-only) | `manifest_writer.write_project_manifest` / `serialize_manifest` | Accepts `declared_regions`, omits the key when empty (shipped batch-19). |
| reused (read-only) | `variant_execution_service.read_project_manifest` → `ProjectManifest.declared_regions` | Reads regions back (shipped batch-19). |
| reused (read-only) | `report_addendum.DeclaredRegion` | Name scrub at `__post_init__` (shipped batch-19) — the injection defense on both write and read paths. |
| closed | D-1 (batch-19 BACKLOG) | UI save/load auto-wire — closed by US-024. |
| closed | D-2 (batch-19 BACKLOG) | Malformed region-line on-screen feedback — closed by US-025. |

---

## 5. Quick bidirectional mapping

### 5.1 By user story
- **US-024** → HLR-027, HLR-028 → LLR-027.1–027.4, LLR-028.1–028.3 → TC-027.1, TC-027.2, TC-027.3, TC-028.1, TC-028.2 → AT-027a/b/c, AT-028a (C-12 gate), AT-028b (guard)
- **US-025** → HLR-029 → LLR-029.1–029.3 → TC-029.1, TC-029.2, TC-024.5 → AT-029a/b/c/d

### 5.2 By code file
- `s19_app/tui/app.py` → LLR-027.1/027.2/027.3, LLR-028.1/028.3 → TC-027.1, TC-027.2, TC-028.1 (state init `:713`, capture `:1899`, save `:3791`/`:3802`/`:3867`, load `:3977`, reports hand-off `:1874`)
- `s19_app/tui/screens.py` → LLR-028.2, LLR-029.1/029.2/029.3 → TC-028.2, TC-029.1, TC-029.2, TC-024.5 (`_parse_declared_regions` `:543`, `ReportViewerScreen` seed `:667`/`:691`–`698`/`:703`–`708`, notify `:804`/`:807`–`813`)
- `tests/test_tui_report_seam.py` → all TC + all AT nodes

---

## 6. Batch sign-off

| Field | Value |
|-------|-------|
| Batch ID | 2026-06-29-batch-20 |
| Closing date | 2026-06-29 |
| Total iterations (sum of phases) | per `state.json` |
| Validation passed | yes (942 passed / 0 failed, non-slow; frozen-engine diff 0) |
| Synced to Obsidian | pending (`/dev-flow-sync` after merge) |
