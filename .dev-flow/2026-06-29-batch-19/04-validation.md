# Validation — s19_app — Batch 2026-06-29-batch-19

> Phase 4 artifact. Owner: `qa-reviewer`. Executes the Phase-1 validation strategy. Stories US-020c (declared-region report addendum + persistence) + US-020d (issue enrichment).

## ✅ Verdict (read first)

- **Result:** **PASS**
- **Requirements:** 2 US / 3 HLR / 5 LLR — all covered on BOTH layers · **0** blocker fails
- **Black-box acceptance (Layer B):** ✓ every story's `AT` observes its outcome through the shipped surface — report file on disk (US-020d, US-020c addendum), the report dialog → produced report (AT-024c, C-12), the on-disk `project.json` (AT-026a, qa-F4) — each with boundary + negative evidence
- **Surface-reachability (bidirectional):** ✓ all named inputs (declared regions via dialog; issue fields) AND outputs (report addendum, project.json) reached/observed
- **Supersession inspection:** ✓ N/A — net-new surfaces (`report_addendum.py`, addendum section, dialog input, manifest key); no placeholder/marker retired
- **Test ledger:** ✓ reconciles (`908 − 0 + 18 = 926`)
- **Engine-frozen / ruff:** ✓ `git diff origin/main -- validation/ + color_policy.py + core/hexfile/range_index` = 0; production + new tests ruff-clean
- **Counterfactual REDs (QC-2):** ✓ one+ per increment, all value-discriminating
- **Evidence checklist (qa-reviewer):** ✓ complete

> One minor process note (G-1, non-blocking): a pre-existing unused `import pytest` in `tests/test_manifest_writer.py` (present on `origin/main`, NOT introduced this batch) — lint nit only; CI runs `pytest`, not ruff. Left per surgical discipline; logged for a separate lint sweep.

---

## Detail (reference)

### Layer A — functional (white-box): per-requirement results (real reconciled nodes)

| Req | Method | Executed verification | Result | Evidence |
|-----|--------|-----------------------|--------|----------|
| HLR-025 / LLR-025.1 (issue enrichment) | test (unit) | `test_report_service.py::test_report_issue_line_shows_address_symbol_related` / `::test_report_issue_address_zero_renders` | **pass** | `@0x{addr}`/symbol/related rendered; `@ 0x0` at the boundary |
| LLR-024.1 (DeclaredRegion) | test (unit) | `test_report_addendum.py::test_membership_is_inclusive_at_both_bounds` / `::test_rejects_bad_bounds` / `::test_rejects_empty_or_control_only_name` / `::test_name_is_scrubbed_of_control_and_ansi` / `::test_name_is_length_capped` | **pass** | inclusive bounds; per-field ValueError; name scrubbed+capped (security-F1) |
| LLR-024.2 (`_addendum_lines`) | test (unit+integration) | `test_report_service.py::test_addendum_lists_region_with_mods_and_issues` / `::test_addendum_membership_inclusive_at_bounds` | **pass** | region table + per-region membership; inclusive at start/end; past-end excluded |
| LLR-024.3 (dialog input) | test (pilot) + analysis | `test_tui_report_seam.py::test_parse_declared_regions_handles_hex_dec_and_skips_malformed` / `::test_report_dialog_with_region_input_fits_80_and_120_cols` | **pass** | parse hex/dec + skip malformed; **C-13 MEASURED** dialog fits 80 & 120 (no fallback) |
| LLR-026.1 (persistence) | test (integration) | `test_manifest_writer.py::test_serialize_omits_declared_regions_key_when_empty` / `::test_read_absent_key_empty_and_malformed_collected` | **pass** | key omitted when empty (back-compat); absent→empty; malformed→issue, read completes; read-path scrub |
| TC-S3 (single-source anti-drift) | test (unit) | `test_report_service.py::test_addendum_and_issue_render_use_same_address` | **pass** | same `ValidationIssue.address` in the issue line and the addendum |

### Layer B — behavioral (black-box) acceptance (real reconciled nodes)

| US | Acceptance test | Surface driven | Deliverable observed | repr · boundary · negative | Result |
|----|-----------------|----------------|----------------------|----------------------------|--------|
| US-020d | `test_report_issue_line_shows_address_symbol_related` (AT-025a) | `generate_project_report` → report file | issue line shows address/symbol/related | ✓·✓(`0x0`)·✓ | **pass** |
| US-020d | `test_report_issue_without_address_has_no_hex` (AT-025b) | same, no-address issue | no `@0x` | — · — · ✓ | **pass** |
| US-020c | `test_addendum_lists_region_with_mods_and_issues` (AT-024a) | `generate_project_report` → report file | addendum lists region + mods/issues inside | ✓·✓·— | **pass** |
| US-020c | `test_addendum_region_with_no_hits_shows_none` (AT-024b) | same, zero-hit region | "None." | — · ✓ · ✓ | **pass** |
| US-020c | `test_declared_region_in_dialog_reaches_report_addendum` (AT-024c) | `ReportViewerScreen` TextArea + Generate → produced report file | typed region in the addendum (C-12) | ✓·—·— | **pass** |
| US-020c | `test_declared_regions_roundtrip_and_on_disk` (AT-026a) | `serialize_manifest`/`write` → `project.json`; `read_project_manifest` | on-disk project.json carries regions + read returns them (qa-F4) | ✓·✓(empty/absent)·✓(malformed) | **pass** |

### Bidirectional surface-reachability

| Direction | Dimension / deliverable | Producer / surface | Reached? | Test |
|-----------|-------------------------|--------------------|----------|------|
| input | declared regions (dialog) | `ReportViewerScreen` → `GenerateRequested` → `ReportOptions` | yes | AT-024c |
| input | issue address/symbol/related | `ValidationIssue` fields (read-only) | yes | AT-025a |
| input | malformed region (parse / manifest) | `_parse_declared_regions` / `_parse_manifest_declared_regions` | yes (skip-don't-abort) | TC-024.5, TC-026.2 |
| output | report addendum | `_addendum_lines` → report file | yes | AT-024a/b/c |
| output | persisted regions | `serialize_manifest` → project.json | yes | AT-026a |

### Signed-balance test ledger

| base | − D | + A | = post | actual collected (non-slow) | passed-full | reconciles? |
|------|-----|-----|--------|------------------------------|-------------|-------------|
| 908 | 0 | 18 | 926 | 926 passed / 29 skipped / 3 xfailed / 21 deselected | 926 | **yes** |

`+A` = Inc1 (3: AT-025a/b, TC-025.1) + Inc2 (9: TC-024.3 ×5, AT-024a/b, TC-024.4, TC-S3) + Inc3 (3: AT-024c, TC-024.5, TC-024.6) + Inc4 (3: AT-026a, TC-026.1, TC-026.2).

### Counterfactual RED evidence (QC-2 — captured per increment)

| Increment | Counterfactual | RED kind | Result | Restored |
|-----------|----------------|----------|--------|----------|
| Inc1 | issue-enrichment `if False`'d | value | AT-025a + TC-025.1 RED (AT-025b green) | ✓ |
| Inc2 | addendum emit off | value | 4 addendum ATs RED | ✓ |
| Inc2 | name scrub bypassed | value | 3 model tests RED (injection/cap) | ✓ |
| Inc3 | app threading dropped (`declared_regions=()`) | value | AT-024c RED | ✓ |
| Inc4 | manifest key not written | value | AT-026a RED | ✓ |

All value-discriminating (the post-fix assertion keys on the right payload — rendered fields / membership / scrubbed name / persisted bytes).

### Gaps detected

| ID | Requirement | Gap | Severity | Action |
|----|-------------|-----|----------|--------|
| G-1 | tests/test_manifest_writer.py | pre-existing unused `import pytest` (on `origin/main`) | minor (lint, pre-existing) | separate lint sweep; CI runs pytest not ruff |
| D-1 | HLR-026 follow-on | UI auto-wire (save dialog regions to manifest / pre-fill on load) — out of LLR-026.1 scope (operator option 1) | deferred feature | log to BACKLOG at close |
| D-2 | Inc3 / LLR-024.3 | malformed region line skipped with log only, no on-screen feedback (reviewer F1) | deferred UX | log to BACKLOG at close |

### Evidence checklist — qa-reviewer
- ✓ Both layers present for every requirement (Layer A TCs + Layer B ATs).
- ✓ Every AT drives the SHIPPED surface (report file, dialog→report, on-disk project.json); asserts content, references no internal symbol in the outcome.
- ✓ Boundary + negative evidence (zero-hit region, no-address issue, empty/absent/malformed manifest, inclusive bounds, `0x0`).
- ✓ Provisional AT/TC ids reconciled to real on-disk nodes (V-5) — every id above is a real `pytest` node.
- ✓ Signed-balance ledger reconciles (908−0+18=926); full non-slow suite 926/0.
- ✓ Engine-frozen untouched (diff=0); production + new tests ruff-clean.
- ✓ §6.4 Phase-2 folds reflected (security-F1 scrub, architect-M1 inclusive bounds, contract-touch); no §6.5 amendment (C-13 measured PASS, no fallback — unlike batch-18).
- ✓ Single-source coupling validated (TC-S3).
