# Traceability Matrix — s19_app — Batch 35

> **Artifact language:** English. Phase 6 artifact. Owner: `docs-writer`.
> Sources of truth: `01-requirements.md` §5.2 (dual-traceability table) and
> `04-validation.md` §1/§2 (on-disk node table, C-18 reconciliation). Every node id
> below was copied from 04-validation's grep-verified table; a 5-node sample was
> independently re-grep-verified by docs-writer on 2026-07-11 at the Phase-6 tree
> (see §7).

> Two chains (per the Two-layer validation rule) — a story is complete only when BOTH exist:
> - **Functional (white-box):** User Story → HLR → LLR → `TC-NNN` → File:line.
> - **Behavioral (black-box):** User Story → `AT-NNN` → observed outcome through the shipped surface.

---

## 1. Master table — functional chain (white-box)

Status "pass" = green in the Phase-4 full-suite run (04-validation §6: `1335 passed, 2
skipped, 21 deselected, 4 xfailed, 1 xpassed`, exit 0).

| US | HLR | LLR | TC / AT | File:line | Status | Notes |
|----|-----|-----|---------|-----------|--------|-------|
| US-053 | HLR-053 | LLR-053.1 | TC-307 | `tests/test_report_filter.py:57` (`TestTc307ValidRoundTrip`, 6 tests) | pass | hex/int equivalence, single-byte, 2^32 boundary, D-10 empty include, file round-trip |
| US-053 | HLR-053 | LLR-053.1 | TC-308 | `tests/test_report_filter.py:117` (`TestTc308RejectionMatrix`, 16 tests) | pass | one diagnostic per fault; N faults → ≥N diagnostics; `CAL_[` accepted (Q-10) |
| US-053 | HLR-053 | LLR-053.2 | TC-309 | `tests/test_report_filter.py:265` (`TestTc309ReadPathAndCeilings`) | pass | 4 MiB cap probed pre-read; symlink/non-regular refused at read time; never-raise hostile corpus |
| US-053 | HLR-053 | LLR-053.2 | TC-317 (swap arm) | `tests/test_tui_report_filter_surface.py:1193` | pass | S-F2 TOCTOU swap classes → read-time refusal |
| US-053 | HLR-053 | LLR-053.3 | TC-309 (ceilings) | `tests/test_report_filter.py:356` (symbols), `:369` (addresses) | pass | boundary-exact: 4096 OK, 4097 rejected |
| US-053 | HLR-053 | LLR-053.4 | TC-310 | `tests/test_report_filter.py:396` (`TestTc310TruthTable`), `:435` (`TestTc310ExtentPins`), `:490` (`TestTc310MetacharacterPins`) | pass | (a)/(b)/(c) 8-combo table; `fnmatchcase` pin; F-1 extent + Q-9 discriminators; F-2 `PAR[0]` equality; Q-10 bracket |
| US-053 | HLR-053 | LLR-053.5 | AT-053a | `tests/test_tui_report_filter_surface.py:782` | pass | both surfaces, 0 files; white-box twin `tests/test_tui_report_seam.py:1523` (declared TC-level guard) |
| US-053 | HLR-053 | LLR-053.6 | AT-053b, AT-056b | `tests/test_tui_report_filter_surface.py:860`, `:509` | pass | C-17 status side; S-F1 exit grep executed (04-validation §4 item 3: 0 call sites) |
| US-053 | HLR-053 | LLR-053.7 | TC-310 (never-raise) + AT-053a | `tests/test_report_filter.py:512` (`TestTc310NeverRaise`); `tests/test_tui_report_filter_surface.py:782` | pass | resolved matcher; refusal precedes any write |
| US-054 | HLR-054 | LLR-054.1 | TC-311 | `tests/test_before_after_report.py:972`, `:1028` | pass | one matcher kwarg; unfiltered generator kwargs shape == pre-batch (F-01 guard) |
| US-054 | HLR-054 | LLR-054.2 | TC-312 | `tests/test_diff_report_service.py:1249`, `:1283`, `:1332`, `:1371` | pass | both formats; A9 merged-window case; filter-before-merge (D-5) |
| US-054 | HLR-054 | LLR-054.3 | TC-312, TC-314 + AT-054c, AT-055c | nodes above; `tests/test_report_service.py:1367`, `:1431`; `tests/test_tui_report_filter_surface.py:1071`; `tests/test_tui_report_seam.py:1487` | pass | audit header first-block position (S-F6); per-section counts (F-07); Q-12 wording disjointness |
| US-054 | HLR-054 | LLR-054.4 | AT-054b (golden) | `tests/test_before_after_report.py:881` + `tests/goldens/batch35/at054b-before-after-report.{md,html}` | pass | double-proof ×3 (Inc-0 author, Inc-0 reviewer, Phase-4 independent re-derivation) |
| US-054 | HLR-054 | LLR-054.5 | inspection + TC-313 + AT-056e | inspection `app.py:3311-3318` (0 `report_filter` hits, 04-validation §4 item 2); `tests/test_diff_report_service.py:1431`; `tests/test_tui_report_filter_surface.py:716` | pass | A2B diff unconditionally complete |
| US-055 | HLR-055 | LLR-055.1 | TC-315 + AT-055a | `tests/test_report_service.py:1497`; `tests/test_tui_report_seam.py:1430` | pass | `ReportOptions.report_filter` type validation; UI-thread capture, worker argument (D-9/F-04) |
| US-055 | HLR-055 | LLR-055.2 | TC-314 | `tests/test_report_service.py:1367`, `:1465` | pass | three surfaces; F-02 symbol-branch checklist row; end-exclusive boundary `[0x0FFE,0x1000)` vs `0x1000` |
| US-055 | HLR-055 | LLR-055.3 | AT-055b (golden) | `tests/test_tui_report_seam.py:1292` + `tests/goldens/batch35/at055b-project-report.md` | pass | double-proof ×3, as LLR-054.4 |
| US-055 | HLR-055 | LLR-055.4 | TC-318 (both halves) + AT-053b | `tests/test_diff_report_service.py:1407`; `tests/test_report_service.py:1541`; `tests/test_tui_report_filter_surface.py:860` | pass | C-17 file side: ctl-strip, `_md_table_cell`, HTML escape |
| US-056 | HLR-056 | LLR-056.1 | TC-316 | `tests/test_tui_report_filter_surface.py:1136` | pass | sorted scan, symlink skipped, absent dir → `[]`; `validate_project_files` `filters/`-subdir regression in-body |
| US-056 | HLR-056 | LLR-056.2 | AT-056a, AT-056b, AT-056c | `tests/test_tui_report_filter_surface.py:313`, `:509`, `:587` | pass | C-15 probe executed at Inc-4 entry (`rich.markup.escape` chosen) |
| US-056 | HLR-056 | LLR-056.3 | AT-056a + AT-056a3 | `tests/test_tui_report_filter_surface.py:313`, `:456` | pass | sticky selection; F-09 reset funnel re-verified at Phase 4 (`app.py:960/:1903/:2486/:4832/:7143`) |
| US-056 | HLR-056 | LLR-056.4 | TC-317 + AT-056d | `tests/test_tui_report_filter_surface.py:1193`, `:639` | pass | relative resolve; missing/symlink typed refusals; both S-F2 swap classes |
| US-056 | HLR-056 | LLR-056.5 | AT-056a2 | `tests/test_tui_report_filter_surface.py:388` | pass | both geometry regimes (80x24 + 120x30); `e15b744` dock-overlap guard at `:441-444` |
| US-057 | HLR-057 | LLR-057.1 | AT-057a + TC-319 | `tests/test_tui_patch_editor_v2.py:2269`; `tests/test_tui_patch_layout.py:351` | pass | 15/15 ids, 2/2 section labels, parentage census |
| US-057 | HLR-057 | LLR-057.2 | existing AT-032a / AT-052a unmodified | `tests/test_tui_patch_editor_v2.py:1780` (AT-032a), `:2148` (AT-052a); `_CHECKS_HELP_TOKEN` at `:1775` | pass | file has 0 deleted lines vs base — locked token span untouched |
| US-057 | HLR-057 | LLR-057.3 | AT-057b + existing suite | `tests/test_tui_patch_editor_v2.py:2350` | pass | per-button wiring regression; 0 un-censused edits (04-validation §4 item 6) |
| US-057 | HLR-057 | LLR-057.4 | TC-320 + snapshot run | `tests/test_tui_snapshot.py:825` | pass | observed drift set == §6.5 amendment #21 (patch-120x30 xfailed, patch-80x24 xpassed under defensive mark) |

**25/25 LLRs covered — 0 rows incomplete.**

## 1b. Behavioral chain (black-box)

All 17 ATs map to exactly one on-disk node each (C-18, verified 04-validation §2); all
drive the shipped surfaces (key `b` → `action_before_after_report`; `ReportViewerScreen`
Generate → `_trigger_generate_report` → worker; Patch Editor screen; A2B report surface).

| US | AT | On-disk node (file:line) | Shipped surface | Observed outcome / deliverable | Status |
|----|----|--------------------------|-----------------|--------------------------------|--------|
| US-053 | AT-053a | `test_at_053a_invalid_filter_refuses_both_surfaces_zero_files` — `tests/test_tui_report_filter_surface.py:782` | key `b` + Generate | named refusal on status, 0 new files under `reports/` on BOTH surfaces | pass |
| US-053 | AT-053b | `test_at_053b_hostile_valid_filter_proceeds_sanitized_everywhere` — `tests/test_tui_report_filter_surface.py:860` | key `b` + Generate → written files | hostile-named VALID filter proceeds; literal status confirmation; every written file re-read, sanitation asserted | pass |
| US-054 | AT-054a | `test_at_054a_bkey_filtered_pair_keeps_match_omits_unmatched` — `tests/test_tui_report_filter_surface.py:996` | key `b` | filtered MD+HTML pair: match kept, unmatched absent, audit header present | pass |
| US-054 | AT-054b | `test_at_054b_no_filter_bkey_report_pair_byte_identical_to_golden` — `tests/test_before_after_report.py:881` | key `b` | no filter → pair byte-identical (canonical form) to base-revision golden under the fixed-clock pin | pass |
| US-054 | AT-054c | `test_at_054c_bkey_zero_match_writes_pair_with_loud_notice` — `tests/test_tui_report_filter_surface.py:1071` | key `b` | zero-match → pair still written, `filter matched 0 of N items` notice, wording disjoint from refusal (Q-12) | pass |
| US-055 | AT-055a | `test_at_055a_generate_surface_filtered_report_with_audit_header` — `tests/test_tui_report_seam.py:1430` | Generate | filtered project report on disk with audit header | pass |
| US-055 | AT-055b | `test_at_055b_no_filter_generate_report_byte_identical_to_golden` — `tests/test_tui_report_seam.py:1292` | Generate | no filter → report byte-identical to base golden | pass |
| US-055 | AT-055c | `test_at_055c_generate_surface_zero_match_notice` — `tests/test_tui_report_seam.py:1487` | Generate | zero-match → report written with loud notice | pass |
| US-056 | AT-056a | `test_at_056a_dropdown_selection_filters_both_triggers` — `tests/test_tui_report_filter_surface.py:313` | selector + both triggers | non-default selection → next report byte-differs on BOTH triggers + audit header (C-10) | pass |
| US-056 | AT-056a2 | `test_at_056a2_selector_row_and_generate_visible_at_both_regimes` — `tests/test_tui_report_filter_surface.py:388` | ReportViewerScreen modal | selector row + buttons row visible at 80x24 AND 120x30 | pass |
| US-056 | AT-056a3 | `test_at_056a3_project_switch_resets_selection_next_report_unfiltered` — `tests/test_tui_report_filter_surface.py:456` | project switch + next trigger | selection reset; next report unfiltered | pass |
| US-056 | AT-056b | `test_at_056b_hostile_filename_populates_and_renders_literally` — `tests/test_tui_report_filter_surface.py:509` | selector + overlay + status | hostile filename populates dropdown, overlay renders it literally, markup-safe status, no `MarkupError` | pass |
| US-056 | AT-056c | `test_at_056c_fresh_default_blank_dropdown_full_report_golden` — `tests/test_tui_report_filter_surface.py:587` | selector default | fresh app, none selected → full report (anchored to the AT-055b golden) | pass |
| US-056 | AT-056d | `test_at_056d_typed_path_valid_filters_missing_refuses` — `tests/test_tui_report_filter_surface.py:639` | free path input + next trigger | typed valid path → filtered; missing file → refusal | pass |
| US-056 | AT-056e | `test_at_056e_a2b_diff_report_byte_identical_despite_selection` — `tests/test_tui_report_filter_surface.py:716` | A2B report surface | with a filter SELECTED, A2B diff report byte-identical to a no-filter run (exemption holds) | pass |
| US-057 | AT-057a | `test_at057a_two_labeled_sections_ids_and_parentage` — `tests/test_tui_patch_editor_v2.py:2269` | Patch Editor screen | two labeled sections; 15 ids + AT-032a span survive | pass |
| US-057 | AT-057b | `test_at057b_regroup_wiring_and_binding_regression` — `tests/test_tui_patch_editor_v2.py:2350` | Patch Editor screen | every button press yields its pre-batch status surface; key `b` binding unchanged | pass |

**17/17 ATs complete — every output-producing story has a black-box deliverable observation.**

---

## 2. Coverage summary

| Metric | Value |
|--------|-------|
| Total user stories | 5 (US-053..US-057) |
| Covered user stories | 5 (100%) |
| Total HLR | 5 (HLR-053..HLR-057) |
| Implemented HLR | 5 (100%) |
| Total LLR | 25 |
| Implemented LLR | 25 (100%) |
| Acceptance tests (AT) | 17 (C-18: one on-disk node each) |
| Test cases (TC) | 14 (TC-307..TC-320) |
| New collected nodes this batch | +93 (1270 → 1363; D = 0) |
| TC/AT pass | all (Phase-4 run: 1335 passed, 0 failures) |
| TC/AT fail | 0 |
| TC/AT pending | 0 |

---

## 3. Detected gaps

**None.** Zero incomplete rows; no LLR without a node; no node without a code mapping.

Not gaps, but owed post-merge work carried in 04-validation §9 / 05-postmortem §6 (for
the record): canonical snapshot regen for the two patch cells; ubuntu CI run as the
cross-platform golden proof; S-F7 pre-existing raw `linkage_symbol` interpolation
(backlog, out of batch scope); minor test-hygiene items (redundant Generate-half TC,
canonicalizer twins).

---

## 4. Changes from previous batch

| Type | Item | Detail |
|------|------|--------|
| new | HLR-053..HLR-057 + 25 LLRs | Batch-35 requirement set (B-07: report filter + patch-editor regroup) |
| new | AT-053a..AT-057b (17) / TC-307..TC-320 (14) | +93 collected nodes; 0 nodes deleted |
| new | `R-RPT-FILTER-001`, `R-TUI-045` | REQUIREMENTS.md ledger rows added in this Phase 6 |
| modified | LLR-054.4 / LLR-055.3 | Canonical-form byte-identity amendment (§6.5 #19/#20, Inc-0 gate) |
| modified | LLR-057.4 | Observed drift set = patch-120x30 only (§6.5 #21, Inc-5 gate) |
| closed | Batch-34 dependency | PR #63 confirmed merged (`79699a5` == `origin/main`) at Phase 4 |

---

## 5. Quick bidirectional mapping

### 5.1 By user story
- **US-053** → HLR-053 → LLR-053.1–.7 → TC-307, TC-308, TC-309, TC-310 + AT-053a, AT-053b
- **US-054** → HLR-054 → LLR-054.1–.5 → TC-311, TC-312, TC-313 + AT-054a, AT-054b, AT-054c, AT-056e
- **US-055** → HLR-055 → LLR-055.1–.4 → TC-314, TC-315, TC-318 + AT-055a, AT-055b, AT-055c
- **US-056** → HLR-056 → LLR-056.1–.5 → TC-316, TC-317 + AT-056a, AT-056a2, AT-056a3, AT-056b, AT-056c, AT-056d
- **US-057** → HLR-057 → LLR-057.1–.4 → TC-319, TC-320 + AT-057a, AT-057b

### 5.2 By code file
- `s19_app/tui/services/report_filter.py` → LLR-053.1/.2/.3/.4/.7 → TC-307..TC-310
- `s19_app/tui/services/before_after_service.py` → LLR-054.1 → TC-311
- `s19_app/tui/services/diff_report_service.py` → LLR-054.2/.3/.5, LLR-055.4 → TC-312, TC-313, TC-318 (diff half)
- `s19_app/tui/services/report_service.py` → LLR-054.3, LLR-055.1/.2/.4 → TC-314, TC-315, TC-318 (report half)
- `s19_app/tui/app.py` → LLR-053.5/.6, LLR-056.1/.3/.4 → AT-053a/b, TC-316, TC-317
- `s19_app/tui/screens.py` → LLR-056.2/.5 → AT-056a/a2/b/c
- `s19_app/tui/screens_directionb.py` + `s19_app/tui/styles.tcss` → LLR-057.1–.4 → AT-057a/b, TC-319, TC-320

---

## 6. Batch sign-off

| Field | Value |
|-------|-------|
| Batch ID | 2026-07-10-batch-35 |
| Closing date | 2026-07-11 |
| Total iterations (sum of phases) | 14 (P0:1 · P1:1 · P2:2 · P3:7 · P4:1 · P5:1 · P6:1) |
| Validation passed | yes (04-validation §10: all three exit axes MET) |
| Synced to Obsidian | no — pending post-merge `/dev-flow-sync` |

---

## 7. Phase-6 sample re-verification (docs-writer, 2026-07-11)

Five nodes re-grep-verified on disk at the Phase-6 tree (grep for the exact
class/function definition; all five match 04-validation's file:line exactly):

| Node | Expected | Grep result |
|------|----------|-------------|
| `TestTc307ValidRoundTrip` | `tests/test_report_filter.py:57` | ✓ `:57` |
| `test_at_053a_invalid_filter_refuses_both_surfaces_zero_files` | `tests/test_tui_report_filter_surface.py:782` | ✓ `:782` |
| `test_at_054b_no_filter_bkey_report_pair_byte_identical_to_golden` | `tests/test_before_after_report.py:881` | ✓ `:881` |
| `test_at_055b_no_filter_generate_report_byte_identical_to_golden` | `tests/test_tui_report_seam.py:1292` | ✓ `:1292` |
| `test_at057a_two_labeled_sections_ids_and_parentage` | `tests/test_tui_patch_editor_v2.py:2269` | ✓ `:2269` |
