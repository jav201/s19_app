# Requirements Document — s19_app — Batch 35

> **Artifact language:** English. Normative keyword: `shall` — ONLY inside HLR/LLR statements.
> `should` never appears in a normative statement. `may` = optional. `will` = external fact.
>
> **Scope contract:** PLAN.md (`.dev-flow/2026-07-10-batch-35/PLAN.md`), operator spec locked
> 2026-07-10. OUT of scope: A/B diff report filtering, exclude-lists, per-project auto-apply,
> filter editor UI.
>
> **Draft-time verification:** every `file:line` in this document was re-verified at tree
> `79699a5` (branch `feat/batch-35-report-filter`) on 2026-07-10 unless flagged
> `assumed — verify in Phase N`. Symbols that do not exist yet are flagged `NEW — created in
> Phase 3`.

---

## 1. Introduction

### 1.1 Purpose
Derive the verifiable HLR/LLR set for batch-35 (backlog item B-07, last P1): an
operator-authored JSON **report filter file** that restricts the before/after report and the
project report to whitelisted symbols/address ranges, plus the **patch-editor regroup**
separating patch-script controls from check-script controls. This document is the Phase-2
review input and the Phase-3 implementation contract.

### 1.2 Scope
**In scope**
- Filter file format `s19app-report-filter` v1.0: parse, rejection diagnostics, ceilings (US-053).
- Filtered before/after report (`b`-key flow) (US-054).
- Filtered project report (`generate_project_report` flow) (US-055).
- Filter selection UX: dropdown of `<project>/filters/*.json` + free path; none = full report (US-056).
- Patch-editor regroup: two labeled control sections, zero behavior change (US-057).

**Out of scope (operator-locked)**
- A/B diff report filtering — the A2B diff stays always-complete (a filtered diff could hide
  unexpected deltas).
- Exclude-lists, per-project auto-apply, filter editor UI.
- Any edit to the engine-frozen set (§2.4).

### 1.3 Definitions, acronyms, abbreviations
| Term | Definition |
|------|------------|
| Filter file | Operator-authored JSON whitelist, envelope `s19app-report-filter` v1.0, under `<project>/filters/` or a free path. |
| Matched address set | The union of (a) explicit `include.addresses` ranges and (b) the address EXTENTS of loaded A2L/MAC records whose NAME matches an `include.symbols` pattern (D-1; extent = `[address, address + (byte_size or 1))` — F-1 fold). |
| Item match | A report row matches when its `linkage_symbol` matches a pattern (exact-equality OR `fnmatchcase` — F-2 fold) OR its `[address_start, address_end)` range intersects the matched address set (D-1 (a)/(b)/(c)). |
| Resolved matcher | `ReportFilterMatcher` (NEW — created in Phase 3): the per-run object built ONCE by `resolve_report_filter(filter, a2l_records, mac_records)` on the UI thread at trigger time — carries the symbol patterns plus the pre-built sorted matched-address ranges; the ONLY filter object that flows into composers, generators, `ReportOptions`, and workers (D-9). |
| Audit header | Mandatory header block in every FILTERED report naming the applied filter file and the per-section shown/hidden counts (LLR-054.3) — a filtered report must never pass for a complete one. |
| Byte-identity | With no filter selected, each report output is byte-for-byte identical to the pre-batch output for the same inputs under the declared fixed-clock environment pin (LLR-054.4/055.3; golden double-proof at Phase 3). |
| Engine-frozen set | `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py` — git-frozen by `tests/test_engine_unchanged.py` guards; consumed, never edited. |
| C-10 / C-12 / C-13 / C-15 / C-17 | Encoded dev-flow controls: non-default-selector AT / output-then-consume AT / geometry budget / framework-constant runtime probe / markup-safety on file-derived text. |

### 1.4 References
- `.dev-flow/2026-07-10-batch-35/PLAN.md` — locked spec, design defaults D-1..D-5, recon.
- `REQUIREMENTS.md` — project ledger; this batch sites **R-RPT-FILTER-001** (filter) and
  **R-TUI-045** (regroup). Probe run 2026-07-10: `grep R-RPT-FILTER REQUIREMENTS.md` → 0 hits;
  highest existing ids `R-RPT-002`, `R-TUI-044` → both proposed ids are free.
- Parse precedent: `s19_app/tui/operations/crc_config.py` (read/parse split, one error per
  fault, never raises). Envelope precedent: `s19_app/tui/changes/io.py` `FORMAT_ID` (:110).
- Batch-34 (PR #63, merged as `79699a5`): merged hex windows, `_md_table_cell` hardening.

### 1.5 Document overview
§2 context + Phase-0 story refinement; §3 HLR; §4 LLR; §5 validation strategy + dual
traceability; §6 assumptions, risks, reconciliation log, amendments.

---

## 2. Overall description

### 2.1 Product perspective
Two report generators exist today and stay architecturally unchanged:
- **Before/after report** — `compose_before_after_report`
  (`s19_app/tui/services/before_after_service.py:182`) validates five preconditions then calls
  BOTH diff generators (`generate_diff_report` `diff_report_service.py:1030`,
  `generate_diff_report_html` `:1573`) with `linkage_entries=summary.entries`
  (`before_after_service.py:337-345`). App handler: `action_before_after_report`
  (`app.py:1834`), key binding `b` (`app.py:786`, `show=False`).
- **Project report** — `generate_project_report` (`report_service.py:1128`) with frozen
  `ReportOptions` (`report_service.py:143-250`, one `ValueError` per fault). Operator surface:
  `ReportViewerScreen` modal (`screens.py:781`, opened by `action_view_reports`
  `app.py:2183-2189`) → `GenerateRequested` message (`screens.py:835`) →
  `on_report_viewer_screen_generate_requested` (`app.py:2191`) → `_trigger_generate_report`
  (`app.py:2226`) → `_start_generate_report_worker` (`app.py:2297`) → `generate_project_report`
  (`app.py:2372`).

The filter is a NEW cross-cutting input consumed by both generators; the match engine consumes
`range_index` primitives and `fnmatch.fnmatchcase` (no fnmatch use exists in production today —
probe run 2026-07-10: `grep -rn "fnmatch" s19_app/` → 0 hits).

**Key plumbing facts (verified):**
- `generate_diff_report` ALREADY accepts `a2l_records`/`mac_records` kwargs
  (`diff_report_service.py:1037-1038`) and extracts `(address, name)` pairs via
  `_artifact_addresses_with_names` (`diff_report_service.py:616-650`; MAC records
  `record['address']/['name']`, enriched A2L tags `tag['address']/['name']`). **D-9 note:
  this batch does NOT use those kwargs** — they feed `_annotate_run`
  (`diff_report_service.py:653-693`), which today renders `-` on the before/after path;
  forwarding them would change UNFILTERED run-table bytes (F-01). Annotation inputs stay
  untouched.
- The before/after composer passes neither today (`before_after_service.py:337-345` kwargs
  dict) and gains neither — D-1(c) is realized by the app resolving the filter against
  `loaded.mac_records` + `self._compute_a2l_enriched_tags()` (handler gather idiom
  `app.py:2984-2985`; function def `app.py:8009`) into a `ReportFilterMatcher` on the UI
  thread at trigger time (D-9, LLR-053.7); the resolved matcher is the ONLY new generator
  input (LLR-054.1).
- `ChangeSummaryEntry` (`changes/model.py:321-372`): `address_start` inclusive, `address_end`
  EXCLUSIVE, `linkage_symbol: Optional[str]` — the filter's `end` is exclusive to match.
- `CheckRunEntry.linkage_symbol` EXISTS (`changes/model.py:678`, populated at
  `changes/check.py:346` and `:387`) — checklist rows match via branch (a) on
  `linkage_symbol` OR range intersection, like every other item (F-02 correction; the draft's
  "check entries carry no `linkage_symbol`" claim was FALSE).
- Project-report filtered surfaces: Modifications table (`_modifications_lines`
  `report_service.py:657`, interpolates `entry.linkage_symbol` RAW at `:703` — no escaping
  today), Checklists tables (`report_service.py:772-803`, per-row `address_start/address_end`
  at `:796-797`), hexdump windows (`_hexdump_section` `report_service.py:871`,
  `_applied_regions` `:806-831` feeding `compute_hexdump_windows` `:262`,
  `merge_gap_bytes` param `:266`).
- Before/after filtered surfaces: linkage table (`_linkage_table_lines`
  `diff_report_service.py:384`, batch-34 `_md_table_cell` `:281` cells), differing-runs
  hex windows (`_hex_windows_lines` `diff_report_service.py:940-1027`, merged via
  `compute_hexdump_windows(..., merge_gap_bytes=MERGE_GAP_ROWS * HEX_WIDTH)` at `:1003-1008`,
  `MERGE_GAP_ROWS = 5` at `:864`; HTML twin at `:1423-1427`).

### 2.2 Product functions
1. Parse + validate an operator filter file; refuse invalid filters loudly (US-053).
2. Apply the filter to the before/after report (US-054) and project report (US-055) with an
   audit header; no filter → byte-identical output.
3. Select the filter per run: dropdown of project `filters/*.json` + free path (US-056).
4. Regroup patch-editor controls into two labeled sections (US-057).

### 2.3 User characteristics
Single operator (firmware/calibration engineer) using the `s19tui` Textual TUI; comfortable
authoring JSON by hand; relies on reports as engineering evidence — hence the
no-silent-truncation rule.

### 2.4 Constraints
- **Engine-frozen guard (hard):** no LLR in this batch may be satisfied by editing `core.py`,
  `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, or
  `tui/color_policy.py`. `range_index` is CONSUMED for address matching
  (`build_sorted_range_index` / `address_in_sorted_ranges` / `range_in_sorted_ranges`), never
  modified. Guards: `tests/test_engine_unchanged.py` `_ENGINE_PATHS` +
  `tests/test_tui_directionb.py::test_tc031_*`.
- **Byte-identity constraint:** unfiltered output of both reports must not change by even one
  byte — every new report parameter defaults to "absent".
- **Locked UI pin:** `#patch_checks_help` (`screens_directionb.py:1874-1883`) AT-032a token
  span is locked — extension allowed, deletion not (`tests/test_tui_patch_editor_v2.py:1783`,
  `_CHECKS_HELP_TOKEN` at `:1775`).
- **Snapshot baselines** regen only in canonical CI (textual==8.2.8 pin); local drift → xfail.
- Standing batch authorizations: no self-merge, 0 engine-frozen diffs, propose-not-encode
  controls.

### 2.5 Assumptions and dependencies
See §6.3/§6.4 for the full flagged list. Headline dependencies: PR #63 merged (verified:
`79699a5` is the branch base, `git log` 2026-07-10); `validate_project_files`
(`workspace.py:323`) iterates direct children and skips non-files (`:360-362`) → a `filters/`
subdirectory is safe (verified by code read, exercised by TC-316); `.json` suffix falls through
both extension buckets (`:363-369`) → loose JSON in the project dir is also inert.

### 2.6 Source user stories

| ID | User Story | Source | DoR status |
|----|------------|--------|------------|
| US-053 | As the operator, I want to author a `filters/*.json` whitelist and have an INVALID filter refuse report generation with named per-fault errors (0 files written), so that a filtered report can never silently degrade to a wrong or partial one. | B-07 / operator spec gate 2026-07-10 | READY |
| US-054 | As the operator, I want the `b`-key before/after report, with a filter selected, to show only matching linkage rows and overlapping hex windows under an audit header naming the filter and the hidden count, so that I can hand a customer a focused report that declares its own incompleteness. | B-07 | READY |
| US-055 | As the operator, I want the same filter contract on the project report (Modifications, Checklists, Memory-regions hexdumps), so that both report kinds obey one filter semantics. | B-07 | READY |
| US-056 | As the operator, I want a per-run dropdown of the project's `filters/*.json` plus a free path input, with "none" as the default meaning full report, so that the selection drives the next generated report without any persistent configuration. | B-07 | READY |
| US-057 | As the operator, I want the patch editor's mixed button row split into two labeled sections — patch-script controls vs check controls — so that I never run checks when I meant to apply a patch. | B-07 (regroup half) | READY |

#### Refinement log (Phase-0 record, 2026-07-10)

**US-053 — Filter file + rejection diagnostics**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** user = operator · outcome = valid filter parses; invalid filter refuses
  generation with named errors and writes nothing · why = no-silent-truncation is the whole
  point of the feature · out of scope = filter editor UI, exclude semantics.
- **Feasibility:** mirror `crc_config.py` read/parse split; net-new module; no unknowns.
- **Evaluability (black-box):** When a filter with a bad envelope is selected and a report is
  triggered, the operator observes a refusal status naming the fault and `reports/` unchanged.
- **Open questions:** none. **Classification: READY.**

**US-054 — Filtered before/after report**
- **INVEST:** I ✗ (depends on US-053's parse+match engine — accepted, ordered 053→054) ·
  N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** outcome = filtered rows/windows + audit header; no filter → byte-identical.
- **Feasibility:** resolved matcher threaded composer→generators (D-9); record shapes and
  handler gather idiom verified (§2.1). **Evaluability:** AT drives key `b`, re-reads the
  written MD+HTML pair.
- **Classification: READY.**

**US-055 — Filtered project report**
- **INVEST:** I ✗ (same US-053 dependency) · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** same contract on `generate_project_report` surfaces.
- **Feasibility:** filter rides on `ReportOptions` (frozen-dataclass validation precedent).
- **Evaluability:** AT drives the Generate flow, re-reads the written report file.
- **Classification: READY.**

**US-056 — Filter selection UX**
- **INVEST:** I ✗ (needs US-053 to have something to select; UI shell independent) · N ✓ ·
  V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** dropdown + free path; none = default; drives the NEXT report.
- **Feasibility:** A2B `Select` + `OsClipboardInput` precedent
  (`screens_directionb.py:2481-2492`); scan idiom `_scan_patch_change_files` (`app.py:2505`).
- **Evaluability:** non-default selection changes the next report's bytes (C-10).
- **Open design item (resolved in this document, §6.2 D-6):** WHERE the selector lives —
  before/after fires directly on `b` with no dialog; the project report collects options in the
  `ReportViewerScreen` modal. **Decision: one selector row in `ReportViewerScreen` writing a
  sticky app-level selection consumed by BOTH triggers** (rationale + alternatives §6.2).
- **Classification: READY.**

**US-057 — Patch-editor regroup**
- **INVEST:** I ✓ (fully independent) · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** two labeled sections; every existing widget id survives; zero handler
  change. **Feasibility:** CSS/compose-only; `#patch_doc_controls` is already a 3-column grid
  (`styles.tcss:900-906`); pane scrolls (`styles.tcss:707-714`).
- **Evaluability:** pilot queries both section labels + button parentage + wiring regression.
- **Classification: READY.**

---

## 3. High-level requirements (HLR)

### HLR-053 — Report filter file: format, parse, refusal
- **Traceability:** US-053
- **Statement:** When a report filter file is designated for a report run, the system shall
  parse it against the `s19app-report-filter` version `1.0` whitelist schema and, if the file
  is invalid on ANY count, shall refuse the report generation with one named diagnostic per
  fault and shall write zero report files.
- **Rationale (informative):** A filter that silently falls back to a full or partial report
  defeats the audit contract. Mirrors the `crc_config` operations-input discipline.
- **Validation:** test
- **Executed verification:** `pytest tests/test_report_filter.py -q` (file name provisional
  per V-5) + AT-053a via `pytest -k at053`.
- **Numeric pass threshold:** 0 failures; refusal case writes 0 files under `reports/`
  (directory listing count unchanged).
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** invalid filter → status line names the fault(s); `reports/`
    unchanged. Valid filter → generation proceeds.
  - **Shipped surface:** key `b` (before/after) and the `ReportViewerScreen` Generate button.
  - **Deliverable + observation:** ABSENCE of new files under `<project>/reports/` (count
    before == after) + the refusal status text.
  - **Acceptance test(s):** AT-053a (bad envelope → refusal + named error, 0 files, driven on
    BOTH surfaces — one on-disk node, same assertion class, one fixture, C-18),
    AT-053b (REDEFINED per Q-3: a VALID filter whose FILENAME and PATTERNS are hostile —
    markup brackets, `|`, backticks, `<b>`, control chars → generation PROCEEDS on both
    report kinds → status shows the literal confirmation carrying its token (budget per
    LLR-053.6) AND the AT re-reads every written file — before/after MD+HTML and the project
    report — asserting sanitation).
  - **Boundary catalog (QC-3):** ☑ empty (`include` lists both empty = valid, matches nothing
    → zero-match path, D-10, AT-054c/AT-055c) · ☑ boundary (range `start == end-1` single
    byte; ceilings at exactly 4096, TC-309) · ☑ invalid (bad envelope/keys/types, AT-053a,
    TC-308) · ☑ error (unreadable file, over size cap, symlink at read time, TC-309/TC-317).

### HLR-054 — Filtered before/after report
- **Traceability:** US-054
- **Statement:** When a valid report filter is selected and the operator triggers the
  before/after report, the system shall write the MD+HTML report pair containing only linkage
  rows and hex windows that match the filter, under an audit header naming the applied filter
  file and the shown/hidden counts; and when no filter is selected the system shall write
  output byte-identical to the unfiltered output of this tree's base revision, byte-identity
  being defined under the declared fixed-clock environment pin (LLR-054.4).
- **Rationale (informative):** D-1/D-2/D-5 locked defaults; byte-identity keeps the default
  path provably untouched. Golden mechanism (a) per Q-1: without the pin, the timestamped
  filename and content make surface-driven byte-equality impossible.
- **Validation:** test
- **Executed verification:** AT-054a/b/c via `pytest tests/test_before_after_report.py -k at054`
  (file exists today, hosts AT-038*; provisional per V-5).
- **Numeric pass threshold:** 0 failures; AT-054b asserts `bytes(filtered_run) ==
  bytes(golden)` exact equality (golden double-proof at Phase 3: golden captured at base
  revision, proven both by equality and by a deliberate-perturbation RED).
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** filtered report pair on disk; matching row present, non-matching
    absent; audit header present; no-filter run byte-identical.
  - **Shipped surface:** key `b` → `action_before_after_report` (`app.py:1834`).
  - **Deliverable + observation:** files at `<project>/reports/` (MD + HTML), non-empty,
    re-read by the AT and content-asserted (C-12 — the AT never writes the artifact itself).
  - **Acceptance test(s):** AT-054a (match/omit + header), AT-054b (no-filter byte-identity
    golden under the environment pin), AT-054c (zero-match filter → report still written,
    loud "matched 0 of N" notice, wording asserted disjoint from the refusal wording — no
    shared prefix token, Q-12).
  - **Boundary catalog (QC-3):** ☑ empty (zero-match, AT-054c) · ☑ boundary (window exactly
    abutting a matched range; entry with `linkage_symbol=None` matched only by range, TC-310) ·
    ☑ invalid (invalid filter refuses — HLR-053, AT-053a) · ☑ error (composer precondition
    refusals unchanged — existing AT-038* suite, regression).

### HLR-055 — Filtered project report
- **Traceability:** US-055
- **Statement:** When a valid report filter is selected and the operator triggers project
  report generation, the system shall write the report containing only Modifications rows,
  Checklists rows, and hexdump windows that match the filter, under the same audit header
  contract; and when no filter is selected the system shall write output byte-identical to the
  unfiltered output of this tree's base revision, byte-identity being defined under the
  declared fixed-clock environment pin (LLR-055.3).
- **Rationale (informative):** one filter semantics across both report kinds; header,
  statistics, and inventory sections stay whole (D-2), statistics gain shown/hidden counts.
- **Validation:** test
- **Executed verification:** AT-055a/b/c via `pytest tests/test_tui_report_seam.py -k at055`
  (file exists today; provisional per V-5) + `pytest tests/test_report_service.py -q`.
- **Numeric pass threshold:** 0 failures; AT-055b exact byte equality vs golden
  (double-proof, as AT-054b).
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** filtered project report on disk with audit header; no-filter run
    byte-identical.
  - **Shipped surface:** `ReportViewerScreen` Generate button → `GenerateRequested` →
    `_start_generate_report_worker` (`app.py:2297`).
  - **Deliverable + observation:** report file under `<project>/reports/`
    (`REPORTS_DIR_NAME = "reports"`, `report_service.py:113`), non-empty, re-read and
    content-asserted by the AT (C-12).
  - **Acceptance test(s):** AT-055a (match/omit + header), AT-055b (no-filter golden),
    AT-055c (zero-match notice).
  - **Boundary catalog (QC-3):** ☑ empty (zero-match, AT-055c) · ☑ boundary (checklist row
    exactly at a range edge — end-exclusive semantics, TC-314) · ☑ invalid (HLR-053 refusal
    reaches this surface too, AT-053a drives Generate) · ☑ error (existing `ReportOptions`
    `ValueError` path unchanged — regression, TC-315).

### HLR-056 — Filter selection UX
- **Traceability:** US-056
- **Statement:** The system shall present, on the report-viewer screen, a filter selector
  consisting of a dropdown listing the active project's `filters/*.json` files (symlinks
  skipped, sorted) plus a free path input; the selection shall default to none (full report),
  shall drive the next generated report of either kind, and shall be surfaced on the status
  line markup-safely.
- **Rationale (informative):** D-6 (§6.2) — a single selector home feeding a sticky app-level
  selection is the only design in which one widget serves both trigger flows without geometry
  risk in the patch editor.
- **Validation:** test
- **Executed verification:** AT-056a/a2/a3/b/c/d/e via `pytest -k at056`; TC-316/317 unit
  level.
- **Numeric pass threshold:** 0 failures; AT-056a asserts filtered output `!=` unfiltered
  baseline bytes (a non-default selection observably changes output, C-10).
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** dropdown lists the project's filter files; selecting one changes
    the next report; "none" keeps it byte-identical; a hostile filename renders literally on
    the status line.
  - **Shipped surface:** `ReportViewerScreen` modal (`screens.py:875-918` compose; new row
    NEW — created in Phase 3) + key `b` consuming the same selection.
  - **Deliverable + observation:** rendered `Select` options (pilot query) + the next written
    report file's content delta.
  - **Acceptance test(s):** AT-056a (non-default selection → next report byte-differs on
    BOTH triggers + audit header present), AT-056a2 (geometry: selector row + buttons row
    visible at 80x24 AND 120x30 — the TC-024.6 per-width idiom), AT-056a3 (project-switch
    reset → next report unfiltered), AT-056b (hostile filename in `filters/` → the dropdown
    POPULATES with the hostile name, the options overlay opens and renders it literally,
    markup-safe status, no `MarkupError`), AT-056c (fresh app, no selection → full report,
    dropdown shows none), AT-056d (typed-path arm: type a path to a valid filter → next
    report filtered; point at a missing file → refusal), AT-056e (with a filter SELECTED,
    the A2B diff report driven through its shipped surface is byte-identical to a no-filter
    A2B run). C-18: one on-disk node per AT — the AT-056a split exists because the three
    concerns are distinct assertion classes.
  - **Boundary catalog (QC-3):** ☑ empty (no `filters/` dir or empty dir → dropdown empty,
    none default, TC-316) · ☑ boundary (exactly one file; name sorting determinism, TC-316) ·
    ☑ invalid (free path to nonexistent/symlinked file → refusal, TC-317) · ☑ error
    (selected file deleted between selection and generation → HLR-053 refusal path, TC-317).

### HLR-057 — Patch-editor control regroup
- **Traceability:** US-057
- **Statement:** The system shall render the patch editor's change-file controls as two
  labeled sections — a patch-script section containing the Load/Validate/Apply/Save buttons
  and a checks section containing the Run-checks button with its help text — while preserving
  every existing widget id, the AT-032a help token span, and the behavior of every existing
  handler and key binding.
- **Rationale (informative):** B-07 second half; the current mixed row
  (`screens_directionb.py:1861-1868`) invites running checks when a patch action was intended.
- **Validation:** test
- **Executed verification:** AT-057a/b via
  `pytest tests/test_tui_patch_editor_v2.py tests/test_tui_patch_layout.py -q`.
- **Numeric pass threshold:** 0 failures; both section labels queryable; all 15 preserved ids
  (LLR-057.1 list) present; AT-032a token span present.
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** two visually labeled sections; every button still works.
  - **Shipped surface:** Patch Editor screen (`action_show_screen("patch")`).
  - **Deliverable + observation:** rendered section labels + button parentage via pilot
    queries; check-run status line still appears when Run checks is pressed (AT-032b idiom,
    `tests/test_tui_patch_editor_v2.py:1811-1850`).
  - **Acceptance test(s):** AT-057a (section labels + parentage + AT-032a span survives),
    AT-057b (wiring/bindings regression: each button press produces its pre-batch status
    surface; key `b` binding unchanged).
  - **Boundary catalog (QC-3):** ☑ empty (N/A — no data input; the regroup is layout-only,
    reason recorded) · ☑ boundary (80x24 floor geometry — snapshot cell + AT-033a host-clip
    regression) · ☑ invalid (N/A — no new input surface, reason recorded) · ☑ error
    (N/A — no new failure path; existing handlers regression-covered by AT-057b).

---

## 4. Low-level requirements (LLR)

> Engine-frozen constraint applies to every LLR below (§2.4). All new-module and new-symbol
> names are provisional per V-5 and flagged NEW.

#### HLR-053 decomposition

### LLR-053.1 — Envelope and schema
- **Traceability:** HLR-053
- **Statement:** The filter parser shall accept exactly this top-level shape —
  `{"format": "s19app-report-filter", "version": "1.0", "include": {"symbols": [<str>...],
  "addresses": [{"start": <hex-or-int>, "end": <hex-or-int>}...]}}` — where `start`/`end`
  accept a JSON integer or a `"0x"`-prefixed hex string, `end` is exclusive (matching
  `ChangeSummaryEntry.address_end`, `changes/model.py:333`), the address domain is pinned to
  `0 <= start < end <= 2^32` (crc_config address-domain precedent), and shall reject with one
  named diagnostic per fault: wrong/missing `format`, wrong/missing `version`, unknown
  top-level or `include`-level key, non-list `symbols`/`addresses`, non-string pattern,
  non-parsable address, address outside the pinned domain, and `start >= end`.
- **Validation:** test (unit)
- **Executed verification:** `pytest tests/test_report_filter.py -k tc307 -k tc308`
  (TC-307 valid round-trip incl. hex/int equivalence: `"0x10"` and `16` parse to the same
  range; TC-308 one-error-per-fault matrix incl. negative, `> 2^32`, and `start >= end`;
  plus the unbalanced-bracket pattern `CAL_[` ACCEPTED — no rejection, Q-10).
- **Numeric pass threshold:** 0 failures; a file with N distinct faults yields ≥ N diagnostics,
  each containing the offending key/index.
- **Acceptance criteria:** envelope mirrors `changes/io.py` `FORMAT_ID` precedent (`:110`,
  `"s19app-changeset"`) with the new id `"s19app-report-filter"` (NEW — created in Phase 3);
  unknown-key rejection mirrors `crc_config.py` one-error-per-fault style
  (`parse_crc_config`, `crc_config.py:385`). Q-10 pattern note: an unbalanced-bracket
  pattern such as `CAL_[` is VALID — `fnmatchcase` treats the lone `[` literally and F-2's
  equality branch makes the pattern inert-safe; documented in the format docs, exercised as
  a TC-310 match case, never a parse rejection.

### LLR-053.2 — Read/parse split, size cap, never-raise contract
- **Traceability:** HLR-053
- **Statement:** The filter module (NEW — `s19_app/tui/services/report_filter.py`, created in
  Phase 3) shall expose `read_report_filter_text(path)` and `parse_report_filter(text)`
  returning `(ReportFilter | None, list[str])`, shall probe the on-disk size BEFORE reading
  and reject files over a filter-specific cap of 4 MiB (constant NEW — created in Phase 3;
  not larger than the shared `READ_SIZE_CAP_BYTES` in `changes/io.py`; import precedent
  `crc_config.py:32`), shall refuse a path that is a symlink or not a regular file AT READ
  TIME with a named diagnostic (S-F2 — closes the TOCTOU swap window on the dropdown arm),
  and shall never raise for any input.
- **Validation:** test (unit)
- **Executed verification:** `pytest tests/test_report_filter.py -k tc309` (size cap, malformed
  JSON, empty file, non-UTF-8 bytes — each returns `(None, [errors])`, no exception) +
  TC-317 swap case (dropdown-selected file replaced by a symlink before generation →
  refusal).
- **Numeric pass threshold:** 0 failures; 0 uncaught exceptions across the hostile corpus.
- **Acceptance criteria:** style decision — `(obj|None, list[str])` (crc_config) over
  `ValidationIssue` codes (changes/io): the filter is an operations-side config whose
  diagnostics surface on the status line as plain strings, exactly crc_config's profile;
  `ValidationIssue` codes are the Issues-panel contract, which the filter never reaches.
  Recorded as design decision D-7 (§6.2).

### LLR-053.3 — Count ceilings
- **Traceability:** HLR-053
- **Statement:** The filter parser shall reject a filter whose `symbols` list exceeds 4096
  patterns or whose `addresses` list exceeds 4096 ranges, each with one named diagnostic
  stating the ceiling.
- **Validation:** test (unit)
- **Executed verification:** `pytest tests/test_report_filter.py -k tc309` (4096 accepted,
  4097 rejected, per list).
- **Numeric pass threshold:** boundary exact: 4096 → parse OK; 4097 → 1 ceiling diagnostic.
- **Acceptance criteria:** ceiling value mirrors `CRC_SPAN_COUNT_CEILING = 4096`
  (`crc_config.py:82`) — same operator-JSON class and same cost profile (range list sorts
  O(n log n); `fnmatch` compiled-pattern caching makes 4096 patterns tractable per report run).

### LLR-053.4 — Match engine semantics (D-1)
- **Traceability:** HLR-053, HLR-054, HLR-055
- **Statement:** The match engine (NEW — in `report_filter.py`, created in Phase 3) shall
  classify an item with symbol `s` and half-open range `[a, b)` as MATCHED when (a) `s` is not
  None and, for any `include.symbols` pattern, `s == pattern` OR
  `fnmatch.fnmatchcase(s, pattern)` holds, OR (b) `[a, b)` intersects any `include.addresses`
  range, OR (c) `[a, b)` intersects the address EXTENT of any loaded A2L/MAC record whose NAME
  satisfies (a), where a record's extent is `[addr, addr + size)` with `size` = the record's
  `byte_size` value when it is a positive integer, else 1; the matched address set shall
  be built once per report run, and membership checks shall consume
  `build_sorted_range_index` / `address_in_sorted_ranges` / `range_in_sorted_ranges` from
  `range_index.py` without modifying that module.
- **Validation:** test (unit)
- **Executed verification:** `pytest tests/test_report_filter.py -k tc310` (each of (a)/(b)/(c)
  isolated + a `fnmatchcase` case-sensitivity pin: pattern `CAL_*` must NOT match `cal_x`;
  + the F-1 extent pin: an entry range overlapping only the TAIL byte of a 4-byte matched A2L
  parameter still matches; + the F-2 metacharacter pin: literal symbol `PAR[0]` with pattern
  `PAR[0]` matches via the equality branch — `fnmatchcase` alone treats `[0]` as a char class
  and would match only `PAR0`; + the Q-9 extent discriminators: `byte_size=None` → extent 1,
  `byte_size=0`/non-positive → extent 1 (pins the "positive integer" wording boundary), the
  extent-END negative twin (an entry starting exactly at `addr + byte_size` does NOT match),
  and a MAC-record-stays-point vs A2L-extent divergence fixture (same name/address in both
  artifacts, only the A2L extent matches the tail byte); + the Q-10 unbalanced-bracket case:
  pattern `CAL_[` matches the literal symbol `CAL_[` and nothing else).
- **Numeric pass threshold:** 0 failures across the (a)/(b)/(c) truth table (8 combinations)
  plus the extent, metacharacter, Q-9 discriminator, and Q-10 bracket pins.
- **Acceptance criteria:** artifact record extraction reuses the shapes consumed by
  `_artifact_addresses_with_names` (`diff_report_service.py:616-650`): MAC
  `record['address']/['name']`, enriched A2L `tag['address']/['name']`. `fnmatchcase` (not
  `fnmatch`) is pinned because A2L symbols are case-sensitive (PLAN risk item).
  **F-1 (extent, supersedes the draft's point semantics):** enriched A2L tags carry
  `byte_size` directly on the record (`a2l.py:1200`, Optional — None when the layout is
  unresolvable), so a name-matched parameter covers its REAL extent; MAC records carry no
  `byte_size` key → extent 1 (point). Point semantics would HIDE a patch landing on byte 2..n
  of a filtered-for parameter — a silent miss contradicting the audit contract. This filter
  membership deliberately diverges from `_annotate_run`'s point membership
  (`diff_report_service.py:653-676`): annotation is best-effort labeling, filtering is a
  visibility contract. Informative (F-10): an extent-matched row may therefore still
  annotate `-` in the Symbols column — the divergence is accepted and documented in the
  format docs. **F-2 (metacharacters, closes QA gap G6):** the exact-equality
  short-circuit guarantees a literal name containing fnmatch metacharacters matches itself.
  Informative: a metacharacter pattern also keeps its glob meaning (`PAR[0]` as a pattern also
  matches `PAR0`) — whitelist over-match is acceptable and visible in the output; the format
  documentation states this.

### LLR-053.5 — Refusal reaches both trigger surfaces, zero files
- **Traceability:** HLR-053
- **Statement:** When the selected filter fails read, parse, or resolution,
  `action_before_after_report` and `_trigger_generate_report` (`app.py:2226` — on the UI
  thread, BEFORE `_start_generate_report_worker` is started, per D-9/F-04) shall each surface
  the diagnostics on the status line prefixed with the report kind, shall not invoke their
  generator or start the worker, and shall leave `<project>/reports/` unchanged.
- **Validation:** test (e2e / pilot)
- **Executed verification:** AT-053a — pilot drives BOTH surfaces with an invalid filter
  selected; asserts status text + `len(list(reports_dir.iterdir()))` unchanged.
- **Numeric pass threshold:** 0 new files on both surfaces; both status lines contain the
  parser's named fault.
- **Acceptance criteria:** never a silent fallback to the full report (the refusal REPLACES
  generation); composer preconditions (`before_after_service.py:250-314`) remain evaluated in
  their existing order — the filter check is additive, not a reordering.

### LLR-053.6 — Markup-safe diagnostics and filter naming on status (C-17)
- **Traceability:** HLR-053, HLR-056
- **Statement:** Every status-line message carrying the filter FILENAME or parser diagnostics
  shall flow exclusively through markup-inert render paths: the `set_status` funnel
  (`app.py:8880` → `_append_log_line` `:8888` → `#log_line_*` Labels, which are constructed
  `markup=False` at `app.py:1279-1282`), and any NEW widget rendering filter-derived text
  shall be constructed with `markup=False`; filter-derived text shall NOT be routed through
  `notify()` or `set_file_status` (S-F1); and the status message budget is pinned (Q-7): the
  SELECTION CONFIRMATION carries the filter filename, the REFUSAL message carries the named
  fault (report-kind-prefixed), and each message shall fit the 50-char funnel or lead with
  its token.
- **Validation:** test (e2e / pilot)
- **Executed verification:** AT-053b + AT-056b — filter named `[red]x[/red].json` containing
  patterns with `[bold]`/control characters; AT-056b drives selection (confirmation message)
  and AT-053a drives refusal (fault message); AT-053b asserts the literal confirmation on the
  proceed path; each AT asserts the message that carries its token; assert the rendered label
  text contains the literal bracket sequence and no `MarkupError` is raised.
- **Numeric pass threshold:** 0 `MarkupError`; literal token present in
  `str(label.render())`; each asserted token within its message's 50-char-visible span.
- **Acceptance criteria:** DRAFT-TIME CORRECTION to PLAN.md — the plan's claim "NO call site
  escapes today" is stale at `79699a5`: batch-33 made the log-line funnel markup-inert at
  construction (verified `app.py:1273-1282`). The residual hazard is (i) `#status_text` via
  `set_file_status` (`app.py:1269`, `:8883-8886` — NOT markup=False; the filter flows must
  not use it, enforced by this LLR's "exclusively" clause) and (ii) any NEW label this batch
  adds. Note `_append_log_line` trims to 50
  chars (`app.py:8892`) — diagnostics must lead with the fault, not the path. Phase-3 exit
  grep (S-F1): sweep new call sites of BOTH `notify(` and `set_file_status(` for
  filter-derived arguments (`set_status` itself is markup-inert and needs no sweep).

### LLR-053.7 — Resolved matcher (D-9)
- **Traceability:** HLR-053, HLR-054, HLR-055
- **Statement:** The filter module shall expose
  `resolve_report_filter(report_filter, a2l_records, mac_records) -> ReportFilterMatcher`
  (NEW symbol — created in Phase 3) building the matcher ONCE per report run — carrying the
  symbol patterns and the pre-built sorted matched-address ranges (explicit
  `include.addresses` ranges ∪ name-matched record extents per LLR-053.4(c)/F-1); item
  classification shall be exposed as methods on the matcher; the never-raise contract
  (LLR-053.2) shall extend to resolution and classification for any record shape (S-F4);
  and all per-run filter computation (read, parse, resolve) shall complete before the first
  report file write (S-F4).
- **Validation:** test (unit + pilot)
- **Executed verification:** TC-310 (the (a)/(b)/(c) truth table exercised through the
  matcher API, plus hostile/corrupt record-shape cases — no exception) + AT-053a (refusal
  precedes any file write on both surfaces).
- **Numeric pass threshold:** 0 uncaught exceptions across the hostile record corpus;
  AT-053a 0 new files.
- **Acceptance criteria:** the matcher is the ONLY filter object crossing the service
  boundary (composer kwarg LLR-054.1, `ReportOptions` field LLR-055.1, worker argument
  LLR-055.1) — generators never see the raw `ReportFilter` or artifact record lists (D-9;
  kills the F-01 byte-drift class and delivers branch (c) to the project report, F-02-ii).

#### HLR-054 decomposition

### LLR-054.1 — Composer and handler plumbing
- **Traceability:** HLR-054
- **Statement:** `compose_before_after_report` (`before_after_service.py:182`) shall accept
  exactly ONE new optional keyword parameter `report_filter` (the resolved
  `ReportFilterMatcher | None`, default None; NEW — created in Phase 3) and shall forward it
  into both `generate_diff_report` and `generate_diff_report_html` via its shared kwargs
  dict (`before_after_service.py:337-345`); NO `a2l_records`/`mac_records` kwarg shall be
  added to any generator call — generator annotation inputs stay UNTOUCHED (F-01);
  `action_before_after_report` (`app.py:1834`) shall, on the UI thread at trigger time,
  resolve the current selection per LLR-053.7 using `loaded.mac_records` and
  `self._compute_a2l_enriched_tags()` (def `app.py:8009`; handler gather idiom
  `app.py:2984-2985`) and pass only the resolved matcher.
- **Validation:** test (integration)
- **Executed verification:** `pytest tests/test_before_after_report.py -k tc311` — composer
  called with a matcher; generator output reflects it; called without → TC-311 asserts the
  unfiltered generator kwargs are byte-for-byte today's (kwargs-shape equality vs the
  pre-batch call).
- **Numeric pass threshold:** 0 failures; unfiltered kwargs-shape assertion exact.
- **Acceptance criteria:** the default-absent parameter preserves every existing call site
  unchanged (byte-identity, LLR-054.4); `LoadedFile.mac_records` verified at
  `models.py:52`; `_compute_a2l_enriched_tags` def verified at `app.py:8009` (call sites
  `app.py:1610`/`:2985`).

### LLR-054.2 — Filtered surfaces in the diff generators (D-2, D-5)
- **Traceability:** HLR-054
- **Statement:** When `generate_diff_report` / `generate_diff_report_html` receive a
  `report_filter`, they shall (a) restrict linkage-table rows (`_linkage_table_lines`,
  `diff_report_service.py:384`) to entries matching LLR-053.4, (b) restrict differing-run
  sections and hex windows to runs whose `[start, end)` intersects the matched address set,
  and (c) apply the run filtering BEFORE `compute_hexdump_windows` (`:1003-1008` MD,
  `:1423-1427` HTML) so the batch-34 merged windows are computed over the filtered run set
  only; the filter hides ITEMS — linkage rows and hex windows SEEDED by unmatched runs —
  and merged-window or context rows of a window seeded by matched runs MAY cover excluded
  addresses, disclosed by an informative audit note (F-03/Q-2 semantics pin); header,
  statistics, and inventory sections shall remain complete.
- **Validation:** test (integration)
- **Executed verification:** `pytest tests/test_diff_report_service.py -k tc312` — filter
  matching one of two disjoint runs: matched run's rows/windows present, unmatched absent
  from BOTH formats; merged-window assertion: two matched near runs still merge, a filtered-out
  run between them does not extend any window; A9 case: an excluded run lying INSIDE a merged
  window spanning two matched runs renders no linkage row and seeds no window/heading.
- **Numeric pass threshold:** 0 failures; the unmatched run seeds 0 linkage rows and 0 window
  headings (threshold re-scoped per Q-2 to linkage rows + window headings, NOT raw address
  tokens — merged/context rows may legitimately contain excluded addresses; the address token
  may also appear in the whole-statistics section).
- **Acceptance criteria:** D-5 resolves the PLAN watch-item "merge before or after
  filtering?": FILTER FIRST, then merge — no half-filtered windows.

### LLR-054.3 — Audit header, shown/hidden counts, zero-match notice
- **Traceability:** HLR-054, HLR-055
- **Statement:** Every FILTERED report (both kinds, both formats) shall carry an audit header
  block naming the applied filter file name, the count of items shown, and the count of items
  hidden, with the item-count basis defined per surface (F-07): the before/after report
  counts LINKAGE ENTRIES; the project report counts PER SECTION (Modifications rows,
  Checklists rows, applied regions), the header stating each; shown+hidden shall equal the
  pre-filter count per section; and a filter matching zero items shall still write the
  report, replacing the filtered sections' bodies with a notice stating
  `filter matched 0 of N items` (N = the pre-filter item count).
- **Validation:** test (integration)
- **Executed verification:** TC-312/TC-314 header assertions (including the S-F6 position
  assertion) + AT-054c/AT-055c zero-match pilots; AT-054c additionally asserts the zero-match
  notice wording is disjoint from the refusal wording — no shared prefix token (Q-12).
- **Numeric pass threshold:** header present in 100% of filtered outputs; shown+hidden ==
  pre-filter count per section; zero-match file exists and is non-empty.
- **Acceptance criteria:** an UNFILTERED report carries NO audit header (byte-identity);
  the header appears in the MD, the HTML, and the project report; D-3 encoded — never a
  silently empty file. Informative (S-F6): the audit header is the FIRST block after the
  report title with a fixed line format; TC-312/TC-314 assert its position.

### LLR-054.4 — No-filter byte-identity (before/after)
- **Traceability:** HLR-054
- **Statement:** With no filter selected, the MD and HTML outputs of the before/after report,
  produced by driving the SHIPPED `b`-key surface with the clock seams
  (`diff_report_service._default_now` — the default both generators resolve when no `now_fn`
  is passed, diff_report_service.py:1127/:1664 — and `changes/apply.py`'s `datetime`, whose
  inline `datetime.now(timezone.utc)` default stamps `ChangeSummary.timestamp_utc` printed as
  `Applied (UTC)` in both formats; resolved at Inc-0) monkeypatched to a fixed clock as a
  declared ENVIRONMENT PIN, shall be byte-identical **in canonical form** to the outputs
  captured at this batch's base revision (`79699a5`) through the same surface with the
  IDENTICAL pin, for the same inputs — where canonical form normalizes exactly two
  environment classes and nothing else: (a) platform newline translation (CRLF→LF), and
  (b) the per-run absolute run-root path (masked to `<RUN-ROOT>`, separators normalized only
  inside masked spans).
- **Validation:** test (golden)
- **Executed verification:** AT-054b — golden pair captured at base revision under the
  identical environment pin; equality re-proven post-implementation; double-proof: a
  deliberate one-byte perturbation of the golden makes the AT RED (Phase-3 procedure,
  batch-24 C control; EXECUTED at Inc-0 — all three goldens proven live).
- **Numeric pass threshold:** canonical-form bytes equality == True for both formats; every
  byte outside the two environment classes compared exact.
- **Acceptance criteria:** golden fixtures NEW — created in Phase 3 and counted in the
  increment file budget; `now_fn` service seams verified (`before_after_service.py:188`,
  `:344`) but UNREACHABLE from the shipped surface — the handler passes no `now_fn`
  (`app.py:1868-1873`); without the pin, the timestamped filename and content make
  byte-equality impossible (Q-1). The pin is an environment declaration on the AT and the
  golden-capture procedure, not a code change to the shipped path.

### LLR-054.5 — A/B diff report stays unconditionally complete
- **Traceability:** HLR-054 (scope guard)
- **Statement:** The A2B diff report path shall pass no `report_filter` and shall produce
  complete output regardless of any app-level filter selection.
- **Validation:** inspection + test (integration + pilot)
- **Executed verification:** inspection of the A2B handler kwargs (`app.py:2986-2993` — no
  filter key added) + TC-313: `generate_diff_report` called with `report_filter` omitted
  equals today's output for a fixture comparison + AT-056e (Q-5 black-box arm): with a
  filter SELECTED, the A2B diff report driven through its shipped surface is byte-identical
  to a no-filter A2B run — the sticky selection observably does NOT leak.
- **Numeric pass threshold:** grep of the A2B handler for the filter kwarg → 0 hits;
  TC-313 equality True; AT-056e bytes equality True.
- **Acceptance criteria:** encodes the operator's lock: "a filtered diff could hide
  unexpected deltas".

#### HLR-055 decomposition

### LLR-055.1 — Filter rides on ReportOptions
- **Traceability:** HLR-055
- **Statement:** `ReportOptions` (`report_service.py:143`) shall gain a
  `report_filter: Optional[ReportFilterMatcher] = None` field (NEW — created in Phase 3,
  holding the RESOLVED matcher) validated in `__post_init__` with one explicit `ValueError`
  on a wrong type (the existing one-fault pattern, `report_service.py:202-249`); the
  selection shall be captured, read+parsed, and resolved (LLR-053.7) on the UI THREAD in
  `_trigger_generate_report` (`app.py:2226`) BEFORE the worker starts — an invalid filter
  refuses per LLR-053.5 before any variant execution (F-04) — and the resolved matcher shall
  be passed to `_start_generate_report_worker` (`app.py:2297`) as an explicit WORKER
  ARGUMENT; the worker shall not re-read the app-level selection state (thread contract:
  UI-thread capture, worker consumes an immutable argument — no stale/torn read).
- **Validation:** test (unit + integration)
- **Executed verification:** `pytest tests/test_report_service.py -k tc315` (type validation)
  + AT-055a through the Generate flow.
- **Numeric pass threshold:** 0 failures; wrong-type field raises exactly one `ValueError`.
- **Acceptance criteria:** batch-32 precedent — configuration lives on the options/result
  object, screens hold no config; the frozen dataclass keeps report knobs per-invocation
  (matching the operator's "per-run" lock).

### LLR-055.2 — Filtered project-report surfaces (D-2, D-5)
- **Traceability:** HLR-055
- **Statement:** When `ReportOptions.report_filter` is set, `generate_project_report`
  (`report_service.py:1128`) shall (a) restrict Modifications rows (`_modifications_lines`,
  `:657`) to entries matching LLR-053.4, (b) restrict Checklists rows (`:772-803`) to check
  entries matching LLR-053.4 — branch (a) on `CheckRunEntry.linkage_symbol`
  (`changes/model.py:678`, populated at `changes/check.py:346`/`:387`) OR intersection of
  `[address_start, address_end)` (`:796-797`) with the matched address set, like every other
  item — and (c) restrict `_applied_regions` (`:806-831`) to matching entries BEFORE
  `compute_hexdump_windows` inside `_hexdump_section` (`:871`) so hexdump windows cover only
  the filtered region set; header, statistics, variant inventory, legend, entropy, and
  declared-regions addendum sections shall remain complete, with the statistics section
  extended by the shown/hidden counts.
- **Validation:** test (integration)
- **Executed verification:** `pytest tests/test_report_service.py -k tc314` — two-entry
  fixture, filter matches one: matched row/window present, unmatched absent; checklist
  end-exclusive boundary row (range ending exactly at a filter start does NOT match).
- **Numeric pass threshold:** 0 failures; unmatched entry's address token absent from the
  three filtered sections.
- **Acceptance criteria:** F-02 correction — the draft's claim "check entries carry no
  `linkage_symbol`" was FALSE (`CheckRunEntry.linkage_symbol`, `changes/model.py:678`);
  range-only checklist matching would hide a symbol-matched check row while the same
  symbol's Modifications row shows. Checklist rows use the full LLR-053.4 branch set via the
  resolved matcher (which carries branch (c) to this path, D-9).

### LLR-055.3 — No-filter byte-identity (project report)
- **Traceability:** HLR-055
- **Statement:** With `report_filter=None`, the project-report output, produced by driving
  the SHIPPED Generate surface with the report service's `_default_now`
  (`report_service.py:125-140` `NowFn`/`_default_now`) monkeypatched to a fixed clock as a
  declared ENVIRONMENT PIN, shall be byte-identical **in canonical form** (per LLR-054.4's
  two-environment-class definition) to the base-revision output captured through the same
  surface with the IDENTICAL pin, for the same inputs.
- **Validation:** test (golden)
- **Executed verification:** AT-055b — golden captured at base revision under the identical
  environment pin; double-proof as LLR-054.4 (EXECUTED at Inc-0).
- **Numeric pass threshold:** canonical-form bytes equality == True.
- **Acceptance criteria:** golden fixture NEW — created in Phase 3; the seam is UNREACHABLE
  from the shipped surface — the worker passes no `now_fn` (`app.py:2372-2374`); without the
  pin, the timestamped filename and content make byte-equality impossible (Q-1).

### LLR-055.4 — Sanitized filter-derived text in report files
- **Traceability:** HLR-054, HLR-055 (C-17 file side)
- **Statement:** Every filter-derived string interpolated into a report file — the filter
  file name in the audit header and any echoed symbol pattern — shall pass through the diff
  report's sanitation discipline: `_strip_ctl`-equivalent control-character stripping and
  `_md_table_cell` escaping in Markdown table cells (`diff_report_service.py:227`, `:255`,
  `:281`) and `_esc` HTML escaping in the HTML format (`:1163`); non-cell header lines
  (audit header, notices) shall pass control-character stripping at minimum (S-F5 —
  structurally sufficient: ctl-strip removes newlines, so a hostile name cannot forge
  header lines); in `report_service.py`,
  which performs no escaping today (verified raw interpolation at `:703`), the audit-header
  writer shall apply the same sanitation locally without altering any existing line.
- **Validation:** test (unit)
- **Executed verification:** `pytest -k tc318` — filter named `a|b*[x].json` with patterns
  containing `|`, backticks, `<script>`, and 0x00-0x1F bytes; assert MD table integrity
  (cell count per row constant), literal rendering, HTML-escaped output.
- **Numeric pass threshold:** 0 structural breaks (parsed MD table column count constant);
  `<script>` appears 0 times unescaped in HTML.
- **Acceptance criteria:** hostile-input coverage: the REDEFINED AT-053b (Q-3) is the
  black-box observer — it re-reads every written file (before/after MD+HTML, project report)
  and asserts sanitation through the shipped surface — while TC-318 remains the white-box
  seam check; together they discharge the mandatory C-17 pair at Phase 1.

#### HLR-056 decomposition

### LLR-056.1 — filters/ directory scan
- **Traceability:** HLR-056
- **Statement:** The app shall list filter candidates by globbing
  `<project_dir>/filters/*.json`, skipping symlink entries and returning bare names sorted
  deterministically, yielding an empty list when the directory is absent — mirroring
  `_scan_patch_change_files` (`app.py:2505-2549`).
- **Validation:** test (unit)
- **Executed verification:** `pytest -k tc316` — sorted order, symlink skipped, absent dir →
  `[]`; plus a `validate_project_files` regression: a project WITH a `filters/` subdir still
  validates (subdir skip verified at `workspace.py:360-362`).
- **Numeric pass threshold:** 0 failures.
- **Acceptance criteria:** `filters` as a project-dir name is net-new — probe run 2026-07-10:
  `grep -rn '"filters"|filters/' s19_app/tui/*.py s19_app/tui/services/*.py` → 0 hits (scan
  function and directory constant NEW — created in Phase 3).

### LLR-056.2 — Selector row in ReportViewerScreen
- **Traceability:** HLR-056
- **Statement:** `ReportViewerScreen.compose` (`screens.py:875-918`) shall gain one row (NEW —
  created in Phase 3: `#report_filter_row` containing `Select(id="report_filter_select",
  allow_blank=True)` and `OsClipboardInput(id="report_filter_path")`) placed above the
  `#reportviewer_buttons` container, following the A2B Select+path precedent
  (`screens_directionb.py:2481-2492`); on every screen open the selector shall be SEEDED from
  the current `_report_filter_path` so a reopen shows the true sticky state (F-05(i);
  declared-regions seeding precedent `screens.py:894-900`); every `Select` option label built
  from a filter filename shall be markup-escaped at option construction —
  `rich.markup.escape` on the prompt string or a `Text` prompt (F-05(ii)); the none/blank
  selection shall map to "no filter", and blank-vs-value transitions shall handle the
  `Select.NULL` sentinel per the batch-23 verified runtime identity (C-15 precedent: the
  A2B `Select.NULL` runtime handling at `screens_directionb.py:2148-2159`).
- **Validation:** test (e2e / pilot)
- **Executed verification:** AT-056a/c — pilot opens the screen, queries the row, drives a
  non-default selection — + AT-056b (dropdown POPULATES with the hostile name, the options
  overlay opens and renders it literally, no `MarkupError`). C-15 runtime probe (F-05(ii)):
  Select option-label markup behavior on textual==8.2.8 is UNVERIFIED at draft time —
  `probe at Phase 3 entry` before relying on either escape mechanism.
- **Numeric pass threshold:** row queryable at 80x24 and 120x30; 0 `NoMatches` errors;
  0 `MarkupError` with the hostile option present.
- **Acceptance criteria:** geometry per LLR-056.5 (verified by AT-056a2); selection semantics
  per LLR-056.3. Precedent-divergence note (F-08): the A2B precedent actually uses
  `allow_blank=False` + an `_EXTERNAL_OPTION` sentinel row, diverging from the specced
  `allow_blank=True` — justified in one line: "none = full report" is a first-class default
  here, so a blank Select models it directly instead of a sentinel option.

### LLR-056.3 — Sticky app-level selection consumed by both triggers
- **Traceability:** HLR-056
- **Statement:** The app shall hold the current selection in one field (NEW — created in
  Phase 3: `S19TuiApp._report_filter_path: Optional[Path]`), updated when the operator
  changes the selector (dropdown or free path) and confirmed on the status line
  (markup-safely per LLR-053.6, the confirmation carrying the filter filename within the
  Q-7 message budget); `action_before_after_report` and `_trigger_generate_report` shall
  both consult this field at trigger time on the UI thread (D-9); the field shall default to
  None (full report) and shall reset to None on EVERY path that swaps the active
  project/loaded file set — project load, create, close, and loose-file load (F-09; Phase 3
  shall locate the common funnel and cite it in the increment — `assumed — verify funnel
  completeness in Phase 3`).
- **Validation:** test (e2e / pilot)
- **Executed verification:** AT-056a — selection made in the report screen, then BOTH
  triggers driven; both outputs reflect the filter — + AT-056a3: project switch → next
  report unfiltered.
- **Numeric pass threshold:** 0 failures on the three assertions (b-key filtered, Generate
  filtered, post-switch unfiltered — the last in AT-056a3's own node, C-18).
- **Acceptance criteria:** "selection drives the NEXT generated report" (operator lock) is
  encoded as consult-at-generation-time — the filter FILE is re-read and re-parsed per run,
  so an edited file takes effect on the next run and a deleted file refuses (state-lifetime
  provenance: the selection stores only the PATH, never a parsed snapshot; the
  project-switch reset closes the batch-24 cross-project survivor class).

### LLR-056.4 — Free-path resolution and read-path fold
- **Traceability:** HLR-056
- **Statement:** A free-path selection shall resolve through `resolve_input_path`
  (`workspace.py:471`) against the app base directory, and a path that resolves to a symlink
  or to a non-file shall be refused with a named diagnostic (the `_scan_patch_change_files`
  read-path security fold, `app.py:2513-2515`, applied to the typed-path arm); an
  out-of-project free path is ALLOWED (S-F5 — read-only input, change-set precedent), and no
  write shall ever occur outside `<project>/reports/`.
- **Validation:** test (unit + pilot)
- **Executed verification:** `pytest -k tc317` — symlinked filter file refused; relative
  path resolved; missing file refused with named diagnostic; S-F2 swap case
  (dropdown-selected file replaced by a symlink before generation → refusal at read time) —
  + AT-056d (Q-4 black-box arm): type a path to a valid filter → next report filtered; point
  at a missing file → refusal, both through the shipped surface.
- **Numeric pass threshold:** 0 failures.
- **Acceptance criteria:** refusal flows through LLR-053.5 (report kind prefix, zero files).

### LLR-056.5 — Selector geometry budget (C-13)
- **Traceability:** HLR-056
- **Statement:** The selector row shall keep `#report_dialog` within its `height: 80%`
  envelope (`styles.tcss:1091-1093`) at the 80x24 and 120x30 regimes, with the `1fr`
  `#report_markdown_scroll` (`styles.tcss:1109-1113`) absorbing the added height.
- **Validation:** test (e2e / pilot)
- **Executed verification:** AT-056a2 (dedicated geometry node, C-18 — the TC-024.6
  per-width idiom) — `region` checks on the row and the
  buttons row at both sizes. Budget: `assumed — measure in Phase 3` (the absorb-by-1fr
  pattern is the PROVEN batch-19 precedent for this exact dialog — declared-regions comment
  `styles.tcss:1119-1121` — but the row's realized height with a `Select` is unmeasured).
- **Numeric pass threshold:** row fully inside the dialog region; Generate button visible
  (region.bottom ≤ dialog.bottom) at both regimes.
- **Acceptance criteria:** C-13.1 fallback ladder, deficit-matched: (rung 1) rely on the
  `1fr` scroll absorber; (rung 2) shrink `#report_list` `height: 8` → `6`
  (`styles.tcss:1095-1100`, −2 rows); (rung 3) fold the Select into the existing
  `#reportviewer_buttons` Horizontal (0 added rows); (rung 4) move the selector to a small
  dedicated modal behind a "Filter..." button (last resort — adds a step).

#### HLR-057 decomposition

### LLR-057.1 — Two labeled sections, ids preserved
- **Traceability:** HLR-057
- **Statement:** The change-file pane shall render a patch-script section label above
  `#patch_doc_controls` retaining exactly the Load/Validate/Apply/Save buttons, and a checks
  section label above a NEW container (`#patch_checks_controls`, created in Phase 3) holding
  `#patch_checks_run_button` and `#patch_checks_help`; every pre-batch widget id in
  `screens_directionb.py:1848-1898` shall survive: `patch_doc_file_select`,
  `patch_doc_path_input`, `patch_doc_load_button`, `patch_doc_validate_button`,
  `patch_doc_apply_button`, `patch_doc_save_button`, `patch_checks_run_button`,
  `patch_doc_controls`, `patch_checks_help`, `patch_doc_file_row`, `patch_paste_text`,
  `patch_paste_parse_button`, `patch_paste_controls`, `patch_paste_row`,
  `patch_pane_changefile`.
- **Validation:** test (e2e / pilot)
- **Executed verification:** AT-057a — pilot queries both section labels, all 15 ids, and
  asserts `#patch_checks_run_button` parentage under `#patch_checks_controls`. TC-319 (Q-8
  body): white-box compose query asserting both section labels, button parentage, and the
  15-id census against the composed widget tree.
- **Numeric pass threshold:** 15/15 ids queryable; 2/2 section labels rendered.
- **Acceptance criteria:** guard census (change-first, per the census principle): (i)
  `tests/test_tui_patch_layout.py:301-325` pins `#patch_doc_controls` as a `grid-size: 3`
  grid — the id and grid survive with 4 buttons, pin stays GREEN unmodified; (ii)
  `tests/test_tui_patch_editor_v2.py:67` pins id existence — all preserved; (iii) no test
  pins Run-checks parentage inside `#patch_doc_controls` (probe run 2026-07-10:
  `grep -rn patch_checks_run_button tests/` → existence + wiring assertions only, lines 8,
  67, 1818, 1850); (iv) engine-frozen guards untouched (no frozen file in the edit set).

### LLR-057.2 — AT-032a token span preserved
- **Traceability:** HLR-057
- **Statement:** The `#patch_checks_help` label text shall retain the locked AT-032a token
  span (`_CHECKS_HELP_TOKEN`, `tests/test_tui_patch_editor_v2.py:1775`); extension is
  permitted, deletion or rewording of the span is not.
- **Validation:** test (e2e / pilot)
- **Executed verification:** existing AT-032a (`tests/test_tui_patch_editor_v2.py:1783-1808`)
  and AT-052a (`:2149-2164`) run unmodified.
- **Numeric pass threshold:** both existing tests GREEN with 0 edits to their assertions.
- **Acceptance criteria:** the regroup moves the label's CONTAINER, not its text.

### LLR-057.3 — Zero behavior change
- **Traceability:** HLR-057
- **Statement:** The regroup shall change no handler, no action, no key binding, and no
  message flow: every button press shall produce its pre-batch observable effect, and the
  `b` binding (`app.py:786`) shall remain bound to `before_after_report`.
- **Validation:** test (e2e / pilot)
- **Executed verification:** AT-057b — press each of the five buttons via pilot and assert
  the pre-batch status surface per button (the AT-032b wiring idiom,
  `tests/test_tui_patch_editor_v2.py:1811-1850`); plus the full existing patch-editor suite
  `pytest tests/test_tui_patch_editor_v2.py -q` unmodified.
- **Numeric pass threshold:** existing suite 0 failures with 0 UN-CENSUSED edits;
  census-authorized test EXTENDS are permitted and recorded in the census (F-06 rewording —
  the id/text pins themselves do not change per LLR-057.1/057.2).
- **Acceptance criteria:** compose + CSS only; the `on_button_pressed` dict is untouched.

### LLR-057.4 — Snapshot drift plan
- **Traceability:** HLR-057
- **Statement:** The two patch-screen snapshot cells (80x24 floor + 120x30,
  `tests/test_tui_snapshot.py` `_TWO_SIZE_SCAFFOLDS = ("patch", "map")` at `:504`) shall be
  marked xfail-until-canonical-regen in the increment that lands the regroup, and no other
  snapshot cell shall drift.
- **Validation:** test (snapshot)
- **Executed verification:** `pytest tests/test_tui_snapshot.py -q` — exactly 2 xfails
  (patch cells), 29 green. TC-320 (Q-8 body): asserts the xfail set is exactly the 2 patch
  snapshot cells — no other cell xfailed or drifted.
- **Numeric pass threshold:** 29 green / 2 xfail / 0 unexpected; canonical regen follows the
  standing CI-only procedure post-merge.
- **Acceptance criteria:** map/diff/others unaffected because the regroup is confined to
  `#patch_pane_changefile`; the report-viewer selector (LLR-056.2) is a MODAL not covered by
  the scaffold snapshot set (`_SCAFFOLD_SCREENS = ["map", "patch", "diff"]`,
  `test_tui_snapshot.py:116`) — `assumed — verify at Phase 3` that no snapshot cell renders
  the modal.

---

## 5. Validation strategy

### 5.1 Methods
Both layers per the two-layer rule:
- **Layer A (white-box, `TC-NNN`):** pytest unit/integration against the parser, match engine,
  and generator seams. Every `test` LLR above names its executed verification + numeric
  threshold. Testing stack cross-check: pytest is the ratified runner (CI
  `.github/workflows/tui-ci.yml` runs `pytest -q`); Textual Pilot (`App.run_test`) is the
  established e2e idiom (`tests/test_tui_patch_editor_v2.py:1797-1803`). No new runtime is
  introduced.
- **Layer B (black-box, `AT-NNN`):** Textual Pilot drives the SHIPPED surfaces (key `b`,
  `ReportViewerScreen` Generate, patch screen) and re-reads handler-written artifacts (C-12).
  No AT references a service-internal symbol; assertions are on rendered text and files on
  disk. All AT/TC file paths, `-k` selectors, and node ids are provisional-until-Phase-3 (V-5).
  C-18 node discipline: every AT maps to exactly ONE on-disk test node; AT-053a driving both
  surfaces stays ONE node (same assertion class, one fixture); AT-056a was split into
  AT-056a/a2/a3 (Q-6) because its three concerns are distinct assertion classes. The
  byte-identity ATs (AT-054b/AT-055b) and AT-056e run under the declared fixed-clock
  environment pin (LLR-054.4/055.3).

Probe ledger (executed at draft, 2026-07-10, tree `79699a5`):
- `grep R-RPT-FILTER REQUIREMENTS.md` → 0 hits (id free); highest `R-TUI-044` → `R-TUI-045` free.
- `grep -rhoE 'AT-0[0-9]{2}[a-z]?' tests/*.py | sort -u | tail` → max `AT-052b` → AT-053a+ free.
- `grep -rhoE 'TC-[0-9]{3}' tests/ | sort -u | tail` → max `TC-306` → TC-307+ free.
- `grep -rn fnmatch s19_app/` → 0 hits (regime: production package, all files) — the
  net-new-matching claim's pre-state.
- `grep -rn '"filters"|filters/' s19_app/tui` → 0 hits — new directory constant pre-state.
- `grep -rn patch_doc_controls tests/` → grid-3 pin at `test_tui_patch_layout.py:301-325`
  only (regime: test package, id-token search) — LLR-057.1 census pre-state.
- Byte-identity goldens: `unexecuted — verify in Phase 2/3` (goldens can only be captured at
  implementation time, under the environment pin; the double-proof procedure is specified in
  LLR-054.4/055.3).
- Select option-label markup behavior on textual==8.2.8: `probe at Phase 3 entry`
  (C-15, F-05(ii) — before relying on `rich.markup.escape` vs `Text` prompt).

### 5.2 Dual-traceability table

**Behavioral chain (black-box) — per user story:**

| US | Observable outcome | Shipped surface | Acceptance test | Observed? |
|----|--------------------|-----------------|-----------------|-----------|
| US-053 | Invalid filter → named refusal, 0 files written, on both report triggers | key `b` + ReportViewerScreen Generate | AT-053a | Phase 4 |
| US-053 | VALID filter with hostile filename+patterns → generation PROCEEDS on both kinds; literal confirmation on status; every written file (before/after MD+HTML, project report) re-read, sanitation asserted | key `b` + Generate → status funnel + written reports | AT-053b (redefined, Q-3) | Phase 4 |
| US-054 | Filtered MD+HTML pair: matching rows/windows only + audit header | key `b` → files in `reports/` | AT-054a | Phase 4 |
| US-054 | No filter → byte-identical pair (golden double-proof, environment pin) | key `b` | AT-054b | Phase 4 |
| US-054 | Zero-match filter → report written with "matched 0 of N" notice, wording disjoint from refusal (Q-12) | key `b` | AT-054c | Phase 4 |
| US-055 | Filtered project report: filtered Modifications/Checklists/hexdumps + header | Generate → file in `reports/` | AT-055a | Phase 4 |
| US-055 | No filter → byte-identical report | Generate | AT-055b | Phase 4 |
| US-055 | Zero-match → loud notice | Generate | AT-055c | Phase 4 |
| US-056 | Non-default selection → next report byte-differs on BOTH triggers + audit header | ReportViewerScreen selector | AT-056a | Phase 4 |
| US-056 | Selector row + buttons row visible at 80x24 AND 120x30 | ReportViewerScreen modal | AT-056a2 | Phase 4 |
| US-056 | Project switch → selection reset, next report unfiltered | project switch + next trigger | AT-056a3 | Phase 4 |
| US-056 | Hostile filename → dropdown POPULATES, overlay opens + renders literally, markup-safe status, no `MarkupError` | selector + overlay + status | AT-056b | Phase 4 |
| US-056 | Fresh app / none selected → full report | selector default | AT-056c | Phase 4 |
| US-056 | Typed free path: valid file → next report filtered; missing file → refusal | free path input → next trigger | AT-056d | Phase 4 |
| US-056 | With a filter SELECTED, the A2B diff report stays complete — byte-identical to a no-filter A2B run | A2B report shipped surface | AT-056e | Phase 4 |
| US-057 | Two labeled sections; ids + AT-032a span survive | Patch Editor screen | AT-057a | Phase 4 |
| US-057 | Every button/binding behaves as pre-batch | Patch Editor screen | AT-057b | Phase 4 |

**Functional chain (white-box) — per requirement:**

| Requirement | Method | Test case | Notes |
|-------------|--------|-----------|-------|
| HLR-053 | test | TC-307, TC-308, TC-309 + AT-053a/b | |
| LLR-053.1 | test (unit) | TC-307, TC-308 | envelope + fault matrix |
| LLR-053.2 | test (unit) | TC-309 | cap, never-raise, hostile corpus |
| LLR-053.3 | test (unit) | TC-309 | ceilings boundary-exact |
| LLR-053.4 | test (unit) | TC-310 | D-1 truth table + fnmatchcase pin |
| LLR-053.5 | test (pilot) | AT-053a | both surfaces, zero files, refusal before worker |
| LLR-053.6 | test (pilot) | AT-053b, AT-056b | C-17 status side + Q-7 message budget |
| LLR-053.7 | test (unit + pilot) | TC-310 + AT-053a | resolved matcher, never-raise classification, resolve-before-first-write |
| HLR-054 | test | TC-311..313 + AT-054a/b/c | |
| LLR-054.1 | test (integration) | TC-311 | one matcher kwarg; unfiltered kwargs byte-for-byte today's |
| LLR-054.2 | test (integration) | TC-312 | D-2/D-5 both formats; F-03 window semantics + A9 case |
| LLR-054.3 | test (integration) | TC-312, TC-314 + AT-054c/055c | audit header (position, per-section counts), zero-match, Q-12 wording |
| LLR-054.4 | test (golden) | AT-054b | double-proof, environment pin |
| LLR-054.5 | inspection + test | TC-313 + AT-056e | A/B diff always complete (Q-5 black-box arm) |
| HLR-055 | test | TC-314, TC-315 + AT-055a/b/c | |
| LLR-055.1 | test (unit+integration) | TC-315 | ReportOptions matcher field, UI-thread capture, worker argument |
| LLR-055.2 | test (integration) | TC-314 | three surfaces, symbol+range checklist match, end-exclusive boundary |
| LLR-055.3 | test (golden) | AT-055b | double-proof, environment pin |
| LLR-055.4 | test (unit) | TC-318 | C-17 file side (white-box seam; black-box arm = AT-053b) |
| HLR-056 | test | TC-316, TC-317 + AT-056a/a2/a3/b/c/d/e | |
| LLR-056.1 | test (unit) | TC-316 | scan + validate_project_files regression |
| LLR-056.2 | test (pilot) | AT-056a, AT-056b, AT-056c | selector row, reopen seeding, option-label escape (C-15 probe at Phase 3 entry) |
| LLR-056.3 | test (pilot) | AT-056a, AT-056a3 | sticky state; project-switch reset (F-09 funnel) |
| LLR-056.4 | test (unit+pilot) | TC-317 + AT-056d | free path, symlink refusal + swap case (S-F2), typed-path arm |
| LLR-056.5 | test (pilot) | AT-056a2 | C-13, ladder in body, TC-024.6 per-width idiom |
| HLR-057 | test | TC-319 + AT-057a/b | |
| LLR-057.1 | test (pilot) | AT-057a, TC-319 | ids + parentage + grid-3 pin GREEN |
| LLR-057.2 | test (pilot) | existing AT-032a/AT-052a unmodified | |
| LLR-057.3 | test (pilot) | AT-057b + existing suite unmodified | |
| LLR-057.4 | test (snapshot) | TC-320 (xfail set assertion) | 2 patch cells only |

### 5.3 Batch acceptance criteria
- 100% of LLRs covered by ≥1 TC or AT with a pass result; 0 blocker failures.
- Every US has ≥1 passing AT observing its outcome through the shipped surface with boundary +
  negative evidence (table above).
- Both byte-identity goldens pass under the declared fixed-clock environment pin with the
  double-proof executed and recorded (LLR-054.4/055.3).
- 0 diffs vs `main` in the engine-frozen set (`tests/test_engine_unchanged.py` green).
- Full suite green except the declared 2-cell patch snapshot xfail set (LLR-057.4:
  29 green / 2 xfail / 0 unexpected).
- Existing AT-032a/AT-052a/AT-038* pass with 0 un-censused edits to their assertion bodies
  (census-authorized extends recorded per LLR-057.3).

---

## 6. Appendices

### 6.1 Extended glossary
Covered in §1.3.

### 6.2 Relevant design decisions
- **D-1..D-5 (PLAN, adopted):** match semantics (a/b/c); filtered surfaces with whole
  header/statistics/inventory; zero-match still writes with loud notice; envelope
  `s19app-report-filter` 1.0 end-exclusive; filter-before-window-merge.
- **D-6 (NEW, this document) — selector home = one row in `ReportViewerScreen`, sticky
  app-level state consumed by both triggers.** Candidates compared:
  (A) *chosen* — one selector in the report viewer (`screens.py:875-918`), sticky
  `_report_filter_path`, both triggers consult at generation time. Pros: single widget, modal
  vertical layout with a proven `1fr` absorber (`styles.tcss:1119-1121` precedent), zero
  patch-editor geometry risk, one state, C-10 provable across both surfaces. Cons: the `b`
  operator must have visited the report screen to select — mitigated by the status line and
  audit header always naming the applied filter (or none is default, matching today).
  (B) duplicate selectors in the patch editor + report viewer — better locality for `b`, but
  the change-file pane is the tightest cell (~35 cols @80, `styles.tcss:692-696` measured
  comment) already growing by the US-057 regroup, plus duplicated state sync. Rejected.
  (C) a per-press modal before each report — purest "per-run" but adds a step to a one-key
  flow and breaks the AT-038 pilot flows. Rejected.
- **D-7 (NEW) — diagnostics style = crc_config `(obj|None, list[str])`**, not
  changes/io `ValidationIssue` (rationale in LLR-053.2).
- **D-8 (NEW) — ceilings = 4096/4096** mirroring `CRC_SPAN_COUNT_CEILING`
  (rationale in LLR-053.3).
- **D-9 (Phase-2 fold, 02-review) — resolved-matcher architecture.** Parse + resolve on the
  UI THREAD at trigger time: the app resolves the selected filter against
  `loaded.mac_records` + `_compute_a2l_enriched_tags()` into a `ReportFilterMatcher`
  (patterns + pre-built sorted matched-address ranges, LLR-053.7); ONLY the matcher (default
  None) flows onward — composer kwarg (LLR-054.1), `ReportOptions` field + worker argument
  (LLR-055.1). NO `a2l_records`/`mac_records` kwargs on any generator call — annotation
  inputs stay byte-identical (kills F-01); the matcher carries branch (c) to the project
  report (kills F-02-ii); UI-thread capture + refusal-before-worker kills F-04's stale/torn
  window and refuses ahead of the expensive variant run.
- **D-10 (Phase-2 fold, F-11) — empty include lists are VALID** → the zero-match loud path
  (AT-054c/AT-055c). Supersedes 01b's P6 reject-preference, allowed by its own fallback
  clause.
- **Requirement ledger sites:** filter → **R-RPT-FILTER-001**; regroup → **R-TUI-045**
  (both verified free, §1.4).

### 6.3 Open risks (for Phase-2 focus)
1. **Byte-identity breadth** — LLR-054.4/055.3 depend on every new parameter defaulting to
   absent AND no incidental formatting drift; the goldens are the net, but they cannot be
   captured until Phase 3 (`unexecuted` flag in the probe ledger).
2. **D-1(c) blast radius** — name-matched artifact records pull in windows for entries with
   no linkage symbol; a broad glob (`*`) makes the "filtered" report near-complete. Accepted:
   whitelist semantics are operator-owned; the audit header still reports shown/hidden.
   Post-F-1 note: extent semantics widens each matched record from 1 byte to its `byte_size`
   — still bounded by the loaded artifact's own declarations; `byte_size=None` records fall
   back to point, so unresolvable layouts never over-match.
3. **Selector geometry** — LLR-056.5 is `assumed — measure in Phase 3`; ladder is
   deficit-matched but rung 3 changes the buttons-row composition (minor snapshot risk if any
   modal snapshot exists — flagged in LLR-057.4 acceptance).
4. **PLAN staleness corrected here:** the C-17 status-funnel claim (see LLR-053.6). Phase-2
   reviewers must confirm no OTHER filter-text path reaches a markup-enabled widget
   (`#status_text` via `set_file_status` is the known residual, excluded by LLR-053.6).
5. **Zero-match vs invalid confusion** — the operator must be able to distinguish "filter
   valid, matched nothing" (report written, AT-054c) from "filter invalid" (refusal,
   AT-053a); the two paths share no wording — AT-054c asserts the disjointness (no shared
   prefix token, Q-12; LLR-053.5 vs LLR-054.3 texts).
6. **Per-run re-parse cost** — 4096-pattern worst case per report run is unbenchmarked;
   `analysis` deferred: `assumed — verify in Phase 3` with a perf smoke. THREADING CORRECTION
   (S-F3): the `b` path runs SYNCHRONOUSLY on the UI thread (`app.py:1867-1882`) — only the
   project report runs on a worker (`app.py:2297`), and under D-9 the parse+resolve step runs
   on the UI thread on BOTH paths; the 4 MiB filter cap (LLR-053.2) + the 4096 ceilings
   (LLR-053.3) bound the stall.

### 6.4 Phase-1 reconciliation log

| Decision ID | What changed | Parent HLR re-read? | Body edit landed? |
|-------------|--------------|---------------------|-------------------|
| F-1 (orchestrator fold, Phase-1 gate 2026-07-10) | LLR-053.4(c) point semantics → EXTENT semantics: name-matched record covers `[addr, addr + (byte_size or 1))`; enriched A2L tags carry `byte_size` at `a2l.py:1200` (verified), MAC records stay point. Gap class: point semantics could silently hide a patch to byte 2..n of a filtered-for parameter. TC-310 gains the tail-byte pin; §1.3 definitions updated. | HLR-053/054/055 re-read — statements unaffected (they bind to "match the filter", semantics live in LLR-053.4) | Yes |
| F-2 (orchestrator fold, Phase-1 gate 2026-07-10) | LLR-053.4(a) gains an exact-equality short-circuit (`s == pattern` OR `fnmatchcase`) closing QA gap G6 (01b §3.1): a literal A2L name containing fnmatch metacharacters (`PAR[0]`) now matches itself; glob over-match documented informative. TC-310 gains the discriminating pair; §1.3 updated. | HLR-053 re-read — unaffected | Yes |
| F-01 + D-9 (Phase-2 amendment, 02-review 2026-07-10) | LLR-054.1 REWRITTEN: composer gains ONE `report_filter` kwarg (resolved matcher); NO `a2l_records`/`mac_records` on any generator call — annotation inputs untouched, unfiltered run-table bytes cannot drift; TC-311 asserts unfiltered kwargs byte-for-byte today's. §2.1 plumbing facts swept. | HLR-054 re-read — statement unaffected (pin lives in LLRs) | Yes |
| F-02 (Phase-2 amendment) | FALSE claim corrected in LLR-055.2 + §2.1: `CheckRunEntry.linkage_symbol` EXISTS (`changes/model.py:678`, populated `changes/check.py:346`/`:387`); checklist rows match via branch (a) OR range intersection; the resolved matcher (D-9) delivers branch (c) to the project report. | HLR-055 re-read — unaffected | Yes |
| Q-1 (Phase-2 amendment) | Golden mechanism (a) pinned in HLR-054/055 + LLR-054.4/055.3: byte-identity ATs drive the SHIPPED surface with `_default_now` (+ diff-report clock seam, generic name, Phase-3 resolution) monkeypatched as a declared ENVIRONMENT PIN; base golden captured with the IDENTICAL pin; handlers pass no `now_fn` (`app.py:1868-1873`, `:2372-2374`). §1.3, §5.1, §5.3 swept. | HLR-054/055 statements amended (§6.5 #1/#2) | Yes |
| F-03 + Q-2 (Phase-2 amendment) | LLR-054.2 merged-window semantics pin: filter hides ITEMS (rows + windows SEEDED by unmatched runs); merged/context rows MAY cover excluded addresses with informative audit note; TC-312 threshold re-scoped to linkage rows + window headings; A9 case added. | HLR-054 re-read — unaffected | Yes |
| F-04 (Phase-2 amendment, via D-9) | LLR-055.1 + LLR-053.5: selection captured+parsed+resolved on the UI thread in `_trigger_generate_report` BEFORE the worker starts; matcher passed as WORKER ARGUMENT; invalid filter refuses before any variant execution; thread contract documented. | HLR-055 re-read — unaffected | Yes |
| F-05 (Phase-2 amendment) | LLR-056.2: (i) reopen-seeding from `_report_filter_path` (precedent `screens.py:894-900`); (ii) Select option-label escape pinned (`rich.markup.escape` or `Text` prompt) + C-15 runtime probe of Select option markup on textual==8.2.8, `probe at Phase 3 entry`; AT-056b extended (dropdown populates, overlay opens, literal render, no `MarkupError`). | HLR-056 re-read — unaffected | Yes |
| F-06 + Q-11 (Phase-2 amendment) | 01b→01 AT registry reconciled (table below); 01 declared CANONICAL; LLR-057.3 threshold reworded to "0 un-censused edits; census-authorized extends recorded". | HLR-057 re-read — unaffected | Yes |
| Q-3 (Phase-2 amendment) | AT-053b REDEFINED: valid filter, hostile FILENAME+PATTERNS → generation PROCEEDS on both kinds → literal confirmation (Q-7 budget) + every written file re-read, sanitation asserted. HLR-053 acceptance, LLR-053.6/055.4, §5.2 swept. | HLR-053 re-read — statement unaffected | Yes |
| Q-4 (Phase-2 amendment) | NEW AT-056d (typed-path arm through the surface: valid → filtered; missing → refusal); added to HLR-056 acceptance, LLR-056.4 verification, §5.2. | HLR-056 re-read — unaffected | Yes |
| Q-5 (Phase-2 amendment) | NEW AT-056e (filter SELECTED → A2B diff via shipped surface byte-identical to no-filter run); attached to LLR-054.5, upgrading it from inspection+TC-313. | HLR-054 re-read — unaffected | Yes |
| Q-6 (Phase-2 amendment) | AT-056a SPLIT → AT-056a (selection → byte-diff both triggers + audit header), AT-056a2 (geometry at 80x24 + 120x30, TC-024.6 idiom), AT-056a3 (project-switch reset); one on-disk node each (C-18); AT-053a explicitly stays ONE node. LLR-056.2/.3/.5 + §5.2 updated. | HLR-056 re-read — unaffected | Yes |
| Q-7 (Phase-2 amendment) | Status message budget in LLR-053.6 + LLR-056.3: confirmation carries the filter filename; refusal carries the kind-prefixed named fault; each fits the 50-char funnel or leads with its token; each AT asserts the message carrying its token. | HLR-053/056 re-read — 056 unaffected; 053.6 statement amended (§6.5) | Yes |
| Q-8 (Phase-2 amendment) | TC-319/TC-320 given one-line bodies under LLR-057.1/057.4 executed verification. | HLR-057 re-read — unaffected | Yes |
| Q-9 (Phase-2 amendment) | TC-310 extended: `byte_size=None` → extent 1; `byte_size=0`/non-positive → extent 1 (positive-integer boundary pin); extent-END negative twin; MAC-point vs A2L-extent divergence fixture. | HLR-053 re-read — unaffected | Yes |
| Q-10 (Phase-2 amendment) | LLR-053.1 address domain pinned `0 <= start < end <= 2^32` (crc_config precedent), named diagnostic outside; hex/int equivalence case (`0x10` == `16`); unbalanced-bracket `CAL_[` documented literal-inert (accepted, TC case, no rejection). | HLR-053 re-read — statement unaffected | Yes |
| Q-12 (Phase-2 amendment) | AT-054c additionally asserts zero-match notice wording disjoint from refusal wording (no shared prefix token); LLR-054.3 + §6.3 risk 5 updated. | HLR-054 re-read — unaffected | Yes |
| F-07 (Phase-2 amendment) | LLR-054.3 item-count basis per surface: before/after = linkage entries; project report = per section (Modifications / Checklists / regions), header states each; shown+hidden == pre-filter count per section. | HLR-054/055 re-read — unaffected | Yes |
| F-08 (Phase-2 amendment) | Citations fixed: `_compute_a2l_enriched_tags` def `app.py:8009`; `Select.NULL` runtime handling `screens_directionb.py:2148-2159`; A2B precedent divergence noted (`allow_blank=False` + `_EXTERNAL_OPTION` vs specced `allow_blank=True`, one-line justification in LLR-056.2). | n/a (citation precision) | Yes |
| F-09 (Phase-2 amendment) | LLR-056.3 reset funnel NAMED: every path swapping the active project/loaded file set (project load/create/close, loose-file load); Phase 3 locates + cites the common funnel; flagged `assumed — verify funnel completeness in Phase 3`. | HLR-056 re-read — unaffected | Yes |
| F-10 (Phase-2 amendment) | LLR-053.4 informative note: extent-matched row may still annotate `-` in the Symbols column; divergence accepted, documented in format docs. | HLR-053 re-read — unaffected | Yes |
| F-11 (Phase-2 amendment) | D-10 recorded in §6.2: empty include lists = VALID → zero-match loud path (supersedes 01b P6 reject-preference via its fallback clause). | HLR-053 re-read — unaffected | Yes |
| S-F1 (Phase-2 amendment) | LLR-053.6 extended: routing filter-derived text via `notify()` or `set_file_status` is prohibited; Phase-3 exit grep covers new call sites of BOTH (`set_status` is inert, excluded). | HLR-053/056 re-read — see §6.5 | Yes |
| S-F2 (Phase-2 amendment) | LLR-053.2: `read_report_filter_text` refuses symlink/non-regular-file AT READ TIME with named diagnostic; TC-317 swap case added (dropdown-selected file replaced by symlink before generation → refusal). | HLR-053 re-read — unaffected | Yes |
| S-F3 (Phase-2 amendment) | LLR-053.2 cap → filter-specific 4 MiB (constant NEW, Phase 3; "not larger than the shared `READ_SIZE_CAP_BYTES`"); §6.3 risk 6 threading claim corrected (b-path synchronous on UI thread, `app.py:1867-1882`); Phase-3 perf smoke kept. | HLR-053 re-read — unaffected | Yes |
| S-F4 (Phase-2 amendment, via LLR-053.7) | Never-raise extended to resolution + classification for any record shape; all per-run filter computation completes before the first file write. | HLR-053 re-read — unaffected | Yes |
| S-F5 (Phase-2 amendment) | LLR-055.4: non-cell header lines pass ctl-strip at minimum (structurally sufficient); LLR-056.4: out-of-project free paths ALLOWED (read-only input, change-set precedent), no write ever outside `reports/`. | HLR-055/056 re-read — unaffected | Yes |
| S-F6 (Phase-2 amendment) | LLR-054.3 informative pin: audit header = FIRST block after the title, fixed line format; TC-312/TC-314 assert its position. | HLR-054/055 re-read — unaffected | Yes |

#### 01b→01 AT registry reconciliation (F-06 / Q-11) — 01 is CANONICAL

| 01b id | 01b meaning | Disposition in 01 (canonical) |
|--------|-------------|-------------------------------|
| AT-053b | hostile-content refusal observer | REDEFINED as 01's AT-053b per Q-3 (valid hostile filter → proceed + files re-read) |
| AT-053c | match-semantics observer | superseded by TC-310 (white-box truth table; Q-11 record) |
| AT-054d | file-side sanitation observer | ABSORBED into the redefined AT-053b |
| AT-056c | A2B exempt-guard | renumbered → NEW AT-056e (01's AT-056c = fresh-default, kept) |
| AT-055c | — (01-only id) | 01's zero-match project-report AT, kept as-is |

### 6.5 Requirement amendments (Before / After · Deleted / New)

Phase-2 amendment pass (02-review fold list, 2026-07-10). Clause-level records; full amended
statements live in §3/§4. Each record: requirement · Before (superseded clause) · After
(amended clause) · driving finding(s).

1. **HLR-054 (Amended).** Before: "...the system shall write output byte-identical to the
   unfiltered output of this tree's base revision." After: adds "...byte-identity being
   defined under the declared fixed-clock environment pin (LLR-054.4)." — Q-1.
2. **HLR-055 (Amended).** Same clause as #1, pin ref LLR-055.3. — Q-1.
3. **LLR-053.1 (Amended).** Before: rejects "non-parsable or negative address". After: address
   domain pinned "0 <= start < end <= 2^32 (crc_config address-domain precedent)"; rejects
   "address outside the pinned domain". — Q-10.
4. **LLR-053.2 (Amended).** Before: "reject files over `READ_SIZE_CAP_BYTES` (shared cap —
   imported, not redefined)". After: "reject files over a filter-specific cap of 4 MiB
   (constant NEW — Phase 3; not larger than the shared `READ_SIZE_CAP_BYTES`)" + "shall
   refuse a path that is a symlink or not a regular file AT READ TIME with a named
   diagnostic". — S-F3, S-F2.
5. **LLR-053.5 (Amended).** Before: refusal surfaced by "`action_before_after_report` and
   `_start_generate_report_worker`". After: "`action_before_after_report` and
   `_trigger_generate_report` (`app.py:2226` — on the UI thread, BEFORE
   `_start_generate_report_worker` is started)... shall not invoke their generator or start
   the worker"; scope extended to resolution failures. — F-04, D-9.
6. **LLR-053.6 (Amended).** Before: exclusivity over the `set_status` funnel + markup=False
   on new widgets. After: adds "filter-derived text shall NOT be routed through `notify()`
   or `set_file_status`" + the Q-7 message budget (confirmation carries filename; refusal
   carries kind-prefixed fault; each fits the 50-char funnel or leads with its token). —
   S-F1, Q-7.
7. **LLR-053.7 (NEW).** Resolved matcher: `resolve_report_filter(filter, a2l_records,
   mac_records) -> ReportFilterMatcher`, built once per run, classification methods on the
   matcher, never-raise extended to classification, all per-run computation before the first
   file write. — D-9, S-F4, F-02-ii.
8. **LLR-054.1 (Amended — rewrite).** Before: composer accepts `report_filter` +
   `a2l_records` + `mac_records` and forwards all three into both generators. After: composer
   accepts exactly ONE kwarg `report_filter` (resolved matcher); NO artifact-record kwargs on
   any generator call — annotation inputs untouched; the app resolves at trigger time on the
   UI thread (`_compute_a2l_enriched_tags` def `app.py:8009`). — F-01, D-9, F-08.
9. **LLR-054.2 (Amended).** Before: restrict rows/windows, filter-before-merge, sections
   complete. After: adds the semantics pin "the filter hides ITEMS — rows and windows SEEDED
   by unmatched runs; merged-window/context rows of matched-seeded windows MAY cover excluded
   addresses, disclosed by an informative audit note". — F-03, Q-2.
10. **LLR-054.3 (Amended).** Before: header names filter + shown/hidden counts. After: adds
    the per-surface item-count basis (before/after = linkage entries; project report = per
    section, header states each; shown+hidden == pre-filter count per section). — F-07.
11. **LLR-054.4 (Amended).** Before: byte-identical "for the same inputs and injected clock".
    After: production through the SHIPPED `b`-key surface with `_default_now` (+ diff-report
    clock seam) monkeypatched as a declared ENVIRONMENT PIN; base golden captured through the
    same surface with the IDENTICAL pin. — Q-1.
12. **LLR-055.1 (Amended — rewrite).** Before: field `Optional[ReportFilter]`; worker
    "populates it from the app-level selection after a successful parse". After: field holds
    the RESOLVED `ReportFilterMatcher`; capture+parse+resolve on the UI thread in
    `_trigger_generate_report` BEFORE the worker starts; matcher passed as explicit WORKER
    ARGUMENT; worker never re-reads app state. — F-04, D-9.
13. **LLR-055.2 (Amended).** Before: checklist rows match by range intersection (claim:
    "check entries carry no `linkage_symbol`"). After: checklist rows match via branch (a) on
    `CheckRunEntry.linkage_symbol` (`changes/model.py:678`) OR range intersection. — F-02.
14. **LLR-055.3 (Amended).** Same pin as #11 through the Generate surface; worker passes no
    `now_fn` (`app.py:2372-2374`). — Q-1.
15. **LLR-055.4 (Amended).** After adds: "non-cell header lines (audit header, notices) shall
    pass control-character stripping at minimum". — S-F5.
16. **LLR-056.2 (Amended).** After adds: reopen-seeding from `_report_filter_path`
    (`screens.py:894-900` precedent); Select option labels markup-escaped at construction
    (`rich.markup.escape` or `Text` prompt); C-15 citation corrected to the A2B `Select.NULL`
    runtime handling (`screens_directionb.py:2148-2159`); new C-15 probe declared for option
    markup on textual==8.2.8. — F-05, F-08.
17. **LLR-056.3 (Amended).** Before: "reset to None on project switch";
    `_start_generate_report_worker` consults the field. After: consult moved to
    `_trigger_generate_report` (UI thread); reset on EVERY path swapping the active
    project/loaded file set (load/create/close, loose-file load; funnel located at Phase 3);
    confirmation message budget per Q-7. — F-09, Q-7, D-9.
18. **LLR-056.4 (Amended).** After adds: "an out-of-project free path is ALLOWED (read-only
    input, change-set precedent), and no write shall ever occur outside
    `<project>/reports/`". — S-F5.
19. **LLR-054.4 (Amended, Inc-0 gate 2026-07-10).** Before: "shall be byte-identical to the
    outputs captured at this batch's base revision ... `filecmp`/bytes equality == True".
    After: "byte-identical IN CANONICAL FORM", canonical form normalizing exactly two
    environment classes — (a) platform newline translation (CRLF→LF: the writers use
    `Path.write_text` with no `newline=` pin, diff_report_service.py:1153/:1705,
    report_service.py:1242), (b) the per-run absolute run-root path (embedded in 4-5 content
    lines; masked `<RUN-ROOT>`, separators normalized only inside masked spans) — every other
    byte exact. Rationale: raw-byte equality through the shipped surface is infeasible on any
    per-run tmp root and cross-platform (proven by Inc-0's double-run probe); the guard's
    intent (generator drift detection) is fully preserved. Also resolves the "diff-report
    clock default seam" to its exact symbols: `diff_report_service._default_now` +
    `changes/apply.py` `datetime` (second clock discovered at Inc-0: `ChangeSummary.
    timestamp_utc` prints as `Applied (UTC)` in both formats). — Inc-0 deviation flag,
    ratified at the Inc-0 gate.
20. **LLR-055.3 (Amended, Inc-0 gate 2026-07-10).** Same canonical-form definition by
    reference to LLR-054.4. — Inc-0 deviation flag.

Record count: 19 amended + 1 new; no requirement deleted.
