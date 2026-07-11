# PLAN — batch-35 · Report filter file + patch-editor regroup (B-07, last P1)

> Living compendium. Updated at every gate + significant checkpoint.

## Where we are
- **Phase 5 — post-mortem in flight.** Phase 3 CLOSED (7 increments, Inc-0..6, commits
  92df3f4..428470a + folds; ALL reviews APPROVE, 0 HIGH across the batch; suite 1244→1335
  not-slow, goldens green throughout, frozen 0 diffs every increment). Phase 4 PASS
  (04-validation.md: 25/25 LLRs, 17/17 ATs C-18-single-noded, goldens double-proven thrice,
  census 14/14, perf measured, ledger 1363 collected = 1270+93 exact). Owed Phase 6:
  REQUIREMENTS.md rows R-RPT-FILTER-001/R-TUI-045 + operator format docs (+ ceiling-perf
  note). Post-merge: canonical snapshot regen (retire both batch-35 marks; 120x30 = real
  drift, 80x24 defensive) + ubuntu CI as the cross-platform canonicalization proof.
- Phase-3-era status (superseded): DONE: **Inc-0** `92df3f4` goldens (canonical-form ratified
  §6.5 #19/#20; double-proven ×3; reviewer re-derived byte-identical; APPROVE) → **Inc-1**
  `2f237d1` filter engine (56 TCs; reviewer oracle-checked 18k probes, 0 divergences; APPROVE;
  gate folds `d9a73c2`: D-10a + LLR-053.4 reword) → **Inc-2** `58d7c7e` before/after filtering
  (audit header first-block, filter-then-merge, zero-match notice; goldens HELD; suite 1311).
  Process incidents logged for Phase 5: stash-RED trap on untracked files (batch-29 leftover
  stash popped → state.json conflict, resolved; move-aside is the net-new-module RED idiom);
  agents backgrounding pytest (3 stalls, Inc-0).
- Superseded Inc-0 status: Phase 2 APPROVED 2026-07-10 after one
  amendment round: triple review found 3 blockers (F-01 record-forwarding byte-drift, F-02
  project-report branch-(c)/linkage_symbol, Q-1 unreachable clock seam) + 10 majors → ALL 25
  findings folded under the **D-9 resolved-matcher** architecture (UI-thread parse+resolve at
  trigger → matcher is the only forwarded object); independent checklist verification CLEAN
  12/12. Final census **17 ATs / 14 TCs**; §6.4 = 29 rows + AT registry; §6.5 = 18 records.
  Increment cut: Inc-0 goldens → Inc-1 report_filter.py → Inc-2 before/after → Inc-3 project
  report → Inc-4 selector UX → Inc-5 regroup (independent).
- Phase-2 history (superseded):
  Phase 0 approved (RC-1 PASS @ 79699a5 — #63 merged; 5 stories READY). Phase 1 approved after one
  fold round: 01-requirements.md = 5 US / 5 HLR / 24 LLR / 13 AT / TC-307..320; **D-6** selector =
  one row in ReportViewerScreen + sticky path-only `_report_filter_path` consumed by BOTH triggers,
  reset on project switch; **D-7** crc_config diagnostics style; **D-8** ceilings 4096/4096.
  Orchestrator folds at the gate: **F-1** D-1(c) point→EXTENT (`[addr, addr+(byte_size or 1))`,
  byte_size verified on enriched tags a2l.py:1200 — point semantics could hide mid-parameter
  patches; resolves QA-1); **F-2** equality short-circuit `s == pattern` OR fnmatchcase (closes G6
  `PAR[0]` hazard). Architect draft-time corrections: C-17 status claim STALE (batch-33 already
  made the log-label funnel markup=False; residual = `#status_text` via set_file_status + any NEW
  widget); `generate_diff_report` ALREADY accepts a2l/mac records — only the composer signature +
  handler gather are new.

## Recon findings (exploration agent, 2026-07-10)
- **Before/after report** = thin composer `before_after_service.compose_before_after_report`
  (:182) → BOTH diff-report generators (`generate_diff_report`/`_html`, diff_report_service.py
  :1030) with `linkage_entries=summary.entries`; app handler `action_before_after_report`
  (app.py:1834, key `b`). Composer does NOT currently pass `a2l_records`/`mac_records` — symbol
  data reaches rows only via `ChangeSummaryEntry.linkage_symbol` (changes/model.py:320; rows carry
  symbol + address_start/end already).
- **Project report** = `report_service.generate_project_report` (:1128) + frozen `ReportOptions`
  (:143, one ValueError per fault); sections: Modifications table (reads `entry.linkage_symbol`,
  :657), Checklists, Memory regions hexdumps (:871), addendum. App: `_start_generate_report_worker`
  (app.py:2296) → `generate_project_report` (:2372).
- **Parse pattern to mirror:** crc_config.py — `read_*_text` + `parse_*` split returning
  `(obj|None, list[str])`, one collected error per fault, never raises; size-cap
  `READ_SIZE_CAP_BYTES` pre-read; `resolve_input_path` (workspace.py:471). Change-set io.py gives
  the `format`/`version` envelope precedent (`s19app-changeset` 2.0) — filter file adopts BOTH.
- **Selection UX precedent:** A2B Diff panel — `Select` + `OsClipboardInput` path pair
  (screens_directionb.py:2484-2492, `_EXTERNAL_OPTION` sentinel); population idiom
  `_scan_patch_change_files` (app.py:2505: `glob("*.json")`, symlink-skip, sorted).
- **`validate_project_files` (workspace.py:323) skips subdirectories** → a `filters/` subdir
  (mirroring `reports/`) is safe; loose `.json` in the project dir is also ignored.
- **NO fnmatch/glob-pattern matching exists in production** — net-new (use `fnmatch.fnmatchcase`).
  Address-range matching reuses `range_index` (frozen — consume, don't modify).
- **C-17 CONFIRMED REAL:** `set_status` → `Label.update` (app.py:8880/8896) interprets Rich markup;
  NO call site escapes today. A "filter: <name>" status line MUST be markup-escaped. Also:
  report_service does NOT escape interpolations (reports = files on disk, lower risk) — filter
  name echoed into the audit header follows the diff-report `_md_cell`/`_esc` discipline anyway.
- **Tests:** test_before_after_report.py (Pilot ATs AT-038*), test_report_service.py,
  test_diff_report_service.py, test_crc_config.py (parse precedent).

## Objective
B-07 (operator: "one of the most important changes"), two halves:
1. **Report filter file** — operator-authored JSON whitelist that restricts what the before/after
   report and the project report show; unfiltered = today's full report, byte-identical.
2. **Patch-editor regroup** — separate, clearly labeled sections for patch-script vs check-script
   controls (currently one mixed button row).

## Locked operator decisions (2026-07-10)
- **Match keys:** symbols + addresses — an item appears if its A2L/MAC symbol name matches OR its
  address falls in a listed range.
- **Wildcards:** glob patterns on symbol names (`CAL_*`); exact names still work.
- **Report scope:** before/after report + project report ONLY. The A/B diff report stays
  always-complete (a filtered diff could hide unexpected deltas).
- **Selection:** per-run dropdown listing the project's `filters/*.json` + free path input with
  paste support; "none" = full report (default unchanged).
- **Strawman format (Phase-1 to firm):**
  `{"format": "s19app-report-filter", "version": "1.0", "include": {"symbols": [...], "addresses": [{"start","end"}]}}`
- **Audit header:** a filtered report states which filter was applied and how many items it hid —
  a filtered report must never pass for a complete one (no-silent-truncation rule).

## Route
Full /dev-flow: new operator-JSON input surface (parse rejections, hostile content), file-derived
symbol names + filter filename rendered into MD/HTML and TUI status (C-17 class), and a
report-semantics change to two shipped surfaces. Standing authorization carried (batches 29/31–34
model): autonomous phases, packets in-conversation, NO self-merge, 0 engine-frozen diffs,
propose-not-encode controls, snapshot regen canonical-CI-only.

## RC-1 (pending)
Branch `feat/batch-35-report-filter` from origin/main AFTER #63 merges (batch-34 squash).
Nothing-shipped check: no filter concept in either report service; patch-editor right pane still a
mixed button row.

## Design defaults (adopted pending operator override — batch-32 Q1-Q4 model)
- **D-1 Match semantics (symbol resolution):** an item shows if (a) its `linkage_symbol` matches
  any pattern (`fnmatch.fnmatchcase`), OR (b) its address range intersects any explicit filter
  range, OR (c) its address range intersects the address of any loaded A2L/MAC record whose NAME
  matches a pattern — so `CAL_*` pulls in the memory windows of every CAL parameter even when a
  change entry carries no linkage_symbol. (c) requires passing `a2l_records`/`mac_records` into
  the before/after composer (app already holds them). Alternative on file: (a)+(b) only.
- **D-2 Filtered surfaces:** Modifications/linkage rows, checklist rows, and hex windows (only
  windows intersecting the matched address set); header/statistics/inventory stay whole —
  statistics gain "shown/hidden" counts (audit header).
- **D-3 Empty result:** a filter matching NOTHING still writes the report with a loud
  "filter matched 0 of N items" notice — never a silently empty file.
- **D-4 Envelope:** `format: "s19app-report-filter"`, `version: "1.0"`, `include.symbols` +
  `include.addresses` (start/end hex-or-int, end exclusive to match ChangeSummaryEntry); unknown
  top-level keys → named error (crc_config one-error-per-fault style).
- **D-5 Window interaction:** filtering selects runs/entries BEFORE window computation, so
  batch-34 merged windows are computed over the filtered set (no half-filtered windows).

## Stories (Phase 0 — all READY 2026-07-10)
| US | Status | What (observable outcome) | Black-box AC seed |
|----|--------|---------------------------|-------------------|
| US-053 filter file + rejection diagnostics | READY | Operator authors `filters/*.json`; an invalid filter REFUSES report generation with named per-fault errors (never a silent full/partial report), 0 files written | AT-053a: bad envelope → refusal + named error on status, reports/ unchanged |
| US-054 filtered before/after report | READY | With a filter selected, the `b`-key report shows only matching linkage rows + overlapping hex windows, audit header names filter + hidden count; no filter → byte-identical | AT-054a match/omit + header; AT-054b no-filter golden (double-proof) |
| US-055 filtered project report | READY | Same contract on `generate_project_report` surfaces (Modifications, Checklists, Memory regions) | AT-055a match/omit + header; AT-055b no-filter golden |
| US-056 filter selection UX | READY | Dropdown lists project `filters/*.json` (symlink-skipped, sorted) + free path input; none = default; selection drives the NEXT generated report | AT-056a non-default selection changes output (C-10); AT-056b hostile filename markup-safe on status (C-17) |
| US-057 patch-editor regroup | READY | Patch-script controls (Load/Validate/Apply/Save) and check controls (Run checks + help) appear as two labeled sections; all button ids + AT-032a help token span preserved | AT-057a pilot queries both section labels + button parentage; bindings regression |

INVEST notes: all Independent except US-054/055 depend on US-053's parse+match engine
(implementation order: 053 → 054/055 → 056 → 057; 057 fully independent). All Small-to-Medium;
no SPIKE needed (recon closed feasibility). Out of scope: A/B diff report filtering (operator),
exclude-lists, per-project auto-apply, filter editor UI.

**Open design item for Phase 1 (flagged, not blocking DoR):** WHERE the filter selector lives —
before/after report fires directly on `b` (no dialog) and the project report builds `ReportOptions`
in `_start_generate_report_worker`; the architect must verify both trigger flows and site the
dropdown+path row (patch editor pane? report options surface?) with a C-13 geometry budget.

## QA strategy landed (01b, 2026-07-10) — highest-risk gaps for Phase 2
- **QA-1 D-1(c) semantics + plumbing:** "address intersects a matched A2L/MAC record" is
  intersect-vs-contain ambiguous (a record is a point address — what extent does a symbol cover?);
  and adding `a2l_records`/`mac_records` kwargs to the composer risks perturbing the no-filter
  default path — the double-proof golden (AT-054b/055b) is the tripwire; architect must pin the
  semantics before TC-F2 is writable.
- **QA-2 report_service has NO escaping** (diff_report_service does): the audit header + the
  "matched 0 of N" notice inject filter-derived text into it; every new `set_status` call hits the
  markup-interpreting funnel (app.py:8880). 01-requirements must name the escape mechanism per
  surface or C-17 case H3 ships open.
- **QA-3 D-5 × batch-34 merged windows:** two matched entries whose merge gap spans an EXCLUDED
  entry — gap-context-row semantics undefined; needs a pinned answer + TC pre-implementation.
- **G6 fnmatch metacharacters in real A2L names** (`PAR[0]`): an "exact name" entry silently
  becomes a char-class pattern — format spec must pin escape-or-document before Phase 3.
- Census: ONE true supersession (`test_tui_patch_layout.py:290-325` grid-size-3 pin on
  `#patch_doc_controls`); 2 snapshot cells drift (patch 80x24 + 120x30) → xfail until canonical
  regen; goldens survive as AT anchors. Ledger base **1270 collected** @ 79699a5.

## Risks / watch-items
- Filter semantics on hex windows: only windows overlapping the filtered set render — define the
  interaction with batch-34's merged windows (merge before or after filtering?).
- C-17: filter FILENAME + match counts on any markup-enabled status/log surface; symbol patterns
  (operator JSON = still untrusted at render time) into MD/HTML.
- Unmatched-filter edge: a filter hiding EVERYTHING must render a loud empty-report notice, not a
  silently empty file.
- Glob semantics: fnmatch vs fnmatchcase — pick and pin (A2L symbols are case-sensitive).
- Snapshot drift from the regroup (patch-editor cells) — plan the xfail set up front.
- workspace.py `validate_project_files` (one S19+one MAC+one A2L) — verify a `filters/` subdir
  doesn't trip it.

## Decision log (mirror)
- 2026-07-10 spec gate: 4 operator answers locked (above); full /dev-flow route announced.
- 2026-07-10 P0 started: exploration dispatched; RC-1 waiting on #63.
