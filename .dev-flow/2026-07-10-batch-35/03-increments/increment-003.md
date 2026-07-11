# Batch-35 — Increment 3 (Inc-3): project-report filtering + UI-thread trigger resolution

> Wiring increment on `feat/batch-35-report-filter` @ `58d7c7e` (Inc-0 goldens
> + Inc-1 engine + Inc-2 before/after filtering committed). Implements
> LLR-055.1 (`ReportOptions.report_filter` + UI-thread capture/parse/resolve
> in `_trigger_generate_report` BEFORE the worker, matcher as worker
> argument), LLR-055.2 (filtered Modifications / Checklists /
> `_applied_regions`-fed hexdump surfaces), LLR-054.3 (audit header +
> per-section counts + zero-match notice, S-F6), LLR-055.4
> `report_service.py` half (local ctl-strip, no existing line altered),
> LLR-053.5 Generate half (refusal before worker, zero files), LLR-053.6
> (markup-inert `set_status` route only), plus the Inc-2 review handoff:
> `source_name` promoted to a DECLARED `ReportFilterMatcher` field. The
> Inc-0 AT-055b golden stands guard: unfiltered output is byte-identical.

## 1. What changed

- **`s19_app/tui/services/report_filter.py`** — `source_name: Optional[str]
  = None` promoted from the Inc-2 duck-typed attribute to a DECLARED field
  on `ReportFilterMatcher` (frozen dataclass, no `slots` — the two existing
  `object.__setattr__` test attachments keep working, superseded naturally
  when Inc-4 touches them). `resolve_report_filter` gains an optional
  `source_name` parameter (default `None` → the display fallback stays
  `(unnamed filter)`), stamped onto the matcher with an `isinstance(str)`
  guard (never-raise discipline). Docstrings updated (field, resolver Args /
  Returns). Every existing TC-307..310 node green unmodified.
- **`s19_app/tui/services/report_service.py`** —
  - `ReportOptions` gains `report_filter: Optional[ReportFilterMatcher] =
    None`; `__post_init__` adds ONE explicit `ValueError` on a wrong type,
    matching the existing per-field one-fault pattern (LLR-055.1, TC-315).
  - `generate_project_report` applies the matcher (LLR-055.2):
    (a) Modifications rows via `matches_item(entry.linkage_symbol,
    entry.address_start, entry.address_end)` (shared `_matches_entry`
    helper); (b) Checklists rows via the SAME full item semantics —
    `CheckRunEntry` CARRIES `linkage_symbol` (`changes/model.py:678`, the
    F-02 correction) so a symbol-glob-matched check row renders even with
    its range outside every filter range; per-file aggregates lines keep
    PRE-filter counts (the audit header discloses hidden rows);
    (c) `_applied_regions` gains the optional matcher and filters applied
    ENTRIES (symbol OR range) BEFORE `compute_hexdump_windows` in
    `_hexdump_section` (D-5 filter-then-window).
  - Audit header (`_audit_header_lines`, same fixed format family as
    Inc-2's diff header): FIRST block after the title (S-F6) —
    `## Report filter applied` / `- Filter file: <name>` / three
    `- <section>: shown S of N (hidden H)` lines (Modifications rows,
    Checklist rows, Applied regions — F-07 per-section basis, counts
    aggregated across variants by `_filter_section_counts`) / the F-03
    merged-context note. shown+hidden == pre-filter count per section.
  - Zero-match (LLR-054.3/D-3): a filtered section whose non-empty
    pre-filter set filters to empty replaces its body with
    `filter matched 0 of N items` (`_zero_match_notice`, wording identical
    to Inc-2, prefix-disjoint from refusals per Q-12); the report is still
    written, never silently empty.
  - Sanitation (LLR-055.4 half): `_strip_ctl_local` (twin of the diff
    module's `_strip_ctl`) applied to the filter display name ONLY — the
    module still performs no escaping on any pre-existing output line; not
    one existing line was altered. `_filter_display_name` reads the now
    DECLARED `source_name` field with the `(unnamed filter)` fallback.
  - Unfiltered path: `report_filter=None` short-circuits every new branch —
    no audit header, no filtering, no code-path change (LLR-055.3; AT-055b
    golden + TC-314 no-kwarg equality both green).
- **`s19_app/tui/app.py`** — LLR-055.1 / 053.5-Generate / 053.6:
  - NEW `self._report_filter_path: Optional[Path] = None` in `__init__`
    (existing attribute-block comment style): the sticky selection field
    the Inc-4 selector will write; stores ONLY the path (state-lifetime
    provenance — re-read/re-parse per run).
  - `_trigger_generate_report` (UI thread): when the field is set,
    `read_report_filter_text` → `parse_report_filter` →
    `resolve_report_filter(parsed, self._compute_a2l_enriched_tags() or
    None, loaded.mac_records, source_name=filter_path.name)` — the
    app.py:2984-2992 gather idiom — all BEFORE
    `_start_generate_report_worker` (F-04: refusal precedes any variant
    execution). On ANY read/parse fault: `set_status("Project report
    refused: " + "; ".join(errors))` (kind-prefixed, fault-leading, the
    markup-inert funnel ONLY — no `notify()`, no `set_file_status`), no
    worker, `reports/` untouched. Placed AFTER the existing no-project
    guard: additive, no reordering of existing refusals.
  - `_start_generate_report_worker` gains `report_filter:
    Optional[ReportFilterMatcher] = None` as an explicit immutable worker
    argument, passed into `ReportOptions(report_filter=...)` — the worker
    reads NO app-level selection state (F-04 thread contract; options are
    built inside the worker exactly as today because `execution_mode`
    depends on the in-worker scope resolution — the matcher rides in
    pre-resolved).
  - `action_before_after_report` NOT touched (Inc-4 with the selector).
- **`tests/test_report_service.py`** — TC-314 ×3 + TC-315 ×1:
  filtered-sections node (audit header position/counts, matched/unmatched
  rows, checklist end-exclusive boundary `[0x0FFE,0x1000)` vs filter start
  `0x1000` NOT matching, F-02 symbol-branch row `CAL_TEMP` matching with
  its range outside, single filtered window, D-2 whole sections);
  zero-match node (notice per section with per-section N, report written
  non-empty, shown-0 header); unfiltered no-kwarg == `report_filter=None`
  byte equality + no-header pin; TC-315 wrong-type `ValueError` + None
  default + matcher accepted.
- **`tests/test_tui_report_seam.py`** — Generate-surface arms driven
  through the REAL `#report_generate` button (the AT-055b idiom); the
  sticky field is set directly as FIXTURE SETUP (the selection UI is
  Inc-4/AT-056a — noted in each docstring):
  - `test_at_055a_generate_surface_filtered_report_with_audit_header`
    (AT-055a surface arm): two-entry change doc (local
    `_write_two_entry_change_document` — the shared one-entry helper is
    untouched because the AT-055b golden was captured over it), filter
    matching one entry → filtered report + audit header naming the REAL
    fixture filename; **F1 condition (Inc-2 review) discharged**: asserts
    `- Filter file: only-first.json` present AND `(unnamed filter)`
    ABSENT — a production wiring that forgets `source_name` goes RED here.
  - `test_at_055c_generate_surface_zero_match_notice` (AT-055c): valid
    zero-match filter → report written with the loud notice, no refusal
    wording.
  - `test_tc_generate_refusal_half_invalid_filter_refuses_before_worker`:
    deliberately named as the TC-level GENERATE-HALF guard, NOT `at053a` —
    per §5.2/C-18, AT-053a is ONE node driving BOTH surfaces and lands in
    Inc-4 when the `b`-key side exists (extend or supersede this node).
    Asserts: 0 files via reports-dir listing, status line
    `Project report refused:` prefix + the parser's `'format'` fault
    token, and neither worker progress status ever appears.

## 2. Files modified

1. `s19_app/tui/services/report_filter.py`
2. `s19_app/tui/services/report_service.py`
3. `s19_app/tui/app.py`
4. `tests/test_report_service.py`
5. `tests/test_tui_report_seam.py`

File cap: 5/5 exactly as tasked (+ this mandated dev-flow record).
Engine-frozen set untouched — `git diff --stat main` over the seven frozen
paths → 0 diffs.

## 3. How to test

```bash
# scoped — the new nodes
python -m pytest tests/test_report_service.py -q
python -m pytest tests/test_tui_report_seam.py -q            # incl. AT-055b golden
# goldens gate (mandated)
python -m pytest tests/test_before_after_report.py tests/test_tui_report_seam.py tests/test_report_service.py -q
# full fast suite
python -m pytest -q -m "not slow"
# lint
python -m ruff check s19_app/tui/services/report_filter.py s19_app/tui/services/report_service.py s19_app/tui/app.py tests/test_report_service.py tests/test_tui_report_seam.py
```

## 4. Test results (real output)

- RED-first (all 7 new nodes written before implementation; single
  foreground run):

```
FAILED tests/test_report_service.py::test_tc314_filtered_sections_and_audit_header
FAILED tests/test_report_service.py::test_tc314_zero_match_notice_report_still_written
FAILED tests/test_report_service.py::test_tc314_unfiltered_output_identical_with_and_without_kwarg
FAILED tests/test_report_service.py::test_tc315_report_filter_option_type_validation
FAILED tests/test_tui_report_seam.py::test_at_055a_generate_surface_filtered_report_with_audit_header
FAILED tests/test_tui_report_seam.py::test_at_055c_generate_surface_zero_match_notice
FAILED tests/test_tui_report_seam.py::test_tc_generate_refusal_half_invalid_filter_refuses_before_worker
7 failed, 57 deselected in 9.51s
```

  Recorded RED signatures (live, not import errors):

```
E       TypeError: resolve_report_filter() got an unexpected keyword argument 'source_name'
tests\test_report_service.py:1304: TypeError
E       TypeError: ReportOptions.__init__() got an unexpected keyword argument 'report_filter'
tests\test_report_service.py:1483 / :1505
E       AssertionError: AT-055a: the audit header must be the first block after the title
E       assert '- Project: proj' == '## Report filter applied'
tests\test_tui_report_seam.py:1465
E       AssertionError: assert '- Filter file: matches-nothing.json' in '# Project report: proj\n...'
tests\test_tui_report_seam.py:1512
E       AssertionError: AT-053a(Generate): a refused run must write ZERO report files, got ['20260711T021512Z-report.md']
tests\test_tui_report_seam.py:1544
```

  (The refusal RED is the live pre-change behavior: the invalid filter was
  IGNORED and a full report was written — exactly the silent-degrade class
  LLR-053.5 closes. NO `git stash` was used at any point; the batch-29
  stash entry is untouched.)

- Post-implementation scoped: `tests/test_report_service.py` →
  `38 passed in 1.38s`, exit 0.
- Seam file: `tests/test_tui_report_seam.py` → `26 passed in 75.72s`
  incl. AT-055b golden, exit 0.
- Goldens gate (mandated triple): `tests/test_before_after_report.py
  tests/test_tui_report_seam.py tests/test_report_service.py` →
  `77 passed in 84.00s` incl. AT-054b (MD+HTML) and AT-055b — unfiltered
  bytes UNCHANGED, exit 0.
- `ruff check` on all five touched files: `All checks passed!`, exit 0.
- Engine-frozen: `git diff --stat main` over `core.py hexfile.py
  range_index.py validation/ tui/a2l.py tui/mac.py tui/color_policy.py` →
  empty (0 diffs).
- Full fast suite: `1318 passed, 2 skipped, 21 deselected, 3 xfailed in
  657.41s (0:10:57)`, `31 snapshots passed`, exit 0 — base 1311 + 7 new
  exactly; skips/xfails unchanged from the Inc-2 baseline. (Harness
  auto-backgrounded the single pytest invocation; the exit code and summary
  were read from that one run's output — no re-run, no parallel duplicate.)

## 5. Risks

- **F1 closed at the surface**: `source_name` is now a declared field set
  by `resolve_report_filter`; the AT-055a node asserts the REAL filename
  and rejects `(unnamed filter)`, so a future wiring that forgets the
  attachment is RED, not silent.
- **Checklist aggregates vs visible rows**: under a filter, the per-file
  `Passed/Failed/Uncheckable` line keeps pre-filter counts while rows are
  hidden — deliberate (D-2 statistics-whole analog; the audit header
  states the hidden row count). A check FILE none of whose rows match
  still renders its heading/aggregates/empty table unless the variant's
  WHOLE checklist population zero-matches (then the notice replaces the
  section body). Documented in `_checklist_lines`.
- **Refusal placement**: the filter gate sits AFTER the no-project guard
  and BEFORE the snapshot/manifest logic, so an invalid filter refuses
  without emitting any `Report: ...` progress status — additive, no
  reordering of existing refusals (LLR-053.5).
- **Fixed header wording now test-pinned** (S-F6) — TC-314/AT-055a assert
  exact lines; changing the format requires superseding them.
- **`_report_filter_path` has no writer in production yet** — Inc-4's
  selector is the writer; until then the field stays `None` and every
  shipped run is unfiltered (byte-identity preserved by AT-055b).

## 6. Pending items

- Inc-4: selector row (LLR-056.2), sticky-selection writer + project-switch
  reset (LLR-056.3, F-09 funnel census), `action_before_after_report`
  consumption + the JOINED AT-053a both-surfaces node, AT-054a/c pilots,
  AT-056a/a2/a3/b/c/d/e, TC-316/317, patch-editor regroup (US-057).
- LLR-055.4 pattern-echo arm: no symbol pattern is echoed into the project
  report in this increment; TC-318's project-report half rides the
  increment that echoes patterns (if any) — the filter NAME is the only
  filter-derived string written today, ctl-stripped.
- Format documentation for operators — rides the UX increment.
- LLR-053.4 perf smoke (4096-pattern worst case) — now reachable through a
  shipped run; still deferred per PLAN.

## 7. Suggested next task

Batch-35 Inc-4 per PLAN: the selection UX — `filters/*.json` scan
(LLR-056.1, TC-316), `ReportViewerScreen` selector row (LLR-056.2, C-15
Select probe), sticky selection + reset funnel (LLR-056.3),
`action_before_after_report` resolution + refusal (LLR-054.1 app arm,
LLR-053.5 b-key half → join AT-053a into its single both-surfaces node),
free-path fold (LLR-056.4, TC-317), geometry AT-056a2 (LLR-056.5).

## Ledger delta

Base 1311 + 7 new = **1318** expected (TC-314 ×3, TC-315 ×1, AT-055a ×1,
AT-055c ×1, Generate-refusal-half ×1); 0 existing tests modified, 0
deletions; engine-frozen set untouched.

### source_name promotion note (Inc-2 handoff, executed)

The Inc-2 duck-typed `source_name` attribute is now a declared
`Optional[str] = None` field on `ReportFilterMatcher`, stamped by
`resolve_report_filter(..., source_name=...)`. `diff_report_service.
_filter_display_name` needed ZERO change (it reads `getattr(...,
"source_name", None)` — now hitting the declared field); the two Inc-2
test helpers' `object.__setattr__` attachments keep working (frozen
dataclass, no slots) and can collapse to constructor kwargs whenever those
files are next in an edit set. `report_service._filter_display_name` reads
the field directly.

## Evidence checklist

- [x] Tests/type checks/lint pass — scoped + goldens-gate runs exit 0
  (outputs above); full fast suite result in §4; `ruff check` clean on all
  five files.
- [x] No secrets in code or output — synthetic S19/JSON fixtures only.
- [x] No destructive commands run without approval — no stash, no reset,
  no force; direct edits only.
- [x] File count within cap — 5/5 exactly the tasked set + this mandated
  record.
- [x] Review packet attached — this file (sections 1-7).
