# Batch-35 — Increment 2 (Inc-2): before/after report filtering + audit header

> Wiring increment on `feat/batch-35-report-filter` @ `d9a73c2` (Inc-0 goldens
> `92df3f4`/`2f237d1` + Inc-1 filter engine + Inc-1 gate-fold docs committed;
> the task brief named `2f237d1` — the tip had advanced by the one docs
> commit, no code delta). Implements LLR-054.1 (composer plumbing),
> LLR-054.2 (filtered surfaces, D-5 filter-then-merge, F-03/Q-2 semantics pin),
> LLR-054.3 (audit header + per-section counts + zero-match notice, S-F6),
> LLR-055.4 diff-module half (filter-derived text sanitation), plus the D-10a
> missing-key pin ratified at the Inc-1 gate. LLR-054.5 white-box half (TC-313)
> rides along. The Inc-0 AT-054b/AT-055b goldens stand guard: unfiltered output
> is byte-identical.

## 1. What changed

- **`s19_app/tui/services/diff_report_service.py`** — both generators gain
  exactly one new optional kwarg `report_filter: Optional[ReportFilterMatcher]
  = None` (TYPE_CHECKING import; the matcher is duck-called, LLR-053.7):
  - `_apply_report_filter` (shared, both formats): runs classified via
    `matcher.matches_range(run.start, run.end)` BEFORE any window computation
    (D-5 filter-then-merge); linkage entries via
    `matcher.matches_item(linkage_symbol, address_start, address_end)`.
    `report_filter=None` is the identity — returns the inputs untouched.
  - `_run_table_lines` / `_hex_windows_lines` / `_html_run_rows` /
    `_html_hex_windows` gain an optional `runs` override (default `None` =
    `comparison.runs`, byte-identical path). Merged windows and grouped
    headings compute over the filtered run list ONLY — an excluded run seeds
    no window and no heading member; its bytes may appear as merged context
    (F-03/Q-2, disclosed by the audit note).
  - `_audit_header_lines` (MD) / `_html_audit_header` (HTML): the FIRST block
    after the report title (S-F6), fixed line format —
    `## Report filter applied` / `- Filter file: <name>` /
    `- Linkage entries: shown S of N (hidden H)` /
    `- Runs: shown S of N (hidden H)` / the F-03 note. shown+hidden ==
    pre-filter count per section (F-07). The linkage-count line renders only
    when a linkage section renders.
  - `_zero_match_notice(total)` = `filter matched 0 of N items` — replaces a
    filtered section's body when its non-empty pre-filter set filters to
    empty (linkage table, Runs, Hex windows each); report still written,
    non-empty (D-3). First token "filter" is prefix-disjoint from every
    refusal wording ("report filter ...", LLR-053.5/Q-12).
  - Sanitation (LLR-055.4 diff half): the filter name passes `_strip_ctl` on
    the non-cell MD audit line (S-F5 minimum — newline strip kills the
    line-forging class) and `_esc(_strip_ctl(...))` in HTML. No pattern is
    echoed anywhere in this increment. Statistics/header/inventory sections
    stay COMPLETE (D-2).
- **`s19_app/tui/services/before_after_service.py`** — `compose_before_after_report`
  gains exactly ONE new optional kwarg `report_filter` (LLR-054.1), added to
  the shared kwargs dict ONLY when not `None` so the no-filter generator call
  shape stays byte-for-byte today's (F-01, TC-311 kwargs pin). Precondition
  order untouched (LLR-053.5 additive rule). NO `a2l_records`/`mac_records`
  kwarg anywhere — annotation inputs untouched.
- **`tests/test_diff_report_service.py`** — TC-312 (4 nodes), TC-318 diff-half,
  TC-313; plus removal of a pre-existing unused `DiffReportResult` import
  (F401 present at HEAD — verified by running ruff on the HEAD version; the
  "ruff clean on touched files" gate required it).
- **`tests/test_before_after_report.py`** — TC-311 (2 nodes).
- **`tests/test_report_filter.py`** — D-10a missing-key pin (1 node, GREEN by
  design: it pins the Inc-1 behavior the gate ratified).

### How the filter display name reaches the audit header (in-cap design decision)

LLR-054.3 requires the header to NAME the filter file, but the Inc-1
`ReportFilterMatcher` carries no display name, and adding a `source_name`
field to `report_filter.py` would have been a 6th file (cap breach). The
task mandate: carry the name "as part of the composer/generator kwarg" and
decide the cleanest in-cap route. Candidates weighed:

1. **Second kwarg (`report_filter_name`)** — violates LLR-054.1's literal
   "exactly ONE new optional keyword parameter". Rejected.
2. **Tuple/wrapper value `(matcher, name)`** — keeps one kwarg but violates
   the LLR's parenthetical type pin ("the resolved `ReportFilterMatcher |
   None`") and forces every later consumer (LLR-055.1 `ReportOptions` field)
   to carry the wrapper. Rejected.
3. **CHOSEN — duck-typed `source_name` attribute on the matcher**: the
   generators read `getattr(report_filter, "source_name", None)` via
   `_filter_display_name` (fallback `(unnamed filter)`); callers attach the
   name with `object.__setattr__` (the frozen dataclass has no `slots`, so
   the instance `__dict__` accepts it). The kwarg stays EXACTLY the matcher
   (zero LLR deviation); the semantics are exactly the requirements' "the
   matcher carries a display name"; when a later increment (the app-wiring
   one, whose file set includes `report_filter.py`) promotes `source_name`
   to a declared `Optional[str] = None` field, `_filter_display_name` needs
   ZERO change and the `object.__setattr__` call sites collapse to a normal
   constructor/`dataclasses.replace` argument.

   Trade-off accepted: until that promotion, the attachment idiom is
   implicit — mitigated by documenting it in `_filter_display_name`'s
   docstring, both test helpers, and this record. **Recommended Inc-3/Inc-4
   action:** add the declared field when `report_filter.py` is in the edit
   set, and have `resolve_report_filter` (or the app resolution step) stamp
   it.

## 2. Files modified

1. `s19_app/tui/services/diff_report_service.py`
2. `s19_app/tui/services/before_after_service.py`
3. `tests/test_diff_report_service.py`
4. `tests/test_before_after_report.py`
5. `tests/test_report_filter.py`

File cap: 5/5 exactly as tasked (this report file is the mandated dev-flow
record). Engine-frozen set untouched (`tests/test_engine_unchanged.py` green).

## 3. How to test

```bash
# scoped — the new nodes
python -m pytest tests/test_diff_report_service.py tests/test_report_filter.py -q
python -m pytest tests/test_before_after_report.py tests/test_tui_report_seam.py -q  # incl. AT-054b/AT-055b goldens
# full fast suite
python -m pytest -q -m "not slow"
# lint
python -m ruff check s19_app/tui/services/diff_report_service.py s19_app/tui/services/before_after_service.py tests/test_diff_report_service.py tests/test_before_after_report.py tests/test_report_filter.py
```

## 4. Test results (real output)

- RED-first (tests written before implementation, single foreground runs):

```
E       TypeError: generate_diff_report() got an unexpected keyword argument 'report_filter'
...
FAILED tests/test_diff_report_service.py::test_tc312_filter_restricts_linkage_and_run_sections_both_formats
FAILED tests/test_diff_report_service.py::test_tc312_a9_merged_window_spans_excluded_run
FAILED tests/test_diff_report_service.py::test_tc312_zero_match_notice_and_refusal_disjoint
FAILED tests/test_diff_report_service.py::test_tc312_audit_header_first_block_fixed_format
FAILED tests/test_diff_report_service.py::test_tc318_hostile_filter_name_sanitized_md_html
FAILED tests/test_diff_report_service.py::test_tc313_no_filter_output_byte_identical_todays
6 failed, 36 deselected in 0.58s
```

```
E       TypeError: compose_before_after_report() got an unexpected keyword argument 'report_filter'
FAILED tests/test_before_after_report.py::test_tc311_composer_forwards_matcher_filtered_output_both_formats
FAILED tests/test_before_after_report.py::test_tc311_no_filter_generator_kwargs_shape_is_todays
2 failed, 1 passed in 0.37s
```

  (The `1 passed` is the D-10a pin — GREEN by design: it pins ratified Inc-1
  behavior, recorded as such. The TC-311 kwargs node failed on its
  with-matcher arm AFTER its no-filter arm passed against today's shape —
  live proof the shape assertion matches the pre-change composer. NO
  `git stash` was used at any point in this increment; the batch-29 stash
  entry is untouched.)

- Post-implementation scoped: `tests/test_diff_report_service.py
  tests/test_report_filter.py` → `96 passed in 0.59s`, exit 0.
- Goldens gate: `tests/test_before_after_report.py tests/test_tui_report_seam.py`
  → `36 passed in 81.18s` incl. AT-054b (MD+HTML) and AT-055b — unfiltered
  bytes UNCHANGED, exit 0.
- Engine-frozen guard: `tests/test_engine_unchanged.py` → `1 passed`.
- `ruff check` on all five touched files: `All checks passed!`, exit 0
  (one pre-existing F401 in `test_diff_report_service.py` removed — verified
  present at HEAD before the change).
- Full fast suite: `1311 passed, 2 skipped, 21 deselected, 3 xfailed in
  629.58s (0:10:29)`, `31 snapshots passed`, exit 0 — base 1302 + 9 new
  exactly; skips/xfails unchanged from the Inc-1 baseline. (Harness
  auto-backgrounded the single pytest invocation; the exit code and summary
  were read from that one run's output — no re-run, no parallel duplicate.)

## 5. Risks

- **Duck-typed `source_name`** — implicit contract until promoted to a
  declared field (decision record above); the fallback `(unnamed filter)`
  can only surface if a later wiring increment forgets to stamp the name,
  and TC-312's zero-match node pins that fallback so it is visible, never
  silent.
- **Fixed header wording is now test-pinned** (S-F6): changing any audit
  line requires superseding TC-312's exact-line asserts — intentional.
- **Zero-match scope choice**: the notice replaces a section body only when
  that section's PRE-filter set was non-empty; a genuinely empty comparison
  keeps its truthful legacy text ("No differing runs...") even under a
  filter. Documented in `_apply_report_filter`.
- **`## Runs` table is filtered** as part of "differing-run sections"
  (LLR-054.2 (b)); the statistics table stays complete, so total run counts
  remain visible (D-2) — TC-312 pins both sides.

## 6. Pending items

- Promote `source_name` to a declared `ReportFilterMatcher` field when
  `report_filter.py` enters an increment's edit set (recommended Inc-3/4).
- LLR-054.2's app-side arm (handler resolution at trigger time, LLR-053.5
  refusal surfaces, AT-054a/c pilots) — later increments per PLAN.
- Format documentation for operators — rides the UX increment.
- LLR-053.4 perf smoke (4096-pattern worst case) — still deferred to the
  increment that wires the matcher into a shipped report run.

## 7. Suggested next task

Batch-35 Inc-3 per PLAN: project-report filtering — `ReportOptions.report_filter`
field (LLR-055.1), filtered Modifications/Checklists/`_applied_regions`
surfaces (LLR-055.2, TC-314/315), `report_service.py` audit header with local
sanitation (LLR-055.4), guarded by the Inc-0 AT-055b golden; take
`report_filter.py` into that edit set to land the declared `source_name` field.

## Ledger delta

Base 1302 + 9 new = **1311** expected (TC-311 ×2, TC-312 ×4, TC-313 ×1,
TC-318-half ×1, D-10a ×1); 0 existing tests modified, 0 deletions (one unused
import removed), engine-frozen set untouched.

## Evidence checklist

- [x] Tests/type checks/lint pass — scoped runs exit 0 (outputs above); full fast suite result recorded in §4; `ruff check` all five files clean.
- [x] No secrets in code or output — synthetic byte/symbol/JSON fixtures only.
- [x] No destructive commands run without approval — no stash, no reset, no force; direct edits only.
- [x] File count within cap — 5/5 exactly the tasked set + this mandated record.
- [x] Review packet attached — this file (sections 1-7).
