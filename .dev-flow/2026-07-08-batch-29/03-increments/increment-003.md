# Increment 003 — C-14 test-migration, part 1 (census rows 12,13,15,16,17,18)

**Scope:** Re-point the census test *readers* that CAN pass against the live `GroupedIssuesPanel`
while the hidden `#validation_issues_list` DataTable is STILL PRESENT (retired in Inc4). This keeps
the suite green through the retirement. **No `app.py`/`styles.tcss`/`issues_view.py` change; the
DataTable is NOT removed this increment.** 3 test files touched (≤5 cap).

Deliberately NOT migrated here (invert/retire in Inc4): `test_tc023_*` (assert the DataTable EXISTS)
and census row 14 `test_tc024_issues_paging_advances` (already surface-agnostic — reads summary +
`window_start`, left unchanged).

## 1. What changed

**`tests/test_tui_directionb.py`** — 4 tests re-pointed off `#validation_issues_list.row_count` /
the `issue:` row-key path onto the grouped panel:
- `test_tc024_issues_severity_filters_narrow_through_dedicated_screen` (#12): the all/error/warning
  partition now reads the **whole-filtered** count via `sum(IssueGroupHeader.issue_count)` instead of
  `table.row_count`. `_count` became `async` and awaits `pilot.pause()` after each
  `update_validation_issues_view()` so the prior render's `remove_children` is flushed before the
  headers are summed (without the pause the not-yet-removed rows/headers double the count → 60/40).
  Added the count-guard `assert len(query(IssueRow)) <= _GROUP_DISPLAY_MAX` (30 < 40 → single page).
- `test_tc024_issues_filter_buttons_route_through_dedicated_screen` (#13): before/after the Errors
  button now read `sum(IssueGroupHeader.issue_count)` (via a local `_filtered_total`) instead of
  `table.row_count`; each read carries the `<= _GROUP_DISPLAY_MAX` guard.
- `test_tc024_issues_severity_color_round_trips` (#15): tail `row_count == 12` → `len(query(IssueRow))
  == 12` (with the `<= _GROUP_DISPLAY_MAX` guard); the colour source-of-truth is re-observed on the
  grouped panel's own path — `IssueRow._sev_class == css_class_for_severity(issue.severity)` for every
  mounted row. The payload-half assertion (`precompute_issue_datatable_payload` styles) is **kept
  unchanged** — that formatter still exists (tracked-orphan, retired in a follow-up batch).
- `test_tc024_issues_row_select_jumps_to_source` (#16): the retired `issue:` row-key
  `_Evt → on_data_table_row_selected` drive is replaced by the surviving selection path (C-16 real
  mechanism): seed a mixed set incl. an `address=None` INFO row, focus a real `IssueRow`, press
  `Enter` → `IssueRow.on_key` → `Selected` → `on_issue_row_selected` → `#issues_hex_pane`. Asserts
  the pane repaints to `0x80000100` and CHANGES for the addressed row, and shows the neutral
  "no address" placeholder with no stale bytes for the `address None` row.

**`tests/test_tui_a2l_issue_recolor.py`** (#17) and **`tests/test_validation_service_supplemental.py`**
(#18) — the `_issue_rows` content read-back migrated in both:
- `_issue_rows` now iterates `app.query(IssueRow)` and returns
  `(row.issue.severity, .code, .artifact, .symbol, .message)` tuples (reads the `ValidationIssue`
  object, not rendered cells → robust against detail-string formatting). Tuple-index constants updated
  to the new order (`_SEV,_CODE,_SYMBOL = 0,1,3`; supplemental adds `_MESSAGE = 4`).
- `_SEV` comparisons changed from the DataTable string `ValidationSeverity.ERROR.value.upper()`
  (`"ERROR"`) to the **enum** `ValidationSeverity.ERROR` (stronger typing).
- A shared `_assert_within_cap(app)` helper (added to each file) pins the count-guard
  `len(app._filtered_validation_issues()) <= _GROUP_DISPLAY_MAX`, and is called before EVERY
  whole-list claim — the "exactly one" counts AND the `not any(...)` **absence** asserts (incl.
  `test_at_036c`'s absence-only claim, which still needs the guard). Fixtures emit ≤4 issues → safe.
- Module docstring one-liners updated to say the issue read-back is the grouped `IssueRow` (C-14),
  not the retired DataTable.

**Untouched (as required):** the A2L colour oracle — `_a2l_row_list` reading `#a2l_tags_list` and every
`cell.style == _severity_style(...)` assertion, plus the zero-tag `a2l_table.row_count == 0` check in
`test_validation_service_supplemental.py` — is a **different** DataTable that is NOT retired, so it was
left exactly as-is in both files.

## 2. Files modified
1. `tests/test_tui_directionb.py` — census #12,#13,#15,#16 (#14 left unchanged).
2. `tests/test_tui_a2l_issue_recolor.py` — census #17 (`_issue_rows` + `_assert_within_cap` + AT-037a/b).
3. `tests/test_validation_service_supplemental.py` — census #18 (`_issue_rows` + `_assert_within_cap` +
   AT-036a/b/c).

No product code touched. `app.py`, `styles.tcss`, `issues_view.py` and the `#validation_issues_list`
DataTable are unchanged (Inc4 owns the removal).

## Census-row → test map
| Census # | File | Test / helper | Migration |
|---|---|---|---|
| 12 | directionb | `test_tc024_issues_severity_filters_narrow_through_dedicated_screen` | `row_count` → `sum(IssueGroupHeader.issue_count)` + async pause + cap-guard |
| 13 | directionb | `test_tc024_issues_filter_buttons_route_through_dedicated_screen` | `row_count` before/after → header-sum via `_filtered_total` + cap-guard |
| 14 | directionb | `test_tc024_issues_paging_advances_through_dedicated_screen` | **left unchanged** (already surface-agnostic: summary + `window_start`) |
| 15 | directionb | `test_tc024_issues_severity_color_round_trips` | tail → `len(query(IssueRow))==12`; colour → `IssueRow._sev_class == css_class_for_severity`; payload-half kept |
| 16 | directionb | `test_tc024_issues_row_select_jumps_to_source` | row-key `on_data_table_row_selected` → real `IssueRow` focus+Enter → `on_issue_row_selected` → `#issues_hex_pane` |
| 17 | a2l_issue_recolor | `_issue_rows`, `test_at_037a`, `test_at_037b` | `_issue_rows` → `query(IssueRow)`; `_SEV` enum; `_assert_within_cap` on every whole-list claim |
| 18 | validation_service_supplemental | `_issue_rows`, `test_at_036a/b/c` | same re-point + enum `_SEV` + `_assert_within_cap` on all counts + absences |

## 3. How to test
```
python -m pytest tests/test_tui_directionb.py tests/test_tui_a2l_issue_recolor.py tests/test_validation_service_supplemental.py -q
python -m ruff check tests/test_tui_directionb.py tests/test_tui_a2l_issue_recolor.py tests/test_validation_service_supplemental.py
python -m pytest tests/test_engine_unchanged.py -q
```

## 4. Test results
- Three migrated files: **171 passed** in 120.5 s (`pytest -q`). (First run surfaced the async-removal
  double-count in #12 — 60/40 — fixed by awaiting `pilot.pause()` before summing; re-run green.)
- Ruff: **All checks passed!** on all three files.
- `tests/test_engine_unchanged.py`: **1 passed** — 0 engine-frozen diffs (only test files changed).
- Ledger: test-function counts identical to HEAD (155 / 5 / 11 for the three files) → **net delta 0**
  from 1181 (all migrations are rewrites-in-place; no test split, added, or retired this increment).

## 5. Risks
- **R-043-1 (mitigated for these 6 rows):** the migrated reads are faithful only while the whole
  filtered list ≤ `_GROUP_DISPLAY_MAX (40)`. The `_assert_within_cap` guards and the `<= _GROUP_DISPLAY_MAX`
  asserts make that a hard, self-failing precondition — a future larger fixture trips the guard rather
  than passing a count/absence vacuously.
- **Async-removal ordering (found & fixed):** grouped-panel re-renders schedule `remove_children`
  asynchronously; any whole-DOM `query(IssueRow)`/`query(IssueGroupHeader)` between a re-render and the
  next `pilot.pause()` double-counts. #12 now awaits a pause; #13/#15 read after an existing pause. A
  latent trap for Inc4/future migrations — noted.
- The `precompute_issue_datatable_payload` payload-half in #15 still exercises the retained formatter;
  when that formatter is retired in a follow-up batch, that assertion block must retire with it.

## 6. Pending items
- Inc4: remove the `#validation_issues_list` DataTable (compose, CSS, column-init, populate, row-key map,
  `on_data_table_row_selected` branch) and **invert** `test_tc023_*` (census #10/#11) to assert the
  DataTable is absent + the grouped panel is primary. The migrations here are written to stay green
  before AND after that removal (grouped panel is populated in parallel since batch-28).
- Remaining census rows not in this increment's scope: #1–#9 (`test_tui_issues_view.py`,
  `test_tui_app.py`) — handled in their own increments per the batch plan.

## 7. Suggested next task
Inc4 — retire the `#validation_issues_list` DataTable in `app.py` + `styles.tcss` (LLR-043.R1–.R7),
invert census #10/#11, and confirm the engine-frozen diff stays 0 and the snapshot suite is SVG-neutral
(regen in canonical CI only if any Issues cell shifts).

## Evidence checklist
- [✓] Tests pass — 171 passed (3 files); engine-frozen 1 passed (0 diffs). Evidence: `pytest -q` output above.
- [✓] No secrets in code or output — synthetic A2L/S19 fixtures + public `case_04` only.
- [✓] No destructive commands run — read/pytest/ruff/git-show only.
- [✓] File count within cap — 3 test files (≤5).
- [✓] Review packet attached — this file.
- [✓] A2L colour oracle left untouched — `_a2l_row_list` / `#a2l_tags_list` `cell.style` asserts +
  zero-tag `a2l_table.row_count == 0` unchanged in both recolor files (verified: only `_issue_rows`,
  `_SEV` constant/comparison, and count-guards were edited).
- [✓] Count-guard v2 — every migrated whole-list claim (counts AND `not any(...)` absences, incl.
  `test_at_036c`) guards `<= _GROUP_DISPLAY_MAX (40)`, not `< page_size`.
