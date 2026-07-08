# Increment 002 — US-039 Issues Report grouped-by-severity dense view

Batch-28 · R-TUI-042 · Direction B · TUI render-side only.
LLR-042.3 (grouping) · .4 (code chips) · .5 (selection→peek) · .6 (paging+filter+DoS+observables) · .10 (C-17 markup-safety).

## 1. What changed
- **LLR-042.3 grouping.** A new scrollable `GroupedIssuesPanel`
  (`#validation_issues_groups`) renders the already-computed
  `_validation_issues` grouped by severity in fixed **error → warning → info**
  order. Each present group is led by an `IssueGroupHeader` (class
  `issue-group-header`) showing `"<LABEL>  (<count>)"`.
- **LLR-042.4 code chips.** Each issue renders as a focusable `IssueRow` (class
  `issue-row`) carrying a compact code chip (a `Static`, class
  `issue-code-chip`) beside a symbol · address · message detail span. Chip /
  header / row colour comes exclusively from the frozen
  `css_class_for_severity` `sev-*` classes — **no hard-coded hex** in the new
  render or CSS (the `.sev-*` colour rules are the existing frozen source).
- **LLR-042.6 paging + filter + DoS + observables.** The grouped view reuses
  the existing `_get_window_bounds` / `page_size` window, so **at most one
  bounded window of rows is mounted** (a 5 000-issue list mounts ≤ `page_size`
  = 200 chips, not O(N)). Each group-header count is the **whole (filtered)**
  count for that severity, not the windowed subset. The existing severity
  filter (`issues_filter_all/error/warning`) still scopes the rendered set. A
  truncation note (`issues-truncation-note`) shows when the filtered list
  exceeds the window. Queryable `.issue-group-header` (with `.severity_label`
  + integer `.issue_count`) and `.issue-code-chip` nodes are exposed.
- **LLR-042.5 selection → hex-peek.** A real click or `Enter` on a row posts
  `IssueRow.Selected(address)`, which bubbles to the app's new
  `on_issue_row_selected` handler → the existing `_update_issues_hex_pane`.
  `address is None` → the neutral placeholder, no crash. `#issues_hex_pane` is
  unchanged. (No per-card Open-in — descoped.)
- **LLR-042.10 markup-safety (C-17).** Every file-derived string on the view
  (`.code`, `.symbol`, `.message`) is composed through the batch-27 `safe_text`
  helper (imported from `screens_directionb`) as a literal `rich.text.Text`
  with explicit `style=` — never interpolated into a markup string, never
  handed to a markup-parsing widget over the raw value. Verified: a hostile
  `code="MAP_Model[bold]"`, `symbol="…\x1b[31m"`,
  `message="open[red]sensor[/] [link=file:///etc]"` renders LITERAL — no
  `MarkupError`, no style/ANSI leak, no OSC-8 hyperlink, no crash.

### Design note — additive, not replacing (compat + file cap)
The existing Issues `DataTable` (`#validation_issues_list`) is **retained**,
not replaced or hidden: `test_tui_issues_view.py` and `test_tui_app.py` (both
OUTSIDE this increment's ≤5-file set) drive real selection through that
DataTable and assert on `row_count` / `get_row_at`. `update_validation_issues_view`
keeps its exact DataTable + summary behaviour (all monkeypatched unit tests
pass unchanged) and additionally calls the new, **screen-stack-guarded**
`_render_validation_issues_groups` (a no-op when unmounted, so headless unit
tests are unaffected). The Issues screen's left slot is now a vertical
`#issues_list_stack`: the grouped panel (primary, `2fr`) above the retained
DataTable (compat surface, `1fr`). Both feed the same `#issues_hex_pane`.

## 2. Files modified (5 code/test + this packet)
- `s19_app/tui/issues_view.py` — **NEW** widget module: `IssueGroupHeader`,
  `IssueRow` (+ `Selected` message), `GroupedIssuesPanel.render_groups`,
  `SEVERITY_ORDER` / `SEVERITY_LABELS`. Reuses `safe_text` + `css_class_for_severity`.
- `s19_app/tui/app.py` — import `GroupedIssuesPanel` / `IssueRow`; compose the
  grouped panel + DataTable into `#issues_list_stack`; append guarded
  `_render_validation_issues_groups()` at both exit points of
  `update_validation_issues_view`; add `_render_validation_issues_groups` +
  `on_issue_row_selected`.
- `s19_app/tui/styles.tcss` — `#issues_list_stack` (vertical 2fr) split;
  `#validation_issues_groups` (2fr) / retained DataTable (1fr, proportional so
  the two stacked surfaces cannot overflow/overlap in the short Issues body);
  `.issue-group-header` / `.issue-row` (+`:focus`) / `.issue-code-chip` /
  `.issue-detail` / `.issues-empty-note` / `.issues-truncation-note` (colour via
  `sev-*` classes only).
- `tests/test_tui_directionb.py` — +11 tests + 2 helpers (`_seed_issue_objects`,
  `_mixed_issues_with_info` seeding ≥1 INFO).
- `tests/test_tui_snapshot.py` — `_restyled_cell_marks` now xfail-until-baseline
  for the 6 `issues-*` cells (grouped panel shifts the SVG), same
  batch-25/27 pattern.
- `.dev-flow/2026-07-07-batch-28/03-increments/increment-002.md` — this packet.

**Engine-frozen set: 0 diffs** (`core.py`, `hexfile.py`, `range_index.py`,
`validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py` untouched).

## 3. How to test
```bash
# New AT/TC (Layer A + B)
python -m pytest tests/test_tui_directionb.py -k "039 or 042_3 or 042_4 or 042_5 or 042_6 or 042_10" -q
# Regression — existing Issues surface (DataTable, filters, paging, peek)
python -m pytest tests/test_tui_directionb.py -k "issues or 023 or 024" tests/test_tui_issues_view.py -q
python -m pytest tests/test_tui_app.py -k "issue or validation" -q
# Engine-frozen guards
python -m pytest tests/test_engine_unchanged.py tests/test_tui_directionb.py -k "tc031" -q
# Snapshot issues cells resolve as xfail (not hard-fail)
python -m pytest tests/test_tui_snapshot.py -q -k "issues"
# Lint (Python files only; .tcss is not Python)
python -m ruff check s19_app/tui/app.py s19_app/tui/issues_view.py tests/test_tui_directionb.py tests/test_tui_snapshot.py
```

## 4. Test results (real output)
- `pytest -k "039 or 042_3..10"` → **11 passed, 130 deselected in 10.26s**.
- `pytest -k "issues or 023 or 024" + test_tui_issues_view.py` → **13 passed**.
- `pytest test_tui_app.py -k "issue or validation" + a2l_recolor + validation_supplemental`
  → **25 passed**.
- `tests/test_tui_directionb.py` full → **141 passed in 106.38s** (130 → 141, +11).
- `test_engine_unchanged.py` → **1 passed**; `-k tc031` → **3 passed** (0 frozen diffs).
- `test_tui_snapshot.py -k issues` → **6 xfailed, 28 deselected** (expected
  mismatch until canonical-CI regen — not a hard failure).
- `ruff check` (4 `.py` files) → **All checks passed!**

### Evidence checklist
- [✓] Tests/type checks/lint pass — 11 new + 141 directionb + 38 regression pass;
  ruff clean on all `.py`. (`.tcss` is not linted by ruff.)
- [✓] No secrets in code or output — render-only widget/CSS change.
- [✓] No destructive commands run — none.
- [✓] File count within cap — 5 code/test files (the exact authorized set:
  app.py, styles.tcss, new issues_view.py, 2 test files) + this mandated packet.
- [✓] Review packet attached — this file.

## 5. Risks
- **Two Issues surfaces (intentional compat).** The grouped view is the primary
  US-039 deliverable but the legacy `DataTable` remains beside it because
  `test_tui_issues_view.py` / `test_tui_app.py` (outside the ≤5-file cap) drive
  real selection through it. Cleanly retiring the DataTable (and rewriting those
  external tests) is a follow-up increment that is *allowed* to touch those
  files. Both surfaces already feed one `#issues_hex_pane`, so behaviour is
  consistent.
- **Short Issues body geometry.** `#screen_issues` gives `#issues_columns` only
  ~8 rows at 80–120 cols. Fixed row heights overflowed/overlapped, so the split
  is **proportional** (`2fr`/`1fr`) — no overlap at any height; the grouped
  panel scrolls its own overflow. Selection ATs focus the target row (auto-
  scrolling it into view) then press real `Enter` (batch-27 AT-036a C-16
  precedent — `.focus()` positions, the keypress selects). AT-039f confirms the
  DoS bound (≤ `page_size` mounted) rather than relying on visible-row count.
- **Snapshot drift (contained).** The 6 `issues-*` baselines are xfail-until-
  baseline and MUST be regenerated in canonical CI (`snapshot-regen.yml`,
  textual==8.2.8) post-merge, then the `issues` branch of `_restyled_cell_marks`
  dropped. **Local regen is FORBIDDEN.**
- **Selection wiring (verified).** `IssueRow.Selected` bubbles to the App's
  `on_issue_row_selected` (handler-name derivation confirmed:
  `on_issue_row_selected`); AT-039c drives the real `Enter` keypath end-to-end
  and observes the peek repaint, so an unwired `on_key` would fail.

## 6. Pending items (this batch, later increments)
- US-040 Workspace signal (LLR-042.7 micro-bar / .8 memory strip / .9 stat pane).
- Post-merge: canonical-CI `issues-*` (and inc-1 `a2l-*`) snapshot regen +
  retire both xfail branches.
- Follow-up (own increment, may touch `test_tui_issues_view.py` /
  `test_tui_app.py`): retire the compat DataTable so the grouped view is the
  sole Issues surface.

## 7. Suggested next task
Increment 3 — **US-040 Workspace signal** (LLR-042.7 per-range coverage
micro-bar + LLR-042.9 stat pane; LLR-042.8 memory strip may be its own slice
per §6.2). Carries the single genuine geometry pinch (the coverage micro-bar in
the fixed 22-col `#ws_left`, C-13 #3) — measure at 80/120 in Phase 3.

---
**Test-count delta:** tests/test_tui_directionb.py 130 → 141 (+11:
AT-039a/b/c/d/e/f + TC-042.3/.4/.5/.6/.10). Snapshot suite: 6 existing `issues-*`
cells flipped green → xfail-until-baseline; 0 new snapshot cells.

---

## HIGH-fix — hide the duplicate legacy DataTable (post-review)

**Finding.** The Issues screen showed the same issues twice: the new
`GroupedIssuesPanel` (`#validation_issues_groups`) stacked *above* the retained
legacy `#validation_issues_list` DataTable, both visible. The grouped panel must
be the sole VISIBLE Issues surface.

**Fix (surgical, no engine-frozen changes).**
- **Hid the DataTable, kept it mounted + populated.** `styles.tcss`: the
  more-specific `#issues_columns #validation_issues_list` rule is now
  `display: none` (Textual's `.hidden` pattern). The DataTable stays in the DOM
  and `update_validation_issues_view` still clears/populates it, so the
  monkeypatched unit tests and all `get_row_at` model reads are untouched.
  `#validation_issues_groups` now takes `height: 100%` (was `2fr` sharing with
  the table) so the grouped panel fills the stack and is the only thing a user
  sees on `#screen_issues`.
- **Comment at both sites.** Added a "hidden compatibility surface pending full
  retirement (backlog)" comment at the DataTable compose site (`app.py`) and in
  the `styles.tcss` rule, so the next reader understands why a hidden populated
  table exists.
- **Rewrote the one broken selection path.** `tests/test_tui_issues_view.py`
  `_select_issue_row` drove selection via `DataTable.focus()` + `move_cursor` +
  Enter — `.focus()` is a no-op on a `display:none` widget, so it would break.
  Rewrote it to the C-16 real mechanism (shared with AT-039c): `list(app.query(
  IssueRow))`, focus the real `IssueRow`, `pilot.press("enter")` →
  `IssueRow.Selected` → `on_issue_row_selected` → repaints `#issues_hex_pane`.
  Grouped render order (error→warning→info) keeps the AT-020a seed's addressed
  error at index 0 and address-less warning at index 1 — same indices, same
  hex-peek assertions (unchanged, not weakened).
- **Untouched:** `test_at021` and every `tests/test_tui_app.py` reader use
  `get_row_at` (model reads that work on a hidden mounted table) — no change
  needed. `test_tui_app.py` had no real focus-driven DataTable selection, so it
  was not edited.

**Verification.**
- `ruff check s19_app/tui/app.py tests/test_tui_issues_view.py` → clean.
- `pytest tests/test_tui_issues_view.py tests/test_tui_app.py -k issue -q` →
  12 passed.
- `pytest tests/test_tui_directionb.py -k "039 or 042_" -q` → 12 passed.
- `pytest tests/test_engine_unchanged.py -q` → 1 passed (0 frozen diffs).
- Full `tests/test_tui_issues_view.py` + `tests/test_tui_directionb.py` →
  144 passed.
- Issues snapshot cells stay `xfail(strict=False)` (6 xfailed, 0 xpass) —
  the additional SVG shift from the hide is absorbed by the existing
  xfail-until-baseline marks; no snapshot file edited.

**Test-count delta:** net 0 tests added/removed. `tests/test_tui_issues_view.py`
`_select_issue_row` rewritten in place (DataTable path → grouped `IssueRow`
path); `IssueRow` import added. Files touched: `s19_app/tui/app.py`,
`s19_app/tui/styles.tcss`, `tests/test_tui_issues_view.py` (3 files).

---

## Perf-fix (post-merge regression — grouped view mass-mount)

**Root cause (reproduced).** `GroupedIssuesPanel.render_groups` mounted one
`IssueRow` (a `Horizontal` composing 2 `Static`s) per issue in the *whole*
paging window — up to `page_size` (200) issues → ~600 non-virtualized widgets
remounted on every `update_validation_issues_view` call. The old flat
`#validation_issues_list` DataTable was virtualized (cheap); the grouped view is
not. Mounting hundreds of widgets floods Textual's message pump, so
`pilot.pause()`'s `_wait_for_screen` never settles. Confirmed **not** a state
leak: the failure is `textual.pilot.WaitForScreenTimeout` ("Timed out while
waiting for widgets to process pending messages"), i.e. a pure per-render
perf-cascade. On clean `main` the `TestCrossFileCompatibilityPanelRender` class
is `7 passed / 1 xfailed in ~34s`; on the branch it was
`5 failed / 2 passed / 1 xfailed in 276s` (each failing test times out mid-mount).
The tc_065 assertions read codes from the *DataTable*, not the grouped panel, so
they never depended on the grouped row count — only on the render completing.

**Fix.** Cap the grouped view's mounted `IssueRow` count to a small constant
`_GROUP_DISPLAY_MAX = 40` in `render_groups` (rows taken in error→warning→info
order until the budget is spent). Group **headers still report the whole-filtered
count** (`group_counts`), only the rows are display-capped. The truncation note
now also fires when the cap hides rows on the current page (`truncated or capped`).
This tightens — never loosens — the LLR-042.6 DoS bound: mounted rows stay
`<= _GROUP_DISPLAY_MAX (40) <= page_size (200)`. Paging (PgUp/PgDn) still reaches
the rest of the window. Sole file changed in product code: `s19_app/tui/issues_view.py`
(no `app.py` caller change — it already passes the window + counts + `truncated`).

**Before / after.**

| Metric | Before (branch) | After (fix) | Clean `main` |
| --- | --- | --- | --- |
| tc_065 class result | 5 failed / 2 passed / 1 xfailed | **7 passed / 1 xfailed** | 7 passed / 1 xfailed |
| tc_065 class wall time | ~276 s | **~34 s** | ~34 s |
| Mounted `IssueRow` @ 200-issue page | up to 200 (~600 widgets) | ≤ 40 (~120 widgets) | n/a (DataTable) |

**Test-threshold adjustments:** none required. AT-039f asserts
`0 < mounted <= page_size` and TC-042.6 asserts `mounted <= 200`; both are
`<=` bounds that a 40-row cap satisfies (no `== page_size` assertion existed).
AT-039a/b/c/d/e and TC-042.3/.4/.5/.10 seed ≤ 4 issues, all under the cap.
No US-039 AT/TC weakened.

**Direct regression test added — AT-039g / TC-042.6b**
(`tests/test_tui_directionb.py::test_at_039g_tc_042_6b_full_page_render_is_row_capped_and_settles`):
seeds a FULL `page_size` (200) issue page through the real Issues surface
(`_seed_issues_screen`, `action_show_screen("issues")`, `pilot.pause()`) and
asserts (a) the render SETTLES — reaching the asserts at all proves no
`WaitForScreenTimeout` — (b) mounted `IssueRow` count `== chip count` and
`0 < rows <= _GROUP_DISPLAY_MAX` (imported from `issues_view`), i.e. capped, not
~200, and (c) a truncation note is present (200 > cap). This guards the Inc-2
perf regression DIRECTLY: a future uncapped render fails here instead of only
surfacing as the `tc_065` panel-render timeout. Net **+1 test** (this is the
only test-count change; no existing test edited).

**Verification (this fix):**
- `ruff check s19_app/tui/issues_view.py tests/test_tui_directionb.py` → clean.
- `pytest "tests/test_tui_app.py::TestCrossFileCompatibilityPanelRender"` →
  **7 passed / 1 xfailed in 34.47s** (was 5 failed / 276s).
- `pytest tests/test_tui_directionb.py -k "039g or 042_6"` → **2 passed in 1.86s**
  (new AT-039g/TC-042.6b + TC-042.6).
- `pytest tests/test_tui_directionb.py` (full) → **155 passed in 110s**
  (154 → 155, +1; the whole file now settles — previously 039/042 timed out).
- `pytest tests/test_tui_issues_view.py` → 3 passed.
- `pytest tests/test_engine_unchanged.py` → 1 passed (0 frozen diffs).

**Files touched:** `s19_app/tui/issues_view.py` (product), `tests/test_tui_directionb.py`
(+1 regression test), and this increment doc.
