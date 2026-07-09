# Increment 002 — US-043 restore half (LLR-043.R8)

**Scope:** ADDITIVE restore of the "Related artifacts" info onto the grouped `IssueRow`,
per operator Path A. Adds a dedicated markup-safe `.issue-related` node to `IssueRow.compose`,
pins it with TC-043-restore.1 (white-box), and migrates AT-021 to observe it black-box through
the shipped grouped surface. The hidden `#validation_issues_list` DataTable STAYS this increment
(retired in Inc4), so the suite stays green throughout. 3 files touched (≤5 cap).

## 1. What changed
- `IssueRow.compose` now yields a **third** `Static` carrying class `.issue-related`, rendering
  `safe_text(", ".join(issue.related_artifacts) or "-")` — the value the retired Related column
  showed (app.py:786), restored to the sole grouped surface. Built via `safe_text` (never raw
  markup) so a future file-derived `related_artifacts` value cannot become an injection sink
  (defense-in-depth; the values are fixed engine type-tokens today).
- `IssueRow` docstring (Summary + Data Flow) updated to describe the related node.
- `.issue-related` CSS rule added (muted `#6b7280`, `width:auto`, `margin-left:1`) so it trails
  the `1fr` `.issue-detail` span without forcing horizontal overflow — row stays single-line.
- AT-021 migrated: stops reading the batch-28-hidden DataTable via `get_row_at`; now reads the
  `.issue-related` node of each mounted `IssueRow` (rows ordered error→warning by `SEVERITY_ORDER`).
- TC-043-restore.1 added (white-box on `compose`): asserts the `.issue-related` node's plain text
  is `", ".join(related_artifacts) or "-"` AND that a hostile payload
  (`["a2l[bold]", "x[link=file:///etc]"]`) renders literal — no `MarkupError`, brackets survive,
  the `[link=...]` token is not consumed.
- Existing `IssueRow` cells (code chip + `.issue-detail`) untouched (LLR-043.R6).

## 2. Files modified
1. `s19_app/tui/issues_view.py` — `IssueRow.compose` + docstring (Summary/Data Flow).
2. `s19_app/tui/styles.tcss` — new `.issue-related` rule after `.issue-detail`.
3. `tests/test_tui_issues_view.py` — `DataTable` import dropped, `Text` import added,
   `_static_content`/`_related_plain` helpers, AT-021 migrated, TC-043-restore.1 added.

Not touched (per Inc2 boundary): `app.py`, the DataTable itself, `validation/model.py`
(`related_artifacts` read-only, engine-frozen).

## 3. How to test
```
python -m pytest tests/test_tui_issues_view.py -q
python -m pytest tests/test_tui_directionb.py -q
python -m ruff check s19_app/tui/issues_view.py tests/test_tui_issues_view.py
python -m pytest tests/test_engine_unchanged.py -q
```

## 4. Test results (real output)
- `tests/test_tui_issues_view.py` → **4 passed** in 1.87s.
- `tests/test_tui_directionb.py` → **155 passed** in 117.68s (grouped panel + Issues screen still
  render; no layout regression from the added node).
- `ruff check` (both files) → **All checks passed!**
- `tests/test_engine_unchanged.py` → **1 passed** — **0 engine-frozen diffs** (LLR-043.R7 holds;
  none of the 3 touched files is frozen).

## 5. Risks
- **CSS-only (Analysis):** `.issue-related` uses `width:auto` so the `1fr` detail span flexes; no
  horizontal overflow of `#validation_issues_groups` observed (directionb Issues-screen tests green).
- **White-box coupling (low):** TC-043-restore.1 reads `Static._Static__content` (name-mangled) to
  inspect the un-rendered `Text` app-independently. This is stable against the repo's pinned
  `textual==8.2.8` (local + CI); documented in the `_static_content` helper docstring. Rendering via
  `render()` was rejected — it needs an active-app console (raises `NoActiveAppError` when unmounted).
- **Snapshot (V-5):** the Issues-screen cells in `tests/test_tui_snapshot.py` already carry
  `xfail(strict=False)` from batch-28 (US-039 grouped-dense). Adding a visible node drifts the SVG
  further but the cells stay xfailed — no suite failure, no new mark needed. File 4 NOT touched.

## 6. Pending items (later increments — NOT this one)
- Inc4: retire the hidden `#validation_issues_list` DataTable (LLR-043.R1–.R7), migrate the
  remaining 4 test files per the C-14 census, update `on_data_table_row_selected` docstring.
- Follow-up batch (R-043-3): retire the worker `precompute_issue_datatable_payload` calls + dead
  caches. `test_tc021_precompute_payload_emits_related_cell` retained meanwhile (formatter TC).
- Canonical-CI snapshot regen retires the Issues-cell xfail once the new baseline lands
  (local regen FORBIDDEN).

## 7. Suggested next task
Inc3 — US-042 clipboard read cap (LLR-044.1–.5 + AT-042a–f + TC-042.1–.3) in
`os_clipboard_input.py` / `tests/test_loadfilescreen_input.py` (independent of US-043; safe to land
before or after Inc4).

---

## AT/TC → LLR map
| Test | Kind | LLR | Observes |
|------|------|-----|----------|
| `test_at021_issues_list_shows_related_artifacts` (migrated) | black-box | LLR-043.R8 | `.issue-related` node plain text on mounted `IssueRow`s (error row = `"a2l, mac"`, warning row = `"-"`) |
| `test_tc043_restore1_related_node_is_markup_safe` (new) | white-box | LLR-043.R8 (+ C-17) | `compose` yields exactly one `.issue-related` node; plain text contract; hostile payload renders literal (no `MarkupError`, brackets intact, `[link=...]` not consumed, content is a `safe_text` `Text`) |

## Ledger delta
**1180 → 1181 (+1).** Net-new: TC-043-restore.1 (`test_tc043_restore1_related_node_is_markup_safe`).
AT-021 was migrated (rewritten in place, not added); the other 3 tests in the file are unchanged.

## Snapshot cells xfail'd this increment
None added. The Issues-screen cells (`issues-{compact,comfortable}-{80x24,120x30,...}`) already carry
`xfail(strict=False)` from batch-28 US-039; they absorb this increment's SVG drift with no change.

## Evidence checklist
- [✓] Tests/type checks/lint pass — issues_view 4 passed · directionb 155 passed · ruff clean.
- [✓] No secrets in code or output.
- [✓] No destructive commands run.
- [✓] File count within cap — 3 files (≤5).
- [✓] Review packet attached (this file).
- [✓] 0 engine-frozen diffs — `test_engine_unchanged.py` 1 passed.
