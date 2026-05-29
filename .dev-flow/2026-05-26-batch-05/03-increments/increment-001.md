# Increment 1 — US-01 · Hex-search anchor reset on pagination + first-visible resume

**Date:** 2026-05-27
**Scope:** HLR-001 · LLR-001.1 / 001.2 / 001.3 / 001.4
**TC coverage:** TC-001 · TC-002 · TC-002b · TC-002c · TC-003 · TC-003b
**Agent:** `software-dev` (supervised-incremental-development)

## 1. What changed

A new private helper `S19TuiApp._first_visible_hex_address(view: str) -> Optional[int]` returns the address of the first row currently rendered in the requested hex pane. For `"main"` it reads `current_file.row_bases[self._hex_window_start]`. For `"alt"` and `"mac"` it reads two new instance caches (`_alt_first_visible_address`, `_mac_first_visible_address`) written inside `update_alt_hex_view` and `update_mac_hex_view` at the moment the renderer chooses its first row.

`last_search_address` is now cleared to `None` on every event that invalidates the prior anchor:
- main view: `action_hex_page_next`, `action_hex_page_prev`.
- alt view: `_jump_to_tag_by_data`, `_handle_a2l_tag_find_next`.
- mac view: `_jump_to_mac_address` (the canonical MAC record-selection entry-point — see §6 spec-deviation note).

The three search handlers (`_handle_search`, `_handle_search_alt`, `_handle_search_mac`) now, when `last_search_address is None` AND `last_search_text == query`, seed `find_string_in_mem`'s `start_address` from `_first_visible_hex_address(view)`. Query-change semantics (full-image search from the lowest mem-map address) are unchanged.

## 2. Files modified

- `s19_app/tui/app.py` — `__init__` (cache fields), `update_alt_hex_view` (cache write), `update_mac_hex_view` (cache write), `action_hex_page_next` / `action_hex_page_prev` (anchor clear), `_jump_to_tag_by_data` / `_handle_a2l_tag_find_next` / `_jump_to_mac_address` (anchor clear), `_handle_search` / `_handle_search_alt` / `_handle_search_mac` (first-visible seed), new `_first_visible_hex_address` helper.
- `tests/test_tui_search_pagination.py` (new) — 6 integration tests against `App.run_test()`.

**Total: 2 files** (well under the 5-file increment cap).

## 3. How to test

```bash
pytest -q tests/test_tui_search_pagination.py -m "not slow"
pytest -q tests/test_tui_app.py -m "not slow"
# Broader regression:
pytest -q tests/test_tui_app.py tests/test_tui_commandbar.py tests/test_tui_search_pagination.py tests/test_tui_hexview.py -m "not slow"
```

## 4. Test results

| Suite | Result |
|---|---|
| `test_tui_search_pagination.py` (new) | **6 passed in 2.36 s** |
| `test_tui_app.py` (regression) | **67 passed · 3 deselected · 1 xfailed in 43.98 s** (xfail pre-existing) |
| Broader regression (4 suites) | **106 passed · 3 deselected · 1 xfailed in 53.99 s** |

## 5. Risks

- Alt/MAC cache is written immediately *before* the renderer call inside the same branch as the actual render decision. A future refactor that splits the cache-write from the renderer call could let them drift. Mitigation: both writes use the same `start_row_index` value that's passed straight into `render_hex_view_text`.
- The anchor-clear in `_jump_to_tag` (legacy adapter) is reached through `_jump_to_tag_by_data`; non-dict payload paths early-return without clearing — consistent with "nothing changed in the view."
- LLR-001.2's full-image semantics on query change (`last_search_text != query` → `start_address = None`) is preserved but only indirectly exercised (TC-002 first-call). A dedicated regression for the "new query never seeds from first-visible" path would strengthen coverage in Phase 4.

## 6. Pending items / spec deviations to surface

- **LLR-001.4 entry-point name** — the LLR names `_on_mac_records_row_highlighted`; that method does not exist in the codebase. The canonical MAC record-selection entry-point is `_jump_to_mac_address` (`s19_app/tui/app.py:2891-2895`, called from `on_data_table_row_selected` for `table_id == "mac_records_list"`). The implementation and TC-003b use the actual name. **Phase 6 doc update: amend LLR-001.4 wording.**
- **LLR-003.6 trigger list (forward-reference)** — LLR-003.6 also calls for clearing `_<view>_goto_focus_address` on the same triggers we just touched. The focus-address field doesn't exist yet (created in Increment 3). When Increment 3 lands, the focus-clear must be added to the same five entry-points (`action_hex_page_*`, `_jump_to_tag_by_data`, `_handle_a2l_tag_find_next`, `_jump_to_mac_address`) plus the search-handlers' new-query branch.
- **`_jump_to_validation_issue_by_index`** also drives a hex-view shift (issues table → focus). LLR-001 doesn't enumerate it. Increment 3 may want to add it to LLR-003.6's focus-clear set.
- LLR-001.1's "anchor cleared even when clamped at `max_start` / `0`" — TC-001 doesn't exercise the clamped-at-boundary case explicitly. Python's `min` / `max` always assigns, so the line after `_hex_window_start` mutation runs unconditionally — the clear is guaranteed. Phase 4 may add a stricter coverage case.

## 7. Phase-2 §5.5 open items — explicit answers

1. **`_handle_goto_alt` and `_handle_goto_mac` exist as separate methods** at `s19_app/tui/app.py:5890` / `:5932` / `:5974` respectively. The parse-error trigger enumeration in LLR-003.6 stands (three distinct cases, one per view).
2. **`_first_visible_hex_address` cache wired inside renderers** — both writes are placed immediately after computing `start_row_index` and before the `render_hex_view_text` call. Cache cleared to `None` on `current_file is None` early-return paths. The helper reads these caches for `"alt"` and `"mac"`; for `"main"` it computes directly from `_hex_window_start`.

## 8. Suggested next task

**Increment 2 — US-02** (HLR-002 / LLR-002.1..002.4): apply CSS to `s19_app/tui/styles.tcss` (bump `#mac_hex_pane { width: 82 }`, add `#mac_hex_scroll { height: 100%; overflow: auto; }`, preserve `width-narrow`, assert records-pane stays ≥1 cell), plus matching tests in `tests/test_tui_hexview.py` driven through `App.run_test(size=(120, 30))`. Expected files: 2.
