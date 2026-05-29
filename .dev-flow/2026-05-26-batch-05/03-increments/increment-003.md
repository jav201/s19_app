# Increment 3 — US-03 · Goto out-of-range feedback + non-color focus-row marker

**Date:** 2026-05-27
**Scope:** HLR-003 · LLR-003.1 / 003.2 / 003.3 / 003.4 / 003.5 / 003.6
**TC coverage:** TC-007 · TC-008 · TC-009a · TC-009b · TC-010 (×3) · TC-011 (×4) · TC-012 (main/alt/mac + tab-switch control)
**Agent:** `software-dev` (supervised-incremental-development)

## 1. What changed

`render_hex_view_text` gained a keyword-only `focus_row_marker_address: Optional[int] = None`; each rendered row is now prefixed with `"> "` (focus row) or `"  "` (all other rows), plain text, no Rich style — column alignment unchanged, no collision with `sev-*` / search-yellow / MAC-orange. Three per-view focus fields (`_goto_focus_address`, `_alt_goto_focus_address`, `_mac_goto_focus_address`) are managed by a shared `_apply_goto(view, addr) -> bool` helper that rejects out-of-range addresses with `Address 0x... not in loaded file.` and leaves the view unmoved. The three `update_*_hex_view` renderers forward the matching field; the three `_handle_goto*` handlers clear focus on empty/parse-error input. Focus clears on every LLR-003.6 trigger (pagination, new search, tag/record selection, file load/unload) but persists across tab switches.

## 2. Files modified

- `s19_app/tui/hexview.py` — `render_hex_view_text` keyword-only param + docstring; row loop prepends the 2-cell marker.
- `s19_app/tui/app.py` — 3 `__init__` focus fields; `_apply_goto` helper; goto handlers route through it + clear on empty/parse-error; 3 renderers forward the field + clear on no-file branch; focus-clear at main/alt/mac pagination, `_jump_to_tag_by_data`, `_handle_a2l_tag_find_next`, `_jump_to_mac_address`, the 3 search new-query branches, and `_apply_prepared_load` (file-load).
- `tests/test_tui_goto_marker.py` (new) — 15 tests.

**Total: 3 files** (under the 5-file cap).

## 3. How to test

```bash
pytest -q tests/test_tui_goto_marker.py -m "not slow"
pytest -q tests/test_tui_hexview.py tests/test_tui_app.py -m "not slow"
pytest -q tests/test_tui_search_pagination.py tests/test_tui_mac_layout.py -m "not slow"
git --no-pager diff --stat s19_app/tui/color_policy.py   # must be empty
```

## 4. Test results

| Suite | Result |
|---|---|
| `test_tui_goto_marker.py` (new) | **15 passed in 6.17 s** |
| `test_tui_hexview.py` + `test_tui_app.py` | **87 passed · 3 deselected · 1 xfailed in 33.46 s** (xfail pre-existing) |
| `test_tui_search_pagination.py` + `test_tui_mac_layout.py` (Inc 1+2) | **10 passed in 4.58 s** |
| `-k "goto or focus_row_marker"` | **15 passed · 91 deselected** |
| `git diff color_policy.py` | **empty** (byte-for-byte unchanged) ✓ |

## 5. Risks

- Focus-clear at alt/mac `action_*_page_*` sits after the early-return content guards — clear only fires when there is content to page. TC-012 seeds real filtered tags / MAC records to exercise the trigger genuinely.
- "File-unload" has no dedicated action; focus is cleared in the three `update_*_hex_view` no-file branches (covers `current_file = None` + re-render). File *replacement* covered in `_apply_prepared_load`. TC-012 covers both.
- Header lines (`... window limited ...`, `... not present ...`) deliberately do not get the marker — only true hex rows do. Tests filter on `"0x" in line`.

## 6. Spec deviations / Phase-6 doc notes

- **LLR-003.1 range attribute** — the LLR statement says `self.current_file.sorted_ranges`; the real `LoadedFile` attribute is `ranges` (`List[Tuple[int,int]]`), and there is no `sorted_ranges`. Implementation reuses the existing cached accessor `self._get_range_index(self.current_file)` (`app.py:3586`) → `address_in_sorted_ranges(addr, range_index)`, matching the call sites at `app.py:3692` / `:4495`. **Phase 6 doc: amend LLR-003.1 wording.**
- **`render_hex_view` (non-Text variant)** — left untouched. The app renders all three panes via `render_hex_view_text`; the str variant is only used by `test_tc_023_*` constant tests and is off the goto path. Adding the param there would be unused speculative code.
- **`_jump_to_validation_issue_by_index`** focus-clear — NOT added. LLR-003.6 does not enumerate it; adding it would be scope creep. Flagged for Phase 6 review if desired.

## 7. Pending items / Suggested next task

- US-03 complete; the Increment-1 §6 forward-references are all satisfied.
- **Next: Phase 4 (validation)** — run the full `pytest -q -m "not slow"` then `pytest -q` suite on Python 3.11, execute the §5.2 TC matrix, confirm 0 blocker fails, fill `04-validation.md`.

### Explicit answers
- **Range accessor:** real attribute is `LoadedFile.ranges`; reused `_get_range_index(self.current_file)` cached accessor (lazily builds via `build_sorted_range_index`). LLR-003.1 to be amended in docs.
- **`render_hex_view` need the param?** No — untouched, justified above.
- **Existing hexview test updates?** None needed — `None` default keeps the `"  "` prefix; existing assertions match on `0x{addr:08X}` substrings, not line-start. 87 passed with no edits.
