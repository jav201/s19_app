# Increment 2 — US-02 · MAC hex pane CSS (width + scroll height)

**Date:** 2026-05-27
**Scope:** HLR-002 · LLR-002.1 / 002.2 / 002.3 / 002.4
**TC coverage:** TC-004 · TC-005 · TC-006 · TC-013
**Agent:** `software-dev` (supervised-incremental-development)

## 1. What changed

The MAC View's hex pane now fits a full hex row at terminal widths ≥120 columns, and its inner scroll container fills available vertical space. `#mac_hex_pane` width went 40 → 82 (LLR-002.1); a new `#mac_hex_scroll { height: 100%; overflow: auto; }` rule was added mirroring the main `#hex_scroll` (LLR-002.2). The `<120`-column `width-narrow` regime is byte-identical (LLR-002.3). Four integration tests added; one pre-existing test that hard-coded width 40 was updated to 82.

## 2. Files modified

- `s19_app/tui/styles.tcss` — `#mac_hex_pane` width 40→82; added `#mac_hex_scroll` rule.
- `tests/test_tui_mac_layout.py` (new) — TC-004, TC-005, TC-006, TC-013.
- `tests/test_tui_directionb.py` — updated `test_tc021_mac_two_panes_fixed_regime` band 38–42 → 80–84 (+ docstring). **Existing-test assertion change, flagged below.**

**Total: 3 files** (within the 5-file cap).

## 3. How to test

```bash
python -m pytest -q tests/test_tui_mac_layout.py -m "not slow"
python -m pytest -q tests/test_tui_directionb.py -m "not slow"
python -m pytest -q tests/test_tui_hexview.py -m "not slow"
git diff main -- s19_app/tui/styles.tcss   # LLR-002.3 inspection
```

## 4. Test results

| Suite | Result |
|---|---|
| `test_tui_mac_layout.py` (new) | **4 passed in 2.48 s** |
| `test_tui_directionb.py` (incl. updated TC-021) | **101 passed in 70.51 s** |
| `test_tui_hexview.py` | **26 passed in 0.36 s** |
| `git diff` styles.tcss | only `#mac_hex_pane` width + new `#mac_hex_scroll`; `width-narrow` selectors untouched (0 lines) |

Measured geometry at `(120, 30)`: `#mac_hex_pane.region.width = 82`, `#mac_records_pane.region.width = 14`, `#mac_hex_scroll.region.height = 11` (pane 15, title 1, controls 4).

## 5. Risks

- TC-005 cannot assert literal `scroll.height == pane.height` (HLR-002 wording) because the pane stacks `#mac_hex_title` (1 row) + `#mac_hex_controls` (4 rows) above the scroll. Softened to a structural invariant: scroll height > 1, fills the remainder (`>= pane − title − controls`), and is the tallest child. This is the more robust form; HLR-002's wording should be read as "scroll fills the remaining vertical space," not pixel-equal. **Phase 6 doc note: reconcile HLR-002 threshold wording (TC-005) with this structural form.**
- Narrow-regime % bound (TC-006) is proportional to `#workspace_body` width (~113 at terminal 119), not the raw terminal width — so the pane lands at 39, not `round(119×0.35)=42`. The test asserts against body width (matching the existing TC-021 proportional tolerance) plus `hex_w < 82` to prove the fixed-82 rule didn't leak into the narrow regime.

## 6. Existing-test assertion change (loud flag)

- **File/test:** `tests/test_tui_directionb.py::test_tc021_mac_two_panes_fixed_regime`.
- **Old:** asserted `38 <= dims["hex"] <= 42` ("fixed 40 ±2 cols") at `(120,30)` and `(160,40)`.
- **New:** `80 <= dims["hex"] <= 84` ("fixed 82 ±2 cols"); docstring amended to explain the batch-05 40→82 widening.
- **Why in-scope:** LLR-002.1 changed the layout; this test pinned the old layout. The test still pins a fixed ±2 band — it was updated to the new value, not weakened or deleted.

## 7. Pending items

- US-03 (HLR-003: goto feedback + focus-row marker) — not started, correct for this increment.
- `REQUIREMENTS.md` `R-*` rows for batch-05 not updated here (batch tracks via `.dev-flow/`); Phase 6 docs decision.

## 8. Suggested next task

**Increment 3 — US-03** (HLR-003 / LLR-003.1..003.6): `_handle_goto*` out-of-range guard (`address_in_sorted_ranges` + `Address 0x... not in loaded file.` status), `focus_row_marker_address` plumbing through `render_hex_view_text` with the ASCII `>` marker, `_apply_goto` shared helper, and `_<view>_goto_focus_address` reset on the LLR-003.6 trigger set (reusing the five entry-points touched in Increment 1). Spans `app.py` + `hexview.py` + tests — the largest increment.

### Explicit answers
- **TC-005 height softened?** Yes — to a 4-part structural invariant (scroll fills remaining height; tallest child). Pane stacks title+controls above scroll, so pixel-equality is impossible.
- **Existing test asserting old width 40?** `test_tc021_mac_two_panes_fixed_regime` — updated 38–42 → 80–84.
- **MAC view need a loaded file?** No — panes compose unconditionally. Activated via `app.action_show_screen("mac")` + `await pilot.pause()`; all four queried widgets resolve with no file loaded.
