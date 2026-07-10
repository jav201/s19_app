# fast-dev-flow spec — Data Sections label readability (two-line wrap)

- **Status:** closed 2026-07-07 (code complete; AC-1..4 green; awaiting operator commit/PR)
- **Created:** 2026-07-07
- **Branch:** `claude/sections-label` @ `d0b47fd` (origin/main, incl. batch-26 entropy + batch-27 memory map)
- **Route:** /fast-dev-flow (small non-trivial UI fix; operator-approved solution via /prototype)
- **security_required:** false (see §6)

## 1. Objective
Stop the Workspace "Data Sections" range labels from clipping in the fixed 22-column `#ws_left` pane. Today `update_sections` (`app.py:7205`) builds `0x{start:08X} - 0x{end-1:08X} ({size} bytes)` (~33 chars) but the pane shows ~17, so the end address + size are cut (`0x80302040 - 0x8...`). Fix = **Variant A (two-line wrap)**, operator-approved from `scratchpad/sections_prototype.html`.

## 2. Loose user stories
- As an operator inspecting an image, I want each Data Sections entry to show the **full range** (start, end, size) without clipping in the narrow left pane, so I can read where each section is without resizing.

## 3. Scope
**In:** the range label at `app.py:7205` → two-line format (start on line 1; `– 0x{end-1:08X}  {size}B` on line 2). **The sibling MAC out-of-range label at `app.py:7228`** (`MAC out-of-range @ 0x{address:08X}`, ~29 chars, also clips) → same two-line treatment for consistency (Phase-0 decision: **IN scope**).
**Out:** widening `#ws_left` (would steal from the hex view — the C-13 tradeoff); any other pane; the Memory Map (shipped batch-27); Search/Goto; the truncation "... N more ranges ..." line (short, doesn't clip).

## 4. Acceptance criteria (observable)
- **AC-1 (the gate, black-box):** When a file whose ranges produce a label wider than the pane is loaded and the Workspace `#sections_list` renders, each range ListItem's rendered text **shall contain the end-address token `0x{end-1:08X}`** (currently absent/clipped). Verified by Textual Pilot over a fixture (e.g. `case_02` or a seeded `0x80302040`-style range): assert the end token appears in the ListItem/Label text.
- **AC-2:** A range ListItem **shall render two lines** — start address on line 1, `– <end>  <size>B` on line 2 (assert the label text contains a newline and both the start and end tokens).
- **AC-3:** MAC out-of-range ListItems **shall render the full `0x{address:08X}`** without clipping (two-line if needed), asserted through the rendered text.
- **AC-4 (regression):** The `sev-*` colour class (`css_class_for_severity`) and the `ListItem.data = (start, end)` selection payload **shall be unchanged** — selecting a section still carries its `(start, end)` and jumps the hex view (assert `item.data` intact + a Pilot select still focuses hex).

## 5. Design decision
Obvious — no architect delegation. Pure relabel in `update_sections`; no new widget, no layout/geometry change, no new breakpoint. Label uses `\n` → Textual renders two lines and the ListItem auto-grows. Colour + `.data` untouched.

## 6. Security-flag scan
Scanned objective + criteria + description against the sensitive-pattern list: **no match.** No auth/identity, secrets, external integration, PII/payment, destructive-DB, input-surface (the labels render already-parsed address/size **ints**, not file-derived strings — no markup/injection surface; **C-17 does NOT apply**), or network/exposure. → **security_required: false.**

## 7. Test plan (map each to an AC)
- `test_sections_label_shows_end_address_not_clipped` → AC-1 (Pilot, black-box).
- `test_sections_label_two_line_format` → AC-2 (white-box on the label text).
- `test_mac_out_of_range_label_full_address` → AC-3.
- `test_sections_item_data_and_colour_preserved` → AC-4 (regression).
Match `tests/test_tui_directionb.py` Pilot idiom + `_install_case_*` helpers. Engine-frozen guard (`test_engine_unchanged`) must stay green (app.py is not frozen; 0 frozen diffs expected).

## 8. Batch status
| Field | Value |
|---|---|
| Current phase | A — spec (awaiting gate) |
| Files (est.) | `s19_app/tui/app.py` + `tests/test_tui_directionb.py` (≤5) |
| Closed | — |
