# Functionality — s19_app TUI hex viewer — Batch 2026-05-26-batch-05

**Audience:** technical stakeholder (firmware/test engineer, tech lead). Not a code walkthrough.
**Purpose:** understand what changed for the user across the three UX fixes in this batch, why it matters, and which components carry the behavior.
**Scope:** TUI-only (`s19tui`). No parser, range-engine, or validation-engine behavior changed.

This batch fixes three independent defects that surfaced from real use of the previous build. Each is described as the user experiences it (before → after), followed by a short "How it works" and the design constraints that were honored.

---

## 1. Hex-search now tracks the page

### What the user sees
- **Before:** You search for a byte string, get a hit, then page through the hex view to read around the firmware. The next time you press **Find Next**, search seemed to "stop working" — it resumed from the old hit (far behind your current view) and often reported nothing found, even though matches existed forward on the page you were looking at.
- **After:** **Find Next** resumes from the first address currently visible on your page. Search now means "find from where I'm looking now," which matches the intuitive mental model. This works identically in all three hex panes: the **main** tab, the **A2L (alt)** tab preview, and the **MAC** tab preview.

### How it works
When you page the hex window (or, on the alt/MAC tabs, select a different A2L tag or MAC record), the app drops its stale search anchor (`last_search_address` is set to `None`). On the next Find Next — when the search text is unchanged but the anchor was cleared — the handler asks **`_first_visible_hex_address(view)`** for the address of the first row currently rendered in that pane and seeds the search from there. For the main view that address comes straight from the current window position; for the alt and MAC views the renderer caches its first-row address each time it draws, so search and rendering can't disagree. Changing the search text still resets to a full-image search from the lowest address — that behavior is unchanged.

---

## 2. The MAC view hex pane is now readable

### What the user sees
- **Before:** The MAC tab's embedded hex pane was pinned to 40 columns. A full hex row (address + 16 bytes + ASCII gutter) needs roughly 80 columns, so the pane clipped or wrapped the data — an embedded hex viewer you couldn't actually read.
- **After:** On terminals 120 columns wide or more, the MAC hex pane is wide enough to show a complete hex row without wrapping or clipping, and the scrollable area fills the full height beneath the pane's title and controls. The record list beside it keeps a usable width. On narrow terminals (under 120 columns) the previous proportional layout is untouched.

### How it works
The fix lives entirely in CSS (`s19_app/tui/styles.tcss`). The **`#mac_hex_pane`** width went from 40 to 82 columns under the comfortable (≥120-column) regime — 82 fits the goto-marker padding, the `0xAAAAAAAA` address, 16 hex bytes, the ASCII gutter, and a little border slack. A new **`#mac_hex_scroll`** rule (`height: 100%; overflow: auto;`) makes the inner scroll container fill the vertical space below the pane's title (1 row) and controls (4 rows), mirroring the main `#hex_scroll`. The records pane absorbs the remaining width and stays comfortably positive (measured at 14 cells at terminal width 120). The narrow-regime selectors were left byte-identical.

---

## 3. Goto feedback and a non-disruptive focus marker

### What the user sees
- **Before:** The goto field silently accepted any integer — even an address outside the loaded image — and just shifted the window. You couldn't tell whether the address actually landed inside a real range.
- **After:** Two clear outcomes:
  - **Address not in the image →** an explicit status message: `Address 0xAAAAAAAA not in loaded file.`, and the view stays put.
  - **Valid address →** the view moves and the target row is marked with a plain `> ` glyph at the start of the line (every other row is padded with two spaces so the columns stay perfectly aligned). The marker is pure text — it does not touch the validation color scheme, the yellow search highlight, or the orange MAC overlay.
- The marker is per-view and persists when you switch tabs, but clears as soon as you page, start a new search, select a different tag/record, type a bad goto address, or load/unload a file.

### How it works
Each `_handle_goto*` handler routes through a shared **`_apply_goto(view, addr)`** helper. The helper resolves the cached sorted range index via **`_get_range_index(self.current_file)`** and runs a binary-search membership check with **`address_in_sorted_ranges(addr, range_index)`**. A miss emits the status message and returns without moving the view; a hit records the per-view focus address (`_goto_focus_address` / `_alt_goto_focus_address` / `_mac_goto_focus_address`) and moves the window. The three `update_*_hex_view` renderers forward that focus address into **`render_hex_view_text`** via the keyword-only `focus_row_marker_address` parameter; the renderer prepends `> ` to the row whose address range contains the focus address and `  ` (two spaces) to every other row, with no Rich style attached.

---

## Design constraints honored

| Constraint | How it was honored |
|------------|--------------------|
| **No `sev-*` collision** | The focus marker is plain ASCII `> ` with no Rich style and no CSS class. The validation severity classes (`sev-error/warning/info/ok/neutral`) are untouched and cannot be confused with the marker. A test asserts that no styled span overlaps the 2-cell marker region. |
| **Rendering caps untouched** | `MAX_HEX_BYTES` (65536) and `MAX_HEX_ROWS` (512) — the public rendering-cost caps exported from `tui/__init__.py` — were not changed. The marker is a 2-cell prefix per already-rendered row, so it adds no rows or bytes. |
| **`color_policy.py` unchanged** | `git diff main -- s19_app/tui/color_policy.py` is empty: `SEVERITY_CLASS_MAP`, `FOCUS_HIGHLIGHT_STYLE`, and `MAC_ADDRESS_OVERLAY_STYLE` are byte-for-byte unchanged. |
| **Narrow-regime layout preserved** | The `#workspace_body.width-narrow` selectors for the MAC panes are byte-identical to the previous build; only the comfortable-regime `#mac_hex_pane` width and the new `#mac_hex_scroll` block were added. |
| **Defense in depth on the marker** | Besides emitting no Rich style on the marker cells, the MAC hex pane hosts the text in a `Static` widget built with `markup=False`, so the `> ` glyph can never be interpreted as markup. |

---

## Assumptions, risks, next steps

**Assumptions**
- "Comfortable" MAC layout assumes a terminal ≥120 columns; below that the proportional (35%) rule still applies.
- The `> ` glyph is exactly 2 monospace cells in every terminal, so no wcwidth handling is needed.

**Risks / limitations**
- Validation ran locally on Python 3.14.4; CI on Python 3.11 is the authoritative gate and must be confirmed green on the PR before merge (behavior is version-independent).
- `_jump_to_validation_issue_by_index` also shifts the hex view but was deliberately **not** added to the focus-clear trigger set (out of scope this batch). A future batch may add an LLR for it.

**Next steps**
- Confirm the Python 3.11 CI job is green on the PR.
- Append the living-requirement rows `R-TUI-038/039/040` to `REQUIREMENTS.md` (handled by a parallel agent this phase).
- After merge, run `dev-flow-sync` to mirror `.dev-flow/` into the Obsidian vault.
