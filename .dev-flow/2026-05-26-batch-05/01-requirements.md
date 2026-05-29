# Requirements Document — s19_app — Batch 2026-05-26-batch-05

> **Strict normative convention — IEEE 830 + EARS**
> - `shall` = normative, binding, verifiable. **Only** inside HLR/LLR statements.
> - `should` = informative. **Only** in rationale / explanatory text.
> - Any `should` inside an HLR/LLR statement is a writing error and a phase-2 blocker.

> **Verifiability rule.** Every `test` / `analysis` requirement carries:
> - **Executed verification:** what exactly runs (e.g. `pytest tests/test_tui_app.py::test_search_after_pagination_finds_forward`).
> - **Numeric pass threshold:** the objective pass criterion (e.g. `0 failures`, `marker glyph present in 1 row`).

---

## 1. Introduction

### 1.1 Purpose
Document the requirements for batch-05, a small UX-correctness batch that fixes three independent defects in the S19 TUI hex viewer surfaced from real use of the batch-04 build: (a) hex-search anchor goes stale after page navigation, (b) the MAC view's hex pane is too narrow to render a full hex row, and (c) the goto handler gives no feedback when the address is outside the loaded image.

### 1.2 Scope
**In scope.** Three TUI-layer changes:
- The hex-search resume behavior when `_hex_window_start` has moved due to pagination (main / alt / MAC variants).
- The CSS sizing of `#mac_hex_pane` and `#mac_hex_scroll` in `s19_app/tui/styles.tcss`.
- The `_handle_goto` family of handlers and a non-color row-marker plumbed through `render_hex_view_text` so the focus row is identifiable without disturbing the `sev-*` severity classes, the yellow search highlight, or the orange MAC overlay.

**Out of scope.** Parser/range/validation engine changes. New A2L or MAC features. The Patch Editor. Any change to the saved `.s19tool/` project format or hot-path rendering caps (`MAX_HEX_BYTES`, `MAX_HEX_ROWS`).

### 1.3 Definitions, acronyms, abbreviations
| Term | Definition |
|------|------------|
| Search anchor | The `S19TuiApp.last_search_address` field used to resume `find_string_in_mem` on the next Find Next. |
| Pagination | Moving the hex viewer window forward / backward by `hex_rows_page_size` rows via `action_hex_page_next` / `action_hex_page_prev` (and the alt/MAC dispatchers). |
| Focus row | The row that currently contains the user's last goto target address. |
| Row marker | A plain-text ASCII glyph (`> ` — `>` followed by a space) prepended to the focus row, with two-space padding on non-focus rows so columns stay aligned. No Rich style, no CSS class, no color. |
| `sev-*` classes | Validation severity CSS classes defined in `s19_app/tui/color_policy.py::SEVERITY_CLASS_MAP` (`sev-error`, `sev-warning`, `sev-info`, `sev-ok`, `sev-neutral`). Reserved for validation severity — must not be reused by the marker. |
| Loaded range | A `(start, end)` tuple in `LoadedFile.ranges` (membership checked via `address_in_sorted_ranges` from `s19_app/range_index.py`). |

### 1.4 References
- `CLAUDE.md` (repo root) — project layout, architecture, conventions.
- `REQUIREMENTS.md` (repo root) — living per-feature requirements; this batch appends new R-* rows.
- `~/.claude/templates/dev-flow/req-template-en.md` — source template for this document.
- Prior batches: `.dev-flow/2026-05-21-batch-04/01-requirements.md` (memory-edit + selective export) for naming conventions and validation-method examples.
- Source code anchors (read in Phase-1 exploration):
  - `s19_app/tui/app.py` lines 2186–2250 (pagination dispatch + main hex pagination), 4914 (`update_hex_view`), 4983 (`update_alt_hex_view`), 5044 (`update_mac_hex_view`), 5810–5849 (`_handle_search`, `_handle_goto`), 5851–5875 (`_handle_search_alt`).
  - `s19_app/tui/hexview.py` lines 151–189 (`find_string_in_mem`), 192–291 (`_collect_hex_rows`), 324–383 (`render_hex_view_text`).
  - `s19_app/tui/styles.tcss` lines 264–296 (MAC two-pane layout), 367–370 (main `#hex_scroll`).
  - `s19_app/tui/color_policy.py` lines 5–14 (`SEVERITY_CLASS_MAP`, `FOCUS_HIGHLIGHT_STYLE`, `MAC_ADDRESS_OVERLAY_STYLE`).
  - `s19_app/range_index.py` (`address_in_sorted_ranges`, `build_sorted_range_index`).

### 1.5 Document overview
§2 frames the change in product terms. §3 declares the 3 HLRs (one per user story). §4 decomposes them into 14 LLRs aligned with the implementation increments (LLR-001.1..001.4, LLR-002.1..002.4, LLR-003.1..003.6). §5 lists the validation strategy and the per-requirement TC-IDs.

---

## 2. Overall description

### 2.1 Product perspective
`s19_app` exposes a Rich CLI (`s19tool`) and a Textual TUI (`s19tui`). The TUI is the integration surface where parsers, the range/validation engine, and per-tab renderers compose. This batch is a TUI-only correction; it touches `s19_app/tui/app.py`, `s19_app/tui/hexview.py`, and `s19_app/tui/styles.tcss`. No parser/engine module is modified.

### 2.2 Product functions
The hex viewer panels (main tab, alt/A2L tab hex preview, MAC tab hex preview) shall after this batch:
- Resume Find Next searches relative to the user's current page rather than the absolute last hit.
- Render a full hex row (address + 16 bytes + ASCII) inside the MAC tab's hex pane on terminals ≥120 columns.
- Reject out-of-range goto addresses with a user-visible status message and mark valid goto-target rows with a plain-text glyph that does not collide with any color-based highlight.

### 2.3 User characteristics
End user is a firmware engineer or test engineer using `s19tui` against S19/HEX/A2L/MAC artifacts. They expect: paging behavior to be predictable, search to track the page, the MAC tab to be a legitimate hex viewer (not a teaser), and goto to fail loudly when an address isn't in the image.

### 2.4 Constraints
- Python 3.11+. Textual TUI. Single-process. CI runs `pytest -q` on Python 3.11.
- Existing `MAX_HEX_BYTES = 65536` and `MAX_HEX_ROWS = 512` rendering caps are public API exported from `tui/__init__.py` and must not change.
- `sev-*` CSS classes and the yellow / orange byte-level highlight styles are reserved for validation severity and search/MAC overlays — must not be reused by the new row marker.
- ≤5 files per increment per CLAUDE.md supervised-incremental-development rule.

### 2.5 Assumptions and dependencies
- The user stories were captured at the start of this batch from the operator's direct observation of the batch-04 build. No external ticket.
- `address_in_sorted_ranges` is the correct membership primitive (already used at `app.py:3642, 3895, 4485`).
- Terminal default width assumption: ≥120 columns for the "comfortable" MAC layout; the `width-narrow` (`< 120`) regime keeps its existing 35 % proportional rule.
- The marker is the ASCII character `>` followed by a space — exactly 2 cells in every monospace terminal. No wcwidth assertion is needed and there is no font-rendering ambiguity.

### 2.6 Source user stories

| ID | User Story | Source |
|----|------------|--------|
| US-001 | As a firmware engineer using the hex viewer, I want the hex-text search to keep working after I navigate pages, so that I do not lose the ability to find strings once I have scrolled. | Operator observation on the batch-04 build, 2026-05-26. |
| US-002 | As a firmware engineer using the MAC view, I want the embedded hex viewer pane to be wide enough to show a full hex row, so that I can actually read the information instead of having it wrap or clip. | Operator observation on the batch-04 build, 2026-05-26. |
| US-003 | As a firmware engineer using the hex viewer's goto field, I want clear feedback when the address I typed is invalid or outside the loaded image, and a non-disruptive marker on the row when the address is valid, so that I always know whether the address was accepted and where it landed — without disturbing the existing validation color scheme or the search/MAC byte highlights. | Operator observation on the batch-04 build, 2026-05-26. |

---

## 3. High-level requirements (HLR)

### HLR-001 — Hex-search resumes from current page after pagination
- **Traceability:** US-001
- **Statement:** When the user navigates the hex viewer window away from the last search hit and then triggers Find Next, the TUI shall resume the search from the first address that is currently visible on the page rather than from the stale prior hit address.
- **Rationale (informative):** The current `_handle_search` resumes from `last_search_address + 1`. After pagination, that anchor is far behind (or far ahead of) the user's viewport, so the next match often appears off-screen or the user is told "not found" even though hits exist forward. Resuming from the first visible address is the intuitive "find from where I'm looking now" behavior and matches the operator's mental model.
- **Validation:** test
- **Executed verification:** `pytest -q tests/test_tui_app.py -k "search_after_pagination"`
- **Numeric pass threshold:** 0 failures across the three view variants (main / alt / MAC).
- **Priority:** high

### HLR-002 — MAC hex pane shows a full hex row at ≥120 columns
- **Traceability:** US-002
> Phase-6 reconciliation (2026-05-28): reworded the inner-scroll threshold from "fill the full vertical extent of the pane" (literal `scroll.height == pane.height`) to "fill the REMAINING vertical space below the title and controls, and be the tallest child of the pane." The pane stacks `#mac_hex_title` (1 row) + `#mac_hex_controls` (4 rows) above the scroll, so pixel-equality with the pane is structurally impossible; the implemented/tested invariant is the more-robust remainder form (Phase-4 §5 doc-debt item 3).
- **Statement:** While the terminal width is ≥120 columns, the MAC tab's hex pane shall render at least one full hex row (`> ` marker padding + `0xAAAAAAAA  ` + 16 hex bytes + ASCII gutter, ≈81 visible columns including the goto marker padding) without horizontal wrapping or clipping, and its inner scroll container (`#mac_hex_scroll`) shall fill the REMAINING vertical space of the pane below `#mac_hex_title` (1 row) and `#mac_hex_controls` (4 rows) and be the tallest child of the pane.
- **Rationale (informative):** The current `#mac_hex_pane { width: 40 }` cannot fit a full hex row (marker padding + address + 16 bytes + ASCII + separators ≈ 81 cols), so users see a clipped or wrapped pane that defeats the purpose of an embedded hex viewer. The `width-narrow` (<120 cols) regime is left untouched because the proportional 35% rule there is already the best compromise for narrow terminals.
- **Validation:** test (integration) + inspection
- **Executed verification:** `pytest -q tests/test_tui_hexview.py -k "mac_hex_pane or mac_hex_scroll"` driving `App.run_test(size=(120, 30))`; plus reading `s19_app/tui/styles.tcss` to confirm (a) `#mac_hex_pane { width: 82 }` under the comfortable regime, (b) a `#mac_hex_scroll { height: 100%; overflow: auto; }` rule exists, and (c) the `#workspace_body.width-narrow #mac_hex_pane { width: 35% }` rule is unchanged.
- **Numeric pass threshold:** rendered `#mac_hex_pane.region.width ≥ 82` at terminal width 120; `#mac_hex_scroll.region.height >= #mac_hex_pane.region.height − (title + controls height)` (i.e. the scroll fills the remaining vertical space below the 1-row title and 4-row controls) and `#mac_hex_scroll` is the tallest child of `#mac_hex_pane` at the same size; `git diff` over the two `width-narrow` selectors reports 0 changed lines.
- **Priority:** high

### HLR-003 — Goto gives explicit feedback and a non-color row marker
- **Traceability:** US-003
- **Statement:** When the user submits a goto address, the TUI shall (a) emit an explicit status message of the form `Address 0xAAAAAAAA not in loaded file.` if the address is not contained in any loaded range, and (b) on a valid address, set a per-view focus address that is rendered as a plain-text ASCII marker (`> ` — `>` followed by a space) prepended to the focus row and `  ` (two spaces) on every other row, without applying any Rich style, CSS class, or color attribute, and without modifying the existing `sev-*`, `FOCUS_HIGHLIGHT_STYLE`, or `MAC_ADDRESS_OVERLAY_STYLE` styling.
- **Rationale (informative):** The current `_handle_goto` silently accepts any integer (even one outside the loaded image) and only shifts the window, so users can't tell whether the address landed in a real range. A color-based marker would collide with the validation severity classes and the byte-level overlays, so a pure-text glyph is the safest signal. Two-space padding on non-focus rows preserves column alignment so the rest of the viewer is undisturbed.
- **Validation:** test
- **Executed verification:** `pytest -q tests/test_tui_app.py -k "goto_out_of_range or goto_focus_marker"` plus inspection of `s19_app/tui/color_policy.py` to confirm `SEVERITY_CLASS_MAP`, `FOCUS_HIGHLIGHT_STYLE`, and `MAC_ADDRESS_OVERLAY_STYLE` are unchanged.
- **Numeric pass threshold:** 0 failures; exactly 1 row carries the `> ` prefix on a valid hit; 0 rows carry it on an invalid (out-of-range) goto; 0 changes to the three colour constants.
- **Priority:** high

---

## 4. Low-level requirements (LLR)

### LLR-001.1 — Pagination clears the search anchor (main hex view)
- **Traceability:** HLR-001
- **Statement:** When `action_hex_page_next` or `action_hex_page_prev` mutates `_hex_window_start`, the `S19TuiApp` shall set `self.last_search_address = None` before returning.
- **Validation:** test (integration)
- **Executed verification:** `pytest -q tests/test_tui_app.py::test_main_hex_pagination_clears_search_anchor`
- **Numeric pass threshold:** 0 failures; `last_search_address is None` asserted after each of `action_hex_page_next` and `action_hex_page_prev`.
- **Acceptance criteria (informative):**
  - Calling the action with no file loaded must not raise (guards remain in place).
  - The anchor is cleared regardless of whether the window actually moved (i.e. even if clamped at `max_start` or `0`).

### LLR-001.2 — Search resumes from first visible address when anchor is `None`
- **Traceability:** HLR-001
- **Statement:** When `_handle_search` is invoked with `self.last_search_address is None` and `self.last_search_text == query` (i.e. paginated since the prior hit), the handler shall compute `start_address` as the first address in `current_file.row_bases` at index `self._hex_window_start` and pass that to `find_string_in_mem`.
- **Validation:** test (integration)
- **Executed verification:** `pytest -q tests/test_tui_app.py::test_search_after_pagination_resumes_from_visible_address`
- **Numeric pass threshold:** 0 failures; `find_string_in_mem` receives the address returned by the new helper `_first_visible_hex_address("main")`.
- **Acceptance criteria (informative):**
  - If `row_bases` is empty or `_hex_window_start` is out of bounds, the handler falls back to `start_address = None` (search from the lowest mem_map key).
  - When the user changes the search text, the existing reset to `None` keeps its full-image semantics (start from address 0 / lowest key).
  - When `find_string_in_mem` returns `None`, the anchor stays `None` and the next `_handle_search` invocation again resumes from `_first_visible_hex_address(view)` — i.e. the miss-after-pagination round-trip is idempotent.

### LLR-001.3 — Alt (A2L) tab parity: tag-selection clears the anchor; search resumes from first visible alt hex row
- **Traceability:** HLR-001
- **Statement:** When the alt (A2L) tab's hex pane is re-rendered in response to a tag-selection change (via the existing `_jump_to_tag` / `_handle_a2l_tag_find_next` entry-points), the `S19TuiApp` shall set `self.last_search_address = None`; the next `_handle_search_alt` shall resume from `_first_visible_hex_address("alt")` — defined as the address of the first row currently rendered in the alt hex pane.
- **Validation:** test (integration)
- **Executed verification:** `pytest -q tests/test_tui_app.py -k "search_after_pagination_alt or alt_tag_selection_clears_search_anchor"`
- **Numeric pass threshold:** 0 failures across the alt variant (≥2 test cases: anchor cleared after `_jump_to_tag`; `_handle_search_alt` after a clear receives the first-visible alt address).
- **Acceptance criteria (informative):**
  - The handler routes through the shared `_first_visible_hex_address(view: str)` helper with `view = "alt"`.
  - The alt hex pane has no independent `_alt_hex_window_start` field; it re-renders in response to tag selection. The trigger is therefore the tag-selection entry-points, not a pagination action.

### LLR-001.4 — MAC tab parity: record-selection clears the anchor; search resumes from first visible MAC hex row
- **Traceability:** HLR-001
> Phase-6 reconciliation (2026-05-28): the entry-point name was corrected from the non-existent `_on_mac_records_row_highlighted` to the actual MAC record-selection entry-point `_jump_to_mac_address` (`s19_app/tui/app.py:3192`). Behavior was always correct; only the symbol name was wrong (Phase-4 §5 doc-debt item 1).
- **Statement:** When the MAC tab's hex pane is re-rendered in response to a MAC record selection change (via `_jump_to_mac_address` or the equivalent entry-point), the `S19TuiApp` shall set `self.last_search_address = None`; the next `_handle_search_mac` shall resume from `_first_visible_hex_address("mac")` — defined as the address of the first row currently rendered in the MAC hex pane.
- **Validation:** test (integration)
- **Executed verification:** `pytest -q tests/test_tui_app.py -k "search_after_pagination_mac or mac_record_selection_clears_search_anchor"`
- **Numeric pass threshold:** 0 failures across the MAC variant (≥2 test cases: anchor cleared after `_jump_to_mac_address`; `_handle_search_mac` after a clear receives the first-visible MAC address).
- **Acceptance criteria (informative):**
  - The handler routes through the shared `_first_visible_hex_address(view: str)` helper with `view = "mac"`.
  - The MAC hex pane has no independent `_mac_hex_window_start` field; it re-renders in response to record selection. The trigger is therefore the record-selection entry-point, not a pagination action.
  - `_first_visible_hex_address(view)` accepts `view ∈ {"main", "alt", "mac"}`. For `"main"` it reads `current_file.row_bases[self._hex_window_start]`. For `"alt"` and `"mac"` it reads a cached first-row-base value set on the `S19TuiApp` instance from inside the most recent `update_<view>_hex_view()` call (cache approach chosen over recompute to avoid renderer-state coupling).

### LLR-002.1 — `#mac_hex_pane` width is set to 82 columns at ≥120 cols
- **Traceability:** HLR-002
- **Statement:** The CSS rule for `#mac_hex_pane` in `s19_app/tui/styles.tcss` (the rule currently at lines 282–285) shall declare `width: 82;` under the comfortable (≥120-column) regime.
- **Validation:** test (integration) + inspection
- **Executed verification:** Read `s19_app/tui/styles.tcss` and confirm the literal token `width: 82` appears in the `#mac_hex_pane` selector block outside any `width-narrow` qualifier; plus `pytest -q tests/test_tui_hexview.py::test_mac_hex_pane_width_at_wide_terminal` driving `App.run_test(size=(120, 30))` and asserting `app.query_one("#mac_hex_pane").region.width >= 82`.
- **Numeric pass threshold:** Exactly one matching declaration; value ≥ 82.
- **Acceptance criteria (informative):**
  - The value 82 = `2 (marker padding) + 10 (0xAAAAAAAA  — 8 hex digits + "0x" prefix + 2-space gap) + 47 (16 × "XX " minus the final trailing space) + 2 (" |") + 16 (ASCII gutter) + 1 ("|") + 4 (slack for border/padding) ≈ 82`.

### LLR-002.2 — `#mac_hex_scroll` fills available vertical space
- **Traceability:** HLR-002
- **Statement:** A new CSS rule `#mac_hex_scroll { height: 100%; overflow: auto; }` shall be added to `s19_app/tui/styles.tcss`, mirroring the existing `#hex_scroll` rule at lines 367–370.
- **Validation:** test (integration) + inspection
- **Executed verification:** Read `s19_app/tui/styles.tcss` and grep for `#mac_hex_scroll`; confirm exactly one block with `height: 100%` and `overflow: auto`.
- **Numeric pass threshold:** Exactly one such block present.
- **Acceptance criteria (informative):**
  - The selector matches the existing widget id used in the MAC tab compose tree (verified by inspection of `app.py` compose).

### LLR-002.3 — The `width-narrow` regime for the MAC hex pane is preserved unchanged
- **Traceability:** HLR-002
- **Statement:** The `#workspace_body.width-narrow #mac_hex_pane { width: 35%; }` rule and the `#workspace_body.width-narrow #mac_records_pane { width: 1fr; }` rule in `styles.tcss` shall remain byte-identical to their pre-batch state.
- **Validation:** test (integration) + inspection
- **Executed verification:** `git diff main -- s19_app/tui/styles.tcss` for the lines defining the two `width-narrow` rules.
- **Numeric pass threshold:** 0 lines changed inside those two selector blocks.
- **Acceptance criteria (informative):**
  - Diff context shown by `git diff` must not touch the `width-narrow` rules; only `#mac_hex_pane` (comfortable regime) and the new `#mac_hex_scroll` block are added/modified.

### LLR-002.4 — The records pane retains a strictly-positive width at 120 cols
- **Traceability:** HLR-002
- **Statement:** While the terminal width is ≥120 columns, the `#mac_records_pane.region.width` shall be ≥ 1 cell.
- **Validation:** test (integration) + inspection
- **Executed verification:** `pytest -q tests/test_tui_hexview.py::test_mac_records_pane_positive_width_at_wide_terminal` driving `App.run_test(size=(120, 30))` and asserting `app.query_one("#mac_records_pane").region.width >= 1`.
- **Numeric pass threshold:** 0 failures; `mac_records_pane.region.width >= 1` at terminal width 120.
- **Acceptance criteria (informative):**
  - This closes the symmetric invariant left implicit when LLR-002.1 raised `#mac_hex_pane` to 82 cols: at terminal width 120 the records pane gets approximately `120 − 82 − borders` columns, which must remain non-zero so the operator can still see the record list.

### LLR-003.1 — `_handle_goto` rejects addresses outside loaded ranges
- **Traceability:** HLR-003
> Phase-6 reconciliation (2026-05-28): corrected the range accessor from the non-existent `self.current_file.sorted_ranges` to the real path — `LoadedFile` exposes `ranges` (not `sorted_ranges`); the handler resolves the cached index via `self._get_range_index(self.current_file)` then calls `address_in_sorted_ranges(addr, range_index)`. Behavior (binary-search membership) always matched the LLR intent; only the symbol/signature wording was wrong (Phase-4 §5 doc-debt item 2).
- **Statement:** When `_handle_goto` parses a valid integer address, the handler shall resolve the cached sorted range index via `range_index = self._get_range_index(self.current_file)`, call `address_in_sorted_ranges(addr, range_index)` and, if the result is `False`, emit `self.set_status(f"Address 0x{addr:08X} not in loaded file.")` and return without mutating `_goto_focus_address` or calling `update_hex_view`.
- **Validation:** test (integration)
- **Executed verification:** `pytest -q tests/test_tui_app.py::test_handle_goto_out_of_range_sets_status_and_does_not_move_view`
- **Numeric pass threshold:** 0 failures; status text starts with `Address 0x` and ends with `not in loaded file.`; `_goto_focus_address` remains `None`.
- **Acceptance criteria (informative):**
  - The existing `int(raw, 0)` parse-error branch keeps its `Invalid address format.` status — this LLR adds the second guard only.
  - The membership check uses the sorted range index (binary search) built from `LoadedFile.ranges` via `_get_range_index`, not a linear scan and not a `sorted_ranges` attribute (which does not exist).

### LLR-003.2 — On a valid hit, `_handle_goto` records the focus address
- **Traceability:** HLR-003
- **Statement:** When `address_in_sorted_ranges` returns `True`, `_handle_goto` shall set `self._goto_focus_address = addr` before calling `self.update_hex_view(addr)` and emitting the existing `Goto 0x{addr:08X}` status.
- **Validation:** test (integration)
- **Executed verification:** `pytest -q tests/test_tui_app.py::test_handle_goto_valid_hit_sets_focus_address`
- **Numeric pass threshold:** 0 failures; `app._goto_focus_address == addr` post-call.
- **Acceptance criteria (informative):**
  - The field defaults to `Optional[int] = None` on `S19TuiApp` initialization.

### LLR-003.3 — `render_hex_view_text` accepts `focus_row_marker_address` and emits the glyph
- **Traceability:** HLR-003
- **Statement:** `render_hex_view_text` in `s19_app/tui/hexview.py` shall accept a new keyword-only parameter `focus_row_marker_address: Optional[int] = None` and, for each row, prepend either `> ` (`>` followed by a space, when `row_addr <= focus_row_marker_address < row_addr + HEX_WIDTH`) or `  ` (two spaces) otherwise, with no Rich `style` argument on the appended marker.
- **Validation:** test (unit)
- **Executed verification:** `pytest -q tests/test_tui_hexview.py::test_render_hex_view_text_focus_row_marker_present_on_match` and `::test_render_hex_view_text_focus_row_marker_absent_when_unset`
- **Numeric pass threshold:** 0 failures; exactly 1 row contains the `> ` prefix when the address falls inside one of the rendered rows; 0 rows contain it when `focus_row_marker_address is None`; column alignment of the hex bytes is identical with and without the marker.
- **Acceptance criteria (informative):**
  - The marker is appended via `text.append("> ")` / `text.append("  ")` with no `style=` argument, so the Text span carries the default style.
  - The default value `None` preserves backward compatibility for all existing callers and tests.
  - The marker is forwarded into the MAC hex pane via a Static widget constructed with `markup=False` (`app.py:1493`); this preserves the defense-in-depth check (no `style=` on the appended cells, plus `markup=False` on the host widget).

### LLR-003.4 — The three `update_*_hex_view` renderers forward `focus_row_marker_address`
- **Traceability:** HLR-003
- **Statement:** `update_hex_view`, `update_alt_hex_view`, and `update_mac_hex_view` in `s19_app/tui/app.py` shall pass `focus_row_marker_address=self._goto_focus_address` (main) or the matching `_alt_goto_focus_address` / `_mac_goto_focus_address` per-view field to `render_hex_view_text`.
- **Validation:** test (unit)
- **Executed verification:** `pytest -q tests/test_tui_app.py -k "goto_focus_marker_forwarded"`
- **Numeric pass threshold:** 0 failures across the three renderers (≥3 test cases or one parameterised case).
- **Acceptance criteria (informative):**
  - The field name convention is `_<view>_goto_focus_address` for parity with the existing `_<view>_hex_window_start` naming.

### LLR-003.5 — Parity of out-of-range and focus-marker behavior across alt / MAC
- **Traceability:** HLR-003
- **Statement:** `_handle_goto_alt` and `_handle_goto_mac` shall apply the same address-in-range check, status message, focus-address assignment, and downstream marker forwarding as `_handle_goto`, operating on `_alt_goto_focus_address` and `_mac_goto_focus_address` respectively.
- **Validation:** test (integration)
- **Executed verification:** `pytest -q tests/test_tui_app.py -k "goto_out_of_range and (alt or mac)"` and `-k "goto_focus and (alt or mac)"`
- **Numeric pass threshold:** 0 failures across both variants (≥4 test cases).
- **Acceptance criteria (informative):**
  - The three handlers share a private helper `_apply_goto(view: str, addr: int) -> bool` to avoid drift; the helper returns `True` on a valid hit and `False` on out-of-range.
  - The `_apply_goto(view, addr) -> bool` helper is a Phase-1 derivation (not an explicit plan item), bounded to `s19_app/tui/app.py`; it shares the membership-check / status / focus-assignment logic across all three `_handle_goto*` handlers.

### LLR-003.6 — Focus address is cleared on pagination, new search, parse-error goto, tag-find, file load/unload
- **Traceability:** HLR-003
- **Statement:** The corresponding `_<view>_goto_focus_address` shall be reset to `None` on every trigger that mutates the active hex window or invalidates the goto target, namely:
  - main view: `action_hex_page_next`, `action_hex_page_prev`, `_handle_search` invoked with a new search term, the `int(raw, 0)` parse-error branch in `_handle_goto` (clear `_goto_focus_address` before the early return), file-load (`current_file` replaced), file-unload (`current_file = None`);
  - alt view: `action_a2l_tags_page_next`, `action_a2l_tags_page_prev`, `_jump_to_tag`, `_handle_a2l_tag_find_next`, `_handle_search_alt` invoked with a new search term, the `int(raw, 0)` parse-error branch in `_handle_goto_alt`, file-load, file-unload;
  - mac view: `action_mac_records_page_next`, `action_mac_records_page_prev`, `_jump_to_mac_address`, `_handle_search_mac` invoked with a new search term, the `int(raw, 0)` parse-error branch in `_handle_goto_mac`, file-load, file-unload.

  Tab/view switches shall NOT clear `_<view>_goto_focus_address` — the focus address persists per view across tab switches, and is cleared only on file-load / file-unload or one of the per-view triggers enumerated above.
- **Validation:** test (integration)
- **Executed verification:** `pytest -q tests/test_tui_app.py -k "goto_focus_cleared"`
- **Numeric pass threshold:** 0 failures; `_<view>_goto_focus_address is None` asserted after each per-view trigger above — explicit enumeration yields ≥17 trigger cases (7 main + 6 alt + 6 mac, counting file-load and file-unload once per view; the parse-error branch is one case per view); plus a positive-control case asserting the focus address is NOT cleared by a pure tab-switch.
- **Acceptance criteria (informative):**
  - The reset is centralised in the same `_first_visible_hex_address` helper region (or an adjacent helper) so anchor-clear and focus-clear cannot diverge.
  - File-unload covers the `current_file = None` branch in addition to explicit re-load.
  - Tab/view switch policy (focus persists per view) is documented explicitly so the implementer does not have to guess.

---

## 5. Validation strategy

### 5.1 Methods

- **test (unit)** — Primary method for `render_hex_view_text` marker emission (TC-009a/b) and the `update_*_hex_view` renderer-forwarding TC-010. Pure-function or single-method behaviors are exercised by direct calls in `pytest` modules under `tests/test_tui_hexview.py` and `tests/test_tui_app.py`, using `SimpleNamespace`-style fixtures (see `tests/test_tui_hexview.py` baseline). Tests use tiny purpose-built fixtures (a ≤256-byte S19 with ≥3 row bases for pagination, and a few in-range / out-of-range addresses for goto). The repository's stress-sized `large_s19` / `large_mac` generators are NOT used by this batch — they remain reserved for `@pytest.mark.slow` cases per commit 86f4910. Numeric pass threshold is universally `0 failures`.
- **test (integration)** — Used where the LLR requires the Textual app object: state transitions on pagination (`last_search_address`, `_<view>_goto_focus_address` reset), three-pane parity, and CSS-driven layout under a concrete terminal size. Driven through the `App.run_test()` async pilot pattern already established in `tests/test_tui_snapshot.py` and `tests/test_tui_commandbar.py`. Numeric pass threshold is `0 failures` per case; assertions target observable app fields and rendered hex panel `.plain` text.
- **inspection** — Paired with `test (integration)` for the CSS-targeted LLR-002.1, LLR-002.2, LLR-002.3, and LLR-002.4 — the Textual `styles.tcss` rules cannot be cleanly introspected via the live `App` style cascade at the resolution required (computed `width: 82` is layout-dependent), and a `git diff` check is the most deterministic way to assert the narrow-regime is byte-identical. Each such LLR is **paired** with a `pytest -q tests/test_tui_hexview.py -k "mac_hex_pane or mac_hex_scroll or mac_records_pane"` regression test that asserts the rendered MAC pane shape in cells via `App.run_test(size=(W, 30))`, so the pytest form is the executed verification of record and inspection serves as the human-readable corroboration. Pass threshold: `mac_hex_pane.region.width >= 82` at width 120; `mac_records_pane.region.width >= 1` at width 120; narrow regime byte-identical to pre-batch.
- **demo** — Not used as a primary method for any LLR in this batch. The marker glyph is verified by substring assertion on `text.plain`; visual confirmation is reserved for Phase 4 final sanity walk-through and is not coverage of record.
- **analysis** — Not used in this batch. No probabilistic, statistical, or load-bound claim appears in any HLR/LLR — every rule is a deterministic single-call assertion.

### 5.2 Coverage matrix

TC-IDs are aligned with the `Executed verification` strings the architect already pinned in §3 and §4 — each TC is the pytest node specified there, not a renaming.

| Req ID | TC-ID(s) | Method | Notes (Executed verification · Numeric pass threshold) |
|--------|----------|--------|--------------------------------------------------------|
| HLR-001 | TC-001, TC-002, TC-002b, TC-002c, TC-003, TC-003b | test (integration) | Roll-up of LLR-001.1/.2/.3/.4 — green only if all four pass. **Executed verification:** `pytest -q tests/test_tui_app.py -k "search_after_pagination or main_hex_pagination_clears_search_anchor or alt_tag_selection_clears_search_anchor or mac_record_selection_clears_search_anchor"`. **Numeric pass threshold:** 0 failures across the six TCs (main pagination + main empty-fallback + main miss-round-trip + alt tag-selection + mac record-selection). |
| LLR-001.1 | TC-001 | test (integration) | Pagination clears the search anchor. **Executed verification:** `pytest -q tests/test_tui_app.py::test_main_hex_pagination_clears_search_anchor`. **Numeric pass threshold:** 0 failures; `app.last_search_address is None` asserted after each of `action_hex_page_next` and `action_hex_page_prev` (also when the window is already clamped at `max_start` / `0`). |
| LLR-001.2 | TC-002, TC-002b, TC-002c | test (integration) | Cleared anchor resumes from first visible address; miss-after-pagination round-trip; empty-`row_bases` fallback. **Executed verification:** (TC-002) `pytest -q tests/test_tui_app.py::test_search_after_pagination_resumes_from_visible_address`; (TC-002b) `pytest -q tests/test_tui_app.py::test_search_miss_after_pagination_round_trip_resumes_from_first_visible`; (TC-002c) `pytest -q tests/test_tui_app.py::test_search_after_pagination_empty_row_bases_falls_back_to_none`. **Numeric pass threshold:** 0 failures. (TC-002) `find_string_in_mem` is called with the address returned by `_first_visible_hex_address("main")` (matches `current_file.row_bases[_hex_window_start]`). (TC-002b) when `find_string_in_mem` returns `None`, the anchor stays `None` and the next `_handle_search` invocation again resumes from `_first_visible_hex_address("main")`. (TC-002c) when `app.current_file.row_bases == []` or `_hex_window_start == len(row_bases)`, the post-pagination `_handle_search` call receives `start_address=None`. |
| LLR-001.3 | TC-003 | test (integration) | Alt (A2L) tab: tag-selection clears the anchor; `_handle_search_alt` after a clear resumes from first visible alt hex address. **Executed verification:** `pytest -q tests/test_tui_app.py -k "search_after_pagination_alt or alt_tag_selection_clears_search_anchor"`. **Numeric pass threshold:** 0 failures across the alt variant (≥2 test cases); handler routes through `_first_visible_hex_address("alt")`. |
| LLR-001.4 | TC-003b | test (integration) | MAC tab: record-selection clears the anchor; `_handle_search_mac` after a clear resumes from first visible MAC hex address. **Executed verification:** `pytest -q tests/test_tui_app.py -k "search_after_pagination_mac or mac_record_selection_clears_search_anchor"`. **Numeric pass threshold:** 0 failures across the MAC variant (≥2 test cases); handler routes through `_first_visible_hex_address("mac")`. |
| HLR-002 | TC-004, TC-005, TC-006, TC-013 | test (integration) + inspection | Roll-up of LLR-002.1/.2/.3/.4 — MAC hex pane fits a full hex row at ≥120 cols, scroll fills vertically, narrow regime preserved, records pane retains positive width. **Executed verification:** `pytest -q tests/test_tui_hexview.py -k "mac_hex_pane or mac_hex_scroll or mac_records_pane"` plus `git diff main -- s19_app/tui/styles.tcss` confirming the `width-narrow` rules are untouched. **Numeric pass threshold:** 0 failures; rendered pane width in cells ≥ 82 at 120 cols; `mac_records_pane.region.width >= 1` at 120 cols; 0 lines changed inside `width-narrow` selectors. |
| LLR-002.1 | TC-004 | test (integration) + inspection | `#mac_hex_pane { width: 82 }` at ≥120 cols. **Executed verification (primary):** `pytest -q tests/test_tui_hexview.py::test_mac_hex_pane_width_at_wide_terminal` driving `App.run_test(size=(120, 30))` and asserting `app.query_one("#mac_hex_pane").region.width >= 82`. **Executed verification (inspection):** read `s19_app/tui/styles.tcss` and confirm the literal `width: 82` token in the `#mac_hex_pane` block outside any `width-narrow` qualifier. **Numeric pass threshold:** 0 failures; exactly 1 matching declaration; rendered width ≥ 82. |
| LLR-002.2 | TC-005 | test (integration) + inspection | `#mac_hex_scroll { height: 100%; overflow: auto; }`. *Phase-6 reconciliation (2026-05-28): pixel-equality with the pane is structurally impossible — the pane stacks `#mac_hex_title` (1 row) + `#mac_hex_controls` (4 rows) above the scroll — so the assertion is the remainder-fill / tallest-child invariant.* **Executed verification (primary):** `pytest -q tests/test_tui_hexview.py::test_mac_hex_scroll_fills_pane_height` driving `App.run_test(size=(120, 30))` and asserting `#mac_hex_scroll.region.height >= #mac_hex_pane.region.height − (title + controls height)` (scroll fills the remaining vertical space) and that `#mac_hex_scroll` is the tallest child of `#mac_hex_pane`. **Executed verification (inspection):** grep `s19_app/tui/styles.tcss` for `#mac_hex_scroll` — exactly one block with `height: 100%` and `overflow: auto`. **Numeric pass threshold:** 0 failures; exactly 1 block present; scroll height fills the remainder below title+controls and is the tallest child. |
| LLR-002.3 | TC-006 | test (integration) + inspection | Narrow-regime (< 120 cols) preserved byte-identical. **Executed verification (primary):** `pytest -q tests/test_tui_hexview.py::test_mac_hex_pane_narrow_regime_unchanged` driving `App.run_test(size=(119, 30))` and asserting `mac_hex_pane.region.width` is within ±1 cell of `round(119 * 0.35)`. **Executed verification (inspection):** `git diff main -- s19_app/tui/styles.tcss` for the two `width-narrow` selectors. **Numeric pass threshold:** 0 failures; 0 lines changed inside `width-narrow` selectors. |
| LLR-002.4 | TC-013 | test (integration) + inspection | Records pane retains a strictly-positive width at 120 cols. **Executed verification:** `pytest -q tests/test_tui_hexview.py::test_mac_records_pane_positive_width_at_wide_terminal` driving `App.run_test(size=(120, 30))` and asserting `app.query_one("#mac_records_pane").region.width >= 1`. **Numeric pass threshold:** 0 failures; `mac_records_pane.region.width >= 1` at terminal width 120. |
| HLR-003 | TC-007, TC-008, TC-009a, TC-009b, TC-010, TC-011, TC-012 | test (unit) + test (integration) | Roll-up of LLR-003.1..6 — goto validates, marks the focus row with `> `, marker is non-colliding, focus clears on view-mutating events. **Executed verification:** `pytest -q tests/test_tui_app.py tests/test_tui_hexview.py -k "goto or focus_row_marker"`. **Numeric pass threshold:** 0 failures across all 7 TCs; the three colour constants in `s19_app/tui/color_policy.py` are byte-for-byte unchanged. |
| LLR-003.1 | TC-007 | test (integration) | `_handle_goto` rejects out-of-range and emits status. **Executed verification:** `pytest -q tests/test_tui_app.py::test_handle_goto_out_of_range_sets_status_and_does_not_move_view`. **Numeric pass threshold:** 0 failures; for an address not in any loaded range, `address_in_sorted_ranges(...)` returns `False`, `set_status` is called once with a message starting `Address 0x` and ending `not in loaded file.`, `app._goto_focus_address` remains `None`, and `update_hex_view` is not called. |
| LLR-003.2 | TC-008 | test (integration) | Valid goto sets `_goto_focus_address`. **Executed verification:** `pytest -q tests/test_tui_app.py::test_handle_goto_valid_hit_sets_focus_address`. **Numeric pass threshold:** 0 failures; after submitting an in-range address `addr`, `app._goto_focus_address == addr` and `update_hex_view(addr)` is called exactly once. |
| LLR-003.3 | TC-009a, TC-009b | test (unit) | `render_hex_view_text` accepts `focus_row_marker_address` and emits `> ` on the focus row, `  ` elsewhere, with no Rich style on the marker cells. **Executed verification:** `pytest -q tests/test_tui_hexview.py::test_render_hex_view_text_focus_row_marker_present_on_match` (TC-009a) and `pytest -q tests/test_tui_hexview.py::test_render_hex_view_text_focus_row_marker_absent_when_unset` (TC-009b). **Numeric pass threshold:** 0 failures. (009a) exactly 1 line in `text.plain` starts with `> `; every other rendered hex row starts with `  `; for each rendered row, no `Span` in `text.spans` overlaps columns `[row_offset, row_offset+2)` with a non-default `Style`; OR if a span does overlap, its `style` resolves to `Style.null()` / the empty style (per `rich.style.Style.parse('')`); column alignment of the hex bytes is identical with and without the marker. (009b) When `focus_row_marker_address is None`, 0 lines contain `> `. |
| LLR-003.4 | TC-010 | test (unit) | Three `update_*_hex_view` renderers forward the focus address. **Executed verification:** `pytest -q tests/test_tui_app.py -k "goto_focus_marker_forwarded"` (parametrized across `update_hex_view`, `update_alt_hex_view`, `update_mac_hex_view`). The monkeypatch target is `s19_app.tui.app.render_hex_view_text` (the imported alias inside `app.py`), not the canonical `s19_app.tui.hexview.render_hex_view_text`. **Numeric pass threshold:** 0 failures; a monkeypatched `render_hex_view_text` records `kwargs["focus_row_marker_address"]` and the recorded value equals `app._goto_focus_address` / `_alt_goto_focus_address` / `_mac_goto_focus_address` for the matching view (≥3 cases). |
| LLR-003.5 | TC-011 | test (integration) | Parity across alt + MAC goto handlers. **Executed verification:** `pytest -q tests/test_tui_app.py -k "goto_out_of_range and (alt or mac)"` and `-k "goto_focus and (alt or mac)"`. **Numeric pass threshold:** 0 failures across both variants (≥4 test cases); all three handlers route through the shared `_apply_goto(view, addr) -> bool` helper. |
| LLR-003.6 | TC-012 | test (integration) | Focus address cleared on pagination, new search, parse-error goto, tag-find, file load/unload — explicit per-view × per-trigger enumeration. **Executed verification:** `pytest -q tests/test_tui_app.py -k "goto_focus_cleared"`. **Numeric pass threshold:** 0 failures; `_<view>_goto_focus_address is None` asserted after each of: (main) `action_hex_page_next`, `action_hex_page_prev`, `_handle_search` with a new term, parse-error branch in `_handle_goto`, file-load, file-unload (6 cases); (alt) `action_a2l_tags_page_next`, `action_a2l_tags_page_prev`, `_jump_to_tag`, `_handle_a2l_tag_find_next`, `_handle_search_alt` with a new term, parse-error branch in `_handle_goto_alt`, file-load, file-unload (8 cases); (mac) `action_mac_records_page_next`, `action_mac_records_page_prev`, `_jump_to_mac_address`, `_handle_search_mac` with a new term, parse-error branch in `_handle_goto_mac`, file-load, file-unload (7 cases) — total ≥21 trigger cases; plus a positive-control case asserting tab-switch does NOT clear the focus address. |

### 5.3 Batch acceptance criteria
- 100 % of LLRs covered by at least one TC with a defined executed verification and numeric pass threshold — verified by §5.2 (all 14 LLRs map to ≥1 TC; LLR-001.2 maps to 3, LLR-003.3 maps to 2).
- 0 blocker fails in Phase 4 validation.
- `pytest -q` (default `-m "not slow"`) is green on Python 3.11 on the CI matrix defined in `.github/workflows/tui-ci.yml`. No batch-05 TC depends on `@pytest.mark.slow` fixtures.
- No `should` inside any HLR / LLR statement (Phase-2 blocker class) — Independent re-check via Grep tool with pattern `\bshould\b` over `.dev-flow/2026-05-26-batch-05/01-requirements.md` returns 0 hits inside `### HLR-*` or `### LLR-*` blocks (matches in rationale / informative paragraphs are allowed).
- `sev-*` classes in `s19_app/tui/color_policy.py::SEVERITY_CLASS_MAP` and the `FOCUS_HIGHLIGHT_STYLE` / `MAC_ADDRESS_OVERLAY_STYLE` constants are byte-for-byte unchanged — verified by `git diff main -- s19_app/tui/color_policy.py` reporting 0 changed lines in those definitions.
- The new row-marker code path emits no Rich style on the marker cells — verified by the negative-span assertion in TC-009a.

---

## 6. Appendices

### 6.1 Extended glossary
*(Filled in if Phase-1 / Phase-2 surfaces new terminology.)*

### 6.2 Relevant design decisions
- Reuse `address_in_sorted_ranges` rather than re-walking `ranges` in handler code.
- Marker glyph is plain ASCII `> ` (single `>` + space, 2 cells in every monospace terminal), not a CSS class, so it cannot collide with validation severity or byte-level overlays. Rationale documented in `1.3` and `2.4`. The choice of ASCII over `▶` (U+25B6) avoids East-Asian Width ambiguity and removes the need for any wcwidth assertion.
- Pagination resets `last_search_address` to None; the search handler treats `None + paginated` as "start from first visible address" rather than "start from 0," yielding the intuitive "Find from where I'm looking now" behavior.
- `#mac_hex_pane { width: 82 }` is chosen to fit the full hex row including the new 2-cell goto marker padding (`2 + 10 + 47 + 2 + 16 + 1 + 4 ≈ 82`). Earlier 78-col arithmetic in Phase-1 iteration #1 undercounted the marker; corrected in iteration #2.
- LLR-001.1, LLR-001.2, LLR-001.3, LLR-001.4, LLR-003.1, LLR-003.2, LLR-003.5, LLR-003.6 are classified as `test (integration)` rather than `test (unit)` because `_handle_goto*` and `_handle_search*` read state via `self.query_one(...).value` from the live widget tree, so they require `App.run_test()` integration to exercise — not direct method calls against `SimpleNamespace` shims.
- `_first_visible_hex_address(view)` uses a cache approach for the alt and MAC views (renderer sets the cached first-row-base on the app instance) rather than recomputing from focus address + `FOCUS_CONTEXT_ROWS`, to avoid coupling search-resume logic to renderer state.
- Tab/view switch does NOT clear `_<view>_goto_focus_address`; focus address persists per view. Documented in LLR-003.6 so the implementer does not have to guess.

### 6.3 Open risks
- Marker forwarded into MAC hex pane is rendered via a Static widget with `markup=False` (`app.py:1493`); the LLR-003.3 acceptance criterion preserves both safeguards (no `style=` on the appended cells, plus `markup=False` on the host widget). Non-blocking design-risk note recorded from the Phase-2 security review (F-S-01).
