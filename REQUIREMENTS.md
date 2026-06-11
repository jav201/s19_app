# Application Requirements

This document captures functional requirements for reading, parsing, and
validating S19, Intel HEX, A2L, MAC, and TUI behavior, plus the v2 JSON
change/check system, multi-variant projects, and project reporting. (CDFX
read/write support was retired in batch `2026-06-10-batch-07`; sections 8–9
are retained as historical record.)

It is organized by **functional subsystem** so that every requirement for a
given system function lives together and is easy to find. (Earlier revisions
grouped some requirements by the batch that introduced them; that batch grouping
has been replaced by the functional grouping below. The per-requirement
traceability — IDs, `Code:`, `Validation:`, `Status:` — is unchanged.)

Each numbered requirement is mapped to the implementing code and its current
validation state:

- `Automated`: covered by one or more `pytest` tests in `tests/`
- `Partial`: some behavior is automated, but UI integration or wording still
  requires manual confirmation
- `Manual`: no stable automated check is currently in place

Functional subsystems:

1. S19 / HEX File Reading & Parsing
2. A2L Subsystem (parsing · decode · viewer)
3. Validation Engine (cross-artifact severity & issues policy)
4. Hex Viewer
5. MAC View
6. TUI Shell · Layout · Navigation (Direction B)
7. Workspace & File I/O
8. CDFX / Patch Editor *(historical — superseded in batch `2026-06-10-batch-07`)*
9. Memory-value Editing & Unified Change-set *(historical — superseded/evolved in batch `2026-06-10-batch-07`)*
10. Hex-first Change & Check System (v2 Patch Editor)
11. Multi-variant Projects & Execution
12. Project Report
13. Project / Documentation meta

---

# 1. S19 / HEX File Reading & Parsing

## Reading

**R-READ-001**: The loader must read an S19 file line-by-line and ignore
empty lines.

- Code: `s19_app/core.py` (`S19File._load`)
- Validation: `Automated` via `tests/test_core_srecord_validation.py`
  (`test_s19file_collects_errors`)

## Parsing

**R-PARSE-001**: Each non-empty line must start with `S` and include a
supported record type.

- Code: `s19_app/core.py` (`SRecord.__init__`)
- Validation: `Automated` via `tests/test_core_srecord_validation.py`
  (`test_srecord_unsupported_type_raises`, `test_s19file_collects_errors`)

**R-PARSE-002**: The byte count must be valid hex and the line length must
match the declared byte count.

- Code: `s19_app/core.py` (`SRecord.__init__`)
- Validation: `Automated` via `tests/test_core_srecord_validation.py`
  (`test_srecord_invalid_byte_count_hex_raises`,
  `test_srecord_length_mismatch_raises`)

**R-PARSE-003**: The address field must be valid hex and fit the address
length for the record type.

- Code: `s19_app/core.py` (`SRecord.__init__`)
- Validation: `Automated` via `tests/test_core_srecord_validation.py`
  (`test_srecord_valid_line`, `test_srecord_invalid_address_hex_raises`)

**R-PARSE-004**: The data field length must match the byte count and all
data bytes must be valid hex.

- Code: `s19_app/core.py` (`SRecord.__init__`)
- Validation: `Automated` via `tests/test_core_srecord_validation.py`
  (`test_srecord_invalid_data_hex_raises`)

**R-PARSE-005**: The checksum field must be valid hex.

- Code: `s19_app/core.py` (`SRecord.__init__`)
- Validation: `Automated` via `tests/test_core_srecord_validation.py`
  (`test_srecord_invalid_checksum_hex_raises`)

## S-Record Validation

**R-VAL-001**: The parsed record must validate byte count and checksum
according to the S-record specification.

- Code: `s19_app/core.py` (`SRecord._validate`, `SRecord._calculate_checksum`)
- Validation: `Automated` via `tests/test_core_srecord_validation.py`
  (`test_srecord_valid_line`, `test_srecord_checksum_mismatch_invalid`)

**R-VAL-002**: The loader must record validation failures with line numbers
and error details without aborting the load.

- Code: `s19_app/core.py` (`S19File._load`)
- Validation: `Automated` via `tests/test_core_srecord_validation.py`
  (`test_s19file_collects_errors`)

## Intel HEX Parsing

**R-HEX-001**: The Intel HEX loader must handle extended linear address
records (`:04`) to compose full 32-bit addresses for data records.

- Code: `s19_app/hexfile.py` (`IntelHexFile._load`)
- Validation: `Automated` via `tests/test_hexfile.py`
  (`test_hex_extended_linear_address`)

**R-HEX-002**: The Intel HEX loader must handle extended segment address
records (`:02`) to compose addresses for segmented data records.

- Code: `s19_app/hexfile.py` (`IntelHexFile._load`)
- Validation: `Automated` via `tests/test_hexfile.py`
  (`test_hex_extended_segment_address`)

**R-HEX-003**: Start address records (`:03`, `:05`) must be accepted and
ignored without raising parsing errors.

- Code: `s19_app/hexfile.py` (`IntelHexFile._load`)
- Validation: `Automated` via `tests/test_hexfile.py`
  (`test_hex_start_address_records_are_ignored`)

---

# 2. A2L Subsystem (parsing · decode · viewer)

## A2L Structural Parsing

The application shall parse and retain the following A2L structures for decode and display workflows:

- `CHARACTERISTIC`
- `COMPU_METHOD`
- `RECORD_LAYOUT`
- `BYTE_ORDER`
- `COMPU_TAB` / `COMPU_VTAB`
- `AXIS_DESCR`

The parser shall expose indexed maps in the A2L payload:

- `record_layouts_by_name`
- `compu_methods_by_name`
- `compu_tabs_by_name`

Each parsed tag shall preserve backward-compatible fields and may include additional normalized fields:

- `record_layout_name`
- `compu_method_name`
- `effective_byte_order`
- `axis_meta`

## RECORD_LAYOUT Interpretation

The application shall resolve a record layout into decode metadata:

- `decode_type` (canonical scalar type)
- `element_count`
- `byte_size`
- `decode_endian`

Byte-order resolution shall follow this precedence:

1. Tag-level explicit byte order
2. Layout-level byte order
3. Existing tag endian fallback
4. Default little-endian fallback

## Raw Memory Extraction

Given tag address and resolved byte size, the application shall:

- locate bytes in S19/HEX memory map
- extract `N` bytes when available
- report missing bytes/ranges
- retain overlap/conflict marker fields for diagnostics

Per-tag extraction fields:

- `raw_bytes`
- `raw_available`
- `missing_ranges`
- `overlap_conflict`

## Raw Value Decoding

The application shall decode extracted bytes into raw values with endianness support:

- unsigned integer decode
- signed integer decode (two's complement)
- IEEE754 float decode (`FLOAT32_IEEE`, `FLOAT64_IEEE`)
- array decode for multi-element layouts

Decode results shall provide:

- `raw_value`
- `decode_error` (empty when decode succeeds)

## COMPU_METHOD Execution

The application shall support the following conversion behaviors:

| Method | Required behavior |
| --- | --- |
| `IDENTICAL` | return raw value |
| `LINEAR` | apply `a*x + b` |
| `RAT_FUNC` | apply rational polynomial from coefficients |
| `TAB_NOINTP` | table lookup without interpolation |
| `TAB_INTP` | table lookup with interpolation |
| `FORM` | explicit guarded/unsupported status unless safe evaluation is enabled |

Conversion results shall provide:

- `physical_value`
- `conversion_status`
- `conversion_error`

## A2L Decode Validation Requirements

Validation output shall detect and expose at least:

- layout missing
- compu method missing
- byte order unresolved/missing
- size mismatch
- value outside configured limits

Validation enhancements shall remain additive and preserve existing compatibility fields:

- `schema_ok`
- `memory_checked`
- `in_memory`

## A2L Viewer Requirements

The A2L viewer shall:

- enrich tag rows with decoded payload before rendering
- display `Raw` and `Physical` columns
- support find/filter matching for raw and physical values
- display unavailable or invalid values with stable fallback text (`n/a`, `ERR`, `MISS`, or equivalent)

Unit display precedence for A2L tags:

1. Use the explicit `UNIT` keyword on the tag when present.
2. Otherwise use the physical unit string from the referenced `COMPU_METHOD` conversion body line (for example `LINEAR "%.3" "kOhm"`).

## A2L Output API Requirements

The decode/validation layer shall expose deterministic accessor APIs:

- `get_raw_value(name)`
- `get_physical_value(name)`
- `validate_characteristic(name)`

Each API response shall include both value payload and status/error metadata.

## A2L Load / Parse / Tags View

**R-A2L-001**: The tool must parse A2L files into a minimal JSON-friendly
structure capturing sections and parse errors.

- Code: `s19_app/tui/a2l.py` (`parse_a2l_file`)
- Validation: `Automated` via `tests/test_tui_helpers.py`
  (`test_parse_a2l_file_captures_sections`,
  `test_parse_a2l_file_reports_unclosed_section`) and
  `tests/test_tui_a2l.py` (`test_parse_a2l_file_reports_missing_file`)

**R-A2L-002**: The A2L view tile must display parsed A2L content in a readable
summary, show parse errors if present, and indicate tag validation status.

- Code: `s19_app/tui/a2l.py` (`render_a2l_view`, `validate_a2l_tags`),
  `s19_app/tui/app.py` (`update_a2l_view`)
- Validation: `Partial` via `tests/test_tui_helpers.py`
  (`test_render_a2l_view_shows_sections`,
  `test_render_a2l_view_shows_errors`,
  `test_validate_a2l_tags_matches_memory`) and
  `tests/test_tui_a2l.py` (`test_render_a2l_view_shows_tag_validation_status`);
  still verify the live tile integration manually

**R-A2L-003**: The tool must allow exporting parsed A2L data to JSON via a
keyboard binding.

- Code: `s19_app/tui/app.py` (`action_dump_a2l_json`)
- Validation: `Manual` (trigger the export action in the TUI)

**R-A2L-004**: The tool must allow loading an A2L file and show its parsed
content in the A2L view.

- Code: `s19_app/tui/screens.py` (`LoadFileScreen`),
  `s19_app/tui/app.py` (`_load_path_from_user_input`, `load_a2l_from_path`,
  `update_a2l_view`)
- Validation: `Manual` (load a `.a2l` file in the TUI)

**R-A2L-005**: The tool must extract tag address/length metadata for
MEASUREMENT and CHARACTERISTIC sections.

- Code: `s19_app/tui/a2l.py` (`extract_a2l_tags`)
- Validation: `Automated` via `tests/test_tui_a2l.py`
  (`test_parse_a2l_file_extracts_nested_measurement_and_characteristic_tags`,
  `test_extract_a2l_tags_ignores_unrelated_sections`)

**R-A2L-006**: The UI must display A2L tags with columns for name, address,
length, source type (assigned/formula), memory presence, limits, units, bit
organization, endianness, virtual flag, function group, and access.

- Code: `s19_app/tui/app.py` (`update_a2l_tags_view`)
- Validation: `Partial` via `tests/test_tui_helpers.py`
  (`test_a2l_tag_filters_by_mode_and_field`) and `tests/test_tui_a2l.py`
  (`test_parse_a2l_file_extracts_nested_measurement_and_characteristic_tags`);
  still verify the rendered column layout manually

**R-A2L-007**: The A2L Tags tile must support filtering by field and
filter modes (All/Invalid/In-Memory).

- Code: `s19_app/tui/app.py` (`_filter_a2l_tags`, `_set_a2l_filter_field`,
  `_toggle_a2l_filter_menu`)
- Validation: `Automated` via `tests/test_tui_helpers.py`
  (`test_a2l_tag_filters_by_mode_and_field`) and
  `tests/test_tui_app.py`
  (`test_filter_a2l_tags_supports_in_memory_and_boolean_fields`)

## A2L / MAC Table Paging

**R-TUI-019**: The A2L and MAC viewers must expose page navigation buttons
without removing existing keyboard paging shortcuts.

- Code: `s19_app/tui/app.py` (`compose`, button handlers, paging actions)
- Validation: `Automated` via `tests/test_tui_app.py`

**R-TUI-020**: Context paging (`+` / `-`) must continue to route to A2L/MAC
table paging while explicit page buttons trigger the same underlying actions.

- Code: `s19_app/tui/app.py` (`action_page_next_context`, `action_page_prev_context`,
  `action_a2l_tags_page_next`, `action_a2l_tags_page_prev`,
  `action_mac_records_page_next`, `action_mac_records_page_prev`)
- Validation: `Automated` via `tests/test_tui_app.py`

---

# 3. Validation Engine (cross-artifact severity & issues policy)

### A2L Tag/Parameter Validation Criteria

A2L row severity/color semantics shall follow:

- `Red`: structural/schema failure for the declared object type, malformed required field, invalid required reference, and duplicate symbol when configured as a hard error.
- `Green`: memory checked and tag/range fully found in the loaded S19/HEX image.
- `White`: valid A2L record with no hard inconsistency, including valid records not found in image and records whose value is not expected to come directly from image bytes.
- `Grey`: memory not checked yet or no primary S19/HEX context loaded.

Notes:

- Absence from S19/HEX does not invalidate an A2L record.
- Schema validity must be judged by A2L object type, not by image presence.

### MAC Tag/Parameter Validation Criteria

MAC row severity/color semantics shall follow:

- `Red`: MAC parse failed, invalid/missing name, invalid/missing hexadecimal address, and same-name A2L↔MAC address mismatch.
- `Orange`: symbol exists in MAC but not in A2L, duplicate-address alias when alias policy is warning, and overlap ambiguity findings.
- `Green`: exact name+address match with A2L (with optional future promotion for image-backed value-resolvable states).
- `White`: structurally valid MAC entry with no hard inconsistency but not positively cross-confirmed.
- `Grey`: no A2L loaded or validation context missing.

Notes:

- Address absence from S19/HEX is not a MAC-invalid condition.
- Out-of-image facts may still appear as warning/info in Issues.

### Issues Tile Severity Policy

The Issues panel shall classify at least the following:

- `Errors`: MAC parse error, empty name, invalid/missing address, duplicate MAC symbol name, A2L parser/structure errors, invalid A2L address field type, duplicate A2L symbol, broken GROUP/FUNCTION references, and A2L↔MAC same-name address mismatch.
- `Warnings`: MAC address out of S19 range, A2L range out of S19 range, overlap ambiguity, symbol-only-in-MAC, symbol-only-in-A2L, and duplicate-address alias when policy emits warning.
- `Optional info`: valid-but-not-image-backed, not-checked-without-primary-image, and virtual/dependent/non-memory-backed object notes.

---

# 4. Hex Viewer

**R-TUI-004**: The hex view must display decoded bytes from the selected
file in a readable hex+ASCII layout.

- Code: `s19_app/tui/hexview.py` (`render_hex_view`, `render_hex_view_text`)
- Validation: `Automated` via `tests/test_tui_helpers.py`
  (`test_render_hex_view_includes_focus_context`,
  `test_render_hex_view_truncates_output`) and
  `tests/test_tui_hexview.py` (`test_render_hex_view_text_highlights_match_range`)

**R-TUI-007**: The hex view should provide context around a focused address
and truncate large outputs safely.

- Code: `s19_app/tui/hexview.py` (`render_hex_view`, `_collect_hex_rows`)
- Validation: `Automated` via `tests/test_tui_helpers.py`
  (`test_render_hex_view_includes_focus_context`,
  `test_render_hex_view_truncates_output`) and
  `tests/test_tui_hexview.py` (`test_collect_hex_rows_reports_missing_focus_address`)

**R-TUI-009**: Selecting a data section should jump the hex view to the
section start address.

- Code: `s19_app/tui/app.py` (`_jump_to_section`, `update_hex_view`)
- Validation: `Manual` (select a section in the running TUI)

**R-TUI-010**: The hex view must be scrollable and occupy the full right
column height.

- Code: `s19_app/tui/app.py` (`S19TuiApp.CSS`, `S19TuiApp.compose`)
- Validation: `Manual` (scroll and resize the running TUI)

**R-TUI-017**: The hex view must support case-insensitive ASCII search
(with find-next behavior), highlight matches, and go to a specific address.

- Code: `s19_app/tui/hexview.py` (`find_string_in_mem`, `render_hex_view_text`),
  `s19_app/tui/app.py` (`_handle_search`, `_handle_goto`)
- Validation: `Partial` via `tests/test_tui_helpers.py`
  (`test_find_string_in_mem_finds_address`,
  `test_find_string_in_mem_returns_none_when_missing`,
  `test_find_string_in_mem_supports_next_search`) and
  `tests/test_tui_hexview.py` (`test_render_hex_view_text_highlights_match_range`);
  still verify the interactive goto flow manually

**R-TUI-018**: Clicking an A2L tag row or MAC row must focus the corresponding
hex panel with the target address/range visible near the top of the viewport,
reset the panel scroll position to top, and update status text.

- Code: `s19_app/tui/app.py` (`_jump_to_tag_by_data`, `_jump_to_mac_address`,
  `update_alt_hex_view`, `update_mac_hex_view`), `s19_app/tui/hexview.py`
  (`_collect_hex_rows`, `render_hex_view_text`)
- Validation: `Automated` via `tests/test_tui_app.py` (selection jump behavior)

**R-TUI-038**: Hex-text search resumes from the first address visible on the current page after the viewer window has been paginated (main view) or re-rendered following a tag/record selection (alt / MAC views), rather than from the stale prior hit.

- Code: `s19_app/tui/app.py` (`_first_visible_hex_address`, `action_hex_page_next`/`action_hex_page_prev`, `_jump_to_tag_by_data`, `_handle_a2l_tag_find_next`, `_jump_to_mac_address`, `_handle_search`/`_handle_search_alt`/`_handle_search_mac`)
- Validation: `Automated` via `tests/test_tui_search_pagination.py` (TC-001/002/002b/002c/003/003b)
- Status: Added in batch `2026-05-26-batch-05` (US-01 / HLR-001 / LLR-001.1–001.4)

**R-TUI-040**: The goto-address handler reports a status message when the typed address is not contained in any loaded range, and on a valid address marks the focus row with a plain-text `> ` glyph (no Rich style, no CSS class) that does not collide with the `sev-*` validation severity classes or the byte-level search / MAC highlights; the marker is forwarded through `render_hex_view_text` and cleared on the view-mutating triggers.

- Code: `s19_app/tui/hexview.py` (`render_hex_view_text` `focus_row_marker_address`), `s19_app/tui/app.py` (`_apply_goto`, `_goto_focus_address`/`_alt_goto_focus_address`/`_mac_goto_focus_address`, the three `update_*_hex_view` renderers)
- Validation: `Automated` via `tests/test_tui_goto_marker.py` (TC-007/008/009a/009b/010/011/012)
- Status: Added in batch `2026-05-26-batch-05` (US-03 / HLR-003 / LLR-003.1–003.6)

---

# 5. MAC View

**R-TUI-039**: The MAC tab lays out the records table and the hex pane as a single-regime proportional split with a floor, at every terminal width: the records pane occupies 4fr and the hex pane 3fr of the MAC panes content width, with the hex pane clamped to a minimum of 82 columns so a full hex row (address + 16 hex bytes + ASCII gutter) always renders; the hex pane's inner scroll container fills the available vertical space. Effective hex width = `max(82, round(3/7 · body_width))`. There are no `width-narrow` MAC pane rules — this supersedes the batch-05 fixed model (`#mac_hex_pane width: 82` at ≥120 columns plus a `width-narrow` 35% proportional regime below 120 columns), bringing the MAC View to parity with the A2L Explorer split of `R-TUI-037` (batch `2026-06-09-batch-06`).

- Code: `s19_app/tui/styles.tcss` (`#mac_records_pane { width: 4fr }`, `#mac_hex_pane { width: 3fr; min-width: 82 }`, `#mac_hex_scroll { height: 100%; overflow: auto }`)
- Validation: `Automated` via `tests/test_tui_mac_layout.py` (`test_mac_hex_pane_proportional_at_wide_terminal`, `test_mac_records_pane_proportional_at_wide_terminal`, `test_mac_hex_pane_floor_at_120`, `test_mac_hex_floor_holds_across_retired_breakpoint`, `test_mac_hex_pane_width_at_wide_terminal`, `test_mac_records_pane_positive_width_at_wide_terminal`, `test_mac_hex_scroll_fills_pane_height`) and `tests/test_tui_directionb.py` (`test_tc021_mac_two_panes_fixed_regime` re-banded to 80–86, `test_tc021_mac_two_panes_floor_below_minimum`)
- Status: Added in batch `2026-05-26-batch-05` (US-02 / HLR-002 / LLR-002.1–002.4); amended to proportional+floor in batch `2026-06-09-batch-06` (US-001)

---

# 6. TUI Shell · Layout · Navigation (Direction B)

The Direction B "Rail + Command" view-layer restyle (batch
`2026-05-20-batch-02`) re-layouts the `s19tui` TUI to a single-context workspace
navigated by a left activity rail and a top command bar, and adds three new view
scaffolds. It is a view-layer-only batch: the parsing/validation engine is
frozen. Each row traces to the batch HLR/LLR/TC set in
`.dev-flow/2026-05-20-batch-02/01-requirements.md` and the per-test verdicts in
`.dev-flow/2026-05-20-batch-02/04-validation.md`.

**R-TUI-021**: The TUI must present a left activity rail of exactly eight
ordered items (Workspace, A2L Explorer, MAC View, Memory Map, Issues Report,
Patch Editor, A↔B Diff, Bookmarks) bound to keys `1`–`8`, with exactly one item
marked active, swapping the workspace content on rail selection; rail items
render Unicode glyphs with a defined per-item ASCII fallback.

- Code: `s19_app/tui/rail.py` (`Rail`, `RailItem`),
  `s19_app/tui/app.py` (`action_show_screen`, screen routing)
- Validation: `Automated` via `tests/test_tui_directionb.py`
  (`tc001` rail composition, `tc002` single-active item, `tc035` glyph +
  ASCII fallback) — covers LLR-001.1, LLR-001.2, LLR-001.3

**R-TUI-022**: The TUI must present a persistent top command bar exposing a
searchable (type-to-filter) command palette plus a find input and a
go-to-address input, reachable from every Direction B screen.

- Code: `s19_app/tui/command_bar.py` (`CommandBar`),
  `s19_app/tui/app.py` (command-bar wiring)
- Validation: `Automated` via `tests/test_tui_commandbar.py`
  (`tc006` present on every screen, `tc007` palette population, `tc036`
  type-to-filter) — covers LLR-003.1, LLR-003.2, LLR-003.3

**R-TUI-023**: The TUI must support a `Ctrl+D` density toggle (compact /
comfortable, default Comfortable) that does not break any screen layout at the
supported terminal sizes (80×24, 120×30, 160×40), observing a two-regime width
layout — fixed pane widths at terminal width `>= 120` columns and proportional
pane widths at terminal width `< 120` columns — for the Workspace screen. The
A2L Explorer hex/tags panes are the exception: they use a flat 3/7 hex : 4/7
tags proportional ratio at all terminal widths (see `R-TUI-037`). Since batch
`2026-06-09-batch-06` the MAC View panes follow the same single-regime
proportional+floor model (see `R-TUI-039`) and are no longer two-regime.

- Code: `s19_app/tui/styles.tcss` (density classes, two-regime layout rules),
  `s19_app/tui/app.py` (`action_cycle_density`)
- Validation: `Automated` via `tests/test_tui_directionb.py`
  (`tc014` density cycle, `tc015` Comfortable default) and
  `tests/test_tui_snapshot.py` (`tc016-S`, 27-baseline snapshot matrix);
  `tc016` inspection checklist + CV-04 boundary tests corroborate — covers
  LLR-006.1, LLR-006.2, LLR-007.1

**R-TUI-024**: The TUI must apply a dark-only "Calm Dark" theme using exactly
one accent hue plus the five severity colors defined by
`color_policy.SEVERITY_CLASS_MAP` (`sev-error`, `sev-warning`, `sev-info`,
`sev-ok`, `sev-neutral`), preserving `MAC_ADDRESS_OVERLAY_STYLE` and
`FOCUS_HIGHLIGHT_STYLE` unchanged, with no light-theme variant.

- Code: `s19_app/tui/styles.tcss` (`$accent-calm`, `sev-*` rules)
- Validation: `Automated` via `tests/test_tui_theme.py`
  (TC-012 token-budget inspection backed by 16 cases, TC-013 severity
  round-trip + per-`sev-*` rule) — covers LLR-005.1, LLR-005.2

**R-TUI-025**: The validation issues table must be presented as a dedicated
rail screen (no longer nested inside the Workspace Status tile), preserving
severity coloring, the All/Errors/Warnings filters, paging, and row-level
jump-to-source.

- Code: `s19_app/tui/app.py` (`#screen_issues`, `update_validation_issues_view`)
- Validation: `Automated` via `tests/test_tui_directionb.py`
  (`tc023` dedicated screen, `tc024` behavior preserved) — covers LLR-011.1,
  LLR-011.2

**R-TUI-026**: The TUI must present a Memory Map screen rendering firmware
coverage (ranges, gaps, validity) from the existing `LoadedFile.ranges` and
`range_validity` data, without computing new coverage data.

- Code: `s19_app/tui/screens_directionb.py` (Memory Map scaffold),
  `s19_app/tui/app.py` (`#screen_map` wiring)
- Validation: `Automated` via `tests/test_tui_directionb.py`
  (`tc025`) — covers LLR-012.1

**R-TUI-028**: The TUI must present an A↔B Firmware Diff view shell — a static
three-column layout (range list, hex A, hex B) populated with constant,
clearly-labelled placeholder hex rows — with no second-file load path and no
diff computation this batch. Diff logic is deferred to a follow-up batch.

- Code: `s19_app/tui/screens_directionb.py` (A↔B Diff scaffold)
- Validation: `Automated` via `tests/test_tui_directionb.py`
  (`tc027` three-column placeholder, `tc028` deferred-logic guard) — covers
  LLR-012.3, LLR-012.4

**R-TUI-029**: The TUI must present the data ranges/sections, the hex view, and
a context pane as a three-pane Direction B Workspace screen populated from the
existing `LoadedFile` snapshot. This **supersedes `R-TUI-003`** (the pre-batch
five-tile Main view).

- Code: `s19_app/tui/app.py` (`#screen_workspace`, `compose`),
  `s19_app/tui/styles.tcss` (Workspace two-regime layout)
- Validation: `Automated` via `tests/test_tui_directionb.py`
  (`tc017` three named panes + two-regime widths, `tc018` data wiring + hex
  caps unchanged) — covers LLR-008.1, LLR-008.2

**R-TUI-030**: When a rail screen is activated with no file loaded, the TUI
must show a neutral empty-state panel prompting a load action instead of an
error or a blank pane.

- Code: `s19_app/tui/app.py` (empty-state panels), `s19_app/tui/screens_directionb.py`
- Validation: `Automated` via `tests/test_tui_directionb.py`
  (`tc037`, all 8 rail screens) — covers LLR-002.3

**R-TUI-031**: While a command-bar input (find, go-to-address, or palette) holds
keyboard focus, every unmodified single-key binding (`g`, the digits `1`–`8`,
and the paging keys `+`, `-`, `,`, `.`) must be routed into the input as text
rather than firing its binding action; modified-key bindings (`Ctrl+K`,
`Ctrl+D`) stay active.

- Code: `s19_app/tui/app.py` (binding/focus handling),
  `s19_app/tui/command_bar.py`
- Validation: `Automated` via `tests/test_tui_commandbar.py` and
  `tests/test_tui_directionb.py` (`tc008`, `tc009`, `tc029` input-focus
  sub-cases) — covers LLR-004.5

**R-TUI-032**: `pytest-textual-snapshot` is declared as a dev-only optional
dependency under `[project.optional-dependencies]` in `pyproject.toml` only
(the legacy `project.toml` is not edited and kept aligned), carrying a version
constraint; `textual` gains a `>=` version floor. This is a dev/test-tooling
note, not a runtime requirement — the runtime dependency set (`rich`,
`textual`) is unchanged.

- Code: `pyproject.toml` (`[project.optional-dependencies]`)
- Validation: `Automated` via `tests/test_tui_directionb.py` (`tc028` — no new
  runtime dependency) — recorded for traceability against constraints C-2 / C-8

**R-TUI-033**: The command-bar find and go-to inputs must route submitted text
to the existing `find_string_in_mem` and `_handle_goto` handlers respectively,
introducing no new string-decoding or address-parsing code; invalid input is
reported via the existing `set_status` path.

- Code: `s19_app/tui/command_bar.py`, `s19_app/tui/app.py`
  (`_handle_search`, `_handle_goto` wiring)
- Validation: `Automated` via `tests/test_tui_commandbar.py`
  (`tc008` find-routing + AST guard, `tc009` go-to routing + AST guard) —
  covers LLR-004.2, LLR-004.6 (security finding S-1)

**R-TUI-034**: `pytest-textual-snapshot` SVG baselines must be rendered only
against the public synthetic fixtures (`examples/case_00_public/` and the
`tests/conftest.py` generators) and never against client firmware, A2L or MAC
artifacts.

- Code: `tests/test_tui_snapshot.py` (snapshot test setup)
- Validation: `Automated` via `tests/test_tui_snapshot.py` (`tc016-S`
  fixture-setup check) and the TC-031 no-leak inspection (0 client tokens in
  any of the 27 `.svg`) — covers LLR-007.2 (security finding S-2)

**R-TUI-035**: The command bar must not write user-typed find / go-to / palette
text or rendered file content to the `.s19tool/logs/` rotating log beyond the
existing `set_status` behavior; log verbosity must not exceed the pre-batch
baseline.

- Code: `s19_app/tui/command_bar.py`, `s19_app/tui/app.py`
- Validation: `Automated` via `tests/test_tui_commandbar.py` (`tc039` —
  AST inspection + driven-session log assertion, 2 cases) — covers LLR-013.3
  (security finding S-3)

**R-TUI-036**: When the validation issues table is promoted to its own rail
screen, the project-name and A2L-filename status content (see `R-TUI-016`) must
render in the persistent command bar so it stays visible from every Direction B
screen. `R-TUI-016` is not regressed by the move.

- Code: `s19_app/tui/command_bar.py` (project/A2L labels),
  `s19_app/tui/app.py` (`update_project_labels` wiring)
- Validation: `Automated` via `tests/test_tui_commandbar.py` (`tc038`) — covers
  LLR-011.3

**R-TUI-037**: The A2L Explorer screen must lay out the A2L symbol table and
the hex pane as a flat proportional split at every terminal width — the hex
pane occupying 3/7 (≈42.9%) of the A2L panes content width and the A2L symbol
table the remaining 4/7 (≈57.1%) (`#a2l_hex_pane` 3fr, `#a2l_tags_pane` 4fr).
There is no 120-column regime split for the A2L panes. Amended by batch
`2026-05-20-batch-02` increment 13 (review feedback): the prior iteration-3
two-regime A2L split — a fixed 40-column hex pane at terminal width `>= 120`
columns and a 35% proportional hex pane below 120 columns — was superseded
because the 40-column hex pane was too narrow to render the hex view
correctly. The change was A2L-only at the time; in batch `2026-06-09-batch-06`
the MAC View adopted the same proportional model with an 82-column floor (see
`R-TUI-039`), retiring the MAC two-regime layout.

- Code: `s19_app/tui/styles.tcss` (`#a2l_hex_pane`, `#a2l_tags_pane` widths),
  `s19_app/tui/app.py` (`_compose_screen_a2l`)
- Validation: `Automated` via `tests/test_tui_directionb.py` (`tc019` — hex
  pane 3/7 ±3 points at 80×24 / 120×30 / 160×40) and
  `tests/test_tui_snapshot.py` (`tc016-S`, the 6 regenerated `a2l-*` snapshot
  baselines) — covers LLR-009.1

## History / superseded

**R-TUI-003**: The TUI layout must expose tiles for work area files (top left),
data sections with validity coloring (top middle), a hex view (right, full
height), and reserved empty tiles (bottom left/right).

- Code: `s19_app/tui/app.py` (`S19TuiApp.CSS`, `S19TuiApp.compose`)
- Validation: `Manual` (visual inspection)
- Status: **Superseded** by `R-TUI-029` (batch `2026-05-20-batch-02`,
  Direction B restyle). The pre-batch five-tile Main view is replaced by the
  Direction B three-pane Workspace screen; this row is retained for history.
  The retired `#view_bar` button bar and the `view_main` / `view_alt` /
  `view_mac` actions are likewise superseded by rail items 1 / 2 / 3 (intended
  design change, not a regression).

**R-TUI-027**: The TUI must present a Patch Editor view shell — a before/after
hex-pane layout plus address/value input fields — with the input fields inert
(not wired to any patch-apply, undo or redo logic) and a visible deferral
notice. Patch logic is deferred to a follow-up batch.

- Code: `s19_app/tui/screens_directionb.py` (Patch Editor scaffold)
- Validation: `Automated` via `tests/test_tui_directionb.py`
  (`tc026` view shell + inert inputs) — covers LLR-012.2
- Status: **Superseded** by `R-CDFX-016` (batch `2026-05-21-batch-03`,
  functional Patch Editor). The inert view shell is replaced by a working
  Patch Editor that builds, edits and removes change-list entries and
  saves/loads them as ASAM CDFX `.cdfx` files; the `R-TUI-027` deferral
  notice is removed. This row is retained for history (intended supersession,
  not a regression). `R-CDFX-016` was itself superseded in batch
  `2026-06-10-batch-07` by the consolidated v2 Patch Editor — see
  `R-CHG-004`.

---

# 7. Workspace & File I/O

**R-TUI-001**: The application must create a work area for file operations
at startup if it does not already exist.

- Code: `s19_app/tui/workspace.py` (`ensure_workarea`),
  `s19_app/tui/app.py` (`S19TuiApp.__init__`)
- Validation: `Partial` via `tests/test_tui_workspace.py`
  (`test_ensure_workarea_creates_expected_directories`); still verify startup
  wiring manually during app launch

**R-TUI-002**: Loading a `.s19` or `.hex` file must copy the file into the
work area before parsing.

- Code: `s19_app/tui/workspace.py` (`copy_into_workarea`),
  `s19_app/tui/app.py` (`load_selected_file`)
- Validation: `Partial` via `tests/test_tui_helpers.py`
  (`test_copy_into_workarea_creates_unique_names`); still verify the full load
  action manually

**R-TUI-005**: The loader must resolve relative paths against the app
working directory and the repo root.

- Code: `s19_app/tui/workspace.py` (`resolve_input_path`, `find_repo_root`)
- Validation: `Automated` via `tests/test_tui_helpers.py`
  (`test_resolve_input_path_prefers_base_dir`,
  `test_resolve_input_path_falls_back_to_repo_root`)

**R-TUI-006**: The workarea copy should avoid name collisions by creating
unique filenames when needed.

- Code: `s19_app/tui/workspace.py` (`copy_into_workarea`)
- Validation: `Automated` via `tests/test_tui_helpers.py`
  (`test_copy_into_workarea_creates_unique_names`)

**R-TUI-008**: Users must be able to open the workarea in the OS file
explorer from the TUI.

- Code: `s19_app/tui/app.py` (`action_open_workarea`)
- Validation: `Manual` (trigger the action in the TUI on the target OS)

**R-TUI-011**: Loaded files must be copied into a temporary folder within
the workarea.

- Code: `s19_app/tui/workspace.py` (`WORKAREA_TEMP`, `ensure_workarea`),
  `s19_app/tui/app.py` (`load_from_path`)
- Validation: `Partial` via `tests/test_tui_workspace.py`
  (`test_ensure_workarea_creates_expected_directories`); still verify the
  runtime load flow manually

**R-TUI-012**: Saving a project must copy the loaded file into a
workarea subfolder named by a sanitized project name.

- Code: `s19_app/tui/workspace.py` (`sanitize_project_name`, `copy_into_workarea`),
  `s19_app/tui/app.py` (`action_save_project`, `_handle_save_dialog`)
- Validation: `Partial` via `tests/test_tui_helpers.py`
  (`test_sanitize_project_name_allows_safe_chars`,
  `test_sanitize_project_name_strips_invalid_chars`,
  `test_sanitize_project_name_rejects_empty`); still verify the save flow
  manually

**R-TUI-013**: Loading a project must list all project folders in the
workarea except for the temp folder and load the selected project file.

- Code: `s19_app/tui/app.py` (`LoadProjectScreen`, `list_projects`,
  `action_load_project`, `_handle_load_project`)
- Validation: `Partial` via `tests/test_tui_helpers.py`
  (`test_list_projects_ignores_temp`) and `tests/test_tui_app.py`
  (`test_list_projects_skips_files_and_sorts_names`); still verify loading a
  selected project manually

**R-TUI-014**: Each project must contain at most one S19/HEX data file and
at most one A2L file.

- Code: `s19_app/tui/workspace.py` (`validate_project_files`)
- Validation: `Automated` via `tests/test_tui_helpers.py`
  (`test_validate_project_files_allows_single_data_and_a2l`,
  `test_validate_project_files_rejects_multiple_data`,
  `test_validate_project_files_rejects_multiple_a2l`)

**R-TUI-015**: The TUI must log actions to a rotating log file under
`.s19tool/logs` with a maximum size of 5 MB.

- Code: `s19_app/tui/workspace.py` (`setup_logging`, `ensure_workarea`)
- Validation: `Automated` via `tests/test_tui_helpers.py`
  (`test_setup_logging_creates_log_handler`,
  `test_setup_logging_uses_rotating_file_handler`) and
  `tests/test_tui_workspace.py` (`test_setup_logging_reuses_handler_for_same_path`)

**R-PROJ-001**: Saving a project must persist both the loaded data file
and the loaded A2L file into the project folder when available.

- Code: `s19_app/tui/app.py` (`_handle_save_dialog`)
- Validation: `Manual` (save a project with data and A2L loaded)

**R-PROJ-002**: If a project is active, loading a data or A2L file later
must copy it into the corresponding project folder (respecting limits).

- Code: `s19_app/tui/app.py` (`_sync_loaded_file_to_project`,
  `_sync_loaded_a2l_to_project`, `load_from_path`, `load_a2l_from_path`,
  `_load_path_from_user_input`)
- Validation: `Manual` (save a project, then load replacement files)

**R-TUI-016**: The status tile must display the active project name and
the loaded A2L filename.

- Code: `s19_app/tui/app.py` (`update_project_labels`)
- Validation: `Manual` (load/save a project and then load an A2L file)

---

# 8. CDFX / Patch Editor

> **Historical section.** Batch `2026-06-10-batch-07` (US-002) retired the
> entire cfdx/.cdfx parameter flow — CDFX XML read/write, the
> parameter-by-name change list, and the selective `.cdfx` export — in favor
> of the v2 address-only JSON change system (see §10, `R-CHG-*` /
> `R-CHK-001`). The statements below are unchanged historical record; each
> entry's `Status:` line carries the supersession.

The functional Patch Editor + ASAM CDFX (`.cdfx`) read/write batch
(`2026-05-21-batch-03`) makes the Patch Editor rail screen functional: it lets a
calibration engineer build a parameter change-list, resolve each entry against
the loaded A2L, see values in a type-driven display form, and exchange the
change-list as a structurally valid ASAM CDF 2.0 `.cdfx` file (read + write)
compatible with Vector vCDM.

Unlike the batch-02 view-layer restyle, this batch deliberately adds a
data-processing layer — the `s19_app/tui/cdfx/` package and a
`s19_app/tui/services/cdfx_service.py` service seam — while leaving the
parsing/validation engine frozen (`git diff main` empty across `core.py`,
`hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`). Each
row traces to the batch HLR/LLR/TC set in
`.dev-flow/2026-05-21-batch-03/01-requirements.md` and the per-test verdicts in
`.dev-flow/2026-05-21-batch-03/04-validation.md` (full suite 611 passed /
0 failed / 3 xfailed / 2 skipped; CDFX + Patch subset 192 passed; 8 HLR /
44 LLR / 47 TC all `pass`).

**R-CDFX-001**: The tool must maintain a parameter change-list in which each
entry holds an A2L parameter name, an array index (`None` for a scalar or ASCII
string parameter, a non-negative integer for an array element), and a physical
value, and must support adding, editing and removing entries with
`(parameter_name, array_index)` as the entry identity and a deterministic
entry order.

- Code: `s19_app/tui/cdfx/changelist.py` (`ChangeListEntry`, `ChangeList`,
  `ResolutionStatus`)
- Validation: `Automated` via `tests/test_cdfx_changelist.py` (TC-001 entry
  construction, TC-002 add/edit/remove + identity de-duplication, TC-003
  deterministic ordering) — covers LLR-001.1, LLR-001.2, LLR-001.3, LLR-001.4
- Status: Superseded in batch `2026-06-10-batch-07` (US-002 — cfdx/.cdfx flow retired in favor of the v2 address-only JSON change system; see R-CHG-*). Statement retained as historical record.

**R-CDFX-002**: The tool must resolve each change-list entry against the loaded
A2L through the enriched A2L pipeline (`parse_a2l_file` →
`enrich_a2l_tags_with_values`, not bare `extract_a2l_tags`), returning the
parameter's data type, element count and category, and must mark an entry
`unresolved`, `index-out-of-range` or `unresolved-no-a2l` without raising an
exception when the name, index or A2L is absent.

- Code: `s19_app/tui/cdfx/resolve.py` (`resolve_against_a2l`), reusing
  `s19_app/tui/a2l.py` (`enrich_a2l_tags_with_values`, `DATATYPE_SIZES`)
- Validation: `Automated` via `tests/test_cdfx_resolve.py` (TC-004 resolve a
  known parameter, TC-005 unresolved-name, TC-006 array-index range check,
  TC-007 resolution without an A2L) — covers LLR-002.1, LLR-002.2, LLR-002.3,
  LLR-002.4
- Status: Superseded in batch `2026-06-10-batch-07` (US-002 — cfdx/.cdfx flow retired in favor of the v2 address-only JSON change system; see R-CHG-*). Statement retained as historical record.

**R-CDFX-003**: The tool must display a change-list entry's value in the form
determined by the resolved A2L data type — decimal for unsigned integers (with
a hexadecimal companion only when the physical value is integral), signed
decimal for signed integers, fractional decimal for IEEE floats, a quoted
string for `ASCII`-`char_type` parameters — and must render an unresolved
entry's value as plain decimal text without error.

- Code: `s19_app/tui/cdfx/display.py` (`format_value`)
- Validation: `Automated` via `tests/test_cdfx_display.py` (TC-008 type-driven
  display-format selection, TC-009 unresolved-entry fallback) — covers
  LLR-003.1, LLR-003.2
- Status: Superseded in batch `2026-06-10-batch-07` (US-002 — cfdx/.cdfx flow retired in favor of the v2 address-only JSON change system; see R-CHG-*). Statement retained as historical record.

**R-CDFX-004**: The change-list must store the entered value as the parameter's
physical value; the hexadecimal / ASCII rendering must be derived for display
only and must not alter the stored value.

- Code: `s19_app/tui/cdfx/changelist.py` (`ChangeListEntry.value`),
  `s19_app/tui/cdfx/display.py`
- Validation: `Automated` via `tests/test_cdfx_display.py` and
  `tests/test_cdfx_changelist.py` (TC-010 physical value stored, display
  derived) — covers LLR-003.3
- Status: Superseded in batch `2026-06-10-batch-07` (US-002 — cfdx/.cdfx flow retired in favor of the v2 address-only JSON change system; see R-CHG-*). Statement retained as historical record.

**R-CDFX-005**: The CDFX writer must emit a structurally valid CDF 2.0 `.cdfx`
file — an `MSRSW` root with a `SHORT-NAME`, a `CATEGORY` of `CDF20`, and the
`SW-SYSTEMS/SW-SYSTEM/SW-INSTANCE-SPEC/SW-INSTANCE-TREE` backbone, each
container carrying a `SHORT-NAME` — using the Python standard library
`xml.etree.ElementTree` only, with no new runtime dependency.

- Code: `s19_app/tui/cdfx/writer.py` (`write_cdfx`, `_build_backbone`)
- Validation: `Automated` via `tests/test_cdfx_writer.py` (TC-011 CDF 2.0
  backbone, TC-014 well-formed UTF-8 XML) — covers LLR-004.1, LLR-004.4
- Status: Superseded in batch `2026-06-10-batch-07` (US-002 — cfdx/.cdfx flow retired in favor of the v2 address-only JSON change system; see R-CHG-*). Statement retained as historical record.

**R-CDFX-006**: The CDFX writer must emit exactly one `SW-INSTANCE` per distinct
resolved `parameter_name` — a scalar/string parameter from its single entry, a
1-D array parameter by coalescing its array-element entries into one `VAL_BLK`
`SW-INSTANCE` whose `SW-VALUE-CONT/SW-VALUES-PHYS` carries one `VG` of ascending
positional `V` — encoding a scalar as a bare `V`, an ASCII string as a `VT`, and
never emitting a `SW-ARRAY-INDEX` element.

- Code: `s19_app/tui/cdfx/writer.py` (`_group_writable_entries`, `_append_group`,
  `_append_scalar_instance`, `_append_array_instance`)
- Validation: `Automated` via `tests/test_cdfx_writer.py` (TC-012 one
  `SW-INSTANCE` per resolved parameter, TC-013 scalar/array/string value
  encoding) — covers LLR-004.2, LLR-004.3
- Status: Superseded in batch `2026-06-10-batch-07` (US-002 — cfdx/.cdfx flow retired in favor of the v2 address-only JSON change system; see R-CHG-*). Statement retained as historical record.

**R-CDFX-007**: The CDFX writer must reject a sparse or non-zero-based 1-D array
group — whose integer indices are not the contiguous gapless zero-based
sequence `0…N-1` — by excluding the whole `parameter_name` group from the output
and emitting exactly one warning-level `ValidationIssue` with code
`W-ARRAY-SPARSE`, and must never gap-fill, default, interpolate or synthesize a
value for a missing index.

- Code: `s19_app/tui/cdfx/writer.py` (`_is_contiguous_zero_based`,
  `_sparse_array_issue`)
- Validation: `Automated` via `tests/test_cdfx_writer.py` and
  `tests/test_cdfx_w_rules.py` (TC-038 writer coalescing + sparse-array
  rejection) — covers LLR-004.9
- Status: Superseded in batch `2026-06-10-batch-07` (US-002 — cfdx/.cdfx flow retired in favor of the v2 address-only JSON change system; see R-CHG-*). Statement retained as historical record.

**R-CDFX-008**: When a write request contains unresolved / index-out-of-range
entries or has zero writable entries, the CDFX writer must exclude those entries
(one warning `W-INSTANCE-EXCLUDED` per excluded entry), still emit a valid
backbone-only `.cdfx`, and emit exactly one warning `W-EMPTY-CHANGELIST` when no
writable entry remains.

- Code: `s19_app/tui/cdfx/writer.py` (`_exclusion_issue`,
  `_empty_changelist_issue`)
- Validation: `Automated` via `tests/test_cdfx_w_rules.py` and
  `tests/test_cdfx_writer.py` (TC-019d unresolved-exclusion, TC-019h empty +
  all-unresolved) — covers LLR-004.5, LLR-004.6
- Status: Superseded in batch `2026-06-10-batch-07` (US-002 — cfdx/.cdfx flow retired in favor of the v2 address-only JSON change system; see R-CHG-*). Statement retained as historical record.

**R-CDFX-009**: The CDFX writer must emit a leading `Created with s19_app CDF
2.0 Writer` tool-identification XML comment, and must emit IEEE float `V` values
in a round-trip-safe full-precision (`repr()`-equivalent) textual
representation so a write→read cycle is exact with no float tolerance required.

- Code: `s19_app/tui/cdfx/writer.py` (`_serialize`, `_value_text`)
- Validation: `Automated` via `tests/test_cdfx_writer.py` and
  `tests/test_cdfx_roundtrip.py` (TC-032 tool-identification note, TC-033
  round-trip-safe float values, TC-024 round-trip) — covers LLR-004.7,
  LLR-004.8
- Status: Superseded in batch `2026-06-10-batch-07` (US-002 — cfdx/.cdfx flow retired in favor of the v2 address-only JSON change system; see R-CHG-*). Statement retained as historical record.

**R-CDFX-010**: The CDFX writer must apply the eight write-time `W-*` structural
rules of `design-input/cdfx-research.md` §7 (`W-XML-WELLFORMED`,
`W-ROOT-MSRSW`, `W-BACKBONE`, `W-INSTANCE-NAME`, `W-INSTANCE-CATEGORY`,
`W-VALUE-PRESENT`, `W-CATEGORY-VALUE-CONSISTENT`, `W-EMPTY-CHANGELIST`) via a
standalone validator, emitting one `ValidationIssue` with the rule's documented
code and severity per violation.

- Code: `s19_app/tui/cdfx/writer.py` (`validate_w_rules`,
  `validate_w_rules_bytes`, `_check_instance`)
- Validation: `Automated` via `tests/test_cdfx_w_rules.py` (TC-019a..TC-019h —
  each of the eight `W-*` structural codes provoked and asserted) — covers
  LLR-006.1
- Status: Superseded in batch `2026-06-10-batch-07` (US-002 — cfdx/.cdfx flow retired in favor of the v2 address-only JSON change system; see R-CHG-*). Statement retained as historical record.

**R-CDFX-011**: The CDFX reader must parse a well-formed `.cdfx` file with
`xml.etree.ElementTree`, locate each `SW-INSTANCE` scoped to the
`SW-INSTANCE-TREE` backbone, expand a `VAL_BLK` instance into N array-element
entries `(name, 0…N-1)` and a `VALUE`/`BOOLEAN`/`ASCII` instance into one
`array_index = None` entry, and decode `V` text in decimal, exponential and
hexadecimal notation.

- Code: `s19_app/tui/cdfx/reader.py` (`read_cdfx`, `_read_instance`,
  `_add_array_entries`, `_add_scalar_entry`, `_add_string_entry`,
  `_decode_numeric`)
- Validation: `Automated` via `tests/test_cdfx_reader.py` and
  `tests/test_cdfx_roundtrip.py` (TC-015 well-formed parse, TC-018 numeric
  notation decode, TC-039 `VAL_BLK` expansion, TC-024 round-trip) — covers
  LLR-005.1, LLR-005.4, LLR-005.6
- Status: Superseded in batch `2026-06-10-batch-07` (US-002 — cfdx/.cdfx flow retired in favor of the v2 address-only JSON change system; see R-CHG-*). Statement retained as historical record.

**R-CDFX-012**: The CDFX reader must tolerate malformed XML and
producer-specific variation — emitting one `R-XML-PARSE` error issue and an
empty change-list (no exception) for non-well-formed input, matching elements by
local name regardless of XML namespace, ignoring unrecognized optional sibling
elements (`ADMIN-DATA`, `SW-CS-HISTORY`, `SW-CS-FLAGS`), and treating a leading
or embedded writer / tool-identification XML comment as non-significant content.

- Code: `s19_app/tui/cdfx/reader.py` (`read_cdfx`, `_local_name`,
  `_find_instance_tree`)
- Validation: `Automated` via `tests/test_cdfx_reader.py` and
  `tests/test_cdfx_r_rules.py` (TC-016 malformed-XML tolerance, TC-017
  producer-variation tolerance, TC-034 tool-note tolerance) — covers
  LLR-005.2, LLR-005.3, LLR-006.7
- Status: Superseded in batch `2026-06-10-batch-07` (US-002 — cfdx/.cdfx flow retired in favor of the v2 address-only JSON change system; see R-CHG-*). Statement retained as historical record.

**R-CDFX-013**: The CDFX reader must apply the read-time `R-*` structural rules
of `design-input/cdfx-research.md` §7 (`R-XML-PARSE`, `R-ROOT-MSRSW`,
`R-VERSION-UNKNOWN`, `R-BACKBONE-MISSING`, `R-INSTANCE-NO-NAME`,
`R-INSTANCE-NO-VALUE`, `R-CATEGORY-UNSUPPORTED`, `R-CATEGORY-VALUE-MISMATCH`,
`R-VALUE-NOT-NUMERIC`), tolerate a non-`CDF20` version token with an info
issue, load an unsupported `CATEGORY` (e.g. `MAP`) read-only with a warning,
and collect every finding as a `ValidationIssue` with `artifact = "cdfx"`
without aborting the load.

- Code: `s19_app/tui/cdfx/reader.py` (`read_cdfx`, `_read_instance`,
  `_check_value_shape`, `_r_issue`), reusing
  `s19_app/validation/model.py` (`ValidationIssue`)
- Validation: `Automated` via `tests/test_cdfx_r_rules.py` (TC-020 read-time
  rule violations, TC-021 version-token tolerance, TC-022 `ValidationIssue`
  reuse, TC-023 unsupported categories read-only) — covers LLR-006.2,
  LLR-006.3, LLR-006.4, LLR-006.5
- Status: Superseded in batch `2026-06-10-batch-07` (US-002 — cfdx/.cdfx flow retired in favor of the v2 address-only JSON change system; see R-CHG-*). Statement retained as historical record.

**R-CDFX-014**: The CDFX reader must reject any `.cdfx` containing a `DOCTYPE`
or `<!ENTITY>` declaration via an `xml.etree.ElementTree.XMLParser` whose
`expat`-level handler raises before any entity is expanded, must reject any
`.cdfx` over the 256 MB byte cap before parsing, and must bound XML element
nesting depth — surfacing each as exactly one `R-XML-PARSE` issue with an empty
change-list, no entity expanded, no external file read and no uncaught
exception.

- Code: `s19_app/tui/cdfx/reader.py` (`_safe_parse`, `_probe_size`,
  `_UnsafeXmlError`), reusing `s19_app/tui/workspace.py`
  (`DEFAULT_COPY_SIZE_CAP_BYTES`)
- Validation: `Automated` via `tests/test_cdfx_safety.py` (TC-027a
  billion-laughs rejection, TC-027b external-entity rejection, TC-035
  size / nesting-depth bound) — covers LLR-006.6, LLR-006.8
- Status: Superseded in batch `2026-06-10-batch-07` (US-002 — cfdx/.cdfx flow retired in favor of the v2 address-only JSON change system; see R-CHG-*). Statement retained as historical record.

**R-CDFX-015**: When a `.cdfx` is loaded while an A2L is loaded, the CDFX reader
must cross-check each parsed `SW-INSTANCE` against the A2L — emitting a warning
`R-NAME-NOT-IN-A2L` for an instance whose name matches no A2L parameter and a
warning `R-ARRAY-LEN-MISMATCH` for an array whose `V` count differs from the
A2L `element_count` — and must emit neither cross-check issue when no A2L is
loaded.

- Code: `s19_app/tui/cdfx/reader.py` (`_cross_check_instance`,
  `_index_a2l_tags`, `_element_count_of`)
- Validation: `Automated` via `tests/test_cdfx_r_rules.py` (TC-029 name
  cross-check, TC-030 array-length cross-check, TC-031 cross-check skipped
  without an A2L) — covers LLR-008.1, LLR-008.2, LLR-008.3
- Status: Superseded in batch `2026-06-10-batch-07` (US-002 — cfdx/.cdfx flow retired in favor of the v2 address-only JSON change system; see R-CHG-*). Statement retained as historical record.

**R-CDFX-016**: The TUI must present the Patch Editor rail screen as a
functional tool — rendering the change-list as a row per entry, wiring the
parameter-name / index / value inputs to the change-list add/edit/remove
operations, exposing save and load actions, and showing a neutral empty-state
prompt for an empty change-list — replacing the inert view shell delivered under
`R-TUI-027`. This **supersedes `R-TUI-027`**.

- Code: `s19_app/tui/screens_directionb.py` (`PatchEditorPanel`),
  `s19_app/tui/app.py` (Patch Editor action handler)
- Validation: `Automated` via `tests/test_tui_patch_editor.py` (TC-025 render /
  edit / empty state, TC-026 save and load actions) — covers LLR-007.1,
  LLR-007.2, LLR-007.3, LLR-007.4, LLR-007.6
- Status: Superseded in batch `2026-06-10-batch-07` (US-002 — cfdx/.cdfx flow retired in favor of the v2 address-only JSON change system; see R-CHG-*). Statement retained as historical record.

**R-CDFX-017**: The CDFX read/write and change-list-model logic must reside in
a dedicated service-style module (the `s19_app/tui/cdfx/` package plus
`s19_app/tui/services/cdfx_service.py`); `app.py` must contain only the
UI-state wiring that calls it, with no `xml.etree.ElementTree` import and no XML
parse/serialize call.

- Code: `s19_app/tui/services/cdfx_service.py` (`CdfxService`),
  `s19_app/tui/cdfx/` (package), `s19_app/tui/app.py` (UI wiring only)
- Validation: `Automated` via `tests/test_tui_patch_editor.py`
  (`test_tc028_app_py_holds_no_cdfx_xml_logic`,
  `test_tc028_patch_action_handler_routes_through_the_service`); TC-028 is an
  inspection checklist backed by these tests — covers LLR-007.5
- Status: Superseded in batch `2026-06-10-batch-07` (US-002 — cfdx/.cdfx flow retired in favor of the v2 address-only JSON change system; see R-CHG-*). Statement retained as historical record.

**R-CDFX-018**: The CDFX write path must resolve and containment-validate its
target the same way `s19_app/tui/workspace.py` `copy_into_workarea` does — the
resolved target under a `.s19tool/workarea/` root, a symbolic-link / NTFS
reparse-point traversal rejected, an existing filename dedup-suffixed — and the
CDFX load path must resolve a user-supplied `.cdfx` path through
`workspace.resolve_input_path`; a containment, reparse-point, overwrite or
path-resolution failure must be surfaced as a `ValidationIssue`, not an uncaught
exception.

- Code: `s19_app/tui/cdfx/writer.py` (`write_cdfx_to_workarea`, `_safe_name`,
  `_containment_issue`), `s19_app/tui/cdfx/reader.py` (`_resolve_source`),
  reusing `s19_app/tui/workspace.py` (`resolve_input_path`,
  `copy_into_workarea`, `_path_traverses_reparse_point`)
- Validation: `Automated` via `tests/test_cdfx_path_containment.py` and
  `tests/test_tui_patch_containment.py` (TC-036 write target
  work-area-contained, TC-037 load path resolves the user-supplied path) —
  covers LLR-005.5, LLR-007.7
- Status: Superseded in batch `2026-06-10-batch-07` (US-002 — cfdx/.cdfx flow retired in favor of the v2 address-only JSON change system; see R-CHG-*). Statement retained as historical record.

---

# 9. Memory-value Editing & Unified Change-set

> **Historical section.** Batch `2026-06-10-batch-07` (US-002) superseded the
> v1 unified JSON container and the selective `.cdfx` export, and evolved the
> memory-change model, the containment-validated JSON writes, and the
> resource ceilings into the v2 change system (`s19_app/tui/changes/` — see
> §10, `R-CHG-*`). Each entry's `Status:` line marks it Superseded or
> Evolved; statements are unchanged historical record.

The memory-value editing + unified change-set + selective export batch
(`2026-05-21-batch-04`) extends the Patch Editor so it can also edit **raw
memory values** — direct `(memory address → new bytes)` changes against the
loaded firmware image — not only A2L calibration parameters. It adds a
memory-change model keyed by memory address, validation of each memory change
against the loaded image's address ranges, hex/ASCII/decimal value display, a
`UnifiedChangeSet` container holding both the batch-03 parameter `ChangeList` and
the new `MemoryChangeList`, a unified-file JSON read/write handler with a fixed
`MF-*` structural rule set, and a selective-export coordinator that splits the
unified change-set into a CDFX `.cdfx` file (parameter half, via the unchanged
batch-03 writer) plus a separate memory-field JSON file.

Like the batch-03 CDFX feature, this batch deliberately adds a data layer — six
new modules inside the existing `s19_app/tui/cdfx/` package plus the
`cdfx_service.py` extension — while leaving the parsing/validation engine frozen
(`git diff main` empty across `core.py`, `hexfile.py`, `range_index.py`,
`validation/`, `tui/a2l.py`, `tui/mac.py`) and the batch-03 CDFX writer/resolver
byte-unchanged (`cdfx/writer.py` and `cdfx/resolve.py` SHA-256-pinned;
`changelist.py` / `reader.py` carry no worktree edit). No firmware image is
modified — the memory-change model is a recorded edit *intent* only. Each row
traces to the batch HLR/LLR/TC set in
`.dev-flow/2026-05-21-batch-04/01-requirements.md` and the per-test verdicts in
`.dev-flow/2026-05-21-batch-04/04-validation.md` (full suite 762 passed /
0 failed / 3 xfailed / 2 skipped; memory / unified / export subset 151 passed;
9 HLR / 37 LLR / 37 TC all `pass`).

**R-MEM-001**: The tool must maintain a memory-change list in which each entry
holds a non-negative integer memory start address and a contiguous, non-empty,
ordered run of new byte values (each `0–255`) for that address, must support
adding, editing and removing entries with `address` as the entry identity and a
deterministic entry order, and must reject construction of an entry with a
negative byte, a byte greater than 255, or an empty `new_bytes` run by raising
`ValueError`.

- Code: `s19_app/tui/cdfx/memory.py` (`MemoryStatus`, `MemoryChange`,
  `MemoryChangeList`)
- Validation: `Automated` via `tests/test_memory_changelist.py` (TC-001 entry
  construction, TC-002 add/edit/remove + identity de-duplication, TC-003
  deterministic ordering, TC-004 model coherence, TC-008 `ValueError` arms) —
  covers LLR-001.1, LLR-001.2, LLR-001.3, LLR-001.4, LLR-002.5
- Status: Evolved into the v2 system in batch `2026-06-10-batch-07` (see R-CHG-*). Statement retained as historical record of the batch-04 contract.

**R-MEM-002**: The tool must validate each memory-change entry's addressed byte
range against the loaded firmware image's address ranges (consuming the
`LoadedFile.ranges` snapshot read-only, never re-parsing the firmware), marking
the entry `inside`, `partial` or `outside` — `unvalidated-no-image` while no
image is loaded — collecting exactly one warning-level `ValidationIssue` per
partial/outside entry and one per inter-entry overlap without raising an
exception, and the `ValidationIssue` message must reference the entry's
`address` and a byte-count summary and must not embed the raw `new_bytes`
content.

- Code: `s19_app/tui/cdfx/memory_validate.py` (`validate_memory_changes`,
  `_range_status`, `_range_issue`, `_overlap_issues`),
  `s19_app/tui/cdfx/memory_display.py` (`format_memory_value`,
  `MemoryValueRendering`), reusing `s19_app/tui/models.py` (`LoadedFile.ranges`)
  and `s19_app/tui/color_policy.py` (`css_class_for_severity`)
- Validation: `Automated` via `tests/test_memory_validate.py` (TC-005
  inside/partial/outside/gap-spanning status, TC-006 collect-don't-abort
  warnings, TC-007 validation without an image, TC-008 inter-entry overlap arm)
  and `tests/test_memory_display.py` (TC-009 hex-primary rendering, TC-010 ASCII
  + decimal companions with the pinned `.` `0x2E` placeholder, TC-011 display
  never mutates the stored bytes) — covers LLR-002.1, LLR-002.2, LLR-002.3,
  LLR-002.4, LLR-003.1, LLR-003.2, LLR-003.3, LLR-008.3
- Status: Evolved into the v2 system in batch `2026-06-10-batch-07` (see R-CHG-*). Statement retained as historical record of the batch-04 contract.

**R-MEM-003**: The tool must provide a unified change-set container holding both
the batch-03 parameter `ChangeList` and the batch-04 `MemoryChangeList` by
composition (not subclassing — `changelist.py` byte-unchanged), exposing each
half for independent inspection, mutation, per-half counts and an empty-state
query; the parameter half is a plain resolution-free `ChangeList`.

- Code: `s19_app/tui/cdfx/changeset.py` (`UnifiedChangeSet`), composing
  `s19_app/tui/cdfx/changelist.py` (`ChangeList`, reused byte-unchanged) and
  `s19_app/tui/cdfx/memory.py` (`MemoryChangeList`)
- Validation: `Automated` via `tests/test_unified_changeset.py` (TC-012 holds
  both halves, TC-013 independent mutation + per-half counts + empty-state,
  TC-026 composes the two existing list types) and `tests/test_cdfx_unchanged.py`
  (TC-027 compose-not-subclass + `app.py`-clean inspection checklist; the
  batch-03 `changelist.py` / `reader.py` / `writer.py` / `resolve.py` confirmed
  byte-unchanged) — covers LLR-004.1, LLR-004.2, LLR-004.3, LLR-004.4, LLR-004.5
- Status: Superseded in batch `2026-06-10-batch-07` (US-002 — cfdx/.cdfx flow retired in favor of the v2 address-only JSON change system; see R-CHG-*). Statement retained as historical record.

**R-MEM-004**: The tool must write the unified change-set to a single JSON file
(stdlib `json`, no new dependency) carrying a format-identifier
(`s19app-unified-changeset`), a version (`1.0`), a parameter half holding the
`ChangeListEntry` fields and a memory-field half encoded as a JSON array of
objects (`address` an integer-valued field, never an object key), placed inside
`.s19tool/workarea/` through the existing `workspace.py` containment path; and
must read a unified change-set file back, parsing both halves and applying a
fixed `MF-*` structural rule set (`MF-JSON-PARSE`, `MF-BAD-STRUCTURE`,
`MF-NO-ADDRESS`, `MF-EMPTY-BYTES`, `MF-BYTE-RANGE`, `MF-VERSION-UNKNOWN`,
`MF-SIZE-CAP`, `MF-ENTRY-LIMIT`, `MF-PATH-UNRESOLVED`, `MF-WRITE-CONTAINMENT`) —
a 256 MB on-disk size cap, a decoded-structure entry-count / run-length ceiling,
an explicit `RecursionError` catch and a structural-shape check that precedes
any half-indexing — collecting every finding as a `ValidationIssue` without
aborting the load (no escaping `KeyError`, no escaping `RecursionError`).

- Code: `s19_app/tui/cdfx/unified_io.py` (`serialize_unified`,
  `write_unified_to_workarea`, `read_unified`, the `MF-*` code constants,
  `MF_ENTRY_COUNT_CEILING`, `MF_RUN_LENGTH_CEILING`), reusing
  `s19_app/tui/workspace.py` (`resolve_input_path`, `copy_into_workarea`,
  `DEFAULT_COPY_SIZE_CAP_BYTES`) and `s19_app/validation/model.py`
  (`ValidationIssue`)
- Validation: `Automated` via `tests/test_unified_write.py` (TC-015 JSON
  structure, TC-016 parameter-entry encoding, TC-017 memory-entry encoding,
  TC-018 work-area-contained write), `tests/test_unified_read.py` (TC-014
  `MF-BAD-STRUCTURE`, TC-019 parses both halves, TC-021 path resolution, TC-022
  size cap, TC-035 deeply-nested `RecursionError` catch, TC-037 decoded-structure
  ceiling), `tests/test_unified_rules.py` (TC-020 malformed JSON, TC-023 per-entry
  `MF-*` rules, TC-024 unknown version) and `tests/test_unified_roundtrip.py`
  (TC-025 write→read structural equality) — covers LLR-005.1, LLR-005.2,
  LLR-005.3, LLR-005.4, LLR-006.1, LLR-006.2, LLR-006.3, LLR-006.4, LLR-006.5,
  LLR-008.1, LLR-008.2
- Status: Evolved into the v2 system in batch `2026-06-10-batch-07` (see R-CHG-*). Statement retained as historical record of the batch-04 contract.

**R-MEM-005**: The tool must selectively export the unified change-set as two
distinct work-area files — a CDFX `.cdfx` file from the parameter half produced
by re-resolving the parameter `ChangeList` against the loaded A2L
(`resolve_against_a2l`) and invoking the **unchanged** batch-03 CDFX writer
(`write_cdfx_to_workarea`), and a separate memory-field JSON file from the
`MemoryChangeList` — collecting each half's `ValidationIssue` results into one
combined result tagged by originating half on the existing `ValidationIssue.artifact`
field, with neither half aborting because the other produced issues; and must
extend the Patch Editor rail screen to add/edit/remove memory-field changes
alongside the batch-03 parameter changes and to save/load the unified file and
trigger the selective export, with `app.py` holding only UI-state wiring that
routes through `CdfxService`.

- Code: `s19_app/tui/cdfx/export.py` (`export_unified`, `ExportResult`,
  `serialize_memory_field`, `write_memory_field_to_workarea`),
  `s19_app/tui/services/cdfx_service.py` (`CdfxService` memory-change + unified
  save/load/export operations), `s19_app/tui/screens_directionb.py`
  (`PatchEditorPanel` memory-change extension), `s19_app/tui/app.py`
  (`on_patch_editor_panel_action_requested` UI wiring), reusing
  `s19_app/tui/cdfx/writer.py` / `resolve.py` (batch-03, byte-unchanged)
- Validation: `Automated` via `tests/test_unified_export.py` (TC-028 CDFX via
  the batch-03 writer, TC-029 memory-field JSON file, TC-030 two distinct files
  + writer byte-unchanged, TC-031 cross-half issue collection, TC-036
  export-time re-resolution) and `tests/test_tui_memory_patch.py` (TC-032 Patch
  Editor renders the memory-change list, TC-033 memory-change controls wired,
  TC-034 save/load/selective-export actions) — covers LLR-007.1, LLR-007.2,
  LLR-007.3, LLR-007.4, LLR-007.5, LLR-009.1, LLR-009.2, LLR-009.3
- Status: Superseded in batch `2026-06-10-batch-07` (US-002 — cfdx/.cdfx flow retired in favor of the v2 address-only JSON change system; see R-CHG-*). Statement retained as historical record.

---

# 10. Hex-first Change & Check System (v2 Patch Editor)

The single-JSON hex-first change system batch (`2026-06-10-batch-07`, US-002 /
US-003) replaces the batch-03/04 three-subflow change system (§8–9) with one
declarative, address-only JSON family: **change files** (`kind = "change"`)
that patch the loaded image and **check files** (`kind = "check"`) whose
entries are expected values compared against it. All logic lives in the
`s19_app/tui/changes/` package plus `s19_app/tui/services/change_service.py`;
`app.py` stays orchestration-only. Each row traces to the batch HLR/LLR/TC set
in `.dev-flow/2026-06-10-batch-07/01-requirements.md`.

**R-CHG-001**: The tool must define a single v2 JSON change-file format — a
document carrying `format` (`s19app-changeset`), `version` (`2.0`), `kind`,
`encoding` (text codecs only), and `value_mode` (`text` / `codes`) metadata
plus an `entries` array of address-only entries of exactly two kinds: string
patches (`type: "string"`, `value` encoded per `encoding`/`value_mode`) and
byte patches (`type: "bytes"`, strict whitespace-separated two-hex-digit wire
grammar) — with no symbolic addressing field. The reader must collect every
schema, metadata, per-entry, collision, and resource-ceiling finding as a
`ValidationIssue` without raising; intersecting (or identical-address) target
ranges in one document must record an ERROR-severity `CHG-COLLISION` finding
per colliding entry; resource ceilings (pre-parse size cap, entry-count
ceiling, encoded run-length ceiling with a pre-encode guard) must be enforced;
and a v1 unified document (`s19app-unified-changeset`) must be rejected with
exactly one ERROR `CHG-V1-FORMAT` finding and an empty document (hard break,
no read shim).

- Code: `s19_app/tui/changes/model.py` (`ChangeEntry`, `ChangeDocument`,
  `MemoryStatus`), `s19_app/tui/changes/io.py` (`read_change_document`,
  `write_change_document`, `serialize_change_document`),
  `s19_app/tui/changes/validate.py` (`collision_issues`)
- Validation: `Automated` via `tests/test_changes_schema.py`
  (`test_metadata_roundtrip`, `test_entry_shapes`, `test_metadata_faults`,
  `test_entry_faults`, the `test_resource_ceilings_*` group,
  `test_v1_rejected`), `tests/test_changes_collision.py`
  (`test_collision_geometries`, `test_collision_messages_name_both_addresses`,
  `test_collision_uses_encoded_length_not_char_count`) and
  `tests/test_changes_containment.py` (`test_containment_status_with_image`,
  `test_no_image_stamps_every_entry_unvalidated_with_no_issues`)
- Status: Added in batch `2026-06-10-batch-07` (US-002 / HLR-001)

**R-CHG-002**: The apply engine must refuse to write anything when the change
document carries any ERROR-severity issue or `kind != "change"` (every
disposition `blocked`); otherwise it must write only fully-`INSIDE` entries
into the loaded image's memory map, capturing each written range's prior
bytes before mutation, and must return a `ChangeSummary` recording per entry
the target range, `before_bytes`/`after_bytes`, disposition (applied /
skipped-partial / skipped-outside / skipped-no-image / blocked), and an
informative linkage classification (standalone / mac-linked / a2l-linked /
both, with the matching symbol) computed via the sorted-range primitives —
linkage never influences whether an entry is applied. The summary carries the
document's collected `ValidationIssue` list, aggregate per-disposition counts,
and a deterministic `to_dict()` under an injectable UTC clock.

- Code: `s19_app/tui/changes/apply.py` (`apply_change_document`,
  `classify_containment`), `s19_app/tui/changes/model.py` (`ChangeSummary`,
  `ChangeSummaryEntry`), reusing `s19_app/range_index.py`
- Validation: `Automated` via `tests/test_changes_apply.py`
  (`test_error_blocks_apply_zero_writes_all_blocked`,
  `test_non_change_kind_blocks_apply`,
  `test_dispositions_inside_partial_outside`, `test_disposition_no_image`,
  `test_before_after_capture_exact_tuples_outside_keys_unchanged`,
  `test_summary_shape_and_serialization_determinism`) and
  `tests/test_changes_linkage.py`
  (`test_four_linkage_classifications_with_symbols`,
  `test_both_linked_outside_entry_is_still_skipped`)
- Status: Added in batch `2026-06-10-batch-07` (US-002 / HLR-002)

**R-CHG-003**: After an apply with at least one applied entry on an
S19-loaded image, the tool must offer to persist the patched image to
`.s19tool/workarea/<project>/` under an operator-provided filename (headless
callers pass the filename explicitly), emitting the file from the post-apply
memory map via a dedicated S19 emitter. The typed filename must pass an
extension-preserving sanitizer — path separators, traversal segments,
absolute/drive-qualified paths, and Windows reserved device names rejected or
neutralized — and the resolved target must remain inside the project work
area. The written path is recorded in `ChangeSummary.saved_path` (`None` when
the operator declines). Save-back is S19-only this batch: on an Intel
HEX-loaded image the tool reports that HEX save-back is not supported and
persists nothing (Intel HEX emitter is a batch-08 candidate).

- Code: `s19_app/tui/changes/apply.py` (`save_patched_image`,
  `_sanitize_s19_filename`), `s19_app/tui/changes/io.py`
  (`emit_s19_from_mem_map`)
- Validation: `Automated` via `tests/test_changes_apply.py`
  (`test_emit_s19_reparses_to_equal_mem_map`,
  `test_emit_s19_roundtrips_public_example_file`,
  `test_save_back_written_file_reparses_to_post_apply_map`,
  `test_save_back_declined_saved_path_none_and_no_file`,
  `test_save_back_adversarial_filenames_contained_or_refused`,
  `test_save_back_hex_source_refused_with_clear_issue`) and
  `tests/test_tui_patch_editor_v2.py` (`test_save_back_prompt`)
- Status: Added in batch `2026-06-10-batch-07` (US-002 / HLR-002, LLR-002.7;
  S19-only per operator decision D-1)

**R-CHG-004**: The Patch Editor rail screen must present exactly one
change-flow section operating on v2 JSON documents (entries table, entry
inputs for both kinds, Load/Validate/Apply/Save/Run-checks controls), routing
exactly nine actions (`add_entry`, `edit_entry`, `remove_entry`, `load_doc`,
`validate_doc`, `apply_doc`, `save_doc`, `run_checks`, `execute_scope`)
through the consolidated `ChangeService`; loading a `.cdfx` file or a v1
unified JSON document must surface exactly one ERROR-severity
unsupported-format finding without crashing; and declaration faults must
remain persistently visible (per-entry status in the entries table plus an
issue count in the panel, surviving unrelated UI actions) until the document
is re-validated clean. This **supersedes `R-CDFX-016`** (and with it the
batch-03/04 parameter and unified sections of the panel).

- Code: `s19_app/tui/screens_directionb.py` (`PatchEditorPanel`, v2
  single-section), `s19_app/tui/services/change_service.py` (`ChangeService`),
  `s19_app/tui/app.py` (action router, UI wiring only)
- Validation: `Automated` via `tests/test_tui_patch_editor_v2.py`
  (`test_panel_composition`, `test_action_routing_pins_exactly_nine_v2_actions`,
  `test_action_routing_observable_effects`, `test_legacy_load_rejected`,
  `test_declaration_faults_visible`) and `tests/test_change_service.py`
  (`test_v2_save_load_round_trip`, `test_validate_flags_interactive_collision`,
  `test_clean_revalidate_clears_stale_collision_faults`,
  `test_legacy_v1_load_rejected_with_single_error`,
  `test_retired_method_names_absent`,
  `test_change_service_module_imports_no_textual`)
- Status: Added in batch `2026-06-10-batch-07` (US-002 / HLR-003)

**R-CHK-001**: The tool must accept check documents in the same v2 schema
family, discriminated by `kind = "check"` (identical entry shapes, metadata
rules, collision ERROR, containment statuses, and ceilings — one reader, one
rule set), and execute them against a loaded image producing per entry exactly
one of pass / fail / uncheckable — uncheckable covering any entry whose target
range is not fully inside the loaded image or when no image is loaded — while
mutating nothing. The `CheckRunResult` carries per-entry expected/actual bytes
and linkage classification, aggregate pass/fail/uncheckable counts, and the
check document's collected declaration-fault issues; a headless service entry
point (`run_checks_for_project`) executes a check document against project
files with no TUI interaction, and the TUI renders results with severity
colours plus the three aggregate counts.

- Code: `s19_app/tui/changes/check.py` (`run_check_document`),
  `s19_app/tui/changes/model.py` (`CheckRunEntry`, `CheckRunResult`),
  `s19_app/tui/services/change_service.py` (`run_checks_for_project`)
- Validation: `Automated` via `tests/test_checks_engine.py`
  (`test_check_schema_shared`, `test_results_two_one_two_with_immutability`,
  `test_results_no_image_all_uncheckable`,
  `test_faulted_or_wrong_kind_document_not_runnable`,
  `test_result_shape_deterministic`, `test_headless_project_run`,
  `test_no_textual_in_static_import_graph`) and
  `tests/test_tui_patch_editor_v2.py` (`test_check_run_display`)
- Status: Added in batch `2026-06-10-batch-07` (US-003 / HLR-004)

---

# 11. Multi-variant Projects & Execution

The multi-S19 variant batch (`2026-06-10-batch-07`, US-005) relaxes the
1-S19-per-project limit: a project may hold N ≥ 1 S19/HEX variants of the same
software sharing one MAC and one A2L, with change/check files executed in
batch or per-variant.

**R-VAR-001**: A project directory containing N ≥ 1 S19/HEX files, at most one
MAC file, and at most one A2L file must validate as a project, with the
S19/HEX files enumerated as an ordered variant set under a deterministic
`(name.lower(), name)` sort and exactly one active variant rendered in the TUI
at any time — parsed on a worker thread and applied on the main UI thread (the
pre-batch thread contract is preserved, and a single-S19 project loads
identically to before). The variant model is additive: `VariantDescriptor` /
`ProjectVariantSet` dataclasses plus one defaulted `LoadedFile.variant_id`
field. A modal variant selector and a `«project»:«variant_id» (i/N)` project
label expose switching when N > 1.

- Code: `s19_app/tui/workspace.py` (`validate_project_files`, multi-S19
  relaxation), `s19_app/tui/models.py` (`VariantDescriptor`,
  `ProjectVariantSet`, `LoadedFile.variant_id`), `s19_app/tui/screens.py`
  (`SelectVariantScreen`), `s19_app/tui/app.py` (`action_select_variant`,
  project-label suffix)
- Validation: `Automated` via `tests/test_workspace_variants.py`
  (`test_three_s19_variants_accepted_in_deterministic_order`,
  `test_variants_with_two_mac_files_still_rejected`,
  `test_two_a2l_files_still_rejected`,
  `test_single_s19_project_loads_equivalently`,
  `test_build_variant_set_orders_variants_and_defaults_active_to_first`) and
  `tests/test_tui_variants.py` (`test_project_load_activates_first_variant`,
  `test_select_variant_updates_label`,
  `test_no_new_parse_loaded_file_call_sites`,
  `test_load_second_s19_appends_variant`)
- Status: Added in batch `2026-06-10-batch-07` (US-005 / HLR-005)

**R-VAR-002**: Execution of change and/or check files against a multi-variant
project must follow the optional `.s19tool/workarea/<project>/project.json`
manifest (schema version, `active_variant` load override, per-variant
`assignments`, `batch` list) — manifest absent means batch mode over all
variants — with every manifest path resolved strictly inside the project
directory (traversal, absolute, drive-qualified, or reparse-point escapes
produce one ERROR issue and the entry is skipped) and the manifest read
size-capped before parse. Execution runs in deterministic order, parses each
assigned non-active variant headlessly via the load service (never mutating
the TUI's active snapshot), isolates per-variant failures
(collect-don't-abort; result count always equals assigned-variant count), and
produces exactly one `ChangeSummary` and/or `CheckRunResult` per assigned
variant, consumed intact by the report layer. The TUI exposes a scope
selector (active variant / all variants / per assignment) via the
`execute_scope` Patch Editor action.

- Code: `s19_app/tui/services/variant_execution_service.py`
  (`ProjectManifest`, `read_project_manifest`, `plan_variant_executions`,
  `execute_variant_plan`, `execute_project_variants`,
  `VariantExecutionResult`), `s19_app/tui/app.py` (`execute_scope` routing,
  `_trigger_execute_scope`)
- Validation: `Automated` via `tests/test_variant_execution.py`
  (`test_manifest_absent_defaults_to_batch_all`, `test_manifest_round_trip`,
  `test_load_project_honors_manifest_active_variant`,
  `test_load_project_unknown_active_variant_falls_back`,
  `test_manifest_containment_skips_unsafe_entries`,
  `test_double_run_orderings_identical`,
  `test_failing_variant_never_aborts_the_rest`,
  `test_batch_execution_stamps_variant_ids`,
  `test_save_back_files_land_under_project_dir`)
- Status: Added in batch `2026-06-10-batch-07` (US-005 / HLR-006)

---

# 12. Project Report

The project-report batch (`2026-06-10-batch-07`, US-004) adds an auditable
Markdown artifact per project plus a read-only TUI viewer.

**R-RPT-001**: On request, the tool must generate a Markdown report at
`.s19tool/workarea/<project>/reports/<timestamp>-report.md` (UTC
`%Y%m%dT%H%M%SZ` timestamp; same-second collisions take a zero-padded `-NN`
counter, never a silent overwrite) containing (a) the project and variant
inventory with a consolidated overview, (b) the modified files (including
`saved_path` when present), (c) per-modification before→after values with
linkage annotation and a declaration-error subsection, (d) each executed
checklist with per-entry pass/fail/uncheckable results, and (e) a hexdump of
every modified region with ±`context_bytes` (default 64, adjustable per
invocation, domain-validated — out-of-domain values rejected, never silently
clamped) of surrounding memory, the window computed as
`[max(0, align16(start − c)), min(align16_up(end + c), align16_up(top)))`
with overlapping/adjacent windows merged. Size caps
(`REPORT_MAX_REGIONS_PER_VARIANT`, `REPORT_MAX_TOTAL_BYTES`) truncate with an
explicit in-document marker stating the omitted count. Reports live only
under the gitignored `.s19tool/` tree and report body bytes are never written
to the rotating log.

- Code: `s19_app/tui/services/report_service.py` (`generate_project_report`,
  `ReportOptions`, `compute_hexdump_windows`, `list_project_reports`),
  reusing `s19_app/tui/hexview.py` (`render_hex_view`)
- Validation: `Automated` via `tests/test_report_service.py`
  (`test_full_report_content`,
  `test_filename_regex_and_same_second_collision`,
  `test_window_math_region_at_address_zero`,
  `test_window_math_region_at_image_top`,
  `test_window_math_adjacent_windows_merge`,
  `test_report_level_edge_windows`,
  `test_context_bytes_out_of_domain_rejected`,
  `test_region_cap_marker_exact_omitted_count`,
  `test_total_bytes_cap_marker`, `test_inspection_no_forbidden_symbols`,
  `test_execution_capture_feeds_report_end_to_end`)
- Status: Added in batch `2026-06-10-batch-07` (US-004 / HLR-007)

**R-RPT-002**: The TUI must list the active project's reports newest-first by
the parsed `(timestamp, NN)` sort key and render the selected report
read-only in a modal Markdown viewer constructed with `open_links=False` and a
render size cap (an explicit too-large message instead of rendering past the
cap), reached via the key-bound `action_view_reports` — the activity rail
stays at exactly eight items (no 9th rail item). Report generation must also
be available headlessly: invoking the service entry point constructs no
Textual `App`.

- Code: `s19_app/tui/screens.py` (`ReportViewerScreen`),
  `s19_app/tui/app.py` (`action_view_reports`, generation trigger),
  `s19_app/tui/services/report_service.py` (`generate_project_report`,
  `list_project_reports`)
- Validation: `Automated` via `tests/test_tui_report_view.py`
  (`test_view_reports_no_project_neutral_status`,
  `test_list_project_reports_order`, `test_report_viewer_lists_newest_first`,
  `test_select_renders_markdown_open_links_false`,
  `test_oversized_report_refused`, `test_empty_reports_dir_empty_state`,
  `test_generate_trigger_calls_service_and_drops_results`) and
  `tests/test_report_service.py` (`test_generation_is_headless_no_app`)
- Status: Added in batch `2026-06-10-batch-07` (US-004 / HLR-008)

---

# 13. Project / Documentation meta

**R-DOC-001**: The TUI module must include high-level documentation and
key method docstrings to aid maintenance.

- Code: `s19_app/tui/__init__.py`, `s19_app/tui/app.py`
- Validation: `Automated` via `tests/test_tui_helpers.py`
  (`test_tui_module_has_docstring`, `test_tui_app_has_docstring`)
