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
14. Operation Framework (batch-08)
15. Hex Compare Mode (batch-09)
16. HEX Emitter + Verify-on-Save (batch-10)
17. Project Manifest Writer (batch-11)
18. CRC Operation (CRC_F2) (batch-12)
19. CRC Config-from-File + Patch-Editor Paste (batch-13)
20. A↔B Compare Load-Failure Honesty (batch-15)
21. Selectable S19 Record Width + Populated S0 Header (batch-14)
22. Declared-region UI round-trip + skip notice (batch-20)
23. Patch-editor change-file management + Checks clarity (batch-21)
24. Patch-editor 4-pane 2×2 layout (batch-22)
25. Patch-editor inline variant dropdown (batch-23)
26. A2L red-row ↔ Issues reconcile (batch-24)
27. Before/after save-back report (batch-24)

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
- Validation: `Automated` via `tests/test_tui_evidence_packs.py`
  (`test_dump_a2l_json_writes_file_on_disk` — drives the `j` binding through
  Pilot and asserts the `<name>.a2l.json` exists, is non-empty, and re-parses)

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
- Status: **Superseded by R-CMP-006** (batch-09, US-006). The placeholder shell
  is now the completed `AbDiffPanel` with real compare/render; the `tc027`
  family + the `#diff_deferral_notice` activation guard were superseded at the
  I4 gate (statement preserved here as historical record).

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
- Validation: `Automated` via `tests/test_tui_helpers.py`
  (`test_sanitize_project_name_allows_safe_chars`,
  `test_sanitize_project_name_strips_invalid_chars`,
  `test_sanitize_project_name_rejects_empty`) and
  `tests/test_tui_evidence_packs.py`
  (`test_save_project_creates_project_folder_on_disk` — drives the real save
  handler through Pilot and asserts the sanitized `<project>/` folder appears
  on disk under `.s19tool/workarea/` with the copied primary)

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
- Validation: `Automated` via `tests/test_tui_evidence_packs.py`
  (`test_save_project_creates_project_folder_on_disk` — asserts the loaded
  primary is persisted into the project folder on disk; the A2L-also-present
  leg remains exercised by `tests/test_tui_manifest_save.py`)

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

> **The manifest WRITER (batch-11) is documented in §17.** Batch-06/E6 added
> only the manifest *reader* (`R-VAR-002`); batch-11 (US-010) adds the missing
> write + verify-on-write side. To keep all US-010 requirements together they
> live in their own subsystem section — see **§17 Project Manifest Writer**
> (`R-MAN-SER-001` / `R-MAN-WRITE-001` / `R-MAN-VERIFY-001` / `R-MAN-TUI-001`).


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
  `test_execution_capture_feeds_report_end_to_end`) plus the black-box e2e
  seam in `tests/test_tui_report_seam.py`
  (`test_report_seam_writes_real_file_on_disk` — triggers generation through
  the shipped Reports surface and asserts the real `<timestamp>-report.md`
  exists and is non-empty on disk, no faked service)
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
  `tests/test_report_service.py` (`test_generation_is_headless_no_app`) plus
  the black-box e2e seam in `tests/test_tui_report_seam.py`
  (`test_report_seam_surfaces_written_path_in_status`,
  `test_report_seam_renders_generated_report_in_viewer` — drive the real
  generation trigger and observe the surfaced path + the just-generated
  report rendered through `ReportViewerScreen`)
- Status: Added in batch `2026-06-10-batch-07` (US-004 / HLR-008)

---

# 13. Project / Documentation meta

**R-DOC-001**: The TUI module must include high-level documentation and
key method docstrings to aid maintenance.

- Code: `s19_app/tui/__init__.py`, `s19_app/tui/app.py`
- Validation: `Automated` via `tests/test_tui_helpers.py`
  (`test_tui_module_has_docstring`, `test_tui_app_has_docstring`)

---

# 14. Operation Framework (batch-08)

The operation-framework batch (`2026-06-11-batch-08`, US-007) adds a
placeholder operations skeleton — Operation abstraction, structured result
envelope, deterministic registry, headless service seam, and a TUI operations
view — so each future operation (CRC, extract, split per memory segment) can
receive real behavior without re-plumbing the app. All three shipped
operations are placeholders: identity passthrough over the loaded snapshot,
`status="placeholder"`, zero operation logic.

**R-OPS-001**: The system must define an `Operation` abstract base class
(class-level `operation_id` and `title`, `describe()`, and
`execute(loaded: LoadedFile, *, now_fn=...) -> OperationResult` with an
injectable UTC clock seam) and an `OperationResult` dataclass carrying exactly
the 7 canonical fields (`operation_id`, `status`, `input_path`, `variant_id`,
`output`, `notes`, `timestamp_utc`), with `status` constrained to the closed
domain {`placeholder`, `ok`, `error`} (`STATUS_DOMAIN`; out-of-domain raises
`ValueError`) and a deterministic `to_dict()` that serializes `output` as
exactly `{path, file_type, byte_count}` — never the `mem_map` payload. The
three placeholder operations (`CrcOperation`, `ExtractOperation`,
`SplitBySegmentOperation`) must perform an identity passthrough for both S19-
and HEX-built snapshots: `result.output is loaded`, `mem_map`/`ranges`/`errors`
unmutated, `status == "placeholder"`, and exactly one note of the form
`"placeholder: <operation_id> not yet implemented"`.

- Code: `s19_app/tui/operations/model.py` (`Operation`, `OperationResult`,
  `STATUS_DOMAIN`, `OperationResult.to_dict`),
  `s19_app/tui/operations/placeholders.py` (`CrcOperation`,
  `ExtractOperation`, `SplitBySegmentOperation`)
- Validation: `Automated` via `tests/test_operations.py`
  (`test_operation_interface`, `test_operation_result_schema`,
  `test_identity_passthrough_s19`, `test_identity_passthrough_hex`,
  `test_placeholders_registered`)
- Status: Added in batch `2026-06-11-batch-08` (US-007 / HLR-001, HLR-002(1))

**R-OPS-002**: The system must provide a deterministic, code-driven operation
registry — a static in-module mapping exposing
`list_operation_ids() -> ["crc", "extract", "split_by_segment"]` in that fixed
order on every call and `get_operation(operation_id)` resolving to the
registered instance, raising `KeyError` naming the requested id verbatim for
unknown ids (no fallback, no fuzzy match, no model involvement in dispatch) —
plus a headless service entry point
`run_operation(operation_id, loaded, *, now_fn=...)` that resolves through an
injectable registry-lookup seam (`operation_resolver`, default
`get_operation`), forwards `now_fn` unchanged to the operation's `execute`,
propagates the registry `KeyError` unchanged, and performs no I/O, no disk
writes, and no parsing. The operations package and the service module must
import no Textual modules and no TUI view module (`s19_app.tui.app`,
`s19_app.tui.screens`) — the view imports the service, never the reverse.

- Code: `s19_app/tui/operations/registry.py` (`_REGISTRY`,
  `list_operation_ids`, `get_operation`),
  `s19_app/tui/services/operation_service.py` (`run_operation`,
  `operation_resolver`)
- Validation: `Automated` via `tests/test_operations.py`
  (`test_registry_deterministic_order`, `test_unknown_operation_raises`,
  `test_run_operation_service`); import/filesystem bans checked by inspection
  probes (batch-08 `04-validation.md` §2.1–2.3: textual-import +
  reverse-import + filesystem-call probes, 0 hits)
- Status: Added in batch `2026-06-11-batch-08` (US-007 / HLR-002(2–3),
  HLR-003)

**R-OPS-003**: The TUI must provide an `OperationsScreen` modal, reachable via
the key binding `x` (`action_operations_view`), that lists exactly the
registry's operation ids in registry order labelled with each operation's
`title` (option pairs pre-computed by the app — enumeration happens in the
app, not the screen). Confirming a selection must execute the operation
inside the modal exclusively through the `run_operation` service seam
(`OperationsScreen._execute_selected`; no direct `.execute(` call in
`app.py`/`screens.py`), synchronously on the UI thread (no `@work` worker —
valid only while operations are placeholder no-ops), and present the result's
`status` and `notes` plus a hex render of `result.output.mem_map` produced by
`render_hex_view_text` with the pinned argument tuple (`focus_address=None`,
`row_bases=None`, `highlight=None`, `mac_highlight_addresses=None`,
`max_rows=MAX_HEX_ROWS`) into the `#operation_result_hex` widget. If no file
is loaded, the action must set a status-line message and must not push the
screen nor invoke the service. The activity rail stays at exactly eight items
(no 9th rail entry; `rail.py` unmodified by the batch).

- Code: `s19_app/tui/screens.py` (`OperationsScreen`,
  `OperationsScreen._execute_selected`), `s19_app/tui/app.py`
  (`action_operations_view`, `Binding("x", "operations_view", ...)`)
- Validation: `Automated` via `tests/test_tui_operations_view.py`
  (`test_operations_view_lists_registry_ids`,
  `test_operations_view_executes_via_service`,
  `test_operations_view_result_hex_render_matches_baseline`)
- Status: Added in batch `2026-06-11-batch-08` (US-007 / HLR-004)

## Per-operation requirements convention (C-7)

Each operation's REAL behavior (the future fill-in replacing a placeholder's
`execute`) gets its own HLR/LLR requirements set, SEPARATE from the
application's requirements, co-located with the module at
`s19_app/tui/operations/requirements/REQ-<operation_id>.md` — created by that
operation's fill-in batch, not by batch-08 (the directory does not exist yet).
This document and the `.dev-flow/` batch documents only REFERENCE those local
documents; they never carry the operation requirements themselves. Rationale
(operator decision, 2026-06-11, batch-08 `01-requirements.md` §6.2 C-7):
operations may become ad-hoc functions reused in different applications, so
their requirements must travel with the module, not bind to the main
application.

# 15. Hex Compare Mode (batch-09)

The hex-compare batch (`2026-06-11-batch-09`, US-006) adds a pairwise
comparison mode for two HEX/S19 images — in-project variants or external
files — sharing the same A2L/MAC artifacts: a reusable headless diff engine, a
service that resolves sources and computes per-image artifact-usage notes, a
complete two-format (Markdown + HTML) diff report, and the completed A↔B Diff
TUI screen. Pairwise (two images) by deliberate decision (G-1); N-way deferred.

**R-CMP-001**: The system must provide a headless diff engine
(`diff_mem_maps`) that compares two sparse memory maps and returns a
`ComparisonResult` carrying exactly the canonical field set (`image_a`,
`image_b`, `runs`, `stats`, `notes`, `diagnostics`, `refused`). Differences
must be reported as classified contiguous runs (`DiffRun` with kind ∈
{`changed`, `only_a`, `only_b`}) in ascending-start order, with `DiffStats`
giving per-kind run and byte counts. Output must be deterministic for fixed
inputs and symmetric (diff(A,B).only_a == diff(B,A).only_b). The engine imports
no Textual and no parser (S19File/IntelHexFile) — package-root headless module.
A large-image diff (two `make_large_s19` maps) must complete within ≤ 2.0 s
(measured 1.39 s).

- Code: `s19_app/compare.py` (`ComparisonResult` :183, `DiffRun`, `DiffStats`,
  `_classify_address`, `diff_mem_maps` :272), `s19_app/range_index.py`
  (`build_sorted_range_index`, `address_in_sorted_ranges`)
- Validation: `Automated` via `tests/test_compare_engine.py`
  (`test_classification_set_equality`, `test_adjacency_merge_same_kind_merges`,
  `test_boundary_cases`, `test_stats_byte_count_equals_run_lengths`,
  `test_symmetry_swap_only_a_only_b`, `test_large_image_perf` [`@slow`])
- Status: Added in batch `2026-06-11-batch-09` (US-006 / HLR-001)

**R-CMP-002**: The system must provide a headless comparison service
(`compare_images`) that resolves the two sources — in-project variant by id
from a `ProjectVariantSet` and/or external file via `resolve_input_path`
(read-only, existence-checked) — parses each through the existing load path,
invokes the engine, and assembles the `ComparisonResult`. A per-source parse
failure or unresolvable path must yield a `refused` result, never raise. The
service imports no Textual.

- Code: `s19_app/tui/services/compare_service.py` (`compare_images` :451,
  `_resolve_source`, `_load_image`, `_refused`)
- Validation: `Automated` via `tests/test_compare_service.py`
  (`test_variant_pair_matches_engine`, `test_external_unresolvable_returns_refused`,
  `test_mixed_source_pairings_record_identity`,
  `test_parse_failure_isolated_to_refused`,
  `test_result_field_set_matches_c9_contract`)
- Status: Added in batch `2026-06-11-batch-09` (US-006 / HLR-002)

**R-CMP-003**: For each image, the system must compute an artifact-usage note
(`both` / `one` / `none`) recording which of the shared A2L/MAC artifacts the
image covers, where "used" means coverage of ≥ 1 artifact address within the
image's ranges (via `range_index`). The note is informative and must never gate
or alter the binary diff.

- Code: `s19_app/tui/services/compare_service.py` (`_coverage_count` :276,
  `_artifact_note` :324, `_build_usage` :385)
- Validation: `Automated` via `tests/test_compare_service.py`
  (`test_coverage_counts_match_hand_computed`,
  `test_usage_summary_all_four_outcomes`, `test_absent_artifacts_summary_none`,
  `test_artifact_context_applies_to_external`)
- Status: Added in batch `2026-06-11-batch-09` (US-006 / HLR-003)

**R-CMP-004**: The system must generate a diff report from a `ComparisonResult`
as a COMPLETE file (no run cap, no byte truncation, no TRUNCATED markers — the
display caps bound only the TUI view, never the file) in two formats: (a)
Markdown rendering `changed` runs as fenced ```diff blocks (A bytes as `-`
lines, B bytes as `+` lines) with best-effort A2L/MAC symbol annotation; (b) a
self-contained HTML export with inline-CSS colour (changed/only-A/only-B
distinct), `html.escape` applied to all embedded content, and no `<script>`, no
external resources/fonts/CDN, no network. Each format owns its own filename
regex (`DIFF_REPORT_FILENAME_REGEX` / `DIFF_REPORT_HTML_FILENAME_REGEX`); the
shared `report_service.REPORT_FILENAME_REGEX` is not edited (G-4). The module
performs no logging (F-S-07).

- Code: `s19_app/tui/services/diff_report_service.py` (`generate_diff_report`
  :720, `generate_diff_report_html` :1015, `DIFF_REPORT_HTML_FILENAME_REGEX`,
  `list_diff_reports` :233, `_annotate_run`, `_esc`)
- Validation: `Automated` via `tests/test_diff_report_service.py`
  (`test_markdown_file_is_complete_no_truncation`,
  `test_changed_run_emits_diff_fenced_block`,
  `test_html_export_complete_and_safe`, `test_html_escapes_embedded_payload`,
  `test_module_performs_no_logging`, `test_self_contained_listing_newest_first`,
  `test_report_service_regex_unedited`)
- Status: Added in batch `2026-06-11-batch-09` (US-006 / HLR-004; G-9 complete-export + HTML)

**R-CMP-005**: The diff-report destination must resolve to
`<project>/reports/` when a project is active, and to an operator-prompted
directory when no project is loaded — validated by
`Path(input).expanduser().resolve()` then requiring `is_dir()`, else REFUSE
with a diagnostic and write no file. There is no implicit Downloads default
(G-8 solo-prompt) and `sanitize_project_name` is not used as the path validator
(it is a name-token cleaner). The tool-generated timestamp filename carries no
operator-supplied string; both branches use the no-silent-overwrite collision
counter (M-5).

- Code: `s19_app/tui/services/diff_report_service.py` (`_resolve_destination`
  :287, `_diff_report_filename`)
- Validation: `Automated` via `tests/test_diff_report_service.py`
  (`test_no_project_valid_directory_writes_one_file`,
  `test_no_project_nonexistent_dir_refused`,
  `test_no_project_collision_no_overwrite`,
  `test_collision_never_overwrites_existing_file`,
  `test_no_sanitize_project_name_in_validator`)
- Status: Added in batch `2026-06-11-batch-09` (US-006 / HLR-004 / LLR-004.6; G-8)

**R-CMP-006**: The TUI must provide the completed A↔B Diff rail screen
(`AbDiffPanel`, reachable via rail key `7`): inline selection of the two
comparison sources (not a modal — G-6), execution exclusively through
`compare_images` (never the engine directly), Rich-coloured rendering of the
classified runs (changed/only-A/only-B) plus the per-image artifact-usage
notes, and an operator prompt for the no-project report destination. The
display caps (`DISPLAY_MAX_RUNS`=128 / `DISPLAY_MAX_TOTAL_BYTES`=2 MB) bound the
on-screen render only — the persisted report file stays complete. The activity
rail stays at exactly eight items (`rail.py` unmodified). This supersedes the
batch-04 A↔B Diff placeholder (see R-TUI-028).

- Code: `s19_app/tui/screens_directionb.py` (`AbDiffPanel` :849), `s19_app/tui/app.py`
  (`compare_images` wiring, report-trigger handlers)
- Validation: `Automated` via `tests/test_tui_diff_screen.py`
  (`test_tc021_compare_routes_through_service`,
  `test_tc022_render_shows_runs_and_hex_windows`,
  `test_tc023_refused_compare_surfaces_diagnostic`,
  `test_tc024_report_trigger_surfaces_paths`,
  `test_tc029_display_caps_bound_on_screen_runs`)
- Status: Added in batch `2026-06-11-batch-09` (US-006 / HLR-005); supersedes the batch-04 placeholder

> **Reusable substrate note:** `s19_app/compare.py` (R-CMP-001) is a
> general-purpose diff engine. Its first planned downstream consumer is the
> batch-10 verify-on-save pair (save → re-read → diff against intent). The
> batch-04 package-root module allowlist (the two
> `test_tc028_no_new_processing_module_added_outside_view_layer` guards) was
> updated to include `compare.py` — the newer requirement (HLR-001/D-7, an
> engine module at the package root) supersedes the batch-04 7-module
> invariant; the guard still flags any OTHER unexpected root module.

---

# 16. HEX Emitter + Verify-on-Save (batch-10)

The HEX-emitter / verify-on-save batch (`2026-06-13-batch-10`, US-008 + US-009)
closes the read/write asymmetry in the firmware-format layer — the repo could
*read* Intel HEX (`IntelHexFile`) but only *write* Motorola S19 — and adds
post-write certainty by re-reading the written file and diffing it against the
intended memory map with the batch-09 compare engine (`compare.diff_mem_maps`).
It is the first downstream consumer of `compare.py` outside the comparison
feature. Folded TUI hygiene (N-3 modal button-id de-collision, M-3 `KeyError`
scoping) rides the TUI-touching increment. The parsing-layer engine modules
stayed git-frozen throughout (see the design note below).

> **Design note — emitter location (the batch's key learning).** The Intel HEX
> emitter lives in `s19_app/tui/changes/io.py` (next to `emit_s19_from_mem_map`,
> emission-purpose cohesion) and **NOT** in `s19_app/hexfile.py`, even though
> `hexfile.py` holds the *reader* half. `hexfile.py` is in the git-frozen engine
> set `_ENGINE_PATHS` (`tests/test_engine_unchanged.py:120-127`,
> `tests/test_tui_directionb.py:3738-3746`): any diff to it vs `main` trips the
> engine-frozen guards (`test_tc027_engine_modules_unchanged_vs_main`,
> `test_tc031_engine_modules_have_no_diff_vs_main` /
> `..._no_name_only_diff_vs_main`). The original placement in `hexfile.py` was
> reversed at the I1 gate after it tripped that guard family; `io.py` is neither
> engine-frozen nor a package-root module, so it trips zero guards. `hexfile.py`
> remains the round-trip *oracle* (reader) only. (Batch-10 `01-requirements.md`
> §6.2 D-A reversal record + §6.3 R-10-ENGINE-FROZEN; `04-validation.md` §2.3.)

**R-HEX-EMIT-001**: The system must serialize a sparse memory map and its
contiguous ranges into structurally valid Intel HEX text via
`emit_intel_hex_from_mem_map(mem_map, ranges) -> str` — type-0x00 data records
(≤ 16 data bytes per record), a type-0x04 extended-linear-address (ELA) record
whenever the active upper-16 of the next data address changes (including the
first address above 0xFFFF), and exactly one terminating type-0x01 EOF record
(`:00000001FF`) — each record carrying the Intel HEX two's-complement-of-sum
checksum. Re-parsing the emitted text through `s19_app.hexfile.IntelHexFile`
must reconstruct a memory map equal to the input with zero load errors. The
emitter is pure (stdlib only, no Textual import, no I/O side effect) and lives
in `io.py` for emission-purpose cohesion — `hexfile.py` is git-frozen and is
not edited (see the design note above; HLR-001).

- Code: `s19_app/tui/changes/io.py` (`emit_intel_hex_from_mem_map` :1424,
  `_intel_hex_record` :1497 with the two's-complement checksum at :1529, inline
  ELA emission at :1489, `HEX_DATA_BYTES_PER_RECORD` :1421)
- Validation: `Automated` via `tests/test_hex_emit.py`
  (`test_low_address_roundtrip`, `test_data_records_max_16_bytes_and_checksum`,
  `test_ela_high_address_roundtrip`, `test_ela_record_emitted_per_upper16_change`,
  `test_empty_mem_map_emits_eof_only`, `test_output_terminates_with_single_eof`,
  `test_public_example_roundtrips_as_hex`)
- Status: Added in batch `2026-06-13-batch-10` (US-008 / HLR-001 / LLR-001.1–001.4)

**R-HEX-SAVE-001**: When the operator confirms a save-back for an image whose
`LoadedFile.file_type` is `"hex"`, the system must persist the post-apply image
as Intel HEX through the save engine — `save_patched_image` serializes with
`emit_intel_hex_from_mem_map`, forces a `.hex` suffix via the single
parametric-`suffix` filename sanitizer (default `.s19`, `.hex` on the HEX
branch — traversal / reserved-device-name / trailing-dot rejection unforked),
and stages/places the file through the existing `copy_into_workarea`
containment + no-silent-overwrite machinery — instead of refusing with
`CHG-HEX-SAVE-UNSUPPORTED`. The refusal code stays defined and continues to
refuse any source that is neither `"s19"` nor `"hex"` (e.g. `"mac"`).
`save_patched_image`'s 2-tuple return `(Optional[Path], List[ValidationIssue])`
is preserved unchanged. Variant-execution HEX persist remains out of scope this
batch (HLR-002).

- Code: `s19_app/tui/changes/apply.py` (`save_patched_image` :574, HEX branch /
  retired refusal near `CHG_HEX_SAVE_UNSUPPORTED` :94 / :658,
  `_sanitize_s19_filename` parametric `suffix` :711),
  `s19_app/tui/services/change_service.py` (`save_patched` :807)
- Validation: `Automated` via `tests/test_changes_apply.py`
  (`test_hex_save_writes_hex_file_that_reparses_to_post_apply_map`,
  `test_hex_save_forces_hex_suffix_when_name_lacks_it`,
  `test_s19_save_still_forces_s19_suffix`,
  `test_hex_save_adversarial_filenames_contained_or_refused`,
  `test_save_back_unsupported_source_refused_with_clear_issue`)
- Status: Added in batch `2026-06-13-batch-10` (US-008 / HLR-002 / LLR-002.1–002.3)

**R-HEX-VERIFY-001**: When a save-back has written a file, the system must
re-read the written file with the parser matching its format — `IntelHexFile`
for `"hex"`, `S19File` for `"s19"` — diff the re-read memory map against the
intended memory map using `compare.diff_mem_maps`, and return a `VerifyResult`
carrying exactly `(status, runs, stats, written_path)` with `status ==
"verified"` when the diff is empty and `status == "mismatch"` (carrying the
diff runs/stats) otherwise. The verify helper is headless (no Textual import).
The `VerifyResult` reaches callers on a back-compatible carrier —
`ChangeService.last_summary.verify_result` — leaving `save_patched_image`'s
2-tuple return unchanged; a mismatch must not delete or suppress the written
file (collect-don't-abort). `VerifyResult` exposes only run/byte counts and the
file name — never raw memory bytes (HLR-003).

- Code: `s19_app/tui/changes/verify.py` (`VerifyResult` :35,
  `verify_written_image` :119, `STATUS_VERIFIED` / `STATUS_MISMATCH`),
  `s19_app/compare.py` (`diff_mem_maps` :272, `DiffRun` :100 / `.length`
  `@property` :138, `DiffStats` :150, `DIFF_KIND_DOMAIN` :53),
  `s19_app/tui/services/change_service.py` (verify call + `last_summary`
  stamping :867-869)
- Validation: `Automated` via `tests/test_verify_on_save.py`
  (`test_identity_write_is_verified`, `test_mutated_byte_is_mismatch_changed`,
  `test_dropped_byte_is_mismatch_only_a`, `test_unsupported_file_type_raises`,
  `test_written_path_is_stamped`) and `tests/test_changes_apply.py`
  (`test_verify_written_hex_image_is_verified`,
  `test_verify_on_dropped_byte_is_mismatch_file_kept`) and
  `tests/test_change_service.py`
  (`test_hex_save_stamps_verified_result_on_summary`,
  `test_refused_save_leaves_verify_result_none`)
- Status: Added in batch `2026-06-13-batch-10` (US-009 / HLR-003 / LLR-003.1–003.3)

**R-HEX-VERIFY-002**: While a save-back completes, the TUI must surface a single
concise "Saved + verified" status line on a clean verify and must not raise a
modal or notice; on a verify mismatch it must surface a prominent error notice
naming the written file and the per-kind run/byte mismatch summary (built from
`DiffStats.run_counts` / `byte_counts` over `DIFF_KIND_DOMAIN`), while leaving
the written file in place. The default suggested save filename is format-aware
(`.hex` for a `"hex"` image, `.s19` for an `"s19"` image) (HLR-004; hybrid
trigger — verify always runs, only a mismatch interrupts).

- Code: `s19_app/tui/app.py` (`_surface_verify_result` :1420 reading
  `last_summary.verify_result`, `_verify_mismatch_summary` :1476,
  `_report_change_result` :1506)
- Validation: `Automated` via `tests/test_tui_patch_editor_v2.py`
  (`test_verify_quiet_pass_on_faithful_hex_save`,
  `test_verify_loud_mismatch_notice`)
- Status: Added in batch `2026-06-13-batch-10` (US-009 / HLR-004 / LLR-004.1–004.2)

**R-HEX-HYGIENE-001**: Where the batch touches the TUI modal screens, each
modal must give its button-row container a screen-unique widget id (eliminating
the `load_buttons` id formerly shared across six screens), preserving the
shared `.modal-buttons` styling; and `OperationsScreen._execute_selected` must
resolve the operation id through the module-level `operation_service.
operation_resolver` seam inside a narrow `try`/`except KeyError` and call the
resolved operation's `.execute(...)` OUTSIDE that `try`, so a `KeyError` raised
inside operation execution propagates rather than being misreported as "unknown
operation" (HLR-005; folded N-3 + M-3 hygiene).

- Code: `s19_app/tui/screens.py` (`OperationsScreen` button row id
  `operations_buttons` :562, `_execute_selected` :583 with the narrowed
  `operation_resolver` call :631 inside `try`/`except KeyError` :632 and
  `operation.execute(...)` :636 outside)
- Validation: `Automated` via `tests/test_tui_operations_view.py`
  (`test_operations_button_row_has_screen_unique_id`,
  `test_execute_internal_keyerror_not_masked_as_unknown_operation`)
- Status: Added in batch `2026-06-13-batch-10` (US-008/US-009 folded /
  HLR-005 / LLR-005.1–005.2)

---

# 17. Project Manifest Writer (batch-11)

The project-manifest-writer batch (`2026-06-14-batch-11`, US-010) closes the
read/write asymmetry in the project layer — the repo could *read* the
per-project `.s19tool/workarea/<project>/project.json` manifest (`R-VAR-002`)
but the file had to be hand-authored — by adding the WRITE side plus
post-write certainty: re-read the written manifest and compare the parse
against the intended composition. It is the JSON analogue of the batch-10
verify-on-save discipline (write image → re-read → diff,
§16 `R-HEX-VERIFY-001`). The manifest *reader* `read_project_manifest`
(`s19_app/tui/services/variant_execution_service.py`) is the schema oracle and
stays unchanged; the writer round-trips against it (the batch-10
emitter→`IntelHexFile` precedent). Each row traces to the batch HLR/LLR/TC
set in `.dev-flow/2026-06-14-batch-11/01-requirements.md` and the per-test
verdicts in `.dev-flow/2026-06-14-batch-11/04-validation.md` (PASS-WITH-NOTES;
targeted matrix 23/23 PASS; full suite 807 passed / 0 failed / 29 skipped /
3 xfailed; signed balance `839 = 816 − 0 + 23`).

> **Design note — writer location + atomic placement (the batch's key
> learning).** The serialize/write/verify logic lives in
> `s19_app/tui/services/manifest_writer.py`, a service-layer module beside the
> reader's home rationale — NOT in any git-frozen engine module and NOT at
> the `s19_app/` package root, so it trips zero structural guards
> (`test_engine_unchanged.py`, the `s19_app/` root-module guards in
> `tests/test_tui_directionb.py`) and stays headless (no `textual`, no
> `logging` import). The contained write REUSES `copy_into_workarea`'s
> containment CHECKS (`_find_workarea_root` + `is_relative_to` +
> `_path_traverses_reparse_point`, `s19_app/tui/workspace.py`) against the
> destination, then performs an atomic `os.replace(staged, project.json)` at
> the fixed name — it does NOT route through `copy_into_workarea`'s
> copy-with-dedup body, which would append `_<N>` on collision and produce a
> `project_1.json` invisible to the reader (which opens only the fixed
> `project_dir / PROJECT_MANIFEST_NAME`). A re-save therefore overwrites in
> place atomically, never dedup-suffixed. (Batch-11 `01-requirements.md` §6.2
> D-3 locked mechanism; `04-validation.md` I-2.)

**R-MAN-SER-001**: The system must serialize an in-memory project composition
into the canonical manifest envelope — a JSON object with exactly the four
keys `{schema_version, active_variant, batch, assignments}`, emitted via the
stdlib `json` encoder (never string assembly), where `active_variant` is the
`ProjectVariantSet.active_id`, `batch` is the project-wide change/check file
list, and `assignments` maps each `variant_id` to its file list, with every
`batch`/`assignments` entry written as a project-relative forward-slash path
string. Correctness is defined by round-trip to the reader (the oracle): the
serialized dict, written and re-read through `read_project_manifest`, must
yield a `ProjectManifest` with zero `issues` and `active_variant`/`batch`/
`assignments` equal to intent in the canonical comparison form (intended
entries resolved against the same `project_root` before comparison). Output is
byte-deterministic for a given composition. As a security input gate, if any
`batch`/`assignments` entry is absolute or resolves outside `project_root`,
the serializer must REFUSE the whole operation — returning `(None, [finding])`
and writing nothing — reusing the reader's own rejection predicate
(`_resolve_manifest_entry`), never emitting a string the reader would later
silently skip (HLR-001 incl. LLR-001.5).

- Code: `s19_app/tui/services/manifest_writer.py` (`serialize_manifest` :224,
  `_reject_unsafe_entry` :178 reusing `variant_execution_service.
  _resolve_manifest_entry`, `_posix_entries` :152, `MANIFEST_WRITE_ESCAPE` :74
  value `"MANIFEST-WRITE-ESCAPE"`), round-trip oracle
  `s19_app/tui/services/variant_execution_service.py` (`read_project_manifest`)
- Validation: `Automated` via `tests/test_manifest_writer.py`
  (`test_envelope_keys_and_active_variant`,
  `test_envelope_empty_project_active_variant_is_null`,
  `test_relative_paths_resolve_with_no_escape`,
  `test_windows_backslashes_normalized_to_forward_slash`,
  `test_roundtrip_equals_intent_in_canonical_form`,
  `test_roundtrip_schema_version_survives`,
  `test_deterministic_byte_identical_output`,
  `test_refuse_escape_and_absolute_entries_writes_nothing`,
  `test_clean_composition_passes_the_gate`,
  `test_refusal_emits_no_file_when_caller_would_write`)
- Status: Added in batch `2026-06-14-batch-11` (US-010 / HLR-001 /
  LLR-001.1–001.5)

**R-MAN-WRITE-001**: When a serialized manifest is written, the system must
stage the bytes under `.s19tool/workarea/temp/`, validate the final
destination `project_dir / "project.json"` with the SAME containment checks
`copy_into_workarea` applies (`_find_workarea_root` + `is_relative_to` +
`_path_traverses_reparse_point`), and then perform an ATOMIC `os.replace` onto
the fixed `project.json` name (`PROJECT_MANIFEST_NAME`) — so a re-save
overwrites the existing manifest in place and two saves into one project dir
leave exactly one `project.json` and zero `project_1.json` (no dedup-suffix).
It must NOT route the manifest through `copy_into_workarea`'s copy-with-dedup
function body, and must remove the staged temp file afterward. If the
destination fails the containment check (`WorkareaContainmentError`) or the
stage / `os.replace` raises an `OSError`, the writer must return
`(None, [finding])` with a `MANIFEST-WRITE-CONTAINMENT` issue rather than
raise (collect-don't-abort) (HLR-002).

- Code: `s19_app/tui/services/manifest_writer.py` (`write_project_manifest`
  :370, atomic `os.replace(staged, destination)` :463,
  `_check_destination_contained` :322 reusing `s19_app/tui/workspace.py`
  containment checks, `MANIFEST_WRITE_CONTAINMENT` :81 value
  `"MANIFEST-WRITE-CONTAINMENT"`)
- Validation: `Automated` via `tests/test_manifest_writer.py`
  (`test_write_places_manifest_and_reads_back`,
  `test_two_saves_leave_exactly_one_manifest_second_wins`,
  `test_fixed_name_and_staged_temp_removed`,
  `test_destination_outside_workarea_returns_finding`,
  `test_refused_serialize_short_circuits_without_writing`)
- Status: Added in batch `2026-06-14-batch-11` (US-010 / HLR-002 /
  LLR-002.1–002.3; atomic same-name `os.replace` is the locked D-3 mechanism)

**R-MAN-VERIFY-001**: When a manifest has been written, the system must
re-read `project.json` via `read_project_manifest` addressed by the CANONICAL
`project_dir / PROJECT_MANIFEST_NAME` (not the path the writer returns) and
compare the re-read `active_variant`/`batch`/`assignments` against the intended
composition (key-wise dict equality in the canonical comparison form, NOT
`compare.diff_mem_maps` — a manifest is a JSON dict, not a memory map),
returning a `ManifestVerifyResult` whose `status` is `"verified"` iff all
three keys are equal AND the re-read `issues` list is empty, and `"mismatch"`
otherwise. A mismatch result must enumerate the drifting key(s) and carry the
re-read reader issues; a write the reader degrades or rejects (size cap, JSON
parse, bad structure, path escape) must classify as mismatch, not a false
verify (the R-1 guard). The verify module is headless (HLR-003).

- Code: `s19_app/tui/services/manifest_writer.py` (`verify_written_manifest`
  :580, `ManifestVerifyResult` :490, `_resolve_intended_entries` :543,
  `MANIFEST_VERIFIED` :481 value `"verified"`, `MANIFEST_MISMATCH` :486 value
  `"mismatch"`), re-read oracle
  `s19_app/tui/services/variant_execution_service.py` (`read_project_manifest`)
- Validation: `Automated` via `tests/test_manifest_verify.py`
  (`test_faithful_write_verifies`,
  `test_tampered_active_variant_mismatches_naming_the_key`,
  `test_reader_issues_force_mismatch_even_if_surviving_keys_match`,
  `test_verify_reads_canonical_name_not_a_stray_suffixed_file`)
- Status: Added in batch `2026-06-14-batch-11` (US-010 / HLR-003 /
  LLR-003.1–003.3)

**R-MAN-TUI-001**: Where the operator triggers project save, the TUI must
invoke the serialize→write→verify pipeline for the active project (without
changing the existing project file-copy save behavior) and surface the verify
outcome: a concise quiet "manifest verified" status on success, and a loud
notice naming the drifting key(s) / plain-text reader-issue messages on
mismatch or write-refusal (reader-issue text rendered as PLAIN text, never
interpolated into Rich markup, so a crafted path string cannot inject markup;
severity colour via the frozen `color_policy.SEVERITY_CLASS_MAP`). A
write-failure surfaces an error notice without crashing the save flow
(HLR-004).

- Code: `s19_app/tui/app.py` (`_handle_save_dialog` :3443 calling
  `_write_and_verify_manifest` :3539, which calls `write_project_manifest`
  :3578 + `verify_written_manifest` :3592 and routes to
  `_surface_manifest_verify_result` :3595; service imports :92–93)
- Validation: `Automated` via `tests/test_tui_manifest_save.py`
  (`test_project_save_writes_and_verifies_manifest`,
  `test_manifest_mismatch_surfaces_loud_notice_naming_drift`,
  `test_manifest_write_refusal_surfaces_error_notice_no_crash`,
  `test_manifest_writer_module_is_headless`)
- Status: Added in batch `2026-06-14-batch-11` (US-010 / HLR-004 /
  LLR-004.1–004.3). **Scope note (SCOPE-1, per `04-validation.md` §4):** the
  serialize/write/verify engine fully supports and tests `batch` and
  `assignments`, but the TUI save handler this batch composes only
  `active_variant` (it calls `write_project_manifest` with empty `batch`/
  `assignments`). Persisting `batch`/`assignments` from the loaded project
  state via the save UI is a batch-12 candidate; this row does not claim it.

---

# 18. CRC Operation (CRC_F2)

The CRC operation batch (`2026-06-16-batch-12`, US-011 / US-012) is the first
concrete *operation* fill-in of the batch-08 operations framework: a
parameterized CRC32 over one or more configured memory ranges of a loaded S19
(incl. S3/32-bit), with a non-mutating **check** (compute + compare against the
stored value) and an operator-confirmed **inject** (write + re-emit modified
S19 + verify). It resolves the two batch-08 deferred framework risks — the
neutral input contract (R-2) and the `OperationResult` widening (R-3) — and
reuses `emit_s19_from_mem_map` / `verify_written_image` / `range_index`
import-only, touching ZERO frozen engine path.

> **Per-operation HLR/LLR detail:**
> `s19_app/tui/operations/requirements/REQ-crc.md` (co-located with the module,
> per the batch-08 C-7 operations-module convention). The rows below are the
> repo-wide `R-CRC-*` traceability that REFERENCE that doc; the operation's own
> HLR/LLR statements, EARS form, engine decisions (D-4 default param set, D-5
> 4-byte LE codec), and open risks live there and are NOT inlined here. The
> normative source of truth for the full statements is
> `.dev-flow/2026-06-16-batch-12/01-requirements.md` §3 (HLR) / §4 (LLR); the
> per-node validation verdicts are in
> `.dev-flow/2026-06-16-batch-12/04-validation.md` (PASS-WITH-NOTES; 5/5 HLR +
> 12/12 in-scope LLR PASS, 1 LLR WITHDRAWN, 0 FAIL; CRC subset 53 passed; full
> suite 847 passed / 0 failed / 29 skipped / 3 xfailed).

> **Scope boundaries (honest).** This batch is **TUI-only** — no CLI `ops`
> subcommand (deferred at batch-08). CRC inputs are **S19 only** — no A2L, no
> HEX/MAC as CRC inputs. There is **no `report_service` integration** (J-3
> re-scope, `01-requirements.md` §6.4 / `04-validation.md` §5): `report_service`
> is project/variant-scoped while CRC is a per-file operation, so the CRC's
> persistent record is the emitted modified S19 (FR9) plus the `OperationResult`
> result summary — not a report-service section. `report_service.py` is
> untouched this batch.

**R-CRC-ENGINE-001**: The CRC operation must provide a parameterized, headless
CRC32 compute engine that, for each configured region, selects only in-region
`mem_map` bytes, orders them ascending, reconstructs contiguous segments
(splitting on any gap, contiguity rule `current == previous + 1`, inserting no
bytes for gaps), digests the concatenated segments through one non-resetting
CRC32 state, applies the configured final XOR, and returns one computed CRC per
region — with no I/O, no parsing, and no mutation of the input. With the default
params (zlib/PKZIP convention: poly `0x04C11DB7`, init `0xFFFFFFFF`, reverse
`true`, xorout `0xFFFFFFFF`) the result equals `zlib.crc32` over the same bytes
(HLR-001 / LLR-001.1–001.3; engine surface detail in `REQ-crc.md`).

- Code: `s19_app/tui/operations/crc.py` (`crc32_stream`, `region_segments`,
  `compute_region_crc`, `compute_region_crcs`, `encode_le32`/`decode_le32`),
  reusing `s19_app/range_index.py` (`build_sorted_range_index`,
  `address_in_sorted_ranges`) import-only
- Validation: `Automated` via `tests/test_crc_engine.py`
  (`test_known_answer_vector` — the gating KAT `crc32(b"123456789") ==
  0xCBF43926`, `test_segment_chaining_does_not_reset_state`,
  `test_gap_splits_segments_no_inserted_bytes`,
  `test_ascending_address_ordering`,
  `test_region_filter_excludes_out_of_range`,
  `test_entry_point_does_not_mutate_mem_map`, `test_config_params_change_result`,
  `test_le_codec_roundtrip`)
- Status: Added in batch `2026-06-16-batch-12` (US-011 / HLR-001 /
  LLR-001.1–001.3)

**R-CRC-ENGINE-002**: With non-default CRC parameters the engine uses a bitwise
reflected loop rather than the `zlib.crc32` fast path; the default (zlib) path
is fully verified by the known-answer vector, and the bitwise path is
corroborated against published CRC-32 variant KATs, but a real device's
*non-zlib* convention still requires an operator-sourced reference vector before
its computed CRC can be trusted (RK-3; the params are proven *wired*, not a
non-default result proven *correct*).

- Code: `s19_app/tui/operations/crc.py` (`crc32_stream` bitwise reflected branch)
- Validation: `Partial` — the default zlib path is `Automated` via
  `tests/test_crc_engine.py` (`test_known_answer_vector`,
  `test_config_params_change_result`) and the bitwise path is corroborated by
  `test_bitwise_path_reproduces_published_variant_kats`; a non-default *device*
  convention reference vector is `Manual` (operator-sourced fixture pending —
  RK-3, see `REQ-crc.md` Open risks and `04-validation.md` §5)
- Status: Added in batch `2026-06-16-batch-12` (US-011 / HLR-001 / LLR-001.1,
  RK-3 residual)

**R-CRC-CHECK-001**: When the CRC operation runs in its default (check) mode
over a loaded S19, the system must, for each configured region, read the 4-byte
little-endian value stored at that region's output address, compare it to the
computed CRC, and report per output address whether the stored value matches —
without modifying the loaded `mem_map` or writing any file. A missing output
address yields no stored value (no exception) (HLR-002 / LLR-002.1–002.4; detail
in `REQ-crc.md`).

- Code: `s19_app/tui/operations/crc.py` (check/compare + read-stored 4-byte LE
  via `decode_le32`), `s19_app/tui/screens.py` (`OperationsScreen` CRC result
  rows + `@work(thread=True)` execute path)
- Validation: `Automated` via `tests/test_crc_operation.py`
  (`test_check_reports_match_nonmutating`, `test_check_reports_mismatch`,
  `test_read_stored_missing_returns_none`, `test_check_multi_region_order`,
  `test_execute_with_config_populates_crc_regions`) and
  `tests/test_tui_crc_surface.py`
  (`test_crc_check_reaches_result_surface_via_handler`,
  `test_crc_execute_path_uses_thread_worker`,
  `test_stale_crc_worker_result_does_not_overwrite_error`)
- Status: Added in batch `2026-06-16-batch-12` (US-011 / HLR-002 /
  LLR-002.1–002.4). **Note (J-3):** LLR-002.5 (persistent project-report
  render) is **WITHDRAWN** — the check has no separate persistent artifact; its
  surface is the op-result view (LLR-002.4).

**R-CRC-WRITE-001**: When the operator confirms the write stage after a check,
the system must write each computed CRC as a 4-byte little-endian value at its
output address — extending `mem_map` and `ranges` to include the 4 bytes when
the output address falls in a gap — emit a structurally valid modified S19 from
the resulting memory map into the contained work area, re-read that S19 with the
production parser and confirm it equals the intended (injected) memory map, and
record the emitted path + verify verdict in the `OperationResult`; and if the
operator does not confirm, then the system must write no file. The original
`mem_map` is left byte-for-byte unchanged (inject works on a working copy)
(HLR-003 / LLR-003.1–003.5; detail in `REQ-crc.md`).

- Code: `s19_app/tui/operations/crc.py` (inject 4-byte LE via `encode_le32` +
  extend-on-gap + emit via `emit_s19_from_mem_map` + verify via
  `verify_written_image` + assemble the write `OperationResult`),
  `s19_app/tui/screens.py` (`ConfirmWriteScreen` two-stage confirm +
  `confirm_write_ok`/`confirm_write_cancel` + write-outcome rows)
- Validation: `Automated` via `tests/test_crc_operation.py`
  (`test_inject_writes_le_at_output_address`,
  `test_inject_into_gap_extends_ranges`,
  `test_modified_s19_reread_matches_intent` — clean → verified + empty diff,
  corrupted → mismatch (non-tautological), `test_write_only_when_invoked`,
  `test_write_outside_workarea_collects_finding_and_writes_no_file`,
  `test_write_result_records_emitted_path_and_verdict`) and
  `tests/test_tui_crc_surface.py` (`test_no_write_without_confirmation` —
  pilot-driven `ConfirmWriteScreen` decline → 0 files / confirm → 1 file,
  `test_crc_inject_reaches_surface_via_handler`)
- Status: Added in batch `2026-06-16-batch-12` (US-012 / HLR-003 /
  LLR-003.1–003.4 + re-scoped LLR-003.5). **Note (J-3):** LLR-003.5 is
  **RE-SCOPED** — the persistent record is the operation's own output (emitted
  S19 + `OperationResult`), NOT a `report_service` binding.

**R-CRC-CONFIG-001**: When the operator supplies a CRC config file path, the
system must resolve it via `resolve_input_path` under the `READ_SIZE_CAP_BYTES`
size cap, parse the JSON into a typed config (regions with `(start, end)` +
output address, polynomial, init, reverse flag, final-XOR), and present the
config in the TUI as editable text pre-filled with dummy values for format
guidance; and if the path is unresolvable or the JSON is structurally invalid,
then the system must report the failure as exactly one collected error and run
no CRC computation (collect-don't-abort, never raises). Real per-firmware config
values are never committed — the repo carries only the dummy template
`examples/crc_config.example.json` (HLR-004 / LLR-004.1–004.2; detail in
`REQ-crc.md`).

- Code: `s19_app/tui/operations/crc_config.py` (`read_crc_config`,
  `parse_crc_config`, `CrcConfig`, `CrcRegion`, `DUMMY_CONFIG_TEXT`),
  `s19_app/tui/screens.py` (CRC config text editor surface)
- Validation: `Automated` via `tests/test_crc_config.py`
  (`test_params_loaded_from_synthetic_json`,
  `test_unresolvable_path_collects_one_error`,
  `test_malformed_json_collects_one_error`,
  `test_over_size_cap_collects_one_error_without_reading`,
  `test_missing_field_collects_one_error`,
  `test_parse_crc_config_valid_text_populates_config`,
  `test_parse_crc_config_dummy_prefill_is_valid`,
  `test_parse_crc_config_malformed_text_collects_one_error`,
  `test_parse_crc_config_non_object_top_level_collects_one_error`,
  `test_parse_crc_config_missing_field_collects_one_error`,
  `test_no_real_config_required`) and `tests/test_tui_crc_surface.py`
  (`test_crc_config_error_surfaces_error_and_no_match`)
- Status: Added in batch `2026-06-16-batch-12` (US-011/US-012 / HLR-004 /
  LLR-004.1–004.2)

**R-CRC-CONTRACT-001**: The operations framework must provide a neutral
operation input (`OperationInput`) carrying `mem_map`, `ranges`, and identifying
metadata — replacing the `execute(loaded: LoadedFile, …)` binding so an
operation does not depend on the Textual-side `LoadedFile` (a
`OperationInput.from_loaded` adapter keeps existing callers working) — and
`OperationResult` must be widened with one optional structured per-region CRC
payload field (`crc_regions`) while preserving its 7 canonical fields and the
closed `STATUS_DOMAIN` `{"placeholder","ok","error"}` for all current callers
(resolves batch-08 R-2 / R-3; HLR-005 / LLR-005.1–005.3).

- Code: `s19_app/tui/operations/model.py` (`OperationInput` :27 +
  `from_loaded` :82, `OperationResult.crc_regions` :260, `CrcRegionResult` :131,
  `STATUS_DOMAIN` :23 unchanged), `s19_app/tui/services/operation_service.py`
  (`run_operation` builds the neutral input), `s19_app/tui/operations/
  placeholders.py` (3 placeholder `execute` signatures adapted)
- Validation: `Automated` via `tests/test_operations.py`
  (`test_operation_input_exposes_mem_map_ranges_metadata`,
  `test_operation_result_widened_field_count_and_status_domain`,
  `test_run_operation_service`, `test_operation_interface`,
  `test_identity_passthrough_s19`, `test_identity_passthrough_hex`,
  `test_placeholders_registered` — 10 nodes, 0 regressions post-widening)
- Status: Added in batch `2026-06-16-batch-12` (US-011/US-012 / HLR-005 /
  LLR-005.1–005.3, resolves batch-08 deferred R-2 / R-3)

---

# 19. CRC Config-from-File + Patch-Editor Paste (CRC_F2 / Patch Editor)

The batch (`2026-06-17-batch-13`, US-013 / US-014) adds **two existing-substrate
TUI surfaces** — no new engine math. US-013 lets the operator load the CRC config
JSON from a file path into the editable `#operation_config` `TextArea` (rather
than only pasting it), reusing the shipped resolve + size-cap read contract.
US-014 lets the operator paste a whole `s19app-changeset` (kind=change) document
into the Patch Editor — pre-loaded with a dummy reference — and parse it into the
owned `ChangeService` document, which then feeds the **already-shipped**
apply / containment / contained-emit / verify / save-back path **with zero new
write surface**. Both surfaces preserve the collect-don't-abort reader contract
and touch ZERO frozen engine path (the CRC reader lands in non-frozen
`tui/operations/crc_config.py`; the change-document parse seam lands in
non-frozen `tui/changes/io.py`).

> **Per-story HLR/LLR detail:** the normative source of truth for the full EARS
> statements is `.dev-flow/2026-06-17-batch-13/01-requirements.md` §3 (HLR-013 /
> HLR-014) / §4 (LLR-013.1–.3 / LLR-014.1–.3); the per-node validation verdicts
> are in `.dev-flow/2026-06-17-batch-13/04-validation.md` (verdict **PASS**:
> 2/2 HLR + 6/6 LLR PASS, 0 FAIL; full suite **861 passed / 0 failed / 29
> skipped / 3 xfailed**, 893 collected; TC-201..211 each map to exactly one real
> passing node, 0 orphans). The rows below are the repo-wide `R-*`
> traceability that REFERENCE those docs; the EARS statements, consumer-input
> contracts, and the change-first census are NOT inlined here.

> **Scope boundaries (honest).** This batch is **TUI-only** — no CLI (`s19tool`)
> config-load or paste. US-014 is a **Phase-0 re-scope** to the one genuinely
> missing ergonomic (paste-full-changeset + dummy pre-load, at CRC parity): the
> shipped Patch Editor load-from-file, apply, INSIDE/PARTIAL/OUTSIDE containment,
> contained emit (`emit_s19_from_mem_map` via `copy_into_workarea`), and
> `verify_written_image` reader-as-oracle are reused **unchanged** and were NOT
> re-specified. The two-stage write modal and a write worker-thread remain
> operator-DEFERRED. The stale `app.py:938` "inert shell" docstring was corrected
> as a surgical truth-fix (not a requirement).

**R-CRC-CONFIGLOAD-001**: Where the CRC operation is the selected operation on
the `OperationsScreen`, when the operator supplies a config file path and
triggers a load, the system must ingest the file's RAW text into the editable
`#operation_config` `TextArea` under the existing resolve + size-cap read
contract (`resolve_input_path` + `READ_SIZE_CAP_BYTES`, size-cap enforced BEFORE
read); and if the path is empty, unresolvable, over the size cap, or unreadable,
then the system must surface exactly one collected error on the operations status
surface, leave the `#operation_config` text unchanged, and run no CRC check
(collect-don't-abort, never raises). The CRC run path is unchanged — Execute
still parses the editor text via `parse_crc_config(TextArea.text)`, and while no
file has been loaded the editor keeps `DUMMY_CONFIG_TEXT` as the pre-loaded
reference (HLR-013 / LLR-013.1–013.3; detail in `01-requirements.md` §3/§4).

- Code: `s19_app/tui/operations/crc_config.py` (`read_crc_config_text` :221 — the
  NEW raw-text reader: resolve + size-cap + `read_text`, returns
  `tuple[Optional[str], list[str]]` WITHOUT parsing; `read_crc_config` /
  `parse_crc_config` / `DUMMY_CONFIG_TEXT` reused import-only),
  `s19_app/tui/screens.py` (`OperationsScreen` config-path `Input`
  `#operation_config_path` + "Load config" `Button` `#operation_config_load` in
  `compose`, toggled with `#operation_config` by `_sync_config_visibility`;
  `on_button_pressed` → `_load_config_from_path` handler at screens.py:795/801/841)
- Validation: `Automated` via `tests/test_crc_config.py`
  (`test_read_crc_config_text_returns_raw_text_without_parsing`,
  `test_read_crc_config_text_over_cap_collects_one_error_without_reading`,
  `test_read_crc_config_text_returns_unparsed_invalid_json`,
  `test_read_crc_config_text_unresolvable_path_collects_one_error`) and
  `tests/test_tui_crc_surface.py`
  (`test_crc_config_load_widgets_present_and_toggle` — TC-201,
  `test_crc_config_load_ok_populates_editor_via_handler` — TC-203,
  `test_crc_config_load_fault_surfaces_error_and_no_check` — TC-204,
  `test_crc_config_error_surfaces_error_and_no_match`)
- Status: Added in batch `2026-06-17-batch-13` (US-013 / HLR-013 /
  LLR-013.1–013.3). A-5 surface-reachability: the load reaches `#operation_config`
  THROUGH the `on_button_pressed` handler call-site (not a direct reader call).

**R-PATCH-PASTE-001**: While the Patch Editor is mounted, the system must present
an editable paste `TextArea` pre-loaded with `DUMMY_CHANGESET_TEXT` (a
syntactically valid `s19app-changeset`, kind=change, FAKE values only) as a
format reference; when the operator triggers the `parse_paste` action, the panel
must post a `PatchEditorPanel.ActionRequested` carrying the paste text, `app.py`
must route it to `ChangeService.load_text`, and the service must parse the text
into a `ChangeDocument` via a string-input parse seam under collect-don't-abort,
replacing the owned document; a malformed paste must yield a document carrying
the collected findings (including `MF-JSON-PARSE` on a JSON-decode failure) and
must not raise. The string seam is a delegation refactor of the file reader —
`read_change_document(path)` delegates to `parse_change_document(text)` exactly
once — and a string-parsed document equals the equivalent file read on `entries`
and issue-code set (the string seam sets `source_path=None`, the only intended
divergence) (HLR-014 / LLR-014.1–014.2; detail in `01-requirements.md` §3/§4).

- Code: `s19_app/tui/changes/io.py` (`parse_change_document` :431 — NEW string
  seam factored out of the post-`json.load` interpretation, re-homing the
  `MF-JSON-PARSE` three-exception catch onto `json.loads(text)`;
  `read_change_document` refactored to delegate after resolve + size-cap + read;
  `DUMMY_CHANGESET_TEXT` :134; both added to `__all__`),
  `s19_app/tui/services/change_service.py` (`load_text` :633 — NEW sibling of
  `load` that calls `parse_change_document(text)` and does the same
  `self.document = …` / `last_summary = None` / `ChangeActionResult` shaping),
  `s19_app/tui/screens_directionb.py` (paste `TextArea` `#patch_paste_text` on
  `PatchEditorPanel` + `parse_paste` action + `paste_text` field on
  `ActionRequested`), `s19_app/tui/app.py` (`parse_paste` route to `load_text`
  at app.py:1336-1338; `PATCH_ACTIONS_V2` extended 9→10)
- Validation: `Automated` via `tests/test_changes_schema.py`
  (`test_dummy_changeset_parses` — TC-206,
  `test_parse_from_string_matches_file_read` — TC-207 (narrowed `entries` +
  `{issue.code}` parity oracle, `source_path=None` divergence asserted),
  `test_parse_malformed_json_emits_mf_json_parse` — TC-209,
  `test_read_change_document_delegates_to_parse` — TC-210 (`call_count == 1`),
  `test_no_changeset_under_examples` — TC-211 tripwire) and
  `tests/test_tui_patch_editor_v2.py`
  (`test_paste_textarea_preloads_dummy_changeset` — TC-205,
  `test_paste_parse_then_apply_matches_file_loaded` — TC-208 (route half),
  `test_action_routing_pins_exactly_ten_v2_actions` — the `PATCH_ACTIONS_V2`
  9→10 REUSE-extend)
- Status: Added in batch `2026-06-17-batch-13` (US-014 / HLR-014 /
  LLR-014.1–014.2). A-5 surface-reachability: parse reaches the service THROUGH
  the panel → `ActionRequested(paste_text)` → router call-site, not a direct
  `load_text` kwarg.

**R-PATCH-WRITE-REUSE-001**: After a paste is parsed into the owned document, the
system must make that document drive the EXISTING apply / INSIDE-PARTIAL-OUTSIDE /
contained-emit / verify / save-back path unchanged, introducing **no new write
surface** — a paste-parsed document and an equivalent file-loaded document must
produce identical apply outcomes (entries applied + save-back prompt state,
including the pre-filled save name) (HLR-014 / LLR-014.3; the standing F-S-03
write-surface gate).

- Code: no new write code — reuse-only. The shipped write path
  (`s19_app/tui/changes/apply.py`, `s19_app/tui/changes/verify.py`,
  `s19_app/tui/workspace.py`, plus `emit_s19_from_mem_map` and `save_patched`)
  is consumed unchanged; the parse seam (`R-PATCH-PASTE-001`) is the only delta
  feeding it
- Validation: `Automated (inspection)` — the standing write-surface gate is a
  HARD Phase-4 row, verified against the batch-13 branch point `febd843` (the
  PR #17 merge = real `origin/main` tip, NOT the stale local `main` ref):
  `git diff febd843 -- s19_app/tui/changes/apply.py s19_app/tui/changes/verify.py
  s19_app/tui/workspace.py` = **0 changed lines**, and the `emit_s19_from_mem_map`
  / `save_patched` symbol bodies are unchanged vs `febd843` (0 new write paths).
  The reuse itself is exercised by `tests/test_tui_patch_editor_v2.py`
  (`test_paste_parse_then_apply_matches_file_loaded` — TC-208, apply + save-back
  prompt-name identity vs a file-loaded document)
- Status: Added in batch `2026-06-17-batch-13` (US-014 / HLR-014 / LLR-014.3).
  Standing gate — re-run on any future batch that touches the Patch Editor write
  surface; PASS at batch-13 close vs `febd843`.

---

# 20. A↔B Compare Load-Failure Honesty (batch-15)

The batch (`2026-06-24-batch-15`, US-016) is a **retroactive black-box acceptance
closure** of an escaped bug in the A↔B Diff compare: when one of the two compared
images was a non-empty file that parsed to an **empty** memory map (every S-record
malformed — the collect-don't-abort degenerate case the comparison service does
NOT refuse), the panel rendered a green `sev-ok` verdict with bogus `only_a`/`only_b`
runs, silently presenting a load failure as a clean compare. The fix is a
display-side verdict-honesty change in `tui/app.py` (outside the engine-frozen
set); the comparison engine and `compare_service` are unchanged. The escape was
possible because **every prior diff handler test monkeypatched `compare_images`**,
so the real on-disk parse path was never driven through the shipped button.

> **Per-story HLR/LLR detail:** the normative source of truth for the full EARS
> statements is `.dev-flow/2026-06-24-batch-15/01-requirements.md` §3 (HLR-016) /
> §4 (LLR-016.1–.3); the black-box acceptance design (AT-016.1/.2/.3/.4, the
> pre-fix-RED oracle, the R-2 reachability gate) and the per-node validation
> verdicts are in that batch folder (`02-review.md`, `04-validation.md`). The row
> below is the repo-wide `R-*` traceability that REFERENCES those docs.

> **Scope boundaries (honest).** US-015 (16/32 S19 record width + populated S0)
> was carried in the batch-14 backlog alongside this story but is **net-new
> feature work, not an escaped bug**; it was **deferred** at the batch-15 Phase-0
> gate to its own forward-feature batch (its spec is preserved in
> `.dev-flow/2026-06-23-batch-14/01-requirements.md`). batch-15 ships US-016 only.

**R-DIFF-LOADFAIL-001**: When the operator runs an A↔B compare of two images
selected by absolute path through the `#diff_compare_button` surface, and one side
is a non-empty source file that re-parses to an empty memory map (or whose
re-parse raises), then the system must surface a `sev-error` diagnostic on
`#diff_status` naming the failed side — rather than a `sev-ok` status (whether "0
runs" or runs derived from a partially-loaded pair); and when both images load to
usable maps the genuine differing runs and `sev-ok` are reported as before. A
legitimately small but valid image (maps ≥1 byte) must NOT be flagged. The failed
side is detected display-side (`_diff_load_maps`: source file has content on disk
yet maps empty) and carried out-of-band of the `(mem_map_a, mem_map_b)` tuple the
report path consumes; the diagnostic text is surfaced as plain text
(`#diff_status` stays `markup=False`) (HLR-016 / LLR-016.1–.3; detail in
`01-requirements.md` §3/§4).

- Code: `s19_app/tui/app.py` (`_diff_load_maps` :2151 — return widened to
  `tuple[dict, dict, list[str]]` with the NEW `failed_sides` out-of-band signal +
  inner `_source_has_content` predicate; `on_ab_diff_panel_compare_requested`
  :2083 — conditional `sev-error`-naming-the-side vs the prior unconditional
  `sev-ok` at :2144). No engine / `compare_service` / widget change; report path
  (`on_ab_diff_panel_report_requested`, reads `panel.mem_map_a/b`) untouched.
- Validation: `Automated` via `tests/test_tui_diff_compare_realpath.py` — four
  black-box `App.run_test()` pilots driving the real `#diff_compare_button` with
  NO `compare_images` monkeypatch:
  `test_at_016_1_two_wellformed_images_show_changed_runs` (AT-016.1, regression
  lock), `test_at_016_2_degenerate_image_is_flagged_not_silent` (AT-016.2, the
  escaped-bug regression — RED on the pre-fix tree, GREEN post-fix),
  `test_at_016_3_unresolvable_path_refuses_without_crash` (AT-016.3),
  `test_at_016_4_legit_small_valid_image_is_not_flagged` (AT-016.4,
  over-correction guard). Pre-fix-RED vs post-fix-GREEN evidence captured in
  `04-validation.md`.
- Status: Added in batch `2026-06-24-batch-15` (US-016 / HLR-016 /
  LLR-016.1–.3). A-5 surface-reachability: the diagnostic reaches `#diff_status`
  THROUGH the `#diff_compare_button` → `on_ab_diff_panel_compare_requested`
  handler (not a direct service call). Closes the 2026-06-23 black-box
  acceptance-gap audit item for batch-14 US-016.

---

# 21. Selectable S19 Record Width + Populated S0 Header (batch-14)

The batch (`2026-06-23-batch-14`, US-015) is a **net-new data-fidelity feature**:
the S19 emitter gains a 16-or-32 data-bytes-per-record selector (default 32),
and in 32-byte mode the emitted file carries a **populated S0 header** — the
preserved source S0 when the loaded image had one, else a minimal ASCII header
synthesized from the output filename — while 16-byte mode keeps the legacy empty
S0. The operator chooses the width through a cycling Width selector on the Patch
Editor save-back surface; the choice and the S0 policy are threaded through the
existing contained-write save path into `emit_s19_from_mem_map`. The integrity
guarantee is verified by re-reading every emitted image through the frozen
`S19File` reader-as-oracle. **0 engine-frozen edits** (all new code lives outside
the `_ENGINE_PATHS` set). US-016 was satisfied separately by batch-15 (§20) and
is out of this batch's scope.

> **Per-story HLR/LLR detail:** the normative source of truth for the full EARS
> statements is `.dev-flow/2026-06-23-batch-14/01-requirements.md` §3 (HLR-015) /
> §4 (LLR-015.1–.5), including the two Phase-3 spec amendments — Amendment A
> (S0 length bound ≤252) and Amendment B (S0-inertness asserted against the
> data-record map, not the full `get_memory_map`). The black-box acceptance design
> (AT-015.1/.2/.3 + the preserve-leg AT) and per-node validation verdicts are in
> that batch folder (`02-review.md`, `04-validation.md`,
> `06-docs/traceability-matrix.md`). The rows below are the repo-wide `R-*`
> traceability that REFERENCES those docs.

**R-S19-WIDTH-001**: When the operator saves a patched image through the Patch
Editor save-back surface, the system must emit the S19 at either 16 or 32 data
bytes per record (default 32), selectable through a cycling Width control, such
that every emitted data record carries no more than the chosen number of data
bytes and the emitted file re-parses through the frozen `S19File` reader to a
data-record memory map byte-equal to the in-app patched map; the 16-byte mode
must remain byte-identical to the pre-change framing, and a `bytes_per_line`
value other than 16 or 32 must raise `ValueError` before any record is emitted
(HLR-015 / LLR-015.1, .3, .4; detail in `01-requirements.md` §3/§4).

- Code: `s19_app/tui/changes/io.py` (`emit_s19_from_mem_map` — NEW keyword
  `bytes_per_line: int = 32`, validate-before-emit `ValueError` on values ∉
  {16,32}, replacing the hardcoded 16-byte row step), `s19_app/tui/screens_directionb.py`
  (NEW cycling Width selector `#patch_saveback_width_button` on the save-back
  surface, carried on `SaveBackDecision`), `s19_app/tui/app.py` (save-back handler
  threads the selected width), `s19_app/tui/changes/apply.py`
  (`save_patched_image` — CHANGED signature threading `bytes_per_line` to the
  emitter), `s19_app/tui/services/change_service.py` (`save_patched` — forwards
  the width two hops), `s19_app/tui/services/variant_execution_service.py`
  (project-save threads `bytes_per_line=32`)
- Validation: `Automated` via `tests/test_changes_apply.py`
  (`test_tc212_default_emit_packs_32_byte_rows`,
  `test_tc213_bytes_per_line_16_back_compat_byte_identical`,
  `test_tc214_invalid_bytes_per_line_raises_and_emits_nothing`,
  `test_tc216_32_byte_emit_reparses_byte_equal`,
  `test_tc217_16_byte_emit_reparses_byte_equal`,
  `test_tc218_negative_control_corrupt_data_byte_detected`,
  `test_tc219_save_patched_image_threads_width_and_s0_header`,
  `test_tc220_change_service_save_patched_threads_to_emitter`) and
  `tests/test_tui_patch_editor_v2.py`
  (`test_saveback_width_32_packs_wide_records_and_populates_s0` — AT-015.1,
  `test_saveback_width_16_caps_records_and_empties_s0` — AT-015.3, both black-box
  through the shipped save-back widget read off disk)
- Status: Added in batch `2026-06-23-batch-14` (US-015 / HLR-015 /
  LLR-015.1/.3/.4). A-5 surface-reachability: the 16/32 choice reaches the emitter
  THROUGH `#patch_saveback_width_button` → `SaveBackDecision` → the save-back
  handler → `save_patched` (not a direct emitter kwarg).

**R-S19-S0HEADER-001**: While 32-byte mode is selected, the emitted S19 must carry
a populated S0 header — the captured source S0 when the loaded image had a
content-bearing S0, else a minimal ASCII header synthesized from the output
filename — bounded to a data length of at most 252 bytes (an over-long header
raises `ValueError` before any record is emitted); while 16-byte mode is selected
the system must keep the legacy empty S0. The populated S0 must be inert to the
firmware payload: the re-parsed data-record map (S1/S2/S3 records only) stays
byte-equal to the input map (HLR-015 / LLR-015.2; detail in `01-requirements.md`
§3/§4, including Amendment A and Amendment B).

- Code: `s19_app/tui/changes/io.py` (`emit_s19_from_mem_map` — NEW optional
  `s0_header: bytes | None = None`; when provided emits a populated S0 record,
  with the `len(s0_header) <= 252` bound from Amendment A),
  `s19_app/tui/app.py` (save-back handler S0 policy: `source_s0_header or synth`
  — empty/`None` source S0 falls through to the filename-synthesized header,
  documented in the handler docstring), `s19_app/tui/models.py`
  (NEW `LoadedFile.source_s0_header` capture field),
  `s19_app/tui/services/load_service.py` (`build_loaded_s19` — captures the
  source S0 from `S19File.records`, read-only; no frozen-file edit)
- Validation: `Automated` via `tests/test_changes_apply.py`
  (`test_tc215_populated_s0_is_inert_to_data_and_empty_when_none`,
  `test_c4_overlong_s0_header_raises` — Amendment A 252 bound,
  `test_build_loaded_s19_captures_source_s0_header` — load-seam capture) and
  `tests/test_tui_patch_editor_v2.py`
  (`test_saveback_width_32_preserves_source_s0_header` — the preserve-leg
  black-box AT: a source image with a content-bearing S0 emits that source S0,
  not the synthesized filename, observed off disk)
- Status: Added in batch `2026-06-23-batch-14` (US-015 / HLR-015 / LLR-015.2).
  The S0 header is cosmetic for data integrity — it contributes 0 bytes to the
  firmware payload (it sits at low addresses that never collide with the high-
  address image); its only purpose is downstream tools that display or key on the
  label. A-5 surface-reachability: both the preserve and synthesize legs are
  observed end-to-end through the save-back widget → on-disk file, not via direct
  emitter kwargs.

**R-S19-SAVE-REUSE-001**: The new record-width and S0-header content must reach
disk only through the EXISTING contained-write save path — the save-back handler
threads the width/header into `save_patched` → `save_patched_image` →
`emit_s19_from_mem_map`, which still writes via the established
`copy_into_workarea` contained-write, introducing **no new write surface**; the
dispatch must be S19-branch-only, so the Intel-HEX save path is unaffected by the
S19-only `bytes_per_line` kwarg (HLR-015 / LLR-015.3; the standing C1 HEX-isolation
gate).

- Code: no new write code — reuse-only. The shipped write path
  (`s19_app/tui/changes/apply.py`, the `_SAVE_BACK_EMITTERS` dispatch, the
  workspace contained-write) is consumed unchanged; the `bytes_per_line` /
  `s0_header` threading (`R-S19-WIDTH-001` / `R-S19-S0HEADER-001`) is the only
  delta feeding it, and it is gated to the S19 emitter branch
- Validation: `Automated` via `tests/test_changes_apply.py`
  (`test_tc220b_hex_save_unaffected_by_s19_only_kwargs` — HEX save with
  `bytes_per_line=32` writes a valid `.hex`, no `TypeError`, map-equal) and the
  cross-format integrity guard `test_tc226_cross_format_round_trip_integrity`
  (AT-015.2 — 0 byte delta + 0 errors across S19↔re-parse, HEX→S19(32), S19→HEX)
- Status: Added in batch `2026-06-23-batch-14` (US-015 / HLR-015 / LLR-015.3).
  0 engine-frozen edits — `git diff --name-only origin/main` over the 7 frozen
  paths is empty, confirmed by the `test_tc027_*` / `test_tc031_*` / `test_tc032_*`
  guards. A-5 surface-reachability: the C1 isolation is exercised through the HEX
  save branch, confirming the S19-only kwarg does not leak into the HEX writer.

---

# 22. Per-variant File-Assignment at Project Save (batch-16)

The batch (`2026-06-25-batch-16`, US-017) **closes batch-11 SCOPE-1**: the project
save now persists a project-wide `batch` list and a per-variant `assignments` map
(keyed by `variant_id`) into `project.json`, alongside the pre-existing
`active_variant`. Pre-batch-16 the save handler passed neither dimension and there
was no assignment UI, so the manifest writer / verifier / consumer — which already
accepted `batch`/`assignments` — were reachable only by direct service kwargs in
tests (`test_manifest_verify.py`), never through the shipped save surface; the
saved artifact therefore carried only `active_variant`. The fix threads the
composition from a NEW per-variant assignment UI on `SaveProjectScreen` through the
`SaveProjectPayload` into both `write_project_manifest` and `verify_written_manifest`,
and the persisted entries are consumed unchanged by `plan_variant_executions`.
**0 engine-frozen edits; the writer (`manifest_writer.py`) and consumer
(`variant_execution_service.py`) substrate is edit-free** — all new code lives in
`tui/screens.py` + `tui/app.py` (+ `tui/styles.tcss`), outside the `_ENGINE_PATHS`
set.

> **Per-story HLR/LLR detail:** the normative source of truth for the full EARS
> statements is `.dev-flow/2026-06-25-batch-16/01-requirements.md` §3 (HLR-017) /
> §4 (LLR-017.1–.4), including the load-bearing D-KEY contract (assignment keys are
> the variant's `variant_id` — the filename **stem**, or the **full filename** on
> stem-collision — never a recomputed `Path.stem`) and the D-NEWPROJ scope decision
> (the assignment UI targets re-saving an EXISTING multi-variant project). The
> black-box acceptance design (AT-017.1/.2/.3/.4/.5 + the e2e through-handler AT,
> the four pre-fix-RED handler counterfactuals, the A-5 surface-reachability matrix)
> and the per-node validation verdicts are in that batch folder (`02-review.md`,
> `04-validation.md`, `06-docs/traceability-matrix.md`). The rows below are the
> repo-wide `R-*` traceability that REFERENCES those docs.

**R-PROJ-ASSIGN-001**: When the operator saves a multi-variant project through the
save dialog, the system must persist into `project.json` a project-wide `batch`
list and a per-variant `assignments` map keyed by `variant_id` (alongside
`active_variant`), threading the payload's composition into BOTH
`write_project_manifest` and `verify_written_manifest` with identical values; the
re-read manifest must reproduce `active_variant`/`batch`/`assignments` with zero
drift, and the persisted entries must be consumable by `plan_variant_executions`
such that an assigned variant's execution plan tuple **exactly equals**
`tuple(batch) + tuple(assignments[variant_id])` (resolved). Where the operator
makes no selection the system must write empty `batch`/`assignments`, preserving
the prior active-variant-only save (HLR-017 / LLR-017.1, .2, .4; detail in
`01-requirements.md` §3/§4).

- Code: `s19_app/tui/screens.py` (`SaveProjectPayload` — NEW `batch` +
  `assignments` fields defaulting empty via `field(default_factory=...)`),
  `s19_app/tui/app.py` (`_handle_save_dialog` threads the payload into
  `_write_and_verify_manifest`, which gains a NEW `*, batch, assignments` keyword
  pair; write call `app.py:3785/3786` and verify call `app.py:3803/3804` both carry
  the kwargs). The writer `s19_app/tui/services/manifest_writer.py` and the
  consumer `s19_app/tui/services/variant_execution_service.py` are consumed
  unchanged (read-only substrate)
- Validation: `Automated` via `tests/test_tui_manifest_save.py`
  (`test_at017_1_save_persists_and_round_trips_composition` — AT-017.1, on-disk
  round-trip 0-drift through the shipped handler;
  `test_at017_3_zero_selection_save_no_regression` — AT-017.3, zero-selection
  no-regression guard;
  `test_tc302_303_handler_threads_batch_assignments_to_write_and_verify` — TC-302/303,
  spies assert write & verify each receive `batch`/`assignments` with write-intent
  == verify-intent; `test_tc301_payload_carries_batch_and_assignments` — TC-301,
  payload unit guard) and `tests/test_variant_execution.py`
  (`test_at017_2_consumer_pickup_of_saved_composition` — AT-017.2, exact-tuple
  consumer pickup contract guard). The two pre-fix-RED handler counterfactuals
  AT-017.1 and TC-302/303 fail on the pre-feature tree
  (`TypeError: SaveProjectPayload.__init__() got an unexpected keyword argument
  'batch'`) and pass post-fix; AT-017.3 is green both sides by design (no-regression
  guard). Pre-fix-RED vs post-fix-GREEN evidence captured in `04-validation.md`
- Status: Added in batch `2026-06-25-batch-16` (US-017 / HLR-017 / LLR-017.1, .2,
  .4). Closes batch-11 SCOPE-1. A-5 surface-reachability: every dimension (`batch`,
  `assignments`) reaches `project.json` THROUGH the save dialog →
  `_handle_save_dialog` → `_write_and_verify_manifest` handler, not via the writer's
  direct kwargs (the SCOPE-1 hole). G-3 (Phase-4 iteration): the consumer pickup is
  also observed end-to-end through the handler by
  `tests/test_tui_manifest_save.py::test_at017_2_e2e_consumer_pickup_through_handler`,
  which re-reads the handler-written `project.json` and feeds it to
  `plan_variant_executions`.

**R-PROJ-ASSIGN-UI-001**: While re-saving an existing multi-variant project, the
`SaveProjectScreen` must collect per-variant assignment files and a project-wide
batch list, offering ONLY project-relative `.json` change/check documents
enumerated from the project directory (excluding `project.json` and any file
outside the work-area), and must source each assignment key from the variant's
`ProjectVariantSet.variants[*].variant_id` — never a recomputed `Path.stem` — so a
stem-colliding variant (`fw.s19`+`fw.hex`) is keyed by its full filename (D-KEY);
empty fields must collect `batch==[]`/`assignments=={}` without crashing (HLR-017 /
LLR-017.3; detail in `01-requirements.md` §3/§4).

- Code: `s19_app/tui/screens.py` (`SaveProjectScreen._collect_composition` — NEW
  helper that keys per-variant rows from `variant_id` by index, with no `Path.stem`
  recomputation; `screens.py:298-303`), `s19_app/tui/app.py`
  (`action_save_project` `app.py:2637` passes the variant ids + candidate
  workarea-relative files into the screen), `s19_app/tui/styles.tcss` (assignment
  rows, as needed)
- Validation: `Automated` via `tests/test_tui_manifest_save.py`
  (`test_tc304_...` — TC-304, keys `{"b": ("extra.json",)}` from the variant set;
  `test_tc305_...` — TC-305, offers only `["doc.json"]`, excluding `outside.json`
  and `project.json`; `test_tc306_...` — TC-306, empty fields collect `()`/`{}`
  without crash). The stem-collision key contract is exercised by
  `tests/test_tui_manifest_save.py::test_at017_5_stem_collision_assignment_keyed_by_full_filename`
  (AT-017.5)
- Status: Added in batch `2026-06-25-batch-16` (US-017 / HLR-017 / LLR-017.3).
  D-NEWPROJ scope: a brand-new project save (variant set not yet built) writes the
  HLR-017 zero-selection empty composition; the assignment UI is for re-saving a
  project whose variants are already known. A-5 surface-reachability: the
  assignment reaches the payload THROUGH `action_save_project` →
  `SaveProjectScreen._collect_composition`, not a direct payload construction.

**R-PROJ-ASSIGN-SEC-001**: Every `batch`/`assignments` entry collected at save time
must be a project-relative path inside the work-area; an absolute or escaping
entry driven through the save handler must be refused — surfacing a POSITIVE
"Manifest write failed" notice AND leaving `project.json` un-written — rather than
crashing or persisting the escaping entry. The writer's `_reject_unsafe_entry`
remains the sole path-safety authority (the UI's workarea restriction is
convenience, not the security boundary) (HLR-017 / LLR-017.3, .4; detail in
`01-requirements.md` §3/§4).

- Code: no new security code — the payload carries project-relative strings
  (no pre-resolution to absolute) and the existing writer gate
  `s19_app/tui/services/manifest_writer.py::_reject_unsafe_entry` (`:178`) is the
  enforcement point, now reached end-to-end through the handler. The handler
  surfaces the writer's refusal as a status notice rather than swallowing it
- Validation: `Automated` via `tests/test_tui_manifest_save.py`
  (`test_at017_4_escaping_assignment_refused_no_file_written` — AT-017.4: asserts
  the refusal notice is present AND `not (project_dir / PROJECT_MANIFEST_NAME).exists()`).
  AT-017.4 is RED on the pre-feature tree (the refusal path is unreachable — the
  handler ignores assignments pre-fix, same `TypeError`) and GREEN post-fix
- Status: Added in batch `2026-06-25-batch-16` (US-017 / HLR-017 / LLR-017.3, .4).
  New output surface → Phase-2 security-reviewer mandatory (per D-SEC). A-5
  surface-reachability: the refusal is driven through the save handler
  end-to-end, not by a direct `_reject_unsafe_entry` unit call.

# 23. Workspace / CRC / Issues usability (batch-17)

> Three previously-deferred usability features + an issues-list field exposure, full `/dev-flow`. US-018 / US-019 / US-020a / US-020b shipped; US-020c/d (issues-report addendum) deferred to a follow-on batch. Statements: `.dev-flow/2026-06-26-batch-17/01-requirements.md` §3/§4.

**R-WS-HEXROW-001**: When the Workspace renders the hex view, a full 16-byte + ASCII row shall lay out on one line — the hex view content-sizes and `#hex_scroll` scrolls horizontally when the pane is narrower — while all three Workspace panes stay visible.
- Code: `s19_app/tui/styles.tcss` `#hex_view { width: auto }` (US-018). Supersedes a rejected `#ws_center { min-width: 82 }` floor that pushed the right context pane off-screen on a 3-pane layout at 120 cols (§6.5 amendment A2 — the likely cause of prior failed attempts).
- Validation: `Automated` — `tests/test_tui_workspace_layout.py::test_ws_hex_row_on_one_line_and_scrollable` (AT-018; RED pre-fix: hex view wraps to ~28) + `::test_ws_all_three_panes_stay_visible` + `::test_ws_hex_one_line_holds_in_narrow_regime`.
- Status: Added batch-17 (US-018 / HLR-018 / LLR-018.1).

**R-CRC-WIDTH-001**: When the operator confirms a CRC-injected write after selecting a 16- or 32-byte record width, the written `.s19` shall use the selected width; absent a selection it shall default to 32.
- Code: `s19_app/tui/screens.py` ConfirmWriteScreen width selector + `ConfirmWriteResult(confirmed, bytes_per_line)` threaded `_on_confirm_write` → `_run_crc_write_worker` → `s19_app/tui/operations/crc.py::write_crc_image(bytes_per_line=)` → `emit_s19_from_mem_map` (US-019; `io.py` unchanged — kwarg pre-existed).
- Validation: `Automated` — `tests/test_tui_crc_surface.py::test_crc_write_honours_selected_16_width_through_confirm` (AT-019b; RED pre-fix: emits 32) + `::test_confirm_write_width_selector_cycles` + `tests/test_crc_operation.py::test_crc_write_emits_16_byte_records_when_selected` / `::test_crc_write_emits_32_byte_records` (default lock).
- Status: Added batch-17 (US-019 / HLR-019 / LLR-019.1, .2). Builds on the batch-16 fixed-32 lock (re-pointed as the default branch).

**R-ISSUES-HEXPANE-001**: When the operator selects a validation-issue row carrying an address, the bytes at that address shall render in the Issues screen's hex pane; an address-less issue shall show a placeholder, not stale bytes.
- Code: `s19_app/tui/app.py` `_compose_screen_issues` `#issues_hex_pane` + `_update_issues_hex_pane` (via `render_hex_view_text`) wired into `_jump_to_validation_issue_object`; `s19_app/tui/styles.tcss` `#issues_columns` split (US-020a).
- Validation: `Automated` — `tests/test_tui_issues_view.py::test_at020a_issue_hex_pane_shows_bytes_and_clears_on_no_address` (AT-020a; RED pre-fix: pane empty).
- Status: Added batch-17 (US-020a / HLR-020 / LLR-020.1, .2).

**R-ISSUES-RELATED-001**: Where a validation issue carries related artifacts, the issues list shall display them in a "Related" column (comma-joined, or `-` when none).
- Code: `s19_app/tui/app.py` `precompute_issue_datatable_payload` Related cell + the issues `add_columns` "Related" header (cell tuple 7→8, kept in lockstep) (US-020b).
- Validation: `Automated` — `tests/test_tui_issues_view.py::test_at021_issues_list_shows_related_artifacts` (AT-021; RED pre-fix: cell shows `-`) + `::test_tc021_precompute_payload_emits_related_cell` + `tests/test_tui_app.py::test_precompute_issue_datatable_payload_emits_eight_columns_and_styles`.
- Status: Added batch-17 (US-020b / HLR-021 / LLR-021.1).

> Deferred to a follow-on batch (`.dev-flow/BACKLOG.md`): US-020c (issues-report addendum input / declared memory locations) + US-020d (issues→report integration).

# 24. Classification legend — report + in-app (batch-18)

> Feature #11: surface the existing classification/colour semantics (REQUIREMENTS.md §3) as a legend in the generated report (Q1) and via an in-app modal reachable from each colour-coded view (Q2). Content derived from ONE non-frozen source; never re-invented. Statements: `.dev-flow/2026-06-26-batch-18/01-requirements.md` §3/§4 (+ §6.5 amendment A1).

**R-LEGEND-SOURCE-001**: The shared classification legend (artifact → classification → colour + meaning, mirroring §3 and `color_policy.SEVERITY_CLASS_MAP`) shall be defined in the non-frozen module `s19_app/tui/legend.py` and consumed by both the report and the in-app modal; it shall NOT be added to the engine-frozen `color_policy.py`.
- Code: `s19_app/tui/legend.py::LEGEND_TABLE` (`:33`) + `COLOUR_SEVERITY` (`:103`) (US-022/US-023, LLR-022.1).
- Validation: `Automated` — `tests/test_tui_legend.py::test_legend_table_covers_all_severities` (TC-S1; anti-drift — every `SEVERITY_CLASS_MAP` severity reachable) + `::test_legend_table_has_documented_artifacts_and_rows` + `::test_legend_data_not_in_frozen_color_policy` (`color_policy.py` diff vs `main` = 0). Frozen guard `tests/test_tui_directionb.py::_ENGINE_PATHS` green.
- Status: Added batch-18.

**R-LEGEND-REPORT-001**: When the operator generates a project report (`include_legend=True`, the default), the report shall include a `## Legend` section listing each artifact's colour→meaning rows read from `LEGEND_TABLE`; `include_legend=False` shall omit it.
- Code: `s19_app/tui/services/report_service.py::_legend_lines` (`:923`) + `ReportOptions.include_legend` (`:192`, domain-validated in `__post_init__`) (US-022, LLR-022.2).
- Validation: `Automated` — `tests/test_report_service.py::test_report_includes_legend_with_documented_rows` (AT-022a; RED pre-fix: no `## Legend`) + `::test_report_omits_legend_when_disabled` (AT-022b, negative) + `::test_legend_lines_renders_shared_table` + `::test_include_legend_default_true_and_validated`.
- Status: Added batch-18 (US-022 / HLR-022).

**R-LEGEND-MODAL-001**: When the operator invokes the legend on a colour-coded view (the `k` key on A2L; the "Legend" button on MAC and Issues), the system shall open a read-only `LegendScreen` modal rendering every `LEGEND_TABLE` row, colourized via `color_policy.css_class_for_severity`, dismissable by Close; the static legend shall show even with no file loaded.
- Code: `s19_app/tui/screens.py::LegendScreen` (`:474`) + `app.py::action_show_legend` (`:3059`), `Binding("k","show_legend")` (`:563`), MAC/Issues buttons (`:2477`/`:1171`), dispatch (`:7511`); `s19_app/tui/styles.tcss` `#legend_dialog`/`#legend_body` (US-023, LLR-023.1/.2).
- Validation: `Automated` — `tests/test_tui_legend.py::test_at023a_a2l_legend_opens_via_key` / `::test_at023b_mac_legend_button_opens` / `::test_at023c_issues_legend_button_opens` / `::test_at023d_close_dismisses_modal` / `::test_at023f_legend_shows_without_file_loaded` (AT-023a–d,f) + `::test_tc023_1_modal_renders_all_table_rows` + `::test_tc023_2_mac_issues_buttons_present_a2l_absent` + `::test_tc_s2_report_and_modal_render_same_rows` (TC-S2 Q1/Q2 anti-drift).
- Status: Added batch-18 (US-023 / HLR-023). §6.5 A1: A2L uses the `k` key (not a button) — the A2L filter row overflows at 80 & 120 cols (C-13 measurement).

**R-LEGEND-GEOMETRY-001**: The legend affordances shall fit the supported terminal regimes: the MAC/Issues "Legend" buttons render fully on-screen at 80 and 120 cols, the A2L view exposes no (clippable) legend button, and the opened modal fits within the terminal.
- Code: `s19_app/tui/styles.tcss` `#legend_dialog { height: 90% }` + `#legend_body { height: 1fr; overflow-y: auto }` (US-023, LLR-023.3 / C-13).
- Validation: `Automated` — `tests/test_tui_legend.py::test_at023e_c13_geometry_at_80_cols` (measured: MAC right=23, Issues=69 ≤80; A2L 0 buttons; modal within 80×30). `Manual` — SVG snapshot baselines for the 3 views + footer regenerate in canonical CI (G-1; never local).
- Status: Added batch-18 (US-023 / HLR-023 / LLR-023.3).

# 25. Issues-report addendum + issue enrichment (batch-19)

> Feature #10 follow-on: enrich the report's validation issues with their address/symbol/related fields (Q1d), and add an operator-declared "expected-zone" addendum that cross-references modifications/issues per declared memory region (Q1c) + persists the regions. Stories: `.dev-flow/2026-06-29-batch-19/01-requirements.md` §3/§4. DoR: A Expected-zone + Both + persist. `ValidationIssue` (validation/, FROZEN) consumed read-only.

**R-RPT-ISSUE-FIELDS-001**: When the report renders a validation issue, it shall append the issue's address (hex, when present), symbol (when set), and related artifacts (when non-empty) to the code/severity/message line; an issue lacking a field shall show no empty placeholder, and `address == 0` shall render `@ 0x0`.
- Code: `s19_app/tui/services/report_service.py::_declaration_error_lines` (~:712) (US-020d, LLR-025.1; reads `ValidationIssue.address/.symbol/.related_artifacts`).
- Validation: `Automated` — `tests/test_report_service.py::test_report_issue_line_shows_address_symbol_related` (AT-025a; RED pre-fix: fields absent) + `::test_report_issue_without_address_has_no_hex` (AT-025b, negative) + `::test_report_issue_address_zero_renders` (TC-025.1 boundary).
- Status: Added batch-19 (US-020d / HLR-025).

**R-RPT-ADDENDUM-001**: The `DeclaredRegion(name,start,end)` model shall scrub + length-cap `name` via `validation.model._scrub_issue_message` at construction and validate `name` non-empty / `start>=0` / `start<=end` (one `ValueError` each); membership is the INCLUSIVE `[start,end]` predicate.
- Code: `s19_app/tui/services/report_addendum.py::DeclaredRegion` (:30) (US-020c, LLR-024.1).
- Validation: `Automated` — `tests/test_report_addendum.py` (membership inclusive; bad bounds; empty/control-only name rejected; name scrubbed of control/ANSI; length-capped — RED pre-fix: scrub bypass lets a newline name survive).
- Status: Added batch-19. **Security**: the region `name` is operator free text reaching the Markdown report + `project.json`; the construction-time scrub (reusing the existing `_scrub_issue_message`) is the injection defense (Phase-2 security-F1).

**R-RPT-ADDENDUM-002**: When the operator declares memory regions for a report, the report shall emit an "Addendum: declared regions" section listing each region and, per region, the modifications and validation issues whose address falls within `[start,end]` (aggregated across variants); a zero-hit region renders "None.". Regions are entered in `ReportViewerScreen` and threaded to `ReportOptions.declared_regions`.
- Code: `report_service.py::_addendum_lines` (:977) + `ReportOptions.declared_regions` (:198); `screens.py::_parse_declared_regions` (:543) + `ReportViewerScreen` TextArea + `GenerateRequested.declared_regions` (:652); `app.py` 4-hop thread → `ReportOptions` (US-020c, LLR-024.2/024.3).
- Validation: `Automated` — `tests/test_report_service.py::test_addendum_lists_region_with_mods_and_issues` (AT-024a) + `::test_addendum_region_with_no_hits_shows_none` (AT-024b) + `::test_addendum_membership_inclusive_at_bounds` (TC-024.4) + `::test_addendum_and_issue_render_use_same_address` (TC-S3 single-source); `tests/test_tui_report_seam.py::test_declared_region_in_dialog_reaches_report_addendum` (AT-024c, true e2e dialog→report file, C-12; RED pre-fix: app threading dropped) + `::test_parse_declared_regions_handles_hex_dec_and_skips_malformed` (TC-024.5) + `::test_report_dialog_with_region_input_fits_80_and_120_cols` (TC-024.6 / C-13 MEASURED PASS).
- Status: Added batch-19 (US-020c / HLR-024).

**R-RPT-ADDENDUM-PERSIST-001**: Declared regions shall persist in `project.json` as an OPTIONAL `declared_regions` array, written only when non-empty (back-compat — no `schema_version` bump); the reader shall return them (absent key → empty), emitting one `MANIFEST-BAD-STRUCTURE` issue for a malformed/invalid entry without aborting, and re-scrubbing each name on read.
- Code: `manifest_writer.py::serialize_manifest`/`write_project_manifest` (optional key); `variant_execution_service.py::_parse_manifest_declared_regions` (:295) + `ProjectManifest.declared_regions` (:201) (US-020c, LLR-026.1).
- Validation: `Automated` — `tests/test_manifest_writer.py::test_declared_regions_roundtrip_and_on_disk` (AT-026a; on-disk project.json + read roundtrip, qa-F4; RED pre-fix: key not written) + `::test_serialize_omits_declared_regions_key_when_empty` (TC-026.1 back-compat) + `::test_read_absent_key_empty_and_malformed_collected` (TC-026.2; absent→empty, malformed→issue, read-path scrub).
- Status: Added batch-19 (US-020c / HLR-026). Serialization layer only; UI auto-wire (save dialog regions / pre-fill on load) deferred to BACKLOG (operator option-1).

> Deferred to BACKLOG: UI region save/load auto-wiring (HLR-026 follow-on); on-screen feedback when the dialog parser skips a malformed region line.

---

# 26. Declared-region UI round-trip + skip notice (batch-20)

> Feature #10 follow-on D-1/D-2: wire batch-19's declared-region **serialization layer** to the Reports dialog UI. D-1 — declared regions persist on project SAVE and pre-fill the dialog on project LOAD (round-trip). D-2 — malformed/invalid region lines surface a count-only skip notice. The batch-19 manifest reader/writer and `DeclaredRegion` model (shipped batch-19) are consumed read-only; frozen-engine diff = 0. Stories: `.dev-flow/2026-06-29-batch-20/01-requirements.md`. All AT/TC in `tests/test_tui_report_seam.py`.

**R-RPT-REGION-PERSIST-001**: On project SAVE the operator's declared regions — captured into app state ON Generate (a region typed but never Generated is not saved) — shall be threaded into `write_project_manifest(declared_regions=...)` and written to `project.json` only when non-empty; a save with no regions remains byte-identical to the pre-batch-20 output (key omitted). The save's verify leg is deliberately not threaded from state (it re-reads from disk).
- Code: `s19_app/tui/app.py::S19TuiApp` — `self._declared_regions` (:713), `GenerateRequested` capture (:1899), `_handle_save_dialog` (:3791) → `_write_and_verify_manifest` (:3802) → `write_project_manifest(declared_regions=)` (:3867) (US-024, HLR-027 / LLR-027.1–027.4). Reuses `manifest_writer.serialize_manifest` (key-omit-when-empty, batch-19).
- Validation: `Automated` — `tests/test_tui_report_seam.py::test_save_persists_declared_regions` (AT-027a; on-disk `project.json`) + `::test_typed_but_not_generated_not_saved` (AT-027b, capture-on-Generate) + `::test_save_without_regions_byte_identical` (AT-027c, back-compat) + `::test_save_threads_declared_regions_to_writer` (TC-027.1) + `::test_write_and_verify_manifest_accepts_declared_regions_default` (TC-027.2) + `::test_empty_regions_omits_key` (TC-027.3).
- Status: Added batch-20 (US-024 / HLR-027). Closes batch-19 BACKLOG D-1 (save leg).

**R-RPT-REGION-PERSIST-002**: On project LOAD the manifest's declared regions shall be adopted into app state (legacy/no-key project → empty, `else ()`, so a prior project's regions never leak), and the next Reports dialog shall pre-fill its `#report_declared_regions` TextArea from that state in the exact inverse format of `_parse_declared_regions`.
- Code: `s19_app/tui/app.py::_handle_load_project` (:3977, adopt + `else ()` reset), `action_view_reports` (:1874, passes seed), `s19_app/tui/screens.py::ReportViewerScreen.__init__` (:667) + `compose` TextArea seed (:691–698) (US-024, HLR-028 / LLR-028.1–028.4). Reuses `variant_execution_service.read_project_manifest` → `ProjectManifest.declared_regions` (read-path name re-scrub, batch-19).
- Validation: `Automated` — `tests/test_tui_report_seam.py::test_load_prefills_declared_regions` (AT-028a, C-12 through-surface GATE — round-trip observed back through the dialog, not a same-values direct write) + `::test_load_seed_guard` (AT-028b, consumer guard — no-key load is empty, no cross-load leak) + `::test_load_sets_declared_regions_state` (TC-028.1) + `::test_seed_format_is_parser_inverse` (TC-028.2).
- Status: Added batch-20 (US-024 / HLR-028). Closes batch-19 BACKLOG D-1 (load leg).

**R-RPT-REGION-SKIP-001**: When the Reports dialog parses declared-region input, malformed (wrong field count) and invalid (failed `int`/`DeclaredRegion` parse) lines shall be skipped and counted (the two sites mutually exclusive per line), blank/whitespace-only lines excluded from the count; on Generate a count-only toast `"N region line(s) skipped"` is shown only when the count ≥ 1 (zero suppresses the notice), and the offending line text is never interpolated (no pre-scrub echo).
- Code: `s19_app/tui/screens.py::_parse_declared_regions` (:543, returns `(regions, skipped)`), `on_button_pressed` notify (:804 / :807–813) (US-025, HLR-029 / LLR-029.1–029.3).
- Validation: `Automated` — `tests/test_tui_report_seam.py::test_skipped_malformed_line_counted` (AT-029a) + `::test_skipped_invalid_line_counted` (AT-029b) + `::test_skipped_count_excludes_blank` (AT-029c) + `::test_all_valid_no_skip_message` (AT-029d) + `::test_parse_returns_skip_count` (TC-029.1) + `::test_zero_skip_suppresses_notify` (TC-029.2) + `::test_parse_declared_regions_handles_hex_dec_and_skips_malformed` (TC-024.5, batch-19 TC rewritten for the `(regions, skipped)` return shape).
- Status: Added batch-20 (US-025 / HLR-029). Closes batch-19 BACKLOG D-2.

> Scoped out (BACKLOG): a region name containing a comma is not representable in the comma-delimited `name,start,end` line format (skipped as malformed); the construction-time scrub neutralizes injection content regardless.

---

# 27. Patch-editor change-file management + Checks clarity (batch-21)

> Feature #8 (patch-editor overhaul), **slice 1**: give the patch editor a durable home for saved change documents and a way to reopen them, plus a one-line explanation of the Checks action. US-027 — change-document saves land in a dedicated global `patches/` folder (was the workarea root; `temp/` is staging-only). US-026 — a `Select` dropdown lists those saved change files (sorted) and loads the selected one via `ChangeService.load`. US-029 — a description Label states what Checks does and which artifact it runs against (button id + `run_checks` action unchanged). Read-path containment guard (F1) hardens the scan/load. Frozen-engine diff = 0. Stories: `.dev-flow/2026-06-29-batch-21/01-requirements.md`. AT/TC in `tests/test_tui_patch_editor_v2.py` + `tests/test_unified_write.py`.

**R-PATCH-SAVE-FOLDER-001**: Change-document saves shall be placed in a dedicated global `.s19tool/workarea/patches/` folder (named by the new `WORKAREA_PATCHES="patches"` constant and created by `ensure_workarea`), never the workarea root; `temp/` remains staging-only. Two distinct saves shall not clobber one another on disk.
- Code: `s19_app/tui/workspace.py::WORKAREA_PATCHES` (:19) + `ensure_workarea` mkdir (:47-48); `s19_app/tui/changes/io.py::write_change_document` placement under `workarea/patches/` (:1354) (US-027, HLR-031 / LLR-031.1–031.2).
- Validation: `Automated` — `tests/test_tui_patch_editor_v2.py::test_at031a_save_doc_lands_in_patches_folder` (AT-031a) + `::test_at031b_two_saves_are_distinct_no_clobber` (AT-031b) + `tests/test_unified_write.py::test_tc031_write_target_resolves_under_patches_folder` (TC-031).
- Status: Added batch-21 (US-027 / HLR-031). Advances feature #8 (patch-editor) slice 1.

**R-PATCH-DOC-DROPDOWN-001**: On patch-screen activation and after each save, a `Select#patch_doc_file_select` dropdown shall list the change files scanned from `patches/` (sorted `.json` set, non-change files ignored, symlink entries skipped); selecting an entry shall load it via `ChangeService.load` after an `is_relative_to(patches/)` read-path containment check. An empty `patches/` shall render a placeholder without crashing, and a change file dropped directly into `patches/` shall be listed and loadable.
- Code: `s19_app/tui/app.py::_scan_patch_change_files` (:2217-2240, sorted + symlink-skip), `_prefill_patch_change_files` (:1428-1431, post-save), load handler + F1 containment (:2315-2322); `s19_app/tui/screens_directionb.py::set_change_files` (:549/:587) → `Select#patch_doc_file_select` (:649), `Select.Changed` handler (:889) (US-026, HLR-030 / LLR-030.1–030.3).
- Validation: `Automated` — `tests/test_tui_patch_editor_v2.py::test_at030a_dropdown_lists_and_loads_selected_change_file` (AT-030a, C-12 through-surface GATE over the handler-produced change file) + `::test_at030a_r2_save_while_open_appears_without_reactivation` (AT-030a-R2) + `::test_at030b_empty_patches_folder_renders_placeholder_no_crash` (AT-030b) + `::test_at030c_directly_dropped_file_is_listed_and_loadable` (AT-030c, consumer guard) + `::test_f1_symlink_entry_is_skipped_by_scan` (F1, security-adversarial) + `tests/test_unified_write.py::test_tc030_scan_returns_sorted_json_set_ignoring_non_change_files` (TC-030).
- Status: Added batch-21 (US-026 / HLR-030). Consumes R-PATCH-SAVE-FOLDER-001's producer output.

**R-PATCH-CHECKS-CLARITY-001**: The patch editor shall render a description Label `#patch_checks_help` under the Checks button reading `"Checks: runs the loaded change document's checks against the loaded image."`, stating both what the action does and which artifact it runs against; the Checks button id (`patch_checks_run_button`) and its `run_checks` action shall be unchanged (text-only clarity, no behavior change).
- Code: `s19_app/tui/screens_directionb.py::#patch_checks_help` Label (:665-670), Checks button `patch_checks_run_button` (:662) + `run_checks` action (:856, UNCHANGED); `s19_app/tui/styles.tcss` Label CSS (:680-685) (US-029, HLR-032 / LLR-032.1–032.2).
- Validation: `Automated` — `tests/test_tui_patch_editor_v2.py::test_at032a_checks_help_states_what_and_which_artifact` (AT-032a) + `::test_at032b_clarity_added_action_wiring_unchanged` (AT-032b).
- Status: Added batch-21 (US-029 / HLR-032).

> Scoped out (BACKLOG, deferred to later patch-editor slices — not gaps): US-028 (inline variant dropdown), US-030 (4-pane split — geometry SPIKE, needs host-width measurement + C-13.1 fallback), US-031 (4-pane geometry snapshots).

---

# 28. Patch-editor 4-pane 2×2 layout (batch-22)

> Feature #8 (patch-editor overhaul), **slice 2**: reorganize the Patch Editor from a single ~12-group vertical scroll into a 2×2 grid of four independently-scrolling area-panes (Entries · Change-file · Checks · Variant), all visible together, with the save-back prompt spanning full width below. View-layer only; frozen-engine diff = 0. Phase-0 measurement de-risked it: measured host content = 70 cols @80 / 92 @120 (batch-21's ~37/~58 estimate was wrong) → a 2×2 (~35/~46 per pane) rather than a cramped 4-across. Stories: `.dev-flow/2026-07-01-batch-22/01-requirements.md`. AT/TC in `tests/test_tui_patch_layout.py` + `tests/test_tui_snapshot.py`.

**R-PATCH-2X2-LAYOUT-001**: The Patch Editor shall lay its four area-panes out as a 2×2 grid — `#patch_pane_entries` (top-left), `#patch_pane_changefile` (top-right), `#patch_pane_checks` (bottom-left), `#patch_pane_variant` (bottom-right) — all visible together, each pane scrolling vertically and independently (`overflow-y: auto; overflow-x: hidden`). `#patch_editor_panel` shall be `layout: grid; grid-size: 2 3` with `grid-rows: 1fr 1fr auto`; the hidden `#patch_saveback_row` shall be a `column-span: 2` grid child in the `auto` third row (full width when shown, zero-height while hidden, panes not squeezed). Each area's pre-existing widget sub-tree is reparented wholesale — every `patch_*` inner id and its action wiring stay queryable. The Change-file control row `#patch_doc_controls` shall be an explicit `layout: grid; grid-size: 3` (Textual `Horizontal` does not wrap → would clip its five buttons) so Load·Validate·Apply·Save·Run-checks flow to two rows within the pane budget. The 2×2 holds at both supported terminal sizes (80×24 floor, 120×30).
- Code: `s19_app/tui/screens_directionb.py::PatchEditorPanel.compose` four-pane reparent + save-back span child; `s19_app/tui/styles.tcss` `#patch_editor_panel` grid, `#patch_pane_*` overflow, `#patch_saveback_row { column-span: 2 }`, `#patch_doc_controls { grid-size: 3 }` (US-030, HLR-033 / LLR-033.1–033.4).
- Validation: `Automated` — `tests/test_tui_patch_layout.py::test_at_033a_two_by_two_at_80_floor` (AT-033a, 80-col floor boundary gate) + `::test_at_033b_two_by_two_at_120` (AT-033b) + `::test_at_033c_reparent_safety_at_80` + `::test_at_033c_reparent_safety_at_120` (AT-033c, reparent-safety) + `::test_tc_pane_styles_and_grid` (TC-033, white-box grid + `grid_size_columns == 3`).
- Status: Added batch-22 (US-030 / HLR-033). Advances feature #8 (patch-editor) slice 2. Frozen-engine diff = 0.

**R-PATCH-2X2-SNAPSHOT-001**: The Patch Editor 2×2 layout shall be pixel-locked by SVG snapshot cells at 80×24 and 120×30 (snapshot matrix 27→28). Because `pytest-textual-snapshot` baselines regenerate only in the canonical CI environment (local regen drifts unrelated baselines), both patch cells ride `xfail(strict=False)` until the CI baseline lands — neither failing the suite nor claiming a pass. The 2×2 is behaviorally proven by `R-PATCH-2X2-LAYOUT-001`'s AT set; this row locks the pixels once the baseline exists.
- Code: `tests/test_tui_snapshot.py` `_SCAFFOLD_CELLS` patch cells (`xfail(strict=False)`), `patch` in `_SCAFFOLD_SCREENS`, `_SIZES` (US-031, HLR-034 / LLR-034.1–034.2).
- Validation: `CI-locked` (xfail-until-baseline) — `tests/test_tui_snapshot.py::test_tc016s_density_layout_snapshot[patch-comfortable-80x24]` (AT-034a) + `::...[patch-comfortable-120x30]` (AT-034b); SKIP-local / xfail-CI until the canonical-CI baseline is regenerated, then flip to `Automated`.
- Status: Added batch-22 (US-031 / HLR-034). Follow-on: regenerate the two `patch-comfortable-*` baselines in CI, confirm green, promote to `Automated`.

---

# 29. Patch-editor inline variant dropdown (batch-23)

> Feature #8 (patch-editor overhaul), **final slice**: switch the project's active variant from a dropdown inside the patch editor's Variant pane without leaving the editor. US-028 — `Select#patch_variant_select` (in `#patch_variant_row`, composed ABOVE `#patch_execute_row` per the C-13 measured 35×3 @80×24 pane budget) lists the project's variants in model order with the active one pre-selected; a pick routes WHOLESALE through the existing `_handle_select_variant` activation pipeline (guards reused, zero new activation logic) and persists only via the existing project-save manifest write (DoR Q2: persist-on-save, no new disk-write surface). Degenerate states (no project / <2 variants) render a present-but-disabled placeholder (DoR Q1). Picks arriving while a load is in flight are suppressed (LLR-035.7, security F2). Frozen-engine diff = 0. Stories: `.dev-flow/2026-07-01-batch-23/01-requirements.md`. AT/TC in `tests/test_tui_patch_variant.py`.

**R-PATCH-VARIANT-SELECT-001**: The patch editor's Variant pane shall host a `Select#patch_variant_select` (always present; `allow_blank=True`, placeholder prompt, disabled at construction) composed above `#patch_execute_row` so the switch affordance renders within the pane's visible region at scroll 0 @80×24. On patch-screen activation and on any variant-set change while the screen is shown, the app shall repopulate it: N ≥ 2 → one `(variant_id, variant_id)` option per variant in `ProjectVariantSet` model order with `value == active_id`; N < 2 or no project → empty options, blank placeholder, `disabled` (no false affordance, no single-id preselection). Picking a concrete non-active variant shall activate it through the existing `_handle_select_variant` pipeline exactly once (blank and same-as-active picks fire no activation — absorbing the `set_options` reset echo); a pick arriving while a prior load is in flight shall be suppressed with a status line (switch-during-load integrity: final label == rendered image's variant, 0 files created in the project dir). The switch shall introduce no disk write; `active_variant` reaches `project.json` exclusively through the existing project-save serialization.
- Code: `s19_app/tui/screens_directionb.py::PatchEditorPanel.VariantSelected` (:538), `set_variants` (:614), compose `#patch_variant_row` + `Select#patch_variant_select` (:797-807), `on_select_changed` variant branch (:1025); `s19_app/tui/app.py::_refresh_patch_variant_select` (:2278), `_variant_load_in_flight` (:2329), `on_patch_editor_panel_variant_selected` (:2366), `action_show_screen` patch-activation hook (:3401), `update_project_labels` variant-set-change hook (:7830); `s19_app/tui/styles.tcss` `#patch_variant_row, #patch_execute_row { height: auto }` (:592) (US-028, HLR-035 / LLR-035.1–035.7).
- Validation: `Automated` — `tests/test_tui_patch_variant.py::test_at035a_dropdown_switch_updates_label_and_image` (AT-035a, C-10 switch-through-surface GATE: rendered label + hex content) + `::test_at035b_switch_persists_on_save_and_load_consumes` (AT-035b, C-12 output-then-consume GATE over the handler-written `project.json`; the direct-write consumer guard stays `tests/test_variant_execution.py::test_load_project_honors_manifest_active_variant`) + `::test_at035c_no_project_disabled_placeholder` / `::test_at035c_single_variant_disabled_placeholder` (AT-035c) + `::test_tc_035_1_compose_presence` (TC-035.1) + `::test_tc_035_2_variant_group_above_execute_row` (TC-035.2, 80×24 + 120×30) + `::test_tc_035_3_options_order_preselection_and_triggers` (TC-035.3) + `::test_tc_035_4_routing_guards` (TC-035.4) + `::test_tc_035_5_disabled_state_table` (TC-035.5) + `::test_tc_035_6_switch_writes_nothing_to_disk` (TC-035.6) + `::test_tc_035_7_rapid_double_pick_stays_consistent` (TC-035.7, security F2).
- Status: Added batch-23 (US-028 / HLR-035). Closes feature #8 (patch-editor overhaul) — last open story. Frozen-engine diff = 0.

---

# 30. A2L red-row ↔ Issues reconcile (batch-24)

> Feature #12(c), **both directions**: the A2L table and the Issues surface must not disagree. **Direction 1** — every red A2L row gains a matching ERROR `ValidationIssue`. Divergence proven at intake: a non-virtual tag with a missing address gets `schema_ok=False` (frozen `tui/a2l.py:1290-1291`) and renders red, while the engine emits `A2L_INVALID_ADDRESS` only for present-but-non-int addresses — red row, zero issues. The fix is a supplemental TUI-side rule at the open seam `validation_service.build_validation_report` (frozen `validation/` and `tui/a2l.py` untouched), plus the LLR-037.4 substrate fix: pre-fix, `update_mac_view` wiped `_validation_report`/`_validation_issues` in EVERY no-MAC session, so S19+A2L sessions ended issue-less regardless of what validation computed. **Direction 2** — a tag whose symbol carries an ERROR-severity A2L issue (e.g. `A2L_DUPLICATE_SYMBOL`) renders red: pre-fix the row-severity function never consulted issues, so duplicate-symbol rows rendered green/normal while the ERROR sat on the Issues surface. Render-side-only fix in `app.py` (severity map + row-severity consult + refresh reorder); issue list content untouched. Stories: `.dev-flow/2026-07-02-batch-24/01-requirements.md`. AT/TC in `tests/test_validation_service_supplemental.py` (direction 1) + `tests/test_tui_a2l_issue_recolor.py` (direction 2).

**R-A2L-ISSUE-RECONCILE-001**: When the validation report is built for a session whose effective A2L tag set contains a tag with `schema_ok is False` (the red-row predicate), the issue list shall carry one ERROR-severity `A2L_TAG_SCHEMA_INCOMPLETE` issue (NEW code; `artifact="a2l"`, symbol/address/reason populated, constructor-scrubbed message) for that tag — unless an ERROR-severity a2l issue for the same casefolded symbol is already collected (dedup key = casefolded symbol × `artifact=="a2l"` × ERROR; symbol-less `A2L_STRUCTURE_ERROR` never suppresses). The merge happens in BOTH `build_validation_report` branches before `dedupe_issues`, only when the effective tag list is non-empty. Raw/un-enriched tags (no `schema_ok` key) gain no issue. Virtual tags with no address are exempt by construction (`schema_ok=True`). Additionally, a no-MAC session WITH a loaded primary shall compute/retain the primary+A2L validation report through `update_mac_view`'s no-MAC branches — routed through the MAC-view cache key with a stable `id(current_file)` substitute for the empty-records identity component (worker-precomputed reports are cache HITS, never wipe-then-recompute) — while sessions with no primary keep the historical clear (LLR-037.4, B-1a).
- Code: `s19_app/tui/services/validation_service.py::supplemental_a2l_row_issues` + both merge points in `build_validation_report` (US-032, HLR-036 / LLR-036.1–036.3); `s19_app/tui/app.py::_refresh_no_mac_validation` + `_mac_view_cache_key_for` + `update_mac_view` no-MAC branches + `_prepare_load_payload` shared key (LLR-037.4).
- Validation: `Automated` — `tests/test_validation_service_supplemental.py::test_at_036a_missing_schema_red_row_has_matching_error_issue` (AT-036a GATE, MAC-less fixture, RED pre-fix: red row + zero rendered issue rows) + `::test_at_036b_already_covered_symbol_gains_no_second_error` (AT-036b dedup) + `::test_at_036c_clean_a2l_yields_zero_supplemental_issues` / `::test_at_036c_empty_tag_set_yields_zero_supplemental_issues` (AT-036c) + `::test_tc_036_1_one_error_per_schema_bad_tag_keyed_on_is_false` (TC-036.1) + `::test_tc_036_2_dedup_casefolded_symbol_a2l_error_only` (TC-036.2) + `::test_tc_036_3_merge_in_both_report_branches` (TC-036.3) + `::test_tc_036_4_nameless_schema_bad_tag_falls_back_to_context` (TC-036.4) + `::test_tc_037_4_worker_path_retains_report_without_mac` / `::test_tc_037_4_sync_path_computes_once_and_caches` / `::test_tc_037_4_no_primary_session_keeps_the_clear` (TC-037.4).
- Status: Added batch-24 (US-032 / HLR-036 + LLR-037.4). Frozen-engine diff = 0.

**R-A2L-ISSUE-RECONCILE-002**: While the current validation issue list contains an ERROR-severity A2L issue carrying a symbol, every A2L table row whose casefolded tag name matches that casefolded symbol shall render with ERROR (red) severity — issue-ERROR overrides every ladder outcome (including memory-checked green), while WARNING never recolours (the A2L palette is Red/Green/White/Grey only; orange is a MAC-view convention). The symbol→max-severity map is built by a pure module-level helper (`_a2l_issue_severity_map`: `artifact=="a2l"` + non-empty symbol only, casefolded keys, ERROR ranked above all) once per render by `update_a2l_tags_view` from `self._validation_issues` and consulted O(1) per row; an issue symbol absent from the rendered tag set is inert (no crash, no row change). For map freshness on the sync-fallback load path, `update_a2l_view`'s A2L-present branch calls `update_mac_view()` AFTER `_compute_a2l_enriched_tags()` (the MAC-view cache consumes `_a2l_enriched_tags`) and BEFORE `_refresh_a2l_filtered_tags` — so duplicate-symbol rows are red on the FIRST rendered frame; the call is idempotent over `_mac_view_cache_key`, adding no recomputation (the worker path was already ordered).
- Code: `s19_app/tui/app.py::_a2l_issue_severity_map` + `_A2L_ISSUE_SEVERITY_RANK` (LLR-037.1), `_a2l_tag_row_severity` map parameter + ERROR-only precedence (LLR-037.2), `update_a2l_tags_view` once-per-render map build, `update_a2l_view` refresh reorder (LLR-037.3) (US-033, HLR-037 / LLR-037.1–037.3).
- Validation: `Automated` — `tests/test_tui_a2l_issue_recolor.py::test_at_037a_duplicate_symbol_error_issue_reds_both_rows` (AT-037a GATE, MAC-less case-variant duplicate fixture, RED pre-fix: both duplicate rows non-red while the `A2L_DUPLICATE_SYMBOL` ERROR rendered) + `::test_at_037b_absent_from_table_issue_symbol_is_inert` (AT-037b, natural `A2L_BROKEN_REFERENCE` absent-symbol boundary) + `::test_tc_037_1_issue_severity_map_build_and_filter_semantics` (TC-037.1) + `::test_tc_037_2_row_severity_precedence_matrix_and_warning_guard` (TC-037.2, incl. the WARNING-no-recolour GUARD over constructed issues) + `::test_tc_037_3_sync_fallback_first_render_is_fresh` (TC-037.3); ladder-only unit set updated in place `tests/test_tui_app.py::test_a2l_tag_row_severity_matches_updated_policy`.
- Status: Added batch-24 (US-033 / HLR-037). Closes feature #12(c) — both reconcile directions shipped. Frozen-engine diff = 0.

---

# 31. Before/after save-back report (batch-24)

> Feature #12(a): one action after apply → save-back writes a report pair proving what changed between the ORIGINAL loaded image and the SAVED patched image. Reuses the batch-09 backbone (`compare_images` fresh-from-disk + `generate_diff_report(_html)` complete reports) with three default-off generator kwargs (provenance header, per-entry change-linkage table, filename stem — default path byte-identical, golden-pinned), a NEW headless composer service, and a notify-offer + key-`b` trigger (C-13 N/A: zero geometry). B-2 provenance: `ChangeSummary.source_image_path` (runtime-only, off `to_dict`) is stamped by `save_patched` beside `saved_path` so a summary surviving a project switch is detected STALE and refused — never a false-provenance report into the wrong project tree. Every failure is a surfaced refusal that writes 0 files. Stories: `.dev-flow/2026-07-02-batch-24/01-requirements.md`. AT/TC in `tests/test_before_after_report.py` + `tests/test_diff_report_service.py` + `tests/test_change_service.py`.

**R-BEFORE-AFTER-REPORT-001**: When a change document has been applied and the patched image saved back successfully (`ChangeSummary.saved_path` stamped), invoking the offered report action (information notify after `_surface_verify_result`, key `b` → `action_before_after_report`) shall write a Markdown + self-contained-HTML report pair under the active project's `reports/` directory — own filename scheme `<UTC ts>(-NN)?-before-after-report.md|.html` (module-owned regex twins; shared/diff regexes untouched) — comparing `LoadedFile.path` (before) against `last_summary.saved_path` (after, the actual post-dedup written path) fresh from disk, containing a before/after provenance header, a per-entry change-linkage table (`before_bytes=None` renders an explicit marker, never fabricated bytes), and `-`/`+` diff lines at each patched address. The composer shall validate five preconditions in order (summary present; `saved_path` stamped; both paths on disk; `loaded.path == summary.source_image_path`; `saved_path` contained in the current project dir/workarea) and shall refuse — one surfaced human-readable diagnostic, 0 files written, app running — on every failure class, including no-active-project (names the manual A↔B path) and a symlinked `reports/` destination. Markdown cells strip control characters and escape `|` (`_strip_ctl`/`_md_cell`); the before/after HTML helpers apply the same `_strip_ctl` so a ctl-bearing symbol renders identically in both formats. The composer imports no Textual symbol and performs no logging; surfaced trigger text carries paths and diagnostics only, never entry byte content.
- Code: `s19_app/tui/services/before_after_service.py::compose_before_after_report` + `BeforeAfterReportResult` + owned filename regexes (LLR-038.2/.4/.5); `s19_app/tui/services/diff_report_service.py::BeforeAfterProvenance` + `provenance`/`linkage_entries`/`filename_stem` kwargs + `_strip_ctl`/`_md_cell`/`_bytes_cell` + `_provenance_lines`/`_linkage_table_lines`/`_html_provenance`/`_html_linkage` (LLR-038.1); `s19_app/tui/changes/model.py::ChangeSummary.source_image_path` + `s19_app/tui/services/change_service.py::save_patched` stamp (B-2); `s19_app/tui/app.py::action_before_after_report` + `Binding("b", ...)` + the save-back offer notify in `on_patch_editor_panel_save_back_decision` (LLR-038.3) (US-034, HLR-038 / LLR-038.1–038.5).
- Validation: `Automated` — `tests/test_before_after_report.py::test_at_038a_saveback_trigger_report_pair_reread_from_surfaced_path` (AT-038a GATE, C-10 collision-dedup drive + C-12 surfaced-path → dir-diff → re-read; RED pre-fix: key `b` unbound → no file, dir-diff assert failed) + `::test_at_038b_declined_saveback_trigger_refuses_and_writes_nothing` (AT-038b) + `::test_at_038c_missing_original_trigger_refuses_and_writes_nothing` (AT-038c) + `::test_at_038d_stale_summary_cross_project_refusal_writes_nothing` (AT-038d, B-2) + `::test_tc_038_3_composer_happy_path_and_regex_ownership` / `::test_tc_038_3_symlink_reports_destination_refused` / `::test_tc_038_3_ctl_symbol_renders_identically_in_md_and_html_pair` (TC-038.3) + `::test_tc_038_4_all_refusal_classes_write_no_files` / `::test_tc_038_4_no_project_refusal_names_manual_ab_path` (TC-038.4) + `::test_tc_038_5_module_imports_no_textual_and_no_logging` (TC-038.5) + `tests/test_diff_report_service.py::test_provenance_and_linkage_render_in_both_formats` / `::test_default_kwargs_output_byte_identical_pre_change_golden` / `::test_zero_entries_linkage_states_no_entries` (TC-038.2) / `::test_pipe_bearing_symbol_md_escaped_html_intact` (TC-038.1/.6) + `tests/test_change_service.py::test_save_patched_stamps_source_image_path` / `::test_save_patched_without_kwarg_leaves_source_image_path_none` / `::test_to_dict_excludes_source_image_path_and_stays_byte_stable` (B-2 stamp).
- Status: Added batch-24 (US-034 / HLR-038). Closes feature #12(a). Frozen-engine diff = 0.
