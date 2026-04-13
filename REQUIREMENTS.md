# S19 File Requirements

This document captures functional requirements for reading, parsing, and
validating S19, Intel HEX, and TUI helper behavior. Each requirement is mapped
to the implementing code and its current validation state:

- `Automated`: covered by one or more `pytest` tests in `tests/`
- `Partial`: some behavior is automated, but UI integration or wording still
  requires manual confirmation
- `Manual`: no stable automated check is currently in place

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

## Validation

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

## TUI

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

**R-TUI-003**: The TUI layout must expose tiles for work area files (top left),
data sections with validity coloring (top middle), a hex view (right, full
height), and reserved empty tiles (bottom left/right).

- Code: `s19_app/tui/app.py` (`S19TuiApp.CSS`, `S19TuiApp.compose`)
- Validation: `Manual` (visual inspection)

**R-TUI-004**: The hex view must display decoded bytes from the selected
file in a readable hex+ASCII layout.

- Code: `s19_app/tui/hexview.py` (`render_hex_view`, `render_hex_view_text`)
- Validation: `Automated` via `tests/test_tui_helpers.py`
  (`test_render_hex_view_includes_focus_context`,
  `test_render_hex_view_truncates_output`) and
  `tests/test_tui_hexview.py` (`test_render_hex_view_text_highlights_match_range`)

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

**R-TUI-007**: The hex view should provide context around a focused address
and truncate large outputs safely.

- Code: `s19_app/tui/hexview.py` (`render_hex_view`, `_collect_hex_rows`)
- Validation: `Automated` via `tests/test_tui_helpers.py`
  (`test_render_hex_view_includes_focus_context`,
  `test_render_hex_view_truncates_output`) and
  `tests/test_tui_hexview.py` (`test_collect_hex_rows_reports_missing_focus_address`)

**R-TUI-008**: Users must be able to open the workarea in the OS file
explorer from the TUI.

- Code: `s19_app/tui/app.py` (`action_open_workarea`)
- Validation: `Manual` (trigger the action in the TUI on the target OS)

**R-TUI-009**: Selecting a data section should jump the hex view to the
section start address.

- Code: `s19_app/tui/app.py` (`_jump_to_section`, `update_hex_view`)
- Validation: `Manual` (select a section in the running TUI)

**R-TUI-010**: The hex view must be scrollable and occupy the full right
column height.

- Code: `s19_app/tui/app.py` (`S19TuiApp.CSS`, `S19TuiApp.compose`)
- Validation: `Manual` (scroll and resize the running TUI)

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

**R-DOC-001**: The TUI module must include high-level documentation and
key method docstrings to aid maintenance.

- Code: `s19_app/tui/__init__.py`, `s19_app/tui/app.py`
- Validation: `Automated` via `tests/test_tui_helpers.py`
  (`test_tui_module_has_docstring`, `test_tui_app_has_docstring`)

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
