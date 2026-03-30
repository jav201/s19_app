# S19 File Requirements

This document captures functional requirements for reading, parsing, and
validating S19 files and maps each requirement to the implementing code
and corresponding tests.

## Reading

**R-READ-001**: The loader must read an S19 file line-by-line and ignore
empty lines.

- Code: `s19_app/core.py` (`S19File._load`)
- Tests: `tests/test_core_srecord_validation.py` (`test_s19file_collects_errors`)

## Parsing

**R-PARSE-001**: Each non-empty line must start with `S` and include a
supported record type.

- Code: `s19_app/core.py` (`SRecord.__init__`)
- Tests: `tests/test_core_srecord_validation.py` (`test_srecord_length_mismatch_raises`)

**R-PARSE-002**: The byte count must be valid hex and the line length must
match the declared byte count.

- Code: `s19_app/core.py` (`SRecord.__init__`)
- Tests: `tests/test_core_srecord_validation.py`
  (`test_srecord_length_mismatch_raises`)

**R-PARSE-003**: The address field must be valid hex and fit the address
length for the record type.

- Code: `s19_app/core.py` (`SRecord.__init__`)
- Tests: `tests/test_core_srecord_validation.py` (`test_srecord_valid_line`)

**R-PARSE-004**: The data field length must match the byte count and all
data bytes must be valid hex.

- Code: `s19_app/core.py` (`SRecord.__init__`)
- Tests: `tests/test_core_srecord_validation.py`
  (`test_srecord_invalid_data_hex_raises`)

**R-PARSE-005**: The checksum field must be valid hex.

- Code: `s19_app/core.py` (`SRecord.__init__`)
- Tests: `tests/test_core_srecord_validation.py` (`test_srecord_valid_line`)

## Validation

**R-VAL-001**: The parsed record must validate byte count and checksum
according to the S-record specification.

- Code: `s19_app/core.py` (`SRecord._validate`, `SRecord._calculate_checksum`)
- Tests: `tests/test_core_srecord_validation.py`
  (`test_srecord_checksum_mismatch_invalid`)

**R-VAL-002**: The loader must record validation failures with line numbers
and error details without aborting the load.

- Code: `s19_app/core.py` (`S19File._load`)
- Tests: `tests/test_core_srecord_validation.py` (`test_s19file_collects_errors`)

## TUI

**R-TUI-001**: The application must create a work area for file operations
at startup if it does not already exist.

- Code: `s19_app/tui.py` (`ensure_workarea`)
- Tests: Manual (TUI startup)

**R-TUI-002**: Loading a `.s19` or `.hex` file must copy the file into the
work area before parsing.

- Code: `s19_app/tui.py` (`copy_into_workarea`, `load_selected_file`)
- Tests: Manual (TUI load action)

**R-TUI-003**: The TUI layout must expose tiles for work area files (top left),
data sections with validity coloring (top middle), a hex view (right, full
height), and reserved empty tiles (bottom left/right).

- Code: `s19_app/tui.py` (CSS layout, `S19TuiApp.compose`)
- Tests: Manual (visual inspection)

**R-TUI-004**: The hex view must display decoded bytes from the selected
file in a readable hex+ASCII layout.

- Code: `s19_app/tui.py` (`render_hex_view`)
- Tests: Manual (load and inspect file)

**R-TUI-005**: The loader must resolve relative paths against the app
working directory and the repo root.

- Code: `s19_app/tui.py` (`resolve_input_path`, `find_repo_root`)
- Tests: `tests/test_tui_helpers.py`
  (`test_resolve_input_path_prefers_base_dir`,
  `test_resolve_input_path_falls_back_to_repo_root`)

**R-TUI-006**: The workarea copy should avoid name collisions by creating
unique filenames when needed.

- Code: `s19_app/tui.py` (`copy_into_workarea`)
- Tests: `tests/test_tui_helpers.py`
  (`test_copy_into_workarea_creates_unique_names`)

**R-TUI-007**: The hex view should provide context around a focused address
and truncate large outputs safely.

- Code: `s19_app/tui.py` (`render_hex_view`)
- Tests: `tests/test_tui_helpers.py`
  (`test_render_hex_view_includes_focus_context`,
  `test_render_hex_view_truncates_output`)

**R-TUI-008**: Users must be able to open the workarea in the OS file
explorer from the TUI.

- Code: `s19_app/tui.py` (`action_open_workarea`)
- Tests: Manual (press `O` in TUI)

**R-TUI-009**: Selecting a data section should jump the hex view to the
section start address.

- Code: `s19_app/tui.py` (`_jump_to_section`, `update_hex_view`)
- Tests: Manual (select section in TUI)

**R-TUI-010**: The hex view must be scrollable and occupy the full right
column height.

- Code: `s19_app/tui.py` (CSS `#hex_panel`, `#hex_scroll`, `compose`)
- Tests: Manual (scroll and resize)

**R-TUI-011**: Loaded files must be copied into a temporary folder within
the workarea.

- Code: `s19_app/tui.py` (`WORKAREA_TEMP`, `ensure_workarea`, `load_from_path`)
- Tests: Manual (load and verify `.s19tool/workarea/temp`)

**R-TUI-012**: Saving a project must copy the loaded file into a
workarea subfolder named by a sanitized project name.

- Code: `s19_app/tui.py` (`SaveProjectScreen`, `sanitize_project_name`,
  `action_save_project`, `copy_into_workarea`)
- Tests: `tests/test_tui_helpers.py`
  (`test_sanitize_project_name_allows_safe_chars`,
  `test_sanitize_project_name_strips_invalid_chars`,
  `test_sanitize_project_name_rejects_empty`)

**R-TUI-013**: Loading a project must list all project folders in the
workarea except for the temp folder and load the selected project file.

- Code: `s19_app/tui.py` (`LoadProjectScreen`, `list_projects`,
  `action_load_project`, `_handle_load_project`)
- Tests: `tests/test_tui_helpers.py`
  (`test_list_projects_ignores_temp`)

**R-TUI-014**: Each project must contain at most one S19/HEX data file and
at most one A2L file.

- Code: `s19_app/tui.py` (`validate_project_files`)
- Tests: `tests/test_tui_helpers.py`
  (`test_validate_project_files_allows_single_data_and_a2l`,
  `test_validate_project_files_rejects_multiple_data`,
  `test_validate_project_files_rejects_multiple_a2l`)

**R-TUI-015**: The TUI must log actions to a rotating log file under
`.s19tool/logs` with a maximum size of 5 MB.

- Code: `s19_app/tui.py` (`setup_logging`, `ensure_workarea`)
- Tests: `tests/test_tui_helpers.py`
  (`test_setup_logging_creates_log_handler`,
  `test_setup_logging_uses_rotating_file_handler`)

**R-A2L-001**: The tool must parse A2L files into a minimal JSON-friendly
structure capturing sections and parse errors.

- Code: `s19_app/tui.py` (`parse_a2l_file`)
- Tests: `tests/test_tui_helpers.py`
  (`test_parse_a2l_file_captures_sections`,
  `test_parse_a2l_file_reports_unclosed_section`)

**R-A2L-002**: The A2L view tile must display parsed A2L content in a readable
summary and show parse errors if present.

- Code: `s19_app/tui.py` (`render_a2l_view`, `update_a2l_view`)
- Tests: `tests/test_tui_helpers.py`
  (`test_render_a2l_view_shows_sections`,
  `test_render_a2l_view_shows_errors`)

**R-A2L-003**: The tool must allow exporting parsed A2L data to JSON via a
keyboard binding.

- Code: `s19_app/tui.py` (`action_dump_a2l_json`)
- Tests: Manual (press `J` in TUI)

**R-A2L-004**: The tool must allow loading an A2L file and show its parsed
content in the A2L view.

- Code: `s19_app/tui.py` (`LoadA2LScreen`, `load_a2l_from_path`,
  `update_a2l_view`)
- Tests: Manual (press `A` in TUI and load `.a2l`)

**R-PROJ-001**: Saving a project must persist both the loaded data file
and the loaded A2L file into the project folder when available.

- Code: `s19_app/tui.py` (`_handle_save_dialog`)
- Tests: Manual (save project with data + A2L loaded)

**R-PROJ-002**: If a project is active, loading a data or A2L file later
must copy it into the corresponding project folder (respecting limits).

- Code: `s19_app/tui.py` (`_sync_loaded_file_to_project`,
  `_sync_loaded_a2l_to_project`, `load_from_path`, `load_a2l_from_path`)
- Tests: Manual (save project, then load files)

**R-TUI-016**: The status tile must display the active project name and
the loaded A2L filename.

- Code: `s19_app/tui.py` (`update_project_labels`, status labels)
- Tests: Manual (load/save project, load A2L)
