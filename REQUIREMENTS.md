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
