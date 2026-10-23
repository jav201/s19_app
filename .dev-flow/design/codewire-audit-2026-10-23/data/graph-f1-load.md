# Code-Wire graph F1: load S19 / MAC / A2L into the in-memory image and tags (data audit, reverse)

> Format B, Code-Wire v2.6 (`code-wire` main `dd39f91`). Reverse direction: the graph comes from the code at `s19_app` `9793fcd` (worktree `s19_app-cwaudit-data`). The node name is the code qualname.
> Thread T1: `cwaudit/test_t1_load.py` (recorded: `trace-t1.json`). Data: `examples/case_01_basic_valid` (`firmware.s19` line 1 `S00F00004341534530315F4241534943B2`, `firmware.mac` line 2 `BLOCK_A=80000000`), `case_03_overlapping_records`, and `case_01` cut after line 5 of 9. Thread line of interest: the S0 record and the first S3 record.
> `req:` ids: `REQUIREMENTS.md` (the living canon) or `.dev-flow/<batch>/01-requirements.md`. `to trace` = no requirement found.

## Nodes

S19File.__init__
req: R-READ-001, R-PARSE-001, LLR-122.1
in: S19File self; str path; str? endian = None
out: S19File s19
func: parses each S-record line, keeps per-record errors, does not abort. Does not require a terminator or check an S5 count
module: s19_app/core.py
examples: (T1, t1a) path ".../case_01_basic_valid/firmware.s19" → s19 record 1 of 9 {type "S0", address `0`, raw_line "S00F00004341534530315F4241534943B2"}; record 2 {type "S3", address 0x80000000}
examples: (T1, t1b) path ".../firmware_cut.s19" (lines 1 to 5 of 9, no S7) → s19 with no error and no terminator record

build_mem_map_s19
req: LLR-122.1, R-S19-S0HEADER-001
in: S19File s19
out: Dict[int, int] mem_map
func: folds the data of every record into one address map. The S0 record is folded too (address 0)
module: s19_app/render/hexview.py
examples: (T1, t1a) s19 (S0 data CASE01_BASIC) → mem_map 0x0: 0x43, 0x1: 0x41, 0x80000000: 0x53; the S0 text is data at address zero

S19File.get_memory_ranges
req: LLR-122.1
in: S19File self
out: List[tuple[int, int]] ranges
func: contiguous ranges of the same folded map
module: s19_app/core.py
examples: (T1, t1a) → ranges [[`0`, `12`], [`2147483648`, `2147483681`], [`2147483712`, `2147483776`]] (3 ranges; the case_01 README says two used ranges)
examples: (T1, t1b) → last range ends at `2147483728` (0x80000050), the cut tail is absent with no error

build_loaded_s19
req: LLR-015.2, LLR-066.5, R-S19-S0HEADER-001
in: Path path; S19File s19; Path? a2l_path; dict? a2l_data
out: LoadedFile loaded {mem_map, ranges, errors, source_s0_header, entry_point}
func: builds the render snapshot: map, ranges, validity, entropy, S0 header, terminator address
module: s19_app/tui/services/load_service.py
examples: (T1, t1a) path ".../firmware.s19" → loaded {source_s0_header "CASE01_BASIC", entry_point 0x80000000, errors []}
examples: (T1, t1b) path ".../firmware_cut.s19" → loaded {errors [], entry_point None}; nothing says the file is cut

parse_mac_file
req: to trace
in: Path path
out: dict[str, Any] mac_data {records, diagnostics}
func: parses `NAME=ADDRESS` lines into records with an address
module: s19_app/tui/mac.py
examples: (T1, t1e) path ".../firmware.mac" → records 2 of 2: {raw "; Synthetic MAC", parse_ok False}, {name "BLOCK_A", address 0x80000000, parse_ok True}

S19TuiApp._load_mac_file
req: to trace
in: S19TuiApp self; Path path; list[Path]? a2l_files = None
out: LoadedFile loaded
func: builds a MAC-only snapshot. Its mem_map has one placeholder byte `0` at each MAC address
module: s19_app/tui/app.py
modify: [Data: S19TuiApp.current_file] (replace)
examples: (T1, t1e) path ".../temp/firmware.mac" → loaded {file_type "mac", mem_map 0x80000000: 0x0, ranges []}

S19TuiApp._merge_primary_with_existing_mac
req: LLR-066.7, LLR-005.6
in: S19TuiApp self; LoadedFile primary_loaded
out: LoadedFile merged
func: copies the MAC and the A2L of the current session onto a newly loaded primary image
module: s19_app/tui/app.py
examples: (T1, t1d) primary_loaded {path ".../temp/other.s19" (case_02)} with current MAC "firmware.mac" (case_01) → merged keeps mac_records {name "BLOCK_A", address 0x80000000}; the status line names only other.s19

S19TuiApp._parse_loaded_file
req: R-TUI-013, LLR-066.7
in: S19TuiApp self; Path path; list[Path]? a2l_files = None
out: LoadedFile? loaded
func: dispatches on the suffix to the S19, HEX or MAC branch, and takes `current_a2l_path` when no A2L comes with the call
module: s19_app/tui/app.py
inner: build_loaded_s19, S19TuiApp._merge_primary_with_existing_mac, S19TuiApp._load_mac_file
examples: (T1, t1d) path ".../temp/firmware.s19" → loaded {file_type "s19", mem_map 0x0: 0x43}

parse_a2l_file
req: R-A2L-001
in: Path path
out: dict a2l_data {sections, tags, compu_methods_by_name}
func: parses the A2L text into sections, tags and the side tables
module: s19_app/tui/a2l.py
inner: extract_a2l_tags
examples: (T1, t1d) path ".../temp/firmware.a2l" (case_01, `BYTE_ORDER MSB_FIRST`) → a2l_data with section "PROJECT"

_apply_compu_method
req: to trace
in: Any raw_value; dict? method; dict[str, dict] compu_tables_by_name
out: tuple(Any physical, str status, str message)
func: raw to physical by the COMPU_METHOD kind (see F4)
module: s19_app/tui/a2l.py
examples: (T1, t1d) raw_value `3`; method {name "CM_IDENT", conversion_type "IDENTICAL", unit "%6.2"} → physical `3`, status "ok"; the A2L line 32 declares an empty unit, the method carries the format text as its unit

## Entities

[I/O: S19 file]
in: str
desc: the S19 text the operator loads (thread: case_01 firmware.s19)

[I/O: MAC file]
in: str
desc: the MAC text (thread: case_01 firmware.mac)

[Data: S19TuiApp.current_file]
in: LoadedFile?
desc: the in-memory image of the session. Every writer reads it (F2, F5, F6)
sequence:
  loadS19: _parse_loaded_file → _merge_primary_with_existing_mac → _apply_prepared_load wins
  loadMacAlone: _load_mac_file → _apply_prepared_load wins (mem_map = MAC placeholders)
  loadOtherS19: _merge_primary_with_existing_mac (!) reads the old MAC and A2L → _apply_prepared_load wins

## Edges

[I/O: S19 file] ──▶ S19File.__init__.path
S19File.__init__.s19 ──▶ build_mem_map_s19.s19
S19File.__init__.s19 ──▶ build_loaded_s19.s19
build_mem_map_s19 ──▶ build_loaded_s19
S19File.get_memory_ranges ──▶ build_loaded_s19
build_loaded_s19.loaded ──▶ S19TuiApp._merge_primary_with_existing_mac.primary_loaded
[Data: S19TuiApp.current_file] ──▶ S19TuiApp._merge_primary_with_existing_mac
S19TuiApp._merge_primary_with_existing_mac.merged ──▶ S19TuiApp._parse_loaded_file
[I/O: MAC file] ──▶ parse_mac_file.path
parse_mac_file.mac_data ──▶ S19TuiApp._load_mac_file
S19TuiApp._parse_loaded_file.loaded ──▶ [Data: S19TuiApp.current_file]

## Boundary

[Outside: Load file dialog] ──▶ S19TuiApp._parse_loaded_file
discarded: parse_a2l_file.a2l_data — the A2L route is outside this slice (the tags feed F4)
discarded: _apply_compu_method.physical — the tag view is outside this slice

## Findings

CW-D-1
anchor: build_mem_map_s19 ──▶ build_loaded_s19
what: the S0 header bytes become image data at 0x0 (`3` ranges for case_01, README says two)
evidence: T1 t1a mem_map 0x0: 0x43 ("C" of "CASE01_BASIC")
consequence: known I-H-1. The graph shows each downstream writer that reads this map (F2 save-back, F3 WRITE-OUT, F5 project via disk copy, F6 Split range_00)

CW-D-2
anchor: S19TuiApp._merge_primary_with_existing_mac
what: a plain Load file of a different image keeps the MAC and the A2L of the previous image. The status names only the new file
evidence: T1 t1d: case_02 other.s19 carries case_01 BLOCK_A 0x80000000 (outside case_02 ranges); status "Loaded other.s19"
consequence: extends P-H-2 (same root, now on the Load file route with no project). No requirement says when a new primary keeps or drops the MAC

CW-D-3
anchor: S19File.__init__
what: a cut file loads with no error and no terminator
evidence: T1 t1b errors [] entry_point None, range ends 0x80000050
consequence: known I-H-8. `entry_point` None is already computed and could flag it
