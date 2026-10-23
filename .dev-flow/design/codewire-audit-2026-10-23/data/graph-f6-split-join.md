# Code-Wire graph F6: Split / Join / Export from the in-memory image (data audit, reverse)

> Format B, Code-Wire v2.6. Reverse direction from `s19_app` `9793fcd`. Node name = code qualname.
> Thread T6: `cwaudit/test_t6_split.py` (recorded: `trace-t6.json`). Data: `examples/case_01_basic_valid/firmware.s19` (rows of the `ranges` tab) and `case_01/firmware.mac` alone (a MAC-only session, one Manual row `0x80000000-0x8000000F`). The rows are built as the window builds them (`segment_split_view.py:1125-1130`, `:181-210`). The window's `action_export` calls the same `write_split_join_export` with `zero_coverage_empty=True` (`:1627-1637`).

## Nodes

build_plan
req: LLR-136.1, LLR-136.6, LLR-135.5
in: List[SegRow] rows; set sel; List[Tuple[int, int]] src; Dict[int, int] mem_map; str mode; str gap; str stem; str ext; int? pad_byte = None
out: Plan plan {files, packed, empty_files, guard}
func: plans the export from the source ranges `src`: bytes per file, empty files, the span guard. The confirm gate reads it
module: s19_app/tui/segment_split_view.py
examples: (T6, t6b) rows [{name "locality_00", base 0x80000000, size `16`}]; src []; mem_map 0x80000000: 0x0 → plan {files [{label "firmware_locality_00.s19", packed `0`, empty True}]}

write_split_join_export
req: LLR-136.5, LLR-136.6, HLR-137
in: Dict[int, int] mem_map; List[SegRow] rows; str mode; str gap; int pad_byte; str fmt; str stem; Path dest_dir; bool zero_coverage_empty = False
out: List[Path] written
func: writes one file per row (split) or one joined file, from `mem_map`. A row is empty only when no `mem_map` key is inside it
module: s19_app/tui/segment_split_view.py
modify: [I/O: export file] (replace)
inner: fill_range, join_concat, emit_image
examples: (T6, t6a) mem_map of case_01 (with 0x0: 0x43); rows range_00 to range_02 → written [".../splits/firmware_range_00.s19", ".../firmware_range_01.s19", ".../firmware_range_02.s19"]
examples: (T6, t6b) mem_map 0x80000000: 0x0; rows [locality_00] → written [".../splits/firmware_locality_00.s19"]

fill_range
req: LLR-137.3
in: dict[int, int] mem_map; int start; int end; int pad_byte; str intra_gap
out: tuple(dict[int, int] planned_map, list[tuple[int, int]] planned_ranges)
func: the bytes of one file span, with pad only inside the span
module: s19_app/segment_ops.py
examples: (T6, t6a) start `0`; end `12` → planned_map 0x0: 0x43 … 0xb: 0x43

emit_image
req: LLR-137.2, R-HEX-EMIT-001
in: dict[int, int] mem_map; list[tuple[int, int]] ranges; str fmt
out: str text
func: S19 / HEX / BIN text from a map. No S0 header and no entry point are passed in
module: s19_app/segment_ops.py
examples: (T6, t6a) mem_map 0x0: 0x43 … (12 bytes); ranges [[`0`, `12`]] → text "S0030000FC" / "S10F00004341534530315F4241534943B2" / "S9030000FC"
examples: (T6, t6b) mem_map 0x80000000: 0x0 → text with "S306800000000079" (one data byte 0x00)

## Entities

[Data: S19TuiApp.current_file]
in: LoadedFile?
desc: the in-memory image; the window reads `mem_map` (the writer) and `ranges` (the plan)

[I/O: export file]
in: str
desc: files under `splits/` (common or project)

## Edges

[Data: S19TuiApp.current_file] ──▶ build_plan.src
[Data: S19TuiApp.current_file] ──▶ write_split_join_export.mem_map
write_split_join_export ──▶ fill_range.mem_map
fill_range.planned_map ──▶ emit_image.mem_map
emit_image.text ──▶ [I/O: export file]
build_plan.plan ──▶ write_split_join_export
when: build_plan.plan

## Boundary

[Outside: Split window rows] ──▶ build_plan.rows
[Outside: Split window rows] ──▶ write_split_join_export.rows
discarded: write_split_join_export.written — the status line names the files

## Findings

CW-D-7
anchor: build_plan.plan ──▶ write_split_join_export
what: the plan and the writer read two different sources. The plan reads `ranges` (empty for a MAC-only session). The writer reads `mem_map` (one placeholder byte per MAC address). The confirm says the file is empty; the file gets a fabricated byte
evidence: T6 t6b plan {packed 0, empty True}; written line "S306800000000079" = 0x00 at 0x80000000; the MAC never declared a value
consequence: a silent fabricated byte in a written image. LLR-136.6 says the confirmed empty file is "header-only for S19/HEX"; the code writes a data record. Req ↔ code mismatch

CW-D-8
anchor: emit_image
what: every split or join file loses the source S0 header and the entry point (S0 empty, terminator address 0)
evidence: T6 t6a range_01 file "S0030000FC" … "S70500000000FA"; source entry 0x80000000, S0 "CASE01_BASIC"
consequence: extends I-M-1 (terminator) to a third writer; the S0 drop is new on this path

CW-D-9
anchor: fill_range
what: the `ranges` tab offers the phantom S0 range as row range_00; Split exports the header text as an image
evidence: T6 t6a firmware_range_00.s19 holds "S10F00004341534530315F4241534943B2" (CASE01_BASIC at 0x0)
consequence: a consequence of I-H-1 in a new sink
