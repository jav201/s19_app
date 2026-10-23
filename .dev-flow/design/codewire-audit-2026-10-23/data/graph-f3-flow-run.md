# Code-Wire graph F3: flow run SOURCE → PATCH → CRC → CHECK → WRITE-OUT → REPORT, and the chain-set lane path (data audit, reverse)

> Format B, Code-Wire v2.6. Reverse direction from `s19_app` `9793fcd`. Node name = code qualname.
> Reuses the structure of the pilot graph `piloto-s19-parche/grafo-parche.md` (v2.4, `b6c5ec2`). Re-derived on the current code: the 11 pilot nodes still exist with the same signatures; CRC, CHECK, REPORT and the chain-set nodes are new here. The pilot thread used `prg.s19`, the one example with no S0 record, so it could not show I-H-1.
> Thread T3: `cwaudit/test_t3_flow.py` (recorded: `trace-t3.json`). Data: project `P` = `examples/case_01_basic_valid/firmware.s19` + `firmware.a2l`; `patch.json` = entry 1 `0x80000050` `DE AD` (inside range `0x80000040..0x80000080`), entry 2 `0x80000100` `01` (outside every range); CRC region `0x80000040..0x80000070` → slot `0x8000007C`; check `0x80000000` = `53 31 39 54` ("S19T"). Chain set: lane A = `patch.json` → `a.s19`, lane B = a doc with only the outside entry → `b.s19`, parallel.

## Nodes

run_flow
req: R-TUI-059, LLR-085.2, LLR-086.4, LLR-087.2, LLR-089.2, LLR-143.1
in: Flow flow; FlowContext ctx
out: FlowRunResult result {status, block_results, change_records, refusals, written_paths}
func: runs the blocks in order on one working image; each block appends a BlockResult; the run rolls up a status
module: s19_app/tui/services/flow_execution_service.py
inner: build_loaded_s19, read_change_document, apply_change_document, check_regions, inject_crcs, run_check_document, save_patched_image, compose_flow_report
examples: (T3, t3a) flow "t3" → result {status "ok", block_results [source "loaded firmware.s19 (3 ranges)", patch "applied 1 entry", crc "injected 1 CRC region", check "passed=1 failed=0 uncheckable=0", write_out "wrote out.s19"]}

apply_change_document
req: R-CHG-002, LLR-002.1, LLR-143.1
in: ChangeDocument document; Dict[int, int]? mem_map; Sequence[Tuple[int, int]]? ranges; Sequence[dict]? mac_records; Sequence[dict]? a2l_tags; (Callable) (->datetime)? now_fn = None; str? variant_id = None
out: ChangeSummary summary {counts, entries}
func: applies each entry inside the image and classifies the rest; mem_map changes in place
module: s19_app/tui/changes/apply.py
modify: mem_map (replace)
examples: (T3, t3a) entries 2 of 2 → summary {counts {applied `1`, skipped-outside `1`}, entries [{address_start `2147483728`, disposition "applied"}, {address_start `2147483904`, disposition "skipped-outside"}]}

inject_crcs
req: LLR-089.3, LLR-090.1
in: OperationInput op_input; list[CrcRegionResult] crc_regions
out: tuple(dict[int, int] mem_map, list[tuple[int, int]] ranges, list[CrcRegionResult] written)
func: writes each computed CRC into a working copy and grows the ranges when the slot is outside
module: s19_app/tui/operations/crc.py
examples: (T3, t3a) → written [{output_address `2147483772`, computed_crc `2344078287`, stored_value `1061043516`, written True}]; ranges keep [`0`, `12`] (the phantom S0 range)

save_patched_image
req: LLR-002.7, LLR-015.3, R-MAN-WRITE-001
in: Dict[int, int] mem_map; Sequence[Tuple[int, int]] ranges; Path dest_dir; str filename; str source_kind; int bytes_per_line = 32; bytes? s0_header = None
out: tuple(Path? saved_path, List[ValidationIssue] issues)
func: emits, stages at `temp/<name>`, places with containment and dedup
module: s19_app/tui/changes/apply.py
modify: [I/O: out.s19] (replace)
examples: (T3, t3a) filename "out.s19"; source_kind "s19" → saved_path ".../workarea/P/out.s19"

compose_flow_report
req: LLR-001.1, LLR-001.2, AMD-8
in: FlowReportState state; datetime generated_at
out: str markdown
func: the flow report: status, ledger, change attribution (applied records only), footprint, written files. Paths are made relative (AMD-8)
module: s19_app/tui/services/flow_report_service.py
examples: (T3, t3a) → markdown with "**Status:** CLEAN", "| 2 | PATCH | ● ok | applied 1 entry |", "0x80000050 | 2 | 10 11 | DE AD", "**Before CRC:** 0x00000000–0x0000000C"; no line for 0x80000100

run_chain_set
req: HLR-019, LLR-019.2, LLR-020.2
in: Sequence[ChainSpec] chains; FlowContext ctx; str mode = 'sequential'; str set_name = 'chain-set'; (Callable) (Flow, FlowContext)->FlowRunResult? run_one = None; (Callable) (->float)? clock = None
out: ChainSetRunRecord record {mode, outcomes, report_path}
func: runs one flow per lane (parallel in a thread pool) and keeps one ChainRunOutcome per lane
module: s19_app/tui/services/flow_execution_service.py
inner: run_flow, compose_chain_set_report
examples: (T3, t3b) chains [laneA, laneB]; mode "parallel" → record {outcomes [{chain "laneA", status "ok"}, {chain "laneB", status "ok", block_results with "applied 0 entries"}]}

compose_chain_set_report
req: LLR-020.1, LLR-020.2
in: ChainSetRunRecord record; str set_name; datetime generated_at
out: str markdown
func: the chain-set report: ledger and input provenance per lane
module: s19_app/tui/services/flow_execution_service.py
examples: (T3, t3b) → markdown with "| 2 | laneB | t | ✓ ok | 3 |", «[bound] path=» and «AppData/Local/Temp» (an absolute host path; C16 turns each backslash into a slash), and no written file name

## Entities

[I/O: firmware.s19]
in: str
desc: the project source image (case_01)

[I/O: patch.json]
in: bytes
desc: the change document of the thread

[I/O: out.s19]
in: str
desc: the image the WRITE-OUT block writes

[I/O: flow report]
in: str
desc: `reports/<ts>-report.md`

[I/O: chain-set report]
in: str
desc: `reports/<ts>-chainset.md`

## Edges

[I/O: firmware.s19] ──▶ run_flow.ctx
[I/O: patch.json] ──▶ apply_change_document.document
run_flow ──▶ apply_change_document.mem_map
apply_change_document.mem_map ──▶ inject_crcs.op_input
inject_crcs.mem_map ──▶ save_patched_image.mem_map
save_patched_image ──▶ [I/O: out.s19]
apply_change_document.summary ──▶ run_flow.result
run_flow.result ──▶ compose_flow_report.state
compose_flow_report.markdown ──▶ [I/O: flow report]
run_chain_set ──▶ run_flow.flow
run_flow.result ──▶ run_chain_set.record
run_chain_set.record ──▶ compose_chain_set_report.record
compose_chain_set_report.markdown ──▶ [I/O: chain-set report]

## Boundary

[Outside: Flow Builder run key] ──▶ run_flow.flow
[Outside: Flow Execution panel] ──▶ run_chain_set.chains
discarded: inject_crcs.written — the block summary keeps only the count

## Findings

CW-D-11
anchor: apply_change_document.summary ──▶ run_flow.result
what: the PATCH status does not come from the summary (known I-H-2); the run record keeps the dispositions but the lane outcome and both reports drop them (known I-H-10)
evidence: T3 t3a summary skipped-outside `1` → block "applied 1 entry" ok, report "Status: CLEAN" with no 0x80000100 line; T3 t3b laneB "applied 0 entries" → "✓ ok"

CW-D-12
anchor: compose_chain_set_report.markdown ──▶ [I/O: chain-set report]
what: the chain-set report writes absolute host paths. The flow report, a second writer of the same kind of record, redacts them by rule AMD-8
evidence: T3 t3b "path=`C:\Users\…\Temp\…\workarea\P\firmware.s19`"; T3 t3a flow report shows only "out\.s19"
consequence: a shareable record discloses the host user name and folder layout. LLR-020.2 says only "record the input files"; AMD-8 was not carried to the second report writer
