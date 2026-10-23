"""P13: consequence of the S0-as-data load: a patch aimed at address 0x0 of an
image whose data lives at 0x80000000 is reported APPLIED (into the header
bytes), and the written file carries a data record at 0x0."""
from common import *
from s19_app.tui.services.flow_model import Flow, FlowContext, SourceBlock, PatchBlock, WriteOutBlock
from s19_app.tui.services.flow_execution_service import run_flow
proj = new_project(src=EX / "case_01_basic_valid" / "firmware.s19", dst_name="fw.s19")
write_doc(proj / "zero.json", [(0x0, (0xAA, 0xBB))])
r = run_flow(Flow(name="z", blocks=[SourceBlock("fw.s19"), PatchBlock("zero.json"), WriteOutBlock("z.s19")]), FlowContext(project_dir=proj))
mem, _, meta = mini_s19(r.written_paths[0])
print("run:", r.status, [(b.kind, b.status, b.summary) for b in r.block_results], [c.disposition for c in r.change_records])
print("written file: S0 =", meta["s0"], "| data record at 0x0..0xB =", bytes(mem[a] for a in range(0, 12)))
print("source file has data at 0x0?", 0 in mini_s19(proj / "fw.s19")[0])
