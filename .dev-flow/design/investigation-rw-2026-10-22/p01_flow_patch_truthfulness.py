"""P01: does run_flow's PATCH block status reflect entries NOT applied?"""
from common import *
from s19_app.core import S19File
from s19_app.tui.services.flow_model import Flow, FlowContext, SourceBlock, PatchBlock, WriteOutBlock
from s19_app.tui.services.flow_execution_service import run_flow

proj = new_project()
img = S19File(str(proj / "prg.s19")).get_memory_ranges()
print("prg.s19 ranges:", [(hex(a), hex(b)) for a, b in img])
end = img[-1][1]
cases = {
    "outside_0x20000": [(0x20000, (1, 2, 3, 4))],
    "straddle_end": [(end - 2, (0xAA, 0xBB, 0xCC, 0xDD))],
    "one_in_one_out": [(0xEB10, (0xDE, 0xAD)), (0x20000, (1,))],
    "kind_check_not_change": None,
    "v1_legacy": "v1",
    "malformed_json": "bad",
}
for name, entries in cases.items():
    p = proj / f"{name}.json"
    if entries is None:
        write_doc(p, [(0xEB10, (1, 2))], kind="check")
    elif entries == "v1":
        p.write_text(json.dumps({"format": "s19app-unified-changeset", "parameters": [], "memory": [{"address": "0xEB10", "bytes": "DE AD"}]}))
    elif entries == "bad":
        p.write_text('{"format": "s19app-changeset", "version": "2.0", "entries": [ {"type":"bytes"')
    else:
        write_doc(p, entries)
    flow = Flow(name=name, blocks=[SourceBlock("prg.s19"), PatchBlock(p.name), WriteOutBlock(f"out_{name}.s19")])
    r = run_flow(flow, FlowContext(project_dir=proj))
    pb = r.block_results[1]
    disp = [c.disposition for c in r.change_records]
    print(f"{name:24s} run={r.status:22s} patch={pb.status}:{pb.summary!r} dispositions={disp} refusals={[x.code for x in r.refusals]} wrote={[x.name for x in r.written_paths]}")
