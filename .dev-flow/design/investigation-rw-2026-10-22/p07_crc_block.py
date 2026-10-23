"""P07: flow CRC block — a region with NO image bytes, a region spanning a gap,
and an output slot outside the image: what does the block report, and what is
written?"""
from common import *
from s19_app.tui.services.flow_model import Flow, FlowContext, SourceBlock, PatchBlock, CrcBlock, WriteOutBlock
from s19_app.tui.services.flow_execution_service import run_flow
proj = new_project()
write_doc(proj / "p.json", [(0xEB10, (1, 2, 3, 4))])
cfgs = {
    "region_no_bytes": [{"start": "0x00020000", "end": "0x00030000", "output_address": "0x0000EB20"}],
    "region_over_gap": [{"start": "0x0000EB00", "end": "0x0000EB10", "output_address": "0x0000EB20"}],
    "slot_outside_image": [{"start": "0x0000EB08", "end": "0x0000EB18", "output_address": "0x00030000"}],
}
for name, regions in cfgs.items():
    (proj / f"{name}.json").write_text(json.dumps({"polynomial": "0x04C11DB7", "init": "0xFFFFFFFF", "reverse": True, "final_xor": "0xFFFFFFFF", "regions": regions}))
    r = run_flow(Flow(name=name, blocks=[SourceBlock("prg.s19"), PatchBlock("p.json"), CrcBlock(f"{name}.json"), WriteOutBlock(f"{name}.s19")]), FlowContext(project_dir=proj))
    cb = r.block_results[2]
    mem, errs, _ = mini_s19(r.written_paths[0]) if r.written_paths else ({}, [], {})
    out = int(regions[0]["output_address"], 16)
    print(f"{name:20s} run={r.status:22s} crc={cb.status}:{cb.summary!r} findings={[f.message for f in cb.findings]} slot_bytes={bytes(mem.get(out + i, 0) for i in range(4)).hex()} out_ranges_tail={[(hex(a),hex(b)) for a,b in ranges_of(mem)][-2:]}")
