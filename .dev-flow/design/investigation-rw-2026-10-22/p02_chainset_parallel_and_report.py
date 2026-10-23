"""P02: chain-set run — (a) parallel lanes with the same WRITE-OUT name race on the
shared staging file; (b) rerun dedup leaves a stale out.s19; (c) the chain-set
report and ChainRunOutcome for a lane whose change doc is malformed."""
from common import *
from s19_app.core import S19File
from s19_app.tui.services.flow_model import Flow, FlowContext, SourceBlock, PatchBlock, WriteOutBlock
from s19_app.tui.services.flow_execution_service import run_chain_set, ChainSpec, CHAIN_RUN_PARALLEL, run_flow

proj = new_project()
src = S19File(str(proj / "prg.s19")).get_memory_map()
# 8 lanes, each patches a distinct marker at 0xEB10 then writes the SAME output name
specs = []
for i in range(8):
    write_doc(proj / f"lane{i}.json", [(0xEB10, (0xA0 + i,) * 4)])
    specs.append(ChainSpec(name=f"lane{i}", template="t", flow=Flow(name=f"l{i}", blocks=[
        SourceBlock("prg.s19"), PatchBlock(f"lane{i}.json"), WriteOutBlock("same.s19")])))
mismatch = 0
for trial in range(5):
    for f in proj.glob("same*.s19"):
        f.unlink()
    rec = run_chain_set(specs, FlowContext(project_dir=proj), mode=CHAIN_RUN_PARALLEL)
    for o in rec.outcomes:
        want = 0xA0 + int(o.chain[4:])
        if not o.written_paths:
            print(f"trial{trial} {o.chain}: status={o.status} NO FILE blocks={[ (b.status,b.summary,b.diagnostics) for b in o.block_results][-1]}")
            continue
        p = o.written_paths[0]
        mem, errs, _ = mini_s19(p)
        got = mem.get(0xEB10)
        if got != want:
            mismatch += 1
            print(f"trial{trial} {o.chain}: status={o.status} claims {p.name} but file holds marker {got:#x} (expected {want:#x})")
print("parallel mismatches:", mismatch, "files now:", sorted(f.name for f in proj.glob('same*.s19')))

# (b) rerun with a different patch: name dedup
for f in proj.glob("same*.s19"):
    f.unlink()
r1 = run_flow(specs[0].flow, FlowContext(project_dir=proj))
r2 = run_flow(specs[1].flow, FlowContext(project_dir=proj))
print("rerun:", r1.block_results[-1].summary, "|", r2.block_results[-1].summary, "| status", r2.status)
m0, _, _ = mini_s19(proj / "same.s19")
print("same.s19 now holds marker", hex(m0[0xEB10]), "(stale: from the first run)")

# (c) malformed change doc lane in a chain set — what does the report say?
(proj / "bad.json").write_text("{not json")
bad = ChainSpec(name="badlane", template="t", flow=Flow(name="bad", blocks=[SourceBlock("prg.s19"), PatchBlock("bad.json"), WriteOutBlock("bad_out.s19")]))
rec = run_chain_set([bad], FlowContext(project_dir=proj))
o = rec.outcomes[0]
print("ChainRunOutcome fields:", [f for f in o.__slots__] if hasattr(o, '__slots__') else vars(o).keys())
print("outcome status:", o.status, [(b.kind, b.status, b.summary) for b in o.block_results])
print("--- chain-set report ---"); print(rec.report_path.read_text(encoding="utf-8"))
