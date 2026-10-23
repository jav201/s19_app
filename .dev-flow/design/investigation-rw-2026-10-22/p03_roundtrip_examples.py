"""P03: identity round-trip of every example image through the flow
(SOURCE -> WRITE-OUT, no patch) as S19 and as HEX; compare the written file,
parsed by an INDEPENDENT minimal parser, against the source's data records
(also parsed independently)."""
from common import *
from s19_app.core import S19File
from s19_app.hexfile import IntelHexFile
from s19_app.tui.services.flow_model import Flow, FlowContext, SourceBlock, WriteOutBlock
from s19_app.tui.services.flow_execution_service import run_flow

srcs = sorted(EX.glob("**/*.s19"))
for s in srcs:
    proj = new_project(src=s, dst_name="in.s19")
    src_mem, src_errs, src_meta = mini_s19(proj / "in.s19")
    for fmt in ("s19", "hex"):
        flow = Flow(name="rt", blocks=[SourceBlock("in.s19"), WriteOutBlock(f"out.{fmt}", fmt=fmt)])
        r = run_flow(flow, FlowContext(project_dir=proj))
        if not r.written_paths:
            print(f"{s.relative_to(EX)} {fmt}: NOT WRITTEN status={r.status} {[b.summary for b in r.block_results]}")
            continue
        out = r.written_paths[0]
        if fmt == "s19":
            mem, errs, meta = mini_s19(out)
            reload = S19File(str(out)).get_memory_map()
        else:
            mem, errs = mini_hex(out); meta = {}
            reload = dict(IntelHexFile(str(out)).memory)
        extra = sorted(set(mem) - set(src_mem)); missing = sorted(set(src_mem) - set(mem))
        changed = [a for a in src_mem if a in mem and mem[a] != src_mem[a]]
        flag = "OK " if not (extra or missing or changed) else "BAD"
        print(f"{flag} {str(s.relative_to(EX)):48s} {fmt} run={r.status:22s} src_bytes={len(src_mem)} out_bytes={len(mem)} extra={len(extra)}"
              f"{'@'+hex(extra[0])+'..'+hex(extra[-1]) if extra else ''} missing={len(missing)} changed={len(changed)} out_errs={errs[:2]}"
              + (f" src_term={src_meta['term']} out_term={meta.get('term')}" if fmt=='s19' else ""))
