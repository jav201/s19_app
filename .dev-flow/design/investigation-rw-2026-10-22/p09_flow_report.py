"""P09: the flow REPORT file for a patch with one applied + one dropped entry,
and for a malformed change doc: does the report name what was NOT applied?"""
from common import *
import re
from s19_app.tui.services.flow_model import Flow, FlowContext, SourceBlock, PatchBlock, WriteOutBlock, ReportBlock
from s19_app.tui.services.flow_execution_service import run_flow
proj = new_project()
write_doc(proj / "mix.json", [(0xEB10, (0xDE, 0xAD)), (0x20000, (1, 2, 3, 4))])
(proj / "bad.json").write_text("{nope")
for doc in ("mix.json", "bad.json"):
    r = run_flow(Flow(name=doc, blocks=[SourceBlock("prg.s19"), PatchBlock(doc), WriteOutBlock("o.s19"), ReportBlock()]), FlowContext(project_dir=proj))
    rep = max((proj / "reports").glob("*.md"), key=lambda f: f.stat().st_mtime_ns).read_text(encoding="utf-8")
    print(f"=== {doc}: run={r.status}; report mentions 0x20000/20000: {bool(re.search('0x0*20000|20000', rep, re.I))}; mentions skipped/outside: {bool(re.search('skip|outside', rep, re.I))}; mentions MF-JSON-PARSE/refus: {bool(re.search('MF-JSON|refus', rep, re.I))}")
    for line in rep.splitlines():
        if line.strip() and not line.startswith("|---"):
            print("   ", line[:140])
print("report files:", sorted(x.name for x in (proj / "reports").glob("*.md")))
for f in sorted((proj / "reports").glob("*.md")):
    print(f.name, "->", f.read_text(encoding="utf-8").splitlines()[0])
