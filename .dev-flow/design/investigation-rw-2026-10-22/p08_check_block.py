"""P08: flow CHECK block — expectations outside the image (uncheckable), a
malformed check doc, and a kind=change doc used as a check doc."""
from common import *
from s19_app.tui.services.flow_model import Flow, FlowContext, SourceBlock, CheckBlock
from s19_app.tui.services.flow_execution_service import run_flow
proj = new_project()
write_doc(proj / "outside.chk.json", [(0x20000, (1, 2))], kind="check")
write_doc(proj / "mismatch.chk.json", [(0xEB10, (0x99, 0x99))], kind="check")
(proj / "bad.chk.json").write_text("{oops")
write_doc(proj / "change_as_check.json", [(0xEB10, (0x99, 0x99))], kind="change")
for name in ("outside.chk.json", "mismatch.chk.json", "bad.chk.json", "change_as_check.json"):
    r = run_flow(Flow(name="c", blocks=[SourceBlock("prg.s19"), CheckBlock(name)]), FlowContext(project_dir=proj))
    cb = r.block_results[1]
    print(f"{name:22s} run={r.status:22s} check={cb.status}:{cb.summary!r} findings={[f.message for f in cb.findings]} diag={cb.diagnostics[:1]}")
