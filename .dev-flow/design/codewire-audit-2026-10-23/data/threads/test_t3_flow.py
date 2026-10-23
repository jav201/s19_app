"""T3 threads: flow run SOURCE -> PATCH -> CRC -> CHECK -> WRITE-OUT -> REPORT on case_01, then a
two-lane chain set, to the run record and both reports (Code-Wire data audit)."""
import json
import re

from cwh import C1, new_base, new_project, mini_s19, out


def _doc(path, entries, kind="change"):
    from s19_app.tui.changes.model import ChangeDocument, ChangeEntry
    from s19_app.tui.changes.io import serialize_change_document
    doc = ChangeDocument(format="s19app-changeset", version="2.0", kind=kind, encoding="utf-8",
                         value_mode="text",
                         entries=[ChangeEntry(entry_type="bytes", address=a, encoded_bytes=tuple(b)) for a, b in entries])
    path.write_bytes(serialize_change_document(doc))


def _project():
    base = new_base()
    proj = new_project(base, "P", [C1 / "firmware.s19", C1 / "firmware.a2l"])
    # entry 1 inside range 0x80000040..0x80000080; entry 2 outside every range
    _doc(proj / "patch.json", [(0x80000050, (0xDE, 0xAD)), (0x80000100, (0x01,))])
    _doc(proj / "check.chk.json", [(0x80000000, (0x53, 0x31, 0x39, 0x54))], kind="check")
    (proj / "crc.json").write_text(json.dumps({
        "polynomial": "0x04C11DB7", "init": "0xFFFFFFFF", "reverse": True, "final_xor": "0xFFFFFFFF",
        "regions": [{"start": "0x80000040", "end": "0x80000070", "output_address": "0x8000007C"}]}))
    return proj


def test_t3a_flow_case01():
    from s19_app.tui.services.flow_model import (Flow, FlowContext, SourceBlock, PatchBlock, CrcBlock,
                                                 CheckBlock, WriteOutBlock, ReportBlock)
    from s19_app.tui.services.flow_execution_service import run_flow
    proj = _project()
    flow = Flow(name="t3", blocks=[SourceBlock("firmware.s19"), PatchBlock("patch.json"), CrcBlock("crc.json"),
                                   CheckBlock("check.chk.json"), WriteOutBlock("out.s19"), ReportBlock()])
    r = run_flow(flow, FlowContext(project_dir=proj))
    out("T3a-run", status=r.status, blocks=[(b.kind, b.status, b.summary) for b in r.block_results])
    out("T3a-records", dispositions=[(hex(c.address_start), c.disposition) for c in r.change_records],
        refusals=[x.code for x in r.refusals], written=[p.name for p in r.written_paths])
    mem, _, meta = mini_s19(proj / "out.s19")
    out("T3a-file", at_0x80000050=bytes(mem.get(0x80000050 + i, 0) for i in range(2)).hex(" "),
        crc_slot=bytes(mem.get(0x8000007C + i, 0) for i in range(4)).hex(" "),
        phantom_0x0=bytes(mem.get(i, 0) for i in range(6)), s0=meta["s0"], term=meta["term"])
    rep = max((proj / "reports").glob("*.md"), key=lambda f: f.stat().st_mtime_ns).read_text(encoding="utf-8")
    hdr = [l for l in rep.splitlines() if re.search(r"Status|0x80000100|80000100|skipped|PATCH|CRC|CHECK", l)]
    out("T3a-report", lines=hdr[:10])


def test_t3b_chain_set_two_lanes():
    from s19_app.tui.services.flow_model import Flow, FlowContext, SourceBlock, PatchBlock, WriteOutBlock
    from s19_app.tui.services.flow_execution_service import run_chain_set, ChainSpec, CHAIN_RUN_PARALLEL
    proj = _project()
    _doc(proj / "lane_b.json", [(0x80000100, (0x02,))])   # outside every range: nothing applies
    specs = [
        ChainSpec(name="laneA", template="t", flow=Flow(name="a", blocks=[SourceBlock("firmware.s19"),
                  PatchBlock("patch.json"), WriteOutBlock("a.s19")])),
        ChainSpec(name="laneB", template="t", flow=Flow(name="b", blocks=[SourceBlock("firmware.s19"),
                  PatchBlock("lane_b.json"), WriteOutBlock("b.s19")])),
    ]
    rec = run_chain_set(specs, FlowContext(project_dir=proj), mode=CHAIN_RUN_PARALLEL)
    for o in rec.outcomes:
        out("T3b-lane", chain=o.chain, status=o.status, blocks=[(b.kind, b.status, b.summary) for b in o.block_results],
            written=[p.name for p in o.written_paths], has_records=hasattr(o, "change_records"))
    text = rec.report_path.read_text(encoding="utf-8") if rec.report_path else ""
    out("T3b-report", lines=[l for l in text.splitlines() if "lane" in l.lower() or "status" in l.lower()][:8],
        names_written="a.s19" in text)
