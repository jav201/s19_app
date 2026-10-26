# ADAPTED for batch-99: the flow now writes nothing when PATCH errors; that case is printed, probe logic otherwise unchanged.
"""P06: (a) A2L physical->raw encode (the Patch Editor symbol picker's write
path) under MOD_COMMON BYTE_ORDER MSB_FIRST; (b) a change doc mixing good
address entries with one refused symbol entry, run through the flow."""
from common import *
from s19_app.tui.a2l import parse_a2l_file
from s19_app.tui.services.change_service import resolve_symbol_entry
import inspect
src = (EX / "case_03_overlapping_records" / "firmware.a2l").read_text()
a2l_text = src.replace("VALUE 0x80020000 RL_U8 0 CM_IDENT 0 255", "VALUE 0x80020000 RL_U16 0 CM_IDENT 0 65535")
d = Path(tempfile.mkdtemp()); (d / "be.a2l").write_text(a2l_text)
a2l = parse_a2l_file(d / "be.a2l")
tag = next(t for t in a2l["tags"] if t["name"] == "OVER_A")
print("OVER_A: datatype/length/effective_byte_order =", tag.get("datatype"), tag.get("length"), tag.get("effective_byte_order"))
print("resolve_symbol_entry signature:", inspect.signature(resolve_symbol_entry))
res = resolve_symbol_entry("OVER_A", "4113", a2l)
print("encode physical 4113 (0x1011) ->", bytes(res.entry.encoded_bytes).hex() if res.entry else None, "issues:", [i.message for i in res.issues],
      "| expected MSB_FIRST bytes: 1011")

# (b) flow: two in-image entries + one unresolved symbol entry -> whole doc blocked
from s19_app.tui.services.flow_model import Flow, FlowContext, SourceBlock, PatchBlock, WriteOutBlock
from s19_app.tui.services.flow_execution_service import run_flow
proj = new_project()
doc = {"format": "s19app-changeset", "version": "2.0", "kind": "change", "encoding": "utf-8", "value_mode": "text",
       "entries": [{"type": "bytes", "address": "0xEB10", "bytes": "DE AD"},
                   {"type": "bytes", "address": "0xEB40", "bytes": "01"},
                   {"type": "bytes", "address": "0xEC00", "bytes": "FF", "symbol": "NO_SUCH"}]}
(proj / "mixed.json").write_text(json.dumps(doc))
r = run_flow(Flow(name="m", blocks=[SourceBlock("prg.s19"), PatchBlock("mixed.json"), WriteOutBlock("m.s19")]), FlowContext(project_dir=proj))
pb = r.block_results[1]
mem, _, _ = (mini_s19(r.written_paths[0]) if r.written_paths else (print("NO FILE WRITTEN (flow stopped):", r.status, [(b.kind, b.status, b.summary) for b in r.block_results]) or ({}, None, None))); srcm, _, _ = mini_s19(proj / "prg.s19")
print("mixed doc: run =", r.status, "| patch =", pb.status, pb.summary, "| dispositions =", [c.disposition for c in r.change_records],
      "| refusals =", [x.code for x in r.refusals], "| file changed bytes =", sum(1 for a in srcm if mem.get(a) != srcm[a]))

# (c) COMPU_TAB inversion: a physical value absent from a TAB_NOINTP table, and
# one outside a TAB_INTP table's range — written silently as a different value?
from s19_app.tui.a2l import encode_physical_to_raw_bytes
tag = {"name": "T", "char_type": "VALUE", "datatype": "UBYTE", "length": 1, "compu_method_name": "CM", "effective_byte_order": "little"}
tab = {"TAB": {"entries": [(0, 0.0), (1, 10.0), (2, 20.0)]}}
for ctype, phys in (("TAB_NOINTP", 13.0), ("TAB_NOINTP", 10.0), ("TAB_INTP", 500.0), ("TAB_INTP", -50.0)):
    cm = {"CM": {"conversion_type": ctype, "compu_tab_ref": "TAB"}}
    raw, err, flags = encode_physical_to_raw_bytes(tag, phys, cm, tab, {})
    print(f"{ctype} physical {phys:>6} -> raw {bytes(raw).hex() if raw else None} (decodes back to {dict((x, y) for x, y in tab['TAB']['entries']).get(raw[0]) if raw else None}) err={err} flags={flags}")
