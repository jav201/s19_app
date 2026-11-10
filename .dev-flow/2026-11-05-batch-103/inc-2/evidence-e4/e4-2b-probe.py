"""Inc 2b E4 probe (runner only, never a test): re-derive V171 shared_with names
through the current parser, and dump C08 / DEFC object facts for exact test bytes."""
import sys, random, tempfile, subprocess
from pathlib import Path
sys.path.insert(0, ".")
sys.path.insert(0, "tools/synth")
import s19_app.tui.a2l_definition as M
from s19_app.tui.a2l_definition import describe_definitions
from s19_app.tui.a2l_parse import parse_a2l_file
from s19_app.tui.a2l import parse_begin_meta
import make_release_case as gen

print("s19_app.__file__ =", __import__("s19_app").__file__)

def spans_overlap(a, alen, b, blen):
    a_last = a + alen - 1
    if blen is None:
        return a <= b <= a_last
    b_last = b + blen - 1
    return a <= b_last and b <= a_last

def rederive(a2l, names):
    tags = {t["name"]: t for t in a2l.get("tags") or []}
    declared = list(a2l.get("declared_spans") or [])
    dit = iter(declared)
    entries = []
    pos = 0
    def walk(nodes):
        nonlocal pos
        for node in nodes:
            nm = node.get("name")
            if nm in ("MEASUREMENT", "CHARACTERISTIC"):
                pname = parse_begin_meta(node.get("meta", "") or "")[0]
                tag = tags.get(pname)
                if tag is not None and tag.get("address") is not None:
                    entries.append((pos, pname, nm, tag.get("address"), tag.get("length")))
            elif nm in ("BLOB", "INSTANCE"):
                span = next(dit, None)
                if span is not None and span.get("address") is not None:
                    entries.append((pos, span["name"], span["kind"], span["address"], span["length"]))
            pos += 1
            walk(node.get("children") or [])
    walk(a2l.get("sections") or [])
    defs = describe_definitions(names, a2l)
    out = {}
    for name in names:
        d = defs[name]
        if d.address is None or d.byte_length is None or d.byte_length < 1:
            out[name] = None
            continue
        my_pos = None
        for (p, n, k, a, l) in entries:
            if n == name and k in ("MEASUREMENT", "CHARACTERISTIC"):
                my_pos = p
                break
        others = sorted((p, n, k, a, l) for (p, n, k, a, l) in entries
                        if p != my_pos and spans_overlap(d.address, d.byte_length, a, l))
        out[name] = others[0][1] if others else None
    return out, defs, entries

V = parse_a2l_file(Path("examples/case_00_public/ASAP2_Demo_V171.a2l"))
targets = [
    "ASAM.C.SCALAR.SWORD.IDENTICAL",
    "ASAM.C.SCALAR.SWORD.LINEAR_MUL_2",
    "ASAM.C.SCALAR.SWORD.TAB_VERB_DEFAULT_VALUE",
    "ASAM.C.SCALAR.SWORD.TAB_VERB_NO_DEFAULT_VALUE",
    "ASAM.C.SCALAR.SWORD.VTAB_RANGE_DEFAULT_VALUE",
    "ASAM.C.SCALAR.SWORD.VTAB_RANGE_NO_DEFAULT_VALUE",
    "ASAM.C.SCALAR.UWORD.IDENTICAL",
    "ASAM.C.SCALAR.UWORD.IDENTICAL.BITMASK_0FF0",
    "ASAM.C.SCALAR.UWORD.IDENTICAL.BITMASK_0001",
    "ASAM.C.SCALAR.UWORD.IDENTICAL.BITMASK_0010",
    "ASAM.C.SCALAR.SBYTE.IDENTICAL",
    "ASAM.C.SCALAR.UBYTE.IDENTICAL",
    "ASAM.M.SCALAR.UBYTE.VTAB_RANGE_NO_DEFAULT_VALUE",
    "ASAM.C.SCALAR.ULONG.IDENTICAL",
    "ASAM.C.DEPENDENT.REF_1.SWORD",
]
sw, defs, entries = rederive(V, targets)
print("== V171 shared_with (re-derived) ==")
for n in targets:
    d = defs.get(n)
    if d is None:
        print(f"{n}: NOT A TAG")
        continue
    addr = d.address
    print(f"{n}  addr={hex(addr) if addr is not None else None} len={d.byte_length} mask={d.bit_mask} refusal={d.refusal.code if d.refusal else None} shared_with={sw.get(n)}")

print("== ASCII tag name (current reader) ==")
for t in V["tags"]:
    if t.get("char_type") == "ASCII" or "ASCII" in (t.get("name") or "") or "UNKNOWN" in (t.get("name") or ""):
        print(f"  name={t['name']!r} addr={t.get('address')} len={t.get('length')} char_type={t.get('char_type')}")

print("== V171 declared_spans ==")
for s in V.get("declared_spans") or []:
    print(" ", s)

print("== V171 entries at 0x13A00 ==")
for (p, n, k, a, l) in sorted(entries):
    if a == 0x13A00:
        print(f"  pos={p} {n} kind={k} len={l}")

folder = Path(tempfile.mkdtemp(prefix="b103e4c08_"))
gen.generate(folder, 20260001, 1.0)
regions = gen.compute_region_sizes(1.0)
objs = gen.build_objects(regions, random.Random(20260001))
print("== C08 objects ==")
def find(conv=None, dt=None, name=None, kind=None):
    for o in objs:
        if name and o["name"] != name: continue
        if conv and o["conversion"] != conv: continue
        if dt and o["datatype"] != dt: continue
        if kind and o["kind"] != kind: continue
        return o
    return None
for label, kw in [
    ("VALUE_0019 UWORD LIN_OFF", dict(conv="CM_LIN_OFF", dt="UWORD")),
    ("VALUE_0004", dict(name="VALUE_0004")),
    ("MEAS_0002", dict(name="MEASUREMENT_0002")),
    ("MEAS_0001", dict(name="MEASUREMENT_0001")),
    ("VALUE_0002", dict(name="VALUE_0002")),
    ("VALUE_0001", dict(name="VALUE_0001")),
]:
    o = find(**kw)
    if o:
        print(f"  {label}: name={o['name']} dt={o['datatype']} addr=0x{o['address']:X} be={o['big_endian']} bytes={o['raw_bytes'].hex()} phys={o['physical']} low={o['low']} high={o['high']}")

folder2 = Path(tempfile.mkdtemp(prefix="b103e4defc_"))
r = subprocess.run([sys.executable, "tools/synth/make_release_case.py", "--out", str(folder2), "--seed", "20260001", "--case", "definitions"], capture_output=True, text=True)
print("== DEFC CLI rc ==", r.returncode)
_regions, dobjs = gen.build_definition_objects(random.Random(20260001))
print("== DEFC objects ==")
for o in dobjs:
    keys = ("name","section","kind","datatype","conversion","address","length","big_endian","bit_mask","planned_stored","planned_text","low","high")
    print("  ", {k: o.get(k) for k in keys if k in o})
# the generated word at 0x800010
s19 = (folder2 / "definitions.s19").read_text()
print("== DEFC 0x800010 region word ==")
a2l = parse_a2l_file(folder2 / "definitions.a2l")
from s19_app.core import S19File
mem = S19File(str(folder2 / "definitions.s19")).get_memory_map()
print("  mem[0x800010..11] =", hex(mem[0x800010]), hex(mem[0x800011]), "word", hex((mem[0x800010]<<8)|mem[0x800011]))
