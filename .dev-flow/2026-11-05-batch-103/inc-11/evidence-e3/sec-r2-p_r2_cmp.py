"""E3 round-2 security probe (Inc 11), runner only: for the corpus tags where the round-2 model and the e07fb00
reader give two different integer addresses or lengths, print the RELATION CLASS only (no name, no address, no
file text): is the base address the model address with digits glued after it (the comment-glue class), does the
model's length equal base x the MATRIX_DIM product (D4) or the datatype x ARRAY_SIZE (D7), and which size keywords
the tag carries. Files are read as bytes, never copied."""
import sys, hashlib, collections, runpy
sys.argv = ["p_r2_model.py", "none"]
M = runpy.run_path("/tmp/b103-e3r2-11-S/scripts/p_r2_model.py")
sys.path.insert(0, "/home/javiergr/work/s19_app")
from pathlib import Path
from s19_app.tui import a2l as A
rel = collections.Counter(); seen = set()
for f in sorted(Path("/home/javiergr/a2l-corpus/files").iterdir()):
    raw = f.read_bytes(); sha = hashlib.sha256(raw).hexdigest()
    if sha in seen or raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        continue
    seen.add(sha)
    r = M["read"](raw.decode("utf-8", errors="replace"))
    d = A.parse_a2l_file(f)
    base = collections.defaultdict(list)
    for t in d["tags"]:
        base[(t.get("section"), t.get("name"))].append(t)
    occ = collections.Counter()
    for t in r["tags"]:
        key = (t["section"], t["name"]); i = occ[key]; occ[key] += 1
        if i >= len(base.get(key, [])):
            continue
        b = base[key][i]
        ba, ma = b.get("address"), t["address"]
        if isinstance(ba, int) and isinstance(ma, int) and ba != ma:
            hb, hm = f"{ba:X}", f"{ma:X}"
            cls = "base = model + glued digits" if hb.startswith(hm) and len(hb) > len(hm) else (
                "model = base + glued digits" if hm.startswith(hb) else "other")
            rel[("address", t["section"], cls, "base>32bit" if ba > 0xFFFFFFFF else "base<=32bit")] += 1
        bl, ml = b.get("length"), t["length"]
        if isinstance(bl, int) and isinstance(ml, int) and bl != ml:
            kws = tuple(sorted({w for w, _ in t.get("_kw", [])})) if t.get("_kw") else ()
            ratio = ml / bl if bl else None
            rel[("length", t["section"], t["kind"], f"model/base={ratio:.3g}" if ratio else "base=0", b.get("matrix_dim"))] += 1
for k, v in sorted(rel.items(), key=lambda kv: -kv[1]):
    print(f"[CMP] {v} x {k}")
