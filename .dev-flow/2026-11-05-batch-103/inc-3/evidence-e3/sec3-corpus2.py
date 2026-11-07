"""E3 security probe, Inc 3a (batch-103), follow-up over the same files: derived data only (file number, kind,
shape, counts; no third-party names). The largest element counts, the datatypes of every NO_AXIS_PTS component in a
readable layout of an array, curve or map, and the forms of the FIX_AXIS parameter words.
Usage: sec3-corpus2.py worker <file> | sec3-corpus2.py main <list file>
"""
import json, os, subprocess, sys
from collections import Counter

TREE = "/home/javiergr/work/b103-int2a"


def worker(path):
    sys.path.insert(0, TREE)
    sys.path.insert(1, "/tmp/b103-e3-3-security")
    import s19_app.tui.a2l as a
    import m3a
    m3a.bind(a)
    from pathlib import Path
    data = a.parse_a2l_file(Path(path))
    maps = m3a.build_maps(data)
    secs = m3a.object_sections(data)
    big, cdt, fixform = [], Counter(), Counter()
    done = set()
    for tag in data.get("tags") or []:
        nm = tag.get("name")
        ss = secs.get(nm) or []
        if len(ss) != 1 or nm in done or not m3a.is_array_kind(tag, ss[0]):
            continue
        done.add(nm)
        r = m3a.describe_array(tag, ss[0], data, maps)
        kind = "MEASUREMENT" if tag.get("section") == "MEASUREMENT" else tag.get("char_type")
        big.append((r["element_count"] or 0, kind, list(r["shape"]), r["byte_length"], r["refusal"]))
        if tag.get("section") == "CHARACTERISTIC":
            lname = (m3a.flat([ss[0].get("meta") or ""] + (ss[0].get("lines") or [])) + [None] * 5)[4]
            rl = m3a.read_record_layout(lname, data, nm)
            if isinstance(rl, dict):
                for c in rl["components"]:
                    if c[0].startswith("NO_AXIS_PTS"):
                        cdt[c[2] if len(c) > 2 else "(none)"] += 1
        for ax in ss[0].get("children") or []:
            if ax.get("name") != "AXIS_DESCR":
                continue
            w = m3a.flat(ax.get("lines") or [])
            for kw in ("FIX_AXIS_PAR", "FIX_AXIS_PAR_DIST"):
                if kw in w:
                    i = w.index(kw)
                    vals = w[i + 1:i + 3]
                    integral = all((m3a.whole(v.lstrip("-")) is not None) for v in vals)
                    fixform[f"{kw} {'integer words' if integral else 'other words'}"] += 1
    big.sort(reverse=True)
    print(json.dumps({"file": os.path.basename(path), "big": big[:3], "cdt": dict(cdt), "fixform": dict(fixform)}))


def main(listfile):
    files = [ln.strip() for ln in open(listfile) if ln.strip()]
    from concurrent.futures import ThreadPoolExecutor

    def one(f):
        p = subprocess.run([sys.executable, "-I", __file__, "worker", f], capture_output=True, text=True, timeout=900,
                           stdin=subprocess.DEVNULL)
        line = (p.stdout.strip().splitlines() or [""])[-1]
        return json.loads(line) if line.startswith("{") else {"file": os.path.basename(f), "err": p.returncode}
    with ThreadPoolExecutor(max_workers=12) as ex:
        res = list(ex.map(one, files))
    allbig, cdt, ff = [], Counter(), Counter()
    for r in res:
        if "err" in r:
            print("worker error", r); continue
        allbig += [(b[0], r["file"], b[1], b[2], b[3], b[4]) for b in r["big"]]
        cdt.update(r["cdt"]); ff.update(r["fixform"])
    allbig.sort(reverse=True)
    print("[D1] largest element counts (count, file, kind, shape, byte length, first refusal):")
    for b in allbig[:8]:
        print("   ", b)
    print("[D2] NO_AXIS_PTS component datatypes in the objects' own readable layouts:", dict(cdt))
    print("[D3] FIX_AXIS_PAR / _DIST offset and step/shift words:", dict(ff))


if __name__ == "__main__":
    worker(sys.argv[2]) if sys.argv[1] == "worker" else main(sys.argv[2])
