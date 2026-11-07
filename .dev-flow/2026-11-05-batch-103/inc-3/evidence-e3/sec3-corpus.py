"""E3 security probe, Inc 3a (batch-103): the throwaway 3a model (m3a.py) over real A2L files.

For each file (one subprocess each, read-only): parse with the frozen base parser, build every VAL_BLK, CURVE, MAP and
MEASUREMENT array with the model, and report exceptions, refusal codes, open branches, model time and the largest
real shapes (point counts, element counts, FIX counts, record lengths, layout components of arrays, NO_AXIS_PTS
datatypes, MOD_COMMON alignments). Usage: sec3-corpus.py worker <file> | sec3-corpus.py main <list file>
"""
import json, math, os, subprocess, sys, time, traceback
from collections import Counter

TREE = "/home/javiergr/work/b103-int2a"


def worker(path):
    sys.path.insert(0, TREE)
    sys.path.insert(1, "/tmp/b103-e3-3-security")
    import s19_app.tui.a2l as a
    import m3a
    m3a.bind(a)
    from pathlib import Path
    t0 = time.perf_counter()
    data = a.parse_a2l_file(Path(path))
    tp = time.perf_counter() - t0
    out = {"file": os.path.basename(path), "parse_s": round(tp, 3), "exceptions": [], "codes": Counter(),
           "open": Counter(), "max": {}, "valblk_layout_comps": Counter(), "count_dtypes": Counter(),
           "modcommon_align": Counter(), "fixpar_nonint": 0, "fix_n": [], "objects": 0}
    t1 = time.perf_counter()
    maps = m3a.build_maps(data)
    secs = m3a.object_sections(data)
    mx = Counter()
    done = set()
    for tag in data.get("tags") or []:
        nm = tag.get("name")
        ss = secs.get(nm) or []
        if len(ss) != 1 or nm in done:
            continue
        done.add(nm)
        try:
            if not m3a.is_array_kind(tag, ss[0]):
                continue
            out["objects"] += 1
            r = m3a.describe_array(tag, ss[0], data, maps)
        except Exception as e:  # the model must not raise; record and go on
            out["exceptions"].append([nm[:60], type(e).__name__, str(e)[:120], traceback.format_exc().splitlines()[-3][:160]])
            continue
        out["codes"][r["refusal"] or "none"] += 1
        for o in r["open"]:
            out["open"][o[0]] += 1
        mx["element_count"] = max(mx["element_count"], r["element_count"] or 0)
        if r["refusal"] is None and r["byte_length"]:
            mx["byte_length_ok"] = max(mx["byte_length_ok"], r["byte_length"])
        for ax in r["axes"]:
            mx["point_count"] = max(mx["point_count"], ax.get("point_count") or 0)
            fp = ax.get("fixed_points")
            if fp is not None:
                out["fix_n"].append(len(fp))
                out["fixpar_nonint"] += sum(1 for p in fp if isinstance(p, float))
            if ax.get("count_datatype"):
                out["count_dtypes"][ax["count_datatype"]] += 1
        if tag.get("char_type") == "VAL_BLK":
            lname = (m3a.flat([ss[0].get("meta") or ""] + (ss[0].get("lines") or [])) + [None] * 5)[4]
            rl = m3a.read_record_layout(lname, data, nm)
            if isinstance(rl, dict):
                out["valblk_layout_comps"][",".join(c[0] for c in rl["components"])] += 1
    for mc in {id(v): v for v in maps["mod_common_of"].values() if v is not None}.values():
        for w in m3a.clean_lines(mc.get("lines")):
            if w and w[0].startswith("ALIGNMENT_") and len(w) > 1:
                out["modcommon_align"][f"{w[0]} {w[1][:12]}"] += 1
    out["model_s"] = round(time.perf_counter() - t1, 3)
    out["max"] = dict(mx)
    out["fix_n"] = [max(out["fix_n"]) if out["fix_n"] else 0, len(out["fix_n"])]
    for k in ("codes", "open", "valblk_layout_comps", "count_dtypes", "modcommon_align"):
        out[k] = dict(out[k])
    print(json.dumps(out))


def main(listfile):
    files = [ln.strip() for ln in open(listfile) if ln.strip()]
    from concurrent.futures import ThreadPoolExecutor
    env = dict(os.environ)

    def one(f):
        try:
            p = subprocess.run([sys.executable, "-I", __file__, "worker", f], capture_output=True, text=True,
                               timeout=900, env=env, stdin=subprocess.DEVNULL)
            line = (p.stdout.strip().splitlines() or [""])[-1]
            return json.loads(line) if line.startswith("{") else {"file": os.path.basename(f), "worker_error": p.returncode,
                                                                   "stderr": p.stderr.strip().splitlines()[-1:] if p.stderr else []}
        except subprocess.TimeoutExpired:
            return {"file": os.path.basename(f), "worker_error": "timeout 900 s"}
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=12) as ex:
        res = list(ex.map(one, files))
    tot = Counter(); opn = Counter(); exc = []; werr = []; mx = Counter(); vb = Counter(); cdt = Counter(); mca = Counter()
    objs = 0; fixn = [0, 0]; fixnon = 0; slow = []
    for r in res:
        if "worker_error" in r:
            werr.append(r); continue
        objs += r["objects"]; tot.update(r["codes"]); opn.update(r["open"]); vb.update(r["valblk_layout_comps"])
        cdt.update(r["count_dtypes"]); mca.update(r["modcommon_align"]); fixnon += r["fixpar_nonint"]
        fixn = [max(fixn[0], r["fix_n"][0]), fixn[1] + r["fix_n"][1]]
        for e in r["exceptions"]:
            exc.append([r["file"]] + e)
        for k, v in r["max"].items():
            mx[k] = max(mx[k], v)
        slow.append((r["model_s"], r["parse_s"], r["file"], r["objects"]))
    print(f"[C0] files {len(files)}, parsed {len(files) - len(werr)}, worker errors {len(werr)}, wall {time.perf_counter() - t0:.1f} s")
    for w in werr:
        print("   worker error:", w)
    print(f"[C1] array/curve/map objects built by the model: {objs}; exceptions: {len(exc)}")
    for e in exc[:20]:
        print("   EXC", e)
    print("[C2] first refusal per object:", dict(tot.most_common()))
    print("[C3] open branches reached (graph gives no result):", dict(opn))
    print("[C4] largest real shapes:", dict(mx), "| FIX axes built:", fixn[1], "largest FIX point count:", fixn[0],
          "| non-integral FIX points:", fixnon)
    print("[C5] VAL_BLK record layout components (readable layouts):", dict(vb.most_common()))
    print("[C6] NO_AXIS_PTS_X datatypes of COM axis objects:", dict(cdt))
    print("[C7] MOD_COMMON ALIGNMENT lines:", dict(mca.most_common(20)))
    slow.sort(reverse=True)
    print("[C8] slowest model runs (model s, parse s, file, objects):", slow[:6])
    print(f"[C9] model seconds total {sum(s[0] for s in slow):.2f}, parse seconds total {sum(s[1] for s in slow):.1f}")


if __name__ == "__main__":
    if sys.argv[1] == "worker":
        worker(sys.argv[2])
    else:
        main(sys.argv[2])
