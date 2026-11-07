"""E3 round-2 security probe, Inc 3a (batch-103): the corrected model (sec-r2-m3a.py) over real A2L files.

Per file (one subprocess each, read-only): parse with the frozen parser, describe every VAL_BLK / CURVE / MAP with
the corrected model; for every FIX axis with a fixed_rule, build its points at "decode" with both arithmetics the
node leaves open (literal: the stored ints; float: IEEE double as the check) and decode each point with Inc 2a's
display_text; report exceptions, refusal codes, NO_AXIS_PTS datatypes, FIX forms and whether the two arithmetics
give the same points. Usage: sec-r2-corpus.py worker <tree> <scratch> <file> | main <tree> <scratch> <list>...
"""
import importlib.util, json, os, subprocess, sys, time, traceback
from collections import Counter
from pathlib import Path


def worker(tree, scratch, path):
    sys.path.insert(0, tree)
    import s19_app.tui.a2l as a
    import s19_app.tui.a2l_definition as D
    spec = importlib.util.spec_from_file_location("m3r2", str(Path(scratch) / "sec-r2-m3a.py"))
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); m.bind(a)
    t0 = time.perf_counter()
    data = a.parse_a2l_file(Path(path))
    tp = time.perf_counter() - t0
    out = {"file": os.path.basename(path), "parse_s": round(tp, 3), "exceptions": [], "codes": Counter(),
           "count_dtypes": Counter(), "fix_forms": Counter(), "fix_same": 0, "fix_diff": 0, "fix_decode_exc": 0,
           "fix_points": 0, "objects": 0}
    t1 = time.perf_counter()
    res = {}
    try:
        maps, secs = m.build_maps(data), m.object_sections(data)
        done = set()
        for tag in data.get("tags") or []:
            nm = tag.get("name")
            ss = secs.get(nm) or []
            if len(ss) != 1 or nm in done:
                continue
            done.add(nm)
            if not m.is_array_kind(tag, ss[0]):
                continue
            out["objects"] += 1
            try:
                res[nm] = m.describe_array(tag, ss[0], data, maps)
            except Exception as e:
                out["exceptions"].append([nm[:60], type(e).__name__, str(e)[:120]])
    except Exception as e:
        out["exceptions"].append(["(walk)", type(e).__name__, traceback.format_exc().splitlines()[-1][:160]])
    template = None
    for nm, r in res.items():
        out["codes"][r["refusal"] or "none"] += 1
        for ax in r["axes"]:
            if ax.get("count_datatype"):
                out["count_dtypes"][ax["count_datatype"]] += 1
            rule = ax.get("fixed_rule")
            if rule is None:
                continue
            out["fix_forms"][rule[0]] += 1
            try:
                lit, flt = m.fixed_points(rule, "literal"), m.fixed_points(rule, "float")
                out["fix_points"] += len(lit)
                same = len(lit) == len(flt) and all(x == y and type(x) is type(y) for x, y in zip(lit, flt))
                out["fix_same" if same else "fix_diff"] += 1
                if template is None:
                    template = D.Definition(name="P", section="AXIS_DESCR", char_type=None, kind="number",
                                            address=None, byte_length=None, datatype=None, byte_order="big",
                                            bit_mask=None, bit_mask_text=None, conversion_type="IDENTICAL",
                                            method_name="CM", display_format=None, decimals=None, unit="",
                                            limits=D.Limits(None, None, "", ""), extended_limits=None, enum_table=None,
                                            enum_entries=(), default_text=None, coeffs_linear=None, coeffs=None,
                                            compu_tab_ref=None, refusal=None)
                for p in lit:
                    D.display_text(template, p)
            except Exception as e:
                out["fix_decode_exc"] += 1
                out["exceptions"].append([nm[:60], "fix-decode " + type(e).__name__, str(e)[:120]])
    out["model_s"] = round(time.perf_counter() - t1, 3)
    for k in ("codes", "count_dtypes", "fix_forms"):
        out[k] = dict(out[k])
    print(json.dumps(out))


def main(tree, scratch, lists):
    files = [ln.strip() for lf in lists for ln in open(lf) if ln.strip()]
    from concurrent.futures import ThreadPoolExecutor

    def one(f):
        try:
            p = subprocess.run([sys.executable, "-I", __file__, "worker", tree, scratch, f], capture_output=True,
                               text=True, timeout=900, stdin=subprocess.DEVNULL)
            line = (p.stdout.strip().splitlines() or [""])[-1]
            return json.loads(line) if line.startswith("{") else {
                "file": os.path.basename(f), "worker_error": p.returncode,
                "stderr": p.stderr.strip().splitlines()[-1:] if p.stderr else []}
        except subprocess.TimeoutExpired:
            return {"file": os.path.basename(f), "worker_error": "timeout 900 s"}
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=12) as ex:
        res = list(ex.map(one, files))
    codes, cdt, forms, exc, werr = Counter(), Counter(), Counter(), [], []
    objs = same = diff = fexc = fpts = 0
    for r in res:
        if "worker_error" in r:
            werr.append(r); continue
        objs += r["objects"]; codes.update(r["codes"]); cdt.update(r["count_dtypes"]); forms.update(r["fix_forms"])
        same += r["fix_same"]; diff += r["fix_diff"]; fexc += r["fix_decode_exc"]; fpts += r["fix_points"]
        exc += [[r["file"]] + e for e in r["exceptions"]]
    print(f"[Q0] files {len(files)}, parsed {len(files) - len(werr)}, worker errors {len(werr)}, wall {time.perf_counter() - t0:.1f} s")
    for w in werr:
        print("   worker error:", w)
    print(f"[Q1] array/curve/map objects described by the corrected model: {objs}; exceptions: {len(exc)}")
    for e in exc[:20]:
        print("   EXC", e)
    print("[Q2] first refusal per object:", dict(codes.most_common()))
    print("[Q3] NO_AXIS_PTS datatypes of admitted axes (STD and COM):", dict(cdt))
    print(f"[Q4] FIX axes with a fixed_rule: {dict(forms)}; points built at decode {fpts}; literal == float arithmetic "
          f"(value and type) for {same}, different for {diff}; decode exceptions {fexc}")


if __name__ == "__main__":
    if sys.argv[1] == "worker":
        worker(sys.argv[2], sys.argv[3], sys.argv[4])
    else:
        main(sys.argv[2], sys.argv[3], sys.argv[4:])
