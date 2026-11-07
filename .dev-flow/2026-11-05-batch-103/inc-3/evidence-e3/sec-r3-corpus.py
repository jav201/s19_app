"""E3 round-3 security probe, Inc 3a (batch-103): the round-2-corrected model (sec-r3-m3a.py) over real A2L files.
Per file (one subprocess each, read-only): parse with the frozen parser; describe every VAL_BLK / CURVE / MAP in
one walk with `maps["reads"]`; count .147 refusals; for every FIX axis with a fixed_rule build its points with the
exact `_fixed_points` and compare them (value and type) with the round-2 IEEE-double arithmetic; decode each point
with Inc 2a's `display_text`. Usage: sec-r3-corpus.py worker <tree> <scratch> <file> | main <tree> <scratch> <list>...
"""
import importlib.util, json, os, subprocess, sys, time, traceback
from collections import Counter
from pathlib import Path


def worker(tree, scratch, path):
    sys.path.insert(0, tree)
    import s19_app.tui.a2l as a
    import s19_app.tui.a2l_definition as D
    spec = importlib.util.spec_from_file_location("m3r3", str(Path(scratch) / "sec-r3-m3a.py"))
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); m.bind(a)
    data = a.parse_a2l_file(Path(path))
    out = {"file": os.path.basename(path), "exceptions": [], "codes": Counter(), "fix_forms": Counter(),
           "fix_same": 0, "fix_diff": 0, "fix_points": 0, "objects": 0, "reads": None, "par_shifts": Counter(),
           "max_abs_point": 0}
    t1 = time.perf_counter()
    try:
        res, maps = m.describe_all(data)
        out["objects"] = len(res)
        out["reads"] = maps["stats"]
    except Exception as e:
        out["exceptions"].append(["(walk)", type(e).__name__, traceback.format_exc().splitlines()[-1][:160]])
        res = {}
    tmpl = None
    for nm, r in res.items():
        out["codes"][r["refusal"] or "none"] += 1
        for ax in r["axes"]:
            rule = ax.get("fixed_rule")
            if rule is None:
                continue
            out["fix_forms"][rule[0]] += 1
            if rule[0] == "PAR":
                out["par_shifts"][str(rule[1][1])] += 1
            try:
                ex = m.fixed_points(rule)
                m.FIX_RULE = "r2"
                flt = m.B.fixed_points(rule, "float")
                m.FIX_RULE = "r3"
                out["fix_points"] += len(ex)
                same = len(ex) == len(flt) and all(x == y and type(x) is type(y) for x, y in zip(ex, flt))
                out["fix_same" if same else "fix_diff"] += 1
                out["max_abs_point"] = max(out["max_abs_point"], max((abs(p) for p in ex), default=0))
                if tmpl is None:
                    tmpl = D.Definition(name="P", section="AXIS_DESCR", char_type=None, kind="number", address=None,
                                        byte_length=None, datatype=None, byte_order="big", bit_mask=None,
                                        bit_mask_text=None, conversion_type="IDENTICAL", method_name="CM",
                                        display_format=None, decimals=None, unit="", limits=D.Limits(None, None, "", ""),
                                        extended_limits=None, enum_table=None, enum_entries=(), default_text=None,
                                        coeffs_linear=None, coeffs=None, compu_tab_ref=None, refusal=None)
                for p in ex:
                    D.display_text(tmpl, p)
            except Exception as e:
                m.FIX_RULE = "r3"
                out["exceptions"].append([nm[:60], "fix-decode " + type(e).__name__, str(e)[:120]])
    out["model_s"] = round(time.perf_counter() - t1, 3)
    for k in ("codes", "fix_forms", "par_shifts"):
        out[k] = dict(out[k])
    out["max_abs_point"] = float(out["max_abs_point"])
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
                "file": os.path.basename(f), "worker_error": (p.stderr.strip().splitlines() or ["?"])[-1][:200]}
        except subprocess.TimeoutExpired:
            return {"file": os.path.basename(f), "worker_error": "timeout 900 s"}
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=12) as ex:
        res = list(ex.map(one, files))
    codes, forms, shifts, exc, werr = Counter(), Counter(), Counter(), [], []
    objs = same = diff = fpts = 0
    mx = 0.0
    lr = mr = 0
    for r in res:
        if "worker_error" in r:
            werr.append(r); continue
        objs += r["objects"]; codes.update(r["codes"]); forms.update(r["fix_forms"]); shifts.update(r["par_shifts"])
        same += r["fix_same"]; diff += r["fix_diff"]; fpts += r["fix_points"]; mx = max(mx, r["max_abs_point"])
        exc += [[r["file"]] + e for e in r["exceptions"]]
        if r["reads"]:
            lr += r["reads"]["layout_reads"]; mr += r["reads"]["modc_reads"]
    print(f"[Q0] files {len(files)}, parsed {len(files) - len(werr)}, worker errors {len(werr)}, wall "
          f"{time.perf_counter() - t0:.1f} s")
    for w in werr:
        print("   worker error:", w)
    print(f"[Q1] array/curve/map objects described in one walk per file (maps['reads']): {objs}; exceptions {len(exc)}; "
          f"section reads: {lr} layouts, {mr} MOD_COMMONs")
    for e in exc[:20]:
        print("   EXC", e)
    print("[Q2] first refusal per object:", dict(codes.most_common()))
    print(f"[Q4] FIX axes with a fixed_rule: {dict(forms)}; PAR shifts {dict(shifts)}; points built at decode {fpts}; "
          f"exact == IEEE-double points (value and type) for {same}, different for {diff}; largest |point| {mx:g}")


if __name__ == "__main__":
    if sys.argv[1] == "worker":
        worker(sys.argv[2], sys.argv[3], sys.argv[4])
    else:
        main(sys.argv[2], sys.argv[3], sys.argv[4:])
