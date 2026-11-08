"""Inc 2a E5 gap probe, part 3 (batch-103): how stable is the per-object part of R-A2L-DEF.149 on a correct design?
`gap-2a-gc.py` showed the collector is not why the model's ratio swung (x0.42 ... x4.19): the per-object part of 400
names (0.01-0.04 s) is the difference of two calls that each hold the one read of the shared section (0.07-0.21 s),
so the read's run-to-run spread lands in it. This probe repeats the estimate three times per case and size with:
  E7   least of 7 runs, (400 names) - (first name alone)            -- the row as first written
  E21  least of 21 runs, same difference
  P21  median of 21 paired differences (first name, then 400 names, back to back)
  N7   least of 7 runs at 4,000 objects (the same file shape, 10x the objects), (4,000 names) - (first name alone)
and the negative control (the model with the case's stored form off, i.e. read per object again) under N7 at
4,000 objects is not run (it is ~10x the 400-object 41-57 s). THROWAWAY; read-only.
Usage: python -I gap-2a-est.py <tree> <scratch>   (after `gap-2a-probe.py scale`, which wrote the 400-object files)
"""
import gc, importlib.util, pathlib, statistics, sys, time

TREE, S = sys.argv[1], pathlib.Path(sys.argv[2])
sys.argv = ["gap-2a-probe.py", "none", TREE, str(S)]
spec = importlib.util.spec_from_file_location("gapprobe", str(S / "gap-2a-probe.py"))
P = importlib.util.module_from_spec(spec); spec.loader.exec_module(P)
D, parse_a2l_file = P.D, P.parse_a2l_file


def t(fn):
    gc.collect(); t0 = time.perf_counter(); fn(); return time.perf_counter() - t0


def estimates(names, data, big):
    one = lambda: D.describe_definitions(names[:1], data)
    alln = lambda: D.describe_definitions(names, data)
    if big:
        a = [t(alln) for _ in range(7)]; f = [t(one) for _ in range(7)]
        return {"N7": min(a) - min(f), "tot": min(a)}
    pairs = [(t(one), t(alln)) for _ in range(21)]
    f = [p[0] for p in pairs]; a = [p[1] for p in pairs]
    return {"E7": min(a[:7]) - min(f[:7]), "E21": min(a) - min(f),
            "P21": statistics.median(x - y for y, x in pairs), "tot": min(a[:7])}


P.use("model")
W = S / "work"
for case in ("method", "vtab", "range", "layout"):
    files = {}
    for kib in (256, 512):
        files[(kib, 400)] = W / f"gap_{case}_{kib}.a2l"
        p = W / f"gap_{case}_{kib}_n4000.a2l"
        p.write_text(P.a2l_text(case, kib, n=4000), encoding="utf-8")
        files[(kib, 4000)] = p
    for rep in range(3):
        res = {}
        for (kib, n), p in files.items():
            data = parse_a2l_file(p)
            names = [x["name"] for x in data["tags"] if x.get("char_type") == "VALUE"]
            assert len(names) == n
            res[(kib, n)] = estimates(names, data, n == 4000)
            del data; gc.collect()
        line = [f"[est {case} rep {rep + 1}]"]
        for key in ("E7", "E21", "P21"):
            b1, b2 = res[(256, 400)][key], res[(512, 400)][key]
            line.append(f"{key} {b1:.4f}->{b2:.4f} s x{b2 / b1:.2f}" if b1 > 0 else f"{key} {b1:.4f}->{b2:.4f} s x(n/a)")
        b1, b2 = res[(256, 4000)]["N7"], res[(512, 4000)]["N7"]
        line.append(f"N7(4000) {b1:.4f}->{b2:.4f} s x{b2 / b1:.2f}")
        line.append(f"totals 400: {res[(256, 400)]['tot']:.3f}/{res[(512, 400)]['tot']:.3f} s, "
                    f"4000: {res[(256, 4000)]['tot']:.3f}/{res[(512, 4000)]['tot']:.3f} s")
        print(" | ".join(line), flush=True)
    for (kib, n), p in files.items():
        if n == 4000:
            p.unlink()
P.use("cur")
