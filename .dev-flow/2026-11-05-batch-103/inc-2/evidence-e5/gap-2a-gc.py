"""Inc 2a E5 gap probe, part 2 (batch-103): why the model's time beyond the first name rose x3.07 on .149/2 (vtab).
Hypothesis: not a per-object walk but the cyclic garbage collector -- a collection that runs during the 399 later
names traverses the freshly built shared table once (its cost grows with the table), while the first name's own call
ends before any such collection. Measures, for the model of `gap-2a-probe.py`, the time spent inside collections
(`gc.callbacks`) in each call, with the collector on, and the same runs with it paused during the call (as `timeit`
does). THROWAWAY; read-only. Usage: python -I gap-2a-gc.py <tree> <scratch>   (after `gap-2a-probe.py scale`)
"""
import gc, importlib.util, pathlib, sys, time

TREE, S = sys.argv[1], pathlib.Path(sys.argv[2])
sys.argv = ["gap-2a-probe.py", "none", TREE, str(S)]          # import the probe's model without running a mode
spec = importlib.util.spec_from_file_location("gapprobe", str(S / "gap-2a-probe.py"))
P = importlib.util.module_from_spec(spec); spec.loader.exec_module(P)
D, parse_a2l_file = P.D, P.parse_a2l_file

GCT = {"t": 0.0, "n": [0, 0, 0], "t0": 0.0}


def cb(phase, info):
    if phase == "start":
        GCT["t0"] = time.perf_counter()
    else:
        GCT["t"] += time.perf_counter() - GCT["t0"]; GCT["n"][info["generation"]] += 1


gc.callbacks.append(cb)


def run(fn, k, paused):
    best = None
    for _ in range(k):
        gc.collect(); GCT["t"], GCT["n"] = 0.0, [0, 0, 0]
        if paused:
            gc.disable()
        t0 = time.perf_counter(); fn(); dt = time.perf_counter() - t0
        if paused:
            gc.enable()
        if best is None or dt < best[0]:
            best = (dt, GCT["t"], list(GCT["n"]))
    return best


P.use("model")
for case in ("vtab", "method", "range", "layout"):
    per = {}
    for kib in (256, 512):
        p = S / "work" / f"gap_{case}_{kib}.a2l"
        if not p.exists():
            continue
        data = parse_a2l_file(p)
        names = [t["name"] for t in data["tags"] if t.get("char_type") == "VALUE"]
        for paused in (False, True):
            a = run(lambda: D.describe_definitions(names, data), 7, paused)
            f = run(lambda: D.describe_definitions(names[:1], data), 7, paused)
            per[(kib, paused)] = (a, f)
            print(f"[gc {case} {kib} KiB, collector {'paused' if paused else 'on'}] 400 names {a[0]:.4f} s "
                  f"(in collections {a[1]:.4f} s, gen0/1/2 {a[2]}); first name {f[0]:.4f} s (in collections "
                  f"{f[1]:.4f} s, {f[2]}); beyond {a[0] - f[0]:.4f} s; beyond less collections "
                  f"{(a[0] - a[1]) - (f[0] - f[1]):.4f} s", flush=True)
        del data
        gc.collect()
    for paused in (False, True):
        if (256, paused) in per and (512, paused) in per:
            (a1, f1), (a2, f2) = per[(256, paused)], per[(512, paused)]
            b1, b2 = a1[0] - f1[0], a2[0] - f2[0]
            print(f"[gc {case}] collector {'paused' if paused else 'on'}: beyond {b1:.4f} -> {b2:.4f} s, "
                  f"x{b2 / b1:.2f}; total 256 KiB {a1[0]:.3f} s", flush=True)
P.use("cur")
