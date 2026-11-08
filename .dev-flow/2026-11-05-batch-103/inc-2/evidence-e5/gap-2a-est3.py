"""Inc 2a E5 gap probe, part 5 (batch-103): an interleaved estimator for R-A2L-DEF.149's ratio.
Parts 3 and 4 (`gap-2a-est.py`, `gap-2a-est2.py`) timed all runs of the 256 KiB file, then all runs of the 512 KiB
file; at load average 13-15 on 16 cores the host's speed drifts between the two blocks (the per-object part of the
same 4,000-object file read 0.07-0.22 s), so every estimator swung (E7 x0.25-4.4, P21 x0.60-1.85).
This one interleaves: each of 21 rounds times, back to back, the first name alone and the 400 names on the 256 KiB
file, then the same on the 512 KiB file, and takes that round's ratio of the two per-object parts (400 names less
the first name); the estimate is the median of the 21 ratios (I21). Wall clock, 3 reps per case. THROWAWAY; read-only.
Usage: python -I gap-2a-est3.py <tree> <scratch>   (after `gap-2a-probe.py scale`, which wrote the files)
"""
import gc, importlib.util, os, pathlib, statistics, sys, time

TREE, S = sys.argv[1], pathlib.Path(sys.argv[2])
sys.argv = ["gap-2a-probe.py", "none", TREE, str(S)]
spec = importlib.util.spec_from_file_location("gapprobe", str(S / "gap-2a-probe.py"))
P = importlib.util.module_from_spec(spec); spec.loader.exec_module(P)
D, parse_a2l_file = P.D, P.parse_a2l_file


def t(fn):
    gc.collect(); t0 = time.perf_counter(); fn(); return time.perf_counter() - t0


P.use("model")
W = S / "work"
for case in ("method", "vtab", "range", "layout"):
    sets = {}
    for kib in (256, 512):
        data = parse_a2l_file(W / f"gap_{case}_{kib}.a2l")
        sets[kib] = (data, [x["name"] for x in data["tags"] if x.get("char_type") == "VALUE"])
    for rep in range(3):
        ratios, parts, totals = [], {256: [], 512: []}, {256: [], 512: []}
        for _ in range(21):
            b = {}
            for kib in (256, 512):
                data, names = sets[kib]
                f = t(lambda: D.describe_definitions(names[:1], data))
                a = t(lambda: D.describe_definitions(names, data))
                b[kib] = a - f; parts[kib].append(a - f); totals[kib].append(a)
            ratios.append(b[512] / b[256] if b[256] > 0 else float("inf"))
        med = statistics.median(ratios)
        q = statistics.quantiles(ratios, n=4)
        print(f"[est3 {case} rep {rep + 1}] load {os.getloadavg()[0]:.1f} | I21 median ratio x{med:.2f} "
              f"(quartiles x{q[0]:.2f} .. x{q[2]:.2f}) | per-object part median {statistics.median(parts[256]):.4f} -> "
              f"{statistics.median(parts[512]):.4f} s | 400-name total least {min(totals[256]):.3f} / "
              f"{min(totals[512]):.3f} s -> {'GREEN' if med <= 1.3 and min(totals[256]) <= 0.5 else 'RED'}", flush=True)
    del sets; gc.collect()
P.use("cur")
