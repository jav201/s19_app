#!/usr/bin/env python3
"""batch-103 Inc 4 E3 round-2 security: _prefix_distance without a band (THROWAWAY).
Names of one long token (<= 1,024 characters, so R-A2L-MATCH.39 keeps them) and a
256-character query token 1-2 edits away: every listed fuzzy entry runs _classify,
whose capped OSA has no early exit along the diagonal (graph node _prefix_distance)."""
import os, runpy, statistics, time
M = runpy.run_path(os.path.join(os.path.dirname(os.path.abspath(__file__)), "sec-r2-probe.py"), run_name="band")
R2, header, load = M["R2"], M["header"], M["load"]
g = M["classify"].__globals__
unbanded = g["osa_cap"]

def osa_band(q, t, cap):
    """The same value, computed only on |i - j| <= cap (the walk's band)."""
    m, n = len(q), len(t)
    INF = cap + 1
    prev2 = None
    prev = [j if j <= cap else INF for j in range(n + 1)]
    for i in range(1, m + 1):
        cur = [INF] * (n + 1)
        if i <= cap:
            cur[0] = i
        lo_j, hi_j = max(1, i - cap), min(n, i + cap)
        qi = q[i - 1]
        lo = cur[0]
        for j in range(lo_j, hi_j + 1):
            tj = t[j - 1]
            v = prev[j - 1] + (0 if qi == tj else 1)
            a = prev[j] + 1
            if a < v: v = a
            a = cur[j - 1] + 1
            if a < v: v = a
            if i > 1 and j > 1 and qi == t[j - 2] and q[i - 2] == tj:
                a = prev2[j - 2] + 1
                if a < v: v = a
            if v > INF: v = INF
            cur[j] = v
            if v < lo: lo = v
        if lo > cap:
            return INF
        prev2, prev = prev, cur
    d = min(prev)
    return d if d <= cap else INF

header()
_, ref, _ = load()
short = ref[:100]
for L, cnt in ((1000, 25), (1020, 100)):
    names = short + [("a" * L) + "_" + str(i) for i in range(cnt)]
    for q in ("a" * 255 + "b", "a" * 254 + "bb", "a" * 128 + "b"):
        res = {}
        for label, fn in (("graph (no band)", unbanded), ("banded |i-j|<=cap", osa_band)):
            g["osa_cap"] = fn
            ix = R2(names)
            out = ix.rank(q, 20)
            runs = []
            for _ in range(3):
                t0 = time.perf_counter(); ix.rank(q, 20); runs.append(time.perf_counter() - t0)
            res[label] = (statistics.median(runs), out)
        g["osa_cap"] = unbanded
        (ta, oa), (tb, ob) = res.values()
        print(f"  {cnt} names of a {L}-char token; query {len(q)} chars: no band {ta*1000:8.1f} ms | band {tb*1000:6.1f} ms | same list {oa == ob} | listed {len(oa)} {oa[0][1] if oa else '-'} e{oa[0][2] if oa else '-'}")
print(f"load after = {os.getloadavg()}")
