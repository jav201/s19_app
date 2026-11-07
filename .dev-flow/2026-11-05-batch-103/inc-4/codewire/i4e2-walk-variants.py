#!/usr/bin/env python3
"""batch-103 Inc 4 E2: the fuzzy-walk variants, timed per query token on REF.

THROWAWAY EVIDENCE, NOT PRODUCT CODE. Run on <runner> in PILOT_DIR next to
i4e2-pilot4.py and the E1 pilots. Four walks that must give the same
{token: prefix distance} map, over the 77,256 distinct tokens of REF:
  * trie         -- v3's dict trie (IndexB._trie_search), the ~78 MiB baseline;
  * sorted       -- the first v4 variant: the bare sorted token list, columns
                    re-used over the common prefix, bisect to skip a pruned
                    prefix (the walk of i4e2-pilot4-variantA-transcript.txt,
                    worst rank median 158.3 ms); its code is walk_sorted below;
  * sorted+band  -- the same with columns capped at k + 1 on the band
                    |row - depth| <= k and a precomputed common-prefix array;
  * nodes        -- the pre-order array trie of i4e2-pilot4.py (fuzzy_walk),
                    the design the graph pins.
"""
import bisect, os, runpy, statistics, sys, time
from array import array
from pathlib import Path

HERE = Path(os.environ.get("PILOT_DIR", "/tmp/b103-e2-4"))
P4 = runpy.run_path(str(HERE / "i4e2-pilot4.py"), run_name="p4")
IndexB, IndexC, fuzzy_walk, prefix_end, allowed, names_of, REPO, s19_app = (
    P4["IndexB"], P4["IndexC"], P4["fuzzy_walk"], P4["prefix_end"], P4["allowed"], P4["names_of"], P4["REPO"], P4["s19_app"])


def walk_sorted(utok, q, k):
    m = len(q)
    res = {}
    n = len(utok)
    cols = [list(range(m + 1))]
    best = [m]
    path = ""
    i = 0
    while i < n:
        t = utok[i]
        lim = len(path) if len(path) < len(t) else len(t)
        l = 0
        while l < lim and path[l] == t[l]:
            l += 1
        if l + 1 < len(cols):
            del cols[l + 1:]
            del best[l + 1:]
        d = l
        lt = len(t)
        skipped = False
        while d < lt:
            c = t[d]
            prev = cols[d]
            prev2 = cols[d - 1] if d >= 1 else None
            pchar = t[d - 1] if d >= 1 else ""
            jj = d + 1
            new = [jj] + [0] * m
            for ii in range(1, m + 1):
                qi = q[ii - 1]
                v = prev[ii - 1] + (0 if qi == c else 1)
                a = prev[ii] + 1
                if a < v:
                    v = a
                a = new[ii - 1] + 1
                if a < v:
                    v = a
                if ii > 1 and d >= 1 and qi == pchar and q[ii - 2] == c:
                    a = prev2[ii - 2] + 1
                    if a < v:
                        v = a
                new[ii] = v
            b2 = best[d] if best[d] < new[m] else new[m]
            cols.append(new)
            best.append(b2)
            d = jj
            low = min(new)
            if low > k or low >= b2:
                end = prefix_end(utok, t[:d], i + 1)
                if b2 <= k:
                    for j in range(i, end):
                        res[j] = b2
                path = t[:d]
                i = end
                skipped = True
                break
        if not skipped:
            if best[lt] <= k:
                res[i] = best[lt]
            path = t
            i += 1
    return res


def walk_band(utok, lcps, q, k):
    m = len(q)
    cap = k + 1
    res = {}
    n = len(utok)
    col0 = [min(i, cap) for i in range(m + 1)]
    cols = [col0]
    best = [min(m, cap)]
    plen = 0          # len(path); path is utok[i-1][:plen] (a prefix of the token before i)
    i = 0
    qs = q
    while i < n:
        t = utok[i]
        l = lcps[i]
        if l > plen:
            l = plen
        if l + 1 < len(cols):
            del cols[l + 1:]
            del best[l + 1:]
        d = l
        lt = len(t)
        skipped = False
        while d < lt:
            c = t[d]
            prev = cols[d]
            jj = d + 1
            new = [cap] * (m + 1)
            new[0] = jj if jj < cap else cap
            lo_r = jj - k
            if lo_r < 1:
                lo_r = 1
            hi_r = jj + k
            if hi_r > m:
                hi_r = m
            low = new[0]
            if d >= 1:
                prev2 = cols[d - 1]
                pchar = t[d - 1]
                for ii in range(lo_r, hi_r + 1):
                    qi = qs[ii - 1]
                    v = prev[ii - 1] + (0 if qi == c else 1)
                    a = prev[ii] + 1
                    if a < v:
                        v = a
                    a = new[ii - 1] + 1
                    if a < v:
                        v = a
                    if ii > 1 and qi == pchar and qs[ii - 2] == c:
                        a = prev2[ii - 2] + 1
                        if a < v:
                            v = a
                    if v > cap:
                        v = cap
                    new[ii] = v
                    if v < low:
                        low = v
            else:
                for ii in range(lo_r, hi_r + 1):
                    qi = qs[ii - 1]
                    v = prev[ii - 1] + (0 if qi == c else 1)
                    a = prev[ii] + 1
                    if a < v:
                        v = a
                    a = new[ii - 1] + 1
                    if a < v:
                        v = a
                    if v > cap:
                        v = cap
                    new[ii] = v
                    if v < low:
                        low = v
            bd = best[d]
            b2 = bd if bd < new[m] else new[m]
            cols.append(new)
            best.append(b2)
            d = jj
            if low > k or low >= b2:
                end = prefix_end(utok, t[:d], i + 1)
                if b2 <= k:
                    for j in range(i, end):
                        res[j] = b2
                plen = d
                i = end
                skipped = True
                break
        if not skipped:
            if best[lt] <= k:
                res[i] = best[lt]
            plen = lt
            i += 1
    return res


def main():
    print(f"s19_app.__file__ = {s19_app.__file__}")
    print(f"python = {sys.version.split()[0]}  host = {os.uname().nodename}  load = {os.getloadavg()}")
    sw_a = names_of(REPO / "examples/case_00_public/software_a.a2l")
    ref = (sw_a + [n + "_1" for n in sw_a] + [n + "_2" for n in sw_a] + [n + "_3" for n in sw_a])[:50000]
    c = IndexC(ref)
    b = IndexB(ref)
    utok = c.utok
    lcps = array("H", [0]) if utok else array("H")
    for j in range(1, len(utok)):
        x, y = utok[j - 1], utok[j]
        lim = min(len(x), len(y))
        l = 0
        while l < lim and x[l] == y[l]:
            l += 1
        lcps.append(l)
    print(f"REF distinct tokens {len(utok)}, trie nodes {len(c.nodes[1])}, longest token {max(map(len, utok))}")
    qtoks = ["nzukij", "ierxjr", "eud", "pposbxiif", "temp", "sensor", "max", "xqzjvkw", "pposbxiifkdgfiajnbbpvb", "dyan",
             "xvz", "led", "ring", "jotaf", "vod", "msr", "aaaa", "qqqq", "zzzz", "cnt", "srql", "jotafvod", "cuvre", "maesu"]
    tot = {"trie": 0.0, "sorted": 0.0, "sorted+band": 0.0, "nodes": 0.0}
    bad = 0
    for qt in qtoks:
        k = allowed(qt)
        rows = {}
        for label, fn in (("trie", lambda: b._trie_search(qt, k)), ("sorted", lambda: walk_sorted(utok, qt, k)),
                          ("sorted+band", lambda: walk_band(utok, lcps, qt, k)), ("nodes", lambda: fuzzy_walk(utok, c.nodes, qt, k))):
            runs = []
            for _ in range(5):
                t0 = time.perf_counter()
                r = fn()
                runs.append(time.perf_counter() - t0)
            rows[label] = (statistics.median(runs) * 1000, r)
            tot[label] += rows[label][0]
        ref_map = dict(rows["trie"][1])
        same = all({utok[i]: d for i, d in rows[x][1].items()} == ref_map for x in ("sorted", "sorted+band", "nodes"))
        bad += not same
        print(f"  {qt!r:26s} k={k} within k {len(ref_map):4d}  " + "  ".join(f"{x} {rows[x][0]:6.1f} ms" for x in tot) + f"  all equal {same}")
    print("  total ms: " + ", ".join(f"{x} {v:.1f}" for x, v in tot.items()) + f"; query tokens {len(qtoks)}, maps not equal = {bad}")
    print(f"load at end = {os.getloadavg()}")


main()
