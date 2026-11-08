#!/usr/bin/env python3
"""batch-103 Inc 4 E3 addenda A-1 .. A-3 probe. THROWAWAY EVIDENCE, NOT PRODUCT CODE.

Reuses the round-2 security probe (sec-r2-probe.py, an unchanged copy in EVID_DIR, sha256
81f5c22d...e422) over the E2 pilot's IndexC buffers (PILOT_DIR):
  R2   the graph's procedure at 15129b64 (sub="any": CTX case-exactness)
  R2D  R2 with identical query tokens collapsed in the token and fuzzy tiers (one range or
       map per distinct token; a FUZZY key adds a token's smallest distance times its count)
The addenda procedure A = R2D + sub="any" (A-1) + the length check before the parse (A-4,
E3A-16 / E3S-13) + a banded _prefix_distance (A-3: osa_band, as sec-r2-band.py). R2's
per-candidate check already stops at the first query token a candidate fails (E3A-14).
Modes: check | time
"""
from __future__ import annotations

import gc
import os
import random
import runpy
import sys
import time
from pathlib import Path

EV = Path(os.environ["EVID_DIR"])
M = runpy.run_path(str(EV / "sec-r2-probe.py"), run_name="addenda")
g = M["classify"].__globals__
R2, R2D, header, load, naive_r2, med = g["R2"], g["R2D"], g["header"], g["load"], g["naive_r2"], g["med"]
typos_of, tokens, names_of, REPO = g["typos_of"], g["tokens"], g["names_of"], g["REPO"]
QSET22, MULTI3, REF6Q = g["QSET22"], g["MULTI3"], g["REF6Q"]
UNBANDED = g["osa_cap"]
L = "abcdefghijklmnopqrstuvwxyz"
NEAR = ["ch" + c for c in L] + [c + "ha" for c in L] + ["c" + c + "a" for c in L]


def osa_band(q: str, t: str, cap: int) -> int:
    """min(OSA prefix distance, cap + 1), computed only on |i - j| <= cap (sec-r2-band.py)."""
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
            if a < v:
                v = a
            a = cur[j - 1] + 1
            if a < v:
                v = a
            if i > 1 and j > 1 and qi == t[j - 2] and q[i - 2] == tj:
                a = prev2[j - 2] + 1
                if a < v:
                    v = a
            if v > INF:
                v = INF
            cur[j] = v
            if v < lo:
                lo = v
        if lo > cap:
            return INF
        prev2, prev = prev, cur
    d = min(prev)
    return d if d <= cap else INF


def use(fn):
    g["osa_cap"] = fn


class A(R2D):
    def __init__(self, names):
        super().__init__(names, sub="any", fz="lazy", cap_first=True)


def qset33(sw_a, ref):
    rng = random.Random(20261108)
    pool = rng.sample(sw_a, 400)
    most = sorted(ref, key=lambda n: (-len(tokens(n)), n))[0]
    shapes = ["e " * 128, ((" ".join(L) + " ") * 20)[:256], "0 " * 128, "a" * 256,
              ",".join(pool)[:256], ",".join(pool[200:])[:256], most, most[1] + most[0] + most[2:]]
    return QSET22 + MULTI3 + shapes, shapes


def pset(ref6_index, e3s01):
    ty = typos_of("char", ref6_index)
    ref_q = {
        "'qzx ' x 64": "qzx " * 64,
        "'qza' .. 'qzz' 3x, cut at 256": ((" ".join("qz" + c for c in L) + " ") * 3)[:256],
        "'cnt ' x 64": "cnt " * 64,
        "'1a' x 128": "1a" * 128,
        "'rat ' x 64, cut at 256": ("rat " * 64)[:256],
        "'e ' x 120 + 'rat'": "e " * 120 + "rat",
    }
    ref6_q = {
        "'chr ' x 64": "chr " * 64,
        "'cahr ' x 51": "cahr " * 51,
        "'0 ' x 128": "0 " * 128,
        "'00 ' x 85": "00 " * 85,
        "'c 0 ' x 64": "c 0 " * 64,
        "'c ' x 128": "c " * 128,
        "'m ' x 128": "m " * 128,
        "'1 ' x 128": "1 " * 128,
        "'c ' x 125 + 'chax'": "c " * 125 + "chax",
        "'0 ' x 125 + 'chax'": "0 " * 125 + "chax",
        "'chax ' x 52, cut at 256": ("chax " * 52)[:256],
        "'mesa ' x 52, cut at 256": ("mesa " * 52)[:256],
        "NEAR (64 distinct near tokens), cut at 256": " ".join(NEAR)[:256],
        "'cha' .. 'chz' 3x, cut at 256": ((" ".join(NEAR[:26]) + " ") * 3)[:256],
        "51 distinct 1-edit typos of 'char'": " ".join(ty[:51])[:256],
    }
    for k, q in enumerate(e3s01, 1):
        ref6_q[f"QSET E3S-01 shape {k} over REF6"] = q
    return ref_q, ref6_q, ty[:51]


def long_list(ref):
    return ref[:49900] + ["a" * 1020 + "_" + str(i) for i in range(100)]


LONGQ = {"'a' x 255 + 'b'": "a" * 255 + "b", "'a' x 254 + 'bb'": "a" * 254 + "bb", "'a' x 128 + 'b'": "a" * 128 + "b"}


def check():
    header()
    print("\n=== A-3: banded == unbanded _prefix_distance")
    rng = random.Random(20261109)
    bad = 0
    for _ in range(20000):
        q = "".join(rng.choice("abc") for _ in range(rng.randint(0, 12)))
        t = "".join(rng.choice("abc") for _ in range(rng.randint(0, 14)))
        k = rng.randint(0, 2)
        bad += osa_band(q, t, k) != UNBANDED(q, t, k)
    print(f"  20,000 random pairs (alphabet abc, cap 0-2): {bad} differences")
    print(f"  example: osa_band('a' * 255 + 'b', 'a' * 1000, 2) = {osa_band('a' * 255 + 'b', 'a' * 1000, 2)}"
          f"  (unbanded {UNBANDED('a' * 255 + 'b', 'a' * 1000, 2)})")
    use(osa_band)
    print("\n=== A-1: case .24/4 and the security variant (oracle any / oracle boundary / A / R2 boundary)")
    for names in (["DiscouNTCount", "DiscountCount"], ["abcdefg_count", "DiscountCount"]):
        rows = {"oracle any": naive_r2("count", names, 20, "any"), "oracle boundary": naive_r2("count", names, 20, "boundary"),
                "A (step 6 `in`)": A(names).rank("count", 20), "R2 sub=boundary": R2(names, sub="boundary").rank("count", 20)}
        print(f"  {names}, 'count':")
        for k, v in rows.items():
            print(f"    {k:18s} {v}")
    print("\n=== A changes no list: A == naive_r2 (any) on the small fixtures, repeated words included")
    sw_a, ref, ref6 = load()
    small = {n: names_of(REPO / f"examples/case_00_public/{n}") for n in ("BalanceTube_STMicro.a2l", "from_source.a2l", "software_b.a2l")}
    extra = ["value value", "cuvre cuvre", "knife knife 1", "oks ahw ahw", "stop stop watch", "ledring ledring 1 1",
             "timer timer timer", "0 0 0", "x x y", "mian mian class"]
    for label, names in small.items():
        ix = A(names)
        qs = QSET22 + MULTI3 + extra
        diff = sum(ix.rank(q, k) != naive_r2(q, names, k, "any") for q in qs for k in (1, 5, 20))
        print(f"  {label:26s} {len(qs)} queries x 3 limits: {diff} mismatches")
    print("\n=== A == R2 (graph at 15129b64, unbanded) on REF, REF6 and LONG")
    q33, e3s01 = qset33(sw_a, ref)
    rq, r6q, _ = pset(R2(ref6, sub="any"), e3s01)
    for label, names, qs in (("REF", ref, q33 + list(rq.values())), ("REF6", ref6, REF6Q + list(r6q.values())),
                             ("LONG", long_list(ref), list(LONGQ.values()))):
        a, r = A(names), R2(names, sub="any")
        use(osa_band)
        ra = [a.rank(q, 20) for q in qs]
        use(UNBANDED)
        rr = [r.rank(q, 20) for q in qs]
        use(osa_band)
        print(f"  {label:5s} {len(qs):3d} queries: {sum(x != y for x, y in zip(ra, rr))} differences;"
              f" tier/_classify disagreements A {a.tier_disagree}")
        del a, r
        gc.collect()
    print(f"\nload after = {os.getloadavg()}")


def timed(ix, qs, label, fn=osa_band, n=7):
    use(fn)
    print(f"\n=== {label}; limit 20, median of {n}; load {os.getloadavg()}")
    worst = (0.0, None)
    for desc, q in qs.items():
        m, st, out = med(ix, q, 20, n)
        rules = {}
        for r in out or []:
            rules[r[1]] = rules.get(r[1], 0) + 1
        print(f"  {m * 1000:8.1f} ms  {st:3s} chars {len(q.strip()):3d}  {desc}  {rules}")
        worst = max(worst, (m, desc))
    print(f"  worst {worst[0] * 1000:.1f} ms ({worst[1]})")
    use(osa_band)
    return worst


def timing():
    header()
    sw_a, ref, ref6 = load()
    q33, e3s01 = qset33(sw_a, ref)
    a_ref, a_ref6 = A(ref), A(ref6)
    rq, r6q, ty = pset(a_ref6, e3s01)
    with open(EV / "out" / "addenda-pset.txt", "w", encoding="utf-8") as fh:
        fh.write("# PSET of R-A2L-MATCH.40/1 (addenda-probe.py pset()); one repr per line: <list> <tab> <label> <tab> repr(query)\n")
        for d, q in rq.items():
            fh.write(f"REF\t{d}\t{q!r}\n")
        for d, q in r6q.items():
            fh.write(f"REF6\t{d}\t{q!r}\n")
        fh.write(f"# the 51 typos of 'char' (positions 0-3, letters a-z, no REF6 token starts with them): {ty!r}\n")
        for d, q in LONGQ.items():
            fh.write(f"LONG\t{d}\t{q!r}\n")
    print(f"  PSET: {len(rq)} REF queries, {len(r6q)} REF6 queries -> out/addenda-pset.txt")
    w = {}
    w["36 REF"] = timed(a_ref, {q[:40] + ("..." if len(q) > 40 else ""): q for q in q33}, "R-A2L-MATCH.36: QSET over REF (A)")
    w["36 REF6"] = timed(a_ref6, {q: q for q in REF6Q}, "R-A2L-MATCH.36: REF6 queries over REF6 (A)")
    w["40 REF"] = timed(a_ref, rq, "R-A2L-MATCH.40/1: PSET over REF (A)")
    w["40 REF6"] = timed(a_ref6, r6q, "R-A2L-MATCH.40/1: PSET over REF6 (A)")
    r2_ref6 = R2(ref6, sub="any")
    neg = {k: r6q[k] for k in ("'0 ' x 125 + 'chax'", "'c ' x 125 + 'chax'", "'0 ' x 128", "'chr ' x 64")}
    w["40 neg collapse"] = timed(r2_ref6, neg, "R-A2L-MATCH.40 negative control 1: no collapse (R2), REF6")
    del a_ref, a_ref6, r2_ref6
    gc.collect()
    a_long = A(long_list(ref))
    print(f"  LONG: {len(a_long.names)} names (49,900 REF + 100 of 'a' x 1020 + '_' + i)")
    w["40/2 LONG"] = timed(a_long, LONGQ, "R-A2L-MATCH.40/2: LONG, banded _prefix_distance (A)")
    w["40 neg band"] = timed(a_long, LONGQ, "R-A2L-MATCH.40 negative control 2: unbanded _prefix_distance, LONG", fn=UNBANDED)
    print("\n=== summary (worst median per set)")
    for k, (m, d) in w.items():
        print(f"  {k:16s} {m * 1000:8.1f} ms  {d}")
    print(f"\nload after = {os.getloadavg()}")


if __name__ == "__main__":
    {"check": check, "time": timing}[sys.argv[1]]()
