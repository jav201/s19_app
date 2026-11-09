#!/usr/bin/env python3
"""batch-103 Inc 4 E1 pilot v3: the RECOMMENDED design (rule order B, decision D-3).

THROWAWAY EVIDENCE, NOT PRODUCT CODE. Run on <runner> next to i4e1-pilot.py
(v1) and i4e1-pilot2.py (v2). Order B: exact > prefix > substring > token >
fuzzy > subsequence (v1/v2 used the handoff order A, with subsequence before
fuzzy; i4e1-order-eval-transcript.txt measured both).
  * evaluate_b / naive_rank_b -- v1's definitional oracle with the two last
    rules swapped (the oracle of every expected result in 02-test-cases.md);
  * IndexB -- v2's index with the two last tiers swapped;
  * agreement check IndexB == naive_rank_b, the curated and black-box
    examples, and the timing of R-A2L-MATCH.35 / .36 on the reference list.
"""
from __future__ import annotations

import os
import random
import resource
import runpy
import statistics
import sys
import time
from pathlib import Path

HERE = Path(os.environ.get("PILOT_DIR", "/tmp/b103-e1-4"))
P2 = runpy.run_path(str(HERE / "i4e1-pilot2.py"), run_name="i4e1_pilot_v2")
Index2 = P2["Index2"]
P1 = P2["P1"]
tokens, fold, allowed, is_subseq, query_parts, merge = (
    P1["tokens"], P1["fold"], P1["allowed"], P1["is_subseq"], P1["query_parts"], P1["merge"])
osa_prefix, names_of, REPO, OUT, s19_app, _mask, _sep = (
    P1["osa_prefix"], P1["names_of"], P1["REPO"], P1["OUT"], P1["s19_app"], P1["_mask"], P1["_sep"])

RULES_B = ("exact", "prefix", "substring", "token", "fuzzy", "subsequence")


def evaluate_b(query: str, name: str, folded: bool = True):
    """(rule index in RULES_B, rule key, spans) of the first rule in order B, or None."""
    q, qq, qtoks, keys = query_parts(query, folded)
    if not keys:
        return None
    nn = fold(name) if folded else name
    ntok = [(nn[s:e], s, e) for s, e in tokens(name)]
    if nn == qq:
        return (0, 0, [(0, len(nn))])
    if nn.startswith(qq):
        return (1, 0, [(0, len(qq))])
    if qq in nn:
        bounds = {0} | {s for _, s, _ in ntok} | {i for i, c in enumerate(nn) if _sep(c)}
        occ = []
        p = nn.find(qq)
        while p >= 0:
            occ.append(p)
            p = nn.find(qq, p + 1)
        at = [p for p in occ if p in bounds]
        p = at[0] if at else occ[0]
        return (2, 0 if at else 1, [(p, p + len(qq))])
    if qtoks:
        spans = []
        ok = True
        for qt in qtoks:
            hit = next(((s, s + len(qt)) for t, s, _ in ntok if t.startswith(qt)), None)
            if hit is None:
                ok = False
                break
            spans.append(hit)
        if ok:
            return (3, 0, merge(spans))
    if qtoks and ntok:
        total = 0
        spans = []
        ok = True
        for qt in qtoks:
            best = None
            for t, s, e in ntok:
                d = osa_prefix(qt, t)
                if best is None or d < best[0]:
                    best = (d, s, e)
            if best[0] > allowed(qt):
                ok = False
                break
            total += best[0]
            spans.append((best[1], best[2]))
        if ok:
            return (4, total, merge(spans))
    pos = is_subseq(keys, nn)
    if pos is not None:
        return (5, 0, merge([(p, p + 1) for p in pos]))
    return None


def naive_rank_b(query: str, names, limit: int) -> list:
    if limit < 1:
        return []
    rows = []
    for name in dict.fromkeys(names):
        ev = evaluate_b(query, name)
        if ev is None:
            continue
        ce = evaluate_b(query, name, folded=False)
        case_exact = ce is not None and ce[0] == ev[0]
        rows.append(((ev[0], ev[1], len(name), 0 if case_exact else 1, name), ev))
    rows.sort(key=lambda r: r[0])
    return [(r[0][4], RULES_B[r[1][0]], r[1][1], r[1][2]) for r in rows[:limit]]


class IndexB(Index2):
    def _case_exact(self, query, q, name, rule):
        if rule == 0:
            return name == q
        if rule == 1:
            return name.startswith(q)
        if rule == 2:
            return q in name
        ce = evaluate_b(query, name, folded=False)
        return ce is not None and ce[0] == rule

    def rank(self, query: str, limit: int) -> list:
        if limit < 1:
            return []
        q, qf, qtoks, keys = query_parts(query, True)
        if not keys:
            return []
        names, folded = self.names, self.folded
        exact, prefix, subs = [], [], []
        lq = len(qf)
        for i, nf in enumerate(folded):
            if qf in nf:
                if nf.startswith(qf):
                    (exact if len(nf) == lq else prefix).append(i)
                else:
                    subs.append(i)
        groups: dict = {}
        for i in exact:
            groups.setdefault((0, 0, len(names[i])), []).append(i)
        for i in prefix:
            groups.setdefault((1, 0, len(names[i])), []).append(i)
        found = len(exact) + len(prefix)
        if found < limit and subs:
            for i in subs:
                nf = folded[i]
                b = self.bound[i]
                key = 1
                p = nf.find(qf)
                while p >= 0:
                    if (b >> p) & 1:
                        key = 0
                        break
                    p = nf.find(qf, p + 1)
                groups.setdefault((2, key, len(names[i])), []).append(i)
            found += len(subs)
        if found < limit:
            taken = set(exact)
            taken.update(prefix)
            taken.update(subs)
            per = [self._prefix_tokens(qt) for qt in qtoks]
            if per and all(per):
                sizes = [sum(len(self.inv[t]) for t in ts) for ts in per]
                r = min(range(len(per)), key=sizes.__getitem__)
                cand = set()
                for t in per[r]:
                    cand.update(self.inv[t])
                cand -= taken
                others = [qt for jx, qt in enumerate(qtoks) if jx != r]
                for i in cand:
                    toks = self.ntoks[i]
                    if all(any(t.startswith(qt) for t in toks) for qt in others):
                        groups.setdefault((3, 0, len(names[i])), []).append(i)
                        taken.add(i)
                        found += 1
            if found < limit and qtoks:  # tier 4: fuzzy
                dists = []
                for qt in qtoks:
                    k = allowed(qt)
                    d = {t: 0 for t in self._prefix_tokens(qt)} if k == 0 else self._trie_search(qt, k)
                    if not d:
                        dists = []
                        break
                    dists.append(d)
                if dists:
                    sizes = [sum(len(self.inv[t]) for t in d) for d in dists]
                    r = min(range(len(dists)), key=sizes.__getitem__)
                    cand = set()
                    for t in dists[r]:
                        cand.update(self.inv[t])
                    cand -= taken
                    for i in cand:
                        total = 0
                        ok = True
                        for d in dists:
                            best = None
                            for t in self.ntoks[i]:
                                v = d.get(t)
                                if v is not None and (best is None or v < best):
                                    best = v
                            if best is None:
                                ok = False
                                break
                            total += best
                        if ok:
                            groups.setdefault((4, total, len(names[i])), []).append(i)
                            taken.add(i)
                            found += 1
            if found < limit:  # tier 5: subsequence
                kmask = _mask(keys)
                nmask = self.nmask
                for i, nf in enumerate(folded):
                    if kmask & ~nmask[i] or i in taken:
                        continue
                    if is_subseq(keys, nf) is not None:
                        groups.setdefault((5, 0, len(names[i])), []).append(i)
        out = []
        for gk in sorted(groups):
            keyed = sorted(
                (0 if self._case_exact(query, q, names[i], gk[0]) else 1, names[i]) for i in groups[gk]
            )
            for _, name in keyed:
                ev = evaluate_b(query, name)
                out.append((name, RULES_B[ev[0]], ev[1], ev[2]))
                if len(out) >= limit:
                    return out
        return out


def show(label, names, q, lim):
    rows = naive_rank_b(q, names, lim)
    print(f"[{label}] query={q!r} limit={lim}")
    if not rows:
        print("    (empty)")
    for name, rule, key, spans in rows:
        print(f"    {name!r:56s} {rule:11s} edits/key={key} spans={spans}")


def main() -> int:
    print(f"s19_app.__file__ = {s19_app.__file__}")
    print(f"python = {sys.version.split()[0]}")
    print(f"host = {os.uname().nodename}  load = {os.getloadavg()}  cpus = {os.cpu_count()}")
    print(f"HOME = {os.environ.get('HOME')}  LOCALAPPDATA = {os.environ.get('LOCALAPPDATA')}")
    case08 = names_of(OUT / "firmware.a2l")
    issues = names_of(OUT / "firmware_issues.a2l")
    sw_a = names_of(REPO / "examples/case_00_public/software_a.a2l")
    sw_b = names_of(REPO / "examples/case_00_public/software_b.a2l")
    bal = names_of(REPO / "examples/case_00_public/BalanceTube_STMicro.a2l")
    src = names_of(REPO / "examples/case_00_public/from_source.a2l")
    print(f"names: case08 {len(case08)}  case08_issues {len(issues)}  software_a {len(sw_a)}  software_b {len(sw_b)}  BalanceTube {len(bal)}  from_source {len(src)}")

    print("\n=== 1. examples of 02-test-cases.md under order B (naive oracle)")
    cur = ["ABSValue", "AValue", "engineSpeed", "Map3D"]
    nonascii = ["Drück_Max", "DRÜCK_MAX", "druck_max"]
    ex = [
        ("C08", case08, "  VALUE_0001  ", 20), ("C08", case08, "\tVALUE_0001\n", 20), ("C08", case08, " value_000 ", 5),
        ("C08", case08, "", 20), ("C08", case08, "   ", 20), ("C08", case08, "\t\n", 20), ("C08", case08, "_", 20), ("C08", case08, "._[]", 20),
        ("C08", case08, "value_0001", 20), ("C08", case08, "Value_0001", 20), ("twins", ["RPM", "rpm", "Rpm"], "rpm", 20),
        ("nonascii", nonascii, "drück", 20), ("nonascii", nonascii, "DRÜCK", 20), ("C08", case08, "VALUE-0001", 20),
        ("C08", case08, "VALUE_0001", 20), ("C08", case08, "map_0020", 20),
        ("C08", case08, "value_000", 5), ("C08i", issues, "span", 20), ("C08i", issues, "LIMIT", 20),
        ("C08", case08, "0001", 20), ("SRC", src, "knife[1]", 20), ("SRC", src, "[0].Spoon", 20), ("BAL", bal, "ledRing[1]", 4),
        ("C08", case08, "blk val 00", 3), ("BAL", bal, "stop watch", 20), ("SWB", sw_b, "oks ahw", 20), ("SRC", src, "knife 1 x", 20),
        ("C08i", issues, "out range", 20), ("SRC", src, "knife.*", 4), ("cur", cur, "a value", 20), ("cur", cur, "map 3 d", 20),
        ("cur", cur, "abs value", 20), ("C08", case08, "VALUE_0001_VALUE_0001", 20),
        ("C08", case08, "mp", 3), ("C08", case08, "ascii 1", 20), ("C08", case08, "map 2", 20), ("BAL", bal, "gamecontroller timer", 3),
        ("C08", case08, "map 20", 20),
        ("C08", case08, "cuvre", 3), ("C08", case08, "maesurement_0001", 20), ("C08", case08, "vlaue_0001", 20), ("C08", case08, "mpa", 3),
        ("C08", case08, "xmap", 3), ("C08", case08, "maq", 3), ("C08", case08, "measurementss_0001", 20), ("C08", case08, "vblk", 2),
        ("C08", case08, "VALUE_0300", 20), ("cur1", ["BA_X"], "ab", 20), ("cur1", ["abc"], "ca", 20), ("C08", case08, "cvure", 20),
        ("C08", case08, "valuexx_0001", 20), ("C08", case08, "valuexxx_0001", 20), ("cur2", ["CUVE", "CURVE_0001"], "curvee", 20),
        ("C08", case08, "value_000", 100), ("C08", case08, "0001", 100), ("C08", case08, "temp_sensor_max", 20),
        ("blank", ["", "   ", "VALUE_0001"], "v", 20), ("C08", case08, "value_000", 20), ("C08", case08, "valu_0001", 20),
        ("C08", case08, "vale_0001", 20), ("C08i", issues, "VALUE_0001", 20), ("C08i", issues, "value_000", 20),
        ("C08", case08, "value_000", 1), ("C08", case08, "VALUE", 0), ("C08", case08, "VALUE", -1),
        ("BAL", bal, "gamecontroller.timer", 20), ("cur3", ["timeCounter", "Encounter"], "counter", 20), ("C08", case08, "_0001", 20),
        ("BAL", bal, "ounter", 4), ("cur4", ["rpm_x", "RPMX"], "rpm", 20), ("twins", ["RPM", "rpm", "Rpm"], "RPM", 20),
        ("C08rev", list(reversed(case08)), "0001", 20), ("twins2", ["Rpm", "rpm", "RPM"], "rpm", 20),
        ("cur5", ["DiscountCount"], "count", 20), ("SWB", sw_b, "sahw", 20), ("C08", case08, "maesu", 3), ("cur6", ["Curve_Map_X"], "cuvre maq", 20),
    ]
    for c in ex:
        show(*c)

    print("\n=== 2. black-box examples under order B")
    print("AT-B103-I4-1: typing over case08, limit 5")
    for qy in ["m", "ma", "map", "map_", "map_00", "map_002", "map_0020"]:
        show("C08", case08, qy, 5)
    print("AT-B103-I4-2: start, middle, end, words, typo over software_a, limit 5")
    target = sw_a[1234]
    print(f"target software_a[1234] = {target!r}")
    for qy in [target, "jotafvod", "msrqlLzL", "pfue._0_", "jotaf vod", "vod jotaf", "jotfa vod", "jotaf_vdo"]:
        rows = naive_rank_b(qy, sw_a, 5)
        pos = next((i for i, r in enumerate(rows) if r[0] == target), None)
        print(f"[software_a] query={qy!r} limit=5  target position = {pos}  target entry = {rows[pos] if pos is not None else None}")

    print("\n=== 3. IndexB vs naive_rank_b (v1 pool and queries, seed 20261106)")
    rng = random.Random(20261106)
    pool = sorted(set(rng.sample(sw_a, 600) + rng.sample(bal, 60) + rng.sample(src, 40) + rng.sample(sw_b, 40) + case08[:200] + ["RPM", "rpm", "Drück_Max", "DRÜCK_MAX"]))
    idx = IndexB(pool)
    qs = []
    for _ in range(400):
        name = rng.choice(pool)
        toks = [name[a:b] for a, b in tokens(name)] or [name]
        r = rng.random()
        if r < 0.2:
            qs.append(name[: rng.randint(1, len(name))])
        elif r < 0.4:
            a = rng.randint(0, len(name) - 1)
            qs.append(name[a : a + rng.randint(1, 8)])
        elif r < 0.6:
            qs.append(" ".join(rng.sample(toks, min(len(toks), rng.randint(1, 3)))).lower())
        elif r < 0.7:
            qs.append("".join(t[0] for t in toks[: rng.randint(1, 4)] if t))
        else:
            s = list(name[: rng.randint(3, min(len(name), 14))])
            p = rng.randrange(len(s))
            op = rng.randint(0, 2)
            if op == 0:
                s[p] = rng.choice("abcxyz0123")
            elif op == 1 and len(s) > 1:
                del s[p]
            else:
                s.insert(p, rng.choice("abcxyz"))
            qs.append("".join(s))
    qs += ["", "_", "zzzzqqq", "q", "AB", "1", "qqqq zzzz", "aaaa", "e e e"]
    bad = 0
    for qy in qs:
        full = naive_rank_b(qy, pool, 100000)
        for lim in (1, 5, 50, 100000):
            if full[:lim] != idx.rank(qy, lim):
                bad += 1
                if bad <= 5:
                    print(f"  MISMATCH query={qy!r} limit={lim}")
    print(f"  pool {len(pool)} names, {len(qs)} queries x 4 limits: mismatches = {bad}")

    print("\n=== 4. timing (R-A2L-MATCH.35, .36) on the reference list")
    ref = (sw_a + [n + "_1" for n in sw_a] + [n + "_2" for n in sw_a] + [n + "_3" for n in sw_a])[:50000]
    rss0 = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    builds = []
    for _ in range(3):
        t0 = time.perf_counter()
        big = IndexB(ref)
        builds.append(time.perf_counter() - t0)
    rss1 = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    print(f"  reference list {len(ref)} names, unique {len(set(ref))}, distinct tokens {len(big.utok)}")
    print(f"  build: {[round(b, 3) for b in builds]} s  median {statistics.median(builds):.3f} s  max-RSS growth ~{(rss1 - rss0) / 1024:.0f} MiB")
    tq = ["a", "e", "0", "zz", "ab", "JotafVod_msrqlLzL_kh2C_rWl_pfue._0_", "JotafVod_msr", "srqlLzL_", "0 jotaf", "JVmL",
          "xqzjvkw", "qqqq zzzz", "aaaa", "e e e", "Nzukij", "Ierxjr_Eud", "ledRing", "pposbxiif", "cnt", "temp_sensor_max",
          "x y z w v u", "pposbxiifkdgfiajnbbpvb_dyan_xvz1"]
    worst = (0.0, "")
    for qy in tq:
        runs = []
        for _ in range(7):
            t0 = time.perf_counter()
            res = big.rank(qy, 20)
            runs.append(time.perf_counter() - t0)
        med = statistics.median(runs) * 1000
        if med > worst[0]:
            worst = (med, qy)
        hist = {}
        for row in res:
            hist[row[1]] = hist.get(row[1], 0) + 1
        print(f"  limit=20 query={qy!r:40s} median {med:7.1f} ms  max {max(runs) * 1000:7.1f} ms  results {len(res):3d} {hist}")
    print(f"  limit=20: worst median over {len(tq)} queries = {worst[0]:.1f} ms (query {worst[1]!r})")
    print(f"\nload at end = {os.getloadavg()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
