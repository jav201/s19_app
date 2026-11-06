#!/usr/bin/env python3
"""batch-103 Inc 4 E1 pilot v2: can an index meet a tight per-keystroke bound?

THROWAWAY EVIDENCE, NOT PRODUCT CODE. Run on cachyos-rtx only, next to
i4e1-pilot.py (v1), whose naive oracle and rule helpers it loads with runpy.

v1 showed that the rules are implementable without ambiguity (naive == index
on 406 queries) but that the first index is slow on short queries (it resolved
every substring key eagerly) and on many-token or repeated-letter queries (its
fuzzy step scanned every distinct token). v2 changes only the index:
  * tiers are resolved in rank order and stop once `limit` names are found;
  * substring keys use a per-name bitmask of boundary offsets;
  * the fuzzy step walks a trie of the distinct folded tokens with an OSA
    column per node, pruned when the column minimum exceeds the allowed edits;
  * token and fuzzy candidates start from the rarest query token.
It re-checks agreement with v1's naive oracle, then times build and rank on
the same 50,000-name reference list.
"""
from __future__ import annotations

import bisect
import os
import random
import re
import resource
import runpy
import statistics
import sys
import time
from pathlib import Path

HERE = Path(os.environ.get("PILOT_DIR", "/tmp/b103-e1-4"))
P1 = runpy.run_path(str(HERE / "i4e1-pilot.py"), run_name="i4e1_pilot_v1")
naive_rank = P1["naive_rank"]
evaluate = P1["evaluate"]
tokens = P1["tokens"]
fold = P1["fold"]
allowed = P1["allowed"]
is_subseq = P1["is_subseq"]
query_parts = P1["query_parts"]
RULES = P1["RULES"]
_mask = P1["_mask"]
names_of = P1["names_of"]
REPO = P1["REPO"]
OUT = P1["OUT"]
s19_app = P1["s19_app"]

_SEP_RE = re.compile(r"[\x00-\x2f\x3a-\x40\x5b-\x60\x7b-\x7f]")
_END = "\0"  # terminal key in the trie; never a token character


class Index2:
    def __init__(self, names):
        self.names = list(dict.fromkeys(names))
        self.folded = [fold(n) for n in self.names]
        self.nmask = [_mask(nf) for nf in self.folded]
        self.ntoks = []
        self.bound = []
        inv: dict = {}
        for i, n in enumerate(self.names):
            nf = self.folded[i]
            sp = tokens(n)
            toks = tuple(nf[s:e] for s, e in sp)
            self.ntoks.append(toks)
            b = 1
            for s, _ in sp:
                b |= 1 << s
            for m in _SEP_RE.finditer(nf):
                b |= 1 << m.start()
            self.bound.append(b)
            for t in set(toks):
                inv.setdefault(t, []).append(i)
        self.inv = inv
        self.utok = sorted(inv)
        root: dict = {}
        for t in self.utok:
            node = root
            for c in t:
                node = node.setdefault(c, {})
            node[_END] = t
        self.trie = root

    # --- helpers ----------------------------------------------------------
    def _prefix_tokens(self, qt):
        lo = bisect.bisect_left(self.utok, qt)
        out = []
        for t in self.utok[lo:]:
            if not t.startswith(qt):
                break
            out.append(t)
        return out

    @staticmethod
    def _subtree(node, best, res):
        stack = [node]
        while stack:
            nd = stack.pop()
            for c, child in nd.items():
                if c == _END:
                    res[child] = best
                else:
                    stack.append(child)

    def _trie_search(self, q, k):
        m = len(q)
        res: dict = {}
        col0 = list(range(m + 1))
        stack = [(self.trie, col0, None, "", 0, m)]
        while stack:
            node, prev, prev2, pchar, j, best = stack.pop()
            for c, child in node.items():
                if c == _END:
                    continue
                jj = j + 1
                new = [jj] + [0] * m
                for i in range(1, m + 1):
                    qi = q[i - 1]
                    v = prev[i - 1] + (0 if qi == c else 1)
                    a = prev[i] + 1
                    if a < v:
                        v = a
                    a = new[i - 1] + 1
                    if a < v:
                        v = a
                    if i > 1 and jj > 1 and qi == pchar and q[i - 2] == c:
                        a = prev2[i - 2] + 1
                        if a < v:
                            v = a
                    new[i] = v
                b2 = best if best < new[m] else new[m]
                lo = min(new)
                if _END in child and b2 <= k:
                    res[child[_END]] = b2
                if lo > k or lo >= b2:
                    if b2 <= k:
                        self._subtree(child, b2, res)
                    continue
                stack.append((child, new, prev, c, jj, b2))
        return res

    def _case_exact(self, query, q, name, rule):
        if rule == 0:
            return name == q
        if rule == 1:
            return name.startswith(q)
        if rule == 2:
            return q in name
        ce = evaluate(query, name, folded=False)
        return ce is not None and ce[0] == rule

    # --- rank -------------------------------------------------------------
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
            if found < limit:
                kmask = _mask(keys)
                nmask = self.nmask
                for i, nf in enumerate(folded):
                    if kmask & ~nmask[i] or i in taken:
                        continue
                    if is_subseq(keys, nf) is not None:
                        groups.setdefault((4, 0, len(names[i])), []).append(i)
                        taken.add(i)
                        found += 1
            if found < limit and qtoks:
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
                            groups.setdefault((5, total, len(names[i])), []).append(i)
        out = []
        for gk in sorted(groups):
            keyed = sorted(
                (0 if self._case_exact(query, q, names[i], gk[0]) else 1, names[i]) for i in groups[gk]
            )
            for _, name in keyed:
                ev = evaluate(query, name)
                out.append((name, RULES[ev[0]], ev[1], ev[2]))
                if len(out) >= limit:
                    return out
        return out


def main() -> int:
    print(f"s19_app.__file__ = {s19_app.__file__}")
    print(f"python = {sys.version.split()[0]}")
    print(f"host = {os.uname().nodename}  load = {os.getloadavg()}  cpus = {os.cpu_count()}")
    print(f"HOME = {os.environ.get('HOME')}  LOCALAPPDATA = {os.environ.get('LOCALAPPDATA')}")
    case08 = names_of(OUT / "firmware.a2l")
    sw_a = names_of(REPO / "examples/case_00_public/software_a.a2l")
    sw_b = names_of(REPO / "examples/case_00_public/software_b.a2l")
    bal = names_of(REPO / "examples/case_00_public/BalanceTube_STMicro.a2l")
    src = names_of(REPO / "examples/case_00_public/from_source.a2l")

    print("\n=== 1. v2 index vs v1 naive oracle (same pool and queries as v1, seed 20261106)")
    rng = random.Random(20261106)
    pool = sorted(set(rng.sample(sw_a, 600) + rng.sample(bal, 60) + rng.sample(src, 40) + rng.sample(sw_b, 40) + case08[:200] + ["RPM", "rpm", "Drück_Max", "DRÜCK_MAX"]))
    idx = Index2(pool)

    def mutate(name: str) -> str:
        toks = [name[a:b] for a, b in tokens(name)] or [name]
        r = rng.random()
        if r < 0.15:
            return name
        if r < 0.3:
            return name[: rng.randint(1, len(name))]
        if r < 0.45:
            a = rng.randint(0, len(name) - 1)
            return name[a : a + rng.randint(1, 8)]
        if r < 0.6:
            return " ".join(rng.sample(toks, min(len(toks), rng.randint(1, 3)))).lower()
        if r < 0.7:
            return "".join(t[0] for t in toks[: rng.randint(1, 4)] if t)
        s = list(name[: rng.randint(3, min(len(name), 14))])
        op = rng.randint(0, 3)
        p = rng.randrange(len(s))
        if op == 0:
            s[p] = rng.choice("abcxyz0123")
        elif op == 1 and len(s) > 1:
            del s[p]
        elif op == 2:
            s.insert(p, rng.choice("abcxyz"))
        elif p + 1 < len(s):
            s[p], s[p + 1] = s[p + 1], s[p]
        return "".join(s)

    queries = [mutate(rng.choice(pool)) for _ in range(400)] + ["", "_", "zzzzqqq", "q", "AB", "1", "qqqq zzzz", "aaaa", "e e e"]
    bad = 0
    for qy in queries:
        full = naive_rank(qy, pool, 100000)
        for lim in (1, 5, 50, 100000):
            if full[:lim] != idx.rank(qy, lim):
                bad += 1
                if bad <= 5:
                    print(f"  MISMATCH query={qy!r} limit={lim}")
    print(f"  pool {len(pool)} names, {len(queries)} queries x 4 limits: mismatches = {bad}")

    print("\n=== 2. timing on the 50,000-name reference list")
    ref = (sw_a + [n + "_1" for n in sw_a] + [n + "_2" for n in sw_a] + [n + "_3" for n in sw_a])[:50000]
    rss0 = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    builds = []
    for _ in range(3):
        t0 = time.perf_counter()
        big = Index2(ref)
        builds.append(time.perf_counter() - t0)
    rss1 = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    print(f"  reference list: {len(ref)} names (software_a, then +_1, +_2, +_3), unique {len(set(ref))}, distinct tokens {len(big.utok)}")
    print(f"  build: {[round(b, 3) for b in builds]} s  median {statistics.median(builds):.3f} s  max-RSS growth ~{(rss1 - rss0) / 1024:.0f} MiB")
    sample = sw_a[1234]
    stoks = [sample[a:b] for a, b in tokens(sample)]
    tq = [
        "a", "e", "0", "zz", "ab", sample, sample[:12], sample[10:18], " ".join(stoks[-1:] + stoks[:1]).lower(),
        "".join(t[0] for t in stoks[:4]), "xqzjvkw", "qqqq zzzz", "aaaa", "e e e", "Nzukij", "Ierxjr_Eud",
        "ledRing", "pposbxiif", "cnt", "temp_sensor_max", "x y z w v u", "pposbxiifkdgfiajnbbpvb_dyan_xvz1",
    ]
    print(f"  sample name software_a[1234] = {sample!r}")
    summary = {}
    for lim in (20, 100):
        worst = (0.0, "")
        for qy in tq:
            runs = []
            for _ in range(7):
                t0 = time.perf_counter()
                res = big.rank(qy, lim)
                runs.append(time.perf_counter() - t0)
            med = statistics.median(runs) * 1000
            if med > worst[0]:
                worst = (med, qy)
            hist = {}
            for row in res:
                hist[row[1]] = hist.get(row[1], 0) + 1
            print(f"  limit={lim:4d} query={qy!r:40s} median {med:7.1f} ms  max {max(runs) * 1000:7.1f} ms  results {len(res):4d} {hist}")
        summary[lim] = worst
        print(f"  limit={lim}: worst median over {len(tq)} queries = {worst[0]:.1f} ms (query {worst[1]!r})")
    print(f"\nload at end = {os.getloadavg()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
