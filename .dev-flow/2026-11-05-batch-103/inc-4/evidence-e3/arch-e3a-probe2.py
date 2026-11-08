#!/usr/bin/env python3
"""batch-103 Inc 4 E3 architect probe 2 (THROWAWAY): candidate fixes for the
cost drivers probe 1 found, measured on REF and on case_06's first 50,000 names.

Variants of the pilot's IndexC.rank (i4e2-pilot4.py), same tiers:
  ce   = "pilot" : case-exactness as the pilot (string checks for exact/prefix/
                   substring, a raw evaluate_b for token/fuzzy/subsequence)
         "text3" : string checks for exact/prefix/substring; token/fuzzy/
                   subsequence names are never case-exact (rows change)
         "none"  : no case-exactness at all (R-A2L-MATCH.24 removed)
  fz   = "all"   : the pilot's fuzzy tier (a map per query token, then the check)
         "lazy"  : maps in ascending cost (k = 0, 1, 2), candidates intersected
                   after each; once at most CAND_MAX candidates remain, the other
                   query tokens are checked per candidate (memoised osa_prefix)
"lazy" must give the same lists as "all" for the same ce (asserted).
"""
from __future__ import annotations

import gc
import os
import random
import runpy
import statistics
import sys
import time
from pathlib import Path

HERE = Path(os.environ["PILOT_DIR"])
P4 = runpy.run_path(str(HERE / "i4e2-pilot4.py"), run_name="i4e2_pilot_v4")
IndexC, evaluate_b, RULES_B = P4["IndexC"], P4["evaluate_b"], P4["RULES_B"]
tokens, names_of, REPO, s19_app = P4["tokens"], P4["names_of"], P4["REPO"], P4["s19_app"]
allowed, is_subseq, query_parts = P4["allowed"], P4["is_subseq"], P4["query_parts"]
prefix_range, fuzzy_walk, at_boundary, _mask = P4["prefix_range"], P4["fuzzy_walk"], P4["at_boundary"], P4["_mask"]
osa_prefix = P4["P1"]["osa_prefix"]
CAND_MAX = 300


class V(IndexC):
    def __init__(self, names, ce="pilot", fz="all"):
        super().__init__(names)
        self.ce, self.fz = ce, fz

    def _ce(self, query, q, name, rule):
        if self.ce == "none":
            return False
        if rule == 0:
            return name == q
        if rule == 1:
            return name.startswith(q)
        if rule == 2:
            return q in name
        if self.ce == "text3":
            return False
        ce = evaluate_b(query, name, folded=False)
        return ce is not None and ce[0] == rule

    def _fuzzy(self, qtoks, taken):
        utok, post, poff, ntid, noff = self.utok, self.post, self.poff, self.ntid, self.noff
        if self.fz == "all":
            dists = []
            for qt in qtoks:
                k = allowed(qt)
                if k == 0:
                    lo, hi = prefix_range(utok, qt)
                    d = dict.fromkeys(range(lo, hi), 0)
                else:
                    d = fuzzy_walk(utok, self.nodes, qt, k)
                if not d:
                    return {}
                dists.append(d)
            sizes = [sum(poff[t + 1] - poff[t] for t in d) for d in dists]
            r = min(range(len(dists)), key=sizes.__getitem__)
            cand = set()
            for t in dists[r]:
                cand.update(post[poff[t]:poff[t + 1]])
            cand -= taken
            out = {}
            for i in cand:
                ids = ntid[noff[i]:noff[i + 1]]
                total = 0
                for d in dists:
                    bst = None
                    for t in ids:
                        v = d.get(t)
                        if v is not None and (bst is None or v < bst):
                            bst = v
                    if bst is None:
                        break
                    total += bst
                else:
                    out[i] = total
            return out
        info = [(qt, allowed(qt)) for qt in qtoks]
        order = sorted(range(len(info)), key=lambda j: info[j][1])
        dists = [None] * len(info)
        cand = None
        for j in order:
            if cand is not None and len(cand) <= CAND_MAX:
                break
            qt, k = info[j]
            if k == 0:
                lo, hi = prefix_range(utok, qt)
                d = dict.fromkeys(range(lo, hi), 0)
            else:
                d = fuzzy_walk(utok, self.nodes, qt, k)
            if not d:
                return {}
            dists[j] = d
            have = set()
            for t in d:
                have.update(post[poff[t]:poff[t + 1]])
            cand = (have - taken) if cand is None else (cand & have)
            if not cand:
                return {}
        memo = [dict() for _ in info]
        out = {}
        for i in cand:
            ids = ntid[noff[i]:noff[i + 1]]
            total = 0
            for j, (qt, k) in enumerate(info):
                d = dists[j]
                bst = None
                for t in ids:
                    if d is not None:
                        v = d.get(t)
                    else:
                        v = memo[j].get(t)
                        if v is None:
                            v = memo[j][t] = osa_prefix(qt, utok[t])
                        if v > k:
                            v = None
                    if v is not None and (bst is None or v < bst):
                        bst = v
                if bst is None:
                    break
                total += bst
            else:
                out[i] = total
        return out

    def rank(self, query, limit):
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
        groups = {}
        for i in exact:
            groups.setdefault((0, 0, len(names[i])), []).append(i)
        for i in prefix:
            groups.setdefault((1, 0, len(names[i])), []).append(i)
        found = len(exact) + len(prefix)
        if found < limit and subs:
            for i in subs:
                nf, nm, key = folded[i], names[i], 1
                p = nf.find(qf)
                while p >= 0:
                    if at_boundary(nm, p):
                        key = 0
                        break
                    p = nf.find(qf, p + 1)
                groups.setdefault((2, key, len(nm)), []).append(i)
            found += len(subs)
        if found < limit:
            taken = set(exact)
            taken.update(prefix)
            taken.update(subs)
            utok, post, poff = self.utok, self.post, self.poff
            ranges = [prefix_range(utok, qt) for qt in qtoks]
            if ranges and all(lo < hi for lo, hi in ranges):
                order = sorted(range(len(ranges)), key=lambda j: poff[ranges[j][1]] - poff[ranges[j][0]])
                lo, hi = ranges[order[0]]
                cand = set(post[poff[lo]:poff[hi]])
                cand -= taken
                for j in order[1:]:
                    if not cand:
                        break
                    lo, hi = ranges[j]
                    cand.intersection_update(post[poff[lo]:poff[hi]])
                for i in cand:
                    groups.setdefault((3, 0, len(names[i])), []).append(i)
                taken |= cand
                found += len(cand)
            if found < limit and qtoks:
                for i, total in self._fuzzy(qtoks, taken).items():
                    groups.setdefault((4, total, len(names[i])), []).append(i)
                    taken.add(i)
                    found += 1
            if found < limit:
                kmask = _mask(keys)
                nmask = self.nmask
                for i in range(len(folded)):
                    if kmask & ~nmask[i] or i in taken:
                        continue
                    if is_subseq(keys, folded[i]) is not None:
                        groups.setdefault((5, 0, len(names[i])), []).append(i)
        out = []
        for gk in sorted(groups):
            keyed = sorted((0 if self._ce(query, q, names[i], gk[0]) else 1, names[i]) for i in groups[gk])
            for _, name in keyed:
                ev = evaluate_b(query, name)
                out.append((name, RULES_B[ev[0]], ev[1], ev[2]))
                if len(out) >= limit:
                    return out
        return out


def med_ms(idx, q, lim=20, n=7):
    runs = []
    for _ in range(n):
        t0 = time.perf_counter()
        idx.rank(q, lim)
        runs.append(time.perf_counter() - t0)
    return statistics.median(runs) * 1000


def main() -> int:
    print(f"s19_app.__file__ = {s19_app.__file__}")
    print(f"python = {sys.version.split()[0]}  host = {os.uname().nodename}  cpus = {os.cpu_count()}")
    print(f"load before = {os.getloadavg()}")
    sw_a = names_of(REPO / "examples/case_00_public/software_a.a2l")
    ref = (sw_a + [n + "_1" for n in sw_a] + [n + "_2" for n in sw_a] + [n + "_3" for n in sw_a])[:50000]
    c6 = names_of(REPO / "examples/case_06_large_nested_a2l/firmware.a2l")[:50000]
    qset = ["a", "e", "0", "zz", "ab", "JotafVod_msrqlLzL_kh2C_rWl_pfue._0_", "JotafVod_msr", "srqlLzL_", "0 jotaf", "JVmL",
            "xqzjvkw", "qqqq zzzz", "aaaa", "e e e", "Nzukij", "Ierxjr_Eud", "ledRing", "pposbxiif", "cnt", "temp_sensor_max",
            "x y z w v u", "pposbxiifkdgfiajnbbpvb_dyan_xvz1"]
    rng = random.Random(20261108)
    cands = [n for n in sw_a if sum(1 for s, e in tokens(n) if e - s >= 6 and n[s].isalpha()) >= 6]
    multi = []
    for name in rng.sample(cands, 4):
        words = [name[s:e].lower() for s, e in tokens(name) if e - s >= 6]
        for nw in (4, 5, 6):
            w = words[:nw]
            multi.append(" ".join(x[:2] + x[3] + x[2] + x[4:] for x in w))
    rng2 = random.Random(20261109)
    labels = []
    for n in rng2.sample(ref, 100):
        p = rng2.randrange(1, len(n) - 1)
        labels.append(n[:p] + ("x" if n[p] != "x" else "q") + n[p + 1:])
    c6q = ["m", "me", "meas", "meas_", "c", "chr", "mesa", "cahr", "char 1", "meas 12", "0", "00", "char_", "cr0", "c 1 2"]
    sets = {"REF": (ref, qset + multi), "C06": (c6, c6q)}
    for label, (names, queries) in sets.items():
        print(f"\n=== {label} ({len(names)} names), limit 20, median of 7 per query; load {os.getloadavg()}")
        idx = {}
        for ce in ("pilot", "text3", "none"):
            for fz in ("all", "lazy"):
                idx[(ce, fz)] = V(names, ce, fz)
        worst = {key: (0.0, "") for key in idx}
        for q in queries:
            cells = []
            for key, ix in idx.items():
                if key[1] == "lazy":
                    assert ix.rank(q, 20) == idx[(key[0], "all")].rank(q, 20), (label, key, q)
                ms = med_ms(ix, q)
                worst[key] = max(worst[key], (ms, q))
                cells.append(f"{key[0]}/{key[1]} {ms:6.1f}")
            print(f"  {' | '.join(cells)}  query={q!r}")
        for key, (ms, q) in worst.items():
            print(f"  worst {key[0]:5s}/{key[1]:4s} = {ms:7.1f} ms  query={q!r}")
        if label == "REF":
            print(f"  paste-modal workload (100 labels, limit 3); load {os.getloadavg()}")
            for key in (("pilot", "all"), ("pilot", "lazy"), ("text3", "lazy")):
                per = []
                for lab in labels:
                    t0 = time.perf_counter()
                    idx[key].rank(lab, 3)
                    per.append(time.perf_counter() - t0)
                print(f"    {key[0]}/{key[1]}: total {sum(per):.2f} s  median {statistics.median(per) * 1000:.1f} ms  max {max(per) * 1000:.1f} ms")
        del idx
        gc.collect()
    print(f"\nload after = {os.getloadavg()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
