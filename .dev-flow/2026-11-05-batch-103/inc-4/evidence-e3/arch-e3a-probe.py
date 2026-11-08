#!/usr/bin/env python3
"""batch-103 Inc 4 E3 architect probe (THROWAWAY; not evidence of record).

Loads the E2 pilot v4 (IndexC) and the E1 oracle unchanged, then measures
cases QSET/REF do not cover:
  A. multi-word queries on REF (several query tokens that reach the fuzzy tier);
  B. a mechanical 50,000-name list (case_06's first 50,000 names, all 13 chars);
  C. the graph's literal step 6 (case-exactness by a raw _classify for every
     member of a reached group) against the pilot's shortcut;
  D. memory mutants for R-A2L-MATCH.37 (what a product mutant must add);
  E. OSA prefix distance vs unrestricted Damerau-Levenshtein (D-5);
  F. str-mixin Enum formatting on this Python;
  G. paste-modal workload: 100 typo'd labels ranked with limit 3 on REF.
"""
from __future__ import annotations

import gc
import os
import random
import runpy
import statistics
import sys
import time
import tracemalloc
from enum import Enum
from pathlib import Path

HERE = Path(os.environ["PILOT_DIR"])
P4 = runpy.run_path(str(HERE / "i4e2-pilot4.py"), run_name="i4e2_pilot_v4")
IndexC, naive_rank_b, evaluate_b = P4["IndexC"], P4["naive_rank_b"], P4["evaluate_b"]
tokens, names_of, REPO, s19_app = P4["tokens"], P4["names_of"], P4["REPO"], P4["s19_app"]
osa_prefix = P4["P1"]["osa_prefix"]


class IndexGraph6(IndexC):
    """Step 6 as graph-inc4.md:174 pins it: case-exact = raw _classify gives the rule."""

    def _case_exact(self, query, q, name, rule):
        ce = evaluate_b(query, name, folded=False)
        return ce is not None and ce[0] == rule


def med_ms(idx, q, lim=20, n=7):
    runs = []
    res = None
    for _ in range(n):
        t0 = time.perf_counter()
        res = idx.rank(q, lim)
        runs.append(time.perf_counter() - t0)
    hist = {}
    for r in res:
        hist[r[1]] = hist.get(r[1], 0) + 1
    return statistics.median(runs) * 1000, len(res), hist


def peak(fn):
    gc.collect()
    tracemalloc.start()
    obj = fn()
    cur, pk = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return obj, cur, pk


def dl_prefix(q: str, t: str) -> int:
    """Unrestricted Damerau-Levenshtein (Lowrance-Wagner) to the nearest prefix of t."""
    m, n = len(q), len(t)
    inf = m + n
    da = {}
    d = [[0] * (n + 2) for _ in range(m + 2)]
    d[0][0] = inf
    for i in range(m + 1):
        d[i + 1][0] = inf
        d[i + 1][1] = i
    for j in range(n + 1):
        d[0][j + 1] = inf
        d[1][j + 1] = j
    for i in range(1, m + 1):
        db = 0
        for j in range(1, n + 1):
            i1 = da.get(t[j - 1], 0)
            j1 = db
            cost = 0 if q[i - 1] == t[j - 1] else 1
            if cost == 0:
                db = j
            d[i + 1][j + 1] = min(d[i][j] + cost, d[i + 1][j] + 1, d[i][j + 1] + 1,
                                  d[i1][j1] + (i - i1 - 1) + 1 + (j - j1 - 1))
        da[q[i - 1]] = i
    return min(d[m + 1][j + 1] for j in range(n + 1))


def main() -> int:
    print(f"s19_app.__file__ = {s19_app.__file__}")
    print(f"python = {sys.version.split()[0]}  host = {os.uname().nodename}  cpus = {os.cpu_count()}")
    print(f"load before = {os.getloadavg()}")
    sw_a = names_of(REPO / "examples/case_00_public/software_a.a2l")
    ref = (sw_a + [n + "_1" for n in sw_a] + [n + "_2" for n in sw_a] + [n + "_3" for n in sw_a])[:50000]
    big = IndexC(ref)

    print("\n=== A. multi-word queries on REF (limit 20, median of 7)")
    rng = random.Random(20261108)
    cands = [n for n in sw_a if sum(1 for s, e in tokens(n) if e - s >= 6 and n[s].isalpha()) >= 4]
    print(f"  SWA names with >= 4 letter tokens of >= 6 letters: {len(cands)}")
    qa = ["nzukij ierxjr", "nzukij ierxjr pposbxiif", "nzukij ierxjr pposbxiif jotafvod",
          "engine speed sensor value", "engine speed sensor value offset limit"]
    for name in rng.sample(cands, 6):
        words = [name[s:e].lower() for s, e in tokens(name) if e - s >= 6][:4]
        qa.append(" ".join(words))
        typo = [w[:2] + w[3] + w[2] + w[4:] for w in words]
        qa.append(" ".join(typo))
    worst = (0.0, "")
    for q in qa:
        ms, n, hist = med_ms(big, q)
        worst = max(worst, (ms, q))
        print(f"  {ms:7.1f} ms  results {n:2d} {hist}  query={q!r}")
    print(f"  A worst median = {worst[0]:.1f} ms  query={worst[1]!r}")

    print("\n=== B/C. mechanical list: the first 50,000 names of case_06 (limit 20, median of 7)")
    c6 = names_of(REPO / "examples/case_06_large_nested_a2l/firmware.a2l")[:50000]
    lens = sorted({len(n) for n in c6})
    print(f"  names {len(c6)}  lengths {lens}  sample {c6[:3]} ... {c6[-2:]}")
    t0 = time.perf_counter()
    i6 = IndexC(c6)
    print(f"  IndexC build {time.perf_counter() - t0:.3f} s")
    _, cur6, pk6 = peak(lambda: IndexC(c6))
    print(f"  IndexC tracemalloc peak {pk6:,} bytes = {pk6 / 1048576:.1f} MiB (retained {cur6 / 1048576:.1f} MiB)")
    g6 = IndexGraph6(c6)
    target = c6[31337].lower()
    typing = [target[:k] for k in range(1, len(target) + 1)]
    extra = ["chr", "mesa", "char 1", "meas 12", "cahr_01234_00", "0", "00", "char_", "meas_"]
    worst_c = (0.0, "")
    worst_g = (0.0, "")
    for q in typing + extra:
        ms_c, n_c, h_c = med_ms(i6, q, n=5)
        ms_g, n_g, _ = med_ms(g6, q, n=3)
        assert i6.rank(q, 20) == g6.rank(q, 20)
        worst_c = max(worst_c, (ms_c, q))
        worst_g = max(worst_g, (ms_g, q))
        print(f"  pilot {ms_c:7.1f} ms | graph-step-6 {ms_g:8.1f} ms  results {n_c:2d} {h_c}  query={q!r}")
    print(f"  B worst median (pilot shortcut)      = {worst_c[0]:.1f} ms  query={worst_c[1]!r}")
    print(f"  C worst median (graph literal step 6) = {worst_g[0]:.1f} ms  query={worst_g[1]!r}")
    print("  C on REF: QSET with the graph's literal step 6")
    gref = IndexGraph6(ref)
    qset = ["a", "e", "0", "zz", "ab", "JotafVod_msrqlLzL_kh2C_rWl_pfue._0_", "JotafVod_msr", "srqlLzL_", "0 jotaf", "JVmL",
            "xqzjvkw", "qqqq zzzz", "aaaa", "e e e", "Nzukij", "Ierxjr_Eud", "ledRing", "pposbxiif", "cnt", "temp_sensor_max",
            "x y z w v u", "pposbxiifkdgfiajnbbpvb_dyan_xvz1"]
    wq = (0.0, "")
    for q in qset:
        ms, _, _ = med_ms(gref, q, n=5)
        wq = max(wq, (ms, q))
    print(f"  REF QSET worst median (graph literal step 6) = {wq[0]:.1f} ms  query={wq[1]!r}")
    del gref, g6, i6
    gc.collect()

    print("\n=== D. memory mutants on REF (tracemalloc peak during one build; bound 67,108,864)")

    class Lists(IndexC):
        def __init__(self, names):
            super().__init__(names)
            self.nmask, self.ntid, self.noff = list(self.nmask), list(self.ntid), list(self.noff)
            self.post, self.poff = list(self.post), list(self.poff)
            ch, de, fi, en = self.nodes
            self.nodes = (ch, list(de), list(fi), list(en))

    class DictTrie(IndexC):
        def __init__(self, names):
            super().__init__(names)
            root = {}
            for tid, t in enumerate(self.utok):
                node = root
                for c in t:
                    node = node.setdefault(c, {})
                node[""] = tid
            self.dtrie = root

    class TokStr(IndexC):
        def __init__(self, names):
            super().__init__(names)
            self.ntoks = tuple(tuple(f[s:e] for s, e in tokens(n)) for n, f in zip(self.names, self.folded))

    for label, cls in (("IndexC (as pinned)", IndexC), ("M1 every array -> list", Lists),
                       ("M2 + nested-dict trie of the tokens", DictTrie), ("M3 + per-name tuple of token strings", TokStr)):
        obj, cur, pk = peak(lambda: cls(ref))
        verdict = "RED (> 64 MiB)" if pk > 67_108_864 else "GREEN (<= 64 MiB)"
        print(f"  {label:40s} peak {pk:>12,} = {pk / 1048576:5.1f} MiB  retained {cur / 1048576:5.1f} MiB  -> {verdict}")
        del obj
        gc.collect()

    print("\n=== E. OSA prefix distance (D-5 A) vs unrestricted Damerau-Levenshtein (D-5 B)")
    for q, t in (("crxuve", "curve"), ("cuvre", "curve"), ("ca", "abc"), ("xxxxcayyy", "xxxxabcyyy"), ("maesu", "measurement"),
                 ("vlaue", "value")):
        print(f"  q={q!r:12s} t={t!r:14s} osa_prefix={osa_prefix(q, t)}  dl_prefix={dl_prefix(q, t)}")
    c08 = names_of(Path(os.environ["OUT"]) / "firmware.a2l")
    print(f"  rank over C08 (462), query 'crxuve' (6 letters, 2 allowed edits): naive_rank_b = {naive_rank_b('crxuve', c08, 20)}")

    print("\n=== F. str-mixin Enum formatting")

    class M(str, Enum):
        FUZZY = "fuzzy"
    print(f"  f-string: {f'{M.FUZZY}'!r}  str(): {str(M.FUZZY)!r}  .value: {M.FUZZY.value!r}  == 'fuzzy': {M.FUZZY == 'fuzzy'}")

    print("\n=== G. paste-modal workload: 100 labels with a one-letter substitution, rank limit 3 on REF")
    rng = random.Random(20261109)
    labels = []
    for n in rng.sample(ref, 100):
        p = rng.randrange(1, len(n) - 1)
        labels.append(n[:p] + ("x" if n[p] != "x" else "q") + n[p + 1:])
    t0 = time.perf_counter()
    per = []
    for lab in labels:
        t1 = time.perf_counter()
        big.rank(lab, 3)
        per.append(time.perf_counter() - t1)
    tot = time.perf_counter() - t0
    print(f"  total {tot:.2f} s  median {statistics.median(per) * 1000:.1f} ms  max {max(per) * 1000:.1f} ms per label")
    print(f"\nload after = {os.getloadavg()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
