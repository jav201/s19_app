#!/usr/bin/env python3
"""batch-103 Inc 4 E3 round-2 architect probe. THROWAWAY EVIDENCE, NOT PRODUCT CODE.

Implements the rank procedure the corrected graph pins (codewire/graph-inc4.md at
15129b64, "rank -- the procedure pinned for R-A2L-MATCH.36", steps 1-6) over the E2
pilot's IndexC buffers (i4e2-pilot4.py, an unchanged copy in PILOT_DIR):
  step 1  type checks; limit < 1 -> []; parse; no letter/digit -> []; stripped
          query > 256 characters -> [] (R-A2L-MATCH.38); names > 1,024 characters
          are left out at the build (R-A2L-MATCH.39)
  step 4  FUZZY lazily: maps in ascending allowed edits, candidates intersected
          after each walk, stop when empty; once <= 300 candidates remain, the other
          query tokens are checked per candidate with a capped prefix distance,
          memoised per token id
  step 6  case-exactness only for exact / prefix / substring, by string comparison
Variants (constructor flags), all asserted to give the same lists where they must:
  ce="ctx"   substring case-exact = the raw query occurs anywhere in the raw name
             (CTX case-exact: "whose rule still holds")
  ce="graph" substring case-exact = the raw query occurs at a boundary offset (the
             graph's literal step-6 text "`in` at a boundary offset")
  brk        stop a candidate's check at the first query token it fails (True) or
             score every query token (False; the step text does not say)
  dedupe     one map per distinct query token text (not in the graph)
References:
  naive_rank_r2  the rows' oracle with the ruled case-exactness: i4e1-pilot3's
                 naive_rank_b with case-exactness only for rules 0-2, plus .38/.39
  BN             the v3 index IndexB with the same narrowing (fast reference)
  naive_rank_b / IndexB   the v3 reference (old .24: raw re-classification)
Modes: check | time | adv
"""
from __future__ import annotations

import gc
import hashlib
import os
import random
import runpy
import statistics
import sys
import time
import tracemalloc
from pathlib import Path

HERE = Path(os.environ["PILOT_DIR"])
P4 = runpy.run_path(str(HERE / "i4e2-pilot4.py"), run_name="i4e2_pilot_v4")
IndexC, IndexB = P4["IndexC"], P4["IndexB"]
naive_rank_b, evaluate_b, RULES_B = P4["naive_rank_b"], P4["evaluate_b"], P4["RULES_B"]
tokens, names_of, REPO, OUT, s19_app = P4["tokens"], P4["names_of"], P4["REPO"], P4["OUT"], P4["s19_app"]
allowed, is_subseq, query_parts = P4["allowed"], P4["is_subseq"], P4["query_parts"]
prefix_range, fuzzy_walk, at_boundary, _mask = P4["prefix_range"], P4["fuzzy_walk"], P4["at_boundary"], P4["_mask"]
mutate = P4["mutate"]
osa_prefix = P4["P1"]["osa_prefix"]
QCAP, NCAP, CAND_MAX = 256, 1024, 300


def pd_capped(q: str, t: str, cap: int) -> int:
    """_prefix_distance as pinned: min(OSA prefix distance, cap + 1), early exit."""
    m, n = len(q), len(t)
    prev2 = None
    prev = list(range(n + 1))
    for i in range(1, m + 1):
        cur = [i] + [0] * n
        qi = q[i - 1]
        for j in range(1, n + 1):
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
            cur[j] = v
        if min(cur) > cap and min(prev) > cap:  # two rows above cap: every later row is
            return cap + 1
        prev2, prev = prev, cur
    d = min(prev)
    return d if d <= cap else cap + 1


class R2(IndexC):
    def __init__(self, names, ce="ctx", brk=True, dedupe=False, collapse=False):
        if isinstance(names, (str, bytes)):
            raise TypeError(f"label names must be an iterable of str, got {type(names).__name__}")
        kept = []
        for n in names:
            if not isinstance(n, str):
                raise TypeError(f"label names must be str, got {type(n).__name__}")
            if len(n) <= NCAP:
                kept.append(n)
        super().__init__(kept)
        self.ce, self.brk, self.dedupe, self.collapse = ce, brk, dedupe, collapse
        self.walks = self.pdcalls = 0

    def _ce(self, q, name, rule):
        if rule == 0:
            return name == q
        if rule == 1:
            return name.startswith(q)
        if rule == 2:
            if self.ce == "ctx":
                return q in name
            p = name.find(q)
            while p >= 0:
                if at_boundary(name, p):
                    return True
                p = name.find(q, p + 1)
            return False
        return False

    def _map(self, qt, k):
        self.walks += 1
        if k == 0:
            lo, hi = prefix_range(self.utok, qt)
            return dict.fromkeys(range(lo, hi), 0)
        return fuzzy_walk(self.utok, self.nodes, qt, k)

    def _fuzzy(self, qtoks, taken, mult=None):
        post, poff, ntid, noff, utok = self.post, self.poff, self.ntid, self.noff, self.utok
        info = [(qt, allowed(qt)) for qt in qtoks]
        mult = mult or [1] * len(info)
        order = sorted(range(len(info)), key=lambda j: info[j][1])
        dists = [None] * len(info)
        cache = {}
        cand = None
        for j in order:
            if cand is not None and len(cand) <= CAND_MAX:
                break
            qt, k = info[j]
            if self.dedupe and qt in cache:
                d = cache[qt]
            else:
                d = self._map(qt, k)
                if self.dedupe:
                    cache[qt] = d
            if not d:
                return {}
            dists[j] = d
            have = set()
            for t in d:
                have.update(post[poff[t]:poff[t + 1]])
            cand = (have - taken) if cand is None else (cand & have)
            if not cand:
                return {}
        memo: dict = {}
        out = {}
        for i in cand:
            ids = ntid[noff[i]:noff[i + 1]]
            total = 0
            ok = True
            for j, (qt, k) in enumerate(info):
                d = dists[j]
                bst = None
                if d is not None:
                    for t in ids:
                        v = d.get(t)
                        if v is not None and (bst is None or v < bst):
                            bst = v
                else:
                    mm = memo.setdefault(qt, {})
                    for t in ids:
                        v = mm.get(t)
                        if v is None:
                            v = mm[t] = pd_capped(qt, utok[t], k)
                            self.pdcalls += 1
                        if v <= k and (bst is None or v < bst):
                            bst = v
                if bst is None:
                    ok = False
                    if self.brk:
                        break
                else:
                    total += bst * mult[j]
            if ok:
                out[i] = total
        return out

    def rank(self, query, limit):
        if not isinstance(query, str):
            raise TypeError(f"query must be str, got {type(query).__name__}")
        if not isinstance(limit, int) or isinstance(limit, bool):
            raise TypeError(f"limit must be int, got {type(limit).__name__}")
        if limit < 1:
            return []
        q, qf, qtoks, keys = query_parts(query, True)
        if not keys:
            return []
        if len(q) > QCAP:
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
            if self.collapse:  # a multiset of query tokens: one range / map per distinct token
                cnt: dict = {}
                for qt in qtoks:
                    cnt[qt] = cnt.get(qt, 0) + 1
                tq, mult = list(cnt), list(cnt.values())
            else:
                tq, mult = qtoks, None
            ranges = [prefix_range(utok, qt) for qt in tq]
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
                for i, total in self._fuzzy(tq, taken, mult).items():
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
            keyed = sorted((0 if self._ce(q, names[i], gk[0]) else 1, names[i]) for i in groups[gk])
            for _, name in keyed:
                ev = evaluate_b(query, name)
                if ev[0] != gk[0] or ev[1] != gk[1]:
                    self.tier_disagree += 1
                out.append((name, RULES_B[ev[0]], ev[1], ev[2]))
                if len(out) >= limit:
                    return out
        return out


class BN(IndexB):
    """The v3 index with case-exactness narrowed to rules 0-2 (the ruled .24)."""

    def _case_exact(self, query, q, name, rule):
        if rule >= 3:
            return False
        return IndexB._case_exact(self, query, q, name, rule)


def naive_rank_r2(query: str, names, limit: int) -> list:
    if limit < 1:
        return []
    if len(query_parts(query, True)[0]) > QCAP:
        return []
    rows = []
    for name in dict.fromkeys(n for n in names if len(n) <= NCAP):
        ev = evaluate_b(query, name)
        if ev is None:
            continue
        ce = False
        if ev[0] <= 2:
            raw = evaluate_b(query, name, folded=False)
            ce = raw is not None and raw[0] == ev[0]
        rows.append(((ev[0], ev[1], len(name), 0 if ce else 1, name), ev))
    rows.sort(key=lambda r: r[0])
    return [(r[0][4], RULES_B[r[1][0]], r[1][1], r[1][2]) for r in rows[:limit]]


def header(mode):
    print(f"mode = {mode}")
    print(f"s19_app.__file__ = {s19_app.__file__}")
    print(f"python = {sys.version.split()[0]}  host = {os.uname().nodename}  cpus = {os.cpu_count()}")
    print(f"HOME = {os.environ.get('HOME')}  LOCALAPPDATA = {os.environ.get('LOCALAPPDATA')}  PILOT_DIR = {HERE}  OUT = {OUT}")
    for f in ("i4e2-pilot4.py", "i4e1-pilot3.py", "i4e1-pilot2.py", "i4e1-pilot.py"):
        print(f"  sha256 {f} = {hashlib.sha256((HERE / f).read_bytes()).hexdigest()}")
    print(f"load before = {os.getloadavg()}")


def lists():
    sw_a = names_of(REPO / "examples/case_00_public/software_a.a2l")
    ref = (sw_a + [n + "_1" for n in sw_a] + [n + "_2" for n in sw_a] + [n + "_3" for n in sw_a])[:50000]
    c6 = names_of(REPO / "examples/case_06_large_nested_a2l/firmware.a2l")[:50000]
    return sw_a, ref, c6


def qset33(sw_a, ref):
    """QSET of 02-test-cases.md at 15129b64; the E3S-01 shapes built as i4e3s-probe.py cap() builds them."""
    base = ["a", "e", "0", "zz", "ab", "JotafVod_msrqlLzL_kh2C_rWl_pfue._0_", "JotafVod_msr", "srqlLzL_", "0 jotaf", "JVmL",
            "xqzjvkw", "qqqq zzzz", "aaaa", "e e e", "Nzukij", "Ierxjr_Eud", "ledRing", "pposbxiif", "cnt", "temp_sensor_max",
            "x y z w v u", "pposbxiifkdgfiajnbbpvb_dyan_xvz1"]
    multi = ["njraipjtbtu lsuakcoj hsxgibymjxu orfltalc uadvdygb zobnkw",
             "votklbi fjblnabj qghque pdjxmq tiprdynotu djchlitjt",
             "lmmwngodou jadkvqy khbnukc qomfrybiza evfwbqj"]
    rng = random.Random(20261108)
    pool = rng.sample(sw_a, 400)
    longest = sorted(ref, key=lambda n: (-len(tokens(n)), n))[0]
    shapes = ["e " * 128, ((" ".join("abcdefghijklmnopqrstuvwxyz") + " ") * 20)[:256], "0 " * 128, "a" * 256,
              ",".join(pool)[:256], ",".join(pool[200:])[:256], longest, longest[1] + longest[0] + longest[2:]]
    return base + multi + shapes


def multi12(sw_a):
    """Round-1 probe 2's multi-word queries (4 names x 4, 5, 6 words, one transposition each)."""
    rng = random.Random(20261108)
    cands = [n for n in sw_a if sum(1 for s, e in tokens(n) if e - s >= 6 and n[s].isalpha()) >= 6]
    out = []
    for name in rng.sample(cands, 4):
        words = [name[s:e].lower() for s, e in tokens(name) if e - s >= 6]
        for nw in (4, 5, 6):
            out.append(" ".join(x[:2] + x[3] + x[2] + x[4:] for x in words[:nw]))
    return out


REF6Q = ["m", "meas_", "chr", "mesa", "cahr", "cr0", "char 1", "0", "chr 0", "ch00", "meas 1", "c 0 1"]
C6Q_R1 = ["m", "me", "meas", "meas_", "c", "chr", "mesa", "cahr", "char 1", "meas 12", "0", "00", "char_", "cr0", "c 1 2"]


def cmp(label, got, want):
    return got == want


def check():
    header("check")
    case08 = names_of(OUT / "firmware.a2l")
    issues = names_of(OUT / "firmware_issues.a2l")
    sw_a, ref, c6 = lists()
    sw_b = names_of(REPO / "examples/case_00_public/software_b.a2l")
    bal = names_of(REPO / "examples/case_00_public/BalanceTube_STMicro.a2l")
    src = names_of(REPO / "examples/case_00_public/from_source.a2l")
    print(f"names: case08 {len(case08)}  issues {len(issues)}  software_a {len(sw_a)}  REF {len(ref)}  case06[:50000] {len(c6)} (lengths {sorted(set(map(len, c6)))})")
    for q, t, cap in [("cuvre", "curve", 1), ("crxuve", "curve", 2), ("valuexxx", "value", 2), ("ca", "abc", 0), ("maesu", "measurement", 1)]:
        assert pd_capped(q, t, cap) == min(osa_prefix(q, t), cap + 1), (q, t)
    rng0 = random.Random(7)
    al = "abcxyz01"
    for _ in range(20000):
        q = "".join(rng0.choice(al) for _ in range(rng0.randint(1, 8)))
        t = "".join(rng0.choice(al) for _ in range(rng0.randint(0, 10)))
        for cap in (0, 1, 2):
            assert pd_capped(q, t, cap) == min(osa_prefix(q, t), cap + 1), (q, t, cap)
    print("pd_capped == min(osa_prefix, cap + 1): 20,000 random pairs x caps 0-2 + 5 fixed: OK")

    print("\n=== 1. every example of 02-test-cases.md (pilot4 section 1 list + the round-1 corrections' new cases)")
    cur = ["ABSValue", "AValue", "engineSpeed", "Map3D"]
    na = ["Drück_Max", "DRÜCK_MAX", "druck_max"]
    ex = [
        ("C08", case08, "  VALUE_0001  ", 20), ("C08", case08, "\tVALUE_0001\n", 20), ("C08", case08, " value_000 ", 5),
        ("C08", case08, "", 20), ("C08", case08, "   ", 20), ("C08", case08, "\t\n", 20), ("C08", case08, "_", 20), ("C08", case08, "._[]", 20),
        ("C08", case08, "value_0001", 20), ("C08", case08, "Value_0001", 20), ("TW", ["RPM", "rpm", "Rpm"], "rpm", 20),
        ("NA", na, "drück", 20), ("NA", na, "DRÜCK", 20), ("C08", case08, "VALUE-0001", 20),
        ("C08", case08, "VALUE_0001", 20), ("C08", case08, "map_0020", 20),
        ("C08", case08, "value_000", 5), ("C08i", issues, "span", 20), ("C08i", issues, "LIMIT", 20),
        ("C08", case08, "0001", 20), ("SRC", src, "knife[1]", 20), ("SRC", src, "[0].Spoon", 20), ("BAL", bal, "ledRing[1]", 4),
        ("C08", case08, "blk val 00", 3), ("BAL", bal, "stop watch", 20), ("SWB", sw_b, "oks ahw", 20), ("SRC", src, "knife 1 x", 20),
        ("C08i", issues, "out range", 20), ("SRC", src, "knife.*", 4), ("CUR", cur, "a value", 20), ("CUR", cur, "map 3 d", 20),
        ("CUR", cur, "abs value", 20), ("C08", case08, "VALUE_0001_VALUE_0001", 20),
        ("C08", case08, "mp", 3), ("C08", case08, "ascii 1", 20), ("C08", case08, "map 2", 20), ("BAL", bal, "gamecontroller timer", 3),
        ("C08", case08, "map 20", 20),
        ("C08", case08, "cuvre", 3), ("C08", case08, "maesurement_0001", 20), ("C08", case08, "vlaue_0001", 20), ("C08", case08, "mpa", 3),
        ("C08", case08, "xmap", 3), ("C08", case08, "maq", 3), ("C08", case08, "measurementss_0001", 20), ("C08", case08, "vblk", 2),
        ("C08", case08, "VALUE_0300", 20), ("cur1", ["BA_X"], "ab", 20), ("cur1b", ["abc"], "ca", 20), ("C08", case08, "cvure", 20),
        ("C08", case08, "valuexx_0001", 20), ("C08", case08, "valuexxx_0001", 20), ("cur2", ["CUVE", "CURVE_0001"], "curvee", 20),
        ("C08", case08, "value_000", 100), ("C08", case08, "0001", 100), ("C08", case08, "temp_sensor_max", 20),
        ("blank", ["", "   ", "VALUE_0001"], "v", 20), ("C08", case08, "value_000", 20), ("C08", case08, "valu_0001", 20),
        ("C08", case08, "vale_0001", 20), ("C08i", issues, "VALUE_0001", 20), ("C08i", issues, "value_000", 20),
        ("C08", case08, "value_000", 1), ("C08", case08, "VALUE", 0), ("C08", case08, "VALUE", -1),
        ("BAL", bal, "gamecontroller.timer", 20), ("cur3", ["timeCounter", "Encounter"], "counter", 20), ("C08", case08, "_0001", 20),
        ("BAL", bal, "ounter", 4), ("cur4", ["rpm_x", "RPMX"], "rpm", 20), ("TW", ["RPM", "rpm", "Rpm"], "RPM", 20),
        ("C08r", list(reversed(case08)), "0001", 20), ("TW2", ["Rpm", "rpm", "RPM"], "rpm", 20),
        ("cur5", ["DiscountCount"], "count", 20), ("SWB", sw_b, "sahw", 20), ("C08", case08, "maesu", 3), ("cur6", ["Curve_Map_X"], "cuvre maq", 20),
        # new / changed at the round-1 correction pass (15129b64)
        ("C08", case08, "\x1cVALUE_0001", 20),                       # .1/4
        ("U0663", ["٣٣٣_X"], "٣٣٤", 20),  # .12/4
        ("C08", case08, "crxuve", 20),                                # .13/4
        ("C08", case08, "VALUE_0001_" * 23 + "VAL", 20),              # .38/1 (256)
        ("C08", case08, "VALUE_0001_" * 23 + "VALU", 20),             # .38/2 (257)
        ("X1024", ["x" * 1024], "x", 20),                             # .39/1
        ("X1025", ["x" * 1025], "x", 20),                             # .39/2
        ("CE-sub", ["DiscouNTCount", "DiscountCount"], "count", 20),  # step-6 substring reading (not a case)
    ]
    expect = {  # the literal expected values of 02-test-cases.md for the cases the pass changed or added
        ("NA", "drück"): [("Drück_Max", "prefix", 0, [(0, 5)]), ("DRÜCK_MAX", "fuzzy", 1, [(0, 5)]), ("druck_max", "fuzzy", 1, [(0, 5)])],
        ("C08", "\x1cVALUE_0001"): [("VALUE_0001", "token", 0, [(0, 5), (6, 10)])],
        ("U0663", "٣٣٤"): [("٣٣٣_X", "fuzzy", 1, [(0, 3)])],
        ("C08", "crxuve"): [],
        ("C08", "VALUE_0001_" * 23 + "VAL"): [("VALUE_0001", "token", 0, [(0, 5), (6, 10)])],
        ("C08", "VALUE_0001_" * 23 + "VALU"): [],
        ("X1024", "x"): [("x" * 1024, "prefix", 0, [(0, 1)])],
        ("X1025", "x"): [],
    }
    built: dict = {}
    bad_r2 = bad_lit = 0
    v3diff = []
    for label, names, qy, lim in ex:
        key = (label, id(names))
        if key not in built:
            built[key] = (R2(names), R2(names, ce="graph"))
        ix, ixg = built[key]
        got = ix.rank(qy, lim)
        r2 = naive_rank_r2(qy, names, lim)
        v3 = naive_rank_b(qy, names, lim)
        ok = got == r2
        bad_r2 += not ok
        lit = expect.get((label, qy))
        litok = None if lit is None else got == lit
        bad_lit += litok is False
        if got != v3:
            v3diff.append((label, qy, lim, got, v3))
        gdiff = ixg.rank(qy, lim) != got
        shown = qy if len(qy) <= 40 else f"{qy[:24]}...({len(qy)} chars)"
        print(f"[{label}] query={shown!r} limit={lim}  R2 == oracle(ruled): {ok}  == v3: {got == v3}"
              + ("" if litok is None else f"  == 02-test-cases literal: {litok}") + ("  ce=graph DIFFERS" if gdiff else ""))
        if lit is not None or gdiff or got != v3:
            for name, rule, k, sp in got:
                nm = name if len(name) <= 40 else f"{name[:12]}...({len(name)} chars)"
                print(f"      {nm!r:44s} {rule:11s} key={k} spans={sp}")
            if gdiff:
                print(f"      ce=graph gives: {[r[0] for r in ixg.rank(qy, lim)]}")
            if got != v3:
                print(f"      v3 gives:       {[(r[0], r[1]) for r in v3]}")
    print("AT-B103-I4-1 (C08, limit 5) and AT-B103-I4-2 (SWA, limit 5)")
    ix08 = built[("C08", id(case08))][0]
    for qy in ["m", "ma", "map", "map_", "map_00", "map_002", "map_0020"]:
        ok = ix08.rank(qy, 5) == naive_rank_r2(qy, case08, 5)
        bad_r2 += not ok
        print(f"  [C08] {qy!r}: R2 == oracle(ruled): {ok}")
    ixa = R2(sw_a)
    target = sw_a[1234]
    for qy in [target, "jotafvod", "msrqlLzL", "pfue._0_", "jotaf vod", "vod jotaf", "jotfa vod", "jotaf_vdo"]:
        got = ixa.rank(qy, 5)
        ok = got == naive_rank_r2(qy, sw_a, 5)
        bad_r2 += not ok
        pos = next((i for i, r in enumerate(got) if r[0] == target), None)
        print(f"  [SWA] {qy!r}: R2 == oracle(ruled): {ok}  target position {pos}")
    dis1 = sum(a.tier_disagree for a, _ in built.values()) + ixa.tier_disagree
    print(f"  section 1: R2 vs oracle(ruled) mismatches = {bad_r2}; vs the literal expected values = {bad_lit}; "
          f"tier rule/key disagreements = {dis1}; differences from v3 = {len(v3diff)}: {[(d[0], d[1][:30]) for d in v3diff]}")

    print("\n=== 2. v3's pool and queries (pilot4 section 2, seed 20261106), 4 limits")
    rng = random.Random(20261106)
    pool = sorted(set(rng.sample(sw_a, 600) + rng.sample(bal, 60) + rng.sample(src, 40) + rng.sample(sw_b, 40) + case08[:200] + ["RPM", "rpm", "Drück_Max", "DRÜCK_MAX"]))
    qs = []
    for _ in range(400):
        name = rng.choice(pool)
        toks = [name[a:b] for a, b in tokens(name)] or [name]
        r = rng.random()
        if r < 0.2:
            qs.append(name[: rng.randint(1, len(name))])
        elif r < 0.4:
            a = rng.randint(0, len(name) - 1)
            qs.append(name[a: a + rng.randint(1, 8)])
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
    idxp, idxpg = R2(pool), R2(pool, ce="graph")
    bad2 = v3d2 = gd2 = 0
    for qy in qs:
        full_r2 = naive_rank_r2(qy, pool, 100000)
        full_v3 = naive_rank_b(qy, pool, 100000)
        for lim in (1, 5, 50, 100000):
            got = idxp.rank(qy, lim)
            if got != full_r2[:lim]:
                bad2 += 1
                print(f"  MISMATCH vs oracle(ruled) query={qy!r} limit={lim}")
            if got != full_v3[:lim]:
                v3d2 += 1
                if v3d2 <= 6:
                    print(f"  differs from v3: query={qy!r} limit={lim}: R2 {[(r[0], r[1]) for r in got[:6]]} | v3 {[(r[0], r[1]) for r in full_v3[:lim][:6]]}")
            gd2 += idxpg.rank(qy, lim) != got
    print(f"  pool {len(pool)} names, {len(qs)} queries x 4 limits: R2 vs oracle(ruled) mismatches = {bad2}; "
          f"differences from v3 = {v3d2}; ce=graph differs from ce=ctx = {gd2}; tier disagreements = {idxp.tier_disagree}")

    print("\n=== 3. REF and REF6 (case_06's first 50,000): R2 vs BN (v3 index, ruled .24) and vs IndexB (v3)")
    rng2 = random.Random(20261107)
    gen = [mutate(rng2, rng2.choice(ref)) for _ in range(300)]
    rng3 = random.Random(20261110)
    gen6 = [mutate(rng3, rng3.choice(c6)) for _ in range(300)]
    for label, names, queries in (("REF", ref, qset33(sw_a, ref) + multi12(sw_a) + gen),
                                  ("REF6", c6, REF6Q + [q for q in C6Q_R1 if q not in REF6Q] + gen6)):
        r2, r2g, bn, b3 = R2(names), R2(names, ce="graph"), BN(names), IndexB(names)
        r2nb = R2(names, brk=False)
        r2dd = R2(names, dedupe=True)
        bad3 = v3d = gd = 0
        for qy in queries:
            got = r2.rank(qy, 20)
            if got != bn.rank(qy, 20):
                bad3 += 1
                print(f"  MISMATCH R2 vs BN [{label}] query={qy[:60]!r}")
            assert r2nb.rank(qy, 20) == got and r2dd.rank(qy, 20) == got, (label, qy)
            if got != b3.rank(qy, 20):
                v3d += 1
                print(f"  differs from v3 [{label}] query={qy[:60]!r}")
            gd += r2g.rank(qy, 20) != got
        print(f"  {label}: {len(names)} names, {len(queries)} queries, limit 20: R2 vs BN mismatches = {bad3}; differences from v3 = {v3d}; "
              f"ce=graph differs = {gd}; brk=False and dedupe give the same lists (asserted); tier disagreements = {r2.tier_disagree}")
        del r2, r2g, bn, b3, r2nb, r2dd
        gc.collect()
    print(f"\nload after = {os.getloadavg()}")
    return 0


def med_ms(ix, q, lim=20, n=7):
    runs = []
    for _ in range(n):
        t0 = time.perf_counter()
        ix.rank(q, lim)
        runs.append(time.perf_counter() - t0)
    return statistics.median(runs) * 1000, max(runs) * 1000


def timing():
    header("time")
    sw_a, ref, c6 = lists()
    print("\n=== 4a. R-A2L-MATCH.37: tracemalloc peak during one build (nothing else alive)")
    for label, names in (("REF", ref), ("REF6", c6)):
        gc.collect()
        tracemalloc.start()
        ix = R2(names)
        cur, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        print(f"  {label}: peak {peak:,} bytes = {peak / 1048576:.1f} MiB ({'<=' if peak <= 67108864 else '>'} 64 MiB); held {cur:,} bytes")
        del ix
        gc.collect()
    print(f"\n=== 4b. R-A2L-MATCH.35: build median of 3; load {os.getloadavg()}")
    for label, names in (("REF", ref), ("REF6", c6)):
        b = []
        for _ in range(3):
            gc.collect()
            t0 = time.perf_counter()
            ix = R2(names)
            b.append(time.perf_counter() - t0)
            del ix
        print(f"  {label}: builds {[round(x, 3) for x in b]} s  median {statistics.median(b):.3f} s")
    # E3A-08 as applied: _tokens derived from _at_boundary (graph `_tokens` func) -- same spans? build cost?
    g = IndexC.__init__.__globals__
    sep = P4["_sep"]

    def tokens_ab(s):
        spans, start = [], None
        for i, c in enumerate(s):
            if sep(c):
                if start is not None:
                    spans.append((start, i))
                    start = None
            elif at_boundary(s, i):
                if start is not None:
                    spans.append((start, i))
                start = i
        if start is not None:
            spans.append((start, len(s)))
        return spans

    nchk = 0
    for names in (ref, c6):
        for n in names:
            assert tokens_ab(n) == tokens(n), n
            nchk += 1
    print(f"  _tokens derived from _at_boundary == the scan on {nchk:,} names (REF + REF6): OK")
    orig = g["tokens"]
    g["tokens"] = tokens_ab
    try:
        for label, names in (("REF", ref), ("REF6", c6)):
            b = []
            for _ in range(3):
                gc.collect()
                t0 = time.perf_counter()
                ix = R2(names)
                b.append(time.perf_counter() - t0)
                del ix
            print(f"  {label} with _tokens from _at_boundary: builds {[round(x, 3) for x in b]} s  median {statistics.median(b):.3f} s")
    finally:
        g["tokens"] = orig
    print(f"\n=== 4c. R-A2L-MATCH.36: median of 7 per query, limit 20 (R2 = the corrected graph; nb = no early break)")
    sets = (("REF", ref, [("QSET", q) for q in qset33(sw_a, ref)] + [("r1-multi", q) for q in multi12(sw_a)]),
            ("REF6", c6, [("REF6Q", q) for q in REF6Q] + [("r1-c6q", q) for q in C6Q_R1 if q not in REF6Q]))
    summary = []
    for label, names, queries in sets:
        print(f"  -- {label}; load {os.getloadavg()}")
        ix, nb = R2(names), R2(names, brk=False)
        worst = {"R2": (0.0, ""), "nb": (0.0, "")}
        worst_fix = (0.0, "")
        for tag, qy in queries:
            ix.walks = ix.pdcalls = 0
            res = ix.rank(qy, 20)
            walks, pdc = ix.walks, ix.pdcalls
            m, mx = med_ms(ix, qy)
            m2, _ = med_ms(nb, qy)
            worst["R2"] = max(worst["R2"], (m, qy))
            worst["nb"] = max(worst["nb"], (m2, qy))
            if tag in ("QSET", "REF6Q"):
                worst_fix = max(worst_fix, (m, qy))
            hist: dict = {}
            for r in res:
                hist[r[1]] = hist.get(r[1], 0) + 1
            shown = qy if len(qy) <= 44 else f"{qy[:30]}...({len(qy)})"
            print(f"     [{tag:8s}] {shown!r:52s} R2 {m:7.1f} ms (max {mx:7.1f})  nb {m2:7.1f} ms  walks {walks:3d} pd {pdc:5d}  {hist}")
        print(f"     worst {label}: R2 {worst['R2'][0]:.1f} ms ({worst['R2'][1][:50]!r}); fixture only (.36/1) {worst_fix[0]:.1f} ms ({worst_fix[1][:50]!r}); "
              f"nb {worst['nb'][0]:.1f} ms ({worst['nb'][1][:50]!r})")
        summary.append((label, worst, worst_fix))
        if label == "REF":
            rngp = random.Random(20261109)
            labels = []
            for n in rngp.sample(ref, 100):
                p = rngp.randrange(1, len(n) - 1)
                labels.append(n[:p] + ("x" if n[p] != "x" else "q") + n[p + 1:])
            per = []
            for lab in labels:
                t0 = time.perf_counter()
                ix.rank(lab, 3)
                per.append(time.perf_counter() - t0)
            print(f"     paste-modal workload (100 labels, limit 3): total {sum(per):.2f} s  median {statistics.median(per) * 1000:.1f} ms  max {max(per) * 1000:.1f} ms")
        del ix, nb
        gc.collect()
    print(f"\nSUMMARY {[(l, round(w['R2'][0], 1), w['R2'][1][:30], round(f[0], 1)) for l, w, f in summary]}")
    print(f"load after = {os.getloadavg()}")
    return 0


def adv():
    """Shapes within the 256-character cap that QSET / REF6 do not hold; and the cap's own cost."""
    header("adv")
    sw_a, ref, c6 = lists()
    rng = random.Random(20261111)
    words6 = []
    while len(" ".join(words6)) < 250:
        words6.append("".join(rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(6)))
    c6pool = random.Random(20261112).sample(c6, 40)
    shapes = {
        "REF": [
            ("'qzx ' x 64 (one 3-letter token repeated)", "qzx " * 64),
            ("'qz?' 26 distinct, repeated to 256", (" ".join("qz" + c for c in "abcdefghijklmnopqrstuvwxyz") + " ") * 3),
            ("'value ' x 42", "value " * 42),
            ("'jotaf ' x 42", "jotaf " * 42),
            ("36 random 6-letter words", " ".join(words6)[:256]),
            ("'e e e' x 85 -> 'e ' x 128 (QSET)", "e " * 128),
            ("'0 ' x 128 (QSET)", "0 " * 128),
            ("real names joined by ' ' (seed 20261108)", " ".join(random.Random(20261108).sample(sw_a, 400))[:256]),
        ],
        "REF6": [
            ("'chr ' x 64", "chr " * 64),
            ("'cahr ' x 51", "cahr " * 51),
            ("'char ' x 51", "char " * 51),
            ("'meas ' x 51", "meas " * 51),
            ("'0 ' x 128", "0 " * 128),
            ("'00 ' x 85", "00 " * 85),
            ("'c 0 ' x 64", "c 0 " * 64),
            ("40 REF6 names joined by ','", ",".join(c6pool)[:256]),
            ("40 REF6 names joined by ' '", " ".join(c6pool)[:256]),
            ("the same, lowercase, one transposition each", " ".join(n.lower()[:1] + n.lower()[2] + n.lower()[1] + n.lower()[3:] for n in c6pool)[:256]),
        ],
    }
    for label, names in (("REF", ref), ("REF6", c6)):
        print(f"\n=== 5. {label}: within-cap shapes, limit 20, median of 7; load {os.getloadavg()}")
        ix, dd = R2(names), R2(names, dedupe=True)
        for desc, qy in shapes[label]:
            ix.walks = ix.pdcalls = 0
            gc.collect()
            tracemalloc.start()
            res = ix.rank(qy, 20)
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            walks, pdc = ix.walks, ix.pdcalls
            assert dd.rank(qy, 20) == res
            m, mx = med_ms(ix, qy)
            m2, _ = med_ms(dd, qy)
            hist: dict = {}
            for r in res:
                hist[r[1]] = hist.get(r[1], 0) + 1
            print(f"  {desc:46s} chars {len(qy.strip()):3d} tokens {len(tokens(qy)):3d}: R2 {m:7.1f} ms (max {mx:7.1f})  dedupe {m2:7.1f} ms  "
                  f"walks {walks:3d} pd {pdc:5d} rank peak {peak / 1048576:5.1f} MiB  {hist}")
        del ix, dd
        gc.collect()
    print(f"\n=== 6. the cap's own cost (R-A2L-MATCH.38): the graph parses before it checks the length")
    ix = R2(ref)
    for desc, qy in (("'e ' x 32768", "e " * 32768), ("'a' x 65536", "a" * 65536), ("'0 ' x 32768", "0 " * 32768),
                     ("1,604 real names joined by ','", ",".join(random.Random(20261108).sample(sw_a, 2000))[:65536])):
        m, _ = med_ms(ix, qy)
        t0 = time.perf_counter()
        for _ in range(7):
            query_parts(qy, True)
        tp = (time.perf_counter() - t0) / 7 * 1000
        t0 = time.perf_counter()
        for _ in range(7):
            len(qy.strip(" \t\n\r\x0b\x0c")) > QCAP
        ts = (time.perf_counter() - t0) / 7 * 1000
        print(f"  {desc:34s} {len(qy):6d} chars: rank -> {ix.rank(qy, 20)!r} in {m:6.1f} ms (parse alone {tp:6.1f} ms; strip + length check alone {ts:6.3f} ms)")
    print(f"\nload after = {os.getloadavg()}")
    return 0


def adv2():
    """Round-2 follow-up: collapse duplicate query tokens (a multiset) -- same lists? cost? And distinct
    near tokens, which collapsing does not remove."""
    header("adv2")
    sw_a, ref, c6 = lists()
    L = "abcdefghijklmnopqrstuvwxyz"
    near = ["ch" + c for c in L] + [c + "ha" for c in L] + ["c" + c + "a" for c in L]
    shapes = {
        "REF": [("'qzx ' x 64", "qzx " * 64), ("'e ' x 128 (QSET)", "e " * 128), ("'0 ' x 128 (QSET)", "0 " * 128),
                ("'qz?' 26 distinct (103 chars)", " ".join("qz" + c for c in L)),
                ("'qz?' 26 distinct, twice, cut at 256", ((" ".join("qz" + c for c in L) + " ") * 3)[:256])],
        "REF6": [("'chr ' x 64", "chr " * 64), ("'cahr ' x 51", "cahr " * 51), ("'0 ' x 128", "0 " * 128),
                 ("'00 ' x 85", "00 " * 85), ("'c 0 ' x 64", "c 0 " * 64),
                 ("'ch?' 26 distinct (103 chars)", " ".join(near[:26])),
                 ("'ch?' + '?ha' + 'c?a', 64 distinct (255 chars)", " ".join(near)[:256]),
                 ("'cha' .. 'chz' 3x, cut at 256", ((" ".join(near[:26]) + " ") * 3)[:256])],
    }
    for label, names in (("REF", ref), ("REF6", c6)):
        print(f"\n=== 7. {label}: R2 (graph) vs R2 with collapsed duplicate query tokens, limit 20, median of 7; load {os.getloadavg()}")
        ix, cx = R2(names), R2(names, collapse=True)
        bad = 0
        for desc, qy in shapes[label]:
            ix.walks = cx.walks = 0
            res = ix.rank(qy, 20)
            w1 = ix.walks
            same = cx.rank(qy, 20) == res
            bad += not same
            w2 = cx.walks
            m, _ = med_ms(ix, qy)
            m2, _ = med_ms(cx, qy)
            hist: dict = {}
            for r in res:
                hist[r[1]] = hist.get(r[1], 0) + 1
            print(f"  {desc:48s} chars {len(qy.strip()):3d} tokens {len(tokens(qy)):3d} distinct {len(set(query_parts(qy, True)[2])):3d}: "
                  f"R2 {m:7.1f} ms (walks {w1:3d})  collapsed {m2:7.1f} ms (walks {w2:3d})  same lists: {same}  {hist}")
        print(f"  {label}: collapsed lists differ from R2 in {bad} shapes")
        del ix, cx
        gc.collect()
    # the same equality on the check-mode query sets, to show collapsing changes no list
    rng2 = random.Random(20261107)
    gen = [mutate(rng2, rng2.choice(ref)) for _ in range(300)]
    ix, cx = R2(ref), R2(ref, collapse=True)
    qs = qset33(sw_a, ref) + multi12(sw_a) + gen + ["value value", "map map 0 0", "vlaue vlaue_0001"]
    bad = sum(ix.rank(q, 20) != cx.rank(q, 20) for q in qs)
    print(f"\n  REF, {len(qs)} queries (QSET, round-1 multi-word, 300 generated, 3 with repeated words): collapsed != R2 in {bad}")
    case08 = names_of(OUT / "firmware.a2l")
    i8, c8 = R2(case08), R2(case08, collapse=True)
    qs8 = ["value value", "vlaue vlaue", "map map 0020", "valu valu 0001", "curve curve curve", "cuvre cuvre", "0001 0001", "blk blk val"]
    for q in qs8:
        a, b = i8.rank(q, 20), c8.rank(q, 20)
        assert a == b == naive_rank_r2(q, case08, 20), q
    print(f"  C08, {len(qs8)} repeated-word queries: R2 == collapsed == oracle(ruled) (asserted; e.g. 'cuvre cuvre' -> {i8.rank('cuvre cuvre', 2)})")
    print(f"\nload after = {os.getloadavg()}")
    return 0


if __name__ == "__main__":
    raise SystemExit({"check": check, "time": timing, "adv": adv, "adv2": adv2}[sys.argv[1]]())
