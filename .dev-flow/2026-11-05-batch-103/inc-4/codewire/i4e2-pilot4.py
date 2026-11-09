#!/usr/bin/env python3
"""batch-103 Inc 4 E2 pilot v4: a compact prepared index for R-A2L-MATCH.35-.37.

THROWAWAY EVIDENCE, NOT PRODUCT CODE. Run on <runner> next to the E1
pilots v1-v3, copied unchanged from inc-4/evidence-e1/ into PILOT_DIR; their
oracle (naive_rank_b, evaluate_b) and their index (IndexB, v3) are the
reference this pilot is checked against.

IndexC keeps v3's tiers (rank order B, stop once `limit` names are found) and
its alignment walk, and replaces only the structures that held the memory:
  * no dict trie: the fuzzy step walks a PRE-ORDER ARRAY TRIE of the sorted
    distinct folded tokens (one string of node characters and three
    array('I'): depth, first token id, subtree end), with the alignment
    column capped at k + 1 and computed on the band |row - depth| <= k only
    (a first variant over the bare sorted list met the bounds at 158.3 ms
    worst; this one is the design the graph pins);
  * no per-name tuple of token strings: one flat array('I') of token ids
    (id = position in the sorted token list) and one array('I') of offsets;
  * no dict of Python lists for the postings: one CSR pair of array('I')
    (a run of token ids is one slice of the postings);
  * no per-name boundary bitmask: a boundary offset is tested on the name
    itself (offset 0, a separator, or a token start read from the neighbours);
  * the per-name character masks in one array('Q').
Checks: IndexC == naive_rank_b (v3's pool, 409 queries x 4 limits) and on
every example of 02-test-cases.md; IndexC == IndexB on the 50,000-name
reference list (QSET and 300 generated queries); then the timing of .35/.36
and the tracemalloc peak of .37 for IndexC and, as the baseline, IndexB.
"""
from __future__ import annotations

import bisect
import gc
import os
import random
import runpy
import statistics
import sys
import time
import tracemalloc
from array import array
from pathlib import Path

HERE = Path(os.environ.get("PILOT_DIR", "/tmp/b103-e2-4"))
P3 = runpy.run_path(str(HERE / "i4e1-pilot3.py"), run_name="i4e1_pilot_v3")
IndexB, naive_rank_b, evaluate_b, RULES_B = P3["IndexB"], P3["naive_rank_b"], P3["evaluate_b"], P3["RULES_B"]
tokens, fold, allowed, is_subseq, query_parts = P3["tokens"], P3["fold"], P3["allowed"], P3["is_subseq"], P3["query_parts"]
names_of, REPO, OUT, s19_app = P3["names_of"], P3["REPO"], P3["OUT"], P3["s19_app"]
P1 = P3["P1"]
_bit, _mask, _sep = P1["_bit"], P1["_mask"], P1["_sep"]
_FOLD = {c: c + 32 for c in range(65, 91)}


def _up(c):
    return "A" <= c <= "Z"


def _lo(c):
    return "a" <= c <= "z"


def _dig(c):
    return "0" <= c <= "9"


def at_boundary(name: str, p: int) -> bool:
    """Offset p of name is offset 0, a separator, or the first offset of a token."""
    if p == 0:
        return True
    c = name[p]
    if _sep(c):
        return True
    b = name[p - 1]
    if _sep(b):
        return True
    if _dig(c) != _dig(b):
        return True
    if _up(c):
        if _lo(b):
            return True
        if _up(b) and p + 1 < len(name) and _lo(name[p + 1]):
            return True
    return False


def prefix_end(utok: list, prefix: str, lo: int) -> int:
    """First index >= lo whose token does not start with prefix (utok sorted)."""
    last = ord(prefix[-1])
    if last < 0x10FFFF:
        return bisect.bisect_left(utok, prefix[:-1] + chr(last + 1), lo)
    j = lo
    while j < len(utok) and utok[j].startswith(prefix):
        j += 1
    return j


def prefix_range(utok: list, prefix: str) -> tuple:
    lo = bisect.bisect_left(utok, prefix)
    return lo, prefix_end(utok, prefix, lo)


def build_nodes(utok: list) -> tuple:
    """The pre-order array trie of the sorted distinct tokens.

    One node per distinct non-empty token prefix, in pre-order (= the sorted
    order of the tokens): chars[j] is the node's last character, depth[j] its
    length, first[j] the id of the first token under it (the token that made
    it), end[j] the index after its subtree. first[len(depth)] is a sentinel
    equal to len(utok), so the tokens under node j are first[j] .. first[end[j]] - 1.
    """
    chars = []
    depth = array("I")
    first = array("I")
    end = array("I")
    stack = []
    prev = ""
    for tid, t in enumerate(utok):
        lim = len(prev) if len(prev) < len(t) else len(t)
        l = 0
        while l < lim and prev[l] == t[l]:
            l += 1
        for d in range(l + 1, len(t) + 1):
            j = len(depth)
            while stack and depth[stack[-1]] >= d:
                end[stack.pop()] = j
            chars.append(t[d - 1])
            depth.append(d)
            first.append(tid)
            end.append(0)
            stack.append(j)
        prev = t
    n = len(depth)
    while stack:
        end[stack.pop()] = n
    first.append(len(utok))
    return "".join(chars), depth, first, end


def fuzzy_walk(utok: list, nodes: tuple, q: str, k: int) -> dict:
    """{token id: prefix distance} for every distinct token within k of q (k >= 1).

    The alignment of v2/v3's trie walk (one OSA column per node, the best
    prefix distance carried down, prune when the column minimum is above k or
    not below the best) over the pre-order array trie instead of a dict trie.
    Columns are capped at k + 1 and only the band |row - depth| <= k is
    computed (every value outside it is above k): exact for every decision
    the walk makes, since it compares values with k and with values <= k only.
    """
    chars, depth, first, end = nodes
    m = len(q)
    cap = k + 1
    res: dict = {}
    n = len(depth)
    cols = [None] * 66
    best = [0] * 66
    pch = [""] * 66
    cols[0] = [i if i < cap else cap for i in range(m + 1)]
    best[0] = m if m < cap else cap
    j = 0
    while j < n:
        dep = depth[j]
        if dep + 1 >= len(cols):
            cols.extend([None] * dep)
            best.extend([0] * dep)
            pch.extend([""] * dep)
        c = chars[j]
        prev = cols[dep - 1]
        new = [cap] * (m + 1)
        low = new[0] = dep if dep < cap else cap
        lo_r = dep - k if dep - k > 1 else 1
        hi_r = dep + k if dep + k < m else m
        if dep >= 2:
            prev2 = cols[dep - 2]
            pchar = pch[dep - 1]
            for ii in range(lo_r, hi_r + 1):
                qi = q[ii - 1]
                v = prev[ii - 1] + (0 if qi == c else 1)
                a = prev[ii] + 1
                if a < v:
                    v = a
                a = new[ii - 1] + 1
                if a < v:
                    v = a
                if ii > 1 and qi == pchar and q[ii - 2] == c:
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
                v = prev[ii - 1] + (0 if q[ii - 1] == c else 1)
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
        bd = best[dep - 1]
        b2 = bd if bd < new[m] else new[m]
        if low > k or low >= b2:
            if b2 <= k:
                for t in range(first[j], first[end[j]]):
                    res[t] = b2
            j = end[j]
            continue
        cols[dep] = new
        best[dep] = b2
        pch[dep] = c
        if b2 <= k and len(utok[first[j]]) == dep:
            res[first[j]] = b2
        j += 1
    return res


class IndexC:
    def __init__(self, names):
        uniq = tuple(dict.fromkeys(names))
        self.names = uniq
        folded = [n.translate(_FOLD) for n in uniq]
        self.folded = folded
        count = len(uniq)
        nmask = array("Q", bytes(8 * count))
        tid: dict = {}
        ntid = array("I")
        noff = array("I", [0])
        for i, n in enumerate(uniq):
            nf = folded[i]
            mk = 0
            for ch in set(nf):
                mk |= _bit(ch)
            nmask[i] = mk
            for s, e in tokens(n):
                t = nf[s:e]
                x = tid.get(t)
                if x is None:
                    x = len(tid)
                    tid[t] = x
                ntid.append(x)
            noff.append(len(ntid))
        utok = sorted(tid)
        remap = array("I", bytes(4 * len(utok)))
        for sid, t in enumerate(utok):
            remap[tid[t]] = sid
        del tid
        for j in range(len(ntid)):
            ntid[j] = remap[ntid[j]]
        del remap
        ntok = len(utok)
        poff = array("I", bytes(4 * (ntok + 1)))
        for i in range(count):
            for x in set(ntid[noff[i]:noff[i + 1]]):
                poff[x + 1] += 1
        for x in range(ntok):
            poff[x + 1] += poff[x]
        post = array("I", bytes(4 * poff[ntok]))
        cur = array("I", poff)
        for i in range(count):
            for x in set(ntid[noff[i]:noff[i + 1]]):
                post[cur[x]] = i
                cur[x] += 1
        del cur
        self.nodes = build_nodes(utok)
        self.nmask, self.utok, self.ntid, self.noff, self.post, self.poff = nmask, utok, ntid, noff, post, poff
        self.tier_disagree = 0

    def sizes(self) -> dict:
        g = sys.getsizeof
        return {
            "names (tuple, strings are the caller's)": g(self.names),
            "folded (list + strings)": g(self.folded) + sum(g(s) for s in self.folded),
            "utok (list + strings)": g(self.utok) + sum(g(s) for s in self.utok),
            "nmask array Q": g(self.nmask),
            "ntid array I": g(self.ntid),
            "noff array I": g(self.noff),
            "post array I": g(self.post),
            "poff array I": g(self.poff),
            "trie node chars (str)": g(self.nodes[0]),
            "trie node depth array I": g(self.nodes[1]),
            "trie node first-token array I": g(self.nodes[2]),
            "trie node subtree-end array I": g(self.nodes[3]),
        }

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
                nm = names[i]
                key = 1
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
            if ranges and all(lo < hi for lo, hi in ranges):  # tier 3: token
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
            if found < limit and qtoks:  # tier 4: fuzzy
                dists = []
                for qt in qtoks:
                    k = allowed(qt)
                    if k == 0:
                        lo, hi = prefix_range(utok, qt)
                        d = dict.fromkeys(range(lo, hi), 0)
                    else:
                        d = fuzzy_walk(utok, self.nodes, qt, k)
                    if not d:
                        dists = []
                        break
                    dists.append(d)
                if dists:
                    sizes = [sum(poff[t + 1] - poff[t] for t in d) for d in dists]
                    r = min(range(len(dists)), key=sizes.__getitem__)
                    cand = set()
                    for t in dists[r]:
                        cand.update(post[poff[t]:poff[t + 1]])
                    cand -= taken
                    ntid, noff = self.ntid, self.noff
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
                            groups.setdefault((4, total, len(names[i])), []).append(i)
                            taken.add(i)
                            found += 1
            if found < limit:  # tier 5: subsequence
                kmask = _mask(keys)
                nmask = self.nmask
                for i in range(len(folded)):
                    if kmask & ~nmask[i] or i in taken:
                        continue
                    if is_subseq(keys, folded[i]) is not None:
                        groups.setdefault((5, 0, len(names[i])), []).append(i)
        out = []
        for gk in sorted(groups):
            keyed = sorted(
                (0 if self._case_exact(query, q, names[i], gk[0]) else 1, names[i]) for i in groups[gk]
            )
            for _, name in keyed:
                ev = evaluate_b(query, name)
                if ev[0] != gk[0] or ev[1] != gk[1]:
                    self.tier_disagree += 1
                out.append((name, RULES_B[ev[0]], ev[1], ev[2]))
                if len(out) >= limit:
                    return out
        return out


def fmt(rows) -> list:
    if not rows:
        return ["    (empty)"]
    return [f"    {name!r:56s} {rule:11s} edits/key={key} spans={spans}" for name, rule, key, spans in rows]


def mutate(rng, name: str) -> str:
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


def peak_of(cls, ref) -> tuple:
    gc.collect()
    tracemalloc.start()
    idx = cls(ref)
    cur, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return idx, cur, peak


def main() -> int:
    print(f"s19_app.__file__ = {s19_app.__file__}")
    print(f"python = {sys.version.split()[0]}")
    print(f"host = {os.uname().nodename}  load = {os.getloadavg()}  cpus = {os.cpu_count()}")
    print(f"HOME = {os.environ.get('HOME')}  LOCALAPPDATA = {os.environ.get('LOCALAPPDATA')}  PILOT_DIR = {HERE}")
    case08 = names_of(OUT / "firmware.a2l")
    issues = names_of(OUT / "firmware_issues.a2l")
    sw_a = names_of(REPO / "examples/case_00_public/software_a.a2l")
    sw_b = names_of(REPO / "examples/case_00_public/software_b.a2l")
    bal = names_of(REPO / "examples/case_00_public/BalanceTube_STMicro.a2l")
    src = names_of(REPO / "examples/case_00_public/from_source.a2l")
    print(f"names: case08 {len(case08)}  case08_issues {len(issues)}  software_a {len(sw_a)}  software_b {len(sw_b)}  BalanceTube {len(bal)}  from_source {len(src)}")

    print("\n=== 1. every example of 02-test-cases.md: IndexC vs the v3 oracle naive_rank_b")
    cur = ["ABSValue", "AValue", "engineSpeed", "Map3D"]
    nonascii = ["Drück_Max", "DRÜCK_MAX", "druck_max"]
    ex = [  # the list of i4e1-pilot3.py section 1, unchanged
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
    built: dict = {}
    bad1 = 0
    for label, names, qy, lim in ex:
        key = (label, id(names))
        if key not in built:
            built[key] = IndexC(names)
        got = built[key].rank(qy, lim)
        want = naive_rank_b(qy, names, lim)
        ok = got == want
        bad1 += not ok
        print(f"[{label}] query={qy!r} limit={lim}  IndexC == oracle: {ok}")
        for line in fmt(got):
            print(line)
    print("AT-B103-I4-1: typing over case08, limit 5")
    idx08 = built[("C08", id(case08))]
    for qy in ["m", "ma", "map", "map_", "map_00", "map_002", "map_0020"]:
        got = idx08.rank(qy, 5)
        ok = got == naive_rank_b(qy, case08, 5)
        bad1 += not ok
        print(f"[C08] query={qy!r} limit=5  IndexC == oracle: {ok}")
        for line in fmt(got):
            print(line)
    print("AT-B103-I4-2: software_a, limit 5")
    idxa = IndexC(sw_a)
    target = sw_a[1234]
    print(f"target software_a[1234] = {target!r}")
    for qy in [target, "jotafvod", "msrqlLzL", "pfue._0_", "jotaf vod", "vod jotaf", "jotfa vod", "jotaf_vdo"]:
        got = idxa.rank(qy, 5)
        ok = got == naive_rank_b(qy, sw_a, 5)
        bad1 += not ok
        pos = next((i for i, r in enumerate(got) if r[0] == target), None)
        print(f"[SWA] query={qy!r} limit=5  IndexC == oracle: {ok}  target position = {pos}  entry = {got[pos] if pos is not None else None}")
    disagree1 = sum(ix.tier_disagree for ix in built.values()) + idxa.tier_disagree
    print(f"  section 1: mismatches = {bad1}; tier rule/key vs evaluate_b disagreements = {disagree1}")

    print("\n=== 2. IndexC vs naive_rank_b on v3's pool and queries (i4e1-pilot3.py section 3, seed 20261106)")
    rng = random.Random(20261106)
    pool = sorted(set(rng.sample(sw_a, 600) + rng.sample(bal, 60) + rng.sample(src, 40) + rng.sample(sw_b, 40) + case08[:200] + ["RPM", "rpm", "Drück_Max", "DRÜCK_MAX"]))
    idxp = IndexC(pool)
    qs = []
    for _ in range(400):  # the generator of i4e1-pilot3.py section 3, unchanged
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
    bad2 = 0
    for qy in qs:
        full = naive_rank_b(qy, pool, 100000)
        for lim in (1, 5, 50, 100000):
            if full[:lim] != idxp.rank(qy, lim):
                bad2 += 1
                if bad2 <= 5:
                    print(f"  MISMATCH query={qy!r} limit={lim}")
    print(f"  pool {len(pool)} names, {len(qs)} queries x 4 limits: mismatches = {bad2}; tier disagreements = {idxp.tier_disagree}")

    print("\n=== 3. the reference list REF (02-test-cases.md fixture): IndexC vs IndexB (v3)")
    ref = (sw_a + [n + "_1" for n in sw_a] + [n + "_2" for n in sw_a] + [n + "_3" for n in sw_a])[:50000]
    qset = ["a", "e", "0", "zz", "ab", "JotafVod_msrqlLzL_kh2C_rWl_pfue._0_", "JotafVod_msr", "srqlLzL_", "0 jotaf", "JVmL",
            "xqzjvkw", "qqqq zzzz", "aaaa", "e e e", "Nzukij", "Ierxjr_Eud", "ledRing", "pposbxiif", "cnt", "temp_sensor_max",
            "x y z w v u", "pposbxiifkdgfiajnbbpvb_dyan_xvz1"]
    rng2 = random.Random(20261107)
    gen = [mutate(rng2, rng2.choice(ref)) for _ in range(300)]
    big_b = IndexB(ref)
    big_c = IndexC(ref)
    print(f"  REF {len(ref)} names, unique {len(set(ref))}, distinct tokens IndexB {len(big_b.utok)} IndexC {len(big_c.utok)}  same token list: {big_b.utok == big_c.utok}")
    bad3 = 0
    for qy in qset + gen:
        if big_b.rank(qy, 20) != big_c.rank(qy, 20):
            bad3 += 1
            if bad3 <= 5:
                print(f"  MISMATCH query={qy!r}")
    print(f"  {len(qset)} QSET + {len(gen)} generated queries (seed 20261107), limit 20: mismatches = {bad3}; tier disagreements = {big_c.tier_disagree}")
    del big_b, big_c
    gc.collect()

    print("\n=== 4. memory (R-A2L-MATCH.37): tracemalloc during one preparation of REF (no other index alive)")
    for label, cls in (("IndexB (v3, dict trie; baseline)", IndexB), ("IndexC (v4, compact)", IndexC)):
        idx, cur_b, peak_b = peak_of(cls, ref)
        verdict = "<= 64 MiB" if peak_b <= 67_108_864 else "> 64 MiB"
        print(f"  {label}: peak {peak_b:,} bytes = {peak_b / 1048576:.1f} MiB ({verdict}); retained after build {cur_b:,} bytes = {cur_b / 1048576:.1f} MiB")
        if cls is IndexC:
            for part, size in idx.sizes().items():
                print(f"      {part:42s} {size:>12,} bytes")
        del idx
        gc.collect()

    print("\n=== 5. timing (R-A2L-MATCH.35, .36) of IndexC on REF")
    print(f"  load before = {os.getloadavg()}")
    builds = []
    big = None
    for _ in range(3):
        big = None
        gc.collect()
        t0 = time.perf_counter()
        big = IndexC(ref)
        builds.append(time.perf_counter() - t0)
    print(f"  build: {[round(b, 3) for b in builds]} s  median {statistics.median(builds):.3f} s")
    worst = (0.0, "")
    for qy in qset:
        runs = []
        for _ in range(7):
            t0 = time.perf_counter()
            res = big.rank(qy, 20)
            runs.append(time.perf_counter() - t0)
        med = statistics.median(runs) * 1000
        if med > worst[0]:
            worst = (med, qy)
        hist: dict = {}
        for row in res:
            hist[row[1]] = hist.get(row[1], 0) + 1
        print(f"  limit=20 query={qy!r:40s} median {med:7.1f} ms  max {max(runs) * 1000:7.1f} ms  results {len(res):3d} {hist}")
    print(f"  limit=20: worst median over {len(qset)} queries = {worst[0]:.1f} ms (query {worst[1]!r})")
    print(f"  load after = {os.getloadavg()}")
    print(f"\nSUMMARY mismatches: section1 {bad1}, section2 {bad2}, section3 {bad3}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
