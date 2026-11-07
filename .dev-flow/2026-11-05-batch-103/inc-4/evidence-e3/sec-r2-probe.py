#!/usr/bin/env python3
"""batch-103 Inc 4 E3 ROUND-2 security probe. THROWAWAY EVIDENCE, NOT PRODUCT CODE.

Runs on cachyos-rtx only, next to an unchanged copy of the E1/E2 pilot files
(PILOT_DIR). Class R2 follows the CORRECTED pinned procedure of
graph-inc4.md:176-182 (records at 15129b64):
  step 1  parse (strip, fold, tokens), None -> [], then the stripped query
          longer than 256 characters -> [] (R-A2L-MATCH.38); flag CAP_FIRST
          moves the length check before the fold/tokenise (not the graph order)
  step 2-3  the pilot's text and token tiers (IndexC, unchanged)
  step 4  FUZZY one query token at a time in ascending allowed edits, maps
          computed lazily, candidates intersected after each walk, stop when
          empty, at most 300 candidates -> per-candidate check with a CAPPED
          prefix distance memoised per (query token position, token id)
  step 5  the pilot's subsequence tier
  step 6  case-exactness only for exact / prefix / substring by string
          comparison on the raw stripped query; substring variant SUB:
          "any" = raw `in` (CTX definition, 01-requirements.md:64-67),
          "boundary" = a raw occurrence at a boundary offset (graph :182)
  every listed entry from classify() = evaluate_b with the capped distance.
The build drops names longer than 1,024 characters (R-A2L-MATCH.39).
Oracle: naive_r2 = evaluate_b (uncapped) per name, the same order key.
Modes: check, perf, mem, paste, spans, det. Every case runs under an
address-space cap and a per-case alarm.
"""
from __future__ import annotations

import gc
import hashlib
import os
import random
import resource
import runpy
import signal
import statistics
import sys
import time
import tracemalloc
from pathlib import Path

HERE = Path(os.environ["PILOT_DIR"])
P4 = runpy.run_path(str(HERE / "i4e2-pilot4.py"), run_name="i4e2_pilot_v4")
IndexC, names_of, REPO, s19_app = P4["IndexC"], P4["names_of"], P4["REPO"], P4["s19_app"]
P3, P1 = P4["P3"], P4["P1"]
evaluate_b, RULES_B = P3["evaluate_b"], P3["RULES_B"]
tokens, fold, allowed, is_subseq, query_parts = P4["tokens"], P4["fold"], P4["allowed"], P4["is_subseq"], P4["query_parts"]
prefix_range, fuzzy_walk, at_boundary, _mask = P4["prefix_range"], P4["fuzzy_walk"], P4["at_boundary"], P4["_mask"]
merge, WS = P1["merge"], P1["WS"]
osa_prefix = P1["osa_prefix"]
QCAP, NCAP, CAND_MAX = 256, 1024, 300
EVID = Path(os.environ.get("EVID_DIR", "/tmp/b103-e3r2-4-security"))

CAP = int(os.environ.get("AS_CAP_GIB", "8")) << 30
resource.setrlimit(resource.RLIMIT_AS, (CAP, CAP))


class Budget(Exception):
    pass


def _alarm(signum, frame):
    raise Budget()


signal.signal(signal.SIGALRM, _alarm)


def osa_cap(q: str, t: str, cap: int) -> int:
    """min(osa_prefix(q, t), cap + 1); stops once a whole row is above cap
    (safe for OSA: D[i][j-1] <= D[i-1][j-2] + 1). No band, as the graph pins
    _prefix_distance (graph-inc4.md, node _prefix_distance)."""
    m, n = len(q), len(t)
    prev2 = None
    prev = list(range(n + 1))
    for i in range(1, m + 1):
        cur = [i] + [0] * n
        qi = q[i - 1]
        lo = i
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
            if v < lo:
                lo = v
        if lo > cap:
            return cap + 1
        prev2, prev = prev, cur
    d = min(prev)
    return d if d <= cap else cap + 1


def classify(qq, qtoks, keys, name):
    """_classify of the graph: evaluate_b's chain on the folded name, capped distance."""
    nn = fold(name)
    if nn == qq:
        return (0, 0, [(0, len(nn))])
    if nn.startswith(qq):
        return (1, 0, [(0, len(qq))])
    p = nn.find(qq)
    if p >= 0:
        first = p
        while p >= 0:
            if at_boundary(name, p):
                return (2, 0, [(p, p + len(qq))])
            p = nn.find(qq, p + 1)
        return (2, 1, [(first, first + len(qq))])
    ntok = [(nn[s:e], s, e) for s, e in tokens(name)]
    if qtoks:
        spans = []
        for qt in qtoks:
            hit = next(((s, s + len(qt)) for t, s, _ in ntok if t.startswith(qt)), None)
            if hit is None:
                break
            spans.append(hit)
        else:
            return (3, 0, merge(spans))
    if qtoks and ntok:
        total, spans = 0, []
        for qt in qtoks:
            k = allowed(qt)
            best = None
            for t, s, e in ntok:
                d = osa_cap(qt, t, k)
                if best is None or d < best[0]:
                    best = (d, s, e)
            if best[0] > k:
                break
            total += best[0]
            spans.append((best[1], best[2]))
        else:
            return (4, total, merge(spans))
    pos = is_subseq(keys, nn)
    if pos is not None:
        return (5, 0, merge([(p, p + 1) for p in pos]))
    return None


def ce_raw(q: str, name: str, rule: int, sub: str) -> bool:
    if rule == 0:
        return name == q
    if rule == 1:
        return name.startswith(q)
    if rule == 2:
        if sub == "any":
            return q in name
        p = name.find(q)
        while p >= 0:
            if at_boundary(name, p):
                return True
            p = name.find(q, p + 1)
        return False
    return False


class R2(IndexC):
    def __init__(self, names, sub="any", fz="lazy", cap_first=False):
        super().__init__([n for n in names if len(n) <= NCAP])
        self.sub, self.fz, self.cap_first = sub, fz, cap_first
        self.stats = {}

    def _fuzzy(self, qtoks, taken):
        utok, post, poff, ntid, noff, nodes = self.utok, self.post, self.poff, self.ntid, self.noff, self.nodes
        info = [(qt, allowed(qt)) for qt in qtoks]
        order = sorted(range(len(info)), key=lambda j: info[j][1])
        dists = [None] * len(info)
        cand = None
        walks = 0
        for j in order:
            if self.fz == "lazy" and cand is not None and len(cand) <= CAND_MAX:
                break
            qt, k = info[j]
            if k == 0:
                lo, hi = prefix_range(utok, qt)
                d = dict.fromkeys(range(lo, hi), 0)
            else:
                d = fuzzy_walk(utok, nodes, qt, k)
            walks += 1
            if not d:
                self.stats.update(walks=walks, cand=0)
                return {}
            dists[j] = d
            have = set()
            for t in d:
                have.update(post[poff[t]:poff[t + 1]])
            cand = (have - taken) if cand is None else (cand & have)
            if not cand:
                self.stats.update(walks=walks, cand=0)
                return {}
        self.stats.update(walks=walks, cand=len(cand))
        memo = [dict() for _ in info]
        out = {}
        checks = 0
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
                            checks += 1
                            v = memo[j][t] = osa_cap(qt, utok[t], k)
                        if v > k:
                            v = None
                    if v is not None and (bst is None or v < bst):
                        bst = v
                if bst is None:
                    break
                total += bst
            else:
                out[i] = total
        self.stats["checks"] = checks
        return out

    def rank(self, query: str, limit: int) -> list:
        self.stats = {}
        if limit < 1:
            return []
        if self.cap_first and len(query.strip(WS)) > QCAP:
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
            ranges = [prefix_range(utok, qt) for qt in (dict.fromkeys(qtoks) if getattr(self, 'dedup_tok', False) else qtoks)]
            if ranges and all(lo < hi for lo, hi in ranges):
                order = sorted(range(len(ranges)), key=lambda j: poff[ranges[j][1]] - poff[ranges[j][0]])
                lo, hi = ranges[order[0]]
                cand = set(post[poff[lo]:poff[hi]])
                cand -= taken
                inter = 0
                for j in order[1:]:
                    if not cand:
                        break
                    lo, hi = ranges[j]
                    cand.intersection_update(post[poff[lo]:poff[hi]])
                    inter += 1
                self.stats["token_intersections"] = inter
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
        sorted_members = 0
        for gk in sorted(groups):
            members = groups[gk]
            sorted_members += len(members)
            keyed = sorted((0 if ce_raw(q, names[i], gk[0], self.sub) else 1, names[i]) for i in members)
            for _, name in keyed:
                ev = classify(qf, qtoks, keys, name)
                if ev is None or ev[0] != gk[0] or ev[1] != gk[1]:
                    self.tier_disagree += 1
                out.append((name, RULES_B[ev[0]], ev[1], ev[2]))
                if len(out) >= limit:
                    self.stats["sorted_members"] = sorted_members
                    return out
        self.stats["sorted_members"] = sorted_members
        return out


def naive_r2(query, names, limit, sub="any"):
    """The corrected rows by definition: evaluate_b per name (uncapped OSA)."""
    if limit < 1:
        return []
    q = query.strip(WS)
    if len(q) > QCAP:
        return []
    rows = []
    for name in dict.fromkeys(n for n in names if len(n) <= NCAP):
        ev = evaluate_b(query, name)
        if ev is None:
            continue
        ce = ce_raw(q, name, ev[0], sub)
        rows.append(((ev[0], ev[1], len(name), 0 if ce else 1, name), ev))
    rows.sort(key=lambda r: r[0])
    return [(r[0][4], RULES_B[r[1][0]], r[1][1], r[1][2]) for r in rows[:limit]]


# ---------------------------------------------------------------- harness
def run(fn, budget):
    gc.collect()
    signal.alarm(budget)
    t0 = time.perf_counter()
    try:
        out, status = fn(), "ok"
    except Budget:
        out, status = None, f"STOPPED at {budget} s"
    except MemoryError:
        out, status = None, f"MemoryError (cap {CAP >> 30} GiB)"
    except Exception as e:  # noqa: BLE001 - the probe counts every exception
        out, status = None, f"EXCEPTION {e!r}"
    finally:
        signal.alarm(0)
    return time.perf_counter() - t0, status, out


def header():
    print(f"s19_app.__file__ = {s19_app.__file__}")
    print(f"python = {sys.version.split()[0]}  PYTHONHASHSEED = {os.environ.get('PYTHONHASHSEED')}")
    print(f"host = {os.uname().nodename}  load = {os.getloadavg()}  cpus = {os.cpu_count()}  RLIMIT_AS = {CAP >> 30} GiB")
    print(f"HOME = {os.environ.get('HOME')}  LOCALAPPDATA = {os.environ.get('LOCALAPPDATA')}  PILOT_DIR = {HERE}")


def bad_spans(rows):
    n = 0
    for name, rule, key, sp in rows or []:
        ok = len(sp) >= 1 and all(0 <= s < e <= len(name) for s, e in sp) and all(sp[i][1] < sp[i + 1][0] for i in range(len(sp) - 1))
        n += not ok
    return n


def load():
    sw_a = names_of(REPO / "examples/case_00_public/software_a.a2l")
    ref = (sw_a + [n + "_1" for n in sw_a] + [n + "_2" for n in sw_a] + [n + "_3" for n in sw_a])[:50000]
    ref6 = names_of(REPO / "examples/case_06_large_nested_a2l/firmware.a2l")[:50000]
    return sw_a, ref, ref6


QSET22 = ["a", "e", "0", "zz", "ab", "JotafVod_msrqlLzL_kh2C_rWl_pfue._0_", "JotafVod_msr", "srqlLzL_", "0 jotaf", "JVmL",
          "xqzjvkw", "qqqq zzzz", "aaaa", "e e e", "Nzukij", "Ierxjr_Eud", "ledRing", "pposbxiif", "cnt", "temp_sensor_max",
          "x y z w v u", "pposbxiifkdgfiajnbbpvb_dyan_xvz1"]
MULTI3 = ["njraipjtbtu lsuakcoj hsxgibymjxu orfltalc uadvdygb zobnkw", "votklbi fjblnabj qghque pdjxmq tiprdynotu djchlitjt",
          "lmmwngodou jadkvqy khbnukc qomfrybiza evfwbqj"]
REF6Q = ["m", "meas_", "chr", "mesa", "cahr", "cr0", "char 1", "0", "chr 0", "ch00", "meas 1", "c 0 1"]
ABC = " ".join("abcdefghijklmnopqrstuvwxyz") + " "


def qset_shapes(sw_a, ref):
    """The 8 E3S-01 shapes 02-test-cases.md:20 adds to QSET (seeds as round 1)."""
    rng = random.Random(20261108)
    pool = rng.sample(sw_a, 400)
    by_tok = sorted(ref, key=lambda n: (-len(tokens(n)), n))[0]
    by_len = sorted(ref, key=lambda n: (-len(n), n))[0]
    return {
        "'e ' x 128": "e " * 128,
        "'a b c ... z ' cut at 256": (ABC * 5)[:256],
        "'0 ' x 128": "0 " * 128,
        "'a' x 256": "a" * 256,
        "SWA names joined by ',' (draw 1)": ",".join(pool)[:256],
        "SWA names joined by ',' (draw 2)": ",".join(pool[200:])[:256],
        f"longest REF name by tokens ({len(tokens(by_tok))} tok, {len(by_tok)} ch)": by_tok,
        "  the same with a transposition": by_tok[1] + by_tok[0] + by_tok[2:],
        f"longest REF name by characters ({len(by_len)} ch)": by_len,
    }


def extra_shapes():
    """Shapes the brief names, beyond QSET: many short tokens, repeated letters, digits, non-ASCII."""
    return {
        "'1a' x 128 (256 one-char tokens, no separator)": "1a" * 128,
        "'aB' x 128 (camel cuts: 128 tokens)": "aB" * 128,
        "'aBcd' x 64 (64 fuzzy tokens, no separator)": "aBcd" * 64,
        "'x y z w v u ' cut at 256": ("x y z w v u " * 22)[:256],
        "'a' x 255": "a" * 255,
        "'e' x 255": "e" * 255,
        "'z' x 255": "z" * 255,
        "'ab' x 127 + 'a' (255)": "ab" * 127 + "a",
        "digits '0123456789' cut at 256 (one token)": ("0123456789" * 26)[:256],
        "'0' x 256": "0" * 256,
        "'1 2 3 ' cut at 256": ("1 2 3 " * 43)[:256],
        "'é' x 256": "é" * 256,
        "'é ' x 128": "é " * 128,
        "'漢字 ' cut at 256": ("漢字 " * 86)[:256],
        "'Ä' x 256": "Ä" * 256,
        "'İ' x 256": "İ" * 256,
        "'U+1F600 ' x 128": "\U0001F600 " * 128,
        "'drück ' cut at 256": ("drück " * 43)[:256],
        "'cnt ' x 64": "cnt " * 64,
    }


def ref6_shapes(ref6):
    """Repeated-token shapes against REF6's two tokens (char, meas) and its digit runs."""
    return {
        "'c ' x 128": "c " * 128,
        "'m ' x 128": "m " * 128,
        "'0 ' x 128": "0 " * 128,
        "'1 ' x 128": "1 " * 128,
        "'char ' cut at 256": ("char " * 52)[:256],
        "'chax ' cut at 256 (fuzzy, 1 edit each)": ("chax " * 52)[:256],
        "'mesa ' cut at 256": ("mesa " * 52)[:256],
        "'c ' x 125 + 'chax'": "c " * 125 + "chax",
        "'0 ' x 125 + 'chax'": "0 " * 125 + "chax",
        "'1a' x 128": "1a" * 128,
        "REF6 names joined by ','": ",".join(ref6[:40])[:256],
        "'a b c ... z ' cut at 256": (ABC * 5)[:256],
        "'e ' x 128": "e " * 128,
        "'a' x 256": "a" * 256,
    }


def ref_adversarial(idx, sw_a):
    """Search REF for a 3-5 letter typo with an empty prefix range and the largest
    fuzzy candidate set, then repeat it to the cap (the shape whose candidates never
    drop to 300, so every walk runs and every candidate is scored)."""
    utok, post, poff = idx.utok, idx.post, idx.poff
    cnt = [(poff[t + 1] - poff[t], utok[t]) for t in range(len(utok)) if 3 <= len(utok[t]) <= 6 and utok[t].isalpha()]
    cnt.sort(reverse=True)
    best = []
    for _, tok in cnt[:300]:
        for v in (tok[1] + tok[0] + tok[2:], tok[:-1] + ("q" if tok[-1] != "q" else "z"), tok[0] + "x" + tok[1:]):
            v = v[:5]
            if len(v) < 3:
                continue
            lo, hi = prefix_range(utok, v)
            if lo < hi:
                continue
            d = fuzzy_walk(utok, idx.nodes, v, allowed(v))
            have = set()
            for t in d:
                have.update(post[poff[t]:poff[t + 1]])
            best.append((len(have), v))
    best.sort(reverse=True)
    out = {}
    for n, v in best[:2]:
        out[f"'{v} ' cut at 256 (typo, {n} fuzzy names)"] = ((v + " ") * 60)[:256]
        out[f"'e ' x 120 + '{v}'"] = "e " * 120 + v
    lo = [v for n, v in best if n <= CAND_MAX]
    if lo:
        v = lo[0]
        out[f"'{v} ' cut at 256 (typo, <= 300 fuzzy names: the per-candidate check)"] = ((v + " ") * 60)[:256]
    return out


def med(idx, q, limit=20, n=7, budget=60):
    runs, st, out = [], "ok", None
    for _ in range(n):
        dt, st, out = run(lambda: idx.rank(q, limit), budget)
        runs.append(dt)
        if st != "ok":
            break
    return statistics.median(runs), st, out


def perf():
    header()
    sw_a, ref, ref6 = load()
    for label, names, queries in (
        ("REF", ref, None),
        ("REF6", ref6, None),
    ):
        dt, st, idx = run(lambda: R2(names), 120)
        print(f"\n=== {label} ({len(idx.names)} names) built in {dt:.2f} s [{st}]; limit 20, median of 7; load {os.getloadavg()}")
        if label == "REF":
            groups = {"QSET (22)": {q: q for q in QSET22}, "QSET multi-word (3)": {q: q for q in MULTI3},
                      "QSET shapes (E3S-01)": qset_shapes(sw_a, ref), "extra shapes (beyond QSET)": extra_shapes(),
                      "adversarial typo shapes (beyond QSET)": ref_adversarial(idx, sw_a)}
        else:
            groups = {"REF6 query set (12)": {q: q for q in REF6Q}, "QSET shapes over REF6 (beyond the row)": qset_shapes(sw_a, ref),
                      "repeated-token shapes over REF6 (beyond the row)": ref6_shapes(ref6), "extra shapes over REF6": extra_shapes()}
        worst = {}
        exc = spans = disagree0 = 0
        disagree0 = idx.tier_disagree
        for g, qs in groups.items():
            print(f"  -- {g}")
            for lab, q in qs.items():
                m, st, out = med(idx, q)
                exc += st != "ok"
                spans += bad_spans(out)
                s = idx.stats
                worst[g] = max(worst.get(g, (0, "")), (m, lab))
                flag = "  > 200 ms" if m > 0.2 else ""
                print(f"     {m * 1000:8.1f} ms [{st}] n={'-' if out is None else len(out):<3} chars={len(q.strip(WS)):<4} qtok={len(tokens(q.strip(WS))):<4} "
                      f"stats={s} {lab!r}{flag}")
        print(f"  worst per group: " + "; ".join(f"{g}: {m * 1000:.1f} ms ({lab})" for g, (m, lab) in worst.items()))
        print(f"  non-ok calls {exc}; out-of-range/unsorted/touching/empty spans {bad_spans([]) + spans}; tier/_classify disagreements {idx.tier_disagree - disagree0}")
        del idx
        gc.collect()
    print(f"\nload after = {os.getloadavg()}")


def paste():
    """64 KiB pastes reach rank whole (R-TUI-044.2 cut, Textual Input keeps the first line)."""
    header()
    sw_a, ref, ref6 = load()
    rng = random.Random(20261106)
    pool = rng.sample(sw_a, 3000)
    full = ",".join(pool)
    while len(full) > 65536:
        full = full[: full.rfind(",")]
    shapes = {
        f"{full.count(',') + 1} SWA names joined by ','": full,
        "'e ' x 32768": "e " * 32768,
        "'a' x 65536": "a" * 65536,
        "'1a' x 32768": "1a" * 32768,
        "'é' x 65536": "é" * 65536,
        "'a b c ... z ' x 1260": ABC * 1260,
        "'\U0001F600' x 65536": "\U0001F600" * 65536,
        "65,000 spaces + 'VALUE' (stripped 5 chars: ranked)": " " * 65000 + "VALUE",
        "32,000 spaces + 'a' x 300 + 32,000 spaces": " " * 32000 + "a" * 300 + " " * 32000,
        "'a' x 257 (just over)": "a" * 257,
    }
    for order in ("graph order (parse, then the 256 check)", "length check first (CAP_FIRST)"):
        idx = R2(ref, cap_first=order.startswith("length"))
        print(f"\n=== REF prepared; {order}; limit 20; load {os.getloadavg()}")
        for lab, q in shapes.items():
            runs = []
            for _ in range(5):
                dt, st, out = run(lambda: idx.rank(q, 20), 60)
                runs.append(dt)
            gc.collect()
            tracemalloc.start()
            dt2, st2, out2 = run(lambda: idx.rank(q, 20), 60)
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            print(f"     {statistics.median(runs) * 1000:8.2f} ms median of 5 [{st}] peak {peak / 1048576:7.2f} MiB  "
                  f"result={'-' if out is None else len(out)} len={len(q)} {lab!r}")
        del idx
        gc.collect()
    print(f"\nload after = {os.getloadavg()}")


def mem():
    """tracemalloc peak of ONE ranking per shape (index built before tracemalloc.start)."""
    header()
    sw_a, ref, ref6 = load()
    for label, names in (("REF", ref), ("REF6", ref6)):
        idx = R2(names)
        if label == "REF":
            qs = {**{q: q for q in QSET22 + MULTI3}, **qset_shapes(sw_a, ref), **extra_shapes(), **ref_adversarial(idx, sw_a)}
        else:
            qs = {**{q: q for q in REF6Q}, **ref6_shapes(ref6), **extra_shapes()}
        rows = []
        for lab, q in qs.items():
            idx.rank(q, 20)
            gc.collect()
            tracemalloc.start()
            dt, st, out = run(lambda: idx.rank(q, 20), 60)
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            rows.append((peak, lab, st))
        rows.sort(reverse=True)
        print(f"\n=== {label}: {len(rows)} shapes; tracemalloc peak of one ranking, top 8")
        for peak, lab, st in rows[:8]:
            print(f"     {peak / 1048576:8.2f} MiB [{st}] {lab!r}")
        del idx
        gc.collect()
    print(f"\nload after = {os.getloadavg()}")


HOSTILE = [
    "A[/x]B", "[@click=app.quit]OFF[/]", "Map[b]x", "esc\x1b[2Jname", "nul\x00name", "bell\x07x", "cr\rx",
    "éte_Val", "İstanbul_MAP", "straße_X", "ﬁle_X", "repl�_X", "lone\ud800sur_X",
    "max\U0010ffff_X", "漢字_Val", "rtl‮X_VAL", "zw​X", "٣٣٣_X", "tab\tname",
    "quoted name with spaces", "VALUE_0001", "value_0001", "Value_0001", "x" * 300, "_" * 50 + "a",
    "aB" * 100, "A" * 40 + "b", "9" * 64, "x" * 1024, "y" * 1025, "DiscountCount", "abcdefg_count",
]


def check():
    """The corrected rows on their own cases, the oracle, the lazy == all-maps equality,
    and the substring case-exact ambiguity."""
    header()
    c08 = (HERE / "case08-names.txt").read_text(encoding="utf-8").split("\n")
    c08 = [n for n in c08 if n]
    NA = ["Drück_Max", "DRÜCK_MAX", "druck_max"]
    TW, TW2 = ["RPM", "rpm", "Rpm"], ["Rpm", "rpm", "RPM"]
    cases = [
        ("R-A2L-MATCH.38/1", c08, "VALUE_0001_" * 23 + "VAL", 20, [("VALUE_0001", "token", 0, [(0, 5), (6, 10)])]),
        ("R-A2L-MATCH.38/2", c08, "VALUE_0001_" * 23 + "VALU", 20, []),
        ("R-A2L-MATCH.4/1 = .24/3", NA, "drück", 20, [("Drück_Max", "prefix", 0, [(0, 5)]), ("DRÜCK_MAX", "fuzzy", 1, [(0, 5)]), ("druck_max", "fuzzy", 1, [(0, 5)])]),
        ("R-A2L-MATCH.4/2", NA, "DRÜCK", 20, [("DRÜCK_MAX", "prefix", 0, [(0, 5)]), ("Drück_Max", "fuzzy", 1, [(0, 5)]), ("druck_max", "fuzzy", 1, [(0, 5)])]),
        ("R-A2L-MATCH.3/3 = .24/1", TW, "rpm", 20, [("rpm", "exact", 0, [(0, 3)]), ("RPM", "exact", 0, [(0, 3)]), ("Rpm", "exact", 0, [(0, 3)])]),
        ("R-A2L-MATCH.24/2", TW, "RPM", 20, [("RPM", "exact", 0, [(0, 3)]), ("Rpm", "exact", 0, [(0, 3)]), ("rpm", "exact", 0, [(0, 3)])]),
        ("R-A2L-MATCH.25/3", TW2, "rpm", 20, [("rpm", "exact", 0, [(0, 3)]), ("RPM", "exact", 0, [(0, 3)]), ("Rpm", "exact", 0, [(0, 3)])]),
        ("R-A2L-MATCH.23/2", ["rpm_x", "RPMX"], "rpm", 20, [("RPMX", "prefix", 0, [(0, 3)]), ("rpm_x", "prefix", 0, [(0, 3)])]),
        ("R-A2L-MATCH.39/1", ["x" * 1024], "x", 20, [("x" * 1024, "prefix", 0, [(0, 1)])]),
        ("R-A2L-MATCH.39/2", ["x" * 1025], "x", 20, []),
        ("R-A2L-MATCH.1/4", c08, "\x1cVALUE_0001", 20, [("VALUE_0001", "token", 0, [(0, 5), (6, 10)])]),
        ("R-A2L-MATCH.12/4", ["٣٣٣_X"], "٣٣٤", 20, [("٣٣٣_X", "fuzzy", 1, [(0, 3)])]),
        ("R-A2L-MATCH.13/4", c08, "crxuve", 20, []),
    ]
    print("\n=== the corrected rows' cases (expected values from 02-test-cases.md at 15129b64)")
    for cid, names, q, lim, exp in cases:
        got = R2(names).rank(q, lim)
        print(f"  {cid:24s} {'PASS' if got == exp else 'FAIL'}  query len {len(q)}  got {ascii(got)[:160]}")
    print("\n=== substring case-exactness: CTX definition (raw `in`) vs graph step 6 (raw occurrence at a boundary offset)")
    pair = ["abcdefg_count", "DiscountCount"]
    for sub in ("any", "boundary"):
        print(f"  sub={sub:8s} rank('count', {pair}) -> {[r[0] for r in R2(pair, sub=sub).rank('count', 5)]}")
    print("\n=== lazy fuzzy tier == all-maps fuzzy tier (same lists) and R2 == oracle (naive_r2)")
    sw_a, ref, ref6 = load()
    rng = random.Random(20261110)
    sample = rng.sample(ref, 1500)
    queries = QSET22 + MULTI3 + list(qset_shapes(sw_a, ref).values()) + list(extra_shapes().values())
    for _ in range(150):
        nm = rng.choice(sample)
        a = rng.randrange(len(nm))
        queries.append(nm[a:a + rng.randint(1, 12)])
    lazy, allm = R2(sample), R2(sample, fz="all")
    mism_lazy = mism_oracle = differs_sub = n = 0
    for q in queries:
        for lim in (1, 20):
            a = lazy.rank(q, lim)
            if a != allm.rank(q, lim):
                mism_lazy += 1
            n += 1
    t0 = time.perf_counter()
    for q in queries[:200]:
        if lazy.rank(q, 20) != naive_r2(q, sample, 20):
            mism_oracle += 1
    print(f"  REF sample 1,500 names: {n} rankings lazy != all-maps {mism_lazy}; {min(200, len(queries))} rankings R2 != oracle {mism_oracle} ({time.perf_counter() - t0:.0f} s)")
    big_lazy, big_all = R2(ref), R2(ref, fz="all")
    bq = list(qset_shapes(sw_a, ref).values()) + MULTI3 + list(extra_shapes().values()) + list(ref_adversarial(big_lazy, sw_a).values())
    m2 = sum(big_lazy.rank(q, 20) != big_all.rank(q, 20) for q in bq)
    print(f"  REF (50,000): {len(bq)} shape rankings lazy != all-maps {m2}; tier/_classify disagreements {big_lazy.tier_disagree}")
    b6 = R2(ref6)
    b6a = R2(ref6, fz="all")
    b6q = REF6Q + list(ref6_shapes(ref6).values())
    m3 = sum(b6.rank(q, 20) != b6a.rank(q, 20) for q in b6q)
    s6 = random.Random(7).sample(ref6, 2000)
    m4 = sum(R2(s6).rank(q, 20) != naive_r2(q, s6, 20) for q in REF6Q)
    print(f"  REF6 (50,000): {len(b6q)} rankings lazy != all-maps {m3}; tier disagreements {b6.tier_disagree}; REF6 sample 2,000 x 12 queries R2 != oracle {m4}")
    for nm, names, qs in (("REF sample", sample, queries[:200]), ("REF6 queries", s6, REF6Q)):
        ia, ib = R2(names, sub="any"), R2(names, sub="boundary")
        d = sum(ia.rank(q, 20) != ib.rank(q, 20) for q in qs)
        print(f"  {nm}: rankings where sub=any != sub=boundary: {d} of {len(qs)}")


def spans():
    header()
    rng = random.Random(4242)
    idx = R2(HOSTILE)
    alphabet = "".join(sorted(set("".join(HOSTILE)))) + " _.[]"
    queries = list(alphabet) + ["\ud800", "\U0010ffff", "é", "İ", "\x1b[2J", "[/x]", "[b]", "  \x1c VALUE", "\x00",
                                "x" * 256, "x" * 257, "y" * 256, "İ" * 256, "1a" * 128]
    for _ in range(3000):
        nm = rng.choice(HOSTILE)
        a = rng.randrange(len(nm))
        q = nm[a:a + rng.randint(1, 8)]
        if rng.random() < 0.3:
            q = q.upper() if rng.random() < 0.5 else q.lower()
        if rng.random() < 0.2:
            q = q + " " + rng.choice(alphabet)
        queries.append(q)
    exc = bad = mism = listed = 0
    first = []
    for q in queries:
        for lim in (1, 5, 100):
            try:
                got = idx.rank(q, lim)
            except Exception as e:  # noqa: BLE001
                exc += 1
                first.append(("exception", q, repr(e)))
                continue
            listed += len(got)
            if got != naive_r2(q, HOSTILE, lim):
                mism += 1
                first.append(("mismatch", q[:40], lim))
            b = bad_spans(got)
            bad += b
    print(f"hostile names {len(HOSTILE)} (indexed {len(idx.names)}: the 1,025-character name left out); queries {len(queries)} x 3 limits; "
          f"listed entries {listed}; exceptions {exc}; bad spans {bad}; R2 != oracle {mism}; tier disagreements {idx.tier_disagree}")
    for row in first[:5]:
        print("  ", ascii(row))


def det():
    sw_a, ref, ref6 = load()
    rng = random.Random(20261107)
    gen = []
    for _ in range(300):
        nm = rng.choice(ref)
        a = rng.randrange(len(nm))
        gen.append(nm[a:a + rng.randint(1, 10)])
    h = hashlib.sha256()
    n = 0
    t0 = time.perf_counter()
    for names, qs in ((ref, QSET22 + MULTI3 + list(qset_shapes(sw_a, ref).values()) + list(extra_shapes().values()) + gen),
                      (ref6, REF6Q + list(ref6_shapes(ref6).values())),
                      (HOSTILE, list("abex_[0́") + ["x" * 256, "1a" * 128])):
        ix = R2(list(names))
        for q in qs:
            for lim in (1, 20, 100):
                h.update(repr(ix.rank(q, lim)).encode("utf-8", "surrogatepass"))
                n += 1
    print(f"PYTHONHASHSEED={os.environ.get('PYTHONHASHSEED')} hash('abc')={hash('abc')} rankings={n} sha256={h.hexdigest()} ({time.perf_counter() - t0:.0f} s)")


class R2D(R2):
    """R2 with identical query tokens de-duplicated for the token and fuzzy tiers
    (a repeated query token adds the same condition; its edits count once per
    occurrence in the key). Must give R2's lists (asserted in mode dedupe)."""
    def _fuzzy(self, qtoks, taken):
        cnt = {}
        for qt in qtoks:
            cnt[qt] = cnt.get(qt, 0) + 1
        uq = list(cnt)
        out = R2._fuzzy(self, uq, taken) if len(uq) == len(qtoks) else None
        if out is not None:
            return out
        # weighted: score per distinct token, multiply by its count
        utok, post, poff, ntid, noff, nodes = self.utok, self.post, self.poff, self.ntid, self.noff, self.nodes
        info = [(qt, allowed(qt), cnt[qt]) for qt in uq]
        order = sorted(range(len(info)), key=lambda j: info[j][1])
        dists = [None] * len(info)
        cand = None
        walks = 0
        for j in order:
            if cand is not None and len(cand) <= CAND_MAX:
                break
            qt, k, _ = info[j]
            if k == 0:
                lo, hi = prefix_range(utok, qt)
                d = dict.fromkeys(range(lo, hi), 0)
            else:
                d = fuzzy_walk(utok, nodes, qt, k)
            walks += 1
            if not d:
                return {}
            dists[j] = d
            have = set()
            for t in d:
                have.update(post[poff[t]:poff[t + 1]])
            cand = (have - taken) if cand is None else (cand & have)
            if not cand:
                return {}
        self.stats.update(walks=walks, cand=len(cand))
        memo = [dict() for _ in info]
        res = {}
        for i in cand:
            ids = ntid[noff[i]:noff[i + 1]]
            total = 0
            for j, (qt, k, c) in enumerate(info):
                d = dists[j]
                bst = None
                for t in ids:
                    if d is not None:
                        v = d.get(t)
                    else:
                        v = memo[j].get(t)
                        if v is None:
                            v = memo[j][t] = osa_cap(qt, utok[t], k)
                        if v > k:
                            v = None
                    if v is not None and (bst is None or v < bst):
                        bst = v
                if bst is None:
                    break
                total += bst * c
            else:
                res[i] = total
        return res

    dedup_tok = True  # the token tier intersects each distinct query token range once (same set)


def _dedupe_ranges_patch():
    pass


def typos_of(tok, idx):
    out = []
    for p in range(len(tok)):
        for c in "abcdefghijklmnopqrstuvwxyz":
            if c != tok[p]:
                v = tok[:p] + c + tok[p + 1:]
                lo, hi = prefix_range(idx.utok, v)
                if lo == hi:
                    out.append(v)
    return out


def dedupe():
    header()
    sw_a, ref, ref6 = load()
    for label, names in (("REF6", ref6), ("REF", ref)):
        a, b = R2(names), R2D(names)
        print(f"\n=== {label}; limit 20, median of 7; R2 (graph) vs R2D (identical query tokens de-duplicated in the fuzzy tier); load {os.getloadavg()}")
        if label == "REF6":
            ty = typos_of("char", a)
            ty2 = typos_of("meas", a)
            shapes = {
                "'0 ' x 128": "0 " * 128, "'chax ' cut at 256": ("chax " * 52)[:256], "'c ' x 125 + 'chax'": "c " * 125 + "chax",
                "'0 ' x 125 + 'chax'": "0 " * 125 + "chax",
            }
            for n in (4, 8, 16, 32, 51):
                shapes[f"{n} DISTINCT 1-edit typos of 'char'"] = " ".join(ty[:n])[:256]
            shapes["51 distinct typos of 'char' and 'meas' alternating"] = " ".join(x for pair in zip(ty, ty2) for x in pair)[:256]
        else:
            shapes = {"'1a' x 128": "1a" * 128, "'cnt ' x 64": "cnt " * 64, "'rat ' cut at 256": ("rat " * 64)[:256],
                      "'e ' x 120 + 'rat'": "e " * 120 + "rat"}
            ty = [v for v in typos_of("rat", a)]
            for n in (8, 16, 32, 64):
                shapes[f"{n} DISTINCT 1-edit typos of 'rat'"] = " ".join(ty[:n])[:256]
        for lab, q in shapes.items():
            ra = a.rank(q, 20)
            rb = b.rank(q, 20)
            ma, sa, _ = med(a, q)
            sta = dict(a.stats)
            mb, sb, _ = med(b, q)
            stb = dict(b.stats)
            print(f"   graph {ma * 1000:8.1f} ms | dedupe {mb * 1000:8.1f} ms | same list {ra == rb} | qtok {len(tokens(q))} distinct {len(set(fold(q[s:e]) for s, e in tokens(q)))} "
                  f"| walks {sta.get('walks')}->{stb.get('walks')} cand {sta.get('cand')} tokint {sta.get('token_intersections')} | {lab!r}")
        del a, b
        gc.collect()
    print(f"\nload after = {os.getloadavg()}")


if __name__ == "__main__":
    {"perf": perf, "paste": paste, "mem": mem, "check": check, "spans": spans, "det": det, "dedupe": dedupe}[sys.argv[1]]()
