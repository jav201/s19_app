#!/usr/bin/env python3
"""batch-103 Inc 4 E1 pilot: are the proposed matcher rules unambiguous and fast enough?

THROWAWAY EVIDENCE, NOT PRODUCT CODE. Run on cachyos-rtx only (it imports
s19_app to read A2L names with the app's own parser).

It holds two implementations of the E1 proposal (01-requirements.md,
R-A2L-MATCH.*, definitions in CTX-A2L-MATCH):
  * naive_rank -- the rules written as directly as possible (the oracle);
  * Index.rank -- a pre-built index over the names (the timing candidate).
It checks that both give the same ranked lists (rule, key, spans) on generated
queries, times the index on the 50,000-name reference list, and prints the
ranked lists of the curated examples used in 02-test-cases.md.
"""
from __future__ import annotations

import bisect
import os
import random
import statistics
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(os.environ.get("REPO", str(Path.home() / "work" / "s19_app")))
OUT = Path(os.environ.get("OUT", "/tmp/b103-e1-4/out"))

import s19_app  # noqa: E402
from s19_app.tui.a2l import parse_a2l_file  # noqa: E402

RULES = ("exact", "prefix", "substring", "token", "subsequence", "fuzzy")
WS = " \t\n\r\x0b\x0c"
_FOLD = {c: c + 32 for c in range(65, 91)}


def fold(s: str) -> str:
    return s.translate(_FOLD)


def _up(c):
    return "A" <= c <= "Z"


def _lo(c):
    return "a" <= c <= "z"


def _dig(c):
    return "0" <= c <= "9"


def _let(c):
    return _up(c) or _lo(c) or ord(c) > 127


def _sep(c):
    return not (_let(c) or _dig(c))


def tokens(s: str) -> list:
    """(start, end) spans of the tokens of s (case boundaries read on s itself)."""
    spans = []
    n = len(s)
    i = 0
    while i < n:
        c = s[i]
        if _sep(c):
            i += 1
            continue
        start = i
        if _dig(c):
            while i < n and _dig(s[i]):
                i += 1
            spans.append((start, i))
            continue
        i += 1
        while i < n and _let(s[i]):
            p, cur = s[i - 1], s[i]
            if _lo(p) and _up(cur):
                break
            if _up(p) and _up(cur) and i + 1 < n and _lo(s[i + 1]):
                break
            i += 1
        spans.append((start, i))
    return spans


def allowed(tok: str) -> int:
    if all(_dig(c) for c in tok):
        return 0
    if len(tok) < 3:
        return 0
    if len(tok) <= 5:
        return 1
    return 2


def osa_prefix(q: str, t: str) -> int:
    """Smallest OSA distance between q and any prefix of t (empty included)."""
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
        prev2, prev = prev, cur
    return min(prev)


def is_subseq(keys: str, s: str) -> list | None:
    """Leftmost positions of keys in s, in order, or None."""
    pos = []
    j = 0
    for k in keys:
        j = s.find(k, j)
        if j < 0:
            return None
        pos.append(j)
        j += 1
    return pos


def merge(spans: list) -> list:
    out = []
    for s, e in sorted(spans):
        if out and s <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], e))
        else:
            out.append((s, e))
    return out


def query_parts(query: str, folded: bool):
    q = query.strip(WS)
    qq = fold(q) if folded else q
    toks = [qq[s:e] for s, e in tokens(q)]
    keys = "".join(c for c in qq if not _sep(c))
    return q, qq, toks, keys


def evaluate(query: str, name: str, folded: bool = True):
    """(rule_index, rule_key, spans) of the highest rule that holds, or None."""
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
    pos = is_subseq(keys, nn)
    if pos is not None:
        return (4, 0, merge([(p, p + 1) for p in pos]))
    if qtoks and ntok:
        total = 0
        spans = []
        for qt in qtoks:
            best = None
            for t, s, e in ntok:
                d = osa_prefix(qt, t)
                if best is None or d < best[0]:
                    best = (d, s, e)
            if best[0] > allowed(qt):
                return None
            total += best[0]
            spans.append((best[1], best[2]))
        return (5, total, merge(spans))
    return None


def naive_rank(query: str, names, limit: int) -> list:
    if limit < 1:
        return []
    rows = []
    for name in dict.fromkeys(names):
        ev = evaluate(query, name)
        if ev is None:
            continue
        ce = evaluate(query, name, folded=False)
        case_exact = ce is not None and ce[0] == ev[0]
        rows.append(((ev[0], ev[1], len(name), 0 if case_exact else 1, name), ev))
    rows.sort(key=lambda r: r[0])
    return [(r[0][4], RULES[r[1][0]], r[1][1], r[1][2]) for r in rows[:limit]]


def _bit(c: str) -> int:
    if "a" <= c <= "z":
        return 1 << (ord(c) - 97)
    if "0" <= c <= "9":
        return 1 << (26 + ord(c) - 48)
    return 1 << (36 + ord(c) % 27)  # collisions only weaken the prefilter


def _mask(s: str) -> int:
    m = 0
    for c in s:
        m |= _bit(c)
    return m


class Index:
    """Pre-built snapshot of a name list (the timing candidate)."""

    def __init__(self, names):
        self.names = list(dict.fromkeys(names))
        self.folded = [fold(n) for n in self.names]
        self.nmask = [_mask(nf) for nf in self.folded]
        self.ntok = []
        inv: dict = {}
        for i, (n, nf) in enumerate(zip(self.names, self.folded)):
            toks = [(nf[s:e], s, e) for s, e in tokens(n)]
            self.ntok.append(toks)
            for t, _, _ in toks:
                inv.setdefault(t, set()).add(i)
        self.inv = inv
        self.utok = sorted(inv)
        self.bylen: dict = {}
        self.cum: dict = {}
        for t in self.utok:
            self.bylen.setdefault(len(t), []).append(t)
            acc = [0]
            m = 0
            for c in t:
                m |= _bit(c)
                acc.append(m)
            self.cum[t] = acc
        self.maxlen = max(self.bylen) if self.bylen else 0

    def _prefix_tokens(self, qt):
        lo = bisect.bisect_left(self.utok, qt)
        out = []
        for t in self.utok[lo:]:
            if not t.startswith(qt):
                break
            out.append(t)
        return out

    def rank(self, query: str, limit: int) -> list:
        if limit < 1:
            return []
        q, qf, qtoks, keys = query_parts(query, True)
        if not keys:
            return []
        groups: dict = {}  # (rule, key, len) -> [ids]
        taken = set()
        found = 0

        def add(i, rule, key):
            nonlocal found
            groups.setdefault((rule, key, len(self.names[i])), []).append(i)
            taken.add(i)
            found += 1

        # tiers 0-2 (C-level `in`)
        for i, nf in enumerate(self.folded):
            if qf in nf:
                if nf == qf:
                    add(i, 0, 0)
                elif nf.startswith(qf):
                    add(i, 1, 0)
                else:
                    add(i, 2, -1)  # key resolved below
        # resolve substring keys
        g2 = groups.pop
        subs = [k for k in groups if k[0] == 2]
        for k in subs:
            for i in g2(k):
                ev = evaluate(query, self.names[i])
                groups.setdefault((2, ev[1], len(self.names[i])), []).append(i)
        # tier 3 token
        if found < limit and qtoks:
            cand = None
            for qt in qtoks:
                ids = set()
                for t in self._prefix_tokens(qt):
                    ids |= self.inv[t]
                cand = ids if cand is None else cand & ids
                if not cand:
                    break
            for i in sorted(cand or ()):
                if i not in taken:
                    add(i, 3, 0)
        # tier 4 subsequence
        if found < limit:
            kmask = _mask(keys)
            nmask = self.nmask
            for i, nf in enumerate(self.folded):
                if kmask & ~nmask[i] or i in taken:
                    continue
                if is_subseq(keys, nf) is not None:
                    add(i, 4, 0)
        # tier 5 fuzzy
        if found < limit and qtoks:
            per = []
            for qt in qtoks:
                k = allowed(qt)
                dist = {}
                if k == 0:
                    for t in self._prefix_tokens(qt):
                        dist[t] = 0
                else:
                    qmask = _mask(qt)
                    m = len(qt)
                    cut = m + k
                    cum = self.cum
                    for L in range(max(1, m - k), self.maxlen + 1):
                        j = L if L < cut else cut
                        for t in self.bylen.get(L, ()):
                            if (qmask & ~cum[t][j]).bit_count() > k:
                                continue
                            d = osa_prefix(qt, t[:cut])
                            if d <= k:
                                dist[t] = d
                per.append(dist)
            best: dict = {}
            for qi, dist in enumerate(per):
                for t, d in dist.items():
                    for i in self.inv[t]:
                        if i in taken:
                            continue
                        row = best.setdefault(i, [None] * len(per))
                        if row[qi] is None or d < row[qi]:
                            row[qi] = d
            for i, row in best.items():
                if all(v is not None for v in row):
                    add(i, 5, sum(row))
        # order: groups by (rule, key, len); case-exact then name inside a group
        out = []
        for gk in sorted(groups):
            members = groups[gk]
            keyed = []
            for i in members:
                ce = evaluate(query, self.names[i], folded=False)
                keyed.append((0 if ce is not None and ce[0] == gk[0] else 1, self.names[i], i))
            keyed.sort()
            for _, name, i in keyed:
                ev = evaluate(query, name)
                out.append((name, RULES[ev[0]], ev[1], ev[2]))
                if len(out) >= limit:
                    return out
        return out


def names_of(path: Path) -> list:
    return [str(t["name"]) for t in parse_a2l_file(path)["tags"] if t.get("name") is not None]


def show(title, rows):
    print(f"  {title}")
    if not rows:
        print("    (empty)")
    for name, rule, key, spans in rows:
        print(f"    {name!r:60s} {rule:11s} key={key} spans={spans}")


def main() -> int:
    print(f"s19_app.__file__ = {s19_app.__file__}")
    print(f"python = {sys.version.split()[0]}")
    print(f"repo HEAD = {subprocess.run(['git', '-C', str(REPO), 'rev-parse', '--short', 'HEAD'], capture_output=True, text=True).stdout.strip()}")
    print(f"host = {os.uname().nodename}  load = {os.getloadavg()}  cpus = {os.cpu_count()}")
    print(f"HOME = {os.environ.get('HOME')}  LOCALAPPDATA = {os.environ.get('LOCALAPPDATA')}")
    print()

    case08 = names_of(OUT / "firmware.a2l")
    issues = names_of(OUT / "firmware_issues.a2l")
    sw_a = names_of(REPO / "examples/case_00_public/software_a.a2l")
    sw_b = names_of(REPO / "examples/case_00_public/software_b.a2l")
    bal = names_of(REPO / "examples/case_00_public/BalanceTube_STMicro.a2l")
    src = names_of(REPO / "examples/case_00_public/from_source.a2l")
    print(f"names: case08 {len(case08)}  case08_issues {len(issues)}  software_a {len(sw_a)}  software_b {len(sw_b)}  BalanceTube {len(bal)}  from_source {len(src)}")

    # --- 1. curated examples (02-test-cases.md) ---------------------------
    print("\n=== 1. curated examples")
    examples = [
        ("case08", case08, "VALUE_0001", 20),
        ("case08_issues", issues, "VALUE_0001", 20),
        ("case08", case08, "  VALUE_0001  ", 20),
        ("case08", case08, "value_000", 5),
        ("case08", case08, "value_000", 20),
        ("case08", case08, "0001", 20),
        ("case08", case08, "blk val 00", 3),
        ("case08", case08, "vblk", 2),
        ("case08", case08, "maesurement_0001", 20),
        ("case08", case08, "maesurement", 3),
        ("case08", case08, "cuvre", 3),
        ("case08", case08, "VALUE_0300", 20),
        ("case08", case08, "measurementss_0001", 20),
        ("case08", case08, "VALUE", 0),
        ("case08", case08, "VALUE", -1),
        ("case08", case08, "", 20),
        ("case08", case08, "   ", 20),
        ("case08", case08, "_", 20),
        ("case08", case08, "._[]", 20),
        ("case08_issues", issues, "out range", 20),
        ("case08_issues", issues, "span", 20),
        ("case08_issues", issues, "LIMIT", 20),
        ("case08", case08, "map 2", 20),
        ("case08", case08, "valu_0001", 20),
        ("case08", case08, "vlaue_0001", 20),
        ("case08", case08, "vale_0001", 20),
        ("case08", case08, "ma", 3),
        ("case08", case08, "mp", 3),
        ("case08", case08, "xmap", 3),
        ("case08", case08, "mpa", 3),
        ("case08", case08, "maq", 3),
        ("case08", case08, "ascii 1", 20),
        ("case08", case08, "Value_0001", 20),
        ("cases", ["RPM", "rpm", "Rpm"], "rpm", 20),
        ("cases", ["RPM", "rpm", "Rpm"], "RPM", 20),
        ("cases", ["Rpm_Max", "rpm_max_x", "RPM_MAX"], "rpm_max", 20),
        ("nonascii", ["Drück_Max", "DRÜCK_MAX", "druck_max"], "drück", 20),
        ("nonascii", ["Drück_Max", "DRÜCK_MAX", "druck_max"], "DRÜCK", 20),
        ("BalanceTube", bal, "stop watch", 20),
        ("BalanceTube", bal, "watch time", 20),
        ("BalanceTube", bal, "gamecontroller.timer", 20),
        ("BalanceTube", bal, "ledRing[1]", 4),
        ("BalanceTube", bal, "counter", 4),
        ("BalanceTube", bal, "ounter", 4),
        ("from_source", src, "knife[1]", 20),
        ("from_source", src, "knife 1 x", 20),
        ("from_source", src, "knife.*", 4),
        ("from_source", src, "[0].Spoon", 20),
        ("from_source", src, "instance[0", 3),
        ("software_b", sw_b, "oks ahw", 20),
        ("software_b", sw_b, "sahw", 20),
        ("software_b", sw_b, "JXML_UPQ", 20),
    ]
    for label, names, q, lim in examples:
        a = naive_rank(q, names, lim)
        b = Index(names).rank(q, lim)
        show(f"[{label}] query={q!r} limit={lim}  naive==index: {a == b}", a)

    # tokenisation samples (definition check)
    print("\n=== 2. token samples (definition CTX-A2L-MATCH 'token')")
    for s in [
        "ABSValue", "AValue", "engineSpeed", "eNGINE", "Map3D", "x2y", "VAL_BLK_0001",
        "AehduMbpv__Miotc1.BvhVofqLubhoanQopechsNbeu", "Aabcx_GgrDwx_kaudIvm_ydmuH_uoz3._5_",
        "model.MainClass.ledController.ledRing[0].red", "parameter_instance[0].Knife[1].x",
        "LukPvq.JXML_UPQ_BI.OKSAhwvcueaniy", "Drück_Max", "aÄB", "aBÄ", "ASAM.M.SCALAR.UWORD.IDENTICAL.BITMASK_0FF0",
    ]:
        print(f"  {s!r:55s} -> {[s[a:b] for a, b in tokens(s)]}")

    print("\n=== 3. OSA prefix-distance samples")
    for q, t in [("cuvre", "curve"), ("maesurement", "measurement"), ("valuee", "value"), ("value", "val"),
                 ("vale", "value"), ("valu", "value"), ("vlaue", "value"), ("ca", "abc"), ("measurementss", "measurement"),
                 ("0300", "0208"), ("drück", "drÜck"), ("drück", "druck"), ("ab", "ba"), ("abc", "")]:
        print(f"  d({q!r}, {t!r}) = {osa_prefix(q, t)}   allowed({q!r}) = {allowed(q)}")

    # --- 4. naive vs index agreement on generated queries -------------------
    print("\n=== 4. naive vs index agreement")
    rng = random.Random(20261106)
    pool = sorted(set(rng.sample(sw_a, 600) + rng.sample(bal, 60) + rng.sample(src, 40) + rng.sample(sw_b, 40) + case08[:200] + ["RPM", "rpm", "Drück_Max", "DRÜCK_MAX"]))
    idx = Index(pool)

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

    queries = [mutate(rng.choice(pool)) for _ in range(400)] + ["", "_", "zzzzqqq", "q", "AB", "1"]
    bad = 0
    rule_hist = {}
    for q in queries:
        full = naive_rank(q, pool, 100000)
        for row in full:
            rule_hist[row[1]] = rule_hist.get(row[1], 0) + 1
        for lim in (5, 50, 100000):
            a = full[:lim]
            b = idx.rank(q, lim)
            if a != b:
                bad += 1
                if bad <= 5:
                    print(f"  MISMATCH query={q!r} limit={lim}\n    naive={a[:4]}\n    index={b[:4]}")
    print(f"  pool {len(pool)} names, {len(queries)} queries x 3 limits: mismatches = {bad}")
    print(f"  rules hit over all queries (limit all): {rule_hist}")

    # --- 5. timing on the 50,000-name reference list ------------------------
    print("\n=== 5. timing")
    ref = (sw_a + [n + "_1" for n in sw_a] + [n + "_2" for n in sw_a] + [n + "_3" for n in sw_a])[:50000]
    print(f"  reference list: software_a names, then each with _1, _2, _3 appended; first {len(ref)}; unique {len(set(ref))}")
    builds = []
    for _ in range(3):
        t0 = time.perf_counter()
        big = Index(ref)
        builds.append(time.perf_counter() - t0)
    print(f"  index build: {[round(b, 3) for b in builds]} s  median {statistics.median(builds):.3f} s; unique tokens {len(big.utok)}")
    t0 = time.perf_counter()
    for n in ref:
        tokens(n)
    print(f"  tokenising the 50,000 names once: {time.perf_counter() - t0:.3f} s")
    sample = sw_a[1234]
    stoks = [sample[a:b] for a, b in tokens(sample)]
    tq = [
        "a", "zz", sample, sample[:12], sample[10:18], " ".join(stoks[-1:] + stoks[:1]).lower(),
        "".join(t[0] for t in stoks[:4]), "xqzjvkw", "qqqq zzzz", "Nzukij", "Ierxjr_Eud", "ledRing",
        "ab", "pposbxiif", "cnt", "temp_sensor_max",
    ]
    print(f"  sample name software_a[1234] = {sample!r}")
    for lim in (20, len(ref)):
        worst = 0.0
        for q in tq:
            runs = []
            for _ in range(7):
                t0 = time.perf_counter()
                res = big.rank(q, lim)
                runs.append(time.perf_counter() - t0)
            med = statistics.median(runs) * 1000
            worst = max(worst, med)
            hist = {}
            for row in res:
                hist[row[1]] = hist.get(row[1], 0) + 1
            print(f"  limit={lim:6d} query={q!r:48s} median {med:8.1f} ms  max {max(runs) * 1000:8.1f} ms  results {len(res):6d} {hist}")
        print(f"  limit={lim}: worst median over the query set = {worst:.1f} ms")
    # naive single call for scale
    t0 = time.perf_counter()
    naive_rank("xqzjvkw", ref, 20)
    print(f"  naive_rank (no index) on the 50,000 names, query 'xqzjvkw': {time.perf_counter() - t0:.2f} s")
    print(f"\nload at end = {os.getloadavg()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
