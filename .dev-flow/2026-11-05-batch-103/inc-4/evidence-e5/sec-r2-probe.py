#!/usr/bin/env python3
"""batch-103 Inc 4 E5 security probe, ROUND 2. THROWAWAY EVIDENCE, NOT PRODUCT CODE.

Runs on <runner> only, against the REAL corrected module s19_app/tui/services/label_match.py
(sha256 394bf2f9...) of a read-only COPY of the integrated tree (env TREE, first on PYTHONPATH).
It loads the round-1 probe (sec-e5-probe.py, same directory) for its fixtures, the E1 oracle
(evaluate_b, uncapped OSA, from the E3 pilot copy in PILOT_DIR), the instrumentation and the
address-space cap / per-case alarm. CRAFT and BAND are built by the test module's own builders.

Switch paths: rank() reads lm._FUZZY_SWITCH_CAP at call time, so the probe can force the map path
(cap 0: never switch) or the per-id path right after the first walk (cap 10**9) and compare lists.

Modes: craft, band, switch, dense, fixcheck, subkey, fuzz.
"""
from __future__ import annotations

import cProfile
import hashlib
import importlib.util
import io
import pstats
import random
import statistics
import sys
import time
from collections import Counter, _count_elements
from contextlib import contextmanager
from itertools import chain, repeat
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("sec_e5_probe", HERE / "sec-e5-probe.py")
P = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(P)

lm, T, rank, build_label_index = P.lm, P.T, P.rank, P.build_label_index
WS, LOWER = P.WS, P.LOWER
LET = [c for c in LOWER if c != "q"]  # 25 letters


def header(mode):
    P.header(mode)
    print(f"probe = {Path(__file__).name} sha256 {hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}; "
          f"round-1 helpers = sec-e5-probe.py sha256 {hashlib.sha256((HERE / 'sec-e5-probe.py').read_bytes()).hexdigest()}")
    print(f"_FUZZY_SWITCH_CAP = {lm._FUZZY_SWITCH_CAP}")


@contextmanager
def switch_cap(value):
    old = lm._FUZZY_SWITCH_CAP
    lm._FUZZY_SWITCH_CAP = value
    try:
        yield
    finally:
        lm._FUZZY_SWITCH_CAP = old


def paths_equal(ix, q, limit=20, forced=True, budget=300):
    """tup(rank) at the shipped cap vs cap 0 (map path only) [vs cap 10**9 (per-id right after walk 1)]."""
    base = P.tup(rank(q, ix, limit))
    with switch_cap(0):
        dt0, st0, never = P.run(lambda: P.tup(rank(q, ix, limit)), budget)
    res = {"map-only": (never == base) if st0 == "ok" else st0}
    if forced:
        with switch_cap(10 ** 9):
            dt1, st1, always = P.run(lambda: P.tup(rank(q, ix, limit)), budget)
        res["per-id after walk 1"] = (always == base) if st1 == "ok" else st1
    return res


def tier_calls(ix, q):
    out, calls, _ = P.counted(lambda: rank(q, ix, 20))
    return out, calls.get("_fuzzy_token_distances", 0), calls.get("_prefix_distance", 0), calls.get("_classify", 0)


MAPSIZE = []


@contextmanager
def map_sizes():
    """Record len() of every _fuzzy_token_distances table and its postings count."""
    orig = lm._fuzzy_token_distances
    MAPSIZE.clear()

    def wrap(index, q, allowed):
        r = orig(index, q, allowed)
        ps = index._posting_starts
        MAPSIZE.append((len(r), sum(ps[t + 1] - ps[t] for t in r)))
        return r

    lm._fuzzy_token_distances = wrap
    try:
        yield MAPSIZE
    finally:
        lm._fuzzy_token_distances = orig


def describe(names):
    return f"{len(names):,} names, {sum(map(len, names)):,} characters in all (.40 scope: 50,000 names, <= 2,356,624)"


def show(lab, ix, q, n=7, budget=300, paths=True, forced=True):
    m, st, out = P.med(ix, q, n=n, budget=budget)
    flag = "  > 1.0 s (.40)" if m > 1.0 else ""
    toks = lm._parse_query(q.strip(WS)).tokens
    rules = sorted({r.rule.value for r in out}) if out else "-"
    edits = sorted({r.edits for r in out}) if out else "-"
    print(f"  {m * 1000:9.1f} ms [{st}] median of {n}; chars {len(q.strip(WS)):>3}, tokens {len(toks):>3} (distinct {len(set(toks)):>3}); "
          f"listed {'-' if out is None else len(out)} {rules} edits {edits}; bad spans {P.bad_spans(out)}{flag}  {lab}")
    if st == "ok":
        _, walks, pd, cls = tier_calls(ix, q)
        line = f"      walks {walks}, _prefix_distance {pd:,}, _classify {cls}"
        if paths:
            line += f"; same list on {paths_equal(ix, q, forced=forced, budget=budget)}"
        print(line)
    return m


# ---------------------------------------------------------------- mode craft (R-A2L-MATCH.40/3)
def craft():
    header("r2 craft")
    f = P.fixtures()
    names = T.craft_names() + f["ref"][:49700]
    sha = hashlib.sha256("\n".join(names).encode("utf-8")).hexdigest()
    print(f"CRAFT: {describe(names)}; sha256 {sha[:16]} == test's CRAFT_SHA256: {sha == T.CRAFT_SHA256}")
    dt, st, ix = P.run(lambda: build_label_index(names), 300)
    occ = sum(ix._name_token_starts[i + 1] - ix._name_token_starts[i] for i in range(300))
    print(f"  built in {dt:.2f} s [{st}]; the 300 crafted names hold {occ:,} token occurrences (> 512: the switch never fires); load {P.load()}")
    for n_tok in (4, 8, 16, 32, 51):
        show(f"CRAFT {n_tok}-token query", ix, T.craft_query(n_tok), forced=n_tok <= 16)
    for n_tok in (16, 51):
        pk, dt, st, _ = P.peak_of(lambda: rank(T.craft_query(n_tok), ix, 20), 300)
        print(f"  {n_tok} tokens, one ranking under tracemalloc: peak {pk / 1048576:.2f} MiB ({dt:.2f} s [{st}]) (round 1: 118.3 / 464.0 MiB)")
    pr = cProfile.Profile()
    pr.enable()
    rank(T.craft_query(51), ix, 20)
    pr.disable()
    buf = io.StringIO()
    pstats.Stats(pr, stream=buf).sort_stats("tottime").print_stats(6)
    print("  cProfile (51 tokens), top by own time:")
    for line in buf.getvalue().splitlines():
        if "label_match.py" in line or "ncalls" in line or "{method" in line or "{built-in" in line:
            print("    " + line.replace(str(P.TREE), "<tree>")[:150])
    del ix

    print("\n=== round-1 A1 variants (P.crafted, P.memo_query): 1 / 2 / 300 / 2,000 crafted names + REF padding to 50,000")
    ref_ix = build_label_index(f["ref"])
    for n_crafted, distinct in ((1, True), (2, True), (300, True), (2000, False)):
        head, pairs, cr = P.crafted(ref_ix, n_crafted, 20261113 + n_crafted, distinct)
        lst = cr + f["ref"][: 50000 - n_crafted]
        ix = build_label_index(lst)
        occ = sum(ix._name_token_starts[i + 1] - ix._name_token_starts[i] for i in range(n_crafted))
        print(f"\n  {n_crafted} crafted (junk distinct {distinct}; {occ:,} occurrences; switch {'fires' if occ <= 512 else 'never fires'}); {describe(lst)}")
        for n_tok in (4, 16, 51):
            show(f"{n_crafted} crafted, {n_tok}-token query", ix, P.memo_query(head, pairs, n_tok), n=5,
                 forced=n_crafted <= 300 and n_tok <= 16)
        del ix
    print(f"\nload after = {P.load()}")


# ---------------------------------------------------------------- mode band (R-A2L-MATCH.40/4 and the per-id path's worst)
def band():
    header("r2 band")
    f = P.fixtures()
    bn = T.band_names()
    names = bn + f["ref"][: 50000 - len(bn)]
    print(f"BAND: {describe(names)}")
    ix = build_label_index(names)
    q = T.BAND_HEAD + " " + "a" * 248 + "b"
    show("BAND .40/4 query (head + 249-char token)", ix, q)
    for qq, lab in ((T.BAND_HEAD + " " + "a" * 249, "head + 249 'a' (0 edits)"),
                    (T.BAND_HEAD + " " + "b" * 249, "head + 249 'b' (no match: candidates emptied)"),
                    (T.BAND_HEAD + " " + "a" * 120 + "b " + "a" * 126 + "c", "head + two ~124-char tokens")):
        show(f"BAND {lab}", ix, qq)
    del ix

    print("\n=== SW-MAX: the most distinct long tokens the switch admits (<= 512 occurrences): 102 names = head + 4 tokens of 252 chars")
    print("    (510 occurrences, 408 distinct long tokens; BAND has 225) + REF padding; query head + 249-char token")
    suffix = [a + b + c for a in "cdefghijklmnop" for b in "cdefghijklmnop" for c in "cdefghijklmnop"]
    sw = []
    k = 0
    for i in range(102):
        toks = []
        for _ in range(4):
            toks.append("a" * 249 + suffix[k])
            k += 1
        sw.append(T.BAND_HEAD + "_" + "_".join(toks))
    assert all(len(n) <= 1024 for n in sw) and len(set(sw)) == 102
    names = sw + f["ref"][: 50000 - len(sw)]
    print(f"    {describe(names)}; name length {len(sw[0])}")
    ix = build_label_index(names)
    occ = sum(ix._name_token_starts[i + 1] - ix._name_token_starts[i] for i in range(102))
    print(f"    crafted occurrences {occ}")
    show("SW-MAX head + 248 'a' + 'b'", ix, T.BAND_HEAD + " " + "a" * 248 + "b")
    show("SW-MAX head + 249-char 'abcd..p' cycle (no match: candidates emptied, then the subsequence scan)", ix,
         T.BAND_HEAD + " " + ("abcdefghijklmnop" * 16)[:249], paths=False)
    pk, dt, st, _ = P.peak_of(lambda: rank(T.BAND_HEAD + " " + "a" * 248 + "b", ix, 20), 300)
    print(f"    one ranking under tracemalloc: peak {pk / 1048576:.2f} MiB ({dt:.2f} s [{st}])")

    print("\n=== oracle (E1 evaluate_b, uncapped OSA) on reduced lists (the switch depends on the candidates only)")
    for lab, lst, qq in (("BAND 225 + 275 REF", bn + f["ref"][:275], q),
                         ("SW-MAX 102 + 398 REF", sw + f["ref"][:398], T.BAND_HEAD + " " + "a" * 248 + "b")):
        ixr = build_label_index(lst)
        got = P.tup(rank(qq, ixr, 20))
        dt, st, want = P.run(lambda: P.oracle(qq, lst, 20), 900)
        print(f"  {lab}: rank == oracle {got == want if st == 'ok' else st} ({dt:.0f} s); listed {len(got)}")
    print(f"\nload after = {P.load()}")


# ---------------------------------------------------------------- mode switch (511 / 512 / 513 occurrences)
def switch():
    header("r2 switch")
    f = P.fixtures()
    head = T.CRAFT_HEAD
    hits = T.CRAFT_HITS[:3]  # 'kem', 'vbc', 'sdl'
    q = " ".join([head] + [h + "q" for h in hits])
    print(f"query {q!r}: head (0 edits, walked first) + 3 tokens, each 1 edit from a hit")
    rng = random.Random(512)
    pool = rng.sample(range(25 ** 4), 2000)
    for target in (511, 512, 513):
        k_names = 100
        extra = target - 5 * k_names  # each name: head + 3 hits + 1 tag = 5 occurrences, then junk
        crafted = []
        j = 0
        for i in range(k_names):
            n_junk = extra // k_names + (1 if i < extra % k_names else 0)
            junk = "".join(P.b25(pool[j + t], 4, LET).capitalize() for t in range(n_junk))
            j += n_junk
            crafted.append(head + "".join(h.capitalize() for h in hits) + junk + P.b25(i, 3, "cdefghijklmnop").capitalize())
        lst = crafted + f["ref"][: 50000 - k_names]
        ix = build_label_index(lst)
        occ = sum(ix._name_token_starts[i + 1] - ix._name_token_starts[i] for i in range(k_names))
        print(f"\n  target {target}: 100 crafted names hold {occ} occurrences -> switch {'fires' if occ <= 512 else 'does not fire'}; {describe(lst)}")
        show(f"{occ} occurrences", ix, q)
        small = crafted + f["ref"][:900]
        ixs = build_label_index(small)
        got = P.tup(rank(q, ixs, 20))
        dt, st, want = P.run(lambda: P.oracle(q, small, 20), 900)
        _, walks, pd, _ = tier_calls(ixs, q)
        print(f"      reduced list (100 crafted + 900 REF): walks {walks}, _prefix_distance {pd}; rank == oracle {got == want if st == 'ok' else st} ({dt:.0f} s)")
        del ix, ixs

    print("\n=== the occurrence switch off with few candidates (2 names of 'Ab' x 300) while every walk's table is large")
    fam = (["ab" + c for c in LOWER] + ["a" + c + "b" for c in LOWER if c != "b"] + [c + "ab" for c in LOWER if c != "a"])
    dense = [f"ab{P.b25(i, 4, LET)}" for i in range(49998)]
    for n_big, reps in ((1, 300), (2, 300)):
        big = [head + "Ab" * reps + P.b25(i, 3, "cdefghijklmnop").capitalize() for i in range(n_big)]
        lst = big + dense[: 50000 - n_big]
        ix = build_label_index(lst)
        occ = sum(ix._name_token_starts[i + 1] - ix._name_token_starts[i] for i in range(n_big))
        qq = head + " " + fam[0] + "".join(t.capitalize() for t in fam[1:75])
        print(f"  {n_big} head name(s) with {occ} occurrences (switch {'fires' if occ <= 512 else 'off'}); {describe(lst)}")
        show(f"{n_big} head names: head + 74 distinct 3-letter tokens", ix, qq, n=3, forced=False)
        del ix

    print("\n=== _classify cost per listed FUZZY name (limit 20 x distinct tokens x name tokens): 40 names head + 'Ab' x 509 among REF")
    big = [head + "Ab" * 508 + P.b25(i, 3, "cdefghijklmnop").capitalize() for i in range(40)]
    lst = big + f["ref"][: 50000 - 40]
    ix = build_label_index(lst)
    qq = head + " " + fam[0] + "".join(t.capitalize() for t in fam[1:75])
    show("40 x 510-token names: head + 74 distinct 3-letter tokens", ix, qq, forced=False)
    for lim in (20, 100):
        m, st, out = P.med(ix, qq, limit=lim, n=3)
        print(f"      limit {lim}: {m * 1000:.1f} ms [{st}] listed {len(out) if out else '-'}")
    print(f"\nload after = {P.load()}")


# ---------------------------------------------------------------- mode dense (the map path: many distinct tokens, large tables)
FAM3 = (["ab" + c for c in LOWER] + ["a" + c + "b" for c in LOWER if c != "b"] + [c + "ab" for c in LOWER if c != "a"])


def fam_query(fam, n):
    return fam[0] + "".join(t.capitalize() for t in fam[1:n])


def dense_lists():
    u6 = []
    v = 0
    for i in range(50000):
        u6.append("_".join("ab" + P.b25(v + t, 4, LET) for t in range(6)))
        v += 6
    return {
        "U1: 50,000 names 'ab' + 4 letters (one distinct token each)": [f"ab{P.b25(i, 4, LET)}" for i in range(50000)],
        "U6: 50,000 names of 6 distinct 'ab'+4-letter tokens": u6,
        "S1: 50,000 names 'ab_' + number (one shared token 'ab')": [f"ab_{i}" for i in range(50000)],
        "E2: 50,000 names 'abcd' + 4 letters (2-edit queries)": [f"abcd{P.b25(i, 4, LET)}" for i in range(50000)],
        "M1: 25,000 U1 names + 25,000 REF names": None,
    }


FAM6 = ["abcd" + x + y for x in "efghijklmnopr" for y in "stuvwxyz"]  # 6 letters: 2 allowed edits


def dense():
    header("r2 dense")
    f = P.fixtures()
    lists = dense_lists()
    lists["M1: 25,000 U1 names + 25,000 REF names"] = lists["U1: 50,000 names 'ab' + 4 letters (one distinct token each)"][:25000] + f["ref"][:25000]
    for lab, names in lists.items():
        assert len(names) == len(set(names)) == 50000 and sum(map(len, names)) <= 2356624, lab
        dt, st, ix = P.run(lambda: build_label_index(names), 300)
        print(f"\n=== {lab}\n    {describe(names)}; build {dt:.2f} s [{st}]; {len(ix._tokens):,} distinct tokens; load {P.load()}")
        fam, ns = (FAM6, (4, 12, 24, 36)) if lab.startswith("E2") else (FAM3, (4, 16, 32, 52, 76))
        for n in ns:
            q = fam_query(fam, n)
            with map_sizes() as sizes:
                rank(q, ix, 20)
            tbl = f"tables: {len(sizes)}, ids {sum(s[0] for s in sizes):,}, postings {sum(s[1] for s in sizes):,}"
            m = show(f"{n} distinct tokens ({tbl})", ix, q, n=3, budget=600, paths=n <= 16, forced=False)
            if m > 3.0 and n < ns[-1]:
                print("      (larger n skipped: already over 3 s)")
                break
        if lab.startswith("U6"):
            q = fam_query(FAM3, 76)
            pk, dt, st, _ = P.peak_of(lambda: rank(q, ix, 20), 900)
            print(f"    76 tokens, one ranking under tracemalloc: peak {pk / 1048576:.2f} MiB ({dt:.2f} s [{st}])")
            pr = cProfile.Profile()
            pr.enable()
            rank(fam_query(FAM3, 32), ix, 20)
            pr.disable()
            buf = io.StringIO()
            pstats.Stats(pr, stream=buf).sort_stats("tottime").print_stats(8)
            print("    cProfile (U6, 32 tokens), top by own time:")
            for line in buf.getvalue().splitlines():
                if "label_match.py" in line or "ncalls" in line or "{method" in line or "{built-in" in line:
                    print("      " + line.replace(str(P.TREE), "<tree>")[:150])
        del ix
    print(f"\nload after = {P.load()}")


# ---------------------------------------------------------------- mode fixcheck (what a range-based table buys on the map path)
def walk_ranges(index, q, k):
    """_fuzzy_token_distances with the same walk, returning (lo, hi, d) id ranges instead of one dict entry per id."""
    if k == 0:
        lo, hi = lm._token_range(index._tokens, q)
        return [(lo, hi, 0)] if lo < hi else []
    chars, depth, first, end, tokens = index._trie_chars, index._trie_depth, index._trie_first, index._trie_end, index._tokens
    m = len(q)
    limit = k + 1
    out = []
    node_count = len(depth)
    cols = [None] * 66
    best = [0] * 66
    prev_char = [""] * 66
    cols[0] = [i if i < limit else limit for i in range(m + 1)]
    best[0] = m if m < limit else limit
    j = 0
    while j < node_count:
        dep = depth[j]
        if dep + 1 >= len(cols):
            cols.extend([None] * dep)
            best.extend([0] * dep)
            prev_char.extend([""] * dep)
        c = chars[j]
        prev = cols[dep - 1]
        new = [limit] * (m + 1)
        low = new[0] = dep if dep < limit else limit
        lo_r = dep - k if dep - k > 1 else 1
        hi_r = dep + k if dep + k < m else m
        prev2 = cols[dep - 2] if dep >= 2 else None
        pchar = prev_char[dep - 1] if dep >= 2 else ""
        for ii in range(lo_r, hi_r + 1):
            qi = q[ii - 1]
            value = prev[ii - 1] + (0 if qi == c else 1)
            alt = prev[ii] + 1
            if alt < value:
                value = alt
            alt = new[ii - 1] + 1
            if alt < value:
                value = alt
            if prev2 is not None and ii > 1 and qi == pchar and q[ii - 2] == c:
                alt = prev2[ii - 2] + 1
                if alt < value:
                    value = alt
            if value > limit:
                value = limit
            new[ii] = value
            if value < low:
                low = value
        bd = best[dep - 1]
        b2 = bd if bd < new[m] else new[m]
        if low > k or low >= b2:
            if b2 <= k:
                out.append((first[j], first[end[j]], b2))
            j = end[j]
            continue
        cols[dep] = new
        best[dep] = b2
        prev_char[dep] = c
        if b2 <= k and len(tokens[first[j]]) == dep:
            out.append((first[j], first[j] + 1, b2))
        j += 1
    return out


def tier_ranges(parsed, ix, taken):
    """The map path of _fuzzy_tier (no switch) with range tables (one C-level postings slice per range) and
    C-level totals (collections._count_elements)."""
    counts = Counter(parsed.tokens)
    distinct = sorted(dict.fromkeys(parsed.tokens), key=lm._allowed_edits)
    ps, po = ix._posting_starts, ix._postings
    cands = None
    totals: Counter = Counter()
    for tok in distinct:
        k = lm._allowed_edits(tok)
        rng = walk_ranges(ix, tok, k)
        if not rng:
            return {}
        layers = [set() for _ in range(k + 1)]
        for lo, hi, d in rng:
            layers[d].update(po[ps[lo]:ps[hi]])
        reached = layers[0].union(*layers[1:])
        if cands is None:
            cands = reached
            cands.difference_update(taken)
        else:
            cands &= reached
        if not cands:
            return {}
        lower = layers[0]
        for d in range(1, k + 1):
            diff = (layers[d] & cands) - lower
            if diff:
                _count_elements(totals, chain.from_iterable(repeat(diff, d * counts[tok])))
            if d < k:
                lower = lower | layers[d]
    return {n: totals.get(n, 0) for n in cands}


def fixcheck():
    header("r2 fixcheck")
    f = P.fixtures()
    lists = dense_lists()
    lists["M1: 25,000 U1 names + 25,000 REF names"] = lists["U1: 50,000 names 'ab' + 4 letters (one distinct token each)"][:25000] + f["ref"][:25000]
    lists["REF6 (case 06, first 50,000)"] = f["ref6"]
    lists["CRAFT"] = T.craft_names() + f["ref"][:49700]
    cases = []
    for lab, names in lists.items():
        if lab.startswith("E2"):
            qs = [fam_query(FAM6, 36)]
        elif lab.startswith("REF6"):
            qs = [q for _, q in T.pset_ref6(f["swa"])][:6]
        elif lab == "CRAFT":
            qs = [T.craft_query(51)]
        else:
            qs = [fam_query(FAM3, 32), fam_query(FAM3, 76)]
        cases.append((lab, names, qs))
    print("real = lm._fuzzy_tier (shipped); ranges = same walk, a (lo, hi, d) table, one postings slice per range, C-level totals")
    for lab, names, qs in cases:
        ix = build_label_index(names)
        print(f"\n=== {lab}: {describe(names)}")
        for q in qs:
            parsed = lm._parse_query(q.strip(WS))
            t0 = time.perf_counter()
            real, _ = lm._fuzzy_tier(parsed, ix, set())
            t_real = time.perf_counter() - t0
            t0 = time.perf_counter()
            alt = tier_ranges(parsed, ix, set())
            t_alt = time.perf_counter() - t0
            t0 = time.perf_counter()
            walks = [walk_ranges(ix, t, lm._allowed_edits(t)) for t in dict.fromkeys(parsed.tokens)]
            t_walk = time.perf_counter() - t0
            print(f"  real {t_real * 1000:8.1f} ms | ranges {t_alt * 1000:8.1f} ms (of which the walks {t_walk * 1000:7.1f} ms, "
                  f"{sum(len(w) for w in walks):,} ranges) | candidates {len(real):,}; equal totals {real == alt}  {q[:44]!r}")
        del ix
    print(f"\nload after = {P.load()}")


# ---------------------------------------------------------------- mode subkey (E5S-02 residuals inside the .40 scope)
def subkey():
    header("r2 subkey")
    print("the E5S-02 shapes cut to the row's scope (50,000 names, <= 2,356,624 characters)")
    short = [f"s{i:05d}" for i in range(50000)]
    k = 2000
    sub = ["x" + "ab" * 509 + "Q" + P.b25(i, 4, LOWER) for i in range(k)]
    lst = sub + short[: 50000 - k]
    ix = build_label_index(lst)
    print(f"\n  substring key: {k:,} names 'x' + 'ab' * 509 + 'Q' + tag + {50000 - k:,} short names: {describe(lst)}")
    for q in ("ba", "bab", "xa"):
        show(f"substring {q!r}", ix, q, n=3, paths=False)
    k = 7900
    seq = ["ab" * 130 + "z" + P.b25(i, 4, "cdefghijklmnop") for i in range(k)]
    lst = seq + short[: 50000 - k]
    ix = build_label_index(lst)
    print(f"\n  subsequence scan: {k:,} names 'ab' * 130 + 'z' + tag + {50000 - k:,} short names: {describe(lst)}")
    for q in ("ab" * 125 + "zzzzz", "ab" * 60 + "zzzzz"):
        show(f"subsequence len {len(q)}", ix, q, n=3, paths=False)
    print(f"\nload after = {P.load()}")


# ---------------------------------------------------------------- mode fuzz (rank == oracle == both forced paths; no exception)
def mutate(rng, tok):
    if len(tok) < 2:
        return tok
    op = rng.randrange(5)
    i = rng.randrange(len(tok))
    c = rng.choice(LOWER + "0123456789")
    if op == 0:
        return tok[:i] + c + tok[i + 1:]
    if op == 1:
        return tok[:i] + c + tok[i:]
    if op == 2:
        return tok[:i] + tok[i + 1:]
    if op == 3 and i < len(tok) - 1:
        return tok[:i] + tok[i + 1] + tok[i] + tok[i + 2:]
    return tok


def fuzz():
    header("r2 fuzz")
    f = P.fixtures()
    rng = random.Random(20261107)
    many = [T.CRAFT_HEAD + "".join(h.capitalize() for h in T.CRAFT_HITS[:rng.randint(3, 12)]) + P.b25(i, 3, "cdefghijklmnop").capitalize()
            for i in range(60)]
    longt = [T.BAND_HEAD + "_" + "a" * rng.randint(40, 80) + P.b25(i, 2, "cdefghijklmnop") for i in range(40)]
    lists = {
        "HOSTILE + 250 REF + 60 many-token + 40 long-token": P.HOSTILE + rng.sample(f["ref"], 250) + many + longt,
        "400 REF6": rng.sample(f["ref6"], 400),
    }
    n_q = exc = bad = mism = path_mism = listed = 0
    first = []
    t0 = time.perf_counter()
    for lab, names in lists.items():
        ix = build_label_index(names)
        pool = [n for n in names if n and len(n) <= 200]
        for _ in range(350):
            parts = []
            for _ in range(rng.choice((1, 1, 2, 3, 4, 8))):
                nm = rng.choice(pool)
                sp = lm._tokens(nm)
                if not sp:
                    continue
                s, e = rng.choice(sp)
                tok = nm[s:e]
                for _ in range(rng.choice((0, 1, 1, 2))):
                    tok = mutate(rng, tok)
                parts.append(tok)
            if not parts:
                continue
            if rng.random() < 0.15:
                parts = parts * rng.randint(2, 6)
            q = rng.choice((" ", "_", "")).join(parts)[:256] if rng.random() < 0.9 else T.CRAFT_HEAD + " " + " ".join(parts)
            q = q[:256]
            want20 = P.oracle(q, names, 20)
            for lim in (1, 20):
                n_q += 1
                try:
                    res = rank(q, ix, lim)
                    got = P.tup(res)
                    with switch_cap(0):
                        never = P.tup(rank(q, ix, lim))
                    with switch_cap(10 ** 9):
                        always = P.tup(rank(q, ix, lim))
                except Exception as e:  # noqa: BLE001 - the probe counts every exception
                    exc += 1
                    first.append(("exception", lab, ascii(q[:50]), lim, repr(e)[:120]))
                    continue
                listed += len(got)
                path_mism += (never != got) + (always != got)
                if never != got or always != got:
                    first.append(("path mismatch", lab, ascii(q[:50]), lim))
                bad += P.bad_spans(res)
                if got != want20[:lim]:
                    mism += 1
                    first.append(("oracle mismatch", lab, ascii(q[:50]), lim))
    print(f"queries x limits {n_q} ({time.perf_counter() - t0:.0f} s); listed entries {listed}; exceptions {exc}; bad spans {bad}; "
          f"rank != oracle {mism}; shipped vs forced paths (cap 0, cap 10**9) differing {path_mism}")
    for row in first[:8]:
        print("   ", row)


# ---------------------------------------------------------------- mode buildscope (.35 / .37 inside their reworded scope)
def buildscope():
    header("r2 buildscope")
    print(".35 / .37 bound 'a name list of 50,000 names that hold at most 2,062,041 characters in all' (REF's total, E5S-02)")
    f = P.fixtures()
    al = LOWER
    lists = {"REF (the row's fixture)": f["ref"]}
    v = 0
    b4 = []
    for i in range(50000):
        b4.append("_".join(P.b25(v + t, 4, al) for t in range(8)))
        v += 8
    lists["B4: 8 distinct 4-letter tokens per name, '_'-joined (400,000 distinct tokens)"] = b4
    v = 0
    b4c = []
    for i in range(50000):
        b4c.append("".join(P.b25(v + t, 4, al).capitalize() for t in range(9)))
        v += 9
    lists["B4c: 9 distinct 4-letter camel tokens per name (450,000 distinct tokens)"] = b4c
    v = 0
    u6 = []
    for i in range(50000):
        u6.append("_".join("ab" + P.b25(v + t, 4, LET) for t in range(6)))
        v += 6
    lists["U6 (mode dense): 6 distinct 'ab'+4-letter tokens per name (300,000 distinct tokens)"] = u6
    for lab, names in lists.items():
        assert len(names) == len(set(names)) == 50000 and sum(map(len, names)) <= 2062041, lab
        times = []
        for _ in range(3):
            dt, st, ix = P.run(lambda: build_label_index(names), 300)
            times.append(dt)
            ntok = len(ix._tokens) if ix is not None else -1
            del ix
        pk, dt, st, ix = P.peak_of(lambda: build_label_index(names), 600)
        print(f"  {lab}\n    {describe(names)}; distinct tokens {ntok:,}; build median of 3 {statistics.median(times):.2f} s [{st}] (.35: 5.0 s)"
              f"{'  > 5.0 s' if statistics.median(times) > 5.0 else ''}; tracemalloc peak {pk:,} B = {pk / 1048576:.1f} MiB (.37: 64 MiB)"
              f"{'  > 64 MiB' if pk > 67108864 else ''}; load {P.load()}")
        del ix
    print(f"\nload after = {P.load()}")


# ---------------------------------------------------------------- mode extra (follow-ups of switch / dense / fixcheck)
def extra():
    header("r2 extra")
    f = P.fixtures()
    head = T.CRAFT_HEAD
    print("=== _classify cost per listed FUZZY name (limit x distinct tokens x name tokens): 40 names head + 'Ab' x 507 + tag "
          "(1,023 chars, 509 tokens; mode switch's 'Ab' x 508 made 1,025-char names, left out by .39) among REF")
    big = [head + "Ab" * 507 + P.b25(i, 3, "cdefghijklmnop").capitalize() for i in range(40)]
    assert all(len(n) <= 1024 for n in big)
    lst = big + f["ref"][: 50000 - 40]
    ix = build_label_index(lst)
    qq = head + " " + fam_query(FAM3, 75)
    show("40 x 509-token names: head + 74 distinct 3-letter tokens", ix, qq, forced=False)
    for lim in (20, 40):
        m, st, out = P.med(ix, qq, limit=lim, n=3)
        pr = cProfile.Profile()
        pr.enable()
        rank(qq, ix, lim)
        pr.disable()
        st_ = pstats.Stats(pr)
        cls = [v for k, v in st_.stats.items() if k[2] == "_classify"]
        print(f"      limit {lim}: {m * 1000:.1f} ms [{st}] listed {len(out) if out else '-'}; _classify cumulative {cls[0][3] * 1000 if cls else 0:.1f} ms under cProfile")
    del ix
    print("\n=== memory of one fuzzy tier: shipped dict tables (kept to step 6) vs range tables")
    lists = dense_lists()
    for lab, n in (("U1: 50,000 names 'ab' + 4 letters (one distinct token each)", 76),
                   ("U6: 50,000 names of 6 distinct 'ab'+4-letter tokens", 32),
                   ("U6: 50,000 names of 6 distinct 'ab'+4-letter tokens", 76)):
        ix = build_label_index(lists[lab])
        parsed = lm._parse_query(fam_query(FAM3, n))
        pk_a, dt_a, st_a, _ = P.peak_of(lambda: tier_ranges(parsed, ix, set()), 900)
        print(f"  {lab[:3]} {n} tokens: ranges peak {pk_a / 1048576:8.2f} MiB ({dt_a:.1f} s [{st_a}] under tracemalloc)")
        if not (lab.startswith("U6") and n == 76):  # mode dense measured the shipped rank there: 1,470.38 MiB
            pk_r, dt_r, st_r, _ = P.peak_of(lambda: lm._fuzzy_tier(parsed, ix, set()), 900)
            print(f"  {lab[:3]} {n} tokens: shipped _fuzzy_tier peak {pk_r / 1048576:8.2f} MiB ({dt_r:.1f} s [{st_r}] under tracemalloc)")
        del ix
    print(f"\nload after = {P.load()}")


if __name__ == "__main__":
    {"extra": extra, "craft": craft, "band": band, "switch": switch, "dense": dense, "fixcheck": fixcheck, "subkey": subkey, "fuzz": fuzz,
     "buildscope": buildscope}[sys.argv[1]]()
