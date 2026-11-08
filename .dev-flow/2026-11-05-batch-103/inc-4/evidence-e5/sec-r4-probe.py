#!/usr/bin/env python3
"""batch-103 Inc 4 E5 security probe, ROUND 4. THROWAWAY EVIDENCE, NOT PRODUCT CODE.

Runs on <runner> only, against the REAL module s19_app/tui/services/label_match.py (sha256 b97d19eb...)
of a read-only COPY of the integrated tree (env TREE, first on PYTHONPATH). It loads the round-3 probe
(sec-r3-probe.py, unchanged; it loads the round-1 probe sec-e5-probe.py, unchanged) for its fixtures, list
builders, the E1 oracle, the address-space cap and the per-case alarm.

Visits: the shipped _fuzzy_token_distances now returns its visit count; a pass-through wrapper records each
walk's (token, allowed, budget passed, visits, runs, ms). Timing medians always use the unwrapped module.
Tier times: pass-through wrappers around _text_tiers, _token_tier, _fuzzy_tier, _subsequence_tier, _cut
(one extra ranking, never the timed ones).

Modes: shapes4, dear, cheap, boundary, det4, nonascii, check4.
"""
from __future__ import annotations

import hashlib
import importlib.util
import os
import random
import sys
import time
from contextlib import contextmanager
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("sec_r3_probe", HERE / "sec-r3-probe.py")
R3 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(R3)
P = R3.P

lm, T, rank, build_label_index = P.lm, P.T, P.rank, P.build_label_index
WS = P.WS
BOUND = T.ANY_QUERY_BOUND_S
SCOPE40 = 2356624
BUDGET = lm._FUZZY_NODE_BUDGET
AL25 = R3.AL25  # b..z
UP25 = AL25.upper()


def header(mode):
    P.header(mode)
    print(f"probe = {Path(__file__).name} sha256 {hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}; "
          f"sec-r3-probe.py sha256 {hashlib.sha256((HERE / 'sec-r3-probe.py').read_bytes()).hexdigest()}; "
          f"sec-e5-probe.py sha256 {hashlib.sha256((HERE / 'sec-e5-probe.py').read_bytes()).hexdigest()}")
    print(f"_FUZZY_NODE_BUDGET = {lm._FUZZY_NODE_BUDGET:,}; _FUZZY_TOKEN_CAP = {lm._FUZZY_TOKEN_CAP}; "
          f"_FUZZY_SWITCH_CAP = {lm._FUZZY_SWITCH_CAP}; _TRIE_PREFIX = {lm._TRIE_PREFIX}; "
          f"T.ANY_QUERY_BOUND_S = {T.ANY_QUERY_BOUND_S}; T.KEYSTROKE_BOUND_S = {T.KEYSTROKE_BOUND_S}")


# ---------------------------------------------------------------- instrumentation (pass-through)
@contextmanager
def walk_log():
    rec = []
    orig = lm._fuzzy_token_distances

    def wrap(index, q, allowed, budget):
        t0 = time.perf_counter()
        runs, visits = orig(index, q, allowed, budget)
        rec.append((q, allowed, budget, visits, len(runs), time.perf_counter() - t0))
        return runs, visits

    lm._fuzzy_token_distances = wrap
    try:
        yield rec
    finally:
        lm._fuzzy_token_distances = orig


TIERS = ("_text_tiers", "_token_tier", "_fuzzy_tier", "_subsequence_tier", "_cut")


@contextmanager
def tier_timer():
    acc = {t: 0.0 for t in TIERS}
    origs = {t: getattr(lm, t) for t in TIERS}

    def mk(name, fn):
        def w(*a, **k):
            t0 = time.perf_counter()
            try:
                return fn(*a, **k)
            finally:
                acc[name] += time.perf_counter() - t0
        return w

    for t in TIERS:
        setattr(lm, t, mk(t, origs[t]))
    try:
        yield acc
    finally:
        for t in TIERS:
            setattr(lm, t, origs[t])


def describe(names):
    return (f"{len(names):,} names, {sum(map(len, names)):,} characters in all (.40 scope: 50,000 names, <= {SCOPE40:,}); "
            f"all ASCII {all(n.isascii() for n in names)}; longest name {max(map(len, names))}")


def build(lab, names):
    print(f"\n=== {lab}\n    {describe(names)}")
    dt, st, ix = P.run(lambda: build_label_index(names), 600)
    print(f"    build {dt:.2f} s [{st}]; {len(ix):,} prepared names; {len(ix._tokens):,} distinct tokens; "
          f"{len(ix._trie_depth):,} trie nodes; {len(ix._postings):,} postings; load {P.load()}")
    return ix


def measure(lab, ix, q, n=7, limit=20, peak=True, budget=900):
    """Median of n shipped rankings; then one ranking with the walk log and the tier timers; then one under tracemalloc."""
    m, st, out = P.med(ix, q, limit=limit, n=n, budget=budget)
    qs = q.strip(WS)
    pq = lm._parse_query(qs) if len(qs) <= 256 else None
    toks = pq.tokens if pq else ()
    rules = sorted({r.rule.value for r in out}) if out else "-"
    edits = sorted({r.edits for r in out}) if out else "-"
    if m > BOUND:
        flag = f"  > {BOUND:.1f} s (.40) x{m / BOUND:.2f}"
    else:
        flag = f"  ({BOUND / m:.2f}x under {BOUND:.1f} s)" if m > 0 else ""
    print(f"  {m * 1000:10.1f} ms [{st}] median of {n}; chars {len(qs):>3}, tokens {len(toks):>3} (distinct {len(set(toks)):>3}); "
          f"listed {'-' if out is None else len(out)} {rules} edits {edits}; bad spans {P.bad_spans(out)}{flag}  {lab}")
    if st != "ok":
        return m, None
    with walk_log() as rec, tier_timer() as acc:
        t0 = time.perf_counter()
        out2 = rank(q, ix, limit)
        tot = time.perf_counter() - t0
    same = P.tup(out2) == P.tup(out)
    visits = sum(r[3] for r in rec)
    wt = sum(r[5] for r in rec)
    walked = [r for r in rec if r[1] > 0]
    us = f"{wt / visits * 1e6:.2f} us/visit incl. walk setup" if visits else "-"
    tiers = ", ".join(f"{k.strip('_').replace('_tiers', '').replace('_tier', '')} {v * 1000:.0f}" for k, v in acc.items())
    print(f"        walks {len(rec)} ({len(walked)} walked, allowed>0), visits {visits:,} (budget {BUDGET:,} reached: "
          f"{visits >= BUDGET}; {us}; walks {wt * 1000:.0f} ms); tiers ms [{tiers}] of {tot * 1000:.0f} ms; "
          f"instrumented list == shipped {same}")
    if rec:
        per = "; ".join(f"{len(r[0])}ch k{r[1]} b{r[2]:,} v{r[3]:,} r{r[4]:,}" for r in rec[:5])
        print(f"        first walks: {per}{' ...' if len(rec) > 5 else ''}")
    if peak:
        pk, dt, st2, _ = P.peak_of(lambda: rank(q, ix, limit), budget)
        print(f"        one ranking under tracemalloc: peak {pk / 1048576:.2f} MiB [{st2}]")
    return m, visits


def control(lab, ix, q, n=1):
    """The same ranking with the node budget removed (_FUZZY_NODE_BUDGET = 10**9): the mechanism's effect."""
    with R3.cap_value("_FUZZY_NODE_BUDGET", 10 ** 9):
        m, st, out = P.med(ix, q, n=n, budget=900)
        with walk_log() as rec:
            rank(q, ix, 20)
    rules = sorted({r.rule.value for r in out}) if out else "-"
    print(f"      budget removed: {m * 1000:10.1f} ms [{st}] (n={n}); visits {sum(r[3] for r in rec):,}; listed "
          f"{len(out) if out else 0} {rules}  {lab}")


# ---------------------------------------------------------------- list builders (round 4)
def pad_alpha(names, total=50000, prefix="zw"):
    """Pads 'zw' + X + 3 letters (X varies fastest): every pad token sits under 'zwX', a node any 'a'-run query
    prunes at depth 3, so the pads add a constant 1 + 25 visits whatever their number (>= 25)."""
    names = list(names)
    k = 0
    while len(names) < total:
        names.append(prefix + AL25[k % 25] + P.b25(k // 25, 3, AL25))
        k += 1
    assert len(names) == len(set(names)) == total, (len(names), len(set(names)))
    return names


def deep_names(n_tokens, seed=20261301):
    """The first n_tokens of a seeded shuffle of DEEP40's 41,250 tokens ('a' * 40, 2 substitutions in the first 12),
    24 per name joined by '_'."""
    toks = R3.two_sub_tokens(40, 12)
    random.Random(seed).shuffle(toks)
    toks = toks[:n_tokens]
    return ["_".join(toks[k:k + 24]) for k in range(0, len(toks), 24)]


def submax():
    """SUBMAX: 50,000 names of a 4-letter upper tag (no 'A') + 'A' * 43 (2,350,000 characters): 'a' occurs 43 times in
    each, never at a boundary offset (upper after upper, followed by upper: the longest _at_boundary path)."""
    names = [P.b25(i, 4, UP25) + "A" * 43 for i in range(50000)]
    assert len(set(names)) == 50000 and sum(map(len, names)) <= SCOPE40
    return names


def subd():
    """SUBD: 50,000 names of a 5-digit tag (no '0') + '0' * 42: '0' occurs 42 times, never at a boundary offset."""
    names = [P.b25(i, 5, "123456789") + "0" * 42 for i in range(50000)]
    assert len(set(names)) == 50000 and sum(map(len, names)) <= SCOPE40
    return names


INWQ = "a" * 253 + "b" + "aa"  # 256 letters; default_find (n < 2500) compares 254 characters per window, gap 0


def inw():
    """INW: as many 1,024-character names 'b' + 3 letters + 'a' * 1020 as .40's scope allows (2,114), padded with
    4-letter names: INWQ never occurs, but str.__contains__ checks ~765 windows x 254 characters in each long name."""
    long_ = ["b" + P.b25(i, 3, AL25) + "a" * 1020 for i in range(2114)]
    names = long_ + [P.b25(i, 4, AL25) for i in range(50000 - len(long_))]
    assert len(set(names)) == 50000 and sum(map(len, names)) <= SCOPE40, sum(map(len, names))
    return names


def inwd():
    """INWD: 600 names of 24 DEEP40 tokens (589,800 characters; enough trie for INWQ's walk to spend the budget at
    m = 256), 1,538 INW long names, padded with 4-letter names."""
    deep = deep_names(14400)
    long_ = ["b" + P.b25(i, 3, AL25) + "a" * 1020 for i in range(1538)]
    names = deep + long_
    names += [P.b25(i, 4, AL25) for i in range(50000 - len(names))]
    assert len(set(names)) == 50000 and sum(map(len, names)) <= SCOPE40, sum(map(len, names))
    return names


def combo():
    """COMBO: 600 DEEP names (the budget walk) + 49,400 names of 11 or 12 camel tokens 'Ab' + X (X distinct per name):
    every 3-letter query token 'ab' + c is within 1 edit of every such token, so 19 such walks each read ~588,000
    postings, and the 20th token, 'a' * k, spends what is left of the budget on the DEEP trie."""
    deep = deep_names(14400)
    rng = random.Random(20261302)
    letters = "abcdefghijklmnopqrstuvwxyz"
    seen = set(deep)
    h = []
    while len(h) < 49400:
        k = 12 if len(h) < 45000 else 11
        nm = "".join("Ab" + c for c in rng.sample(letters, k))
        if nm not in seen:
            seen.add(nm)
            h.append(nm)
    names = deep + h
    assert len(set(names)) == 50000 and sum(map(len, names)) <= SCOPE40, sum(map(len, names))
    return names


def combo_query(n_heavy, sep=False):
    heavy = ["Ab" + c for c in "bcdefghijklmnopqrstuvwxyz"[:n_heavy]]
    head = (" ".join(heavy) if sep else "".join(heavy)) + " "
    return head + "a" * (256 - len(head))


# ---------------------------------------------------------------- mode shapes4 (round-3 shapes on the budgeted code)
def shapes4():
    header("r4 shapes4")
    print(f".40 as ruled: 50,000 names, <= {SCOPE40:,} characters, any query of <= 256 characters, limit <= 20, within {BOUND} s")
    ix = build("W40 (the test module's own list, w40_names())", T.w40_names())
    for lab, q in (("'a' * 40 (1 token)", "a" * 40),
                   ("'a' * 64 (1 token)", "a" * 64),
                   ("'a' * 40, 'a' * 39 (2 distinct; .42/1)", R3.runs_query((40, 39))),
                   ("'a' * 40 .. 'a' * 38 (3 distinct)", R3.runs_query((40, 39, 38))),
                   ("'a' * 40 .. 'a' * 35 (6 distinct, 230 chars; .42/2)", R3.runs_query(range(40, 34, -1))),
                   ("'a' * 39 + b .. g (6 distinct, 245 chars)", " ".join("a" * 39 + c for c in "bcdefg"))):
        measure(lab, ix, q)
    control("W40 6 tokens (.42/2's control)", ix, R3.runs_query(range(40, 34, -1)))
    del ix
    ix = build("DEEP40", R3.deep40())
    for lab, q in (("'a' * 40 (1 token; .42/3)", "a" * 40),
                   ("'a' * 40, 'a' * 39 (2 distinct)", R3.runs_query((40, 39))),
                   ("'a' * 40 .. 'a' * 35 (6 distinct; .42/4)", R3.runs_query(range(40, 34, -1)))):
        measure(lab, ix, q)
    control("DEEP40 6 tokens", ix, R3.runs_query(range(40, 34, -1)))
    del ix
    ix = build("DEEP258", R3.deep258())
    for lab, q in (("'a' * 256 (1 token)", "a" * 256),
                   ("'a' * 128, 'a' * 127 (2 distinct)", R3.runs_query((128, 127))),
                   ("'a' * 40 (1 token)", "a" * 40)):
        measure(lab, ix, q)
    del ix
    ix = build("W12", R3.w12())
    for k in (1, 4, 8, 16, 20, 21):
        measure(f"T{k}: {k} distinct tokens 'a' * 10 + c{' (.42/5)' if k == 20 else ''}", ix, R3.t_query(k))
    measure("T20 + its first token again (21 tokens, 20 distinct)", ix, R3.t_query(20) + " " + R3.t_query(1))
    control("W12 T20", ix, R3.t_query(20))
    del ix
    u1 = [f"ab{P.b25(i, 4, T.LET25)}" for i in range(50000)]
    for lab, names, qs in (("U6", T.u6_names(), (20, 76)), ("D3", T.d3_names(), (20, 76)), ("U1", u1, (76,))):
        ix = build(lab, names)
        for k in qs:
            measure(f"FAMQ({k}){' (the 76-token query)' if k == 76 else ''}", ix, T.fam_query(T.FAMQ, k))
        del ix
    print(f"\nload after = {P.load()}")


# ---------------------------------------------------------------- mode dear (budget x the dearest visit)
def dear():
    header("r4 dear")
    print("The budget bounds visits; a visit's cost grows with the query token's length m (the column list is m + 1 long).")
    ix = build("DEEP40", R3.deep40())
    for k in (40, 64, 128, 200, 256):
        measure(f"'a' * {k} (1 token, m = {k})", ix, "a" * k)
    measure("'a' * 128, 'a' * 127 (2 distinct)", ix, R3.runs_query((128, 127)))
    measure("'a' * 84, 'a' * 83, 'a' * 82 (3 distinct, 251 chars)", ix, R3.runs_query((84, 83, 82)))
    del ix
    ix = build("DEEP258", R3.deep258())
    for k in (128, 256):
        measure(f"'a' * {k} (1 token)", ix, "a" * k)
    del ix
    print(f"\nload after = {P.load()}")


# ---------------------------------------------------------------- mode cheap (the tiers the budget does not cover)
def cheap():
    header("r4 cheap")
    print("Shapes that make the exact / prefix / substring / token / subsequence tiers (and the fuzzy postings work) dear.")
    tag = "cdefghijklmnop"
    tags = [P.b25(i, 5, tag) for i in range(50000)]
    plan = [
        ("SUBO (subo_names(), the row's list)", T.subo_names(), [("'a'", "a"), ("'aa'", "aa")], 5),
        ("SUBU (round 3): 'X' + 'A' * 40 + 'Q' + 5-letter tag", ["X" + "A" * 40 + "Q" + t for t in tags], [("'a'", "a"), ("'A'", "A")], 5),
        ("SUBMAX: 4-letter upper tag + 'A' * 43 (2,150,000 non-boundary occurrences)", submax(), [("'a'", "a"), ("'A'", "A"), ("'aa'", "aa")], 7),
        ("SUBD: 5-digit tag + '0' * 42", subd(), [("'0'", "0")], 5),
        ("INW: 2,114 names of 1,024 characters + 4-letter pads", inw(), [("INWQ ('a' * 253 + 'b' + 'aa')", INWQ), ("'a' * 255 + 'b'", "a" * 255 + "b")], 5),
        ("INWD: 600 DEEP names + 1,538 INW names + 4-letter pads", inwd(), [("INWQ", INWQ), ("'a' * 256", "a" * 256)], 7),
        ("COMBO: 600 DEEP names + 49,400 'Ab' + X camel names", combo(),
         [("19 camel 'Ab' + c tokens + 'a' * 198", combo_query(19)), ("19 spaced 'Ab' + c + 'a' * 180", combo_query(19, sep=True)),
          ("10 camel + 'a' * 225", combo_query(10)), ("19 camel + 'a' * 40", combo_query(19)[:58] + "a" * 40)], 7),
    ]
    for lab, names, qs, n in plan:
        ix = build(lab, names)
        for qlab, q in qs:
            assert len(q) <= 256, qlab
            measure(qlab, ix, q, n=n)
        if lab.startswith(("INWD", "COMBO")):
            control(qs[0][0], ix, qs[0][1])
        del ix
    print(f"\nload after = {P.load()}")


# ---------------------------------------------------------------- mode boundary (a walk of 399,999 / 400,000 / 400,001 visits)
SENTINEL = "zz" + "a" * 38  # within 2 edits of 'a' * 40, the last token in code-point order: the walk's last visit
PARENTS = ("zy", "zx", "zv", "zs", "zr", "zq")
FILL = [p + c for p in PARENTS for c in AL25]  # 150 tokens; each is visited once and pruned (3 edits at depth 3)


def bnd_names(n_tok, n_fill):
    """DEEP tokens (the sentinel's own token left out) + one name holding the filler parents (so each filler adds
    exactly one visit) + two names holding n_fill fillers + the sentinel name + 'zw' pads."""
    deep = deep_names(n_tok)
    deep = ["_".join(t for t in nm.split("_") if t != SENTINEL) for nm in deep]
    fill = FILL[:n_fill]
    holders = ["zu_" + "_".join(PARENTS), "_".join(["zt"] + fill[:75]), "_".join(["zp"] + fill[75:])]
    return pad_alpha(deep + holders + [SENTINEL])


def natural_visits(names, q="a" * 40):
    ix = build_label_index(names)
    return lm._fuzzy_token_distances(ix, q, 2, 10 ** 9)[1], ix


def boundary():
    header("r4 boundary")
    q = "a" * 40
    print(f"query {q!r} (1 token, 2 allowed edits); natural visits = the shipped walk with budget 10**9; budget {BUDGET:,}")
    lo, hi = 1000, 41250
    while lo < hi:  # the largest n_tok whose natural visits with no filler <= BUDGET - 1
        mid = (lo + hi + 1) // 2
        v, _ = natural_visits(bnd_names(mid, 0))
        if v <= BUDGET - 1:
            lo = mid
        else:
            hi = mid - 1
    n_tok = lo
    v0, _ = natural_visits(bnd_names(n_tok, 0))
    v5, _ = natural_visits(bnd_names(n_tok, 5))
    print(f"n_tok = {n_tok:,} DEEP tokens; natural visits with 0 fillers {v0:,}, with 5 fillers {v5:,} (one visit per filler: {v5 - v0 == 5})")
    found = {}
    for f in range(BUDGET - 1 - v0, BUDGET + 2 - v0):
        v, _ = natural_visits(bnd_names(n_tok, f))
        found[v] = f
    print(f"filler counts by natural visits: {found}")
    print(f"\n{'natural':>9} {'fillers':>7} | shipped rank('a'*40, limit 20): first entry; sentinel listed | budget removed: first entry; sentinel listed | visits in the ranking")
    for v in sorted(found):
        names = bnd_names(n_tok, found[v])
        assert len(names) == 50000 and sum(map(len, names)) <= SCOPE40
        vv, ix = natural_visits(names)
        assert vv == v
        with walk_log() as rec:
            got = rank(q, ix, 20)
        with R3.cap_value("_FUZZY_NODE_BUDGET", 10 ** 9):
            ref = rank(q, ix, 20)
        g0 = (got[0].name[:12], got[0].rule.value, got[0].edits, got[0].spans) if got else None
        r0 = (ref[0].name[:12], ref[0].rule.value, ref[0].edits, ref[0].spans) if ref else None
        s_got = any(m.name == SENTINEL for m in got)
        s_ref = any(m.name == SENTINEL for m in ref)
        print(f"{v:>9,} {found[v]:>7} | {g0} {s_got} | {r0} {s_ref} | {[(r[2], r[3]) for r in rec]}; "
              f"listed {len(got)}; same as no budget {P.tup(got) == P.tup(ref)}")
        m, st, _ = P.med(ix, q, n=5)
        print(f"          median of 5: {m * 1000:.1f} ms [{st}]; 2-token query 'a'*40 + ' ' + 'a'*39 -> "
              f"{sorted({r.rule.value for r in rank(R3.runs_query((40, 39)), ix, 20)})}")
    print(f"\nload after = {P.load()}")


# ---------------------------------------------------------------- mode det4 (truncated lists across hash seeds and calls)
PINNED = {  # tests/test_b103_label_match_perf.py, R-A2L-MATCH.42/1 .. /4 (T._sha_list projection)
    "42/1": "29cb2305cae359f658d4f9d00644608ed26c83214fc09889ba8efd4076cb32cd",
    "42/2": "4243a09dd1d9577dd3ceb5e710c17716a066f9bd4f8423c86684689bb8a1b3e7",
    "42/3": "094071ae7a78cfda29d688955b846ef9984090df8b7133a136a3efe5579e350c",
    "42/4": "c032a4c1c1816604f9fe0f37368a6fe3d96f2100e0a3da96667b36f787529ef2",
}


def det4():
    header("r4 det4")
    h = hashlib.sha256()
    n = rep_bad = reached = nq = 0
    pins = {}
    t0 = time.perf_counter()
    plan = [
        ("W40", T.w40_names, [("42/1", R3.runs_query((40, 39))), ("42/2", R3.runs_query(range(40, 34, -1))), ("", "a" * 40), ("", "a" * 64)]),
        ("DEEP40", R3.deep40, [("42/3", "a" * 40), ("42/4", R3.runs_query(range(40, 34, -1))), ("", "a" * 256)]),
        ("W12", R3.w12, [("42/5", R3.t_query(20)), ("", R3.t_query(16)), ("", R3.t_query(8))]),
        ("DEEP258", R3.deep258, [("", "a" * 256), ("", R3.runs_query((128, 127)))]),
        ("INWD", inwd, [("", INWQ)]),
        ("COMBO", combo, [("", combo_query(19))]),
    ]
    for lab, maker, qs in plan:
        ix = build_label_index(maker())
        for pin, q in qs:
            with walk_log() as rec:
                first = P.tup(rank(q, ix, 20))
            reached += sum(r[3] for r in rec) >= BUDGET
            nq += 1
            for _ in range(2):
                rep_bad += P.tup(rank(q, ix, 20)) != first
            for lim in (1, 20, 100):
                h.update(repr(P.tup(rank(q, ix, lim))).encode("utf-8", "surrogatepass"))
                n += 1
            if pin in PINNED:
                pins[pin] = T._sha_list(rank(q, ix, 20)) == PINNED[pin]
            elif pin == "42/5":
                pins[pin] = rank(q, ix, 20) == []
        del ix
    print(f"PYTHONHASHSEED={os.environ.get('PYTHONHASHSEED')} hash('abc')={hash('abc')} rankings={n} sha256={h.hexdigest()} "
          f"({time.perf_counter() - t0:.0f} s); queries whose ranking reached the budget {reached} of {nq}; "
          f"repeated calls differing {rep_bad}; .42 cases equal to the test-pinned lists {pins}")


# ---------------------------------------------------------------- mode nonascii (R-A2L-MATCH.43)
def nonascii():
    header("r4 nonascii")
    chars = {"U+007F": "\x7f", "U+0080": "\x80", "U+00E9": "é", "U+00FF": "ÿ", "U+0100": "Ā", "U+0130": "İ",
             "U+2028": " ", "U+FEFF": "﻿", "U+FFFF": "￿", "U+10000": "\U00010000",
             "U+10FFFF": "\U0010ffff", "lone U+D800": "\ud800", "U+212A": "K"}
    print("=== A. one character in an otherwise matching name (start / middle / end), beside 'VALUE_0001'")
    for lab, c in chars.items():
        names = ["VALUE_0001", c + "VALUE_X", "VALUE" + c + "_X", "VALUE_X" + c, "value_" + c]
        dt, st, ix = P.run(lambda: build_label_index(names), 60)
        kept = [ascii(n) for n in ix.names] if ix is not None else st
        got = [(ascii(m.name), m.rule.value) for m in rank("value", ix, 50)] if ix is not None else st
        print(f"  {lab:12s} prepared {kept}; rank('value') {got}")
    print("\n=== B. lists that are all or half non-ASCII (50,000 names)")
    ast1 = ["_".join(chr(0x10000 + 20 * i + t) for t in range(20)) for i in range(50000)]
    lat1 = ["_".join(P.b25(8 * i + t, 4, "àáâãäåæçèéêëìíîïðñòóôõöøùúûü") for t in range(8)) for i in range(50000)]
    one = [f"Sig_{i:05d}" + "é" for i in range(50000)]  # each name one non-ASCII character, at the end
    half = [n for pair in zip([f"Sig_{i:05d}" for i in range(25000)], one[:25000]) for n in pair]
    ref = P.fixtures()["ref"]
    mixed_dups = ["A_1", "B_é", "A_1", "C_2", "B_é", "c_2", "ü"]
    for lab, names in (("AST1 (20 astral 1-character tokens per name)", ast1), ("LAT1 (8 Latin-1 tokens per name)", lat1),
                       ("ONE (ASCII name + one trailing U+00E9)", one), ("HALF (ASCII / ONE alternating)", half),
                       ("REF with every 7th name given a trailing U+00E9", [n + "é" if k % 7 == 0 else n for k, n in enumerate(ref)]),
                       ("duplicates around non-ASCII twins", mixed_dups)):
        dt, st, ix = P.run(lambda: build_label_index(names), 600)
        expect = list(dict.fromkeys(n for n in names if n.isascii() and len(n) <= 1024))
        ok = ix is not None and list(ix.names) == expect
        pk, dt2, st2, ix2 = P.peak_of(lambda: build_label_index(names), 600)
        del ix2
        rk = []
        if ix is not None:
            for q in ("sig", "a", "é", "\U00010000", "sig_00001", names[3][:6], "x" * 256):
                m, st3, out = P.med(ix, q, n=3)
                rk.append(f"{ascii(q[:8])}: {len(out) if out is not None else st3} in {m * 1000:.1f} ms, bad spans {P.bad_spans(out)}, "
                          f"non-ASCII listed {sum(not r.name.isascii() for r in out or [])}")
        print(f"  {lab}\n    {len(names):,} names, {sum(map(len, names)):,} characters; build {dt:.2f} s [{st}]; prepared {len(ix) if ix is not None else '-'} "
              f"names == the ASCII names in first-occurrence order {ok}; tracemalloc peak {pk:,} B ({pk / 1048576:.2f} MiB) [{st2}]")
        for r in rk:
            print(f"      rank {r}")
    print("\n=== C. a str subclass, an iterator, and a generator")

    class S(str):
        pass

    for lab, src in (("[S('Sub_é'), S('Sub_x')]", lambda: [S("Sub_é"), S("Sub_x")]), ("iter([...])", lambda: iter(["é_a", "a_b"])),
                     ("generator", lambda: (n for n in ("x_é", "x_y")))):
        try:
            ix = build_label_index(src())
            print(f"  {lab:28s} -> prepared {[ascii(n) for n in ix.names]}; rank('x') {[ascii(m.name) for m in rank('x', ix, 5)]}")
        except Exception as e:  # noqa: BLE001
            print(f"  {lab:28s} -> {type(e).__name__}: {e}")
    print(f"\nload after = {P.load()}")


# ---------------------------------------------------------------- mode check4 (round-3 check with .43 applied to the oracle)
def check4():
    """R3.check with the oracle given only the ASCII names (R-A2L-MATCH.43); the walks are logged to show the node
    budget is never reached in these sets (so the oracle, which has no budget, still applies)."""
    orig = R3.capped_oracle

    def ascii_capped(query, names, limit):
        return orig(query, [n for n in names if n.isascii()], limit)

    R3.capped_oracle = ascii_capped
    orig_walk = lm._fuzzy_token_distances
    stat = {"walks": 0, "min_left": BUDGET, "max_visits": 0}

    def wrap(index, q, allowed, budget):
        runs, visits = orig_walk(index, q, allowed, budget)
        stat["walks"] += 1
        stat["min_left"] = min(stat["min_left"], budget - visits)
        stat["max_visits"] = max(stat["max_visits"], visits)
        return runs, visits

    lm._fuzzy_token_distances = wrap
    try:
        R3.check()
    finally:
        lm._fuzzy_token_distances = orig_walk
        R3.capped_oracle = orig
    print(f"\nwalk log over the whole mode: {stat['walks']:,} calls; most visits in one walk {stat['max_visits']:,}; "
          f"smallest budget left after a walk {stat['min_left']:,} (> 0: the budget was never spent)")


# ---------------------------------------------------------------- mode detx (round-1 det set: round-3 code vs this code)
def detx():
    """The round-1 det set (P.det's plan, same queries) ranked by this module and by the round-3 module (lm_r3.py, from
    git 1c5314ec, loaded standalone under another name), with the HOSTILE list as is and with its ASCII names only.
    If round 3 on the ASCII names equals this code, R-A2L-MATCH.43 is the only change of any list in the set."""
    header("r4 detx")
    spec = importlib.util.spec_from_file_location("lm_r3", HERE / "lm_r3.py")
    lm3 = importlib.util.module_from_spec(spec)
    sys.modules["lm_r3"] = lm3  # dataclass(slots=True) looks its module up in sys.modules
    spec.loader.exec_module(lm3)
    print(f"round-3 module lm_r3.py sha256 {hashlib.sha256((HERE / 'lm_r3.py').read_bytes()).hexdigest()}; "
          f"has _FUZZY_NODE_BUDGET {hasattr(lm3, '_FUZZY_NODE_BUDGET')}")
    # P.det itself (its own literal queries) with its module-level build_label_index / rank / HOSTILE swapped.
    ascii_h = [n for n in P.HOSTILE if n.isascii()]
    saved = (P.build_label_index, P.rank, P.HOSTILE)
    try:
        for lab, mod, hostile in (("b97d19eb (this code), HOSTILE as is", lm, saved[2]),
                                  ("b97d19eb (this code), HOSTILE ASCII names only", lm, ascii_h),
                                  ("8f396c15 (round 3), HOSTILE ASCII names only", lm3, ascii_h),
                                  ("8f396c15 (round 3), HOSTILE as is", lm3, saved[2])):
            P.build_label_index, P.rank, P.HOSTILE = mod.build_label_index, mod.rank, hostile
            print(f"\n--- {lab} (P.det with {mod.__name__}.build_label_index / rank; {len(hostile)} HOSTILE names)")
            P.det()
    finally:
        P.build_label_index, P.rank, P.HOSTILE = saved


# ---------------------------------------------------------------- mode rerun (the thinnest margins, again, at a quieter time)
def rerun():
    header("r4 rerun")
    plan = [
        ("SUBMAX", submax, [("'a'", "a")]),
        ("SUBU", lambda: ["X" + "A" * 40 + "Q" + P.b25(i, 5, "cdefghijklmnop") for i in range(50000)], [("'a'", "a")]),
        ("COMBO", combo, [("19 camel 'Ab' + c tokens + 'a' * 198", combo_query(19)), ("19 camel + 'a' * 40", combo_query(19)[:58] + "a" * 40)]),
        ("INWD", inwd, [("INWQ", INWQ)]),
        ("DEEP40", R3.deep40, [("'a' * 256", "a" * 256)]),
        ("W40", T.w40_names, [(".42/2", R3.runs_query(range(40, 34, -1)))]),
    ]
    for lab, maker, qs in plan:
        ix = build(lab, maker())
        for qlab, q in qs:
            print(f"    load before {P.load()}")
            measure(qlab, ix, q, n=7, peak=False)
            print(f"    load after {P.load()}")
        del ix
    print(f"\nload after = {P.load()}")


if __name__ == "__main__":
    {"shapes4": shapes4, "dear": dear, "cheap": cheap, "boundary": boundary, "det4": det4, "nonascii": nonascii,
     "check4": check4, "detx": detx, "rerun": rerun}[sys.argv[1]]()
