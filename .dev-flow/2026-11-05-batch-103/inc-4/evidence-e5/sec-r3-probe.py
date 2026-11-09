#!/usr/bin/env python3
"""batch-103 Inc 4 E5 security probe, ROUND 3. THROWAWAY EVIDENCE, NOT PRODUCT CODE.

Runs on <runner> only, against the REAL module s19_app/tui/services/label_match.py
(sha256 8f396c15...) of a read-only COPY of the integrated tree (env TREE, first on PYTHONPATH).
It loads the round-1 probe (sec-e5-probe.py, unchanged, same directory) for its fixtures, the E1
oracle (evaluate_b, uncapped OSA, from the E3 pilot copy in PILOT_DIR), the address-space cap and
the per-case alarm. U6, D3, E2, W40, SUBO, CRAFT, BAND and B4MAX come from the test module's own
builders. The R-A2L-MATCH.41 cap is applied to the oracle here (more than 20 distinct query tokens:
the fuzzy rule is left out, the subsequence rule still runs).

Node counter: an instrumented copy of the shipped _fuzzy_token_distances (its own source, one counter
line added at the top of the walk loop) counts the trie nodes each walk visits. Timing medians always
use the shipped, uninstrumented function.

Modes: walk, cap, shapes, subs, budget, build37, check, det3, fixb (pilot of a node budget), detnocap.
"""
from __future__ import annotations

import hashlib
import importlib.util
import inspect
import os
import random
import statistics
import sys
import time
from contextlib import contextmanager
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("sec_e5_probe", HERE / "sec-e5-probe.py")
P = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(P)

lm, T, rank, build_label_index = P.lm, P.T, P.rank, P.build_label_index
WS, LOWER = P.WS, P.LOWER
AL25 = "bcdefghijklmnopqrstuvwxyz"  # 25 substitution letters (no 'a')
BOUND = T.ANY_QUERY_BOUND_S  # R-A2L-MATCH.40 as ruled at E5 round 2: 2.0 s
SCOPE40 = 2356624
SCOPE37 = 2062041


def header(mode):
    P.header(mode)
    print(f"probe = {Path(__file__).name} sha256 {hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}; "
          f"round-1 helpers = sec-e5-probe.py sha256 {hashlib.sha256((HERE / 'sec-e5-probe.py').read_bytes()).hexdigest()}")
    print(f"_FUZZY_TOKEN_CAP = {lm._FUZZY_TOKEN_CAP}; _FUZZY_SWITCH_CAP = {lm._FUZZY_SWITCH_CAP}; "
          f"T.ANY_QUERY_BOUND_S = {T.ANY_QUERY_BOUND_S}; T.KEYSTROKE_BOUND_S = {T.KEYSTROKE_BOUND_S}")


# ---------------------------------------------------------------- instrumentation
_SRC = inspect.getsource(lm._fuzzy_token_distances)
_LOOP = "    while j < node_count:\n"
assert _SRC.count(_LOOP) == 1, "walk loop not found"
NODES = [0]
_NS = dict(lm.__dict__)
_NS["_NODES"] = NODES
exec(compile("from __future__ import annotations\n" + _SRC.replace(_LOOP, _LOOP + "        _NODES[0] += 1\n", 1),
             "<instrumented _fuzzy_token_distances>", "exec"), _NS)
COUNTED_WALK = _NS["_fuzzy_token_distances"]


@contextmanager
def walk_log():
    rec = []
    orig_walk, orig_pd = lm._fuzzy_token_distances, lm._prefix_distance
    pd = [0]

    def wrap(index, q, allowed):
        NODES[0] = 0
        t0 = time.perf_counter()
        r = COUNTED_WALK(index, q, allowed)
        rec.append((q, allowed, NODES[0], len(r), time.perf_counter() - t0))
        return r

    def wrap_pd(*a):
        pd[0] += 1
        return orig_pd(*a)

    lm._fuzzy_token_distances, lm._prefix_distance = wrap, wrap_pd
    try:
        yield rec, pd
    finally:
        lm._fuzzy_token_distances, lm._prefix_distance = orig_walk, orig_pd


def walks_of(ix, q, limit=20):
    with walk_log() as (rec, pd):
        out = rank(q, ix, limit)
    return out, rec, pd[0]


@contextmanager
def cap_value(name, value):
    old = getattr(lm, name)
    setattr(lm, name, value)
    try:
        yield
    finally:
        setattr(lm, name, old)


def describe(names):
    return (f"{len(names):,} names, {sum(map(len, names)):,} characters in all (.40 scope: 50,000 names, <= {SCOPE40:,}; "
            f".35/.37 scope: <= {SCOPE37:,}); all ASCII {all(n.isascii() for n in names)}; longest name {max(map(len, names))}")


def measure(lab, ix, q, n=3, budget=900, peak=True, limit=20, check_instr=True):
    """Median of n shipped rankings, then one instrumented ranking (walks, nodes, per-walk ms, _prefix_distance
    calls) and one ranking under tracemalloc. Returns the median in seconds."""
    m, st, out = P.med(ix, q, limit=limit, n=n, budget=budget)
    qs = q.strip(WS)
    toks = lm._parse_query(qs).tokens if lm._parse_query(qs) else ()
    rules = sorted({r.rule.value for r in out}) if out else "-"
    edits = sorted({r.edits for r in out}) if out else "-"
    flag = f"  > {BOUND:.1f} s (.40)  x{m / BOUND:.2f}" if m > BOUND else ""
    print(f"  {m * 1000:10.1f} ms [{st}] median of {n}; chars {len(qs):>3}, tokens {len(toks):>3} (distinct {len(set(toks)):>3}); "
          f"listed {'-' if out is None else len(out)} {rules} edits {edits}; bad spans {P.bad_spans(out)}{flag}  {lab}")
    if st != "ok":
        return m
    out2, rec, pd = walks_of(ix, q, limit)
    same = P.tup(out2) == P.tup(out)
    nodes = sum(r[2] for r in rec)
    wt = sum(r[4] for r in rec)
    per = ", ".join(f"{len(r[0])}ch k{r[1]}: {r[2]:,} nodes {r[4] * 1000:.0f} ms" for r in rec[:8])
    more = f", ... (+{len(rec) - 8})" if len(rec) > 8 else ""
    us = f"{wt / nodes * 1e6:.2f} us/node" if nodes else "-"
    print(f"        walks {len(rec)}, nodes visited {nodes:,} ({us}, walks {wt * 1000:.0f} ms instrumented); _prefix_distance {pd:,}; "
          f"instrumented list == shipped {same}")
    if rec:
        print(f"        per walk: {per}{more}")
    if peak:
        pk, dt, st2, _ = P.peak_of(lambda: rank(q, ix, limit), budget)
        print(f"        one ranking under tracemalloc: peak {pk / 1048576:.2f} MiB ({dt:.1f} s [{st2}])")
    return m


def pad(names):
    names = list(names)
    names += [f"s{i:05d}" for i in range(50000 - len(names))]
    assert len(names) == len(set(names)) == 50000, (len(names), len(set(names)))
    return names


def two_sub_tokens(length, first):
    """Every 'a' * length with exactly two substitutions from AL25 at positions i < j < first."""
    out = []
    for i in range(first):
        for j in range(i + 1, first):
            for c1 in AL25:
                for c2 in AL25:
                    t = ["a"] * length
                    t[i], t[j] = c1, c2
                    out.append("".join(t))
    return out


def pack(tokens, per, seed, head=None):
    toks = list(tokens)
    random.Random(seed).shuffle(toks)
    names = []
    for k in range(0, len(toks), per):
        part = toks[k:k + per]
        names.append("_".join(([head] if head else []) + part))
    return names


def deep40():
    """DEEP40: all 41,250 40-letter tokens with exactly 2 substitutions in their first 12 letters, 24 per name."""
    names = pad(pack(two_sub_tokens(40, 12), 24, 20261201))
    assert sum(map(len, names)) <= SCOPE37
    return names


def deep258():
    """DEEP258: all 6,250 258-letter tokens with exactly 2 substitutions in their first 5 letters, 3 per name."""
    names = pad(pack(two_sub_tokens(258, 5), 3, 20261202))
    assert sum(map(len, names)) <= SCOPE37 and max(map(len, names)) <= 1024
    return names


def w12():
    """W12: every 12-letter string with at most 2 substitutions from 'a' * 12 (41,551, 'a' * 12 included) except
    'a' * 12, 23 per name, each name led by 'a' * 12 (so every W12 name is within 1 edit of every T20 token)."""
    toks = set()
    for i in range(12):
        for c1 in AL25:
            t = ["a"] * 12
            t[i] = c1
            toks.add("".join(t))
    toks.update(two_sub_tokens(12, 12))
    names = pad(pack(sorted(toks), 23, 20261203, head="a" * 12))
    assert sum(map(len, names)) <= SCOPE37
    return names


def t_query(n, letters=AL25):
    """n distinct 11-letter tokens 'a' * 10 + c (2 allowed edits each), space-joined."""
    return " ".join("a" * 10 + c for c in letters[:n])


def runs_query(lengths):
    return " ".join("a" * k for k in lengths)


def build(lab, names):
    print(f"\n=== {lab}\n    {describe(names)}")
    dt, st, ix = P.run(lambda: build_label_index(names), 600)
    print(f"    build {dt:.2f} s [{st}]; {len(ix._tokens):,} distinct tokens; {len(ix._trie_depth):,} trie nodes; load {P.load()}")
    return ix


# ---------------------------------------------------------------- mode walk (one walk's size: the cap does not bound it)
def walk():
    header("r3 walk")
    print(f".40 as ruled: 50,000 names, <= {SCOPE40:,} characters, any query of <= 256 characters, limit <= 20, within {BOUND} s")
    ix = build("W40 (the test module's own list, w40_names())", T.w40_names())
    for lab, q in (("'a' * 40 (the test's one-token query)", "a" * 40),
                   ("'a' * 64 (the test's one-token query)", "a" * 64),
                   ("'a' * 40, 'a' * 39 (2 distinct tokens)", runs_query((40, 39))),
                   ("'a' * 40 .. 'a' * 38 (3 distinct tokens)", runs_query((40, 39, 38))),
                   ("'a' * 40 .. 'a' * 35 (6 distinct tokens, 230 chars)", runs_query(range(40, 34, -1))),
                   ("'a' * 39 + b .. g (6 distinct tokens, 245 chars)", " ".join("a" * 39 + c for c in "bcdefg"))):
        measure(lab, ix, q)
    del ix
    ix = build("DEEP40", deep40())
    for lab, q in (("'a' * 40 (1 token)", "a" * 40),
                   ("'a' * 40, 'a' * 39 (2 distinct tokens)", runs_query((40, 39))),
                   ("'a' * 40 .. 'a' * 35 (6 distinct tokens, 230 chars)", runs_query(range(40, 34, -1)))):
        measure(lab, ix, q)
    del ix
    ix = build("DEEP258", deep258())
    for lab, q in (("'a' * 256 (1 token)", "a" * 256),
                   ("'a' * 128, 'a' * 127 (2 distinct tokens)", runs_query((128, 127))),
                   ("'a' * 40 (1 token)", "a" * 40)):
        measure(lab, ix, q)
    del ix
    ix = build("W12", w12())
    for n in (1, 4, 8, 16, 20, 21):
        measure(f"T{n}: {n} distinct tokens 'a' * 10 + c", ix, t_query(n))
    del ix
    print(f"\nload after = {P.load()}")


# ---------------------------------------------------------------- mode cap (the 20 / 21 boundary on the worst list of each shape)
def cap():
    header("r3 cap")
    f = P.fixtures()
    plan = [
        ("U6 (u6_names())", T.u6_names, [("FAMQ(20)", T.fam_query(T.FAMQ, 20)), ("FAMQ(21)", T.fam_query(T.FAMQ, 21)),
                                          ("FAMQ(20) + 20 repeats (40 tokens, 20 distinct)", T.fam_query(T.FAMQ, 20) + " " + " ".join(T.FAMQ[:20]))]),
        ("D3 (d3_names())", T.d3_names, [("FAMQ(20)", T.fam_query(T.FAMQ, 20)), ("FAMQ(21)", T.fam_query(T.FAMQ, 21))]),
        ("E2 (e2_names())", T.e2_names, [("FAM6(20)", T.fam_query(T.FAM6, 20)), ("FAM6(21)", T.fam_query(T.FAM6, 21))]),
        ("CRAFT (craft_names() + 49,700 REF)", lambda: T.craft_names() + f["ref"][:49700],
         [("craft_query(20)", T.craft_query(20)), ("craft_query(21)", T.craft_query(21))]),
        ("W12", w12, [("T20", t_query(20)), ("T21", t_query(21)),
                      ("T20 + its 20 tokens again (40 tokens, 20 distinct)", t_query(20) + " " + t_query(1))]),
    ]
    for lab, maker, qs in plan:
        ix = build(lab, maker())
        for qlab, q in qs:
            assert len(q.strip(WS)) <= 256, qlab
            measure(qlab, ix, q)
        del ix
    print(f"\nload after = {P.load()}")


# ---------------------------------------------------------------- mode shapes (the round-2 shapes on the corrected code)
def shapes():
    header("r3 shapes")
    f = P.fixtures()
    u1 = [f"ab{P.b25(i, 4, T.LET25)}" for i in range(50000)]
    lists = [
        ("U1: 50,000 names 'ab' + 4 letters", u1, [(f"FAMQ({n})", T.fam_query(T.FAMQ, n)) for n in (4, 16, 20, 52, 76)]),
        ("U6", T.u6_names(), [(f"FAMQ({n})", T.fam_query(T.FAMQ, n)) for n in (4, 16, 20, 32, 76)]),
        ("M1: 25,000 U1 + 25,000 REF", u1[:25000] + f["ref"][:25000], [(f"FAMQ({n})", T.fam_query(T.FAMQ, n)) for n in (20, 76)]),
        ("D3", T.d3_names(), [(f"FAMQ({n})", T.fam_query(T.FAMQ, n)) for n in (4, 12, 20, 76)]),
        ("E2", T.e2_names(), [(f"FAM6({n})", T.fam_query(T.FAM6, n)) for n in (4, 12, 20, 24, 36)]),
        ("CRAFT", T.craft_names() + f["ref"][:49700], [(f"craft_query({n})", T.craft_query(n)) for n in (4, 8, 16, 20, 32, 51)]),
        ("BAND", T.band_names() + f["ref"][:50000 - 225], [("987654 + 248 a + b", T.BAND_HEAD + " " + "a" * 248 + "b")]),
        ("SUBO", T.subo_names(), [(repr(q), q) for q in ("a", "aa", "aaa", "aaaaaaaa")]),
    ]
    for lab, names, qs in lists:
        ix = build(lab, names)
        for qlab, q in qs:
            measure(qlab, ix, q, n=7 if lab != "SUBO" else 5)
        del ix
    print(f"\nload after = {P.load()}")


# ---------------------------------------------------------------- mode subs (the substring key, the one tier with no cap)
def subs():
    header("r3 subs")
    tag = "cdefghijklmnop"  # 14 letters, no 'a'
    tags = [P.b25(i, 5, tag) for i in range(50000)]
    lists = [
        ("SUBO (subo_names())", T.subo_names(), ["a", "aa"]),
        ("SUBL: 50,000 names 'x' + 'a' * 40 + 'Q' + 5-letter tag (2,350,000 chars)", ["x" + "a" * 40 + "Q" + t for t in tags], ["a", "aa"]),
        ("SUBU: 50,000 names 'X' + 'A' * 40 + 'Q' + 5-letter tag (upper case: the longest _at_boundary path)",
         ["X" + "A" * 40 + "Q" + t for t in tags], ["a", "A", "aa"]),
        ("SUBN: 50,000 names 'x' + U+00E9 * 40 + 'Q' + 5-letter tag (non-ASCII letters: .40 has no ASCII scope)",
         ["x" + "é" * 40 + "Q" + t for t in tags], ["é", "éé"]),
    ]
    for lab, names, qs in lists:
        ix = build(lab, names)
        for q in qs:
            measure(repr(q), ix, q, n=5)
        del ix
    print(f"\nload after = {P.load()}")


# ---------------------------------------------------------------- mode budget (nodes visited per ranking: the data for a node budget)
def budget():
    header("r3 budget")
    f = P.fixtures()
    plan = [
        ("REF", f["ref"], {**{f"QSET {i:02d}": q for i, q in enumerate(T.qset33(f["swa"], f["ref"]))}, **{f"PSET {k}": q for k, q in T.pset_ref()},
                           **{f"extra {k}": q for k, q in P.extra_shapes().items()}}),
        ("REF6", f["ref6"], {**{f"REF6Q {q}": q for q in T.REF6_QUERIES}, **{f"PSET {k}": q for k, q in T.pset_ref6(f["swa"])},
                             **{f"shape {k}": q for k, q in P.ref6_shapes(f["ref6"]).items()}}),
        ("LONG", f["long"], {**{f"LONGQ {k}": q for k, q in T.LONG_QUERIES}, **{f"shape {k}": q for k, q in P.long_shapes().items()}}),
        ("CRAFT", T.craft_names() + f["ref"][:49700], {f"craft_query({n})": T.craft_query(n) for n in (4, 20)}),
        ("U6", T.u6_names(), {"FAMQ(20)": T.fam_query(T.FAMQ, 20)}),
        ("D3", T.d3_names(), {"FAMQ(20)": T.fam_query(T.FAMQ, 20)}),
        ("E2", T.e2_names(), {"FAM6(20)": T.fam_query(T.FAM6, 20)}),
        ("BAND", T.band_names() + f["ref"][:50000 - 225], {"BAND": T.BAND_HEAD + " " + "a" * 248 + "b"}),
        ("W40", T.w40_names(), {"'a' * 40": "a" * 40, "'a' * 40 .. 'a' * 35": runs_query(range(40, 34, -1))}),
        ("W12", w12(), {"T20": t_query(20)}),
        ("DEEP40", deep40(), {"'a' * 40": "a" * 40}),
    ]
    for lab, names, qs in plan:
        ix = build_label_index(names)
        rows = []
        for qlab, q in qs.items():
            t0 = time.perf_counter()
            _, rec, _ = walks_of(ix, q)
            dt = time.perf_counter() - t0
            rows.append((sum(r[2] for r in rec), len(rec), dt, qlab))
        rows.sort(reverse=True)
        print(f"\n=== {lab}: {len(rows)} queries; nodes visited per ranking (all walks), top 5; load {P.load()}")
        for nodes, nw, dt, qlab in rows[:5]:
            print(f"     {nodes:>11,} nodes in {nw:>2} walks; instrumented ranking {dt * 1000:9.1f} ms  {qlab[:70]!r}")
        del ix
    print(f"\nload after = {P.load()}")


# ---------------------------------------------------------------- mode build37 (.37's ASCII scope; non-ASCII lists)
def _b26(i, w):
    return P.b25(i, w, LOWER)


def b4mix():
    """B4MIX: the most distinct ASCII tokens found for REF's total: every 2-, 3- and 4-letter camel token, every
    2-, 3- and 4-digit token, then 5-digit tokens up to 2,062,041 characters; no separator (camel / digit cuts)."""
    letters = [_b26(i, w).capitalize() for w in (2, 3, 4) for i in range(26 ** w)]
    digits = [f"{i:0{w}d}" for w in (2, 3, 4) for i in range(10 ** w)]
    used = sum(map(len, letters)) + sum(map(len, digits))
    digits += [f"{i:05d}" for i in range((SCOPE37 - used) // 5)]
    rng = random.Random(20261204)
    rng.shuffle(letters)
    rng.shuffle(digits)
    names = [[] for _ in range(50000)]
    for k, t in enumerate(letters):
        names[k % 50000].append(t)
    for k, d in enumerate(digits):  # a digit token only after a letter token: never two digit tokens in a row
        row = names[k % 50000]
        slot = 1 + 2 * (k // 50000)
        assert slot <= len(row)
        row.insert(slot, d)
    out = ["".join(r) for r in names]
    assert len(set(out)) == 50000 and sum(map(len, out)) <= SCOPE37 and max(map(len, out)) <= 1024
    return out, len(letters) + len(digits)


def build37():
    header("r3 build37")
    print(".37: 'a name list of 50,000 ASCII names that hold at most 2,062,041 characters in all ... at most 64 MiB'")
    f = P.fixtures()
    mix, nmix = b4mix()
    astral = []
    cp = 0x10000
    for i in range(50000):
        astral.append("_".join(chr(cp + t) for t in range(20)))
        cp += 20
    cjk = []
    v = 0
    for i in range(50000):
        toks = []
        for _ in range(12):
            toks.append(chr(0x4E00 + v % 20902) + chr(0x4E00 + (v // 20902) % 20902))
            v += 1
        cjk.append("_".join(toks))
    lat = "àáâãäåæçèéêëìíîïðñòóôõöøùúûü"
    lat1 = []
    v = 0
    for i in range(50000):
        lat1.append("_".join(P.b25(v + t, 4, lat) for t in range(8)))
        v += 8
    lists = [
        ("REF (.37/1)", f["ref"]),
        ("B4MAX (.37/2, b4max_names())", T.b4max_names()),
        (f"B4MIX ({nmix:,} distinct ASCII tokens)", mix),
        ("LAT1: 8 distinct 4-letter Latin-1 tokens per name (400,000 distinct; 1-byte strings, not ASCII)", lat1),
        ("CJK2: 12 distinct 2-letter CJK tokens per name (600,000 distinct)", cjk),
        ("AST1: 20 distinct 1-character tokens above U+FFFF per name (1,000,000 distinct)", astral),
    ]
    for lab, names in lists:
        assert len(names) == len(set(names)) == 50000, lab
        ascii_ = all(n.isascii() for n in names)
        dt, st, ix = P.run(lambda: build_label_index(names), 600)
        ntok = len(ix._tokens) if ix is not None else -1
        rk = ""
        if ix is not None:
            q = names[123][:8]
            m, st2, out = P.med(ix, q, n=3)
            rk = f"; rank({ascii(q)}) {m * 1000:.1f} ms [{st2}] listed {len(out) if out else 0}, bad spans {P.bad_spans(out)}"
        del ix
        pk, dt2, st3, ix = P.peak_of(lambda: build_label_index(names), 900)
        del ix
        chars = sum(map(len, names))
        inscope = ascii_ and chars <= SCOPE37
        print(f"  {lab}\n    {describe(names)}; in .37's scope {inscope}; build {dt:.2f} s [{st}] (raised: {st != 'ok'}); "
              f"{ntok:,} distinct tokens{rk}\n    tracemalloc peak {pk:,} B = {pk / 1048576:.1f} MiB [{st3}]"
              f"{'  > 64 MiB' if pk > 67108864 else ''}; {pk / chars:.1f} B per character; load {P.load()}")
    print(f"\nload after = {P.load()}")


# ---------------------------------------------------------------- mode check (exceptions, spans, capped oracle, paths, .41)
def capped_oracle(query, names, limit):
    """The E1 oracle with R-A2L-MATCH.41 applied: past 20 distinct query tokens a fuzzy row becomes the
    subsequence row (when the keys are a subsequence) or nothing."""
    o = P.oracle_fns()
    q = query.strip(WS)
    if limit < 1 or len(q) > P.QCAP:
        return []
    ns = _PILOT_NS()
    _, _, qtoks, keys = ns["query_parts"](query, True)
    over = len(set(qtoks)) > 20  # the oracle's own tokeniser decides the cap
    rows = []
    for name in dict.fromkeys(n for n in names if len(n) <= P.NCAP):
        ev = o["evaluate_b"](query, name)
        if ev is None:
            continue
        if over and ev[0] == 4:
            pos = ns["is_subseq"](keys, ns["fold"](name))
            if pos is None:
                continue
            ev = (5, 0, ns["merge"]([(p, p + 1) for p in pos]))
        rule, key, sp = ev
        ce = (name == q) if rule == 0 else name.startswith(q) if rule == 1 else (q in name) if rule == 2 else False
        rows.append(((rule, key, len(name), 0 if ce else 1, name), ev))
    rows.sort(key=lambda r: r[0])
    return [(k[4], o["RULES_B"][ev[0]], ev[1] if ev[0] == 4 else 0, tuple(tuple(s) for s in ev[2])) for k, ev in rows[:limit]]


_PNS = {}


def _PILOT_NS():
    if not _PNS:
        import runpy
        _PNS.update(runpy.run_path(str(P.PILOT / "i4e1-pilot3.py"), run_name="i4e1_pilot_v3"))
    return _PNS


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


def check():
    header("r3 check")
    print("=== A. hostile set (round-1 spans mode) with the R-A2L-MATCH.41-capped oracle")
    P.oracle = capped_oracle  # P.spans looks the oracle up at call time
    P.spans()

    print("\n=== B. randomized rankings: shipped == capped oracle == both forced switch paths; 15-30 distinct tokens included")
    f = P.fixtures()
    rng = random.Random(20261207)
    many = [T.CRAFT_HEAD + "".join(h.capitalize() for h in T.CRAFT_HITS[:rng.randint(3, 30)]) + P.b25(i, 3, "cdefghijklmnop").capitalize()
            for i in range(60)]
    longt = [T.BAND_HEAD + "_" + "a" * rng.randint(40, 80) + P.b25(i, 2, "cdefghijklmnop") for i in range(40)]
    w12s = rng.sample(w12()[:1807], 60)
    lists = {"HOSTILE + 250 REF + 60 many-token + 40 long-token + 60 W12": P.HOSTILE + rng.sample(f["ref"], 250) + many + longt + w12s,
             "400 REF6": rng.sample(f["ref6"], 400)}
    n_q = exc = bad = mism = path_mism = listed = over = 0
    first = []
    t0 = time.perf_counter()
    for lab, names in lists.items():
        ix = build_label_index(names)
        pool = [n for n in names if n and len(n) <= 400]
        for _ in range(400):
            parts = []
            for _ in range(rng.choice((1, 1, 2, 3, 4, 8, 16, 22, 30))):
                nm = rng.choice(pool)
                sp = lm._tokens(nm)
                if not sp:
                    continue
                s, e = rng.choice(sp)
                tok = nm[s:e][:12]
                for _ in range(rng.choice((0, 1, 1, 2))):
                    tok = mutate(rng, tok)
                parts.append(tok)
            if not parts:
                continue
            if rng.random() < 0.15:
                parts = parts * rng.randint(2, 6)
            q = rng.choice((" ", "_", "")).join(parts) if rng.random() < 0.9 else T.CRAFT_HEAD + " " + " ".join(parts)
            q = q[:256]
            pq = lm._parse_query(q.strip(WS))
            over += pq is not None and len(set(pq.tokens)) > 20
            want = capped_oracle(q, names, 20)
            for lim in (1, 20):
                n_q += 1
                try:
                    res = rank(q, ix, lim)
                    got = P.tup(res)
                    with cap_value("_FUZZY_SWITCH_CAP", 0):
                        never = P.tup(rank(q, ix, lim))
                    with cap_value("_FUZZY_SWITCH_CAP", 10 ** 9):
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
                if got != want[:lim]:
                    mism += 1
                    first.append(("oracle mismatch", lab, ascii(q[:60]), lim, got[:2], want[:2]))
    print(f"queries x limits {n_q} ({time.perf_counter() - t0:.0f} s; {over} queries past 20 distinct tokens); listed entries {listed}; "
          f"exceptions {exc}; bad spans {bad}; rank != capped oracle {mism}; shipped vs forced paths (cap 0, cap 10**9) differing {path_mism}")
    for row in first[:8]:
        print("   ", ascii(row)[:300])

    print("\n=== C. R-A2L-MATCH.41 cases on C08 (02-test-cases.md), and the cap removed (_FUZZY_TOKEN_CAP = 10**9)")
    c08 = [n for n in (P.PILOT / "case08-names.txt").read_text(encoding="utf-8").split("\n") if n]
    ix08 = build_label_index(c08)
    cases = [("/1 curva .. curvu (20 distinct), limit 3", " ".join("curv" + c for c in "abcdfghijklmnopqrstu"), 3),
             ("/2 curva .. curvv (21 distinct), limit 3", " ".join("curv" + c for c in "abcdfghijklmnopqrstuv"), 3),
             ("/3 curva twice + curvb .. curvu (21 tokens, 20 distinct), limit 3", "curva " + " ".join("curv" + c for c in "abcdfghijklmnopqrstu"), 3)]
    for lab, q, lim in cases:
        got = P.tup(rank(q, ix08, lim))
        with cap_value("_FUZZY_TOKEN_CAP", 10 ** 9):
            nocap = P.tup(rank(q, ix08, lim))
        print(f"  {lab}: shipped {ascii(got)[:160]}\n      cap removed {ascii(nocap)[:160]}")
    print(f"\nload after = {P.load()}")


# ---------------------------------------------------------------- mode det3 (the new stress shapes under each hash seed)
def det3():
    header("r3 det3")
    f = P.fixtures()
    h = hashlib.sha256()
    n = 0
    t0 = time.perf_counter()
    plan = [
        (w12()[:3000] + f["ref"][:2000], [t_query(k) for k in (1, 4, 8, 20, 21)] + ["a" * 12, "aaaaaaaaaaab_q"]),
        (T.craft_names()[:120] + f["ref"][:5000], [T.craft_query(k) for k in (4, 8, 20, 21, 51)]),
        (T.u6_names()[:6000], [T.fam_query(T.FAMQ, k) for k in (4, 20, 21, 76)]),
        (T.w40_names()[:400] + f["ref"][:3000], ["a" * 40, runs_query((40, 39, 38)), "a" * 64]),
        (deep258()[:300], ["a" * 256, runs_query((128, 127))]),
    ]
    for names, qs in plan:
        ix = build_label_index(names)
        for q in qs:
            for lim in (1, 20, 100):
                res = rank(q, ix, lim)
                h.update(repr(P.tup(res)).encode("utf-8", "surrogatepass"))
                n += 1
    print(f"PYTHONHASHSEED={os.environ.get('PYTHONHASHSEED')} hash('abc')={hash('abc')} rankings={n} sha256={h.hexdigest()} ({time.perf_counter() - t0:.0f} s)")


# ---------------------------------------------------------------- mode fixb (pilot of a fix: a node budget per ranking)
class _Over(Exception):
    pass


USED, LIMIT = [0], [0]
_NS2 = dict(lm.__dict__)
_NS2.update(_USED=USED, _LIMIT=LIMIT, _Over=_Over)
exec(compile("from __future__ import annotations\n" + _SRC.replace(
    _LOOP, _LOOP + "        _USED[0] += 1\n        if _USED[0] > _LIMIT[0]:\n            raise _Over()\n", 1),
    "<budgeted _fuzzy_token_distances>", "exec"), _NS2)
BUDGET_WALK = _NS2["_fuzzy_token_distances"]


@contextmanager
def node_budget(b):
    """Pilot: the fuzzy tier's walks of one ranking visit at most b trie nodes in all; past b the tier gives no
    fuzzy name (the R-A2L-MATCH.41 outcome). Deterministic: the count depends on the index and the query only."""
    orig_walk, orig_tier = lm._fuzzy_token_distances, lm._fuzzy_tier

    def tier(query, index, taken):
        USED[0] = 0
        try:
            return orig_tier(query, index, taken)
        except _Over:
            return {}, {}

    LIMIT[0] = b
    lm._fuzzy_token_distances, lm._fuzzy_tier = BUDGET_WALK, tier
    try:
        yield
    finally:
        lm._fuzzy_token_distances, lm._fuzzy_tier = orig_walk, orig_tier


def fixb():
    header("r3 fixb")
    f = P.fixtures()
    budgets = (200_000, 400_000, 800_000)
    keep = [
        ("REF", f["ref"], [q for q in T.qset33(f["swa"], f["ref"])] + [q for _, q in T.pset_ref()] + list(P.extra_shapes().values())),
        ("REF6", f["ref6"], list(T.REF6_QUERIES) + [q for _, q in T.pset_ref6(f["swa"])] + list(P.ref6_shapes(f["ref6"]).values())),
        ("LONG", f["long"], [q for _, q in T.LONG_QUERIES] + list(P.long_shapes().values())),
        ("CRAFT", T.craft_names() + f["ref"][:49700], [T.craft_query(n) for n in (4, 8, 16, 20)]),
        ("U6", T.u6_names(), [T.fam_query(T.FAMQ, n) for n in (4, 16, 20)]),
        ("D3", T.d3_names(), [T.fam_query(T.FAMQ, n) for n in (4, 12, 20)]),
        ("E2", T.e2_names(), [T.fam_query(T.FAM6, n) for n in (4, 12, 20)]),
        ("BAND", T.band_names() + f["ref"][:50000 - 225], [T.BAND_HEAD + " " + "a" * 248 + "b"]),
        ("W40", T.w40_names(), ["a" * 40, "a" * 64]),
    ]
    print("=== A. lists the budget must leave unchanged (fixtures, the row's cases): shipped == budgeted, per budget")
    for lab, names, qs in keep:
        ix = build_label_index(names)
        diff = {b: 0 for b in budgets}
        worst = 0
        for q in qs:
            base = P.tup(rank(q, ix, 20))
            _, rec, _ = walks_of(ix, q)
            worst = max(worst, sum(r[2] for r in rec))
            for b in budgets:
                with node_budget(b):
                    diff[b] += P.tup(rank(q, ix, 20)) != base
        print(f"  {lab:5s} {len(qs):>3} queries; most nodes in one ranking {worst:>9,}; lists changed per budget {diff}; load {P.load()}")
        del ix
    print("\n=== B. the adversarial rankings under each budget (median of 3, limit 20)")
    adv = [("W40", T.w40_names, [runs_query(range(40, 34, -1))]),
           ("DEEP40", deep40, ["a" * 40, runs_query(range(40, 34, -1))]),
           ("DEEP258", deep258, ["a" * 256]),
           ("W12", w12, [t_query(20)])]
    for lab, maker, qs in adv:
        ix = build_label_index(maker())
        for q in qs:
            for b in budgets:
                with node_budget(b):
                    m, st, out = P.med(ix, q, n=3, budget=900)
                rules = sorted({r.rule.value for r in out}) if out else "-"
                print(f"  {lab:7s} budget {b:>9,}: {m * 1000:9.1f} ms [{st}] listed {len(out) if out else 0} {rules}  {ascii(q[:24])} ({len(q)} chars)")
        del ix
    print(f"\nload after = {P.load()}")


# ---------------------------------------------------------------- mode detnocap (round-1 det with the .41 cap removed)
def detnocap():
    """The round-1 det mode with _FUZZY_TOKEN_CAP = 10**9: if its sha256 equals rounds 1 and 2 (b528ae21...844c),
    the cap is the only change of any ranked list in that set since the code under round 1."""
    header("r3 detnocap")
    with cap_value("_FUZZY_TOKEN_CAP", 10 ** 9):
        P.det()


if __name__ == "__main__":
    {"walk": walk, "cap": cap, "shapes": shapes, "subs": subs, "budget": budget, "build37": build37, "check": check,
     "det3": det3, "fixb": fixb, "detnocap": detnocap}[sys.argv[1]]()
