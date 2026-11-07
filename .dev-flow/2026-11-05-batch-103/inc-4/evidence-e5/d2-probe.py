#!/usr/bin/env python3
"""batch-103 Inc 4 E5 design-gap pass, round 2 (E5S-07, E5S-08, E5S-09). THROWAWAY EVIDENCE, NOT PRODUCT CODE.

Runs on cachyos-rtx only (python -I -B), against the REAL module s19_app/tui/services/label_match.py
(sha256 394bf2f9...) of a COPY of the read-only integrated tree (env TREE). It loads the security
round-2 probe (sec-r2-probe.py, same directory), which loads the round-1 probe, for the fixtures, the
dense lists and the timing helpers.

The pilot is the design this pass pins (graph rank step 4 and step 6, `_fuzzy_token_distances`,
`_classify`, `build_label_index`), installed by monkeypatching the module's private globals, which
`rank` looks up at call time:
  * range tables: the trie walk returns sorted, disjoint (lo, hi, d) runs of token ids; step 4 takes one
    CSR postings slice per run; a table is (los, his, ds); step 6 finds a token id's distance by bisect,
    once per distinct token id of the listed name (E5S-09 (3));
  * the cap: a query holding more than CAP_N distinct query tokens gets no fuzzy tier (the other tiers run);
  * the compact build: distinct tokens collected in a set, sorted, then each occurrence's id by bisect (no
    token -> id dict, no int objects), the dedup set dropped once used.

Modes: curve, verify <N>, build, census, beyond.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.environ["TREE"])

import bisect  # noqa: E402
import collections  # noqa: E402
import gc  # noqa: E402
import hashlib  # noqa: E402
import importlib.util  # noqa: E402
import random  # noqa: E402
import signal  # noqa: E402
import statistics  # noqa: E402
import time  # noqa: E402
from array import array  # noqa: E402
from contextlib import contextmanager  # noqa: E402
from pathlib import Path  # noqa: E402

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("sec_r2_probe", HERE / "sec-r2-probe.py")
R2 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(R2)
P = R2.P
lm, T, rank, build_label_index = P.lm, P.T, P.rank, P.build_label_index
WS = P.WS
LET = R2.LET
ORIG_FUZZY = lm._fuzzy_tier
ORIG_CLASSIFY = lm._classify
CAP_N = [10 ** 9]
TOTALS = ["py"]  # 'py': the shipped per-candidate loop; 'counter': one collections.Counter per weight (Counter.update is C-level)
OCCUR = 512  # lm._FUZZY_SWITCH_CAP


# ---------------------------------------------------------------- the pilot: range tables + the cap
def p_ranges(index, q, k):
    """The walk of lm._fuzzy_token_distances (same arithmetic), returning sorted, disjoint (lo, hi, d) runs."""
    out = []

    def emit(lo, hi, d):
        if out and out[-1][1] == lo and out[-1][2] == d:
            out[-1] = (out[-1][0], hi, d)
        else:
            out.append((lo, hi, d))

    if k == 0:
        lo, hi = lm._token_range(index._tokens, q)
        return [(lo, hi, 0)] if lo < hi else []
    chars, depth, first, end, tokens = index._trie_chars, index._trie_depth, index._trie_first, index._trie_end, index._tokens
    m = len(q)
    limit = k + 1
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
        if dep >= 2:
            prev2 = cols[dep - 2]
            pchar = prev_char[dep - 1]
            for ii in range(lo_r, hi_r + 1):
                qi = q[ii - 1]
                value = prev[ii - 1] + (0 if qi == c else 1)
                alt = prev[ii] + 1
                if alt < value:
                    value = alt
                alt = new[ii - 1] + 1
                if alt < value:
                    value = alt
                if ii > 1 and qi == pchar and q[ii - 2] == c:
                    alt = prev2[ii - 2] + 1
                    if alt < value:
                        value = alt
                if value > limit:
                    value = limit
                new[ii] = value
                if value < low:
                    low = value
        else:
            for ii in range(lo_r, hi_r + 1):
                value = prev[ii - 1] + (0 if q[ii - 1] == c else 1)
                alt = prev[ii] + 1
                if alt < value:
                    value = alt
                alt = new[ii - 1] + 1
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
                emit(first[j], first[end[j]], b2)
            j = end[j]
            continue
        cols[dep] = new
        best[dep] = b2
        prev_char[dep] = c
        if b2 <= k and len(tokens[first[j]]) == dep:
            emit(first[j], first[j] + 1, b2)
        j += 1
    return out


def p_fuzzy_tier(query, index, taken):
    """rank step 4 as this pass pins it: the cap, then the E5 posting variant with range tables."""
    counts = {}
    for token in query.tokens:
        counts[token] = counts.get(token, 0) + 1
    if len(counts) > CAP_N[0]:
        return {}, {}
    distinct = sorted(counts, key=lm._allowed_edits)
    ps, po = index._posting_starts, index._postings
    starts, ids_all, tokens = index._name_token_starts, index._name_token_ids, index._tokens
    tables = {}
    candidates = None
    totals = {}
    weights = {}  # TOTALS 'counter': weight d * count -> Counter of the names at that smallest distance (C-level counting)
    switched = False
    for token in distinct:
        allowed = lm._allowed_edits(token)
        count = counts[token]
        if (not switched and candidates is not None and len(candidates) <= OCCUR
                and sum(starts[n + 1] - starts[n] for n in candidates) <= OCCUR):
            switched = True
        if switched:
            seen = {}
            kept = set()
            for name_id in candidates:
                best = None
                for token_id in ids_all[starts[name_id]:starts[name_id + 1]]:
                    value = seen.get(token_id)
                    if value is None:
                        value = lm._prefix_distance(token, tokens[token_id], allowed)
                        seen[token_id] = value
                    if value <= allowed and (best is None or value < best):
                        best = value
                if best is not None:
                    kept.add(name_id)
                    totals[name_id] = totals.get(name_id, 0) + best * count
            ids = sorted(t for t, v in seen.items() if v <= allowed)
            tables[token] = (ids, [t + 1 for t in ids], [seen[t] for t in ids])
            candidates = kept
            if not candidates:
                return {}, tables
            continue
        runs = p_ranges(index, token, allowed)
        tables[token] = ([r[0] for r in runs], [r[1] for r in runs], [r[2] for r in runs])
        if not runs:
            return {}, tables
        layers = [set() for _ in range(allowed + 1)]
        for lo, hi, d in runs:
            layers[d].update(po[ps[lo]:ps[hi]])
        reached = layers[0].union(*layers[1:])
        if candidates is None:
            candidates = reached
            candidates.difference_update(taken)
        else:
            candidates &= reached
        if not candidates:
            return {}, tables
        lower = layers[0]
        for d in range(1, allowed + 1):
            diff = (layers[d] & candidates) - lower
            if TOTALS[0] == "counter":
                if diff:
                    weights.setdefault(d * count, collections.Counter()).update(diff)
            else:
                for name_id in diff:
                    totals[name_id] = totals.get(name_id, 0) + d * count
            if d < allowed:
                lower = lower | layers[d]
    if weights:
        return {n: totals.get(n, 0) + sum(w * c[n] for w, c in weights.items()) for n in candidates}, tables
    return {name_id: totals.get(name_id, 0) for name_id in candidates}, tables


def p_classify(query, name, rule, token_ids, tables):
    """_classify with the FUZZY branch on range tables: each distinct token id of the name looked up once per
    distinct query token (bisect over the runs), ties to the leftmost name token."""
    if rule is not lm.MatchRule.FUZZY:
        return ORIG_CLASSIFY(query, name, rule, token_ids, tables)
    name_spans = lm._tokens(name)
    first = {}
    for pos, tid in enumerate(token_ids):
        if tid not in first:
            first[tid] = pos
    spans = []
    for qt in dict.fromkeys(query.tokens):
        table = tables.get(qt)
        if table is None:
            raise ValueError(f"fuzzy: {name!r} does not meet its tier")
        los, his, ds = table
        best = best_pos = None
        for tid, pos in first.items():
            i = bisect.bisect_right(los, tid) - 1
            if i >= 0 and tid < his[i]:
                v = ds[i]
                if best is None or v < best or (v == best and pos < best_pos):
                    best, best_pos = v, pos
        if best is None:
            raise ValueError(f"fuzzy: {name!r} does not meet its tier")
        spans.append(name_spans[best_pos])
    return lm._join_spans(spans)


@contextmanager
def pilot(cap):
    old = CAP_N[0]
    CAP_N[0] = cap
    lm._fuzzy_tier, lm._classify = p_fuzzy_tier, p_classify
    try:
        yield
    finally:
        lm._fuzzy_tier, lm._classify = ORIG_FUZZY, ORIG_CLASSIFY
        CAP_N[0] = old


@contextmanager
def nofuzzy():
    lm._fuzzy_tier = lambda q, i, t: ({}, {})
    try:
        yield
    finally:
        lm._fuzzy_tier = ORIG_FUZZY


# ---------------------------------------------------------------- lists and queries
FAMQ = ["abq"] + [t for t in R2.FAM3 if t != "abq"]  # 76 distinct 3-letter tokens; 'abq' starts no name token
assert len(FAMQ) == 76 and len(set(FAMQ)) == 76


def famq(n):
    return R2.fam_query(FAMQ, n)


def d3():
    """D3: the densest postings shape found for one 1-edit 3-letter query token: names of the 25 camel tokens
    'Ab' + c (c in LET, 3 characters per posting) and a decimal tag, padded with 's' + number names."""
    body = "".join("Ab" + c for c in LET)
    k = 27000
    dense = [body + str(i) for i in range(k)]
    pad = [f"s{i:05d}" for i in range(50000 - k)]
    names = dense + pad
    assert len(set(names)) == 50000 and sum(map(len, names)) <= 2356624
    return names


def lists_fuzzy():
    f = P.fixtures()
    out = {"REF": f["ref"], "REF6": f["ref6"], "LONG": f["long"],
           "CRAFT": T.craft_names() + f["ref"][:49700]}
    bn = T.band_names()
    out["BAND"] = bn + f["ref"][:50000 - len(bn)]
    dl = R2.dense_lists()
    keys = list(dl)
    out["U1"], out["U6"], out["S1"], out["E2"] = dl[keys[0]], dl[keys[1]], dl[keys[2]], dl[keys[3]]
    out["M1"] = out["U1"][:25000] + f["ref"][:25000]
    out["D3"] = d3()
    head = T.CRAFT_HEAD
    big = [head + "Ab" * 300 + P.b25(i, 3, "cdefghijklmnop").capitalize() for i in range(2)]
    dense = [f"ab{P.b25(i, 4, LET)}" for i in range(49998)]
    out["SWC"] = big + dense
    big40 = [head + "Ab" * 507 + P.b25(i, 3, "cdefghijklmnop").capitalize() for i in range(40)]
    out["X40"] = big40 + f["ref"][:50000 - 40]
    seq = ["ab" * 130 + "z" + P.b25(i, 4, "cdefghijklmnop") for i in range(7900)]
    out["SEQ"] = seq + [f"s{i:05d}" for i in range(42100)]
    for lab, names in out.items():
        assert len(names) == len(set(names)) == 50000 and sum(map(len, names)) <= 2356624, lab
    return out


NS = (4, 6, 8, 10, 12, 16, 24, 32, 52, 76)


def queries_for(lab, f):
    if lab == "REF":
        return [(f"QSET {i}", q) for i, q in enumerate(T.qset33(f["swa"], f["ref"]))] + [(f"PSET {a}", q) for a, q in T.pset_ref()]
    if lab == "REF6":
        return [(f"REF6Q {q}", q) for q in T.REF6_QUERIES] + [(f"PSET6 {a}", q) for a, q in T.pset_ref6(f["swa"])]
    if lab == "LONG":
        return [(f"LONGQ {a}", q) for a, q in T.LONG_QUERIES] + [(f"LONGX {a}", q) for a, q in P.long_shapes().items()]
    if lab == "CRAFT":
        return [(f"CRAFT {n} tokens", T.craft_query(n)) for n in (4, 6, 8, 10, 12, 16, 32, 51)]
    if lab == "BAND":
        h = T.BAND_HEAD
        return [("BAND .40/4", h + " " + "a" * 248 + "b"), ("BAND head + 249 a", h + " " + "a" * 249),
                ("BAND head + 249 b", h + " " + "b" * 249), ("BAND two ~124", h + " " + "a" * 120 + "b " + "a" * 126 + "c")]
    if lab == "E2":
        return [(f"FAM6 {n}", R2.fam_query(R2.FAM6, n)) for n in (4, 6, 8, 10, 12, 24, 36)]
    if lab == "SEQ":
        words = ["a", "b"] + ["".join(w) for k in (2, 3, 4, 5) for w in __import__("itertools").product("ab", repeat=k)]
        return [("SEQ reviewer 255", "ab" * 125 + "zzzzz"), ("SEQ reviewer 125", "ab" * 60 + "zzzzz"),
                ("SEQ {a,b} words", " ".join(words)[:256])]
    if lab in ("SWC", "X40"):
        return [(f"head + FAM3 {n - 1}", T.CRAFT_HEAD + " " + R2.fam_query(R2.FAM3, n - 1)) for n in NS]
    return [(f"FAMQ {n}", famq(n)) for n in NS]


def ndistinct(q):
    parsed = lm._parse_query(q.strip(WS))
    return 0 if parsed is None else len(set(parsed.tokens))


def med(ix, q, n, limit=20, budget=300):
    m, st, out = P.med(ix, q, limit=limit, n=n, budget=budget)
    return m, st, out


def tup(out):
    return None if out is None else P.tup(out)


# ---------------------------------------------------------------- mode curve
HEAVY = {"U1", "U6", "S1", "E2", "M1", "D3", "SWC", "X40"}


def curve(totals="py", only=""):
    TOTALS[0] = totals
    P.header(f"d2 curve totals={totals} lists={only or 'all'}")
    print("per query: P = pilot uncapped (range tables, cap off); F = pilot with the fuzzy tier left out (cap 0);"
          " S = shipped rank (dict tables), run only where cheap; medians of 3, limit 20")
    f = P.fixtures()
    worst = collections.defaultdict(float)
    mism = 0
    for lab, names in lists_fuzzy().items():
        if only and lab not in only.split(","):
            continue
        t0 = time.perf_counter()
        ix = build_label_index(names)
        print(f"\n=== {lab}: {R2.describe(names)}; "
              f"{len(ix._tokens):,} distinct tokens, {len(ix._postings):,} postings; built in {time.perf_counter() - t0:.2f} s; load {P.load()}")
        for qlab, q in queries_for(lab, f):
            nd = ndistinct(q)
            with pilot(10 ** 9):
                tp, sp, op = med(ix, q, 3)
            with pilot(0):
                tf, sf, of = med(ix, q, 3)
            with nofuzzy():
                _, _, on = med(ix, q, 1)
            run_shipped = lab not in HEAVY or nd <= 16
            if run_shipped:
                ts, ss, os_ = med(ix, q, 3)
                eq = tup(op) == tup(os_)
            else:
                ts, ss, eq = float("nan"), "skipped", "n/a"
            eqf = tup(of) == tup(on)
            mism += (eq is False) + (not eqf)
            worst[(lab, nd)] = max(worst[(lab, nd)], tp)
            print(f"  n={nd:>3}  P {tp * 1000:8.1f} ms [{sp}]  F {tf * 1000:8.1f} ms [{sf}]  S {ts * 1000:8.1f} ms [{ss}]  "
                  f"P==S {eq}  F==S-without-fuzzy {eqf}  listed {len(op) if op else 0} {sorted({m.rule.value for m in op}) if op else '-'}  {qlab[:60]}")
            if lab == "X40":
                with pilot(10 ** 9):
                    t40, s40, o40 = med(ix, q, 3, limit=40)
                print(f"         limit 40: P {t40 * 1000:8.1f} ms [{s40}] listed {len(o40) if o40 else 0}")
        del ix
        gc.collect()
    print(f"\nmismatches (P != S where S ran, or F != S-without-fuzzy): {mism}")
    print(f"load after = {P.load()}")


# ---------------------------------------------------------------- mode verify <N>
def verify(cap, totals="counter"):
    TOTALS[0] = totals
    P.header(f"d2 verify N={cap} totals={totals}")
    print(f"pilot with the cap N = {cap} (a query of more than {cap} distinct query tokens gets no fuzzy tier); "
          "median of 7 consecutive rankings, limit 20 (X40 also limit 40); every list's every query")
    f = P.fixtures()
    rows = []
    for lab, names in lists_fuzzy().items():
        ix = build_label_index(names)
        print(f"\n=== {lab}: {R2.describe(names)}; load {P.load()}")
        for qlab, q in queries_for(lab, f):
            with pilot(cap):
                t, st, out = med(ix, q, 7)
            rows.append((t, lab, qlab, ndistinct(q)))
            print(f"  {t * 1000:8.1f} ms [{st}] n={ndistinct(q):>3} listed {len(out) if out else 0} "
                  f"{sorted({m.rule.value for m in out}) if out else '-'} bad spans {P.bad_spans(out)}  {qlab[:60]}")
            if lab == "X40":
                with pilot(cap):
                    t, st, out = med(ix, q, 7, limit=40)
                rows.append((t, lab, qlab + " limit 40", ndistinct(q)))
                print(f"  {t * 1000:8.1f} ms [{st}] limit 40 listed {len(out) if out else 0}")
        if lab in ("D3", "U6", "U1"):
            for n in (cap, 76):
                q = famq(n)
                with pilot(cap):
                    pk, dt, st, _ = P.peak_of(lambda: rank(q, ix, 20), 600)
                print(f"  one ranking under tracemalloc, FAMQ {n}: peak {pk / 1048576:.2f} MiB ({dt:.2f} s [{st}])")
            print("  negative controls:")
            q76 = famq(76)
            with pilot(10 ** 9):
                t, st, _ = med(ix, q76, 3)
            print(f"    cap removed (range tables kept), FAMQ 76: median of 3 {t * 1000:.1f} ms [{st}]{'  > 1.0 s: RED' if t > 1.0 else ''}"
                  f"{'  > 2.0 s: RED under CI x 2' if t > 2.0 else ''}")
            qn = famq(cap)
            t, st, _ = med(ix, qn, 3)
            print(f"    the shipped dict tables (rank as shipped, no cap), FAMQ {cap}: median of 3 {t * 1000:.1f} ms [{st}]"
                  f"{'  > 1.0 s: RED' if t > 1.0 else ''}")
        del ix
        gc.collect()
    rows.sort(reverse=True)
    print("\nworst 12 medians:")
    for t, lab, qlab, nd in rows[:12]:
        print(f"  {t * 1000:8.1f} ms  {lab}  n={nd}  {qlab[:60]}")
    print(f"load after = {P.load()}")


# ---------------------------------------------------------------- mode build (.35 / .37)
def p_build(names):
    """build_label_index with the compact staging (E5S-08): no token -> id dict, ids by bisect."""
    if isinstance(names, (str, bytes)):
        raise TypeError(f"label names must be an iterable of str, got {type(names).__name__}")
    uniq = []
    seen = set()
    for name in names:
        if not isinstance(name, str):
            raise TypeError(f"label names must be str, got {type(name).__name__}")
        if len(name) > 1024:
            continue
        if name not in seen:
            seen.add(name)
            uniq.append(name)
    del seen
    names_tuple = tuple(uniq)
    del uniq
    count = len(names_tuple)
    folded = tuple(lm._fold(name) for name in names_tuple)
    masks = array("Q", (lm._char_mask(text) for text in folded))
    distinct = set()
    for i in range(count):
        text = folded[i]
        for start, end in lm._tokens(names_tuple[i]):
            distinct.add(text[start:end])
    tokens = sorted(distinct)
    del distinct
    tokens = tuple(tokens)
    name_token_ids = array("I")
    name_token_starts = array("I", [0])
    find = bisect.bisect_left
    for i in range(count):
        text = folded[i]
        for start, end in lm._tokens(names_tuple[i]):
            name_token_ids.append(find(tokens, text[start:end]))
        name_token_starts.append(len(name_token_ids))
    ntok = len(tokens)
    posting_starts = array("I", [0]) * (ntok + 1)
    for i in range(count):
        for token_id in set(name_token_ids[name_token_starts[i]:name_token_starts[i + 1]]):
            posting_starts[token_id + 1] += 1
    for token_id in range(ntok):
        posting_starts[token_id + 1] += posting_starts[token_id]
    postings = array("I", [0]) * posting_starts[ntok]
    cursor = array("I", posting_starts)
    for i in range(count):
        for token_id in set(name_token_ids[name_token_starts[i]:name_token_starts[i + 1]]):
            postings[cursor[token_id]] = i
            cursor[token_id] += 1
    del cursor
    trie_chars, trie_depth, trie_first, trie_end = lm._build_trie(tokens)
    return lm.LabelIndex(names=names_tuple, _folded=folded, _masks=masks, _tokens=tokens,
                         _name_token_ids=name_token_ids, _name_token_starts=name_token_starts,
                         _postings=postings, _posting_starts=posting_starts, _trie_chars=trie_chars,
                         _trie_depth=trie_depth, _trie_first=trie_first, _trie_end=trie_end)


def p_build2(names):
    """The compact build, one tokenising pass: pass 1 keeps every token's (start, end) in two flat array('I')
    buffers (8 bytes per occurrence) beside the distinct set; pass 2 slices and bisects from them."""
    if isinstance(names, (str, bytes)):
        raise TypeError(f"label names must be an iterable of str, got {type(names).__name__}")
    uniq = []
    seen = set()
    for name in names:
        if not isinstance(name, str):
            raise TypeError(f"label names must be str, got {type(name).__name__}")
        if len(name) > 1024:
            continue
        if name not in seen:
            seen.add(name)
            uniq.append(name)
    del seen
    names_tuple = tuple(uniq)
    del uniq
    count = len(names_tuple)
    folded = tuple(lm._fold(name) for name in names_tuple)
    masks = array("Q", (lm._char_mask(text) for text in folded))
    distinct = set()
    add = distinct.add
    span_start = array("I")
    span_end = array("I")
    name_token_starts = array("I", [0])
    for i in range(count):
        text = folded[i]
        for start, end in lm._tokens(names_tuple[i]):
            add(text[start:end])
            span_start.append(start)
            span_end.append(end)
        name_token_starts.append(len(span_start))
    del add  # the bound method holds the set: without this the set outlives `del distinct` (the first p_build2 run)
    tokens = sorted(distinct)
    del distinct
    tokens = tuple(tokens)
    find = bisect.bisect_left
    name_token_ids = array("I", [0]) * len(span_start)
    for i in range(count):
        text = folded[i]
        for j in range(name_token_starts[i], name_token_starts[i + 1]):
            name_token_ids[j] = find(tokens, text[span_start[j]:span_end[j]])
    del span_start, span_end
    ntok = len(tokens)
    posting_starts = array("I", [0]) * (ntok + 1)
    for i in range(count):
        for token_id in set(name_token_ids[name_token_starts[i]:name_token_starts[i + 1]]):
            posting_starts[token_id + 1] += 1
    for token_id in range(ntok):
        posting_starts[token_id + 1] += posting_starts[token_id]
    postings = array("I", [0]) * posting_starts[ntok]
    cursor = array("I", posting_starts)
    for i in range(count):
        for token_id in set(name_token_ids[name_token_starts[i]:name_token_starts[i + 1]]):
            postings[cursor[token_id]] = i
            cursor[token_id] += 1
    del cursor
    trie_chars, trie_depth, trie_first, trie_end = lm._build_trie(tokens)
    return lm.LabelIndex(names=names_tuple, _folded=folded, _masks=masks, _tokens=tokens,
                         _name_token_ids=name_token_ids, _name_token_starts=name_token_starts,
                         _postings=postings, _posting_starts=posting_starts, _trie_chars=trie_chars,
                         _trie_depth=trie_depth, _trie_first=trie_first, _trie_end=trie_end)


FIELDS = ("names", "_folded", "_masks", "_tokens", "_name_token_ids", "_name_token_starts", "_postings",
          "_posting_starts", "_trie_chars", "_trie_depth", "_trie_first", "_trie_end")


def b26(v, width, al="abcdefghijklmnopqrstuvwxyz"):
    out = []
    for _ in range(width):
        v, r = divmod(v, len(al))
        out.append(al[r])
    return "".join(out)


def lists_build():
    f = P.fixtures()
    al = P.LOWER
    out = {"REF (the row's fixture)": f["ref"]}
    v = 0
    b4 = []
    for _ in range(50000):
        b4.append("_".join(P.b25(v + t, 4, al) for t in range(8)))
        v += 8
    out["B4: 8 distinct 4-letter tokens per name, '_'-joined"] = b4
    v = 0
    b4c = []
    for _ in range(50000):
        b4c.append("".join(P.b25(v + t, 4, al).capitalize() for t in range(9)))
        v += 9
    out["B4c: 9 distinct 4-letter camel tokens per name (the reviewer's 65.9 MiB list)"] = b4c
    u6 = R2.dense_lists()[list(R2.dense_lists())[1]]
    out["U6: 6 distinct 'ab'+4-letter tokens per name"] = u6
    toks = [b26(i, 4) for i in range(26 ** 4)] + [b26(i, 5) for i in range(500000 - 26 ** 4)]
    random.Random(20261109).shuffle(toks)
    bmax = ["".join(t.capitalize() for t in toks[i * 10:(i + 1) * 10]) for i in range(50000)]
    out["B4max: 10 distinct camel tokens per name, 500,000 distinct (all 456,976 4-letter + 43,024 5-letter)"] = bmax
    cjk = [chr(c) for c in range(0x4E00, 0x4E00 + 800)]
    pairs = [a + b for a in cjk for b in cjk]
    random.Random(20261110).shuffle(pairs)
    na = ["0".join(pairs[i * 12:(i + 1) * 12]) for i in range(50000)]
    out["NA2: non-ASCII, 12 distinct 2-letter CJK tokens per name, '0'-joined (600,000 distinct)"] = na
    out["NA2h: the first 25,000 NA2 names"] = na[:25000]
    out["NA2q: the first 12,500 NA2 names"] = na[:12500]
    for lab, names in out.items():
        assert len(names) == len(set(names)), lab
    return out


def build(variant="both"):
    P.header(f"d2 build {variant}")
    print(".35 / .37 scope today: 50,000 names that hold at most 2,062,041 characters in all (REF's total)")
    print(f"S = shipped build_label_index; C = compact build ({'p_build: two tokenising passes' if variant == 'both' else 'p_build2: one tokenising pass, flat span buffers'}); time = median of 3 builds; peak = one build under tracemalloc")
    for lab, names in lists_build().items():
        chars = sum(map(len, names))
        ascii_ = all(max(map(ord, n)) < 128 for n in names if n)
        res = {}
        pairs = (("S", build_label_index), ("C", p_build)) if variant == "both" else (("S", build_label_index), ("C", p_build2))
        if variant != "both" and lab.startswith(("B4:", "U6", "NA2q")):
            continue
        for tag, fn in pairs:
            times = []
            for _ in range(3):
                dt, st, ix = P.run(lambda: fn(names), 300)
                times.append(dt)
                del ix
            gc.collect()
            pk, dt, st, ix = P.peak_of(lambda: fn(names), 600)
            res[tag] = (statistics.median(times), pk, ix)
        same = all(getattr(res["S"][2], fld) == getattr(res["C"][2], fld) for fld in FIELDS)
        ntok = len(res["C"][2]._tokens)
        print(f"\n  {lab}\n    {len(names):,} names, {chars:,} characters, ASCII {ascii_}, {ntok:,} distinct tokens; load {P.load()}")
        print(f"    sha256 of the names joined by newline: {hashlib.sha256(chr(10).join(names).encode('utf-8')).hexdigest()}; names 0-1: {names[:2]}")
        for tag in ("S", "C"):
            t, pk, _ = res[tag]
            print(f"    {tag}: build median {t:.2f} s{'  > 5.0 s' if t > 5.0 else ''}; peak {pk:,} B = {pk / 1048576:.1f} MiB"
                  f"{'  > 64 MiB' if pk > 67108864 else ''}; {pk / chars:.1f} B per character")
        print(f"    S and C give equal indexes (all {len(FIELDS)} fields): {same}")
        del res
        gc.collect()
    print(f"\nload after = {P.load()}")


# ---------------------------------------------------------------- mode census (share of names past N)
def census():
    P.header("d2 census")
    from s19_app.tui.a2l import parse_a2l_file
    roots = {"fixtures (35 tracked)": Path(os.environ["CORPUS"]) / "fixtures",
             "public corpus": Path(os.environ["CORPUS"]) / "files"}
    ns = (4, 5, 6, 7, 8, 9, 10, 12, 14, 16, 20, 24, 32)
    for lab, root in roots.items():
        files = sorted(root.glob("*.a2l"), key=lambda p: int(p.stem) if p.stem.isdigit() else 10 ** 9)
        seen_sha = {}
        hist = collections.Counter()
        names_total = over256 = noparse = nonascii = errors = 0
        top = []
        for path in files:
            sha = hashlib.sha256(path.read_bytes()).hexdigest()
            if sha in seen_sha:
                continue
            seen_sha[sha] = path.name
            signal.alarm(900)
            try:
                tags = parse_a2l_file(path)["tags"]
            except Exception as e:  # noqa: BLE001 - counted, the census goes on
                errors += 1
                print(f"  {path.name}: reader error {type(e).__name__}")
                continue
            finally:
                signal.alarm(0)
            fmax = 0
            for name in dict.fromkeys(t.get("name") for t in tags if isinstance(t.get("name"), str)):
                names_total += 1
                if any(ord(c) > 127 for c in name):
                    nonascii += 1
                q = name.strip(WS)
                if len(q) > 256:
                    over256 += 1
                    continue
                parsed = lm._parse_query(q)
                if parsed is None:
                    noparse += 1
                    continue
                nd = len(set(parsed.tokens))
                hist[nd] += 1
                fmax = max(fmax, nd)
            top.append((fmax, path.name))
        ranked = sum(hist.values())
        print(f"\n=== {lab}: {len(seen_sha)} distinct files of {len(files)}; {names_total:,} distinct names per file, summed; "
              f"reader errors {errors}; names over 256 characters {over256}; no letter or digit {noparse}; non-ASCII names {nonascii}")
        print(f"    distinct query tokens per name (as a query): max {max(hist) if hist else 0}, median "
              f"{statistics.median(sorted(hist.elements())) if hist else 0}")
        for n in ns:
            past = sum(c for k, c in hist.items() if k > n)
            print(f"    more than {n:>2} distinct tokens: {past:>8,} of {ranked:,} names = {past / ranked * 100:7.3f} %")
        top.sort(reverse=True)
        print(f"    files with the most distinct tokens in one name: {top[:6]}")
        print("    histogram (distinct tokens: names):", dict(sorted(hist.items())))
    print(f"\nload after = {P.load()}")


# ---------------------------------------------------------------- mode beyond (shapes in .40's scope that no cap N reaches)
def beyond(cap, *_):
    P.header(f"d2 beyond N={cap}")
    print("shapes inside .40's scope (50,000 names, <= 2,356,624 characters, queries <= 256) whose cost does not depend on N")
    al = "bcdefghijklmnoprstuvwxyz"
    pad = [f"s{i:05d}" for i in range(50000)]

    def show(lab, names, qs):
        names = names + pad[: 50000 - len(names)]
        assert len(set(names)) == 50000 and sum(map(len, names)) <= 2356624, lab
        ix = build_label_index(names)
        print(f"\n=== {lab}: {R2.describe(names)}; {len(ix._tokens):,} distinct tokens, {len(ix._trie_depth):,} trie nodes; load {P.load()}")
        for q in qs:
            t, st, out = med(ix, q, 3)
            with pilot(cap):
                tp, sp, _ = med(ix, q, 3)
            print(f"  shipped {t * 1000:9.1f} ms [{st}] | pilot N={cap} {tp * 1000:9.1f} ms [{sp}]  listed {len(out) if out else 0} "
                  f"{sorted({m.rule.value for m in out}) if out else '-'}  query {q[:24]!r}... ({len(q)} characters, {ndistinct(q)} distinct tokens)"
                  f"{'  > 1.0 s' if t > 1.0 else '  > 0.5 s' if t > 0.5 else ''}")
        return ix

    # W16: every 16-letter token 'a' * 16 with two substitutions (positions i < j, letters of al): one 2-edit
    # query token 'a' * 16 walks the whole trie (each node within 2 edits), the cap does not apply (1 token)
    toks = [("a" * i + x + "a" * (j - i - 1) + y + "a" * (15 - j)) for i in range(16) for j in range(i + 1, 16) for x in al for y in al]
    w16 = ["_".join(toks[k:k + 60]) for k in range(0, len(toks), 60)]
    show("W16: 16-letter tokens within 2 substitutions of 'a' * 16, 60 per name", w16, ["a" * 16, "a" * 15 + "q", "aaaaaa"])
    rng = random.Random(20261111)
    toks = set()
    while len(toks) < 50016:
        i, j = sorted(rng.sample(range(40), 2))
        toks.add("a" * i + rng.choice(al) + "a" * (j - i - 1) + rng.choice(al) + "a" * (39 - j))
    toks = sorted(toks)
    rng.shuffle(toks)
    w40 = ["_".join(toks[k:k + 24]) for k in range(0, len(toks), 24)]
    show("W40: 40-letter tokens within 2 substitutions of 'a' * 40, 24 per name", w40, ["a" * 40, "a" * 64])
    # SUBO: the substring key loop: 'aa' occurs 1,016 times in each long name, never at a boundary offset
    subo = ["x" + "a" * 1017 + "Q" + P.b25(i, 4, "cdefghijklmnop") for i in range(2000)]
    show("SUBO: 2,000 names 'x' + 'a' * 1017 + 'Q' + tag (overlapping substring occurrences)", subo, ["aa", "aaa", "aaaaaaaa"])
    subr = ["x" + "ab" * 509 + "Q" + P.b25(i, 4, P.LOWER) for i in range(2000)]
    show("SUBR: the reviewer's substring shape, 'x' + 'ab' * 509 + 'Q' + tag", subr, ["ba"])
    print(f"\nload after = {P.load()}")


# ---------------------------------------------------------------- mode capedge <N> (queries of exactly N and N + 1 distinct tokens)
def capedge(cap, *_):
    P.header(f"d2 capedge N={cap}")
    print(f"pilot cap N = {cap}; each query holds exactly n distinct query tokens; median of 7, limit 20")
    f = P.fixtures()
    lists = lists_fuzzy()
    u6 = lists["U6"]
    print(f"U6 sha256 of the 50,000 names joined by newline: {hashlib.sha256(chr(10).join(u6).encode()).hexdigest()}; "
          f"{sum(map(len, u6)):,} characters; names 0-1: {u6[:2]}")
    for lab in ("U6", "D3", "U1", "E2", "M1", "S1", "CRAFT", "SWC", "X40"):
        ix = build_label_index(lists[lab])
        print(f"\n=== {lab}: load {P.load()}")
        for n in (cap - 4, cap, cap + 1):
            if lab == "E2":
                q = R2.fam_query(R2.FAM6, n)
            elif lab == "CRAFT":
                q = T.craft_query(n)
            elif lab in ("SWC", "X40"):
                q = T.CRAFT_HEAD + " " + R2.fam_query(R2.FAM3, n - 1)
            else:
                q = famq(n)
            assert ndistinct(q) == n, (lab, n, ndistinct(q))
            with pilot(cap):
                t, st, out = med(ix, q, 7)
            print(f"  {t * 1000:8.1f} ms [{st}] n={n:>3} ({len(q)} characters) listed {len(out) if out else 0} "
                  f"{sorted({m.rule.value for m in out}) if out else '-'} edits {sorted({m.edits for m in out}) if out else '-'}")
        del ix
        gc.collect()
    print(f"\nload after = {P.load()}")


# ---------------------------------------------------------------- mode examples <N> (graph examples, the new cases' values)
def notation(rows):
    out = []
    for m in rows:
        e = f" · e{m.edits}" if m.rule is lm.MatchRule.FUZZY else ""
        out.append(f"{m.name} · {m.rule.value} · {','.join(f'({s},{t})' for s, t in m.spans)}{e}")
    return "[" + "; ".join(out) + "]"


def examples(cap, *_):
    P.header(f"d2 examples N={cap}")
    c08 = [ln.strip() for ln in (Path(os.environ["PILOT_DIR"]) / "case08-names.txt").read_text(encoding="utf-8").splitlines() if ln.strip()]
    print(f"C08: {len(c08)} names from pilot/case08-names.txt (sha256 {hashlib.sha256(chr(10).join(c08).encode()).hexdigest()[:16]})")
    ix = build_label_index(c08)
    tok = ix._tokens
    print("\n_fuzzy_token_distances as runs (ids written as their tokens: first .. last, count, d) vs the shipped dict")
    for q, k in (("cuvre", 1), ("mpa", 1), ("maesu", 1), ("vblk", 1), ("valu", 1), ("cvure", 1), ("0300", 0), ("va", 0), ("0", 0)):
        runs = p_ranges(ix, q, k)
        shipped = lm._fuzzy_token_distances(ix, q, k)
        expanded = {t: d for lo, hi, d in runs for t in range(lo, hi)}
        print(f"  C08 {q!r} {k}: runs {[(tok[lo], tok[hi - 1], hi - lo, d) for lo, hi, d in runs]}; raw {runs}; equals the dict: {expanded == shipped}")
    cu = build_label_index(["CUVE", "CURVE_0001"])
    runs = p_ranges(cu, "curvee", 2)
    print(f"  [CUVE, CURVE_0001] 'curvee' 2: runs {[(cu._tokens[lo], cu._tokens[hi - 1], hi - lo, d) for lo, hi, d in runs]}; "
          f"equals the dict: {({t: d for lo, hi, d in runs for t in range(lo, hi)}) == lm._fuzzy_token_distances(cu, 'curvee', 2)}")
    f = P.fixtures()
    ref_ix = build_label_index(f["ref"])
    rng = random.Random(20261112)
    qtoks = sorted({t for q in T.qset33(f["swa"], f["ref"]) for t in (lm._parse_query(q.strip(WS)) or lm._Query("", (), "")).tokens})
    qtoks += [R2.mutate(rng, rng.choice(ref_ix._tokens)) for _ in range(300)]
    bad = 0
    for q in qtoks:
        if not q:
            continue
        k = lm._allowed_edits(q)
        runs = p_ranges(ref_ix, q, k)
        exp = {t: d for lo, hi, d in runs for t in range(lo, hi)}
        ok = exp == lm._fuzzy_token_distances(ref_ix, q, k) and all(runs[i][1] <= runs[i + 1][0] for i in range(len(runs) - 1))
        bad += not ok
    print(f"  REF: {len(qtoks)} query tokens (QSET's and 300 one-edit mutations of REF tokens): runs sorted, disjoint and equal to the dict: {len(qtoks) - bad} / {len(qtoks)}")

    print(f"\nR-A2L-MATCH.41 cases (pilot cap N = {cap}) and their negative control (shipped rank, no cap)")
    variants = ["curv" + c for c in P.LOWER if c != "e"]
    q1 = " ".join(variants[:cap])
    q2 = " ".join(variants[:cap + 1])
    q3 = " ".join([variants[0]] + variants[:cap])
    for lab, q, lim in (("/1 N distinct", q1, 3), ("/2 N + 1 distinct", q2, 3), ("/3 N distinct, N + 1 tokens", q3, 3)):
        with pilot(cap):
            got = rank(q, ix, lim)
        shipped = rank(q, ix, lim)
        print(f"  {lab}: C08, {q!r} ({len(q)} characters, {ndistinct(q)} distinct), limit {lim}\n      pilot   {notation(got)}\n      shipped {notation(shipped)}")
    swa_ix = build_label_index(f["swa"])
    best = min(f["swa"], key=lambda n: (-ndistinct(n), n))
    parsed = lm._parse_query(best)
    q5 = " ".join(reversed(parsed.tokens))
    for lab, q in (("/4 the SWA name with the most distinct tokens, whole", best), ("/5 its tokens in reverse order", q5)):
        with pilot(cap):
            got = rank(q, swa_ix, 5)
        with nofuzzy():
            nof = rank(q, swa_ix, 5)
        shipped = rank(q, swa_ix, 5)
        print(f"  {lab}: SWA, {q!r} ({len(q)} characters, {ndistinct(q)} distinct), limit 5\n      pilot   {notation(got)}\n"
              f"      pilot == shipped-without-fuzzy {P.tup(got) == P.tup(nof)}; shipped {notation(shipped)}")
    u6n = R2.dense_lists()[list(R2.dense_lists())[1]]
    u6_ix = build_label_index(u6n)
    for n in (cap, 76):
        q = famq(n)
        with pilot(cap):
            got = rank(q, u6_ix, 20)
        print(f"  .40/5 U6 FAMQ {n} ({len(q)} characters): {len(got)} entries, rules {sorted({m.rule.value for m in got})}, "
              f"edits {sorted({m.edits for m in got})}, first {notation(got[:1])}; query {q[:40]!r}...")
    d3n = d3()
    d3_ix = build_label_index(d3n)
    for n in (cap, 76):
        q = famq(n)
        with pilot(cap):
            got = rank(q, d3_ix, 20)
        print(f"  .40/5 DENSE FAMQ {n} ({len(q)} characters): {len(got)} entries, rules {sorted({m.rule.value for m in got})}, "
              f"edits {sorted({m.edits for m in got})}, first {notation(got[:1])}")
    print(f"  DENSE: {len(d3n):,} names, {sum(map(len, d3n)):,} characters, sha256 {hashlib.sha256(chr(10).join(d3n).encode()).hexdigest()}; "
          f"{len(d3_ix._tokens):,} distinct tokens, {len(d3_ix._postings):,} postings")
    print(f"\nload after = {P.load()}")


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode in ("verify", "beyond", "examples", "capedge"):
        TOTALS[0] = "counter"
        {"verify": verify, "beyond": beyond, "examples": examples, "capedge": capedge}[mode](int(sys.argv[2]), *sys.argv[3:])
    elif mode == "curve":
        curve(*sys.argv[2:])
    elif mode == "build":
        build(*sys.argv[2:])
    else:
        {"census": census}[mode]()
