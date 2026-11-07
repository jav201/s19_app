#!/usr/bin/env python3
"""batch-103 Inc 4 E5 design-gap correction probe (E5S-01, E5S-02). THROWAWAY EVIDENCE, NOT PRODUCT CODE.

Runs on <runner> only, against the REAL module s19_app/tui/services/label_match.py of a
read-only COPY of the integrated tree (env TREE, first on PYTHONPATH). The fixtures and the
crafted list are those of evidence-e5/sec-e5-probe.py (loaded with runpy, unchanged), so the
strings are identical to the E5 security review's.

rank_v is a copy of label_match.rank with the two changes the correction pins in
codewire/graph-inc4.md (rank step 4 and step 6, node _classify):
  step 4: one trie walk per DISTINCT query token (ascending allowed edits), no 300-candidate
          switch; the "posting variant": for each walk map {token id: distance}, the postings
          of its token ids are taken by distance layer (d = 0 .. allowed); a candidate keeps the
          smallest layer that holds it, the set is intersected after each walk (stop when empty
          or a map is empty), and the key is the sum of count x best. No _prefix_distance call.
  step 6: _classify_v takes FUZZY distances from the step-4 walk maps by the name's token ids
          (a distinct query token without a map fails), iterates DISTINCT query tokens with
          their counts (E5S-04), and never calls _prefix_distance.
Modes: totals, check (rank_v == rank), time, mem.
"""
from __future__ import annotations

import gc
import hashlib
import os
import runpy
import statistics
import sys
import time
import tracemalloc
from pathlib import Path

TREE = Path(os.environ["TREE"]).resolve()
SEC = runpy.run_path(os.environ["SEC_PROBE"], run_name="sec_e5_probe")  # its module-level asserts check TREE
lm, T = SEC["lm"], SEC["T"]
build_label_index, rank, MatchRule = lm.build_label_index, lm.rank, lm.MatchRule
fixtures, crafted, memo_query = SEC["fixtures"], SEC["crafted"], SEC["memo_query"]
WS = " \t\n\r\x0b\x0c"
CALLS = {"_prefix_distance": 0}
_orig_pd = lm._prefix_distance


def _counted_pd(*a, **k):
    CALLS["_prefix_distance"] += 1
    return _orig_pd(*a, **k)


lm._prefix_distance = _counted_pd  # rank's module globals resolve it at call time


def load():
    return f"{tuple(round(x, 2) for x in os.getloadavg())}"


def header(mode):
    import s19_app
    print(f"s19_app.__file__ = {s19_app.__file__}")
    print(f"label_match.__file__ = {lm.__file__}")
    print(f"label_match sha256 = {hashlib.sha256(Path(lm.__file__).read_bytes()).hexdigest()}")
    print(f"sec-e5-probe.py sha256 = {hashlib.sha256(Path(os.environ['SEC_PROBE']).read_bytes()).hexdigest()}")
    print(f"this probe sha256 = {hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}")
    print(f"variant = {VARIANT} (A: walk every distinct token; C: A + switch at <= {OCC_CAP} candidate token occurrences, step 6 by the tier's rule)")
    print(f"mode = {mode}  python = {sys.version.split()[0]}  host = {os.uname().nodename}  load = {load()}  cpus = {os.cpu_count()}")
    print(f"HOME = {os.environ.get('HOME')}  LOCALAPPDATA = {os.environ.get('LOCALAPPDATA')}")


# ---------------------------------------------------------------- the pinned variant
def fuzzy_tier_v(query, index, taken):
    counts: dict[str, int] = {}
    for token in query.tokens:
        counts[token] = counts.get(token, 0) + 1
    distinct = sorted(counts, key=lm._allowed_edits)
    ps, pp = index._posting_starts, index._postings
    maps: dict[str, dict[int, int]] = {}
    cand = None
    totals: dict[int, int] = {}
    for token in distinct:
        allowed = lm._allowed_edits(token)
        dist = lm._fuzzy_token_distances(index, token, allowed)
        maps[token] = dist
        if not dist:
            return {}, maps
        layers = [set() for _ in range(allowed + 1)]
        for token_id, d in dist.items():
            layers[d].update(pp[ps[token_id]:ps[token_id + 1]])
        reached = layers[0].union(*layers[1:])
        if cand is None:
            cand = reached
            cand.difference_update(taken)
        else:
            cand &= reached
        if not cand:
            return {}, maps
        count = counts[token]
        lower = layers[0]
        for d in range(1, allowed + 1):
            for name_id in (layers[d] & cand) - lower:
                totals[name_id] = totals.get(name_id, 0) + d * count
            if d < allowed:
                lower = lower | layers[d]
    return {name_id: totals.get(name_id, 0) for name_id in cand}, maps


OCC_CAP = 512


def fuzzy_tier_c(query, index, taken):
    """Variant C: the posting variant of fuzzy_tier_v, but once the remaining candidates hold at most
    OCC_CAP name-token occurrences in all (tested when at most OCC_CAP candidates remain), each remaining
    distinct query token is computed with _prefix_distance on those candidates' token ids only, once per
    (query token, token id). Returns {name id: total} and {distinct token: {token id: distance <= allowed}}."""
    counts: dict[str, int] = {}
    for token in query.tokens:
        counts[token] = counts.get(token, 0) + 1
    distinct = sorted(counts, key=lm._allowed_edits)
    ps, pp = index._posting_starts, index._postings
    starts, ids_all, toks = index._name_token_starts, index._name_token_ids, index._tokens
    tables: dict[str, dict[int, int]] = {}
    cand = None
    totals: dict[int, int] = {}
    switched = False
    for token in distinct:
        allowed = lm._allowed_edits(token)
        count = counts[token]
        if not switched and cand is not None and len(cand) <= OCC_CAP:
            switched = sum(starts[n + 1] - starts[n] for n in cand) <= OCC_CAP
        if switched:
            seen: dict[int, int] = {}
            kept = set()
            for name_id in cand:
                best = None
                for token_id in ids_all[starts[name_id]:starts[name_id + 1]]:
                    v = seen.get(token_id)
                    if v is None:
                        v = lm._prefix_distance(token, toks[token_id], allowed)
                        seen[token_id] = v
                    if v <= allowed and (best is None or v < best):
                        best = v
                if best is not None:
                    kept.add(name_id)
                    if best:
                        totals[name_id] = totals.get(name_id, 0) + best * count
            tables[token] = {t: v for t, v in seen.items() if v <= allowed}
            cand = kept
            if not cand:
                return {}, tables
            continue
        dist = lm._fuzzy_token_distances(index, token, allowed)
        tables[token] = dist
        if not dist:
            return {}, tables
        layers = [set() for _ in range(allowed + 1)]
        for token_id, d in dist.items():
            layers[d].update(pp[ps[token_id]:ps[token_id + 1]])
        reached = layers[0].union(*layers[1:])
        if cand is None:
            cand = reached
            cand.difference_update(taken)
        else:
            cand &= reached
        if not cand:
            return {}, tables
        lower = layers[0]
        for d in range(1, allowed + 1):
            for name_id in (layers[d] & cand) - lower:
                totals[name_id] = totals.get(name_id, 0) + d * count
            if d < allowed:
                lower = lower | layers[d]
    return {name_id: totals.get(name_id, 0) for name_id in cand}, tables


def emit_c(query, name, rule, key, token_ids, tables):
    """Variant C step 6: the entry's rule and key are the tier's; only that rule's spans are computed.
    FUZZY spans come from the step-4 tables by the name's token ids; SUBSEQUENCE from _subsequence."""
    if rule is MatchRule.FUZZY:
        name_spans = lm._tokens(name)
        assert len(name_spans) == len(token_ids)
        counts: dict[str, int] = {}
        for token in query.tokens:
            counts[token] = counts.get(token, 0) + 1
        total, spans = 0, []
        for qt, count in counts.items():
            table = tables[qt]
            best, best_span = None, None
            for (start, end), token_id in zip(name_spans, token_ids):
                v = table.get(token_id)
                if v is not None and (best is None or v < best):
                    best, best_span = v, (start, end)
            if best is None:
                raise AssertionError(f"fuzzy entry without a table hit: {name[:40]!r} {qt!r}")
            total += best * count
            spans.append(best_span)
        if total != key:
            raise AssertionError(f"fuzzy key {key} != {total} for {name[:40]!r}")
        return lm._join_spans(spans)
    if rule is MatchRule.SUBSEQUENCE:
        offsets = lm._subsequence(query.keys, lm._fold(name))
        if offsets is None:
            raise AssertionError(f"subsequence entry without offsets: {name[:40]!r}")
        return lm._join_spans([(o, o + 1) for o in offsets])
    got = classify_v(query, name, token_ids, tables)  # returns at its own branch for rule <= TOKEN
    if got is None or got[0] is not rule or got[1] != key:
        raise AssertionError(f"tier/classify disagree on {name[:40]!r}")
    return got[2]


VARIANT = os.environ.get("VARIANT", "A")


def classify_v(query, name, token_ids, maps):
    folded = lm._fold(name)
    text = query.text
    text_len = len(text)
    if folded == text:
        return (MatchRule.EXACT, 0, ((0, len(name)),))
    if folded.startswith(text):
        return (MatchRule.PREFIX, 0, ((0, text_len),))
    p = folded.find(text)
    if p >= 0:
        key, span, cursor = 1, (p, p + text_len), p
        while cursor >= 0:
            if lm._at_boundary(name, cursor):
                key, span = 0, (cursor, cursor + text_len)
                break
            cursor = folded.find(text, cursor + 1)
        return (MatchRule.SUBSTRING, key, (span,))
    name_spans = lm._tokens(name)
    assert len(name_spans) == len(token_ids)
    counts: dict[str, int] = {}
    for token in query.tokens:
        counts[token] = counts.get(token, 0) + 1
    if name_spans and counts:
        token_spans, ok = [], True
        for qt in counts:
            ms = None
            for start, end in name_spans:
                if folded[start:end].startswith(qt):
                    ms = (start, start + len(qt))
                    break
            if ms is None:
                ok = False
                break
            token_spans.append(ms)
        if ok:
            return (MatchRule.TOKEN, 0, lm._join_spans(token_spans))
        total, fuzzy_spans = 0, []
        for qt, count in counts.items():
            dmap = maps.get(qt)
            if dmap is None:
                total = -1
                break
            best, best_span = None, None
            for (start, end), token_id in zip(name_spans, token_ids):
                v = dmap.get(token_id)
                if v is not None and (best is None or v < best):
                    best, best_span = v, (start, end)
            if best is None:
                total = -1
                break
            total += best * count
            fuzzy_spans.append(best_span)
        if total >= 0:
            return (MatchRule.FUZZY, total, lm._join_spans(fuzzy_spans))
    if query.keys:
        offsets = lm._subsequence(query.keys, folded)
        if offsets is not None:
            return (MatchRule.SUBSEQUENCE, 0, lm._join_spans([(o, o + 1) for o in offsets]))
    return None


def rank_v(query, index, limit):
    """label_match.rank (sha256 24564b32...) with step 4 and step 6 as pinned; the rest unchanged."""
    if limit < 1:
        return []
    raw = query.strip(WS)
    if len(raw) > 256:
        return []
    parsed = lm._parse_query(raw)
    if parsed is None:
        return []
    names, folded, count = index.names, index._folded, len(index.names)
    text = parsed.text
    text_len = len(text)
    groups: dict[tuple, list[int]] = {}

    def add_group(rule, key, name_id):
        groups.setdefault(lm._order_key(rule, key, names[name_id], False)[:3], []).append(name_id)

    exact, prefix, subs = [], [], []
    for i in range(count):
        nf = folded[i]
        if text in nf:
            if nf.startswith(text):
                (exact if len(nf) == text_len else prefix).append(i)
            else:
                subs.append(i)
    for i in exact:
        add_group(MatchRule.EXACT, 0, i)
    for i in prefix:
        add_group(MatchRule.PREFIX, 0, i)
    for i in subs:
        key, nf = 1, folded[i]
        p = nf.find(text)
        while p >= 0:
            if lm._at_boundary(names[i], p):
                key = 0
                break
            p = nf.find(text, p + 1)
        add_group(MatchRule.SUBSTRING, key, i)
    found = len(exact) + len(prefix) + len(subs)
    taken = set(exact) | set(prefix) | set(subs)

    if found < limit and parsed.tokens:
        distinct = list(dict.fromkeys(parsed.tokens))
        ranges = [lm._token_range(index._tokens, t) for t in distinct]
        if ranges and all(lo < hi for lo, hi in ranges):
            ps, pp = index._posting_starts, index._postings
            order = sorted(range(len(ranges)), key=lambda j: ps[ranges[j][1]] - ps[ranges[j][0]])
            lo, hi = ranges[order[0]]
            cands = set(pp[ps[lo]:ps[hi]])
            cands.difference_update(taken)
            for j in order[1:]:
                if not cands:
                    break
                lo, hi = ranges[j]
                cands.intersection_update(pp[ps[lo]:ps[hi]])
            for name_id in cands:
                add_group(MatchRule.TOKEN, 0, name_id)
                taken.add(name_id)
                found += 1

    maps: dict[str, dict[int, int]] = {}
    if found < limit and parsed.tokens:
        fuzzy, maps = (fuzzy_tier_c if VARIANT == "C" else fuzzy_tier_v)(parsed, index, taken)
        for name_id, total in fuzzy.items():
            add_group(MatchRule.FUZZY, total, name_id)
            taken.add(name_id)
            found += 1

    if found < limit and parsed.keys:
        key_mask = lm._char_mask(parsed.keys)
        for i in range(count):
            if i in taken or key_mask & ~index._masks[i]:
                continue
            if lm._subsequence(parsed.keys, folded[i]) is not None:
                add_group(MatchRule.SUBSEQUENCE, 0, i)

    starts, ids_all = index._name_token_starts, index._name_token_ids
    result = []
    for group_key in sorted(groups):
        rule = lm._RULE_BY_POS[group_key[0]]
        keyed = []
        for name_id in groups[group_key]:
            name = names[name_id]
            if rule is MatchRule.EXACT:
                ce = name == raw
            elif rule is MatchRule.PREFIX:
                ce = name.startswith(raw)
            elif rule is MatchRule.SUBSTRING:
                ce = raw in name
            else:
                ce = False
            keyed.append((lm._order_key(rule, group_key[1], name, ce)[3:], name_id))
        keyed.sort(key=lambda item: item[0])
        for _, name_id in keyed:
            if VARIANT == "C":
                spans = emit_c(parsed, names[name_id], rule, group_key[1], ids_all[starts[name_id]:starts[name_id + 1]], maps)
                result.append(lm.LabelMatch(name=names[name_id], rule=rule, edits=group_key[1] if rule is MatchRule.FUZZY else 0, spans=spans))
                if len(result) >= limit:
                    return result
                continue
            got = classify_v(parsed, names[name_id], ids_all[starts[name_id]:starts[name_id + 1]], maps)
            if got is None or got[0] is not rule or got[1] != group_key[1]:
                raise AssertionError(f"tier/classify disagree on {names[name_id][:40]!r}: {rule} {group_key[1]} vs {got and got[:2]}")
            result.append(lm.LabelMatch(name=names[name_id], rule=got[0], edits=got[1] if got[0] is MatchRule.FUZZY else 0, spans=got[2]))
            if len(result) >= limit:
                return result
    return result


# ---------------------------------------------------------------- shapes
def subseq_query(head, pairs):
    """head + 25 tokens pairs[2k] + pairs[2k+1][0] (4 letters, 1 edit from the hit pairs[2k], start no
    token, keys in name order) + 'eeeeeee' (7 letters: no token within 2 edits; its letters lie in
    every crafted name's junk). Listed names: SUBSEQUENCE (the fuzzy check fails only at the last token)."""
    toks = [pairs[2 * k] + pairs[2 * k + 1][0] for k in range(25)]
    return " ".join([head] + toks + ["eeeeeee"])


def lists():
    f = fixtures()
    ref_ix = build_label_index(f["ref"])
    h3, p3, n3 = crafted(ref_ix, 300, 20261113 + 300, True)
    h2, p2, n2 = crafted(ref_ix, 2000, 20261113 + 2000, False)
    craft300 = n3 + f["ref"][:49700]
    craft2000 = n2 + f["ref"][:48000]
    return f, ref_ix, (h3, p3, craft300), (h2, p2, craft2000)


def med(fn, n):
    runs, out = [], None
    for _ in range(n):
        gc.collect()
        t0 = time.perf_counter()
        out = fn()
        runs.append(time.perf_counter() - t0)
    return statistics.median(runs), out


def tup(rows):
    return [(m.name, m.rule.value, m.edits, m.spans) for m in rows]


# ---------------------------------------------------------------- modes
def totals():
    header("totals")
    f, _, (h3, p3, c300), (h2, p2, c2000) = lists()
    print("\nE5S-02: the lists the performance rows bound, by count and total characters")
    for lab, lst in (("REF", f["ref"]), ("REF6", f["ref6"]), ("LONG", f["long"]), ("CRAFT (300 crafted + 49,700 REF)", c300),
                     ("2,000 crafted + 48,000 REF (map-path shape)", c2000)):
        tot = sum(len(n) for n in lst)
        print(f"  {lab:44} names {len(lst):>6,}  distinct {len(set(lst)):>6,}  total characters {tot:>10,}  "
              f"mean {tot / len(lst):7.2f}  longest {max(len(n) for n in lst):>5,}")
    print(f"  crafted names: {len(c300) - 49700} x {len(c300[0])} characters, {len(lm._tokens(c300[0]))} tokens each, head {h3!r}")
    print(f"  CRAFT sha256 of '\\n'.join(names) = {hashlib.sha256(chr(10).join(c300).encode()).hexdigest()}")
    for nq in (4, 51):
        q = memo_query(h3, p3, nq)
        print(f"  CRAFT query {nq:>2} tokens, {len(q)} characters: {q[:60]!r}{'...' if len(q) > 60 else ''}  sha256 {hashlib.sha256(q.encode()).hexdigest()[:16]}")
    q = subseq_query(h3, p3)
    print(f"  CRAFT subsequence shape, {len(q)} characters: {q[:60]!r}...")


def check():
    header("check")
    f, ref_ix, (h3, p3, c300), _ = lists()
    ref6_ix, long_ix = build_label_index(f["ref6"]), build_label_index(f["long"])
    c300_ix = build_label_index(c300)
    pools = [
        ("REF", ref_ix, list(T.qset33(f["swa"], f["ref"])) + [q for _, q in T.pset_ref()] + list(SEC["extra_shapes"]().values())),
        ("REF6", ref6_ix, ["m", "meas_", "chr", "mesa", "cahr", "cr0", "char 1", "0", "chr 0", "ch00", "meas 1", "c 0 1"]
         + [q for _, q in T.pset_ref6(f["swa"])] + list(SEC["ref6_shapes"](f["ref6"]).values())),
        ("LONG", long_ix, [q for _, q in T.LONG_QUERIES] + list(SEC["long_shapes"]().values())),
        ("CRAFT", c300_ix, [memo_query(h3, p3, n) for n in (1, 2, 4, 8)] + [subseq_query(h3, p3)]),
    ]
    total = mism = 0
    for lab, ix, qs in pools:
        n_lab = m_lab = 0
        for q in qs:
            for limit in (1, 20, 200):
                a, b = tup(rank(q, ix, limit)), tup(rank_v(q, ix, limit))
                n_lab += 1
                if a != b:
                    m_lab += 1
                    print(f"  MISMATCH {lab} limit {limit} {q[:50]!r}")
        total += n_lab
        mism += m_lab
        print(f"  {lab:6} {len(qs):>3} queries x 3 limits (1, 20, 200): {n_lab} comparisons, {m_lab} mismatches")
    q = memo_query(h3, p3, 51)
    a, b = tup(rank(q, c300_ix, 20)), tup(rank_v(q, c300_ix, 20))
    total += 1
    mism += a != b
    print(f"  CRAFT 51-token query, limit 20: equal {a == b}, {len(b)} entries, rules {sorted({r for _, r, _, _ in b})}, edits {sorted({e for _, _, e, _ in b})}")
    print(f"  TOTAL {total} comparisons, {mism} mismatches (rank_v vs label_match.rank)")


def timing():
    header("time")
    f, ref_ix, (h3, p3, c300), (h2, p2, c2000) = lists()
    c300_ix = build_label_index(c300)
    print(f"\nA. CRAFT ({len(c300):,} names; 300 crafted of 1,024 characters + 49,700 REF), limit 20; load {load()}")
    for nq in (4, 8, 16, 32, 51):
        q = memo_query(h3, p3, nq)
        CALLS["_prefix_distance"] = 0
        mv, out = med(lambda: rank_v(q, c300_ix, 20), 7)
        pdv = CALLS["_prefix_distance"] // 7
        line = f"  {nq:>2} tokens ({len(q):>3} ch): pinned median of 7 {mv * 1000:8.1f} ms, _prefix_distance {pdv}/ranking, listed {len(out)} {sorted({m.rule.value for m in out})}"
        if nq in (4, 51):
            CALLS["_prefix_distance"] = 0
            mc, _ = med(lambda: rank(q, c300_ix, 20), 3)
            line += f" | current (per-candidate check) median of 3 {mc * 1000:9.1f} ms, _prefix_distance {CALLS['_prefix_distance'] // 3:,}/ranking"
        print(line)
    q = subseq_query(h3, p3)
    CALLS["_prefix_distance"] = 0
    mv, out = med(lambda: rank_v(q, c300_ix, 20), 7)
    pdv = CALLS["_prefix_distance"] // 7
    CALLS["_prefix_distance"] = 0
    mc, _ = med(lambda: rank(q, c300_ix, 20), 3)
    print(f"  subsequence shape ({len(q)} ch): pinned median of 7 {mv * 1000:8.1f} ms, _prefix_distance {pdv}/ranking, listed {len(out)} "
          f"{sorted({m.rule.value for m in out})} | current median of 3 {mc * 1000:9.1f} ms, _prefix_distance {CALLS['_prefix_distance'] // 3:,}/ranking")
    del c300_ix
    gc.collect()
    c2000_ix = build_label_index(c2000)
    q = memo_query(h2, p2, 51)
    mv, out = med(lambda: rank_v(q, c2000_ix, 20), 7)
    mc, _ = med(lambda: rank(q, c2000_ix, 20), 3)
    print(f"  2,000 crafted + 48,000 REF, 51 tokens: pinned median of 7 {mv * 1000:8.1f} ms | current (map path) median of 3 {mc * 1000:8.1f} ms; load {load()}")
    del c2000_ix
    gc.collect()
    h1, p1, n1 = crafted(ref_ix, 1, 20261113 + 1, True)
    c1_ix = build_label_index(n1 + f["ref"][:49999])
    q = memo_query(h1, p1, 51)
    CALLS["_prefix_distance"] = 0
    mv, out = med(lambda: rank_v(q, c1_ix, 20), 7)
    print(f"  1 crafted (268 token occurrences) + 49,999 REF, 51 tokens: pinned median of 7 {mv * 1000:8.1f} ms, "
          f"_prefix_distance {CALLS['_prefix_distance'] // 7:,}/ranking, listed {len(out)} {sorted({m.rule.value for m in out})}")
    del c1_ix
    gc.collect()

    print(f"\nB. fixture query sets, pinned vs current, median of 7 each, limit 20 (worst per set); load {load()}")
    ref6_ix, long_ix = build_label_index(f["ref6"]), build_label_index(f["long"])
    sets = [
        ("QSET over REF (.36/1, 200 ms)", ref_ix, list(T.qset33(f["swa"], f["ref"]))),
        ("REF6 queries (.36/1, 200 ms)", ref6_ix, ["m", "meas_", "chr", "mesa", "cahr", "cr0", "char 1", "0", "chr 0", "ch00", "meas 1", "c 0 1"]),
        ("PSET over REF (.40/1, 1.0 s)", ref_ix, [q for _, q in T.pset_ref()]),
        ("PSET over REF6 (.40/1, 1.0 s)", ref6_ix, [q for _, q in T.pset_ref6(f["swa"])]),
        ("LONG (.40/2, 1.0 s)", long_ix, [q for _, q in T.LONG_QUERIES]),
    ]
    for lab, ix, qs in sets:
        wv = wc = (0.0, "")
        for q in qs:
            mv, _ = med(lambda: rank_v(q, ix, 20), 7)
            mc, _ = med(lambda: rank(q, ix, 20), 7)
            wv = max(wv, (mv, q[:30]))
            wc = max(wc, (mc, q[:30]))
        print(f"  {lab:32} pinned worst {wv[0] * 1000:7.1f} ms ({wv[1]!r}) | current worst {wc[0] * 1000:7.1f} ms ({wc[1]!r})")
    print(f"\nload after = {load()}")


def mem():
    header("mem")
    f, _, (h3, p3, c300), _ = lists()
    c300_ix = build_label_index(c300)
    ref6_ix = build_label_index(f["ref6"])
    near = dict(T.pset_ref6(f["swa"]))["near tokens"]
    for lab, ix, q in (("CRAFT 51 tokens", c300_ix, memo_query(h3, p3, 51)), ("CRAFT 4 tokens", c300_ix, memo_query(h3, p3, 4)),
                       ("CRAFT subsequence shape", c300_ix, subseq_query(h3, p3)), ("REF6 near tokens", ref6_ix, near)):
        gc.collect()
        tracemalloc.start()
        rank_v(q, ix, 20)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        print(f"  {lab:26} pinned: one ranking under tracemalloc, peak {peak / 1048576:7.1f} MiB")


if __name__ == "__main__":
    {"totals": totals, "check": check, "time": timing, "mem": mem}[sys.argv[1]]()
