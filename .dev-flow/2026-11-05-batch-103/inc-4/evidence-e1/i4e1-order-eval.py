#!/usr/bin/env python3
"""batch-103 Inc 4 E1: which rule order serves the operator's queries? (decision D-3)

THROWAWAY EVIDENCE. Run on <runner> next to i4e1-pilot.py and
i4e1-pilot2.py. For generated queries over the 13,990 real-shape names of
software_a.a2l it finds the rank of the name each query was made from (the
target) under two rule orders:
  A  exact > prefix > substring > token > subsequence > fuzzy   (handoff)
  B  exact > prefix > substring > token > fuzzy > subsequence
Everything else is the E1 proposal (rule key, shorter, case-exact, code point).
Per name it computes every rule the name meets (from the v2 index structures),
so each order gives each name its own first rule.
Query classes (seed 20261106):
  typo-words   2 letter tokens (>= 4 letters) of the target, one edit in one
  typo-word    1 letter token (>= 5 letters) from the middle, one edit
  abbrev       the first letters of the target's first 3 or 4 tokens
  partial      the first 3 letters of 2 tokens, joined by a space
"""
from __future__ import annotations

import os
import random
import runpy
import statistics
from pathlib import Path

HERE = Path(os.environ.get("PILOT_DIR", "/tmp/b103-e1-4"))
P2 = runpy.run_path(str(HERE / "i4e1-pilot2.py"), run_name="i4e1_pilot_v2")
Index2 = P2["Index2"]
P1 = P2["P1"]
tokens, fold, allowed, is_subseq, query_parts = P1["tokens"], P1["fold"], P1["allowed"], P1["is_subseq"], P1["query_parts"]
evaluate, names_of, REPO, s19_app, _mask = P1["evaluate"], P1["names_of"], P1["REPO"], P1["s19_app"], P1["_mask"]

ORDERS = {"A": (0, 1, 2, 3, 4, 5), "B": (0, 1, 2, 3, 5, 4)}  # rank of rule index 0..5


def rules_met(idx, query):
    """name id -> (set of rule indexes met, substring key, fuzzy total)."""
    q, qf, qtoks, keys = query_parts(query, True)
    out = {}
    if not keys:
        return out
    for i, nf in enumerate(idx.folded):
        if qf in nf:
            s = {2}
            if nf.startswith(qf):
                s.add(1)
                if len(nf) == len(qf):
                    s.add(0)
            ev = evaluate(query, idx.names[i])
            out[i] = [s, ev[1] if ev[0] == 2 else 0, None]
    per = [idx._prefix_tokens(qt) for qt in qtoks]
    if per and all(per):
        cand = None
        for ts in per:
            ids = set()
            for t in ts:
                ids.update(idx.inv[t])
            cand = ids if cand is None else cand & ids
        for i in cand or ():
            out.setdefault(i, [set(), 0, None])[0].add(3)
    kmask = _mask(keys)
    for i, nf in enumerate(idx.folded):
        if not (kmask & ~idx.nmask[i]) and is_subseq(keys, nf) is not None:
            out.setdefault(i, [set(), 0, None])[0].add(4)
    dists = []
    for qt in qtoks:
        k = allowed(qt)
        d = {t: 0 for t in idx._prefix_tokens(qt)} if k == 0 else idx._trie_search(qt, k)
        if not d:
            dists = []
            break
        dists.append(d)
    if dists:
        cand = None
        for d in dists:
            ids = set()
            for t in d:
                ids.update(idx.inv[t])
            cand = ids if cand is None else cand & ids
        for i in cand or ():
            total = 0
            for d in dists:
                total += min(d[t] for t in idx.ntoks[i] if t in d)
            row = out.setdefault(i, [set(), 0, None])
            row[0].add(5)
            row[2] = total
    return out


def position(idx, query, target_id, order):
    met = rules_met(idx, query)
    if target_id not in met:
        return None
    rank = ORDERS[order]
    q = query_parts(query, True)[0]

    def base(i):
        s, skey, total = met[i]
        r = min(s, key=lambda x: rank[x])
        rk = skey if r == 2 else (total if r == 5 else 0)
        return (rank[r], rk, len(idx.names[i])), r

    def tail(i, r):
        name = idx.names[i]
        ce = evaluate(query, name, folded=False)
        return (0 if ce is not None and ce[0] == r else 1, name)

    tb, tr = base(target_id)
    tt = tail(target_id, tr)
    better = 0
    for i in met:
        if i == target_id:
            continue
        b, r = base(i)
        if b < tb or (b == tb and tail(i, r) < tt):
            better += 1
    return better


def edit(rng, tok):
    s = list(tok)
    op = rng.randint(0, 3)
    p = rng.randrange(len(s))
    if op == 0:
        s[p] = rng.choice([c for c in "abcdefghijklmnopqrstuvwxyz" if c != s[p]])
    elif op == 1:
        del s[p]
    elif op == 2:
        s.insert(p, rng.choice("abcdefghijklmnopqrstuvwxyz"))
    else:
        p = min(p, len(s) - 2)
        if s[p] == s[p + 1]:
            s[p] = "z" if s[p] != "z" else "y"
        else:
            s[p], s[p + 1] = s[p + 1], s[p]
    return "".join(s)


def main() -> int:
    print(f"s19_app.__file__ = {s19_app.__file__}")
    sw_a = names_of(REPO / "examples/case_00_public/software_a.a2l")
    idx = Index2(sw_a)
    pos_of = {n: i for i, n in enumerate(idx.names)}
    rng = random.Random(20261106)
    classes = {"typo-words": [], "typo-word": [], "abbrev": [], "partial": []}
    tries = 0
    while min(len(v) for v in classes.values()) < 60 and tries < 20000:
        tries += 1
        name = rng.choice(idx.names)
        toks = [fold(name[a:b]) for a, b in tokens(name)]
        lets = [t for t in toks if t.isalpha()]
        if len(classes["typo-words"]) < 60 and len([t for t in lets if len(t) >= 4]) >= 2:
            pick = [t for t in lets if len(t) >= 4][:2]
            j = rng.randrange(2)
            pick[j] = edit(rng, pick[j])
            classes["typo-words"].append((" ".join(pick), name))
        if len(classes["typo-word"]) < 60:
            mid = [t for t in lets[1:] if len(t) >= 5]
            if mid:
                classes["typo-word"].append((edit(rng, rng.choice(mid)), name))
        if len(classes["abbrev"]) < 60 and len(toks) >= 4:
            n = rng.choice((3, 4))
            classes["abbrev"].append(("".join(t[0] for t in toks[:n]), name))
        if len(classes["partial"]) < 60 and len([t for t in lets if len(t) >= 3]) >= 2:
            pick = [t[:3] for t in lets if len(t) >= 3][:2]
            classes["partial"].append((" ".join(pick), name))
    print(f"names {len(idx.names)}; queries per class: {[len(v) for v in classes.values()]}")
    for cls, qs in classes.items():
        print(f"\n=== {cls}")
        stats = {}
        for order in ("A", "B"):
            ps = [position(idx, q, pos_of[t], order) for q, t in qs]
            found = [p for p in ps if p is not None]
            top1 = sum(1 for p in found if p == 0)
            top5 = sum(1 for p in found if p < 5)
            mrr = sum(1.0 / (p + 1) for p in found) / len(qs)
            stats[order] = ps
            print(f"  order {order}: target listed {len(found)}/{len(qs)}  top-1 {top1}/{len(qs)}  top-5 {top5}/{len(qs)}  MRR {mrr:.3f}  median position {statistics.median(found) if found else None}")
        diff = [(q, t, a, b) for (q, t), a, b in zip(qs, stats["A"], stats["B"]) if a != b]
        print(f"  queries whose target position differs between A and B: {len(diff)}")
        for q, t, a, b in diff[:6]:
            print(f"    query={q!r:28s} A={a} B={b}  target={t[:60]!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
