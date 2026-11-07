#!/usr/bin/env python3
"""batch-103 Inc 4 E2: the values the graph's private-node examples quote.

THROWAWAY EVIDENCE, NOT PRODUCT CODE. Run on cachyos-rtx in PILOT_DIR next to
i4e2-pilot4.py and the E1 pilots v1-v3. Every value comes from the E1 oracle
helpers (tokens, allowed, osa_prefix, merge, evaluate_b, naive_rank_b) or from
the two v4 helpers the graph adds (at_boundary, fuzzy_walk), and each v4
helper is checked against the oracle's definition:
  * at_boundary == the oracle's boundary set, at every offset of every name
    of the fixtures;
  * fuzzy_walk == brute force (osa_prefix over every distinct token of REF)
    for the query tokens of the test cases and of QSET.
"""
from __future__ import annotations

import os
import runpy
import sys
from pathlib import Path

HERE = Path(os.environ.get("PILOT_DIR", "/tmp/b103-e2-4"))
P4 = runpy.run_path(str(HERE / "i4e2-pilot4.py"), run_name="i4e2_pilot_v4")
IndexC, at_boundary, fuzzy_walk, build_nodes, prefix_range = (
    P4["IndexC"], P4["at_boundary"], P4["fuzzy_walk"], P4["build_nodes"], P4["prefix_range"])
tokens, allowed, fold, query_parts = P4["tokens"], P4["allowed"], P4["fold"], P4["query_parts"]
naive_rank_b, evaluate_b, names_of, REPO, OUT, s19_app = (
    P4["naive_rank_b"], P4["evaluate_b"], P4["names_of"], P4["REPO"], P4["OUT"], P4["s19_app"])
P1 = P4["P1"]
osa_prefix, merge, _sep, _mask = P1["osa_prefix"], P1["merge"], P1["_sep"], P1["_mask"]


def main() -> int:
    print(f"s19_app.__file__ = {s19_app.__file__}")
    print(f"python = {sys.version.split()[0]}  host = {os.uname().nodename}")
    case08 = names_of(OUT / "firmware.a2l")
    issues = names_of(OUT / "firmware_issues.a2l")
    sw_a = names_of(REPO / "examples/case_00_public/software_a.a2l")
    sw_b = names_of(REPO / "examples/case_00_public/software_b.a2l")
    bal = names_of(REPO / "examples/case_00_public/BalanceTube_STMicro.a2l")
    src = names_of(REPO / "examples/case_00_public/from_source.a2l")

    print("\n=== A. _tokens (spans, then texts)")
    for s in ["VAL_BLK_0001", "model.MainClass.ledRing[0].red", "parameter_instance[0].Knife[1].x", "ABSValue", "AValue",
              "Map3D", "LukPvq.JXML_UPQ_BI.OKSAhwvcueaniy", "Aabcx_GgrDwx_kaudIvm_ydmuH_uoz3._5_", "Drück_Max",
              "JVmL", "knife.*", "___", "", "blk val 00", "\xa0VALUE_0001", "\x1cVALUE_0001"]:
        sp = tokens(s)
        print(f"  {s!r:40s} {sp}  {[s[a:b] for a, b in sp]}")

    print("\n=== B. _allowed_edits")
    for t in ["0300", "1", "ab", "x", "maq", "cuvre", "drück", "valuexx", "curvee", "measurementss"]:
        print(f"  {t!r:16s} {allowed(t)}")

    print("\n=== C. _prefix_distance (OSA to the nearest prefix, the empty prefix included)")
    for q, t in [("cuvre", "curve"), ("valuee", "value"), ("value", "val"), ("mpa", "map"), ("xmap", "map"), ("maq", "map"),
                 ("cvure", "curve"), ("maesu", "measurement"), ("ab", "ba"), ("ca", "abc"), ("vblk", "blk"), ("vblk", "val"),
                 ("valu", "val"), ("valu", "value"), ("curvee", "cuve"), ("curvee", "curve"), ("valuexx", "value"),
                 ("valuexxx", "value"), ("drück", "druck"), ("drück", "drÜck"), ("measurementss", "measurement"), ("jotfa", "jotaf")]:
        print(f"  {q!r:16s} -> {t!r:16s} {osa_prefix(q, t)}")

    print("\n=== D. _join_spans")
    for spans in [[(4, 7), (0, 3), (8, 10)], [(0, 3), (3, 8)], [(0, 1), (1, 6)], [(0, 1), (3, 8)], [(16, 30), (31, 36)],
                  [(0, 1), (2, 3)], [(0, 1), (1, 2), (2, 3), (3, 4), (4, 5), (6, 7), (7, 8), (9, 10)]]:
        print(f"  {spans} -> {merge(spans)}")

    print("\n=== E. _at_boundary: examples, then agreement with the oracle's boundary set")
    for s, p in [("DiscountCount", 3), ("DiscountCount", 8), ("MAP_0001", 0), ("MAP_0001", 3), ("MAP_0001", 4), ("MAP_0001", 5),
                 ("timeCounter", 4), ("Encounter", 2), ("ABSValue", 2), ("ABSValue", 3), ("Map3D", 3), ("Map3D", 4),
                 ("model.MainClass.ledController.sw.timeCounter", 38), ("LukPvq.JXML_UPQ_BI.OKSAhwvcueaniy", 21),
                 ("LukPvq.JXML_UPQ_BI.OKSAhwvcueaniy", 22), ("Drück_Max", 3)]:
        print(f"  {s!r:48s} offset {p:2d} -> {at_boundary(s, p)}")
    checked = disagree = 0
    for name in set(case08 + issues + src + bal + sw_b + sw_a + ["Drück_Max", "DRÜCK_MAX", "ABSValue", "AValue", "Map3D", "DiscountCount"]):
        nn = fold(name)
        bounds = {0} | {s for s, _ in tokens(name)} | {i for i, c in enumerate(nn) if _sep(c)}
        for p in range(len(name)):
            checked += 1
            if at_boundary(name, p) != (p in bounds):
                disagree += 1
                if disagree <= 5:
                    print(f"  DISAGREE {name!r} offset {p}")
    print(f"  offsets checked {checked:,}: disagreements = {disagree}")

    print("\n=== F. fuzzy_walk over the sorted distinct tokens")
    small = IndexC(case08)
    print(f"  C08 sorted distinct tokens ({len(small.utok)}), the letter tokens: {[t for t in small.utok if not t.isdigit()]}")
    for qt in ["cuvre", "maq", "mpa", "xmap", "maesu", "vlaue", "vblk", "valu", "cvure"]:
        k = allowed(qt)
        res = fuzzy_walk(small.utok, small.nodes, qt, k)
        print(f"  C08 {qt!r:8s} k={k} -> {{{', '.join(f'{small.utok[i]!r}: {d}' for i, d in sorted(res.items()))}}}")
    two = IndexC(["CUVE", "CURVE_0001"])
    res = fuzzy_walk(two.utok, two.nodes, "curvee", 2)
    print(f"  [CUVE, CURVE_0001] tokens {two.utok}  'curvee' k=2 -> {{{', '.join(f'{two.utok[i]!r}: {d}' for i, d in sorted(res.items()))}}}")
    ref = (sw_a + [n + "_1" for n in sw_a] + [n + "_2" for n in sw_a] + [n + "_3" for n in sw_a])[:50000]
    big = IndexC(ref)
    qtoks = ["cuvre", "maq", "mpa", "xmap", "maesu", "vlaue", "vblk", "curvee", "valuexx", "aaaa", "qqqq", "zzzz", "nzukij",
             "ierxjr", "eud", "led", "ring", "pposbxiif", "temp", "sensor", "max", "pposbxiifkdgfiajnbbpvb", "dyan", "xvz",
             "jotfa", "vdo", "oks", "ahw", "drück", "xqzjvkw", "cnt", "jotaf", "msrql", "kh"]
    bad = 0
    for qt in qtoks:
        k = allowed(qt)
        if k == 0:
            continue
        walk = fuzzy_walk(big.utok, big.nodes, qt, k)
        brute = {i: d for i, t in enumerate(big.utok) if (d := osa_prefix(qt, t)) <= k}
        same = walk == brute
        bad += not same
        print(f"  REF {qt!r:26s} k={k}  tokens within k: {len(brute):5d}  walk == brute force: {same}")
    print(f"  REF distinct tokens {len(big.utok)}; query tokens checked {sum(allowed(q) > 0 for q in qtoks)}: mismatches = {bad}")

    print("\n=== G. derived examples (rows .1, .17, purity), oracle and IndexC")
    idx08 = IndexC(case08)
    for qy in ["\xa0VALUE_0001", "\x1cVALUE_0001", "VALUE_0001\x1c"]:
        want = naive_rank_b(qy, case08, 20)
        got = idx08.rank(qy, 20)
        print(f"  C08 query={qy!r}: IndexC == oracle {got == want}  -> {got}")
    print(f"  C08i: {len(issues)} names, {len(set(issues))} distinct; IndexC(C08i).names has {len(IndexC(issues).names)}; first-occurrence order kept: {list(IndexC(issues).names) == list(dict.fromkeys(issues))}")
    before = list(case08)
    r1 = idx08.rank("value_000", 20)
    r2 = idx08.rank("value_000", 20)
    print(f"  purity: two rankings equal {r1 == r2}; names list unchanged {before == case08}")

    print("\n=== H. more derived values (trie layout, character classes, cap, masks, empty index, token ranges)")
    nd = build_nodes(["0001", "curve", "cuve"])
    print(f"  build_nodes(['0001', 'curve', 'cuve']): chars {nd[0]!r} depth {list(nd[1])} first {list(nd[2])} end {list(nd[3])}")
    for t in [chr(0x663) * 3, chr(0xB2), chr(0xA0)]:
        print(f"  {t!r}: tokens {tokens(t)}  allowed {allowed(t) if tokens(t) else None}  str.isdigit() {t.isdigit()}  str.isalnum() {t.isalnum()}")
    six = "".join(map(chr, (32, 9, 10, 13, 11, 12)))
    fs, nb = chr(0x1C) + "X", chr(0xA0) + "X"
    print(f"  str.strip() removes U+001C: {fs.strip() == 'X'}; removes U+00A0: {nb.strip() == 'X'}; the six-character strip keeps both: {fs.strip(six) == fs and nb.strip(six) == nb}")
    for q, t, cap in [("cvure", "curve", 1), ("cuvre", "curve", 1), ("pposbxiif", "xyz", 2), ("valuexxx", "value", 2), ("value", "val", 2)]:
        print(f"  prefix distance capped at cap + 1: {q!r} -> {t!r} cap {cap}: {min(osa_prefix(q, t), cap + 1)}")
    for s in ["MAP_0001", "mp", "mpz"]:
        print(f"  _char_mask(_fold({s!r})) = {_mask(fold(s))}")
    print(f"  mask('mp') & ~mask('map_0001') = {_mask('mp') & ~_mask('map_0001')};  mask('mpz') & ~mask('map_0001') = {_mask('mpz') & ~_mask('map_0001')}")
    empty = IndexC([])
    print(f"  IndexC([]): names {empty.names}  rank('VALUE', 20) -> {empty.rank('VALUE', 20)}")
    for pre in ["va", "val", "valu", "m", "zz", "0"]:
        lo, hi = prefix_range(small.utok, pre)
        shown = small.utok[lo:hi] if hi - lo <= 4 else small.utok[lo:lo + 2] + ["..."] + small.utok[hi - 1:hi]
        print(f"  _token_range(C08 tokens, {pre!r}) = ({lo}, {hi}) -> {shown}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
