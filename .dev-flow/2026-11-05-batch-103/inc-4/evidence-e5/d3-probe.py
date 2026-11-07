#!/usr/bin/env python3
"""batch-103 Inc 4 E5 round-3 DESIGN probe (d3). THROWAWAY EVIDENCE, NOT PRODUCT CODE.

Runs on cachyos-rtx only, against the REAL module s19_app/tui/services/label_match.py (sha256 8f396c15...) of a
COPY of the read-only integrated tree (env TREE, first on PYTHONPATH). It loads the security reviewer's round-3
probe (sec-r3-probe.py, unchanged, same directory; it loads sec-e5-probe.py) for its fixtures, builders, node
counter (COUNTED_WALK), address-space cap and alarm, and the d3 pilot (d3-pilot.py) for the two round-3 rulings:
R-A2L-MATCH.42 (a per-ranking budget of 400,000 trie node visits; when spent, the fuzzy rule lists what it found so
far) and R-A2L-MATCH.43 (a non-ASCII name is left out of the prepared list).

Modes:
  keep   lists the budget must leave unchanged: every query of REF, REF6, LONG (the fixtures) and of the row lists
         CRAFT, U6, D3, E2, BAND, SUBO, W40 (the test's one-token queries); shipped == budgeted, nodes per ranking.
  cases  the cases of R-A2L-MATCH.42 (W40 2 and 6 tokens, DEEP40 1 and 6, W12 T20): budgeted median of 7, the
         listed entries, whether the budget truncates the list (budgeted == unbudgeted?), the negative controls
         (budget removed: W40 6 tokens median of 3; the lists the budget removes), and the dearest node (DEEP258).
  det    the budgeted case lists' sha256 (run it under several PYTHONHASHSEED values).
  detail what differs in a one-token list the budget cuts (DEEP40, W40 'a' * 40): names, edits, spans (added after
         the keep, cases and ascii runs; the edit only added this mode).
  walkex the walk node's examples: runs and visits per budget (added after detail; the edit only added this mode).
  ascii  the cases of R-A2L-MATCH.43 and the cases it changes (.4/1, .4/2, .12/4, .24/3, new .4/4), each shipped and
         piloted, the .4 controls, AST1's preparation with and without the rule, and the fixture census.
"""
from __future__ import annotations

import hashlib
import importlib
import importlib.util
import os
import statistics
import sys
import time
import tracemalloc
import unicodedata
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


R = _load("sec_r3_probe", "sec-r3-probe.py")
D3 = _load("d3_pilot", "d3-pilot.py")
P, T, lm = R.P, R.T, R.lm
rank, build_label_index = P.rank, P.build_label_index
PIL = D3.Pilot(lm)
B = D3.BUDGET


def header(mode):
    R.header(mode)
    print(f"d3 probe = {Path(__file__).name} sha256 {hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}; "
          f"d3 pilot = d3-pilot.py sha256 {hashlib.sha256((HERE / 'd3-pilot.py').read_bytes()).hexdigest()}; budget {B:,}")


def sha_list(out):
    return hashlib.sha256(repr(P.tup(out or [])).encode("utf-8", "surrogatepass")).hexdigest()


def sha_names(names):
    return hashlib.sha256("\n".join(names).encode("utf-8", "surrogatepass")).hexdigest()


def shape(out):
    if not out:
        return "[] (0 entries)"
    rules = sorted({m.rule.value for m in out})
    edits = sorted({m.edits for m in out})
    f = out[0]
    return (f"{len(out)} entries, rules {rules}, edits {edits}; entry 1 {ascii(f.name[:44])}{'...' if len(f.name) > 44 else ''} "
            f"(len {len(f.name)}) {f.rule.value} e{f.edits} spans {f.spans[:4]}{'...' if len(f.spans) > 4 else ''}")


def budgeted(ix, q, limit=20, b=B):
    PIL.install(budget=b)
    PIL.last_nodes = 0
    try:
        out = rank(q, ix, limit)
        return out, PIL.last_nodes
    finally:
        PIL.uninstall()


def med_budgeted(ix, q, n, b=B, limit=20):
    PIL.install(budget=b)
    try:
        return P.med(ix, q, limit=limit, n=n, budget=600)
    finally:
        PIL.uninstall()


def nodes_unbudgeted(ix, q, limit=20):
    out, rec, pd = R.walks_of(ix, q, limit)
    return out, sum(r[2] for r in rec), len(rec)


# ---------------------------------------------------------------- mode keep
def keep():
    header("d3 keep")
    f = P.fixtures()
    plan = [
        ("REF (fixture)", f["ref"], list(T.qset33(f["swa"], f["ref"])) + [q for _, q in T.pset_ref()] + list(P.extra_shapes().values())),
        ("REF6 (fixture)", f["ref6"], list(T.REF6_QUERIES) + [q for _, q in T.pset_ref6(f["swa"])] + list(P.ref6_shapes(f["ref6"]).values())),
        ("LONG (fixture)", f["long"], [q for _, q in T.LONG_QUERIES] + list(P.long_shapes().values())),
        ("CRAFT (.40/3)", T.craft_names() + f["ref"][:49700], [T.craft_query(n) for n in (4, 8, 16, 20, 21, 51)]),
        ("U6 (.40/5)", T.u6_names(), [T.fam_query(T.FAMQ, n) for n in (4, 16, 20, 21, 76)]),
        ("D3 (.40 list)", T.d3_names(), [T.fam_query(T.FAMQ, n) for n in (4, 12, 20)]),
        ("E2 (.40 list)", T.e2_names(), [T.fam_query(T.FAM6, n) for n in (4, 12, 20)]),
        ("BAND (.40/4)", T.band_names() + f["ref"][:50000 - 225], [T.BAND_HEAD + " " + "a" * 248 + "b"]),
        ("SUBO (.40 list)", T.subo_names(), ["aa", "aaa", "aaaaaaaa"]),
        ("W40 (.40 list; the test's one-token queries)", T.w40_names(), ["a" * 40, "a" * 64]),
    ]
    total_q = total_changed = 0
    print(f"=== shipped == budgeted ({B:,} trie node visits per ranking, the fuzzy rule keeping what it found so far), limit 20")
    for lab, names, qs in plan:
        ix = build_label_index(names)
        changed, worst, worst_q, reached = [], 0, "", 0
        for q in qs:
            base = P.tup(rank(q, ix, 20))
            _, nodes, _ = nodes_unbudgeted(ix, q)
            out, used = budgeted(ix, q)
            if nodes > worst:
                worst, worst_q = nodes, q
            reached += used >= B
            if P.tup(out) != base:
                changed.append((q, nodes, used, shape(out), len(base), sorted({r[1] for r in base})))
        total_q += len(qs)
        total_changed += len(changed)
        print(f"  {lab:46s} {len(qs):>3} queries; most nodes in one unbudgeted ranking {worst:>9,} ({worst / B:.3f} of the budget; "
              f"{ascii(worst_q[:24])}); budget reached in {reached}; lists changed {len(changed)}; load {P.load()}")
        for q, nodes, used, sh, nb, rb in changed:
            print(f"      CHANGED {ascii(q[:40])} ({len(q)} chars): {nodes:,} nodes unbudgeted ({nb} entries {rb}) -> budgeted {used:,} nodes: {sh}")
        del ix
    print(f"\nTOTAL {total_q} queries, {total_changed} lists changed under the budget; load after {P.load()}")


# ---------------------------------------------------------------- mode cases
def case_lists():
    return [
        ("W40 = the test module's w40_names()", T.w40_names, [
            ("R-A2L-MATCH.42/1", "'a' * 40 + ' ' + 'a' * 39 (2 distinct tokens, 80 chars)", R.runs_query((40, 39))),
            ("R-A2L-MATCH.42/2", "'a' * 40 ... 'a' * 35 (6 distinct tokens, 230 chars)", R.runs_query(range(40, 34, -1))),
            ("derived", "'a' * 39 + b ... g (6 distinct tokens, 245 chars; the reviewer's dearest W40 query)", " ".join("a" * 39 + c for c in "bcdefg")),
            ("derived", "'a' * 40 (1 token; the test's query)", "a" * 40)]),
        ("DEEP40 = sec-r3-probe.py deep40()", R.deep40, [
            ("R-A2L-MATCH.42/3", "'a' * 40 (1 token)", "a" * 40),
            ("R-A2L-MATCH.42/4", "'a' * 40 ... 'a' * 35 (6 distinct tokens, 230 chars)", R.runs_query(range(40, 34, -1)))]),
        ("W12 = sec-r3-probe.py w12()", R.w12, [
            ("R-A2L-MATCH.42/5", "T20: 'a' * 10 + b ... u (20 distinct tokens, 239 chars)", R.t_query(20))]),
    ]


def cases():
    header("d3 cases")
    for lab, maker, qs in case_lists():
        names = maker()
        ix = R.build(lab, names)
        print(f"    sha256 of the 50,000 names joined by '\\n': {sha_names(names)}")
        for cid, qlab, q in qs:
            assert len(q.strip(R.WS)) <= 256
            m, st, out = med_budgeted(ix, q, n=7)
            _, used = budgeted(ix, q)
            flag = f"  > {R.BOUND} s" if m > R.BOUND else f"  <= {R.BOUND} s (x{R.BOUND / m:.2f} margin)"
            print(f"\n  [{cid}] {qlab}")
            print(f"    BUDGETED   median of 7 {m * 1000:9.1f} ms [{st}]{flag}; trie node visits {used:,} (budget reached: {used >= B}); load {P.load()}")
            print(f"               {shape(out)}; bad spans {P.bad_spans(out)}; list sha256 {sha_list(out)}")
            t0 = time.perf_counter()
            dt, st0, out0 = P.run(lambda: rank(q, ix, 20), 300)
            _, nodes0, walks0 = nodes_unbudgeted(ix, q) if st0 == "ok" else (None, -1, -1)
            print(f"    UNBUDGETED one ranking {dt * 1000:9.1f} ms [{st0}]; trie node visits {nodes0:,} in {walks0} walks")
            print(f"               {shape(out0)}; list sha256 {sha_list(out0)}")
            same = st0 == "ok" and P.tup(out0) == P.tup(out)
            print(f"    TRUNCATED BY THE BUDGET: {'no (the same list)' if same else 'yes (the lists differ)'}")
            if cid == "R-A2L-MATCH.42/2":
                mc, stc, _ = P.med(ix, q, n=3, budget=600)
                print(f"    NEGATIVE CONTROL (budget removed = the shipped rank) median of 3 {mc * 1000:9.1f} ms [{stc}]"
                      f"{'  > ' + str(R.BOUND) + ' s -> RED' if mc > R.BOUND else '  NOT RED'}; load {P.load()}")
        del ix
    names = R.deep258()
    ix = R.build("DEEP258 (the dearest node: a 256-character query of two 128-letter tokens)", names)
    q = R.runs_query((128, 127))
    m, st, out = med_budgeted(ix, q, n=3)
    _, used = budgeted(ix, q)
    print(f"\n  [derived] 'a' * 128 + ' ' + 'a' * 127 BUDGETED median of 3 {m * 1000:.1f} ms [{st}]; {used:,} visits; "
          f"{m / max(used, 1) * 1e6:.2f} us per visit (upper bound: the whole ranking over the visits); {shape(out)}; load {P.load()}")
    print(f"\nload after = {P.load()}")


# ---------------------------------------------------------------- mode det
def det():
    header("d3 det")
    h = hashlib.sha256()
    n = 0
    for lab, maker, qs in case_lists():
        ix = build_label_index(maker())
        for cid, qlab, q in qs:
            for lim in (1, 20):
                out, used = budgeted(ix, q, lim)
                h.update(repr((used, P.tup(out))).encode("utf-8", "surrogatepass"))
                n += 1
        del ix
    print(f"PYTHONHASHSEED={os.environ.get('PYTHONHASHSEED')} hash('abc')={hash('abc')} budgeted rankings={n} sha256={h.hexdigest()}")


# ---------------------------------------------------------------- mode detail (what differs in a one-token list cut by the budget)
def detail():
    header("d3 detail")
    for lab, maker in (("DEEP40", R.deep40), ("W40", T.w40_names)):
        ix = build_label_index(maker())
        q = "a" * 40
        a, used = budgeted(ix, q)
        b = rank(q, ix, 20)
        same_names = [m.name for m in a] == [m.name for m in b]
        same_edits = [m.edits for m in a] == [m.edits for m in b]
        spans_diff = sum(x.spans != y.spans for x, y in zip(a, b))
        print(f"  {lab} 'a' * 40, limit 20: budgeted {used:,} visits; same names in the same order {same_names}; same edits {same_edits}; "
              f"entries whose spans differ {spans_diff} of {len(a)}")
        for x, y in list(zip(a, b))[:3]:
            print(f"    {ascii(x.name[:30])}... budgeted e{x.edits} {x.spans}  |  unbudgeted e{y.edits} {y.spans}")
        del ix


# ---------------------------------------------------------------- mode walkex (the walk node's examples: runs and visits)
def walkex():
    header("d3 walkex")

    def walk(ix, q, allowed, b):
        PIL.limit[0], PIL.used[0] = b, 0
        runs = PIL.walk(ix, q, allowed)
        return runs, PIL.used[0]

    def named(ix, runs):
        return ", ".join(f"({lo}, {hi}, {d}) {ix._tokens[lo]}{'..' + ix._tokens[hi - 1] if hi - lo > 1 else ''}" for lo, hi, d in runs)

    c08 = build_label_index(c08_lists()["C08"])
    print(f"C08: {len(c08._tokens)} distinct tokens, {len(c08._trie_depth)} trie nodes")
    for q, k in (("cuvre", 1), ("mpa", 1), ("maesu", 1), ("vblk", 1), ("valu", 1), ("cvure", 1), ("0300", 0), ("va", 0)):
        runs, used = walk(c08, q, k, B)
        print(f"  {q!r}, {k}, budget {B:,} -> runs {runs} [{named(c08, runs)}], visits {used}")
    full = walk(c08, "valu", 1, B)
    for b in sorted({0, 1, 2, full[1] // 2, full[1] - 1, full[1]}):
        runs, used = walk(c08, "valu", 1, b)
        print(f"  'valu', 1, budget {b} -> runs {runs}, visits {used}")
    cu = build_label_index(["CUVE", "CURVE_0001"])
    runs, used = walk(cu, "curvee", 2, B)
    print(f"  [CUVE, CURVE_0001], 'curvee', 2, budget {B:,} -> runs {runs}, visits {used}")
    w = build_label_index(T.w40_names())
    for b in (B, 10 ** 9):
        runs, used = walk(w, "a" * 40, 2, b)
        print(f"  W40, 'a' * 40, 2, budget {b:,} -> {len(runs):,} runs covering {sum(hi - lo for lo, hi, _ in runs):,} token ids, "
              f"visits {used:,}; first run {runs[0] if runs else None}, last run {runs[-1] if runs else None}")
    print(f"load after = {P.load()}")


# ---------------------------------------------------------------- mode ascii
def c08_lists():
    TB = importlib.import_module("tests.test_b103_label_match")
    out = Path(os.environ["SCRATCH"]) / "c08"
    out.mkdir(exist_ok=True)
    paths = TB.gen.generate(out, TB.SEED, 10.0)
    c08 = TB.read_names(paths["a2l"])
    assert len(c08) == 462
    ex = TB.EXAMPLES
    return {"C08": c08, "BAL": TB.read_names(ex / "BalanceTube_STMicro.a2l"), "SRC": TB.read_names(ex / "from_source.a2l"),
            "SWB": TB.read_names(ex / "software_b.a2l"), "SWA": TB.read_names(ex / "software_a.a2l")}


def fmt(out):
    return "[" + "; ".join(f"{ascii(m.name)} . {m.rule.value} . {','.join(f'({s},{e})' for s, e in m.spans)}"
                           + (f" . e{m.edits}" if m.rule.value == "fuzzy" else "") for m in out) + "]"


def ascii_mode():
    header("d3 ascii")
    L = c08_lists()
    NA = ["Drück_Max", "DRÜCK_MAX", "druck_max"]
    plan = [
        ("R-A2L-MATCH.43/1", "['VALUE' + U+007F]", ["VALUE\x7f"], "value", 20),
        ("R-A2L-MATCH.43/2", "['VALUE' + U+0080]", ["VALUE\x80"], "value", 20),
        ("R-A2L-MATCH.43/3", "NA", NA, "max", 20),
        ("R-A2L-MATCH.4/1", "NA", NA, "drück", 20),
        ("R-A2L-MATCH.4/2", "NA", NA, "DRÜCK", 20),
        ("R-A2L-MATCH.4/4 (new)", "['KEY']", ["KEY"], "Key", 20),
        ("R-A2L-MATCH.12/4 (old input)", "['٣٣٣_X']", ["٣٣٣_X"], "٣٣٤", 20),
        ("R-A2L-MATCH.12/4 (new input)", "C08", L["C08"], "ma٣", 3),
        ("R-A2L-MATCH.24/3 (old input)", "NA", NA, "drück", 20),
        ("R-A2L-MATCH.24/3 (new input)", "DR = ['druck_max', 'DRUCK_MAX']", ["druck_max", "DRUCK_MAX"], "drück", 20),
    ]
    for cid, lab, names, q, lim in plan:
        shipped = rank(q, build_label_index(names), lim)
        PIL.install(ascii_only=True)
        try:
            ix = lm.build_label_index(names)
            piloted = rank(q, ix, lim)
            n_ix = len(ix)
        finally:
            PIL.uninstall()
        print(f"\n  [{cid}] {lab}, query {ascii(q)}, limit {lim}\n    shipped  {fmt(shipped)}\n    .43      {fmt(piloted)}  (prepared names {n_ix})")
    print("\n=== .4 negative controls on the piloted lists (the mutation applied to the query)")
    PIL.install(ascii_only=True)
    try:
        na = lm.build_label_index(NA)
        strip = "".join(c for c in unicodedata.normalize("NFKD", "drück") if not unicodedata.combining(c))
        print(f"  accent folding: 'drück' -> {ascii(strip)} over NA -> {fmt(rank(strip, na, 20))}")
        k = chr(0x212A) + "ey"
        print(f"  str.lower: {ascii(k)}.lower() = {ascii(k.lower())} over ['KEY'] -> {fmt(rank(k.lower(), lm.build_label_index(['KEY']), 20))}")
        print(f"  str.lower on 'DRÜCK' -> {ascii('DRÜCK'.lower())} over NA -> {fmt(rank('DRÜCK'.lower(), na, 20))} (no difference: not a control)")
    finally:
        PIL.uninstall()
    print("\n=== AST1 (E5S-11: 50,000 names of 20 distinct 1-character tokens above U+FFFF), tracemalloc peak of one preparation")
    astral, cp = [], 0x10000
    for _ in range(50000):
        astral.append("_".join(chr(cp + t) for t in range(20)))
        cp += 20
    print(f"    {R.describe(astral)}")
    pk, dt, st, ix = P.peak_of(lambda: build_label_index(astral), 900)
    print(f"    shipped: {len(ix):,} names prepared, peak {pk:,} B = {pk / 1048576:.1f} MiB{'  > 64 MiB' if pk > 67108864 else ''} ({dt:.2f} s [{st}])")
    del ix
    PIL.install(ascii_only=True)
    try:
        pk, dt, st, ix = P.peak_of(lambda: lm.build_label_index(astral), 900)
    finally:
        PIL.uninstall()
    print(f"    .43:     {len(ix):,} names prepared, peak {pk:,} B = {pk / 1048576:.3f} MiB ({dt:.2f} s [{st}])")
    del ix
    print("\n=== census: ASCII names only? (.43 leaves every name of these lists in)")
    f = P.fixtures()
    for lab, names in [("REF", f["ref"]), ("REF6", f["ref6"]), ("LONG", f["long"])] + list(L.items()) + [
            ("CRAFT", T.craft_names()), ("U6", T.u6_names()), ("B4MAX", T.b4max_names()), ("W40", T.w40_names()), ("SUBO", T.subo_names())]:
        bad = [n for n in names if not n.isascii()]
        print(f"  {lab:6s} {len(names):>6,} names; non-ASCII {len(bad)}")
    print(f"\nload after = {P.load()}")


if __name__ == "__main__":
    {"keep": keep, "cases": cases, "det": det, "ascii": ascii_mode, "detail": detail, "walkex": walkex}[sys.argv[1]]()
