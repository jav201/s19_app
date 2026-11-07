#!/usr/bin/env python3
"""batch-103 Inc 4 E3 security probes. THROWAWAY EVIDENCE, NOT PRODUCT CODE.

Runs on cachyos-rtx only, next to an unchanged copy of the E2 pilot files
(PILOT_DIR). It drives IndexC (the compact index the graph pins; it classifies
each listed name with the E1 oracle evaluate_b) with pathological queries and
name lists. Every case runs under an address-space cap and a per-case alarm.
Modes: perf (cost probes), det (one hash-seed run, prints a digest),
spans (hostile characters: exceptions, span bounds, oracle agreement).
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
P3 = P4["P3"]
naive_rank_b, tokens = P3["naive_rank_b"], P3["tokens"]

CAP = int(os.environ.get("AS_CAP_GIB", "8")) << 30
resource.setrlimit(resource.RLIMIT_AS, (CAP, CAP))


class Budget(Exception):
    pass


def _alarm(signum, frame):
    raise Budget()


signal.signal(signal.SIGALRM, _alarm)


def run(fn, budget):
    gc.collect()
    signal.alarm(budget)
    t0 = time.perf_counter()
    try:
        out = fn()
        status = "ok"
    except Budget:
        out, status = None, f"STOPPED at {budget} s"
    except MemoryError:
        out, status = None, f"MemoryError (cap {CAP >> 30} GiB)"
    finally:
        signal.alarm(0)
    return time.perf_counter() - t0, status, out


def header():
    print(f"s19_app.__file__ = {s19_app.__file__}")
    print(f"python = {sys.version.split()[0]}  PYTHONHASHSEED = {os.environ.get('PYTHONHASHSEED')}")
    print(f"host = {os.uname().nodename}  load = {os.getloadavg()}  cpus = {os.cpu_count()}  RLIMIT_AS = {CAP >> 30} GiB")
    print(f"HOME = {os.environ.get('HOME')}  LOCALAPPDATA = {os.environ.get('LOCALAPPDATA')}  PILOT_DIR = {HERE}")


def load():
    sw_a = names_of(REPO / "examples/case_00_public/software_a.a2l")
    ref = (sw_a + [n + "_1" for n in sw_a] + [n + "_2" for n in sw_a] + [n + "_3" for n in sw_a])[:50000]
    return sw_a, ref


def series(idx, label, make, sizes, budget=150, limit=20):
    print(f"  -- {label}")
    for n in sizes:
        q = make(n)
        qt = len(tokens(q))
        dt, st, out = run(lambda: idx.rank(q, limit), budget)
        res = "-" if out is None else str(len(out))
        print(f"     n={n:<6} chars={len(q):<6} query tokens={qt:<6} rank {dt * 1000:10.1f} ms  {st:24s} results={res}")
        if dt > 60 or st != "ok":
            print("     (series stopped)")
            break


def perf():
    header()
    sw_a, ref = load()
    rng = random.Random(20261106)
    dt, st, idx = run(lambda: IndexC(ref), 120)
    print(f"\n=== A. REF (50,000 names) built in {dt:.2f} s [{st}]; queries with limit 20")
    series(idx, "one letter token repeated ('e ' * n)", lambda n: "e " * n, [3, 32, 256, 2048, 8192, 32768])
    series(idx, "four 1-letter tokens repeated ('e x q z ' * n)", lambda n: "e x q z " * n, [1, 16, 128, 1024, 8192])
    series(idx, "one long token ('a' * n)", lambda n: "a" * n, [32, 256, 1024, 4096, 16384, 65536])
    series(idx, "digit tokens ('0 ' * n)", lambda n: "0 " * n, [3, 256, 2048, 32768])
    pool = rng.sample(sw_a, 3000)
    series(idx, "pasted label list: n real names joined by ','", lambda n: ",".join(pool[:n]), [1, 10, 50, 200, 800])
    words = [t for nm in pool[:400] for t in (nm[a:b].lower() for a, b in tokens(nm)) if len(t) >= 3]

    def typo(w):
        s = list(w)
        s[0], s[1] = s[1], s[0]
        return "".join(s)

    series(idx, "n real words, each with a transposition, joined by ' '", lambda n: " ".join(typo(w) for w in words[:n]), [3, 10, 50, 200, 800])
    full = ",".join(pool)
    while len(full.encode()) > 65536:
        full = full[: full.rfind(",")]
    print(f"  -- the 64 KiB paste itself: {len(full)} chars, {full.count(',') + 1} names, {len(tokens(full))} query tokens: not run (extrapolate from the series)")
    del idx
    gc.collect()

    print("\n=== B. hostile name lists")
    dt, st, ix = run(lambda: IndexC(["VALUE_0001"] * 50000), 60)
    print(f"  B1 50,000 identical names: build {dt * 1000:.1f} ms [{st}] len {len(ix.names)}; rank 'value' {run(lambda: ix.rank('value', 20), 30)[0] * 1000:.2f} ms")
    c06 = names_of(REPO / "examples/case_06_large_nested_a2l/firmware.a2l")
    lens = sorted({len(n) for n in c06})
    print(f"  B2 case_06 (a tracked example file): {len(c06)} names, lengths {lens[:5]}")
    for label, names in (("first 50,000 of case_06", c06[:50000]), ("all of case_06", c06)):
        dt, st, ix = run(lambda: IndexC(names), 120)
        print(f"     {label}: build {dt:.2f} s [{st}]")
        for q in ["char", "char_0", "chr 0", "cahr", "meas 1", "c 0 1", "ch00", "mes_00001", "cahr_0001", "zz"]:
            times = []
            for _ in range(3):
                dt, st, out = run(lambda: ix.rank(q, 20), 120)
                times.append(dt)
                if st != "ok":
                    break
            rules = {} if out is None else {}
            for r in out or []:
                rules[r[1]] = rules.get(r[1], 0) + 1
            print(f"       rank {q!r:14} median {statistics.median(times) * 1000:9.1f} ms [{st}] {rules}")
        del ix
        gc.collect()

    print("  B3 one giant name 'x' + 'ab' * k beside 100 short names; queries 'ba', 'bab'")
    short = ref[:100]
    for k in (50_000, 500_000, 2_500_000):
        g = "x" + "ab" * k
        dt, st, ix = run(lambda: IndexC(short + [g]), 120)
        r1 = run(lambda: ix.rank("ba", 20), 120)
        r2 = run(lambda: ix.rank("bab", 20), 120)
        print(f"     len {len(g):>9,}: build {dt:.2f} s [{st}]; rank 'ba' {r1[0] * 1000:9.1f} ms [{r1[1]}]; 'bab' {r2[0] * 1000:9.1f} ms [{r2[1]}]")
        del ix
    print("  B4 one giant name 'value_' * k (k tokens) beside 100 short names; queries 'valeu' (fuzzy), 'vlu' (subsequence)")
    for k in (10_000, 100_000, 500_000):
        g = "value_" * k
        dt, st, ix = run(lambda: IndexC(short + [g]), 120)
        r1 = run(lambda: ix.rank("valeu", 20), 150)
        r2 = run(lambda: ix.rank("vlu", 20), 150)
        print(f"     k {k:>7,} (len {len(g):>9,}): build {dt:.2f} s [{st}]; rank 'valeu' {r1[0] * 1000:9.1f} ms [{r1[1]}]; 'vlu' {r2[0] * 1000:9.1f} ms [{r2[1]}]")
        del ix
    print("  B5 build memory: names of one unique random lowercase token each (trie amplification)")
    for count, length in ((5_000, 200), (5_000, 1_000), (20_000, 500)):
        r = random.Random(count * length)
        names = ["".join(r.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(length)) for _ in range(count)]
        gc.collect()
        tracemalloc.start()
        t0 = time.perf_counter()
        try:
            ix = IndexC(names)
            st = "ok"
        except MemoryError:
            ix, st = None, "MemoryError"
        dt = time.perf_counter() - t0
        cur, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        chars = count * length
        nodes = len(ix.nodes[1]) if ix else -1
        print(f"     {count:,} x {length} chars ({chars / 1048576:.1f} MiB of names): build {dt:.2f} s [{st}] trie nodes {nodes:,}  tracemalloc peak {peak / 1048576:.1f} MiB = {peak / chars:.1f} bytes per name character")
        del ix
        gc.collect()
    print(f"\nload after = {os.getloadavg()}")


HOSTILE = [
    "A[/x]B", "[@click=app.quit]OFF[/]", "Map[b]x", "esc\x1b[2Jname", "nul\x00name", "bell\x07x", "cr\rx",
    "éte_Val", "İstanbul_MAP", "straße_X", "ﬁle_X", "repl�_X", "lone\ud800sur_X",
    "max\U0010ffff_X", "漢字_Val", "rtl‮X_VAL", "zw​X", "٣٣٣_X", "tab\tname",
    "quoted name with spaces", "VALUE_0001", "value_0001", "Value_0001", "x" * 300, "_" * 50 + "a",
    "aB" * 100, "A" * 40 + "b", "9" * 64,
]


def spans():
    header()
    rng = random.Random(4242)
    idx = IndexC(HOSTILE)
    alphabet = "".join(sorted(set("".join(HOSTILE)))) + " _.[]"
    queries = [c for c in alphabet] + ["\ud800", "\U0010ffff", "é", "İ", "\x1b[2J", "[/x]", "[b]", "  \x1c VALUE", "\x00"]
    for _ in range(3000):
        nm = rng.choice(HOSTILE)
        a = rng.randrange(len(nm))
        q = nm[a : a + rng.randint(1, 8)]
        if rng.random() < 0.3:
            q = q.upper() if rng.random() < 0.5 else q.lower()
        if rng.random() < 0.2:
            q = q + " " + rng.choice(alphabet)
        queries.append(q)
    exc = bad_span = mism = same_obj = listed = 0
    first_bad = []
    for q in queries:
        for lim in (1, 5, 100):
            try:
                got = idx.rank(q, lim)
            except Exception as e:  # noqa: BLE001 - the probe counts every exception
                exc += 1
                first_bad.append(("exception", q, repr(e)))
                continue
            if got != naive_rank_b(q, HOSTILE, lim):
                mism += 1
            for name, rule, key, sp in got:
                listed += 1
                same_obj += any(name is h for h in HOSTILE)
                ok = all(0 <= s < e <= len(name) for s, e in sp) and all(sp[i][1] < sp[i + 1][0] for i in range(len(sp) - 1)) and len(sp) >= 1
                if not ok:
                    bad_span += 1
                    first_bad.append(("span", q, name, sp))
    print(f"queries {len(queries)} x 3 limits; listed entries {listed}; exceptions {exc}; spans outside the name, unsorted, touching or empty {bad_span}; IndexC != oracle {mism}; entries whose name is the very input object {same_obj}")
    for row in first_bad[:5]:
        print("  ", ascii(row))
    lower_len = [h for h in HOSTILE if len(h.lower()) != len(h)]
    print(f"names whose str.lower() changes their length (a span hazard the A-Z fold avoids): {ascii(lower_len)}")
    for q in ["[b]", "\x1b[2j", "a[/x]b", "nul\x00"]:
        print(f"  rank({ascii(q)}) -> {ascii(idx.rank(q, 3))}")


def det():
    sw_a, ref = load()
    c06 = names_of(REPO / "examples/case_06_large_nested_a2l/firmware.a2l")[:50000]
    rng = random.Random(20261107)
    qset = ["a", "e", "0", "zz", "ab", "JotafVod_msrqlLzL_kh2C_rWl_pfue._0_", "JotafVod_msr", "srqlLzL_", "0 jotaf", "JVmL",
            "xqzjvkw", "qqqq zzzz", "aaaa", "e e e", "Nzukij", "Ierxjr_Eud", "ledRing", "pposbxiif", "cnt", "temp_sensor_max",
            "x y z w v u", "pposbxiifkdgfiajnbbpvb_dyan_xvz1"]
    gen = []
    for _ in range(300):
        nm = rng.choice(ref)
        a = rng.randrange(len(nm))
        gen.append(nm[a : a + rng.randint(1, 10)])
    h = hashlib.sha256()
    n = 0
    for names, qs in ((ref, qset + gen), (c06, ["char", "chr 0", "cahr", "c 0 1", "meas 1"]), (HOSTILE, [c for c in "abex_[0́"])):
        ix = IndexC(list(names))
        for q in qs:
            for lim in (1, 20, 100):
                h.update(repr(ix.rank(q, lim)).encode("utf-8", "surrogatepass"))
                n += 1
    print(f"PYTHONHASHSEED={os.environ.get('PYTHONHASHSEED')} rankings={n} sha256={h.hexdigest()}")


def mem():
    """The fuzzy tier keeps one {token id: distance} map per query token until it picks candidates."""
    header()
    _, ref = load()
    idx = IndexC(ref)
    abc = " ".join("abcdefghijklmnopqrstuvwxyz") + " "
    for n in (1, 10, 100, 1260):
        q = abc * n
        gc.collect()
        tracemalloc.start()
        dt, st, out = run(lambda: idx.rank(q, 20), 300)
        cur, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        print(f"  ('a b c ... z ' * {n}): {len(q)} chars, {len(tokens(q))} query tokens: rank {dt * 1000:9.1f} ms (under tracemalloc) [{st}] results={'-' if out is None else len(out)}  tracemalloc peak {peak / 1048576:9.1f} MiB")
        if st != "ok":
            break
    print(f"load after = {os.getloadavg()}")


def cap():
    """Queries of at most CAPLEN characters over REF: does a length cap alone keep the 200 ms bound?"""
    header()
    sw_a, ref = load()
    idx = IndexC(ref)
    rng = random.Random(20261108)
    pool = rng.sample(sw_a, 400)
    longest = sorted(ref, key=lambda n: (-len(tokens(n)), n))[:2]
    for caplen in (64, 128, 256):
        def cut(s):
            return s[:caplen]
        qs = {
            "'e ' repeated": cut("e " * caplen),
            "'a b c ... z ' repeated": cut((" ".join("abcdefghijklmnopqrstuvwxyz") + " ") * 20),
            "'0 ' repeated": cut("0 " * caplen),
            "'a' repeated": "a" * caplen,
            "real names joined by ','": cut(",".join(pool)),
            "real names joined by ',' (other draw)": cut(",".join(pool[200:])),
            f"longest REF name ({len(tokens(longest[0]))} tokens)": cut(longest[0]),
            "the same name with a transposition": cut(longest[0][1] + longest[0][0] + longest[0][2:]),
        }
        print(f"  -- cap {caplen} characters")
        for label, q in qs.items():
            runs = []
            for _ in range(7):
                dt, st, out = run(lambda: idx.rank(q, 20), 60)
                runs.append(dt)
                if st != "ok":
                    break
            print(f"     {label:44s} chars={len(q):<4} tokens={len(tokens(q)):<4} median {statistics.median(runs) * 1000:8.1f} ms [{st}] results={'-' if out is None else len(out)}")
    print(f"load after = {os.getloadavg()}")


def prof():
    """Where the time goes on the first 50,000 case_06 names (one length: 13)."""
    import cProfile
    import pstats

    header()
    c06 = names_of(REPO / "examples/case_06_large_nested_a2l/firmware.a2l")[:50000]
    idx = IndexC(c06)
    real_ce = IndexC._case_exact
    for q in ["cahr", "chr 0", "ch00", "meas 1", "c 0 1"]:
        idx.rank(q, 20)
        calls = [0]

        def counting(self, *a, _f=real_ce):
            calls[0] += 1
            return _f(self, *a)

        IndexC._case_exact = counting
        t0 = time.perf_counter()
        out = idx.rank(q, 20)
        full = time.perf_counter() - t0
        IndexC._case_exact = lambda self, *a: False
        t0 = time.perf_counter()
        idx.rank(q, 20)
        no_ce = time.perf_counter() - t0
        IndexC._case_exact = real_ce
        groups = {}
        print(f"  {q!r:9}: rank {full * 1000:7.1f} ms; case-exact checks {calls[0]:,} for {len(out)} listed; with the case-exact check stubbed to False {no_ce * 1000:7.1f} ms")
    pr = cProfile.Profile()
    pr.enable()
    idx.rank("cahr", 20)
    pr.disable()
    st = pstats.Stats(pr)
    st.sort_stats("cumulative").print_stats(8)


if __name__ == "__main__":
    {"perf": perf, "det": det, "spans": spans, "mem": mem, "prof": prof, "cap": cap}[sys.argv[1]]()
