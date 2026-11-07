#!/usr/bin/env python3
"""batch-103 Inc 4 E5 security probe. THROWAWAY EVIDENCE, NOT PRODUCT CODE.

Runs on <runner> only, against the REAL module s19_app/tui/services/label_match.py
of a read-only COPY of the integrated tree (env TREE, first on PYTHONPATH). Adapted
from the E3 probes (evidence-e3/i4e3s-probe.py, sec-r2-probe.py, sec-r2-band.py):
their pilot classes IndexC / R2 are replaced by build_label_index + rank. The
fixtures (REF, REF6, LONG, QSET, PSET, LONG queries) are the test module's own
builders (tests/test_b103_label_match_perf.py), so the strings are identical.
The independent oracle is the E1 evaluate_b (uncapped OSA) from an unchanged copy of
the E3 pilot files (env PILOT_DIR), with the same order key and the 256 / 1,024 caps.
Every case runs under an address-space cap and a per-case alarm.

Modes: caps, perf, paste, mem, spans, det, adv, build.
"""
from __future__ import annotations

import cProfile
import gc
import hashlib
import importlib
import io
import os
import pstats
import random
import resource
import runpy
import signal
import statistics
import string
import sys
import time
import tracemalloc
from pathlib import Path

TREE = Path(os.environ["TREE"]).resolve()
PILOT = Path(os.environ["PILOT_DIR"]).resolve()

import s19_app  # noqa: E402
from s19_app.tui.services import label_match as lm  # noqa: E402
from s19_app.tui.services.label_match import LabelMatch, MatchRule, build_label_index, rank  # noqa: E402

assert Path(lm.__file__).resolve().is_relative_to(TREE), f"wrong module: {lm.__file__}"
T = importlib.import_module("tests.test_b103_label_match_perf")
assert Path(T.__file__).resolve().is_relative_to(TREE), f"wrong test module: {T.__file__}"

CAP = int(os.environ.get("AS_CAP_GIB", "8")) << 30
resource.setrlimit(resource.RLIMIT_AS, (CAP, CAP))
WS = " \t\n\r\x0b\x0c"
LOWER = string.ascii_lowercase
QCAP, NCAP = 256, 1024


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
        out, status = fn(), "ok"
    except Budget:
        out, status = None, f"STOPPED at {budget} s"
    except MemoryError:
        out, status = None, f"MemoryError (cap {CAP >> 30} GiB)"
    except Exception as e:  # noqa: BLE001 - the probe counts every exception
        out, status = None, f"EXCEPTION {e!r}"
    finally:
        signal.alarm(0)
    return time.perf_counter() - t0, status, out


def med(ix, q, limit=20, n=7, budget=120):
    runs, st, out = [], "ok", None
    for _ in range(n):
        dt, st, out = run(lambda: rank(q, ix, limit), budget)
        runs.append(dt)
        if st != "ok":
            break
    return statistics.median(runs), st, out


def peak_of(fn, budget=300):
    gc.collect()
    tracemalloc.start()
    dt, st, out = run(fn, budget)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return peak, dt, st, out


def load():
    return f"{tuple(round(x, 2) for x in os.getloadavg())}"


def header(mode):
    print(f"s19_app.__file__ = {s19_app.__file__}")
    print(f"label_match.__file__ = {lm.__file__}")
    print(f"label_match sha256 = {hashlib.sha256(Path(lm.__file__).read_bytes()).hexdigest()}")
    print(f"tests module = {T.__file__}")
    print(f"mode = {mode}  python = {sys.version.split()[0]}  PYTHONHASHSEED = {os.environ.get('PYTHONHASHSEED')}  hash('abc') = {hash('abc')}")
    print(f"host = {os.uname().nodename}  load = {load()}  cpus = {os.cpu_count()}  RLIMIT_AS = {CAP >> 30} GiB")
    print(f"HOME = {os.environ.get('HOME')}  LOCALAPPDATA = {os.environ.get('LOCALAPPDATA')}  PILOT_DIR = {PILOT}")


def bad_spans(rows):
    n = 0
    for m in rows or []:
        sp = m.spans
        ok = (isinstance(sp, tuple) and len(sp) >= 1
              and all(isinstance(s, int) and isinstance(e, int) and 0 <= s < e <= len(m.name) for s, e in sp)
              and all(sp[i][1] < sp[i + 1][0] for i in range(len(sp) - 1)))
        n += not ok
    return n


def tup(rows):
    return [(m.name, m.rule.value, m.edits, tuple(tuple(s) for s in m.spans)) for m in rows]


# ---------------------------------------------------------------- fixtures
_FIX = {}


def fixtures():
    if not _FIX:
        swa = T._read_names(T.SWA_PATH)
        ref = (swa + [n + "_1" for n in swa] + [n + "_2" for n in swa] + [n + "_3" for n in swa])[:50000]
        ref6 = T._read_names(T.CASE6_PATH)[:50000]
        long_ = ref[:49900] + ["a" * 1020 + "_" + str(i) for i in range(100)]
        assert len(ref) == len(set(ref)) == 50000 and len(ref6) == 50000 and len(long_) == 50000
        _FIX.update(swa=swa, ref=ref, ref6=ref6, long=long_)
    return _FIX


ABC = " ".join(LOWER) + " "


def extra_shapes():
    """E3 round-2 shapes beyond QSET (sec-r2-probe.py extra_shapes)."""
    return {
        "'1a' x 128": "1a" * 128, "'aB' x 128": "aB" * 128, "'aBcd' x 64": "aBcd" * 64,
        "'x y z w v u ' cut 256": ("x y z w v u " * 22)[:256], "'a' x 255": "a" * 255, "'e' x 255": "e" * 255,
        "'z' x 255": "z" * 255, "'ab' x 127 + 'a'": "ab" * 127 + "a", "'0123456789' cut 256": ("0123456789" * 26)[:256],
        "'0' x 256": "0" * 256, "'1 2 3 ' cut 256": ("1 2 3 " * 43)[:256], "'é' x 256": "é" * 256, "'é ' x 128": "é " * 128,
        "'漢字 ' cut 256": ("漢字 " * 86)[:256], "'Ä' x 256": "Ä" * 256, "'İ' x 256": "İ" * 256,
        "'U+1F600 ' x 128": "\U0001F600 " * 128, "'drück ' cut 256": ("drück " * 43)[:256], "'cnt ' x 64": "cnt " * 64,
    }


def ref6_shapes(ref6):
    """E3 round-2 repeated-token shapes over REF6 (sec-r2-probe.py ref6_shapes)."""
    return {
        "'c ' x 128": "c " * 128, "'m ' x 128": "m " * 128, "'0 ' x 128": "0 " * 128, "'1 ' x 128": "1 " * 128,
        "'char ' cut 256": ("char " * 52)[:256], "'chax ' cut 256": ("chax " * 52)[:256], "'mesa ' cut 256": ("mesa " * 52)[:256],
        "'c ' x 125 + 'chax'": "c " * 125 + "chax", "'0 ' x 125 + 'chax'": "0 " * 125 + "chax", "'1a' x 128": "1a" * 128,
        "REF6 names joined by ','": ",".join(ref6[:40])[:256], "'a b c ... z ' cut 256": (ABC * 5)[:256],
        "'e ' x 128": "e " * 128, "'a' x 256": "a" * 256,
    }


def long_shapes():
    """Beyond LONG_QUERIES: short query tokens against names of one 1,020-character token."""
    distinct = " ".join("aa" + c for c in LOWER if c != "a")
    return {
        "'aaq ' x 64 (one 1-edit token, repeated)": "aaq " * 64,
        "'aaaq ' x 51": "aaaq " * 51,
        "'aaaaaq ' x 36 (2-edit token, repeated)": "aaaaaq " * 36,
        "'aab' .. 'aaz' x 2, cut 256 (distinct 1-edit tokens)": ((distinct + " ") * 3)[:256],
        "'aaq'": "aaq",
        "'a' x 256": "a" * 256,
    }


# ---------------------------------------------------------------- oracle (E1 evaluate_b, via the E3 pilot copy)
_OR = {}


def oracle_fns():
    if not _OR:
        p3 = runpy.run_path(str(PILOT / "i4e1-pilot3.py"), run_name="i4e1_pilot_v3")
        _OR.update(evaluate_b=p3["evaluate_b"], RULES_B=p3["RULES_B"], osa_prefix=p3["P1"]["osa_prefix"])
    return _OR


def oracle(query, names, limit):
    o = oracle_fns()
    if limit < 1:
        return []
    q = query.strip(WS)
    if len(q) > QCAP:
        return []
    rows = []
    for name in dict.fromkeys(n for n in names if len(n) <= NCAP):
        ev = o["evaluate_b"](query, name)
        if ev is None:
            continue
        rule, key, sp = ev
        ce = (name == q) if rule == 0 else name.startswith(q) if rule == 1 else (q in name) if rule == 2 else False
        rows.append(((rule, key, len(name), 0 if ce else 1, name), ev))
    rows.sort(key=lambda r: r[0])
    return [(k[4], o["RULES_B"][ev[0]], ev[1] if ev[0] == 4 else 0, tuple(tuple(s) for s in ev[2])) for k, ev in rows[:limit]]


# ---------------------------------------------------------------- instrumentation
CALLS: dict = {}
MAXLEN: dict = {}
IN_CLASSIFY = [False]


def instrument(names):
    orig = {}
    for fn in names:
        f = getattr(lm, fn)
        orig[fn] = f

        def wrap(*a, _f=f, _n=fn, **k):
            key = _n + (" (in _classify)" if IN_CLASSIFY[0] and _n != "_classify" else "")
            CALLS[key] = CALLS.get(key, 0) + 1
            if a and isinstance(a[0], str):
                MAXLEN[_n] = max(MAXLEN.get(_n, 0), len(a[0]))
            if _n == "_classify":
                IN_CLASSIFY[0] = True
                try:
                    return _f(*a, **k)
                finally:
                    IN_CLASSIFY[0] = False
            return _f(*a, **k)

        setattr(lm, fn, wrap)
    return orig


def restore(orig):
    for k, v in orig.items():
        setattr(lm, k, v)


WATCH = ["_parse_query", "_fold", "_tokens", "_at_boundary", "_char_mask", "_token_range", "_fuzzy_tier",
         "_fuzzy_token_distances", "_prefix_distance", "_classify", "_subsequence", "_order_key"]


def counted(fn, watch=WATCH):
    CALLS.clear()
    MAXLEN.clear()
    orig = instrument(watch)
    try:
        out = fn()
    finally:
        restore(orig)
    return out, dict(CALLS), dict(MAXLEN)


# ---------------------------------------------------------------- mode caps
def osa_prefix_full(q, t):
    """Reference: min over the prefixes of t (empty included) of the full OSA distance."""
    m, n = len(q), len(t)
    D = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m + 1):
        D[i][0] = i
    for j in range(n + 1):
        D[0][j] = j
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            v = min(D[i - 1][j] + 1, D[i][j - 1] + 1, D[i - 1][j - 1] + (q[i - 1] != t[j - 1]))
            if i > 1 and j > 1 and q[i - 1] == t[j - 2] and q[i - 2] == t[j - 1]:
                v = min(v, D[i - 2][j - 2] + 1)
            D[i][j] = v
    return min(D[m])


def caps():
    header("caps")
    c08 = [n for n in (PILOT / "case08-names.txt").read_text(encoding="utf-8").split("\n") if n]
    ix08 = build_label_index(c08)
    print(f"\n=== A. R-A2L-MATCH.38: the 256-character cap runs before any parse (C08, {len(ix08)} names, limit 20)")
    pool = random.Random(20261106).sample(fixtures()["swa"], 3000)
    paste = ",".join(pool)
    while len(paste) > 65536:
        paste = paste[: paste.rfind(",")]
    qs = {
        ".38/1 'VALUE_0001_' x 23 + 'VAL' (256)": "VALUE_0001_" * 23 + "VAL",
        ".38/2 'VALUE_0001_' x 23 + 'VALU' (257)": "VALUE_0001_" * 23 + "VALU",
        "256 'a' + the six whitespace chars on both ends (stripped: 256)": WS + "a" * 256 + WS,
        "U+00A0 + 255 'a' (not stripped: 256)": " " + "a" * 255,
        "U+00A0 + 256 'a' (not stripped: 257)": " " + "a" * 256,
        "U+0085 + 256 'a' (not stripped: 257)": "\u0085" + "a" * 256,
        "256 x U+1F600 (astral, 256 code points)": "\U0001F600" * 256,
        "257 x U+1F600": "\U0001F600" * 257,
        f"64 KiB paste: {paste.count(',') + 1} SWA names joined by ',' ({len(paste)} chars)": paste,
        "'e ' x 32768 (65,536 chars)": "e " * 32768,
        "'\\x00' x 65536": "\x00" * 65536,
        "'\\ud800' x 65536 (lone surrogates)": "\ud800" * 65536,
        "65,000 spaces + 'VALUE' (stripped: 5)": " " * 65000 + "VALUE",
    }
    for lab, q in qs.items():
        out, calls, _ = counted(lambda: rank(q, ix08, 20))
        work = {k: v for k, v in calls.items() if k != "_parse_query"}
        print(f"  stripped len {len(q.strip(WS)):>6}: result {len(out):>2} entries; _parse_query calls {calls.get('_parse_query', 0)}; "
              f"other matcher calls {sum(work.values()):>7}  {lab}")
        if len(q.strip(WS)) <= 64 or "38/1" in lab:
            print(f"      -> {ascii(tup(out)[:2])[:150]}")
    print("\n=== B. R-A2L-MATCH.39: the 1,024-character cap runs before fold, mask and tokenising (build)")
    names = ["x" * 1024, "y" * 1025, "z" * 65536, "w" * 1_000_000, "SHORT_name", "x" * 1024]
    ix, calls, maxlen = counted(lambda: build_label_index(names))
    print(f"  names in {[len(n) for n in names]} -> len(index) {len(ix)}; longest text seen by _fold {maxlen.get('_fold')}, "
          f"_char_mask {maxlen.get('_char_mask')}, _tokens {maxlen.get('_tokens')}; calls {calls}")
    for q in ("x", "y", "z", "w", "short"):
        r = rank(q, ix, 5)
        print(f"  rank({q!r}) -> {[(len(m.name), m.rule.value, m.spans) for m in r]}")
    dt, st, _ = run(lambda: build_label_index(["v" * 10_000_000] + ["k" * 1025] * 1000), 60)
    print(f"  build of one 10,000,000-char name + 1,000 x 1,025-char names: {dt * 1000:.1f} ms [{st}]")

    print("\n=== C. A-2: duplicate query tokens collapsed (calls during one ranking)")
    f = fixtures()
    ref_ix = build_label_index(f["ref"])
    ref6_ix = build_label_index(f["ref6"])
    for lab, ix_, q in (("REF", ref_ix, "cnt " * 64), ("REF", ref_ix, "1a" * 128), ("REF", ref_ix, "e " * 128),
                        ("REF6", ref6_ix, "0 " * 125 + "chax"), ("REF6", ref6_ix, "chr " * 64), ("REF6", ref6_ix, "c " * 128)):
        out, calls, _ = counted(lambda: rank(q, ix_, 20))
        qt = len(lm._tokens(q.strip(WS)))
        dq = len({lm._fold(q.strip(WS))[s:e] for s, e in lm._tokens(q.strip(WS))})
        print(f"  {lab:4s} {q[:24]!r:28} query tokens {qt:>3} distinct {dq:>2}: _token_range {calls.get('_token_range', 0):>3} "
              f"(+{calls.get('_token_range (in _classify)', 0)} in _classify); _fuzzy_token_distances {calls.get('_fuzzy_token_distances', 0):>3}; "
              f"_prefix_distance {calls.get('_prefix_distance', 0):>6} in the tier, {calls.get('_prefix_distance (in _classify)', 0):>6} in _classify; listed {len(out)}")

    print("\n=== D. step 4: the fuzzy tier stops when no candidate is left (walks = _fuzzy_token_distances calls)")
    al = [f"alpha_{i:03d}" for i in range(400)]
    br = [f"bravo_{i:03d}" for i in range(400)]
    ixab = build_label_index(al + br)
    many = "alpah brvao charlie delta echoo foxtrot golff hotel indiaa julliet kilo lima mike novem oscar papa"
    for lab, q in (("first map empty ('qqqqx' first)", "qqqqx " + many),
                   ("400 'alpha' candidates, then 'brvao' empties the set (2 walks, of 16 distinct)", many),
                   ("one token, 400 candidates", "alpah")):
        out, calls, _ = counted(lambda: rank(q, ixab, 20))
        print(f"  walks {calls.get('_fuzzy_token_distances', 0):>2}; _prefix_distance {calls.get('_prefix_distance', 0):>5}; listed {len(out):>2}  {lab}")
    ixt = build_label_index(["alpah_zz", "other_name"])
    out, calls, _ = counted(lambda: rank("alpah_z", ixt, 20))
    print(f"  walks {calls.get('_fuzzy_token_distances', 0):>2}; listed {len(out)} {[m.rule.value for m in out]}  "
          f"every fuzzy candidate already taken by the prefix tier ('alpah_z' over ['alpah_zz', 'other_name'])")

    print("\n=== E. A-3: banded _prefix_distance equals the full OSA prefix distance (capped), and its cost")
    o = oracle_fns()
    rng = random.Random(20261112)
    mism = mism_pilot = n = 0
    first = []
    for _ in range(20000):
        alpha = rng.choice(["ab", "abc", "aab", LOWER[:5]])
        q = "".join(rng.choice(alpha) for _ in range(rng.randint(1, 9)))
        t = "".join(rng.choice(alpha) for _ in range(rng.randint(0, 14)))
        if rng.random() < 0.3 and len(q) > 2:
            p = rng.randrange(len(q) - 1)
            t = q[:p] + q[p + 1] + q[p] + q[p + 2:] + t[: rng.randint(0, 4)]
        for cap in (0, 1, 2):
            want = min(osa_prefix_full(q, t), cap + 1)
            pilot = min(o["osa_prefix"](q, t), cap + 1)
            got = lm._prefix_distance(q, t, cap)
            n += 1
            mism_pilot += pilot != want
            if got != want:
                mism += 1
                first.append((q, t, cap, got, want, pilot))
    print(f"  {n} (pair, cap) checks: banded _prefix_distance != full reference {mism}; pilot osa_prefix != full reference {mism_pilot}  {first[:3]}")
    for q, t, cap in (("a" * 255 + "b", "a" * 1000, 2), ("a" * 128 + "b", "a" * 1020, 1), ("aaq", "a" * 1020, 1),
                      ("aaaaaq", "a" * 1020, 2), ("aaq", "aaaa", 1), ("abq", "ab", 1)):
        runs = []
        for _ in range(7):
            t0 = time.perf_counter()
            v = lm._prefix_distance(q, t, cap)
            runs.append(time.perf_counter() - t0)
        print(f"  _prefix_distance(len {len(q):>3}, len {len(t):>4}, cap {cap}) = {v}  median {statistics.median(runs) * 1e6:9.1f} us")
    print(f"\nload after = {load()}")


# ---------------------------------------------------------------- mode perf
def perf():
    header("perf")
    f = fixtures()
    dt, st, ref_ix = run(lambda: build_label_index(f["ref"]), 120)
    print(f"REF built in {dt:.2f} s [{st}]")
    dt, st, ref6_ix = run(lambda: build_label_index(f["ref6"]), 120)
    print(f"REF6 built in {dt:.2f} s [{st}]")
    dt, st, long_ix = run(lambda: build_label_index(f["long"]), 120)
    print(f"LONG built in {dt:.2f} s [{st}]")
    plan = [
        ("REF", ref_ix, "QSET (33, .36/1)", {f"{i:02d} {q[:44]}": q for i, q in enumerate(T.qset33(f["swa"], f["ref"]))}, 0.2),
        ("REF", ref_ix, "PSET over REF (.40/1)", dict(T.pset_ref()), 1.0),
        ("REF", ref_ix, "E3 extra shapes (beyond the tests)", extra_shapes(), 1.0),
        ("REF6", ref6_ix, "REF6 queries (12, .36/1)", {q: q for q in T.REF6_QUERIES}, 0.2),
        ("REF6", ref6_ix, "PSET over REF6 (.40/1)", dict(T.pset_ref6(f["swa"])), 1.0),
        ("REF6", ref6_ix, "E3 REF6 shapes (beyond the tests)", ref6_shapes(f["ref6"]), 1.0),
        ("REF6", ref6_ix, "E3 extra shapes over REF6 (beyond the tests)", extra_shapes(), 1.0),
        ("LONG", long_ix, "LONG queries (.40/2)", dict(T.LONG_QUERIES), 1.0),
        ("LONG", long_ix, "short-token shapes over LONG (beyond the tests)", long_shapes(), 1.0),
    ]
    summary = []
    for lab, ix, group, qs, bound in plan:
        print(f"\n=== {lab}: {group}; limit 20, median of 7; bound {bound * 1000:.0f} ms; load {load()}")
        worst = (0.0, "")
        exc = spans = over = 0
        for qlab, q in qs.items():
            m, st, out = med(ix, q)
            exc += st != "ok"
            spans += bad_spans(out)
            over += m > bound
            worst = max(worst, (m, qlab))
            flag = "  > bound" if m > bound else ""
            print(f"     {m * 1000:8.1f} ms [{st}] n={'-' if out is None else len(out):<3} chars={len(q.strip(WS)):<4} {qlab!r}{flag}")
        summary.append((lab, group, worst, exc, spans, over, len(qs)))
        print(f"  worst {worst[0] * 1000:.1f} ms ({worst[1]}); non-ok {exc}; bad spans {spans}; over the bound {over} of {len(qs)}; load {load()}")
    print("\n=== summary")
    for lab, group, worst, exc, spans, over, nq in summary:
        print(f"  {lab:4s} {group:48s} worst {worst[0] * 1000:8.1f} ms ({worst[1][:40]}); non-ok {exc}; bad spans {spans}; over {over}/{nq}")
    print(f"\nload after = {load()}")


# ---------------------------------------------------------------- mode paste
def paste():
    header("paste")
    f = fixtures()
    pool = random.Random(20261106).sample(f["swa"], 3000)
    full = ",".join(pool)
    while len(full) > 65536:
        full = full[: full.rfind(",")]
    shapes = {
        f"{full.count(',') + 1} SWA names joined by ','": full,
        "'e ' x 32768": "e " * 32768, "'a' x 65536": "a" * 65536, "'1a' x 32768": "1a" * 32768,
        "'é' x 65536": "é" * 65536, "'a b c ... z ' x 1260": ABC * 1260, "'U+1F600' x 65536": "\U0001F600" * 65536,
        "'\\x00' x 65536": "\x00" * 65536, "'\\ud800' x 65536": "\ud800" * 65536,
        "65,000 spaces + 'VALUE' (stripped 5 chars: ranked)": " " * 65000 + "VALUE",
        "32,000 spaces + 'a' x 300 + 32,000 spaces": " " * 32000 + "a" * 300 + " " * 32000,
        "'a' x 257 (just over)": "a" * 257,
    }
    for lab, ix in (("REF", build_label_index(f["ref"])), ("REF6", build_label_index(f["ref6"]))):
        print(f"\n=== {lab} prepared; limit 20; median of 5, then one ranking under tracemalloc; load {load()}")
        for slab, q in shapes.items():
            m, st, out = med(ix, q, n=5, budget=60)
            pk, _, st2, _ = peak_of(lambda: rank(q, ix, 20), 60)
            print(f"     {m * 1000:9.3f} ms [{st}] peak {pk / 1024:9.1f} KiB [{st2}] result={'-' if out is None else len(out):<3} "
                  f"len={len(q):<6} {slab!r}")
    print(f"\nload after = {load()}")


# ---------------------------------------------------------------- mode mem
def mem():
    header("mem")
    f = fixtures()
    gc.collect()
    pk, dt, st, ix = peak_of(lambda: build_label_index(f["ref"]), 300)
    print(f"REF build: tracemalloc peak {pk:,} B ({pk / 1048576:.1f} MiB; .37 bound 67,108,864) {dt:.2f} s under tracemalloc [{st}]")
    del ix
    for lab, names, qs in (
        ("REF", f["ref"], {**{q[:40]: q for q in T.qset33(f["swa"], f["ref"])}, **dict(T.pset_ref()), **extra_shapes()}),
        ("REF6", f["ref6"], {**{q: q for q in T.REF6_QUERIES}, **dict(T.pset_ref6(f["swa"])), **ref6_shapes(f["ref6"])}),
        ("LONG", f["long"], {**dict(T.LONG_QUERIES), **long_shapes()}),
    ):
        ix = build_label_index(names)
        rows = []
        for qlab, q in qs.items():
            rank(q, ix, 20)
            pk, dt, st, _ = peak_of(lambda: rank(q, ix, 20), 120)
            rows.append((pk, qlab, st))
        rows.sort(reverse=True)
        print(f"\n=== {lab}: {len(rows)} shapes; tracemalloc peak of one ranking, top 6")
        for pk, qlab, st in rows[:6]:
            print(f"     {pk / 1048576:8.2f} MiB [{st}] {qlab!r}")
        del ix
        gc.collect()
    print(f"\nload after = {load()}")


# ---------------------------------------------------------------- mode spans
HOSTILE = [
    "A[/x]B", "[@click=app.quit]OFF[/]", "Map[b]x", "esc\x1b[2Jname", "nul\x00name", "bell\x07x", "cr\rx",
    "éte_Val", "İstanbul_MAP", "straße_X", "ﬁle_X", "repl�_X", "lone\ud800sur_X",
    "max\U0010ffff_X", "漢字_Val", "rtl‮X_VAL", "zw​X", "٣٣٣_X", "tab\tname",
    "quoted name with spaces", "VALUE_0001", "value_0001", "Value_0001", "x" * 300, "_" * 50 + "a",
    "aB" * 100, "A" * 40 + "b", "9" * 64, "x" * 1024, "y" * 1025, "DiscountCount", "abcdefg_count",
    # E5 additions: combining marks, joiners, BOM, astral, surrogate halves, NUL runs, C1, line separators, caps edges
    "éte_Val", "́́lead_comb", "à́̂b_X", "‍_zwj_x", "﻿bom_X", "\U0001F600_smile",
    "𐀀pair_X", "\udfff_low", "\x00" * 8, "\x00", "nul_\x00_mid", "\x7f\x80\x9f_c1", " line sep",
    "AİB", " nbsp_X", "\x1c_fs_X", "\u0085nel_X", "mixedCASE_ÄÖÜ_x", "x" * 1000 + "Y" * 24,
    "_".join(["a"] * 500), "aB" * 512, "1a" * 512, "", " ", "￿_nonchar",
]


def spans():
    header("spans")
    rng = random.Random(4242)
    idx = build_label_index(HOSTILE)
    print(f"hostile names {len(HOSTILE)}; indexed {len(idx)} (duplicates and names over 1,024 characters left out)")
    alphabet = "".join(sorted(set("".join(HOSTILE)))) + " _.[]"
    queries = list(alphabet) + ["\ud800", "\udc00", "\U0010ffff", "é", "é", "́", "́" * 10, "İ", "\x1b[2J", "[/x]", "[b]",
                                "  \x1c VALUE", "\x00", "\x00" * 300, "﻿", "Aİ", "x" * 256, "x" * 257, "y" * 256,
                                "İ" * 256, "1a" * 128, "ab" * 128, "aB" * 128, "_".join("a" * 128), " ", "pair", "𐀀"]
    for _ in range(3000):
        nm = rng.choice([h for h in HOSTILE if h])
        a = rng.randrange(len(nm))
        q = nm[a:a + rng.randint(1, 8)]
        if rng.random() < 0.3:
            q = q.upper() if rng.random() < 0.5 else q.lower()
        if rng.random() < 0.2:
            q = q + " " + rng.choice(alphabet)
        queries.append(q)
    exc = bad = mism = listed = same_obj = 0
    first = []
    t0 = time.perf_counter()
    for q in queries:
        for lim in (1, 5, 100):
            try:
                got = rank(q, idx, lim)
            except Exception as e:  # noqa: BLE001
                exc += 1
                first.append(("exception", ascii(q[:40]), repr(e)))
                continue
            listed += len(got)
            same_obj += sum(any(m.name is h for h in HOSTILE) for m in got)
            b = bad_spans(got)
            bad += b
            if b:
                first.append(("span", ascii(q[:40]), lim))
            if tup(got) != oracle(q, HOSTILE, lim):
                mism += 1
                first.append(("oracle mismatch", ascii(q[:40]), lim))
    print(f"queries {len(queries)} x 3 limits ({time.perf_counter() - t0:.0f} s); listed entries {listed}; exceptions {exc}; "
          f"bad spans (empty, outside [0, len(name)), unsorted or touching) {bad}; rank != oracle {mism}; entries whose name is the input object {same_obj}")
    for row in first[:6]:
        print("   ", row)

    print("\n=== argument checks (I-3 pins the TypeError texts)")

    class S(str):
        pass

    checks = [
        ("build_label_index(['a', None])", lambda: build_label_index(["a", None])),
        ("build_label_index(['a', b'b'])", lambda: build_label_index(["a", b"b"])),
        ("build_label_index([1])", lambda: build_label_index([1])),
        ("build_label_index(['a', ['x']])", lambda: build_label_index(["a", ["x"]])),
        ("build_label_index('abc')", lambda: build_label_index("abc")),
        ("build_label_index(b'abc')", lambda: build_label_index(b"abc")),
        ("build_label_index(bytearray(b'ab'))", lambda: build_label_index(bytearray(b"ab"))),
        ("build_label_index(None)  [not pinned]", lambda: build_label_index(None)),
        ("build_label_index(iter([]))", lambda: len(build_label_index(iter([])))),
        ("build_label_index([S('Sub_name')]) then rank('sub')", lambda: tup(rank("sub", build_label_index([S("Sub_name")]), 5))),
        ("rank(None, ix, 20)", lambda: rank(None, idx, 20)),
        ("rank(b'x', ix, 20)", lambda: rank(b"x", idx, 20)),
        ("rank(None, ix, 'x')  [query checked first]", lambda: rank(None, idx, "x")),
        ("rank('x', ix, True)", lambda: rank("x", idx, True)),
        ("rank('x', ix, 2.0)", lambda: rank("x", idx, 2.0)),
        ("rank('x', ix, -5)", lambda: rank("x", idx, -5)),
        ("rank('x', ix, 0)", lambda: rank("x", idx, 0)),
        ("rank('x', ix, 10**30) -> count", lambda: len(rank("x", idx, 10 ** 30))),
        ("rank(S(' VALUE '), ix, 3)", lambda: tup(rank(S(" VALUE "), idx, 3))),
    ]
    for lab, fn in checks:
        try:
            r = fn()
            print(f"  {lab:52s} -> returned {ascii(r)[:110]}")
        except Exception as e:  # noqa: BLE001
            print(f"  {lab:52s} -> {type(e).__name__}: {e}")

    print("\n=== purity: private buffers and the argument list unchanged after rankings (E3S-07)")
    f = fixtures()
    src = list(f["ref6"][:5000]) + HOSTILE
    before_src = list(src)
    ix = build_label_index(src)

    def snap(i):
        return tuple((k, (v.tobytes() if hasattr(v, "tobytes") else v)) for k, v in
                     ((k, getattr(i, k)) for k in ("names", "_folded", "_masks", "_tokens", "_name_token_ids", "_name_token_starts",
                                                   "_postings", "_posting_starts", "_trie_chars", "_trie_depth", "_trie_first", "_trie_end")))
    s0 = hashlib.sha256(repr(snap(ix)).encode("utf-8", "surrogatepass")).hexdigest()
    for q in queries[:400] + list(T.REF6_QUERIES) + ["0 " * 125 + "chax"]:
        rank(q, ix, 20)
    s1 = hashlib.sha256(repr(snap(ix)).encode("utf-8", "surrogatepass")).hexdigest()
    print(f"  buffers sha256 before {s0[:16]} after {s1[:16]} equal {s0 == s1}; argument list unchanged {src == before_src}")

    print("\n=== huge lists (no count cap: cost linear in the list)")
    c06 = T._read_names(T.CASE6_PATH)
    pk, dt, st, ix = peak_of(lambda: build_label_index(c06), 600)
    print(f"  all of case_06: {len(c06):,} names -> build {dt:.2f} s under tracemalloc [{st}], peak {pk / 1048576:.1f} MiB")
    if ix is not None:
        worst = max((med(ix, q, n=3)[0], q) for q in T.REF6_QUERIES)
        print(f"     worst REF6 query over all {len(ix):,}: {worst[0] * 1000:.1f} ms ({worst[1]!r})")
    del ix
    big = [f"N{i:07d}_sig" for i in range(1_000_000)]
    dt, st, ix = run(lambda: build_label_index(big), 600)
    print(f"  1,000,000 short names: build {dt:.2f} s [{st}]; ru_maxrss now {resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024:.0f} MiB")
    if ix is not None:
        for q in ("n0000001", "sig", "n000x001", "zzz"):
            m, st2, out = med(ix, q, n=3)
            print(f"     rank {q!r:12} median {m * 1000:8.1f} ms [{st2}] n={'-' if out is None else len(out)} bad spans {bad_spans(out)}")
    print(f"\nload after = {load()}")


# ---------------------------------------------------------------- mode det
def det():
    header("det")
    f = fixtures()
    rng = random.Random(20261107)
    gen = []
    for _ in range(300):
        nm = rng.choice(f["ref"])
        a = rng.randrange(len(nm))
        gen.append(nm[a:a + rng.randint(1, 10)])
    h = hashlib.sha256()
    n = 0
    t0 = time.perf_counter()
    for names, qs in ((f["ref"], T.qset33(f["swa"], f["ref"]) + [q for _, q in T.pset_ref()] + list(extra_shapes().values()) + gen),
                      (f["ref6"], list(T.REF6_QUERIES) + [q for _, q in T.pset_ref6(f["swa"])] + list(ref6_shapes(f["ref6"]).values())),
                      (f["long"], [q for _, q in T.LONG_QUERIES] + list(long_shapes().values())),
                      (HOSTILE, list("abex_[0́") + ["x" * 256, "1a" * 128, "\ud800", "é", "\x00"])):
        ix = build_label_index(list(names))
        for q in qs:
            for lim in (1, 20, 100):
                h.update(repr(tup(rank(q, ix, lim))).encode("utf-8", "surrogatepass"))
                n += 1
    print(f"PYTHONHASHSEED={os.environ.get('PYTHONHASHSEED')} hash('abc')={hash('abc')} rankings={n} sha256={h.hexdigest()} ({time.perf_counter() - t0:.0f} s)")


# ---------------------------------------------------------------- mode adv (shapes beyond PSET / LONG)
def b25(i, width, alphabet):
    s = []
    for _ in range(width):
        i, r = divmod(i, len(alphabet))
        s.append(alphabet[r])
    return "".join(s)


def crafted(ref_ix, n_crafted, seed, distinct_junk=True):
    """Names that every query token of memo_query() matches, each with many other tokens.
    head: a digit run no REF token starts with (0 allowed edits: walked first, it yields only these names;
    every 2- and 3-letter prefix occurs in REF). hits: 50 three-letter camel tokens ('Abc', ...) whose query
    token hit+'q' (4 letters, 1 edit away) has an empty range in REF, so the token tier finds nothing.
    junk: four-letter camel tokens (no 'q'), distinct across names when distinct_junk (so the
    per-(query token, token id) memo never hits)."""
    def empty(p):
        lo, hi = lm._token_range(ref_ix._tokens, p)
        return lo == hi
    head = next(h for h in (f"{v:06d}" for v in range(987654, 0, -7919)) if empty(h))
    letters = [c for c in LOWER if c != "q"]
    rng0 = random.Random(7)
    pairs, seen = [], set()
    while len(pairs) < 50:
        h = "".join(rng0.choice(letters) for _ in range(3))
        if h not in seen and empty(h + "q"):
            seen.add(h)
            pairs.append(h)
    rng = random.Random(seed)
    k_junk = (NCAP - len(head) - 3 * len(pairs)) // 4
    pool = rng.sample(range(len(letters) ** 4), n_crafted * k_junk) if distinct_junk else [rng.randrange(len(letters) ** 4) for _ in range(n_crafted * k_junk)]
    names = []
    for i in range(n_crafted):
        junk = "".join(b25(v, 4, letters).capitalize() for v in pool[i * k_junk:(i + 1) * k_junk])
        names.append(head + "".join(p.capitalize() for p in pairs) + junk)
    assert len(set(names)) == n_crafted and all(len(n) <= NCAP for n in names)
    return head, pairs, names


def memo_query(head, pairs, n_tokens):
    """head (0 edits) + (n_tokens - 1) four-letter tokens hit+'q', each 1 edit from the hit
    and each with an empty token range (so the token tier finds nothing)."""
    return " ".join([head] + [p + "q" for p in pairs[: n_tokens - 1]])


def adv():
    header("adv")
    f = fixtures()
    ref_ix = build_label_index(f["ref"])
    print("\n=== A1. per-candidate check (step 4, <= 300 candidates) over crafted names + REF padding to 50,000")
    for n_crafted, distinct_junk in ((300, True), (2000, False)):
        head, pairs, names = crafted(ref_ix, n_crafted, 20261113 + n_crafted, distinct_junk)
        lst = names + f["ref"][: 50000 - n_crafted]
        dt, st, ix = run(lambda: build_label_index(lst), 300)
        ntok = len(lm._tokens(names[0]))
        print(f"\n  {n_crafted} crafted names of {len(names[0])} chars ({ntok} tokens each, junk distinct across names: {distinct_junk}) "
              f"+ {50000 - n_crafted} REF names: build {dt:.2f} s [{st}], {len(ix):,} names, {len(ix._tokens):,} distinct tokens; load {load()}")
        for nq in (4, 8, 16, 32, 51):
            q = memo_query(head, pairs, nq)
            m, st, out = med(ix, q, n=3, budget=180)
            rules = sorted({r.rule.value for r in out}) if out else "-"
            print(f"     {nq:>2} query tokens ({len(q):>3} chars): median of 3 {m * 1000:9.1f} ms [{st}] listed {'-' if out is None else len(out)} {rules}"
                  f" bad spans {bad_spans(out)}{'  > 1.0 s (.40)' if m > 1.0 else ''}")
        q = memo_query(head, pairs, 51)
        out, calls, _ = counted(lambda: rank(q, ix, 20))
        print(f"     51 tokens, counted: walks {calls.get('_fuzzy_token_distances', 0)}; _prefix_distance {calls.get('_prefix_distance', 0):,} in the tier, "
              f"{calls.get('_prefix_distance (in _classify)', 0):,} in _classify ({calls.get('_classify', 0)} listed names)")
        pk, dt, st, _ = peak_of(lambda: rank(q, ix, 20), 600)
        print(f"     51 tokens, one ranking under tracemalloc: peak {pk / 1048576:9.1f} MiB  ({dt:.1f} s [{st}])")
        if n_crafted == 300:
            q16 = memo_query(head, pairs, 16)
            pk, dt, st, _ = peak_of(lambda: rank(q16, ix, 20), 600)
            print(f"     16 tokens, one ranking under tracemalloc: peak {pk / 1048576:9.1f} MiB  ({dt:.1f} s [{st}])")
            pr = cProfile.Profile()
            pr.enable()
            rank(q, ix, 20)
            pr.disable()
            buf = io.StringIO()
            pstats.Stats(pr, stream=buf).sort_stats("tottime").print_stats(6)
            print("     cProfile (51 tokens), top by own time:")
            for line in buf.getvalue().splitlines():
                if "label_match.py" in line or "ncalls" in line or "{method" in line or "{built-in" in line:
                    print("       " + line.replace(str(TREE), "<tree>")[:150])
        del ix
        gc.collect()

    print("\n=== A2. _classify over listed names: repeated short tokens against one 1,020-character token (LONG)")
    long_ix = build_label_index(f["long"])
    for lab, q in long_shapes().items():
        m, st, out = med(long_ix, q, n=5, budget=120)
        out2, calls, _ = counted(lambda: rank(q, long_ix, 20))
        print(f"     {m * 1000:8.1f} ms [{st}] listed {len(out2)}; _prefix_distance {calls.get('_prefix_distance', 0):>5} in the tier, "
              f"{calls.get('_prefix_distance (in _classify)', 0):>5} in _classify  {lab}")

    print("\n=== A3. substring key over every SUBSTRING name (residual E3S-03 (c)): names 'x' + 'ab' * 509 + 'Q' + tag (1,024 chars), query 'ba'")
    for n in (5000, 50000):
        names = ["x" + "ab" * 509 + "Q" + b25(i, 4, LOWER) for i in range(n)]
        lst = names + f["ref"][: max(0, 50000 - n)]
        dt, st, ix = run(lambda: build_label_index(lst), 600)
        print(f"  {n:,} crafted + {max(0, 50000 - n):,} REF names: build {dt:.2f} s [{st}] (.35 bound 5.0 s); load {load()}")
        if ix is not None:
            for q in ("ba", "bab", "xa"):
                m, st2, out = med(ix, q, n=3, budget=300)
                print(f"     rank {q!r:6} median of 3 {m * 1000:9.1f} ms [{st2}] listed {'-' if out is None else len(out)}{'  > 1.0 s (.40)' if m > 1.0 else ''}")
        del ix
        gc.collect()
    print(f"\nload after = {load()}")


# ---------------------------------------------------------------- mode adv2 (subsequence tier scan)
def adv2():
    header("adv2")
    f = fixtures()
    print("\n=== A4. subsequence tier (step 5): _subsequence over every name whose mask holds the keys")
    print("names 'ab' * 130 + 'z' + tag (265 chars, one token); queries 'ab' * k + 'zzzzz' (one token, 5 edits: no fuzzy match)")
    for n in (5000, 50000):
        names = ["ab" * 130 + "z" + b25(i, 4, "cdefghijklmnop") for i in range(n)]
        lst = names + f["ref"][: max(0, 50000 - n)]
        dt, st, ix = run(lambda: build_label_index(lst), 600)
        print(f"  {n:,} crafted + {max(0, 50000 - n):,} REF names: build {dt:.2f} s [{st}]; load {load()}")
        for q in ("ab" * 125 + "zzzzz", "ab" * 60 + "zzzzz", "ab" * 20 + "zzzzz", "abzzz"):
            m, st2, out = med(ix, q, n=3, budget=300)
            out2, calls, _ = counted(lambda: rank(q, ix, 20))
            print(f"     len {len(q):>3}: median of 3 {m * 1000:9.1f} ms [{st2}] listed {len(out2)} {sorted({r.rule.value for r in out2})}; "
                  f"_subsequence calls {calls.get('_subsequence', 0):,}{'  > 1.0 s (.40)' if m > 1.0 else ''}")
        del ix
        gc.collect()
    print(f"\nload after = {load()}")


# ---------------------------------------------------------------- mode fixcheck (where A1's time goes; what a fix buys)
def fixcheck():
    header("fixcheck")
    f = fixtures()
    ref_ix = build_label_index(f["ref"])
    head, pairs, names = crafted(ref_ix, 300, 20261113 + 300, True)
    ix = build_label_index(names + f["ref"][:49700])
    for nq in (4, 16, 51):
        q = memo_query(head, pairs, nq)
        parsed = lm._parse_query(q.strip(WS))
        distinct = list(dict.fromkeys(parsed.tokens))
        t0 = time.perf_counter()
        maps = {t: lm._fuzzy_token_distances(ix, t, lm._allowed_edits(t)) for t in distinct}
        t_walk = time.perf_counter() - t0
        lo, hi = lm._token_range(ix._tokens, head)
        cands = set()
        for tid in maps[head]:
            cands.update(ix._postings[ix._posting_starts[tid]:ix._posting_starts[tid + 1]])
        t0 = time.perf_counter()
        res = {}
        for nid in cands:
            ids = ix._name_token_ids[ix._name_token_starts[nid]:ix._name_token_starts[nid + 1]]
            total = 0
            for t in distinct:
                d = maps[t]
                best = min((d[i] for i in ids if i in d), default=None)
                if best is None:
                    break
                total += best
            else:
                res[nid] = total
        t_map = time.perf_counter() - t0
        out = rank(q, ix, 20)
        t0 = time.perf_counter()
        for m in out:
            lm._classify(parsed, m.name)
        t_cls = time.perf_counter() - t0
        t0 = time.perf_counter()
        rank(q, ix, 20)
        t_rank = time.perf_counter() - t0
        same = sorted(res) == sorted(n for n in cands if n in res) and len(res) == len(cands)
        print(f"  {nq:>2} tokens: rank {t_rank * 1000:8.1f} ms | one walk per distinct token, all tokens {t_walk * 1000:7.1f} ms "
              f"| candidate check from the maps {t_map * 1000:6.1f} ms ({len(cands)} candidates, all fuzzy {same}) "
              f"| _classify of the {len(out)} listed {t_cls * 1000:7.1f} ms")
    print(f"\nload after = {load()}")


# ---------------------------------------------------------------- mode build (hostile build memory)
def build():
    header("build")
    print("names of one unique random lowercase token each (E3S-03 B5 shape; the trie keeps 258 characters per token)")
    for count, length in ((5000, 1000), (20000, 1024), (5000, 200)):
        r = random.Random(count * length)
        names = ["".join(r.choices(LOWER, k=length)) for _ in range(count)]
        pk, dt, st, ix = peak_of(lambda: build_label_index(names), 900)
        nodes = len(ix._trie_depth) if ix is not None else -1
        print(f"  {count:,} x {length} chars ({count * length / 1048576:.1f} MiB of names): build {dt:.2f} s under tracemalloc [{st}], "
              f"trie nodes {nodes:,}, peak {pk / 1048576:.1f} MiB = {pk / (count * length):.1f} B per name character")
        del ix, names
        gc.collect()
    r = random.Random(50000)
    names = ["".join(r.choices(LOWER, k=1024)) for _ in range(50000)]
    rss0 = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    dt, st, ix = run(lambda: build_label_index(names), 900)
    rss1 = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    print(f"  50,000 x 1024 chars (no tracemalloc): build {dt:.2f} s [{st}] (.35 bound 5.0 s); ru_maxrss {rss0 / 1024:.0f} -> {rss1 / 1024:.0f} MiB")
    if ix is not None:
        for q in ("abc", "qzxw", "a" * 256):
            m, st2, out = med(ix, q, n=3, budget=300)
            print(f"     rank {q[:10]!r:12} median of 3 {m * 1000:9.1f} ms [{st2}] listed {'-' if out is None else len(out)}")
    print(f"\nload after = {load()}")


if __name__ == "__main__":
    {"caps": caps, "perf": perf, "paste": paste, "mem": mem, "spans": spans, "det": det, "adv": adv, "adv2": adv2, "fixcheck": fixcheck, "build": build}[sys.argv[1]]()
