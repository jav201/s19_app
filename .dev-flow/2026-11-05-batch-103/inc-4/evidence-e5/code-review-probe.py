"""E5 code-review probe, inc-4 label_match (runs on cachyos-rtx in a /tmp copy only).

Part A: an independent oracle written from the rows' definitions (01-requirements.md),
        sharing no helper with the module, compared with rank() on random inputs.
Part B: _prefix_distance against a full (unbanded) OSA prefix distance.
Part C: timing of _prefix_distance per call and of rank() on crafted 50,000-name lists,
        with and without an early column stop (monkeypatched in this process only).
"""
import os
import random
import statistics
import sys
import time

import s19_app
from s19_app.tui.a2l import parse_a2l_file
import s19_app.tui.services.label_match as lm

print("s19_app.__file__ =", s19_app.__file__)
print("label_match.__file__ =", lm.__file__)
print("python", sys.version.split()[0])


def load():
    return "load %.2f %.2f %.2f" % os.getloadavg()


# ---------------------------------------------------------------- oracle (rows only)
WS = " \t\n\r\v\f"


def is_letter(c):
    return ("a" <= c <= "z") or ("A" <= c <= "Z") or ord(c) > 0x7F


def is_digit(c):
    return "0" <= c <= "9"


def is_upper(c):
    return "A" <= c <= "Z"


def is_lower(c):
    return "a" <= c <= "z"


def fold(s):
    return "".join(chr(ord(c) + 32) if is_upper(c) else c for c in s)


def o_tokens(s):
    """Maximal digit runs; maximal letter runs cut by the two case rules (CTX token)."""
    runs = []
    i, n = 0, len(s)
    while i < n:
        if is_digit(s[i]):
            j = i
            while j < n and is_digit(s[j]):
                j += 1
            runs.append((i, j))
            i = j
        elif is_letter(s[i]):
            j = i
            while j < n and is_letter(s[j]):
                j += 1
            # cut the letter run [i, j)
            cuts = [i]
            for k in range(i + 1, j):
                if is_upper(s[k]) and is_lower(s[k - 1]):
                    cuts.append(k)
                elif is_upper(s[k]) and is_upper(s[k - 1]) and k + 1 < j and is_lower(s[k + 1]):
                    cuts.append(k)
            cuts.append(j)
            for a, b in zip(cuts, cuts[1:]):
                runs.append((a, b))
            i = j
        else:
            i += 1
    return runs


def boundary_offsets(name):
    b = {0}
    for a, _ in o_tokens(name):
        b.add(a)
    for k, c in enumerate(name):
        if not (is_letter(c) or is_digit(c)):
            b.add(k)
    return b


def osa(a, b):
    m, n = len(a), len(b)
    d = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m + 1):
        d[i][0] = i
    for j in range(n + 1):
        d[0][j] = j
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d


def o_prefix_distance(q, t):
    d = osa(q, t)
    return min(d[len(q)][j] for j in range(len(t) + 1))


def o_allowed(qt):
    if is_digit(qt[0]):
        return 0
    if len(qt) <= 2:
        return 0
    if len(qt) <= 5:
        return 1
    return 2


def join(spans):
    out = []
    for s, e in sorted(spans):
        if out and s <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], e))
        else:
            out.append((s, e))
    return tuple(out)


RULES = ["exact", "prefix", "substring", "token", "fuzzy", "subsequence"]


def o_classify(raw, qtext, qtoks, keys, name):
    f = fold(name)
    if f == qtext:
        return ("exact", 0, ((0, len(name)),), name == raw)
    if f.startswith(qtext):
        return ("prefix", 0, ((0, len(qtext)),), name.startswith(raw))
    if qtext in f:
        occ = [p for p in range(len(f)) if f.startswith(qtext, p)]
        bset = boundary_offsets(name)
        at_b = [p for p in occ if p in bset]
        p = at_b[0] if at_b else occ[0]
        return ("substring", 0 if at_b else 1, ((p, p + len(qtext)),), raw in name)
    ntoks = [(a, b, f[a:b]) for a, b in o_tokens(name)]
    spans = []
    ok = True
    for qt in qtoks:
        hit = [(a, b) for a, b, t in ntoks if t.startswith(qt)]
        if not hit:
            ok = False
            break
        spans.append((hit[0][0], hit[0][0] + len(qt)))
    if ok and ntoks:
        return ("token", 0, join(spans), False)
    total, spans, ok = 0, [], bool(ntoks)
    for qt in qtoks:
        if not ok:
            break
        al = o_allowed(qt)
        ds = [(o_prefix_distance(qt, t), a, b) for a, b, t in ntoks]
        best = min(x[0] for x in ds)
        if best > al:
            ok = False
            break
        a, b = next((a, b) for dd, a, b in ds if dd == best)
        total += best
        spans.append((a, b))
    if ok:
        return ("fuzzy", total, join(spans), False)
    pos, offs = 0, []
    for c in keys:
        k = f.find(c, pos)
        if k < 0:
            return None
        offs.append(k)
        pos = k + 1
    return ("subsequence", 0, join([(o, o + 1) for o in offs]), False)


def o_rank(query, names, limit):
    if limit < 1:
        return []
    raw = query.strip(WS)
    if len(raw) > 256:
        return []
    if not any(is_letter(c) or is_digit(c) for c in raw):
        return []
    qtext = fold(raw)
    qtoks = [qtext[a:b] for a, b in o_tokens(raw)]
    keys = "".join(c for c in qtext if is_letter(c) or is_digit(c))
    seen, uniq = set(), []
    for n in names:
        if len(n) > 1024 or n in seen:
            continue
        seen.add(n)
        uniq.append(n)
    rows = []
    for n in uniq:
        c = o_classify(raw, qtext, qtoks, keys, n)
        if c is None:
            continue
        rule, key, spans, ce = c
        rows.append(((RULES.index(rule), key, len(n), 0 if ce else 1, n), (n, rule, key if rule == "fuzzy" else 0, spans)))
    rows.sort()
    return [r[1] for r in rows[:limit]]


def as_tuples(matches):
    return [(m.name, m.rule.value, m.edits, m.spans) for m in matches]


# ---------------------------------------------------------------- fixtures
swa_path = os.path.join(os.path.dirname(os.path.dirname(s19_app.__file__)), "examples", "case_00_public", "software_a.a2l")
from pathlib import Path
swa = [str(t["name"]) for t in parse_a2l_file(Path(swa_path))["tags"] if t.get("name") is not None]
print("SWA names:", len(swa))

rng = random.Random(20261107)
EXTRA = ["Drück_Max", "DRÜCK_MAX", "druck_max", "rpm", "RPM", "Rpm", "rpm_x", "RPMX", "ABSValue", "AValue",
         "Map3D", "timeCounter", "Encounter", "DiscountCount", "DiscouNTCount", "\xa0VALUE_0001", "٣٣٣_X",
         "VALUE_0001", "VALUE_0001", "CUVE", "CURVE_0001", "Curve_Map_X", "JVmL", "a" * 300 + "x", "a" * 300 + "y",
         "A" * 259 + "b", "a" * 1024, "a" * 1025, "", "   ", "___", "x\x1cy", "aB1cD2", "OKSAhwvcueaniy"]
ALPH = "abcdeAB01_.[]-\xe9\xdc "


def rand_name():
    return "".join(rng.choice(ALPH) for _ in range(rng.randint(1, 14)))


def mutate(s):
    s = list(s)
    for _ in range(rng.randint(0, 2)):
        op = rng.randint(0, 3)
        if not s:
            break
        k = rng.randrange(len(s))
        if op == 0:
            del s[k]
        elif op == 1:
            s.insert(k, rng.choice(ALPH))
        elif op == 2:
            s[k] = rng.choice(ALPH)
        elif k + 1 < len(s):
            s[k], s[k + 1] = s[k + 1], s[k]
    return "".join(s)


def rand_query(pool):
    n = rng.choice(pool)
    kind = rng.randint(0, 7)
    if kind == 0:
        return n
    if kind == 1 and n:
        a = rng.randrange(len(n))
        return n[a:a + rng.randint(1, 8)]
    if kind == 2:
        return mutate(n[: rng.randint(1, 12)])
    if kind == 3:
        t = o_tokens(n)
        rng.shuffle(t)
        return " ".join(n[a:b] for a, b in t[: rng.randint(1, 3)])
    if kind == 4:
        return rand_name()
    if kind == 5:
        return n.swapcase()
    if kind == 6:
        return "  " + mutate(n) + "\t"
    return " ".join(mutate(rng.choice(pool)[:6]) for _ in range(rng.randint(2, 4)))


print("\n== Part A: rank() vs the rows oracle ==", load())
mismatch = 0
checks = 0
first = []
for trial in range(60):
    pool = rng.sample(swa, 120) + [rand_name() for _ in range(60)] + EXTRA
    pool += [rng.choice(pool).swapcase() for _ in range(10)]
    rng.shuffle(pool)
    idx = lm.build_label_index(pool)
    for _ in range(40):
        q = rand_query([p for p in pool if p] or ["x"])
        full = o_rank(q, pool, 10 ** 6)
        for limit in (1, 3, 20, 10 ** 6):
            got = as_tuples(lm.rank(q, idx, limit))
            exp = full[:limit]
            checks += 1
            if got != exp:
                mismatch += 1
                if len(first) < 5:
                    first.append((q, limit, got[:4], exp[:4]))
print("checks", checks, "mismatches", mismatch)
for f in first:
    print("MISMATCH q=%r limit=%d\n  got=%r\n  exp=%r" % f)

# long-token / trie-truncation shapes (tokens over 258 characters sharing a 258 prefix)
pool = ["a" * 300 + "x", "a" * 300 + "y", "a" * 259, "a" * 258, "a" * 257 + "b", "A" * 258 + "bc", "b" + "a" * 280] + rng.sample(swa, 50)
idx = lm.build_label_index(pool)
lm_checks = lm_mis = 0
for q in ["a" * 256, "a" * 255 + "b", "a" * 254 + "ba", "a" * 255 + "x", "b" + "a" * 255, "a" * 250 + "xy", "a" * 256 + " ", "aa" * 128]:
    full = o_rank(q, pool, 10 ** 6)
    for limit in (1, 20, 10 ** 6):
        lm_checks += 1
        if as_tuples(lm.rank(q, idx, limit)) != full[:limit]:
            lm_mis += 1
            print("MISMATCH long q len", len(q.strip()), "limit", limit)
print("long-token checks", lm_checks, "mismatches", lm_mis)

print("\n== Part B: _prefix_distance vs full OSA ==", load())
bad = 0
pairs = 0
for _ in range(20000):
    q = "".join(rng.choice("abcd") for _ in range(rng.randint(1, 9)))
    t = "".join(rng.choice("abcd") for _ in range(rng.randint(0, 12)))
    cap = rng.randint(0, 2)
    full = o_prefix_distance(q, t)
    exp = full if full <= cap else cap + 1
    pairs += 1
    if lm._prefix_distance(q, t, cap) != exp:
        bad += 1
print("pairs", pairs, "mismatches", bad)

print("\n== Part C: cost ==")


def med(n, call):
    ts = []
    for _ in range(n):
        t0 = time.perf_counter()
        call()
        ts.append(time.perf_counter() - t0)
    return statistics.median(ts)


orig_pd = lm._prefix_distance


def pd_stop(query_token, name_token, cap):
    # the same function with the column loop bounded at m + cap (columns past it hold no band cell)
    return orig_pd(query_token, name_token[: len(query_token) + cap], cap)


# equivalence of the bounded variant on the Part B shapes plus long tokens
eq_bad = 0
for _ in range(20000):
    q = "".join(rng.choice("abcd") for _ in range(rng.randint(1, 9)))
    t = "".join(rng.choice("abcd") for _ in range(rng.randint(0, 40)))
    cap = rng.randint(0, 2)
    if orig_pd(q, t, cap) != pd_stop(q, t, cap):
        eq_bad += 1
print("bounded-variant equivalence: 20000 pairs, mismatches", eq_bad)

for args in [("aab", "a" * 5, 1), ("aab", "a" * 1000, 1), ("a" * 255 + "b", "a" * 1020, 2), ("a" * 128 + "b", "a" * 1020, 2)]:
    t_cur = med(21, lambda: orig_pd(*args))
    t_stop = med(21, lambda: pd_stop(*args))
    print("_prefix_distance(len %d, len %d, cap %d): current %.3f ms, bounded %.3f ms" % (len(args[0]), len(args[1]), args[2], t_cur * 1e3, t_stop * 1e3))

ref = (swa + [n + "_1" for n in swa] + [n + "_2" for n in swa] + [n + "_3" for n in swa])[:50000]
DIST = ref[:49700] + ["a" * k for k in range(701, 1001)]  # 300 names, 300 distinct tokens of 701-1000 letters
LONG = ref[:49900] + ["a" * 1020 + "_" + str(i) for i in range(100)]  # the tests' LONG fixture
near = ["aa" + c for c in "bcdefghijklmnopqrstuvwxyz"] + [c + "aa" for c in "bcdefghijklmnopqrstuvwxyz"] + ["a" + c + "a" for c in "bcdefghijklmnopqrstuvwxyz"]
Q64 = " ".join(near[:64])
Q16 = " ".join(near[:16])
QDUP = " ".join(["aab"] * 64)
print("Q64 len", len(Q64), "Q16 len", len(Q16), "QDUP len", len(QDUP))
t0 = time.perf_counter(); i_dist = lm.build_label_index(DIST); print("build DIST %.2f s" % (time.perf_counter() - t0))
t0 = time.perf_counter(); i_long = lm.build_label_index(LONG); print("build LONG %.2f s" % (time.perf_counter() - t0))
for label, ix, q in [("DIST Q16", i_dist, Q16), ("DIST Q64", i_dist, Q64), ("LONG QDUP", i_long, QDUP), ("LONG Q64", i_long, Q64)]:
    lm._prefix_distance = orig_pd
    print(label, "before:", load())
    r_cur = lm.rank(q, ix, 20)
    t_cur = med(3, lambda: lm.rank(q, ix, 20))
    lm._prefix_distance = pd_stop
    r_stop = lm.rank(q, ix, 20)
    t_stop = med(3, lambda: lm.rank(q, ix, 20))
    lm._prefix_distance = orig_pd
    print("  %s: %d entries (%s), current median %.1f ms, bounded median %.1f ms, same list: %s; after: %s"
          % (label, len(r_cur), sorted({m.rule.value for m in r_cur}), t_cur * 1e3, t_stop * 1e3, r_cur == r_stop, load()))
print("done")
