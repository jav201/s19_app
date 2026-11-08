"""E5 code-review round-2 probe, inc-4 label_match (<runner>, a /tmp copy only).

Mode `all` (Parts A-D), `det` (Part A only, prints the sha256 of its results) or `cd` (Parts C, D only).
v2: Part C clamps a query token to 256 characters (R-A2L-MATCH.38: no query token longer than that
reaches the walk; v1 drew one 301-character token from a 301-character name token, outside the domain).
Part A: rank() vs an independent oracle written from 01-requirements.md (43 rows: the .41 cap at
        20 distinct query tokens, .43 non-ASCII names left out), random pools; a wrapper counts the
        node visits of each ranking, so a budget cut (.42) cannot hide behind an equal list.
Part B: the switch is a cost choice, never a semantic one: rank() with _FUZZY_SWITCH_CAP 0 (never
        switch), 512 (shipped) and 10**9 (switch after the first token) gives the same list.
Part C: _fuzzy_token_distances(budget): the unbudgeted runs equal a brute-force prefix distance
        over every token; for every budget 0 .. full+1 the runs are sorted, disjoint, joined, exact,
        a by-id prefix of the full runs, monotone in the budget, and visits == min(budget, full).
Part D: rank() under small node budgets (1 .. 300): no exception; exact/prefix/substring/token
        entries equal the oracle's; each fuzzy entry is an oracle fuzzy name with edits >= the
        oracle's; each subsequence entry is an oracle fuzzy or subsequence name with the oracle's
        subsequence spans; the list is in rank order; at an unbounded limit every oracle
        exact..token and subsequence name is listed with that rule.
"""
import hashlib
import os
import random
import sys
from pathlib import Path

import s19_app
from s19_app.tui.a2l import parse_a2l_file
import s19_app.tui.services.label_match as lm

MODE = sys.argv[1] if len(sys.argv) > 1 else "all"
print("s19_app.__file__ =", s19_app.__file__)
print("label_match.__file__ =", lm.__file__)
print("python", sys.version.split()[0], "mode", MODE, "PYTHONHASHSEED", os.environ.get("PYTHONHASHSEED"))
print("label_match sha256", hashlib.sha256(Path(lm.__file__).read_bytes()).hexdigest())
print("constants: switch", lm._FUZZY_SWITCH_CAP, "token cap", lm._FUZZY_TOKEN_CAP, "node budget", lm._FUZZY_NODE_BUDGET)


def load():
    return "load %.2f %.2f %.2f" % os.getloadavg()


# ---------------------------------------------------------------- oracle (rows only, no module helper)
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


def o_prefix_distance(a, b):
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
    return min(d[m][j] for j in range(n + 1))


def o_allowed(qt):
    if is_digit(qt[0]) or len(qt) <= 2:
        return 0
    return 1 if len(qt) <= 5 else 2


def join(spans):
    out = []
    for s, e in sorted(spans):
        if out and s <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], e))
        else:
            out.append((s, e))
    return tuple(out)


RULES = ["exact", "prefix", "substring", "token", "fuzzy", "subsequence"]


def o_subseq(keys, f):
    pos, offs = 0, []
    for c in keys:
        k = f.find(c, pos)
        if k < 0:
            return None
        offs.append(k)
        pos = k + 1
    return join([(o, o + 1) for o in offs])


def o_classify(raw, qtext, qtoks, keys, name):
    """(rule, key, spans, case_exact) of the first rule the name meets, or None."""
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
    if qtoks and ntoks:
        spans, ok = [], True
        for qt in qtoks:
            hit = [(a, b) for a, b, t in ntoks if t.startswith(qt)]
            if not hit:
                ok = False
                break
            spans.append((hit[0][0], hit[0][0] + len(qt)))
        if ok:
            return ("token", 0, join(spans), False)
    if qtoks and ntoks and len(set(qtoks)) <= 20:  # R-A2L-MATCH.41
        total, spans, ok = 0, [], True
        for qt in qtoks:  # each occurrence adds its edits (.33, A-2)
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
    sp = o_subseq(keys, f)
    if sp is None:
        return None
    return ("subsequence", 0, sp, False)


def o_prepare(names):
    seen, uniq = set(), []
    for n in names:
        if len(n) > 1024 or any(ord(c) > 0x7F for c in n) or n in seen:  # .39, .43, .17
            continue
        seen.add(n)
        uniq.append(n)
    return uniq


def o_parse(query):
    raw = query.strip(WS)
    if len(raw) > 256 or not any(is_letter(c) or is_digit(c) for c in raw):
        return None
    qtext = fold(raw)
    qtoks = [qtext[a:b] for a, b in o_tokens(raw)]
    keys = "".join(c for c in qtext if is_letter(c) or is_digit(c))
    return raw, qtext, qtoks, keys


def o_table(query, uniq):
    """name -> (rule, key, spans, case_exact) for every name meeting a rule."""
    p = o_parse(query)
    if p is None:
        return None, {}
    out = {}
    for n in uniq:
        c = o_classify(*p, n)
        if c is not None:
            out[n] = c
    return p, out


def o_rank_from(table, limit):
    if limit < 1:
        return []
    rows = []
    for n, (rule, key, spans, ce) in table.items():
        rows.append(((RULES.index(rule), key, len(n), 0 if ce else 1, n), (n, rule, key if rule == "fuzzy" else 0, spans)))
    rows.sort()
    return [r[1] for r in rows[:limit]]


def as_tuples(matches):
    return [(m.name, m.rule.value, m.edits, m.spans) for m in matches]


# ---------------------------------------------------------------- visit counter (wraps the walk)
_orig_walk = lm._fuzzy_token_distances
VISITS = [0]


def counting_walk(index, query_token, allowed, budget):
    runs, visits = _orig_walk(index, query_token, allowed, budget)
    VISITS[0] += visits
    return runs, visits


lm._fuzzy_token_distances = counting_walk


def rank_counted(q, idx, limit):
    VISITS[0] = 0
    r = lm.rank(q, idx, limit)
    return r, VISITS[0]


# ---------------------------------------------------------------- fixtures
swa_path = os.path.join(os.path.dirname(os.path.dirname(s19_app.__file__)), "examples", "case_00_public", "software_a.a2l")
swa = [str(t["name"]) for t in parse_a2l_file(Path(swa_path))["tags"] if t.get("name") is not None]
print("SWA names:", len(swa))

rng = random.Random(20261107 + 2)
EXTRA = ["Drück_Max", "DRÜCK_MAX", "druck_max", "rpm", "RPM", "Rpm", "rpm_x", "RPMX", "ABSValue", "AValue",
         "Map3D", "timeCounter", "Encounter", "DiscountCount", "DiscouNTCount", "\xa0VALUE_0001", "٣٣٣_X",
         "VALUE_0001", "VALUE_0001", "CUVE", "CURVE_0001", "Curve_Map_X", "JVmL", "a" * 300 + "x", "a" * 300 + "y",
         "A" * 259 + "b", "a" * 1024, "a" * 1025, "", "   ", "___", "x\x1cy", "aB1cD2", "OKSAhwvcueaniy",
         "VALUE\x7f", "VALUE\x80", "KEY", "curve_curvex_curvy"]
ALPH = "abcdeAB01_.[]-\xe9\xdc "
LETTERS = "abcdefghijklmnopqrstuvwxyz"


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


def cap_query(pool):
    """19-22 distinct one-edit variants of one 4-8 letter name token (crosses the .41 cap)."""
    for _ in range(50):
        n = rng.choice(pool)
        toks = [fold(n)[a:b] for a, b in o_tokens(n)]
        toks = [t for t in toks if 4 <= len(t) <= 8 and t.isascii() and t.isalpha()]
        if toks:
            t = rng.choice(toks)
            variants = list(dict.fromkeys(t[:-1] + c for c in LETTERS if c != t[-1]))
            k = rng.choice((19, 20, 21, 22))
            q = " ".join(variants[:k])
            if rng.random() < 0.3:
                q = variants[0] + " " + q  # a repeated token: the cap counts distinct ones
            return q[:256]
    return "curva curvb"


def rand_query(pool):
    n = rng.choice(pool)
    kind = rng.randint(0, 9)
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
    if kind == 7:
        return " ".join(mutate(rng.choice(pool)[:6]) for _ in range(rng.randint(2, 4)))
    if kind == 8:
        return cap_query(pool)
    t = [fold(n)[a:b] for a, b in o_tokens(n)]
    return " ".join(mutate(x) for x in t for _ in range(rng.randint(1, 2)))[:256] or "x"


def make_pool():
    pool = rng.sample(swa, 120) + [rand_name() for _ in range(60)] + EXTRA
    pool += [rng.choice(pool).swapcase() for _ in range(10)]
    rng.shuffle(pool)
    return pool


# ---------------------------------------------------------------- Part A
print("\n== Part A: rank() vs the rows oracle (43 rows) ==", load())
digest = hashlib.sha256()
checks = mismatch = with_fuzzy = 0
max_visits = 0
cap_queries = {"<=20": 0, ">20": 0}
first = []
TRIALS = 0 if MODE == "cd" else 60
for trial in range(TRIALS):
    pool = make_pool()
    idx = lm.build_label_index(pool)
    uniq = o_prepare(pool)
    assert list(idx.names) == uniq, "prepared names differ"
    for _ in range(40):
        q = rand_query([p for p in pool if p] or ["x"])
        p, table = o_table(q, uniq)
        if p is not None and p[2]:
            cap_queries["<=20" if len(set(p[2])) <= 20 else ">20"] += 1
        for limit in (1, 3, 20, 10 ** 6):
            got_m, v = rank_counted(q, idx, limit)
            max_visits = max(max_visits, v)
            got = as_tuples(got_m)
            exp = o_rank_from(table, limit)
            digest.update(repr((q, limit, got)).encode("utf-8", "surrogatepass"))
            checks += 1
            with_fuzzy += any(x[1] == "fuzzy" for x in exp)
            if got != exp:
                mismatch += 1
                if len(first) < 5:
                    first.append((q, limit, got[:4], exp[:4]))
print("checks", checks, "mismatches", mismatch, "| expected lists holding a fuzzy entry", with_fuzzy,
      "| queries by distinct tokens", cap_queries,
      "| most node visits in one ranking", max_visits, "(budget", lm._FUZZY_NODE_BUDGET, ")")
for f in first:
    print("MISMATCH q=%r limit=%d\n  got=%r\n  exp=%r" % f)
print("Part A results sha256", digest.hexdigest())
if MODE == "det":
    print("done")
    sys.exit(0)

# ---------------------------------------------------------------- Part B
print("\n== Part B: the switch (cap 0 / 512 / 10**9) gives one list ==", load())


def rank_with_switch(cap, q, idx, limit):
    saved = lm._FUZZY_SWITCH_CAP
    lm._FUZZY_SWITCH_CAP = cap
    try:
        return as_tuples(lm.rank(q, idx, limit))
    finally:
        lm._FUZZY_SWITCH_CAP = saved


b_checks = b_mis = b_fuzzy = 0
for trial in range(25 if MODE == "all" else 0):
    pool = make_pool()
    idx = lm.build_label_index(pool)
    for _ in range(30):
        q = rand_query([p for p in pool if p] or ["x"])
        for limit in (3, 10 ** 6):
            r0 = rank_with_switch(0, q, idx, limit)
            r1 = rank_with_switch(512, q, idx, limit)
            r2 = rank_with_switch(10 ** 9, q, idx, limit)
            b_checks += 1
            b_fuzzy += any(x[1] == "fuzzy" for x in r1)
            if not (r0 == r1 == r2):
                b_mis += 1
                if b_mis <= 3:
                    print("MISMATCH small q=%r limit=%d" % (q, limit))
ref = (swa + [n + "_1" for n in swa] + [n + "_2" for n in swa] + [n + "_3" for n in swa])[:50000 if MODE == "all" else 10]
idx_ref = lm.build_label_index(ref)
print("REF-like list:", len(idx_ref), "names,", len(idx_ref._tokens), "tokens")
for _ in range(40 if MODE == "all" else 0):
    n = rng.choice(ref)
    t = [fold(n)[a:b] for a, b in o_tokens(n)]
    rng.shuffle(t)
    q = " ".join(mutate(x) if len(x) >= 3 else x for x in t[: rng.randint(2, 5)])[:256] or "x"
    r0 = rank_with_switch(0, q, idx_ref, 20)
    r1 = rank_with_switch(512, q, idx_ref, 20)
    r2 = rank_with_switch(10 ** 9, q, idx_ref, 20)
    b_checks += 1
    b_fuzzy += any(x[1] == "fuzzy" for x in r1)
    if not (r0 == r1 == r2):
        b_mis += 1
        if b_mis <= 6:
            print("MISMATCH REF q=%r" % q)
print("checks", b_checks, "mismatches", b_mis, "| lists holding a fuzzy entry", b_fuzzy, "|", load())

# ---------------------------------------------------------------- Part C
print("\n== Part C: _fuzzy_token_distances under every budget ==", load())


def expand(runs):
    return {t: d for lo, hi, d in runs for t in range(lo, hi)}


def well_formed(runs):
    for lo, hi, d in runs:
        if not lo < hi:
            return False
    for (a, b, d), (c, e, f) in zip(runs, runs[1:]):
        if b > c or (b == c and d == f):
            return False
    return True


c_tokens = c_budgets = c_bad = 0
c_brute_bad = 0
for trial in range(40):
    pool = [p for p in make_pool()]
    idx = lm.build_label_index(pool)
    toks = idx._tokens
    for _ in range(8):
        base = rng.choice(toks) if toks else "abc"
        qt = fold(mutate(base)) if rng.random() < 0.7 else "".join(rng.choice("abcde") for _ in range(rng.randint(3, 9)))
        qt = ("".join(c for c in qt if is_letter(c) and c.isascii()) or "abc")[:256]  # v2: R-A2L-MATCH.38
        allowed = lm._allowed_edits(qt)
        if allowed == 0:
            continue
        full, fv = _orig_walk(idx, qt, allowed, 10 ** 9)
        fe = expand(full)
        brute = {}
        for t_id, tok in enumerate(toks):
            d = o_prefix_distance(qt, tok[: len(qt) + allowed])
            if d <= allowed:
                brute[t_id] = d
        c_tokens += 1
        if fe != brute or not well_formed(full):
            c_brute_bad += 1
            if c_brute_bad <= 3:
                print("BRUTE MISMATCH qt=%r" % qt)
        prev = {}
        for b in range(0, fv + 2):
            runs, v = _orig_walk(idx, qt, allowed, b)
            e = expand(runs)
            ok = v == min(b, fv) and well_formed(runs) and all(fe.get(t) == d for t, d in e.items())
            if e:
                mx = max(e)
                ok = ok and all(t in e for t in fe if t <= mx)
            ok = ok and all(e.get(t) == d for t, d in prev.items())
            if b >= fv:
                ok = ok and e == fe
            c_budgets += 1
            if not ok:
                c_bad += 1
                if c_bad <= 3:
                    print("BUDGET MISMATCH qt=%r budget=%d visits=%d" % (qt, b, v))
            prev = e
print("query tokens", c_tokens, "unbudgeted vs brute force mismatches", c_brute_bad,
      "| budgets checked", c_budgets, "property failures", c_bad)

# ---------------------------------------------------------------- Part D
print("\n== Part D: rank() under small node budgets ==", load())
d_checks = d_bad = d_exc = d_cut = 0
for trial in range(20):
    pool = make_pool()
    idx = lm.build_label_index(pool)
    uniq = o_prepare(pool)
    for _ in range(20):
        q = rand_query([p for p in pool if p] or ["x"])
        p, table = o_table(q, uniq)
        for budget in (1, 3, 10, 30, 100, 300):
            lm._FUZZY_NODE_BUDGET = budget
            try:
                got = as_tuples(lm.rank(q, idx, 10 ** 6))
            except Exception as exc:  # a tier defect would raise in _classify
                d_exc += 1
                print("EXCEPTION q=%r budget=%d: %r" % (q, budget, exc))
                continue
            finally:
                lm._FUZZY_NODE_BUDGET = 400_000
            d_checks += 1
            ok = True
            listed = {}
            for name, rule, edits, spans in got:
                listed[name] = rule
                o = table.get(name)
                if o is None:
                    ok = False
                    continue
                orule, okey, ospans, _ = o
                if rule in ("exact", "prefix", "substring", "token"):
                    ok = ok and (rule, edits, spans) == (orule, okey if orule == "fuzzy" else 0, ospans)
                elif rule == "fuzzy":
                    ok = ok and orule == "fuzzy" and edits >= okey
                else:
                    ok = ok and orule in ("fuzzy", "subsequence") and spans == o_subseq(p[3], fold(name))
            # group order (rule, key, length); the substring key is the oracle's boundary key, the
            # fuzzy key the listed edits; within a group case-exactness and the name are not checked
            keys = [(RULES.index(r), e if r == "fuzzy" else (table[n][1] if r == "substring" and n in table else 0), len(n))
                    for n, r, e, _ in got]
            ok = ok and all(a <= b for a, b in zip(keys, keys[1:]))
            for name, (orule, _, _, _) in table.items():
                if orule in ("exact", "prefix", "substring", "token", "subsequence"):
                    ok = ok and listed.get(name) == orule
            d_cut += any(table[n][0] == "fuzzy" and r != "fuzzy" for n, r in listed.items())
            if not ok:
                d_bad += 1
                if d_bad <= 3:
                    print("INVARIANT FAILED q=%r budget=%d" % (q, budget))
print("rankings", d_checks, "invariant failures", d_bad, "exceptions", d_exc,
      "| rankings where the budget turned an oracle fuzzy name into another rule", d_cut, "|", load())
print("done")
