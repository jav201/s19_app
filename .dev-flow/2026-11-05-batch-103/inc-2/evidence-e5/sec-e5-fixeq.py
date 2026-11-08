"""E5 security probe, batch-103 Inc 2a: the fix proposed for E5S-02 (the start of the run of equal x found by one
bisect_left in place of the backward walk, `a2l_definition.py:1336-1339`) keeps v2's equality with the frozen
`a2l._table_lookup`, and the real code agrees too, on seeded hostile COMPU_TABs dense in duplicate x (seed 20261108),
at every x, x +/- 1 ulp, midpoints, NaN, +/-inf, 2^63, 2^64 - 1. THROWAWAY. Usage: python -I -B sec-e5-fixeq.py <tree>
"""
import bisect, math, random, sys
sys.dont_write_bytecode = True
sys.path.insert(0, sys.argv[1])
import s19_app  # noqa: E402
import s19_app.tui.a2l as a  # noqa: E402
import s19_app.tui.a2l_definition as D  # noqa: E402

INF, NAN = math.inf, math.nan


def fix(form, stored, interpolate):
    xs, ys, n = form.xs, form.ys, len(form.xs)
    if interpolate or n == 0:
        return D._table_value(form, stored, interpolate)
    x = float(stored)
    i = bisect.bisect_left(xs, x)
    if i < n and xs[i] == x:
        return ys[i], ""
    lo = bisect.bisect_left(xs, xs[i - 1]) if i > 0 else None
    hi = i if i < n else None
    if lo is None:
        return ys[hi], ""
    if hi is None:
        return ys[D._first_equal_below(xs, x, lo, x - xs[lo])], ""
    d_lo, d_hi = x - xs[lo], xs[hi] - x
    if d_lo <= d_hi:
        return ys[D._first_equal_below(xs, x, lo, d_lo)], ""
    return ys[hi], ""


def same(r1, r2):
    (v1, e1), (v2, e2) = r1, r2
    if e1 != e2:
        return False
    if isinstance(v1, float) and isinstance(v2, float):
        return (math.isnan(v1) and math.isnan(v2)) or repr(v1) == repr(v2)
    return type(v1) is type(v2) and v1 == v2


print("s19_app.__file__ =", s19_app.__file__, "| python", sys.version.split()[0], flush=True)
rnd = random.Random(20261108)
xpool = [-INF, -1e300, -(2.0 ** 63), -1.0, -0.0, 0.0, 1.0, 2.0, 100.0, 250.0, 1e18, 2.0 ** 63, 1e300, INF]
pairs = d_fix = d_real = 0
for t in range(4000):
    ents = sorted(((rnd.choice(xpool[:rnd.randint(2, len(xpool))]), rnd.choice([rnd.uniform(-9, 9), j, "TXT"]))
                   for j in range(rnd.randint(1, 60))), key=lambda e: e[0])
    table = {"entries": ents}
    form = D._build_tab_form("H", {"H": table}, {})
    xs = form.xs
    pts = set()
    for x in xs:
        pts |= {x} | ({math.nextafter(x, INF), math.nextafter(x, -INF), x + 1, x - 1} if math.isfinite(x) else set())
    pts |= {(xs[j] + xs[j + 1]) / 2 for j in range(len(xs) - 1) if math.isfinite(xs[j]) and math.isfinite(xs[j + 1])}
    pts |= {NAN, INF, -INF, 2 ** 63, 2 ** 64 - 1, 0, 250}
    for v in pts:
        old = a._table_lookup(float(v), table, False)
        pairs += 1
        d_fix += not same(fix(form, v, False), old)
        d_real += not same(D._table_value(form, v, False), old)
print(f"[fixeq] 4000 hostile COMPU_TABs (duplicate x dense), TAB_NOINTP pairs {pairs}: the fix differs from the frozen "
      f"_table_lookup on {d_fix}, the real code on {d_real}", flush=True)
