"""E5 security re-review (round 2), batch-103 Inc 2a: the equality censuses of R-A2L-DEF.150 (/6, /9, /10) on the FIXED
code (HEAD 26d3e309, product a856fab3; `_table_value` takes the start of a run of equal x with one bisect_left), full,
over every table of every file (35 fixtures + 168 public files), plus seeded hostile tables. Round 1's
`sec-e5-census.py` with three changes: `_read_stored_value` takes the name echo; every v2 pair is also compared with
round 1's code 069171cd (the walk back), which must give the same value; and two hostile blocks for CR-1 = E5S-02:

[T] v2 table lookup against the frozen `a2l._table_lookup` (and against 069171cd's `_table_value`), both interpolations,
    at each x, midpoints, quarter points, +/- 1 ulp, +/- 1, +/-0, NaN, +/-inf, 2^53+1, +/-2^63, 2^64-1, +/-1e300.
    Negative control: `nearest-only` must differ.
[R] route: every corpus definition with a `_TabForm`, decoded on six one-byte images, against the frozen
    `_apply_compu_method`.
[E] enum index against 82f5f8e5's linear first match (unchanged by the fix pass; re-run for completeness).
[H] round 1's seeded hostile tables (seed 20261107).
[F] round 1's fix-equality block (seed 20261108): 4,000 hostile COMPU_TABs dense in duplicate x, TAB_NOINTP, the
    fixed code against the frozen lookup and against 069171cd.
[L] long runs: COMPU_TABs holding one run of k equal x (k = 2 ... 5,000) at the start, in the middle and at the end, with
    neighbours at several distances on both sides (ties included), int, float and text y, both interpolations.
Only derived counts leave the runner. THROWAWAY. Usage: python -I -B sec-e5r2-census.py <tree> <lists>...
"""
import bisect, importlib, math, os, pathlib, random, sys
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from dataclasses import fields, replace

sys.dont_write_bytecode = True
TREE = sys.argv[1]
sys.path.insert(0, TREE)
import s19_app  # noqa: E402
import s19_app.tui.a2l as a  # noqa: E402
import s19_app.tui.a2l_definition as D  # noqa: E402
O = importlib.import_module("s19_app.tui.a2l_definition_82f5")
P0 = importlib.import_module("s19_app.tui.a2l_definition_0691")   # round 1 code: the walk back over equal x

INF, NAN = math.inf, math.nan
EXT_FIXED = [0.0, -0.0, NAN, INF, -INF, 2 ** 53 + 1, 2 ** 63, -(2 ** 63), 2 ** 64 - 1, 1e300, -1e300]


def same(r1, r2):
    (v1, e1), (v2, e2) = r1, r2
    if e1 != e2:
        return False
    if isinstance(v1, float) and isinstance(v2, float):
        return (math.isnan(v1) and math.isnan(v2)) or repr(v1) == repr(v2)
    return type(v1) is type(v2) and v1 == v2


def tab_points(xs):
    pts = set()
    for x in xs:
        if math.isfinite(x):
            pts |= {x, math.nextafter(x, INF), math.nextafter(x, -INF), x + 1, x - 1}
            if x.is_integer() and abs(x) < 2 ** 64:
                pts.add(int(x))
        else:
            pts.add(x)
    for j in range(len(xs) - 1):
        lo, hi = xs[j], xs[j + 1]
        if math.isfinite(lo) and math.isfinite(hi):
            pts |= {(lo + hi) / 2, lo + (hi - lo) / 4, lo + 3 * (hi - lo) / 4}
    return list(pts) + EXT_FIXED


def nearest_only(form, stored, interpolate):
    """Negative control: v2 with the first-equal rule left out (ys[lo], not the first equal distance below)."""
    if interpolate:
        return D._table_value(form, stored, True)
    xs, ys, n = form.xs, form.ys, len(form.xs)
    if n == 0:
        return None, "lookup table is empty"
    x = float(stored)
    i = bisect.bisect_left(xs, x)
    if i < n and xs[i] == x:
        return ys[i], ""
    if i == 0:
        return ys[0], ""
    if i == n:
        return ys[n - 1], ""
    return (ys[i - 1], "") if x - xs[i - 1] <= xs[i] - x else (ys[i], "")


def table_census(tabs_items, out):
    for nm, table in tabs_items:
        try:
            form = D._build_tab_form(nm, {nm: table}, {})
        except Exception as ex:
            out["T_exc"] += 1; out[f"T_exc {type(ex).__name__}"] += 1
            continue
        if form is None:
            continue
        out["T_tables"] += 1
        if form.x_nan:
            out["T_nanx"] += 1
            continue
        out["T_dupx"] += len(form.xs) != len(set(form.xs))
        for v in tab_points(form.xs):
            for interp in (True, False):
                try:
                    r_new = D._table_value(form, v, interp)
                except Exception as ex:
                    out["T_exc"] += 1; out[f"T_exc {type(ex).__name__}"] += 1
                    continue
                r_old = a._table_lookup(float(v), table, interp)
                out["T_pairs"] += 1
                out["T_vs_0691_diff"] += not same(r_new, P0._table_value(form, v, interp))
                if not same(r_new, r_old):
                    out["T_diff"] += 1
                    kind = "nan" if isinstance(v, float) and math.isnan(v) else (
                        "inf" if isinstance(v, float) and math.isinf(v) else ("int" if isinstance(v, int) else "float"))
                    out[f"T_diff {('INTP' if interp else 'NOINTP')} {kind}"] += 1
                if not same(nearest_only(form, v, interp), r_old):
                    out["T_neg_diff"] += 1


IMG_BYTES = (0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF)


class Fill(dict):
    """An image holding every address, each byte `b`."""

    def __init__(self, b):
        super().__init__(); self.b = b
    def __contains__(self, k): return isinstance(k, int)
    def __getitem__(self, k): return self.b


def route_census(data, out):
    tags = [t.get("name") for t in data.get("tags") or [] if t.get("name")]
    defs = D.describe_definitions(tags, data)
    frozen_methods = data.get("compu_methods_by_name") or {}
    tabs = data.get("compu_tabs_by_name") or {}
    for d in defs.values():
        if d.refusal is not None or not isinstance(d._table_form, D._TabForm):
            continue
        out["R_defs"] += 1
        for b in IMG_BYTES:
            img = Fill(b)
            got = D.decode_definition(d, data, img)
            stored = D._read_stored_value(d, img, "x")
            if d._table_form.x_nan:
                ok = isinstance(got, D.Refusal) and "x that is not a number" in got.message
            else:
                v, st, err = a._apply_compu_method(stored, frozen_methods.get(d.method_name), tabs,
                                                   (d.limits.lower, d.limits.upper))
                if st == "error":
                    ok = isinstance(got, D.Refusal) and got.code == "A2L-DEF-DECODE"
                elif not isinstance(v, (int, float)):
                    ok = isinstance(got, D.Refusal) and "not a number" in got.message
                else:
                    ok = isinstance(got, D.Decoded) and same((got.value, ""), (v, ""))
            out["R_pairs"] += 1
            out["R_diff"] += not ok


def enum_points(entries):
    pts = set()
    for e in entries:
        for x in (e.raw, e.raw_max):
            if x is None:
                continue
            if math.isfinite(x):
                pts |= {x, x + 1, x - 1, math.nextafter(x, INF), math.nextafter(x, -INF)}
                if x.is_integer():
                    pts.add(int(x)); pts.add(int(x) + 1); pts.add(int(x) - 1)
            else:
                pts.add(x)
        if e.raw_max is not None and math.isfinite(e.raw) and math.isfinite(e.raw_max):
            pts.add((e.raw + e.raw_max) / 2)
    return list(pts) + [0.0, -0.0, 0, NAN, INF, -INF]


OLD_TEMPLATE = {fl.name: None for fl in fields(O.Definition)}


def enum_compare(kind, entries, default, out, tag):
    form = D._build_enum_form(kind, entries, default)
    nd = D.Definition(**{**{fl.name: None for fl in fields(D.Definition)}, "name": "x", "enum_entries": entries,
                         "default_text": default, "_table_form": form})
    od = O.Definition(**{**OLD_TEMPLATE, "name": "x", "enum_entries": entries, "default_text": default})
    diffs = 0
    for v in enum_points(entries):
        out[f"{tag}_pairs"] += 1
        try:
            e_new, t_new = D._enum_entry_text(nd, v), D._enum_text(nd, v)
        except Exception as ex:
            out[f"{tag}_exc"] += 1; out[f"{tag}_exc {type(ex).__name__}"] += 1
            continue
        e_old, t_old = O._enum_entry_text(od, v), O._enum_text(od, v)
        diffs += (e_new != e_old) or (t_new != t_old)
    out[f"{tag}_diff"] += diffs
    out[f"{tag}_diff_tables"] += diffs > 0
    return form


def enum_negatives(kind, entries, out):
    od = O.Definition(**{**OLD_TEMPLATE, "name": "x", "enum_entries": entries, "default_text": None})
    if kind == "COMPU_VTAB_RANGE":
        rs = sorted(range(len(entries)), key=lambda i: entries[i].raw)
        mins = [entries[i].raw for i in rs]
        diffs = 0
        for v in enum_points(entries):
            if isinstance(v, float) and math.isnan(v):
                continue
            j = bisect.bisect_right(mins, v) - 1
            naive = entries[rs[j]].text if j >= 0 and v <= entries[rs[j]].raw_max else None
            diffs += naive != O._enum_entry_text(od, v)
        out["E_neg_plainbisect_diff"] += diffs
        out["E_neg_plainbisect_tables"] += diffs > 0
    else:
        last = {}
        for e in entries:
            last[e.raw] = e.text
        diffs = sum(last.get(v) != O._enum_entry_text(od, v) for v in enum_points(entries)
                    if not (isinstance(v, float) and math.isnan(v)))
        out["E_neg_lastwins_diff"] += diffs
        out["E_neg_lastwins_tables"] += diffs > 0


def enum_census(data, out):
    secs = []

    def w(nodes):
        for n in nodes:
            if n.get("name") in ("COMPU_VTAB", "COMPU_VTAB_RANGE"):
                secs.append(n)
            w(n.get("children") or [])
    w(data.get("sections") or [])
    for sec in secs:
        nm = a.parse_begin_meta(sec.get("meta", "") or "")[0]
        form = D._read_enum_table(nm, {nm: sec}, {})
        old = O._read_enum_table(nm, {nm: sec})
        if form is None:
            continue
        out[f"E_tables {form.section_kind}"] += 1
        key = lambda es: [(e.raw, e.raw_max, e.text) for e in es]   # the two modules' EnumEntry classes differ
        out["E_reader_diff"] += old is None or repr(key(old[1])) != repr(key(form.entries)) or old[2] != form.default_text
        if not form.entries:
            continue
        out["E_overlap"] += form.section_kind == "COMPU_VTAB_RANGE" and _overlaps(form.entries)
        enum_compare(form.section_kind, form.entries, form.default_text, out, "E")
        enum_negatives(form.section_kind, form.entries, out)


def _overlaps(entries):
    rs = sorted((e.raw, e.raw_max) for e in entries)
    return any(rs[i + 1][0] <= rs[i][1] for i in range(len(rs) - 1))


def one(p):
    out = Counter()
    try:
        data = a.parse_a2l_file(pathlib.Path(p))
    except Exception as ex:
        out["parse_exc"] += 1; out[f"parse_exc {type(ex).__name__}"] += 1
        return out
    out["files"] += 1
    for stage, fn in (("T", lambda: table_census(list((data.get("compu_tabs_by_name") or {}).items()), out)),
                      ("R", lambda: route_census(data, out)), ("E", lambda: enum_census(data, out))):
        try:
            fn()
        except Exception as ex:
            out[f"{stage}_stage_exc {type(ex).__name__}"] += 1
    return out


def hostile(out):
    rnd = random.Random(20261107)
    pool = [-INF, -1e300, -(2.0 ** 63), -5.0, -1.0, -0.0, 0.0, 0.5, 1.0, 2.0, 3.0, 5.0, 7.0, 250.0, 255.0, 1e18,
            2.0 ** 63, 1e300, INF, NAN]
    for _ in range(3000):
        ents = []
        for k in range(rnd.randint(1, 60)):
            lo, hi = rnd.choice(pool), rnd.choice(pool)
            if rnd.random() < 0.7 and not (math.isnan(lo) or math.isnan(hi)) and lo > hi:
                lo, hi = hi, lo
            ents.append(D.EnumEntry(lo, hi, f"r{k}"))
        enum_compare("COMPU_VTAB_RANGE", tuple(ents), rnd.choice([None, "d"]), out, "H_range")
    for _ in range(2000):
        ents = tuple(D.EnumEntry(rnd.choice(pool), None, f"v{k}") for k in range(rnd.randint(1, 60)))
        enum_compare("COMPU_VTAB", ents, rnd.choice([None, "d"]), out, "H_vtab")
    xpool = [x for x in pool if not math.isnan(x)]
    for _ in range(3000):
        ents = sorted(((rnd.choice(xpool), rnd.choice([rnd.uniform(-9, 9), rnd.choice(xpool), "TXT"]))
                       for _ in range(rnd.randint(1, 40))), key=lambda e: e[0])
        table_census([("HT", {"entries": ents})], out)
    out["H_done"] += 1


def fixeq(out):
    """Round 1's sec-e5-fixeq.py block, seed 20261108, on the fixed code (and 069171cd)."""
    rnd = random.Random(20261108)
    xpool = [-INF, -1e300, -(2.0 ** 63), -1.0, -0.0, 0.0, 1.0, 2.0, 100.0, 250.0, 1e18, 2.0 ** 63, 1e300, INF]
    for _t in range(4000):
        ents = sorted(((rnd.choice(xpool[:rnd.randint(2, len(xpool))]), rnd.choice([rnd.uniform(-9, 9), j, "TXT"]))
                       for j in range(rnd.randint(1, 60))), key=lambda e: e[0])
        table = {"entries": ents}
        form = D._build_tab_form("H", {"H": table}, {})
        xs = form.xs
        out["F_tables"] += 1
        out["F_dupx"] += len(xs) != len(set(xs))
        pts = set()
        for x in xs:
            pts |= {x} | ({math.nextafter(x, INF), math.nextafter(x, -INF), x + 1, x - 1} if math.isfinite(x) else set())
        pts |= {(xs[j] + xs[j + 1]) / 2 for j in range(len(xs) - 1) if math.isfinite(xs[j]) and math.isfinite(xs[j + 1])}
        pts |= {NAN, INF, -INF, 2 ** 63, 2 ** 64 - 1, 0, 250}
        for v in pts:
            old = a._table_lookup(float(v), table, False)
            try:
                got = D._table_value(form, v, False)
            except Exception as ex:
                out["F_exc"] += 1; out[f"F_exc {type(ex).__name__}"] += 1
                continue
            out["F_pairs"] += 1
            out["F_diff"] += not same(got, old)
            out["F_vs_0691_diff"] += not same(got, P0._table_value(form, v, False))


def long_runs(out):
    """One run of k equal x placed at the start, in the middle or at the end of a COMPU_TAB, neighbours at several
    distances (ties with the run included)."""
    rnd = random.Random(20261109)
    for k in (2, 3, 7, 10, 100, 1000, 5000):
        for where in ("start", "middle", "end", "alone"):
            for gap_lo, gap_hi in ((1.0, 1.0), (1.0, 3.0), (3.0, 1.0), (0.5, 100.0), (100.0, 0.5)):
                for ykind in ("int", "float", "text"):
                    r = 50.0
                    yv = (lambda j: j) if ykind == "int" else ((lambda j: j / 3) if ykind == "float" else (lambda j: f"t{j}"))
                    run = [(r, yv(j)) for j in range(k)]
                    below = [(r - gap_lo - 10 * i, yv(-1 - i)) for i in range(3)][::-1]
                    above = [(r + gap_hi + 10 * i, yv(10 ** 6 + i)) for i in range(3)]
                    if where == "start":
                        ents = run + above
                    elif where == "end":
                        ents = below + run
                    elif where == "middle":
                        ents = below + run + above
                    else:
                        ents = run
                    ents = sorted(ents, key=lambda e: e[0])
                    table = {"entries": ents}
                    form = D._build_tab_form("L", {"L": table}, {})
                    xs = form.xs
                    out["L_tables"] += 1
                    pts = {r, r + gap_hi / 2, r - gap_lo / 2, r + gap_hi, r - gap_lo, r + 0.25, r - 0.25,
                           math.nextafter(r, INF), math.nextafter(r, -INF), 0, 250, -INF, INF, NAN, rnd.uniform(0, 100)}
                    pts |= {x for x in xs} | {(xs[j] + xs[j + 1]) / 2 for j in range(len(xs) - 1)}
                    for v in pts:
                        for interp in (False, True):
                            old = a._table_lookup(float(v), table, interp)
                            try:
                                got = D._table_value(form, v, interp)
                            except Exception as ex:
                                out["L_exc"] += 1; out[f"L_exc {type(ex).__name__}"] += 1
                                continue
                            out["L_pairs"] += 1
                            out["L_diff"] += not same(got, old)
                            out["L_vs_0691_diff"] += not same(got, P0._table_value(form, v, interp))


if __name__ == "__main__":
    def md5(p):
        import hashlib
        return hashlib.md5(open(p, "rb").read()).hexdigest()[:8]
    print("s19_app.__file__ =", s19_app.__file__, "| python", sys.version.split()[0], "| a2l_definition md5",
          md5(D.__file__), "| 82f5", md5(O.__file__), "| 0691", md5(P0.__file__), "| load",
          " ".join(f"{x:.2f}" for x in os.getloadavg()), flush=True)
    files = [ln.strip() for lf in sys.argv[2:] for ln in open(lf) if ln.strip()]
    total = Counter()
    with ProcessPoolExecutor(int(os.environ.get("E5_WORKERS", "4"))) as ex:
        for r in ex.map(one, files, chunksize=1):
            total.update(r)
    print(f"[corpus] files {len(files)}, parsed {total['files']}, parse exceptions {total['parse_exc']}", flush=True)
    print(f"[T] tables {total['T_tables']} (NaN x, left to the decode refusal: {total['T_nanx']}; with a duplicate x: "
          f"{total['T_dupx']}); pairs {total['T_pairs']}; v2 differs from the frozen _table_lookup on {total['T_diff']},"
          f" from 069171cd on {total['T_vs_0691_diff']}; exceptions {total['T_exc']}; negative nearest-only differs on "
          f"{total['T_neg_diff']}", flush=True)
    print(f"[R] route: definitions with a _TabForm {total['R_defs']}; decodes {total['R_pairs']}; differences from the "
          f"frozen _apply_compu_method {total['R_diff']}", flush=True)
    print(f"[E] sections: COMPU_VTAB {total['E_tables COMPU_VTAB']}, COMPU_VTAB_RANGE {total['E_tables COMPU_VTAB_RANGE']}"
          f" (overlapping: {total['E_overlap']}); reader entries/default differ from 82f5f8e5 in {total['E_reader_diff']};"
          f" pairs {total['E_pairs']}; differences from 82f5f8e5's linear first match {total['E_diff']} in "
          f"{total['E_diff_tables']} tables; exceptions {total['E_exc']}", flush=True)
    print(f"[E] negatives: plain bisect differs on {total['E_neg_plainbisect_diff']} points in "
          f"{total['E_neg_plainbisect_tables']} tables; last-wins dict on {total['E_neg_lastwins_diff']} points in "
          f"{total['E_neg_lastwins_tables']} tables", flush=True)
    h = Counter()
    hostile(h)
    print(f"[H] hostile range tables 3000: pairs {h['H_range_pairs']}, differences {h['H_range_diff']} in "
          f"{h['H_range_diff_tables']} tables, exceptions {h['H_range_exc']}; COMPU_VTAB 2000: pairs {h['H_vtab_pairs']},"
          f" differences {h['H_vtab_diff']}, exceptions {h['H_vtab_exc']}; COMPU_TAB 3000: tables {h['T_tables']}"
          f" (duplicate x {h['T_dupx']}), pairs {h['T_pairs']}, v2 differences {h['T_diff']} (from 069171cd "
          f"{h['T_vs_0691_diff']}), exceptions {h['T_exc']}, negative nearest-only differs on {h['T_neg_diff']}", flush=True)
    fx = Counter()
    fixeq(fx)
    print(f"[F] {fx['F_tables']} hostile COMPU_TABs (duplicate x in {fx['F_dupx']}), TAB_NOINTP pairs {fx['F_pairs']}: the "
          f"fixed code differs from the frozen _table_lookup on {fx['F_diff']}, from 069171cd on {fx['F_vs_0691_diff']}; "
          f"exceptions {fx['F_exc']}", flush=True)
    lr = Counter()
    long_runs(lr)
    print(f"[L] {lr['L_tables']} COMPU_TABs with one run of 2 ... 5,000 equal x: pairs {lr['L_pairs']} (both "
          f"interpolations); differs from the frozen _table_lookup on {lr['L_diff']}, from 069171cd on "
          f"{lr['L_vs_0691_diff']}; exceptions {lr['L_exc']}", flush=True)
    extra = {k: v for k, v in (total + h + fx + lr).items() if " " in k and ("exc" in k or "diff" in k)}
    print("[detail]", dict(sorted(extra.items())), flush=True)
    print("end | load", " ".join(f"{x:.2f}" for x in os.getloadavg()), flush=True)
