"""E3 round-3 security probe, Inc 3a (batch-103): R-A2L-DEF.147 (E3S3-09, -10) as the round-2 correction states it.
Model `sec-r3-m3a.py` (the exact FIX bound and exact `_fixed_points`) on the frozen parser; every accepted axis is
decoded point by point through Inc 2a's real `display_text`, `_enum_entry_text` / `_enum_text` and a2l's
`_apply_compu_method` (the second half of Inc 2a's `decode_definition`, which 3a moves into `_decode_stored`).
THROWAWAY; read-only trees; writes only under <scratch>/work.
Usage: python -I sec-r3-fix.py <inc2a tree> <scratch> <part>     part in: bounds controls largest
"""
import gc, importlib.util, math, pathlib, random, sys, time, tracemalloc
from fractions import Fraction

TREE, S, PART = sys.argv[1], pathlib.Path(sys.argv[2]), sys.argv[3]
sys.path.insert(0, TREE)
import s19_app, s19_app.tui.a2l as a  # noqa: E402
import s19_app.tui.a2l_definition as D  # noqa: E402

spec = importlib.util.spec_from_file_location("m3r3", str(S / "sec-r3-m3a.py"))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); m.bind(a)
print("s19_app.__file__ =", s19_app.__file__.replace(str(pathlib.Path.home()), "~"), "| python",
      sys.version.split()[0], "| part", PART, flush=True)
W = S / "work"; W.mkdir(parents=True, exist_ok=True)
CAP, LIM = 1_048_576, 2 ** 53
HDR = ('ASAP2_VERSION 1 71\n/begin PROJECT P ""\n/begin MODULE M ""\n/begin MOD_COMMON ""\nBYTE_ORDER MSB_FIRST\n'
       '/end MOD_COMMON\n/begin COMPU_METHOD CM_ID "" IDENTICAL "%.3" ""\n/end COMPU_METHOD\n'
       '/begin COMPU_TAB TABI "" TAB_INTP 2\n 0 0\n 100 1000\n/end COMPU_TAB\n'
       '/begin RECORD_LAYOUT RL_U16\n FNC_VALUES 1 UWORD ROW_DIR DIRECT\n/end RECORD_LAYOUT\n'
       '@BODY@\n/end MODULE\n/end PROJECT\n')
NO_LIMITS = D.Limits(None, None, "", "")
# (label, kind, conversion_type, method_name, decimals, coeffs_linear, coeffs, compu_tab_ref, enum_entries)
CONVERSIONS = [
    ("IDENTICAL", "number", "IDENTICAL", "CM_ID", None, None, None, None, ()),
    ("IDENTICAL%.3", "number", "IDENTICAL", "CM_ID", 3, None, None, None, ()),
    ("IDENTICAL%.20", "number", "IDENTICAL", "CM_ID", 20, None, None, None, ()),
    ("LINEAR0.5", "number", "LINEAR", "CM_LIN", 3, (0.5, 0.0), None, None, ()),
    ("LINEAR1e300", "number", "LINEAR", "CM_BIG", 3, (1e300, 0.0), None, None, ()),
    ("RAT_FUNC", "number", "RAT_FUNC", "CM_RAT", 3, None, (0.0, 1.0, 0.0, 0.0, 0.0, 1.0), None, ()),
    ("TAB_INTP", "number", "TAB_INTP", "CM_TABI", 3, None, None, "TABI", ()),
    ("TAB_NOINTP", "number", "TAB_NOINTP", "CM_TABN", 3, None, None, "TABI", ()),
    ("NO_COMPU_METHOD", "number", None, "NO_COMPU_METHOD", None, None, None, None, ()),
    ("TAB_VERB", "enum", "TAB_VERB", "CM_VERB", None, None, None, None,
     (D.EnumEntry(0.0, None, "zero"), D.EnumEntry(float(LIM), None, "max"), D.EnumEntry(-1e308, 1e308, "any"))),
]


def point_def(name, conv):
    label, kind, ct, mn, dec, cl, co, tab, ee = conv
    return D.Definition(name=f"{name}.X", section="AXIS_DESCR", char_type=None, kind=kind, address=None,
                        byte_length=None, datatype=None, byte_order="big", bit_mask=None, bit_mask_text=None,
                        conversion_type=ct, method_name=mn, display_format=None, decimals=dec, unit="",
                        limits=NO_LIMITS, extended_limits=None, enum_table="VT" if kind == "enum" else None,
                        enum_entries=ee, default_text=None, coeffs_linear=cl, coeffs=co, compu_tab_ref=tab,
                        refusal=None)


def decode_stored(defn, a2l_data, stored):
    """Inc 2a's decode_definition after the stored value is read (graph slice: `_decode_stored`), verbatim."""
    if defn.kind == "enum":
        return D.Decoded(stored, D._enum_entry_text(defn, stored), D._enum_text(defn, stored))
    if defn.method_name == "NO_COMPU_METHOD":
        value = stored
    else:
        method = {"conversion_type": defn.conversion_type, "coeffs_linear": defn.coeffs_linear,
                  "coeffs": defn.coeffs, "compu_tab_ref": defn.compu_tab_ref}
        value, status, error = a._apply_compu_method(stored, method, a2l_data.get("compu_tabs_by_name") or {},
                                                     (defn.limits.lower, defn.limits.upper))
        if status == "error":
            return D.Refusal("A2L-DEF-DECODE", f"{defn.name}: {error}")
    return D.Decoded(stored, value, D.display_text(defn, value))


def fix_curve(name, addr, maxn, par):
    if par.startswith("LIST "):
        inner = f'  /begin FIX_AXIS_PAR_LIST\n   {par[5:]}\n  /end FIX_AXIS_PAR_LIST\n'
    else:
        inner = f'  {par}\n'
    return (f'/begin CHARACTERISTIC {name} ""\n CURVE 0x{addr:X} RL_U16 0 CM_ID 0 255\n /begin AXIS_DESCR\n'
            f'  FIX_AXIS NO_INPUT_QUANTITY CM_ID {maxn} 0 255\n{inner} /end AXIS_DESCR\n/end CHARACTERISTIC\n')


def parse(tag, body):
    p = W / f"{tag}.a2l"
    p.write_text(HDR.replace("@BODY@", body), encoding="utf-8")
    return a.parse_a2l_file(p)


def exact_points(rule):
    form, nums = rule
    if form == "PAR_LIST":
        return [Fraction(v) for v in nums]
    o, x, n = nums
    step = Fraction(2) ** x if form == "PAR" else Fraction(x)
    return [Fraction(o) + k * step for k in range(n)]


def check_points(rule, pts, ks=None):
    """(not exact ints, ints beyond 2^53, fractional points not the nearest double, max |p| as a Fraction)."""
    form, nums = rule
    if form == "PAR_LIST":
        ex = exact_points(rule)
    else:
        o, x, n = nums
        step = Fraction(2) ** x if form == "PAR" else Fraction(x)
        ks = range(n) if ks is None else ks
        ex = {k: Fraction(o) + k * step for k in ks}
    bad_int = big = bad_frac = 0
    mx = Fraction(0)
    for k, e in (enumerate(ex) if isinstance(ex, list) else ex.items()):
        p = pts[k]
        mx = max(mx, abs(e))
        if e.denominator == 1:
            if not (type(p) is int and p == e.numerator):
                bad_int += 1
            if type(p) is int and abs(p) > LIM:
                big += 1
        else:
            if not (type(p) is float and p == float(e)):
                bad_frac += 1
    return bad_int, big, bad_frac, mx


def run_shape(label, maxn, par, mode="r3"):
    m.FIX_RULE = mode
    data = parse("b_" + str(abs(hash((label, par, mode)))), fix_curve("FE", 0x100, maxn, par))
    out, _ = m.describe_all(data)
    d = out["FE"]
    rule = d["axes"][0]["fixed_rule"] if d["axes"] else None
    line = f"{label:<7} max {maxn:<8} {par[:78]:<78} -> {d['refusal'] or 'no refusal'}"
    exc = 0
    if rule is not None and d["refusal"] is None:
        try:
            pts = m.fixed_points(rule)
        except Exception as e:
            print(line + f"; _fixed_points RAISE {type(e).__name__}: {e}", flush=True)
            m.FIX_RULE = "r3"
            return 1
        bi, big, bf, mx = check_points(rule, pts) if mode == "r3" else (0, 0, 0, Fraction(0))
        texts = []
        for conv in CONVERSIONS:
            pd = point_def("FE", conv)
            for k, p in enumerate(pts):
                try:
                    r = decode_stored(pd, data, p)
                    if k == len(pts) - 1:
                        texts.append(f"{conv[0]}={(r.text if isinstance(r, D.Decoded) else r.code)[:24]}")
                except Exception as e:
                    exc += 1
                    texts.append(f"{conv[0]}=RAISE {type(e).__name__}")
                    break
        shown = ", ".join(repr(p) for p in pts[:3]) + (", …" if len(pts) > 3 else "")
        line += (f"; points ({shown}) types {sorted({type(p).__name__ for p in pts})}; not-exact ints {bi}, "
                 f"ints > 2^53 {big}, fractional not nearest double {bf}, max |exact| {float(mx):.17g}; "
                 f"decode exceptions {exc}; last texts: {'; '.join(texts)}")
    print(line, flush=True)
    m.FIX_RULE = "r3"
    return exc


if PART == "bounds":
    o2, d2 = repr(1.5 * 2.0 ** 969), repr(7205759403792793 * 2.0 ** 969)
    T = repr(sys.float_info.max)
    shapes = [
        # PAR: shift
        ("P1", 1, "FIX_AXIS_PAR 0 1024 1"), ("P2", 1, "FIX_AXIS_PAR 0 62 1"), ("P3", 1, "FIX_AXIS_PAR 0 63 1"),
        ("P4", 1, "FIX_AXIS_PAR 0 61 1"), ("P5", 4, "FIX_AXIS_PAR 0 -1 4"), ("P6", 4, "FIX_AXIS_PAR 0 1.5 4"),
        ("P7", 4, "FIX_AXIS_PAR 0 1e1 4"), ("P8", 4, "FIX_AXIS_PAR 0 000000005 4"),
        ("P9", 2, "FIX_AXIS_PAR 0 062 2"), ("P10", 4, "FIX_AXIS_PAR 0 1000000000 4"),
        ("P11", 4, "FIX_AXIS_PAR 0 9999999999 4"), ("P12", 4, "FIX_AXIS_PAR 0 1e400 4"),
        ("P13", 2, "FIX_AXIS_PAR 0 1023 2"), ("P14", 1, "FIX_AXIS_PAR 7 1e300 1"),
        ("P15", 4, "FIX_AXIS_PAR 0 +5 4"), ("P16", 4, "FIX_AXIS_PAR 0 5.0 4"),
        # PAR: magnitude of the first and the last point
        ("P17", 3, "FIX_AXIS_PAR 1 52 3"), ("P18", 3, "FIX_AXIS_PAR 0 52 3"), ("P19", 3, "FIX_AXIS_PAR -1 52 3"),
        ("P20", 3, "FIX_AXIS_PAR -9007199254740992 52 3"), ("P21", 1, "FIX_AXIS_PAR -9007199254740994 0 1"),
        ("P22", 1, "FIX_AXIS_PAR 9007199254740992 62 1"), ("P23", 2, "FIX_AXIS_PAR 0 62 2"),
        ("P24", 4, "FIX_AXIS_PAR 0.5 0 4"), ("P25", 2, "FIX_AXIS_PAR 4503599627370495.5 0 2"),
        ("P26", 1, "FIX_AXIS_PAR 9007199254740993 0 1"), ("P27", 2, "FIX_AXIS_PAR 9007199254740991 0 2"),
        ("P28", 1, f"FIX_AXIS_PAR {T} 0 1"),
        # PAR_DIST
        ("D1", 6, f"FIX_AXIS_PAR_DIST {o2} {d2} 6"), ("D2", 6, f"FIX_AXIS_PAR_DIST -{o2} -{d2} 6"),
        ("D3", 3, "FIX_AXIS_PAR_DIST 0 4503599627370496 3"), ("D4", 3, "FIX_AXIS_PAR_DIST 1 4503599627370496 3"),
        ("D5", 3, "FIX_AXIS_PAR_DIST -9007199254740992 9007199254740992 3"),
        ("D6", 3, "FIX_AXIS_PAR_DIST 9007199254740992 -9007199254740992 3"),
        ("D7", 2, "FIX_AXIS_PAR_DIST -9007199254740992 18014398509481984 2"),
        ("D8", 1, "FIX_AXIS_PAR_DIST 0 1e308 1"), ("D9", 2, f"FIX_AXIS_PAR_DIST {T} 0 2"),
        ("D10", 6, "FIX_AXIS_PAR_DIST 5e-324 5e-324 6"), ("D11", 10, "FIX_AXIS_PAR_DIST 0 0.1 10"),
        ("D12", 2, "FIX_AXIS_PAR_DIST 0 9007199254740993 2"), ("D13", 3, "FIX_AXIS_PAR_DIST 0 4503599627370496.5 3"),
        ("D14", 4, "FIX_AXIS_PAR_DIST nan 1 4"), ("D15", 4, "FIX_AXIS_PAR_DIST inf 1 4"),
        ("D16", 4, "FIX_AXIS_PAR_DIST 1e400 1 4"), ("D17", 1, "FIX_AXIS_PAR_DIST -0 0 1"),
        ("D18", 4, "FIX_AXIS_PAR_DIST 0 1 999999999"), ("D19", 4, "FIX_AXIS_PAR_DIST 0 1e10 999999999"),
        ("D20", 4, "FIX_AXIS_PAR_DIST 0 1 0"), ("D21", 4, "FIX_AXIS_PAR_DIST 0 1e300 0"),
        ("D22", 3, "FIX_AXIS_PAR_DIST 0 -4503599627370496 3"), ("D23", 4, "FIX_AXIS_PAR_DIST 0 1e-400 4"),
        ("D24", 4, "FIX_AXIS_PAR_DIST 0 1_000 4"), ("D25", 2, "FIX_AXIS_PAR_DIST 4503599627370496 0.5 2"),
        ("D26", 3, "FIX_AXIS_PAR_DIST 0.5 4503599627370495.75 3"),
        # PAR_LIST (no .147: the numbers are doubles as read)
        ("L1", 5, f"LIST {T} -{T} 5e-324 -0.0 9007199254740993"), ("L2", 4, "LIST 1 nan 3 4"),
        ("L3", 3, "LIST 1e308 1e-308 -1e308"),
    ]
    total = 0
    for lab, mx, par in shapes:
        total += run_shape(lab, mx, par)
    print(f"[B-total] shapes {len(shapes)}; decode exceptions over {len(CONVERSIONS)} conversions: {total}", flush=True)

elif PART == "controls":
    # the .147 cases and each row's negative control (mutant) on the same inputs
    o2, d2 = repr(1.5 * 2.0 ** 969), repr(7205759403792793 * 2.0 ** 969)
    cases = [("/1", 1, "FIX_AXIS_PAR 0 1024 1"), ("/2", 6, f"FIX_AXIS_PAR_DIST {o2} {d2} 6"),
             ("/3", 3, "FIX_AXIS_PAR_DIST 0 4503599627370496 3"), ("/4", 3, "FIX_AXIS_PAR_DIST 1 4503599627370496 3"),
             ("/5", 3, "FIX_AXIS_PAR 1 52 3"), ("/6", 1, "FIX_AXIS_PAR 0 62 1"), ("/7", 1, "FIX_AXIS_PAR 0 63 1"),
             ("/8", 4, "FIX_AXIS_PAR 0 -1 4"), ("/9", 4, "FIX_AXIS_PAR 0 1000000000 4"),
             ("/10", 2, "FIX_AXIS_PAR 0 1023 2")]
    for mode in ("r3", "r2", "bound63", "bound61"):
        print(f"--- rule {mode}", flush=True)
        for lab, mx, par in cases:
            t0 = time.perf_counter()
            run_shape(f".147{lab}", mx, par, mode)
            dt = time.perf_counter() - t0
            if lab == "/9":
                print(f"    /9 wall {dt:.3f} s", flush=True)
    # /9's negative control: `2**s` computed before the shift check
    for s in (10 ** 9,):
        gc.collect(); tracemalloc.start(); t0 = time.perf_counter()
        v = 2 ** s
        dt = time.perf_counter() - t0
        _, peak = tracemalloc.get_traced_memory(); tracemalloc.stop()
        print(f"[C9] 2**{s} (int, the '2**s first' mutant): {dt:.3f} s, peak {peak / 2**20:.0f} MiB, "
              f"bit length {v.bit_length():,}", flush=True)
        del v
        t0 = time.perf_counter()
        try:
            2.0 ** s
            print("[C9] 2.0**s no raise")
        except OverflowError as e:
            print(f"[C9] 2.0**{s} (float form of the mutant): OverflowError after {time.perf_counter() - t0:.6f} s: {e}")
    m.FIX_RULE = "pow-first"
    t0 = time.perf_counter()
    run_shape(".147/9", 4, "FIX_AXIS_PAR 0 1000000000 4", "pow-first")
    print(f"[C9] .147/9 under the pow-first mutant: wall {time.perf_counter() - t0:.3f} s", flush=True)

elif PART == "largest":
    # decode cost and exactness of the largest axes .147 accepts (n = 1,048,576)
    big = [("L1", ("PAR", (0, 0, CAP))),
           ("L2", ("PAR_DIST", (-LIM, 2 ** 33, CAP))),
           ("L3", ("PAR", (2 ** 53 - (CAP - 1) * 2 ** 33, 33, CAP))),
           ("L4", ("PAR_DIST", (5e-324, 5e-324, CAP))),
           ("L5", ("PAR_DIST", (0.1, 0.1, CAP))),
           ("L6", ("PAR_DIST", (2 ** 52, 0.5, CAP))),
           ("L7", ("PAR_DIST", (-LIM + 0.5 * 0 + 1, 8589934591.999998, CAP)))]
    random.seed(7)
    for lab, rule in big:
        form, (o, x, n) = rule
        m.FIX_RULE = "r3"
        step = 2 ** x if form == "PAR" else x
        a_, b_, d = m._ratio3(o, step)
        accepted = not (abs(a_) > LIM * d or abs(a_ + (n - 1) * b_) > LIM * d)
        gc.collect(); tracemalloc.start(); t0 = time.perf_counter()
        pts = m.fixed_points(rule)
        dt = time.perf_counter() - t0
        cur, peak = tracemalloc.get_traced_memory(); tracemalloc.stop()
        del pts; gc.collect(); t0 = time.perf_counter(); pts = m.fixed_points(rule); dt_u = time.perf_counter() - t0
        ks = sorted(set([0, 1, 2, n - 2, n - 1] + random.sample(range(n), 20000)))
        bi, bigc, bf, mx = check_points(rule, pts, ks)
        nonfinite = sum(1 for p in pts if isinstance(p, float) and not math.isfinite(p))
        over = sum(1 for p in pts if abs(p) > LIM)
        dup = n - len(set(pts))
        print(f"[{lab}] {form} {tuple(rule[1])!r:.90}: .147 accepts {accepted}; denominator 2^{d.bit_length() - 1}; "
              f"_fixed_points {dt_u:.3f} s untraced ({dt:.3f} s traced), peak {peak / 2**20:.0f} MiB, kept "
              f"{cur / 2**20:.0f} MiB; types {sorted({type(p).__name__ for p in pts})}; |p| > 2^53: {over}; "
              f"non-finite {nonfinite}; checked {len(ks):,} points vs exact: not-exact ints {bi}, fractional not "
              f"nearest double {bf}; duplicate points {dup:,}", flush=True)
        if lab in ("L1", "L4"):
            data = parse("largest", fix_curve("FE", 0x100, 4, "FIX_AXIS_PAR 0 0 4"))
            conv = CONVERSIONS[3]  # LINEAR 0.5, decimals 3
            pd = point_def("FE", conv)
            from dataclasses import replace

            def dec():
                return tuple(decode_stored(replace(pd, name=f"FE.X[{k}]"), data, p) for k, p in enumerate(pts))
            gc.collect(); tracemalloc.start(); t0 = time.perf_counter()
            res = dec()
            dt = time.perf_counter() - t0
            cur, peak = tracemalloc.get_traced_memory(); tracemalloc.stop()
            del res; gc.collect(); t0 = time.perf_counter(); res = dec(); dt_u = time.perf_counter() - t0
            print(f"[{lab}d] decode of its {n:,} points (per point: replace + _decode_stored, LINEAR %.3): "
                  f"{dt_u:.2f} s untraced, peak {peak / 2**20:.0f} MiB traced; non-Decoded "
                  f"{sum(1 for r in res if not isinstance(r, D.Decoded))}", flush=True)
            del res
        del pts
