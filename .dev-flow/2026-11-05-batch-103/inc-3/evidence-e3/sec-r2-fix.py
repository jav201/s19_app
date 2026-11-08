"""E3 round-2 security probe, Inc 3a (batch-103): E3S3-02 as corrected (FIX points at decode, `fixed_rule` in
AxisDefinition, R-A2L-DEF.142/5) and what the correction touched (`_read_axis` FIX step, `_fixed_points`,
`_decode_axis`). Corrected model `sec-r2-m3a.py` on the frozen parser; Inc 2a's real `display_text`,
`decode_definition`, `describe_definitions` and a2l's `_apply_compu_method` where 3a reuses them.
THROWAWAY; read-only trees; writes only under <scratch>/work.
Usage: python -I sec-r2-fix.py <inc2a tree> <scratch> <part>   part in: cap describe-all list raise decode
"""
import gc, importlib.util, math, pathlib, sys, time, tracemalloc
from dataclasses import replace

TREE, S, PART = sys.argv[1], pathlib.Path(sys.argv[2]), sys.argv[3]
sys.path.insert(0, TREE)
import s19_app, s19_app.tui.a2l as a  # noqa: E402
import s19_app.tui.a2l_definition as D  # noqa: E402

spec = importlib.util.spec_from_file_location("m3r2", str(S / "sec-r2-m3a.py"))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); m.bind(a)
print("s19_app.__file__ =", s19_app.__file__, "| python", sys.version.split()[0], "| part", PART, flush=True)
W = S / "work"; W.mkdir(parents=True, exist_ok=True)
CAP = 1_048_576
HDR = ('ASAP2_VERSION 1 71\n/begin PROJECT P ""\n/begin MODULE M ""\n/begin MOD_COMMON ""\nBYTE_ORDER MSB_FIRST\n'
       '/end MOD_COMMON\n/begin COMPU_METHOD CM_ID "" IDENTICAL "%.3" ""\n/end COMPU_METHOD\n'
       '/begin COMPU_METHOD CM_LIN "" LINEAR "%.3" ""\n COEFFS_LINEAR 0.5 0\n/end COMPU_METHOD\n'
       '/begin COMPU_METHOD CM_RAT "" RAT_FUNC "%.3" ""\n COEFFS 0 1 0 0 0 1\n/end COMPU_METHOD\n'
       '/begin RECORD_LAYOUT RL_U8\n FNC_VALUES 1 UBYTE ROW_DIR DIRECT\n/end RECORD_LAYOUT\n'
       '/begin RECORD_LAYOUT RL_AXO8\n NO_AXIS_PTS_X 1 UBYTE\n AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT\n/end RECORD_LAYOUT\n'
       '@BODY@\n/end MODULE\n/end PROJECT\n')


def fix_curve(name, addr, maxn, par, cm="CM_ID"):
    return (f'/begin CHARACTERISTIC {name} ""\n CURVE 0x{addr:X} RL_U8 0 {cm} 0 255\n /begin AXIS_DESCR\n'
            f'  FIX_AXIS NO_INPUT_QUANTITY {cm} {maxn} 0 2000000\n  {par}\n /end AXIS_DESCR\n/end CHARACTERISTIC\n')


def fix_map(name, addr, maxn):
    ax = (f' /begin AXIS_DESCR\n  FIX_AXIS NO_INPUT_QUANTITY CM_ID {maxn} 0 2000000\n  FIX_AXIS_PAR 0 0 {maxn}\n'
          f' /end AXIS_DESCR\n')
    return f'/begin CHARACTERISTIC {name} ""\n MAP 0x{addr:X} RL_U8 0 CM_ID 0 255\n{ax}{ax}/end CHARACTERISTIC\n'


def parse(name, body):
    p = W / f"{name}.a2l"
    p.write_text(HDR.replace("@BODY@", body), encoding="utf-8")
    t0 = time.perf_counter()
    data = a.parse_a2l_file(p)
    return data, time.perf_counter() - t0, p.stat().st_size


def measure(fn, untraced_time=False):
    """(result, seconds, peak MiB, kept MiB). untraced_time: the seconds come from a second run without
    tracemalloc (tracemalloc slows allocation-heavy loops about 2x)."""
    gc.collect(); tracemalloc.start(); t0 = time.perf_counter()
    r = fn()
    dt = time.perf_counter() - t0
    cur, peak = tracemalloc.get_traced_memory(); tracemalloc.stop()
    if untraced_time:
        del r; gc.collect(); t0 = time.perf_counter(); r = fn(); dt = time.perf_counter() - t0
    return r, dt, peak / 2**20, cur / 2**20


V171 = pathlib.Path(TREE) / "examples/case_00_public/ASAP2_Demo_V171.a2l"
TEMPLATE = D.describe_definition("ASAM.C.SCALAR.UBYTE.IDENTICAL", a.parse_a2l_file(V171))


def point_def(name, cm, datatype=None):
    conv = {"CM_ID": ("IDENTICAL", None, None), "CM_LIN": ("LINEAR", (0.5, 0.0), None),
            "CM_RAT": ("RAT_FUNC", None, (0.0, 1.0, 0.0, 0.0, 0.0, 1.0)), "NO": (None, None, None)}[cm]
    return replace(TEMPLATE, name=f"{name}.X", section="AXIS_DESCR", char_type=None, kind="number", address=None,
                   byte_length=None if datatype is None else 1, datatype=datatype, conversion_type=conv[0],
                   method_name="NO_COMPU_METHOD" if cm == "NO" else cm, coeffs_linear=conv[1], coeffs=conv[2],
                   compu_tab_ref=None, refusal=None)


def decode_stored(defn, a2l_data, stored):
    """_decode_stored = the second half of Inc 2a's decode_definition, moved unchanged (graph slice #20)."""
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


def decode_fix_axis(name, rule, a2l_data, cm="CM_ID", arith="literal"):
    pd = point_def(name, cm)
    out = []
    for k, p in enumerate(m.fixed_points(rule, arith)):
        ed = replace(pd, name=f"{name}.X[{k}]")
        out.append(decode_stored(ed, a2l_data, p))
    return tuple(out)


if PART == "cap":
    # FIX `0 0 n` at the cap and one above; describe O(1); decode cost of the largest accepted FIX axis
    for n in (CAP, CAP + 1):
        data, tp, size = parse(f"cap{n}", fix_curve("FC", 0x100000, n, f"FIX_AXIS_PAR 0 0 {n}"))
        maps, secs = m.build_maps(data), m.object_sections(data)
        tag = [t for t in data["tags"] if t.get("name") == "FC"][0]
        d, dt, peak, _ = measure(lambda: m.describe_array(tag, secs["FC"][0], data, maps))
        ax = d["axes"][0] if d["axes"] else {}
        print(f"[X1] FIX_AXIS_PAR 0 0 {n:,} (max {n:,}): describe {dt * 1e3:.2f} ms, peak {peak:.3f} MiB, refusal "
              f"{d['refusal']}, fixed_rule {ax.get('fixed_rule')}, element count {d['element_count']}, "
              f"byte length {d['byte_length']}", flush=True)
    rule = ("PAR", (0, 0, CAP))
    pts, dt, peak, cur = measure(lambda: m.fixed_points(rule))
    print(f"[X2] _fixed_points alone, 1,048,576 points: {dt:.3f} s, peak {peak:.1f} MiB, kept {cur:.1f} MiB; "
          f"points 0..{pts[-1]} ok={pts == tuple(range(CAP))}", flush=True)
    del pts
    res, dt, peak, cur = measure(lambda: decode_fix_axis("FC", rule, data), True)
    bad = sum(1 for r in res if not isinstance(r, D.Decoded))
    print(f"[X3] decode of that FIX axis (per point: _element_definition replace + _decode_stored + display_text): "
          f"{dt:.2f} s, peak {peak:.0f} MiB, kept {cur:.0f} MiB, non-Decoded {bad}, last text {res[-1].text!r}", flush=True)
    del res
    # the curve's values: 1,048,576 UBYTE elements through Inc 2a's decode_definition (as [B1], here at full size)
    vdef = replace(TEMPLATE, name="FC", address=0x100000, byte_length=1)
    image = {0x100000 + i: i & 0xFF for i in range(CAP)}

    def values():
        return tuple(D.decode_definition(replace(vdef, name=f"FC[{i}]", address=0x100000 + i), data, image)
                     for i in range(CAP))
    res, dt, peak, cur = measure(values, True)
    print(f"[X4] decode of the curve's 1,048,576 values (same per-element loop): {dt:.2f} s, peak {peak:.0f} MiB, "
          f"kept {cur:.0f} MiB, non-Decoded {sum(1 for r in res if not isinstance(r, D.Decoded))}", flush=True)

elif PART == "describe-all":
    # a hostile file of thousands of FIX curves (and maps) at the cap; describe every name
    K_CURVES, K_MAPS = 5000, 1000
    body = "".join(fix_curve(f"FC{i:05d}", 0x100000 + i * 0x200000 % 0xF0000000, CAP, f"FIX_AXIS_PAR_DIST 0 1 {CAP}")
                   for i in range(K_CURVES))
    body += "".join(fix_map(f"FM{i:05d}", 0x10 + i * 0x10, CAP) for i in range(K_MAPS))
    data, tp, size = parse("many", body)
    print(f"[X5] file: {K_CURVES:,} FIX curves at max {CAP:,} + {K_MAPS:,} FIX maps of two such axes; "
          f"{size / 1e6:.2f} MB; parse (frozen a2l.py) {tp:.2f} s; tags {len(data['tags']):,}", flush=True)
    for rep in range(3):
        res, dt, peak, cur = measure(lambda: m.describe_all(data))
        refs = {}
        for v in res.values():
            refs[v["refusal"]] = refs.get(v["refusal"], 0) + 1
        nrule = sum(1 for v in res.values() for ax in v["axes"] if ax.get("fixed_rule"))
        npts = sum(1 for v in res.values() for ax in v["axes"] if "fixed_points" in ax)
        print(f"[X6] model describe-all (Inc 3a reads, corrected), run {rep + 1}: {dt:.3f} s, peak {peak:.1f} MiB, "
              f"kept {cur:.1f} MiB; objects {len(res):,}; refusals {refs}; axes with a fixed_rule {nrule:,}; "
              f"axes holding built points {npts}", flush=True)
        del res
    names = [t["name"] for t in data["tags"]]
    for rep in range(3):
        res, dt, peak, cur = measure(lambda: D.describe_definitions(names, data))
        print(f"[X7] Inc 2a real describe_definitions over the {len(names):,} names, run {rep + 1}: {dt:.3f} s, "
              f"peak {peak:.1f} MiB", flush=True)
        del res

elif PART == "list":
    # the one FIX form whose describe work is O(list length): a FIX_AXIS_PAR_LIST at the cap
    nums = " ".join(str(k) for k in range(CAP))
    body = (f'/begin CHARACTERISTIC FL ""\n CURVE 0x100000 RL_U8 0 CM_ID 0 255\n /begin AXIS_DESCR\n'
            f'  FIX_AXIS NO_INPUT_QUANTITY CM_ID {CAP} 0 2000000\n  /begin FIX_AXIS_PAR_LIST\n   {nums}\n'
            f'  /end FIX_AXIS_PAR_LIST\n /end AXIS_DESCR\n/end CHARACTERISTIC\n')
    data, tp, size = parse("list", body)
    maps, secs = m.build_maps(data), m.object_sections(data)
    tag = [t for t in data["tags"] if t.get("name") == "FL"][0]
    d, dt, peak, cur = measure(lambda: m.describe_array(tag, secs["FL"][0], data, maps))
    rule = d["axes"][0]["fixed_rule"] if d["axes"] else None
    print(f"[X8] FIX_AXIS_PAR_LIST of {CAP:,} numbers: file {size / 1e6:.2f} MB, parse {tp:.2f} s; describe "
          f"{dt:.2f} s, peak {peak:.0f} MiB, kept {cur:.0f} MiB; refusal {d['refusal']}; fixed_rule numbers "
          f"{len(rule[1]) if rule else None} (the file's own numbers; describe/parse = {dt / tp:.2f})", flush=True)

elif PART == "raise":
    # decode-time shapes of the moved `_fixed_points`: the arithmetic the node leaves open
    T = sys.float_info.max  # largest double
    o = 1.5 * 2.0 ** 969
    q = 7205759403792793                # 5 * q = 2**55 - 3
    d = q * 2.0 ** 969
    assert 5 * q == 2 ** 55 - 3 and 2 ** 52 <= q < 2 ** 53
    cases = [
        ("R1", 1, "FIX_AXIS_PAR 0 1024 1", "max 1, s = 1024 (admitted: n = 1)"),
        ("R2", 1, "FIX_AXIS_PAR 7 1e300 1", "max 1, s = 1e300 (admitted: n = 1)"),
        ("R3", 6, f"FIX_AXIS_PAR_DIST {o!r} {d!r} 6", "PAR_DIST o = 1.5*2^969, d = q*2^969 (integral), n = 6"),
        ("R4", 6, f"FIX_AXIS_PAR_DIST {-o!r} {-d!r} 6", "the mirror, negative"),
        ("R5", 2, f"FIX_AXIS_PAR_DIST {T!r} 0 2", "PAR_DIST at the largest double, d = 0 (control)"),
        ("R6", 2, "FIX_AXIS_PAR 0 1023 2", ".141/7 (control)"),
    ]
    for tagid, n, par, what in cases:
        for cm in ("CM_ID", "CM_LIN", "CM_RAT", "NO"):
            cmw = "NO_COMPU_METHOD" if cm == "NO" else cm
            data, _, _ = parse(f"raise_{tagid}_{cm}", fix_curve("FR", 0x100, n, par, cmw))
            res = m.describe_all(data)["FR"]
            rule = res["axes"][0]["fixed_rule"] if res["axes"] else None
            line = f"[{tagid}] {what}, {cmw}: describe refusal {res['refusal']}"
            if rule is not None:
                for arith in ("literal", "float"):
                    try:
                        out = decode_fix_axis("FR", rule, data, cm, arith)
                        line += f"; decode[{arith}] ok, last {out[-1].text if isinstance(out[-1], D.Decoded) else out[-1]}"
                    except Exception as e:
                        line += f"; decode[{arith}] RAISE {type(e).__name__}: {e}"
            print(line, flush=True)
    # the describe-side variant: the last-point check done on the int-where-integral numbers
    oi, di = int(o), int(d)
    try:
        math.isfinite(oi + 5 * di)
        print("[R7] check on ints: no raise")
    except Exception as e:
        print(f"[R7] the .141 last-point check on the fixed_rule's ints (math.isfinite(o + 5*d)) -> RAISE "
              f"{type(e).__name__}: {e}")
    print(f"[R8] float check value o + 5*d = {o + 5 * d!r} (finite {math.isfinite(o + 5 * d)}); exact int point 5 - "
          f"largest double = {(oi + 5 * di) - int(T)} (> half-ulp 2^970 = {2 ** 970}: {(oi + 5 * di) - int(T) >= 2 ** 970})")

elif PART == "decode":
    # decode cost of the largest accepted axis with points in memory: a COM axis object, ULONG count + UBYTE points,
    # whose record is exactly 1 MiB (1,048,572 points); one more point and .143 refuses the record
    body = ""
    for nm, axo, addr, caddr, n in (("CC", "AXO", 0x100000, 0x300000, CAP - 4), ("CC2", "AXO2", 0x500000, 0x700000, CAP - 3)):
        body += (f'/begin AXIS_PTS {axo} "" 0x{addr:X} NO_INPUT_QUANTITY RL_AXO32 0 CM_ID {n} 0 255\n/end AXIS_PTS\n'
                 f'/begin CHARACTERISTIC {nm} ""\n CURVE 0x{caddr:X} RL_U8 0 CM_ID 0 255\n /begin AXIS_DESCR\n'
                 f'  COM_AXIS NO_INPUT_QUANTITY CM_ID {n} 0 255\n  AXIS_PTS_REF {axo}\n /end AXIS_DESCR\n'
                 f'/end CHARACTERISTIC\n')
    body = ('/begin RECORD_LAYOUT RL_AXO32\n NO_AXIS_PTS_X 1 ULONG\n AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT\n'
            '/end RECORD_LAYOUT\n') + body
    data, tp, size = parse("com", body)
    res = m.describe_all(data)
    for nm in ("CC", "CC2"):
        r = res[nm]
        ax = r["axes"][0] if r["axes"] else {}
        print(f"[X9] {nm}: describe refusal {r['refusal']}, point count {ax.get('point_count')}, axis object record "
              f"end {ax.get('record_end')}, element count {r['element_count']}, byte length {r['byte_length']}", flush=True)
    ax = res["CC"]["axes"][0]
    n = ax["point_count"]
    rec_addr = ax["axis_object_address"]
    image = {rec_addr + i: b for i, b in enumerate(n.to_bytes(4, "big"))}
    image.update({rec_addr + ax["offset"] + k: k & 0xFF for k in range(n)})
    rec = bytes(image[rec_addr + i] for i in range(ax["record_end"]))
    print(f"[X10] _current_count on that record: {m.current_count(ax, rec, 'big')}", flush=True)
    pd = replace(point_def("CC", "CM_ID", "UBYTE"), byte_length=1, byte_order="big")

    def points():
        return tuple(D.decode_definition(replace(pd, name=f"CC.X[{k}]", address=rec_addr + ax["offset"] + k), data, image)
                     for k in range(n))
    out, dt, peak, cur = measure(points, True)
    print(f"[X11] decode loop over the {n:,} COM points (per point replace + _read_stored_value + _decode_stored): "
          f"{dt:.2f} s, peak {peak:.0f} MiB, kept {cur:.0f} MiB, non-Decoded "
          f"{sum(1 for r in out if not isinstance(r, D.Decoded))}", flush=True)
