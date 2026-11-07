"""E3 round-2 security probe, Inc 3a (batch-103): E3S3-01 / -05 as corrected (R-A2L-DEF.86 count datatype,
R-A2L-DEF.116.2 below 1). Every count datatype shape, on a STD curve (count in its own record) and a COM curve
(count in the axis object's record): describe through the corrected model on the frozen parser; for the
admitted datatypes, `_current_count` over every count value a datatype can hold (exhaustive for 8/16 bit, edges
and a seeded sample for 32/64 bit), both byte orders; then `range(count)` as `_decode_axis` does. Negative
control: the round-1 rule (float admitted, '0 or above / below') on the same shapes. THROWAWAY; read-only trees.
Usage: python -I sec-r2-count.py <inc2a tree> <scratch>
"""
import importlib.util, itertools, pathlib, random, struct, sys

TREE, S = sys.argv[1], pathlib.Path(sys.argv[2])
sys.path.insert(0, TREE)
import s19_app, s19_app.tui.a2l as a  # noqa: E402

spec = importlib.util.spec_from_file_location("m3r2", str(S / "sec-r2-m3a.py"))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); m.bind(a)
print("s19_app.__file__ =", s19_app.__file__); print("python", sys.version.split()[0])
W = S / "work"; W.mkdir(parents=True, exist_ok=True)

HDR = ('ASAP2_VERSION 1 71\n/begin PROJECT P ""\n/begin MODULE M ""\n/begin MOD_COMMON ""\nBYTE_ORDER MSB_FIRST\n'
       '/end MOD_COMMON\n/begin COMPU_METHOD CM_ID "" IDENTICAL "%.3" ""\n/end COMPU_METHOD\n@BODY@\n/end MODULE\n'
       '/end PROJECT\n')


def body(dt_words):
    cnt = f"NO_AXIS_PTS_X 1 {dt_words}".rstrip()
    return (f'/begin RECORD_LAYOUT RL_CQ\n {cnt}\n AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT\n'
            f' FNC_VALUES 3 UWORD ROW_DIR DIRECT\n/end RECORD_LAYOUT\n'
            f'/begin RECORD_LAYOUT RL_AXO\n {cnt}\n AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT\n/end RECORD_LAYOUT\n'
            f'/begin RECORD_LAYOUT RL_V\n FNC_VALUES 1 UWORD ROW_DIR DIRECT\n/end RECORD_LAYOUT\n'
            f'/begin CHARACTERISTIC CQ ""\n CURVE 0x100 RL_CQ 0 CM_ID 0 65535\n /begin AXIS_DESCR\n'
            f'  STD_AXIS NO_INPUT_QUANTITY CM_ID 4 0 255\n /end AXIS_DESCR\n/end CHARACTERISTIC\n'
            f'/begin AXIS_PTS AXO "" 0x400 NO_INPUT_QUANTITY RL_AXO 0 CM_ID 4 0 255\n/end AXIS_PTS\n'
            f'/begin CHARACTERISTIC CR ""\n CURVE 0x200 RL_V 0 CM_ID 0 65535\n /begin AXIS_DESCR\n'
            f'  COM_AXIS NO_INPUT_QUANTITY CM_ID 4 0 255\n  AXIS_PTS_REF AXO\n /end AXIS_DESCR\n/end CHARACTERISTIC\n')


def values_for(dt):
    size = m.SIZES[dt]
    code = a.DATATYPE_STRUCT_CODES[dt]
    signed = code.islower()
    lo, hi = (-(1 << (8 * size - 1)), (1 << (8 * size - 1)) - 1) if signed else (0, (1 << (8 * size)) - 1)
    if size <= 2:
        return code, range(lo, hi + 1), lo, hi
    rnd = random.Random(103 + size)
    edge =[v for v in (lo, lo + 1, -2, -1, 0, 1, 2, 3, 4, 5, 6, 255, 256, 65535, hi - 1, hi) if lo <= v <= hi]
    return code, edge + [rnd.randint(lo, hi) for _ in range(200_000)], lo, hi


def round1_rule(c, n):
    if c == 0 or c > n:
        return "CURRENT"
    if c < n:
        return "PARTIAL"
    return c


SHAPES = ["UBYTE", "SBYTE", "UWORD", "SWORD", "ULONG", "SLONG", "A_UINT64", "A_INT64",
          "FLOAT16_IEEE", "FLOAT32_IEEE", "FLOAT64_IEEE", "BYTE", "WORD", "LONG", "FOO", ""]
exc_total = 0
for dt in SHAPES:
    p = W / f"count_{dt or 'missing'}.a2l"
    p.write_text(HDR.replace("@BODY@", body(dt)), encoding="utf-8")
    data = a.parse_a2l_file(p)
    try:
        res = m.describe_all(data)
    except Exception as e:  # pragma: no cover - reported
        exc_total += 1
        print(f"[K1] {dt or '(missing word)'}: describe RAISE {type(e).__name__}: {e}")
        continue
    cq, cr = res.get("CQ"), res.get("CR")
    print(f"[K1] NO_AXIS_PTS_X datatype {dt or '(missing word)':13s}: STD curve CQ -> {cq['refusal']}; "
          f"COM curve CR (axis object AXO) -> {cr['refusal']}")
    if cq["refusal"] is not None:
        continue
    for label, d in (("CQ", cq), ("CR", cr)):
        ax = d["axes"][0]
        assert ax["count_datatype"] == dt and ax["count_offset"] == 0, (label, ax)
    code, vals, lo, hi = values_for(dt)
    outcome = {}
    exc = 0
    nvals = 0
    for order, label in itertools.product(("big", "little"), ("CQ", "CR")):
        ax = (cq if label == "CQ" else cr)["axes"][0]
        prefix = ">" if order == "big" else "<"
        for v in vals:
            rec = struct.pack(prefix + code, v) + bytes(16)
            nvals += 1
            try:
                r = m.current_count(ax, rec, order)
                if isinstance(r, int):
                    k = sum(1 for _ in range(r))
                    key = f"count {r}"
                    assert k == ax["point_count"]
                else:
                    key = r[1]
                    if r[1] == "A2L-DEF-AXIS-PARTIAL":
                        assert 1 <= r[2] <= 3
                outcome[key] = outcome.get(key, 0) + 1
            except Exception as e:
                exc += 1
                outcome[f"RAISE {type(e).__name__}"] = outcome.get(f"RAISE {type(e).__name__}", 0) + 1
    exc_total += exc
    neg = [v for v in (-1, lo) if lo <= v < 0]
    print(f"[K2] {dt}: {nvals:,} count values (range {lo}..{hi}{', exhaustive' if m.SIZES[dt] <= 2 else ', edges + 200,000 seeded'}"
          f" x 2 byte orders x STD/COM) -> {dict(sorted(outcome.items()))}; exceptions {exc}")
    if neg:
        for v in neg:
            r = m.current_count(cq["axes"][0], struct.pack(">" + code, v) + bytes(16), "big")
            print(f"     {dt} count {v}: {r}  (E3S3-05: CURRENT, not PARTIAL)")
    big = struct.pack(">" + code, hi) + bytes(16)
    print(f"     {dt} count {hi} (largest): {m.current_count(cq['axes'][0], big, 'big')}")
print(f"[K3] exceptions over every shape: {exc_total}; open branches met: {m.OPEN}")

# negative control: the round-1 rule (float count admitted, '0 or above n / below n')
for dt, raw in (("FLOAT16_IEEE", b"\x48\x00"), ("FLOAT32_IEEE", b"\x41\x00\x00\x00"),
                ("FLOAT32_IEEE", b"\x7f\xc0\x00\x00"), ("FLOAT64_IEEE", b"\x40\x10\x00\x00\x00\x00\x00\x00")):
    c = a._decode_scalar(raw, dt, "big")
    try:
        r = round1_rule(c, 4)
        if not isinstance(r, str):
            sum(1 for _ in range(r))
        out = f"round-1 rule -> {r!r}"
    except Exception as e:
        out = f"round-1 rule -> RAISE {type(e).__name__}: {e}"
    print(f"[K4] negative control {dt} {raw.hex(' ')} (decodes {c!r}): {out}; corrected rule -> "
          f"{m.current_count({'count_offset': 0, 'count_datatype': dt, 'point_count': 4}, raw + bytes(8), 'big')}")
