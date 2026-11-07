"""E3 security probe, Inc 3a: the datatype of a NO_AXIS_PTS (current-count) component. The graph's `_current_count`
reads it with `_decode_scalar(record[...], count_datatype, byte_order)` and then compares the result with the point
count and iterates `range(count)`. `_read_record_layout` admits any datatype CTX-A2L-TAG lists, FLOAT included. This
checks what `_decode_scalar` + the graph's count rule do for a float count datatype. Inc 2a code; read-only trees.
"""
import sys
sys.path.insert(0, "/home/<user>/work/b103-int2a")
import s19_app, s19_app.tui.a2l as a  # noqa: E402

print("s19_app.__file__ =", s19_app.__file__)
POINT_COUNT = 8


def current_count_rule(record, count_offset, count_datatype, byte_order, point_count):
    """The graph's `_current_count` body (3a): decode the count bytes, then the 0/above/below rule."""
    size = a.DATATYPE_SIZES.get(count_datatype)
    raw = bytes(record[count_offset:count_offset + size])
    c = a._decode_scalar(raw, count_datatype, byte_order)
    # graph: "0 or above point_count -> A2L-DEF-AXIS-CURRENT; below -> A2L-DEF-AXIS-PARTIAL; else the count"
    if c == 0 or c > point_count:
        return ("refusal", "A2L-DEF-AXIS-CURRENT", c)
    if c < point_count:
        return ("refusal", "A2L-DEF-AXIS-PARTIAL", c)
    return ("count", c)


def decode_axis_range(c):
    """`_decode_axis` then reads `c` points: `for k in range(c)`."""
    n = 0
    for _k in range(c):
        n += 1
    return n


for dt, raw_desc, raw in (
    ("UBYTE", "08", b"\x08"),
    ("FLOAT16_IEEE", "an IEEE half 8.0 (48 00 big)", b"\x48\x00"),
    ("FLOAT32_IEEE", "8.0 (41 00 00 00 big)", b"\x41\x00\x00\x00"),
    ("FLOAT32_IEEE", "NaN (7F C0 00 00 big)", b"\x7f\xc0\x00\x00"),
    ("FLOAT64_IEEE", "+inf (7F F0.. big)", b"\x7f\xf0\x00\x00\x00\x00\x00\x00"),
):
    size = a.DATATYPE_SIZES.get(dt)
    record = raw + b"\x00" * 64
    try:
        res = current_count_rule(record, 0, dt, "big", POINT_COUNT)
        tag = res[0]
        detail = f"{res}"
        if tag == "count":
            try:
                n = decode_axis_range(res[1])
                detail += f"; _decode_axis read {n} points"
            except Exception as e:
                detail += f"; _decode_axis range() -> {type(e).__name__}: {e}"
    except Exception as e:
        detail = f"RAISE {type(e).__name__}: {e}"
    print(f"[G1] NO_AXIS_PTS_X {dt} = {raw_desc}: {detail}")

# whether _read_record_layout would even admit a float count component: the graph lists the component datatypes
print("[G2] the graph's component datatype whitelist includes the float types:",
      "FLOAT16_IEEE" in a.DATATYPE_SIZES, "FLOAT32_IEEE" in a.DATATYPE_SIZES,
      "(a NO_AXIS_PTS_X FLOAT16_IEEE / FLOAT32_IEEE passes the R-A2L-DEF.86 datatype check)")
