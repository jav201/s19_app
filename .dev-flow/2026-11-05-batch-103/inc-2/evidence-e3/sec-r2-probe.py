"""E3 round-2 security probe, Inc 2 (batch-103). Base parser only (clone e07fb00), read-only.
Q1: when does the tag walk's bit_org miss a BIT_MASK that the model's header-then-keyword
    read (graph _read_object_lines: first 8/9 words = header) also misses?
Q2: stdlib facts used on paper (span end, enum <raw> text on inf/nan)."""
import sys, tempfile, pathlib, math
repo = pathlib.Path(sys.argv[1]); sys.path.insert(0, str(repo))
import s19_app, s19_app.tui.a2l as a
print("s19_app.__file__ =", s19_app.__file__)
HDR = '''ASAP2_VERSION 1 71
/begin PROJECT P ""
/begin MODULE M ""
/begin MOD_COMMON ""
BYTE_ORDER MSB_FIRST
/end MOD_COMMON
/begin COMPU_METHOD CM_ID "" IDENTICAL "%.0" ""
/end COMPU_METHOD
@BODY@
/end MODULE
/end PROJECT
'''
shapes = {
 "A full header, BIT_MASK own line": '/begin MEASUREMENT MA ""\n UWORD CM_ID 0 0 0 65535\n BIT_MASK 0x0FF0\n ECU_ADDRESS 0x10\n/end MEASUREMENT',
 "B short header (no upper), BIT_MASK own line": '/begin MEASUREMENT MB ""\n UWORD CM_ID 0 0 0\n BIT_MASK 0x0FF0\n ECU_ADDRESS 0x10\n/end MEASUREMENT',
 "C short header (no upper), BIT_MASK same line": '/begin MEASUREMENT MC ""\n UWORD CM_ID 0 0 0 BIT_MASK 0x0FF0\n ECU_ADDRESS 0x10\n/end MEASUREMENT',
 "D short header, BIT_MASK after a comment": '/begin MEASUREMENT MD ""\n UWORD CM_ID 0 0 0\n /* mask */ BIT_MASK 0x0FF0\n ECU_ADDRESS 0x10\n/end MEASUREMENT',
 "E full header on /begin line + BIT_MASK same line": '/begin MEASUREMENT ME "" UWORD CM_ID 0 0 0 65535 BIT_MASK 0x0FF0\n ECU_ADDRESS 0x10\n/end MEASUREMENT',
}
with tempfile.TemporaryDirectory(dir="/tmp/b103-e3r2-2-security") as d:
    for label, body in shapes.items():
        p = pathlib.Path(d) / "x.a2l"; p.write_text(HDR.replace('@BODY@', body), encoding="utf-8")
        data = a.parse_a2l_file(p)
        tag = data["tags"][0]
        sec = None
        def walk(ss):
            global sec
            for s in ss:
                if s["name"] == "MEASUREMENT" and sec is None: sec = s
                walk(s.get("children") or [])
        sec = None; walk(data["sections"])
        words = a._flatten_body_tokens([sec["meta"]] + sec["lines"])
        header, rest = words[:8], words[8:]
        model_mask = rest[rest.index("BIT_MASK") + 1] if "BIT_MASK" in rest[:-1] else None
        print(f"[Q1-{label[0]}] {label}: tag bit_org={tag['bit_org']!r} datatype={tag['datatype']!r} "
              f"addr={tag['address']!r} len={tag['length']!r} upper={tag['upper_limit']!r} | header={header} "
              f"| model mask={model_mask!r} | BOTH MISS={tag['bit_org'] is None and model_mask is None}")
# Q2
for addr, n in ((0xFFFFFF00, 256), (0xFFFFFFFF, 3), (0xFFFFFFFF, 1)):
    print(f"[Q2-span] addr=0x{addr:X} len={n}: last byte=0x{addr+n-1:X} (above 0xFFFFFFFF: {addr+n-1 > 0xFFFFFFFF}); exclusive end=0x{addr+n:X} (above: {addr+n > 0xFFFFFFFF})")
for v in (math.inf, math.nan):
    try: r = ("int-compare", v == int(v))
    except Exception as e: r = ("int-compare raises", type(e).__name__)
    print(f"[Q2-raw] {v!r}: is_integer={v.is_integer()} ; {r}")
print("hex(-16) =", hex(-16), "; hex(0xFFFFFFFF) =", hex(0xFFFFFFFF))
