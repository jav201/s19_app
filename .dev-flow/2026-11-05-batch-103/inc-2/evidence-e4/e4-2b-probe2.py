"""Inc 2b E4 probe 2: parse-error shapes, duplicate BIT_MASK, hostile ASCII."""
import sys, tempfile
from pathlib import Path
sys.path.insert(0, ".")
sys.path.insert(0, "tools/synth")
from s19_app.tui.a2l_parse import parse_a2l_file
from s19_app.tui.a2l_definition import describe_definition, describe_definitions

print("s19_app.__file__ =", __import__("s19_app").__file__)

def inline(path, *blocks, byte_order="MSB_FIRST"):
    lines = ["ASAP2_VERSION 1 71", '/begin PROJECT P ""', '  /begin MODULE M ""']
    if byte_order is not None:
        lines += ['    /begin MOD_COMMON ""', f"      BYTE_ORDER {byte_order}", "    /end MOD_COMMON"]
    for rl, dt in (("RL_U8","UBYTE"),("RL_S8","SBYTE"),("RL_U16","UWORD"),("RL_S16","SWORD"),("RL_U32","ULONG"),("RL_F16","FLOAT16_IEEE"),("RL_F32","FLOAT32_IEEE"),("RL_F64","FLOAT64_IEEE")):
        lines += [f"    /begin RECORD_LAYOUT {rl}", f"      FNC_VALUES 1 {dt} ROW_DIR DIRECT", "    /end RECORD_LAYOUT"]
    for b in blocks: lines.append(b)
    lines += ["  /end MODULE", "/end PROJECT"]
    p = path / "x.a2l"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return parse_a2l_file(p)

def val(name, addr, layout, conv="NO_COMPU_METHOD", lo="0", hi="65535", *extra):
    return "\n".join([f'/begin CHARACTERISTIC {name} ""', f"  VALUE {addr} {layout} 0 {conv} {lo} {hi}"] + [f"  {e}" for e in extra] + ["/end CHARACTERISTIC"])

tp = Path(tempfile.mkdtemp(prefix="b103e4p2_"))

# 1. two BIT_MASK lines
a = inline(tp, val("MP", "0x10", "RL_U16", "NO_COMPU_METHOD", "0", "65535", "BIT_MASK 0x000F", "BIT_MASK 0x000F"))
print("== two BIT_MASK lines ==")
print("errors:", a.get("errors"))
d = describe_definition("MP", a)
print("MP refusal:", d.refusal)

# 2. duplicate BYTE_ORDER in MOD_COMMON + masked object
block_mod2 = ['    /begin MOD_COMMON ""', "      BYTE_ORDER MSB_FIRST", "      BYTE_ORDER MSB_LAST", "    /end MOD_COMMON"]
lines = ["ASAP2_VERSION 1 71", '/begin PROJECT P ""', '  /begin MODULE M ""'] + block_mod2
for rl, dt in (("RL_U8","UBYTE"),("RL_U16","UWORD")):
    lines += [f"    /begin RECORD_LAYOUT {rl}", f"      FNC_VALUES 1 {dt} ROW_DIR DIRECT", "    /end RECORD_LAYOUT"]
lines += [val("BO", "0x10", "RL_U16", "NO_COMPU_METHOD", "0", "65535", "BIT_MASK 0x0FF0"), "  /end MODULE", "/end PROJECT"]
p = tp / "bo.a2l"; p.write_text("\n".join(lines)+"\n", encoding="utf-8")
a = parse_a2l_file(p)
print("== duplicate BYTE_ORDER MOD_COMMON + masked BO ==")
print("errors:", a.get("errors"))
d = describe_definition("BO", a)
print("BO refusal:", d.refusal, "byte_order:", d.byte_order)

# 3. .152 shapes
shapes = {
    "include": ['/include "x.a2l"'],
    "stray_star": ["*/"],
    "unclosed_comment": ["/* never closed"],
    "unclosed_quote": ['/begin CHARACTERISTIC Q "unclosed'],
}
for label, extra in shapes.items():
    # build a valid object, then a defect on line 20
    lines = ["ASAP2_VERSION 1 71", '/begin PROJECT P ""', '  /begin MODULE M ""']
    for rl, dt in (("RL_U8","UBYTE"),("RL_U16","UWORD")):
        lines += [f"    /begin RECORD_LAYOUT {rl}", f"      FNC_VALUES 1 {dt} ROW_DIR DIRECT", "    /end RECORD_LAYOUT"]
    lines += [val("P1", "0x10", "RL_U16", "NO_COMPU_METHOD", "0", "65535")]
    # pad to make defect land on line 20
    while len(lines) < 19:
        lines.append("")
    lines.append(extra[0])
    lines += ["  /end MODULE", "/end PROJECT"]
    p = tp / f"{label}.a2l"; p.write_text("\n".join(lines)+"\n", encoding="utf-8")
    a = parse_a2l_file(p)
    print(f"== .152 {label} ==")
    print("  errors:", a.get("errors"))
    d = describe_definition("P1", a)
    print("  P1 refusal:", d.refusal)

# 4. capped marker: /end without /begin on line 20, plus many errors
lines = ["ASAP2_VERSION 1 71", '/begin PROJECT P ""', '  /begin MODULE M ""']
for rl, dt in (("RL_U8","UBYTE"),("RL_U16","UWORD")):
    lines += [f"    /begin RECORD_LAYOUT {rl}", f"      FNC_VALUES 1 {dt} ROW_DIR DIRECT", "    /end RECORD_LAYOUT"]
lines += [val("P5", "0x10", "RL_U16", "NO_COMPU_METHOD", "0", "65535")]
lines += ["  /end MODULE", "/end PROJECT"]
while len(lines) < 19:
    lines.append("")
lines.append("/end X")
for i in range(200):
    lines.append(f"/end X{i}")
p = tp / "capped.a2l"; p.write_text("\n".join(lines)+"\n", encoding="utf-8")
a = parse_a2l_file(p)
print("== .152 capped marker ==")
print("  errors[:3]:", a.get("errors")[:3])
print("  errors[-1]:", a.get("errors")[-1] if a.get("errors") else None)
d = describe_definition("P5", a)
print("  P5 refusal:", d.refusal)

# 5. hostile ASCII H1 (NUMBER 1000000000000)
h = inline(tp, val("VH", "0x10", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
           "/begin CHARACTERISTIC H1 \"\"\n  ASCII 0x10 RL_U8 0 NO_COMPU_METHOD 0 255\n  NUMBER 1000000000000\n/end CHARACTERISTIC")
print("== hostile H1 ==")
for t in h["tags"]:
    if t["name"] == "H1":
        print("  H1 tag:", {k: t.get(k) for k in ("name","address","length","char_type")})
d = describe_definition("H1", h)
print("  H1 refusal:", d.refusal)

# 6. ASCII name confirmation + A2L-READ error presence for H1
print("== H1 errors ==", h.get("errors"))
