import sys, tempfile
from pathlib import Path
sys.path.insert(0, ".")
from s19_app.tui.a2l_parse import parse_a2l_file
print("s19_app.__file__ =", __import__("s19_app").__file__)

_LAYOUTS = (("RL_U8","UBYTE"),("RL_S8","SBYTE"),("RL_U16","UWORD"),("RL_S16","SWORD"),("RL_U32","ULONG"),("RL_F16","FLOAT16_IEEE"),("RL_F32","FLOAT32_IEEE"),("RL_F64","FLOAT64_IEEE"))

def inline(path, *blocks, byte_order="MSB_FIRST"):
    lines = ["ASAP2_VERSION 1 71", '/begin PROJECT P ""', '  /begin MODULE M ""']
    if byte_order is not None:
        lines += ['    /begin MOD_COMMON ""', f"      BYTE_ORDER {byte_order}", "    /end MOD_COMMON"]
    for rl, dt in _LAYOUTS:
        lines += [f"    /begin RECORD_LAYOUT {rl}", f"      FNC_VALUES 1 {dt} ROW_DIR DIRECT", "    /end RECORD_LAYOUT"]
    for b in blocks: lines.append(b)
    lines += ["  /end MODULE", "/end PROJECT"]
    p = path / "x.a2l"; p.write_text("\n".join(lines)+"\n", encoding="utf-8")
    return parse_a2l_file(p)

def val(name, addr, layout, conv="NO_COMPU_METHOD", lo="0", hi="65535", *extra):
    return "\n".join([f'/begin CHARACTERISTIC {name} ""', f"  VALUE {addr} {layout} 0 {conv} {lo} {hi}"] + [f"  {e}" for e in extra] + ["/end CHARACTERISTIC"])

tp = Path(tempfile.mkdtemp(prefix="b103e4p5_"))
c = 0

# BLOB
c += 1
a = inline(tp, val("VB", "0x10", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
           '/begin BLOB B1 ""\n  0x10 2\n/end BLOB')
print(f"[{c}] BLOB declared_spans:", a.get("declared_spans"), "errors:", a.get("errors"))

# sized INSTANCE (TYPEDEF_MEASUREMENT UWORD)
c += 1
a = inline(tp, val("VI", "0x10", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
           '/begin TYPEDEF_MEASUREMENT T_U16 ""\n  UWORD NO_COMPU_METHOD 0 0 0 65535\n/end TYPEDEF_MEASUREMENT',
           '/begin INSTANCE I1 ""\n  T_U16 0x10\n/end INSTANCE')
print(f"[{c}] sized INSTANCE declared_spans:", a.get("declared_spans"), "errors:", a.get("errors"))

# unsized INSTANCE (T_NONE undeclared)
c += 1
a = inline(tp, val("VU", "0x10", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
           '/begin INSTANCE IU ""\n  T_NONE 0x10\n/end INSTANCE')
print(f"[{c}] unsized INSTANCE declared_spans:", a.get("declared_spans"), "errors:", a.get("errors"))

# duplicate BYTE_ORDER in MOD_COMMON (via byte_order=None, custom block)
c += 1
mod_common = '\n'.join(['    /begin MOD_COMMON ""', "      BYTE_ORDER MSB_FIRST", "      BYTE_ORDER MSB_LAST", "    /end MOD_COMMON"])
a = inline(tp, mod_common, val("BO", "0x10", "RL_U16", "NO_COMPU_METHOD", "0", "65535", "BIT_MASK 0x0FF0"), byte_order=None)
print(f"[{c}] dup BYTE_ORDER errors:", a.get("errors"))
from s19_app.tui.a2l_definition import describe_definition
d = describe_definition("BO", a)
print(f"    BO: byte_order={d.byte_order} refusal={d.refusal}")

# OA/OB overlap (unmasked UWORD 0x10 + UBYTE 0x11)
c += 1
a = inline(tp, val("OA", "0x10", "RL_U16", "NO_COMPU_METHOD", "0", "65535"), val("OB", "0x11", "RL_U8", "NO_COMPU_METHOD", "0", "255"))
print(f"[{c}] OA/OB errors:", a.get("errors"))

# MA/MB common-bit masks
c += 1
a = inline(tp, val("MA", "0x10", "RL_U16", "NO_COMPU_METHOD", "0", "65535", "BIT_MASK 0x0FF0"), val("MB", "0x10", "RL_U16", "NO_COMPU_METHOD", "0", "65535", "BIT_MASK 0x0010"))
print(f"[{c}] MA/MB errors:", a.get("errors"))
