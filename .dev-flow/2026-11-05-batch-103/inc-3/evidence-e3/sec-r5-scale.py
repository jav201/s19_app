"""E3 round-5 security probe, Inc 3a (batch-103): the R-A2L-DEF.148 scaling test run over every 3a node path, describe
and decode, on the model of the round-4 correction (`sec-r5-m3a.py`, graph cbaf970b) with Inc 2a's real code.

For each path (a kind of shared content an object can reach, a fill of it, the objects that reach it): two INLINE files
of 400 objects, the shared section at S = 256 KiB and at 2S = 512 KiB.
  describe: T400 = describe of the 400 names, T1 = describe of the first name alone (a fresh walk; it reads each shared
            section once); the per-object part P = T400 - T1; ratio P(2S) / P(S) (R-A2L-DEF.148: <= 1.3; T400(S) <= 0.5 s).
  decode:   400 objects decoded one by one (decode_values per object, model); ratio T(2S) / T(S) (per-object time).
  retained: message bytes per object (describe), text bytes per object (decode), at S and 2S.
Least of 9 describe / 7 decode runs, GC off inside each (1 run once a run passes 2 s). Every definition's public fields compared between S and 2S.
THROWAWAY; read-only trees. Usage: python -I sec-r5-scale.py <inc2a tree> <scratch> [main|describe [pids]|steady [pids]|neg|immut|corpus <lists>...]
"""
import gc, hashlib, importlib.util, pathlib, pickle, signal, sys, time

TREE, S = sys.argv[1], pathlib.Path(sys.argv[2])
MODE = sys.argv[3] if len(sys.argv) > 3 else "main"
ARGS = sys.argv[4:]
sys.path.insert(0, TREE)
import s19_app, s19_app.tui.a2l as a  # noqa: E402
import s19_app.tui.a2l_definition as D  # noqa: E402

spec = importlib.util.spec_from_file_location("m3r5", str(S / "sec-r5-m3a.py"))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); m.bind(a, D)
print("s19_app.__file__ =", s19_app.__file__.replace(str(pathlib.Path.home()), "~"), "| python",
      sys.version.split()[0], "| a2l_definition md5", hashlib.md5(open(D.__file__, "rb").read()).hexdigest()[:8],
      flush=True)
W = S / "work"; W.mkdir(parents=True, exist_ok=True)
N = 400
KIB = 1024


class Timeout(Exception):
    pass


def _alarm(*_):
    raise Timeout()


signal.signal(signal.SIGALRM, _alarm)

# ------------------------------------------------------------------ fills (each about `n` bytes)
ALIGN7 = ("ALIGNMENT_BYTE 1\nALIGNMENT_WORD 2\nALIGNMENT_LONG 4\nALIGNMENT_INT64 8\nALIGNMENT_FLOAT16_IEEE 2\n"
          "ALIGNMENT_FLOAT32_IEEE 4\nALIGNMENT_FLOAT64_IEEE 8\n")


def rep(line, n):
    return line * max(1, n // len(line))


def comment(n):
    return "/* " + ("x" * 78 + "\n") * (n // 79) + " */\n"


def vt_entries(n, base=1000):
    out, k, size = [], 0, 0
    while size < n:
        ln = f' {base + k} "v{k}"\n'
        out.append(ln); size += len(ln); k += 1
    return k, "".join(out)


def vr_entries(n, base=1000):
    out, k, size = [], 0, 0
    while size < n:
        ln = f' {base + 2 * k} {base + 2 * k + 1} "r{k}"\n'
        out.append(ln); size += len(ln); k += 1
    return k, "".join(out)


def tab_entries(n):
    lines, k, size = [], 0, 0
    while size < n:
        ln = f" {k} {k}\n"
        lines.append(ln); size += len(ln); k += 1
    cnt = k
    # x_k = 200 k / (cnt - 1) for k < cnt - 1, last x = 300: a stored 250 lies in the last interval (a full scan)
    out = [f" {200.0 * j / (cnt - 1):.6f} {j}\n" for j in range(cnt - 1)] + [" 300 999\n"]
    return cnt, "".join(out)


# ------------------------------------------------------------------ the file pieces
HEAD = 'ASAP2_VERSION 1 71\n/begin PROJECT P ""\n/begin MODULE M ""\n'
TAIL = "/end MODULE\n/end PROJECT\n"


def mod_common(fill=""):
    return '/begin MOD_COMMON ""\nBYTE_ORDER MSB_FIRST\n' + fill + "/end MOD_COMMON\n"


def rl(name, body, fill=""):
    return f"/begin RECORD_LAYOUT {name}\n{body}{fill}/end RECORD_LAYOUT\n"


CM_BASE = '/begin COMPU_METHOD CM_ID "" IDENTICAL "%.3" ""\n/end COMPU_METHOD\n'
RL_U8 = rl("RL_U8", " FNC_VALUES 1 UBYTE ROW_DIR DIRECT\n")
RL_C = rl("RL_C", " AXIS_PTS_X 1 UBYTE INDEX_INCR DIRECT\n FNC_VALUES 2 UBYTE ROW_DIR DIRECT\n")
RL_M = rl("RL_M", " AXIS_PTS_X 1 UBYTE INDEX_INCR DIRECT\n AXIS_PTS_Y 2 UBYTE INDEX_INCR DIRECT\n"
                  " FNC_VALUES 3 UBYTE ROW_DIR DIRECT\n")
RL_AXO = rl("RL_AXO", " NO_AXIS_PTS_X 1 UBYTE\n AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT\n")


def axo(fill="", lid='""', lname="RL_AXO", maxw="4", addr="0x100"):
    return f'/begin AXIS_PTS AXO {lid} {addr} NO_INPUT_QUANTITY {lname} 0 CM_ID {maxw} 0 255\n{fill}/end AXIS_PTS\n'


def valblks(layout, cm="NO_COMPU_METHOD", number=1):
    return "".join(f'/begin CHARACTERISTIC V{i:05d} ""\n VAL_BLK 0x{0x1000 + 16 * i:X} {layout} 0 {cm} 0 255\n'
                   f' NUMBER {number}\n/end CHARACTERISTIC\n' for i in range(N))


def values(layout, cm="NO_COMPU_METHOD"):
    return "".join(f'/begin CHARACTERISTIC S{i:05d} ""\n VALUE 0x{0x1000 + 16 * i:X} {layout} 0 {cm} 0 255\n'
                   f'/end CHARACTERISTIC\n' for i in range(N))


def cuboids(layout):
    return "".join(f'/begin CHARACTERISTIC Q{i:05d} ""\n CUBOID 0x{0x1000 + 16 * i:X} {layout} 0 NO_COMPU_METHOD 0 255\n'
                   f'/end CHARACTERISTIC\n' for i in range(N))


def std_curves(layout="RL_C", cm="CM_ID", acm=None):
    acm = acm or cm
    return "".join(f'/begin CHARACTERISTIC C{i:05d} ""\n CURVE 0x{0x1000 + 16 * i:X} {layout} 0 {cm} 0 255\n'
                   f' /begin AXIS_DESCR\n  STD_AXIS NO_INPUT_QUANTITY {acm} 4 0 255\n /end AXIS_DESCR\n'
                   f'/end CHARACTERISTIC\n' for i in range(N))


def std_maps(layout="RL_M", cm="CM_ID"):
    ax = f' /begin AXIS_DESCR\n  STD_AXIS NO_INPUT_QUANTITY {cm} 2 0 255\n /end AXIS_DESCR\n'
    return "".join(f'/begin CHARACTERISTIC M{i:05d} ""\n MAP 0x{0x1000 + 16 * i:X} {layout} 0 {cm} 0 255\n'
                   f'{ax}{ax}/end CHARACTERISTIC\n' for i in range(N))


def com_curves(layout="RL_U8", cm="CM_ID"):
    return "".join(f'/begin CHARACTERISTIC C{i:05d} ""\n CURVE 0x{0x1000 + 16 * i:X} {layout} 0 {cm} 0 255\n'
                   f' /begin AXIS_DESCR\n  COM_AXIS NO_INPUT_QUANTITY {cm} 4 0 255\n  AXIS_PTS_REF AXO\n'
                   f' /end AXIS_DESCR\n/end CHARACTERISTIC\n' for i in range(N))


def method(name, typ, fmt, unit, body="", fill=""):
    return f'/begin COMPU_METHOD {name} "" {typ} {fmt} {unit}\n{body}{fill}/end COMPU_METHOD\n'


def vtab(name, count, body, default=""):
    return f'/begin COMPU_VTAB {name} "" TAB_VERB {count}\n{body}{default}/end COMPU_VTAB\n'


def vrange(name, count, body, default=""):
    return f'/begin COMPU_VTAB_RANGE {name} "" {count}\n{body}{default}/end COMPU_VTAB_RANGE\n'


def ctab(name, count, body):
    return f'/begin COMPU_TAB {name} "" TAB_INTP {count}\n{body}/end COMPU_TAB\n'


def f(*parts):
    return HEAD + "".join(parts) + TAIL


# ------------------------------------------------------------------ every path: id -> (users, what, builder(n), decode)
# Users: VB = VAL_BLK (3a, _describe_array), VA = VALUE (Inc 2a scalar path via 3a's _describe_one), QB = CUBOID (kind
# refused; Inc 2a's _resolve_datatype), SC = STD_AXIS CURVE (object + axis _conversion_fields), MP = MAP STD x STD,
# CC = COM_AXIS CURVE (axis object header, its layout, its MOD_COMMON, its byte order).
P = {}


def path(pid, users, what, owner, decode=True, image_byte=250):
    def deco(fn):
        P[pid] = dict(users=users, what=what, build=fn, owner=owner, decode=decode, byte=image_byte)
        return fn
    return deco


# RECORD_LAYOUT ------------------------------------------------------------------------------------------------------
@path("RL-1", "VB", "layout: ALIGNMENT_BYTE 1 lines (.148/1)", "3a #8 _read_record_layout, #9 _place_components")
def _(n): return f(mod_common(), CM_BASE, rl("RL", " FNC_VALUES 1 UBYTE ROW_DIR DIRECT\n", rep("ALIGNMENT_BYTE 1\n", n)), valblks("RL"))
@path("RL-2", "VB", "layout: the 7 ALIGNMENT classes repeated", "3a #8, #9")
def _(n): return f(mod_common(), CM_BASE, rl("RL", " FNC_VALUES 1 UWORD ROW_DIR DIRECT\n", rep(ALIGN7, n)), valblks("RL"))
@path("RL-3", "VB", "layout: a block comment", "3a #8")
def _(n): return f(mod_common(), CM_BASE, rl("RL", " FNC_VALUES 1 UBYTE ROW_DIR DIRECT\n", comment(n)), valblks("RL"))
@path("RL-4", "VB", "layout: DIRECT-only lines (layout keyword)", "3a #8")
def _(n): return f(mod_common(), CM_BASE, rl("RL", " FNC_VALUES 1 UBYTE ROW_DIR DIRECT\n", rep("DIRECT\n", n)), valblks("RL"))
@path("RL-5", "SC", "layout: FIX_NO_AXIS_PTS_X 4 lines (STD curve)", "3a #8, #11 _read_axis")
def _(n): return f(mod_common(), CM_BASE, rl("RL_C", " AXIS_PTS_X 1 UBYTE INDEX_INCR DIRECT\n FNC_VALUES 2 UBYTE ROW_DIR DIRECT\n", rep("FIX_NO_AXIS_PTS_X 4\n", n)), std_curves())
@path("RL-6", "VB", "layout: first line 256 KiB of words, datatype last (.148/2)", "3a #8 (part); Inc 2a _resolve_datatype skipped")
def _(n): return f(mod_common(), CM_BASE, rl("RL_LONG", " FNC_VALUES 1 " + " ".join("X" for _ in range(n // 2)) + " UBYTE ROW_DIR DIRECT\n"), valblks("RL_LONG"))
@path("RL-7", "VB", "layout: one part line, a single 256 KiB word (echoed by .84)", "3a #8 (.84 message)")
def _(n): return f(mod_common(), CM_BASE, rl("RL", " FNC_VALUES 1 UBYTE ROW_DIR DIRECT\n " + "P" * n + "\n"), valblks("RL"))
@path("RL-8", "VB", "layout: FNC_VALUES mode word of 256 KiB (echoed by .85)", "3a #8 (.85 message)")
def _(n): return f(mod_common(), CM_BASE, rl("RL", " FNC_VALUES 1 UBYTE " + "M" * n + " DIRECT\n"), valblks("RL"))
@path("RL-9", "VB", "layout: FNC_VALUES datatype word of 256 KiB (echoed by .86)", "3a #8 (.86 message)")
def _(n): return f(mod_common(), CM_BASE, rl("RL", " FNC_VALUES 1 " + "T" * n + " ROW_DIR DIRECT\n"), valblks("RL"))
@path("RL-10", "VA", "layout: first line 256 KiB, datatype last (.148/3)", "Inc 2a _resolve_datatype (2a E5 memo)")
def _(n): return f(mod_common(), CM_BASE, rl("RL_LONG", " FNC_VALUES 1 " + " ".join("X" for _ in range(n // 2)) + " UBYTE ROW_DIR DIRECT\n"), values("RL_LONG"))
@path("RL-11", "QB", "layout: first line 256 KiB, datatype last, CUBOID objects (kind refused)", "Inc 2a _resolve_datatype (2a E5 memo)", decode=False)
def _(n): return f(mod_common(), CM_BASE, rl("RL_LONG", " FNC_VALUES 1 " + " ".join("X" for _ in range(n // 2)) + " UBYTE ROW_DIR DIRECT\n"), cuboids("RL_LONG"))
@path("RL-12", "SC", "layout: ALIGNMENT_BYTE 1 lines (STD curve)", "3a #8, #9, #11")
def _(n): return f(mod_common(), CM_BASE, rl("RL_C", " AXIS_PTS_X 1 UBYTE INDEX_INCR DIRECT\n FNC_VALUES 2 UBYTE ROW_DIR DIRECT\n", rep("ALIGNMENT_BYTE 1\n", n)), std_curves())
@path("RL-13", "MP", "layout: ALIGNMENT_BYTE 1 lines (STD x STD map)", "3a #8, #9, #11")
def _(n): return f(mod_common(), CM_BASE, rl("RL_M", " AXIS_PTS_X 1 UBYTE INDEX_INCR DIRECT\n AXIS_PTS_Y 2 UBYTE INDEX_INCR DIRECT\n FNC_VALUES 3 UBYTE ROW_DIR DIRECT\n", rep("ALIGNMENT_BYTE 1\n", n)), std_maps())
@path("RL-14", "CC", "the axis object's layout: ALIGNMENT_BYTE 1 lines", "3a #8, #9, #11 (COM)")
def _(n): return f(mod_common(), CM_BASE, RL_U8, rl("RL_AXO", " NO_AXIS_PTS_X 1 UBYTE\n AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT\n", rep("ALIGNMENT_BYTE 1\n", n)), axo(), com_curves())
@path("RL-15", "CC", "the axis object's layout: one part line of a 256 KiB word", "3a #8, #11 (COM; .84 message)")
def _(n): return f(mod_common(), CM_BASE, RL_U8, rl("RL_AXO", " NO_AXIS_PTS_X 1 UBYTE\n AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT\n " + "P" * n + "\n"), axo(), com_curves())


# MOD_COMMON ---------------------------------------------------------------------------------------------------------
@path("MC-1", "VB", "MOD_COMMON: ALIGNMENT_BYTE 1 lines (.148/4)", "3a _module_common, #10 _check_module_alignment")
def _(n): return f(mod_common(rep("ALIGNMENT_BYTE 1\n", n)), CM_BASE, RL_U8, valblks("RL_U8"))
@path("MC-2", "CC", "MOD_COMMON: ALIGNMENT_BYTE 1 lines, COM axis object (.148/5)", "3a _module_common, #10, #11")
def _(n): return f(mod_common(rep("ALIGNMENT_BYTE 1\n", n)), CM_BASE, rl("RL_S16", " FNC_VALUES 1 SWORD ROW_DIR DIRECT\n"), RL_AXO, axo(), com_curves("RL_S16"))
@path("MC-3", "VB", "MOD_COMMON: the 7 classes repeated, UWORD values (moved check)", "3a _module_common, #10")
def _(n): return f(mod_common(rep(ALIGN7, n)), CM_BASE, rl("RL_W", " FNC_VALUES 1 UWORD ROW_DIR DIRECT\n"), valblks("RL_W"))
@path("MC-4", "VB", "MOD_COMMON: DEPOSIT ABSOLUTE lines", "3a _module_common")
def _(n): return f(mod_common(rep("DEPOSIT ABSOLUTE\n", n)), CM_BASE, RL_U8, valblks("RL_U8"))
@path("MC-5", "CC", "MOD_COMMON: BYTE_ORDER lines (the axis object's module byte order)", "3a _module_common, #11")
def _(n): return f('/begin MOD_COMMON ""\n' + rep("BYTE_ORDER MSB_LAST\n", n) + "/end MOD_COMMON\n", CM_BASE, RL_U8, RL_AXO, axo(), com_curves())
@path("MC-6", "VB", "MOD_COMMON: ALIGNMENT_BYTE x lines, each unreadable (.144)", "3a _module_common, #10 (.144)")
def _(n): return f(mod_common(rep("ALIGNMENT_BYTE x\n", n)), CM_BASE, RL_U8, valblks("RL_U8"))
@path("MC-7", "VB", "MOD_COMMON: one ALIGNMENT_BYTE line whose word is 256 KiB (.144 echo)", "3a #10 + _describe_array (.144 message)")
def _(n): return f(mod_common("ALIGNMENT_BYTE " + "9" * n + "\n"), CM_BASE, RL_U8, valblks("RL_U8"))
@path("MC-8", "CC", "MOD_COMMON: one 256 KiB ALIGNMENT_BYTE word, COM axis object (.144 echo)", "3a #10 + _describe_array (.144)")
def _(n): return f(mod_common("ALIGNMENT_BYTE " + "9" * n + "\n"), CM_BASE, rl("RL_S16", " FNC_VALUES 1 SWORD ROW_DIR DIRECT\n"), RL_AXO, axo(), com_curves("RL_S16"))


# AXIS_PTS -----------------------------------------------------------------------------------------------------------
@path("AX-1", "CC", "AXIS_PTS: DEPOSIT ABSOLUTE lines in its body (.148/6)", "3a walk header, #12 _find_axis_object, #11")
def _(n): return f(mod_common(), CM_BASE, RL_U8, RL_AXO, axo(rep("DEPOSIT ABSOLUTE\n", n)), com_curves())
@path("AX-2", "CC", "AXIS_PTS: a block comment in its body", "3a walk, #12, #11")
def _(n): return f(mod_common(), CM_BASE, RL_U8, RL_AXO, axo(comment(n)), com_curves())
@path("AX-3", "CC", "AXIS_PTS: BYTE_ORDER lines in its body (its own byte order)", "3a #11 (axis object byte order)")
def _(n): return f(mod_common(), CM_BASE, RL_U8, RL_AXO, axo(rep("BYTE_ORDER MSB_LAST\n", n)), com_curves())
@path("AX-4", "CC", "AXIS_PTS: a 256 KiB long identifier (header word 2)", "3a walk header (10 words)")
def _(n): return f(mod_common(), CM_BASE, RL_U8, RL_AXO, axo(lid='"' + "L" * n + '"'), com_curves())
@path("AX-5", "CC", "AXIS_PTS: a 256 KiB layout word, not declared (.96 AXIS-LAYOUT)", "3a #11", decode=False)
def _(n): return f(mod_common(), CM_BASE, RL_U8, RL_AXO, axo(lname="R" * n), com_curves())
@path("AX-6", "CC", "AXIS_PTS: a 256 KiB max-axis-points word (.142)", "3a #11", decode=False)
def _(n): return f(mod_common(), CM_BASE, RL_U8, RL_AXO, axo(maxw="9" * n), com_curves())
@path("AX-7", "CC", "AXIS_PTS: a 256 KiB address word (.96 AXIS-REF)", "3a #11", decode=False)
def _(n): return f(mod_common(), CM_BASE, RL_U8, RL_AXO, axo(addr="1" * n), com_curves())


# COMPU_METHOD -------------------------------------------------------------------------------------------------------
LIN = " COEFFS_LINEAR 0.5 0\n"
@path("CM-1", "SC", "COMPU_METHOD: DEPOSIT ABSOLUTE lines (.148/7)", "3a _conversion_fields (object, axis)")
def _(n): return f(mod_common(), CM_BASE, method("CM_L", "LINEAR", '"%.3"', '""', LIN, rep("DEPOSIT ABSOLUTE\n", n)), RL_C, std_curves(cm="CM_L"))
@path("CM-2", "VA", "COMPU_METHOD: a block comment (VALUEs)", "Inc 2a _read_method_record (2a E5 memo)")
def _(n): return f(mod_common(), CM_BASE, method("CM_L", "LINEAR", '"%.3"', '""', LIN, comment(n)), RL_U8, values("RL_U8", "CM_L"))
@path("CM-3", "SC", "COMPU_METHOD: COEFFS_LINEAR lines repeated", "3a _conversion_fields")
def _(n): return f(mod_common(), CM_BASE, method("CM_L", "LINEAR", '"%.3"', '""', rep(LIN, n)), RL_C, std_curves(cm="CM_L"))
@path("CM-4", "SC", "COMPU_METHOD: FORMAT word of 256 KiB ('%' + digits + '.2')", "3a _describe_one decimals, _conversion_fields (axis)")
def _(n): return f(mod_common(), CM_BASE, method("CM_F", "LINEAR", '"%' + "9" * n + '.2"', '""', LIN), RL_C, std_curves(cm="CM_F"))
@path("CM-5", "VA", "COMPU_METHOD: FORMAT word of 256 KiB (VALUEs)", "Inc 2a _describe_one decimals (_display_decimals)")
def _(n): return f(mod_common(), CM_BASE, method("CM_F", "LINEAR", '"%' + "9" * n + '.2"', '""', LIN), RL_U8, values("RL_U8", "CM_F"))
@path("CM-6", "SC", "COMPU_METHOD: conversion type word of 256 KiB (.81/.103 CONVERSION echo)", "3a _conversion_fields (object, axis)", decode=False)
def _(n): return f(mod_common(), CM_BASE, method("CM_T", "Z" * n, '"%.3"', '""'), RL_C, std_curves(cm="CM_T"))
@path("CM-7", "VA", "COMPU_METHOD: conversion type word of 256 KiB (VALUEs)", "Inc 2a _describe_one (CONVERSION message)", decode=False)
def _(n): return f(mod_common(), CM_BASE, method("CM_T", "Z" * n, '"%.3"', '""'), RL_U8, values("RL_U8", "CM_T"))
@path("CM-8", "SC", "COMPU_METHOD: TAB_VERB, COMPU_TAB_REF word of 256 KiB, not declared (TABLE echo)", "3a _conversion_fields", decode=False)
def _(n): return f(mod_common(), CM_BASE, method("CM_V", "TAB_VERB", '"%.3"', '""', " COMPU_TAB_REF " + "G" * n + "\n"), RL_C, std_curves(cm="CM_V"))
@path("CM-9", "VA", "COMPU_METHOD: TAB_VERB, COMPU_TAB_REF word of 256 KiB (VALUEs)", "Inc 2a _describe_one (TABLE message)", decode=False)
def _(n): return f(mod_common(), CM_BASE, method("CM_V", "TAB_VERB", '"%.3"', '""', " COMPU_TAB_REF " + "G" * n + "\n"), RL_U8, values("RL_U8", "CM_V"))
@path("CM-10", "VA", "COMPU_METHOD: unit word of 256 KiB (VALUEs)", "Inc 2a _describe_one (unit by reference)")
def _(n): return f(mod_common(), CM_BASE, method("CM_U", "LINEAR", '"%.3"', '"' + "U" * n + '"', LIN), RL_U8, values("RL_U8", "CM_U"))
@path("CM-11", "VB", "COMPU_METHOD: TAB_INTP, COMPU_TAB_REF word of 256 KiB, not declared", "3a _conversion_fields; decode _apply_compu_method")
def _(n): return f(mod_common(), CM_BASE, method("CM_I", "TAB_INTP", '"%.3"', '""', " COMPU_TAB_REF " + "G" * n + "\n"), RL_U8, valblks("RL_U8", "CM_I"))


# COMPU_VTAB / COMPU_VTAB_RANGE / COMPU_TAB --------------------------------------------------------------------------
def _vt(n):
    k, body = vt_entries(n)
    return vtab("VT", k, body)


def _vr(n):
    k, body = vr_entries(n)
    return vrange("VR", k, body)


CMV = method("CM_V", "TAB_VERB", '"%.3"', '""', " COMPU_TAB_REF VT\n")
CMR = method("CM_R", "TAB_VERB", '"%.3"', '""', " COMPU_TAB_REF VR\n")
@path("VT-1", "SC", "COMPU_VTAB: entries (.148/8)", "3a _conversion_fields; decode _enum_entry_text")
def _(n): return f(mod_common(), CM_BASE, CMV, _vt(n), RL_C, std_curves(cm="CM_V"))
@path("VT-2", "VB", "COMPU_VTAB: entries (VAL_BLKs)", "3a _conversion_fields; decode _enum_entry_text")
def _(n): return f(mod_common(), CM_BASE, CMV, _vt(n), RL_U8, valblks("RL_U8", "CM_V"))
@path("VT-3", "VA", "COMPU_VTAB: entries (enum VALUEs)", "Inc 2a _read_enum_table (2a E5); decode _enum_text")
def _(n): return f(mod_common(), CM_BASE, CMV, _vt(n), RL_U8, values("RL_U8", "CM_V"))
@path("VT-4", "VB", "COMPU_VTAB: a block comment", "3a _conversion_fields")
def _(n): return f(mod_common(), CM_BASE, CMV, vtab("VT", 2, ' 1000 "a"\n 1001 "b"\n' + comment(n)), RL_U8, valblks("RL_U8", "CM_V"))
@path("VT-5", "VB", "COMPU_VTAB: one entry whose text is 256 KiB, matched", "decode _enum_text (_clean per element)", image_byte=0)
def _(n): return f(mod_common(), CM_BASE, CMV, vtab("VT", 1, ' 0 "' + "t" * n + '"\n'), RL_U8, valblks("RL_U8", "CM_V"))
@path("VT-6", "VB", "COMPU_VTAB: a DEFAULT_VALUE text of 256 KiB, no entry matched", "decode _enum_text (_clean per element)")
def _(n): return f(mod_common(), CM_BASE, CMV, vtab("VT", 1, ' 1000 "a"\n', ' DEFAULT_VALUE "' + "d" * n + '"\n'), RL_U8, valblks("RL_U8", "CM_V"))
@path("VT-7", "VB", "COMPU_VTAB: count 0, 256 KiB of entries after it (TABLE-EMPTY)", "3a _conversion_fields (.81 message)", decode=False)
def _(n): return f(mod_common(), CM_BASE, CMV, vtab("VT", 0, vt_entries(n)[1]), RL_U8, valblks("RL_U8", "CM_V"))
@path("VR-1", "SC", "COMPU_VTAB_RANGE: entries (.148/9)", "3a _conversion_fields; decode _enum_entry_text")
def _(n): return f(mod_common(), CM_BASE, CMR, _vr(n), RL_C, std_curves(cm="CM_R"))
@path("VR-2", "VB", "COMPU_VTAB_RANGE: one range whose text is 256 KiB, matched", "decode _enum_text", image_byte=0)
def _(n): return f(mod_common(), CM_BASE, CMR, vrange("VR", 1, ' 0 255 "' + "t" * n + '"\n'), RL_U8, valblks("RL_U8", "CM_R"))
@path("CT-1", "VB", "COMPU_TAB: entries, TAB_INTP (value in the last interval)", "decode frozen _table_lookup")
def _(n):
    k, body = tab_entries(n)
    return f(mod_common(), CM_BASE, method("CM_I", "TAB_INTP", '"%.3"', '""', " COMPU_TAB_REF CT\n"), ctab("CT", k, body), RL_U8, valblks("RL_U8", "CM_I"))
@path("CT-2", "VB", "COMPU_TAB: entries, TAB_NOINTP (no exact entry)", "decode frozen _table_lookup")
def _(n):
    k, body = tab_entries(n)
    return f(mod_common(), CM_BASE, method("CM_N", "TAB_NOINTP", '"%.3"', '""', " COMPU_TAB_REF CT\n"), ctab("CT", k, body), RL_U8, valblks("RL_U8", "CM_N"))


# ------------------------------------------------------------------ harness
def parse(tag, txt):
    p = W / f"{tag}.a2l"
    p.write_text(txt, encoding="utf-8")
    t0 = time.perf_counter()
    data = a.parse_a2l_file(p)
    return data, time.perf_counter() - t0, p.stat().st_size


CLOCK = time.process_time if MODE == "steady" else time.perf_counter   # steady: this process's CPU time


def least(fn, reps, cap=120):
    """Least of `reps` timed runs, the cyclic GC off inside each run (collected before it)."""
    best, res = None, None
    for i in range(reps):
        res = None
        gc.collect()
        signal.alarm(cap)
        gc.disable()
        try:
            t0 = CLOCK(); res = fn(); t = CLOCK() - t0
        except Timeout:
            return None, float("inf")
        finally:
            gc.enable()
            signal.alarm(0)
        best = t if best is None else min(best, t)
        if t > 2.0:
            break
    return res, best


def image_for(data, byte):
    img = {}
    for i in range(N):
        for o in range(16):
            img[0x1000 + 16 * i + o] = byte
    img[0x100] = 4
    for o in range(1, 5):
        img[0x100 + o] = 10 * o
    return img


def run_path(pid, reps=9, mutant=None, do_decode=True):
    spec_ = P[pid]
    m.set_mutant(mutant)
    row = {"pid": pid}
    pubs = {}
    for size in (256, 512):
        data, tparse, fsize = parse(f"r5_{pid}_{size}", spec_["build"](size * KIB))
        names = [nm for nm in (t["name"] for t in data["tags"]) if nm[:1] in "VSQCM" and nm[1:].isdigit()]
        assert len(names) == N, (pid, size, len(names))
        m.STATS.clear()
        r400, t400 = least(lambda: m.describe(names, data), reps)
        r1, t1 = least(lambda: m.describe(names[:1], data), reps)
        rec = {"file_kib": fsize / KIB, "parse": tparse, "t400": t400, "t1": t1, "per": t400 - t1}
        if r400 is not None:
            d2a, d3a, maps = r400
            pubs[size] = {nm: m.public(d2a[nm], d3a.get(nm)) for nm in names}
            codes = {}
            for nm in names:
                k = (d3a[nm]["refusal"] if nm in d3a else (d2a[nm].refusal.code if d2a[nm].refusal else None))
                codes[k] = codes.get(k, 0) + 1
            rec["codes"] = codes
            rec["msg_per_obj"] = m.message_bytes(d2a, d3a) / N
            st = maps["stats"]
            rec["reads"] = {k: v for k, v in st.items() if k.endswith("_reads") and v}
            if do_decode and spec_["decode"]:
                img = image_for(data, spec_["byte"])
                rdec, tdec = least(lambda: [m.decode_model(d2a[nm], d3a.get(nm), data, img) for nm in names], 7)
                rec["tdec"] = tdec
                if rdec is not None:
                    texts = 0
                    errs = {}
                    for res in rdec:
                        for x in res if isinstance(res, tuple) else (res,):
                            if hasattr(x, "text") and isinstance(x.text, str):
                                texts += len(x.text)
                            elif isinstance(x, D.Refusal):
                                errs[x.code] = errs.get(x.code, 0) + 1
                            elif isinstance(x, str):
                                errs[x] = errs.get(x, 0) + 1
                    rec["text_per_obj"] = texts / N
                    rec["dec_refusals"] = errs
                del rdec
        del r400, r1
        row[size] = rec
    a_, b_ = row[256], row[512]
    row["ratio"] = (b_["per"] / a_["per"]) if a_["per"] > 0 else float("nan")
    row["same"] = pubs.get(256) == pubs.get(512) if pubs else None
    if "tdec" in a_ and "tdec" in b_:
        row["dratio"] = b_["tdec"] / a_["tdec"] if a_["tdec"] > 0 else float("nan")
    verdict = []
    if not (a_["t400"] <= 0.5):
        verdict.append("T400>0.5s")
    if not (row["ratio"] <= 1.3):
        verdict.append("describe x%.2f" % row["ratio"])
    if "dratio" in row and not (row["dratio"] <= 1.3):
        verdict.append("decode x%.2f" % row["dratio"])
    row["verdict"] = "GREEN" if not verdict else "RED: " + ", ".join(verdict)
    m.set_mutant(None)
    return row


def show(row, mutant=None):
    pid = row["pid"]
    sp = P[pid]
    a_, b_ = row[256], row[512]
    dec = ""
    if "tdec" in a_:
        dec = (f" | decode {a_['tdec']:.3f} -> {b_['tdec']:.3f} s (x{row.get('dratio', float('nan')):.2f}), text/obj "
               f"{a_.get('text_per_obj', 0) / KIB:.1f} -> {b_.get('text_per_obj', 0) / KIB:.1f} KiB, decode refusals "
               f"{a_.get('dec_refusals')}")
    print(f"[{pid}]{' MUTANT=' + mutant if mutant else ''} {sp['users']} {sp['what']} ({sp['owner']}): files "
          f"{a_['file_kib']:.0f}/{b_['file_kib']:.0f} KiB, parse {a_['parse']:.2f}/{b_['parse']:.2f} s | describe T400 "
          f"{a_['t400']:.3f} / {b_['t400']:.3f} s, T1 {a_['t1']:.3f} / {b_['t1']:.3f} s, per-object part "
          f"{a_['per']:.4f} -> {b_['per']:.4f} s (x{row['ratio']:.2f}); msg/obj {a_.get('msg_per_obj', 0) / KIB:.1f} -> "
          f"{b_.get('msg_per_obj', 0) / KIB:.1f} KiB; reads {a_.get('reads')}; codes {a_.get('codes')}; same at both "
          f"sizes {row['same']}{dec} => {row['verdict']}", flush=True)


if MODE in ("main", "describe"):                    # "describe": the describe half only
    only = ARGS
    for pid in P:
        if only and pid not in only:
            continue
        try:
            show(run_path(pid, do_decode=MODE == "main"))
        except Exception as e:                         # an exception is itself a finding (R-A2L-DEF.58.2)
            print(f"[{pid}] EXCEPTION {type(e).__name__}: {e}", flush=True)

elif MODE == "steady":                                # the per-object part measured directly (host under load)
    # One walk's maps built once (Inc 2a's describe_definitions maps, 3a's `maps`), the first name described (it fills
    # every read and memo, as the first name's own call does), then the other 399 names timed in that walk: the time
    # beyond the first name, with no walk in the timed part. Decode: `passes` passes over the 400 objects per run.
    # Times are this process's CPU time (time.process_time): the host is shared, and wall time counts waits.
    only = ARGS
    R4 = m.R4

    def walk2a(data):
        tbn, osn, cmn, ctn = {}, {}, {}, {}
        for t in data.get("tags") or []:
            tbn.setdefault(t.get("name"), []).append(t)

        def w(nodes):
            for node in nodes:
                nn = node.get("name")
                pm = a.parse_begin_meta(node.get("meta", "") or "")
                if nn in ("MEASUREMENT", "CHARACTERISTIC"):
                    osn.setdefault(pm[0], []).append(node)
                elif nn == "COMPU_METHOD":
                    cmn.setdefault(pm[0], node)
                elif nn in ("COMPU_VTAB", "COMPU_VTAB_RANGE"):
                    ctn.setdefault(pm[0], node)
                w(node.get("children") or [])
        w(data.get("sections") or [])
        return tbn, osn, cmn, ctn

    class Ctx:
        """One file of a path at one size: one walk's maps, the first name described, the 399 others to time."""

        def __init__(self, pid, size, mutant):
            sp = P[pid]
            self.size = size
            data, _, _ = parse(f"r5s_{pid}_{size}", sp["build"](size * KIB))
            self.data = data
            self.names = [nm for nm in (t["name"] for t in data["tags"]) if nm[:1] in "VSQCM" and nm[1:].isdigit()]
            assert len(self.names) == N
            self.w2a = walk2a(data)
            self.maps = m.new_maps(data)
            self.secs = m.B.object_sections(data)
            self.tags = {}
            for t in data.get("tags") or []:
                self.tags.setdefault(t.get("name"), t)
            self.memo = ({} if mutant != "per-call" else None, {} if mutant != "per-call" else None)
            self.d2a, self.d3a = {}, {}
            self.one(self.names[0])
            gc.collect(); gc.disable()
            try:
                t0 = CLOCK(); self.desc(); self.first_run = CLOCK() - t0   # every definition; its time is one run
            finally:
                gc.enable()
            self.img = image_for(data, sp["byte"]) if sp["decode"] else None

        def _on(self):
            R4._E5["memo"], m._RD["memo"] = self.memo

        def one(self, nm):
            self._on()
            self.d2a[nm] = D._describe_one(nm, *self.w2a, self.data)
            if m.B.is_array_kind(self.tags[nm], self.secs[nm][0]):
                self.d3a[nm] = m.describe_array(self.tags[nm], self.secs[nm][0], self.data, self.maps)

        def desc(self):
            for nm in self.names[1:]:
                self.one(nm)

        def dec(self, passes):
            for _ in range(passes):
                for nm in self.names:
                    m.decode_model(self.d2a[nm], self.d3a.get(nm), self.data, self.img)

    def interleaved(ctxs, fn, reps):
        """Least of `reps` runs per context, the contexts' runs interleaved (same host conditions for each size)."""
        best = [float("inf")] * len(ctxs)
        for r in range(reps):
            slow = False
            for i, c in enumerate(ctxs):
                gc.collect(); gc.disable()
                try:
                    t0 = CLOCK(); fn(c); t = CLOCK() - t0
                finally:
                    gc.enable()
                best[i] = min(best[i], t)
                slow = slow or t > 2.0
            if slow:
                break
        return best

    def measure(pid, mutant=None):
        sp = P[pid]
        m.set_mutant(mutant)
        try:
            ctxs = [Ctx(pid, 256, mutant), Ctx(pid, 512, mutant)]
            if ctxs[0].first_run / (N - 1) < 1e-3:      # flat or nearly: add 8S, where a per-object walk gives x8
                ctxs.append(Ctx(pid, 2048, mutant))
                tdesc = [t / (N - 1) for t in interleaved(ctxs, lambda c: c.desc(), 15)]
            else:                                        # >= 1 ms per object: the one run each is the measure
                tdesc = [c.first_run / (N - 1) for c in ctxs]
            out = {"sizes": [c.size for c in ctxs], "desc": tdesc,
                   "msg": [m.message_bytes(c.d2a, c.d3a) / N for c in ctxs],
                   "codes": sorted({(c.d3a[nm]["refusal"] if nm in c.d3a else
                                     (c.d2a[nm].refusal.code if c.d2a[nm].refusal else None))
                                    for c in ctxs[:1] for nm in c.names}, key=str),
                   "same": len({tuple(m.public(c.d2a[nm], c.d3a.get(nm)) for nm in c.names) for c in ctxs}) == 1}
            if sp["decode"] and mutant is None:
                one_pass = interleaved(ctxs[:1], lambda c: c.dec(1), 1)[0]
                dctx = ctxs if one_pass < 0.4 else ctxs[:2]
                passes = max(1, min(10, int(0.05 / max(one_pass, 1e-6)) + 1))
                td = interleaved(dctx, lambda c: c.dec(passes), 9 if one_pass < 0.5 else (3 if one_pass < 3 else 1))
                out["dec"] = [t / passes / N for t in td]
                texts = []
                for c in dctx:
                    rs = [m.decode_model(c.d2a[nm], c.d3a.get(nm), c.data, c.img) for nm in c.names]
                    texts.append(sum(len(x.text) for r in rs for x in r if hasattr(x, "text") and isinstance(x.text, str)) / N)
                    del rs
                out["text"] = texts
            return out
        finally:
            R4._E5["memo"] = None
            m._RD["memo"] = None
            m.set_mutant(None)

    def fmt(vals, unit=1e6):
        return " / ".join(f"{v * unit:.1f}" for v in vals)

    todo = [(pid, None) for pid in P if not only or pid in only]
    if not only:
        todo += [("RL-1", "every-pair"), ("MC-1", "every-pair"), ("MC-2", "every-pair"), ("RL-10", "rd-per-object"),
                 ("RL-11", "rd-per-object"), ("CM-2", "per-call"), ("VT-3", "per-call")]
    for pid, mut in todo:
        try:
            o = measure(pid, mut)
        except Exception as e:                        # an exception is itself a finding
            print(f"[{pid}] EXCEPTION {type(e).__name__}: {e}", flush=True)
            continue
        d = o["desc"]
        r2 = d[1] / d[0]
        r8 = d[2] / d[0] if len(d) > 2 else None
        red = r2 > 1.3 and (r8 is None or r8 > 2.0)    # under load: x1.3 at 2S confirmed by x2 or more at 8S
        line = (f"[S {pid}]{' MUTANT=' + mut if mut else ''} {P[pid]['users']} {P[pid]['what']}: sizes {o['sizes']} KiB; "
                f"describe per object {fmt(d)} us (2S x{r2:.2f}{f', 8S x{r8:.2f}' if r8 else ''}); message/obj "
                f"{fmt(o['msg'], 1 / KIB)} KiB; codes {o['codes']}; same at every size {o['same']}")
        if "dec" in o:
            dd = o["dec"]
            q2 = dd[1] / dd[0]
            q8 = dd[2] / dd[0] if len(dd) > 2 else None
            dred = q2 > 1.3 and (q8 is None or q8 > 2.0)
            red = red or dred
            line += (f" | decode per object {fmt(dd)} us (2S x{q2:.2f}{f', 8S x{q8:.2f}' if q8 else ''}); text/obj "
                     f"{fmt(o['text'], 1 / KIB)} KiB{' RED' if dred else ''}")
        print(line + (" => RED" if red else " => GREEN"), flush=True)

elif MODE == "neg":                                   # the harness turns RED on the mutants the row names
    for pid, mut in (("RL-1", "every-pair"), ("MC-2", "every-pair"), ("RL-10", "rd-per-object"),
                     ("CM-2", "per-call")):
        show(run_path(pid, reps=3, mutant=mut, do_decode=False), mut)

elif MODE == "immut":                                 # [I] the cached reduced forms stay immutable
    import dataclasses, types
    MPT = types.MappingProxyType
    ok_types = (str, int, float, bool, type(None))

    def walk(x, path_, bad):
        if isinstance(x, ok_types):
            return
        if isinstance(x, tuple):
            for i, y in enumerate(x):
                walk(y, path_ + f"[{i}]", bad)
            try:
                x.append(1); bad.append(path_ + " tuple.append")
            except AttributeError:
                pass
            return
        if isinstance(x, MPT):
            try:
                x["__probe"] = 1; bad.append(path_ + " MP assign")
            except TypeError:
                pass
            for k, y in x.items():
                walk(y, path_ + f".{k}", bad)
            return
        if isinstance(x, D.EnumEntry):
            try:
                setattr(x, "text", "X"); bad.append(path_ + " EnumEntry setattr")
            except dataclasses.FrozenInstanceError:
                pass
            return
        bad.append(f"{path_} {type(x).__name__}")      # a list, dict, set or other mutable container

    tot = {}
    for pid in ("RL-1", "RL-2", "RL-7", "RL-14", "MC-3", "MC-6", "MC-7", "AX-1", "AX-4", "CM-1", "CM-6", "CM-8",
                "VT-1", "VT-6", "VR-1", "CT-1"):
        data, _, _ = parse(f"r5i_{pid}", P[pid]["build"](64 * KIB))
        before = hashlib.md5(pickle.dumps(data, protocol=4)).hexdigest()
        names = [t["name"] for t in data["tags"]]
        d2a, d3a, maps = m.describe(names, data)
        img = image_for(data, P[pid]["byte"])
        for nm in names:
            m.decode_model(d2a[nm], d3a.get(nm), data, img)
        after = hashlib.md5(pickle.dumps(data, protocol=4)).hexdigest()
        bad = []
        kinds = {}
        for key, form in maps["reads"].items():
            kind = ("layout" if isinstance(form, MPT) and "components" in form else
                    "mod_common" if isinstance(form, MPT) and "byte_order" in form else
                    "method" if isinstance(form, MPT) and "conversion_type" in form else
                    "layout-refusal" if isinstance(form, tuple) and form and form[0] == "REFUSAL" else
                    "enum-table" if isinstance(form, tuple) else
                    "byte-order" if isinstance(form, str) else type(form).__name__)
            kinds[kind] = kinds.get(kind, 0) + 1
            walk(form, f"reads[{kind}]", bad)
            if kind == "method" and set(form) != set(m.SIX):
                bad.append(f"method keys {sorted(form)}")
            if kind in ("layout", "mod_common"):
                al = form["alignment"]
                if len(al) > 7:
                    bad.append(f"{kind} alignment {len(al)} entries")
        for k, hdr in maps.get("axis_pts_hdr", {}).items():
            walk(hdr, "axis_pts_hdr", bad)
            if len(hdr) > 10:
                bad.append(f"header {len(hdr)} words")
        for v in maps.get("axo_bo", {}).values():
            walk(v, "axo_bo", bad)
        for kk, vv in kinds.items():
            tot[kk] = tot.get(kk, 0) + vv
        print(f"[I] {pid}: read forms {kinds}, headers {len(maps.get('axis_pts_hdr', {}))}; mutable or mutated: "
              f"{bad or 'none'}; a2l_data digest unchanged by describe + decode: {before == after}", flush=True)
    print(f"[I] total read forms by kind {tot}", flush=True)

elif MODE == "corpus":                                # [E] the reduced forms change no definition (vs every pair)
    from concurrent.futures import ProcessPoolExecutor

    def one(path_):
        try:
            data = a.parse_a2l_file(pathlib.Path(path_))
            m.set_mutant(None)
            r, _ = m.describe_all(data)
            m.set_mutant("every-pair")
            e, _ = m.describe_all(data)
            m.set_mutant(None)
            diffs = [nm for nm in r if (r[nm]["refusal"], r[nm]["message"], m.public(None, r[nm])) !=
                     (e[nm]["refusal"], e[nm]["message"], m.public(None, e[nm]))]
            codes = {}
            for v in r.values():
                codes[v["refusal"]] = codes.get(v["refusal"], 0) + 1
            return {"objects": len(r), "diffs": len(diffs), "first": diffs[:3], "align": codes.get("A2L-DEF-ALIGNMENT", 0)}
        except Exception as ex:
            return {"error": f"{type(ex).__name__}: {ex}"[:200]}

    files = [ln.strip() for lf in ARGS for ln in open(lf) if ln.strip()]
    with ProcessPoolExecutor(8) as ex:
        res = list(ex.map(one, files))
    errs = [r for r in res if "error" in r]
    print(f"[E] files {len(files)}, errors {len(errs)} {errs[:3]}, objects {sum(r.get('objects', 0) for r in res)}, "
          f"A2L-DEF-ALIGNMENT {sum(r.get('align', 0) for r in res)}, definitions that differ between the reduced "
          f"forms and every pair: {sum(r.get('diffs', 0) for r in res)} "
          f"{[r['first'] for r in res if r.get('diffs')][:3]}", flush=True)
