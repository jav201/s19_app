"""E3 round-7 security probe, Inc 3a (batch-103): R-A2L-DEF.148 / .150's scaling test under E3S3-24's steady measure,
on the model of the round-6 correction (`sec-r7-m3a.py`, graph 0db7c4b7) with Inc 2a's real code; the round-6 paths
(builders copied unchanged from `sec-r6-scale.py`) plus round 7's own (CT-5, CT-6, CT-7, VT-10); and the round-7
checks: the v2 bisect census and the range segment index equality, the raise cases, the carried table form.

Measure (E3S3-24 with the round-6 correction's ruling): one walk's maps built, the first name described in that walk,
then the 399 other names timed in it with time.process_time(), garbage collection off around each timed run; S, 2S and
8S (256 KiB, 512 KiB, 2 MiB) interleaved run by run; the least of 15 runs (the one run at S and 2S once a run takes
>= 1 ms per object). Round 7: each of the 15 runs is a FRESH walk, so the 399 names are each described for the first
time in their walk (round 6 re-described them in the warm walk, which hides a per-object first-use reduction). Decode: the 400 objects' decode per object, interleaved likewise. GREEN when x2S <= 1.5 and
x8S <= 2.0 (describe and decode), the 400 names' walk at S <= 0.5 s, every definition's message <= 1,024 characters at
every size, and the decoded text per object does not grow.
THROWAWAY; read-only trees; derived numbers only. Usage:
  python -I -B sec-r7-scale.py <inc2a tree> <scratch> steady [pids] | neg [pids] | raise | bisect <lists>
"""
import gc, hashlib, importlib.util, math, pathlib, signal, struct, sys, time
sys.dont_write_bytecode = True

TREE, S = sys.argv[1], pathlib.Path(sys.argv[2])
MODE = sys.argv[3] if len(sys.argv) > 3 else "steady"
ARGS = sys.argv[4:]
sys.path.insert(0, TREE)
import s19_app, s19_app.tui.a2l as a  # noqa: E402
import s19_app.tui.a2l_definition as D  # noqa: E402

spec = importlib.util.spec_from_file_location("m3r7", str(S / "sec-r7-m3a.py"))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); m.bind(a, D)
R6 = m.R6
R5, R4 = R6.R5, R6.R4
print("s19_app.__file__ =", s19_app.__file__.replace(str(pathlib.Path.home()), "~"), "| python",
      sys.version.split()[0], "| a2l_definition md5", hashlib.md5(open(D.__file__, "rb").read()).hexdigest()[:8],
      "| a2l md5", hashlib.md5(open(a.__file__, "rb").read()).hexdigest()[:8], flush=True)
W = S / "work"; W.mkdir(parents=True, exist_ok=True)
N = 400
KIB = 1024
CLOCK = time.process_time
B2, B8 = 1.5, 2.0          # the ruled bounds: x2S <= 1.5, x8S <= 2.0
FULL = False               # mode "full": no one-run shortcut, no early stop; 15 cold runs at every size

# ------------------------------------------------------------------ fills and file pieces (round 5's, unchanged)
ALIGN7 = ("ALIGNMENT_BYTE 1\nALIGNMENT_WORD 2\nALIGNMENT_LONG 4\nALIGNMENT_INT64 8\nALIGNMENT_FLOAT16_IEEE 2\n"
          "ALIGNMENT_FLOAT32_IEEE 4\nALIGNMENT_FLOAT64_IEEE 8\n")


def rep(line, n): return line * max(1, n // len(line))
def comment(n): return "/* " + ("x" * 78 + "\n") * (n // 79) + " */\n"


def vt_entries(n, base=1000):
    out, k, size = [], 0, 0
    while size < n:
        ln = f' {base + k} "v{k}"\n'; out.append(ln); size += len(ln); k += 1
    return k, "".join(out)


def vr_entries(n, base=1000):
    out, k, size = [], 0, 0
    while size < n:
        ln = f' {base + 2 * k} {base + 2 * k + 1} "r{k}"\n'; out.append(ln); size += len(ln); k += 1
    return k, "".join(out)


def tab_entries(n):
    k, size = 0, 0
    while size < n:
        size += len(f" {k} {k}\n"); k += 1
    cnt = k
    out = [f" {200.0 * j / (cnt - 1):.6f} {j}\n" for j in range(cnt - 1)] + [" 300 999\n"]
    return cnt, "".join(out)


HEAD = 'ASAP2_VERSION 1 71\n/begin PROJECT P ""\n/begin MODULE M ""\n'
TAIL = "/end MODULE\n/end PROJECT\n"
def mod_common(fill=""): return '/begin MOD_COMMON ""\nBYTE_ORDER MSB_FIRST\n' + fill + "/end MOD_COMMON\n"
def rl(name, body, fill=""): return f"/begin RECORD_LAYOUT {name}\n{body}{fill}/end RECORD_LAYOUT\n"


CM_BASE = '/begin COMPU_METHOD CM_ID "" IDENTICAL "%.3" ""\n/end COMPU_METHOD\n'
RL_U8 = rl("RL_U8", " FNC_VALUES 1 UBYTE ROW_DIR DIRECT\n")
RL_C = rl("RL_C", " AXIS_PTS_X 1 UBYTE INDEX_INCR DIRECT\n FNC_VALUES 2 UBYTE ROW_DIR DIRECT\n")
RL_M = rl("RL_M", " AXIS_PTS_X 1 UBYTE INDEX_INCR DIRECT\n AXIS_PTS_Y 2 UBYTE INDEX_INCR DIRECT\n"
                  " FNC_VALUES 3 UBYTE ROW_DIR DIRECT\n")
RL_AXO = rl("RL_AXO", " NO_AXIS_PTS_X 1 UBYTE\n AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT\n")
AXO_BODY = " NO_AXIS_PTS_X 1 UBYTE\n AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT\n"


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


def vtab(name, count, body, default=""): return f'/begin COMPU_VTAB {name} "" TAB_VERB {count}\n{body}{default}/end COMPU_VTAB\n'
def vrange(name, count, body, default=""): return f'/begin COMPU_VTAB_RANGE {name} "" {count}\n{body}{default}/end COMPU_VTAB_RANGE\n'
def ctab(name, count, body, kind="TAB_INTP"): return f'/begin COMPU_TAB {name} "" {kind} {count}\n{body}/end COMPU_TAB\n'
def f(*parts): return HEAD + "".join(parts) + TAIL


P = {}


def path(pid, users, what, owner, decode=True, image_byte=250, new=False):
    def deco(fn):
        P[pid] = dict(users=users, what=what, build=fn, owner=owner, decode=decode, byte=image_byte, new=new)
        return fn
    return deco


# RECORD_LAYOUT (round 5)
@path("RL-1", "VB", "layout: ALIGNMENT_BYTE 1 lines (.148/1)", "3a")
def _(n): return f(mod_common(), CM_BASE, rl("RL", " FNC_VALUES 1 UBYTE ROW_DIR DIRECT\n", rep("ALIGNMENT_BYTE 1\n", n)), valblks("RL"))
@path("RL-2", "VB", "layout: the 7 ALIGNMENT classes repeated", "3a")
def _(n): return f(mod_common(), CM_BASE, rl("RL", " FNC_VALUES 1 UWORD ROW_DIR DIRECT\n", rep(ALIGN7, n)), valblks("RL"))
@path("RL-3", "VB", "layout: a block comment", "3a")
def _(n): return f(mod_common(), CM_BASE, rl("RL", " FNC_VALUES 1 UBYTE ROW_DIR DIRECT\n", comment(n)), valblks("RL"))
@path("RL-4", "VB", "layout: DIRECT-only lines", "3a")
def _(n): return f(mod_common(), CM_BASE, rl("RL", " FNC_VALUES 1 UBYTE ROW_DIR DIRECT\n", rep("DIRECT\n", n)), valblks("RL"))
@path("RL-5", "SC", "layout: FIX_NO_AXIS_PTS_X 4 lines (STD curve)", "3a")
def _(n): return f(mod_common(), CM_BASE, rl("RL_C", " AXIS_PTS_X 1 UBYTE INDEX_INCR DIRECT\n FNC_VALUES 2 UBYTE ROW_DIR DIRECT\n", rep("FIX_NO_AXIS_PTS_X 4\n", n)), std_curves())
@path("RL-6", "VB", "layout: first line 256 KiB of words, datatype last (.148/2)", "3a")
def _(n): return f(mod_common(), CM_BASE, rl("RL_LONG", " FNC_VALUES 1 " + " ".join("X" for _ in range(n // 2)) + " UBYTE ROW_DIR DIRECT\n"), valblks("RL_LONG"))
@path("RL-7", "VB", "layout: one part line, a single long word (.84 echo, .148/10)", "3a")
def _(n): return f(mod_common(), CM_BASE, rl("RL", " FNC_VALUES 1 UBYTE ROW_DIR DIRECT\n " + "P" * n + "\n"), valblks("RL"))
@path("RL-8", "VB", "layout: long FNC_VALUES mode word (.85 echo)", "3a")
def _(n): return f(mod_common(), CM_BASE, rl("RL", " FNC_VALUES 1 UBYTE " + "M" * n + " DIRECT\n"), valblks("RL"))
@path("RL-9", "VB", "layout: long FNC_VALUES datatype word (.86 echo)", "3a")
def _(n): return f(mod_common(), CM_BASE, rl("RL", " FNC_VALUES 1 " + "T" * n + " ROW_DIR DIRECT\n"), valblks("RL"))
@path("RL-10", "VA", "layout: long first line, datatype last (.148/3)", "2a, as ruled")
def _(n): return f(mod_common(), CM_BASE, rl("RL_LONG", " FNC_VALUES 1 " + " ".join("X" for _ in range(n // 2)) + " UBYTE ROW_DIR DIRECT\n"), values("RL_LONG"))
@path("RL-11", "QB", "the same, CUBOID objects (kind refused)", "2a, as ruled", decode=False)
def _(n): return f(mod_common(), CM_BASE, rl("RL_LONG", " FNC_VALUES 1 " + " ".join("X" for _ in range(n // 2)) + " UBYTE ROW_DIR DIRECT\n"), cuboids("RL_LONG"))
@path("RL-12", "SC", "layout: ALIGNMENT_BYTE 1 lines (STD curve)", "3a")
def _(n): return f(mod_common(), CM_BASE, rl("RL_C", " AXIS_PTS_X 1 UBYTE INDEX_INCR DIRECT\n FNC_VALUES 2 UBYTE ROW_DIR DIRECT\n", rep("ALIGNMENT_BYTE 1\n", n)), std_curves())
@path("RL-13", "MP", "layout: ALIGNMENT_BYTE 1 lines (STD x STD map)", "3a")
def _(n): return f(mod_common(), CM_BASE, rl("RL_M", " AXIS_PTS_X 1 UBYTE INDEX_INCR DIRECT\n AXIS_PTS_Y 2 UBYTE INDEX_INCR DIRECT\n FNC_VALUES 3 UBYTE ROW_DIR DIRECT\n", rep("ALIGNMENT_BYTE 1\n", n)), std_maps())
@path("RL-14", "CC", "axis object's layout: ALIGNMENT_BYTE 1 lines", "3a")
def _(n): return f(mod_common(), CM_BASE, RL_U8, rl("RL_AXO", AXO_BODY, rep("ALIGNMENT_BYTE 1\n", n)), axo(), com_curves())
@path("RL-15", "CC", "axis object's layout: one part line, a single long word (.148/15)", "3a")
def _(n): return f(mod_common(), CM_BASE, RL_U8, rl("RL_AXO", AXO_BODY + " " + "P" * n + "\n"), axo(), com_curves())
# new in round 6: <layout> of a COM axis object's layout is a word of the shared AXIS_PTS header (word 5)
@path("RL-16", "CC", "axis object's layout NAME long (AXIS_PTS word 5), a short part word (.84 <layout>)", "3a", new=True)
def _(n): return f(mod_common(), CM_BASE, RL_U8, rl("L" * n, AXO_BODY + " P\n"), axo(lname="L" * n), com_curves())
@path("RL-17", "CC", "axis object's layout NAME long, MOD_COMMON ALIGNMENT_BYTE 2 moves AXIS_PTS_X (.89 <layout>)", "3a", new=True)
def _(n): return f(mod_common("ALIGNMENT_BYTE 2\n"), CM_BASE, RL_U8, rl("L" * n, AXO_BODY), axo(lname="L" * n), com_curves())

# MOD_COMMON (round 5)
@path("MC-1", "VB", "MOD_COMMON: ALIGNMENT_BYTE 1 lines (.148/4)", "3a")
def _(n): return f(mod_common(rep("ALIGNMENT_BYTE 1\n", n)), CM_BASE, RL_U8, valblks("RL_U8"))
@path("MC-2", "CC", "MOD_COMMON: ALIGNMENT_BYTE 1 lines, COM axis object (.148/5)", "3a")
def _(n): return f(mod_common(rep("ALIGNMENT_BYTE 1\n", n)), CM_BASE, rl("RL_S16", " FNC_VALUES 1 SWORD ROW_DIR DIRECT\n"), RL_AXO, axo(), com_curves("RL_S16"))
@path("MC-3", "VB", "MOD_COMMON: the 7 classes repeated, UWORD values", "3a")
def _(n): return f(mod_common(rep(ALIGN7, n)), CM_BASE, rl("RL_W", " FNC_VALUES 1 UWORD ROW_DIR DIRECT\n"), valblks("RL_W"))
@path("MC-4", "VB", "MOD_COMMON: DEPOSIT ABSOLUTE lines", "3a")
def _(n): return f(mod_common(rep("DEPOSIT ABSOLUTE\n", n)), CM_BASE, RL_U8, valblks("RL_U8"))
@path("MC-5", "CC", "MOD_COMMON: BYTE_ORDER lines", "3a")
def _(n): return f('/begin MOD_COMMON ""\n' + rep("BYTE_ORDER MSB_LAST\n", n) + "/end MOD_COMMON\n", CM_BASE, RL_U8, RL_AXO, axo(), com_curves())
@path("MC-6", "VB", "MOD_COMMON: ALIGNMENT_BYTE x lines (.144, short word)", "3a")
def _(n): return f(mod_common(rep("ALIGNMENT_BYTE x\n", n)), CM_BASE, RL_U8, valblks("RL_U8"))
@path("MC-7", "VB", "MOD_COMMON: one ALIGNMENT_BYTE line, a long word (.144 echo, .148/11)", "3a")
def _(n): return f(mod_common("ALIGNMENT_BYTE " + "9" * n + "\n"), CM_BASE, RL_U8, valblks("RL_U8"))
@path("MC-8", "CC", "the same, on the axis object's layout", "3a")
def _(n): return f(mod_common("ALIGNMENT_BYTE " + "9" * n + "\n"), CM_BASE, rl("RL_S16", " FNC_VALUES 1 SWORD ROW_DIR DIRECT\n"), RL_AXO, axo(), com_curves("RL_S16"))

# AXIS_PTS (round 5)
@path("AX-1", "CC", "AXIS_PTS: DEPOSIT ABSOLUTE lines (.148/6)", "3a")
def _(n): return f(mod_common(), CM_BASE, RL_U8, RL_AXO, axo(rep("DEPOSIT ABSOLUTE\n", n)), com_curves())
@path("AX-2", "CC", "AXIS_PTS: block comment", "3a")
def _(n): return f(mod_common(), CM_BASE, RL_U8, RL_AXO, axo(comment(n)), com_curves())
@path("AX-3", "CC", "AXIS_PTS: BYTE_ORDER lines", "3a")
def _(n): return f(mod_common(), CM_BASE, RL_U8, RL_AXO, axo(rep("BYTE_ORDER MSB_LAST\n", n)), com_curves())
@path("AX-4", "CC", "AXIS_PTS: long identifier", "3a")
def _(n): return f(mod_common(), CM_BASE, RL_U8, RL_AXO, axo(lid='"' + "L" * n + '"'), com_curves())
@path("AX-5", "CC", "AXIS_PTS: long layout word, not declared", "3a", decode=False)
def _(n): return f(mod_common(), CM_BASE, RL_U8, RL_AXO, axo(lname="R" * n), com_curves())
@path("AX-6", "CC", "AXIS_PTS: long max-axis-points word", "3a", decode=False)
def _(n): return f(mod_common(), CM_BASE, RL_U8, RL_AXO, axo(maxw="9" * n), com_curves())
@path("AX-7", "CC", "AXIS_PTS: long address word", "3a", decode=False)
def _(n): return f(mod_common(), CM_BASE, RL_U8, RL_AXO, axo(addr="1" * n), com_curves())

# COMPU_METHOD (round 5)
LIN = " COEFFS_LINEAR 0.5 0\n"
@path("CM-1", "SC", "COMPU_METHOD: DEPOSIT ABSOLUTE lines (.148/7)", "3a")
def _(n): return f(mod_common(), CM_BASE, method("CM_L", "LINEAR", '"%.3"', '""', LIN, rep("DEPOSIT ABSOLUTE\n", n)), RL_C, std_curves(cm="CM_L"))
@path("CM-2", "VA", "COMPU_METHOD: block comment (VALUEs)", "2a, as ruled")
def _(n): return f(mod_common(), CM_BASE, method("CM_L", "LINEAR", '"%.3"', '""', LIN, comment(n)), RL_U8, values("RL_U8", "CM_L"))
@path("CM-3", "SC", "COMPU_METHOD: COEFFS_LINEAR lines", "3a")
def _(n): return f(mod_common(), CM_BASE, method("CM_L", "LINEAR", '"%.3"', '""', rep(LIN, n)), RL_C, std_curves(cm="CM_L"))
@path("CM-4", "SC", "COMPU_METHOD: FORMAT word %+digits+.2 (.148/12)", "3a + 2a, as ruled (object decimals)")
def _(n): return f(mod_common(), CM_BASE, method("CM_F", "LINEAR", '"%' + "9" * n + '.2"', '""', LIN), RL_C, std_curves(cm="CM_F"))
@path("CM-5", "VA", "the same, VALUEs", "2a, as ruled")
def _(n): return f(mod_common(), CM_BASE, method("CM_F", "LINEAR", '"%' + "9" * n + '.2"', '""', LIN), RL_U8, values("RL_U8", "CM_F"))
@path("CM-6", "SC", "COMPU_METHOD: long conversion type word (CONVERSION echo, .148/13)", "3a", decode=False)
def _(n): return f(mod_common(), CM_BASE, method("CM_T", "Z" * n, '"%.3"', '""'), RL_C, std_curves(cm="CM_T"))
@path("CM-7", "VA", "the same, VALUEs", "2a, as ruled + 3a _conversion_fields", decode=False)
def _(n): return f(mod_common(), CM_BASE, method("CM_T", "Z" * n, '"%.3"', '""'), RL_U8, values("RL_U8", "CM_T"))
@path("CM-8", "SC", "COMPU_METHOD: long COMPU_TAB_REF, not declared (TABLE echo, .148/14)", "3a", decode=False)
def _(n): return f(mod_common(), CM_BASE, method("CM_V", "TAB_VERB", '"%.3"', '""', " COMPU_TAB_REF " + "G" * n + "\n"), RL_C, std_curves(cm="CM_V"))
@path("CM-9", "VA", "the same, VALUEs", "2a, as ruled + 3a _conversion_fields", decode=False)
def _(n): return f(mod_common(), CM_BASE, method("CM_V", "TAB_VERB", '"%.3"', '""', " COMPU_TAB_REF " + "G" * n + "\n"), RL_U8, values("RL_U8", "CM_V"))
@path("CM-10", "VA", "COMPU_METHOD: long unit word", "2a (by reference)")
def _(n): return f(mod_common(), CM_BASE, method("CM_U", "LINEAR", '"%.3"', '"' + "U" * n + '"', LIN), RL_U8, values("RL_U8", "CM_U"))
@path("CM-11", "VB", "COMPU_METHOD: TAB_INTP, long COMPU_TAB_REF, not declared", "3a")
def _(n): return f(mod_common(), CM_BASE, method("CM_I", "TAB_INTP", '"%.3"', '""', " COMPU_TAB_REF " + "G" * n + "\n"), RL_U8, valblks("RL_U8", "CM_I"))


def _vt(n):
    k, body = vt_entries(n); return vtab("VT", k, body)


def _vr(n):
    k, body = vr_entries(n); return vrange("VR", k, body)


CMV = method("CM_V", "TAB_VERB", '"%.3"', '""', " COMPU_TAB_REF VT\n")
CMR = method("CM_R", "TAB_VERB", '"%.3"', '""', " COMPU_TAB_REF VR\n")
@path("VT-1", "SC", "COMPU_VTAB: entries (.148/8; .150/arr-1)", "decode 2a, as ruled")
def _(n): return f(mod_common(), CM_BASE, CMV, _vt(n), RL_C, std_curves(cm="CM_V"))
@path("VT-2", "VB", "COMPU_VTAB: entries (.150/arr-2)", "decode 2a, as ruled")
def _(n): return f(mod_common(), CM_BASE, CMV, _vt(n), RL_U8, valblks("RL_U8", "CM_V"))
@path("VT-3", "VA", "COMPU_VTAB: entries, enum VALUEs", "decode 2a, as ruled")
def _(n): return f(mod_common(), CM_BASE, CMV, _vt(n), RL_U8, values("RL_U8", "CM_V"))
@path("VT-4", "VB", "COMPU_VTAB: block comment", "3a")
def _(n): return f(mod_common(), CM_BASE, CMV, vtab("VT", 2, ' 1000 "a"\n 1001 "b"\n' + comment(n)), RL_U8, valblks("RL_U8", "CM_V"))
@path("VT-5", "VB", "COMPU_VTAB: one entry, long text, matched (.150/arr-3)", "decode 2a, as ruled", image_byte=0)
def _(n): return f(mod_common(), CM_BASE, CMV, vtab("VT", 1, ' 0 "' + "t" * n + '"\n'), RL_U8, valblks("RL_U8", "CM_V"))
@path("VT-6", "VB", "COMPU_VTAB: long DEFAULT_VALUE text, no match (.150/arr-4)", "decode 2a, as ruled")
def _(n): return f(mod_common(), CM_BASE, CMV, vtab("VT", 1, ' 1000 "a"\n', ' DEFAULT_VALUE "' + "d" * n + '"\n'), RL_U8, valblks("RL_U8", "CM_V"))
@path("VT-7", "VB", "COMPU_VTAB: count 0, entries after it (TABLE-EMPTY)", "3a", decode=False)
def _(n): return f(mod_common(), CM_BASE, CMV, vtab("VT", 0, vt_entries(n)[1]), RL_U8, valblks("RL_U8", "CM_V"))
# new in round 6: TABLE-EMPTY echoes the method's COMPU_TAB_REF word, which names a declared, empty table
@path("VT-8", "SC", "COMPU_VTAB named by a long word, count 0 (TABLE-EMPTY <table>)", "3a", decode=False, new=True)
def _(n): return f(mod_common(), CM_BASE, method("CM_E", "TAB_VERB", '"%.3"', '""', " COMPU_TAB_REF " + "E" * n + "\n"), vtab("E" * n, 0, ""), RL_C, std_curves(cm="CM_E"))
@path("VT-9", "VA", "the same, VALUEs", "3a _conversion_fields (2a :529)", decode=False, new=True)
def _(n): return f(mod_common(), CM_BASE, method("CM_E", "TAB_VERB", '"%.3"', '""', " COMPU_TAB_REF " + "E" * n + "\n"), vtab("E" * n, 0, ""), RL_U8, values("RL_U8", "CM_E"))
@path("VR-1", "SC", "COMPU_VTAB_RANGE: entries (.148/9; .150/arr-5)", "decode 2a, as ruled")
def _(n): return f(mod_common(), CM_BASE, CMR, _vr(n), RL_C, std_curves(cm="CM_R"))
@path("VR-2", "VB", "COMPU_VTAB_RANGE: one range, long text, matched (.150/arr-6)", "decode 2a, as ruled", image_byte=0)
def _(n): return f(mod_common(), CM_BASE, CMR, vrange("VR", 1, ' 0 255 "' + "t" * n + '"\n'), RL_U8, valblks("RL_U8", "CM_R"))


def _ct(n, kind="TAB_INTP"):
    k, body = tab_entries(n); return ctab("CT", k, body, kind)


@path("CT-1", "VB", "COMPU_TAB: entries, TAB_INTP, last interval (.150/arr-7)", "3a bisect")
def _(n): return f(mod_common(), CM_BASE, method("CM_I", "TAB_INTP", '"%.3"', '""', " COMPU_TAB_REF CT\n"), _ct(n), RL_U8, valblks("RL_U8", "CM_I"))
@path("CT-2", "VB", "COMPU_TAB: entries, TAB_NOINTP, no exact entry (.150/arr-8)", "3a bisect")
def _(n): return f(mod_common(), CM_BASE, method("CM_N", "TAB_NOINTP", '"%.3"', '""', " COMPU_TAB_REF CT\n"), _ct(n), RL_U8, valblks("RL_U8", "CM_N"))
# new in round 6: the scalar TAB_INTP / TAB_NOINTP decode (VALUEs)
@path("CT-3", "VA", "COMPU_TAB: TAB_INTP, VALUEs", "3a decode_definition -> _decode_stored (2a alone: frozen)", new=True)
def _(n): return f(mod_common(), CM_BASE, method("CM_I", "TAB_INTP", '"%.3"', '""', " COMPU_TAB_REF CT\n"), _ct(n), RL_U8, values("RL_U8", "CM_I"))
@path("CT-4", "VA", "COMPU_TAB: TAB_NOINTP, VALUEs", "3a decode_definition -> _decode_stored (2a alone: frozen)", new=True)
def _(n): return f(mod_common(), CM_BASE, method("CM_N", "TAB_NOINTP", '"%.3"', '""', " COMPU_TAB_REF CT\n"), _ct(n), RL_U8, values("RL_U8", "CM_N"))


# element name paths (one object, 64 elements, the object's name of S characters)
EN = {}


def en_file(n, cm):
    nm = "V" + "N" * (n - 1)
    meth = method("CM_I", "TAB_INTP", '"%.3"', '""', " COMPU_TAB_REF NOT_DECLARED\n")
    return f(mod_common(), CM_BASE, meth, RL_U8, f'/begin CHARACTERISTIC {nm} ""\n VAL_BLK 0x1000 RL_U8 0 {cm} 0 255\n'
             f' NUMBER 64\n/end CHARACTERISTIC\n'), nm


EN["EN-1"] = ("VB", "one VAL_BLK of 64 elements, its NAME long; TAB_INTP, table not declared: each element A2L-DEF-DECODE", "CM_I")
EN["EN-2"] = ("VB", "the same, NO_COMPU_METHOD: each element accepted", "NO_COMPU_METHOD")


# ------------------------------------------------------------------ round 7's own paths
def valblks_m(layout, prefix, number=1):
    return "".join(f'/begin CHARACTERISTIC V{i:05d} ""\n VAL_BLK 0x{0x1000 + 16 * i:X} {layout} 0 {prefix}{i:05d} 0 255\n'
                   f' NUMBER {number}\n/end CHARACTERISTIC\n' for i in range(N))


def values_m(layout, prefix):
    return "".join(f'/begin CHARACTERISTIC S{i:05d} ""\n VALUE 0x{0x1000 + 16 * i:X} {layout} 0 {prefix}{i:05d} 0 255\n'
                   f'/end CHARACTERISTIC\n' for i in range(N))


def methods_m(prefix, kind, ref):
    return "".join(method(f"{prefix}{i:05d}", kind, '"%.3"', '""', f" COMPU_TAB_REF {ref}\n") for i in range(N))


@path("CT-5", "VB", "COMPU_TAB of entries named by 400 TAB_NOINTP methods, one per object (the table form)", "3a", new=True)
def _(n): return f(mod_common(), CM_BASE, methods_m("CMT", "TAB_NOINTP", "CT"), _ct(n, "TAB_NOINTP"), RL_U8, valblks_m("RL_U8", "CMT"))
@path("CT-6", "VA", "the same, VALUEs (3a _conversion_fields via 3a's _describe_one)", "3a", new=True)
def _(n): return f(mod_common(), CM_BASE, methods_m("CMT", "TAB_INTP", "CT"), _ct(n), RL_U8, values_m("RL_U8", "CMT"))
@path("CT-7", "VB", "COMPU_TAB named by a long word (3 entries), TAB_NOINTP (decode: the resolved table)", "3a", new=True)
def _(n): return f(mod_common(), CM_BASE, method("CM_N", "TAB_NOINTP", '"%.3"', '""', " COMPU_TAB_REF " + "K" * n + "\n"), ctab("K" * n, 3, " 0 0\n 100 1\n 300 2\n", "TAB_NOINTP"), RL_U8, valblks("RL_U8", "CM_N"))
@path("VT-10", "VB", "COMPU_VTAB of entries named by 400 TAB_VERB methods, one per object", "3a (2a, as ruled: the proxy's table read once)", new=True)
def _(n): return f(mod_common(), CM_BASE, methods_m("CMV", "TAB_VERB", "VT"), _vt(n), RL_U8, valblks_m("RL_U8", "CMV"))


# ------------------------------------------------------------------ harness
def parse(tag, txt):
    p = W / f"{MODE}_{__import__('os').getpid()}_{tag}.a2l"     # one name per process (runs in parallel)
    p.write_text(txt, encoding="utf-8")
    data = a.parse_a2l_file(p)
    p.unlink()
    return data


def image_for(byte):
    img = {}
    for i in range(N):
        for o in range(16):
            img[0x1000 + 16 * i + o] = byte
    img[0x100] = 4
    for o in range(1, 5):
        img[0x100 + o] = 10 * o
    return img


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
    """One file at one size: one walk's maps, the first name described, the 399 others to time."""

    def __init__(self, data, names, size, mutant, byte):
        self.size, self.data, self.names, self.mutant = size, data, names, mutant
        self.memo = ({} if mutant != "per-call" else None, {} if mutant != "per-call" else None)
        self.secs = m.B.object_sections(data)
        self.tags = {}
        for t in data.get("tags") or []:
            self.tags.setdefault(t.get("name"), t)
        gc.collect(); gc.disable()
        try:
            t0 = CLOCK()
            self.w2a = walk2a(data)
            self.maps = m.new_maps(data)
            self.w6 = R6.new_walk(self.w2a[3])
            self.d2a, self.d3a = {}, {}
            self.one(names[0])
            t1 = CLOCK()
            self.desc()
            t2 = CLOCK()
        finally:
            gc.enable()
        self.t400, self.first_run = t2 - t0, t2 - t1
        self.img = image_for(byte)

    def _on(self):
        R4._E5["memo"], R5._RD["memo"] = self.memo
        R6.WALK = self.w6

    def one(self, nm):
        self._on()
        d2a = D._describe_one(nm, *self.w2a, self.data)
        if m.B.is_array_kind(self.tags[nm], self.secs[nm][0]):
            self.d3a[nm] = m.describe_array(self.tags[nm], self.secs[nm][0], self.data, self.maps)
        else:
            d2a = m.fix_scalar(d2a, self.tags[nm], self.maps)
        self.d2a[nm] = d2a

    def desc(self):
        for nm in self.names[1:]:
            self.one(nm)

    def dec(self, passes):
        self._on()
        for _ in range(passes):
            for nm in self.names:
                m.decode_model(self.d2a[nm], self.d3a.get(nm), self.data, self.img)


def interleaved(ctxs, fn, reps):
    best = [float("inf")] * len(ctxs)
    for _ in range(reps):
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


def code_of(c, nm):
    return c.d3a[nm]["refusal"] if nm in c.d3a else (c.d2a[nm].refusal.code if c.d2a[nm].refusal else None)


def knobs(mutant=None, te="echo", tf="method"):
    m.set_mutant(mutant)
    m.TE = R6.TE = te
    m.TF = tf
    R6.ENUM.clear(); m.CARRY.clear()


def reset():
    R4._E5["memo"] = None
    R5._RD["memo"] = None
    R6.WALK = {"on": False, "ct": {}, "dec": {}, "proxy": {}}
    knobs()


def measure(pid, mutant=None, te="echo", tf="method"):
    sp = P[pid]
    knobs(mutant, te, tf)
    try:
        datas, ctxs = [], []
        for size in (256, 512, 2048):
            data = parse(f"r7_{pid}_{size}", sp["build"](size * KIB))
            names = [nm for nm in (t["name"] for t in data["tags"]) if nm[:1] in "VSQCM" and nm[1:].isdigit()]
            assert len(names) == N, (pid, size, len(names))
            R6.ENUM.clear()
            c = Ctx(data, names, size, mutant, sp["byte"])
            datas.append((size, data, names)); ctxs.append(c)
            if not FULL and size == 512 and ctxs[0].first_run / (N - 1) >= 1e-3:
                break                                     # >= 1 ms per object: the one run each is the measure
        best, t400 = [c.first_run for c in ctxs], ctxs[0].t400
        if len(ctxs) == 3:                                # 15 runs in all, EACH A FRESH WALK (cold), sizes interleaved
            for _ in range(14):
                slow = False
                for i, (size, data, names) in enumerate(datas):
                    R6.ENUM.clear()
                    c = Ctx(data, names, size, mutant, sp["byte"])
                    best[i] = min(best[i], c.first_run)
                    t400 = min(t400, c.t400) if i == 0 else t400
                    slow = slow or c.first_run > 2.0
                    del c
                if slow and not FULL:
                    break
            R6.ENUM.clear(); m.CARRY.clear()
            ctxs = [Ctx(data, names, size, mutant, sp["byte"]) for size, data, names in datas]
        tdesc = [b / (N - 1) for b in best]
        msg = []
        for c in ctxs:
            ml = m.message_lengths(c.d2a, c.d3a)
            msg.append((max(ml.values()), sum(ml.values()) / N))
        out = {"sizes": [c.size for c in ctxs], "desc": tdesc, "t400": t400, "msg": msg,
               "codes": sorted({code_of(ctxs[0], nm) for nm in ctxs[0].names}, key=str),
               "same": len({tuple(m.public(c.d2a[nm], c.d3a.get(nm)) for nm in c.names) for c in ctxs}) == 1,
               "nan_passes": [c.maps["stats"].get("nan_passes", 0) for c in ctxs]}
        if sp["decode"]:
            one_pass = interleaved(ctxs[:1], lambda c: c.dec(1), 1)[0]
            dctx = ctxs if one_pass < 0.4 else ctxs[:2]
            passes = max(1, min(10, int(0.05 / max(one_pass, 1e-6)) + 1))
            td = interleaved(dctx, lambda c: c.dec(passes), 9 if one_pass < 0.5 else (3 if one_pass < 3 else 1))
            out["dec"] = [t / passes / N for t in td]
            texts, objs, refs = [], [], []
            for c in dctx:
                c._on()
                rs = [m.decode_model(c.d2a[nm], c.d3a.get(nm), c.data, c.img) for nm in c.names]
                xs = [x for r in rs for x in r if hasattr(x, "text") and isinstance(x.text, str)]
                texts.append(sum(len(x.text) for x in xs) / N)
                big = [x.text for x in xs if len(x.text) > 64]
                objs.append(len({id(t) for t in big}) if big else 0)
                refs.append(sorted({x.code for r in rs for x in r if isinstance(x, D.Refusal)}))
                del rs, xs, big
            out["text"], out["text_objs"], out["dec_ref"] = texts, objs, refs
        return out
    finally:
        reset()


def ratios(v):
    return v[1] / v[0], (v[2] / v[0] if len(v) > 2 else None)


def fmt(vals, unit=1e6):
    return " / ".join(f"{v * unit:.1f}" for v in vals)


def show(pid, o, label=""):
    r2, r8 = ratios(o["desc"])
    bad = []
    if r2 > B2 or (r8 is not None and r8 > B8):
        bad.append("describe")
    if o["t400"] > 0.5:
        bad.append("T400")
    if any(mx > 1024 for mx, _ in o["msg"]):
        bad.append("message>1024")
    line = (f"[S {pid}]{label} {P[pid]['users']} {P[pid]['what']} ({P[pid]['owner']}): sizes {o['sizes']} KiB; "
            f"T400(S) {o['t400']:.3f} s; describe per object {fmt(o['desc'])} us (2S x{r2:.2f}"
            f"{f', 8S x{r8:.2f}' if r8 is not None else ''}); message max/mean chars "
            f"{' / '.join(f'{mx}/{mn:.0f}' for mx, mn in o['msg'])}; codes {o['codes']}; same at every size {o['same']}; "
            f"NaN-x passes per walk {o['nan_passes']}")
    if "dec" in o:
        q2, q8 = ratios(o["dec"])
        # the text kept per object grows only through private copies: one string shared by every element is one
        # object (round 6's rule for VT-5, VT-6, VR-2)
        grow = len(o["text"]) > 1 and o["text"][1] > 1.3 * o["text"][0] + 64 and max(o["text_objs"]) > 1
        # every object refused at describe: decode returns the stored refusal (O(1), sub-microsecond); no bound
        if None in o["codes"] and (q2 > B2 or (q8 is not None and q8 > B8) or grow):
            bad.append("decode")
        line += (f" | decode per object {fmt(o['dec'])} us (2S x{q2:.2f}{f', 8S x{q8:.2f}' if q8 is not None else ''}); "
                 f"text/obj {fmt(o['text'], 1 / KIB)} KiB; distinct long text objects {o['text_objs']}; "
                 f"element refusals {o['dec_ref'][0]}")
    print(line + (" => RED (" + ", ".join(bad) + ")" if bad else " => GREEN"), flush=True)


def measure_en(pid, mutant=None):
    users, what, cm = EN[pid]
    knobs(mutant)
    try:
        ctxs = []
        for size in (256, 512, 2048):
            txt, nm = en_file(size * KIB, cm)
            data = parse(f"r7_{pid}_{size}", txt)
            w2a = walk2a(data)
            maps = m.new_maps(data)
            R4._E5["memo"], R5._RD["memo"] = {}, {}
            R6.WALK = R6.new_walk(w2a[3])
            d2a = D._describe_one(nm, *w2a, data)
            tag = next(t for t in data["tags"] if t["name"] == nm)
            d3a = m.describe_array(tag, m.B.object_sections(data)[nm][0], data, maps)
            img = {0x1000 + o: 7 for o in range(64)}
            ctxs.append((size, data, d2a, d3a, img))
        best = [float("inf")] * 3
        for _ in range(15):
            slow = False
            for i, (size, data, d2a, d3a, img) in enumerate(ctxs):
                gc.collect(); gc.disable()
                try:
                    t0 = CLOCK(); r = m.decode_model(d2a, d3a, data, img); t = CLOCK() - t0
                finally:
                    gc.enable()
                best[i] = min(best[i], t)
                slow = slow or t > 2.0
            if slow:
                break
        per = [b / 64 for b in best]
        kept, sample = [], None
        for size, data, d2a, d3a, img in ctxs:
            r = m.decode_model(d2a, d3a, data, img)
            refs = [x for x in r if isinstance(x, D.Refusal)]
            kept.append(sum(len(x.message) for x in refs) / 64)
            if len(refs) > 1 and sample is None:
                msg = refs[1].message
                sample = f"{len(msg)} chars, '{msg[:3]}...{msg[250:]}'"
        q2, q8 = ratios(per)
        red = q2 > B2 or q8 > B8 or kept[-1] > 1024
        print(f"[EN {pid}]{' MUTANT=' + mutant if mutant else ''} {users} {what}: name {', '.join(str(c[0]) for c in ctxs)} "
              f"KiB; decode per ELEMENT {fmt(per)} us (2S x{q2:.2f}, 8S x{q8:.2f}); message kept per element "
              f"{' / '.join(f'{k:.0f}' for k in kept)} chars; element [1] message {sample}; describe refusal "
              f"{ctxs[0][3]['refusal']} => {'RED' if red else 'GREEN'}", flush=True)
    finally:
        reset()


NEG = [("RL-16", "r6", "echo", "method"), ("RL-17", "r6", "echo", "method"),
       ("VT-8", None, "clean", "method"), ("VT-9", None, "clean", "method"),
       ("RL-16", "byname", "echo", "method"), ("RL-17", "byname", "echo", "method"),
       ("VT-8", "byname", "echo", "method"), ("VT-9", "byname", "echo", "method"), ("CT-7", "byname", "echo", "method"),
       ("CT-1", "r5", "echo", "method"), ("CT-2", "r5", "echo", "method"), ("CT-3", "r5", "echo", "method"),
       ("CT-4", "r5", "echo", "method"),
       ("CT-5", None, "echo", "table"), ("CT-6", None, "echo", "table")]
NEG_EN = [("EN-1", "r6"), ("EN-2", "r6"), ("EN-1", "named"), ("EN-2", "named")]

if MODE == "steady":
    todo = [pid for pid in P if not ARGS or pid in ARGS]
    for pid in todo:
        try:
            show(pid, measure(pid))
        except Exception as e:
            print(f"[S {pid}] EXCEPTION {type(e).__name__}: {e}", flush=True)
            reset()
    for pid in EN:
        if not ARGS or pid in ARGS:
            try:
                measure_en(pid)
            except Exception as e:
                print(f"[EN {pid}] EXCEPTION {type(e).__name__}: {e}", flush=True)
                reset()

elif MODE == "full":                                   # usage: full [TF=table] [MUT=<mutant>] <pids>
    FULL = True
    tf = next((x[3:] for x in ARGS if x.startswith("TF=")), "method")
    mut = next((x[4:] for x in ARGS if x.startswith("MUT=")), None)
    for pid in [x for x in ARGS if "=" not in x]:
        try:
            show(pid, measure(pid, mut, "echo", tf), f" FULL (15 cold runs at S, 2S, 8S) MUTANT={mut} TF={tf}")
        except Exception as e:
            print(f"[S {pid}] FULL EXCEPTION {type(e).__name__}: {e}", flush=True)
            reset()

elif MODE == "neg":
    for pid, mut, te, tf in NEG:
        if ARGS and pid not in ARGS:
            continue
        try:
            show(pid, measure(pid, mut, te, tf), f" MUTANT={mut} TE={te} TF={tf}")
        except Exception as e:
            print(f"[S {pid}] MUTANT={mut} TE={te} TF={tf} EXCEPTION {type(e).__name__}: {e}", flush=True)
            reset()
    for pid, mut in NEG_EN:
        if ARGS and pid not in ARGS:
            continue
        try:
            measure_en(pid, mut)
        except Exception as e:
            print(f"[EN {pid}] MUTANT={mut} EXCEPTION {type(e).__name__}: {e}", flush=True)
            reset()

elif MODE == "raise":                                  # [X] the raise cases (.150/arr-11), NaN x, non-finite values
    def run(label, txt, names, img, how):
        data = parse("r7x", txt)
        knobs(None if how in ("r7", "real") else how)
        try:
            c = Ctx(data, names, 0, m.MUTANT, 0)
            c.img = img
            c._on()
            for nm in names:
                try:
                    if how == "real":                  # Inc 2a's real decode_definition (2a alone, as merged)
                        m.set_mutant("r5")
                        r = D.decode_definition(D.describe_definitions([nm], data)[nm], data, img)
                        m.set_mutant(None)
                    else:
                        r = m.decode_model(c.d2a[nm], c.d3a.get(nm), data, img)
                    print(f"[X] {label} {nm} ({how}): {repr(r)[:200]}", flush=True)
                except Exception as e:
                    print(f"[X] {label} {nm} ({how}): RAISES {type(e).__name__}: {e}", flush=True)
            return c
        finally:
            reset()

    one_v = lambda nm, cm, dt="UBYTE": (f'/begin CHARACTERISTIC {nm} ""\n VALUE 0x1000 RL_{dt} 0 {cm} 0 255\n'
                                        f'/end CHARACTERISTIC\n')
    one_b = lambda nm, cm, dt="UBYTE": (f'/begin CHARACTERISTIC {nm} ""\n VAL_BLK 0x1000 RL_{dt} 0 {cm} 0 255\n'
                                        f' NUMBER 2\n/end CHARACTERISTIC\n')
    layouts = (rl("RL_UBYTE", " FNC_VALUES 1 UBYTE ROW_DIR DIRECT\n") +
               rl("RL_FLOAT32_IEEE", " FNC_VALUES 1 FLOAT32_IEEE ROW_DIR DIRECT\n"))
    vt = vtab("VTX", 2, ' 0 "zero"\n 1 "one"\n')
    meths = (method("CM_XN", "TAB_NOINTP", '"%.3"', '""', " COMPU_TAB_REF VTX\n") +
             method("CM_XI", "TAB_INTP", '"%.3"', '""', " COMPU_TAB_REF VTX\n"))
    txt = f(mod_common(), CM_BASE, layouts, vt, meths, one_v("SV1", "CM_XN"), one_v("SV2", "CM_XI"),
            one_b("BV1", "CM_XN"), one_b("BV2", "CM_XI"))
    img = {0x1000: 1, 0x1001: 0}
    for how in ("r7", "nonum", "r6", "real"):
        run(".150/arr-11 TAB_NOINTP / TAB_INTP naming a COMPU_VTAB (text y)", txt,
            ["SV1", "SV2"] if how == "real" else ["SV1", "SV2", "BV1", "BV2"], img, how)
    # non-finite stored values on a numeric table (FLOAT32): frozen vs 3a's route on the carried table form
    ct = ctab("CTF", 3, " 0 0\n 10 100\n 20 50\n")
    meths = (method("CM_I_F", "TAB_INTP", '"%.3"', '""', " COMPU_TAB_REF CTF\n") +
             method("CM_N_F", "TAB_NOINTP", '"%.3"', '""', " COMPU_TAB_REF CTF\n"))
    txt = f(mod_common(), CM_BASE, layouts, ct, meths, one_b("FB1", "CM_I_F", "FLOAT32_IEEE"),
            one_b("FB2", "CM_N_F", "FLOAT32_IEEE"))
    data = parse("r7x2", txt)
    tab = data["compu_tabs_by_name"]["CTF"]
    tf = (tab, m.echo("CTF"), False)
    for v in (float("nan"), float("inf"), -float("inf"), 2.5, 15.0):
        for interp in (True, False):
            print(f"[X] stored {v!r} {'TAB_INTP' if interp else 'TAB_NOINTP'} on 0 0 / 10 100 / 20 50: frozen "
                  f"{a._table_lookup(v, tab, interp)}, r7 {m.table_route(tf, v, interp)}, v1 "
                  f"{m.table_route(tf, v, interp, 'v1')}", flush=True)
    for bits, label in ((0x7FC00000, "NaN"), (0x7F800000, "+inf")):
        img = {}
        for k in range(2):
            for j, byte in enumerate(struct.pack(">I", bits)):
                img[0x1000 + 4 * k + j] = byte
        c = run(f"FLOAT32 VAL_BLK stored {label}", txt, ["FB1", "FB2"], img, "r7")
    # [I] the carried table form: what a definition holds by reference
    knobs()
    c = Ctx(data, ["FB1", "FB2"], 0, None, 0)
    tfc = c.d3a["FB2"]["_table_form"]
    rec = next(v for v in c.maps["reads"].values() if isinstance(v, R6.MP) and "table_form" in v and v["table_form"])
    print(f"[I] FB2's carried table form: {type(tfc).__name__} of ({type(tfc[0]).__name__}, {type(tfc[1]).__name__}, "
          f"{type(tfc[2]).__name__}); the COMPU_TAB is a2l_data['compu_tabs_by_name']['CTF'] itself: "
          f"{tfc[0] is data['compu_tabs_by_name']['CTF']}; its entries {type(tfc[0]['entries']).__name__}; the same "
          f"object in the stored method record (a read-only mapping): {rec['table_form'][0] is tfc[0]}; the record's "
          f"table_form {type(rec['table_form']).__name__}", flush=True)
    reset()
    # a NaN x in a COMPU_TAB ("nan" word): the verdict once per walk, the refusal at decode
    ctn = ctab("CTN", 4, " 0 0\n nan 7\n 10 100\n 20 50\n")
    meths = (method("CM_NN", "TAB_NOINTP", '"%.3"', '""', " COMPU_TAB_REF CTN\n") +
             method("CM_NI", "TAB_INTP", '"%.3"', '""', " COMPU_TAB_REF CTN\n"))
    txt = f(mod_common(), CM_BASE, layouts, ctn, meths, one_v("NV1", "CM_NN"), one_v("NV2", "CM_NI"),
            one_b("NB1", "CM_NN"), one_b("NB2", "CM_NI"))
    data = parse("r7x3", txt)
    tab = data["compu_tabs_by_name"]["CTN"]
    print(f"[X] COMPU_TAB CTN with a 'nan' x: entries as parsed {tab['entries']}", flush=True)
    for v in (5.0, 10.0, 15.0):
        for interp in (True, False):
            print(f"[X]   stored {v} {'TAB_INTP' if interp else 'TAB_NOINTP'}: frozen {a._table_lookup(v, tab, interp)}, "
                  f"r7 {m.table_route((tab, m.echo('CTN'), True), v, interp)}, nonan "
                  f"{m.table_route((tab, m.echo('CTN'), False), v, interp)}", flush=True)
    for how in ("r7", "nonan"):
        run("NaN-x table CTN, stored 5", txt, ["NV1", "NV2", "NB1", "NB2"], {0x1000 + o: 5 for o in range(2)}, how)
    # A_UINT64 stored 2^64 - 1 on a small table: every rounded distance ties
    tab = {"entries": [(0.0, 1.0), (50.0, 2.0), (100.0, 3.0)]}
    for v in (float(2 ** 64 - 1), float(2 ** 63)):
        print(f"[X] TAB_NOINTP stored {v:.6g} on x 0 / 50 / 100: frozen {a._table_lookup(v, tab, False)}, r7 "
              f"{m.table_route((tab, 'T', False), v, False)}, v1 {m.table_route((tab, 'T', False), v, False, 'v1')}",
              flush=True)

elif MODE == "bisect":                                 # [B] the v2 route against the frozen lookup; the enum index
    import bisect as bs
    from concurrent.futures import ProcessPoolExecutor
    NAN, INF = float("nan"), float("inf")
    NAN_MSG, NUM_MSG = "has an x that is not a number", "gives a value that is not a number"

    def same(x, y):
        if isinstance(x, float) and isinstance(y, float) and x != x and y != y:
            return True
        return type(x) == type(y) and x == y

    def points(xs):
        case = set(xs)
        for j in range(len(xs) - 1):
            case.add(xs[j] + (xs[j + 1] - xs[j]) / 4)
        case.add(xs[0] - 1); case.add(xs[-1] + 1)
        ext = set()
        for j in range(len(xs) - 1):
            ext.add((xs[j] + xs[j + 1]) / 2)
        for x in xs:
            if math.isfinite(x):
                ext.add(math.nextafter(x, INF)); ext.add(math.nextafter(x, -INF))
        ext.update((0.0, -0.0, 1e300, -1e300, float(2 ** 53 + 1), float(2 ** 63), float(2 ** 64 - 1), -float(2 ** 63)))
        return sorted(v for v in case if v == v), sorted(v for v in ext if v == v and v not in case), [NAN, INF, -INF]

    def expect(ref):
        """What 3a's route must give where the frozen lookup gives `ref` (arr-9 / arr-11)."""
        if ref[1]:
            return (None, ref[1])
        if isinstance(ref[0], bool) or not isinstance(ref[0], (int, float)):
            return (None, NUM_MSG)
        return (ref[0], "")

    def norm(got):
        err = got[1]
        return (got[0], NUM_MSG if NUM_MSG in err else (NAN_MSG if NAN_MSG in err else err))

    def plain_range(entries, v):                       # the negative control: last range with min <= v, then its max
        rs = sorted(range(len(entries)), key=lambda i: entries[i].raw)
        mins = [entries[i].raw for i in rs]
        j = bs.bisect_right(mins, v) - 1
        return entries[rs[j]].text if j >= 0 and v <= entries[rs[j]].raw_max else None

    def one(path_):
        try:
            data = a.parse_a2l_file(pathlib.Path(path_))
            tabs = data.get("compu_tabs_by_name") or {}
            named = {}
            for cm in (data.get("compu_methods_by_name") or {}).values():
                t = str(cm.get("conversion_type") or "").upper()
                if t in ("TAB_INTP", "TAB_NOINTP") and cm.get("compu_tab_ref") in tabs:
                    named.setdefault(cm["compu_tab_ref"], set()).add(t)
            out = {"tables": 0, "named": len(named), "pairs": [0, 0, 0], "d7": [0, 0, 0], "d1": [0, 0, 0],
                   "num": [0, 0, 0], "nonum_text": [0, 0, 0], "named_num": 0, "named_pts": 0, "nanX": 0, "first": []}
            m.set_mutant(None)
            for tn, tab in tabs.items():
                ents = tab.get("entries") or []
                if not ents:
                    continue
                out["tables"] += 1
                xs = [e[0] for e in ents]
                nan = any(x != x for x in xs)
                out["nanX"] += nan
                tf = (tab, m.echo(tn), nan)
                for cat, vals in enumerate(points(xs)):
                    for v in vals:
                        for interp in (True, False):
                            ref = a._table_lookup(v, tab, interp)
                            want = expect(ref)
                            out["pairs"][cat] += 1
                            got7 = norm(m.table_route(tf, v, interp, "v2"))
                            got1 = norm(m.table_route(tf, v, interp, "v1"))
                            if want[1] == NUM_MSG:
                                out["num"][cat] += 1
                                if tn in named and cat == 0 and ("TAB_INTP" if interp else "TAB_NOINTP") in named[tn]:
                                    out["named_num"] += 1
                            if tn in named and cat == 0 and ("TAB_INTP" if interp else "TAB_NOINTP") in named[tn]:
                                out["named_pts"] += 1
                            m.MUTANT = "nonum"
                            gn = m.table_route(tf, v, interp, "v2")
                            m.MUTANT = None
                            out["nonum_text"][cat] += isinstance(gn[0], str)
                            for got, key in ((got7, "d7"), (got1, "d1")):
                                if not (same(got[0], want[0]) and got[1] == want[1]):
                                    out[key][cat] += 1
                                    if key == "d7" and len(out["first"]) < 4:
                                        out["first"].append((["case", "ext", "nonfinite"][cat], interp, repr(v)[:24],
                                                             repr(want)[:40], repr(got)[:40]))
            # the enum index (2a, as ruled: dict / segment index) vs Inc 2a's first-in-file-order lookup; and the
            # negative control, a plain bisect over the ranges sorted by min
            ct = walk2a(data)[3]
            e = {"vtab": 0, "vrange": 0, "pairs": [0, 0, 0], "diff": [0, 0, 0], "plain": [0, 0, 0],
                 "plain_tables": 0, "rng_pairs": [0, 0, 0]}
            for tn, sec in ct.items():
                tab = m._RT_RAW(tn, ct)
                if tab is None or not tab[1]:
                    continue
                form = R6._enum_form(*tab)
                d = D.Definition(**{**{fl.name: None for fl in __import__("dataclasses").fields(D.Definition)},
                                    "enum_entries": tab[1], "default_text": tab[2], "name": "x"})
                rng = tab[0] == "COMPU_VTAB_RANGE"
                e["vrange" if rng else "vtab"] += 1
                case, ext = set(), set()
                for en in tab[1]:
                    bounds = (en.raw,) if en.raw_max is None else (en.raw, en.raw_max)
                    case.update(bounds)
                    if en.raw_max is not None:
                        case.add((en.raw + en.raw_max) / 2)
                    for b in bounds:
                        case.update((b - 1, b + 1))
                        if isinstance(b, float) or isinstance(b, int):
                            ext.update((math.nextafter(float(b), INF), math.nextafter(float(b), -INF)))
                ext -= case
                pd = 0
                for cat, vals in enumerate((sorted(case), sorted(ext), [NAN, INF, -INF])):
                    for v in vals:
                        e["pairs"][cat] += 1
                        i = R6._find(form, v)
                        got = form["entries"][i].text if i >= 0 else None
                        want = R6.ORIG["eet"](d, v)
                        e["diff"][cat] += got != want
                        if rng:
                            e["rng_pairs"][cat] += 1
                            x = plain_range(tab[1], v) != want
                            e["plain"][cat] += x
                            pd += x
                e["plain_tables"] += pd > 0
            out["enum"] = e
            return out
        except Exception as ex:
            import traceback
            return {"error": f"{type(ex).__name__}: {ex} @ {traceback.format_exc().splitlines()[-3].strip()}"[:240]}

    files = [ln.strip() for lf in ARGS for ln in open(lf) if ln.strip()]
    with ProcessPoolExecutor(8) as ex:
        res = list(ex.map(one, files))
    errs = [r for r in res if "error" in r]
    ok = [r for r in res if "error" not in r]
    s = lambda k: sum(r[k] for r in ok)
    v = lambda k, i: sum(r[k][i] for r in ok)
    ev = lambda k, i: sum(r["enum"][k][i] for r in ok)
    es = lambda k: sum(r["enum"][k] for r in ok)
    print(f"[B] files {len(files)}, errors {len(errs)} {errs[:3]}; COMPU_TAB / COMPU_VTAB tables with entries "
          f"{s('tables')} in {sum(1 for r in ok if r['tables'])} files; named by a TAB_INTP / TAB_NOINTP method "
          f"{s('named')}; tables with a NaN x {s('nanX')}", flush=True)
    for i, cat in enumerate(("the case's values (each x, quarter points, first x - 1, last x + 1)",
                             "extended finite (midpoints, x +/- 1 ulp, +/-0, +/-1e300, 2^53+1, +/-2^63, 2^64-1)",
                             "non-finite (NaN, +inf, -inf)")):
        print(f"[B] {cat}: pairs {v('pairs', i)} (both TAB_INTP and TAB_NOINTP on every table); where the frozen "
              f"lookup gives a text {v('num', i)}; differences of 3a's route (v2, number test, NaN-x verdict) from what "
              f"arr-9 / arr-11 expect: {v('d7', i)}; negative v1: {v('d1', i)}; negative 'nonum' gives a text "
              f"(display_text would raise) on {v('nonum_text', i)}", flush=True)
    print(f"[B] total pairs {sum(v('pairs', i) for i in range(3))}, r7 differences {sum(v('d7', i) for i in range(3))}, "
          f"v1 differences {sum(v('d1', i) for i in range(3))}; first r7 differences "
          f"{[x for r in ok for x in r['first']][:6]}", flush=True)
    print(f"[B] arr-11's corpus table: case points on tables a TAB_INTP / TAB_NOINTP method names, tried as named "
          f"{s('named_pts')}, refused 'gives a value that is not a number' {s('named_num')}", flush=True)
    print(f"[B] enum index (2a, as ruled) vs Inc 2a's _enum_entry_text: COMPU_VTAB {es('vtab')}, COMPU_VTAB_RANGE "
          f"{es('vrange')} tables; pairs case {ev('pairs', 0)} (each raw, min, max, midpoint, bound +/- 1), extended "
          f"{ev('pairs', 1)} (bound +/- 1 ulp), non-finite {ev('pairs', 2)}; differences {ev('diff', 0)} / "
          f"{ev('diff', 1)} / {ev('diff', 2)}", flush=True)
    print(f"[B] negative, a plain bisect over the ranges sorted by min: range pairs {ev('rng_pairs', 0)} / "
          f"{ev('rng_pairs', 1)} / {ev('rng_pairs', 2)}, differences {ev('plain', 0)} / {ev('plain', 1)} / "
          f"{ev('plain', 2)}, in {es('plain_tables')} tables", flush=True)
