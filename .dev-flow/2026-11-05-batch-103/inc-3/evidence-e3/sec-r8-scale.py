"""E3 round-8 security probe, Inc 3a (batch-103): R-A2L-DEF.148 / .150's scaling test under the fresh-walk steady
measure, on the model of the round-7 correction (`sec-r8-m3a.py`, graph 25c13dec) running on Inc 2a's REAL code (a
copy of the Inc 2a tree at e9bad3ca); the path builders are round 7's (`sec-r7-scale.py`, unchanged); the counting
mappings of E3S3-35; the [K] probe (one `reads` shared by Inc 2a's `_resolve_datatype` and 3a's layout read form).

Measure (E3S3-24, -34, with the round-6 ruling's bounds): each run builds its own walk from scratch on the parsed file
(Inc 2a's four name maps, 3a's maps and `reads`), describes the first name, then times the 399 other names, each
described for the first time in that walk, with time.process_time(), garbage collection off around each timed run;
S, 2S and 8S (256 KiB, 512 KiB, 2 MiB) interleaved run by run; the least of 15 runs (mode `full` and the in-scope
paths: 15 at every size; the table pass: one run each at S and 2S once a run takes >= 1 ms per object). Decode: the 400
objects' decode per object, interleaved likewise. GREEN when x2S <= 1.5 and x8S <= 2.0 (describe and decode), the 400
names' walk at S <= 0.5 s, every definition's message <= 1,024 characters at every size, and the decoded text per
object does not grow.
Each name is described as 3a's `_describe_one` does: a scalar kind by Inc 2a's real `_describe_one(..., reads)` with
the walk's `reads`, its method steps through 3a's `_conversion_fields` (the two compared); an array kind by
`_describe_array` with the walk's `reads`, its base fields from Inc 2a's real `_describe_one` given a map of its own
(3a does not run `_resolve_datatype` for VAL_BLK / CURVE / MAP, graph `_describe_one`).
THROWAWAY; read-only trees; derived numbers only. Usage:
  python -I -B sec-r8-scale.py <inc2a tree copy> <scratch> steady [pids] | full [TF=..] [MUT=..] <pids> | neg [pids]
                                                          | count [pids] | collide
"""
import gc, hashlib, importlib.util, math, os, pathlib, sys, time
sys.dont_write_bytecode = True

TREE, S = sys.argv[1], pathlib.Path(sys.argv[2])
MODE = sys.argv[3] if len(sys.argv) > 3 else "steady"
ARGS = sys.argv[4:]
sys.path.insert(0, TREE)
import s19_app, s19_app.tui.a2l as a  # noqa: E402
import s19_app.tui.a2l_definition as D  # noqa: E402

spec = importlib.util.spec_from_file_location("m3r8", str(S / "sec-r8-m3a.py"))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); m.bind(a, D)


def load():
    with open("/proc/loadavg") as fh:
        return " ".join(fh.read().split()[:3])


print("s19_app.__file__ =", s19_app.__file__.replace(str(pathlib.Path.home()), "~"), "| python",
      sys.version.split()[0], "| a2l_definition md5", hashlib.md5(open(D.__file__, "rb").read()).hexdigest()[:8],
      "| a2l md5", hashlib.md5(open(a.__file__, "rb").read()).hexdigest()[:8], "| mode", MODE, ARGS,
      "| load", load(), "on", os.cpu_count(), "cpus", flush=True)
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



# ------------------------------------------------------------------ harness (round 8)
def parse(tag, txt):
    p = W / f"{MODE}_{os.getpid()}_{tag}.a2l"     # one name per process
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
    """Inc 2a's describe_definitions maps (a2l_definition.py:342-362): tags, object sections, the first COMPU_METHOD and
    the first COMPU_VTAB / COMPU_VTAB_RANGE of each name."""
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


PHASE = ["-"]


class Ctx:
    """One file at one size: ONE FRESH WALK (Inc 2a's maps, 3a's maps, `reads`), the first name, then the 399 others."""

    def __init__(self, data, names, size, byte, wrap=None):
        self.size, self.data, self.names = size, data, names
        self.secs = m.B.object_sections(data)
        self.tags = {}
        for t in data.get("tags") or []:
            self.tags.setdefault(t.get("name"), t)
        self.err = {}
        gc.collect(); gc.disable()
        try:
            t0 = CLOCK()
            PHASE[0] = "walk"
            self.w2a = walk2a(data)
            if wrap is not None:
                self.w2a = wrap(self.w2a)
            self.maps = m.new_maps(data, self.w2a)
            self.reads_base = {}
            self.d2a, self.d3a = {}, {}
            PHASE[0] = "first"
            self.one(names[0])
            t1 = CLOCK()
            PHASE[0] = "rest"
            self.desc()
            t2 = CLOCK()
            PHASE[0] = "-"
        finally:
            gc.enable()
        self.t400, self.first_run = t2 - t0, t2 - t1
        self.img = image_for(byte)

    def one(self, nm):
        tag = self.tags.get(nm)
        sec = (self.secs.get(nm) or [None])[0]
        if tag is not None and m.B.is_array_kind(tag, sec):
            d2a = D._describe_one(nm, *self.w2a, self.data, self.reads_base)
            self.d3a[nm] = m.describe_array(tag, sec, self.data, self.maps)
        else:
            d2a = D._describe_one(nm, *self.w2a, self.data, self.maps["reads"])
            d2a = m.fix_scalar(d2a, tag, self.maps)
        self.d2a[nm] = d2a

    def desc(self):
        for nm in self.names[1:]:
            self.one(nm)

    def dec(self, passes):
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


def carried_forms(c):
    out = set()
    for nm in c.names:
        tf = c.d3a[nm]["_table_form"] if nm in c.d3a else c.d2a[nm]._table_form
        if tf is not None:
            out.add(id(tf))
    return len(out)


def names_of(data):
    return [nm for nm in (t["name"] for t in data["tags"]) if nm[:1] in "VSQCM" and nm[1:].isdigit()]


def measure(pid, mutant=None, te="echo", tf="table"):
    sp = P[pid]
    m.set_knobs(mutant, te, tf)
    try:
        datas, ctxs = [], []
        for size in (256, 512, 2048):
            data = parse(f"r8_{pid}_{size}", sp["build"](size * KIB))
            names = names_of(data)
            assert len(names) == N, (pid, size, len(names))
            c = Ctx(data, names, size, sp["byte"])
            datas.append((size, data, names)); ctxs.append(c)
            if not FULL and size == 512 and ctxs[0].first_run / (N - 1) >= 1e-3:
                break                                     # >= 1 ms per object: the one run each is the measure
        best, t400, runs = [c.first_run for c in ctxs], ctxs[0].t400, 1
        if len(ctxs) == 3:                                # 15 runs in all, EACH A FRESH WALK, sizes interleaved
            for _ in range(14):
                slow = False
                for i, (size, data, names) in enumerate(datas):
                    c = Ctx(data, names, size, sp["byte"])
                    best[i] = min(best[i], c.first_run)
                    t400 = min(t400, c.t400) if i == 0 else t400
                    slow = slow or c.first_run > 2.0
                    del c
                runs += 1
                if slow and not FULL:
                    break
            ctxs = []
            for size, data, names in datas:               # the walk the checks read: builds counted per walk
                b0 = m.STATS["btf_builds"]
                c = Ctx(data, names, size, sp["byte"])
                c.builds = m.STATS["btf_builds"] - b0
                ctxs.append(c)
        else:
            for c in ctxs:
                c.builds = None
        tdesc = [b / (N - 1) for b in best]
        msg = []
        for c in ctxs:
            ml = m.message_lengths(c.d2a, c.d3a)
            msg.append((max(ml.values()), sum(ml.values()) / N))
        out = {"sizes": [c.size for c in ctxs], "desc": tdesc, "t400": t400, "msg": msg, "runs": runs,
               "codes": sorted({code_of(ctxs[0], nm) for nm in ctxs[0].names}, key=str),
               "same": len({tuple(m.public(c.d2a[nm], c.d3a.get(nm)) for nm in c.names) for c in ctxs}) == 1,
               "forms": [carried_forms(c) for c in ctxs],
               "tabforms_in_reads": [sum(isinstance(v, D._TabForm) for v in c.maps["reads"].values()) for c in ctxs],
               "builds": [c.builds for c in ctxs],
               "scalar": (m.STATS["scalar_checked"], m.STATS["scalar_msg_diff"])}
        if sp["decode"]:
            one_pass = interleaved(ctxs[:1], lambda c: c.dec(1), 1)[0]
            dctx = ctxs if one_pass < 0.4 else ctxs[:2]
            passes = max(1, min(10, int(0.05 / max(one_pass, 1e-6)) + 1))
            td = interleaved(dctx, lambda c: c.dec(passes), 15 if one_pass < 0.5 else (3 if one_pass < 3 else 1))
            out["dec"] = [t / passes / N for t in td]
            texts, objs, refs = [], [], []
            for c in dctx:
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
        m.set_knobs()


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
    if o["scalar"][1]:
        bad.append("scalar 3a/2a message differs")
    line = (f"[S {pid}]{label} {P[pid]['users']} {P[pid]['what']} ({P[pid]['owner']}): sizes {o['sizes']} KiB; runs "
            f"{o['runs']}; T400(S) {o['t400']:.3f} s; describe per object {fmt(o['desc'])} us (2S x{r2:.2f}"
            f"{f', 8S x{r8:.2f}' if r8 is not None else ''}); message max/mean chars "
            f"{' / '.join(f'{mx}/{mn:.0f}' for mx, mn in o['msg'])}; codes {o['codes']}; same at every size {o['same']}; "
            f"carried table forms {o['forms']}; _TabForm in reads {o['tabforms_in_reads']}; table-form builds per walk "
            f"{o['builds']}; scalar conv checked/differ {o['scalar'][0]}/{o['scalar'][1]}")
    if "dec" in o:
        q2, q8 = ratios(o["dec"])
        grow = len(o["text"]) > 1 and o["text"][1] > 1.3 * o["text"][0] + 64 and max(o["text_objs"]) > 1
        if None in o["codes"] and (q2 > B2 or (q8 is not None and q8 > B8) or grow):
            bad.append("decode")
        line += (f" | decode per object {fmt(o['dec'])} us (2S x{q2:.2f}{f', 8S x{q8:.2f}' if q8 is not None else ''}); "
                 f"text/obj {fmt(o['text'], 1 / KIB)} KiB; distinct long text objects {o['text_objs']}; "
                 f"element refusals {o['dec_ref'][0]}")
    print(line + f" | load {load()}" + (" => RED (" + ", ".join(bad) + ")" if bad else " => GREEN"), flush=True)


def measure_en(pid, mutant=None):
    users, what, cm = EN[pid]
    m.set_knobs(mutant)
    try:
        ctxs = []
        for size in (256, 512, 2048):
            txt, nm = en_file(size * KIB, cm)
            data = parse(f"r8_{pid}_{size}", txt)
            w2a = walk2a(data)
            maps = m.new_maps(data, w2a)
            d2a = D._describe_one(nm, *w2a, data, {})
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
              f"{ctxs[0][3]['refusal']} | load {load()} => {'RED' if red else 'GREEN'}", flush=True)
    finally:
        m.set_knobs()


# ------------------------------------------------------------------ E3S3-35: the counting mappings
class Counting(dict):
    """A dict that counts the lookups whose key is one of `words` (identity first, then length, then equality), per
    phase of the walk; plain-dict calls (`dict.get(d, k)`) are not counted."""

    def setup(self, label, words, counts):
        self.label, self.words, self.counts = label, words, counts
        return self

    def _hit(self, key):
        if type(key) is str:
            for w in self.words:
                if key is w or (len(key) == len(w) and key == w):
                    k = (self.label, PHASE[0])
                    self.counts[k] = self.counts.get(k, 0) + 1
                    return

    def get(self, key, default=None):
        self._hit(key)
        return dict.get(self, key, default)

    def __getitem__(self, key):
        self._hit(key)
        return dict.__getitem__(self, key)

    def __contains__(self, key):
        self._hit(key)
        return dict.__contains__(self, key)


COUNT_WORDS = {"RL-16": lambda n: "L" * n, "RL-17": lambda n: "L" * n, "VT-8": lambda n: "E" * n,
               "VT-9": lambda n: "E" * n, "CT-1": lambda n: "CT", "CT-5": lambda n: "CT", "CT-6": lambda n: "CT"}
COUNT_CASE = {"RL-16": ".148/16", "RL-17": ".148/17", "VT-8": ".148/18", "VT-9": ".148/18", "CT-1": ".150/arr-7",
              "CT-5": ".148/19 (own-method word)", "CT-6": ".148/19 (own-method word)"}


def count_case(pid, mutant=None):
    sp = P[pid]
    m.set_knobs(mutant)
    try:
        res = []
        for size in (256, 512, 2048):
            data = parse(f"r8c_{pid}_{size}", sp["build"](size * KIB))
            names = names_of(data)
            word = COUNT_WORDS[pid](size * KIB)
            counts = {}
            data["record_layouts_by_name"] = Counting(data.get("record_layouts_by_name") or {}).setup(
                "record_layouts_by_name", (word,), counts)
            data["compu_tabs_by_name"] = Counting(data.get("compu_tabs_by_name") or {}).setup(
                "compu_tabs_by_name", (word,), counts)

            def wrap(w2a):
                return (w2a[0], w2a[1], w2a[2],
                        Counting(w2a[3]).setup("compu_tables_by_name", (word,), counts))
            c = Ctx(data, names, size, sp["byte"], wrap=wrap)
            if sp["decode"]:
                PHASE[0] = "decode"
                c.dec(1)
                PHASE[0] = "-"
            per = {}
            for (lab, ph), n in counts.items():
                per.setdefault(ph, {})[lab] = n
            after = sum(n for (lab, ph), n in counts.items() if ph in ("rest", "decode"))
            res.append((size, per, after))
        verdict = "GREEN (0 after the first name)" if all(r[2] == 0 for r in res) else "RED on the count"
        print(f"[C {pid}]{' MUTANT=' + mutant if mutant else ''} {COUNT_CASE[pid]}: lookups keyed by the shared word, "
              f"per phase (walk = the maps, first = the first name, rest = the 399 after it, decode = all 400): "
              + "; ".join(f"{s} KiB {per}" for s, per, _ in res)
              + f"; after the first name {[r[2] for r in res]} | load {load()} => {verdict}", flush=True)
    finally:
        m.set_knobs()


# ------------------------------------------------------------------ [K]: one `reads` for Inc 2a and 3a
def k_inline():
    rl_s = rl("RL_S", " FNC_VALUES 1 SWORD ROW_DIR DIRECT\n")
    rl_n = rl("RL_N", " ALIGNMENT_BYTE 1\n FNC_VALUES 1 SWORD ROW_DIR DIRECT\n")
    rl_c = rl("RL_SC", " AXIS_PTS_X 1 SWORD INDEX_INCR DIRECT\n FNC_VALUES 2 SWORD ROW_DIR DIRECT\n")

    def val(nm, lay, addr):
        return f'/begin CHARACTERISTIC {nm} ""\n VALUE 0x{addr:X} {lay} 0 NO_COMPU_METHOD -32768 32767\n/end CHARACTERISTIC\n'

    def blk(nm, lay, addr):
        return (f'/begin CHARACTERISTIC {nm} ""\n VAL_BLK 0x{addr:X} {lay} 0 NO_COMPU_METHOD -32768 32767\n NUMBER 4\n'
                f'/end CHARACTERISTIC\n')

    def crv(nm, lay, addr):
        return (f'/begin CHARACTERISTIC {nm} ""\n CURVE 0x{addr:X} {lay} 0 NO_COMPU_METHOD -32768 32767\n'
                f' /begin AXIS_DESCR\n  STD_AXIS NO_INPUT_QUANTITY NO_COMPU_METHOD 4 0 255\n /end AXIS_DESCR\n'
                f'/end CHARACTERISTIC\n')
    return {
        "K1 VALUE + VAL_BLK, one layout (datatype on its first line)":
            f(mod_common(), CM_BASE, rl_s, val("K1V", "RL_S", 0x1000), blk("K1B", "RL_S", 0x1010)),
        "K2 VALUE + VAL_BLK, one layout whose first line holds no datatype":
            f(mod_common(), CM_BASE, rl_n, val("K2V", "RL_N", 0x1000), blk("K2B", "RL_N", 0x1010)),
        "K3 VALUE + CURVE, one layout":
            f(mod_common(), CM_BASE, rl_c, val("K3V", "RL_SC", 0x1000), crv("K3C", "RL_SC", 0x1010)),
    }


def kview(c, nm):
    """What is compared: an array's public view and message; a scalar's whole Definition (dataclass equality)."""
    if nm in c.d3a:
        return (m.public(c.d2a[nm], c.d3a[nm]), c.d3a[nm]["message"])
    return ("scalar", c.d2a[nm])


def k_run(label, data, names):
    fresh = {}
    m.set_knobs(key="tuple")
    for nm in names:
        try:
            c = Ctx(data, [nm], 0, 0)
            fresh[nm] = kview(c, nm)
        except Exception as e:
            fresh[nm] = ("EXC", f"{type(e).__name__}")
    model_exc = sum(1 for v in fresh.values() if v[0] == "EXC")
    for key in ("bare", "tuple"):
        for order_label, order in (("file order", names), ("reversed", list(reversed(names)))):
            m.set_knobs(key=key)
            exc, diffs, first = 0, 0, []
            c = None
            try:
                c = Ctx.__new__(Ctx)
                c.size, c.data, c.names = 0, data, order
                c.secs = m.B.object_sections(data)
                c.tags = {}
                for t in data.get("tags") or []:
                    c.tags.setdefault(t.get("name"), t)
                c.w2a = walk2a(data)
                c.maps = m.new_maps(data, c.w2a)
                c.reads_base = {}
                c.d2a, c.d3a = {}, {}
                for nm in order:
                    try:
                        c.one(nm)
                    except Exception as e:
                        exc += 1
                        if len(first) < 3:
                            import traceback
                            tb = traceback.extract_tb(e.__traceback__)[-1]
                            first.append(f"{nm}: {type(e).__name__}: {str(e)[:60]} at "
                                         f"{pathlib.Path(tb.filename).name}:{tb.lineno} {tb.name}")
                        continue
                    got = kview(c, nm)
                    if fresh[nm][0] != "EXC" and got != fresh[nm]:
                        diffs += 1
                        if len(first) < 3:
                            first.append(f"{nm}: one walk {str(got)[:110]} | fresh {str(fresh[nm])[:110]}")
            finally:
                m.set_knobs()
            kl = ("id() of the record_layouts_by_name entry, as the graph writes it" if key == "bare"
                  else "('RL', id()), a key no Inc 2a read uses")
            fl = f"; first {first}" if first else ""
            print(f"[K] {label}, KEY={key} ({kl}), {order_label}: names {len(order)}; exceptions {exc}; differences "
                  f"from a fresh walk per name {diffs}{fl} (model limits: {model_exc} names raise in a fresh walk too)",
                  flush=True)


def k_share(data):
    """Static count: RECORD_LAYOUT entries named both by a VALUE whose tag has no datatype (Inc 2a's _resolve_datatype
    stores its result in `reads`) and by a VAL_BLK / CURVE / MAP (3a's _read_record_layout stores its form there)."""
    by = {}
    for t in data.get("tags") or []:
        if t.get("section") != "CHARACTERISTIC":
            continue
        ln = t.get("record_layout_name") or t.get("deposit")
        if not ln or ln not in (data.get("record_layouts_by_name") or {}):
            continue
        ct = t.get("char_type")
        if ct == "VALUE" and t.get("datatype") not in a.DATATYPE_SIZES:
            by.setdefault(ln, [0, 0])[0] += 1
        elif ct in ("VAL_BLK", "CURVE", "MAP"):
            by.setdefault(ln, [0, 0])[1] += 1
    both = {k: v for k, v in by.items() if v[0] and v[1]}
    return len(both), sum(v[0] + v[1] for v in both.values())


NEG = [("CT-5", None, "echo", "method"), ("CT-6", None, "echo", "method"),
       ("RL-16", "r6", "echo", "table"), ("RL-17", "r6", "echo", "table")]
NEG_EN = [("EN-1", "r6"), ("EN-2", "r6"), ("EN-1", "named"), ("EN-2", "named")]

if MODE == "steady":
    todo = [pid for pid in P if not ARGS or pid in ARGS]
    for pid in todo:
        try:
            show(pid, measure(pid))
        except Exception as e:
            import traceback
            tb = traceback.extract_tb(e.__traceback__)[-1]
            print(f"[S {pid}] EXCEPTION {type(e).__name__}: {e} at {pathlib.Path(tb.filename).name}:{tb.lineno}", flush=True)
            m.set_knobs()
    for pid in EN:
        if not ARGS or pid in ARGS:
            try:
                measure_en(pid)
            except Exception as e:
                print(f"[EN {pid}] EXCEPTION {type(e).__name__}: {e}", flush=True)
                m.set_knobs()

elif MODE == "full":                                   # usage: full [TF=method] [MUT=<mutant>] <pids>
    FULL = True
    tf = next((x[3:] for x in ARGS if x.startswith("TF=")), "table")
    mut = next((x[4:] for x in ARGS if x.startswith("MUT=")), None)
    for pid in [x for x in ARGS if "=" not in x]:
        try:
            show(pid, measure(pid, mut, "echo", tf), f" FULL (15 fresh walks at S, 2S, 8S) MUTANT={mut} TF={tf}")
        except Exception as e:
            print(f"[S {pid}] FULL EXCEPTION {type(e).__name__}: {e}", flush=True)
            m.set_knobs()

elif MODE == "neg":
    for pid, mut, te, tf in NEG:
        if ARGS and pid not in ARGS:
            continue
        try:
            show(pid, measure(pid, mut, te, tf), f" MUTANT={mut} TE={te} TF={tf}")
        except Exception as e:
            print(f"[S {pid}] MUTANT={mut} TE={te} TF={tf} EXCEPTION {type(e).__name__}: {e}", flush=True)
            m.set_knobs()
    for pid, mut in NEG_EN:
        if ARGS and pid not in ARGS:
            continue
        try:
            measure_en(pid, mut)
        except Exception as e:
            print(f"[EN {pid}] MUTANT={mut} EXCEPTION {type(e).__name__}: {e}", flush=True)
            m.set_knobs()

elif MODE == "count":
    for pid in COUNT_WORDS:
        if ARGS and pid not in ARGS:
            continue
        for mut in (None, "byname"):
            try:
                count_case(pid, mut)
            except Exception as e:
                print(f"[C {pid}] MUTANT={mut} EXCEPTION {type(e).__name__}: {e}", flush=True)
                m.set_knobs()

elif MODE == "collide":
    for label, txt in k_inline().items():
        data = parse("r8k", txt)
        k_run(label, data, [t["name"] for t in data["tags"]])
    v171 = pathlib.Path(TREE) / "examples" / "case_00_public" / "ASAP2_Demo_V171.a2l"
    data = a.parse_a2l_file(v171)
    names = list(dict.fromkeys(t["name"] for t in data["tags"]))
    print(f"[K] V171: layouts named by a VALUE without a tag datatype and by a VAL_BLK / CURVE / MAP, objects naming "
          f"them: {k_share(data)}", flush=True)
    k_run("V171 (examples/case_00_public, .136/arr-4's file)", data, names)
    files = sorted(p for d in ("examples", "tests") for p in (pathlib.Path(TREE) / d).rglob("*.a2l"))
    tot = [0, 0, 0]
    for p in files:
        try:
            n_l, n_o = k_share(a.parse_a2l_file(p))
        except Exception:
            continue
        tot[0] += 1; tot[1] += n_l > 0; tot[2] += n_l
    print(f"[K] tracked .a2l under examples/ and tests/ of the copy: files {len(files)} (parsed {tot[0]}); files with "
          f"such a shared layout {tot[1]}; such layouts {tot[2]}", flush=True)
