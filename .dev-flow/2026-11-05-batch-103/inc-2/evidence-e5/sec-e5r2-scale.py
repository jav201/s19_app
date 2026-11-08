"""E5 security re-review (round 2), batch-103 Inc 2a: per-object work on shared content, on the FIXED code (HEAD
26d3e309, product a856fab3, a2l_definition.py md5 f661674b).

Rows: R-A2L-DEF.149 (describe) and .150 (decode). Paths: the 39 paths of round 1 (`sec-e5-scale.py`, builders copied
unchanged), plus CT-12 = the shape of case .150/10 (one run of equal x = 0 with y 0, 1, 2, ... then `1000 5`).

Measure (E5-rulings.md "E5-3 (measure)"; inc-2/E5-code-review.md section E5-3):
- describe: each run is a FRESH `describe_definitions(gen(), a2l_data)` call (its own walk and `reads` map); `gen()`
  yields the first name, reads the process clock, yields `names[1:]`, reads the clock again: the interval is the CPU
  time of the 399 names after the first, each described for the first time in that walk. No difference of two walks,
  no hook on a private function. gc.collect() then gc.disable() around each run. T400 = the whole call, walk included.
  Non-vacuity: the interval at S must be >= 2 ms and the walk must have consumed the generator lazily (2 marks).
- decode: the 400 definitions of the same run; each run decodes the 400 objects K times; per object = time / (400 K).
- S, 2S, 8S = 256 KiB, 512 KiB, 2 MiB, interleaved run by run; the least of R runs (R = 15 by default).
- GREEN: x2S <= 1.5 and x8S <= 2.0 (describe and decode); T400 at S <= 0.5 s; 400 decodes at S <= 0.5 s; every
  refusal message <= 1,024 characters; no private copy that grows with S.
Negative controls (mode `neg`, R = 3, each must be RED): CT-8, CT-9, CT-12 on 069171cd (the walk back over equal x,
E5S-02); RL-10, CM-2 on 82f5f8e5 and CM-5, VT-9 on f2f955aa (round 1's per-object controls, now under the E5-3
measure). THROWAWAY; read-only trees; derived numbers only.
Usage: python -I -B sec-e5r2-scale.py <tree> <scratch> steady [pids...] | neg | list
"""
import gc, hashlib, importlib, math, os, pathlib, sys, time
from collections import Counter

sys.dont_write_bytecode = True
TREE, S = sys.argv[1], pathlib.Path(sys.argv[2])
MODE = sys.argv[3] if len(sys.argv) > 3 else "steady"
ARGS = sys.argv[4:]
sys.path.insert(0, TREE)
import s19_app  # noqa: E402
import s19_app.tui.a2l as a  # noqa: E402
import s19_app.tui.a2l_definition as D  # noqa: E402

OLD = {t: importlib.import_module(f"s19_app.tui.a2l_definition_{t}") for t in ("0691", "82f5", "f2f9")}


def md5(p):
    return hashlib.md5(open(p, "rb").read()).hexdigest()[:8]


print("s19_app.__file__ =", s19_app.__file__, "| python", sys.version.split()[0],
      "| a2l_definition md5", md5(D.__file__), "| a2l md5", md5(a.__file__),
      "| " + " | ".join(f"{t} {md5(m.__file__)}" for t, m in OLD.items()),
      "| load", " ".join(f"{x:.2f}" for x in os.getloadavg()), "| cpus", os.cpu_count(), flush=True)

W = S / "work"
W.mkdir(parents=True, exist_ok=True)
N = 400
KIB = 1024
SIZES = (256 * KIB, 512 * KIB, 2048 * KIB)
CLOCK = time.process_time
B2, B8 = 1.5, 2.0
R = int(os.environ.get("E5_RUNS", "15"))

# ------------------------------------------------------------------ file pieces (sec-r7-scale.py's, unchanged)
HEAD = 'ASAP2_VERSION 1 71\n/begin PROJECT P ""\n/begin MODULE M ""\n'
TAIL = "/end MODULE\n/end PROJECT\n"


def rep(line, n): return line * max(1, n // len(line))
def comment(n): return "/* " + ("x" * 78 + "\n") * (n // 79) + " */\n"
def mod_common(fill=""): return '/begin MOD_COMMON ""\nBYTE_ORDER MSB_FIRST\n' + fill + "/end MOD_COMMON\n"
def rl(name, body, fill=""): return f"/begin RECORD_LAYOUT {name}\n{body}{fill}/end RECORD_LAYOUT\n"
def method(name, typ, fmt, unit, body="", fill=""): return f'/begin COMPU_METHOD {name} "" {typ} {fmt} {unit}\n{body}{fill}/end COMPU_METHOD\n'
def vtab(name, count, body, default=""): return f'/begin COMPU_VTAB {name} "" TAB_VERB {count}\n{body}{default}/end COMPU_VTAB\n'
def vrange(name, count, body, default=""): return f'/begin COMPU_VTAB_RANGE {name} "" {count}\n{body}{default}/end COMPU_VTAB_RANGE\n'
def ctab(name, count, body, kind="TAB_INTP"): return f'/begin COMPU_TAB {name} "" {kind} {count}\n{body}/end COMPU_TAB\n'
def f(*parts): return HEAD + "".join(parts) + TAIL


CM_BASE = '/begin COMPU_METHOD CM_ID "" IDENTICAL "%.3" ""\n/end COMPU_METHOD\n'
RL_U8 = rl("RL_U8", " FNC_VALUES 1 UBYTE ROW_DIR DIRECT\n")
LIN = " COEFFS_LINEAR 0.5 0\n"


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


def vr_overlap(n):
    out, k, size = [], 0, 0
    while size < n:
        ln = f' 0 {1000 + k} "o{k}"\n'; out.append(ln); size += len(ln); k += 1
    return k, "".join(out)


def tab_entries(n):
    k, size = 0, 0
    while size < n:
        size += len(f" {k} {k}\n"); k += 1
    cnt = k
    out = [f" {200.0 * j / (cnt - 1):.6f} {j}\n" for j in range(cnt - 1)] + [" 300 999\n"]
    return cnt, "".join(out)


def addr(i): return 0x1000 + 16 * i


def values(layout, cm="NO_COMPU_METHOD"):
    return "".join(f'/begin CHARACTERISTIC S{i:05d} ""\n VALUE 0x{addr(i):X} {layout} 0 {cm} 0 255\n'
                   f'/end CHARACTERISTIC\n' for i in range(N))


def values_m(layout, prefix):
    return "".join(f'/begin CHARACTERISTIC S{i:05d} ""\n VALUE 0x{addr(i):X} {layout} 0 {prefix}{i:05d} 0 255\n'
                   f'/end CHARACTERISTIC\n' for i in range(N))


def methods_m(prefix, kind, ref):
    return "".join(method(f"{prefix}{i:05d}", kind, '"%.3"', '""', f" COMPU_TAB_REF {ref}\n") for i in range(N))


def meas(cm):
    return "".join(f'/begin MEASUREMENT S{i:05d} "" UBYTE {cm} 0 0 0 255\n ECU_ADDRESS 0x{addr(i):X}\n'
                   f'/end MEASUREMENT\n' for i in range(N))


def cuboids(layout):
    return "".join(f'/begin CHARACTERISTIC S{i:05d} ""\n CUBOID 0x{addr(i):X} {layout} 0 NO_COMPU_METHOD 0 255\n'
                   f'/end CHARACTERISTIC\n' for i in range(N))


def long_rl(n, dt=" UBYTE"): return rl("RL_LONG", " FNC_VALUES 1 " + " ".join("X" for _ in range(n // 2)) + dt + " ROW_DIR DIRECT\n")


P = {}


def path(pid, users, what, origin, decode=True, byte=250):
    def deco(fn):
        P[pid] = dict(users=users, what=what, build=fn, origin=origin, decode=decode, byte=byte)
        return fn
    return deco


# RECORD_LAYOUT
@path("RL-10", "VA", "layout: first line S of words, datatype last (.149/4)", "r5")
def _(n): return f(mod_common(), CM_BASE, long_rl(n), values("RL_LONG"))
@path("RL-11", "QB", "the same, CUBOIDs (KIND; .149/9)", "r5", decode=False)
def _(n): return f(mod_common(), CM_BASE, long_rl(n), cuboids("RL_LONG"))
@path("RL-18", "VA", "layout: ALIGNMENT_BYTE 1 lines after the first line", "e5")
def _(n): return f(mod_common(), CM_BASE, rl("RL", " FNC_VALUES 1 UBYTE ROW_DIR DIRECT\n", rep("ALIGNMENT_BYTE 1\n", n)), values("RL"))
@path("RL-19", "VA", "layout: first line S of words, no datatype word (a None result read once; DATATYPE)", "e5", decode=False)
def _(n): return f(mod_common(), CM_BASE, long_rl(n, ""), values("RL_LONG"))


# COMPU_METHOD
@path("CM-1", "VA", "COMPU_METHOD: DEPOSIT ABSOLUTE lines (.149/1)", "r5")
def _(n): return f(mod_common(), CM_BASE, method("CM_L", "LINEAR", '"%.3"', '""', LIN, rep("DEPOSIT ABSOLUTE\n", n)), RL_U8, values("RL_U8", "CM_L"))
@path("CM-2", "VA", "COMPU_METHOD: block comment", "r5")
def _(n): return f(mod_common(), CM_BASE, method("CM_L", "LINEAR", '"%.3"', '""', LIN, comment(n)), RL_U8, values("RL_U8", "CM_L"))
@path("CM-2M", "ME", "the same, MEASUREMENTs", "e5")
def _(n): return f(mod_common(), CM_BASE, method("CM_L", "LINEAR", '"%.3"', '""', LIN, comment(n)), meas("CM_L"))
@path("CM-3", "VA", "COMPU_METHOD: COEFFS_LINEAR lines", "r5")
def _(n): return f(mod_common(), CM_BASE, method("CM_L", "LINEAR", '"%.3"', '""', rep(LIN, n)), RL_U8, values("RL_U8", "CM_L"))
@path("CM-5", "VA", "COMPU_METHOD: FORMAT word % + S of 9 + .2 (.149/6)", "r5")
def _(n): return f(mod_common(), CM_BASE, method("CM_F", "LINEAR", '"%' + "9" * n + '.2"', '""', LIN), RL_U8, values("RL_U8", "CM_F"))
@path("CM-7", "VA", "COMPU_METHOD: conversion type word of S (CONVERSION; .149/7)", "r5", decode=False)
def _(n): return f(mod_common(), CM_BASE, method("CM_T", "Z" * n, '"%.3"', '""'), RL_U8, values("RL_U8", "CM_T"))
@path("CM-9", "VA", "COMPU_METHOD: TAB_VERB, COMPU_TAB_REF word of S, not declared (TABLE; .149/8)", "r5", decode=False)
def _(n): return f(mod_common(), CM_BASE, method("CM_V", "TAB_VERB", '"%.3"', '""', " COMPU_TAB_REF " + "G" * n + "\n"), RL_U8, values("RL_U8", "CM_V"))
@path("CM-10", "VA", "COMPU_METHOD: unit word of S", "r5")
def _(n): return f(mod_common(), CM_BASE, method("CM_U", "LINEAR", '"%.3"', '"' + "U" * n + '"', LIN), RL_U8, values("RL_U8", "CM_U"))
@path("CM-11", "VA", "COMPU_METHOD: TAB_INTP, COMPU_TAB_REF word of S, not declared (decode A2L-DEF-DECODE)", "r5")
def _(n): return f(mod_common(), CM_BASE, method("CM_I", "TAB_INTP", '"%.3"', '""', " COMPU_TAB_REF " + "G" * n + "\n"), RL_U8, values("RL_U8", "CM_I"))
@path("CM-12", "VA", "COMPU_METHOD: long identifier of S", "e5")
def _(n): return f(mod_common(), CM_BASE, f'/begin COMPU_METHOD CM_D "{"D" * n}" LINEAR "%.3" ""\n{LIN}/end COMPU_METHOD\n', RL_U8, values("RL_U8", "CM_D"))
@path("CM-13", "VA", "COMPU_METHOD: RAT_FUNC, COEFFS lines repeated", "e5")
def _(n): return f(mod_common(), CM_BASE, method("CM_R", "RAT_FUNC", '"%.3"', '""', rep(" COEFFS 0 1 0 0 0 1\n", n)), RL_U8, values("RL_U8", "CM_R"))
@path("CM-14", "VA", "COMPU_METHOD: FORMAT word of S that is not a format (decimals none)", "e5")
def _(n): return f(mod_common(), CM_BASE, method("CM_Q", "LINEAR", '"' + "Q" * n + '"', '""', LIN), RL_U8, values("RL_U8", "CM_Q"))


# COMPU_VTAB
CMV = method("CM_V", "TAB_VERB", '"%.3"', '""', " COMPU_TAB_REF VT\n")
CMR = method("CM_R", "TAB_VERB", '"%.3"', '""', " COMPU_TAB_REF VR\n")


def _vt(n): k, body = vt_entries(n); return vtab("VT", k, body)
def _vr(n): k, body = vr_entries(n); return vrange("VR", k, body)


@path("VT-3", "VA", "COMPU_VTAB: entries, no match (.149/2, .150/1)", "r5")
def _(n): return f(mod_common(), CM_BASE, CMV, _vt(n), RL_U8, values("RL_U8", "CM_V"))
@path("VT-3M", "ME", "the same, MEASUREMENTs", "e5")
def _(n): return f(mod_common(), CM_BASE, CMV, _vt(n), meas("CM_V"))
@path("VT-4", "VA", "COMPU_VTAB: block comment", "r5")
def _(n): return f(mod_common(), CM_BASE, CMV, vtab("VT", 2, ' 1000 "a"\n 1001 "b"\n' + comment(n)), RL_U8, values("RL_U8", "CM_V"))
@path("VT-5", "VA", "COMPU_VTAB: one entry, text of S, matched (.150/2)", "r5", byte=0)
def _(n): return f(mod_common(), CM_BASE, CMV, vtab("VT", 1, ' 0 "' + "t" * n + '"\n'), RL_U8, values("RL_U8", "CM_V"))
@path("VT-6", "VA", "COMPU_VTAB: DEFAULT_VALUE text of S, no match (.150/3)", "r5")
def _(n): return f(mod_common(), CM_BASE, CMV, vtab("VT", 1, ' 1000 "a"\n', ' DEFAULT_VALUE "' + "d" * n + '"\n'), RL_U8, values("RL_U8", "CM_V"))
@path("VT-7", "VA", "COMPU_VTAB: count 0, entries after it (TABLE-EMPTY)", "r5", decode=False)
def _(n): return f(mod_common(), CM_BASE, CMV, vtab("VT", 0, vt_entries(n)[1]), RL_U8, values("RL_U8", "CM_V"))
@path("VT-9", "VA", "COMPU_VTAB named by a word of S, count 0 (TABLE-EMPTY <table>; .149/10)", "r6", decode=False)
def _(n): return f(mod_common(), CM_BASE, method("CM_E", "TAB_VERB", '"%.3"', '""', " COMPU_TAB_REF " + "E" * n + "\n"), vtab("E" * n, 0, ""), RL_U8, values("RL_U8", "CM_E"))
@path("VT-10", "VA", "one COMPU_VTAB of entries named by 400 TAB_VERB methods, one per object", "r7")
def _(n): return f(mod_common(), CM_BASE, methods_m("CMV", "TAB_VERB", "VT"), _vt(n), RL_U8, values_m("RL_U8", "CMV"))
@path("VT-11", "VA", "COMPU_VTAB: S of entries all of raw 250, matched (first wins)", "e5")
def _(n): return f(mod_common(), CM_BASE, CMV, vtab("VT", n // 9, "".join(f' 250 "{k:05d}"\n' for k in range(n // 9))), RL_U8, values("RL_U8", "CM_V"))


# COMPU_VTAB_RANGE
@path("VR-1", "VA", "COMPU_VTAB_RANGE: entries, no match (.149/3, .150/4)", "r5")
def _(n): return f(mod_common(), CM_BASE, CMR, _vr(n), RL_U8, values("RL_U8", "CM_R"))
@path("VR-2", "VA", "COMPU_VTAB_RANGE: one range, text of S, matched (.150/5)", "r5", byte=0)
def _(n): return f(mod_common(), CM_BASE, CMR, vrange("VR", 1, ' 0 255 "' + "t" * n + '"\n'), RL_U8, values("RL_U8", "CM_R"))
@path("VR-3", "VA", "one COMPU_VTAB_RANGE of entries named by 400 TAB_VERB methods, one per object", "e5")
def _(n): return f(mod_common(), CM_BASE, methods_m("CMR", "TAB_VERB", "VR"), _vr(n), RL_U8, values_m("RL_U8", "CMR"))
@path("VR-4", "VA", "COMPU_VTAB_RANGE: S of overlapping ranges 0..1000+k, every one covering 250 (first wins)", "e5")
def _(n): k, body = vr_overlap(n); return f(mod_common(), CM_BASE, CMR, vrange("VR", k, body), RL_U8, values("RL_U8", "CM_R"))
@path("VR-5", "VA", "COMPU_VTAB_RANGE: DEFAULT_VALUE text of S, no match", "e5")
def _(n): return f(mod_common(), CM_BASE, CMR, vrange("VR", 1, ' 1000 1001 "a"\n', ' DEFAULT_VALUE "' + "d" * n + '"\n'), RL_U8, values("RL_U8", "CM_R"))


# COMPU_TAB
def _ct(n, kind="TAB_INTP"): k, body = tab_entries(n); return ctab("CT", k, body, kind)


@path("CT-3", "VA", "COMPU_TAB: entries, TAB_INTP (.150/7)", "r6")
def _(n): return f(mod_common(), CM_BASE, method("CM_I", "TAB_INTP", '"%.3"', '""', " COMPU_TAB_REF CT\n"), _ct(n), RL_U8, values("RL_U8", "CM_I"))
@path("CT-4", "VA", "COMPU_TAB: entries, TAB_NOINTP, no exact entry (.150/8)", "r6")
def _(n): return f(mod_common(), CM_BASE, method("CM_N", "TAB_NOINTP", '"%.3"', '""', " COMPU_TAB_REF CT\n"), _ct(n, "TAB_NOINTP"), RL_U8, values("RL_U8", "CM_N"))
@path("CT-5", "VA", "one COMPU_TAB of entries named by 400 TAB_NOINTP methods, one per object (E3S3-33's shape)", "r7")
def _(n): return f(mod_common(), CM_BASE, methods_m("CMT", "TAB_NOINTP", "CT"), _ct(n, "TAB_NOINTP"), RL_U8, values_m("RL_U8", "CMT"))
@path("CT-6", "VA", "the same, TAB_INTP (E3S3-33's CT-6)", "r7")
def _(n): return f(mod_common(), CM_BASE, methods_m("CMT", "TAB_INTP", "CT"), _ct(n), RL_U8, values_m("RL_U8", "CMT"))
@path("CT-7", "VA", "COMPU_TAB named by a word of S (3 entries), TAB_NOINTP", "r7")
def _(n): return f(mod_common(), CM_BASE, method("CM_N", "TAB_NOINTP", '"%.3"', '""', " COMPU_TAB_REF " + "K" * n + "\n"), ctab("K" * n, 3, " 0 0\n 100 1\n 300 2\n", "TAB_NOINTP"), RL_U8, values("RL_U8", "CM_N"))
@path("CT-8", "VA", "COMPU_TAB: S of entries all x = 0, TAB_NOINTP; stored 250 (above every x, no exact entry)", "e5")
def _(n): return f(mod_common(), CM_BASE, method("CM_N", "TAB_NOINTP", '"%.3"', '""', " COMPU_TAB_REF CT\n"), ctab("CT", n // 5, rep(" 0 7\n", n), "TAB_NOINTP"), RL_U8, values("RL_U8", "CM_N"))
@path("CT-9", "VA", "COMPU_TAB: 0 0, S of entries x = 100, then 300 9; TAB_NOINTP; stored 250 (the run is the lower neighbour)", "e5")
def _(n): return f(mod_common(), CM_BASE, method("CM_N", "TAB_NOINTP", '"%.3"', '""', " COMPU_TAB_REF CT\n"), ctab("CT", n // 7, " 0 0\n" + rep(" 100 7\n", n) + " 300 9\n", "TAB_NOINTP"), RL_U8, values("RL_U8", "CM_N"))
@path("CT-10", "VA", "COMPU_TAB: S of entries and one NaN x (decode refused, NaN-x verdict once per table)", "e5")
def _(n): k, body = tab_entries(n); return f(mod_common(), CM_BASE, method("CM_I", "TAB_INTP", '"%.3"', '""', " COMPU_TAB_REF CT\n"), ctab("CT", k + 1, body + " nan 5\n"), RL_U8, values("RL_U8", "CM_I"))
@path("CT-11", "VA", "TAB_INTP naming a COMPU_VTAB of S entries (decode refused: not a number)", "e5")
def _(n): return f(mod_common(), CM_BASE, method("CM_I", "TAB_INTP", '"%.3"', '""', " COMPU_TAB_REF VT\n"), _vt(n), RL_U8, values("RL_U8", "CM_I"))


@path("CT-12", "VA", "COMPU_TAB: one run of x = 0 (y 0, 1, 2, ...) then 1000 5, TAB_NOINTP; stored 250 (.150/10's shape)", "e5r2")
def _(n):
    k, size, lines = 0, 0, []
    while size < n:
        ln = f" 0 {k}\n"; lines.append(ln); size += len(ln); k += 1
    return f(mod_common(), CM_BASE, method("CM_N", "TAB_NOINTP", '"%.3"', '""', " COMPU_TAB_REF CT\n"),
             ctab("CT", k + 1, "".join(lines) + " 1000 5\n", "TAB_NOINTP"), RL_U8, values("RL_U8", "CM_N"))


NAMES = [f"S{i:05d}" for i in range(N)]
NON_VACUITY_S = 2e-3


def parse(tag, txt):
    p = W / f"{MODE}_{os.getpid()}_{tag}.a2l"
    p.write_text(txt, encoding="utf-8")
    try:
        return a.parse_a2l_file(p)
    finally:
        p.unlink()


def image_for(byte):
    return {addr(i) + o: byte for i in range(N) for o in range(16)}


def describe_run(mod, data):
    """E5-3: one fresh walk; the clock is read when the walk asks for the 2nd name and when the names run out."""
    marks = []

    def gen():
        yield NAMES[0]
        marks.append(CLOCK())
        yield from NAMES[1:]
        marks.append(CLOCK())

    gc.collect(); gc.disable()
    try:
        t = CLOCK()
        defs = mod.describe_definitions(gen(), data)
        T = CLOCK() - t
    finally:
        gc.enable()
    lazy = len(marks) == 2 and list(defs) == NAMES
    interval = (marks[1] - marks[0]) if len(marks) == 2 else 0.0
    return defs, interval / (N - 1), T, lazy, interval


def decode_run(mod, dl, data, img, K):
    gc.collect(); gc.disable()
    try:
        t = CLOCK()
        for _ in range(K):
            out = [mod.decode_definition(d, data, img) for d in dl]
        T = CLOCK() - t
    finally:
        gc.enable()
    return out, T / (K * len(dl)), T / K


def def_facts(defs):
    dl = [defs[n] for n in NAMES]
    refs = Counter((d.refusal.code if d.refusal else "-") for d in dl)
    msgs = [d.refusal.message for d in dl if d.refusal]
    mmax = max((len(m) for m in msgs), default=0)
    run = max((max((len(w) for w in m.split(" ")), default=0) for m in msgs), default=0)
    ids = Counter()
    strs = []
    for d in dl:
        own = [getattr(d, fn, None) for fn in ("name", "_name_echo", "method_name", "display_format", "unit", "default_text",
                                          "enum_table", "compu_tab_ref", "bit_mask_text", "conversion_type")]
        own += [d.refusal.message] if d.refusal else []
        own = [s for s in own if isinstance(s, str)]
        strs.append(own)
        for s in own:
            ids[id(s)] += 1
    priv = max(sum(len(s) for s in own if ids[id(s)] == 1) for own in strs)
    forms = len({id(getattr(d, "_table_form", None)) for d in dl if getattr(d, "_table_form", None) is not None})
    sig = (tuple(sorted(refs.items())), tuple(sorted(Counter((d.kind, d.datatype) for d in dl).items())))
    return dict(refs=refs, mmax=mmax, run=run, priv=priv, forms=forms, sig=sig)


def dec_facts(out):
    kinds = Counter((type(o).__name__ + ("/" + o.code if hasattr(o, "code") else "")) for o in out)
    texts = [o.text for o in out if hasattr(o, "text")]
    msgs = [o.message for o in out if hasattr(o, "message")]
    tmax = max((len(t) for t in texts), default=0)
    tobj = len({id(t) for t in texts if len(t) > 64})
    mmax = max((len(m) for m in msgs), default=0)
    vals = Counter(repr(o.value)[:40] if hasattr(o, "value") else o.code for o in out)
    return dict(kinds=kinds, tmax=tmax, tobj=tobj, mmax=mmax, sig=(tuple(sorted(kinds.items())), len(vals)))


def us(x): return f"{x * 1e6:,.0f}" if x < 1e-3 else f"{x * 1e3:,.1f} ms"
def ratio(b, x): return x / b if b and b > 0 else float("nan")


def run_path(pid, mod, label, runs=R):
    p = P[pid]
    datas = {sz: parse(f"{pid}_{sz}", p["build"](sz)) for sz in SIZES}
    imgs = image_for(p["byte"])
    best = {sz: dict(desc=math.inf, T=math.inf, dec=math.inf, decT=math.inf, iv=math.inf) for sz in SIZES}
    facts, dfacts, slow, skip, dslow = {}, {}, set(), set(), set()
    K = {sz: 1 for sz in SIZES}
    lazy_all = True
    load0 = os.getloadavg()[0]
    for r in range(runs):
        for sz in SIZES:
            if sz in skip or (r > 0 and sz in slow):
                continue
            defs, per, T, lazy, iv = describe_run(mod, datas[sz])
            lazy_all = lazy_all and lazy
            b = best[sz]
            b["desc"], b["T"], b["iv"] = min(b["desc"], per), min(b["T"], T), min(b["iv"], iv)
            if T > 3.0:
                slow.add(sz)
            if sz == SIZES[1] and T > 15.0:
                skip.add(SIZES[2])
            if r == 0:
                facts[sz] = def_facts(defs)
            if p["decode"] and not (r > 0 and sz in dslow):
                dl = [defs[n] for n in NAMES]
                out, perd, Td = decode_run(mod, dl, datas[sz], imgs, K[sz])
                if r == 0 and Td < 0.004:
                    K[sz] = 5          # >= 2,000 decodes per timed run on the flat paths
                if perd > 1e-3:
                    dslow.add(sz)      # one run at that size once a decode takes over 1 ms
                b["dec"], b["decT"] = min(b["dec"], perd), min(b["decT"], Td)
                if r == 0:
                    dfacts[sz] = dec_facts(out)
    s, s2, s8 = SIZES
    d2, d8 = ratio(best[s]["desc"], best[s2]["desc"]), ratio(best[s]["desc"], best[s8]["desc"])
    nonvac = lazy_all and best[s]["iv"] >= NON_VACUITY_S
    desc_ok = (s8 not in skip and d2 <= B2 and d8 <= B8 and best[s]["T"] <= 0.5
               and all(fa["mmax"] <= 1024 for fa in facts.values()))
    priv_grow = (facts[s8]["priv"] > 1024 and facts[s8]["priv"] > 1.2 * facts[s]["priv"]) if s8 in facts else True
    same = len({fa["sig"] for fa in facts.values()}) == 1
    line = (f"{pid:6} | {label:7} | {p['users']} | {p['what']} | load {load0:.1f} | describe "
            f"{us(best[s]['desc'])} / {us(best[s2]['desc'])} / {us(best[s8]['desc']) if s8 not in skip else '-'} "
            f"(x{d2:.2f}, x{d8:.2f}) 399-name interval at S {best[s]['iv'] * 1e3:.1f} ms, lazy {'yes' if lazy_all else 'NO'}"
            f", T400(S) {best[s]['T']:.3f} s | msg max {max(fa['mmax'] for fa in facts.values())} "
            f"chars, longest word {max(fa['run'] for fa in facts.values())}, private chars/def S {facts[s]['priv']} "
            f"8S {facts[s8]['priv'] if s8 in facts else '-'}, forms {facts[s]['forms']}, refusals {dict(facts[s]['refs'])}")
    dec_ok = True
    if p["decode"] and dfacts:
        e2, e8 = ratio(best[s]["dec"], best[s2]["dec"]), ratio(best[s]["dec"], best[s8]["dec"])
        tgrow = any(df["tobj"] > 1 and df["tmax"] > 1024 for df in dfacts.values())
        dec_ok = e2 <= B2 and (s8 in dfacts and e8 <= B8) and best[s]["decT"] <= 0.5 and not tgrow and all(
            df["mmax"] <= 1024 for df in dfacts.values())
        same = same and len({df["sig"] for df in dfacts.values()}) == 1
        line += (f" | decode {us(best[s]['dec'])} / {us(best[s2]['dec'])} / "
                 f"{us(best[s8]['dec']) if s8 in dfacts else '-'} (x{e2:.2f}, x{e8:.2f}) 400 at S {best[s]['decT']:.4f} s"
                 f" | texts: max {max(df['tmax'] for df in dfacts.values())} chars, objects>64ch at 8S "
                 f"{dfacts[s8]['tobj'] if s8 in dfacts else '-'}, msg max {max(df['mmax'] for df in dfacts.values())}"
                 f", outcomes {dict(dfacts[s]['kinds'])}")
    bad = [x for x, b in (("describe", not desc_ok), ("decode", not dec_ok), ("private copy", priv_grow),
                          ("differs by size", not same), ("vacuous measure", not nonvac)) if b]
    verdict = "GREEN" if not bad else "RED (" + ", ".join(bad) + ")"
    line += f" | same at every size {'yes' if same else 'NO'} | {verdict}"
    print(line, flush=True)
    return verdict


if MODE == "list":
    for pid, p in P.items():
        print(pid, p["users"], p["origin"], p["what"])
elif MODE == "steady":
    pids = ARGS or list(P)
    print(f"[steady] {len(pids)} paths on the fixed code; R = {R} fresh walks per size (E5-3 measure); bounds x2S <= "
          f"{B2}, x8S <= {B8}", flush=True)
    res = Counter(run_path(pid, D, "2a fix").split(" ")[0] for pid in pids)
    print("[steady] verdicts", dict(res), "| load", " ".join(f"{x:.2f}" for x in os.getloadavg()), flush=True)
elif MODE == "neg":
    NEG = [("CT-8", "0691"), ("CT-9", "0691"), ("CT-12", "0691"), ("RL-10", "82f5"), ("CM-2", "82f5"),
           ("CM-5", "f2f9"), ("VT-9", "f2f9")]
    print(f"[neg] {len(NEG)} negative controls under the E5-3 measure (each must be RED); R = 3", flush=True)
    res = Counter(run_path(pid, OLD[t], t, runs=3).split(" ")[0] for pid, t in NEG)
    print("[neg] verdicts", dict(res), "| load", " ".join(f"{x:.2f}" for x in os.getloadavg()), flush=True)
print("end | load", " ".join(f"{x:.2f}" for x in os.getloadavg()), flush=True)
