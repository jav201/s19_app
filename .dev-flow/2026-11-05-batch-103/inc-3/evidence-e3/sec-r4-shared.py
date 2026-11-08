"""E3 round-4 security probe, Inc 3a (batch-103): E3S3-13 as corrected (dc1ba751: every section an object names read
once per walk) -- 400 objects sharing one 256 KiB section of each of the six kinds, read once vs per call; the same
at 4,000 objects (per-object cost flat?); and the per-object USE of a read form whose size grows with its section
(ALIGNMENT lines in a RECORD_LAYOUT or a MOD_COMMON; Inc 2a's `_resolve_datatype` scan of a layout's first line).
Model `sec-r4-m3a.py` (3a's reads) + Inc 2a's real `describe_definitions` (memoised = 2a's E5; as merged = per call).
THROWAWAY; read-only trees. Usage: python -I sec-r4-shared.py <inc2a tree> <scratch> [kinds...]
"""
import gc, importlib.util, pathlib, sys, time, tracemalloc

TREE, S = sys.argv[1], pathlib.Path(sys.argv[2])
ONLY = set(sys.argv[3:])
sys.path.insert(0, TREE)
import s19_app, s19_app.tui.a2l as a  # noqa: E402
import s19_app.tui.a2l_definition as D  # noqa: E402

spec = importlib.util.spec_from_file_location("m3r4", str(S / "sec-r4-m3a.py"))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); m.bind(a, D)
print("s19_app.__file__ =", s19_app.__file__.replace(str(pathlib.Path.home()), "~"), "| python",
      sys.version.split()[0], flush=True)
W = S / "work"; W.mkdir(parents=True, exist_ok=True)

KB = 256
N_BYTES = KB * 1024
COMMENT = "/* " + ("x" * 78 + "\n") * (N_BYTES // 79) + " */\n"
DEPOSIT = "DEPOSIT ABSOLUTE\n" * (N_BYTES // 17)
ALIGN_B = "ALIGNMENT_BYTE 1\n" * (N_BYTES // 17)
HEAD = 'ASAP2_VERSION 1 71\n/begin PROJECT P ""\n/begin MODULE M ""\n'
TAIL = "/end MODULE\n/end PROJECT\n"
MC = '/begin MOD_COMMON ""\nBYTE_ORDER MSB_FIRST\n{fill}/end MOD_COMMON\n'
CMS = ('/begin COMPU_METHOD CM_ID "" IDENTICAL "%.3" ""\n/end COMPU_METHOD\n'
       '/begin COMPU_METHOD CM_L "" LINEAR "%.3" ""\n COEFFS_LINEAR 0.5 0\n{fm}/end COMPU_METHOD\n'
       '/begin COMPU_METHOD CM_V "" TAB_VERB "%.3" ""\n COMPU_TAB_REF VT\n/end COMPU_METHOD\n'
       '/begin COMPU_METHOD CM_R "" TAB_VERB "%.3" ""\n COMPU_TAB_REF VR\n/end COMPU_METHOD\n'
       '/begin COMPU_VTAB VT "" TAB_VERB 2\n 0 "zero"\n 1 "one"\n{fv}/end COMPU_VTAB\n'
       '/begin COMPU_VTAB_RANGE VR "" 2\n 0 0 "zero"\n 1 255 "other"\n{fr}/end COMPU_VTAB_RANGE\n')


def valblks(n, layout, cm="NO_COMPU_METHOD"):
    return "".join(f'/begin CHARACTERISTIC V{i:05d} ""\n VAL_BLK 0x{0x1000 + 16 * i:X} {layout} 0 {cm} 0 255\n'
                   f' NUMBER 4\n/end CHARACTERISTIC\n' for i in range(n))


def std_curves(n, cm):
    return "".join(f'/begin CHARACTERISTIC C{i:05d} ""\n CURVE 0x{0x1000 + 16 * i:X} RL_C 0 {cm} 0 255\n'
                   f' /begin AXIS_DESCR\n  STD_AXIS NO_INPUT_QUANTITY {cm} 4 0 255\n /end AXIS_DESCR\n'
                   f'/end CHARACTERISTIC\n' for i in range(n))


RL_C = ('/begin RECORD_LAYOUT RL_C\n AXIS_PTS_X 1 UBYTE INDEX_INCR DIRECT\n FNC_VALUES 2 UBYTE ROW_DIR DIRECT\n'
        '/end RECORD_LAYOUT\n')


def text(kind, n, fill):
    f = {"comment": COMMENT, "deposit": DEPOSIT, "align": ALIGN_B, "none": ""}[fill]
    cms = CMS.format(fm=f if kind == "method" else "", fv=f if kind == "vtab" else "", fr=f if kind == "vrange" else "")
    if kind == "layout":
        rl = "/begin RECORD_LAYOUT RL_BIG\n FNC_VALUES 1 UBYTE ROW_DIR DIRECT\n" + f + "/end RECORD_LAYOUT\n"
        return HEAD + MC.format(fill="") + cms + rl + valblks(n, "RL_BIG") + TAIL
    if kind == "modcommon":
        rl = "/begin RECORD_LAYOUT RL_U8\n FNC_VALUES 1 UBYTE ROW_DIR DIRECT\n/end RECORD_LAYOUT\n"
        return HEAD + MC.format(fill="ALIGNMENT_WORD 2\n" + f) + cms + rl + valblks(n, "RL_U8") + TAIL
    if kind == "axispts":
        rls = ('/begin RECORD_LAYOUT RL_U8\n FNC_VALUES 1 UBYTE ROW_DIR DIRECT\n/end RECORD_LAYOUT\n'
               '/begin RECORD_LAYOUT RL_AXO\n NO_AXIS_PTS_X 1 UBYTE\n AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT\n'
               '/end RECORD_LAYOUT\n')
        axo = f'/begin AXIS_PTS AXO "" 0x100 NO_INPUT_QUANTITY RL_AXO 0 CM_ID 4 0 255\n{f}/end AXIS_PTS\n'
        objs = "".join(f'/begin CHARACTERISTIC C{i:05d} ""\n CURVE 0x{0x1000 + 16 * i:X} RL_U8 0 CM_ID 0 255\n'
                       f' /begin AXIS_DESCR\n  COM_AXIS NO_INPUT_QUANTITY CM_ID 4 0 255\n  AXIS_PTS_REF AXO\n'
                       f' /end AXIS_DESCR\n/end CHARACTERISTIC\n' for i in range(n))
        return HEAD + MC.format(fill="") + cms + rls + axo + objs + TAIL
    if kind in ("method", "vtab", "vrange"):
        cm = {"method": "CM_L", "vtab": "CM_V", "vrange": "CM_R"}[kind]
        return HEAD + MC.format(fill="") + cms + RL_C + std_curves(n, cm) + TAIL
    raise ValueError(kind)


def parse(tag, txt):
    p = W / f"{tag}.a2l"
    p.write_text(txt, encoding="utf-8")
    t0 = time.perf_counter(); data = a.parse_a2l_file(p); tp = time.perf_counter() - t0
    return data, tp, p.stat().st_size


def med(fn, reps):
    ts, r = [], None
    for _ in range(reps):
        gc.collect(); t0 = time.perf_counter(); r = fn(); ts.append(time.perf_counter() - t0)
    ts.sort()
    return r, ts[len(ts) // 2]


def run(kind, fill, n, read_once, reps):
    data, tp, size = parse(f"r4_{kind}_{fill}_{n}", text(kind, n, fill))
    names = [t["name"] for t in data["tags"]]
    m.set_read_once(read_once)
    m.STATS.clear()
    _, t2a = med(lambda: m.describe_e5(names, data), reps)
    e5 = dict(m.STATS)
    (res, maps), t3a = med(lambda: m.describe_all(data), reps)
    refs = {}
    for v in res.values():
        k = v.get("refusal") or v.get("conv_refusal")
        refs[k] = refs.get(k, 0) + 1
    st = {k: v for k, v in maps["stats"].items() if v}
    per = (t2a + t3a) / n * 1e3
    print(f"[{kind}/{fill}] n={n} {'read once' if read_once else 'per call '}: file {size / 1024:.0f} KiB (parse "
          f"{tp:.2f} s); Inc 2a describe {t2a:.3f} s + 3a reads {t3a:.3f} s = {t2a + t3a:.3f} s ({per:.2f} ms/object)"
          f"; 3a stats {st}; 2a method/table reads {e5.get('e5_method_reads', 0) // reps}/"
          f"{e5.get('e5_table_reads', 0) // reps}; refusals {refs}", flush=True)
    m.set_read_once(True)
    return t2a + t3a


CASES = [("layout", "comment"), ("modcommon", "deposit"), ("axispts", "deposit"), ("axispts", "comment"),
         ("method", "comment"), ("method", "deposit"), ("vtab", "comment"), ("vtab", "deposit"),
         ("vrange", "comment"), ("vrange", "deposit")]
if not ONLY or "kinds" in ONLY:
    for kind, fill in CASES:
        run(kind, fill, 400, True, 3)
        run(kind, fill, 4000, True, 1)
        run(kind, fill, 400, False, 1)

# [U] the per-object USE of a read form that grows with its section (round-3 correction: the read is once, the use?)
if not ONLY or "use" in ONLY:
    for kind in ("layout", "modcommon"):
        for n in (100, 400):
            run(kind, "align", n, True, 1)
    # Inc 2a's _resolve_datatype: the layout's first line (parse tokens) scanned per object
    for n in (100, 400):
        for where in ("end", "none"):
            junk = " ".join("X" for _ in range(N_BYTES // 2))
            first = f"FNC_VALUES 1 {junk} UBYTE ROW_DIR DIRECT" if where == "end" else f"FNC_VALUES 1 {junk}"
            rl = "/begin RECORD_LAYOUT RL_LONG\n " + first + "\n/end RECORD_LAYOUT\n"
            objs = "".join(f'/begin CHARACTERISTIC S{i:05d} ""\n VALUE 0x{0x1000 + i:X} RL_LONG 0 NO_COMPU_METHOD 0 255\n'
                           f'/end CHARACTERISTIC\n' for i in range(n))
            data, tp, size = parse(f"r4_first_{where}_{n}", HEAD + MC.format(fill="") + rl + objs + TAIL)
            names = [t["name"] for t in data["tags"]]
            _, t2a = med(lambda: m.describe_e5(names, data), 1)
            t0 = time.perf_counter()
            for t in data["tags"]:
                D._resolve_datatype(t, data)
            tr = time.perf_counter() - t0
            print(f"[first-line/{where}] {n} VALUEs sharing a layout whose first line is {N_BYTES // 1024} KiB "
                  f"(datatype word {'last' if where == 'end' else 'absent'}): file {size / 1024:.0f} KiB, parse "
                  f"{tp:.2f} s; Inc 2a describe_definitions {t2a:.3f} s ({t2a / n * 1e3:.2f} ms/object), of which "
                  f"_resolve_datatype {tr:.3f} s", flush=True)
