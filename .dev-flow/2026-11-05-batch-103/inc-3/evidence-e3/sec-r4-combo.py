"""E3 round-4 security probe, Inc 3a (batch-103): combinations, the largest shared sections within the span caps,
and a hostile file of many small shared sections -- read once per walk (dc1ba751) -- plus the E3S3-14 oracle
(one walk equals a fresh walk per name, both orders) on each file.
[C] combination: 400 COM curves over 20 AXIS_PTS that share one layout and one TAB_VERB method / COMPU_VTAB with
    the curves' own conversion and with 400 VALUEs, under one MOD_COMMON; every shared section 256 KiB.
[X] largest within the caps: an AXIS_PTS whose record is exactly 1 MiB (max 1,048,575, R-A2L-DEF.143's bound)
    shared by 400 COM curves of 1,048,575 values; 1 MiB shared sections of each kind; a COMPU_VTAB of 65,536 real
    entries shared by 400 enum VALUEs (one tuple, or one per object?).
[H] many small: N MODULEs, each with its own MOD_COMMON, layouts, method, table and AXIS_PTS, shared by 2 COM
    curves -- 5 distinct shared sections per 2 objects; N = 2,500 and 10,000.
[O] the oracle on [C] (small fills), [H] (N = 200), V171 and P1 ... P5 of round 3; mutants of round 3.
THROWAWAY; read-only. Usage: python -I sec-r4-combo.py <tree> <scratch> [parts...]
"""
import gc, importlib.util, pathlib, sys, time, tracemalloc

TREE, S = sys.argv[1], pathlib.Path(sys.argv[2])
ONLY = set(sys.argv[3:])
sys.path.insert(0, TREE)
import s19_app, s19_app.tui.a2l as a  # noqa: E402
import s19_app.tui.a2l_definition as D  # noqa: E402

spec = importlib.util.spec_from_file_location("m3r4", str(S / "sec-r4-m3a.py"))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); m.bind(a, D)
B, R3 = m.B, m.R3
print("s19_app.__file__ =", s19_app.__file__.replace(str(pathlib.Path.home()), "~"), "| python",
      sys.version.split()[0], flush=True)
W = S / "work"; W.mkdir(parents=True, exist_ok=True)


def fills(kb):
    nb = kb * 1024
    return ("/* " + ("x" * 78 + "\n") * (nb // 79) + " */\n" if kb else "",
            "DEPOSIT ABSOLUTE\n" * (nb // 17) if kb else "")


def parse(tag, txt):
    p = W / f"{tag}.a2l"
    p.write_text(txt, encoding="utf-8")
    t0 = time.perf_counter(); data = a.parse_a2l_file(p); tp = time.perf_counter() - t0
    return data, tp, p.stat().st_size


def timed(fn):
    gc.collect(); t0 = time.perf_counter(); r = fn(); return r, time.perf_counter() - t0


def oracle(data, label):
    """one walk (file order, reversed) == a fresh walk per name, for the model; and for Inc 2a's real describe."""
    m.R3.MUTANT = None
    names = [t["name"] for t in data["tags"]]
    fresh = {}
    for nm in names:
        r, _ = m.describe_all(data, [nm])
        if nm in r:
            fresh[nm] = m.public(r[nm])
    out = []
    for order in (names, names[::-1]):
        r, _ = m.describe_all(data, order)
        out.append(sum(1 for nm in fresh if m.public(r[nm]) != fresh[nm]))
    real_fresh = {nm: D.describe_definitions([nm], data)[nm] for nm in names}
    real = []
    for order in (names, names[::-1]):
        r = m.describe_e5(order, data)
        real.append(sum(1 for nm in names if r[nm] != real_fresh[nm]))
    print(f"[O] {label}: {len(fresh)} model objects, one walk != fresh walk per name: forward {out[0]}, reversed "
          f"{out[1]}; Inc 2a real describe (memoised) != per name: forward {real[0]}, reversed {real[1]}", flush=True)
    return out, real


def stats_line(maps):
    return {k: v for k, v in maps["stats"].items() if v}


# ---------------------------------------------------------------- [C] combination
def combo_text(kb, n=400, k=20):
    com, dep = fills(kb)
    mc = '/begin MOD_COMMON ""\nBYTE_ORDER MSB_FIRST\nALIGNMENT_WORD 2\n' + dep + '/end MOD_COMMON\n'
    rls = ('/begin RECORD_LAYOUT RL_U8\n FNC_VALUES 1 UBYTE ROW_DIR DIRECT\n' + com + '/end RECORD_LAYOUT\n'
           '/begin RECORD_LAYOUT RL_AXO\n NO_AXIS_PTS_X 1 UWORD\n AXIS_PTS_X 2 UWORD INDEX_INCR DIRECT\n' + com +
           '/end RECORD_LAYOUT\n')
    cms = ('/begin COMPU_METHOD CM_V "" TAB_VERB "%.3" ""\n COMPU_TAB_REF VT\n' + com + '/end COMPU_METHOD\n'
           '/begin COMPU_VTAB VT "" TAB_VERB 2\n 0 "zero"\n 1 "one"\n' + com + '/end COMPU_VTAB\n')
    axos = "".join(f'/begin AXIS_PTS AXO_{j:02d} "" 0x{0x100 + 16 * j:X} NO_INPUT_QUANTITY RL_AXO 0 CM_V 4 0 255\n'
                   f'{dep if j == 0 else ""}/end AXIS_PTS\n' for j in range(k))
    curves = "".join(f'/begin CHARACTERISTIC C{i:05d} ""\n CURVE 0x{0x10000 + 16 * i:X} RL_U8 0 CM_V 0 255\n'
                     f' /begin AXIS_DESCR\n  COM_AXIS NO_INPUT_QUANTITY CM_V 4 0 255\n  AXIS_PTS_REF AXO_{i % k:02d}\n'
                     f' /end AXIS_DESCR\n/end CHARACTERISTIC\n' for i in range(n))
    values = "".join(f'/begin CHARACTERISTIC V{i:05d} ""\n VALUE 0x{0x20000 + i:X} RL_U8 0 CM_V 0 255\n'
                     f'/end CHARACTERISTIC\n' for i in range(n))
    return ('ASAP2_VERSION 1 71\n/begin PROJECT P ""\n/begin MODULE M ""\n' + mc + rls + cms + axos + curves + values
            + '/end MODULE\n/end PROJECT\n')


if not ONLY or "C" in ONLY:
    data, tp, size = parse("combo256", combo_text(256))
    names = [t["name"] for t in data["tags"]]
    for once in (True, False):
        m.set_read_once(once)
        _, t2a = timed(lambda: m.describe_e5(names, data))
        (res, maps), t3a = timed(lambda: m.describe_all(data))
        refs = {}
        for v in res.values():
            k = v.get("refusal") or v.get("conv_refusal")
            refs[k] = refs.get(k, 0) + 1
        print(f"[C] combination (file {size / 1024:.0f} KiB, parse {tp:.2f} s; 7 shared sections of 256 KiB: "
              f"MOD_COMMON, RL_U8, RL_AXO, CM_V, VT, AXO_00; 20 AXIS_PTS; 400 COM curves + 400 VALUEs) "
              f"{'read once' if once else 'per call '}: Inc 2a describe {t2a:.3f} s + 3a {t3a:.3f} s = "
              f"{t2a + t3a:.3f} s; stats {stats_line(maps)}; refusals {refs}", flush=True)
    m.set_read_once(True)
    small, _, _ = parse("combo0", combo_text(0, n=40, k=4))
    oracle(small, "combination (no fill, 40 + 40 objects, 4 AXIS_PTS)")

# ---------------------------------------------------------------- [X] largest within the caps
if not ONLY or "X" in ONLY:
    MAXP = 1_048_575
    com, dep = fills(1024)
    txt = ('ASAP2_VERSION 1 71\n/begin PROJECT P ""\n/begin MODULE M ""\n/begin MOD_COMMON ""\nBYTE_ORDER MSB_FIRST\n'
           '/end MOD_COMMON\n/begin RECORD_LAYOUT RL_U8\n FNC_VALUES 1 UBYTE ROW_DIR DIRECT\n/end RECORD_LAYOUT\n'
           '/begin RECORD_LAYOUT RL_AXO\n NO_AXIS_PTS_X 1 UBYTE\n AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT\n'
           '/end RECORD_LAYOUT\n/begin COMPU_METHOD CM_ID "" IDENTICAL "%.3" ""\n/end COMPU_METHOD\n'
           f'/begin AXIS_PTS AXO "" 0x100 NO_INPUT_QUANTITY RL_AXO 0 CM_ID {MAXP} 0 255\n{dep}/end AXIS_PTS\n'
           + "".join(f'/begin CHARACTERISTIC C{i:05d} ""\n CURVE 0x{0x200000 + 0x100000 * i:X} RL_U8 0 CM_ID 0 255\n'
                     f' /begin AXIS_DESCR\n  COM_AXIS NO_INPUT_QUANTITY CM_ID {MAXP} 0 255\n  AXIS_PTS_REF AXO\n'
                     f' /end AXIS_DESCR\n/end CHARACTERISTIC\n' for i in range(400))
           + '/end MODULE\n/end PROJECT\n')
    data, tp, size = parse("x_axo_cap", txt)
    names = [t["name"] for t in data["tags"]]
    _, t2a = timed(lambda: m.describe_e5(names, data))
    tracemalloc.start()
    (res, maps), t3a = timed(lambda: m.describe_all(data))
    _, peak = tracemalloc.get_traced_memory(); tracemalloc.stop()
    refs = {}
    for v in res.values():
        refs[v["refusal"]] = refs.get(v["refusal"], 0) + 1
    v0 = next(iter(res.values()))
    print(f"[X1] AXO at the .143 bound (max {MAXP}: record {MAXP + 1} bytes; body 1 MiB of DEPOSIT lines) shared by "
          f"400 COM curves of {MAXP} UBYTE values: file {size / 2**20:.2f} MiB, parse {tp:.2f} s; Inc 2a describe "
          f"{t2a:.3f} s + 3a {t3a:.3f} s (tracemalloc on, peak {peak / 2**20:.1f} MiB); stats {stats_line(maps)}; "
          f"refusals {refs}; first: shape {v0['shape']}, byte length {v0['byte_length']}", flush=True)
    data2, tp2, _ = parse("x_axo_over", txt.replace(f"CM_ID {MAXP} 0 255\n{dep}", f"CM_ID {MAXP + 1} 0 255\n{dep}", 1))
    r2, _ = m.describe_all(data2)
    rf = {}
    for v in r2.values():
        rf[v["refusal"]] = rf.get(v["refusal"], 0) + 1
    print(f"[X1] control, the AXO one point over (record 1 MiB + 1): refusals {rf}", flush=True)

    for kind in ("layout", "modcommon", "axispts", "method", "vtab"):
        mc = '/begin MOD_COMMON ""\nBYTE_ORDER MSB_FIRST\n' + (dep if kind == "modcommon" else "") + '/end MOD_COMMON\n'
        rl = ('/begin RECORD_LAYOUT RL_C\n AXIS_PTS_X 1 UBYTE INDEX_INCR DIRECT\n FNC_VALUES 2 UBYTE ROW_DIR DIRECT\n'
              + (com if kind == "layout" else "") + '/end RECORD_LAYOUT\n'
              '/begin RECORD_LAYOUT RL_U8\n FNC_VALUES 1 UBYTE ROW_DIR DIRECT\n/end RECORD_LAYOUT\n'
              '/begin RECORD_LAYOUT RL_AXO\n NO_AXIS_PTS_X 1 UBYTE\n AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT\n'
              '/end RECORD_LAYOUT\n')
        cmw = "CM_V" if kind == "vtab" else "CM_L"
        cms = ('/begin COMPU_METHOD CM_L "" LINEAR "%.3" ""\n COEFFS_LINEAR 0.5 0\n' + (com if kind == "method" else "")
               + '/end COMPU_METHOD\n/begin COMPU_METHOD CM_V "" TAB_VERB "%.3" ""\n COMPU_TAB_REF VT\n/end COMPU_METHOD\n'
               '/begin COMPU_VTAB VT "" TAB_VERB 2\n 0 "zero"\n 1 "one"\n' + (com if kind == "vtab" else "")
               + '/end COMPU_VTAB\n')
        if kind == "axispts":
            objs = (f'/begin AXIS_PTS AXO "" 0x100 NO_INPUT_QUANTITY RL_AXO 0 {cmw} 4 0 255\n{dep}/end AXIS_PTS\n'
                    + "".join(f'/begin CHARACTERISTIC C{i:05d} ""\n CURVE 0x{0x1000 + 16 * i:X} RL_U8 0 {cmw} 0 255\n'
                              f' /begin AXIS_DESCR\n  COM_AXIS NO_INPUT_QUANTITY {cmw} 4 0 255\n  AXIS_PTS_REF AXO\n'
                              f' /end AXIS_DESCR\n/end CHARACTERISTIC\n' for i in range(400)))
        else:
            objs = "".join(f'/begin CHARACTERISTIC C{i:05d} ""\n CURVE 0x{0x1000 + 16 * i:X} RL_C 0 {cmw} 0 255\n'
                           f' /begin AXIS_DESCR\n  STD_AXIS NO_INPUT_QUANTITY {cmw} 4 0 255\n /end AXIS_DESCR\n'
                           f'/end CHARACTERISTIC\n' for i in range(400))
        data, tp, size = parse(f"x_1m_{kind}", 'ASAP2_VERSION 1 71\n/begin PROJECT P ""\n/begin MODULE M ""\n' + mc + rl
                               + cms + objs + '/end MODULE\n/end PROJECT\n')
        names = [t["name"] for t in data["tags"]]
        _, t2a = timed(lambda: m.describe_e5(names, data))
        (res, maps), t3a = timed(lambda: m.describe_all(data))
        refs = {}
        for v in res.values():
            refs[v["refusal"] or v["conv_refusal"]] = refs.get(v["refusal"] or v["conv_refusal"], 0) + 1
        print(f"[X2] 400 curves sharing one 1 MiB {kind} (file {size / 2**20:.2f} MiB, parse {tp:.2f} s), read once: "
              f"Inc 2a describe {t2a:.3f} s + 3a {t3a:.3f} s = {t2a + t3a:.3f} s; stats {stats_line(maps)}; "
              f"refusals {refs}", flush=True)

    entries = "".join(f' {1000 + k} "t{k}"\n' for k in range(65536))
    txt = ('ASAP2_VERSION 1 71\n/begin PROJECT P ""\n/begin MODULE M ""\n/begin MOD_COMMON ""\n/end MOD_COMMON\n'
           '/begin RECORD_LAYOUT RL_U8\n FNC_VALUES 1 UBYTE ROW_DIR DIRECT\n/end RECORD_LAYOUT\n'
           '/begin COMPU_METHOD CM_V "" TAB_VERB "%.3" ""\n COMPU_TAB_REF VT\n/end COMPU_METHOD\n'
           f'/begin COMPU_VTAB VT "" TAB_VERB 65536\n{entries}/end COMPU_VTAB\n'
           + "".join(f'/begin CHARACTERISTIC V{i:05d} ""\n VALUE 0x{0x1000 + i:X} RL_U8 0 CM_V 0 255\n'
                     f'/end CHARACTERISTIC\n' for i in range(400)) + '/end MODULE\n/end PROJECT\n')
    data, tp, size = parse("x_vtab64k", txt)
    names = [t["name"] for t in data["tags"]]
    for once in (True, False):
        m.set_read_once(once)
        sub = names if once else names[:50]
        gc.collect(); tracemalloc.start()
        res, t2a = timed(lambda: m.describe_e5(sub, data))
        _, peak = tracemalloc.get_traced_memory(); tracemalloc.stop()
        ids = {id(d.enum_entries) for d in res.values()}
        print(f"[X3] COMPU_VTAB of 65,536 entries (file {size / 2**20:.2f} MiB) named by {len(sub)} enum VALUEs, "
              f"Inc 2a describe {'memoised (E5)' if once else 'as merged   '}: {t2a:.3f} s (tracemalloc on), peak "
              f"{peak / 2**20:.1f} MiB, distinct enum_entries tuples {len(ids)}, entries each "
              f"{len(next(iter(res.values())).enum_entries)}", flush=True)
    m.set_read_once(True)

# ---------------------------------------------------------------- [H] many small distinct shared sections
def many_text(n):
    parts = ['ASAP2_VERSION 1 71\n/begin PROJECT P ""\n']
    for j in range(n):
        parts.append(
            f'/begin MODULE M{j} ""\n/begin MOD_COMMON ""\nBYTE_ORDER MSB_FIRST\nALIGNMENT_WORD 2\n/end MOD_COMMON\n'
            f'/begin RECORD_LAYOUT RL{j}\n FNC_VALUES 1 UBYTE ROW_DIR DIRECT\n/end RECORD_LAYOUT\n'
            f'/begin RECORD_LAYOUT RA{j}\n NO_AXIS_PTS_X 1 UWORD\n AXIS_PTS_X 2 UWORD INDEX_INCR DIRECT\n/end RECORD_LAYOUT\n'
            f'/begin COMPU_METHOD CM{j} "" TAB_VERB "%.3" ""\n COMPU_TAB_REF VT{j}\n/end COMPU_METHOD\n'
            f'/begin COMPU_VTAB VT{j} "" TAB_VERB 2\n 0 "zero"\n 1 "one"\n/end COMPU_VTAB\n'
            f'/begin AXIS_PTS AX{j} "" 0x{0x100000 + 16 * j:X} NO_INPUT_QUANTITY RA{j} 0 CM{j} 4 0 255\n/end AXIS_PTS\n'
            + "".join(f'/begin CHARACTERISTIC C{j}_{q} ""\n CURVE 0x{0x1000000 + 32 * j + 16 * q:X} RL{j} 0 CM{j} 0 255\n'
                      f' /begin AXIS_DESCR\n  COM_AXIS NO_INPUT_QUANTITY CM{j} 4 0 255\n  AXIS_PTS_REF AX{j}\n'
                      f' /end AXIS_DESCR\n/end CHARACTERISTIC\n' for q in range(2))
            + '/end MODULE\n')
    parts.append('/end PROJECT\n')
    return "".join(parts)


if not ONLY or "H" in ONLY:
    for n in (2500, 10000):
        data, tp, size = parse(f"many_{n}", many_text(n))
        names = [t["name"] for t in data["tags"]]
        _, t2a = timed(lambda: m.describe_e5(names, data))
        (res, maps), t3a = timed(lambda: m.describe_all(data))
        gc.collect(); tracemalloc.start(); r2, mp2 = m.describe_all(data)
        _, peak = tracemalloc.get_traced_memory(); tracemalloc.stop()
        refs = {}
        for v in res.values():
            refs[v["refusal"] or v["conv_refusal"]] = refs.get(v["refusal"] or v["conv_refusal"], 0) + 1
        print(f"[H] {n} MODULEs x (MOD_COMMON, 2 layouts, method, table, AXIS_PTS) and 2 COM curves each: "
              f"{2 * n} curves, {6 * n} distinct shared sections; file {size / 2**20:.2f} MiB, parse {tp:.2f} s; "
              f"Inc 2a describe {t2a:.3f} s ({t2a / (2 * n) * 1e3:.3f} ms/object) + 3a {t3a:.3f} s "
              f"({t3a / (2 * n) * 1e3:.3f} ms/object); reads entries {len(mp2['reads'])}, tracemalloc peak "
              f"{peak / 2**20:.1f} MiB; stats {stats_line(maps)}; refusals {refs}", flush=True)
    small, _, _ = parse("many_200", many_text(200))
    oracle(small, "many small (N = 200: 400 curves, 1,200 shared sections)")

# ---------------------------------------------------------------- [O] V171 and P1 ... P5, mutants
if not ONLY or "O" in ONLY:
    v171 = a.parse_a2l_file(pathlib.Path(TREE).parent / "s19_app/examples/case_00_public/ASAP2_Demo_V171.a2l")
    oracle(v171, "V171")
    src = (S / "sec-r3-poison.py").read_text()
    ns = {}
    exec(compile(src[src.index("INLINE = {"):src.index("def inline(")], "poison", "exec"), ns)
    texts = {k: (f'ASAP2_VERSION 1 71\n/begin PROJECT P ""\n/begin MODULE M ""\n/begin MOD_COMMON ""\n'
                 f'BYTE_ORDER MSB_FIRST\n{mc}\n/end MOD_COMMON\n{body}/end MODULE\n/end PROJECT\n')
             for k, (body, mc) in ns["INLINE"].items()}
    texts["P3 two MODULEs share RL_C"] = ns["P3"]
    for i, (label, txt) in enumerate(sorted(texts.items())):
        data, _, _ = parse(f"r4_poison{i}", txt)
        oracle(data, label[:2])
        names = [t["name"] for t in data["tags"]]
        fresh = {}
        for nm in names:
            r, _ = m.describe_all(data, [nm])
            if nm in r:
                fresh[nm] = m.public(r[nm])
        for mu in ("owner-leak", "mutate", "cache-check"):
            m.R3.MUTANT = mu
            row = []
            for order in (names, names[::-1]):
                try:
                    r, _ = m.describe_all(data, order)
                    row.append(str(sum(1 for nm in fresh if m.public(r[nm]) != fresh[nm])))
                except Exception as e:  # noqa: BLE001
                    row.append(f"raises {type(e).__name__}")
            m.R3.MUTANT = None
            print(f"    {label[:2]} mutant {mu:<11}: forward {row[0]}, reversed {row[1]}", flush=True)
