"""E3 security measurement, Inc 3a (batch-103): the describe-time cost of a FIX axis, whose stored points
`_fixed_points` materializes during describe (STD/COM read points only at decode). Bound: R-A2L-DEF.142 caps a point
count at 1,048,576. This measures one FIX axis at that cap and the per-object and aggregate cost for a file that
declares several, all within the cap. Pure model (m3a.py) on the frozen parser; read-only trees; nothing is written
outside /tmp/b103-e3-3-security; the aggregate is reported arithmetically, not by allocating it.
"""
import gc, pathlib, sys, time, tracemalloc

sys.path.insert(0, "/home/javiergr/work/b103-int2a")
sys.path.insert(1, "/tmp/b103-e3-3-security")
import s19_app, s19_app.tui.a2l as a  # noqa: E402
import m3a  # noqa: E402

m3a.bind(a)
print("s19_app.__file__ =", s19_app.__file__)
W = pathlib.Path("/tmp/b103-e3-3-security/work")
W.mkdir(parents=True, exist_ok=True)
HDR = ('ASAP2_VERSION 1 71\n/begin PROJECT P ""\n/begin MODULE M ""\n/begin MOD_COMMON ""\nBYTE_ORDER MSB_FIRST\n/end MOD_COMMON\n'
       '/begin COMPU_METHOD CM_ID "" IDENTICAL "%.3" ""\n/end COMPU_METHOD\n'
       '/begin RECORD_LAYOUT RL_U8\nFNC_VALUES 1 UBYTE ROW_DIR DIRECT\n/end RECORD_LAYOUT\n@BODY@\n/end MODULE\n/end PROJECT\n')


def fix_curve(name, addr, maxn):
    return (f'/begin CHARACTERISTIC {name} ""\n CURVE 0x{addr:X} RL_U8 0 CM_ID 0 255\n'
            f' /begin AXIS_DESCR\n  FIX_AXIS NO_INPUT_QUANTITY CM_ID {maxn} 0 2000000\n'
            f'  FIX_AXIS_PAR_DIST 0 1 {maxn}\n /end AXIS_DESCR\n/end CHARACTERISTIC\n')


def build_file(name, body):
    p = W / f"{name}.a2l"
    p.write_text(HDR.replace("@BODY@", body), encoding="utf-8")
    return a.parse_a2l_file(p)


# one FIX axis at a modest size and at the R-A2L-DEF.142 cap -------------------------------------------------------
for maxn in (65_536, 262_144, 1_048_576):
    data = build_file("one", fix_curve("C", 0x10, maxn))
    maps = m3a.build_maps(data)
    secs = m3a.object_sections(data)
    tag = [t for t in data["tags"] if t.get("name") == "C"][0]
    sec = secs["C"][0]
    gc.collect()
    tracemalloc.start()
    t0 = time.perf_counter()
    r = m3a.describe_array(tag, sec, data, maps)
    dt = time.perf_counter() - t0
    cur, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    ax = r["axes"][0] if r["axes"] else {}
    npts = len(ax.get("fixed_points", ()))
    print(f"[F1] FIX axis max {maxn:,}: describe {dt * 1e3:.1f} ms, peak {peak / 2**20:.1f} MiB, "
          f"points built {npts:,}, refusal {r['refusal']!r}")
    del r

# a file that declares several FIX curves at the cap; describe EVERY name (the Inc 6 'describe all' path) ----------
K = 8
body = "".join(fix_curve(f"C{i}", 0x10 + i * 0x200000, 1_048_576) for i in range(K))
data = build_file("many", body)
maps = m3a.build_maps(data)
secs = m3a.object_sections(data)
names = [t.get("name") for t in data["tags"]]
gc.collect()
tracemalloc.start()
t0 = time.perf_counter()
built = {}
for nm in names:
    ss = secs.get(nm) or []
    if len(ss) == 1 and m3a.is_array_kind(ss and [t for t in data["tags"] if t.get("name") == nm][0], ss[0]):
        built[nm] = m3a.describe_array([t for t in data["tags"] if t.get("name") == nm][0], ss[0], data, maps)
dt = time.perf_counter() - t0
cur, peak = tracemalloc.get_traced_memory()
tracemalloc.stop()
print(f"[F2] {K} FIX curves at the cap, describe all: {dt:.2f} s, peak {peak / 2**20:.0f} MiB, "
      f"objects {len(built)} (each keeps its 1,048,576-point tuple while the dict is held)")
per_obj_mib = peak / 2**20 / max(1, K)
print(f"[F3] per FIX axis at the cap ~ {per_obj_mib:.0f} MiB and ~{dt / K * 1e3:.0f} ms; a 1 MB A2L holds about "
      f"{1_000_000 // len(fix_curve('C0', 0x10, 1048576)):,} such curves "
      f"(each declaration {len(fix_curve('C0', 0x10, 1048576))} bytes); describing them all is that count times the above")
