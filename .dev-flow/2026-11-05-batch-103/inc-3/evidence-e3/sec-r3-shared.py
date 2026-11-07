"""E3 round-3 security probe, Inc 3a (batch-103): E3S3-11 as corrected (`maps["reads"]`: each RECORD_LAYOUT and
MOD_COMMON read once per walk) and the third shared section kind, an AXIS_PTS named by many COM_AXIS curves,
whose header and own BYTE_ORDER line `_read_axis` reads per referencing axis.
Model `sec-r3-m3a.py`; Inc 2a's real `describe_definitions` of the same names for reference.
THROWAWAY; read-only trees. Usage: python -I sec-r3-shared.py <inc2a tree> <scratch>
"""
import gc, importlib.util, pathlib, sys, time, tracemalloc

TREE, S = sys.argv[1], pathlib.Path(sys.argv[2])
sys.path.insert(0, TREE)
import s19_app, s19_app.tui.a2l as a  # noqa: E402
import s19_app.tui.a2l_definition as D  # noqa: E402

spec = importlib.util.spec_from_file_location("m3r3", str(S / "sec-r3-m3a.py"))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); m.bind(a)
print("s19_app.__file__ =", s19_app.__file__.replace(str(pathlib.Path.home()), "~"), "| python",
      sys.version.split()[0], flush=True)
W = S / "work"; W.mkdir(parents=True, exist_ok=True)

KB = 256
FILL_COMMENT = "/* " + ("x" * 78 + "\n") * (KB * 1024 // 79) + " */\n"
FILL_DEPOSIT = 'DEPOSIT ABSOLUTE\n' * (KB * 1024 // 17)


def text_layout_modc(n):
    """.136/arr-2's file: a 256 KiB block comment in the shared layout, 256 KiB of DEPOSIT lines in MOD_COMMON."""
    mc = '/begin MOD_COMMON ""\nBYTE_ORDER MSB_FIRST\nALIGNMENT_WORD 2\n' + FILL_DEPOSIT + "/end MOD_COMMON\n"
    rl = "/begin RECORD_LAYOUT RL_BIG\n FNC_VALUES 1 UBYTE ROW_DIR DIRECT\n" + FILL_COMMENT + "/end RECORD_LAYOUT\n"
    objs = "".join(f'/begin CHARACTERISTIC V{i:05d} ""\n VAL_BLK 0x{0x1000 + 16 * i:X} RL_BIG 0 NO_COMPU_METHOD 0 255\n'
                   f' NUMBER 4\n/end CHARACTERISTIC\n' for i in range(n))
    return f'ASAP2_VERSION 1 71\n/begin PROJECT P ""\n/begin MODULE M ""\n{mc}{rl}{objs}/end MODULE\n/end PROJECT\n'


def text_axis_pts(n, fill):
    """n COM_AXIS curves sharing one AXIS_PTS `AXO` whose body holds 256 KiB of `fill` (no BYTE_ORDER line)."""
    mc = '/begin MOD_COMMON ""\nBYTE_ORDER MSB_FIRST\n/end MOD_COMMON\n'
    rls = ('/begin RECORD_LAYOUT RL_U8\n FNC_VALUES 1 UBYTE ROW_DIR DIRECT\n/end RECORD_LAYOUT\n'
           '/begin RECORD_LAYOUT RL_AXO\n NO_AXIS_PTS_X 1 UBYTE\n AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT\n'
           '/end RECORD_LAYOUT\n/begin COMPU_METHOD CM_ID "" IDENTICAL "%.3" ""\n/end COMPU_METHOD\n')
    axo = (f'/begin AXIS_PTS AXO "" 0x100 NO_INPUT_QUANTITY RL_AXO 0 CM_ID 4 0 255\n'
           f'{FILL_COMMENT if fill == "comment" else FILL_DEPOSIT}/end AXIS_PTS\n')
    objs = "".join(f'/begin CHARACTERISTIC C{i:05d} ""\n CURVE 0x{0x1000 + 16 * i:X} RL_U8 0 CM_ID 0 255\n'
                   f' /begin AXIS_DESCR\n  COM_AXIS NO_INPUT_QUANTITY CM_ID 4 0 255\n  AXIS_PTS_REF AXO\n'
                   f' /end AXIS_DESCR\n/end CHARACTERISTIC\n' for i in range(n))
    return f'ASAP2_VERSION 1 71\n/begin PROJECT P ""\n/begin MODULE M ""\n{mc}{rls}{axo}{objs}/end MODULE\n/end PROJECT\n'


def parse(tag, txt):
    p = W / f"{tag}.a2l"
    p.write_text(txt, encoding="utf-8")
    t0 = time.perf_counter(); data = a.parse_a2l_file(p); tp = time.perf_counter() - t0
    return data, tp, p.stat().st_size


def timed(fn, reps=3):
    best = []
    for _ in range(reps):
        gc.collect(); t0 = time.perf_counter(); r = fn(); best.append(time.perf_counter() - t0)
    best.sort()
    return r, best[len(best) // 2]


# [M1] .136/arr-2 as written, reads once per walk vs the per-object reads (the round-2 graph)
data, tp, size = parse("arr2", text_layout_modc(400))
names = [t["name"] for t in data["tags"]]
(res, maps), dt = timed(lambda: m.describe_all(data))
tracemalloc.start(); m.describe_all(data); _, peak = tracemalloc.get_traced_memory(); tracemalloc.stop()
refs = {}
for v in res.values():
    refs[v["refusal"]] = refs.get(v["refusal"], 0) + 1
shapes = {v["shape"] for v in res.values()}
print(f"[M1] .136/arr-2 file {size / 1024:.0f} KiB (parse {tp:.2f} s): model describe-all with maps['reads'] "
      f"{dt:.3f} s (median of 3), peak {peak / 2**20:.1f} MiB; objects {len(res)}; refusals {refs}; shapes {shapes}; "
      f"reads {maps['stats']}", flush=True)
_, dt2 = timed(lambda: D.describe_definitions(names, data))
print(f"[M1] Inc 2a's real describe_definitions of the same 400 names: {dt2:.3f} s (median of 3)", flush=True)


class Fresh(dict):
    """A `reads` that never finds an entry: every call re-reads its section (the round-2 graph)."""
    def __contains__(self, key):
        return False


def per_object(data):
    maps = m.new_maps(data)
    maps["reads"] = Fresh()
    out, _ = m.describe_all(data, maps=maps)
    return out, maps


(_, mp), dt3 = timed(lambda: per_object(data), reps=1)
print(f"[M2] negative control: one walk, but each object re-reads the layout and MOD_COMMON (the round-2 graph) "
      f"{dt3:.2f} s; reads {mp['stats']}", flush=True)

# [A1..A4] the AXIS_PTS shared by many COM axes: header and own BYTE_ORDER line per referencing axis
for fill in ("comment", "deposit"):
    data, tp, size = parse(f"axo_{fill}", text_axis_pts(400, fill))
    kept = len("\n".join(next(iter(s for s in m.B.build_maps(data)["axis_pts_by_name"].values())).get("lines") or []))
    names = [t["name"] for t in data["tags"]]
    for hdr, bo in (("per-call", "per-call"), ("walk", "per-call"), ("walk", "memo")):
        m.AXO_HEADER, m.AXO_BYTE_ORDER = hdr, bo
        (res, maps), dt = timed(lambda: m.describe_all(data), reps=1 if hdr == "per-call" else 3)
        refs = {}
        for v in res.values():
            refs[v["refusal"]] = refs.get(v["refusal"], 0) + 1
        print(f"[A-{fill}] 400 COM curves sharing AXO ({kept / 1024:.0f} KiB kept in its lines, file "
              f"{size / 1024:.0f} KiB, parse {tp:.2f} s): header {hdr}, own BYTE_ORDER {bo}: describe-all {dt:.3f} s "
              f"({dt / 400 * 1e3:.2f} ms per object); refusals {refs}; stats {maps['stats']}", flush=True)
    m.AXO_HEADER, m.AXO_BYTE_ORDER = "walk", "per-call"
    t0 = time.perf_counter(); a._byte_order_from_section_lines(
        next(iter(m.B.build_maps(data)["axis_pts_by_name"].values())).get("lines") or [])
    print(f"[A-{fill}] one _byte_order_from_section_lines over AXO's lines: {time.perf_counter() - t0:.4f} s", flush=True)
    t0 = time.perf_counter(); ap = next(iter(m.B.build_maps(data)["axis_pts_by_name"].values()))
    a._flatten_body_tokens([ap.get("meta") or ""] + (ap.get("lines") or []))
    print(f"[A-{fill}] one header read (_flatten_body_tokens) of AXO: {time.perf_counter() - t0:.4f} s", flush=True)
    _, dt2 = timed(lambda: D.describe_definitions(names, data))
    print(f"[A-{fill}] Inc 2a's real describe_definitions of the same names: {dt2:.3f} s", flush=True)
