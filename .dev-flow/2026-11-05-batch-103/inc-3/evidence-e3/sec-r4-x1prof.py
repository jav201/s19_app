"""E3 round-4: why does [X1] (an AXIS_PTS at the .143 bound, max 1,048,575, shared by COM curves) cost ~15 ms per
object? cProfile of the model's describe_all on 50 and 200 such curves, tracemalloc off. THROWAWAY.
Usage: python -I sec-r4-x1prof.py <tree> <scratch>"""
import cProfile, importlib.util, io, pathlib, pstats, sys, time
TREE, S = sys.argv[1], pathlib.Path(sys.argv[2])
sys.path.insert(0, TREE)
import s19_app.tui.a2l as a  # noqa: E402
import s19_app.tui.a2l_definition as D  # noqa: E402
spec = importlib.util.spec_from_file_location("m3r4", str(S / "sec-r4-m3a.py"))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); m.bind(a, D)
W = S / "work"
MAXP = 1_048_575
for n, maxp in ((50, MAXP), (200, MAXP), (200, 4)):
    txt = ('ASAP2_VERSION 1 71\n/begin PROJECT P ""\n/begin MODULE M ""\n/begin MOD_COMMON ""\nBYTE_ORDER MSB_FIRST\n'
           '/end MOD_COMMON\n/begin RECORD_LAYOUT RL_U8\n FNC_VALUES 1 UBYTE ROW_DIR DIRECT\n/end RECORD_LAYOUT\n'
           '/begin RECORD_LAYOUT RL_AXO\n NO_AXIS_PTS_X 1 UBYTE\n AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT\n'
           '/end RECORD_LAYOUT\n/begin COMPU_METHOD CM_ID "" IDENTICAL "%.3" ""\n/end COMPU_METHOD\n'
           f'/begin AXIS_PTS AXO "" 0x100 NO_INPUT_QUANTITY RL_AXO 0 CM_ID {maxp} 0 255\n/end AXIS_PTS\n'
           + "".join(f'/begin CHARACTERISTIC C{i:05d} ""\n CURVE 0x{0x200000 + 0x100000 * i:X} RL_U8 0 CM_ID 0 255\n'
                     f' /begin AXIS_DESCR\n  COM_AXIS NO_INPUT_QUANTITY CM_ID {maxp} 0 255\n  AXIS_PTS_REF AXO\n'
                     f' /end AXIS_DESCR\n/end CHARACTERISTIC\n' for i in range(n)) + '/end MODULE\n/end PROJECT\n')
    p = W / f"x1prof_{n}_{maxp}.a2l"; p.write_text(txt, encoding="utf-8")
    data = a.parse_a2l_file(p)
    t0 = time.perf_counter(); m.describe_all(data); dt = time.perf_counter() - t0
    pr = cProfile.Profile(); pr.enable(); m.describe_all(data); pr.disable()
    s = io.StringIO(); pstats.Stats(pr, stream=s).sort_stats("tottime").print_stats(6)
    top = [ln for ln in s.getvalue().splitlines() if ln.strip() and (ln.strip()[0].isdigit())][:6]
    print(f"[X1p] {n} COM curves on an AXO of max {maxp}: describe_all {dt:.3f} s ({dt / n * 1e3:.2f} ms/object); "
          f"top by tottime:", flush=True)
    for ln in top:
        print("    " + ln.strip()[:160], flush=True)
