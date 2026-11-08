"""E3 security probe, Inc 3a: a COM_AXIS that names itself / an AXIS_PTS section, a dangling reference, and control
characters in a layout / ref / name echoed in a message. Model m3a.py + Inc 2a `_clean`; read-only trees.
"""
import pathlib, sys, time
sys.path.insert(0, "/home/<user>/work/b103-int2a")
sys.path.insert(1, "/tmp/b103-e3-3-security")
import s19_app, s19_app.tui.a2l as a  # noqa: E402
import s19_app.tui.a2l_definition as d2  # noqa: E402
import m3a  # noqa: E402
m3a.bind(a)
print("s19_app.__file__ =", s19_app.__file__)
W = pathlib.Path("/tmp/b103-e3-3-security/work"); W.mkdir(parents=True, exist_ok=True)
HDR = ('ASAP2_VERSION 1 71\n/begin PROJECT P ""\n/begin MODULE M ""\n/begin MOD_COMMON ""\nBYTE_ORDER MSB_FIRST\n/end MOD_COMMON\n'
       '/begin COMPU_METHOD CM_ID "" IDENTICAL "%.3" ""\n/end COMPU_METHOD\n'
       '/begin RECORD_LAYOUT RL_U8\nFNC_VALUES 1 UBYTE ROW_DIR DIRECT\n/end RECORD_LAYOUT\n'
       '/begin RECORD_LAYOUT RL_AX\nNO_AXIS_PTS_X 1 UBYTE\nAXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT\n/end RECORD_LAYOUT\n@BODY@\n/end MODULE\n/end PROJECT\n')


def run(label, body):
    p = W / "ref.a2l"; p.write_text(HDR.replace("@BODY@", body), encoding="utf-8")
    t0 = time.perf_counter()
    data = a.parse_a2l_file(p)
    out = m3a.describe_all(data)
    dt = time.perf_counter() - t0
    rows = {k: (v["refusal"], v["shape"]) for k, v in out.items()}
    print(f"[H] {label}: {dt*1e3:.1f} ms, {rows}")


CURVE_SELF = '/begin CHARACTERISTIC C ""\n CURVE 0x100 RL_U8 0 CM_ID 0 255\n /begin AXIS_DESCR\n  COM_AXIS NO_INPUT CM_ID 4 0 255 AXIS_PTS_REF C\n /end AXIS_DESCR\n/end CHARACTERISTIC\n'
run("COM_AXIS AXIS_PTS_REF names the curve itself", CURVE_SELF)

# an AXIS_PTS whose own record layout is itself an AXIS_PTS-like chain: the axis object is read for points only, never
# re-described, so no cycle. Two AXIS_PTS cross-naming via record layout cannot recurse.
AXPTS = ('/begin AXIS_PTS AXO "" 0x200 NO_INPUT RL_AX 0 CM_ID 4 0 255\n/end AXIS_PTS\n'
         '/begin CHARACTERISTIC C ""\n CURVE 0x100 RL_U8 0 CM_ID 0 255\n /begin AXIS_DESCR\n  COM_AXIS NO_INPUT CM_ID 4 0 255 AXIS_PTS_REF AXO\n /end AXIS_DESCR\n/end CHARACTERISTIC\n')
run("COM_AXIS -> AXIS_PTS AXO (normal)", AXPTS)
run("COM_AXIS -> missing AXO", AXPTS.replace("AXIS_PTS_REF AXO", "AXIS_PTS_REF GONE"))

# control characters in names / refs echoed in messages
ESC = "\x1b"
LAYOUT_CTRL = f'/begin CHARACTERISTIC V ""\n VAL_BLK 0x10 RL{ESC}X 0 CM_ID 0 255\n MATRIX_DIM 2\n/end CHARACTERISTIC\n'
p = W / "ctrl.a2l"; p.write_text(HDR.replace("@BODY@", LAYOUT_CTRL), encoding="utf-8")
data = a.parse_a2l_file(p)
out = m3a.describe_all(data)
# the model records only the code; show that Inc 2a `_clean` replaces the ESC in the name the message would echo
print(f"[H2] control char in layout name: model first refusal {out.get('V', {}).get('refusal')}; "
      f"_clean('RL{{ESC}}X') = {d2._clean('RL' + ESC + 'X')!r}  (U+FFFD for the ESC)")
