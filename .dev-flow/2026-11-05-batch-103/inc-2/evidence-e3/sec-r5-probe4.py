"""E3 round-5 security probe 4, Inc 2 (batch-103): the cost of R-A2L-DEF.138's page index for a tag length the tag
table does not cap. Base parser only (clone e07fb00), read-only.

The graph (`describe_definitions`): "every MEASUREMENT and CHARACTERISTIC tag whose address the A2L declares and that
has a byte length ... filed under each 256-byte page (address >> 8) its span touches". R-A2L-DEF.7.2 bounds the
DEFINITION's span (1 .. 1,048,576 bytes); nothing bounds an index entry. This prints the tag length the base gives
for one hostile line and the number of pages that entry would be filed under; it builds no index.
"""
import pathlib, sys, tempfile
repo = pathlib.Path(sys.argv[1]); scratch = pathlib.Path(sys.argv[2])
sys.path.insert(0, str(repo))
import s19_app, s19_app.tui.a2l as a  # noqa: E402
print("s19_app.__file__ =", s19_app.__file__)
HDR = ('ASAP2_VERSION 1 71\n/begin PROJECT P ""\n/begin MODULE M ""\n/begin MOD_COMMON ""\nBYTE_ORDER MSB_FIRST\n/end MOD_COMMON\n'
       '/begin COMPU_METHOD CM_ID "" IDENTICAL "%.0" ""\n/end COMPU_METHOD\n'
       '/begin RECORD_LAYOUT RL_U8\nFNC_VALUES 1 UBYTE ROW_DIR DIRECT\n/end RECORD_LAYOUT\n@BODY@\n/end MODULE\n/end PROJECT\n')
SHAPES = {
 "H1 ASCII NUMBER 10^12": '/begin CHARACTERISTIC T ""\n ASCII 0x10 RL_U8 0 CM_ID 0 255\n NUMBER 1000000000000\n/end CHARACTERISTIC',
 "H2 MEASUREMENT MATRIX_DIM 2^32": '/begin MEASUREMENT M ""\n UWORD CM_ID 0 0 0 65535\n ECU_ADDRESS 0x10\n MATRIX_DIM 4294967296\n/end MEASUREMENT',
 "H3 VALUE with a LENGTH line 10^11": '/begin CHARACTERISTIC V ""\n VALUE 0x10 RL_U8 0 CM_ID 0 255\n LENGTH 99999999999\n/end CHARACTERISTIC',
 "H4 MEASUREMENT DATA_SIZE 0x7FFFFFFFFFFF": '/begin MEASUREMENT D ""\n UBYTE CM_ID 0 0 0 255\n ECU_ADDRESS 0x10\n DATA_SIZE 0x7FFFFFFFFFFF\n/end MEASUREMENT',
}
with tempfile.TemporaryDirectory(dir=str(scratch)) as d:
    for label, body in SHAPES.items():
        p = pathlib.Path(d) / "x.a2l"; p.write_text(HDR.replace("@BODY@", body), encoding="utf-8")
        data = a.parse_a2l_file(p)
        t = data["tags"][0]
        L, A = t.get("length"), t.get("address")
        pages = None if (L is None or A is None or L < 1) else ((A + L - 1) >> 8) - (A >> 8) + 1
        print(f"[{label.split()[0]}] {label}: tag address={A!r} length={L!r} matrix_dim={t.get('matrix_dim')!r} "
              f"| pages the index files it under={pages:,} | R-A2L-DEF.7.2 refuses its own definition: {L is not None and L > 1 << 20}")
