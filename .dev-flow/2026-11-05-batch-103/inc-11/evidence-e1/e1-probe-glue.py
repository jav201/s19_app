"""Inc 11 E1 probe (batch-103), run on cachyos-rtx only: python e1-probe-glue.py <repo> <scratch>

Which inputs make the e07fb00 reader itself give an address (or a length) with extra digits?
Synthetic MAP / VALUE shapes only. For each shape: the tag's address and length as the reader gives them.
Hypotheses: H1 a separator the reader does not split on, removed later; H2 a comment or string next to the
address word; H3 a header with a word missing, or axis numbers reaching the length.
"""
import pathlib, sys

repo = pathlib.Path(sys.argv[1]); scratch = pathlib.Path(sys.argv[2])
sys.path.insert(0, str(repo))
import s19_app  # noqa: E402
print("s19_app.__file__ =", s19_app.__file__)
from s19_app.tui.a2l import parse_a2l_file  # noqa: E402

HEAD = ('ASAP2_VERSION 1 71\n/begin PROJECT PSYN ""\n/begin MODULE MSYN ""\n'
        '/begin COMPU_METHOD CM_SYN "" IDENTICAL "%.0" "rpm"\n/end COMPU_METHOD\n'
        '/begin RECORD_LAYOUT RL_SYN_U16\nFNC_VALUES 1 UWORD COLUMN_DIR DIRECT\n/end RECORD_LAYOUT\n')
TAIL = '/end MODULE\n/end PROJECT\n'
AX = ('  /begin AXIS_DESCR\n    FIX_AXIS NO_INPUT_QUANTITY CM_SYN 33 0 32\n    FIX_AXIS_PAR 0 1 33\n  /end AXIS_DESCR\n'
      '  /begin AXIS_DESCR\n    FIX_AXIS NO_INPUT_QUANTITY CM_SYN 61 0 60\n    FIX_AXIS_PAR 0 1 61\n  /end AXIS_DESCR\n')
def mp(header, axes=AX, name='"Synthetic map"'):
    return f'/begin CHARACTERISTIC {name}\n{header}\n{axes}/end CHARACTERISTIC\n'
GOOD = "  MAP 0x1C2D3E00 RL_SYN_U16 4095 CM_SYN 0 4095"
SHAPES = [
    ("G0", "baseline: the header on one body line", mp(GOOD)),
    ("H2a", "a block comment glued between the address word and digits: 0x1C2D3E00/*c*/4026", mp(GOOD.replace("0x1C2D3E00", "0x1C2D3E00/*c*/4026"))),
    ("H2b", "a block comment from the address word to the next line, digits glued after */", mp("  MAP 0x1C2D3E00/* moved\n  */4026 RL_SYN_U16 4095 CM_SYN 0 4095")),
    ("H2c", "a line comment after the address word, digits on the next line", mp("  MAP 0x1C2D3E00//c\n4026 RL_SYN_U16 4095 CM_SYN 0 4095")),
    ("H2d", "a quoted string glued after the address word: 0x1C2D3E00\"4026\"", mp(GOOD.replace("0x1C2D3E00", '0x1C2D3E00"4026"'))),
    ("H2e", "an underscore between address digits and more digits: 0x1C2D3E00_4026", mp(GOOD.replace("0x1C2D3E00", "0x1C2D3E00_4026"))),
    ("H2f", "an ECU_ADDRESS word glued to a comment and digits: ECU_ADDRESS 0x1C2D3E00/*c*/4026", mp(GOOD + "\n  ECU_ADDRESS 0x1C2D3E00/*c*/4026")),
    ("H1a", "NUL between the address word and digits", mp(GOOD.replace("0x1C2D3E00", "0x1C2D3E00\x004026"))),
    ("H1b", "U+200B ZERO WIDTH SPACE between the address word and digits", mp(GOOD.replace("0x1C2D3E00", "0x1C2D3E00​4026"))),
    ("H1c", "U+FEFF between the address word and digits", mp(GOOD.replace("0x1C2D3E00", "0x1C2D3E00﻿4026"))),
    ("H1d", "a lone CR between the address word and digits", mp(GOOD.replace("0x1C2D3E00", "0x1C2D3E00\r4026"))),
    ("H1e", "VT between the address word and digits", mp(GOOD.replace("0x1C2D3E00", "0x1C2D3E00\x0b4026"))),
    ("H1f", "NBSP U+00A0 between the address word and digits", mp(GOOD.replace("0x1C2D3E00", "0x1C2D3E00 4026"))),
    ("H3a", "the name missing (a quoted string where the name stands) and no long identifier", mp(GOOD)),
    ("H3b", "a long identifier on a body line before the header", mp('  "the long identifier"\n' + GOOD, name="SYN_MAP_B")),
    ("H3c", "the header one word short (no lower limit)", mp("  MAP 0x1C2D3E00 RL_SYN_U16 4095 CM_SYN 4095")),
    ("H3d", "the kind word missing (an extended or absent kind)", mp("  0x1C2D3E00 RL_SYN_U16 4095 CM_SYN 0 4095")),
    ("H3e", "AXIS_DESCR headers on their /begin lines (FIX_AXIS_PAR alone in the body)",
     mp(GOOD, axes='  /begin AXIS_DESCR FIX_AXIS NO_INPUT_QUANTITY CM_SYN 33 0 32\n    FIX_AXIS_PAR 5 2 7\n  /end AXIS_DESCR\n'
                   '  /begin AXIS_DESCR FIX_AXIS NO_INPUT_QUANTITY CM_SYN 61 0 60\n    FIX_AXIS_PAR 5 2 9\n  /end AXIS_DESCR\n')),
    ("H3f", "an AXIS_DESCR whose FIX_AXIS_PAR count differs from its MaxAxisPoints",
     mp(GOOD, axes=AX.replace("FIX_AXIS_PAR 0 1 33", "FIX_AXIS_PAR 0 1 7"))),
    ("H3g", "a third AXIS_DESCR with one word and no axis kind",
     mp(GOOD, axes=AX + '  /begin AXIS_DESCR\n    NO_INPUT_QUANTITY\n  /end AXIS_DESCR\n')),
]
for key, label, body in SHAPES:
    p = scratch / "glue.a2l"
    p.write_text(HEAD + body + TAIL, encoding="utf-8")
    d = parse_a2l_file(p)
    t = d["tags"][0] if d["tags"] else {}
    a, ln = t.get("address"), t.get("length")
    shown = f"0x{a:08X}" if isinstance(a, int) else "n/a"
    print(f"[{key}] {label}: name={t.get('name')!r} address shown={shown} length={ln!r} "
          f"axis max points={[m.get('max_axis_points') for m in t.get('axis_meta') or []]} errors={d['errors']}")
    p.unlink()
