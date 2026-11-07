"""Inc 11 E2 probe (batch-103): synthetic reductions of the public-corpus anomaly classes 1-7 and the Latin-1 input
(`design/a2l-corpus/anomalies.md`), read by the e07fb00 reader. Each shape is written from the class's structure
description only: no corpus file content, name or value is used. Run on <runner> only.

Usage: python -I i11e2-corpus-shapes.py <repo> <scratch dir>
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

repo = Path(sys.argv[1])
scratch = Path(sys.argv[2])
sys.path.insert(0, str(repo))
import s19_app  # noqa: E402
import s19_app.tui.a2l as a  # noqa: E402
from s19_app.validation.rules import validate_a2l_structure  # noqa: E402

print("s19_app.__file__ =", s19_app.__file__)

HDR = ('ASAP2_VERSION 1 71\n/begin PROJECT P ""\n/begin MODULE M ""\n/begin MOD_COMMON ""\nBYTE_ORDER MSB_FIRST\n'
       '/end MOD_COMMON\n/begin COMPU_METHOD CM_ID "" IDENTICAL "%.0" ""\n/end COMPU_METHOD\n'
       + "".join(f'/begin RECORD_LAYOUT RL_{k}\nFNC_VALUES 1 {v} ROW_DIR DIRECT\n/end RECORD_LAYOUT\n'
                 for k, v in (("U8", "UBYTE"), ("U16", "UWORD"), ("U32", "ULONG"))))
TAIL = "/end MODULE\n/end PROJECT\n"

SHAPES = [
    ("K1", "class 1: /begin MEASUREMENT alone on its line, one word per line (two such objects)",
     "".join("/begin MEASUREMENT\n" + f"{nm}\n" + '"long id"\nUWORD\nCM_ID\n0\n0\n0\n65535\nECU_ADDRESS\n' + f"{ad}\n"
             + "/end MEASUREMENT\n" for nm, ad in (("XK1", "0x1234"), ("XK1B", "0x1236")))),
    ("K1c", "class 1: /begin CHARACTERISTIC alone on its line, one word per line",
     '/begin CHARACTERISTIC\nCK1\n"long id"\nVALUE\n0x2000\nRL_U16\n0\nCM_ID\n0\n65535\n/end CHARACTERISTIC\n'),
    ("K2", "class 2: MEASUREMENT name on the /begin line, header one word per line",
     '/begin MEASUREMENT XK2 ""\nUWORD\nCM_ID\n0\n0\n0\n65535\nECU_ADDRESS 0x1234\n/end MEASUREMENT\n'),
    ("K3", "classes 3+4: CHARACTERISTIC header on the /begin line, ECU_ADDRESS_EXTENSION first in the body",
     '/begin CHARACTERISTIC CK3 "d" VALUE 0x1000 RL_U16 0 CM_ID 100 10000\nECU_ADDRESS_EXTENSION 0\n'
     'BYTE_ORDER MSB_LAST\nPHYS_UNIT "ms"\nSTEP_SIZE 1\n/end CHARACTERISTIC\n'),
    ("K4", "class 4: extended kind CUBE_5 on the /begin line, NUMBER first in the body",
     '/begin CHARACTERISTIC CK4 "d" CUBE_5 0x123 RL_U16 1 CM_ID 0 10\nNUMBER 10000\nREAD_ONLY\nFORMAT "%3.3"\n'
     'STEP_SIZE 1\n/end CHARACTERISTIC\n'),
    ("K5", "class 5: one-line MEASUREMENT, ECU_ADDRESS mid-line, a nested one-line IF_DATA, /end on the same line",
     '/begin MEASUREMENT XK5 "d" FLOAT64_IEEE NO_COMPU_METHOD 0 0 -100 100  ECU_ADDRESS 0x18 ECU_ADDRESS_EXTENSION 3 '
     'READ_WRITE /begin IF_DATA XCP /begin DAQ_EVENT FIXED_EVENT_LIST EVENT 0x0 /end DAQ_EVENT /end IF_DATA /end MEASUREMENT\n'),
    ("K5b", "class 5: a comment before ECU_ADDRESS on its line",
     '/begin MEASUREMENT XK5B ""\nUWORD CM_ID 0 0 0 65535\n/* moved */ ECU_ADDRESS 0x1234\n/end MEASUREMENT\n'),
    ("K6", "class 6: VAL_BLK on a project-named layout (no size in its name), MATRIX_DIM, header on its own line",
     '/begin CHARACTERISTIC CK6 ""\nVAL_BLK 0x3000 RL_U16 0 CM_ID 0 65535\nMATRIX_DIM 4\n/end CHARACTERISTIC\n'),
    ("K6b", "class 6: VAL_BLK on a project-named layout, NUMBER (ASAP2 1.6 style), no MATRIX_DIM",
     '/begin CHARACTERISTIC CK6B ""\nVAL_BLK 0x3010 RL_U16 0 CM_ID 0 65535\nNUMBER 4\n/end CHARACTERISTIC\n'),
    ("K6c", "class 6: ASCII on a project-named layout, MATRIX_DIM (ASAP2 1.7 style), no NUMBER",
     '/begin CHARACTERISTIC CK6C ""\nASCII 0x3020 RL_U8 0 CM_ID 0 255\nMATRIX_DIM 8\n/end CHARACTERISTIC\n'),
    ("K6d", "class 6: VALUE on a project-named layout, header one word per line",
     '/begin CHARACTERISTIC CK6D ""\nVALUE\n0x3030\nRL_U32\n0\nCM_ID\n0\n100\n/end CHARACTERISTIC\n'),
    ("K7", "class 7: a MEASUREMENT header with 4 of its 6 words",
     '/begin MEASUREMENT XK7 "" UWORD CM_ID 0 0\nECU_ADDRESS 0x10\n/end MEASUREMENT\n'),
    ("K7b", "class 7: /begin INSTANCE after other words on its line",
     '/begin TYPEDEF_MEASUREMENT T_U16 "" UWORD CM_ID 0 0 0 65535\n/end TYPEDEF_MEASUREMENT\n'
     '/begin INSTANCE IK7 "" T_U16 0x20 /end INSTANCE /begin INSTANCE IK7B "" T_U16 0x40 /end INSTANCE\n'
     '/begin MEASUREMENT XK7B ""\nUWORD CM_ID 0 0 0 65535\nECU_ADDRESS 0x60\n/end MEASUREMENT\n'),
]
LATIN1 = ("L1", "Latin-1 bytes 0xB0 in a comment, in a long identifier and in a name word",
          HDR + '/* 20 \xb0C */\n/begin MEASUREMENT XL1 "Temp \xb0C"\nUWORD CM_ID 0 0 0 65535\nECU_ADDRESS 0x70\n'
          '/end MEASUREMENT\n/begin MEASUREMENT XL1_\xb0 ""\nUWORD CM_ID 0 0 0 65535\nECU_ADDRESS 0x72\n/end MEASUREMENT\n' + TAIL)


def show(t: dict) -> str:
    ad = t.get("address")
    return (f"name={t.get('name')!r} section={t.get('section')} kind={t.get('char_type')} "
            f"address={hex(ad) if isinstance(ad, int) else ad} datatype={t.get('datatype')} length={t.get('length')} "
            f"deposit={t.get('deposit')} desc={t.get('description')!r}")


with tempfile.TemporaryDirectory(dir=str(scratch)) as d:
    for key, label, body in SHAPES:
        p = Path(d) / f"{key}.a2l"
        p.write_text(HDR + body + TAIL, encoding="utf-8")
        data = a.parse_a2l_file(p)
        dups = [i.message for i in validate_a2l_structure(data) if i.code == "A2L_DUPLICATE_SYMBOL"]
        print(f"[{key}] {label}")
        for t in data["tags"]:
            print("      tag:", show(t))
        print(f"      errors={data['errors']} duplicate issues={dups} payload keys={sorted(data)}")
    key, label, text = LATIN1
    p = Path(d) / "L1.a2l"
    p.write_bytes(text.encode("latin-1"))
    data = a.parse_a2l_file(p)
    print(f"[{key}] {label}")
    for t in data["tags"]:
        print("      tag:", show(t))
    print(f"      errors={data['errors']}")
