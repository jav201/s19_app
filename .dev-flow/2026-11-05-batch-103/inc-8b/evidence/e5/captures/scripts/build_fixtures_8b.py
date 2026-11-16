"""Inc 8b E5 capture fixture (batch-103): DEFC (seed 20260001) plus a text row TEXT_0001 and a NaN row NAN_0001,
so one `_0001` page holds every row kind: number, enum, bit mask, text, array, NaN
(CURVE_DEF_0001 and VAL_BLK_DEF_0001 are dropped to keep the page inside the body window).
Usage: python -I -B build_fixtures_8b.py <tree> <out_dir>   (writes <out_dir>/grid8b.a2l and grid8b.s19; nothing in the repo)"""
import subprocess
import sys
from pathlib import Path

root, out = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
out.mkdir(parents=True, exist_ok=True)
subprocess.run([sys.executable, "-B", str(root / "tools/synth/make_release_case.py"), "--out", str(out / "defc"),
                "--seed", "20260001", "--case", "definitions"], check=True, capture_output=True, timeout=600)
a2l = (out / "defc" / "definitions.a2l").read_text(encoding="utf-8")
s19 = (out / "defc" / "definitions.s19").read_text(encoding="utf-8").splitlines()


def sub(text, old, new):
    assert text.count(old) == 1, old
    return text.replace(old, new)


a2l = sub(a2l, "0x00800000 0x000100", "0x00800000 0x000200")
# The sheet body paints 9 lines at 118x54 (header and rule included), so a page of 9 rows plus the selected row's detail
# scrolls the first row out (the approved D.off.sheet does the same). Drop two array-like rows so the page keeps one
# row of every kind and all of them stay on screen with a one-line detail: CURVE_DEF_0001 and VAL_BLK_DEF_0001
# (MAP_DEF_0001 stays as the array row).
import re
for name in ("CURVE_DEF_0001", "VAL_BLK_DEF_0001"):
    a2l, n = re.subn(r"    /begin CHARACTERISTIC " + name + r" .*?    /end CHARACTERISTIC\n", "", a2l, flags=re.S)
    assert n == 1, name
a2l = sub(a2l, "    /begin RECORD_LAYOUT RL_DEF_AXIS\n",
          "    /begin RECORD_LAYOUT RL_F32_NAN\n      FNC_VALUES 1 FLOAT32_IEEE COLUMN_DIR DIRECT\n    /end RECORD_LAYOUT\n"
          "    /begin RECORD_LAYOUT RL_DEF_AXIS\n")
extra = (
    '    /begin CHARACTERISTIC TEXT_0001 "synthetic text row"\n'
    "      ASCII 0x00800100 RL_U8 0 CM_DEF_IDENT 0 255\n      NUMBER 42\n    /end CHARACTERISTIC\n"
    '    /begin CHARACTERISTIC NAN_0001 "synthetic erased float row"\n'
    "      VALUE 0x00800140 RL_F32_NAN 0 CM_DEF_LIN -40 150\n      EXTENDED_LIMITS -50 200\n"
    '      FORMAT "%.1"\n      PHYS_UNIT "deg C"\n    /end CHARACTERISTIC\n'
)
a2l = sub(a2l, "  /end MODULE\n", extra + "  /end MODULE\n")


def rec(address, data):
    body = bytes([len(data) + 5]) + address.to_bytes(4, "big") + data
    return "S3" + body.hex().upper() + f"{(~sum(body)) & 0xFF:02X}"


end = [i for i, line in enumerate(s19) if line.startswith("S7")][0]
s19[end:end] = [rec(0x00800100, (b"Hello ASAM, ASCII text row 42 bytes" + bytes(42))[:42]), rec(0x00800140, b"\xff\xff\xff\xff")]
(out / "grid8b.a2l").write_text(a2l, encoding="utf-8", newline="\n")
(out / "grid8b.s19").write_text("\n".join(s19) + "\n", encoding="ascii", newline="\n")
print("ok", sorted(p.name for p in out.iterdir()))
