"""Build the Inc 9 capture fixtures once (hand A2Ls built like tests/support/b103_inc9_w.py; DEFC via the shipped generator).
Usage: python -I -B build_fixtures_i9.py <tree> <out_dir>"""
import subprocess, sys
from pathlib import Path

root, out = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
sys.path.insert(0, str(root))
out.mkdir(parents=True, exist_ok=True)
from tests.support import b103_a2l_arrays as arrays  # noqa: E402


def rec(kind, addr_bytes, payload):
    body = bytes([len(addr_bytes) + len(payload) + 1]) + addr_bytes + payload
    return f"{kind}{body.hex().upper()}{(~sum(body)) & 0xFF:02X}"


def s19(path, memory):
    lines = [rec("S0", b"\x00\x00", b"cap")]
    for address, data in memory:
        for off in range(0, len(data), 32):
            lines.append(rec("S3", (address + off).to_bytes(4, "big"), data[off:off + 32]))
    lines.append(rec("S7", b"\x00\x00\x00\x00", b""))
    path.write_text("\n".join(lines) + "\n", encoding="ascii", newline="\n")


def a2l(name, *blocks):
    d = out / f"build_{name}"
    d.mkdir(exist_ok=True)
    arrays.inline(d, *blocks)
    target = out / f"{name}.a2l"
    target.write_text(next(d.glob("*.a2l")).read_text(encoding="utf-8"), encoding="utf-8", newline="\n")


subprocess.run([sys.executable, "-B", str(root / "tools/synth/make_release_case.py"), "--out", str(out / "defc"),
                "--seed", "20260001", "--case", "definitions"], check=True, capture_output=True, timeout=600)

cm, vtab, vb = arrays.cm, arrays.vtab, arrays.valblk
# hand: 1-D VAL_BLK (40), TAB_VB (texts), F32_BLK (1, nan, 3), REF_BLK (6 elements, the image holds 5 bytes)
blocks = (cm("CM_E", "TAB_VERB", fmt='"%.0"', ref="VT_E"), vtab("VT_E", "2", '0 "OFF"', '1 "ON"'),
          vb("VB1D", "0x100000", "RL_U8", "NO_COMPU_METHOD", "0", "255", "MATRIX_DIM 40"),
          vb("TAB_VB", "0x200000", "RL_U8", "CM_E", "0", "255", "MATRIX_DIM 2"),
          vb("F32_BLK", "0x300000", "RL_F32", "NO_COMPU_METHOD", "-1000", "1000", "MATRIX_DIM 3"),
          vb("REF_BLK", "0x400000", "RL_U8", "NO_COMPU_METHOD", "0", "255", "MATRIX_DIM 6"),
          vb("NTC_BLK", "0x500000", "RL_U8", "NO_COMPU_METHOD", "0", "100", "MATRIX_DIM 4", extras="EXTENDED_LIMITS 0 200"))
a2l("hand", *blocks)
s19(out / "hand.s19", [(0x100000, bytes((i * 5 + (i % 3) * 7) % 200 for i in range(40))), (0x200000, bytes([1, 0])),
                       (0x300000, bytes.fromhex("3F800000FFFFFFFF40400000")), (0x400000, bytes([1, 2, 3, 4, 5])), (0x500000, bytes([10, 20, 30, 40]))])
# refused: same A2L, no image byte for REF_BLK's last element (above) -> hand already; separate empty-ish no-op

# large: LARGE (UBYTE x 1,048,576) + SMALL_BLK
a2l("large", vb("LARGE", "0x100000", "RL_U8", "NO_COMPU_METHOD", "0", "255", "MATRIX_DIM 1048576"),
    vb("SMALL_BLK", "0x400000", "RL_U8", "NO_COMPU_METHOD", "0", "255", "MATRIX_DIM 4"))
s19(out / "large.s19", [(0x100000, bytes(1048576)), (0x400000, bytes([1, 2, 3, 4]))])
print("ok", sorted(p.name for p in out.iterdir()))
