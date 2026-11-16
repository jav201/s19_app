"""Inc 10 E3 correction (E3-2): build fixture x64u and its expected Intel HEX lines as data.

x64u = 32 bytes, values 0x00 .. 0x1F, at 0x0000FFF8 .. 0x00010017: one contiguous range whose
start is not 16-aligned and that crosses the 64 KiB boundary 0x00010000 inside a 16-byte row.

Stdlib only; it imports nothing from s19_app, so the expected lines are an oracle independent of
the code under test (R-HEX-EMIT-001.11). Writes, into the folder given as the only argument
(default: this script's folder):
  x64u.s19              the S19 source (S0 data `X64U`, two S2 records of 16 bytes, S8 at 0)
  x64u.hex              the HEX twin AND the expected output of the system's Intel HEX writer for
                        both sources (R-HEX-EMIT-001.11/1, /2): no data record crosses 0x10000
  x64u-base-emitter.hex what the base emitter's loop (`changes/io.py` at 287b9dc3, reproduced
                        below, not imported) writes: one record `:10FFF800...` crosses 0x10000 —
                        the negative control's output
Self-checks (exit 1 on any failure): checksums, the boundary rule on x64u.hex, exactly one
crossing record in the base output, and all three files decode to the same image.
"""
import sys
from pathlib import Path

START = 0x0000FFF8
DATA = list(range(0x20))  # 0x00 .. 0x1F
IMAGE = {START + i: b for i, b in enumerate(DATA)}
RANGES = [(START, START + len(DATA))]
ROW = 16  # HEX_DATA_BYTES_PER_RECORD (R-HEX-EMIT-001.1)


def hex_record(rtype, offset, data):
    body = [len(data), (offset >> 8) & 0xFF, offset & 0xFF, rtype] + list(data)
    cs = (-sum(body)) & 0xFF
    return ":" + "".join("%02X" % b for b in body + [cs])


def s_record(tag, addr, addr_len, data):
    body = [addr_len + len(data) + 1] + list(addr.to_bytes(addr_len, "big")) + list(data)
    cs = 0xFF - (sum(body) & 0xFF)
    return tag + "".join("%02X" % b for b in body + [cs])


def emit_hex(rows_of):
    lines, active = [], None
    for start, end in sorted(RANGES):
        for row_start, row_end in rows_of(start, end):
            upper = (row_start >> 16) & 0xFFFF
            if upper != active:
                lines.append(hex_record(0x04, 0, [upper >> 8, upper & 0xFF]))
                active = upper
            lines.append(hex_record(0x00, row_start & 0xFFFF,
                                    [IMAGE[a] for a in range(row_start, row_end)]))
    lines.append(hex_record(0x01, 0, []))
    return lines


def rows_base(start, end):  # the base loop: 16-byte rows from the range start
    for row_start in range(start, end, ROW):
        yield row_start, min(row_start + ROW, end)


def rows_fixed(start, end):  # each row ends at or before the next 64 KiB boundary
    row_start = start
    while row_start < end:
        row_end = min(row_start + ROW, end, (row_start | 0xFFFF) + 1)
        yield row_start, row_end
        row_start = row_end


def decode_hex(lines):
    mem, upper, crossing = {}, 0, 0
    for ln in lines:
        raw = bytes.fromhex(ln[1:])
        assert sum(raw) & 0xFF == 0, "bad checksum: " + ln
        n, off, rtype, data = raw[0], (raw[1] << 8) | raw[2], raw[3], raw[4:-1]
        assert len(data) == n, "bad length: " + ln
        if rtype == 0x04:
            upper = (data[0] << 8) | data[1]
        elif rtype == 0x00:
            if off + n > 0x10000:
                crossing += 1
            for i, b in enumerate(data):  # linear, as the system's reader (no wrap)
                mem[(upper << 16) + off + i] = b
    return mem, crossing


def decode_s19(lines):
    mem = {}
    for ln in lines:
        raw = bytes.fromhex(ln[2:])
        assert (sum(raw[:-1]) + raw[-1]) & 0xFF == 0xFF, "bad checksum: " + ln
        if ln[:2] in ("S1", "S2", "S3"):
            alen = {"S1": 2, "S2": 3, "S3": 4}[ln[:2]]
            addr = int.from_bytes(raw[1:1 + alen], "big")
            for i, b in enumerate(raw[1 + alen:-1]):
                mem[addr + i] = b
    return mem


def main():
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent
    s19 = [s_record("S0", 0, 2, b"X64U"),
           s_record("S2", START, 3, DATA[:16]),
           s_record("S2", START + 16, 3, DATA[16:]),
           s_record("S8", 0, 3, [])]
    fixed = emit_hex(rows_fixed)
    base = emit_hex(rows_base)
    files = {"x64u.s19": s19, "x64u.hex": fixed, "x64u-base-emitter.hex": base}
    for name, lines in files.items():
        (out / name).write_text("\n".join(lines) + "\n", encoding="ascii", newline="\n")
        print("== %s" % name)
        for ln in lines:
            print(ln)
    m_fixed, c_fixed = decode_hex(fixed)
    m_base, c_base = decode_hex(base)
    m_s19 = decode_s19(s19)
    checks = [
        ("x64u.hex: data records crossing 0x10000", c_fixed, 0),
        ("x64u-base-emitter.hex: data records crossing 0x10000", c_base, 1),
        ("x64u.hex decodes to the image", m_fixed == IMAGE, True),
        ("x64u-base-emitter.hex decodes to the image (linear reader)", m_base == IMAGE, True),
        ("x64u.s19 decodes to the image", m_s19 == IMAGE, True),
        ("x64u.hex data records", sum(1 for ln in fixed if ln[7:9] == "00"), 3),
    ]
    bad = 0
    for label, got, want in checks:
        ok = got == want
        bad += not ok
        print("CHECK %-62s got=%s want=%s %s" % (label, got, want, "ok" if ok else "FAIL"))
    print("RESULT", "ok" if not bad else "FAIL (%d)" % bad)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
