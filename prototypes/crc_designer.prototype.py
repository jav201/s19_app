#!/usr/bin/env python3
"""
CRC Algorithm Designer — runnable prototype (throwaway, batch-52 design pass).

Purpose: prove the *state + business logic* of the designer before committing to
the real engine + view. The centrepiece is LIVE KNOWN-ANSWER VERIFICATION — the
thing the operator asked the prototype to prioritise: tweak a knob, instantly see
the CRC of "123456789" and whether it matches the variant's reference `check`.

What this validates (and what the /dev-flow implementation must preserve):
  1. A WIDTH-GENERAL parametric CRC (8/16/32/64) reproduces the public catalogue
     check values — replacing today's 32-bit-only crc32_stream.
  2. The SEED template (CRC-32/ISO-HDLC) equals zlib.crc32 byte-for-byte
     (AT-CRC-DSN-010) — the "first template = current implementation" test.
  3. The two firmware extras — gap_policy (skip|fill) and store_endianness
     (little|big) — behave as specified (AT-CRC-DSN-013 / -014).

Run it:
    python prototypes/crc_designer.prototype.py            # KAT table + demos
    python prototypes/crc_designer.prototype.py --repl     # tweak knobs live

NOT production code. The real engine lands in operations/crc.py (non-frozen).
"""
from __future__ import annotations

import sys
import zlib
from dataclasses import dataclass, replace

# Windows consoles default to cp1252 — make the tick/box glyphs safe everywhere.
try:
    sys.stdout.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass


# ─────────────────────────────────────────────────────────────────────────────
# The width-general engine (the E1 rewrite, in miniature)
# ─────────────────────────────────────────────────────────────────────────────
def reflect(value: int, width: int) -> int:
    """Reverse the low `width` bits of `value`."""
    r = 0
    for _ in range(width):
        r = (r << 1) | (value & 1)
        value >>= 1
    return r


def crc_stream(
    data: bytes,
    *,
    width: int,
    poly: int,
    init: int,
    refin: bool,
    refout: bool,
    xorout: int,
) -> int:
    """
    Table-less bitwise parametric CRC for any width in 8..64 (the Rocksoft model).
    refin / refout are INDEPENDENT (today's engine couples them under one `reverse`).
    """
    if width < 8:
        raise ValueError("v1 prototype targets width >= 8 (8/16/32/64)")
    mask = (1 << width) - 1
    topbit = 1 << (width - 1)
    reg = init & mask
    for byte in data:
        if refin:
            byte = reflect(byte, 8)
        reg ^= (byte << (width - 8)) & mask
        for _ in range(8):
            if reg & topbit:
                reg = ((reg << 1) ^ poly) & mask
            else:
                reg = (reg << 1) & mask
    if refout:
        reg = reflect(reg, width)
    return (reg ^ xorout) & mask


# ─────────────────────────────────────────────────────────────────────────────
# The template model (§3-§4 of the requirements)
# ─────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class CrcTemplate:
    name: str
    width: int
    poly: int
    init: int
    refin: bool
    refout: bool
    xorout: int
    check: int                       # expected CRC of "123456789"
    gap_policy: str = "skip"         # "skip" | "fill"
    pad_byte: int = 0xFF
    store_width: int = 0             # 0 → ceil(width/8)
    store_endianness: str = "little"  # "little" | "big"

    def store_bytes(self) -> int:
        return self.store_width or ((self.width + 7) // 8)

    def compute(self, data: bytes) -> int:
        return crc_stream(
            data, width=self.width, poly=self.poly, init=self.init,
            refin=self.refin, refout=self.refout, xorout=self.xorout,
        )

    def kat(self) -> int:
        return self.compute(b"123456789")

    def kat_ok(self) -> bool:
        return self.kat() == self.check


# The seed preset library (§5). Each `check` is the published catalogue value.
PRESETS: list[CrcTemplate] = [
    CrcTemplate("CRC-8/SMBUS",        8,  0x07,               0x00,               False, False, 0x00,               0xF4),
    CrcTemplate("CRC-16/CCITT-FALSE", 16, 0x1021,             0xFFFF,             False, False, 0x0000,             0x29B1),
    CrcTemplate("CRC-16/MODBUS",      16, 0x8005,             0xFFFF,             True,  True,  0x0000,             0x4B37),
    CrcTemplate("CRC-16/XMODEM",      16, 0x1021,             0x0000,             False, False, 0x0000,             0x31C3),
    # The SEED — today's zlib CRC-32, expressed as a template (AT-CRC-DSN-010):
    CrcTemplate("CRC-32/ISO-HDLC",    32, 0x04C11DB7,         0xFFFFFFFF,         True,  True,  0xFFFFFFFF,         0xCBF43926),
    CrcTemplate("CRC-32C/Castagnoli", 32, 0x1EDC6F41,         0xFFFFFFFF,         True,  True,  0xFFFFFFFF,         0xE3069283),
    CrcTemplate("CRC-64/XZ",          64, 0x42F0E1EBA9EA3693, 0xFFFFFFFFFFFFFFFF, True,  True,  0xFFFFFFFFFFFFFFFF, 0x995DC9BBDF1939FA),
]


# ─────────────────────────────────────────────────────────────────────────────
# The two firmware extras (serialization policy)
# ─────────────────────────────────────────────────────────────────────────────
def gather_window(mem: dict[int, int], start: int, end: int, tmpl: CrcTemplate) -> bytes:
    """
    Materialise [start, end) under the template's gap policy.
      skip → present bytes only, in ascending order (today's behaviour).
      fill → every address; absent ones take pad_byte (erased-flash CRC).
    """
    if tmpl.gap_policy == "fill":
        return bytes(mem.get(a, tmpl.pad_byte) for a in range(start, end))
    return bytes(mem[a] for a in range(start, end) if a in mem)


def gather_target(
    mem: dict[int, int],
    ranges: list[tuple[int, int]],
    tmpl: CrcTemplate,
    join: str = "concat",
) -> bytes:
    """
    MULTI-RANGE coverage — the flexibility knob the operator asked for.

    Two independent gap levels, per CRC target:
      intra-range (tmpl.gap_policy): holes INSIDE a range → skip present-only
                                     or fill with pad_byte.
      inter-range (join):            space BETWEEN consecutive ranges →
        "concat" = butt the present ranges together (today's group behaviour);
        "fill"   = pad [prev_end, next_start) with pad_byte so the digest sees
                   one contiguous window across the ranges (erased-flash CRC of
                   a whole region that spans several mapped blocks).

    Ranges are digested in DECLARED ORDER — never address-sorted (parity with
    the existing group contract, S-2).
    """
    segments: list[bytes] = []
    prev_end: int | None = None
    for start, end in ranges:
        if join == "fill" and prev_end is not None and start > prev_end:
            segments.append(bytes([tmpl.pad_byte]) * (start - prev_end))
        segments.append(gather_window(mem, start, end, tmpl))
        prev_end = end
    return b"".join(segments)


def gap_conflict(
    mem: dict[int, int],
    ranges: list[tuple[int, int]],
    tmpl: CrcTemplate,
    join: str = "concat",
) -> list[int]:
    """
    Safety gate (observation #2): return the addresses that VIOLATE the
    coverage's emptiness assumption — real data sitting where the operator
    promised an erased/pad gap.

    For join="fill", the inter-range span [prev_end, next_start) is padded with
    pad_byte WITHOUT consulting the image. If any of those addresses is actually
    present AND differs from pad_byte, the previewed CRC will silently diverge
    from what the device computes over real flash. An industrial tool must not
    fill blindly — it flags (and, on the write path, aborts).
    """
    conflicts: list[int] = []
    prev_end: int | None = None
    for start, end in ranges:
        if join == "fill" and prev_end is not None and start > prev_end:
            for addr in range(prev_end, start):
                if addr in mem and mem[addr] != tmpl.pad_byte:
                    conflicts.append(addr)
        prev_end = end
    return conflicts


def store_word(value: int, tmpl: CrcTemplate) -> bytes:
    n = tmpl.store_bytes()
    return (value & ((1 << (8 * n)) - 1)).to_bytes(n, tmpl.store_endianness)


# ─────────────────────────────────────────────────────────────────────────────
# Rendering — the live known-answer verdict (prototype centrepiece)
# ─────────────────────────────────────────────────────────────────────────────
def verdict_line(tmpl: CrcTemplate) -> str:
    got = tmpl.kat()
    hexw = tmpl.store_bytes() * 2
    if tmpl.kat_ok():
        mark = "✓ MATCH"
    else:
        mark = f"✗ MISMATCH (expected 0x{tmpl.check:0{hexw}X})"
    return f"check('123456789') = 0x{got:0{hexw}X}   {mark}"


def print_kat_table() -> bool:
    print("=" * 72)
    print("  KNOWN-ANSWER TABLE  —  engine vs published catalogue check value")
    print("=" * 72)
    all_ok = True
    for t in PRESETS:
        ok = t.kat_ok()
        all_ok &= ok
        hexw = t.store_bytes() * 2
        print(f"  {'OK ' if ok else 'BAD'}  {t.name:<20} w={t.width:<2}  "
              f"got=0x{t.kat():0{hexw}X}  want=0x{t.check:0{hexw}X}")
    print("-" * 72)
    # AT-CRC-DSN-010: the seed template must equal zlib.crc32.
    seed = next(t for t in PRESETS if t.name == "CRC-32/ISO-HDLC")
    for sample in (b"123456789", b"", b"The quick brown fox", bytes(range(256))):
        assert seed.compute(sample) == zlib.crc32(sample) & 0xFFFFFFFF, sample
    print("  AT-CRC-DSN-010  seed CRC-32/ISO-HDLC == zlib.crc32   ✓ (4 vectors)")
    print(f"  KAT TABLE: {'ALL PASS ✓' if all_ok else 'FAILURES ✗'}")
    return all_ok


def demo_gap_and_endian() -> None:
    print()
    print("=" * 72)
    print("  FIRMWARE EXTRAS  —  gap_policy (skip|fill) & store_endianness")
    print("=" * 72)
    # A sparse window: 0x00..0x07 present, 0x08..0x0F absent (erased flash).
    mem = {a: a for a in range(0x08)}
    base = next(t for t in PRESETS if t.name == "CRC-32/ISO-HDLC")
    skip = replace(base, gap_policy="skip")
    fill = replace(base, gap_policy="fill", pad_byte=0xFF)
    win_skip = gather_window(mem, 0x00, 0x10, skip)
    win_fill = gather_window(mem, 0x00, 0x10, fill)
    print(f"  window [0x00,0x10)  8 present + 8 erased")
    print(f"   skip  -> {len(win_skip):>2} bytes  crc=0x{skip.compute(win_skip):08X}")
    print(f"   fill  -> {len(win_fill):>2} bytes  crc=0x{fill.compute(win_fill):08X}  (covers 0xFF pad)")
    crc = 0x04030201
    le = replace(base, store_endianness="little")
    be = replace(base, store_endianness="big")
    print(f"  store 0x{crc:08X}:  little={store_word(crc, le).hex(' ')}   "
          f"big={store_word(crc, be).hex(' ')}")


def demo_multirange() -> None:
    print()
    print("=" * 72)
    print("  MULTI-RANGE COVERAGE  —  intra gap (skip|fill) x inter gap (concat|fill)")
    print("=" * 72)
    # Two mapped blocks with an 8-byte erased gap between them:
    #   range1 [0x8000,0x8008) present 0x00..0x07
    #   <gap>  [0x8008,0x8010) erased
    #   range2 [0x8010,0x8018) present 0x10..0x17
    mem = {0x8000 + i: i for i in range(8)}
    mem.update({0x8010 + i: 0x10 + i for i in range(8)})
    ranges = [(0x8000, 0x8008), (0x8010, 0x8018)]
    base = next(t for t in PRESETS if t.name == "CRC-32/ISO-HDLC")
    skip = replace(base, gap_policy="skip")
    fill = replace(base, gap_policy="fill", pad_byte=0xFF)
    print("  ranges: 0x8000-0x8008 , 0x8010-0x8018   (8-byte erased gap between)")
    combos = [
        ("intra=skip  inter=concat", skip, "concat"),
        ("intra=skip  inter=fill  ", skip, "fill"),
        ("intra=fill  inter=fill  ", fill, "fill"),
    ]
    for label, tmpl, join in combos:
        window = gather_target(mem, ranges, tmpl, join=join)
        print(f"   {label} -> {len(window):>2} B  crc=0x{tmpl.compute(window):08X}")
    print("  (concat = butt present bytes; fill = pad the between-range gap 0xFF)")


def demo_gap_conflict() -> None:
    print()
    print("=" * 72)
    print("  GAP SAFETY (obs #2)  —  on_gap_conflict: abort if a filled gap holds data")
    print("=" * 72)
    base = next(t for t in PRESETS if t.name == "CRC-32/ISO-HDLC")
    fill = replace(base, gap_policy="skip", pad_byte=0xFF)  # intra skip, join fill below
    ranges = [(0x8000, 0x8008), (0x8010, 0x8018)]
    clean = {0x8000 + i: i for i in range(8)}
    clean.update({0x8010 + i: 0x10 + i for i in range(8)})
    dirty = dict(clean)
    dirty[0x800A] = 0x99  # a stray real byte inside the "erased" gap
    print("  join=fill over 0x8008–0x8010 (promised erased 0xFF):")
    print(f"   clean gap -> conflicts={gap_conflict(clean, ranges, fill, 'fill')}  -> OK, fill safe")
    hits = gap_conflict(dirty, ranges, fill, "fill")
    print(f"   dirty gap -> conflicts={[hex(a) for a in hits]}  -> ABORT (real data at 0x{hits[0]:X}=0x99)")
    print("  without this gate the previewed CRC would silently diverge from the device.")


# ─────────────────────────────────────────────────────────────────────────────
# Optional REPL — feel the "live verify" the real view will give (R-CRC-DSN-002)
# ─────────────────────────────────────────────────────────────────────────────
def repl() -> None:
    t = next(x for x in PRESETS if x.name == "CRC-32/ISO-HDLC")
    print("CRC Designer REPL — edit a field, see the check verdict update.")
    print("fields: name width poly init refin refout xorout gap pad endian")
    print("commands: <field> <value> | preset <name> | vec <ascii> | list | quit\n")
    while True:
        print(f"  [{t.name}] w={t.width} poly=0x{t.poly:X} init=0x{t.init:X} "
              f"refin={t.refin} refout={t.refout} xorout=0x{t.xorout:X} "
              f"gap={t.gap_policy} endian={t.store_endianness}")
        print("  " + verdict_line(t))
        try:
            raw = input("  > ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if not raw:
            continue
        parts = raw.split(maxsplit=1)
        cmd = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""
        if cmd in ("quit", "q"):
            return
        if cmd == "list":
            for p in PRESETS:
                print(f"     {p.name}")
            continue
        if cmd == "preset":
            match = next((p for p in PRESETS if p.name.lower() == arg.lower()), None)
            t = match if match else t
            continue
        if cmd == "vec":
            print(f"     crc('{arg}') = 0x{t.compute(arg.encode()):X}")
            continue
        try:
            if cmd == "width":
                t = replace(t, width=int(arg))
            elif cmd == "poly":
                t = replace(t, poly=int(arg, 0))
            elif cmd == "init":
                t = replace(t, init=int(arg, 0))
            elif cmd == "xorout":
                t = replace(t, xorout=int(arg, 0))
            elif cmd == "refin":
                t = replace(t, refin=arg.lower() in ("1", "true", "yes", "y"))
            elif cmd == "refout":
                t = replace(t, refout=arg.lower() in ("1", "true", "yes", "y"))
            elif cmd == "gap":
                t = replace(t, gap_policy=arg)
            elif cmd == "pad":
                t = replace(t, pad_byte=int(arg, 0))
            elif cmd == "endian":
                t = replace(t, store_endianness=arg)
            elif cmd == "name":
                t = replace(t, name=arg)
            else:
                print("     ? unknown field")
        except ValueError as exc:
            print(f"     ! {exc}")


if __name__ == "__main__":
    if "--repl" in sys.argv:
        repl()
    else:
        ok = print_kat_table()
        demo_gap_and_endian()
        demo_multirange()
        demo_gap_conflict()
        sys.exit(0 if ok else 1)
