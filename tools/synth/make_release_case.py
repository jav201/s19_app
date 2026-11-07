#!/usr/bin/env python3
"""Deterministic generator of a synthetic, VALID release-demo case for s19_app.

Builds a self-consistent set of firmware images (Motorola S19 + Intel HEX),
an ASAP2 description (A2L), a MAC address list, and two change documents whose
every byte is generated locally (no firmware, no downloads, no names, no PKI).

Usage:
    python tools/synth/make_release_case.py --out <dir> [--seed N] [--size-mb 10]

The same ``--seed`` reproduces byte-identical files. Standard library only.

Memory image layout (four regions separated by gaps, addresses ascending):

    boot    0x00000000   pseudo-code + ASCII banner + entry point
    app     0x00040000   pseudo-code with 0xFF erased pages and 0x00 runs
    cal     0x00800000   structured numeric tables (calibration objects live here)
    config  0x00C00000   ASCII ID / version block

A2L objects (CHARACTERISTIC / MEASUREMENT) are placed inside those regions and
their raw bytes are OVERLAID on the generic region fill so the app's decoder
round-trips each object to a physical value inside its declared limits.
"""

from __future__ import annotations

import argparse
import json
import math
import random
import struct
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Public contract constants (imported by tests/test_synth_release_case.py).
# ---------------------------------------------------------------------------

S19_BYTES_PER_LINE = 32

BOOT_BASE = 0x00000000
APP_BASE = 0x00040000
CAL_BASE = 0x00800000
CONFIG_BASE = 0x00C00000

BOOT_SIZE = 0x10000        # 64 KB
CONFIG_SIZE = 0x1000       # 4 KB
MIN_CAL_SIZE = 0x20000     # 128 KB floor for the object inventory
MIN_APP_SIZE = 0x30000     # 192 KB floor for the object inventory

#: firmware_v2 deltas vs firmware: a changed window inside the calibration
#: region plus an extension appended to the calibration region's end.
CHANGE_WINDOW_BYTES = 512
EXTENSION_BYTES = 4096
CHANGE_XOR = 0xA5

S0_HEADER = b"S19TOOL_RELEASE_DEMO"
PROJECT_NAME = "SYNTH_RELEASE_DEMO"
MODULE_NAME = "ECU_DEMO"
MAC_LINE_COUNT = 200

#: ASAP2 datatypes the app decodes (mirrors s19_app.tui.a2l.DATATYPE_SIZES /
#: DATATYPE_STRUCT_CODES). ``code`` is the stdlib struct pack/unpack char.
DATATYPE_META = {
    "UBYTE": {"size": 1, "code": "B", "umin": 0, "umax": 255, "float": False},
    "UWORD": {"size": 2, "code": "H", "umin": 0, "umax": 65535, "float": False},
    "ULONG": {"size": 4, "code": "I", "umin": 0, "umax": 0xFFFFFFFF, "float": False},
    "SWORD": {"size": 2, "code": "h", "umin": -32768, "umax": 32767, "float": False},
    "SLONG": {"size": 4, "code": "i", "umin": -0x80000000, "umax": 0x7FFFFFFF, "float": False},
    "FLOAT32_IEEE": {"size": 4, "code": "f", "umin": 0, "umax": 0, "float": True},
}

#: Every COMPU_METHOD kind the app's decoder handles (IDENTICAL, LINEAR,
#: RAT_FUNC, TAB_INTP, TAB_NOINTP). TAB_VERB is expressed as the COMPU_VTAB
#: table kind, exactly as the app's ``extract_compu_tables`` reads it.
CONVERSION_ORDER = [
    "CM_IDENT",
    "CM_LIN_10",
    "CM_LIN_OFF",
    "CM_RAT",
    "CM_TAB_INTP",
    "CM_TAB_NOINTP",
]

CONVERSIONS = {
    "CM_IDENT": {"kind": "IDENTICAL"},
    "CM_LIN_10": {"kind": "LINEAR", "a": 10, "b": 0},
    "CM_LIN_OFF": {"kind": "LINEAR", "a": 1, "b": 100},
    "CM_RAT": {"kind": "RAT_FUNC"},
    "CM_TAB_INTP": {"kind": "TAB_INTP", "table": "TBL_INTP"},
    "CM_TAB_NOINTP": {"kind": "TAB_NOINTP", "table": "TBL_NOINTP"},
}

ALLOWED_DATATYPES = {
    "CM_IDENT": ["UBYTE", "UWORD", "ULONG", "SWORD", "SLONG", "FLOAT32_IEEE"],
    "CM_LIN_10": ["UBYTE", "UWORD", "ULONG", "SWORD", "FLOAT32_IEEE"],
    "CM_LIN_OFF": ["UBYTE", "UWORD", "ULONG", "SWORD", "FLOAT32_IEEE"],
    "CM_RAT": ["UWORD", "ULONG", "SWORD", "SLONG"],
    "CM_TAB_INTP": ["UWORD", "ULONG", "SWORD", "SLONG"],
    "CM_TAB_NOINTP": ["UBYTE", "UWORD", "ULONG", "SWORD"],
}

TABLES = {
    "TBL_INTP": [(0, 0.0), (100, 10.0), (200, 20.0), (300, 30.0), (400, 40.0)],
    "TBL_NOINTP": [(0, 0.0), (1, 5.0), (2, 10.0), (3, 15.0), (4, 20.0)],
}

#: RECORD_LAYOUT name per datatype (used as a CHARACTERISTIC's ``deposit``).
RECORD_LAYOUT_NAMES = {
    "UBYTE": "RL_U8",
    "UWORD": "RL_U16",
    "ULONG": "RL_U32",
    "SWORD": "RL_S16",
    "SLONG": "RL_S32",
    "FLOAT32_IEEE": "RL_F32",
}

#: Fixed datatypes for the array/block CHARACTERISTIC kinds.
CURVE_DATATYPE = "UWORD"
MAP_DATATYPE = "UWORD"
VALBLK_DATATYPE = "UWORD"
ASCII_DATATYPE = "UBYTE"

CURVE_POINTS = 32
MAP_X_POINTS = 8
MAP_Y_POINTS = 8
VALBLK_LENGTH = 256
ASCII_LENGTH = 32


# ---------------------------------------------------------------------------
# Region sizing.
# ---------------------------------------------------------------------------

def compute_region_sizes(size_mb: float) -> dict[str, tuple[int, int]]:
    """Return ``{name: (base, size)}`` for the four regions.

    The total data byte budget is derived so the emitted S19 text lands close
    to ``size_mb`` MiB: an S3 record carrying 32 data bytes serializes to 79
    bytes (78 + newline), so data ≈ target × 32 / 79.
    """
    target_data = int(size_mb * 1024 * 1024 * S19_BYTES_PER_LINE / (S19_BYTES_PER_LINE * 2 + 15))
    fixed = BOOT_SIZE + CONFIG_SIZE
    remaining = max(MIN_CAL_SIZE + MIN_APP_SIZE, target_data - fixed)
    cal = max(MIN_CAL_SIZE, _round32(int(remaining * 0.30)))
    app = max(MIN_APP_SIZE, _round32(remaining - cal))
    return {
        "boot": (BOOT_BASE, BOOT_SIZE),
        "app": (APP_BASE, app),
        "cal": (CAL_BASE, cal),
        "config": (CONFIG_BASE, CONFIG_SIZE),
    }


def _round32(value: int) -> int:
    return (value // 32) * 32


def _region_len(size) -> int:
    return size if isinstance(size, int) else len(size)


def compute_change_window(regions: dict[str, tuple[int, int]]) -> tuple[int, int]:
    """Start address of the firmware_v2 changed window (inside ``cal``)."""
    base, size = regions["cal"]
    start = base + _region_len(size) - (_region_len(size) // 4)
    return _align4(start), CHANGE_WINDOW_BYTES


def compute_extension(regions: dict[str, tuple[int, int]]) -> tuple[int, int]:
    """Start address of the firmware_v2 extended tail (just past ``cal``)."""
    base, size = regions["cal"]
    return base + _region_len(size), EXTENSION_BYTES


def _align4(value: int) -> int:
    return (value + 3) // 4 * 4


# ---------------------------------------------------------------------------
# Region content fill (deterministic, seeded).
# ---------------------------------------------------------------------------

def _fill_pseudocode(buf: bytearray, rng: random.Random) -> None:
    """Low/mid-entropy pseudo-code: opcode-ish bytes + periodic structure."""
    n = len(buf)
    i = 0
    while i < n:
        # A 16-byte "cache line" with a header word and operand bytes.
        line_len = min(16, n - i)
        buf[i] = rng.choice([0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,
                             0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0])
        for j in range(1, line_len):
            buf[i + j] = rng.randint(0, 255)
        i += line_len


def _fill_calibration_tables(buf: bytearray, rng: random.Random) -> None:
    """Structured numeric tables: ramps, sines, and sawtooths of UWORDs."""
    n = len(buf)
    i = 0
    ramp = 0
    while i + 1 < n:
        # Deterministic little blocks of structured 16-bit values.
        mode = (i // 256) % 3
        if mode == 0:
            value = ramp & 0xFFFF
            ramp += 3
        elif mode == 1:
            value = int((math.sin(i / 32.0) * 0.5 + 0.5) * 65535) & 0xFFFF
        else:
            value = (65535 - (i % 65536)) & 0xFFFF
        buf[i] = value & 0xFF
        buf[i + 1] = (value >> 8) & 0xFF
        i += 2
    if i < n:
        buf[i] = 0xFF


def _fill_erased(buf: bytearray, rng: random.Random) -> None:
    for i in range(len(buf)):
        buf[i] = 0xFF


def _fill_zero(buf: bytearray, rng: random.Random) -> None:
    for i in range(len(buf)):
        buf[i] = 0x00


def _fill_config(buf: bytearray, rng: random.Random) -> None:
    """ASCII ID / version block plus a small config word table."""
    text = (
        b"S19TOOL_RELEASE_DEMO\x00"
        b"FW_VERSION=01.02.03.04\x00"
        b"BUILD_ID=SYNTH_0001\x00"
        b"SERIAL=00000000\x00"
    )
    for i, b in enumerate(text):
        if i < len(buf):
            buf[i] = b
    for i in range(len(text), len(buf)):
        buf[i] = 0xFF


def _fill_boot(buf: bytearray, rng: random.Random) -> None:
    banner = b"S19TOOL BOOT v1.0\x00"
    for i, b in enumerate(banner):
        if i < len(buf):
            buf[i] = b
    _fill_pseudocode(buf[len(banner):], rng)


REGION_FILLERS = {
    "boot": _fill_boot,
    "app": _fill_pseudocode,
    "cal": _fill_calibration_tables,
    "config": _fill_config,
}


# ---------------------------------------------------------------------------
# Object value planning (raw bytes <-> physical value, per conversion kind).
# ---------------------------------------------------------------------------

def _pack_scalar(datatype: str, raw: int, big_endian: bool) -> bytes:
    meta = DATATYPE_META[datatype]
    if meta["float"]:
        return struct.pack((">" if big_endian else "<") + meta["code"], float(raw))
    return struct.pack((">" if big_endian else "<") + meta["code"], int(raw))


def _pack_u16s(values: list[int], big_endian: bool) -> bytes:
    code = ">" if big_endian else "<"
    return b"".join(struct.pack(code + "H", v & 0xFFFF) for v in values)


def _int_limit_strings(physical: float) -> tuple[str, str]:
    p = int(round(physical))
    margin = max(100, abs(p) // 2)
    low = min(p, 0) - margin
    high = max(p, 0) + margin
    return str(low), str(high)


def _float_limit_strings(physical: float) -> tuple[str, str]:
    margin = max(10.0, abs(physical) * 0.5)
    return f"{physical - margin:.3f}", f"{physical + margin:.3f}"


def _datatype_domain(datatype: str) -> tuple[str, str]:
    """Natural physical domain per datatype (for IDENTICAL conversions)."""
    domains = {
        "UBYTE": ("0", "255"),
        "UWORD": ("0", "65535"),
        "ULONG": ("0", "4294967295"),
        "SWORD": ("-32768", "32767"),
        "SLONG": ("-2147483648", "2147483647"),
        "FLOAT32_IEEE": ("0.0", "100.0"),
    }
    return domains[datatype]


def _scalar_value(datatype: str, conv_name: str, big_endian: bool, rng: random.Random) -> dict:
    """Plan one scalar (VALUE / MEASUREMENT) object.

    Returns ``{bytes, physical, low, high, length}`` where ``bytes`` is the
    on-image run (already byte-order encoded) and ``physical`` is the value the
    app decodes — guaranteed inside ``[low, high]``.
    """
    meta = DATATYPE_META[datatype]
    size = meta["size"]
    conv = CONVERSIONS[conv_name]
    kind = conv["kind"]

    if meta["float"]:
        f = rng.uniform(5.0, 95.0)
        if kind == "LINEAR":
            physical = conv["a"] * f + conv["b"]
        else:  # FLOAT32 is only paired with IDENTICAL / LINEAR here
            physical = f
        raw_bytes = _pack_scalar(datatype, f, big_endian)
        low, high = _float_limit_strings(physical)
        return {"bytes": raw_bytes, "physical": physical, "low": low, "high": high, "length": size}

    umin, umax = meta["umin"], meta["umax"]
    span = umax - umin
    lo = umin + span // 20
    hi = umax - span // 20

    if kind == "IDENTICAL":
        raw = rng.randint(lo, hi)
        physical = raw
        low, high = _datatype_domain(datatype)
    elif kind == "LINEAR":
        raw = rng.randint(lo, hi)
        physical = conv["a"] * raw + conv["b"]
        low = conv["a"] * umin + conv["b"]
        high = conv["a"] * umax + conv["b"]
        if low > high:
            low, high = high, low
        low, high = str(low), str(high)
    elif kind == "RAT_FUNC":
        # raw = (physical + 50) / 2  (COEFFS 0 1 50 0 0 2); decode inverts exactly.
        physical = rng.randrange(20, 1981, 2)
        raw = (physical + 50) // 2
        low, high = "0", "2000"
    else:  # TAB_INTP / TAB_NOINTP
        pairs = TABLES[conv["table"]]
        keys = [p[0] for p in pairs]
        raw = rng.choice(keys)
        physical = dict(pairs)[raw]
        low = "0"
        high = str(int(max(p[1] for p in pairs)) + 10)

    raw_bytes = _pack_scalar(datatype, raw, big_endian)
    return {"bytes": raw_bytes, "physical": physical, "low": low, "high": high, "length": size}


def _array_value(kind: str, big_endian: bool, rng: random.Random) -> dict:
    """Plan one CURVE / MAP / VAL_BLK / ASCII object (array of values)."""
    if kind == "ASCII":
        strings = [
            b"S19TOOL_RELEASE_DEMO",
            b"FW_VERSION=01.02.03.04",
            b"BUILD_ID=SYNTH_0001",
            b"SERIAL=00000000",
            b"HW_REV=00.01.00.00",
            b"MODEL=SYNTH_ECU",
            b"PROD_DATE=SYNTHETIC",
            b"SW_PARTNO=SYNTH-0001",
            b"CFG_CKSUM=00000000",
            b"END_OF_ID_BLOCK",
        ]
        text = rng.choice(strings)
        raw_bytes = (text + b"\x00" * ASCII_LENGTH)[:ASCII_LENGTH]
        physical = raw_bytes[0]
        return {"bytes": raw_bytes, "physical": physical, "low": "0", "high": "255", "length": ASCII_LENGTH}

    base = rng.randint(1000, 64000)
    if kind == "CURVE":
        values = [(base + i * 7) & 0xFFFF for i in range(CURVE_POINTS)]
    elif kind == "MAP":
        values = [(base + i * 11) & 0xFFFF for i in range(MAP_X_POINTS * MAP_Y_POINTS)]
    else:  # VAL_BLK
        values = [(base + i * 5) & 0xFFFF for i in range(VALBLK_LENGTH // 2)]

    raw_bytes = _pack_u16s(values, big_endian)
    return {"bytes": raw_bytes, "physical": values[0], "low": "0", "high": "65535", "length": len(raw_bytes)}


# ---------------------------------------------------------------------------
# Object inventory and placement.
# ---------------------------------------------------------------------------

def build_objects(regions: dict[str, tuple[int, int]], rng: random.Random) -> list[dict]:
    """Build and place every A2L object, overlaying its bytes into ``regions``.

    ``regions`` is mutated in place: each entry becomes ``(base, bytearray)``.
    Returns the object list with assigned ``address`` and every A2L field.
    """
    region_bytes: dict[str, bytearray] = {}
    for name, (base, size) in regions.items():
        buf = bytearray(size)
        REGION_FILLERS[name](buf, rng)
        region_bytes[name] = buf

    # Deterministic spec list: (region, kind, datatype, conversion).
    specs: list[tuple[str, str, str, str]] = []

    def _push_scalars(region: str, count: int, is_meas: bool) -> None:
        for _ in range(count):
            conv = CONVERSION_ORDER[len(specs) % len(CONVERSION_ORDER)]
            dts = ALLOWED_DATATYPES[conv]
            dt = dts[len(specs) % len(dts)]
            specs.append((region, "MEASUREMENT" if is_meas else "VALUE", dt, conv))

    _push_scalars("boot", 4, False)
    _push_scalars("boot", 8, True)
    _push_scalars("app", 180, False)
    _push_scalars("app", 52, True)
    for _ in range(60):
        specs.append(("cal", "VAL_BLK", VALBLK_DATATYPE, "CM_IDENT"))
    for _ in range(60):
        specs.append(("cal", "CURVE", CURVE_DATATYPE, "CM_IDENT"))
    for _ in range(20):
        specs.append(("cal", "MAP", MAP_DATATYPE, "CM_IDENT"))
    _push_scalars("cal", 20, False)
    _push_scalars("cal", 34, True)
    for _ in range(10):
        specs.append(("config", "ASCII", ASCII_DATATYPE, "CM_IDENT"))
    _push_scalars("config", 4, False)
    _push_scalars("config", 10, True)

    cursors = {name: base for name, (base, _size) in regions.items()}
    objects: list[dict] = []
    counter = {"VALUE": 0, "MEASUREMENT": 0, "VAL_BLK": 0, "CURVE": 0, "MAP": 0, "ASCII": 0}
    name_counter = 0

    for spec in specs:
        region, kind, datatype, conv = spec
        base, _size = regions[region]
        size = region_bytes[region]
        big_endian = (name_counter % 2 == 0)

        if kind in ("CURVE", "MAP", "VAL_BLK", "ASCII"):
            value = _array_value(kind, big_endian, rng)
        else:
            value = _scalar_value(datatype, conv, big_endian, rng)

        cur = cursors[region]
        if cur % 4:
            cur = (cur + 3) // 4 * 4
        addr = cur
        length = value["length"]
        if addr + length > base + len(size):
            raise RuntimeError(f"region {region} overflowed at object {name_counter}")

        for offset, byte in enumerate(value["bytes"]):
            size[addr - base + offset] = byte

        counter[kind] += 1
        idx = counter[kind]
        name = f"{kind}_{idx:04d}"
        objects.append({
            "name": name,
            "region": region,
            "section": "MEASUREMENT" if kind == "MEASUREMENT" else "CHARACTERISTIC",
            "kind": kind,
            "datatype": datatype,
            "conversion": conv,
            "address": addr,
            "length": length,
            "big_endian": big_endian,
            "raw_bytes": value["bytes"],
            "physical": value["physical"],
            "low": value["low"],
            "high": value["high"],
        })

        gap = 8 if kind in ("CURVE", "MAP", "VAL_BLK", "ASCII") else 16
        cursors[region] = addr + length + gap
        name_counter += 1

    # Rebuild regions as (base, bytearray) for the emitters.
    for name in list(regions.keys()):
        base, _size = regions[name]
        regions[name] = (base, region_bytes[name])

    return objects


# ---------------------------------------------------------------------------
# S19 / HEX emitters.
# ---------------------------------------------------------------------------

def _s_record(record_type: str, address: int, data: bytes, addr_len: int) -> str:
    byte_count = addr_len + len(data) + 1
    addr_bytes = [(address >> (8 * i)) & 0xFF for i in reversed(range(addr_len))]
    total = byte_count + sum(addr_bytes) + sum(data)
    checksum = (~total) & 0xFF
    addr_text = "".join(f"{b:02X}" for b in addr_bytes)
    data_text = "".join(f"{b:02X}" for b in data)
    return f"{record_type}{byte_count:02X}{addr_text}{data_text}{checksum:02X}"


def _s3_line(address: int, data: bytes) -> str:
    return _s_record("S3", address, data, 4)


def _s0_line(payload: bytes) -> str:
    return _s_record("S0", 0, payload, 2)


def _s7_line(address: int) -> str:
    return _s_record("S7", address, b"", 4)


def _hex_line(record_type: int, address16: int, data: bytes) -> str:
    byte_count = len(data)
    total = (byte_count + ((address16 >> 8) & 0xFF) + (address16 & 0xFF)
             + record_type + sum(data))
    checksum = (-total) & 0xFF
    data_text = "".join(f"{b:02X}" for b in data)
    return f":{byte_count:02X}{address16:04X}{record_type:02X}{data_text}{checksum:02X}"


def _iter_regions(regions: dict[str, tuple[int, bytearray]]):
    for name in ("boot", "app", "cal", "config"):
        yield name, regions[name]


def emit_s19(regions: dict[str, tuple[int, bytearray]], entry_point: int) -> str:
    lines = [_s0_line(S0_HEADER)]
    for _name, (base, buf) in _iter_regions(regions):
        for start in range(0, len(buf), S19_BYTES_PER_LINE):
            chunk = buf[start:start + S19_BYTES_PER_LINE]
            lines.append(_s3_line(base + start, bytes(chunk)))
    lines.append(_s7_line(entry_point))
    return "\n".join(lines) + "\n"


def emit_hex(regions: dict[str, tuple[int, bytearray]]) -> str:
    lines: list[str] = []
    active_upper = None
    for _name, (base, buf) in _iter_regions(regions):
        for start in range(0, len(buf), S19_BYTES_PER_LINE):
            addr = base + start
            upper = (addr >> 16) & 0xFFFF
            if upper != active_upper:
                lines.append(_hex_line(0x04, 0, bytes([upper >> 8, upper & 0xFF])))
                active_upper = upper
            chunk = buf[start:start + S19_BYTES_PER_LINE]
            lines.append(_hex_line(0x00, addr & 0xFFFF, bytes(chunk)))
    lines.append(_hex_line(0x01, 0, b""))
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# A2L / MAC / change-document emitters.
# ---------------------------------------------------------------------------

def _fmt_addr(addr: int) -> str:
    return f"0x{addr:08X}"


def emit_a2l(regions: dict[str, tuple[int, bytearray]], objects: list[dict]) -> str:
    out: list[str] = []
    out.append("ASAP2_VERSION 1 71")
    out.append(f'/begin PROJECT {PROJECT_NAME} "Synthetic release demo project"')
    out.append(f'  /begin MODULE {MODULE_NAME} "Synthetic release demo module"')

    out.append('    /begin MOD_PAR ""')
    out.append('      EPK "S19TOOL_SYNTH_RELEASE_DEMO"')
    out.append("    /end MOD_PAR")

    out.append('    /begin MOD_COMMON ""')
    out.append("      BYTE_ORDER MSB_FIRST")
    out.append("      ALIGNMENT_BYTE 1")
    out.append("      ALIGNMENT_WORD 2")
    out.append("      ALIGNMENT_LONG 4")
    out.append("      ALIGNMENT_FLOAT32_IEEE 4")
    out.append("    /end MOD_COMMON")

    for name, (base, buf) in _iter_regions(regions):
        if name == "boot":
            usage, kind = "CODE", "FLASH"
        elif name == "config":
            usage, kind = "DATA", "FLASH"
        elif name == "cal":
            usage, kind = "DATA", "FLASH"
        else:
            usage, kind = "CODE", "FLASH"
        out.append(f"    /begin MEMORY_SEGMENT {name} {usage} {kind} INTERN {kind} "
                   f"{_fmt_addr(base)} 0x{len(buf):06X}")
        out.append("    /end MEMORY_SEGMENT")

    for dt, layout in RECORD_LAYOUT_NAMES.items():
        out.append(f"    /begin RECORD_LAYOUT {layout}")
        out.append(f"      FNC_VALUES 1 {dt} COLUMN_DIR DIRECT")
        out.append("    /end RECORD_LAYOUT")

    for conv in CONVERSION_ORDER:
        spec = CONVERSIONS[conv]
        kind = spec["kind"]
        out.append(f'    /begin COMPU_METHOD {conv} "synthetic {kind} conversion"')
        if kind == "IDENTICAL":
            out.append('      IDENTICAL "%.0f" "counts"')
            out.append("      COEFFS 0 1 0 0 0 1")
        elif kind == "LINEAR":
            out.append(f'      LINEAR "%.1f" "units"')
            out.append(f"      COEFFS_LINEAR {spec['a']} {spec['b']}")
        elif kind == "RAT_FUNC":
            out.append('      RAT_FUNC "%.1f" "units"')
            out.append("      COEFFS 0 1 50 0 0 2")
        else:
            out.append(f'      {kind} "%.1f" "units"')
            out.append(f"      COMPU_TAB_REF {spec['table']}")
        out.append("    /end COMPU_METHOD")

    out.append('    /begin COMPU_TAB TBL_INTP "interpolated demo table"')
    for x, y in TABLES["TBL_INTP"]:
        out.append(f"      {x} {y:g}")
    out.append("    /end COMPU_TAB")

    out.append('    /begin COMPU_VTAB TBL_NOINTP "non-interpolated demo table"')
    out.append(f"      TAB_VERB {len(TABLES['TBL_NOINTP'])}")
    for x, y in TABLES["TBL_NOINTP"]:
        out.append(f"      {x} {y:g}")
    out.append("    /end COMPU_VTAB")

    for obj in objects:
        name = obj["name"]
        kind = obj["kind"]
        addr = _fmt_addr(obj["address"])
        bo = "MSB_FIRST" if obj["big_endian"] else "LITTLE_ENDIAN"
        low, high = obj["low"], obj["high"]
        if obj["section"] == "MEASUREMENT":
            out.append(f'    /begin MEASUREMENT {name} "synthetic measurement"')
            out.append(f"      {obj['datatype']} {obj['conversion']} 1 0 {low} {high}")
            out.append(f"      ECU_ADDRESS {addr}")
            out.append(f"      BYTE_ORDER {bo}")
            out.append('      UNIT "units"')
            out.append("      READ_ONLY")
            out.append("    /end MEASUREMENT")
            continue

        deposit = RECORD_LAYOUT_NAMES[obj["datatype"]]
        out.append(f'    /begin CHARACTERISTIC {name} "synthetic demo characteristic"')
        out.append(f"      {kind} {addr} {deposit} 0 {obj['conversion']} {low} {high}")
        out.append(f"      BYTE_ORDER {bo}")
        if kind == "VAL_BLK":
            out.append(f"      LENGTH {VALBLK_LENGTH}")
        elif kind == "ASCII":
            out.append(f"      NUMBER {ASCII_LENGTH}")
        elif kind == "CURVE":
            out.append("      /begin AXIS_DESCR")
            out.append(f"        STD_AXIS NO_INPUT NO_COMPU_METHOD {CURVE_POINTS} 0 65535")
            out.append("      /end AXIS_DESCR")
        elif kind == "MAP":
            out.append("      /begin AXIS_DESCR")
            out.append(f"        STD_AXIS NO_INPUT NO_COMPU_METHOD {MAP_X_POINTS} 0 65535")
            out.append("      /end AXIS_DESCR")
            out.append("      /begin AXIS_DESCR")
            out.append(f"        STD_AXIS NO_INPUT NO_COMPU_METHOD {MAP_Y_POINTS} 0 65535")
            out.append("      /end AXIS_DESCR")
        out.append("    /end CHARACTERISTIC")

    out.append("  /end MODULE")
    out.append("/end PROJECT")
    return "\n".join(out) + "\n"


def emit_mac(objects: list[dict]) -> str:
    # A deterministic subset of the A2L objects, names matching A2L exactly.
    chosen = objects[:MAC_LINE_COUNT]
    lines = ["# Synthetic MAC address list (subset of the A2L objects)"]
    for obj in chosen:
        lines.append(f"{obj['name']}={_fmt_addr(obj['address'])}")
    return "\n".join(lines) + "\n"


def _hex_bytes(data: bytes) -> str:
    """Render raw bytes as the strict wire-grammar hex token list (C-1)."""
    return " ".join(f"{b:02X}" for b in data)


def _xored_run(buf: bytearray, offset: int, length: int) -> bytes:
    """The region's bytes at ``offset`` with every bit flipped.

    Derived from the clean image so a change/check entry's bytes are
    guaranteed to differ from the before bytes at any seed or size.
    """
    return bytes(b ^ 0xFF for b in buf[offset:offset + length])


def _erased_run_offset(buf: bytearray, length: int) -> int:
    """First offset of a ``length``-byte 0xFF run (config erased-flash zone)."""
    idx = buf.find(bytes([0xFF]) * length)
    if idx < 0:
        raise RuntimeError(f"no {length}-byte 0xFF run in region")
    return idx


def _pick_symbol_target(objects: list[dict], region: str, section: str) -> dict:
    """Return the first integer-datatype IDENTICAL scalar in ``region``.

    A change-5 symbol entry must address a scalar whose raw bytes equal its
    physical value (IDENTICAL), so a changed value maps 1:1 to changed bytes
    without floating-point rounding. FLOAT32_IEEE is excluded on purpose.
    """
    for obj in objects:
        if obj.get("region") != region or obj["section"] != section:
            continue
        if obj["kind"] not in ("VALUE", "MEASUREMENT"):
            continue
        if obj["conversion"] != "CM_IDENT":
            continue
        if DATATYPE_META[obj["datatype"]]["float"]:
            continue
        return obj
    raise RuntimeError(f"no integer IDENTICAL {section} scalar in region {region}")


def _changed_scalar_bytes(obj: dict) -> bytes:
    """Raw bytes for a new physical value (≠ current) of an IDENTICAL scalar."""
    dt = obj["datatype"]
    meta = DATATYPE_META[dt]
    current = int(obj["physical"])
    candidate = current + 7
    if candidate > meta["umax"]:
        candidate = current - 7
    return _pack_scalar(dt, candidate, obj["big_endian"])


def emit_change_document(regions: dict, objects: list[dict]) -> str:
    """A valid v2 ``kind=change`` document with 7 entries in 3 regions.

    Covers every entry kind the reader accepts: ``bytes``, ``string`` (text
    mode), and the change-5 ``bytes`` + ``symbol`` form (physical value by
    A2L tag name). Every entry is inside the clean image and its after bytes
    differ from the before bytes, so the Patch Editor before/after report
    shows visible changes in the calibration and config regions. The byte
    runs are XOR-derived from the clean image (and the strings land in the
    always-erased config tail) so the before/after difference holds at any
    seed or size.
    """
    cal_base, cal_buf = regions["cal"]
    config_base, config_buf = regions["config"]
    app_base, app_buf = regions["app"]

    value_target = _pick_symbol_target(objects, "cal", "CHARACTERISTIC")
    meas_target = _pick_symbol_target(objects, "cal", "MEASUREMENT")

    cfg_off = _erased_run_offset(config_buf, 10)

    entries = [
        {"type": "bytes", "address": f"0x{cal_base:08X}",
         "bytes": _hex_bytes(_xored_run(cal_buf, 0, 4))},
        {"type": "string", "address": f"0x{config_base + cfg_off:08X}",
         "value": "CAL_MODE=7"},
        {"type": "bytes", "address": f"0x{value_target['address']:08X}",
         "bytes": _hex_bytes(_changed_scalar_bytes(value_target)),
         "symbol": value_target["name"]},
        {"type": "bytes", "address": f"0x{meas_target['address']:08X}",
         "bytes": _hex_bytes(_changed_scalar_bytes(meas_target)),
         "symbol": meas_target["name"]},
        {"type": "bytes", "address": f"0x{app_base + 0x100:08X}",
         "bytes": _hex_bytes(_xored_run(app_buf, 0x100, 4))},
        {"type": "string", "address": f"0x{config_base + cfg_off + 16:08X}",
         "value": "HW_REV=99"},
        {"type": "bytes", "address": f"0x{cal_base + 0x80:08X}",
         "bytes": _hex_bytes(_xored_run(cal_buf, 0x80, 8))},
    ]
    doc = {
        "format": "s19app-changeset",
        "version": "2.0",
        "kind": "change",
        "encoding": "utf-8",
        "value_mode": "text",
        "entries": entries,
    }
    return json.dumps(doc, indent=2) + "\n"


def emit_check_document(regions: dict, objects: list[dict]) -> str:
    """A valid v2 ``kind=check`` document: one PASSING entry per check kind.

    bytes / string / symbol checks each assert the bytes actually present in
    the clean image, so the Checks window reports all ``pass``.
    """
    cal_base, cal_buf = regions["cal"]
    config_base, config_buf = regions["config"]
    symbol = _pick_symbol_target(objects, "cal", "CHARACTERISTIC")

    probe = cal_base + 0x20
    actual = bytes(cal_buf[0x20:0x24])
    # The first config ASCII object's text is the string-check expected value.
    id_text = config_buf[0:8].decode("ascii")
    entries = [
        {"type": "bytes", "address": f"0x{probe:08X}", "bytes": _hex_bytes(actual)},
        {"type": "string", "address": f"0x{config_base:08X}", "value": id_text},
        {"type": "bytes", "address": f"0x{symbol['address']:08X}",
         "bytes": _hex_bytes(symbol["raw_bytes"]), "symbol": symbol["name"]},
    ]
    doc = {
        "format": "s19app-changeset",
        "version": "2.0",
        "kind": "check",
        "encoding": "utf-8",
        "value_mode": "text",
        "entries": entries,
    }
    return json.dumps(doc, indent=2) + "\n"


def emit_check_fails_document(regions: dict, objects: list[dict]) -> str:
    """A valid v2 ``kind=check`` document whose checks all FAIL the image.

    Mirrors :func:`emit_check_document` one-for-one but declares expected
    bytes that deliberately differ from the clean image (XOR 0xFF for the
    bytes/symbol checks, a wrong id string), so the Checks window shows the
    fail outcome.
    """
    cal_base, cal_buf = regions["cal"]
    config_base, _config_buf = regions["config"]
    symbol = _pick_symbol_target(objects, "cal", "CHARACTERISTIC")

    wrong_head = _xored_run(cal_buf, 0, 4)
    wrong_symbol = bytes(b ^ 0xFF for b in symbol["raw_bytes"])
    entries = [
        {"type": "bytes", "address": f"0x{cal_base:08X}",
         "bytes": _hex_bytes(wrong_head)},
        {"type": "string", "address": f"0x{config_base:08X}",
         "value": "WRONG_ID_STRING"},
        {"type": "bytes", "address": f"0x{symbol['address']:08X}",
         "bytes": _hex_bytes(wrong_symbol), "symbol": symbol["name"]},
    ]
    doc = {
        "format": "s19app-changeset",
        "version": "2.0",
        "kind": "check",
        "encoding": "utf-8",
        "value_mode": "text",
        "entries": entries,
    }
    return json.dumps(doc, indent=2) + "\n"


def _a2l_issue_tag_block(objects: list[dict]) -> str:
    """The injected-fault tag block appended to the clean A2L (well-formed)."""
    lines: list[str] = []

    def measurement(name: str, datatype: str, addr: int, low: str, high: str) -> None:
        lines.append(f'    /begin MEASUREMENT {name} "synthetic injected fault"')
        lines.append(f"      {datatype} CM_IDENT 1 0 {low} {high}")
        lines.append(f"      ECU_ADDRESS 0x{addr:08X}")
        lines.append("      BYTE_ORDER MSB_FIRST")
        lines.append('      UNIT "units"')
        lines.append("      READ_ONLY")
        lines.append("    /end MEASUREMENT")

    # 3 tags whose address is outside every image region (past config).
    for index, addr in enumerate((0x00D00000, 0x00D00010, 0x00D00020), start=1):
        measurement(f"OUT_OF_RANGE_{index}", "UBYTE", addr, "0", "255")

    # 2 tags whose 4-byte span crosses the config region end (0x00C00FFF).
    for index, addr in enumerate((0x00C00FFE, 0x00C00FFF), start=1):
        measurement(f"SPAN_OVER_{index}", "ULONG", addr, "0", "4294967295")

    # 1 duplicate symbol: same name AND address as the existing VALUE_0001.
    dup = next(obj for obj in objects if obj["name"] == "VALUE_0001")
    bo = "MSB_FIRST" if dup["big_endian"] else "LITTLE_ENDIAN"
    deposit = RECORD_LAYOUT_NAMES[dup["datatype"]]
    lines.append('    /begin CHARACTERISTIC VALUE_0001 "duplicate symbol fault"')
    lines.append(
        f"      VALUE 0x{dup['address']:08X} {deposit} 0 {dup['conversion']} "
        f"{dup['low']} {dup['high']}"
    )
    lines.append(f"      BYTE_ORDER {bo}")
    lines.append("    /end CHARACTERISTIC")

    # 1 reference to a missing COMPU_METHOD (CM_MISSING is never defined).
    lines.append('    /begin CHARACTERISTIC MISSING_CM "missing compu method fault"')
    lines.append("      VALUE 0x00C00000 RL_U8 0 CM_MISSING 0 255")
    lines.append("      BYTE_ORDER MSB_FIRST")
    lines.append("    /end CHARACTERISTIC")

    # 1 value outside its limits: the 0xFF erase byte at CONFIG+0x200 (255)
    # exceeds the declared [100, 120] band.
    measurement("LIMIT_BREAKER", "UBYTE", 0x00C00200, "100", "120")
    return "\n".join(lines)


def emit_a2l_issues(regions: dict, objects: list[dict]) -> str:
    """The clean A2L plus the injected-fault tag block (valid ASAP2)."""
    clean = emit_a2l(regions, objects)
    marker = "  /end MODULE\n/end PROJECT\n"
    assert clean.endswith(marker), "A2L tail changed shape"
    injected = _a2l_issue_tag_block(objects)
    return clean[: -len(marker)] + injected + "\n" + marker


def emit_mac_issues(objects: list[dict]) -> str:
    """The clean MAC plus the injected-fault lines (same 200-line prefix)."""
    clean = emit_mac(objects)
    a2l_only_names = [obj["name"] for obj in objects[MAC_LINE_COUNT:MAC_LINE_COUNT + 3]]
    first_name = objects[0]["name"]
    first_addr = _fmt_addr(objects[0]["address"])
    lines = [
        # 3 names absent from the A2L (addresses inside the image).
        "ABSENT_ALPHA=0x00800000",
        "ABSENT_BETA=0x00800020",
        "ABSENT_GAMMA=0x00C00000",
        # 3 addresses outside the image (names present in the A2L but not
        # in the MAC subset, so no MAC-side duplicate name is introduced).
        f"{a2l_only_names[0]}=0x00FF0000",
        f"{a2l_only_names[1]}=0x01000000",
        f"{a2l_only_names[2]}=0xFFFF0000",
        # 1 duplicate name (repeats the first clean MAC record, same address).
        f"{first_name}={first_addr}",
        # 1 line with a bad hex value.
        "BAD_HEX_VALUE=0xGGGGGGGG",
        # 1 line with no '=' separator.
        "NO_EQUALS_LINE_0x00800000",
    ]
    return clean + "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# firmware_v2 derivation.
# ---------------------------------------------------------------------------

def derive_v2(regions: dict[str, tuple[int, bytearray]], rng: random.Random) -> dict[str, tuple[int, bytearray]]:
    """Return a deep-copied region map with the v2 deltas applied.

    The deltas are (1) ``CHANGE_WINDOW_BYTES`` bytes inside ``cal`` XOR-ed with
    ``CHANGE_XOR``, and (2) ``EXTENSION_BYTES`` of new bytes appended to the end
    of ``cal`` (the "extended region").
    """
    v2 = {name: (base, bytearray(buf)) for name, (base, buf) in regions.items()}
    cal_base, cal_buf = v2["cal"]
    window_start, window_len = compute_change_window(regions)
    for offset in range(window_len):
        idx = window_start - cal_base + offset
        cal_buf[idx] = cal_buf[idx] ^ CHANGE_XOR

    extension_start, extension_len = compute_extension(regions)
    tail = bytearray(extension_len)
    _fill_calibration_tables(tail, rng)
    v2["cal"] = (cal_base, cal_buf + tail)
    return v2


# ---------------------------------------------------------------------------
# Definitions case (D6): a small calibration region whose four objects
# exercise the enum, bit-mask and display-format model behaviour.
# ---------------------------------------------------------------------------

#: Long identifier per definitions-case CHARACTERISTIC (the /begin line's text).
DEFINITIONS_LONG_IDS = {
    "ENUM_0001": "synthetic enum",
    "MASK_BIT_0001": "synthetic one-bit field",
    "MASK_FIELD_0001": "synthetic multi-bit field",
    "DISPLAY_0001": "synthetic display object",
}

#: Display text per COMPU_VTAB raw value (also the enum's planned text).
DEFINITIONS_ENUM_TEXTS = ("OFF", "IDLE", "RUN", "FAULT")

#: Extra body lines (after the VALUE header and any BIT_MASK line) per object.
DEFINITIONS_EXTRA_LINES = {
    "DISPLAY_0001": (
        "EXTENDED_LIMITS -50 200",
        'FORMAT "%.1"',
        'PHYS_UNIT "deg C"',
    ),
}


def build_definition_objects(rng: random.Random) -> tuple[dict[str, tuple[int, bytearray]], list[dict]]:
    """
    Summary:
        Build the definitions case's one calibration region and its four-object
        inventory (an enum, two masked fields of one word, and a display object).

    Args:
        rng (random.Random): Seeded generator; draws the fill bytes and the
            planned values in the pinned order.

    Returns:
        tuple[dict[str, tuple[int, bytearray]], list[dict]]:
            ``(regions, objects)``. ``regions`` maps ``boot`` / ``app`` /
            ``cal`` / ``config`` to ``(base, bytearray)`` — ``cal`` is the
            256-byte region at ``CAL_BASE``, the other three are empty so
            :func:`emit_s19` writes the case unchanged. ``objects`` is the
            four-object list carrying the I-D keys (``name``, ``section``,
            ``kind``, ``datatype``, ``conversion``, ``address``, ``length``,
            ``big_endian``, ``raw_bytes``, ``physical``, ``low``, ``high``,
            ``bit_mask``, ``planned_stored``, ``planned_text``).

    Data Flow:
        - Fill the 256-byte calibration region with seeded random bytes.
        - Draw the four planned values (enum raw, one-bit field, multi-bit
          field, display raw) in the pinned order.
        - Overlay the enum byte, the two masked fields of the word at +0x10,
          and the display SWORD at +0x20 into the region.
        - Emit the four object dicts with the I-D keys and the planned texts.

    Dependencies:
        Uses:
            - _pack_scalar
        Used by:
            - generate_definitions_case

    Example:
        With ``random.Random(20260001)`` the enum raw is ``1``, the one-bit
        field ``1``, the multi-bit field ``174`` and the display raw ``287``;
        the planned word at ``+0x10`` is ``0x1AE7`` (bytes ``1a e7``) and the
        display bytes are ``01 1f``.
    """
    cal = bytearray(rng.randrange(256) for _ in range(256))
    enum_raw = rng.choice([0, 1, 2, 3])
    one_bit = rng.randrange(2)
    field = rng.randrange(256)
    display_raw = rng.randint(-80, 300)

    cal[0x00] = enum_raw
    # The two masked fields share the big-endian word at +0x10: bit 0 holds
    # the one-bit field and bits 4..11 the multi-bit field, the other bits
    # kept from the fill.
    word = (cal[0x10] << 8) | cal[0x11]
    word = (word & ~(0x0001 | 0x0FF0)) | one_bit | (field << 4)
    cal[0x10] = (word >> 8) & 0xFF
    cal[0x11] = word & 0xFF
    display_bytes = _pack_scalar("SWORD", display_raw, True)
    cal[0x20:0x22] = display_bytes

    regions = {
        "boot": (BOOT_BASE, bytearray()),
        "app": (APP_BASE, bytearray()),
        "cal": (CAL_BASE, cal),
        "config": (CONFIG_BASE, bytearray()),
    }
    word_bytes = bytes((cal[0x10], cal[0x11]))
    objects = [
        {
            "name": "ENUM_0001",
            "section": "CHARACTERISTIC",
            "kind": "VALUE",
            "datatype": "UBYTE",
            "conversion": "CM_DEF_ENUM",
            "address": CAL_BASE + 0x00,
            "length": 1,
            "big_endian": True,
            "raw_bytes": bytes((enum_raw,)),
            "physical": enum_raw,
            "low": "0",
            "high": "3",
            "bit_mask": None,
            "planned_stored": enum_raw,
            "planned_text": DEFINITIONS_ENUM_TEXTS[enum_raw],
        },
        {
            "name": "MASK_BIT_0001",
            "section": "CHARACTERISTIC",
            "kind": "VALUE",
            "datatype": "UWORD",
            "conversion": "CM_DEF_IDENT",
            "address": CAL_BASE + 0x10,
            "length": 2,
            "big_endian": True,
            "raw_bytes": word_bytes,
            "physical": one_bit,
            "low": "0",
            "high": "1",
            "bit_mask": 0x0001,
            "planned_stored": one_bit,
            "planned_text": str(one_bit),
        },
        {
            "name": "MASK_FIELD_0001",
            "section": "CHARACTERISTIC",
            "kind": "VALUE",
            "datatype": "UWORD",
            "conversion": "CM_DEF_IDENT",
            "address": CAL_BASE + 0x10,
            "length": 2,
            "big_endian": True,
            "raw_bytes": word_bytes,
            "physical": field,
            "low": "0",
            "high": "255",
            "bit_mask": 0x0FF0,
            "planned_stored": field,
            "planned_text": str(field),
        },
        {
            "name": "DISPLAY_0001",
            "section": "CHARACTERISTIC",
            "kind": "VALUE",
            "datatype": "SWORD",
            "conversion": "CM_DEF_LIN",
            "address": CAL_BASE + 0x20,
            "length": 2,
            "big_endian": True,
            "raw_bytes": display_bytes,
            "physical": display_raw * 0.5,
            "low": "-40",
            "high": "150",
            "bit_mask": None,
            "planned_stored": display_raw,
            "planned_text": f"{display_raw * 0.5:.1f}",
        },
    ]
    return regions, objects


def emit_definitions_a2l(regions: dict[str, tuple[int, bytearray]], objects: list[dict]) -> str:
    """
    Summary:
        Emit the definitions case's A2L text (own PROJECT, MODULE, MOD_COMMON,
        RECORD_LAYOUTs, COMPU_METHODs, one COMPU_VTAB and the four objects).

    Args:
        regions (dict[str, tuple[int, bytearray]]): Region map whose ``cal``
            entry gives the MEMORY_SEGMENT address and byte length.
        objects (list[dict]): The four-object list from
            :func:`build_definition_objects`, in file order.

    Returns:
        str: The A2L text with ``\n`` line ends, each keyword on its own line
            and each CHARACTERISTIC header on its own body line after its
            /begin line.

    Data Flow:
        - Write the PROJECT / MODULE / MOD_COMMON header and the one
          MEMORY_SEGMENT for the calibration region.
        - Write the RECORD_LAYOUTs RL_U8 / RL_U16 / RL_S16.
        - Write the COMPU_METHODs and the COMPU_VTAB with its four pairs and
          DEFAULT_VALUE.
        - Write the four CHARACTERISTICs from the object list, with the
          BIT_MASK line and the DISPLAY_0001 extra lines.

    Dependencies:
        Uses:
            - _fmt_addr
            - RECORD_LAYOUT_NAMES
            - DATATYPE_META
        Used by:
            - generate_definitions_case
    """
    cal_base, cal_buf = regions["cal"]
    out = [
        "ASAP2_VERSION 1 71",
        '/begin PROJECT SYNTH_DEFINITIONS_DEMO "Synthetic definitions demo project"',
        '  /begin MODULE ECU_DEFINITIONS "Synthetic definitions demo module"',
        '    /begin MOD_COMMON ""',
        "      BYTE_ORDER MSB_FIRST",
        "      ALIGNMENT_BYTE 1",
        "      ALIGNMENT_WORD 2",
        "    /end MOD_COMMON",
        "    /begin MEMORY_SEGMENT cal DATA FLASH INTERN FLASH "
        f"{_fmt_addr(cal_base)} 0x{len(cal_buf):06X}",
        "    /end MEMORY_SEGMENT",
    ]
    for layout, datatype in (("RL_U8", "UBYTE"), ("RL_U16", "UWORD"), ("RL_S16", "SWORD")):
        out.append(f"    /begin RECORD_LAYOUT {layout}")
        out.append(f"      FNC_VALUES 1 {datatype} COLUMN_DIR DIRECT")
        out.append("    /end RECORD_LAYOUT")
    out += [
        '    /begin COMPU_METHOD CM_DEF_ENUM "synthetic verbal conversion"',
        '      TAB_VERB "%.0" ""',
        "      COMPU_TAB_REF VT_DEF_STATE",
        "    /end COMPU_METHOD",
        '    /begin COMPU_VTAB VT_DEF_STATE "synthetic states"',
        "      TAB_VERB 4",
        f'      0 "{DEFINITIONS_ENUM_TEXTS[0]}"',
        f'      1 "{DEFINITIONS_ENUM_TEXTS[1]}"',
        f'      2 "{DEFINITIONS_ENUM_TEXTS[2]}"',
        f'      3 "{DEFINITIONS_ENUM_TEXTS[3]}"',
        '      DEFAULT_VALUE "UNKNOWN_STATE"',
        "    /end COMPU_VTAB",
        '    /begin COMPU_METHOD CM_DEF_IDENT "synthetic IDENTICAL conversion"',
        '      IDENTICAL "%.0" ""',
        "    /end COMPU_METHOD",
        '    /begin COMPU_METHOD CM_DEF_LIN "synthetic LINEAR conversion"',
        '      LINEAR "%.3" "units"',
        "      COEFFS_LINEAR 0.5 0",
        "    /end COMPU_METHOD",
    ]
    for obj in objects:
        long_id = DEFINITIONS_LONG_IDS[obj["name"]]
        deposit = RECORD_LAYOUT_NAMES[obj["datatype"]]
        out.append(f'    /begin CHARACTERISTIC {obj["name"]} "{long_id}"')
        out.append(
            f"      VALUE {_fmt_addr(obj['address'])} {deposit} 0 "
            f"{obj['conversion']} {obj['low']} {obj['high']}"
        )
        if obj["bit_mask"] is not None:
            width = 2 * DATATYPE_META[obj["datatype"]]["size"]
            out.append(f"      BIT_MASK 0x{obj['bit_mask']:0{width}X}")
        for line in DEFINITIONS_EXTRA_LINES.get(obj["name"], ()):
            out.append(f"      {line}")
        out.append("    /end CHARACTERISTIC")
    out += ["  /end MODULE", "/end PROJECT"]
    return "\n".join(out) + "\n"


def generate_definitions_case(out_dir: Path, seed: int) -> dict[str, Path]:
    """
    Summary:
        Write the definitions case's ``definitions.s19`` and
        ``definitions.a2l`` into ``out_dir``.

    Args:
        out_dir (Path): Output directory (created if absent).
        seed (int): Deterministic seed for the image and object planning.

    Returns:
        dict[str, Path]: ``{"s19": ..., "a2l": ...}`` paths of the two files.

    Data Flow:
        - Build the regions and object list from the seeded generator.
        - Serialize the image with :func:`emit_s19` and the A2L with
          :func:`emit_definitions_a2l`.
        - Write both files as UTF-8 text (no wall clock, no case 08 file).

    Dependencies:
        Uses:
            - build_definition_objects
            - emit_s19
            - emit_definitions_a2l
        Used by:
            - main
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)
    regions, objects = build_definition_objects(rng)
    paths = {
        "s19": out_dir / "definitions.s19",
        "a2l": out_dir / "definitions.a2l",
    }
    paths["s19"].write_text(emit_s19(regions, BOOT_BASE), encoding="utf-8")
    paths["a2l"].write_text(emit_definitions_a2l(regions, objects), encoding="utf-8")
    return paths


# ---------------------------------------------------------------------------
# README and entry point.
# ---------------------------------------------------------------------------

def emit_readme(seed: int, size_mb: float, regions: dict, objects: list[dict]) -> str:
    boot, app, cal, config = (regions[k] for k in ("boot", "app", "cal", "config"))
    window_start, window_len = compute_change_window(regions)
    extension_start, extension_len = compute_extension(regions)
    meas = sum(1 for o in objects if o["section"] == "MEASUREMENT")
    chars = sum(1 for o in objects if o["section"] == "CHARACTERISTIC")
    curves = sum(1 for o in objects if o["kind"] == "CURVE")
    maps = sum(1 for o in objects if o["kind"] == "MAP")
    valblks = sum(1 for o in objects if o["kind"] == "VAL_BLK")
    asciis = sum(1 for o in objects if o["kind"] == "ASCII")
    tab_verbs = sum(
        1 for o in objects if o["conversion"] in ("CM_TAB_INTP", "CM_TAB_NOINTP")
    )
    lines = [
        "Case 08: Synthetic release demo (deterministic, fully generated).",
        "Every byte is produced locally by tools/synth/make_release_case.py - no",
        "real firmware, no downloads, no names, no PKI.",
        "",
        "What this case exercises:",
        f"  - A ~{size_mb:.0f} MiB S19 image: boot + application + calibration + config/ID",
        "    regions separated by gaps, with pseudo-code, 0xFF erased runs, 0x00",
        "    runs, structured calibration tables, and an ASCII ID/version block.",
        "  - firmware.hex is the SAME image as Intel HEX (identical compare pair).",
        f"  - firmware_v2.s19 differs only in a {window_len}-byte changed window inside",
        f"    the calibration region and a {extension_len}-byte extension of that region.",
        f"  - firmware.a2l: {chars} CHARACTERISTICs and {meas} MEASUREMENTs, COMPU_METHODs",
        "    of every decoded kind (IDENTICAL, LINEAR, RAT_FUNC, TAB_INTP, TAB_NOINTP;",
        "    TAB_INTP/TAB_NOINTP reference a COMPU_TAB/COMPU_VTAB, the latter declared",
        f"    with the TAB_VERB keyword) - {tab_verbs} objects use a table conversion.",
        f"    Arrays: {curves} CURVE, {maps} MAP (both with AXIS_DESCR, in-image),",
        f"    {valblks} VAL_BLK, {asciis} ASCII.",
        f"  - firmware.mac: {MAC_LINE_COUNT} clean NAME=0xADDRESS lines matching A2L objects.",
        "  - demo_patch.changes.json: 7-entry v2 change document (bytes, string, and",
        "    bytes+symbol entry kinds) with visible changes in cal + config regions.",
        "  - demo_check.chk.json / demo_check_fails.chk.json: one entry per check kind;",
        "    the first all-PASS, the second all-FAIL on the clean image.",
        "  - firmware_issues.a2l / firmware_issues.mac: the clean files plus injected",
        "    faults (outside image, span-over, duplicate, missing compu method,",
        "    value-out-of-limits, absent names, bad hex, no '=') for the Issues window.",
        "",
        "Layout:",
        f"  boot   0x{boot[0]:08X}  size 0x{_region_len(boot[1]):06X}",
        f"  app    0x{app[0]:08X}  size 0x{_region_len(app[1]):06X}",
        f"  cal    0x{cal[0]:08X}  size 0x{_region_len(cal[1]):06X}",
        f"  config 0x{config[0]:08X}  size 0x{_region_len(config[1]):06X}",
        f"  v2 changed window: 0x{window_start:08X} .. 0x{window_start + window_len - 1:08X}",
        f"  v2 extension:      0x{extension_start:08X} .. 0x{extension_start + extension_len - 1:08X}",
        "",
        f"Seed: {seed}",
        "Regeneration command:",
        f"  python tools/synth/make_release_case.py --out examples/case_08_release_demo --seed {seed} --size-mb {size_mb:g}",
        "",
    ]
    return "\n".join(lines)


def generate(out_dir: Path, seed: int, size_mb: float) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)

    regions = compute_region_sizes(size_mb)
    objects = build_objects(regions, rng)

    paths: dict[str, Path] = {}
    paths["s19"] = out_dir / "firmware.s19"
    paths["hex"] = out_dir / "firmware.hex"
    paths["v2"] = out_dir / "firmware_v2.s19"
    paths["a2l"] = out_dir / "firmware.a2l"
    paths["mac"] = out_dir / "firmware.mac"
    paths["change"] = out_dir / "demo_patch.changes.json"
    paths["check"] = out_dir / "demo_check.chk.json"
    paths["check_fails"] = out_dir / "demo_check_fails.chk.json"
    paths["a2l_issues"] = out_dir / "firmware_issues.a2l"
    paths["mac_issues"] = out_dir / "firmware_issues.mac"
    paths["readme"] = out_dir / "README.txt"

    paths["s19"].write_text(emit_s19(regions, BOOT_BASE), encoding="utf-8")
    paths["hex"].write_text(emit_hex(regions), encoding="utf-8")
    paths["v2"].write_text(emit_s19(derive_v2(regions, rng), BOOT_BASE), encoding="utf-8")
    paths["a2l"].write_text(emit_a2l(regions, objects), encoding="utf-8")
    paths["mac"].write_text(emit_mac(objects), encoding="utf-8")
    paths["change"].write_text(emit_change_document(regions, objects), encoding="utf-8")
    paths["check"].write_text(emit_check_document(regions, objects), encoding="utf-8")
    paths["check_fails"].write_text(emit_check_fails_document(regions, objects), encoding="utf-8")
    paths["a2l_issues"].write_text(emit_a2l_issues(regions, objects), encoding="utf-8")
    paths["mac_issues"].write_text(emit_mac_issues(objects), encoding="utf-8")
    paths["readme"].write_text(emit_readme(seed, size_mb, regions, objects), encoding="utf-8")
    return paths


def main(argv: list[str]) -> int:
    """
    Summary:
        Run the synthetic case generator for the chosen case and print one
        line per written file.

    Args:
        argv (list[str]): Command-line arguments without the program name.

    Returns:
        int: Process exit code (0 on success).

    Data Flow:
        - Parse ``--out``, ``--seed``, ``--size-mb`` and ``--case``.
        - Run ``release`` (the default, case 08) through :func:`generate`, or
          ``definitions`` through :func:`generate_definitions_case`.
        - Print each written file's size and name.

    Dependencies:
        Uses:
            - generate
            - generate_definitions_case
        Used by:
            - the ``__main__`` guard
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, help="output directory")
    parser.add_argument("--seed", type=int, default=20260001, help="deterministic seed")
    parser.add_argument("--size-mb", type=float, default=10.0, help="target S19 size in MiB")
    parser.add_argument("--case", choices=("release", "definitions"), default="release",
                        help="case to generate (default: release)")
    args = parser.parse_args(argv)

    if args.case == "definitions":
        paths = generate_definitions_case(Path(args.out), args.seed)
    else:
        paths = generate(Path(args.out), args.seed, args.size_mb)
    for label, path in sorted(paths.items()):
        print(f"{label:8s} {path.stat().st_size:>10d}  {path.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
