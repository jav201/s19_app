"""Independent S19 and Intel HEX reader for batch-99 test oracles.

Summary:
    Minimal Motorola S19 / Intel HEX parsers that import nothing from
    ``s19_app``, so test oracles can check the app's own loaders and writers
    against an outside implementation (HLR-152, LLR-152.3). Ported from the
    read/write investigation probes (``common.py``: ``mini_s19`` /
    ``mini_hex``).

    Facts recorded beyond the address -> byte image:

    - ``header`` — S19: the S0 record payload (``None`` when absent).
    - ``terminator`` — S19: ``("S7" | "S8" | "S9", entry_address)``; Intel HEX:
      a type 05 start-address record as ``("HEX05", address)``, else ``None``.
    - ``s5_count`` — S19: the address field of the S5/S6 record (the declared
      data-record count), else ``None``.
    - ``eof_seen`` — S19: a terminator record was seen; Intel HEX: a type 01
      EOF record was seen.
    - ``records_after_end`` — non-empty lines after the terminator / EOF.
      They are never parsed and their bytes never enter the image.
    - ``errors`` — checksum / count / structure problems, as strings.

    Overlapping data records resolve last-wins (matching the loader); a
    differing overlapped byte is reported in ``errors``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union

PathLike = Union[str, Path]

#: Address-field width per S19 record type.
_S19_ADDR_LEN = {"0": 2, "1": 2, "2": 3, "3": 4, "5": 2, "6": 3, "7": 4, "8": 3, "9": 2}


@dataclass
class Image:
    """Summary: one parsed image — data bytes plus load facts.

    Args:
        data: address -> byte from S1/S2/S3 (or HEX type 00) records only.
        header: S19 S0 payload, or ``None``.
        terminator: ``("S7"/"S8"/"S9", entry)`` for S19, ``("HEX05", start)``
            for a HEX type 05 record, else ``None``.
        s5_count: S19 S5/S6 declared data-record count, or ``None``.
        eof_seen: terminator (S19) / EOF (HEX) present.
        records_after_end: non-empty lines after the terminator / EOF.
        errors: structural problems found while parsing.
    """

    data: dict = field(default_factory=dict)
    header: Optional[bytes] = None
    terminator: Optional[tuple] = None
    s5_count: Optional[int] = None
    eof_seen: bool = False
    records_after_end: int = 0
    errors: list = field(default_factory=list)


def _store(image: Image, addr: int, value: int, line_no: int) -> None:
    if addr in image.data and image.data[addr] != value:
        image.errors.append(f"line {line_no}: overlap at 0x{addr:x} differs")
    image.data[addr] = value


def read_s19(path: PathLike) -> Image:
    """Summary: parse a Motorola S19 file into an :class:`Image`.

    Args:
        path: the file to read.

    Returns:
        Image: the parsed image; records after the terminator are counted in
        ``records_after_end`` and never enter ``data``.
    """
    image = Image()
    terminated = False
    text = Path(path).read_text(encoding="ascii")
    for line_no, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line:
            continue
        if terminated:
            image.records_after_end += 1
            continue
        if len(line) < 4 or line[0] != "S" or line[1] not in _S19_ADDR_LEN:
            image.errors.append(f"line {line_no}: unsupported record {line[:8]!r}")
            continue
        rectype = line[1]
        try:
            raw = bytes.fromhex(line[2:])
        except ValueError:
            image.errors.append(f"line {line_no}: not hexadecimal")
            continue
        if not raw or raw[0] != len(raw) - 1:
            image.errors.append(f"line {line_no}: count mismatch")
            continue
        if (sum(raw) & 0xFF) != 0xFF:
            image.errors.append(f"line {line_no}: checksum")
            continue
        width = _S19_ADDR_LEN[rectype]
        addr = int.from_bytes(raw[1 : 1 + width], "big")
        payload = raw[1 + width : -1]
        if rectype == "0":
            image.header = bytes(payload)
        elif rectype in "123":
            for i, b in enumerate(payload):
                _store(image, addr + i, b, line_no)
        elif rectype in "56":
            image.s5_count = addr
        else:
            image.terminator = ("S" + rectype, addr)
            image.eof_seen = True
            terminated = True
    return image


def read_hex(path: PathLike) -> Image:
    """Summary: parse an Intel HEX file into an :class:`Image`.

    Args:
        path: the file to read.

    Returns:
        Image: the parsed image. Type 02 sets the segment base (the 16-bit
        offset wraps mod 64 KiB); type 04 sets the linear base; type 05 is
        recorded as ``terminator == ("HEX05", start)``; type 01 is EOF — lines
        after it are counted in ``records_after_end`` and never parsed.
    """
    image = Image()
    upper = 0
    seg = 0
    mode = "lin"
    terminated = False
    text = Path(path).read_text(encoding="ascii")
    for line_no, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line:
            continue
        if terminated:
            image.records_after_end += 1
            continue
        if len(line) < 9 or line[0] != ":":
            image.errors.append(f"line {line_no}: missing ':'")
            continue
        try:
            raw = bytes.fromhex(line[1:])
        except ValueError:
            image.errors.append(f"line {line_no}: not hexadecimal")
            continue
        if len(raw) < 5 or raw[0] != len(raw) - 5:
            image.errors.append(f"line {line_no}: count mismatch")
            continue
        if (sum(raw) & 0xFF) != 0:
            image.errors.append(f"line {line_no}: checksum")
            continue
        addr = int.from_bytes(raw[1:3], "big")
        rectype = raw[3]
        payload = raw[4 : 4 + raw[0]]
        if rectype == 0:
            for i, b in enumerate(payload):
                if mode == "lin":
                    full = (upper << 16) + addr + i
                else:
                    full = seg + ((addr + i) & 0xFFFF)
                _store(image, full, b, line_no)
        elif rectype == 1:
            image.eof_seen = True
            terminated = True
        elif rectype == 2:
            seg = int.from_bytes(payload, "big") << 4
            mode = "seg"
        elif rectype == 3:
            pass  # segment start address: informational only
        elif rectype == 4:
            upper = int.from_bytes(payload, "big")
            mode = "lin"
        elif rectype == 5:
            image.terminator = ("HEX05", int.from_bytes(payload, "big"))
        else:
            image.errors.append(f"line {line_no}: unsupported record type {rectype:02x}")
    return image
