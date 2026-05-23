"""Sample data so the sketch screens render without parsing a real .s19.

Replace each function with the real implementation when wiring up `bincopy` /
`pya2l`. The shape of the returned dataclasses is what the widgets depend on —
keep that stable and the UI doesn't have to change.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Range:
    label: str
    start: int
    end: int
    kind: str  # "code" | "data" | "cal" | "boot"
    valid: bool = True


@dataclass(frozen=True)
class FileEntry:
    name: str
    type: str  # "s19" | "a2l" | "map"
    size: str


@dataclass(frozen=True)
class Bookmark:
    addr: int
    note: str


@dataclass(frozen=True)
class Project:
    name: str
    path: str


def sample_project() -> Project:
    return Project(name="ECU_2024_R3", path="~/work/ecu/ecu_2024_r3")


def sample_files() -> list[FileEntry]:
    return [
        FileEntry("firmware.s19", "s19", "2.4 MB"),
        FileEntry("ecu.a2l", "a2l", "812 KB"),
        FileEntry("map.txt", "map", "184 KB"),
    ]


def sample_ranges() -> list[Range]:
    return [
        Range("Boot ROM",       0x80000000, 0x80004000, "boot", True),
        Range("Reset vectors",  0x80004000, 0x80004400, "code", True),
        Range("App code",       0x80004400, 0x80140000, "code", True),
        Range("Calibration A",  0x80140000, 0x801C0000, "cal",  True),
        Range("Calibration B",  0x801C0000, 0x801E0000, "cal",  False),
        Range("Constants",      0x801E0000, 0x80200000, "data", True),
    ]


def sample_bookmarks() -> list[Bookmark]:
    return [
        Bookmark(0x80004000, "reset entry"),
        Bookmark(0x80140000, "cal table A start"),
        Bookmark(0x801C00FC, "suspect MAC delta"),
    ]


def sample_hex_rows(base: int = 0x80000000, count: int = 256) -> list[tuple[int, bytes]]:
    """Return (addr, 16-byte chunk) tuples. Replace with bincopy reads."""
    out: list[tuple[int, bytes]] = []
    rng = bytes(range(256))
    for i in range(count):
        addr = base + i * 16
        chunk = rng[(i * 16) % 256 : (i * 16) % 256 + 16]
        if len(chunk) < 16:  # wrap
            chunk = (chunk + rng)[:16]
        out.append((addr, chunk))
    return out
