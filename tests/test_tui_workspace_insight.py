"""Unit tests for the derived ``LoadedFile`` insight fields (batch-47 Inc-2).

Covers LLR-066.5 / MN-6: the two NEW derived fields
``LoadedFile.out_of_order_count`` and ``LoadedFile.entry_point`` populated by
``load_service`` at construction, plus the defaulting contract that keeps every
existing ``LoadedFile(...)`` constructor working.

Realizes the Layer-A derived-field TCs from
``.dev-flow/2026-07-15-batch-47/01b-qa-strategy-and-verification.md``:
    - TC-066.1 — ``out_of_order_count`` populated from ``get_out_of_order_records()``.
    - TC-066.2 — ``entry_point`` populated from the S7/S8/S9 terminator scan.
    - TC-066.3 — HEX load → ``entry_point is None`` (start records discarded, MN-9).

These are service-layer/data-layer tests only (no render, no ``App.run_test``);
the black-box ``#ws_stats`` render ATs (AT-066a..d) land in Inc-3.
"""

from __future__ import annotations

from pathlib import Path

from s19_app.core import S19File
from s19_app.hexfile import IntelHexFile
from s19_app.tui.models import LoadedFile
from s19_app.tui.services.load_service import build_loaded_hex, build_loaded_s19

EXAMPLES_ROOT = Path(__file__).resolve().parent.parent / "examples"
PRG_S19 = EXAMPLES_ROOT / "case_00_public" / "prg.s19"
CASE01_S19 = EXAMPLES_ROOT / "case_01_basic_valid" / "firmware.s19"


def _build_hex_record(byte_count: int, address: int, record_type: int, data: list[int]) -> str:
    """Build one Intel-HEX record line (mirrors tests/test_hexfile.py helper)."""
    values = [byte_count, (address >> 8) & 0xFF, address & 0xFF, record_type] + data
    checksum = (-sum(values)) & 0xFF
    return ":" + "".join(f"{value:02X}" for value in values) + f"{checksum:02X}"


def test_ooo_count_populated() -> None:
    """TC-066.1 — ``out_of_order_count`` == ``len(get_out_of_order_records())``.

    ``prg.s19`` has 4 out-of-order data records; ``case_01/firmware.s19`` has 0.
    """
    prg = build_loaded_s19(PRG_S19, S19File(str(PRG_S19)), a2l_path=None, a2l_data=None)
    case01 = build_loaded_s19(CASE01_S19, S19File(str(CASE01_S19)), a2l_path=None, a2l_data=None)

    assert prg.out_of_order_count == 4
    assert case01.out_of_order_count == 0


def test_entry_point_s19() -> None:
    """TC-066.2 — ``entry_point`` == the terminator (S7/S8/S9) record address.

    ``case_01/firmware.s19`` terminates with S7 ``0x80000000`` (non-zero); the
    zero-address case (``prg.s19`` S9 ``0x0``) is PRESENT-but-zero, distinct from
    the absent (``None``) HEX case — see ``test_entry_point_hex_none``.
    """
    prg = build_loaded_s19(PRG_S19, S19File(str(PRG_S19)), a2l_path=None, a2l_data=None)
    case01 = build_loaded_s19(CASE01_S19, S19File(str(CASE01_S19)), a2l_path=None, a2l_data=None)

    assert case01.entry_point == 0x80000000
    assert prg.entry_point == 0x0
    assert prg.entry_point is not None  # present-but-zero, NOT absent


def test_entry_point_hex_none(tmp_path: Path) -> None:
    """TC-066.3 (MN-9) — Intel-HEX load → ``entry_point is None`` + OOO == 0.

    ``build_loaded_hex`` HARD-SETS ``entry_point=None`` / ``out_of_order_count=0``
    (it never surfaces a start record — hexfile.py:135-137 discards type 03/05
    upstream). This test pins those constants AND proves the loader does not
    crash when the input file *contains* a type-03 start record. Built inline via
    ``IntelHexFile`` — no ``examples/*.hex`` fixture is added (T-2 / MN-9).
    """
    lines = [
        # type-03 start-addr record: discarded upstream; present here to prove
        # build_loaded_hex tolerates it (it does not drive the None result).
        _build_hex_record(4, 0x0000, 0x03, [0x00, 0x00, 0x80, 0x00]),
        _build_hex_record(1, 0x0010, 0x00, [0xAA]),  # data
        _build_hex_record(0, 0x0000, 0x01, []),  # EOF
    ]
    hex_path = tmp_path / "inline.hex"
    hex_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    loaded = build_loaded_hex(hex_path, IntelHexFile(str(hex_path)), a2l_path=None, a2l_data=None)

    assert loaded.entry_point is None
    assert loaded.out_of_order_count == 0


def test_fields_default_on_bare_construction() -> None:
    """MN-6 — the two new fields are DEFAULTED on a bare ``LoadedFile()``.

    Every existing constructor (~40 test sites + crc.py / placeholders.py) omits
    the two new fields and must keep compiling with safe defaults. Proven here by
    constructing ``LoadedFile`` with only the pre-existing required positional
    fields and asserting the defaults.
    """
    loaded = LoadedFile(
        path=Path("bare"),
        file_type="s19",
        mem_map={},
        row_bases=[],
        ranges=[],
        range_validity=[],
        errors=[],
        a2l_path=None,
        a2l_data=None,
    )

    assert loaded.out_of_order_count == 0
    assert loaded.entry_point is None
