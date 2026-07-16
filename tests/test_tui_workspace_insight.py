"""Tests for the Workspace insight layer (batch-47 Inc-2 + Inc-3).

Inc-2 (Layer-A, data): the two NEW derived ``LoadedFile`` fields
``out_of_order_count`` / ``entry_point`` populated by ``load_service``, plus the
defaulting contract that keeps every existing ``LoadedFile(...)`` constructor
working (LLR-066.5 / MN-6):
    - TC-066.1 — ``out_of_order_count`` from ``get_out_of_order_records()``.
    - TC-066.2 — ``entry_point`` from the S7/S8/S9 terminator scan.
    - TC-066.3 — HEX load → ``entry_point is None`` (start records discarded, MN-9).

Inc-3 (Layer-B, black-box): the shipped Workspace render ATs, each driven
through ``App.run_test`` at BOTH 80×24 and 120×30 (per the 01b crosswalk),
asserting the observed content in the mounted widgets:
    - AT-066a — ``#ws_stats`` shows ``⚠4 OOO`` for ``prg.s19``.
    - AT-066b — ``#ws_stats`` shows ``Entry 0x80000000`` (present) for ``case_01``;
      the ``0x0`` note-case renders ``0x00000000`` (PRESENT, not ``—``).
    - AT-066c — inline Intel-HEX load → ``#ws_stats`` shows ``Entry —`` (absent).
    - AT-066d — S19 (OOO=4) → attach MAC → ``#ws_stats`` STILL shows ``⚠4 OOO`` +
      entry preserved (the MJ-1 merge-carry counterfactual, LLR-066.7).
    - AT-067 — gapped fixture → ``#ws_memstrip`` shows ≥2 distinct entropy-band
      glyphs from ``· ░ ▒ ▓`` AND ≥1 ``╱`` gap glyph.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from textual.widgets import Static

from s19_app.core import S19File
from s19_app.hexfile import IntelHexFile
from s19_app.tui.app import S19TuiApp
from s19_app.tui.models import LoadedFile
from s19_app.tui.services.load_service import build_loaded_hex, build_loaded_s19

EXAMPLES_ROOT = Path(__file__).resolve().parent.parent / "examples"
PRG_S19 = EXAMPLES_ROOT / "case_00_public" / "prg.s19"
CASE01_S19 = EXAMPLES_ROOT / "case_01_basic_valid" / "firmware.s19"

#: The two pilot regimes every Inc-3 AT is driven at (01b: BOTH 80×24 + 120×30).
PILOT_SIZES = [(80, 24), (120, 30)]

#: Canonical entropy-band glyphs (``entropy_style.ENTROPY_BAND_GLYPH``); the
#: memstrip AT asserts membership in this set, never a hard-coded cell count (C-29).
_BAND_GLYPHS = frozenset("·░▒▓")
_GAP_GLYPH = "╱"


def _static_plain(node: Static) -> str:
    """Return a ``Static``'s rendered content as plain text (Rich ``Text.plain``)."""
    rendered = node.render()
    return rendered.plain if hasattr(rendered, "plain") else str(rendered)


def _stats_plain(app: S19TuiApp) -> str:
    """Return the rendered ``#ws_stats`` text (Rich ``Text.plain``)."""
    return _static_plain(app.query_one("#ws_stats", Static))


def _memstrip_plain(app: S19TuiApp) -> str:
    """Concatenate the rendered glyph of every mounted ``#ws_memstrip`` cell."""
    band = app.query_one("#ws_memstrip")
    return "".join(_static_plain(cell) for cell in band.query(Static))


def _install_and_render(app: S19TuiApp, loaded: LoadedFile) -> None:
    """Install ``loaded`` as ``current_file`` and drive the Workspace render.

    Mirrors the post-load refresh: reveal the panes (``_apply_empty_state``) then
    call ``update_sections`` (which refreshes ``#ws_stats`` + ``#ws_memstrip``).
    """
    app.current_file = loaded
    app._apply_empty_state()
    app.update_sections()


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


# ---------------------------------------------------------------------------
# Inc-3 — black-box Workspace render ATs (App.run_test @ 80×24 AND 120×30)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("size", PILOT_SIZES)
def test_at066a_ooo(tmp_path: Path, size: tuple[int, int]) -> None:
    """AT-066a — ``#ws_stats`` renders ``⚠4 OOO`` for ``prg.s19`` (OOO == 4).

    WHY: the out-of-order count is a load-health fact the analyst must read at a
    glance; the AT asserts the CONTENT (the number 4), not "some OOO text", so a
    regression that silently zeroed the count would fail here.
    """

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            loaded = build_loaded_s19(PRG_S19, S19File(str(PRG_S19)), a2l_path=None, a2l_data=None)
            _install_and_render(app, loaded)
            await pilot.pause()
            return _stats_plain(app)

    assert "⚠4 OOO" in asyncio.run(_drive())


@pytest.mark.parametrize("size", PILOT_SIZES)
def test_at066b_entry_present(tmp_path: Path, size: tuple[int, int]) -> None:
    """AT-066b — entry PRESENT branch: ``case_01`` renders ``Entry 0x80000000``.

    WHY: the entry point is a present-vs-absent policy branch (C-10). This is the
    A-branch: a non-zero S7 terminator must render its exact hex address. The
    ``0x0`` note-case (``prg.s19``) is asserted too — it renders
    ``Entry 0x00000000`` (PRESENT-but-zero), which must stay distinct from the
    absent ``—`` of the B-branch (AT-066c).
    """

    async def _drive() -> tuple[str, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            case01 = build_loaded_s19(CASE01_S19, S19File(str(CASE01_S19)), a2l_path=None, a2l_data=None)
            _install_and_render(app, case01)
            await pilot.pause()
            present = _stats_plain(app)
            prg = build_loaded_s19(PRG_S19, S19File(str(PRG_S19)), a2l_path=None, a2l_data=None)
            _install_and_render(app, prg)
            await pilot.pause()
            zero = _stats_plain(app)
            return present, zero

    present, zero = asyncio.run(_drive())
    assert "Entry 0x80000000" in present
    assert "Entry 0x00000000" in zero  # present-but-zero, NOT the absent "—"


@pytest.mark.parametrize("size", PILOT_SIZES)
def test_at066c_entry_absent_hex(tmp_path: Path, size: tuple[int, int]) -> None:
    """AT-066c — entry ABSENT branch: an inline Intel-HEX load renders ``Entry —``.

    WHY: the B-branch of the entry-point policy (C-10). Intel-HEX discards type
    03/05 start records, so ``entry_point is None`` → the render must show the
    em-dash placeholder, distinct from a present-but-zero ``0x00000000``. Built
    inline via ``IntelHexFile`` — no ``examples/*.hex`` fixture is added (MN-9).
    """
    lines = [
        _build_hex_record(4, 0x0000, 0x03, [0x00, 0x00, 0x80, 0x00]),  # type-03 start (discarded)
        _build_hex_record(1, 0x0010, 0x00, [0xAA]),  # data
        _build_hex_record(0, 0x0000, 0x01, []),  # EOF
    ]
    hex_path = tmp_path / "inline.hex"
    hex_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            loaded = build_loaded_hex(hex_path, IntelHexFile(str(hex_path)), a2l_path=None, a2l_data=None)
            _install_and_render(app, loaded)
            await pilot.pause()
            return _stats_plain(app)

    assert "Entry —" in asyncio.run(_drive())


@pytest.mark.parametrize("size", PILOT_SIZES)
def test_at066d_merge_preserves_facts(tmp_path: Path, size: tuple[int, int]) -> None:
    """AT-066d (MJ-1) — attaching a MAC preserves the loader facts.

    WHY: the counterfactual is the pre-carry merge dropping the derived fields to
    their dataclass defaults (``⚠0 OOO · Entry —``). This drives the real
    ``_merge_mac_with_existing_primary`` handler over an already-loaded S19
    (OOO=4, S9 entry ``0x0``) and asserts the CONTENT survives the merge
    (LLR-066.7).
    """

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            primary = build_loaded_s19(PRG_S19, S19File(str(PRG_S19)), a2l_path=None, a2l_data=None)
            _install_and_render(app, primary)
            await pilot.pause()
            mac_loaded = LoadedFile(
                path=tmp_path / "attach.mac",
                file_type="mac",
                mem_map={},
                row_bases=[],
                ranges=[],
                range_validity=[],
                errors=[],
                a2l_path=None,
                a2l_data=None,
                mac_path=tmp_path / "attach.mac",
                mac_records=[{"tag": "T", "address": 0x1000, "parse_ok": True}],
                mac_diagnostics=[],
            )
            merged = app._merge_mac_with_existing_primary(mac_loaded)
            _install_and_render(app, merged)
            await pilot.pause()
            return _stats_plain(app)

    stats = asyncio.run(_drive())
    assert "⚠4 OOO" in stats  # NOT reset to ⚠0 OOO by the merge
    assert "Entry 0x00000000" in stats  # present-but-zero entry preserved


@pytest.mark.parametrize("size", PILOT_SIZES)
def test_at067_memstrip(tmp_path: Path, size: tuple[int, int]) -> None:
    """AT-067 — the entropy memstrip shows ≥2 band glyphs AND ≥1 ``╱`` gap.

    WHY: the memstrip surfaces already-computed entropy plus the unmapped-gap
    structure. Asserts the STRUCTURAL invariant (≥2 distinct band glyphs from the
    ``· ░ ▒ ▓`` set + ≥1 ``╱`` gap) that holds at any geometry — never a
    hard-coded cell count (C-29). ``prg.s19`` has 11 gapped, multi-band ranges.
    """

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            loaded = build_loaded_s19(PRG_S19, S19File(str(PRG_S19)), a2l_path=None, a2l_data=None)
            _install_and_render(app, loaded)
            await pilot.pause()
            return _memstrip_plain(app)

    strip = asyncio.run(_drive())
    distinct_bands = {ch for ch in strip if ch in _BAND_GLYPHS}
    assert len(distinct_bands) >= 2, f"expected ≥2 band glyphs, got {sorted(distinct_bands)} in {strip!r}"
    assert _GAP_GLYPH in strip, f"expected ≥1 gap glyph ╱ in {strip!r}"
