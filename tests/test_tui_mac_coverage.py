"""batch-47 US-MAC View MID — black-box acceptance for the MAC insight layer.

Layer B (`AT-NNN`) drives the SHIPPED MAC View screen under Textual Pilot at
**both** 80x24 and 120x30 (sync ``asyncio.run`` wrappers; pytest-asyncio is not
installed — idiom: ``tests/test_tui_a2l_detail.py``) and asserts the observed
rendered content:

- ``AT-070`` — the records table carries a leading status glyph, showing BOTH a
  ``✓`` (parse-ok + in-image) row AND a ``⚠`` (parse-ok + out-of-image) row for
  the mixed public ``case_02`` fixture (C-10 both branches by content).
- ``AT-070b`` ★ (gate-blocking C-17) — a hostile MAC record NAME renders
  **verbatim** in the table cell ``Text.plain`` with no payload-derived style
  span and no ``MarkupError`` / crash.
- ``AT-070c`` — a parse-error MAC record (malformed ``.mac`` line, driven through
  the frozen parser's error-collection contract) shows the ``✗`` glyph (C-10
  third branch).
- ``AT-071`` — while a MAC is loaded, the coverage strip shows ``X of Y`` equal to
  ``CoverageMetrics.mac_in_s19`` of ``mac_total`` (``case_02`` → ``1 of 2``), and
  the strip is present whenever a MAC is loaded.

Layer A boundary: ``mac_total == 0`` → strip renders ``0 of 0`` with no
divide-by-zero (MN-3 / TC-068.5).

The C-17 payload set (MD-1) is applied verbatim: ``[red]…[/red]``,
``[link=http://x]u[/link]``, an ANSI escape, and the UNBALANCED ``sensor[unclosed``
— the last is the deliberate ``Text.from_markup`` counterfactual (it passes every
balanced fixture but raises ``MarkupError`` under ``from_markup``). The hostile
name is planted directly into ``LoadedFile.mac_records`` so the (frozen) MAC
parser cannot sanitize it away before the render sink under test.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Awaitable, Callable

from rich.text import Text
from textual.widgets import DataTable, Static

from s19_app.core import S19File
from s19_app.tui.app import S19TuiApp
from s19_app.tui.changes.io import emit_s19_from_mem_map
from s19_app.tui.mac import parse_mac_file
from s19_app.tui.services.load_service import build_loaded_s19
from s19_app.tui.services.validation_service import build_mac_coverage_strip
from s19_app.validation.model import CoverageMetrics

_SIZES = ((80, 24), (120, 30))

_EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
_CASE_02 = _EXAMPLES / "case_02_gaps_and_patch_targets"
_CASE_02_S19 = _CASE_02 / "firmware.s19"
_CASE_02_MAC = _CASE_02 / "firmware.mac"

# --- C-17 payload set (MD-1) ------------------------------------------------
_P_BRACKET = "[red]PWNED[/red]"
_P_LINK = "[link=http://x]u[/link]"
_P_ANSI = "\x1b[31mX\x1b[0m"
_P_UNBAL = "sensor[unclosed"
_PAYLOADS = (_P_BRACKET, _P_LINK, _P_ANSI, _P_UNBAL)
_HOSTILE = "".join(_PAYLOADS)


def _load_case_02(app: S19TuiApp) -> None:
    """Install the public case_02 S19+MAC fixture (1 in-image + 1 out-of-image)."""
    s19 = S19File(str(_CASE_02_S19))
    loaded = build_loaded_s19(_CASE_02_S19, s19, a2l_path=None, a2l_data=None)
    mac = parse_mac_file(_CASE_02_MAC)
    loaded.mac_path = _CASE_02_MAC
    loaded.mac_records = mac.get("records", [])
    loaded.mac_diagnostics = mac.get("diagnostics", [])
    app.current_a2l_path = None
    app.current_a2l_data = None
    app.current_file = loaded


def _s19_loaded(tmp: Path, mac_records: list[dict]) -> "object":
    """Build a real tiny S19 ``LoadedFile`` (0x1000..0x100F mapped) and attach
    the given hand-crafted MAC records — driving the render sink directly."""
    mem = {0x1000 + off: 0 for off in range(16)}
    s19_path = tmp / "img.s19"
    s19_path.write_text(emit_s19_from_mem_map(mem, [(0x1000, 0x1010)]), encoding="ascii")
    loaded = build_loaded_s19(s19_path, S19File(str(s19_path)), a2l_path=None, a2l_data=None)
    loaded.mac_records = mac_records
    loaded.mac_diagnostics = []
    return loaded


def _mac_cells(app: S19TuiApp) -> list[Text]:
    table = app.query_one("#mac_records_list", DataTable)
    return [table.get_row_at(i)[0] for i in range(table.row_count)]


def _strip_text(app: S19TuiApp) -> str:
    strip = app.query_one("#mac_coverage_strip", Static)
    return str(strip.render())


def _drive_mac(
    size: tuple[int, int],
    install: Callable[[S19TuiApp, Path], None],
    observe: Callable[[S19TuiApp, object], Awaitable[None]],
) -> None:
    """Boot the app, install a fixture, show the MAC screen, render, observe."""

    async def _run() -> None:
        import tempfile

        tmp = Path(tempfile.mkdtemp())
        app = S19TuiApp(base_dir=tmp)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            install(app, tmp)
            app.action_show_screen("mac")
            for _ in range(4):
                await pilot.pause()
            app.update_mac_view()
            await pilot.pause()
            await observe(app, pilot)

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# AT-070 — status-glyph column shows BOTH ✓ (in-image) AND ⚠ (out-of-image)
# by content on the mixed case_02 fixture (C-10 both branches), both sizes.
# ---------------------------------------------------------------------------


def test_at070_glyph_branches() -> None:
    for size in _SIZES:

        async def _observe(app: S19TuiApp, pilot: object) -> None:
            plains = [c.plain for c in _mac_cells(app)]
            assert any(p.startswith("✓") for p in plains), (
                f"expected an in-image ✓ row; got {plains!r}"
            )
            assert any(p.startswith("⚠") for p in plains), (
                f"expected an out-of-image ⚠ row; got {plains!r}"
            )

        _drive_mac(size, lambda app, _tmp: _load_case_02(app), _observe)


# ---------------------------------------------------------------------------
# AT-070b ★ (GATE-BLOCKING C-17) — hostile MAC name renders verbatim in the
# table cell Text.plain, no payload-derived style span, no MarkupError.
# ---------------------------------------------------------------------------


def test_at070b_c17_name() -> None:
    for size in _SIZES:

        def _install(app: S19TuiApp, tmp: Path) -> None:
            record = {
                "parse_ok": True,
                "name": _HOSTILE,
                "address": 0x1000,
                "line_number": 1,
                "parse_error": "",
            }
            app.current_file = _s19_loaded(tmp, [record])

        async def _observe(app: S19TuiApp, pilot: object) -> None:
            table = app.query_one("#mac_records_list", DataTable)
            assert table.row_count == 1, "expected the single hostile row rendered"
            name_cell = table.get_row_at(0)[0]
            assert isinstance(name_cell, Text), "table cell must be a Rich Text"
            plain = name_cell.plain
            for payload in _PAYLOADS:
                assert payload in plain, (
                    f"payload {payload!r} not verbatim in cell; got {plain!r}"
                )
            # The cell legitimately carries a glyph span + a severity span; assert
            # NO span style originates from the payload (a from_markup regression
            # would inject 'red' / 'link' styles).
            styles = " ".join(str(span.style) for span in name_cell.spans)
            assert "link" not in styles and "red" not in styles, (
                f"payload-derived style leaked into cell spans: {styles!r}"
            )

        _drive_mac(size, _install, _observe)


# ---------------------------------------------------------------------------
# AT-070c — a parse-error MAC record (malformed line via the frozen parser's
# error-collection contract) shows the ✗ glyph (C-10 third branch).
# ---------------------------------------------------------------------------


def test_at070c_parse_error() -> None:
    for size in _SIZES:

        def _install(app: S19TuiApp, tmp: Path) -> None:
            mac_path = tmp / "broken.mac"
            # One well-formed record + one malformed line (non-hex address) that
            # the parser marks parse_ok=False without aborting the load.
            mac_path.write_text("GOOD=0x1000\nBADREC=ZZZZ\n", encoding="utf-8")
            parsed = parse_mac_file(mac_path)
            loaded = _s19_loaded(tmp, parsed.get("records", []))
            loaded.mac_path = mac_path
            loaded.mac_diagnostics = parsed.get("diagnostics", [])
            app.current_file = loaded

        async def _observe(app: S19TuiApp, pilot: object) -> None:
            plains = [c.plain for c in _mac_cells(app)]
            assert any(p.startswith("✗") for p in plains), (
                f"expected a parse-error ✗ row; got {plains!r}"
            )

        _drive_mac(size, _install, _observe)


# ---------------------------------------------------------------------------
# AT-070d — a MAC-ONLY load (no primary image, so records are never image-
# checked) renders a parse-ok record as the grey `·` "not yet checked" glyph,
# NOT a false green `✓`. Closes the C-10 coverage gap for the un-checked branch
# (LLR-070.1: green = memory-checked + present).
# ---------------------------------------------------------------------------


def test_at070d_mac_only_unchecked_glyph() -> None:
    for size in _SIZES:

        def _install(app: S19TuiApp, tmp: Path) -> None:
            from s19_app.tui.models import LoadedFile

            app.current_a2l_path = None
            app.current_a2l_data = None
            app.current_file = LoadedFile(
                path=tmp / "only.mac",
                file_type="mac",
                mem_map={},
                row_bases=[],
                ranges=[],
                range_validity=[],
                errors=[],
                a2l_path=None,
                a2l_data=None,
                mac_records=[
                    {
                        "parse_ok": True,
                        "name": "SENSOR_A",
                        "address": 0x1000,
                        "line_number": 1,
                        "parse_error": "",
                    }
                ],
            )

        async def _observe(app: S19TuiApp, pilot: object) -> None:
            plains = [c.plain for c in _mac_cells(app)]
            assert plains, "expected the single MAC-only row rendered"
            assert plains[0].startswith("· "), (
                f"un-image-checked MAC record must render grey '·', not ✓; got {plains!r}"
            )
            assert not plains[0].startswith("✓"), (
                f"MAC-only record must NOT read as a green verified-present ✓; got {plains!r}"
            )

        _drive_mac(size, _install, _observe)


# ---------------------------------------------------------------------------
# AT-071 — coverage strip shows `X of Y` == mac_in_s19 / mac_total; case_02 →
# `1 of 2`; the strip is present whenever a MAC is loaded, both sizes.
# ---------------------------------------------------------------------------


def test_at071_strip() -> None:
    for size in _SIZES:

        async def _observe(app: S19TuiApp, pilot: object) -> None:
            text = _strip_text(app)
            assert "1 of 2" in text, (
                f"strip must show mac_in_s19 of mac_total (1 of 2); got {text!r}"
            )
            assert text.strip(), "coverage strip must be present when a MAC is loaded"

        _drive_mac(size, lambda app, _tmp: _load_case_02(app), _observe)


# ---------------------------------------------------------------------------
# MN-3 / TC-068.5 boundary — mac_total == 0 → `0 of 0`, mac_in_s19_pct → 0.0,
# no divide-by-zero on the microbar (pure builder unit).
# ---------------------------------------------------------------------------


def test_zero_total_no_divzero() -> None:
    empty = CoverageMetrics()
    assert empty.mac_total == 0
    assert empty.mac_in_s19_pct() == 0.0
    strip = build_mac_coverage_strip(empty)  # must not raise ZeroDivisionError
    assert isinstance(strip, Text)
    assert "0 of 0" in strip.plain


def test_build_mac_coverage_strip_counts() -> None:
    strip = build_mac_coverage_strip(
        CoverageMetrics(mac_total=2, mac_in_s19=1, a2l_mac_address_matches=3)
    )
    assert "1 of 2" in strip.plain
    assert "3 matches" in strip.plain
    # numeric-only strip → no payload/markup surface
    assert isinstance(strip, Text)
