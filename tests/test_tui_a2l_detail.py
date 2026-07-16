"""batch-47 US-A2L Explorer MID — black-box acceptance for the A2L insight layer.

Layer B (`AT-NNN`) drives the SHIPPED A2L Explorer screen under Textual Pilot at
**both** 80x24 and 120x30 (sync ``asyncio.run`` wrappers; pytest-asyncio is not
installed — idiom: ``tests/test_validation_service_supplemental.py``) and asserts
the observed rendered content:

- ``AT-068`` — the tag-table name cell carries a leading in-image glyph: ``✓`` on
  an ``in_memory``-True row AND ``·`` on an ``in_memory``-False row (C-10 both
  branches by content).
- ``AT-069`` — highlighting a NON-default row updates the detail card to THAT
  tag's description/unit (C-10(a) operator-selectable driven off the default).
- ``AT-069b`` ★ (gate-blocking C-17) — a hostile description/unit renders
  **verbatim** in the CARD ``Text.plain`` with no payload-derived style and no
  ``MarkupError``.
- ``AT-069c`` ★ (gate-blocking C-17) — a hostile tag NAME renders **verbatim** in
  the TABLE CELL ``Text.plain`` (a DISTINCT sink/builder from the card) with no
  payload-derived style span and no ``MarkupError``.

Layer A units pin the builder contract (``TC-067.1`` every cell is Rich ``Text`` +
correct glyph) and the colored in-image summary (``TC-067.5``).

The C-17 payload set (MD-1) is applied verbatim: ``[red]…[/red]``,
``[link=http://x]u[/link]``, an ANSI escape, and the UNBALANCED ``sensor[unclosed``
— the last is the deliberate ``Text.from_markup`` counterfactual (it passes every
balanced fixture but raises ``MarkupError`` under ``from_markup``). Hostile-input
tests inject the payload as an enriched-tag dict directly into the render path so
the (frozen) A2L parser cannot sanitize it away before the render sink under test.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Awaitable, Callable

from rich.text import Text
from textual.widgets import DataTable

from s19_app.tui.app import A2LDetailCard, S19TuiApp
from s19_app.tui.changes.io import emit_s19_from_mem_map

_SIZES = ((80, 24), (120, 30))

# --- C-17 payload set (MD-1) ------------------------------------------------
_P_BRACKET = "[red]PWNED[/red]"
_P_LINK = "[link=http://x]u[/link]"
_P_ANSI = "\x1b[31mX\x1b[0m"
_P_UNBAL = "sensor[unclosed"
_PAYLOADS = (_P_BRACKET, _P_LINK, _P_ANSI, _P_UNBAL)
_HOSTILE = "".join(_PAYLOADS)


# A mixed A2L: RPM sits inside the loaded S19 image (0x1000), COOLANT is outside
# (0x9000) — so enrichment marks one in_memory=True and one in_memory=False, and
# both carry a description + unit for the detail card.
_MIX_A2L = (
    "/begin PROJECT Demo\n"
    "  /begin MODULE Engine\n"
    '    /begin MEASUREMENT RPM "Engine speed sensor"\n'
    "      ECU_ADDRESS 0x1000\n"
    "      DATA_SIZE 2\n"
    "      LOWER_LIMIT 0\n"
    "      UPPER_LIMIT 7000\n"
    "      UNIT rpm\n"
    "    /end MEASUREMENT\n"
    '    /begin MEASUREMENT COOLANT "Coolant temperature"\n'
    "      ECU_ADDRESS 0x9000\n"
    "      DATA_SIZE 2\n"
    "      UNIT degC\n"
    "    /end MEASUREMENT\n"
    "  /end MODULE\n"
    "/end PROJECT\n"
)


def _write_s19(tmp_path: Path) -> Path:
    """16-byte synthetic S19 image at 0x1000 (covers RPM, not COOLANT)."""
    mem_map = {0x1000 + offset: 0x00 for offset in range(16)}
    text = emit_s19_from_mem_map(mem_map, [(0x1000, 0x1010)])
    path = tmp_path / "img.s19"
    path.write_text(text, encoding="ascii")
    return path


def _write_a2l(tmp_path: Path, text: str, name: str = "tags.a2l") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


class _Evt:
    """Duck-typed ``DataTable.RowHighlighted`` stand-in (idiom:
    ``tests/test_tui_app.py::test_on_data_table_row_selected_routes``)."""

    def __init__(self, table_id: str, key: str) -> None:
        class _T:
            id = table_id

        class _K:
            value = key

        self.data_table = _T()
        self.row_key = _K()


def _hostile_tag(field: str, payload: str) -> dict:
    """An enriched-tag dict with ``payload`` planted in ``field`` and the other
    keys the render path reads populated defensively."""
    tag = {
        "name": "SAFE_NAME",
        "address": 0x1000,
        "length": 2,
        "source": "assigned",
        "raw_value": None,
        "physical_value": None,
        "memory_region": "seg0",
        "lower_limit": 0,
        "upper_limit": 10,
        "unit": "u",
        "bit_org": None,
        "endian": None,
        "virtual": False,
        "function_group": None,
        "access": None,
        "datatype": "UWORD",
        "description": "clean description",
        "conversion": None,
        "record_layout_name": None,
        "effective_byte_order": "little",
        "display_identifier": None,
        "schema_ok": True,
        "memory_checked": True,
        "in_memory": True,
    }
    tag[field] = payload
    return tag


def _drive_mixed(
    size: tuple[int, int],
    observe: Callable[[S19TuiApp, object], Awaitable[None]],
) -> None:
    """Load the mixed S19+A2L through the shipped worker-path chain, show the A2L
    screen, then hand the app to ``observe`` at ``size``."""

    async def _run() -> None:
        import tempfile

        tmp = Path(tempfile.mkdtemp())
        s19_path = _write_s19(tmp)
        a2l_path = _write_a2l(tmp, _MIX_A2L)
        app = S19TuiApp(base_dir=tmp)
        app.current_a2l_path = a2l_path
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            loaded = app._parse_loaded_file(s19_path)
            assert loaded is not None, "shipped parse chain returned no LoadedFile"
            prepared = app._prepare_load_payload(loaded)
            app._apply_prepared_load(prepared, s19_path, 0.0)
            for _ in range(8):
                await pilot.pause()
            app.action_show_screen("a2l")
            for _ in range(4):
                await pilot.pause()
            await observe(app, pilot)

    asyncio.run(_run())


def _drive_bare(
    size: tuple[int, int],
    observe: Callable[[S19TuiApp, object], Awaitable[None]],
) -> None:
    """Boot the app + show the A2L screen (columns initialized) with NO file
    loaded, for hostile-tag injection straight into the render path."""

    async def _run() -> None:
        import tempfile

        tmp = Path(tempfile.mkdtemp())
        app = S19TuiApp(base_dir=tmp)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            app.action_show_screen("a2l")
            for _ in range(4):
                await pilot.pause()
            await observe(app, pilot)

    asyncio.run(_run())


def _name_cells(app: S19TuiApp) -> list[str]:
    table = app.query_one("#a2l_tags_list", DataTable)
    return [str(table.get_row_at(i)[0]) for i in range(table.row_count)]


# ---------------------------------------------------------------------------
# AT-068 — leading in-image glyph column: ✓ on an in_memory row AND · on a
# not-in_memory row (C-10 both branches by content), at both pilot sizes.
# ---------------------------------------------------------------------------


def test_at068_glyph_branches() -> None:
    for size in _SIZES:

        async def _observe(app: S19TuiApp, pilot: object) -> None:
            names = _name_cells(app)
            assert any(n.startswith("✓ ") and "RPM" in n for n in names), (
                f"expected an in-image ✓ row (RPM); got {names!r}"
            )
            assert any(n.startswith("· ") and "COOLANT" in n for n in names), (
                f"expected a not-in-image · row (COOLANT); got {names!r}"
            )

        _drive_mixed(size, _observe)


# ---------------------------------------------------------------------------
# AT-069 — highlighting a NON-default row (row != 0) updates the detail card to
# THAT tag's description/unit; the card content CHANGED off the default hint.
# ---------------------------------------------------------------------------


def test_at069_card_highlight() -> None:
    for size in _SIZES:

        async def _observe(app: S19TuiApp, pilot: object) -> None:
            card = app.query_one("#a2l_detail_card", A2LDetailCard)
            before = card.render().plain
            # locate the COOLANT (non-default) row key from the shipped map
            key = next(
                k
                for k, tag in app._a2l_row_key_to_tag.items()
                if tag.get("name") == "COOLANT"
            )
            assert key != "a2l:0", "COOLANT must be a non-default (row != 0) key"
            app.on_data_table_row_highlighted(_Evt("a2l_tags_list", key))
            await pilot.pause()
            after = card.render().plain
            assert after != before, "card did not change on highlight"
            assert "Coolant temperature" in after, (
                f"card missing highlighted tag description; got {after!r}"
            )
            assert "degC" in after, f"card missing highlighted tag unit; got {after!r}"
            assert "Engine speed sensor" not in after, (
                "card still shows the non-highlighted row's description"
            )

        _drive_mixed(size, _observe)


# ---------------------------------------------------------------------------
# AT-069b ★ (GATE-BLOCKING C-17) — hostile description/unit render verbatim in
# the CARD Text.plain, no payload-derived style, no MarkupError. Injected as an
# enriched-tag dict so the frozen parser cannot sanitize it away.
# ---------------------------------------------------------------------------


def test_at069b_c17_card() -> None:
    for size in _SIZES:

        async def _observe(app: S19TuiApp, pilot: object) -> None:
            tag = _hostile_tag("description", _HOSTILE)
            tag["unit"] = _HOSTILE
            app._a2l_row_key_to_tag = {"a2l:0": tag}
            app.on_data_table_row_highlighted(_Evt("a2l_tags_list", "a2l:0"))
            await pilot.pause()
            card = app.query_one("#a2l_detail_card", A2LDetailCard)
            rendered = card.render()
            plain = rendered.plain
            for payload in _PAYLOADS:
                assert payload in plain, (
                    f"payload {payload!r} not verbatim in card; got {plain!r}"
                )
            # no style span originates from the payload (the developer styles are
            # LABEL/VALUE/etc.; a from_markup regression would inject 'red'/'link')
            styles = " ".join(str(span.style) for span in rendered.spans)
            assert "link" not in styles and "red" not in styles, (
                f"payload-derived style leaked into card spans: {styles!r}"
            )

        # a MarkupError inside compose/update would surface as run_test exception
        _drive_bare(size, _observe)


# ---------------------------------------------------------------------------
# AT-069c ★ (GATE-BLOCKING C-17) — hostile NAME renders verbatim in the TABLE
# CELL Text.plain (distinct builder/path from the card), no payload-derived
# style span, no MarkupError.
# ---------------------------------------------------------------------------


def test_at069c_c17_table_name() -> None:
    for size in _SIZES:

        async def _observe(app: S19TuiApp, pilot: object) -> None:
            tag = _hostile_tag("name", _HOSTILE)
            app.update_a2l_tags_view([tag])
            await pilot.pause()
            table = app.query_one("#a2l_tags_list", DataTable)
            assert table.row_count == 1, "expected the single hostile row rendered"
            name_cell = table.get_row_at(0)[0]
            assert isinstance(name_cell, Text), "table cell must be a Rich Text"
            plain = name_cell.plain
            for payload in _PAYLOADS:
                assert payload in plain, (
                    f"payload {payload!r} not verbatim in cell; got {plain!r}"
                )
            # safe_text builds a base-styled Text with NO spans → no payload span
            assert not name_cell.spans, (
                f"hostile name cell grew spans (markup leak): {name_cell.spans!r}"
            )

        _drive_bare(size, _observe)


# ---------------------------------------------------------------------------
# TC-067.1 — `_build_a2l_table_cells` returns a 16-cell tuple of Rich `Text`
# and the name cell carries ✓ (in_memory True) / · (False).
# ---------------------------------------------------------------------------


def test_cells_are_text_and_glyph(tmp_path: Path) -> None:
    app = S19TuiApp(base_dir=tmp_path)
    in_tag = _hostile_tag("name", "IN_TAG")
    in_tag["in_memory"] = True
    out_tag = _hostile_tag("name", "OUT_TAG")
    out_tag["in_memory"] = False

    in_cells = app._build_a2l_table_cells(in_tag)
    out_cells = app._build_a2l_table_cells(out_tag)

    assert len(in_cells) == 16, "the DataTable expects a 16-cell row"
    assert all(isinstance(cell, Text) for cell in in_cells), "every cell must be Text"
    assert all(isinstance(cell, Text) for cell in out_cells)
    assert in_cells[0].plain.startswith("✓ "), in_cells[0].plain
    assert out_cells[0].plain.startswith("· "), out_cells[0].plain


# ---------------------------------------------------------------------------
# TC-067.5 — `#a2l_tags_summary` shows a colored in-image count equal to the
# number of `in_memory`-truthy tags.
# ---------------------------------------------------------------------------


def test_summary_count() -> None:
    async def _observe(app: S19TuiApp, pilot: object) -> None:
        from textual.widgets import Label

        summary = app.query_one("#a2l_tags_summary", Label)
        plain = summary.render().plain
        # mixed fixture: exactly one tag (RPM) is in image
        assert "1 in image" in plain, f"summary missing in-image count; got {plain!r}"

    _drive_mixed((120, 30), _observe)
