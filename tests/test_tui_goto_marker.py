"""Goto validation + non-color focus-row marker tests — batch 2026-05-26-batch-05 US-03.

Covers HLR-003 / LLR-003.1..003.6:
  * TC-009a / TC-009b — ``render_hex_view_text`` emits the plain ``> `` marker on the
    focus row (and ``  `` elsewhere) with no Rich style on the marker cells, and emits
    no marker at all when ``focus_row_marker_address is None``.
  * TC-007 / TC-008 — ``_handle_goto`` rejects out-of-range addresses (status, no move,
    focus stays None) and records the focus address on a valid hit.
  * TC-010 — the three ``update_*_hex_view`` renderers forward the per-view focus field
    into ``render_hex_view_text`` (monkeypatching the imported alias in ``app.py``).
  * TC-011 — alt/MAC goto-handler parity for both the out-of-range and the valid-hit path.
  * TC-012 — the per-view focus address clears on pagination, new search, parse-error
    goto, tag/record selection, and file-load/unload, but NOT on a pure tab switch.

Tiny in-memory ``LoadedFile`` fixtures (no ``large_s19``) keep the suite on the lean
``pytest -q -m "not slow"`` path.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from rich.style import Style
from textual.widgets import Input

from s19_app.tui.app import S19TuiApp
from s19_app.tui.hexview import HEX_WIDTH, build_row_bases, render_hex_view_text
from s19_app.tui.models import LoadedFile


def _loaded_s19_dense(tmp_path: Path) -> LoadedFile:
    """A contiguous 256-byte image at 0x1000 (range 0x1000..0x10FF).

    16 row-bases (one per 16-byte stride). Addresses below 0x1000 and at/above
    0x1100 are out of range, giving stable in-range / out-of-range goto targets.
    """
    mem: dict[int, int] = {0x1000 + i: 0x41 for i in range(0x100)}
    row_bases = sorted({addr - (addr % HEX_WIDTH) for addr in mem})
    return LoadedFile(
        path=tmp_path / "dense.s19",
        file_type="s19",
        mem_map=mem,
        row_bases=row_bases,
        ranges=[(0x1000, 0x1100)],
        range_validity=[True],
        errors=[],
        a2l_path=None,
        a2l_data=None,
    )


# ---------------------------------------------------------------------------
# TC-009a / TC-009b — render_hex_view_text marker (LLR-003.3, unit)
# ---------------------------------------------------------------------------


def _hex_row_lines(plain: str) -> list[str]:
    """Return only the rendered hex rows (lines whose content carries a 0x address)."""
    return [line for line in plain.splitlines() if "0x" in line]


def test_render_hex_view_text_focus_row_marker_present_on_match() -> None:
    """TC-009a — exactly one row carries the ``> `` prefix, all others ``  ``; no style
    on the leading 2 columns; hex-byte alignment is identical to a marker-less render."""
    mem = {0x1000 + i: 0x41 for i in range(HEX_WIDTH * 4)}
    row_bases = build_row_bases(mem)
    focus = 0x1000 + HEX_WIDTH * 2 + 3  # falls inside the third row (base 0x1020)

    text = render_hex_view_text(
        mem, focus_address=None, row_bases=row_bases, highlight=None,
        focus_row_marker_address=focus,
    )
    plain = text.plain
    rows = _hex_row_lines(plain)

    # Exactly one row prefixed with "> "; every other hex row prefixed with "  ".
    marked = [line for line in rows if line.startswith("> ")]
    assert len(marked) == 1, f"expected exactly 1 marked row, got {len(marked)}: {marked!r}"
    assert "0x00001020" in marked[0], f"marker must land on row 0x1020, got {marked[0]!r}"
    non_marked = [line for line in rows if not line.startswith("> ")]
    assert all(line.startswith("  ") for line in non_marked), (
        f"every non-focus hex row must start with two spaces, got {non_marked!r}"
    )

    # No span applies a non-default style over the leading 2 columns of any row.
    # Compute each row's start offset within text.plain and check span overlap.
    null_style = Style.null()
    offset = 0
    line_offsets: list[tuple[int, str]] = []
    for line in plain.splitlines(keepends=True):
        line_offsets.append((offset, line))
        offset += len(line)
    row_prefix_spans = [(start, start + 2) for start, line in line_offsets if "0x" in line]
    for span in text.spans:
        if span.style is None:
            continue
        resolved = span.style if isinstance(span.style, Style) else Style.parse(str(span.style))
        if resolved == null_style:
            continue
        for ps, pe in row_prefix_spans:
            # A span overlapping the 2-cell prefix region with a non-default style is a violation.
            assert not (span.start < pe and span.end > ps), (
                f"styled span {span!r} overlaps a marker prefix region [{ps}, {pe})"
            )

    # Hex-byte column alignment is identical with and without the marker:
    # stripping the uniform 2-char prefix yields the same body as the marker-less render.
    text_plain_off = render_hex_view_text(
        mem, focus_address=None, row_bases=row_bases, highlight=None,
        focus_row_marker_address=None,
    )
    rows_off = _hex_row_lines(text_plain_off.plain)
    assert [line[2:] for line in rows] == [line[2:] for line in rows_off], (
        "stripping the 2-char marker prefix must reproduce the marker-less row body"
    )


def test_render_hex_view_text_focus_row_marker_absent_when_unset() -> None:
    """TC-009b — with ``focus_row_marker_address=None``, 0 rows carry the ``> `` prefix."""
    mem = {0x1000 + i: 0x41 for i in range(HEX_WIDTH * 4)}
    row_bases = build_row_bases(mem)

    text = render_hex_view_text(
        mem, focus_address=None, row_bases=row_bases, highlight=None,
        focus_row_marker_address=None,
    )
    rows = _hex_row_lines(text.plain)
    assert rows, "fixture must render at least one hex row"
    assert not any(line.startswith("> ") for line in rows), (
        "no row may carry the focus marker when focus_row_marker_address is None"
    )


# ---------------------------------------------------------------------------
# TC-007 / TC-008 — _handle_goto out-of-range + valid-hit (LLR-003.1 / 003.2)
# ---------------------------------------------------------------------------


def test_handle_goto_out_of_range_sets_status_and_does_not_move_view(tmp_path: Path) -> None:
    """TC-007 — out-of-range goto emits the status, does not move the view, leaves focus None."""

    async def _drive() -> tuple[object, str, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.current_file = _loaded_s19_dense(tmp_path)
            move_calls = {"n": 0}
            orig = app.update_hex_view
            app.update_hex_view = lambda *a, **k: (move_calls.__setitem__("n", move_calls["n"] + 1), orig(*a, **k))[1]  # type: ignore[assignment]
            app.query_one("#goto_input", Input).value = "0x9999"
            app._handle_goto()
            return app._goto_focus_address, app.log_lines[-1], move_calls["n"]

    focus, last_status, moves = asyncio.run(_drive())
    assert focus is None, f"out-of-range goto must leave _goto_focus_address None, got {focus!r}"
    assert last_status.startswith("Address 0x"), f"status must start 'Address 0x', got {last_status!r}"
    assert last_status.endswith("not in loaded file."), (
        f"status must end 'not in loaded file.', got {last_status!r}"
    )
    assert moves == 0, f"out-of-range goto must not call update_hex_view, got {moves} calls"


def test_handle_goto_valid_hit_sets_focus_address(tmp_path: Path) -> None:
    """TC-008 — in-range goto records the focus address and moves the view once."""

    async def _drive() -> tuple[object, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.current_file = _loaded_s19_dense(tmp_path)
            move_calls = {"n": 0}
            orig = app.update_hex_view
            app.update_hex_view = lambda *a, **k: (move_calls.__setitem__("n", move_calls["n"] + 1), orig(*a, **k))[1]  # type: ignore[assignment]
            app.query_one("#goto_input", Input).value = "0x1040"
            app._handle_goto()
            return app._goto_focus_address, move_calls["n"]

    focus, moves = asyncio.run(_drive())
    assert focus == 0x1040, f"valid goto must set _goto_focus_address to 0x1040, got {focus!r}"
    assert moves == 1, f"valid goto must call update_hex_view exactly once, got {moves}"


# ---------------------------------------------------------------------------
# TC-010 — update_*_hex_view forward the per-view focus address (LLR-003.4)
# ---------------------------------------------------------------------------


def _capture_focus_kwarg(app: S19TuiApp, monkeypatch) -> list[object]:
    """Monkeypatch the imported ``render_hex_view_text`` alias in app.py to record kwargs."""
    captured: list[object] = []

    def _spy(*args, **kwargs):
        captured.append(kwargs.get("focus_row_marker_address"))
        from s19_app.tui.hexview import render_hex_view_text as real
        return real(*args, **kwargs)

    monkeypatch.setattr("s19_app.tui.app.render_hex_view_text", _spy)
    return captured


def test_goto_focus_marker_forwarded_main(tmp_path: Path, monkeypatch) -> None:
    """TC-010 (main) — update_hex_view forwards _goto_focus_address."""

    async def _drive() -> tuple[list[object], object]:
        app = S19TuiApp(base_dir=tmp_path)
        captured = _capture_focus_kwarg(app, monkeypatch)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.current_file = _loaded_s19_dense(tmp_path)
            app._goto_focus_address = 0x1050
            captured.clear()
            app.update_hex_view(0x1050)
            return captured, app._goto_focus_address

    captured, field = asyncio.run(_drive())
    assert captured and captured[-1] == field == 0x1050, (
        f"update_hex_view must forward _goto_focus_address (0x1050), got {captured!r}"
    )


def test_goto_focus_marker_forwarded_alt(tmp_path: Path, monkeypatch) -> None:
    """TC-010 (alt) — update_alt_hex_view forwards _alt_goto_focus_address."""

    async def _drive() -> tuple[list[object], object]:
        app = S19TuiApp(base_dir=tmp_path)
        captured = _capture_focus_kwarg(app, monkeypatch)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.current_file = _loaded_s19_dense(tmp_path)
            app._alt_goto_focus_address = 0x1060
            captured.clear()
            app.update_alt_hex_view(0x1060)
            return captured, app._alt_goto_focus_address

    captured, field = asyncio.run(_drive())
    assert captured and captured[-1] == field == 0x1060, (
        f"update_alt_hex_view must forward _alt_goto_focus_address (0x1060), got {captured!r}"
    )


def test_goto_focus_marker_forwarded_mac(tmp_path: Path, monkeypatch) -> None:
    """TC-010 (mac) — update_mac_hex_view forwards _mac_goto_focus_address."""

    async def _drive() -> tuple[list[object], object]:
        app = S19TuiApp(base_dir=tmp_path)
        captured = _capture_focus_kwarg(app, monkeypatch)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.current_file = _loaded_s19_dense(tmp_path)
            app._mac_goto_focus_address = 0x1070
            captured.clear()
            app.update_mac_hex_view(0x1070)
            return captured, app._mac_goto_focus_address

    captured, field = asyncio.run(_drive())
    assert captured and captured[-1] == field == 0x1070, (
        f"update_mac_hex_view must forward _mac_goto_focus_address (0x1070), got {captured!r}"
    )


# ---------------------------------------------------------------------------
# TC-011 — alt / MAC goto-handler parity (LLR-003.5)
# ---------------------------------------------------------------------------


def test_handle_goto_alt_out_of_range(tmp_path: Path) -> None:
    """TC-011 (alt, out-of-range) — status emitted, focus stays None."""

    async def _drive() -> tuple[object, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.current_file = _loaded_s19_dense(tmp_path)
            app.query_one("#alt_goto_input", Input).value = "0x9999"
            app._handle_goto_alt()
            return app._alt_goto_focus_address, app.log_lines[-1]

    focus, last_status = asyncio.run(_drive())
    assert focus is None
    assert last_status.startswith("Address 0x") and last_status.endswith("not in loaded file.")


def test_handle_goto_alt_focus(tmp_path: Path) -> None:
    """TC-011 (alt, valid) — _alt_goto_focus_address recorded on a hit."""

    async def _drive() -> object:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.current_file = _loaded_s19_dense(tmp_path)
            app.query_one("#alt_goto_input", Input).value = "0x1040"
            app._handle_goto_alt()
            return app._alt_goto_focus_address

    assert asyncio.run(_drive()) == 0x1040


def test_handle_goto_mac_out_of_range(tmp_path: Path) -> None:
    """TC-011 (mac, out-of-range) — status emitted, focus stays None."""

    async def _drive() -> tuple[object, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.current_file = _loaded_s19_dense(tmp_path)
            app.query_one("#mac_goto_input", Input).value = "0x9999"
            app._handle_goto_mac()
            return app._mac_goto_focus_address, app.log_lines[-1]

    focus, last_status = asyncio.run(_drive())
    assert focus is None
    assert last_status.startswith("Address 0x") and last_status.endswith("not in loaded file.")


def test_handle_goto_mac_focus(tmp_path: Path) -> None:
    """TC-011 (mac, valid) — _mac_goto_focus_address recorded on a hit."""

    async def _drive() -> object:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.current_file = _loaded_s19_dense(tmp_path)
            app.query_one("#mac_goto_input", Input).value = "0x1040"
            app._handle_goto_mac()
            return app._mac_goto_focus_address

    assert asyncio.run(_drive()) == 0x1040


# ---------------------------------------------------------------------------
# TC-012 — focus address cleared on view-mutating events; NOT on tab switch
# (LLR-003.6) — grouped per view to cover the enumerated triggers.
# ---------------------------------------------------------------------------


def test_goto_focus_cleared_main_triggers(tmp_path: Path) -> None:
    """TC-012 (main) — pagination, new search, parse-error goto, file-load, file-unload."""

    async def _drive() -> dict[str, object]:
        app = S19TuiApp(base_dir=tmp_path)
        results: dict[str, object] = {}
        async with app.run_test() as pilot:
            await pilot.pause()
            app.current_file = _loaded_s19_dense(tmp_path)

            # action_hex_page_next
            app._goto_focus_address = 0x1040
            app.action_hex_page_next()
            results["page_next"] = app._goto_focus_address

            # action_hex_page_prev
            app._goto_focus_address = 0x1040
            app.action_hex_page_prev()
            results["page_prev"] = app._goto_focus_address

            # _handle_search with a new term
            app._goto_focus_address = 0x1040
            app.last_search_text = None
            app.query_one("#search_input", Input).value = "AAA"
            app._handle_search()
            results["new_search"] = app._goto_focus_address

            # parse-error branch in _handle_goto
            app._goto_focus_address = 0x1040
            app.query_one("#goto_input", Input).value = "nothex"
            app._handle_goto()
            results["parse_error"] = app._goto_focus_address

            # file-load (replacing current_file goes through _apply_prepared_load)
            app._goto_focus_address = 0x1040
            app._apply_loaded_file(_loaded_s19_dense(tmp_path), tmp_path / "dense.s19", 0.0)
            results["file_load"] = app._goto_focus_address

            # file-unload (current_file None then a re-render)
            app._goto_focus_address = 0x1040
            app.current_file = None
            app.update_hex_view()
            results["file_unload"] = app._goto_focus_address
        return results

    results = asyncio.run(_drive())
    for trigger, value in results.items():
        assert value is None, f"main focus must clear on {trigger}, got {value!r}"


def test_goto_focus_cleared_alt_triggers(tmp_path: Path) -> None:
    """TC-012 (alt) — pagination, tag-jump, tag-find, new search, parse-error, file-load/unload."""

    async def _drive() -> dict[str, object]:
        app = S19TuiApp(base_dir=tmp_path)
        results: dict[str, object] = {}
        async with app.run_test() as pilot:
            await pilot.pause()
            app.current_file = _loaded_s19_dense(tmp_path)
            # Seed filtered tags and a small page so the A2L page actions do real work
            # (they early-return when there is nothing to page).
            app._a2l_filtered_tags = [
                {"name": f"t{i}", "address": 0x1000 + i * 16} for i in range(8)
            ]
            app.a2l_tags_page_size = 4

            app._alt_goto_focus_address = 0x1040
            app.action_a2l_tags_page_next()
            results["a2l_page_next"] = app._alt_goto_focus_address

            app._alt_goto_focus_address = 0x1040
            app.action_a2l_tags_page_prev()
            results["a2l_page_prev"] = app._alt_goto_focus_address

            app._alt_goto_focus_address = 0x1040
            app._jump_to_tag_by_data({"address": 0x1040})
            results["jump_to_tag"] = app._alt_goto_focus_address

            app._alt_goto_focus_address = 0x1040
            app.last_search_text = None
            app.query_one("#alt_search_input", Input).value = "AAA"
            app._handle_search_alt()
            results["new_search_alt"] = app._alt_goto_focus_address

            app._alt_goto_focus_address = 0x1040
            app.query_one("#alt_goto_input", Input).value = "nothex"
            app._handle_goto_alt()
            results["parse_error_alt"] = app._alt_goto_focus_address

            app._alt_goto_focus_address = 0x1040
            app._apply_loaded_file(_loaded_s19_dense(tmp_path), tmp_path / "dense.s19", 0.0)
            results["file_load"] = app._alt_goto_focus_address

            app._alt_goto_focus_address = 0x1040
            app.current_file = None
            app.update_alt_hex_view()
            results["file_unload"] = app._alt_goto_focus_address
        return results

    results = asyncio.run(_drive())
    for trigger, value in results.items():
        assert value is None, f"alt focus must clear on {trigger}, got {value!r}"


def test_goto_focus_cleared_mac_triggers(tmp_path: Path) -> None:
    """TC-012 (mac) — pagination, record-jump, new search, parse-error, file-load/unload."""

    async def _drive() -> dict[str, object]:
        app = S19TuiApp(base_dir=tmp_path)
        results: dict[str, object] = {}
        async with app.run_test() as pilot:
            await pilot.pause()
            app.current_file = _loaded_s19_dense(tmp_path)
            # Seed a MAC record so the page actions don't short-circuit on empty records.
            app.current_file.mac_records = [{"address": 0x1040, "parse_ok": True}]

            app._mac_goto_focus_address = 0x1040
            app.action_mac_records_page_next()
            results["mac_page_next"] = app._mac_goto_focus_address

            app._mac_goto_focus_address = 0x1040
            app.action_mac_records_page_prev()
            results["mac_page_prev"] = app._mac_goto_focus_address

            app._mac_goto_focus_address = 0x1040
            app._jump_to_mac_address(0x1040)
            results["jump_to_mac"] = app._mac_goto_focus_address

            app._mac_goto_focus_address = 0x1040
            app.last_search_text = None
            app.query_one("#mac_search_input", Input).value = "AAA"
            app._handle_search_mac()
            results["new_search_mac"] = app._mac_goto_focus_address

            app._mac_goto_focus_address = 0x1040
            app.query_one("#mac_goto_input", Input).value = "nothex"
            app._handle_goto_mac()
            results["parse_error_mac"] = app._mac_goto_focus_address

            app._mac_goto_focus_address = 0x1040
            app._apply_loaded_file(_loaded_s19_dense(tmp_path), tmp_path / "dense.s19", 0.0)
            results["file_load"] = app._mac_goto_focus_address

            app._mac_goto_focus_address = 0x1040
            app.current_file = None
            app.update_mac_hex_view()
            results["file_unload"] = app._mac_goto_focus_address
        return results

    results = asyncio.run(_drive())
    for trigger, value in results.items():
        assert value is None, f"mac focus must clear on {trigger}, got {value!r}"


def test_goto_focus_not_cleared_on_tab_switch(tmp_path: Path) -> None:
    """TC-012 (positive control) — a pure tab switch must NOT clear the focus address."""

    async def _drive() -> object:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.current_file = _loaded_s19_dense(tmp_path)
            app._goto_focus_address = 0x1040
            # Switch the active view (workspace -> a2l -> mac -> workspace); the main
            # focus address must persist per view across these tab switches.
            app.action_view_alt()
            await pilot.pause()
            app.action_view_mac()
            await pilot.pause()
            app.action_view_main()
            await pilot.pause()
            return app._goto_focus_address

    assert asyncio.run(_drive()) == 0x1040
