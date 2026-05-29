"""Search-anchor / pagination interaction tests — batch 2026-05-26-batch-05 US-01.

Covers LLR-001.1 / 001.2 / 001.3 / 001.4 — pagination and tag/record selection
clear the search anchor, and a follow-up Find Next then resumes from the first
address currently rendered in the active hex pane via the new
``S19TuiApp._first_visible_hex_address`` helper.

Tiny in-memory ``LoadedFile`` fixtures are used (no ``large_s19``) so the suite
stays on the ``pytest -q -m "not slow"`` lean path.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from textual.widgets import Input

from s19_app.tui import hexview as hexview_module
from s19_app.tui.app import S19TuiApp
from s19_app.tui.models import LoadedFile


def _loaded_s19_dense(tmp_path: Path) -> LoadedFile:
    """A contiguous 256-byte image at 0x1000 with ``HI`` at exactly 0x1000 and 0x1080.

    The body is filled with 0x00 (NUL) so the only matches for the literal
    bytes ``HI`` (0x48 0x49) are at the two seeded addresses. 16 row-bases
    (one per 16-byte stride) so a 4-row page leaves room to page forward past
    the first hit before the second is reached.
    """
    mem: dict[int, int] = {0x1000 + i: 0x00 for i in range(0x100)}
    mem[0x1000] = 0x48
    mem[0x1001] = 0x49
    mem[0x1080] = 0x48
    mem[0x1081] = 0x49
    row_bases = sorted({addr - (addr % 16) for addr in mem})
    return LoadedFile(
        path=tmp_path / "dense.s19",
        file_type="s19",
        mem_map=mem,
        row_bases=row_bases,
        ranges=[(0x1000, 0x10FF)],
        range_validity=[True],
        errors=[],
        a2l_path=None,
        a2l_data=None,
    )


# ---------------------------------------------------------------------------
# LLR-001.1 — pagination clears the search anchor
# ---------------------------------------------------------------------------


def test_main_hex_pagination_clears_search_anchor(tmp_path: Path) -> None:
    """TC-001 — `action_hex_page_next` / `_prev` reset `last_search_address`."""

    async def _drive() -> tuple[object, object]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.current_file = _loaded_s19_dense(tmp_path)
            app.last_search_address = 0xDEAD
            app.action_hex_page_next()
            after_next = app.last_search_address
            app.last_search_address = 0xDEAD
            app.action_hex_page_prev()
            after_prev = app.last_search_address
        return after_next, after_prev

    after_next, after_prev = asyncio.run(_drive())
    assert after_next is None, (
        f"action_hex_page_next must clear last_search_address, got {after_next!r}"
    )
    assert after_prev is None, (
        f"action_hex_page_prev must clear last_search_address, got {after_prev!r}"
    )


# ---------------------------------------------------------------------------
# LLR-001.2 — search after pagination resumes from first visible address
# ---------------------------------------------------------------------------


def test_search_after_pagination_resumes_from_visible_address(
    tmp_path: Path, monkeypatch
) -> None:
    """TC-002 — second Find Next after a page-forward starts from the new page top."""

    captured: list[object] = []
    real_find = hexview_module.find_string_in_mem

    def _spy(mem_map, query, start_address=None):
        captured.append(start_address)
        return real_find(mem_map, query, start_address)

    async def _drive() -> tuple[int, int]:
        app = S19TuiApp(base_dir=tmp_path)
        # Patch the *imported alias* inside app.py so the search handlers
        # actually see the spy (the canonical handle in hexview is bypassed).
        monkeypatch.setattr("s19_app.tui.app.find_string_in_mem", _spy)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.current_file = _loaded_s19_dense(tmp_path)
            # Force the page size to 4 so 0x1080 (row 8) is on the second page.
            app.hex_rows_page_size = 4
            app.query_one("#search_input", Input).value = "HI"
            app._handle_search()  # first hit -> 0x1000
            first_hit = app.last_search_address
            app.action_hex_page_next()  # _hex_window_start -> 4; first visible = 0x1040
            app._handle_search()  # paginated; should seed from 0x1040
            second_hit = app.last_search_address
        return first_hit, second_hit

    first_hit, second_hit = asyncio.run(_drive())
    assert first_hit == 0x1000, f"first Find Next must land on 0x1000, got {first_hit!r}"
    assert second_hit == 0x1080, (
        f"second Find Next after pagination must land on 0x1080, got {second_hit!r}"
    )
    # captured = [None for the first call, then the seeded first-visible addr].
    assert len(captured) >= 2, f"find_string_in_mem must run twice, got {captured!r}"
    assert captured[0] is None, (
        f"first invocation must search from the lowest mem address, got {captured[0]!r}"
    )
    assert captured[1] == 0x1040, (
        f"second invocation must be seeded with the first-visible address 0x1040, "
        f"got {captured[1]!r}"
    )


def test_search_after_pagination_miss_round_trip(
    tmp_path: Path, monkeypatch
) -> None:
    """TC-002b — when a paginated search misses, the anchor stays None and the
    NEXT Find Next is again seeded from the (possibly new) first-visible.
    """

    captured: list[object] = []
    real_find = hexview_module.find_string_in_mem

    def _spy(mem_map, query, start_address=None):
        captured.append(start_address)
        return real_find(mem_map, query, start_address)

    async def _drive() -> object:
        app = S19TuiApp(base_dir=tmp_path)
        monkeypatch.setattr("s19_app.tui.app.find_string_in_mem", _spy)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.current_file = _loaded_s19_dense(tmp_path)
            app.hex_rows_page_size = 4
            # Use a query that won't match anywhere so the search misses.
            app.query_one("#search_input", Input).value = "ZZ"
            app.last_search_text = "ZZ"
            app.last_search_address = None
            app.action_hex_page_next()  # first visible = 0x1040
            app._handle_search()  # paginated; seed = 0x1040; misses -> anchor stays None
            after_miss = app.last_search_address
            # Anchor stayed None: the next call must again seed from first-visible.
            app._handle_search()
        return after_miss

    after_miss = asyncio.run(_drive())
    assert after_miss is None, (
        f"after a paginated miss, anchor must remain None, got {after_miss!r}"
    )
    # First two recorded start_address values must both be the first-visible
    # address (0x1040); neither should fall back to None / 0.
    assert captured[:2] == [0x1040, 0x1040], (
        f"both paginated Find Next calls must be seeded with 0x1040, got {captured!r}"
    )


def test_search_empty_row_bases_fallback(tmp_path: Path, monkeypatch) -> None:
    """TC-002c — empty `row_bases` => helper returns None and `start_address=None`."""

    captured: list[object] = []
    real_find = hexview_module.find_string_in_mem

    def _spy(mem_map, query, start_address=None):
        captured.append(start_address)
        return real_find(mem_map, query, start_address)

    async def _drive() -> object:
        app = S19TuiApp(base_dir=tmp_path)
        monkeypatch.setattr("s19_app.tui.app.find_string_in_mem", _spy)
        async with app.run_test() as pilot:
            await pilot.pause()
            # A LoadedFile whose row_bases is empty even though mem_map has data.
            mem = {0x2000: 0x48, 0x2001: 0x49}
            app.current_file = LoadedFile(
                path=tmp_path / "empty.s19",
                file_type="s19",
                mem_map=mem,
                row_bases=[],
                ranges=[(0x2000, 0x2001)],
                range_validity=[True],
                errors=[],
                a2l_path=None,
                a2l_data=None,
            )
            # Set up a same-query paginated state directly: anchor None, text set.
            app.last_search_text = "HI"
            app.last_search_address = None
            app.query_one("#search_input", Input).value = "HI"
            # Helper short-circuit check: row_bases is empty -> None.
            helper_value = app._first_visible_hex_address("main")
            app._handle_search()
        return helper_value

    helper_value = asyncio.run(_drive())
    assert helper_value is None, (
        f"_first_visible_hex_address must return None on empty row_bases, "
        f"got {helper_value!r}"
    )
    # Even though find_string_in_mem can locate "HI" in the mem_map, the seed
    # must be None (the fallback) — not e.g. 0.
    assert captured and captured[0] is None, (
        f"search handler must pass start_address=None when row_bases is empty, "
        f"got {captured!r}"
    )


# ---------------------------------------------------------------------------
# LLR-001.3 — alt tag selection clears the search anchor
# ---------------------------------------------------------------------------


def test_alt_tag_selection_clears_search_anchor(tmp_path: Path) -> None:
    """TC-003 — `_jump_to_tag_by_data` (and `_jump_to_tag`) reset the anchor."""

    async def _drive() -> tuple[object, object]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.current_file = _loaded_s19_dense(tmp_path)
            app.last_search_address = 0xDEAD
            app._jump_to_tag_by_data({"address": 0x1000})
            after_jump_data = app.last_search_address
            # Re-arm and exercise the legacy ListView adapter path too.
            app.last_search_address = 0xDEAD
            from textual.widgets import ListItem
            item = ListItem()
            item.data = {"tag": {"address": 0x1040}}
            app._jump_to_tag(item)
            after_legacy = app.last_search_address
        return after_jump_data, after_legacy

    after_jump_data, after_legacy = asyncio.run(_drive())
    assert after_jump_data is None, (
        f"_jump_to_tag_by_data must clear last_search_address, got {after_jump_data!r}"
    )
    assert after_legacy is None, (
        f"_jump_to_tag (legacy) must clear last_search_address, got {after_legacy!r}"
    )


# ---------------------------------------------------------------------------
# LLR-001.4 — MAC record selection clears the search anchor
# ---------------------------------------------------------------------------


def test_mac_record_selection_clears_search_anchor(tmp_path: Path) -> None:
    """TC-003b — `_jump_to_mac_address` (the canonical entry-point) resets the anchor."""

    async def _drive() -> object:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.current_file = _loaded_s19_dense(tmp_path)
            app.last_search_address = 0xDEAD
            app._jump_to_mac_address(0x1040)
            return app.last_search_address

    after = asyncio.run(_drive())
    assert after is None, (
        f"_jump_to_mac_address must clear last_search_address, got {after!r}"
    )
