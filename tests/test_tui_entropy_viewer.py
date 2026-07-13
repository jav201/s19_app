"""Entropy viewer modal — s19_app batch-26, Increment 3 (US-036 / HLR-036).

Black-box ATs (Layer B) drive the shipped surface through Textual ``Pilot``
(sync-wrapped in ``asyncio.run`` — pytest-asyncio is NOT installed, idiom
``tests/test_tui_patch_layout.py:71-96``): press the ``e`` key on a loaded
image, read the pushed :class:`EntropyViewerScreen`'s strip + jump list, and
observe the jump-to-address focus move.

White-box TCs (Layer A) pin the band→colour map (no ``sev-*`` reuse), the
per-window strip/jump composition, the ``"e"`` binding registration (the
silent-unbind class that shipped in PRs #37/#38), and the ``large_s19``
cost cap.

Fixtures are purpose-built in-memory ``mem_map`` dict literals (exact,
deterministic entropy — §5 of the validation strategy) plus the shipped
``large_s19`` parser fixture for the cost-cap stress.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from rich.text import Text
from textual.widgets import ListView

import s19_app.tui.screens as screens_module
from s19_app.core import S19File
from s19_app.tui.app import S19TuiApp
from s19_app.tui.changes.io import emit_s19_from_mem_map
from s19_app.tui.screens import (
    ENTROPY_BAND_COLOUR,
    ENTROPY_MAX_ROWS,
    EntropyViewerScreen,
)
from s19_app.tui.services.load_service import build_loaded_s19

# --- Fixtures (purpose-built exact-entropy images) -------------------------

# A constant-fill 256-byte run at 0x3000 (band constant/padding, H=0.0) and a
# 0..255 permutation 256-byte run at 0x4000 (band high/random, H=8.0), with an
# unmapped gap between (0x3100..0x3FFF) so the walk yields exactly TWO windows.
_MIXED_MEM_MAP = {
    **{0x3000 + i: 0x00 for i in range(256)},
    **{0x4000 + i: i for i in range(256)},
}
_MIXED_RANGES = [(0x3000, 0x3100), (0x4000, 0x4100)]

# A single 256-byte constant run → exactly one window / one jump row.
_SINGLE_MEM_MAP = {0x2000 + i: 0xFF for i in range(256)}
_SINGLE_RANGES = [(0x2000, 0x2100)]


def _write_image(tmp_path: Path, mem_map: dict, ranges: list, name: str) -> Path:
    """Emit ``mem_map`` as an S19 image on disk via the shipped emitter."""
    text = emit_s19_from_mem_map(mem_map, ranges)
    path = tmp_path / name
    path.write_text(text, encoding="ascii")
    return path


def _load_image(app: S19TuiApp, s19_path: Path) -> None:
    """Install an S19 ``LoadedFile`` snapshot on the app (test shortcut,
    mirrors ``test_tui_patch_editor_v2.py:110-113``)."""
    s19 = S19File(str(s19_path))
    app.current_file = build_loaded_s19(s19_path, s19, a2l_path=None, a2l_data=None)


# ===========================================================================
# AT-036a — GATE — open modal via `e`, strip renders band cells + jump list
#            shows the expected start addresses (LLR-036.1/.2/.3/.4)
# ===========================================================================


def test_at036a_open_modal_strip_and_jump_list(tmp_path: Path) -> None:
    """Load the mixed image, press ``e`` at 80x24, assert the strip cells map
    (semantically) to ``ENTROPY_BAND_COLOUR`` and the jump list shows rows for
    0x3000 and 0x4000 with band + ``H=`` text.

    Counterfactual: before this increment ``e`` is unbound and
    ``action_show_entropy`` / ``EntropyViewerScreen`` do not exist → the key
    press pushes nothing (satisfied by construction; see TC-036.4 for the
    binding pin)."""

    image = _write_image(tmp_path, _MIXED_MEM_MAP, _MIXED_RANGES, "mixed.s19")

    async def _drive() -> tuple[bool, list, list[str], bool]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            _load_image(app, image)
            await pilot.pause()
            app.set_focus(None)
            await pilot.press("e")
            await pilot.pause()
            on_entropy = isinstance(app.screen, EntropyViewerScreen)
            if not on_entropy:
                return False, [], [], False
            # The strip's band colours are read from the screen's own composed
            # Rich Text (reflects push-time state, LLR-036.2); the textual
            # 8.2.8 Static exposes no `.renderable` Rich object to introspect.
            strip_text = app.screen._strip_text()
            spans = [
                (str(span.style), strip_text.plain[span.start : span.end])
                for span in strip_text.spans
            ]
            rows = [
                str(item.query_one("Label").render())
                for item in app.screen.query("#entropy_jump_list > ListItem")
            ]
            strip_present = len(app.screen.query("#entropy_strip")) == 1
            return on_entropy, spans, rows, strip_present

    on_entropy, spans, rows, strip_present = asyncio.run(_drive())
    assert on_entropy, "pressing 'e' with an image loaded did not open the modal"
    assert strip_present, "the entropy strip widget did not render"

    # Semantic style assert: the two band cells carry the entropy-map colours
    # for their windows (constant/padding=grey50, high/random=red), NOT raw
    # literals divorced from the map.
    styles = [style for style, _cell in spans]
    assert ENTROPY_BAND_COLOUR["constant/padding"] in " ".join(styles)
    assert ENTROPY_BAND_COLOUR["high/random"] in " ".join(styles)

    # Jump list: one row per window, expected start addresses + band + H=.
    assert len(rows) == 2
    assert any("0x00003000" in r and "constant/padding" in r and "H=" in r for r in rows)
    assert any("0x00004000" in r and "high/random" in r and "H=" in r for r in rows)


# ===========================================================================
# AT-036b — GATE (C-10 off-default) — activate the SECOND jump row → the
#            main hex focus moves to that window's start (LLR-036.5)
# ===========================================================================


def test_at036b_jump_second_row_moves_focus(tmp_path: Path) -> None:
    """After open, select the second (non-initial) jump row and assert the
    observable focus state CHANGED — the app's ``_goto_focus_address`` moves to
    0x4000 (before ≠ after)."""

    image = _write_image(tmp_path, _MIXED_MEM_MAP, _MIXED_RANGES, "mixed.s19")

    async def _drive() -> tuple[object, object]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _load_image(app, image)
            await pilot.pause()
            app.set_focus(None)
            await pilot.press("e")
            await pilot.pause()
            before = app._goto_focus_address
            jump = app.screen.query_one("#entropy_jump_list", ListView)
            jump.index = 1  # the second window → 0x4000
            jump.action_select_cursor()
            await pilot.pause()
            after = app._goto_focus_address
            return before, after

    before, after = asyncio.run(_drive())
    assert before != after, "jump activation did not change the focus state"
    assert after == 0x4000


# ===========================================================================
# AT-036c — edge — (a) no image loaded → safe empty affordance, no crash;
#            (b) single-window image → exactly one cell + one jump row
# ===========================================================================


def test_at036c_no_image_safe_noop(tmp_path: Path) -> None:
    """(a) Press ``e`` with NO image loaded → no modal pushed, no crash. The
    action is a safe no-op notify (LLR-036.4)."""

    async def _drive() -> bool:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            app.set_focus(None)
            await pilot.press("e")
            await pilot.pause()
            return isinstance(app.screen, EntropyViewerScreen)

    assert asyncio.run(_drive()) is False


def test_at036c_no_image_empty_state_text() -> None:
    """(a') A directly-constructed modal over an empty mem_map exposes the
    positive empty-state affordance (not vacuous — asserts the text)."""
    screen = EntropyViewerScreen({})
    assert screen._windows == []
    assert screen.EMPTY_TEXT  # non-empty affordance string
    assert screen._strip_text().plain == screen.EMPTY_TEXT


def test_at036c_single_window_one_cell_one_row(tmp_path: Path) -> None:
    """(b) A single-window image → exactly one strip cell + one jump row."""

    image = _write_image(tmp_path, _SINGLE_MEM_MAP, _SINGLE_RANGES, "single.s19")

    async def _drive() -> tuple[int, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            _load_image(app, image)
            await pilot.pause()
            app.set_focus(None)
            await pilot.press("e")
            await pilot.pause()
            n_cells = len(app.screen._strip_text().plain.replace("\n", ""))
            n_rows = len(app.screen.query("#entropy_jump_list > ListItem"))
            return n_cells, n_rows

    n_cells, n_rows = asyncio.run(_drive())
    assert n_cells == 1
    assert n_rows == 1


# ===========================================================================
# TC-036.1 — band→colour map has the 4 documented entries + no `sev-*`
#            (LLR-036.1)
# ===========================================================================


def test_tc036_1_band_colour_map_and_no_sev(tmp_path: Path) -> None:
    """The map holds exactly the four documented bands mapped to distinct
    colours, and the band-cell path never references a ``sev-*`` class."""
    assert set(ENTROPY_BAND_COLOUR) == {
        "constant/padding",
        "low",
        "medium",
        "high/random",
    }
    # Four distinct colours, none of them a `sev-*` severity class.
    assert len(set(ENTROPY_BAND_COLOUR.values())) == 4
    assert not any("sev-" in colour for colour in ENTROPY_BAND_COLOUR.values())

    # Grep-guard: the band-cell CODE path must not reuse the severity classes
    # (LLR-036.1 / QR-6). Scope the guard to code-bearing lines (drop the
    # docstring / comment lines, which legitimately NAME `sev-*` to say they
    # are deliberately NOT used).
    src = (
        Path(__file__).resolve().parents[1] / "s19_app" / "tui" / "screens.py"
    ).read_text(encoding="utf-8")
    start = src.index("class EntropyViewerScreen")
    end = src.index("def _parse_declared_regions", start)
    entropy_block = src[start:end]
    # No severity-class helper is called, and no `sev-` string LITERAL appears
    # in the code (quoted). Prose mentions in docstrings/comments are excluded.
    assert "css_class_for_severity" not in entropy_block
    assert '"sev-' not in entropy_block
    assert "'sev-" not in entropy_block
    assert "SEVERITY_CLASS_MAP" not in entropy_block


# ===========================================================================
# TC-036.2 — N windows → N strip cells (up to the cap) with per-cell band
#            styling (LLR-036.2)
# ===========================================================================


def test_tc036_2_strip_cell_per_window() -> None:
    """A three-window mem_map composes three styled strip cells, one per
    band present."""
    mem_map = {
        **{0x1000 + i: 0x00 for i in range(256)},  # constant/padding
        **{0x1100 + i: (i % 4) for i in range(256)},  # low (2 bits)
        **{0x1200 + i: i for i in range(256)},  # high/random
    }
    screen = EntropyViewerScreen(mem_map)
    assert len(screen._windows) == 3
    strip = screen._strip_text()
    assert isinstance(strip, Text)
    assert len(strip.plain) == 3  # three cells
    assert len(strip.spans) == 3  # each cell independently styled
    styles = " ".join(str(span.style) for span in strip.spans)
    assert ENTROPY_BAND_COLOUR["constant/padding"] in styles
    assert ENTROPY_BAND_COLOUR["low"] in styles
    assert ENTROPY_BAND_COLOUR["high/random"] in styles


# ===========================================================================
# TC-036.3 — jump list builds one row per window in the `0xADDR  band  H=`
#            shape (LLR-036.2)
# ===========================================================================


def test_tc036_3_jump_rows_documented_shape(tmp_path: Path) -> None:
    """One jump row per window, each in the documented
    ``0xXXXXXXXX  <band>  H=<h>`` shape."""

    image = _write_image(tmp_path, _MIXED_MEM_MAP, _MIXED_RANGES, "mixed.s19")

    async def _drive() -> list[str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _load_image(app, image)
            await pilot.pause()
            app.set_focus(None)
            await pilot.press("e")
            await pilot.pause()
            return [
                str(item.query_one("Label").render())
                for item in app.screen.query("#entropy_jump_list > ListItem")
            ]

    rows = asyncio.run(_drive())
    assert len(rows) == 2
    for row in rows:
        assert row.startswith("0x")
        assert "H=" in row
    assert rows[0].startswith("0x00003000")
    assert rows[1].startswith("0x00004000")


# ===========================================================================
# TC-036.4 — silent-unbind guard (white-box): `e` in BINDINGS → show_entropy
#            (LLR-036.4; the class of bug that shipped in PRs #37/#38)
# ===========================================================================


def test_tc036_4_e_binding_registered() -> None:
    """``"e"`` is a registered binding mapping to ``show_entropy`` and the
    action method exists — pin the binding at registration, not just at open."""
    bound = {
        b.key: b.action
        for b in S19TuiApp.BINDINGS
        if hasattr(b, "key")  # Binding objects (not bare tuples)
    }
    assert "e" in bound, "the 'e' key is not registered in BINDINGS"
    assert bound["e"] == "show_entropy"
    assert callable(getattr(S19TuiApp, "action_show_entropy", None))


# ===========================================================================
# TC-036.5 — per-page render cap on large_s19: page 0 renders at most one
#            512-window page, and the `page P/Q` position indicator is present
#            (LLR-062.1 — REDEFINED from the batch-26 truncation semantics: the
#            512 cap is now the per-page render BUDGET, not a dataset drop, and
#            the former `#entropy_truncated` indicator is `#entropy_page_indicator`
#            reading `page 1/Q` with Q>1; the cap still bounds per-page cost)
# ===========================================================================


def test_tc036_5_cost_cap_and_truncation(large_s19: Path) -> None:
    """On the 200x4KB ``large_s19`` image (>>512 windows), page 0 renders at
    most ``ENTROPY_MAX_ROWS`` strip cells and jump rows (the per-page budget
    still bounds cost) AND a ``page P/Q`` position
    indicator is present with Q > 1 (the tail is reachable by paging, not
    silently dropped — the batch-37 US-062 redefinition of the batch-26
    truncation node, Q-02)."""

    s19 = S19File(str(large_s19))
    loaded = build_loaded_s19(large_s19, s19, a2l_path=None, a2l_data=None)

    screen = EntropyViewerScreen(loaded.mem_map)
    # Precondition: the image genuinely exceeds one page (else the test is
    # vacuous — it would pass for a tiny image too).
    assert len(screen._windows) > ENTROPY_MAX_ROWS

    strip = screen._strip_text()
    assert len(strip.plain) <= ENTROPY_MAX_ROWS

    async def _drive() -> tuple[int, int, bool, str]:
        from s19_app.tui.app import S19TuiApp

        app = S19TuiApp(base_dir=large_s19.parent)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.current_file = loaded
            await pilot.pause()
            app.set_focus(None)
            await pilot.press("e")
            await pilot.pause()
            n_cells = len(app.screen._strip_text().plain)
            n_rows = len(app.screen.query("#entropy_jump_list > ListItem"))
            indicator = app.screen.query("#entropy_page_indicator")
            present = len(indicator) == 1
            text = str(indicator.first().render()) if present else ""
            return n_cells, n_rows, present, text

    n_cells, n_rows, present, text = asyncio.run(_drive())
    assert n_cells <= ENTROPY_MAX_ROWS
    assert n_rows <= ENTROPY_MAX_ROWS
    assert present, "no page indicator shown when window count exceeds one page"
    # `page 1/Q` with Q > 1 — the tail is reachable by paging, not truncated.
    assert text.startswith("page 1/")
    total_pages = int(text.split("/", 1)[1])
    assert total_pages > 1, f"expected multiple pages, got {text!r}"


def test_tc036_5_truncation_fires_on_either_cap(
    large_s19: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The page indicator's total-page count tracks the FIXED per-page budget
    (LLR-062.1 — REDEFINED from the batch-26 ``min()`` either-cap guard, Q-02).
    Shrinking the per-page window budget (``ENTROPY_MAX_ROWS``) below the real
    window count must produce MORE pages in ``page 1/Q`` — the cap still bounds
    per-page render, but no window is dropped (every window is reachable by
    paging). Monkeypatches the module-level budget (never edits its production
    VALUE) so the page slice is small and Q grows accordingly."""

    s19 = S19File(str(large_s19))
    loaded = build_loaded_s19(large_s19, s19, a2l_path=None, a2l_data=None)

    n_windows = len(EntropyViewerScreen(loaded.mem_map)._windows)
    assert n_windows > 2, "large_s19 must yield enough windows to page"

    small_budget = n_windows // 4  # force ~4 pages
    assert small_budget >= 1
    monkeypatch.setattr(screens_module, "ENTROPY_MAX_ROWS", small_budget)
    expected_pages = (n_windows + small_budget - 1) // small_budget

    async def _drive() -> tuple[int, str]:
        app = S19TuiApp(base_dir=large_s19.parent)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.current_file = loaded
            await pilot.pause()
            app.set_focus(None)
            await pilot.press("e")
            await pilot.pause()
            n_rows = len(app.screen.query("#entropy_jump_list > ListItem"))
            text = str(app.screen.query_one("#entropy_page_indicator").render())
            return n_rows, text

    n_rows, text = asyncio.run(_drive())
    # The per-page render is bounded by the (shrunken) budget — the cap still
    # bounds cost — and Q reflects the smaller budget (more pages, no drop).
    assert n_rows <= small_budget
    assert text == f"page 1/{expected_pages}", (
        "page indicator must track the FIXED per-page budget — a smaller "
        "budget yields more pages, never a silent drop of the tail"
    )


# ===========================================================================
# US-062 (batch-37) — entropy viewer pagination + sort
# ===========================================================================

# A three-band exact-entropy image: a constant 256-byte run (H=0.0,
# constant/padding), a 2-bit run (H=2.0, low), and a 0..255 permutation
# (H=8.0, high/random), each in its own contiguous 256-byte range so the walk
# yields exactly THREE windows with distinct, strictly-ordered entropies.
_BANDS_MEM_MAP = {
    **{0x1000 + i: 0x00 for i in range(256)},  # constant/padding, H=0.0
    **{0x1100 + i: (i % 4) for i in range(256)},  # low, H=2.0
    **{0x1200 + i: i for i in range(256)},  # high/random, H=8.0
}
_BANDS_RANGES = [(0x1000, 0x1100), (0x1100, 0x1200), (0x1200, 0x1300)]

# Two equal-entropy (H=0.0) constant runs + one high run, for the stable
# tie-break assertion (equal entropy → ascending start).
_TIE_MEM_MAP = {
    **{0x1000 + i: 0x00 for i in range(256)},  # constant, H=0.0
    **{0x1200 + i: 0x00 for i in range(256)},  # constant, H=0.0 (tie)
    **{0x1400 + i: i for i in range(256)},  # high/random, H=8.0
}


# ---------------------------------------------------------------------------
# AT-062a — page past the 512-window cap to reach (and dismiss with) a later
#           window (US-062, LLR-062.1). Runs at BOTH 80x24 and 120x30 in the
#           one node (C-18). CF: today `self._windows[:512]` truncates and a
#           window with index >= 512 is unreachable.
# ---------------------------------------------------------------------------


def test_at062a_page_past_cap_reaches_later_window(large_s19: Path) -> None:
    """With > 512 windows, one page advance reaches page 2 (windows
    ``[512, 1024)``); a window whose index >= 512 is now listed and selecting
    it dismisses with THAT window's address — reachable only because the 512
    cap is now a per-page budget, not a dataset truncation."""

    s19 = S19File(str(large_s19))
    loaded = build_loaded_s19(large_s19, s19, a2l_path=None, a2l_data=None)

    def _drive(size: tuple[int, int]):
        async def _run():
            app = S19TuiApp(base_dir=large_s19.parent)
            async with app.run_test(size=size) as pilot:
                await pilot.pause()
                app.current_file = loaded
                await pilot.pause()
                app.set_focus(None)
                await pilot.press("e")
                await pilot.pause()
                screen = app.screen
                assert isinstance(screen, EntropyViewerScreen)
                assert len(screen._windows) > ENTROPY_MAX_ROWS, (
                    "large_s19 must exceed one page for this test to be real"
                )
                # First window of page 2 under the default address sort.
                expected = sorted(screen._windows, key=lambda w: w.start)[
                    ENTROPY_MAX_ROWS
                ]
                page0_rows = [
                    str(i.query_one("Label").render())
                    for i in screen.query("#entropy_jump_list > ListItem")
                ]
                # Advance one page via the real PgDn binding (close button has
                # focus, so the key bubbles to the screen binding).
                await pilot.press("pagedown")
                await pilot.pause()
                page1_rows = [
                    str(i.query_one("Label").render())
                    for i in screen.query("#entropy_jump_list > ListItem")
                ]
                indicator = str(
                    screen.query_one("#entropy_page_indicator").render()
                )
                # Select row 0 of page 2 → dismiss with the later window addr.
                jump = screen.query_one("#entropy_jump_list", ListView)
                jump.index = 0
                jump.action_select_cursor()
                await pilot.pause()
                return page0_rows, page1_rows, indicator, app._goto_focus_address, expected.start

        return asyncio.run(_run())

    for size in ((80, 24), (120, 30)):
        page0_rows, page1_rows, indicator, focus_after, expected_start = _drive(size)
        addr = f"0x{expected_start:08X}"
        assert not any(addr in r for r in page0_rows), (
            f"{addr} must NOT appear on page 1 at {size}"
        )
        assert any(addr in r for r in page1_rows), (
            f"{addr} (index >= 512) must be reachable on page 2 at {size}"
        )
        assert indicator.startswith("page 2/"), (
            f"expected page 2/Q indicator at {size}, got {indicator!r}"
        )
        assert focus_after == expected_start, (
            f"selecting the later window must dismiss with its address at {size}"
        )


# ---------------------------------------------------------------------------
# AT-062b — sort by entropy reorders strip + jump list so the top row is the
#           highest-entropy window (US-062, LLR-062.2). Runs at BOTH sizes.
#           CF: today the top row is the lowest-address window.
# ---------------------------------------------------------------------------


def test_at062b_sort_entropy_top_row_is_max(tmp_path: Path) -> None:
    """Toggling sort to entropy puts the MAX-entropy window at jump row 0 and
    the strip's first cell carries that window's band colour; the pager resets
    to page 0. Asserts CONTENT (row 0 == the actual extremal window), not that
    a row merely changed."""

    image = _write_image(tmp_path, _BANDS_MEM_MAP, _BANDS_RANGES, "bands.s19")

    def _drive(size: tuple[int, int]):
        async def _run():
            app = S19TuiApp(base_dir=tmp_path)
            async with app.run_test(size=size) as pilot:
                await pilot.pause()
                _load_image(app, image)
                await pilot.pause()
                app.set_focus(None)
                await pilot.press("e")
                await pilot.pause()
                screen = app.screen
                assert isinstance(screen, EntropyViewerScreen)
                max_w = max(screen._windows, key=lambda w: w.entropy)
                before_rows = [
                    str(i.query_one("Label").render())
                    for i in screen.query("#entropy_jump_list > ListItem")
                ]
                # Toggle sort via the real `s` binding.
                await pilot.press("s")
                await pilot.pause()
                after_rows = [
                    str(i.query_one("Label").render())
                    for i in screen.query("#entropy_jump_list > ListItem")
                ]
                strip = screen._strip_text()
                first_style = str(strip.spans[0].style) if strip.spans else ""
                return (
                    before_rows,
                    after_rows,
                    max_w.start,
                    max_w.entropy,
                    max_w.band,
                    first_style,
                    screen._sort_key,
                    screen._page,
                )

        return asyncio.run(_run())

    for size in ((80, 24), (120, 30)):
        (
            before_rows,
            after_rows,
            max_start,
            max_entropy,
            max_band,
            first_style,
            sort_key,
            page,
        ) = _drive(size)
        assert sort_key == "entropy"
        assert page == 0, "sort toggle must reset the pager to page 0"
        # CF: address-order top row is the lowest address (0x1000, H=0).
        assert before_rows[0].startswith("0x00001000")
        # Entropy sort: top row is the MAX-entropy window (content assert).
        assert after_rows[0].startswith(f"0x{max_start:08X}")
        assert f"H={max_entropy:.2f}" in after_rows[0]
        # Strip cell order follows the same permutation — first cell = max band.
        assert ENTROPY_BAND_COLOUR[max_band] in first_style


# ---------------------------------------------------------------------------
# TC-324 — page-slice math: page size fixed, page count, slice bounds, clamp,
#          `page P/Q` indicator, and the shared row→window bound (LLR-062.1)
# ---------------------------------------------------------------------------


def test_tc324_page_slice_math(monkeypatch: pytest.MonkeyPatch) -> None:
    """White-box the paging arithmetic over a 3-window image with the per-page
    budget monkeypatched to 2 → two pages. Pins the slice, the clamp, the
    indicator text, and the ``0 <= row < len(page)`` resolver bound."""
    monkeypatch.setattr(screens_module, "ENTROPY_MAX_ROWS", 2)
    screen = EntropyViewerScreen(_BANDS_MEM_MAP)
    assert len(screen._windows) == 3
    assert screen._page_size() == 2
    assert screen._page_count() == 2  # ceil(3/2)

    # Page 0 slice = the first two display (address-sorted) windows.
    assert [w.start for w in screen._page_slice()] == [0x1000, 0x1100]
    assert screen._page_indicator_text() == "page 1/2"

    # Page 1 slice = the remaining window; the tail is reachable, not dropped.
    screen._page = 1
    assert [w.start for w in screen._page_slice()] == [0x1200]
    assert screen._page_indicator_text() == "page 2/2"

    # Union of all page slices == all windows (no window unreachable).
    all_starts = set()
    for p in range(screen._page_count()):
        screen._page = p
        all_starts.update(w.start for w in screen._page_slice())
    assert all_starts == {0x1000, 0x1100, 0x1200}

    # Clamp: over-run pins to the last page, under-run to page 0.
    assert screen._clamp_page(9) == 1
    assert screen._clamp_page(-3) == 0

    # Resolver bound (S-03): in-range rows resolve, out-of-range → None.
    screen._page = 1
    assert screen._window_for_row(0).start == 0x1200
    assert screen._window_for_row(5) is None
    assert screen._window_for_row(None) is None


# ---------------------------------------------------------------------------
# TC-325 — sort-key function: entropy desc + ascending-start tie-break, no
#          mutation of self._windows, and the shared (sort,page,row)→window
#          remap under a non-default sort (LLR-062.2, Q-04)
# ---------------------------------------------------------------------------


def test_tc325_sort_key_no_mutation_and_remap() -> None:
    """The display sort is a COPY (self._windows untouched); entropy sort is
    descending with a stable ascending-``start`` tie-break; and the shared
    ``_window_for_row`` resolves rows correctly under the entropy sort."""
    screen = EntropyViewerScreen(_TIE_MEM_MAP)
    original = [w.start for w in screen._windows]
    assert len(original) == 3

    # Default address sort → ascending start.
    assert [w.start for w in screen._display_windows()] == [0x1000, 0x1200, 0x1400]

    # Entropy sort → max first, then the two H=0 ties in ascending start.
    screen._sort_key = "entropy"
    disp = screen._display_windows()
    assert disp[0].start == 0x1400  # the sole max-entropy window
    assert [w.start for w in disp[1:]] == [0x1000, 0x1200]  # stable tie-break

    # self._windows (the computation snapshot) is NOT mutated.
    assert [w.start for w in screen._windows] == original

    # Shared remap under entropy sort, page 0: row → the display window.
    assert screen._window_for_row(0).start == 0x1400
    assert screen._window_for_row(2).start == 0x1200
    assert screen._window_for_row(99) is None


# ===========================================================================
# US-063 (batch-37) — entropy band legend + clickable strip
# ===========================================================================


# ---------------------------------------------------------------------------
# AT-063a — the entropy modal shows a band-colour legend mapping EACH
#           ENTROPY_BAND_COLOUR band to its meaning + the low-confidence cue
#           (US-063, LLR-063.1). CF: no legend widget exists in compose today.
# ---------------------------------------------------------------------------


def test_at063a_band_legend_present_with_meanings(tmp_path: Path) -> None:
    """Open the modal at 80x24; assert `#entropy_legend` renders one row per
    band with the ACTUAL band→meaning text (content, not just a heading) plus
    the low-confidence (dim) cue. Also asserts the legend content is available
    for an EMPTY image (it documents the colour vocabulary, window-independent
    — AT-063a boundary)."""

    image = _write_image(tmp_path, _MIXED_MEM_MAP, _MIXED_RANGES, "mixed.s19")

    async def _drive() -> tuple[bool, list[str]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            _load_image(app, image)
            await pilot.pause()
            app.set_focus(None)
            await pilot.press("e")
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, EntropyViewerScreen)
            present = len(screen.query("#entropy_legend")) == 1
            rows = [
                str(label.render())
                for label in screen.query("#entropy_legend Label")
            ]
            return present, rows

    present, rows = asyncio.run(_drive())
    assert present, "the entropy band legend did not render in the modal"
    joined = " ".join(rows)

    band_meaning = screens_module.ENTROPY_BAND_MEANING
    for band, meaning in band_meaning.items():
        assert band in joined, f"legend missing band label {band!r}"
        assert meaning in joined, f"legend missing meaning text for {band!r}"
    # The low-confidence (dim) cue is documented alongside the four bands.
    assert EntropyViewerScreen.LOW_CONFIDENCE_MEANING in joined

    # Boundary: the legend content is window-independent (renders for 0 windows).
    empty = EntropyViewerScreen({})
    empty_plain = " ".join(line.plain for line in empty._legend_lines())
    for band in ENTROPY_BAND_COLOUR:
        assert band in empty_plain


# ---------------------------------------------------------------------------
# AT-063b — a REAL pointer click on a per-cell strip widget (#entropy_cell_k)
#           dismisses the modal with THAT cell's window address, correct under
#           a non-default sort state (US-063, LLR-063.2, C-16). CF: today the
#           strip is a plain Static — a click posts nothing.
# ---------------------------------------------------------------------------


def test_at063b_click_strip_cell_dismisses_with_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Drive the actual `pilot.click("#entropy_cell_k")` (never a proxy call to
    the action) after toggling to a non-default (entropy) sort with a shrunken
    per-page budget, and assert the modal dismissed with the SPECIFIC address of
    the clicked cell's window — proving the click→window remap is correct under
    sort+page. Clicks the FIRST and the LAST cell of the visible page (the
    classic off-by-one edges)."""

    image = _write_image(tmp_path, _BANDS_MEM_MAP, _BANDS_RANGES, "bands.s19")
    # Force two pages over the 3-window image so the click path is exercised
    # under a non-trivial page slice (never edits the production value).
    monkeypatch.setattr(screens_module, "ENTROPY_MAX_ROWS", 2)

    def _drive_click(cell_id: str) -> object:
        async def _run() -> object:
            app = S19TuiApp(base_dir=tmp_path)
            async with app.run_test(size=(80, 24)) as pilot:
                await pilot.pause()
                _load_image(app, image)
                await pilot.pause()
                app.set_focus(None)
                await pilot.press("e")
                await pilot.pause()
                screen = app.screen
                assert isinstance(screen, EntropyViewerScreen)
                # Non-default sort state (resets to page 0): entropy-desc order
                # is [0x1200 (H=8), 0x1100 (H=2), 0x1000 (H=0)]; page 0 slice
                # (budget 2) = [0x1200, 0x1100].
                await pilot.press("s")
                await pilot.pause()
                await pilot.pause()
                assert screen._sort_key == "entropy"
                assert screen._page == 0
                await pilot.click(cell_id)
                await pilot.pause()
                return app._goto_focus_address

        return asyncio.run(_run())

    # First cell of the sorted page → the max-entropy window (0x1200).
    assert _drive_click("#entropy_cell_0") == 0x1200
    # Last cell of the visible page → the second window in the slice (0x1100).
    assert _drive_click("#entropy_cell_1") == 0x1100


# ---------------------------------------------------------------------------
# TC-326 — legend↔ENTROPY_BAND_COLOUR anti-drift: one row per band (derived,
#          not hardcoded), meanings non-blank + free of `[`/`]` markup, not the
#          severity LEGEND_TABLE (LLR-063.1, S-03 authoring pin)
# ---------------------------------------------------------------------------


def test_tc326_legend_derived_from_band_colour() -> None:
    """The legend rows are DERIVED from `ENTROPY_BAND_COLOUR` (the single
    source): the band set matches exactly, so a band added to the colour map
    without a meaning fails here; every meaning is non-blank and carries no
    Textual markup metacharacter; and the legend never references a `sev-*`
    severity class (the colour domain is the viewer's own, not
    `LEGEND_TABLE`)."""
    screen = EntropyViewerScreen({})  # legend is window-independent
    lines = screen._legend_lines()
    # Exactly one row per band + one low-confidence (dim) row.
    assert len(lines) == len(ENTROPY_BAND_COLOUR) + 1

    # Anti-drift: the meaning map's band set == ENTROPY_BAND_COLOUR keys.
    assert set(screens_module.ENTROPY_BAND_MEANING) == set(ENTROPY_BAND_COLOUR)

    plains = [line.plain for line in lines]
    joined = " ".join(plains)
    for band, meaning in screens_module.ENTROPY_BAND_MEANING.items():
        assert band in joined, f"legend missing band {band!r}"
        assert meaning.strip(), f"blank meaning for band {band!r}"
    # No markup metacharacters (the row may render markup-enabled — S-03 pin).
    for line in plains:
        assert "[" not in line and "]" not in line, f"markup metachar in {line!r}"
    # The entropy legend is NOT the severity table — no `sev-*` class leaks in.
    assert "sev-" not in joined


# ---------------------------------------------------------------------------
# TC-327 — per-cell click → shared (sort,page,row)→window remap → dismiss, incl.
#          the S-03 `0 <= row < len(page)` bound (LLR-063.2, Q-04). White-box:
#          `action_jump` routes through `_window_for_row` and dismisses with the
#          sorted-view window's start; an out-of-range click is a no-op.
# ---------------------------------------------------------------------------


def test_tc327_action_jump_remap_and_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    """`action_jump(row)` resolves the row through the shared
    `_window_for_row` helper under the CURRENT sort + page and dismisses with
    that window's `start`; an out-of-range / None row dismisses nothing (S-03
    bound → a click on padding beyond the last cell is a safe no-op)."""
    monkeypatch.setattr(screens_module, "ENTROPY_MAX_ROWS", 2)
    screen = EntropyViewerScreen(_BANDS_MEM_MAP)
    assert callable(getattr(EntropyViewerScreen, "action_jump", None))

    dismissed: list = []
    monkeypatch.setattr(screen, "dismiss", lambda value=None: dismissed.append(value))

    # Address sort, page 0 (budget 2): row 0 → 0x1000, row 1 → 0x1100.
    screen.action_jump(0)
    screen.action_jump(1)
    # Page 1: the tail window is reachable via the click path too.
    screen._page = 1
    screen.action_jump(0)  # → 0x1200
    # Entropy sort, page 0: row 0 → the max-entropy window (0x1200).
    screen._page = 0
    screen._sort_key = "entropy"
    screen.action_jump(0)
    # S-03 bound: out-of-range / None rows dismiss NOTHING.
    screen.action_jump(5)
    screen.action_jump(None)

    assert dismissed == [0x1000, 0x1100, 0x1200, 0x1200]


# ===========================================================================
# Geometry — no rendered line exceeds the modal inner width (<=48 @80,
#            <=76 @120) (LLR-036.3)
# ===========================================================================


def _modal_dialog_right(tmp_path: Path, size: tuple[int, int]) -> tuple[int, int]:
    image = _write_image(tmp_path, _MIXED_MEM_MAP, _MIXED_RANGES, "mixed.s19")

    async def _drive() -> tuple[int, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            _load_image(app, image)
            await pilot.pause()
            app.set_focus(None)
            await pilot.press("e")
            await pilot.pause()
            dlg = app.screen.query_one("#entropy_dialog")
            # US-063: the strip is now a `Horizontal` of per-cell widgets (was a
            # `Static`); query by id (type-agnostic) so the bounds check holds
            # under the new widget type — the assertion (region within the
            # terminal width, LLR-036.3) is unchanged.
            strip = app.screen.query_one("#entropy_strip")
            return dlg.region.right, strip.region.right

    return asyncio.run(_drive())


def test_geometry_fits_80(tmp_path: Path) -> None:
    """At 80x24 the dialog and the strip stay within the terminal width — no
    horizontal overflow (LLR-036.3, 48-col content budget)."""
    dlg_right, strip_right = _modal_dialog_right(tmp_path, (80, 24))
    assert dlg_right <= 80, f"dialog clipped at 80: right={dlg_right}"
    assert strip_right <= 80, f"strip clipped at 80: right={strip_right}"


def test_geometry_fits_120(tmp_path: Path) -> None:
    """At 120x30 the dialog and the strip stay within the terminal width
    (LLR-036.3, 76-col content budget)."""
    dlg_right, strip_right = _modal_dialog_right(tmp_path, (120, 30))
    assert dlg_right <= 120, f"dialog clipped at 120: right={dlg_right}"
    assert strip_right <= 120, f"strip clipped at 120: right={strip_right}"
