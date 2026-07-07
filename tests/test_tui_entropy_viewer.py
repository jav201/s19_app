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
from textual.widgets import ListView, Static

import s19_app.tui.screens as screens_module
from s19_app.core import S19File
from s19_app.tui.app import S19TuiApp
from s19_app.tui.changes.io import emit_s19_from_mem_map
from s19_app.tui.screens import (
    ENTROPY_BAND_COLOUR,
    ENTROPY_MAX_ROWS,
    ENTROPY_STRIP_MAX_CELLS,
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
# TC-036.5 — cost cap on large_s19: strip cells <= cap, jump rows <= cap,
#            truncation indicator present (LLR-036.6)
# ===========================================================================


def test_tc036_5_cost_cap_and_truncation(large_s19: Path) -> None:
    """On the 200x4KB ``large_s19`` image (>>512 windows), the strip renders
    at most ``ENTROPY_STRIP_MAX_CELLS`` cells, the jump list at most
    ``ENTROPY_MAX_ROWS`` rows, and a truncation indicator is present."""

    s19 = S19File(str(large_s19))
    loaded = build_loaded_s19(large_s19, s19, a2l_path=None, a2l_data=None)

    screen = EntropyViewerScreen(loaded.mem_map)
    # Precondition: the image genuinely exceeds the caps (else the test is
    # vacuous — it would pass for a tiny image too).
    assert len(screen._windows) > ENTROPY_STRIP_MAX_CELLS
    assert len(screen._windows) > ENTROPY_MAX_ROWS

    strip = screen._strip_text()
    assert len(strip.plain) <= ENTROPY_STRIP_MAX_CELLS

    async def _drive() -> tuple[int, int]:
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
            truncated = len(app.screen.query("#entropy_truncated")) == 1
            return n_cells, (n_rows, truncated)

    n_cells, (n_rows, truncated) = asyncio.run(_drive())
    assert n_cells <= ENTROPY_STRIP_MAX_CELLS
    assert n_rows <= ENTROPY_MAX_ROWS
    assert truncated, "no truncation indicator shown when window count exceeds caps"


def test_tc036_5_truncation_fires_on_either_cap(
    large_s19: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The truncation indicator must fire when EITHER cap is exceeded, not
    both (LLR-036.6). This pins the ``min()`` guard in ``compose``: with the
    two caps set UNEQUAL — strip cap below the window count while the row cap
    stays above it — the ``max()`` form would suppress the indicator, but
    ``min()`` still shows it because the strip surface truncates.

    Monkeypatches the module-level cap constants (never edits their production
    VALUES) so the strip cap sits below the real window count and the row cap
    sits above it, then asserts the indicator is still present.
    """

    s19 = S19File(str(large_s19))
    loaded = build_loaded_s19(large_s19, s19, a2l_path=None, a2l_data=None)

    n_windows = len(EntropyViewerScreen(loaded.mem_map)._windows)
    assert n_windows > 2, "large_s19 must yield enough windows to straddle caps"

    low_cap = n_windows - 1  # strip truncates
    high_cap = n_windows + 1  # jump list does NOT truncate
    monkeypatch.setattr(screens_module, "ENTROPY_STRIP_MAX_CELLS", low_cap)
    monkeypatch.setattr(screens_module, "ENTROPY_MAX_ROWS", high_cap)

    async def _drive() -> bool:
        app = S19TuiApp(base_dir=large_s19.parent)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.current_file = loaded
            await pilot.pause()
            app.set_focus(None)
            await pilot.press("e")
            await pilot.pause()
            return len(app.screen.query("#entropy_truncated")) == 1

    truncated = asyncio.run(_drive())
    assert truncated, (
        "indicator must fire when only ONE cap is exceeded — the min() guard "
        "enforces the either-cap rule (a max() guard would suppress it here)"
    )


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
            strip = app.screen.query_one("#entropy_strip", Static)
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
