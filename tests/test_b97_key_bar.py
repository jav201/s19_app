"""Batch-97 Inc-8 — the two-row key bar on every window (HLR-150).

TC-B97-66..72 (LLR-150.1..150.7) and AT-B97-25 / AT-B97-26. Every painted
claim reads the compositor strips (``tests/b97_probes.py``): the bar's rows
as painted text, the colours as painted cell styles. Every wait is bounded
(``settled`` / ``poll``); the repaint arms allow 3 pauses — a few
milliseconds — so a polling timer (the prototype's 0.5 s) cannot pass them.

On ``main`` the bar is the shipped one-row ``Footer``: the row readers fall
back to it, so the RED of each node names the clause ``main`` breaks
(``perio▏``, no ``? Help`` with the focus in a window, one row).
"""
from __future__ import annotations

import ast
import asyncio
import re
from pathlib import Path

import pytest

from s19_app.tui.app import S19TuiApp
from tests.b97_fixtures import (
    DEMO_A2L,
    EXAMPLES_DIR,
    calib_hotfix,
    load_change_file,
    open_check_editor,
    open_patch_editor,
)
from tests.b97_probes import painted_rows, painted_style, settle, settled

ROOT = Path(__file__).resolve().parents[1]
SIZES = ((118, 54), (220, 60))
GLOBAL_TEXTS = (
    "^k Palette", "^d Density", "^l Load file", "^s Save project", "x Operations", "? Help", "q Quit",
    "^p palette",
)
#: The `.db-screen-title` pair and the accent (styles.tcss token block).
TAG_FG, TAG_BG, ACCENT = "#0a0e1b", "#91abec", "#91abec"
#: Colours that must never paint in the key bar (waiting, CRC, Textual's warning).
RESERVED = {"#e8ad3d", "#c9562b", "#f6ff8f"}
#: The `main` container height at 118x54 (P-68) and at 220x60 (Inc-8's RED run
#: on 9793fcd, `evidence/inc-8/red.txt`).
MAIN_CONTAINER_ROWS = {(118, 54): 42, (220, 60): 48}
#: Row 1 at 80x24 (operator decision at the Inc-8 gate, LED-…97.38): with the
#: longer `Load file` / `Save project` labels `q Quit` and `^p palette` drop;
#: row 1 never paints `? more` (LLR-150.2) — `? Help` lists every binding.
GLOBAL_TEXTS_80 = GLOBAL_TEXTS[:6]
#: Rows that bound the repaint after a state change: no timer can meet it.
REPAINT_PAUSES = 3


def _windows() -> tuple:
    return tuple(S19TuiApp.SCREEN_CONTAINER_IDS) + ("split_join",)


def _bindings():
    from textual.binding import Binding

    return [b if isinstance(b, Binding) else Binding(*b) for b in S19TuiApp.BINDINGS]


def _rail_key(window: str):
    for binding in _bindings():
        if binding.action == f"show_screen('{window}')":
            return binding
    return None


def _tag(window: str) -> str:
    binding = _rail_key(window)
    if binding is not None:
        return binding.description
    return dict((a, l) for l, a in S19TuiApp.EXTRA_PALETTE_ENTRIES)["open_split_join_export"]


def _container(app, window: str):
    return app.query_one(f"#{app.SCREEN_CONTAINER_IDS.get(window, 'screen_' + window)}")


def focus_rail(app) -> None:
    """Put the focus on the activity rail (its first item; ``Rail`` itself is
    not focusable) without switching windows."""
    from s19_app.tui.rail import RailItem

    app.query(RailItem).first().focus()


async def show(app, pilot, window: str) -> None:
    if window == "split_join":
        app.action_open_split_join_export()
    else:
        app.action_show_screen(window)
    await settle(pilot, 3)


def bar_regions(app) -> list:
    """The key bar's row regions — on ``main`` the Footer's single row."""
    from textual.widgets import Footer

    rows = list(app.query("#key_bar KeyRow"))
    if rows:
        return [row.region for row in rows]
    return [footer.region for footer in app.query(Footer)]


def bar_rows(app) -> list:
    return [painted_rows(app, None, region)[0] for region in bar_regions(app)]


def pieces(row: str) -> list:
    """Split a painted row into its tokens (tokens are separated by two
    spaces; a go separator ``· go`` / ``go`` is stripped from its token)."""
    out = []
    for part in re.split(r" {2,}", row.strip()):
        for lead in ("· go ", "go "):
            if part.startswith(lead):
                part = part[len(lead):]
        if part:
            out.append(part)
    return out


def piece_x(row: str, piece: str, start: int = 0) -> int:
    return row.index(piece, start)


def _hex(color) -> str:
    if color is None:
        return ""
    triplet = color.get_truecolor()
    return triplet.hex.lower()


def window_tokens(app, window: str):
    from s19_app.tui.window_help import resolve_window_tokens

    return resolve_window_tokens(app, window)


def allowed_texts(app, window: str) -> set:
    tokens, go = window_tokens(app, window)
    return (
        {f"{t.key_display} {t.label}" for t in (*tokens, *go)}
        | {_tag(window), "? more"}
    )


# --------------------------------------------------------------------------- #
# TC-B97-66 — LLR-150.1, one table feeds row 2 and the help
# --------------------------------------------------------------------------- #


def test_tc_b97_66_table_covers_the_13_windows_and_resolves(tmp_path: Path) -> None:
    """TC-B97-66 (LLR-150.1): the table's window set is the 12 rail windows
    plus ``split_join``; every entry and go key resolves to a binding whose
    description is its label; the five rendered rows hold >= 15 entries and
    >= 9 go keys.

    RED on main (P-62): ``window_help`` holds no key table.
    """
    from s19_app.tui import window_help as wh

    assert hasattr(wh, "WINDOW_KEYS"), "window_help holds the window-key table"
    expected = set(S19TuiApp.SCREEN_CONTAINER_IDS) | {"split_join"}
    assert set(wh.WINDOW_KEYS) == expected and set(wh.WINDOW_GO_KEYS) == expected

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(118, 54)) as pilot:
            await settle(pilot)
            return {w: window_tokens(app, w) for w in _windows()}

    resolved = asyncio.run(_drive())
    by_key = {b.key: b for b in _bindings()}
    for window, (tokens, go) in resolved.items():
        assert len(tokens) == len(wh.WINDOW_KEYS[window]) and len(go) == len(wh.WINDOW_GO_KEYS[window])
        for token in (*tokens, *go):
            assert token.label, (window, token)
            if token.owner is None:
                assert token.label == by_key[token.key].description, (window, token)
    rendered = ("workspace", "patch", "check_editor", "flow", "flow_execution")
    assert sum(len(resolved[w][0]) for w in rendered) >= 15
    assert sum(len(resolved[w][1]) for w in rendered) >= 9


@pytest.mark.parametrize("fault", ["unbound", "empty"])
def test_tc_b97_66_unbound_key_or_empty_description_raises_at_mount(
    tmp_path: Path, monkeypatch, fault: str
) -> None:
    """TC-B97-66 invalid arm: an entry naming an unbound key, or a binding with
    an empty description, makes the key bar's mount raise.

    RED on main: no table to patch (``KeyEntry`` absent)."""
    from textual.binding import Binding

    from s19_app.tui import window_help as wh

    entries = dict(wh.WINDOW_KEYS)
    if fault == "unbound":
        entries["map"] = (wh.KeyEntry("f13"),)
        expected = KeyError
    else:
        monkeypatch.setattr(S19TuiApp, "BINDINGS", [*S19TuiApp.BINDINGS, Binding("f13", "noop", "")])
        entries["map"] = (wh.KeyEntry("f13"),)
        expected = ValueError
    monkeypatch.setattr(wh, "WINDOW_KEYS", entries)

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(118, 54)) as pilot:
            await settle(pilot)

    with pytest.raises(expected):
        asyncio.run(_drive())


def test_tc_b97_66_help_keys_block_is_generated_from_the_table(tmp_path: Path) -> None:
    """TC-B97-66 (LLR-150.1, help): every help section mapped to a window shows
    a keys block whose ``key — label`` lines equal the table's entries for that
    window (set-equal); no key line is also a hand-typed step; the steps body
    is still ``section_body_text`` alone; Reports shows no block and Split /
    Join / Export shows ``split_join``'s.

    RED on main: no keys block, ``c — Confirm`` / ``ctrl+z — Undo`` typed by
    hand. Mutation: a hand-typed block with another label.
    """
    from textual.widgets import Static

    from s19_app.tui import window_help as wh

    mapping = getattr(wh, "HELP_KEY_WINDOW", None)
    assert mapping is not None, "the help-key -> window table exists"
    assert mapping["split_join_export"] == "split_join"
    assert mapping["reports"] is None and mapping["changes_file_notation"] is None
    assert set(mapping) == set(wh.WINDOW_HELP_SECTIONS)

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        out = {}
        async with app.run_test(size=(220, 60)) as pilot:
            await settle(pilot)
            for key in wh.WINDOW_HELP_SECTIONS:
                assert wh.open_window_help(app, key)
                await settle(pilot, 2)
                modal = app.screen
                body = str(modal.query_one("#window_help_body", Static).render())
                blocks = modal.query("#window_help_keys")
                block = str(blocks.first(Static).render()) if blocks else None
                window = mapping[key]
                tokens = window_tokens(app, window)[0] if window else ()
                out[key] = (body, block, tokens)
                modal.dismiss(None)
                await settle(pilot, 2)
        return out

    readings = asyncio.run(_drive())
    for key, (body, block, tokens) in readings.items():
        assert body == wh.section_body_text(key), f"{key}: the steps body changed"
        expected = {f"{t.key_display} — {t.label}" for t in tokens}
        if not expected:
            assert block is None, f"{key}: a keys block with no entries"
            continue
        lines = {line.strip() for line in block.split("\n") if " — " in line}
        assert lines == expected, (key, lines, expected)
        step_labels = {
            step.split(" — ", 1)[0].strip()
            for step in wh.WINDOW_HELP_SECTIONS[key]["steps"]
            if " — " in step
        }
        twice = step_labels & ({t.key_display for t in tokens} | {t.key for t in tokens})
        assert not twice, f"{key}: keys described twice: {sorted(twice)}"
    assert readings["reports"][1] is None
    assert readings["split_join_export"][1] is not None


def test_tc_b97_66_map_help_names_only_keys_that_act_on_the_map(tmp_path: Path) -> None:
    """TC-B97-66 (operator decision at the Inc-8 gate, LED-…97.41): every key
    a Memory Map help step quotes (a backticked token) acts on the Map — a
    global key of row 1 or a key of the Map's row 2.

    RED on the pre-fold tree: the md-ported steps quote `+` `-` `,` `.` `g`,
    none of which acts on the Map (D28 disables the first four there)."""
    from s19_app.tui.window_help import WINDOW_HELP_SECTIONS, global_tokens

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(118, 54)) as pilot:
            await settle(pilot)
            tokens, go = window_tokens(app, "map")
            return {t.key_display.lower() for t in (*global_tokens(app), *tokens, *go)}

    acting = asyncio.run(_drive())
    quoted = {
        q.lower() for step in WINDOW_HELP_SECTIONS["map"]["steps"]
        for q in re.findall(r"`([^`]{1,3})`", step)
    }
    assert quoted - acting == set(), f"Map help quotes keys that do not act on the Map: {sorted(quoted - acting)}"


def test_tc_b97_66_table_stores_no_labels() -> None:
    """TC-B97-66: the table literal holds key names, selectors and conditions
    only, and the key-bar code's only label literals are ``more`` and
    ``palette``.

    Mutation: a label typed into an entry; a third painter literal."""
    from s19_app.tui import window_help as wh

    source = (ROOT / "s19_app" / "tui" / "window_help.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    allowed = {b.key for b in _bindings()} | {"has_image", "patch_history", "has_variants"}
    for owner in ("#check_param_table", "#ab_diff_panel", "#screen_split_join"):
        allowed.add(owner)
    from s19_app.tui.screens_directionb import AbDiffPanel, IncludeTable
    from s19_app.tui.segment_split_view import SplitJoinWindow

    for cls in (AbDiffPanel, IncludeTable, SplitJoinWindow):
        allowed |= {b.key for b in cls.BINDINGS}
    table_names = {"GLOBAL_KEYS", "WINDOW_KEYS", "WINDOW_GO_KEYS"}
    strings = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(t, ast.Name) and t.id in table_names for t in targets):
                strings += [
                    c.value for c in ast.walk(node.value)
                    if isinstance(c, ast.Constant) and isinstance(c.value, str)
                ]
    assert strings, "the table literals were found"
    stray = sorted(set(strings) - allowed - set(wh.WINDOW_KEYS))
    assert stray == [], f"strings in the table that are no key name: {stray}"
    labels = sorted(
        kw.value.value for node in ast.walk(tree) if isinstance(node, ast.Call)
        for kw in node.keywords
        if kw.arg == "label" and isinstance(kw.value, ast.Constant)
    )
    assert labels == ["more", "palette"], labels


# --------------------------------------------------------------------------- #
# TC-B97-67 — LLR-150.2, row 1
# --------------------------------------------------------------------------- #


def _first_control(app, window: str):
    for widget in _container(app, window).query("*"):
        if widget.focusable and widget.region.width and widget.display:
            return widget
    return None


@pytest.mark.parametrize("size", SIZES, ids=["118x54", "220x60"])
def test_tc_b97_67_row_one_is_the_eight_globals_whatever_the_focus(tmp_path: Path, size) -> None:
    """TC-B97-67 (LLR-150.2): on each of the 13 windows, with the focus on the
    rail, on the window's first control and in a text ``Input`` (the command
    palette's), row 1 paints exactly the 8 global tokens in order and never
    ``? more``; every key-glyph cell paints ``footer-key-foreground``.

    RED on main (P-61, P-67): with the focus inside a window the Footer paints
    no ``? Help``, and at 118x54 it ends ``perio▏``.
    """
    
    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        out = []
        async with app.run_test(size=size) as pilot:
            await settle(pilot)
            key_fg = app.get_css_variables()["footer-key-foreground"].lower()
            for window in _windows():
                await show(app, pilot, window)
                for focus in ("rail", "control", "input"):
                    if focus == "rail":
                        focus_rail(app)
                    elif focus == "control":
                        # A window with no file shows an empty state with no
                        # focusable control (Issues, Map, Checks): no arm there.
                        control = _first_control(app, window)
                        if control is None:
                            continue
                        control.focus()
                    else:
                        app.action_focus_palette()
                    await settle(pilot, 2)
                    row = bar_rows(app)[0]
                    y = bar_regions(app)[0].y
                    x0 = bar_regions(app)[0].x
                    glyphs = set()
                    start = 0
                    for piece in pieces(row):
                        x = piece_x(row, piece, start)
                        start = x + len(piece)
                        key = piece.split(" ", 1)[0]
                        for i in range(len(key)):
                            glyphs.add(_hex(painted_style(app, x0 + x + i, y).color))
                    out.append((window, focus, pieces(row), glyphs, key_fg))
                    if focus == "input":
                        app.query_one("#command_palette").add_class("hidden")
                        focus_rail(app)
                        await settle(pilot, 2)
        return out

    readings = asyncio.run(_drive())
    assert sum(1 for _w, focus, *_r in readings if focus == "control") >= 9, "control arms ran"
    for window, focus, row, glyphs, key_fg in readings:
        assert row == list(GLOBAL_TEXTS), (window, focus, row)
        assert "? more" not in row
        assert glyphs == {key_fg}, (window, focus, glyphs, key_fg)


def test_tc_b97_67_row_one_at_80x24_drops_palette_whole(tmp_path: Path) -> None:
    """TC-B97-67 boundary: at 80x24 (the 97-cell row is wider than the bar)
    row 1 paints the first 6 tokens in order — ``? Help`` kept, mandatory —
    with ``q Quit`` and ``^p palette`` dropped whole and no ``? more``.

    RED on main: the Footer crops a token (``perio▏``)."""

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            await settle(pilot)
            out = {}
            for window in _windows():
                await show(app, pilot, window)
                out[window] = pieces(bar_rows(app)[0])
            return out

    for window, row in asyncio.run(_drive()).items():
        assert row == list(GLOBAL_TEXTS_80), (window, row)


# --------------------------------------------------------------------------- #
# TC-B97-68 — LLR-150.3, row 2: tag, keys, go keys, colours
# --------------------------------------------------------------------------- #


def test_tc_b97_68_row_two_tag_tokens_and_colours(tmp_path: Path) -> None:
    """TC-B97-68 (LLR-150.3): per window row 2 starts with the window's rail
    description in bold ``#0a0e1b`` on ``#91abec``; enabled descriptions paint
    ``#91abec``; key glyphs paint the row-1 key colour; the background is
    ``footer-background``; no reserved colour paints in the bar; the go
    separator reads `` · go`` after window keys and `` go`` without.

    RED on main: no second row (one Footer). Mutation: the tag in the
    description pair.
    """

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        out = {}
        async with app.run_test(size=(220, 60)) as pilot:
            await settle(pilot)
            css = app.get_css_variables()
            colours = (css["footer-key-foreground"].lower(), css["footer-background"].lower())
            for window in _windows():
                await show(app, pilot, window)
                regions = bar_regions(app)
                assert len(regions) == 2, f"{window}: the key bar has two rows, got {len(regions)}"
                rows = bar_rows(app)
                region = regions[1]
                row = rows[1]
                cells = {}
                for x in range(region.width):
                    style = painted_style(app, region.x + x, region.y)
                    cells[x] = style
                every = {
                    _hex(s.color) for r in regions for x in range(r.width)
                    if (s := painted_style(app, r.x + x, r.y)) is not None
                } | {
                    _hex(s.bgcolor) for r in regions for x in range(r.width)
                    if (s := painted_style(app, r.x + x, r.y)) is not None
                }
                out[window] = (row, cells, every, colours)
        return out

    for window, (row, cells, every, (key_fg, bar_bg)) in asyncio.run(_drive()).items():
        tag = _tag(window)
        tokens = pieces(row)
        assert tokens[0] == tag, (window, tokens)
        tag_x = piece_x(row, tag)
        for x in range(tag_x, tag_x + len(tag)):
            assert (_hex(cells[x].color), _hex(cells[x].bgcolor), bool(cells[x].bold)) == (TAG_FG, TAG_BG, True), (window, x)
        start = tag_x + len(tag)
        for piece in tokens[1:]:
            x = piece_x(row, piece, start)
            start = x + len(piece)
            key, label = piece.split(" ", 1)
            if _hex(cells[x].color) != key_fg:
                # a dimmed token (a false condition): both halves blended
                assert {_hex(cells[label_x].color) for label_x in [x + len(key) + 1]} != {ACCENT}, (window, piece)
                continue
            assert {_hex(cells[x + i].color) for i in range(len(key))} == {key_fg}, (window, piece)
            label_x = x + len(key) + 1
            assert {_hex(cells[label_x + i].color) for i in range(len(label))} == {ACCENT}, (window, piece)
        assert _hex(cells[len(row) - 1].bgcolor) == bar_bg, (window, "row background")
        assert not (every & RESERVED), (window, every & RESERVED)


def test_tc_b97_68_go_separator_switch_and_modal(tmp_path: Path) -> None:
    """TC-B97-68: `` · go`` on Patch / Check / Flow Execution, `` go`` on the
    Flow Builder; after each rail key the new tag paints within the repaint
    bound (no timer); after the Patch Editor help modal is dismissed row 2 is
    its reading before the modal.

    RED on main: no row 2."""
    from s19_app.tui.window_help import open_window_help

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        out = {"sep": {}, "switch": [], "modal": None}
        async with app.run_test(size=(220, 60)) as pilot:
            await settle(pilot)
            assert len(bar_regions(app)) == 2, "the key bar has two rows"
            for window in ("patch", "check_editor", "flow_execution", "flow"):
                await show(app, pilot, window)
                out["sep"][window] = bar_rows(app)[1]
            for window in S19TuiApp.SCREEN_CONTAINER_IDS:
                focus_rail(app)
                await settle(pilot, 1)
                await pilot.press(_rail_key(window).key)
                tag = _tag(window)
                await settled(
                    pilot, lambda: pieces(bar_rows(app)[1])[:1] == [tag],
                    f"row 2 shows {tag}", attempts=REPAINT_PAUSES,
                )
                out["switch"].append(window)
            await show(app, pilot, "patch")
            before = bar_rows(app)[1]
            open_window_help(app, "patch")
            await settle(pilot, 2)
            app.screen.dismiss(None)
            await settled(pilot, lambda: bar_rows(app)[1] == before, "row 2 back after the modal", attempts=REPAINT_PAUSES)
            out["modal"] = (before, bar_rows(app)[1])
        return out

    out = asyncio.run(_drive())
    for window in ("patch", "check_editor", "flow_execution"):
        assert " · go " in out["sep"][window], (window, out["sep"][window])
    flow = out["sep"]["flow"]
    assert "· go" not in flow and f"{_tag('flow')}  go " in flow, flow
    assert out["switch"] == list(S19TuiApp.SCREEN_CONTAINER_IDS)
    assert out["modal"][0] == out["modal"][1]


def test_tc_b97_68_no_hex_literal_in_the_key_bar_code() -> None:
    """TC-B97-68: no ``#rrggbb`` string literal in ``window_help.py`` (every
    key-bar colour comes from its component classes in ``styles.tcss``).

    Mutation: a hex colour written into the painter."""
    tree = ast.parse((ROOT / "s19_app" / "tui" / "window_help.py").read_text(encoding="utf-8"))
    hexes = [
        node.value for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
        and re.search(r"#[0-9a-fA-F]{6}\b", node.value)
    ]
    assert hexes == [], hexes


# --------------------------------------------------------------------------- #
# TC-B97-69 — LLR-150.4, keys not handled are neither painted nor live; dims
# --------------------------------------------------------------------------- #

#: PC-26: each derived row's entries with the guard they were read from — the
#: file, the function or class attribute that holds the guard (``Class.name``)
#: and the guard's text. The test locates the text inside that node with
#: ``ast`` (no fixed line), and checks that the key's binding reaches it: an
#: app key's action method contains the guard node's name, directly or
#: through at most two ``self.<method>(`` hops; an owned key is bound in the
#: guard's own class ``BINDINGS``.
APP_PY, SDB_PY, SJ_PY = "s19_app/tui/app.py", "s19_app/tui/screens_directionb.py", "s19_app/tui/segment_split_view.py"
DERIVED_GUARDS = (
    ("a2l", "slash", APP_PY, "S19TuiApp._FIND_GOTO_INPUTS", '"a2l": ("alt_search_input", "alt_goto_input"),'),
    ("a2l", "g", APP_PY, "S19TuiApp._FIND_GOTO_INPUTS", '"a2l": ("alt_search_input", "alt_goto_input"),'),
    ("a2l", "plus", APP_PY, "S19TuiApp.action_page_next_context", "self.action_a2l_tags_page_next()"),
    ("a2l", "minus", APP_PY, "S19TuiApp.action_page_prev_context", "self.action_a2l_tags_page_prev()"),
    ("a2l", "d", APP_PY, "S19TuiApp.action_a2l_describe_tag", 'if self._active_screen_key != "a2l" or not self.current_a2l_data:'),
    ("a2l", "k", APP_PY, "S19TuiApp._SCREEN_LEGEND_SECTIONS", '"a2l": ("A2L",),'),
    ("mac", "slash", APP_PY, "S19TuiApp._FIND_GOTO_INPUTS", '"mac": ("mac_search_input", "mac_goto_input"),'),
    ("mac", "g", APP_PY, "S19TuiApp._FIND_GOTO_INPUTS", '"mac": ("mac_search_input", "mac_goto_input"),'),
    ("mac", "plus", APP_PY, "S19TuiApp.action_page_next_context", "self.action_mac_records_page_next()"),
    ("mac", "minus", APP_PY, "S19TuiApp.action_page_prev_context", "self.action_mac_records_page_prev()"),
    ("mac", "k", APP_PY, "S19TuiApp._SCREEN_LEGEND_SECTIONS", '"mac": ("MAC",),'),
    ("map", "k", APP_PY, "S19TuiApp._SCREEN_LEGEND_SECTIONS", '"map": (),'),
    ("issues", "pagedown", APP_PY, "S19TuiApp.action_page_down_context", "self.action_validation_issues_page_next()"),
    ("issues", "pageup", APP_PY, "S19TuiApp.action_page_up_context", "self.action_validation_issues_page_prev()"),
    ("issues", "k", APP_PY, "S19TuiApp._SCREEN_LEGEND_SECTIONS", '"issues": ("Issues",),'),
    ("diff", "k", APP_PY, "S19TuiApp._SCREEN_LEGEND_SECTIONS", '"diff": ("Hex",),'),
    ("diff", "f", SDB_PY, "AbDiffPanel.BINDINGS", 'Binding("f", "toggle_run_overlay", "Run list", show=False),'),
    ("diff", "escape", SDB_PY, "AbDiffPanel.BINDINGS", 'Binding("escape", "close_run_overlay", "Close the run list", show=False),'),
    ("diff", "right_square_bracket", SDB_PY, "AbDiffPanel.BINDINGS", 'Binding("right_square_bracket", "page_window_down", "Window page +", show=False),'),
    ("diff", "left_square_bracket", SDB_PY, "AbDiffPanel.BINDINGS", 'Binding("left_square_bracket", "page_window_up", "Window page -", show=False),'),
    ("checks", "k", APP_PY, "S19TuiApp._SCREEN_LEGEND_SECTIONS", '"checks": ("Issues",),'),
    ("split_join", "space", SJ_PY, "SplitJoinWindow.BINDINGS", 'Binding("space", "toggle_row", "Tick", show=False),'),
    ("split_join", "a", SJ_PY, "SplitJoinWindow.BINDINGS", 'Binding("a", "select_all", "All", show=False),'),
    ("split_join", "n", SJ_PY, "SplitJoinWindow.BINDINGS", 'Binding("n", "select_none", "None", show=False),'),
    ("split_join", "t", SJ_PY, "SplitJoinWindow.BINDINGS", 'Binding("t", "cycle_tab", "Source", show=False),'),
    ("split_join", "m", SJ_PY, "SplitJoinWindow.BINDINGS", 'Binding("m", "toggle_mode", "Mode", show=False),'),
    ("split_join", "g", SJ_PY, "SplitJoinWindow.BINDINGS", 'Binding("g", "cycle_gap", "Gap", show=False),'),
    ("split_join", "f", SJ_PY, "SplitJoinWindow.BINDINGS", 'Binding("f", "cycle_format", "Format", show=False),'),
    ("split_join", "p", SJ_PY, "SplitJoinWindow.BINDINGS", 'Binding("p", "cycle_pad", "Pad", show=False),'),
    ("split_join", "d", SJ_PY, "SplitJoinWindow.BINDINGS", 'Binding("d", "cycle_dest", "Dest", show=False),'),
    ("split_join", "e", SJ_PY, "SplitJoinWindow.BINDINGS", 'Binding("e", "export", "Export", show=False),'),
    ("split_join", "escape", SJ_PY, "SplitJoinWindow.BINDINGS", 'Binding("escape", "close_window", "Close", show=False),'),
)
#: The derived windows whose row is empty, with the guard that leaves them out
#: (no find / go-to input; no legend section of their own).
DERIVED_EMPTY = (("crc_designer", APP_PY, "S19TuiApp._FIND_GOTO_INPUTS", '"crc_designer": None,'),)
DERIVED = ("a2l", "mac", "map", "issues", "diff", "checks", "crc_designer", "split_join")


def _node_source(rel: str, qualname: str):
    """(source text, first line) of the function or class attribute
    ``Class.name`` in ``rel``, located with ``ast``."""
    source = (ROOT / rel).read_text(encoding="utf-8")
    tree = ast.parse(source)
    cls_name, name = qualname.split(".")
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == cls_name)
    for node in cls.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return ast.get_source_segment(source, node), node.lineno
        targets = node.targets if isinstance(node, ast.Assign) else [node.target] if isinstance(node, ast.AnnAssign) else []
        if any(isinstance(t, ast.Name) and t.id == name for t in targets):
            return ast.get_source_segment(source, node), node.lineno
    raise AssertionError(f"{qualname} not found in {rel}")


def _reaches(action: str, target: str, hops: int = 2) -> bool:
    """``action_<action>`` of the app names ``target`` directly or through at
    most ``hops`` ``self.<method>(`` calls."""
    import inspect

    method = getattr(S19TuiApp, f"action_{action}", None) or getattr(S19TuiApp, action, None)
    if method is None:
        return False
    body = inspect.getsource(method)
    if target in body:
        return True
    if hops == 0:
        return False
    return any(
        _reaches(callee, target, hops - 1)
        for callee in set(re.findall(r"self\.(\w+)\(", body))
        if callee != action and hasattr(S19TuiApp, callee)
    )


def test_tc_b97_69_derived_rows_follow_their_guards() -> None:
    """TC-B97-69 / PC-26: each derived row is exactly the keys whose guard is
    recorded above, in order, with no go keys; each guard text sits inside its
    named function or attribute (located by ``ast``, not by line); and each
    key's binding reaches its guard — an app key's action names the guard
    node (≤ 2 method hops), an owned key is bound in the guard's class.

    RED on main: no table. Mutation: a guard moved out of its function; a key
    added to a derived row without a guard; a key whose action never reaches
    the guard it claims."""
    from textual.binding import Binding

    from s19_app.tui import window_help as wh

    app_bindings = {b.key: b for b in _bindings()}
    for window in DERIVED:
        recorded = [key for w, key, *_ in DERIVED_GUARDS if w == window]
        assert [e.key for e in wh.WINDOW_KEYS[window]] == recorded, window
        assert wh.WINDOW_GO_KEYS[window] == (), window
    for window, key, rel, qualname, snippet in DERIVED_GUARDS:
        text, _line = _node_source(rel, qualname)
        assert snippet in text, f"{window} {key}: {snippet!r} is no longer inside {rel}::{qualname}"
        entry = next(e for e in wh.WINDOW_KEYS[window] if e.key == key)
        if entry.owner is None:
            action = app_bindings[key].action
            assert _reaches(action, qualname.split(".")[1]), (
                f"{window} {key}: action {action!r} never reaches {qualname}"
            )
        else:
            cls_name, attr = qualname.split(".")
            assert attr == "BINDINGS", qualname
            bound = [
                b if isinstance(b, Binding) else Binding(*b)
                for b in __import__("s19_app.tui." + Path(rel).stem, fromlist=[cls_name]).__dict__[cls_name].BINDINGS
            ]
            assert any(b.key == key for b in bound), (window, key, qualname)
    for window, rel, qualname, snippet in DERIVED_EMPTY:
        text, _line = _node_source(rel, qualname)
        assert snippet in text, f"{window}: {snippet!r} is no longer inside {rel}::{qualname}"
        assert wh.WINDOW_KEYS[window] == () and wh.WINDOW_GO_KEYS[window] == ()


def _hex_start(app):
    return (app._hex_window_start, app._a2l_window_start, app._mac_window_start)


def test_tc_b97_69_page_keys_do_nothing_where_disabled(tmp_path: Path) -> None:
    """TC-B97-69 (LLR-150.4, behaviour): with an image and an A2L loaded, ``,``
    ``.`` pressed on every window but Workspace and ``+`` ``-`` on every
    window but A2L / MAC leave the Workspace hex window start and the A2L /
    MAC page starts unchanged (0 changes) and none of them is a live binding
    there (``app.active_bindings``); ``.`` on Workspace advances the
    hex window by one page and ``+`` on A2L advances the tag page.

    RED on main (P-63): ``.`` on the Patch Editor advances the hidden hex view.
    Mutation: drop a ``check_action`` arm.
    """
    
    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        changes, positives, live = [], {}, []
        async with app.run_test(size=(118, 54)) as pilot:
            await settle(pilot)
            app.load_from_path(EXAMPLES_DIR / "prg.s19")
            await settled(pilot, lambda: app.current_file is not None, "image loaded", 200)
            app.load_a2l_from_path(DEMO_A2L)
            await settled(pilot, lambda: bool(app.current_a2l_data), "A2L loaded", 200)
            await settle(pilot, 3)
            app.a2l_tags_page_size = 10
            for window in _windows():
                await show(app, pilot, window)
                for key in ("comma", "period", "plus", "minus"):
                    enabled = (window == "workspace") if key in ("comma", "period") else window in ("a2l", "mac")
                    if enabled:
                        continue
                    app.screen.set_focus(None)
                    if key in app.active_bindings:
                        live.append((window, key))
                    before = _hex_start(app)
                    await pilot.press(key)
                    await settle(pilot, 2)
                    if _hex_start(app) != before:
                        changes.append((window, key, before, _hex_start(app)))
            await show(app, pilot, "workspace")
            app.screen.set_focus(None)
            before = app._hex_window_start
            await pilot.press("period")
            await settle(pilot, 2)
            positives["hex"] = (before, app._hex_window_start)
            await show(app, pilot, "a2l")
            focus_rail(app)
            before = app._a2l_window_start
            await pilot.press("plus")
            await settle(pilot, 2)
            positives["a2l"] = (before, app._a2l_window_start)
        return changes, positives, live

    changes, positives, live = asyncio.run(_drive())
    assert changes == [], f"a disabled key paged something: {changes}"
    assert live == [], f"a disabled key is still a live binding: {live}"
    assert positives["hex"][1] > positives["hex"][0], positives
    assert positives["a2l"][1] > positives["a2l"][0], positives


@pytest.mark.parametrize("size", SIZES, ids=["118x54", "220x60"])
def test_tc_b97_69_painted_keys_within_the_allowed_set(tmp_path: Path, size) -> None:
    """TC-B97-69 pin: on every window row 2's tokens lie in the window's
    allowed set (its tag, entries, go keys, ``? more``), and row 2 paints none
    of ``+ - , .`` where the window does not handle them.

    RED on main: the Footer paints ``+ Page+ - Page- , Hex-`` on the Patch
    Editor."""

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        out = {}
        async with app.run_test(size=size) as pilot:
            await settle(pilot)
            for window in _windows():
                await show(app, pilot, window)
                rows = bar_rows(app)
                painted = [p for row in rows for p in pieces(row)]
                assert "+ Page+" not in painted or window in ("a2l", "mac"), (window, painted)
                assert ", Hex-" not in painted or window == "workspace", (window, painted)
                assert len(rows) == 2, (window, rows)
                out[window] = (rows, allowed_texts(app, window))
        return out

    for window, (rows, allowed) in asyncio.run(_drive()).items():
        stray = [p for p in pieces(rows[1]) if p not in allowed]
        assert stray == [], (window, stray)


def _dim(app, row: str, region, piece: str) -> bool:
    """A token is dimmed when its key glyph does not paint the enabled key
    colour: Textual paints ``dim`` as a colour blended toward the background
    (the strips carry no ``dim`` attribute), so the colour is the evidence."""
    x = piece_x(row, piece)
    key_fg = app.get_css_variables()["footer-key-foreground"].lower()
    return _hex(painted_style(app, region.x + x, region.y).color) != key_fg


def test_tc_b97_69_dimmed_entries_follow_their_condition(tmp_path: Path) -> None:
    """TC-B97-69 dim arms (PC-23): no image → Workspace ``, . U`` dimmed, lit
    once an image loads; a file-backed change-set → Patch ``^z ^y`` dimmed,
    lit after a paste-authored one; no variant set → ``v`` dimmed, lit once a
    set exists. Each flip paints within the repaint bound (no timer).

    RED on main: no row 2. Mutation: a writer without ``refresh_bindings``
    (the unload arm: unloading moves no focus, so only the writer's refresh
    repaints the bar).
    """
    from textual.widgets import Button, TextArea

    from s19_app.tui.workspace import build_variant_set, validate_project_files
    from tests.b97_fixtures import make_project

    def dims(app, *texts):
        region = bar_regions(app)[1]
        row = bar_rows(app)[1]
        return tuple(_dim(app, row, region, t) for t in texts)

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        out = {}
        async with app.run_test(size=(220, 60)) as pilot:
            await settle(pilot)
            assert len(bar_regions(app)) == 2, "the key bar has two rows"
            await show(app, pilot, "workspace")
            out["no_image"] = dims(app, ", Hex-", ". Hex+", "U Unload all")
            app.load_from_path(EXAMPLES_DIR / "prg.s19")
            await settled(pilot, lambda: app.current_file is not None, "image loaded", 200)
            await settled(
                pilot, lambda: dims(app, ", Hex-", ". Hex+", "U Unload all") == (False,) * 3,
                "image keys lit", attempts=REPAINT_PAUSES,
            )
            out["image"] = dims(app, ", Hex-", ". Hex+", "U Unload all")
            app.action_unload_all()
            await settled(pilot, lambda: app.current_file is None, "image unloaded", 200)
            await settled(
                pilot, lambda: dims(app, ", Hex-", ". Hex+", "U Unload all") == (True,) * 3,
                "image keys dimmed after the unload", attempts=REPAINT_PAUSES,
            )
            out["unloaded"] = dims(app, ", Hex-", ". Hex+", "U Unload all")
            panel = await open_patch_editor(app, pilot, image=False)
            out["no_variants"] = dims(app, "v Select variant")
            await load_change_file(app, pilot, panel, calib_hotfix(tmp_path))
            await settle(pilot, 2)
            out["file_backed"] = dims(app, "^z Undo", "^y Redo")
            text = calib_hotfix(tmp_path / "src").read_text(encoding="utf-8")
            panel.query_one("#patch_paste_text", TextArea).load_text(text)
            panel.query_one("#patch_paste_parse_button", Button).press()
            await settled(pilot, lambda: app._change_service.document.source_path is None, "pasted document", 200)
            await settled(
                pilot, lambda: dims(app, "^z Undo", "^y Redo") == (False, False),
                "undo / redo lit", attempts=REPAINT_PAUSES,
            )
            out["pasted"] = dims(app, "^z Undo", "^y Redo")
            project_dir = make_project(app)
            data_files, _a2l, _error = validate_project_files(project_dir)
            app._variant_set = build_variant_set(project_dir.name, data_files)
            await settled(
                pilot, lambda: dims(app, "v Select variant") == (False,),
                "select variant lit", attempts=REPAINT_PAUSES,
            )
            out["variants"] = dims(app, "v Select variant")
        return out

    out = asyncio.run(_drive())
    assert out["no_image"] == (True, True, True), out
    assert out["image"] == (False, False, False), out
    assert out["unloaded"] == (True, True, True), out
    assert out["no_variants"] == (True,), out
    assert out["file_backed"] == (True, True), out
    assert out["pasted"] == (False, False), out
    assert out["variants"] == (False,), out


def test_tc_b97_69_a_dimmed_token_paints_whole_in_one_colour(tmp_path: Path) -> None:
    """TC-B97-69 (operator decision at the Inc-8 gate, ux F2): a dimmed token
    paints its key AND its description in one dim colour — neither the key
    colour nor the accent — while an enabled token keeps its two colours.

    RED on the pre-fold tree: the description of a dimmed token keeps a
    blended accent, a different colour from its key. Mutation: the dim style
    on the key only."""

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(118, 54)) as pilot:
            await settle(pilot)
            await show(app, pilot, "workspace")
            region = bar_regions(app)[1]
            row = bar_rows(app)[1]
            key_fg = app.get_css_variables()["footer-key-foreground"].lower()

            def cells(piece):
                x = piece_x(row, piece)
                return [_hex(painted_style(app, region.x + x + i, region.y).color) for i in range(len(piece))
                        if piece[i] != " "]

            return cells(", Hex-"), cells("U Unload all") if "U Unload all" in row else None, cells("k Legend"), key_fg

    dim_hex, dim_unload, lit, key_fg = asyncio.run(_drive())
    assert len(set(dim_hex)) == 1, f"a dimmed token paints one colour: {dim_hex}"
    assert dim_hex[0] not in (key_fg, ACCENT), dim_hex[0]
    assert len(set(lit)) == 2 and lit[0] == key_fg and lit[-1] == ACCENT, lit


def test_tc_b97_69_owned_keys_dim_outside_their_window(tmp_path: Path) -> None:
    """TC-B97-69 (operator decision at the Inc-8 gate, LED-…97.39): an owned
    key is lit only while the focus is inside its window and its owner's
    ``check_action`` allows it. Split / Join / Export: lit with the focus in
    its range table, dimmed within the repaint bound once the focus moves to
    the rail (the bindings signal on a focus change), lit again back inside.
    Diff (ux F1): with the focus inside the panel at 220x60 (wide regime)
    ``] [`` are lit while ``f`` (fallback-only) and ``esc`` (overlay closed)
    are dimmed; at 118x54 (fallback regime) ``f`` is lit.

    RED on the pre-fold tree: owned keys are always lit. Mutation: drop the
    focus clause; drop the owner ``check_action`` clause."""

    async def lit_map(app, texts):
        region = bar_regions(app)[1]
        row = bar_rows(app)[1]
        return {t: (not _dim(app, row, region, t)) if t in row else None for t in texts}

    async def _split(size):
        app = S19TuiApp(base_dir=tmp_path)
        out = {}
        async with app.run_test(size=size) as pilot:
            await settle(pilot)
            app.load_from_path(EXAMPLES_DIR / "prg.s19")
            await settled(pilot, lambda: app.current_file is not None, "image loaded", 200)
            app.action_open_split_join_export()
            await settle(pilot, 3)
            inside = app.query_one("#screen_split_join")
            out["focus"] = app.focused is not None and inside in app.focused.ancestors
            out["inside"] = await lit_map(app, ("t Source", "g Gap", "space Tick"))
            focus_rail(app)
            await settled(
                pilot, lambda: bar_rows(app)[1] and _dim(app, bar_rows(app)[1], bar_regions(app)[1], "t Source"),
                "owned keys dimmed with the focus on the rail", attempts=REPAINT_PAUSES,
            )
            out["rail"] = await lit_map(app, ("t Source", "g Gap", "space Tick"))
            app.query_one("#sje_table").focus()
            await settled(
                pilot, lambda: not _dim(app, bar_rows(app)[1], bar_regions(app)[1], "t Source"),
                "owned keys lit again inside", attempts=REPAINT_PAUSES,
            )
            out["back"] = await lit_map(app, ("t Source",))
        return out

    async def _diff(size):
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await settle(pilot)
            await show(app, pilot, "diff")
            panel = app.query_one("#ab_diff_panel")
            target = next(w for w in panel.query("*") if w.focusable and w.display and w.region.width)
            target.focus()
            await settle(pilot, 3)
            return await lit_map(app, ("f Run list", "esc Close the run list", "] Window page +", "[ Window page -"))

    split = asyncio.run(_split((220, 60)))
    assert split["focus"], "Split / Join / Export focuses its own table on entry"
    assert split["inside"] == {"t Source": True, "g Gap": True, "space Tick": True}, split
    assert split["rail"] == {"t Source": False, "g Gap": False, "space Tick": False}, split
    assert split["back"] == {"t Source": True}, split
    wide = asyncio.run(_diff((220, 60)))
    assert wide == {"f Run list": False, "esc Close the run list": False,
                    "] Window page +": True, "[ Window page -": True}, wide
    fallback = asyncio.run(_diff((118, 54)))
    assert fallback["f Run list"] is True and fallback["esc Close the run list"] is False, fallback


#: The Diff panel's owned tokens and the action each one runs (`AbDiffPanel.BINDINGS`).
DIFF_TOKENS = {"f Run list": "toggle_run_overlay", "] Window page +": "page_window_down", "[ Window page -": "page_window_up"}


@pytest.mark.parametrize(
    "start, end",
    [((220, 60), (220, 28)), ((130, 60), (130, 28)), ((220, 28), (220, 60)), ((130, 28), (130, 60)),
     ((220, 60), (130, 60))],
    ids=["wide-to-notice", "fallback-to-notice", "notice-to-wide", "notice-to-fallback", "width-only-wide-to-fallback"],
)
def test_tc_b97_69_diff_keys_follow_a_height_only_regime_switch(tmp_path: Path, start, end) -> None:
    """TC-B97-69 (Inc-8 code re-read L2, owed to Inc-7): a HEIGHT-only resize
    that switches the A2B Diff regime (wide / fallback <-> notice at the
    29-row floor) repaints the panel's owned tokens within the repaint bound:
    each of ``f ] [`` is lit exactly when ``AbDiffPanel.check_action`` allows
    its action in the new regime, with the focus left inside the panel. One
    width-only arm (wide -> fallback, ``f`` lights) rides along: the same
    regime switch reached through the other axis.

    RED on HEAD 5cb7618 (executed, `evidence/inc-7/red.txt`): no writer calls
    ``refresh_bindings()`` on a regime switch, so the bar keeps the old state
    until the next focus change. Mutation: drop the refresh again."""

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=start) as pilot:
            await settle(pilot)
            await show(app, pilot, "diff")
            panel = app.query_one("#ab_diff_panel")
            target = next(w for w in panel.query("*") if w.focusable and w.display and w.region.width)
            target.focus()
            await settle(pilot, 3)
            before = sorted(c for c in panel.classes if c.startswith("diff-"))
            await pilot.resize_terminal(*end)
            await settled(pilot, lambda: app.size == end, f"terminal at {end}")
            await settle(pilot, 2)
            after = sorted(c for c in panel.classes if c.startswith("diff-"))
            focus_inside = app.focused is not None and panel in app.focused.ancestors_with_self
            expected = {t: bool(panel.check_action(a, ())) for t, a in DIFF_TOKENS.items()}

            def painted() -> dict:
                row, region = bar_rows(app)[1], bar_regions(app)[1]
                return {t: (not _dim(app, row, region, t)) if t in row else None for t in DIFF_TOKENS}

            try:
                await settled(pilot, lambda: painted() == expected, "the Diff tokens follow the regime", attempts=REPAINT_PAUSES)
            except AssertionError:
                pass
            return before, after, focus_inside, expected, painted()

    before, after, focus_inside, expected, painted = asyncio.run(_drive())
    assert before != after, f"guard: the resize switches the regime ({before} -> {after})"
    assert focus_inside, "guard: the focus stays inside the Diff panel"
    assert painted == expected, (before, after, painted, expected)


# --------------------------------------------------------------------------- #
# TC-B97-70 — LLR-150.5, whole tokens, `? more`
# --------------------------------------------------------------------------- #


def _tok(key, label, enabled=True):
    from s19_app.tui.window_help import KeyToken

    return KeyToken(key, key, label, "noop", enabled=enabled)


def _layer0_lists():
    from s19_app.tui.window_help import KeyToken

    tag = KeyToken("", "", "Workspace", "", tag=True)
    workspace = [tag] + [
        _tok(k, l) for k, l in (
            ("/", "Find"), ("g", "Go-to"), (",", "Hex-"), (".", "Hex+"), ("k", "Legend"),
            ("p", "Load project"), ("o", "Open workarea"), ("r", "Refresh workarea"), ("U", "Unload all"),
        )
    ]
    wide_second = [tag, _tok("a", "A"), _tok("b", "B" * 40), _tok("c", "C"), _tok("d", "D")]
    return workspace, wide_second


@pytest.mark.parametrize("which", [0, 1], ids=["workspace", "wide_second"])
def test_tc_b97_70_pack_key_row_keeps_a_whole_display_order_prefix(which: int) -> None:
    """TC-B97-70 layer 0 (``pack_key_row``): over widths 20..240 the painted
    length is <= the width; the tag is kept whenever it fits; the kept others
    are a display-order prefix (no gap — the greedy-skip mutation fails); a
    ``? more`` tail ends the row exactly when a token was dropped; every kept
    token is painted whole with its hit range over its own cells.

    Mutation: a packer that crops; the prototype's greedy packer."""
    from s19_app.tui.window_help import pack_key_row

    tokens = _layer0_lists()[which]
    more = _tok("?", "more")
    tag_width = len(f" {tokens[0].label} ")
    for width in range(20, 241):
        row = pack_key_row(tokens, width, keep=frozenset({0}), more=more)
        plain = row.text.plain
        assert row.text.cell_len <= width, (width, plain)
        if width >= tag_width:
            assert plain.startswith(f" {tokens[0].label} "), (width, plain)
        kept = [t for t in tokens[1:] if f" {t.key_display} {t.label} " in plain]
        assert kept == tokens[1:1 + len(kept)], (width, plain)
        assert row.dropped == len(tokens) - 1 - len(kept), (width, row.dropped)
        assert plain.endswith(" ? more ") == (row.dropped > 0 and width >= tag_width + 8), (width, plain)
        for x0, x1, key in row.hits:
            token = next((t for t in [*tokens, more] if t.key == key))
            assert plain[x0:x1] == f" {token.key_display} {token.label} ", (width, key, plain[x0:x1])


def test_tc_b97_70_pack_key_row_dims_and_does_not_hit_disabled() -> None:
    """TC-B97-70 layer 0: a disabled token is painted whole in the dim style
    (key and description in one span) and has no hit range (it lands in
    ``dimmed``); an exactly-fitting row drops nothing."""
    from s19_app.tui.window_help import pack_key_row

    tokens = [_tok("a", "Alpha"), _tok("b", "Beta", enabled=False)]
    width = len(" a Alpha ") + len(" b Beta ")
    row = pack_key_row(tokens, width)
    assert row.dropped == 0 and row.text.cell_len == width
    assert [h[2] for h in row.hits] == ["a"] and [d[2] for d in row.dimmed] == ["b"]
    # Inc-8 gate fold (ux F2): the whole disabled token is ONE span in the dim
    # style — key and description alike; with no styles the fallback is dim.
    spans = [s for s in row.text.spans if row.text.plain[s.start:s.end].strip() == "b Beta"]
    assert len(spans) == 1 and spans[0].style.dim, row.text.spans
    from rich.style import Style

    dim = Style(color="grey50")
    styled = pack_key_row(tokens, width, styles={"dim": dim, "key": Style(color="red"), "description": Style(color="blue")})
    whole = [s for s in styled.text.spans if styled.text.plain[s.start:s.end] == " b Beta "]
    assert len(whole) == 1 and whole[0].style == dim, styled.text.spans


@pytest.mark.parametrize("size", [(118, 54), (220, 60), (80, 24)], ids=["118x54", "220x60", "80x24"])
def test_tc_b97_70_every_painted_row_is_whole_tokens(tmp_path: Path, size) -> None:
    """TC-B97-70 integration: on each window every painted row of the bar
    parses into known tokens with no remainder but padding and holds no
    ``perio``; at 118x54 the Workspace row 2 ends ``? more`` and holds no
    ``U Unload all``; at 220x60 no row paints ``? more``.

    RED on main (P-65, P-67): the Footer ends ``perio▏`` at 118x54."""

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        out = {}
        async with app.run_test(size=size) as pilot:
            await settle(pilot)
            for window in _windows():
                await show(app, pilot, window)
                rows = bar_rows(app)
                assert not any("perio" in row for row in rows), (window, rows)
                out[window] = (rows, allowed_texts(app, window))
        return out

    for window, (rows, allowed) in asyncio.run(_drive()).items():
        known = allowed | set(GLOBAL_TEXTS)
        for row in rows:
            stray = [p for p in pieces(row) if p not in known]
            assert stray == [], (window, stray)
        if size == (220, 60):
            assert not any("? more" in row for row in rows), (window, rows)
        if size == (118, 54) and window == "workspace":
            assert pieces(rows[1])[-1] == "? more" and "U Unload all" not in rows[1], rows


# --------------------------------------------------------------------------- #
# TC-B97-71 — LLR-150.6, the bar replaces the Footer and costs one row
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("size", SIZES, ids=["118x54", "220x60"])
def test_tc_b97_71_the_bar_replaces_the_footer_and_costs_one_row(tmp_path: Path, size) -> None:
    """TC-B97-71 (LLR-150.6): no ``Footer`` is mounted; the key bar is 2 rows
    high and ends on the row above the screen's bottom padding row (where the
    Footer sat); every window's container is exactly 1 row shorter than on
    ``main`` (42 at 118x54, P-68).

    RED on main: one Footer of height 1, containers 42. Mutation: a key bar of
    height 3."""
    from textual.widgets import Footer

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await settle(pilot)
            heights = {}
            for window in _windows():
                await show(app, pilot, window)
                heights[window] = _container(app, window).region.height
            footers = len(app.query(Footer))
            regions = bar_regions(app)
            return heights, footers, regions, app.size.height

    heights, footers, regions, height = asyncio.run(_drive())
    expected = MAIN_CONTAINER_ROWS[size] - 1
    assert heights == {w: expected for w in _windows()}, heights
    assert footers == 0, "the Footer is replaced"
    assert len(regions) == 2 and all(r.height == 1 for r in regions), regions
    assert regions[1].y == regions[0].y + 1 and regions[1].y == height - 2, (regions, height)


# --------------------------------------------------------------------------- #
# TC-B97-72 — LLR-150.7, a click runs the token's action in its namespace
# --------------------------------------------------------------------------- #


async def click_bar(pilot, offset) -> None:
    """``pilot.click("#key_bar", offset=offset)`` without its bounds check.

    Textual's pilot checks the target against ``screen.size``, which is the
    app size minus the Screen's padding, so it refuses every cell of the bottom
    content row (``y == height - 2``) — row 2 of the bar — although the
    compositor paints it and a real terminal click reaches it. This posts the
    same MouseDown / MouseUp / Click sequence through ``screen._forward_event``
    that ``Pilot._post_mouse_events`` posts.
    """
    from textual.events import Click, MouseDown, MouseUp
    from textual.geometry import Offset
    from textual.pilot import _get_mouse_message_arguments

    app = pilot.app
    screen = app.screen
    target = screen.query_one("#key_bar")
    arguments = _get_mouse_message_arguments(target, offset, button=1)
    point = Offset(arguments["x"], arguments["y"])
    assert point in app.size.region, f"click outside the terminal: {point}"
    for cls in (MouseDown, MouseUp, Click):
        await pilot.pause()
        kwargs = {**arguments, "chain": 1} if cls is Click else arguments
        app.mouse_position = point
        screen._forward_event(cls(**kwargs))
    await pilot.pause()


def _token_offset(app, row_index: int, piece: str, *, last: bool = False, first: bool = False):
    """The click offset (relative to ``#key_bar``) of ``piece`` on a row."""
    row = bar_rows(app)[row_index]
    x = piece_x(row, piece)
    if first:
        return (x - 1, row_index)
    if last:
        return (x + len(piece), row_index)
    return (x + len(piece) // 2, row_index)


def test_tc_b97_72_hit_ranges_are_the_painted_cells(tmp_path: Path) -> None:
    """TC-B97-72: on every window each enabled token's hit range is exactly its
    painted cells (`` key label `` — the token's own leading and trailing
    space), on both rows.

    Mutation: hit ranges offset by the tag's width."""

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        out = []
        async with app.run_test(size=(220, 60)) as pilot:
            await settle(pilot)
            for window in _windows():
                await show(app, pilot, window)
                for index, row_widget in enumerate(app.query("#key_bar KeyRow")):
                    row = bar_rows(app)[index]
                    for x0, x1, _key in row_widget._packed.hits:
                        out.append((window, index, row[x0:x1], x0, x1, row))
        return out

    readings = asyncio.run(_drive())
    assert readings
    for window, index, text, x0, x1, row in readings:
        assert text.startswith(" ") and text.endswith(" ") and text.strip() in pieces(row), (window, index, text)
        assert row[x0 + 1] != " " and row[x1 - 2] != " ", (window, index, text)


def test_tc_b97_72_clicks_run_the_action_and_type_nothing(tmp_path: Path, monkeypatch) -> None:
    """TC-B97-72 (LLR-150.7): with a text ``Input`` focused (the command
    palette's) a click on ``9 Checks`` shows Checks and a click on ``q`` calls
    ``action_quit`` once, the input staying empty; with the focus inside the
    Patch Editor a click on ``? Help`` opens the stock help panel, not the
    window help; a click on the dimmed ``^z Undo`` (file-backed document)
    changes nothing and rings one bell; a click on the tag changes nothing.

    Mutation: the click as ``app.simulate_key`` (types ``q`` / ``9`` into the
    input); dimmed tokens clickable."""
    from textual.widgets import HelpPanel, Input

    from s19_app.tui.window_help import WindowHelpScreen

    quits, bells = [], []
    monkeypatch.setattr(S19TuiApp, "action_quit", lambda self: quits.append(1))

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        out = {}
        async with app.run_test(size=(220, 60)) as pilot:
            original_bell = app.bell
            app.bell = lambda: bells.append(1) or original_bell()
            panel = await open_patch_editor(app, pilot)
            await load_change_file(app, pilot, panel, calib_hotfix(tmp_path))
            doc = (app._change_service.document.source_path, len(app._change_service.document.entries))
            # tag: nothing
            await click_bar(pilot, _token_offset(app, 1, _tag("patch")))
            await settle(pilot, 2)
            out["tag"] = app._active_screen_key
            # dimmed ^z: nothing, one bell
            await click_bar(pilot, _token_offset(app, 1, "^z Undo"))
            await settle(pilot, 2)
            out["undo"] = (
                app._active_screen_key,
                (app._change_service.document.source_path, len(app._change_service.document.entries)) == doc,
                len(bells),
            )
            # ? Help with the focus inside the window -> the stock panel
            panel.query_one("#patch_doc_path_input").focus()
            await settle(pilot, 1)
            await click_bar(pilot, _token_offset(app, 0, "? Help"))
            await settled(pilot, lambda: bool(app.query(HelpPanel)), "the stock help panel opened")
            out["help"] = (bool(app.query(HelpPanel)), isinstance(app.screen, WindowHelpScreen))
            app.action_show_help_panel()
            await settle(pilot, 2)
            # 9 and q with the palette input focused
            app.action_focus_palette()
            await settle(pilot, 2)
            field = app.query_one("#palette_input", Input)
            out["focused"] = app.focused is field
            await click_bar(pilot, _token_offset(app, 1, "9 Checks"))
            await settled(pilot, lambda: app._active_screen_key == "checks", "Checks shown")
            await click_bar(pilot, _token_offset(app, 0, "q Quit"))
            await settle(pilot, 2)
            out["typed"] = (app._active_screen_key, field.value, len(quits))
        return out

    out = asyncio.run(_drive())
    assert out["tag"] == "patch", out
    assert out["undo"] == ("patch", True, 1), out
    assert out["help"] == (True, False), out
    assert out["focused"], "the palette input held the focus"
    assert out["typed"] == ("checks", "", 1), out


def test_tc_b97_72_owner_click_runs_on_its_widget_not_the_focus(tmp_path: Path) -> None:
    """TC-B97-72 owner arm: on the Check Editor with the focus on the JSON tab
    chip, a click on ``space Include`` toggles the highlighted parameter's
    inclusion (count +1) and leaves the active card tab unchanged; the
    boundary clicks — the last cell of ``space Include`` and the first cell of
    the next token — run their own token.

    Mutation: the click as ``simulate_key`` presses the focused tab chip."""
    from textual.widgets import ContentSwitcher, DataTable

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(220, 60)) as pilot:
            panel = await open_check_editor(app, pilot)
            table = panel.query_one("#check_param_table", DataTable)
            table.move_cursor(row=2)
            await settle(pilot, 2)
            count = panel.query_one("#check_fields_count")
            switcher = panel.query_one("#check_card_switcher", ContentSwitcher)
            panel.query_one("#check_tab_json").focus()
            await settle(pilot, 2)
            before = (str(count.render()), switcher.current, app.focused.id)
            await click_bar(pilot, _token_offset(app, 1, "space Include", last=True))
            await settle(pilot, 3)
            after = (str(count.render()), switcher.current, app.focused.id)
            await click_bar(pilot, _token_offset(app, 1, "6 Patch Editor", first=True))
            await settled(pilot, lambda: app._active_screen_key == "patch", "the next token ran")
            return before, after, app._active_screen_key

    before, after, window = asyncio.run(_drive())
    assert after[1:] == before[1:], (before, after)
    numbers = [int(re.search(r"\d+", text).group()) for text in (before[0], after[0])]
    assert numbers[1] == numbers[0] + 1, (before, after)
    assert window == "patch"


def test_tc_b97_72_confirm_click_with_the_focus_in_an_input(tmp_path: Path, monkeypatch) -> None:
    """TC-B97-72 ``c`` arm: Flow Execution paused on ``flash_chain`` with the
    focus in ``#fx_in_0_0`` after typing ``x``: a click on ``c Confirm`` (after
    the dwell) confirms the attention lane once and the input still reads what
    it read before the click.

    Mutation: the click as ``simulate_key`` types ``c`` into the input."""
    from tests.test_b97_flow_execution import THREE, ConfirmSpy, poll, run_fx

    confirms = ConfirmSpy(monkeypatch)

    async def body(app, pilot, panel, project_dir):
        await poll(pilot, lambda: panel._lanes[1].paused_block is not None, 200)
        field = panel.query_one("#fx_in_0_0")
        field.focus()
        await poll(pilot, lambda: app.focused is field)
        field.cursor_position = len(field.value)
        await pilot.press("x")
        await settle(pilot, 2)
        typed = field.value
        await poll(pilot, lambda: panel._attention is None or panel._attention_since is not None, 200)
        await pilot.pause(0.6)
        await click_bar(pilot, _token_offset(app, 1, "c Confirm"))
        await poll(pilot, lambda: len(confirms.posts) == 1, 200)
        return typed, field.value, list(confirms.posts)

    typed, after, posts = run_fx(tmp_path, (220, 60), body, stems=THREE, run=True, evidence=True)
    assert typed.endswith("x") and after == typed, (typed, after)
    assert posts == [(1, 2)], posts


# --------------------------------------------------------------------------- #
# AT-B97-25 / AT-B97-26 — black-box
# --------------------------------------------------------------------------- #


def test_at_b97_25_two_rows_on_every_window_and_clicks(tmp_path: Path, monkeypatch) -> None:
    """AT-B97-25 (US-140 / HLR-150): rail keys through the 13 windows (the
    palette entry for Split / Join / Export) at 118x54 and 220x60 and the
    Workspace at 80x24: row 1 is exactly the 8 globals (7 at 80x24), never
    ``? more``; row 2 starts with the tag, holds only allowed tokens, none
    partial, no ``perio``; the Workspace row 2 ends ``? more`` at 118x54 and
    no row paints ``? more`` at 220x60; the tag paints ``#0a0e1b`` on
    ``#91abec``; containers are ``main`` − 1. On the Patch Editor, with the
    palette input focused, a click on ``9 Checks`` shows Checks with nothing
    typed. Empty-window arm: the CRC Designer row 2 is its tag alone.

    RED on main (P-61, P-67, P-68): ``perio▏``, no ``? Help``, one row.
    """
    from textual.widgets import Input

    
    async def _drive(size):
        app = S19TuiApp(base_dir=tmp_path)
        out = {}
        async with app.run_test(size=size) as pilot:
            await settle(pilot)
            for window in _windows():
                if window == "split_join":
                    app.action_focus_palette()
                    await settle(pilot, 2)
                    await pilot.press(*"Split")
                    await settle(pilot, 2)
                    await pilot.press("enter")
                    await settled(pilot, lambda: app._active_screen_key == "split_join", "Split / Join / Export opened")
                else:
                    focus_rail(app)
                    await settle(pilot, 1)
                    await pilot.press(_rail_key(window).key)
                    await settled(pilot, lambda: app._active_screen_key == window, f"{window} shown")
                await settle(pilot, 2)
                regions = bar_regions(app)
                rows = bar_rows(app)
                assert not any("perio" in r for r in rows), (size, window, rows)
                assert pieces(rows[0]) == list(GLOBAL_TEXTS), (size, window, rows[0])
                assert len(rows) == 2, (size, window, rows)
                tag_cell = None
                if len(regions) == 2:
                    row = bar_rows(app)[1]
                    x = row.find(_tag(window))
                    style = painted_style(app, regions[1].x + max(x, 0), regions[1].y)
                    tag_cell = (_hex(style.color), _hex(style.bgcolor))
                out[window] = (bar_rows(app), allowed_texts(app, window), tag_cell, _container(app, window).region.height)
            if size == (220, 60):
                app.action_show_screen("patch")
                await settle(pilot, 3)
                app.action_focus_palette()
                await settle(pilot, 2)
                field = app.query_one("#palette_input", Input)
                await click_bar(pilot, _token_offset(app, 1, "9 Checks"))
                await settled(pilot, lambda: app._active_screen_key == "checks", "Checks shown by the click")
                out["click"] = (app._active_screen_key, field.value)
        return out

    async def _small():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            await settle(pilot)
            return bar_rows(app)

    for size in SIZES:
        out = asyncio.run(_drive(size))
        for window in _windows():
            rows, allowed, tag_cell, height = out[window]
            assert len(rows) == 2, (size, window, rows)
            assert pieces(rows[0]) == list(GLOBAL_TEXTS), (size, window, rows[0])
            assert pieces(rows[1])[0] == _tag(window), (size, window, rows[1])
            assert [p for p in pieces(rows[1]) if p not in allowed] == [], (size, window, rows[1])
            assert not any("perio" in r for r in rows)
            assert tag_cell == (TAG_FG, TAG_BG), (size, window, tag_cell)
            assert height == MAIN_CONTAINER_ROWS[size] - 1, (size, window, height)
            if size == (220, 60):
                assert "? more" not in rows[1], (window, rows[1])
        if size == (118, 54):
            assert pieces(out["workspace"][0][1])[-1] == "? more"
        else:
            assert out["click"] == ("checks", ""), out["click"]
        assert pieces(out["crc_designer"][0][1]) == [_tag("crc_designer")]
    small = asyncio.run(_small())
    assert pieces(small[0]) == list(GLOBAL_TEXTS_80), small


def test_at_b97_26_keys_only_help_and_hidden_view(tmp_path: Path) -> None:
    """AT-B97-26 (US-140 / HLR-150, keys only): ``1`` and the first painted hex
    address; ``6`` and ``tab`` into the Patch Editor (focus inside its
    section): row 1 holds ``? Help`` and ``?`` opens that window's help;
    ``.`` and ``+`` pressed there; ``1`` again: the first painted hex address
    is unchanged; with the file-backed document ``^z ^y`` are dimmed, and lit
    after a paste-authored document parsed by key.

    RED on main (P-61, P-63): no ``? Help`` with the focus in the window; ``.``
    on the Patch Editor advances the hidden hex view.
    """
    from textual.widgets import Input, TextArea

    from s19_app.tui.window_help import WindowHelpScreen
    from tests.b97_fixtures import CALIB_ENTRIES, _bytes_entry, write_changeset

    def first_address(app) -> str:
        for row in painted_rows(app, app.query_one("#hex_view")):
            match = re.match(r"\s*(0x[0-9A-Fa-f]{6,8})\b", row)
            if match:
                return match.group(1)
        return ""

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        out = {}
        async with app.run_test(size=(118, 54)) as pilot:
            await settle(pilot)
            app.load_from_path(EXAMPLES_DIR / "prg.s19")
            await settled(pilot, lambda: app.current_file is not None, "image loaded", 200)
            focus_rail(app)
            await pilot.press("1")
            await settled(pilot, lambda: first_address(app) != "", "hex painted")
            out["addr_before"] = first_address(app)
            focus_rail(app)
            await pilot.press("6")
            await settled(pilot, lambda: app._active_screen_key == "patch", "patch shown")
            for _ in range(40):
                await pilot.press("tab")
                await settle(pilot, 1)
                if app.focused is not None and app.query_one("#screen_patch") in app.focused.ancestors:
                    break
            out["inside"] = app.focused is not None and app.query_one("#screen_patch") in app.focused.ancestors
            assert out["inside"], "the focus reached the Patch Editor's section"
            out["row1"] = pieces(bar_rows(app)[0])
            assert "? Help" in out["row1"], out["row1"]
            await pilot.press("question_mark")
            await settle(pilot, 3)
            out["help"] = (isinstance(app.screen, WindowHelpScreen), getattr(app.screen, "section_key", None))
            assert out["help"] == (True, "patch"), out["help"]
            await pilot.press("escape")
            await settle(pilot, 3)
            app.screen.set_focus(None)
            await pilot.press("period")
            await pilot.press("plus")
            await settle(pilot, 2)
            focus_rail(app)
            await pilot.press("1")
            await settled(pilot, lambda: app._active_screen_key == "workspace", "workspace shown")
            await settle(pilot, 2)
            out["addr_after"] = first_address(app)
            assert out["addr_after"] == out["addr_before"], out
            # Undo / Redo: the file-backed document dims them; a paste-authored
            # one lights them. The texts are placed in the fields; Load and
            # Parse pasted are pressed by key (enter on the focused chip).
            focus_rail(app)
            await pilot.press("6")
            await settled(pilot, lambda: app._active_screen_key == "patch", "patch shown")
            panel = app.query_one("#patch_editor_panel")
            panel.query_one("#patch_doc_path_input", Input).value = str(calib_hotfix(tmp_path))
            panel.query_one("#patch_doc_load_button").focus()
            await pilot.press("enter")
            await settled(pilot, lambda: app._change_service.document.source_path is not None, "file loaded", 200)
            await settle(pilot, 2)
            out["file_backed"] = undo_dims(app)
            two = write_changeset(tmp_path / "two.json", [_bytes_entry(a, r) for a, r in CALIB_ENTRIES[:2]])
            if panel.query("#patch_tab_json"):
                panel.query_one("#patch_tab_json").focus()
                await pilot.press("enter")
                await settle(pilot, 2)
            panel.query_one("#patch_paste_text", TextArea).load_text(two.read_text(encoding="utf-8"))
            panel.query_one("#patch_paste_parse_button").focus()
            await pilot.press("enter")
            await settled(pilot, lambda: app._change_service.document.source_path is None, "pasted document", 200)
            await settled(pilot, lambda: undo_dims(app) == (False, False), "undo / redo lit", attempts=REPAINT_PAUSES)
            out["pasted"] = (undo_dims(app), len(app._change_service.document.entries))
        return out

    def undo_dims(app):
        region = bar_regions(app)[-1]
        row = bar_rows(app)[-1]
        return tuple(_dim(app, row, region, t) if t in row else None for t in ("^z Undo", "^y Redo"))

    out = asyncio.run(_drive())
    assert out["inside"], "the focus reached the Patch Editor's section"
    assert "? Help" in out["row1"], out["row1"]
    assert out["help"] == (True, "patch"), out["help"]
    assert out["addr_after"] == out["addr_before"], out
    assert out["file_backed"] == (True, True), out
    assert out["pasted"] == ((False, False), 2), out
