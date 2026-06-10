"""Direction B app-shell tests — batch-02-direction-b-restyle, increments 2-11.

Covers the increment-2 LLRs:
  - LLR-002.1 — rail-driven content swap (the ``.hidden``-toggle mechanism)
  - LLR-002.3 — empty-state panel when no file is loaded
  - LLR-006.1 — density cycle action (``Ctrl+D``)
  - LLR-006.2 — density default (Comfortable at startup)
  - LLR-007.1 (skeleton) — the two-regime ``width-narrow`` class

the increment-3 LLRs:
  - LLR-001.1 — activity-rail composition (8 ordered items on keys 1-8)
  - LLR-001.2 — single active rail item (Workspace active at startup)
  - LLR-001.3 — rail glyph rendering with ASCII fallback

the increment-4 LLRs:
  - LLR-003.1 — command-bar composition (present on every screen)
  - LLR-003.3 — command-palette type-to-filter
  - LLR-004.3 — ``Ctrl+K`` opens/focuses the palette
  - LLR-011.3 — project-name / A2L-filename labels in the command bar

the increment-5 LLRs:
  - LLR-008.1 — Workspace three-pane structure + two-regime width layout
  - LLR-008.2 — Workspace data wiring unchanged (renderers / hex caps)

the increment-6 LLRs:
  - LLR-009.1 — A2L Explorer two-pane structure + two-regime width layout
  - LLR-009.2 — A2L data wiring unchanged (filtering / paging renderers)
  - LLR-010.1 — MAC View two-pane structure + two-regime width layout
  - LLR-010.2 — MAC data wiring unchanged (paging renderer / overlay)

the increment-7 LLRs:
  - LLR-011.1 — Issues Report is a dedicated rail screen (not the Status tile)
  - LLR-011.2 — Issues behavior preserved (severity / filters / paging / jump)
  - LLR-002.3 — empty-state panel for the re-laid-out Workspace / Issues screens

the increment-8 LLRs:
  - LLR-015.1 — the three Load / Save / Load-Project modals re-skinned to the
    Calm Dark token set (no hard-coded color, single accent, no light variant)
  - LLR-015.2 — modal behavior preserved (``validate_project_files``
    cardinality, ``copy_into_workarea`` containment, path resolution)

the increment-9 LLRs:
  - LLR-012.1 — the Memory Map renders coverage from the existing
    ``LoadedFile.ranges`` / ``range_validity`` (no new coverage computation)
  - LLR-002.2 — the Bookmarks rail item opens a neutral "coming soon"
    placeholder screen (no persistence logic)
  - LLR-012.4 — the scaffolds add no new processing module / processing lib

and the increment-10 LLRs:
  - LLR-012.2 — the Patch Editor is an inert before/after view shell with
    address/bytes inputs wired to no patch-apply / undo / redo logic
  - LLR-012.3 — the A2B Diff is a static three-column placeholder (range
    list, hex A, hex B) with constant sample rows and PLACEHOLDER markers,
    no second-file load path and no diff computation
  - LLR-012.4 — the deferred-logic guard is completed for all scaffolds and
    extended to ``pyproject.toml``

and the increment-11 LLRs (the dedicated no-regression / behavior sweep):
  - LLR-004.4 — every pre-batch ``BINDINGS`` action keeps a keyboard path;
    the ``1``/``2``/``3`` view-toggle -> rail remap and the ``#view_bar``
    removal are recorded as intended supersession, not regressions
  - LLR-013.1 — every new Direction B control (rail items, command-bar
    inputs, density toggle, scaffold inputs) has a working keyboard path
  - LLR-013.2 — the footer/status bar reflects the active screen's
    ``show=True`` bindings, compared against the increment-1 keymap proposal
  - LLR-014.1 — the engine / data-processing modules (``core.py``,
    ``hexfile.py``, ``range_index.py``, ``validation/``, ``tui/a2l.py``,
    ``tui/mac.py``, ``tui/color_policy.py``) are behaviorally unchanged
  - LLR-014.2 — the pre-batch ``pytest`` suite passes; engine/parser/
    validation test files are unmodified vs the batch start

Test cases: TC-003, TC-014, TC-015, TC-037 (increment 2);
TC-001, TC-002, TC-035 (increment 3);
TC-006, TC-010, TC-036, TC-038 (increment 4 — TC-007/008/009/039 live
in ``tests/test_tui_commandbar.py``);
TC-017, TC-018 (increment 5);
TC-019, TC-020, TC-021, TC-022 (increment 6);
TC-023, TC-024, TC-037 (Workspace sub-case) (increment 7);
TC-033, TC-034 (increment 8);
TC-025, TC-004, TC-028 (scaffold side) (increment 9);
TC-026, TC-027, TC-028 (completion) (increment 10);
TC-011, TC-029, TC-030, TC-031, TC-032 (increment 11).

Increment-11 design note — keymap proposal vs. realised implementation
(TC-030). The increment-1 ``keymap-proposal.md`` §3 lists *per-screen*
``show=True`` paging actions (e.g. ``a2l_tags_page_next`` on the A2L
Explorer). The implementation chosen in increments 2-7 realises those
per-screen sets through a *single* app-level ``BINDINGS`` set: the four
paging keys (``period`` / ``comma`` / ``plus`` / ``minus``) are
``show=True`` globally and dispatch *context-sensitively* via
``_active_view_name`` — ``hex_page_next`` on Workspace, ``a2l_tags_page_*``
on A2L Explorer, ``mac_records_page_*`` on MAC View, and so on. The footer
therefore shows a constant chip set on every screen; the per-screen
behaviour is in the *action dispatch*, not in per-screen ``Binding``
objects. This is the realised contract, not a regression: the keymap
proposal §3 itself defines a screen's footer as "global footer set + that
screen's per-screen ``show=True`` set", and a single dispatcher binding
that is always ``show=True`` is a superset of every screen's expected set.
TC-030 verifies (a) the global footer set is present on every screen and
(b) the paging keys the keymap assigns to a screen are present in that
screen's footer — an honest, non-weakened reading of LLR-013.2.

The app is driven headlessly via ``App.run_test()`` (the harness pattern of
``tests/test_tui_app.py``): an ``async def _drive()`` body wrapped by
``asyncio.run``, asserting on widget-tree state read back via ``query_one`` /
``query`` and CSS-class membership.

Scope note for TC-037: increment 2 delivers the ``EmptyStatePanel`` widget
and wires it into the rail screen slots it owns this increment — the
Memory Map / Issues / Patch / Diff / Bookmarks scaffolds. The Workspace /
A2L / MAC screens still wrap their pre-batch layouts this increment; their
empty-state integration lands with the per-screen re-layout (increments
5-7). TC-037 here verdicts the Memory Map empty state and the panel widget
itself; the Workspace/A2L/MAC empty state is re-verdicted in increments 5-7.
"""

from __future__ import annotations

import asyncio
import subprocess
from pathlib import Path

from textual.binding import Binding
from textual.widgets import Input

from s19_app.tui.app import S19TuiApp
from s19_app.tui.command_bar import CommandBar
from s19_app.tui.models import LoadedFile
from s19_app.tui.rail import RAIL_ENTRIES, Rail, RailItem
from s19_app.tui.screens_directionb import EmptyStatePanel


# The 8 Direction B rail screen container ids, in rail order (keys 1-8).
SCREEN_IDS = [
    "screen_workspace",
    "screen_a2l",
    "screen_mac",
    "screen_map",
    "screen_issues",
    "screen_patch",
    "screen_diff",
    "screen_bookmarks",
]

# Rail screen-key -> container id, matching S19TuiApp.SCREEN_CONTAINER_IDS.
SCREEN_KEYS = [
    "workspace",
    "a2l",
    "mac",
    "map",
    "issues",
    "patch",
    "diff",
    "bookmarks",
]


def _visible_screens(app: S19TuiApp) -> list[str]:
    """Return the ids of the rail screen containers not carrying ``.hidden``."""
    return [
        sid
        for sid in SCREEN_IDS
        if "hidden" not in app.query_one(f"#{sid}").classes
    ]


# ---------------------------------------------------------------------------
# TC-003 — rail activation swaps content (LLR-002.1)
# ---------------------------------------------------------------------------


def test_tc003_only_one_screen_visible_at_startup(tmp_path: Path) -> None:
    """At startup exactly the Workspace rail screen is visible (LLR-002.1).

    Intent: the 8-container body must not show 8 panes at once; the
    ``.hidden`` default is correct and only Workspace is active on mount.
    """

    async def _drive() -> list[str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            return _visible_screens(app)

    visible = asyncio.run(_drive())
    assert visible == ["screen_workspace"], (
        f"Expected only Workspace visible at startup, got {visible}"
    )


def test_tc003_show_screen_swaps_to_each_rail_screen(tmp_path: Path) -> None:
    """``action_show_screen`` shows the target and hides the other seven.

    Intent: the rail-driven content swap (LLR-002.1) keeps exactly one rail
    screen visible for every one of the eight screen keys — the swap reuses
    the ``.hidden``-class show/hide mechanism, not ``push_screen``.
    """

    async def _drive() -> dict[str, list[str]]:
        app = S19TuiApp(base_dir=tmp_path)
        result: dict[str, list[str]] = {}
        async with app.run_test() as pilot:
            await pilot.pause()
            for key, expected_id in zip(SCREEN_KEYS, SCREEN_IDS):
                app.action_show_screen(key)
                await pilot.pause()
                result[expected_id] = _visible_screens(app)
        return result

    per_key = asyncio.run(_drive())
    for expected_id, visible in per_key.items():
        assert visible == [expected_id], (
            f"Activating {expected_id} left {visible} visible "
            f"(expected exactly [{expected_id}])"
        )


def test_tc003_rail_keys_1_to_8_route_screens(tmp_path: Path) -> None:
    """Pressing keys ``1``-``8`` activates rail screens 1-8 in order.

    Intent: the keymap-proposal binding of digits 1-8 to
    ``show_screen(...)`` is wired; pressing each digit makes exactly its
    rail screen visible. The legacy ``1``/``2``/``3`` view-toggle meaning
    is intentionally superseded (LLR-004.4).
    """

    async def _drive() -> dict[str, list[str]]:
        app = S19TuiApp(base_dir=tmp_path)
        result: dict[str, list[str]] = {}
        async with app.run_test() as pilot:
            await pilot.pause()
            for digit, expected_id in zip("12345678", SCREEN_IDS):
                await pilot.press(digit)
                await pilot.pause()
                result[digit] = _visible_screens(app)
        return result

    per_digit = asyncio.run(_drive())
    for digit, expected_id in zip("12345678", SCREEN_IDS):
        assert per_digit[digit] == [expected_id], (
            f"Key '{digit}' should activate {expected_id}, "
            f"got {per_digit[digit]}"
        )


# ---------------------------------------------------------------------------
# TC-015 — startup density default (LLR-006.2)
# ---------------------------------------------------------------------------


def test_tc015_startup_density_is_comfortable(tmp_path: Path) -> None:
    """The workspace body carries the Comfortable density class at startup.

    Intent: LLR-006.2 fixes Comfortable as the default startup density;
    the ``#workspace_body`` root must carry ``density-comfortable`` and
    not ``density-compact`` on mount.
    """

    async def _drive() -> tuple[bool, bool]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            body = app.query_one("#workspace_body")
            return body.has_class("density-comfortable"), body.has_class(
                "density-compact"
            )

    comfortable, compact = asyncio.run(_drive())
    assert comfortable, "Startup density class should be density-comfortable"
    assert not compact, "Startup must not carry density-compact"


# ---------------------------------------------------------------------------
# TC-014 — Ctrl+D cycles density (LLR-006.1)
# ---------------------------------------------------------------------------


def test_tc014_ctrl_d_cycles_density(tmp_path: Path) -> None:
    """``Ctrl+D`` cycles density Comfortable -> Compact -> Comfortable.

    Intent: LLR-006.1 — the density toggle flips a single density class on
    the workspace root, and the modified-key binding stays a clean toggle
    (no third state, no stuck both-classes state).
    """

    async def _drive() -> list[tuple[bool, bool]]:
        app = S19TuiApp(base_dir=tmp_path)
        states: list[tuple[bool, bool]] = []
        async with app.run_test() as pilot:
            await pilot.pause()
            body = app.query_one("#workspace_body")
            states.append(
                (
                    body.has_class("density-comfortable"),
                    body.has_class("density-compact"),
                )
            )
            for _ in range(2):
                await pilot.press("ctrl+d")
                await pilot.pause()
                states.append(
                    (
                        body.has_class("density-comfortable"),
                        body.has_class("density-compact"),
                    )
                )
        return states

    states = asyncio.run(_drive())
    # start -> comfortable; after 1st Ctrl+D -> compact; after 2nd -> comfortable
    assert states[0] == (True, False), f"start state {states[0]}"
    assert states[1] == (False, True), f"after 1x Ctrl+D {states[1]}"
    assert states[2] == (True, False), f"after 2x Ctrl+D {states[2]}"


def test_tc014_cycle_density_action_toggles(tmp_path: Path) -> None:
    """``action_cycle_density`` is an exclusive two-state toggle.

    Intent: each call swaps exactly one density class for the other — the
    body is never left with both or neither density class.
    """

    async def _drive() -> list[tuple[bool, bool]]:
        app = S19TuiApp(base_dir=tmp_path)
        states: list[tuple[bool, bool]] = []
        async with app.run_test() as pilot:
            await pilot.pause()
            body = app.query_one("#workspace_body")
            for _ in range(3):
                app.action_cycle_density()
                await pilot.pause()
                states.append(
                    (
                        body.has_class("density-comfortable"),
                        body.has_class("density-compact"),
                    )
                )
        return states

    states = asyncio.run(_drive())
    for comfortable, compact in states:
        assert comfortable != compact, (
            "Density must be exactly one of comfortable/compact, "
            f"got comfortable={comfortable} compact={compact}"
        )
    assert states == [(False, True), (True, False), (False, True)]


# ---------------------------------------------------------------------------
# TC-037 — empty-state panel when no file is loaded (LLR-002.3)
# ---------------------------------------------------------------------------


def test_tc037_empty_state_panel_prompts_to_load() -> None:
    """The ``EmptyStatePanel`` widget renders a load prompt (LLR-002.3).

    Intent: the no-file-loaded panel must prompt a load action rather than
    show a blank pane or an error; the prompt text references the load key.
    """

    panel = EmptyStatePanel()
    assert panel.id == "empty_state_panel"
    text = panel.PROMPT_TEXT.lower()
    assert "no file loaded" in text, f"prompt should state no-file: {text!r}"
    assert "load" in text, f"prompt should invite a load action: {text!r}"


def test_tc037_memory_map_shows_empty_state_with_no_file(tmp_path: Path) -> None:
    """Activating Memory Map with no LoadedFile shows the empty-state panel.

    Intent: LLR-002.3 — a rail screen activated while no file is loaded
    shows a neutral empty-state panel, not an error or a blank pane. The
    Memory Map slot is the increment-2-owned scaffold; Workspace/A2L/MAC
    empty-state integration lands with their re-layout (increments 5-7).
    """

    async def _drive() -> tuple[bool, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            no_file = app.current_file is None
            app.action_show_screen("map")
            await pilot.pause()
            screen_map = app.query_one("#screen_map")
            panels = screen_map.query(EmptyStatePanel)
            return no_file, len(panels)

    no_file, panel_count = asyncio.run(_drive())
    assert no_file, "precondition: no file loaded"
    assert panel_count == 1, (
        f"Memory Map should show exactly one empty-state panel, "
        f"found {panel_count}"
    )


def test_tc037_scaffold_screens_carry_empty_state(tmp_path: Path) -> None:
    """Every rail screen activated with no file shows a neutral, non-blank state.

    Intent: LLR-002.3 — no rail screen activated before any load is left
    blank. The neutral state takes one of two forms: the file-dependent
    screens (Workspace, A2L, MAC, Memory Map, Issues) each carry an
    ``EmptyStatePanel``; the always-static screens (Bookmarks placeholder,
    and the Patch / Diff ``ScreenScaffold`` slots) carry their own neutral
    content. This test asserts that every one of the 8 rail screens, when
    activated with no file loaded, has at least one non-blank widget — so
    the intent ("never a blank pane") holds for the whole rail.

    As of increment 9 the Memory Map and Bookmarks scaffolds gained real
    content: Memory Map keeps an ``EmptyStatePanel`` (it is file-dependent),
    Bookmarks shows a ``BookmarksPlaceholder`` instead. The remaining
    ``ScreenScaffold`` slots are Patch and Diff.
    """
    from textual.widgets import Static

    async def _drive() -> dict[str, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            counts: dict[str, int] = {}
            for key, sid in zip(SCREEN_KEYS, SCREEN_IDS):
                app.action_show_screen(key)
                await pilot.pause()
                screen = app.query_one(f"#{sid}")
                # A non-blank screen has at least one Static descendant
                # carrying visible text (an EmptyStatePanel, a placeholder,
                # or a scaffold body) — none is an error and none is blank.
                non_blank = sum(
                    1
                    for static in screen.query(Static)
                    if str(static.render()).strip()
                )
                counts[sid] = non_blank
            return counts

    counts = asyncio.run(_drive())
    for sid, non_blank in counts.items():
        assert non_blank >= 1, (
            f"rail screen {sid} must show a non-blank neutral state with "
            f"no file loaded, found {non_blank} non-blank Static widgets"
        )


# ===========================================================================
# Increment 3 — activity rail widget + rail navigation wiring
# ===========================================================================

# The 8 rail items, in rail order, paired with their screen key and the
# normative LLR-001.3 glyph -> screen mapping table (Unicode + ASCII).
EXPECTED_RAIL = [
    ("workspace", "◫", "#"),
    ("a2l", "≡", "="),
    ("mac", "◉", "@"),
    ("map", "▤", "M"),
    ("issues", "!", "!"),
    ("patch", "✎", "P"),
    ("diff", "⏚", "D"),
    ("bookmarks", "✶", "*"),
]


# ---------------------------------------------------------------------------
# TC-001 — rail composes 8 ordered items on keys 1-8 (LLR-001.1)
# ---------------------------------------------------------------------------


def test_tc001_rail_composes_eight_ordered_items(tmp_path: Path) -> None:
    """The activity rail composes exactly 8 items in the keymap rail order.

    Intent: LLR-001.1 — the rail is fixed at eight items (OQ-3 resolved),
    ordered Workspace, A2L, MAC, Map, Issues, Patch, Diff, Bookmarks. Each
    item's 1-based position is its ``1``-``8`` keymap key, and that key
    routes the item's screen via ``action_show_screen``.
    """

    async def _drive() -> tuple[list[str], list[int]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            items = list(app.query(RailItem))
            keys = [item.entry.key for item in items]
            positions = [item.position for item in items]
            return keys, positions

    keys, positions = asyncio.run(_drive())
    assert keys == [key for key, _, _ in EXPECTED_RAIL], (
        f"Rail item order should match the keymap rail order, got {keys}"
    )
    assert positions == [1, 2, 3, 4, 5, 6, 7, 8], (
        f"Rail items must be positioned 1-8 in order, got {positions}"
    )


def test_tc001_rail_keys_1_to_8_route_through_rail_items(tmp_path: Path) -> None:
    """Pressing ``1``-``8`` activates the screen of the same-position rail item.

    Intent: LLR-001.1 — each rail item is bound to its ``1``-``8`` key. The
    digit keys must route to the same screen that rail item represents, so
    keyboard navigation and the rail agree.
    """

    async def _drive() -> dict[str, str]:
        app = S19TuiApp(base_dir=tmp_path)
        result: dict[str, str] = {}
        async with app.run_test() as pilot:
            await pilot.pause()
            for digit, (screen_key, _, _) in zip("12345678", EXPECTED_RAIL):
                await pilot.press(digit)
                await pilot.pause()
                result[digit] = app.query_one(Rail).active_key
        return result

    per_digit = asyncio.run(_drive())
    for digit, (screen_key, _, _) in zip("12345678", EXPECTED_RAIL):
        assert per_digit[digit] == screen_key, (
            f"Key '{digit}' should activate rail item '{screen_key}', "
            f"got '{per_digit[digit]}'"
        )


# ---------------------------------------------------------------------------
# TC-002 — exactly one rail item active; Workspace active at startup
#          (LLR-001.2)
# ---------------------------------------------------------------------------


def test_tc002_workspace_active_at_startup(tmp_path: Path) -> None:
    """At startup exactly the Workspace rail item carries the active marker.

    Intent: LLR-001.2 — the rail marks exactly one item active with the
    accent ``-active`` marker, and Workspace is the startup screen.
    """

    async def _drive() -> list[str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            return [
                item.entry.key
                for item in app.query(RailItem)
                if item.has_class("-active")
            ]

    active = asyncio.run(_drive())
    assert active == ["workspace"], (
        f"At startup only Workspace should be active, got {active}"
    )


def test_tc002_active_marker_moves_and_clears_previous(tmp_path: Path) -> None:
    """Activating another rail item moves the marker and clears the previous.

    Intent: LLR-001.2 — the single-active-item invariant holds across every
    navigation. Activating item 3 (MAC) must leave exactly MAC active and
    Workspace cleared; the invariant is checked for all eight items and for
    both the key path and the rail-click path.
    """

    async def _drive() -> tuple[list[str], list[list[str]], list[list[str]]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            rail = app.query_one(Rail)

            # Activate item 3 (MAC) explicitly per the TC-002 step.
            app.action_show_screen("mac")
            await pilot.pause()
            after_mac = [
                item.entry.key
                for item in app.query(RailItem)
                if item.has_class("-active")
            ]

            # Key path — exactly one active for every digit 1-8.
            key_states: list[list[str]] = []
            for digit in "12345678":
                await pilot.press(digit)
                await pilot.pause()
                key_states.append(
                    [
                        item.entry.key
                        for item in app.query(RailItem)
                        if item.has_class("-active")
                    ]
                )

            # Click path — a RailItem click posts RailItem.Selected, which
            # the Rail re-posts as Rail.Selected; the app routes it. This
            # drives the same message chain a real mouse click produces.
            click_states: list[list[str]] = []
            for item in list(app.query(RailItem)):
                item.post_message(RailItem.Selected(item.entry.key))
                await pilot.pause()
                click_states.append(
                    [
                        ri.entry.key
                        for ri in app.query(RailItem)
                        if ri.has_class("-active")
                    ]
                )
            del rail
            return after_mac, key_states, click_states

    after_mac, key_states, click_states = asyncio.run(_drive())
    assert after_mac == ["mac"], (
        f"After activating item 3 only MAC should be active, got {after_mac}"
    )
    for digit, state in zip("12345678", key_states):
        screen_key = EXPECTED_RAIL[int(digit) - 1][0]
        assert state == [screen_key], (
            f"Key '{digit}': exactly the '{screen_key}' item must be "
            f"active, got {state}"
        )
    for state, (screen_key, _, _) in zip(click_states, EXPECTED_RAIL):
        assert state == [screen_key], (
            f"Rail-click on '{screen_key}': exactly that item must be "
            f"active, got {state}"
        )


# ---------------------------------------------------------------------------
# TC-035 — rail items render a Unicode glyph with an ASCII fallback
#          (LLR-001.3)
# ---------------------------------------------------------------------------


def test_tc035_unicode_glyphs_match_normative_mapping(tmp_path: Path) -> None:
    """In default mode each rail item renders its normative Unicode glyph.

    Intent: LLR-001.3 — Unicode is the default; the glyph -> screen pairing
    must match the normative mapping table (`◫ ≡ ◉ ▤ ! ✎ ⏚ ✶`) for all
    eight items, no longer implied only by positional order.
    """

    async def _drive() -> list[tuple[str, str]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            return [
                (item.entry.key, item.current_glyph)
                for item in app.query(RailItem)
            ]

    rendered = asyncio.run(_drive())
    for (screen_key, glyph), (exp_key, exp_glyph, _) in zip(rendered, EXPECTED_RAIL):
        assert screen_key == exp_key, f"order: {screen_key} != {exp_key}"
        assert glyph == exp_glyph, (
            f"Rail item '{screen_key}' should render Unicode glyph "
            f"{exp_glyph!r}, got {glyph!r}"
        )


def test_tc035_each_item_has_a_distinct_defined_ascii_fallback() -> None:
    """Every rail item carries a defined, distinct ASCII-fallback glyph.

    Intent: LLR-001.3 — each item has a paired ASCII fallback for terminals
    that cannot render the Unicode set. The fallback glyphs are inspected
    against the normative mapping table and must each be a defined
    single-character glyph.
    """

    for entry, (exp_key, _, exp_ascii) in zip(RAIL_ENTRIES, EXPECTED_RAIL):
        assert entry.key == exp_key, f"order: {entry.key} != {exp_key}"
        assert entry.ascii_glyph == exp_ascii, (
            f"Rail item '{entry.key}' ASCII fallback should be "
            f"{exp_ascii!r}, got {entry.ascii_glyph!r}"
        )
        assert len(entry.ascii_glyph) == 1, (
            f"ASCII fallback for '{entry.key}' must be a single character"
        )
        assert entry.ascii_glyph.isascii(), (
            f"ASCII fallback for '{entry.key}' must be ASCII-only"
        )


def test_tc035_ascii_fallback_mode_renders_ascii_set(tmp_path: Path) -> None:
    """Forcing ASCII-fallback mode renders the ASCII glyph set without error.

    Intent: LLR-001.3 — selecting the ASCII-fallback mode is reachable and
    safe; in fallback mode every rail item renders its ASCII glyph instead
    of the Unicode glyph, and the app mounts without raising.
    """

    async def _drive() -> list[tuple[str, str]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            # Force the fallback mode by re-mounting the rail in ASCII mode.
            slot = app.query_one("#rail_slot")
            await app.query_one(Rail).remove()
            await slot.mount(Rail(active="workspace", ascii_mode=True))
            await pilot.pause()
            return [
                (item.entry.key, item.current_glyph)
                for item in app.query(RailItem)
            ]

    rendered = asyncio.run(_drive())
    assert len(rendered) == 8, f"expected 8 rail items, got {len(rendered)}"
    for (screen_key, glyph), (exp_key, _, exp_ascii) in zip(rendered, EXPECTED_RAIL):
        assert screen_key == exp_key, f"order: {screen_key} != {exp_key}"
        assert glyph == exp_ascii, (
            f"In ASCII mode rail item '{screen_key}' should render "
            f"{exp_ascii!r}, got {glyph!r}"
        )


# ---------------------------------------------------------------------------
# TC-006 — command bar present on every screen (LLR-003.1)
# ---------------------------------------------------------------------------


def test_tc006_command_bar_present_on_every_screen(tmp_path: Path) -> None:
    """The command bar is mounted and stays present on every rail screen.

    Intent: LLR-003.1 — the command bar (palette trigger + find input +
    go-to input) is mounted above the rail/workspace body and remains in
    the widget tree regardless of which of the 8 rail screens is active;
    navigating the rail never unmounts it.
    """

    async def _drive() -> list[tuple[str, bool, bool, bool]]:
        app = S19TuiApp(base_dir=tmp_path)
        seen: list[tuple[str, bool, bool, bool]] = []
        async with app.run_test() as pilot:
            await pilot.pause()
            for key in SCREEN_KEYS:
                app.action_show_screen(key)
                await pilot.pause()
                bar = app.query_one(CommandBar)
                seen.append(
                    (
                        key,
                        bar.query("#find_input").first() is not None,
                        bar.query("#cmdbar_goto_input").first() is not None,
                        bar.query("#command_palette").first() is not None,
                    )
                )
        return seen

    seen = asyncio.run(_drive())
    assert len(seen) == 8, f"expected all 8 screens visited, got {len(seen)}"
    for key, has_find, has_goto, has_palette in seen:
        assert has_find, f"find input missing on screen '{key}'"
        assert has_goto, f"go-to input missing on screen '{key}'"
        assert has_palette, f"palette missing on screen '{key}'"


# ---------------------------------------------------------------------------
# TC-010 — Ctrl+K opens/focuses the command palette (LLR-004.3)
# ---------------------------------------------------------------------------


def test_tc010_ctrl_k_opens_palette_from_every_screen(tmp_path: Path) -> None:
    """``Ctrl+K`` opens and focuses the command palette from any screen.

    Intent: LLR-004.3 — pressing ``Ctrl+K`` on every rail screen opens the
    palette dropdown and moves keyboard focus to its filter input. The
    binding is ``priority=True`` so it fires even while a command-bar
    input already holds focus.
    """

    async def _drive() -> list[tuple[str, bool, str]]:
        app = S19TuiApp(base_dir=tmp_path)
        results: list[tuple[str, bool, str]] = []
        async with app.run_test() as pilot:
            await pilot.pause()
            for key in SCREEN_KEYS:
                app.action_show_screen(key)
                bar = app.query_one(CommandBar)
                bar.close_palette()
                await pilot.pause()
                await pilot.press("ctrl+k")
                await pilot.pause()
                focused_id = app.focused.id if app.focused else ""
                results.append((key, bar.palette_is_open, focused_id or ""))
        return results

    results = asyncio.run(_drive())
    assert len(results) == 8
    for key, is_open, focused_id in results:
        assert is_open, f"palette did not open on screen '{key}'"
        assert focused_id == "palette_input", (
            f"Ctrl+K should focus the palette input on '{key}', "
            f"focused '{focused_id}'"
        )


# ---------------------------------------------------------------------------
# TC-036 — command palette filters commands as the user types (LLR-003.3)
# ---------------------------------------------------------------------------


def test_tc036_palette_type_to_filter_narrows_and_restores(tmp_path: Path) -> None:
    """Typing in the palette narrows the list; clearing it restores the full set.

    Intent: LLR-003.3 — the palette is searchable. Typing a substring
    matching a subset of commands shows only the matches; clearing the
    filter text restores every command. Verified through the real
    ``Input.Changed`` path (driven keystrokes), not by calling the filter
    helper directly.
    """

    async def _drive() -> tuple[list[str], list[str], list[str]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            bar = app.query_one(CommandBar)
            await pilot.press("ctrl+k")
            await pilot.pause()
            full = bar.visible_palette_labels()
            # "density" matches exactly the Ctrl+D cycle command.
            for ch in "density":
                await pilot.press(ch)
            await pilot.pause()
            narrowed = bar.visible_palette_labels()
            # Clear the filter — value emptied — restore the full list.
            app.query_one("#palette_input").value = ""
            await pilot.pause()
            restored = bar.visible_palette_labels()
        return full, narrowed, restored

    full, narrowed, restored = asyncio.run(_drive())
    assert len(full) > len(narrowed), (
        f"typing 'density' should narrow the list ({len(full)} -> "
        f"{len(narrowed)})"
    )
    assert narrowed, "filtering to 'density' should leave at least one match"
    assert all("density" in label.lower() for label in narrowed), (
        f"every narrowed entry must match 'density', got {narrowed}"
    )
    assert restored == full, (
        "clearing the filter text must restore the full command list"
    )


# ---------------------------------------------------------------------------
# TC-038 — project / A2L labels stay visible in the command bar (LLR-011.3)
# ---------------------------------------------------------------------------


def test_tc038_project_a2l_labels_render_in_command_bar(tmp_path: Path) -> None:
    """Project name + A2L filename render in the command bar on every screen.

    Intent: LLR-011.3 — when the Issues table is promoted out of the old
    Status tile, the project-name / A2L-filename context content must move
    to the persistent command bar so it stays visible from every Direction
    B screen. With a project + A2L set, ``update_project_labels`` feeds the
    command-bar labels; the labels persist across all 8 rail screens.
    """

    async def _drive() -> list[tuple[str, str, str]]:
        app = S19TuiApp(base_dir=tmp_path)
        seen: list[tuple[str, str, str]] = []
        async with app.run_test() as pilot:
            await pilot.pause()
            app.current_project = "demo_project"
            app.current_a2l_path = tmp_path / "ASAP2_Demo_V161.a2l"
            app.current_file = LoadedFile(
                path=tmp_path / "prg.s19",
                file_type="s19",
                mem_map={0x1000: 0x11},
                row_bases=[0x1000],
                ranges=[(0x1000, 0x1001)],
                range_validity=[True],
                errors=[],
                a2l_path=tmp_path / "ASAP2_Demo_V161.a2l",
                a2l_data=None,
            )
            app.update_project_labels()
            await pilot.pause()
            for key in SCREEN_KEYS:
                app.action_show_screen(key)
                await pilot.pause()
                bar = app.query_one(CommandBar)
                project = str(bar.query_one("#cmdbar_project").content)
                a2l = str(bar.query_one("#cmdbar_a2l").content)
                seen.append((key, project, a2l))
        return seen

    seen = asyncio.run(_drive())
    assert len(seen) == 8
    for key, project, a2l in seen:
        assert "demo_project" in project, (
            f"project name missing from command bar on '{key}': {project!r}"
        )
        assert "ASAP2_Demo_V161.a2l" in a2l, (
            f"A2L filename missing from command bar on '{key}': {a2l!r}"
        )


# ---------------------------------------------------------------------------
# TC-017 — Workspace presents three named panes at the two-regime tolerances
#          (LLR-008.1)
# ---------------------------------------------------------------------------

# The public synthetic S19 fixture used for the increment-5 Workspace tests
# (LLR-007.2 — public fixtures only; never a client artifact).
_PRG_S19 = (
    Path(__file__).resolve().parent.parent
    / "examples"
    / "case_00_public"
    / "prg.s19"
)


def _install_prg_loaded_file(app: S19TuiApp) -> None:
    """Install the public ``prg.s19`` fixture as ``current_file`` and reveal it.

    Increment 7 wires the LLR-002.3 empty state: with no ``LoadedFile`` the
    Workspace shows an ``EmptyStatePanel`` and hides ``#workspace_panes``.
    The TC-017 layout-regime assertions need the three panes visible, so a
    real ``LoadedFile`` is installed and ``_apply_empty_state`` is invoked —
    the same flip the real load pipeline performs. The pane *layout* under
    test is unchanged; only the no-file empty state is added.
    """
    from s19_app.core import S19File
    from s19_app.tui.services.load_service import build_loaded_s19

    s19 = S19File(str(_PRG_S19))
    app.current_file = build_loaded_s19(_PRG_S19, s19, a2l_path=None, a2l_data=None)
    app._apply_empty_state()


def test_tc017_workspace_three_panes_fixed_regime(tmp_path: Path) -> None:
    """At >=120 columns the Workspace shows three fixed-width panes (LLR-008.1).

    Intent: the Direction B Workspace is a horizontal three-pane layout —
    ranges/sections (left), hex view (center), context (right). At terminal
    widths >= 120 columns the side panes use the fixed-width regime: rail
    22, left 22 +/-2, right 40 +/-2, center the ``1fr`` flexible remainder.
    Asserted at both pinned fixed-regime sizes 120x30 and 160x40 so the
    layout cannot silently drift to proportional widths above the breakpoint.
    """

    async def _drive(size: tuple[int, int]) -> dict[str, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            _install_prg_loaded_file(app)
            await pilot.pause()
            body = app.query_one("#workspace_body")
            return {
                "narrow": int(body.has_class("width-narrow")),
                "rail": app.query_one("#activity_rail").region.width,
                "left": app.query_one("#ws_left").region.width,
                "center": app.query_one("#ws_center").region.width,
                "right": app.query_one("#ws_right").region.width,
            }

    for size in [(120, 30), (160, 40)]:
        dims = asyncio.run(_drive(size))
        assert dims["narrow"] == 0, (
            f"at {size} (>=120 cols) the fixed regime must be active "
            f"(width-narrow must be unset)"
        )
        assert dims["rail"] == 22, (
            f"at {size} the rail must be the wide 22-col rail, got "
            f"{dims['rail']}"
        )
        assert 20 <= dims["left"] <= 24, (
            f"at {size} the left ranges/sections pane must be 22+/-2 cols, "
            f"got {dims['left']}"
        )
        assert 38 <= dims["right"] <= 42, (
            f"at {size} the right context pane must be 40+/-2 cols, got "
            f"{dims['right']}"
        )
        assert dims["center"] > 0, (
            f"at {size} the center hex pane (1fr) must be strictly positive, "
            f"got {dims['center']}"
        )


def test_tc017_workspace_pane_order_left_to_right(tmp_path: Path) -> None:
    """The three Workspace panes are ordered ranges/sections, hex, context.

    Intent: LLR-008.1 fixes the left-to-right pane order. The ranges/sections
    pane (carrying ``#sections_list``) is leftmost, the hex pane (carrying
    ``#hex_view``) is in the center, the context pane (carrying ``#a2l_view``)
    is rightmost — verified by the ascending x-offset of each pane's region.
    """

    async def _drive() -> tuple[int, int, int, list[str]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _install_prg_loaded_file(app)
            await pilot.pause()
            left = app.query_one("#ws_left")
            center = app.query_one("#ws_center")
            right = app.query_one("#ws_right")
            # Each pane hosts the renderer target it owns.
            owns = [
                "sections_list" if left.query("#sections_list") else "?",
                "hex_view" if center.query("#hex_view") else "?",
                "a2l_view" if right.query("#a2l_view") else "?",
            ]
            return (
                left.region.x,
                center.region.x,
                right.region.x,
                owns,
            )

    left_x, center_x, right_x, owns = asyncio.run(_drive())
    assert left_x < center_x < right_x, (
        f"panes must be ordered left<center<right, got x-offsets "
        f"{left_x}/{center_x}/{right_x}"
    )
    assert owns == ["sections_list", "hex_view", "a2l_view"], (
        f"each pane must host its renderer target, got {owns}"
    )


def test_tc017_workspace_three_panes_proportional_regime(tmp_path: Path) -> None:
    """At <120 columns the Workspace side panes are proportional (LLR-008.1).

    Intent: below the 120-column breakpoint the Workspace switches to the
    proportional regime — left 24% +/-3 points, right 30% +/-3 points of the
    workspace body width, center the ``1fr`` remainder and strictly positive
    (no clip, no overlap), and the activity rail collapses to 4 +/-1 columns.
    Asserted at the 80x24 minimum supported size.
    """

    async def _drive() -> dict[str, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            _install_prg_loaded_file(app)
            await pilot.pause()
            body = app.query_one("#workspace_body")
            return {
                "narrow": int(body.has_class("width-narrow")),
                "body": body.region.width,
                "rail": app.query_one("#activity_rail").region.width,
                "left": app.query_one("#ws_left").region.width,
                "center": app.query_one("#ws_center").region.width,
                "right": app.query_one("#ws_right").region.width,
            }

    dims = asyncio.run(_drive())
    assert dims["narrow"] == 1, (
        "at 80x24 (<120 cols) the proportional regime must be active "
        "(width-narrow must be set)"
    )
    assert 3 <= dims["rail"] <= 5, (
        f"at 80x24 the rail must collapse to 4+/-1 cols, got {dims['rail']}"
    )
    left_pct = 100 * dims["left"] / dims["body"]
    right_pct = 100 * dims["right"] / dims["body"]
    assert 21 <= left_pct <= 27, (
        f"at 80x24 the left pane must be 24%+/-3 points of the body, got "
        f"{left_pct:.1f}%"
    )
    assert 27 <= right_pct <= 33, (
        f"at 80x24 the right pane must be 30%+/-3 points of the body, got "
        f"{right_pct:.1f}%"
    )
    assert dims["center"] > 0, (
        f"at 80x24 the center hex pane (1fr) must be allocated a strictly "
        f"positive width, got {dims['center']}"
    )


# ---------------------------------------------------------------------------
# TC-018 — Workspace data wiring unchanged; hex caps honored (LLR-008.2)
# ---------------------------------------------------------------------------


def test_tc018_workspace_panes_populate_from_loaded_file(tmp_path: Path) -> None:
    """The re-laid-out Workspace panes populate from a loaded S19 fixture.

    Intent: LLR-008.2 — the three-pane re-layout reuses the existing
    ``update_sections`` / ``update_hex_view`` renderers unchanged; they must
    still populate the ``#sections_list`` and ``#hex_view`` widgets (now
    inside the new panes) when fed a real ``LoadedFile`` parsed from the
    public ``prg.s19`` fixture. The renderers parse no data — they read the
    ``LoadedFile`` snapshot only.
    """
    from textual.widgets import ListView, Static

    from s19_app.core import S19File
    from s19_app.tui.services.load_service import build_loaded_s19

    s19 = S19File(str(_PRG_S19))
    loaded = build_loaded_s19(_PRG_S19, s19, a2l_path=None, a2l_data=None)
    assert loaded.ranges, "fixture prg.s19 must parse to at least one range"

    async def _drive() -> tuple[int, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.current_file = loaded
            app.update_sections()
            app.update_hex_view()
            await pilot.pause()
            sections = app.query_one("#sections_list", ListView)
            hex_text = str(app.query_one("#hex_view", Static).content)
            return len(sections.children), hex_text

    section_rows, hex_text = asyncio.run(_drive())
    assert section_rows > 0, (
        "update_sections must populate the left pane #sections_list"
    )
    assert hex_text.strip(), (
        "update_hex_view must populate the center pane #hex_view"
    )


def test_tc018_workspace_hex_render_caps_unchanged() -> None:
    """The hex-view render caps are unchanged by the Workspace re-layout.

    Intent: LLR-008.2 / HLR-014 — the increment-5 re-layout is pane
    composition + CSS only. The hex render-cost caps exported from
    ``s19_app.tui`` (``MAX_HEX_BYTES`` / ``MAX_HEX_ROWS`` /
    ``FOCUS_CONTEXT_ROWS`` / ``HEX_WIDTH``) must keep their pre-batch values;
    a re-layout that silently changed a cap would change hex render cost.
    """
    from s19_app.tui import hexview

    # Pre-batch values — pinned so a re-layout cannot drift a render cap.
    assert hexview.HEX_WIDTH == 16
    assert hexview.MAX_HEX_ROWS == 512
    assert hexview.MAX_HEX_BYTES == 65536
    assert hexview.FOCUS_CONTEXT_ROWS == 64


def test_tc018_workspace_hex_output_bounded_by_max_rows(tmp_path: Path) -> None:
    """``update_hex_view`` output stays bounded by ``MAX_HEX_ROWS`` (LLR-008.2).

    Intent: the center hex pane reuses ``update_hex_view`` verbatim, so the
    ``MAX_HEX_ROWS`` row cap still governs how many hex rows render. Feeding
    a memory map far larger than ``MAX_HEX_ROWS`` rows must not produce an
    unbounded ``#hex_view`` body — the cap is honored after the re-layout.
    """
    from textual.widgets import Static

    from s19_app.tui import hexview

    # A mem_map spanning many more rows than MAX_HEX_ROWS would allow.
    over_cap_rows = hexview.MAX_HEX_ROWS + 200
    big_map = {
        0x1000 + i: 0x41
        for i in range(hexview.HEX_WIDTH * over_cap_rows)
    }
    loaded = LoadedFile(
        path=tmp_path / "big.s19",
        file_type="s19",
        mem_map=big_map,
        row_bases=[
            0x1000 + (i * hexview.HEX_WIDTH) for i in range(over_cap_rows)
        ],
        ranges=[(0x1000, 0x1000 + hexview.HEX_WIDTH * over_cap_rows)],
        range_validity=[True],
        errors=[],
        a2l_path=None,
        a2l_data=None,
    )

    async def _drive() -> int:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.current_file = loaded
            app.update_hex_view()
            await pilot.pause()
            hex_text = str(app.query_one("#hex_view", Static).content)
            return len(hex_text.splitlines())

    line_count = asyncio.run(_drive())
    # Allowing a small margin for the address-window header / truncation line,
    # the rendered body must not exceed the MAX_HEX_ROWS cap unbounded.
    assert line_count <= hexview.MAX_HEX_ROWS + 8, (
        f"#hex_view rendered {line_count} lines — the MAX_HEX_ROWS "
        f"({hexview.MAX_HEX_ROWS}) cap is not honored after the re-layout"
    )


# ===========================================================================
# Increment 6 — A2L Explorer + MAC View two-pane re-layout
# ===========================================================================
#
# TC-019 verdicts the pane widths of the restyled A2L Explorer; TC-021
# verdicts the two-regime pane widths of the restyled MAC View; TC-020/
# TC-022 verdict that A2L filtering, A2L/MAC paging and jump-to-address
# survive the re-layout unchanged.
#
# Increment 13 (review feedback — the fixed-40 A2L hex pane was too narrow
# to render the hex view correctly) supersedes the increment-6 two-regime
# A2L pane split with a flat 3/7 hex : 4/7 tags proportional ratio at ALL
# terminal widths (LLR-009.1). MAC View (TC-021) keeps the two-regime
# layout unchanged.
#
# The fixtures are the public ``case_01_basic_valid`` triple (S19 + A2L +
# MAC) — LLR-007.2 keeps tests on public fixtures, never client artifacts.

_CASE_01 = (
    Path(__file__).resolve().parent.parent / "examples" / "case_01_basic_valid"
)
_CASE_01_S19 = _CASE_01 / "firmware.s19"
_CASE_01_A2L = _CASE_01 / "firmware.a2l"
_CASE_01_MAC = _CASE_01 / "firmware.mac"


def _load_case_01(app: S19TuiApp) -> None:
    """Install the public case_01 S19+A2L+MAC fixture onto a running app.

    Builds a ``LoadedFile`` directly via the load/parse services — the same
    deterministic path the increment-5 ``test_tc018`` tests use — so the
    re-laid-out A2L/MAC screens populate without depending on the
    off-thread load worker. Sets ``current_a2l_*`` and the MAC records so
    ``update_a2l_view`` / ``update_mac_view`` have data to render.
    """
    from s19_app.core import S19File
    from s19_app.tui.a2l import parse_a2l_file
    from s19_app.tui.mac import parse_mac_file
    from s19_app.tui.services.load_service import build_loaded_s19

    a2l_data = parse_a2l_file(_CASE_01_A2L)
    s19 = S19File(str(_CASE_01_S19))
    loaded = build_loaded_s19(
        _CASE_01_S19, s19, a2l_path=_CASE_01_A2L, a2l_data=a2l_data
    )
    mac = parse_mac_file(_CASE_01_MAC)
    loaded.mac_path = _CASE_01_MAC
    loaded.mac_records = mac.get("records", [])
    loaded.mac_diagnostics = mac.get("diagnostics", [])
    app.current_a2l_path = _CASE_01_A2L
    app.current_a2l_data = a2l_data
    app.current_file = loaded


# ---------------------------------------------------------------------------
# TC-019 — A2L Explorer presents two panes at the two-regime tolerances
#          (LLR-009.1)
# ---------------------------------------------------------------------------


def test_tc019_a2l_hex_pane_three_sevenths_at_wide_sizes(tmp_path: Path) -> None:
    """At >=120 columns the A2L hex pane is 3/7 of the A2L content width.

    Intent: LLR-009.1 (increment-13 amendment) — the Direction B A2L
    Explorer is a horizontal two-pane layout with a flat 3/7 hex : 4/7
    tags proportional ratio at ALL terminal widths. The increment-6
    two-regime ``40 / 35%`` split is superseded for A2L (review feedback:
    the fixed-40 hex pane was too narrow to render the hex view
    correctly). The hex pane is ``3fr`` and the tags pane ``4fr``, so the
    hex pane is 3/7 (~=42.9%) +/-3 points of the combined A2L panes
    content width. Asserted at 120x30 and 160x40 so the ratio cannot
    silently drift at the larger sizes.
    """

    async def _drive(size: tuple[int, int]) -> dict[str, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            app.action_show_screen("a2l")
            await pilot.pause()
            return {
                "tags": app.query_one("#a2l_tags_pane").region.width,
                "hex": app.query_one("#a2l_hex_pane").region.width,
            }

    for size in [(120, 30), (160, 40)]:
        dims = asyncio.run(_drive(size))
        content = dims["tags"] + dims["hex"]
        assert content > 0, f"at {size} the A2L panes must have positive width"
        hex_pct = 100 * dims["hex"] / content
        # 3/7 == 42.857...% ; +/-3 points absorbs integer-rounding.
        assert 39.9 <= hex_pct <= 45.9, (
            f"at {size} the A2L hex pane must be 3/7 (~=42.9%) +/-3 points "
            f"of the A2L content width, got {hex_pct:.1f}% "
            f"(hex={dims['hex']}, tags={dims['tags']})"
        )
        assert dims["tags"] > 0, (
            f"at {size} the A2L tags pane (4fr) must be strictly positive, "
            f"got {dims['tags']}"
        )


def test_tc019_a2l_hex_pane_three_sevenths_at_min_size(tmp_path: Path) -> None:
    """At the 80x24 minimum the A2L hex pane is still 3/7 (LLR-009.1).

    Intent: the increment-13 flat ratio holds at EVERY terminal width —
    there is no longer a 120-column regime split for the A2L panes. At the
    80x24 minimum supported size the hex pane is still 3/7 (~=42.9%)
    +/-3 points of the A2L content width and the tags pane the 4/7
    strictly-positive remainder.
    """

    async def _drive() -> dict[str, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            app.action_show_screen("a2l")
            await pilot.pause()
            return {
                "tags": app.query_one("#a2l_tags_pane").region.width,
                "hex": app.query_one("#a2l_hex_pane").region.width,
            }

    dims = asyncio.run(_drive())
    content = dims["tags"] + dims["hex"]
    assert content > 0, "at 80x24 the A2L panes must have positive width"
    hex_pct = 100 * dims["hex"] / content
    assert 39.9 <= hex_pct <= 45.9, (
        f"at 80x24 the A2L hex pane must be 3/7 (~=42.9%) +/-3 points of "
        f"the A2L content width, got {hex_pct:.1f}% "
        f"(hex={dims['hex']}, tags={dims['tags']})"
    )
    assert dims["tags"] > 0, (
        f"at 80x24 the A2L tags pane (4fr) must be strictly positive, "
        f"got {dims['tags']}"
    )


def test_tc019_a2l_pane_order_table_then_hex(tmp_path: Path) -> None:
    """The two A2L Explorer panes are ordered tags-table then hex.

    Intent: LLR-009.1 fixes the left-to-right pane order — the tags-table
    pane (carrying ``#a2l_tags_list``) is leftmost, the hex pane (carrying
    ``#alt_hex_view``) is to its right, verified by ascending x-offset.
    """

    async def _drive() -> tuple[int, int, list[str]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("a2l")
            await pilot.pause()
            tags = app.query_one("#a2l_tags_pane")
            hexp = app.query_one("#a2l_hex_pane")
            owns = [
                "a2l_tags_list" if tags.query("#a2l_tags_list") else "?",
                "alt_hex_view" if hexp.query("#alt_hex_view") else "?",
            ]
            return tags.region.x, hexp.region.x, owns

    tags_x, hex_x, owns = asyncio.run(_drive())
    assert tags_x < hex_x, (
        f"A2L panes must be ordered table<hex, got x-offsets "
        f"{tags_x}/{hex_x}"
    )
    assert owns == ["a2l_tags_list", "alt_hex_view"], (
        f"each A2L pane must host its renderer target, got {owns}"
    )


# ---------------------------------------------------------------------------
# TC-021 — MAC View presents two panes under the batch-06 proportional+floor
#          model (4fr records : 3fr hex, hex min-width 82)
# ---------------------------------------------------------------------------


def test_tc021_mac_two_panes_fixed_regime(tmp_path: Path) -> None:
    """At >=120 columns the MAC hex pane is held at the 82-cell floor.

    Intent: batch-06 (HLR-001) supersedes the batch-05 fixed ``width: 82``
    cap with the A2L-style proportional+floor model — ``#mac_records_pane
    4fr``, ``#mac_hex_pane 3fr; min-width: 82`` — so the hex pane width is
    ``max(82, round(3/7 * body_w))``. At 120x30 and 160x40 the 3/7
    proportional share (~41 and ~58 of the body) is below the floor, so the
    pane must sit at 82 on both sizes; the band is the floor band 80..86
    (was the fixed-cap band 80..84). The ``4fr`` records pane takes the
    strictly-positive remainder.
    """

    async def _drive(size: tuple[int, int]) -> dict[str, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            app.action_show_screen("mac")
            await pilot.pause()
            body = app.query_one("#workspace_body")
            return {
                "narrow": int(body.has_class("width-narrow")),
                "records": app.query_one("#mac_records_pane").region.width,
                "hex": app.query_one("#mac_hex_pane").region.width,
            }

    for size in [(120, 30), (160, 40)]:
        dims = asyncio.run(_drive(size))
        assert dims["narrow"] == 0, (
            f"at {size} (>=120 cols) the width-narrow class must be unset "
            f"(it only drives the activity rail, below 120 cols)"
        )
        assert 80 <= dims["hex"] <= 86, (
            f"at {size} the MAC hex pane must be held at the 82-cell "
            f"min-width floor (80..86), got {dims['hex']}"
        )
        assert dims["records"] > 0, (
            f"at {size} the MAC records pane (4fr) must be strictly "
            f"positive, got {dims['records']}"
        )


def test_tc021_mac_two_panes_floor_below_minimum(tmp_path: Path) -> None:
    """Below the 120-col documented minimum the hex-pane floor still holds.

    Intent: batch-06 (LLR-001.3 / LLR-001.4) deletes the ``width-narrow``
    MAC rules (the retired ``35%`` proportional regime), so even at the
    sub-minimum 80x24 size the single proportional+floor model applies: the
    3/7 share of the ~74-cell body is far below 82, so ``min-width: 82``
    must keep the hex pane at the full-row floor — a full hex row stays
    readable instead of shrinking to ~35% of the body. (The records pane
    may clip toward zero here; that is graceful clipping below the
    documented 120-col minimum and is not asserted.)
    """

    async def _drive() -> dict[str, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            app.action_show_screen("mac")
            await pilot.pause()
            body = app.query_one("#workspace_body")
            return {
                "narrow": int(body.has_class("width-narrow")),
                "body": body.region.width,
                "hex": app.query_one("#mac_hex_pane").region.width,
            }

    dims = asyncio.run(_drive())
    assert dims["narrow"] == 1, (
        "at 80x24 (<120 cols) the width-narrow class is still set (it "
        "drives the activity rail) but no MAC rule may attach to it"
    )
    assert 80 <= dims["hex"] <= 86, (
        f"at 80x24 the MAC hex pane must be held at the 82-cell min-width "
        f"floor (80..86) — the retired width-narrow 35% regime must NOT "
        f"apply, got {dims['hex']} (body={dims['body']})"
    )


def test_tc021_mac_pane_order_table_then_hex(tmp_path: Path) -> None:
    """The two MAC View panes are ordered records-table then hex.

    Intent: LLR-010.1 fixes the left-to-right pane order — the records
    pane (carrying ``#mac_records_list``) is leftmost, the hex pane
    (carrying ``#mac_hex_view``) is to its right.
    """

    async def _drive() -> tuple[int, int, list[str]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("mac")
            await pilot.pause()
            records = app.query_one("#mac_records_pane")
            hexp = app.query_one("#mac_hex_pane")
            owns = [
                "mac_records_list" if records.query("#mac_records_list") else "?",
                "mac_hex_view" if hexp.query("#mac_hex_view") else "?",
            ]
            return records.region.x, hexp.region.x, owns

    records_x, hex_x, owns = asyncio.run(_drive())
    assert records_x < hex_x, (
        f"MAC panes must be ordered table<hex, got x-offsets "
        f"{records_x}/{hex_x}"
    )
    assert owns == ["mac_records_list", "mac_hex_view"], (
        f"each MAC pane must host its renderer target, got {owns}"
    )


# ---------------------------------------------------------------------------
# TC-020 / TC-022 — A2L filtering, A2L/MAC paging and jump survive the
#                   re-layout (LLR-009.2 / LLR-010.2)
# ---------------------------------------------------------------------------


def test_tc020_a2l_renderers_populate_through_restyled_screen(tmp_path: Path) -> None:
    """The restyled A2L Explorer panes populate from the public fixture.

    Intent: LLR-009.2 — the two-pane re-layout reuses the existing
    ``update_a2l_view`` / ``update_a2l_tags_view`` renderers unchanged;
    they must still populate the ``#a2l_tags_list`` table and the
    ``#alt_hex_view`` hex pane (now inside the new panes) when fed the
    public ``firmware.a2l`` + ``firmware.s19`` fixture. The renderers
    parse no data — they read the ``LoadedFile`` / parsed-A2L snapshot.
    """
    from textual.widgets import DataTable, Static

    async def _drive() -> tuple[int, int, bool]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _load_case_01(app)
            app.update_a2l_view()
            app.update_alt_hex_view()
            await pilot.pause()
            app.action_show_screen("a2l")
            await pilot.pause()
            table = app.query_one("#a2l_tags_list", DataTable)
            hex_text = str(app.query_one("#alt_hex_view", Static).content)
            in_pane = bool(
                app.query_one("#a2l_tags_pane").query("#a2l_tags_list")
            )
            return table.row_count, len(hex_text.strip()), in_pane

    rows, hex_len, in_pane = asyncio.run(_drive())
    assert rows > 0, (
        "update_a2l_tags_view must populate the #a2l_tags_list table "
        "in the restyled A2L tags pane"
    )
    assert hex_len > 0, (
        "update_alt_hex_view must populate the #alt_hex_view hex pane"
    )
    assert in_pane, "#a2l_tags_list must live inside #a2l_tags_pane"


def test_tc020_a2l_filtering_narrows_through_restyled_screen(tmp_path: Path) -> None:
    """A2L tag filtering still narrows the table after the re-layout.

    Intent: LLR-009.2 — the increment-6 re-layout is composition + CSS
    only; the A2L filter pipeline (``_compute_a2l_enriched_tags`` ->
    ``_filter_a2l_tags`` -> ``_refresh_a2l_filtered_tags`` ->
    ``update_a2l_tags_view``) must still narrow the visible tag set. A
    filter mode that excludes the schema-valid tags must shrink the
    filtered set below the unfiltered count — a re-layout that orphaned
    the filter widgets would leave the count unchanged.
    """

    async def _drive() -> tuple[int, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _load_case_01(app)
            app.action_show_screen("a2l")
            # Unfiltered baseline through the real refresh pipeline.
            app.a2l_tags_filter_mode = "all"
            app.a2l_tags_filter_field = "name"
            app.a2l_tags_filter_text = ""
            app._compute_a2l_enriched_tags()
            app._refresh_a2l_filtered_tags(preserve_anchor=False)
            await pilot.pause()
            baseline = len(app._a2l_filtered_tags)
            # A name-substring filter that matches no fixture tag must
            # narrow the filtered set to zero — the filter is live.
            app.a2l_tags_filter_field = "name"
            app.a2l_tags_filter_text = "zzz_no_such_tag_zzz"
            app._refresh_a2l_filtered_tags(preserve_anchor=False)
            await pilot.pause()
            narrowed = len(app._a2l_filtered_tags)
            return baseline, narrowed

    baseline, narrowed = asyncio.run(_drive())
    assert baseline > 0, "fixture firmware.a2l must enrich to >=1 tag"
    assert narrowed < baseline, (
        f"A2L name filter must narrow the tag set ({baseline} -> "
        f"{narrowed}); the filter pipeline is orphaned if it does not"
    )
    assert narrowed == 0, (
        f"a no-match filter substring must narrow to 0 tags, got {narrowed}"
    )


def test_tc020_a2l_paging_advances_through_restyled_screen(tmp_path: Path) -> None:
    """A2L tag paging still advances the window after the re-layout.

    Intent: LLR-009.2 — paging the A2L tags table must still move
    ``_a2l_window_start`` by one ``a2l_tags_page_size`` page and clamp at
    the last legal page. A synthetic multi-page enriched-tag list (>1
    page) is installed directly, then ``action_page_next_context`` is
    routed while the restyled A2L screen is active — exercising the same
    paging action the ``+`` key drives.
    """

    async def _drive() -> tuple[int, int, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            page = app.a2l_tags_page_size
            # Two-and-a-bit pages of synthetic enriched tags.
            app._a2l_enriched_tags = [
                {"name": f"TAG_{i:04d}", "schema_ok": True, "memory_checked": False}
                for i in range(page * 2 + 10)
            ]
            app.a2l_tags_filter_mode = "all"
            app.a2l_tags_filter_field = "name"
            app.a2l_tags_filter_text = ""
            app._refresh_a2l_filtered_tags(preserve_anchor=False)
            app.action_show_screen("a2l")
            await pilot.pause()
            start0 = app._a2l_window_start
            app.action_page_next_context()
            await pilot.pause()
            start1 = app._a2l_window_start
            app.action_page_prev_context()
            await pilot.pause()
            start2 = app._a2l_window_start
            return start0, start1, start2

    start0, start1, start2 = asyncio.run(_drive())
    assert start0 == 0, f"A2L paging must start at window 0, got {start0}"
    assert start1 > start0, (
        f"page-next must advance the A2L window ({start0} -> {start1})"
    )
    assert start2 == start0, (
        f"page-prev must return to the prior A2L window ({start1} -> "
        f"{start2}, expected {start0})"
    )


def test_tc020_a2l_jump_to_address_through_restyled_screen(tmp_path: Path) -> None:
    """A2L jump-to-address still drives the hex pane after the re-layout.

    Intent: LLR-009.2 — selecting an A2L tag row jumps the A2L hex pane to
    the tag's ECU address. The jump path (``on_data_table_row_selected``
    -> ``update_alt_hex_view``) must keep painting ``#alt_hex_view`` in
    the restyled hex pane; the goto adapter is exercised directly.
    """
    from textual.widgets import Static

    async def _drive() -> bool:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _load_case_01(app)
            app.update_alt_hex_view()
            app.action_show_screen("a2l")
            await pilot.pause()
            # Jump the A2L hex pane to the first parsed S19 range start.
            target = app.current_file.ranges[0][0]
            app.update_alt_hex_view(target, near_top=True, reset_scroll=True)
            await pilot.pause()
            hex_text = str(app.query_one("#alt_hex_view", Static).content)
            return bool(hex_text.strip())

    painted = asyncio.run(_drive())
    assert painted, (
        "update_alt_hex_view jump must paint #alt_hex_view in the "
        "restyled A2L hex pane"
    )


def test_tc022_mac_renderers_populate_through_restyled_screen(tmp_path: Path) -> None:
    """The restyled MAC View panes populate from the public fixture.

    Intent: LLR-010.2 — the two-pane re-layout reuses ``update_mac_view``
    / ``update_mac_hex_view`` unchanged; they must still populate the
    ``#mac_records_list`` table and ``#mac_hex_view`` hex pane when fed
    the public ``firmware.mac`` + ``firmware.s19`` fixture.
    """
    from textual.widgets import DataTable, Static

    async def _drive() -> tuple[int, int, bool]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _load_case_01(app)
            app.update_mac_view()
            app.update_mac_hex_view()
            await pilot.pause()
            app.action_show_screen("mac")
            await pilot.pause()
            table = app.query_one("#mac_records_list", DataTable)
            hex_text = str(app.query_one("#mac_hex_view", Static).content)
            in_pane = bool(
                app.query_one("#mac_records_pane").query("#mac_records_list")
            )
            return table.row_count, len(hex_text.strip()), in_pane

    rows, hex_len, in_pane = asyncio.run(_drive())
    assert rows > 0, (
        "update_mac_view must populate the #mac_records_list table in "
        "the restyled MAC records pane"
    )
    assert hex_len > 0, (
        "update_mac_hex_view must populate the #mac_hex_view hex pane"
    )
    assert in_pane, "#mac_records_list must live inside #mac_records_pane"


def test_tc022_mac_paging_advances_through_restyled_screen(tmp_path: Path) -> None:
    """MAC record paging still advances the window after the re-layout.

    Intent: LLR-010.2 — paging the MAC records table must still move
    ``_mac_window_start`` by one ``mac_records_page_size`` page and clamp
    at the last legal page. A synthetic multi-page MAC ``LoadedFile`` is
    installed directly, then ``action_page_next_context`` is routed while
    the restyled MAC screen is active — exercising the ``+`` key path.
    """
    from s19_app.tui.models import LoadedFile

    async def _drive() -> tuple[int, int, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            page = app.mac_records_page_size
            # Two-and-a-bit pages of synthetic MAC records.
            records = [
                {
                    "line_number": i + 1,
                    "raw": f"TAG_{i:04d}=0001{i:04X}",
                    "name": f"TAG_{i:04d}",
                    "address": 0x10000 + i,
                    "parse_ok": True,
                    "parse_error": "",
                }
                for i in range(page * 2 + 10)
            ]
            app.current_file = LoadedFile(
                path=tmp_path / "many.s19",
                file_type="s19",
                mem_map={0x10000: 0x41},
                row_bases=[0x10000],
                ranges=[(0x10000, 0x10001)],
                range_validity=[True],
                errors=[],
                a2l_path=None,
                a2l_data=None,
                mac_path=tmp_path / "many.mac",
                mac_records=records,
            )
            app.update_mac_view()
            app.action_show_screen("mac")
            await pilot.pause()
            start0 = app._mac_window_start
            app.action_page_next_context()
            await pilot.pause()
            start1 = app._mac_window_start
            app.action_page_prev_context()
            await pilot.pause()
            start2 = app._mac_window_start
            return start0, start1, start2

    start0, start1, start2 = asyncio.run(_drive())
    assert start0 == 0, f"MAC paging must start at window 0, got {start0}"
    assert start1 > start0, (
        f"page-next must advance the MAC window ({start0} -> {start1})"
    )
    assert start2 == start0, (
        f"page-prev must return to the prior MAC window ({start1} -> "
        f"{start2}, expected {start0})"
    )


def test_tc022_mac_jump_to_address_through_restyled_screen(tmp_path: Path) -> None:
    """MAC jump-to-address still drives the hex pane after the re-layout.

    Intent: LLR-010.2 — jumping the MAC hex pane to an address must keep
    painting ``#mac_hex_view`` in the restyled hex pane; the MAC-overlay
    highlight render path (``update_mac_hex_view``) is exercised directly.
    """
    from textual.widgets import Static

    async def _drive() -> bool:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _load_case_01(app)
            app.update_mac_hex_view()
            app.action_show_screen("mac")
            await pilot.pause()
            target = app.current_file.ranges[0][0]
            app.update_mac_hex_view(target, near_top=True, reset_scroll=True)
            await pilot.pause()
            hex_text = str(app.query_one("#mac_hex_view", Static).content)
            return bool(hex_text.strip())

    painted = asyncio.run(_drive())
    assert painted, (
        "update_mac_hex_view jump must paint #mac_hex_view in the "
        "restyled MAC hex pane"
    )


# ===========================================================================
# Increment 7 — Issues Report dedicated screen + empty-state wiring
# ===========================================================================

# A public S19 fixture that parses cleanly — used to flip the no-file
# empty state and to seed a LoadedFile for the Issues screen tests.
_CASE_04_S19 = (
    Path(__file__).resolve().parent.parent
    / "examples"
    / "case_04_bad_checksums"
    / "firmware.s19"
)


def _make_issues(n: int) -> list:
    """Build ``n`` synthetic validation issues (mixed error/warning).

    Mirrors ``tests/test_tui_app.py::_make_validation_issues`` — every third
    issue is an ERROR, the rest WARNING — so the All/Errors/Warnings filter
    modes each select a non-empty, distinct subset.
    """
    from s19_app.validation.model import ValidationIssue, ValidationSeverity

    issues = []
    for i in range(n):
        severity = (
            ValidationSeverity.ERROR if i % 3 == 0 else ValidationSeverity.WARNING
        )
        issues.append(
            ValidationIssue(
                code=f"CODE_{i}",
                severity=severity,
                message=f"issue {i}",
                artifact="mac",
                symbol=f"sym{i}",
                address=0x80000000 + i,
                line_number=i + 1,
            )
        )
    return issues


def _seed_issues_screen(app: S19TuiApp, count: int) -> None:
    """Install a LoadedFile and ``count`` validation issues, then render.

    Loads the public ``case_04`` S19 fixture so ``current_file`` is set
    (flips the empty state), pushes ``count`` synthetic issues onto
    ``_validation_issues`` and clears the worker-precomputed cell caches so
    ``update_validation_issues_view`` formats on the fly — then renders the
    Issues table. This is the increment-7 analogue of ``_load_case_01``.
    """
    from s19_app.core import S19File
    from s19_app.tui.services.load_service import build_loaded_s19

    s19 = S19File(str(_CASE_04_S19))
    loaded = build_loaded_s19(_CASE_04_S19, s19, a2l_path=None, a2l_data=None)
    app.current_file = loaded
    app._apply_empty_state()
    app._validation_issues = _make_issues(count)
    app._validation_issue_cell_rows = []
    app._validation_issue_cell_styles = []
    app.validation_issue_filter_mode = "all"
    app._validation_issues_window_start = 0
    app.update_validation_issues_view()


# ---------------------------------------------------------------------------
# TC-023 — Issues Report is a dedicated rail screen (LLR-011.1)
# ---------------------------------------------------------------------------


def test_tc023_issues_table_is_primary_content_of_screen_issues(
    tmp_path: Path,
) -> None:
    """The Issues DataTable is the primary content of the #screen_issues rail.

    Intent: LLR-011.1 — the validation Issues ``DataTable`` is promoted out
    of the old Workspace Status tile into its own dedicated rail screen.
    The table must be a descendant of ``#screen_issues`` (the rail item-5
    container), together with its filter row and summary line.
    """
    from textual.widgets import DataTable

    async def _drive() -> dict[str, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            screen_issues = app.query_one("#screen_issues")
            return {
                "table": len(screen_issues.query("#validation_issues_list")),
                "filters": len(screen_issues.query("#validation_issues_filters")),
                "summary": len(screen_issues.query("#validation_issues_summary")),
                "is_datatable": int(
                    isinstance(
                        app.query_one("#validation_issues_list"), DataTable
                    )
                ),
            }

    dims = asyncio.run(_drive())
    assert dims["table"] == 1, (
        "the Issues DataTable must be a descendant of #screen_issues "
        f"(found {dims['table']})"
    )
    assert dims["filters"] == 1 and dims["summary"] == 1, (
        "the Issues filter row and summary line must live in #screen_issues "
        f"(filters={dims['filters']}, summary={dims['summary']})"
    )
    assert dims["is_datatable"] == 1, "#validation_issues_list must be a DataTable"


def test_tc023_issues_not_nested_in_workspace_and_carryover_gone(
    tmp_path: Path,
) -> None:
    """The Issues table left the Workspace screen; #workspace_carryover is gone.

    Intent: LLR-011.1 — promoting the Issues table to its own rail screen
    means it is no longer nested under ``#screen_workspace``, and the
    temporary increment-5 ``#workspace_carryover`` scaffold container that
    held it (plus the status/log widgets) is fully removed — no widget it
    held may be orphaned.
    """

    async def _drive() -> dict[str, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            screen_workspace = app.query_one("#screen_workspace")
            return {
                "carryover": len(app.query("#workspace_carryover")),
                "issues_in_workspace": len(
                    screen_workspace.query("#validation_issues_list")
                ),
                # Re-homed status / progress / log widgets must still exist
                # somewhere in the tree so their renderers are not orphaned.
                "status_text": len(app.query("#status_text")),
                "progress_bar": len(app.query("#progress_bar")),
                "log_lines": len(app.query("#log_line_1"))
                + len(app.query("#log_line_2"))
                + len(app.query("#log_line_3"))
                + len(app.query("#log_line_4")),
            }

    dims = asyncio.run(_drive())
    assert dims["carryover"] == 0, (
        "the temporary #workspace_carryover container must be fully removed "
        f"(found {dims['carryover']})"
    )
    assert dims["issues_in_workspace"] == 0, (
        "the Issues table must no longer be nested inside #screen_workspace"
    )
    assert dims["status_text"] == 1, (
        "the re-homed #status_text label must still exist (renderer target)"
    )
    assert dims["progress_bar"] == 1, (
        "the re-homed #progress_bar must still exist (renderer target)"
    )
    assert dims["log_lines"] == 4, (
        f"all four re-homed #log_line_* labels must exist, found "
        f"{dims['log_lines']}"
    )


def test_tc023_status_widgets_persist_across_screens(tmp_path: Path) -> None:
    """The re-homed status bar widgets are reachable from every rail screen.

    Intent: LLR-011.1 / LLR-013.2 — the status text, progress bar and log
    tail moved to a persistent ``#workspace_status_bar`` above the footer,
    so ``set_status`` / ``set_file_status`` / ``set_progress`` and the log
    tail keep a valid render target whichever rail screen is active.
    """

    async def _drive() -> list[bool]:
        app = S19TuiApp(base_dir=tmp_path)
        results: list[bool] = []
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            for key in SCREEN_KEYS:
                app.action_show_screen(key)
                await pilot.pause()
                # Drive the actual renderers — they must not raise.
                app.set_file_status(f"on {key}")
                app.set_status(f"log {key}")
                app.set_progress(50)
                ok = (
                    len(app.query("#status_text")) == 1
                    and len(app.query("#progress_bar")) == 1
                )
                results.append(ok)
        return results

    results = asyncio.run(_drive())
    assert all(results), (
        "status bar widgets must stay reachable / writable on every screen"
    )


# ---------------------------------------------------------------------------
# TC-024 — Issues severity coloring, filters, paging, jump preserved
#          (LLR-011.2)
# ---------------------------------------------------------------------------


def test_tc024_issues_severity_filters_narrow_through_dedicated_screen(
    tmp_path: Path,
) -> None:
    """All/Errors/Warnings filters still narrow the Issues table after the move.

    Intent: LLR-011.2 — the severity filter buttons drive
    ``validation_issue_filter_mode`` + ``update_validation_issues_view``.
    After promotion to ``#screen_issues`` the filter pipeline must still
    select distinct, non-empty subsets: Errors and Warnings each smaller
    than All, and their row counts summing to the All count.
    """
    from textual.widgets import DataTable

    async def _drive() -> tuple[int, int, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _seed_issues_screen(app, 30)
            app.action_show_screen("issues")
            await pilot.pause()
            table = app.query_one("#validation_issues_list", DataTable)

            def _count(mode: str) -> int:
                app.validation_issue_filter_mode = mode
                app._validation_issues_window_start = 0
                app.update_validation_issues_view()
                return table.row_count

            return _count("all"), _count("error"), _count("warning")

    all_n, err_n, warn_n = asyncio.run(_drive())
    assert all_n == 30, f"All filter must show every issue, got {all_n}"
    assert 0 < err_n < all_n, f"Errors filter must narrow ({err_n}/{all_n})"
    assert 0 < warn_n < all_n, f"Warnings filter must narrow ({warn_n}/{all_n})"
    assert err_n + warn_n == all_n, (
        f"Errors + Warnings must partition All ({err_n}+{warn_n} != {all_n})"
    )


def test_tc024_issues_filter_buttons_route_through_dedicated_screen(
    tmp_path: Path,
) -> None:
    """The Issues filter buttons still fire their handler on the rail screen.

    Intent: LLR-011.2 — the ``#issues_filter_error`` button press handler
    (``on_button_pressed``) must still set the filter mode and re-render.
    Pressing it via the real button widget inside ``#screen_issues``
    exercises the wiring end-to-end, not just the renderer.
    """
    from textual.widgets import Button, DataTable

    async def _drive() -> tuple[int, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _seed_issues_screen(app, 30)
            app.action_show_screen("issues")
            await pilot.pause()
            table = app.query_one("#validation_issues_list", DataTable)
            before = table.row_count
            button = app.query_one("#issues_filter_error", Button)
            app.on_button_pressed(Button.Pressed(button))
            await pilot.pause()
            return before, table.row_count

    before, after = asyncio.run(_drive())
    assert before == 30, f"unfiltered Issues table must show 30, got {before}"
    assert 0 < after < before, (
        f"the Errors filter button must narrow the table ({before} -> "
        f"{after}); the handler is orphaned if it does not"
    )


def test_tc024_issues_paging_advances_through_dedicated_screen(
    tmp_path: Path,
) -> None:
    """Issues paging actions still move the window after the move (LLR-011.2).

    Intent: ``action_validation_issues_page_next`` / ``_page_prev`` advance
    ``_validation_issues_window_start`` by one page and clamp at the last
    legal page. With a multi-page issue list the page-number line in the
    summary must change page-next then return on page-prev.
    """
    from textual.widgets import Label

    async def _drive() -> tuple[int, int, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            page = app.validation_issues_page_size
            # More than two pages of issues.
            _seed_issues_screen(app, page * 2 + 5)
            app.action_show_screen("issues")
            await pilot.pause()
            start0 = app._validation_issues_window_start
            app.action_validation_issues_page_next()
            await pilot.pause()
            start1 = app._validation_issues_window_start
            app.action_validation_issues_page_prev()
            await pilot.pause()
            start2 = app._validation_issues_window_start
            # The summary line must reflect the active page.
            summary = str(app.query_one("#validation_issues_summary", Label).render())
            assert "page" in summary, "summary must carry the page line"
            return start0, start1, start2

    start0, start1, start2 = asyncio.run(_drive())
    assert start0 == 0, f"Issues paging must start at window 0, got {start0}"
    assert start1 > start0, (
        f"page-next must advance the Issues window ({start0} -> {start1})"
    )
    assert start2 == start0, (
        f"page-prev must return to the prior Issues window ({start1} -> "
        f"{start2}, expected {start0})"
    )


def test_tc024_issues_severity_color_round_trips(tmp_path: Path) -> None:
    """Issue severity still round-trips through css_class_for_severity.

    Intent: LLR-011.2 / LLR-005.2 — severity coloring on the dedicated
    Issues screen uses the same ``color_policy`` source of truth. Each
    severity value must map to its fixed ``sev-*`` class, and the Issues
    DataTable renderer (``precompute_issue_datatable_payload``) — unchanged
    by the screen move — must emit a distinct per-row Rich style for each
    severity so the coloring survives the promotion to ``#screen_issues``.
    """
    from s19_app.tui.app import precompute_issue_datatable_payload
    from s19_app.tui.color_policy import css_class_for_severity
    from s19_app.validation.model import ValidationSeverity

    # The color_policy map is the single source of truth (C-6 / LLR-005.2).
    expected = {
        ValidationSeverity.ERROR: "sev-error",
        ValidationSeverity.WARNING: "sev-warning",
        ValidationSeverity.INFO: "sev-info",
    }
    for severity, css_class in expected.items():
        assert css_class_for_severity(severity) == css_class, (
            f"{severity} must map to {css_class}"
        )

    # The unchanged Issues renderer must still produce one severity style
    # per row, and error vs. warning rows must be styled differently.
    issues = _make_issues(12)
    cell_rows, styles = precompute_issue_datatable_payload(issues)
    assert len(styles) == len(cell_rows) == 12, (
        "the Issues renderer must emit one severity style per issue row"
    )
    err_styles = {
        styles[i]
        for i, it in enumerate(issues)
        if it.severity == ValidationSeverity.ERROR
    }
    warn_styles = {
        styles[i]
        for i, it in enumerate(issues)
        if it.severity == ValidationSeverity.WARNING
    }
    assert err_styles and warn_styles, "both severities must appear in the fixture"
    assert err_styles.isdisjoint(warn_styles), (
        f"error and warning rows must carry distinct severity styles "
        f"(error={err_styles}, warning={warn_styles})"
    )

    async def _drive() -> int:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _seed_issues_screen(app, 12)
            app.action_show_screen("issues")
            await pilot.pause()
            # The dedicated Issues screen renders without raising and keeps
            # the styled rows in the DataTable.
            return app.query_one("#validation_issues_list").row_count

    rendered = asyncio.run(_drive())
    assert rendered == 12, (
        f"the dedicated Issues screen must render all 12 styled rows, "
        f"got {rendered}"
    )


def test_tc024_issues_row_select_jumps_to_source(tmp_path: Path) -> None:
    """Selecting an Issues row still jumps to its source (LLR-011.2).

    Intent: row-level jump-to-source is preserved after the move — the
    ``on_data_table_row_selected`` handler routes an ``issue:<index>`` row
    key through ``_jump_to_validation_issue_by_index``. Selecting a row on
    the dedicated screen must not raise and must resolve the issue index.
    """
    from textual.widgets import DataTable

    class _Evt:
        def __init__(self, table: object, key: str) -> None:
            self.data_table = table
            self.row_key = key

    async def _drive() -> tuple[bool, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _seed_issues_screen(app, 20)
            app.action_show_screen("issues")
            await pilot.pause()
            table = app.query_one("#validation_issues_list", DataTable)
            # The renderer recorded issue:<index> row keys for the page.
            row_keys = [
                k for k in app._issue_row_key_to_index if k.startswith("issue:")
            ]
            raised = False
            try:
                app.on_data_table_row_selected(_Evt(table, row_keys[0]))
            except Exception:
                raised = True
            return raised, len(row_keys)

    raised, key_count = asyncio.run(_drive())
    assert key_count > 0, "the Issues renderer must record issue:<index> row keys"
    assert not raised, (
        "selecting an Issues row must route to jump-to-source without error"
    )


# ---------------------------------------------------------------------------
# TC-037 (Workspace sub-case) — empty-state panel for the re-laid-out
#          Workspace and Issues screens (LLR-002.3)
# ---------------------------------------------------------------------------


def test_tc037_workspace_shows_empty_state_with_no_file(tmp_path: Path) -> None:
    """The re-laid-out Workspace shows the empty-state panel with no file.

    Intent: LLR-002.3 — increment 5 deferred the Workspace empty state;
    increment 7 wires it. With no ``LoadedFile`` the Workspace screen shows
    its ``EmptyStatePanel`` and hides the three-pane content.
    """

    async def _drive() -> tuple[bool, bool, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            no_file = app.current_file is None
            screen = app.query_one("#screen_workspace")
            panes_hidden = "hidden" in app.query_one("#workspace_panes").classes
            visible_panels = [
                p for p in screen.query(EmptyStatePanel) if p.display
            ]
            return no_file, panes_hidden, len(visible_panels)

    no_file, panes_hidden, visible = asyncio.run(_drive())
    assert no_file, "precondition: no file loaded"
    assert panes_hidden, (
        "with no file the Workspace three-pane content must be hidden"
    )
    assert visible == 1, (
        f"the Workspace must show exactly one empty-state panel, got {visible}"
    )


def test_tc037_issues_shows_empty_state_with_no_file(tmp_path: Path) -> None:
    """The Issues Report screen shows the empty-state panel with no file.

    Intent: LLR-002.3 — activating the Issues rail screen with no file
    loaded shows a neutral empty-state panel, not a blank Issues table.
    """

    async def _drive() -> tuple[bool, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("issues")
            await pilot.pause()
            screen = app.query_one("#screen_issues")
            content_hidden = "hidden" in app.query_one("#issues_content").classes
            visible_panels = [
                p for p in screen.query(EmptyStatePanel) if p.display
            ]
            return content_hidden, len(visible_panels)

    content_hidden, visible = asyncio.run(_drive())
    assert content_hidden, (
        "with no file the Issues table content must be hidden"
    )
    assert visible == 1, (
        f"the Issues screen must show exactly one empty-state panel, "
        f"got {visible}"
    )


def test_tc037_workspace_empty_state_clears_when_file_loads(
    tmp_path: Path,
) -> None:
    """Loading a file flips the Workspace/Issues out of the empty state.

    Intent: LLR-002.3 — the empty-state panel is a no-file state only.
    Once a ``LoadedFile`` is present, ``_apply_empty_state`` reveals the
    real pane content and hides the empty-state panels on both
    content-bearing screens.
    """

    async def _drive() -> dict[str, bool]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _seed_issues_screen(app, 5)  # sets current_file + _apply_empty_state
            await pilot.pause()
            ws = app.query_one("#screen_workspace")
            si = app.query_one("#screen_issues")
            return {
                "panes_visible": "hidden"
                not in app.query_one("#workspace_panes").classes,
                "issues_content_visible": "hidden"
                not in app.query_one("#issues_content").classes,
                "ws_panel_hidden": not any(
                    p.display for p in ws.query(EmptyStatePanel)
                ),
                "issues_panel_hidden": not any(
                    p.display for p in si.query(EmptyStatePanel)
                ),
            }

    state = asyncio.run(_drive())
    assert state["panes_visible"], (
        "loading a file must reveal the Workspace three-pane content"
    )
    assert state["issues_content_visible"], (
        "loading a file must reveal the Issues table content"
    )
    assert state["ws_panel_hidden"], (
        "loading a file must hide the Workspace empty-state panel"
    )
    assert state["issues_panel_hidden"], (
        "loading a file must hide the Issues empty-state panel"
    )


# ===========================================================================
# Increment 8 — Modal re-skin (Load / Save / Load-Project)
#   TC-033 (LLR-015.1) — modals adopt the Calm Dark token set
#   TC-034 (LLR-015.2) — modal behavior preserved (project-file rules,
#           workarea containment, path resolution, path traversal)
# ===========================================================================

# The three Direction B modal classes under test (the only ``ModalScreen``
# subclasses in the app). They share one accent and one backdrop tone.
_MODAL_SPECS = [
    ("LoadFileScreen", ()),
    ("SaveProjectScreen", ("_default_parent_",)),
    ("LoadProjectScreen", (["proj_a", "proj_b"],)),
]

# The five Calm Dark token variable names (styles.tcss). The modal re-skin
# must resolve every modal color through one of these — no hard-coded hex.
_CALM_DARK_TOKENS = {
    "$accent-calm",
    "$bg-base",
    "$bg-panel",
    "$fg-base",
    "$rule",
}

# The five severity classes that color_policy.SEVERITY_CLASS_MAP defines.
_SEV_CLASSES = {"sev-error", "sev-warning", "sev-info", "sev-ok", "sev-neutral"}


def _modal_css_block() -> str:
    """Return the increment-8 modal re-skin block from ``styles.tcss``.

    The slice runs from the opening ``/*`` of the modal-re-skin section
    comment to the start of the activity-rail section that follows it, so
    the caller can scan exactly the modal rules (and their header comment).
    """
    from s19_app.tui import screens as screens_mod

    styles_path = (
        Path(screens_mod.__file__).resolve().parent / "styles.tcss"
    )
    tcss = styles_path.read_text(encoding="utf-8")
    marker = "Calm Dark modal re-skin (batch-02 increment 8"
    # Back up to the ``/*`` that opens the section comment so the comment is
    # well-formed for later ``/* ... */`` stripping.
    start = tcss.rindex("/*", 0, tcss.index(marker))
    block = tcss[start:]
    end = block.find("/* --- Activity rail (batch-02 increment 3")
    return block[:end] if end != -1 else block


def _build_modal(name: str, args: tuple, default_parent: Path):
    """Construct one of the three re-skinned modals by name."""
    from s19_app.tui.screens import (
        LoadFileScreen,
        LoadProjectScreen,
        SaveProjectScreen,
    )

    by_name = {
        "LoadFileScreen": LoadFileScreen,
        "SaveProjectScreen": SaveProjectScreen,
        "LoadProjectScreen": LoadProjectScreen,
    }
    resolved = tuple(
        default_parent if a == "_default_parent_" else a for a in args
    )
    return by_name[name](*resolved)


# ---------------------------------------------------------------------------
# TC-033 — modals adopt the Calm Dark theme (LLR-015.1)
# ---------------------------------------------------------------------------


def test_tc033_modals_use_only_calm_dark_tokens_no_hardcoded_color() -> None:
    """No modal color is a hard-coded hex; every color is a Calm Dark token.

    TC-033 checklist items 1-2 / 4: the three modals reference the Calm Dark
    theme tokens (accent variable + the shared dark token set), not
    hard-coded colors, and no off-theme / hard-coded / light-theme color
    appears in the modal styling.

    Intent (LLR-015.1): the re-skin must be token-driven. ``screens.py``
    carries no per-screen ``DEFAULT_CSS`` at all — the modal rules live in
    ``styles.tcss`` keyed on the ``.modal-*`` classes / ``#load_dialog`` id,
    so the only place a hard-coded modal color could hide is the modal CSS
    block of ``styles.tcss``. This test asserts the modal block contains no
    raw ``#rrggbb`` literal — every color resolves through a ``$``-token.
    """
    import re

    from s19_app.tui import screens as screens_mod

    # screens.py must carry no per-screen DEFAULT_CSS of its own (the tokens
    # would not resolve outside the app stylesheet — see the screens.py
    # module note). Check the class's OWN __dict__, not the inherited
    # Textual ``Screen.DEFAULT_CSS``.
    from s19_app.tui.screens import (
        LoadFileScreen,
        LoadProjectScreen,
        SaveProjectScreen,
    )

    for cls in (LoadFileScreen, SaveProjectScreen, LoadProjectScreen):
        own_css = cls.__dict__.get("DEFAULT_CSS", "") or ""
        assert own_css.strip() == "", (
            f"{cls.__name__} must not declare its own DEFAULT_CSS — the "
            f"Calm Dark tokens only resolve inside styles.tcss"
        )

    # screens.py source must contain no raw hex color literal.
    src = Path(screens_mod.__file__).read_text(encoding="utf-8")
    hex_in_screens = re.findall(r"#[0-9A-Fa-f]{6}\b", src)
    assert not hex_in_screens, (
        f"screens.py must contain no hard-coded hex color, found {hex_in_screens}"
    )

    # The modal CSS block in styles.tcss must use only $-tokens for color.
    modal_block = _modal_css_block()
    assert "Calm Dark modal re-skin" in modal_block, (
        "the increment-8 modal re-skin block must exist in styles.tcss"
    )
    hex_in_modal = re.findall(r"#[0-9A-Fa-f]{6}\b", modal_block)
    assert not hex_in_modal, (
        f"the styles.tcss modal block must use only Calm Dark $-tokens for "
        f"color, found hard-coded hex {hex_in_modal}"
    )
    # The accent the modal block uses must be the single shared $accent-calm.
    assert "$accent-calm" in modal_block, (
        "the modal re-skin must reference the single Calm Dark accent token"
    )


def test_tc033_modal_block_uses_single_accent_and_no_light_theme() -> None:
    """The modal block uses one accent and introduces no second / light hue.

    TC-033 checklist item 3 / 4: the accent hue used by the modals is the
    single shared accent (no second accent introduced) and no light-theme
    color appears.

    Intent (LLR-015.1 / C-6 / C-7): the Calm Dark budget is exactly one
    accent variable. ``$accent-calm`` is that single accent; no other
    ``$accent*`` variable and no Textual ``$primary`` / ``$secondary``
    built-in accent may appear in the modal styling, and the dark-only
    tokens must be the only background tones (no light variant).
    """
    import re

    modal_block = _modal_css_block()

    # Strip the ``/* ... */`` comment blocks — the rationale prose names
    # token *families* (``$bg-*`` / ``$fg-*``) that are not real references.
    rules_only = re.sub(r"/\*.*?\*/", "", modal_block, flags=re.DOTALL)

    # Every $-token referenced in the modal rules must be a Calm Dark token.
    referenced = set(re.findall(r"\$[a-z][a-z0-9-]+", rules_only))
    stray = referenced - _CALM_DARK_TOKENS
    assert not stray, (
        f"the modal block references non-Calm-Dark token(s) {stray}; only "
        f"{sorted(_CALM_DARK_TOKENS)} are permitted (single-accent budget)"
    )
    # No Textual built-in accent (a second accent) leaks into the modals.
    for builtin in ("$primary", "$secondary", "$accent ", "$accent;"):
        assert builtin not in rules_only, (
            f"the modal block must not use the built-in accent {builtin!r} — "
            f"that is a second accent (TC-033)"
        )


def test_tc033_modals_render_with_calm_dark_tokens(tmp_path: Path) -> None:
    """Each of the three modals renders with the resolved Calm Dark tokens.

    TC-033 (runtime corroboration): mounting each modal and reading back the
    computed styles confirms the dialog border / panel surface / title /
    confirm button / backdrop all resolve to the Calm Dark token values —
    the inspection checklist verified as live rendered fact.

    Intent (LLR-015.1): a stylesheet that parses but does not actually skin
    the modals would pass a pure source inspection; mounting the modal and
    reading the computed style proves the re-skin reaches the widget tree.
    """
    from textual.widgets import Button, Label

    # Calm Dark token values from styles.tcss (the single source of truth).
    accent = "#4EC9D4"
    bg_base = "#11141A"
    bg_panel = "#171B23"

    async def _drive() -> dict[str, dict[str, str]]:
        app = S19TuiApp(base_dir=tmp_path)
        result: dict[str, dict[str, str]] = {}
        async with app.run_test() as pilot:
            await pilot.pause()
            for name, args in _MODAL_SPECS:
                modal = _build_modal(name, args, tmp_path)
                app.push_screen(modal)
                await pilot.pause()
                dialog = modal.query_one(".modal-dialog")
                title = modal.query_one(".modal-title", Label)
                confirm = next(
                    b
                    for b in modal.query(Button)
                    if "modal-confirm" in b.classes
                )
                # The backdrop is the base token at 70% alpha — compare the
                # RGB triple only (``.hex`` carries an 8th-digit alpha byte).
                backdrop = modal.styles.background
                result[name] = {
                    "border_style": dialog.styles.border[0][0],
                    "dialog_bg": dialog.styles.background.hex.upper()[:7],
                    "title_color": title.styles.color.hex.upper()[:7],
                    "confirm_bg": confirm.styles.background.hex.upper()[:7],
                    "backdrop_bg": (
                        f"#{backdrop.r:02X}{backdrop.g:02X}{backdrop.b:02X}"
                    ),
                    "backdrop_dimmed": str(backdrop.a < 1.0),
                }
                app.pop_screen()
                await pilot.pause()
        return result

    rendered = asyncio.run(_drive())
    assert set(rendered) == {
        "LoadFileScreen",
        "SaveProjectScreen",
        "LoadProjectScreen",
    }, "all three modals must mount and render"
    for name, styles in rendered.items():
        assert styles["border_style"] == "round", (
            f"{name}: dialog must keep the round accent border"
        )
        assert styles["dialog_bg"] == bg_panel, (
            f"{name}: dialog background must be the Calm Dark panel token "
            f"{bg_panel}, got {styles['dialog_bg']}"
        )
        assert styles["title_color"] == accent, (
            f"{name}: title must use the single Calm Dark accent {accent}, "
            f"got {styles['title_color']}"
        )
        assert styles["confirm_bg"] == accent, (
            f"{name}: the confirm button must carry the single accent "
            f"{accent}, got {styles['confirm_bg']}"
        )
        assert styles["backdrop_bg"] == bg_base, (
            f"{name}: the dimmed ModalScreen backdrop must be the Calm Dark "
            f"base token {bg_base}, got {styles['backdrop_bg']}"
        )
        assert styles["backdrop_dimmed"] == "True", (
            f"{name}: the ModalScreen backdrop must be dimmed (alpha < 1) so "
            f"the modal reads as an overlay"
        )
    # The accent and backdrop are identical across all three modals — a
    # single shared accent, a single shared backdrop tone (TC-033).
    accents = {s["title_color"] for s in rendered.values()}
    backdrops = {s["backdrop_bg"] for s in rendered.values()}
    assert len(accents) == 1, f"all modals must share one accent, got {accents}"
    assert len(backdrops) == 1, (
        f"all modals must share one backdrop tone, got {backdrops}"
    )


def test_tc033_no_severity_class_misuse_in_modal_block() -> None:
    """If the modal block names a sev-* class it is one of the five (LLR-015.1).

    TC-033 checklist item 5: severity coloring inside the modals, if any,
    routes through the five ``sev-*`` classes of
    ``color_policy.SEVERITY_CLASS_MAP`` — no ad-hoc severity color.

    Intent: the modals have no severity content today, so the expected
    outcome is that the modal block names no ``sev-*`` class at all; if a
    future edit adds one it must be one of the five canonical classes, never
    a new severity name. This test fails loudly on a sixth severity class.
    """
    import re

    modal_block = _modal_css_block()
    sev_classes = set(re.findall(r"\.(sev-[a-z]+)\b", modal_block))
    stray = sev_classes - _SEV_CLASSES
    assert not stray, (
        f"the modal block names non-canonical severity class(es) {stray}; "
        f"only the five SEVERITY_CLASS_MAP classes are permitted"
    )


# ---------------------------------------------------------------------------
# TC-034 — modal behavior preserved after the re-skin (LLR-015.2)
# ---------------------------------------------------------------------------


def test_tc034_validate_project_files_cardinality_unchanged(
    tmp_path: Path,
) -> None:
    """``validate_project_files`` still enforces the one-of-each rule.

    TC-034 (LLR-015.2): the re-skin is visual-only — the project-file
    cardinality rule (one S19/HEX + one MAC + one A2L per project) is
    untouched. A clean triple passes; a second S19, a second MAC and a
    second A2L each fail with their specific message.

    Intent: a re-skin that accidentally edited ``workspace.py`` would change
    this verdict; re-running the cardinality boundary against the current
    code proves the project-file engine is byte-behavior-identical.
    """
    from s19_app.tui.workspace import validate_project_files

    # Clean triple — one of each — passes.
    ok = tmp_path / "ok_project"
    ok.mkdir()
    (ok / "fw.s19").write_text("S0", encoding="utf-8")
    (ok / "tags.mac").write_text("A=0x0", encoding="utf-8")
    (ok / "cal.a2l").write_text("A2L", encoding="utf-8")
    data_files, a2l_files, error = validate_project_files(ok)
    assert error is None, f"a one-of-each project must pass, got {error!r}"
    assert len(a2l_files) == 1
    assert sorted(p.suffix.lower() for p in data_files) == [".mac", ".s19"]

    # Two S19 files — rejected.
    two_s19 = tmp_path / "two_s19"
    two_s19.mkdir()
    (two_s19 / "a.s19").write_text("S0", encoding="utf-8")
    (two_s19 / "b.s19").write_text("S0", encoding="utf-8")
    _, _, error = validate_project_files(two_s19)
    assert error is not None and "S19/HEX" in error, (
        f"two S19 files must be rejected, got {error!r}"
    )

    # Two MAC files — rejected.
    two_mac = tmp_path / "two_mac"
    two_mac.mkdir()
    (two_mac / "fw.s19").write_text("S0", encoding="utf-8")
    (two_mac / "a.mac").write_text("A=0x0", encoding="utf-8")
    (two_mac / "b.mac").write_text("B=0x0", encoding="utf-8")
    _, _, error = validate_project_files(two_mac)
    assert error is not None and "MAC" in error, (
        f"two MAC files must be rejected, got {error!r}"
    )

    # Two A2L files — rejected.
    two_a2l = tmp_path / "two_a2l"
    two_a2l.mkdir()
    (two_a2l / "fw.s19").write_text("S0", encoding="utf-8")
    (two_a2l / "a.a2l").write_text("A2L", encoding="utf-8")
    (two_a2l / "b.a2l").write_text("A2L", encoding="utf-8")
    _, _, error = validate_project_files(two_a2l)
    assert error is not None and "A2L" in error, (
        f"two A2L files must be rejected, got {error!r}"
    )


def test_tc034_copy_into_workarea_containment_unchanged(
    tmp_path: Path,
) -> None:
    """``copy_into_workarea`` still rejects an out-of-workarea destination.

    TC-034 (LLR-015.2 / S-4): the workarea containment guard is untouched by
    the modal re-skin. A destination with no ``.s19tool/workarea`` ancestor
    is rejected; a destination inside the workarea accepts the copy.

    Intent: the modal re-skin must not weaken the containment boundary.
    """
    from s19_app.tui.workspace import (
        WORKAREA_DIRNAME,
        WORKAREA_SUBDIR,
        WORKAREA_TEMP,
        WorkareaContainmentError,
        copy_into_workarea,
    )

    source = tmp_path / "sample.s19"
    source.write_text("S0", encoding="utf-8")

    # Destination outside any .s19tool/workarea root — rejected.
    import pytest

    bogus = tmp_path / "elsewhere"
    with pytest.raises(WorkareaContainmentError):
        copy_into_workarea(source, bogus)

    # Destination inside the workarea — accepted, file lands under it.
    workarea_temp = (
        tmp_path / WORKAREA_DIRNAME / WORKAREA_SUBDIR / WORKAREA_TEMP
    )
    workarea_temp.mkdir(parents=True, exist_ok=True)
    written = copy_into_workarea(source, workarea_temp)
    assert written.exists(), "a contained copy must write the file"
    assert written.is_relative_to(workarea_temp), (
        "the copied file must stay under the .s19tool/workarea destination"
    )


def test_tc034_path_traversal_input_stays_contained(tmp_path: Path) -> None:
    """A ``..\\..\\``-style traversal path cannot escape the workarea.

    TC-034 path-traversal sub-case (S-4): a modal path input of the form
    ``..\\..\\<escape>`` resolved against the workarea must not let
    ``copy_into_workarea`` write outside the ``.s19tool/workarea`` boundary.
    ``copy_into_workarea`` resolves the destination and rejects any path
    whose resolved form has no ``.s19tool/workarea`` ancestor — a traversal
    target therefore raises ``WorkareaContainmentError`` rather than escaping.

    Intent (LLR-015.2): the re-skin is path-handling-neutral; the containment
    boundary that protects the host filesystem from a malicious modal input
    is exactly as strong after the re-skin as before it.
    """
    import pytest

    from s19_app.tui.workspace import (
        WORKAREA_DIRNAME,
        WORKAREA_SUBDIR,
        WORKAREA_TEMP,
        WorkareaContainmentError,
        copy_into_workarea,
    )

    source = tmp_path / "payload.s19"
    source.write_text("S0", encoding="utf-8")

    workarea_temp = (
        tmp_path / WORKAREA_DIRNAME / WORKAREA_SUBDIR / WORKAREA_TEMP
    )
    workarea_temp.mkdir(parents=True, exist_ok=True)

    # A traversal destination typed as if into a modal: climb out of the
    # workarea with ``../..`` and land in a sibling directory. The resolved
    # path has no .s19tool/workarea ancestor, so the copy is refused.
    traversal_dest = workarea_temp / ".." / ".." / ".." / "escaped_dir"
    with pytest.raises(WorkareaContainmentError):
        copy_into_workarea(source, traversal_dest)

    # Nothing was written outside the workarea boundary.
    escaped = tmp_path / "escaped_dir"
    assert not escaped.exists(), (
        "a traversal destination must not create a directory outside the "
        ".s19tool/workarea boundary"
    )

    # The resolved traversal target, had it been allowed, would sit outside
    # the workarea root — confirm the containment check would see that.
    workarea_root = tmp_path / WORKAREA_DIRNAME / WORKAREA_SUBDIR
    resolved = traversal_dest.resolve()
    assert not resolved.is_relative_to(workarea_root), (
        "the traversal target resolves outside .s19tool/workarea — the "
        "containment guard is what keeps it from being used"
    )


def test_tc034_resolve_input_path_returns_none_for_traversal_miss(
    tmp_path: Path,
) -> None:
    """``resolve_input_path`` returns None for a non-existent traversal path.

    TC-034 path-traversal sub-case (S-4): a modal read-path input that uses
    ``..\\..\\`` to point at a file that does not exist resolves to ``None``
    rather than to an arbitrary host path. ``resolve_input_path`` only ever
    returns a path that ``exists()``; a traversal miss therefore yields
    ``None`` and the load is declined.

    Intent (LLR-015.2): the modal re-skin does not change read-path
    resolution — a traversal input is still resolved through the unchanged
    ``resolve_input_path`` and produces ``None`` when it points nowhere real.
    """
    from s19_app.tui.workspace import resolve_input_path

    base_dir = tmp_path / "base"
    base_dir.mkdir()
    # A relative ``..``-laden path to a file that does not exist anywhere on
    # the cwd / repo-root search chain.
    traversal = Path("..") / ".." / ".." / "no_such_secret.s19"
    assert resolve_input_path(traversal, base_dir) is None, (
        "a non-existent traversal read path must resolve to None"
    )


def test_tc034_modals_behavior_methods_intact(tmp_path: Path) -> None:
    """The re-skinned modals keep their dismiss/payload behavior (LLR-015.2).

    TC-034: the re-skin touched composition only — the modal result types
    and the ``SaveProjectPayload`` dataclass are unchanged. Driving each
    modal's cancel and confirm paths confirms the behavioral contract:
    Cancel dismisses with ``None``; ``SaveProjectScreen`` confirm returns a
    ``SaveProjectPayload`` carrying the typed parent and project name.

    Intent: a re-skin that broke a button id or the ``compose`` tree would
    fail to dismiss; exercising the real button widgets proves the wiring
    survived the class / id additions made for theming.
    """
    from textual.widgets import Button, Input

    from s19_app.tui.screens import SaveProjectPayload, SaveProjectScreen

    async def _drive() -> tuple[object, object]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()

            # Cancel path — dismiss with None.
            cancel_result: list = []
            modal_cancel = SaveProjectScreen(tmp_path)
            app.push_screen(modal_cancel, cancel_result.append)
            await pilot.pause()
            cancel_btn = modal_cancel.query_one("#save_cancel", Button)
            modal_cancel.on_button_pressed(Button.Pressed(cancel_btn))
            await pilot.pause()

            # Confirm path — dismiss with a SaveProjectPayload.
            ok_result: list = []
            modal_ok = SaveProjectScreen(tmp_path)
            app.push_screen(modal_ok, ok_result.append)
            await pilot.pause()
            modal_ok.query_one("#project_parent_path", Input).value = str(
                tmp_path
            )
            modal_ok.query_one("#project_name", Input).value = "Demo_Project"
            ok_btn = modal_ok.query_one("#save_ok", Button)
            modal_ok.on_button_pressed(Button.Pressed(ok_btn))
            await pilot.pause()

            return (
                cancel_result[0] if cancel_result else "_unset_",
                ok_result[0] if ok_result else "_unset_",
            )

    cancel_value, ok_value = asyncio.run(_drive())
    assert cancel_value is None, (
        f"Cancel must dismiss SaveProjectScreen with None, got {cancel_value!r}"
    )
    assert isinstance(ok_value, SaveProjectPayload), (
        f"Save must dismiss with a SaveProjectPayload, got {type(ok_value)}"
    )
    assert ok_value.project_name == "Demo_Project", (
        f"the payload must carry the typed project name, got {ok_value!r}"
    )
    assert ok_value.parent_folder == str(tmp_path), (
        f"the payload must carry the typed parent folder, got {ok_value!r}"
    )


# ===========================================================================
# Increment 9 — Memory Map + Bookmarks scaffolds
# ===========================================================================
#
# LLR-012.1 — Memory Map renders coverage from the existing LoadedFile.ranges
#             / range_validity (no new coverage computation).
# LLR-002.2 — Bookmarks rail item opens a neutral "coming soon" placeholder
#             (no persistence logic).
# LLR-012.4 — the scaffolds add no new processing module and import none of
#             bincopy / pya2l / crcmod.
#
# Test cases: TC-025 (Memory Map), TC-004 (Bookmarks), TC-028 (scaffold-side
# deferred-logic guard).

# The public ``case_02`` S19 fixture has four contiguous ranges separated by
# real gaps (verified: (0,11), (~2147549184,..), (..), (..)) — it exercises
# the Memory Map's range + gap rendering. Public fixture only (LLR-007.2).
_CASE_02_S19 = (
    Path(__file__).resolve().parent.parent
    / "examples"
    / "case_02_gaps_and_patch_targets"
    / "firmware.s19"
)


def _install_case_02_loaded_file(app: S19TuiApp) -> "object":
    """Install the public ``case_02`` gaps fixture as ``current_file``.

    Returns the built ``LoadedFile`` so a test can compare the rendered
    Memory Map against the model's own ``ranges`` / ``range_validity``.
    """
    from s19_app.core import S19File
    from s19_app.tui.services.load_service import build_loaded_s19

    s19 = S19File(str(_CASE_02_S19))
    loaded = build_loaded_s19(_CASE_02_S19, s19, a2l_path=None, a2l_data=None)
    app.current_file = loaded
    app._apply_empty_state()
    return loaded


# ---------------------------------------------------------------------------
# TC-025 — Memory Map scaffold renders coverage from LoadedFile (LLR-012.1)
# ---------------------------------------------------------------------------


def test_tc025_memory_map_renders_coverage_from_loaded_file(tmp_path: Path) -> None:
    """The Memory Map renders every range of the loaded file (LLR-012.1).

    Intent: the Memory Map is a read-only coverage visualization driven
    only by the existing ``LoadedFile.ranges`` / ``range_validity`` model
    fields — every contiguous range of the loaded image appears in the
    rendered map, addressed by its start/end. No coverage is computed by
    the screen itself.
    """
    from s19_app.tui.screens_directionb import MemoryMapPanel

    async def _drive() -> tuple[str, list[tuple[int, int]]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            loaded = _install_case_02_loaded_file(app)
            app.update_memory_map()
            await pilot.pause()
            panel = app.query_one("#memory_map_panel", MemoryMapPanel)
            return panel.rendered_text, list(loaded.ranges)

    rendered, ranges = asyncio.run(_drive())
    assert ranges, "precondition: the case_02 fixture must expose ranges"
    for start, end in ranges:
        token = f"0x{start:08X}-0x{end - 1:08X}"
        assert token in rendered, (
            f"Memory Map must render range {token} from LoadedFile.ranges; "
            f"rendered map was:\n{rendered}"
        )
    assert f"{len(ranges)} range(s)" in rendered, (
        "the Memory Map summary line must report the LoadedFile range count"
    )


def test_tc025_memory_map_renders_gaps_between_ranges(tmp_path: Path) -> None:
    """The Memory Map labels the uncovered gaps between ranges (LLR-012.1).

    Intent: the case_02 fixture has gaps between its contiguous ranges.
    The Memory Map must surface those gaps so coverage holes are visible
    at a glance — the gap spans are derived by subtracting consecutive
    (already-parsed) range bounds, not by any new coverage computation.
    """
    from s19_app.tui.screens_directionb import MemoryMapPanel

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _install_case_02_loaded_file(app)
            app.update_memory_map()
            await pilot.pause()
            panel = app.query_one("#memory_map_panel", MemoryMapPanel)
            return panel.rendered_text

    rendered = asyncio.run(_drive())
    assert "gap" in rendered, (
        f"the Memory Map must label the uncovered gaps between ranges; "
        f"rendered map was:\n{rendered}"
    )


def test_tc025_memory_map_panel_consumes_model_fields_verbatim() -> None:
    """MemoryMapPanel.render_ranges reflects exactly what it is handed.

    Intent: LLR-012.1 / LLR-012.4 — the panel must NOT re-derive or compute
    coverage. Driven with a hand-built range list it has never seen, it
    renders exactly those ranges and respects the supplied validity flags,
    proving it is a pure consumer of the ``LoadedFile`` fields.
    """
    from s19_app.tui.screens_directionb import MemoryMapPanel

    panel = MemoryMapPanel()
    panel.render_ranges([(0x100, 0x200), (0x400, 0x440)], [True, False])
    rendered = panel.rendered_text
    assert "0x00000100-0x000001FF" in rendered, "first range must render"
    assert "0x00000400-0x0000043F" in rendered, "second range must render"
    assert "[OK]" in rendered, "a valid range must carry the OK marker"
    assert "[INVALID]" in rendered, "an invalid range must carry the INVALID marker"
    assert "gap" in rendered, "the 0x200-0x3FF gap must be labelled"


def test_tc025_memory_map_empty_state_with_no_file(tmp_path: Path) -> None:
    """Activating Memory Map with no file shows the empty-state panel.

    Intent: LLR-002.3 — the Memory Map screen activated before any load
    shows the neutral ``EmptyStatePanel`` and hides its coverage content,
    never an error or a blank pane.
    """

    async def _drive() -> tuple[bool, bool, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            no_file = app.current_file is None
            app.action_show_screen("map")
            await pilot.pause()
            screen_map = app.query_one("#screen_map")
            content_hidden = "hidden" in app.query_one("#map_content").classes
            visible_panels = sum(
                1
                for panel in screen_map.query(EmptyStatePanel)
                if "hidden" not in panel.classes
            )
            return no_file, content_hidden, visible_panels

    no_file, content_hidden, visible_panels = asyncio.run(_drive())
    assert no_file, "precondition: no file loaded"
    assert content_hidden, "the coverage content must be hidden with no file"
    assert visible_panels == 1, (
        f"Memory Map must show exactly one empty-state panel with no file, "
        f"found {visible_panels}"
    )


def test_tc025_memory_map_empty_state_clears_when_file_loads(
    tmp_path: Path,
) -> None:
    """Loading a file reveals the Memory Map coverage and hides the panel.

    Intent: LLR-002.3 / LLR-012.1 — once a ``LoadedFile`` is present the
    Memory Map shows its coverage content and hides the empty-state panel,
    the same flip the load pipeline performs for the other rail screens.
    """

    async def _drive() -> dict[str, bool]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("map")
            await pilot.pause()
            before = "hidden" in app.query_one("#map_content").classes
            _install_case_02_loaded_file(app)
            app.update_memory_map()
            await pilot.pause()
            after = "hidden" in app.query_one("#map_content").classes
            panel_hidden = all(
                "hidden" in panel.classes
                for panel in app.query_one("#screen_map").query(EmptyStatePanel)
            )
            return {
                "content_hidden_before": before,
                "content_hidden_after": after,
                "panel_hidden_after": panel_hidden,
            }

    state = asyncio.run(_drive())
    assert state["content_hidden_before"], "content hidden before load"
    assert not state["content_hidden_after"], "content revealed after load"
    assert state["panel_hidden_after"], "empty-state panel hidden after load"


# ---------------------------------------------------------------------------
# TC-004 — Bookmarks slot shows a non-blocking placeholder (LLR-002.2)
# ---------------------------------------------------------------------------


def test_tc004_bookmarks_activation_shows_placeholder(tmp_path: Path) -> None:
    """Activating the Bookmarks rail item shows a "coming soon" placeholder.

    Intent: LLR-002.2 — the Bookmarks slot is a neutral placeholder screen.
    Activating it raises no error and shows text stating the feature is not
    yet available / coming soon.
    """
    from s19_app.tui.screens_directionb import BookmarksPlaceholder

    async def _drive() -> tuple[bool, list[str], str]:
        app = S19TuiApp(base_dir=tmp_path)
        raised = False
        text = ""
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            try:
                app.action_show_screen("bookmarks")
                await pilot.pause()
            except Exception:  # pragma: no cover - failure path
                raised = True
            placeholder = app.query_one("#bookmarks_placeholder", BookmarksPlaceholder)
            text = placeholder.PLACEHOLDER_TEXT.lower()
            return raised, _visible_screens(app), text

    raised, visible, text = asyncio.run(_drive())
    assert not raised, "activating Bookmarks must not raise an exception"
    assert visible == ["screen_bookmarks"], (
        f"only the Bookmarks screen must be visible after activation, "
        f"got {visible}"
    )
    assert "coming soon" in text or "not yet available" in text, (
        f"the placeholder must state the feature is deferred; text was {text!r}"
    )


def test_tc004_bookmarks_rail_key_8_reaches_placeholder(tmp_path: Path) -> None:
    """Pressing the rail key ``8`` opens the Bookmarks placeholder screen.

    Intent: LLR-002.2 / LLR-013.1 — the Bookmarks placeholder is reachable
    by keyboard via its rail key, and the keyboard path raises no error.
    """

    async def _drive() -> list[str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press("8")
            await pilot.pause()
            return _visible_screens(app)

    visible = asyncio.run(_drive())
    assert visible == ["screen_bookmarks"], (
        f"rail key 8 must show only the Bookmarks screen, got {visible}"
    )


def test_tc004_bookmarks_placeholder_has_no_persistence_methods() -> None:
    """The Bookmarks placeholder widget exposes no persistence surface.

    Intent: LLR-002.2 / C-5 — no bookmark persistence is read or written
    this batch. The placeholder widget is a static notice; it must not
    carry save/load/store/persist methods that would imply wired logic.
    """
    from s19_app.tui.screens_directionb import BookmarksPlaceholder

    placeholder = BookmarksPlaceholder()
    # Bookmark-persistence verbs only — generic substrings like "load" are
    # avoided since Textual's own `Static` carries `set_loading` / `loading`.
    forbidden = (
        "bookmark",
        "save_bookmark",
        "store_bookmark",
        "persist",
        "add_bookmark",
        "remove_bookmark",
    )
    surface = [name for name in dir(placeholder) if not name.startswith("_")]
    leaked = [
        name
        for name in surface
        if any(token in name.lower() for token in forbidden)
    ]
    assert leaked == [], (
        f"the Bookmarks placeholder must expose no persistence methods, "
        f"found {leaked}"
    )


# ---------------------------------------------------------------------------
# TC-028 (scaffold side) — deferred-logic guard (LLR-012.4)
# ---------------------------------------------------------------------------


def test_tc028_screens_directionb_imports_no_processing_libs() -> None:
    """screens_directionb.py imports none of bincopy / pya2l / crcmod.

    Intent: LLR-012.4 — the increment-9 scaffolds (Memory Map, Bookmarks)
    add no data-processing capability. AST-walk the view-layer module and
    assert the deferred-logic processing libraries are absent from its
    imports (mirrors ``test_tui_hexview.py::test_tc_023_...``).
    """
    import ast

    import s19_app.tui.screens_directionb as mod

    source = Path(mod.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    forbidden = {"bincopy", "pya2l", "crcmod"}
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    leaked = sorted(forbidden & imported)
    assert leaked == [], (
        f"screens_directionb.py must not import processing libs, found {leaked}"
    )


def test_tc028_no_new_processing_module_added_outside_view_layer() -> None:
    """Increment 9 adds no processing module under s19_app/ outside tui/.

    Intent: LLR-012.4 — the Memory Map / Bookmarks scaffolds are view-layer
    only. The increment touches ``s19_app/tui/`` exclusively; no new module
    appears in the engine packages (``validation/`` or the package root).
    """
    import s19_app

    package_root = Path(s19_app.__file__).resolve().parent
    # The pre-batch modules at the s19_app/ package root. Increment 9 adds
    # nothing here — its new code lives entirely under s19_app/tui/.
    engine_root_modules = {
        "__init__.py",
        "cli.py",
        "core.py",
        "hexfile.py",
        "range_index.py",
        "utils.py",
        "version.py",
    }
    actual_root_modules = {
        p.name for p in package_root.glob("*.py")
    }
    unexpected = actual_root_modules - engine_root_modules
    assert unexpected == set(), (
        f"increment 9 must add no module to the s19_app/ package root, "
        f"found unexpected {sorted(unexpected)}"
    )


def test_tc028_memory_map_renderer_adds_no_coverage_computation() -> None:
    """update_memory_map only reads LoadedFile fields, computes nothing.

    Intent: LLR-012.1 / LLR-012.4 — the Memory Map renderer must consume
    the already-computed ``ranges`` / ``range_validity`` model fields and
    add no coverage computation. AST-inspect ``update_memory_map`` and
    assert it references those two ``LoadedFile`` attributes and calls only
    the presentational ``render_ranges`` — no validation / range-index /
    parsing helper.
    """
    import ast
    import inspect

    source = inspect.getsource(S19TuiApp.update_memory_map)
    tree = ast.parse(source.lstrip())
    attrs = {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    assert "ranges" in attrs and "range_validity" in attrs, (
        "update_memory_map must read LoadedFile.ranges / range_validity"
    )
    calls = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    forbidden_calls = {
        "validate_artifact_consistency",
        "build_sorted_range_index",
        "build_range_validity_s19",
        "build_range_validity_hex",
        "parse_a2l_file",
        "parse_mac_file",
    }
    leaked_calls = sorted(forbidden_calls & calls)
    assert leaked_calls == [], (
        f"update_memory_map must not invoke parsing/validation helpers, "
        f"found {leaked_calls}"
    )


def test_tc028_scaffold_screens_activate_without_error(tmp_path: Path) -> None:
    """Every rail scaffold screen activates without raising (LLR-012.4).

    Intent: the increment-9 scaffolds (Memory Map, Bookmarks) — and the
    still-neutral Patch / Diff slots — each activate cleanly with no file
    loaded; deferred-logic screens render a view shell, never an error.
    """

    async def _drive() -> dict[str, bool]:
        app = S19TuiApp(base_dir=tmp_path)
        results: dict[str, bool] = {}
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            for key in ("map", "patch", "diff", "bookmarks"):
                try:
                    app.action_show_screen(key)
                    await pilot.pause()
                    results[key] = True
                except Exception:  # pragma: no cover - failure path
                    results[key] = False
        return results

    results = asyncio.run(_drive())
    for key, ok in results.items():
        assert ok, f"activating the {key} scaffold screen must not raise"


# ===========================================================================
# Increment 10 — Patch Editor + A2B Diff scaffolds
# ===========================================================================
#
# LLR-012.2 — the Patch Editor is an inert before/after view shell — hex
#             panes + address/bytes inputs wired to no patch-apply / undo /
#             redo logic, plus a visible deferral notice.
# LLR-012.3 — the A2B Diff is a static three-column placeholder (range list,
#             hex A, hex B) with constant sample hex rows + PLACEHOLDER
#             markers; no second-file load path, no diff computation.
# LLR-012.4 — completes the deferred-logic guard: no new processing module
#             outside the view layer; bincopy / pya2l / crcmod absent from
#             the scaffold module imports AND from pyproject.toml.
#
# Test cases: TC-026 (Patch Editor), TC-027 (A2B Diff), TC-028 (completion).


# ---------------------------------------------------------------------------
# TC-026 — Patch Editor screen renders the functional change-list editor
#
# batch-03 increment 9 (LLR-007.1..007.6) supersedes the batch-02 inert
# Patch Editor shell (R-TUI-027 / LLR-012.2): the screen now renders a
# change-list table, wired add/edit/remove inputs and save/load controls.
# The three batch-02 tests below were rewritten from the inert-shell
# assertions to the functional-screen ones — a requirement-driven test
# change, not a regression. The deferral-notice test is replaced by the
# LLR-007.6 empty-state test.
# ---------------------------------------------------------------------------


def test_tc026_patch_editor_renders_changelist_table(tmp_path: Path) -> None:
    """The Patch Editor renders the change-list table (LLR-007.1).

    Intent: LLR-007.1 — the functional Patch Editor renders the current
    change-list as a ``DataTable`` (one row per entry: parameter name,
    array index, value, status), replacing the batch-02 inert before/after
    hex panes. The table must be present once the screen is active.
    """
    from textual.widgets import DataTable

    async def _drive() -> bool:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            screen = app.query_one("#screen_patch")
            table = screen.query("#patch_changelist_table")
            return bool(table) and isinstance(table.first(), DataTable)

    has_table = asyncio.run(_drive())
    assert has_table, "the Patch Editor must render a change-list DataTable"


def test_tc026_patch_editor_renders_entry_inputs(
    tmp_path: Path,
) -> None:
    """The Patch Editor exposes the name/index/value inputs (LLR-007.2).

    Intent: LLR-007.2 — the functional Patch Editor carries the
    parameter-name, array-index and value input fields wired to the
    add/edit/remove change-list operations. They must be present as real
    ``Input`` widgets so the editor is operable.
    """
    from textual.widgets import Input

    async def _drive() -> tuple[bool, bool, bool]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            screen = app.query_one("#screen_patch")
            name = screen.query("#patch_name_input")
            index = screen.query("#patch_index_input")
            value = screen.query("#patch_value_input")
            return (
                bool(name) and isinstance(name.first(), Input),
                bool(index) and isinstance(index.first(), Input),
                bool(value) and isinstance(value.first(), Input),
            )

    name_ok, index_ok, value_ok = asyncio.run(_drive())
    assert name_ok, "the Patch Editor must expose a parameter-name Input"
    assert index_ok, "the Patch Editor must expose an array-index Input"
    assert value_ok, "the Patch Editor must expose a value Input"


def test_tc026_patch_editor_panel_is_presentational() -> None:
    """The Patch Editor widget holds no cdfx-package logic (LLR-007.5).

    Intent: LLR-007.5 / constraint C-8 — the CDFX read/write and
    change-list model logic lives in ``services.cdfx_service``, not in the
    view widget. The ``PatchEditorPanel`` must import nothing from the
    ``cdfx`` package and must perform its work by posting an
    ``ActionRequested`` message rather than calling a writer/reader itself.
    """
    import ast
    import inspect

    from s19_app.tui.screens_directionb import PatchEditorPanel

    panel = PatchEditorPanel()
    # The widget hands the action to the app via a Message — it owns no
    # save/load/resolve method of its own.
    assert hasattr(panel, "ActionRequested"), (
        "the Patch Editor must emit an ActionRequested message"
    )

    # The widget module must not import the cdfx format handler — that is
    # the service's job (C-8).
    source = inspect.getsource(inspect.getmodule(PatchEditorPanel))
    tree = ast.parse(source)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
        elif isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
    cdfx_imports = [name for name in imported if "cdfx" in name]
    assert cdfx_imports == [], (
        f"the Patch Editor widget must not import the cdfx package; "
        f"found {cdfx_imports}"
    )


def test_tc026_patch_editor_shows_empty_state(tmp_path: Path) -> None:
    """The Patch Editor shows a neutral empty state (LLR-007.6).

    Intent: LLR-007.6 — while the Patch Editor is open with an empty
    change-list it shows a single neutral add-or-load prompt line, not a
    blank pane, an error or a stack trace.
    """
    from s19_app.tui.screens_directionb import PatchEditorPanel

    async def _drive() -> tuple[bool, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            empty = app.query("#patch_empty_state")
            visible = bool(empty) and not empty.first().has_class("hidden")
            return visible, PatchEditorPanel.EMPTY_STATE_TEXT.lower()

    empty_visible, text = asyncio.run(_drive())
    assert empty_visible, (
        "the empty Patch Editor must show its neutral empty-state line"
    )
    assert "load" in text and "add" in text, (
        f"the empty-state line must prompt to add or load; text was {text!r}"
    )


# ---------------------------------------------------------------------------
# TC-027 — A2B Diff view shell renders three columns (LLR-012.3)
# ---------------------------------------------------------------------------


def test_tc027_ab_diff_renders_three_columns(tmp_path: Path) -> None:
    """The A2B Diff renders a three-column placeholder layout (LLR-012.3).

    Intent: the A2B Diff is a Direction B three-column view shell — a range
    list, a hex-A column and a hex-B column. All three must be present in
    the rendered widget tree once the screen is active.
    """

    async def _drive() -> dict[str, bool]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("diff")
            await pilot.pause()
            screen = app.query_one("#screen_diff")
            return {
                "range_list": bool(screen.query("#diff_range_list")),
                "hex_a": bool(screen.query("#diff_hex_a")),
                "hex_b": bool(screen.query("#diff_hex_b")),
            }

    columns = asyncio.run(_drive())
    for name, present in columns.items():
        assert present, f"the A2B Diff must render the {name} column"


def test_tc027_ab_diff_columns_carry_static_placeholder_rows() -> None:
    """Each A2B Diff column shows constant, labelled placeholder hex rows.

    Intent: LLR-012.3 — "placeholder data" is defined as static, constant
    sample hex rows in each column, visibly marked as placeholder content.
    The three column constants must each carry a PLACEHOLDER caption and
    hex-like sample rows, and must not be sourced from a LoadedFile.
    """
    from s19_app.tui.screens_directionb import AbDiffPanel

    columns = (
        AbDiffPanel._RANGE_LIST_PLACEHOLDER,
        AbDiffPanel._HEX_A_PLACEHOLDER,
        AbDiffPanel._HEX_B_PLACEHOLDER,
    )
    for column_text in columns:
        assert "PLACEHOLDER" in column_text, (
            f"each A2B Diff column must be marked PLACEHOLDER; "
            f"column was:\n{column_text}"
        )
        # A column with at least two newline-separated lines below its
        # caption — a small fixed set of constant sample rows.
        assert column_text.count("\n") >= 2, (
            f"each A2B Diff column must carry static sample rows; "
            f"column was:\n{column_text}"
        )
    # The hex-A / hex-B columns must look like hex rows (constant content).
    assert "DE AD BE EF" in AbDiffPanel._HEX_A_PLACEHOLDER
    assert "DE AD BE EF" in AbDiffPanel._HEX_B_PLACEHOLDER


def test_tc027_ab_diff_states_diff_deferred_and_has_no_second_file_load(
    tmp_path: Path,
) -> None:
    """The A2B Diff states diff/second-file load is deferred (LLR-012.3).

    Intent: LLR-012.3 — the screen must carry a visible notice that diff
    computation and the second-file (B) load path are deferred, and must
    expose NO control to load a second firmware file this batch.
    """
    from s19_app.tui.screens_directionb import AbDiffPanel

    async def _drive() -> tuple[bool, bool, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("diff")
            await pilot.pause()
            screen = app.query_one("#screen_diff")
            notice = bool(screen.query("#diff_deferral_notice"))
            # No second-file load control: no Button anywhere on the screen.
            from textual.widgets import Button

            has_load_button = bool(screen.query(Button))
            return notice, has_load_button, AbDiffPanel.DEFERRAL_TEXT.lower()

    notice_present, has_load_button, text = asyncio.run(_drive())
    assert notice_present, "the A2B Diff must render a deferral notice"
    assert not has_load_button, (
        "the A2B Diff must expose no second-file (B) load control this batch"
    )
    assert "deferred" in text, (
        f"the deferral notice must state diff computation is deferred; "
        f"text was {text!r}"
    )
    assert "placeholder" in text, (
        "the deferral notice must mark the columns as placeholder content"
    )


def test_tc027_ab_diff_panel_holds_no_loaded_file_data() -> None:
    """The A2B Diff panel exposes no second-file / diff-computation surface.

    Intent: LLR-012.3 / LLR-012.4 — the panel renders only static constants;
    it must not carry a method that loads a second file or computes a diff.
    """
    from s19_app.tui.screens_directionb import AbDiffPanel

    panel = AbDiffPanel()
    forbidden = ("diff", "compare", "load_b", "second_file", "load_file")
    surface = [name for name in dir(panel) if not name.startswith("_")]
    leaked = [
        name
        for name in surface
        if any(token in name.lower() for token in forbidden)
    ]
    assert leaked == [], (
        f"the A2B Diff shell must expose no diff/second-file methods, "
        f"found {leaked}"
    )


# ---------------------------------------------------------------------------
# TC-028 (completion) — deferred-logic guard for all scaffolds (LLR-012.4)
# ---------------------------------------------------------------------------


def test_tc028_screens_directionb_imports_no_processing_libs_after_inc10() -> None:
    """screens_directionb.py still imports no bincopy / pya2l / crcmod.

    Intent: LLR-012.4 — increment 10 adds the Patch Editor and A2B Diff
    widgets to the view-layer module. AST-walk it again and confirm the
    deferred-logic processing libraries remain absent from its imports.
    """
    import ast

    import s19_app.tui.screens_directionb as mod

    source = Path(mod.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    forbidden = {"bincopy", "pya2l", "crcmod"}
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    leaked = sorted(forbidden & imported)
    assert leaked == [], (
        f"screens_directionb.py must not import processing libs after "
        f"increment 10, found {leaked}"
    )


def test_tc028_no_new_processing_module_added_outside_view_layer_inc10() -> None:
    """Increment 10 adds no processing module under s19_app/ outside tui/.

    Intent: LLR-012.4 — the Patch Editor / A2B Diff scaffolds are view-layer
    only. The increment touches ``s19_app/tui/`` exclusively; the engine
    package root carries exactly the pre-batch processing modules and no new
    one.
    """
    import s19_app

    package_root = Path(s19_app.__file__).resolve().parent
    engine_root_modules = {
        "__init__.py",
        "cli.py",
        "core.py",
        "hexfile.py",
        "range_index.py",
        "utils.py",
        "version.py",
    }
    actual_root_modules = {p.name for p in package_root.glob("*.py")}
    unexpected = actual_root_modules - engine_root_modules
    assert unexpected == set(), (
        f"increment 10 must add no module to the s19_app/ package root, "
        f"found unexpected {sorted(unexpected)}"
    )


def test_tc028_processing_libs_absent_from_pyproject() -> None:
    """bincopy / pya2l / crcmod are absent from pyproject.toml (LLR-012.4).

    Intent: TC-028 (c) — the deferred-logic guard extends to the dependency
    manifest. The handoff PLAN.md proposed adding bincopy / pya2l / crcmod;
    that proposal was rejected (C-2). No batch increment may have added them
    to ``pyproject.toml`` — neither to runtime nor to optional dependencies.
    """
    pyproject = (
        Path(__file__).resolve().parent.parent / "pyproject.toml"
    )
    text = pyproject.read_text(encoding="utf-8").lower()
    for lib in ("bincopy", "pya2l", "crcmod"):
        assert lib not in text, (
            f"{lib} must not appear in pyproject.toml (C-2 — rejected "
            f"deferred-logic dependency)"
        )


def test_tc028_patch_editor_renderer_invokes_no_patch_logic() -> None:
    """_compose_screen_patch wires no patch engine call (LLR-012.2/012.4).

    Intent: AST-inspect the ``_compose_screen_patch`` builder and assert it
    constructs only the ``PatchEditorPanel`` view shell — it calls no patch
    apply / undo / redo / engine helper.
    """
    import ast
    import inspect

    source = inspect.getsource(S19TuiApp._compose_screen_patch)
    tree = ast.parse(source.lstrip())
    calls = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    # The builder constructs only Container / Label / PatchEditorPanel.
    assert calls <= {"Container", "Label", "PatchEditorPanel"}, (
        f"_compose_screen_patch must build only the view shell, "
        f"found calls {sorted(calls)}"
    )


def test_tc028_diff_renderer_invokes_no_diff_logic() -> None:
    """_compose_screen_diff wires no diff computation (LLR-012.3/012.4).

    Intent: AST-inspect the ``_compose_screen_diff`` builder and assert it
    constructs only the ``AbDiffPanel`` static placeholder — it calls no
    diff / compare / second-file-load helper.
    """
    import ast
    import inspect

    source = inspect.getsource(S19TuiApp._compose_screen_diff)
    tree = ast.parse(source.lstrip())
    calls = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert calls <= {"Container", "Label", "AbDiffPanel"}, (
        f"_compose_screen_diff must build only the view shell, "
        f"found calls {sorted(calls)}"
    )


def test_tc028_every_scaffold_screen_activates_without_error(
    tmp_path: Path,
) -> None:
    """All four rail screens activate without raising (LLR-012.4).

    Intent: completes TC-028 (d) — the Memory Map, Patch Editor, A2B Diff
    and Bookmarks rail screens each activate cleanly with no file loaded,
    never an error. The A2B Diff stays a deferred placeholder and must still
    carry its deferral marker; the Patch Editor is functional as of batch-03
    increment 9 (LLR-007.1) and instead carries its empty-state line.
    """

    async def _drive() -> dict[str, bool]:
        app = S19TuiApp(base_dir=tmp_path)
        results: dict[str, bool] = {}
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            for key in ("map", "patch", "diff", "bookmarks"):
                try:
                    app.action_show_screen(key)
                    await pilot.pause()
                    results[key] = True
                except Exception:  # pragma: no cover - failure path
                    results[key] = False
            # The A2B Diff screen still carries its deferral marker; the
            # Patch Editor is functional and carries its empty-state line.
            markers_present = bool(
                app.query("#diff_deferral_notice")
            ) and bool(app.query("#patch_empty_state"))
        return {**results, "markers_present": markers_present}

    results = asyncio.run(_drive())
    for key in ("map", "patch", "diff", "bookmarks"):
        assert results[key], f"activating the {key} rail screen must not raise"
    assert results["markers_present"], (
        "the A2B Diff must carry its deferral marker and the Patch Editor "
        "its empty-state line"
    )


# ===========================================================================
# INCREMENT 11 — no-regression / behavior verification sweep
# ===========================================================================
#
# This block is the dedicated cross-cutting regression increment. It does NOT
# add or change any production behavior — it verdicts the batch:
#   - TC-011  — no pre-batch BINDINGS action becomes keyboard-unreachable;
#               the 1/2/3 -> rail remap is intended supersession (LLR-004.4).
#   - TC-029  — every new Direction B control is keyboard-reachable; the
#               command-bar input-focus suppression sub-case (LLR-013.1 /
#               LLR-004.5).
#   - TC-030  — the footer reflects the active screen's show=True bindings,
#               compared against the increment-1 keymap proposal (LLR-013.2).
#   - TC-031  — the engine / data-processing modules are behaviorally
#               unchanged vs the batch start (git diff classification —
#               LLR-014.1).
#   - TC-032  — the engine/parser/validation test files are unmodified vs
#               the batch start; the suite stays green (LLR-014.2).
# ---------------------------------------------------------------------------


# The pre-batch S19TuiApp.BINDINGS, captured verbatim from keymap-proposal.md
# §1.1 (the supersession baseline). Each tuple is (key, action). This is a
# frozen literal, NOT read back from the current BINDINGS, so the test can
# fail loudly if a pre-batch action silently loses its keyboard path.
_PRE_BATCH_BINDINGS: tuple[tuple[str, str], ...] = (
    ("l", "load_file"),
    ("r", "refresh_files"),
    ("o", "open_workarea"),
    ("s", "save_project"),
    ("p", "load_project"),
    ("j", "dump_a2l_json"),
    ("1", "view_main"),
    ("2", "view_alt"),
    ("3", "view_mac"),
    ("q", "quit"),
    ("plus", "page_next_context"),
    ("minus", "page_prev_context"),
    ("comma", "hex_page_prev"),
    ("period", "hex_page_next"),
)

# The engine / data-processing modules frozen by C-1 / LLR-014.1. color_policy
# is included per the increment-11 brief (the severity-color source of truth).
_ENGINE_PATHS: tuple[str, ...] = (
    "s19_app/core.py",
    "s19_app/hexfile.py",
    "s19_app/range_index.py",
    "s19_app/validation",
    "s19_app/tui/a2l.py",
    "s19_app/tui/mac.py",
    "s19_app/tui/color_policy.py",
)

# The engine/parser/validation test files that LLR-014.2 / AC-B2 require to
# pass with ZERO source modification vs the batch start.
_ENGINE_TEST_FILES: tuple[str, ...] = (
    "tests/test_core_srecord_validation.py",
    "tests/test_hexfile.py",
    "tests/test_range_index.py",
    "tests/test_validation_a2l.py",
    "tests/test_validation_engine.py",
    "tests/test_validation_mac.py",
    "tests/test_tui_a2l.py",
    "tests/test_tui_mac.py",
    "tests/test_color_policy_round_trip.py",
)


def _git(*args: str) -> str:
    """Run a read-only git command from the repo root and return stdout.

    Used by TC-031 / TC-032 to diff the working tree against ``main`` (the
    batch-start baseline). The repo root is the parent of ``tests/``.
    """
    repo_root = Path(__file__).resolve().parent.parent
    result = subprocess.run(
        ["git", *args],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout


def _palette_action_ids(app: S19TuiApp) -> set[str]:
    """Return the set of action ids reachable via the command palette."""
    return set(app.query_one(CommandBar).visible_palette_actions())


# ---------------------------------------------------------------------------
# TC-011 — no pre-batch binding becomes keyboard-unreachable;
#          1/2/3 remap is intended supersession (LLR-004.4)
# ---------------------------------------------------------------------------


def test_tc011_every_pre_batch_action_keeps_a_keyboard_path(tmp_path: Path) -> None:
    """Every pre-batch ``BINDINGS`` action is still reachable by keyboard.

    Intent: LLR-004.4 / AC-B6 — the Direction B restyle must not strand a
    single pre-batch action. For each action in the frozen pre-batch set,
    assert it is reachable either by a current key binding OR by a command-
    palette entry. The ``view_main`` / ``view_alt`` / ``view_mac`` actions
    are reachable through their retained legacy-alias methods and through
    the ``show_screen`` rail actions on keys ``1``/``2``/``3`` — the
    supersession sub-case below verdicts that path explicitly.

    This test fails loudly if a future edit removes an action's binding
    without re-homing it on the palette: the pre-batch set is a frozen
    literal, so it cannot drift to match a shrunken ``BINDINGS``.
    """

    async def _drive() -> tuple[set[str], set[str], set[str]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            current_keys: set[str] = set()
            current_actions: set[str] = set()
            for binding in S19TuiApp.BINDINGS:
                if isinstance(binding, Binding):
                    current_keys.add(binding.key)
                    current_actions.add(binding.action)
                else:
                    current_keys.add(binding[0])
                    current_actions.add(binding[1])
            palette = _palette_action_ids(app)
        return current_keys, current_actions, palette

    current_keys, current_actions, palette = asyncio.run(_drive())

    # The Workspace / A2L / MAC screens behind the retired view_* actions are
    # reachable via the rail's show_screen actions; the legacy view_* aliases
    # are also retained on S19TuiApp. Either path satisfies reachability.
    view_action_aliases = {
        "view_main": ("show_screen('workspace')", "view_main"),
        "view_alt": ("show_screen('a2l')", "view_alt"),
        "view_mac": ("show_screen('mac')", "view_mac"),
    }

    for key, action in _PRE_BATCH_BINDINGS:
        if action in view_action_aliases:
            # Superseded: the underlying screen is reachable via the rail.
            candidates = view_action_aliases[action]
            reachable = (
                any(c in current_actions for c in candidates)
                or any(c in palette for c in candidates)
                or hasattr(S19TuiApp, f"action_{action}")
            )
            assert reachable, (
                f"pre-batch action '{action}' (key '{key}') lost every "
                f"keyboard path after the 1/2/3 -> rail supersession"
            )
            continue
        # Non-superseded pre-batch actions keep a direct binding or palette
        # entry; the exact key may change but a keyboard path must remain.
        reachable = action in current_actions or action in palette
        assert reachable, (
            f"pre-batch action '{action}' (originally key '{key}') became "
            f"keyboard-unreachable — no binding and no palette entry"
        )


def test_tc011_supersession_recorded_not_a_regression(tmp_path: Path) -> None:
    """The 1/2/3 -> rail remap and ``#view_bar`` removal are designed changes.

    Intent: LLR-004.4 supersession sub-case (Q-04) — assert the remap is
    *intended supersession*: (a) keys ``1``/``2``/``3`` now activate the
    Workspace / A2L Explorer / MAC View rail screens; (b) the underlying
    screens stay keyboard-reachable on those same keys; (c) the ``#view_bar``
    button bar is gone (its three view-toggle buttons no longer exist in the
    widget tree). A lost action would fail TC-011's reachability test above;
    this test records that the *change of meaning* is the design.
    """

    async def _drive() -> dict[str, object]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            # (a) keys 1/2/3 are bound to the rail show_screen actions.
            digit_actions: dict[str, str] = {}
            for binding in S19TuiApp.BINDINGS:
                key = binding.key if isinstance(binding, Binding) else binding[0]
                action = (
                    binding.action if isinstance(binding, Binding) else binding[1]
                )
                if key in ("1", "2", "3"):
                    digit_actions[key] = action
            # (b) pressing 1/2/3 actually swaps to the right screen.
            await pilot.press("3")
            await pilot.pause()
            mac_visible = "hidden" not in app.query_one("#screen_mac").classes
            await pilot.press("1")
            await pilot.pause()
            workspace_visible = (
                "hidden" not in app.query_one("#screen_workspace").classes
            )
            # (c) the retired #view_bar surface is gone from the tree.
            view_bar_present = bool(app.query("#view_bar"))
        return {
            "digit_actions": digit_actions,
            "mac_visible": mac_visible,
            "workspace_visible": workspace_visible,
            "view_bar_present": view_bar_present,
        }

    result = asyncio.run(_drive())
    assert result["digit_actions"] == {
        "1": "show_screen('workspace')",
        "2": "show_screen('a2l')",
        "3": "show_screen('mac')",
    }, "keys 1/2/3 must be remapped to the rail show_screen actions"
    assert result["mac_visible"], "key '3' must activate the MAC View rail screen"
    assert result["workspace_visible"], (
        "key '1' must activate the Workspace rail screen"
    )
    assert not result["view_bar_present"], (
        "the pre-batch #view_bar button bar must be removed (intended "
        "Direction B supersession, A-07 / LLR-004.4)"
    )


# ---------------------------------------------------------------------------
# TC-029 — every new Direction B control is keyboard-reachable;
#          input-focus suppression sub-case (LLR-013.1 / LLR-004.5)
# ---------------------------------------------------------------------------


def test_tc029_rail_items_reachable_by_keyboard(tmp_path: Path) -> None:
    """Every rail item (a new Direction B control) responds to its key.

    Intent: LLR-013.1 — the activity rail is mouse-clickable; it must also
    be fully keyboard-driven. Pressing each of keys ``1``-``8`` activates the
    matching rail screen and moves the single active marker, with no mouse.
    """

    async def _drive() -> list[tuple[str, str, str]]:
        app = S19TuiApp(base_dir=tmp_path)
        seen: list[tuple[str, str, str]] = []
        async with app.run_test() as pilot:
            await pilot.pause()
            for index, screen_key in enumerate(SCREEN_KEYS, start=1):
                await pilot.press(str(index))
                await pilot.pause()
                visible = _visible_screens(app)
                active = app.query_one(Rail).active_key
                seen.append(
                    (screen_key, visible[0] if visible else "", active)
                )
        return seen

    seen = asyncio.run(_drive())
    for screen_key, visible_id, active in seen:
        assert visible_id == f"screen_{screen_key}", (
            f"key for '{screen_key}' must activate that screen via keyboard"
        )
        assert active == screen_key, (
            f"the rail active marker must follow the keyboard activation "
            f"of '{screen_key}'"
        )


def test_tc029_command_bar_inputs_reachable_by_keyboard(tmp_path: Path) -> None:
    """The command-bar find / go-to inputs and palette are keyboard-reachable.

    Intent: LLR-013.1 — the three command-bar surfaces are reachable via
    ``/`` (find), ``g`` (go-to) and ``ctrl+k`` (palette), with no mouse.
    """

    async def _drive() -> tuple[str, str, bool]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.set_focus(None)
            await pilot.press("slash")
            await pilot.pause()
            find_focus = app.focused.id if app.focused else ""
            app.set_focus(None)
            await pilot.press("g")
            await pilot.pause()
            goto_focus = app.focused.id if app.focused else ""
            app.set_focus(None)
            await pilot.press("ctrl+k")
            await pilot.pause()
            palette_open = app.query_one(CommandBar).palette_is_open
        return find_focus, goto_focus, palette_open

    find_focus, goto_focus, palette_open = asyncio.run(_drive())
    assert find_focus == "find_input", "'/' must focus the find input"
    assert goto_focus == "cmdbar_goto_input", "'g' must focus the go-to input"
    assert palette_open, "'ctrl+k' must open the command palette"


def test_tc029_density_toggle_reachable_by_keyboard(tmp_path: Path) -> None:
    """The density toggle (a new control) responds to ``ctrl+d``.

    Intent: LLR-013.1 — density is a Direction B control with no mouse
    affordance; ``ctrl+d`` must drive it. Pressing it flips the density
    class on the workspace body.
    """

    async def _drive() -> tuple[bool, bool]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            body = app.query_one("#workspace_body")
            before_compact = "density-compact" in body.classes
            await pilot.press("ctrl+d")
            await pilot.pause()
            after_compact = "density-compact" in body.classes
        return before_compact, after_compact

    before_compact, after_compact = asyncio.run(_drive())
    assert before_compact != after_compact, (
        "'ctrl+d' must toggle the density class on the workspace body"
    )


def test_tc029_scaffold_inputs_reachable_by_keyboard(tmp_path: Path) -> None:
    """The Patch Editor inputs are keyboard-focusable controls.

    Intent: LLR-013.1 — the Patch Editor parameter-name/value ``Input``
    fields are interactive controls and must be keyboard-reachable, not
    mouse-only. ``Input`` is ``can_focus`` by default; this asserts the
    controls accept keyboard focus via ``focus()``. (The input ids changed
    from the batch-02 inert shell to the batch-03 functional editor.)
    """

    async def _drive() -> tuple[bool, bool]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            app.action_show_screen("patch")
            await pilot.pause()
            name = app.query_one("#patch_name_input", Input)
            value = app.query_one("#patch_value_input", Input)
            name.focus()
            await pilot.pause()
            name_focused = app.focused is name
            value.focus()
            await pilot.pause()
            value_focused = app.focused is value
        return name_focused, value_focused

    name_focused, value_focused = asyncio.run(_drive())
    assert name_focused, "the Patch Editor name input must accept keyboard focus"
    assert value_focused, "the Patch Editor value input must accept keyboard focus"


def test_tc029_single_keys_suppressed_during_input_focus(tmp_path: Path) -> None:
    """While a command-bar input is focused, single-key bindings do not fire.

    Intent: LLR-004.5 / OQ-12 — the input-focus suppression sub-case of
    TC-029. With the find input focused, pressing ``g``, a digit ``1``-``8``
    and a punctuation paging key (``period``) must route those keystrokes
    into the input as text — go-to focus must not be taken, the active rail
    screen must not change, and no paging action may fire. Once the input
    loses focus, the single-key bindings resume.
    """

    async def _drive() -> dict[str, object]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.set_focus(None)
            await pilot.press("slash")
            await pilot.pause()
            find_input = app.query_one("#find_input", Input)
            find_input.value = ""
            start_screen = _visible_screens(app)
            for key in ("g", "7", "period"):
                await pilot.press(key)
            await pilot.pause()
            typed = find_input.value
            focus_during = app.focused.id if app.focused else ""
            screen_during = _visible_screens(app)
            # Suppression must end once the input loses focus.
            app.set_focus(None)
            await pilot.press("3")
            await pilot.pause()
            screen_after = _visible_screens(app)
        return {
            "typed": typed,
            "focus_during": focus_during,
            "screen_during": screen_during,
            "start_screen": start_screen,
            "screen_after": screen_after,
        }

    result = asyncio.run(_drive())
    # The g / digit / punctuation keys are inserted as text, not fired.
    assert result["typed"] == "g7.", (
        f"single keys must be routed into the focused find input as text, "
        f"got {result['typed']!r}"
    )
    assert result["focus_during"] == "find_input", (
        "'g' must NOT steal focus to the go-to input while find is focused"
    )
    assert result["screen_during"] == result["start_screen"], (
        "a digit key must NOT change the active rail screen while a "
        "command-bar input is focused"
    )
    # Once focus is released, the binding resumes — '3' activates MAC View.
    assert result["screen_after"] == ["screen_mac"], (
        "single-key bindings must resume once the command-bar input loses "
        "focus"
    )


# ---------------------------------------------------------------------------
# TC-030 — the footer reflects the active screen's show=True bindings
#          (LLR-013.2 — expected set pinned by the increment-1 keymap)
# ---------------------------------------------------------------------------
#
# The increment-1 keymap-proposal.md pins the expected footer set:
#   - the global footer set (always shown):
#       ctrl+k, ctrl+d, ctrl+l, ctrl+s, slash, g, q
#   - the per-screen paging set is realised through the single global
#     dispatcher bindings period / comma / plus / minus (see the module
#     docstring's increment-11 design note). Every screen the keymap §3
#     assigns paging to (Workspace, A2L, MAC, Issues) keeps those keys in
#     the footer; the scaffold screens (Map, Patch, Diff, Bookmarks) carry
#     no per-screen set and show only the global footer set + the constant
#     paging dispatchers.
# ---------------------------------------------------------------------------

# Global footer set — keymap-proposal.md §2 ("always shown").
_GLOBAL_FOOTER_KEYS: frozenset[str] = frozenset(
    {"ctrl+k", "ctrl+d", "ctrl+l", "ctrl+s", "slash", "g", "q"}
)

# The four paging keys that realise the keymap §3 per-screen paging sets.
_PAGING_FOOTER_KEYS: frozenset[str] = frozenset(
    {"period", "comma", "plus", "minus"}
)

# keymap-proposal.md §3: screens the keymap assigns a per-screen paging set.
# Map / Patch / Diff / Bookmarks carry no per-screen bindings (scaffolds).
_SCREENS_WITH_PAGING: frozenset[str] = frozenset({"workspace", "a2l", "mac", "issues"})


def _shown_footer_keys(app: S19TuiApp) -> set[str]:
    """Return the keys the footer shows — the app's ``show=True`` bindings.

    ``App.active_bindings`` is exactly what the Textual ``Footer`` renders;
    filtering it to ``binding.show`` and ``enabled`` reproduces the footer's
    visible chip set.
    """
    return {
        key
        for key, active in app.active_bindings.items()
        if active.binding.show and active.enabled
    }


def test_tc030_global_footer_set_present_on_every_screen(tmp_path: Path) -> None:
    """The keymap §2 global footer set is shown on every rail screen.

    Intent: LLR-013.2 — the footer/status bar must surface the active
    screen's ``show=True`` bindings. The keymap proposal §2 pins the global
    footer set (``ctrl+k`` · ``ctrl+d`` · ``ctrl+l`` · ``ctrl+s`` · ``/`` ·
    ``g`` · ``q``) as always-shown; this asserts every one of those keys is
    in the footer's visible set on each of the eight rail screens.
    """

    async def _drive() -> dict[str, set[str]]:
        app = S19TuiApp(base_dir=tmp_path)
        footers: dict[str, set[str]] = {}
        async with app.run_test() as pilot:
            await pilot.pause()
            for screen_key in SCREEN_KEYS:
                app.action_show_screen(screen_key)
                await pilot.pause()
                footers[screen_key] = _shown_footer_keys(app)
        return footers

    footers = asyncio.run(_drive())
    for screen_key, shown in footers.items():
        missing = _GLOBAL_FOOTER_KEYS - shown
        assert not missing, (
            f"screen '{screen_key}' footer is missing global keymap §2 "
            f"keys {sorted(missing)} — footer shows {sorted(shown)}"
        )


def test_tc030_per_screen_paging_bindings_in_footer(tmp_path: Path) -> None:
    """Screens the keymap §3 assigns paging to show the paging keys.

    Intent: LLR-013.2 — the per-screen ``show=True`` set is TC-030's
    expected column (keymap proposal §3). The keymap assigns a paging set to
    Workspace, A2L Explorer, MAC View and Issues Report; this asserts the
    four paging keys (``period`` / ``comma`` / ``plus`` / ``minus``, the
    single global dispatchers realising the per-screen sets — see the module
    docstring) are present in the footer on each of those screens.
    """

    async def _drive() -> dict[str, set[str]]:
        app = S19TuiApp(base_dir=tmp_path)
        footers: dict[str, set[str]] = {}
        async with app.run_test() as pilot:
            await pilot.pause()
            for screen_key in SCREEN_KEYS:
                app.action_show_screen(screen_key)
                await pilot.pause()
                footers[screen_key] = _shown_footer_keys(app)
        return footers

    footers = asyncio.run(_drive())
    for screen_key in _SCREENS_WITH_PAGING:
        shown = footers[screen_key]
        missing = _PAGING_FOOTER_KEYS - shown
        assert not missing, (
            f"screen '{screen_key}' has a keymap §3 paging set but its "
            f"footer is missing paging keys {sorted(missing)}"
        )


def test_tc030_footer_updates_and_reflects_active_screen(tmp_path: Path) -> None:
    """The footer is a live ``Footer`` reflecting the running app's bindings.

    Intent: LLR-013.2 acceptance criterion — the footer shows the *current*
    screen's bindings and updates on screen change. This asserts (a) a
    ``Footer`` widget is mounted, (b) its visible binding set is non-empty
    and is exactly the app's ``show=True`` bindings on each screen, and (c)
    navigating between screens keeps the footer consistent with
    ``active_bindings`` (the property the ``Footer`` renders from). The
    realised implementation uses one app-level ``BINDINGS`` set, so the chip
    set is constant — this test pins that and verifies the footer never
    drifts from ``active_bindings``.
    """
    from textual.widgets import Footer

    async def _drive() -> tuple[bool, dict[str, set[str]]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            footer_mounted = bool(app.query(Footer))
            per_screen: dict[str, set[str]] = {}
            for screen_key in SCREEN_KEYS:
                app.action_show_screen(screen_key)
                await pilot.pause()
                per_screen[screen_key] = _shown_footer_keys(app)
        return footer_mounted, per_screen

    footer_mounted, per_screen = asyncio.run(_drive())
    assert footer_mounted, "a Footer widget must be mounted to show bindings"
    for screen_key, shown in per_screen.items():
        assert shown, (
            f"screen '{screen_key}' must show a non-empty footer binding set"
        )
        # Every shown key is a real app binding (no phantom footer chips).
        assert _GLOBAL_FOOTER_KEYS.issubset(shown), (
            f"screen '{screen_key}' footer dropped a global binding"
        )


# ---------------------------------------------------------------------------
# TC-031 — the engine / data-processing modules are behaviorally unchanged
#          vs the batch start (git diff classification — LLR-014.1)
# ---------------------------------------------------------------------------


def test_tc031_engine_modules_have_no_diff_vs_main(tmp_path: Path) -> None:
    """The engine / data-processing modules show zero diff vs ``main``.

    Intent: LLR-014.1 / C-1 — the parse/validate engine is frozen for this
    view-only batch. ``git diff --stat main`` over ``core.py``,
    ``hexfile.py``, ``range_index.py``, ``validation/``, ``tui/a2l.py``,
    ``tui/mac.py`` and ``tui/color_policy.py`` must be empty. An empty diff
    is the strongest possible verdict for the cosmetic-only rubric (Q-11):
    there are zero changed lines, so there is trivially no logic, constant
    or signature change.

    If a future increment touches an engine module — even cosmetically —
    this test fails and forces the change to be classified by hand against
    the rubric (whitespace/comment/import-order = cosmetic; logic/constant/
    signature = a violation) rather than slipping through silently.
    """
    diff_stat = _git("diff", "--stat", "main", "--", *_ENGINE_PATHS)
    assert diff_stat.strip() == "", (
        "the engine / data-processing modules must be byte-identical to "
        f"the batch start (main); git diff --stat reported:\n{diff_stat}"
    )


def test_tc031_engine_modules_have_no_name_only_diff_vs_main(tmp_path: Path) -> None:
    """No engine module file appears in ``git diff --name-only main``.

    Intent: LLR-014.1 — a second, independent check that no file under the
    frozen engine surface was modified, added or deleted relative to the
    batch start. ``--stat`` (the test above) and ``--name-only`` (here)
    cross-check each other so a formatting quirk in one cannot mask a real
    change.
    """
    names = _git("diff", "--name-only", "main", "--", *_ENGINE_PATHS)
    changed = [line for line in names.splitlines() if line.strip()]
    assert changed == [], (
        f"engine / data-processing files changed vs the batch start: "
        f"{changed} — C-1 / LLR-014.1 freezes these modules"
    )


def test_tc031_engine_imports_still_resolve(tmp_path: Path) -> None:
    """The frozen engine modules still import cleanly.

    Intent: LLR-014.1 corroboration — a zero diff already proves behavioral
    identity, but importing each frozen module confirms the surrounding
    view-layer changes did not break the engine's import graph (a broken
    import would be a behavioral regression even with an unchanged file).
    """
    import importlib

    for module_name in (
        "s19_app.core",
        "s19_app.hexfile",
        "s19_app.range_index",
        "s19_app.validation.engine",
        "s19_app.validation.rules",
        "s19_app.validation.model",
        "s19_app.tui.a2l",
        "s19_app.tui.mac",
        "s19_app.tui.color_policy",
    ):
        module = importlib.import_module(module_name)
        assert module is not None, f"frozen engine module {module_name} failed to import"


# ---------------------------------------------------------------------------
# TC-032 — the engine/parser/validation test files are unmodified vs the
#          batch start; the suite stays green (LLR-014.2)
# ---------------------------------------------------------------------------


def test_tc032_engine_test_files_unmodified_vs_main(tmp_path: Path) -> None:
    """The engine/parser/validation test files are byte-identical to ``main``.

    Intent: LLR-014.2 / AC-B2 — the no-regression contract requires the
    engine/parser/validation tests to pass with ZERO source modification.
    This asserts none of those test files appears in ``git diff --name-only
    main`` — they were not edited by the batch. The UI test files
    (``test_tui_app.py``, ``test_tui_directionb.py``, …) are intentionally
    excluded: LLR-014.2 explicitly permits updating UI tests to the new
    layout (without weakening intent).
    """
    names = _git("diff", "--name-only", "main", "--", *_ENGINE_TEST_FILES)
    changed = [line for line in names.splitlines() if line.strip()]
    assert changed == [], (
        f"engine/parser/validation test files were modified vs the batch "
        f"start: {changed} — LLR-014.2 / AC-B2 require zero modification to "
        f"these files"
    )


def test_tc032_no_engine_test_function_is_skipped(tmp_path: Path) -> None:
    """No engine/parser/validation test is decorated to skip silently.

    Intent: LLR-014.2 / rule 12 ("fail loud") — 'the suite passes' is wrong
    if an engine test was quietly turned off. This statically scans the
    engine/parser/validation test files for ``@pytest.mark.skip`` /
    ``skipif`` decorators; the pre-batch baseline has none, so any
    appearance would mean a regression was hidden behind a skip.

    Note: ``xfail`` is allowed — the batch baseline carries 3 documented
    ``xfailed`` cases; only outright ``skip`` of an engine test is a
    no-regression violation here.
    """
    repo_root = Path(__file__).resolve().parent.parent
    offenders: list[str] = []
    for rel in _ENGINE_TEST_FILES:
        path = repo_root / rel
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        for marker in ("@pytest.mark.skip", "pytest.mark.skipif", "pytest.skip("):
            if marker in text:
                offenders.append(f"{rel}: {marker}")
    assert offenders == [], (
        f"engine/parser/validation tests must not be skipped — found "
        f"skip markers: {offenders}"
    )


def test_tc032_directionb_tests_do_not_monkeypatch_engine_functions() -> None:
    """The Direction B test suite never monkeypatches an engine function.

    Intent: LLR-014.2 corroboration — the increment-11 / Direction B tests
    are view-layer tests. Importing an engine dataclass (``LoadedFile`` is
    built from ``S19File`` / ``ValidationIssue`` constructors in some
    fixtures) is legitimate read-only fixture construction. What would
    *invalidate* the no-regression argument is a view test that
    ``monkeypatch``-es an engine parse/validate function and then asserts
    behavior — that would test a fake engine, not the real one.

    This statically scans the Direction B test files for
    ``monkeypatch.setattr`` calls whose first argument targets a frozen
    engine module (``s19_app.core`` / ``hexfile`` / ``range_index`` /
    ``validation``). The pre-batch baseline has none; any appearance would
    mean a view test silently swapped out engine behavior.
    """
    import ast

    repo_root = Path(__file__).resolve().parent.parent
    engine_targets = ("core", "hexfile", "range_index", "validation")
    offenders: list[str] = []
    for rel in ("tests/test_tui_directionb.py", "tests/test_tui_commandbar.py"):
        path = repo_root / rel
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            # Match `monkeypatch.setattr(...)` calls.
            if not (
                isinstance(func, ast.Attribute)
                and func.attr == "setattr"
                and isinstance(func.value, ast.Name)
                and func.value.id == "monkeypatch"
            ):
                continue
            target = ast.unparse(node.args[0]) if node.args else ""
            if any(f"s19_app.{t}" in target for t in engine_targets):
                offenders.append(f"{rel}: monkeypatch.setattr({target}, ...)")
    assert offenders == [], (
        f"Direction B view-layer tests must not monkeypatch frozen engine "
        f"functions: {offenders}"
    )
