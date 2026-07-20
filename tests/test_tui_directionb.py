"""Direction B app-shell tests — batch-02-direction-b-restyle, increments 2-11.

Covers the increment-2 LLRs:
  - LLR-002.1 — rail-driven content swap (the ``.hidden``-toggle mechanism)
  - LLR-002.3 — empty-state panel when no file is loaded
  - LLR-006.1 — density cycle action (``Ctrl+D``)
  - LLR-006.2 — density default (Comfortable at startup)
  - LLR-007.1 (skeleton) — the two-regime ``width-narrow`` class

the increment-3 LLRs:
  - LLR-001.1 — activity-rail composition (9 ordered items on keys 1-9;
    batch-49 LLR-083.1 appended Checks as the 9th)
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


# The 9 Direction B rail screen container ids, in rail order (keys 1-9).
SCREEN_IDS = [
    "screen_workspace",
    "screen_a2l",
    "screen_mac",
    "screen_map",
    "screen_issues",
    "screen_patch",
    "screen_diff",
    "screen_flow",
    "screen_checks",
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
    "flow",
    "checks",
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


def test_tc003_rail_keys_1_to_9_route_screens(tmp_path: Path) -> None:
    """Pressing keys ``1``-``9`` activates rail screens 1-9 in order.

    Intent: the keymap-proposal binding of digits 1-9 to
    ``show_screen(...)`` is wired (batch-49 LLR-083.3 adds key 9 → Checks);
    pressing each digit makes exactly its rail screen visible. The legacy
    ``1``/``2``/``3`` view-toggle meaning is intentionally superseded
    (LLR-004.4).
    """

    async def _drive() -> dict[str, list[str]]:
        app = S19TuiApp(base_dir=tmp_path)
        result: dict[str, list[str]] = {}
        async with app.run_test() as pilot:
            await pilot.pause()
            for digit, expected_id in zip("123456789", SCREEN_IDS):
                await pilot.press(digit)
                await pilot.pause()
                result[digit] = _visible_screens(app)
        return result

    per_digit = asyncio.run(_drive())
    for digit, expected_id in zip("123456789", SCREEN_IDS):
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

# The 9 rail items, in rail order, paired with their screen key and the
# normative LLR-001.3 glyph -> screen mapping table (Unicode + ASCII).
# batch-49 (LLR-083.1): Checks appended as the 9th entry on key 9.
EXPECTED_RAIL = [
    ("workspace", "◫", "#"),
    ("a2l", "≡", "="),
    ("mac", "◉", "@"),
    ("map", "▤", "M"),
    ("issues", "!", "!"),
    ("patch", "✎", "P"),
    ("diff", "⏚", "D"),
    ("flow", "✦", "F"),
    ("checks", "☑", "C"),
]


# ---------------------------------------------------------------------------
# TC-001 — rail composes 9 ordered items on keys 1-9 (LLR-001.1 / LLR-083.1)
# ---------------------------------------------------------------------------


def test_tc001_rail_composes_nine_ordered_items(tmp_path: Path) -> None:
    """The activity rail composes exactly 9 items in the keymap rail order.

    Intent: LLR-001.1 / batch-49 LLR-083.1 — the rail is fixed at nine items,
    ordered Workspace, A2L, MAC, Map, Issues, Patch, Diff, Flow, Checks. Each
    item's 1-based position is its ``1``-``9`` keymap key, and that key
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
    assert positions == [1, 2, 3, 4, 5, 6, 7, 8, 9], (
        f"Rail items must be positioned 1-9 in order, got {positions}"
    )


def test_tc001_rail_keys_1_to_9_route_through_rail_items(tmp_path: Path) -> None:
    """Pressing ``1``-``9`` activates the screen of the same-position rail item.

    Intent: LLR-001.1 / batch-49 LLR-083.1 — each rail item is bound to its
    ``1``-``9`` key. The digit keys must route to the same screen that rail
    item represents, so keyboard navigation and the rail agree.
    """

    async def _drive() -> dict[str, str]:
        app = S19TuiApp(base_dir=tmp_path)
        result: dict[str, str] = {}
        async with app.run_test() as pilot:
            await pilot.pause()
            for digit, (screen_key, _, _) in zip("123456789", EXPECTED_RAIL):
                await pilot.press(digit)
                await pilot.pause()
                result[digit] = app.query_one(Rail).active_key
        return result

    per_digit = asyncio.run(_drive())
    for digit, (screen_key, _, _) in zip("123456789", EXPECTED_RAIL):
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

            # Key path — exactly one active for every digit 1-9.
            key_states: list[list[str]] = []
            for digit in "123456789":
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
    for digit, state in zip("123456789", key_states):
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
    assert len(rendered) == 9, f"expected 9 rail items, got {len(rendered)}"
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
    assert len(seen) == 9, f"expected all 9 screens visited, got {len(seen)}"
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
    assert len(results) == 9
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
    assert len(seen) == 9
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
    app.validation_issue_filter_mode = "all"
    app._validation_issues_window_start = 0
    app.update_validation_issues_view()


# ---------------------------------------------------------------------------
# TC-023 — Issues Report is a dedicated rail screen (LLR-011.1)
# ---------------------------------------------------------------------------


def test_tc023_grouped_panel_is_primary_content_of_screen_issues(
    tmp_path: Path,
) -> None:
    """The grouped panel is the sole primary content of the #screen_issues rail.

    Intent (batch-29, AT-043a home / LLR-043.R1): the legacy Issues
    ``#validation_issues_list`` ``DataTable`` is fully retired, so it must be
    absent from ``#screen_issues`` and the ``GroupedIssuesPanel``
    (``#validation_issues_groups``) is the sole primary descendant — together
    with the filter row and the summary line. Inverts the pre-retirement
    assertion (the DataTable used to be required present).
    """
    from s19_app.tui.issues_view import GroupedIssuesPanel

    async def _drive() -> dict[str, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            screen_issues = app.query_one("#screen_issues")
            return {
                "table": len(screen_issues.query("#validation_issues_list")),
                "groups": len(screen_issues.query("#validation_issues_groups")),
                "filters": len(screen_issues.query("#validation_issues_filters")),
                "summary": len(screen_issues.query("#validation_issues_summary")),
                "is_grouped_panel": int(
                    isinstance(
                        app.query_one("#validation_issues_groups"),
                        GroupedIssuesPanel,
                    )
                ),
            }

    dims = asyncio.run(_drive())
    assert dims["table"] == 0, (
        "the legacy Issues DataTable must be GONE from #screen_issues "
        f"(found {dims['table']})"
    )
    assert dims["groups"] == 1, (
        "the GroupedIssuesPanel must be the primary descendant of #screen_issues "
        f"(found {dims['groups']})"
    )
    assert dims["filters"] == 1 and dims["summary"] == 1, (
        "the Issues filter row and summary line must live in #screen_issues "
        f"(filters={dims['filters']}, summary={dims['summary']})"
    )
    assert dims["is_grouped_panel"] == 1, (
        "#validation_issues_groups must be a GroupedIssuesPanel"
    )


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


def test_at043a_datatable_retired_grouped_panel_populated(tmp_path: Path) -> None:
    """AT-043a (retirement): with issues seeded, the legacy DataTable is gone and
    the grouped panel is the populated Issues surface.

    Real mechanism: Pilot render of ``#screen_issues`` after seeding a mixed
    error/warning/info issue set. Observed: ``query("#validation_issues_list")``
    is empty tree-wide (DataTable retired) AND ``#validation_issues_groups`` is
    present with ``>= 1`` mounted ``IssueRow``. Counterfactual: pre-retirement
    the ``display:none`` DataTable was still mounted (query == 1) -> FAIL.
    """
    from s19_app.tui.issues_view import IssueRow

    async def _drive() -> tuple[int, int, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("issues")
            _seed_issue_objects(app, _mixed_issues_with_info())
            await pilot.pause()
            return (
                len(app.query("#validation_issues_list")),
                len(app.query("#validation_issues_groups")),
                len(app.query(IssueRow)),
            )

    tables, groups, rows = asyncio.run(_drive())
    assert tables == 0, (
        f"the legacy Issues DataTable must be retired tree-wide (found {tables})"
    )
    assert groups == 1, (
        f"the grouped panel must be the Issues surface (found {groups})"
    )
    assert rows >= 1, (
        f"the grouped panel must mount >= 1 IssueRow for a seeded mix (found {rows})"
    )


def test_at043b_selection_preserved_after_retirement(tmp_path: Path) -> None:
    """AT-043b (selection preserved): a real ``IssueRow`` focus + ``Enter`` still
    repaints ``#issues_hex_pane`` for an addressed issue after retirement.

    Real mechanism: ``IssueRow.on_key`` -> ``IssueRow.Selected`` ->
    ``on_issue_row_selected`` -> ``#issues_hex_pane`` (no DataTable path). An
    addressed row peeks at its ``0x…`` bytes and CHANGES the pane; an
    ``address is None`` row yields the neutral placeholder with no stale bytes.
    """
    from textual.widgets import Static
    from s19_app.tui.issues_view import IssueRow

    async def _select(app, pilot, row) -> str:
        row.focus()
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        return str(app.query_one("#issues_hex_pane", Static).render())

    async def _drive() -> tuple[str, str, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("issues")
            _seed_issue_objects(app, _mixed_issues_with_info())
            await pilot.pause()
            before = str(app.query_one("#issues_hex_pane", Static).render())
            rows = list(app.query(IssueRow))
            # Order is [ERR_0, ERR_1, WARN_0(0x80000100), INFO_0(None)].
            addressed = await _select(app, pilot, rows[2])
            no_address = await _select(app, pilot, rows[3])
            return before, addressed, no_address

    before, addressed, no_address = asyncio.run(_drive())
    assert "80000100" in addressed, (
        f"selecting the addressed row must peek at 0x80000100; pane={addressed!r}"
    )
    assert addressed != before, "the hex peek must change on selection"
    assert "80000100" not in no_address, (
        f"an address-less row must clear the prior selection's bytes; "
        f"pane={no_address!r}"
    )


def test_at043c_no_datatable_orphan_on_any_screen(tmp_path: Path) -> None:
    """AT-043c (retirement total): the legacy DataTable exists on NO rail screen.

    Real mechanism: boot the app, open Issues, and query the retired id on both
    ``#screen_issues`` and ``#screen_workspace`` — both must be 0, proving no
    second mount survived the retirement.
    """

    async def _drive() -> tuple[int, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("issues")
            await pilot.pause()
            return (
                len(app.query_one("#screen_issues").query("#validation_issues_list")),
                len(
                    app.query_one("#screen_workspace").query("#validation_issues_list")
                ),
            )

    on_issues, on_workspace = asyncio.run(_drive())
    assert on_issues == 0, (
        f"no DataTable may survive on #screen_issues (found {on_issues})"
    )
    assert on_workspace == 0, (
        f"no DataTable may survive on #screen_workspace (found {on_workspace})"
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
    from s19_app.tui.issues_view import (
        IssueGroupHeader,
        IssueRow,
        _GROUP_DISPLAY_MAX,
    )

    async def _drive() -> tuple[int, int, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _seed_issues_screen(app, 30)
            app.action_show_screen("issues")
            await pilot.pause()

            async def _count(mode: str) -> int:
                # Whole-filtered partition via the group headers (each reports
                # the whole-filtered count for its severity), not the windowed
                # rows. The pause flushes the prior render's remove_children so
                # only the current render's headers/rows are counted. Count-guard:
                # the capped IssueRow read must equal the whole list
                # (30 < _GROUP_DISPLAY_MAX), else the count is vacuous.
                app.validation_issue_filter_mode = mode
                app._validation_issues_window_start = 0
                app.update_validation_issues_view()
                await pilot.pause()
                assert len(app.query(IssueRow)) <= _GROUP_DISPLAY_MAX
                return sum(h.issue_count for h in app.query(IssueGroupHeader))

            return (
                await _count("all"),
                await _count("error"),
                await _count("warning"),
            )

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
    from textual.widgets import Button
    from s19_app.tui.issues_view import IssueGroupHeader, IssueRow, _GROUP_DISPLAY_MAX

    def _filtered_total(app: S19TuiApp) -> int:
        # Whole-filtered count via the group headers; count-guard the capped
        # IssueRow read cannot make the count vacuous (30 < _GROUP_DISPLAY_MAX).
        assert len(app.query(IssueRow)) <= _GROUP_DISPLAY_MAX
        return sum(h.issue_count for h in app.query(IssueGroupHeader))

    async def _drive() -> tuple[int, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _seed_issues_screen(app, 30)
            app.action_show_screen("issues")
            await pilot.pause()
            before = _filtered_total(app)
            button = app.query_one("#issues_filter_error", Button)
            app.on_button_pressed(Button.Pressed(button))
            await pilot.pause()
            return before, _filtered_total(app)

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
    severity value must map to its fixed ``sev-*`` class.
    """
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

    from s19_app.tui.issues_view import IssueRow, _GROUP_DISPLAY_MAX

    async def _drive() -> list:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _seed_issues_screen(app, 12)
            app.action_show_screen("issues")
            await pilot.pause()
            # The grouped Issues panel mounts a row per issue (12 < the cap)
            # and colours each through the same css_class_for_severity path —
            # the grouped panel's colour source of truth (IssueRow._sev_class).
            rows = list(app.query(IssueRow))
            assert len(rows) <= _GROUP_DISPLAY_MAX
            return [(r.issue.severity, r._sev_class) for r in rows]

    rendered = asyncio.run(_drive())
    assert len(rendered) == 12, (
        f"the grouped Issues panel must mount all 12 rows, got {len(rendered)}"
    )
    for severity, sev_class in rendered:
        assert sev_class == css_class_for_severity(severity), (
            f"IssueRow colour must round-trip through css_class_for_severity: "
            f"{severity} -> {sev_class}"
        )


def test_tc024_issues_row_select_jumps_to_source(tmp_path: Path) -> None:
    """Selecting an Issues row still jumps to its source (LLR-011.2).

    Intent: row-level jump-to-source is preserved after the legacy DataTable
    retirement — the surviving path is a real ``IssueRow`` focus + ``Enter``
    keypress that posts ``IssueRow.Selected`` and drives
    ``on_issue_row_selected`` -> ``#issues_hex_pane`` (C-16 real mechanism; the
    retired ``issue:<index>`` row-key path via ``on_data_table_row_selected`` is
    gone). An addressed row must repaint the peek at its address; an
    address-less row yields the neutral placeholder with no stale bytes.
    """
    from textual.widgets import Static
    from s19_app.tui.issues_view import IssueRow

    async def _select(app, pilot, row) -> str:
        row.focus()
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        return str(app.query_one("#issues_hex_pane", Static).render())

    async def _drive() -> tuple[str, str, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("issues")
            _seed_issue_objects(app, _mixed_issues_with_info())
            await pilot.pause()
            before = str(app.query_one("#issues_hex_pane", Static).render())
            rows = list(app.query(IssueRow))
            # Order is [ERR_0, ERR_1, WARN_0(0x80000100), INFO_0(None)].
            addressed = await _select(app, pilot, rows[2])
            no_address = await _select(app, pilot, rows[3])
            return before, addressed, no_address

    before, addressed, no_address = asyncio.run(_drive())
    assert "80000100" in addressed, (
        f"selecting the addressed row must peek at 0x80000100; pane={addressed!r}"
    )
    assert addressed != before, "the hex peek must change on selection"
    assert "no address" in no_address.lower(), (
        f"an address-less issue must show the neutral placeholder; "
        f"pane={no_address!r}"
    )
    assert "80000100" not in no_address, (
        f"the prior selection's bytes must clear on an address-less row; "
        f"pane={no_address!r}"
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

    # Theme token values from styles.tcss (the single source of truth).
    # batch-47 Inc-8 (US-FND) re-themed the $-vars to the navy/pastel
    # insight_style depth stack — the var NAMES are unchanged, only the hues.
    accent = "#91ABEC"   # $accent-calm — insight_style.HILITE
    bg_base = "#0A0E1B"  # $bg-base — insight_style.DEPTH_BG
    bg_panel = "#0F1525"  # $bg-panel — insight_style.DEPTH_PANEL

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
    """``validate_project_files`` still enforces the MAC/A2L one-each rule.

    TC-034 (LLR-015.2): the re-skin is visual-only — the project-file
    cardinality rules are untouched by it. A clean triple passes; a second
    MAC and a second A2L each fail with their specific message.

    Batch-07 LLR-005.1 superseded the original one-S19/HEX clause: multiple
    primaries are now project variants and must be ACCEPTED (the multi-variant
    coverage lives in tests/test_workspace_variants.py).

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

    # Two S19 files — accepted as variants since LLR-005.1 (batch-07).
    two_s19 = tmp_path / "two_s19"
    two_s19.mkdir()
    (two_s19 / "a.s19").write_text("S0", encoding="utf-8")
    (two_s19 / "b.s19").write_text("S0", encoding="utf-8")
    _, _, error = validate_project_files(two_s19)
    assert error is None, (
        f"two S19 files are variants and must be accepted, got {error!r}"
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
# batch-27 (R-TUI-041) — Interactive colour-coded Memory-Map minimap grid.
#
# Increment 1 (US-035): the read-only monochrome text list (superseded
# R-TUI-026 realisation — the three old `test_tc025_memory_map_renders_*`
# text-format tests were removed here) is replaced by a 2-D colour-coded cell
# grid whose cells route their status through `css_class_for_severity`.
#
# TCs below map 1:1 to the Inc-1 LLRs; AT-035 is the black-box Pilot proof.
# ---------------------------------------------------------------------------


# The public ``case_04`` S19 fixture has one valid range and one INVALID range
# (bad checksums) — it exercises the minimap's invalid (red / sev-error) cells.
_CASE_04_S19 = (
    Path(__file__).resolve().parent.parent
    / "examples"
    / "case_04_bad_checksums"
    / "firmware.s19"
)


def _install_case_04_loaded_file(app: S19TuiApp) -> "object":
    """Install the public ``case_04`` bad-checksums fixture as ``current_file``.

    Sibling of ``_install_case_02_loaded_file``; returns the built
    ``LoadedFile`` so a test can read its ``ranges`` / ``range_validity``.
    """
    from s19_app.core import S19File
    from s19_app.tui.services.load_service import build_loaded_s19

    s19 = S19File(str(_CASE_04_S19))
    loaded = build_loaded_s19(_CASE_04_S19, s19, a2l_path=None, a2l_data=None)
    app.current_file = loaded
    app._apply_empty_state()
    return loaded


def test_tc041_1_cell_status_derivation() -> None:
    """Cell status = invalid/valid/gap by range overlap (LLR-041.1).

    Intent: a cell overlapping any invalid range is ``invalid``; overlapping
    only valid range(s) is ``valid``; overlapping no range is ``gap``. This
    is the pure grid-model contract the colour routing binds to — if the
    overlap logic changes, the whole minimap mis-colours.
    """
    from s19_app.tui.screens_directionb import cell_status

    ordered = [(0, 8, True), (8, 16, False), (32, 40, True)]

    # Cell spanning both a valid and an invalid range → invalid wins.
    assert cell_status(0, 16, ordered) == "invalid"
    # Cell over the valid-only range.
    assert cell_status(32, 40, ordered) == "valid"
    # Cell over an uncovered window between ranges → gap.
    assert cell_status(16, 24, ordered) == "gap"
    # Half-open boundary: a cell that starts exactly at a range's end does
    # NOT overlap it (end is exclusive).
    assert cell_status(8, 16, [(0, 8, True)]) == "gap"


def test_tc041_2_auto_scale_cell_count_and_zero_span() -> None:
    """Cell count fits the injected geometry; zero-span → empty, no crash
    (LLR-041.2).

    Intent: the number of cells is a pure function of ``(span, cols, rows)``
    (version-stable, snapshot-safe — NOT live ``panel.size``) and never
    exceeds the grid capacity nor the byte count. A zero/empty span takes the
    empty path and computes no ratio (no divide-by-zero).
    """
    from s19_app.tui.screens_directionb import (
        bytes_per_cell,
        cell_count_for_geometry,
        derive_image_span,
    )

    # Large synthetic span, injected geometry (16x8 = 128 capacity).
    span_start, span_end = derive_image_span([(0x0, 0x100000)])
    span = span_end - span_start
    count = cell_count_for_geometry(span, 16, 8)
    assert count == 128, "cell count must be capped at the injected capacity"
    assert count <= span, "never more cells than bytes in the span"
    per_cell = bytes_per_cell(span, count)
    assert per_cell * count >= span, "the cells must cover the whole span"

    # A span smaller than capacity → one cell per byte, not padded up.
    assert cell_count_for_geometry(10, 16, 8) == 10

    # Zero-span guard: no cells, no ratio, no exception.
    assert cell_count_for_geometry(0, 16, 8) == 0
    assert bytes_per_cell(0, 0) == 0
    assert derive_image_span([]) == (0, 0)


def test_tc041_3_invalid_cell_carries_sev_error_class() -> None:
    """Invalid cell status routes to ``sev-error`` via color_policy
    (LLR-041.3).

    Intent: colours are NOT hard-coded — an invalid cell's class must equal
    ``css_class_for_severity(ValidationSeverity.ERROR)``, so the frozen
    severity map stays the single source of truth.
    """
    from s19_app.tui.color_policy import css_class_for_severity
    from s19_app.tui.screens_directionb import status_to_css_class
    from s19_app.validation import ValidationSeverity

    assert status_to_css_class("invalid") == css_class_for_severity(
        ValidationSeverity.ERROR
    )
    assert status_to_css_class("invalid") == "sev-error"
    assert status_to_css_class("valid") == css_class_for_severity(
        ValidationSeverity.OK
    )
    assert status_to_css_class("gap") == css_class_for_severity(
        ValidationSeverity.NEUTRAL
    )


def test_tc041_11_markup_safe_render_of_hostile_text() -> None:
    """File-derived text with markup / ANSI renders literally (LLR-041.11).

    Intent: the panel renders with markup enabled to colour cells, so a
    loaded A2L/MAC symbol like ``sensor[red]`` or ``x[link=file:///]`` — or a
    raw ANSI escape byte — must be treated as literal text, never parsed as
    Rich markup. Otherwise it corrupts the render, injects styling, or raises
    ``MarkupError`` and crashes the Memory Map on load (security B-1 / F2).
    """
    from rich.console import Console

    from s19_app.tui.screens_directionb import safe_text

    hostile = "sensor[red]value[/]\x1b[31mANSI\x1b[0m"
    text = safe_text(hostile)

    # The literal string is preserved verbatim — brackets and ANSI as text.
    assert text.plain == hostile

    # Rendering never raises MarkupError and never emits a real SGR sequence
    # from the file-derived content (the ANSI byte is literal, not active).
    console = Console(color_system=None, width=120)
    with console.capture() as capture:
        console.print(text)
    rendered = capture.get()
    assert "sensor[red]" in rendered, "brackets must survive as literal text"
    assert "[/]" in rendered, "closing-tag markup must survive as literal text"


def test_at035_map_shows_band_bar_and_summary_header(tmp_path: Path) -> None:
    """Black-box: the map shows an entropy band bar with ≥2 distinct band
    colours + a band-summary header (AT-035, REWORKED batch-45 R-TUI-060).

    Superseded form: batch-27 asserted a ``sev-*`` cell grid + "≈ KiB/cell"
    header. Batch-45 replaces the grid RENDER with the entropy band view, so
    this proof now observes the band bar (``#map_band_bar`` with ≥2 distinct
    ``band-*`` segment classes over a two-band image) and the band-summary
    header (no longer the neutral no-file note). Region-row band/glyph/label
    coverage is AT-069/070/071's job; this proves the bar + header surface.
    """
    from s19_app.tui.screens_directionb import MemoryMapPanel

    loaded = _two_band_loaded(tmp_path)

    async def _drive() -> "tuple[list, str]":
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.current_file = loaded
            app.action_show_screen("map")
            app.update_memory_map()
            await pilot.pause()
            bar = app.query_one(".map-band-bar")
            seg_classes = [tuple(seg.classes) for seg in bar.query(".map-band-seg")]
            panel = app.query_one("#memory_map_panel", MemoryMapPanel)
            return seg_classes, panel.rendered_text

    seg_classes, header = asyncio.run(_drive())
    assert seg_classes, "the band bar must mount ≥1 segment for a loaded image"
    band_tokens = {
        cls for classes in seg_classes for cls in classes if cls.startswith("band-")
    }
    assert len(band_tokens) >= 2, (
        f"a two-band image must colour ≥2 distinct band segments; got {band_tokens}"
    )
    assert header != MemoryMapPanel._EMPTY_TEXT and header.strip(), (
        f"the header must show a band summary, not the empty note; got {header!r}"
    )


# ---------------------------------------------------------------------------
# batch-27 Increment 2 (US-036) — cell selection → detail pane, cell-scoped
# issue join, and Open-in-Hex jump.
#
# TC-041.4/.5/.6 are the white-box unit contracts; AT-036a..g are the
# black-box Pilot proofs over the shipped `#screen_map` surface.
# ---------------------------------------------------------------------------


# RETIRED batch-45 Inc-5: the ``_mounted_map_panel`` / ``_first_cell_with_status``
# / ``_cell_containing`` / ``_invalid_range_start`` helpers served only the
# retired MapCell grid tests (removed Inc-2..5); deleted with the MapCell class.


def test_tc041_4_build_detail_text_content(tmp_path: Path) -> None:
    """The detail assembler emits chip, window, region and issue lines
    (TC-041.4 / LLR-041.4).

    Intent: given a selected cell over an INVALID range plus one in-cell
    seeded issue, ``build_detail_text`` must produce the status chip, the
    ``0x..-0x..`` window, the covering-region bounds/size/status, the issue
    ``code``+address line, and the "N issue(s)" cell + region counts. If the
    assembler drops any of these, the detail pane is incomplete.
    """
    from s19_app.tui.screens_directionb import MemoryMapPanel
    from s19_app.validation.model import ValidationIssue, ValidationSeverity

    panel = MemoryMapPanel()
    # Directly seed the stored state the assembler reads (pure-function test).
    panel._ordered_ranges = [(0x100, 0x200, False)]
    panel._issues = [
        ValidationIssue(
            code="S19_RECORD_CHECKSUM",
            severity=ValidationSeverity.ERROR,
            message="bad record checksum",
            artifact="s19",
            address=0x110,
        )
    ]
    text = panel.build_detail_text(0x100, 0x140, "invalid").plain

    assert "INVALID" in text, f"status chip missing; got {text!r}"
    assert "0x00000100-0x0000013F" in text, f"cell window missing; got {text!r}"
    assert "0x00000100-0x000001FF" in text, f"region bounds missing; got {text!r}"
    assert "256 bytes" in text, f"region size missing; got {text!r}"
    assert "S19_RECORD_CHECKSUM" in text, f"issue code missing; got {text!r}"
    assert "0x00000110" in text, f"issue address missing; got {text!r}"
    assert "1 issue(s) in this cell" in text, f"cell count missing; got {text!r}"
    assert "1 issue(s) in region" in text, f"region count missing; got {text!r}"


def test_symbols_in_window_matching_point_and_hostile_shapes() -> None:
    """``symbols_in_window`` joins A2L tags to a window by extent overlap,
    address-then-name sorted, and is hostile-shape-safe (R-TUI-041 R-3).

    Intent: the join is the pure core both the detail-pane naming and the
    per-cell tooltip bind to — a tag overlaps ``[start, end)`` iff
    ``addr < end and addr + size > start`` (``size = byte_size>0 else 1``),
    and any malformed tag (non-dict, None/str/bool address, empty name) is
    skipped, never raised (S-F4).
    """
    from s19_app.tui.screens_directionb import symbols_in_window

    tags = [
        {"name": "B", "address": 0x120, "byte_size": 4},   # inside
        {"name": "A", "address": 0x100, "byte_size": 4},   # inside, earlier addr
        {"name": "POINT", "address": 0x130},               # no byte_size -> point
        {"name": "OUT", "address": 0x200, "byte_size": 4}, # outside [0x100,0x140)
        {"name": "EDGE", "address": 0x13F, "byte_size": 1},# last byte inside
        "not-a-dict",                                      # skipped
        {"name": "NOADDR", "address": None},               # None addr skipped
        {"name": "STRADDR", "address": "0x110"},           # non-int addr skipped
        {"name": "", "address": 0x105},                    # empty name skipped
        {"name": "BOOLADDR", "address": True},             # bool addr skipped
    ]
    # address-then-name sorted, overlap-only
    assert symbols_in_window(tags, 0x100, 0x140) == ["A", "B", "POINT", "EDGE"]
    # a window entirely before the first extent matches nothing
    assert symbols_in_window(tags, 0x00, 0x100) == []


def test_at_r3_detail_region_named_by_a2l_symbols() -> None:
    """R-TUI-041 R-3 (AC-1): the detail-pane region line names the covering
    region by the overlapping A2L symbol(s), address-sorted, capped at 3 with a
    ``+N more`` tail, alongside the bounds.

    RED pre-fix: the region line is bounds-only and never contains a symbol
    name (``symbols_in_window`` / the region-naming append do not exist).
    """
    from s19_app.tui.screens_directionb import MemoryMapPanel

    panel = MemoryMapPanel()
    panel._ordered_ranges = [(0x8000, 0x9000, True)]
    panel._issues = []
    panel._a2l_tags = [
        {"name": "CAL_KI", "address": 0x8100, "byte_size": 4},
        {"name": "CAL_KP", "address": 0x8010, "byte_size": 4},
        {"name": "CAL_KD", "address": 0x8080, "byte_size": 4},
        {"name": "CAL_X4", "address": 0x8200, "byte_size": 4},  # 4th -> "+1 more"
        {"name": "OTHER", "address": 0x9500, "byte_size": 4},   # outside region
    ]
    text = panel.build_detail_text(0x8000, 0x8100, "valid").plain

    assert "CAL_KP" in text and "CAL_KD" in text and "CAL_KI" in text
    assert "+1 more" in text, f"cap/overflow missing; got {text!r}"
    assert "CAL_X4" not in text, "the 4th symbol must be behind '+N more'"
    assert "OTHER" not in text, "an out-of-region symbol must not appear"
    assert "0x00008000-0x00008FFF" in text, "region bounds must still show"


def test_at_r3_detail_hostile_symbol_name_rendered_literally() -> None:
    """R-TUI-041 R-3 (AC-3, detail): a hostile A2L symbol name renders LITERALLY
    in the region line — no Rich-markup injection, no ``MarkupError`` (the
    batch-27 Phase-2 BLOCKER class; markup-safe via ``safe_text`` / ``Text``).
    """
    from s19_app.tui.screens_directionb import MemoryMapPanel

    panel = MemoryMapPanel()
    panel._ordered_ranges = [(0x8000, 0x9000, True)]
    panel._issues = []
    for hostile in ("evil[red]", "x[/]", "y[bold", "z[link=file:///etc/passwd]"):
        panel._a2l_tags = [{"name": hostile, "address": 0x8010, "byte_size": 4}]
        text = panel.build_detail_text(0x8000, 0x8100, "valid").plain
        assert hostile in text, f"hostile name not rendered literally; got {text!r}"


def test_at_r3_detail_no_a2l_region_bounds_only() -> None:
    """R-TUI-041 R-3 (AC-4): with no A2L tags the region line is the unchanged
    bounds-only form — no symbol suffix, no regression to the R-TUI-041 detail.
    """
    from s19_app.tui.screens_directionb import MemoryMapPanel

    panel = MemoryMapPanel()
    panel._ordered_ranges = [(0x8000, 0x9000, True)]
    panel._issues = []
    panel._a2l_tags = []
    text = panel.build_detail_text(0x8000, 0x8100, "valid").plain
    region_line = next(
        ln for ln in text.splitlines() if ln.startswith("Region:")
    )
    assert region_line == "Region: 0x00008000-0x00008FFF (4096 bytes, valid)", (
        f"region line should be bounds-only; got {region_line!r}"
    )


# RETIRED batch-45 (R-TUI-060): ``test_at_r3_cell_tooltip_names_symbols_and_
# renders_literally`` tested the per-CELL A2L hover tooltip. The entropy band
# view removes the cell surface (region-list rows are addr/size/band-only, no
# A2L text — security B3), so the tooltip sink no longer exists. The security
# F1 markup-safety guard on the RETAINED ``safe_text`` path stays covered by the
# surviving pure-function test ``test_at_r3_detail_hostile_symbol_name_rendered_
# literally`` (build_detail_text, re-wired to region-row selection in Inc-3).


# RETIRED batch-45 Inc-5: ``test_tc041_4b_arrow_adjacent_index_and_edge_clamp``
# tested ``adjacent_cell_index`` (the MapCell arrow-nav math), removed with the
# grid. Region→hex nav is single-click (AT-074); no keyboard grid traversal.


def test_tc041_5_cell_issue_join_boundary_and_negative() -> None:
    """Cell→issue join: in-window in, ``end`` excluded, ``None`` excluded
    (TC-041.5 / LLR-041.5).

    Intent: the half-open ``[start, end)`` join is the contract the detail
    pane and the region count both bind to — an issue at exactly ``end`` must
    NOT match (it belongs to the next cell), and an ``address is None`` issue
    can never be spatially anchored (locks the R-1 default).
    """
    from s19_app.tui.screens_directionb import issues_in_window
    from s19_app.validation.model import ValidationIssue, ValidationSeverity

    def _issue(addr: "object") -> ValidationIssue:
        return ValidationIssue(
            code="C",
            severity=ValidationSeverity.ERROR,
            message="m",
            artifact="s19",
            address=addr,
        )

    at_start = _issue(0)
    inside = _issue(8)
    at_end = _issue(16)  # exclusive end → excluded
    addressless = _issue(None)  # cannot be anchored → excluded

    hits = issues_in_window(
        [at_start, inside, at_end, addressless], 0, 16
    )
    codes_addrs = [i.address for i in hits]
    assert codes_addrs == [0, 8], (
        f"in-window included, end + None excluded; got {codes_addrs}"
    )


def test_tc041_6_region_activation_focus_equals_region_start(
    tmp_path: Path,
) -> None:
    """A region activation posts a focus address equal to the region start
    (TC-041.6, REWORKED batch-45 R-TUI-062 — was cell_start, now region_start).

    Intent (white-box): the ``OpenInHexRequested`` the panel posts on a region
    click carries EXACTLY the run's ``region_start`` — no off-by-one, no
    row-base rounding on the panel side (the app handler owns the focus math /
    the nearest-present-row snap). Complements AT-074's behavioral hex-render.
    """
    from s19_app.tui.screens_directionb import (
        MemoryMapPanel,
        RegionRow,
    )

    loaded = _two_band_loaded(tmp_path)

    async def _drive() -> "tuple[list, int]":
        app = S19TuiApp(base_dir=tmp_path)
        posted: list[int] = []
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.current_file = loaded
            app.action_show_screen("map")
            app.update_memory_map()
            await pilot.pause()
            panel = app.query_one("#memory_map_panel", MemoryMapPanel)
            row = next(
                r for r in app.query(RegionRow) if "high/random" in _widget_plain(r)
            )
            orig_post = panel.post_message

            def _cap(msg: "object") -> bool:
                if isinstance(msg, MemoryMapPanel.OpenInHexRequested):
                    posted.append(msg.focus_address)
                return orig_post(msg)

            panel.post_message = _cap  # type: ignore[method-assign]
            panel.on_region_row_activated(
                RegionRow.Activated(row.region_start, row.region_end)
            )
            return posted, row.region_start

    posted, region_start = asyncio.run(_drive())
    assert posted == [region_start], (
        f"region activation must post exactly OpenInHexRequested(region_start); "
        f"posted={posted} region_start={region_start}"
    )


# RETIRED batch-45 (R-TUI-060, PLAN R2 "arrow-nav ATs superseded"): the entropy
# band view removes the ``MapCell`` grid + its keyboard focus-order, so the
# following three cell-surface ATs no longer have a surface to drive and are
# retired (MapCell + arrow-nav helpers stay DEFINED as dead code until Inc-5):
#   - ``test_at036a_non_default_cell_changes_detail`` (arrow-nav + select→detail):
#     the detail-changes-on-selection behavior is covered by the surviving pure
#     ``build_detail_text`` tests (test_tc041_4 / test_at_r3_detail_no_a2l), and
#     region-row→detail selection is Inc-3's single-click nav.
#   - ``test_at036_detail_hint_prompts_navigation_before_selection``: the hint
#     prompted arrow-key nav, which is removed; Inc-3 owns region-row selection
#     discoverability.
#   - ``test_at036_arrow_moves_cell_focus_without_scrolling``: arrow-key grid
#     focus scoping — the grid is gone.


def test_at036b_region_click_reveals_hex_at_region_start(tmp_path: Path) -> None:
    """Black-box: a region click switches to the hex view focused on the region
    (AT-036b, REWORKED batch-45 R-TUI-062 — was cell, now region).

    Intent: a single REAL ``pilot.click`` on the CONSTANT region row (start
    ``0x80000000``) must reveal the Workspace/hex screen AND render the hex row
    containing that start in ``#hex_view`` — the C-10 non-default counterpart to
    AT-074 (which clicks the HIGH region), proving the clicked region's start
    (not a fixed address) drives the focus. Confirms ``update_hex_view`` ran
    through the shipped surface (NOT a mock assertion — TC-041.6's job).
    """
    loaded = _two_band_loaded(tmp_path)

    async def _drive() -> "tuple[bool, str, int]":
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.current_file = loaded
            app.action_show_screen("map")
            app.update_memory_map()
            await pilot.pause()
            row = await _click_region_row(
                pilot, app, lambda r: "constant/padding" in _widget_plain(r)
            )
            ws_visible = "hidden" not in app.query_one("#screen_workspace").classes
            hex_str = str(app.query_one("#hex_view").render())
            return ws_visible, hex_str, row.region_start

    ws_visible, hex_str, start = asyncio.run(_drive())
    assert ws_visible, "a region click must reveal the Workspace/hex screen"
    row_token = f"{start - (start % 16):08X}"
    assert row_token in hex_str.upper(), (
        f"the hex row containing 0x{start:08X} must render; "
        f"expected row base {row_token} in the hex view"
    )


# RETIRED batch-45 (R-TUI-060): the cell-selection→detail black-box variants
# ``test_at036c`` (valid chip + region) and ``test_at036d`` (invalid chip +
# code + addr + counts) drove the removed ``MapCell`` surface. Their detail
# ASSEMBLY behavior is retained and still covered by the SURVIVING pure-function
# tests over ``build_detail_text`` (kept live, C-17): ``test_at_r3_detail_no_a2l_
# region_bounds_only`` (VALID chip + region bounds/size) and ``test_tc041_4_
# build_detail_text_content`` (INVALID chip + issue code + address + cell/region
# counts). ``test_at036g`` (addressless issue excluded) is covered by
# ``test_tc041_5_cell_issue_join_boundary_and_negative`` (the ``address is None``
# exclusion) plus ``test_tc041_4`` (the count lines). AT-036e/f are NOT covered
# by a survivor and so are REWORKED below into pure ``build_detail_text`` tests
# rather than retired.


def test_tc041_4c_gap_cell_detail_no_region(tmp_path: Path) -> None:
    """The detail assembler reports an uncovered gap with no region
    (REWORKED from AT-036e → pure ``build_detail_text``, LLR-041.4).

    Intent: for a cell that lies outside every stored range, the detail must
    show the GAP/uncovered chip and must NOT claim a covering region — the
    region-None branch of ``build_detail_text``, which no surviving test
    exercises. Reworked (not retired) because the entropy band view removes the
    gap-cell surface but the assembler branch stays reachable via Inc-3
    region-row selection.
    """
    from s19_app.tui.screens_directionb import MemoryMapPanel

    panel = MemoryMapPanel()
    panel._ordered_ranges = [(0x8000, 0x9000, True)]  # a gap cell sits outside
    panel._issues = []
    text = panel.build_detail_text(0x100, 0x140, "gap").plain

    assert "GAP" in text.upper() or "UNCOVERED" in text.upper(), (
        f"gap chip missing; got {text!r}"
    )
    assert "gap - no region" in text, f"gap must not claim a region; got {text!r}"


def test_tc041_4d_hostile_issue_symbol_rendered_literally(tmp_path: Path) -> None:
    """A hostile issue ``symbol`` renders literally in the detail
    (REWORKED from AT-036f → pure ``build_detail_text``, LLR-041.11 / B-1).

    Intent: a loaded ``ValidationIssue.symbol`` like ``sensor[red]`` reaches
    the detail pane through ``safe_text`` and must render with its brackets
    literal — never parsed as Rich markup (no injection, no ``MarkupError``).
    Reworked (not retired) so the issue-``symbol`` markup-safety sink stays
    guarded; complements ``test_at_r3_detail_hostile...`` (the A2L-name sink).
    """
    from s19_app.tui.screens_directionb import MemoryMapPanel
    from s19_app.validation.model import ValidationIssue, ValidationSeverity

    panel = MemoryMapPanel()
    panel._ordered_ranges = [(0x100, 0x200, False)]
    panel._issues = [
        ValidationIssue(
            code="X",
            severity=ValidationSeverity.ERROR,
            message="m",
            artifact="s19",
            symbol="sensor[red]",
            address=0x110,
        )
    ]
    text = panel.build_detail_text(0x100, 0x140, "invalid").plain
    assert "sensor[red]" in text, (
        f"the hostile symbol must render literally (brackets present); "
        f"got {text!r}"
    )


# ---------------------------------------------------------------------------
# batch-27 Increment 3 (US-037) — coverage stats strip + two-regime reflow.
#
# TC-041.8 hand-computes the EXACT case_02 coverage literals; TC-041.9 locks
# the empty-state strip; TC-041.10 asserts the width-narrow reflow class per
# regime; AT-037 is the black-box Pilot proof over `#map_stats`.
# ---------------------------------------------------------------------------

# The public ``case_02`` image's ranges are four disjoint spans over a ~2 GiB
# address window. Its EXACT coverage arithmetic (verified against the built
# LoadedFile): span 0x0..0x80010140 = 2_147_549_504 bytes; covered = 11 + 34 +
# 16 + 32 = 93 bytes; 3 gaps (2_147_549_173 / 94 / 144), largest 2_147_549_173;
# all four ranges valid → 0 invalid; coverage = 93 / 2_147_549_504 * 100.
_CASE_02_IMAGE_SPAN = 0x80010140
_CASE_02_COVERED_BYTES = 93
_CASE_02_GAP_COUNT = 3
_CASE_02_LARGEST_GAP = 2_147_549_173
_CASE_02_VALID_COUNT = 4
_CASE_02_INVALID_COUNT = 0
_CASE_02_COVERAGE_PCT = _CASE_02_COVERED_BYTES / _CASE_02_IMAGE_SPAN * 100


def test_tc041_8_coverage_stats_exact_case_02_literals() -> None:
    """Coverage stats equal the hand-computed case_02 literals (TC-041.8 /
    LLR-041.8).

    Intent: the strip's numbers are pure arithmetic on the parsed ranges, so
    every metric must equal an EXACT hand-computed literal (NOT ``> 0``) — a
    coverage-math regression (double-count, off-by-one gap, wrong span) fails
    a specific number, not just a sign check. Coverage % is strictly < 100.
    """
    from s19_app.core import S19File
    from s19_app.tui.screens_directionb import coverage_stats
    from s19_app.tui.services.load_service import build_loaded_s19

    s19 = S19File(str(_CASE_02_S19))
    loaded = build_loaded_s19(_CASE_02_S19, s19, a2l_path=None, a2l_data=None)

    stats = coverage_stats(loaded.ranges, loaded.range_validity, [])

    assert stats.image_span == _CASE_02_IMAGE_SPAN, "span literal"
    assert stats.covered_bytes == _CASE_02_COVERED_BYTES, "covered bytes literal"
    assert stats.gap_count == _CASE_02_GAP_COUNT, "gap count literal"
    assert stats.largest_gap == _CASE_02_LARGEST_GAP, "largest gap literal"
    assert stats.valid_count == _CASE_02_VALID_COUNT, "valid count literal"
    assert stats.invalid_count == _CASE_02_INVALID_COUNT, "invalid count literal"
    assert stats.coverage_pct == _CASE_02_COVERAGE_PCT, "coverage %% literal"
    assert stats.coverage_pct < 100, "case_02 is far from fully covered"
    assert stats.total_issues == 0, "no issues handed in → zero"


def test_tc041_8_single_range_full_coverage_no_gaps() -> None:
    """Boundary: a single range → 100%% coverage, 0 gaps, 0 largest-gap
    (TC-041.8 boundary).

    Intent: the QC-3 boundary row — one contiguous range with no holes must
    report exactly 100%%, gap count 0 and largest gap 0, and route validity
    into the valid count.
    """
    from s19_app.tui.screens_directionb import coverage_stats

    stats = coverage_stats([(0x100, 0x200)], [True], [])
    assert stats.coverage_pct == 100.0
    assert stats.gap_count == 0
    assert stats.largest_gap == 0
    assert stats.covered_bytes == 0x100
    assert stats.valid_count == 1 and stats.invalid_count == 0


def test_tc041_9_empty_state_stats_neutral_no_exception(tmp_path: Path) -> None:
    """No file → the stats strip is neutral/blank, no divide-by-zero
    (TC-041.9 / LLR-041.9).

    Intent: with ``ranges`` empty the coverage-% guard must not divide, the
    stats value object is all-zero, and the rendered ``#map_stats_body`` shows
    no coverage numbers — the empty state is preserved.
    """
    from s19_app.tui.screens_directionb import coverage_stats

    # Pure guard: no ranges → all-zero stats, no exception, no ratio.
    stats = coverage_stats([], [], [])
    assert stats.image_span == 0
    assert stats.coverage_pct == 0.0
    assert stats.covered_bytes == 0
    assert stats.gap_count == 0

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("map")
            app.update_memory_map()  # no current_file → empty path
            await pilot.pause()
            return str(app.query_one("#map_stats_body").render())

    strip = asyncio.run(_drive())
    assert "Coverage:" not in strip, (
        f"the no-file stats strip must be neutral/blank; got {strip!r}"
    )


def test_tc041_10_reflow_class_toggles_at_119_vs_120(tmp_path: Path) -> None:
    """The map reflow follows the width-narrow class at 119 vs 120
    (TC-041.10 / LLR-041.10).

    Intent: the two-regime reflow reuses the EXISTING ``width-narrow`` class
    (no new breakpoint). At width >= 120 the class is absent (wide: detail
    beside grid); at < 120 it is present (narrow: detail stacked below). Assert
    the class per regime AND that both `#map_grid` and `#map_detail` are present
    in both regimes with a positive-width, non-clipping layout.
    """
    from s19_app.tui.screens_directionb import MemoryMapPanel

    async def _regime(width: int) -> dict[str, object]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(width, 30)) as pilot:
            await pilot.pause()
            _install_case_02_loaded_file(app)
            app.action_show_screen("map")
            app.update_memory_map()
            await pilot.pause()
            body = app.query_one("#workspace_body")
            grid = app.query_one("#map_grid")
            detail = app.query_one("#map_detail")
            panel = app.query_one("#memory_map_panel", MemoryMapPanel)
            return {
                "narrow": body.has_class("width-narrow"),
                "grid_w": grid.size.width,
                "detail_w": detail.size.width,
                "grid_x": grid.region.x,
                "detail_x": detail.region.x,
                "detail_y": detail.region.y,
                "grid_y": grid.region.y,
                "panel_w": panel.size.width,
            }

    wide = asyncio.run(_regime(120))
    narrow_100 = asyncio.run(_regime(100))
    narrow_80 = asyncio.run(_regime(80))

    # Wide (>= 120): fixed regime, detail BESIDE the grid (same row, to its
    # right) — a horizontal split, both panes positive width (C-13 budget).
    assert wide["narrow"] is False, "at 120 the fixed (wide) regime is active"
    assert wide["grid_w"] > 0 and wide["detail_w"] > 0, (
        f"both map panes must have positive width at 120; got {wide!r}"
    )
    assert wide["detail_x"] > wide["grid_x"], (
        f"wide regime: detail must sit to the RIGHT of the grid; got {wide!r}"
    )
    assert wide["detail_y"] == wide["grid_y"], (
        f"wide regime: detail must be on the SAME row as the grid; got {wide!r}"
    )

    # Narrow (< 120): proportional regime, detail STACKED BELOW the grid.
    for narrow in (narrow_100, narrow_80):
        assert narrow["narrow"] is True, (
            f"below 120 the proportional (narrow) regime is active; got {narrow!r}"
        )
        assert narrow["grid_w"] > 0 and narrow["detail_w"] > 0, (
            f"both map panes must have positive width when narrow; got {narrow!r}"
        )
        assert narrow["detail_y"] > narrow["grid_y"], (
            f"narrow regime: detail must stack BELOW the grid; got {narrow!r}"
        )


# RETIRED batch-45 (R-TUI-060): ``test_carry_f2_fixed_cell_count_at_120x30``
# pinned the live ``MapCell`` count against grid geometry. The entropy band view
# renders no cell grid (region rows are proportional to merged runs, not to a
# geometry-derived cell count), so the invariant no longer exists. Snapshot
# drift of the two map cells is covered by ``_batch45_map_drift_marks`` in
# ``tests/test_tui_snapshot.py`` (xfail-until canonical-CI regen).


def test_at037_stats_strip_matches_case_02_coverage(tmp_path: Path) -> None:
    """Black-box: the `#map_stats` strip shows the seven case_02 metrics
    (AT-037 / US-037).

    Intent: load case_02, show the map, read `#map_stats`, and assert each of
    the seven metric labels is present with its value — the coverage %% equals
    TC-041.8's hand-computed number, and the total-issue count equals
    ``len(app._validation_issues)`` (the single canonical source).
    """

    async def _drive() -> tuple[str, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _install_case_02_loaded_file(app)
            app.action_show_screen("map")
            app.update_memory_map()
            await pilot.pause()
            strip = str(app.query_one("#map_stats_body").render())
            return strip, len(app._validation_issues)

    strip, issue_count = asyncio.run(_drive())

    # All seven labels present.
    for label in (
        "Coverage:",
        "Bytes covered:",
        "Valid ranges:",
        "Invalid ranges:",
        "Gaps:",
        "Largest gap:",
        "Total issues:",
    ):
        assert label in strip, f"stats label {label!r} missing; got {strip!r}"

    # Values match the hand-computed case_02 literals. batch-40 S3: the strip
    # renders coverage to a clean 2 decimals (was an ugly .6f), matching the
    # A-view (app.build_workspace_stats_text). AC-3.1: .2f present, no 6-dec tail.
    assert f"Coverage: {_CASE_02_COVERAGE_PCT:.2f}%" in strip, (
        f"coverage %% must render at .2f (TC-041.8's number); got {strip!r}"
    )
    assert f"{_CASE_02_COVERAGE_PCT:.6f}%" not in strip, (
        f"coverage %% must NOT render the 6-decimal form; got {strip!r}"
    )
    assert f"Bytes covered: {_CASE_02_COVERED_BYTES}" in strip
    assert f"Valid ranges: {_CASE_02_VALID_COUNT}" in strip
    assert f"Invalid ranges: {_CASE_02_INVALID_COUNT}" in strip
    assert f"Gaps: {_CASE_02_GAP_COUNT}" in strip
    assert f"Largest gap: {_CASE_02_LARGEST_GAP} bytes" in strip
    # Total issues == the single canonical source len(_validation_issues).
    assert f"Total issues: {issue_count}" in strip, (
        f"total issues must equal len(_validation_issues)={issue_count}; "
        f"got {strip!r}"
    )


# ---------------------------------------------------------------------------
# batch-45 Inc-2 (R-TUI-060, US-045a / LLR-045A.2..045A.6) — the Memory Map's
# validation cell-grid RENDER is REPLACED by an ENTROPY band view: a
# proportional band bar + a per-region list (address · size · band) + a band
# legend, driven by loader-computed ``LoadedFile.entropy_windows``. AT-069/070/
# 071 are the black-box proofs over the shipped ``#screen_map`` surface.
# ---------------------------------------------------------------------------


def _two_band_loaded(tmp_path: Path) -> "LoadedFile":
    """Build a two-band ``LoadedFile`` through the real load pipeline.

    Two NON-ADJACENT 256-byte blocks (an address gap keeps them separate
    derived ranges): a ``0xFF``-fill block (Shannon ``H == 0.0`` →
    ``constant/padding``) and a seeded-shuffle permutation of ``0..255`` (each
    byte value once → ``H == 8.0`` → ``high/random``). Emitted to S19, parsed,
    and built via ``build_loaded_s19`` so entropy is LOADER-computed exactly as
    the app sees it. Asserts IN-TEST (via ``compute_entropy``) that BOTH bands
    are present before any render assertion depends on them.
    """
    import random

    from s19_app.core import S19File
    from s19_app.tui.changes import emit_s19_from_mem_map
    from s19_app.tui.services.entropy_service import compute_entropy
    from s19_app.tui.services.load_service import build_loaded_s19

    const_base = 0x80000000
    high_base = 0x80010000  # 0x10000 gap → a distinct second range (no merge)
    mem_map: dict[int, int] = {const_base + i: 0xFF for i in range(256)}
    values = list(range(256))
    random.Random(20260714).shuffle(values)
    for i, value in enumerate(values):
        mem_map[high_base + i] = value
    ranges = [(const_base, const_base + 256), (high_base, high_base + 256)]

    bands = {w.band for w in compute_entropy(mem_map)}
    assert {"constant/padding", "high/random"} <= bands, (
        f"fixture must expose both a constant and a high band; got {bands}"
    )

    path = tmp_path / "two_band.s19"
    path.write_text(emit_s19_from_mem_map(mem_map, ranges), encoding="ascii")
    return build_loaded_s19(
        path, S19File(str(path)), a2l_path=None, a2l_data=None
    )


def _widget_plain(widget: "object") -> str:
    """Return the plain text of a ``Static``-like widget's rendered content."""
    return str(widget.render())


def _region_rows(app: "S19TuiApp") -> "list":
    """Return the mounted band-view region-list rows on the map screen."""
    return list(app.query(".map-region-row"))


async def _click_region_row(pilot: "object", app: "S19TuiApp", match) -> "object":
    """Scroll the first ``RegionRow`` matching ``match`` into view and REAL-click it.

    A single genuine ``pilot.click`` on the widget instance (C-16 real pointer,
    precedent: ``test_tui_patch_editor_v2.py`` scroll-then-``pilot.click`` and
    ``test_tui_variants.py::test_at067a`` — NOT the retired cell path). Returns
    the clicked row so the caller can read its ``region_start``.
    """
    from s19_app.tui.screens_directionb import RegionRow

    target = next(r for r in app.query(RegionRow) if match(r))
    target.scroll_visible(animate=False)
    await pilot.pause()
    await pilot.click(target)
    await pilot.pause()
    await pilot.pause()
    return target


def _expected_band_runs(loaded: "LoadedFile") -> "list":
    """Merge address-contiguous same-band windows into ``(band, bytes, start)``.

    The test's own oracle — computed inline from ``compute_entropy``, using an
    INDEPENDENT contiguity formulation from the production ``_merge_band_runs``:
    it tracks each open run's expected next address explicitly and breaks the
    run when the band changes OR the next window is not adjacent to it (review
    F1). Returns ``(band, summed_bytes, start)`` triples.
    """
    from s19_app.tui.services.entropy_service import compute_entropy

    runs: "list" = []
    open_band: "object" = None
    open_next_addr: "object" = None
    for window in compute_entropy(loaded.mem_map):
        adjacent = window.start == open_next_addr
        if runs and window.band == open_band and adjacent:
            band, total, start = runs[-1]
            runs[-1] = (band, total + window.sample_count, start)
        else:
            runs.append((window.band, window.sample_count, window.start))
            open_band = window.band
        open_next_addr = window.end
    return runs


def test_at069_high_region_renders_high_band(tmp_path: Path) -> None:
    """Black-box: the region row over the high-entropy block carries the
    high band's glyph, class and label (AT-069 / LLR-045A.2/.3/.4).

    RED pre-impl: the map renders a uniform ``sev-*`` cell grid — there is no
    ``.map-region-row`` widget, so no ``band-high``/``▓``/``high/random`` row
    exists.
    """
    loaded = _two_band_loaded(tmp_path)

    async def _drive() -> "tuple[bool, str]":
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.current_file = loaded
            app.action_show_screen("map")
            app.update_memory_map()
            await pilot.pause()
            for row in _region_rows(app):
                text = _widget_plain(row)
                if "high/random" in text:
                    return "band-high" in row.classes, text
            return False, ""

    has_class, text = asyncio.run(_drive())
    assert has_class, "the high region row must carry the band-high class"
    assert "▓" in text, f"the high region row must carry the ▓ glyph; got {text!r}"
    assert "high/random" in text, f"high band label missing; got {text!r}"


def test_at070_constant_vs_high_bands_differ(tmp_path: Path) -> None:
    """Black-box: the constant and high region rows differ in BOTH glyph and
    band class (AT-070 / LLR-045A.3, C-10 two-branch — reads both rows).

    RED pre-impl: no ``.map-region-row`` widgets exist, so neither branch is
    readable.
    """
    loaded = _two_band_loaded(tmp_path)

    async def _drive() -> "tuple[str, tuple, str, tuple]":
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.current_file = loaded
            app.action_show_screen("map")
            app.update_memory_map()
            await pilot.pause()
            const_text = const_classes = high_text = high_classes = None
            for row in _region_rows(app):
                text = _widget_plain(row)
                if "constant/padding" in text:
                    const_text, const_classes = text, tuple(row.classes)
                elif "high/random" in text:
                    high_text, high_classes = text, tuple(row.classes)
            return const_text, const_classes, high_text, high_classes

    const_text, const_classes, high_text, high_classes = asyncio.run(_drive())
    assert const_text is not None, "a constant-band region row must render"
    assert high_text is not None, "a high-band region row must render"
    # Glyph differs: ▓ marks high only; · marks the constant row's glyph.
    assert "▓" in high_text and "▓" not in const_text, (
        f"the high/constant glyphs must differ; const={const_text!r} "
        f"high={high_text!r}"
    )
    # Class differs: band-high vs band-constant.
    assert "band-high" in high_classes and "band-constant" in const_classes, (
        f"the band classes must differ; const={const_classes} high={high_classes}"
    )
    assert set(high_classes) != set(const_classes), "band classes must differ"


def test_at071_region_list_rows_addr_size_band(tmp_path: Path) -> None:
    """Black-box: one region row per merged run, each showing its address,
    size and band (AT-071 / LLR-045A.4).

    RED pre-impl: the grid mounts ``.map-cell`` widgets, not ``.map-region-row``
    rows, so the row count is 0 (not the merged-run count).
    """
    loaded = _two_band_loaded(tmp_path)
    runs = _expected_band_runs(loaded)

    async def _drive() -> "list":
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.current_file = loaded
            app.action_show_screen("map")
            app.update_memory_map()
            await pilot.pause()
            return [_widget_plain(row) for row in _region_rows(app)]

    texts = asyncio.run(_drive())
    assert len(texts) == len(runs), (
        f"one region row per merged run expected {len(runs)}; got {len(texts)}"
    )
    # A specific run's row must carry its address, size (bytes) and band.
    band, run_bytes, start = next(r for r in runs if r[0] == "high/random")
    row_text = next(t for t in texts if "high/random" in t)
    assert f"0x{start:08X}" in row_text, f"row start address missing; got {row_text!r}"
    assert f"{run_bytes} B" in row_text, f"row size missing; got {row_text!r}"
    assert band in row_text, f"row band label missing; got {row_text!r}"


def test_at071b_disjoint_same_band_regions_stay_separate(tmp_path: Path) -> None:
    """Two physically separate SAME-band blocks render as TWO region rows, not
    one merged span (AT-071b / LLR-045A.4, review F1).

    ``compute_entropy`` walks per-contiguous-range, so two 0xFF-fill padding
    blocks across an address gap sit back-to-back in the window list with the
    SAME band. A band-only merge would collapse them into one row showing a
    single contiguous span + summed size that crosses the gap. The merge must
    also break on an address discontinuity, so each block keeps its own row.
    """
    from s19_app.core import S19File
    from s19_app.tui.changes import emit_s19_from_mem_map
    from s19_app.tui.services.entropy_service import compute_entropy
    from s19_app.tui.services.load_service import build_loaded_s19

    block_a = 0x80000000
    block_b = 0x80020000  # gap → a distinct second range, same 0xFF band
    mem_map = {block_a + i: 0xFF for i in range(256)}
    mem_map.update({block_b + i: 0xFF for i in range(256)})
    ranges = [(block_a, block_a + 256), (block_b, block_b + 256)]
    # Precondition: both blocks are the SAME band (so only contiguity separates).
    bands = [w.band for w in compute_entropy(mem_map)]
    assert bands == ["constant/padding", "constant/padding"], bands

    path = tmp_path / "two_pad.s19"
    path.write_text(emit_s19_from_mem_map(mem_map, ranges), encoding="ascii")
    loaded = build_loaded_s19(path, S19File(str(path)), a2l_path=None, a2l_data=None)

    async def _drive() -> "list":
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.current_file = loaded
            app.action_show_screen("map")
            app.update_memory_map()
            await pilot.pause()
            return [_widget_plain(row) for row in _region_rows(app)]

    texts = asyncio.run(_drive())
    assert len(texts) == 2, (
        f"two disjoint same-band blocks must render as 2 region rows; got {texts}"
    )
    # Each row is its own block: 256 B (never the merged 512 B), at its own start.
    assert any(f"0x{block_a:08X}" in t and "256 B" in t for t in texts), texts
    assert any(f"0x{block_b:08X}" in t and "256 B" in t for t in texts), texts
    assert not any("512 B" in t for t in texts), (
        f"the two blocks must NOT merge into a 512 B span; got {texts}"
    )


def test_map_band_view_survives_rerender(tmp_path: Path) -> None:
    """A second ``update_memory_map`` re-renders the band view without a
    DuplicateIds crash or doubled region rows (regression: the re-mounted band
    containers must use CLASSES, not unique IDs — ``grid.remove_children`` is
    deferred, so an id collides at re-render, LLR-045A.2).
    """
    loaded = _two_band_loaded(tmp_path)
    runs = _expected_band_runs(loaded)

    async def _drive() -> int:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.current_file = loaded
            app.action_show_screen("map")
            app.update_memory_map()
            await pilot.pause()
            app.update_memory_map()  # re-render: must not raise / must not double
            await pilot.pause()
            return len(_region_rows(app))

    assert asyncio.run(_drive()) == len(runs), (
        "a re-render must leave exactly one region row per run (no doubling, "
        "no DuplicateIds)"
    )


# ---------------------------------------------------------------------------
# batch-45 Inc-3 (R-TUI-062, LLR-045C) — single-click region→hex nav + the
# detail-pane re-wire (keeps R-TUI-041 R-3 A2L naming + its C-17 guard on a
# LIVE path) + re-cover of the retired test_ac1 B-01 nearest-present-row snap.
# ---------------------------------------------------------------------------


def _install_two_far_ranges(app: "S19TuiApp", tmp_path: Path) -> "object":
    """Load a two-range image whose ranges sit ~1 MiB apart (B-01 fixture).

    Range B's rows live far past range A's first page, so a hex window that
    fails to reposition provably does NOT render them. Built through the real
    emit → S19File → build_loaded_s19 pipeline.
    """
    from s19_app.core import S19File
    from s19_app.tui.changes import emit_s19_from_mem_map
    from s19_app.tui.services.load_service import build_loaded_s19

    ranges = [(0x1000, 0x1000 + 3200), (0x100000, 0x100000 + 3200)]
    mem_map = {
        addr: (addr & 0xFF) for start, end in ranges for addr in range(start, end)
    }
    path = tmp_path / "two_far.s19"
    path.write_text(emit_s19_from_mem_map(mem_map, ranges), encoding="ascii")
    loaded = build_loaded_s19(path, S19File(str(path)), a2l_path=None, a2l_data=None)
    app.current_file = loaded
    app._apply_empty_state()
    return loaded


def test_at074_single_click_repositions_hex(tmp_path: Path) -> None:
    """Black-box: ONE real click on a region row repositions the hex view
    (AT-074 / R-TUI-062, LLR-045C.1, C-16 real pointer).

    A single ``pilot.click`` on the HIGH region row (start ``0x80010000``) must
    reveal the Workspace/hex screen AND render that region's 16-aligned row
    token in ``#hex_view`` — with EXACTLY ONE click (no reveal-button, no
    two-step). RED pre-Inc-3: Inc-2 mounted region rows but wired NO click nav,
    so the click posts nothing and the hex view never repositions.
    """
    loaded = _two_band_loaded(tmp_path)

    async def _drive() -> "tuple[bool, str, int]":
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.current_file = loaded
            app.action_show_screen("map")
            app.update_memory_map()
            await pilot.pause()
            row = await _click_region_row(
                pilot, app, lambda r: "high/random" in _widget_plain(r)
            )
            ws_visible = "hidden" not in app.query_one("#screen_workspace").classes
            hex_str = str(app.query_one("#hex_view").render())
            return ws_visible, hex_str, row.region_start

    ws_visible, hex_str, start = asyncio.run(_drive())
    assert ws_visible, "a single region click must reveal the Workspace/hex screen"
    row_token = f"{start - (start % 16):08X}"
    assert row_token in hex_str.upper(), (
        f"the hex row for the clicked region 0x{start:08X} must render; "
        f"expected row base {row_token}"
    )


def test_tc062_1_region_activation_posts_single_open_in_hex(tmp_path: Path) -> None:
    """A region activation posts EXACTLY ONE OpenInHexRequested; no activation
    posts none (TC-062.1 / R-TUI-062, white-box message contract).
    """
    from s19_app.tui.screens_directionb import MemoryMapPanel, RegionRow

    loaded = _two_band_loaded(tmp_path)

    async def _drive() -> "tuple[int, int]":
        app = S19TuiApp(base_dir=tmp_path)
        posted: list[int] = []
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.current_file = loaded
            app.action_show_screen("map")
            app.update_memory_map()
            await pilot.pause()
            panel = app.query_one("#memory_map_panel", MemoryMapPanel)
            orig_post = panel.post_message

            def _cap(msg: "object") -> bool:
                if isinstance(msg, MemoryMapPanel.OpenInHexRequested):
                    posted.append(msg.focus_address)
                return orig_post(msg)

            panel.post_message = _cap  # type: ignore[method-assign]
            # No activation yet → no message.
            none_yet = len(posted)
            row = next(iter(app.query(RegionRow)))
            panel.on_region_row_activated(
                RegionRow.Activated(row.region_start, row.region_end)
            )
            return none_yet, len(posted)

    none_yet, after_one = asyncio.run(_drive())
    assert none_yet == 0, "no region activation must post no OpenInHexRequested"
    assert after_one == 1, (
        f"one activation must post exactly one OpenInHexRequested; got {after_one}"
    )


def test_b01_region_click_snaps_hex_to_far_range(tmp_path: Path) -> None:
    """Re-cover of the retired test_ac1 (B-01): navigating to a FAR region lands
    the hex window on the nearest present row (R-TUI-062 + batch-31 AC-1).

    Two facets: (1) a REAL region click over the far range B repositions the
    hex window to range B's first row (0x00100000) — the map→far-region nav
    test_ac1 covered; (2) the underlying nearest-present-row snap for an
    ABSENT-in-gap focus address (test_ac1's precondition — a region click uses a
    PRESENT start, so the absent-address branch is driven directly through
    ``update_hex_view``) still lands on the nearest present row.
    """

    async def _drive() -> "tuple[str, str]":
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _install_two_far_ranges(app, tmp_path)
            app.action_show_screen("map")
            app.update_memory_map()
            await pilot.pause()
            # (1) Real click on the far range-B region (start 0x00100000).
            await _click_region_row(pilot, app, lambda r: r.region_start == 0x100000)
            for _ in range(3):
                await pilot.pause()
            click_hex = str(app.query_one("#hex_view").render())
            # (2) Absent-in-gap focus address snaps to the nearest present row.
            app.update_hex_view(focus_address=0x0FFFF0)  # in the gap, not present
            await pilot.pause()
            snap_hex = str(app.query_one("#hex_view").render())
            return click_hex, snap_hex

    click_hex, snap_hex = asyncio.run(_drive())
    assert "00100000" in click_hex.upper(), (
        "a click on range B's region must render range B's first row "
        "(0x00100000)"
    )
    assert "00100000" in snap_hex.upper(), (
        "an absent-in-gap focus must snap to the nearest present row "
        "(range B's first row 0x00100000)"
    )


def test_at_r3_region_click_detail_names_a2l_symbol_literally(
    tmp_path: Path,
) -> None:
    """The region-triggered detail pane keeps R-TUI-041 R-3 A2L naming alive and
    renders a hostile symbol literally (LLR-045C detail re-wire, C-17 F1).

    A single region click populates ``#map_detail`` via ``build_detail_text`` for
    the clicked run's window; the covering region is named by the overlapping
    A2L symbol(s) through the retained ``safe_text``/``symbol_list_text`` path.
    A hostile symbol name (``evil[red]``) must render LITERALLY — proving the
    C-17 markup-safety guard now runs on a LIVE (region-triggered), not merely a
    pure-function, path. Region-LIST rows themselves stay addr/size/band-only.
    """
    loaded = _two_band_loaded(tmp_path)

    async def _drive() -> "tuple[str, str]":
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.current_file = loaded
            # Seed an A2L symbol overlapping the CONSTANT region's covering range.
            app._a2l_enriched_tags = [
                {"name": "evil[red]", "address": 0x80000010, "byte_size": 4},
            ]
            app.action_show_screen("map")
            app.update_memory_map()
            await pilot.pause()
            row = await _click_region_row(
                pilot, app, lambda r: r.region_start == 0x80000000
            )
            detail = str(app.query_one("#map_detail_body").render())
            row_text = _widget_plain(row)
            return detail, row_text

    detail, row_text = asyncio.run(_drive())
    assert "evil[red]" in detail, (
        f"the region-triggered detail must name the A2L symbol literally; "
        f"got {detail!r}"
    )
    assert "0x80000000" in detail, (
        f"the detail must show the clicked region's bounds; got {detail!r}"
    )
    # B3: the region-LIST row itself must NOT carry the A2L symbol name.
    assert "evil[red]" not in row_text, (
        f"region rows are addr/size/band-only (B3); got {row_text!r}"
    )


# ---------------------------------------------------------------------------
# batch-45 Inc-4 (R-TUI-061, LLR-045B) — docked "At a glance" panel: a per-band
# histogram (region counts + %) + a band-coloured profile sparkline, docked
# beside the band bar at >=120 cols and stacked below it at the 80x24 floor.
# ---------------------------------------------------------------------------


def _constant_only_loaded(tmp_path: Path) -> "LoadedFile":
    """A single 0xFF-fill block (one constant/padding window) → uniform profile."""
    from s19_app.core import S19File
    from s19_app.tui.changes import emit_s19_from_mem_map
    from s19_app.tui.services.entropy_service import compute_entropy
    from s19_app.tui.services.load_service import build_loaded_s19

    base = 0x80000000
    mem_map = {base + i: 0xFF for i in range(256)}
    ranges = [(base, base + 256)]
    bands = {w.band for w in compute_entropy(mem_map)}
    assert bands == {"constant/padding"}, bands
    path = tmp_path / "const.s19"
    path.write_text(emit_s19_from_mem_map(mem_map, ranges), encoding="ascii")
    return build_loaded_s19(path, S19File(str(path)), a2l_path=None, a2l_data=None)


def _glance_rows(app: "S19TuiApp") -> "list":
    """Return the At-a-glance histogram rows on the map screen."""
    return list(app.query(".map-glance-row"))


def _sparkline_text(app: "S19TuiApp") -> str:
    """Concatenated plain text of the At-a-glance sparkline segments."""
    return "".join(_widget_plain(s) for s in app.query(".map-sparkline-seg"))


def test_tc061_1_band_histogram_counts() -> None:
    """band_histogram tallies REGION counts per occupied band + percentages
    (TC-061.1 / LLR-045B.1, pure).
    """
    from s19_app.tui.screens_directionb import band_histogram

    runs = [
        ("constant/padding", 256, 0x0),
        ("high/random", 256, 0x1000),
        ("high/random", 256, 0x2000),
    ]
    rows = band_histogram(runs)
    # Occupied bands only, in canonical band order.
    assert [(b, c) for b, c, _p in rows] == [
        ("constant/padding", 1),
        ("high/random", 2),
    ]
    pcts = [p for _b, _c, p in rows]
    assert abs(sum(pcts) - 100.0) < 1e-9, f"percentages must sum to 100; {pcts}"
    assert band_histogram([]) == [], "empty runs → empty histogram"


def test_tc061_2_sparkline_ramp_mapping() -> None:
    """entropy_ramp_glyph maps 0→space, 8→full block, mid→ramp; sparkline_glyphs
    sub-samples with step max(1, N//width) (TC-061.2 / LLR-045B.2, pure).
    """
    from s19_app.tui.screens_directionb import (
        _ENTROPY_BAR_RAMP,
        entropy_ramp_glyph,
        sparkline_glyphs,
    )
    from s19_app.tui.services.entropy_service import EntropyWindow

    assert entropy_ramp_glyph(0.0) == _ENTROPY_BAR_RAMP[0] == " "
    assert entropy_ramp_glyph(8.0) == _ENTROPY_BAR_RAMP[8] == "█"
    assert entropy_ramp_glyph(4.0) == _ENTROPY_BAR_RAMP[4]
    # Clamp out-of-range without raising.
    assert entropy_ramp_glyph(99.0) == _ENTROPY_BAR_RAMP[8]

    def _w(e: float) -> EntropyWindow:
        return EntropyWindow(0, 256, 256, e, "x", False)

    # width >= N → step 1 → one glyph per window.
    assert sparkline_glyphs([_w(0.0), _w(8.0)], 24) == " █"
    # width < N → step N//width samples down.
    windows = [_w(0.0) for _ in range(48)]
    assert len(sparkline_glyphs(windows, 24)) == 24  # step 48//24 = 2 → 24 samples
    assert sparkline_glyphs([], 24) == ""


def test_at072_histogram_per_band_counts(tmp_path: Path) -> None:
    """Black-box: the At-a-glance histogram lists each occupied band with a
    count equal to its region tally, %s ~summing to 100 (AT-072 / LLR-045B.1).

    RED pre-impl: no ``.at-a-glance`` / ``.map-glance-row`` surface exists.
    """
    from s19_app.tui.screens_directionb import band_histogram

    loaded = _two_band_loaded(tmp_path)
    expected = {b: c for b, c, _p in band_histogram(_expected_band_runs(loaded))}

    async def _drive() -> "dict":
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.current_file = loaded
            app.action_show_screen("map")
            app.update_memory_map()
            await pilot.pause()
            out: dict = {}
            for row in _glance_rows(app):
                text = _widget_plain(row)
                classes = tuple(row.classes)
                out[classes] = text
            return out

    rows = asyncio.run(_drive())
    # Both bands present as histogram rows (by band class), non-vacuous counts.
    const_row = next(t for c, t in rows.items() if "band-constant" in c)
    high_row = next(t for c, t in rows.items() if "band-high" in c)
    const_count = expected["constant/padding"]
    high_count = expected["high/random"]
    assert const_count >= 1 and high_count >= 1, expected
    assert f"constant/padding {const_count} " in const_row, (
        f"constant row must show its region count {const_count}; got {const_row!r}"
    )
    assert f"high/random {high_count} " in high_row, (
        f"high row must show its region count {high_count}; got {high_row!r}"
    )
    # Percentages present and ~sum to 100 across the two rows.
    import re

    pcts = [
        int(re.search(r"(\d+)%", t).group(1))
        for t in (const_row, high_row)
    ]
    assert abs(sum(pcts) - 100) <= 1, f"histogram %s must ~sum to 100; got {pcts}"


def test_at073_sparkline_tracks_profile(tmp_path: Path) -> None:
    """Black-box: a mixed image's sparkline has >=2 distinct ramp glyphs, and a
    constant-only image's sparkline is uniform (AT-073 / LLR-045B.2, two-branch).

    RED pre-impl: no ``.map-sparkline`` surface exists.
    """
    mixed = _two_band_loaded(tmp_path)
    flat = _constant_only_loaded(tmp_path)

    async def _spark(loaded) -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.current_file = loaded
            app.action_show_screen("map")
            app.update_memory_map()
            await pilot.pause()
            return _sparkline_text(app)

    async def _both() -> "tuple[str, str]":
        return await _spark(mixed), await _spark(flat)

    mixed_spark, flat_spark = asyncio.run(_both())
    assert len(set(mixed_spark)) >= 2, (
        f"a mixed-entropy image's sparkline must vary (>=2 distinct glyphs); "
        f"got {mixed_spark!r}"
    )
    assert flat_spark and len(set(flat_spark)) == 1, (
        f"a constant-only image's sparkline must be uniform (1 glyph); "
        f"got {flat_spark!r}"
    )


def test_at073b_glance_geometry_fits_and_reflows(tmp_path: Path) -> None:
    """Pilot-geometry: the band bar + At-a-glance fit the viewport at 120x30 AND
    80x24, docked side-by-side when wide and stacked when narrow (LLR-045B.3,
    C-23 — measured regions, not fr-math).
    """
    loaded = _two_band_loaded(tmp_path)

    async def _measure(size) -> "dict":
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            app.current_file = loaded
            app.action_show_screen("map")
            app.update_memory_map()
            await pilot.pause()
            body = app.query_one("#workspace_body")
            bar = app.query_one(".map-band-bar")
            glance = app.query_one(".at-a-glance")
            return {
                "narrow": body.has_class("width-narrow"),
                "body_right": body.region.right,
                "bar": (bar.region.x, bar.region.y, bar.region.width, bar.region.right),
                "glance": (
                    glance.region.x,
                    glance.region.y,
                    glance.region.width,
                    glance.region.right,
                ),
            }

    wide = asyncio.run(_measure((120, 30)))
    narrow = asyncio.run(_measure((80, 24)))

    for tag, m in (("120x30", wide), ("80x24", narrow)):
        bx, by, bw, bright = m["bar"]
        gx, gy, gw, gright = m["glance"]
        assert bw > 0 and gw > 0, f"{tag}: both widgets must have width; {m}"
        # No horizontal overflow past the body's right edge (no clip off-screen).
        assert bright <= m["body_right"], f"{tag}: band bar overflows body; {m}"
        assert gright <= m["body_right"], f"{tag}: glance overflows body; {m}"

    # Wide (>=120): NOT narrow → glance docked to the RIGHT of the bar (same row).
    assert not wide["narrow"], f"120x30 must be the wide regime; {wide}"
    assert wide["glance"][0] > wide["bar"][0], (
        f"at 120x30 the glance must dock beside (right of) the band bar; {wide}"
    )
    # Narrow (<120): width-narrow → glance STACKS below the band bar.
    assert narrow["narrow"], f"80x24 must be the narrow regime; {narrow}"
    assert narrow["glance"][1] > narrow["bar"][1], (
        f"at 80x24 the glance must stack below the band bar; {narrow}"
    )


# ---------------------------------------------------------------------------
# batch-45 Inc-5 (R-TUI-050/051 retire) — the standalone entropy pop-up is
# removed; its function lives in the always-visible Memory-Map band view. A
# deletion still owes an observation (AT-075/076).
# ---------------------------------------------------------------------------


def test_at075_e_key_opens_no_modal_map_has_legend(tmp_path: Path) -> None:
    """Black-box: pressing ``e`` opens no modal, and the map's band legend is
    present (AT-075 / R-TUI-050/051 retire).

    RED pre-delete: ``e`` was bound to ``show_entropy`` and pushed the
    ``EntropyViewerScreen`` modal (the screen stack grew).
    """
    from textual.screen import ModalScreen

    loaded = _two_band_loaded(tmp_path)

    async def _drive() -> "tuple[int, int, bool, list]":
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.current_file = loaded
            app.action_show_screen("map")
            app.update_memory_map()
            await pilot.pause()
            before = len(app.screen_stack)
            await pilot.press("e")
            await pilot.pause()
            after = len(app.screen_stack)
            is_modal = isinstance(app.screen, ModalScreen)
            legend = [_widget_plain(r) for r in app.query(".map-legend-row")]
            return before, after, is_modal, legend

    before, after, is_modal, legend = asyncio.run(_drive())
    assert after == before, (
        f"pressing 'e' must push no modal (stack {before} -> {after})"
    )
    assert not is_modal, "no ModalScreen may be active after pressing 'e'"
    joined = " ".join(legend)
    for band in ("constant/padding", "low", "medium", "high/random"):
        assert band in joined, f"the map band legend must list {band!r}; got {legend}"


def test_at076_entropy_screen_and_action_removed() -> None:
    """Black-box: ``EntropyViewerScreen`` is gone from ``screens``, and
    ``S19TuiApp`` has no ``show_entropy`` action or ``e`` binding (AT-076).

    RED pre-delete: all three existed.
    """
    import s19_app.tui.screens as screens_module

    assert not hasattr(screens_module, "EntropyViewerScreen"), (
        "EntropyViewerScreen must be removed from s19_app.tui.screens"
    )
    assert not hasattr(S19TuiApp, "action_show_entropy"), (
        "S19TuiApp.action_show_entropy must be removed"
    )
    bound = {b.key: b.action for b in S19TuiApp.BINDINGS if hasattr(b, "key")}
    assert bound.get("e") != "show_entropy", (
        f"the 'e' -> show_entropy binding must be removed; got {bound.get('e')!r}"
    )


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


#: 4 bytes (01 02 03 04) at 0x1000 — the Flow Builder AT source image.
_FLOW_S19 = "S107100001020304DE\nS9030000FC\n"
#: A change document patching 0x1000 -> 0xAA (byte-addressed, no linkage).
_FLOW_PATCH = (
    '{"format": "s19app-changeset", "version": "2.0", "kind": "change", '
    '"encoding": "utf-8", "value_mode": "text", '
    '"entries": [{"type": "bytes", "address": "0x1000", "bytes": "AA"}]}'
)


def _flow_project(app: "S19TuiApp") -> None:
    """Seed a workarea project (``prg.s19`` + ``patch.json``) and select it."""
    project = app.workarea / "proj"
    project.mkdir(parents=True, exist_ok=True)
    (project / "prg.s19").write_text(_FLOW_S19, encoding="utf-8")
    (project / "patch.json").write_text(_FLOW_PATCH, encoding="utf-8")
    app.current_project = "proj"


def _add_flow_block(app: "S19TuiApp", kind: str, ref: str) -> None:
    """Drive the Flow Builder add row: set kind + ref, press Add."""
    from textual.widgets import Button, Input, Select

    app.query_one("#flow_kind", Select).value = kind
    app.query_one("#flow_ref", Input).value = ref
    app.query_one("#flow_add", Button).press()


def _static_plain(app: "S19TuiApp", selector: str) -> str:
    """Return the plain text of a ``Static``'s current rendered content."""
    from textual.widgets import Static

    return str(app.query_one(selector, Static).render())


def test_at_flow_add_blocks_and_run_renders_result(tmp_path: Path) -> None:
    """AC-4: rail-8 is the Flow Builder; adding Load/Patch/WriteOut blocks and
    pressing Run executes the flow and renders the Direction-A result (a CLEAN
    banner + the written path).

    RED pre-code: rail-8 is the Bookmarks placeholder; ``#screen_flow`` and the
    panel are absent. Reconciled at batch-51 Inc-2: ``#flow_result`` is now a
    ``VerticalScroll`` of block nodes + banner + written-path lines (was a flat
    ``Static``), and SOURCE is surfaced as "LOAD" (its ``"source"`` tag is kept).
    """
    from textual.widgets import Button, Static

    async def _drive() -> tuple[list[str], str, str]:
        app = S19TuiApp(base_dir=tmp_path)
        _flow_project(app)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("flow")
            await pilot.pause()
            visible = _visible_screens(app)
            _add_flow_block(app, "source", "prg.s19")
            await pilot.pause()
            _add_flow_block(app, "patch", "patch.json")
            await pilot.pause()
            _add_flow_block(app, "write_out", "out.s19")
            await pilot.pause()
            blocks_text = _static_plain(app, "#flow_blocks")
            app.query_one("#flow_run", Button).press()
            await pilot.pause()
            await pilot.pause()
            banner = str(
                app.query_one("#flow_result .flow-banner", Static).render()
            )
            wrote = " ".join(
                str(w.render()) for w in app.query("#flow_result .flow-wrote")
            )
            return visible, blocks_text, f"{banner} {wrote}"

    visible, blocks_text, result_text = asyncio.run(_drive())

    assert visible == ["screen_flow"], f"rail-8 must show #screen_flow; {visible}"
    # The composed flow lists all three blocks in order (SOURCE surfaced LOAD).
    assert "LOAD" in blocks_text and "prg.s19" in blocks_text
    assert "PATCH" in blocks_text and "patch.json" in blocks_text
    assert "WRITE-OUT" in blocks_text and "out.s19" in blocks_text
    # Run succeeded (CLEAN banner) and the result names the written file.
    assert "CLEAN" in result_text, f"run should succeed; got {result_text!r}"
    assert "out.s19" in result_text, f"result must name the output; {result_text!r}"


def test_at_flow_rail_key_8_reaches_panel(tmp_path: Path) -> None:
    """AC-4: pressing the rail key ``8`` opens the Flow Builder screen.

    RED pre-code: rail key 8 showed ``#screen_bookmarks``.
    """

    async def _drive() -> list[str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press("8")
            await pilot.pause()
            return _visible_screens(app)

    visible = asyncio.run(_drive())
    assert visible == ["screen_flow"], (
        f"rail key 8 must show only the Flow Builder screen, got {visible}"
    )


def test_at_flow_block_label_markup_safe(tmp_path: Path) -> None:
    """AC-5: a block ref carrying hostile markup renders LITERALLY in the block
    list — no Rich markup injection / MarkupError (the batch-27/43 class).
    """

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("flow")
            await pilot.pause()
            _add_flow_block(app, "source", "evil[red].s19")
            await pilot.pause()
            return _static_plain(app, "#flow_blocks")

    blocks_text = asyncio.run(_drive())
    assert "evil[red].s19" in blocks_text, (
        f"hostile ref must render literally; got {blocks_text!r}"
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
    # batch-09 (US-006, D-7): the headless diff engine ``compare.py`` is
    # deliberately added at the package root beside ``range_index.py`` — the
    # newer requirement supersedes this batch-04 "nothing new at root"
    # invariant for that one module; the guard still catches any OTHER
    # unexpected root module.
    engine_root_modules = {
        "__init__.py",
        "cli.py",
        "core.py",
        "hexfile.py",
        "range_index.py",
        "compare.py",
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
    # Gather BOTH attribute-form (``x.compute_entropy(...)``) and bare-name
    # (``compute_entropy(...)`` — the actual import+call shape) so an inline
    # entropy recompute trips the guard regardless of call form (review F2).
    calls = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    } | {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    forbidden_calls = {
        "validate_artifact_consistency",
        "build_sorted_range_index",
        "build_range_validity_s19",
        "build_range_validity_hex",
        "parse_a2l_file",
        "parse_mac_file",
        # batch-45 (R-TUI-060, M4): entropy is computed on the worker-thread
        # load path (load_service.build_loaded_*) and cached on
        # ``LoadedFile.entropy_windows``; ``update_memory_map`` must only READ
        # that field, never recompute it inline (render-only / off-thread).
        "compute_entropy",
        "_merge_band_runs",
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
# TC-026 — Patch Editor screen (v2 consolidated panel, batch-07 E3a/E3b)
#
# batch-03 increment 9 superseded the batch-02 inert shell with the
# functional parameter editor; batch-07 consolidated the Patch Editor to the
# single v2 JSON change flow (LLR-003.1) and retired the parameter section.
# The two parameter-widget render tests RETIRED with that section (their v2
# replacements live in ``test_tui_patch_editor_v2.py::
# test_panel_composition``); the presentational and empty-state guards below
# are REWRITTEN to the v2 panel.
# ---------------------------------------------------------------------------


def test_tc026_patch_editor_panel_is_presentational() -> None:
    """The Patch Editor widget holds no changes-package logic (LLR-003.1).

    Intent (carried from batch-03 C-8, re-pinned to the v2 module names at
    E3b): the change-document read/write and model logic lives in
    ``services.change_service``, not in the view widget. The
    ``PatchEditorPanel`` must import nothing from the ``changes`` package
    (nor the retired ``cdfx`` one) and must perform its work by posting an
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

    # The widget module must not import the change-format handler — that is
    # the service's job.
    source = inspect.getsource(inspect.getmodule(PatchEditorPanel))
    tree = ast.parse(source)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
        elif isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
    model_imports = [
        name
        for name in imported
        if "cdfx" in name
        or name.endswith(".changes")
        or ".changes." in name
        or name == "changes"
    ]
    assert model_imports == [], (
        f"the Patch Editor widget must not import the changes/cdfx model "
        f"packages; found {model_imports}"
    )


def test_tc026_patch_editor_shows_empty_state(tmp_path: Path) -> None:
    """The Patch Editor shows a neutral empty state (v2 panel).

    Intent (carried from batch-03 LLR-007.6, re-pinned to the v2 ids at
    E3b): while the Patch Editor is open with an empty change document it
    shows a single neutral add-or-load prompt line, not a blank pane, an
    error or a stack trace.
    """
    from s19_app.tui.screens_directionb import PatchEditorPanel

    async def _drive() -> tuple[bool, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            empty = app.query("#patch_doc_empty_state")
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
# A↔B Diff panel — completed in batch-09 I4 (HLR-005). The four placeholder
# tests below were SUPERSEDED from the batch-04 LLR-012.3/012.4 census: the
# panel is no longer a static placeholder, so the assertions now pin the new
# behavior (inline selection, service-routed compare, Rich render, no
# placeholder constants). See increment-I4.md §R-8 disposition.
# ---------------------------------------------------------------------------


def test_tc027_ab_diff_renders_three_columns(tmp_path: Path) -> None:
    """The A2B Diff renders the three result columns (HLR-005, superseding LLR-012.3).

    Intent: the A2B Diff keeps its three-column result layout — a range list,
    a hex-A column and a hex-B column. All three must be present in the
    rendered widget tree once the screen is active. (Unchanged from the
    placeholder era: the new panel reuses the same column ids.)
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


def test_tc027_ab_diff_has_no_placeholder_constants() -> None:
    """The A2B Diff panel carries no static placeholder constants (LLR-005.2).

    Intent: the placeholder constants (``_RANGE_LIST_PLACEHOLDER`` /
    ``_HEX_A_PLACEHOLDER`` / ``_HEX_B_PLACEHOLDER`` / ``DEFERRAL_TEXT``) are
    gone — the panel renders real comparison output, not constant sample rows.
    This is the LLR-005.2 named-constant probe expressed as a unit test.
    """
    from s19_app.tui.screens_directionb import AbDiffPanel

    for removed in (
        "_RANGE_LIST_PLACEHOLDER",
        "_HEX_A_PLACEHOLDER",
        "_HEX_B_PLACEHOLDER",
        "DEFERRAL_TEXT",
    ):
        assert not hasattr(AbDiffPanel, removed), (
            f"the completed A2B Diff panel must not keep the placeholder "
            f"constant {removed!r}"
        )


def test_tc027_ab_diff_renders_inline_selection_surface(tmp_path: Path) -> None:
    """The A2B Diff renders an INLINE image-pair selection surface (G-6/LLR-005.1).

    Intent: G-6 — source selection is inline within the diff screen, not a
    modal. The screen must expose the two variant ``Select`` dropdowns, the
    two external-path inputs, and the Compare button, all mounted inside the
    diff screen (no separate ModalScreen pushed).
    """
    from textual.widgets import Button, Input, Select

    async def _drive() -> dict[str, bool]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("diff")
            await pilot.pause()
            screen = app.query_one("#screen_diff")
            return {
                "select_a": bool(screen.query("#diff_select_a")),
                "select_b": bool(screen.query("#diff_select_b")),
                "path_a": bool(screen.query("#diff_path_a")),
                "path_b": bool(screen.query("#diff_path_b")),
                "compare": bool(screen.query("#diff_compare_button")),
                "selects_are_select": all(
                    isinstance(w, Select) for w in screen.query("#diff_select_a")
                ),
                "compare_is_button": all(
                    isinstance(w, Button)
                    for w in screen.query("#diff_compare_button")
                ),
                "paths_are_input": all(
                    isinstance(w, Input) for w in screen.query("#diff_path_a")
                ),
            }

    surface = asyncio.run(_drive())
    for name, present in surface.items():
        assert present, f"the inline selection surface must expose {name}"


def test_tc027_ab_diff_panel_routes_through_service() -> None:
    """The A2B Diff panel exposes a service-routed surface, not a diff engine.

    Intent: LLR-005.1 — the panel is presentational: it emits
    ``CompareRequested`` / ``ReportRequested`` messages and renders results the
    app hands back. It must carry NO method that classifies runs or computes a
    report itself (no ``diff_mem_maps`` / coverage / generate-report helper).
    """
    from s19_app.tui.screens_directionb import AbDiffPanel

    # The message + render surface the app routes through must exist.
    assert hasattr(AbDiffPanel, "CompareRequested")
    assert hasattr(AbDiffPanel, "ReportRequested")
    assert hasattr(AbDiffPanel, "render_comparison")

    # The panel must not embed any engine/report computation helper.
    forbidden = (
        "diff_mem_maps",
        "classify",
        "coverage",
        "generate_diff_report",
        "generate_report",
    )
    surface = [name for name in dir(AbDiffPanel)]
    leaked = [
        name
        for name in surface
        if any(token in name.lower() for token in forbidden)
    ]
    assert leaked == [], (
        f"the A2B Diff panel must route compute through the services, not "
        f"embed it; found {leaked}"
    )


def test_ab_diff_blank_select_yields_none_variant(tmp_path: Path) -> None:
    """A blank A/B variant ``Select`` resolves to ``None``, not "Select.NULL".

    Intent: regression for the textual 8.2.5 blank sentinel. The
    no-selection value is ``Select.NULL`` (a ``NoSelection`` instance);
    ``Select.BLANK`` resolves to the inherited ``Widget.BLANK`` bool and
    never matches a real value. Under the old ``Select.BLANK`` comparison,
    ``AbDiffPanel._selected_variant`` stringified the sentinel and Compare
    received the bogus variant id ``"Select.NULL"`` instead of ``None``.
    The panel's selects are ``allow_blank=False``, so the blank state is
    forced via ``set_reactive`` (the validated ``value`` setter refuses it).
    """
    from textual.widgets import Select

    from s19_app.tui.screens_directionb import AbDiffPanel

    async def _drive() -> tuple[object, object]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("diff")
            await pilot.pause()
            panel = app.query_one("#ab_diff_panel", AbDiffPanel)
            default = panel._selected_variant("#diff_select_a")
            select = app.query_one("#diff_select_a", Select)
            select.set_reactive(Select.value, Select.NULL)
            return default, panel._selected_variant("#diff_select_a")

    default, blank = asyncio.run(_drive())
    assert default is None, (
        f"the default (external-option) selection must map to None, "
        f"got {default!r}"
    )
    assert blank is None, (
        f"a blank Select (Select.NULL) must map to None, got {blank!r}"
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
    # batch-09 (US-006, D-7): ``compare.py`` headless diff engine added at the
    # package root by design; newer requirement supersedes the batch-04
    # "nothing new at root" invariant for that module. Guard still flags any
    # OTHER unexpected root module.
    engine_root_modules = {
        "__init__.py",
        "cli.py",
        "core.py",
        "hexfile.py",
        "range_index.py",
        "compare.py",
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
    """All four rail screens activate without raising (LLR-012.4 / HLR-005).

    Intent: the Memory Map, Patch Editor, A2B Diff and Bookmarks rail screens
    each activate cleanly with no file loaded, never an error. The A2B Diff is
    now the completed panel (batch-09 I4, HLR-005) and carries its inline
    status line in place of the retired deferral notice; the Patch Editor is
    functional and carries its empty-state line (batch-07 E3b).
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
            # The completed A2B Diff carries its inline status line; the Patch
            # Editor carries its empty-state line. The retired deferral notice
            # must be GONE (LLR-005.2 placeholder removal).
            markers_present = (
                bool(app.query("#diff_status"))
                and bool(app.query("#patch_doc_empty_state"))
                and not bool(app.query("#diff_deferral_notice"))
            )
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
    # ``s19_app/tui/a2l.py`` is temporarily UNFROZEN for batch-54 (operator-
    # approved multi-line A2L header parsing) — absent from TC-031's frozen set
    # so the sanctioned parser edits do not trip the guard. RE-FREEZE is a
    # post-merge follow-up PR (batch-50 P-2 pattern).
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


def test_tc030_operations_binding_shown_in_footer(tmp_path: Path) -> None:
    """The Operations view's ``x`` binding is footer-discoverable.

    Intent: fast-dev-flow AC "x/Operations is footer-discoverable" — the
    Operations view (host of the CRC operation) was reachable only by the
    undocumented ``x`` key. Flipping that binding to ``show=True`` surfaces it
    in the footer. AC-1: ``x`` is in the footer's visible set on every rail
    screen. AC-2: the chip's description reads ``Operations``.
    """

    async def _drive() -> tuple[dict[str, set[str]], str]:
        app = S19TuiApp(base_dir=tmp_path)
        footers: dict[str, set[str]] = {}
        description = ""
        async with app.run_test() as pilot:
            await pilot.pause()
            for screen_key in SCREEN_KEYS:
                app.action_show_screen(screen_key)
                await pilot.pause()
                footers[screen_key] = _shown_footer_keys(app)
            description = app.active_bindings["x"].binding.description
        return footers, description

    footers, description = asyncio.run(_drive())
    for screen_key, shown in footers.items():
        assert "x" in shown, (
            f"screen '{screen_key}' footer is missing the Operations key "
            f"'x' — footer shows {sorted(shown)}"
        )
    assert description == "Operations", (
        f"the 'x' binding footer description must read 'Operations', "
        f"got {description!r}"
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


# ---------------------------------------------------------------------------
# fast-dev-flow (sections-label) — Data Sections range label two-line wrap.
#
# The fixed 22-column ``#ws_left`` pane clipped the old single-line range
# label ``0x{start:08X} - 0x{end-1:08X} ({size} bytes)`` (~33 chars), so the
# end address + size fell off. ``update_sections`` (app.py) now emits a
# two-line label — start on line 1, ``– <end>  <size>B`` on line 2 — and the
# sibling MAC out-of-range label gets the same treatment. These tests pin the
# rendered text through the mounted ``Label.content`` (the same accessor the
# existing ``#hex_view`` tests read), which preserves the newline.
#
#   AC-1 -> test_sections_label_shows_end_address_not_clipped (gate)
#   AC-2 -> test_sections_label_two_line_format
#   AC-3 -> test_mac_out_of_range_label_full_address
#   AC-4 -> test_sections_item_data_and_colour_preserved (regression)
# ---------------------------------------------------------------------------

# A range whose single-line label is far wider than the 22-col left pane —
# start 0x80302040, end-exclusive 0x80302080 (so end token = 0x8030207F).
_WIDE_RANGE_START = 0x80302040
_WIDE_RANGE_END = 0x80302080  # exclusive; size = 64
_WIDE_RANGE_END_TOKEN = f"0x{_WIDE_RANGE_END - 1:08X}"  # 0x8030207F
_WIDE_RANGE_START_TOKEN = f"0x{_WIDE_RANGE_START:08X}"  # 0x80302040


def _install_wide_range_loaded_file(app: "S19TuiApp", tmp_path: Path) -> LoadedFile:
    """Seed a ``LoadedFile`` with one wide, valid range as ``current_file``.

    The range is chosen so its single-line label exceeds the fixed 22-column
    ``#ws_left`` pane — the pre-change format clipped the end address.
    """
    loaded = LoadedFile(
        path=tmp_path / "wide.s19",
        file_type="s19",
        mem_map={_WIDE_RANGE_START: 0x11},
        row_bases=[_WIDE_RANGE_START],
        ranges=[(_WIDE_RANGE_START, _WIDE_RANGE_END)],
        range_validity=[True],
        errors=[],
        a2l_path=None,
        a2l_data=None,
    )
    app.current_file = loaded
    return loaded


def _first_section_label_text(app: "S19TuiApp") -> str:
    """Return the rendered text of the first ``#sections_list`` item's Label."""
    from textual.widgets import Label, ListView

    sections = app.query_one("#sections_list", ListView)
    label = sections.children[0].query_one(Label)
    return str(label.content)


def test_sections_label_shows_end_address_not_clipped(tmp_path: Path) -> None:
    """AC-1 (gate): the end address is placed so it is NOT clipped by the pane.

    Intent: a range wider than the 22-col ``#ws_left`` pane clipped its END
    address under the old single-line ``0x<start> - 0x<end> (<size> bytes)``
    format — the end trailed the start on one physical line past the pane edge.
    The fix moves the end onto its own line. This test observes the discriminator
    that actually stops the clipping: the end token ``0x8030207F`` must appear on
    a rendered line AFTER the start token's line — never trailing it on the same
    line. On the old single-line format everything is one line, so the end never
    lands on a later line and this gate FAILS; on the two-line wrap it PASSES.
    (Verified to genuinely gate: reverting to the single-line format fails this.)
    """

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _install_wide_range_loaded_file(app, tmp_path)
            app.update_sections()
            await pilot.pause()
            return _first_section_label_text(app)

    text = asyncio.run(_drive())
    lines = text.split("\n")
    assert _WIDE_RANGE_END_TOKEN in text, (
        f"the range label must contain the end address {_WIDE_RANGE_END_TOKEN!r}; "
        f"rendered text was {text!r}"
    )
    start_line = next(
        i for i, line in enumerate(lines) if _WIDE_RANGE_START_TOKEN in line
    )
    end_on_later_line = any(
        _WIDE_RANGE_END_TOKEN in line
        for i, line in enumerate(lines)
        if i > start_line
    )
    assert end_on_later_line, (
        f"the end address {_WIDE_RANGE_END_TOKEN!r} must render on a line AFTER "
        f"the start line (so the narrow pane cannot clip it); the old single-line "
        f"format trails it on the start line. Rendered lines were {lines!r}"
    )


def test_sections_label_two_line_format(tmp_path: Path) -> None:
    """AC-2: the range item renders two lines with both start and end tokens.

    Intent: the fix is Variant A (two-line wrap) — start address on line 1,
    ``– <end>  <size>B`` on line 2. Assert the rendered label text contains a
    newline AND both the start and end address tokens, so the whole range
    stays readable in the narrow pane without a layout/width change.
    """

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _install_wide_range_loaded_file(app, tmp_path)
            app.update_sections()
            await pilot.pause()
            return _first_section_label_text(app)

    text = asyncio.run(_drive())
    assert "\n" in text, (
        f"the range label must render two lines (contain a newline); "
        f"rendered text was {text!r}"
    )
    assert _WIDE_RANGE_START_TOKEN in text, (
        f"line 1 must carry the start token {_WIDE_RANGE_START_TOKEN!r}; "
        f"rendered text was {text!r}"
    )
    assert _WIDE_RANGE_END_TOKEN in text, (
        f"line 2 must carry the end token {_WIDE_RANGE_END_TOKEN!r}; "
        f"rendered text was {text!r}"
    )


def test_mac_out_of_range_label_full_address(tmp_path: Path) -> None:
    """AC-3: a MAC out-of-range item renders the full 0x{address:08X}.

    Intent: the sibling ``MAC out-of-range @ 0x{address:08X}`` label (~29 chars)
    also clipped in the 22-col pane. It gets the same two-line treatment. The
    out-of-range address is fed through the exact seam ``update_sections``
    consumes (its ``precomputed_out_of_range`` argument), so the assertion runs
    over the real render path. The full address token must be present.
    """
    from textual.widgets import Label, ListView

    oor_address = 0x80302040

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _install_wide_range_loaded_file(app, tmp_path)
            app.update_sections(precomputed_out_of_range=[oor_address])
            await pilot.pause()
            sections = app.query_one("#sections_list", ListView)
            # The MAC out-of-range item follows the range item(s); find the one
            # carrying the MAC label by its content marker.
            texts = [
                str(item.query_one(Label).content)
                for item in sections.children
            ]
            return next(t for t in texts if "MAC out-of-range" in t)

    text = asyncio.run(_drive())
    assert f"0x{oor_address:08X}" in text, (
        f"the MAC out-of-range label must show the full address "
        f"0x{oor_address:08X}; rendered text was {text!r}"
    )
    # The consistency fix wraps the MAC label too: address on its own line, so
    # the ~29-char single line cannot clip it in the 22-col pane.
    assert "\n" in text and f"0x{oor_address:08X}" in text.split("\n")[-1], (
        f"the MAC out-of-range label must place the address on its own line "
        f"(two-line wrap); rendered text was {text!r}"
    )


def test_sections_item_data_and_colour_preserved(tmp_path: Path) -> None:
    """AC-4 (regression): the (start, end) payload and sev-* colour survive.

    Intent: the relabel must not disturb the selection payload or the colour
    class — ``ListItem.data`` must still be ``(start, end)`` (drives the hex
    jump on select) and the Label must still carry the ``css_class_for_severity``
    class (here ``sev-ok`` for a valid range). A Pilot select of the item must
    still drive the hex view (focus moves onto the hex pane region).
    """
    from textual.widgets import Label, ListView

    from s19_app.tui.color_policy import css_class_for_severity
    from s19_app.validation.model import ValidationSeverity

    ok_class = css_class_for_severity(ValidationSeverity.OK)

    async def _drive() -> tuple[object, bool]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _install_wide_range_loaded_file(app, tmp_path)
            app.update_sections()
            await pilot.pause()
            sections = app.query_one("#sections_list", ListView)
            item = sections.children[0]
            label = item.query_one(Label)
            has_class = label.has_class(ok_class)
            return item.data, has_class

    data, has_class = asyncio.run(_drive())
    assert data == (_WIDE_RANGE_START, _WIDE_RANGE_END), (
        f"the range item must still carry its (start, end) selection payload; "
        f"got {data!r}"
    )
    assert has_class, (
        f"the range Label must still carry the {ok_class!r} colour class"
    )


# ===========================================================================
# batch-28 (R-TUI-042) — Increment 1: US-038 A2L Explorer table polish
# ===========================================================================
#
# LLR-042.1 (verify-not-build): A2L rows scroll INSIDE the `#a2l_tags_list`
# DataTable so its column header stays fixed — the Textual DataTable default;
# AT-038a / TC-042.1 drive a REAL `pagedown` and assert the table (not an outer
# container) actually scrolled.  LLR-042.2 (build): the tags pane carries the
# queryable `density-compact` class + the DataTable renders `cell_padding=0`;
# the per-row `_severity_style` colouring and paging path stay unchanged and
# cells stay `rich.text.Text` (no markup flip — batch-27 B-1 guard).
#
# NOTE (surface fact, verified against app.py:687-691): the A2L Explorer rail
# screen is bound to key "2" (`show_screen('a2l')`); "3" is MAC View. The
# requirement draft's `press("3")` names the wrong surface, so these ATs drive
# the real A2L key, "2".
#
# case_01 carries only 3 A2L tags — too few to overflow the pane — so AT-038a /
# TC-042.1 render a windowful of the case_01 enriched tag repeated through the
# real `update_a2l_tags_view` renderer (all 180 < the default page_size 200, so
# one page mounts) purely to give the table something to scroll; the scroll
# itself is the real mechanism under test (C-16).


def _a2l_enriched_case_01(app: S19TuiApp) -> list[dict]:
    """Return the case_01 enriched A2L tag dicts through the real pipeline.

    Runs `_compute_a2l_enriched_tags` + `_refresh_a2l_filtered_tags` so the
    dicts carry every field `_build_a2l_table_cells` / `_a2l_tag_row_severity`
    read — no hand-built tag shapes.
    """
    app.a2l_tags_filter_mode = "all"
    app.a2l_tags_filter_field = "name"
    app.a2l_tags_filter_text = ""
    app._compute_a2l_enriched_tags()
    app._refresh_a2l_filtered_tags(preserve_anchor=False)
    return list(app._a2l_filtered_tags)


def test_at_038a_a2l_table_owns_scroll_header_fixed(tmp_path: Path) -> None:
    """AT-038a / TC-042.1 / LLR-042.1: a REAL pagedown scrolls the A2L
    DataTable while its header stays fixed.

    Intent: LLR-042.1 is verify-not-build — the fixed column header is the
    Textual DataTable default *because the DataTable itself owns row scrolling*.
    This must be observed, not assumed: navigate to A2L via the real "2" key,
    fill the table past the pane height, focus it, drive a REAL `pagedown`, and
    assert the DataTable's `scroll_offset.y` actually advanced (> 0) while
    `show_header` stays True with a rendered column label. A tautology (columns
    always present) could not fail; a table whose whole body scrolled away —
    losing the header — would fail the scroll-owner check in TC-042.1.
    """
    from textual.widgets import DataTable

    async def _drive() -> dict[str, object]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _load_case_01(app)
            base_tags = _a2l_enriched_case_01(app)
            assert base_tags, "case_01 must enrich at least one A2L tag"
            big = (base_tags * 60)[:180]  # < page_size 200 → one mounted page
            await pilot.press("2")  # real A2L rail key (NOT "3" = MAC)
            await pilot.pause()
            app.update_a2l_tags_view(big)
            await pilot.pause()
            table = app.query_one("#a2l_tags_list", DataTable)
            table.focus()
            await pilot.pause()
            before = table.scroll_offset.y
            await pilot.press("pagedown")
            await pilot.pause()
            return {
                "before": before,
                "after": table.scroll_offset.y,
                "show_header": table.show_header,
                "column_labels": [c.label.plain for c in table.columns.values()],
                # scroll owner: outer containers must NOT scroll (header fixed).
                "pane_scroll_y": app.query_one("#a2l_tags_pane").scroll_offset.y,
                "screen_scroll_y": app.query_one("#screen_a2l").scroll_offset.y,
                "row_count": table.row_count,
            }

    r = asyncio.run(_drive())
    assert r["row_count"] == 180, (
        f"expected a full mounted page of 180 rows, got {r['row_count']}"
    )
    assert r["after"] > r["before"], (
        "a real pagedown must scroll the A2L DataTable rows: "
        f"scroll_offset.y went {r['before']} -> {r['after']}"
    )
    assert r["show_header"] is True, "the A2L column header must stay shown on scroll"
    assert any(label.strip() for label in r["column_labels"]), (
        f"the fixed header must render at least one column label; "
        f"got {r['column_labels']!r}"
    )
    # TC-042.1: the DataTable — not an outer container — owns row scrolling, so
    # the header cannot scroll away with the body.
    assert r["pane_scroll_y"] == 0 and r["screen_scroll_y"] == 0, (
        "row scrolling must be owned by the #a2l_tags_list DataTable, not an "
        f"outer container (pane_y={r['pane_scroll_y']}, "
        f"screen_y={r['screen_scroll_y']})"
    )


def test_at_038b_a2l_pane_carries_density_compact_class(tmp_path: Path) -> None:
    """AT-038b / LLR-042.2: the A2L tags pane carries the queryable
    `density-compact` class after load.

    Intent: the compact-density polish is observable as a queryable class on the
    A2L container (mirroring the `#workspace_body.density-compact` precedent), so
    a test — and any future density-aware CSS — can bind to it. A polish applied
    only via a hard-coded padding literal, with no queryable marker, would leave
    this assertion unable to distinguish compact from comfortable.
    """

    async def _drive() -> bool:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _load_case_01(app)
            app.update_a2l_view()
            await pilot.press("2")
            await pilot.pause()
            return app.query_one("#a2l_tags_pane").has_class("density-compact")

    assert asyncio.run(_drive()), (
        "#a2l_tags_pane must carry the 'density-compact' class (US-038 polish)"
    )


def test_at_038c_a2l_error_row_keeps_severity_style(tmp_path: Path) -> None:
    """AT-038c (regression) / LLR-042.2: an error-severity A2L row still
    carries its severity style after the density polish.

    Intent: the density polish must not disturb the per-row `_severity_style`
    colouring. An A2L symbol carrying a real ERROR-severity issue (`CAL_BLOCK_A`,
    duplicated in the loaded A2L so the recomputed report emits
    `A2L_DUPLICATE_SYMBOL`) must still red that row via the issue-severity map —
    i.e. its DataTable cells must be `rich.text.Text` styled "red" (the frozen
    `_SEVERITY_TO_RICH_STYLE[ERROR]`). A polish that dropped the styled `Text`
    cells (or flipped to markup) would fail this.

    The red MUST come from the REAL recomputed report, not a hand-seeded
    ``_validation_issues``: ``update_a2l_view`` rebuilds the issue list from the
    current file pair (LLR-037.3), so a pre-seeded issue is discarded before the
    row renders. Injecting a genuine duplicate exercises the production
    issue-map -> red path. (Before the a2l-missing-length-fix batch this test
    leaned unknowingly on ``CAL_BLOCK_A``'s missing-length ``schema_ok=False``;
    that batch corrected the verdict — an underivable length is not a schema
    failure — exposing that the seed never wired through. See
    ``.fast-dev-flow/spec.md`` §AC-5.)
    """
    import copy

    from rich.text import Text
    from textual.widgets import DataTable

    async def _drive() -> dict[str, object]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _load_case_01(app)
            # Duplicate CAL_BLOCK_A so the recomputed report flags a
            # symbol-carrying A2L_DUPLICATE_SYMBOL ERROR the issue-severity map
            # maps to a red row (robust to update_a2l_view's issue recompute,
            # unlike a hand-seeded _validation_issues).
            tags = app.current_a2l_data["tags"]
            original = next(t for t in tags if t.get("name") == "CAL_BLOCK_A")
            tags.append(copy.deepcopy(original))
            app.update_a2l_view()
            await pilot.press("2")
            await pilot.pause()
            table = app.query_one("#a2l_tags_list", DataTable)
            # Find the row key whose enriched tag is CAL_BLOCK_A via the render
            # map, then read its cells straight off the DataTable.
            key = next(
                k
                for k, tag in app._a2l_row_key_to_tag.items()
                if str(tag.get("name")) == "CAL_BLOCK_A"
            )
            cells = table.get_row(key)
            return {
                "all_text": all(isinstance(c, Text) for c in cells),
                "styles": [str(c.style) for c in cells],
            }

    r = asyncio.run(_drive())
    assert r["all_text"], "every A2L cell must stay a rich.text.Text instance"
    assert all("red" in style for style in r["styles"]), (
        "the ERROR-severity CAL_BLOCK_A row must keep its red severity style; "
        f"got {r['styles']!r}"
    )


def test_at_038d_a2l_empty_state_no_file(tmp_path: Path) -> None:
    """AT-038d: with no file loaded the A2L Explorer shows its empty table
    and does not crash.

    Intent: the negative/boundary case — navigating to A2L on a fresh app (no
    `current_file`) must leave the `#a2l_tags_list` table mounted and empty
    (0 rows) with no exception, so the polish never assumes a loaded image.
    """
    from textual.widgets import DataTable

    async def _drive() -> int:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press("2")
            await pilot.pause()
            return app.query_one("#a2l_tags_list", DataTable).row_count

    assert asyncio.run(_drive()) == 0, (
        "with no file loaded the A2L table must render empty (0 rows), no crash"
    )


def test_tc_042_2_density_class_text_cells_and_paging(tmp_path: Path) -> None:
    """TC-042.2 / LLR-042.2: density class applied, cells stay `rich.text.Text`
    (markup NOT enabled), and the paging path is unchanged.

    Intent: the white-box companion to AT-038b/c. After the polish the A2L pane
    carries `density-compact`; every rendered cell is a `rich.text.Text`
    instance (batch-27 B-1 guard — the renderer never flips to markup parsing);
    and the existing `_a2l_window_start` paging still advances/retreats by one
    page through `action_a2l_tags_page_next/prev`. Using page_size 2 over the 3
    case_01 tags exercises a real second page without synthetic data.
    """
    from rich.text import Text
    from textual.widgets import DataTable

    async def _drive() -> dict[str, object]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _load_case_01(app)
            tags = _a2l_enriched_case_01(app)
            await pilot.press("2")
            await pilot.pause()
            has_class = app.query_one("#a2l_tags_pane").has_class("density-compact")
            # Cells stay Text — render the first page and inspect a row.
            app.a2l_tags_page_size = 200
            app._a2l_window_start = 0
            app.update_a2l_tags_view(tags)
            table = app.query_one("#a2l_tags_list", DataTable)
            first_key = next(iter(app._a2l_row_key_to_tag))
            cells_are_text = all(
                isinstance(c, Text) for c in table.get_row(first_key)
            )
            # Paging unchanged: page_size 2 over 3 tags → start 0 -> 2 -> 0.
            app.a2l_tags_page_size = 2
            app._a2l_window_start = 0
            app.update_a2l_tags_view(tags)
            start0 = app._a2l_window_start
            app.action_a2l_tags_page_next()
            start1 = app._a2l_window_start
            app.action_a2l_tags_page_prev()
            start2 = app._a2l_window_start
            return {
                "has_class": has_class,
                "cells_are_text": cells_are_text,
                "paging": (start0, start1, start2),
            }

    r = asyncio.run(_drive())
    assert r["has_class"], "#a2l_tags_pane must carry 'density-compact'"
    assert r["cells_are_text"], (
        "A2L cells must remain rich.text.Text (markup must NOT be enabled)"
    )
    assert r["paging"] == (0, 2, 0), (
        f"A2L paging must still advance/retreat one page; got {r['paging']!r}"
    )


# ===========================================================================
# batch-28 Increment 2 — US-039 Issues Report grouped-by-severity dense view
# (LLR-042.3 grouping / .4 code chips / .5 selection->peek / .6 paging+filter
#  +DoS+observables / .10 C-17 markup-safety). Rail key for Issues is "5".
# ===========================================================================


def _seed_issue_objects(app: S19TuiApp, issues: list) -> None:
    """Install ``case_04`` as ``current_file`` + render ``issues`` grouped.

    Sibling of ``_seed_issues_screen`` but takes an explicit issue list (so a
    test can seed a specific severity mix — including INFO — or a hostile
    record). Flips the empty state, clears the worker precompute caches, resets
    filter=all + window 0, then renders the grouped panel (the sole Issues
    surface since batch-29) via ``update_validation_issues_view``.
    """
    from s19_app.core import S19File
    from s19_app.tui.services.load_service import build_loaded_s19

    s19 = S19File(str(_CASE_04_S19))
    loaded = build_loaded_s19(_CASE_04_S19, s19, a2l_path=None, a2l_data=None)
    app.current_file = loaded
    app._apply_empty_state()
    app._validation_issues = list(issues)
    app.validation_issue_filter_mode = "all"
    app._validation_issues_window_start = 0
    app.update_validation_issues_view()


def _mixed_issues_with_info() -> list:
    """Build a 2-error / 1-warning / 1-info issue mix (extends ``_make_issues``,
    which emits only ERROR+WARNING — AT-039b requires a seeded INFO branch)."""
    from s19_app.validation.model import ValidationIssue, ValidationSeverity

    return [
        ValidationIssue(
            code="ERR_0", severity=ValidationSeverity.ERROR, artifact="s19",
            message="e0", symbol="symE0", address=0x80000000, line_number=1,
        ),
        ValidationIssue(
            code="ERR_1", severity=ValidationSeverity.ERROR, artifact="s19",
            message="e1", symbol="symE1", address=0x80000010, line_number=2,
        ),
        ValidationIssue(
            code="WARN_0", severity=ValidationSeverity.WARNING, artifact="mac",
            message="w0", symbol="symW0", address=0x80000100, line_number=3,
        ),
        ValidationIssue(
            code="INFO_0", severity=ValidationSeverity.INFO, artifact="a2l",
            message="i0", symbol="symI0", address=None, line_number=4,
        ),
    ]


def test_at_039a_group_headers_carry_whole_filtered_counts_and_chips(
    tmp_path: Path,
) -> None:
    """AT-039a / LLR-042.3/.4/.6: one group header per present severity whose
    count == the filtered-whole-list count for that severity, and >=1 code chip
    carrying the issue code.

    Intent: seed a 2-error / 1-warning / 1-info mix and open the Issues screen.
    The grouped view must mount exactly three ``.issue-group-header`` nodes
    whose reported counts are (errors=2, warnings=1, info=1) — the WHOLE
    filtered counts, not a windowed subset — and at least one
    ``.issue-code-chip`` whose text is a seeded code. A header that miscounts
    or a dropped chip fails.
    """
    from s19_app.tui.issues_view import IssueGroupHeader

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("issues")
            _seed_issue_objects(app, _mixed_issues_with_info())
            await pilot.pause()
            headers = list(app.query(IssueGroupHeader))
            counts = {h.severity_label: h.issue_count for h in headers}
            chip_texts = [
                str(chip.render()) for chip in app.query(".issue-code-chip")
            ]
            return {"counts": counts, "chips": chip_texts}

    r = asyncio.run(_drive())
    assert r["counts"] == {"ERRORS": 2, "WARNINGS": 1, "INFO": 1}, (
        f"one header per severity with whole-filtered counts; got {r['counts']!r}"
    )
    assert any("ERR_0" in text for text in r["chips"]), (
        f"a code chip must carry the issue code; chips={r['chips']!r}"
    )


def test_at_039b_groups_render_in_error_warning_info_order(tmp_path: Path) -> None:
    """AT-039b / LLR-042.3: with >=1 error, >=1 warning and >=1 info seeded, the
    three group headers render in error -> warning -> info order (observed, C-10b).

    Intent: the INFO branch is seeded (not assumed), and the observed mount
    order of the ``.issue-group-header`` labels must be exactly
    ['ERRORS', 'WARNINGS', 'INFO']. A view that groups but mis-orders fails.
    """
    from s19_app.tui.issues_view import IssueGroupHeader

    async def _drive() -> list:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("issues")
            _seed_issue_objects(app, _mixed_issues_with_info())
            await pilot.pause()
            return [h.severity_label for h in app.query(IssueGroupHeader)]

    order = asyncio.run(_drive())
    assert order == ["ERRORS", "WARNINGS", "INFO"], (
        f"groups must render error -> warning -> info; got {order!r}"
    )


def test_at_039c_real_click_repaints_hex_peek_and_none_is_neutral(
    tmp_path: Path,
) -> None:
    """AT-039c / LLR-042.5 (C-16 real mechanism): a real ``Enter`` keypress on a
    focused NON-DEFAULT issue row repaints ``#issues_hex_pane`` at that issue's
    address; an ``address is None`` row yields the neutral peek with no crash.

    Intent: focus the third row (a warning at 0x80000100, NOT the first error)
    and press ``Enter`` — the real ``IssueRow.on_key`` -> ``Selected`` ->
    ``on_issue_row_selected`` path must repaint the hex pane and show the
    0x80000100 row label (the pane must CHANGE). Then the address-less row ->
    placeholder, no stale bytes. ``.focus()`` only positions focus; the real
    ``Enter`` keypress drives the selection, so an unwired ``on_key`` fails
    (batch-27 AT-036a C-16 precedent — Enter, not a direct setter).
    """
    from textual.widgets import Static
    from s19_app.tui.issues_view import IssueRow

    async def _select(app, pilot, row) -> str:
        row.focus()
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        return str(app.query_one("#issues_hex_pane", Static).render())

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("issues")
            _seed_issue_objects(app, _mixed_issues_with_info())
            await pilot.pause()
            before = str(app.query_one("#issues_hex_pane", Static).render())
            rows = list(app.query(IssueRow))
            # Order is [ERR_0, ERR_1, WARN_0(0x80000100), INFO_0(None)].
            addressed = await _select(app, pilot, rows[2])
            no_address = await _select(app, pilot, rows[3])
            return before, addressed, no_address

    before, addressed, no_address = asyncio.run(_drive())
    assert "80000100" in addressed, (
        f"clicking the warning row must peek at 0x80000100; pane={addressed!r}"
    )
    assert addressed != before, "the hex peek must change on selection"
    assert "no address" in no_address.lower(), (
        f"an address-less issue must show the neutral placeholder; "
        f"pane={no_address!r}"
    )
    assert "80000100" not in no_address, (
        f"the prior selection's bytes must be cleared; pane={no_address!r}"
    )


def test_at_039d_zero_issues_empty_state_and_neutral_peek(tmp_path: Path) -> None:
    """AT-039d / LLR-042.3: with a file loaded but 0 issues, the grouped view
    shows a neutral 'no issues' empty state and no rows, with a neutral peek.

    Intent: seed zero issues -> the grouped panel mounts an ``.issues-empty-note``
    (and no ``.issue-code-chip``), and the hex pane stays neutral (no crash).
    """
    from s19_app.tui.issues_view import GroupedIssuesPanel

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("issues")
            _seed_issue_objects(app, [])
            await pilot.pause()
            panel = app.query_one("#validation_issues_groups", GroupedIssuesPanel)
            return {
                "empty_notes": len(panel.query(".issues-empty-note")),
                "chips": len(panel.query(".issue-code-chip")),
            }

    r = asyncio.run(_drive())
    assert r["empty_notes"] == 1, "0 issues must show one empty-state note"
    assert r["chips"] == 0, "0 issues must mount no code chips"


def test_at_039e_c17_hostile_code_symbol_message_render_literal(
    tmp_path: Path,
) -> None:
    """AT-039e (C-17 MANDATORY) / LLR-042.10: a hostile issue whose code/symbol
    carry Rich markup + a raw ANSI byte and whose message carries markup +
    ``[link=...]`` renders LITERAL — no MarkupError, no style/ANSI leak, no
    OSC-8 hyperlink, no crash.

    Intent: seed ``code='MAP_Model[bold]'``, ``symbol='MAP_Model[bold]\\x1b[31m'``
    and ``message='open[red]sensor[/] [link=file:///etc]'``. The run must NOT
    raise ``rich.errors.MarkupError``; the code chip's plain text must contain
    the literal ``MAP_Model[bold]`` (brackets intact), and the detail's plain
    text must contain the literal ``[link=file:///etc]`` — if markup had been
    parsed, that token would have been consumed (proving no link/OSC-8 escape).
    """
    from s19_app.validation.model import ValidationIssue, ValidationSeverity

    hostile = ValidationIssue(
        code="MAP_Model[bold]",
        severity=ValidationSeverity.ERROR,
        artifact="s19",
        message="open[red]sensor[/] [link=file:///etc]",
        symbol="MAP_Model[bold]\x1b[31m",
        address=0x80000000,
        line_number=1,
    )

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("issues")
            _seed_issue_objects(app, [hostile])
            await pilot.pause()
            chip = app.query(".issue-code-chip").first()
            detail = app.query(".issue-detail").first()
            chip_plain = chip.render().plain  # Content.plain -> literal text
            detail_plain = detail.render().plain
            return chip_plain, detail_plain

    chip_plain, detail_plain = asyncio.run(_drive())
    assert "MAP_Model[bold]" in chip_plain, (
        f"the code chip must render brackets literally; chip={chip_plain!r}"
    )
    assert "[link=file:///etc]" in detail_plain, (
        f"the [link=...] token must survive as literal text (no OSC-8 parse); "
        f"detail={detail_plain!r}"
    )


def test_at_039f_dos_bound_large_issue_list_mounts_one_window(
    tmp_path: Path,
) -> None:
    """AT-039f (DoS bound) / LLR-042.6: ~5000 issues mount at most one bounded
    paging window of rows (mounted ``.issue-code-chip`` <= page_size), not O(N).

    Intent: a hostile large-N issue list must not mount thousands of widgets.
    With page_size 200 and 5000 issues the mounted chip count must be <= 200
    (and > 0) — the grouped view reuses the same paging window as the table.
    """
    from s19_app.validation.model import ValidationIssue, ValidationSeverity

    big = [
        ValidationIssue(
            code=f"C_{i}",
            severity=ValidationSeverity.ERROR if i % 2 == 0 else ValidationSeverity.WARNING,
            artifact="mac",
            message=f"m{i}",
            symbol=f"s{i}",
            address=0x80000000 + i,
            line_number=i + 1,
        )
        for i in range(5000)
    ]

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("issues")
            app.validation_issues_page_size = 200
            _seed_issue_objects(app, big)
            await pilot.pause()
            return len(app.query(".issue-code-chip")), app.validation_issues_page_size

    mounted, page_size = asyncio.run(_drive())
    assert 0 < mounted <= page_size, (
        f"mounted chips ({mounted}) must be bounded by page_size ({page_size}), "
        f"never O(N)=5000"
    )


def test_tc_042_3_group_order_and_header_counts(tmp_path: Path) -> None:
    """TC-042.3 / LLR-042.3 (white-box): the grouped renderer emits headers in
    error->warning->info order carrying whole-filtered counts as attributes.

    Intent: the ``IssueGroupHeader.issue_count`` attribute (read directly, not
    parsed from the string) equals the filtered-list count per severity, and
    the header sequence is fixed-order. Complements AT-039a/b.
    """
    from s19_app.tui.issues_view import IssueGroupHeader

    async def _drive() -> list:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("issues")
            _seed_issue_objects(app, _mixed_issues_with_info())
            await pilot.pause()
            return [(h.severity_label, h.issue_count) for h in app.query(IssueGroupHeader)]

    seq = asyncio.run(_drive())
    assert seq == [("ERRORS", 2), ("WARNINGS", 1), ("INFO", 1)], (
        f"headers must be ordered with whole-filtered counts; got {seq!r}"
    )


def test_tc_042_4_chip_colour_via_policy_no_hardcoded_hex(tmp_path: Path) -> None:
    """TC-042.4 / LLR-042.4 (white-box): each code chip carries the frozen
    ``css_class_for_severity`` sev-* class (colour via policy, no hardcoded hex),
    and there is one chip per windowed issue.

    Intent: an error chip carries ``sev-error`` and a warning chip ``sev-warning``
    — the same frozen classes ``color_policy`` maps — so the chip colour routes
    through the single source of truth. A hardcoded colour would not attach
    these classes.
    """
    from s19_app.tui.issues_view import IssueRow
    from s19_app.tui.color_policy import css_class_for_severity
    from s19_app.validation.model import ValidationSeverity

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("issues")
            _seed_issue_objects(app, _mixed_issues_with_info())
            await pilot.pause()
            rows = list(app.query(IssueRow))
            chip_classes = []
            for row in rows:
                chip = row.query(".issue-code-chip").first()
                chip_classes.append(set(chip.classes))
            return {
                "n_rows": len(rows),
                "n_chips": len(app.query(".issue-code-chip")),
                "err_class": css_class_for_severity(ValidationSeverity.ERROR),
                "warn_class": css_class_for_severity(ValidationSeverity.WARNING),
                "chip0": chip_classes[0],
                "chip2": chip_classes[2],
            }

    r = asyncio.run(_drive())
    assert r["n_chips"] == r["n_rows"] == 4, "one chip per windowed issue"
    assert r["err_class"] in r["chip0"], (
        f"error chip must carry {r['err_class']}; got {r['chip0']!r}"
    )
    assert r["warn_class"] in r["chip2"], (
        f"warning chip must carry {r['warn_class']}; got {r['chip2']!r}"
    )


def test_tc_042_5_selection_handler_drives_peek(tmp_path: Path) -> None:
    """TC-042.5 / LLR-042.5 (white-box): ``on_issue_row_selected`` repaints the
    hex peek at the message address; a None address gives the neutral peek.

    Intent: posting an ``IssueRow.Selected`` with an address reuses
    ``_update_issues_hex_pane`` to show that address; a None-address message
    shows the placeholder and clears prior bytes — no crash on either.
    """
    from textual.widgets import Static
    from s19_app.tui.issues_view import IssueRow

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("issues")
            _seed_issue_objects(app, _mixed_issues_with_info())
            await pilot.pause()
            app.on_issue_row_selected(IssueRow.Selected(0x80000100))
            await pilot.pause()
            addressed = str(app.query_one("#issues_hex_pane", Static).render())
            app.on_issue_row_selected(IssueRow.Selected(None))
            await pilot.pause()
            none_peek = str(app.query_one("#issues_hex_pane", Static).render())
            return addressed, none_peek

    addressed, none_peek = asyncio.run(_drive())
    assert "80000100" in addressed, f"addressed peek must show target; {addressed!r}"
    assert "no address" in none_peek.lower() and "80000100" not in none_peek, (
        f"None address must show neutral peek + clear bytes; {none_peek!r}"
    )


def test_tc_042_6_paging_window_preserved_and_filter_scopes(tmp_path: Path) -> None:
    """TC-042.6 / LLR-042.6 (white-box): the grouped view preserves the paging
    window (bounded mount) AND the severity filter scopes which issues render,
    while the header count stays the whole-filtered count.

    Intent: with 5000 mixed issues + page_size 200 -> mounted rows <= 200 but
    the ERROR header reports the full filtered error count. Switching the filter
    to 'error' drops the WARNING group entirely (scoped render). Paging next
    advances the mounted window (different first code).
    """
    from s19_app.tui.issues_view import IssueGroupHeader, IssueRow
    from s19_app.validation.model import ValidationIssue, ValidationSeverity

    big = [
        ValidationIssue(
            code=f"C_{i}",
            severity=ValidationSeverity.ERROR if i % 2 == 0 else ValidationSeverity.WARNING,
            artifact="mac",
            message=f"m{i}",
            symbol=f"s{i}",
            address=0x80000000 + i,
            line_number=i + 1,
        )
        for i in range(5000)
    ]

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("issues")
            app.validation_issues_page_size = 200
            _seed_issue_objects(app, big)
            await pilot.pause()
            mounted = len(app.query(IssueRow))
            err_header = next(
                h for h in app.query(IssueGroupHeader) if h.severity_label == "ERRORS"
            )
            first_code_p0 = str(list(app.query(".issue-code-chip"))[0].render())
            # Paging next must move the mounted window.
            app.action_validation_issues_page_next()
            await pilot.pause()
            first_code_p1 = str(list(app.query(".issue-code-chip"))[0].render())
            # Filter to errors only -> no WARNINGS group renders.
            app.validation_issue_filter_mode = "error"
            app._validation_issues_window_start = 0
            app.update_validation_issues_view()
            await pilot.pause()
            labels = [h.severity_label for h in app.query(IssueGroupHeader)]
            return {
                "mounted": mounted,
                "err_count": err_header.issue_count,
                "p0": first_code_p0,
                "p1": first_code_p1,
                "labels_error_filter": labels,
            }

    r = asyncio.run(_drive())
    assert r["mounted"] <= 200, f"mounted rows must be bounded; got {r['mounted']}"
    assert r["err_count"] == 2500, (
        f"ERROR header must report the whole-filtered count 2500; got {r['err_count']}"
    )
    assert r["p0"] != r["p1"], "paging next must advance the mounted window"
    assert r["labels_error_filter"] == ["ERRORS"], (
        f"the error filter must scope out the WARNINGS group; got "
        f"{r['labels_error_filter']!r}"
    )


def test_at_039g_tc_042_6b_full_page_render_is_row_capped_and_settles(
    tmp_path: Path,
) -> None:
    """AT-039g / TC-042.6b / LLR-042.6: a full ``page_size`` (200) issue page
    mounts at most ``_GROUP_DISPLAY_MAX`` rows and the render SETTLES.

    Intent — direct guard for the batch-28 Inc-2 perf regression: the grouped
    panel mounted one ``IssueRow`` (a ``Horizontal`` of two ``Static``s) per
    issue in the whole 200-row paging window → ~600 non-virtualized widgets
    remounted per ``update_validation_issues_view``, which flooded Textual's
    message pump and made the Issues screen take ~35s to settle (``pilot.pause``
    raised ``WaitForScreenTimeout``). This test seeds a FULL page of 200 issues
    through the real Issues surface and asserts the mount is row-capped (not
    ~200) and that ``pilot.pause`` returns — so a future uncapped render is
    caught HERE directly, not incidentally via the ``tc_065`` panel-render
    timeout. The mounted ``IssueRow`` count must equal the queryable chip count
    and be ``<= _GROUP_DISPLAY_MAX``, and a truncation note must be present
    (200 window > cap). Reaching the asserts at all proves no timeout.
    """
    from s19_app.tui.issues_view import (
        GroupedIssuesPanel,
        IssueRow,
        _GROUP_DISPLAY_MAX,
    )

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("issues")
            # Default page_size is 200; seed a full page so the window == 200.
            _seed_issues_screen(app, 200)
            await pilot.pause()  # must SETTLE — no WaitForScreenTimeout
            panel = app.query_one(
                "#validation_issues_groups", GroupedIssuesPanel
            )
            return {
                "rows": len(app.query(IssueRow)),
                "chips": len(app.query(".issue-code-chip")),
                "notes": len(panel.query(".issues-truncation-note")),
                "cap": _GROUP_DISPLAY_MAX,
                "page_size": app.validation_issues_page_size,
            }

    r = asyncio.run(_drive())
    assert r["page_size"] == 200, (
        f"precondition: a full page_size window; got {r['page_size']}"
    )
    assert 0 < r["rows"] <= r["cap"], (
        f"a 200-issue page must mount at most {r['cap']} rows (not ~200); "
        f"got {r['rows']}"
    )
    assert r["rows"] == r["chips"], (
        f"one code chip per mounted row; rows={r['rows']} chips={r['chips']}"
    )
    assert r["notes"] == 1, (
        "a full page beyond the display cap must show a truncation note; "
        f"got {r['notes']}"
    )


def test_tc_042_10_markup_safe_renderables_and_no_from_markup(tmp_path: Path) -> None:
    """TC-042.10 / LLR-042.10 (white-box + source): file-derived cells render
    their markup literally (composed as ``Text``, not an interpolated markup
    string), and the render module never calls ``Text.from_markup`` /
    ``markup=True`` on file text.

    Intent: complements AT-039e. For a hostile issue the chip/detail rendered
    plain text preserves the literal brackets (so the value was treated as a
    ``Text``, never markup-parsed), and a source scan of ``issues_view.py``
    finds no ``from_markup`` and no ``markup=True`` — the render surface has
    zero raw file-text-in-a-markup-string path.
    """
    from pathlib import Path as _P
    from s19_app.validation.model import ValidationIssue, ValidationSeverity

    hostile = ValidationIssue(
        code="X[bold]", severity=ValidationSeverity.WARNING, artifact="mac",
        message="m[red]", symbol="s[/]", address=None, line_number=1,
    )

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("issues")
            _seed_issue_objects(app, [hostile])
            await pilot.pause()
            chip = app.query(".issue-code-chip").first()
            detail = app.query(".issue-detail").first()
            return chip.render().plain, detail.render().plain

    chip_plain, detail_plain = asyncio.run(_drive())
    assert "X[bold]" in chip_plain, (
        f"the chip must render the code literally (Text, not markup); {chip_plain!r}"
    )
    assert "m[red]" in detail_plain and "s[/]" in detail_plain, (
        f"detail message/symbol markup must be literal; {detail_plain!r}"
    )
    import s19_app.tui.issues_view as _iv

    source = _P(_iv.__file__).read_text(encoding="utf-8")
    assert "from_markup" not in source, "issues_view must not call Text.from_markup"
    assert "markup=True" not in source, "issues_view must not enable markup on file text"


# ===========================================================================
# batch-28 (R-TUI-042) — Increment 3: US-040 Workspace dense-cockpit signal
# ===========================================================================
#
# LLR-042.7 (per-range coverage micro-bar): each `#ws_left` range row gains an
# ADDED third line — a fixed-8-cell magnitude spark whose FILL WIDTH ∝ the
# range byte-size relative to the largest rendered range (NOT a covered-
# fraction; a contiguous range is 100% covered by definition) and whose COLOUR
# is the row's validity `sev-*` class (valid→sev-ok, invalid→sev-error). The
# bar is composed markup-safe (`rich.text.Text`, no markup parse) and adds no
# horizontal width to the fixed 22-col pane (C-13).
#
# LLR-042.9 (stat pane): `#ws_right` gains a `#ws_stats` block above the
# Context — coverage % + range count (from `coverage_stats`) + error/warning
# counts (severity tally over `_validation_issues`, counting not re-validation);
# NO entropy figure (D3 descoped).
#
# ATs drive the real render path (`update_sections` → the shipped
# `#sections_list` / `#ws_stats` widgets); the pure arithmetic is pinned by
# TC-042.7 / TC-042.9.


def _section_bar_lines(app: "S19TuiApp") -> list[tuple[tuple[int, int], str, "frozenset"]]:
    """Return ``(item.data, bar_line, label.classes)`` for each range row.

    Reads the shipped ``#sections_list`` render: the range Label content is
    three lines (start / end+size / micro-bar); this returns the bar line (the
    third) plus the row's ``(start, end)`` payload and CSS classes so an AT can
    assert on the rendered bar element itself (not a proxy).
    """
    from textual.widgets import Label, ListView

    rows: list[tuple[tuple[int, int], str, "frozenset"]] = []
    sections = app.query_one("#sections_list", ListView)
    for item in sections.children:
        if not isinstance(getattr(item, "data", None), tuple):
            continue
        label = item.query_one(Label)
        lines = str(label.content).split("\n")
        bar_line = lines[2] if len(lines) >= 3 else ""
        rows.append((item.data, bar_line, label.classes))
    return rows


def _ws_stats_text(app: "S19TuiApp") -> str:
    """Return the rendered plain text of the Workspace ``#ws_stats`` pane.

    Mirrors the ``#map_stats_body`` read (``str(widget.render())``) — the
    canonical way to observe a ``Static(markup=False)`` body's text.
    """
    return str(app.query_one("#ws_stats").render())


def test_tc_042_9_stat_pane_values_pure() -> None:
    """TC-042.9 / LLR-042.9 (white-box): the stat-pane text is exactly coverage %
    + range count from ``coverage_stats`` and the passed error/warning tallies;
    an empty image shows a neutral ``—`` coverage.

    Intent: pins the stat-pane formatting AT-040c/d observe. No entropy line is
    emitted (D3 scope-negative).
    """
    from s19_app.tui.app import build_workspace_stats_text
    from s19_app.tui.screens_directionb import CoverageStats

    stats = CoverageStats(
        image_span=100, covered_bytes=42, coverage_pct=42.0,
        valid_count=2, invalid_count=1, gap_count=1, largest_gap=8, total_issues=5,
    )
    plain = build_workspace_stats_text(stats, error_count=3, warning_count=1).plain
    assert "Coverage: 42.00%" in plain
    assert "Ranges: 3" in plain, "range count = valid + invalid"
    assert "Errors: 3" in plain
    assert "Warnings: 1" in plain
    assert "entropy" not in plain.lower(), "no entropy figure (D3 descoped)"

    empty = build_workspace_stats_text(
        CoverageStats(0, 0, 0.0, 0, 0, 0, 0, 0), 0, 0
    ).plain
    assert "Coverage: —" in empty, "no-range image shows a neutral em-dash coverage"
    assert "Ranges: 0" in empty


def test_at040a_per_range_micro_bar_colour_and_width(tmp_path: Path) -> None:
    """AT-040a / LLR-042.7 (black-box, C-10b): each range row renders a micro-bar;
    its width ∝ range size (largest → widest, per-branch), and its colour class
    tracks validity (valid → sev-ok ≠ invalid → sev-error).

    Intent: observe the shipped `#sections_list` render, not a proxy. Width is
    proven over case_02 (four all-valid ranges of differing sizes); the colour
    branch is proven over case_04 (one valid + one INVALID range) so the
    valid≠invalid discriminator is actually exercised. The small-range branch
    drives a 64 B range beside a 512 KiB range — the normal firmware shape, whose
    ratio (0.012%) rounds to 0 cells without the fill floor. case_02 structurally
    cannot catch that: its four ranges are all 32-100% of the largest.
    """

    async def _drive_width() -> list[tuple[tuple[int, int], str, object]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _install_case_02_loaded_file(app)
            app.update_sections()
            await pilot.pause()
            return _section_bar_lines(app)

    async def _drive_small_range() -> list[tuple[tuple[int, int], str, object]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            loaded = _install_case_02_loaded_file(app)
            # A 64 B vector table beside a 512 KiB image: frac = 64/524288 =
            # 0.000122 → round(0.000122 * 8) == 0 filled cells without the floor.
            loaded.ranges = [(0x00000000, 0x00000040), (0x80000000, 0x80080000)]
            loaded.range_validity = [True, True]
            loaded.entropy_windows = []
            app.update_sections()
            await pilot.pause()
            return _section_bar_lines(app)

    async def _drive_colour() -> list[tuple[tuple[int, int], str, object]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _install_case_04_loaded_file(app)
            app.update_sections()
            await pilot.pause()
            return _section_bar_lines(app)

    # --- width branch (case_02, all valid) ---
    width_rows = asyncio.run(_drive_width())
    assert len(width_rows) == 4, "case_02 has four ranges"
    for data, bar_line, _classes in width_rows:
        assert "█" in bar_line, (
            f"each range row must render a micro-bar (filled glyphs); "
            f"row {data!r} bar was {bar_line!r}"
        )
    # The largest range renders a wider-or-equal bar than the smallest — and the
    # widths are NOT all identical (proves fill ∝ magnitude, not covered-fraction).
    filled = {data: bar_line.count("█") for data, bar_line, _ in width_rows}
    largest = max(filled, key=lambda d: d[1] - d[0])
    smallest = min(filled, key=lambda d: d[1] - d[0])
    assert filled[largest] >= filled[smallest]
    assert filled[largest] > filled[smallest], (
        f"the largest range's bar must be strictly wider than the smallest's "
        f"(magnitude spark); filled cells were {filled!r}"
    )

    # --- small-range branch (64 B beside 512 KiB — the counterfactual) ---
    small_rows = asyncio.run(_drive_small_range())
    assert len(small_rows) == 2, "small-range scenario has two ranges"
    small = [r for r in small_rows if (r[0][1] - r[0][0]) == 0x40]
    assert small, f"the 64 B range must render a row; rows were {small_rows!r}"
    small_bar = small[0][1]
    assert "█" in small_bar, (
        f"a range far smaller than the largest (64 B vs 512 KiB) must STILL "
        f"render a visible micro-bar (>=1 filled cell); bar was {small_bar!r}"
    )

    # --- colour branch (case_04, valid + invalid) ---
    colour_rows = asyncio.run(_drive_colour())
    assert len(colour_rows) == 2, "case_04 has a valid and an invalid range"
    valid_classes = [c for (st, en), _bar, c in colour_rows if (en - st) == 13]
    invalid_classes = [c for (st, en), _bar, c in colour_rows if (en - st) == 48]
    assert valid_classes and valid_classes[0].__contains__("sev-ok"), (
        f"the valid range row's bar must carry sev-ok; got {valid_classes!r}"
    )
    assert invalid_classes and invalid_classes[0].__contains__("sev-error"), (
        f"the invalid range row's bar must carry sev-error; got {invalid_classes!r}"
    )
    assert "sev-ok" not in invalid_classes[0], (
        "valid and invalid bars must carry DIFFERENT colour classes"
    )


def test_at040c_stat_pane_values_match_image(tmp_path: Path) -> None:
    """AT-040c / LLR-042.9 (black-box, C-10b): the stat pane shows coverage %,
    range count and error/warning tallies matching the loaded image; a case_04
    image seeded with errors shows a higher error count than a clean image.

    Intent: coverage %/range count come from `coverage_stats` over the parsed
    ranges; error/warning counts are a tally of `_validation_issues` (the app
    state the real load pipeline populates) — asserted against the exact
    computed numbers, not a proxy.
    """
    from s19_app.tui.screens_directionb import coverage_stats

    seeded = _mixed_issues_with_info()  # 2 ERROR + 1 WARNING + 1 INFO

    async def _drive_case04() -> tuple[str, object]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            loaded = _install_case_04_loaded_file(app)
            app._validation_issues = list(seeded)
            app.update_sections()
            await pilot.pause()
            return _ws_stats_text(app), loaded

    async def _drive_clean() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _install_case_02_loaded_file(app)
            app._validation_issues = []
            app.update_sections()
            await pilot.pause()
            return _ws_stats_text(app)

    text_04, loaded_04 = asyncio.run(_drive_case04())
    stats_04 = coverage_stats(loaded_04.ranges, loaded_04.range_validity, seeded)
    assert f"Coverage: {stats_04.coverage_pct:.2f}%" in text_04, (
        f"coverage % must match coverage_stats; pane was {text_04!r}"
    )
    assert f"Ranges: {len(loaded_04.ranges)}" in text_04
    assert "Errors: 2" in text_04, f"error tally must be 2; pane was {text_04!r}"
    assert "Warnings: 1" in text_04, f"warning tally must be 1; pane was {text_04!r}"

    text_clean = asyncio.run(_drive_clean())
    assert "Errors: 0" in text_clean, f"clean image error tally is 0; {text_clean!r}"
    # The discriminating assertion: case_04 (seeded errors) > clean (no errors).
    assert "Errors: 2" in text_04 and "Errors: 0" in text_clean, (
        "case_04's error count must exceed the clean image's"
    )


def test_at040d_stat_pane_neutral_when_no_file(tmp_path: Path) -> None:
    """AT-040d / LLR-042.9 (black-box, negative): with no file loaded the stat
    pane shows a neutral empty state (0 ranges, coverage ``—``) and no micro-bars
    render; no crash.

    Intent: the no-file path takes the neutral branch and never touches a parsed
    model — the panel is safe before any load.
    """

    async def _drive() -> tuple[str, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.current_file = None
            app.update_sections()
            await pilot.pause()
            return _ws_stats_text(app), len(_section_bar_lines(app))

    text, bar_rows = asyncio.run(_drive())
    assert "Ranges: 0" in text, f"no file → 0 ranges; pane was {text!r}"
    assert "Coverage: —" in text, f"no file → neutral coverage; pane was {text!r}"
    assert bar_rows == 0, "no file → no range rows (no micro-bars)"


def test_at040e_stat_pane_has_no_entropy_element(tmp_path: Path) -> None:
    """AT-040e / LLR-042.9 (black-box, scope-negative D3): with a file loaded the
    Workspace stat pane carries NO entropy sparkline / figure.

    Intent: a positive guard that the descoped entropy signal (D3) did not leak
    into the stat pane — neither as text nor as a widget under `#ws_right`.
    """

    async def _drive() -> tuple[str, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _install_case_02_loaded_file(app)
            app.update_sections()
            await pilot.pause()
            entropy_widgets = len(app.query("#ws_right #ws_entropy"))
            return _ws_stats_text(app).lower(), entropy_widgets

    text, entropy_widgets = asyncio.run(_drive())
    assert "entropy" not in text, f"stat pane must show no entropy figure; {text!r}"
    assert entropy_widgets == 0, "no entropy widget may exist under #ws_right"


def test_at040_workspace_geometry_no_clip_80_and_120(tmp_path: Path) -> None:
    """TC-042.11 / C-13 geometry gate: the batch-28 Workspace surfaces — the
    per-range micro-bar line, the stat pane AND the whole-image memory-strip band
    (LLR-042.8) — must not push any Workspace pane off-screen. All three panes
    plus the hex-scroll, sections list, stat pane, the Context scroll
    (``#a2l_scroll``, Inc-3 LOW F1) and the memory strip (``#ws_memstrip``)
    render with positive area at both the 80x24 floor and the 120x40 wide regime;
    the strip's 1-row band must leave ``#hex_scroll`` a positive height at 80x24.

    Intent: the batch-17 failure mode (a 22-col-pane change that widened or
    clipped a pane) must not recur, and the new vertical strip band must not push
    the hex view off-screen. Observing every pane's live region area is the
    discriminator: a clipped/zero-area pane (including the Context scroll a
    stat-band regression would silently shrink, or the hex the strip could crowd)
    fails.
    """

    async def _drive(size: tuple[int, int]) -> dict[str, tuple[int, int]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            _install_case_02_loaded_file(app)
            app.update_sections()
            app.update_hex_view()
            await pilot.pause()
            # #hex_scroll (the hex pane's scroll container filling #ws_center) is
            # checked rather than #hex_view, whose width is `auto` and tracks
            # content — the pane-clip gate is about the laid-out panes/containers.
            ids = (
                "#ws_left", "#ws_center", "#ws_right",
                "#hex_scroll", "#sections_list", "#ws_stats",
                "#a2l_scroll", "#ws_memstrip",
            )
            regions: dict[str, tuple[int, int]] = {}
            for wid in ids:
                region = app.query_one(wid).region
                regions[wid] = (region.width, region.height)
            return regions

    for size in ((80, 24), (120, 40)):
        regions = asyncio.run(_drive(size))
        for wid, (width, height) in regions.items():
            assert width > 0 and height > 0, (
                f"at size {size}, {wid} must render with positive area "
                f"(no clip); got width={width} height={height}"
            )


# ---------------------------------------------------------------------------
# batch-28 Increment 4 (US-040b, LLR-042.8) — Workspace whole-image memory strip.
#
# A single-row `#ws_memstrip` band above `#workspace_panes` whose cells are
# coloured valid/invalid/gap over `current_file.ranges` / `range_validity`,
# reusing the batch-27 `cell_status` / `status_to_css_class` / `cell_count_for_
# geometry` path in a rows=1 variant. The mounted cell count is BOUNDED to the
# band width so a hostile huge image never mounts unbounded cells. Workspace-only.
# ---------------------------------------------------------------------------


def _strip_cell_classes(app: "S19TuiApp") -> list[str]:
    """Return the space-joined class string of each ``#ws_memstrip`` cell.

    Reads the shipped memory-strip band render — one ``.strip-cell`` widget per
    minimap cell — so an AT can assert on the coloured cells the operator sees
    (not a proxy).
    """
    band = app.query_one("#ws_memstrip")
    return [" ".join(cell.classes) for cell in band.query(".strip-cell")]


def test_at040b_memory_strip_valid_and_gap_cells(tmp_path: Path) -> None:
    """AT-040b / LLR-042.8 + batch-47 HLR-067 (black-box, C-10b): a gapped image
    with computed entropy renders a memory strip whose covered cells carry an
    entropy ``band-*`` class AND whose gaps carry the neutral discriminator
    (``sev-neutral``), so the strip still shows BOTH covered and gap regions.

    Intent: observe the shipped ``#ws_memstrip`` cells over case_02 (mapped ranges
    separated by real gaps). Amendment A (batch-47) replaced the covered cells'
    validity colouring with an ENTROPY-BAND colouring (``entropy_style.band_style``);
    the gap discriminator (neutral) is retained. A strip that painted every cell
    one class (lost the covered/gap distinction) fails.
    """
    from s19_app.tui.color_policy import css_class_for_severity
    from s19_app.validation.model import ValidationSeverity

    async def _drive() -> list[str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _install_case_02_loaded_file(app)
            app.update_sections()
            await pilot.pause()
            return _strip_cell_classes(app)

    classes = asyncio.run(_drive())
    assert classes, "case_02 must mount memory-strip cells"
    # Covered cells now carry an entropy band-* class (Amendment A, HLR-067);
    # gaps keep the neutral class from css_class_for_severity (single source).
    gap_class = css_class_for_severity(ValidationSeverity.NEUTRAL)
    assert any("band-" in c for c in classes), (
        f"case_02's covered ranges must produce an entropy band-* cell; got {classes}"
    )
    assert any(gap_class in c for c in classes), (
        f"case_02's gaps must produce a {gap_class} cell; got {classes}"
    )


def test_at040b_memory_strip_is_workspace_only(tmp_path: Path) -> None:
    """AT-040b (scope): the memory strip is present on ``#screen_workspace`` and
    ABSENT on another rail screen (A2L, key ``2``) — it is composed only inside
    the Workspace screen, so no other screen carries a ``#ws_memstrip`` node.

    Intent: a positive Workspace-only guard (D2) — the strip must not leak into
    the A2L/MAC/Issues/Map surfaces.
    """

    async def _drive() -> tuple[int, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _install_case_02_loaded_file(app)
            app.update_sections()
            await pilot.press("2")  # real A2L rail key
            await pilot.pause()
            in_workspace = len(app.query("#screen_workspace #ws_memstrip"))
            in_a2l = len(app.query("#screen_a2l #ws_memstrip"))
            return in_workspace, in_a2l

    in_workspace, in_a2l = asyncio.run(_drive())
    assert in_workspace == 1, "the memory strip must live on #screen_workspace"
    assert in_a2l == 0, "no #ws_memstrip may exist under #screen_a2l"


def test_at040b_memory_strip_empty_when_no_file(tmp_path: Path) -> None:
    """AT-040b (negative): with no file loaded the memory strip is a neutral empty
    band — zero cells mounted — and rendering does not crash.

    Intent: the no-file path takes the neutral branch and never touches a parsed
    model; the band is safe before any load.
    """

    async def _drive() -> int:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.current_file = None
            app.update_sections()
            await pilot.pause()
            return len(_strip_cell_classes(app))

    assert asyncio.run(_drive()) == 0, "no file → neutral empty band (no cells)"


def test_at040b_memory_strip_cell_count_is_bounded(tmp_path: Path) -> None:
    """AT-040b / LLR-042.8 (DoS bound): a huge image mounts a BOUNDED number of
    strip cells — capped at the band's geometry-derived cell count
    (``cell_count_for_geometry(span, band_width, 1)``), never O(image size).

    Intent: the strip auto-scales like the batch-27 minimap; a hostile
    100-MB-span image must not mount ~10^8 widgets. The mounted count equals the
    pure geometry cap and stays ≤ the band width (rows=1) and far below the span.
    """
    from s19_app.tui.screens_directionb import cell_count_for_geometry

    huge_span = 100_000_000

    async def _drive() -> tuple[int, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.current_file = LoadedFile(
                path=tmp_path / "huge.s19",
                file_type="s19",
                mem_map={0: 0x11},
                row_bases=[0],
                ranges=[(0, huge_span)],
                range_validity=[True],
                errors=[],
                a2l_path=None,
                a2l_data=None,
            )
            app.update_sections()
            await pilot.pause()
            band = app.query_one("#ws_memstrip")
            band_width = band.content_size.width
            return len(_strip_cell_classes(app)), band_width

    mounted, band_width = asyncio.run(_drive())
    expected_cap = cell_count_for_geometry(huge_span, band_width, 1)
    assert mounted == expected_cap, (
        f"mounted strip cells must equal the geometry cap {expected_cap}; got {mounted}"
    )
    assert mounted <= band_width, "rows=1 strip mounts at most band-width cells"
    assert mounted < 10_000, (
        f"a {huge_span}-byte span must not mount O(span) cells; got {mounted}"
    )


def test_tc_042_8_strip_colour_is_pure_reuse_of_batch27_helpers() -> None:
    """TC-042.8 / LLR-042.8 (white-box): the strip's per-cell colouring and
    auto-scale are a pure function of ``ranges`` / ``range_validity`` computed via
    the reused batch-27 helpers — ``cell_status`` → ``status_to_css_class`` maps
    valid→sev-ok / invalid→sev-error / gap→sev-neutral, and
    ``cell_count_for_geometry`` bounds the cell count.

    Intent: pins that the strip reuses the frozen-safe minimap colour path (no new
    colour logic, no hard-coded hex) and that ``update_memory_strip`` reads only
    the parsed model — no new parse / coverage / validation call.
    """
    import ast
    import inspect

    from s19_app.tui.screens_directionb import (
        cell_count_for_geometry,
        cell_status,
        status_to_css_class,
    )

    # Pure colour reuse: the three statuses map to the canonical sev-* classes.
    valid = [(0, 8, True), (8, 16, False)]
    assert status_to_css_class(cell_status(0, 8, valid)) == "sev-ok"
    assert status_to_css_class(cell_status(8, 16, valid)) == "sev-error"
    assert status_to_css_class(cell_status(32, 48, valid)) == "sev-neutral"
    # Auto-scale bounds the count (rows=1): never more cells than band cols.
    assert cell_count_for_geometry(100_000_000, 40, 1) == 40
    assert cell_count_for_geometry(10, 40, 1) == 10
    assert cell_count_for_geometry(0, 40, 1) == 0

    # update_memory_strip reads LoadedFile.ranges/range_validity and calls only
    # the reused presentational helpers — no parse/validate/coverage helper.
    source = inspect.getsource(S19TuiApp.update_memory_strip)
    tree = ast.parse(source.lstrip())
    attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert "ranges" in attrs and "range_validity" in attrs, (
        "update_memory_strip must read LoadedFile.ranges / range_validity"
    )
    calls = {
        n.func.id
        for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
    }
    assert {"cell_status", "status_to_css_class", "cell_count_for_geometry"} <= calls, (
        f"update_memory_strip must reuse the batch-27 helpers; called {sorted(calls)}"
    )
    forbidden = {
        "validate_artifact_consistency",
        "build_sorted_range_index",
        "build_range_validity_s19",
        "build_range_validity_hex",
        "parse_a2l_file",
        "parse_mac_file",
    }
    assert forbidden.isdisjoint(calls), (
        f"update_memory_strip must not invoke parse/validate helpers; called {sorted(calls)}"
    )


def test_tc_042_12_memory_strip_touches_no_frozen_path() -> None:
    """TC-042.12 / LLR-042.12: the memory strip is render-side only — its render
    code lives in ``s19_app/tui/app.py`` and reuses the batch-27 public helpers
    from ``screens_directionb`` (NOT in the engine-frozen set), so it adds 0 diff
    to any engine-frozen path.

    Intent: a directionb-side pointer that the engine-frozen invariant holds; the
    authoritative 0-diff proof is the standing guard
    ``test_tc031_engine_modules_have_no_diff_vs_main`` (+ ``test_engine_unchanged``),
    which fails if any frozen path (core.py / hexfile.py / range_index.py /
    validation/ / tui/a2l.py / tui/mac.py / tui/color_policy.py) changed.
    """
    import inspect

    import s19_app.tui.app as app_module
    import s19_app.tui.screens_directionb as sdb

    # The strip renderer is defined in the non-frozen app module.
    assert inspect.getsourcefile(S19TuiApp.update_memory_strip).endswith("app.py")
    # The reused colour/geometry helpers live in the non-frozen screens module.
    for name in ("cell_status", "status_to_css_class", "cell_count_for_geometry"):
        assert hasattr(sdb, name), f"batch-27 helper {name} must be a public reuse"
    # No frozen engine module is imported into the strip's home module namespace
    # under a colour/parse alias (the strip colours only via status_to_css_class).
    assert app_module.status_to_css_class is sdb.status_to_css_class


# ---------------------------------------------------------------------------
# batch-31 (fast-dev-flow P1 quick strike) — Inc-1 geometry.
#
# AC-5 (B-06): the Workspace work-area file list is elastic (was a fixed
# 8-row cap), so taller terminals show more files.
# AC-6 (B-15): Memory Map cells render as a contiguous band — each cell
# fills its grid track with glyphs instead of one centered glyph flanked
# by blank columns.
# ---------------------------------------------------------------------------


def test_ac5_files_list_grows_beyond_legacy_cap(tmp_path: Path) -> None:
    """AC-5 / B-06: `#files_list` is elastic, not capped at 8 rows.

    Intent: the operator reported the work-area file window was too small to
    show the available files. The fix replaces the fixed `height: 8` with a
    `1fr` share of `#ws_left` (AC-5 as amended after geometry measurement):
    at 80x50 the list must exceed the old 8-row cap, and at 80x24 — where the
    pane has only ~3 content rows and the old fixed 8 OVERFLOWED it, starving
    the sections list — both lists must keep >= 1 visible row. A loaded file
    is installed first because the Workspace shows its empty-state panel
    (content hidden, heights 0) until `current_file` is set (LLR-002.3).
    """

    async def _drive(size: "tuple[int, int]") -> "tuple[int, int]":
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            _install_case_02_loaded_file(app)
            app.action_show_screen("workspace")
            await pilot.pause()
            files_h = app.query_one("#files_list").outer_size.height
            sections_h = app.query_one("#sections_list").outer_size.height
            return files_h, sections_h

    files_h, sections_h = asyncio.run(_drive((80, 50)))
    assert files_h > 8, (
        f"#files_list must exceed the legacy 8-row cap at 80x50; got {files_h}"
    )
    assert sections_h > 8, (
        f"#sections_list must share the pane elastically at 80x50; got {sections_h}"
    )
    files_h_24, sections_h_24 = asyncio.run(_drive((80, 24)))
    assert files_h_24 >= 1 and sections_h_24 >= 1, (
        "at 80x24 both lists must remain visible (the old fixed 8 overflowed "
        f"the 3-row pane); got files={files_h_24}, sections={sections_h_24}"
    )


# RETIRED batch-45 (R-TUI-060): ``test_ac6_map_cells_render_contiguous_band``
# (B-15) asserted the ``MapCell`` glyph-fill contiguity across the grid tracks.
# The entropy band view removes the cell grid entirely (the band bar is a single
# proportional segment row), so the gutter-artifact invariant no longer applies.


# ---------------------------------------------------------------------------
# batch-31 Inc-2 — AC-3 (B-04) Issues PgUp/PgDn actually page, and AC-7
# (B-20) a visible Workspace "Load project" button wired to the existing
# `action_load_project` flow.
# ---------------------------------------------------------------------------


def test_ac3_issues_pgdn_pgup_page_the_grouped_panel(tmp_path: Path) -> None:
    """AC-3 / B-04: PgDn / PgUp page the Issues window (RED-first: the keys
    named by `GroupedIssuesPanel.TRUNCATION_NOTE` had no binding at all).

    Intent: with more filtered issues than one page, pressing PgDn on the Issues
    screen must advance `_validation_issues_window_start` by one page (and
    re-render), and PgUp must rewind it — through the real key dispatch, not by
    calling the action directly. The page stride is the grouped-panel mount cap
    `_GROUP_DISPLAY_MAX`, not the configured viewer page size (field-audit B1 —
    a larger stride skipped rows past the cap).
    """
    from s19_app.tui.issues_view import _GROUP_DISPLAY_MAX
    from s19_app.validation.model import ValidationIssue, ValidationSeverity

    async def _drive() -> "tuple[int, int, int]":
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _install_case_02_loaded_file(app)
            app._validation_issues = [
                ValidationIssue(
                    code="SEEDED_ISSUE",
                    severity=ValidationSeverity.WARNING,
                    message=f"seeded issue {i}",
                    artifact="s19",
                    address=i,
                )
                for i in range(app.validation_issues_page_size * 2 + 5)
            ]
            app.action_show_screen("issues")
            app.update_validation_issues_view()
            await pilot.pause()
            start_before = app._validation_issues_window_start
            await pilot.press("pagedown")
            await pilot.pause()
            start_after_down = app._validation_issues_window_start
            await pilot.press("pageup")
            await pilot.pause()
            start_after_up = app._validation_issues_window_start
            return start_before, start_after_down, start_after_up

    before, after_down, after_up = asyncio.run(_drive())
    assert before == 0
    assert after_down == _GROUP_DISPLAY_MAX, (
        f"PgDn must advance the issues window by one page (the mount-cap "
        f"stride {_GROUP_DISPLAY_MAX}); got {after_down}"
    )
    assert after_up == 0, f"PgUp must rewind the issues window; got {after_up}"


def test_ac7_workspace_load_project_button(tmp_path: Path) -> None:
    """AC-7 / B-20: the Workspace shows a "Load project" button that opens
    the same `LoadProjectScreen` as key `p` (RED-first: no such button).

    Intent: the load-project flow existed only behind the undiscoverable `p`
    key. A visible button in the Workspace left pane must push the modal
    project list when at least one saved project exists.
    """
    from s19_app.tui.screens import LoadProjectScreen

    async def _drive() -> "tuple[bool, bool]":
        app = S19TuiApp(base_dir=tmp_path)
        (app.workarea / "demo_project").mkdir(parents=True, exist_ok=True)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _install_case_02_loaded_file(app)
            app.action_show_screen("workspace")
            await pilot.pause()
            button = app.query_one("#ws_load_project_button")
            visible = button.display and not button.has_class("hidden")
            button.press()
            await pilot.pause()
            pushed = isinstance(app.screen, LoadProjectScreen)
            return bool(visible), pushed

    visible, pushed = asyncio.run(_drive())
    assert visible, "#ws_load_project_button must be visible on the Workspace"
    assert pushed, "pressing the button must push LoadProjectScreen (same as key 'p')"


# ---------------------------------------------------------------------------
# batch-31 Inc-4 — AC-1 (B-01): Memory Map "Open in Hex View" must move the
# hex window to the selected cell's region even when the coarse cell start is
# not itself a present 16-aligned row base (the live bug: the exact-membership
# guard in `update_hex_view` silently skipped the reposition).
# ---------------------------------------------------------------------------


def _install_two_far_ranges_loaded_file(app: "S19TuiApp", tmp_path: Path) -> "object":
    """Install a synthetic two-range image whose ranges sit ~1 MiB apart.

    Each range is exactly one 200-row hex page (3200 bytes), so range B's
    rows live on page 2 — a window that stays on page 1 provably does NOT
    render them. Built through the real emit → S19File → build_loaded_s19
    pipeline (no hand-mocked LoadedFile).
    """
    from s19_app.core import S19File
    from s19_app.tui.changes import emit_s19_from_mem_map
    from s19_app.tui.services.load_service import build_loaded_s19

    ranges = [(0x1000, 0x1000 + 3200), (0x100000, 0x100000 + 3200)]
    mem_map = {
        addr: (addr & 0xFF) for start, end in ranges for addr in range(start, end)
    }
    path = tmp_path / "two_far_ranges.s19"
    path.write_text(emit_s19_from_mem_map(mem_map, ranges), encoding="ascii")
    loaded = build_loaded_s19(path, S19File(str(path)), a2l_path=None, a2l_data=None)
    app.current_file = loaded
    app._apply_empty_state()
    return loaded


# RETIRED batch-45 (R-TUI-060): ``test_ac1_open_in_hex_snaps_to_nearest_present_
# row`` (B-01) drove the Open-in-Hex nearest-present-row snap through the removed
# ``MapCell`` + ``on_map_cell_selected`` surface. RE-COVERED in Inc-3 (R-TUI-062)
# by ``test_b01_region_click_snaps_hex_to_far_range`` — a real region click over
# a far range plus the direct absent-in-gap ``update_hex_view`` snap assertion.
# (Coverage flag closed.)


# ===========================================================================
# batch-38 US-065 (B-16) / R-TUI-054 — change-set free-path label clarity
#
# The Patch Editor's change-document section title and the free-path
# ``#patch_doc_path_input`` placeholder must read as an alternative way to
# point at the SAME primary change-set (not a second / "v2" file). Per
# LLR-065.1/LLR-065.2 (01-requirements §3.1, M3): the :1854 entries-pane
# title drops the "v2" token, and the placeholder carries the
# alternative-to-dropdown framing.
# ===========================================================================

# Pinned copy — 01-requirements §3.1 / LLR-065.1 / LLR-065.2 (verbatim).
PATCH_DOC_SECTION_TITLE = "Change document (JSON)"
PATCH_DOC_PATH_PLACEHOLDER = (
    "or type a path to the same change-set JSON "
    "(alternative to the patches/ dropdown)"
)


def _patch_label_and_placeholder(tmp_path: Path) -> tuple[str, str]:
    """Open the Patch Editor and return its change-doc title + path placeholder.

    Summary:
        Drive ``S19TuiApp`` headlessly, activate the Patch Editor rail screen,
        and read the two rendered strings that US-065 relabels: the
        entries-pane change-document section-title ``Label`` (``:1854``, the
        only ``patch-section-title`` inside ``#patch_pane_entries``) and the
        ``#patch_doc_path_input`` free-path placeholder (``:1904``).

    Args:
        tmp_path: Per-test temp dir used as the app ``base_dir``.

    Returns:
        A ``(title_text, placeholder_text)`` tuple of the rendered plain-text
        strings, for verbatim assertion by AT-065a / TC-332.

    Raises:
        textual.css.query.NoMatches: If either widget is absent (compose drift).

    Data Flow:
        run_test → action_show_screen("patch") → query_one the title Label and
        the path Input → extract plain text.

    Dependencies:
        Uses:
            - S19TuiApp.action_show_screen
            - textual.widgets.Label / Input
        Used by:
            - test_at065a_change_doc_label_reads_as_dropdown_alternative
            - test_tc332_change_doc_copy_pins_verbatim

    Example:
        >>> title, placeholder = _patch_label_and_placeholder(tmp_path)
        >>> title
        'Change document (JSON)'
    """
    from textual.widgets import Label

    async def _drive() -> tuple[str, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            label = app.query_one(
                "#patch_pane_entries .patch-section-title", Label
            )
            title = str(label.render())
            placeholder = app.query_one(
                "#patch_doc_path_input", Input
            ).placeholder
            return title, placeholder

    return asyncio.run(_drive())


def test_at065a_change_doc_label_reads_as_dropdown_alternative(
    tmp_path: Path,
) -> None:
    """AT-065a: the change-doc title + free-path placeholder drop "v2" framing.

    Intent: US-065 (R-TUI-054) — a Patch Editor user reads the free-path field
    as an alternative way to point at the SAME primary change-set (not a second
    / "v2" file). Black-box through the shipped ``PatchEditorPanel`` surface:
    the entries-pane section-title ``Label`` renderable and the
    ``#patch_doc_path_input`` placeholder are asserted verbatim, the
    alternative-to-dropdown tokens are present, and the substring ``v2`` is
    absent from BOTH (C-10 content assertion, not merely non-empty).

    RED counterfactual: at ``main`` the title is ``"Change document (v2 JSON)"``
    and the placeholder ``"path to v2 change-set .json"`` — the verbatim-equality
    and "no v2" assertions fail.
    """
    title, placeholder = _patch_label_and_placeholder(tmp_path)

    assert title == PATCH_DOC_SECTION_TITLE, (
        f"section title must read {PATCH_DOC_SECTION_TITLE!r}, got {title!r}"
    )
    assert placeholder == PATCH_DOC_PATH_PLACEHOLDER, (
        f"placeholder must read {PATCH_DOC_PATH_PLACEHOLDER!r}, "
        f"got {placeholder!r}"
    )
    for token in ("alternative to", "same change-set", "patches/ dropdown"):
        assert token in placeholder, (
            f"placeholder must state it is an {token!r}; got {placeholder!r}"
        )
    assert "v2" not in title, f"title must not mention 'v2'; got {title!r}"
    assert "v2" not in placeholder, (
        f"placeholder must not mention 'v2'; got {placeholder!r}"
    )


def test_tc332_change_doc_copy_pins_verbatim(tmp_path: Path) -> None:
    """TC-332: the two rendered strings equal the pinned copy verbatim.

    Intent: LLR-065.1 / LLR-065.2 — white-box pin of the exact composed copy.
    The rendered ``#patch_pane_entries`` section-title ``Label`` and the
    ``#patch_doc_path_input`` placeholder must equal the module-level pinned
    constants byte-for-byte (the single source of truth the wording is locked
    to), with ``v2`` absent from both.
    """
    title, placeholder = _patch_label_and_placeholder(tmp_path)

    assert title == PATCH_DOC_SECTION_TITLE
    assert placeholder == PATCH_DOC_PATH_PLACEHOLDER
    assert "v2" not in title and "v2" not in placeholder
