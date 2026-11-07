"""Per-window usage help — the ``?`` affordance + modal (batch-95 change 3,
HLR-140 / LLR-140.1..140.2).

The help sections ship operator-editable from ONE home —
``window_help.WINDOW_HELP_SECTIONS`` (twelve code-authored sections; since
batch-101 Inc 14, ruling D-3, none is ported from the operator's
``help_sections.md`` draft and no test reads it) — and render on the shipped
modal pattern: a per-window modal with numbered steps in plain
prose, no markup parsing (``Static(markup=False)``), dismissed by Close and
Esc. Each shipped window seats a ``?`` ghost chip beside its title (never
displacing the change-2 ``📂 Open folder`` chip) and claims the ``?`` key while
one of its widgets holds focus; the app-wide ``question_mark`` binding (stock
``HelpPanel``) is untouched and fires whenever no window-focused path claims
the key. The Split / Join / Export window (opened from the palette) seats the
same chip and binding through ``WindowSection``.

Coverage map (test -> TC -> LLR):

- TC-707 / LLR-140.2 — ``test_tc707_section_census_nine_sections_min_three_steps``
  / ``test_tc707_copy_matches_help_sections_md_verbatim`` /
  ``test_tc707_numbering_generated_sequential`` /
  ``test_tc707_boundary_no_orphan_seats_no_blank_modal`` (node names kept
  from batch-95): every section has a title and at least three steps; the six
  sections Inc 14 rewrote equal the approved copy
  (``tests/support/help_copy_i14.py``) step for step; the ``N.`` numbering is
  generated at render, no stored step carries a number, and each section keeps
  its pinned step count (R-WHELP.7); and the boundary limbs — a key with no
  section opens nothing (never a blank modal), the chip/screen constructors
  refuse to seat an unknown key, and the shipped seats are exactly the
  code-authored set ``_CODE_AUTHORED_SHIPPED``.
- TC-706 / LLR-140.1 — ``test_tc706_affordance_opens_window_section_modal``
  (parametrized over all 9 chip seats): pressing the ``?`` chip pushes
  ``WindowHelpScreen`` with that window's section — the modal title is the
  section title and the body Static renders the numbered steps VERBATIM with
  markup parsing off. ``test_tc706_close_and_escape_dismiss`` (all 9): Close
  and Esc each dismiss. ``test_tc706_focused_question_mark_opens_same_modal``
  (all 9): with a widget of the window focused, ``?`` opens the same modal
  (and mounts no HelpPanel). ``test_tc706_stock_help_panel_untouched``: the
  global binding is still ``question_mark -> show_help_panel`` (show=True,
  the only app-level ``?``) and a press on the no-window-focused path (rail
  focus, the shipped startup state) still mounts the stock ``HelpPanel``.
  ``test_tc706_seat_census_header_row_and_window_section``: the chip rides
  the ``.db-screen-header`` row between the title and the open-folder chip
  (chip windows keep the folder chip rightmost — TC-703's placement still
  holds), the four non-chip windows gained the same title row, and every
  rail window's container is a ``WindowSection`` carrying exactly one
  ``show=False`` ``question_mark`` binding.

Harness: the ``App.run_test(size=(120, 36))`` pilot pattern of
``tests/test_open_folder_chips.py`` — the batch-93 pinning rule: the app
hands the tests a 118x34 screen. Chips are pressed via ``Button.press()``
after their screen is displayed (``press()`` is a no-op on a hidden screen
by Textual design); the Reports seat is pushed like TC-703 pushes
``ReportViewerScreen``.
"""
from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Tuple

import pytest
from textual.binding import Binding
from textual.containers import Horizontal
from textual.widgets import Button, HelpPanel, Label, Static

from s19_app.tui.app import S19TuiApp
from s19_app.tui.open_folder_chip import HEADER_ROW_CLASS
from s19_app.tui.screens import ReportViewerScreen
from s19_app.tui.window_help import (
    SHIPPED_WINDOW_KEYS,
    WINDOW_HELP_SECTIONS,
    WindowHelpChip,
    WindowHelpScreen,
    WindowSection,
    open_window_help,
    section_body_text,
)

#: The sections still ported from the operator's untracked
#: ``help_sections.md`` draft. Named supersession (batch-101 Inc 14,
#: orchestrator ruling D-3): the last four (``checks``, ``a2l``, ``workspace``,
#: ``split_join_export``) are rewritten code-authored (F-37 / D7-26) and no
#: test reads the draft any more -- it is in no clone, so the md-reading arms
#: failed with ``FileNotFoundError`` before any assertion. The set is empty.
_EXPECTED_KEYS: frozenset = frozenset()

#: (window key, chip id, rail screen key or "reports") for the nine shipped chip
#: surfaces.
_SEATS: Tuple[Tuple[str, str, str], ...] = (
    ("patch", "#window_help_patch", "patch"),
    ("checks", "#window_help_checks", "checks"),
    ("crc_designer", "#window_help_crc_designer", "crc_designer"),
    ("map", "#window_help_map", "map"),
    ("flow", "#window_help_flow", "flow"),
    ("a2l", "#window_help_a2l", "a2l"),
    ("workspace", "#window_help_workspace", "workspace"),
    ("reports", "#window_help_reports", "reports"),
    ("check_editor", "#window_help_check_editor", "check_editor"),
)

#: Code-authored shipped sections (not md ports, so outside TC-707's md
#: fidelity census): batch-97 Inc-3 adds ``check_editor`` (D10 / D25,
#: LLR-148.6); Inc-4 adds ``patch``, and at its gate ``crc_designer`` and
#: ``reports`` (their step 6 names the folder; the draft is not versioned);
#: Inc-5 adds ``flow``; Inc-6 adds ``flow_execution``.
# batch-97 Inc-6 (named supersession, D25 / I-4): ``flow_execution`` joins the
# code-authored shipped seats (LLR-148.6).
# batch-101 Inc 14 (named supersession, orchestrator ruling D-3): ``checks``,
# ``a2l`` and ``workspace`` join the code-authored shipped seats.
_CODE_AUTHORED_SHIPPED = frozenset(
    {
        "check_editor",
        "patch",
        "crc_designer",
        "reports",
        "flow",
        "flow_execution",
        "map",
        "checks",
        "a2l",
        "workspace",
    }
)


async def _pilot_pause(pilot) -> None:
    for _ in range(4):
        await pilot.pause()


async def _show_seat(app: S19TuiApp, pilot, screen_key: str) -> object:
    """Display the seat's window (rail screen or the Reports modal)."""
    if screen_key == "reports":
        modal = ReportViewerScreen("proj1", [])
        app.push_screen(modal)
        await _pilot_pause(pilot)
        return modal
    app.action_show_screen(screen_key)
    await _pilot_pause(pilot)
    return app


async def _open_via_chip(app: S19TuiApp, pilot, screen_key: str, chip_id: str):
    """Show the window and press its ``?`` chip — returns the pushed modal."""
    root = await _show_seat(app, pilot, screen_key)
    chip = root.query_one(chip_id, WindowHelpChip)
    chip.press()
    await _pilot_pause(pilot)
    return app.screen


# --------------------------------------------------------------------------- #
# TC-707 / LLR-140.2 — the section census
# --------------------------------------------------------------------------- #


#: The twelve section keys of the data home (R-WHELP.7).
_ALL_SECTION_KEYS = frozenset(
    {
        "patch",
        "checks",
        "crc_designer",
        "reports",
        "map",
        "flow",
        "a2l",
        "workspace",
        "split_join_export",
        "flow_execution",
        "check_editor",
        "changes_file_notation",
    }
)

#: The pinned step count of every section (R-WHELP.7 (c)). A later increment
#: that changes a count updates its pin by named supersession.
_PINNED_STEP_COUNTS = {
    "patch": 43,
    "checks": 6,
    "crc_designer": 6,
    "reports": 6,
    "map": 4,
    "flow": 59,
    "a2l": 5,
    "workspace": 5,
    "split_join_export": 8,
    "flow_execution": 35,
    "check_editor": 25,
    "changes_file_notation": 4,
}


def _census_defects(sections: dict) -> list:
    """Sections with no title, fewer than 3 steps, or an empty step."""
    defects = []
    for key, section in sections.items():
        if not (isinstance(section["title"], str) and section["title"]):
            defects.append((key, "title"))
        steps = section["steps"]
        if not (isinstance(steps, tuple) and len(steps) >= 3):
            defects.append((key, "fewer than 3 steps"))
            continue
        for number, step in enumerate(steps, start=1):
            if not (isinstance(step, str) and step.strip()):
                defects.append((key, f"empty step {number}"))
    return defects


def test_tc707_section_census_nine_sections_min_three_steps() -> None:
    """TC-707 (R-WHELP.7/1 census; node name kept): EVERY section of the data
    home (12) has a title and >= 3 non-empty steps.

    Named supersession (batch-101 Inc 14, D-3): the census used to cover the
    four sections still ported from the untracked ``help_sections.md``; that
    contract is retired, so it now covers all twelve and reads no file.
    Negative control: a section cut to two steps, one with a blank step and one
    with no title are each reported.
    """
    assert frozenset(WINDOW_HELP_SECTIONS) == _ALL_SECTION_KEYS
    assert _census_defects(WINDOW_HELP_SECTIONS) == []
    broken = {
        **WINDOW_HELP_SECTIONS,
        "checks": {
            **WINDOW_HELP_SECTIONS["checks"],
            "steps": WINDOW_HELP_SECTIONS["checks"]["steps"][:2],
        },
        "a2l": {**WINDOW_HELP_SECTIONS["a2l"], "steps": ("one", " ", "three")},
        "workspace": {**WINDOW_HELP_SECTIONS["workspace"], "title": ""},
    }
    assert {key for key, _why in _census_defects(broken)} == {
        "checks",
        "a2l",
        "workspace",
    }


def _copy_defects(sections: dict, copy_sections: dict, flow_steps: dict) -> list:
    """Where the shipped sections differ from the approved copy."""
    defects = []
    for key, (title, steps) in copy_sections.items():
        if sections[key]["title"] != title:
            defects.append((key, "title"))
        if tuple(sections[key]["steps"]) != steps:
            defects.append((key, "steps"))
    for number, text in flow_steps.items():
        if sections["flow"]["steps"][number - 1] != text:
            defects.append(("flow", number))
    return defects


def test_tc707_copy_matches_help_sections_md_verbatim() -> None:
    """TC-707 (R-WHELP.12/4; node name kept, it no longer reads the md): the
    six rewritten sections (A2L Explorer, Workspace, Checks, CRC Designer,
    Reports, Split / Join / Export: titles and 36 steps) and the six changed
    Flow Builder steps (1, 5, 12, 17, 18, 19) equal the approved copy, pinned
    in ``tests/support/help_copy_i14.py``; the help sections hold exactly the
    12 keys.

    Named supersession (batch-101 Inc 14, D-3). Negative control: the base
    text of one Flow Builder step and of one rewritten step are each reported.
    """
    from tests.support.help_copy_i14 import FLOW_STEPS, REWRITTEN_SECTIONS

    assert frozenset(WINDOW_HELP_SECTIONS) == _ALL_SECTION_KEYS
    assert sum(len(steps) for _title, steps in REWRITTEN_SECTIONS.values()) == 36
    assert len(FLOW_STEPS) == 6
    assert _copy_defects(WINDOW_HELP_SECTIONS, REWRITTEN_SECTIONS, FLOW_STEPS) == []
    flow = list(WINDOW_HELP_SECTIONS["flow"]["steps"])
    flow[0] += " (LLR-003.7)"
    a2l = list(WINDOW_HELP_SECTIONS["a2l"]["steps"])
    a2l[0] = "Open the section tree."
    broken = {
        **WINDOW_HELP_SECTIONS,
        "flow": {**WINDOW_HELP_SECTIONS["flow"], "steps": tuple(flow)},
        "a2l": {**WINDOW_HELP_SECTIONS["a2l"], "steps": tuple(a2l)},
    }
    assert set(_copy_defects(broken, REWRITTEN_SECTIONS, FLOW_STEPS)) == {
        ("flow", 1),
        ("a2l", "steps"),
    }


_STORED_NUMBER = re.compile(r"^\s*\d+[.)]\s")


def _numbering_defects(sections: dict, bodies: dict = None) -> list:
    """(a) the body is the steps numbered ``f"{n}. {step}"``, joined by blank
    lines; (b) no stored step starts with its own number; (c) the step count is
    the pinned one."""
    defects = []
    for key, section in sections.items():
        steps = section["steps"]
        body = bodies[key] if bodies is not None else section_body_text(key)
        expected = [f"{n}. {step}" for n, step in enumerate(steps, start=1)]
        if body != "\n\n".join(expected):
            defects.append((key, "a"))
        if any(_STORED_NUMBER.match(step) for step in steps):
            defects.append((key, "b"))
        if len(steps) != _PINNED_STEP_COUNTS[key]:
            defects.append((key, "c"))
    return defects


def test_tc707_numbering_generated_sequential() -> None:
    """TC-707 (R-WHELP.7/1, E3 A-3; node name kept, it no longer reads the
    md): in all 12 sections (a) paragraph n of the rendered body equals
    ``f"{n}. {steps[n-1]}"`` -- the numbering is generated at render so an
    edit can never leave a gap; (b) no stored step starts with its own number;
    (c) the step count equals the pinned count.

    Negative controls: a stored step ``1. Checks run ...`` reddens (b); one
    step dropped from any section reddens (c); a gap in a rendered body
    reddens (a).
    """
    assert _numbering_defects(WINDOW_HELP_SECTIONS) == []
    checks = WINDOW_HELP_SECTIONS["checks"]
    stored = {
        **WINDOW_HELP_SECTIONS,
        "checks": {
            **checks,
            "steps": ("1. Checks run in the Patch Editor.",) + tuple(checks["steps"][1:]),
        },
    }
    assert ("checks", "b") in _numbering_defects(stored)
    reports = WINDOW_HELP_SECTIONS["reports"]
    dropped = {
        **WINDOW_HELP_SECTIONS,
        "reports": {**reports, "steps": reports["steps"][:-1]},
    }
    assert ("reports", "c") in _numbering_defects(dropped)
    gapped = {key: section_body_text(key) for key in WINDOW_HELP_SECTIONS}
    gapped["workspace"] = gapped["workspace"].replace("2. ", "3. ", 1)
    assert ("workspace", "a") in _numbering_defects(WINDOW_HELP_SECTIONS, gapped)


def test_tc707_boundary_no_orphan_seats_no_blank_modal() -> None:
    """TC-707/TC-706 (the boundary catalog): a window with no authored
    section keeps the stock help only — the seat constructors refuse an
    unknown key, the opener pushes nothing for one (never a blank modal),
    and the shipped chip seats are exactly the code-authored set (the
    Split / Join / Export window seats its chip through ``WindowSection``)."""
    # Named supersession (batch-97 Inc-3, I-4): the shipped seats grow by the
    # code-authored ``check_editor`` key; the md-authored nine are unchanged.
    # Named supersession (batch-101 Inc 14, D-3): ``_EXPECTED_KEYS`` is empty
    # and ``checks``, ``a2l``, ``workspace`` join ``_CODE_AUTHORED_SHIPPED``;
    # the seat formula is unchanged and still holds.
    assert frozenset(SHIPPED_WINDOW_KEYS) == (
        _EXPECTED_KEYS - {"split_join_export"}
    ) | _CODE_AUTHORED_SHIPPED, (
        "the shipped seats are the code-authored sections (no md-ported "
        "section remains, D-3)"
    )
    for key in WINDOW_HELP_SECTIONS:
        body = section_body_text(key)
        assert body.startswith("1. ") and len(body) > 0, (
            f"{key}: no section may render a blank modal"
        )
    # Unknown keys: no seat, no modal, no crash.
    with pytest.raises(ValueError):
        WindowHelpChip("no_such_window")
    with pytest.raises(ValueError):
        WindowHelpScreen("no_such_window")
    with pytest.raises(ValueError):
        WindowSection("no_such_window")
    # The opener never touches the app for a key with no section.
    assert open_window_help(None, "no_such_window") is False


# --------------------------------------------------------------------------- #
# TC-706 / LLR-140.1 — per-window modal: open, render, dismiss
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("window_key,chip_id,screen_key", _SEATS)
def test_tc706_affordance_opens_window_section_modal(
    tmp_path: Path,
    window_key: str,
    chip_id: str,
    screen_key: str,
) -> None:
    """TC-706 (LLR-140.1): the ``?`` affordance on each of the 8 shipped
    windows opens the modal with THAT window's section — title + steps —
    and the body renders the copy verbatim with markup parsing off."""

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await _pilot_pause(pilot)
            screen = await _open_via_chip(app, pilot, screen_key, chip_id)
            assert isinstance(screen, WindowHelpScreen)
            title = screen.query_one(".modal-title", Label)
            body = screen.query_one("#window_help_body", Static)
            return {
                "section_key": screen.section_key,
                "title": str(title.render()),
                "markup_off": body._render_markup is False,
                "verbatim": body.content == section_body_text(window_key),
                "non_empty": len(str(body.content)) > 0,
            }

    observed = asyncio.run(_drive())
    section = WINDOW_HELP_SECTIONS[window_key]
    assert observed["section_key"] == window_key
    assert observed["title"] == str(section["title"]), (
        "the modal title is the authored section title"
    )
    assert observed["markup_off"], "the copy must render with markup=False"
    assert observed["verbatim"], (
        "the body must be the verbatim numbered port — no markup parsing, "
        "no re-flow of the operator copy"
    )
    assert observed["non_empty"]


@pytest.mark.parametrize("window_key,chip_id,screen_key", _SEATS)
def test_tc706_close_and_escape_dismiss(
    tmp_path: Path,
    window_key: str,
    chip_id: str,
    screen_key: str,
) -> None:
    """TC-706 (LLR-140.1, the empty boundary): Close and Esc each dismiss
    the modal 1/1 on every shipped window."""

    async def _drive() -> Tuple[bool, bool]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await _pilot_pause(pilot)
            await _open_via_chip(app, pilot, screen_key, chip_id)
            app.screen.query_one("#window_help_close", Button).press()
            await _pilot_pause(pilot)
            closed = not isinstance(app.screen, WindowHelpScreen)
            # Reopen for the Esc limb — the chip queries from whichever
            # root holds it (the main screen, or the Reports modal).
            root = app.screen if screen_key == "reports" else app
            chip = root.query_one(chip_id, WindowHelpChip)
            chip.press()
            await _pilot_pause(pilot)
            await pilot.press("escape")
            await _pilot_pause(pilot)
            escaped = not isinstance(app.screen, WindowHelpScreen)
            return closed, escaped

    closed, escaped = asyncio.run(_drive())
    assert closed, f"{window_key}: Close must dismiss the modal"
    assert escaped, f"{window_key}: Esc must dismiss the modal"


@pytest.mark.parametrize("window_key,chip_id,screen_key", _SEATS)
def test_tc706_focused_question_mark_opens_same_modal(
    tmp_path: Path,
    window_key: str,
    chip_id: str,
    screen_key: str,
) -> None:
    """TC-706 (LLR-140.1, the focused-window key): with a widget of the
    window focused, ``?`` opens the same per-window modal (and mounts no
    stock HelpPanel) — the binding is window-scoped and ``show=False``."""

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await _pilot_pause(pilot)
            root = await _show_seat(app, pilot, screen_key)
            chip = root.query_one(chip_id, WindowHelpChip)
            chip.focus()
            await pilot.pause()
            await pilot.press("question_mark")
            await _pilot_pause(pilot)
            opened = isinstance(app.screen, WindowHelpScreen)
            section_key = getattr(app.screen, "section_key", None)
            help_panels = len(app.query(HelpPanel))
            await pilot.press("escape")
            await _pilot_pause(pilot)
            dismissed = not isinstance(app.screen, WindowHelpScreen)
            return {
                "opened": opened,
                "section_key": section_key,
                "help_panels": help_panels,
                "dismissed": dismissed,
            }

    observed = asyncio.run(_drive())
    assert observed["opened"], (
        f"{window_key}: `?` with the window focused must open its usage modal"
    )
    assert observed["section_key"] == window_key
    assert observed["help_panels"] == 0, (
        "the window-scoped `?` must not mount the stock HelpPanel"
    )
    assert observed["dismissed"]


def test_tc706_stock_help_panel_untouched(tmp_path: Path) -> None:
    """TC-706 (LLR-140.1, the negative control): the global ``question_mark``
    binding still names ``show_help_panel`` (show=True, the only app-level
    ``?``), and a press with no window-focused path — the shipped startup
    state, focus on the rail — still mounts the stock ``HelpPanel``."""

    question_mark_bindings = [
        binding
        for binding in S19TuiApp.BINDINGS
        if (binding.key if isinstance(binding, Binding) else binding[0])
        == "question_mark"
    ]
    assert len(question_mark_bindings) == 1, (
        "exactly one application binding may claim `?`"
    )
    binding = question_mark_bindings[0]
    assert isinstance(binding, Binding)
    assert binding.action == "show_help_panel", (
        "the stock `?` action name must stay show_help_panel (untouched)"
    )
    assert binding.show is True

    async def _drive() -> Tuple[int, int, int, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await _pilot_pause(pilot)
            start = len(app.query(HelpPanel))
            await pilot.press("question_mark")
            await _pilot_pause(pilot)
            opened = len(app.query(HelpPanel))
            opened_screen = type(app.screen).__name__
            await pilot.press("question_mark")
            await _pilot_pause(pilot)
            closed = len(app.query(HelpPanel))
            return start, opened, closed, opened_screen

    start, opened, closed, opened_screen = asyncio.run(_drive())
    assert start == 0
    assert opened == 1, (
        "a `?` press with no window-focused path must still mount the stock "
        "HelpPanel"
    )
    assert opened_screen != "WindowHelpScreen"
    assert closed == 0, "the shipped toggle still hides it on the second press"


def test_tc706_seat_census_header_row_and_window_section(tmp_path: Path) -> None:
    """TC-706 (LLR-140.1, the seats): every rail window's container is a
    ``WindowSection`` (the focused-`?` binding, exactly one ``show=False``
    ``question_mark`` binding each), the ``?`` chip rides the
    ``.db-screen-header`` row between the title and the open-folder chip
    (the chip windows keep the folder chip rightmost — TC-703's placement
    assertion is unchanged), and no seat exists for ``split_join_export``."""
    rail_seats = [seat for seat in _SEATS if seat[2] != "reports"]
    # batch-97 Inc-3 (D9): the Check Editor seat carries its suffixed chip.
    folder_chip_windows = {
        "patch": "open_folder_patch",
        "checks": "open_folder_checks",
        "crc_designer": "open_folder_templates",
        "check_editor": "open_folder_checks_editor",
        # batch-97 Inc-5 (LLR-148.5, named supersession): the Flow Builder
        # header gains the `📂 Open flows/` chip, rightmost like the others.
        "flow": "open_folder_flows",
    }

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await _pilot_pause(pilot)
            observed = {}
            for window_key, chip_id, screen_key in rail_seats:
                app.action_show_screen(screen_key)
                await _pilot_pause(pilot)
                section = app.query_one(f"#screen_{screen_key}", WindowSection)
                row = section.query_one(f".{HEADER_ROW_CLASS}", Horizontal)
                child_ids = [getattr(child, "id", None) for child in row.children]
                observed[window_key] = {
                    "section_key": section._window_help_key,
                    "child_ids": child_ids,
                    "bindings": [
                        (b.key, b.action, b.show) for b in WindowSection.BINDINGS
                    ],
                }
            modal = ReportViewerScreen("proj1", [])
            app.push_screen(modal)
            await _pilot_pause(pilot)
            modal_row = modal.query_one(f".{HEADER_ROW_CLASS}", Horizontal)
            observed["reports"] = {
                "child_ids": [
                    getattr(child, "id", None) for child in modal_row.children
                ],
                "bindings": [
                    (b.key, b.action, b.show) for b in ReportViewerScreen.BINDINGS
                ],
            }
            return observed

    observed = asyncio.run(_drive())

    for window_key, chip_id, screen_key in _SEATS:
        seat = observed[window_key]
        if screen_key != "reports":
            assert seat["section_key"] == window_key
            assert seat["bindings"] == [
                ("question_mark", "show_window_usage_help", False)
            ], "one window-scoped show=False `?` binding per rail window"
        if window_key in folder_chip_windows or window_key == "reports":
            expected_folder_chip = (
                "open_folder_reports"
                if window_key == "reports"
                else folder_chip_windows[window_key]
            )
            assert seat["child_ids"] == [
                None,
                f"window_help_{window_key}",
                expected_folder_chip,
            ], (
                f"{window_key}: [title label, `?` chip, open-folder chip] — "
                f"the folder chip stays rightmost (TC-703 unchanged)"
            )
        else:
            assert seat["child_ids"] == [None, f"window_help_{window_key}"], (
                f"{window_key}: [title label, `?` chip]"
            )
    assert observed["reports"]["child_ids"] == [
        None,
        "window_help_reports",
        "open_folder_reports",
    ]
    assert observed["reports"]["bindings"] == [
        ("question_mark", "show_window_usage_help", False),
        ("escape", "close_reports", False),
    ]


# ---------------------------------------------------------------------------
# batch-97 Inc-7 (Inc-8 ux-review F3) — a help modal taller than the terminal
# scrolls, so every line of its steps and keys block can be read
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("size", [(80, 24), (118, 54), (220, 60)])
def test_help_modal_fits_and_every_line_is_reachable_by_key(tmp_path: Path, size) -> None:
    """batch-97 Inc-7 (Inc-8 ux F3, LLR-148.6's help with the generated keys
    block): on every window's help modal the dialog lies inside the terminal
    (its title and its Close button on screen), and every non-blank line of
    the steps and of the keys block is painted at some point while the
    operator scrolls the body by key — ``pagedown`` (bounded) with the focus
    left on Close, no ``tab`` first (Inc-7 fix round, ux UX-F1) — so no line
    is cut off above or below. A line is found by its head (first 20 cells)
    and by its tail (its last word: a word wrap never splits it, while a
    fixed 20-cell tail can straddle a wrap), so a wrapped line's end cannot
    hide (code-reviewer CR-F4).

    RED on HEAD 5cb7618 (executed, ``evidence/inc-7/red.txt``): at 118x54 the
    Patch Editor dialog is 105 rows with its top at row -48, and the Flow
    Builder and Flow Execution keys blocks are never painted; at 80x24 every
    dialog overflows. Mutation: the body unwrapped from its scroll container."""
    from tests.b97_probes import painted_rows

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        report = {}
        async with app.run_test(size=size) as pilot:
            await _pilot_pause(pilot)
            for key in WINDOW_HELP_SECTIONS:
                assert open_window_help(app, key)
                await _pilot_pause(pilot)
                screen = app.screen
                dialog = screen.query_one("#window_help_dialog")
                close = screen.query_one("#window_help_close")
                inside = all(
                    r.x >= 0 and r.y >= 0 and r.right <= size[0] and r.bottom <= size[1]
                    for r in (dialog.region, close.region)
                )
                texts = [str(w.render()) for w in screen.query("#window_help_body, #window_help_keys")]
                lines = [ln.strip() for t in texts for ln in t.split("\n") if ln.strip()]
                seen = set(painted_rows(app, screen, screen.region))
                body = screen.query_one("#window_help_body")
                scroller = next((a for a in body.ancestors if getattr(a, "max_scroll_y", 0) > 0), None)
                focus_kept = True
                if scroller is not None:
                    pages = 0
                    while scroller.scroll_y < scroller.max_scroll_y and pages < 60:
                        await pilot.press("pagedown")
                        # page_down animates: read once the scroll has come to rest
                        await _scroll_at_rest(app, pilot, scroller)
                        seen.update(painted_rows(app, screen, screen.region))
                        pages += 1
                    focus_kept = app.focused is close
                painted = "\n".join(seen)
                missing = [ln for ln in lines if ln[:20] not in painted or ln.split()[-1] not in painted]
                report[key] = (inside and focus_kept, missing, tuple(dialog.region))
                await pilot.press("escape")
                await _pilot_pause(pilot)
        return report

    report = asyncio.run(_drive())
    assert set(report) == set(WINDOW_HELP_SECTIONS), "guard: every section was opened"
    bad = {k: v for k, v in report.items() if not v[0] or v[1]}
    assert bad == {}, {k: (inside, missing[:3], region) for k, (inside, missing, region) in bad.items()}


#: Inc-7 fix round (ux UX-F1): the keys that scroll the help body while Close
#: keeps the focus, and the scroll each one must cause from the top.
HELP_SCROLL_KEYS = ("down", "pagedown", "end", "up", "pageup", "home")


async def _scroll_at_rest(app, pilot, scroller) -> None:
    """Wait until ``scroller``'s scroll animation has finished. Comparing two
    consecutive reads is not enough: under full-suite load two pauses can pass
    with no animation frame between them (Inc-7 full suite, ``end`` read at
    92 of 150)."""
    for _ in range(250):
        await pilot.pause(0.02)
        if not app.animator.is_being_animated(scroller, "scroll_y") and scroller.scroll_y == scroller.scroll_target_y:
            return


def test_help_modal_scrolls_by_key_while_close_keeps_the_focus(tmp_path: Path) -> None:
    """batch-97 Inc-7 fix round (ux UX-F1): a help modal opens with the focus
    on Close, and the body scrolls from there — ``down`` one row,
    ``pagedown`` a page, ``end`` to the last row (the last keys line
    painted), ``up`` / ``pageup`` back, ``home`` to the top — with no ``tab``
    first. Close keeps the focus throughout, so ``enter`` still closes the
    modal. One arm ``tab``s into the body first and ``pagedown`` still
    scrolls there. Run at 80x24, where every section overflows.

    RED on the first-round tree (executed, ``evidence/inc-7/red-r2.txt``):
    with Close focused every key leaves ``scroll_y`` at 0. Mutation: the
    screen's scroll bindings removed."""
    from tests.b97_probes import painted_rows

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        report = {}
        async with app.run_test(size=(80, 24)) as pilot:
            await _pilot_pause(pilot)
            for key in WINDOW_HELP_SECTIONS:
                assert open_window_help(app, key)
                await _pilot_pause(pilot)
                screen = app.screen
                scroll = screen.query_one("#window_help_scroll")
                close = screen.query_one("#window_help_close")
                focused_on_open = app.focused is close
                ys = {}
                for name in HELP_SCROLL_KEYS:
                    await pilot.press(name)
                    await _scroll_at_rest(app, pilot, scroll)  # scrolls animate: read once at rest
                    ys[name] = scroll.scroll_y
                    if name == "end":
                        last = str(screen.query("#window_help_keys, #window_help_body").last().render()).strip().split("\n")[-1].strip()
                        ys["last_painted"] = last[:20] in "\n".join(painted_rows(app, screen, screen.region))
                report[key] = (focused_on_open, scroll.max_scroll_y, ys, app.focused is close)
                await pilot.press("enter")
                await _pilot_pause(pilot)
                report[key] += (not isinstance(app.screen, WindowHelpScreen),)
            assert open_window_help(app, "patch")
            await _pilot_pause(pilot)
            scroll = app.screen.query_one("#window_help_scroll")
            await pilot.press("tab")
            await pilot.pause()
            focused_scroll = app.focused is scroll
            await pilot.press("pagedown")
            await _scroll_at_rest(app, pilot, scroll)
            report["tab-arm"] = (focused_scroll, scroll.scroll_y)
        return report

    report = asyncio.run(_drive())
    tab_focus, tab_y = report.pop("tab-arm")
    assert tab_focus and tab_y > 0, ("after tab, pagedown still scrolls", tab_focus, tab_y)
    bad = {}
    for key, (on_open, max_y, ys, still_close, closed) in report.items():
        ok = (
            on_open and still_close and closed and max_y > 0
            and ys["down"] == 1
            and ys["pagedown"] > ys["down"]
            and ys["end"] == max_y and ys["last_painted"]
            and ys["up"] == max_y - 1
            and ys["pageup"] < ys["up"]
            and ys["home"] == 0
        )
        if not ok:
            bad[key] = (on_open, max_y, ys, still_close, closed)
    assert bad == {}, bad


def test_help_modal_close_names_its_key_and_the_keys_block_stands_apart(tmp_path: Path) -> None:
    """batch-97 Inc-7 fix round (ux UX-F3, UX-F4): the Close button paints
    the key that closes the modal (``Close  esc``, the ``EXPORT  e``
    form), and the generated keys block starts after one blank row below the
    last step, so a key line never reads as part of that step.

    RED on the first-round tree (executed, ``evidence/inc-7/red-r2.txt``):
    the button paints ``Close`` and the keys block's first row sits directly
    under the last step. Mutations: the key dropped from the label; the
    keys block's top margin removed."""
    from tests.b97_probes import painted_rows

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        out = {}
        async with app.run_test(size=(118, 54)) as pilot:
            await _pilot_pause(pilot)
            for key in WINDOW_HELP_SECTIONS:
                assert open_window_help(app, key)
                await _pilot_pause(pilot)
                screen = app.screen
                label = [t for t in " ".join(painted_rows(app, screen.query_one("#window_help_close"))).split() if t.isalnum()]
                keys = screen.query("#window_help_keys")
                gap = None
                if keys:
                    body = screen.query_one("#window_help_body")
                    gap = keys.first().virtual_region.y - body.virtual_region.bottom
                out[key] = (label, gap)
                await pilot.press("escape")
                await _pilot_pause(pilot)
        return out

    out = asyncio.run(_drive())
    assert any(gap is not None for _label, gap in out.values()), "guard: some section has a keys block"
    bad = {k: v for k, v in out.items() if v[0] != ["Close", "esc"] or (v[1] is not None and v[1] < 1)}
    assert bad == {}, bad
