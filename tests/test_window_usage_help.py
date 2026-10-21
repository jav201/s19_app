"""Per-window usage help — the ``?`` affordance + modal (batch-95 change 3,
HLR-140 / LLR-140.1..140.2).

The nine authored sections of ``prototypes/cambios_10_12_2026/help_sections.md``
ship operator-editable from ONE home — ``window_help.WINDOW_HELP_SECTIONS`` —
and render on the shipped ``VariantHelpScreen`` pattern: a per-window modal
with numbered steps in plain prose, no markup parsing
(``Static(markup=False)``), dismissed by Close and Esc. Each of the eight
shipped windows seats a ``?`` ghost chip beside its title (never displacing
the change-2 ``📂 Open folder`` chip) and claims the ``?`` key while one of
its widgets holds focus; the app-wide ``question_mark`` binding (stock
``HelpPanel``) is untouched and fires whenever no window-focused path claims
the key. The ninth section (Split / Join / Export) ships copy-only — inc-004
mounts its window and calls ``open_window_help("split_join_export")``.

Coverage map (test -> TC -> LLR):

- TC-707 / LLR-140.2 — ``test_tc707_section_census_nine_sections_min_three_steps``
  / ``test_tc707_copy_matches_help_sections_md_verbatim`` /
  ``test_tc707_numbering_generated_sequential`` /
  ``test_tc707_boundary_no_orphan_seats_no_blank_modal``: the data home holds
  the nine md-authored sections under the windows' keys, each >= 3
  numbered steps; the copy is a verbatim port of the operator's md (every
  shipped step string occurs in it, the md's per-section numbering is
  sequential and matches the step counts); the ``N.`` numbering is generated
  at render so operator delete/reorder can never gap it; and the boundary
  limbs — a key with no section opens nothing (never a blank modal), the
  chip/screen constructors refuse to seat an unknown key, and the eight
  shipped seats are exactly the nine keys minus ``split_join_export``.
  Scope note (batch-96): the three md-fidelity census tests iterate
  ``_EXPECTED_KEYS`` — the nine ``help_sections.md`` sections — because
  that contract froze at batch-95; the data home's tenth section
  (``changes_file_notation``, code-authored, TC-1802) is censused in
  tests/test_changes_file_notation_help.py instead.
- TC-706 / LLR-140.1 — ``test_tc706_affordance_opens_window_section_modal``
  (parametrized over all 8 windows): pressing the ``?`` chip pushes
  ``WindowHelpScreen`` with that window's section — the modal title is the
  section title and the body Static renders the numbered steps VERBATIM with
  markup parsing off. ``test_tc706_close_and_escape_dismiss`` (all 8): Close
  and Esc each dismiss. ``test_tc706_focused_question_mark_opens_same_modal``
  (all 8): with a widget of the window focused, ``?`` opens the same modal
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

#: The authored-copy source (LLR-140.2) — read-only for the fidelity census.
_HELP_SECTIONS_MD = (
    Path(__file__).resolve().parent.parent
    / "prototypes"
    / "cambios_10_12_2026"
    / "help_sections.md"
)

#: The exact nine section keys (LLR-140.2): the seven rail SCREEN_CONTAINER_IDS
#: keys + ``reports`` + the inc-004 ``split_join_export``.
_EXPECTED_KEYS = frozenset(
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
    }
)

#: (window key, chip id, rail screen key or "reports") for the eight shipped
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
#: LLR-148.6); Inc-6 adds ``flow_execution``.
_CODE_AUTHORED_SHIPPED = frozenset({"check_editor"})


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


def test_tc707_section_census_nine_sections_min_three_steps() -> None:
    """TC-707 (LLR-140.2 census): the nine md-authored sections stay present
    under the windows' keys, each >= 3 non-empty numbered steps and a title —
    9/9 keys, 9/9 with >= 3 steps.

    Scope note (batch-96 / TC-1802): the census is deliberately scoped to
    ``_EXPECTED_KEYS`` — the nine sections ported from ``help_sections.md``
    — because that md-fidelity contract froze at batch-95. The data home
    has since grown a tenth, CODE-authored section
    (``changes_file_notation``) that is not an md port; its presence and
    the exact ten-key census are asserted by tests/
    test_changes_file_notation_help.py (TC-1802), not here.
    """
    assert _EXPECTED_KEYS <= frozenset(WINDOW_HELP_SECTIONS), (
        "the data home must still hold the nine md-authored sections, keyed "
        "by the windows' keys"
    )
    for key in _EXPECTED_KEYS:
        section = WINDOW_HELP_SECTIONS[key]
        assert isinstance(section["title"], str) and section["title"], key
        steps = section["steps"]
        assert isinstance(steps, tuple) and len(steps) >= 3, (
            f"{key}: each section ships >= 3 numbered steps"
        )
        for step in steps:
            assert isinstance(step, str) and step.strip(), (
                f"{key}: no empty step may ship (a blank modal is the "
                f"boundary the contract forbids)"
            )


def test_tc707_copy_matches_help_sections_md_verbatim() -> None:
    """TC-707 (LLR-140.2, the operator-editable home): every shipped step
    string of the nine md-authored sections is a verbatim port of
    ``help_sections.md`` — the md is the source draft, so a drifted copy
    edit reddens here against the source. The batch-96
    ``changes_file_notation`` section is code-authored (not an md port);
    it is iterated here only if it ever lands in the md, and is covered by
    TC-1802 otherwise."""
    md_text = _HELP_SECTIONS_MD.read_text(encoding="utf-8")
    normalized_md = re.sub(r"\s+", " ", md_text)
    for key in _EXPECTED_KEYS:
        section = WINDOW_HELP_SECTIONS[key]
        title = str(section["title"])
        assert title in normalized_md, (
            f"{key}: the section title {title!r} must appear in the md"
        )
        for step in section["steps"]:
            assert step in normalized_md, (
                f"{key}: step not found verbatim in help_sections.md: "
                f"{step!r}"
            )


def test_tc707_numbering_generated_sequential() -> None:
    """TC-707 (LLR-140.2, the numbered-steps voice): the rendered body's
    paragraphs are numbered 1..N with no gap — the numbering is generated
    at render so the operator's delete/reorder edits can never strand a
    gap, and it matches the md's own sequential numbering per section."""
    md_text = _HELP_SECTIONS_MD.read_text(encoding="utf-8")
    # Split the md into per-section bodies at the "## " headings.
    chunks = re.split(r"(?m)^## ", md_text)[1:]
    md_numbered_counts = {}
    for chunk in chunks:
        heading = chunk.splitlines()[0]
        count = len(re.findall(r"(?m)^\d+\.", chunk))
        for key, section in WINDOW_HELP_SECTIONS.items():
            if heading.startswith(str(section["title"])):
                md_numbered_counts[key] = count
    assert frozenset(md_numbered_counts) == _EXPECTED_KEYS, (
        f"every authored section must be found in the md by its title; "
        f"matched: {sorted(md_numbered_counts)}"
    )
    # Scoped to the nine md-authored sections: the batch-96
    # ``changes_file_notation`` section is not an md port (its rendered
    # numbering is covered by TC-1802).
    for key in _EXPECTED_KEYS:
        body = section_body_text(key)
        paragraphs = body.split("\n\n")
        for number, paragraph in enumerate(paragraphs, start=1):
            assert paragraph.startswith(f"{number}. "), (
                f"{key}: paragraph {number} must render with its generated "
                f"number prefix; got {paragraph[:20]!r}"
            )
        assert len(paragraphs) == md_numbered_counts[key], (
            f"{key}: the shipped step count must match the md's numbered "
            f"items ({md_numbered_counts[key]}); got {len(paragraphs)}"
        )


def test_tc707_boundary_no_orphan_seats_no_blank_modal() -> None:
    """TC-707/TC-706 (the boundary catalog): a window with no authored
    section keeps the stock help only — the seat constructors refuse an
    unknown key, the opener pushes nothing for one (never a blank modal),
    and the shipped seats are exactly the nine keys minus the inc-004
    ``split_join_export``."""
    # Named supersession (batch-97 Inc-3, I-4): the shipped seats grow by the
    # code-authored ``check_editor`` key; the md-authored nine are unchanged.
    assert frozenset(SHIPPED_WINDOW_KEYS) == (
        _EXPECTED_KEYS - {"split_join_export"}
    ) | _CODE_AUTHORED_SHIPPED, (
        "the shipped seats are the nine md sections minus split_join_export, "
        "plus the code-authored check_editor section"
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
        ("question_mark", "show_window_usage_help", False)
    ]
