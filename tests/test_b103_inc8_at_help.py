"""Batch-103 Inc 8 — acceptance test of the Patch Editor's help window (AT-B103-I8-6, E4 AT tester).

Cases: ``.dev-flow/2026-11-05-batch-103/inc-8/02-test-cases-AT.md``. Requirement ids verified end to end:
R-PE-DEF.83, R-PE-DEF.84, R-PE-DEF.85, R-PE-DEF.86, R-PE-DEF.87.

The operator opens the window's own ``?`` chip (``#window_help_patch``), the real modal is pushed, and its painted
text (``#window_help_body`` steps and ``#window_help_keys``) is parsed with TC-B97-32's ``label — effect`` rule
(``tests/test_b97_chips_help.py::_help_lines``). Nothing is read from the help module's source text.

Control (per file): the same parser run over the Check Editor's help finds no ``STAGING SHEET`` line, so the parser
does not find the row anywhere it looks.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

from textual.widgets import Button

from s19_app.tui.app import S19TuiApp
from tests.b97_probes import settle

SIZE = (118, 54)
HELP_CHIP = "#window_help_patch"
HELP_BODY = "#window_help_body"
HELP_KEYS = "#window_help_keys"
HELP_CLOSE = "#window_help_close"


def _painted_help(app) -> str:
    """The modal's painted body and keys blocks."""
    parts = []
    for selector in (HELP_BODY, HELP_KEYS):
        found = list(app.screen.query(selector))
        if found:
            rendered = found[0].render()
            parts.append(getattr(rendered, "plain", None) or str(rendered))
    return "\n".join(parts)


def _parse(text: str) -> tuple[list[str], dict[str, str]]:
    """(numbered steps, label -> effect) of the painted help, by the TC-B97-32 rule: strip the step number, split at
    the first ``" — "``."""
    steps, lines = [], {}
    for raw in text.split("\n"):
        line = raw.strip()
        if line[:1].isdigit() and ". " in line:
            line = line.split(". ", 1)[1]
            steps.append(line)
        if " — " in line:
            label, effect = line.split(" — ", 1)
            lines[label.strip()] = effect.strip()
    return steps, lines


def _open_help(tmp_path: Path, window: str):
    """Show ``window``'s screen, press its ``?`` chip and return the painted help of the pushed modal."""

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=SIZE) as pilot:
            await settle(pilot, 4)
            app.action_show_screen(window)
            await settle(pilot, 6)
            chips = list(app.query(f"#window_help_{window}"))
            assert len(chips) == 1, f"#window_help_{window}: expected 1 chip, found {len(chips)}"
            chips[0].press()
            await settle(pilot, 6)
            assert list(app.screen.query(HELP_BODY)), "the help modal did not open"
            text = _painted_help(app)
            app.screen.query_one(HELP_CLOSE, Button).press()
            await settle(pilot, 3)
            return text

    return asyncio.run(_drive())


def test_at_b103_i8_6_help_window_shows_the_new_rows(tmp_path: Path) -> None:
    """AT-B103-I8-6 (R-PE-DEF.83/1-2, .84/1, .85/1, .86/1-3, .87/1): the Patch Editor's help window, opened from its
    chip, names the filter row / STAGING SHEET / LANDS IN and the four tabs in its first step (and none of the
    retired A2L-tab wording), and carries the `Patch script`, `STAGING SHEET`, `new =`, `field =`, `text =` and
    `Use parameter` lines the requirements pin.
    """
    steps, lines = _parse(_open_help(tmp_path, "patch"))
    assert steps, "the help window painted no numbered step"
    first = steps[0]
    first_lower = first.lower()
    # R-PE-DEF.83/1
    assert "filter row" in first_lower, first
    assert "STAGING SHEET" in first, first
    assert "LANDS IN" in first, first
    for tab in ("Patch script", "Inspector", "JSON", "Checks"):
        assert tab in first, (tab, first)
    # R-PE-DEF.83/2: no step names the retired layout
    for step in steps:
        low = step.lower()
        for retired in ("a2l tab", "a2l parameters", "on the left", "on the right"):
            assert retired not in low, (retired, step)
    # R-PE-DEF.84/1
    assert "Patch script" in lines and "entries" in lines["Patch script"], lines.get("Patch script")
    # R-PE-DEF.85/1
    sheet = lines.get("STAGING SHEET", "")
    for token in ("↑↓", "enter", "←→", "home", "end", "esc"):
        assert token in sheet.lower() or token in sheet, (token, sheet)
    # R-PE-DEF.86/1-3
    for label in ("new =", "field =", "text ="):
        assert label in lines, (label, sorted(lines))
        assert "enter" in lines[label].lower(), (label, lines[label])
    # R-PE-DEF.87/1
    use = lines.get("Use parameter", "")
    assert "Inspector" in use and "selected row" in use and "A2L tab" not in use, use


def test_at_b103_i8_6_control_other_windows_help_has_no_sheet_line(tmp_path: Path) -> None:
    """Control of AT-B103-I8-6: the Check Editor's help (same parser, same open route) has no `STAGING SHEET` line and
    no `field =` line, so the parser does not find them wherever it looks."""
    steps, lines = _parse(_open_help(tmp_path, "checks"))
    assert steps, "the checks help painted no numbered step"
    assert "STAGING SHEET" not in lines and "field =" not in lines, sorted(lines)
