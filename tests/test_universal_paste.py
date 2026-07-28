"""batch-66 AC-1 / AC-2 — OS-clipboard paste is universal across TUI text boxes.

Summary:
    The TUI historically mixed two text-entry widgets: ``OsClipboardInput``
    (Ctrl+V reads the real OS clipboard through the tkinter → Win32 → PowerShell
    cascade) on the file-load and A2B-diff paths, and stock Textual ``Input``
    everywhere else — so Ctrl+V silently did nothing in the search, goto, filter,
    palette, save-name and CRC boxes. batch-66 converts every remaining site.

    Two complementary oracles, because either alone is weak:

    - **AC-1 is a structural census** over the module's AST. It fails on a
      *newly introduced* stock ``Input(...)`` construction, which a behavioural
      test over today's widget ids cannot see. Constructions are counted, not
      references: ``query_one("#x", Input)`` and ``Input.Changed`` annotations
      are legitimate and must stay.
    - **AC-2 is behavioural** and drives the real widget, because the census
      only proves a *class name* — it cannot prove the class actually pastes.

Data Flow:
    - AC-1 parses each converted module's source and walks ``ast.Call`` nodes.
    - AC-2 monkeypatches ``read_os_clipboard`` (the real OS clipboard is shared
      with the developer's workstation and would make the test flaky), mounts
      the app, and exercises the paste path on a converted widget.

Dependencies:
    Uses:
        - ``s19_app.tui.app.S19TuiApp`` / ``s19_app.tui.os_clipboard_input``
    Used by:
        - the batch-66 acceptance gate (AC-1, AC-2)
"""

from __future__ import annotations

import ast
import asyncio
from pathlib import Path
from typing import List, Tuple

import pytest

from s19_app.tui.app import S19TuiApp
from s19_app.tui.os_clipboard_input import OsClipboardInput

#: Modules converted by batch-66 Inc-1. Inc-2 replaces this hand-kept list with
#: a package-wide sweep; until then the census is scoped to what has landed, so
#: a green increment means "everything claimed converted IS converted".
_CONVERTED_MODULES = ("app.py", "command_bar.py")

#: Repo-relative root of the TUI package under census.
_TUI_DIR = Path(__file__).resolve().parents[1] / "s19_app" / "tui"


def _stock_input_constructions(module_path: Path) -> List[Tuple[int, str]]:
    """Return ``(lineno, source_segment)`` for every stock ``Input(...)`` call.

    Summary:
        Parse ``module_path`` and collect calls whose callee is the bare name
        ``Input``. Attribute callees (``Input.Changed``) and bare references
        (``query_one("#x", Input)``) are NOT constructions and are excluded —
        the rule being enforced is "do not *instantiate* a stock Input", not
        "do not mention Input".

    Args:
        module_path (Path): Absolute path to the module to scan.

    Returns:
        List[Tuple[int, str]]: One ``(line number, source line)`` per offending
        construction, in source order; ``[]`` when the module is clean.

    Data Flow:
        - Reads the module source; produces the offender list the census asserts
          is empty.

    Dependencies:
        Used by:
            - ``test_ac1_converted_modules_construct_no_stock_input``

    Example:
        >>> _stock_input_constructions(_TUI_DIR / "os_clipboard_input.py")
        []
    """
    source = module_path.read_text(encoding="utf-8")
    lines = source.splitlines()
    offenders: List[Tuple[int, str]] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id == "Input":
            offenders.append((node.lineno, lines[node.lineno - 1].strip()))
    return sorted(offenders)


@pytest.mark.parametrize("module_name", _CONVERTED_MODULES)
def test_ac1_converted_modules_construct_no_stock_input(module_name: str) -> None:
    """AC-1: no converted module may instantiate a stock ``Input``.

    Measured pre-fix on ``73e3fb9``: ``app.py`` had 8 such constructions and
    ``command_bar.py`` had 3 — so this assertion is RED on the unfixed tree,
    not vacuously green.
    """
    offenders = _stock_input_constructions(_TUI_DIR / module_name)
    assert offenders == [], (
        f"{module_name} constructs stock Input() at "
        f"{[ln for ln, _ in offenders]} — Ctrl+V will silently do nothing "
        f"there. Use OsClipboardInput. Offending lines: "
        f"{[src for _, src in offenders]}"
    )


def test_ac1_census_can_detect_an_offender() -> None:
    """AC-1 positive control: the census is not structurally unable to fail.

    A census that returns ``[]`` for every input is indistinguishable from a
    correct one. Feed it a module that *does* construct a stock ``Input`` and
    require a hit — otherwise the parametrized test above proves nothing.
    """
    probe = _TUI_DIR / "screens.py"
    assert _stock_input_constructions(probe), (
        "screens.py is expected to still hold stock Input() constructions at "
        "Inc-1 (they are Inc-2's scope). If it is already clean, this positive "
        "control must be re-pointed at another unconverted module — do not "
        "delete it, or the census loses its only proof that it can fail."
    )


def test_ac2_hex_search_box_pastes_from_the_os_clipboard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-2: the converted hex-search box inserts real OS-clipboard text.

    Drives ``action_paste`` on the live widget rather than pressing Ctrl+V,
    because ``#search_input`` lives on a non-active screen container at mount
    and an unfocusable widget cannot receive the key. The Ctrl+V *binding* path
    for this widget class is already covered end-to-end by
    ``test_loadfilescreen_ctrl_v_reads_from_os_clipboard``; what is new here is
    that this particular box is now the class that honours it.
    """
    from s19_app.tui import os_clipboard_input as os_clip_mod

    monkeypatch.setattr(os_clip_mod, "read_os_clipboard", lambda: "DEADBEEF")

    async def _drive() -> tuple[str, bool]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            widget = app.query_one("#search_input", OsClipboardInput)
            await widget.action_paste()
            await pilot.pause()
            return widget.value, isinstance(widget, OsClipboardInput)

    value, is_os_input = asyncio.run(_drive())
    assert is_os_input, "#search_input must be an OsClipboardInput"
    assert "DEADBEEF" in value, (
        f"Paste into #search_input must insert the OS clipboard payload. "
        f"Got: {value!r}"
    )


def test_ac2_command_palette_pastes_from_the_os_clipboard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-2 (second site): the command-palette box also honours the OS clipboard.

    A second, independently-composed widget (``command_bar.py``, not ``app.py``)
    so a single-file conversion cannot make AC-2 look complete.
    """
    from s19_app.tui import os_clipboard_input as os_clip_mod

    monkeypatch.setattr(os_clip_mod, "read_os_clipboard", lambda: "0x80040000")

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            widget = app.query_one("#palette_input", OsClipboardInput)
            await widget.action_paste()
            await pilot.pause()
            return widget.value

    value = asyncio.run(_drive())
    assert "0x80040000" in value, (
        f"Paste into #palette_input must insert the OS clipboard payload. "
        f"Got: {value!r}"
    )
