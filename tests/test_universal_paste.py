"""batch-67 AC-1 / AC-2 — OS-clipboard paste is universal across TUI text boxes.

Summary:
    The TUI historically mixed two text-entry widgets: ``OsClipboardInput``
    (Ctrl+V reads the real OS clipboard through the tkinter → Win32 → PowerShell
    cascade) on the file-load and A2B-diff paths, and stock Textual ``Input``
    everywhere else — so Ctrl+V silently did nothing in the search, goto, filter,
    palette, save-name and CRC boxes. batch-67 converts every remaining site.

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
        - the batch-67 acceptance gate (AC-1, AC-2)
"""

from __future__ import annotations

import ast
import asyncio
from pathlib import Path
from typing import List, Tuple

import pytest

from s19_app.tui.app import S19TuiApp
from s19_app.tui.os_clipboard_input import OsClipboardInput

#: Repo-relative root of the TUI package under census.
_TUI_DIR = Path(__file__).resolve().parents[1] / "s19_app" / "tui"

#: The census sweeps the WHOLE package rather than a hand-kept list (Inc-2
#: widened it from the Inc-1 pair). A list only pins the modules someone
#: remembered to add; the sweep also fails on a NEW module that reintroduces a
#: stock ``Input`` — which is the actual regression this batch must prevent.
_SWEPT_MODULES = sorted(_TUI_DIR.rglob("*.py"))


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
            - ``test_ac1_no_tui_module_constructs_a_stock_input``
            - ``test_ac1_census_can_detect_an_offender``

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


@pytest.mark.parametrize(
    "module_path", _SWEPT_MODULES, ids=lambda p: p.name
)
def test_ac1_no_tui_module_constructs_a_stock_input(module_path: Path) -> None:
    """AC-1: no module in ``s19_app/tui/`` may instantiate a stock ``Input``.

    Measured pre-fix on ``73e3fb9``: 16 such constructions across 5 modules
    (``app.py`` 8, ``command_bar.py`` 3, ``screens.py`` 3,
    ``screens_directionb.py`` 1, ``crc_designer_view.py`` 1) — so this
    assertion is RED on the unfixed tree, not vacuously green.

    Swept over the whole package rather than a fixed list, so a module added
    later that reintroduces a stock ``Input`` fails here without anyone having
    to remember to register it.
    """
    offenders = _stock_input_constructions(module_path)
    assert offenders == [], (
        f"{module_path.name} constructs stock Input() at "
        f"{[ln for ln, _ in offenders]} — Ctrl+V will silently do nothing "
        f"there. Use OsClipboardInput. Offending lines: "
        f"{[src for _, src in offenders]}"
    )


def test_ac1_census_can_detect_an_offender(tmp_path: Path) -> None:
    """AC-1 positive control: the census is not structurally unable to fail.

    A census that returns ``[]`` for every input is indistinguishable from a
    correct one, and once the package is clean every real module returns ``[]``
    — so with no positive control the sweep above would stay green even if
    ``_stock_input_constructions`` were replaced by ``return []``.

    Feeds it a synthetic module containing one construction plus the two shapes
    that must NOT count (a ``query_one`` reference and an ``Input.Changed``
    annotation), and requires exactly the construction to be reported.
    """
    probe = tmp_path / "probe.py"
    probe.write_text(
        "from textual.widgets import Input\n"
        "def build():\n"
        "    w = Input(placeholder='x', id='y')\n"
        "    ref = query_one('#y', Input)\n"
        "    return w, ref\n"
        "def on_input_changed(event: Input.Changed) -> None:\n"
        "    pass\n",
        encoding="utf-8",
    )
    offenders = _stock_input_constructions(probe)
    assert [ln for ln, _ in offenders] == [3], (
        "The census must report the construction on line 3 and ONLY that one: "
        "a bare reference (line 4) and an attribute annotation (line 6) are "
        f"legitimate and must not be flagged. Got: {offenders}"
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
