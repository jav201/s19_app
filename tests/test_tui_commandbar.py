"""Command-bar tests — batch-02-direction-b-restyle, increment 4.

Covers the command-bar input surface introduced by increment 4:
  - LLR-003.2 — command palette lists every ``BINDINGS`` action; each
    palette entry dispatches the same action id (TC-007).
  - LLR-004.1 / LLR-004.5 / LLR-004.6 — ``/`` focuses the find input; the
    find submission routes to the existing ``find_string_in_mem`` path;
    single-key bindings are suppressed while a command-bar input is
    focused; malformed input is surfaced via ``set_status`` (TC-008).
  - LLR-004.2 / LLR-004.5 — ``g`` focuses the go-to input; submission
    produces the ``_handle_goto`` observable effect; single-key bindings
    are suppressed while it is focused; malformed input via ``set_status``
    (TC-009).
  - LLR-013.3 — the command bar writes no user-typed find / go-to /
    palette text or rendered file content to the rotating log (TC-039).

S-1 / S-2 design contract verified here: the find and go-to inputs route
to the *existing validated* handlers ``find_string_in_mem`` /
``_handle_goto`` with NO new address-parsing or string-decoding code; TC-008
and TC-009 assert that ``command_bar.py`` adds no such code, and TC-039
asserts the command bar adds no logging.

The app is driven headlessly via ``App.run_test()`` (the harness pattern of
``tests/test_tui_app.py`` / ``tests/test_tui_directionb.py``).
"""

from __future__ import annotations

import asyncio
import ast
from pathlib import Path

from textual.binding import Binding
from textual.widgets import Input

from s19_app.tui.app import S19TuiApp
from s19_app.tui.command_bar import CommandBar
from s19_app.tui.models import LoadedFile

_COMMAND_BAR_SOURCE = Path("s19_app/tui/command_bar.py")


def _loaded_s19(tmp_path: Path) -> LoadedFile:
    """Build a small in-memory ``LoadedFile`` whose memory spells 'HELLO'.

    The bytes 0x48 0x45 0x4C 0x4C 0x4F at 0x1000 let the find test submit
    the literal text ``HELLO`` and exercise the real ``find_string_in_mem``
    match path; the surrounding metadata mirrors the ``test_tui_app.py``
    fixtures.
    """
    mem = {0x1000 + i: b for i, b in enumerate(b"HELLO")}
    return LoadedFile(
        path=tmp_path / "prg.s19",
        file_type="s19",
        mem_map=mem,
        row_bases=[0x1000],
        ranges=[(0x1000, 0x1005)],
        range_validity=[True],
        errors=[],
        a2l_path=None,
        a2l_data=None,
    )


# ---------------------------------------------------------------------------
# TC-007 — command palette lists every BINDINGS action (LLR-003.2)
# ---------------------------------------------------------------------------


def test_tc007_palette_lists_every_bindings_action(tmp_path: Path) -> None:
    """Every ``BINDINGS`` action id has exactly one palette entry.

    Intent: LLR-003.2 — the palette must not drift from ``BINDINGS``. This
    iterates the *full* pre-batch + Direction B binding set and asserts a
    palette entry exists for every distinct action id, and that no palette
    entry carries an action id outside ``BINDINGS`` (apart from the one
    explicitly resurfaced ``open_settings_menu`` command). Built
    programmatically so a palette missing an action fails loudly.
    """

    async def _drive() -> tuple[set[str], set[str]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            bar = app.query_one(CommandBar)
            palette_actions = set(bar.visible_palette_actions())
        binding_actions: set[str] = set()
        for binding in S19TuiApp.BINDINGS:
            if isinstance(binding, Binding):
                binding_actions.add(binding.action)
            else:
                binding_actions.add(binding[1])
        return binding_actions, palette_actions

    binding_actions, palette_actions = asyncio.run(_drive())
    missing = binding_actions - palette_actions
    assert not missing, (
        f"these BINDINGS actions have no palette entry: {sorted(missing)}"
    )
    # The only palette action allowed beyond BINDINGS is the resurfaced
    # viewer settings command (owner decision C-9).
    extra = palette_actions - binding_actions
    assert extra == {"open_settings_menu"}, (
        f"palette carries unexpected non-BINDINGS actions: {sorted(extra)}"
    )


def test_tc007_palette_entry_dispatches_same_action(tmp_path: Path) -> None:
    """Selecting a palette entry runs the same action id as its key binding.

    Intent: LLR-003.2 — a palette entry must dispatch the action, not a
    look-alike. Selecting the 'A2L Explorer' command must activate the A2L
    rail screen exactly as the digit ``2`` binding does.
    """

    async def _drive() -> list[str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            # Dispatch via the same message the palette posts on selection.
            app.post_message(CommandBar.PaletteAction("show_screen('a2l')"))
            await pilot.pause()
            return [
                sid
                for sid in ("screen_workspace", "screen_a2l", "screen_mac")
                if "hidden" not in app.query_one(f"#{sid}").classes
            ]

    visible = asyncio.run(_drive())
    assert visible == ["screen_a2l"], (
        f"palette 'A2L Explorer' command should activate the A2L screen, "
        f"got {visible}"
    )


# ---------------------------------------------------------------------------
# TC-008 — find input: focus, routing, suppression, malformed input
# ---------------------------------------------------------------------------


def test_tc008_slash_focuses_find_from_every_screen(tmp_path: Path) -> None:
    """``/`` moves keyboard focus to the command-bar find input (LLR-004.1)."""

    async def _drive() -> list[tuple[str, str]]:
        app = S19TuiApp(base_dir=tmp_path)
        seen: list[tuple[str, str]] = []
        async with app.run_test() as pilot:
            await pilot.pause()
            for key in (
                "workspace",
                "a2l",
                "mac",
                "map",
                "issues",
                "patch",
                "diff",
                "bookmarks",
            ):
                app.action_show_screen(key)
                app.set_focus(None)
                await pilot.pause()
                await pilot.press("slash")
                await pilot.pause()
                seen.append((key, app.focused.id if app.focused else ""))
        return seen

    seen = asyncio.run(_drive())
    for key, focused_id in seen:
        assert focused_id == "find_input", (
            f"'/' should focus the find input on screen '{key}', "
            f"focused '{focused_id}'"
        )


def test_tc008_find_submission_routes_to_find_string_in_mem(tmp_path: Path) -> None:
    """Submitting find text runs the existing ``find_string_in_mem`` path.

    Intent: LLR-004.6 / S-1 — the find input must route to the already
    validated search handler. A submitted ``HELLO`` against memory that
    spells HELLO produces the existing handler's ``Found at 0x...`` status;
    a no-match string produces the existing ``Search text not found.``
    status. No new search function is introduced.
    """

    async def _drive() -> tuple[str, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.current_file = _loaded_s19(tmp_path)
            app.post_message(CommandBar.Find("HELLO"))
            await pilot.pause()
            hit = list(app.log_lines)[-1] if app.log_lines else ""
            app.post_message(CommandBar.Find("ZZZ_NO_MATCH"))
            await pilot.pause()
            miss = list(app.log_lines)[-1] if app.log_lines else ""
        return hit, miss

    hit, miss = asyncio.run(_drive())
    assert hit.startswith("Found at 0x"), (
        f"submitting 'HELLO' should route through find_string_in_mem and "
        f"report a hit, got status {hit!r}"
    )
    assert miss == "Search text not found.", (
        f"a non-matching find must surface the existing miss status, "
        f"got {miss!r}"
    )


def test_tc008_malformed_find_uses_set_status_no_exception(tmp_path: Path) -> None:
    """An empty / no-file find is reported via ``set_status``, not an error.

    Intent: LLR-004.6 / S-1 — malformed or non-matching find input is
    surfaced through the existing ``set_status`` path; no new error path
    and no exception. Submitting find with no file loaded must report the
    existing 'No file loaded.' status without raising.
    """

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            # No current_file -> the existing handler's no-file branch.
            app.post_message(CommandBar.Find("anything"))
            await pilot.pause()
            return list(app.log_lines)[-1] if app.log_lines else ""

    status = asyncio.run(_drive())
    assert status == "No file loaded.", (
        f"find with no file must surface the existing set_status message, "
        f"got {status!r}"
    )


def test_tc008_single_keys_suppressed_while_find_focused(tmp_path: Path) -> None:
    """While the find input is focused, single-key bindings do not fire.

    Intent: LLR-004.5 / keymap §4 — typing ``g``, a digit ``1``-``8`` and a
    punctuation paging key (``.`` and ``,``) into the focused find input
    inserts them as text; go-to focus is not taken, the active rail screen
    does not change, and no paging action fires. Bindings resume once the
    input loses focus.
    """

    async def _drive() -> tuple[str, list[str], str, list[str]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.set_focus(None)
            await pilot.press("slash")
            await pilot.pause()
            find_input = app.query_one("#find_input", Input)
            find_input.value = ""
            for key in ("g", "5", "period", "comma"):
                await pilot.press(key)
            await pilot.pause()
            typed = find_input.value
            visible_during = [
                sid
                for sid in ("screen_workspace", "screen_issues")
                if "hidden" not in app.query_one(f"#{sid}").classes
            ]
            focused_during = app.focused.id if app.focused else ""
            # After the input loses focus the digit binding fires normally.
            app.set_focus(None)
            await pilot.press("3")
            await pilot.pause()
            visible_after = [
                sid
                for sid in ("screen_workspace", "screen_mac")
                if "hidden" not in app.query_one(f"#{sid}").classes
            ]
        return typed, visible_during, focused_during, visible_after

    typed, visible_during, focused_during, visible_after = asyncio.run(_drive())
    assert typed == "g5.,", (
        f"g / digit / paging keys must be inserted as text into the find "
        f"input, got {typed!r}"
    )
    assert focused_during == "find_input", (
        "typing 'g' must not steal focus to the go-to input"
    )
    assert visible_during == ["screen_workspace"], (
        f"digit '5' while find focused must not switch screens, "
        f"got {visible_during}"
    )
    assert visible_after == ["screen_mac"], (
        f"after the input loses focus, digit '3' must route to MAC, "
        f"got {visible_after}"
    )


def test_tc008_no_new_search_function_in_command_bar() -> None:
    """``command_bar.py`` adds no string-decoding / search-parsing code.

    Intent: LLR-004.6 / S-1 — the command bar must route to the existing
    ``find_string_in_mem`` handler and introduce no fresh, unguarded search
    or decoding code path. An AST walk confirms the module defines no
    search/decode function and imports nothing from the hex-search engine.
    """
    tree = ast.parse(_COMMAND_BAR_SOURCE.read_text(encoding="utf-8"))
    func_names = [
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    for name in func_names:
        lowered = name.lower()
        assert "search" not in lowered, (
            f"command_bar.py must not define a search function ({name})"
        )
        assert "decode" not in lowered, (
            f"command_bar.py must not define a decoding function ({name})"
        )
    imported_modules: set[str] = set()
    imported_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported_modules.add(node.module)
            for alias in node.names:
                imported_names.add(alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                imported_modules.add(alias.name)
    assert not any("hexview" in mod for mod in imported_modules), (
        f"command_bar.py must not import the hex-search engine, "
        f"got {imported_modules}"
    )
    # The handler is named in the module docstring (it documents the
    # routing contract) but must never be imported / called from here —
    # the search runs in the app's existing handler, not the widget.
    assert "find_string_in_mem" not in imported_names, (
        "command_bar.py must not import find_string_in_mem — the search "
        "runs through the app's existing handler (S-1)"
    )


# ---------------------------------------------------------------------------
# TC-009 — go-to input: focus, observable effect, suppression, malformed
# ---------------------------------------------------------------------------


def test_tc009_g_focuses_goto_and_submit_has_handle_goto_effect(
    tmp_path: Path,
) -> None:
    """``g`` focuses go-to; submitting an address shows the ``_handle_goto`` effect.

    Intent: LLR-004.2 / S-1 — ``_handle_goto`` takes no address argument; it
    reads ``#goto_input`` off the widget tree. The command bar feeds its
    typed text into that existing input and calls the unchanged handler, so
    the observable effect is asserted: a valid address yields the existing
    ``Goto 0x...`` status. No new address-parsing code is added.
    """

    async def _drive() -> tuple[str, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.set_focus(None)
            await pilot.press("g")
            await pilot.pause()
            focused = app.focused.id if app.focused else ""
            app.current_file = _loaded_s19(tmp_path)
            app.post_message(CommandBar.Goto("0x1000"))
            await pilot.pause()
            status = list(app.log_lines)[-1] if app.log_lines else ""
        return focused, status

    focused, status = asyncio.run(_drive())
    assert focused == "cmdbar_goto_input", (
        f"'g' should focus the command-bar go-to input, focused {focused!r}"
    )
    assert status == "Goto 0x00001000", (
        f"submitting a valid address must produce the _handle_goto "
        f"observable effect, got status {status!r}"
    )


def test_tc009_malformed_goto_uses_set_status_no_exception(tmp_path: Path) -> None:
    """A malformed go-to address is reported via ``set_status``, not an error.

    Intent: LLR-004.2 / S-1 — ``_handle_goto`` already validates the address
    and reports a malformed one via ``set_status``; the command bar routes
    to it unchanged, so a non-hex address produces the existing 'Invalid
    address format.' status with no new error path and no exception.
    """

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.current_file = _loaded_s19(tmp_path)
            app.post_message(CommandBar.Goto("not_an_address"))
            await pilot.pause()
            return list(app.log_lines)[-1] if app.log_lines else ""

    status = asyncio.run(_drive())
    assert status == "Invalid address format.", (
        f"a malformed go-to address must surface the existing set_status "
        f"message, got {status!r}"
    )


def test_tc009_single_keys_suppressed_while_goto_focused(tmp_path: Path) -> None:
    """While the go-to input is focused, single-key bindings do not fire.

    Intent: LLR-004.5 / keymap §4 — typing a digit ``1``-``8`` and a
    punctuation paging key into the focused go-to input inserts them as
    text; rail navigation does not fire and the active screen does not
    change.
    """

    async def _drive() -> tuple[str, list[str]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.set_focus(None)
            await pilot.press("g")
            await pilot.pause()
            goto_input = app.query_one("#cmdbar_goto_input", Input)
            goto_input.value = ""
            for key in ("4", "period", "comma"):
                await pilot.press(key)
            await pilot.pause()
            typed = goto_input.value
            visible = [
                sid
                for sid in ("screen_workspace", "screen_map")
                if "hidden" not in app.query_one(f"#{sid}").classes
            ]
        return typed, visible

    typed, visible = asyncio.run(_drive())
    assert typed == "4.,", (
        f"digit / paging keys must be inserted into the go-to input, "
        f"got {typed!r}"
    )
    assert visible == ["screen_workspace"], (
        f"digit '4' while go-to focused must not switch to Memory Map, "
        f"got {visible}"
    )


def test_tc009_no_new_address_parser_in_command_bar() -> None:
    """``command_bar.py`` adds no address-parsing code.

    Intent: LLR-004.2 / S-1 — the command bar must route to the existing
    ``_handle_goto`` handler and introduce no fresh address-parsing path.
    An AST walk confirms no parse/address function is defined and that
    ``int(... , 0)`` style parsing does not appear in the module.
    """
    source = _COMMAND_BAR_SOURCE.read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            lowered = node.name.lower()
            assert "parse" not in lowered, (
                f"command_bar.py must not define a parse function ({node.name})"
            )
            assert "address" not in lowered or "labels" in lowered, (
                f"command_bar.py must not define an address-parsing "
                f"function ({node.name})"
            )
    # No int(..., 0)/int(..., 16) base-conversion address parsing.
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "int"
            and len(node.args) >= 2
        ):
            raise AssertionError(
                "command_bar.py must not perform int() base parsing of "
                "address text — go-to parsing belongs to _handle_goto"
            )


# ---------------------------------------------------------------------------
# TC-039 — command bar logs no typed text or rendered file content (LLR-013.3)
# ---------------------------------------------------------------------------


def test_tc039_command_bar_adds_no_logger_calls() -> None:
    """``command_bar.py`` makes no logging calls (LLR-013.3 inspection).

    Intent: LLR-013.3 / S-3 — the command bar must not write user-typed
    find / go-to / palette text (nor rendered file content) to the rotating
    log. An AST walk confirms the module contains no ``logger`` /
    ``logging`` references and no ``.log`` / ``.info`` / ``.debug`` /
    ``.warning`` call surface at all.
    """
    source = _COMMAND_BAR_SOURCE.read_text(encoding="utf-8")
    assert "logger" not in source, (
        "command_bar.py must not reference a logger (LLR-013.3)"
    )
    assert "logging" not in source, (
        "command_bar.py must not import or use logging (LLR-013.3)"
    )
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in (
                "info",
                "debug",
                "warning",
                "error",
                "exception",
            ), (
                f"command_bar.py must not make a log call "
                f"(.{node.func.attr}) — LLR-013.3"
            )


def test_tc039_typed_find_and_palette_text_not_written_to_log(
    tmp_path: Path,
) -> None:
    """A driven find / palette session leaves typed text out of the on-disk log.

    Intent: LLR-013.3 / S-3 — the command bar is a new input surface; the
    text typed into the find input and the palette filter must not reach
    the rotating log under ``.s19tool/logs/``. The command bar's only
    status surface is ``set_status`` (the in-app log lines), not the
    on-disk log.

    Scope note: the go-to path is exercised separately. Submitting a go-to
    address routes to the unchanged ``_handle_goto`` -> ``update_hex_view``,
    and ``update_hex_view`` carries a *pre-batch* "Hex view focused at
    0x..." log line (``app.py``) that logs the resolved hex address. That
    line predates this batch — the command bar adds no logging of its own
    (asserted by ``test_tc039_command_bar_adds_no_logger_calls``) and does
    not raise log verbosity above the pre-batch baseline. This test
    therefore verdicts the genuinely new surfaces — typed find text and
    palette filter text — which have no pre-batch logging path at all.
    """
    secret_find = "SECRET_FIND_TOKEN_XYZ"
    secret_palette = "SECRET_PALETTE_TOKEN_QRS"

    async def _drive() -> None:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.current_file = _loaded_s19(tmp_path)
            app.set_focus(None)
            await pilot.press("slash")
            await pilot.pause()
            app.query_one("#find_input", Input).value = secret_find
            app.post_message(CommandBar.Find(secret_find))
            await pilot.pause()
            await pilot.press("ctrl+k")
            await pilot.pause()
            app.query_one("#palette_input", Input).value = secret_palette
            await pilot.pause()

    asyncio.run(_drive())
    log_dir = tmp_path / ".s19tool" / "logs"
    log_text = ""
    if log_dir.exists():
        for log_file in log_dir.glob("*"):
            if log_file.is_file():
                log_text += log_file.read_text(encoding="utf-8", errors="ignore")
    assert secret_find not in log_text, (
        "typed find text must not be written to .s19tool/logs/ (LLR-013.3)"
    )
    assert secret_palette not in log_text, (
        "typed palette filter text must not be written to .s19tool/logs/ "
        "(LLR-013.3)"
    )
