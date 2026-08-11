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
import json
import re
from hashlib import blake2b
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
    """``/`` reaches the ACTIVE screen's find input, or notices (LLR-119.1).

    ⚠️ **Re-pointed at batch-79 Inc-9, not retired.** This node asserted the
    pre-`HLR-119` contract — *"`/` focuses the command-bar find input"*, the
    same `#find_input` from all eight screens it drove — which is exactly the
    behaviour `HLR-119` replaces: the bar's find wrote into the workspace pane
    regardless of what the operator was looking at.

    The node id survives because its observable does: *"`/` from every screen
    goes somewhere well-defined."* Only the destination changed — from one
    shared input to the active screen's own, or, on the seven screens owning
    none, to a notice. Retiring it would have dropped a per-screen sweep that
    `AT-B78-04` (3 owning screens) and `AT-B78-05` (7 notice screens) cover only
    when read together, and it would have touched the AT/TC registry, which is
    Inc-11's declared work.
    """

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
                "flow",
            ):
                app.action_show_screen(key)
                app.set_focus(None)
                await pilot.pause()
                await pilot.press("slash")
                await pilot.pause()
                seen.append((key, app.focused.id if app.focused else ""))
        return seen

    seen = asyncio.run(_drive())
    expected = {
        "workspace": "search_input",
        "a2l": "alt_search_input",
        "mac": "mac_search_input",
    }
    for key, focused_id in seen:
        if key in expected:
            assert focused_id == expected[key], (
                f"'/' must focus {key!r}'s OWN find input {expected[key]!r}, "
                f"focused {focused_id!r}"
            )
        else:
            assert focused_id == "", (
                f"on {key!r}, which owns no find input, '/' must take no focus "
                f"at all (the notice path); focused {focused_id!r}"
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
            find_input = app.query_one("#search_input", Input)
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
    assert focused_during == "search_input", (
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
    assert focused == "goto_input", (
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
            goto_input = app.query_one("#goto_input", Input)
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
            # batch-79 Inc-10: `#find_input` is deleted with the bar row. `/`
            # now focuses the ACTIVE screen's own input (Inc-9), and the
            # observable this node guards -- typed text never reaches the log
            # FILE -- is unchanged by where the text was typed.
            app.query_one("#search_input", Input).value = secret_find
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


# ---------------------------------------------------------------------------
# batch-78 Inc-0 — pre-change artifact capture (LLR-121.2, TC-B78-44)
# ---------------------------------------------------------------------------
#
# WHY THIS EXISTS. Three later acceptance tests need an oracle for a claim of
# the form "X is unchanged by batch-78". ``AT-B78-03`` (palette action set),
# ``AT-B78-12`` (workspace / A2L / MAC search + go-to behaviour) and
# ``AT-B78-33`` (the diff result area grows) are all invariance or
# before/after claims, and such a claim has no oracle inside the post-change
# tree.
#
# Phase 2 proved that concretely for ``AT-B78-03``: the palette is constructed
# as ``CommandBar(self._build_palette_entries())`` (``app.py:1878``), so
# comparing the observed action set against ``_build_palette_entries()``
# compares a producer with itself. Deleting an entire ``Binding`` from
# ``S19TuiApp.BINDINGS`` left that predicate GREEN at 36 == 36.
#
# What removes the circularity is the TEMPORAL FREEZE, not the capture path.
# The artifacts below were captured from the SHIPPED surface (C-35) on the
# pre-change tree, committed in their own commit ahead of every production edit
# of this batch, and are re-read FROM DISK by their consumers. Nothing in the
# test path rebuilds them: the capture helpers here PRODUCE values, the reader
# ``_b78_artifact`` only READS, and ``test_tc_b78_44_...`` runs an AST census
# asserting no test module writes into the artifact directory. A test that
# regenerated an artifact would restore the exact defect this capture removes.
#
# BYTE FIDELITY. ``core.autocrlf=true`` on this host rewrites committed
# evidence (batch-25 snapshots, batch-66 pre-bytes). ``tests/goldens/batch78/**
# -text`` in ``.gitattributes`` stops that in BOTH directions, and the digests
# below are taken over ``read_bytes()`` so a missing or wrong attribute rule
# reddens here instead of drifting between a Windows checkout and Linux CI.

_B78_ARTIFACT_DIR = Path(__file__).resolve().parent / "goldens" / "batch78"

_B78_PAYLOAD_ARTIFACT = "at-b78-12-search-goto-payload.json"
_B78_PALETTE_ARTIFACT = "at-b78-03-palette-actions.json"
_B78_DIFF_HEIGHT_ARTIFACT = "at-b78-33-diff-hex-a-height.json"

#: ``blake2b(digest_size=8)`` over each artifact file's bytes AS STORED.
_B78_ARTIFACT_DIGESTS = {
    _B78_PAYLOAD_ARTIFACT: "713be432b69cb2e0",
    _B78_PALETTE_ARTIFACT: "65bfd6bf668a0249",
    _B78_DIFF_HEIGHT_ARTIFACT: "167c7a4dd5ac5821",
}

#: Terminal sizes the three captures were taken at. Each consumer MUST drive
#: its live capture at the same size or it compares two different layouts.
#: 132x44 is mandated for the diff geometry by the spec's own Inc-1 gate.
_B78_CAPTURE_SIZE = (160, 40)
_B78_PALETTE_SIZE = (120, 30)
_B78_DIFF_SIZE = (132, 44)

#: The three screens that own local find / go-to inputs, and the shipped Button
#: ids the capture drives — never ``_handle_search*`` directly.
_B78_SEARCH_SURFACES = {
    "workspace": ("search_input", "search_button", "goto_input", "goto_button"),
    "a2l": (
        "alt_search_input",
        "alt_search_button",
        "alt_goto_input",
        "alt_goto_button",
    ),
    "mac": (
        "mac_search_input",
        "mac_search_button",
        "mac_goto_input",
        "mac_goto_button",
    ),
}

_B78_GOTO_FOCUS_ATTR = {
    "workspace": "_goto_focus_address",
    "a2l": "_alt_goto_focus_address",
    "mac": "_mac_goto_focus_address",
}

#: {hit, miss, empty} — the 3-case axis of the 9-row matrix.
_B78_CASES = (
    ("BOOT", "0x1010"),
    ("ZZZ_NO_MATCH", "0xFFFFFFFF"),
    ("", ""),
)

#: The seven fields of a payload row (LLR-121.2's stated row shape).
_B78_ROW_KEYS = frozenset(
    {
        "screen",
        "query",
        "goto",
        "log_line_4_after_search",
        "last_search_address",
        "log_line_4_after_goto",
        "per_view_goto_focus_address",
    }
)

#: The census below INVERTS the obvious shape, and the inversion is the point.
#:
#: A list of the verbs that WRITE is a vacuous input set — it is only as strong
#: as a list someone remembered to write, and an omission leaves the guard GREEN.
#: The first form of this census hand-listed seven write methods and inspected
#: only the RECEIVER; executed against five regeneration forms it let two
#: through: ``json.dump(rows, open(path, "w"))`` — the idiomatic way to write
#: JSON, so precisely the accident the census exists to prevent — and
#: ``shutil.copy(src, path)``. Both name this module's own symbol, so the gap
#: was verb-side and argument-side, never receiver-naming. That is the same
#: C-31 vacuous-input-set defect the batch's hand-filled propagation register
#: had, one layer down, inside the control built to prevent it.
#:
#: So the allowlist names the calls that provably CANNOT write an artifact and
#: everything else is an offender. An omission now makes the guard RED, and
#: widening it is a deliberate edit rather than a silent hole. Every member
#: below was added because it fired on the real tree, and each one either reads
#: or is pure — none can reach a filesystem write.
_B78_NON_WRITING_CALLS = frozenset(
    {
        "_b78_artifact",  # the one sanctioned reader
        "read_text",
        "read_bytes",
        "loads",  # json.loads
        "is_file",
        "exists",
        "blake2b",  # consumes bytes, writes nothing
        "hexdigest",
        "items",  # _B78_ARTIFACT_DIGESTS.items()
        "frozenset",  # this very allowlist, whose literals name the reader
    }
)


def _b78_mentions_path(segment: str, tainted: set[str]) -> bool:
    """True when ``segment`` names the artifact directory, or an alias of it."""
    if "b78_artifact" in segment.lower():
        return True
    return any(re.search(rf"\b{re.escape(name)}\b", segment) for name in tainted)


def _b78_write_offenders(source: str) -> list[tuple[int, str]]:
    """Every call in ``source`` not provably incapable of writing an artifact.

    Matches the WHOLE call — receiver and arguments alike — because the two
    forms that slipped the receiver-only first draft put the path in an
    ARGUMENT: ``json.dump(rows, open(path, "w"))`` and ``shutil.copy(src, path)``.
    """
    tree = ast.parse(source)

    # One level of local aliasing, iterated to a fixed point, so
    # `p = _B78_ARTIFACT_DIR / n; p.write_text(...)` is still caught. Only
    # PATH-SHAPED values propagate (a `/` join, or a bare name/attribute):
    # tainting a call's RESULT would tag `read_bytes()` output as a path and
    # drown the census in noise. Taint is module-scoped, so a name collision
    # yields a FALSE POSITIVE — a red test — never a false negative.
    tainted: set[str] = set()
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                targets, value = node.targets, node.value
            elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
                targets, value = [node.target], node.value
            else:
                continue
            if value is None:
                continue
            path_shaped = isinstance(value, (ast.Name, ast.Attribute)) or (
                isinstance(value, ast.BinOp) and isinstance(value.op, ast.Div)
            )
            if not path_shaped:
                continue
            segment = ast.get_source_segment(source, value) or ""
            if not _b78_mentions_path(segment, tainted):
                continue
            for target in targets:
                if isinstance(target, ast.Name) and target.id not in tainted:
                    tainted.add(target.id)
                    changed = True

    offenders: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not _b78_mentions_path(ast.get_source_segment(source, node) or "", tainted):
            continue
        func = node.func
        if isinstance(func, ast.Attribute):
            name = func.attr
        elif isinstance(func, ast.Name):
            name = func.id
        else:
            name = ast.get_source_segment(source, func) or "<expr>"
        if name not in _B78_NON_WRITING_CALLS:
            offenders.append((node.lineno, name))
    return offenders


def _b78_canonical_json(payload: object) -> str:
    """Serialise ``payload`` in the ONE form the artifacts are stored in.

    LLR-121.2 pins "sorted-key JSON with ``ensure_ascii=True``" but not the
    separators, and a digest recipe with an unpinned serialisation is not
    re-derivable — an unstated pattern is an unstated definition. ``indent=2``
    plus a trailing newline is pinned here so the stored bytes, the recorded
    digest and any future re-derivation agree exactly.
    """
    return json.dumps(payload, sort_keys=True, ensure_ascii=True, indent=2) + "\n"


def _b78_artifact(name: str) -> object:
    """Re-read an Inc-0 pre-change artifact FROM DISK.

    This is the ONLY accessor consumers may use. It reads; it never writes,
    never regenerates and never falls back to a live producer — a fallback
    would silently restore the ``f(x) == f(x)`` shape that made ``AT-B78-03``
    inert. A missing artifact raises, deliberately.
    """
    return json.loads((_B78_ARTIFACT_DIR / name).read_text(encoding="utf-8"))


def _b78_loaded_s19(base_dir: Path) -> LoadedFile:
    """The fixture the 9-row payload is captured against.

    32 bytes at 0x1000 spelling ``BOOT`` at 0x1006, in one half-open range
    [0x1000, 0x1020) so the go-to hit address 0x1010 falls inside it. The
    fixture lives HERE, in the committed test module, because the artifact and
    every later live capture must be taken against byte-identical memory —
    the spec recorded a digest whose fixture was never written down, which is
    why that digest is not re-derivable.
    """
    mem = {0x1000 + i: b for i, b in enumerate(b"\x00" * 6 + b"BOOT" + b"\x00" * 22)}
    return LoadedFile(
        path=base_dir / "b78.s19",
        file_type="s19",
        mem_map=mem,
        row_bases=[0x1000],
        ranges=[(0x1000, 0x1020)],
        range_validity=[True],
        errors=[],
        a2l_path=None,
        a2l_data=None,
    )


async def _b78_capture_row(
    base_dir: Path, screen: str, query: str, goto: str
) -> dict[str, object]:
    """Capture one payload row by driving the screen's own shipped Buttons.

    A fresh ``S19TuiApp`` per row on purpose: ``last_search_text`` and
    ``last_search_address`` are app-wide and carry across screens, so a shared
    app would make every row order-dependent and the artifact would encode the
    traversal order rather than the behaviour.
    """
    search_input, search_button, goto_input, goto_button = _B78_SEARCH_SURFACES[screen]
    app = S19TuiApp(base_dir=base_dir)
    async with app.run_test(size=_B78_CAPTURE_SIZE) as pilot:
        await pilot.pause()
        app.current_file = _b78_loaded_s19(base_dir)
        app.action_show_screen(screen)
        await pilot.pause()
        app.query_one(f"#{search_input}", Input).value = query
        await pilot.pause()
        await pilot.click(f"#{search_button}")
        await pilot.pause()
        log_after_search = list(app.log_lines)[-1] if app.log_lines else ""
        last_search_address = app.last_search_address
        app.query_one(f"#{goto_input}", Input).value = goto
        await pilot.pause()
        await pilot.click(f"#{goto_button}")
        await pilot.pause()
        log_after_goto = list(app.log_lines)[-1] if app.log_lines else ""
        goto_focus = getattr(app, _B78_GOTO_FOCUS_ATTR[screen])
    return {
        "screen": screen,
        "query": query,
        "goto": goto,
        "log_line_4_after_search": log_after_search,
        "last_search_address": last_search_address,
        "log_line_4_after_goto": log_after_goto,
        "per_view_goto_focus_address": goto_focus,
    }


def b78_capture_search_goto_payload(base_dir: Path) -> list[dict[str, object]]:
    """Capture the full 9-row search / go-to payload from the shipped surface."""

    async def _drive() -> list[dict[str, object]]:
        rows: list[dict[str, object]] = []
        for screen in _B78_SEARCH_SURFACES:
            for query, goto in _B78_CASES:
                rows.append(await _b78_capture_row(base_dir, screen, query, goto))
        return rows

    return asyncio.run(_drive())


def b78_capture_palette_actions(base_dir: Path) -> list[str]:
    """Capture the palette action set through Ctrl+K on the shipped surface.

    Read off ``CommandBar.visible_palette_actions()`` — the widget's own public
    accessor — after a real key press, never off ``_build_palette_entries()``.
    """

    async def _drive() -> list[str]:
        app = S19TuiApp(base_dir=base_dir)
        async with app.run_test(size=_B78_PALETTE_SIZE) as pilot:
            await pilot.pause()
            app.set_focus(None)
            await pilot.pause()
            await pilot.press("ctrl+k")
            await pilot.pause()
            bar = app.query_one(CommandBar)
            assert bar.palette_is_open, (
                "the palette must actually be open before its action set is "
                "captured; a closed palette would freeze a stale entry list"
            )
            return list(bar.visible_palette_actions())

    return asyncio.run(_drive())


def b78_capture_diff_hex_a_geometry(base_dir: Path) -> dict[str, object]:
    """Capture the pre-change diff result-area geometry at 132x44.

    Both layers are recorded (C-32/C-37): ``size.height`` is the content layer
    ``AT-B78-33`` compares, and the region intersected with ``#screen_diff`` is
    the painted layer — ``region.height`` alone reads non-zero for a box that
    paints nothing.
    """

    async def _drive() -> dict[str, object]:
        app = S19TuiApp(base_dir=base_dir)
        async with app.run_test(size=_B78_DIFF_SIZE) as pilot:
            await pilot.pause()
            app.action_show_screen("diff")
            await pilot.pause()
            widget = app.query_one("#diff_hex_a")
            host = app.query_one("#screen_diff")
            clipped = widget.region.intersection(host.region)
            return {
                "widget": "#diff_hex_a",
                "terminal": list(_B78_DIFF_SIZE),
                "content_height": widget.size.height,
                "content_width": widget.size.width,
                "clipped_height": clipped.height,
                "clipped_width": clipped.width,
            }

    return asyncio.run(_drive())


def test_tc_b78_44_pre_change_artifacts_are_frozen_on_disk() -> None:
    """TC-B78-44 — the Inc-0 artifacts are a committed, unrebuildable freeze.

    Intent: LLR-121.2 / §5.1 rule 10 — an invariance AT takes its expectation
    from a committed PRE-CHANGE artifact, never from the live producer. That
    holds only while two things do, and this node asserts both because they are
    one subject (*the capture is frozen*) observed on two layers:

      (a) the artifacts are on disk, byte-identical to what was captured, and
          carry the shapes their consumers depend on — 9 rows over the seven
          declared fields, 37 distinct palette actions, a positive 132x44
          content height. The digest is over ``read_bytes()``, so a lost
          ``-text`` attribute reddens here rather than drifting between hosts.

      (b) nothing under ``tests/`` writes into the artifact directory. This is
          the clause that keeps the freeze a freeze: a test that regenerated an
          artifact at run time would restore the producer-compared-with-itself
          defect that left ``AT-B78-03`` GREEN at 36 == 36 with a whole
          ``Binding`` removed.

    Falsifiable on both limbs: substitute one value in a stored artifact and (a)
    reddens; add any of ``write_text`` / ``open(...).write`` / ``json.dump`` /
    ``shutil.copy`` against the artifact path to a test module and (b) reddens —
    all four executed.

    Scope limit, stated exactly rather than implied. (b) is a token census. It
    matches a call — receiver OR any argument — that names ``_B78_ARTIFACT_DIR``
    / ``_b78_artifact``, or a local aliased from one by a path-shaped assignment
    (`p = _B78_ARTIFACT_DIR / n`, chained to a fixed point). Within that reach it
    is verb-agnostic and fails CLOSED: any call not on ``_B78_NON_WRITING_CALLS``
    is an offender, so a write form nobody anticipated reddens by default. What
    it does NOT reach: a module that rebuilds the path from raw string literals
    (``Path("tests/goldens/batch78") / …``), or one that passes the path through
    a function-call return value rather than a path-shaped assignment. It bounds
    accident, not intent — and the first draft of this census proved the point by
    letting ``json.dump`` through.

    Known over-reporting, measured not assumed. Taint is MODULE-scoped, so a
    common alias name collides: the alias-form verification bound ``p`` in
    ``test_tui_directionb.py`` and the census additionally reported three
    unrelated calls (``sorted``/``lower``/``any``) elsewhere in that module.
    That is a false POSITIVE — a loud red test — never a false negative, and it
    only occurs once someone introduces an artifact-path alias, which is
    precisely when a loud test is wanted. Per-function taint scoping would
    remove the noise; it is deliberately not built, because ~25 lines of scope
    resolution inside a test guard buys accuracy the guard's purpose does not
    need.
    """
    # --- (a) the artifacts exist, byte-for-byte, in the declared shapes -----
    for name, expected_digest in _B78_ARTIFACT_DIGESTS.items():
        artifact_path = _B78_ARTIFACT_DIR / name
        assert artifact_path.is_file(), (
            f"Inc-0 artifact {name!r} is missing from {_B78_ARTIFACT_DIR}; it is "
            f"the only oracle its consumer has and cannot be regenerated once a "
            f"production edit has landed"
        )
        actual_digest = blake2b(artifact_path.read_bytes(), digest_size=8).hexdigest()
        assert actual_digest == expected_digest, (
            f"{name} no longer hashes to its recorded digest "
            f"({actual_digest} != {expected_digest}). Either the artifact was "
            f"edited or regenerated, or the stored blob was line-ending "
            f"normalised — check that `.gitattributes` still carries "
            f"`tests/goldens/batch78/** -text`"
        )

    payload = _b78_artifact(_B78_PAYLOAD_ARTIFACT)
    assert isinstance(payload, list) and len(payload) == 9, (
        f"the search / go-to payload must hold 3 screens x 3 cases = 9 rows, got "
        f"{len(payload) if isinstance(payload, list) else type(payload)}"
    )
    assert {row["screen"] for row in payload} == set(_B78_SEARCH_SURFACES), (
        "the payload must cover exactly the three screens that own local find / "
        "go-to inputs"
    )
    for row in payload:
        assert set(row) == _B78_ROW_KEYS, (
            f"payload row {row.get('screen')!r}/{row.get('query')!r} does not "
            f"carry LLR-121.2's seven declared fields: {sorted(row)}"
        )

    actions = _b78_artifact(_B78_PALETTE_ARTIFACT)
    assert isinstance(actions, list) and len(actions) == 37, (
        f"the palette artifact must hold the 37 pre-change actions (D-3), got "
        f"{len(actions) if isinstance(actions, list) else type(actions)}"
    )
    assert len(set(actions)) == len(actions), (
        "palette action ids must be distinct; a duplicate would make a "
        "set-equality comparison at AT-B78-03 blind to one deletion"
    )

    geometry = _b78_artifact(_B78_DIFF_HEIGHT_ARTIFACT)
    assert geometry["terminal"] == list(_B78_DIFF_SIZE), (
        f"the diff geometry baseline must be the 132x44 one Inc-1's gate names, "
        f"got {geometry['terminal']}"
    )
    assert (
        isinstance(geometry["content_height"], int) and geometry["content_height"] >= 1
    ), (
        f"a pre-change baseline of 0 rows would make AT-B78-33's strict increase "
        f"satisfiable by any non-empty result, got {geometry['content_height']!r}"
    )

    # --- (b) no test module can rebuild an artifact -------------------------
    swept: list[str] = []
    offenders: list[str] = []
    for module in sorted(Path(__file__).resolve().parent.rglob("*.py")):
        swept.append(module.name)
        for lineno, call in _b78_write_offenders(module.read_text(encoding="utf-8")):
            offenders.append(f"{module.name}:{lineno} {call}()")

    assert swept, "the AST census swept no modules at all — it proves nothing"
    assert "test_tui_commandbar.py" in swept, (
        "the AST census must include this module, the one that names the "
        "artifact path; a sweep that misses it is vacuous"
    )
    assert not offenders, (
        f"a test module writes into the Inc-0 artifact path: {offenders}. The "
        f"artifacts are a PRE-CHANGE freeze — regenerating one at test time "
        f"makes its consumer compare a producer with itself, which is exactly "
        f"the defect (BL-1) this capture exists to remove."
    )


# ---------------------------------------------------------------------------
# batch-79 Inc-7 -- HLR-120: the project and A2L are named on every screen,
# in both display forms, on BOTH context surfaces (LLR-120.1 .. 120.5)
# ---------------------------------------------------------------------------

from test_tui_variants import S19_A, S19_B, _flush, _make_project  # noqa: E402


def _b79_status_context(app) -> str:
    """The status bar's context cell, as PAINTED — not as rendered.

    ⚠️ This read `str(...render())` until the Inc-6/Inc-7 independent review,
    and the difference is the whole finding. `render()` returns what the widget
    WOULD draw given room; the compositor decides how much room it gets. With a
    routine `set_file_status` coexistence message at 80x24, `#status_text` sized
    itself to 93 columns on a 78-column bar, `#status_context` got 1 column and
    painted NOTHING — while `render()` still returned the full string. Every
    gate below was green over an operator who could not read the context at all.

    That is the class the spec names in its own section 1.3 (C-32, "a predicate
    on `region` alone ships the bug green"). The painted oracle already existed
    in this module for TC-B78-12; the gates simply did not use it.
    """
    return _b79_painted_strip(app, "#status_context")


def _b79_loaded_panel(app) -> str:
    """The Loaded panel's rows, joined.

    Read through the mounted children rather than through a stored string: the
    panel re-mounts its rows on every render, so anything cached is a snapshot
    of a tree that no longer exists.
    """
    return _b79_painted_strip(app, "#loaded_slots")


def _b79_both_surfaces(app) -> tuple[str, str]:
    """(status-bar context, Loaded-panel text) -- the two surfaces HLR-120 names.

    Returned as a PAIR because every acceptance in this block needs both. An
    implementation that updates only one passes a single-surface test, which is
    the C-40 hazard the operator's two-surface ruling created.
    """
    return _b79_status_context(app), _b79_loaded_panel(app)


def _b79_painted_strip(app, selector: str) -> str:
    """Text actually PAINTED in a widget's region, read from the compositor.

    `TC-B78-12` asserts over the painted strip, not over the widget's own
    renderable: a control codepoint that a renderable still carries but the
    compositor never paints is a different claim from the one LLR-120.4 makes.
    """
    widget = app.query_one(selector)
    strips = app.screen._compositor.render_strips()
    region = widget.region
    out = []
    for y in range(region.y, min(region.y + region.height, len(strips))):
        row = "".join(segment.text for segment in strips[y])
        out.append(row[region.x : region.x + region.width])
    return "".join(out)


#: `C0 ∪ {DEL} ∪ C1`, RE-DERIVED here rather than imported from
#: `_CONTROL_SCRUB` -- the discipline `tests/test_tui_hostile_map.py:86-89`
#: already states. Importing the production set would make the assertion
#: "the scrub removes what the scrub removes", true for any scrub including an
#: empty one.
_B79_CONTROL_CLASS = frozenset(
    chr(cp) for cp in (*range(0x00, 0x20), 0x7F, *range(0x80, 0xA0))
)


def test_at_b78_08_and_11_status_bar_names_both_on_every_screen(
    tmp_path: Path,
) -> None:
    """AT-B78-08 (GATE) + AT-B78-11 (PIN) -- asserted in ONE run, deliberately.

    `AT-B78-08`: with a project and an A2L loaded, `#workspace_status_bar`
    carries BOTH names on all 10 screens of `SCREEN_CONTAINER_IDS` (today 0 of
    10).

    `AT-B78-11`: the bar's height stays inside `1 <= h <= 7`. **Both bounds are
    normative and neither alone would do.** A bare `== 7` false-fails a
    conforming implementation that REDUCES the height; a bare `<= 7` is
    satisfied by a COLLAPSED bar of height 0 — which is why this is asserted in
    the SAME run as `AT-B78-08`: a height-0 bar paints nothing, so it cannot
    satisfy the naming clause and pass the height clause at once (NEW-7).
    """

    async def _drive(size, base):
        app = S19TuiApp(base_dir=base)
        _make_project(app, "demoproj", {"a.s19": S19_A})
        a2l = base / "b79ctx.a2l"
        a2l.write_text('/begin PROJECT p "" /end PROJECT\n', encoding="utf-8")
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            app._handle_load_project("demoproj")
            await _flush(pilot)
            app.load_a2l_from_path(a2l)
            await _flush(pilot)
            # A REALISTIC status message, not an idle bar. `set_file_status`
            # runs on every real file load with `_format_coexistence_status`,
            # whose text carries up to TWO filenames. Without it this node
            # exercises a nearly-empty `#status_text` and cannot see the sibling
            # starving the context — which is exactly how the 80x24 defect
            # survived this node's first authoring.
            app.set_file_status(
                "Loaded ECU_calibration_release_2026_v161.s19 "
                "(S19+MAC: ECU_calibration_release_2026_v161.mac)"
            )
            await pilot.pause()
            observed = {}
            for key in list(S19TuiApp.SCREEN_CONTAINER_IDS):
                app.action_show_screen(key)
                await pilot.pause()
                observed[key] = (
                    _b79_status_context(app),
                    app.query_one("#workspace_status_bar").size.height,
                )
            return observed

    # ALL THREE sizes §2.3 declares supported. Running at 120x30 alone was the
    # second half of the same defect: it is the one size where a starved context
    # still happens to fit.
    for size in ((160, 40), (120, 30), (80, 24)):
        base = tmp_path / f"s{size[0]}x{size[1]}"
        base.mkdir()
        observed = asyncio.run(_drive(size, base))

        assert len(observed) == 10, (
            f"@{size}: all 10 screens must be visited; got {len(observed)}"
        )
        for screen, (text, height) in observed.items():
            assert "demoproj" in text, (
                f"AT-B78-08 @{size}: the status bar must name the PROJECT on "
                f"{screen!r}; painted context={text!r}"
            )
            assert "b79ctx.a2l" in text, (
                f"AT-B78-08 @{size}: the status bar must name the A2L on "
                f"{screen!r}; painted context={text!r}"
            )
            assert 1 <= height <= 7, (
                f"AT-B78-11 @{size}: the status bar must not grow past 7 rows "
                f"and must not collapse; on {screen!r} height={height}"
            )


def test_at_b78_09_loaded_panel_names_the_project(tmp_path: Path) -> None:
    """AT-B78-09 (GATE) -- `#loaded_panel` names the active project.

    The A2L clause is deliberately NOT asserted here: the panel's A2L slot
    already renders the filename today (P-35), so an acceptance for it would be
    green before the change and could not gate it. Only the project row is new.
    """

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        _make_project(app, "demoproj", {"a.s19": S19_A})
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app._handle_load_project("demoproj")
            await _flush(pilot)
            return _b79_loaded_panel(app)

    panel = asyncio.run(_drive())

    assert "demoproj" in panel, (
        f"AT-B78-09: the Loaded panel must name the active project; panel={panel!r}"
    )


def test_at_b78_30_both_display_forms_on_both_surfaces(tmp_path: Path) -> None:
    """AT-B78-30 (GATE) -- LLR-120.5, four observations.

    The re-home is of a FORM, not just a name. An implementation emitting one
    uniform string satisfies "the project is named" on both surfaces and still
    breaks LLR-005.3, which `tests/test_tui_variants.py:259` pins.

    Plain at `N == 1` (no `(`), `proj:b (2/2)` after a real switch at `N == 2`,
    each read on BOTH surfaces.
    """

    async def _drive_single():
        app = S19TuiApp(base_dir=tmp_path / "one")
        _make_project(app, "solo", {"a.s19": S19_A})
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app._handle_load_project("solo")
            await _flush(pilot)
            return _b79_both_surfaces(app)

    async def _drive_multi():
        app = S19TuiApp(base_dir=tmp_path / "two")
        _make_project(app, "duo", {"a.s19": S19_A, "b.s19": S19_B})
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app._handle_load_project("duo")
            await _flush(pilot)
            return _b79_both_surfaces(app)

    single_ctx, single_panel = asyncio.run(_drive_single())
    multi_ctx, multi_panel = asyncio.run(_drive_multi())

    # N == 1 -> the PLAIN name, on both surfaces. `app.py`'s branch gates the
    # suffix on `> 1`, and an earlier draft of this spec asserted `(1/1)` — a
    # literal that would have false-failed a correct implementation AND
    # contradicted a shipped acceptance.
    assert "solo" in single_ctx and "(" not in single_ctx.split("|")[0], (
        f"AT-B78-30: a 1-variant project must render PLAIN on the status bar; "
        f"context={single_ctx!r}"
    )
    assert "solo" in single_panel and "solo:" not in single_panel, (
        f"AT-B78-30: a 1-variant project must render PLAIN in the Loaded panel; "
        f"panel={single_panel!r}"
    )

    # N == 2 -> the suffixed form, on both surfaces.
    assert "duo:a (1/2)" in multi_ctx, (
        f"AT-B78-30: a 2-variant project must render `project:variant (i/N)` on "
        f"the status bar; context={multi_ctx!r}"
    )
    assert "duo:a (1/2)" in multi_panel, (
        f"AT-B78-30: a 2-variant project must render `project:variant (i/N)` in "
        f"the Loaded panel; panel={multi_panel!r}"
    )


def test_at_b78_10_a_variant_switch_moves_both_surfaces(tmp_path: Path) -> None:
    """AT-B78-10 -- the update PATH, not just the end state.

    Driven through the SHIPPED affordance: `action_select_variant` opens
    `SelectVariantScreen`, the list index moves, `#variant_ok` is pressed, and
    activation routes through the real load worker. The AT never calls
    `update_project_labels` directly — a test that did would pass over an
    implementation whose load path never reaches the refresh at all.

    Asserted `before != after` PER SURFACE **and** `after` equal to the expected
    string: `before != after` alone is satisfied by any change, including a
    wrong one, and the expected form is what LLR-120.5 actually promises.
    """
    from textual.widgets import Button, ListView

    from s19_app.tui.screens import SelectVariantScreen

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        _make_project(app, "proj", {"a.s19": S19_A, "b.s19": S19_B})
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app._handle_load_project("proj")
            await _flush(pilot)
            before = _b79_both_surfaces(app)

            app.action_select_variant()
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, SelectVariantScreen)
            screen.query_one("#variant_list", ListView).index = 1
            await pilot.pause()
            screen.query_one("#variant_ok", Button).press()
            await pilot.pause()
            await app.workers.wait_for_complete()
            await _flush(pilot)

            after = _b79_both_surfaces(app)
            return before, after

    (ctx_before, panel_before), (ctx_after, panel_after) = asyncio.run(_drive())

    assert ctx_before != ctx_after, (
        f"AT-B78-10: the status bar must MOVE on a variant switch; "
        f"before={ctx_before!r} after={ctx_after!r}"
    )
    assert panel_before != panel_after, (
        f"AT-B78-10: the Loaded panel must MOVE on a variant switch; "
        f"before={panel_before!r} after={panel_after!r}"
    )
    assert "proj:b (2/2)" in ctx_after, (
        f"AT-B78-10: the status bar must land on the EXPECTED string, not merely "
        f"a different one; after={ctx_after!r}"
    )
    assert "proj:b (2/2)" in panel_after, (
        f"AT-B78-10: the Loaded panel must land on the EXPECTED string; "
        f"after={panel_after!r}"
    )


def test_tc_b78_12_hostile_a2l_name_is_control_safe_on_both_surfaces(
    tmp_path: Path,
) -> None:
    """TC-B78-12 -- the control-character limb (SEC-F1), on BOTH surfaces.

    The payload carries BOTH hostile shapes. That matters because the previous
    payload `[red]evil[/].a2l` contains ZERO control characters: it certifies
    the markup axis and is blind to the control axis, which is this batch's own
    F-6 shape.

    `markup=False` would pass a markup-only assertion and fail this one — it is
    a PARSE FLAG that performs no string transform, so `0x1b`, `0x9b`, `0x9d`
    reach the strip byte-identical. `U+009B` (single-byte C1 CSI) and `U+009D`
    (single-byte C1 OSC) carry no `\\x1b` at all.

    ⚠️ Measured platform bound, recorded rather than assumed: the full payload
    is NOT creatable as a filename on Windows — `\\x1b` and `\\x7f` are illegal
    path characters — so the state is set through the app's own attribute and
    the SHIPPED `update_project_labels` is then driven. The sink is the subject
    of LLR-120.4; the loader is not. The subset that IS reachable through a real
    file on this platform (`\\x9b`, `\\x9d`, markup brackets) is exactly the
    subset the spec's rationale calls out as legal Windows filename characters.
    """
    hostile = "evil\x1b[31m\x9b1m\x9d8;;http:x\x7f[red].a2l"

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        _make_project(app, "demoproj", {"a.s19": S19_A})
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app._handle_load_project("demoproj")
            await _flush(pilot)
            app.current_a2l_path = Path(hostile)
            app.update_project_labels()
            await pilot.pause()
            return (
                _b79_painted_strip(app, "#status_context"),
                _b79_painted_strip(app, "#loaded_slots"),
                _b79_status_context(app),
            )

    strip_ctx, strip_panel, rendered = asyncio.run(_drive())

    # Presence co-assertion first (C-40): an absence clause over an EMPTY strip
    # is vacuously true, so prove the payload actually reached the surface
    # before asserting what is missing from it.
    assert "evil" in rendered, (
        f"the hostile name must actually REACH the surface, or the control-class "
        f"assertion below is vacuous; rendered={rendered!r}"
    )

    for label, strip in (("#status_context", strip_ctx), ("#loaded_slots", strip_panel)):
        leaked = sorted(_B79_CONTROL_CLASS & set(strip))
        assert not leaked, (
            f"TC-B78-12: no codepoint of C0 u {{DEL}} u C1 may reach {label}'s "
            f"painted strip; leaked={[hex(ord(c)) for c in leaked]}"
        )


def test_tc_b78_09_nothing_loaded_shows_sentinels_not_blanks(tmp_path: Path) -> None:
    """TC-B78-09 -- empty boundary: both surfaces show `(none)`, never a blank.

    A blank is the failure this guards: it is what a surface renders when the
    update never ran, and it is indistinguishable from "loaded nothing" to the
    operator.
    """

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.update_project_labels()
            await pilot.pause()
            return _b79_both_surfaces(app)

    ctx, panel = asyncio.run(_drive())

    assert "(none)" in ctx, f"the status bar must show the sentinel; context={ctx!r}"
    from s19_app.tui.screens_directionb import LoadedArtifactsPanel

    assert LoadedArtifactsPanel._PROJECT_KIND in panel and "(none)" in panel, (
        f"the Loaded panel's project row must show the sentinel, not vanish; "
        f"panel={panel!r}"
    )


def test_tc_b78_10_a2l_without_a_project(tmp_path: Path) -> None:
    """TC-B78-10 -- alternative: an A2L loaded with NO project.

    The two halves are independent, and this is the arm that proves it: the A2L
    name must appear while the project stays at its sentinel.
    """

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        a2l = tmp_path / "orphan.a2l"
        a2l.write_text("/begin PROJECT p \"\" /end PROJECT\n", encoding="utf-8")
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.load_a2l_from_path(a2l)
            await _flush(pilot)
            return _b79_status_context(app)

    ctx = asyncio.run(_drive())

    assert "orphan.a2l" in ctx, f"the A2L half must render alone; context={ctx!r}"
    assert "(none)" in ctx, (
        f"the project half must stay at its sentinel with no project loaded; "
        f"context={ctx!r}"
    )


def test_tc_b78_42_three_variants_render_the_active_index(tmp_path: Path) -> None:
    """TC-B78-42 -- boundary: `N == 3`, active index 2, renders `(2/3)`.

    Guards the composition arithmetic against an off-by-one that `N == 2` cannot
    see: at two variants `(1/2)` and `(2/2)` are symmetric, so a wrong index
    base still produces a plausible string.
    """
    from textual.widgets import Button, ListView

    from s19_app.tui.screens import SelectVariantScreen

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        _make_project(
            app, "trio", {"a.s19": S19_A, "b.s19": S19_B, "c.s19": S19_A}
        )
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app._handle_load_project("trio")
            await _flush(pilot)
            app.action_select_variant()
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, SelectVariantScreen)
            screen.query_one("#variant_list", ListView).index = 1
            await pilot.pause()
            screen.query_one("#variant_ok", Button).press()
            await pilot.pause()
            await app.workers.wait_for_complete()
            await _flush(pilot)
            return _b79_both_surfaces(app)

    ctx, panel = asyncio.run(_drive())

    assert "(2/3)" in ctx, f"the status bar must read (2/3); context={ctx!r}"
    assert "(2/3)" in panel, f"the Loaded panel must read (2/3); panel={panel!r}"


def test_tc_b78_43_unload_all_clears_the_artifact_slots_not_the_context(
    tmp_path: Path,
) -> None:
    """TC-B78-43 -- negative: unload-all. The spec was HALF right, not wrong.

    ⚠️ **Corrected twice, and the second correction reverses part of the
    first.** The catalog reads *"unload all -> both surfaces return to
    `(none)`"*. My first pass measured that as false of BOTH halves and
    re-authored the node around the executed behaviour. The independent review
    (F6) showed that dismissed too much: the **A2L half of the catalog was
    RIGHT**, and what made it read as false was a defect, not a contract.

    `current_a2l_path` was written in two places and cleared in none, so the app
    held two sources of truth for "which A2L is in effect" —
    `current_file.a2l_path` (cleared on unload) and `current_a2l_path` (not).
    The Loaded panel read the fresh one and the context surface the stale one,
    so after an unload they contradicted each other about the same A2L on the
    same screen. Fixed at the source in `_apply_unload`, and this node now pins
    both halves:

    * **A2L half — returns to the sentinel.** The catalog was right.
    * **Project half — persists.** The catalog was wrong here: `_apply_unload`
      never touches `current_project`, and making it do so would change what
      unload-all MEANS, which is nowhere in `HLR-120`.

    The lesson is the one worth keeping: *a boundary catalog that disagrees with
    the code is not automatically wrong.* Measuring it told me the two differed;
    it did not tell me which one was mistaken, and I resolved that in favour of
    the code without asking the question for each half separately.
    `action_unload_all` delegates to `_apply_unload("all")`, which clears
    Before the fix, `_apply_unload("all")` cleared `current_file` and touched
    neither `current_project` nor `current_a2l_path`, so the status context read
    `'demoproj  |  ctx.a2l'` unchanged after an unload-all.

    The project half of the catalog stays rejected — making it true would mean
    unloading artifacts starts deselecting the project, which is nowhere in
    `HLR-120`'s statement. That half is owed upstream as a §6.5 Before/After
    amendment.

    The presence co-assertions are load-bearing: without them, "the sentinel is
    showing" is satisfied by a surface that never rendered anything at all.
    """

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        _make_project(app, "demoproj", {"a.s19": S19_A})
        a2l = tmp_path / "ctx.a2l"
        a2l.write_text('/begin PROJECT p "" /end PROJECT\n', encoding="utf-8")
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app._handle_load_project("demoproj")
            await _flush(pilot)
            app.load_a2l_from_path(a2l)
            await _flush(pilot)
            loaded = _b79_both_surfaces(app)
            app.action_unload_all()
            await _flush(pilot)
            return loaded, _b79_both_surfaces(app)

    (ctx_loaded, panel_loaded), (ctx_after, panel_after) = asyncio.run(_drive())

    # Presence co-assertions -- prove there was something to clear.
    assert "demoproj" in ctx_loaded and "ctx.a2l" in ctx_loaded, (
        f"both names must be present BEFORE the unload, or every assertion "
        f"below is vacuous; loaded={ctx_loaded!r}"
    )
    assert "demoproj" in panel_loaded, (
        f"the Loaded panel must name the project before the unload; "
        f"panel={panel_loaded!r}"
    )

    # The artifact slots empty -- this is what unload-all actually contracts.
    assert panel_after != panel_loaded, (
        f"the Loaded panel must MOVE on unload-all, or this node cannot tell an "
        f"unload from a no-op; loaded={panel_loaded!r} after={panel_after!r}"
    )

    # The A2L half RETURNS TO THE SENTINEL — the catalog was right about this,
    # and the F6 fix in `_apply_unload` is what makes it true. Asserted as the
    # name's ABSENCE plus the sentinel's presence: the sentinel alone would be
    # satisfied by the project half's own `(none)` in a two-part string.
    assert "ctx.a2l" not in ctx_after, (
        f"the A2L must be gone from the context after unload-all — a stale "
        f"`current_a2l_path` here means the two surfaces contradict each other "
        f"about the same A2L on the same screen; after={ctx_after!r}"
    )
    assert "(none)" in ctx_after, (
        f"the A2L half must render its sentinel, not a blank; after={ctx_after!r}"
    )

    # The project half PERSISTS, and that is correct, not a defect.
    assert "demoproj" in ctx_after, (
        f"the project half must PERSIST: `_apply_unload` never touches "
        f"`current_project`, so unloading artifacts does not deselect the "
        f"project; after={ctx_after!r}"
    )
    assert "demoproj" in panel_after, (
        f"the Loaded panel's project ROW must persist for the same reason; "
        f"after={panel_after!r}"
    )


def test_tc_b78_13_update_before_mount_does_not_raise(tmp_path: Path) -> None:
    """TC-B78-13 -- error boundary: the entry point is safe before mount.

    `update_project_labels` is reachable from load handlers that can run before
    the tree exists (headless unit tests do exactly this), so it must degrade to
    a no-op rather than raise — matching `_refresh_loaded_panel` /
    `_apply_empty_state`.
    """
    app = S19TuiApp(base_dir=tmp_path)
    app.update_project_labels()  # must not raise


# ---------------------------------------------------------------------------
# batch-79 Inc-9 -- HLR-119: `/` and `g` act on the ACTIVE screen, `Esc` releases
# ---------------------------------------------------------------------------

_B79_OWNING = {"workspace", "a2l", "mac"}


async def _b79_blurred(app, pilot) -> None:
    """LLR-119.4's precondition, asserted rather than assumed.

    A focused ``Input`` swallows a bare ``g`` as TEXT instead of dispatching the
    binding, so every node here would measure the wrong thing if something
    still held focus. Both Phase-1 lanes independently adopted this, and
    Phase-0 records the self-caught defect that produced it.
    """
    app.set_focus(None)
    await pilot.pause()
    assert app.focused is None, (
        f"the precondition failed: {app.focused!r} still holds focus, so the "
        f"single-letter key below would be swallowed as text"
    )


def _b79_owning_derivation(app) -> set:
    """The owning set, derived from the RULE rather than from the routing map.

    ⚠️ Deriving it from `_FIND_GOTO_INPUTS` would make the assertion
    "the map equals the map" — the artefact under test supplying its own
    oracle (C-40 limb 2). This walks the real widget tree with the pattern the
    requirement states, so the two can disagree and the node can fail.

    The pattern is normative because two honest derivations disagree: "any
    `Input` in the container" yields **7** (patch 5, diff 3, flow 1,
    crc_designer 13 inputs, none of them find or go-to), the id pattern yields
    **3**. An unstated grep pattern is an unstated definition.
    """
    import re

    from textual.widgets import Input

    pattern = re.compile(r"(search|goto)_input$")
    owning = set()
    for key, container in S19TuiApp.SCREEN_CONTAINER_IDS.items():
        ids = [w.id for w in app.query_one(f"#{container}").query(Input) if w.id]
        if any(pattern.search(i) for i in ids):
            owning.add(key)
    return owning


def test_at_b78_04_slash_and_g_focus_the_local_inputs(tmp_path: Path) -> None:
    """AT-B78-04 (GATE) -- on the 3 owning screens the keys focus LOCAL inputs.

    Today all ten screens focus the command bar's inputs, so this is RED on the
    pre-change tree by construction.

    The owning set is asserted by SET EQUALITY against a tree-walked derivation,
    with `len == 3` kept only as a redundant guard: a bare count would be
    satisfied by any three screens, and the derivation that gives 3 is the one
    the requirement states rather than the one the map asserts.
    """

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            derived = _b79_owning_derivation(app)
            observed = {}
            for key in sorted(_B79_OWNING):
                app.action_show_screen(key)
                await pilot.pause()
                await _b79_blurred(app, pilot)
                await pilot.press("slash")
                await pilot.pause()
                find_id = app.focused.id if app.focused else None
                await _b79_blurred(app, pilot)
                await pilot.press("g")
                await pilot.pause()
                goto_id = app.focused.id if app.focused else None
                observed[key] = (find_id, goto_id)
            return derived, observed

    derived, observed = asyncio.run(_drive())

    assert derived == _B79_OWNING, (
        f"the owning set derived from the widget tree must equal "
        f"{sorted(_B79_OWNING)}; derived {sorted(derived)}"
    )
    assert len(derived) == 3, f"redundant guard: expected 3, got {len(derived)}"

    expected = {
        "workspace": ("search_input", "goto_input"),
        "a2l": ("alt_search_input", "alt_goto_input"),
        "mac": ("mac_search_input", "mac_goto_input"),
    }
    for key, pair in expected.items():
        assert observed[key] == pair, (
            f"on {key!r}, `/` and `g` must focus that screen's OWN inputs "
            f"{pair}; observed {observed[key]}"
        )


def test_at_b78_05_the_seven_non_owning_screens_notice_exactly_once(
    tmp_path: Path,
) -> None:
    """AT-B78-05 (GATE) -- the notice path, which is the MAJORITY: 7 of 10.

    The gate is the notice COUNT per key, not "no exception raised" -- the
    latter is green on an action that does nothing at all, so it is kept below
    only as a labelled regression pin. *Exactly one* is what separates a notice
    from a notice-per-keystroke loop.

    ⚠️ **The spec's stated threshold is not measurable as written, and this node
    uses a different oracle for a recorded reason.** `LLR-119.2` reads
    *"`len(app.log_lines)` grows by exactly 1 per key on each of the 7
    screens"*. Executed: `log_lines` is a `deque(maxlen=4)` (`app.py:1445`), so
    its LENGTH saturates at 4 and stops growing after the fourth notice. Driving
    all seven screens, the first four report a delta of 1 and the last three
    report **0** -- with a correct implementation. A node asserting the spec's
    literal wording would have false-failed on whichever three screens happened
    to come last. Owed upstream as a §6.5 amendment.

    The oracle is therefore the SEQUENCE of emitted notices, captured through
    `set_status` -- the repo's established idiom (`_statuses` in
    `tests/test_tui_patch_variant.py`) -- paired with the rendered `#log_line_4`
    so the operator-visible deliverable is asserted too, not just the call.
    """

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            captured: list[str] = []
            original = app.set_status
            app.set_status = lambda message: (  # type: ignore[method-assign]
                captured.append(message),
                original(message),
            )[1]

            notice_screens = sorted(set(S19TuiApp.SCREEN_CONTAINER_IDS) - _B79_OWNING)
            observed = {}
            raised = []
            for key in notice_screens:
                app.action_show_screen(key)
                await pilot.pause()
                await _b79_blurred(app, pilot)
                try:
                    before = len(captured)
                    await pilot.press("slash")
                    await pilot.pause()
                    slash_delta = len(captured) - before
                    await _b79_blurred(app, pilot)
                    mid = len(captured)
                    await pilot.press("g")
                    await pilot.pause()
                    g_delta = len(captured) - mid
                except Exception as exc:  # pragma: no cover - the pin
                    raised.append((key, repr(exc)))
                    continue
                observed[key] = (slash_delta, g_delta, app.focused)
            tail = str(app.query_one("#log_line_4").render())
            return notice_screens, observed, raised, tail

    notice_screens, observed, raised, tail = asyncio.run(_drive())

    assert len(notice_screens) == 7, (
        f"the notice path must be 7 of 10 screens; got {len(notice_screens)}: "
        f"{notice_screens}"
    )
    assert len(observed) == 7, (
        f"every non-owning screen must have been exercised; got {sorted(observed)}"
    )
    # The GATE: exactly one notice per key, on every non-owning screen.
    for key, (slash_delta, g_delta, focused) in observed.items():
        assert slash_delta == 1, (
            f"on {key!r}, `/` must emit EXACTLY ONE notice; emitted {slash_delta}"
        )
        assert g_delta == 1, (
            f"on {key!r}, `g` must emit EXACTLY ONE notice; emitted {g_delta}"
        )
        assert focused is None, (
            f"on {key!r} nothing should have taken focus; focused={focused!r}"
        )
    # Regression PIN, labelled as such: green on an action that does nothing.
    assert not raised, f"no key may raise on a non-owning screen; raised={raised}"
    # The operator-visible deliverable, not merely the call: the tail NAMES the
    # absence rather than being any line at all.
    assert "no find" in tail.lower() or "no go-to" in tail.lower(), (
        f"the log tail must NAME the absence; #log_line_4={tail!r}"
    )


def test_at_b78_06_a_find_on_a2l_does_not_write_into_the_workspace(
    tmp_path: Path,
) -> None:
    """AT-B78-06 (GATE) -- the wrong-pane defect, with `== ""` as the load-bearing half.

    This is the executed defect HLR-119 exists for: with A2L active, a find used
    to write into the WORKSPACE `#search_input` and search the workspace map.

    **The `== ""` clause is the half that gates.** Asserting only that the A2L
    input carries the text would stay green on an implementation that wrote into
    BOTH — which is exactly what a presence-based resolution does.
    """

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("a2l")
            await pilot.pause()
            await _b79_blurred(app, pilot)
            await pilot.press("slash")
            await pilot.pause()
            for char in "BOOT":
                await pilot.press(char)
            await pilot.pause()
            return (
                str(app.query_one("#alt_search_input", Input).value),
                str(app.query_one("#search_input", Input).value),
            )

    a2l_value, workspace_value = asyncio.run(_drive())

    assert a2l_value == "BOOT", (
        f"the find must land in the A2L screen's own input; got {a2l_value!r}"
    )
    assert workspace_value == "", (
        f"the workspace input must be UNTOUCHED -- this is the clause that fails "
        f"on an implementation writing into both panes; got {workspace_value!r}"
    )


def test_at_b78_07_escape_releases_a_focused_input(tmp_path: Path) -> None:
    """AT-B78-07 (GATE) -- `Escape` moves focus off a find/goto input.

    Driven with `pilot.press("escape")` only. A node calling `.blur()` does not
    discharge LLR-119.3 — it would pass against an application with no escape
    handling whatsoever, which is precisely the pre-change state.

    ⚠️ The palette arm is the DISPOSITION this increment owed in writing. The
    spec asserted that this handler "must not shadow the palette's
    `escape`-to-close"; re-executed here, the palette HAS no such mechanism, so
    the original clause asserted a constraint against nothing. What is pinned
    instead is the true, checkable property: the handler leaves the palette
    exactly as it found it. Closing the palette's own dismissal is deferred as a
    carry — it is a new capability on a different widget, outside HLR-119.
    """
    from s19_app.tui.command_bar import CommandBar

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            released = {}
            for key in sorted(_B79_OWNING):
                app.action_show_screen(key)
                await pilot.pause()
                await _b79_blurred(app, pilot)
                await pilot.press("slash")
                await pilot.pause()
                focused_before = app.focused.id if app.focused else None
                await pilot.press("escape")
                await pilot.pause()
                released[key] = (
                    focused_before,
                    app.focused.id if app.focused else None,
                )
            # The palette arm.
            bar = app.query_one(CommandBar)
            await pilot.press("ctrl+k")
            await pilot.pause()
            palette_open_before = bar.palette_is_open
            await pilot.press("escape")
            await pilot.pause()
            return released, palette_open_before, bar.palette_is_open

    released, palette_before, palette_after = asyncio.run(_drive())

    for key, (before, after) in released.items():
        assert before is not None, (
            f"on {key!r} the input must have taken focus first, or the release "
            f"assertion is vacuous"
        )
        assert after != before, (
            f"on {key!r}, `escape` must move focus OFF {before!r}; it stayed"
        )

    # The palette is untouched -- neither shadowed nor accidentally improved.
    assert palette_before is True, "the palette must be open before the escape"
    assert palette_after is True, (
        "this handler must leave the palette exactly as it found it. The "
        "palette has no `escape`-to-close (command_bar.py declares no BINDINGS), "
        "so `escape` there is a no-op both before and after this increment; a "
        "CLOSED palette here would mean the handler reached a widget it has no "
        "requirement to touch."
    )


def test_tc_b78_46_the_other_screens_input_is_still_resolvable(
    tmp_path: Path,
) -> None:
    """TC-B78-46 -- the P-10 discrimination, white-box.

    Routing must be by SCREEN KEY, not by which inputs exist. The way to tell
    the two apart is to show that the workspace input is **still resolvable**
    while A2L is active and the action nonetheless resolves the A2L input — a
    presence-based implementation would be indistinguishable from a correct one
    without this.
    """

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("a2l")
            await pilot.pause()
            resolvable = app.query_one("#search_input", Input) is not None
            await _b79_blurred(app, pilot)
            await pilot.press("slash")
            await pilot.pause()
            return resolvable, (app.focused.id if app.focused else None)

    resolvable, focused = asyncio.run(_drive())

    assert resolvable, (
        "the workspace input must STILL resolve while A2L is active -- if it "
        "did not, this node could not tell key-routing from presence-routing"
    )
    assert focused == "alt_search_input", (
        f"the action must resolve the ACTIVE screen's input even though the "
        f"other one is resolvable; focused={focused!r}"
    )


def test_tc_b78_05_a_second_slash_adds_no_second_notice(tmp_path: Path) -> None:
    """TC-B78-05 -- boundary: `/` twice on a non-owning screen is idempotent.

    One press, one line. The failure this guards is a notice-per-keystroke loop,
    which "no exception raised" would never see.
    """

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("map")
            await pilot.pause()
            await _b79_blurred(app, pilot)
            before = len(app.log_lines)
            await pilot.press("slash")
            await pilot.pause()
            after_one = len(app.log_lines)
            await pilot.press("slash")
            await pilot.pause()
            return before, after_one, len(app.log_lines)

    before, after_one, after_two = asyncio.run(_drive())

    assert after_one - before == 1, f"the first `/` must add one line; {after_one - before}"
    assert after_two - after_one == 1, (
        f"the second `/` must add exactly one more, never a burst; "
        f"delta={after_two - after_one}"
    )


def test_tc_b78_06_switching_screens_re_points_the_key(tmp_path: Path) -> None:
    """TC-B78-06 -- boundary: the key follows the NEW screen after a switch.

    A resolution cached at first use, or bound to whichever input was focused,
    would pass every single-screen node and fail here.
    """

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("workspace")
            await pilot.pause()
            await _b79_blurred(app, pilot)
            await pilot.press("slash")
            await pilot.pause()
            first = app.focused.id if app.focused else None
            # Switch WHILE the input holds focus -- the harder ordering.
            app.action_show_screen("mac")
            await pilot.pause()
            await _b79_blurred(app, pilot)
            await pilot.press("slash")
            await pilot.pause()
            return first, (app.focused.id if app.focused else None)

    first, second = asyncio.run(_drive())

    assert first == "search_input", f"expected the workspace input; got {first!r}"
    assert second == "mac_search_input", (
        f"after switching to MAC the key must follow the NEW screen; got {second!r}"
    )


def test_tc_b78_08_slash_while_the_palette_is_open_does_not_steal_focus(
    tmp_path: Path,
) -> None:
    """TC-B78-08 -- negative: `/` is a literal character inside the palette.

    The one place in the application where `/` must NOT be a binding. If the
    action fired here it would yank focus out of `#palette_input` mid-typing.
    """
    from s19_app.tui.command_bar import CommandBar

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("workspace")
            await pilot.pause()
            await pilot.press("ctrl+k")
            await pilot.pause()
            bar = app.query_one(CommandBar)
            focused_before = app.focused.id if app.focused else None
            await pilot.press("slash")
            await pilot.pause()
            return bar.palette_is_open, focused_before, (
                app.focused.id if app.focused else None
            )

    palette_open, before, after = asyncio.run(_drive())

    assert palette_open, "the palette must be open for this node to mean anything"
    assert before == "palette_input", (
        f"the palette input must hold focus before the key; got {before!r}"
    )
    assert after == "palette_input", (
        f"`/` must stay a literal character inside the palette and must not "
        f"steal focus to a find input; focus moved to {after!r}"
    )


def test_tc_b78_41_focus_find_before_mount_does_not_raise(tmp_path: Path) -> None:
    """TC-B78-41 -- error boundary: the action is safe before the tree exists.

    Split off `TC-B78-46` at Phase 2: one id carrying two unrelated subjects is
    a node that cannot say which half failed.
    """
    app = S19TuiApp(base_dir=tmp_path)
    app.action_focus_find()  # must not raise
    app.action_focus_goto()  # must not raise


def test_tc_b78_04_no_file_loaded_still_focuses(tmp_path: Path) -> None:
    """TC-B78-04 -- empty boundary: focus moves with nothing loaded.

    The find input is a text box, not a view over the image, so an empty session
    must still reach it. The pre-existing "No file loaded." line is a SEARCH
    diagnostic and is unrelated to focus — asserted here as unchanged so the
    node cannot be satisfied by an implementation that logs instead of focusing.
    """

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("workspace")
            await pilot.pause()
            await _b79_blurred(app, pilot)
            before = len(app.log_lines)
            await pilot.press("slash")
            await pilot.pause()
            return (
                app.focused.id if app.focused else None,
                len(app.log_lines) - before,
            )

    focused, delta = asyncio.run(_drive())

    assert focused == "search_input", (
        f"focus must move even with nothing loaded; got {focused!r}"
    )
    assert delta == 0, (
        f"focusing an owning screen's input must log NOTHING -- a notice here "
        f"would mean the owning screen fell onto the notice path; delta={delta}"
    )


# ---------------------------------------------------------------------------
# batch-79 Inc-10 -- HLR-118: the command-bar row is deleted
# ---------------------------------------------------------------------------

_B79_DELETED_IDS = (
    "command_bar_row",
    "command_bar_prompt",
    "cmdbar_project",
    "cmdbar_a2l",
    "find_input",
    "cmdbar_goto_input",
)


def test_at_b78_01_the_row_is_absent_and_the_palette_survives(tmp_path: Path) -> None:
    """AT-B78-01 (GATE) -- the row is gone, the palette host is not.

    Three clauses, and the third is the one that gates:

    * every one of the six deleted ids resolves nowhere, on all 10 screens;
    * `#command_palette` is still a DIRECT child of `CommandBar` -- the widget
      and `#command_bar_slot` exist to host it, which is why the CSS deletion is
      `:66-103` and not `:55-102`;
    * **`#command_bar_slot` has height 0.** Without it, an implementation that
      deleted the row's CONTENT and left its three-row hole would satisfy both
      clauses above while the operator still stared at an empty band. Adopted
      wholesale from the QA lane, whose form was stronger than the author's
      query-only one.
    """
    from s19_app.tui.command_bar import CommandBar

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            per_screen = {}
            for key in list(S19TuiApp.SCREEN_CONTAINER_IDS):
                app.action_show_screen(key)
                await pilot.pause()
                present = [i for i in _B79_DELETED_IDS if len(app.query(f"#{i}")) > 0]
                per_screen[key] = (
                    present,
                    app.query_one("#command_bar_slot").size.height,
                )
            bar = app.query_one(CommandBar)
            palette_parent = app.query_one("#command_palette").parent
            return per_screen, (palette_parent is bar)

    per_screen, palette_is_direct_child = asyncio.run(_drive())

    assert len(per_screen) == 10, f"all 10 screens; got {len(per_screen)}"
    for key, (present, slot_height) in per_screen.items():
        assert not present, (
            f"on {key!r} these deleted ids still resolve: {present}"
        )
        assert slot_height == 0, (
            f"on {key!r} `#command_bar_slot` still spends {slot_height} rows. "
            f"Deleting the row's CONTENT while leaving its hole is the "
            f"implementation this clause exists to defeat."
        )
    assert palette_is_direct_child, (
        "`#command_palette` must remain a DIRECT child of `CommandBar` -- the "
        "widget survives HLR-118 precisely to host it"
    )


def test_at_b78_02_ctrl_k_opens_the_palette_everywhere(tmp_path: Path) -> None:
    """AT-B78-02 (PIN) -- `Ctrl+K` still opens the palette on all 10 screens.

    Labelled a PIN, not a gate: it is GREEN today and green before the change,
    so it cannot gate `HLR-118`. It is kept because the deletion runs through
    the widget that hosts the palette, and a regression here would be silent
    everywhere else.
    """
    from s19_app.tui.command_bar import CommandBar

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            opened = {}
            bar = app.query_one(CommandBar)
            for key in list(S19TuiApp.SCREEN_CONTAINER_IDS):
                app.action_show_screen(key)
                await pilot.pause()
                app.set_focus(None)
                await pilot.pause()
                await pilot.press("ctrl+k")
                await pilot.pause()
                opened[key] = bar.palette_is_open
                await pilot.press("escape")
                await pilot.pause()
                bar.close_palette()
                await pilot.pause()
            return opened

    opened = asyncio.run(_drive())

    assert len(opened) == 10 and all(opened.values()), (
        f"`ctrl+k` must open the palette on all 10 screens; got {opened}"
    )


def test_at_b78_03_the_palette_action_set_matches_the_frozen_artifact(
    tmp_path: Path,
) -> None:
    """AT-B78-03 (GATE) -- the action set equals the Inc-0 ARTIFACT, not the producer.

    ⚠️ **This node was provably INERT before Inc-0 froze the artifact, and the
    reason is worth carrying.** `CommandBar` is constructed as
    `CommandBar(self._build_palette_entries())`, so an implementation comparing
    the rendered palette against `_build_palette_entries()` compares a producer
    with ITSELF: executed, the predicate stayed GREEN at `36 == 36` with a whole
    `Binding` removed from `S19TuiApp.BINDINGS`.

    What breaks the circularity is the TEMPORAL FREEZE -- a set captured before
    the change and read back from disk. So this reads
    `tests/goldens/batch78/at-b78-03-palette-actions.json` and **never
    regenerates it**; a run that rebuilds it has restored the tautology.
    """
    import json

    from s19_app.tui.command_bar import CommandBar

    frozen = json.loads(
        Path("tests/goldens/batch78/at-b78-03-palette-actions.json").read_text(
            encoding="utf-8"
        )
    )
    expected = frozen if isinstance(frozen, list) else frozen.get("actions", frozen)

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            bar = app.query_one(CommandBar)
            await pilot.press("ctrl+k")
            await pilot.pause()
            rows = list(bar.query_one("#palette_list").children)
            return [item.data for item in rows]

    observed = asyncio.run(_drive())

    assert len(expected) == 37, (
        f"the frozen artifact must still carry 37 actions; it has "
        f"{len(expected)} -- if this fails the artifact was REGENERATED, which "
        f"restores the tautology this node exists to break"
    )
    assert observed == list(expected), (
        f"the palette action set must equal the Inc-0 freeze.\n"
        f"missing: {sorted(set(expected) - set(observed))}\n"
        f"unexpected: {sorted(set(observed) - set(expected))}"
    )
