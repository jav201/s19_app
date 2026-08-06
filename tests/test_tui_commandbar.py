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

#: Method names that would rewrite an artifact if pointed at one.
_B78_WRITE_METHODS = frozenset(
    {"write_text", "write_bytes", "write", "writelines", "mkdir", "touch", "unlink"}
)


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

    Falsifiable on both limbs: corrupt one stored byte and (a) reddens; add
    ``_b78_artifact(...).write_text(...)`` to any test module and (b) reddens.

    Scope limit, stated rather than implied: (b) is a token census over calls
    whose receiver names ``b78_artifact``. A module reconstructing the path
    from raw string literals would evade it. It bounds accident, not intent.
    """
    # --- (a) the artifacts exist, byte-for-byte, in the declared shapes -----
    for name, expected_digest in _B78_ARTIFACT_DIGESTS.items():
        path = _B78_ARTIFACT_DIR / name
        assert path.is_file(), (
            f"Inc-0 artifact {name!r} is missing from {_B78_ARTIFACT_DIR}; it is "
            f"the only oracle its consumer has and cannot be regenerated once a "
            f"production edit has landed"
        )
        actual_digest = blake2b(path.read_bytes(), digest_size=8).hexdigest()
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
        source = module.read_text(encoding="utf-8")
        swept.append(module.name)
        for node in ast.walk(ast.parse(source)):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr not in _B78_WRITE_METHODS:
                continue
            receiver = ast.get_source_segment(source, node.func.value) or ""
            if "b78_artifact" in receiver.lower():
                offenders.append(f"{module.name}:{node.lineno} {node.func.attr}")

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
