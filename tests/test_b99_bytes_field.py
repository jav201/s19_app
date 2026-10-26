"""Batch-99 Increment 11 — the Bytes field reads one base (HLR-161).

LLR-161.1 (amends batch-07 LLR-001.2): ``parse_new_bytes`` reads every
token as hexadecimal, with an optional ``0x`` prefix, accepts 1–2 hex
digits and refuses any other token with a message naming it (P-16: at
HEAD a digit-only token was read as decimal, so ``0F 10 1F 20`` applied
as ``0F 0A 1F 14``). LLR-161.2: the field's placeholder and the Patch
Editor's window help state that tokens are hex — TC-B99-33 pins text
that is absent at HEAD (PQ-6 / UX-C9: the help already said "a run of
hex bytes", so asserting only "contains hex" would be vacuous).

- **TC-B99-32** — the hex-only token grammar of ``parse_new_bytes``.
- **TC-B99-33** — the placeholder and the help state the hex rule; the
  placeholder fits the compact input at width 118 without clipping.
- **AT-B99-12** — the pilot types ``0F 10 1F 20`` at an in-image address
  in the Patch Editor, adds, applies, confirms the save-back prompt; the
  saved file holds ``0F 10 1F 20`` (independent reader).
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from s19_app.tui.services.change_service import parse_new_bytes
from tests.support.independent_reader import read_s19


# ---------------------------------------------------------------------------
# TC-B99-32 — LLR-161.1: hex-only token grammar
# ---------------------------------------------------------------------------


def test_tc_b99_32_hex_only_token_grammar() -> None:
    """TC-B99-32 (LLR-161.1): every token is base 16, ``0x`` optional.

    Boundary: ``00`` and ``FF`` accepted (1–2 hex digits). Invalid:
    ``100`` (three digits), ``G1`` (not hex), ``0x123`` (three digits),
    ``+F`` / ``-1`` (a sign — ``int(token, 16)`` alone would admit them;
    ``-1`` surfaced later as a ChangeEntry value-range refusal naming the
    value, not the token), ``0x+F`` (sign after the prefix), ``１２`` and
    ``٣٣`` (fullwidth / Arabic-Indic digits — non-ASCII, refused because the
    grammar is ASCII-only) — each refused with a ``ValueError`` naming the
    token.
    """
    assert parse_new_bytes("0F 10 1F 20") == [0x0F, 0x10, 0x1F, 0x20]
    assert parse_new_bytes("11 22") == [0x11, 0x22]
    assert parse_new_bytes("0x0A ff") == [0x0A, 0xFF]
    assert parse_new_bytes("00") == [0x00]
    assert parse_new_bytes("FF") == [0xFF]
    for bad in ("100", "G1", "0x123", "+F", "-1", "0x+F", "１２", "٣٣"):
        with pytest.raises(ValueError) as err:
            parse_new_bytes(bad)
        assert bad in str(err.value), (
            f"the refusal must name the token {bad!r}; got {err.value!r}"
        )


# ---------------------------------------------------------------------------
# TC-B99-33 — LLR-161.2: the field and the help say hex
# ---------------------------------------------------------------------------


def test_tc_b99_33_field_and_help_state_the_hex_rule(tmp_path: Path) -> None:
    """TC-B99-33 (LLR-161.2): the placeholder contains ``hex``, fits the
    compact input at width 118 without clipping, and the Patch Editor's
    window help states the rule — every token is hex, ``0x`` is optional,
    decimals are not accepted. The String line keeps the document-encoding
    note (string entries are unchanged by HLR-161).

    RED on HEAD: the placeholder is ``DE AD BE EF`` (no ``hex``) and the
    help line reads "a run of hex bytes" without the rule (PQ-6 / UX-C9).
    """

    async def _drive() -> tuple[str, int, list[str]]:
        from textual.widgets import Input

        from s19_app.tui.app import S19TuiApp
        from s19_app.tui.window_help import WINDOW_HELP_SECTIONS

        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(118, 54)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            field = app.query_one("#patch_entry_bytes_input", Input)
            placeholder = field.placeholder
            inner_width = field.content_size.width
        steps = list(WINDOW_HELP_SECTIONS["patch"]["steps"])
        return placeholder, inner_width, steps

    placeholder, inner_width, steps = asyncio.run(_drive())

    assert "hex" in placeholder, (
        f"the Bytes placeholder must state hex; got {placeholder!r}"
    )
    assert len(placeholder) <= inner_width, (
        f"placeholder {placeholder!r} ({len(placeholder)} chars) clips the "
        f"compact input at width 118 (inner {inner_width})"
    )

    bytes_lines = [line for line in steps if line.startswith("Bytes")]
    assert len(bytes_lines) == 1, steps
    bytes_line = bytes_lines[0]
    assert "hex" in bytes_line
    assert "0x" in bytes_line, (
        f"the help must state the 0x prefix is optional; got {bytes_line!r}"
    )
    assert "decimal" in bytes_line and "not accepted" in bytes_line, (
        f"the help must state decimals are not accepted; got {bytes_line!r}"
    )

    string_lines = [line for line in steps if line.startswith("String")]
    assert len(string_lines) == 1, steps
    assert "encoding" in string_lines[0], (
        "the String line must keep the document-encoding note (string "
        f"entries are unchanged); got {string_lines[0]!r}"
    )


# ---------------------------------------------------------------------------
# AT-B99-12 — HLR-161: the typed run saves back in hex
# ---------------------------------------------------------------------------


def test_at_b99_12_typed_hex_run_saves_back(tmp_path: Path) -> None:
    """AT-B99-12 (HLR-161): typing ``0F 10 1F 20`` at an in-image address
    in the Patch Editor, adding, applying and confirming the save-back
    prompt writes a file holding ``0F 10 1F 20`` at that address, read
    with the independent reader.

    Black-box: the image loads through the app's own load path (the
    ``b97_fixtures`` idiom), the saved file is found on disk under the
    work area by the name the save-back prompt shows, and only the
    independent reader inspects the bytes — no injected state, no
    internal attribute or service.

    RED on HEAD (P-16): the digit-only tokens ``10`` and ``20`` were read
    as decimal, so the file held ``0F 0A 1F 14``.
    """
    from textual.widgets import Button, Input

    from s19_app.tui.app import S19TuiApp
    from s19_app.tui.changes import emit_s19_from_mem_map
    from s19_app.tui.workspace import WORKAREA_DIRNAME, WORKAREA_SUBDIR

    mem_map = {0x100 + offset: 0x00 for offset in range(16)}
    image_path = tmp_path / "img.s19"
    image_path.write_text(
        emit_s19_from_mem_map(mem_map, [(0x100, 0x110)]), encoding="ascii"
    )
    workarea = tmp_path / WORKAREA_DIRNAME / WORKAREA_SUBDIR

    async def _drive() -> Path:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            # Load through the shipped Load file dialog (rail key ``l``),
            # typed and confirmed by click; wait on the painted status line.
            await pilot.press("l")
            for _ in range(6):
                await pilot.pause()
            assert await pilot.click("#load_path"), "click missed #load_path"
            await pilot.press(*str(image_path))
            assert await pilot.click("#load_ok"), "click missed #load_ok"
            status = ""
            for _ in range(200):
                await pilot.pause(0.05)
                status = str(app.query_one("#log_line_4").render())
                if f"Loaded {image_path.name}" in status:
                    break
            assert f"Loaded {image_path.name}" in status, status
            # Patch Editor by its rail key.
            await pilot.press("6")
            for _ in range(6):
                await pilot.pause()

            # Type through the real key path (focus + keys, no .value=).
            address = app.query_one("#patch_entry_address_input", Input)
            address.focus()
            await pilot.pause()
            await pilot.press(*list("0x100"))
            await pilot.pause()

            field = app.query_one("#patch_entry_bytes_input", Input)
            field.focus()
            await pilot.pause()
            await pilot.press(
                *(ch if ch != " " else "space" for ch in "0F 10 1F 20")
            )
            await pilot.pause()
            assert field.value == "0F 10 1F 20", field.value

            # Press the shipped buttons (the save-back confirm sits in a
            # hidden prompt container until Apply, so a pilot click would
            # land on a zero-region widget).
            app.query_one("#patch_entry_add_button", Button).press()
            await pilot.pause()
            app.query_one("#patch_doc_apply_button", Button).press()
            await pilot.pause()
            await pilot.pause()
            await pilot.pause()

            # The shipped name input pre-fills the save-back suggestion;
            # read it (a painted widget value) and find the written file
            # on disk under the work area.
            saved_name = app.query_one(
                "#patch_saveback_name_input", Input
            ).value
            assert saved_name, "the save-back prompt pre-fills the name"
            app.query_one("#patch_saveback_confirm_button", Button).press()
            await pilot.pause()
            target = workarea / saved_name
            for _ in range(100):
                if target.exists():
                    break
                await pilot.pause(0.05)
            assert target.exists(), (
                f"the save-back prompt must write {saved_name!r} under the "
                f"work area; {target} is absent"
            )
            return target

    written = asyncio.run(_drive())
    out = read_s19(written)
    assert out.errors == [], out.errors
    assert [out.data[0x100 + i] for i in range(4)] == [0x0F, 0x10, 0x1F, 0x20], (
        f"the saved file must hold the typed run 0F 10 1F 20 at 0x100; "
        f"got {[out.data.get(0x100 + i) for i in range(4)]}"
    )
