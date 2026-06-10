"""
Patch Editor memory-change integration tests — s19_app batch-04, increment 8;
enacted to the v2 consolidated Patch Editor at batch-07 E3b (§6.6
dispositions).

What remains here after the retirement:

- the four **TUI-input grammar** helper unit checks (SURVIVES — re-pointed to
  ``services/change_service.py``, the v2 home of ``parse_address`` /
  ``parse_new_bytes``; the permissive grammar is the TUI-input convenience of
  the LLR-001.2 grammar split, never the file format);
- the entry-row display REWRITE (the v2 ``ChangeService.rows`` value column
  carries the hex byte preview and the containment status); and
- the bad-address-is-reported REWRITE (an unparseable address typed into the
  v2 panel is a status-line report, never a crash).

Everything else moved with the model: the add/edit/remove/save/load screen
arms are covered by ``test_tui_patch_editor_v2.py::
test_action_routing_observable_effects`` and ``test_change_service.py``; the
malformed-load arm by ``test_tui_patch_editor_v2.py::test_legacy_load_
rejected``; the parameter-half and export arms retired with the cfdx flow;
the scroll-to-export-button arm (D3) retired with the export control itself
(resolved by measurement at E3a).
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from textual.widgets import Input

from s19_app.tui.app import S19TuiApp
from s19_app.tui.screens_directionb import PatchEditorPanel
from s19_app.tui.services.change_service import (
    ChangeService,
    parse_address,
    parse_new_bytes,
)


# ===========================================================================
# Entry-row display — the value column shows the hex run and the status
# (REWRITE of batch-04 TC-032's row-content arm, re-targeted to the v2
# service rows; LLR-003.1 columns)
# ===========================================================================


def test_entry_row_shows_hex_value_and_status() -> None:
    """A bytes-entry row shows the hex byte rendering and a status.

    Intent (carried from batch-04 TC-032): a row's columns are the hex
    address, the hex rendering of the declared bytes, and the validation
    status. With no image loaded the status is ``unvalidated-no-image``.
    """
    service = ChangeService()
    service.add_entry("0x100", "", "0x01 0xAB 0xFF")

    (row,) = service.rows(None)

    assert row.address_text == "0x100", "the address column must show hex"
    assert row.value_text == "01 AB FF", (
        f"the value column must show the hex byte run, got {row.value_text!r}"
    )
    assert row.status_text == "unvalidated-no-image", (
        f"with no image loaded the status must be unvalidated-no-image, "
        f"got {row.status_text!r}"
    )


# ===========================================================================
# Bad address is reported, never raised (REWRITE of batch-04 TC-033's
# bad-address arm, re-targeted to the v2 panel; LLR-003.2 routing)
# ===========================================================================


def test_bad_entry_address_is_reported_not_raised(tmp_path: Path) -> None:
    """An invalid address typed into the v2 panel is reported, never raised.

    Intent (carried from batch-04 TC-033): an unparseable address field is a
    user error surfaced through the status path — the ``add_entry`` action
    must not crash the Patch Editor and must not land a half-built entry.
    """

    async def _drive() -> tuple[int, bool]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            app.query_one("#patch_entry_address_input", Input).value = (
                "not-an-address"
            )
            app.query_one("#patch_entry_bytes_input", Input).value = "01"
            panel.request_action("add_entry")  # must not raise
            await pilot.pause()
            # Status lines truncate at 50 chars (E3a contract), so assert
            # the parse-error prefix, not the full bad literal.
            reported = any(
                line.startswith("Patch Editor:") and "invalid literal" in line
                for line in app.log_lines
            )
            return len(app._change_service.document.entries), reported

    entry_count, reported = asyncio.run(_drive())
    assert entry_count == 0, (
        "a bad address must be reported, not added and not raised"
    )
    assert reported, "the bad address must surface on the status path"


# ===========================================================================
# Service-helper unit checks — the memory address / new-bytes parsers
# (SURVIVES — re-pointed to services/change_service.py)
# ===========================================================================


def test_parse_address_accepts_hex_and_decimal() -> None:
    """A memory address parses from a 0x hex or a plain decimal literal."""
    assert parse_address("0x100") == 256
    assert parse_address("512") == 512


def test_parse_address_rejects_blank_and_negative() -> None:
    """A blank or negative memory address is rejected."""
    with pytest.raises(ValueError):
        parse_address("")
    with pytest.raises(ValueError):
        parse_address("-1")


def test_parse_new_bytes_accepts_hex_decimal_and_bare_hex() -> None:
    """A new-bytes field parses prefixed hex, decimal and bare hex tokens."""
    assert parse_new_bytes("0x01 0xAB 0xFF") == [1, 171, 255]
    assert parse_new_bytes("DE AD BE EF") == [222, 173, 190, 239]
    assert parse_new_bytes("1, 2, 3") == [1, 2, 3]


def test_parse_new_bytes_rejects_a_garbage_token() -> None:
    """A non-numeric byte token is rejected."""
    with pytest.raises(ValueError):
        parse_new_bytes("01 ZZ 03")
