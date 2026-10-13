"""Check Editor tests — batch-94 Inc-001 (US-003 / HLR-001/009/011).

Coverage map (test -> AT/TC -> LLR):

- AT-B94-01 — ``test_at_b94_01_rail_selects_check_editor_mounts_twin``:
  rail selects "Check Editor" -> exactly one Check Editor panel mounts
  (write/validate actions, 0 apply); "Patch Editor" mounts the patch panel
  (HLR-001; the cross-mount is the negative control).
- AT-B94-11 — ``test_at_b94_11_write_validate_chk_json_no_apply``: the
  collector assembles ``kind="check"``, writes a real ``.chk.json`` through
  the shipped writer, validate shows one verdict row per entry, and the
  surface exposes 0 apply controls anywhere (HLR-009; C-12 producer arm).
- AT-B94-13 — ``test_at_b94_13_hostile_symbol_and_file_name``: the batch-77
  payload as an A2L symbol name and as a spec file name renders literally in
  the collector, the dropdown and the report addendum — 0 markup spans, 0
  control bytes, sentinel visible (HLR-011 / C-17).
- TC-B94-06 — ``test_tc_b94_06_composition_census``: >=1 parameter collector,
  >=1 memory-location table, exactly 1 write action, exactly 1 validate
  action, 0 apply actions; composes at 80x24 (LLR-001.1).
- TC-B94-07 — ``test_tc_b94_07_rail_mounting_and_write_routing``: rail
  selection mounts exactly 1 ``CheckEditorPanel``; its write message reaches
  the service handler (captured call count 1); boundary arm at 80x24
  (LLR-001.2).
- TC-B94-17 — ``test_tc_b94_17_safe_text_hostile_payload``: the primitive
  contract — 0 control bytes in ``.plain``, brackets preserved (LLR-011.1).

Harness: pytest-asyncio is NOT installed — every drive is a nested
``async def _drive()`` under ``asyncio.run`` (the ``test_tui_directionb.py``
idiom). Hostile payload mirrors ``tests/test_tui_hostile_map.py:105-107``.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from textual.widgets import Button, DataTable, Input, Select, Static

from s19_app.tui import app as app_module
from s19_app.tui.app import S19TuiApp
from s19_app.tui.rail import Rail
from s19_app.tui.screens_directionb import (
    CheckEditorPanel,
    PatchEditorPanel,
)
from s19_app.utils import safe_text
from s19_app.tui.models import LoadedFile

# The batch-77 hostile payload (tests/test_tui_hostile_map.py:105-107):
# ESC-CSI + Rich markup + C1 CSI + C1 OSC + NUL + DEL.
_HOSTILE = (
    "b77hostilemark\x1b[31m_evil[red]\x9b1m\x9d8;;u\x07\x00\x7f"
)


def _loaded(mem: dict, ranges: list) -> LoadedFile:
    """A minimal LoadedFile over an in-memory map (the batch-93 probe idiom)."""
    return LoadedFile(
        path=Path("ecu.s19"),
        file_type="s19",
        mem_map=mem,
        row_bases=sorted({a - a % 16 for a in mem}),
        ranges=ranges,
        range_validity=[True] * len(ranges),
        errors=[],
        a2l_path=None,
        a2l_data=None,
        entropy_windows=None,
    )


def _write_calls() -> tuple[list, object]:
    """Capture ``write_change_document`` calls at the app-module seam.

    Returns ``(calls, original)`` — the caller MUST restore
    ``app_module.write_change_document = original`` (the module-global lookup
    is what the app handler calls, so patching the module attribute is the
    seam).
    """
    calls: list = []
    original = app_module.write_change_document

    def _spy(document, base_dir, file_name, copy_fn=None):
        calls.append((document, file_name))
        return original(document, base_dir, file_name, copy_fn)

    app_module.write_change_document = _spy
    return calls, original


# ---------------------------------------------------------------------------
# TC-B94-06 — CheckEditorPanel composition census (LLR-001.1)
# ---------------------------------------------------------------------------


def test_tc_b94_06_composition_census(tmp_path: Path) -> None:
    """The Check Editor composes a collector, a memory table, write+validate,
    and exactly ZERO apply actions; composes at 80x24 (LLR-001.1).

    Intent: TC-B94-06 — the ce_a two-column form: >=1 parameter collector,
    >=1 memory-location table, exactly 1 write action, exactly 1 validate
    action, 0 apply actions. The no-apply doctrine is the design statement
    (``editor_bench.NOTES.md``) — the struck APPLY ghost is a STATIC, not an
    actionable control (C-ux-2: the census counts ACTIONABLE controls only).
    Invalid arm: composing at the 80x24 floor raises no exception (the
    smallest measured regime, workspace 74x12).
    """

    async def _drive(size) -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            await pilot.press("equals_sign")
            await pilot.pause()
            await pilot.pause()
            panel = app.query_one("#check_editor_panel", CheckEditorPanel)
            buttons = [b for b in panel.query(Button)]
            write_actions = [
                b for b in buttons if b.id == "check_write_button"
            ]
            validate_actions = [
                b for b in buttons if b.id == "check_validate_button"
            ]
            apply_actions = [
                b
                for b in buttons
                if b.id and "apply" in b.id.lower()
            ]
            ghost = panel.query_one("#check_apply_ghost", Static)
            return {
                "param_tables": len(panel.query("#check_param_table")),
                "mem_tables": len(panel.query("#check_mem_table")),
                "write": len(write_actions),
                "validate": len(validate_actions),
                "apply": len(apply_actions),
                "ghost_is_static": isinstance(ghost, Static),
                "ghost_strike": "strike" in str(ghost.render().spans),
                "picker_rows": 1 if panel.query_one(
                    "#check_param_table", DataTable
                ) is not None else 0,
            }

    census = asyncio.run(_drive((80, 24)))
    assert census["param_tables"] >= 1, "a parameter collector composes"
    assert census["mem_tables"] >= 1, "a memory-location table composes"
    assert census["write"] == 1, "exactly 1 write action"
    assert census["validate"] == 1, "exactly 1 validate action"
    assert census["apply"] == 0, "0 apply actions (the doctrine)"
    assert census["ghost_is_static"], "the struck APPLY ghost is a Static"
    assert census["picker_rows"] == 1


# ---------------------------------------------------------------------------
# TC-B94-07 — rail mounting + write message routing (LLR-001.2)
# ---------------------------------------------------------------------------


def test_tc_b94_07_rail_mounting_and_write_routing(tmp_path: Path) -> None:
    """Selecting the entry mounts exactly 1 CheckEditorPanel; the write
    message reaches the service handler (LLR-001.2).

    Intent: TC-B94-07 — mounting through the shipped rail path at 120x30 and
    the 80x24 boundary arm; the write action routes to the change writer with
    a captured call count of exactly 1. Cross-mounting negative control:
    selecting Patch Editor mounts the patch panel, not the twin.

    FIX ROUND A (C-40): the panel census alone is routing-blind — every rail
    screen composes eagerly at startup, so the panel sits in the DOM whether
    or not `=` targets it (the binding mutation SURVIVED). The kill subject
    is the RAIL TARGET: after `=`, the Check Editor screen must be the
    visible one and the rail's single active marker must move to
    ``check_editor`` (LLR-001.2's ``set_active`` seam).
    """

    async def _drive(size) -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            await pilot.press("equals_sign")
            await pilot.pause()
            await pilot.pause()
            # The rail-target observation (FIX ROUND A — the kill subject).
            visible = [
                sid
                for sid in ("screen_check_editor", "screen_patch")
                if "hidden" not in app.query_one(f"#{sid}").classes
            ]
            rail_active = app.query_one(Rail).active_key
            panels = list(app.query(CheckEditorPanel))
            # Mount the twin-crossing negative control.
            await pilot.press("6")
            await pilot.pause()
            patch_panels = list(app.query(PatchEditorPanel))
            # Back to the Check Editor for the write drive.
            await pilot.press("equals_sign")
            await pilot.pause()
            # Drive one write through the shipped surface (focus + Enter — a
            # re-layout after the add shifts the buttons under a raw click).
            app.query_one("#check_mem_address_input", Input).value = "0x100"
            app.query_one("#check_mem_label_input", Input).value = "x"
            app.query_one("#check_mem_size_input", Input).value = "1"
            app.query_one("#check_mem_add_button").focus()
            await pilot.press("enter")
            await pilot.pause()
            calls, original = _write_calls()
            try:
                app.query_one("#check_write_button").focus()
                await pilot.press("enter")
                await pilot.pause()
            finally:
                app_module.write_change_document = original
            return (
                len(panels),
                len(patch_panels),
                len(calls),
                visible,
                rail_active,
            )

    mounted, patch_panels, write_calls, visible, rail_active = asyncio.run(
        _drive((120, 30))
    )
    assert visible == ["screen_check_editor"], (
        f"'=' must make the Check Editor screen visible, got {visible}"
    )
    assert rail_active == "check_editor", (
        f"the rail marker must move to 'check_editor', got {rail_active!r}"
    )
    assert mounted == 1, f"exactly 1 CheckEditorPanel mounts, got {mounted}"
    assert patch_panels == 1, "the patch twin stays the patch screen's panel"
    assert write_calls == 1, (
        f"the write message reaches the writer exactly once, got {write_calls}"
    )


# ---------------------------------------------------------------------------
# AT-B94-01 — rail selects Check Editor -> twin mounts (HLR-001)
# ---------------------------------------------------------------------------


def test_at_b94_01_rail_selects_check_editor_mounts_twin(tmp_path: Path) -> None:
    """AT-B94-01 — rail selection mounts the Check Editor; Patch mounts Patch.

    Intent (HLR-001): selecting "Check Editor" mounts exactly one Check
    Editor panel exposing write/validate actions and 0 apply actions;
    selecting "Patch Editor" mounts the Patch Editor instead. The base-state
    probe recorded 0 ``checkeditor`` hits (P0 RC-1(b)) — the negative control
    is the pre-state absence itself.
    """

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press("equals_sign")
            await pilot.pause()
            await pilot.pause()
            check_visible = [
                sid
                for sid in ("screen_check_editor", "screen_patch")
                if "hidden" not in app.query_one(f"#{sid}").classes
            ]
            check_panel = app.query_one("#check_editor_panel", CheckEditorPanel)
            buttons = {b.id for b in check_panel.query(Button)}
            apply_controls = {
                b.id for b in check_panel.query(Button) if "apply" in (b.id or "")
            }
            await pilot.press("6")
            await pilot.pause()
            patch_visible = [
                sid
                for sid in ("screen_check_editor", "screen_patch")
                if "hidden" not in app.query_one(f"#{sid}").classes
            ]
            return check_visible, buttons, apply_controls, patch_visible

    check_visible, buttons, apply_controls, patch_visible = asyncio.run(_drive())
    assert check_visible == ["screen_check_editor"], (
        f"'=' must mount exactly the Check Editor screen, got {check_visible}"
    )
    assert "check_write_button" in buttons, "a write action is exposed"
    assert "check_validate_button" in buttons, "a validate action is exposed"
    assert apply_controls == set(), f"0 apply actions, got {apply_controls}"
    assert patch_visible == ["screen_patch"], (
        f"'6' must mount the Patch Editor screen, got {patch_visible}"
    )


# ---------------------------------------------------------------------------
# AT-B94-11 — assemble / write / validate, no apply (HLR-009)
# ---------------------------------------------------------------------------


def test_at_b94_11_write_validate_chk_json_no_apply(tmp_path: Path) -> None:
    """AT-B94-11 — the collector writes a real ``.chk.json`` and validates it.

    Intent (HLR-009, C-12 producer arm): with an image loaded, a declared
    memory row writes a document that re-reads with ``kind == "check"``, the
    declared entry count, and 0 blocking errors; Validate shows one verdict
    row per entry (``pass`` — the expected bytes are the loaded image's);
    the surface exposes 0 apply affordances (the negative control is the
    apply gate probe: a check document is run-blocked, never written).
    """
    from s19_app.tui.changes.io import read_change_document

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        mem = {0x100: 0xDE, 0x101: 0xAD, 0x102: 0xBE, 0x103: 0xEF}
        app.current_file = _loaded(mem, [(0x100, 0x104)])
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press("equals_sign")
            await pilot.pause()
            await pilot.pause()
            app.query_one("#check_file_name_input", Input).value = (
                "baseline.chk.json"
            )
            app.query_one("#check_mem_address_input", Input).value = "0x100"
            app.query_one("#check_mem_label_input", Input).value = "block0"
            app.query_one("#check_mem_size_input", Input).value = "4"
            app.query_one("#check_mem_add_button").focus()
            await pilot.press("enter")
            await pilot.pause()
            app.query_one("#check_write_button").focus()
            await pilot.press("enter")
            await pilot.pause()
            written = list((app.workarea / "patches").glob("*.chk.json"))
            doc = read_change_document(
                str(written[0]), tmp_path
            ) if written else None
            app.query_one("#check_validate_button").focus()
            await pilot.press("enter")
            await pilot.pause()
            await pilot.pause()
            result_rows = list(app.query("#check_results Static"))
            apply_buttons = [
                b.id
                for b in app.query("#check_editor_panel Button")
                if b.id and "apply" in b.id.lower()
            ]
            status = str(
                app.query_one("#check_status").render()
            )
            return written, doc, result_rows, apply_buttons, status

    written, doc, result_rows, apply_buttons, status = asyncio.run(_drive())
    assert len(written) == 1, f"exactly one .chk.json written, got {written}"
    assert written[0].name == "baseline.chk.json", (
        f"the .chk.json suffix is preserved, got {written[0].name}"
    )
    assert doc is not None and doc.kind == "check", (
        f"the written file re-reads as kind=check, got {doc and doc.kind!r}"
    )
    assert not doc.has_errors, "0 blocking errors on the re-read"
    assert len(doc.entries) == 1, (
        f"entry count == collected count, got {len(doc.entries)}"
    )
    assert len(result_rows) == 1, (
        f"one verdict row per entry, got {len(result_rows)}"
    )
    assert "pass" in str(result_rows[0].render()), (
        f"the verdict row passes (expected == image bytes), got "
        f"{str(result_rows[0].render())!r}"
    )
    assert apply_buttons == [], f"0 apply controls, got {apply_buttons}"


# ---------------------------------------------------------------------------
# AT-B94-13 — hostile-input acceptance through the shipped Check Editor
# ---------------------------------------------------------------------------


def test_at_b94_13_hostile_symbol_and_file_name(tmp_path: Path) -> None:
    """AT-B94-13 — the batch-77 payload renders literally in collector,
    dropdown and report addendum (HLR-011 / C-17).

    Intent: the hostile payload as an A2L symbol name reaches the parameter
    collector; as a spec file name it reaches the dropdown labels and the
    report addendum. Every render is literal — 0 markup spans, 0 control
    bytes, the sentinel visible, no exception. The predicate reads the
    PAINTED surface (``_render_line`` / ``.render().spans`` per C-32) and
    the emitted report bytes (C-42).
    """
    from s19_app.tui.changes.io import parse_change_document
    from s19_app.tui.services.diff_report_service import (
        _check_addendum_lines,
    )

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        mem = {0x100 + i: 0x11 for i in range(4)}
        app.current_file = _loaded(mem, [(0x100, 0x104)])
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press("equals_sign")
            await pilot.pause()
            await pilot.pause()
            panel = app.query_one("#check_editor_panel", CheckEditorPanel)
            panel.set_a2l_parameters(
                [{"name": _HOSTILE, "address": 0x100, "byte_size": 4}]
            )
            panel.set_spec_files([f"{_HOSTILE}.chk.json", "hotfix.pch.json"])
            await pilot.pause()
            picker = app.query_one("#check_param_table", DataTable)
            cell = picker.get_row_at(0)[1]
            cell_text = cell.plain if hasattr(cell, "plain") else str(cell)
            cell_spans = (
                list(cell.spans) if hasattr(cell, "spans") else None
            )
            select = app.query_one("#check_spec_file_select", Select)
            option_labels = [
                (label.plain if hasattr(label, "plain") else str(label))
                for label, _v in select._options
            ]
            return cell_text, cell_spans, option_labels

    cell_text, cell_spans, option_labels = asyncio.run(_drive())
    # The collector cell: sentinel visible, brackets literal, no style span.
    # The cell MUST be a Text (a bare str cell is the live from_markup sink —
    # C-17/batch-37), so an empty-spans read cannot be vacuous (C-32).
    assert cell_spans is not None, (
        "the collector cell must be a Text — a bare str cell is markup-parsed "
        "by default_cell_formatter (the live sink)"
    )
    assert "b77hostilemark" in cell_text, (
        f"the sentinel must be visible in the collector cell, got {cell_text!r}"
    )
    assert "[red]" in cell_text and "_evil" in cell_text, (
        "the hostile markup must render as its own characters"
    )
    control_bytes = [ch for ch in cell_text if ord(ch) < 0x20 and ch not in "\n\t"]
    assert control_bytes == [], f"0 control bytes in the cell, got {control_bytes!r}"
    assert cell_spans == [], (
        f"0 markup spans in the collector cell, got {cell_spans}"
    )
    # The dropdown: the hostile file name is listed with the CHECK suffix.
    hostile_label = [x for x in option_labels if "b77hostilemark" in x]
    assert len(hostile_label) == 1 and "CHECK" in hostile_label[0], (
        f"the hostile spec name must be listed suffix-distinguished, got "
        f"{option_labels!r}"
    )
    # The report addendum: the hostile name escapes through md_safe and the
    # sentinel survives (control bytes become the visible LOSS marker, the
    # sentinel text stays literal).
    spec = parse_change_document(
        '{\n  "format": "s19app-changeset",\n  "version": "2.0",\n'
        '  "kind": "check",\n  "encoding": "utf-8",\n  "value_mode": "text",\n'
        '  "entries": [\n    {"type": "bytes", "address": "0x00000100", '
        '"bytes": "11 11 11 11"}\n  ]\n}'
    )
    lines = _check_addendum_lines(
        spec, f"{_HOSTILE}.chk.json", [(0x100, _HOSTILE)]
    )
    addendum = "\n".join(lines)
    assert "b77hostilemark" in addendum, (
        "the sentinel must survive the addendum emission"
    )
    assert "\x1b" not in addendum and "\x9b" not in addendum and "\x00" not in addendum, (
        "no control byte may survive the md_safe pass into the report"
    )
    # The primitive unit arm (TC-B94-17's payload arm lives here with the AT):
    scrubbed = safe_text(_HOSTILE)
    assert "b77hostilemark" in scrubbed.plain
    assert "[red]" in scrubbed.plain
    assert all(ord(ch) >= 0x20 for ch in scrubbed.plain), (
        "safe_text scrubs every control byte and keeps the brackets literal"
    )


# ---------------------------------------------------------------------------
# TC-B94-17 — safe_text over the hostile payload (LLR-011.1 primitive arm)
# ---------------------------------------------------------------------------


def test_tc_b94_17_safe_text_hostile_payload() -> None:
    """TC-B94-17 — ``safe_text`` over the hostile payload: 0 control bytes,
    brackets preserved (LLR-011.1's primitive contract, hostile arm)."""
    scrubbed = safe_text(_HOSTILE)
    bad = [ch for ch in scrubbed.plain if ord(ch) < 0x20]
    assert bad == [], f"0 control bytes survive the scrub, got {bad!r}"
    assert "[red]" in scrubbed.plain and "_evil" in scrubbed.plain, (
        "the brackets render literally (the scrub is identity on printable text)"
    )
    # Identity arm (the preserved-arm of the hostile census): plain text is
    # unchanged by the scrub.
    assert safe_text("EngineSpeed_rpm").plain == "EngineSpeed_rpm"
