"""Batch-103 Inc 6 E4: Patch editor prefill, Check specs and bulk selection.

The 33 parametrized nodes are R-PICKER-CORRECT.006 through .016, .020 and .021 from
``inc-6/02-test-cases.md``. Expected bytes, statuses, summaries and spec shapes
are pinned from that ledger. Real A2L/S19 files load through ``S19TuiApp``;
Textual Pilot drives editor tabs, keys and buttons. The only stand-in is the
ledger-authorized full-coverage READ spy at the 1 MiB boundary.
"""
from __future__ import annotations

import asyncio
import copy
import sys
from collections.abc import Mapping
from pathlib import Path

sys.path.insert(0, ".")
import s19_app

print(f"S19_APP_UNDER_TEST={s19_app.__file__}", flush=True)

import pytest
from rich.text import Text
from textual.widgets import Button, DataTable, Input, Label, Static, TextArea

from s19_app.tui.a2l import MAX_A2L_DECODE_BYTES
from s19_app.tui.a2l_definition import describe_definition
from s19_app.tui.a2l_parse import parse_a2l_file
from s19_app.tui.a2l_parameter_picker import A2LParameterPicker
from s19_app.tui.app import S19TuiApp
from tests.b97_probes import is_displayed
from tests.support.b100_workers import settle_workers
from tests.support.b103_a2l_arrays import (
    BASE_LAYOUTS,
    axis,
    characteristic,
    mapchar,
    meas,
    rl,
    valblk,
)
from tests.support.timing import wait_until

SIZE = (118, 54)
NO_BYTES = "Parameter address loaded; image bytes unavailable."
INSTRUCTION = "Separate names with new lines, commas, semicolons or spaces."

ARR12_TEXT = "00 01 02 03 04 05 06 07 08 09 0A 0B"
VB4_TEXT = "10 11 12 13"
TXT5_TEXT = "41 42 43 44 45"
MAP10_TEXT = "20 21 22 23 24 25 26 27 28 29"
ARR12_BYTES = bytes.fromhex(ARR12_TEXT)
VB4_BYTES = bytes.fromhex(VB4_TEXT)
TXT5_BYTES = bytes.fromhex(TXT5_TEXT)
MAP10_BYTES = bytes.fromhex(MAP10_TEXT)
FULL_IMAGE = {
    **{0x1000 + i: b for i, b in enumerate(ARR12_BYTES)},
    **{0x2000 + i: b for i, b in enumerate(VB4_BYTES)},
    **{0x3000 + i: b for i, b in enumerate(MAP10_BYTES)},
    **{0x4000 + i: b for i, b in enumerate(TXT5_BYTES)},
}
EXPECTED_SIZES = {"ARR12": 12, "VB4": 4, "MAP10": 10, "TXT5": 5}
REFUSED_ADDRESSES = {
    "R1": 0x5000,
    "R2": 0x5004,
    "R3": 0x5008,
    "R4": 0x500C,
    "R5": 0x5010,
}


def _editor_blocks(arr_length: int = 12) -> list[str]:
    matrix = "MATRIX_DIM 2 3" if arr_length == 12 else "MATRIX_DIM 2 2"
    return [
        meas("ARR12", "UWORD", addr="0x1000", extras=(matrix,)),
        valblk("VB4", "0x2000", "RL_U8", extras=("NUMBER 4",)),
        rl("RL_MAP10", "FNC_VALUES 1 UBYTE ROW_DIR DIRECT"),
        mapchar(
            "MAP10",
            "0x3000",
            "RL_MAP10",
            axis("FIX_AXIS", "CM_IDENT", "2", "0", "255", "FIX_AXIS_PAR_DIST 0 1 2"),
            axis("FIX_AXIS", "CM_IDENT", "5", "0", "255", "FIX_AXIS_PAR_DIST 0 1 5"),
        ),
        characteristic(
            "TXT5", "ASCII", "0x4000", "RL_U8", "NO_COMPU_METHOD", "0", "255",
            extras=("NUMBER 5",),
        ),
        characteristic(
            "R1", "VALUE", "0x5000", "RL_U16", "NO_COMPU_METHOD", "0", "65535",
            extras=("LENGTH 4",),
        ),
        valblk("R2", "0x5004", "RL_U16", extras=("MATRIX_DIM 4", "NUMBER 5")),
        characteristic(
            "R3", "VALUE", "0x5008", "RL_U16", "NO_COMPU_METHOD", "0", "65535",
            extras=("LENGTH 0",),
        ),
        valblk("R4", "0x500C", "RL_U8", extras=("MATRIX_DIM 4 x",)),
        meas("R5", "UWORD", addr="0x5010", extras=("LENGTH 99999999999",)),
    ]


def _write_a2l(path: Path, blocks: list[str]) -> Path:
    lines = [
        "ASAP2_VERSION 1 71",
        '/begin PROJECT P ""',
        '  /begin MODULE M ""',
        '    /begin MOD_COMMON ""',
        "      BYTE_ORDER MSB_FIRST",
        "    /end MOD_COMMON",
    ]
    for layout, datatype in BASE_LAYOUTS:
        lines += [
            f"    /begin RECORD_LAYOUT {layout}",
            f"      FNC_VALUES 1 {datatype} ROW_DIR DIRECT",
            "    /end RECORD_LAYOUT",
        ]
    lines += [
        '    /begin COMPU_METHOD CM_IDENT "" IDENTICAL "%.3" ""',
        "    /end COMPU_METHOD",
        *blocks,
        "  /end MODULE",
        "/end PROJECT",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def _write_editor_a2l(tmp_path: Path, *, arr_length: int = 12, name: str = "editor.a2l") -> Path:
    path = _write_a2l(tmp_path / name, _editor_blocks(arr_length))
    data = parse_a2l_file(path)
    tags = {tag["name"]: tag for tag in data["tags"]}
    expected = dict(EXPECTED_SIZES, ARR12=arr_length)
    for parameter, length in expected.items():
        assert tags[parameter]["length"] == length, (parameter, tags[parameter])
        definition = describe_definition(parameter, data)
        assert definition.refusal is None, (parameter, definition.refusal)
        assert definition.byte_length == length, (parameter, definition.byte_length)
    for parameter, address in REFUSED_ADDRESSES.items():
        assert tags[parameter]["address"] == address, (parameter, tags[parameter])
        assert tags[parameter]["length"] is None, (parameter, tags[parameter])
    return path


def _write_names_a2l(tmp_path: Path, names: list[str], name: str = "names.a2l") -> Path:
    blocks = [
        characteristic(
            parameter, "VALUE", f"0x{0x6000 + 2 * i:04X}", "RL_U16",
            "NO_COMPU_METHOD", "0", "65535",
        )
        for i, parameter in enumerate(names)
    ]
    return _write_a2l(tmp_path / name, blocks)


def _s2_record(address: int, data: list[int]) -> str:
    payload = [3 + len(data) + 1, *address.to_bytes(3, "big"), *data]
    checksum = (~sum(payload)) & 0xFF
    return "S2" + "".join(f"{byte:02X}" for byte in (*payload, checksum))


def _write_s19(path: Path, mem: dict[int, int]) -> Path:
    lines = ["S0030000FC"]
    start = None
    chunk: list[int] = []
    for address in sorted(mem):
        if start is None or address != start + len(chunk):
            if start is not None:
                lines.append(_s2_record(start, chunk))
            start, chunk = address, []
        chunk.append(mem[address])
    if start is not None:
        lines.append(_s2_record(start, chunk))
    lines.append("S804000000FB")
    path.write_text("\n".join(lines) + "\n", encoding="ascii")
    return path


def _run(
    tmp_path: Path,
    body,
    *,
    a2l: Path | None,
    image: dict[int, int] | None = None,
    size: tuple[int, int] = SIZE,
    screen: str = "patch",
):
    async def drive():
        app = S19TuiApp(base_dir=tmp_path / "app")
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            if a2l is not None:
                app.load_a2l_from_path(a2l, copy=False)
                await settle_workers(pilot)
                assert app.current_a2l_path == a2l, list(app.log_lines)[-5:]
            if image is not None:
                image_path = _write_s19(tmp_path / "image.s19", image)
                app.load_from_path(image_path)
                await settle_workers(pilot)
                assert app.current_file is not None, list(app.log_lines)[-5:]
                assert app.current_file.mem_map == image
            app.action_show_screen(screen)
            await pilot.pause()
            await pilot.pause()
            panel_id = "#patch_editor_panel" if screen == "patch" else "#check_editor_panel"
            panel = app.query_one(panel_id)
            if a2l is not None and a2l.name.startswith("editor"):
                enriched = {row["name"]: row for row in app._compute_a2l_enriched_tags()}
                if "ARR12" in enriched:
                    assert enriched["ARR12"]["length"] in (8, 12)
                    assert enriched["VB4"]["byte_size"] == 1
                    for parameter in REFUSED_ADDRESSES:
                        assert enriched[parameter]["byte_size"] is None, enriched[parameter]
                    rows = copy.deepcopy(list(enriched.values()))
                    next(row for row in rows if row["name"] == "ARR12")["byte_size"] = 2
                    signature = ("e4-ledger-decode-units", app._a2l_enriched_key)
                    for editor in (
                        app.query_one("#check_editor_panel"),
                        app.query_one("#patch_editor_panel"),
                    ):
                        editor.set_a2l_parameters(rows, signature)
                    await pilot.pause()
            return await body(app, pilot, panel)

    return asyncio.run(drive())


def _need(root, selector: str, kind=None):
    found = list(root.query(selector))
    assert len(found) == 1, f"{selector}: expected one widget, found {len(found)}"
    widget = found[0]
    if kind is not None:
        assert isinstance(widget, kind), (selector, type(widget).__name__)
    return widget


def _picker(panel, prefix: str = "patch_param") -> A2LParameterPicker:
    return panel._a2l_picker if prefix == "patch_param" else panel._picker


async def _show_patch_a2l(panel, pilot) -> None:
    _need(panel, "#patch_tab_a2l", Button).press()
    await pilot.pause()
    await pilot.pause()


async def _filter_to(panel, pilot, name: str, prefix: str = "patch_param") -> None:
    picker = _picker(panel, prefix)
    _need(panel, f"#{prefix}_filter", Input).value = name
    await wait_until(
        pilot,
        lambda: picker.visible_params == [name],
        lambda: f"filter {name!r}: visible={picker.visible_params!r}",
    )
    table = _need(panel, f"#{prefix}_table", DataTable)
    table.focus()
    table.move_cursor(row=0)
    await pilot.pause()


def _plain(value) -> str:
    return value.plain if isinstance(value, Text) else str(value)


def _entry(panel) -> tuple[str, str]:
    return (
        _need(panel, "#patch_entry_address_input", Input).value,
        _need(panel, "#patch_entry_bytes_input", Input).value,
    )


def _use_status(panel) -> str:
    return _plain(_need(panel, "#patch_param_use_status", Static).render())


def _arm_doc(app, panel) -> tuple:
    service = app._change_service
    service.add_entry("0x00F0", "", "AA")
    service.add_entry("0x00F1", "", "BB")
    service.undo()
    panel.mark_pasted()
    snapshot = (
        copy.deepcopy(service.document),
        panel.is_dirty,
        copy.deepcopy(service._undo_stack),
        copy.deepcopy(service._redo_stack),
    )
    assert snapshot[1] is True
    assert snapshot[2] or snapshot[3], "DOC fixture must have non-empty history"
    return snapshot


def _assert_doc_unchanged(app, panel, before: tuple) -> None:
    service = app._change_service
    after = (
        copy.deepcopy(service.document),
        panel.is_dirty,
        copy.deepcopy(service._undo_stack),
        copy.deepcopy(service._redo_stack),
    )
    assert after == before


async def _use(panel, pilot, name: str) -> None:
    await _filter_to(panel, pilot, name)
    _need(panel, "#patch_param_use_button", Button).press()
    await pilot.pause()
    await pilot.pause()


async def _pick(panel, pilot, name: str) -> None:
    await _filter_to(panel, pilot, name)
    _need(panel, "#patch_param_include_button", Button).press()
    await pilot.pause()


async def _open_bulk(app, pilot, panel):
    _need(panel, "#patch_param_bulk_button", Button).press()
    await wait_until(
        pilot,
        lambda: type(app.screen).__name__ == "BulkParameterAddScreen"
        and len(app.screen.query("#bulk_param_text")) == 1,
        "Patch Add list did not open the shared bulk modal",
    )
    modal = app.screen
    assert sum(type(s).__name__ == "BulkParameterAddScreen" for s in app.screen_stack) == 1
    assert modal._picker is panel._a2l_picker, "bulk modal must bind the Patch picker"
    return modal


async def _close_bulk(app, pilot, modal, *, escape: bool = False) -> None:
    if escape:
        await pilot.press("escape")
    else:
        _need(modal, "#bulk_param_close_button", Button).press()
    await wait_until(
        pilot,
        lambda: type(app.screen).__name__ != "BulkParameterAddScreen",
        "bulk modal did not close",
    )


async def _include_text(modal, pilot, text: str) -> str:
    _need(modal, "#bulk_param_text", TextArea).text = text
    _need(modal, "#bulk_param_include_button", Button).press()
    await pilot.pause()
    await pilot.pause()
    return _plain(_need(modal, "#bulk_param_summary", Static).render())


def _spy_rebuilds(monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    count = {"n": 0}
    original = A2LParameterPicker._rebuild_ledger

    def counting(self):
        count["n"] += 1
        return original(self)

    monkeypatch.setattr(A2LParameterPicker, "_rebuild_ledger", counting)
    return count


def _spy_selections(monkeypatch: pytest.MonkeyPatch, picker: A2LParameterPicker) -> list[tuple[str, ...]]:
    events: list[tuple[str, ...]] = []
    original = picker.post_message

    def recording(message) -> bool:
        if isinstance(message, A2LParameterPicker.SelectionChanged):
            events.append(tuple(message.names))
        return original(message)

    monkeypatch.setattr(picker, "post_message", recording)
    return events


@pytest.mark.parametrize(
    "case,parameter,address,expected",
    [
        ("R-PICKER-CORRECT.006/1", "VB4", "0x00002000", VB4_TEXT),
        ("R-PICKER-CORRECT.006/2", "ARR12", "0x00001000", ARR12_TEXT),
        ("R-PICKER-CORRECT.006/3", "TXT5", "0x00004000", TXT5_TEXT),
    ],
    ids=lambda value: value if value.startswith("R-") else "",
)
def test_r006_use_transfers_whole_object(tmp_path: Path, case: str, parameter: str, address: str, expected: str) -> None:
    """R-PICKER-CORRECT.006/1, R-PICKER-CORRECT.006/2 and
    R-PICKER-CORRECT.006/3: Use transfers all pinned non-uniform bytes and no document write."""
    a2l = _write_editor_a2l(tmp_path)

    async def body(app, pilot, panel):
        await _show_patch_a2l(panel, pilot)
        before = _arm_doc(app, panel)
        await _use(panel, pilot, parameter)
        assert _entry(panel) == (address, expected)
        assert _use_status(panel) == ""
        _assert_doc_unchanged(app, panel, before)

    _run(tmp_path, body, a2l=a2l, image=FULL_IMAGE)


@pytest.mark.parametrize("case", ["R-PICKER-CORRECT.007/1", "R-PICKER-CORRECT.007/2"], ids=lambda value: value)
def test_r007_unavailable_bytes_are_all_or_nothing(tmp_path: Path, case: str) -> None:
    """R-PICKER-CORRECT.007/1 and R-PICKER-CORRECT.007/2: no image and a missing
    middle byte both clear Bytes, paint the exact status and preserve DOC."""
    image = None if case.endswith("/1") else {a: b for a, b in FULL_IMAGE.items() if a != 0x1005}
    a2l = _write_editor_a2l(tmp_path)

    async def body(app, pilot, panel):
        await _show_patch_a2l(panel, pilot)
        before = _arm_doc(app, panel)
        _need(panel, "#patch_entry_bytes_input", Input).value = "FE ED"
        await _use(panel, pilot, "ARR12")
        assert _entry(panel) == ("0x00001000", "")
        assert _use_status(panel) == NO_BYTES
        _assert_doc_unchanged(app, panel, before)

    _run(tmp_path, body, a2l=a2l, image=image)


class _CoverageReadSpy(Mapping):
    def __init__(self, base: int):
        self.base = base
        self.reads: list[int] = []

    def get(self, address, default=None):
        self.reads.append(address)
        return (address - self.base) & 0xFF

    def __getitem__(self, address: int) -> int:
        return (address - self.base) & 0xFF

    def __iter__(self):
        return iter(())

    def __len__(self) -> int:
        return MAX_A2L_DECODE_BYTES + 1


@pytest.mark.parametrize("case", ["R-PICKER-CORRECT.008/1", "R-PICKER-CORRECT.008/2"], ids=lambda value: value)
def test_r008_declared_length_observes_decode_cap(tmp_path: Path, case: str) -> None:
    """R-PICKER-CORRECT.008/1 refuses cap+1 before any READ with the exact
    over-cap line; R-PICKER-CORRECT.008/2 reads exactly cap ascending bytes."""
    cap = MAX_A2L_DECODE_BYTES
    length = cap + 1 if case.endswith("/1") else cap

    async def body(app, pilot, panel):
        await _show_patch_a2l(panel, pilot)
        before = _arm_doc(app, panel)
        panel.set_a2l_parameters(
            [{"name": "CAP", "address": 0x1000, "length": length, "byte_size": 2, "datatype": "UBYTE"}],
            ("cap", length),
        )
        coverage = _CoverageReadSpy(0x1000)
        panel._mem_map = coverage
        await _use(panel, pilot, "CAP")
        if case.endswith("/1"):
            assert coverage.reads == []
            assert _entry(panel) == ("0x00001000", "")
            assert _use_status(panel) == (
                f"Parameter size {cap + 1} bytes over the {cap}-byte decode cap — Bytes not prefilled."
            )
        else:
            assert len(coverage.reads) == cap
            assert coverage.reads == list(range(0x1000, 0x1000 + cap))
            bytes_value = _entry(panel)[1]
            assert len(bytes_value.split(" ")) == cap
            assert bytes_value == " ".join(f"{offset & 0xFF:02X}" for offset in range(cap))
            assert _use_status(panel) == ""
        _assert_doc_unchanged(app, panel, before)

    _run(tmp_path, body, a2l=None)


@pytest.mark.parametrize("case", ["R-PICKER-CORRECT.009/1", "R-PICKER-CORRECT.009/2", "R-PICKER-CORRECT.009/3"], ids=lambda value: value)
def test_r009_check_spec_matches_address_and_full_length(tmp_path: Path, case: str) -> None:
    """R-PICKER-CORRECT.009/1, R-PICKER-CORRECT.009/2 and
    R-PICKER-CORRECT.009/3 pin scalar naming, full-array naming and element-size demotion."""
    if case.endswith("/1"):
        a2l = _write_a2l(
            tmp_path / "editor-scalar.a2l",
            [characteristic("Scalar2", "VALUE", "0x1000", "RL_U16", "NO_COMPU_METHOD", "0", "65535")],
        )
        parameter, size, expected = "Scalar2", 2, (0xA5, 0x5A)
    else:
        a2l = _write_editor_a2l(tmp_path)
        parameter = "ARR12"
        size = 12 if case.endswith("/2") else 2
        expected = ARR12_BYTES if size == 12 else ARR12_BYTES[:2]

    async def body(app, pilot, panel):
        panel.load_spec(
            [{"address": 0x1000, "size": size, "expected": tuple(expected), "symbol": parameter}],
            "pinned.chk.json",
        )
        await pilot.pause()
        if case.endswith("/3"):
            assert panel._picker.picked_params == []
            assert panel._spec_bytes == {}
            assert panel._memory_rows == [(0x1000, "field @ 0x00001000", 2, (0x00, 0x01))]
        else:
            assert panel._picker.picked_params == [parameter]
            assert panel._spec_bytes == {parameter: (0x1000, size, tuple(expected))}
            assert panel._memory_rows == []
        memory = _need(panel, "#check_mem_table", DataTable)
        assert memory.row_count == (1 if case.endswith("/3") else 0)

    _run(tmp_path, body, a2l=a2l, screen="check_editor")


@pytest.mark.parametrize("case", ["R-PICKER-CORRECT.010/1", "R-PICKER-CORRECT.010/2"], ids=lambda value: value)
def test_r010_new_generation_keeps_or_demotes_full_spec(tmp_path: Path, case: str) -> None:
    """R-PICKER-CORRECT.010/1 keeps a 12-byte spec across a 12→12 reload;
    R-PICKER-CORRECT.010/2 demotes 12→8 while preserving original spec bytes."""
    old_a2l = _write_editor_a2l(tmp_path, name="editor-old.a2l")
    new_length = 12 if case.endswith("/1") else 8
    new_a2l = _write_editor_a2l(tmp_path, arr_length=new_length, name="editor-new.a2l")

    async def body(app, pilot, panel):
        panel.load_spec(
            [{"address": 0x1000, "size": 12, "expected": tuple(ARR12_BYTES), "symbol": "ARR12"}],
            "pinned.chk.json",
        )
        assert panel._picker.picked_params == ["ARR12"]
        app.load_a2l_from_path(new_a2l, copy=False)
        await settle_workers(pilot)
        assert app.current_a2l_path == new_a2l
        if case.endswith("/1"):
            assert panel._picker.picked_params == ["ARR12"]
            assert panel._spec_bytes == {"ARR12": (0x1000, 12, tuple(ARR12_BYTES))}
            assert panel._memory_rows == []
        else:
            assert panel._picker.picked_params == []
            assert panel._spec_bytes == {}
            assert panel._memory_rows == [(0x1000, "field @ 0x00001000", 12, tuple(ARR12_BYTES))]
        memory = _need(panel, "#check_mem_table", DataTable)
        assert memory.row_count == (0 if case.endswith("/1") else 1)

    _run(tmp_path, body, a2l=old_a2l, screen="check_editor")


@pytest.mark.parametrize("case", ["R-PICKER-CORRECT.011/1", "R-PICKER-CORRECT.011/2", "R-PICKER-CORRECT.011/3"], ids=lambda value: value)
def test_r011_patch_pick_controls_and_id_isolation(tmp_path: Path, case: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """R-PICKER-CORRECT.011/1 toggles with space/enter and SelectionChanged;
    R-PICKER-CORRECT.011/2 pins Add list; R-PICKER-CORRECT.011/3 pins unique ids and independent editors."""
    a2l = _write_editor_a2l(tmp_path)

    async def body(app, pilot, panel):
        await _show_patch_a2l(panel, pilot)
        before = _arm_doc(app, panel)
        picker = panel._a2l_picker
        if case.endswith("/2"):
            button = _need(picker, "#patch_param_bulk_button", Button)
            assert str(button.label) == "Add list"
            assert not button.disabled
            assert button.region.width > 0 and button.region.height > 0
            return
        events = _spy_selections(monkeypatch, picker)
        if case.endswith("/1"):
            include = _need(panel, "#patch_param_include_button", Button)
            assert is_displayed(include) and not include.disabled
            assert include.region.width > 0 and include.region.height > 0
            await _filter_to(panel, pilot, "ARR12")
            table = _need(panel, "#patch_param_table", DataTable)
            await pilot.press("space")
            await pilot.pause()
            assert picker.picked_params == ["ARR12"]
            await pilot.press("enter")
            await pilot.pause()
            assert picker.picked_params == []
            assert events == [("ARR12",), ()]
            _assert_doc_unchanged(app, panel, before)
            return
        check = app.query_one("#check_editor_panel")
        check_events = _spy_selections(monkeypatch, check._picker)
        await _filter_to(panel, pilot, "ARR12")
        patch_table = _need(panel, "#patch_param_table", DataTable)
        patch_table.focus()
        await pilot.press("space")
        app.action_show_screen("check_editor")
        await pilot.pause()
        await _filter_to(check, pilot, "VB4", "check_param")
        check_table = _need(check, "#check_param_table", DataTable)
        check_table.focus()
        await pilot.press("enter")
        await pilot.pause()
        ids = [
            widget.id for widget in app.query("*")
            if widget.id and widget.id.startswith(("patch_param_", "check_param_", "check_full_name_line"))
        ]
        assert len(ids) == len(set(ids)), sorted(ids)
        assert picker.picked_params == ["ARR12"]
        assert check._picker.picked_params == ["VB4"]
        assert events == [("ARR12",)]
        assert check_events == [("VB4",)]
        _assert_doc_unchanged(app, panel, before)

    _run(tmp_path, body, a2l=a2l)


@pytest.mark.parametrize("case", ["R-PICKER-CORRECT.012/1", "R-PICKER-CORRECT.012/2"], ids=lambda value: value)
def test_r012_patch_add_list_opens_shared_modal(tmp_path: Path, case: str) -> None:
    """R-PICKER-CORRECT.012/1 opens with no picks; R-PICKER-CORRECT.012/2
    preserves Alpha and pins focus, exact instruction, actions and Patch binding."""
    a2l = _write_names_a2l(tmp_path, ["Alpha", "Beta"])

    async def body(app, pilot, panel):
        await _show_patch_a2l(panel, pilot)
        if case.endswith("/2"):
            await _pick(panel, pilot, "Alpha")
        modal = await _open_bulk(app, pilot, panel)
        area = _need(modal, "#bulk_param_text", TextArea)
        await wait_until(pilot, lambda: app.focused is area, "bulk text area did not receive focus")
        assert _plain(_need(modal, "#bulk_param_instruction", Label).render()) == INSTRUCTION
        assert str(_need(modal, "#bulk_param_include_button", Button).label) == "Include matches"
        assert str(_need(modal, "#bulk_param_close_button", Button).label) == "Close"
        assert panel._a2l_picker.picked_params == (["Alpha"] if case.endswith("/2") else [])
        await _close_bulk(app, pilot, modal)

    _run(tmp_path, body, a2l=a2l)


_BULK_CASES = {
    "R-PICKER-CORRECT.013/1": (["Alpha", "Beta"], True, "Beta, Missing; Alpha", ["Alpha", "Beta"], "Included 1 · already included 1 · not found 1 — first missing: Missing"),
    "R-PICKER-CORRECT.013/2": (["Beta"], False, "Beta Beta", ["Beta"], "Included 1 · already included 0 · not found 0"),
    "R-PICKER-CORRECT.013/3": (["Alpha"], True, "Alpha Alpha", ["Alpha"], "Included 0 · already included 1 · not found 0"),
    "R-PICKER-CORRECT.013/4": (["Alpha"], False, "alpha", [], "Included 0 · already included 0 · not found 1 — first missing: alpha"),
    "R-PICKER-CORRECT.014/1": (["Alpha", "Beta"], True, "Beta,Alpha,Gamma", ["Alpha", "Beta"], "Included 1 · already included 1 · not found 1 — first missing: Gamma"),
    "R-PICKER-CORRECT.014/2": (["Alpha", "Beta"], True, "  \n,; \t", ["Alpha"], "No listed parameters found."),
    "R-PICKER-CORRECT.014/3": (["Alpha", "Beta"], False, "Gamma Delta", [], "Included 0 · already included 0 · not found 2 — first missing: Gamma"),
}


@pytest.mark.parametrize("case", list(_BULK_CASES), ids=lambda value: value)
def test_r013_r014_patch_bulk_counts_and_exact_summaries(tmp_path: Path, case: str) -> None:
    """R-PICKER-CORRECT.013/1, R-PICKER-CORRECT.013/2, R-PICKER-CORRECT.013/3,
    R-PICKER-CORRECT.013/4, R-PICKER-CORRECT.014/1, R-PICKER-CORRECT.014/2 and
    R-PICKER-CORRECT.014/3 pin exact picks, unique counts and every summary alternative."""
    names, preseed, payload, expected_picks, expected_summary = _BULK_CASES[case]
    a2l = _write_names_a2l(tmp_path, names)

    async def body(app, pilot, panel):
        await _show_patch_a2l(panel, pilot)
        before = _arm_doc(app, panel)
        if preseed:
            await _pick(panel, pilot, "Alpha")
        modal = await _open_bulk(app, pilot, panel)
        summary = await _include_text(modal, pilot, payload)
        assert summary == expected_summary
        assert panel._a2l_picker.picked_params == expected_picks
        _assert_doc_unchanged(app, panel, before)
        await _close_bulk(app, pilot, modal)

    _run(tmp_path, body, a2l=a2l)


@pytest.mark.parametrize("case", ["R-PICKER-CORRECT.015/1", "R-PICKER-CORRECT.015/2", "R-PICKER-CORRECT.015/3"], ids=lambda value: value)
def test_r015_patch_bulk_close_preserves_ledger_and_document(tmp_path: Path, case: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """R-PICKER-CORRECT.015/1 includes and closes; R-PICKER-CORRECT.015/2
    cancels; R-PICKER-CORRECT.015/3 escapes. All preserve page/filter/DOC and REBUILD=0."""
    names = [f"A{i:03d}" for i in range(200)] + ["Alpha", "Beta", "Gamma"]
    a2l = _write_names_a2l(tmp_path, names, "editor-bulk.a2l")
    rebuilds = _spy_rebuilds(monkeypatch)

    async def body(app, pilot, panel):
        await _show_patch_a2l(panel, pilot)
        picker = panel._a2l_picker
        _need(panel, "#patch_param_filter", Input).value = "A"
        await wait_until(pilot, lambda: len(picker.visible_params) == 200, "page-one filter did not settle")
        _need(panel, "#patch_param_page_next_button", Button).press()
        await wait_until(
            pilot,
            lambda: picker.page == 2 and picker.visible_params == ["Alpha", "Beta", "Gamma"],
            "page two did not mount Alpha/Beta/Gamma",
        )
        if not case.endswith("/1"):
            await _pick(panel, pilot, "Alpha")
            _need(panel, "#patch_param_filter", Input).value = "A"
            await wait_until(pilot, lambda: len(picker.visible_params) == 200, "page-one filter did not restore")
            _need(panel, "#patch_param_page_next_button", Button).press()
            await wait_until(
                pilot,
                lambda: picker.page == 2 and picker.visible_params == ["Alpha", "Beta", "Gamma"],
                "page two did not restore after the preseed pick",
            )
        before_doc = _arm_doc(app, panel)
        before_ledger = (
            _need(panel, "#patch_param_filter", Input).value,
            picker.page,
            list(picker.visible_params),
        )
        rebuilds["n"] = 0
        modal = await _open_bulk(app, pilot, panel)
        _need(modal, "#bulk_param_text", TextArea).text = "Beta"
        if case.endswith("/1"):
            _need(modal, "#bulk_param_include_button", Button).press()
            await pilot.pause()
        await _close_bulk(app, pilot, modal, escape=case.endswith("/3"))
        expected_picks = ["Beta"] if case.endswith("/1") else ["Alpha"]
        assert picker.picked_params == expected_picks
        after_ledger = (
            _need(panel, "#patch_param_filter", Input).value,
            picker.page,
            list(picker.visible_params),
        )
        assert after_ledger == before_ledger
        assert rebuilds["n"] == 0
        row = picker.visible_params.index("Beta")
        mark = _plain(_need(panel, "#patch_param_table", DataTable).get_row_at(row)[0])
        assert mark == ("✓" if case.endswith("/1") else " ")
        _assert_doc_unchanged(app, panel, before_doc)

    _run(tmp_path, body, a2l=a2l)


@pytest.mark.parametrize("case", ["R-PICKER-CORRECT.016/1", "R-PICKER-CORRECT.016/2"], ids=lambda value: value)
def test_r016_use_after_bulk_transfers_only_highlight(tmp_path: Path, case: str) -> None:
    """R-PICKER-CORRECT.016/1 transfers highlighted ARR12 only;
    R-PICKER-CORRECT.016/2 transfers highlighted VB4 only; both picks and DOC remain."""
    a2l = _write_editor_a2l(tmp_path)
    parameter = "ARR12" if case.endswith("/1") else "VB4"
    address = "0x00001000" if case.endswith("/1") else "0x00002000"
    expected = ARR12_TEXT if case.endswith("/1") else VB4_TEXT

    async def body(app, pilot, panel):
        await _show_patch_a2l(panel, pilot)
        before = _arm_doc(app, panel)
        modal = await _open_bulk(app, pilot, panel)
        await _include_text(modal, pilot, "ARR12 VB4")
        await _close_bulk(app, pilot, modal)
        await _use(panel, pilot, parameter)
        assert _entry(panel) == (address, expected)
        assert panel._a2l_picker.picked_params == ["ARR12", "VB4"]
        _assert_doc_unchanged(app, panel, before)

    _run(tmp_path, body, a2l=a2l, image=FULL_IMAGE)


@pytest.mark.parametrize(
    "case,size",
    [("R-PICKER-CORRECT.020/1", (80, 24)), ("R-PICKER-CORRECT.020/2", (118, 54))],
    ids=lambda value: value if isinstance(value, str) and value.startswith("R-") else "",
)
def test_r020_patch_surfaces_fit_real_terminal_regions(tmp_path: Path, case: str, size: tuple[int, int]) -> None:
    """R-PICKER-CORRECT.020/1 measures and operates 80x24;
    R-PICKER-CORRECT.020/2 measures and operates 118x54, including every named region."""
    a2l = _write_editor_a2l(tmp_path)

    async def body(app, pilot, panel):
        await _show_patch_a2l(panel, pilot)
        await _pick(panel, pilot, "ARR12")
        assert panel._a2l_picker.picked_params == ["ARR12"]
        await _use(panel, pilot, "ARR12")
        assert _use_status(panel) == NO_BYTES
        panel.set_a2l_parameters(
            [{
                "name": "CAP",
                "address": 0x1000,
                "length": MAX_A2L_DECODE_BYTES + 1,
                "byte_size": MAX_A2L_DECODE_BYTES + 1,
                "datatype": "UWORD",
            }],
            ("r020-cap", 1),
        )
        panel._mem_map = _CoverageReadSpy(0x1000)
        await _use(panel, pilot, "CAP")
        over_cap = (
            f"Parameter size {MAX_A2L_DECODE_BYTES + 1} bytes over the "
            f"{MAX_A2L_DECODE_BYTES}-byte decode cap — Bytes not prefilled."
        )
        assert _use_status(panel) == over_cap
        assert _need(panel, "#patch_param_use_status").region.height >= 3
        selectors = [
            "#patch_param_filter", "#patch_param_table", "#patch_param_full_name_line",
            "#patch_param_status", "#patch_param_page_prev_button", "#patch_param_page_label",
            "#patch_param_page_next_button", "#patch_param_include_button", "#patch_param_bulk_button",
            "#patch_param_use_button", "#patch_param_use_status",
        ]
        assert _need(panel, "#patch_param_table", DataTable).show_header is True
        assert _need(panel, "#patch_param_use_status").region.y > _need(
            panel, "#patch_param_use_button", Button
        ).region.y
        widgets = [_need(panel, selector) for selector in selectors]
        for widget in widgets:
            region = widget.region
            assert is_displayed(widget), (size, widget.id, "not displayed")
            assert region.width > 0 and region.height > 0, (size, widget.id, region)
            assert panel.region.x <= region.x and region.right <= panel.region.right, (
                size, widget.id, region, panel.region,
            )
            assert panel.region.y <= region.y and region.bottom <= panel.region.bottom, (
                size, widget.id, region, panel.region,
            )
            assert 0 <= region.x and region.right <= size[0]
            assert 0 <= region.y and region.bottom <= size[1]
        modal = await _open_bulk(app, pilot, panel)
        await _close_bulk(app, pilot, modal)

    _run(tmp_path, body, a2l=a2l, size=size)


@pytest.mark.parametrize(
    "case,button_id",
    [
        ("R-PICKER-CORRECT.021/1", "check_validate_button"),
        ("R-PICKER-CORRECT.021/2", "check_write_button"),
    ],
    ids=lambda value: value,
)
def test_r021_check_validate_write_refuses_missing_length(
    tmp_path: Path, case: str, button_id: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R-PICKER-CORRECT.021/1 and .021/2: direct handler, substituted status label, zero action/read/write."""
    from s19_app.tui.changes import io as changes_io
    from s19_app.tui.models import LoadedFile
    from s19_app.tui.screens_directionb import CheckEditorPanel

    app = S19TuiApp(base_dir=tmp_path)
    coverage = _CoverageReadSpy(0x5000)
    object.__setattr__(
        app,
        "current_file",
        LoadedFile(
            path=tmp_path / "coverage.s19",
            file_type="s19",
            mem_map=coverage,
            row_bases=[],
            ranges=[],
            range_validity=[],
            errors=[],
            a2l_path=None,
            a2l_data=None,
        ),
    )
    panel = CheckEditorPanel()
    panel.set_a2l_parameters(
        [
            {"name": "R1", "address": 0x5000, "length": None, "byte_size": None, "datatype": "UWORD"},
            {"name": "ARR12", "address": 0x1000, "length": 12, "byte_size": 2, "datatype": "UWORD"},
        ],
        ("r021", 1),
    )
    assert panel._picker.include_names(["R1", "ARR12"])["included"] == 2
    before = panel._collected_items()
    actions = []
    reads = []
    writes = []
    monkeypatch.setattr(panel, "post_message", lambda message: actions.append(message) or None)
    monkeypatch.setattr(app, "_check_items_to_document", lambda items: reads.append(items) or None)
    monkeypatch.setattr(changes_io, "write_change_document", lambda *args, **kwargs: writes.append((args, kwargs)))
    status = Label()
    monkeypatch.setattr(panel, "query_one", lambda selector, kind=None: status)
    panel.on_button_pressed(Button.Pressed(Button(id=button_id)))
    after = panel._collected_items()
    assert actions == []
    assert reads == []
    assert writes == []
    assert coverage.reads == []
    assert before == after
    assert status.render().plain == "Check Editor: parameter has no length — validate/write refused."
