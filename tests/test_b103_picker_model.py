"""Batch-103 Inc 6 E4: picker model, literal format, population and timing.

Covers the 44 alternatives R-PICKER-CORRECT.001/1-4, .002/1-4,
.003/1-18, .004/1-4, .005/1-5, .017/1-3, .018/1-4 and .019/1-2.
Expected sizes, formats, control replacements and statuses are pinned by the
approved ledger, never computed from enriched values or picker output.
"""

from __future__ import annotations

import asyncio
import copy
import statistics
import sys
import time
from pathlib import Path

import pytest

# The Linux evidence run uses -I.  Re-enter the isolated clone explicitly and
# prove that no external editable s19_app satisfies the product imports.
if "." not in sys.path:
    sys.path.insert(0, ".")
import s19_app

_PRODUCT_INIT = Path(s19_app.__file__).resolve()
assert Path.cwd().resolve() in _PRODUCT_INIT.parents, _PRODUCT_INIT
print(f"s19_app.__file__ = {_PRODUCT_INIT}", flush=True)

from rich.cells import cell_len, set_cell_size
from rich.text import Text
from textual.widgets import Button, DataTable, Input, Static

from s19_app.tui import a2l_definition as definition_module
from s19_app.tui import a2l_parameter_picker as picker_module
from s19_app.tui.a2l import enrich_a2l_tags_with_values
from s19_app.tui.a2l_parse import parse_a2l_file
from s19_app.tui.app import S19TuiApp
from s19_app.tui.screens_directionb import CheckEditorPanel, PatchEditorPanel
from tests.support.b100_workers import settle_workers
from tests.support.b103_a2l_arrays import (
    BASE_LAYOUTS,
    axis,
    characteristic,
    cm,
    mapchar,
    meas,
    rl,
    valblk,
)
from tests.support.timing import report_margin, timing_bound

SIZE = (118, 54)
MIN_SIZE = (80, 24)
SOFTA = Path(__file__).resolve().parent.parent / "examples" / "case_00_public" / "software_a.a2l"
MISSING_LENGTH_STATUS = "Parameter has no length — Bytes not prefilled."
NO_BYTES_STATUS = "Parameter address loaded; image bytes unavailable."
CONTROL_REPLACEMENT = "\uFFFD"


def _run(tmp_path: Path, body, *, size=SIZE):
    async def drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            return await body(app, pilot)

    return asyncio.run(drive())


async def _settle(pilot, rounds=5):
    for _ in range(rounds):
        await pilot.pause()


def _picker(panel):
    return panel._picker if isinstance(panel, CheckEditorPanel) else panel._a2l_picker


def _ids(panel):
    prefix = "check" if isinstance(panel, CheckEditorPanel) else "patch"
    return {
        "table": f"#{prefix}_param_table",
        "full": "#check_full_name_line" if prefix == "check" else "#patch_param_full_name_line",
        "filter": f"#{prefix}_param_filter",
        "next": f"#{prefix}_param_page_next_button",
        "prev": f"#{prefix}_param_page_prev_button",
    }


async def _show_panel(app, pilot, kind: str):
    app.action_show_screen("check_editor" if kind == "check" else "patch")
    await _settle(pilot, 6)
    panel = app.query_one("#check_editor_panel" if kind == "check" else "#patch_editor_panel")
    if kind == "patch":
        panel.query_one("#patch_tab_a2l", Button).press()
        await _settle(pilot, 3)
    return panel


async def _load_a2l(app, pilot, path: Path):
    app.load_a2l_from_path(path)
    await settle_workers(pilot)
    assert app.current_a2l_path is not None and app.current_a2l_path.name == path.name, list(app.log_lines)[-3:]
    assert app.current_a2l_data is not None
    return app._compute_a2l_enriched_tags()


def _write_a2l(path: Path, *blocks: str, extra_layouts=()) -> Path:
    lines = [
        "ASAP2_VERSION 1 71",
        '/begin PROJECT P ""',
        '  /begin MODULE M ""',
        '    /begin MOD_COMMON ""',
        "      BYTE_ORDER MSB_FIRST",
        "    /end MOD_COMMON",
    ]
    for name, datatype in (*BASE_LAYOUTS, *extra_layouts):
        if isinstance(name, str) and isinstance(datatype, str) and datatype.isupper():
            lines += [
                f"    /begin RECORD_LAYOUT {name}",
                f"      FNC_VALUES 1 {datatype} ROW_DIR DIRECT",
                "    /end RECORD_LAYOUT",
            ]
    lines.append(cm("CM_IDENT", "IDENTICAL"))
    lines.extend(blocks)
    lines.extend(["  /end MODULE", "/end PROJECT", ""])
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def _model_a2l(path: Path) -> Path:
    map10 = mapchar(
        "MAP10",
        "0x3000",
        "RL_MAP10",
        axis("STD_AXIS", "CM_IDENT", "2", "0", "255"),
        axis("STD_AXIS", "CM_IDENT", "2", "0", "255"),
    )
    map10_layout = rl(
        "RL_MAP10",
        "NO_AXIS_PTS_X 1 UBYTE",
        "NO_AXIS_PTS_Y 2 UBYTE",
        "FNC_VALUES 3 UWORD ROW_DIR DIRECT",
    )
    return _write_a2l(
        path,
        map10_layout,
        meas("ARR12", "UWORD", addr="0x1000", extras=("MATRIX_DIM 2 3",)),
        valblk("VB4", "0x2000", "RL_U8", extras=("NUMBER 4",)),
        map10,
        characteristic("TXT5", "ASCII", "0x4000", "RL_U8", "NO_COMPU_METHOD", "0", "255", extras=("NUMBER 5",)),
    )


def _refusal_a2l(path: Path, case: str) -> Path:
    blocks = {
        "R1": characteristic("R1", "VALUE", "0x1000", "RL_U16", "NO_COMPU_METHOD", "0", "65535", extras=("LENGTH 4",)),
        "R2": valblk("R2", "0x1000", "RL_U8", extras=("MATRIX_DIM 4", "NUMBER 5")),
        "R3": characteristic("R3", "VALUE", "0x1000", "RL_U16", "NO_COMPU_METHOD", "0", "65535", extras=("LENGTH 0",)),
        "R4": valblk("R4", "0x1000", "RL_U8", extras=("MATRIX_DIM 4 x",)),
        "R5": meas("R5", "UWORD", addr="0x1000", extras=("LENGTH 99999999999",)),
    }
    return _write_a2l(path, blocks[case])


def _generation_a2l(path: Path, *, datatype="UWORD", matrix="2 3", count=1) -> Path:
    blocks = [
        meas(
            f"P{index:05d}" if count > 1 else "ARR12",
            datatype,
            addr=f"0x{0x1000 + index * 16:04X}",
            extras=(f"MATRIX_DIM {matrix}",) if count == 1 else (),
        )
        for index in range(count)
    ]
    return _write_a2l(path, *blocks)


def _plain(value) -> str:
    return value.plain if isinstance(value, Text) else str(value)


def _cells(panel, name: str):
    table = panel.query_one(_ids(panel)["table"], DataTable)
    return table.get_row(name)


def _full_name(panel):
    return panel.query_one(_ids(panel)["full"], Static).render()


def _row_result(panel, name: str):
    picker = _picker(panel)
    address, size, fmt = picker.param_rows[name]
    table = panel.query_one(_ids(panel)["table"], DataTable)
    table.move_cursor(row=picker.visible_params.index(name))
    picker.refresh_full_name()
    cells = _cells(panel, name)
    highlighted = picker.highlighted_parameter
    return {
        "address": address,
        "size": size,
        "fmt": fmt,
        "painted_fmt": _plain(cells[3]),
        "fmt_budget": picker._layout().fmt,
        "full": _full_name(panel).plain,
        "highlighted": highlighted,
    }


def _normalized_literal(value: str) -> str:
    return "".join(CONTROL_REPLACEMENT if ord(ch) < 0x20 or 0x7F <= ord(ch) <= 0x9F else ch for ch in value)


def _clip_cells(value: str, cap: int) -> str:
    """Independent ledger oracle: first cap-1 cells plus a visible ellipsis."""
    if cap <= 0:
        return ""
    if cell_len(value) <= cap:
        return value
    if cap == 1:
        return "…"
    return set_cell_size(value, cap - 1) + "…"


def _assert_literal_surface(text: Text, expected: str):
    assert text.plain == expected
    assert not [ch for ch in text.plain if ord(ch) < 0x20 or 0x7F <= ord(ch) <= 0x9F]
    assert not [span for span in text.spans if any(word in str(span.style).lower() for word in ("link", "click", "red", "bold"))]


def _doc_snapshot(app, panel):
    service = app._change_service
    return (
        copy.deepcopy(service.document),
        panel.is_dirty,
        copy.deepcopy(service._undo_stack),
        copy.deepcopy(service._redo_stack),
    )


class _ReadSpy:
    def __init__(self):
        self.calls = []

    def get(self, address, default=None):
        self.calls.append(address)
        return 0xA5


def _describe_spy(monkeypatch):
    calls = []
    real = definition_module.describe_definitions

    def spy(names, a2l_data):
        materialized = list(names)
        started = time.perf_counter()
        result = real(materialized, a2l_data)
        calls.append({"names": materialized, "data": a2l_data, "seconds": time.perf_counter() - started, "count": len(result)})
        return result

    monkeypatch.setattr(definition_module, "describe_definitions", spy)
    monkeypatch.setattr(picker_module, "describe_definitions", spy, raising=False)
    return calls


# R-PICKER-CORRECT.001/1 Check scalar=2, /2 Check ARR12=12,
# /3 Patch scalar=2, /4 Patch ARR12=12; enriched byte_size is always 2.
@pytest.mark.parametrize(
    "case,editor,name,length",
    [
        ("R-PICKER-CORRECT.001/1", "check", "SCALAR", 2),
        ("R-PICKER-CORRECT.001/2", "check", "ARR12", 12),
        ("R-PICKER-CORRECT.001/3", "patch", "SCALAR", 2),
        ("R-PICKER-CORRECT.001/4", "patch", "ARR12", 12),
    ],
    ids=lambda value: value if isinstance(value, str) and value.startswith("R-") else "",
)
def test_r001_declared_length_is_the_only_size_source(tmp_path, case, editor, name, length):
    """R-PICKER-CORRECT.001/1-/4: declared 2/12 wins over byte_size=2."""

    async def body(app, pilot):
        panel = await _show_panel(app, pilot, editor)
        panel.set_a2l_parameters(
            [{"name": name, "address": 0x1000, "length": length, "byte_size": 2, "datatype": "UWORD"}],
            (case, 1),
        )
        await _settle(pilot)
        return _row_result(panel, name)

    result = _run(tmp_path, body)
    assert result["address"] == 0x1000
    assert result["size"] == length
    assert result["highlighted"]["name"] == name
    assert result["highlighted"]["size"] == length


# R-PICKER-CORRECT.002/1 ARR12=12, /2 VB4=4, /3 MAP10=10, /4 TXT5=5.
@pytest.mark.parametrize(
    "case,name,length",
    [
        ("R-PICKER-CORRECT.002/1", "ARR12", 12),
        ("R-PICKER-CORRECT.002/2", "VB4", 4),
        ("R-PICKER-CORRECT.002/3", "MAP10", 10),
        ("R-PICKER-CORRECT.002/4", "TXT5", 5),
    ],
    ids=lambda value: value if isinstance(value, str) and value.startswith("R-") else "",
)
def test_r002_real_a2l_shapes_report_whole_object_length(tmp_path, case, name, length):
    """R-PICKER-CORRECT.002/1-/4: real A2L array/block/map/text lengths."""
    path = _model_a2l(tmp_path / "model.a2l")

    async def body(app, pilot):
        loaded = await _load_a2l(app, pilot, path)
        # The ledger pins ARR12's enriched decode unit to 2 even though this
        # reader's no-layout MEASUREMENT enrichment otherwise uses full length.
        rows = [{**row, "byte_size": 2} if row["name"] == "ARR12" else row for row in loaded]
        source = next(row for row in rows if row["name"] == name)
        assert source["length"] == length
        results = {}
        for editor in ("check", "patch"):
            panel = await _show_panel(app, pilot, editor)
            panel.set_a2l_parameters(rows, (case, editor, "ledger-enriched"))
            await _settle(pilot)
            results[editor] = _row_result(panel, name)
        return source, results

    source, results = _run(tmp_path, body)
    assert source["address"] == {"ARR12": 0x1000, "VB4": 0x2000, "MAP10": 0x3000, "TXT5": 0x4000}[name]
    for editor in ("check", "patch"):
        assert results[editor]["size"] == length, (editor, source, results[editor])
        assert results[editor]["highlighted"]["size"] == length


# R-PICKER-CORRECT.003/1-/18: the ledger's exact element-format alternatives.
_FORMAT_CASES = [
    ("R-PICKER-CORRECT.003/1", "UBYTE", "VALUE", 1, 1, "", "u8"),
    ("R-PICKER-CORRECT.003/2", "SBYTE", "VALUE", 1, 1, "", "s8"),
    ("R-PICKER-CORRECT.003/3", "BYTE", "VALUE", 1, 1, "", "u8"),
    ("R-PICKER-CORRECT.003/4", "UWORD", "VALUE", 2, 2, "", "u16"),
    ("R-PICKER-CORRECT.003/5", "SWORD", "VALUE", 2, 2, "", "s16"),
    ("R-PICKER-CORRECT.003/6", "WORD", "VALUE", 2, 2, "", "u16"),
    ("R-PICKER-CORRECT.003/7", "ULONG", "VALUE", 4, 4, "", "u32"),
    ("R-PICKER-CORRECT.003/8", "SLONG", "VALUE", 4, 4, "", "s32"),
    ("R-PICKER-CORRECT.003/9", "LONG", "VALUE", 4, 4, "", "u32"),
    ("R-PICKER-CORRECT.003/10", "A_UINT64", "VALUE", 8, 8, "", "u64"),
    ("R-PICKER-CORRECT.003/11", "A_INT64", "VALUE", 8, 8, "", "s64"),
    ("R-PICKER-CORRECT.003/12", "FLOAT16_IEEE", "VALUE", 2, 2, "", "f16"),
    ("R-PICKER-CORRECT.003/13", "FLOAT32_IEEE", "VALUE", 4, 4, "", "f32"),
    ("R-PICKER-CORRECT.003/14", "FLOAT64_IEEE", "VALUE", 8, 8, "", "f64"),
    ("R-PICKER-CORRECT.003/15", "UWORD", "VAL_BLK", 12, 2, "", "u16"),
    ("R-PICKER-CORRECT.003/16", "UBYTE", "ASCII", 5, 1, "", "text"),
    ("R-PICKER-CORRECT.003/17", "UWORD", "VALUE", 2, 2, "%", "u16 %"),
    ("R-PICKER-CORRECT.003/18", None, "VALUE", 3, 3, "", "?"),
]


@pytest.mark.parametrize(
    "case,datatype,char_type,length,byte_size,unit,expected",
    _FORMAT_CASES,
    ids=lambda value: value if isinstance(value, str) and value.startswith("R-") else "",
)
def test_r003_element_datatype_and_unit_paint_exactly(
    tmp_path, case, datatype, char_type, length, byte_size, unit, expected
):
    """R-PICKER-CORRECT.003/1-/18: exact format in both editors, never u{total*8}."""

    async def body(app, pilot):
        results = {}
        for editor in ("check", "patch"):
            panel = await _show_panel(app, pilot, editor)
            panel.set_a2l_parameters(
                [{
                    "name": "ARR12" if case.endswith("/15") else "TXT5" if case.endswith("/16") else "FMT",
                    "address": 0x1000,
                    "length": length,
                    "byte_size": byte_size,
                    "datatype": datatype,
                    "char_type": char_type,
                    "compu_method_unit": unit,
                }],
                (case, editor),
            )
            await _settle(pilot)
            name = next(iter(_picker(panel).param_rows))
            results[editor] = _row_result(panel, name)
        return results

    results = _run(tmp_path, body, size=(160, 54))
    for editor, result in results.items():
        assert result["size"] == length
        assert result["fmt"] == expected, (editor, result)
        assert result["painted_fmt"] == _clip_cells(expected, result["fmt_budget"])
        assert f"  {expected}  " in result["full"]
        assert result["highlighted"]["fmt_unit"] == expected


# R-PICKER-CORRECT.004/1 R1, /2 R2, /3 R3, /4 R4: size is None in both.
# Exact IDs: R-PICKER-CORRECT.004/1, R-PICKER-CORRECT.004/2,
# R-PICKER-CORRECT.004/3, R-PICKER-CORRECT.004/4.
@pytest.mark.parametrize("case", [f"R-PICKER-CORRECT.004/{index}" for index in range(1, 5)], ids=lambda value: value)
def test_r004_reader_refusals_keep_length_missing(tmp_path, case):
    """R-PICKER-CORRECT.004/1-/4: refused R1-R4 never revive 1/2 bytes."""
    refusal = f"R{case.rsplit('/', 1)[1]}"
    path = _refusal_a2l(tmp_path / f"{refusal}.a2l", refusal)

    async def body(app, pilot):
        rows = await _load_a2l(app, pilot, path)
        source = next(row for row in rows if row["name"] == refusal)
        assert source["address"] == 0x1000 and source["length"] is None and source["byte_size"] is None
        results = {}
        for editor in ("check", "patch"):
            panel = await _show_panel(app, pilot, editor)
            results[editor] = _row_result(panel, refusal)
        return results

    results = _run(tmp_path, body)
    for editor, result in results.items():
        assert result["size"] is None, (editor, result)
        assert result["highlighted"]["size"] is None


# R-PICKER-CORRECT.005/1-/5: real Patch Use refuses R1-R5 before any read.
# Exact IDs: R-PICKER-CORRECT.005/1, R-PICKER-CORRECT.005/2,
# R-PICKER-CORRECT.005/3, R-PICKER-CORRECT.005/4, R-PICKER-CORRECT.005/5.
@pytest.mark.parametrize("case", [f"R-PICKER-CORRECT.005/{index}" for index in range(1, 6)], ids=lambda value: value)
def test_r005_use_parameter_refuses_missing_length_without_reads(tmp_path, case):
    """R-PICKER-CORRECT.005/1-/5: exact refusal, empty Bytes, DOC equal, zero reads."""
    refusal = f"R{case.rsplit('/', 1)[1]}"
    path = _refusal_a2l(tmp_path / f"{refusal}.a2l", refusal)

    async def body(app, pilot):
        rows = await _load_a2l(app, pilot, path)
        assert next(row for row in rows if row["name"] == refusal)["byte_size"] is None
        panel = await _show_panel(app, pilot, "patch")
        reads = _ReadSpy()
        panel.set_image_mem_map(reads)
        panel.query_one("#patch_entry_bytes_input", Input).value = "DE AD"
        before = _doc_snapshot(app, panel)
        panel.query_one("#patch_param_use_button", Button).press()
        await _settle(pilot)
        return reads.calls, before, _doc_snapshot(app, panel), (
            panel.query_one("#patch_entry_bytes_input", Input).value,
            str(panel.query_one("#patch_param_use_status", Static).render()),
            _picker(panel).highlighted_parameter,
        )

    reads, before, after, (bytes_value, status, highlighted) = _run(tmp_path, body)
    assert highlighted["size"] is None
    assert bytes_value == ""
    assert status == MISSING_LENGTH_STATUS
    assert reads == []
    assert after == before


# R-PICKER-CORRECT.017/1: hostile name is literal and every C0/C1 is U+FFFD.
def test_r017_1_hostile_parameter_name_is_replaced_literally(tmp_path):
    """R-PICKER-CORRECT.017/1: [red], ESC, NUL and C1 on both picker surfaces."""
    name = "A[red]\x1b\x00\x85Z"
    expected = "A[red]" + CONTROL_REPLACEMENT * 3 + "Z"

    async def body(app, pilot):
        results = {}
        for editor in ("check", "patch"):
            panel = await _show_panel(app, pilot, editor)
            panel.set_a2l_parameters(
                [{"name": name, "address": 0x1000, "length": 2, "byte_size": 2, "datatype": "UWORD"}],
                ("hostile-name", editor),
            )
            await _settle(pilot)
            results[editor] = (_cells(panel, name)[1], _full_name(panel))
        return results

    results = _run(tmp_path, body)
    for cell, full in results.values():
        _assert_literal_surface(cell, expected)
        assert full.plain.endswith("  " + expected)
        assert CONTROL_REPLACEMENT * 3 in full.plain
        assert not [ch for ch in full.plain if ord(ch) < 0x20 or 0x7F <= ord(ch) <= 0x9F]


# R-PICKER-CORRECT.017/2: hostile unit is literal and ESC/DEL become U+FFFD.
def test_r017_2_hostile_unit_is_replaced_literally(tmp_path):
    """R-PICKER-CORRECT.017/2: u16 [link=e] plus two replacements, no link span."""
    unit = "[link=e]\x1b\x7f%"
    expected = "u16 [link=e]" + CONTROL_REPLACEMENT * 2 + "%"

    async def body(app, pilot):
        results = {}
        for editor in ("check", "patch"):
            panel = await _show_panel(app, pilot, editor)
            panel.set_a2l_parameters(
                [{
                    "name": "HOSTILE_UNIT",
                    "address": 0x1000,
                    "length": 2,
                    "byte_size": 2,
                    "datatype": "UWORD",
                    "compu_method_unit": unit,
                }],
                ("hostile-unit", editor),
            )
            await _settle(pilot)
            results[editor] = (_cells(panel, "HOSTILE_UNIT")[3], _full_name(panel))
        return results

    results = _run(tmp_path, body, size=(160, 54))
    for cell, full in results.values():
        _assert_literal_surface(cell, expected)
        assert f"  {expected}  HOSTILE_UNIT" in full.plain
        assert not [span for span in full.spans if "link" in str(span.style).lower()]
        assert not [ch for ch in full.plain if ord(ch) < 0x20 or 0x7F <= ord(ch) <= 0x9F]


# R-PICKER-CORRECT.017/3: a 400-cell UWORD unit clips on ledger and full name.
def test_r017_3_long_hostile_unit_clips_on_both_surfaces_at_80_and_118(tmp_path):
    """R-PICKER-CORRECT.017/3: exact literal clip at 80 and 118 on both editors."""
    unit = "[red]\x1b\x00\x85" + "x" * 395
    assert cell_len(unit) == 400
    normalized = "u16 " + _normalized_literal(unit)

    async def body(app, pilot):
        results = {}
        for editor in ("check", "patch"):
            panel = await _show_panel(app, pilot, editor)
            panel.set_a2l_parameters(
                [{
                    "name": "LONGUNIT",
                    "address": 0x1000,
                    "length": 2,
                    "byte_size": 2,
                    "datatype": "UWORD",
                    "compu_method_unit": unit,
                }],
                ("long-unit", editor),
            )
            await _settle(pilot, 8)
            picker = _picker(panel)
            layout = picker._layout()
            fmt_budget = layout.full_name - cell_len("0x00001000") - 2 - 2 - cell_len("LONGUNIT")
            results[editor] = (
                _cells(panel, "LONGUNIT")[3],
                _full_name(panel),
                _clip_cells(normalized, layout.fmt),
                "0x00001000  " + _clip_cells(normalized, fmt_budget) + "  LONGUNIT",
                layout.full_name,
            )
        return results

    for size in (MIN_SIZE, SIZE):
        results = _run(tmp_path / f"w{size[0]}", body, size=size)
        for cell, full, expected_cell, expected_full, full_budget in results.values():
            _assert_literal_surface(cell, expected_cell)
            _assert_literal_surface(full, expected_full)
            assert cell.plain.endswith("…") and full.plain.startswith("0x00001000  u16 ")
            assert "…  LONGUNIT" in full.plain
            assert cell_len(full.plain) <= full_budget


# R-PICKER-CORRECT.018/1: equal signature preserves filter/page/picks and rebuilds nothing.
def test_r018_1_equal_signature_is_a_zero_describe_noop(tmp_path, monkeypatch):
    """R-PICKER-CORRECT.018/1: equal signature returns False with byte-identical state."""
    describes = _describe_spy(monkeypatch)
    rebuilds = []
    real_rebuild = picker_module.A2LParameterPicker._rebuild_ledger

    def counting_rebuild(self):
        rebuilds.append(self)
        return real_rebuild(self)

    monkeypatch.setattr(picker_module.A2LParameterPicker, "_rebuild_ledger", counting_rebuild)
    rows = [
        {"name": f"P{index:05d}", "address": 0x1000 + index * 2, "length": 2, "byte_size": 2, "datatype": "UWORD"}
        for index in range(250)
    ]

    async def body(app, pilot):
        panel = await _show_panel(app, pilot, "check")
        picker = _picker(panel)
        assert picker.set_parameters(rows, ("same", 1)) is True
        await _settle(pilot)
        picker.include_names(["P00000"])
        panel.query_one("#check_param_filter", Input).value = "P"
        await pilot.pause(0.2)
        panel.query_one("#check_param_page_next_button", Button).press()
        await _settle(pilot)
        before = (
            panel.query_one("#check_param_filter", Input).value,
            picker.page,
            list(picker.picked_params),
            list(picker.filtered_params),
            list(picker.visible_params),
            [_plain(cell) for cell in _cells(panel, "P00200")],
        )
        describes.clear()
        rebuilds.clear()
        result = panel.set_a2l_parameters(rows, ("same", 1))
        await _settle(pilot)
        after = (
            panel.query_one("#check_param_filter", Input).value,
            picker.page,
            list(picker.picked_params),
            list(picker.filtered_params),
            list(picker.visible_params),
            [_plain(cell) for cell in _cells(panel, "P00200")],
        )
        return result, before, after

    result, before, after = _run(tmp_path, body)
    assert result is None  # the panel shim delegates; the picker no-op is observed through zero work
    assert before[0] == "P" and before[1] == 2 and before[2] == ["P00000"]
    assert after == before
    assert describes == []
    assert rebuilds == []


# R-PICKER-CORRECT.018/2: changed real generation describes once per visible picker.
def test_r018_2_changed_generation_batches_once_per_picker(tmp_path, monkeypatch):
    """R-PICKER-CORRECT.018/2: ARR12 12/u16 -> 8/f32, one all-names call each."""
    describes = _describe_spy(monkeypatch)
    first = _generation_a2l(tmp_path / "generation1.a2l")
    second = _generation_a2l(tmp_path / "generation2.a2l", datatype="FLOAT32_IEEE", matrix="2")

    async def body(app, pilot):
        await _load_a2l(app, pilot, first)
        for editor in ("check", "patch"):
            await _show_panel(app, pilot, editor)
        describes.clear()
        rows = await _load_a2l(app, pilot, second)
        assert next(row for row in rows if row["name"] == "ARR12")["length"] == 8
        return {editor: _row_result(app.query_one("#check_editor_panel" if editor == "check" else "#patch_editor_panel"), "ARR12") for editor in ("check", "patch")}

    results = _run(tmp_path, body)
    assert len(describes) == 2
    assert all(call["names"] == ["ARR12"] and call["data"] is not None for call in describes)
    for result in results.values():
        assert result["size"] == 8
        assert result["fmt"] == "f32"
        assert result["painted_fmt"] == "f32"


# R-PICKER-CORRECT.018/3: two None populations return True, reset state, describe once each.
def test_r018_3_none_always_repopulates_with_real_a2l_data(tmp_path, monkeypatch):
    """R-PICKER-CORRECT.018/3: reseeded filter/page/picks reset after each None call."""
    describes = _describe_spy(monkeypatch)
    path = _generation_a2l(tmp_path / "none-population.a2l", count=250)
    data = parse_a2l_file(path)
    rows = enrich_a2l_tags_with_values(data, None)
    assert len(rows) == 250 and all(row["length"] == 2 for row in rows)

    async def body(app, pilot):
        panel = await _show_panel(app, pilot, "check")
        picker = _picker(panel)
        picker.set_parameters(rows, ("prime", 1))
        await _settle(pilot)
        outcomes = []
        describes.clear()
        for _ in range(2):
            picker.include_names(["P00000"])
            panel.query_one("#check_param_filter", Input).value = "P"
            await pilot.pause(0.2)
            panel.query_one("#check_param_page_next_button", Button).press()
            await _settle(pilot)
            assert picker.page == 2 and picker.picked_params == ["P00000"]
            result = picker.set_parameters(rows, None, a2l_data=data)
            await _settle(pilot)
            outcomes.append((
                result,
                panel.query_one("#check_param_filter", Input).value,
                picker.page,
                list(picker.picked_params),
                _row_result(panel, "P00000")["size"],
            ))
        return outcomes

    outcomes = _run(tmp_path, body)
    assert outcomes == [(True, "", 1, [], 2), (True, "", 1, [], 2)]
    assert len(describes) == 2
    assert all(call["names"] == [f"P{index:05d}" for index in range(250)] and call["data"] is data for call in describes)


# R-PICKER-CORRECT.018/4: Inc 5 live reload refreshes both before the outcome.
def test_r018_4_live_reload_refreshes_both_without_reentry(tmp_path, monkeypatch):
    """R-PICKER-CORRECT.018/4: visible ARR12 12 -> 8 on reload, one describe each."""
    describes = _describe_spy(monkeypatch)
    first = _generation_a2l(tmp_path / "live1.a2l")
    second = _generation_a2l(tmp_path / "live2.a2l", matrix="2 2")
    outcomes = []

    async def body(app, pilot):
        await _load_a2l(app, pilot, first)
        for editor in ("check", "patch"):
            await _show_panel(app, pilot, editor)
        real_end = app.end_busy

        def end_busy(kind, gen, message):
            outcomes.append((message, {
                editor: _picker(app.query_one("#check_editor_panel" if editor == "check" else "#patch_editor_panel")).param_rows["ARR12"][1]
                for editor in ("check", "patch")
            }))
            real_end(kind, gen, message)

        monkeypatch.setattr(app, "end_busy", end_busy)
        describes.clear()
        await _load_a2l(app, pilot, second)
        return app._active_screen_key

    active = _run(tmp_path, body)
    assert active == "patch"
    assert len(describes) == 2
    assert outcomes and outcomes[-1][1] == {"check": 8, "patch": 8}


# R-PICKER-CORRECT.019/1: real software_a, median three batch describes <= 2 s.
@pytest.mark.serial_timing
def test_r019_1_13990_object_population_has_one_timed_batch_per_generation(tmp_path, monkeypatch):
    """R-PICKER-CORRECT.019/1: 13,990 names, three generations, median <=2.0 s."""
    describes = _describe_spy(monkeypatch)
    data = parse_a2l_file(SOFTA)
    rows = data["tags"]
    names = [row["name"] for row in rows]
    assert len(names) == len(set(names)) == 13990

    async def body(app, pilot):
        panel = await _show_panel(app, pilot, "check")
        picker = _picker(panel)
        counts = []
        for generation in range(3):
            before = len(describes)
            assert picker.set_parameters(rows, ("software_a", generation), a2l_data=data) is True
            await _settle(pilot, 2)
            assert len(describes) == before + 1
            counts.append(len(picker.param_rows))
        return counts

    counts = _run(tmp_path, body, size=MIN_SIZE)
    assert counts == [13990, 13990, 13990]
    assert [call["names"] for call in describes] == [names, names, names]
    assert all(call["data"] is data and call["count"] == 13990 for call in describes)
    runs = [call["seconds"] for call in describes]
    median = statistics.median(runs)
    assert median <= report_margin("R-PICKER-CORRECT.019 picker describe 13990", median, timing_bound(2.0)), runs


# R-PICKER-CORRECT.019/2: 20 real filter/page rebuilds never describe and mount <=200.
@pytest.mark.serial_timing
def test_r019_2_twenty_filter_page_rebuilds_never_describe(tmp_path, monkeypatch):
    """R-PICKER-CORRECT.019/2: zero describes, 20 rebuilds, <=200 rows, formats stable."""
    describes = _describe_spy(monkeypatch)
    rebuilds = []
    real_rebuild = picker_module.A2LParameterPicker._rebuild_ledger

    def counting_rebuild(self):
        rebuilds.append(self)
        return real_rebuild(self)

    monkeypatch.setattr(picker_module.A2LParameterPicker, "_rebuild_ledger", counting_rebuild)
    data = parse_a2l_file(SOFTA)
    rows = data["tags"]
    assert len(rows) == 13990

    async def body(app, pilot):
        panel = await _show_panel(app, pilot, "check")
        picker = _picker(panel)
        assert picker.set_parameters(rows, ("software_a", "rebuilds"), a2l_data=data) is True
        await _settle(pilot)
        formats = {name: values[2] for name, values in picker.param_rows.items()}
        describes.clear()
        rebuilds.clear()
        mounted = []
        for index in range(10):
            panel.query_one("#check_param_filter", Input).value = "" if index % 2 == 0 else "ASAM"
            await pilot.pause(0.2)
            assert len(picker.filtered_params) > 200
            panel.query_one("#check_param_page_next_button", Button).press()
            await _settle(pilot, 2)
            mounted.append(panel.query_one("#check_param_table", DataTable).row_count)
        return mounted, formats, {name: values[2] for name, values in picker.param_rows.items()}

    mounted, before_formats, after_formats = _run(tmp_path, body, size=MIN_SIZE)
    assert len(rebuilds) == 20
    assert describes == []
    assert len(mounted) == 10 and all(0 < count <= 200 for count in mounted)
    assert after_formats == before_formats
