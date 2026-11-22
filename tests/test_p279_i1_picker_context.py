"""P-279 I1 E4, group G-PICK: the Check and Patch pickers through the describe context.

Requirements: R-A2L-REFRESH.060 (format column and longest cell from the format fields),
R-PE-DEF.11.1 and .11.2 (page rows from the context describe; was R-A2L-REFRESH.061,
withdrawn in I2), R-A2L-REFRESH.078 (one width measurement per distinct format text) and the
page-change arm of
R-A2L-REFRESH.070 (a raise inside the context describe falls back to the non-context
describe and logs one fixed line). The stage arm of .070 belongs to the App group.
Cases: ``records/2026-11-20-p279/I1/E4/02-test-cases-PICK.md``.

Oracle: the eager path, i.e. today's ``set_parameters(rows, sig, a2l_data=a2l)`` with the
bulk describe, computed in each test. Nothing is retyped from a count.

Private seams (``build_describe_context``, ``describe_in_context``, the picker's
``describe_context`` / ``page_definitions`` and the new keyword) are reached lazily inside
each test body, so the module collects on the base revision and each node fails on its own.

Section-walk proxy: "0 walks" is asserted as 0 calls of the bulk describes
(``describe_definitions`` / ``describe_definition``) in the a2l_definition and picker modules.

Log sink (E4 R3): the fixed line is counted by exact text on the app's ``s19tui`` channel
only, so a line written to any other logger fails. Absence checks read every logger and the
app's ``log_lines``.
The filter change uses the repo's ``wait_until`` (debounce of 150 ms; bounded, event-yielding).
"""
from __future__ import annotations

import asyncio
import contextlib
import functools
import importlib
import logging
from math import ceil
from pathlib import Path
from types import MappingProxyType

import pytest

ROOT = Path(__file__).resolve().parents[1]
PUBLIC = ROOT / "examples" / "case_00_public"
D171 = PUBLIC / "ASAP2_Demo_V171.a2l"
SOFTWARE_A = PUBLIC / "software_a.a2l"
CASE01 = ROOT / "examples" / "case_01_basic_valid" / "firmware.a2l"
FIXED = "A2L describe context failed: full describe used."
SIZE = (118, 54)
PAGE = 200
CURVE = "ASAM.C.CURVE.STD_AXIS"


def _mod(name: str):
    return importlib.import_module(name)


@functools.lru_cache(maxsize=None)
def _parsed(path: Path) -> dict:
    return _mod("s19_app.tui.a2l_parse").parse_a2l_file(path)


def _rows(a2l: dict) -> list:
    """The picker rows of an A2L: one per tag with an integer address, in tag order."""
    seen, rows = set(), []
    for tag in a2l["tags"]:
        name, address = tag.get("name"), tag.get("address")
        if not isinstance(address, int) or isinstance(address, bool) or name in seen:
            continue
        seen.add(name)
        rows.append(
            {
                "name": name,
                "address": address,
                "datatype": tag.get("datatype"),
                "char_type": tag.get("char_type"),
                "compu_method_unit": tag.get("compu_method_unit"),
            }
        )
    return rows


def _context(a2l: dict, rows: list):
    build = getattr(_mod("s19_app.tui.a2l_definition"), "build_describe_context")
    return build(a2l, [row["name"] for row in rows])


def _eager(rows: list, a2l: dict):
    picker = _mod("s19_app.tui.a2l_parameter_picker").A2LParameterPicker()
    picker.set_parameters(rows, "eager", a2l_data=a2l)
    return picker


def _lazy(rows: list, a2l: dict, context):
    picker = _mod("s19_app.tui.a2l_parameter_picker").A2LParameterPicker()
    picker.set_parameters(rows, "lazy", a2l_data=a2l, describe_context=context)
    return picker


def _counting(real, calls, label):
    def wrapper(*args, **kwargs):
        calls.append(label)
        return real(*args, **kwargs)

    return wrapper


def _spy_bulk(monkeypatch) -> list:
    """Count every call of a bulk describe (either module's binding)."""
    calls: list = []
    for module in ("s19_app.tui.a2l_definition", "s19_app.tui.a2l_parameter_picker"):
        target = _mod(module)
        for attr in ("describe_definitions", "describe_definition"):
            real = getattr(target, attr, None)
            if real is not None:
                monkeypatch.setattr(target, attr, _counting(real, calls, attr))
    return calls


def _spy_in_context(monkeypatch, exc=None) -> list:
    """Wrap ``describe_in_context`` (the I-1 function) in both modules; raise ``exc`` if given."""
    defn = _mod("s19_app.tui.a2l_definition")
    real = getattr(defn, "describe_in_context")
    calls: list = []

    def wrapper(*args, **kwargs):
        calls.append("describe_in_context")
        if exc is not None:
            raise exc
        return real(*args, **kwargs)

    monkeypatch.setattr(defn, "describe_in_context", wrapper)
    monkeypatch.setattr(
        _mod("s19_app.tui.a2l_parameter_picker"), "describe_in_context", wrapper, raising=False
    )
    return calls


class _Tap(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.records: list = []

    def emit(self, record) -> None:
        # The tap sits on the root and on ``s19tui``; a propagating record reaches both.
        if not any(seen is record for seen in self.records):
            self.records.append(record)


@contextlib.contextmanager
def _tap():
    tap, root, app_logger = _Tap(), logging.getLogger(), logging.getLogger("s19tui")
    previous = root.level
    root.setLevel(logging.INFO)
    root.addHandler(tap)
    app_logger.addHandler(tap)
    try:
        yield tap
    finally:
        app_logger.removeHandler(tap)
        root.removeHandler(tap)
        root.setLevel(previous)


def _fixed_count(tap) -> int:
    return sum(
        record.name == "s19tui" and record.getMessage() == FIXED for record in tap.records
    )


def _assert_fixed_line_only(tap, names, app=None) -> None:
    """Every captured message hides the exception text, the traceback and the page's names."""
    texts = [record.getMessage() for record in tap.records]
    if app is not None:
        texts += list(app.log_lines)
    assert not [t for t in texts if "CONTEXT_CONTROL" in t], texts
    assert all(record.exc_info is None for record in tap.records)
    fixed = [t for t in texts if FIXED in t]
    assert not [n for n in names for t in fixed if n in t.replace(FIXED, "")], fixed


async def _with_picker(body):
    from textual.app import App

    picker_cls = _mod("s19_app.tui.a2l_parameter_picker").A2LParameterPicker

    class Host(App):
        def compose(self):
            yield picker_cls()

    app = Host()
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause()
        picker = app.query_one(picker_cls)
        return await body(pilot, picker)


async def _with_panel(tmp_path, screen, body):
    from s19_app.tui.app import S19TuiApp

    app = S19TuiApp(base_dir=tmp_path / "app")
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause()
        app.action_show_screen(screen)
        await pilot.pause()
        await pilot.pause()
        panel = app.query_one(f"#{screen}_editor_panel")
        return await body(app, pilot, panel)


async def _filter(pilot, picker, text, prefix="check_param") -> None:
    """Type ``text`` into the filter and wait until the shown page holds only matching names."""
    from textual.widgets import Input

    from tests.support.timing import wait_until

    picker.query_one(f"#{prefix}_filter", Input).value = text
    await wait_until(
        pilot,
        lambda: bool(picker.visible_params)
        and all(text.lower() in name.lower() for name in picker.visible_params),
        lambda: f"filter {text!r}: visible={len(picker.visible_params)}",
    )


async def _clear_filter(pilot, picker, prefix="check_param") -> None:
    """Empty the filter input and wait for the unfiltered first page (no-op when already empty)."""
    from textual.widgets import Input

    from tests.support.timing import wait_until

    box = picker.query_one(f"#{prefix}_filter", Input)
    if not box.value:
        return
    box.value = ""
    await wait_until(
        pilot,
        lambda: len(picker.visible_params) == min(PAGE, len(picker.param_rows)),
        lambda: f"clear filter: visible={len(picker.visible_params)}",
    )


async def _next_pages(pilot, panel, count) -> None:
    from textual.widgets import Button

    for _ in range(count):
        panel.query_one("#patch_param_page_next_button", Button).press()
        await pilot.pause()
    await pilot.pause()


def _sheet_snapshot(panel):
    picker = panel._a2l_picker
    return list(picker.visible_params), list(panel._sheet.rows)


# ----------------------------------------------------------------------------- .060


def _assert_cells_equal_eager(rows, a2l, monkeypatch=None):
    context = _context(a2l, rows)
    eager = _eager(rows, a2l)
    calls = _spy_bulk(monkeypatch) if monkeypatch is not None else []
    lazy = _lazy(rows, a2l, context)
    assert lazy.param_rows == eager.param_rows
    assert lazy.fmt_longest == eager.fmt_longest
    assert calls == [], calls
    return eager, lazy, context


def test_r_a2l_refresh_060_1_d171_cells_and_longest_equal_eager_without_describe(monkeypatch):
    """Why: the format column must not change when definitions are not built at load."""
    a2l = _parsed(D171)
    rows = _rows(a2l)
    eager, lazy, _ = _assert_cells_equal_eager(rows, a2l, monkeypatch)
    assert len(lazy.param_rows) == len(rows) and lazy.fmt_longest > 0
    assert dict(lazy.definitions) == {}


def test_r_a2l_refresh_060_2_case01_cells_and_longest_equal_eager(monkeypatch):
    a2l = _parsed(CASE01)
    rows = _rows(a2l)
    eager, lazy, _ = _assert_cells_equal_eager(rows, a2l, monkeypatch)
    assert rows and lazy.fmt_longest == eager.fmt_longest


def test_r_a2l_refresh_060_3_curve_std_axis_cell_is_s16_hours():
    """The tag row gives '?' for this curve; the format fields give the element format."""
    a2l = _parsed(D171)
    rows = _rows(a2l)
    context = _context(a2l, rows)
    lazy, eager = _lazy(rows, a2l, context), _eager(rows, a2l)
    assert lazy.param_rows[CURVE][2] == "s16 hours"
    assert eager.param_rows[CURVE][2] == "s16 hours"


def test_r_a2l_refresh_060_4_control_tag_row_fallback_differs_on_d171():
    """Control: the tag-row format differs from the eager cell on d171, so the equality above can fail."""
    a2l = _parsed(D171)
    rows = _rows(a2l)
    eager = _eager(rows, a2l)
    bare = _mod("s19_app.tui.a2l_parameter_picker").A2LParameterPicker()
    bare.set_parameters(rows, "bare")
    differing = [n for n in eager.param_rows if eager.param_rows[n][2] != bare.param_rows[n][2]]
    assert differing, "the oracle cannot fail: tag-row cells already equal the eager ones"
    context = _context(a2l, rows)
    lazy = _lazy(rows, a2l, context)
    assert all(lazy.param_rows[n][2] == eager.param_rows[n][2] for n in differing)


def test_r_a2l_refresh_060_5_unchanged_signature_returns_false_keeps_context():
    a2l = _parsed(D171)
    rows = _rows(a2l)
    context = _context(a2l, rows)
    lazy = _lazy(rows, a2l, context)
    assert lazy.set_parameters(rows, "lazy", a2l_data=a2l, describe_context=context) is False
    assert lazy.describe_context is context


def test_r_a2l_refresh_060_6_describe_context_property_tracks_last_population():
    a2l = _parsed(D171)
    rows = _rows(a2l)
    picker = _mod("s19_app.tui.a2l_parameter_picker").A2LParameterPicker()
    assert picker.describe_context is None
    context = _context(a2l, rows)
    picker.set_parameters(rows, "a", a2l_data=a2l, describe_context=context)
    assert picker.describe_context is context
    assert picker.definitions_source is context.source
    picker.set_parameters(rows, "b", a2l_data=a2l)
    assert picker.describe_context is None
    with pytest.raises(AttributeError):
        picker.describe_context = context


def test_r_a2l_refresh_060_7_context_wins_over_prepared_definitions():
    a2l = _parsed(D171)
    rows = _rows(a2l)
    context = _context(a2l, rows)
    eager = _eager(rows, a2l)
    picker = _mod("s19_app.tui.a2l_parameter_picker").A2LParameterPicker()
    picker.set_parameters(
        rows, "w", a2l_data=a2l, prepared_definitions=MappingProxyType({}), describe_context=context
    )
    assert picker.describe_context is context
    assert picker.param_rows == eager.param_rows
    assert dict(picker.definitions) == {}


def test_r_a2l_refresh_060_8_mounted_patch_panel_forwards_context(tmp_path):
    a2l = _parsed(D171)
    rows = _rows(a2l)
    context = _context(a2l, rows)
    eager = _eager(rows, a2l)

    async def body(app, pilot, panel):
        panel.set_a2l_parameters(rows, "sig", a2l_data=a2l, describe_context=context)
        await pilot.pause()
        picker = panel._a2l_picker
        assert picker.describe_context is context
        assert picker.param_rows == eager.param_rows
        assert picker.fmt_longest == eager.fmt_longest

    asyncio.run(_with_panel(tmp_path, "patch", body))


def test_r_a2l_refresh_060_9_unmounted_patch_panel_forwards_no_context():
    from s19_app.tui.screens_directionb import PatchEditorPanel

    a2l = _parsed(D171)
    rows = _rows(a2l)
    context = _context(a2l, rows)
    panel = PatchEditorPanel()
    panel.set_a2l_parameters(rows, "sig", a2l_data=a2l, describe_context=context)
    assert panel._a2l_picker.describe_context is None
    assert panel._a2l_picker.definitions_source is None


def _check_entry(a2l, context, signature):
    from s19_app.tui.app.file_load import A2LPickerSnapshot

    return A2LPickerSnapshot(
        picker="check",
        signature=signature,
        a2l_source=a2l,
        definitions=MappingProxyType({}),
        describe_context=context,
    )


def test_r_a2l_refresh_060_10_check_panel_matching_entry_forwards_context_cells_equal_eager(tmp_path):
    a2l = _parsed(D171)
    rows = _rows(a2l)
    context = _context(a2l, rows)
    eager = _eager(rows, a2l)
    key = (1, 2, 3)

    async def body(app, pilot, panel):
        app.current_a2l_data = a2l
        app._accepted_a2l_picker_snapshots = MappingProxyType(
            {"check": _check_entry(a2l, context, key)}
        )
        panel.set_a2l_parameters(rows, key)
        await pilot.pause()
        assert panel._picker.describe_context is context
        assert panel._picker.param_rows == eager.param_rows
        assert panel._picker.fmt_longest == eager.fmt_longest

    asyncio.run(_with_panel(tmp_path, "check", body))


def test_r_a2l_refresh_060_11_check_panel_mismatched_entry_bulk_population(tmp_path):
    a2l = _parsed(D171)
    rows = _rows(a2l)
    context = _context(a2l, rows)
    eager = _eager(rows, a2l)

    async def body(app, pilot, panel):
        app.current_a2l_data = a2l
        app._accepted_a2l_picker_snapshots = MappingProxyType(
            {"check": _check_entry(a2l, context, (9, 9, 9))}
        )
        panel.set_a2l_parameters(rows, (1, 2, 3))
        await pilot.pause()
        assert panel._picker.describe_context is None
        assert dict(app._accepted_a2l_picker_snapshots) == {}
        assert panel._picker.param_rows == eager.param_rows
        assert panel._picker.fmt_longest == eager.fmt_longest
        assert dict(panel._picker.definitions) == dict(eager.definitions)

    asyncio.run(_with_panel(tmp_path, "check", body))


# ----------------------------------------------------------------------------- R-PE-DEF.11.1 / .11.2 (was R-A2L-REFRESH.061, withdrawn in I2)


def test_r_pe_def_11_1_1_page_definitions_equal_bulk_no_bulk_describe(monkeypatch):
    a2l = _parsed(D171)
    rows = _rows(a2l)
    context = _context(a2l, rows)
    eager = _eager(rows, a2l)

    async def body(pilot, picker):
        picker.set_parameters(rows, "lazy", a2l_data=a2l, describe_context=context)
        await pilot.pause()
        calls = _spy_bulk(monkeypatch)
        page = picker.page_definitions()
        visible = list(picker.visible_params)
        assert visible and set(page) == set(visible)
        assert dict(page) == {name: eager.definitions[name] for name in visible}
        assert calls == [], calls

    asyncio.run(_with_picker(body))


def test_r_pe_def_11_2_1_same_page_twice_one_context_describe_no_walk(monkeypatch):
    a2l = _parsed(D171)
    rows = _rows(a2l)
    context = _context(a2l, rows)

    async def body(pilot, picker):
        picker.set_parameters(rows, "lazy", a2l_data=a2l, describe_context=context)
        await pilot.pause()
        calls = _spy_in_context(monkeypatch)
        first = picker.page_definitions()
        second = picker.page_definitions()
        assert dict(first) == dict(second) and first
        assert len(calls) == 1, calls

    asyncio.run(_with_picker(body))


def test_r_pe_def_11_2_2_filter_change_same_page_new_key_second_describe(monkeypatch):
    a2l = _parsed(D171)
    rows = _rows(a2l)
    context = _context(a2l, rows)
    eager = _eager(rows, a2l)

    async def body(pilot, picker):
        picker.set_parameters(rows, "lazy", a2l_data=a2l, describe_context=context)
        await pilot.pause()
        calls = _spy_in_context(monkeypatch)
        picker.page_definitions()
        before = list(picker.visible_params)
        await _filter(pilot, picker, "CURVE")
        assert list(picker.visible_params) != before and picker.visible_params
        page = picker.page_definitions()
        assert len(calls) == 2, calls
        assert dict(page) == {n: eager.definitions[n] for n in picker.visible_params}

    asyncio.run(_with_picker(body))


def test_r_pe_def_11_1_2_population_fallback_page_definitions_is_population_mapping():
    a2l = _parsed(D171)
    eager = _eager(_rows(a2l), a2l)
    assert eager.page_definitions() is eager.definitions


def test_r_pe_def_11_1_3_software_a_three_pages_sheet_rows_equal_eager(tmp_path, monkeypatch):
    a2l = _parsed(SOFTWARE_A)
    rows = _rows(a2l)
    pages = ceil(len(rows) / PAGE)
    assert pages >= 3
    middle = (pages + 1) // 2
    steps = [0, middle - 1, pages - 1 - (middle - 1)]
    context = _context(a2l, rows)

    async def walk(pilot, panel):
        shots = []
        for step in steps:
            await _next_pages(pilot, panel, step)
            shots.append(_sheet_snapshot(panel))
        return shots

    async def body(app, pilot, panel):
        panel.set_a2l_parameters(rows, "eager", a2l_data=a2l)
        await pilot.pause()
        await pilot.pause()
        want = await walk(pilot, panel)
        calls = _spy_bulk(monkeypatch)
        panel.set_a2l_parameters(rows, "lazy", a2l_data=a2l, describe_context=context)
        await pilot.pause()
        await pilot.pause()
        got = await walk(pilot, panel)
        assert calls == [], calls
        assert len({tuple(shot[0]) for shot in want}) == 3
        for (names_w, rows_w), (names_g, rows_g) in zip(want, got):
            assert names_g == names_w
            assert len(rows_g) == len(names_g) > 0
            assert rows_g == rows_w

    asyncio.run(_with_panel(tmp_path, "patch", body))


# ----------------------------------------------------------------------------- .070


def test_r_a2l_refresh_070_1_picker_page_raise_falls_back_one_fixed_line(monkeypatch):
    a2l = _parsed(D171)
    rows = _rows(a2l)
    context = _context(a2l, rows)
    eager = _eager(rows, a2l)

    async def body(pilot, picker):
        picker.set_parameters(rows, "lazy", a2l_data=a2l, describe_context=context)
        await pilot.pause()
        with _tap() as clean:
            picker.page_definitions()
        assert _fixed_count(clean) == 0
        _spy_in_context(monkeypatch, TypeError("CONTEXT_CONTROL"))
        picker.set_parameters(rows, "lazy-2", a2l_data=a2l, describe_context=context)
        await pilot.pause()
        with _tap() as tap:
            page = picker.page_definitions()
        names = list(picker.visible_params)
        assert dict(page) == {n: eager.definitions[n] for n in names}
        assert _fixed_count(tap) == 1, [(r.name, r.getMessage()) for r in tap.records]
        _assert_fixed_line_only(tap, names)

    asyncio.run(_with_picker(body))


def test_r_a2l_refresh_070_2_panel_page_raise_rows_equal_eager_one_line(tmp_path, monkeypatch):
    a2l = _parsed(D171)
    rows = _rows(a2l)
    context = _context(a2l, rows)

    async def body(app, pilot, panel):
        panel.set_a2l_parameters(rows, "eager", a2l_data=a2l)
        await pilot.pause()
        await pilot.pause()
        want = _sheet_snapshot(panel)
        with _tap() as clean:
            panel.set_a2l_parameters(rows, "lazy-clean", a2l_data=a2l, describe_context=context)
            await pilot.pause()
            await pilot.pause()
        assert _fixed_count(clean) == 0
        _spy_in_context(monkeypatch, TypeError("CONTEXT_CONTROL"))
        with _tap() as tap:
            panel.set_a2l_parameters(rows, "lazy", a2l_data=a2l, describe_context=context)
            await pilot.pause()
            await pilot.pause()
        got = _sheet_snapshot(panel)
        assert got == want and want[1]
        assert _fixed_count(tap) == 1, [(r.name, r.getMessage()) for r in tap.records]
        _assert_fixed_line_only(tap, got[0], app)

    asyncio.run(_with_panel(tmp_path, "patch", body))


def test_r_a2l_refresh_070_3_panel_filter_page_raise_rows_equal_eager_one_line(tmp_path, monkeypatch):
    a2l = _parsed(D171)
    rows = _rows(a2l)
    context = _context(a2l, rows)

    async def body(app, pilot, panel):
        picker = panel._a2l_picker
        panel.set_a2l_parameters(rows, "eager", a2l_data=a2l)
        await pilot.pause()
        await _filter(pilot, picker, "CURVE", "patch_param")
        await pilot.pause()
        want = _sheet_snapshot(panel)
        panel.set_a2l_parameters(rows, "lazy", a2l_data=a2l, describe_context=context)
        await pilot.pause()
        await pilot.pause()
        await _clear_filter(pilot, picker, "patch_param")
        _spy_in_context(monkeypatch, TypeError("CONTEXT_CONTROL"))
        with _tap() as tap:
            await _filter(pilot, picker, "CURVE", "patch_param")
            await pilot.pause()
        got = _sheet_snapshot(panel)
        assert got == want and want[1]
        assert _fixed_count(tap) == 1, [(r.name, r.getMessage()) for r in tap.records]
        _assert_fixed_line_only(tap, got[0], app)

    asyncio.run(_with_panel(tmp_path, "patch", body))


# ----------------------------------------------------------------------------- .078


def _independent_width(text: str) -> int:
    """The cell width of one format text, computed here (not by the product helper):
    every C0/C1 control becomes one U+FFFD cell, the trailing space is stripped."""
    from rich.cells import cell_len

    replaced = "".join("�" if ord(c) <= 31 or 127 <= ord(c) <= 159 else c for c in text)
    return cell_len(replaced.rstrip())


def _raw_cells(text: str) -> int:
    """The width of a text without the control replacement (a C0 control is zero cells wide)."""
    from rich.cells import cell_len

    return cell_len(text.rstrip())


def _unmounted_picker(kind: str):
    """An unmounted Check (default ids) or Patch (``patch_param``) picker: no ledger row is painted."""
    cls = _mod("s19_app.tui.a2l_parameter_picker").A2LParameterPicker
    return cls() if kind == "check" else cls(id_prefix="patch_param", mode="pick")


def _count_measurements(monkeypatch) -> list:
    """Count the width measurements: each builds one literal text of a format cell."""
    target = _mod("s19_app.tui.a2l_parameter_picker")
    calls: list = []
    monkeypatch.setattr(
        target,
        "_literal_parameter_text",
        _counting(getattr(target, "_literal_parameter_text"), calls, "measure"),
    )
    return calls


@pytest.mark.parametrize(
    "path, dedupes",
    [(D171, True), (CASE01, False), (SOFTWARE_A, True)],
    ids=["d171", "case_01", "software_a"],
)
@pytest.mark.parametrize("kind", ["check", "patch"])
def test_r_a2l_refresh_078_one_width_measurement_per_distinct_text(monkeypatch, kind, path, dedupes):
    """R-A2L-REFRESH.078/1-6: measurements <= distinct format texts; the longest cell equals the
    largest per-row width (computed here). A population that measured every row fails on d171
    and software_a, whose rows repeat their format texts."""
    a2l = _parsed(path)
    rows = _rows(a2l)
    context = _context(a2l, rows)
    picker = _unmounted_picker(kind)
    assert not picker.is_mounted
    calls = _count_measurements(monkeypatch)
    picker.set_parameters(rows, "sig", describe_context=context)
    texts = [cells[2] for cells in picker.param_rows.values()]
    distinct = set(texts)
    assert len(texts) == len(rows) and distinct
    if dedupes:
        assert len(distinct) < len(texts), "control: the population repeats a format text"
    assert len(calls) <= len(distinct), (len(calls), len(distinct), len(texts))
    assert picker.fmt_longest == max(_independent_width(text) for text in texts)


@pytest.mark.parametrize(
    "arm, units, naive",
    [
        ("control", ("a" + "" * 10, "ab"), lambda t: _raw_cells(t)),
        ("wide", ("ｋｍｋｍ", "abcdef"), lambda t: len(t.rstrip())),
    ],
    ids=["control", "wide"],
)
def test_r_a2l_refresh_078_control_and_wide_units_keep_the_longest_cell(arm, units, naive):
    """R-A2L-REFRESH.078/7: units with a C0 control (one cell each after replacement) or a double-width
    character (two cells) give the largest per-row width; a code-point or raw-control length differs."""
    rows = [
        {"name": f"P{index}", "address": 0x100 + index, "datatype": "UBYTE", "compu_method_unit": unit}
        for index, unit in enumerate(units)
    ]
    picker = _unmounted_picker("check")
    picker.set_parameters(rows, "sig")
    texts = [cells[2] for cells in picker.param_rows.values()]
    assert any(unit in text for unit in units for text in texts), "control: the units reach the cells"
    expected = max(_independent_width(text) for text in texts)
    assert picker.fmt_longest == expected
    assert expected != max(naive(text) for text in texts), "control: the naive length would differ"

