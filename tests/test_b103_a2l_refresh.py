"""Batch 103 Inc 5: independent product-route tests for A2L refresh."""

from __future__ import annotations

import asyncio
import hashlib
import json
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import pytest
from rich.text import Text
from textual.widgets import Button, DataTable, Input, Label, Static, TextArea

from s19_app.tui.a2l import parse_a2l_file
from s19_app.tui.a2l_parameter_picker import A2LParameterPicker
from s19_app.tui.app import A2LDetailCard, PreparedLoad, S19TuiApp
from s19_app.tui.changes.io import emit_s19_from_mem_map
from s19_app.tui.issues_view import IssueRow
from s19_app.tui.screens import ConfirmQuestionScreen
from s19_app.tui.screens_directionb import (
    CheckEditorPanel,
    LoadedArtifactsPanel,
    MemoryMapPanel,
    PatchEditorPanel,
)
from s19_app.tui.segment_split_view import SplitJoinWindow
from tests.support.b100_workers import settle_workers
from tests.support.timing import wait_until


OLD = (
    ("OLD_ONLY", 0x0010, 1),
    ("AlphaShared", 0x0020, 2),
    ("OUT_WARN", 0x0030, 1),
    ("PAGE2_OLD", 0x0070, 1),
)
NEW = (
    ("NEW_ONLY", 0x0040, 1),
    ("AlphaShared", 0x0020, 2),
    ("NEW_ERROR", 0x0050, 1),
    ("PAGE2_NEW", 0x0071, 1),
)
PLAIN = (("BetaOnly", 0x0060, 1),)
MODE = (
    ("AlphaIn", 0x0020, 1),
    ("AlphaOutside", 0x1000, 1),
    ("AlphaInvalid", 0x2000, 1),
)
IMG1 = {i: (3 * i + 1) % 256 for i in range(256)}
IMG2 = {i: (3 * i + 2) % 256 for i in range(256)}
NO_PICKERS = "No A2L parameters — load an A2L (^L) to list them."
HINT = "Highlight a tag to inspect its fields."


@dataclass
class Fixture:
    base: Path
    src: Path
    old: Path
    new: Path
    plain: Path
    mode1: Path
    mode2: Path
    img1: Path
    img2: Path
    mac: Path

    @classmethod
    def build(cls, tmp_path: Path) -> "Fixture":
        base = tmp_path / "app"
        src = tmp_path / "src"
        src.mkdir()
        paths = {
            "old": src / "old.a2l",
            "new": src / "new.a2l",
            "plain": src / "plain.a2l",
            "mode1": src / "mode1.a2l",
            "mode2": src / "mode2.a2l",
        }
        for key, rows in (("old", OLD), ("new", NEW), ("plain", PLAIN)):
            paths[key].write_text(_a2l_text(rows), encoding="utf-8")
            data = parse_a2l_file(paths[key])
            assert data["errors"] == [], (key, data["errors"])
            assert [(t["name"], t["address"], t["length"]) for t in data["tags"]] == list(rows)
        for key in ("mode1", "mode2"):
            paths[key].write_text(_mode_text(key), encoding="utf-8")
            data = parse_a2l_file(paths[key])
            assert [t["name"] for t in data["tags"]] == [row[0] for row in MODE]
            assert any(t["name"] == "AlphaInvalid" and t.get("address") is None for t in data["tags"])
        img1 = src / "img1.s19"
        img2 = src / "img2.s19"
        _write_image(img1, IMG1)
        _write_image(img2, IMG2)
        mac = src / "records.mac"
        lines = ["BROKEN=not-hex"]
        lines += [f"FILL_{i:03d}=0x{i + 0x80:04X}" for i in range(99)]
        lines += [
            "OLD_ONLY=0x0010",
            "NEW_ONLY=0x0040",
            "NEW_ERROR=0x0051",
            "NO_MATCH=0x0070",
        ]
        mac.write_text("\n".join(lines) + "\n", encoding="ascii")
        return cls(base, src, paths["old"], paths["new"], paths["plain"], paths["mode1"], paths["mode2"], img1, img2, mac)


def _a2l_text(rows: tuple[tuple[str, int, int], ...]) -> str:
    lines = [
        "ASAP2_VERSION 1 71",
        '/begin PROJECT P ""',
        '  /begin MODULE M ""',
        '    /begin MOD_COMMON ""',
        "      BYTE_ORDER LITTLE_ENDIAN",
        "    /end MOD_COMMON",
        '    /begin RECORD_LAYOUT RL_U8',
        "      FNC_VALUES 1 UBYTE ROW_DIR DIRECT",
        "    /end RECORD_LAYOUT",
        '    /begin RECORD_LAYOUT RL_U16',
        "      FNC_VALUES 1 UWORD ROW_DIR DIRECT",
        "    /end RECORD_LAYOUT",
        '    /begin COMPU_METHOD CM_IDENT "" IDENTICAL "%.3" ""',
        "    /end COMPU_METHOD",
    ]
    for name, address, size in rows:
        lines += [
            f'    /begin MEMORY_SEGMENT {name} ""',
            f"      DATA FLASH INTERN 0x{address:04X} 0x{size:04X} -1 -1 -1 -1 -1",
            "    /end MEMORY_SEGMENT",
            f'    /begin CHARACTERISTIC {name} "{name} description"',
            f"      VALUE 0x{address:04X} RL_U{size * 8} 0 CM_IDENT 0 {2 ** (size * 8) - 1}",
            f"      UNIT \"u{size * 8}\"",
            "    /end CHARACTERISTIC",
        ]
    lines += ["  /end MODULE", "/end PROJECT", ""]
    return "\n".join(lines)


def _mode_text(marker: str) -> str:
    text = _a2l_text(MODE[:2])
    return text.replace(
        "  /end MODULE",
        '    /begin CHARACTERISTIC AlphaInvalid "invalid fixture"\n'
        "    /end CHARACTERISTIC\n"
        f'    /begin GROUP {marker} ""\n'
        "    /end GROUP\n"
        "  /end MODULE",
    )


def _write_image(path: Path, mem: dict[int, int]) -> None:
    path.write_text(emit_s19_from_mem_map(mem, [(min(mem), max(mem) + 1)]), encoding="ascii")


def _project(f: Fixture, name: str, *, image: Path | None, a2l: Path, mac: bool = False) -> Path:
    folder = f.base / ".s19tool" / "workarea" / name
    folder.mkdir(parents=True)
    active = None
    if image is not None:
        target = folder / image.name
        target.write_bytes(image.read_bytes())
        active = target.stem
    target_a2l = folder / a2l.name
    target_a2l.write_bytes(a2l.read_bytes())
    if mac:
        (folder / f.mac.name).write_bytes(f.mac.read_bytes())
    (folder / "project.json").write_text(
        json.dumps({"schema_version": 1, "active_variant": active}), encoding="utf-8"
    )
    return folder


def _plain(value: object) -> str:
    return value.plain if isinstance(value, Text) else str(value)


def _table_names(table: DataTable) -> list[str]:
    index = next(i for i, col in enumerate(table.ordered_columns) if str(col.label) in {"Tag", "Parameter"})
    names = []
    for row in range(table.row_count):
        value = _plain(table.get_row_at(row)[index])
        names.append(value.removeprefix("✓ ").removeprefix("· "))
    return names


def _picker(panel: CheckEditorPanel | PatchEditorPanel) -> A2LParameterPicker:
    return panel._picker if isinstance(panel, CheckEditorPanel) else panel._a2l_picker


def _loaded_text(app: S19TuiApp) -> list[str]:
    return [_plain(cell.render()) for cell in app.query_one("#loaded_panel", LoadedArtifactsPanel).query(".loaded-detail")]


def _expected_values(rows: tuple[tuple[str, int, int], ...], image: dict[int, int] | None) -> list[int | None]:
    if image is None:
        return [None] * len(rows)
    return [sum(image[address + offset] << (8 * offset) for offset in range(size)) for _, address, size in rows]


def _a2l_visible_shape(app: S19TuiApp) -> list[tuple[str, str, str, str]]:
    table = app.query_one("#a2l_tags_list", DataTable)
    columns = {str(column.label): index for index, column in enumerate(table.ordered_columns)}
    result = []
    for index in range(table.row_count):
        cells = table.get_row_at(index)
        result.append((
            _plain(cells[columns["Tag"]]).removeprefix("✓ ").removeprefix("· "),
            _plain(cells[columns["Address"]]),
            _plain(cells[columns["Length"]]),
            _plain(cells[columns["Raw"]]),
        ))
    return result


def _picker_visible_shape(panel: CheckEditorPanel | PatchEditorPanel) -> list[tuple[str, str, str]]:
    table = panel.query_one("#check_param_table" if isinstance(panel, CheckEditorPanel) else "#patch_param_table", DataTable)
    result = []
    for index in range(table.row_count):
        cells = table.get_row_at(index)
        result.append(tuple(_plain(cell) for cell in cells[1:4]))
    return result


def _split_visible_text(split: SplitJoinWindow) -> str:
    return _plain(split.query_one("#sje_table").query_one(Static).render())


def _memory_visible_text(memory: MemoryMapPanel) -> str:
    parts = [memory.rendered_text]
    parts.extend(_plain(row.render()) for row in memory.query(".map-region-row"))
    if len(memory.query("#map_detail_body")) > 0:
        parts.append(_plain(memory.query_one("#map_detail_body", Static).render()))
    return "\n".join(parts)


async def _assert_snap(
    app: S19TuiApp,
    pilot,
    *,
    rows: tuple[tuple[str, int, int], ...] | None,
    image: dict[int, int] | None,
    a2l_name: str | None,
    check_pick: bool = True,
    loaded_mac: bool = False,
    memory_names: list[str] | None = None,
) -> None:
    expected = list(rows or ())
    names = [row[0] for row in expected]
    assert [(t["name"], t["address"], t["length"]) for t in app._a2l_enriched_tags] == expected
    assert [t.get("raw_value") for t in app._a2l_enriched_tags] == _expected_values(expected, image)
    summary = _plain(app.query_one("#a2l_view", Static).render())
    if a2l_name is None:
        assert summary == "No A2L loaded."
    else:
        assert app.current_a2l_path is not None
        assert app.current_a2l_path.name == a2l_name
    table = app.query_one("#a2l_tags_list", DataTable)
    assert _table_names(table) == names
    raw_values = _expected_values(expected, image)
    assert _a2l_visible_shape(app) == [
        (name, f"0x{address:08X}", str(size), "" if raw is None else str(raw))
        for (name, address, size), raw in zip(expected, raw_values)
    ]
    assert app.query_one("#a2l_detail_card", A2LDetailCard).render().plain == HINT
    assert app._a2l_tag_hex_highlight is None
    for panel in (
        app.query_one("#check_editor_panel", CheckEditorPanel),
        app.query_one("#patch_editor_panel", PatchEditorPanel),
    ):
        picker = _picker(panel)
        assert list(picker.param_rows) == names
        assert [picker.param_rows[name][0] for name in names] == [row[1] for row in expected]
        assert [picker.param_rows[name][2].split()[0] for name in names] == [f"u{row[2] * 8}" for row in expected]
        visible_rows = _picker_visible_shape(panel)
        assert len(visible_rows) == len(expected)
        for (name, address, size), (visible_name, visible_address, visible_format) in zip(expected, visible_rows):
            assert visible_name == name
            assert visible_address == f"0x{address:08X}"
            assert visible_format.startswith(f"u{size * 8}")
        full_name = panel.query_one("#check_full_name_line" if isinstance(panel, CheckEditorPanel) else "#patch_param_full_name_line", Static)
        if not names:
            assert _plain(full_name.render()) == NO_PICKERS
        else:
            first = expected[0]
            assert _plain(full_name.render()) == f"0x{first[1]:08X}  {picker.param_rows[first[0]][2]}  {first[0]}"
        if check_pick:
            assert picker._signature == app._a2l_enriched_key
    split = app.query_one("#screen_split_join", SplitJoinWindow)
    assert [(r.name, r.base, r.size) for r in split._a2l_rows_cache] == expected
    assert split._sel["a2l"] == set()
    assert split._cursor["a2l"] == 0
    assert split._armed is False
    while split._tab != "a2l":
        split.action_cycle_tab()
    app.action_open_split_join_export()
    await pilot.pause()
    split_text = _split_visible_text(split)
    if not expected:
        assert split_text == "no A2L loaded — load one (^L) or use ranges/manual"
    else:
        visible_rows = [line for line in split_text.splitlines() if line.strip()]
        assert len(visible_rows) == len(expected)
        for name, address, size in expected:
            assert name in split_text
            assert f"0x{address:08X}" in split_text
            assert f"{size} B" in split_text
    memory = app.query_one("#memory_map_panel", MemoryMapPanel)
    expected_memory_names = memory_names if memory_names is not None else (names if image is not None else [])
    assert [t["name"] for t in memory._a2l_tags] == expected_memory_names
    memory_text = _memory_visible_text(memory)
    if image is None:
        assert memory.rendered_text == memory._EMPTY_TEXT
    else:
        assert memory.rendered_text != memory._EMPTY_TEXT
        assert "256 B mapped" in memory_text
        for name in expected_memory_names:
            assert name in memory_text
        assert any(line.strip().startswith("Symbols") and line.rstrip().endswith(str(len(expected_memory_names))) for line in memory_text.splitlines()), memory_text
    stale_names = {row[0] for row in (*OLD, *NEW, *PLAIN)} - set(names)
    for stale in stale_names:
        assert stale not in split_text
        if image is not None:
            assert stale not in memory_text
    loaded = _loaded_text(app)
    if image is None:
        assert loaded[0] == "(none)"
    else:
        assert loaded[0] == f"{app.current_file.path.name}  {len(app.current_file.mem_map)} B · {len(app.current_file.ranges)} rng"
    if loaded_mac:
        assert loaded[1] == f"{app.current_file.mac_path.name}  {len(app.current_file.mac_records)} records"
    else:
        assert loaded[1] == "(none)"
    if a2l_name is None:
        assert loaded[2] == "(none)"
    else:
        assert loaded[2] == f"{a2l_name}  {len(expected)} tags"


def _arm_fanout(app: S19TuiApp, monkeypatch: pytest.MonkeyPatch, events: list[tuple]) -> None:
    ui = threading.get_ident()
    real = getattr(app, "_refresh_a2l_dependent_views", None)

    def fanout() -> None:
        events.append(("F", threading.get_ident(), app.current_a2l_path.name if app.current_a2l_path else None))
        if real is not None:
            real()

    monkeypatch.setattr(app, "_refresh_a2l_dependent_views", fanout, raising=False)
    real_end = app.end_busy

    def end_busy(kind: str, gen: int, message: str) -> None:
        assert message.startswith(("Loaded ", "A2L loaded", "Unloaded "))
        events.append(("OUTCOME", threading.get_ident(), message))
        real_end(kind, gen, message)

    monkeypatch.setattr(app, "end_busy", end_busy)
    events.append(("UI", ui, None))


async def _submit_load_path(app: S19TuiApp, pilot, value: str, *, project: bool = False, action: bool = False) -> None:
    if project:
        if action:
            app.action_load_project()
        else:
            await pilot.press("p")
    else:
        await pilot.press("ctrl+l")
    await wait_until(pilot, lambda: len(app.screen.query("#load_path")) > 0, "Load dialog did not open")
    if project:
        rows = app.screen._rows
        index = next(
            index for index, (_section, _label, choice) in enumerate(rows)
            if choice is not None and choice.kind == "project" and choice.value == value
        )
        assert await pilot.click("#load_list"), "click missed #load_list"
        app.screen.query_one("#load_list").highlighted = index
        await pilot.press("enter")
    else:
        assert await pilot.click("#load_path"), "click missed #load_path"
        await pilot.press("ctrl+a", "delete")
        await pilot.press(*value)
        assert await pilot.click("#load_ok"), "click missed #load_ok"
    await pilot.pause()


async def _request_a2l(app: S19TuiApp, pilot, path: Path) -> None:
    await _submit_load_path(app, pilot, str(path))


async def _load_a2l(app: S19TuiApp, pilot, path: Path) -> None:
    await _request_a2l(app, pilot, path)
    await settle_workers(pilot)
    assert app.current_a2l_path == path, list(app.log_lines)


async def _load_image(app: S19TuiApp, pilot, path: Path) -> None:
    await _submit_load_path(app, pilot, str(path))
    if isinstance(app.screen, ConfirmQuestionScreen):
        await pilot.press("y")
    await settle_workers(pilot)
    assert app.current_file is not None and app.current_file.mem_map, list(app.log_lines)


async def _load_project(app: S19TuiApp, pilot, name: str, *, action: bool = False) -> None:
    await _submit_load_path(app, pilot, name, project=True, action=action)
    if isinstance(app.screen, ConfirmQuestionScreen):
        await pilot.press("y")
    await settle_workers(pilot)
    assert app.current_project == name, list(app.log_lines)
    if len(app.screen.query("#result_ok")) > 0:
        await pilot.press("escape")
        await wait_until(pilot, lambda: len(app.screen.query("#result_ok")) == 0, "Load result did not close")


def _unload(app: S19TuiApp, kind: str) -> None:
    panel = app.query_one("#loaded_panel", LoadedArtifactsPanel)
    next(button for button in panel.query(Button) if button.name == kind).press()


def _mount_views(app: S19TuiApp, visible: str = "a2l") -> None:
    app.action_show_screen("check_editor")
    app.action_show_screen("patch")
    app.action_show_screen("map")
    app.action_open_split_join_export()
    app.action_show_screen(visible)


def _run(tmp_path: Path, scenario) -> None:
    fixture = Fixture.build(tmp_path)

    async def drive():
        app = S19TuiApp(base_dir=fixture.base)
        real_a2l_route = app.load_a2l_from_path

        def in_place_a2l_route(path: Path, *, copy: bool = False) -> None:
            real_a2l_route(path, copy=copy)

        app.load_a2l_from_path = in_place_a2l_route
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            _mount_views(app)
            await pilot.pause()
            await scenario(app, pilot, fixture)

    asyncio.run(drive())


@pytest.mark.parametrize("case", [f"R-A2L-REFRESH.001/{i}" for i in range(1, 4)], ids=lambda x: x)
def test_r001_direct_attach_publication(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str) -> None:
    async def scenario(app, pilot, f):
        await _load_image(app, pilot, f.img1)
        if case.endswith("/2"):
            await _load_a2l(app, pilot, f.old)
        elif case.endswith("/3"):
            await _load_a2l(app, pilot, f.old)
            _unload(app, "a2l")
            await pilot.pause()
            assert app.current_a2l_path is None
        events = []
        _arm_fanout(app, monkeypatch, events)
        ui_calls = _arm_thread_spies(app, monkeypatch)
        await _load_a2l(app, pilot, f.old if case.endswith("/1") else f.new)
        await pilot.pause()
        assert [e[0] for e in events if e[0] != "UI"] == ["F", "OUTCOME"]
        assert events[0][1] == events[1][1] == events[2][1]
        assert all(thread == events[0][1] for _, thread in ui_calls)
        await _assert_snap(app, pilot, rows=OLD if case.endswith("/1") else NEW, image=IMG1, a2l_name="old.a2l" if case.endswith("/1") else "new.a2l")

    _run(tmp_path, scenario)


@pytest.mark.parametrize("case", [f"R-A2L-REFRESH.002/{i}" for i in range(1, 4)], ids=lambda x: x)
def test_r002_image_load_refreshes_pair(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str) -> None:
    async def scenario(app, pilot, f):
        source = f.img1
        if case.endswith("/3"):
            source = f.src / "image.s19"
            source.write_bytes(f.img1.read_bytes())
        if not case.endswith("/1"):
            await _load_image(app, pilot, source)
        await _load_a2l(app, pilot, f.old)
        events = []
        _arm_fanout(app, monkeypatch, events)
        if case.endswith("/3"):
            source.write_bytes(f.img2.read_bytes())
        await _load_image(app, pilot, source if case.endswith("/3") else f.img2)
        assert [e[0] for e in events if e[0] != "UI"] == ["F", "OUTCOME"]
        await _assert_snap(app, pilot, rows=OLD, image=IMG2, a2l_name="old.a2l")
        if case.endswith("/3"):
            assert app.current_file.path.name in {"image.s19", "image_1.s19"}

    _run(tmp_path, scenario)


@pytest.mark.parametrize("case", [f"R-A2L-REFRESH.003/{i}" for i in range(1, 3)], ids=lambda x: x)
def test_r003_project_final_pair(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str) -> None:
    async def scenario(app, pilot, f):
        _project(f, "P_OLD", image=f.img1, a2l=f.old, mac=True)
        _project(f, "P_NEW", image=f.img2, a2l=f.new, mac=True)
        if case.endswith("/2"):
            await _load_project(app, pilot, "P_OLD")
        events = []
        _arm_fanout(app, monkeypatch, events)
        await _load_project(app, pilot, "P_NEW")
        assert [e[0] for e in events if e[0] != "UI"] == ["F", "OUTCOME"]
        await _assert_snap(app, pilot, rows=NEW, image=IMG2, a2l_name="new.a2l", loaded_mac=True)

    _run(tmp_path, scenario)


@pytest.mark.parametrize("case", [f"R-A2L-REFRESH.004/{i}" for i in range(1, 3)], ids=lambda x: x)
def test_r004_a2l_only_project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str) -> None:
    async def scenario(app, pilot, f):
        _project(f, "P_ONLY", image=None, a2l=f.new)
        if case.endswith("/2"):
            await _load_image(app, pilot, f.img1)
            await _load_a2l(app, pilot, f.old)
        events = []
        _arm_fanout(app, monkeypatch, events)
        await _load_project(app, pilot, "P_ONLY")
        assert [event[0] for event in events if event[0] != "UI"] == ["F", "OUTCOME"]
        assert app.current_file is None
        await _assert_snap(app, pilot, rows=NEW, image=None, a2l_name="new.a2l")

    _run(tmp_path, scenario)


@pytest.mark.parametrize("case", [f"R-A2L-REFRESH.005/{i}" for i in range(1, 6)], ids=lambda x: x)
def test_r005_unload_publication(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str) -> None:
    async def scenario(app, pilot, f):
        kind = ("primary", "mac", "a2l", "all", "a2l")[int(case.rsplit("/", 1)[1]) - 1]
        if case.endswith("/5"):
            _project(f, "P_ONLY", image=None, a2l=f.new)
            await _load_project(app, pilot, "P_ONLY")
        else:
            await _load_image(app, pilot, f.img1)
            await _load_image(app, pilot, f.mac)
            await _load_a2l(app, pilot, f.old)
        events = []
        _arm_fanout(app, monkeypatch, events)
        timeline = []

        def artifacts():
            current = app.current_file
            return (
                None if current is None else dict(current.mem_map),
                None if current is None or current.mac_path is None else current.mac_path.name,
                None if app.current_a2l_path is None else app.current_a2l_path.name,
            )

        real_empty = app._apply_empty_state

        def clear_event() -> None:
            timeline.append(("CLEAR", artifacts()))
            real_empty()

        monkeypatch.setattr(app, "_apply_empty_state", clear_event)
        real_fanout = app._refresh_a2l_dependent_views

        def fanout_event() -> None:
            timeline.append(("F", artifacts()))
            real_fanout()

        monkeypatch.setattr(app, "_refresh_a2l_dependent_views", fanout_event)
        real_status = app.set_status

        def status_event(message: str) -> None:
            timeline.append(("UNLOADED", message))
            real_status(message)

        monkeypatch.setattr(app, "set_status", status_event)
        _unload(app, kind)
        await pilot.pause()
        await pilot.pause()
        assert [e[0] for e in events if e[0] != "UI"] == ["F"]
        unload_label = {"primary": "primary image", "mac": "MAC", "a2l": "A2L", "all": "all artifacts"}[kind]
        assert [event[0] for event in timeline] == ["CLEAR", "F", "UNLOADED"]
        assert timeline[0][1] == timeline[1][1] == artifacts()
        assert timeline[-1][1] == f"Unloaded {unload_label}."
        if kind == "primary":
            await _assert_snap(app, pilot, rows=OLD, image=None, a2l_name="old.a2l", loaded_mac=True, memory_names=[row[0] for row in OLD])
        elif kind == "mac":
            await _assert_snap(app, pilot, rows=OLD, image=IMG1, a2l_name="old.a2l")
        elif kind == "a2l" and not case.endswith("/5"):
            await _assert_snap(app, pilot, rows=None, image=IMG1, a2l_name=None, loaded_mac=True)
        else:
            await _assert_snap(app, pilot, rows=None, image=None, a2l_name=None)

    _run(tmp_path, scenario)


@pytest.mark.parametrize("case", [f"R-A2L-REFRESH.006/{i}" for i in range(1, 7)], ids=lambda x: x)
def test_r006_viewer_values(tmp_path: Path, case: str) -> None:
    async def scenario(app, pilot, f):
        rows = OLD
        image = IMG1
        name = "old.a2l"
        if case.endswith("/4"):
            _project(f, "P_OLD", image=f.img1, a2l=f.old, mac=True)
            _project(f, "P_NEW", image=f.img2, a2l=f.new, mac=True)
            await _load_project(app, pilot, "P_OLD")
            await _load_project(app, pilot, "P_NEW")
            rows, image, name = NEW, IMG2, "new.a2l"
        elif case.endswith("/5"):
            _project(f, "P_ONLY", image=None, a2l=f.new)
            await _load_project(app, pilot, "P_ONLY")
            rows, image, name = NEW, None, "new.a2l"
        else:
            if not case.endswith("/1"):
                await _load_image(app, pilot, f.img1)
                await _load_a2l(app, pilot, f.old)
            else:
                await _load_image(app, pilot, f.img1)
            if case.endswith("/1"):
                await _load_a2l(app, pilot, f.old)
            elif case.endswith("/2"):
                await _load_a2l(app, pilot, f.new)
                rows, name = NEW, "new.a2l"
            elif case.endswith("/3"):
                await _load_image(app, pilot, f.img2)
                image = IMG2
            elif case.endswith("/6"):
                _unload(app, "a2l")
                await pilot.pause()
                rows, name = (), None
        await _assert_snap(app, pilot, rows=rows, image=image, a2l_name=name, check_pick=False, loaded_mac=case.endswith("/4"))

    _run(tmp_path, scenario)


@pytest.mark.parametrize(
    ("case", "route", "field", "text"),
    [
        ("R-A2L-REFRESH.007/1", "attach", "name", "  Alpha  "),
        ("R-A2L-REFRESH.007/2", "image", "name", "  Alpha  "),
        ("R-A2L-REFRESH.007/3", "project", "name", "  Alpha  "),
        ("R-A2L-REFRESH.007/4", "only", "name", "  Alpha  "),
        ("R-A2L-REFRESH.007/5", "unload", "name", "  Alpha  "),
        ("R-A2L-REFRESH.007/6", "plain", "name", "  Alpha  "),
        ("R-A2L-REFRESH.008/1", "attach", "name", "  Alpha  "),
        ("R-A2L-REFRESH.008/2", "image", "name", "  Alpha  "),
        ("R-A2L-REFRESH.008/3", "project", "name", "  Alpha  "),
        ("R-A2L-REFRESH.008/4", "only", "name", "  Alpha  "),
        ("R-A2L-REFRESH.008/5", "unload", "name", "  Alpha  "),
        ("R-A2L-REFRESH.008/6", "replace", "address", "  32  "),
        ("R-A2L-REFRESH.008/7", "image", "address", "  32  "),
    ],
    ids=lambda x: x if isinstance(x, str) and x.startswith("R-") else "",
)
def test_r007_r008_filters(tmp_path: Path, case: str, route: str, field: str, text: str) -> None:
    async def scenario(app, pilot, f):
        _project(f, "P_OLD", image=f.img1, a2l=f.old, mac=True)
        _project(f, "P_NEW", image=f.img2, a2l=f.new, mac=True)
        _project(f, "P_ONLY", image=None, a2l=f.new)
        if route == "project":
            await _load_project(app, pilot, "P_OLD")
        elif route not in {"attach"}:
            await _load_image(app, pilot, f.img1)
            await _load_a2l(app, pilot, f.old)
        else:
            await _load_image(app, pilot, f.img1)
        app._set_a2l_filter_field(field)
        app.query_one("#a2l_tags_filter_input", Input).value = text
        await pilot.pause(0.15)
        if route == "attach":
            await _load_a2l(app, pilot, f.old)
        elif route == "replace":
            await _load_a2l(app, pilot, f.new)
        elif route == "plain":
            await _load_a2l(app, pilot, f.plain)
        elif route == "image":
            await _load_image(app, pilot, f.img2)
        elif route == "project":
            await _load_project(app, pilot, "P_NEW")
        elif route == "only":
            await _load_project(app, pilot, "P_ONLY")
        else:
            _unload(app, "a2l")
            await pilot.pause()
        assert app.query_one("#a2l_tags_filter_input", Input).value == text
        assert app.a2l_tags_filter_field == field
        assert str(app.query_one("#a2l_filter_field", Button).label) == f"Field: {field}"
        names = _table_names(app.query_one("#a2l_tags_list", DataTable))
        if route == "unload":
            assert names == []
            assert _plain(app.query_one("#a2l_view", Static).render()) == "No A2L loaded."
        elif route == "plain":
            assert names == []
            assert _plain(app.query_one("#a2l_tags_summary", Label).render()) == "No A2L tags match 'Alpha'."
        else:
            assert names == ["AlphaShared"]
            expected = 0x6562 if route in {"image", "project"} else (0x6461 if route != "only" else None)
            assert app._a2l_filtered_tags[0]["raw_value"] == expected

    _run(tmp_path, scenario)


@pytest.mark.parametrize(
    ("case", "route", "mode"),
    [
        (f"R-A2L-REFRESH.009/{i}", route, mode)
        for i, (route, mode) in enumerate(
            (("replace", "inmem"), ("replace", "invalid"), ("image", "inmem"), ("image", "invalid"), ("unload", "inmem"), ("unload", "invalid"), ("project", "inmem"), ("same", "invalid")), 1
        )
    ],
    ids=lambda x: x if isinstance(x, str) and x.startswith("R-") else "",
)
def test_r009_mode_reset(tmp_path: Path, case: str, route: str, mode: str) -> None:
    async def scenario(app, pilot, f):
        _project(f, "P_OLD", image=f.img1, a2l=f.mode1, mac=True)
        _project(f, "P_NEW", image=f.img2, a2l=f.mode2, mac=True)
        a2l = f.mode1
        if route == "project":
            await _load_project(app, pilot, "P_OLD")
        else:
            await _load_image(app, pilot, f.img1)
            if route == "same":
                a2l = f.src / "same.a2l"
                a2l.write_bytes(f.mode1.read_bytes())
            await _load_a2l(app, pilot, a2l)
        app.a2l_tags_filter_mode = mode
        app._set_a2l_filter_field("name")
        app.query_one("#a2l_tags_filter_input", Input).value = "  Alpha  "
        app.query_one(f"#a2l_filter_{mode}", Button).variant = "primary"
        app.query_one("#a2l_filter_all", Button).variant = "default"
        app._refresh_a2l_filtered_tags(preserve_anchor=False)
        await pilot.pause()
        assert [t["name"] for t in app._a2l_filtered_tags] == (["AlphaIn"] if mode == "inmem" else ["AlphaOutside", "AlphaInvalid"])
        if route == "replace":
            await _load_a2l(app, pilot, f.mode2)
        elif route == "image":
            await _load_image(app, pilot, f.img2)
        elif route == "unload":
            _unload(app, "a2l")
            await pilot.pause()
        elif route == "project":
            await _load_project(app, pilot, "P_NEW")
        else:
            a2l.write_bytes(f.mode2.read_bytes())
            await _load_a2l(app, pilot, a2l)
        assert app.a2l_tags_filter_mode == "all"
        assert app.query_one("#a2l_filter_all", Button).variant == "primary"
        assert app.query_one("#a2l_filter_inmem", Button).variant == "default"
        assert app.query_one("#a2l_filter_invalid", Button).variant == "default"
        assert app.query_one("#a2l_tags_filter_input", Input).value == "  Alpha  "
        assert app.a2l_tags_filter_field == "name"
        expected_names = [] if route == "unload" else [row[0] for row in MODE]
        assert [t["name"] for t in app._a2l_filtered_tags] == expected_names
        assert _table_names(app.query_one("#a2l_tags_list", DataTable)) == expected_names

    _run(tmp_path, scenario)


@pytest.mark.parametrize("case", [f"R-A2L-REFRESH.014/{i}" for i in range(1, 3)], ids=lambda x: x)
def test_r014_same_path(tmp_path: Path, case: str) -> None:
    async def scenario(app, pilot, f):
        same = f.src / "same.a2l"
        same.write_bytes(f.old.read_bytes())
        await _load_image(app, pilot, f.img1)
        await _load_a2l(app, pilot, same)
        same.write_bytes(f.new.read_bytes())
        if case.endswith("/2"):
            _project(f, "Proj1", image=None, a2l=same, mac=True)
            await _load_image(app, pilot, f.mac)
            app.current_project = "Proj One"
            app.current_project_dir = f.base / ".s19tool" / "workarea" / "Proj1"
            project_hashes = _project_digests(app.current_project_dir)
        old_generation = app._a2l_view_generation
        image_generation = app._image_generation
        await _load_a2l(app, pilot, same)
        if case.endswith("/2"):
            assert isinstance(app.screen, ConfirmQuestionScreen)
            await pilot.press("y")
            await settle_workers(pilot)
            assert _project_digests(app.current_project_dir) == project_hashes
        assert app._a2l_view_generation > old_generation
        assert app._image_generation == image_generation
        await _assert_snap(app, pilot, rows=NEW, image=IMG1, a2l_name="same.a2l", loaded_mac=case.endswith("/2"))

    _run(tmp_path, scenario)


@pytest.mark.parametrize("case", [f"R-A2L-REFRESH.015/{i}" for i in range(1, 4)], ids=lambda x: x)
def test_r015_memory_map(tmp_path: Path, case: str) -> None:
    async def scenario(app, pilot, f):
        await _load_image(app, pilot, f.img1)
        baseline = app.query_one("#memory_map_panel", MemoryMapPanel).rendered_text
        if not case.endswith("/1"):
            await _load_a2l(app, pilot, f.old)
        if case.endswith("/1"):
            await _load_a2l(app, pilot, f.old)
            rows = OLD
        elif case.endswith("/2"):
            await _load_a2l(app, pilot, f.new)
            rows = NEW
        else:
            _unload(app, "a2l")
            await pilot.pause()
            rows = ()
        memory = app.query_one("#memory_map_panel", MemoryMapPanel)
        assert [t["name"] for t in memory._a2l_tags] == [row[0] for row in rows]
        assert len(memory._a2l_tags) == len(rows)
        assert memory.rendered_text != memory._EMPTY_TEXT
        memory_text = _memory_visible_text(memory)
        assert "256 B mapped" in memory_text
        assert memory._ordered_ranges == [(0, 256, True)]
        assert "Region" in memory_text and "0x00000000" in memory_text
        for name in [row[0] for row in rows]:
            assert name in memory_text
        if rows:
            assert any(line.strip().startswith("Symbols") and line.rstrip().endswith("4") for line in memory_text.splitlines()), memory_text
        else:
            assert memory.rendered_text == baseline
            assert any(line.strip().startswith("Symbols") and line.rstrip().endswith("0") for line in memory_text.splitlines()), memory_text
            assert "OLD_ONLY" not in memory_text

    _run(tmp_path, scenario)


@pytest.mark.parametrize("case", [f"R-A2L-REFRESH.016/{i}" for i in range(1, 4)], ids=lambda x: x)
def test_r016_split_join(tmp_path: Path, case: str) -> None:
    async def scenario(app, pilot, f):
        path = f.old
        if case.endswith("/2"):
            path = f.src / "same.a2l"
            path.write_bytes(f.old.read_bytes())
        await _load_image(app, pilot, f.img1)
        await _load_a2l(app, pilot, path)
        app.action_open_split_join_export()
        split = app.query_one("#screen_split_join", SplitJoinWindow)
        split._tab = "a2l"
        split._sel["a2l"] = {0}
        split._cursor["a2l"] = 0
        split._armed = True
        split.query_one("#sje_manual", TextArea).text = "manual: keep [x]"
        split._sync()
        await pilot.pause()
        assert len(split._a2l_rows_cache) == 4
        if case.endswith("/1"):
            await _load_a2l(app, pilot, f.new)
        elif case.endswith("/2"):
            path.write_bytes(f.new.read_bytes())
            await _load_a2l(app, pilot, path)
        else:
            _unload(app, "a2l")
            await pilot.pause()
        assert split._sel["a2l"] == set()
        assert split._cursor["a2l"] == 0
        assert split._armed is False
        assert split.query_one("#sje_manual", TextArea).text == "manual: keep [x]"
        expected = () if case.endswith("/3") else NEW
        assert [(r.name, r.base, r.size) for r in split._a2l_rows_cache] == list(expected)
        split_text = _split_visible_text(split)
        if not expected:
            assert split_text == "no A2L loaded — load one (^L) or use ranges/manual"
        for name, address, size in expected:
            assert name in split_text
            assert f"0x{address:08X}" in split_text
            assert f"{size} B" in split_text
        assert "OLD_ONLY" not in split_text

    _run(tmp_path, scenario)


@pytest.mark.parametrize("case", [f"R-A2L-REFRESH.017/{i}" for i in range(1, 5)], ids=lambda x: x)
def test_r017_loaded_panel(tmp_path: Path, case: str) -> None:
    async def scenario(app, pilot, f):
        if case.endswith("/4"):
            _project(f, "P_ONLY", image=None, a2l=f.new)
        await _load_image(app, pilot, f.img1)
        await _load_image(app, pilot, f.mac)
        if not case.endswith("/1"):
            await _load_a2l(app, pilot, f.old)
        if case.endswith("/1"):
            await _load_a2l(app, pilot, f.old)
        elif case.endswith("/2"):
            await _load_a2l(app, pilot, f.new)
        elif case.endswith("/3"):
            _unload(app, "a2l")
            await pilot.pause()
        else:
            await _load_project(app, pilot, "P_ONLY")
        slots = _loaded_text(app)
        if case.endswith("/4"):
            assert slots == ["(none)", "(none)", "new.a2l  4 tags"]
            assert app.current_file is None
        else:
            assert slots[0] == "img1.s19  256 B · 1 rng"
            assert slots[1] == "records.mac  104 records"
            assert slots[2] == "(none)" if case.endswith("/3") else slots[2] == ("new.a2l  4 tags" if case.endswith("/2") else "old.a2l  4 tags")

    _run(tmp_path, scenario)


@pytest.mark.parametrize("case", [f"R-A2L-REFRESH.027/{i}" for i in range(1, 5)], ids=lambda x: x)
def test_r027_generations(tmp_path: Path, case: str) -> None:
    async def scenario(app, pilot, f):
        if case.endswith("/3"):
            _project(f, "P_ONLY", image=None, a2l=f.new)
        elif case.endswith("/4"):
            _project(f, "P_ONLY", image=None, a2l=f.new)
            await _load_image(app, pilot, f.img1)
            await _load_a2l(app, pilot, f.old)
        elif case.endswith("/2"):
            same = f.src / "same.a2l"
            same.write_bytes(f.old.read_bytes())
            await _load_image(app, pilot, f.img1)
            await _load_a2l(app, pilot, same)
        else:
            await _load_image(app, pilot, f.img1)
        before = (app._a2l_view_generation, app._image_generation)
        if case.endswith("/1"):
            await _load_a2l(app, pilot, f.old)
        elif case.endswith("/2"):
            same.write_bytes(f.new.read_bytes())
            await _load_a2l(app, pilot, same)
        else:
            await _load_project(app, pilot, "P_ONLY")
        assert app._a2l_view_generation > before[0]
        assert app._image_generation == before[1]
        assert app._a2l_enriched_key[:2] == (app._a2l_view_generation, app._image_generation)
        expected_rows = OLD if case.endswith("/1") else NEW
        for panel in (app.query_one("#check_editor_panel", CheckEditorPanel), app.query_one("#patch_editor_panel", PatchEditorPanel)):
            picker = _picker(panel)
            assert picker._signature == app._a2l_enriched_key
            _assert_picker_visible(panel, tuple(
                (name, f"0x{address:08X}", f"u{size * 8}")
                for name, address, size in expected_rows
            ))

    _run(tmp_path, scenario)



async def _highlight_first_tag(app: S19TuiApp, pilot) -> None:
    app.action_show_screen("a2l")
    table = app.query_one("#a2l_tags_list", DataTable)
    table.focus()
    table.move_cursor(row=0)
    await pilot.pause()
    table.move_cursor(row=1)
    await pilot.pause()
    table.move_cursor(row=0)
    await pilot.pause()
    assert "OLD_ONLY" in app.query_one("#a2l_detail_card", A2LDetailCard).render().plain


@pytest.mark.parametrize("case", [f"R-A2L-REFRESH.010/{i}" for i in range(1, 7)], ids=lambda x: x)
def test_r010_detail_invalidation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str) -> None:
    async def scenario(app, pilot, f):
        if case.endswith("/3"):
            _project(f, "P_OLD", image=f.img1, a2l=f.old, mac=True)
            _project(f, "P_NEW", image=f.img2, a2l=f.new, mac=True)
            await _load_project(app, pilot, "P_OLD")
        else:
            if case.endswith("/4"):
                _project(f, "P_ONLY", image=None, a2l=f.new)
            await _load_image(app, pilot, f.img1)
            await _load_a2l(app, pilot, f.old)
        await _highlight_first_tag(app, pilot)
        if case.endswith("/6"):
            import importlib

            module = importlib.import_module("s19_app.tui.app")
            real_parse = module.parse_a2l_cached
            started = threading.Event()
            release = threading.Event()

            def gated(*args, **kwargs):
                started.set()
                assert release.wait(20)
                return real_parse(*args, **kwargs)

            monkeypatch.setattr(module, "parse_a2l_cached", gated)
            await _request_a2l(app, pilot, f.new)
            await wait_until(pilot, started.is_set, "A2L worker did not reach its parse gate")
            await pilot.press("d")
            await pilot.pause()
            assert type(app.screen).__name__ == "CurveDescriptionScreen"
            release.set()
            await settle_workers(pilot)
            assert type(app.screen).__name__ != "CurveDescriptionScreen"
        elif case.endswith("/1"):
            await _load_a2l(app, pilot, f.new)
        elif case.endswith("/2"):
            await _load_image(app, pilot, f.img2)
        elif case.endswith("/3"):
            await _load_project(app, pilot, "P_NEW")
        elif case.endswith("/4"):
            await _load_project(app, pilot, "P_ONLY")
        else:
            _unload(app, "a2l")
            await pilot.pause()
        await pilot.pause()
        card = app.query_one("#a2l_detail_card", A2LDetailCard).render().plain
        assert card == HINT
        assert not any(type(screen).__name__ == "CurveDescriptionScreen" for screen in app.screen_stack)

    _run(tmp_path, scenario)


@pytest.mark.parametrize("case", [f"R-A2L-REFRESH.011/{i}" for i in range(1, 6)], ids=lambda x: x)
def test_r011_hex_span_repaint(tmp_path: Path, case: str) -> None:
    async def scenario(app, pilot, f):
        if case.endswith("/3"):
            _project(f, "P_OLD", image=f.img1, a2l=f.old, mac=True)
            _project(f, "P_NEW", image=f.img2, a2l=f.new, mac=True)
            await _load_project(app, pilot, "P_OLD")
        else:
            if case.endswith("/4"):
                _project(f, "P_ONLY", image=None, a2l=f.new)
            await _load_image(app, pilot, f.img1)
            await _load_a2l(app, pilot, f.old)
        await _highlight_first_tag(app, pilot)
        await pilot.press("enter")
        await pilot.pause()
        assert app._a2l_tag_hex_highlight == (0x0010, 1)
        pane = app.query_one("#alt_hex_view", Static)
        before = pane.render()
        from s19_app.render.hexview import FOCUS_HIGHLIGHT_STYLE

        def has_focus_style(text) -> bool:
            return any(all(token in str(span.style) for token in FOCUS_HIGHLIGHT_STYLE.split()) for span in text.spans)

        assert has_focus_style(before)
        first = app._alt_first_visible_address
        if case.endswith("/1"):
            await _load_a2l(app, pilot, f.new)
        elif case.endswith("/2"):
            await _load_image(app, pilot, f.img2)
        elif case.endswith("/3"):
            await _load_project(app, pilot, "P_NEW")
        elif case.endswith("/4"):
            await _load_project(app, pilot, "P_ONLY")
        else:
            _unload(app, "a2l")
            await pilot.pause()
        assert app._a2l_tag_hex_highlight is None
        after = pane.render()
        assert not has_focus_style(after)
        if case.endswith("/4"):
            assert _plain(after) == "No file loaded."
            assert app.current_file is None
        else:
            expected_image = IMG2 if case.endswith("/2") or case.endswith("/3") else IMG1
            assert app.current_file.mem_map == expected_image
            assert app._alt_first_visible_address == first
            for address, value in expected_image.items():
                if address < first + 16:
                    assert f"{value:02X}" in after.plain

    _run(tmp_path, scenario)


def _picker_shape(panel: CheckEditorPanel | PatchEditorPanel) -> tuple:
    picker = _picker(panel)
    return (
        tuple((name, values[0], values[2].split()[0]) for name, values in picker.param_rows.items()),
        picker._signature,
    )


def _assert_picker_visible(panel: CheckEditorPanel | PatchEditorPanel, expected: tuple) -> None:
    visible = _picker_visible_shape(panel)
    assert len(visible) == len(expected)
    for (name, address, fmt), (expected_name, expected_address, expected_fmt) in zip(visible, expected):
        if isinstance(expected_address, int):
            expected_address = f"0x{expected_address:08X}"
        assert (name, address) == (expected_name, expected_address)
        assert fmt.startswith(expected_fmt)


@pytest.mark.parametrize("case", [f"R-A2L-REFRESH.012/{i}" for i in range(1, 5)], ids=lambda x: x)
def test_r012_visible_check_prefill(tmp_path: Path, case: str) -> None:
    async def scenario(app, pilot, f):
        await _load_image(app, pilot, f.img1)
        if not case.endswith("/1"):
            await _load_a2l(app, pilot, f.old)
        app.action_show_screen("check_editor")
        panel = app.query_one("#check_editor_panel", CheckEditorPanel)
        panel.load_spec([{"address": 0xF0, "size": 1, "expected": (0xAA,)}], "SPEC_KEEP.chk.json")
        app._change_service._last_check_message = "HIST_KEEP"
        await pilot.pause()
        before_spec = (panel._spec_bytes.copy(), list(panel._memory_rows))
        before_key = _picker(panel)._signature
        if case.endswith("/1"):
            await _load_a2l(app, pilot, f.old)
            rows = OLD
        elif case.endswith("/2"):
            await _load_a2l(app, pilot, f.new)
            rows = NEW
        elif case.endswith("/3"):
            await _load_image(app, pilot, f.img2)
            rows = OLD
        else:
            _unload(app, "a2l")
            await pilot.pause()
            rows = ()
        assert app._active_screen_key == "check_editor"
        expected = tuple((name, address, f"u{size * 8}") for name, address, size in rows)
        assert _picker_shape(panel)[0] == expected
        _assert_picker_visible(panel, expected)
        assert _picker(panel)._signature == app._a2l_enriched_key
        if case.endswith("/3"):
            assert _picker(panel)._signature != before_key
        if not rows:
            assert _plain(panel.query_one("#check_full_name_line", Static).render()) == NO_PICKERS
        assert (panel._spec_bytes, panel._memory_rows) == before_spec
        assert app._change_service._last_check_message == "HIST_KEEP"

    _run(tmp_path, scenario)


@pytest.mark.parametrize("case", [f"R-A2L-REFRESH.013/{i}" for i in range(1, 5)], ids=lambda x: x)
def test_r013_visible_patch_prefill(tmp_path: Path, case: str) -> None:
    async def scenario(app, pilot, f):
        await _load_image(app, pilot, f.img1)
        if not case.endswith("/1"):
            await _load_a2l(app, pilot, f.old)
        app.action_show_screen("patch")
        panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
        app._change_service.add_entry("0x00F0", "", "AA")
        app._change_service.add_entry("0x00F1", "", "BB")
        app._change_service.undo()
        panel.mark_pasted()
        await pilot.pause()
        document = app._change_service.document
        before = (
            document,
            panel.is_dirty,
            len(app._change_service._undo_stack),
            len(app._change_service._redo_stack),
        )
        before_key = _picker(panel)._signature
        if case.endswith("/1"):
            await _load_a2l(app, pilot, f.old)
            rows = OLD
        elif case.endswith("/2"):
            await _load_a2l(app, pilot, f.new)
            rows = NEW
        elif case.endswith("/3"):
            await _load_image(app, pilot, f.img2)
            rows = OLD
        else:
            _unload(app, "a2l")
            await pilot.pause()
            rows = ()
        assert app._active_screen_key == "patch"
        expected = tuple((name, address, f"u{size * 8}") for name, address, size in rows)
        assert _picker_shape(panel)[0] == expected
        _assert_picker_visible(panel, expected)
        assert _picker(panel)._signature == app._a2l_enriched_key
        if case.endswith("/3"):
            assert _picker(panel)._signature != before_key
        if not rows:
            assert _plain(panel.query_one("#patch_param_full_name_line", Static).render()) == NO_PICKERS
        after = (
            app._change_service.document,
            panel.is_dirty,
            len(app._change_service._undo_stack),
            len(app._change_service._redo_stack),
        )
        assert after == before

    _run(tmp_path, scenario)


def _mac_page_two(app: S19TuiApp) -> list[tuple[str, ...]]:
    table = app.query_one("#mac_records_list", DataTable)
    return [tuple(_plain(cell) for cell in table.get_row_at(index)) for index in range(table.row_count)]


@pytest.mark.parametrize("case", [f"R-A2L-REFRESH.018/{i}" for i in range(1, 3)], ids=lambda x: x)
def test_r018_mac_page_two(tmp_path: Path, case: str) -> None:
    async def scenario(app, pilot, f):
        await _load_image(app, pilot, f.img1)
        await _load_image(app, pilot, f.mac)
        await _load_a2l(app, pilot, f.old)
        app._mac_window_start = 100
        app.action_show_screen("mac")
        app.update_mac_view()
        await pilot.pause()
        records = list(app.current_file.mac_records)
        assert app._mac_window_start == 100
        before = _mac_page_two(app)
        assert [row[0].removeprefix("✓ ").removeprefix("· ") for row in before[-4:]] == ["OLD_ONLY", "NEW_ONLY", "NEW_ERROR", "NO_MATCH"]
        if case.endswith("/1"):
            await _load_a2l(app, pilot, f.new)
            statuses = ["NOT_IN_A2L", "OK", "A2L_ADDR_MISMATCH", "NOT_IN_A2L"]
            matches = ["", "CHARACTERISTIC:NEW_ONLY", "CHARACTERISTIC:NEW_ERROR", ""]
            in_a2l = ["no", "yes", "yes", "no"]
            count = 2
        else:
            _unload(app, "a2l")
            await pilot.pause()
            statuses = ["NO_A2L"] * 4
            matches = [""] * 4
            in_a2l = ["no"] * 4
            count = 0
        assert app.current_file.mac_records == records
        assert app._mac_window_start == 100
        rows = _mac_page_two(app)[-4:]
        assert [row[4] for row in rows] == statuses
        assert [row[7] for row in rows] == matches
        assert [row[2] for row in rows] == in_a2l
        summary = _plain(app.query_one("#mac_records_summary", Label).render())
        assert "Page 2/2" in summary
        assert f"NameInA2L={count}" in summary

    _run(tmp_path, scenario)


def _issues(app: S19TuiApp) -> list[tuple[str, str, str]]:
    return [(row.issue.symbol or "", row.issue.code, row.issue.severity.value) for row in app.query(IssueRow)]


@pytest.mark.parametrize("case", [f"R-A2L-REFRESH.019/{i}" for i in range(1, 4)], ids=lambda x: x)
def test_r019_issues_refresh(tmp_path: Path, case: str) -> None:
    async def scenario(app, pilot, f):
        await _load_image(app, pilot, f.img1)
        await _load_image(app, pilot, f.mac)
        await _load_a2l(app, pilot, f.old)
        severity = "warning" if case.endswith("/2") else "error"
        app.validation_issue_filter_mode = severity
        app.action_show_screen("issues")
        app.update_validation_issues_view()
        await pilot.pause()
        if case.endswith("/3"):
            _unload(app, "a2l")
            await pilot.pause()
            assert _issues(app) == [("", "MAC_PARSE_ERROR", "error")]
        else:
            await _load_a2l(app, pilot, f.new)
            if case.endswith("/1"):
                assert set(_issues(app)) == {
                    ("new_error", "TRIPLE_NAME_ADDRESS_MISMATCH", "error"),
                    ("", "MAC_PARSE_ERROR", "error"),
                }
            else:
                fresh = {
                    (issue.symbol or "", issue.code, issue.severity.value)
                    for issue in app._validation_issues
                    if issue.severity.value == "warning"
                }
                filtered = app._filtered_validation_issues()
                start = app._validation_issues_window_start
                visible = filtered[start:start + app._issues_page_size()]
                assert set(_issues(app)) == {
                    (issue.symbol or "", issue.code, issue.severity.value)
                    for issue in visible
                }
                assert {
                    ("old_only", "CROSS_MAC_ONLY_SYMBOL", "warning"),
                    ("no_match", "CROSS_MAC_ONLY_SYMBOL", "warning"),
                } <= fresh
                assert all(code != "NOT_IN_A2L" for _, code, _ in fresh)
                assert all(symbol not in {"new_only", "new_error"} for symbol, _, _ in fresh)
        assert app.validation_issue_filter_mode == severity

    _run(tmp_path, scenario)



def _status_recorder(app: S19TuiApp, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    messages: list[str] = []
    real = app.set_status

    def record(message: str) -> None:
        messages.append(str(message))
        real(message)

    monkeypatch.setattr(app, "set_status", record)
    return messages


def _assert_visible_log(app: S19TuiApp, expected: str) -> None:
    lines = [_plain(app.query_one(f"#log_line_{index}", Label).render()) for index in range(1, 5)]
    assert expected in lines, (expected, lines)


def _worker_spy(app: S19TuiApp, monkeypatch: pytest.MonkeyPatch) -> list:
    calls = []
    real = app._a2l_attach_worker

    def worker(request) -> None:
        calls.append(request)
        real(request)

    monkeypatch.setattr(app, "_a2l_attach_worker", worker)
    return calls


def _modal_text(app: S19TuiApp) -> tuple[str, str, str, str]:
    screen = app.screen
    return (
        _plain(screen.query_one("#confirm_title", Label).render()),
        _plain(screen.query_one("#confirm_body", Static).render()),
        _plain(screen.query_one("#confirm_yes", Button).label),
        _plain(screen.query_one("#confirm_no", Button).label),
    )


async def _open_replacement(app: S19TuiApp, pilot, f: Fixture, candidate: Path | None = None) -> Path:
    _project(f, "P_OLD", image=None, a2l=f.old)
    await _load_project(app, pilot, "P_OLD")
    app.current_project = "Proj One"
    path = candidate or f.new
    await _request_a2l(app, pilot, path)
    await pilot.pause()
    assert isinstance(app.screen, ConfirmQuestionScreen), list(app.log_lines)
    return app.current_project_dir / app.current_a2l_path.name


def _project_digests(folder: Path) -> dict[str, str]:
    return {
        str(path.relative_to(folder)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in folder.rglob("*")
        if path.is_file()
    }


def _state_snapshot(app: S19TuiApp) -> tuple:
    import copy

    check = app.query_one("#check_editor_panel", CheckEditorPanel)
    patch = app.query_one("#patch_editor_panel", PatchEditorPanel)
    memory = app.query_one("#memory_map_panel", MemoryMapPanel)
    split = app.query_one("#screen_split_join", SplitJoinWindow)
    workers = tuple(sorted(
        (id(worker), worker.name, worker.group, worker.is_running, worker.is_cancelled)
        for worker in app.workers
    ))
    return (
        app.current_project,
        app.current_project_dir,
        app.current_a2l_path,
        copy.deepcopy(app.current_a2l_data),
        copy.deepcopy(app.current_file),
        app._a2l_view_generation,
        app._image_generation,
        copy.deepcopy(app._a2l_enriched_tags),
        app._mac_window_start,
        copy.deepcopy(app._mac_view_cache_summary),
        app.validation_issue_filter_mode,
        copy.deepcopy(app._validation_report),
        copy.deepcopy(app._validation_issues),
        _table_names(app.query_one("#a2l_tags_list", DataTable)),
        _a2l_visible_shape(app),
        _loaded_text(app),
        _project_digests(app.current_project_dir) if app.current_project_dir else {},
        _picker_visible_shape(check),
        _picker_visible_shape(patch),
        _picker(check)._signature,
        _picker(patch)._signature,
        copy.deepcopy(memory._a2l_tags),
        memory.rendered_text,
        _memory_visible_text(memory),
        copy.deepcopy(split._a2l_rows_cache),
        copy.deepcopy(split._sel),
        copy.deepcopy(split._cursor),
        split._armed,
        split._tab,
        split.query_one("#sje_manual", TextArea).text,
        _split_visible_text(split),
        patch.is_dirty,
        copy.deepcopy(app._change_service.document),
        copy.deepcopy(app._change_service._undo_stack),
        copy.deepcopy(app._change_service._redo_stack),
        app._change_service._last_check_message,
        copy.deepcopy(getattr(app, "_last_flow_run", None)),
        copy.deepcopy(getattr(app, "_diff_last_result", None)),
        workers,
    )


@pytest.mark.parametrize("case", [f"R-A2L-REFRESH.020/{i}" for i in range(1, 3)], ids=lambda x: x)
def test_r020_replacement_question(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str) -> None:
    async def scenario(app, pilot, f):
        workers = _worker_spy(app, monkeypatch)
        source = f.old if case.endswith("/1") else f.src / "same.a2l"
        if case.endswith("/2"):
            source.write_bytes(f.old.read_bytes())
        _project(f, "P_OLD", image=None, a2l=source)
        await _load_project(app, pilot, "P_OLD")
        app.current_project = "Proj One"
        listed = app.current_a2l_path
        candidate_path = f.new if case.endswith("/1") else listed
        candidate = candidate_path.name
        if case.endswith("/2"):
            listed.write_bytes(f.new.read_bytes())
        before = _state_snapshot(app)
        await _request_a2l(app, pilot, candidate_path)
        await pilot.pause()
        assert isinstance(app.screen, ConfirmQuestionScreen)
        assert _modal_text(app) == (
            "Replace project A2L?",
            f"Project 'Proj One' already has A2L '{listed.name}'. Load '{candidate}' instead?",
            "Yes (y)",
            "No (n)",
        )
        assert workers == []
        assert _state_snapshot(app) == before
        assert len([screen for screen in app.screen_stack if isinstance(screen, ConfirmQuestionScreen)]) == 1

    _run(tmp_path, scenario)


@pytest.mark.parametrize(
    ("case", "answer"),
    [("R-A2L-REFRESH.021/1", "button"), ("R-A2L-REFRESH.021/2", "n"), ("R-A2L-REFRESH.021/3", "escape")],
    ids=lambda x: x if isinstance(x, str) and x.startswith("R-") else "",
)
def test_r021_cancel_is_inert(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str, answer: str) -> None:
    async def scenario(app, pilot, f):
        workers = _worker_spy(app, monkeypatch)
        await _open_replacement(app, pilot, f)
        unrelated = app.run_worker(asyncio.sleep(30), group="unrelated")
        before = _state_snapshot(app)
        hashes = _project_digests(app.current_project_dir)
        statuses = _status_recorder(app, monkeypatch)
        if answer == "button":
            app.screen.query_one("#confirm_no", Button).press()
        else:
            await pilot.press(answer)
        await pilot.pause()
        await pilot.pause()
        assert not isinstance(app.screen, ConfirmQuestionScreen)
        assert _state_snapshot(app) == before
        assert _project_digests(app.current_project_dir) == hashes
        assert workers == []
        assert unrelated.is_running
        assert statuses == []
        unrelated.cancel()
        await wait_until(pilot, lambda: not unrelated.is_running, "unrelated worker did not stop")

    _run(tmp_path, scenario)


@pytest.mark.parametrize("case", [f"R-A2L-REFRESH.022/{i}" for i in range(1, 4)], ids=lambda x: x)
def test_r022_confirmation_identity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str) -> None:
    async def scenario(app, pilot, f):
        workers = _worker_spy(app, monkeypatch)
        statuses = _status_recorder(app, monkeypatch)
        await _open_replacement(app, pilot, f)
        if case.endswith("/2"):
            listed = app.current_project_dir / "old.a2l"
            listed.rename(app.current_project_dir / "other.a2l")
            before = _state_snapshot(app)
        elif case.endswith("/3"):
            _project(f, "P_NEW", image=f.img2, a2l=f.new, mac=True)
            await _load_project(app, pilot, "P_NEW", action=True)
            before = _state_snapshot(app)
        await pilot.press("y")
        await settle_workers(pilot)
        if case.endswith("/1"):
            assert len(workers) == 1
            assert app.current_a2l_path == f.new
            await _assert_snap(app, pilot, rows=NEW, image=None, a2l_name="new.a2l")
        else:
            assert workers == []
            assert _state_snapshot(app) == before
            assert statuses[-1] == "A2L NOT loaded: project or its A2L changed — load again."
            _assert_visible_log(app, statuses[-1])
            assert "A2L loaded" not in statuses[-1]

    _run(tmp_path, scenario)


@pytest.mark.parametrize("case", [f"R-A2L-REFRESH.023/{i}" for i in range(1, 3)], ids=lambda x: x)
def test_r023_accepted_replacement(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str) -> None:
    async def scenario(app, pilot, f):
        workers = _worker_spy(app, monkeypatch)
        if case.endswith("/1"):
            _project(f, "P_OLD", image=f.img1, a2l=f.old, mac=True)
            await _load_project(app, pilot, "P_OLD")
            app.current_project = "Proj One"
            candidate = f.new
        else:
            same = f.src / "same.a2l"
            same.write_bytes(f.old.read_bytes())
            _project(f, "P_OLD", image=f.img1, a2l=same, mac=True)
            await _load_project(app, pilot, "P_OLD")
            app.current_project = "Proj One"
            candidate = app.current_a2l_path
            candidate.write_bytes(f.new.read_bytes())
        project_hashes = _project_digests(app.current_project_dir)
        events = []
        _arm_fanout(app, monkeypatch, events)
        if case.endswith("/2"):
            real_attached = app._on_a2l_attached

            def disappear_before_install(result) -> None:
                assert result.request.sync_project is False
                candidate.unlink()
                real_attached(result)

            monkeypatch.setattr(app, "_on_a2l_attached", disappear_before_install)
        await _request_a2l(app, pilot, candidate)
        await pilot.pause()
        assert isinstance(app.screen, ConfirmQuestionScreen)
        await pilot.press("y")
        await settle_workers(pilot)
        assert len(workers) == 1
        assert workers[0].sync_project is False
        assert [event[0] for event in events if event[0] != "UI"] == ["F", "OUTCOME"]
        await _assert_snap(app, pilot, rows=NEW, image=IMG1, a2l_name=candidate.name, loaded_mac=True)
        expected_hashes = dict(project_hashes)
        if case.endswith("/2"):
            assert not candidate.exists()
            del expected_hashes[candidate.name]
        assert _project_digests(app.current_project_dir) == expected_hashes

    _run(tmp_path, scenario)


async def _start_busy_action(app: S19TuiApp, pilot, f: Fixture, monkeypatch: pytest.MonkeyPatch, case: str) -> threading.Event:
    """Setup auxiliary: start a real session worker and hold its actual work step."""
    started = threading.Event()
    release = threading.Event()
    if case.endswith("/1"):
        real = app._parse_loaded_file

        def gated(*args, **kwargs):
            started.set()
            assert release.wait(20)
            return real(*args, **kwargs)

        monkeypatch.setattr(app, "_parse_loaded_file", gated)
        gen = app._busy_begin_action("file_load", "image.bin")
        app._start_load_worker(f.img1, gen=gen)
    elif case.endswith("/2"):
        import importlib

        module = importlib.import_module("s19_app.tui.app")
        real = module.parse_a2l_cached

        def gated(*args, **kwargs):
            started.set()
            assert release.wait(20)
            return real(*args, **kwargs)

        monkeypatch.setattr(module, "parse_a2l_cached", gated)
        await _request_a2l(app, pilot, f.old)
    elif case.endswith("/3"):
        _project(f, "project_b", image=f.img1, a2l=f.old)
        real = app._prepare_project_load

        def gated(*args, **kwargs):
            started.set()
            assert release.wait(20)
            return real(*args, **kwargs)

        monkeypatch.setattr(app, "_prepare_project_load", gated)
        await _submit_load_path(app, pilot, "project_b", project=True, action=True)
    else:
        from s19_app.tui.screens import SaveProjectPayload

        if app.current_file is None and app.current_a2l_path is None:
            await _load_a2l(app, pilot, f.old)
        real = app._save_project_files

        def gated(*args, **kwargs):
            started.set()
            assert release.wait(20)
            return real(*args, **kwargs)

        monkeypatch.setattr(app, "_save_project_files", gated)
        app._handle_save_dialog(SaveProjectPayload(parent_folder=str(app.workarea), project_name="project_b"))
    await wait_until(pilot, started.is_set, "the real session worker did not start")
    return release


@pytest.mark.parametrize("case", [f"R-A2L-REFRESH.024/{i}" for i in range(1, 5)], ids=lambda x: x)
def test_r024_initial_busy_refusal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str) -> None:
    async def scenario(app, pilot, f):
        release = await _start_busy_action(app, pilot, f, monkeypatch, case)
        workers = _worker_spy(app, monkeypatch)
        statuses = _status_recorder(app, monkeypatch)
        before = _state_snapshot(app)
        progress_before = str(app.query_one("#status_text").render())
        worker_count = len(app.workers)
        starts = []
        real_start = app._start_a2l_load

        def start_spy(*args, **kwargs):
            starts.append((args, kwargs))
            return real_start(*args, **kwargs)

        monkeypatch.setattr(app, "_start_a2l_load", start_spy)
        await pilot.press("ctrl+l")
        await pilot.pause()
        labels = ("Loading image.bin", "Loading old.a2l", "Loading project project_b", "Saving project project_b")
        label = labels[int(case.rsplit("/", 1)[1]) - 1]
        assert statuses == [f"busy: {label} is running — wait for it to finish."]
        _assert_visible_log(app, statuses[0])
        assert str(app.query_one("#status_text").render())[1:] == progress_before[1:]
        assert starts == []
        assert workers == []
        assert len(app.workers) == worker_count
        assert not isinstance(app.screen, ConfirmQuestionScreen)
        assert _state_snapshot(app) == before
        release.set()
        await settle_workers(pilot)

    _run(tmp_path, scenario)


@pytest.mark.parametrize("case", [f"R-A2L-REFRESH.025/{i}" for i in range(1, 3)], ids=lambda x: x)
def test_r025_post_yes_busy_boundaries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str) -> None:
    async def scenario(app, pilot, f):
        workers = _worker_spy(app, monkeypatch)
        statuses = _status_recorder(app, monkeypatch)
        await _open_replacement(app, pilot, f)
        before = _state_snapshot(app)
        if case.endswith("/1"):
            real_call = app.call_after_refresh
            held = []

            def hold(callback, *args, **kwargs):
                held.append((callback, args, kwargs))

            monkeypatch.setattr(app, "call_after_refresh", hold)
            await pilot.press("y")
            await pilot.pause()
            assert held
            monkeypatch.setattr(app, "call_after_refresh", real_call)
            release = await _start_busy_action(app, pilot, f, monkeypatch, "R-A2L-REFRESH.024/1")
            for callback, args, kwargs in held:
                real_call(callback, *args, **kwargs)
            await pilot.pause()
            expected = "busy: Loading image.bin is running — wait for it to finish."
        else:
            real_start = getattr(app, "_start_a2l_load", None)
            held = []

            def hold(*args, **kwargs):
                held.append((args, kwargs))

            monkeypatch.setattr(app, "_start_a2l_load", hold, raising=False)
            await pilot.press("y")
            await wait_until(pilot, lambda: bool(held), "N3 was not reached")
            release = await _start_busy_action(app, pilot, f, monkeypatch, "R-A2L-REFRESH.024/4")
            assert real_start is not None
            for args, kwargs in held:
                real_start(*args, **kwargs)
            await pilot.pause()
            expected = "busy: Saving project project_b is running — wait for it to finish."
        assert expected in statuses
        _assert_visible_log(app, expected)
        assert workers == []
        after = _state_snapshot(app)
        assert after[:-1] == before[:-1]
        assert after[-1] != before[-1]
        assert app._running_session_action() is not None
        release.set()
        await settle_workers(pilot)

    _run(tmp_path, scenario)


def _arm_thread_spies(app: S19TuiApp, monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, int]]:
    calls: list[tuple[str, int]] = []
    for name in (
        "update_a2l_view",
        "update_alt_hex_view",
        "_prefill_check_editor",
        "_prefill_patch_editor",
        "update_memory_map",
        "_refresh_loaded_panel",
        "update_mac_view",
        "update_validation_issues_view",
    ):
        real = getattr(app, name)

        def wrapper(*args, __real=real, __name=name, **kwargs):
            calls.append((__name, threading.get_ident()))
            return __real(*args, **kwargs)

        monkeypatch.setattr(app, name, wrapper)
    split = app.query_one("#screen_split_join", SplitJoinWindow)
    real = getattr(split, "invalidate_a2l_selection", None)

    def invalidate() -> None:
        calls.append(("invalidate_a2l_selection", threading.get_ident()))
        if real is not None:
            real()

    monkeypatch.setattr(split, "invalidate_a2l_selection", invalidate, raising=False)
    for panel in (
        app.query_one("#check_editor_panel", CheckEditorPanel),
        app.query_one("#patch_editor_panel", PatchEditorPanel),
    ):
        picker = _picker(panel)
        real_set = picker.set_parameters

        def set_parameters(*args, __real=real_set, **kwargs):
            calls.append(("picker.set_parameters", threading.get_ident()))
            return __real(*args, **kwargs)

        monkeypatch.setattr(picker, "set_parameters", set_parameters)
    memory = app.query_one("#memory_map_panel", MemoryMapPanel)
    real_ranges = memory.render_ranges

    def render_ranges(*args, **kwargs):
        calls.append(("MemoryMap.render_ranges", threading.get_ident()))
        return real_ranges(*args, **kwargs)

    monkeypatch.setattr(memory, "render_ranges", render_ranges)
    real_refresh = split.refresh_window

    def refresh_window() -> None:
        calls.append(("Split.refresh_window", threading.get_ident()))
        real_refresh()

    monkeypatch.setattr(split, "refresh_window", refresh_window)
    return calls


@pytest.mark.parametrize("case", [f"R-A2L-REFRESH.026/{i}" for i in range(1, 4)], ids=lambda x: x)
def test_r026_all_painting_on_ui(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str) -> None:
    async def scenario(app, pilot, f):
        ui = threading.get_ident()
        if case.endswith("/2"):
            await _load_a2l(app, pilot, f.old)
        elif case.endswith("/3"):
            _project(f, "P_OLD", image=f.img1, a2l=f.old, mac=True)
            _project(f, "P_NEW", image=f.img2, a2l=f.new, mac=True)
            await _load_project(app, pilot, "P_OLD")
        else:
            await _load_image(app, pilot, f.img1)
        calls = _arm_thread_spies(app, monkeypatch)
        events = []
        _arm_fanout(app, monkeypatch, events)
        if case.endswith("/1"):
            await _load_a2l(app, pilot, f.old)
            rows, image, name, mac = OLD, IMG1, "old.a2l", False
        elif case.endswith("/2"):
            await _load_image(app, pilot, f.img2)
            rows, image, name, mac = OLD, IMG2, "old.a2l", False
        else:
            await _load_project(app, pilot, "P_NEW")
            rows, image, name, mac = NEW, IMG2, "new.a2l", True
        assert calls
        assert all(thread == ui for _, thread in calls)
        assert {"invalidate_a2l_selection", "picker.set_parameters", "MemoryMap.render_ranges", "Split.refresh_window"} <= {name for name, _ in calls}
        assert [event[0] for event in events if event[0] != "UI"] == ["F", "OUTCOME"]
        await _assert_snap(app, pilot, rows=rows, image=image, a2l_name=name, loaded_mac=mac)

    _run(tmp_path, scenario)


@pytest.mark.parametrize("case", [f"R-A2L-REFRESH.028/{i}" for i in range(1, 3)], ids=lambda x: x)
def test_r028_superseded_prepared_load(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str) -> None:
    async def scenario(app, pilot, f):
        await _load_image(app, pilot, f.img1)
        await _load_image(app, pilot, f.mac)
        await _load_a2l(app, pilot, f.old)
        started = threading.Event()
        release = threading.Event()
        dispatched = []
        real_call_from_thread = app.call_from_thread

        def gated_dispatch(callback, *args, **kwargs):
            if getattr(callback, "__name__", "") == "_complete_prepared_load" and not dispatched:
                dispatched.append((callback, args, kwargs))
                started.set()
                assert release.wait(20)
            return real_call_from_thread(callback, *args, **kwargs)

        monkeypatch.setattr(app, "call_from_thread", gated_dispatch)
        await _submit_load_path(app, pilot, str(f.img2))
        await wait_until(pilot, started.is_set, "real worker did not reach N5 dispatch")
        assert len(dispatched) == 1
        prepared = dispatched[0][1][0]
        assert prepared.a2l_enriched_key is not None
        assert any(tag["name"] == "OLD_ONLY" for tag in prepared.a2l_enriched_tags)
        if case.endswith("/1"):
            prepared.a2l_view_generation -= 1
            expected_rows = OLD
            expected_name = "old.a2l"
        else:
            prepared.a2l_image_generation -= 1
            expected_rows = OLD
            expected_name = "old.a2l"
        await pilot.pause()
        before = _state_snapshot(app)
        current_file = app.current_file
        current_data = app.current_a2l_data
        enriched_key = app._a2l_enriched_key
        statuses = _status_recorder(app, monkeypatch)
        sync_calls = []
        real_sync = app._sync_loaded_file_to_project

        def sync() -> None:
            sync_calls.append(threading.get_ident())
            real_sync()

        monkeypatch.setattr(app, "_sync_loaded_file_to_project", sync)
        widget_calls = _arm_thread_spies(app, monkeypatch)
        release.set()
        await settle_workers(pilot)
        after = _state_snapshot(app)
        assert after[:-1] == before[:-1]
        assert after[-1] != before[-1]
        assert app.current_file is current_file
        assert app.current_a2l_data is current_data
        assert app._a2l_enriched_key == enriched_key
        assert app.current_a2l_path.name == expected_name
        assert [tag["name"] for tag in app._a2l_enriched_tags] == [row[0] for row in expected_rows]
        assert sync_calls == []
        assert widget_calls == []
        assert statuses[-1] == "Load superseded — current state kept."
        _assert_visible_log(app, statuses[-1])
        assert not any(message.startswith("Loaded ") for message in statuses)
        assert "file_load" not in app._busy.runs

    _run(tmp_path, scenario)
