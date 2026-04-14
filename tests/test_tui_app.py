from pathlib import Path

import pytest

from s19_app.tui.app import S19TuiApp, _mac_record_ui_state
from s19_app.tui.models import LoadedFile
from s19_app.tui.screens import SaveProjectPayload
from s19_app.tui.workspace import WORKAREA_TEMP


def test_default_tag_and_mac_page_sizes(tmp_path: Path):
    app = S19TuiApp(base_dir=tmp_path)
    assert app.a2l_tags_page_size == 200
    assert app.mac_records_page_size == 200


def test_mac_record_ui_state_a2l_verification_buckets():
    idx = {"rpm": [{"name": "RPM", "address": 0x1000, "section": "MEASUREMENT"}]}
    assert _mac_record_ui_state(
        {"parse_ok": True, "name": "RPM", "address": 0x1000}, idx, True, False, None
    ) == ("OK", "ok")
    assert _mac_record_ui_state(
        {"parse_ok": True, "name": "RPM", "address": 0x2000}, idx, True, False, None
    )[1] == "error"
    assert _mac_record_ui_state(
        {"parse_ok": True, "name": "MISSING", "address": 0x1000}, idx, True, False, None
    ) == ("NOT_IN_A2L", "warning")
    assert _mac_record_ui_state(
        {"parse_ok": True, "name": "RPM", "address": 0x1000}, idx, False, False, None
    )[1] == "neutral"
    assert _mac_record_ui_state(
        {"parse_ok": False, "name": "RPM", "address": 0x1000}, idx, True, False, None
    )[1] == "error"


def test_save_project_writes_under_chosen_parent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    ensure = tmp_path / ".s19tool" / "workarea"
    ensure.mkdir(parents=True)
    src = tmp_path / "data.mac"
    src.write_text("A=0x10\n", encoding="utf-8")
    parent = tmp_path / "dest"
    parent.mkdir()
    app = S19TuiApp(base_dir=tmp_path)
    app.workarea = ensure
    monkeypatch.setattr(app, "set_status", lambda _m: None)
    monkeypatch.setattr(app, "update_project_labels", lambda: None)
    monkeypatch.setattr(app, "refresh_files", lambda: None)
    app.current_file = LoadedFile(
        path=src,
        file_type="mac",
        mem_map={16: 0},
        row_bases=[0],
        ranges=[],
        range_validity=[],
        errors=[],
        a2l_path=None,
        a2l_data=None,
        mac_records=[],
    )
    app.current_a2l_path = None
    app._handle_save_dialog(SaveProjectPayload(parent_folder=str(parent), project_name="P1"))
    assert (parent / "P1" / "data.mac").exists()
    assert app.current_project == "P1"
    assert app.current_project_dir == (parent / "P1").resolve()


def test_active_project_dir_prefers_explicit_path(tmp_path: Path):
    app = S19TuiApp(base_dir=tmp_path)
    app.workarea = tmp_path / "wa"
    app.workarea.mkdir()
    app.current_project = "Alpha"
    app.current_project_dir = None
    assert app._active_project_dir() == (app.workarea / "Alpha").resolve()
    external = (tmp_path / "ext" / "Beta").resolve()
    app.current_project_dir = external
    assert app._active_project_dir() == external


def test_mac_records_page_next_prev(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    app = S19TuiApp(base_dir=tmp_path)
    recs = [
        {"parse_ok": True, "name": f"T{i}", "address": 0x1000 + i, "line_number": i + 1}
        for i in range(250)
    ]
    app.current_file = LoadedFile(
        path=tmp_path / "x.mac",
        file_type="mac",
        mem_map={},
        row_bases=[],
        ranges=[],
        range_validity=[],
        errors=[],
        a2l_path=None,
        a2l_data=None,
        mac_records=recs,
    )
    app.mac_records_page_size = 100
    monkeypatch.setattr(app, "update_mac_view", lambda: None)
    app._mac_window_start = 0
    app.action_mac_records_page_next()
    assert app._mac_window_start == 100
    app.action_mac_records_page_next()
    assert app._mac_window_start == 200
    app.action_mac_records_page_next()
    assert app._mac_window_start == 200
    app.action_mac_records_page_prev()
    assert app._mac_window_start == 100


def test_load_selected_file_attaches_mac_to_loaded_binary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    app = S19TuiApp(base_dir=tmp_path)
    app.current_file = LoadedFile(
        path=tmp_path / "base.s19",
        file_type="s19",
        mem_map={0x1000: 0x11},
        row_bases=[0x1000],
        ranges=[(0x1000, 0x1001)],
        range_validity=[True],
        errors=[],
        a2l_path=None,
        a2l_data=None,
    )

    mac_loaded = LoadedFile(
        path=tmp_path / "tags.mac",
        file_type="mac",
        mem_map={0x2000: 0},
        row_bases=[0x2000],
        ranges=[],
        range_validity=[],
        errors=[],
        a2l_path=None,
        a2l_data=None,
        mac_path=tmp_path / "tags.mac",
        mac_records=[{"parse_ok": True, "name": "RPM", "address": 0x2000}],
        mac_diagnostics=[],
    )

    monkeypatch.setattr(app, "_load_mac_file", lambda path, a2l_files=None: mac_loaded)
    monkeypatch.setattr(app, "update_sections", lambda: None)
    monkeypatch.setattr(app, "update_hex_view", lambda focus_address=None: None)
    monkeypatch.setattr(app, "update_alt_hex_view", lambda focus_address=None: None)
    monkeypatch.setattr(app, "update_mac_hex_view", lambda focus_address=None: None)
    monkeypatch.setattr(app, "update_mac_view", lambda: None)
    monkeypatch.setattr(app, "update_a2l_view", lambda: None)
    monkeypatch.setattr(app, "update_project_labels", lambda: None)
    monkeypatch.setattr(app, "set_file_status", lambda _: None)
    monkeypatch.setattr(app, "_append_log_line", lambda _: None)

    app.load_selected_file(tmp_path / "tags.mac")

    assert app.current_file is not None
    assert app.current_file.file_type == "s19"
    assert app.current_file.mem_map == {0x1000: 0x11}
    assert app.current_file.mac_path == (tmp_path / "tags.mac")
    assert len(app.current_file.mac_records) == 1


def test_collect_mac_out_of_range_addresses_uses_ranges(tmp_path: Path):
    app = S19TuiApp(base_dir=tmp_path)
    loaded = LoadedFile(
        path=tmp_path / "base.s19",
        file_type="s19",
        mem_map={0x1000: 0x11},
        row_bases=[0x1000],
        ranges=[(0x1000, 0x1010)],
        range_validity=[True],
        errors=[],
        a2l_path=None,
        a2l_data=None,
        mac_records=[
            {"parse_ok": True, "address": 0x1005},
            {"parse_ok": True, "address": 0x2200},
            {"parse_ok": False, "address": 0x3300},
        ],
    )

    out_of_range = app._collect_mac_out_of_range_addresses(loaded)

    assert out_of_range == {0x2200}


def test_list_projects_skips_files_and_sorts_names(tmp_path: Path):
    workarea = tmp_path / "workarea"
    workarea.mkdir()
    (workarea / "Zulu").mkdir()
    (workarea / "Alpha").mkdir()
    (workarea / WORKAREA_TEMP).mkdir()
    (workarea / "notes.txt").write_text("ignore me", encoding="utf-8")
    app = S19TuiApp(base_dir=tmp_path)
    app.workarea = workarea

    assert app.list_projects() == ["Alpha", "Zulu"]


def test_filter_a2l_tags_supports_in_memory_and_boolean_fields(tmp_path: Path):
    app = S19TuiApp(base_dir=tmp_path)
    tags = [
        {"name": "RPM", "in_memory": True, "virtual": False, "source": "assigned"},
        {"name": "TORQUE", "in_memory": False, "virtual": True, "source": "formula"},
    ]

    app.a2l_tags_filter_mode = "inmem"
    app.a2l_tags_filter_field = "all"
    app.a2l_tags_filter_text = ""
    assert [tag["name"] for tag in app._filter_a2l_tags(tags)] == ["RPM"]

    app.a2l_tags_filter_mode = "all"
    app.a2l_tags_filter_field = "virtual"
    app.a2l_tags_filter_text = "yes"
    assert [tag["name"] for tag in app._filter_a2l_tags(tags)] == ["TORQUE"]


def test_a2l_cache_reuses_parse_for_unchanged_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    app = S19TuiApp(base_dir=tmp_path)
    a2l_path = tmp_path / "sample.a2l"
    a2l_path.write_text("/begin PROJECT Demo\n/end PROJECT\n", encoding="utf-8")
    calls = {"count": 0}

    def fake_parse(path: Path) -> dict:
        calls["count"] += 1
        return {"path": str(path), "sections": [], "errors": [], "tags": []}

    monkeypatch.setattr("s19_app.tui.app.parse_a2l_file", fake_parse)

    first = app._load_a2l_data_with_cache(a2l_path)
    second = app._load_a2l_data_with_cache(a2l_path)

    assert calls["count"] == 1
    assert first == second


def test_window_bounds_and_shift_logic(tmp_path: Path):
    app = S19TuiApp(base_dir=tmp_path)
    start, end = app._get_window_bounds(total=1000, start=950, window_size=200)
    assert (start, end) == (950, 1000)

    app.a2l_window_overscan = 20
    shifted = app._shift_window_for_index(total=1000, index=399, start=200, window_size=200)
    assert shifted > 200


def test_refresh_a2l_filtered_tags_resets_anchor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    app = S19TuiApp(base_dir=tmp_path)
    app._a2l_enriched_tags = [
        {"name": "RPM", "schema_ok": True, "memory_checked": False},
        {"name": "TORQUE", "schema_ok": False, "memory_checked": False},
    ]
    app.a2l_tags_filter_mode = "invalid"
    app._a2l_window_start = 150
    captured: dict[str, int] = {}

    def fake_update(tags: list[dict]) -> None:
        captured["count"] = len(tags)

    monkeypatch.setattr(app, "update_a2l_tags_view", fake_update)
    app._refresh_a2l_filtered_tags(preserve_anchor=False)

    assert app._a2l_window_start == 0
    assert captured["count"] == 1


def test_a2l_clamp_page_start_aligns_and_clamps(tmp_path: Path):
    app = S19TuiApp(base_dir=tmp_path)
    app.a2l_tags_page_size = 10
    app._a2l_window_start = 15
    assert app._a2l_clamp_page_start(25) == 10
    app._a2l_window_start = 0
    assert app._a2l_clamp_page_start(25) == 0
    app._a2l_window_start = 200
    assert app._a2l_clamp_page_start(25) == 20


def test_a2l_tags_page_next_prev_and_focus_snap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    app = S19TuiApp(base_dir=tmp_path)
    app.a2l_tags_page_size = 10
    app._a2l_filtered_tags = [{"name": f"T{i}", "address": 0x1000 + i, "length": 4} for i in range(25)]

    monkeypatch.setattr(app, "update_a2l_tags_view", lambda tags: None)

    app._a2l_window_start = 0
    app.action_a2l_tags_page_next()
    assert app._a2l_window_start == 10
    app.action_a2l_tags_page_next()
    assert app._a2l_window_start == 20
    app.action_a2l_tags_page_next()
    assert app._a2l_window_start == 20
    app.action_a2l_tags_page_prev()
    assert app._a2l_window_start == 10

    class _FakeListView:
        def __init__(self) -> None:
            self.index = -1

    fake_lv = _FakeListView()

    def _fake_query_one(selector: str, *args: object, **kwargs: object) -> object:
        if selector == "#a2l_tags_list":
            return fake_lv
        raise AssertionError(selector)

    monkeypatch.setattr(app, "query_one", _fake_query_one)
    assert app._focus_a2l_tag_absolute_index(17) is True
    assert app._a2l_window_start == 10
    assert fake_lv.index == 2 + (17 - 10)
    assert app._focus_a2l_tag_absolute_index(5) is True
    assert app._a2l_window_start == 0
    assert fake_lv.index == 2 + 5


def test_a2l_tag_find_haystack_keeps_zero_numeric_values(tmp_path: Path):
    app = S19TuiApp(base_dir=tmp_path)
    tag = {
        "name": "RPM",
        "address": 0,
        "length": 0,
        "source": "assigned",
        "lower_limit": 0,
        "upper_limit": 100,
        "unit": "rpm",
        "bit_org": 0,
        "endian": "little",
        "virtual": False,
        "function_group": "FG",
        "access": "rw",
        "datatype": "UWORD",
        "description": "desc",
        "memory_region": "region",
        "memory_checked": True,
        "in_memory": True,
    }

    haystack = app._a2l_tag_find_haystack(tag)
    assert " 0 " in f" {haystack} "
