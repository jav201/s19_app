from pathlib import Path

import pytest

from s19_app.tui.app import (
    S19TuiApp,
    _a2l_tag_row_severity,
    _a2l_tag_unit_display,
    _mac_record_ui_state,
    _severity_style,
    precompute_issue_datatable_payload,
    precompute_mac_datatable_payload,
)
from s19_app.tui.models import LoadedFile
from s19_app.tui.screens import SaveProjectPayload
from s19_app.tui.workspace import WORKAREA_TEMP
from s19_app.validation import ValidationIssue, ValidationSeverity


def test_default_tag_and_mac_page_sizes(tmp_path: Path):
    app = S19TuiApp(base_dir=tmp_path)
    assert app.a2l_tags_page_size == 200
    assert app.mac_records_page_size == 100
    assert app.hex_rows_page_size == 200


def test_mac_record_ui_state_a2l_verification_buckets():
    idx = {"rpm": [{"name": "RPM", "address": 0x1000, "section": "MEASUREMENT"}]}
    assert _mac_record_ui_state(
        {"parse_ok": True, "name": "RPM", "address": 0x1000}, idx, True, False, None
    ) == ("OK", "ok")
    assert _mac_record_ui_state(
        {"parse_ok": True, "name": "RPM", "address": 0x2000}, idx, True, False, None
    )[1] == "error"
    assert _mac_record_ui_state(
        {"parse_ok": True, "name": "RPM", "address": 0x2000}, idx, True, True, False
    ) == ("OUT_OF_IMAGE", "info")
    assert _mac_record_ui_state(
        {"parse_ok": True, "name": "MISSING", "address": 0x1000}, idx, True, False, None
    ) == ("NOT_IN_A2L", "warning")
    assert _mac_record_ui_state(
        {"parse_ok": True, "name": "RPM", "address": 0x1000}, idx, False, False, None
    )[1] == "neutral"
    assert _mac_record_ui_state(
        {"parse_ok": False, "name": "RPM", "address": 0x1000}, idx, True, False, None
    )[1] == "error"


def test_a2l_tag_row_severity_matches_updated_policy():
    assert _a2l_tag_row_severity({"schema_ok": False}) == ValidationSeverity.ERROR
    assert _a2l_tag_row_severity({"schema_ok": True, "memory_checked": True, "in_memory": True}) == ValidationSeverity.OK
    assert _a2l_tag_row_severity({"schema_ok": True, "memory_checked": True, "in_memory": False}) == ValidationSeverity.INFO
    assert _a2l_tag_row_severity({"schema_ok": True, "memory_checked": False, "source": "formula"}) == ValidationSeverity.INFO
    assert _a2l_tag_row_severity({"schema_ok": True, "memory_checked": False}) == ValidationSeverity.NEUTRAL


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


def test_context_page_actions_route_by_active_view(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    app = S19TuiApp(base_dir=tmp_path)
    calls = {"a2l_next": 0, "a2l_prev": 0, "mac_next": 0, "mac_prev": 0}
    monkeypatch.setattr(app, "action_a2l_tags_page_next", lambda: calls.__setitem__("a2l_next", calls["a2l_next"] + 1))
    monkeypatch.setattr(app, "action_a2l_tags_page_prev", lambda: calls.__setitem__("a2l_prev", calls["a2l_prev"] + 1))
    monkeypatch.setattr(app, "action_mac_records_page_next", lambda: calls.__setitem__("mac_next", calls["mac_next"] + 1))
    monkeypatch.setattr(app, "action_mac_records_page_prev", lambda: calls.__setitem__("mac_prev", calls["mac_prev"] + 1))
    monkeypatch.setattr(app, "_active_view_name", lambda: "alt")
    app.action_page_next_context()
    app.action_page_prev_context()
    assert calls["a2l_next"] == 1
    assert calls["a2l_prev"] == 1
    monkeypatch.setattr(app, "_active_view_name", lambda: "mac")
    app.action_page_next_context()
    app.action_page_prev_context()
    assert calls["mac_next"] == 1
    assert calls["mac_prev"] == 1


def test_apply_viewer_setting_clamps_to_200(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    app = S19TuiApp(base_dir=tmp_path)
    monkeypatch.setattr(app, "update_hex_view", lambda addr=None: None)
    monkeypatch.setattr(app, "update_alt_hex_view", lambda addr=None: None)
    monkeypatch.setattr(app, "update_mac_hex_view", lambda addr=None: None)
    monkeypatch.setattr(app, "update_a2l_tags_view", lambda tags: None)
    monkeypatch.setattr(app, "update_mac_view", lambda: None)
    monkeypatch.setattr(app, "set_status", lambda _msg: None)
    monkeypatch.setattr(app, "_update_settings_menu", lambda: None)
    app._a2l_filtered_tags = [{"name": "X"}]
    app._apply_viewer_setting("hex_rows_page_size", 999)
    app._apply_viewer_setting("a2l_tags_page_size", 999)
    app._apply_viewer_setting("mac_records_page_size", 999)
    assert app.hex_rows_page_size == 200
    assert app.a2l_tags_page_size == 200
    assert app.mac_records_page_size == 200


def test_hex_page_actions_only_work_in_main_view(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    app = S19TuiApp(base_dir=tmp_path)
    app.current_file = LoadedFile(
        path=tmp_path / "x.s19",
        file_type="s19",
        mem_map={0x1000 + i: i for i in range(16 * 12)},
        row_bases=[0x1000 + (i * 16) for i in range(12)],
        ranges=[],
        range_validity=[],
        errors=[],
        a2l_path=None,
        a2l_data=None,
    )
    app.hex_rows_page_size = 5
    app._hex_window_start = 0
    monkeypatch.setattr(app, "update_hex_view", lambda addr=None: None)
    monkeypatch.setattr(app, "_active_view_name", lambda: "main")
    app.action_hex_page_next()
    assert app._hex_window_start == 5
    app.action_hex_page_prev()
    assert app._hex_window_start == 0
    monkeypatch.setattr(app, "_active_view_name", lambda: "alt")
    app.action_hex_page_next()
    assert app._hex_window_start == 0


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


def test_merge_primary_with_existing_mac_keeps_mac_payload(tmp_path: Path):
    app = S19TuiApp(base_dir=tmp_path)
    app.current_file = LoadedFile(
        path=tmp_path / "old.s19",
        file_type="s19",
        mem_map={0x1000: 0xAA},
        row_bases=[0x1000],
        ranges=[(0x1000, 0x1001)],
        range_validity=[True],
        errors=[],
        a2l_path=None,
        a2l_data=None,
        mac_path=tmp_path / "tags.mac",
        mac_records=[{"parse_ok": True, "name": "RPM", "address": 0x2000}],
        mac_diagnostics=["ok"],
    )
    primary_loaded = LoadedFile(
        path=tmp_path / "new.hex",
        file_type="hex",
        mem_map={0x3000: 0x11},
        row_bases=[0x3000],
        ranges=[(0x3000, 0x3001)],
        range_validity=[True],
        errors=[],
        a2l_path=None,
        a2l_data=None,
    )

    merged = app._merge_primary_with_existing_mac(primary_loaded)

    assert merged.file_type == "hex"
    assert merged.mem_map == {0x3000: 0x11}
    assert merged.mac_path == (tmp_path / "tags.mac")
    assert len(merged.mac_records) == 1
    assert merged.mac_diagnostics == ["ok"]


def test_update_mac_view_reuses_cached_model_between_pages(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    app = S19TuiApp(base_dir=tmp_path)
    app.current_file = LoadedFile(
        path=tmp_path / "base.s19",
        file_type="s19",
        mem_map={0x1000: 0x10},
        row_bases=[0x1000],
        ranges=[(0x1000, 0x1001)],
        range_validity=[True],
        errors=[],
        a2l_path=None,
        a2l_data=None,
        mac_records=[
            {"parse_ok": True, "name": f"T{i}", "address": 0x1000, "line_number": i + 1, "parse_error": ""}
            for i in range(150)
        ],
    )
    app.mac_records_page_size = 50
    calls = {"build": 0}

    class FakeTable:
        columns = ["Tag", "Address"]
        row_count = 0

        def clear(self, columns: bool = True) -> None:
            return

        def add_row(self, *_cells: object, key: object = None) -> None:
            return

    class FakeLabel:
        def update(self, _text: str) -> None:
            return

    fake_table = FakeTable()
    fake_label = FakeLabel()

    def _query(selector: str, *_a, **_k):
        if selector == "#mac_records_list":
            return fake_table
        if selector == "#mac_records_summary":
            return fake_label
        return None

    monkeypatch.setattr(app, "query_one", _query)
    monkeypatch.setattr(app, "update_validation_issues_view", lambda: None)
    original = app._build_mac_view_cache

    def wrapped() -> None:
        calls["build"] += 1
        original()

    monkeypatch.setattr(app, "_build_mac_view_cache", wrapped)

    app.update_mac_view()
    app.action_mac_records_page_next()

    assert calls["build"] == 1


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

    class _FakeDataTable:
        def __init__(self) -> None:
            self.row_count = 50
            self.cursor_row = -1

        def move_cursor(self, *, row: int) -> None:
            self.cursor_row = row

    fake_table = _FakeDataTable()

    def _fake_query_one(selector: str, *args: object, **kwargs: object) -> object:
        if selector == "#a2l_tags_list":
            return fake_table
        raise AssertionError(selector)

    monkeypatch.setattr(app, "query_one", _fake_query_one)
    assert app._focus_a2l_tag_absolute_index(17) is True
    assert app._a2l_window_start == 10
    assert fake_table.cursor_row == 17 - 10
    assert app._focus_a2l_tag_absolute_index(5) is True
    assert app._a2l_window_start == 0
    assert fake_table.cursor_row == 5


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


def test_a2l_tag_unit_display_prefers_explicit_unit_over_compu(tmp_path: Path):
    tag = {"unit": "V", "compu_method_unit": "kOhm"}
    assert _a2l_tag_unit_display(tag) == "V"


def test_a2l_tag_unit_display_falls_back_to_compu_method_unit(tmp_path: Path):
    tag = {"compu_method_unit": "kOhm"}
    assert _a2l_tag_unit_display(tag) == "kOhm"


def test_filter_a2l_tags_supports_raw_and_physical_value_fields(tmp_path: Path):
    app = S19TuiApp(base_dir=tmp_path)
    tags = [
        {"name": "RPM", "raw_value": 10, "physical_value": 25.0},
        {"name": "LOAD", "raw_value": 2, "physical_value": 4.0},
    ]
    app.a2l_tags_filter_mode = "all"
    app.a2l_tags_filter_field = "raw_value"
    app.a2l_tags_filter_text = "10"
    assert [tag["name"] for tag in app._filter_a2l_tags(tags)] == ["RPM"]
    app.a2l_tags_filter_field = "physical_value"
    app.a2l_tags_filter_text = "4.0"
    assert [tag["name"] for tag in app._filter_a2l_tags(tags)] == ["LOAD"]


def test_validation_issue_filtering_and_format(tmp_path: Path):
    app = S19TuiApp(base_dir=tmp_path)
    app._validation_issues = [
        ValidationIssue(
            code="CROSS_X",
            severity=ValidationSeverity.ERROR,
            message="bad",
            artifact="cross",
            symbol="RPM",
            address=0x1000,
        ),
        ValidationIssue(
            code="CROSS_Y",
            severity=ValidationSeverity.WARNING,
            message="warn",
            artifact="cross",
            symbol="LOAD",
        ),
    ]
    app.validation_issue_filter_mode = "error"
    filtered = app._filtered_validation_issues()
    assert len(filtered) == 1
    assert filtered[0].code == "CROSS_X"
    line = app._format_validation_issue_line(filtered[0])
    assert "CROSS_X" in line
    assert "0x00001000" in line


def test_jump_to_validation_issue_prefers_address(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    app = S19TuiApp(base_dir=tmp_path)
    app.current_file = LoadedFile(
        path=tmp_path / "x.s19",
        file_type="s19",
        mem_map={0x1000: 0x01},
        row_bases=[0x1000],
        ranges=[(0x1000, 0x1001)],
        range_validity=[True],
        errors=[],
        a2l_path=None,
        a2l_data=None,
    )
    called: dict[str, int] = {"hex": 0, "alt": 0, "mac": 0}
    monkeypatch.setattr(app, "update_hex_view", lambda addr=None: called.__setitem__("hex", int(addr or 0)))
    monkeypatch.setattr(app, "update_alt_hex_view", lambda addr=None: called.__setitem__("alt", int(addr or 0)))
    monkeypatch.setattr(app, "update_mac_hex_view", lambda addr=None: called.__setitem__("mac", int(addr or 0)))
    monkeypatch.setattr(app, "set_status", lambda _msg: None)

    class FakeItem:
        data = {"code": "ERR", "address": 0x1000}

    app._jump_to_validation_issue(FakeItem())  # type: ignore[arg-type]

    assert called["hex"] == 0x1000
    assert called["alt"] == 0x1000
    assert called["mac"] == 0x1000


def test_parse_loaded_file_mac_after_s19_preserves_both(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
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

    merged = app._parse_loaded_file(tmp_path / "tags.mac")

    assert merged is not None
    assert merged.file_type == "s19"
    assert merged.mem_map == {0x1000: 0x11}
    assert merged.ranges == [(0x1000, 0x1001)]
    assert merged.mac_path == (tmp_path / "tags.mac")
    assert len(merged.mac_records) == 1
    assert merged.mac_records[0]["name"] == "RPM"


def test_parse_loaded_file_primary_after_mac_keeps_mac_payload(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    app = S19TuiApp(base_dir=tmp_path)
    app.current_file = LoadedFile(
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
        mac_diagnostics=["ok"],
    )

    primary_loaded = LoadedFile(
        path=tmp_path / "new.hex",
        file_type="hex",
        mem_map={0x3000: 0x11},
        row_bases=[0x3000],
        ranges=[(0x3000, 0x3001)],
        range_validity=[True],
        errors=[],
        a2l_path=None,
        a2l_data=None,
    )

    monkeypatch.setattr(
        "s19_app.tui.app.IntelHexFile",
        lambda _path: type(
            "FakeHex",
            (),
            {
                "memory": primary_loaded.mem_map,
                "get_ranges": lambda self: primary_loaded.ranges,
                "get_errors": lambda self: [],
            },
        )(),
    )
    monkeypatch.setattr(
        "s19_app.tui.app.build_range_validity_hex",
        lambda _f, _r: primary_loaded.range_validity,
    )

    merged = app._parse_loaded_file(tmp_path / "new.hex")

    assert merged is not None
    assert merged.file_type == "hex"
    assert merged.mem_map == {0x3000: 0x11}
    assert merged.ranges == [(0x3000, 0x3001)]
    assert merged.mac_path == (tmp_path / "tags.mac")
    assert len(merged.mac_records) == 1
    assert merged.mac_diagnostics == ["ok"]


def test_format_coexistence_status_signals_primary_plus_mac(tmp_path: Path):
    app = S19TuiApp(base_dir=tmp_path)
    loaded = LoadedFile(
        path=tmp_path / "base.s19",
        file_type="s19",
        mem_map={},
        row_bases=[],
        ranges=[],
        range_validity=[],
        errors=[],
        a2l_path=None,
        a2l_data=None,
        mac_path=tmp_path / "tags.mac",
        mac_records=[{"parse_ok": True, "name": "RPM", "address": 0x1000}],
    )

    message = app._format_coexistence_status(loaded, tmp_path / "base.s19")
    assert "S19+MAC" in message
    assert "tags.mac" in message


def test_format_coexistence_status_primary_only(tmp_path: Path):
    app = S19TuiApp(base_dir=tmp_path)
    loaded = LoadedFile(
        path=tmp_path / "base.s19",
        file_type="s19",
        mem_map={},
        row_bases=[],
        ranges=[],
        range_validity=[],
        errors=[],
        a2l_path=None,
        a2l_data=None,
    )

    assert app._format_coexistence_status(loaded, tmp_path / "base.s19") == "Loaded base.s19 (S19 only)"


def test_format_coexistence_status_mac_only(tmp_path: Path):
    app = S19TuiApp(base_dir=tmp_path)
    loaded = LoadedFile(
        path=tmp_path / "tags.mac",
        file_type="mac",
        mem_map={},
        row_bases=[],
        ranges=[],
        range_validity=[],
        errors=[],
        a2l_path=None,
        a2l_data=None,
        mac_path=tmp_path / "tags.mac",
        mac_records=[{"parse_ok": True, "name": "RPM", "address": 0x1000}],
    )

    assert app._format_coexistence_status(loaded, tmp_path / "tags.mac") == "Loaded tags.mac (MAC only)"


def test_get_range_index_caches_and_speeds_up_membership(tmp_path: Path):
    app = S19TuiApp(base_dir=tmp_path)
    ranges = [(0x1000, 0x1010), (0x2000, 0x2020), (0x3000, 0x3040)]
    loaded = LoadedFile(
        path=tmp_path / "x.s19",
        file_type="s19",
        mem_map={},
        row_bases=[],
        ranges=ranges,
        range_validity=[True, True, True],
        errors=[],
        a2l_path=None,
        a2l_data=None,
    )

    first = app._get_range_index(loaded)
    second = app._get_range_index(loaded)

    assert first is second
    assert first[0] == [0x1000, 0x2000, 0x3000]
    assert first[1] == [0x1010, 0x2020, 0x3040]


def test_build_mac_view_cache_scales_under_load(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Perf smoke: 5k MAC records over 2k fragmented ranges must finish under a tight budget."""
    app = S19TuiApp(base_dir=tmp_path)
    num_ranges = 2000
    ranges = [(i * 0x100, i * 0x100 + 0x80) for i in range(num_ranges)]
    mac_records = [
        {
            "parse_ok": True,
            "name": f"T{i}",
            "address": i * 0x20,
            "line_number": i + 1,
            "parse_error": "",
        }
        for i in range(5000)
    ]
    app.current_file = LoadedFile(
        path=tmp_path / "big.s19",
        file_type="s19",
        mem_map={},
        row_bases=[],
        ranges=ranges,
        range_validity=[True] * num_ranges,
        errors=[],
        a2l_path=None,
        a2l_data=None,
        mac_records=mac_records,
    )

    import time as _time

    started = _time.perf_counter()
    app._build_mac_view_cache()
    elapsed = _time.perf_counter() - started

    # Binary-search lookups make this O((N + R) log R); on any laptop this should finish
    # well under 2 seconds even without a JIT. Keep the budget generous to avoid flakes.
    assert elapsed < 2.0, f"_build_mac_view_cache too slow: {elapsed:.3f}s"
    assert app._mac_view_cache_rows, "cache should populate rows"


def test_update_validation_issues_view_empty_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    app = S19TuiApp(base_dir=tmp_path)
    summary_text: list[str] = []

    class FakeTable:
        columns = ["Severity"]

        def clear(self, columns: bool = True) -> None:
            return

        def add_row(self, *_cells: object, key: object = None) -> None:
            summary_text.append("row")

    class FakeLabel:
        def update(self, text: str) -> None:
            summary_text.append(text)

    fake_table = FakeTable()
    fake_label = FakeLabel()

    def _query(selector: str, *_a, **_k):
        if selector == "#validation_issues_list":
            return fake_table
        if selector == "#validation_issues_summary":
            return fake_label
        return None

    monkeypatch.setattr(app, "query_one", _query)
    app._validation_issues = []
    app.update_validation_issues_view()
    assert summary_text and summary_text[0] == "No validation issues."


def _make_validation_issues(n: int) -> list[ValidationIssue]:
    """Build ``n`` synthetic validation issues for paging tests."""
    issues: list[ValidationIssue] = []
    for i in range(n):
        severity = ValidationSeverity.ERROR if i % 3 == 0 else ValidationSeverity.WARNING
        issues.append(
            ValidationIssue(
                code=f"CODE_{i}",
                severity=severity,
                message=f"issue {i}",
                artifact="mac",
                symbol=f"sym{i}",
                address=0x1000 + i,
                line_number=i + 1,
            )
        )
    return issues


def test_update_validation_issues_view_pages_large_issue_list(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """With thousands of issues, the panel must render at most one page-sized slice into the DataTable."""
    app = S19TuiApp(base_dir=tmp_path)
    row_keys: list[object] = []
    summary_captured: list[str] = []

    class FakeTable:
        columns = ["Severity"]

        def clear(self, columns: bool = True) -> None:
            row_keys.clear()

        def add_row(self, *_cells: object, key: object = None) -> None:
            row_keys.append(key)

    class FakeLabel:
        def update(self, text: str) -> None:
            summary_captured.append(text)

    fake_table = FakeTable()
    fake_label = FakeLabel()

    def _query(selector: str, *_a, **_k):
        if selector == "#validation_issues_list":
            return fake_table
        if selector == "#validation_issues_summary":
            return fake_label
        return None

    monkeypatch.setattr(app, "query_one", _query)
    total = 5000
    app._validation_issues = _make_validation_issues(total)
    app.validation_issues_page_size = 150
    app._validation_issues_window_start = 0

    app.update_validation_issues_view()

    # One add_row call per visible issue; no summary rows bleed into the table.
    assert len(row_keys) == 150
    assert all(isinstance(key, str) and key.startswith("issue:") for key in row_keys)
    assert summary_captured and "page 1/" in summary_captured[-1]


def test_validation_issues_paging_actions_advance_window(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    app = S19TuiApp(base_dir=tmp_path)
    renders: list[int] = []

    class FakeTable:
        columns = ["Severity"]

        def clear(self, columns: bool = True) -> None:
            return

        def add_row(self, *_cells: object, key: object = None) -> None:
            return

    class FakeLabel:
        def update(self, _text: str) -> None:
            return

    fake_table = FakeTable()
    fake_label = FakeLabel()

    def _query(selector: str, *_a, **_k):
        if selector == "#validation_issues_list":
            return fake_table
        if selector == "#validation_issues_summary":
            return fake_label
        return None

    monkeypatch.setattr(app, "query_one", _query)
    app._validation_issues = _make_validation_issues(450)
    app.validation_issues_page_size = 100
    app._validation_issues_window_start = 0

    original = app.update_validation_issues_view

    def wrapped() -> None:
        renders.append(app._validation_issues_window_start)
        original()

    monkeypatch.setattr(app, "update_validation_issues_view", wrapped)

    app.action_validation_issues_page_next()
    app.action_validation_issues_page_next()
    app.action_validation_issues_page_prev()

    assert renders == [100, 200, 100]
    # Advance past the end should clamp.
    app._validation_issues_window_start = 400
    app.action_validation_issues_page_next()
    assert app._validation_issues_window_start == 400


def test_compute_mac_view_payload_matches_build_cache(tmp_path: Path):
    """``_compute_mac_view_payload`` returns the same rows/summary as ``_build_mac_view_cache``."""
    app = S19TuiApp(base_dir=tmp_path)
    loaded = LoadedFile(
        path=tmp_path / "base.s19",
        file_type="s19",
        mem_map={0x1000 + i: 0x11 for i in range(0x20)},
        row_bases=[0x1000, 0x1010],
        ranges=[(0x1000, 0x1020)],
        range_validity=[True],
        errors=[],
        a2l_path=None,
        a2l_data=None,
        mac_records=[
            {"parse_ok": True, "name": "RPM", "address": 0x1000, "line_number": 1, "parse_error": ""},
            {"parse_ok": True, "name": "TEMP", "address": 0x5000, "line_number": 2, "parse_error": ""},
            {"parse_ok": False, "name": "BAD", "address": None, "line_number": 3, "parse_error": "x"},
        ],
    )

    payload = app._compute_mac_view_payload(loaded, None)

    app.current_file = loaded
    app.current_a2l_data = None
    app._build_mac_view_cache()

    assert payload["rows"] == app._mac_view_cache_rows
    assert payload["meta"] == app._mac_view_cache_meta
    assert payload["summary"] == app._mac_view_cache_summary
    assert payload["coverage_line"] == app._mac_view_cache_coverage_line
    assert len(payload["issues"]) == len(app._validation_issues)


def test_prepare_load_payload_fills_bases_highlights_and_cache_key(tmp_path: Path):
    app = S19TuiApp(base_dir=tmp_path)
    loaded = LoadedFile(
        path=tmp_path / "base.s19",
        file_type="s19",
        mem_map={0x1000 + i: 0x11 for i in range(0x20)},
        row_bases=[0x1000, 0x1010],
        ranges=[(0x1000, 0x1020)],
        range_validity=[True],
        errors=[],
        a2l_path=None,
        a2l_data=None,
        mac_records=[
            {"parse_ok": True, "name": "RPM", "address": 0x1008, "line_number": 1, "parse_error": ""},
            {"parse_ok": True, "name": "OOR", "address": 0x5000, "line_number": 2, "parse_error": ""},
        ],
    )

    prepared = app._prepare_load_payload(loaded)

    assert prepared.precomputed is True
    assert 0x1008 in prepared.mac_highlights
    assert 0x5000 in prepared.mac_highlights
    assert prepared.mac_out_of_range == [0x5000]
    assert prepared.bases_set == frozenset({0x1000, 0x1010})
    assert prepared.mac_cache_key is not None
    assert prepared.mac_cache_key[1] == 2  # len(records)
    assert prepared.mac_rows, "rows populated"


def test_update_sections_caps_mac_out_of_range(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from s19_app.tui import app as app_module

    app = S19TuiApp(base_dir=tmp_path)
    app.current_file = LoadedFile(
        path=tmp_path / "big.s19",
        file_type="s19",
        mem_map={0x1000: 0x11},
        row_bases=[0x1000],
        ranges=[(0x1000, 0x1010)],
        range_validity=[True],
        errors=[],
        a2l_path=None,
        a2l_data=None,
    )

    captured_labels: list[str] = []

    class FakeLabel:
        def __init__(self, text: str) -> None:
            self.text = text

        def add_class(self, _cls: str) -> None:
            return

    class FakeItem:
        def __init__(self, label: FakeLabel) -> None:
            self.label = label
            self.data = None

    class FakeList:
        def clear(self) -> None:
            captured_labels.clear()

        def append(self, item: object) -> None:
            label = getattr(item, "label", None) or getattr(item, "_label", None)
            captured_labels.append(label.text if label is not None else str(item))

    monkeypatch.setattr(app, "query_one", lambda selector, *_a, **_k: FakeList() if selector == "#sections_list" else None)
    monkeypatch.setattr(app_module, "Label", FakeLabel)
    monkeypatch.setattr(app_module, "ListItem", FakeItem)

    precomputed = list(range(0x5000, 0x5000 + app_module.MAX_SECTIONS_OUT_OF_RANGE * 3))
    app.update_sections(precomputed_out_of_range=precomputed)

    # 1 range row + MAX_SECTIONS_OUT_OF_RANGE MAC rows + 1 truncation marker.
    assert len(captured_labels) == 1 + app_module.MAX_SECTIONS_OUT_OF_RANGE + 1
    assert captured_labels[-1].startswith("...")
    assert f"{len(precomputed) - app_module.MAX_SECTIONS_OUT_OF_RANGE}" in captured_labels[-1]


@pytest.mark.slow
def test_end_to_end_load_pipeline_under_budget(tmp_path: Path):
    """Perf smoke: 32k MAC records + 2k ranges + 625k row_bases finish prepare+compute in time."""
    import time as _time

    app = S19TuiApp(base_dir=tmp_path)
    num_ranges = 2000
    ranges = [(i * 0x100, i * 0x100 + 0x80) for i in range(num_ranges)]
    row_bases = [i * 16 for i in range(625_000)]
    mac_records = [
        {
            "parse_ok": (i % 3 != 0),
            "name": f"T{i}",
            "address": i * 0x20,
            "line_number": i + 1,
            "parse_error": "err" if i % 3 == 0 else "",
        }
        for i in range(32_000)
    ]
    loaded = LoadedFile(
        path=tmp_path / "big.s19",
        file_type="s19",
        mem_map={},
        row_bases=row_bases,
        ranges=ranges,
        range_validity=[True] * num_ranges,
        errors=[],
        a2l_path=None,
        a2l_data=None,
        mac_records=mac_records,
    )

    started = _time.perf_counter()
    prepared = app._prepare_load_payload(loaded)
    elapsed = _time.perf_counter() - started

    assert prepared.precomputed is True
    assert len(prepared.mac_rows) == len(mac_records)
    # Keep the CI budget generous; the point is the pipeline finishes in seconds,
    # not the original "frozen for an hour" user reported.
    assert elapsed < 10.0, f"end-to-end prepare too slow: {elapsed:.3f}s"


@pytest.mark.slow
@pytest.mark.parametrize("load_order", ["s19_first", "mac_first"])
def test_stress_load_s19_then_a2l_then_mac(
    tmp_path: Path, load_order: str
) -> None:
    """
    Summary:
        End-to-end stress test: generate a realistic S19 + A2L + MAC triple on disk
        and push it through ``_parse_loaded_file`` and ``_prepare_load_payload``
        within a generous time budget for both load orders.

    Data Flow:
        - Write large S19 / A2L / MAC fixtures via the shared generators.
        - Seed ``current_a2l_path`` so the primary branch attaches A2L data naturally.
        - Call ``_parse_loaded_file`` for each artifact in the requested order,
          propagating ``current_file`` between calls so the merge helpers see prior state.
        - Run ``_prepare_load_payload`` once on the final merged ``LoadedFile``.
        - Assert coexistence, precomputed shape, and total elapsed time under budget.
    """
    import os
    import time as _time

    from tests.conftest import make_large_a2l, make_large_mac, make_large_s19

    s19_path = make_large_s19(
        tmp_path / "stress.s19", num_ranges=80, bytes_per_range=4096
    )
    a2l_path = make_large_a2l(
        tmp_path / "stress.a2l",
        num_measurements=1500,
        num_characteristics=300,
        memory_span_bytes=80 * 4096,
    )
    mac_path = make_large_mac(
        tmp_path / "stress.mac",
        num_records=8000,
        num_diagnostics=3000,
        memory_span_bytes=80 * 4096,
        num_a2l_tags=1500,
    )

    app = S19TuiApp(base_dir=tmp_path)
    app.current_a2l_path = a2l_path

    phase_times: dict[str, float] = {}
    started_total = _time.perf_counter()

    if load_order == "s19_first":
        steps = [("s19", s19_path), ("mac", mac_path)]
    else:
        steps = [("mac", mac_path), ("s19", s19_path)]

    final_loaded: LoadedFile | None = None
    for label, path in steps:
        phase_start = _time.perf_counter()
        loaded = app._parse_loaded_file(path)
        phase_times[f"parse_{label}"] = _time.perf_counter() - phase_start
        assert loaded is not None, f"_parse_loaded_file returned None for {label}"
        app.current_file = loaded
        final_loaded = loaded

    assert final_loaded is not None

    phase_start = _time.perf_counter()
    prepared = app._prepare_load_payload(final_loaded)
    phase_times["prepare"] = _time.perf_counter() - phase_start

    elapsed_total = _time.perf_counter() - started_total

    # Coexistence: after both loads, the merged payload always resolves to the
    # primary image but carries the MAC records alongside.
    assert final_loaded.file_type in {"s19", "hex"}, (
        f"primary image must win after merge; got {final_loaded.file_type}"
    )
    assert final_loaded.mac_path == mac_path
    assert final_loaded.mac_records, "MAC records must coexist with primary image"
    assert final_loaded.a2l_data is not None, "A2L must be attached to the primary payload"

    # Prepared payload shape: precomputed DataTable artifacts are present.
    assert prepared.precomputed is True
    assert len(prepared.mac_rows) == len(final_loaded.mac_records)
    assert len(prepared.mac_cell_rows) == len(final_loaded.mac_records)
    assert len(prepared.issue_cell_rows) == len(prepared.validation_issues)
    assert prepared.mac_widths is not None and len(prepared.mac_widths) == 8

    # Perf budget: default 20s on CI, overridable for slower hardware via env var.
    budget_s = float(os.environ.get("S19_APP_STRESS_BUDGET_S", "20.0"))
    assert elapsed_total < budget_s, (
        f"stress load over budget: order={load_order} elapsed={elapsed_total:.2f}s "
        f"phases={phase_times}"
    )


def test_handle_load_dialog_defers_load_until_after_modal_dismiss(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """``_handle_load_dialog`` must schedule the load via ``call_after_refresh`` so
    Textual pops the modal before the heavy copy/parse/install pipeline begins.
    """
    app = S19TuiApp(base_dir=tmp_path)

    load_calls: list[Path] = []
    monkeypatch.setattr(
        app, "_load_path_from_user_input", lambda path: load_calls.append(path)
    )

    scheduled: list[tuple] = []
    monkeypatch.setattr(
        app,
        "call_after_refresh",
        lambda callback, *args, **kwargs: scheduled.append((callback, args, kwargs)),
    )

    target = tmp_path / "sample.s19"
    app._handle_load_dialog(target)

    assert load_calls == [], "load must not run synchronously before modal pops"
    assert len(scheduled) == 1, "a single deferred load must be queued"
    callback, args, kwargs = scheduled[0]
    assert callback == app._load_path_from_user_input
    assert args == (target,)
    assert kwargs == {}

    callback(*args, **kwargs)
    assert load_calls == [target]


def test_handle_load_dialog_none_path_skips_scheduling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Cancelling the load dialog must not schedule any deferred work."""
    app = S19TuiApp(base_dir=tmp_path)
    scheduled: list[tuple] = []
    monkeypatch.setattr(
        app,
        "call_after_refresh",
        lambda callback, *args, **kwargs: scheduled.append((callback, args, kwargs)),
    )
    loaded: list[Path] = []
    monkeypatch.setattr(
        app, "_load_path_from_user_input", lambda path: loaded.append(path)
    )

    app._handle_load_dialog(None)

    assert scheduled == []
    assert loaded == []


def test_apply_prepared_load_chains_updates_via_call_later(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """``_apply_prepared_load`` must install reactive state synchronously and defer
    every heavy UI refresh through ``call_later`` so the event loop can repaint.
    """
    from s19_app.tui.app import PreparedLoad

    app = S19TuiApp(base_dir=tmp_path)

    deferred: list = []
    monkeypatch.setattr(
        app, "call_later", lambda callback, *args, **kwargs: deferred.append(callback)
    )

    call_log: list[str] = []

    def record(name: str):
        def _inner(*_a, **_k):
            call_log.append(name)

        return _inner

    monkeypatch.setattr(app, "update_sections", record("sections"))
    monkeypatch.setattr(app, "update_hex_view", record("hex"))
    monkeypatch.setattr(app, "update_alt_hex_view", record("alt_hex"))
    monkeypatch.setattr(app, "update_mac_hex_view", record("mac_hex"))
    monkeypatch.setattr(app, "update_a2l_view", record("a2l"))
    monkeypatch.setattr(app, "update_project_labels", record("labels"))
    monkeypatch.setattr(app, "set_file_status", record("status"))
    monkeypatch.setattr(app, "_append_log_line", record("log_line"))

    loaded = LoadedFile(
        path=tmp_path / "big.s19",
        file_type="s19",
        mem_map={0x1000: 0x11},
        row_bases=[0x1000],
        ranges=[(0x1000, 0x1010)],
        range_validity=[True],
        errors=[],
        a2l_path=None,
        a2l_data=None,
    )
    prepared = PreparedLoad(loaded=loaded)

    app._apply_prepared_load(prepared, tmp_path / "big.s19", 0.0)

    # Synchronous effects: status + log line appended before any deferred step runs.
    assert "status" in call_log
    assert "log_line" in call_log
    assert app.current_file is loaded
    assert "sections" not in call_log, "sections must be deferred, not sync"
    assert "hex" not in call_log, "hex must be deferred, not sync"

    assert len(deferred) == 1, "first chain step must be queued via call_later"
    deferred[0]()
    assert "sections" in call_log

    assert len(deferred) == 2
    deferred[1]()
    assert "hex" in call_log
    assert "alt_hex" in call_log
    assert "mac_hex" in call_log

    assert len(deferred) == 3
    deferred[2]()
    assert "a2l" in call_log

    assert len(deferred) == 4
    deferred[3]()
    assert "labels" in call_log


def test_update_sections_caps_primary_ranges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Primary ranges list must truncate to ``MAX_SECTIONS_PRIMARY_RANGES`` rows."""
    from s19_app.tui import app as app_module

    app = S19TuiApp(base_dir=tmp_path)
    total_ranges = app_module.MAX_SECTIONS_PRIMARY_RANGES + 100
    ranges = [(i * 0x10, i * 0x10 + 0x10) for i in range(total_ranges)]
    app.current_file = LoadedFile(
        path=tmp_path / "big.s19",
        file_type="s19",
        mem_map={start: 0 for start, _ in ranges},
        row_bases=[start for start, _ in ranges],
        ranges=ranges,
        range_validity=[True] * total_ranges,
        errors=[],
        a2l_path=None,
        a2l_data=None,
    )

    captured_labels: list[str] = []

    class FakeLabel:
        def __init__(self, text: str) -> None:
            self.text = text

        def add_class(self, _cls: str) -> None:
            return

    class FakeItem:
        def __init__(self, label: FakeLabel) -> None:
            self.label = label
            self.data = None

    class FakeList:
        def clear(self) -> None:
            captured_labels.clear()

        def append(self, item: object) -> None:
            label = getattr(item, "label", None) or getattr(item, "_label", None)
            captured_labels.append(label.text if label is not None else str(item))

    monkeypatch.setattr(
        app,
        "query_one",
        lambda selector, *_a, **_k: FakeList() if selector == "#sections_list" else None,
    )
    monkeypatch.setattr(app_module, "Label", FakeLabel)
    monkeypatch.setattr(app_module, "ListItem", FakeItem)

    app.update_sections(precomputed_out_of_range=[])

    # MAX_SECTIONS_PRIMARY_RANGES range rows + 1 truncation marker + 0 MAC rows.
    assert len(captured_labels) == app_module.MAX_SECTIONS_PRIMARY_RANGES + 1
    assert captured_labels[-1].startswith("...")
    extra = total_ranges - app_module.MAX_SECTIONS_PRIMARY_RANGES
    assert f"{extra} more ranges" in captured_labels[-1]


# --- DataTable populate / precompute / selection -----------------------------


def _build_mac_row_vector(n: int) -> tuple[list[tuple], list[dict]]:
    rows = []
    meta = []
    severities = [
        ValidationSeverity.OK,
        ValidationSeverity.ERROR,
        ValidationSeverity.WARNING,
        ValidationSeverity.NEUTRAL,
    ]
    for i in range(n):
        name = f"TAG_{i:05d}"
        addr = f"0x{0x1000 + i:08X}"
        rows.append(
            (
                name,
                addr,
                "yes" if i % 2 == 0 else "no",
                "yes" if i % 3 == 0 else "no",
                "OK",
                str(i),
                "",
                "MEAS:RPM",
            )
        )
        meta.append({"severity": severities[i % len(severities)], "address": 0x1000 + i})
    return rows, meta


def test_precompute_mac_datatable_payload_returns_widths_rows_and_styles():
    rows, meta = _build_mac_row_vector(10)
    widths, cell_rows, styles = precompute_mac_datatable_payload(rows, meta)
    assert len(widths) == 8
    assert widths[0] >= len("Tag")
    # Address column width should be at least the formatted address length (10 chars for 0x%08X).
    assert widths[1] >= 10
    assert len(cell_rows) == 10
    assert all(isinstance(row, tuple) and len(row) == 8 for row in cell_rows)
    assert len(styles) == 10
    assert styles[0] == _severity_style(ValidationSeverity.OK)
    assert styles[1] == _severity_style(ValidationSeverity.ERROR)


def test_precompute_mac_datatable_payload_clamps_wide_columns():
    wide_name = "X" * 200
    rows = [(wide_name, "0x00001000", "no", "no", "OK", "1", "also wide " * 50, "match " * 50)]
    meta = [{"severity": ValidationSeverity.OK, "address": 0x1000}]
    widths, _cells, _styles = precompute_mac_datatable_payload(rows, meta)
    assert widths[0] == 48  # Tag clamp.
    assert widths[6] == 48  # ParseErr clamp.
    assert widths[7] == 48  # A2LMatch clamp.


def test_precompute_issue_datatable_payload_emits_seven_columns_and_styles():
    issues = [
        ValidationIssue(
            code="E001",
            severity=ValidationSeverity.ERROR,
            message="addr missing",
            artifact="mac",
            symbol="RPM",
            address=0x1000,
            line_number=7,
        ),
        ValidationIssue(
            code="W002",
            severity=ValidationSeverity.WARNING,
            message="not in a2l",
            artifact="mac",
            symbol=None,
            address=None,
            line_number=None,
        ),
    ]
    cell_rows, styles = precompute_issue_datatable_payload(issues)
    assert len(cell_rows) == 2
    assert all(len(row) == 7 for row in cell_rows)
    assert cell_rows[0][0] == "ERROR"
    assert cell_rows[0][4] == "0x00001000"
    assert cell_rows[1][3] == "-"  # missing symbol is rendered as dash
    assert cell_rows[1][4] == "-"  # missing address is rendered as dash
    assert styles == [_severity_style(ValidationSeverity.ERROR), _severity_style(ValidationSeverity.WARNING)]


def test_prepare_load_payload_precomputes_datatable_fields(tmp_path: Path):
    app = S19TuiApp(base_dir=tmp_path)
    mac_records = [
        {"parse_ok": True, "name": f"TAG{i}", "address": 0x1000 + i, "line_number": i}
        for i in range(25)
    ]
    loaded = LoadedFile(
        path=tmp_path / "demo.s19",
        file_type="s19",
        mem_map={0x1000 + i: i & 0xFF for i in range(25)},
        row_bases=[0x1000],
        ranges=[(0x1000, 0x1020)],
        range_validity=[True],
        errors=[],
        a2l_path=None,
        a2l_data=None,
        mac_records=mac_records,
    )
    prepared = app._prepare_load_payload(loaded)
    assert prepared.mac_widths is not None and len(prepared.mac_widths) == 8
    assert len(prepared.mac_cell_rows) == 25
    assert all(isinstance(row, tuple) for row in prepared.mac_cell_rows)
    assert len(prepared.mac_cell_styles) == 25
    # issue_cell_rows parallels validation_issues.
    assert len(prepared.issue_cell_rows) == len(prepared.validation_issues)
    assert len(prepared.issue_cell_styles) == len(prepared.validation_issues)


def test_populate_mac_datatable_emits_row_keys_and_records_addresses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    app = S19TuiApp(base_dir=tmp_path)
    visible_rows = [
        ("TAG_A", "0x00001000", "yes", "yes", "OK", "1", "", "MEAS:A"),
        ("TAG_B", "0x00001004", "no", "yes", "OK", "2", "", "MEAS:B"),
    ]
    visible_styles = [_severity_style(ValidationSeverity.OK), _severity_style(ValidationSeverity.ERROR)]
    visible_meta = [
        {"severity": ValidationSeverity.OK, "address": 0x1000},
        {"severity": ValidationSeverity.ERROR, "address": 0x1004},
    ]

    captured_keys: list[object] = []
    captured_rows: list[tuple] = []

    class _FakeTable:
        def add_row(self, *cells: object, key: object = None) -> None:
            captured_keys.append(key)
            captured_rows.append(cells)

    app._mac_row_key_to_address = {}
    app._populate_mac_datatable(_FakeTable(), visible_rows, visible_styles, visible_meta, start=10)
    assert captured_keys == ["mac:10", "mac:11"]
    assert len(captured_rows) == 2
    assert app._mac_row_key_to_address == {"mac:10": 0x1000, "mac:11": 0x1004}


def test_populate_issues_datatable_records_filtered_index(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    app = S19TuiApp(base_dir=tmp_path)
    issues = [
        ValidationIssue(
            code=f"C{i}",
            severity=ValidationSeverity.ERROR if i % 2 == 0 else ValidationSeverity.WARNING,
            message="m",
            artifact="mac",
            symbol=f"s{i}",
            address=0x1000 + i,
            line_number=i,
        )
        for i in range(3)
    ]
    cell_rows, styles = precompute_issue_datatable_payload(issues)

    captured_keys: list[object] = []

    class _FakeTable:
        def add_row(self, *_cells: object, key: object = None) -> None:
            captured_keys.append(key)

    app._issue_row_key_to_index = {}
    app._populate_issues_datatable(_FakeTable(), cell_rows, styles, issues, index_base=5)
    assert captured_keys == ["issue:5", "issue:6", "issue:7"]
    assert app._issue_row_key_to_index == {"issue:5": 5, "issue:6": 6, "issue:7": 7}


def test_on_data_table_row_selected_dispatches_by_id(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from s19_app.tui import app as app_module

    app = S19TuiApp(base_dir=tmp_path)
    jumps: dict[str, object] = {}

    monkeypatch.setattr(app, "_jump_to_mac_address", lambda addr: jumps.setdefault("mac", addr))
    monkeypatch.setattr(
        app,
        "_jump_to_validation_issue_by_index",
        lambda idx: jumps.setdefault("issue", idx),
    )
    monkeypatch.setattr(app, "_jump_to_tag_by_data", lambda tag: jumps.setdefault("a2l", tag))

    app._mac_row_key_to_address = {"mac:3": 0xABCD}
    app._issue_row_key_to_index = {"issue:2": 2}
    tag_dict = {"name": "RPM", "address": 0x2000}
    app._a2l_row_key_to_tag = {"a2l:0": tag_dict}

    class _Evt:
        def __init__(self, table_id: str, key: str) -> None:
            class _T:
                id = table_id

            class _K:
                value = key

            self.data_table = _T()
            self.row_key = _K()

    app.on_data_table_row_selected(_Evt("mac_records_list", "mac:3"))
    app.on_data_table_row_selected(_Evt("validation_issues_list", "issue:2"))
    app.on_data_table_row_selected(_Evt("a2l_tags_list", "a2l:0"))

    assert jumps == {"mac": 0xABCD, "issue": 2, "a2l": tag_dict}


def test_on_button_pressed_routes_new_page_buttons(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    app = S19TuiApp(base_dir=tmp_path)
    calls = {"a2l_prev": 0, "a2l_next": 0, "mac_prev": 0, "mac_next": 0}
    monkeypatch.setattr(app, "action_a2l_tags_page_prev", lambda: calls.__setitem__("a2l_prev", calls["a2l_prev"] + 1))
    monkeypatch.setattr(app, "action_a2l_tags_page_next", lambda: calls.__setitem__("a2l_next", calls["a2l_next"] + 1))
    monkeypatch.setattr(app, "action_mac_records_page_prev", lambda: calls.__setitem__("mac_prev", calls["mac_prev"] + 1))
    monkeypatch.setattr(app, "action_mac_records_page_next", lambda: calls.__setitem__("mac_next", calls["mac_next"] + 1))

    class _Event:
        def __init__(self, button_id: str) -> None:
            class _Button:
                id = button_id

            self.button = _Button()

    app.on_button_pressed(_Event("a2l_page_prev_button"))  # type: ignore[arg-type]
    app.on_button_pressed(_Event("a2l_page_next_button"))  # type: ignore[arg-type]
    app.on_button_pressed(_Event("mac_page_prev_button"))  # type: ignore[arg-type]
    app.on_button_pressed(_Event("mac_page_next_button"))  # type: ignore[arg-type]

    assert calls == {"a2l_prev": 1, "a2l_next": 1, "mac_prev": 1, "mac_next": 1}


def test_jump_actions_request_near_top_focus_and_scroll_reset(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    app = S19TuiApp(base_dir=tmp_path)
    a2l_calls: list[tuple[int | None, bool, bool]] = []
    mac_calls: list[tuple[int | None, bool, bool]] = []
    monkeypatch.setattr(
        app,
        "update_alt_hex_view",
        lambda focus_address=None, near_top=False, reset_scroll=False: a2l_calls.append(
            (focus_address, near_top, reset_scroll)
        ),
    )
    monkeypatch.setattr(
        app,
        "update_mac_hex_view",
        lambda focus_address=None, near_top=False, reset_scroll=False: mac_calls.append(
            (focus_address, near_top, reset_scroll)
        ),
    )
    monkeypatch.setattr(app, "set_status", lambda _msg: None)

    app._jump_to_tag_by_data({"name": "RPM", "address": 0x1000, "length": 4})
    app._jump_to_mac_address(0x2000)

    assert a2l_calls == [(0x1000, True, True)]
    assert mac_calls == [(0x2000, True, True)]


def test_update_validation_issues_view_uses_worker_precomputed_cells(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    app = S19TuiApp(base_dir=tmp_path)
    issues = _make_validation_issues(20)
    precomputed_rows, precomputed_styles = precompute_issue_datatable_payload(issues)
    app._validation_issues = issues
    app._validation_issue_cell_rows = precomputed_rows
    app._validation_issue_cell_styles = precomputed_styles
    app.validation_issues_page_size = 10
    app.validation_issue_filter_mode = "all"

    recorded: list[tuple[str, ...]] = []

    class FakeTable:
        columns = ["Severity"]

        def clear(self, columns: bool = True) -> None:
            recorded.clear()

        def add_row(self, *cells: object, key: object = None) -> None:
            recorded.append(tuple(str(cell) for cell in cells))

    class FakeLabel:
        def update(self, _text: str) -> None:
            return

    fake_table = FakeTable()
    fake_label = FakeLabel()

    def _query(selector: str, *_a, **_k):
        if selector == "#validation_issues_list":
            return fake_table
        if selector == "#validation_issues_summary":
            return fake_label
        return None

    monkeypatch.setattr(app, "query_one", _query)

    app.update_validation_issues_view()
    assert len(recorded) == 10
    assert recorded[0][0] == precomputed_rows[0][0]  # severity cell reused verbatim


