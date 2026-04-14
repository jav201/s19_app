from pathlib import Path

import pytest

from s19_app.tui.app import S19TuiApp
from s19_app.tui.workspace import WORKAREA_TEMP


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


def test_recompute_a2l_tag_column_widths_caps_name_column(tmp_path: Path):
    app = S19TuiApp(base_dir=tmp_path)
    tags = [
        {"name": "a", "address": 0, "length": 1, "source": "assigned", "memory_region": "r"},
        {"name": "b" * 80, "address": 1, "length": 1, "source": "assigned", "memory_region": "r"},
    ]
    app._recompute_a2l_tag_column_widths(tags)
    assert app._a2l_tag_column_widths is not None
    assert app._a2l_tag_column_widths[0] == 48


def test_a2l_summary_page_delta_moves_start_and_preserves_backing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    app = S19TuiApp(base_dir=tmp_path)
    monkeypatch.setattr(app, "_update_a2l_summary_buffer", lambda: None)
    app._a2l_summary_lines = [f"x{i}" for i in range(400)]
    app.a2l_summary_window_size = 100
    app._a2l_summary_start = 0
    app._a2l_summary_page_delta(150)
    assert app._a2l_summary_start == 150
    assert len(app._a2l_summary_lines) == 400


def test_a2l_summary_find_next_advances_line_index(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    app = S19TuiApp(base_dir=tmp_path)
    app._a2l_summary_lines = ["alpha", "beta needle", "gamma", "delta needle"]
    app.a2l_summary_window_size = 10
    app._a2l_summary_start = 0

    class _FakeInput:
        value = "needle"

    class _FakeStatic:
        def update(self, _text: str) -> None:
            return None

    def fake_query_one(selector: str, _type=None):
        if selector == "#a2l_summary_find_input":
            return _FakeInput()
        if selector == "#a2l_view":
            return _FakeStatic()
        raise AssertionError(selector)

    monkeypatch.setattr(app, "query_one", fake_query_one)
    monkeypatch.setattr(app, "set_status", lambda _msg: None)
    app._handle_a2l_summary_find_next()
    assert app._a2l_summary_find_last_line_index == 1
    app._handle_a2l_summary_find_next()
    assert app._a2l_summary_find_last_line_index == 3


def test_a2l_tag_find_next_wraps_filtered_list(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    app = S19TuiApp(base_dir=tmp_path)
    app._a2l_filtered_tags = [
        {"name": "bob", "address": 0, "length": 1, "source": "assigned", "memory_region": "r", "schema_ok": True},
        {"name": "bab", "address": 1, "length": 1, "source": "assigned", "memory_region": "r", "schema_ok": True},
    ]
    app._a2l_window_start = 0
    app.a2l_window_size = 50

    class _FakeInput:
        value = "b"

    class _FakeListView:
        children: list = [None, None, object()]

        def __init__(self) -> None:
            self.index = 0

    fake_lv = _FakeListView()

    def fake_query_one(selector: str, _type=None):
        if selector == "#a2l_tag_find_input":
            return _FakeInput()
        if selector == "#a2l_tags_list":
            return fake_lv
        raise AssertionError(selector)

    updated: list[int] = []

    def capture_update(_tags: list[dict]) -> None:
        updated.append(len(_tags))

    monkeypatch.setattr(app, "query_one", fake_query_one)
    monkeypatch.setattr(app, "update_a2l_tags_view", capture_update)
    monkeypatch.setattr(app, "set_status", lambda _msg: None)
    app._handle_a2l_tag_find_next()
    assert app._a2l_tag_find_last_index == 0
    assert updated == [2]
    app._handle_a2l_tag_find_next()
    assert app._a2l_tag_find_last_index == 1
    app._handle_a2l_tag_find_next()
    assert app._a2l_tag_find_last_index == 0


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
