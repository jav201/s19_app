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
