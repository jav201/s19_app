from pathlib import Path

from s19_app import tui
from s19_app.tui import (
    FOCUS_CONTEXT_ROWS,
    HEX_WIDTH,
    MAX_HEX_BYTES,
    MAX_HEX_ROWS,
    S19TuiApp,
    A2L_EXTENSIONS,
    copy_into_workarea,
    find_repo_root,
    render_hex_view,
    render_hex_view_text,
    find_string_in_mem,
    render_a2l_view,
    sanitize_project_name,
    resolve_input_path,
    validate_project_files,
    validate_a2l_tags,
    WORKAREA_TEMP,
    setup_logging,
    LOGS_SUBDIR,
    LOG_FILENAME,
    parse_a2l_file,
)


def test_copy_into_workarea_creates_unique_names(tmp_path):
    workarea = tmp_path / "workarea"
    source = tmp_path / "sample.s19"
    source.write_text("S0", encoding="utf-8")

    first = copy_into_workarea(source, workarea)
    second = copy_into_workarea(source, workarea)

    assert first.exists()
    assert second.exists()
    assert first.name == "sample.s19"
    assert second.name.startswith("sample_")
    assert second.name.endswith(".s19")


def test_find_repo_root_detects_marker(tmp_path):
    repo = tmp_path / "repo"
    nested = repo / "a" / "b"
    nested.mkdir(parents=True)
    (repo / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")

    assert find_repo_root(nested) == repo


def test_resolve_input_path_prefers_base_dir(tmp_path):
    base_dir = tmp_path / "base"
    base_dir.mkdir()
    target = base_dir / "examples" / "file.s19"
    target.parent.mkdir()
    target.write_text("S0", encoding="utf-8")

    resolved = resolve_input_path(Path("examples/file.s19"), base_dir)
    assert resolved == target


def test_resolve_input_path_falls_back_to_repo_root(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "project.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    target = repo / "examples" / "file.s19"
    target.parent.mkdir()
    target.write_text("S0", encoding="utf-8")
    base_dir = repo / "nested"
    base_dir.mkdir()

    resolved = resolve_input_path(Path("examples/file.s19"), base_dir)
    assert resolved == target


def test_render_hex_view_includes_focus_context():
    mem_map = {addr: 0x41 for addr in range(0x1000, 0x1000 + (HEX_WIDTH * 80))}
    focus = 0x1000 + (HEX_WIDTH * 70)

    output = render_hex_view(mem_map, focus)
    assert "context preserved" in output
    assert f"0x{focus - (FOCUS_CONTEXT_ROWS * HEX_WIDTH):08X}" in output


def test_render_hex_view_truncates_output():
    mem_map = {addr: 0x41 for addr in range(0x2000, 0x2000 + (MAX_HEX_BYTES + 64))}

    output = render_hex_view(mem_map)
    assert "output truncated" in output or f"window limited to {MAX_HEX_ROWS} rows" in output


def test_render_hex_view_text_includes_rows_for_mac_overlay_addresses():
    mem_map = {0x1000: 0x41}

    text = render_hex_view_text(
        mem_map=mem_map,
        focus_address=None,
        row_bases=[0x1000],
        highlight=None,
        mac_highlight_addresses={0x2200},
    )

    output = str(text)
    assert "0x00002200" in output


def test_sanitize_project_name_allows_safe_chars():
    assert sanitize_project_name("My_Project-1") == "My_Project-1"


def test_sanitize_project_name_strips_invalid_chars():
    assert sanitize_project_name("My Project!@#") == "MyProject"


def test_sanitize_project_name_rejects_empty():
    assert sanitize_project_name("   ") is None


def test_list_projects_ignores_temp(tmp_path):
    workarea = tmp_path / "workarea"
    temp_dir = workarea / WORKAREA_TEMP
    temp_dir.mkdir(parents=True)
    (workarea / "ProjectA").mkdir()
    (workarea / "ProjectB").mkdir()
    app = S19TuiApp(base_dir=tmp_path)
    app.workarea = workarea

    projects = app.list_projects()

    assert projects == ["ProjectA", "ProjectB"]


def test_validate_project_files_allows_single_data_and_a2l(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "file.s19").write_text("S0", encoding="utf-8")
    (project / "calibration.a2l").write_text("A2L", encoding="utf-8")

    data_files, a2l_files, error = validate_project_files(project)

    assert error is None
    assert len(data_files) == 1
    assert len(a2l_files) == 1
    assert (A2L_EXTENSIONS and a2l_files[0].suffix.lower() in A2L_EXTENSIONS)


def test_validate_project_files_rejects_multiple_data(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "one.s19").write_text("S0", encoding="utf-8")
    (project / "two.hex").write_text(":00", encoding="utf-8")

    _, _, error = validate_project_files(project)

    assert error is not None


def test_validate_project_files_allows_primary_plus_mac(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "one.s19").write_text("S0", encoding="utf-8")
    (project / "tags.mac").write_text("RPM=0x1000", encoding="utf-8")

    data_files, _, error = validate_project_files(project)

    assert error is None
    assert sorted(path.suffix.lower() for path in data_files) == [".mac", ".s19"]


def test_validate_project_files_rejects_multiple_a2l(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "file.s19").write_text("S0", encoding="utf-8")
    (project / "one.a2l").write_text("A2L", encoding="utf-8")
    (project / "two.a2l").write_text("A2L", encoding="utf-8")

    _, _, error = validate_project_files(project)

    assert error is not None


def test_setup_logging_creates_log_handler(tmp_path):
    logger = setup_logging(tmp_path)

    assert logger.handlers
    log_dir = tmp_path / ".s19tool" / LOGS_SUBDIR
    assert log_dir.exists()
    logger.info("test log entry")
    log_path = log_dir / LOG_FILENAME
    assert log_path.exists()


def test_setup_logging_uses_rotating_file_handler(tmp_path):
    logger = setup_logging(tmp_path)
    handler_types = {type(handler).__name__ for handler in logger.handlers}

    assert "RotatingFileHandler" in handler_types


def test_parse_a2l_file_captures_sections(tmp_path):
    a2l = tmp_path / "sample.a2l"
    a2l.write_text(
        "/begin PROJECT Demo\n"
        "  /begin MODULE Engine\n"
        "  /end MODULE\n"
        "/end PROJECT\n",
        encoding="utf-8",
    )

    data = parse_a2l_file(a2l)

    assert data["errors"] == []
    assert data["sections"][0]["name"] == "PROJECT"
    assert data["sections"][0]["children"][0]["name"] == "MODULE"


def test_parse_a2l_file_reports_unclosed_section(tmp_path):
    a2l = tmp_path / "bad.a2l"
    a2l.write_text("/begin PROJECT Demo\n", encoding="utf-8")

    data = parse_a2l_file(a2l)

    assert data["errors"]


def test_render_a2l_view_shows_sections():
    data = {
        "sections": [
            {"name": "PROJECT", "meta": "Demo", "start_line": 1, "end_line": 3, "children": []}
        ],
        "errors": [],
    }

    output = render_a2l_view(data)

    assert "PROJECT Demo" in output


def test_render_a2l_view_shows_nested_sections():
    data = {
        "sections": [
            {
                "name": "PROJECT",
                "meta": "Demo",
                "start_line": 1,
                "end_line": 5,
                "children": [
                    {
                        "name": "MODULE",
                        "meta": "Engine",
                        "start_line": 2,
                        "end_line": 4,
                        "children": [],
                    }
                ],
            }
        ],
        "errors": [],
    }

    output = render_a2l_view(data)

    assert "- PROJECT Demo (lines 1-5)" in output
    assert "  - MODULE Engine (lines 2-4)" in output


def test_render_a2l_view_shows_errors():
    data = {"sections": [], "errors": ["Line 1: /end without /begin"]}

    output = render_a2l_view(data)

    assert "A2L parse errors" in output


def test_validate_a2l_tags_matches_memory():
    tags = [
        {"section": "MEASUREMENT", "name": "A", "address": 0x1000, "length": 2},
        {"section": "MEASUREMENT", "name": "B", "address": 0x2000, "length": 2},
    ]
    mem_map = {0x1000: 0x01, 0x1001: 0x02}

    results = validate_a2l_tags(tags, mem_map)

    assert results[0]["valid"] is True
    assert results[0]["schema_ok"] is True
    assert results[0]["memory_checked"] is True
    assert results[0]["in_memory"] is True
    assert results[1]["valid"] is True
    assert results[1]["schema_ok"] is True
    assert results[1]["memory_checked"] is True
    assert results[1]["in_memory"] is False


def test_a2l_tag_filters_by_mode_and_field(tmp_path):
    app = S19TuiApp(base_dir=tmp_path)
    tags = [
        {
            "name": "FOO",
            "address": 0x1000,
            "length": 2,
            "source": "assigned",
            "schema_ok": True,
            "memory_checked": True,
            "in_memory": True,
            "lower_limit": "0",
            "upper_limit": "10",
            "unit": "rpm",
            "bit_org": "u16",
            "endian": "BIG",
            "virtual": False,
            "function_group": "ENG",
            "access": "read_only",
        },
        {
            "name": "BAR",
            "address": 0x2000,
            "length": 2,
            "source": "formula",
            "schema_ok": True,
            "memory_checked": True,
            "in_memory": False,
            "lower_limit": None,
            "upper_limit": None,
            "unit": "",
            "bit_org": "",
            "endian": "",
            "virtual": True,
            "function_group": "",
            "access": "calibratable",
        },
    ]

    app.a2l_tags_filter_mode = "invalid"
    app.a2l_tags_filter_text = ""
    filtered = app._filter_a2l_tags(tags)
    assert [tag["name"] for tag in filtered] == ["BAR"]

    app.a2l_tags_filter_mode = "all"
    app.a2l_tags_filter_field = "name"
    app.a2l_tags_filter_text = "foo"
    filtered = app._filter_a2l_tags(tags)
    assert [tag["name"] for tag in filtered] == ["FOO"]

    app.a2l_tags_filter_field = "limits"
    app.a2l_tags_filter_text = "0..10"
    filtered = app._filter_a2l_tags(tags)
    assert [tag["name"] for tag in filtered] == ["FOO"]


def test_find_string_in_mem_finds_address():
    mem_map = {0x1000 + i: b for i, b in enumerate(b"HELLO WORLD")}
    assert find_string_in_mem(mem_map, "WORLD") == 0x1006
    assert find_string_in_mem(mem_map, "world") == 0x1006


def test_find_string_in_mem_returns_none_when_missing():
    mem_map = {0x2000: 0x41, 0x2001: 0x42}
    assert find_string_in_mem(mem_map, "ZZ") is None


def test_find_string_in_mem_supports_next_search():
    mem_map = {0x3000 + i: b for i, b in enumerate(b"ABC ABC")}
    first = find_string_in_mem(mem_map, "ABC")
    second = find_string_in_mem(mem_map, "ABC", start_address=first + 1)
    assert first == 0x3000
    assert second == 0x3004


def test_tui_module_has_docstring():
    assert tui.__doc__


def test_tui_app_has_docstring():
    assert S19TuiApp.__doc__
