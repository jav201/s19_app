from pathlib import Path

import pytest

from s19_app.tui.a2l import (
    extract_a2l_tags,
    format_tag_validation_status,
    parse_a2l_file,
    render_a2l_view,
    validate_a2l_tags,
)


def test_parse_a2l_file_extracts_nested_measurement_and_characteristic_tags(tmp_path: Path):
    a2l = tmp_path / "sample.a2l"
    a2l.write_text(
        "/begin PROJECT Demo\n"
        "  /begin MODULE Engine\n"
        "    /begin MEASUREMENT RPM\n"
        "      ECU_ADDRESS 0x1000\n"
        "      DATA_SIZE 2\n"
        "      LOWER_LIMIT 0\n"
        "      UPPER_LIMIT 7000\n"
        "      UNIT rpm\n"
        "      READ_ONLY\n"
        "    /end MEASUREMENT\n"
        "    /begin CHARACTERISTIC TORQUE\n"
        "      ECU_ADDRESS 0x2000\n"
        "      LENGTH 4\n"
        "      BYTE_ORDER BIG_ENDIAN\n"
        "      FUNCTION ENG\n"
        "      CALIBRATABLE\n"
        "      COMPU_METHOD SCALE\n"
        "      VIRTUAL\n"
        "    /end CHARACTERISTIC\n"
        "  /end MODULE\n"
        "/end PROJECT\n",
        encoding="utf-8",
    )

    data = parse_a2l_file(a2l)

    assert data["errors"] == []
    assert [tag["name"] for tag in data["tags"]] == ["RPM", "TORQUE"]
    assert data["tags"][0]["address"] == 0x1000
    assert data["tags"][0]["length"] == 2
    assert data["tags"][0]["access"] == "read_only"
    assert data["tags"][1]["source"] == "formula"
    assert data["tags"][1]["endian"] == "BIG_ENDIAN"
    assert data["tags"][1]["virtual"] is True


def test_parse_a2l_file_reports_missing_file():
    data = parse_a2l_file(Path("missing.a2l"))

    assert data["sections"] == []
    assert data["tags"] == []
    assert data["errors"] == ["File not found."]


def test_extract_a2l_tags_ignores_unrelated_sections():
    sections = [
        {
            "name": "PROJECT",
            "meta": "Demo",
            "lines": [],
            "children": [
                {
                    "name": "MODULE",
                    "meta": "Engine",
                    "lines": [],
                    "children": [
                        {"name": "AXIS_PTS", "meta": "Ignored", "lines": [], "children": []},
                    ],
                }
            ],
        }
    ]

    assert extract_a2l_tags(sections) == []


def test_validate_a2l_tags_marks_missing_address_or_length_invalid():
    tags = [{"section": "MEASUREMENT", "name": "RPM", "address": None, "length": 2}]

    results = validate_a2l_tags(tags, {0x1000: 0x01})

    assert results == [
        {
            "section": "MEASUREMENT",
            "name": "RPM",
            "address": None,
            "length": 2,
            "schema_ok": False,
            "memory_checked": False,
            "valid": False,
            "reason": "missing address/length",
            "in_memory": None,
        }
    ]


def test_render_a2l_view_shows_tag_validation_status():
    a2l_data = {
        "sections": [{"name": "PROJECT", "meta": "Demo", "start_line": 1, "end_line": 8, "children": []}],
        "errors": [],
        "tags": [{"section": "MEASUREMENT", "name": "RPM", "address": 0x1000, "length": 2}],
    }
    tag_checks = [
        {
            "section": "MEASUREMENT",
            "name": "RPM",
            "address": 0x1000,
            "length": 2,
            "schema_ok": False,
            "valid": False,
            "reason": "missing address/length",
        }
    ]

    output = render_a2l_view(a2l_data, tag_checks)

    assert "MEASUREMENT RPM: 0x00001000 len=2 mem=unknown ERR (missing address/length)" in output


def test_validate_a2l_tags_without_mem_map_skips_image_check():
    tags = [{"section": "MEASUREMENT", "name": "A", "address": 0x1000, "length": 2}]

    results = validate_a2l_tags(tags, None)

    assert results[0]["schema_ok"] is True
    assert results[0]["memory_checked"] is False
    assert results[0]["in_memory"] is None


def test_validate_a2l_tags_virtual_without_address_skips_range():
    tags = [{"section": "MEASUREMENT", "name": "V", "virtual": True, "address": None, "length": None}]

    results = validate_a2l_tags(tags, {0x1000: 0x01})

    assert results[0]["schema_ok"] is True
    assert results[0]["memory_checked"] is False
    assert results[0]["in_memory"] is None


def test_render_a2l_view_shows_out_of_image_status():
    assert format_tag_validation_status(
        {"schema_ok": True, "memory_checked": True, "in_memory": False}
    ) == "OUT(image)"


def test_parse_a2l_file_emits_stage_logs(tmp_path: Path, caplog: pytest.LogCaptureFixture):
    a2l = tmp_path / "stage.a2l"
    a2l.write_text("/begin PROJECT Demo\n/end PROJECT\n", encoding="utf-8")

    with caplog.at_level("INFO"):
        parse_a2l_file(a2l)

    assert any("A2L section tree built:" in message for message in caplog.messages)
    assert any("A2L parse stages:" in message for message in caplog.messages)
