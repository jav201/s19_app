"""Tests for enriched A2L parsing (headers, Vector IF_DATA, segments)."""

from pathlib import Path

import pytest

from s19_app.tui.a2l import (
    build_section_tree,
    extract_a2l_tags,
    parse_a2l_file,
    parse_begin_meta,
    parse_measurement_header,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = REPO_ROOT / "examples"


def test_parse_begin_meta_long_identifier_quoted():
    name, desc = parse_begin_meta('shapes_a2l[0].Square.it "ein anderer Kommentar"')
    assert name == "shapes_a2l[0].Square.it"
    assert desc == "ein anderer Kommentar"


def test_parse_begin_meta_no_description():
    name, desc = parse_begin_meta("RPM")
    assert name == "RPM"
    assert desc is None


def test_measurement_header_and_matrix_dim_length(tmp_path: Path):
    a2l = tmp_path / "m.a2l"
    a2l.write_text(
        "/begin PROJECT P\n/begin MODULE M\n"
        '/begin MEASUREMENT T.sub "note"\n'
        "FLOAT32_IEEE NO_COMPU_METHOD 0 0 -1 1\n"
        "ECU_ADDRESS 0x4000\n"
        "MATRIX_DIM 7\n"
        "/end MEASUREMENT\n/end MODULE\n/end PROJECT\n",
        encoding="utf-8",
    )
    data = parse_a2l_file(a2l)
    assert data["errors"] == []
    tag = data["tags"][0]
    assert tag["name"] == "T.sub"
    assert tag["description"] == "note"
    assert tag["datatype"] == "FLOAT32_IEEE"
    assert tag["address"] == 0x4000
    assert tag["length"] == 28
    assert tag["matrix_dim"] == 7


def test_characteristic_inline_address_and_symbol_link(tmp_path: Path):
    a2l = tmp_path / "c.a2l"
    a2l.write_text(
        "/begin PROJECT P\n/begin MODULE M\n"
        "/begin CHARACTERISTIC Cal.K\n"
        "VAL_BLK 0x8000 __SBYTE_Z 0 NO_COMPU_METHOD -128 127\n"
        "MATRIX_DIM 5\n"
        'SYMBOL_LINK "Cal.K.sym" 0\n'
        "/end CHARACTERISTIC\n/end MODULE\n/end PROJECT\n",
        encoding="utf-8",
    )
    tag = parse_a2l_file(a2l)["tags"][0]
    assert tag["address"] == 0x8000
    assert tag["length"] == 5
    assert tag["symbol_link"] == "Cal.K.sym"


def test_data_type_keyword_sets_datatype_not_bit_mask(tmp_path: Path):
    a2l = tmp_path / "dt.a2l"
    a2l.write_text(
        "/begin PROJECT P\n/begin MODULE M\n/begin MEASUREMENT X\n"
        "ECU_ADDRESS 0x1000\nDATA_SIZE 1\nDATA_TYPE UWORD\n"
        "/end MEASUREMENT\n/end MODULE\n/end PROJECT\n",
        encoding="utf-8",
    )
    tag = parse_a2l_file(a2l)["tags"][0]
    assert tag["datatype"] == "UWORD"
    assert tag["bit_org"] is None


def test_memory_region_flash_and_ram(tmp_path: Path):
    a2l = tmp_path / "seg.a2l"
    a2l.write_text(
        "/begin PROJECT P\n/begin MODULE M\n"
        '/begin MEMORY_SEGMENT Code ""\n'
        "CODE FLASH INTERN 0x08000000 0x00001000 -1 -1 -1 -1 -1\n"
        "/end MEMORY_SEGMENT\n"
        '/begin MEMORY_SEGMENT Vars ""\n'
        "DATA RAM INTERN 0x20000000 0x00000400 -1 -1 -1 -1 -1\n"
        "/end MEMORY_SEGMENT\n"
        "/begin MEASUREMENT InFlash\n"
        "UBYTE NO_COMPU_METHOD 0 0 0 255\n"
        "ECU_ADDRESS 0x08000080\n"
        "/end MEASUREMENT\n"
        "/begin MEASUREMENT InRam\n"
        "UBYTE NO_COMPU_METHOD 0 0 0 255\n"
        "ECU_ADDRESS 0x20000010\n"
        "/end MEASUREMENT\n"
        "/end MODULE\n/end PROJECT\n",
        encoding="utf-8",
    )
    tags = parse_a2l_file(a2l)["tags"]
    by_name = {t["name"]: t for t in tags}
    assert by_name["InFlash"]["memory_region"] == "flash"
    assert by_name["InRam"]["memory_region"] == "ram"


def test_vector_canape_ext_link_map_extraction(tmp_path: Path):
    src = EXAMPLES / "check_test.a2l"
    if not src.is_file():
        pytest.skip("examples/check_test.a2l not present")
    data = parse_a2l_file(src)
    assert data["errors"] == []
    tag = next(t for t in data["tags"] if t.get("name") == "Curve_ExternalAxis")
    assert tag["link_map"]
    assert tag["link_map"][0]["name"] == "Curve_ExternalAxis"
    assert "0x0" in tag["link_map"][0]["values"]


def test_vector_software_a_smoke_parse():
    src = EXAMPLES / "software_a.a2l"
    if not src.is_file():
        pytest.skip("examples/software_a.a2l not present")
    data = parse_a2l_file(src)
    assert not any("Unclosed" in e for e in data["errors"]), data["errors"]
    assert len(data["tags"]) > 100
    sample = "AAD_UTRQ.HWV_VIUF_C_PposBXIIFfkdGfiaJnbbPvb_DYAN_XVZ1_Ierxjr_Eud_Y"
    assert any(t.get("name") == sample for t in data["tags"])


def test_build_section_tree_canape_ext_meta_numeric(tmp_path: Path):
    a2l = tmp_path / "canape_meta.a2l"
    a2l.write_text(
        "/begin PROJECT P\n/begin MODULE M\n/begin IF_DATA CANAPE_EXT 0x64\n"
        'LINK_MAP "X" 0x1 0x2\n/end IF_DATA\n/end MODULE\n/end PROJECT\n',
        encoding="utf-8",
    )
    sections, errors = build_section_tree(a2l)
    assert errors == []
    mod = sections[0]["children"][0]
    ifd = mod["children"][0]
    assert ifd["name"] == "IF_DATA"
    assert ifd["meta"].startswith("CANAPE_EXT")
    assert "0x64" in ifd["meta"]


def test_parse_measurement_header_rejects_ecu_line():
    assert parse_measurement_header("ECU_ADDRESS 0x1000") is None
