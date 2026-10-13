"""Tests for enriched A2L parsing (headers, Vector IF_DATA, segments).

Batch-91 contract adoption (HLR-122):
# TC-622 — this module pins the A2L engine's enrichment of raw and physical values via datatype/COMPU_METHOD (LLR-122.2).

Batch-95 contract adoption (HLR-137):
# TC-682 — this module pins the hardened extract_memory_segments (LLR-137.4):
  quoted multi-word MEMORY_SEGMENT long identifiers parse to full rows with
  non-null base/size on the shipped ASAP2 demos, the unquoted fixture parses
  byte-identically, and the entry carries the offset field where declared.
"""

from pathlib import Path

import pytest

from s19_app.tui.a2l import (
    build_section_tree,
    extract_memory_segments,
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


# ---------------------------------------------------------------------------
# TC-682 — batch-95 LLR-137.4: the hardened extract_memory_segments
# ---------------------------------------------------------------------------

CASE00 = EXAMPLES / "case_00_public"

#: The pinned expectations of the shipped quoted demo (values verified
#: against the fixture at batch-95 P1): name -> (usage, kind, base, size).
QUOTED_DEMO_EXPECTATIONS = {
    "ASAP2_Demo_V161.a2l": {
        "ECU_Code": ("DATA", "FLASH", 0x16000, 0x86C),
        "ECU_Data": ("DATA", "FLASH", 0x810000, 0x10000),
    },
    "ASAP2_Demo_V171.a2l": {
        "ECU_Code": ("DATA", "FLASH", 0x16000, 0x86C),
        "ECU_Data": ("DATA", "FLASH", 0x810000, 0x10000),
        "ECU_Data_Instances": ("DATA", "FLASH", 0x820000, 0x10000),
        "TRANSFORMER_CALIBRATION": ("DATA", "NOT_IN_ECU", 0x7FFF0000, 0x1000),
    },
}

#: The unquoted fixture's rows — byte-identical to today's parse (the only
#: shipped fixture that yielded full rows before the hardening, P-6).
UNQUOTED_EXPECTATIONS = {
    "AscetCode": ("CODE", "FLASH", 0x08000000, 0x0000F800),
    "AscetCalibrationRom": ("DATA", "ROM", 0x0800F800, 0x00000800),
    "Variables": ("DATA", "RAM", 0x20000000, 0x00002800),
}


@pytest.mark.parametrize("file_name", sorted(QUOTED_DEMO_EXPECTATIONS))
def test_tc682_quoted_demo_a2l_segments_parse_to_full_rows(file_name: str) -> None:
    """TC-682 (LLR-137.4): the shipped quoted ASAP2 demos yield full rows —
    every MEMORY_SEGMENT carries non-null base/size (the P-6 bug: the quoted
    multi-word long-identifier line broke the tokenizer, base/size -> null)."""
    src = CASE00 / file_name
    if not src.is_file():
        pytest.skip(f"examples/case_00_public/{file_name} not present")
    segments = extract_memory_segments(parse_a2l_file(src)["sections"])
    expected = QUOTED_DEMO_EXPECTATIONS[file_name]

    assert len(segments) == len(expected)
    for row in segments:
        usage, kind, base, size = expected[row["block_name"]]
        assert row["usage"] == usage
        assert row["kind"] == kind
        assert row["base"] == base
        assert row["base"] is not None
        assert row["size"] == size
        assert row["size"] is not None
        assert row["offset"] == -1  # the demos declare the -1 placeholder
        # The quoted long-identifier line is skipped, not misparsed:
        # the record line is the usage/kind/base/size line.
        assert row["raw_first_line"].split()[0] in {"CODE", "DATA", "VARIABLES"}


def test_tc682_unquoted_fixture_rows_parse_byte_identically() -> None:
    """TC-682 (LLR-137.4's backward-compat limb): the unquoted fixture parses
    exactly as today — same usage/kind/base/size, and the demos' placeholder
    offset (-1) is now surfaced as the new offset field."""
    src = CASE00 / "memorysegment.a2l"
    if not src.is_file():
        pytest.skip("examples/case_00_public/memorysegment.a2l not present")
    segments = extract_memory_segments(parse_a2l_file(src)["sections"])

    assert [row["block_name"] for row in segments] == list(UNQUOTED_EXPECTATIONS)
    for row in segments:
        usage, kind, base, size = UNQUOTED_EXPECTATIONS[row["block_name"]]
        assert row["usage"] == usage
        assert row["kind"] == kind
        assert row["base"] == base
        assert row["size"] == size
        assert row["offset"] == -1


def test_tc682_quoted_names_and_the_offset_field(tmp_path: Path) -> None:
    """TC-682 (LLR-137.4): a quoted multi-word name AND long identifier parse
    to a full row; the offset field (record parts[5]) lands when declared and
    stays None when the block declares none."""
    a2l = tmp_path / "quoted.a2l"
    a2l.write_text(
        "/begin PROJECT P\n/begin MODULE M\n"
        '/begin MEMORY_SEGMENT "Calib Vars Rom" ""\n'
        '    "multi word long identifier"\n'
        "    DATA ROM INTERN 0x0800F800 0x00000800 0x00000400 -1 -1 -1\n"
        "/end MEMORY_SEGMENT\n"
        '/begin MEMORY_SEGMENT Plain ""\n'
        "    CODE FLASH INTERN 0x08000000 0x0000F800\n"
        "/end MEMORY_SEGMENT\n"
        "/end MODULE\n/end PROJECT\n",
        encoding="utf-8",
    )
    segments = extract_memory_segments(parse_a2l_file(a2l)["sections"])

    assert len(segments) == 2
    quoted, plain = segments
    assert quoted["block_name"] == "Calib Vars Rom"
    assert quoted["usage"] == "DATA"
    assert quoted["kind"] == "ROM"
    assert quoted["base"] == 0x0800F800
    assert quoted["size"] == 0x00000800
    assert quoted["offset"] == 0x00000400  # parts[5] surfaced

    assert plain["block_name"] == "Plain"
    assert plain["base"] == 0x08000000
    assert plain["size"] == 0x0000F800
    assert plain["offset"] is None  # no offset declared


def test_tc682_signature_and_consumers_keep_working(tmp_path: Path) -> None:
    """TC-682 (LLR-137.4's compatibility limb): the signature is unchanged,
    the a2l_parse re-export still re-exports the same function, and the
    shipped consumers keep working — extract_a2l_tags classifies
    memory_region through the hardened (quoted) rows."""
    from s19_app.tui import a2l_parse

    assert a2l_parse.extract_memory_segments is extract_memory_segments

    a2l = tmp_path / "quoted_consumer.a2l"
    a2l.write_text(
        "/begin PROJECT P\n/begin MODULE M\n"
        "/begin MEMORY_SEGMENT CodeSeg\n"
        '    "code segment long identifier"\n'
        "    CODE FLASH INTERN 0x08000000 0x00001000 -1 -1 -1 -1 -1\n"
        "/end MEMORY_SEGMENT\n"
        "/begin MEASUREMENT InFlash\n"
        "UBYTE NO_COMPU_METHOD 0 0 0 255\n"
        "ECU_ADDRESS 0x08000080\n"
        "/end MEASUREMENT\n"
        "/end MODULE\n/end PROJECT\n",
        encoding="utf-8",
    )
    data = parse_a2l_file(a2l)
    segments = extract_memory_segments(data["sections"])
    assert segments[0]["base"] == 0x08000000  # quoted long-id did not break it
    tag = data["tags"][0]
    assert tag["memory_region"] == "flash"  # the consumer path, end to end
