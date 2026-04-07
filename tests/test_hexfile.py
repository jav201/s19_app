import pytest

from s19_app.hexfile import IntelHexFile


def _build_record(byte_count: int, address: int, record_type: int, data: list[int]) -> str:
    values = [byte_count, (address >> 8) & 0xFF, address & 0xFF, record_type] + data
    checksum = (-sum(values)) & 0xFF
    return ":" + "".join(f"{value:02X}" for value in values) + f"{checksum:02X}"


def test_hex_extended_linear_address(tmp_path):
    lines = [
        _build_record(2, 0x0000, 0x04, [0x00, 0x01]),
        _build_record(1, 0x0010, 0x00, [0xAA]),
        _build_record(0, 0x0000, 0x01, []),
    ]
    hex_path = tmp_path / "sample.hex"
    hex_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    parsed = IntelHexFile(str(hex_path))

    assert parsed.get_errors() == []
    assert parsed.memory[0x00010010] == 0xAA


def test_hex_extended_segment_address(tmp_path):
    lines = [
        _build_record(2, 0x0000, 0x02, [0x12, 0x34]),
        _build_record(1, 0x0020, 0x00, [0xBB]),
        _build_record(0, 0x0000, 0x01, []),
    ]
    hex_path = tmp_path / "segment.hex"
    hex_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    parsed = IntelHexFile(str(hex_path))

    assert parsed.get_errors() == []
    assert parsed.memory[0x12360] == 0xBB


def test_hex_start_address_records_are_ignored(tmp_path):
    lines = [
        _build_record(4, 0x0000, 0x03, [0x00, 0x00, 0x00, 0x00]),
        _build_record(4, 0x0000, 0x05, [0x00, 0x00, 0x00, 0x00]),
        _build_record(0, 0x0000, 0x01, []),
    ]
    hex_path = tmp_path / "start.hex"
    hex_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    parsed = IntelHexFile(str(hex_path))

    assert parsed.get_errors() == []


def test_hex_data_record_without_extended_address(tmp_path):
    lines = [
        _build_record(2, 0x0010, 0x00, [0xAA, 0xBB]),
        _build_record(0, 0x0000, 0x01, []),
    ]
    hex_path = tmp_path / "plain.hex"
    hex_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    parsed = IntelHexFile(str(hex_path))

    assert parsed.get_errors() == []
    assert parsed.memory == {0x0010: 0xAA, 0x0011: 0xBB}


def test_hex_missing_prefix_is_reported(tmp_path):
    hex_path = tmp_path / "bad.hex"
    hex_path.write_text("10010000214601360121470136007EFE09D2190140\n", encoding="utf-8")

    parsed = IntelHexFile(str(hex_path))

    assert parsed.get_errors()[0]["segment"] == "format"
    assert "Missing ':' prefix" in parsed.get_errors()[0]["error"]


def test_hex_parse_error_is_reported(tmp_path):
    hex_path = tmp_path / "parse.hex"
    hex_path.write_text(":01ZZ0000FE\n", encoding="utf-8")

    parsed = IntelHexFile(str(hex_path))

    assert parsed.get_errors()[0]["segment"] == "parse"


def test_hex_length_mismatch_is_reported(tmp_path):
    line = _build_record(1, 0x0010, 0x00, [0xAA])
    hex_path = tmp_path / "length.hex"
    hex_path.write_text(line[:-1] + "\n", encoding="utf-8")

    parsed = IntelHexFile(str(hex_path))

    assert parsed.get_errors()[0]["segment"] == "length"
    assert "Length mismatch" in parsed.get_errors()[0]["error"]


def test_hex_checksum_mismatch_is_reported(tmp_path):
    line = _build_record(1, 0x0010, 0x00, [0xAA])
    hex_path = tmp_path / "checksum.hex"
    hex_path.write_text(line[:-2] + "00\n", encoding="utf-8")

    parsed = IntelHexFile(str(hex_path))

    assert parsed.records[0].valid is False
    assert parsed.get_errors()[0]["segment"] == "checksum"
    assert parsed.memory[0x0010] == 0xAA


def test_hex_unsupported_record_type_is_reported(tmp_path):
    lines = [
        _build_record(0, 0x0000, 0x06, []),
        _build_record(0, 0x0000, 0x01, []),
    ]
    hex_path = tmp_path / "unsupported.hex"
    hex_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    parsed = IntelHexFile(str(hex_path))

    assert parsed.get_errors()[0]["segment"] == "type"
    assert "Unsupported record type: 06" in parsed.get_errors()[0]["error"]


def test_hex_invalid_extended_segment_length_is_reported(tmp_path):
    lines = [
        _build_record(1, 0x0000, 0x02, [0x12]),
        _build_record(0, 0x0000, 0x01, []),
    ]
    hex_path = tmp_path / "segment_bad.hex"
    hex_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    parsed = IntelHexFile(str(hex_path))

    assert parsed.get_errors()[0]["segment"] == "type"
    assert "extended segment address record length" in parsed.get_errors()[0]["error"]


def test_hex_invalid_extended_linear_length_is_reported(tmp_path):
    lines = [
        _build_record(1, 0x0000, 0x04, [0x12]),
        _build_record(0, 0x0000, 0x01, []),
    ]
    hex_path = tmp_path / "linear_bad.hex"
    hex_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    parsed = IntelHexFile(str(hex_path))

    assert parsed.get_errors()[0]["segment"] == "type"
    assert "extended linear address record length" in parsed.get_errors()[0]["error"]


def test_hex_get_ranges_groups_contiguous_addresses(tmp_path):
    lines = [
        _build_record(2, 0x0010, 0x00, [0xAA, 0xBB]),
        _build_record(1, 0x0012, 0x00, [0xCC]),
        _build_record(1, 0x0020, 0x00, [0xDD]),
        _build_record(0, 0x0000, 0x01, []),
    ]
    hex_path = tmp_path / "ranges.hex"
    hex_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    parsed = IntelHexFile(str(hex_path))

    assert parsed.get_ranges() == [(0x0010, 0x0013), (0x0020, 0x0021)]


def test_hex_missing_file_raises(tmp_path):
    missing = tmp_path / "missing.hex"

    with pytest.raises(FileNotFoundError):
        IntelHexFile(str(missing))
