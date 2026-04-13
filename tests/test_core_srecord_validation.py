from pathlib import Path

import pytest

from s19_app.core import S19File, SRecord


def _build_srecord(record_type: str, address: int, data: list[int]) -> str:
    address_length = SRecord.ADDRESS_LENGTH_MAP[record_type]
    byte_count = address_length + len(data) + 1
    address_bytes = [(address >> (8 * i)) & 0xFF for i in reversed(range(address_length))]
    checksum = (~(byte_count + sum(address_bytes) + sum(data))) & 0xFF
    return (
        f"{record_type}{byte_count:02X}{address:0{address_length * 2}X}"
        + "".join(f"{byte:02X}" for byte in data)
        + f"{checksum:02X}"
    )


def test_srecord_valid_line():
    line = _build_srecord("S1", 0x1234, [0xAA, 0xBB])

    record = SRecord(line)

    assert record.type == "S1"
    assert record.byte_count == 5
    assert record.address == 0x1234
    assert record.data == [0xAA, 0xBB]
    assert record.valid is True
    assert record.validation_errors == []


def test_srecord_length_mismatch_raises():
    valid = _build_srecord("S1", 0x1000, [0xAA, 0xBB])
    invalid = valid[:2] + "06" + valid[4:]

    with pytest.raises(ValueError, match="Length mismatch"):
        SRecord(invalid)


def test_srecord_invalid_byte_count_hex_raises():
    valid = _build_srecord("S1", 0x1000, [0xAA, 0xBB])
    invalid = valid[:2] + "ZZ" + valid[4:]

    with pytest.raises(ValueError, match="Invalid byte count hex"):
        SRecord(invalid)


def test_srecord_unsupported_type_raises():
    valid = _build_srecord("S1", 0x1000, [0xAA])
    invalid = "S4" + valid[2:]

    with pytest.raises(ValueError, match="Unsupported S-record type"):
        SRecord(invalid)


def test_srecord_invalid_data_hex_raises():
    valid = _build_srecord("S1", 0x1000, [0xAA, 0xBB])
    invalid = valid[:8] + "GG" + valid[10:]

    with pytest.raises(ValueError, match="Invalid data byte hex"):
        SRecord(invalid)


def test_srecord_invalid_address_hex_raises():
    valid = _build_srecord("S1", 0x1000, [0xAA, 0xBB])
    invalid = valid[:4] + "ZZZZ" + valid[8:]

    with pytest.raises(ValueError, match="Invalid address hex"):
        SRecord(invalid)


def test_srecord_invalid_checksum_hex_raises():
    valid = _build_srecord("S1", 0x1000, [0xAA, 0xBB])
    invalid = valid[:-2] + "ZZ"

    with pytest.raises(ValueError, match="Invalid checksum hex"):
        SRecord(invalid)


def test_srecord_checksum_mismatch_invalid():
    valid = _build_srecord("S1", 0x1000, [0xAA, 0xBB])
    invalid = valid[:-2] + "00"

    record = SRecord(invalid)

    assert record.valid is False
    assert record.validation_errors == [
        f"Checksum mismatch: expected {record._calculate_checksum():02X}, found 00"
    ]


def test_s19file_collects_errors(tmp_path: Path):
    valid = _build_srecord("S1", 0x1000, [0xAA])
    invalid_checksum = valid[:-2] + "00"
    malformed = "not-a-record"
    s19_path = tmp_path / "sample.s19"
    s19_path.write_text(
        "\n".join([valid, "", malformed, invalid_checksum]) + "\n",
        encoding="utf-8",
    )

    parsed = S19File(str(s19_path), endian="big")

    assert len(parsed.records) == 2
    assert [record.address for record in parsed.records] == [0x1000, 0x1000]
    assert [error["line_number"] for error in parsed.get_errors()] == [3, 4]
    assert parsed.get_errors()[0]["segment"] == "SRecord constructor"
    assert parsed.get_errors()[1]["segment"] == "validation"


def test_s19file_emits_load_summary_log(tmp_path: Path, caplog: pytest.LogCaptureFixture):
    valid = _build_srecord("S1", 0x1000, [0xAA])
    s19_path = tmp_path / "summary.s19"
    s19_path.write_text(valid + "\n", encoding="utf-8")

    with caplog.at_level("INFO", logger="s19_app.core"):
        S19File(str(s19_path), endian="big")

    assert any("S19 load summary:" in message for message in caplog.messages)
