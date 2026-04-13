from pathlib import Path

import pytest

from s19_app.tui.mac import parse_mac_file


def test_parse_mac_file_emits_summary_log(tmp_path: Path, caplog: pytest.LogCaptureFixture):
    mac_path = tmp_path / "sample.mac"
    mac_path.write_text("RPM=0x1000\nTORQUE=0x2000\n", encoding="utf-8")

    with caplog.at_level("INFO"):
        parsed = parse_mac_file(mac_path)

    assert len(parsed["records"]) == 2
    assert any("MAC parse summary:" in message for message in caplog.messages)
