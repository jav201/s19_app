"""Tests for the TUI MAC view over the MAC parser.

Batch-91 contract adoption (HLR-122):
# TC-627 — this module pins the MAC parser's TAG=hexaddr reading behind the MAC View (LLR-122.3).
"""

import re
from pathlib import Path

import pytest

from s19_app.tui.mac import parse_mac_file


def test_parse_mac_file_emits_summary_log(tmp_path: Path, caplog: pytest.LogCaptureFixture):
    """Traces: R-MAC-012."""
    mac_path = tmp_path / "sample.mac"
    mac_path.write_text("RPM=0x1000\nTORQUE=0x2000\n", encoding="utf-8")

    with caplog.at_level("INFO"):
        parsed = parse_mac_file(mac_path)

    assert len(parsed["records"]) == 2
    summary = re.compile(
        r"MAC parse summary: path=.+ rows=2 parse_ok=\d+ diagnostics=\d+ valid_addresses=\d+"
    )
    assert any(summary.fullmatch(message) for message in caplog.messages), caplog.messages
