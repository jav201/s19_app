from __future__ import annotations

import io

import pytest

pytest.importorskip("flask")

from s19_app.tui.hexview import build_row_bases, format_hex_row_lines
from s19_app.web.app import create_app


def _minimal_intel_hex() -> str:
    """One data byte at linear address 0x00010010 (extended linear 0x0001 + offset 0x0010)."""
    def rec(byte_count: int, address: int, record_type: int, data: list[int]) -> str:
        values = [byte_count, (address >> 8) & 0xFF, address & 0xFF, record_type] + data
        checksum = (-sum(values)) & 0xFF
        return ":" + "".join(f"{v:02X}" for v in values) + f"{checksum:02X}"

    lines = [
        rec(2, 0x0000, 0x04, [0x00, 0x01]),
        rec(1, 0x0010, 0x00, [0xAA]),
        rec(0, 0x0000, 0x01, []),
    ]
    return "\n".join(lines) + "\n"


@pytest.fixture
def client(tmp_path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.chdir(tmp_path)
    app = create_app({"TESTING": True, "SECRET_KEY": "test-secret", "HEX_INITIAL_ROWS": 64})
    with app.test_client() as c:
        yield c


def test_format_hex_row_lines_past_end_returns_empty() -> None:
    mem = {0x1000: 0x01, 0x1001: 0x02}
    bases = build_row_bases(mem)
    lines, total = format_hex_row_lines(mem, bases, start_index=len(bases), row_count=10)
    assert lines == []
    assert total == len(bases)


def test_upload_hex_and_hex_rows_api(client):
    data = (io.BytesIO(_minimal_intel_hex().encode("ascii")), "sample.hex")
    resp = client.post("/upload", data={"data_file": data}, content_type="multipart/form-data")
    assert resp.status_code == 302
    assert "/view" in resp.headers.get("Location", "")

    view = client.get("/view")
    assert view.status_code == 200
    assert b"0x00010010" in view.data

    api = client.get("/api/hex-rows?start=0&count=50")
    assert api.status_code == 200
    payload = api.get_json()
    assert payload["total_rows"] >= 1
    assert len(payload["lines"]) >= 1
    assert "0x00010010" in payload["lines"][0]


def test_goto_api(client):
    data = (io.BytesIO(_minimal_intel_hex().encode("ascii")), "sample.hex")
    client.post("/upload", data={"data_file": data}, content_type="multipart/form-data")
    resp = client.post("/api/goto", json={"addr": "0x00010010"})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["found"] is True
    assert body["row_index"] >= 0
