from types import SimpleNamespace

from s19_app.tui.hexview import (
    _collect_hex_rows,
    build_mem_map_s19,
    build_range_validity_hex,
    build_range_validity_s19,
    build_row_bases,
    render_hex_view_text,
)


def test_build_mem_map_s19_flattens_record_bytes():
    s19 = SimpleNamespace(
        records=[
            SimpleNamespace(address=0x1000, data=[0x41, 0x42]),
            SimpleNamespace(address=0x1002, data=[0x43]),
        ]
    )

    assert build_mem_map_s19(s19) == {0x1000: 0x41, 0x1001: 0x42, 0x1002: 0x43}


def test_build_range_validity_s19_marks_invalid_ranges():
    s19 = SimpleNamespace(
        records=[
            SimpleNamespace(address=0x1000, data=[0xAA, 0xBB], valid=True),
            SimpleNamespace(address=0x1002, data=[0xCC], valid=False),
        ]
    )

    validity = build_range_validity_s19(s19, [(0x1000, 0x1002), (0x1002, 0x1003), (0x2000, 0x2001)])

    assert validity == [True, False, True]


def test_build_range_validity_hex_reflects_loader_errors():
    hex_file = SimpleNamespace(get_errors=lambda: [{"segment": "checksum", "error": "Checksum mismatch"}])

    assert build_range_validity_hex(hex_file, [(0x1000, 0x1001), (0x2000, 0x2001)]) == [False, False]


def test_build_row_bases_aligns_and_sorts_rows():
    mem_map = {0x1011: 0x41, 0x100F: 0x42, 0x1020: 0x43}

    assert build_row_bases(mem_map) == [0x1000, 0x1010, 0x1020]


def test_collect_hex_rows_reports_missing_focus_address():
    mem_map = {0x1000 + i: 0x41 for i in range(4)}

    lines, rows = _collect_hex_rows(mem_map, focus_address=0x2000)

    assert "... address 0x00002000 not present ..." in lines
    assert rows[0][0] == 0x1000


def test_collect_hex_rows_honors_start_and_row_limit():
    mem_map = {0x1000 + i: 0x41 for i in range(16 * 8)}
    row_bases = build_row_bases(mem_map)

    lines, rows = _collect_hex_rows(mem_map, row_bases=row_bases, start_row_index=3, max_rows=2)

    assert rows[0][0] == 0x1030
    assert len(rows) == 2
    assert "... window limited to 2 rows ..." in lines


def test_render_hex_view_text_highlights_match_range():
    mem_map = {0x1000: ord("A"), 0x1001: ord("B"), 0x1002: ord("C")}

    text = render_hex_view_text(mem_map, focus_address=0x1000, row_bases=None, highlight=(0x1001, 2))

    assert "0x00001000" in text.plain
    assert "|ABC" in text.plain
    assert any("bold yellow" in str(span.style) for span in text.spans)
