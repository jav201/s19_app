from types import SimpleNamespace

from s19_app.tui.hexview import (
    _collect_hex_rows,
    address_in_sorted_ranges,
    build_mem_map_s19,
    build_range_validity_hex,
    build_range_validity_s19,
    build_row_bases,
    build_sorted_range_index,
    range_in_sorted_ranges,
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


def test_build_sorted_range_index_empty_returns_empty_pair():
    assert build_sorted_range_index([]) == ([], [])


def test_build_sorted_range_index_sorts_by_start():
    starts, ends = build_sorted_range_index([(0x2000, 0x2010), (0x1000, 0x1010)])

    assert starts == [0x1000, 0x2000]
    assert ends == [0x1010, 0x2010]


def test_address_in_sorted_ranges_boundary_cases():
    index = build_sorted_range_index([(0x1000, 0x1010), (0x2000, 0x2020)])

    assert address_in_sorted_ranges(0x0FFF, index) is False
    assert address_in_sorted_ranges(0x1000, index) is True
    assert address_in_sorted_ranges(0x100F, index) is True
    assert address_in_sorted_ranges(0x1010, index) is False
    assert address_in_sorted_ranges(0x1800, index) is False
    assert address_in_sorted_ranges(0x2000, index) is True
    assert address_in_sorted_ranges(0x201F, index) is True
    assert address_in_sorted_ranges(0x2020, index) is False


def test_address_in_sorted_ranges_empty_index_is_false():
    assert address_in_sorted_ranges(0x1000, ([], [])) is False


def test_address_in_sorted_ranges_single_range():
    index = build_sorted_range_index([(0x4000, 0x4004)])

    assert address_in_sorted_ranges(0x3FFF, index) is False
    assert address_in_sorted_ranges(0x4003, index) is True
    assert address_in_sorted_ranges(0x4004, index) is False


def test_range_in_sorted_ranges_span_containment():
    index = build_sorted_range_index([(0x1000, 0x1010), (0x2000, 0x2020)])

    assert range_in_sorted_ranges(0x1000, 0x10, index) is True
    assert range_in_sorted_ranges(0x1000, 0x11, index) is False
    assert range_in_sorted_ranges(0x100F, 0x01, index) is True
    assert range_in_sorted_ranges(0x100F, 0x02, index) is False
    assert range_in_sorted_ranges(0x1FFF, 0x21, index) is False
    assert range_in_sorted_ranges(0x2000, 0, index) is False
    assert range_in_sorted_ranges(0x2000, -1, index) is False


def test_collect_hex_rows_reuses_row_bases_when_no_extras():
    mem_map = {0x1000 + i: 0x41 for i in range(32)}
    row_bases = build_row_bases(mem_map)
    sentinel = [*row_bases]

    lines, rows = _collect_hex_rows(mem_map, row_bases=row_bases, extra_addresses=None)

    assert rows[0][0] == 0x1000
    assert row_bases == sentinel


def test_collect_hex_rows_fast_path_when_extras_already_covered():
    mem_map = {0x1000 + i: 0x41 for i in range(32)}
    row_bases = build_row_bases(mem_map)

    lines, rows = _collect_hex_rows(
        mem_map,
        row_bases=row_bases,
        extra_addresses={0x1005, 0x1011},
    )

    assert [addr for addr, _ in rows] == [0x1000, 0x1010]


def test_collect_hex_rows_adds_new_bases_when_extras_outside_row_bases():
    mem_map = {0x1000 + i: 0x41 for i in range(16)}
    row_bases = build_row_bases(mem_map)

    lines, rows = _collect_hex_rows(
        mem_map,
        row_bases=row_bases,
        extra_addresses={0x2005},
    )

    assert [addr for addr, _ in rows] == [0x1000, 0x2000]


def test_collect_hex_rows_uses_row_bases_set_without_rebuilding():
    """When extras are covered, the caller-provided membership set must drive the fast path even when ``row_bases`` is not a set."""
    import s19_app.tui.hexview as hexview

    mem_map = {0x1000 + i: 0x41 for i in range(32)}
    row_bases = build_row_bases(mem_map)

    real_set = set
    call_count = {"n": 0}

    def _tracking_set(*args, **kwargs):
        call_count["n"] += 1
        return real_set(*args, **kwargs)

    original_set = hexview.__builtins__["set"] if isinstance(hexview.__builtins__, dict) else set  # noqa: F841
    try:
        hexview.set = _tracking_set  # type: ignore[attr-defined]
        lines, rows = _collect_hex_rows(
            mem_map,
            row_bases=row_bases,
            extra_addresses={0x1005, 0x1011},
            row_bases_set=frozenset(row_bases),
        )
    finally:
        if hasattr(hexview, "set"):
            delattr(hexview, "set")

    assert [addr for addr, _ in rows] == row_bases
    # The fast path uses ``row_bases_set`` directly without constructing a new ``set(base_row_bases)``.
    assert call_count["n"] == 0


def test_collect_hex_rows_without_row_bases_set_still_rebuilds():
    """Without ``row_bases_set``, ``set(base_row_bases)`` is constructed as before (regression guard)."""
    import s19_app.tui.hexview as hexview

    mem_map = {0x1000 + i: 0x41 for i in range(32)}
    row_bases = build_row_bases(mem_map)

    real_set = set
    call_count = {"n": 0}

    def _tracking_set(*args, **kwargs):
        call_count["n"] += 1
        return real_set(*args, **kwargs)

    try:
        hexview.set = _tracking_set  # type: ignore[attr-defined]
        _collect_hex_rows(mem_map, row_bases=row_bases, extra_addresses={0x1005, 0x1011})
    finally:
        if hasattr(hexview, "set"):
            delattr(hexview, "set")

    # Without an injected membership set, the legacy fast path rebuilds one per call.
    assert call_count["n"] >= 1


def test_collect_hex_rows_row_bases_set_merges_when_extras_outside():
    """If extras fall outside row_bases_set, the union is computed from provided bases."""
    mem_map = {0x1000 + i: 0x41 for i in range(16)}
    row_bases = build_row_bases(mem_map)
    injected = frozenset(row_bases)

    lines, rows = _collect_hex_rows(
        mem_map,
        row_bases=row_bases,
        extra_addresses={0x2005},
        row_bases_set=injected,
    )

    assert [addr for addr, _ in rows] == [0x1000, 0x2000]


def test_render_hex_view_text_accepts_row_bases_set():
    """``render_hex_view_text`` forwards ``row_bases_set`` into ``_collect_hex_rows``."""
    mem_map = {0x1000 + i: 0x41 for i in range(16)}
    row_bases = build_row_bases(mem_map)
    text = render_hex_view_text(
        mem_map,
        focus_address=None,
        row_bases=row_bases,
        highlight=None,
        mac_highlight_addresses={0x1005},
        row_bases_set=frozenset(row_bases),
    )
    rendered = text.plain
    assert "0x00001000" in rendered
