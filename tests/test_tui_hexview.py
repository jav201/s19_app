from pathlib import Path
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


# ---------------------------------------------------------------------------
# Phase 3 increment 7 -- LLR-003.2 / TC-023 hex-view rendering invariants
# ---------------------------------------------------------------------------
#
# LLR-003.2 acceptance bullets:
#   * MAX_HEX_BYTES, MAX_HEX_ROWS, FOCUS_CONTEXT_ROWS, HEX_WIDTH, SEARCH_ENCODING
#     exported from s19_app.tui are the ONLY knobs governing render_hex_view_text /
#     find_string_in_mem / _collect_hex_rows.
#   * No caller in s19_app/tui/app.py references private helpers from hexview.
#
# Existing tests in this file already cover ``_collect_hex_rows`` truncation,
# focus-context insertion, and search wiring. The additions below close the
# remaining acceptance bullets: monkey-patching each constant must change the
# observable behaviour of the corresponding entry-point, and an inspection
# guard catches any future ``app.py`` import of a private hexview helper.


def test_tc_023_search_encoding_is_the_only_knob_for_find_string_in_mem(monkeypatch):
    """Patching SEARCH_ENCODING propagates into find_string_in_mem."""
    import s19_app.tui.hexview as hexview

    # ASCII-only by default: a non-ascii needle returns None.
    mem_map = {0x1000 + i: b for i, b in enumerate("café".encode("utf-8"))}
    assert hexview.find_string_in_mem(mem_map, "café") is None

    # Switch the constant to UTF-8 and the same needle now resolves.
    monkeypatch.setattr(hexview, "SEARCH_ENCODING", "utf-8")
    assert hexview.find_string_in_mem(mem_map, "café") == 0x1000


def test_tc_023_max_hex_rows_caps_collect_hex_rows(monkeypatch):
    """MAX_HEX_ROWS is the upper bound used by _collect_hex_rows when no max_rows is given."""
    import s19_app.tui.hexview as hexview

    # Build enough memory to need many rows.
    mem_map = {0x1000 + i: 0x41 for i in range(hexview.HEX_WIDTH * 32)}
    monkeypatch.setattr(hexview, "MAX_HEX_ROWS", 4)

    lines, rows = hexview._collect_hex_rows(mem_map)
    assert len(rows) == 4
    assert any("window limited to 4 rows" in line for line in lines)


def test_tc_023_focus_context_rows_drives_focus_window(monkeypatch):
    """FOCUS_CONTEXT_ROWS controls the leading window when a focus_address is given."""
    import s19_app.tui.hexview as hexview

    mem_map = {addr: 0x41 for addr in range(0x1000, 0x1000 + hexview.HEX_WIDTH * 80)}
    focus = 0x1000 + (hexview.HEX_WIDTH * 70)

    # Wide context: the window starts well before ``focus`` (default = 64 rows).
    text_default = hexview.render_hex_view(mem_map, focus)
    assert "context preserved" in text_default

    # Tighten the context window to just 2 rows; the window should now start
    # closer to ``focus`` (roughly focus - 2 * HEX_WIDTH).
    monkeypatch.setattr(hexview, "FOCUS_CONTEXT_ROWS", 2)
    text_tight = hexview.render_hex_view(mem_map, focus)
    expected_start = focus - (2 * hexview.HEX_WIDTH)
    assert f"0x{expected_start:08X}" in text_tight


def test_tc_023_max_hex_bytes_truncation_is_governed_by_constant(monkeypatch):
    """MAX_HEX_BYTES is the byte budget that triggers the 'output truncated' line."""
    import s19_app.tui.hexview as hexview

    # Pin MAX_HEX_BYTES low (multiple of HEX_WIDTH) so the truncation message wins
    # over the row-count message.
    monkeypatch.setattr(hexview, "MAX_HEX_BYTES", hexview.HEX_WIDTH * 2)
    monkeypatch.setattr(hexview, "MAX_HEX_ROWS", 1024)
    mem_map = {0x1000 + i: 0x41 for i in range(hexview.HEX_WIDTH * 8)}

    text = hexview.render_hex_view(mem_map)
    assert f"output truncated at {hexview.HEX_WIDTH * 2} bytes" in text


def test_tc_023_hex_width_governs_row_alignment(monkeypatch):
    """HEX_WIDTH is the only knob that decides the row anchor stride."""
    import s19_app.tui.hexview as hexview

    # Force an 8-byte stride. build_row_bases anchors at addr - (addr % HEX_WIDTH).
    monkeypatch.setattr(hexview, "HEX_WIDTH", 8)

    mem_map = {0x1009: 0x41, 0x100F: 0x42, 0x1010: 0x43}
    bases = hexview.build_row_bases(mem_map)
    assert bases == [0x1008, 0x1010]


def test_tc_023_app_does_not_import_private_hexview_helpers():
    """LLR-003.2: no caller in app.py reaches into private hexview helpers."""
    import s19_app.tui.app as app

    # Iterate the AST instead of regex-grepping the source so a multi-line or
    # aliased import is still caught.
    import ast

    source = Path(app.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    private_imports: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            if node.module.endswith("tui.hexview") or node.module == "s19_app.tui.hexview":
                for alias in node.names:
                    if alias.name.startswith("_"):
                        private_imports.append(alias.name)
    assert private_imports == [], (
        f"app.py imports private hexview helpers: {private_imports} -- LLR-003.2 violation"
    )
