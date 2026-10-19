"""TC-1820 / TC-1821 / TC-1822 — E9: A2L parameter description (curves).

Pendiente E9 of the operator's batch-96 PDF (``PENDIENTES-batch96.md`` §3):
a DESCRIPTION of a CHARACTERISTIC of type CURVE/MAP that combines the A2L
metadata (name, COMPU_METHOD long identifier, unit, limits, conversion
type, per-axis kind/max points) with the current S19/HEX values — axis
points and FNC_VALUES decoded from the image bytes at the R5-walked
RECORD_LAYOUT component offsets and converted to physical units point by
point (the shipped ``_apply_compu_method`` + ``_table_lookup``).

- TC-1820 — the description resolves: an inline CURVE (a layout whose axis
  deposit is the ``NO_AXIS_PTS`` placeholder, and a layout with inline
  ``AXIS_PTS_X``) with a LINEAR COMPU_METHOD carrying a long identifier
  yields unit/limits/description, and a point table whose physical y
  values are hand-computed (y = 2·raw + 10); an external COM_AXIS whose
  ``AXIS_PTS_REF`` resolves also yields its point table.
- TC-1821 — a ``TAB_INTP`` COMPU_TAB conversion applies point by point
  (exact hits and mid-interval interpolations, hand-computed); a value
  outside the declared limits is flagged, never rejected.
- TC-1822 — the honest limbs: an unresolvable layout, an external axis
  with a dangling ``AXIS_PTS_REF``, and a scalar VALUE (regression) all
  produce a status + notes payload — never an exception, never invented
  points.

Black-box ATs drive the shipped ``parse_a2l_file`` surface and assert the
concrete decoded/converted numbers; white-box pins the additive
``long_identifier`` extraction on the COMPU_METHOD side table. Oracle
values were executed over the shipped walker/conversion at draft time.
"""

from pathlib import Path

from s19_app.tui.a2l import (
    describe_curve_tag,
    render_curve_description,
    parse_a2l_file,
)

_PROLOGUE = (
    'ASAP2_VERSION 1 71\n'
    '/begin PROJECT P "syn"\n'
    '  /begin MODULE M "syn"\n'
)
_EPILOGUE = "  /end MODULE\n/end PROJECT\n"

#: NO_AXIS_PTS axis deposit: one placeholder byte, then 3 UWORD values.
_LAYOUT_NO_AXIS = """    /begin RECORD_LAYOUT RL_NOAX
      NO_AXIS_PTS_X 1 UBYTE
      FNC_VALUES 2 UWORD ROW_DIR
    /end RECORD_LAYOUT
"""

#: Inline axis deposit: 3 axis bytes, an ALIGNMENT_WORD pad, 3 UWORD values.
_LAYOUT_CURVE3 = """    /begin RECORD_LAYOUT RL_CURVE3
      AXIS_PTS_X 1 UBYTE
      ALIGNMENT_WORD 2
      FNC_VALUES 2 UWORD ROW_DIR
    /end RECORD_LAYOUT
"""

#: The TC-1810 external-axis layout: 4 UWORD axis slots + 4 UWORD values.
_LAYOUT_EXTERNAL = """    /begin RECORD_LAYOUT RL_EXT
      AXIS_PTS_X 1 UWORD
      FNC_VALUES 2 UWORD ROW_DIR
    /end RECORD_LAYOUT
"""

#: LINEAR "phys = 2 raw + 10" with a long identifier, unit rpm.
_COMPU_LINEAR = """    /begin COMPU_METHOD CM_lin "speed linear scale"
      LINEAR "%.1" "rpm"
      COEFFS_LINEAR 2.0 10.0
    /end COMPU_METHOD
"""

#: TAB_INTP lookup: mid-interval interpolation is hand-computable.
_COMPU_TAB = """    /begin COMPU_METHOD CM_tab "temperature table"
      TAB_INTP "%.2" "deg"
      COMPU_TAB_REF T1
    /end COMPU_METHOD
    /begin COMPU_TAB T1 "temp table"
      TAB_INTP
      0 0.0
      100 50.0
      200 200.0
      300 450.0
    /end COMPU_TAB
"""


def _write(tmp_path: Path, name: str, body: str) -> dict:
    path = tmp_path / name
    path.write_text(_PROLOGUE + body + _EPILOGUE, encoding="utf-8")
    return parse_a2l_file(path)


def _char_tags(data: dict) -> dict:
    return {t["name"]: t for t in data["tags"] if t.get("section") == "CHARACTERISTIC"}


def _mem_map(address: int, record: bytes) -> dict:
    return {address + offset: byte for offset, byte in enumerate(record)}


# ---------------------------------------------------------------------------
# TC-1820 — the description resolves: header fields + hand-computed table.
# ---------------------------------------------------------------------------


def test_tc1820_curve_description_no_axis_pts_linear(tmp_path: Path) -> None:
    """NO_AXIS_PTS inline curve: header (unit/limits/description) resolves
    and the 3-point table carries physical y = 2·raw + 10; x is the honest
    point index because the layout deposits no axis points."""
    body = (
        _LAYOUT_NO_AXIS
        + _COMPU_LINEAR
        + '    /begin CHARACTERISTIC C1 "curve one"\n'
        "      CURVE 0x9200 RL_NOAX 0 CM_lin 0 1000\n"
        "      /begin AXIS_DESCR\n"
        "        STD_AXIS NO_INPUT NO_COMPU_METHOD 3 0 255\n"
        "      /end AXIS_DESCR\n"
        "    /end CHARACTERISTIC\n"
    )
    data = _write(tmp_path, "desc_noax.a2l", body)
    tag = _char_tags(data)["C1"]
    # 1 placeholder byte + 3 little-endian UWORDs 100/200/300.
    record = bytes([0xEE, 100, 0, 200, 0, 44, 1])
    assert tag["length"] == 7
    description = describe_curve_tag(tag, data, _mem_map(0x9200, record))

    # White-box on the additive extraction: the COMPU_METHOD long identifier
    # (the quoted description on the /begin line) now rides the side table.
    assert data["compu_methods_by_name"]["CM_lin"]["long_identifier"] == "speed linear scale"

    assert description["status"] == "ok"
    assert description["name"] == "C1"
    assert description["long_identifier"] == "curve one"
    assert description["unit"] == "rpm"
    assert description["lower_limit"] == 0.0
    assert description["upper_limit"] == 1000.0
    assert description["conversion_type"] == "LINEAR"
    assert description["compu_method_name"] == "CM_lin"
    assert description["compu_description"] == "speed linear scale"
    assert description["axes"][0]["kind"] == "STD_AXIS"
    assert description["axes"][0]["max_axis_points"] == 3
    assert description["axes"][0]["external"] is False

    points = description["points"]
    assert points is not None and len(points) == 3
    # y = 2·raw + 10, raw 100/200/300 → 210/410/610; x is the point index.
    assert [(p["x"], p["y"]) for p in points] == [(0, 210.0), (1, 410.0), (2, 610.0)]
    assert [p["y_raw"] for p in points] == [100, 200, 300]
    assert all(p["x_note"] for p in points)
    assert all(p["outside_limits"] is False for p in points)
    assert any("NO_AXIS_PTS" in note for note in description["notes"])

    rendered = render_curve_description(description)
    assert "rpm" in rendered and "speed linear scale" in rendered
    assert "210" in rendered and "610" in rendered
    assert "index (axis points unavailable)" in rendered


def test_tc1820_curve_description_axis_pts_inline(tmp_path: Path) -> None:
    """Inline AXIS_PTS_X curve: the axis bytes decode from the record itself,
    so the table pairs the physical axis points x = 10/20/30 with
    y = 2·raw + 10 = 210/410/610 — a true x→y table, no index notes."""
    body = (
        _LAYOUT_CURVE3
        + _COMPU_LINEAR
        + '    /begin CHARACTERISTIC C3 "three point curve"\n'
        "      CURVE 0x9300 RL_CURVE3 0 CM_lin 0 1000\n"
        "      /begin AXIS_DESCR\n"
        "        STD_AXIS NO_INPUT NO_COMPU_METHOD 3 0 255\n"
        "      /end AXIS_DESCR\n"
    "    /end CHARACTERISTIC\n"
    )
    data = _write(tmp_path, "desc_inline.a2l", body)
    tag = _char_tags(data)["C3"]
    # 3 axis bytes, one ALIGNMENT_WORD pad, 3 little-endian UWORDs 100/200/300.
    record = bytes([10, 20, 30, 0, 100, 0, 200, 0, 44, 1])
    assert tag["length"] == 10
    description = describe_curve_tag(tag, data, _mem_map(0x9300, record))

    assert description["status"] == "ok"
    points = description["points"]
    assert points is not None and len(points) == 3
    assert [(p["x"], p["y"]) for p in points] == [(10, 210.0), (20, 410.0), (30, 610.0)]
    assert [p["x_raw"] for p in points] == [10, 20, 30]
    assert all(p["x_note"] is None for p in points)
    assert description["axes"][0]["points_raw"] == [10, 20, 30]

    rendered = render_curve_description(description)
    assert "10" in rendered and "610" in rendered
    # the optional Unicode-block sparkline rides along when y varies
    assert "y shape:" in rendered


def test_tc1820_external_axis_points_resolved(tmp_path: Path) -> None:
    """A COM_AXIS whose AXIS_PTS_REF resolves derives its count (4) from the
    referenced AXIS_PTS record and decodes the full 16-byte record: 4 axis
    UWORDs + 4 function UWORDs pair into the table (identity conversion)."""
    body = (
        _LAYOUT_EXTERNAL
        + '    /begin CHARACTERISTIC AXIS_SRC "axis points"\n'
        "      VALUE 0x9000 RL_EXT 0 NO_COMPU_METHOD 0 255\n"
        "      /begin AXIS_DESCR\n"
        "        STD_AXIS NO_INPUT NO_COMPU_METHOD 4 0 255\n"
        "      /end AXIS_DESCR\n"
        "    /end CHARACTERISTIC\n"
        + '    /begin CHARACTERISTIC CURVE_EXT "curve external"\n'
        "      CURVE 0x9100 RL_EXT 0 NO_COMPU_METHOD 0 255\n"
        "      /begin AXIS_DESCR\n"
        "        COM_AXIS NO_INPUT NO_COMPU_METHOD 8 0 255\n"
        "        AXIS_PTS_REF AXIS_SRC\n"
        "      /end AXIS_DESCR\n"
        "    /end CHARACTERISTIC\n"
    )
    data = _write(tmp_path, "desc_external.a2l", body)
    tag = _char_tags(data)["CURVE_EXT"]
    assert tag["length"] == 16
    axis_le = b"".join(v.to_bytes(2, "little") for v in (10, 20, 30, 40))
    fnc_le = b"".join(v.to_bytes(2, "little") for v in (100, 200, 300, 400))
    description = describe_curve_tag(tag, data, _mem_map(0x9100, axis_le + fnc_le))

    assert description["status"] == "ok"
    axis = description["axes"][0]
    assert axis["external"] is True
    assert axis["max_axis_points"] == 4
    points = description["points"]
    assert points is not None and len(points) == 4
    assert [(p["x"], p["y"]) for p in points] == [
        (10, 100), (20, 200), (30, 300), (40, 400)
    ]


# ---------------------------------------------------------------------------
# TC-1821 — COMPU_TAB point by point + the outside-limits flag.
# ---------------------------------------------------------------------------


def test_tc1821_compu_tab_applied_point_by_point(tmp_path: Path) -> None:
    """TAB_INTP: raw 50/150/250 interpolate mid-interval to 25/125/325
    (hand-computed over the 0-100-200-300 breakpoints); the axis stays
    raw; a value above the declared upper limit 200 is flagged - the
    description never rejects it."""
    body = (
        _LAYOUT_CURVE3
        + _COMPU_TAB
        + '    /begin CHARACTERISTIC CT "tab curve"\n'
        "      CURVE 0x9400 RL_CURVE3 0 CM_tab 0 200\n"
        "      /begin AXIS_DESCR\n"
        "        STD_AXIS NO_INPUT NO_COMPU_METHOD 3 0 255\n"
        "      /end AXIS_DESCR\n"
        "    /end CHARACTERISTIC\n"
    )
    data = _write(tmp_path, "desc_tab.a2l", body)
    tag = _char_tags(data)["CT"]
    record = bytes([10, 20, 30, 0, 50, 0, 150, 0, 250, 0])
    description = describe_curve_tag(tag, data, _mem_map(0x9400, record))

    assert description["status"] == "ok"
    assert description["conversion_type"] == "TAB_INTP"
    assert description["unit"] == "deg"
    assert description["compu_description"] == "temperature table"
    points = description["points"]
    assert points is not None and len(points) == 3
    # (50→25.0) between (0,0)/(100,50); (150→125.0) between (100,50)/
    # (200,200); (250→325.0) between (200,200)/(300,450) - all mid-interval.
    assert [p["y"] for p in points] == [25.0, 125.0, 325.0]
    assert [p["x"] for p in points] == [10, 20, 30]
    # the last value (325) is above the declared upper limit 200 - flagged.
    assert [p["outside_limits"] for p in points] == [False, False, True]

    rendered = render_curve_description(description)
    assert "(!)" in rendered
    assert "outside the tag's declared limits" in rendered


def test_tc1821_compu_tab_exact_hits_and_lookup(tmp_path: Path) -> None:
    """TAB_INTP exact breakpoint hits convert to the tabulated y verbatim;
    a raw value below the first breakpoint clamps to the first entry."""
    body = (
        _LAYOUT_NO_AXIS
        + _COMPU_TAB
        + '    /begin CHARACTERISTIC CX "tab exact"\n'
        "      CURVE 0x9500 RL_NOAX 0 CM_tab 0 10000\n"
        "      /begin AXIS_DESCR\n"
        "        STD_AXIS NO_INPUT NO_COMPU_METHOD 3 0 255\n"
        "      /end AXIS_DESCR\n"
        "    /end CHARACTERISTIC\n"
    )
    data = _write(tmp_path, "desc_tab_exact.a2l", body)
    tag = _char_tags(data)["CX"]
    # placeholder byte + raw 0/100/25: exact 0→0.0, exact 100→50.0,
    # 25 mid-interval between (0,0)/(100,50) → 12.5.
    record = bytes([0, 0, 0, 100, 0, 25, 0])
    description = describe_curve_tag(tag, data, _mem_map(0x9500, record))

    assert description["status"] == "ok"
    assert [p["y"] for p in description["points"]] == [0.0, 50.0, 12.5]


# ---------------------------------------------------------------------------
# TC-1822 — honest limbs: nothing resolves to invented data; VALUE regression.
# ---------------------------------------------------------------------------


def test_tc1822_unknown_layout_honest_status(tmp_path: Path) -> None:
    """A CURVE whose deposit names no RECORD_LAYOUT answers layout_unresolved
    with the layout named in the notes - no points, no exception."""
    body = (
        '    /begin CHARACTERISTIC C_UNK "curve unknown layout"\n'
        "      CURVE 0x9600 NO_SUCH_LAYOUT 0 NO_COMPU_METHOD 0 255\n"
        "      /begin AXIS_DESCR\n"
        "        STD_AXIS NO_INPUT NO_COMPU_METHOD 3 0 255\n"
        "      /end AXIS_DESCR\n"
        "    /end CHARACTERISTIC\n"
    )
    data = _write(tmp_path, "desc_unknown.a2l", body)
    tag = _char_tags(data)["C_UNK"]
    description = describe_curve_tag(tag, data, {})

    assert description["status"] == "layout_unresolved"
    assert description["points"] is None
    assert any("NO_SUCH_LAYOUT" in note for note in description["notes"])
    rendered = render_curve_description(description)
    assert "Status: layout_unresolved" in rendered


def test_tc1822_dangling_external_axis_honest_status(tmp_path: Path) -> None:
    """A COM_AXIS with a dangling AXIS_PTS_REF cannot resolve its count
    (full-span-or-None) - the description says axes_unresolved and never
    invents a point count."""
    body = (
        _LAYOUT_EXTERNAL
        + '    /begin CHARACTERISTIC C_DANGLING "curve dangling"\n'
        "      CURVE 0x9700 RL_EXT 0 NO_COMPU_METHOD 0 255\n"
        "      /begin AXIS_DESCR\n"
        "        COM_AXIS NO_INPUT NO_COMPU_METHOD 8 0 255\n"
        "        AXIS_PTS_REF NO_SUCH_AXIS_PTS\n"
        "      /end AXIS_DESCR\n"
        "    /end CHARACTERISTIC\n"
    )
    data = _write(tmp_path, "desc_dangling.a2l", body)
    tag = _char_tags(data)["C_DANGLING"]
    assert tag["length"] is None
    description = describe_curve_tag(tag, data, {})

    assert description["status"] == "axes_unresolved"
    assert description["points"] is None
    assert any("AXIS_PTS_REF" in note or "external" in note.lower()
               for note in description["notes"])
    assert "Status: axes_unresolved" in render_curve_description(description)


def test_tc1822_scalar_value_not_a_curve_regression(tmp_path: Path) -> None:
    """A scalar VALUE is not a CURVE/MAP: the description carries the honest
    not_a_curve status and the header fields - never a crash, never a table."""
    body = (
        "    /begin RECORD_LAYOUT RL_U16\n"
        "      FNC_VALUES 1 UWORD ROW_DIR\n"
        "    /end RECORD_LAYOUT\n"
        + _COMPU_LINEAR
        + '    /begin CHARACTERISTIC SPD "speed"\n'
        "      VALUE 0x9800 RL_U16 0 CM_lin 0 255\n"
        "    /end CHARACTERISTIC\n"
    )
    data = _write(tmp_path, "desc_scalar.a2l", body)
    tag = _char_tags(data)["SPD"]
    description = describe_curve_tag(tag, data, {})

    assert description["status"] == "not_a_curve"
    assert description["points"] is None
    assert description["unit"] == "rpm"
    assert description["compu_description"] == "speed linear scale"
    rendered = render_curve_description(description)
    assert "not a CURVE/MAP" in rendered

    # and an ENRICHED scalar row still renders its current value
    from s19_app.tui.a2l import enrich_a2l_tags_with_values

    enriched = {
        t["name"]: t
        for t in enrich_a2l_tags_with_values(
            data, _mem_map(0x9800, (50).to_bytes(2, "little"))
        )
    }["SPD"]
    assert enriched["physical_value"] == 110.0
    described = describe_curve_tag(enriched, data, None)
    assert described["status"] == "not_a_curve"
    assert described["scalar_phys"] == 110.0
    assert "110" in render_curve_description(described)
