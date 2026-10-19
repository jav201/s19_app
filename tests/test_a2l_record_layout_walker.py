"""TC-1810 / TC-1811 — R5: per-component RECORD_LAYOUT walker in a2l.py.

Pendiente R5 of the operator's batch-96 PDF (``PENDIENTES-batch96.md`` §2).
The shipped RECORD_LAYOUT reader flattened the body to the FIRST line's
tokens; R5 walks EVERY component line into accumulated, alignment-padded
offsets:

- TC-1810 — the walker: ``FNC_VALUES <pos> <dt> <ROW_DIR|COL_DIR>`` with the
  operator's loose ``DIRECT`` line and the ``NO_AXIS_PTS_*`` placeholders all
  resolve into per-component offsets (the loose ``DIRECT`` no longer forces
  span=None); and an external axis (COM_AXIS via ``AXIS_PTS_REF``) derives its
  span from the referenced AXIS_PTS CHARACTERISTIC's ``max_axis_points`` —
  full-span-or-None stands when the reference cannot be resolved.
- TC-1811 — the encode: ``encode_physical_to_raw_bytes`` accepts a physical
  SEQUENCE (axis points + FNC_VALUES) for a CURVE whose layout resolves
  per-component and packs ONE record at the walked offsets (padding
  zero-filled); a layout/axis resolution failure keeps the shipped "array
  values are not supported" refusal, and a scalar VALUE encodes unchanged.

Black-box ATs drive the shipped ``parse_a2l_file`` /
``encode_physical_to_raw_bytes`` surfaces and assert THE BYTE VALUE / the
concrete offsets — never "non-empty". White-box pins the walker entries
directly. Oracle values were executed over the shipped walker at draft time.
"""

from pathlib import Path

from s19_app.tui.a2l import (
    _axis_counts_resolving_external,
    _record_layout_full_span,
    _resolve_record_layout_components,
    _walk_record_layout_components,
    encode_physical_to_raw_bytes,
    parse_a2l_file,
)

_PROLOGUE = (
    'ASAP2_VERSION 1 71\n'
    '/begin PROJECT P "syn"\n'
    '  /begin MODULE M "syn"\n'
)
_EPILOGUE = "  /end MODULE\n/end PROJECT\n"

# The operator's layout shape (batch-96 B6 file): FNC_VALUES with direction,
# a LOOSE DIRECT line, and both NO_AXIS_PTS placeholders.
_LAYOUT_OPERATOR_DIRECT = """    /begin RECORD_LAYOUT RL_MAP_DIRECT
      FNC_VALUES 1 FLOAT32_IEEE COL_DIR
      DIRECT
      NO_AXIS_PTS_X 2 UBYTE
      NO_AXIS_PTS_Y 3 UBYTE
    /end RECORD_LAYOUT
"""

# A 3-point curve record: 3 axis bytes, an ALIGNMENT_WORD-padded FNC_VALUES run.
_LAYOUT_CURVE3 = """    /begin RECORD_LAYOUT RL_CURVE3
      AXIS_PTS_X 1 UBYTE
      ALIGNMENT_WORD 2
      FNC_VALUES 2 UWORD ROW_DIR
    /end RECORD_LAYOUT
"""

# A curve whose axis points live in a separate AXIS_PTS CHARACTERISTIC.
_LAYOUT_EXTERNAL = """    /begin RECORD_LAYOUT RL_EXT
      AXIS_PTS_X 1 UWORD
      FNC_VALUES 2 UWORD ROW_DIR
    /end RECORD_LAYOUT
"""


def _write(tmp_path: Path, name: str, body: str) -> dict:
    path = tmp_path / name
    path.write_text(_PROLOGUE + body + _EPILOGUE, encoding="utf-8")
    return parse_a2l_file(path)


def _char_tags(data: dict) -> dict:
    return {t["name"]: t for t in data["tags"] if t.get("section") == "CHARACTERISTIC"}


# ---------------------------------------------------------------------------
# TC-1810 — the per-component walker: loose DIRECT tolerance + offsets, and
#            external-axis spans resolved through AXIS_PTS_REF.
# ---------------------------------------------------------------------------


def test_tc1810_walker_resolves_component_offsets_with_loose_direct(tmp_path: Path) -> None:
    """The operator's DIRECT layout walks EVERY line — offsets accumulate and
    the span is not None (the loose DIRECT carries no bytes, it is skipped)."""
    data = _write(
        tmp_path,
        "walker_direct.a2l",
        _LAYOUT_OPERATOR_DIRECT
        + '    /begin CHARACTERISTIC MAP_DIR_LBL "map direct label"\n'
        "      MAP_EXTENDED 0x810300 RL_MAP_DIRECT 0 CM 0 255\n"
        "    /end CHARACTERISTIC\n",
    )
    layouts = data["record_layouts_by_name"]
    layout = layouts["RL_MAP_DIRECT"]
    # White-box: the walker emits one entry per component line, in body order,
    # with accumulated offsets — FNC_VALUES(8×4=32) then the two placeholders.
    components = _walk_record_layout_components(layout, [2, 4])
    assert [c["component"] for c in components] == [
        "FNC_VALUES",
        "NO_AXIS_PTS_X",
        "NO_AXIS_PTS_Y",
    ]
    fnc = components[0]
    assert fnc["datatype"] == "FLOAT32_IEEE"
    assert fnc["direction"] == "COL_DIR"
    assert fnc["position"] == 1  # the ASAM position index is RECORDED, never a count
    assert (fnc["offset"], fnc["count"], fnc["size"], fnc["end"]) == (0, 8, 4, 32)
    assert components[1]["offset"] == 32 and components[1]["end"] == 33
    assert components[2]["offset"] == 33 and components[2]["end"] == 34
    # The additive resolver: full span + endian carrier, scalar shape untouched.
    resolved = _resolve_record_layout_components("RL_MAP_DIRECT", layouts, [2, 4])
    assert resolved["byte_size"] == 34
    assert resolved["components"][-1]["end"] == 34
    # Black-box: the span over the operator's layout is a NUMBER, not None —
    # pre-R5 the loose DIRECT line forced this to None.
    assert _record_layout_full_span(layout, [2, 4]) == 34


def test_tc1810_external_axis_span_from_axis_pts_characteristic(tmp_path: Path) -> None:
    """A CURVE with COM_AXIS + AXIS_PTS_REF derives length from the referenced
    AXIS_PTS CHARACTERISTIC's max_axis_points (4 → span 4·2 + 4·2 = 16)."""
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
    data = _write(tmp_path, "walker_external.a2l", body)
    tags = _char_tags(data)
    # The referenced record's count (4) wins over the local header value (8) —
    # ASAP2 documents the header value as "will be overwritten by max number
    # of axis points of AXIS_PTS".
    axis_meta = tags["CURVE_EXT"]["axis_meta"]
    assert axis_meta[0]["external"] is True
    assert _axis_counts_resolving_external(axis_meta, data["tags"]) == [4]
    # 4×UWORD axis points + 4×UWORD function values = 16 bytes, not None.
    assert tags["CURVE_EXT"]["length"] == 16


def test_tc1810_external_axis_unresolvable_stays_none(tmp_path: Path) -> None:
    """Full-span-or-None stands: a DANGLING AXIS_PTS_REF keeps length=None —
    never an invented count."""
    body = (
        _LAYOUT_EXTERNAL
        + '    /begin CHARACTERISTIC CURVE_DANGLING "curve dangling"\n'
        "      CURVE 0x9200 RL_EXT 0 NO_COMPU_METHOD 0 255\n"
        "      /begin AXIS_DESCR\n"
        "        COM_AXIS NO_INPUT NO_COMPU_METHOD 8 0 255\n"
        "        AXIS_PTS_REF NO_SUCH_AXIS_PTS\n"
        "      /end AXIS_DESCR\n"
        "    /end CHARACTERISTIC\n"
    )
    tags = _char_tags(_write(tmp_path, "walker_dangling.a2l", body))
    assert tags["CURVE_DANGLING"]["length"] is None


# ---------------------------------------------------------------------------
# TC-1811 — the array encode: a 3-point curve packs at walked offsets; the
#             failure modes keep the shipped refusals; VALUE is unchanged.
# ---------------------------------------------------------------------------


def test_tc1811_curve_sequence_packs_record_bytes(tmp_path: Path) -> None:
    """3 physical values per limb pack into ONE 10-byte record: axis points at
    0..2, the ALIGNMENT_WORD pad at 3, FNC_VALUES at 4..9 (little-endian)."""
    body = (
        _LAYOUT_CURVE3
        + '    /begin CHARACTERISTIC C3 "three point curve"\n'
        "      CURVE 0x9200 RL_CURVE3 0 NO_COMPU_METHOD 0 1000\n"
        "      /begin AXIS_DESCR\n"
        "        STD_AXIS NO_INPUT NO_COMPU_METHOD 3 0 255\n"
        "      /end AXIS_DESCR\n"
        "    /end CHARACTERISTIC\n"
    )
    data = _write(tmp_path, "walker_curve3.a2l", body)
    tag = _char_tags(data)["C3"]
    assert tag["length"] == 10  # 3×UBYTE + pad + 3×UWORD — derived by the R5 walk
    encoded, error, flags = encode_physical_to_raw_bytes(
        tag,
        [10, 20, 30, 100, 200, 300],
        data["compu_methods_by_name"],
        data["compu_tabs_by_name"],
        data["record_layouts_by_name"],
    )
    assert error is None
    assert flags == []
    assert encoded is not None
    assert len(encoded) == 10
    # Axis points land at the AXIS_PTS_X offset (0), one byte each.
    assert encoded[0] == 10 and encoded[1] == 20 and encoded[2] == 30
    # The ALIGNMENT_WORD pad byte is zero-filled (no value component owns it).
    assert encoded[3] == 0
    # FNC_VALUES land at the aligned offset 4, little-endian UWORDs.
    assert encoded[4] == 100 and encoded[5] == 0
    assert encoded[6] == 200 and encoded[7] == 0
    assert encoded[8] == 44 and encoded[9] == 1  # 300 == 0x012C


def test_tc1811_curve_sequence_refused_when_layout_unresolved(tmp_path: Path) -> None:
    """The additive encode accepts nothing that refused before R5: a CURVE
    whose deposit names no layout still answers the shipped arrays refusal."""
    body = (
        '    /begin CHARACTERISTIC C_UNK "curve unknown layout"\n'
        "      CURVE 0x9300 NO_SUCH_LAYOUT 0 NO_COMPU_METHOD 0 255\n"
        "      /begin AXIS_DESCR\n"
        "        STD_AXIS NO_INPUT NO_COMPU_METHOD 3 0 255\n"
        "      /end AXIS_DESCR\n"
        "    /end CHARACTERISTIC\n"
    )
    data = _write(tmp_path, "walker_unknown_layout.a2l", body)
    tag = _char_tags(data)["C_UNK"]
    encoded, error, flags = encode_physical_to_raw_bytes(
        tag,
        [10, 20, 30, 100, 200, 300],
        data["compu_methods_by_name"],
        data["compu_tabs_by_name"],
        data["record_layouts_by_name"],
    )
    assert encoded is None
    assert error == "array values are not supported"
    assert flags == []
    # A scalar value on a CURVE keeps its own shipped refusal too.
    _, scalar_error, _ = encode_physical_to_raw_bytes(
        tag,
        42,
        data["compu_methods_by_name"],
        data["compu_tabs_by_name"],
        data["record_layouts_by_name"],
    )
    assert scalar_error == "characteristic type 'CURVE' is not a scalar VALUE"


def test_tc1811_scalar_value_encode_unchanged_regression(tmp_path: Path) -> None:
    """A scalar VALUE encodes byte-identically to the pre-R5 path (LINEAR
    inversion + big-endian pack through the shared _invert_physical_to_raw)."""
    body = (
        "    /begin RECORD_LAYOUT RL_U16\n"
        "      FNC_VALUES 1 UWORD ROW_DIR\n"
        "    /end RECORD_LAYOUT\n"
        "    /begin COMPU_METHOD CM_double\n"
        '    "phys = 2 raw + 10"\n'
        '    LINEAR "%" "u"\n'
        "    COEFFS_LINEAR 2.0 10.0\n"
        "    /end COMPU_METHOD\n"
        + '    /begin CHARACTERISTIC SPD "speed"\n'
        "      VALUE 0x8000 RL_U16 0 CM_double 0 255\n"
        "      BYTE_ORDER MSB_FIRST\n"
        "    /end CHARACTERISTIC\n"
    )
    data = _write(tmp_path, "walker_scalar.a2l", body)
    tag = _char_tags(data)["SPD"]
    encoded, error, flags = encode_physical_to_raw_bytes(
        tag,
        110,  # physical → raw (110 − 10) / 2 = 50
        data["compu_methods_by_name"],
        data["compu_tabs_by_name"],
        data["record_layouts_by_name"],
    )
    assert error is None
    assert flags == []
    assert encoded == (0x00, 0x32)  # big-endian UWORD 50
