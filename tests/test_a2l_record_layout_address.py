"""TC-1803 — B6: CHARACTERISTICs using the operator's DIRECT record layouts keep a live address.

The operator (bug B6) reported labels whose RECORD_LAYOUT carries the
``FNC_VALUES <pos> <dt> <ROW-DIR|COL-DIR> / DIRECT / NO_AXIS_PTS_X / NO_AXIS_PTS_Y``
block (and the same block without the axis lines) showing ``NA`` in the A2L
table and missing from the A2B report. Root cause: their tool emits an
extended characteristic ``Type`` outside ``CHARACTERISTIC_KINDS``, and
``_characteristic_from_tokens`` used to discard the WHOLE mandatory header —
parseable address included — so the tag was born with ``address=None``.

Fix (B6): an unknown-but-shaped Type slot (identifier-like token immediately
followed by an ``int(x, 0)``-parseable address, ≥7 params) is salvaged — the
raw kind is kept, the address survives, and the label stays visible in the
table and the A2B report. Known kinds resolve exactly as before.
"""

from pathlib import Path

from s19_app.tui.a2l import parse_a2l_file

_LAYOUT_WITH_AXES = """    /begin RECORD_LAYOUT RL_MAP_DIRECT
      FNC_VALUES 1 FLOAT32_IEEE COL_DIR
      DIRECT
      NO_AXIS_PTS_X 2 UBYTE
      NO_AXIS_PTS_Y 3 UBYTE
    /end RECORD_LAYOUT
"""

_LAYOUT_NO_AXES = """    /begin RECORD_LAYOUT RL_SCALAR_DIRECT
      FNC_VALUES 1 FLOAT64_IEEE ROW_DIR
      DIRECT
    /end RECORD_LAYOUT
"""

_PROLOGUE = (
    'ASAP2_VERSION 1 71\n'
    '/begin PROJECT P "syn"\n'
    '  /begin MODULE M "syn"\n'
)
_EPILOGUE = "  /end MODULE\n/end PROJECT\n"


def _write(tmp_path: Path, name: str, body: str) -> dict:
    path = tmp_path / name
    path.write_text(_PROLOGUE + body + _EPILOGUE, encoding="utf-8")
    return parse_a2l_file(path)


def _char_tags(data: dict) -> dict:
    return {t["name"]: t for t in data["tags"] if t.get("section") == "CHARACTERISTIC"}


# ---------------------------------------------------------------------------
# TC-1803 — DIRECT / NO_AXIS_PTS_* layout labels keep a live address (B6).
# ---------------------------------------------------------------------------


def test_tc1803_record_layout_direct_with_axes_address_parsed(tmp_path: Path) -> None:
    """The operator's layout WITH axis lines + an extended kind: address survives."""
    data = _write(
        tmp_path,
        "b6_axes.a2l",
        _LAYOUT_WITH_AXES
        + '    /begin CHARACTERISTIC MAP_DIR_LBL "map direct label"\n'
        "      MAP_EXTENDED 0x810300 RL_MAP_DIRECT 0 CM 0 255\n"
        "    /end CHARACTERISTIC\n",
    )
    tags = _char_tags(data)
    assert "MAP_DIR_LBL" in tags  # label alive, not dropped from the table
    tag = tags["MAP_DIR_LBL"]
    assert tag["address"] == 0x810300  # int, not None → not NA, listed in A2B
    assert isinstance(tag["address"], int)
    assert tag["char_type"] == "MAP_EXTENDED"  # raw kind preserved
    assert tag["deposit"] == "RL_MAP_DIRECT"
    assert tag["conversion"] == "CM"


def test_tc1803_record_layout_direct_no_axes_address_parsed(tmp_path: Path) -> None:
    """The operator's second case — same layout WITHOUT the axis lines."""
    data = _write(
        tmp_path,
        "b6_noaxes.a2l",
        _LAYOUT_NO_AXES
        + '    /begin CHARACTERISTIC SCALAR_DIR_LBL "scalar direct label"\n'
        "      VALUE_EXTENDED 0x810400 RL_SCALAR_DIRECT 0 CM 0 255\n"
        "    /end CHARACTERISTIC\n",
    )
    tags = _char_tags(data)
    assert "SCALAR_DIR_LBL" in tags
    tag = tags["SCALAR_DIR_LBL"]
    assert tag["address"] == 0x810400
    assert isinstance(tag["address"], int)
    assert tag["char_type"] == "VALUE_EXTENDED"
    assert tag["deposit"] == "RL_SCALAR_DIRECT"


def test_tc1803_standard_value_regression(tmp_path: Path) -> None:
    """A standard VALUE characteristic resolves exactly as before the salvage."""
    data = _write(
        tmp_path,
        "b6_std.a2l",
        '    /begin CHARACTERISTIC STD_LBL "std value"\n'
        "      VALUE 0x810600 __UBYTE_Z 0 CM 0 255\n"
        "    /end CHARACTERISTIC\n",
    )
    tag = _char_tags(data)["STD_LBL"]
    assert tag["char_type"] == "VALUE"
    assert tag["address"] == 0x810600
    assert tag["length"] == 1
    assert tag["deposit"] == "__UBYTE_Z"
