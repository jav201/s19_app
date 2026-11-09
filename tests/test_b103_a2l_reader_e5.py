"""Batch-103 Inc 11 E5 — product-review findings reproduced through public routes.

One RED test (or the smallest discriminating set) per accepted product finding
P1-P15 from ``inc-11/E5-rulings.md``. Every shape is synthetic A2L text; the
fixture builders and helpers are reused from ``tests.test_b103_a2l_reader``
(never copied). Each test asserts the *correct* behavior of the requirement
named in its docstring, so on the unmodified baseline ``f4206433`` a finding
that reproduces fails its test (RED) for the stated behavioral reason.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

import pytest

from tests.test_b103_a2l_reader import (
    HDR,
    TAIL,
    _body,
    _parse,
    _spans,
    _tag,
    _tags_named,
    char,
    meas,
)


def _find_section(sections: List[dict], name: str) -> Optional[dict]:
    """Depth-first search for the first section whose keyword is ``name``."""
    for section in sections:
        if section.get("name") == name:
            return section
        found = _find_section(section.get("children") or [], name)
        if found is not None:
            return found
    return None


# ---------------------------------------------------------------------------
# P1 — quoted numeric header words give no number (R-A2L-READ.34-.36, .40, .41, .63).
# ---------------------------------------------------------------------------


def test_e5_p1_quoted_header_words_give_no_number(tmp_path: Path) -> None:
    """R-A2L-READ.34/.36/.63, .40, .41: quoted addresses and sizes are no number."""
    # A CHARACTERISTIC whose header address is quoted must not export it.
    c = _parse(tmp_path, _body(char("CX", "VALUE", '"0x2000"', "RL_U16")))
    assert _tag(c, "CX", "CHARACTERISTIC")["address"] is None

    # A BLOB whose address and size are quoted exports neither.
    b = _parse(tmp_path, _body('/begin BLOB B1 "" "0x10" "2"\n/end BLOB'))
    assert {"name": "B1", "kind": "BLOB", "address": None, "length": None} in _spans(b)

    # An INSTANCE whose address is quoted exports no address.
    i = _parse(tmp_path, _body('/begin INSTANCE I1 "" T_U16 "0x10"\n/end INSTANCE'))
    assert any(s["name"] == "I1" and s["address"] is None for s in _spans(i))


# ---------------------------------------------------------------------------
# P2 — backslash + line end inside a quoted string cannot leak /begin or /end
# (R-A2L-001.3.2, R-A2L-READ.13/.14).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("nl", ["\n", "\r\n", "\r"])
def test_e5_p2_backslash_lineend_keeps_end_inside_string(tmp_path: Path, nl: str) -> None:
    """R-A2L-001.3.2, R-A2L-READ.13/.14: a quoted string spanning a line end is
    one word, so an embedded ``/end`` cannot close the enclosing section."""
    body = meas("X", " ECU_ADDRESS 0x10", ' FORMAT "x\\\n /end MEASUREMENT x"')
    text = _body(body).replace("\n", nl)
    data = _parse(tmp_path, text)
    assert _tag(data, "X")["address"] == 0x10
    assert data["errors"] == []


# ---------------------------------------------------------------------------
# P3 — nested MODULE inheritance of the byte-order source (CTX *byte-order
# source*; R-A2L-READ.60/.68).
# ---------------------------------------------------------------------------


def _nested_module_text(outer_byte_order: str) -> str:
    return (
        "ASAP2_VERSION 1 71\n/project P\n"
        '/begin MODULE M1 ""\n'
        '/begin MOD_COMMON ""\n'
        f"BYTE_ORDER {outer_byte_order}\n"
        "/end MOD_COMMON\n"
        '/begin COMPU_METHOD CM_ID "" IDENTICAL "%.0" ""\n/end COMPU_METHOD\n'
        "/begin RECORD_LAYOUT RL_U16\nFNC_VALUES 1 UWORD ROW_DIR DIRECT\n/end RECORD_LAYOUT\n"
        '/begin MODULE M2 ""\n'
        '/begin MOD_COMMON ""\n/end MOD_COMMON\n'
        + meas("X", " ECU_ADDRESS 0x10")
        + "\n/end MODULE\n/end MODULE\n/end PROJECT\n"
    )


def test_e5_p3_nested_module_inherits_byte_order(tmp_path: Path) -> None:
    """R-A2L-READ.60: a MODULE without its own BYTE_ORDER carries the enclosing
    source instead of resetting to little."""
    data = _parse(tmp_path, _nested_module_text("MSB_FIRST"))
    assert _tag(data, "X")["effective_byte_order"] == "big"


def test_e5_p3_nested_module_inherits_invalid_source(tmp_path: Path) -> None:
    """R-A2L-READ.60/.68: a nested MODULE inherits an enclosing invalid source
    and keeps refusing the address."""
    data = _parse(tmp_path, _nested_module_text("MSB_FRIST"))
    assert _tag(data, "X")["address"] is None


# ---------------------------------------------------------------------------
# P4 — /end and /begin line identities (R-A2L-001.4/.5, R-A2L-READ.48, .64).
# ---------------------------------------------------------------------------


def test_e5_p4_end_line_uses_end_word_line(tmp_path: Path) -> None:
    """R-A2L-READ.48: ``end_line`` is the /end word's line, not the name's."""
    text = (
        HDR
        + '/begin MEASUREMENT X ""\n UWORD CM_ID 0 0 0 65535\n ECU_ADDRESS 0x10\n/end\nMEASUREMENT\n'
        + TAIL
    )
    data = _parse(tmp_path, text)
    sec = _find_section(data["sections"], "MEASUREMENT")
    assert sec is not None
    assert sec["end_line"] == text.split("\n").index("/end") + 1


def test_e5_p4_end_mismatch_uses_end_word_line(tmp_path: Path) -> None:
    """R-A2L-001.5: the mismatch diagnostic names the /end word's line."""
    text = (
        HDR
        + '/begin MEASUREMENT X ""\n UWORD CM_ID 0 0 0 65535\n/end\nIF_DATA\n'
        + TAIL
    )
    data = _parse(tmp_path, text)
    end_line = text.split("\n").index("/end") + 1
    assert any(
        f"Line {end_line}: /end IF_DATA does not close /begin MEASUREMENT" in e
        for e in data["errors"]
    )


def test_e5_p4_nesting_cap_uses_begin_word_line(tmp_path: Path) -> None:
    """R-A2L-READ.64: the depth error names the /begin word's line, not the
    section keyword's line."""
    text = "".join("/begin\nA\n" for _ in range(33))
    data = _parse(tmp_path, text)
    assert data["errors"] == ["Line 65: sections nested deeper than 32"]


# ---------------------------------------------------------------------------
# P5 — words after a multiline comment close get their actual line
# (R-A2L-READ.1, .48, .63).
# ---------------------------------------------------------------------------


def test_e5_p5_words_after_multiline_comment_get_actual_line(tmp_path: Path) -> None:
    """R-A2L-READ.1/.63: a keyword after a later comment close carries the close
    line, not the comment-opening line."""
    text = _body(meas("X", " ECU_ADDRESS 0x10 /* note\n */ LENGTH x4"))
    data = _parse(tmp_path, text)
    close_line = text.split("\n").index(" */ LENGTH x4") + 1
    assert any(f"Line {close_line}: LENGTH x4 is not a number" in e for e in data["errors"])


# ---------------------------------------------------------------------------
# P6 — quoted keyword arguments retain boundaries and unquote (R-A2L-001.3.1,
# R-A2L-READ.29, .33).
# ---------------------------------------------------------------------------


def test_e5_p6_quoted_keyword_arguments_keep_boundaries(tmp_path: Path) -> None:
    """R-A2L-READ.33/.29: quoted DISPLAY_IDENTIFIER/UNIT/SYMBOL_LINK values keep
    their word boundaries and are unquoted."""
    d = _parse(tmp_path, _body(meas("X", " ECU_ADDRESS 0x10", ' DISPLAY_IDENTIFIER "XM disp"')))
    assert _tag(d, "X")["display_identifier"] == "XM disp"

    u = _parse(tmp_path, _body(meas("X", " ECU_ADDRESS 0x10", ' UNIT "rpm per sec"')))
    assert _tag(u, "X")["unit"] == "rpm per sec"

    s = _parse(tmp_path, _body(meas("X", " ECU_ADDRESS 0x10", ' SYMBOL_LINK "sym name" 0')))
    assert _tag(s, "X")["symbol_link"] == "sym name"


# ---------------------------------------------------------------------------
# P7 — external-axis disagreement never reports ``Line None`` (R-A2L-READ.59).
# ---------------------------------------------------------------------------


def _external_axis_map_text() -> str:
    return _body(
        '/begin CHARACTERISTIC AX_REF ""\n'
        " VALUE 0x810000 RL_U16 0 CM_ID 0 65535\n"
        " /begin AXIS_DESCR\n"
        " STD_AXIS NO_INPUT_QUANTITY CM_ID 5 0 255\n"
        " /end AXIS_DESCR\n"
        "/end CHARACTERISTIC\n"
        '/begin CHARACTERISTIC CMAP ""\n'
        " MAP 0x820000 RL_U16 0 CM_ID 0 65535\n"
        " LENGTH 4\n"
        " /begin AXIS_DESCR\n"
        " COM_AXIS NO_INPUT_QUANTITY CM_ID 5 0 255 AXIS_PTS_REF AX_REF\n"
        " /end AXIS_DESCR\n"
        "/end CHARACTERISTIC"
    )


def test_e5_p7_external_axis_disagreement_has_begin_line(tmp_path: Path) -> None:
    """R-A2L-READ.59: the external-axis size disagreement names the tag's /begin
    line, never ``Line None``."""
    text = _external_axis_map_text()
    data = _parse(tmp_path, text)
    begin_line = text.split("\n").index('/begin CHARACTERISTIC CMAP ""') + 1
    size_errors = [e for e in data["errors"] if "declares the sizes" in e]
    assert size_errors, data["errors"]
    assert all(e.startswith(f"Line {begin_line}:") for e in size_errors)
    assert not any("Line None" in e for e in data["errors"])


# ---------------------------------------------------------------------------
# P8 — argument diagnostics name the argument's line (R-A2L-READ.63, .68).
# ---------------------------------------------------------------------------


def test_e5_p8_argument_diagnostics_use_argument_line(tmp_path: Path) -> None:
    """R-A2L-READ.63/.68: a keyword on one line and its bad argument on the next
    report the argument's line."""
    t1 = _body(meas("X", " ECU_ADDRESS", " x4"))
    d1 = _parse(tmp_path, t1)
    l1 = t1.split("\n").index(" x4") + 1
    assert any(f"Line {l1}: ECU_ADDRESS x4 is not a number" in e for e in d1["errors"])

    t2 = _body(meas("Y", " ECU_ADDRESS 0x10", " BYTE_ORDER", " MSB_FRIST"))
    d2 = _parse(tmp_path, t2)
    l2 = t2.split("\n").index(" MSB_FRIST") + 1
    assert any(f"Line {l2}: BYTE_ORDER MSB_FRIST is not a byte order" in e for e in d2["errors"])


# ---------------------------------------------------------------------------
# P9 — unrelated invalidity does not suppress disagreement errors
# (R-A2L-READ.59).
# ---------------------------------------------------------------------------


def test_e5_p9_invalid_byte_order_keeps_address_disagreement(tmp_path: Path) -> None:
    """R-A2L-READ.59: differing addresses are still diagnosed alongside an
    invalid byte order."""
    text = _body(meas("X", " ECU_ADDRESS 0x10", " ECU_ADDRESS 0x20", " BYTE_ORDER MSB_FRIST"))
    data = _parse(tmp_path, text)
    assert _tag(data, "X")["address"] is None
    assert any("declares the addresses 0x00000010 and 0x00000020" in e for e in data["errors"])


def test_e5_p9_no_number_keeps_size_disagreement(tmp_path: Path) -> None:
    """R-A2L-READ.59: disagreeing sizes are still diagnosed alongside a size
    keyword that gives no number."""
    text = _body(meas("X", " ECU_ADDRESS 0x10", " LENGTH 4", " LENGTH 8", " MATRIX_DIM x4"))
    data = _parse(tmp_path, text)
    assert _tag(data, "X")["length"] is None
    assert any("declares the sizes 4 and 8" in e for e in data["errors"])


# ---------------------------------------------------------------------------
# P10 — every invalid BYTE_ORDER argument is diagnosed once (R-A2L-READ.68).
# ---------------------------------------------------------------------------


def test_e5_p10_every_invalid_byte_order_argument_diagnosed(tmp_path: Path) -> None:
    """R-A2L-READ.68: one .68 error per invalid BYTE_ORDER word, duplicates
    included; a valid first word does not hide an invalid second."""
    t1 = _body(meas("X", " ECU_ADDRESS 0x10", " BYTE_ORDER MSB_FRIST", " BYTE_ORDER MSB_FRIST"))
    d1 = _parse(tmp_path, t1)
    assert len([e for e in d1["errors"] if "BYTE_ORDER MSB_FRIST is not a byte order" in e]) == 2

    t2 = _body(meas("Y", " ECU_ADDRESS 0x10", " BYTE_ORDER MSB_FIRST", " BYTE_ORDER MSB_FRIST"))
    d2 = _parse(tmp_path, t2)
    assert any("BYTE_ORDER MSB_FRIST is not a byte order" in e for e in d2["errors"])


# ---------------------------------------------------------------------------
# P11 — a typedef's refused length cannot reappear as an INSTANCE length
# (R-A2L-READ.43, CTX *length rows*, R-A2L-READ.61).
# ---------------------------------------------------------------------------


def test_e5_p11_typedef_refused_length_not_reappearing(tmp_path: Path) -> None:
    """R-A2L-READ.43/.61: a refused typedef length stays refused for the INSTANCE."""
    t1 = _body(
        '/begin TYPEDEF_CHARACTERISTIC TV "" VALUE 0x0 RL_U16 0 CM_ID 0 65535\n'
        " LENGTH 4\n"
        "/end TYPEDEF_CHARACTERISTIC\n"
        '/begin INSTANCE I1 "" TV 0x10\n/end INSTANCE'
    )
    assert any(s["name"] == "I1" and s["length"] is None for s in _spans(_parse(tmp_path, t1)))

    t2 = _body(
        '/begin TYPEDEF_CHARACTERISTIC TV "" VAL_BLK 0x0 RL_U16 0 CM_ID 0 65535\n'
        " MATRIX_DIM 4\n NUMBER 5\n"
        "/end TYPEDEF_CHARACTERISTIC\n"
        '/begin INSTANCE I2 "" TV 0x10\n/end INSTANCE'
    )
    assert any(s["name"] == "I2" and s["length"] is None for s in _spans(_parse(tmp_path, t2)))


# ---------------------------------------------------------------------------
# P12 — declared FNC_VALUES datatype wins over a misleading deposit name
# (CTX *datatype (CHARACTERISTIC)*; R-A2L-015, .016, .43).
# ---------------------------------------------------------------------------


def test_e5_p12_declared_fnc_values_datatype_wins(tmp_path: Path) -> None:
    """R-A2L-015: a layout named ``__UBYTE_Z`` whose FNC_VALUES is ULONG sizes 4,
    not the deposit-name hint of 1."""
    text = (
        "ASAP2_VERSION 1 71\n/project P\n"
        '/begin MODULE M ""\n'
        '/begin MOD_COMMON ""\nBYTE_ORDER MSB_FIRST\n/end MOD_COMMON\n'
        '/begin COMPU_METHOD CM_ID "" IDENTICAL "%.0" ""\n/end COMPU_METHOD\n'
        "/begin RECORD_LAYOUT __UBYTE_Z\nFNC_VALUES 1 ULONG ROW_DIR DIRECT\n/end RECORD_LAYOUT\n"
        '/begin CHARACTERISTIC CX ""\n'
        " VALUE 0x2000 __UBYTE_Z 0 CM_ID 0 65535\n"
        "/end CHARACTERISTIC\n"
        "/end MODULE\n/end PROJECT\n"
    )
    data = _parse(tmp_path, text)
    assert _tag(data, "CX", "CHARACTERISTIC")["length"] == 4


# ---------------------------------------------------------------------------
# P13 — CUBOID/CUBE_4/CUBE_5 layout-span disagreement refused like CURVE/MAP
# (CTX *sizes*; R-A2L-READ.59, .61).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["CUBOID", "CUBE_4", "CUBE_5"])
def test_e5_p13_cuboid_cube_span_disagreement_refused(tmp_path: Path, kind: str) -> None:
    """R-A2L-READ.59/.61: a CUBOID/CUBE_4/CUBE_5 with a resolvable span and a
    conflicting LENGTH is refused like a CURVE/MAP."""
    text = (
        "ASAP2_VERSION 1 71\n/project P\n"
        '/begin MODULE M ""\n'
        '/begin MOD_COMMON ""\nBYTE_ORDER MSB_FIRST\n/end MOD_COMMON\n'
        '/begin COMPU_METHOD CM_ID "" IDENTICAL "%.0" ""\n/end COMPU_METHOD\n'
        "/begin RECORD_LAYOUT RL_CUBE\nFNC_VALUES 1 UWORD ROW_DIR DIRECT\n/end RECORD_LAYOUT\n"
        '/begin CHARACTERISTIC CCUBE ""\n'
        f" {kind} 0x3000 RL_CUBE 0 CM_ID 0 65535\n"
        " LENGTH 4\n"
        " /begin AXIS_DESCR\n"
        " FIX_AXIS NO_INPUT_QUANTITY CM_ID 8 0 255\n"
        " /end AXIS_DESCR\n"
        "/end CHARACTERISTIC\n"
        "/end MODULE\n/end PROJECT\n"
    )
    data = _parse(tmp_path, text)
    assert _tag(data, "CCUBE", "CHARACTERISTIC")["length"] is None
    assert any("declares the sizes" in e for e in data["errors"])


# ---------------------------------------------------------------------------
# P14 — unclosed declared sections export no address and no length
# (R-A2L-READ.70).
# ---------------------------------------------------------------------------


def test_e5_p14_unclosed_declared_sections_no_span(tmp_path: Path) -> None:
    """R-A2L-READ.70: an unclosed BLOB/INSTANCE and an INSTANCE whose typedef is
    unclosed all give no address and no length."""
    t1 = _body('/begin BLOB B1 "" 0x10 2')
    assert any(
        s["name"] == "B1" and s["address"] is None and s["length"] is None
        for s in _spans(_parse(tmp_path, t1))
    )

    t2 = _body('/begin INSTANCE I1 "" T_U16 0x10')
    assert any(
        s["name"] == "I1" and s["address"] is None and s["length"] is None
        for s in _spans(_parse(tmp_path, t2))
    )

    t3 = _body(
        '/begin TYPEDEF_MEASUREMENT T_U2 "" UWORD CM_ID 0 0 0 65535\n'
        '/begin INSTANCE I2 "" T_U2 0x10\n/end INSTANCE'
    )
    assert any(
        s["name"] == "I2" and s["address"] is None and s["length"] is None
        for s in _spans(_parse(tmp_path, t3))
    )


# ---------------------------------------------------------------------------
# P15 — final tag-length refusal cannot be re-derived inline (R-A2L-READ.61,
# E3S-23; mutant B M09).
# ---------------------------------------------------------------------------


def test_e5_p15_length_zero_inline_axis_refusal_final(tmp_path: Path) -> None:
    """R-A2L-READ.61 (E3S-23): a MAP with ``LENGTH 0`` and an inline STD_AXIS keeps
    ``length=None`` and the size-disagreement error; the inline span (13) is never
    re-derived."""
    text = (
        "ASAP2_VERSION 1 71\n/project P\n"
        '/begin MODULE M ""\n'
        '/begin MOD_COMMON ""\nBYTE_ORDER MSB_FIRST\n/end MOD_COMMON\n'
        '/begin COMPU_METHOD CM_ID "" IDENTICAL "%.0" ""\n/end COMPU_METHOD\n'
        "/begin RECORD_LAYOUT RL_MAP\nNO_AXIS_PTS_X 1 UBYTE\nFNC_VALUES 2 UWORD ROW_DIR DIRECT\n/end RECORD_LAYOUT\n"
        '/begin CHARACTERISTIC C ""\n'
        " MAP 0x820000 RL_MAP 0 CM_ID 0 65535\n"
        " LENGTH 0\n"
        " /begin AXIS_DESCR\n"
        " STD_AXIS NO_INPUT_QUANTITY CM_ID 6 0 255\n"
        " /end AXIS_DESCR\n"
        "/end CHARACTERISTIC\n"
        "/end MODULE\n/end PROJECT\n"
    )
    data = _parse(tmp_path, text)
    assert _tag(data, "C", "CHARACTERISTIC")["length"] is None
    assert any("CHARACTERISTIC C declares the sizes 0 and 13" in e for e in data["errors"])


# ---------------------------------------------------------------------------
# P16 — a CURVE on a declared UWORD layout with two inline axis points takes
# the full layout span 4, not the scalar deposit length 2 (R-A2L-018).
# ---------------------------------------------------------------------------


def test_e5_p16_curve_declared_uword_two_axis_points_full_span(tmp_path: Path) -> None:
    """R-A2L-018: a CURVE with a declared UWORD record layout and two inline
    axis points sizes to its whole record (2 × UWORD = 4), not the scalar
    deposit length 2."""
    text = _body(
        "/begin RECORD_LAYOUT __UWORD_Z\nFNC_VALUES 1 UWORD ROW_DIR DIRECT\n/end RECORD_LAYOUT\n"
        + char(
            "C",
            "CURVE",
            "0x2000",
            "__UWORD_Z",
            " /begin AXIS_DESCR",
            " STD_AXIS NO_INPUT_QUANTITY CM_ID 2 0 255",
            " /end AXIS_DESCR",
        )
    )
    data = _parse(tmp_path, text)
    assert _tag(data, "C", "CHARACTERISTIC")["length"] == 4



# ---------------------------------------------------------------------------
# P18 — standing DATA_SIZE and a later full span take precedence over scalar
# inference (R-A2L-READ.48, CTX sizes).
# ---------------------------------------------------------------------------


def test_e5_p18_data_size_only_unresolved_span_uses_standing_size(tmp_path: Path) -> None:
    """A CURVE with DATA_SIZE 4 and no resolvable span keeps 4, never the
    generic UWORD scalar length 2."""
    text = _body(
        char("C", "CURVE", "0x2000", "RL_U16", " DATA_SIZE 4")
    )
    data = _parse(tmp_path, text)
    assert _tag(data, "C", "CHARACTERISTIC")["length"] == 4


def test_e5_p18_external_full_span_agrees_with_standing_data_size(tmp_path: Path) -> None:
    """A later-resolved full span 4 agrees with standing DATA_SIZE 4 and is
    exported as the characteristic length."""
    text = _body(
        char(
            "C",
            "CURVE",
            "0x2000",
            "RL_U16",
            " DATA_SIZE 4",
            " /begin AXIS_DESCR",
            " COM_AXIS NO_INPUT_QUANTITY CM_ID 2 0 1 AXIS_PTS_REF AP",
            " /end AXIS_DESCR",
        )
        + "\n"
        + char(
            "AP",
            "VALUE",
            "0x3000",
            "RL_U16",
            " /begin AXIS_DESCR",
            " STD_AXIS NO_INPUT_QUANTITY CM_ID 2 0 1",
            " /end AXIS_DESCR",
        )
    )
    data = _parse(tmp_path, text)
    assert _tag(data, "C", "CHARACTERISTIC")["length"] == 4
