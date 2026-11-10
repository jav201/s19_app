"""Batch-103 Inc 3b: exact write-side oracles for arrays, curves and maps."""

from __future__ import annotations

import struct
import time
from collections import Counter
from dataclasses import replace
from typing import Mapping

import pytest

from s19_app.tui import a2l, a2l_definition as a2ldef
from tests.support.b103_a2l_arrays import (
    axis,
    axis_pts,
    characteristic,
    cm,
    ctab,
    curve,
    img,
    inline,
    meas,
    rl,
    valblk,
    vtab,
)
from tests.support.timing import report_margin
from tests.test_b103_a2l_definition import (
    _ascii,
    _clear_parse_errors,
    _enum_blocks,
    _inline as inline2,
    _val,
)
from tests.test_b103_a2l_definition_arrays_decode import (  # noqa: F401
    _decode,
    _swords,
    c08,
    defc,
    v171,
)

ROW_ARRAY = "ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR"
COL_ARRAY = "ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.COLUMN_DIR"
COM_CURVE = "ASAM.C.CURVE.COM_AXIS"
COM_MAP = "ASAM.C.MAP.COM_AXIS.FIX_AXIS"
AX8_BYTES = bytes([8, 0x46, 0x3C, 0x32, 0x28, 0x1E, 0x14, 0x0A, 0x00])
SIZES = {
    "UBYTE": 1,
    "SBYTE": 1,
    "UWORD": 2,
    "SWORD": 2,
    "ULONG": 4,
    "SLONG": 4,
    "FLOAT32_IEEE": 4,
    "FLOAT64_IEEE": 8,
    "A_UINT64": 8,
    "A_INT64": 8,
}


def _assert_display_agrees(d, expected, actual):
    if actual == expected:
        return
    if d.decimals is not None and abs(actual - expected) <= 0.5 * 10.0 ** -d.decimals:
        return
    assert f"{actual:.15g}" == f"{expected:.15g}" or (
        d.datatype == "FLOAT32_IEEE" and f"{actual:.6g}" == f"{expected:.6g}"
    )


def _encode(d, a2l_data, edit, image):
    assert hasattr(a2ldef, "encode_values"), "encode_values not implemented"
    return a2ldef.encode_values(d, a2l_data, edit, image)


def _encoded(d, a2l_data, edit, image):
    res = _encode(d, a2l_data, edit, image)
    assert isinstance(res, a2ldef.Encoded), res
    assert res.address == d.address and len(res.data) == d.byte_length
    return res


def _refusal(res, code: str, message: str):
    assert isinstance(res, a2ldef.Refusal), res
    assert (res.code, res.message) == (code, message), res
    return res


def _apply(image: Mapping[int, int], res) -> dict[int, int]:
    after = dict(image)
    after.update(img(res.address, res.data))
    return after


def _decoded(d, a2l_data, image):
    res = _decode(d, a2l_data, image)
    assert isinstance(res, a2ldef.DecodedValues), res
    return res


def _uwords(*values: int) -> bytes:
    return b"".join(struct.pack(">H", value) for value in values)


def _swords_be(*values: int) -> bytes:
    return b"".join(struct.pack(">h", value) for value in values)


def _array_image(addr: int) -> dict[int, int]:
    return img(addr, _swords(*range(1, 13)))


def _com_image(count: int = 8) -> dict[int, int]:
    image = img(0x810320, _swords(*range(8)))
    axis_bytes = bytes([count]) + AX8_BYTES[1:]
    image.update(img(0x810340, axis_bytes))
    return image


def _map_image() -> dict[int, int]:
    image = _com_image()
    image.update(img(0x810440, _swords(*range(24))))
    return image


def _std_blocks(
    name: str = "CM1",
    rule: str | None = "STRICT_INCREASE",
    *,
    point_dt: str = "UBYTE",
    point_order: str = "INDEX_INCR",
    axis_method: str = "CM_IDENT",
    axis_lo: str = "0",
    axis_hi: str = "255",
    layout_name: str = "RL_C",
    with_count: bool = False,
) -> tuple[str, ...]:
    extras = () if rule is None else (f"MONOTONY {rule}",)
    lines = []
    if with_count:
        lines.append("NO_AXIS_PTS_X 1 UBYTE")
    lines.extend([
        f"AXIS_PTS_X {2 if with_count else 1} {point_dt} {point_order} DIRECT",
        f"FNC_VALUES {3 if with_count else 2} UWORD ROW_DIR DIRECT",
    ])
    return (
        rl(layout_name, *lines),
        curve(
            name,
            "0x100",
            layout_name,
            axis("STD_AXIS", axis_method, "4", axis_lo, axis_hi, *extras),
        ),
    )


def _std_image(points: bytes, values: bytes | None = None, *, count: int | None = None) -> dict[int, int]:
    record = (bytes([count]) if count is not None else b"") + points
    record += _uwords(*range(4)) if values is None else values
    return img(0x100, record)


def test_r_a2l_def_120_2_single_text_encode_refuses_array(v171):
    d = a2ldef.describe_definition(ROW_ARRAY, v171)
    res = a2ldef.encode_definition(d, v171, "5", _array_image(0x810100))
    _refusal(
        res,
        "A2L-DEF-ELEMENTS",
        f"{ROW_ARRAY}: it holds 12 values — decode and encode it value by value",
    )


def _parse_array_case(tmp_path, name: str):
    padding = tuple("/* line padding */" for _ in range(7))
    a2l_data = inline(
        tmp_path,
        *padding,
        '/include "x.a2l"',
        valblk(name, "0x10", "RL_U16", extras=("MATRIX_DIM 2",)),
        layouts=(("RL_U16", "UWORD"),),
    )
    assert a2l_data["errors"][0] == "Line 20: /include x.a2l is not read", a2l_data["errors"]
    return a2l_data, a2ldef.describe_definition(name, a2l_data)


def test_r_a2l_def_120_3_parse_precedes_single_text_refusal(tmp_path):
    a2l_data, d = _parse_array_case(tmp_path, "P")
    res = a2ldef.encode_definition(d, a2l_data, "5", img(0x10, bytes(4)))
    _refusal(
        res,
        "A2L-DEF-PARSE",
        "P: the A2L cannot be edited while it has parse errors — the first is Line 20: /include x.a2l is not read",
    )


def test_r_a2l_def_121_1_element_name_in_encode_refusal(tmp_path):
    a2l_data = inline(tmp_path, valblk("V", "0x10", "RL_U16", extras=("MATRIX_DIM 3 4",)))
    d = a2ldef.describe_definition("V", a2l_data)
    res = _encode(d, a2l_data, {(1, 2): "abc"}, img(0x10, bytes(24)))
    _refusal(res, "A2L-DEF-NUMBER", "V[1,2]: 'abc' is not a number")


def test_r_a2l_def_121_2_axis_point_name_in_encode_refusal(tmp_path):
    a2l_data = inline(
        tmp_path,
        cm("CM_S8", "IDENTICAL"),
        rl("RL_C", "AXIS_PTS_X 1 SBYTE INDEX_INCR DIRECT", "FNC_VALUES 2 SWORD ROW_DIR DIRECT"),
        curve("C", "0x100", "RL_C", axis("STD_AXIS", "CM_S8", "4", "-100", "100")),
    )
    d = a2ldef.describe_definition("C", a2l_data)
    image = _std_image(bytes([10, 20, 30, 40]), _swords_be(*range(4)))
    res = _encode(d, a2l_data, {("X", 1): "120"}, image)
    _refusal(res, "A2L-DEF-LIMITS", "C.X[1]: 120 is outside the limits -100..100")


def test_r_a2l_def_122_1_converted_element_edit(tmp_path):
    a2l_data = inline(
        tmp_path,
        cm("CM_HALF", "LINEAR", "0.5", "0", fmt='"%.1"'),
        valblk("VN", "0x10", "RL_U16", "CM_HALF", "0", "65535", extras=("MATRIX_DIM 2",)),
    )
    d = a2ldef.describe_definition("VN", a2l_data)
    image = img(0x10, bytes.fromhex("00030004"))
    res = _encoded(d, a2l_data, {(0,): "2.5"}, image)
    assert res.data == bytes.fromhex("00050004")
    assert _decoded(d, a2l_data, _apply(image, res)).values[0].stored == 5


def test_r_a2l_def_122_2_enum_element_edit(tmp_path):
    a2l_data = inline(
        tmp_path,
        cm("CM_E", "TAB_VERB", fmt='"%.0"', ref="VT_E"),
        vtab("VT_E", "2", '0 "OFF"', '1 "ON"'),
        valblk("VE", "0x10", "RL_U8", "CM_E", "0", "1", extras=("MATRIX_DIM 2",)),
    )
    d = a2ldef.describe_definition("VE", a2l_data)
    image = img(0x10, b"\x01\x00")
    res = _encoded(d, a2l_data, {(1,): "ON"}, image)
    assert res.data == b"\x01\x01"
    decoded = _decoded(d, a2l_data, _apply(image, res))
    assert decoded.values[1].stored == 1 and decoded.values[1].text == "ON"


def test_r_a2l_def_122_3_element_outside_limits(tmp_path):
    a2l_data = inline(
        tmp_path,
        valblk("VX", "0x10", "RL_U16", "NO_COMPU_METHOD", "0", "10", extras=("MATRIX_DIM 2",)),
    )
    d = a2ldef.describe_definition("VX", a2l_data)
    res = _encode(d, a2l_data, {(0,): "11"}, img(0x10, bytes(4)))
    _refusal(res, "A2L-DEF-LIMITS", "VX[0]: 11 is outside the limits 0..10")


def test_r_a2l_def_122_4_converted_axis_point_edit(tmp_path):
    a2l_data = inline(
        tmp_path,
        cm("CM_TWO", "LINEAR", "2", "0"),
        rl("RL_C", "AXIS_PTS_X 1 UWORD INDEX_INCR DIRECT", "FNC_VALUES 2 UWORD ROW_DIR DIRECT"),
        curve("C", "0x100", "RL_C", axis("STD_AXIS", "CM_TWO", "4", "0", "500")),
    )
    d = a2ldef.describe_definition("C", a2l_data)
    image = _std_image(_uwords(1, 2, 3, 4))
    res = _encoded(d, a2l_data, {("X", 3): "10"}, image)
    assert res.data[6:8] == b"\x00\x05"
    assert _decoded(d, a2l_data, _apply(image, res)).axes[0].points[3].stored == 5


def test_r_a2l_def_122_5_float64_element_uses_precision_rule(tmp_path):
    a2l_data = inline(
        tmp_path,
        cm("CM_P", "LINEAR", "1", "1e10", fmt='"%"'),
        valblk("VP", "0x10", "RL_F64", "CM_P", "-10", "10", extras=("MATRIX_DIM 2",)),
    )
    d = a2ldef.describe_definition("VP", a2l_data)
    res = _encode(d, a2l_data, {(1,): "1.0000001"}, img(0x10, bytes(16)))
    _refusal(
        res,
        "A2L-DEF-PRECISION",
        "VP[1]: 1.0000001 cannot be stored at the display precision — the nearest stored value is 1",
    )


def test_r_a2l_def_122_6_exact_integer_check_on_element(tmp_path):
    a2l_data = inline(
        tmp_path,
        valblk("VU", "0x10", "RL_U64", "CM_IDENT", "0", "1e19", extras=("MATRIX_DIM 2",)),
    )
    d = a2ldef.describe_definition("VU", a2l_data)
    res = _encode(d, a2l_data, {(0,): "9007199254740993"}, img(0x10, bytes(16)))
    _refusal(
        res,
        "A2L-DEF-PRECISION",
        "VU[0]: 9007199254740993 cannot be stored at the display precision — the nearest stored value is 9007199254740992",
    )


def test_r_a2l_def_122_7_written_element_against_extended_limits(tmp_path):
    a2l_data = inline(
        tmp_path,
        cm("CM_T", "TAB_INTP", fmt='"%.1"', ref="CT_T"),
        ctab("CT_T", "TAB_INTP", "0 0.0", "10 1.0"),
        valblk(
            "VL4",
            "0x10",
            "RL_U16",
            "CM_T",
            "0",
            "0.55",
            extras=("MATRIX_DIM 2", "EXTENDED_LIMITS 0 0.55"),
        ),
    )
    d = a2ldef.describe_definition("VL4", a2l_data)
    res = _encode(d, a2l_data, {(1,): "0.55"}, img(0x10, bytes(4)))
    _refusal(res, "A2L-DEF-EXTENDED", "VL4[1]: 0.6 is outside the extended limits 0..0.55")


def test_r_a2l_def_123_1_row_dir_whole_record_bytes(v171):
    d = a2ldef.describe_definition(ROW_ARRAY, v171)
    image = _array_image(0x810100)
    before = bytes(image[0x810100 + i] for i in range(24))
    res = _encoded(d, v171, {(1, 0): "-7"}, image)
    assert res.data[2:4] == b"\xf9\xff"
    assert res.data[:2] + res.data[4:] == before[:2] + before[4:]


def test_r_a2l_def_123_2_column_dir_whole_record_bytes(v171):
    d = a2ldef.describe_definition(COL_ARRAY, v171)
    image = _array_image(0x810120)
    before = bytes(image[0x810120 + i] for i in range(24))
    res = _encoded(d, v171, {(1, 0): "-7"}, image)
    assert res.data[8:10] == b"\xf9\xff"
    assert res.data[:8] + res.data[10:] == before[:8] + before[10:]


def test_r_a2l_def_123_3_index_decr_point_edit(tmp_path):
    a2l_data = inline(tmp_path, *_std_blocks("CD", point_order="INDEX_DECR"))
    d = a2ldef.describe_definition("CD", a2l_data)
    image = _std_image(bytes([40, 30, 20, 10]))
    before = bytes(image[0x100 + i] for i in range(12))
    res = _encoded(d, a2l_data, {("X", 0): "5"}, image)
    assert res.data[3] == 5
    assert res.data[:3] + res.data[4:] == before[:3] + before[4:]
    assert [p.stored for p in _decoded(d, a2l_data, _apply(image, res)).axes[0].points] == [5, 20, 30, 40]


def test_r_a2l_def_123_4_count_byte_is_kept(tmp_path):
    a2l_data = inline(tmp_path, *_std_blocks("CI", with_count=True))
    d = a2ldef.describe_definition("CI", a2l_data)
    image = _std_image(bytes([10, 20, 30, 40]), count=4)
    res = _encoded(d, a2l_data, {(2,): "9"}, image)
    assert res.data[0] == 4 and res.data[9:11] == b"\x00\x09"


def test_r_a2l_def_124_1_edit_with_axis_object_missing(v171):
    d = a2ldef.describe_definition(COM_CURVE, v171)
    image = img(0x810320, _swords(*range(8)))
    res = _encode(d, v171, {(0,): "1"}, image)
    _refusal(
        res,
        "A2L-DEF-AXIS-BYTES",
        f"{COM_CURVE}.X: 9 of the 9 bytes of the axis object ASAM.C.AXIS_PTS.UBYTE_8 are not in the image",
    )


def test_r_a2l_def_124_2_edit_on_partial_record(v171):
    d = a2ldef.describe_definition(COM_CURVE, v171)
    res = _encode(d, v171, {(0,): "1"}, _com_image(5))
    _refusal(
        res,
        "A2L-DEF-AXIS-PARTIAL",
        f"{COM_CURVE}.X: the record holds 5 of its 8 points — a record with fewer points than its maximum is not supported",
    )


def test_r_a2l_def_124_3_edit_with_record_byte_missing(tmp_path):
    a2l_data = inline(tmp_path, valblk("VB", "0x10", "RL_U16", extras=("MATRIX_DIM 2",)))
    d = a2ldef.describe_definition("VB", a2l_data)
    res = _encode(d, a2l_data, {(0,): "1"}, img(0x10, bytes(3)))
    _refusal(res, "A2L-DEF-BYTES", "VB: 1 of its 4 bytes are not in the image")


def _invalid_named_position(v171, position, suffix: str):
    d = a2ldef.describe_definition(ROW_ARRAY, v171)
    res = _encode(d, v171, {position: "1"}, _array_image(0x810100))
    _refusal(res, "A2L-DEF-INDEX", f"{ROW_ARRAY}: {ROW_ARRAY}{suffix} is not a value or axis point of it")


def test_r_a2l_def_125_1_index_past_shape(v171):
    _invalid_named_position(v171, (3, 0), "[3,0]")


def test_r_a2l_def_125_2_index_of_wrong_length(v171):
    _invalid_named_position(v171, (0, 0, 0), "[0,0,0]")


def test_r_a2l_def_125_3_axis_point_of_array(v171):
    _invalid_named_position(v171, ("X", 0), ".X[0]")


def test_r_a2l_def_125_4_malformed_positions_fail_closed(v171):
    positions = [("X",), ("X", 0, 1), (0.5,), None, 0, (-1,), ("Z", 0)]
    d = a2ldef.describe_definition(ROW_ARRAY, v171)
    image = _array_image(0x810100)
    before = dict(image)
    for position in positions:
        res = _encode(d, v171, {position: "1"}, image)
        _refusal(res, "A2L-DEF-INDEX", f"{ROW_ARRAY}: {position!r} is not a value or axis point of it")
    assert image == before


def test_r_a2l_def_126_1_fixed_curve_axis(v171):
    name = "ASAM.C.CURVE.FIX_AXIS.PAR_DIST"
    d = a2ldef.describe_definition(name, v171)
    res = _encode(d, v171, {("X", 0): "0"}, img(0x810350, _swords(*range(6))))
    _refusal(res, "A2L-DEF-AXIS-FIXED", f"{name}.X[0]: the points of a fixed axis are not stored in the image")


def test_r_a2l_def_126_2_fixed_map_axis(v171):
    d = a2ldef.describe_definition(COM_MAP, v171)
    res = _encode(d, v171, {("Y", 2): "4"}, _map_image())
    _refusal(res, "A2L-DEF-AXIS-FIXED", f"{COM_MAP}.Y[2]: the points of a fixed axis are not stored in the image")


def test_r_a2l_def_127_1_common_axis_point(v171):
    d = a2ldef.describe_definition(COM_CURVE, v171)
    res = _encode(d, v171, {("X", 3): "35"}, _com_image())
    _refusal(
        res,
        "A2L-DEF-AXIS-SHARED",
        f"{COM_CURVE}.X[3]: the points of the common axis ASAM.C.AXIS_PTS.UBYTE_8 are not edited through {COM_CURVE}",
    )


def test_r_a2l_def_127_2_definitions_case_shared_axis(defc):
    d = a2ldef.describe_definition("CURVE_DEF_0001", defc["a2l"])
    res = _encode(d, defc["a2l"], {("X", 0): "242.500"}, defc["mem"])
    _refusal(
        res,
        "A2L-DEF-AXIS-SHARED",
        "CURVE_DEF_0001.X[0]: the points of the common axis AXIS_DEF_0001 are not edited through CURVE_DEF_0001",
    )


def test_r_a2l_def_128_1_axis_with_no_points(c08):
    a2l_data = _clear_parse_errors(c08["a2l"])
    d = a2ldef.describe_definition("CURVE_0001", a2l_data)
    res = _encode(d, a2l_data, {("X", 0): "1"}, c08["mem"])
    _refusal(res, "A2L-DEF-AXIS-NONE", "CURVE_0001.X[0]: the record layout RL_U16 holds no points for this axis")


def _monotony_refusal(tmp_path, rule, points, position, text, expected):
    a2l_data = inline(tmp_path, *_std_blocks("CM1", rule))
    d = a2ldef.describe_definition("CM1", a2l_data)
    res = _encode(d, a2l_data, {("X", position): text}, _std_image(bytes(points)))
    _refusal(res, "A2L-DEF-MONOTONY", expected)


def _monotony_accepted(tmp_path, rule, position, text, expected):
    a2l_data = inline(tmp_path, *_std_blocks("CM1", rule))
    d = a2ldef.describe_definition("CM1", a2l_data)
    image = _std_image(bytes([10, 20, 30, 40]))
    res = _encoded(d, a2l_data, {("X", position): text}, image)
    assert [p.stored for p in _decoded(d, a2l_data, _apply(image, res)).axes[0].points] == expected


def test_r_a2l_def_129_1_strict_increase(tmp_path):
    _monotony_refusal(tmp_path, "STRICT_INCREASE", [10, 20, 30, 40], 2, "20", "CM1.X[2]: 20 breaks the STRICT_INCREASE order of the axis")


def test_r_a2l_def_129_2_strict_decrease(tmp_path):
    _monotony_refusal(tmp_path, "STRICT_DECREASE", [40, 30, 20, 10], 1, "45", "CM1.X[1]: 45 breaks the STRICT_DECREASE order of the axis")


def test_r_a2l_def_129_3_mon_increase_takes_equal_point(tmp_path):
    _monotony_accepted(tmp_path, "MON_INCREASE", 2, "20", [10, 20, 20, 40])


def test_r_a2l_def_129_4_mon_increase(tmp_path):
    _monotony_refusal(tmp_path, "MON_INCREASE", [10, 20, 30, 40], 2, "15", "CM1.X[2]: 15 breaks the MON_INCREASE order of the axis")


def test_r_a2l_def_129_5_mon_decrease(tmp_path):
    _monotony_refusal(tmp_path, "MON_DECREASE", [40, 30, 20, 10], 2, "35", "CM1.X[2]: 35 breaks the MON_DECREASE order of the axis")


def test_r_a2l_def_129_6_default_rule(tmp_path):
    _monotony_refusal(tmp_path, None, [10, 20, 30, 40], 3, "30", "CM1.X[3]: 30 breaks the STRICT_MON order of the axis")


def test_r_a2l_def_129_7_monotonous(tmp_path):
    _monotony_refusal(tmp_path, "MONOTONOUS", [10, 20, 30, 40], 1, "5", "CM1.X[2]: 30 breaks the MONOTONOUS order of the axis")


def test_r_a2l_def_129_8_not_mon(tmp_path):
    _monotony_accepted(tmp_path, "NOT_MON", 1, "50", [10, 50, 30, 40])


def test_r_a2l_def_129_9_unedited_point_can_break_order(tmp_path):
    _monotony_refusal(tmp_path, "STRICT_INCREASE", [10, 20, 30, 40], 1, "35", "CM1.X[2]: 30 breaks the STRICT_INCREASE order of the axis")


def test_r_a2l_def_130_1_decode_before_shared_axis(v171):
    d = a2ldef.describe_definition(COM_CURVE, v171)
    image = img(0x810320, _swords(*range(8)))
    res = _encode(d, v171, {("X", 0): "1"}, image)
    assert isinstance(res, a2ldef.Refusal) and res.code == "A2L-DEF-AXIS-BYTES"


def test_r_a2l_def_130_2_axis_before_values(tmp_path):
    a2l_data = inline(tmp_path, *_std_blocks("CM1", None))
    d = a2ldef.describe_definition("CM1", a2l_data)
    edit = {("X", 1): "abc", (0,): "abc"}
    res = _encode(d, a2l_data, edit, _std_image(bytes([10, 20, 30, 40])))
    _refusal(res, "A2L-DEF-NUMBER", "CM1.X[1]: 'abc' is not a number")


def test_r_a2l_def_130_3_each_edit_before_monotony(tmp_path):
    a2l_data = inline(tmp_path, *_std_blocks("CM1", "STRICT_INCREASE"))
    d = a2ldef.describe_definition("CM1", a2l_data)
    edit = {("X", 1): "50", (2,): "x"}
    res = _encode(d, a2l_data, edit, _std_image(bytes([10, 20, 30, 40])))
    _refusal(res, "A2L-DEF-NUMBER", "CM1[2]: 'x' is not a number")


def _parse_order_case(tmp_path):
    return _parse_array_case(tmp_path, "VB")


def test_r_a2l_def_130_4_parse_before_missing_bytes(tmp_path):
    a2l_data, d = _parse_order_case(tmp_path)
    res = _encode(d, a2l_data, {(0,): "1"}, img(0x10, bytes(3)))
    _refusal(
        res,
        "A2L-DEF-PARSE",
        "VB: the A2L cannot be edited while it has parse errors — the first is Line 20: /include x.a2l is not read",
    )


def test_r_a2l_def_130_5_parse_before_invalid_position(tmp_path):
    a2l_data, d = _parse_order_case(tmp_path)
    res = _encode(d, a2l_data, {(99,): "1"}, img(0x10, bytes(3)))
    _refusal(
        res,
        "A2L-DEF-PARSE",
        "VB: the A2L cannot be edited while it has parse errors — the first is Line 20: /include x.a2l is not read",
    )


def _positions(shape: tuple[int, ...]) -> list[tuple[int, ...]]:
    from itertools import product

    return [tuple(reversed(position)) for position in product(*(range(n) for n in reversed(shape)))]


def _value_at(decoded, shape, position):
    return decoded.values[_positions(shape).index(position)]


def _point_span(d, position) -> tuple[int, int]:
    if isinstance(position[0], str):
        axis_def = d.axes[0 if position[0] == "X" else 1]
        k = position[1]
        size = SIZES[axis_def.points.datatype]
        if axis_def.point_order == "INDEX_DECR":
            offset = axis_def.offset + size * (axis_def.point_count - 1 - k)
        else:
            offset = axis_def.offset + size * k
        return offset, size
    size = SIZES[d.datatype]
    if d.index_mode == "COLUMN_DIR" and len(position) == 2:
        flat = position[1] + d.shape[1] * position[0]
    else:
        flat = 0
        for index, extent in zip(reversed(position), reversed(d.shape)):
            flat = flat * extent + index
    return d.values_offset + size * flat, size


def _round_trip_edit(d, a2l_data, image, edit) -> None:
    before = _decoded(d, a2l_data, image)
    before_record = bytes(image[d.address + i] for i in range(d.byte_length))
    res = _encoded(d, a2l_data, edit, image)
    after_image = _apply(image, res)
    after = _decoded(d, a2l_data, after_image)
    edited_spans = set()
    for position, text in edit.items():
        if isinstance(position[0], str):
            after_point = after.axes[0 if position[0] == "X" else 1].points[position[1]]
            element_d = d.axes[0 if position[0] == "X" else 1].points
        else:
            after_point = _value_at(after, d.shape, position)
            element_d = d
        assert isinstance(after_point, a2ldef.Decoded), (d.name, position, after_point)
        _assert_display_agrees(element_d, float(text), after_point.value)
        offset, size = _point_span(d, position)
        edited_spans.update(range(offset, offset + size))
    for position in _positions(d.shape):
        if position not in edit:
            assert _value_at(after, d.shape, position).stored == _value_at(before, d.shape, position).stored, (d.name, position)
    for axis_index, axis_decoded in enumerate(before.axes):
        if axis_decoded.points is None:
            continue
        letter = "X" if axis_index == 0 else "Y"
        for k, old_point in enumerate(axis_decoded.points):
            if (letter, k) not in edit:
                assert after.axes[axis_index].points[k].stored == old_point.stored, (d.name, letter, k)
    for offset, old_byte in enumerate(before_record):
        if offset not in edited_spans:
            assert res.data[offset] == old_byte, (d.name, offset)


def _add_value_edits(plan, d, a2l_data, image, repeats: int = 1) -> None:
    decoded = _decoded(d, a2l_data, image)
    positions = _positions(d.shape)
    for index, position in enumerate(positions):
        other = _value_at(decoded, d.shape, positions[(index + 1) % len(positions)])
        text = format(float(other.value), ".17g")
        for _ in range(repeats):
            plan.append((d, a2l_data, image, {position: text}))


def _round_trip_plan(tmp_path, v171, defc):
    plan = []
    row_d = a2ldef.describe_definition(ROW_ARRAY, v171)
    col_d = a2ldef.describe_definition(COL_ARRAY, v171)
    map_d = a2ldef.describe_definition(COM_MAP, v171)
    _add_value_edits(plan, row_d, v171, _array_image(0x810100), 3)
    _add_value_edits(plan, col_d, v171, _array_image(0x810120), 3)
    _add_value_edits(plan, map_d, v171, _map_image(), 2)

    cd_a2l = inline(tmp_path, *_std_blocks("CD", point_order="INDEX_DECR"))
    cd_d = a2ldef.describe_definition("CD", cd_a2l)
    cd_image = _std_image(bytes([40, 30, 20, 10]))
    cd_decoded = _decoded(cd_d, cd_a2l, cd_image)
    for k, point in enumerate(cd_decoded.axes[0].points):
        for _ in range(5):
            plan.append((cd_d, cd_a2l, cd_image, {("X", k): format(float(point.value), ".17g")}))

    vl_a2l = inline(
        tmp_path,
        cm("CM_01", "LINEAR", "0.1", "0", fmt='"%.15"'),
        valblk("VL01", "0x200", "RL_U16", "CM_01", "0", "6553.5", extras=("MATRIX_DIM 3",)),
    )
    vl_d = a2ldef.describe_definition("VL01", vl_a2l)
    vl_image = img(0x200, _uwords(10, 20, 30))
    _add_value_edits(plan, vl_d, vl_a2l, vl_image, 5)
    plan.append((vl_d, vl_a2l, vl_image, {(0,): "4.1"}))

    vf_a2l = inline(
        tmp_path,
        valblk("VF32", "0x300", "RL_F32", "CM_IDENT", "-1000", "1000", extras=("MATRIX_DIM 3", 'FORMAT "%.15"')),
    )
    vf_d = a2ldef.describe_definition("VF32", vf_a2l)
    vf_image = img(0x300, struct.pack(">fff", 0.0, 0.25, 0.5))
    _add_value_edits(plan, vf_d, vf_a2l, vf_image, 5)
    plan.append((vf_d, vf_a2l, vf_image, {(0,): "0.1"}))

    defc_map = a2ldef.describe_definition("MAP_DEF_0001", defc["a2l"])
    _add_value_edits(plan, defc_map, defc["a2l"], defc["mem"])
    map_decoded = _decoded(defc_map, defc["a2l"], defc["mem"])
    for k, point in enumerate(map_decoded.axes[0].points):
        plan.append((defc_map, defc["a2l"], defc["mem"], {("X", k): format(float(point.value), ".17g")}))
    defc_val = a2ldef.describe_definition("VAL_BLK_DEF_0001", defc["a2l"])
    _add_value_edits(plan, defc_val, defc["a2l"], defc["mem"], 2)

    plan.append((row_d, v171, _array_image(0x810100), {(0, 0): "1", (1, 0): "-7", (2, 3): "12"}))
    plan.append((defc_val, defc["a2l"], defc["mem"], {(0, 0): "36.9", (1, 0): "11.0", (2, 0): "31.8"}))
    return plan


def test_r_a2l_def_131_1_edit_round_trip(tmp_path, v171, defc):
    plan = _round_trip_plan(tmp_path, v171, defc)
    for d, a2l_data, image, edit in plan:
        _round_trip_edit(d, a2l_data, image, edit)
    assert len(plan) >= 200, len(plan)


@pytest.mark.serial_timing
def test_r_a2l_def_131_2_inverse_table_cost_does_not_grow_per_cell(tmp_path):
    entries = []
    size = 0
    i = 0
    while size < 256 * 1024:
        line = f"{i} {2 * i}"
        entries.append(line)
        size += len(line) + 3
        i += 1
    a2l_data = inline(
        tmp_path,
        cm("CM_BIG", "TAB_INTP", fmt='"%.3"', ref="CT_BIG"),
        ctab("CT_BIG", "TAB_INTP", *entries),
        valblk("VBIG", "0x1000", "RL_U16", "CM_BIG", "0", str(2 * i), extras=("MATRIX_DIM 64",)),
    )
    d = a2ldef.describe_definition("VBIG", a2l_data)
    image = img(0x1000, bytes(128))
    table = a2l_data["compu_tabs_by_name"]["CT_BIG"]
    expected = []
    for position in range(64):
        physical = float(200 * position)
        raw, reason, flag = a2l._reverse_table_lookup(physical, table, True)
        assert reason == "" and raw is not None
        expected.append((physical, raw, flag))
    started = time.process_time()
    results = [
        _encoded(d, a2l_data, {(position,): str(physical)}, image)
        for position, (physical, _raw, _flag) in enumerate(expected)
    ]
    elapsed = time.process_time() - started
    assert elapsed < report_margin("R-A2L-DEF.131/2", elapsed, 0.500)
    for position, (res, (_physical, raw, flag)) in enumerate(zip(results, expected)):
        decoded = _decoded(d, a2l_data, _apply(image, res))
        assert decoded.values[position].stored == raw, (position, decoded.values[position], raw, flag)


def _check_inverse(d, a2l_data, physical: float, table: dict, interpolate: bool) -> None:
    expected_raw, expected_reason, expected_flag = a2l._reverse_table_lookup(physical, table, interpolate)
    res = a2ldef._encode_number(d, a2l_data, physical)
    if expected_raw is None:
        _refusal(res, "A2L-DEF-ENCODE", f"{d.name}: {expected_reason}")
        return
    assert isinstance(res, bytes), (d.name, physical, res, expected_raw, expected_reason)
    stored = int.from_bytes(res, "big" if d.byte_order == "big" else "little")
    assert stored == expected_raw, (d.name, physical, stored, expected_raw)
    decoded = a2ldef.decode_definition(d, a2l_data, {d.address + i: b for i, b in enumerate(res)})
    assert isinstance(decoded, a2ldef.Decoded), decoded
    if expected_flag is not None:
        written = float(expected_flag.rsplit(" ", 1)[1])
        assert decoded.value == written, (d.name, physical, decoded.value, expected_flag)


def test_r_a2l_def_131_3_exact_inverse_table_semantics(tmp_path):
    table_lines = ("0 0", "1 10", "2 10", '3 "not-a-number"', "4 40")
    physical_values = (10.0, 10.0 + 5e-10, 15.0, -1.0, 41.0, float("nan"))
    for kind in ("TAB_INTP", "TAB_NOINTP"):
        a2l_data = inline(
            tmp_path,
            cm("CM_I", kind, fmt='"%.3"', ref="CT_I"),
            ctab("CT_I", kind, *table_lines),
            valblk("VI", "0x10", "RL_U16", "CM_I", "-1000", "1000", extras=("MATRIX_DIM 2",)),
        )
        parent = a2ldef.describe_definition("VI", a2l_data)
        d = a2ldef._element_definition(parent, (0,))
        table = a2l_data["compu_tabs_by_name"]["CT_I"]
        for physical in physical_values:
            _check_inverse(d, a2l_data, physical, table, kind == "TAB_INTP")

    for name, lines, expected_reason in (
        ("EMPTY", (), "lookup table missing or empty"),
        ("NONNUM", ('3 "not-a-number"',), "lookup table has no numeric entries"),
    ):
        a2l_data = inline(
            tmp_path,
            cm("CM_I", "TAB_INTP", fmt='"%.3"', ref="CT_I"),
            ctab("CT_I", "TAB_INTP", *lines),
            valblk(name, "0x10", "RL_U16", "CM_I", "-1000", "1000", extras=("MATRIX_DIM 2",)),
        )
        d = a2ldef._element_definition(a2ldef.describe_definition(name, a2l_data), (0,))
        table = a2l_data["compu_tabs_by_name"]["CT_I"]
        res = a2ldef._encode_number(d, a2l_data, 1.0)
        _refusal(res, "A2L-DEF-ENCODE", f"{name}[0]: {expected_reason}")

    a2l_data = inline(
        tmp_path,
        cm("CM_E", "TAB_VERB", fmt='"%.0"', ref="VT_E"),
        vtab("VT_E", "2", '1 "X"', '2 "X"'),
        valblk("VE", "0x10", "RL_U8", "CM_E", "0", "2", extras=("MATRIX_DIM 2",)),
    )
    d = a2ldef.describe_definition("VE", a2l_data)
    res = _encoded(d, a2l_data, {(0,): "X"}, img(0x10, bytes(2)))
    assert res.data[0] == 1


def test_r_a2l_def_132_1_unedited_cells_keep_values_and_bytes(tmp_path, v171, defc):
    plan = _round_trip_plan(tmp_path, v171, defc)
    for d, a2l_data, image, edit in plan:
        _round_trip_edit(d, a2l_data, image, edit)
    assert len(plan) >= 200


def _axis_span_blocks(address: str = "0x10", value_address: str = "0x14"):
    return (
        rl("RL_AXS", "NO_AXIS_PTS_X 1 UBYTE", "AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT"),
        axis_pts("AXS", address, "RL_AXS", "4"),
        characteristic("VS", "VALUE", value_address, "RL_U8", "NO_COMPU_METHOD", "0", "255"),
    )


def test_r_a2l_def_140_1_encode_overlapping_axis_pts_is_refused(tmp_path):
    a2l_data = inline(tmp_path, *_axis_span_blocks())
    d = a2ldef.describe_definition("VS", a2l_data)
    assert d.shared_with == "AXS"
    res = a2ldef.encode_definition(d, a2l_data, "35", img(0x10, bytes(5)))
    _refusal(res, "A2L-DEF-OVERLAP", "VS: its bytes at 0x14 are shared with AXS")


def test_r_a2l_def_140_2_value_just_past_axis_pts_record(tmp_path):
    a2l_data = inline(tmp_path, *_axis_span_blocks(value_address="0x15"))
    d = a2ldef.describe_definition("VS", a2l_data)
    assert d.shared_with is None
    res = a2ldef.encode_definition(d, a2l_data, "35", img(0x10, bytes(6)))
    assert res == a2ldef.Encoded(0x15, b"\x23", ())


def test_r_a2l_def_140_3_axis_pts_without_declared_address_joins_no_span(tmp_path):
    a2l_data = inline(
        tmp_path,
        rl("RL_AXS", "NO_AXIS_PTS_X 1 UBYTE", "AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT"),
        axis_pts("AXS", "0xZZ", "RL_AXS", "4"),
        characteristic("VS", "VALUE", "0x10", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
    )
    d = a2ldef.describe_definition("VS", a2l_data)
    assert d.shared_with is None
    res = a2ldef.encode_definition(d, a2l_data, "35", {0x10: 0})
    assert res == a2ldef.Encoded(0x10, b"\x23", ())


def test_r_a2l_def_140_4_axis_pts_inherits_no_homonymous_mask(tmp_path):
    a2l_data = inline(
        tmp_path,
        rl("RL_AXS", "NO_AXIS_PTS_X 1 UBYTE", "AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT"),
        axis_pts("AXS", "0x10", "RL_AXS", "4"),
        characteristic("AXS", "VALUE", "0x100", "RL_U8", "NO_COMPU_METHOD", "0", "255", extras=("BIT_MASK 0x0F",)),
        characteristic("MW", "VALUE", "0x10", "RL_U16", "NO_COMPU_METHOD", "0", "65535", extras=("BIT_MASK 0x000F",)),
    )
    d = a2ldef.describe_definition("MW", a2l_data)
    assert d.shared_with == "AXS"
    image = img(0x10, bytes(2)) | {0x100: 0}
    res = a2ldef.encode_definition(d, a2l_data, "1", image)
    _refusal(res, "A2L-DEF-OVERLAP", "MW: its bytes at 0x10 are shared with AXS")


def _final_curve_blocks(masked: bool = False, name: str = "C8", value_address: str = "0x21"):
    curve_mask = ("BIT_MASK 0x00F0",) if masked else ()
    value_mask = ("BIT_MASK 0x0F",) if masked else ()
    return (
        rl("RL_C8", "FNC_VALUES 1 UWORD ROW_DIR DIRECT"),
        curve(name, "0x20", "RL_C8", axis("STD_AXIS", "CM_IDENT", "4", "0", "255"), extras=curve_mask),
        characteristic("V", "VALUE", value_address, "RL_U8", "NO_COMPU_METHOD", "0", "255", extras=value_mask),
    )


def test_r_a2l_def_140_5_final_curve_span_drives_overlap(tmp_path):
    a2l_data = inline(tmp_path, *_final_curve_blocks())
    c = a2ldef.describe_definition("C8", a2l_data)
    d = a2ldef.describe_definition("V", a2l_data)
    assert c.byte_length == 8 and d.shared_with == "C8"
    res = a2ldef.encode_definition(d, a2l_data, "7", img(0x20, bytes(8)) | {0x21: 0})
    _refusal(res, "A2L-DEF-OVERLAP", "V: its bytes at 0x21 are shared with C8")


def test_r_a2l_def_140_6_final_span_pair_with_masks_cannot_exempt(tmp_path):
    a2l_data = inline(tmp_path, *_final_curve_blocks(masked=True))
    d = a2ldef.describe_definition("V", a2l_data)
    res = a2ldef.encode_definition(d, a2l_data, "7", img(0x20, bytes(8)) | {0x21: 0})
    _refusal(res, "A2L-DEF-OVERLAP", "V: its bytes at 0x21 are shared with C8")


def test_r_a2l_def_140_7_std_point_inherits_parent_shared_bytes(tmp_path):
    a2l_data = inline(
        tmp_path,
        rl("RL_C", "AXIS_PTS_X 1 UBYTE INDEX_INCR DIRECT", "FNC_VALUES 2 UWORD ROW_DIR DIRECT"),
        curve("C", "0x10", "RL_C", axis("STD_AXIS", "CM_IDENT", "4", "0", "255")),
        characteristic("OTHER", "VALUE", "0x11", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
    )
    d = a2ldef.describe_definition("C", a2l_data)
    point = a2ldef._element_definition(d, ("X", 0))
    assert point.shared_with == "OTHER"
    image = img(0x10, bytes(12))
    res = _encode(d, a2l_data, {("X", 0): "5"}, image)
    _refusal(res, "A2L-DEF-OVERLAP", "C.X[0]: its bytes at 0x10 are shared with OTHER")


def test_r_a2l_def_140_8_arrays_receive_no_clean_mask_exemption(tmp_path):
    for byte_order in ("MSB_FIRST", "MSB_LAST"):
        a2l_data = inline(
            tmp_path,
            valblk("ARR", "0x10", "RL_U16", "NO_COMPU_METHOD", "0", "65535", extras=("MATRIX_DIM 2", "BIT_MASK 0xFF00")),
            characteristic("S", "VALUE", "0x12", "RL_U8", "NO_COMPU_METHOD", "0", "255", extras=("BIT_MASK 0x0F",)),
            byte_order=byte_order,
        )
        arr = a2ldef.describe_definition("ARR", a2l_data)
        scalar = a2ldef.describe_definition("S", a2l_data)
        assert arr.shared_with == "S" and scalar.shared_with == "ARR"
        image = img(0x10, bytes(4))
        res = _encode(arr, a2l_data, {(1,): "1"}, image)
        _refusal(res, "A2L-DEF-OVERLAP", "ARR[1]: its bytes at 0x12 are shared with S")
        res = a2ldef.encode_definition(scalar, a2l_data, "1", image)
        _refusal(res, "A2L-DEF-OVERLAP", "S: its bytes at 0x12 are shared with ARR")

    a2l_data = inline(
        tmp_path,
        rl("RL_C", "AXIS_PTS_X 1 UBYTE INDEX_INCR DIRECT", "FNC_VALUES 2 UWORD ROW_DIR DIRECT"),
        curve("C", "0x20", "RL_C", axis("STD_AXIS", "CM_IDENT", "4", "0", "255"), extras=("BIT_MASK 0xFF00",)),
        characteristic("S", "VALUE", "0x21", "RL_U8", "NO_COMPU_METHOD", "0", "255", extras=("BIT_MASK 0x0F",)),
    )
    d = a2ldef.describe_definition("C", a2l_data)
    res = _encode(d, a2l_data, {("X", 0): "1"}, img(0x20, bytes(12)))
    _refusal(res, "A2L-DEF-OVERLAP", "C.X[0]: its bytes at 0x20 are shared with S")


def test_r_a2l_def_140_9_cross_page_final_span_and_single_materialization(tmp_path, monkeypatch):
    a2l_data = inline(
        tmp_path,
        rl("RL_CX", "AXIS_PTS_X 1 UBYTE INDEX_INCR DIRECT", "ALIGNMENT_INT64 32", "FNC_VALUES 2 A_UINT64 ROW_DIR DIRECT"),
        curve("CX", "0x20", "RL_CX", axis("STD_AXIS", "CM_IDENT", "4", "0", "255")),
        characteristic("V", "VALUE", "0x40", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
    )
    assert a2ldef.describe_definition("CX", a2l_data).byte_length == 64
    calls = Counter()
    real_describe_one = a2ldef._describe_one

    def counted(name, *args, **kwargs):
        calls[name] += 1
        return real_describe_one(name, *args, **kwargs)

    monkeypatch.setattr(a2ldef, "_describe_one", counted)
    defs = a2ldef.describe_definitions(["V", "V"], a2l_data)
    assert defs["V"].shared_with == "CX"
    assert defs["V"].address == 0x40
    assert calls["V"] == 1 and calls["CX"] == 1, calls
    d = defs["V"]
    res = a2ldef.encode_definition(d, a2l_data, "7", img(0x20, bytes(64)))
    _refusal(res, "A2L-DEF-OVERLAP", "V: its bytes at 0x40 are shared with CX")


def test_r_a2l_def_153_1_scalar_values_through_encode_values(tmp_path):
    a2l_data = inline2(
        tmp_path,
        _val("N", "0x10", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
        *_enum_blocks("CM_E", "VT_E", "2", '0 "OFF"', '1 "ON"'),
        _val("E", "0x11", "RL_U8", "CM_E", "0", "1"),
        _ascii("T", "0x20", "2"),
    )
    for name, text, expected in (("N", "7", b"\x07"), ("E", "ON", b"\x01"), ("T", "A", b"A\x00")):
        d = a2ldef.describe_definition(name, a2l_data)
        image = img(d.address, bytes(d.byte_length))
        scalar = a2ldef.encode_definition(d, a2l_data, text, image)
        assert scalar == a2ldef.Encoded(d.address, expected, ())
        assert _encode(d, a2l_data, {(0,): text}, image) == scalar
        res = _encode(d, a2l_data, {(1,): text}, image)
        assert isinstance(res, a2ldef.Refusal) and res.code == "A2L-DEF-INDEX"
        assert res.message == f"{name}: {name}[1] is not a value or axis point of it"


def test_r_a2l_def_154_1_unknown_monotony_rule_refuses(tmp_path):
    a2l_data = inline(tmp_path, *_std_blocks("C", "UNKNOWN_RULE"))
    d = a2ldef.describe_definition("C", a2l_data)
    res = _encode(d, a2l_data, {("X", 0): "5"}, _std_image(bytes([10, 20, 30, 40])))
    _refusal(res, "A2L-DEF-MONOTONY", "C.X[0]: the monotony rule UNKNOWN_RULE is not supported")


def test_r_a2l_def_155_1_unedited_point_decode_refusal_propagates(tmp_path):
    a2l_data = inline(
        tmp_path,
        cm("CM_RAT", "RAT_FUNC", "1", "0", "1", "0", "0", "1"),
        rl("RL_C", "AXIS_PTS_X 1 UBYTE INDEX_INCR DIRECT", "FNC_VALUES 2 UWORD ROW_DIR DIRECT"),
        curve("C", "0x100", "RL_C", axis("STD_AXIS", "CM_RAT", "4", "0", "100", "MONOTONY STRICT_INCREASE")),
    )
    d = a2ldef.describe_definition("C", a2l_data)
    res = _encode(d, a2l_data, {("X", 1): "5"}, _std_image(bytes([0, 1, 2, 3])))
    _refusal(res, "A2L-DEF-DECODE", "C.X[0]: RAT_FUNC has no real root for this value")


def test_r_a2l_def_155_2_breaking_enum_point_text_is_bounded(tmp_path):
    long_text = "L" * 300
    a2l_data = inline(
        tmp_path,
        cm("CM_E", "TAB_VERB", fmt='"%.0"', ref="VT_E"),
        vtab("VT_E", "4", '0 "zero"', '1 "one"', f'2 "{long_text}"', '3 "three"'),
        rl("RL_C", "AXIS_PTS_X 1 UBYTE INDEX_INCR DIRECT", "FNC_VALUES 2 UWORD ROW_DIR DIRECT"),
        curve("C", "0x100", "RL_C", axis("STD_AXIS", "CM_E", "4", "0", "3", "MONOTONY STRICT_INCREASE")),
    )
    d = a2ldef.describe_definition("C", a2l_data)
    res = _encode(d, a2l_data, {("X", 1): long_text}, _std_image(bytes([3, 1, 2, 3])))
    _refusal(res, "A2L-DEF-MONOTONY", f"C.X[1]: {'L' * 256}… breaks the STRICT_INCREASE order of the axis")
    assert len(res.message) < 400



def test_r_a2l_def_125_5_public_element_name_is_total_and_bounded(v171):
    d = a2ldef.describe_definition(ROW_ARRAY, v171)
    name = "\x1b" + "N" * 300
    hostile = replace(d, name=name, _name_echo=None)
    echo = "\ufffd" + "N" * 255 + "…"
    assert a2ldef.element_name(hostile, (1, 2)) == f"{echo}[1,2]"
    assert a2ldef.element_name(hostile, ("X", 1)) == f"{echo}.X[1]"
    for position in (("X",), ("X", 0, 1), (0.5,), None, 0, (-1,), ("Z", 0)):
        assert a2ldef.element_name(hostile, position) == repr(position)


def test_r_a2l_def_131_4_nonfinite_interpolation_refuses_without_raising(tmp_path):
    a2l_data = inline(
        tmp_path,
        cm("CM_INF", "TAB_INTP", fmt='"%.3"', ref="CT_INF"),
        ctab("CT_INF", "TAB_INTP", "0 -inf", "1 inf"),
        valblk("VINF", "0x10", "RL_U16", "CM_INF", "-1000", "1000", extras=("MATRIX_DIM 2",)),
    )
    d = a2ldef._element_definition(a2ldef.describe_definition("VINF", a2l_data), (0,))
    res = a2ldef._encode_number(d, a2l_data, 0.0)
    _refusal(res, "A2L-DEF-ENCODE", "VINF[0]: the value 0.0 is not invertible in this table")

    nan_data = inline(
        tmp_path,
        cm("CM_NANY", "TAB_INTP", fmt='"%.3"', ref="CT_NANY"),
        ctab("CT_NANY", "TAB_INTP", "0 0", "1 nan", "2 1"),
        valblk("VNANY", "0x20", "RL_U16", "CM_NANY", "-1000", "1000", extras=("MATRIX_DIM 2",)),
    )
    d = a2ldef._element_definition(a2ldef.describe_definition("VNANY", nan_data), (0,))
    res = a2ldef._encode_number(d, nan_data, 0.5)
    _refusal(res, "A2L-DEF-ENCODE", "VNANY[0]: the value 0.5 is not invertible in this table")


def test_r_a2l_def_131_5_nointp_neighbours_and_exact_match_scale(tmp_path, monkeypatch):
    a2l_data = inline(
        tmp_path,
        cm("CM_NEAR", "TAB_NOINTP", fmt='"%.3"', ref="CT_NEAR"),
        ctab("CT_NEAR", "TAB_NOINTP", "2 -1e-9", "5 0.5", "7 2.0"),
        valblk("VNEAR", "0x10", "RL_U16", "CM_NEAR", "-1000", "1000", extras=("MATRIX_DIM 2",)),
    )
    d = a2ldef._element_definition(a2ldef.describe_definition("VNEAR", a2l_data), (0,))
    res = a2ldef._encode_number(d, a2l_data, 1e308)
    _refusal(
        res,
        "A2L-DEF-ENCODE",
        "VNEAR[0]: the value 1e+308 is not a table value - "
        "the nearest table values are -1e-09 and 0.5",
    )

    for kind in ("TAB_INTP", "TAB_NOINTP"):
        for entries, physical in (
            (("0 1.0", "1 1.0000000005"), 1.0000000005),
            (("0 1e-10", "1 0"), 5e-10),
        ):
            tolerant = inline(
                tmp_path,
                cm("CM_TOL", kind, fmt='"%.15"', ref="CT_TOL"),
                ctab("CT_TOL", kind, *entries),
                valblk("VTOL", "0x10", "RL_U16", "CM_TOL", "-1000", "1000", extras=("MATRIX_DIM 2",)),
            )
            parent = a2ldef.describe_definition("VTOL", tolerant)
            element = a2ldef._element_definition(parent, (0,))
            _check_inverse(element, tolerant, physical, tolerant["compu_tabs_by_name"]["CT_TOL"], kind == "TAB_INTP")

    real_isclose = a2ldef.math.isclose
    match_calls = Counter()

    def counted_isclose(a, b, *, rel_tol=1e-09, abs_tol=0.0):
        if abs_tol == 1e-9:
            match_calls["inverse"] += 1
        return real_isclose(a, b, rel_tol=rel_tol, abs_tol=abs_tol)

    monkeypatch.setattr(a2ldef.math, "isclose", counted_isclose)
    for name, entries, physical, expected_raw in (
        ("DUP", tuple(f"{i} 1" for i in range(20_000)), 1.0 + 5e-10, 0),
        ("NAN", ("0 nan", "0 nan") + tuple(f"{i} {i}" for i in range(1, 20_000)), 19_999.0 + 5e-10, 19_999),
    ):
        scaled = inline(
            tmp_path,
            cm(f"CM_{name}", "TAB_NOINTP", fmt='"%.3"', ref=f"CT_{name}"),
            ctab(f"CT_{name}", "TAB_NOINTP", *entries),
            valblk(f"V{name}", "0x100", "RL_U16", f"CM_{name}", "0", "65535", extras=("MATRIX_DIM 64",)),
        )
        parent = a2ldef.describe_definition(f"V{name}", scaled)
        image = img(0x100, bytes(128))
        for position in range(64):
            res = _encoded(parent, scaled, {(position,): str(physical)}, image)
            assert res.data[2 * position:2 * position + 2] == expected_raw.to_bytes(2, "big")
    assert match_calls["inverse"] == 0


def test_r_a2l_def_131_6_long_and_nonprintable_limit_echoes(tmp_path):
    long_lower = "0" * 2_000 + "1"
    long_upper = "0" * 2_000 + "2"
    long_zero = "0" * 2_000
    long_extended = "0" * 2_000 + "3"
    a2l_data = inline(
        tmp_path,
        valblk(
            "VLIM",
            "0x10",
            "RL_U16",
            "NO_COMPU_METHOD",
            long_lower,
            long_upper,
            extras=("MATRIX_DIM 2", f"EXTENDED_LIMITS {long_zero} {long_extended}"),
        ),
    )
    d = a2ldef.describe_definition("VLIM", a2l_data)
    image = img(0x10, bytes(4))
    res = _encoded(d, a2l_data, {(0,): "0"}, image)
    echo = "0" * 256 + "…"
    assert len(res.notices) == 1
    notice = res.notices[0]
    assert notice.startswith(
        f"VLIM[0]: 0 is outside the limits {echo}..{echo} "
        "and inside the extended limits "
    )
    assert len(notice) == 1_024 and notice.endswith("…")
    controlled = a2ldef._read_limits("\n1", "\t2")
    assert controlled.lower_text == "\ufffd1"
    assert controlled.upper_text == "\ufffd2"


def test_r_a2l_def_140_10_over_cap_span_before_window_still_blocks(tmp_path):
    a2l_data = inline(
        tmp_path,
        characteristic("BIG", "VALUE", "0x0", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
        characteristic("V", "VALUE", "0x100000", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
    )
    next(tag for tag in a2l_data["tags"] if tag.get("name") == "BIG")["length"] = 1_048_577
    d = a2ldef.describe_definition("V", a2l_data)
    assert d.shared_with == "BIG"
    image = {0x100000: 0}
    before = dict(image)
    res = a2ldef.encode_definition(d, a2l_data, "7", image)
    _refusal(res, "A2L-DEF-OVERLAP", "V: its bytes at 0x100000 are shared with BIG")
    assert image == before


def test_r_a2l_def_140_11_refused_matrix_uses_only_its_final_point(tmp_path):
    a2l_data = inline(
        tmp_path,
        meas("M", "UBYTE", addr="0x10", extras=("MATRIX_DIM x 2",)),
        characteristic("V", "VALUE", "0x12", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
        characteristic("VMD", "VALUE", "0x20", "RL_U16", "NO_COMPU_METHOD", "0", "65535", extras=("MATRIX_DIM 2 2",)),
        characteristic("V2", "VALUE", "0x21", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
    )
    a2l_data = _clear_parse_errors(a2l_data)
    next(tag for tag in a2l_data["tags"] if tag.get("name") == "M")["length"] = 4
    malformed = a2ldef.describe_definition("M", a2l_data)
    value_matrix = a2ldef.describe_definition("VMD", a2l_data)
    assert malformed.byte_length is None and malformed.shared_with is None
    assert malformed.refusal.code == "A2L-DEF-MATRIX"
    assert value_matrix.byte_length is None and value_matrix.shared_with is None
    assert value_matrix.refusal.code == "A2L-DEF-MATRIX"
    for name, address in (("V", 0x12), ("V2", 0x21)):
        d = a2ldef.describe_definition(name, a2l_data)
        assert d.shared_with is None
        assert a2ldef.encode_definition(d, a2l_data, "7", {address: 0}) == a2ldef.Encoded(address, b"\x07", ())
