"""Batch-103 Inc 3a (G-T1) - arrays and axes, decode side (S2.7g), the cited
rows and the 3a arms of the acceptance cases.

Expected values are the requirement's exact texts, the file's own bytes, the
generator's planned object list or ``struct`` — never derived from the artifact
under test.  On the Inc 3a base these tests are RED (``decode_values`` does not
exist and the base's single ``decode_definition`` refuses a VAL_BLK / CURVE /
MAP with ``A2L-DEF-KIND``).

Dependencies:
    - ``s19_app.tui.a2l_definition`` (under test), the app's A2L parser and
      S19 loader, ``tools/synth/make_release_case.py`` (case 08 and the
      definitions case)
"""

from __future__ import annotations

import random
import struct
import sys
from pathlib import Path
from typing import Mapping

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SYNTH_DIR = REPO_ROOT / "tools" / "synth"
SEED = 20260001

if str(SYNTH_DIR) not in sys.path:
    sys.path.insert(0, str(SYNTH_DIR))

import make_release_case as gen  # noqa: E402

from s19_app.core import S19File  # noqa: E402
from s19_app.tui import a2l_definition as a2ldef  # noqa: E402
from s19_app.tui.a2l_parse import parse_a2l_file  # noqa: E402
from tests.support.b103_a2l_arrays import (  # noqa: E402
    axis,
    axis_pts,
    cm,
    ctab,
    curve,
    img,
    inline,
    is_refused,
    load,
    mapchar,
    meas,
    rl,
    valblk,
    vtab,
)

Definition = a2ldef.Definition
Decoded = a2ldef.Decoded
Refusal = a2ldef.Refusal


def _swords(*vals: int) -> bytes:
    return b"".join(struct.pack("<h", v) for v in vals)


def _swords_be(*vals: int) -> bytes:
    return b"".join(struct.pack(">h", v) for v in vals)


def _uwords(*vals: int) -> bytes:
    return b"".join(struct.pack("<H", v) for v in vals)


def _decode(d: Definition, a2l: dict, image: Mapping[int, int]):
    assert hasattr(a2ldef, "decode_values"), "decode_values not implemented"
    return a2ldef.decode_values(d, a2l, image)


def _stored(res) -> list:
    return [v.stored for v in res.values]


def _texts(res) -> list:
    return [v.text for v in res.values]


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def v171() -> dict:
    return load("ASAP2_Demo_V171.a2l")


@pytest.fixture(scope="module")
def softa() -> dict:
    return load("software_a.a2l")


@pytest.fixture(scope="module")
def upd2() -> dict:
    return load("update_test2.a2l")


@pytest.fixture(scope="module")
def c08(tmp_path_factory: pytest.TempPathFactory) -> dict:
    folder = tmp_path_factory.mktemp("b103_i3a_c08_dec")
    gen.generate(folder, SEED, 1.0)
    regions = gen.compute_region_sizes(1.0)
    objs = gen.build_objects(regions, random.Random(SEED))
    return {
        "a2l": parse_a2l_file(folder / "firmware.a2l"),
        "a2l_issues": parse_a2l_file(folder / "firmware_issues.a2l"),
        "mem": S19File(str(folder / "firmware.s19")).get_memory_map(),
        "objs": objs,
        "by_name": {o["name"]: o for o in objs},
    }


@pytest.fixture(scope="module")
def defc(tmp_path_factory: pytest.TempPathFactory) -> dict:
    folder = tmp_path_factory.mktemp("b103_i3a_defc")
    paths = gen.generate_definitions_case(folder, SEED)
    return {
        "a2l": parse_a2l_file(paths["a2l"]),
        "mem": S19File(str(paths["s19"])).get_memory_map(),
    }


# --------------------------------------------------------------------------
# S2.7g - decoding
# --------------------------------------------------------------------------

def test_r_a2l_def_105_1_integer_elements(v171):
    d = a2ldef.describe_definition("ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR", v171)
    image = img(0x810100, _swords(*range(1, 13)))
    res = _decode(d, v171, image)
    assert _texts(res) == [str(i) for i in range(1, 13)]
    assert _stored(res) == list(range(1, 13))


def test_r_a2l_def_105_2_enum_elements(tmp_path):
    blocks = [cm("CM_E", "TAB_VERB", fmt='"%.0"', ref="VT_E"),
              vtab("VT_E", "2", '0 "OFF"', '1 "ON"'),
              valblk("VE", "0x10", "RL_U8", "CM_E", "0", "255", "MATRIX_DIM 2")]
    a2l = inline(tmp_path, *blocks)
    d = a2ldef.describe_definition("VE", a2l)
    res = _decode(d, a2l, img(0x10, bytes([0x01, 0x00])))
    assert _texts(res) == ["ON", "OFF"]


def test_r_a2l_def_105_3_converted_elements(tmp_path):
    blocks = [cm("CM_L", "LINEAR", "0.5", "0", fmt='"%.1"'),
              valblk("VN", "0x10", "RL_U16", "CM_L", "0", "100", "MATRIX_DIM 2")]
    a2l = inline(tmp_path, *blocks)
    d = a2ldef.describe_definition("VN", a2l)
    res = _decode(d, a2l, img(0x10, bytes([0x00, 0x03, 0x00, 0x04])))
    assert _texts(res) == ["1.5", "2.0"]


def test_r_a2l_def_105_4_masked_elements(tmp_path):
    a2l = inline(tmp_path, valblk("VM", "0x10", "RL_U16", "CM_IDENT", "0", "65535",
                                  "MATRIX_DIM 2", "BIT_MASK 0x0F00"))
    d = a2ldef.describe_definition("VM", a2l)
    res = _decode(d, a2l, img(0x10, bytes([0x12, 0x34, 0x0A, 0x00])))
    assert _stored(res) == [2, 10]


def test_r_a2l_def_105_5_unmatched_enum_axis_point(tmp_path):
    ax_x = axis("STD_AXIS", "CM_IDENT", "2", "0", "255")
    ax_y = axis("STD_AXIS", "CM_E", "2", "0", "255")
    blocks = [cm("CM_E", "TAB_VERB", fmt='"%.0"', ref="VT_E"),
              vtab("VT_E", "2", '0 "OFF"', '1 "ON"'),
              mapchar("M", "0x100", "RL_M", ax_x, ax_y,
                      extras=(rl("RL_M", "AXIS_PTS_X 1 UBYTE INDEX_INCR DIRECT",
                                 "AXIS_PTS_Y 2 UBYTE INDEX_INCR DIRECT",
                                 "FNC_VALUES 3 UWORD ROW_DIR DIRECT"),))]
    a2l = inline(tmp_path, *blocks)
    d = a2ldef.describe_definition("M", a2l)
    # image: X points 0A 14, Y points 01 07, then the 4 UWORD value bytes (12 bytes)
    image = img(0x100, bytes([0x0A, 0x14, 0x01, 0x07] + [0] * 8))
    res = _decode(d, a2l, image)
    y_points = res.axes[1].points
    assert y_points[0].text == "ON"
    assert y_points[1].text == "7 (no text)"


def test_r_a2l_def_106_1_row_dir_2d(v171):
    d = a2ldef.describe_definition("ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR", v171)
    image = img(0x810100, _swords(*range(1, 13)))
    res = _decode(d, v171, image)
    assert res.values[1].stored == 2  # (1,0)
    assert res.values[3].stored == 4  # (0,1)
    assert res.values[11].stored == 12  # (2,3)


def test_r_a2l_def_106_2_row_dir_3d(v171):
    d = a2ldef.describe_definition("ASAM.M.MATRIX_DIM_8_4_2.UBYTE.IDENTICAL", v171)
    image = img(0x13A30, bytes(range(64)))
    res = _decode(d, v171, image)
    assert res.values[41].stored == 41  # (1,1,1)
    assert res.values[63].stored == 63  # (7,3,1)


def test_r_a2l_def_106_3_row_dir_map(v171):
    d = a2ldef.describe_definition("ASAM.C.MAP.COM_AXIS.FIX_AXIS", v171)
    image = img(0x810440, _swords(*range(24)))
    image.update(img(0x810340, bytes([0x08, 0x46, 0x3C, 0x32, 0x28, 0x1E, 0x14, 0x0A, 0x00])))
    res = _decode(d, v171, image)
    assert res.values[17].stored == 17  # (1,2)
    assert res.values[7].stored == 7  # (7,0)
    assert res.values[8].stored == 8  # (0,1)


def test_r_a2l_def_107_1_column_dir_2d(v171):
    d = a2ldef.describe_definition("ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.COLUMN_DIR", v171)
    image = img(0x810120, _swords(*range(1, 13)))
    res = _decode(d, v171, image)
    assert res.values[1].stored == 5  # (1,0)
    assert res.values[3].stored == 2  # (0,1)
    assert res.values[11].stored == 12  # (2,3)


def test_r_a2l_def_107_2_case08_map_column_dir(c08):
    d = a2ldef.describe_definition("MAP_0001", c08["a2l"])
    o = c08["by_name"]["MAP_0001"]
    raw = o["raw_bytes"]
    endian = ">" if o["big_endian"] else "<"
    res = _decode(d, c08["a2l"], c08["mem"])
    expected = []
    for k in range(64):
        x, y = k % 8, k // 8
        off = 2 * (y + 8 * x)
        expected.append(struct.unpack(endian + "H", raw[off:off + 2])[0])
    assert _stored(res) == expected


def test_r_a2l_def_107_3_case08_curve_column_dir(c08):
    d = a2ldef.describe_definition("CURVE_0001", c08["a2l"])
    o = c08["by_name"]["CURVE_0001"]
    endian = ">" if o["big_endian"] else "<"
    res = _decode(d, c08["a2l"], c08["mem"])
    expected = [struct.unpack(endian + "H", o["raw_bytes"][2 * i:2 * i + 2])[0] for i in range(32)]
    assert _stored(res) == expected


def test_r_a2l_def_108_1_index_incr_points(tmp_path):
    block = curve("CI", "0x100", "RL_CI", axis("STD_AXIS", "CM_IDENT", "4", "0", "255"),
                  extras=(rl("RL_CI", "NO_AXIS_PTS_X 1 UBYTE",
                             "AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT",
                             "FNC_VALUES 3 UWORD ROW_DIR DIRECT"),))
    a2l = inline(tmp_path, block)
    d = a2ldef.describe_definition("CI", a2l)
    image = img(0x100, bytes([0x04, 0x0A, 0x14, 0x1E, 0x28, 0, 0, 0, 0, 0, 0, 0, 0]))
    res = _decode(d, a2l, image)
    assert [p.stored for p in res.axes[0].points] == [10, 20, 30, 40]


def test_r_a2l_def_108_2_definitions_case_map_axis_index_incr(defc):
    d = a2ldef.describe_definition("MAP_DEF_0001", defc["a2l"])
    res = _decode(d, defc["a2l"], defc["mem"])
    assert [p.stored for p in res.axes[0].points] == [224, 577, 648, 909]


def test_r_a2l_def_109_1_index_decr_asam_axis_object(v171):
    d = a2ldef.describe_definition("ASAM.C.CURVE.COM_AXIS", v171)
    image = img(0x810320, _swords(*range(8)))
    image.update(img(0x810340, bytes([0x08, 0x46, 0x3C, 0x32, 0x28, 0x1E, 0x14, 0x0A, 0x00])))
    res = _decode(d, v171, image)
    assert [p.stored for p in res.axes[0].points] == [0, 10, 20, 30, 40, 50, 60, 70]


def test_r_a2l_def_109_2_index_decr_in_record(tmp_path):
    block = curve("CD", "0x100", "RL_CD", axis("STD_AXIS", "CM_IDENT", "4", "0", "255"),
                  extras=(rl("RL_CD", "NO_AXIS_PTS_X 1 UBYTE",
                             "AXIS_PTS_X 2 UBYTE INDEX_DECR DIRECT",
                             "FNC_VALUES 3 UWORD ROW_DIR DIRECT"),))
    a2l = inline(tmp_path, block)
    d = a2ldef.describe_definition("CD", a2l)
    image = img(0x100, bytes([0x04, 0x28, 0x1E, 0x14, 0x0A, 0, 0, 0, 0, 0, 0, 0, 0]))
    res = _decode(d, a2l, image)
    assert [p.stored for p in res.axes[0].points] == [10, 20, 30, 40]


def test_r_a2l_def_110_1_fix_axis_par(tmp_path):
    block = curve("F", "0x100", "RL_U16", axis("FIX_AXIS", "CM_IDENT", "4", "0", "255",
                                               "FIX_AXIS_PAR 0 2 4"))
    a2l = inline(tmp_path, block)
    d = a2ldef.describe_definition("F", a2l)
    res = _decode(d, a2l, img(0x100, bytes(8)))
    assert [p.stored for p in res.axes[0].points] == [0, 4, 8, 12]


def test_r_a2l_def_110_2_fix_axis_par_shift_0(tmp_path):
    block = curve("F", "0x100", "RL_U16", axis("FIX_AXIS", "CM_IDENT", "4", "0", "255",
                                               "FIX_AXIS_PAR 0 0 4"))
    a2l = inline(tmp_path, block)
    d = a2ldef.describe_definition("F", a2l)
    res = _decode(d, a2l, img(0x100, bytes(8)))
    assert [p.stored for p in res.axes[0].points] == [0, 1, 2, 3]


def test_r_a2l_def_111_1_par_dist_1_1_6(v171):
    d = a2ldef.describe_definition("ASAM.C.CURVE.FIX_AXIS.PAR_DIST", v171)
    res = _decode(d, v171, img(0x810350, _swords(*range(6))))
    assert [p.stored for p in res.axes[0].points] == [1, 2, 3, 4, 5, 6]


def test_r_a2l_def_111_2_par_dist_0_4_6(v171):
    d = a2ldef.describe_definition("ASAM.C.CURVE.FIX_AXIS.PAR", v171)
    res = _decode(d, v171, img(0x810360, _swords(*range(6))))
    assert [p.stored for p in res.axes[0].points] == [0, 4, 8, 12, 16, 20]


def test_r_a2l_def_111_3_fixed_map_axis(v171):
    d = a2ldef.describe_definition("ASAM.C.MAP.COM_AXIS.FIX_AXIS", v171)
    image = img(0x810440, _swords(*range(24)))
    image.update(img(0x810340, bytes([0x08, 0x46, 0x3C, 0x32, 0x28, 0x1E, 0x14, 0x0A, 0x00])))
    res = _decode(d, v171, image)
    assert [p.stored for p in res.axes[1].points] == [1, 2, 3]


def test_r_a2l_def_112_1_fix_axis_par_list(v171):
    d = a2ldef.describe_definition("ASAM.C.CURVE.FIX_AXIS.PAR_LIST", v171)
    res = _decode(d, v171, img(0x810370, _swords(*range(6))))
    assert [p.stored for p in res.axes[0].points] == [-1, 4, 6, 8, 9, 10]


def test_r_a2l_def_113_1_two_curves_one_axis_object(v171):
    ax_bytes = bytes([0x08, 0x46, 0x3C, 0x32, 0x28, 0x1E, 0x14, 0x0A, 0x00])
    image = img(0x810320, _swords(*range(8)))
    image.update(img(0x810330, _swords(*range(8))))
    image.update(img(0x810340, ax_bytes))
    for name in ("ASAM.C.CURVE.COM_AXIS", "ASAM.C.CURVE.COM_AXIS_2"):
        d = a2ldef.describe_definition(name, v171)
        res = _decode(d, v171, image)
        assert [p.stored for p in res.axes[0].points] == [0, 10, 20, 30, 40, 50, 60, 70]


def test_r_a2l_def_113_2_definitions_case_shared_axis(defc):
    for name in ("CURVE_DEF_0001", "CURVE_DEF_0002"):
        d = a2ldef.describe_definition(name, defc["a2l"])
        res = _decode(d, defc["a2l"], defc["mem"])
        assert [p.stored for p in res.axes[0].points] == [485, 635, 696, 828, 901]


def test_r_a2l_def_114_1_axis_object_own_byte_order(tmp_path):
    axo = axis_pts("AXO", "0x40", "RL_AXO", "5", "CM_IDENT", "0", "255",
                   "BYTE_ORDER MSB_LAST", extras=rl("RL_AXO", "AXIS_PTS_X 1 UWORD INDEX_INCR DIRECT"))
    block = curve("CR", "0x100", "RL_U16", axis("COM_AXIS", "CM_IDENT", "8", "0", "255",
                                                "AXIS_PTS_REF AXO"))
    a2l = inline(tmp_path, axo, block)
    d = a2ldef.describe_definition("CR", a2l)
    # point count 8 from AXIS_DESCR, 5 from AXO: use AXO's 5; point 0 = 0x0102 LE
    image = img(0x40, bytes([0x02, 0x01, 0, 0, 0, 0, 0, 0, 0, 0]))
    image.update(img(0x100, bytes(10)))  # the curve's 5 UWORD value bytes
    res = _decode(d, a2l, image)
    assert res.axes[0].points[0].stored == 258


def test_r_a2l_def_114_2_module_byte_order_for_axis_object(tmp_path):
    axo = axis_pts("AXO", "0x40", "RL_AXO", "5",
                   extras=rl("RL_AXO", "AXIS_PTS_X 1 UWORD INDEX_INCR DIRECT"))
    block = curve("CR", "0x100", "RL_U16", axis("COM_AXIS", "CM_IDENT", "8", "0", "255",
                                                "AXIS_PTS_REF AXO"))
    a2l = inline(tmp_path, axo, block)
    d = a2ldef.describe_definition("CR", a2l)
    image = img(0x40, bytes([0x02, 0x01, 0, 0, 0, 0, 0, 0, 0, 0]))
    image.update(img(0x100, bytes(10)))  # the curve's 5 UWORD value bytes
    res = _decode(d, a2l, image)
    assert res.axes[0].points[0].stored == 513


def test_r_a2l_def_115_1_axis_object_count(v171):
    d = a2ldef.describe_definition("ASAM.C.CURVE.COM_AXIS", v171)
    image = img(0x810320, _swords(*range(8)))
    image.update(img(0x810340, bytes([0x08, 0x46, 0x3C, 0x32, 0x28, 0x1E, 0x14, 0x0A, 0x00])))
    res = _decode(d, v171, image)
    assert len(res.axes[0].points) == 8


def test_r_a2l_def_115_2_two_count_components(tmp_path):
    block = mapchar("MN", "0x100", "RL_MN", axis("STD_AXIS", "CM_IDENT", "3", "0", "255"),
                    axis("STD_AXIS", "CM_IDENT", "2", "0", "255"),
                    extras=(rl("RL_MN", "NO_AXIS_PTS_X 1 UBYTE", "NO_AXIS_PTS_Y 2 UBYTE",
                               "AXIS_PTS_X 3 UBYTE INDEX_INCR DIRECT",
                               "AXIS_PTS_Y 4 UBYTE INDEX_INCR DIRECT",
                               "FNC_VALUES 5 UWORD ROW_DIR DIRECT"),))
    a2l = inline(tmp_path, block)
    d = a2ldef.describe_definition("MN", a2l)
    # count bytes 03 02, 3 + 2 point bytes, 12 value bytes
    image = img(0x100, bytes([0x03, 0x02, 0x0A, 0x14, 0x1E, 0x0B, 0x15]) + bytes(12))
    res = _decode(d, a2l, image)
    assert len(res.axes[0].points) == 3 and len(res.axes[1].points) == 2


def test_r_a2l_def_116_2_1_count_0(v171):
    d = a2ldef.describe_definition("ASAM.C.CURVE.COM_AXIS", v171)
    image = img(0x810320, _swords(*range(8)))
    image.update(img(0x810340, bytes([0x00] * 9)))
    res = _decode(d, v171, image)
    assert isinstance(res, a2ldef.Refusal)
    assert res == Refusal("A2L-DEF-AXIS-CURRENT",
                          "ASAM.C.CURVE.COM_AXIS.X: the record holds 0 points, outside 1 to 8")


def test_r_a2l_def_116_2_2_count_above_max(v171):
    d = a2ldef.describe_definition("ASAM.C.CURVE.COM_AXIS", v171)
    image = img(0x810320, _swords(*range(8)))
    image.update(img(0x810340, bytes([0x09, 0x46, 0x3C, 0x32, 0x28, 0x1E, 0x14, 0x0A, 0x00])))
    res = _decode(d, v171, image)
    assert isinstance(res, a2ldef.Refusal)
    assert res == Refusal("A2L-DEF-AXIS-CURRENT",
                          "ASAM.C.CURVE.COM_AXIS.X: the record holds 9 points, outside 1 to 8")


def test_r_a2l_def_116_2_4_negative_current_count(tmp_path):
    block = curve("CN", "0x100", "RL_CN", axis("STD_AXIS", "CM_IDENT", "4", "0", "255"),
                  extras=(rl("RL_CN", "NO_AXIS_PTS_X 1 SBYTE",
                             "AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT",
                             "FNC_VALUES 3 UWORD ROW_DIR DIRECT"),))
    a2l = inline(tmp_path, block)
    d = a2ldef.describe_definition("CN", a2l)
    image = img(0x100, bytes([0xFF, 0x0A, 0x14, 0x1E, 0x28]) + bytes(8))
    res = _decode(d, a2l, image)
    assert isinstance(res, a2ldef.Refusal)
    assert res == Refusal("A2L-DEF-AXIS-CURRENT",
                          "CN.X: the record holds -1 points, outside 1 to 4")


def test_r_a2l_def_116_1_3_fix_no_axis_pts_x_0(tmp_path):
    block = curve("CZ", "0x100", "RL_CZ", axis("STD_AXIS", "CM_IDENT", "4", "0", "255"),
                  extras=(rl("RL_CZ", "AXIS_PTS_X 1 UWORD INDEX_INCR DIRECT",
                             "FNC_VALUES 2 UWORD ROW_DIR DIRECT", "FIX_NO_AXIS_PTS_X 0"),))
    a2l = inline(tmp_path, block)
    d = a2ldef.describe_definition("CZ", a2l)
    is_refused(d, "A2L-DEF-AXIS-CURRENT", "CZ.X: the record holds 0 points, outside 1 to 4")


def test_r_a2l_def_117_2_1_partial_record_in_image(v171):
    d = a2ldef.describe_definition("ASAM.C.CURVE.COM_AXIS", v171)
    image = img(0x810320, _swords(*range(8)))
    image.update(img(0x810340, bytes([0x05, 0x46, 0x3C, 0x32, 0x28, 0x1E, 0x14, 0x0A, 0x00])))
    res = _decode(d, v171, image)
    assert isinstance(res, a2ldef.Refusal)
    assert res == Refusal("A2L-DEF-AXIS-PARTIAL",
                          "ASAM.C.CURVE.COM_AXIS.X: the record holds 5 of its 8 points — "
                          "a record with fewer points than its maximum is not supported")


def test_r_a2l_def_117_1_2_partial_record_by_fix_no(upd2):
    d = a2ldef.describe_definition("Curve_InternalAxis_bad_axis_size", upd2)
    is_refused(d, "A2L-DEF-AXIS-PARTIAL",
               "Curve_InternalAxis_bad_axis_size.X: the record holds 4 of its 8 points — "
               "a record with fewer points than its maximum is not supported")


def test_r_a2l_def_117_2_3_map_x_axis_partial(tmp_path):
    block = mapchar("MN", "0x100", "RL_MN", axis("STD_AXIS", "CM_IDENT", "3", "0", "255"),
                    axis("STD_AXIS", "CM_IDENT", "2", "0", "255"),
                    extras=(rl("RL_MN", "NO_AXIS_PTS_X 1 UBYTE", "NO_AXIS_PTS_Y 2 UBYTE",
                               "AXIS_PTS_X 3 UBYTE INDEX_INCR DIRECT",
                               "AXIS_PTS_Y 4 UBYTE INDEX_INCR DIRECT",
                               "FNC_VALUES 5 UWORD ROW_DIR DIRECT"),))
    a2l = inline(tmp_path, block)
    d = a2ldef.describe_definition("MN", a2l)
    image = img(0x100, bytes([0x02, 0x02, 0x0A, 0x14, 0x1E, 0x0B, 0x15]) + bytes(12))
    res = _decode(d, a2l, image)
    assert isinstance(res, a2ldef.Refusal)
    assert res == Refusal("A2L-DEF-AXIS-PARTIAL",
                          "MN.X: the record holds 2 of its 3 points — "
                          "a record with fewer points than its maximum is not supported")


def test_r_a2l_def_118_1_axis_object_outside_image(v171):
    d = a2ldef.describe_definition("ASAM.C.CURVE.COM_AXIS", v171)
    image = img(0x810320, _swords(*range(8)))
    res = _decode(d, v171, image)
    assert isinstance(res, a2ldef.Refusal)
    assert res == Refusal("A2L-DEF-AXIS-BYTES",
                          "ASAM.C.CURVE.COM_AXIS.X: 9 of the 9 bytes of the axis object "
                          "ASAM.C.AXIS_PTS.UBYTE_8 are not in the image")


def test_r_a2l_def_118_2_one_byte_missing(v171):
    d = a2ldef.describe_definition("ASAM.C.CURVE.COM_AXIS", v171)
    image = img(0x810320, _swords(*range(8)))
    image.update(img(0x810340, bytes([0x08, 0x46, 0x3C, 0x32, 0x28, 0x1E, 0x14, 0x0A])))
    res = _decode(d, v171, image)
    assert isinstance(res, a2ldef.Refusal)
    assert res == Refusal("A2L-DEF-AXIS-BYTES",
                          "ASAM.C.CURVE.COM_AXIS.X: 1 of the 9 bytes of the axis object "
                          "ASAM.C.AXIS_PTS.UBYTE_8 are not in the image")


def test_r_a2l_def_119_1_one_failing_element(tmp_path):
    blocks = [cm("CM_RF", "RAT_FUNC", "1", "0", "1", "0", "0", "1"),
              valblk("VR", "0x10", "RL_U16", "CM_RF", "0", "10", "MATRIX_DIM 3")]
    a2l = inline(tmp_path, *blocks)
    d = a2ldef.describe_definition("VR", a2l)
    res = _decode(d, a2l, img(0x10, bytes([0x00, 0x05, 0x00, 0x00, 0x00, 0x0A])))
    assert res.values[0].value == pytest.approx(2.0)
    assert isinstance(res.values[1], a2ldef.Refusal)
    assert res.values[1] == Refusal("A2L-DEF-DECODE", "VR[1]: RAT_FUNC has no real root for this value")
    assert res.values[2].value == pytest.approx(3.0)


def test_r_a2l_def_120_1_single_decode_refusal(v171):
    d = a2ldef.describe_definition("ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR", v171)
    image = img(0x810100, _swords(*range(1, 13)))
    res = a2ldef.decode_definition(d, v171, image)
    assert isinstance(res, a2ldef.Refusal)
    assert res == Refusal("A2L-DEF-ELEMENTS",
                          "ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR: it holds 12 values — "
                          "decode and encode it value by value")


def test_r_a2l_def_121_3_name_in_decode_refusal(tmp_path):
    blocks = [cm("CM_RF", "RAT_FUNC", "1", "0", "1", "0", "0", "1"),
              valblk("VR", "0x10", "RL_U16", "CM_RF", "0", "10", "MATRIX_DIM 3")]
    a2l = inline(tmp_path, *blocks)
    d = a2ldef.describe_definition("VR", a2l)
    res = _decode(d, a2l, img(0x10, bytes([0x00, 0x05, 0x00, 0x00, 0x00, 0x0A])))
    assert res.values[1].message.startswith("VR[1]: ")


def test_r_a2l_def_146_1_scalar_decode_values(v171):
    d = a2ldef.describe_definition("ASAM.C.SCALAR.SWORD.IDENTICAL", v171)
    image = img(0x810004, bytes([0x34, 0x12]))
    res = _decode(d, v171, image)
    assert res.values == (Decoded(4660, 4660, "4660"),)
    assert res.axes == ()


# --------------------------------------------------------------------------
# Cited rows (rows unchanged)
# --------------------------------------------------------------------------

def test_r_a2l_def_5_arr_1_case_included(tmp_path):
    a2l = inline(tmp_path,
                 valblk("DUPA", "0x20", "RL_U16", extras=("MATRIX_DIM 2",)),
                 valblk("dupa", "0x10", "RL_U16", extras=("MATRIX_DIM 2",)))
    d = a2ldef.describe_definition("DUPA", a2l)
    assert d.address == 0x20 and d.kind == "array" and d.refusal is None


def test_r_a2l_def_139_arr_1_name_declared_twice(tmp_path):
    a2l = inline(tmp_path,
                 valblk("DUPA", "0x10", "RL_U16", extras=("MATRIX_DIM 2",)),
                 valblk("DUPA", "0x20", "RL_U16", extras=("MATRIX_DIM 2",)))
    d = a2ldef.describe_definition("DUPA", a2l)
    is_refused(d, "A2L-DEF-NAME", "DUPA: the A2L declares that name more than once")


def test_r_a2l_def_6_arr_1_name_case_for_curve(c08):
    d = a2ldef.describe_definition("curve_0001", c08["a2l"])
    is_refused(d, "A2L-DEF-NAME", "curve_0001: no tag of that name in the A2L")


def test_r_a2l_def_7_1_arr_1_array_length_is_byte_length(v171):
    d = a2ldef.describe_definition("ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR", v171)
    assert d.refusal is None and d.byte_length == 24


def test_r_a2l_def_7_1_arr_2_array_with_no_address(tmp_path):
    a2l = inline(tmp_path, meas("MA0", "UBYTE", extras=("MATRIX_DIM 4",)))
    d = a2ldef.describe_definition("MA0", a2l)
    is_refused(d, "A2L-DEF-ADDRESS", "MA0: the object has no address or no length")


def test_r_a2l_def_7_1_arr_3_curve_record_passes_1mib(tmp_path):
    block = curve("CBIG", "0x100", "RL_U16", axis("STD_AXIS", "CM_IDENT", "600000", "0", "65535",
                                                   "FNC_VALUES 1 UWORD INDEX_INCR DIRECT"))
    # The axis block above is wrong; build the curve with an in-record layout instead.
    block = curve("CBIG", "0x100", "RL_CBIG", axis("STD_AXIS", "CM_IDENT", "600000", "0", "65535"),
                  extras=(rl("RL_CBIG", "AXIS_PTS_X 1 UWORD INDEX_INCR DIRECT",
                             "FNC_VALUES 2 UWORD ROW_DIR DIRECT"),))
    a2l = inline(tmp_path, block)
    d = a2ldef.describe_definition("CBIG", a2l)
    is_refused(d, "A2L-DEF-ADDRESS", "CBIG: the object has no address or no length")
    assert d.shape == (600000,)


def test_r_a2l_def_7_2_arr_1_span_bound_on_computed_length(tmp_path):
    a2l = inline(tmp_path, valblk("VH", "0x10", "RL_U8", extras=("MATRIX_DIM 1048577",)))
    d = a2ldef.describe_definition("VH", a2l)
    is_refused(d, "A2L-DEF-ADDRESS", "VH: its span of 1048577 bytes at 0x10 cannot be read")
    assert d.shape == (1048577,) and d.element_count == 1048577


def test_r_a2l_def_7_2_arr_2_last_byte_above_ffffffff(tmp_path):
    a2l = inline(tmp_path, valblk("VW", "0xFFFFFFF0", "RL_U16", extras=("MATRIX_DIM 3 4",)))
    d = a2ldef.describe_definition("VW", a2l)
    is_refused(d, "A2L-DEF-ADDRESS", "VW: its span of 24 bytes at 0xFFFFFFF0 cannot be read")


def test_r_a2l_def_7_2_arr_3_exactly_1_mib(tmp_path):
    a2l = inline(tmp_path, meas("MH", "UBYTE", addr="0x10", extras=("MATRIX_DIM 1024 1024",)))
    d = a2ldef.describe_definition("MH", a2l)
    assert d.refusal is None and d.byte_length == 1048576


def test_r_a2l_def_26_arr_1_missing_record_bytes(v171):
    d = a2ldef.describe_definition("ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR", v171)
    image = img(0x810100, _swords(*range(1, 13))[:-1])
    res = _decode(d, v171, image)
    assert isinstance(res, a2ldef.Refusal)
    assert res == Refusal("A2L-DEF-BYTES",
                          "ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR: 1 of its 24 bytes are not in the image")


def test_r_a2l_def_58_1_arr_1_unchanged_inputs_v171(v171):
    import copy
    a2l_before = copy.deepcopy(v171)
    image = img(0x810100, _swords(*range(1, 13)))
    image.update(img(0x810120, _swords(*range(1, 13))))
    image_before = dict(image)
    d = a2ldef.describe_definition("ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR", v171)
    _decode(d, v171, image)
    assert v171 == a2l_before and image == image_before


def test_r_a2l_def_58_2_arr_1_5000_digit_matrix_dim(tmp_path):
    big = "9" * 5000
    a2l = inline(tmp_path, valblk("VX", "0x10", "RL_U16", extras=(f"MATRIX_DIM {big}",)))
    d = a2ldef.describe_definition("VX", a2l)
    is_refused(d, "A2L-DEF-MATRIX",
               f"VX: MATRIX_DIM {'9' * 256}\u2026 is not 1 to 3 whole numbers of at least 1")


def test_r_a2l_def_58_2_arr_7_5000_digit_max_axis_points(tmp_path):
    big = "9" * 5000
    block = curve("CX", "0x100", "RL_U16", axis("STD_AXIS", "CM_IDENT", big, "0", "255"))
    a2l = inline(tmp_path, block)
    d = a2ldef.describe_definition("CX", a2l)
    is_refused(d, "A2L-DEF-AXIS-MAX", "CX.X: the axis declares no point count the system can read")


def test_r_a2l_def_137_arr_1_control_character_in_layout_word(tmp_path):
    a2l = inline(tmp_path, valblk("VG", "0x10", "RL\x1bX", extras=("MATRIX_DIM 2",)))
    d = a2ldef.describe_definition("VG", a2l)
    is_refused(d, "A2L-DEF-LAYOUT", "VG: the record layout RL�X is not declared in the A2L")


def test_r_a2l_def_137_arr_2_control_character_in_axis_reference(tmp_path):
    block = curve("CR", "0x100", "RL_U16", axis("COM_AXIS", "CM_IDENT", "4", "0", "255",
                                                "AXIS_PTS_REF AX\x1bGONE"))
    a2l = inline(tmp_path, block)
    d = a2ldef.describe_definition("CR", a2l)
    is_refused(d, "A2L-DEF-AXIS-REF", "CR.X: the A2L declares no axis object AX�GONE with an address")


def test_r_a2l_def_137_arr_4_control_character_in_matrix_dim(tmp_path):
    a2l = inline(tmp_path, valblk("VX", "0x10", "RL_U16", extras=("MATRIX_DIM 3 \x1b",)))
    d = a2ldef.describe_definition("VX", a2l)
    is_refused(d, "A2L-DEF-MATRIX", "VX: MATRIX_DIM 3 � is not 1 to 3 whole numbers of at least 1")


def test_r_a2l_010_arr_1_val_blk_address(v171):
    d = a2ldef.describe_definition("ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR", v171)
    assert d.kind == "array" and d.refusal is None
    assert d.address == 0x810100


def test_r_a2l_011_arr_1_measurement_array_address(v171):
    d = a2ldef.describe_definition("ASAM.M.MATRIX_DIM_8_4_2.UBYTE.IDENTICAL", v171)
    assert d.kind == "array" and d.refusal is None
    assert d.address == 0x13A30


def test_r_a2l_026_arr_1_module_byte_order_of_array(v171):
    d = a2ldef.describe_definition("ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR", v171)
    assert d.kind == "array" and d.refusal is None
    assert d.byte_order == "little"


def test_r_a2l_024_arr_1_case08_array_byte_order(c08):
    d = a2ldef.describe_definition("VAL_BLK_0001", c08["a2l"])
    o = c08["by_name"]["VAL_BLK_0001"]
    assert d.kind == "array" and d.refusal is None
    assert d.byte_order == ("big" if o["big_endian"] else "little")
    endian = ">" if o["big_endian"] else "<"
    raw = o["raw_bytes"]
    expected = [struct.unpack(endian + "H", raw[2 * j:2 * j + 2])[0] for j in range(len(raw) // 2)]
    assert _stored(_decode(d, c08["a2l"], c08["mem"])) == expected


def test_r_a2l_019_arr_1_axis_object_points_counted(v171):
    d = a2ldef.describe_definition("ASAM.C.CURVE.COM_AXIS", v171)
    assert d.axes[0].point_count == 8


# --------------------------------------------------------------------------
# S2.7i - the definitions case (DEFC), seed 20260001
# --------------------------------------------------------------------------

def test_r_a2l_def_133_1_definitions_case_common_axis(defc):
    for name in ("CURVE_DEF_0001", "CURVE_DEF_0002"):
        d = a2ldef.describe_definition(name, defc["a2l"])
        assert d.refusal is None
        res = _decode(d, defc["a2l"], defc["mem"])
        assert [p.stored for p in res.axes[0].points] == [485, 635, 696, 828, 901]
    assert [p.stored for p in _decode(
        a2ldef.describe_definition("CURVE_DEF_0001", defc["a2l"]), defc["a2l"], defc["mem"]).values] \
        == [37818, 52215, 28375, 58106, 11719]
    assert [p.stored for p in _decode(
        a2ldef.describe_definition("CURVE_DEF_0002", defc["a2l"]), defc["a2l"], defc["mem"]).values] \
        == [33014, 24541, 24691, 2267, 39540]


def test_r_a2l_def_134_1_definitions_case_map(defc):
    d = a2ldef.describe_definition("MAP_DEF_0001", defc["a2l"])
    assert d.refusal is None
    res = _decode(d, defc["a2l"], defc["mem"])
    assert [p.stored for p in res.axes[0].points] == [224, 577, 648, 909]
    assert [p.stored for p in res.axes[1].points] == [10, 15, 20]
    assert _stored(res) == [472, 132, 610, 330, 709, -890, -383, -636, 843, -485, 730, -556]


def test_r_a2l_def_135_1_definitions_case_val_blk(defc):
    d = a2ldef.describe_definition("VAL_BLK_DEF_0001", defc["a2l"])
    assert d.refusal is None
    res = _decode(d, defc["a2l"], defc["mem"])
    assert _stored(res) == [737, 219, 636, -413, -395, -214]
    assert _texts(res) == ["36.9", "11.0", "31.8", "-20.7", "-19.8", "-10.7"]


# --------------------------------------------------------------------------
# Acceptance cases, 3a arms
# --------------------------------------------------------------------------

def test_at_b103_i3_1_asam_demo_arrays_decode(v171):
    image = img(0x810100, _swords(*range(1, 13)))
    image.update(img(0x810120, _swords(*range(1, 13))))
    image.update(img(0x13A30, bytes(range(64))))
    image.update(img(0x810320, _swords(*range(8))))
    image.update(img(0x810330, _swords(*range(8))))
    image.update(img(0x810350, _swords(*range(6))))
    image.update(img(0x810360, _swords(*range(6))))
    image.update(img(0x810370, _swords(*range(6))))
    image.update(img(0x810440, _swords(*range(24))))
    image.update(img(0x810340, bytes([0x08, 0x46, 0x3C, 0x32, 0x28, 0x1E, 0x14, 0x0A, 0x00])))
    # the two COM_AXIS curves read one axis 0..70
    for name in ("ASAM.C.CURVE.COM_AXIS", "ASAM.C.CURVE.COM_AXIS_2"):
        d = a2ldef.describe_definition(name, v171)
        assert d.refusal is None
        assert [p.stored for p in _decode(d, v171, image).axes[0].points] == \
            [0, 10, 20, 30, 40, 50, 60, 70]
    # the three FIX curves read 1..6, 0..20, -1..10
    assert [p.stored for p in _decode(
        a2ldef.describe_definition("ASAM.C.CURVE.FIX_AXIS.PAR_DIST", v171), v171, image).axes[0].points] \
        == [1, 2, 3, 4, 5, 6]
    assert [p.stored for p in _decode(
        a2ldef.describe_definition("ASAM.C.CURVE.FIX_AXIS.PAR", v171), v171, image).axes[0].points] \
        == [0, 4, 8, 12, 16, 20]
    assert [p.stored for p in _decode(
        a2ldef.describe_definition("ASAM.C.CURVE.FIX_AXIS.PAR_LIST", v171), v171, image).axes[0].points] \
        == [-1, 4, 6, 8, 9, 10]
    # the 3x4 twins read the same bytes 1..12 in the two orders
    row = _decode(a2ldef.describe_definition("ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR", v171), v171, image)
    col = _decode(a2ldef.describe_definition("ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.COLUMN_DIR", v171), v171, image)
    assert _stored(row) == list(range(1, 13))
    assert _stored(col) == [1 + (k // 3) + 4 * (k % 3) for k in range(12)]
    # the COM/FIX map reads one axis 0..70 and its FIX axis 1..3
    m = _decode(a2ldef.describe_definition("ASAM.C.MAP.COM_AXIS.FIX_AXIS", v171), v171, image)
    assert [p.stored for p in m.axes[0].points] == [0, 10, 20, 30, 40, 50, 60, 70]
    assert [p.stored for p in m.axes[1].points] == [1, 2, 3]
    # the MATRIX_DIM MEASUREMENTs decode their bytes in order
    for name, n in (("ASAM.M.MATRIX_DIM_8_4_2.UBYTE.IDENTICAL", 64),
                    ("ASAM.M.MATRIX_DIM_8_2.UBYTE.IDENTICAL", 16),
                    ("ASAM.M.MATRIX_DIM_16.UBYTE.IDENTICAL", 16)):
        d = a2ldef.describe_definition(name, v171)
        assert d.kind == "array" and d.refusal is None
        assert _stored(_decode(d, v171, image)) == list(range(n))
    # refusals by code
    assert a2ldef.describe_definition("ASAM.C.CURVE.STD_AXIS", v171).refusal.code == "A2L-DEF-ALIGNMENT"
    assert a2ldef.describe_definition("ASAM.C.MAP.STD_AXIS.STD_AXIS", v171).refusal.code == "A2L-DEF-ALIGNMENT"
    assert a2ldef.describe_definition("ASAM.C.CURVE.CURVE_AXIS", v171).refusal.code == "A2L-DEF-AXIS-KIND"
    assert a2ldef.describe_definition("ASAM.C.CURVE.RES_AXIS", v171).refusal.code == "A2L-DEF-AXIS-KIND"
    assert a2ldef.describe_definition("ASAM.C.CUBE_4.ROW_DIR", v171).refusal.code == "A2L-DEF-KIND"


def test_at_b103_i3_3_case08_arrays_decode(c08):
    for a2l in (c08["a2l"], c08["a2l_issues"]):
        for kind, count in (("VAL_BLK", 60), ("CURVE", 60), ("MAP", 20)):
            for i in range(1, count + 1):
                name = f"{kind}_{i:04d}"
                d = a2ldef.describe_definition(name, a2l)
                assert d.refusal is None, name
                res = _decode(d, a2l, c08["mem"])
                assert not isinstance(res, a2ldef.Refusal), name
                o = c08["by_name"][name]
                endian = ">" if o["big_endian"] else "<"
                raw = o["raw_bytes"]
                n = len(raw) // 2
                expected = [struct.unpack(endian + "H", raw[2 * j:2 * j + 2])[0] for j in range(n)]
                if kind == "MAP":
                    expected = [expected[(j // 8) + 8 * (j % 8)] for j in range(n)]
                assert _stored(res) == expected, name
        assert a2ldef.describe_definition("VAL_BLK_0001", a2l).element_count == 128
        assert a2ldef.describe_definition("CURVE_0001", a2l).element_count == 32
        assert a2ldef.describe_definition("MAP_0001", a2l).element_count == 64


# --------------------------------------------------------------------------
# Hostile content (R-A2L-DEF.58.2), echo rules (R-A2L-DEF.151) and the
# remaining cited-row cases
# --------------------------------------------------------------------------

_BIG = "9" * 5000


def test_r_a2l_def_58_2_arr_2_5000_digit_number(tmp_path):
    a2l = inline(tmp_path, valblk("VN5", "0x10", "RL_U16", extras=(f"NUMBER {_BIG}",)))
    is_refused(a2ldef.describe_definition("VN5", a2l), "A2L-DEF-ADDRESS",
               "VN5: the object has no address or no length")


def test_r_a2l_def_58_2_arr_3_5000_digit_position(tmp_path):
    block = curve("C", "0x100", "RL_Q", axis("STD_AXIS", "CM_IDENT", "2", "0", "255"),
                  extras=(rl("RL_Q", f"AXIS_PTS_X {_BIG} UWORD INDEX_INCR DIRECT",
                             "FNC_VALUES 2 UWORD ROW_DIR DIRECT"),))
    a2l = inline(tmp_path, block)
    is_refused(a2ldef.describe_definition("C", a2l), "A2L-DEF-LAYOUT-POSITION",
               "C: the positions of the record layout RL_Q do not give one order")


def test_r_a2l_def_58_2_arr_4_5000_digit_fix_no_axis_pts_x(tmp_path):
    block = curve("CZ", "0x100", "RL_Z", axis("STD_AXIS", "CM_IDENT", "4", "0", "255"),
                  extras=(rl("RL_Z", "AXIS_PTS_X 1 UWORD INDEX_INCR DIRECT",
                             "FNC_VALUES 2 UWORD ROW_DIR DIRECT", f"FIX_NO_AXIS_PTS_X {_BIG}"),))
    a2l = inline(tmp_path, block)
    is_refused(a2ldef.describe_definition("CZ", a2l), "A2L-DEF-LAYOUT-PART",
               "CZ: the record layout RL_Z holds FIX_NO_AXIS_PTS_X, which the system cannot read")


def test_r_a2l_def_58_2_arr_5_5000_digit_alignment_in_layout(tmp_path):
    block = curve("CA2", "0x100", "RL_CA2", axis("STD_AXIS", "CM_IDENT", "2", "0", "255"),
                  extras=(rl("RL_CA2", "NO_AXIS_PTS_X 1 UBYTE",
                             "AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT",
                             f"ALIGNMENT_WORD {_BIG}", "FNC_VALUES 3 UWORD ROW_DIR DIRECT"),))
    a2l = inline(tmp_path, block)
    is_refused(a2ldef.describe_definition("CA2", a2l), "A2L-DEF-LAYOUT-PART",
               "CA2: the record layout RL_CA2 holds ALIGNMENT_WORD, which the system cannot read")


def test_r_a2l_def_58_2_arr_6_5000_digit_alignment_in_mod_common(tmp_path):
    block = curve("CA2", "0x100", "RL_CA2", axis("STD_AXIS", "CM_IDENT", "2", "0", "255"),
                  extras=(rl("RL_CA2", "NO_AXIS_PTS_X 1 UBYTE",
                             "AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT",
                             "FNC_VALUES 3 UWORD ROW_DIR DIRECT"),))
    a2l = inline(tmp_path, block, mod_common=(f"ALIGNMENT_WORD {_BIG}",))
    d = a2ldef.describe_definition("CA2", a2l)
    echo = _BIG[:256] + "…"
    is_refused(d, "A2L-DEF-ALIGNMENT",
               f"CA2: the MOD_COMMON line ALIGNMENT_WORD {echo} cannot be read")


def test_r_a2l_def_58_2_arr_8_5000_digit_axis_object_address(tmp_path):
    axo = axis_pts("AXO", _BIG, "RL_AXO", "5",
                   extras=rl("RL_AXO", "AXIS_PTS_X 1 UWORD INDEX_INCR DIRECT"))
    block = curve("CR", "0x100", "RL_U16", axis("COM_AXIS", "CM_IDENT", "8", "0", "255",
                                                    "AXIS_PTS_REF AXO"))
    a2l = inline(tmp_path, axo, block)
    is_refused(a2ldef.describe_definition("CR", a2l), "A2L-DEF-AXIS-REF",
               "CR.X: the A2L declares no axis object AXO with an address")


def test_r_a2l_def_58_2_arr_9_float32_nan_count(tmp_path):
    block = curve("CQ", "0x100", "RL_CQ", axis("STD_AXIS", "CM_IDENT", "4", "0", "255"),
                  extras=(rl("RL_CQ", "NO_AXIS_PTS_X 1 FLOAT32_IEEE",
                             "AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT",
                             "FNC_VALUES 3 UWORD ROW_DIR DIRECT"),))
    a2l = inline(tmp_path, block)
    is_refused(a2ldef.describe_definition("CQ", a2l), "A2L-DEF-LAYOUT-DATATYPE",
               "CQ: the record layout RL_CQ gives NO_AXIS_PTS_X the datatype FLOAT32_IEEE, "
               "which the system cannot read")


def test_r_a2l_def_137_arr_3_control_character_in_element_name(tmp_path):
    blocks = [cm("CM_RF", "RAT_FUNC", "1", "0", "1", "0", "0", "1"),
              valblk("V\x1bR", "0x10", "RL_U16", "CM_RF", "0", "10", "MATRIX_DIM 3")]
    a2l = inline(tmp_path, *blocks)
    d = a2ldef.describe_definition("V\x1bR", a2l)
    res = _decode(d, a2l, img(0x10, bytes([0x00, 0x05, 0x00, 0x00, 0x00, 0x0A])))
    assert res.values[1].message.startswith("V�R[1]: ")


def test_r_a2l_def_151_arr_1_echo_cap_in_layout_part(tmp_path):
    word = "P" * 1000000
    block = curve("CP", "0x100", "RL_P", axis("STD_AXIS", "CM_IDENT", "2", "0", "255"),
                  extras=(rl("RL_P", "AXIS_PTS_X 1 UWORD INDEX_INCR DIRECT",
                             "FNC_VALUES 2 UWORD ROW_DIR DIRECT", word),))
    a2l = inline(tmp_path, block)
    d = a2ldef.describe_definition("CP", a2l)
    is_refused(d, "A2L-DEF-LAYOUT-PART",
               f"CP: the record layout RL_P holds {'P' * 256}…, which the system cannot read")


def test_r_a2l_def_151_arr_2_256_character_cut(tmp_path):
    for n, suffix in ((256, ""), (257, "…")):
        word = "P" * n
        block = curve("CP", "0x100", "RL_P", axis("STD_AXIS", "CM_IDENT", "2", "0", "255"),
                      extras=(rl("RL_P", "AXIS_PTS_X 1 UWORD INDEX_INCR DIRECT",
                                 "FNC_VALUES 2 UWORD ROW_DIR DIRECT", word),))
        a2l = inline(tmp_path, block)
        d = a2ldef.describe_definition("CP", a2l)
        assert d.refusal.message == (
            f"CP: the record layout RL_P holds {'P' * 256}{suffix}, which the system cannot read")


def test_r_a2l_def_151_arr_6_ufffd_for_each_character_outside_21_7e(tmp_path):
    block = curve("CP", "0x100", "RL_P", axis("STD_AXIS", "CM_IDENT", "2", "0", "255"),
                  extras=(rl("RL_P", "AXIS_PTS_X 1 UWORD INDEX_INCR DIRECT",
                             "FNC_VALUES 2 UWORD ROW_DIR DIRECT", "R\x1bÉ\x7fX"),))
    a2l = inline(tmp_path, block)
    d = a2ldef.describe_definition("CP", a2l)
    is_refused(d, "A2L-DEF-LAYOUT-PART",
               "CP: the record layout RL_P holds R���X, which the system cannot read")


def test_r_a2l_def_58_1_arr_2_unchanged_inputs_case08(c08):
    import copy
    a2l = c08["a2l"]
    # Discriminating RED: the base refuses every VAL_BLK / CURVE / MAP.
    assert a2ldef.describe_definition("VAL_BLK_0001", a2l).kind == "array"
    a2l_before = copy.deepcopy(a2l)
    mem_before = dict(c08["mem"])
    for kind, count in (("VAL_BLK", 60), ("CURVE", 60), ("MAP", 20)):
        for i in range(1, count + 1):
            name = f"{kind}_{i:04d}"
            d = a2ldef.describe_definition(name, a2l)
            if d.refusal is None:
                _decode(d, a2l, c08["mem"])
    assert a2l == a2l_before and c08["mem"] == mem_before


def test_at_b103_i3_2_definitions_case_decode(defc):
    for name in ("CURVE_DEF_0001", "CURVE_DEF_0002", "MAP_DEF_0001", "VAL_BLK_DEF_0001"):
        d = a2ldef.describe_definition(name, defc["a2l"])
        assert d.refusal is None, name
        res = _decode(d, defc["a2l"], defc["mem"])
        assert not isinstance(res, a2ldef.Refusal), name


def test_at_b103_i3_4_softa_element_counts(softa):
    valblk = next(t["name"] for t in softa["tags"] if t.get("char_type") == "VAL_BLK")
    assert a2ldef.describe_definition(valblk, softa).element_count == 4
    # a COM_AXIS curve's element count = its axis object's max axis points
    com = next((t["name"] for t in softa["tags"]
                if t.get("char_type") == "CURVE"
                and any(a.get("header_tokens", [])[:1] == ["COM_AXIS"]
                        for a in (t.get("axis_meta") or []))), None)
    if com is not None:
        d = a2ldef.describe_definition(com, softa)
        ref = None
        t = next(t for t in softa["tags"] if t["name"] == com)
        for a in (t.get("axis_meta") or []):
            ht = a.get("header_tokens") or []
            if "AXIS_PTS_REF" in ht:
                ref = ht[ht.index("AXIS_PTS_REF") + 1]
        from tests.test_b103_a2l_definition_arrays import _axis_pts_max
        assert d.element_count == _axis_pts_max(softa, ref)
