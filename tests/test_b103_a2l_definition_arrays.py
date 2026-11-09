"""Batch-103 Inc 3a (G-T1) - arrays and axes, describe side (S2.7e, S2.7f).

One test per case of ``inc-3/02-test-cases.md`` for the rows R-A2L-DEF.64 ...
.104, .141 ... .144, .145 and .147 (the read side).  Expected values are the
requirement's exact texts or come from an independent source: the file's own
bytes, the generator's planned object list and ``struct`` — never from the
artifact under test.  The model is exercised through its public names only
(``describe_definition``, ``describe_definitions`` and, in the decode file,
``decode_values`` / ``decode_definition`` / ``display_text``).

On the Inc 3a base (``aa7f871c``) these tests are RED: the base refuses a
VAL_BLK / CURVE / MAP with ``A2L-DEF-KIND`` and has no ``shape`` /
``element_count`` / ``axes`` fields, and no array refusal codes.  The RED is
discriminating where the base's value differs from the requirement (kind,
byte length, element count); where the base lacks the field or function
entirely the test fails on the missing attribute, which is the expected RED.

Dependencies:
    - ``s19_app.tui.a2l_definition`` (under test), the app's A2L parser,
      ``tools/synth/make_release_case.py`` (case 08)
"""

from __future__ import annotations

import random
import struct
import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SYNTH_DIR = REPO_ROOT / "tools" / "synth"
EXAMPLES = REPO_ROOT / "examples"
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
    characteristic,
    cm,
    curve,
    img,
    inline,
    is_refused,
    load,
    mapchar,
    meas,
    rl,
    valblk,
)
from tests.support.timing import report_margin, timing_bound  # noqa: E402

Definition = a2ldef.Definition
Refusal = a2ldef.Refusal


def _describe(name: str, a2l: dict) -> Definition:
    return a2ldef.describe_definition(name, a2l)


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
def check() -> dict:
    return load("check_test.a2l")


@pytest.fixture(scope="module")
def upd1() -> dict:
    return load("update_test1.a2l")


@pytest.fixture(scope="module")
def upd2() -> dict:
    return load("update_test2.a2l")


@pytest.fixture(scope="module")
def c08(tmp_path_factory: pytest.TempPathFactory) -> dict:
    folder = tmp_path_factory.mktemp("b103_i3a_c08")
    gen.generate(folder, SEED, 1.0)
    regions = gen.compute_region_sizes(1.0)
    objs = gen.build_objects(regions, random.Random(SEED))
    return {
        "a2l": parse_a2l_file(folder / "firmware.a2l"),
        "objs": objs,
        "by_name": {o["name"]: o for o in objs},
    }


@pytest.fixture(scope="module")
def defc(tmp_path_factory: pytest.TempPathFactory) -> dict:
    folder = tmp_path_factory.mktemp("b103_i3a_defc_desc")
    paths = gen.generate_definitions_case(folder, SEED)
    return parse_a2l_file(paths["a2l"])


# --- helpers for independent expected values -------------------------------

def _section_children(node: dict) -> list[dict]:
    return node.get("children") or []


def _find_sections(a2l: dict, kind: str) -> list[dict]:
    out: list[dict] = []
    stack = list(reversed(a2l.get("sections") or []))
    while stack:
        node = stack.pop()
        if node.get("name") == kind:
            out.append(node)
        stack.extend(reversed(_section_children(node)))
    return out


def _axis_pts_max(a2l: dict, name: str) -> int:
    """The max axis points word (8th header word) of the AXIS_PTS ``name``,
    read independently from the section text."""
    for s in _find_sections(a2l, "AXIS_PTS"):
        head = _header_words(s)
        if head and head[0] == name:
            return int(head[7])
    raise KeyError(name)


def _header_words(section: dict) -> list[str]:
    """A section's header words: the ``/begin`` line's meta then its lines."""
    from s19_app.tui.a2l import _flatten_body_tokens
    meta = section.get("meta") or ""
    lines = section.get("lines") or []
    return _flatten_body_tokens([meta] + list(lines))


# ==========================================================================
# S2.7e - kind, shape, length
# ==========================================================================

def test_r_a2l_def_64_1_2d_val_blk_is_an_array(v171):
    d = _describe("ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR", v171)
    assert d.kind == "array" and d.refusal is None


def test_r_a2l_def_64_2_1d_val_blk_is_an_array(v171):
    d = _describe("ASAM.C.ARRAY.SWORD.MATRIX_DIM_6.ROW_DIR", v171)
    assert d.kind == "array"


def test_r_a2l_def_64_3_matrix_dim_measurement_is_an_array(v171):
    d = _describe("ASAM.M.MATRIX_DIM_8_4_2.UBYTE.IDENTICAL", v171)
    assert d.kind == "array"


def test_r_a2l_def_64_4_a2ltool_val_blk_is_an_array(softa):
    name = next(t["name"] for t in softa["tags"] if t.get("char_type") == "VAL_BLK")
    d = _describe(name, softa)
    assert d.kind == "array"


def test_r_a2l_def_64_5_case08_val_blk_is_an_array(c08):
    d = _describe("VAL_BLK_0001", c08["a2l"])
    assert d.kind == "array" and d.refusal is None


def test_r_a2l_def_64_6_leading_1_matrix_dim(tmp_path):
    a2l = inline(tmp_path, meas("MD161", "UBYTE", addr="0x10", extras=("MATRIX_DIM 1 6 1",)))
    d = _describe("MD161", a2l)
    assert d.kind == "array" and d.refusal is None
    assert d.shape == (1, 6)
    assert d.element_count == 6
    assert d.byte_length == 6


def test_r_a2l_def_65_1_com_axis_curve(v171):
    assert _describe("ASAM.C.CURVE.COM_AXIS", v171).kind == "curve"


def test_r_a2l_def_65_2_fix_axis_curve(v171):
    assert _describe("ASAM.C.CURVE.FIX_AXIS.PAR_DIST", v171).kind == "curve"


def test_r_a2l_def_65_3_case08_curve(c08):
    assert _describe("CURVE_0001", c08["a2l"]).kind == "curve"


def test_r_a2l_def_66_1_com_fix_map(v171):
    assert _describe("ASAM.C.MAP.COM_AXIS.FIX_AXIS", v171).kind == "map"


def test_r_a2l_def_66_2_case08_map(c08):
    assert _describe("MAP_0001", c08["a2l"]).kind == "map"


def test_r_a2l_def_66_3_definitions_case_map(defc):
    assert _describe("MAP_DEF_0001", defc).kind == "map"


def test_r_a2l_def_67_1_2d_shape(v171):
    assert _describe("ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR", v171).shape == (3, 4)


def test_r_a2l_def_67_2_1d_shape(v171):
    assert _describe("ASAM.C.ARRAY.SWORD.MATRIX_DIM_6.ROW_DIR", v171).shape == (6,)


def test_r_a2l_def_67_3_3d_shape(v171):
    assert _describe("ASAM.M.MATRIX_DIM_8_4_2.UBYTE.IDENTICAL", v171).shape == (8, 4, 2)


def test_r_a2l_def_67_4_trailing_1(v171):
    assert _describe("ASAM.M.MATRIX_DIM_16_1.UBYTE.IDENTICAL", v171).shape == (16,)


def test_r_a2l_def_67_5_two_trailing_1s(softa):
    name = next(t["name"] for t in softa["tags"]
                if t.get("section") == "MEASUREMENT" and t.get("matrix_dim") == 8)
    assert _describe(name, softa).shape == (8,)


def test_r_a2l_def_68_1_a2ltool_number(softa):
    name = next(t["name"] for t in softa["tags"] if t.get("char_type") == "VAL_BLK")
    d = _describe(name, softa)
    assert d.shape == (4,)


def test_r_a2l_def_68_2_number_10(tmp_path):
    a2l = inline(tmp_path, valblk("VB10", "0x10", "RL_U16", extras=("NUMBER 10",)))
    assert _describe("VB10", a2l).shape == (10,)


def test_r_a2l_def_69_1_case08_length_only_val_blk(c08):
    d = _describe("VAL_BLK_0001", c08["a2l"])
    assert d.shape == (128,)


def test_r_a2l_def_69_2_small_length_only_val_blk(tmp_path):
    a2l = inline(tmp_path, valblk("VS6", "0x10", "RL_S16", extras=("LENGTH 6",)))
    assert _describe("VS6", a2l).shape == (3,)


def test_r_a2l_def_70_1_length_not_whole_values(tmp_path):
    a2l = inline(tmp_path, valblk("VS", "0x10", "RL_U16", extras=("LENGTH 5",)))
    d = _describe("VS", a2l)
    is_refused(d, "A2L-DEF-SHAPE", "VS: its length 5 is not a whole number of UWORD values")


@pytest.mark.parametrize("dims,text", [
    ("3 0", "3 0"),
    ("2 2 2 2", "2 2 2 2"),
    ("x", "x"),
    ("", "(none)"),
])
def test_r_a2l_def_71_matrix_dim_refused(tmp_path, dims, text):
    a2l = inline(tmp_path, valblk("VX", "0x10", "RL_U16", extras=(f"MATRIX_DIM {dims}".rstrip(),)))
    d = _describe("VX", a2l)
    is_refused(d, "A2L-DEF-MATRIX", f"VX: MATRIX_DIM {text} is not 1 to 3 whole numbers of at least 1")


def test_r_a2l_def_71_5_malformed_measurement_not_scalar(tmp_path):
    a2l = inline(tmp_path, meas("MX4", "UBYTE", addr="0x10", extras=("MATRIX_DIM 4 x",)))
    d = _describe("MX4", a2l)
    is_refused(d, "A2L-DEF-MATRIX", "MX4: MATRIX_DIM 4 x is not 1 to 3 whole numbers of at least 1")


def test_r_a2l_def_72_1_curve_shape(v171):
    assert _describe("ASAM.C.CURVE.FIX_AXIS.PAR_DIST", v171).shape == (6,)


def test_r_a2l_def_72_2_map_shape_x_first(v171):
    assert _describe("ASAM.C.MAP.COM_AXIS.FIX_AXIS", v171).shape == (8, 3)


def test_r_a2l_def_72_3_case08_map_shape(c08):
    assert _describe("MAP_0001", c08["a2l"]).shape == (8, 8)


def test_r_a2l_def_73_1_element_count_2d(v171):
    assert _describe("ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR", v171).element_count == 12


def test_r_a2l_def_73_2_element_count_3d(v171):
    assert _describe("ASAM.M.MATRIX_DIM_8_4_2.UBYTE.IDENTICAL", v171).element_count == 64


def test_r_a2l_def_73_3_element_count_com_curve(v171):
    assert _describe("ASAM.C.CURVE.COM_AXIS", v171).element_count == 8


def test_r_a2l_def_73_4_element_count_com_fix_map(v171):
    assert _describe("ASAM.C.MAP.COM_AXIS.FIX_AXIS", v171).element_count == 24


def test_r_a2l_def_73_5_case08_val_blk_count(c08):
    assert _describe("VAL_BLK_0001", c08["a2l"]).element_count == 128


def test_r_a2l_def_73_6_case08_curve_count(c08):
    assert _describe("CURVE_0001", c08["a2l"]).element_count == 32


def test_r_a2l_def_73_7_case08_map_count(c08):
    assert _describe("MAP_0001", c08["a2l"]).element_count == 64


def test_r_a2l_def_73_8_count_on_a_refused_definition(v171):
    d = _describe("ASAM.C.CURVE.STD_AXIS", v171)
    assert d.refusal is not None and d.refusal.code == "A2L-DEF-ALIGNMENT"
    assert d.element_count == 8


def test_r_a2l_def_73_9_unreadable_shape_has_no_count(tmp_path):
    a2l = inline(tmp_path, valblk("VX", "0x10", "RL_U16", extras=("MATRIX_DIM 3 0",)))
    d = _describe("VX", a2l)
    assert d.refusal is not None and d.refusal.code == "A2L-DEF-MATRIX"
    assert d.shape == ()
    assert d.element_count is None


def test_r_a2l_def_74_1_byte_length_2d(v171):
    d = _describe("ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR", v171)
    assert d.kind == "array" and d.refusal is None
    assert d.byte_length == 24


def test_r_a2l_def_74_2_byte_length_3d_measurement(v171):
    d = _describe("ASAM.M.MATRIX_DIM_8_4_2.UBYTE.IDENTICAL", v171)
    assert d.kind == "array" and d.refusal is None
    assert d.datatype == "UBYTE"
    assert d.byte_length == 64


def test_r_a2l_def_74_3_a2ltool_val_blk_byte_length(softa):
    name = next(t["name"] for t in softa["tags"] if t.get("char_type") == "VAL_BLK")
    d = _describe(name, softa)
    assert d.kind == "array" and d.refusal is None
    assert d.byte_length == 8  # 4 SWORD values


def test_r_a2l_def_74_4_case08_val_blk_byte_length(c08):
    assert _describe("VAL_BLK_0001", c08["a2l"]).byte_length == 256


def test_r_a2l_def_75_1_com_axis_curve_byte_length(v171):
    assert _describe("ASAM.C.CURVE.COM_AXIS", v171).byte_length == 16


def test_r_a2l_def_75_2_com_fix_map_byte_length(v171):
    assert _describe("ASAM.C.MAP.COM_AXIS.FIX_AXIS", v171).byte_length == 48


def test_r_a2l_def_75_3_case08_curve_byte_length(c08):
    d = _describe("CURVE_0001", c08["a2l"])
    assert d.kind == "curve" and d.refusal is None
    assert d.byte_length == 64


def test_r_a2l_def_75_4_case08_map_byte_length(c08):
    d = _describe("MAP_0001", c08["a2l"])
    assert d.kind == "map" and d.refusal is None
    assert d.byte_length == 128


def test_r_a2l_def_76_1_length_differs(tmp_path):
    a2l = inline(tmp_path, valblk("VL", "0x10", "RL_U16", extras=("MATRIX_DIM 4", "LENGTH 6")))
    is_refused(_describe("VL", a2l), "A2L-DEF-LENGTH",
               "VL: its length 6 differs from the 8 bytes of 4 UWORD values")


def test_r_a2l_def_76_2_data_size_differs(tmp_path):
    a2l = inline(tmp_path, meas("ML", "UBYTE", addr="0x10", extras=("MATRIX_DIM 4 2", "DATA_SIZE 4")))
    is_refused(_describe("ML", a2l), "A2L-DEF-LENGTH",
               "ML: its length 4 differs from the 8 bytes of 8 UBYTE values")


def test_r_a2l_def_77_1_values_of_row_dir(v171):
    d = _describe("ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR", v171)
    assert d.datatype == "SWORD" and d.index_mode == "ROW_DIR" and d.values_offset == 0


def test_r_a2l_def_77_2_values_of_column_dir(v171):
    d = _describe("ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.COLUMN_DIR", v171)
    assert d.datatype == "SWORD" and d.index_mode == "COLUMN_DIR" and d.values_offset == 0


def test_r_a2l_def_77_3_curve_layout_starts_with_count(tmp_path):
    block = curve("CS", "0x100", "RL_CS",
                  axis("STD_AXIS", "CM_IDENT", "4", "0", "255"),
                  extras=(rl("RL_CS", "NO_AXIS_PTS_X 1 UBYTE",
                             "AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT",
                             "FNC_VALUES 3 SWORD ROW_DIR DIRECT"),))
    a2l = inline(tmp_path, block)
    d = _describe("CS", a2l)
    assert d.datatype == "SWORD" and d.index_mode == "ROW_DIR" and d.values_offset == 5


def test_r_a2l_def_78_1_layout_column_dir(tmp_path):
    a2l = inline(tmp_path, meas("MC", "UBYTE", addr="0x10", extras=("MATRIX_DIM 3 2", "LAYOUT COLUMN_DIR")))
    assert _describe("MC", a2l).index_mode == "COLUMN_DIR"


def test_r_a2l_def_78_2_layout_row_dir(tmp_path):
    a2l = inline(tmp_path, meas("MC", "UBYTE", addr="0x10", extras=("MATRIX_DIM 3 2", "LAYOUT ROW_DIR")))
    assert _describe("MC", a2l).index_mode == "ROW_DIR"


def test_r_a2l_def_79_1_default_index_mode(v171):
    assert _describe("ASAM.M.MATRIX_DIM_8_2.UBYTE.IDENTICAL", v171).index_mode == "ROW_DIR"


def test_r_a2l_def_80_1_3d_column_dir_measurement(tmp_path):
    a2l = inline(tmp_path, meas("M3", "UBYTE", addr="0x10", extras=("MATRIX_DIM 2 2 2", "LAYOUT COLUMN_DIR")))
    is_refused(_describe("M3", a2l), "A2L-DEF-INDEX-MODE",
               "M3: the system cannot read COLUMN_DIR in three dimensions")


def test_r_a2l_def_80_2_3d_column_dir_val_blk(tmp_path):
    block = valblk("V3", "0x10", "RL_V3", extras=("MATRIX_DIM 2 2 2",),
                   )
    a2l = inline(tmp_path, block, rl("RL_V3", "FNC_VALUES 1 UWORD COLUMN_DIR DIRECT"))
    is_refused(_describe("V3", a2l), "A2L-DEF-INDEX-MODE",
               "V3: the system cannot read COLUMN_DIR in three dimensions")


def test_r_a2l_def_81_1_undeclared_method_on_array(tmp_path):
    a2l = inline(tmp_path, valblk("VC", "0x10", "RL_U16", "CM_GONE", extras=("MATRIX_DIM 3",)))
    is_refused(_describe("VC", a2l), "A2L-DEF-METHOD",
               "VC: the conversion method CM_GONE is not declared in the A2L")


def test_r_a2l_def_81_2_dangling_enum_table(tmp_path):
    blocks = [cm("CM_V", "TAB_VERB", fmt='"%.0"', ref="VT_GONE"),
              valblk("VT", "0x10", "RL_U8", "CM_V", extras=("MATRIX_DIM 2",))]
    a2l = inline(tmp_path, *blocks)
    is_refused(_describe("VT", a2l), "A2L-DEF-TABLE",
               "VT: the table VT_GONE of CM_V is not declared in the A2L")


def test_r_a2l_def_81_3_zero_mask_on_map(tmp_path):
    ax = axis("STD_AXIS", "CM_IDENT", "2", "0", "255")
    block = mapchar("MZ", "0x100", "RL_MZ", ax, ax, extras=("BIT_MASK 0",))
    a2l = inline(tmp_path, block, rl("RL_MZ", "AXIS_PTS_X 1 UWORD INDEX_INCR DIRECT",
                                     "AXIS_PTS_Y 2 UWORD INDEX_INCR DIRECT",
                                     "FNC_VALUES 3 UWORD ROW_DIR DIRECT"))
    is_refused(_describe("MZ", a2l), "A2L-DEF-MASK",
               "MZ: the bit mask 0 cannot be applied to UWORD")


def test_r_a2l_def_81_4_unknown_measurement_datatype(tmp_path):
    a2l = inline(tmp_path, meas("MF", "FOO", "CM_IDENT", "0", "1", "ECU_ADDRESS 0x10", "MATRIX_DIM 4"))
    is_refused(_describe("MF", a2l), "A2L-DEF-DATATYPE",
               "MF: the object declares no datatype the system can read")


def test_r_a2l_def_81_5_unreadable_mask_word(tmp_path):
    a2l = inline(tmp_path, valblk("VZ", "0x10", "RL_U16", extras=("MATRIX_DIM 2", "BIT_MASK 0xZZ")))
    is_refused(_describe("VZ", a2l), "A2L-DEF-MASK",
               "VZ: the bit mask 0xZZ cannot be applied to UWORD")


def test_r_a2l_def_145_1_matrix_dim_on_curve(tmp_path):
    block = curve("CMD", "0x100", "RL_U16", axis("STD_AXIS", "CM_IDENT", "2", "0", "255"),
                  extras=("MATRIX_DIM 4",))
    a2l = inline(tmp_path, block)
    d = _describe("CMD", a2l)
    is_refused(d, "A2L-DEF-MATRIX", "CMD: the system cannot read MATRIX_DIM 4 on a CURVE")
    assert d.shape == () and d.element_count is None and d.byte_length is None


def test_r_a2l_def_145_2_matrix_dim_on_value(tmp_path):
    a2l = inline(tmp_path, characteristic("VMD", "VALUE", "0x10", "RL_U16", "CM_IDENT", "0", "65535",
                                           extras=("MATRIX_DIM 2 2",)))
    d = _describe("VMD", a2l)
    is_refused(d, "A2L-DEF-MATRIX", "VMD: the system cannot read MATRIX_DIM 2 2 on a VALUE")
    assert d.shape == () and d.element_count is None and d.byte_length is None


def test_r_a2l_def_145_3_matrix_dim_1_on_curve(tmp_path):
    block = curve("CMD", "0x100", "RL_U16", axis("STD_AXIS", "CM_IDENT", "2", "0", "255"),
                  extras=("MATRIX_DIM 1",))
    a2l = inline(tmp_path, block)
    d = _describe("CMD", a2l)
    assert d.refusal is None and d.shape == (2,)


# ==========================================================================
# S2.7f - record layouts and axes
# ==========================================================================

def test_r_a2l_def_82_1_undeclared_layout_real_file(check):
    d = _describe("Curve_ExternalAxis", check)
    is_refused(d, "A2L-DEF-LAYOUT",
               "Curve_ExternalAxis: the record layout Curve_ExternalAxis_RecordLayout is not declared in the A2L")


def test_r_a2l_def_82_2_undeclared_layout_on_val_blk(tmp_path):
    a2l = inline(tmp_path, valblk("VG", "0x10", "RL_GONE", extras=("MATRIX_DIM 2",)))
    is_refused(_describe("VG", a2l), "A2L-DEF-LAYOUT",
               "VG: the record layout RL_GONE is not declared in the A2L")


def test_r_a2l_def_83_1_layout_with_no_fnc_values(tmp_path):
    block = curve("CF", "0x100", "RL_AX", axis("STD_AXIS", "CM_IDENT", "4", "0", "255"),
                  extras=(rl("RL_AX", "AXIS_PTS_X 1 UBYTE INDEX_INCR DIRECT"),))
    a2l = inline(tmp_path, block)
    is_refused(_describe("CF", a2l), "A2L-DEF-LAYOUT-VALUES",
               "CF: the record layout RL_AX holds no FNC_VALUES")


@pytest.mark.parametrize("line,word", [
    ("RESERVED 3 BYTE", "RESERVED"),
    ("AXIS_RESCALE_X 3 UBYTE 5 INDEX_INCR DIRECT", "AXIS_RESCALE_X"),
    ("IDENTIFICATION 3 UWORD", "IDENTIFICATION"),
    ("AXIS_PTS_Z 3 UBYTE INDEX_INCR DIRECT", "AXIS_PTS_Z"),
    ("SRC_ADDR_X 3", "SRC_ADDR_X"),
    ("STATIC_RECORD_LAYOUT", "STATIC_RECORD_LAYOUT"),
])
def test_r_a2l_def_84_layout_part(tmp_path, line, word):
    block = curve("CP", "0x100", "RL_P", axis("STD_AXIS", "CM_IDENT", "2", "0", "255"),
                  extras=(rl("RL_P", "AXIS_PTS_X 1 UWORD INDEX_INCR DIRECT",
                             "FNC_VALUES 2 UWORD ROW_DIR DIRECT", line),))
    a2l = inline(tmp_path, block)
    is_refused(_describe("CP", a2l), "A2L-DEF-LAYOUT-PART",
               f"CP: the record layout RL_P holds {word}, which the system cannot read")


def test_r_a2l_def_84_7_component_with_extra_words(tmp_path):
    block = curve("CP2", "0x100", "RL_P2", axis("STD_AXIS", "CM_IDENT", "4", "0", "255"),
                  extras=(rl("RL_P2", "NO_AXIS_PTS_X 1 UBYTE AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT",
                             "FNC_VALUES 3 UWORD ROW_DIR DIRECT"),))
    a2l = inline(tmp_path, block)
    is_refused(_describe("CP2", a2l), "A2L-DEF-LAYOUT-PART",
               "CP2: the record layout RL_P2 holds AXIS_PTS_X, which the system cannot read")


def test_r_a2l_def_85_1_alternate_mode(tmp_path):
    a2l = inline(tmp_path, valblk("VA", "0x10", "RL_A", extras=("MATRIX_DIM 2",)),
                 rl("RL_A", "FNC_VALUES 1 UWORD ALTERNATE_WITH_X DIRECT"))
    is_refused(_describe("VA", a2l), "A2L-DEF-LAYOUT-MODE",
               "VA: the record layout RL_A stores FNC_VALUES as ALTERNATE_WITH_X, which the system cannot read")


def test_r_a2l_def_85_2_unknown_point_order(tmp_path):
    block = curve("C", "0x100", "RL_B", axis("STD_AXIS", "CM_IDENT", "2", "0", "255"),
                  extras=(rl("RL_B", "AXIS_PTS_X 1 UBYTE INDEX_X DIRECT",
                             "FNC_VALUES 2 UWORD ROW_DIR DIRECT"),))
    a2l = inline(tmp_path, block)
    is_refused(_describe("C", a2l), "A2L-DEF-LAYOUT-MODE",
               "C: the record layout RL_B stores AXIS_PTS_X as INDEX_X, which the system cannot read")


def test_r_a2l_def_85_3_pointer_address_type(tmp_path):
    a2l = inline(tmp_path, valblk("VA", "0x10", "RL_A", extras=("MATRIX_DIM 2",)),
                 rl("RL_A", "FNC_VALUES 1 UWORD ROW_DIR PBYTE"))
    is_refused(_describe("VA", a2l), "A2L-DEF-LAYOUT-MODE",
               "VA: the record layout RL_A stores FNC_VALUES as PBYTE, which the system cannot read")


def test_r_a2l_def_85_4_missing_mode(tmp_path):
    a2l = inline(tmp_path, valblk("VA", "0x10", "RL_A", extras=("MATRIX_DIM 2",)),
                 rl("RL_A", "FNC_VALUES 1 UWORD"))
    is_refused(_describe("VA", a2l), "A2L-DEF-LAYOUT-MODE",
               "VA: the record layout RL_A stores FNC_VALUES as (none), which the system cannot read")


def test_r_a2l_def_86_1_unknown_values_datatype(tmp_path):
    a2l = inline(tmp_path, valblk("VD", "0x10", "RL_D", extras=("MATRIX_DIM 2",)),
                 rl("RL_D", "FNC_VALUES 1 FOO ROW_DIR DIRECT"))
    is_refused(_describe("VD", a2l), "A2L-DEF-LAYOUT-DATATYPE",
               "VD: the record layout RL_D gives FNC_VALUES the datatype FOO, which the system cannot read")


def test_r_a2l_def_86_2_byte_on_axis_component(tmp_path):
    block = curve("C", "0x100", "RL_B", axis("STD_AXIS", "CM_IDENT", "2", "0", "255"),
                  extras=(rl("RL_B", "AXIS_PTS_X 1 BYTE INDEX_INCR DIRECT",
                             "FNC_VALUES 2 UWORD ROW_DIR DIRECT"),))
    a2l = inline(tmp_path, block)
    is_refused(_describe("C", a2l), "A2L-DEF-LAYOUT-DATATYPE",
               "C: the record layout RL_B gives AXIS_PTS_X the datatype BYTE, which the system cannot read")


def test_r_a2l_def_86_3_float_count_component(tmp_path):
    block = curve("CQ", "0x100", "RL_CQ", axis("STD_AXIS", "CM_IDENT", "4", "0", "255"),
                  extras=(rl("RL_CQ", "NO_AXIS_PTS_X 1 FLOAT16_IEEE",
                             "AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT",
                             "FNC_VALUES 3 UWORD ROW_DIR DIRECT"),))
    a2l = inline(tmp_path, block)
    d = _describe("CQ", a2l)
    is_refused(d, "A2L-DEF-LAYOUT-DATATYPE",
               "CQ: the record layout RL_CQ gives NO_AXIS_PTS_X the datatype FLOAT16_IEEE, which the system cannot read")


def test_r_a2l_def_86_4_count_component_no_datatype(tmp_path):
    block = curve("CQ", "0x100", "RL_CQ", axis("STD_AXIS", "CM_IDENT", "4", "0", "255"),
                  extras=(rl("RL_CQ", "NO_AXIS_PTS_X 1",
                             "AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT",
                             "FNC_VALUES 3 UWORD ROW_DIR DIRECT"),))
    a2l = inline(tmp_path, block)
    d = _describe("CQ", a2l)
    is_refused(d, "A2L-DEF-LAYOUT-DATATYPE",
               "CQ: the record layout RL_CQ gives NO_AXIS_PTS_X the datatype (none), which the system cannot read")


def test_r_a2l_def_87_1_two_components_one_position(tmp_path):
    block = curve("C", "0x100", "RL_Q", axis("STD_AXIS", "CM_IDENT", "2", "0", "255"),
                  extras=(rl("RL_Q", "AXIS_PTS_X 2 UWORD INDEX_INCR DIRECT",
                             "FNC_VALUES 2 UWORD ROW_DIR DIRECT"),))
    a2l = inline(tmp_path, block)
    is_refused(_describe("C", a2l), "A2L-DEF-LAYOUT-POSITION",
               "C: the positions of the record layout RL_Q do not give one order")


def test_r_a2l_def_87_2_position_not_a_number(tmp_path):
    block = curve("C", "0x100", "RL_Q", axis("STD_AXIS", "CM_IDENT", "2", "0", "255"),
                  extras=(rl("RL_Q", "AXIS_PTS_X x UWORD INDEX_INCR DIRECT",
                             "FNC_VALUES 2 UWORD ROW_DIR DIRECT"),))
    a2l = inline(tmp_path, block)
    is_refused(_describe("C", a2l), "A2L-DEF-LAYOUT-POSITION",
               "C: the positions of the record layout RL_Q do not give one order")


def _ca2(tmp_path, with_alignment: bool):
    lines = ["NO_AXIS_PTS_X 1 UBYTE", "AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT"]
    if with_alignment:
        lines.append("ALIGNMENT_WORD 2")
    lines.append("FNC_VALUES 3 UWORD ROW_DIR DIRECT")
    block = curve("CA2", "0x100", "RL_CA2", axis("STD_AXIS", "CM_IDENT", "2", "0", "255"),
                  extras=(rl("RL_CA2", *lines),))
    return inline(tmp_path, block)


def test_r_a2l_def_88_1_declared_alignment(tmp_path):
    d = _describe("CA2", _ca2(tmp_path, True))
    assert d.values_offset == 4 and d.byte_length == 8


def test_r_a2l_def_88_2_packed_layout(tmp_path):
    d = _describe("CA2", _ca2(tmp_path, False))
    assert d.values_offset == 3 and d.byte_length == 7


def test_r_a2l_def_88_3_position_order(tmp_path):
    block = curve("C", "0x100", "RL_R", axis("STD_AXIS", "CM_IDENT", "2", "0", "255"),
                  extras=(rl("RL_R", "FNC_VALUES 2 UWORD ROW_DIR DIRECT",
                             "AXIS_PTS_X 1 UWORD INDEX_INCR DIRECT"),))
    a2l = inline(tmp_path, block)
    d = _describe("C", a2l)
    # AXIS_PTS_X at 0, FNC_VALUES at 4
    assert d.values_offset == 4
    assert d.axes[0].offset == 0


def test_r_a2l_def_89_1_alignment_refusal_asam_curve(v171):
    d = _describe("ASAM.C.CURVE.STD_AXIS", v171)
    is_refused(d, "A2L-DEF-ALIGNMENT",
               "ASAM.C.CURVE.STD_AXIS: FNC_VALUES of the record layout RL.CURVE.SWORD.SBYTE.DECR "
               "lies at offset 9, or at 10 under the MOD_COMMON alignment")


def test_r_a2l_def_89_2_alignment_refusal_asam_map(v171):
    d = _describe("ASAM.C.MAP.STD_AXIS.STD_AXIS", v171)
    is_refused(d, "A2L-DEF-ALIGNMENT",
               "ASAM.C.MAP.STD_AXIS.STD_AXIS: FNC_VALUES of the record layout RL.MAP.SWORD.SBYTE.SBYTE.INCR "
               "lies at offset 11, or at 12 under the MOD_COMMON alignment")


def test_r_a2l_def_89_3_no_refusal_where_readings_agree(c08):
    d = _describe("CURVE_0001", c08["a2l"])
    assert d.refusal is None


def test_r_a2l_def_90_1_fix_no_axis_pts_x(softa):
    name = next(t["name"] for t in softa["tags"]
                if t.get("char_type") == "CURVE"
                and t.get("record_layout_name") == "Hldoj[5].hg16.uc16.MXW3.QMGZFJ_TGXVUC")
    d = _describe(name, softa)
    assert d.axes[0].fixed_count == 5


def test_r_a2l_def_90_2_fix_no_axis_pts_y(upd1):
    # update_test1's Map_InternalAxis: layout Map_InternalAxis_RecordLayout holds
    # FIX_NO_AXIS_PTS_X 4 and FIX_NO_AXIS_PTS_Y 3 (read from the file text).
    d = _describe("Map_InternalAxis", upd1)
    assert d.axes[0].fixed_count == 4
    assert d.axes[1].fixed_count == 3


def test_r_a2l_def_91_1_curve_with_two_axes(tmp_path):
    ax = axis("STD_AXIS", "CM_IDENT", "2", "0", "255")
    block = curve("C2", "0x100", "RL_U16", ax, extras=(rl("RL_C2", "AXIS_PTS_X 1 UWORD INDEX_INCR DIRECT",
                                                          "AXIS_PTS_Y 2 UWORD INDEX_INCR DIRECT",
                                                          "FNC_VALUES 3 UWORD ROW_DIR DIRECT"),))
    # note: curve takes one axis block; append the second inside the characteristic
    # build manually for the two-axis case
    a2l = inline(tmp_path,
                 characteristic("C2", "CURVE", "0x100", "RL_C2", "CM_IDENT", "0", "65535",
                                axes=(ax, ax), extras=(rl("RL_C2", "AXIS_PTS_X 1 UWORD INDEX_INCR DIRECT",
                                                          "AXIS_PTS_Y 2 UWORD INDEX_INCR DIRECT",
                                                          "FNC_VALUES 3 UWORD ROW_DIR DIRECT"),)))
    is_refused(_describe("C2", a2l), "A2L-DEF-AXES", "C2: a CURVE declares 2 AXIS_DESCR and needs 1")


def test_r_a2l_def_91_2_map_with_one_axis(tmp_path):
    ax = axis("STD_AXIS", "CM_IDENT", "2", "0", "255")
    block = mapchar("M1", "0x100", "RL_U16", ax)
    a2l = inline(tmp_path, block)
    d = _describe("M1", a2l)
    is_refused(d, "A2L-DEF-AXES", "M1: a MAP declares 1 AXIS_DESCR and needs 2")
    assert d.shape == () and d.element_count is None and d.byte_length is None


def test_r_a2l_def_91_3_curve_with_none(tmp_path):
    a2l = inline(tmp_path, characteristic("C0", "CURVE", "0x100", "RL_U16", "CM_IDENT", "0", "65535"))
    is_refused(_describe("C0", a2l), "A2L-DEF-AXES", "C0: a CURVE declares 0 AXIS_DESCR and needs 1")


def test_r_a2l_def_92_1_curve_axis(v171):
    d = _describe("ASAM.C.CURVE.CURVE_AXIS", v171)
    is_refused(d, "A2L-DEF-AXIS-KIND",
               "ASAM.C.CURVE.CURVE_AXIS.X: the system cannot read an axis of the kind CURVE_AXIS")


def test_r_a2l_def_92_2_res_axis(v171):
    d = _describe("ASAM.C.CURVE.RES_AXIS", v171)
    is_refused(d, "A2L-DEF-AXIS-KIND",
               "ASAM.C.CURVE.RES_AXIS.X: the system cannot read an axis of the kind RES_AXIS")


def test_r_a2l_def_92_3_unlisted_kind(tmp_path):
    block = curve("CK", "0x100", "RL_U16", axis("FOO_AXIS", "CM_IDENT", "2", "0", "255"))
    a2l = inline(tmp_path, block)
    is_refused(_describe("CK", a2l), "A2L-DEF-AXIS-KIND",
               "CK.X: the system cannot read an axis of the kind FOO_AXIS")


def test_r_a2l_def_92_4_axis_header_on_begin_line_h3e(tmp_path):
    block = curve("CB1", "0x100", "RL_CB1", axis("STD_AXIS", "CM_IDENT", "4", "0", "255", on_begin=True),
                  extras=(rl("RL_CB1", "AXIS_PTS_X 1 UBYTE INDEX_INCR DIRECT",
                             "FNC_VALUES 2 UWORD ROW_DIR DIRECT"),))
    a2l = inline(tmp_path, block)
    d = _describe("CB1", a2l)
    assert d.refusal is None
    ax0 = d.axes[0]
    assert ax0.axis_kind == "STD_AXIS" and ax0.point_count == 4
    assert ax0.offset == 0


def test_r_a2l_def_92_5_map_with_one_axis_read_has_no_count(tmp_path):
    ax_x = axis("STD_AXIS", "CM_IDENT", "2", "0", "255")
    ax_y = axis("FOO_AXIS", "CM_IDENT", "3", "0", "255")
    block = mapchar("MK", "0x100", "RL_U16", ax_x, ax_y)
    a2l = inline(tmp_path, block)
    d = _describe("MK", a2l)
    is_refused(d, "A2L-DEF-AXIS-KIND", "MK.Y: the system cannot read an axis of the kind FOO_AXIS")
    assert d.shape == () and d.element_count is None and d.byte_length is None
    assert len(d.axes) == 1 and d.axes[0].axis_kind == "STD_AXIS"


def test_r_a2l_def_93_1_fix_axis_count(v171):
    assert _describe("ASAM.C.CURVE.FIX_AXIS.PAR_DIST", v171).axes[0].point_count == 6


def test_r_a2l_def_93_2_std_axis_count(c08):
    assert _describe("CURVE_0001", c08["a2l"]).axes[0].point_count == 32


def test_r_a2l_def_93_3_definitions_case_map_axis_count(defc):
    assert _describe("MAP_DEF_0001", defc).axes[0].point_count == 4


def test_r_a2l_def_94_1_com_axis_count(v171):
    assert _describe("ASAM.C.CURVE.COM_AXIS", v171).axes[0].point_count == 8


def _com_curve(tmp_path, axo_max="5"):
    """The COM_AXIS curve of R-A2L-DEF.94/2: AXO max ``axo_max``."""
    axo = axis_pts("AXO", "0x40", "RL_AXO", axo_max,
                   extras=rl("RL_AXO", "AXIS_PTS_X 1 UWORD INDEX_INCR DIRECT"))
    ax = axis("COM_AXIS", "CM_IDENT", "8", "0", "255", "AXIS_PTS_REF AXO")
    block = curve("CR", "0x100", "RL_U16", ax)
    return inline(tmp_path, axo, block)


def test_r_a2l_def_94_2_axis_object_count_wins(tmp_path):
    d = _describe("CR", _com_curve(tmp_path))
    assert d.axes[0].point_count == 5
    assert d.element_count == 5


def test_r_a2l_def_94_3_a2ltool_com_axis(softa):
    name = next(t["name"] for t in softa["tags"] if t.get("char_type") == "CURVE" and _com_ref(t))
    d = _describe(name, softa)
    ref = _com_ref_name(name, softa)
    assert d.axes[0].point_count == _axis_pts_max(softa, ref)


def _com_ref(t: dict) -> bool:
    return any(a.get("header_tokens", [])[:1] == ["COM_AXIS"] for a in (t.get("axis_meta") or []))


def _com_ref_name(name: str, a2l: dict) -> str:
    t = next(t for t in a2l["tags"] if t["name"] == name)
    for a in (t.get("axis_meta") or []):
        ht = a.get("header_tokens") or []
        if ht[:1] == ["COM_AXIS"]:
            for i, w in enumerate(ht):
                if w == "AXIS_PTS_REF":
                    return ht[i + 1]
    raise KeyError(name)


def test_r_a2l_def_95_1_word_as_max(tmp_path):
    block = curve("CX", "0x100", "RL_U16", axis("STD_AXIS", "CM_IDENT", "x", "0", "255"))
    a2l = inline(tmp_path, block)
    is_refused(_describe("CX", a2l), "A2L-DEF-AXIS-MAX",
               "CX.X: the axis declares no point count the system can read")


def test_r_a2l_def_95_2_fix_axis_max_0(tmp_path):
    block = curve("FC", "0x100", "RL_U16", axis("FIX_AXIS", "CM_IDENT", "0", "0", "255",
                                                "FIX_AXIS_PAR_DIST 0 1 0"))
    a2l = inline(tmp_path, block)
    is_refused(_describe("FC", a2l), "A2L-DEF-AXIS-MAX",
               "FC.X: the axis declares no point count the system can read")


def test_r_a2l_def_95_3_axis_object_max_minus_3(tmp_path):
    d = _describe("CR", _com_curve(tmp_path, axo_max="-3"))
    is_refused(d, "A2L-DEF-AXIS-MAX", "CR.X: the axis declares no point count the system can read")


def test_r_a2l_def_96_1_com_axis_no_reference(tmp_path):
    block = curve("CR", "0x100", "RL_U16", axis("COM_AXIS", "CM_IDENT", "4", "0", "255"))
    a2l = inline(tmp_path, block)
    is_refused(_describe("CR", a2l), "A2L-DEF-AXIS-REF",
               "CR.X: the A2L declares no axis object (none) with an address")


def test_r_a2l_def_96_2_dangling_reference(tmp_path):
    block = curve("CR", "0x100", "RL_U16", axis("COM_AXIS", "CM_IDENT", "4", "0", "255",
                                                "AXIS_PTS_REF AX_GONE"))
    a2l = inline(tmp_path, block)
    is_refused(_describe("CR", a2l), "A2L-DEF-AXIS-REF",
               "CR.X: the A2L declares no axis object AX_GONE with an address")


def test_r_a2l_def_96_3_axis_object_no_address(tmp_path):
    axo = axis_pts("AXO", "0xZZ", "RL_AXO", "5",
                   extras=rl("RL_AXO", "AXIS_PTS_X 1 UWORD INDEX_INCR DIRECT"))
    block = curve("CR", "0x100", "RL_U16", axis("COM_AXIS", "CM_IDENT", "8", "0", "255",
                                                "AXIS_PTS_REF AXO"))
    a2l = inline(tmp_path, axo, block)
    is_refused(_describe("CR", a2l), "A2L-DEF-AXIS-REF",
               "CR.X: the A2L declares no axis object AXO with an address")


def test_r_a2l_def_96_4_address_word_not_one(tmp_path):
    axo = axis_pts("AXO", "0x81_0340", "RL_AXO", "5",
                   extras=rl("RL_AXO", "AXIS_PTS_X 1 UWORD INDEX_INCR DIRECT"))
    block = curve("CR", "0x100", "RL_U16", axis("COM_AXIS", "CM_IDENT", "8", "0", "255",
                                                "AXIS_PTS_REF AXO"))
    a2l = inline(tmp_path, axo, block)
    is_refused(_describe("CR", a2l), "A2L-DEF-AXIS-REF",
               "CR.X: the A2L declares no axis object AXO with an address")


def test_r_a2l_def_97_1_undeclared_axis_layout(tmp_path):
    axo = axis_pts("AXO", "0x40", "RL_GONE", "5")
    block = curve("CR", "0x100", "RL_U16", axis("COM_AXIS", "CM_IDENT", "8", "0", "255",
                                                "AXIS_PTS_REF AXO"))
    a2l = inline(tmp_path, axo, block)
    is_refused(_describe("CR", a2l), "A2L-DEF-AXIS-LAYOUT",
               "CR.X: the axis object AXO has no record layout with AXIS_PTS_X")


def test_r_a2l_def_97_2_axis_layout_no_axis_pts_x(tmp_path):
    axo = axis_pts("AXO", "0x40", "RL_FNC", "5",
                   extras=rl("RL_FNC", "FNC_VALUES 1 UWORD ROW_DIR DIRECT"))
    block = curve("CR", "0x100", "RL_U16", axis("COM_AXIS", "CM_IDENT", "8", "0", "255",
                                                "AXIS_PTS_REF AXO"))
    a2l = inline(tmp_path, axo, block)
    is_refused(_describe("CR", a2l), "A2L-DEF-AXIS-LAYOUT",
               "CR.X: the axis object AXO has no record layout with AXIS_PTS_X")


def test_r_a2l_def_98_1_fix_axis_no_parameters(tmp_path):
    block = curve("FN", "0x100", "RL_U16", axis("FIX_AXIS", "CM_IDENT", "4", "0", "255"))
    a2l = inline(tmp_path, block)
    is_refused(_describe("FN", a2l), "A2L-DEF-AXIS-FIX", "FN.X: the fixed axis gives no points")


def test_r_a2l_def_99_1_fix_axis_par_dist_count_differs(tmp_path):
    block = curve("FC", "0x100", "RL_U16", axis("FIX_AXIS", "CM_IDENT", "6", "0", "255",
                                                "FIX_AXIS_PAR_DIST 0 1 4"))
    a2l = inline(tmp_path, block)
    is_refused(_describe("FC", a2l), "A2L-DEF-AXIS-FIX-COUNT",
               "FC.X: the fixed axis gives 4 points and declares 6")


def test_r_a2l_def_99_2_short_list(tmp_path):
    ax = axis("FIX_AXIS", "CM_IDENT", "6", "0", "255", "/begin FIX_AXIS_PAR_LIST", "  1 2 3 4 5",
              "/end FIX_AXIS_PAR_LIST")
    block = curve("FC", "0x100", "RL_U16", ax)
    a2l = inline(tmp_path, block)
    is_refused(_describe("FC", a2l), "A2L-DEF-AXIS-FIX-COUNT",
               "FC.X: the fixed axis gives 5 points and declares 6")


def test_r_a2l_def_100_1_case08_curve_axis_no_points(c08):
    d = _describe("CURVE_0001", c08["a2l"])
    assert d.axes[0].has_points is False


def test_r_a2l_def_100_2_case08_map_axis_x_no_points(c08):
    d = _describe("MAP_0001", c08["a2l"])
    assert d.axes[0].has_points is False


def test_r_a2l_def_100_3_case08_map_axis_y_no_points(c08):
    d = _describe("MAP_0001", c08["a2l"])
    assert d.axes[1].has_points is False and d.refusal is None


def test_r_a2l_def_101_1_in_record_points_for_fix_axis(tmp_path):
    block = curve("F", "0x100", "RL_FX", axis("FIX_AXIS", "CM_IDENT", "2", "0", "255",
                                               "FIX_AXIS_PAR_DIST 0 1 2"),
                  extras=(rl("RL_FX", "AXIS_PTS_X 1 UBYTE INDEX_INCR DIRECT",
                             "FNC_VALUES 2 UWORD ROW_DIR DIRECT"),))
    a2l = inline(tmp_path, block)
    is_refused(_describe("F", a2l), "A2L-DEF-LAYOUT-AXIS",
               "F: the record layout RL_FX holds AXIS_PTS_X for an axis of the kind FIX_AXIS")


def test_r_a2l_def_101_2_in_record_points_for_com_axis(tmp_path):
    axo = axis_pts("AXO", "0x40", "RL_AXO", "5",
                   extras=rl("RL_AXO", "AXIS_PTS_X 1 UWORD INDEX_INCR DIRECT"))
    block = curve("CR", "0x100", "RL_CR", axis("COM_AXIS", "CM_IDENT", "8", "0", "255",
                                               "AXIS_PTS_REF AXO"),
                  extras=(rl("RL_CR", "AXIS_PTS_X 1 UWORD INDEX_INCR DIRECT",
                             "FNC_VALUES 2 UWORD ROW_DIR DIRECT"),))
    a2l = inline(tmp_path, axo, block)
    is_refused(_describe("CR", a2l), "A2L-DEF-LAYOUT-AXIS",
               "CR: the record layout RL_CR holds AXIS_PTS_X for an axis of the kind COM_AXIS")


def test_r_a2l_def_102_1_enum_axis(v171):
    d = _describe("ASAM.C.MAP.STD_AXIS.STD_AXIS", v171)
    pts = d.axes[1].points
    assert pts.kind == "enum" and pts.enum_table == "CM.TAB_VERB.NO_DEFAULT_VALUE.REF"
    assert pts.datatype == "SBYTE"


def test_r_a2l_def_102_2_com_axis_point_definition(v171):
    d = _describe("ASAM.C.CURVE.COM_AXIS", v171)
    pts = d.axes[0].points
    assert pts.kind == "number" and pts.method_name == "CM.IDENTICAL"
    assert pts.datatype == "SBYTE"
    assert (pts.limits.lower, pts.limits.upper) == (0.0, 255.0)


def test_r_a2l_def_102_3_axis_own_conversion_and_format(tmp_path):
    blocks = [cm("CM_HALF", "LINEAR", "0.5", "0", fmt='"%.1"'),
              curve("CL", "0x100", "RL_CL",
                    axis("STD_AXIS", "CM_HALF", "4", "0", "100", 'FORMAT "%.1"'),
                    extras=(rl("RL_CL", "AXIS_PTS_X 1 UWORD INDEX_INCR DIRECT",
                               "FNC_VALUES 2 UWORD ROW_DIR DIRECT"),))]
    a2l = inline(tmp_path, *blocks)
    pts = _describe("CL", a2l).axes[0].points
    assert pts.kind == "number" and pts.method_name == "CM_HALF"
    assert pts.display_format == "%.1" and pts.datatype == "UWORD"


def test_r_a2l_def_102_4_axis_desc_method_used_for_com_axis(tmp_path):
    blocks = [cm("CM_A", "LINEAR", "2", "0"), cm("CM_B", "LINEAR", "3", "0"),
              axis_pts("AXO", "0x40", "RL_AXO", "5", "CM_B",
                       extras=rl("RL_AXO", "AXIS_PTS_X 1 UWORD INDEX_INCR DIRECT")),
              curve("CR", "0x100", "RL_U16", axis("COM_AXIS", "CM_A", "8", "0", "255",
                                                  "AXIS_PTS_REF AXO"))]
    a2l = inline(tmp_path, *blocks)
    assert _describe("CR", a2l).axes[0].points.method_name == "CM_A"


def test_r_a2l_def_103_1_axis_method_not_declared(tmp_path):
    block = curve("CA", "0x100", "RL_CA", axis("STD_AXIS", "CM_GONE", "2", "0", "255"),
                  extras=(rl("RL_CA", "AXIS_PTS_X 1 UWORD INDEX_INCR DIRECT",
                             "FNC_VALUES 2 UWORD ROW_DIR DIRECT"),))
    a2l = inline(tmp_path, block)
    is_refused(_describe("CA", a2l), "A2L-DEF-METHOD",
               "CA.X: the conversion method CM_GONE is not declared in the A2L")


def test_r_a2l_def_103_2_enum_axis_no_table(tmp_path):
    ax_y = axis("STD_AXIS", "CM_V", "2", "0", "255")
    ax_x = axis("STD_AXIS", "CM_IDENT", "2", "0", "255")
    blocks = [cm("CM_V", "TAB_VERB", fmt='"%.0"'),
              mapchar("MA", "0x100", "RL_U16", ax_x, ax_y)]
    a2l = inline(tmp_path, *blocks)
    is_refused(_describe("MA", a2l), "A2L-DEF-TABLE",
               "MA.Y: the table (none) of CM_V is not declared in the A2L")


def test_r_a2l_def_104_1_layout_before_axis_object(check):
    assert _describe("Curve_ExternalAxis", check).refusal.code == "A2L-DEF-LAYOUT"


def test_r_a2l_def_104_2_matrix_dim_before_layout(tmp_path):
    a2l = inline(tmp_path, valblk("VQ", "0x10", "RL_GONE", extras=("MATRIX_DIM 0",)))
    assert _describe("VQ", a2l).refusal.code == "A2L-DEF-MATRIX"


def test_r_a2l_def_104_3_layout_parts_before_axis_kind(tmp_path):
    ax = axis("RES_AXIS", "CM_IDENT", "2", "0", "255", "AXIS_PTS_REF AXO")
    block = curve("C", "0x100", "RL_P", ax,
                  extras=(rl("RL_P", "RESERVED 2 BYTE", "FNC_VALUES 2 UWORD ROW_DIR DIRECT"),))
    a2l = inline(tmp_path, block)
    assert _describe("C", a2l).refusal.code == "A2L-DEF-LAYOUT-PART"


def test_r_a2l_def_141_3_infinite_offset(tmp_path):
    block = curve("FS", "0x100", "RL_U16", axis("FIX_AXIS", "CM_IDENT", "4", "0", "255",
                                                "FIX_AXIS_PAR_DIST 1e400 1 4"))
    a2l = inline(tmp_path, block)
    is_refused(_describe("FS", a2l), "A2L-DEF-AXIS-FIX",
               "FS.X: the fixed axis gives a point the system cannot read")


def test_r_a2l_def_141_4_nan_offset(tmp_path):
    block = curve("FS", "0x100", "RL_U16", axis("FIX_AXIS", "CM_IDENT", "4", "0", "255",
                                                "FIX_AXIS_PAR_DIST nan 1 4"))
    a2l = inline(tmp_path, block)
    is_refused(_describe("FS", a2l), "A2L-DEF-AXIS-FIX",
               "FS.X: the fixed axis gives a point the system cannot read")


def test_r_a2l_def_141_5_nan_in_list(tmp_path):
    ax = axis("FIX_AXIS", "CM_IDENT", "4", "0", "255", "/begin FIX_AXIS_PAR_LIST",
              "  1 nan 3 4", "/end FIX_AXIS_PAR_LIST")
    block = curve("FS", "0x100", "RL_U16", ax)
    a2l = inline(tmp_path, block)
    is_refused(_describe("FS", a2l), "A2L-DEF-AXIS-FIX",
               "FS.X: the fixed axis gives a point the system cannot read")


def test_r_a2l_def_141_6_5000_digit_count(tmp_path):
    big = "9" * 5000
    block = curve("FS", "0x100", "RL_U16", axis("FIX_AXIS", "CM_IDENT", "4", "0", "255",
                                                f"FIX_AXIS_PAR_DIST 0 1 {big}"))
    a2l = inline(tmp_path, block)
    d = _describe("FS", a2l)
    is_refused(d, "A2L-DEF-AXIS-FIX", "FS.X: the fixed axis gives a point the system cannot read")


def test_r_a2l_def_142_1_fix_axis_1048577_points(tmp_path):
    block = curve("FB", "0x100", "RL_U8", axis("FIX_AXIS", "CM_IDENT", "1048577", "0", "255",
                                               "FIX_AXIS_PAR_DIST 0 1 1048577"))
    a2l = inline(tmp_path, block)
    is_refused(_describe("FB", a2l), "A2L-DEF-AXIS-MAX",
               "FB.X: the axis declares 1048577 points, more than 1048576")


def test_r_a2l_def_142_2_9_digit_std_axis_count(tmp_path):
    block = curve("CW", "0x100", "RL_CW", axis("STD_AXIS", "CM_IDENT", "999999999", "0", "255"),
                  extras=(rl("RL_CW", "AXIS_PTS_X 1 UBYTE INDEX_INCR DIRECT",
                             "FNC_VALUES 2 UBYTE ROW_DIR DIRECT"),))
    a2l = inline(tmp_path, block)
    is_refused(_describe("CW", a2l), "A2L-DEF-AXIS-MAX",
               "CW.X: the axis declares 999999999 points, more than 1048576")


def test_r_a2l_def_142_3_axis_object_count_over_cap(tmp_path):
    d = _describe("CR", _com_curve(tmp_path, axo_max="1048577"))
    is_refused(d, "A2L-DEF-AXIS-MAX",
               "CR.X: the axis declares 1048577 points, more than 1048576")


def test_r_a2l_def_142_4_largest_point_count_read(tmp_path):
    block = curve("CU", "0x100", "RL_U8", axis("STD_AXIS", "CM_IDENT", "1048576", "0", "255"))
    a2l = inline(tmp_path, block)
    d = _describe("CU", a2l)
    assert d.refusal is None
    assert d.axes[0].point_count == 1048576
    assert d.element_count == 1048576
    assert d.byte_length == 1048576


def test_r_a2l_def_143_1_axis_object_negative_address(tmp_path):
    axo = axis_pts("AXO", "-0x10", "RL_AXO", "5",
                   extras=rl("RL_AXO", "AXIS_PTS_X 1 UWORD INDEX_INCR DIRECT"))
    block = curve("CR", "0x100", "RL_U16", axis("COM_AXIS", "CM_IDENT", "8", "0", "255",
                                                "AXIS_PTS_REF AXO"))
    a2l = inline(tmp_path, axo, block)
    is_refused(_describe("CR", a2l), "A2L-DEF-AXIS-REF",
               "CR.X: the record of the axis object AXO at -0x10 cannot be read")


def test_r_a2l_def_143_2_last_byte_above_ffffffff(tmp_path):
    axo = axis_pts("AXO", "0xFFFFFFF7", "RL_AXO", "5",
                   extras=rl("RL_AXO", "AXIS_PTS_X 1 UWORD INDEX_INCR DIRECT"))
    block = curve("CR", "0x100", "RL_U16", axis("COM_AXIS", "CM_IDENT", "8", "0", "255",
                                                "AXIS_PTS_REF AXO"))
    a2l = inline(tmp_path, axo, block)
    is_refused(_describe("CR", a2l), "A2L-DEF-AXIS-REF",
               "CR.X: the record of the axis object AXO at 0xFFFFFFF7 cannot be read")


def test_r_a2l_def_143_3_axis_object_record_above_1mib(tmp_path):
    axo = axis_pts("AXO", "0x40", "RL_AXO", "600000",
                   extras=rl("RL_AXO", "AXIS_PTS_X 1 UWORD INDEX_INCR DIRECT"))
    block = curve("CR", "0x100", "RL_U16", axis("COM_AXIS", "CM_IDENT", "8", "0", "255",
                                                "AXIS_PTS_REF AXO"))
    a2l = inline(tmp_path, axo, block)
    is_refused(_describe("CR", a2l), "A2L-DEF-AXIS-REF",
               "CR.X: the record of the axis object AXO at 0x40 cannot be read")


def test_r_a2l_def_143_4_last_byte_ffffffff(tmp_path):
    axo = axis_pts("AXO", "0xFFFFFFF6", "RL_AXO", "5",
                   extras=rl("RL_AXO", "AXIS_PTS_X 1 UWORD INDEX_INCR DIRECT"))
    block = curve("CR", "0x100", "RL_U16", axis("COM_AXIS", "CM_IDENT", "8", "0", "255",
                                                "AXIS_PTS_REF AXO"))
    a2l = inline(tmp_path, axo, block)
    d = _describe("CR", a2l)
    assert d.refusal is None
    assert d.axes[0].axis_object_address == 0xFFFFFFF6


def test_r_a2l_def_144_1_unreadable_mod_common_alignment(tmp_path):
    a2l = inline(tmp_path, curve("CA2", "0x100", "RL_CA2", axis("STD_AXIS", "CM_IDENT", "2", "0", "255"),
                                 extras=(rl("RL_CA2", "NO_AXIS_PTS_X 1 UBYTE",
                                            "AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT",
                                            "FNC_VALUES 3 UWORD ROW_DIR DIRECT"),)),
                 mod_common=("ALIGNMENT_WORD x",))
    is_refused(_describe("CA2", a2l), "A2L-DEF-ALIGNMENT",
               "CA2: the MOD_COMMON line ALIGNMENT_WORD x cannot be read")


def test_r_a2l_def_144_2_layout_own_alignment_no_mod_common_read(tmp_path):
    a2l = inline(tmp_path, curve("CA2", "0x100", "RL_CA2", axis("STD_AXIS", "CM_IDENT", "2", "0", "255"),
                                 extras=(rl("RL_CA2", "NO_AXIS_PTS_X 1 UBYTE",
                                            "AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT",
                                            "ALIGNMENT_WORD 2",
                                            "FNC_VALUES 3 UWORD ROW_DIR DIRECT"),)),
                 mod_common=("ALIGNMENT_WORD x",))
    d = _describe("CA2", a2l)
    assert d.refusal is None and d.values_offset == 4


def test_r_a2l_def_144_3_unreadable_alignment_unused_class(tmp_path):
    a2l = inline(tmp_path, curve("CA2", "0x100", "RL_CA2", axis("STD_AXIS", "CM_IDENT", "2", "0", "255"),
                                 extras=(rl("RL_CA2", "NO_AXIS_PTS_X 1 UBYTE",
                                            "AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT",
                                            "FNC_VALUES 3 UWORD ROW_DIR DIRECT"),)),
                 mod_common=("ALIGNMENT_LONG x",))
    d = _describe("CA2", a2l)
    assert d.refusal is None and d.values_offset == 3


@pytest.mark.parametrize("maxpts,par,expected,rule,points", [
    ("1", "FIX_AXIS_PAR 0 1024 1", "refuse", None, None),
    ("6", "FIX_AXIS_PAR_DIST 7.484401160755199e+291 3.5953862697246315e+307 6", "refuse", None, None),
    ("3", "FIX_AXIS_PAR_DIST 0 4503599627370496 3", "ok",
     ("PAR_DIST", (0, 4503599627370496, 3)), (0, 4503599627370496, 9007199254740992)),
    ("3", "FIX_AXIS_PAR_DIST 1 4503599627370496 3", "refuse", None, None),
    ("3", "FIX_AXIS_PAR 1 52 3", "refuse", None, None),
    ("1", "FIX_AXIS_PAR 0 62 1", "ok", ("PAR", (0, 62, 1)), (0,)),
    ("1", "FIX_AXIS_PAR 0 63 1", "refuse", None, None),
    ("4", "FIX_AXIS_PAR 0 -1 4", "refuse", None, None),
    ("4", "FIX_AXIS_PAR 0 1000000000 4", "refuse", None, None),
    ("2", "FIX_AXIS_PAR 0 1023 2", "refuse", None, None),
    ("1", "FIX_AXIS_PAR 9007199254740993 0 1", "ok",
     ("PAR", (9007199254740992, 0, 1)), (9007199254740992,)),
])
def test_r_a2l_def_147_fix_point_bound(tmp_path, maxpts, par, expected, rule, points):
    block = curve("FE", "0x100", "RL_U16", axis("FIX_AXIS", "CM_IDENT", maxpts, "0", "255", par))
    a2l = inline(tmp_path, block)
    d = _describe("FE", a2l)
    if expected == "refuse":
        is_refused(d, "A2L-DEF-AXIS-FIX",
                   "FE.X: the fixed axis gives a point the system cannot compute exactly")
    else:
        assert d.refusal is None
        assert d.axes[0].fixed_rule == rule
        res = a2ldef.decode_values(d, a2l, img(0x100, bytes(2 * len(points))))
        assert not isinstance(res, a2ldef.Refusal)
        assert [p.stored for p in res.axes[0].points] == list(points)


@pytest.mark.serial_timing
def test_r_a2l_def_147_9_huge_shift_computes_no_power(tmp_path):
    block = curve("FE", "0x100", "RL_U16", axis("FIX_AXIS", "CM_IDENT", "4", "0", "255",
                                                "FIX_AXIS_PAR 0 1000000000 4"))
    a2l = inline(tmp_path, block)
    started = time.perf_counter()
    d = _describe("FE", a2l)
    elapsed = time.perf_counter() - started
    assert elapsed <= report_margin("R-A2L-DEF.147/9 describe FE huge shift", elapsed,
                                    timing_bound(1.0))
    is_refused(d, "A2L-DEF-AXIS-FIX",
               "FE.X: the fixed axis gives a point the system cannot compute exactly")
