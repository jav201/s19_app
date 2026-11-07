"""Batch-103 Inc 2a (G-T1) - the A2L definition model, read side.

Design under test: ``.dev-flow/2026-11-05-batch-103/inc-2/01-requirements.md``
rows R-A2L-DEF.1 ... .39 (2a part), .58.1, .58.2, .137, .139 and the cited
R-A2L-010 ... R-A2L-063 rows, plus the acceptance cases AT-B103-I2-1 (2a arm)
and AT-B103-I2-3, one test per case of ``inc-2/02-test-cases.md``. The model
is exercised only through its 2a public names (``describe_definition``,
``describe_definitions``, ``decode_definition``, ``display_text`` and the
frozen dataclasses). Expected values are the requirement's exact texts or come
from an independent source: the file's own bytes, the generator's planned
object list, ``struct``. No source file is edited here.

Traceability (E4): test names start ``test_r_a2l_def_<row>_<n>_`` (or
``test_r_a2l_<row>_def_<k>_`` for a cited row, ``test_at_b103_i2_<k>_`` for an
acceptance case) so ``trace_check`` and the test-case table bind them.

Encode arms of the rows that hold one (R-A2L-DEF.19/10 ... /23 and the
encode halves of .21/3, .25/2, .26/2 ... /4, .58.1, .58.2) wait for 2b and are
not tested here.

Dependencies:
    - ``s19_app.tui.a2l_definition`` (under test), the app's A2L parser and
      S19 loader, ``tools/synth/make_release_case.py`` (case 08)
"""

from __future__ import annotations

import copy
import random
import struct
import sys
from pathlib import Path
from typing import Mapping

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SYNTH_DIR = REPO_ROOT / "tools" / "synth"
EXAMPLES = REPO_ROOT / "examples"
SEED = 20260001

if str(SYNTH_DIR) not in sys.path:
    sys.path.insert(0, str(SYNTH_DIR))

import make_release_case as gen  # noqa: E402

from s19_app.core import S19File  # noqa: E402
from s19_app.tui.a2l_definition import (  # noqa: E402
    Decoded,
    Definition,
    Refusal,
    decode_definition,
    describe_definition,
    describe_definitions,
    display_text,
)
from s19_app.tui.a2l_parse import parse_a2l_file  # noqa: E402

FFFD = "�"

# --------------------------------------------------------------------------
# Fixtures and builders (no model code below this line is imported twice)
# --------------------------------------------------------------------------

_LAYOUTS = (
    ("RL_U8", "UBYTE"),
    ("RL_S8", "SBYTE"),
    ("RL_U16", "UWORD"),
    ("RL_S16", "SWORD"),
    ("RL_U32", "ULONG"),
    ("RL_F16", "FLOAT16_IEEE"),
    ("RL_F32", "FLOAT32_IEEE"),
    ("RL_F64", "FLOAT64_IEEE"),
)
LAYOUT = {dt: rl for rl, dt in _LAYOUTS}
_inline_counter = [0]


def _inline(tmp_path: Path, *blocks: str, byte_order: str | None = "MSB_FIRST") -> dict:
    """Write an INLINE A2L (one PROJECT, one MODULE, MOD_COMMON, the eight
    RECORD_LAYOUTs, then ``blocks``) and parse it with the app's parser."""
    lines = ["ASAP2_VERSION 1 71", '/begin PROJECT P ""', '  /begin MODULE M ""']
    if byte_order is not None:
        lines += ['    /begin MOD_COMMON ""', f"      BYTE_ORDER {byte_order}", "    /end MOD_COMMON"]
    for rl, dt in _LAYOUTS:
        lines += [f"    /begin RECORD_LAYOUT {rl}", f"      FNC_VALUES 1 {dt} ROW_DIR DIRECT", "    /end RECORD_LAYOUT"]
    for block in blocks:
        lines.append(block)
    lines += ["  /end MODULE", "/end PROJECT"]
    _inline_counter[0] += 1
    path = tmp_path / f"inline_{_inline_counter[0]}.a2l"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return parse_a2l_file(path)


def _char(name: str, kind: str, addr: str, layout: str, conv: str = "NO_COMPU_METHOD",
          lo: str = "0", hi: str = "65535", *extra: str, desc: str = "") -> str:
    """A CHARACTERISTIC whose header sits on its own body line."""
    body = [f'/begin CHARACTERISTIC {name} "{desc}"', f"  {kind} {addr} {layout} 0 {conv} {lo} {hi}"]
    body += [f"  {e}" for e in extra]
    body.append("/end CHARACTERISTIC")
    return "\n".join(body)


def _val(name: str, addr: str, layout: str, conv: str = "NO_COMPU_METHOD",
         lo: str = "0", hi: str = "65535", *extra: str) -> str:
    return _char(name, "VALUE", addr, layout, conv, lo, hi, *extra)


def _meas(name: str, dt: str, conv: str = "NO_COMPU_METHOD", lo: str = "0", hi: str = "65535",
          *extra: str, addr: str | None = None) -> str:
    body = [f'/begin MEASUREMENT {name} ""', f"  {dt} {conv} 0 0 {lo} {hi}"]
    if addr is not None:
        body.append(f"  ECU_ADDRESS {addr}")
    body += [f"  {e}" for e in extra]
    body.append("/end MEASUREMENT")
    return "\n".join(body)


def _cm(name: str, typ: str | None, *coeffs: str, fmt: str = '"%.3"', unit: str = '""',
        ref: str | None = None) -> str:
    """``CM(<type> <coeffs>)``: a COMPU_METHOD of that type, format ``"%.3"``,
    unit ``""`` and those coefficients (LINEAR -> COEFFS_LINEAR, RAT_FUNC -> COEFFS)."""
    body = [f'/begin COMPU_METHOD {name} ""']
    if typ is not None:
        body.append(f"  {typ} {fmt} {unit}")
    if typ == "LINEAR" and coeffs:
        body.append("  COEFFS_LINEAR " + " ".join(coeffs))
    elif typ == "RAT_FUNC" and coeffs:
        body.append("  COEFFS " + " ".join(coeffs))
    if ref is not None:
        body.append(f"  COMPU_TAB_REF {ref}")
    body.append("/end COMPU_METHOD")
    return "\n".join(body)


def _vtab(name: str, count: str, *pairs: str, default: str | None = None) -> str:
    """A COMPU_VTAB; each pair is the raw line text, e.g. ``0 "A"``."""
    body = [f'/begin COMPU_VTAB {name} "" TAB_VERB {count}']
    body += [f"  {p}" for p in pairs]
    if default is not None:
        body.append(f'  DEFAULT_VALUE "{default}"')
    body.append("/end COMPU_VTAB")
    return "\n".join(body)


def _enum_blocks(method: str, table: str, count: str, *pairs: str, default: str | None = None) -> list[str]:
    return [_cm(method, "TAB_VERB", fmt='"%.0"', ref=table), _vtab(table, count, *pairs, default=default)]


def _img(addr: int, data: bytes) -> dict[int, int]:
    return {addr + i: b for i, b in enumerate(data)}


def _word(d: Definition, data: bytes) -> dict[int, int]:
    assert d.address is not None
    return _img(d.address, data)


def _dec(d: Definition, a2l: dict, image: Mapping[int, int]):
    return decode_definition(d, a2l, image)


def _is_refused(d: Definition, code: str, message: str) -> None:
    assert d.refusal == Refusal(code, message), d.refusal


def _decoded(d: Definition, a2l: dict, image: Mapping[int, int]) -> Decoded:
    res = decode_definition(d, a2l, image)
    assert isinstance(res, Decoded), res
    return res


def _load(name: str) -> dict:
    return parse_a2l_file(EXAMPLES / "case_00_public" / name)


@pytest.fixture(scope="module")
def v171() -> dict:
    return _load("ASAP2_Demo_V171.a2l")


@pytest.fixture(scope="module")
def softa() -> dict:
    return _load("software_a.a2l")


@pytest.fixture(scope="module")
def tube() -> dict:
    return _load("BalanceTube_STMicro.a2l")


@pytest.fixture(scope="module")
def case07() -> dict:
    return parse_a2l_file(EXAMPLES / "case_07_stress_smoke" / "firmware.a2l")


@pytest.fixture(scope="module")
def c08(tmp_path_factory: pytest.TempPathFactory) -> dict:
    """Case 08 at 1 MiB, seed 20260001: both A2Ls, the image, the planned objects."""
    folder = tmp_path_factory.mktemp("b103_c08")
    gen.generate(folder, SEED, 1.0)
    regions = gen.compute_region_sizes(1.0)
    objs = gen.build_objects(regions, random.Random(SEED))
    return {
        "dir": folder,
        "a2l": parse_a2l_file(folder / "firmware.a2l"),
        "issues": parse_a2l_file(folder / "firmware_issues.a2l"),
        "mem": S19File(str(folder / "firmware.s19")).get_memory_map(),
        "objs": objs,
        "by_name": {o["name"]: o for o in objs},
    }


@pytest.fixture(scope="module")
def softa_defs(softa: dict) -> dict[str, Definition]:
    return describe_definitions([t["name"] for t in softa["tags"]], softa)


def _entries(d: Definition) -> list[tuple]:
    return [(e.raw, e.raw_max, e.text) for e in d.enum_entries]


_SIZES = {"UBYTE": 1, "SBYTE": 1, "UWORD": 2, "SWORD": 2, "ULONG": 4, "SLONG": 4}


def _first(c08: dict, conv: str) -> dict:
    return next(o for o in c08["objs"] if o["conversion"] == conv and o["kind"] in ("VALUE", "MEASUREMENT"))


def _planned_close(res: Decoded, planned) -> None:
    assert res.value == pytest.approx(planned, rel=1e-5, abs=1e-6), (res, planned)


# --- END HELPERS ----------------------------------------------------------

V171_SWORD = "ASAM.C.SCALAR.SWORD.IDENTICAL"
V171_M0FF0 = "ASAM.C.SCALAR.UWORD.IDENTICAL.BITMASK_0FF0"
V171_M0001 = "ASAM.C.SCALAR.UWORD.IDENTICAL.BITMASK_0001"
V171_M0010 = "ASAM.C.SCALAR.UWORD.IDENTICAL.BITMASK_0010"
V171_ENUM = "ASAM.C.SCALAR.SWORD.TAB_VERB_DEFAULT_VALUE"
V171_ENUM_NODEF = "ASAM.C.SCALAR.SWORD.TAB_VERB_NO_DEFAULT_VALUE"
V171_RANGE = "ASAM.C.SCALAR.SWORD.VTAB_RANGE_DEFAULT_VALUE"
V171_RANGE_NODEF = "ASAM.C.SCALAR.SWORD.VTAB_RANGE_NO_DEFAULT_VALUE"
V171_ASCII = "UNKNOWN"
V171_SBYTE = "ASAM.C.SCALAR.SBYTE.IDENTICAL"
V171_UBYTE = "ASAM.C.SCALAR.UBYTE.IDENTICAL"

# ==========================================================================
# R-A2L-DEF.1 ... .3 - the kind
# ==========================================================================


def test_r_a2l_def_1_1_value_with_plain_method_is_a_number(v171):
    """R-A2L-DEF.1/1 - a VALUE whose method is not TAB_VERB is a number."""
    d = describe_definition(V171_SWORD, v171)
    assert d.kind == "number" and d.refusal is None


def test_r_a2l_def_1_2_scalar_measurement_is_a_number(v171):
    """R-A2L-DEF.1/2 - a scalar MEASUREMENT is a number."""
    d = describe_definition("ASAM.M.SCALAR.UBYTE.IDENTICAL", v171)
    assert d.kind == "number" and d.section == "MEASUREMENT"


def test_r_a2l_def_1_3_no_compu_method_gives_a_number(softa):
    """R-A2L-DEF.1/3 - NO_COMPU_METHOD gives a number (software_a)."""
    name = next(t["name"] for t in softa["tags"]
                if t["section"] == "MEASUREMENT" and t.get("conversion") == "NO_COMPU_METHOD")
    d = describe_definition(name, softa)
    assert d.kind == "number"
    assert d.method_name == "NO_COMPU_METHOD"


def test_r_a2l_def_1_4_case08_value_is_a_number(c08):
    """R-A2L-DEF.1/4 - case 08 VALUE_0001."""
    d = describe_definition("VALUE_0001", c08["a2l"])
    assert d.kind == "number" and d.refusal is None


def test_r_a2l_def_2_1_tab_verb_with_long_identifier_on_its_own_line_is_an_enum(v171):
    """R-A2L-DEF.2/1 - the method's long identifier on its own line (base: type None)."""
    d = describe_definition(V171_ENUM, v171)
    assert d.kind == "enum" and d.conversion_type == "TAB_VERB"


def test_r_a2l_def_2_2_a2ltool_tab_verb_is_an_enum(softa):
    """R-A2L-DEF.2/2 - a2ltool shape (long identifier on the /begin line)."""
    d = describe_definition("ACN_ULWY.FVH_MUGP_O_SBW_RTD_NJZ_MKE_WODEYLMQXZ46_OXATIRMZ_YOQJZI", softa)
    assert d.kind == "enum" and d.conversion_type == "TAB_VERB"


def test_r_a2l_def_2_3_commented_tab_verb_header_is_an_enum(tube):
    """R-A2L-DEF.2/3 - TUBE: the type sits in a comment on the header."""
    d = describe_definition("model.MainClass.gameController.sm", tube)
    assert d.kind == "enum" and d.conversion_type == "TAB_VERB"


def test_r_a2l_def_3_1_ascii_characteristic_is_a_text(v171):
    """R-A2L-DEF.3/1 - V171 ASCII object (the parser names it UNKNOWN)."""
    d = describe_definition(V171_ASCII, v171)
    assert d.kind == "text" and d.byte_length == 42 and d.address == 0x810200


def test_r_a2l_def_3_2_case08_ascii_is_a_text(c08):
    """R-A2L-DEF.3/2 - case 08 ASCII_0001, byte length 32."""
    d = describe_definition("ASCII_0001", c08["a2l"])
    assert d.kind == "text" and d.byte_length == 32


# ==========================================================================
# R-A2L-DEF.4 - the kind refusal
# ==========================================================================


def _kind_msg(name: str, kind: str) -> tuple[str, str]:
    return "A2L-DEF-KIND", f"{name}: the system has no definition for a {kind} object"


def test_r_a2l_def_4_1_val_blk_is_refused(c08):
    """R-A2L-DEF.4/1 - VAL_BLK refused; address and byte length 256 still given."""
    d = describe_definition("VAL_BLK_0001", c08["a2l"])
    _is_refused(d, *_kind_msg("VAL_BLK_0001", "VAL_BLK"))
    assert d.byte_length == 256
    assert d.address == c08["by_name"]["VAL_BLK_0001"]["address"]


def test_r_a2l_def_4_2_curve_is_refused(c08):
    """R-A2L-DEF.4/2 - CURVE."""
    d = describe_definition("CURVE_0001", c08["a2l"])
    _is_refused(d, *_kind_msg("CURVE_0001", "CURVE"))


def test_r_a2l_def_4_3_map_is_refused(c08):
    """R-A2L-DEF.4/3 - MAP."""
    d = describe_definition("MAP_0001", c08["a2l"])
    _is_refused(d, *_kind_msg("MAP_0001", "MAP"))


def test_r_a2l_def_4_4_cuboid_is_refused(v171):
    """R-A2L-DEF.4/4 - the first CUBOID CHARACTERISTIC of V171."""
    name = next(t["name"] for t in v171["tags"] if t.get("char_type") == "CUBOID")
    d = describe_definition(name, v171)
    _is_refused(d, *_kind_msg(name, "CUBOID"))


def test_r_a2l_def_4_5_map_block_is_refused(tmp_path):
    """R-A2L-DEF.4/5 - MAP_BLOCK."""
    a2l = _inline(tmp_path, _char("MB", "MAP_BLOCK", "0x10", "RL_U16"))
    _is_refused(describe_definition("MB", a2l), *_kind_msg("MB", "MAP_BLOCK"))


def test_r_a2l_def_4_6_vendor_kind_is_refused_and_keeps_its_address(tmp_path):
    """R-A2L-DEF.4/6 - a vendor kind (DIRECT_X) at 0x10."""
    a2l = _inline(tmp_path, _char("VK", "DIRECT_X", "0x10", "RL_U16"))
    d = describe_definition("VK", a2l)
    _is_refused(d, *_kind_msg("VK", "DIRECT_X"))
    assert d.address == 0x10


def test_r_a2l_def_4_7_array_measurement_is_refused(v171):
    """R-A2L-DEF.4/7 - MATRIX_DIM 16 MEASUREMENT."""
    n = "ASAM.M.MATRIX_DIM_16_1.UBYTE.IDENTICAL"
    d = describe_definition(n, v171)
    _is_refused(d, *_kind_msg(n, "MATRIX_DIM 16 MEASUREMENT"))


def test_r_a2l_def_4_8_header_with_no_kind_is_refused(case07):
    """R-A2L-DEF.4/8 - case 07 CHAR_000000: the kind text is (none)."""
    d = describe_definition("CHAR_000000", case07)
    _is_refused(d, *_kind_msg("CHAR_000000", "(none)"))
    assert d.address == 0x08011400 and d.byte_length == 4


# ==========================================================================
# R-A2L-DEF.5, .6, .139 - the name
# ==========================================================================


def test_r_a2l_def_5_1_the_one_tag_of_a_name_is_used_case_included(tmp_path):
    """R-A2L-DEF.5/1 - DUP at 0x20, dup at 0x10: DUP is the 0x20 object."""
    a2l = _inline(tmp_path, _val("DUP", "0x20", "RL_U16"), _val("dup", "0x10", "RL_U16"))
    d = describe_definition("DUP", a2l)
    assert d.address == 0x20 and d.refusal is None


def test_r_a2l_def_5_2_case08_name_declared_once(c08):
    """R-A2L-DEF.5/2 - VALUE_0001 at 0x0."""
    d = describe_definition("VALUE_0001", c08["a2l"])
    assert d.address == 0x0 and d.refusal is None


def test_r_a2l_def_6_1_unknown_name_is_refused(v171):
    """R-A2L-DEF.6/1 - NO_SUCH_TAG."""
    d = describe_definition("NO_SUCH_TAG", v171)
    _is_refused(d, "A2L-DEF-NAME", "NO_SUCH_TAG: no tag of that name in the A2L")
    assert d.kind == "" and d.address is None


def test_r_a2l_def_6_2_name_is_matched_with_its_case(c08):
    """R-A2L-DEF.6/2 - value_0001 is not VALUE_0001."""
    d = describe_definition("value_0001", c08["a2l"])
    _is_refused(d, "A2L-DEF-NAME", "value_0001: no tag of that name in the A2L")


def test_r_a2l_def_139_1_name_declared_twice_is_refused(tmp_path):
    """R-A2L-DEF.139/1 - two VALUEs named DUP."""
    a2l = _inline(tmp_path, _val("DUP", "0x10", "RL_U16"), _val("DUP", "0x20", "RL_U16"))
    _is_refused(describe_definition("DUP", a2l), "A2L-DEF-NAME", "DUP: the A2L declares that name more than once")


def test_r_a2l_def_139_2_case08_issues_duplicate(c08):
    """R-A2L-DEF.139/2 - firmware_issues.a2l declares VALUE_0001 twice."""
    d = describe_definition("VALUE_0001", c08["issues"])
    _is_refused(d, "A2L-DEF-NAME", "VALUE_0001: the A2L declares that name more than once")


def test_r_a2l_def_139_3_commented_out_old_copy_counts_as_a_second_declaration(tmp_path):
    """R-A2L-DEF.139/3 - the builder opens the commented-out copy: two tags."""
    old = "\n".join(["/*", '/begin MEASUREMENT X "old"', "  UWORD CM_ID 0 0 0 65535", "  ECU_ADDRESS 0x10",
                     "/end MEASUREMENT", "*/"])
    a2l = _inline(tmp_path, _cm("CM_ID", "IDENTICAL"), old, _meas("X", "UWORD", "CM_ID", addr="0x20"))
    _is_refused(describe_definition("X", a2l), "A2L-DEF-NAME", "X: the A2L declares that name more than once")


# ==========================================================================
# R-A2L-DEF.7.1, .7.2 - address and length
# ==========================================================================


def test_r_a2l_def_7_1_1_no_address_is_refused(tmp_path):
    """R-A2L-DEF.7.1/1 - MEASUREMENT with no ECU_ADDRESS."""
    a2l = _inline(tmp_path, _meas("NA", "UBYTE"))
    _is_refused(describe_definition("NA", a2l), "A2L-DEF-ADDRESS", "NA: the object has no address or no length")


def test_r_a2l_def_7_1_2_no_length_is_refused(tmp_path):
    """R-A2L-DEF.7.1/2 - ASCII CHARACTERISTIC with no NUMBER, MATRIX_DIM or LENGTH."""
    a2l = _inline(tmp_path, _char("NL", "ASCII", "0x10", "RL_U8", "NO_COMPU_METHOD", "0", "255"))
    _is_refused(describe_definition("NL", a2l), "A2L-DEF-ADDRESS", "NL: the object has no address or no length")


def _ascii(name: str, addr: str, number: str, *extra: str) -> str:
    return _char(name, "ASCII", addr, "RL_U8", "NO_COMPU_METHOD", "0", "255", f"NUMBER {number}", *extra)


def test_r_a2l_def_7_2_1_length_zero_is_refused(tmp_path):
    """R-A2L-DEF.7.2/1 - NUMBER 0."""
    a2l = _inline(tmp_path, _ascii("Z0", "0x10", "0"))
    _is_refused(describe_definition("Z0", a2l), "A2L-DEF-ADDRESS", "Z0: its span of 0 bytes at 0x10 cannot be read")


def test_r_a2l_def_7_2_2_negative_length_is_refused(tmp_path):
    """R-A2L-DEF.7.2/2 - NUMBER -5."""
    a2l = _inline(tmp_path, _ascii("ZN", "0x10", "-5"))
    _is_refused(describe_definition("ZN", a2l), "A2L-DEF-ADDRESS", "ZN: its span of -5 bytes at 0x10 cannot be read")


def test_r_a2l_def_7_2_3_length_above_one_mib_is_refused(tmp_path):
    """R-A2L-DEF.7.2/3 - NUMBER 1048577 (one past the bound)."""
    a2l = _inline(tmp_path, _ascii("ZH", "0x10", "1048577"))
    _is_refused(describe_definition("ZH", a2l), "A2L-DEF-ADDRESS", "ZH: its span of 1048577 bytes at 0x10 cannot be read")


def test_r_a2l_def_7_2_4_negative_address_is_refused(tmp_path):
    """R-A2L-DEF.7.2/4 - address -0x10 (a UWORD object)."""
    a2l = _inline(tmp_path, _meas("NA2", "UWORD", addr="-0x10"))
    _is_refused(describe_definition("NA2", a2l), "A2L-DEF-ADDRESS", "NA2: its span of 2 bytes at -0x10 cannot be read")


def test_r_a2l_def_7_2_5_span_ending_above_32_bits_is_refused(tmp_path):
    """R-A2L-DEF.7.2/5 - 0xFFFFFFFF + 3 bytes."""
    a2l = _inline(tmp_path, _ascii("ZS", "0xFFFFFFFF", "3"))
    _is_refused(describe_definition("ZS", a2l), "A2L-DEF-ADDRESS", "ZS: its span of 3 bytes at 0xFFFFFFFF cannot be read")


def test_r_a2l_def_7_2_6_span_whose_last_byte_is_0xffffffff_is_readable(tmp_path):
    """R-A2L-DEF.7.2/6 - boundary: 0xFFFFFF00 + 256 bytes."""
    a2l = _inline(tmp_path, _ascii("ZB", "0xFFFFFF00", "256"))
    d = describe_definition("ZB", a2l)
    assert d.refusal is None and d.address == 0xFFFFFF00 and d.byte_length == 256


# ==========================================================================
# R-A2L-DEF.8, .9 - datatype and length
# ==========================================================================


def test_r_a2l_def_8_1_unreadable_layout_datatype_is_refused(tmp_path):
    """R-A2L-DEF.8/1 - RECORD_LAYOUT RL_X with datatype FOO."""
    rl = '/begin RECORD_LAYOUT RL_X\n  FNC_VALUES 1 FOO ROW_DIR DIRECT\n/end RECORD_LAYOUT'
    a2l = _inline(tmp_path, rl, _val("ND", "0x10", "RL_X", "NO_COMPU_METHOD", "0", "65535", "LENGTH 2"))
    _is_refused(describe_definition("ND", a2l), "A2L-DEF-DATATYPE",
                "ND: the object declares no datatype the system can read")


def test_r_a2l_def_8_2_unknown_measurement_datatype_is_refused(tmp_path):
    """R-A2L-DEF.8/2 - MEASUREMENT datatype FOO."""
    a2l = _inline(tmp_path, _meas("NM", "FOO", "NO_COMPU_METHOD", "0", "1", "LENGTH 1", addr="0x10"))
    _is_refused(describe_definition("NM", a2l), "A2L-DEF-DATATYPE",
                "NM: the object declares no datatype the system can read")


def test_r_a2l_def_9_1_length_not_the_datatypes_is_refused(tmp_path):
    """R-A2L-DEF.9/1 - UWORD with LENGTH 4."""
    a2l = _inline(tmp_path, _val("LX", "0x10", "RL_U16", "NO_COMPU_METHOD", "0", "65535", "LENGTH 4"))
    _is_refused(describe_definition("LX", a2l), "A2L-DEF-LENGTH", "LX: its length 4 differs from the 2 bytes of UWORD")


# ==========================================================================
# R-A2L-DEF.10 ... .13 - the conversion method
# ==========================================================================


def test_r_a2l_def_10_1_type_of_a_multi_line_v171_method(v171):
    """R-A2L-DEF.10/1 - CM.TAB_VERB.DEFAULT_VALUE."""
    d = describe_definition(V171_ENUM, v171)
    assert d.method_name == "CM.TAB_VERB.DEFAULT_VALUE" and d.conversion_type == "TAB_VERB"


def test_r_a2l_def_10_2_type_of_an_identical_method(v171):
    """R-A2L-DEF.10/2 - CM.IDENTICAL."""
    d = describe_definition(V171_UBYTE, v171)
    assert d.method_name == "CM.IDENTICAL" and d.conversion_type == "IDENTICAL"


def test_r_a2l_def_10_3_type_of_an_a2ltool_method(softa):
    """R-A2L-DEF.10/3 - the method of R-A2L-DEF.2/2."""
    d = describe_definition("ACN_ULWY.FVH_MUGP_O_SBW_RTD_NJZ_MKE_WODEYLMQXZ46_OXATIRMZ_YOQJZI", softa)
    assert d.method_name == "RKR_KC_VVOYJDA" and d.conversion_type == "TAB_VERB"


def test_r_a2l_def_10_4_type_of_a_commented_header(tube):
    """R-A2L-DEF.10/4 - esdl_model_GameControllerStatemachineStates."""
    d = describe_definition("model.MainClass.gameController.sm", tube)
    assert d.method_name == "esdl_model_GameControllerStatemachineStates"
    assert d.conversion_type == "TAB_VERB"


def test_r_a2l_def_11_1_undeclared_method_is_refused(c08):
    """R-A2L-DEF.11/1 - MISSING_CM names CM_MISSING (base: identity)."""
    d = describe_definition("MISSING_CM", c08["issues"])
    _is_refused(d, "A2L-DEF-METHOD", "MISSING_CM: the conversion method CM_MISSING is not declared in the A2L")


def test_r_a2l_def_12_1_form_is_not_supported(tmp_path):
    """R-A2L-DEF.12/1 - FORM."""
    form = ('/begin COMPU_METHOD CM_F ""\n  FORM "%.1" ""\n  /begin FORMULA\n    "X1*2"\n  /end FORMULA\n'
            '/end COMPU_METHOD')
    a2l = _inline(tmp_path, form, _val("FX", "0x10", "RL_U16", "CM_F"))
    _is_refused(describe_definition("FX", a2l), "A2L-DEF-CONVERSION",
                "FX: the conversion type FORM of CM_F is not supported")


def test_r_a2l_def_12_2_an_unlisted_type_is_not_supported(tmp_path):
    """R-A2L-DEF.12/2 - type FOO."""
    a2l = _inline(tmp_path, _cm("CM_Q", "FOO"), _val("QX", "0x10", "RL_U16", "CM_Q"))
    _is_refused(describe_definition("QX", a2l), "A2L-DEF-CONVERSION",
                "QX: the conversion type FOO of CM_Q is not supported")


def test_r_a2l_def_12_3_a_record_with_no_type_is_not_supported(tmp_path):
    """R-A2L-DEF.12/3 - ``/begin COMPU_METHOD CM_E "d"`` and nothing more."""
    a2l = _inline(tmp_path, '/begin COMPU_METHOD CM_E "d"\n/end COMPU_METHOD', _val("EX", "0x10", "RL_U16", "CM_E"))
    _is_refused(describe_definition("EX", a2l), "A2L-DEF-CONVERSION",
                "EX: the conversion type (none) of CM_E is not supported")


def test_r_a2l_def_12_4_a_listed_type_in_another_letter_case_is_not_supported(tmp_path):
    """R-A2L-DEF.12/4 (E5 fix pass, CR-4 = E5S-05) - ``tab_intp`` is not ``TAB_INTP``: describe and decode refuse it."""
    a2l = _inline(
        tmp_path,
        _cm("CM_LC", "tab_intp", fmt='"%.0"', ref="CT_LC"),
        '/begin COMPU_TAB CT_LC "" TAB_INTP 2\n  0 0\n  100 100\n/end COMPU_TAB',
        _val("LC", "0x10", LAYOUT["UBYTE"], "CM_LC", "0", "255"),
    )
    d = describe_definition("LC", a2l)
    want = Refusal("A2L-DEF-CONVERSION", "LC: the conversion type tab_intp of CM_LC is not supported")
    assert d.refusal == want, d.refusal
    # the frozen view of the same bytes interpolates (50.0): a silent 0.0 from a case-folded verdict is the defect
    assert decode_definition(d, a2l, {0x10: 50}) == want


def test_r_a2l_def_13_1_enum_with_no_table_is_refused(tmp_path):
    """R-A2L-DEF.13/1 - TAB_VERB with no COMPU_TAB_REF."""
    a2l = _inline(tmp_path, _cm("CM_V", "TAB_VERB", fmt='"%.0"'), _val("EN", "0x10", "RL_U8", "CM_V"))
    _is_refused(describe_definition("EN", a2l), "A2L-DEF-TABLE", "EN: the table (none) of CM_V is not declared in the A2L")


def test_r_a2l_def_13_2_dangling_table_is_refused(tmp_path):
    """R-A2L-DEF.13/2 - COMPU_TAB_REF VT_GONE."""
    a2l = _inline(tmp_path, _cm("CM_V", "TAB_VERB", fmt='"%.0"', ref="VT_GONE"), _val("EN", "0x10", "RL_U8", "CM_V"))
    _is_refused(describe_definition("EN", a2l), "A2L-DEF-TABLE",
                "EN: the table VT_GONE of CM_V is not declared in the A2L")


# ==========================================================================
# R-A2L-DEF.14 ... .17 - the enum table
# ==========================================================================


def test_r_a2l_def_14_1_pairs_of_a_v171_compu_vtab(v171):
    """R-A2L-DEF.14/1 - (1 SawTooth) (2 Square) (3 Sinus), in file order."""
    d = describe_definition(V171_ENUM, v171)
    assert _entries(d) == [(1.0, None, "SawTooth"), (2.0, None, "Square"), (3.0, None, "Sinus")]


def test_r_a2l_def_14_2_negative_raw_first(softa):
    """R-A2L-DEF.14/2 - an a2ltool COMPU_VTAB whose first pair is -1."""
    d = describe_definition("QUUU_Ywjznkkjwj.AuooouPgqj", softa)
    assert d.kind == "enum"
    assert d.enum_entries[0].raw == -1.0 and d.enum_entries[0].text == "NMUF_MSWGZ_SPTKAGRI"


def test_r_a2l_def_14_3_file_order_and_numeric_text_stay_as_written(tmp_path):
    """R-A2L-DEF.14/3 - ``2 "B"`` then ``1 "10"``: not sorted, text not a float."""
    a2l = _inline(tmp_path, *_enum_blocks("CM_A", "VT_A", "2", '2 "B"', '1 "10"'), _val("EA", "0x10", "RL_U8", "CM_A"))
    d = describe_definition("EA", a2l)
    assert _entries(d) == [(2.0, None, "B"), (1.0, None, "10")]
    assert isinstance(d.enum_entries[1].text, str)


def test_r_a2l_def_15_1_triples_of_a_v171_compu_vtab_range(v171):
    """R-A2L-DEF.15/1 - 11 triples; first (0, 1, Zero_to_one); last (105, 105, hundredfive)."""
    d = describe_definition(V171_RANGE, v171)
    assert len(d.enum_entries) == 11
    assert _entries(d)[0] == (0.0, 1.0, "Zero_to_one")
    assert _entries(d)[-1] == (105.0, 105.0, "hundredfive")


def test_r_a2l_def_15_2_a2ltool_range_table(softa, softa_defs):
    """R-A2L-DEF.15/2 - the first COMPU_VTAB_RANGE of software_a: 5 entries, first (0, 0, text)."""
    # Integration fix (orchestrator, 2026-11-07; diagnosis evidence-e4/diag-2a-transcript.txt):
    # the side table holds only COMPU_VTAB sections, so the first COMPU_VTAB_RANGE is found
    # by a pre-order walk of the section tree, its name read as the reader reads it.
    from s19_app.tui.a2l import parse_begin_meta

    def _first_range(nodes):
        for node in nodes:
            if node.get("name") == "COMPU_VTAB_RANGE":
                return parse_begin_meta(node.get("meta", "") or "")[0]
            found = _first_range(node.get("children") or [])
            if found is not None:
                return found
        return None

    table = _first_range(softa["sections"])
    assert table is not None
    d = next(x for x in softa_defs.values() if x.enum_table == table)
    assert d.kind == "enum"
    assert len(d.enum_entries) == 5
    assert d.enum_entries[0].raw == 0.0 and d.enum_entries[0].raw_max == 0.0
    assert d.enum_entries[0].text == "BPQ_UQKPL_XLDM_EM_SPFMDDQDOEMCT"


def test_r_a2l_def_16_1_default_text_of_a_compu_vtab(v171):
    """R-A2L-DEF.16/1."""
    assert describe_definition(V171_ENUM, v171).default_text == "unknown signal type"


def test_r_a2l_def_16_2_default_text_of_a_range_table(v171):
    """R-A2L-DEF.16/2."""
    assert describe_definition(V171_RANGE, v171).default_text == "out of range value"


def test_r_a2l_def_17_1_count_zero_is_refused(tmp_path):
    """R-A2L-DEF.17/1 - ``TAB_VERB 0``."""
    a2l = _inline(tmp_path, *_enum_blocks("CM_0", "VT_0", "0"), _val("E0", "0x10", "RL_U8", "CM_0"))
    _is_refused(describe_definition("E0", a2l), "A2L-DEF-TABLE-EMPTY", "E0: the table VT_0 has no entries")


def test_r_a2l_def_17_2_count_not_a_number_is_refused(tmp_path):
    """R-A2L-DEF.17/2 - ``TAB_VERB X`` then ``0 "A"``."""
    a2l = _inline(tmp_path, *_enum_blocks("CM_N", "VT_N", "X", '0 "A"'), _val("EN2", "0x10", "RL_U8", "CM_N"))
    _is_refused(describe_definition("EN2", a2l), "A2L-DEF-TABLE-EMPTY", "EN2: the table VT_N has no entries")


# ==========================================================================
# R-A2L-DEF.18 ... .24 - mask, limits, format, order of refusals
# ==========================================================================


def test_r_a2l_def_18_1_hexadecimal_mask(v171):
    """R-A2L-DEF.18/1 - 0x0FF0 and its text."""
    d = describe_definition(V171_M0FF0, v171)
    assert d.bit_mask == 0x0FF0 and d.bit_mask_text == "0x0FF0"


def test_r_a2l_def_18_2_decimal_mask(tmp_path):
    """R-A2L-DEF.18/2 - ``BIT_MASK 16``."""
    a2l = _inline(tmp_path, _val("MD", "0x10", "RL_U16", "NO_COMPU_METHOD", "0", "65535", "BIT_MASK 16"))
    d = describe_definition("MD", a2l)
    assert d.bit_mask == 16 and d.bit_mask_text == "16" and d.refusal is None


def test_r_a2l_def_18_3_a_24_bit_mask_on_a_ulong(softa, tmp_path):
    """R-A2L-DEF.18/3 - software_a (no address -> ADDRESS, not MASK) and INLINE ULONG."""
    d = describe_definition("Adt_UhsihQwbpns._9_.NfwzbMcockRrbkj", softa)
    assert d.bit_mask == 16777215 and d.bit_mask_text == "0xFFFFFF"
    assert d.refusal is not None and d.refusal.code == "A2L-DEF-ADDRESS"
    a2l = _inline(tmp_path, _val("M24", "0x10", "RL_U32", "NO_COMPU_METHOD", "0", "4294967295", "BIT_MASK 0xFFFFFF"))
    d2 = describe_definition("M24", a2l)
    assert d2.bit_mask == 16777215 and d2.refusal is None


def _mask_case(tmp_path, name: str, block: str):
    return describe_definition(name, _inline(tmp_path, block))


def test_r_a2l_def_19_1_mask_zero_is_refused(tmp_path):
    """R-A2L-DEF.19/1."""
    d = _mask_case(tmp_path, "M0", _val("M0", "0x10", "RL_U16", "NO_COMPU_METHOD", "0", "65535", "BIT_MASK 0"))
    _is_refused(d, "A2L-DEF-MASK", "M0: the bit mask 0 cannot be applied to UWORD")


def test_r_a2l_def_19_2_mask_wider_than_the_datatype_is_refused(tmp_path):
    """R-A2L-DEF.19/2 - 0x100 on a UBYTE."""
    d = _mask_case(tmp_path, "MW", _val("MW", "0x10", "RL_U8", "NO_COMPU_METHOD", "0", "255", "BIT_MASK 0x100"))
    _is_refused(d, "A2L-DEF-MASK", "MW: the bit mask 0x100 cannot be applied to UBYTE")


def test_r_a2l_def_19_3_mask_on_a_float_is_refused(tmp_path):
    """R-A2L-DEF.19/3 - FLOAT32_IEEE."""
    d = _mask_case(tmp_path, "MF", _val("MF", "0x10", "RL_F32", "NO_COMPU_METHOD", "0", "1000", "BIT_MASK 0x1"))
    _is_refused(d, "A2L-DEF-MASK", "MF: the bit mask 0x1 cannot be applied to FLOAT32_IEEE")


def test_r_a2l_def_19_4_unreadable_mask_word_is_refused(tmp_path):
    """R-A2L-DEF.19/4 - ``0b11`` (int(x, 0) would read 3)."""
    d = _mask_case(tmp_path, "MX", _val("MX", "0x10", "RL_U16", "NO_COMPU_METHOD", "0", "65535", "BIT_MASK 0b11"))
    _is_refused(d, "A2L-DEF-MASK", "MX: the bit mask 0b11 cannot be applied to UWORD")


def test_r_a2l_def_19_5_mask_on_a_text_object_is_refused(tmp_path):
    """R-A2L-DEF.19/5 - ASCII with BIT_MASK."""
    d = _mask_case(tmp_path, "MT", _ascii("MT", "0x10", "4", "BIT_MASK 0x1"))
    _is_refused(d, "A2L-DEF-MASK", "MT: the bit mask 0x1 cannot be applied to ASCII")


def test_r_a2l_def_19_9_signed_mask_with_bit_0_and_the_sign_bit_is_refused(tmp_path):
    """R-A2L-DEF.19/9 - 0xFF on an SBYTE."""
    d = _mask_case(tmp_path, "MS", _val("MS", "0x10", "RL_S8", "NO_COMPU_METHOD", "-128", "127", "BIT_MASK 0xFF"))
    _is_refused(d, "A2L-DEF-MASK", "MS: the bit mask 0xFF cannot be applied to SBYTE")


def test_r_a2l_def_20_1_integer_extended_limits(v171):
    """R-A2L-DEF.20/1 - extended -128..127, limits -100..100."""
    d = describe_definition(V171_SBYTE, v171)
    assert (d.extended_limits.lower, d.extended_limits.upper) == (-128, 127)
    assert (d.limits.lower, d.limits.upper) == (-100, 100)


def test_r_a2l_def_20_2_decimal_extended_limits(v171):
    """R-A2L-DEF.20/2 - EXTENDED_LIMITS -10000.0 20000.0."""
    d = describe_definition("ASAM.C.SCALAR.FLOAT64_IEEE.IDENTICAL", v171)
    assert (d.extended_limits.lower, d.extended_limits.upper) == (-10000.0, 20000.0)


def test_r_a2l_def_21_1_one_number_gives_no_extended_limits(tmp_path):
    """R-A2L-DEF.21/1 - ``EXTENDED_LIMITS 0`` (next word is a keyword)."""
    a2l = _inline(tmp_path, _val("XL1", "0x10", "RL_U16", "NO_COMPU_METHOD", "0", "65535",
                                 "EXTENDED_LIMITS 0", 'FORMAT "%5.0"'))
    d = describe_definition("XL1", a2l)
    assert d.extended_limits is None and d.display_format == "%5.0"
    ok = _inline(tmp_path, _val("XL0", "0x10", "RL_U16", "NO_COMPU_METHOD", "0", "65535", "EXTENDED_LIMITS 1 2"))
    pair = describe_definition("XL0", ok).extended_limits
    assert (pair.lower, pair.upper) == (1, 2)


def test_r_a2l_def_21_2_words_give_no_extended_limits(tmp_path):
    """R-A2L-DEF.21/2 - ``EXTENDED_LIMITS a b``."""
    a2l = _inline(tmp_path, _val("XL2", "0x10", "RL_U16", "NO_COMPU_METHOD", "0", "65535", "EXTENDED_LIMITS a b"))
    assert describe_definition("XL2", a2l).extended_limits is None
    ok = _inline(tmp_path, _val("XL0", "0x10", "RL_U16", "NO_COMPU_METHOD", "0", "65535", "EXTENDED_LIMITS 1 2"))
    assert describe_definition("XL0", ok).extended_limits is not None


def test_r_a2l_def_21_3_non_finite_words_give_no_extended_limits(tmp_path):
    """R-A2L-DEF.21/3 (2a arm) - ``EXTENDED_LIMITS nan nan`` is not a pair of numbers; the encode of 101 waits for 2b."""
    a2l = _inline(tmp_path, _cm("CM_L", "LINEAR", "1", "0"),
                  _val("XL3", "0x10", "RL_S16", "CM_L", "0", "100", "EXTENDED_LIMITS nan nan"))
    d = describe_definition("XL3", a2l)
    assert d.extended_limits is None
    assert (d.limits.lower, d.limits.upper) == (0, 100) and d.method_name == "CM_L"


def test_r_a2l_def_22_1_format_overrides_the_method_format(v171):
    """R-A2L-DEF.22/1 - %6.1 over %3.0."""
    assert describe_definition(V171_SBYTE, v171).display_format == "%6.1"


def test_r_a2l_def_22_2_format_with_a_trailing_comment(v171):
    """R-A2L-DEF.22/2 - ``FORMAT "%5.0"    /* Note ... */``."""
    assert describe_definition("ASAM.M.SCALAR.UBYTE.IDENTICAL", v171).display_format == "%5.0"


def test_r_a2l_def_23_1_method_format_is_the_fallback(v171):
    """R-A2L-DEF.23/1 - no FORMAT line: the method's %3.0."""
    d = describe_definition(V171_UBYTE, v171)
    assert d.display_format == "%3.0" and d.decimals == 0


def test_r_a2l_def_23_2_format_of_a_commented_header(tube):
    """R-A2L-DEF.23/2 - TUBE: %12.4 (base: None)."""
    assert describe_definition("model.MainClass.gameController.sm", tube).display_format == "%12.4"


def test_r_a2l_def_24_1_kind_comes_before_address(tmp_path):
    """R-A2L-DEF.24/1."""
    a2l = _inline(tmp_path, _meas("MA", "UBYTE", "NO_COMPU_METHOD", "0", "255", "MATRIX_DIM 4"))
    assert describe_definition("MA", a2l).refusal.code == "A2L-DEF-KIND"


def test_r_a2l_def_24_2_address_comes_before_method(tmp_path):
    """R-A2L-DEF.24/2 - no address and an undeclared method: ADDRESS."""
    a2l = _inline(tmp_path, _meas("AM", "UBYTE", "CM_GONE", "0", "255"))
    assert describe_definition("AM", a2l).refusal.code == "A2L-DEF-ADDRESS"


def test_r_a2l_def_24_3_table_comes_before_mask(tmp_path):
    """R-A2L-DEF.24/3."""
    a2l = _inline(tmp_path, _cm("CM_V", "TAB_VERB", fmt='"%.0"', ref="VT_GONE"),
                  _val("TM", "0x10", "RL_U8", "CM_V", "0", "255", "BIT_MASK 0"))
    assert describe_definition("TM", a2l).refusal.code == "A2L-DEF-TABLE"


def test_r_a2l_def_24_4_address_comes_before_the_mask(tmp_path):
    """R-A2L-DEF.24/4 - ASCII with BIT_MASK 0x1 and no NUMBER."""
    a2l = _inline(tmp_path, _char("MA2", "ASCII", "0x10", "RL_U8", "NO_COMPU_METHOD", "0", "255", "BIT_MASK 0x1"))
    _is_refused(describe_definition("MA2", a2l), "A2L-DEF-ADDRESS", "MA2: the object has no address or no length")


# ==========================================================================
# R-A2L-DEF.25 (decode arm), .26/1 - decode refusals
# ==========================================================================


def test_r_a2l_def_25_1_decode_gives_the_definitions_refusal(c08):
    """R-A2L-DEF.25/1 - MISSING_CM decodes to its A2L-DEF-METHOD refusal, no value."""
    d = describe_definition("MISSING_CM", c08["issues"])
    res = decode_definition(d, c08["issues"], c08["mem"])
    assert isinstance(res, Refusal) and res == d.refusal and res.code == "A2L-DEF-METHOD"


def test_r_a2l_def_26_1_a_missing_byte_is_refused_at_decode(tmp_path):
    """R-A2L-DEF.26/1 - UWORD at 0x10, image holds 0x10 only."""
    a2l = _inline(tmp_path, _val("MB2", "0x10", "RL_U16"))
    d = describe_definition("MB2", a2l)
    res = decode_definition(d, a2l, {0x10: 0})
    assert res == Refusal("A2L-DEF-BYTES", "MB2: 1 of its 2 bytes are not in the image")


# ==========================================================================
# R-A2L-DEF.27 ... .39 - decode and display
# ==========================================================================


def test_r_a2l_def_27_1_multi_bit_field(v171):
    """R-A2L-DEF.27/1 - word 0x1234, mask 0x0FF0 -> 35 (base: 4660)."""
    d = describe_definition(V171_M0FF0, v171)
    res = _decoded(d, v171, _img(0x810002, bytes([0x34, 0x12])))
    assert res.stored == 35 and res.text == "35"


def test_r_a2l_def_27_2_single_bit_field(v171):
    """R-A2L-DEF.27/2 - word 0x0010, mask 0x0010 -> 1."""
    d = describe_definition(V171_M0010, v171)
    assert _decoded(d, v171, _img(0x810002, bytes([0x10, 0x00]))).stored == 1


def test_r_a2l_def_27_3_field_of_a_signed_datatype_is_unsigned(tmp_path):
    """R-A2L-DEF.27/3 - SWORD, mask 0xFF00, word F0 F0 -> 240."""
    a2l = _inline(tmp_path, _val("SM", "0x10", "RL_S16", "NO_COMPU_METHOD", "-32768", "32767", "BIT_MASK 0xFF00"))
    d = describe_definition("SM", a2l)
    assert _decoded(d, a2l, _img(0x10, bytes([0xF0, 0xF0]))).stored == 240


def _rat(tmp_path, name: str, coeffs: str, raw: bytes):
    a2l = _inline(tmp_path, _cm("CM_R", "RAT_FUNC", *coeffs.split()), _val(name, "0x10", "RL_U16", "CM_R"))
    d = describe_definition(name, a2l)
    return d, decode_definition(d, a2l, _img(0x10, raw))


def test_r_a2l_def_28_1_rat_func_no_solution(tmp_path):
    """R-A2L-DEF.28/1."""
    _d, res = _rat(tmp_path, "R1", "0 0 5 0 0 1", bytes([0, 7]))
    assert res == Refusal("A2L-DEF-DECODE", "R1: RAT_FUNC has no solution for this value")


def test_r_a2l_def_28_2_rat_func_no_real_root(tmp_path):
    """R-A2L-DEF.28/2."""
    _d, res = _rat(tmp_path, "R2", "1 0 1 0 0 1", bytes([0, 0]))
    assert res == Refusal("A2L-DEF-DECODE", "R2: RAT_FUNC has no real root for this value")


def test_r_a2l_def_28_3_rat_func_zero_denominator(tmp_path):
    """R-A2L-DEF.28/3."""
    _d, res = _rat(tmp_path, "R3", "0 1 1 0 1 1", bytes([0, 2]))
    assert res == Refusal("A2L-DEF-DECODE", "R3: RAT_FUNC root has a zero denominator")


def test_r_a2l_def_29_1_first_of_two_entries_with_one_raw(tmp_path):
    """R-A2L-DEF.29/1 - ``1 "A"`` ``1 "B"``, stored 1 -> A."""
    a2l = _inline(tmp_path, *_enum_blocks("CM_D", "VT_D", "2", '1 "A"', '1 "B"'), _val("ED", "0x10", "RL_U8", "CM_D"))
    d = describe_definition("ED", a2l)
    assert _decoded(d, a2l, _img(0x10, b"\x01")).text == "A"


def _v171_text(v171, name: str, raw: bytes) -> str:
    d = describe_definition(name, v171)
    return _decoded(d, v171, _word(d, raw)).text


def test_r_a2l_def_30_1_range_min(v171):
    """R-A2L-DEF.30/1 - stored 0."""
    assert _v171_text(v171, V171_RANGE, b"\x00\x00") == "Zero_to_one"


def test_r_a2l_def_30_2_range_max(v171):
    """R-A2L-DEF.30/2 - stored 1 (the max end is included)."""
    assert _v171_text(v171, V171_RANGE, b"\x01\x00") == "Zero_to_one"


def test_r_a2l_def_30_3_inside_a_range(v171):
    """R-A2L-DEF.30/3 - stored 5."""
    assert _v171_text(v171, V171_RANGE, b"\x05\x00") == "four_to_seven"


def test_r_a2l_def_30_4_one_value_range(v171):
    """R-A2L-DEF.30/4 - stored 100."""
    assert _v171_text(v171, V171_RANGE, b"\x64\x00") == "hundred"


def test_r_a2l_def_31_1_default_text_of_a_compu_vtab(v171):
    """R-A2L-DEF.31/1 - stored 9."""
    assert _v171_text(v171, V171_ENUM, b"\x09\x00") == "unknown signal type"


def test_r_a2l_def_31_2_default_text_of_a_range_table(v171):
    """R-A2L-DEF.31/2 - stored 10."""
    assert _v171_text(v171, V171_RANGE, b"\x0a\x00") == "out of range value"


def test_r_a2l_def_32_1_unmatched_value_with_no_default_pairs(v171):
    """R-A2L-DEF.32/1 - ``1 (no text)``."""
    assert _v171_text(v171, V171_ENUM_NODEF, b"\x01\x00") == "1 (no text)"


def test_r_a2l_def_32_2_unmatched_value_with_no_default_ranges(v171):
    """R-A2L-DEF.32/2 - ``10 (no text)``."""
    assert _v171_text(v171, V171_RANGE_NODEF, b"\x0a\x00") == "10 (no text)"


def test_r_a2l_def_33_1_text_ended_by_a_nul(v171):
    """R-A2L-DEF.33/1 - ``Hello ASAM`` + 32 x 00 (base: 72)."""
    d = describe_definition(V171_ASCII, v171)
    res = _decoded(d, v171, _img(0x810200, b"Hello ASAM" + bytes(32)))
    assert (res.stored, res.value, res.text) == (None, "Hello ASAM", "Hello ASAM")


def test_r_a2l_def_33_2_case08_text(c08):
    """R-A2L-DEF.33/2 - ASCII_0001 decodes to the planned string."""
    d = describe_definition("ASCII_0001", c08["a2l"])
    planned = c08["by_name"]["ASCII_0001"]["raw_bytes"].split(b"\x00")[0].decode("ascii")
    assert planned and _decoded(d, c08["a2l"], c08["mem"]).text == planned


def test_r_a2l_def_33_3_text_with_no_nul(v171):
    """R-A2L-DEF.33/3 - 42 x ``A``."""
    d = describe_definition(V171_ASCII, v171)
    assert _decoded(d, v171, _img(0x810200, b"A" * 42)).text == "A" * 42


def test_r_a2l_def_34_1_control_byte_shows_as_u_fffd(v171):
    """R-A2L-DEF.34/1."""
    d = describe_definition(V171_ASCII, v171)
    data = b"AB\x07C" + bytes(38)
    assert _decoded(d, v171, _img(0x810200, data)).text == "AB" + FFFD + "C"


def test_r_a2l_def_34_2_bytes_above_0x7e_show_as_u_fffd(v171):
    """R-A2L-DEF.34/2 - C3 A9 (UTF-8 for e-acute) -> two U+FFFD (Latin-1 would give two letters)."""
    d = describe_definition(V171_ASCII, v171)
    data = b"\xc3\xa9" + bytes(40)
    assert _decoded(d, v171, _img(0x810200, data)).text == FFFD + FFFD


def _num(tmp_path, name: str, dt: str, fmt: str | None, raw: bytes, *, method: str | None = None,
         coeffs: tuple[str, ...] = (), cm_fmt: str = '"%.3"', big: bool = True):
    extra = [f'FORMAT "{fmt}"'] if fmt is not None else []
    blocks = []
    conv = "NO_COMPU_METHOD"
    if method:
        blocks.append(_cm("CM_X", method, *coeffs, fmt=cm_fmt))
        conv = "CM_X"
    blocks.append(_val(name, "0x10", LAYOUT[dt], conv, "-1e300" if dt.startswith("FLOAT") else "0",
                       "1e300" if dt.startswith("FLOAT") else "65535", *extra))
    a2l = _inline(tmp_path, *blocks, byte_order="MSB_FIRST" if big else "MSB_LAST")
    d = describe_definition(name, a2l)
    return _decoded(d, a2l, _img(0x10, raw))


def test_r_a2l_def_35_1_two_decimals(tmp_path):
    """R-A2L-DEF.35/1 - LINEAR 0.1, %4.2, stored 123 -> ``12.30``."""
    assert _num(tmp_path, "D1", "UWORD", "%4.2", bytes([0, 0x7B]), method="LINEAR", coeffs=("0.1", "0")).text == "12.30"


def test_r_a2l_def_35_2_zero_decimals_a_tie(tmp_path):
    """R-A2L-DEF.35/2 - FLOAT64 2.5 with %.0 -> ``2``."""
    assert _num(tmp_path, "D2", "FLOAT64_IEEE", "%.0", struct.pack(">d", 2.5)).text == "2"


def test_r_a2l_def_35_3_four_decimals(tmp_path):
    """R-A2L-DEF.35/3 - 3.14159 with %8.4 -> ``3.1416``."""
    assert _num(tmp_path, "D3", "FLOAT64_IEEE", "%8.4", struct.pack(">d", 3.14159)).text == "3.1416"


def test_r_a2l_def_35_4_exact_binary_tie(tmp_path):
    """R-A2L-DEF.35/4 - 0.125 with %.2 -> ``0.12``."""
    assert _num(tmp_path, "D4", "FLOAT64_IEEE", "%.2", struct.pack(">d", 0.125)).text == "0.12"


def test_r_a2l_def_35_5_fifteen_or_more_decimals_round_to_15_significant_digits(tmp_path):
    """R-A2L-DEF.35/5 - LINEAR 0.1 on stored 41 with %.15 -> ``4.100000000000000``."""
    res = _num(tmp_path, "D10", "UWORD", "%.15", bytes([0, 0x29]), method="LINEAR", coeffs=("0.1", "0"))
    assert res.text == "4.100000000000000"


def test_r_a2l_def_35_6_float32_at_15_decimals(tmp_path):
    """R-A2L-DEF.35/6 - FLOAT32 0.1 keeps its stored digits: ``0.100000001490116``."""
    res = _num(tmp_path, "D11", "FLOAT32_IEEE", "%.15", bytes.fromhex("3DCCCCCD"))
    assert res.text == "0.100000001490116"


def test_r_a2l_def_36_1_decimals_are_capped_at_17(tmp_path):
    """R-A2L-DEF.36/1 - %.40 on 0.1 -> 17 decimals."""
    assert _num(tmp_path, "D5", "FLOAT64_IEEE", "%.40", struct.pack(">d", 0.1)).text == "0.10000000000000000"


def test_r_a2l_def_37_1_no_format_gives_the_15_digit_text(tmp_path):
    """R-A2L-DEF.37/1 - format word ``""``: 0.30000000000000004 -> ``0.3``."""
    res = _num(tmp_path, "D6", "UWORD", None, bytes([0, 3]), method="LINEAR", coeffs=("0.1", "0"), cm_fmt='""')
    assert res.text == "0.3"


def test_r_a2l_def_37_2_percent_alone_gives_no_decimals(tmp_path):
    """R-A2L-DEF.37/2 - ``%`` on 1234567.0 -> ``1234567``."""
    assert _num(tmp_path, "D7", "FLOAT64_IEEE", "%", struct.pack(">d", 1234567.0)).text == "1234567"


def test_r_a2l_def_37_3_a_length_with_no_decimals(tmp_path):
    """R-A2L-DEF.37/3 - ``%12`` on 1e-07 -> ``1e-07``."""
    assert _num(tmp_path, "D8", "FLOAT64_IEEE", "%12", struct.pack(">d", 1e-07)).text == "1e-07"


def test_r_a2l_def_37_4_an_unreadable_format(tmp_path):
    """R-A2L-DEF.37/4 - ``x5.1`` on 12.5 -> ``12.5``."""
    assert _num(tmp_path, "D9", "FLOAT64_IEEE", "x5.1", struct.pack(">d", 12.5)).text == "12.5"


def test_r_a2l_def_38_1_integer_text_under_many_decimals(softa):
    """R-A2L-DEF.38/1 - software_a SWORD, NO_COMPU_METHOD, ``%.15``, FB FF -> ``-5``."""
    d = describe_definition("AlyjmQyfk.GrsaEjbkyQmicdevPjq_GpqJraTjkq._1_", softa)
    assert _decoded(d, softa, _word(d, bytes([0xFB, 0xFF]))).text == "-5"


def test_r_a2l_def_38_2_integer_text_of_an_identical_field(v171):
    """R-A2L-DEF.38/2 - the masked field 35 under ``%5.0`` -> ``35``."""
    d = describe_definition(V171_M0FF0, v171)
    assert _decoded(d, v171, _img(0x810002, bytes([0x34, 0x12]))).text == "35"


def _f1(tmp_path, raw_hex: str):
    return _num(tmp_path, "F1", "FLOAT32_IEEE", "%.2", bytes.fromhex(raw_hex))


def test_r_a2l_def_39_1_nan(tmp_path):
    """R-A2L-DEF.39/1."""
    assert _f1(tmp_path, "7FC00000").text == "nan"


def test_r_a2l_def_39_2_positive_infinity(tmp_path):
    """R-A2L-DEF.39/2."""
    assert _f1(tmp_path, "7F800000").text == "inf"


def test_r_a2l_def_39_3_negative_infinity(tmp_path):
    """R-A2L-DEF.39/3."""
    assert _f1(tmp_path, "FF800000").text == "-inf"


# ==========================================================================
# R-A2L-DEF.58.1, .58.2 (describe and decode arms), .137
# ==========================================================================


def _no_exception_triplet(d: Definition, a2l: dict, image: Mapping[int, int]):
    """Describe already ran; decode must give a Decoded or a Refusal, never raise."""
    res = decode_definition(d, a2l, image)
    assert isinstance(res, (Decoded, Refusal))
    return res


def _zero_image(defs) -> dict[int, int]:
    image: dict[int, int] = {}
    for d in defs:
        if d.address is not None and d.byte_length and 0 < d.byte_length <= 4096:
            image.update(_img(d.address, bytes(d.byte_length)))
    return image


def test_r_a2l_def_58_1_1_v171_and_its_image_are_unchanged(v171):
    """R-A2L-DEF.58.1/1 - build and decode every V171 object; payload and image unchanged."""
    before = copy.deepcopy(v171)
    defs = describe_definitions([t["name"] for t in v171["tags"]], v171)
    image = _zero_image(defs.values())
    image_before = dict(image)
    for d in defs.values():
        _no_exception_triplet(d, v171, image)
    assert v171 == before
    assert image == image_before
    for name in (V171_SWORD, V171_ENUM, V171_M0FF0, V171_ASCII):    # the objects really were built
        assert defs[name].refusal is None and isinstance(decode_definition(defs[name], v171, image), Decoded)


def test_r_a2l_def_58_1_2_case08_is_unchanged(c08):
    """R-A2L-DEF.58.1/2 - the same over case 08, with its real image."""
    a2l = c08["a2l"]
    before = copy.deepcopy(a2l)
    defs = describe_definitions([t["name"] for t in a2l["tags"]], a2l)
    for d in defs.values():
        _no_exception_triplet(d, a2l, c08["mem"])
    assert a2l == before
    built = [n for n in _defined_names(c08) if defs[n].refusal is None]
    assert len(built) == 322 and all(isinstance(decode_definition(defs[n], a2l, c08["mem"]), Decoded) for n in built)


def _enum_count_object(tmp_path, count: str):
    a2l = _inline(tmp_path, *_enum_blocks("CM_E", "VT_E", count, '0 "A"'), _val("EE", "0x10", "RL_U8", "CM_E"))
    d = describe_definition("EE", a2l)
    assert d.refusal is not None and d.refusal.code == "A2L-DEF-TABLE-EMPTY"
    assert d.refusal.message == "EE: the table VT_E has no entries"
    assert isinstance(decode_definition(d, a2l, {0x10: 0}), Refusal)


def test_r_a2l_def_58_2_1_count_1e400(tmp_path):
    """R-A2L-DEF.58.2/1."""
    _enum_count_object(tmp_path, "1e400")


def test_r_a2l_def_58_2_2_count_nan(tmp_path):
    """R-A2L-DEF.58.2/2."""
    _enum_count_object(tmp_path, "nan")


def test_r_a2l_def_58_2_3_count_minus_3(tmp_path):
    """R-A2L-DEF.58.2/3."""
    _enum_count_object(tmp_path, "-3")


def test_r_a2l_def_58_2_4_count_2_5(tmp_path):
    """R-A2L-DEF.58.2/4."""
    _enum_count_object(tmp_path, "2.5")


def test_r_a2l_def_58_2_5_a_5000_digit_decimal_mask_is_refused(tmp_path):
    """R-A2L-DEF.58.2/5 - int() of a 5,000-digit run raises ValueError on CPython; the model must refuse."""
    word = "1" * 5000
    a2l = _inline(tmp_path, _val("MX5", "0x10", "RL_U16", "NO_COMPU_METHOD", "0", "65535", f"BIT_MASK {word}"))
    d = describe_definition("MX5", a2l)
    assert d.refusal is not None and d.refusal.code == "A2L-DEF-MASK"
    assert isinstance(decode_definition(d, a2l, {0x10: 0, 0x11: 0}), Refusal)


def test_r_a2l_def_58_2_6_a_5000_digit_decimals_run_is_capped(tmp_path):
    """R-A2L-DEF.58.2/6 - %.<5000 digits> on 0.1 -> 17 decimals."""
    res = _num(tmp_path, "FD", "FLOAT64_IEEE", "%." + "1" * 5000, struct.pack(">d", 0.1))
    assert res.text == "0.10000000000000000"


def test_r_a2l_def_58_2_7_bit_mask_0xzz_is_refused(tmp_path):
    """R-A2L-DEF.58.2/7."""
    a2l = _inline(tmp_path, _val("MZ", "0x10", "RL_U16", "NO_COMPU_METHOD", "0", "65535", "BIT_MASK 0xZZ"))
    d = describe_definition("MZ", a2l)
    assert d.refusal is not None and d.refusal.code == "A2L-DEF-MASK"
    assert isinstance(decode_definition(d, a2l, {0x10: 0, 0x11: 0}), Refusal)


def test_r_a2l_def_58_2_8_number_minus_5(tmp_path):
    """R-A2L-DEF.58.2/8 - the definition refusal comes back from decode too."""
    a2l = _inline(tmp_path, _ascii("T8", "0x10", "-5"))
    d = describe_definition("T8", a2l)
    assert d.refusal is not None and d.refusal.code == "A2L-DEF-ADDRESS"
    assert decode_definition(d, a2l, {}) == d.refusal


def test_r_a2l_def_58_2_9_number_above_one_mib(tmp_path):
    """R-A2L-DEF.58.2/9 - a refusal, not a MemoryError."""
    a2l = _inline(tmp_path, _ascii("T9", "0x10", "1048577"))
    d = describe_definition("T9", a2l)
    assert d.refusal is not None and d.refusal.code == "A2L-DEF-ADDRESS"
    assert decode_definition(d, a2l, {}) == d.refusal


def test_r_a2l_def_58_2_10_negative_ecu_address(tmp_path):
    """R-A2L-DEF.58.2/10."""
    a2l = _inline(tmp_path, _meas("T10", "UWORD", addr="-0x10"))
    d = describe_definition("T10", a2l)
    assert d.refusal is not None and d.refusal.code == "A2L-DEF-ADDRESS"
    assert decode_definition(d, a2l, {}) == d.refusal


def test_r_a2l_def_58_2_11_non_finite_extended_limits(tmp_path):
    """R-A2L-DEF.58.2/11 (2a arm) - ``0 100`` and ``EXTENDED_LIMITS nan nan``: no extended limits."""
    a2l = _inline(tmp_path, _val("T11", "0x10", "RL_S16", "NO_COMPU_METHOD", "0", "100", "EXTENDED_LIMITS nan nan"))
    d = describe_definition("T11", a2l)
    assert d.extended_limits is None and (d.limits.lower, d.limits.upper) == (0, 100)
    assert d.kind == "number" and d.refusal is None


def test_r_a2l_def_58_2_12_non_finite_coefficients_read_as_missing(tmp_path):
    """R-A2L-DEF.58.2/12 - ``RAT_FUNC nan inf 0 0 0 1``: coefficients nan / inf are not numbers."""
    a2l = _inline(tmp_path, _cm("CM_N", "RAT_FUNC", "nan", "inf", "0", "0", "0", "1"), _val("T12", "0x10", "RL_U16", "CM_N"))
    d = describe_definition("T12", a2l)
    assert d.coeffs is not None and d.coeffs[0] is None and d.coeffs[1] is None
    assert list(d.coeffs[2:]) == [0.0, 0.0, 0.0, 1.0]
    _no_exception_triplet(d, a2l, {0x10: 0, 0x11: 5})


def test_r_a2l_def_58_2_13_all_zero_rat_func(tmp_path):
    """R-A2L-DEF.58.2/13 (2a arm) - describe and decode of ``RAT_FUNC 0 0 0 0 0 0`` raise nothing."""
    a2l = _inline(tmp_path, _cm("CM_Z", "RAT_FUNC", "0", "0", "0", "0", "0", "0"), _val("T13", "0x10", "RL_U16", "CM_Z"))
    d = describe_definition("T13", a2l)
    assert d.coeffs == (0.0, 0.0, 0.0, 0.0, 0.0, 0.0) and d.conversion_type == "RAT_FUNC"
    _no_exception_triplet(d, a2l, {0x10: 0, 0x11: 3})


def test_r_a2l_def_58_2_14_esc_and_unterminated_quote_in_an_entry_text(tmp_path):
    """R-A2L-DEF.58.2/14 - ESC shows as U+FFFD; no exception on an unterminated quote."""
    pairs = ('0 "A\x1bB', )
    a2l = _inline(tmp_path, *_enum_blocks("CM_Q", "VT_Q", "1", *pairs), _val("T14", "0x10", "RL_U8", "CM_Q"))
    d = describe_definition("T14", a2l)
    assert d.kind == "enum" and d.refusal is None
    assert d.enum_entries[0].text == "AB"          # unterminated quote read to the end of the line; raw text kept
    res = _no_exception_triplet(d, a2l, {0x10: 0})
    assert isinstance(res, Decoded) and res.text == "A" + FFFD + "B"


def test_r_a2l_def_58_2_15_v171_unclosed_begin(v171):
    """R-A2L-DEF.58.2/15 - V171 parses with 'Unclosed /begin'; every object still describes and decodes."""
    assert v171["errors"]
    defs = describe_definitions([t["name"] for t in v171["tags"]], v171)
    image = _zero_image(defs.values())
    for d in defs.values():
        _no_exception_triplet(d, v171, image)
        _no_exception_triplet(d, v171, {})
    assert defs[V171_SWORD].refusal is None and isinstance(decode_definition(defs[V171_SWORD], v171, image), Decoded)


def test_r_a2l_def_58_2_16_float_enum_with_a_non_finite_stored_value(tmp_path):
    """R-A2L-DEF.58.2/16 - inf and nan on a FLOAT32 enum with no default."""
    a2l = _inline(tmp_path, *_enum_blocks("CM_F", "VT_F", "1", '0 "Zero"'), _val("EF", "0x10", "RL_F32", "CM_F"))
    d = describe_definition("EF", a2l)
    assert _decoded(d, a2l, _img(0x10, bytes.fromhex("7F800000"))).text == "inf (no text)"
    assert _decoded(d, a2l, _img(0x10, bytes.fromhex("7FC00000"))).text == "nan (no text)"


def test_r_a2l_def_58_2_17_masked_object_with_no_datatype(tmp_path):
    """R-A2L-DEF.58.2/17 - DATATYPE first, no KeyError from the mask check."""
    rl = '/begin RECORD_LAYOUT RL_X\n  FNC_VALUES 1 FOO ROW_DIR DIRECT\n/end RECORD_LAYOUT'
    a2l = _inline(tmp_path, rl, _val("ND", "0x10", "RL_X", "NO_COMPU_METHOD", "0", "65535", "LENGTH 2", "BIT_MASK 0x0FF0"))
    d = describe_definition("ND", a2l)
    _is_refused(d, "A2L-DEF-DATATYPE", "ND: the object declares no datatype the system can read")
    assert decode_definition(d, a2l, {}) == d.refusal


def _vtab_nul(tmp_path, name: str, text: str, tab: str):
    a2l = _inline(tmp_path, *_enum_blocks("CM_C", tab, "1", f'0 "{text}"'), _val(name, "0x10", "RL_U8", "CM_C"))
    d = describe_definition(name, a2l)
    return _decoded(d, a2l, _img(0x10, b"\x00"))


def test_r_a2l_def_137_1_nul_in_an_enum_text(tmp_path):
    """R-A2L-DEF.137/1 - NUL in the entry text shows as U+FFFD."""
    assert _vtab_nul(tmp_path, "N1", "A\x00B", "VT_C1").text == "A" + FFFD + "B"


def test_r_a2l_def_137_2_esc_in_an_enum_text(tmp_path):
    """R-A2L-DEF.137/2 - ESC in the entry text shows as U+FFFD."""
    assert _vtab_nul(tmp_path, "N2", "A\x1b[2J", "VT_C2").text == "A" + FFFD + "[2J"


def test_r_a2l_def_137_3_nul_in_a_name(v171):
    """R-A2L-DEF.137/3 - the message echoes the name with U+FFFD."""
    d = describe_definition("AB\x00C", v171)
    _is_refused(d, "A2L-DEF-NAME", "AB" + FFFD + "C: no tag of that name in the A2L")


def test_r_a2l_def_137_4_esc_in_a_name(v171):
    """R-A2L-DEF.137/4."""
    d = describe_definition("AB\x1bC", v171)
    _is_refused(d, "A2L-DEF-NAME", "AB" + FFFD + "C: no tag of that name in the A2L")


# ==========================================================================
# describe_definitions agrees with describe_definition (R-A2L-DEF.136 identity half)
# ==========================================================================


def test_r_a2l_def_136_1_batch_describe_equals_per_name_describe(v171, c08):
    """R-A2L-DEF.136/1 (identity half) - one walk gives what the per-name call gives, on V171 and case 08."""
    for a2l in (v171, c08["a2l"]):
        names = [t["name"] for t in a2l["tags"]]
        batch = describe_definitions(names, a2l)
        assert set(batch) == set(names)
        for n in names[:60]:
            assert batch[n] == describe_definition(n, a2l)
    assert describe_definitions([V171_SWORD], v171)[V171_SWORD].kind == "number"
    assert describe_definitions(["NO_SUCH_TAG"], v171)["NO_SUCH_TAG"].refusal.code == "A2L-DEF-NAME"


# ==========================================================================
# Cited canon rows - the model must meet them (describe / decode arms)
# ==========================================================================


def test_r_a2l_010_def_1_address_from_a_characteristic_header(v171):
    """R-A2L-010/def-1."""
    assert describe_definition(V171_SWORD, v171).address == 0x810004


def test_r_a2l_011_def_1_address_from_ecu_address(v171):
    """R-A2L-011/def-1."""
    assert describe_definition("ASAM.M.SCALAR.UBYTE.IDENTICAL", v171).address == 0x13A00


def test_r_a2l_014_def_1_length_from_the_datatype_when_the_tag_lacks_it(tube):
    """R-A2L-014/def-1 - TUBE sm: byte length 1, UBYTE (base: None)."""
    d = describe_definition("model.MainClass.gameController.sm", tube)
    assert d.byte_length == 1 and d.datatype == "UBYTE"


def test_r_a2l_022_def_1_datatype_from_the_record_layout(v171):
    """R-A2L-022/def-1."""
    assert describe_definition(V171_SWORD, v171).datatype == "SWORD"


def test_r_a2l_023_def_1_datatype_the_deposit_name_spells(tmp_path):
    """R-A2L-023/def-1 - deposit ``__SWORD_Z``; FF FB big-endian -> -5 (the tag table reads UWORD)."""
    rl = '/begin RECORD_LAYOUT __SWORD_Z\n  ALIGNMENT_BYTE 1\n/end RECORD_LAYOUT'
    a2l = _inline(tmp_path, rl, _val("DS", "0x10", "__SWORD_Z", "NO_COMPU_METHOD", "-32768", "32767"))
    d = describe_definition("DS", a2l)
    assert d.datatype == "SWORD"
    assert _decoded(d, a2l, _img(0x10, bytes([0xFF, 0xFB]))).text == "-5"


def test_r_a2l_024_def_1_byte_order_of_the_tag(c08):
    """R-A2L-024/def-1 - VALUE_0001 MSB_FIRST."""
    assert describe_definition("VALUE_0001", c08["a2l"]).byte_order == "big"


def test_r_a2l_025_def_1_byte_order_of_the_record_layout(tmp_path):
    """R-A2L-025/def-1 - RL_BL with BYTE_ORDER MSB_LAST under a big-endian MOD_COMMON."""
    rl = '/begin RECORD_LAYOUT RL_BL\n  FNC_VALUES 1 UWORD ROW_DIR DIRECT\n  BYTE_ORDER MSB_LAST\n/end RECORD_LAYOUT'
    a2l = _inline(tmp_path, rl, _val("BL", "0x10", "RL_BL"), _val("PL", "0x20", "RL_U16"))
    assert describe_definition("BL", a2l).byte_order == "little"
    assert describe_definition("PL", a2l).byte_order == "big"    # control: no layout BYTE_ORDER


def test_r_a2l_026_def_1_byte_order_of_mod_common(v171, tmp_path):
    """R-A2L-026/def-1 - V171 MSB_LAST gives little; an MSB_FIRST MOD_COMMON gives big."""
    assert describe_definition(V171_SWORD, v171).byte_order == "little"
    big = _inline(tmp_path, _val("BG", "0x10", "RL_U16"), byte_order="MSB_FIRST")
    assert describe_definition("BG", big).byte_order == "big"


def test_r_a2l_027_def_1_default_byte_order(tmp_path):
    """R-A2L-027/def-1 - no BYTE_ORDER anywhere: little."""
    a2l = _inline(tmp_path, _val("DB", "0x10", "RL_U16"), byte_order=None)
    assert describe_definition("DB", a2l).byte_order == "little"
    big = _inline(tmp_path, _val("BG", "0x10", "RL_U16"), byte_order="MSB_FIRST")
    assert describe_definition("BG", big).byte_order == "big"    # control: the default is not a constant


def test_r_a2l_030_def_1_phys_unit(softa):
    """R-A2L-030/def-1 - PHYS_UNIT "V" (base: tag unit None)."""
    assert describe_definition("BcpGxvlbvneyoAudnMhl.DRCDJ_XNIFM_DSURLVD_VSJMQJBMW", softa).unit == "V"


def test_r_a2l_030_def_2_a_unit_with_a_space(tmp_path):
    """R-A2L-030/def-2."""
    a2l = _inline(tmp_path, _val("PU", "0x10", "RL_U16", "NO_COMPU_METHOD", "0", "65535", 'PHYS_UNIT "deg C"'))
    assert describe_definition("PU", a2l).unit == "deg C"


def test_r_a2l_031_def_1_the_methods_unit(v171):
    """R-A2L-031/def-1 - no PHYS_UNIT; CM.IDENTICAL unit ``hours``."""
    assert describe_definition(V171_UBYTE, v171).unit == "hours"


def test_r_a2l_033_def_1_unit_on_the_begin_line(tmp_path):
    """R-A2L-033/def-1 - ``/begin COMPU_METHOD CM_B "d" LINEAR "%.1" "km/h"``."""
    cm = '/begin COMPU_METHOD CM_B "d" LINEAR "%.1" "km/h"\n  COEFFS_LINEAR 1 0\n/end COMPU_METHOD'
    a2l = _inline(tmp_path, cm, _val("UB", "0x10", "RL_U16", "CM_B"))
    d = describe_definition("UB", a2l)
    assert d.unit == "km/h" and d.display_format == "%.1"


def test_r_a2l_040_def_1_raw_bytes_are_read_from_the_image(v171):
    """R-A2L-040/def-1 - 34 12 at 0x810004 -> stored 4660."""
    d = describe_definition(V171_SWORD, v171)
    assert _decoded(d, v171, _img(0x810004, bytes([0x34, 0x12]))).stored == 4660


def test_r_a2l_043_def_1_byte_order_of_the_read(tmp_path):
    """R-A2L-043/def-1 - big-endian 12 34 -> 4660."""
    a2l = _inline(tmp_path, _val("BE", "0x10", "RL_U16"))
    assert _decoded(describe_definition("BE", a2l), a2l, _img(0x10, bytes([0x12, 0x34]))).stored == 4660


def test_r_a2l_044_def_1_twos_complement(v171):
    """R-A2L-044/def-1 - FB FF -> -5."""
    d = describe_definition(V171_SWORD, v171)
    assert _decoded(d, v171, _img(0x810004, bytes([0xFB, 0xFF]))).text == "-5"


def test_r_a2l_045_def_1_float16(tmp_path):
    """R-A2L-045/def-1 - 3C 00 -> 1.0 (base: no value)."""
    a2l = _inline(tmp_path, _val("H1", "0x10", "RL_F16", "NO_COMPU_METHOD", "-100", "100"))
    assert _decoded(describe_definition("H1", a2l), a2l, _img(0x10, bytes([0x3C, 0x00]))).value == 1.0


def test_r_a2l_045_def_2_float32(tmp_path):
    """R-A2L-045/def-2 - 3F C0 00 00 -> 1.5."""
    a2l = _inline(tmp_path, _val("H2", "0x10", "RL_F32", "NO_COMPU_METHOD", "-100", "100"))
    assert _decoded(describe_definition("H2", a2l), a2l, _img(0x10, bytes([0x3F, 0xC0, 0, 0]))).value == 1.5


def test_r_a2l_045_def_3_float64(tmp_path):
    """R-A2L-045/def-3 - -2.25."""
    a2l = _inline(tmp_path, _val("H3", "0x10", "RL_F64", "NO_COMPU_METHOD", "-100", "100"))
    assert _decoded(describe_definition("H3", a2l), a2l, _img(0x10, struct.pack(">d", -2.25))).value == -2.25


def test_r_a2l_051_def_1_no_compu_method(tmp_path):
    """R-A2L-051/def-1 - UBYTE 07 -> 7."""
    a2l = _inline(tmp_path, _val("NC", "0x10", "RL_U8", "NO_COMPU_METHOD", "0", "255"))
    assert _decoded(describe_definition("NC", a2l), a2l, {0x10: 7}).value == 7


def test_r_a2l_053_def_1_identical(v171):
    """R-A2L-053/def-1 - 07 00 -> 7."""
    d = describe_definition(V171_SWORD, v171)
    res = _decoded(d, v171, _img(0x810004, bytes([7, 0])))
    assert res.value == 7 and res.text == "7"


def test_r_a2l_054_def_1_linear(c08):
    """R-A2L-054/def-1 - the first CM_LIN_OFF object decodes to its planned physical value."""
    o = _first(c08, "CM_LIN_OFF")
    res = _decoded(describe_definition(o["name"], c08["a2l"]), c08["a2l"], c08["mem"])
    _planned_close(res, o["physical"])


def test_r_a2l_055_def_1_linear_with_b_missing(tmp_path):
    """R-A2L-055/def-1 - COEFFS_LINEAR 2 on stored 3 -> 6.0."""
    a2l = _inline(tmp_path, _cm("CM_L2", "LINEAR", "2"), _val("LB", "0x10", "RL_U16", "CM_L2"))
    d = describe_definition("LB", a2l)
    assert d.coeffs_linear == (2.0, None)
    assert _decoded(d, a2l, _img(0x10, bytes([0, 3]))).value == 6.0


def test_r_a2l_056_def_1_rat_func(c08):
    """R-A2L-056/def-1 - the first CM_RAT object decodes to its planned physical value."""
    o = _first(c08, "CM_RAT")
    res = _decoded(describe_definition(o["name"], c08["a2l"]), c08["a2l"], c08["mem"])
    _planned_close(res, o["physical"])


def test_r_a2l_057_def_1_root_inside_the_limits(tmp_path):
    """R-A2L-057/def-1 - raw = p^2, limits 0..10, stored 9 -> 3.0."""
    a2l = _inline(tmp_path, _cm("CM_S", "RAT_FUNC", "1", "0", "0", "0", "0", "1"),
                  _val("SQ", "0x10", "RL_U16", "CM_S", "0", "10"))
    assert _decoded(describe_definition("SQ", a2l), a2l, _img(0x10, bytes([0, 9]))).value == 3.0


def test_r_a2l_058_1_def_1_no_solution_message(tmp_path):
    """R-A2L-058.1/def-1 - as R-A2L-DEF.28/1."""
    _d, res = _rat(tmp_path, "R1", "0 0 5 0 0 1", bytes([0, 7]))
    assert isinstance(res, Refusal) and res.message == "R1: RAT_FUNC has no solution for this value"


def test_r_a2l_058_2_def_1_no_real_root_message(tmp_path):
    """R-A2L-058.2/def-1 - as R-A2L-DEF.28/2."""
    _d, res = _rat(tmp_path, "R2", "1 0 1 0 0 1", bytes([0, 0]))
    assert isinstance(res, Refusal) and res.message == "R2: RAT_FUNC has no real root for this value"


def test_r_a2l_058_3_def_1_zero_denominator_message(tmp_path):
    """R-A2L-058.3/def-1 - as R-A2L-DEF.28/3."""
    _d, res = _rat(tmp_path, "R3", "0 1 1 0 1 1", bytes([0, 2]))
    assert isinstance(res, Refusal) and res.message == "R3: RAT_FUNC root has a zero denominator"


def test_r_a2l_059_def_1_compu_vtab_text(v171):
    """R-A2L-059/def-1 - raw 2 -> ``Square`` (base: raw 2, unknown method)."""
    d = describe_definition(V171_ENUM, v171)
    res = _decoded(d, v171, _img(0x810004, bytes([2, 0])))
    assert (res.stored, res.value, res.text) == (2, "Square", "Square")


def test_r_a2l_059_def_2_text_of_a_masked_enum(tmp_path):
    """R-A2L-059/def-2 - UWORD enum, mask 0x00F0, word 00 10 -> ON."""
    a2l = _inline(tmp_path, *_enum_blocks("CM_M", "VT_M", "2", '0 "OFF"', '1 "ON"'),
                  _val("ME", "0x10", "RL_U16", "CM_M", "0", "65535", "BIT_MASK 0x00F0"))
    assert _decoded(describe_definition("ME", a2l), a2l, _img(0x10, bytes([0x00, 0x10]))).text == "ON"


def test_r_a2l_061_def_1_tab_intp(c08):
    """R-A2L-061/def-1 - the first CM_TAB_INTP object decodes to its planned value."""
    o = _first(c08, "CM_TAB_INTP")
    res = _decoded(describe_definition(o["name"], c08["a2l"]), c08["a2l"], c08["mem"])
    _planned_close(res, o["physical"])


def _with_raw(c08: dict, o: dict, raw: int) -> dict[int, int]:
    image = dict(c08["mem"])
    size = _SIZES[o["datatype"]]
    image.update(_img(o["address"], raw.to_bytes(size, "big" if o["big_endian"] else "little")))
    return image


def test_r_a2l_062_def_1_tab_intp_outside_the_table(c08):
    """R-A2L-062/def-1 - stored 500 -> 40.0 (the last table point)."""
    o = _first(c08, "CM_TAB_INTP")
    d = describe_definition(o["name"], c08["a2l"])
    assert _decoded(d, c08["a2l"], _with_raw(c08, o, 500)).value == 40.0


def test_r_a2l_063_def_1_tab_nointp_nearest(c08):
    """R-A2L-063/def-1 - stored 6 -> 20.0 (raw 4 is nearest)."""
    o = _first(c08, "CM_TAB_NOINTP")
    d = describe_definition(o["name"], c08["a2l"])
    assert _decoded(d, c08["a2l"], _with_raw(c08, o, 6)).value == 20.0


# ==========================================================================
# display_text (the one number display rule), direct
# ==========================================================================


def test_r_a2l_def_39_4_display_text_of_non_finite_values_direct(v171):
    """R-A2L-DEF.39 - ``display_text`` itself gives nan / inf / -inf for any definition."""
    d = describe_definition("ASAM.C.SCALAR.FLOAT64_IEEE.IDENTICAL", v171)
    assert [display_text(d, v) for v in (float("nan"), float("inf"), float("-inf"))] == ["nan", "inf", "-inf"]


# ==========================================================================
# Acceptance cases
# ==========================================================================


def test_at_b103_i2_1_asam_demo_scalar_kinds_decode_to_the_text_the_a2l_gives(v171):
    """AT-B103-I2-1 (2a arm) - the ten V171 objects: build and decode over the demo image.

    Rows .2, .3, .14, .15, .27, .30, .33 and cited R-A2L-059. The encode, apply
    and re-decode arm and the seven A2L-DEF-OVERLAP refusals wait for 2b.
    """
    image: dict[int, int] = {}
    image.update(_img(0x810000, bytes([0, 0])))                    # UBYTE, SBYTE
    image.update(_img(0x810002, bytes([0x34, 0x12])))              # the UWORD word 0x1234
    image.update(_img(0x810004, bytes([2, 0])))                    # the SWORD
    image.update(_img(0x810200, b"Hello ASAM" + bytes(32)))        # the ASCII object
    expected = {
        V171_ENUM: "Square",
        V171_ENUM_NODEF: "red",
        V171_RANGE: "two_to_three",
        V171_M0FF0: "35",
        V171_M0001: "0",
        V171_M0010: "1",
        V171_ASCII: "Hello ASAM",
        V171_SBYTE: "0",
        V171_UBYTE: "0",
        V171_SWORD: "2",
    }
    for name, text in expected.items():
        d = describe_definition(name, v171)
        assert d.refusal is None, (name, d.refusal)
        res = _decoded(d, v171, image)
        assert res.text == text, (name, res.text)


def _defined_names(c08: dict) -> list[str]:
    return [o["name"] for o in c08["objs"] if o["kind"] in ("VALUE", "MEASUREMENT", "ASCII")]


def test_at_b103_i2_3_case08_builds_and_decodes_with_the_model(c08):
    """AT-B103-I2-3 - case 08 clean and issues, built and decoded; the 11 files of the 1 MiB case equal the pin.

    The 10 MiB half of the 22-file pin is R-A2L-DEF.59/2 (slow).
    """
    names = _defined_names(c08)
    assert len(names) == 322
    a2l, mem = c08["a2l"], c08["mem"]
    for name in names:
        o = c08["by_name"][name]
        d = describe_definition(name, a2l)
        assert d.refusal is None, (name, d.refusal)
        res = _decoded(d, a2l, mem)
        if o["kind"] == "ASCII":
            assert res.text == o["raw_bytes"].split(b"\x00")[0].decode("ascii"), name
        else:
            _planned_close(res, o["physical"])

    issues = c08["issues"]
    refused = []
    undefined_kinds = ("VAL_BLK", "CURVE", "MAP")        # outside the defined objects (R-A2L-DEF.4)
    for n in sorted({t["name"] for t in issues["tags"] if t.get("char_type") not in undefined_kinds}):
        d = describe_definition(n, issues)
        res = decode_definition(d, issues, mem)
        if isinstance(res, Refusal):
            refused.append(res)
    codes = sorted(r.code for r in refused)
    assert codes.count("A2L-DEF-METHOD") == 1 and codes.count("A2L-DEF-NAME") == 1
    assert codes.count("A2L-DEF-BYTES") == 5 and len(codes) == 7
    msgs = {r.message for r in refused}
    assert "MISSING_CM: the conversion method CM_MISSING is not declared in the A2L" in msgs
    assert "VALUE_0001: the A2L declares that name more than once" in msgs
    assert "SPAN_OVER_1: 2 of its 4 bytes are not in the image" in msgs
    assert "SPAN_OVER_2: 3 of its 4 bytes are not in the image" in msgs
    for i in (1, 2, 3):
        assert f"OUT_OF_RANGE_{i}: 1 of its 1 bytes are not in the image" in msgs

    from tests.test_b103_synth_definitions import CASE08_PIN_1MIB, case08_file_digests

    assert case08_file_digests(c08["dir"]) == CASE08_PIN_1MIB


# --------------------------------------------------------------------------
# E5 gap pass 2 (independent tester).  R-A2L-DEF.149/5 (immutability of every stored form),
# .150/6 and .150/9 (the reduced lookups equal the linear / frozen ones), .151/1 ... /3 (the echo
# of a file word in a refusal message), .58.2/18 and /19 (a refusal, not an exception).
# The timed cases .149/6 ... /10 and .150/1 ... /5, /7, /8 are in test_b103_a2l_definition_perf.py.
#
# Private names are used only where the case itself names them (.149/5, .150/6, .150/9): they are
# read through ``defmod`` at call time so that a module without them fails those cases alone.
# --------------------------------------------------------------------------

import dataclasses  # noqa: E402
import math  # noqa: E402
import re  # noqa: E402
from types import MappingProxyType  # noqa: E402

import s19_app.tui.a2l_definition as defmod  # noqa: E402
from s19_app.tui.a2l import parse_begin_meta  # noqa: E402

ELLIPSIS = "…"


def _echo256(word: str) -> str:
    """Test-local statement of R-A2L-DEF.151: the first 256 characters, each outside U+0021 ... U+007E written as
    U+FFFD, and an ellipsis after them when the word is longer."""
    body = "".join(c if "!" <= c <= "~" else FFFD for c in word[:256])
    return body + (ELLIPSIS if len(word) > 256 else "")


def _ctab(name: str, kind: str, *pairs: str) -> str:
    """A COMPU_TAB; each pair is the raw ``x y`` line text."""
    body = [f'/begin COMPU_TAB {name} "" {kind} {len(pairs)}']
    body += [f"  {p}" for p in pairs]
    body.append("/end COMPU_TAB")
    return "\n".join(body)


def _vrange(name: str, count: str, *triples: str, default: str | None = None) -> str:
    """A COMPU_VTAB_RANGE; each triple is the raw ``min max "text"`` line text."""
    body = [f'/begin COMPU_VTAB_RANGE {name} "" {count}']
    body += [f"  {t}" for t in triples]
    if default is not None:
        body.append(f'  DEFAULT_VALUE "{default}"')
    body.append("/end COMPU_VTAB_RANGE")
    return "\n".join(body)


def _name_maps(a2l: dict) -> tuple[dict, dict]:
    """The first COMPU_METHOD and the first COMPU_VTAB / COMPU_VTAB_RANGE of each name (what a walk builds)."""
    methods: dict = {}
    tables: dict = {}

    def walk(nodes):
        for node in nodes:
            nm = node.get("name")
            if nm == "COMPU_METHOD":
                methods.setdefault(parse_begin_meta(node.get("meta", "") or "")[0], node)
            elif nm in ("COMPU_VTAB", "COMPU_VTAB_RANGE"):
                tables.setdefault(parse_begin_meta(node.get("meta", "") or "")[0], node)
            walk(node.get("children") or [])

    walk(a2l.get("sections") or [])
    return methods, tables


def _method_record(a2l: dict, name: str, reads: dict, methods: dict | None = None):
    """``_read_method_record`` with the arguments of I-2's graph."""
    found_methods, tables = _name_maps(a2l)
    return defmod._read_method_record(name, methods if methods is not None else found_methods, tables,
                                      a2l.get("compu_tabs_by_name") or {}, reads)


# ---- the immutability walker (.149/5) -------------------------------------------------------

_SCALARS = (str, int, float, bool, type(None))


def _assert_frozen_tree(value, path: str, seen: set | None = None) -> int:
    """Every value is a scalar, a tuple, a frozen dataclass or a MappingProxyType of these, and a write into each
    container raises.  Returns the number of containers visited."""
    seen = set() if seen is None else seen
    if isinstance(value, _SCALARS):
        return 0
    if id(value) in seen:
        return 0
    seen.add(id(value))
    count = 1
    if isinstance(value, tuple):
        if value:
            with pytest.raises(TypeError):
                value[0] = value[0]                                  # type: ignore[index]
        for i, item in enumerate(value):
            count += _assert_frozen_tree(item, f"{path}[{i}]", seen)
        return count
    if isinstance(value, MappingProxyType):
        with pytest.raises(TypeError):
            value["__new_key__"] = 1                                 # type: ignore[index]
        for key, item in value.items():
            assert isinstance(key, _SCALARS), f"{path}: key {key!r}"
            count += _assert_frozen_tree(item, f"{path}[{key!r}]", seen)
        return count
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        assert value.__dataclass_params__.frozen, f"{path}: {type(value).__name__} is not frozen"
        fields = dataclasses.fields(value)
        if fields:
            with pytest.raises(AttributeError):
                setattr(value, fields[0].name, getattr(value, fields[0].name))
        for f in fields:
            count += _assert_frozen_tree(getattr(value, f.name), f"{path}.{f.name}", seen)
        return count
    pytest.fail(f"{path}: a {type(value).__name__} is a mutable or unlisted container")


def test_r_a2l_def_149_5_cached_read_form_is_immutable(tmp_path):
    """R-A2L-DEF.149/5 (E5 gap pass 2) - every stored form is immutable, the enum / table forms and their indexes included.

    Eight objects share four methods and three tables.  Writes into the method record, the enum forms, the table form,
    their tuples and index and a Definition all raise; the objects described together equal those described alone, in
    either order; each decodes as it decodes alone; the two objects of a table hold the same form object.
    """
    names = ["OBJ_A", "OBJ_B", "LIN_A", "LIN_B", "TAB_A", "TAB_B", "RNG_A", "RNG_B"]
    a2l = _inline(
        tmp_path,
        *_enum_blocks("CM_E", "VT_E", "2", '0 "off"', '1 "on"', default="none"),
        _cm("CM_R", "TAB_VERB", fmt='"%.0"', ref="VR_E"),
        _vrange("VR_E", "2", '0 1 "lo"', '2 3 "hi"'),
        _cm("CM_LIN", "LINEAR", "0.5", "2"),
        _cm("CM_T", "TAB_NOINTP", fmt='"%.0"', ref="CT_T"),
        _ctab("CT_T", "TAB_NOINTP", "0 10", "1 20"),
        _val("OBJ_A", "0x2000", LAYOUT["UBYTE"], "CM_E", "0", "1"),
        _val("OBJ_B", "0x2001", LAYOUT["UBYTE"], "CM_E", "0", "1"),
        _val("LIN_A", "0x2002", LAYOUT["UBYTE"], "CM_LIN", "0", "255"),
        _val("LIN_B", "0x2003", LAYOUT["UBYTE"], "CM_LIN", "0", "255"),
        _val("RNG_A", "0x2004", LAYOUT["UBYTE"], "CM_R", "0", "3"),
        _val("RNG_B", "0x2005", LAYOUT["UBYTE"], "CM_R", "0", "3"),
        _val("TAB_A", "0x2006", LAYOUT["UBYTE"], "CM_T", "0", "255"),
        _val("TAB_B", "0x2007", LAYOUT["UBYTE"], "CM_T", "0", "255"),
    )
    image = {0x2000 + i: 1 for i in range(8)}
    expect = {"OBJ": "on", "RNG": "lo", "LIN": "2.500", "TAB": "20"}

    fresh = {n: describe_definition(n, a2l) for n in names}
    for order in (names, list(reversed(names))):
        together = describe_definitions(order, a2l)
        assert {n: together[n] for n in names} == fresh
    together = describe_definitions(names, a2l)
    assert describe_definitions(names, a2l) == together                        # a second walk
    for n in names:                                                            # decodes as it decodes alone
        assert decode_definition(together[n], a2l, image) == decode_definition(fresh[n], a2l, image)
        assert _decoded(together[n], a2l, image).text == expect[n[:3]], n

    # the two objects of a table hold the same form
    for a, b in (("OBJ_A", "OBJ_B"), ("RNG_A", "RNG_B"), ("TAB_A", "TAB_B")):
        assert together[a]._table_form is not None and together[a]._table_form is together[b]._table_form
    assert together["LIN_A"]._table_form is None

    # CR-7 / P-2: the two private fields change neither equality nor repr nor the decode (I-2's public surface)
    for n in ("OBJ_A", "RNG_A", "TAB_A", "LIN_A"):
        full = together[n]
        bare = dataclasses.replace(full, _name_echo=None, _table_form=None)
        assert full == bare, n                                                 # compare=False
        assert "_table_form" not in repr(full) and "_name_echo" not in repr(full), n      # repr=False
        assert decode_definition(bare, a2l, image) == decode_definition(full, a2l, image), n
        assert _decoded(bare, a2l, image).text == expect[n[:3]], n

    # the public pieces: tuples, frozen entries, frozen definitions
    a = together["OBJ_A"]
    with pytest.raises((TypeError, AttributeError)):
        a.enum_entries[0] = a.enum_entries[1]                                  # type: ignore[index]
    with pytest.raises(AttributeError):
        a.enum_entries[0].text = "changed"                                     # type: ignore[misc]
    with pytest.raises(AttributeError):
        a.unit = "changed"                                                     # type: ignore[misc]
    with pytest.raises(AttributeError):
        a._table_form = None                                                   # type: ignore[misc]

    # the forms the walk stores: each walks as an immutable tree and refuses every write
    methods, tables = _name_maps(a2l)
    reads: dict = {}
    for method in ("CM_E", "CM_R", "CM_LIN", "CM_T"):
        record = _method_record(a2l, method, reads)
        with pytest.raises(TypeError):
            record["unit"] = "changed"                                         # a field
        with pytest.raises(TypeError):
            record["a_new_key"] = 1                                            # a new key
        assert _assert_frozen_tree(record, f"record[{method}]") >= 1
    for table in ("VT_E", "VR_E"):
        form = defmod._read_enum_table(table, tables, {})
        assert _assert_frozen_tree(form, f"enum form[{table}]") >= 3
    enum_form, range_form = together["OBJ_A"]._table_form, together["RNG_A"]._table_form
    tab_form = together["TAB_A"]._table_form
    for form in (enum_form, range_form, tab_form):
        with pytest.raises(AttributeError):
            setattr(form, dataclasses.fields(form)[0].name, "changed")
        assert _assert_frozen_tree(form, type(form).__name__) >= 2
    # the COMPU_VTAB index is a read-only mapping; the range index and the table's x / y are tuples
    assert any(isinstance(getattr(enum_form, f.name), MappingProxyType) for f in dataclasses.fields(enum_form))
    assert any(isinstance(getattr(range_form, f.name), tuple) and len(getattr(range_form, f.name)) >= 2
               for f in dataclasses.fields(range_form))
    for definition in together.values():
        assert _assert_frozen_tree(definition, f"definition {definition.name}") >= 1
    # nothing the writes touched changed for a second object, a new walk or the parsed payload
    assert describe_definitions(names, a2l) == together
    assert together["LIN_A"].coeffs_linear == (0.5, 2.0)
    assert {n: describe_definition(n, a2l) for n in names} == fresh


# ---- .58.2/18, /19 : a refusal, not an exception -----------------------------------------------

def test_r_a2l_def_58_2_18_a_table_conversion_that_gives_a_text_is_refused(tmp_path):
    """R-A2L-DEF.58.2/18 (E3S3-28) - a VALUE whose TAB_NOINTP / TAB_INTP method names a COMPU_VTAB decodes to a refusal, not an exception."""
    a2l = _inline(
        tmp_path,
        _vtab("VT_X", "2", '0 "OFF"', '1 "ON"'),
        _cm("CM_XN", "TAB_NOINTP", fmt='"%.0"', ref="VT_X"),
        _cm("CM_XI", "TAB_INTP", fmt='"%.0"', ref="VT_X"),
        _val("XN", "0x10", LAYOUT["UBYTE"], "CM_XN", "0", "255"),
        _val("XI", "0x11", LAYOUT["UBYTE"], "CM_XI", "0", "255"),
    )
    image = {0x10: 0x01, 0x11: 0x00}
    for name in ("XN", "XI"):
        d = describe_definition(name, a2l)
        assert d.kind == "number" and d.refusal is None, (name, d.refusal)
        result = decode_definition(d, a2l, image)                     # 0 exceptions
        assert result == Refusal("A2L-DEF-DECODE", f"{name}: the table VT_X gives a value that is not a number"), result


def test_r_a2l_def_58_2_19_a_compu_tab_whose_x_holds_a_nan_is_refused(tmp_path):
    """R-A2L-DEF.58.2/19 (E3S3-29) - a COMPU_TAB with a NaN x decodes to a refusal; the frozen parse's unordered sort never gives a value."""
    a2l = _inline(
        tmp_path,
        _ctab("CT_N", "TAB_NOINTP", "0 0", "nan 5", "10 10"),
        _cm("CM_NN", "TAB_NOINTP", fmt='"%.0"', ref="CT_N"),
        _cm("CM_NI", "TAB_INTP", fmt='"%.0"', ref="CT_N"),
        _val("NN", "0x10", LAYOUT["UBYTE"], "CM_NN", "0", "255"),
        _val("NI", "0x11", LAYOUT["UBYTE"], "CM_NI", "0", "255"),
    )
    image = {0x10: 0x04, 0x11: 0x04}
    for name in ("NN", "NI"):
        d = describe_definition(name, a2l)
        result = decode_definition(d, a2l, image)
        assert result == Refusal("A2L-DEF-DECODE", f"{name}: the table CT_N has an x that is not a number"), result


# ---- .151 : the echo of a file word ---------------------------------------------------------------

def _echo_file(tmp_path: Path, n: int) -> dict:
    """The objects of .151/1 with each word of ``n`` characters (``n`` 256)."""
    N, K, M, Z, G, E, F = ("N" * n, "K" * n, "M" * n, "Z" * n, "G" * n, "E" * n, "F" * n)
    a2l = _inline(
        tmp_path,
        _val(N, "0x10", LAYOUT["UBYTE"], "CM_GONE", "0", "255"),
        _char("KX", K, "0x11", LAYOUT["UBYTE"], "NO_COMPU_METHOD", "0", "255"),
        _val("MX1", "0x12", LAYOUT["UBYTE"], M, "0", "255"),
        _cm("CM_T1", Z),
        _val("CT1", "0x13", LAYOUT["UBYTE"], "CM_T1", "0", "255"),
        _cm("CM_R1", "TAB_VERB", fmt='"%.0"', ref=G),
        _val("TR1", "0x14", LAYOUT["UBYTE"], "CM_R1", "0", "255"),
        _cm("CM_E1", "TAB_VERB", fmt='"%.0"', ref=E),
        f'/begin COMPU_VTAB {E} "" TAB_VERB 0\n/end COMPU_VTAB',
        _val("TE1", "0x15", LAYOUT["UBYTE"], "CM_E1", "0", "255"),
        _val("BM1", "0x16", LAYOUT["UWORD"], "NO_COMPU_METHOD", "0", "65535", f"BIT_MASK {F}"),
    )
    return a2l


def _bound(d: Definition) -> None:
    assert d.refusal is not None and len(d.refusal.message) <= 1024, d.refusal


def test_r_a2l_def_151_1_a_word_of_256_characters_is_echoed_whole(tmp_path):
    """R-A2L-DEF.151/1 - 256 characters are echoed whole, in every place a refusal message echoes a file word."""
    a2l = _echo_file(tmp_path, 256)
    N, K, M, Z, G, E, F = ("N" * 256, "K" * 256, "M" * 256, "Z" * 256, "G" * 256, "E" * 256, "F" * 256)
    got = describe_definitions([N, "KX", "MX1", "CT1", "TR1", "TE1", "BM1"], a2l)
    want = {
        N: Refusal("A2L-DEF-METHOD", f"{N}: the conversion method CM_GONE is not declared in the A2L"),
        "KX": Refusal("A2L-DEF-KIND", f"KX: the system has no definition for a {K} object"),
        "MX1": Refusal("A2L-DEF-METHOD", f"MX1: the conversion method {M} is not declared in the A2L"),
        "CT1": Refusal("A2L-DEF-CONVERSION", f"CT1: the conversion type {Z} of CM_T1 is not supported"),
        "TR1": Refusal("A2L-DEF-TABLE", f"TR1: the table {G} of CM_R1 is not declared in the A2L"),
        "TE1": Refusal("A2L-DEF-TABLE-EMPTY", f"TE1: the table {E} has no entries"),
        "BM1": Refusal("A2L-DEF-MASK", f"BM1: the bit mask {F} cannot be applied to UWORD"),
    }
    for key, refusal in want.items():
        assert got[key].refusal == refusal, (key[:8], got[key].refusal)
        _bound(got[key])
        assert ELLIPSIS not in got[key].refusal.message


def test_r_a2l_def_151_2_a_word_of_257_characters_is_cut_at_describe_and_at_decode(tmp_path):
    """R-A2L-DEF.151/2 - the first 256 characters and an ellipsis; describe and decode messages alike; each message <= 1,024."""
    n = 257
    N, K, M, Z, G, E, F = ("N" * n, "K" * n, "M" * n, "Z" * n, "G" * n, "E" * n, "F" * n)
    # the 257-character forms of KX2 ... BM2, and the two decode objects
    a2l = _inline(
        tmp_path,
        _val(N, "0x10", LAYOUT["UBYTE"], "CM_GONE", "0", "255"),
        _char("KX2", K, "0x11", LAYOUT["UBYTE"], "NO_COMPU_METHOD", "0", "255"),
        _val("MX2", "0x12", LAYOUT["UBYTE"], M, "0", "255"),
        _cm("CM_T2", Z),
        _val("CT2", "0x13", LAYOUT["UBYTE"], "CM_T2", "0", "255"),
        _cm("CM_R2", "TAB_VERB", fmt='"%.0"', ref=G),
        _val("TR2", "0x14", LAYOUT["UBYTE"], "CM_R2", "0", "255"),
        _cm("CM_E2", "TAB_VERB", fmt='"%.0"', ref=E),
        f'/begin COMPU_VTAB {E} "" TAB_VERB 0\n/end COMPU_VTAB',
        _val("TE2", "0x15", LAYOUT["UBYTE"], "CM_E2", "0", "255"),
        _val("BM2", "0x16", LAYOUT["UWORD"], "NO_COMPU_METHOD", "0", "65535", f"BIT_MASK {F}"),
        _val("D" * n, "0x20", LAYOUT["UBYTE"], "NO_COMPU_METHOD", "0", "255"),
        _cm("CM_XN2", "TAB_NOINTP", fmt='"%.0"', ref="V" * n),
        f'/begin COMPU_VTAB {"V" * n} "" TAB_VERB 1\n  1 "ON"\n/end COMPU_VTAB',
        _val("X" * n, "0x21", LAYOUT["UBYTE"], "CM_XN2", "0", "255"),
    )
    e = lambda w: w[:256] + ELLIPSIS                                      # noqa: E731
    got = describe_definitions([N, "KX2", "MX2", "CT2", "TR2", "TE2", "BM2", "D" * n, "X" * n, "Q" * n], a2l)
    want = {
        N: Refusal("A2L-DEF-METHOD", f"{e(N)}: the conversion method CM_GONE is not declared in the A2L"),
        "KX2": Refusal("A2L-DEF-KIND", f"KX2: the system has no definition for a {e(K)} object"),
        "MX2": Refusal("A2L-DEF-METHOD", f"MX2: the conversion method {e(M)} is not declared in the A2L"),
        "CT2": Refusal("A2L-DEF-CONVERSION", f"CT2: the conversion type {e(Z)} of CM_T2 is not supported"),
        "TR2": Refusal("A2L-DEF-TABLE", f"TR2: the table {e(G)} of CM_R2 is not declared in the A2L"),
        "TE2": Refusal("A2L-DEF-TABLE-EMPTY", f"TE2: the table {e(E)} has no entries"),
        "BM2": Refusal("A2L-DEF-MASK", f"BM2: the bit mask {e(F)} cannot be applied to UWORD"),
        "Q" * n: Refusal("A2L-DEF-NAME", f"{e('Q' * n)}: no tag of that name in the A2L"),
    }
    for key, refusal in want.items():
        assert got[key].refusal == refusal, (key[:8], got[key].refusal)
        _bound(got[key])
    # decode: the bytes of D are not in the image; X names a table that gives a text
    d_def, x_def = got["D" * n], got["X" * n]
    assert d_def.refusal is None and x_def.refusal is None
    image = {0x21: 0x01}
    d_res = decode_definition(d_def, a2l, image)
    assert d_res == Refusal("A2L-DEF-BYTES", f"{e('D' * n)}: 1 of its 1 bytes are not in the image")
    x_res = decode_definition(x_def, a2l, image)
    assert x_res == Refusal("A2L-DEF-DECODE", f"{e('X' * n)}: the table {e('V' * n)} gives a value that is not a number")
    assert len(d_res.message) <= 1024 and len(x_res.message) <= 1024


def test_r_a2l_def_151_3_each_character_outside_printable_ascii_is_written_as_u_fffd(tmp_path):
    """R-A2L-DEF.151/3 - ESC, E-acute and DEL in an echoed word are each U+FFFD (not control characters only)."""
    word = "{}\x1bÉ\x7f{}"
    N, T, G, F = word.format("N", "X"), word.format("T", "X"), word.format("G", "X"), word.format("F", "X")
    a2l = _inline(
        tmp_path,
        _val(N, "0x10", LAYOUT["UBYTE"], "CM_GONE", "0", "255"),
        _cm("CM_T3", T),
        _val("CT3", "0x11", LAYOUT["UBYTE"], "CM_T3", "0", "255"),
        _cm("CM_R3", "TAB_VERB", fmt='"%.0"', ref=G),
        _val("TR3", "0x12", LAYOUT["UBYTE"], "CM_R3", "0", "255"),
        _val("BM3", "0x14", LAYOUT["UWORD"], "NO_COMPU_METHOD", "0", "65535", f"BIT_MASK {F}"),
    )
    got = describe_definitions([N, "CT3", "TR3", "BM3"], a2l)
    ff = lambda w: w.replace("\x1b", FFFD).replace("É", FFFD).replace("\x7f", FFFD)          # noqa: E731
    assert got[N].refusal == Refusal("A2L-DEF-METHOD", f"{ff(N)}: the conversion method CM_GONE is not declared in the A2L")
    assert got["CT3"].refusal == Refusal("A2L-DEF-CONVERSION", f"CT3: the conversion type {ff(T)} of CM_T3 is not supported")
    assert got["TR3"].refusal == Refusal("A2L-DEF-TABLE", f"TR3: the table {ff(G)} of CM_R3 is not declared in the A2L")
    assert got["BM3"].refusal == Refusal("A2L-DEF-MASK", f"BM3: the bit mask {ff(F)} cannot be applied to UWORD")
    assert got[N].refusal.message.startswith("N" + FFFD * 3 + "X: ")


# ---- .150/6 and /9 : the reduced lookups equal the frozen ones ---------------------------------------
# Oracles, copied verbatim from the frozen code and kept here as test-local functions:
#   _oracle_enum_entry_text / _oracle_enum_text / _oracle_clean / _oracle_raw_text
#       s19_app/tui/a2l_definition.py at 82f5f8e5 (Inc 2a as merged: the linear first match)
#   _oracle_table_lookup
#       s19_app/tui/a2l.py at 82f5f8e5, ``_table_lookup`` (the frozen COMPU_TAB lookup)

def _oracle_clean(text):
    if text is None:
        return None
    return "".join(
        "�"
        if ord(ch) <= 0x1F or ord(ch) == 0x7F or (0x80 <= ord(ch) <= 0x9F)
        else ch
        for ch in text
    )


def _oracle_raw_text(stored):
    if isinstance(stored, float):
        if math.isfinite(stored) and stored.is_integer():
            return str(int(stored))
        return f"{stored:.15g}"
    return str(stored)


def _oracle_enum_entry_text(definition, stored):
    for entry in definition.enum_entries:
        if entry.raw_max is None:
            if entry.raw == stored:
                return entry.text
        elif entry.raw <= stored <= entry.raw_max:
            return entry.text
    return None


def _oracle_enum_text(definition, stored):
    entry = _oracle_enum_entry_text(definition, stored)
    if entry is not None:
        return _oracle_clean(entry)
    if definition.default_text is not None:
        return _oracle_clean(definition.default_text)
    return f"{_oracle_raw_text(stored)} (no text)"


def _oracle_to_float(value):
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _oracle_table_lookup(value, table, interpolate):
    entries = table.get("entries") or []
    if not entries:
        return None, "lookup table is empty"
    if not interpolate:
        for raw_x, raw_y in entries:
            if raw_x == value:
                return raw_y, ""
        nearest = min(entries, key=lambda item: abs(item[0] - value))
        return nearest[1], ""
    if value <= entries[0][0]:
        return entries[0][1], ""
    if value >= entries[-1][0]:
        return entries[-1][1], ""
    for left, right in zip(entries, entries[1:]):
        lx, ly = left
        rx, ry = right
        if lx <= value <= rx:
            lyf = _oracle_to_float(ly)
            ryf = _oracle_to_float(ry)
            if lyf is None or ryf is None:
                return ly, ""
            if rx == lx:
                return lyf, ""
            ratio = (value - lx) / (rx - lx)
            return lyf + ratio * (ryf - lyf), ""
    return None, "value outside interpolation range"


_PROBE_BUDGET = 1_500_000        # probes x entries of the linear oracle, per table (a larger table is sampled by stride)


def _enum_probes(entries) -> list:
    """Each raw / min / max, the midpoint of each two neighbouring ends, each +-1, NaN, +inf and -inf; the
    integral ones also as ints."""
    ends = sorted({v for e in entries for v in (e.raw, e.raw_max) if v is not None and v == v})
    finite = [v for v in ends if math.isfinite(v)]
    pts = set(ends)
    pts.update((a + b) / 2 for a, b in zip(finite, finite[1:]))
    pts.update(v + 1 for v in finite)
    pts.update(v - 1 for v in finite)
    ordered = sorted(pts)
    limit = max(8, _PROBE_BUDGET // max(1, 2 * len(entries)))
    if len(ordered) > limit:
        ordered = ordered[:: -(-len(ordered) // limit)]
    probes: list = ordered + [math.nan, math.inf, -math.inf]
    probes += [int(v) for v in ordered if math.isfinite(v) and v == int(v) and abs(v) < 2**63]
    return probes


def _check_enum_form(base: Definition, form, label: str, stats: dict) -> None:
    d = dataclasses.replace(base, enum_entries=form.entries, default_text=form.default_text, _table_form=form)
    for v in _enum_probes(form.entries):
        want_entry, want_text = _oracle_enum_entry_text(d, v), _oracle_enum_text(d, v)
        got_entry, got_text = defmod._enum_entry_text(d, v), defmod._enum_text(d, v)
        stats["values"] += 1
        if (got_entry, got_text) != (want_entry, want_text):
            stats["diffs"].append((label, v, (got_entry, got_text), (want_entry, want_text)))


def _enum_base(tmp_path: Path, *blocks: str) -> tuple[dict, Definition, dict]:
    a2l = _inline(tmp_path, *blocks, _cm("CM_B", "TAB_VERB", fmt='"%.0"', ref="VT_B"),
                  _vtab("VT_B", "1", '0 "z"'), _val("BASE", "0x10", LAYOUT["UBYTE"], "CM_B", "0", "255"))
    base = describe_definition("BASE", a2l)
    assert base.kind == "enum" and base.refusal is None
    return a2l, base, _name_maps(a2l)[1]


def _tracked_a2l_files() -> list:
    found = sorted((REPO_ROOT / "examples").rglob("*.a2l")) + sorted((REPO_ROOT / "tests").rglob("*.a2l"))
    out = []
    for path in found:
        data = path.read_bytes()
        if b"COMPU_VTAB" in data or b"COMPU_TAB" in data:        # case 06 (37 MB) holds none: not parsed
            out.append(path)
    return out


@pytest.fixture(scope="module")
def corpus() -> list:
    """(label, parse payload) of every tracked .a2l under examples/ and tests/ that holds a COMPU_ table."""
    return [(p.relative_to(REPO_ROOT).as_posix(), parse_a2l_file(p)) for p in _tracked_a2l_files()]


def test_r_a2l_def_150_6_the_enum_form_lookup_is_the_linear_first_match(tmp_path, corpus):
    """R-A2L-DEF.150/6 (E3S3-30 a) - the form's lookup equals the linear first match of 82f5f8e5 for every corpus table and hostile table."""
    base_a2l, base, _t = _enum_base(tmp_path)
    stats: dict = {"values": 0, "diffs": [], "tables": 0}
    for label, a2l in corpus:
        _methods, tables = _name_maps(a2l)
        for name in tables:
            form = defmod._read_enum_table(name, tables, {})
            _check_enum_form(base, form, f"{label}:{name}", stats)
            stats["tables"] += 1
    assert stats["tables"] >= 100 and stats["values"] >= 5000, stats          # the corpus is read, not skipped
    assert stats["diffs"] == [], (len(stats["diffs"]), stats["diffs"][:5])

    # INLINE hostile tables, each with and without a DEFAULT_VALUE
    vt = ('1 "A"', '1 "B"', '-0.0 "Z"', '0 "Y"', 'nan "N"', '2 "C"')
    rg = ('0 10 "a"', '5 15 "b"', '5 5 "c"', '-3 20 "d"', '0 10 "x"', '10 20 "e"', '12 11 "z"', 'nan 5 "n"', '30 30 "p"')
    a2l, base, tables = _enum_base(
        tmp_path,
        _vtab("HV", "6", *vt), _vtab("HV_D", "6", *vt, default="dflt"),
        _vrange("HR", "9", *rg), _vrange("HR_D", "9", *rg, default="dflt"),
    )
    hostile = {"values": 0, "diffs": []}
    forms = {}
    for name in ("HV", "HV_D", "HR", "HR_D"):
        forms[name] = defmod._read_enum_table(name, tables, {})
        _check_enum_form(base, forms[name], name, hostile)
    assert hostile["values"] > 100 and hostile["diffs"] == [], hostile["diffs"][:5]

    def text(name, v):
        d = dataclasses.replace(base, enum_entries=forms[name].entries, default_text=forms[name].default_text,
                                _table_form=forms[name])
        return defmod._enum_entry_text(d, v), defmod._enum_text(d, v)

    for v, want in ((5, "a"), (10, "a"), (10.5, "b"), (16, "d"), (25, None), (30, "p"), (math.nan, None)):
        assert text("HR", v)[0] == want, (v, text("HR", v))
        assert text("HR_D", v)[1] == (want if want is not None else "dflt"), (v, text("HR_D", v))
    assert text("HR", 25)[1] == "25 (no text)" and text("HR", math.nan)[1] == "nan (no text)"
    for v, want in ((1, "A"), (0, "Z"), (2, "C"), (math.nan, None)):
        assert text("HV", v)[0] == want, (v, text("HV", v))
        assert text("HV_D", v)[1] == (want if want is not None else "dflt"), (v, text("HV_D", v))


def _same_result(a, b) -> bool:
    (av, ae), (bv, be) = a, b
    if ae != be:
        return False
    if isinstance(av, float) and isinstance(bv, float):
        return (av != av and bv != bv) or av == bv
    return type(av) is type(bv) and av == bv


def _tab_probes(xs: list) -> list:
    """Each x, each midpoint of two neighbouring x, each x +- 1 ulp, +-0, +-1e300, 2^53 + 1, NaN, +inf, -inf, 2^63,
    2^64 - 1 (floats, and the integral ones also as ints: A_UINT64)."""
    sample = xs
    if len(sample) > 60:                                     # linear oracle: sample the table by stride, keep the ends
        step = -(-len(sample) // 60)
        sample = sorted(set(sample[::step]) | set(sample[:3]) | set(sample[-3:]))
    pts = set(sample)
    for a, b in zip(sample, sample[1:]):
        if math.isfinite(a) and math.isfinite(b):
            pts.add(a / 2 + b / 2)
    for x in sample:
        if math.isfinite(x):
            pts.add(math.nextafter(x, math.inf))
            pts.add(math.nextafter(x, -math.inf))
    pts.update([0.0, -0.0, 1e300, -1e300, float(2**53 + 1), math.nan, math.inf, -math.inf, float(2**63), float(2**64 - 1)])
    probes: list = list(pts)
    probes += [int(v) for v in pts if math.isfinite(v) and v == int(v) and 0 <= v < 2**64]
    probes += [2**53 + 1, 2**63, 2**64 - 1]
    return probes


def _check_tab_form(a2l: dict, table_name: str, form, stats: dict, label: str) -> None:
    table = a2l["compu_tabs_by_name"][table_name]
    xs = [x for x, _y in table.get("entries") or []]
    for interpolate in (False, True):
        for v in _tab_probes(xs):
            want = _oracle_table_lookup(float(v), table, interpolate)
            got = defmod._table_value(form, v, interpolate)
            stats["pairs"] += 1
            if not _same_result(got, want):
                stats["diffs"].append((label, table_name, interpolate, v, got, want))


def _tab_form_of(a2l: dict, table_name: str, kind: str, reads: dict):
    """The table form a TAB_INTP / TAB_NOINTP method naming ``table_name`` holds (a synthetic method section)."""
    section = {"name": "COMPU_METHOD", "meta": f'CMZ_{kind} "" {kind} "%.3" ""',
               "lines": [f"COMPU_TAB_REF {table_name}"]}
    record = _method_record(a2l, f"CMZ_{kind}", reads, {f"CMZ_{kind}": section})
    return record["table_form"]


def test_r_a2l_def_150_9_the_reduced_tab_lookup_equals_the_frozen_lookup(tmp_path, corpus):
    """R-A2L-DEF.150/9 (E3S3-29, v2) - the form's lookup gives the frozen _table_lookup's value for every corpus table and hostile table."""
    stats: dict = {"pairs": 0, "diffs": [], "tables": 0}
    for label, a2l in corpus:
        for name, table in (a2l.get("compu_tabs_by_name") or {}).items():
            if re.search(r'[\s"]', name):
                continue
            for kind in ("TAB_INTP", "TAB_NOINTP"):
                form = _tab_form_of(a2l, name, kind, {})
                assert form is not None, (label, name)
                if form.x_nan:
                    continue                                    # such a table is refused at decode (.58.2/19)
                _check_tab_form(a2l, name, form, stats, label)
            stats["tables"] += 1
    assert stats["tables"] >= 5 and stats["pairs"] >= 2000, stats
    assert stats["diffs"] == [], (len(stats["diffs"]), stats["diffs"][:5])

    # INLINE: the plain table and the table with a duplicate x
    a2l = _inline(tmp_path, _ctab("H1", "TAB_NOINTP", "0 0", "10 100", "20 50"),
                  _ctab("H2", "TAB_NOINTP", "0 0", "10 100", "10 7", "20 50"))
    hostile = {"pairs": 0, "diffs": []}
    forms = {}
    for name in ("H1", "H2"):
        for kind in ("TAB_INTP", "TAB_NOINTP"):
            forms[name, kind] = _tab_form_of(a2l, name, kind, {})
            _check_tab_form(a2l, name, forms[name, kind], hostile, "inline")
    assert hostile["pairs"] > 100 and hostile["diffs"] == [], hostile["diffs"][:5]
    nointp, intp = forms["H1", "TAB_NOINTP"], forms["H1", "TAB_INTP"]
    for v, want in ((2.5, 0.0), (7.5, 100.0), (15, 100.0)):
        assert defmod._table_value(nointp, v, False) == (want, ""), v
    assert defmod._table_value(intp, 15, True) == (75.0, "")
    assert defmod._table_value(intp, -1, True) == (0.0, "")
    assert defmod._table_value(intp, math.nan, True) == (None, "value outside interpolation range")
    assert defmod._table_value(nointp, math.nan, False) == (0.0, "")


# --------------------------------------------------------------------------
# E5 fix pass (independent tester).  R-A2L-DEF.58.2/20 ... /24 (the number rule and the iterative
# walk), .151/4 ... /6 (the number rule for MATRIX_DIM, address and length; a quoted kind word).
# R-A2L-DEF.12/4 is above, next to .12/3; CR-7 is in .149/5; the timed .150/10 is in the perf file.
# Expected messages are written out from the rows: a number above 2^64 - 1 is `0x` and its
# UPPER-case hexadecimal digits cut by the .151 echo (256 characters, then an ellipsis).
# --------------------------------------------------------------------------

import threading  # noqa: E402

HEX256 = "0x" + "F" * 254 + ELLIPSIS         # the echo of `0x` and 5,000 (or 1,000 or 1,500) `F`


def _huge_span_case(tmp_path: Path, name: str, block: str) -> None:
    """One 58.2/20-22 object: its describe refusal, the 1,024-character bound, and the decode of the same refusal."""
    a2l = _inline(tmp_path, block)
    d = describe_definition(name, a2l)                                         # 0 exceptions
    want = Refusal("A2L-DEF-ADDRESS", f"{name}: its span of {HEX256} bytes at 0x10 cannot be read")
    assert d.refusal == want, d.refusal
    assert len(d.refusal.message) <= 1024
    assert decode_definition(d, a2l, {0x10: 1, 0x11: 2}) == want


def test_r_a2l_def_58_2_20_a_length_of_5000_hex_digits_is_a_refusal_not_an_exception(tmp_path):
    """R-A2L-DEF.58.2/20 (E5S-01, CR-2) - LENGTH 0x + 5,000 F on a UWORD VALUE."""
    _huge_span_case(tmp_path, "HL", _val("HL", "0x10", LAYOUT["UWORD"], "NO_COMPU_METHOD", "0", "65535",
                                         "LENGTH 0x" + "F" * 5000))


def test_r_a2l_def_58_2_21_a_data_size_of_5000_hex_digits_is_a_refusal_not_an_exception(tmp_path):
    """R-A2L-DEF.58.2/21 (E5S-01) - DATA_SIZE 0x + 5,000 F on a UBYTE MEASUREMENT."""
    _huge_span_case(tmp_path, "HD", _meas("HD", "UBYTE", "NO_COMPU_METHOD", "0", "255",
                                          "DATA_SIZE 0x" + "F" * 5000, addr="0x10"))


def test_r_a2l_def_58_2_22_a_number_of_5000_hex_digits_is_a_refusal_not_an_exception(tmp_path):
    """R-A2L-DEF.58.2/22 (E5S-01) - NUMBER 0x + 5,000 F on an ASCII CHARACTERISTIC."""
    _huge_span_case(tmp_path, "HN", _ascii("HN", "0x10", "0x" + "F" * 5000))


def test_r_a2l_def_58_2_23_a_matrix_dim_of_5000_hex_digits_is_a_refusal_not_an_exception(tmp_path):
    """R-A2L-DEF.58.2/23 (E5S-01, CR-2) - MATRIX_DIM 0x + 5,000 F on a UBYTE MEASUREMENT: A2L-DEF-KIND, bounded."""
    a2l = _inline(tmp_path, _meas("MD", "UBYTE", "NO_COMPU_METHOD", "0", "255", "MATRIX_DIM 0x" + "F" * 5000,
                                  addr="0x10"))
    d = describe_definition("MD", a2l)                                         # 0 exceptions
    want = Refusal("A2L-DEF-KIND", f"MD: the system has no definition for a MATRIX_DIM {HEX256} MEASUREMENT object")
    assert d.refusal == want, d.refusal
    assert len(d.refusal.message) <= 1024
    assert describe_definitions(["MD"], a2l)["MD"] == d


def _fresh_thread(fn, padding: int = 0):
    """Run ``fn()`` in a new thread, ``padding`` Python frames deep; return its value or re-raise what it raised."""
    box: dict = {}

    def deeper(n: int) -> None:
        if n:
            return deeper(n - 1)
        try:
            box["value"] = fn()
        except BaseException as exc:                                            # noqa: BLE001 - re-raised below
            box["error"] = exc

    thread = threading.Thread(target=deeper, args=(padding,))
    thread.start()
    thread.join()
    if "error" in box:
        raise box["error"]
    return box["value"]


NEST_DEPTH = 980                          # the app's parser reads this depth in a fresh thread; it fails itself at >= 990


def test_r_a2l_def_58_2_24_deep_nesting_does_not_raise_and_the_walk_keeps_file_order(tmp_path):
    """R-A2L-DEF.58.2/24 (E5S-04) - (N) 980 nested sections: 0 exceptions, same definition, same decode;
    (O) the first COMPU_METHOD of a name in file order wins (each section before its children, children in order)."""
    nested_block = "\n".join(['/begin GROUP G%d ""' % k for k in range(NEST_DEPTH)] + ["/end GROUP"] * NEST_DEPTH)
    obj = _val("DN", "0x10", LAYOUT["UBYTE"], "NO_COMPU_METHOD", "0", "255")
    flat = _inline(tmp_path, obj)
    nested = _fresh_thread(lambda: _inline(tmp_path, obj, nested_block))     # the parser reads the depth itself
    alone = describe_definition("DN", flat)
    assert alone.refusal is None and alone.kind == "number" and alone.address == 0x10
    # described and decoded 50 frames deep in a fresh thread: a recursive walk needs 980 more frames
    got = _fresh_thread(lambda: describe_definitions(["DN"], nested)["DN"], padding=50)       # 0 exceptions
    assert got == alone
    assert _fresh_thread(lambda: decode_definition(got, nested, {0x10: 7}), padding=50) == Decoded(7, 7, "7")

    # (O) CM_D is declared twice: inside a section (LINEAR 2 0) and later at module level (LINEAR 3 0)
    inner = '/begin GROUP G ""\n' + _cm("CM_D", "LINEAR", "2", "0") + "\n/end GROUP"
    order = _inline(tmp_path, inner, _cm("CM_D", "LINEAR", "3", "0"),
                    _val("DD", "0x10", LAYOUT["UBYTE"], "CM_D", "0", "255"))
    dd = describe_definitions(["DD"], order)["DD"]
    assert dd.refusal is None, dd.refusal
    assert decode_definition(dd, order, {0x10: 5}) == Decoded(5, 10.0, "10.000")


def test_r_a2l_def_151_4_a_matrix_dim_number_is_written_by_the_number_rule(tmp_path):
    """R-A2L-DEF.151/4 (CR-3, E5S-03) - 4,000 decimal digits and 1,000 hexadecimal digits: `0x` form, 256 characters, bounded."""
    a2l = _inline(
        tmp_path,
        _meas("MD4", "UBYTE", "NO_COMPU_METHOD", "0", "255", "MATRIX_DIM " + "9" * 4000, addr="0x10"),
        _meas("MD5", "UBYTE", "NO_COMPU_METHOD", "0", "255", "MATRIX_DIM 0x" + "F" * 1000, addr="0x11"),
    )
    got = describe_definitions(["MD4", "MD5"], a2l)
    t4 = "0x" + format(10 ** 4000 - 1, "X")[:254] + ELLIPSIS
    assert got["MD4"].refusal == Refusal("A2L-DEF-KIND", f"MD4: the system has no definition for a MATRIX_DIM {t4} MEASUREMENT object")
    assert got["MD5"].refusal == Refusal("A2L-DEF-KIND", f"MD5: the system has no definition for a MATRIX_DIM {HEX256} MEASUREMENT object")
    for name in ("MD4", "MD5"):
        assert len(got[name].refusal.message) <= 1024, (name, len(got[name].refusal.message))


def test_r_a2l_def_151_5_the_number_rule_for_an_address_and_a_length_at_its_bound(tmp_path):
    """R-A2L-DEF.151/5 (E5S-03) - addresses of 1,500 hex digits are cut; 2^64 - 1 stays decimal and 2^64 is `0x` form."""
    a2l = _inline(
        tmp_path,
        _meas("AH", "UBYTE", "NO_COMPU_METHOD", "0", "255", addr="0x" + "F" * 1500),
        _val("CH", "0x" + "F" * 1500, LAYOUT["UBYTE"], "NO_COMPU_METHOD", "0", "255"),
        _ascii("B1", "0x10", "18446744073709551615"),
        _ascii("B2", "0x20", "18446744073709551616"),
    )
    got = describe_definitions(["AH", "CH", "B1", "B2"], a2l)
    assert got["AH"].refusal == Refusal("A2L-DEF-ADDRESS", f"AH: its span of 1 bytes at {HEX256} cannot be read")
    assert got["CH"].refusal == Refusal("A2L-DEF-ADDRESS", f"CH: its span of 1 bytes at {HEX256} cannot be read")
    assert got["B1"].refusal == Refusal("A2L-DEF-ADDRESS", "B1: its span of 18446744073709551615 bytes at 0x10 cannot be read")
    assert got["B2"].refusal == Refusal("A2L-DEF-ADDRESS", "B2: its span of 0x10000000000000000 bytes at 0x20 cannot be read")
    for name in ("AH", "CH", "B1", "B2"):
        assert len(got[name].refusal.message) <= 1024, (name, len(got[name].refusal.message))


def test_r_a2l_def_151_6_a_quoted_kind_word_starting_with_matrix_dim_is_echoed_as_a_file_word(tmp_path):
    """R-A2L-DEF.151/6 (CR-5) - the kind word `MATRIX_DIM <2,000 Z>` is a file word: 256 characters and an ellipsis."""
    a2l = _inline(tmp_path, _char("QK", '"MATRIX_DIM ' + "Z" * 2000 + '"', "0x10", "RL_U8"))
    word = next(t["char_type"] for t in a2l["tags"] if t["name"] == "QK")
    assert len(word) == 2011 and word.startswith("MATRIX_DIM "), len(word)          # the parsed kind word, as the row says
    d = describe_definition("QK", a2l)
    assert d.refusal == Refusal("A2L-DEF-KIND", f"QK: the system has no definition for a {_echo256(word)} object"), d.refusal
    assert len(d.refusal.message) <= 1024
    assert d.refusal.message.count(FFFD) == 1                                   # only the space was rewritten
