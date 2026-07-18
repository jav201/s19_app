"""Scalar CHARACTERISTIC length is derived from a resolved RECORD_LAYOUT (P-1).

Batch: a2l-record-layout-length (follow-up to a2l-missing-length-fix). A scalar
VALUE CHARACTERISTIC that references a project-named RECORD_LAYOUT (whose *name*
encodes no size, e.g. ``RL_U8``) previously parsed with ``length=None`` — grey
"not memory-checked" — because ``_infer_length_characteristic`` only tried
``sizeof_from_deposit(name)``. It now resolves the layout definition
(``FNC_VALUES 1 UBYTE …`` -> element size 1) and uses that size, so the record
becomes memory-checkable.

Two guardrails are pinned alongside the win:
- CURVE/MAP stay ``length=None`` (element size would UNDER-report an array span
  and make the byte-range check falsely pass — a false-green). VALUE only.
- The fallback is additive: a size-encoded deposit name or an absent layout is
  unchanged.
"""

from pathlib import Path

from s19_app.tui.a2l import (
    DATATYPE_SIZES,
    _infer_length_characteristic,
    parse_a2l_file,
    validate_a2l_tags,
)

_CASE_01_A2L = Path(__file__).resolve().parent.parent / "examples" / "case_01_basic_valid" / "firmware.a2l"

# A resolvable scalar layout: name carries no size, definition names UBYTE (1).
_RL_U8 = {"RL_U8": {"name": "RL_U8", "tokens": ["FNC_VALUES", "1", "UBYTE", "COLUMN_DIR", "DIRECT"]}}
_RL_U16 = {"RL_U16": {"name": "RL_U16", "tokens": ["FNC_VALUES", "1", "UWORD", "COLUMN_DIR", "DIRECT"]}}


# ---------------------------------------------------------------------------
# AC-1 — scalar VALUE + name-only layout -> element datatype size.
# ---------------------------------------------------------------------------


def test_ac1_value_layout_resolves_to_element_size() -> None:
    header = {"deposit": "RL_U8", "char_type": "VALUE"}

    length = _infer_length_characteristic([], header, _RL_U8)

    assert length == 1, "scalar VALUE length must resolve to the layout's datatype size"


def test_ac1_wider_layout_resolves() -> None:
    header = {"deposit": "RL_U16", "char_type": "VALUE"}

    assert _infer_length_characteristic([], header, _RL_U16) == DATATYPE_SIZES["UWORD"]


# ---------------------------------------------------------------------------
# AC-1/AC-2 end-to-end — real case_01 fixture: CAL_BLOCK_A gets a length AND
# is memory-checked (not grey) once its layout is resolved.
# ---------------------------------------------------------------------------


def test_ac1_case01_characteristic_gets_layout_length() -> None:
    data = parse_a2l_file(_CASE_01_A2L)
    by_name = {t["name"]: t for t in data["tags"] if t["section"] == "CHARACTERISTIC"}

    assert by_name["CAL_BLOCK_A"]["length"] == 1, "CAL_BLOCK_A (RL_U8) must derive length 1"
    assert by_name["CAL_BLOCK_B"]["length"] == 1


def test_ac2_layout_length_makes_characteristic_memory_checked() -> None:
    data = parse_a2l_file(_CASE_01_A2L)
    cal_a = next(t for t in data["tags"] if t.get("name") == "CAL_BLOCK_A")
    addr = cal_a["address"]

    # address present in the image -> memory-checked + in image
    present = validate_a2l_tags([cal_a], {addr: 0x00})[0]
    assert present["schema_ok"] is True
    assert present["memory_checked"] is True, "a derived length must enable the byte-range check"
    assert present["in_memory"] is True

    # address absent -> still memory-checked, honestly reported out-of-image
    absent = validate_a2l_tags([cal_a], {addr + 999: 0x00})[0]
    assert absent["memory_checked"] is True
    assert absent["in_memory"] is False


# ---------------------------------------------------------------------------
# AC-3 (no false-green) — CURVE/MAP must NOT borrow the element size.
# ---------------------------------------------------------------------------


def test_ac3_curve_layout_stays_unsized() -> None:
    header = {"deposit": "RL_U8", "char_type": "CURVE"}

    assert _infer_length_characteristic([], header, _RL_U8) is None, (
        "a CURVE is an array over its axes — borrowing the element size would "
        "under-count the span and falsely pass the byte-range memory check"
    )


def test_ac3_map_layout_stays_unsized() -> None:
    header = {"deposit": "RL_U8", "char_type": "MAP"}

    assert _infer_length_characteristic([], header, _RL_U8) is None


# ---------------------------------------------------------------------------
# AC-4 — the fallback is additive: name-encoded deposit and absent layout
# behave exactly as before.
# ---------------------------------------------------------------------------


def test_ac4_name_encoded_deposit_unchanged() -> None:
    header = {"deposit": "__UWORD_Z", "char_type": "VALUE"}

    # sizeof_from_deposit already sizes this; the layout fallback is never reached.
    assert _infer_length_characteristic([], header, {}) == 2


def test_ac4_absent_layout_stays_none() -> None:
    header = {"deposit": "RL_MISSING", "char_type": "VALUE"}

    assert _infer_length_characteristic([], header, _RL_U8) is None, (
        "an unresolvable layout must leave length None, not guess"
    )


def test_ac4_no_layout_map_is_safe() -> None:
    header = {"deposit": "RL_U8", "char_type": "VALUE"}

    # record_layouts_by_name omitted (legacy call shape) -> no resolution, None.
    assert _infer_length_characteristic([], header) is None
