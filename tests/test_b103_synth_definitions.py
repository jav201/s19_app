"""Batch-103 Inc 2a (G-T2) - the synthetic generator: the case 08 pin and the definitions case.

Design under test: ``.dev-flow/2026-11-05-batch-103/inc-2/01-requirements.md``
rows R-A2L-DEF.59 (case 08 pin), .60, .61, .62, .63 (the ``--case definitions``
option) and the 2a arm of AT-B103-I2-2 (build and decode each definitions-case
object to its planned value through the app's loaders), one test per case of
``inc-2/02-test-cases.md``. The case 08 pins are SHA-256 values taken on the
base tree ``e07fb00`` (``evidence-e1/i2e1-case08-hashes-transcript.txt``) over
the file bytes with every CR LF read as LF; the object-list digest of
R-A2L-DEF.59/3 was taken at E4 on a clean checkout of ``e07fb00`` before any
edit (``evidence-e4/tests-59-3-digest-transcript.txt``).

The case 08 pin tests pass on the base tree on purpose: they guard the byte
identity of case 08 while the generator gains a second case.

Dependencies:
    - ``tools/synth/make_release_case.py`` (run as the shipped CLI)
    - ``s19_app.tui.a2l_definition`` (AT-B103-I2-2 only), the app's A2L parser
      and S19 loader
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import replace
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SYNTH_DIR = REPO_ROOT / "tools" / "synth"
TOOL = SYNTH_DIR / "make_release_case.py"
SEED = 20260001

if str(SYNTH_DIR) not in sys.path:
    sys.path.insert(0, str(SYNTH_DIR))

import make_release_case as gen  # noqa: E402

from s19_app.core import S19File  # noqa: E402
from s19_app.tui.a2l_parse import parse_a2l_file  # noqa: E402
from tests.test_b103_a2l_definition import _clear_parse_errors  # noqa: E402

CASE08_FILES = [
    "firmware.s19",
    "firmware.hex",
    "firmware_v2.s19",
    "firmware.a2l",
    "firmware.mac",
    "demo_patch.changes.json",
    "demo_check.chk.json",
    "demo_check_fails.chk.json",
    "firmware_issues.a2l",
    "firmware_issues.mac",
    "README.txt",
]

# SHA-256 of each file's bytes, CR LF read as LF. Source: the `1 |` and `10 |`
# rows of evidence-e1/i2e1-case08-hashes-transcript.txt (base tree e07fb00).
CASE08_PIN_1MIB = {
    "firmware.s19": "f5592b511a561c463bf89679b784aea9d9fa552d5aa9b06a17f8e91cd87ea49b",
    "firmware.hex": "f0eb7556d01b31a54009608af0dd0b1c73f5faa4b077941e55e757540bd2e8f2",
    "firmware_v2.s19": "855cdd8434dc639e91732fb0b3ffc2d2f2977804546c8e7cbfae6dc25cf6ec21",
    "firmware.a2l": "34900db01fee2d2f67252b675f1536a0a2213fa178496e1140019bf05b7f3e8f",
    "firmware.mac": "6f28961a896a253829b6188813192f0a43f05025a6662a038093fbda5ce19212",
    "demo_patch.changes.json": "46cfc7b200ecd0dea85c7e80fdf1b6bd3c8af3f756109a650831796393d2ac79",
    "demo_check.chk.json": "819bd4a0fa1290fc725ea368f541d2d909ac95936ecbeab82cae2bb6b8878451",
    "demo_check_fails.chk.json": "8bcefc106cb80cab4f7e381d421b72c881c71fec76b6cfbfd6c7a2633704ec92",
    "firmware_issues.a2l": "bb1522da3e47c083a6705c69cb73da3c3179a760a01e65cac275a6f50498bb91",
    "firmware_issues.mac": "f52799cca08d72c461647a992723915fadd02c6dd90ddd5c33f2cd1449c443c0",
    "README.txt": "1ac1b52e1ddb13ffc0fcf45113ec01ce759992bde87730bfae63c647924506ed",
}
CASE08_PIN_10MIB = {
    "firmware.s19": "cb0cd7f1a07488aecbcb0928d75b4ae57bb5373f2ff4c097147aac41e2a7c2d9",
    "firmware.hex": "2bd129e0ce59d30b70b93ad4660a45f3ff91525fc39fc14c907a587d0766184d",
    "firmware_v2.s19": "7a41b8c7c291b389fe588cc32615176f809cc9267fe547cb0800bd02c42ca906",
    "firmware.a2l": "42ca7d40a8c3a1a4ee15abd6fb36ed9953554156c0bb1865e64b17615ba2d961",
    "firmware.mac": "6f28961a896a253829b6188813192f0a43f05025a6662a038093fbda5ce19212",
    "demo_patch.changes.json": "e5ca0550cafef62222ab65f68126b6cf4b1bee76d389da7862052ff398153980",
    "demo_check.chk.json": "8ebd23b0e5afe12e14bffb72212c6202aa23eba7b8f7965a0329b62a0348594f",
    "demo_check_fails.chk.json": "a2151fae2f1be301662a18b16ae390eb2042f5fe045c058c9915fbd465b1f7fc",
    "firmware_issues.a2l": "6f9362939936a01683756239b2b884bf9b69ece2d9dac62d3d0ef71651f71f36",
    "firmware_issues.mac": "f52799cca08d72c461647a992723915fadd02c6dd90ddd5c33f2cd1449c443c0",
    "README.txt": "b01212e5cdde95a2975a92f64212a988d6f3dec6c35d5cf9e4cf11167d09bc62",
}
# repr() digest of build_objects(compute_region_sizes(1.0), Random(20260001)),
# taken at E4 on a clean checkout of the base tree e07fb00, before any edit.
OBJECT_LIST_DIGEST_1MIB = "71252ba6f06af28c6979ab634e3ee0f5aaff9d25a7bb55d49d467d0403a6fdec"


def case08_file_digests(folder: Path) -> dict[str, str]:
    """SHA-256 of each of the 11 case 08 files, every CR LF read as LF."""
    return {
        name: hashlib.sha256((folder / name).read_bytes().replace(b"\r\n", b"\n")).hexdigest()
        for name in CASE08_FILES
    }


def _model():
    """The 2a model, imported where a test needs it (the case 08 pin tests do not need it)."""
    from s19_app.tui import a2l_definition

    return a2l_definition


def _run_cli(out: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(TOOL), "--out", str(out), *args],
        capture_output=True,
        text=True,
        timeout=600,
    )


def _defc_plan(obj: dict) -> list:
    """The generator's planned values for one definitions-case object, normalized
    to a list of ``(stored, text)`` pairs (a scalar gives one pair)."""
    stored = obj["planned_stored"]
    text = obj["planned_text"]
    if isinstance(stored, tuple):
        return list(zip(stored, text))
    return [(stored, text)]


def _defc_decode(m, obj: dict, a2l: dict, image: dict) -> list | None:
    """Decode one definitions-case object through the app's loaders, per the Inc 3a
    I-D contract: AXIS_PTS is an axis record (returns ``None``; its points decode
    through the curves and maps that reference it), an array/curve/map uses
    ``decode_values``, a scalar keeps ``decode_definition``.  Returns the decoded
    ``(stored, text)`` pairs in element order."""
    if obj.get("section") == "AXIS_PTS":
        return None
    d = m.describe_definition(obj["name"], a2l)
    assert d.refusal is None, (obj["name"], d.refusal)
    if obj.get("kind") in ("CURVE", "MAP", "VAL_BLK"):
        res = m.decode_values(d, a2l, image)
        assert isinstance(res, m.DecodedValues), (obj["name"], res)
        return [(v.stored, v.text) for v in res.values]
    res = m.decode_definition(d, a2l, image)
    assert isinstance(res, m.Decoded), (obj["name"], res)
    return [(res.stored, res.text)]


# ==========================================================================
# R-A2L-DEF.59 - the case 08 pin
# ==========================================================================


def test_r_a2l_def_59_1_case08_at_1_mib_equals_its_pin(tmp_path):
    """R-A2L-DEF.59/1 - seed 20260001, --size-mb 1, no case option: the 11 digests."""
    result = _run_cli(tmp_path / "c08", "--seed", str(SEED), "--size-mb", "1")
    assert result.returncode == 0, result.stderr
    assert case08_file_digests(tmp_path / "c08") == CASE08_PIN_1MIB


@pytest.mark.slow
def test_r_a2l_def_59_2_case08_at_10_mib_equals_its_pin(tmp_path):
    """R-A2L-DEF.59/2 - --size-mb 10 (slow)."""
    result = _run_cli(tmp_path / "c08", "--seed", str(SEED), "--size-mb", "10")
    assert result.returncode == 0, result.stderr
    assert case08_file_digests(tmp_path / "c08") == CASE08_PIN_10MIB


def test_r_a2l_def_59_3_object_list_digest_equals_the_e4_pin():
    """R-A2L-DEF.59/3 - build_objects at 1 MiB, seed 20260001: the digest of repr (E3A-27)."""
    regions = gen.compute_region_sizes(1.0)
    objects = gen.build_objects(regions, random.Random(SEED))
    assert hashlib.sha256(repr(objects).encode("utf-8")).hexdigest() == OBJECT_LIST_DIGEST_1MIB


def test_r_a2l_def_59_4_every_seed_of_the_definitions_case_builds_and_decodes_to_its_plan(tmp_path):
    """R-A2L-DEF.59/4 (CR-6; E5 fix pass) - seeds 1 ... 5: the enum's planned text is the text the model decodes.

    The enum raw is drawn from the seed; its planned text must follow the draw.  Non-vacuity: the five seeds do not
    all draw one raw (a fixed planned text would pass for the seeds that draw it).
    """
    m = _model()
    seen_texts = set()
    for seed in range(1, 6):
        folder = tmp_path / f"seed_{seed}"
        result = _run_cli(folder, "--seed", str(seed), "--case", "definitions")
        assert result.returncode == 0, (seed, result.stderr)
        a2l = parse_a2l_file(folder / "definitions.a2l")
        image = S19File(str(folder / "definitions.s19")).get_memory_map()
        _regions, objects = gen.build_definition_objects(random.Random(seed))
        for obj in objects:
            got = _defc_decode(m, obj, a2l, image)
            if got is None:
                continue                                                   # an AXIS_PTS axis record
            assert got == _defc_plan(obj), (seed, obj["name"], got, _defc_plan(obj))
            if obj["name"] == "ENUM_0001":
                seen_texts.add(got[0][1])
    assert len(seen_texts) >= 2, seen_texts


# ==========================================================================
# R-A2L-DEF.60 ... .63 - the definitions case
# ==========================================================================


@pytest.fixture(scope="module")
def defc(tmp_path_factory: pytest.TempPathFactory) -> dict:
    """The definitions case through the shipped CLI, plus the generator's own object list."""
    folder = tmp_path_factory.mktemp("b103_defc")
    result = _run_cli(folder, "--seed", str(SEED), "--case", "definitions")
    assert result.returncode == 0, result.stderr
    _regions, objects = gen.build_definition_objects(random.Random(SEED))
    return {
        "dir": folder,
        "a2l_path": folder / "definitions.a2l",
        "a2l_text": (folder / "definitions.a2l").read_text(encoding="utf-8"),
        "a2l": parse_a2l_file(folder / "definitions.a2l"),
        "mem": S19File(str(folder / "definitions.s19")).get_memory_map(),
        "objs": {o["name"]: o for o in objects},
    }


def test_r_a2l_def_60_1_the_definitions_case_has_an_enum_with_a_default(defc):
    """R-A2L-DEF.60/1 - ENUM_0001: kind enum, >= 3 pairs, a DEFAULT_VALUE, decodes to the planned pair's text."""
    m = _model()
    Decoded, decode_definition, describe_definition = m.Decoded, m.decode_definition, m.describe_definition
    obj = defc["objs"]["ENUM_0001"]
    d = describe_definition("ENUM_0001", defc["a2l"])
    assert d.refusal is None and d.kind == "enum"
    assert len(d.enum_entries) >= 3 and d.default_text is not None
    assert obj["planned_stored"] in {e.raw for e in d.enum_entries}
    res = decode_definition(d, defc["a2l"], defc["mem"])
    assert isinstance(res, Decoded) and res.text == obj["planned_text"]
    # the design pins at seed 20260001 (graph-inc2.md "The definitions case")
    assert (d.address, obj["planned_stored"], obj["planned_text"]) == (0x800000, 1, "IDLE")
    assert defc["mem"][0x800000] == 0x01


def test_r_a2l_def_61_1_two_disjoint_masks_at_one_address(defc):
    """R-A2L-DEF.61/1 - MASK_BIT_0001 and MASK_FIELD_0001: one address, disjoint masks, popcounts 1 and >= 2."""
    m = _model()
    Decoded, decode_definition, describe_definition = m.Decoded, m.decode_definition, m.describe_definition
    objs = defc["objs"]
    bit, field = objs["MASK_BIT_0001"], objs["MASK_FIELD_0001"]
    assert bit["address"] == field["address"] == 0x800010
    assert bit["bit_mask"] & field["bit_mask"] == 0
    assert (bin(bit["bit_mask"]).count("1"), bin(field["bit_mask"]).count("1")) == (1, 8)
    for name in ("MASK_BIT_0001", "MASK_FIELD_0001"):
        d = describe_definition(name, defc["a2l"])
        assert d.refusal is None and d.bit_mask == objs[name]["bit_mask"]
        res = decode_definition(d, defc["a2l"], defc["mem"])
        assert isinstance(res, Decoded) and res.text == objs[name]["planned_text"]
    # design pins at seed 20260001: planned fields 1 and 174 in the word 1A E7
    assert (bit["planned_text"], field["planned_text"]) == ("1", "174")
    assert (defc["mem"][0x800010], defc["mem"][0x800011]) == (0x1A, 0xE7)


def test_r_a2l_def_62_1_the_display_object_has_format_unit_and_wider_extended_limits(defc):
    """R-A2L-DEF.62/1 - DISPLAY_0001: FORMAT, PHYS_UNIT, EXTENDED_LIMITS wider than the limits."""
    describe_definition = _model().describe_definition
    block = re.search(r"/begin CHARACTERISTIC DISPLAY_0001.*?/end CHARACTERISTIC", defc["a2l_text"], re.S)
    assert block, "DISPLAY_0001 is not in definitions.a2l"
    text = block.group(0)
    assert re.search(r"^\s*FORMAT\s+\"[^\"]+\"", text, re.M)
    unit = re.search(r"^\s*PHYS_UNIT\s+\"([^\"]*)\"", text, re.M)
    assert unit, "no PHYS_UNIT line"
    ext = re.search(r"^\s*EXTENDED_LIMITS\s+(\S+)\s+(\S+)", text, re.M)
    assert ext, "no EXTENDED_LIMITS line"
    d = describe_definition("DISPLAY_0001", defc["a2l"])
    assert d.refusal is None
    assert d.unit == unit.group(1) == "deg C"
    assert d.extended_limits.lower < d.limits.lower and d.extended_limits.upper > d.limits.upper
    assert (d.limits.lower, d.limits.upper) == (-40, 150)
    assert (d.extended_limits.lower, d.extended_limits.upper) == (float(ext.group(1)), float(ext.group(2)))
    assert d.display_format == "%.1"


def test_r_a2l_def_63_1_the_definitions_case_is_deterministic(tmp_path):
    """R-A2L-DEF.63/1 - two runs, same seed, two folders: every file byte-identical."""
    a, b = tmp_path / "run_a", tmp_path / "run_b"
    for folder in (a, b):
        result = _run_cli(folder, "--seed", str(SEED), "--case", "definitions")
        assert result.returncode == 0, result.stderr
    names = sorted(p.name for p in a.iterdir())
    assert names == sorted(p.name for p in b.iterdir()) == ["definitions.a2l", "definitions.s19"]
    for name in names:
        assert (a / name).read_bytes() == (b / name).read_bytes(), name


def test_at_b103_i2_2_the_definitions_case_decodes_to_its_planned_values_through_the_loaders(defc):
    """AT-B103-I2-2 (2a arm) - build and decode each DEFC object to its planned value.

    Rows .60, .61, .62. The write arm (encode the planned text and a second
    value, apply, decode again; rows .46, .48, .55, .56) waits for 2b.
    """
    m = _model()
    Decoded, decode_definition, describe_definition = m.Decoded, m.decode_definition, m.describe_definition
    image = defc["mem"]
    assert sorted(image) == list(range(0x800000, 0x800100))
    for name, obj in defc["objs"].items():
        got = _defc_decode(m, obj, defc["a2l"], image)
        if got is None:
            continue                                                       # an AXIS_PTS axis record
        assert got == _defc_plan(obj), (name, got, _defc_plan(obj))
    display = decode_definition(describe_definition("DISPLAY_0001", defc["a2l"]), defc["a2l"], image)
    assert display.value == pytest.approx(143.5) and display.text == "143.5"
    assert (image[0x800020], image[0x800021]) == (0x01, 0x1F)


# --------------------------------------------------------------------------
# Inc 2b (G-T2) - the write arm of AT-B103-I2-2 and the DEFC masked writes
# (.138/16, .46/3).  Rows .46, .48, .55, .56, .138.  Expected bytes from the
# graph's AT-B103-I2-2 / .138/16 examples over the seed-20260001 word 0x1AE7.
# --------------------------------------------------------------------------

_SCALAR_DEFC = ("ENUM_0001", "MASK_BIT_0001", "MASK_FIELD_0001", "DISPLAY_0001")


def test_r_a2l_def_138_16_two_disjoint_masks_still_encode(defc):
    """R-A2L-DEF.138/16 - DEFC's two disjoint masks of one word both encode, no OVERLAP."""
    m = _model()
    image = defc["mem"]
    bit = m.describe_definition("MASK_BIT_0001", defc["a2l"])
    field = m.describe_definition("MASK_FIELD_0001", defc["a2l"])
    assert bit.shared_with is None and field.shared_with is None
    assert m.encode_definition(bit, defc["a2l"], "0", image) == m.Encoded(0x800010, bytes([0x1A, 0xE6]), ())
    assert m.encode_definition(field, defc["a2l"], "3", image) == m.Encoded(0x800010, bytes([0x10, 0x37]), ())


def test_r_a2l_def_46_3_two_fields_of_one_big_endian_word(defc):
    """R-A2L-DEF.46/3 - write the multi-bit field, then decode both masked objects over the applied image."""
    m = _model()
    field = m.describe_definition("MASK_FIELD_0001", defc["a2l"])
    bit = m.describe_definition("MASK_BIT_0001", defc["a2l"])
    res = m.encode_definition(field, defc["a2l"], "3", defc["mem"])
    assert isinstance(res, m.Encoded)
    new_image = dict(defc["mem"])
    new_image.update({0x800010 + i: b for i, b in enumerate(res.data)})
    assert m.decode_definition(field, defc["a2l"], new_image).text == "3"
    assert m.decode_definition(bit, defc["a2l"], new_image).text == "1"


def test_at_b103_i2_2_write_arm_encodes_planned_then_a_second_value(defc):
    """AT-B103-I2-2 (2b arm) - encode each DEFC scalar's planned text, apply, then a second value.

    ENUM_0001 IDLE -> FAULT (03); MASK_FIELD_0001 174 -> 3 (word 0x1037) with MASK_BIT_0001
    still 1; MASK_BIT_0001 1 -> 0 (0x1036); DISPLAY_0001 143.5 -> -12.5 (FF E7); every other
    byte of the region unchanged.
    """
    m = _model()
    second = {"ENUM_0001": "FAULT", "MASK_BIT_0001": "0", "MASK_FIELD_0001": "3", "DISPLAY_0001": "-12.5"}
    base_image = defc["mem"]
    image = dict(base_image)
    for name in _SCALAR_DEFC:
        d = m.describe_definition(name, defc["a2l"])
        assert d.shared_with is None, (name, d.shared_with)
        planned = m.decode_definition(d, defc["a2l"], image)
        assert isinstance(planned, m.Decoded), (name, planned)
        res = m.encode_definition(d, defc["a2l"], planned.text, image)
        assert isinstance(res, m.Encoded), (name, res)
        image.update({d.address + i: b for i, b in enumerate(res.data)})
        assert m.decode_definition(d, defc["a2l"], image).text == planned.text, name
        res2 = m.encode_definition(d, defc["a2l"], second[name], image)
        assert isinstance(res2, m.Encoded), (name, res2)
        image.update({d.address + i: b for i, b in enumerate(res2.data)})
        assert m.decode_definition(d, defc["a2l"], image).text == second[name], name
    # the four scalars' final bytes, everything else untouched
    assert image[0x800000] == 0x03
    assert (image[0x800010], image[0x800011]) == (0x10, 0x36)
    assert (image[0x800020], image[0x800021]) == (0xFF, 0xE7)
    written = {0x800000, 0x800010, 0x800011, 0x800020, 0x800021}
    for addr, b in base_image.items():
        if addr not in written:
            assert image[addr] == b, hex(addr)


# --------------------------------------------------------------------------
# Inc 3b: only the waiting edit arms of the five mixed Inc 3 cases.
# --------------------------------------------------------------------------

import copy as _copy3b

from tests.support.b103_a2l_arrays import img as _img3b
from tests.test_b103_a2l_definition import _assert_display_agrees as _display_agrees3b
from tests.test_b103_a2l_definition_arrays_decode import v171 as arrays_v171  # noqa: F401


@pytest.fixture(scope="module")
def arrays_c08(tmp_path_factory: pytest.TempPathFactory) -> dict:
    folder = tmp_path_factory.mktemp("b103_i3b_c08_write")
    gen.generate(folder, SEED, 1.0)
    regions = gen.compute_region_sizes(1.0)
    objects = gen.build_objects(regions, random.Random(SEED))
    return {
        "dir": folder,
        "a2l": parse_a2l_file(folder / "firmware.a2l"),
        "a2l_issues": parse_a2l_file(folder / "firmware_issues.a2l"),
        "mem": S19File(str(folder / "firmware.s19")).get_memory_map(),
        "by_name": {o["name"]: o for o in objects},
    }


def _encode3b(m, d, a2l_data, edit, image):
    assert hasattr(m, "encode_values"), "encode_values not implemented"
    res = m.encode_values(d, a2l_data, edit, image)
    assert isinstance(res, m.Encoded), (d.name, res)
    return res


def _decode3b(m, d, a2l_data, image):
    res = m.decode_values(d, a2l_data, image)
    assert isinstance(res, m.DecodedValues), (d.name, res)
    return res


def _positions3b(shape):
    from itertools import product

    return [tuple(reversed(position)) for position in product(*(range(n) for n in reversed(shape)))]


def _apply3b(image, res):
    after = dict(image)
    after.update(_img3b(res.address, res.data))
    return after


def _value_edit3b(m, d, a2l_data, image, position, text):
    d = replace(d, shared_with=None)
    a2l_data = _clear_parse_errors(a2l_data)
    before = _decode3b(m, d, a2l_data, image)
    res = _encode3b(m, d, a2l_data, {position: text}, image)
    after_image = _apply3b(image, res)
    after = _decode3b(m, d, a2l_data, after_image)
    index = _positions3b(d.shape).index(position)
    _display_agrees3b(d, float(text), after.values[index].value)
    for other in _positions3b(d.shape):
        if other != position:
            j = _positions3b(d.shape).index(other)
            assert after.values[j].stored == before.values[j].stored, (d.name, other)
    size = {"UBYTE": 1, "SBYTE": 1, "UWORD": 2, "SWORD": 2, "FLOAT32_IEEE": 4}[d.datatype]
    edited = set(range(d.values_offset, d.values_offset + size))
    for i in range(d.byte_length):
        old = image[d.address + i]
        if i not in edited:
            assert res.data[i] == old, (d.name, i)
    for address, old in image.items():
        if not d.address <= address < d.address + d.byte_length:
            assert after_image[address] == old, (d.name, hex(address))
    return res, after_image


def _v171_write_definitions(m, v171):
    names = [t["name"] for t in v171["tags"]]
    defs = m.describe_definitions(names, v171)
    return {
        name: d
        for name, d in defs.items()
        if d.kind in ("array", "curve", "map") and d.refusal is None
    }


def _v171_write_image(defs):
    image = {}
    for d in defs.values():
        image.update(_img3b(d.address, bytes(d.byte_length)))
    swords = lambda values: b"".join(int(v).to_bytes(2, "little", signed=True) for v in values)
    image.update(_img3b(0x810100, swords(range(1, 13))))
    image.update(_img3b(0x810120, swords(range(1, 13))))
    image.update(_img3b(0x13A30, bytes(range(64))))
    for address, count in ((0x810320, 8), (0x810330, 8), (0x810350, 6), (0x810360, 6), (0x810370, 6), (0x810440, 24)):
        image.update(_img3b(address, swords(range(count))))
    image.update(_img3b(0x810340, bytes([8, 0x46, 0x3C, 0x32, 0x28, 0x1E, 0x14, 0x0A, 0x00])))
    return image


def test_r_a2l_def_58_1_arr_1_edit_arm_leaves_v171_inputs_unchanged(arrays_v171):
    m = _model()
    defs = _v171_write_definitions(m, arrays_v171)
    assert len(defs) == 20, len(defs)
    image = _v171_write_image(defs)
    a2l_before = _copy3b.deepcopy(arrays_v171)
    image_before = dict(image)
    for d in defs.values():
        decoded = _decode3b(m, d, arrays_v171, image)
        position = (0,) * len(d.shape)
        _value_edit3b(m, d, arrays_v171, image, position, decoded.values[0].text)
    assert arrays_v171 == a2l_before and image == image_before


def test_r_a2l_def_58_1_arr_2_edit_arm_leaves_case08_inputs_unchanged(arrays_c08):
    m = _model()
    a2l_data = arrays_c08["a2l"]
    a2l_before = _copy3b.deepcopy(a2l_data)
    image = arrays_c08["mem"]
    image_before = dict(image)
    edited = 0
    for kind, count in (("VAL_BLK", 60), ("CURVE", 60), ("MAP", 20)):
        for i in range(1, count + 1):
            d = m.describe_definition(f"{kind}_{i:04d}", a2l_data)
            decoded = _decode3b(m, d, a2l_data, image)
            _value_edit3b(m, d, a2l_data, image, (0,) * len(d.shape), decoded.values[0].text)
            edited += 1
    assert edited == 140
    assert a2l_data == a2l_before and image == image_before


def test_at_b103_i3_1_edit_arm_asam_demo_arrays_and_axes(arrays_v171):
    m = _model()
    defs = _v171_write_definitions(m, arrays_v171)
    assert len(defs) == 20
    image = _v171_write_image(defs)
    for d in defs.values():
        decoded = _decode3b(m, d, arrays_v171, image)
        old = decoded.values[0].value
        _value_edit3b(m, d, arrays_v171, image, (0,) * len(d.shape), format(float(old) + 1, ".17g"))
    for name, offset in (("ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR", 2), ("ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.COLUMN_DIR", 8)):
        d = m.describe_definition(name, arrays_v171)
        res = _encode3b(m, d, arrays_v171, {(1, 0): "-7"}, image)
        assert res.data[offset:offset + 2] == b"\xf9\xff"


def test_at_b103_i3_2_edit_arm_definitions_case(defc):
    m = _model()
    image = dict(defc["mem"])
    for name in ("CURVE_DEF_0001", "CURVE_DEF_0002", "MAP_DEF_0001", "VAL_BLK_DEF_0001"):
        d = m.describe_definition(name, defc["a2l"])
        obj = defc["objs"][name]
        position = (0,) * len(d.shape)
        _res, image = _value_edit3b(m, d, defc["a2l"], image, position, obj["planned_text"][1])

    d = m.describe_definition("MAP_DEF_0001", defc["a2l"])
    res = _encode3b(m, d, defc["a2l"], {("X", 1): "600"}, image)
    assert res.data[2:4] == b"\x02\x58"
    image = _apply3b(image, res)
    decoded = _decode3b(m, d, defc["a2l"], image)
    assert [p.stored for p in decoded.axes[0].points] == [224, 600, 648, 909]

    curve_d = m.describe_definition("CURVE_DEF_0001", defc["a2l"])
    common = m.encode_values(curve_d, defc["a2l"], {("X", 0): "242.500"}, defc["mem"])
    assert common == m.Refusal(
        "A2L-DEF-AXIS-SHARED",
        "CURVE_DEF_0001.X[0]: the points of the common axis AXIS_DEF_0001 are not edited through CURVE_DEF_0001",
    )
    refusal = m.encode_values(d, defc["a2l"], {("X", 2): "100"}, image)
    assert refusal == m.Refusal("A2L-DEF-MONOTONY", "MAP_DEF_0001.X[2]: 100 breaks the STRICT_INCREASE order of the axis")


def test_at_b103_i3_3_edit_arm_case08_arrays(arrays_c08):
    m = _model()
    edited = 0
    for original in (arrays_c08["a2l"], arrays_c08["a2l_issues"]):
        a2l_data = _copy3b.deepcopy(original)
        a2l_data["errors"] = []
        for kind, count in (("VAL_BLK", 60), ("CURVE", 60), ("MAP", 20)):
            for i in range(1, count + 1):
                d = m.describe_definition(f"{kind}_{i:04d}", a2l_data)
                decoded = _decode3b(m, d, a2l_data, arrays_c08["mem"])
                text = decoded.values[1].text
                _value_edit3b(m, d, a2l_data, arrays_c08["mem"], (0,) * len(d.shape), text)
                edited += 1
    assert edited == 280
    assert case08_file_digests(arrays_c08["dir"]) == CASE08_PIN_1MIB
