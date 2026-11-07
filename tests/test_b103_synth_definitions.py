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
            d = m.describe_definition(obj["name"], a2l)
            assert d.refusal is None, (seed, obj["name"], d.refusal)
            res = m.decode_definition(d, a2l, image)
            assert isinstance(res, m.Decoded), (seed, obj["name"], res)
            assert res.text == obj["planned_text"], (seed, obj["name"], res.text, obj["planned_text"])
            if obj["name"] == "ENUM_0001":
                seen_texts.add(res.text)
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
        d = describe_definition(name, defc["a2l"])
        assert d.refusal is None, (name, d.refusal)
        res = decode_definition(d, defc["a2l"], image)
        assert isinstance(res, Decoded), (name, res)
        assert res.text == obj["planned_text"], name
    display = decode_definition(describe_definition("DISPLAY_0001", defc["a2l"]), defc["a2l"], image)
    assert display.value == pytest.approx(143.5) and display.text == "143.5"
    assert (image[0x800020], image[0x800021]) == (0x01, 0x1F)
