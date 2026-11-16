"""Batch-103 Inc 8, group A (staging and help): the shared fixtures of the three ``test_b103_inc8_a*`` files.

Everything here is synthetic. The DEFC case is the generator's own ``--case definitions`` output (seed
20260001, the one the Inc 2 tests use); V171 is the public demo A2L with the pilot's hand image
(``evidence-e1/pilot_inc8.py``). Expected values are never retyped: they are computed through I-2
(``describe_definitions`` / ``encode_definition`` / ``decode_definition``) by the tests.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SEED = 20260001
V171_A2L = REPO_ROOT / "examples" / "case_00_public" / "ASAP2_Demo_V171.a2l"
V171_ASCII = "ASAM.C.ASCII.UBYTE.NUMBER_42"
V171_ASCII_ADDRESS = 0x810200

DEFC_NAMES = ("ENUM_0001", "MASK_BIT_0001", "MASK_FIELD_0001", "DISPLAY_0001")
MASK_WORD = 0x800010
DISPLAY_ADDRESS = 0x800020
DISPLAY_MOVED_ADDRESS = 0x800030


def build_defc(folder: Path) -> dict:
    """The definitions case through the shipped CLI, parsed through the app's own loaders."""
    from s19_app.core import S19File
    from s19_app.tui.a2l_definition import describe_definitions
    from s19_app.tui.a2l_parse import parse_a2l_file

    result = subprocess.run(
        [sys.executable, "-B", str(REPO_ROOT / "tools" / "synth" / "make_release_case.py"),
         "--out", str(folder), "--seed", str(SEED), "--case", "definitions"],
        capture_output=True, text=True, timeout=600,
    )
    assert result.returncode == 0, result.stderr
    a2l_path = folder / "definitions.a2l"
    s19_path = folder / "definitions.s19"
    a2l = parse_a2l_file(a2l_path)
    image = S19File(str(s19_path)).get_memory_map()
    return {
        "dir": folder, "a2l_path": a2l_path, "s19_path": s19_path, "a2l": a2l,
        "image": dict(image), "defs": describe_definitions(DEFC_NAMES, a2l),
    }


def moved_display_a2l(defc: dict, target: Path) -> Path:
    """A copy of the DEFC A2L whose DISPLAY_0001 sits at 0x800030 (R-PE-DEF.64's reload)."""
    text = defc["a2l_path"].read_text(encoding="utf-8")
    old = f"VALUE 0x{DISPLAY_ADDRESS:08X} RL_S16"
    assert text.count(old) == 1, "the DISPLAY_0001 declaration moved in the generator"
    target.write_text(text.replace(old, f"VALUE 0x{DISPLAY_MOVED_ADDRESS:08X} RL_S16"), encoding="utf-8", newline="\n")
    return target


def v171() -> dict:
    """V171 with the pilot's hand image: 'Hello ASAM' + 32 NUL at the 42-byte ASCII object."""
    from s19_app.tui.a2l_definition import describe_definitions
    from s19_app.tui.a2l_parse import parse_a2l_file

    a2l = parse_a2l_file(V171_A2L)
    image = {V171_ASCII_ADDRESS + i: b for i, b in enumerate(b"Hello ASAM" + bytes(32))}
    return {"a2l": a2l, "image": image, "defs": describe_definitions([V171_ASCII], a2l)}


def overlay_of(image, entries) -> dict:
    """An independent overlay: the image with every entry's bytes written in document order."""
    view = dict(image)
    for entry in entries:
        for offset, byte in enumerate(entry.encoded_bytes):
            view[entry.address + offset] = byte
    return view


def entry_tuples(service) -> list:
    """The document's entries as plain tuples, to compare before and after."""
    return [(e.entry_type, e.address, tuple(e.encoded_bytes), e.value, e.symbol) for e in service.document.entries]
