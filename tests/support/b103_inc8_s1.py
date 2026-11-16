"""Inc 8 group S1 test support: the examples, the fixtures and the cell reader.

Shared by ``tests/test_b103_inc8_s1.py`` and ``tests/test_b103_inc8_s1_detail.py``
(the pure model ``s19_app/tui/definition_sheet.py``). Nothing here imports the
module under test.

* ``EX`` is the committed examples file of E2 (``evidence-e2/examples_inc8.py``)
  loaded as a module: its widths, short numbers and ruler cells are the
  expected values, computed by that file and never retyped here.
* ``defc`` / ``v171`` are the two fixtures of the pilot: DEFC
  (``tools/synth/make_release_case.py --case definitions``, seed 20260001) and
  ``ASAP2_Demo_V171.a2l`` with the hand image of the pilot (``Hello ASAM`` and
  32 NUL bytes at the ASCII object's address).
* Every Definition the model reads is produced by I-2 (``describe_definition``)
  or is a ``dataclasses.replace`` copy of one (the widened text spans, the
  ``cuboid`` copy, the limit copies, a renamed object); nothing is hand-built.
"""

from __future__ import annotations

import contextlib
import dataclasses
import importlib.util
import io
import sys
from pathlib import Path
from typing import Iterator, Mapping

import pytest
from rich.cells import cell_len

REPO_ROOT = Path(__file__).resolve().parents[2]
SYNTH_DIR = REPO_ROOT / "tools" / "synth"
EXAMPLES_FILE = (
    REPO_ROOT / ".dev-flow" / "2026-11-05-batch-103" / "inc-8" / "evidence-e2" / "examples_inc8.py"
)
V171_FILE = REPO_ROOT / "examples" / "case_00_public" / "ASAP2_Demo_V171.a2l"
SEED = 20260001
V171_ASCII = "ASAM.C.ASCII.UBYTE.NUMBER_42"
V171_MEASUREMENT = "ASAM.M.SCALAR.UBYTE.IDENTICAL"
FFFD = "�"

if str(SYNTH_DIR) not in sys.path:
    sys.path.insert(0, str(SYNTH_DIR))

import make_release_case as gen  # noqa: E402

from s19_app.core import S19File  # noqa: E402
from s19_app.tui.a2l_definition import (  # noqa: E402
    Definition,
    Limits,
    describe_definition,
    describe_definitions,
    encode_definition,
)
from s19_app.tui.a2l_parse import parse_a2l_file  # noqa: E402

replace = dataclasses.replace


class _Sink(io.StringIO):
    """A stdout stand-in that has ``reconfigure`` (the examples file calls it)."""

    def reconfigure(self, **_kwargs) -> None:
        return None


def _load_examples():
    spec = importlib.util.spec_from_file_location("b103_inc8_examples", EXAMPLES_FILE)
    module = importlib.util.module_from_spec(spec)
    with contextlib.redirect_stdout(_Sink()):
        spec.loader.exec_module(module)
    return module


EX = _load_examples()


class SpanImage(Mapping):
    """A lazy image: ``length`` bytes of ``fill`` from ``start``, plus ``extra``.

    Counts every lookup in ``lookups`` so a test can show that the model's work
    is bounded by the document and not by the span (E3S-10).
    """

    def __init__(self, start: int, length: int, fill: int, extra: Mapping[int, int] | None = None):
        self.start, self.length, self.fill = start, length, fill
        self.extra = dict(extra or {})
        self.lookups = 0

    def __getitem__(self, address: int) -> int:
        self.lookups += 1
        if address in self.extra:
            return self.extra[address]
        if self.start <= address < self.start + self.length:
            return self.fill
        raise KeyError(address)

    def __iter__(self) -> Iterator[int]:
        yield from range(self.start, self.start + self.length)
        yield from (a for a in self.extra if not self.start <= a < self.start + self.length)

    def __len__(self) -> int:
        return self.length + sum(1 for a in self.extra if not self.start <= a < self.start + self.length)


def cells(line, widths) -> dict[str, str]:
    """Split a painted row by the column widths, counting terminal cells.

    Inc 8b (R-PE-DEF.90, retargeted by T8b-R): a ``│`` gutter follows each column after the
    2-cell mark, so it is skipped before the next column starts; the returned cell texts
    never hold it.
    """
    plain = line.plain
    out: dict[str, str] = {}
    i = 0
    for key in ("mark", "name", "kind", "current", "new", "unit", "limits", "delta"):
        width = getattr(widths, key)
        taken, used = "", 0
        while i < len(plain) and used + cell_len(plain[i]) <= width:
            taken += plain[i]
            used += cell_len(plain[i])
            i += 1
        out[key] = taken
        if key != "mark" and i < len(plain) and plain[i] == "│":
            i += 1
    return out


def hex_bytes(data) -> str:
    return " ".join(f"{b:02X}" for b in data)


def span_bytes(definition: Definition, image: Mapping[int, int]) -> bytes:
    return bytes(image[definition.address + i] for i in range(definition.byte_length))


def stage_entry(definition: Definition, a2l: dict, text: str, image: Mapping[int, int]) -> tuple[int, bytes]:
    """The document entry a stage of ``text`` writes, encoded by I-2 over ``image``."""
    result = encode_definition(definition, a2l, text, image)
    assert not hasattr(result, "code"), result
    return result.address, bytes(result.data)


def widen(definition: Definition, length: int) -> Definition:
    return replace(definition, byte_length=length)


@pytest.fixture(scope="session")
def defc(tmp_path_factory) -> dict:
    """DEFC: its A2L payload, the S19 image as a dict and the definitions by name."""
    folder = tmp_path_factory.mktemp("b103_inc8_s1_defc")
    paths = gen.generate_definitions_case(folder, SEED)
    a2l = parse_a2l_file(paths["a2l"])
    image = dict(S19File(str(paths["s19"])).get_memory_map())
    names = [t["name"] for t in a2l["tags"]]
    return {"a2l": a2l, "image": image, "defs": describe_definitions(names, a2l)}


@pytest.fixture(scope="session")
def v171() -> dict:
    """V171: the payload, the ASCII object's definition and the hand image."""
    a2l = parse_a2l_file(V171_FILE)
    definition = describe_definition(V171_ASCII, a2l)
    assert definition.byte_length == len(EX.before), "the pilot's hand image is one span"
    image = {definition.address + i: b for i, b in enumerate(EX.before)}
    measurement = describe_definition(V171_MEASUREMENT, a2l)
    return {"a2l": a2l, "def": definition, "image": image, "measurement": measurement}
