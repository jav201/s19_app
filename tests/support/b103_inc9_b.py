"""Inc 9 E4 group B (tests): the shared support of the ``test_b103_inc9_b_*`` files.

Pure model ``s19_app/tui/definition_bench.py`` and pure render ``s19_app/tui/definition_bench_view.py``.

* ``EX`` / ``EX3`` are the committed example oracles of E1 / E3R1 (``evidence-e1/examples_inc9.py``,
  ``evidence-e2/examples_e3r1.py``) loaded as modules: ramp steps, short numbers, result texts, strips.
  Expected values come from them, from I-2 or from the requirement's own text, never from the code under test.
* ``defc`` is Inc 8's DEFC fixture (``tests/support/b103_inc8_s1.py``); hand A2Ls (LARGE, F32_BLK, ...) are
  built with ``tests/support/b103_a2l_arrays.py``. Everything is synthetic.
* ``blank_state`` builds a ``BenchState`` field by field from the dataclass, so a test names only the fields
  it cares about and an extra field (E3A-12 ``status``) needs no change here.
"""

from __future__ import annotations

import contextlib
import dataclasses
import gc
import importlib.util
import io
import math
from array import array
from pathlib import Path

from rich.cells import cell_len
from rich.console import Console
from rich.text import Text

from s19_app.tui import definition_bench as db
from s19_app.tui import definition_bench_view as dv
from s19_app.tui import definition_sheet as ds
from s19_app.tui.a2l_definition import (
    Decoded,
    DecodedValues,
    Encoded,
    Refusal,
    decode_values,
    describe_definition,
    encode_values,
)
from tests.support.b103_a2l_arrays import img, inline, valblk
from tests.support.b103_inc8_s1 import defc  # noqa: F401  (a session fixture, used by name)

ROOT = Path(__file__).resolve().parents[2]
INC9 = ROOT / ".dev-flow" / "2026-11-05-batch-103" / "inc-9"
FFFD = "�"
GAP_OLD_NEW = " → "
_CONSOLE = Console(color_system="truecolor", force_terminal=True, width=400)


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    with contextlib.redirect_stdout(io.StringIO()):
        spec.loader.exec_module(module)
    return module


EX = _load(INC9 / "evidence-e1" / "examples_inc9.py", "b103_inc9_examples")
EX3 = _load(INC9 / "evidence-e2" / "examples_e3r1.py", "b103_inc9_examples_e3r1")

_STATE_DEFAULTS = dict(
    cursor=(0, 0), anchor=(0, 0), tool="s", undo=(), origin=(0, 0), focus=False, values=None,
    staged=None, axes=(), preview=None, job=None, runs=(), lo=0.0, hi=0.0, strip=None, labels=None,
)


def blank_state(**over):
    """A ``BenchState`` of a fresh row (cursor (0,0), tool Set, empty edit) with ``over`` applied."""
    names = {f.name for f in dataclasses.fields(db.BenchState)}
    assert set(over) <= names, f"BenchState has no field {set(over) - names}"
    kw = {n: _STATE_DEFAULTS.get(n) for n in names}
    kw["edit"] = {}
    kw.update(over)
    return db.BenchState(**kw)


@dataclasses.dataclass
class Obj:
    """One bench object: definition, payload, image, grid, I-2 decode and the compact values."""

    d: object
    a2l: dict
    image: dict
    grid: object
    decoded: object
    values: object
    axes: tuple


def make_obj(a2l: dict, image: dict, definition) -> Obj:
    decoded = decode_values(definition, a2l, image)
    assert isinstance(decoded, DecodedValues), decoded
    return Obj(definition, a2l, dict(image), db.bench_grid(definition), decoded,
               db.BenchValues.from_decoded(decoded), decoded.axes)


def defc_obj(defc_case: dict, name: str) -> Obj:
    return make_obj(defc_case["a2l"], defc_case["image"], defc_case["defs"][name])


def numbers_of(decoded) -> list:
    """The element numbers of an I-2 decode (a refusal element: None)."""
    return [v.value if isinstance(v, Decoded) else None for v in decoded.values]


def finite_lo_hi(numbers) -> tuple[float, float]:
    finite = [x for x in numbers if x is not None and math.isfinite(x)]
    return (min(finite), max(finite)) if finite else (0.0, 0.0)


def view_state(o: Obj, **over):
    """A state that a render sees after ``_job_done``: values, axes, labels, finite lo / hi stored."""
    lo, hi = finite_lo_hi(numbers_of(o.decoded))
    kw = dict(values=o.values, axes=o.axes, lo=lo, hi=hi, labels=dv.axis_labels(o.d, o.axes, o.grid))
    kw.update(over)
    return blank_state(**kw)


def sheet_row(definition, a2l, image, entries=()):
    """The Inc 8 ``SheetRow`` of a definition (built over the image and the staged overlay)."""
    overlay = ds.StagedOverlay(image, list(entries))
    return ds.build_row(definition, a2l, image, overlay)


def staged_entry(o: Obj, edit: dict) -> tuple[int, bytes]:
    """The document entry a record stage of ``edit`` writes, encoded by I-2 over the image."""
    enc = encode_values(o.d, o.a2l, edit, o.image)
    assert isinstance(enc, Encoded), enc
    return enc.address, bytes(enc.data)


def staged_values(o: Obj, edit: dict):
    """(BenchValues over the staged overlay, the entry) for a record of ``edit``."""
    address, data = staged_entry(o, edit)
    over = dict(o.image)
    over.update({address + i: b for i, b in enumerate(data)})
    decoded = decode_values(o.d, o.a2l, over)
    return db.BenchValues.from_decoded(decoded), (address, data)


def runs_of(old: bytes, new: bytes) -> tuple:
    """The runs of changed bytes in record order: (offset, old bytes, new bytes)."""
    runs, i = [], 0
    while i < len(old):
        if old[i] == new[i]:
            i += 1
            continue
        j = i
        while j < len(old) and old[j] != new[j]:
            j += 1
        runs.append((i, bytes(old[i:j]), bytes(new[i:j])))
        i = j
    return tuple(runs)


def hex_up(data: bytes) -> str:
    return " ".join(f"{b:02X}" for b in data)


def style_at(text: Text, offset: int):
    return text.get_style_at_offset(_CONSOLE, offset)


def ramp_id(text: Text, offset: int) -> tuple:
    style = style_at(text, offset)
    return (style.color, style.bgcolor)


def bg_at(text: Text, offset: int):
    return style_at(text, offset).bgcolor


def same_partition(keys: list, ids: list) -> bool:
    """True when ``ids`` equal exactly where ``keys`` equal (the ramp step classes)."""
    return all((keys[i] == keys[j]) == (ids[i] == ids[j])
               for i in range(len(keys)) for j in range(i + 1, len(keys)))


def locate(lines: list, token: str) -> tuple[int, int]:
    """(line index, offset) of the first ``token`` in the plain lines; fails when absent."""
    for index, line in enumerate(lines):
        at = line.plain.find(token)
        if at >= 0:
            return index, at
    raise AssertionError(f"{token!r} is not in the painted lines: {[l.plain for l in lines]}")


def plain_of(lines) -> list[str]:
    return [line.plain for line in lines]


def max_cells(lines) -> int:
    return max((cell_len(line.plain) for line in lines), default=0)


def linked(text: Text) -> bool:
    """True when a span of ``text`` carries a link or a meta action (an ``@click``)."""
    for span in text.spans:
        style = span.style
        if not isinstance(style, str) and (getattr(style, "link", None) or getattr(style, "meta", None)):
            return True
        if isinstance(style, str) and ("link" in style or "@click" in style):
            return True
    return False


# ---------------------------------------------------------------------------- hand objects


def hand_object(tmp_path, name: str, layout: str, count: int, image_bytes: bytes = b"",
                conv: str = "NO_COMPU_METHOD", lo: str = "-1000", hi: str = "1000", blocks=()) -> Obj | tuple:
    """A hand VAL_BLK of ``count`` elements at 0x10; with ``image_bytes`` the decoded ``Obj``,
    else ``(a2l, definition)``."""
    a2l = inline(tmp_path, *blocks, valblk(name, "0x10", layout, conv, lo, hi, f"MATRIX_DIM {count}"))
    definition = describe_definition(name, a2l)
    if not image_bytes:
        return a2l, definition
    return make_obj(a2l, img(0x10, image_bytes), definition)


def large_definition(tmp_path):
    """LARGE: one VAL_BLK UBYTE ``MATRIX_DIM 1048576``, NO_COMPU_METHOD (never decoded by I-2 here)."""
    return hand_object(tmp_path, "LARGE", "RL_U8", 1048576, lo="0", hi="255")


def big_values(count: int):
    """A compact ``BenchValues`` of ``count`` zeros (8 B each), built without the I-2 decode."""
    return db.BenchValues(numbers=array("d", bytes(8 * count)), texts=None, missing=frozenset())


def decoded_of(*items) -> DecodedValues:
    """A hand ``DecodedValues`` (no axes): a number item is ``(value, text)``, else a Decoded or a Refusal."""
    out = []
    for item in items:
        if isinstance(item, tuple):
            out.append(Decoded(stored=item[0], value=item[0], text=item[1]))
        else:
            out.append(item)
    return DecodedValues(values=tuple(out), axes=())


def gc_collect() -> None:
    gc.collect()
