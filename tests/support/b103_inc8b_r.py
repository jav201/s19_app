"""Inc 8b E4 T8b-R: the committed Inc 8b examples, loaded and never retyped.

Shared by the retargeted Inc 8 and Inc 9 tests. Nothing here imports the product.

* ``EXB`` is ``evidence-e1/examples_inc8b.py`` (stdlib only; the formulas of CTX-PE-DEF
  as amended at Inc 8b) loaded as a module: its grid widths, header line and rule, slots,
  limits cells, strips, bit table, hex grid and card frame are the expected values.
* ``fact(key)`` reads one ``KEY = value`` line of the committed transcript
  ``evidence-e1/examples_inc8b-transcript.txt`` (values are ``repr``; a non-literal such
  as ``nan`` comes back as its text).
"""

from __future__ import annotations

import ast
import contextlib
import importlib.util
import io
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
E1_DIR = REPO_ROOT / ".dev-flow" / "2026-11-05-batch-103" / "inc-8b" / "evidence-e1"
EXAMPLES_FILE = E1_DIR / "examples_inc8b.py"
TRANSCRIPT_FILE = E1_DIR / "examples_inc8b-transcript.txt"

BAR = "  ┊ "
GUTTER = "│"


class _Sink(io.StringIO):
    def reconfigure(self, **_kwargs) -> None:
        return None


def _load_examples():
    spec = importlib.util.spec_from_file_location("b103_inc8b_examples", EXAMPLES_FILE)
    module = importlib.util.module_from_spec(spec)
    with contextlib.redirect_stdout(_Sink()):
        spec.loader.exec_module(module)
    return module


EXB = _load_examples()
GRID_WIDTH = EXB.grid_width()
#: (label, start, width) of the seven grid columns, from the oracle's own formula.
COLUMNS = tuple(EXB.column_starts())
#: the offsets of the gutters ``│`` after each column, from the oracle.
GUTTER_AT = tuple(start + width for _label, start, width in COLUMNS)

_FACTS: dict[str, str] | None = None


def fact(key: str):
    """The value of one transcript line ``KEY = value`` (``ast.literal_eval``, else the text)."""
    global _FACTS
    if _FACTS is None:
        table: dict[str, str] = {}
        for line in TRANSCRIPT_FILE.read_text(encoding="utf-8").splitlines():
            name, sep, value = line.partition(" = ")
            if sep:
                table[name] = value
        _FACTS = table
    raw = _FACTS[key]
    try:
        return ast.literal_eval(raw)
    except (ValueError, SyntaxError):
        return raw


def content(line: str) -> str:
    """One expanded-object line as its content: the bar ``  ┊ `` removed, the ground spaces trimmed."""
    assert line.startswith(BAR), line
    return line[len(BAR):].rstrip()
