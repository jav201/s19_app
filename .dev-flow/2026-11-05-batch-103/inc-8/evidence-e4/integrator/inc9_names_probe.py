"""Inc 8 E4 integrator probe for Inc 9 (E3A-10, E3S-06): run with pytest from the repo root.

    pytest -p no:cacheprovider -q -s .dev-flow/2026-11-05-batch-103/inc-8/evidence-e4/integrator/inc9_names_probe.py

(1) every Inc 8 name Inc 9 reads (Inc 9 graph §Interfaces, "Inc 8 names Inc 9 reads") exists with that
name and shape on the integrated tree; (2) the image lookups of Inc 8's `staged` on a 1 MiB entry (a count,
never a timing: HT-08). Prints `NAME.*` and `COST.*` lines.
"""
from __future__ import annotations

import dataclasses

from rich.text import Text

from s19_app.tui import definition_sheet as ds
from tests.support.b103_inc8_s1 import SpanImage, replace, v171  # noqa: F401  (fixture used by name)

MIB = 1 << 20


def _row(definition, a2l, image, entries):
    overlay = ds.StagedOverlay(image, entries)
    return ds.build_row(definition, a2l, image, overlay), overlay


def test_inc8_names_inc9_reads(v171):
    fields = {f.name for f in dataclasses.fields(ds.SheetRow)}
    for name in ("name", "definition", "kind", "current", "staged", "is_staged"):
        assert name in fields, name
        print(f"NAME.SheetRow.{name} = present")
    for name in ("kind", "current", "new", "limits", "delta"):
        assert name in ds.SheetWidths._fields and isinstance(getattr(ds.sheet_widths(118), name), int), name
        print(f"NAME.SheetWidths.{name} = int")
    assert [f.name for f in dataclasses.fields(ds.Preview)] == ["result", "decoded"]
    print("NAME.Preview = (result, decoded)")
    assert isinstance(ds.short_number(143.5), str) and ds.plain("A\x1bB") == "A�B"
    assert isinstance(ds.name_echo("x" * 300), str)
    print("NAME.short_number, plain, name_echo = callables (str -> str)")
    assert ds.KindOps._fields == (
        "label", "editable", "decode", "value_text", "staged", "preview", "detail", "submit", "cells", "bar", "mark",
    )
    print(f"NAME.KindOps._fields = {ds.KindOps._fields}")
    assert ds.ops_for("array") is ds._FALLBACK_OPS and set(ds._KIND_OPS) == {"number", "bit mask", "enum", "text"}
    print(f"NAME._KIND_OPS = {sorted(ds._KIND_OPS)}; ops_for('array') is _FALLBACK_OPS")
    array = replace(v171["def"], kind="array", element_count=24)
    row, _ = _row(array, v171["a2l"], v171["image"], [])
    line = ds._FALLBACK_OPS.detail(row, None, 118, None, 1)[0]
    assert isinstance(line, Text) and line.plain.startswith("└ ")
    print(f"NAME._FALLBACK_OPS.detail(row, None, 118, None, 1)[0] = {line.plain!r}")


def test_inc8_staged_cost_on_a_1mib_entry(v171):
    base = v171["def"]
    for kind in ("array", "text"):
        definition = replace(base, kind=kind, byte_length=MIB, element_count=MIB // 2)
        for label, data in (("equal", bytes([0x41]) * MIB), ("last_differs", bytes([0x41]) * (MIB - 1) + b"\x42")):
            image = SpanImage(definition.address, MIB, 0x41)
            entries = [(definition.address, data)]
            row, overlay = _row(definition, v171["a2l"], image, entries)
            built = image.lookups
            image.lookups = 0
            staged = ds.ops_for(row.kind).staged(row, image, overlay)
            print(f"COST.{kind}.{label}.build_row_lookups = {built}")
            print(f"COST.{kind}.{label}.staged_lookups = {image.lookups} (is_staged {staged})")
            assert staged is (label == "last_differs")
            assert image.lookups <= MIB
