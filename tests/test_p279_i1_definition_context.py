"""P-279 I1 / G-DEF tests: the describe context of ``a2l_definition``.

Observable outcome only: every equality row compares the context's result with
the bulk ``describe_definitions`` of the same A2L (the oracle). Private seams
and the new API are reached lazily inside each test body, so this module
collects on the base revision and each node fails on its own there.

Requirements: R-A2L-DEF.169 .. R-A2L-DEF.174 (the timing of .173 and the
220,040-name case_06 arms are host-only and have no CI test here).
"""

from __future__ import annotations

import dataclasses
import functools
import hashlib
import importlib
import random
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
_PUBLIC = REPO_ROOT / "examples" / "case_00_public"
CORPUS = {
    "case_01": REPO_ROOT / "examples" / "case_01_basic_valid" / "firmware.a2l",
    "d161": _PUBLIC / "ASAP2_Demo_V161.a2l",
    "d171": _PUBLIC / "ASAP2_Demo_V171.a2l",
    "balance_tube": _PUBLIC / "BalanceTube_STMicro.a2l",
    "software_a": _PUBLIC / "software_a.a2l",
    "software_b": _PUBLIC / "software_b.a2l",
    "from_source": _PUBLIC / "from_source.a2l",
    "from_source_structs": _PUBLIC / "from_source_structs.a2l",
    "memorysegment": _PUBLIC / "memorysegment.a2l",
}
SMALL3 = ("d171", "software_b", "balance_tube")
PAGE_SIZES = (1, 50, 200)
ORDERS = ("forward", "reverse", "shuffle")
SHUFFLE_SEED = 20261120
SAMPLE_SEED = 20261121


def _definition_module():
    return importlib.import_module("s19_app.tui.a2l_definition")


# ----------------------------------------------------------------------------
# Corpus helpers (cached once per fixture)
# ----------------------------------------------------------------------------

@functools.lru_cache(maxsize=None)
def _corpus(key: str) -> dict:
    from s19_app.tui.a2l_parse import parse_a2l_file

    return _bundle(parse_a2l_file(CORPUS[key]))


def _bundle(a2l: dict) -> dict:
    """``names``: the measurable names (enrichment order) the context is built from.

    ``measurable``: the same, de-duplicated. ``unique``: the names the arms
    describe: the measurable names, or every tag name when the A2L has none
    (software_b declares no ECU address, so it has 0 measurable names).
    """
    from s19_app.tui.a2l import enrich_a2l_tags_with_values

    mod = _definition_module()
    names = [t["name"] for t in enrich_a2l_tags_with_values(a2l, None)
             if isinstance(t.get("address"), int)]
    measurable = list(dict.fromkeys(names))
    unique = measurable or list(dict.fromkeys(t["name"] for t in a2l["tags"]))
    return {"a2l": a2l, "names": names, "measurable": measurable, "unique": unique,
            "bulk": mod.describe_definitions(unique, a2l)}


@functools.lru_cache(maxsize=None)
def _context(key: str):
    data = _corpus(key)
    return _definition_module().build_describe_context(data["a2l"], data["names"])


def _fallback_fixtures() -> list:
    return [k for k in CORPUS if not _corpus(k)["measurable"]]


def _ordered(names: list, order: str) -> list:
    out = list(names)
    if order == "reverse":
        out.reverse()
    elif order == "shuffle":
        random.Random(SHUFFLE_SEED).shuffle(out)
    return out


def _pages(names: list, size: int):
    for start in range(0, len(names), size):
        yield names[start:start + size]


def _assert_equal_to_bulk(result: dict, page: list, bulk: dict) -> None:
    assert list(result) == list(dict.fromkeys(page)), "result keys follow the request order"
    for name in page:
        assert result[name] == bulk[name], f"{name!r}: context definition differs from bulk"


def _fmt(definition) -> tuple:
    return (definition.datatype, definition.kind, definition.unit)


# ----------------------------------------------------------------------------
# In-test A2Ls
# ----------------------------------------------------------------------------

def _refused_overlap_a2l(tmp_path: Path) -> dict:
    from tests.support.b103_a2l_arrays import characteristic, inline

    return inline(
        tmp_path,
        characteristic("OOR_A", "VALUE", "0x100", "RL_U8", "NO_COMPU_METHOD", "0", "300"),
        characteristic("OOR_B", "VALUE", "0x100", "RL_U8", "NO_COMPU_METHOD", "0", "70000"),
        characteristic("OK_C", "VALUE", "0x100", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
        characteristic("FAR_D", "VALUE", "0xFFFFFFFE", "RL_U32", "NO_COMPU_METHOD", "0", "255"),
        characteristic("FAR_E", "VALUE", "0xFFFFFFFF", "RL_U32", "NO_COMPU_METHOD", "0", "255"),
        characteristic("PLAIN", "VALUE", "0x300", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
    )


def _two_curves_a2l(tmp_path: Path) -> dict:
    from s19_app.tui.a2l_parse import parse_a2l_file
    from tests.support.b103_a2l_arrays import axis, axis_pts, curve, inline, rl

    axo = axis_pts("AXIS_P", "0x200", "RL_AXP", "4",
                   extras=rl("RL_AXP", "AXIS_PTS_X 1 UWORD INDEX_INCR DIRECT"))

    def ref_axis():
        return axis("COM_AXIS", "CM_IDENT", "8", "0", "255", "AXIS_PTS_REF AXIS_P")

    unterminated = curve("CURVE_C", "0x140", "RL_U16", ref_axis())
    head, _sep, _tail = unterminated.rpartition("/end CHARACTERISTIC")
    inline(
        tmp_path, axo,
        curve("CURVE_A", "0x100", "RL_U16", ref_axis()),
        curve("CURVE_B", "0x120", "RL_U16", ref_axis()),
        head,
    )
    # the file ends inside CURVE_C: drop the closing MODULE / PROJECT lines too
    written = max(tmp_path.glob("inline3_*.a2l"), key=lambda p: p.stat().st_mtime_ns)
    text = written.read_text(encoding="utf-8")
    tail = "  /end MODULE\n/end PROJECT\n"
    assert text.endswith(tail)
    cut = tmp_path / "two_curves_open.a2l"
    cut.write_text(text[: -len(tail)], encoding="utf-8", newline="\n")
    return parse_a2l_file(cut)


def _axis_record_a2l(tmp_path: Path) -> dict:
    """A MAP whose Y axis refers to AXIS_PTS ``AXIS_P``, whose layout gives a
    fixed X count (6) that differs from the point count (4): the map records
    the axis span (its letter is Y, so the fixed X count does not refuse it),
    while the span placed from the layout alone is undefined. ``OVER`` sits
    inside the recorded span, so the order of the two steps is visible in its
    ``shared_with``."""
    from tests.support.b103_a2l_arrays import axis, axis_pts, characteristic, inline, mapchar, rl

    axo = axis_pts("AXIS_P", "0x200", "RL_AXP", "4",
                   extras=rl("RL_AXP", "AXIS_PTS_X 1 UWORD INDEX_INCR DIRECT", "FIX_NO_AXIS_PTS_X 6"))
    layout = rl("RL_MQ", "AXIS_PTS_X 1 UWORD INDEX_INCR DIRECT", "FNC_VALUES 2 UWORD ROW_DIR DIRECT")
    return inline(
        tmp_path, axo,
        mapchar("MAP_Q", "0x100", "RL_MQ", axis("STD_AXIS", "CM_IDENT", "2", "0", "255"),
                axis("COM_AXIS", "CM_IDENT", "8", "0", "255", "AXIS_PTS_REF AXIS_P"), extras=layout),
        characteristic("OVER", "VALUE", "0x204", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
    )


def _homonym_a2l(tmp_path: Path) -> dict:
    from tests.support.b103_a2l_arrays import characteristic, inline

    return inline(
        tmp_path,
        characteristic("DUP", "VALUE", "0x60", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
        characteristic("DUP", "VALUE", "0xF000", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
        characteristic("SOLO", "VALUE", "0x60", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
    )


def _find_nodes(nodes, kind: str, name: str):
    for node in nodes or []:
        if node.get("name") == kind and name in str(node.get("meta", "")).split():
            yield node
        yield from _find_nodes(node.get("children"), kind, name)


# ----------------------------------------------------------------------------
# R-A2L-DEF.169 - equality with the bulk describe
# ----------------------------------------------------------------------------

@pytest.mark.parametrize("order", ORDERS)
@pytest.mark.parametrize("size", PAGE_SIZES)
@pytest.mark.parametrize("key", list(CORPUS))
def test_r_a2l_def_169_pages_equal_bulk(key, size, order):
    """R-A2L-DEF.169/1: every corpus name, pages of 1/50/200, three orders: equal to bulk."""
    mod = _definition_module()
    data = _corpus(key)
    context = _context(key)
    sequence = _ordered(data["unique"], order)
    seen = []
    for page in _pages(sequence, size):
        _assert_equal_to_bulk(mod.describe_in_context(page, context), page, data["bulk"])
        seen.extend(page)
    assert sorted(seen) == sorted(data["unique"]), "every measurable name was described"


def test_r_a2l_def_169_control_corpus_has_names():
    """R-A2L-DEF.169/1 control: every fixture has names to describe; those with 0 measurable names are listed.

    Fixtures with 0 measurable names describe their tag names instead (see
    ``_bundle``); the list is asserted so a change in the corpus is visible.
    """
    tagless = [k for k in CORPUS if not _corpus(k)["unique"]]
    assert tagless == ["from_source_structs", "memorysegment"], tagless  # vacuous arms, by corpus
    assert all(_corpus(k)["measurable"] for k in ("d171", "balance_tube"))
    assert _fallback_fixtures() == ["software_b", *tagless], _fallback_fixtures()


def test_r_a2l_def_169_control_shared_with_present():
    """R-A2L-DEF.169/2 control: >= 1 corpus name has a non-None shared_with (bulk side)."""
    hits = [(k, n) for k in CORPUS for n, d in _corpus(k)["bulk"].items()
            if d.shared_with is not None]
    assert hits, "no corpus name shares occupancy: the shared_with arm would be vacuous"


def test_r_a2l_def_169_shared_with_names_equal_bulk():
    """R-A2L-DEF.169/2: the names that share occupancy carry the same shared_with."""
    mod = _definition_module()
    checked = 0
    for key in CORPUS:
        data = _corpus(key)
        shared = [n for n, d in data["bulk"].items() if d.shared_with is not None]
        if not shared:
            continue
        result = mod.describe_in_context(shared, _context(key))
        for name in shared:
            assert result[name].shared_with == data["bulk"][name].shared_with
            checked += 1
    assert checked >= 1


def test_r_a2l_def_169_refused_scalar_overlap_equal_bulk(tmp_path):
    """R-A2L-DEF.169/3 (E3 F1): refused out-of-range scalars that overlap others equal bulk."""
    mod = _definition_module()
    data = _bundle(_refused_overlap_a2l(tmp_path))
    bulk = data["bulk"]
    refused = [n for n in ("OOR_A", "OOR_B", "FAR_D", "FAR_E")
               if n in bulk and bulk[n].refusal is not None]
    assert refused, "control: at least one refused scalar in the in-test A2L"
    assert any(bulk[n].shared_with is not None for n in refused), \
        "control: a refused scalar overlaps another object"
    context = mod.build_describe_context(data["a2l"], data["names"])
    result = mod.describe_in_context(data["unique"], context)
    _assert_equal_to_bulk(result, data["unique"], bulk)


def test_r_a2l_def_169_two_curves_one_axis_pts_equal_bulk(tmp_path):
    """R-A2L-DEF.169/4 (E3 F5): two curves on one AXIS_PTS plus a curve with no end line."""
    mod = _definition_module()
    a2l = _two_curves_a2l(tmp_path)
    unterminated = list(_find_nodes(a2l.get("sections"), "CHARACTERISTIC", "CURVE_C"))
    assert unterminated and unterminated[0].get("end_line") is None, \
        "control: CURVE_C section has no end line"
    data = _bundle(a2l)
    for name in ("CURVE_A", "CURVE_B"):
        assert data["bulk"][name].kind == "curve", f"control: {name} is a curve"
    # the parser emits no tag for a section without an end line: CURVE_C is
    # asked for by name and must equal the bulk describe's answer for it
    asked = data["unique"] + ["CURVE_C"]
    bulk = mod.describe_definitions(asked, a2l)
    context = mod.build_describe_context(a2l, data["names"])
    for order in ORDERS:
        page = _ordered(asked, order)
        _assert_equal_to_bulk(mod.describe_in_context(page, context), page, bulk)


def test_r_a2l_def_169_axis_span_recorded_by_a_map_equal_bulk(tmp_path):
    """R-A2L-DEF.169/5 (E3 F5, the order): an AXIS_PTS span a described map
    recorded wins over the span placed from the layout, so an object inside it
    shares occupancy with the axis object, as in the bulk describe."""
    mod = _definition_module()
    data = _bundle(_axis_record_a2l(tmp_path))
    bulk = data["bulk"]
    record = bulk["MAP_Q"].axes[1].axis_object_record
    assert bulk["MAP_Q"].refusal is None and record is not None and record.byte_length,         "control: the map is described and records the span of its axis object"
    assert bulk["OVER"].shared_with is not None and "AXIS_P" in str(bulk["OVER"].shared_with),         "control: OVER lies inside the recorded span of AXIS_P"
    context = mod.build_describe_context(data["a2l"], data["names"])
    for order in ORDERS:
        page = _ordered(data["unique"], order)
        _assert_equal_to_bulk(mod.describe_in_context(page, context), page, bulk)
    assert mod.describe_in_context(["OVER"], context)["OVER"].shared_with == bulk["OVER"].shared_with


# ----------------------------------------------------------------------------
# R-A2L-DEF.169 - m5: the bulk seed covers the context's final span (I2)
# ----------------------------------------------------------------------------

def _seed_covers(seed_last, final_last) -> bool:
    """An upper end of ``None`` is open-ended (+infinity): it covers any end; a finite seed covers a
    finite final end only when it is at least as large, and never an open-ended one."""
    if seed_last is None:
        return True
    return final_last is not None and seed_last >= final_last


def _bulk_seed_records(mod, monkeypatch, names: list, a2l: dict) -> list:
    """The records the bulk describe seeds its occupancy index with (``(first, last, entry)``), captured
    from the real ``_build_occupancy_index`` call of ``describe_definitions``."""
    seen: list = []
    real = getattr(mod, "_build_occupancy_index")

    def capture(*args, **kwargs):
        index = real(*args, **kwargs)
        seen.append(list(index.records))
        return index

    monkeypatch.setattr(mod, "_build_occupancy_index", capture)
    mod.describe_definitions(names, a2l)
    monkeypatch.undo()
    assert len(seen) == 1, "the bulk describe builds one index"
    return seen[0]


@pytest.mark.parametrize("request_size", [1, 50], ids=["one-name", "fifty-names"])
@pytest.mark.parametrize("key", list(CORPUS))
def test_r_a2l_def_169_bulk_seed_covers_the_final_span(key, request_size, monkeypatch):
    """R-A2L-DEF.169/11 (m5): for every span entry of the in-repo fixture, the upper end the bulk describe
    seeds its index with is at least the upper end of the context's final span (open-ended covers all)."""
    mod = _definition_module()
    data = _corpus(key)
    context = _context(key)
    final = {record[2][0]: record[1] for record in context._index.records}
    seeds = _bulk_seed_records(mod, monkeypatch, data["unique"][:request_size], data["a2l"])
    assert len(seeds) == len(final) == len(mod._walk_describe_maps(data["a2l"]).span_entries)
    for first, seed_last, entry in seeds:
        assert entry[0] in final, entry
        assert _seed_covers(seed_last, final[entry[0]]), (key, entry[:3], seed_last, final[entry[0]])


def test_r_a2l_def_169_bulk_seed_control_the_arm_sees_entries_and_can_fail(monkeypatch):
    """R-A2L-DEF.169/11 oracle control: the corpus holds entries with a finite and with an open-ended seed,
    and the comparison rejects a finite seed below the final end and a finite seed against an open end."""
    mod = _definition_module()
    total = sum(len(_context(key)._index.records) for key in CORPUS)
    finite = open_ended = 0
    for key in ("d171", "software_a"):
        data = _corpus(key)
        seeds = _bulk_seed_records(mod, monkeypatch, data["unique"][:1], data["a2l"])
        finite += sum(1 for _, last, _ in seeds if last is not None)
        open_ended += sum(1 for _, last, _ in seeds if last is None)
    assert total > 0 and finite > 0 and open_ended > 0, (total, finite, open_ended)
    assert not _seed_covers(0x10, 0x20) and not _seed_covers(0x10, None)
    assert _seed_covers(0x20, 0x20) and _seed_covers(None, None) and _seed_covers(None, 0x20)


# ----------------------------------------------------------------------------
# R-A2L-DEF.170 - refusals
# ----------------------------------------------------------------------------

def test_r_a2l_def_170_undeclared_name_equals_bulk():
    """R-A2L-DEF.170/1: an undeclared name returns the bulk refusal."""
    mod = _definition_module()
    data = _corpus("d171")
    result = mod.describe_in_context(["NO_SUCH_NAME"], _context("d171"))
    expected = mod.describe_definitions(["NO_SUCH_NAME"], data["a2l"])["NO_SUCH_NAME"]
    assert result["NO_SUCH_NAME"] == expected
    assert expected.refusal.code == "A2L-DEF-NAME"
    assert expected.refusal.message == "NO_SUCH_NAME: no tag of that name in the A2L"


def test_r_a2l_def_170_homonym_equals_bulk(tmp_path):
    """R-A2L-DEF.170/2: a name declared twice returns the bulk refusal."""
    mod = _definition_module()
    data = _bundle(_homonym_a2l(tmp_path))
    context = mod.build_describe_context(data["a2l"], data["names"])
    result = mod.describe_in_context(["DUP", "SOLO"], context)
    expected = mod.describe_definitions(["DUP"], data["a2l"])["DUP"]
    assert result["DUP"] == expected
    assert expected.refusal.code == "A2L-DEF-NAME"
    assert expected.refusal.message == "DUP: the A2L declares that name more than once"
    assert result["SOLO"] == mod.describe_definitions(["SOLO"], data["a2l"])["SOLO"]


def test_r_a2l_def_170_empty_name_equals_bulk():
    """R-A2L-DEF.170/3: the empty string returns what the bulk describe returns."""
    mod = _definition_module()
    data = _corpus("d171")
    result = mod.describe_in_context([""], _context("d171"))
    assert result[""] == mod.describe_definitions([""], data["a2l"])[""]


# ----------------------------------------------------------------------------
# R-A2L-DEF.171 - the context is never changed
# ----------------------------------------------------------------------------

def _digest(root: Any) -> str:
    hasher = hashlib.sha256()
    seen: set = set()

    def put(text: str) -> None:
        hasher.update(text.encode("utf-8", "replace") + b"\x00")

    def walk(obj: Any) -> None:
        if obj is None or isinstance(obj, (bool, int, float, str, bytes)):
            put(f"{type(obj).__name__}:{obj!r}")
            return
        if id(obj) in seen:
            put("<seen>")
            return
        seen.add(id(obj))
        put(type(obj).__name__)
        if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
            for f in dataclasses.fields(obj):
                put(f.name)
                walk(getattr(obj, f.name))
        elif isinstance(obj, Mapping):
            for k, v in obj.items():
                walk(k)
                walk(v)
        elif isinstance(obj, (list, tuple)):
            for item in obj:
                walk(item)
        elif isinstance(obj, (set, frozenset)):
            for item in sorted(obj, key=repr):
                walk(item)
        elif hasattr(obj, "__dict__"):
            walk(vars(obj))
        else:
            put(repr(obj))

    walk(root)
    return hasher.hexdigest()


def test_r_a2l_def_171_describe_leaves_context_unchanged():
    """R-A2L-DEF.171/1: digest of every context field equal after describing all names 3 times."""
    mod = _definition_module()
    data = _corpus("d171")
    context = mod.build_describe_context(data["a2l"], data["names"])
    before = _digest(context)
    for _ in range(3):
        mod.describe_in_context(data["unique"], context)
    assert _digest(context) == before


def _payload_ids(source: Any) -> set:
    ids, stack = set(), [source]
    while stack:
        obj = stack.pop()
        if isinstance(obj, (dict, list)) and id(obj) not in ids:
            ids.add(id(obj))
            stack.extend(obj.values() if isinstance(obj, dict) else obj)
    return ids


def _check_held(obj: Any, path: str, exempt: set, seen: set, problems: list) -> None:
    if id(obj) in seen or id(obj) in exempt:
        return
    seen.add(id(obj))
    if isinstance(obj, _definition_module().Definition):
        return
    if isinstance(obj, Mapping):
        try:
            obj["__probe__"] = 0
            problems.append(f"{path}: item assignment succeeded on {type(obj).__name__}")
        except TypeError:
            pass
        for k, v in obj.items():
            _check_held(v, f"{path}[{k!r}]", exempt, seen, problems)
    elif isinstance(obj, tuple):
        for i, item in enumerate(obj):
            _check_held(item, f"{path}[{i}]", exempt, seen, problems)
    elif isinstance(obj, (list, set, bytearray)):
        problems.append(f"{path}: mutable {type(obj).__name__} held by the context")
    elif dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        for f in dataclasses.fields(obj):
            _check_held(getattr(obj, f.name), f"{path}.{f.name}", exempt, seen, problems)


def test_r_a2l_def_171_held_containers_are_read_only():
    """R-A2L-DEF.171/2: every held container is a tuple or a read-only mapping."""
    mod = _definition_module()
    data = _corpus("d171")
    context = mod.build_describe_context(data["a2l"], data["names"])
    exempt = _payload_ids(context.source)
    problems: list = []
    fields = [f for f in dataclasses.fields(context) if f.name != "source"]
    assert any(f.name == "formats" for f in fields)
    for f in fields:
        _check_held(getattr(context, f.name), f.name, exempt, set(), problems)
    assert not problems, problems
    with pytest.raises(TypeError):
        context.formats["__probe__"] = None
    with pytest.raises(dataclasses.FrozenInstanceError):
        context.formats = {}


# ----------------------------------------------------------------------------
# R-A2L-DEF.172 - no section walk per describe
# ----------------------------------------------------------------------------

class _CountingSections(list):
    """A sections list that counts every iteration or indexing of it."""

    visits = 0

    def __iter__(self):
        type(self).visits += 1
        return super().__iter__()

    def __getitem__(self, item):
        type(self).visits += 1
        return super().__getitem__(item)


@pytest.mark.parametrize("size", PAGE_SIZES)
@pytest.mark.parametrize("key", SMALL3)
def test_r_a2l_def_172_describe_walks_no_section(key, size, monkeypatch):
    """R-A2L-DEF.172/1: 0 section visits for 1/50/200 names; two independent seams.

    Seam A: ``a2l_definition._walk_describe_maps`` (named in the G-DEF graph).
    Seam B: the payload's ``sections`` list is replaced by a counting list on a
    shallow copy of the payload (independent of any implementation name).
    """
    mod = _definition_module()
    data = _corpus(key)
    payload = dict(data["a2l"])
    payload["sections"] = _CountingSections(data["a2l"].get("sections") or [])
    context = mod.build_describe_context(payload, data["names"])
    calls: list = []
    real_walk = getattr(mod, "_walk_describe_maps")

    def counting_walk(*args, **kwargs):
        calls.append(1)
        return real_walk(*args, **kwargs)

    monkeypatch.setattr(mod, "_walk_describe_maps", counting_walk)
    # control: both seams observe a real walk (the bulk describe walks the sections)
    _CountingSections.visits = 0
    mod.describe_definitions(data["unique"][:1], payload)
    assert calls and _CountingSections.visits >= 1, "control: the bulk describe is observed walking"
    calls.clear()
    _CountingSections.visits = 0
    page = data["unique"][:size]
    result = mod.describe_in_context(page, context)
    assert len(result) == len(page)
    assert calls == [], "describe_in_context called the section walk"
    assert _CountingSections.visits == 0, "describe_in_context iterated the payload sections"


# ----------------------------------------------------------------------------
# R-A2L-DEF.174 - format fields
# ----------------------------------------------------------------------------

@pytest.mark.parametrize("key", list(CORPUS))
def test_r_a2l_def_174_formats_equal_bulk(key):
    """R-A2L-DEF.174/1: every measurable name's datatype, kind, unit equal the bulk Definition's."""
    data = _corpus(key)
    formats = _context(key).formats
    assert set(data["measurable"]) <= set(formats), "formats covers every measurable name"
    for name in data["measurable"]:
        got = (formats[name].datatype, formats[name].kind, formats[name].unit)
        assert got == _fmt(data["bulk"][name]), name


def test_r_a2l_def_174_control_phys_unit_differs_from_method_unit():
    """R-A2L-DEF.174/2 control: >= 1 name whose own PHYS_UNIT differs from its compu-method unit."""
    hits = []
    for key in CORPUS:
        data = _corpus(key)
        methods = data["a2l"].get("compu_methods_by_name") or {}
        for name, d in data["bulk"].items():
            method = methods.get(d.method_name)
            if method is not None and d.unit != (method.get("unit") or ""):
                hits.append((key, name))
    assert hits, "no corpus name has a PHYS_UNIT differing from the method unit"


def test_r_a2l_def_174_control_curve_or_map_present():
    """R-A2L-DEF.174/3 control: >= 1 curve or map among the corpus names."""
    kinds = {d.kind for k in CORPUS for d in _corpus(k)["bulk"].values()}
    assert kinds & {"curve", "map"}, sorted(kinds)


def test_r_a2l_def_174_unit_is_object_unit_not_method_unit():
    """R-A2L-DEF.174/2: a d171 name with its own PHYS_UNIT keeps it in formats."""
    data = _corpus("d171")
    methods = data["a2l"].get("compu_methods_by_name") or {}
    diff = [n for n, d in data["bulk"].items()
            if d.method_name in methods
            and d.unit != (methods[d.method_name].get("unit") or "")]
    assert diff, "control: d171 has a name whose unit differs from its method unit"
    formats = _context("d171").formats
    for name in diff:
        assert formats[name].unit == data["bulk"][name].unit


# ----------------------------------------------------------------------------
# K-2 arm: single-name describe against the bulk describe, both on the tree
# (narrow = bulk; that the bulk output equals the base revision's is not shown
# here, it is a recorded probe)
# ----------------------------------------------------------------------------

def _k2_names(data: dict) -> list:
    unique = data["unique"]
    if len(unique) <= 150:
        return unique
    rng = random.Random(SAMPLE_SEED)
    shared = [n for n in unique if data["bulk"][n].shared_with is not None][:100]
    return list(dict.fromkeys(shared + rng.sample(unique, 100)))


@pytest.mark.parametrize("key", list(CORPUS))
def test_k2_describe_definition_equals_bulk(key):
    """K-2: describe_definition(name, a2l) equals the bulk describe on the corpus (sampled when large), both on the tree."""
    mod = _definition_module()
    data = _corpus(key)
    different = [n for n in _k2_names(data)
                 if mod.describe_definition(n, data["a2l"]) != data["bulk"][n]]
    assert not different, f"{key}: single-name describe differs from bulk for {different[:5]}"


# ----------------------------------------------------------------------------
# R-A2L-DEF.174 - the build lexes each object section once (change A)
# ----------------------------------------------------------------------------

def _count_lexes(mod, monkeypatch) -> dict:
    """Count the lexes the span and format passes pay themselves: a call of
    ``_object_line_words``, or of ``_flatten_body_tokens`` from an object
    section's ``_read_object_lines`` (a compu method record is read once per
    method and is no object section), made while a span-table or a format pass
    runs and no full ``_describe_one`` (the array-kind path, which owns its own
    reads) is on the stack. ``walk`` and ``describe_one`` count the
    rest, so the control sees every call."""
    counts = {"_object_line_words": 0, "_flatten_body_tokens": 0, "walk": 0, "describe_one": 0}
    state = {"passes": 0, "describe": 0, "objread": 0}

    def scoped(attr, key):
        real = getattr(mod, attr)

        def wrapper(*args, **kwargs):
            state[key] += 1
            try:
                return real(*args, **kwargs)
            finally:
                state[key] -= 1

        monkeypatch.setattr(mod, attr, wrapper)

    def counted(seam):
        real = getattr(mod, seam)

        def wrapper(*args, **kwargs):
            owned = state["passes"] and not state["describe"]
            if owned and (seam == "_object_line_words" or state["objread"]):
                counts[seam] += 1
            else:
                counts["describe_one" if state["describe"] else "walk"] += 1
            return real(*args, **kwargs)

        monkeypatch.setattr(mod, seam, wrapper)

    scoped("_build_span_table", "passes")
    scoped("_format_fields", "passes")
    scoped("_describe_one", "describe")
    scoped("_read_object_lines", "objread")
    counted("_object_line_words")
    counted("_flatten_body_tokens")
    return counts


@pytest.mark.parametrize("key", ["d171", "d161"])
def test_r_a2l_def_174_build_lexes_each_section_once(key, monkeypatch):
    """R-A2L-DEF.174: the span and format passes of the context build lex each
    measurable object section at most once: no ``_flatten_body_tokens`` and at
    most one ``_object_line_words`` per span entry outside the array-kind
    describes. Equality with the bulk describe stays pinned by the
    formats_equal_bulk arm above."""
    mod = _definition_module()
    data = _corpus(key)
    span_entries = len(mod._walk_describe_maps(data["a2l"]).span_entries)
    counts = _count_lexes(mod, monkeypatch)
    context = mod.build_describe_context(data["a2l"], data["names"])
    assert len(context.formats) >= len(data["measurable"]), "control: the build ran"
    assert counts["_object_line_words"] > 0, "control: the lex seam is observed"
    assert counts["describe_one"] > 0, "control: the array-kind describe is observed"
    assert counts["_flatten_body_tokens"] == 0, counts
    assert counts["_object_line_words"] <= span_entries, (counts, span_entries)


def _unit_edge_a2l(tmp_path: Path) -> dict:
    """Object sections the line splitter and the canonical lexer could read
    differently: comments, tabs, a description running over a line end, an
    escaped quote, a keyword that is another keyword's value, a MATRIX_DIM."""
    from tests.support.b103_a2l_arrays import inline

    def char(name, address, *body):
        head = f'/begin CHARACTERISTIC {name} "d" VALUE {address} RL_U8 0 NO_COMPU_METHOD 0 255'
        return "\n".join([head, *body, "/end CHARACTERISTIC"])

    meas = (
        '/begin MEASUREMENT E_MEAS "d" UBYTE NO_COMPU_METHOD 1 0 0 255\n'
        '  ECU_ADDRESS 0x400\n  MATRIX_DIM 2 1 1\n  PHYS_UNIT "rpm"\n/end MEASUREMENT'
    )
    return inline(
        tmp_path,
        char("E_PLAIN", "0x100", '  PHYS_UNIT "km/h"'),
        char("E_TAB", "0x110", '\tPHYS_UNIT\t"tab unit"'),
        char("E_BLOCK", "0x120", '  /* PHYS_UNIT "no" */ PHYS_UNIT "yes"'),
        char("E_LINE", "0x130", '  // PHYS_UNIT "no"', '  UNIT "line"'),
        char("E_FORMAT", "0x140", '  FORMAT "PHYS_UNIT"', '  UNIT "after"'),
        char("E_ESCAPED", "0x150", '  PHYS_UNIT "a \\" b"'),
        char("E_NONE", "0x160", "  BIT_MASK 0x0F"),
        '/begin CHARACTERISTIC E_MULTI "first line\nsecond line" VALUE 0x170 RL_U8 0 '
        'NO_COMPU_METHOD 0 255\n  PHYS_UNIT "multi"\n/end CHARACTERISTIC',
        meas,
    )


def test_r_a2l_def_174_unit_edge_sections_equal_bulk(tmp_path):
    """R-A2L-DEF.174/2: the one-lex unit and shape equal the bulk describe for
    sections whose words the two lexers could split differently."""
    mod = _definition_module()
    data = _bundle(_unit_edge_a2l(tmp_path))
    formats = mod.build_describe_context(data["a2l"], data["names"]).formats
    assert len(data["measurable"]) >= 9, "control: every edge object is measurable"
    assert any(d.unit for d in data["bulk"].values()), "control: an edge object has a unit"
    for name in data["measurable"]:
        got = (formats[name].datatype, formats[name].kind, formats[name].unit)
        assert got == _fmt(data["bulk"][name]), name


# ----------------------------------------------------------------------------
# R-A2L-DEF.169 / .174 - every committed A2L (the context is the only load path)
# ----------------------------------------------------------------------------

def _committed_a2l_paths() -> list:
    import subprocess

    out = subprocess.run(["git", "ls-files", "*.a2l"], cwd=REPO_ROOT, check=True,
                         capture_output=True, text=True).stdout.split("\n")
    return sorted(p for p in out if p and "case_06_" not in p)


def _outcome(call):
    try:
        return "ok", call()
    except Exception as exc:  # noqa: BLE001 - the comparison is "raises or not"
        return "raised", type(exc).__name__


def _context_vs_bulk_problems(context_run, bulk_run, names: list) -> list:
    """Empty when the context agrees with the bulk describe on raise/no-raise,
    on every name's format fields and on the first 200 names' definitions."""
    mod = _definition_module()
    built = _outcome(context_run)
    bulk = _outcome(bulk_run)
    if built[0] != bulk[0]:
        return [f"context {built[0]} ({built[1]}) but bulk {bulk[0]} ({bulk[1]})"]
    if built[0] == "raised":
        return []
    context, bulk_defs = built[1], bulk[1]
    unique = list(dict.fromkeys(names))
    problems = [f"format {n!r}" for n in unique
                if n not in context.formats or _fmt(context.formats[n]) != _fmt(bulk_defs[n])]
    head = unique[:200]
    described = mod.describe_in_context(head, context)
    problems += [f"definition {n!r}" for n in head if described.get(n) != bulk_defs[n]]
    return problems


@pytest.mark.parametrize("rel", _committed_a2l_paths())
def test_r_a2l_def_169_context_matches_bulk_on_every_committed_a2l(rel):
    """R-A2L-DEF.169/.174 differential: on every committed A2L (case_06 is
    host-sized and covered by the host arms) the context build raises iff the
    bulk describe raises, and otherwise agrees with it."""
    from s19_app.tui.a2l import enrich_a2l_tags_with_values
    from s19_app.tui.a2l_parse import parse_a2l_file

    mod = _definition_module()
    a2l = parse_a2l_file(REPO_ROOT / rel)
    names = [t["name"] for t in enrich_a2l_tags_with_values(a2l, None)
             if isinstance(t.get("address"), int)]
    problems = _context_vs_bulk_problems(
        lambda: mod.build_describe_context(a2l, names),
        lambda: mod.describe_definitions(names, a2l),
        names,
    )
    assert not problems, f"{rel}: {problems[:5]}"


def test_r_a2l_def_169_control_committed_a2l_comparator_can_fail():
    """R-A2L-DEF.169/.174 control: the differential rejects a context that
    differs from the bulk describe and a raise on one side only."""
    mod = _definition_module()
    data = _corpus("d171")
    names = data["measurable"]
    good = lambda: mod.build_describe_context(data["a2l"], names)  # noqa: E731
    bulk = lambda: mod.describe_definitions(names, data["a2l"])  # noqa: E731
    assert _context_vs_bulk_problems(good, bulk, names) == []
    other = _corpus("balance_tube")
    swapped = lambda: mod.build_describe_context(other["a2l"], other["measurable"])  # noqa: E731
    assert _context_vs_bulk_problems(swapped, bulk, names), "different A2L must be rejected"

    def boom():
        raise ValueError("synthetic")

    assert _context_vs_bulk_problems(boom, bulk, names), "one-sided raise must be rejected"
    assert _context_vs_bulk_problems(boom, boom, names) == [], "both raising agree"
    assert len(_committed_a2l_paths()) >= 20, "the committed-A2L list is not empty"
