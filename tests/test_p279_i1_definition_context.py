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
# K-2 oracle arm: single-name describe against the bulk describe (base behaviour)
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
    """K-2: describe_definition(name, a2l) equals the bulk describe on the corpus (sampled when large)."""
    mod = _definition_module()
    data = _corpus(key)
    different = [n for n in _k2_names(data)
                 if mod.describe_definition(n, data["a2l"]) != data["bulk"][n]]
    assert not different, f"{key}: single-name describe differs from bulk for {different[:5]}"
