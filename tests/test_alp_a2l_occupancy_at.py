"""Batch a2l-load-performance INC 1 — E4 acceptance tests for the central
occupancy index (AT-ALP-I1-1, AT-ALP-I1-2, AT-ALP-I1-3; public routes only).

Design under test: ``.dev-flow/2026-11-18-a2l-load-performance/inc-1/``
(``01-requirements.md``, ``02-test-cases.md``, ``codewire/graph-inc1.md``).

AT-ALP-I1-1 starts with a fast seam guard (``assert hasattr`` → AttributeError)
so it fails RED on the base without running the base's quadratic route over
220,040 queries.  AT-ALP-I1-2 and AT-ALP-I1-3 run their full body against the
base: their counters and structural witnesses are the RED evidence there
(materializing every global candidate, and zero central-index constructions).

No test here touches the real clipboard, user secrets or user state; temporary
files stay under pytest's isolated temporary directory.
"""

from __future__ import annotations

import pytest

import s19_app.tui.a2l_definition as a2ldef
from s19_app.tui.a2l_parse import parse_a2l_file
from tests.support.b103_a2l_arrays import characteristic, img, inline
from tests.support.timing import report_margin, timing_bound
from tests.test_alp_a2l_occupancy import _install_counters
from tests.test_alp_a2l_occupancy_perf import (
    _CASE06,
    _CASE06_POPULATION,
    _case06_oracle,
    _require_seam,
    _run_integrated_case06,
    _semantic_pins,
)


@pytest.mark.serial_timing
@pytest.mark.slow
def test_at_alp_i1_1_full_case06_public_describe(tmp_path, monkeypatch):
    """AT-ALP-I1-1 - real file bytes → independent source-text order oracle
    computed once → parser → public batch describe of all 220,040 unique
    names: exact ordered key set, 0 full-case oracle differences per run, the
    timing protocol (median of 3 at most 30.0 s), per-run construction and
    population counts, and the R-A2L-DEF.159 / .160 semantic known-answer
    pins in the same node."""
    mod = a2ldef
    median, runs, oracle_seconds, comparison_seconds = _run_integrated_case06(
        tmp_path, monkeypatch, mod
    )
    assert median <= report_margin(
        "AT-ALP-I1-1 case_06 public describe", median, timing_bound(30.0)
    ), (runs, oracle_seconds, comparison_seconds)
    _semantic_pins(tmp_path, mod)


@pytest.mark.slow
def test_at_alp_i1_2_narrow_public_describe_stays_lazy(tmp_path, monkeypatch):
    """AT-ALP-I1-2 - real file bytes → parser → public single-name describe of
    a narrow case_06 query: one correct definition for the exact requested
    name, its shared_with matching the independent oracle, and no eager
    all-file final-span materialization or definition build."""
    mod = a2ldef
    a2l = parse_a2l_file(_CASE06)
    names = [tag["name"] for tag in a2l["tags"]]
    assert len(names) == _CASE06_POPULATION
    name = names[0]
    _oracle_seconds, oracle_by_name, _expected_names = _case06_oracle(a2l)
    state = _install_counters(monkeypatch, mod)
    result = mod.describe_definitions([name], a2l)
    assert list(result) == [name] and len(result) == 1
    assert result[name].shared_with == oracle_by_name[name], (
        result[name].shared_with, oracle_by_name[name]
    )
    assert state["builds"][name] == 1 and len(state["builds"]) == 1, state["builds"]
    assert state["materializations"] <= 64, (
        f"the narrow query materialized {state['materializations']} final spans: "
        "an eager all-file route would materialize every occupancy record"
    )
    assert state["constructions"] == 1, state["constructions"]
    assert result[name] == mod.describe_definition(name, a2l)


def test_at_alp_i1_3_describe_to_encode_overlap_safety(tmp_path, monkeypatch):
    """AT-ALP-I1-3 - inline A2L with one-byte, 64-byte and over-cap spans,
    interleaved kinds, same-name/same-span and same-name/disjoint records →
    parser → public describe → the real encode route: cross-page LATE, both
    homonym shapes and over-cap BIG produce the exact existing outcomes and
    refusals with no image mutation; one central index per describe holds one
    interval record per occupancy entry and 0 page-expansion records."""
    mod = a2ldef
    state = _install_counters(monkeypatch, mod)
    clean = inline(
        tmp_path,
        characteristic("BIG", "ASCII", "0x10", "RL_U8", "NO_COMPU_METHOD", "0", "255", "NUMBER 64"),
        characteristic("LATE", "VALUE", "0x40", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
        characteristic("EARLY", "VALUE", "0x20", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
        characteristic("BIGC", "VALUE", "0x0", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
        characteristic("V", "VALUE", "0x100000", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
    )
    next(tag for tag in clean["tags"] if tag.get("name") == "BIGC")["length"] = 1_048_577

    big = mod.describe_definition("BIG", clean)
    assert big.shared_with == "LATE"
    image = img(0x10, bytes(64))
    before = dict(image)
    refusal = mod.encode_definition(big, clean, "AB", image)
    assert isinstance(refusal, mod.Refusal), refusal
    assert refusal.code == "A2L-DEF-OVERLAP" and "LATE" in refusal.message, refusal
    assert image == before, "a refused encode must not mutate the image"

    point = mod.describe_definition("V", clean)
    assert point.shared_with == "BIGC"
    point_image = {0x100000: 0}
    point_before = dict(point_image)
    refusal = mod.encode_definition(point, clean, "7", point_image)
    assert isinstance(refusal, mod.Refusal), refusal
    assert refusal.code == "A2L-DEF-OVERLAP" and "BIGC" in refusal.message, refusal
    assert point_image == point_before

    # structural witness: one construction per describe, 5 entries → 5 records
    assert state["constructions"] == 2, state["constructions"]
    for index, _defs_by_pos, _entry_cache in state["index_captures"]:
        assert len(index.records) == 5, len(index.records)

    hom = inline(
        tmp_path,
        characteristic("DUP", "VALUE", "0x60", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
        characteristic("DUP", "VALUE", "0xF000", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
        characteristic("DUPX", "VALUE", "0x70", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
        characteristic("DUPX", "VALUE", "0x70", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
        characteristic("Q", "VALUE", "0x60", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
        characteristic("QX", "VALUE", "0x70", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
    )
    assert mod.describe_definition("Q", hom).shared_with == "DUP"
    assert mod.describe_definition("QX", hom).shared_with == "DUPX"
    duplicate = mod.describe_definition("DUP", hom)
    assert duplicate.refusal is not None
    assert duplicate.refusal.code == "A2L-DEF-NAME"
    assert duplicate.refusal.message == "DUP: the A2L declares that name more than once"

    assert state["constructions"] == 5, state["constructions"]
    for index, _defs_by_pos, _entry_cache in state["index_captures"][2:]:
        assert len(index.records) == 6, len(index.records)
