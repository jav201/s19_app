"""Inc 4 (batch-103) - label similarity matcher: behaviour tests (G-T1).

Independent tester file (E4): the expected values are the ones written in
``.dev-flow/2026-11-05-batch-103/inc-4/02-test-cases.md`` and
``codewire/graph-inc4.md``; nothing is read from the implementation or from the
pilots' code. The matcher is driven only through the public I-3 names
(``build_label_index``, ``rank``, ``LabelMatch``, ``MatchRule``).

Requirement -> test coverage (``R-A2L-MATCH.<n>/<k>`` = row n, alternative k):

- ``test_ranked_list_is_exactly``: the cases whose expected result is a whole
  ranked list - R-A2L-MATCH.1/1..4, .2/1..5, .3/1..3, .4/1..3, .5/1..2,
  .6/1..3, .7/1..4, .8/1..9, .9/1..4, .10/1..6, .11/1..3, .12/3..4,
  .13/1..4, .14/1..2, .15/1..2, .16/1..3, .17/1..2, .18/3, .19/1..2,
  .20/2, .21/1..3, .22/1, .23/2, .24/2, .24/4, .25/3, .28/1, .32/1, .32/3,
  .33/2..3, .34/1, .38/1..2, .39/1..2 (the case id is the pytest id).
- ``test_rows_*`` and the single tests below: the relational cases (an entry
  or a part of a list) - R-A2L-MATCH.5/3, .12/1..2, .18/1..2, .20/1, .20/3,
  .23/1, .24/1, .24/3, .25/1..2, .26..31, .32/2, .33/1, .34/2..3.
- ``test_at_b103_i4_1_*`` / ``test_at_b103_i4_2_*``: AT-B103-I4-1 and -2.
- ``test_i3_*``: the I-3 interface checks (errors, purity, read-only, types).
- The timing and memory cases R-A2L-MATCH.35/1, .36/1, .37/1, .40/1, .40/2
  live in ``tests/test_b103_label_match_perf.py``; the R-A2L-MATCH.41/1..5 cases are in EXACT_CASES above,
  with a boundary control sweep (18 .. 25 distinct tokens).

Every test marked ``full`` in the records asserts the matcher's own output;
none asserts a stand-in's text. Fixtures: case 08 is generated into a tmp
directory by ``tools/synth/make_release_case.py`` (seed 20260001) and read with
the repo's A2L reader; the case_00 examples are read the same way.
"""
from __future__ import annotations

import ast
import dataclasses
import enum
import random
import sys
from pathlib import Path

import pytest

from s19_app.tui.a2l import parse_a2l_file
from s19_app.tui.services.label_match import (
    LabelMatch,
    MatchRule,
    build_label_index,
    rank,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
SYNTH_DIR = REPO_ROOT / "tools" / "synth"
if str(SYNTH_DIR) not in sys.path:
    sys.path.insert(0, str(SYNTH_DIR))

import make_release_case as gen  # noqa: E402

SEED = 20260001
EXAMPLES = REPO_ROOT / "examples" / "case_00_public"


# ---------------------------------------------------------------------------
# Notation helpers: an entry is (name, rule word, edits, spans)
# ---------------------------------------------------------------------------


def E(name, rule, *spans, e=0):
    """One expected entry: ``NAME - rule - spans`` (+ ``e<k>`` for fuzzy)."""
    return (name, rule, e, tuple(spans))


def proj(result):
    """Project a ranked list onto plain tuples (name, rule word, edits, spans)."""
    return [(m.name, m.rule.value, m.edits, m.spans) for m in result]


def seq(fmt, nums, rule, *spans, e=0):
    """Entries ``fmt.format(n)`` for each n, all with the same rule and spans."""
    return [E(fmt.format(n), rule, *spans, e=e) for n in nums]


def spans_of(result, name):
    hits = [m for m in result if m.name == name]
    assert len(hits) == 1, f"{name!r} listed {len(hits)} times in {[m.name for m in result]}"
    return hits[0].spans


def names_of_result(result):
    return [m.name for m in result]


def read_names(path: Path):
    return [str(t["name"]) for t in parse_a2l_file(path)["tags"] if t.get("name") is not None]


# ---------------------------------------------------------------------------
# Fixtures (02-test-cases.md "Fixtures")
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def lists(tmp_path_factory):
    out = tmp_path_factory.mktemp("b103_case08")
    paths = gen.generate(out, SEED, 10.0)
    c08 = read_names(paths["a2l"])
    c08i = read_names(paths["a2l_issues"])
    # Fixture sanity (a defective fixture is the tester's to repair, not a product finding).
    assert len(c08) == 462, len(c08)
    assert len(c08i) == 470, len(c08i)
    assert c08i.count("VALUE_0001") == 2
    return {
        "C08": c08,
        "C08i": c08i,
        "C08r": list(reversed(c08)),
        "BAL": read_names(EXAMPLES / "BalanceTube_STMicro.a2l"),
        "SRC": read_names(EXAMPLES / "from_source.a2l"),
        "SWB": read_names(EXAMPLES / "software_b.a2l"),
        "SWA": read_names(EXAMPLES / "software_a.a2l"),
        "TW": ["RPM", "rpm", "Rpm"],
        "TW2": ["Rpm", "rpm", "RPM"],
        "NA": ["Drück_Max", "DRÜCK_MAX", "druck_max"],
        "CUR": ["ABSValue", "AValue", "engineSpeed", "Map3D"],
    }


@pytest.fixture(scope="module")
def prep(lists):
    """prep(key) -> a prepared index; key is a fixture name or a tuple of names."""
    cache = {}

    def get(key):
        if key not in cache:
            names = lists[key] if isinstance(key, str) else list(key)
            cache[key] = build_label_index(names)
        return cache[key]

    return get


def run(prep, key, query, limit=20):
    return rank(query, prep(key), limit)


# ---------------------------------------------------------------------------
# Expected lists shared by several cases
# ---------------------------------------------------------------------------

R_0001 = [  # R-A2L-MATCH.7/1
    E("MAP_0001", "substring", (4, 8)),
    E("ASCII_0001", "substring", (6, 10)),
    E("CURVE_0001", "substring", (6, 10)),
    E("VALUE_0001", "substring", (6, 10)),
    E("VAL_BLK_0001", "substring", (8, 12)),
    E("MEASUREMENT_0001", "substring", (12, 16)),
]

R__0001 = [  # R-A2L-MATCH.21/2
    E("MAP_0001", "substring", (3, 8)),
    E("ASCII_0001", "substring", (5, 10)),
    E("CURVE_0001", "substring", (5, 10)),
    E("VALUE_0001", "substring", (5, 10)),
    E("VAL_BLK_0001", "substring", (7, 12)),
    E("MEASUREMENT_0001", "substring", (11, 16)),
]

R_VALUE_000 = (  # R-A2L-MATCH.14/1 (20 entries)
    seq("VALUE_{:04d}", range(1, 10), "prefix", (0, 9))
    + seq("VALUE_{:04d}", range(10, 100, 10), "subsequence", (0, 5), (6, 8), (9, 10))
    + seq("VALUE_{:04d}", (100, 200), "subsequence", (0, 5), (6, 7), (8, 10))
)

R_OKS_AHW = [  # R-A2L-MATCH.8/3
    E("LukPvq.JXML_UPQ_BI.OKSAhwvcueaniy", "token", (19, 25)),
    E("AwsQdc.VXAO_CSP_KH.NkshfehlTcyfkjea_IPNR", "fuzzy", (0, 3), (19, 27), e=2),
    E(
        "OotGyt.FmcP_UGL_SgvHhu_MME_GEH_kdfba.VsvL_BILR_GtnWga_HGW_RKK_eroog",
        "subsequence",
        (0, 1), (31, 32), (38, 39), (52, 53), (54, 55), (56, 57),
    ),
]

R_GAME_TIMER = [  # R-A2L-MATCH.9/4
    E("model.MainClass.gameController.timer.timeCounter", "subsequence", (16, 30), (31, 36)),
    E(
        "model.MainClass.gameController.stopWatch.timeCounter",
        "subsequence",
        (16, 30), (32, 33), (42, 45), (51, 52),
    ),
]

R_OUNTER = [  # R-A2L-MATCH.21/3
    E("model.MainClass.ledController.sw.timeCounter", "substring", (38, 44)),
    E("model.MainClass.gameController.timer.timeCounter", "substring", (42, 48)),
    E("model.MainClass.gameController.stopWatch.timeCounter", "substring", (46, 52)),
]

R_CURVEE = [  # R-A2L-MATCH.13/3 = .22/1
    E("CURVE_0001", "fuzzy", (0, 5), e=1),
    E("CUVE", "fuzzy", (0, 4), e=2),
]

R_KNIFE_1_X = [  # R-A2L-MATCH.8/4
    E("parameter_instance[0].Knife[1].x", "token", (22, 27), (28, 29), (31, 32)),
    E("parameter_instance[1].Knife[0].x", "token", (19, 20), (22, 27), (31, 32)),
    E("parameter_instance[1].Knife[1].x", "token", (19, 20), (22, 27), (31, 32)),
    E("parameter_instance[2].Knife[1].x", "token", (22, 27), (28, 29), (31, 32)),
    E("parameter_instance[3].Knife[1].x", "token", (22, 27), (28, 29), (31, 32)),
]

R_AT_MAP_DRUCK = [  # R-A2L-MATCH.4/1
    E("Drück_Max", "prefix", (0, 5)),
    E("DRÜCK_MAX", "fuzzy", (0, 5), e=1),
    E("druck_max", "fuzzy", (0, 5), e=1),
]

R_LUK_SAHW = "LukPvq.JXML_UPQ_BI.OKSAhwvcueaniy"

# R-A2L-MATCH.41: the 20 one-edit variants of ``curve`` (``curv`` + each letter but ``e``, in order), and the
# SWA name with the most distinct query tokens (26 tokens, 101 characters) with its tokens reversed.
CURV20 = " ".join("curv" + c for c in "abcdfghijklmnopqrstu")
SWA_PASTED = "HRR_WOL.TNY_U_ZmyrXSZTPeyoMsdpWwbcUtd_Dwvrap_YAL_o8gk5143_Tw_WjPcscmtzpCrxe_GFV_TVY3_YES_AyxwevsxrDBB"
SWA_PASTED_REVERSED = (
    "dbb ayxwevsxr yes 3 tvy gfv crxe pcscmtzp wj tw 5143 gk 8 o yal dwvrap utd wwbc msdp peyo xszt zmyr u tny wol hrr"
)

SPAN_00 = [E("VALUE_0001", "exact", (0, 10))]

# ---------------------------------------------------------------------------
# Whole-list cases: (case id, list key, query, limit, expected ranked list)
# ---------------------------------------------------------------------------

EXACT_CASES = [
    # --- R-A2L-MATCH.1 the query text excludes leading/trailing whitespace
    ("R-A2L-MATCH.1/1", "C08", "  VALUE_0001  ", 20, SPAN_00),
    ("R-A2L-MATCH.1/2", "C08", "\tVALUE_0001\n", 20, SPAN_00),
    ("R-A2L-MATCH.1/3", "C08", " value_000 ", 5, seq("VALUE_{:04d}", range(1, 6), "prefix", (0, 9))),
    ("R-A2L-MATCH.1/4", "C08", "\x1cVALUE_0001", 20, [E("VALUE_0001", "token", (0, 5), (6, 10))]),
    # --- R-A2L-MATCH.2 nothing to search for
    ("R-A2L-MATCH.2/1", "C08", "", 20, []),
    ("R-A2L-MATCH.2/2", "C08", "   ", 20, []),
    ("R-A2L-MATCH.2/3", "C08", "\t\n", 20, []),
    ("R-A2L-MATCH.2/4", "C08", "_", 20, []),
    ("R-A2L-MATCH.2/5", "C08", "._[]", 20, []),
    # --- R-A2L-MATCH.3 ASCII case folding
    ("R-A2L-MATCH.3/1", "C08", "value_0001", 20, SPAN_00),
    ("R-A2L-MATCH.3/2", "C08", "Value_0001", 20, SPAN_00),
    ("R-A2L-MATCH.3/3", "TW", "rpm", 20,
     [E("rpm", "exact", (0, 3)), E("RPM", "exact", (0, 3)), E("Rpm", "exact", (0, 3))]),
    # --- R-A2L-MATCH.4 non-ASCII not folded; '-' != '_'
    ("R-A2L-MATCH.4/1", "NA", "drück", 20, R_AT_MAP_DRUCK),
    ("R-A2L-MATCH.4/2", "NA", "DRÜCK", 20,
     [E("DRÜCK_MAX", "prefix", (0, 5)), E("Drück_Max", "fuzzy", (0, 5), e=1), E("druck_max", "fuzzy", (0, 5), e=1)]),
    ("R-A2L-MATCH.4/3", "C08", "VALUE-0001", 20, [E("VALUE_0001", "token", (0, 5), (6, 10))]),
    # --- R-A2L-MATCH.5 exact
    ("R-A2L-MATCH.5/1", "C08", "VALUE_0001", 20, SPAN_00),
    ("R-A2L-MATCH.5/2", "C08", "map_0020", 20, [E("MAP_0020", "exact", (0, 8))]),
    # --- R-A2L-MATCH.6 prefix
    ("R-A2L-MATCH.6/1", "C08", "value_000", 5, seq("VALUE_{:04d}", range(1, 6), "prefix", (0, 9))),
    ("R-A2L-MATCH.6/2", "C08i", "span", 20,
     [E("SPAN_OVER_1", "prefix", (0, 4)), E("SPAN_OVER_2", "prefix", (0, 4))]),
    ("R-A2L-MATCH.6/3", "C08i", "LIMIT", 20, [E("LIMIT_BREAKER", "prefix", (0, 5))]),
    # --- R-A2L-MATCH.7 substring
    ("R-A2L-MATCH.7/1", "C08", "0001", 20, R_0001),
    ("R-A2L-MATCH.7/2", "SRC", "knife[1]", 20,
     seq("parameter_instance[{}].Knife[1].x", range(4), "substring", (22, 30))
     + [E("parameter_instance[1].Knife[0].x", "token", (19, 20), (22, 27))]),
    ("R-A2L-MATCH.7/3", "SRC", "[0].Spoon", 20, [E("parameter_instance[0].Spoon.x", "substring", (18, 27))]),
    ("R-A2L-MATCH.7/4", "BAL", "ledRing[1]", 4,
     [E("model.Signals.ledRing[1].red", "substring", (14, 24)),
      E("model.Signals.ledRing[1].blue", "substring", (14, 24)),
      E("model.Signals.ledRing[1].green", "substring", (14, 24)),
      E("model.MainClass.ledController.ledRing[1].red", "substring", (30, 40))]),
    # --- R-A2L-MATCH.8 token
    ("R-A2L-MATCH.8/1", "C08", "blk val 00", 3,
     seq("VAL_BLK_{:04d}", range(1, 4), "token", (0, 3), (4, 7), (8, 10))),
    ("R-A2L-MATCH.8/2", "BAL", "stop watch", 20,
     [E("model.MainClass.gameController.stopWatch.timeCounter", "token", (31, 40))]),
    ("R-A2L-MATCH.8/3", "SWB", "oks ahw", 20, R_OKS_AHW),
    ("R-A2L-MATCH.8/4", "SRC", "knife 1 x", 20, R_KNIFE_1_X),
    ("R-A2L-MATCH.8/5", "C08i", "out range", 20,
     seq("OUT_OF_RANGE_{}", range(1, 4), "token", (0, 3), (7, 12))),
    ("R-A2L-MATCH.8/6", "SRC", "knife.*", 4,
     [E("parameter_instance[0].Knife[0].x", "token", (22, 27)),
      E("parameter_instance[0].Knife[1].x", "token", (22, 27)),
      E("parameter_instance[1].Knife[0].x", "token", (22, 27)),
      E("parameter_instance[1].Knife[1].x", "token", (22, 27))]),
    ("R-A2L-MATCH.8/7", "CUR", "a value", 20,
     [E("AValue", "token", (0, 6)), E("ABSValue", "token", (0, 1), (3, 8))]),
    ("R-A2L-MATCH.8/8", "CUR", "map 3 d", 20, [E("Map3D", "token", (0, 5))]),
    ("R-A2L-MATCH.8/9", "C08", "VALUE_0001_VALUE_0001", 20,
     [E("VALUE_0001", "token", (0, 5), (6, 10))]),
    # --- R-A2L-MATCH.9 subsequence
    ("R-A2L-MATCH.9/1", "C08", "mp", 3, seq("MAP_{:04d}", range(1, 4), "subsequence", (0, 1), (2, 3))),
    ("R-A2L-MATCH.9/2", "C08", "ascii 1", 20,
     [E("ASCII_0001", "subsequence", (0, 5), (9, 10)), E("ASCII_0010", "subsequence", (0, 5), (8, 9))]),
    ("R-A2L-MATCH.9/3", "C08", "map 20", 20, [E("MAP_0020", "subsequence", (0, 3), (6, 8))]),
    ("R-A2L-MATCH.9/4", "BAL", "gamecontroller timer", 3, R_GAME_TIMER),
    # --- R-A2L-MATCH.10 fuzzy kinds
    ("R-A2L-MATCH.10/1", "C08", "cuvre", 3, seq("CURVE_{:04d}", range(1, 4), "fuzzy", (0, 5), e=1)),
    ("R-A2L-MATCH.10/2", "C08", "maesurement_0001", 20,
     [E("MEASUREMENT_0001", "fuzzy", (0, 11), (12, 16), e=1)]),
    ("R-A2L-MATCH.10/3", "C08", "vlaue_0001", 20, [E("VALUE_0001", "fuzzy", (0, 5), (6, 10), e=1)]),
    ("R-A2L-MATCH.10/4", "C08", "mpa", 3, seq("MAP_{:04d}", range(1, 4), "fuzzy", (0, 3), e=1)),
    ("R-A2L-MATCH.10/5", "C08", "xmap", 3, seq("MAP_{:04d}", range(1, 4), "fuzzy", (0, 3), e=1)),
    ("R-A2L-MATCH.10/6", "C08", "maq", 3, seq("MAP_{:04d}", range(1, 4), "fuzzy", (0, 3), e=1)),
    # --- R-A2L-MATCH.11 tokens that allow no edit
    ("R-A2L-MATCH.11/1", "C08", "VALUE_0300", 20, []),
    ("R-A2L-MATCH.11/2", ("BA_X",), "ab", 20, []),
    ("R-A2L-MATCH.11/3", ("abc",), "ca", 20, []),
    # --- R-A2L-MATCH.12 one edit
    ("R-A2L-MATCH.12/3", "C08", "cvure", 20, []),
    ("R-A2L-MATCH.12/4", ("٣٣٣_X",), "٣٣٤", 20, [E("٣٣٣_X", "fuzzy", (0, 3), e=1)]),
    # --- R-A2L-MATCH.13 two edits
    ("R-A2L-MATCH.13/1", "C08", "valuexx_0001", 20, [E("VALUE_0001", "fuzzy", (0, 5), (6, 10), e=2)]),
    ("R-A2L-MATCH.13/2", "C08", "valuexxx_0001", 20, []),
    ("R-A2L-MATCH.13/3", ("CUVE", "CURVE_0001"), "curvee", 20, R_CURVEE),
    ("R-A2L-MATCH.13/4", "C08", "crxuve", 20, []),
    # --- R-A2L-MATCH.14 every match is listed
    ("R-A2L-MATCH.14/1", "C08", "value_000", 100, R_VALUE_000),
    ("R-A2L-MATCH.14/2", "C08", "0001", 100, R_0001),
    # --- R-A2L-MATCH.15 names that meet no rule / blank names
    ("R-A2L-MATCH.15/1", "C08", "temp_sensor_max", 20, []),
    ("R-A2L-MATCH.15/2", ("", "   ", "VALUE_0001"), "v", 20, [E("VALUE_0001", "prefix", (0, 1))]),
    # --- R-A2L-MATCH.16 first rule wins
    ("R-A2L-MATCH.16/1", "C08", "value_000", 1, [E("VALUE_0001", "prefix", (0, 9))]),
    ("R-A2L-MATCH.16/2", "C08", "valu_0001", 20,
     [E("VALUE_0001", "token", (0, 4), (6, 10)), E("VAL_BLK_0001", "fuzzy", (0, 3), (8, 12), e=1)]),
    ("R-A2L-MATCH.16/3", "C08", "vale_0001", 20,
     [E("VALUE_0001", "fuzzy", (0, 5), (6, 10), e=1), E("VAL_BLK_0001", "fuzzy", (0, 3), (8, 12), e=1)]),
    # --- R-A2L-MATCH.17 a repeated name is listed once
    ("R-A2L-MATCH.17/1", "C08i", "VALUE_0001", 20, SPAN_00),
    ("R-A2L-MATCH.17/2", "C08i", "value_000", 20, R_VALUE_000),
    # --- R-A2L-MATCH.18/3 limit 1
    ("R-A2L-MATCH.18/3", "C08", "value_000", 1, [E("VALUE_0001", "prefix", (0, 9))]),
    # --- R-A2L-MATCH.19 limit below 1
    ("R-A2L-MATCH.19/1", "C08", "VALUE", 0, []),
    ("R-A2L-MATCH.19/2", "C08", "VALUE", -1, []),
    # --- R-A2L-MATCH.20 rank order
    ("R-A2L-MATCH.20/2", "BAL", "gamecontroller.timer", 20,
     [E("model.MainClass.gameController.timer.timeCounter", "substring", (16, 36)),
      E("model.MainClass.gameController.stopWatch.timeCounter", "subsequence",
        (16, 30), (32, 33), (42, 45), (51, 52))]),
    # --- R-A2L-MATCH.21 boundary occurrence first
    ("R-A2L-MATCH.21/1", ("timeCounter", "Encounter"), "counter", 20,
     [E("timeCounter", "substring", (4, 11)), E("Encounter", "substring", (2, 9))]),
    ("R-A2L-MATCH.21/2", "C08", "_0001", 20, R__0001),
    ("R-A2L-MATCH.21/3", "BAL", "ounter", 4, R_OUNTER),
    # --- R-A2L-MATCH.22 fewer edits first
    ("R-A2L-MATCH.22/1", ("CUVE", "CURVE_0001"), "curvee", 20, R_CURVEE),
    # --- R-A2L-MATCH.23 shorter name first
    ("R-A2L-MATCH.23/2", ("rpm_x", "RPMX"), "rpm", 20,
     [E("RPMX", "prefix", (0, 3)), E("rpm_x", "prefix", (0, 3))]),
    # --- R-A2L-MATCH.24 case-exact first
    ("R-A2L-MATCH.24/2", "TW", "RPM", 20,
     [E("RPM", "exact", (0, 3)), E("Rpm", "exact", (0, 3)), E("rpm", "exact", (0, 3))]),
    ("R-A2L-MATCH.24/4", ("DiscouNTCount", "DiscountCount"), "count", 20,
     [E("DiscountCount", "substring", (8, 13)), E("DiscouNTCount", "substring", (8, 13))]),
    # --- R-A2L-MATCH.25 code-point order
    ("R-A2L-MATCH.25/3", "TW2", "rpm", 20,
     [E("rpm", "exact", (0, 3)), E("RPM", "exact", (0, 3)), E("Rpm", "exact", (0, 3))]),
    # --- R-A2L-MATCH.28 boundary occurrence, not the leftmost
    ("R-A2L-MATCH.28/1", ("DiscountCount",), "count", 20, [E("DiscountCount", "substring", (8, 13))]),
    # --- R-A2L-MATCH.32 fuzzy span = whole name token
    ("R-A2L-MATCH.32/1", "C08", "maesu", 3,
     seq("MEASUREMENT_{:04d}", range(1, 4), "fuzzy", (0, 11), e=1)),
    ("R-A2L-MATCH.32/3", "C08", "vblk", 2,
     [E("VAL_BLK_0001", "fuzzy", (4, 7), e=1), E("VAL_BLK_0002", "fuzzy", (4, 7), e=1)]),
    # --- R-A2L-MATCH.33 total edits
    ("R-A2L-MATCH.33/2", "C08", "measurementss_0001", 20,
     [E("MEASUREMENT_0001", "fuzzy", (0, 11), (12, 16), e=2)]),
    ("R-A2L-MATCH.33/3", ("Curve_Map_X",), "cuvre maq", 20,
     [E("Curve_Map_X", "fuzzy", (0, 5), (6, 9), e=2)]),
    # --- R-A2L-MATCH.34 touching spans are joined
    ("R-A2L-MATCH.34/1", "CUR", "abs value", 20, [E("ABSValue", "token", (0, 8))]),
    # --- R-A2L-MATCH.38 query cap
    ("R-A2L-MATCH.38/1", "C08", "VALUE_0001_" * 23 + "VAL", 20,
     [E("VALUE_0001", "token", (0, 5), (6, 10))]),
    ("R-A2L-MATCH.38/2", "C08", "VALUE_0001_" * 23 + "VALU", 20, []),
    # --- R-A2L-MATCH.39 name cap
    ("R-A2L-MATCH.39/1", ("x" * 1024,), "x", 20, [E("x" * 1024, "prefix", (0, 1))]),
    ("R-A2L-MATCH.39/2", ("x" * 1025,), "x", 20, []),
    # --- R-A2L-MATCH.41 fuzzy cap at 20 distinct query tokens (E5 round 2, E5S-07)
    ("R-A2L-MATCH.41/1", "C08", CURV20, 3, seq("CURVE_{:04d}", range(1, 4), "fuzzy", (0, 5), e=20)),
    ("R-A2L-MATCH.41/2", "C08", CURV20 + " curvv", 3, []),
    ("R-A2L-MATCH.41/3", "C08", "curva " + CURV20, 3, seq("CURVE_{:04d}", range(1, 4), "fuzzy", (0, 5), e=21)),
    ("R-A2L-MATCH.41/4", "SWA", SWA_PASTED, 5, [E(SWA_PASTED, "exact", (0, 101))]),
    ("R-A2L-MATCH.41/5", "SWA", SWA_PASTED_REVERSED, 5,
     [E(SWA_PASTED, "token", (0, 3), (4, 7), (8, 11), (12, 13), (14, 37), (38, 44), (45, 48), (49, 57),
        (58, 60), (61, 75), (76, 79), (80, 84), (85, 88), (89, 101))]),
]


@pytest.mark.parametrize(
    "case_id,key,query,limit,expected",
    EXACT_CASES,
    ids=[c[0] for c in EXACT_CASES],
)
def test_ranked_list_is_exactly(prep, case_id, key, query, limit, expected):
    """The ranked list is exactly the case's expected list (names, rules, edits, spans, order).

    Covers (the case id is the pytest id) R-A2L-MATCH.1/1 .1/2 .1/3 .1/4 .2/1 .2/2 .2/3 .2/4
    .2/5 .3/1 .3/2 .3/3 .4/1 .4/2 .4/3 .5/1 .5/2 .6/1 .6/2 .6/3 .7/1 .7/2 .7/3 .7/4 .8/1 .8/2
    .8/3 .8/4 .8/5 .8/6 .8/7 .8/8 .8/9 .9/1 .9/2 .9/3 .9/4 .10/1 .10/2 .10/3 .10/4 .10/5
    .10/6 .11/1 .11/2 .11/3 .12/3 .12/4 .13/1 .13/2 .13/3 .13/4 .14/1 .14/2 .15/1 .15/2
    .16/1 .16/2 .16/3 .17/1 .17/2 .18/3 .19/1 .19/2 .20/2 .21/1 .21/2 .21/3 .22/1 .23/2
    .24/2 .24/4 .25/3 .28/1 .32/1 .32/3 .33/2 .33/3 .34/1 .38/1 .38/2 .39/1 .39/2 .41/1 .41/2 .41/3 .41/4 .41/5.
    """
    got = proj(run(prep, key, query, limit))
    assert got == expected, f"{case_id}: query {query!r} limit {limit}"


# ---------------------------------------------------------------------------
# R-A2L-MATCH.41 behavioural negative control
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("n_distinct", [18, 19, 20, 21, 22, 25])
def test_r_a2l_match_41_cap_boundary_is_exactly_20_distinct_tokens(prep, n_distinct):
    """R-A2L-MATCH.41 (control for /1../3): a query of up to 20 distinct tokens may list a name only the fuzzy
    rule finds (CURVE_0001, one edit per token); a query of more than 20 distinct tokens never lists one.
    Behavioural, not timing: with the cap removed the 21, 22 and 25 token queries list the fuzzy names."""
    letters = [c for c in "abcdefghijklmnopqrstuvwxyz" if c != "e"]
    query = " ".join("curv" + c for c in letters[:n_distinct])
    got = run(prep, "C08", query, 3)
    if n_distinct <= 20:
        assert [(m.name, m.rule.value, m.edits) for m in got] == [
            (f"CURVE_{i:04d}", "fuzzy", n_distinct) for i in range(1, 4)
        ]
    else:
        assert not [m for m in got if m.rule.value == "fuzzy"], [m.name for m in got]
        assert got == []


# ---------------------------------------------------------------------------
# Relational cases (an entry, a part or a property of a list)
# ---------------------------------------------------------------------------


def test_rows_5_3_three_exact_matches_are_all_listed(prep):
    """R-A2L-MATCH.5/3: three exact matches are all listed."""
    got = run(prep, "TW", "rpm")
    assert len(got) == 3
    assert all(m.rule.value == "exact" for m in got)


@pytest.mark.parametrize("query", ["maq", "cuvre"], ids=["R-A2L-MATCH.12/1", "R-A2L-MATCH.12/2"])
def test_rows_12_one_edit_for_3_and_5_letter_tokens(prep, query):
    """R-A2L-MATCH.12/1 (maq, 3 letters) and .12/2 (cuvre, 5 letters): 3 entries, each fuzzy with 1 edit."""
    got = run(prep, "C08", query, 3)
    assert len(got) == 3
    assert [(m.rule.value, m.edits) for m in got] == [("fuzzy", 1)] * 3


def test_rows_18_1_limit_cut_is_the_head_of_the_full_list(prep):
    """R-A2L-MATCH.18/1: limit 5 gives the first 5 entries of R-A2L-MATCH.14/1."""
    assert proj(run(prep, "C08", "value_000", 5)) == R_VALUE_000[:5]


def test_rows_18_2_limit_above_the_count_lists_them_all(prep):
    """R-A2L-MATCH.18/2: limit 20 over a 6-match query gives the 6 entries of R-A2L-MATCH.7/1."""
    assert proj(run(prep, "C08", "0001", 20)) == R_0001


def test_rows_20_1_prefix_before_subsequence(prep):
    """R-A2L-MATCH.20/1: entries 1-9 are the prefix matches and entries 10-20 the subsequence ones."""
    got = proj(run(prep, "C08", "value_000"))
    assert len(got) == 20
    assert [r for (_, r, _, _) in got[:9]] == ["prefix"] * 9
    assert [r for (_, r, _, _) in got[9:]] == ["subsequence"] * 11
    assert got == R_VALUE_000


def test_rows_20_3_token_then_fuzzy_then_subsequence(prep):
    """R-A2L-MATCH.20/3: the three entries of R-A2L-MATCH.8/3, token, then fuzzy, then subsequence."""
    got = proj(run(prep, "SWB", "oks ahw"))
    assert got == R_OKS_AHW
    assert [r for (_, r, _, _) in got] == ["token", "fuzzy", "subsequence"]


def test_rows_23_1_shorter_name_first(prep):
    """R-A2L-MATCH.23/1: among equal rule and key the 8-character MAP_0001 is first, the 16-character MEASUREMENT_0001 last."""
    got = run(prep, "C08", "0001")
    assert len(got) == 6
    assert got[0].name == "MAP_0001" and len(got[0].name) == 8
    assert got[5].name == "MEASUREMENT_0001" and len(got[5].name) == 16
    lengths = [len(m.name) for m in got]
    assert lengths == sorted(lengths)


def test_rows_24_1_case_exact_name_first_for_lowercase_query(prep):
    """R-A2L-MATCH.24/1: for ``rpm`` over RPM, rpm, Rpm entry 1 is ``rpm``."""
    assert run(prep, "TW", "rpm")[0].name == "rpm"


def test_rows_24_3_fuzzy_ties_fall_to_code_point_order(prep):
    """R-A2L-MATCH.24/3: fuzzy names of one rule, key and length are not ordered by case-exactness: entry 2 is DRÜCK_MAX, entry 3 druck_max."""
    got = run(prep, "NA", "drück")
    assert [m.name for m in got] == ["Drück_Max", "DRÜCK_MAX", "druck_max"]
    assert got[1].name == "DRÜCK_MAX" and got[2].name == "druck_max"


def test_rows_25_1_code_point_order_among_equals(prep):
    """R-A2L-MATCH.25/1: entries 2-4 of ``0001`` are ASCII_0001, CURVE_0001, VALUE_0001 in that order."""
    got = names_of_result(run(prep, "C08", "0001"))
    assert got[1:4] == ["ASCII_0001", "CURVE_0001", "VALUE_0001"]


def test_rows_25_2_input_order_decides_nothing(prep):
    """R-A2L-MATCH.25/2: the reversed case-08 list gives the same 6 entries, in the same order, as R-A2L-MATCH.7/1."""
    assert proj(run(prep, "C08r", "0001")) == R_0001


def test_rows_26_exact_span(prep):
    """R-A2L-MATCH.26/1 and .26/2: an exact entry's spans are exactly the whole name."""
    assert spans_of(run(prep, "C08", "VALUE_0001"), "VALUE_0001") == ((0, 10),)
    assert spans_of(run(prep, "C08", "map_0020"), "MAP_0020") == ((0, 8),)


def test_rows_27_prefix_span_counts_the_query_text_not_whitespace(prep):
    """R-A2L-MATCH.27/1, .27/2, .27/3: every prefix entry's spans are exactly (0,k); stripped whitespace counts in no span."""
    assert [m.spans for m in run(prep, "C08", "value_000", 5)] == [((0, 9),)] * 5
    assert [m.spans for m in run(prep, "C08i", "span")] == [((0, 4),)] * 2
    assert [m.spans for m in run(prep, "C08", " value_000 ", 5)] == [((0, 9),)] * 5


def test_rows_28_2_boundary_span_after_a_separator(prep):
    """R-A2L-MATCH.28/2: MAP_0001's span for ``0001`` is exactly (4,8)."""
    assert spans_of(run(prep, "C08", "0001"), "MAP_0001") == ((4, 8),)


def test_rows_29_span_with_no_boundary_occurrence(prep):
    """R-A2L-MATCH.29/1 (BAL ``ounter``) and .29/2 (SWB ``sahw`` inside an uppercase run)."""
    got = run(prep, "BAL", "ounter", 4)
    assert spans_of(got, "model.MainClass.ledController.sw.timeCounter") == ((38, 44),)
    first = run(prep, "SWB", "sahw")[0]
    assert (first.name, first.rule.value, first.spans) == (R_LUK_SAHW, "substring", ((21, 25),))


def test_rows_30_token_spans(prep):
    """R-A2L-MATCH.30/1, .30/2 (leftmost name token a query token starts) and .30/3 (one-letter token)."""
    assert [m.spans for m in run(prep, "C08", "blk val 00", 3)] == [((0, 3), (4, 7), (8, 10))] * 3
    assert spans_of(run(prep, "SRC", "knife 1 x"), "parameter_instance[1].Knife[0].x") == (
        (19, 20), (22, 27), (31, 32))
    assert spans_of(run(prep, "CUR", "a value"), "ABSValue") == ((0, 1), (3, 8))


def test_rows_31_subsequence_spans(prep):
    """R-A2L-MATCH.31/1, .31/2 (across a separator) and .31/3 (leftmost-after-previous on a long name)."""
    assert [m.spans for m in run(prep, "C08", "mp", 3)] == [((0, 1), (2, 3))] * 3
    assert spans_of(run(prep, "C08", "value_000"), "VALUE_0010") == ((0, 5), (6, 8), (9, 10))
    assert spans_of(run(prep, "BAL", "gamecontroller timer", 3),
                    "model.MainClass.gameController.stopWatch.timeCounter") == (
        (16, 30), (32, 33), (42, 45), (51, 52))


def test_rows_32_2_fuzzy_spans_of_two_query_tokens(prep):
    """R-A2L-MATCH.32/2: VAL_BLK_0001's spans for ``valu_0001`` are exactly (0,3),(8,12)."""
    assert spans_of(run(prep, "C08", "valu_0001"), "VAL_BLK_0001") == ((0, 3), (8, 12))


def test_rows_33_1_total_edits_one(prep):
    """R-A2L-MATCH.33/1: ``maesurement_0001`` gives an entry whose total edits are 1."""
    got = run(prep, "C08", "maesurement_0001")
    assert [(m.name, m.edits) for m in got] == [("MEASUREMENT_0001", 1)]


def test_rows_34_spans_in_offset_order_and_joined(prep):
    """R-A2L-MATCH.34/2 (offset order whatever the query order) and .34/3 (touching spans joined)."""
    got = run(prep, "C08", "blk val 00", 1)
    assert [m.name for m in got] == ["VAL_BLK_0001"]
    assert got[0].spans == ((0, 3), (4, 7), (8, 10))
    assert list(got[0].spans) == sorted(got[0].spans)
    assert spans_of(run(prep, "CUR", "a value"), "AValue") == ((0, 6),)


# ---------------------------------------------------------------------------
# Acceptance cases (black-box through I-3)
# ---------------------------------------------------------------------------


def test_at_b103_i4_1_typing_a_name_keystroke_by_keystroke(prep):
    """AT-B103-I4-1: typing MAP_0020 one key at a time over the case-08 names gives the expected list at each step.

    Rows .5, .6, .9, .18, .23, .25, .27, .31 (limit 5, one prepared list ranked in turn).
    """
    steps = [
        ("m", seq("MAP_{:04d}", range(1, 6), "prefix", (0, 1))),
        ("ma", seq("MAP_{:04d}", range(1, 6), "prefix", (0, 2))),
        ("map", seq("MAP_{:04d}", range(1, 6), "prefix", (0, 3))),
        ("map_", seq("MAP_{:04d}", range(1, 6), "prefix", (0, 4))),
        ("map_00", seq("MAP_{:04d}", range(1, 6), "prefix", (0, 6))),
        ("map_002", [
            E("MAP_0020", "prefix", (0, 7)),
            E("MAP_0002", "subsequence", (0, 3), (4, 6), (7, 8)),
            E("MAP_0012", "subsequence", (0, 3), (4, 6), (7, 8)),
        ]),
        ("map_0020", [E("MAP_0020", "exact", (0, 8))]),
    ]
    for query, expected in steps:
        assert proj(run(prep, "C08", query, 5)) == expected, query


AT2_TARGET = "JotafVod_msrqlLzL_kh2C_rWl_pfue._0_"


@pytest.mark.parametrize(
    "query,rule,edits,span",
    [
        (AT2_TARGET, "exact", 0, (0, 35)),
        ("jotafvod", "prefix", 0, (0, 8)),
        ("msrqlLzL", "substring", 0, (9, 17)),
        ("pfue._0_", "substring", 0, (27, 35)),
        ("jotaf vod", "token", 0, (0, 8)),
        ("vod jotaf", "token", 0, (0, 8)),
        ("jotfa vod", "fuzzy", 1, (0, 8)),
        ("jotaf_vdo", "fuzzy", 1, (0, 8)),
    ],
    ids=["whole", "start", "middle", "end", "words", "words-reversed", "typo-words", "typo-underscore"],
)
def test_at_b103_i4_2_a_real_shape_name_is_found_first(prep, query, rule, edits, span):
    """AT-B103-I4-2: over the 13,990 real-shape names the target is entry 1 for its whole text, start, middle, end, two words in either order and a typo."""
    assert len(prep("SWA").names) >= 13_000  # fixture sanity: the real-shape list
    assert AT2_TARGET in prep("SWA").names
    got = run(prep, "SWA", query, 5)
    assert got, f"nothing listed for {query!r}"
    first = got[0]
    assert (first.name, first.rule.value, first.edits, first.spans) == (
        AT2_TARGET, rule, edits, (span,)), query


# ---------------------------------------------------------------------------
# I-3 interface checks (errors, purity, read-only, types)
# ---------------------------------------------------------------------------


def test_i3_match_rule_members_are_the_six_words_in_rank_order():
    """I-3: MatchRule has six members, value = the rule word, declared in rank order (exact first, subsequence last)."""
    assert [m.value for m in MatchRule] == [
        "exact", "prefix", "substring", "token", "fuzzy", "subsequence"]
    assert issubclass(MatchRule, str) and issubclass(MatchRule, enum.Enum)
    assert MatchRule.EXACT == "exact"


def test_i3_label_match_is_a_frozen_value_type_with_four_fields():
    """I-3: LabelMatch has name, rule, edits, spans; it compares by value and is read-only."""
    fields = [f.name for f in dataclasses.fields(LabelMatch)]
    assert fields == ["name", "rule", "edits", "spans"]
    a = LabelMatch(name="A", rule=MatchRule.EXACT, edits=0, spans=((0, 1),))
    b = LabelMatch(name="A", rule=MatchRule.EXACT, edits=0, spans=((0, 1),))
    assert a == b
    with pytest.raises(dataclasses.FrozenInstanceError):
        a.name = "B"  # type: ignore[misc]


def test_i3_rank_returns_label_match_values(prep):
    """I-3: rank returns a list of LabelMatch whose rule is a MatchRule and whose spans are tuples of (start, end) ints."""
    got = run(prep, "C08", "value_000", 5)
    assert isinstance(got, list)
    for m in got:
        assert isinstance(m, LabelMatch)
        assert isinstance(m.rule, MatchRule)
        assert isinstance(m.edits, int) and not isinstance(m.edits, bool)
        assert isinstance(m.spans, tuple)
        assert all(isinstance(s, tuple) and len(s) == 2 for s in m.spans)
    assert got == run(prep, "C08", "value_000", 5)  # compares by value


def test_i3_build_refuses_a_bare_string_and_bytes():
    """I-3 (E3S-06): a str or bytes argument is refused, not iterated as characters."""
    with pytest.raises(TypeError) as err:
        build_label_index("VALUE")
    assert str(err.value) == "label names must be an iterable of str, got str"
    with pytest.raises(TypeError, match="label names must be an iterable of str"):
        build_label_index(b"VALUE")


def test_i3_build_refuses_an_element_that_is_not_a_str():
    """I-3: an element that is not a str raises TypeError('label names must be str, got <type name>')."""
    with pytest.raises(TypeError) as err:
        build_label_index(["VALUE_0001", None])
    assert str(err.value) == "label names must be str, got NoneType"
    with pytest.raises(TypeError) as err2:
        build_label_index(["A", 3])
    assert str(err2.value) == "label names must be str, got int"


def test_i3_empty_iterable_gives_an_empty_index_and_empty_rankings():
    """I-3 / R-A2L-MATCH.15 edge: an empty iterable gives an index of length 0; any ranking over it is []."""
    index = build_label_index([])
    assert len(index) == 0
    assert index.names == ()
    assert rank("VALUE", index, 20) == []
    assert rank("", index, 20) == []


def test_i3_build_accepts_any_iterable_of_str():
    """I-3: build_label_index takes an iterable (a generator, a tuple), not only a list."""
    from_gen = build_label_index(n for n in ("MAP_0001", "MAP_0002"))
    from_tuple = build_label_index(("MAP_0001", "MAP_0002"))
    assert from_gen.names == from_tuple.names == ("MAP_0001", "MAP_0002")
    assert proj(rank("map_0002", from_gen, 5)) == [E("MAP_0002", "exact", (0, 8))]


def test_i3_index_holds_distinct_names_in_first_occurrence_order(prep, lists):
    """I-3 / R-A2L-MATCH.17: names are the distinct input names in first-occurrence order; len is their count."""
    index = prep("C08i")
    assert index.names == tuple(dict.fromkeys(lists["C08i"]))
    assert len(index) == len(index.names) == 469


def test_i3_index_and_names_are_read_only(prep):
    """I-3: a LabelIndex cannot be reassigned after the build (frozen)."""
    index = prep("C08")
    with pytest.raises(dataclasses.FrozenInstanceError):
        index.names = ()  # type: ignore[misc]
    assert isinstance(index.names, tuple)


def test_i3_index_repr_keeps_the_names_out_of_logs(prep):
    """I-3 (repr=False): repr of a prepared index does not dump its names."""
    assert "VALUE_0001" not in repr(prep("C08"))


def test_i3_rank_type_errors_query_first_then_limit(prep):
    """I-3: rank raises TypeError for a non-str query (checked first) and for a non-int or bool limit, with the pinned texts."""
    index = prep("C08")
    with pytest.raises(TypeError) as e1:
        rank(None, index, 20)  # type: ignore[arg-type]
    assert str(e1.value) == "query must be str, got NoneType"
    with pytest.raises(TypeError) as e2:
        rank("VALUE", index, True)  # type: ignore[arg-type]
    assert str(e2.value) == "limit must be int, got bool"
    with pytest.raises(TypeError) as e3:
        rank("VALUE", index, 2.0)  # type: ignore[arg-type]
    assert str(e3.value) == "limit must be int, got float"
    with pytest.raises(TypeError) as e4:
        rank(None, index, True)  # type: ignore[arg-type]
    assert str(e4.value) == "query must be str, got NoneType"


def test_i3_rank_never_raises_for_any_str_query_and_int_limit(prep):
    """I-3: for any str query and int limit rank does not raise (control characters, huge limit, non-BMP, lone surrogates)."""
    index = prep("C08")
    for query in ["\x00", "\x1f\x7f", "😀", "a\ud800b", "́", "[" * 50, "*.?\\"]:
        assert isinstance(rank(query, index, 20), list)
    assert isinstance(rank("value", index, 10**9), list)
    assert len(rank("value", index, 10**9)) <= len(index)


def test_i3_rank_is_pure_and_does_not_change_its_arguments(lists):
    """I-3: same query, index and limit give equal lists; neither call changes its arguments."""
    names = list(lists["C08"])
    before = list(names)
    index = build_label_index(names)
    names_before = index.names
    first = rank("value_000", index, 20)
    second = rank("value_000", index, 20)
    assert first == second
    assert names == before
    assert index.names is names_before and index.names == tuple(before)


def test_i3_the_index_is_shared_not_consumed(prep):
    """I-3: one prepared index serves many rankings in any order with the same results (no per-call state)."""
    a1 = proj(run(prep, "C08", "map", 5))
    run(prep, "C08", "zzzz")
    run(prep, "C08", "value_000", 100)
    a2 = proj(run(prep, "C08", "map", 5))
    assert a1 == a2


def test_i3_ranking_is_independent_of_input_order(lists):
    """R-A2L-MATCH.25 (determinism): two separately built indexes over a shuffled copy give the same ranked lists."""
    names = list(lists["C08"])
    shuffled = list(names)
    random.Random(7).shuffle(shuffled)
    i1, i2 = build_label_index(names), build_label_index(shuffled)
    for q in ["0001", "value_000", "cuvre", "mp", "blk val 00", "_0"]:
        assert proj(rank(q, i1, 50)) == proj(rank(q, i2, 50)), q


def test_i3_module_imports_the_standard_library_only():
    """I-3 / graph header: the matcher imports array, bisect, collections, dataclasses, enum, typing (and __future__) only - no Textual, no s19_app module."""
    import s19_app.tui.services.label_match as module

    tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            roots.add((node.module or "").split(".")[0])
    assert roots <= {"__future__", "array", "bisect", "collections", "dataclasses", "enum", "typing"}, sorted(roots)
