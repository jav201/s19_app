"""Inc 4 (batch-103) - label similarity matcher: time and memory bounds (G-T2).

Independent tester file (E4). Cases (``02-test-cases.md``):

- R-A2L-MATCH.35/1 - preparing 50,000 names: median of 3 <= 5.0 s.
- R-A2L-MATCH.36/1 - ranking per keystroke: for every query of QSET over REF and
  of the REF6 query set, limit 20, the median of 7 consecutive rankings <= 200 ms.
- R-A2L-MATCH.37/1 - the tracemalloc peak of preparing REF <= 64 MiB.
- R-A2L-MATCH.40/1 - every pathological PSET query over its list: median of 7 <= 1.0 s.
- R-A2L-MATCH.40/2 - the three LONG queries over LONG: median of 7 <= 1.0 s.
- R-A2L-MATCH.40/3 - the 4-token and the 51-token CRAFT queries over CRAFT (E5S-01).
- R-A2L-MATCH.40/4 - a query that still reaches ``_prefix_distance`` after the posting
  switch (BAND list): the banded distance keeps it fast, the no-band mutant does not.

The timing arms carry ``serial_timing`` (run apart and serially); the memory
bound R-A2L-MATCH.37/1 is a byte bound and carries none. The bounds are stated
for the reference host (cachyos-rtx, Python 3.11.18); every upper bound goes
through ``report_margin`` as ``tests/support/timing.py`` asks. The host load
average is printed before and after each measured group (POSIX only). Lists are
prepared before any clock or ``tracemalloc`` starts, except where the case
measures the preparation itself.
"""
from __future__ import annotations

import gc
import hashlib
import os
import random
import statistics
import string
import time
import tracemalloc
from pathlib import Path

import pytest

from s19_app.tui.a2l import parse_a2l_file
from s19_app.tui.services.label_match import build_label_index, rank
from tests.support.timing import report_margin, timing_bound

REPO_ROOT = Path(__file__).resolve().parent.parent
SWA_PATH = REPO_ROOT / "examples" / "case_00_public" / "software_a.a2l"
CASE6_PATH = REPO_ROOT / "examples" / "case_06_large_nested_a2l" / "firmware.a2l"

PREP_BOUND_S = 5.0  # R-A2L-MATCH.35
KEYSTROKE_BOUND_S = 0.200  # R-A2L-MATCH.36
ANY_QUERY_BOUND_S = 1.0  # R-A2L-MATCH.40
MEMORY_BOUND_BYTES = 64 * 1024 * 1024  # R-A2L-MATCH.37 = 67,108,864


# ---------------------------------------------------------------------------
# Fixtures (02-test-cases.md "Fixtures")
# ---------------------------------------------------------------------------


def _read_names(path: Path):
    return [str(t["name"]) for t in parse_a2l_file(path)["tags"] if t.get("name") is not None]


def _load(label: str) -> str:
    try:
        one, five, fifteen = os.getloadavg()
    except (AttributeError, OSError):  # not POSIX
        return f"host load {label}: n/a"
    return f"host load {label}: {one:.2f} {five:.2f} {fifteen:.2f}"


@pytest.fixture(scope="module")
def swa():
    return _read_names(SWA_PATH)


@pytest.fixture(scope="module")
def ref_names(swa):
    """REF: the SWA names, then each with ``_1``, ``_2``, ``_3`` appended; the first 50,000."""
    ref = (swa + [n + "_1" for n in swa] + [n + "_2" for n in swa] + [n + "_3" for n in swa])[:50000]
    assert len(ref) == 50000 and len(set(ref)) == 50000  # fixture sanity
    return ref


@pytest.fixture(scope="module")
def ref6_names():
    """REF6: the first 50,000 names of case 06's firmware.a2l (every name 13 characters)."""
    names = _read_names(CASE6_PATH)[:50000]
    assert len(names) == 50000
    assert {len(n) for n in names} == {13}  # fixture sanity
    return names


@pytest.fixture(scope="module")
def ref_index(ref_names):
    return build_label_index(ref_names)


@pytest.fixture(scope="module")
def ref6_index(ref6_names):
    return build_label_index(ref6_names)


@pytest.fixture(scope="module")
def long_names(ref_names):
    """LONG: the first 49,900 REF names and 100 names of 1,022 or 1,023 characters."""
    names = ref_names[:49900] + ["a" * 1020 + "_" + str(i) for i in range(100)]
    assert len(names) == 50000
    assert {len(n) for n in names[49900:]} <= {1022, 1023}
    return names


@pytest.fixture(scope="module")
def long_index(long_names):
    return build_label_index(long_names)


# The REF name with the most tokens (27 tokens, 103 characters; ties in code-point
# order), found once with an independent tokeniser on the reference host, and the same
# name with its first two characters swapped (E3S-01 shapes 7 and 8 of QSET).
LONGEST_REF_NAME = "HRR_WOL.TNY_U_ZmyrXSZTPeyoMsdpWwbcUtd_Dwvrap_YAL_o8gk5143_Tw_WjPcscmtzpCrxe_GFV_TVY3_YES_AyxwevsxrDBB_1"
SWAPPED_REF_NAME = LONGEST_REF_NAME[1] + LONGEST_REF_NAME[0] + LONGEST_REF_NAME[2:]

_LOWER = string.ascii_lowercase


def qset33(swa, ref):
    """QSET: the 33 queries of 02-test-cases.md (E3S-01 shapes built as the case text says)."""
    base = [
        "a", "e", "0", "zz", "ab", "JotafVod_msrqlLzL_kh2C_rWl_pfue._0_", "JotafVod_msr", "srqlLzL_",
        "0 jotaf", "JVmL", "xqzjvkw", "qqqq zzzz", "aaaa", "e e e", "Nzukij", "Ierxjr_Eud", "ledRing",
        "pposbxiif", "cnt", "temp_sensor_max", "x y z w v u", "pposbxiifkdgfiajnbbpvb_dyan_xvz1",
    ]
    multi = [
        "njraipjtbtu lsuakcoj hsxgibymjxu orfltalc uadvdygb zobnkw",
        "votklbi fjblnabj qghque pdjxmq tiprdynotu djchlitjt",
        "lmmwngodou jadkvqy khbnukc qomfrybiza evfwbqj",
    ]
    pool = random.Random(20261108).sample(swa, 400)
    assert LONGEST_REF_NAME in set(ref)  # fixture sanity
    shapes = [
        "e " * 128,
        ((" ".join(_LOWER) + " ") * 20)[:256],
        "0 " * 128,
        "a" * 256,
        ",".join(pool)[:256],
        ",".join(pool[200:])[:256],
        LONGEST_REF_NAME,
        SWAPPED_REF_NAME,
    ]
    out = base + multi + shapes
    assert len(out) == 33
    return out


REF6_QUERIES = ["m", "meas_", "chr", "mesa", "cahr", "cr0", "char 1", "0", "chr 0", "ch00", "meas 1", "c 0 1"]


def pset_ref():
    """PSET over REF: six pathological shapes (R-A2L-MATCH.40/1)."""
    return [
        ("qzx x64", "qzx " * 64),
        ("qza..qzz x3", ((" ".join("qz" + c for c in _LOWER) + " ") * 3)[:256]),
        ("cnt x64", "cnt " * 64),
        ("1a x128", "1a" * 128),
        ("rat x64", ("rat " * 64)[:256]),
        ("e x120 + rat", "e " * 120 + "rat"),
    ]


def pset_ref6(swa):
    """PSET over REF6: the shapes of both E3 round-2 reviews, then QSET's eight E3S-01 shapes."""
    near = (
        ["ch" + c for c in _LOWER] + [c + "ha" for c in _LOWER] + ["c" + c + "a" for c in _LOWER]
    )
    typos = []
    for pos in range(4):
        for c in _LOWER:
            cand = "char"[:pos] + c + "char"[pos + 1:]
            if cand != "char":
                typos.append(cand)
    typos = typos[:51]
    pool = random.Random(20261108).sample(swa, 400)
    return [
        ("chr x64", "chr " * 64),
        ("cahr x51", "cahr " * 51),
        ("0 x128", "0 " * 128),
        ("00 x85", "00 " * 85),
        ("c 0 x64", "c 0 " * 64),
        ("c x128", "c " * 128),
        ("m x128", "m " * 128),
        ("1 x128", "1 " * 128),
        ("c x125 + chax", "c " * 125 + "chax"),
        ("0 x125 + chax", "0 " * 125 + "chax"),
        ("chax x52", ("chax " * 52)[:256]),
        ("mesa x52", ("mesa " * 52)[:256]),
        ("near tokens", " ".join(near)[:256]),
        ("cha..chz x3", ((" ".join("ch" + c for c in _LOWER) + " ") * 3)[:256]),
        ("51 typos of char", " ".join(typos)[:256]),
        ("E3S-01 e x128", "e " * 128),
        ("E3S-01 a..z", ((" ".join(_LOWER) + " ") * 20)[:256]),
        ("E3S-01 0 x128", "0 " * 128),
        ("E3S-01 a x256", "a" * 256),
        ("E3S-01 pool join", ",".join(pool)[:256]),
        ("E3S-01 pool[200:] join", ",".join(pool[200:])[:256]),
        ("E3S-01 longest REF name", LONGEST_REF_NAME),
        ("E3S-01 longest swapped", SWAPPED_REF_NAME),
    ]


LONG_QUERIES = [
    ("a x255 + b", "a" * 255 + "b"),
    ("a x254 + bb", "a" * 254 + "bb"),
    ("a x128 + b", "a" * 128 + "b"),
]


def _median_of(n, call):
    times = []
    for _ in range(n):
        t0 = time.perf_counter()
        call()
        times.append(time.perf_counter() - t0)
    return statistics.median(times)


def _check_all(medians, bound_s):
    """Print EVERY margin line (no truncation, whatever the reporter or a ``tail`` keeps), then assert each
    median against ``report_margin(..., timing_bound(bound_s))``; the failure names its label."""
    bound = timing_bound(bound_s)
    for label_, median in medians:
        print(f"  {median * 1000:9.2f} ms  {(bound - median) / bound * 100:6.1f} % margin  {label_}")
    for label_, median in medians:
        assert median <= report_margin(label_, median, bound), f"{label_}: median {median:.4f} s"


# ---------------------------------------------------------------------------
# Query tables, built once at import from fixtures that need no matcher call
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def qset_ref(swa, ref_names):
    return qset33(swa, ref_names)


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------


@pytest.mark.serial_timing
def test_r_a2l_match_35_1_preparing_50000_names(ref_names):
    """R-A2L-MATCH.35/1: the median of 3 preparations of REF (50,000 names) <= 5.0 s."""
    gc.collect()
    print(_load("before"))
    times = []
    for _ in range(3):
        t0 = time.perf_counter()
        index = build_label_index(ref_names)
        times.append(time.perf_counter() - t0)
        assert len(index) == 50000
        del index
    print(_load("after"), "prep times", [round(t, 3) for t in times])
    median = statistics.median(times)
    _check_all([("R-A2L-MATCH.35 prepare REF", median)], PREP_BOUND_S)


@pytest.mark.serial_timing
def test_r_a2l_match_36_1_ranking_per_keystroke_over_ref(ref_index, qset_ref):
    """R-A2L-MATCH.36/1: each query of QSET over REF, limit 20, median of 7 rankings <= 200 ms."""
    print(_load("before"))
    medians = []
    for query in qset_ref:
        medians.append((f"R-A2L-MATCH.36 REF {query[:40]!r}", _median_of(7, lambda q=query: rank(q, ref_index, 20))))
    print(_load("after"))
    _check_all(medians, KEYSTROKE_BOUND_S)


@pytest.mark.serial_timing
def test_r_a2l_match_36_1_ranking_per_keystroke_over_ref6(ref6_index):
    """R-A2L-MATCH.36/1: each query of the REF6 query set over REF6, limit 20, median of 7 <= 200 ms."""
    print(_load("before"))
    medians = []
    for query in REF6_QUERIES:
        medians.append((f"R-A2L-MATCH.36 REF6 {query!r}", _median_of(7, lambda q=query: rank(q, ref6_index, 20))))
    print(_load("after"))
    _check_all(medians, KEYSTROKE_BOUND_S)


def test_r_a2l_match_37_1_prepared_list_stays_within_64_mib(ref_names):
    """R-A2L-MATCH.37/1: the tracemalloc peak while preparing REF once is <= 67,108,864 bytes."""
    gc.collect()
    tracemalloc.start()
    try:
        index = build_label_index(ref_names)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert len(index) == 50000
    print(f"tracemalloc peak {peak} bytes ({peak / 1048576:.1f} MiB)")
    assert peak <= MEMORY_BOUND_BYTES, f"peak {peak} > {MEMORY_BOUND_BYTES}"


@pytest.mark.serial_timing
def test_r_a2l_match_40_1_pathological_queries_over_ref(ref_index):
    """R-A2L-MATCH.40/1: the six PSET shapes over REF, limit 20, median of 7 <= 1.0 s."""
    print(_load("before"))
    medians = []
    for label, query in pset_ref():
        assert len(query) <= 256, label
        medians.append((f"R-A2L-MATCH.40 REF {label}", _median_of(7, lambda q=query: rank(q, ref_index, 20))))
    print(_load("after"))
    _check_all(medians, ANY_QUERY_BOUND_S)


@pytest.mark.serial_timing
def test_r_a2l_match_40_1_pathological_queries_over_ref6(ref6_index, swa):
    """R-A2L-MATCH.40/1: the PSET shapes over REF6 (repeated, near tokens, 256-character, E3S-01), median of 7 <= 1.0 s."""
    print(_load("before"))
    medians = []
    for label, query in pset_ref6(swa):
        assert len(query) <= 256, label
        medians.append((f"R-A2L-MATCH.40 REF6 {label}", _median_of(7, lambda q=query: rank(q, ref6_index, 20))))
    print(_load("after"))
    _check_all(medians, ANY_QUERY_BOUND_S)


@pytest.mark.serial_timing
def test_r_a2l_match_40_2_long_queries_against_1020_character_tokens(long_index):
    """R-A2L-MATCH.40/2: the three LONG queries over LONG (names of one 1,020-character token), median of 7 <= 1.0 s."""
    print(_load("before"))
    medians = []
    for label, query in LONG_QUERIES:
        medians.append((f"R-A2L-MATCH.40 LONG {label}", _median_of(7, lambda q=query: rank(q, long_index, 20))))
    print(_load("after"))
    _check_all(medians, ANY_QUERY_BOUND_S)


# ---------------------------------------------------------------------------
# R-A2L-MATCH.40/3 and .40/4 (E5 corrective pass)
# ---------------------------------------------------------------------------

CRAFT_NCAP = 1024
CRAFT_HEAD = "987654"  # starts no REF token (0 allowed edits: walked first, it yields only the crafted names)
# 50 three-letter hits (Random(7) over 'a'..'z' minus 'q', kept when hit + 'q' has an empty token range in REF),
# fixed here as literals found once on the reference host with the E5 probe's builder.
CRAFT_HITS = (
    "kem vbc sdl tbr gbc nnc nbt dhv vtb sej nes dtj swf dtt vgl dsx ctb ugp zko tol jhf xzh ctj rpk ucd "
    "rnf zke pnb wcz stk kxl upt occ ipx wcb yxj vtw ojx aol fud pbg zje yhm mpc fom sie nsi xnl wmh ecf"
).split()
CRAFT_SEED = 20261413
CRAFT_TOTAL_CHARS = 2356624  # R-A2L-MATCH.40 row: CRAFT holds this many characters in all
CRAFT_SHA256 = "70a89ba19130fbc699f374ef59419d272ad501776a9f1bdd26be7f4d0a6632db"


def _base25(value, width, alphabet):
    out = []
    for _ in range(width):
        value, rem = divmod(value, len(alphabet))
        out.append(alphabet[rem])
    return "".join(out)


def craft_names(n_crafted=300):
    """300 names of 1,024 characters: ``CRAFT_HEAD``, the 50 hits capitalised (same order in every name), then 217
    four-letter capitalised junk tokens distinct across the names (268 tokens each)."""
    assert len(CRAFT_HITS) == 50
    letters = [c for c in _LOWER if c != "q"]
    k_junk = (CRAFT_NCAP - len(CRAFT_HEAD) - 3 * len(CRAFT_HITS)) // 4
    pool = random.Random(CRAFT_SEED).sample(range(len(letters) ** 4), n_crafted * k_junk)
    names = []
    for i in range(n_crafted):
        junk = "".join(_base25(v, 4, letters).capitalize() for v in pool[i * k_junk:(i + 1) * k_junk])
        names.append(CRAFT_HEAD + "".join(h.capitalize() for h in CRAFT_HITS) + junk)
    assert len(set(names)) == n_crafted and {len(n) for n in names} == {CRAFT_NCAP}
    return names


def craft_query(n_tokens):
    """The head, then n_tokens - 1 tokens, each a hit followed by ``q`` (1 edit from the hit, starting no token)."""
    return " ".join([CRAFT_HEAD] + [h + "q" for h in CRAFT_HITS[: n_tokens - 1]])


@pytest.fixture(scope="module")
def craft_index(ref_names):
    names = craft_names() + ref_names[:49700]
    assert len(names) == 50000
    assert sum(len(n) for n in names) == CRAFT_TOTAL_CHARS  # fixture sanity: the row's list
    assert hashlib.sha256("\n".join(names).encode("utf-8")).hexdigest() == CRAFT_SHA256
    return build_label_index(names)


@pytest.mark.serial_timing
def test_r_a2l_match_40_3_crafted_stress_list(craft_index):
    """R-A2L-MATCH.40/3: the 4-token and the 51-token CRAFT queries (300 names of 1,024 characters, 268 tokens
    each, every query token matching within its allowed edits) over the prepared list CRAFT, limit 20, median of 7
    <= 1.0 s; the list holds 20 entries, each fuzzy (the 51-token list: 50 edits each)."""
    print(_load("before"))
    medians = []
    for n_tokens in (4, 51):
        query = craft_query(n_tokens)
        assert len(query) <= 256 and len(query.split()) == n_tokens
        got = rank(query, craft_index, 20)
        assert len(got) == 20
        assert {m.rule.value for m in got} == {"fuzzy"}
        assert {m.edits for m in got} == {n_tokens - 1}  # one edit per hit-and-q token, none for the head
        medians.append((f"R-A2L-MATCH.40/3 CRAFT {n_tokens} tokens", _median_of(7, lambda q=query: rank(q, craft_index, 20))))
    print(_load("after"))
    _check_all(medians, ANY_QUERY_BOUND_S)


BAND_HEAD = "987654"
BAND_LETTERS = "cdefghijklmnopr"  # 15 letters, no 'b': the query's last letter appears in no name, so no subsequence tier fires


def band_names():
    """225 names ``987654_`` + 1,000 ``a`` + two letters of BAND_LETTERS: one 1,002-character token each (within .39)."""
    return [f"{BAND_HEAD}_{'a' * 1000}{x}{y}" for x in BAND_LETTERS for y in BAND_LETTERS]


@pytest.fixture(scope="module")
def band_index(ref_names):
    names = band_names() + ref_names[:50000 - len(band_names())]
    assert len(names) == 50000 and len(set(names)) == 50000
    return build_label_index(names)


@pytest.mark.serial_timing
def test_r_a2l_match_40_4_prefix_distance_band_after_the_switch(band_index):
    """R-A2L-MATCH.40/4: a two-token query whose first token (``987654``, 0 edits) leaves 225 candidates holding
    450 token occurrences (<= 512: the posting switch) and whose second token (248 ``a`` and a ``b``) is then
    scored against each 1,002-character candidate token by ``_prefix_distance``; ranked 7 times, limit 20,
    median <= 1.0 s. Without the band the 225 alignments cost about 249 x 250 cells each (seconds)."""
    query = BAND_HEAD + " " + "a" * 248 + "b"
    assert len(query) == 256
    got = rank(query, band_index, 20)
    expected = set(band_names())
    assert len(got) == 20
    assert {m.name in expected for m in got} == {True}
    assert {m.rule.value for m in got} == {"fuzzy"}
    assert {m.edits for m in got} == {1}  # the final 'b' replaces one 'a' of the name's token
    print(_load("before"))
    medians = [("R-A2L-MATCH.40/4 BAND head + 249-character token", _median_of(7, lambda: rank(query, band_index, 20)))]
    print(_load("after"))
    _check_all(medians, ANY_QUERY_BOUND_S)
