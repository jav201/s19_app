"""Inc 4 (batch-103) - label similarity matcher: time and memory bounds (G-T2).

Independent tester file (E4). Cases (``02-test-cases.md``):

- R-A2L-MATCH.35/1 - preparing 50,000 names: median of 3 <= 5.0 s.
- R-A2L-MATCH.36/1 - ranking per keystroke: for every query of QSET over REF and
  of the REF6 query set, limit 20, the median of 7 consecutive rankings <= 200 ms.
- R-A2L-MATCH.37/1, /2 - the tracemalloc peak of preparing REF, and B4MAX (500,000 distinct ASCII tokens),
  <= 64 MiB each.
- R-A2L-MATCH.40/1 - every pathological PSET query over its list: median of 7 <= 2.0 s.
- R-A2L-MATCH.40/2 - the three LONG queries over LONG: median of 7 <= 2.0 s.
- R-A2L-MATCH.40/3 - the 4-, 20- and 51-token CRAFT queries over CRAFT (E5S-01; the 51-token one is past the cap).
- R-A2L-MATCH.40/4 - a query that still reaches ``_prefix_distance`` after the posting
  switch (BAND list): the banded distance keeps it fast, the no-band mutant does not.
- R-A2L-MATCH.40/5 - FAMQ(20) and FAMQ(76) over U6, and (E5 round 2, the adversarial lists the row now names)
  the same family over D3, FAM6 over E2, one-token walks over W40 and the substring key over SUBO.
- R-A2L-MATCH.42/1 .. /5 (E5 round 3, E5S-10) - the node budget (400,000 trie node visits per ranking): W40 with 2 and 6
  query tokens, DEEP40 with 1 and 6, W12 with the 20-token T20; each median of 7 <= 2.0 s AND the exact budget-truncated
  list (sha256 of repr of the (name, rule, edits, spans) list). Negative control: with the budget removed (a /tmp mutant
  on the runner, never committed) /2 takes 5.5 s and /1 lists 3-edit fuzzy entries.
- The R-A2L-MATCH.40 bound is 2.0 s (E3-rulings, E5 round-2 design rulings); R-A2L-MATCH.36 stays 200 ms.

The timing arms carry ``serial_timing`` (run apart and serially); the memory
bound R-A2L-MATCH.37/1 is a byte bound and carries none. The bounds are stated
for the reference host (linux-runner, Python 3.11.18); every upper bound goes
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
ANY_QUERY_BOUND_S = 2.0  # R-A2L-MATCH.40 (E5 round-2 ruling: 2.0 s, was 1.0 s)
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


def _b26(value, width):
    out = []
    for _ in range(width):
        value, rem = divmod(value, 26)
        out.append(_LOWER[rem])
    return "".join(out)


B4MAX_SHA256 = "afe7fad05aa652d882d30278315fb5832249cd42a9826c28e5798ea8fd36dfd0"


def b4max_names():
    """B4MAX: all 456,976 4-letter strings and the first 43,024 5-letter ones (base 26, least significant letter
    first), shuffled by ``Random(20261109)``; name i is tokens 10i .. 10i+9, capitalised, joined with no separator."""
    toks = [_b26(i, 4) for i in range(26 ** 4)] + [_b26(i, 5) for i in range(500000 - 26 ** 4)]
    random.Random(20261109).shuffle(toks)
    names = ["".join(t.capitalize() for t in toks[i * 10:(i + 1) * 10]) for i in range(50000)]
    assert sum(len(n) for n in names) == 2043024 and len(set(names)) == 50000  # fixture sanity
    assert hashlib.sha256("\n".join(names).encode("utf-8")).hexdigest() == B4MAX_SHA256
    assert all(n.isascii() for n in names)
    return names


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
        assert median <= report_margin(label_, median, timing_bound(bound_s)), f"{label_}: median {median:.4f} s"


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


def test_r_a2l_match_37_2_densest_ascii_list_stays_within_64_mib():
    """R-A2L-MATCH.37/2: the tracemalloc peak while preparing B4MAX (50,000 ASCII names of 10 camel tokens,
    500,000 distinct tokens, 2,043,024 characters) is <= 67,108,864 bytes; the memory follows the distinct tokens."""
    names = b4max_names()  # built before tracemalloc starts
    gc.collect()
    tracemalloc.start()
    try:
        index = build_label_index(names)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert len(index) == 50000
    print(f"B4MAX tracemalloc peak {peak} bytes ({peak / 1048576:.1f} MiB)")
    assert peak <= MEMORY_BOUND_BYTES, f"peak {peak} > {MEMORY_BOUND_BYTES}"


@pytest.mark.serial_timing
def test_r_a2l_match_40_1_pathological_queries_over_ref(ref_index):
    """R-A2L-MATCH.40/1: the six PSET shapes over REF, limit 20, median of 7 <= 2.0 s."""
    print(_load("before"))
    medians = []
    for label, query in pset_ref():
        assert len(query) <= 256, label
        medians.append((f"R-A2L-MATCH.40 REF {label}", _median_of(7, lambda q=query: rank(q, ref_index, 20))))
    print(_load("after"))
    _check_all(medians, ANY_QUERY_BOUND_S)


@pytest.mark.serial_timing
def test_r_a2l_match_40_1_pathological_queries_over_ref6(ref6_index, swa):
    """R-A2L-MATCH.40/1: the PSET shapes over REF6 (repeated, near tokens, 256-character, E3S-01), median of 7 <= 2.0 s."""
    print(_load("before"))
    medians = []
    for label, query in pset_ref6(swa):
        assert len(query) <= 256, label
        medians.append((f"R-A2L-MATCH.40 REF6 {label}", _median_of(7, lambda q=query: rank(q, ref6_index, 20))))
    print(_load("after"))
    _check_all(medians, ANY_QUERY_BOUND_S)


@pytest.mark.serial_timing
def test_r_a2l_match_40_2_long_queries_against_1020_character_tokens(long_index):
    """R-A2L-MATCH.40/2: the three LONG queries over LONG (names of one 1,020-character token), median of 7 <= 2.0 s."""
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
    """R-A2L-MATCH.40/3: the 4-, 20- and 51-token CRAFT queries (300 names of 1,024 characters, 268 tokens each,
    every query token matching within its allowed edits) over the prepared list CRAFT, limit 20, median of 7
    <= 2.0 s. Up to 20 distinct tokens: 20 entries, each fuzzy with n - 1 edits (one per hit-and-q token, none for
    the head). The 51-token query is past the R-A2L-MATCH.41 cap: no fuzzy entry, so the list is empty (before the
    cap it held 20 entries of 50 edits; the cap is the E5 round-2 change)."""
    print(_load("before"))
    medians = []
    for n_tokens in (4, 20, 51):
        query = craft_query(n_tokens)
        assert len(query) <= 256 and len(query.split()) == n_tokens
        got = rank(query, craft_index, 20)
        if n_tokens <= 20:
            assert len(got) == 20
            assert {m.rule.value for m in got} == {"fuzzy"}
            assert {m.edits for m in got} == {n_tokens - 1}
        else:
            assert got == []
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
    median <= 2.0 s. Without the band the 225 alignments cost about 249 x 250 cells each (seconds)."""
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


# ---------------------------------------------------------------------------
# R-A2L-MATCH.40/5 and the adversarial lists named by the E5 round-2 rulings (U6, D3, E2, W40, SUBO)
# ---------------------------------------------------------------------------

LET25 = [c for c in _LOWER if c != "q"]
U6_SHA256 = "3540f73d2c12242674453036becd9db53f3536c42b7e7ac03625c4b4c3811532"
FAM3 = ["ab" + c for c in _LOWER] + ["a" + c + "b" for c in _LOWER if c != "b"] + [c + "ab" for c in _LOWER if c != "a"]
FAMQ = ["abq"] + [t for t in FAM3 if t != "abq"]  # 76 distinct 3-letter tokens; 'abq' starts no U6 token
FAM6 = ["abcd" + x + y for x in "efghijklmnopr" for y in "stuvwxyz"]  # 6 letters: 2 allowed edits
assert len(FAMQ) == 76 and len(set(FAMQ)) == 76
CHARS_BOUND = 2356624  # R-A2L-MATCH.40: the row's scope


def fam_query(fam, n):
    """The first token as is, then the next n - 1 tokens capitalised, joined with no separator (n distinct tokens)."""
    return fam[0] + "".join(t.capitalize() for t in fam[1:n])


def _check_scope(names):
    assert len(names) == len(set(names)) == 50000 and sum(len(n) for n in names) <= CHARS_BOUND


def u6_names():
    """U6: name i is the six tokens ``ab`` + the 4-letter base-25 numeral of 6i + t (t = 0 .. 5), joined by ``_``."""
    names = []
    for i in range(50000):
        names.append("_".join("ab" + _base25(6 * i + t, 4, LET25) for t in range(6)))
    _check_scope(names)
    assert sum(len(n) for n in names) == 2050000
    assert hashlib.sha256("\n".join(names).encode("utf-8")).hexdigest() == U6_SHA256
    return names


def d3_names():
    """D3: 27,000 names of the 25 camel tokens ``Ab`` + c and a decimal tag, padded with ``s`` + 5-digit names."""
    body = "".join("Ab" + c for c in LET25)
    names = [body + str(i) for i in range(27000)] + [f"s{i:05d}" for i in range(23000)]
    _check_scope(names)
    return names


def e2_names():
    """E2: 50,000 names ``abcd`` + a 4-letter base-25 numeral (2-edit queries)."""
    names = [f"abcd{_base25(i, 4, LET25)}" for i in range(50000)]
    _check_scope(names)
    return names


def w40_names():
    """W40: 50,016 distinct 40-letter tokens within 2 substitutions of ``'a' * 40`` (24 per name, ``_`` joined),
    padded with ``s`` + 5-digit names: the one-token query ``'a' * 40`` walks the whole trie."""
    al = "bcdefghijklmnoprstuvwxyz"
    rng = random.Random(20261111)
    toks = set()
    while len(toks) < 50016:
        i, j = sorted(rng.sample(range(40), 2))
        toks.add("a" * i + rng.choice(al) + "a" * (j - i - 1) + rng.choice(al) + "a" * (39 - j))
    toks = sorted(toks)
    rng.shuffle(toks)
    names = ["_".join(toks[k:k + 24]) for k in range(0, len(toks), 24)]
    names += [f"s{i:05d}" for i in range(50000 - len(names))]
    _check_scope(names)
    return names


def subo_names():
    """SUBO: 2,000 names ``x`` + 1,017 ``a`` + ``Q`` + a 4-letter tag (overlapping substring occurrences of ``aa``),
    padded with ``s`` + 5-digit names."""
    names = ["x" + "a" * 1017 + "Q" + _base25(i, 4, "cdefghijklmnop") for i in range(2000)]
    names += [f"s{i:05d}" for i in range(48000)]
    _check_scope(names)
    return names


@pytest.fixture(scope="module")
def u6_index():
    return build_label_index(u6_names())


@pytest.fixture(scope="module")
def d3_index():
    return build_label_index(d3_names())


@pytest.fixture(scope="module")
def e2_index():
    return build_label_index(e2_names())


@pytest.fixture(scope="module")
def w40_index():
    return build_label_index(w40_names())


@pytest.fixture(scope="module")
def subo_index():
    return build_label_index(subo_names())


@pytest.mark.serial_timing
def test_r_a2l_match_40_5_famq_over_u6_dense_list(u6_index):
    """R-A2L-MATCH.40/5: FAMQ(20) (60 characters) and FAMQ(76) (228 characters) over U6 (300,000 postings every FAMQ
    token reaches within 1 edit), limit 20, median of 7 <= 2.0 s. FAMQ(20): 20 fuzzy entries of 14 edits each;
    FAMQ(76): [] (more than 20 distinct query tokens, R-A2L-MATCH.41)."""
    print(_load("before"))
    medians = []
    for n_tokens in (20, 76):
        query = fam_query(FAMQ, n_tokens)
        assert len(query) == 3 * n_tokens
        got = rank(query, u6_index, 20)
        if n_tokens == 20:
            assert len(got) == 20
            assert {m.rule.value for m in got} == {"fuzzy"}
            assert {m.edits for m in got} == {14}
        else:
            assert got == []
        medians.append((f"R-A2L-MATCH.40/5 U6 FAMQ({n_tokens})", _median_of(7, lambda q=query: rank(q, u6_index, 20))))
    print(_load("after"))
    _check_all(medians, ANY_QUERY_BOUND_S)


@pytest.mark.serial_timing
def test_r_a2l_match_40_famq_over_d3_densest_postings_list(d3_index):
    """R-A2L-MATCH.40 (adversarial list D3, E5 round-2 design pass): FAMQ(n) over the densest postings shape found for
    one 1-edit 3-letter query token, n = 4, 12, 20, 76, limit 20, median of 7 <= 2.0 s; past 20 distinct tokens no
    fuzzy entry is listed."""
    print(_load("before"))
    medians = []
    for n_tokens in (4, 12, 20, 76):
        query = fam_query(FAMQ, n_tokens)
        got = rank(query, d3_index, 20)
        assert len(got) <= 20
        if n_tokens > 20:
            assert "fuzzy" not in {m.rule.value for m in got}
        medians.append((f"R-A2L-MATCH.40 D3 FAMQ({n_tokens})", _median_of(7, lambda q=query: rank(q, d3_index, 20))))
    print(_load("after"))
    _check_all(medians, ANY_QUERY_BOUND_S)


@pytest.mark.serial_timing
def test_r_a2l_match_40_fam6_over_e2_two_edit_list(e2_index):
    """R-A2L-MATCH.40 (adversarial list E2, E5 round-2 design pass): FAM6(n) (6-letter tokens, 2 allowed edits) over
    E2, n = 4, 12, 24, 36, limit 20, median of 7 <= 2.0 s; past 20 distinct tokens no fuzzy entry is listed."""
    print(_load("before"))
    medians = []
    for n_tokens in (4, 12, 24, 36):
        query = fam_query(FAM6, n_tokens)
        assert len(query) <= 256
        got = rank(query, e2_index, 20)
        assert len(got) <= 20
        if n_tokens > 20:
            assert "fuzzy" not in {m.rule.value for m in got}
        medians.append((f"R-A2L-MATCH.40 E2 FAM6({n_tokens})", _median_of(7, lambda q=query: rank(q, e2_index, 20))))
    print(_load("after"))
    _check_all(medians, ANY_QUERY_BOUND_S)


@pytest.mark.serial_timing
def test_r_a2l_match_40_one_token_walk_over_w40(w40_index):
    """R-A2L-MATCH.40 (adversarial list W40, E5 round-2 ruling): the one-token queries ``'a' * 40`` and ``'a' * 64``
    over 50,016 40-letter tokens within 2 substitutions (753,276 trie nodes), limit 20, median of 7 <= 2.0 s."""
    print(_load("before"))
    medians = []
    for query in ("a" * 40, "a" * 64):
        got = rank(query, w40_index, 20)
        assert len(got) == 20
        medians.append((f"R-A2L-MATCH.40 W40 {len(query)} a", _median_of(7, lambda q=query: rank(q, w40_index, 20))))
    print(_load("after"))
    _check_all(medians, ANY_QUERY_BOUND_S)


@pytest.mark.serial_timing
def test_r_a2l_match_40_substring_key_over_subo(subo_index):
    """R-A2L-MATCH.40 (adversarial list SUBO, E5 round-2 ruling): the queries ``aa``, ``aaa`` and ``aaaaaaaa`` over
    2,000 names holding 1,016 overlapping occurrences each, limit 20, median of 7 <= 2.0 s; 20 substring entries."""
    print(_load("before"))
    medians = []
    for query in ("aa", "aaa", "aaaaaaaa"):
        got = rank(query, subo_index, 20)
        assert len(got) == 20
        assert {m.rule.value for m in got} == {"substring"}
        medians.append((f"R-A2L-MATCH.40 SUBO {query!r}", _median_of(7, lambda q=query: rank(q, subo_index, 20))))
    print(_load("after"))
    _check_all(medians, ANY_QUERY_BOUND_S)


# ---------------------------------------------------------------------------
# R-A2L-MATCH.42 - the per-ranking node budget (E5 round 3, E5S-10): lists W40 (above), DEEP40, W12
# ---------------------------------------------------------------------------

SUB25 = "bcdefghijklmnopqrstuvwxyz"  # 25 substitution letters (no 'a')
W40_SHA256 = "467be34c6c101183e60c6ed948e95d4b49bec250a5bbfd676e7baf328083d95b"
DEEP40_SHA256 = "2ce84fa31c55c2d7a457ebe01cfe0746acefb786b9253f221b219362107db0cc"
W12_SHA256 = "ec97932cba99e45011580d70b86cbc140113b9aac8dd715faf948dd71bb79d37"


def _pad(names):
    names = list(names)
    names += [f"s{i:05d}" for i in range(50000 - len(names))]
    assert len(names) == len(set(names)) == 50000
    return names


def _two_sub_tokens(length, first):
    """Every ``'a' * length`` with exactly two substitutions from SUB25 at positions i < j < first."""
    out = []
    for i in range(first):
        for j in range(i + 1, first):
            for c1 in SUB25:
                for c2 in SUB25:
                    t = ["a"] * length
                    t[i], t[j] = c1, c2
                    out.append("".join(t))
    return out


def _pack(tokens, per, seed, head=None):
    toks = list(tokens)
    random.Random(seed).shuffle(toks)
    return ["_".join(([head] if head else []) + toks[k:k + per]) for k in range(0, len(toks), per)]


def deep40_names():
    """DEEP40: all 41,250 40-letter tokens with exactly 2 substitutions in their first 12 letters, 24 per name, padded."""
    names = _pad(_pack(_two_sub_tokens(40, 12), 24, 20261201))
    _check_scope(names)
    return names


def w12_names():
    """W12: every 12-letter string with at most 2 substitutions from ``'a' * 12`` except ``'a' * 12`` itself, 23 per name,
    each name led by ``'a' * 12`` (so every W12 name is within 1 edit of every T20 token), padded."""
    toks = set()
    for i in range(12):
        for c1 in SUB25:
            t = ["a"] * 12
            t[i] = c1
            toks.add("".join(t))
    toks.update(_two_sub_tokens(12, 12))
    names = _pad(_pack(sorted(toks), 23, 20261203, head="a" * 12))
    _check_scope(names)
    return names


def _sha_names(names):
    return hashlib.sha256("\n".join(names).encode("utf-8")).hexdigest()


def _sha_list(got):
    """sha256 of ``repr`` of the list projected onto (name, rule word, edits, spans), as the records pin it."""
    return hashlib.sha256(repr([(m.name, m.rule.value, m.edits, m.spans) for m in got]).encode("utf-8")).hexdigest()


def t20_query():
    """T20: 20 distinct 11-letter tokens ``'a' * 10 + c`` (2 allowed edits each), space-joined (239 characters)."""
    return " ".join("a" * 10 + c for c in SUB25[:20])


def runs_query(lengths):
    return " ".join("a" * k for k in lengths)


@pytest.fixture(scope="module")
def deep40_index():
    names = deep40_names()
    assert _sha_names(names) == DEEP40_SHA256  # fixture sanity
    return build_label_index(names)


@pytest.fixture(scope="module")
def w12_index():
    names = w12_names()
    assert _sha_names(names) == W12_SHA256  # fixture sanity
    return build_label_index(names)


@pytest.fixture(scope="module")
def w40_pinned_index():
    names = w40_names()
    assert _sha_names(names) == W40_SHA256  # fixture sanity
    return build_label_index(names)


def _check_budgeted(case_id, index, query, expected_rule, expected_edits, expected_sha):
    """Exact budget-truncated list first (20 entries, one rule, pinned sha256), then the median of 7 <= 2.0 s."""
    got = rank(query, index, 20)
    assert len(got) == 20, case_id
    assert {m.rule.value for m in got} == {expected_rule}, case_id
    assert {m.edits for m in got} == {expected_edits}, case_id
    assert _sha_list(got) == expected_sha, case_id
    print(_load("before"))
    medians = [(case_id, _median_of(7, lambda: rank(query, index, 20)))]
    print(_load("after"))
    _check_all(medians, ANY_QUERY_BOUND_S)
    return got


@pytest.mark.serial_timing
def test_r_a2l_match_42_1_two_token_query_over_w40_lists_subsequence_entries(w40_pinned_index):
    """R-A2L-MATCH.42/1: ``'a' * 40`` + space + ``'a' * 39`` over W40: the budget runs out in the first walk, the second query
    token finds no name token, so the fuzzy rule lists nothing and 20 ``subsequence`` entries remain; median of 7 <= 2.0 s."""
    query = runs_query((40, 39))
    assert len(query) == 80
    got = _check_budgeted("R-A2L-MATCH.42/1 W40 2 tokens", w40_pinned_index, query, "subsequence", 0,
                          "29cb2305cae359f658d4f9d00644608ed26c83214fc09889ba8efd4076cb32cd")
    assert got[0].name.startswith("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaci_ama") and len(got[0].name) == 983


@pytest.mark.serial_timing
def test_r_a2l_match_42_2_six_token_query_over_w40_the_budget_control(w40_pinned_index):
    """R-A2L-MATCH.42/2: ``'a' * 40`` .. ``'a' * 35`` (230 characters, 6 distinct tokens) over W40: 20 ``subsequence`` entries,
    median of 7 <= 2.0 s. The budget's negative control: with no budget the ranking takes 5.5 s and lists 3-edit ``fuzzy``."""
    query = runs_query(range(40, 34, -1))
    assert len(query) == 230
    got = _check_budgeted("R-A2L-MATCH.42/2 W40 6 tokens", w40_pinned_index, query, "subsequence", 0,
                          "4243a09dd1d9577dd3ceb5e710c17716a066f9bd4f8423c86684689bb8a1b3e7")
    assert got[0].name.startswith("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaci_ama") and len(got[0].name) == 983


@pytest.mark.serial_timing
def test_r_a2l_match_42_3_one_token_walk_cut_by_the_budget_still_lists_what_it_found(deep40_index):
    """R-A2L-MATCH.42/3: ``'a' * 40`` over DEEP40: the one walk stops after 400,000 visits, yet 20 ``fuzzy`` entries of 2 edits
    are listed (the same 20 names as with no budget); entry 1 has the span (123, 163), its leftmost token found; median of 7 <= 2.0 s."""
    got = _check_budgeted("R-A2L-MATCH.42/3 DEEP40 1 token", deep40_index, "a" * 40, "fuzzy", 2,
                          "094071ae7a78cfda29d688955b846ef9984090df8b7133a136a3efe5579e350c")
    assert got[0].name.startswith("agaaaaaazaaaaaaaaaaaaaaaaaaaaa") and len(got[0].name) == 737
    assert got[0].spans == ((123, 163),)


@pytest.mark.serial_timing
def test_r_a2l_match_42_4_six_token_query_over_deep40(deep40_index):
    """R-A2L-MATCH.42/4: ``'a' * 40`` .. ``'a' * 35`` (230 characters) over DEEP40: 20 ``subsequence`` entries (entry 1 the name of
    /3), median of 7 <= 2.0 s; with no budget 20 ``fuzzy`` entries of 12 edits in 11.6 s."""
    got = _check_budgeted("R-A2L-MATCH.42/4 DEEP40 6 tokens", deep40_index, runs_query(range(40, 34, -1)), "subsequence", 0,
                          "c032a4c1c1816604f9fe0f37368a6fe3d96f2100e0a3da96667b36f787529ef2")
    assert got[0].name.startswith("agaaaaaazaaaaaaaaaaaaaaaaaaaaa") and len(got[0].name) == 737


@pytest.mark.serial_timing
def test_r_a2l_match_42_5_twenty_distinct_tokens_over_w12_list_nothing(w12_index):
    """R-A2L-MATCH.42/5: T20 (20 distinct tokens, 239 characters) over W12: [] (the budget runs out before the last walk; no
    W12 name holds T20's key characters in order); median of 7 <= 2.0 s; with no budget 20 ``fuzzy`` entries in 4.7 s."""
    query = t20_query()
    assert len(query) == 239
    assert rank(query, w12_index, 20) == []
    print(_load("before"))
    medians = [("R-A2L-MATCH.42/5 W12 T20", _median_of(7, lambda: rank(query, w12_index, 20)))]
    print(_load("after"))
    _check_all(medians, ANY_QUERY_BOUND_S)
