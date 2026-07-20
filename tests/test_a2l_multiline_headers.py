"""Multi-line A2L CHARACTERISTIC header + AXIS_DESCR body assembly — batch-54.

Requirements ``R-A2L-011`` (char multi-line + no-regression), ``R-A2L-012``
(axis MaxAxisPoints + external flag), ``R-A2L-013`` (comment-strip safety).

The real ASAM demo (``examples/case_00_public/ASAP2_Demo_V161.a2l``) spreads a
CHARACTERISTIC's 7 mandatory params (``Type Address Deposit MaxDiff Conversion
LowerLimit UpperLimit``) across several body lines with inline ``/* … */``
comments. Before this batch the single-line ``parse_characteristic_header`` only
matched a lucky comment-token line, so 0 of the 50 demo CHARACTERISTICs parsed
genuinely (the "1" was a ``ASCII /* … */`` comment artifact). This module pins
the assembled behaviour end-to-end through the shipped ``parse_a2l_file`` surface
(AT-*) plus the new private helpers (TC-*).

NON-frozen sibling on purpose: ``tests/test_tui_a2l.py`` is TC-032 / C-27 frozen,
so the batch's new tests must not land there.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from s19_app.tui.a2l import (
    _characteristic_from_tokens,
    _flatten_body_tokens,
    _split_line_respecting_quotes,
    _strip_a2l_comments,
    assemble_characteristic_header,
    parse_a2l_file,
)

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEMO_A2L = _REPO_ROOT / "examples" / "case_00_public" / "ASAP2_Demo_V161.a2l"
_CASE01_A2L = _REPO_ROOT / "examples" / "case_01_basic_valid" / "firmware.a2l"

_MIN_A2L = (
    '/begin PROJECT P "synthetic"\n'
    '  /begin MODULE M "synthetic"\n'
    "    /begin CHARACTERISTIC C1\n"
    "{body}\n"
    "    /end CHARACTERISTIC\n"
    "  /end MODULE\n"
    "/end PROJECT\n"
)


def _chars(a2l_path: Path) -> list[dict]:
    tags = parse_a2l_file(a2l_path)["tags"]
    return [t for t in tags if t.get("section") == "CHARACTERISTIC"]


def _parse_single_char(tmp_path: Path, body: str, name: str = "case.a2l") -> dict | None:
    """Write a minimal one-CHARACTERISTIC A2L with ``body`` and return that tag."""
    path = tmp_path / name
    path.write_text(_MIN_A2L.format(body=body), encoding="utf-8")
    chars = _chars(path)
    return chars[0] if chars else None


# ---------------------------------------------------------------------------
# AT-096 — golden dual-fact: named STD_AXIS/COM_AXIS + index-2 anchor.
# ---------------------------------------------------------------------------


def test_at096_std_com_golden_header_values() -> None:
    """STD_AXIS/COM_AXIS mandatory params + the bare-``ASCII`` index-2 anchor.

    Intent: the STD_AXIS CURVE spreads Type/Address/Deposit over three body lines
    with a trailing ``/* memory needed … */`` comment on the address line; the
    assembler must recover ``CURVE`` / ``0x810300`` / ``RL.CURVE.SWORD.SBYTE.DECR``
    exactly. The ``ASAM.C.ASCII.UBYTE.NUMBER_42`` block carries its name in the
    body (so the kind anchor lands at token index 2 on a bare ``ASCII``), proving
    the anchor is positional not fixed-at-0 (arch-M1). Pre-fix every value is
    ``None``.
    """
    chars = _chars(_DEMO_A2L)

    std = next(t for t in chars if t["name"] == "ASAM.C.CURVE.STD_AXIS")
    assert std["char_type"] == "CURVE"
    assert std["address"] == 0x810300
    assert std["deposit"] == "RL.CURVE.SWORD.SBYTE.DECR"

    com = next(t for t in chars if t["name"] == "ASAM.C.CURVE.COM_AXIS")
    assert com["deposit"] == "RL.FNC.SWORD.ROW_DIR"

    # Name-in-body block → anchor at index 2 on a bare ``ASCII`` token.
    number_42 = next(t for t in chars if t["address"] == 0x810200)
    assert number_42["char_type"] == "ASCII"


# ---------------------------------------------------------------------------
# AT-097 — the derived universal: all 50 demo CHARACTERISTICs now parse.
# ---------------------------------------------------------------------------


def test_at097_all_fifty_characteristics_have_type_and_address() -> None:
    """50/50 demo CHARACTERISTICs get a ``char_type`` and a non-None address.

    Intent: the demo has exactly 50 ``/begin CHARACTERISTIC`` blocks. Pre-fix,
    ~0 parsed genuinely. The address check uses ``is not None`` (never
    ``all(t.get("address"))``) because 5/50 chars legitimately sit at address 0
    (e.g. ``ASAM.C.VIRTUAL.ASCII`` @0x0) — a truthiness test would wrongly fail
    on those valid zero addresses (arch-M3).
    """
    chars = _chars(_DEMO_A2L)
    assert len(chars) == 50
    assert all(t.get("char_type") for t in chars)
    assert all(t.get("address") is not None for t in chars)
    # Guard the arch-M3 rationale: some addresses really are 0.
    assert sum(1 for t in chars if t["address"] == 0) == 5


# ---------------------------------------------------------------------------
# AT-098 — no regression on the single-line CHARACTERISTIC path.
# ---------------------------------------------------------------------------


def test_at098_single_line_characteristics_unchanged() -> None:
    """``case_01`` single-line headers parse identically (superset invariant).

    Intent: the multi-line assembler flattens a one-line body to that line's own
    tokens, so the single-line path is a strict subset. This pins the exact
    shipped values (char_type/address/length/limits) that must not move.
    """
    tags = parse_a2l_file(_CASE01_A2L)["tags"]
    assert len(tags) == 3
    chars = [t for t in tags if t.get("section") == "CHARACTERISTIC"]
    assert len(chars) == 2

    by_name = {t["name"]: t for t in chars}
    a = by_name["CAL_BLOCK_A"]
    b = by_name["CAL_BLOCK_B"]
    assert a["char_type"] == "VALUE" and b["char_type"] == "VALUE"
    assert a["address"] == 0x80000010
    assert b["address"] == 0x80000040
    for t in (a, b):
        assert t["length"] == 1
        assert t["lower_limit"] == "0"
        assert t["upper_limit"] == "255"


# ---------------------------------------------------------------------------
# AT-099 — MEASUREMENT + synthetic no-kind regression sentinels (gate-blocking).
# ---------------------------------------------------------------------------


def test_at099_measurement_and_synthetic_no_kind_preserved(tmp_path: Path) -> None:
    """MEASUREMENT parsing intact; synthetic no-kind chars stay ``char_type=None``.

    Intent: MEASUREMENT keeps the single-line ``_first_header_line`` path — 25/25
    datatype + >=24 length must be untouched. The ``make_large_a2l`` synthetic
    CHARACTERISTIC blocks have no mandatory-kind token (body is ECU_ADDRESS /
    LENGTH / …), so they must stay ``char_type=None`` — the snapshot sentinel
    that proves no drift on the synthetic-fixtured snapshot suite. The count is
    pinned (``== 8``) so the ``all(... is None)`` universal can't pass vacuously
    on an empty set (qa-M2 / C-31).
    """
    from tests.conftest import make_large_a2l

    meas = [t for t in parse_a2l_file(_DEMO_A2L)["tags"] if t.get("section") == "MEASUREMENT"]
    assert len(meas) == 25
    assert all(t.get("datatype") for t in meas)
    assert sum(1 for t in meas if t.get("length") is not None) >= 24

    synth_path = make_large_a2l(
        tmp_path / "synth_at099.a2l",
        num_measurements=0,
        num_characteristics=8,
    )
    synth_chars = [
        t for t in parse_a2l_file(synth_path)["tags"] if t.get("section") == "CHARACTERISTIC"
    ]
    assert len(synth_chars) == 8
    assert all(t.get("char_type") is None for t in synth_chars)


# ---------------------------------------------------------------------------
# AT-100 — AXIS_DESCR multi-line: MaxAxisPoints + external-axis flag.
# ---------------------------------------------------------------------------


def test_at100_axis_descr_max_points_and_external_flag() -> None:
    """STD/COM/FIX axis bodies yield ``max_axis_points`` + ``external`` correctly.

    Intent: AXIS_DESCR bodies span lines with inline comments. The 4th positional
    token (comment-stripped) is MaxAxisPoints; ``external`` is true iff
    ``AXIS_PTS_REF`` appears. STD → 8/False, COM (has AXIS_PTS_REF) → True, FIX →
    6/False. Pre-fix only the first body line was tokenised.
    """
    chars = _chars(_DEMO_A2L)

    std_axis = next(t for t in chars if t["name"] == "ASAM.C.CURVE.STD_AXIS")["axis_meta"][0]
    assert std_axis["max_axis_points"] == "8"
    assert std_axis["external"] is False

    com_axis = next(t for t in chars if t["name"] == "ASAM.C.CURVE.COM_AXIS")["axis_meta"][0]
    assert com_axis["external"] is True

    fix_axis = next(
        t for t in chars if t["name"] == "ASAM.C.CURVE.FIX_AXIS.PAR_DIST"
    )["axis_meta"][0]
    assert fix_axis["max_axis_points"] == "6"
    assert fix_axis["external"] is False


def test_at100_axis_descr_short_body_no_crash(tmp_path: Path) -> None:
    """An AXIS_DESCR body with <4 tokens yields ``max_axis_points=None``, no crash."""
    body = (
        '      "desc"\n'
        "      CURVE 0x810000 RL_X 0 CM 0 255\n"
        "      /begin AXIS_DESCR\n"
        "        STD_AXIS X\n"
        "      /end AXIS_DESCR\n"
    )
    char = _parse_single_char(tmp_path, body)
    assert char is not None
    axis = char["axis_meta"][0]
    assert axis["max_axis_points"] is None
    assert axis["external"] is False


# ---------------------------------------------------------------------------
# AT-101 — hostile comment corpus through parse_a2l_file (gate-blocking, R-A2L-013).
# ---------------------------------------------------------------------------

# Each case = (id, body, expected_char_type). ``None`` means the malformed body
# must degrade to a None header (no kind / <7 params after stripping); a string
# means the mandatory params survive and parse to that char_type.
_HOSTILE_CASES = [
    # 1. Unterminated /* swallows every mandatory param → None header.
    ("unterminated_block_eats_mandatory", "      VALUE /* runaway to EOF with no close", None),
    # 2. A block comment spanning several lines is removed as one unit → parses.
    (
        "multiline_block_removed",
        '      "d"\n      VALUE 0x810000 /* start\n        still comment\n        end */ RL_X 0 CM 0 255',
        "VALUE",
    ),
    # 3. */ and // inside a quoted span must NOT eat the following mandatory params.
    (
        "quoted_metachars_preserved",
        '      "see */ and http:// inside" VALUE 0x810000 RL_X 0 CM 0 255',
        "VALUE",
    ),
    # 4. Unterminated " consumes to EOF; too few tokens remain → None, no raise.
    ("unterminated_quote", '      VALUE 0x810000 RL "never closes', None),
    # 5. arch-M2: an early-line // truncates ONLY its line; later params survive.
    (
        "line_comment_truncates_to_newline",
        "      VALUE // trailing junk on this line only\n      0x810000 RL_X 0 CM 0 255",
        "VALUE",
    ),
    # 6. A block comment between params is dropped; params rejoin → parses.
    ("block_comment_between_params", "      VALUE /* mid */ 0x810000 RL_X 0 CM 0 255", "VALUE"),
    # 7. A stray */ with no opening /* is a normal token → no crash, still parses.
    ("stray_close_no_open", "      VALUE 0x810000 */ 0 CM 0 255 X", "VALUE"),
    # 8. A comment-only body has no tokens → None header.
    ("comment_only_body", "      /* the entire body is a comment */", None),
]


@pytest.mark.parametrize("case_id,body,expected", _HOSTILE_CASES, ids=[c[0] for c in _HOSTILE_CASES])
def test_at101_hostile_comment_corpus(tmp_path: Path, case_id: str, body: str, expected: str | None) -> None:
    """8 hostile comment/quote bodies: 0 raise; malformed→None; valid→parse.

    Intent: R-A2L-013 (C-17) — the stripper is crash-free and content-preserving
    over malformed input. Driving through ``parse_a2l_file`` exercises the whole
    load path, not just the helper. The per-case ``expected`` distinguishes
    genuine degradation (None) from cases where valid mandatory params must
    survive the hostile syntax around them.
    """
    char = _parse_single_char(tmp_path, body, name=f"{case_id}.a2l")
    assert char is not None  # the block always yields a tag; only its header may be None
    assert char.get("char_type") == expected


def test_at101_positive_control_clean_multiline_parses(tmp_path: Path) -> None:
    """qa-M3: a clean well-formed multi-line block parses to a non-None char_type.

    Guards against a degenerate 'strip everything' implementation that would
    satisfy every malformed→None case vacuously.
    """
    body = '      "clean desc"\n      VALUE 0x810000\n      RL_X 0 CM 0 255'
    char = _parse_single_char(tmp_path, body, name="positive_control.a2l")
    assert char is not None
    assert char["char_type"] == "VALUE"
    assert char["address"] == 0x810000


def test_at101_quoted_metachar_bytes_preserved(tmp_path: Path) -> None:
    """The mandatory params survive a quoted ``*/``/``http://`` on the same line.

    A wrong stripper that honoured ``*/`` or ``//`` inside the quote would shift
    the token stream and drop ``VALUE 0x810000``. Their survival is the
    behavioural proxy for byte-preservation (exact bytes pinned in TC-101).
    """
    char = _parse_single_char(
        tmp_path,
        '      "x */ y http://z" VALUE 0x810000 RL_X 0 CM 0 255',
        name="quoted_bytes.a2l",
    )
    assert char is not None
    assert char["char_type"] == "VALUE"
    assert char["address"] == 0x810000


@pytest.mark.slow
def test_at101_megabyte_unterminated_block_is_linear(tmp_path: Path) -> None:
    """sec-F1: an MB-scale unterminated ``/*`` completes well under a wall bound.

    Locks the O(n) contract for the gate-blocking SAFE requirement — a naive
    backtracking/regex stripper would blow up here.
    """
    body = "      VALUE 0x810000 RL_X 0 CM 0 255 /*" + ("A" * 2_000_000)
    started = time.perf_counter()
    char = _parse_single_char(tmp_path, body, name="dos.a2l")
    elapsed = time.perf_counter() - started
    assert char is not None
    assert elapsed < 5.0


# ---------------------------------------------------------------------------
# AT-102 — batch-55 scope boundary: array length stays None this batch.
# ---------------------------------------------------------------------------


def test_at102_curve_map_length_stays_none() -> None:
    """CURVE/MAP STD_AXIS chars keep ``length is None`` (batch-55 owns the summer).

    Intent: now that the header populates ``deposit``/``char_type``, the length
    inferer must still NOT size a CURVE/MAP from its element-only deposit (that
    would under-report the array span). This guards the batch boundary — a
    premature length summer would trip here.
    """
    chars = _chars(_DEMO_A2L)
    curve = next(t for t in chars if t["name"] == "ASAM.C.CURVE.STD_AXIS")
    cmap = next(t for t in chars if t["name"] == "ASAM.C.MAP.STD_AXIS.STD_AXIS")
    assert curve["length"] is None
    assert cmap["length"] is None


# ---------------------------------------------------------------------------
# AT-103 — the now-live deposit renders verbatim (C-17, non-gate-blocking).
# ---------------------------------------------------------------------------


def test_at103_deposit_with_markup_metachars_renders_verbatim() -> None:
    """A ``deposit``/``record_layout_name`` with markup metachars renders literally.

    Intent: the field is newly populated for multi-line chars, so re-confirm the
    render sinks treat it as literal text. ``safe_text`` (the DataTable cell
    primitive) yields ``.plain`` equal to the input with ``spans == []`` (no
    markup parse), and the detail card appends it literally (verbatim in
    ``.plain``, no ``MarkupError``).
    """
    from s19_app.tui.app import _a2l_detail_card_text
    from s19_app.tui.screens_directionb import safe_text

    hostile = "RL.CURVE[red]/*x*/SWORD"
    cell = safe_text(hostile)
    assert cell.plain == hostile
    assert cell.spans == []

    tag = {
        "name": "C1",
        "record_layout_name": hostile,
        "deposit": hostile,
        "address": 0x810000,
    }
    card = _a2l_detail_card_text(tag)
    assert hostile in card.plain


# ---------------------------------------------------------------------------
# TC-097 — _strip_a2l_comments white-box.
# ---------------------------------------------------------------------------


def test_tc097_strip_removes_block_and_line_comments() -> None:
    # Spanning block comment (across the newline sentinel) removed as one unit.
    assert _strip_a2l_comments("A /* c\n more c */ B") == "A  B"
    # Adjacent (no-space) block comment fuses the surrounding tokens.
    assert _strip_a2l_comments("CURVE/*c*/0x1") == "CURVE0x1"


def test_tc097_line_comment_truncates_to_next_newline_only() -> None:
    """arch-M2: an early-line ``//`` must not swallow mandatory params on later lines."""
    text = "VALUE // junk\n0x10 RL 0 CM 0 255"
    stripped = _strip_a2l_comments(text)
    tokens = _split_line_respecting_quotes(stripped)
    # All 7 mandatory params recovered despite the first-line // comment.
    assert tokens == ["VALUE", "0x10", "RL", "0", "CM", "0", "255"]


def test_tc097_unterminated_constructs_never_raise() -> None:
    assert _strip_a2l_comments("VALUE /* no close") == "VALUE "
    assert _strip_a2l_comments('VALUE "no close') == 'VALUE "no close'
    # */ and // inside a quoted span are literal — bytes preserved exactly.
    assert _strip_a2l_comments('"a */ b // c http://d"') == '"a */ b // c http://d"'


# ---------------------------------------------------------------------------
# TC-098 — _flatten_body_tokens white-box.
# ---------------------------------------------------------------------------


def test_tc098_flatten_respects_quotes_across_lines() -> None:
    assert _flatten_body_tokens(['"a b" VALUE', "0x1 RL"]) == ["a b", "VALUE", "0x1", "RL"]


def test_tc098_flatten_escaped_quote_parity_with_splitter() -> None:
    """sec-F3: the flatten path's escape rule matches ``_split_line_respecting_quotes``."""
    line = '"a\\"b" X'
    assert _flatten_body_tokens([line]) == _split_line_respecting_quotes(line)


# ---------------------------------------------------------------------------
# TC-099 — kind-anchor positional white-box.
# ---------------------------------------------------------------------------


def test_tc099_kind_anchor_index_0_1_2() -> None:
    at0 = _characteristic_from_tokens(["VALUE", "0x10", "RL", "0", "CM", "0", "255"])
    assert at0["char_type"] == "VALUE" and at0["address_inline"] == 0x10

    at1 = _characteristic_from_tokens(["desc", "CURVE", "0x20", "RL", "0", "CM", "0", "255"])
    assert at1["char_type"] == "CURVE" and at1["address_inline"] == 0x20

    at2 = _characteristic_from_tokens(["NAME", "desc", "ASCII", "0x30", "RL", "0", "CM", "0", "255"])
    assert at2["char_type"] == "ASCII" and at2["address_inline"] == 0x30


def test_tc099_bad_address_and_no_kind_and_short() -> None:
    # int(addr) fails → address None, header still built.
    bad = _characteristic_from_tokens(["VALUE", "notanaddr", "RL", "0", "CM", "0", "255"])
    assert bad["char_type"] == "VALUE" and bad["address_inline"] is None
    # No kind token → None.
    assert _characteristic_from_tokens(["a", "b", "c", "d", "e", "f", "g"]) is None
    # Kind present but <7 tokens follow → None (fail-closed, no IndexError).
    assert _characteristic_from_tokens(["VALUE", "0x10", "RL"]) is None


def test_tc099_bare_kind_word_before_type_degrades_to_none_address() -> None:
    """arch-M1 negative: a bare unquoted kind word used as a name mis-anchors.

    This is a documented non-goal — the real ASAM corpus always quotes/dots
    identifiers so it cannot occur there. The contract is graceful degradation
    (``address_inline is None``), never a crash.
    """
    header = _characteristic_from_tokens(["MAP", "desc", "VALUE", "0x40", "RL", "0", "CM", "0", "255"])
    assert header is not None
    assert header["char_type"] == "MAP"  # mis-anchored on the bare kind word
    assert header["address_inline"] is None  # int("desc", 0) → None, no crash


# ---------------------------------------------------------------------------
# TC-100 — axis full-body tokenisation white-box.
# ---------------------------------------------------------------------------


def test_tc100_axis_tokenise_full_body() -> None:
    std = _flatten_body_tokens(["STD_AXIS X CM /* c */", "8", "-128 127"])
    assert std[3] == "8"
    assert ("AXIS_PTS_REF" in std) is False

    com = _flatten_body_tokens(["COM_AXIS X CM", "8 -128 127", "AXIS_PTS_REF AXPTS"])
    assert ("AXIS_PTS_REF" in com) is True


# ---------------------------------------------------------------------------
# TC-098b — single-line parse_characteristic_header back-compat (delegation).
# ---------------------------------------------------------------------------


def test_backcompat_parse_characteristic_header_delegates() -> None:
    from s19_app.tui.a2l import parse_characteristic_header

    header = parse_characteristic_header("VALUE 0x80000010 RL_U8 0 CM_IDENT 0 255")
    assert header == {
        "char_type": "VALUE",
        "address_inline": 0x80000010,
        "deposit": "RL_U8",
        "max_diff": "0",
        "conversion": "CM_IDENT",
        "lower_limit": "0",
        "upper_limit": "255",
        "datatype": None,
    }


def test_assemble_characteristic_header_public_and_facade() -> None:
    """The public assembler flattens a multi-line body; facade re-exports it."""
    from s19_app.tui import a2l_parse

    lines = ['"desc"', "CURVE 0x810300 /* c */", "RL.X 0 CM 0 255"]
    header = assemble_characteristic_header(lines)
    assert header is not None
    assert header["char_type"] == "CURVE"
    assert header["address_inline"] == 0x810300
    assert header["deposit"] == "RL.X"
    # Same object re-exported from the narrow facade.
    assert a2l_parse.assemble_characteristic_header is assemble_characteristic_header
    # No-kind body → None.
    assert assemble_characteristic_header(["ECU_ADDRESS 0x10", "LENGTH 4"]) is None
