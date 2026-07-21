"""Alignment-aware CURVE/MAP length sizing — batch-56 (alignment-aware padding).

Requirement ``R-A2L-016`` (HLR-A56): a CURVE/MAP whose RECORD_LAYOUT declares
``ALIGNMENT_<CLASS> N`` directives in its body sizes CORRECTLY via a
cumulative-offset walk that pads each component's start up to its datatype's
declared alignment (R-B), with NO trailing pad (R-C) and no MOD_COMMON honoring
(R-A). A layout with no body-level ``ALIGNMENT_*`` stays packed, byte-identical
to batch-55.

Black-box ATs drive the shipped ``parse_a2l_file`` surface (AT-113 additionally
the ``enrich_tags_and_render`` / ``_a2l_tag_row_severity`` view-row consumer) and
assert THE BYTE VALUE / the ``None`` — never "non-empty". White-box TCs pin the
``_record_layout_full_span`` walk, the ``_collect_declared_alignments`` first
pass, the ``align_up`` primitive, and the ``_DATATYPE_ALIGNMENT_DIRECTIVE`` census
directly. Oracles are hand-computed from the in-test layout strings + the §2.5
offset table; the demo oracles (25/51/12/None) are the batch-55 shipped values,
preserved by the R-A packed default.

NON-frozen file on purpose: ``tests/test_tui_a2l.py`` is TC-032 / C-27 frozen, so
batch-56's new tests must NOT land there (LLR-A56.6 / TC-152). The helpers
``_write_a2l`` / ``_axis_meta`` / ``_demo_char`` are imported from the batch-55
module (M5: never duplicated).
"""

from __future__ import annotations

import time
from pathlib import Path

from s19_app.tui.a2l import (
    DATATYPE_SIZES,
    MAX_A2L_DECODE_BYTES,
    _ALIGNMENT_DIRECTIVES,
    _DATATYPE_ALIGNMENT_DIRECTIVE,
    _collect_declared_alignments,
    _record_layout_full_span,
    align_up,
    parse_a2l_file,
)
from s19_app.tui.app import _a2l_tag_row_severity
from s19_app.tui.services.a2l_service import enrich_tags_and_render
from s19_app.validation.model import ValidationSeverity

from tests.test_a2l_inline_axis_length import _demo_char, _write_a2l  # M5: reuse, no dup

# The §2.5 primary fixture — a CURVE with an inline STD_AXIS (MaxAxisPoints=2) and
# a RECORD_LAYOUT declaring two alignment classes (WORD + LONG). Packed span 13;
# aligned span 16 (3 pad bytes across two classes, ends LONG-aligned → R-C
# independent). token[1] values (1/2/3) are POSITION INDICES, never counts.
_MULTI_CLASS_LINES = [
    "NO_AXIS_PTS_X 1 UBYTE",   # BYTE class, undeclared → align 1, count 1
    "ALIGNMENT_WORD 2",
    "ALIGNMENT_LONG 4",
    "AXIS_PTS_X 2 UWORD",      # WORD class → align 2, count = axis[0] = 2
    "FNC_VALUES 3 ULONG",      # LONG class → align 4, count = prod(axis) = 2
]
_PACKED_MULTI_LINES = [ln for ln in _MULTI_CLASS_LINES if not ln.startswith("ALIGNMENT_")]


def _expected_directive(datatype: str, size: int) -> str:
    """Derive the ALIGNMENT_* directive a datatype MUST map to (TC-143 oracle).

    Independent of ``_DATATYPE_ALIGNMENT_DIRECTIVE`` itself: float datatypes take
    their own ``ALIGNMENT_<name>`` directive; integers key on byte width. A drop
    or a mis-map in the census then diverges from this derivation → RED.
    """
    if datatype.endswith("_IEEE"):
        return "ALIGNMENT_" + datatype  # FLOAT16_IEEE → ALIGNMENT_FLOAT16_IEEE
    return {1: "ALIGNMENT_BYTE", 2: "ALIGNMENT_WORD", 4: "ALIGNMENT_LONG", 8: "ALIGNMENT_INT64"}[size]


# ===========================================================================
# Black-box AT (US-A56) — observed through parse_a2l_file (+ the view consumer).
# ===========================================================================


def test_at113_multi_class_alignment_curve_length_16(tmp_path: Path) -> None:
    """AT-113 — multi-class ALIGNMENT CURVE → length 16 (packed 13); (b) row grey→checkable.

    Intent: the value proof of the alignment walk (two alignment classes, 3 pad
    bytes) AND the output-then-consume chain (C-12): the derived length flips the
    A2L row from grey (None) to memory-checkable. Pre-fix (force-None on any
    ALIGNMENT_*) → None → grey.
    """
    tag = _write_a2l(
        tmp_path, cname="C_ALIGN", char_type="CURVE", deposit="RL_ALIGN",
        layout_lines=_MULTI_CLASS_LINES, axes=[("STD_AXIS", 2)], name="align.a2l",
    )
    assert tag["char_type"] == "CURVE"
    assert tag["length"] == 16
    # packed counterfactual: strip the ALIGNMENT lines → 13 (1 + 2×2 + 4×2)
    packed = _write_a2l(
        tmp_path, cname="C_PACK", char_type="CURVE", deposit="RL_PACK",
        layout_lines=_PACKED_MULTI_LINES, axes=[("STD_AXIS", 2)], name="pack.a2l",
    )
    assert packed["length"] == 13

    # (b) output-then-consume: the filled length makes the row memory-checkable.
    a2l_data = parse_a2l_file(tmp_path / "align.a2l")
    curve = next(t for t in a2l_data["tags"] if t["name"] == "C_ALIGN")
    assert curve["length"] == 16
    addr = curve["address"]
    cover = {addr + i: 0 for i in range(16)}
    merged, _ = enrich_tags_and_render(a2l_data, cover)
    row = next(t for t in merged if t["name"] == "C_ALIGN")
    assert row.get("memory_checked") is True
    assert _a2l_tag_row_severity(row, {}) is ValidationSeverity.OK
    # counterfactual: revert length to None over the SAME map → grey (not checkable).
    for t in a2l_data["tags"]:
        if t["name"] == "C_ALIGN":
            t["length"] = None
    merged2, _ = enrich_tags_and_render(a2l_data, cover)
    row2 = next(t for t in merged2 if t["name"] == "C_ALIGN")
    assert row2.get("memory_checked") is False
    assert _a2l_tag_row_severity(row2, {}) is not ValidationSeverity.OK


def test_at114_demo_packed_oracles_unchanged() -> None:
    """AT-114 (gate anchor) — the demo CURVE/MAP packed oracles are UNCHANGED.

    Intent: the batch-55 regression anchor. The whole demo corpus declares zero
    body-level ALIGNMENT_* (probe: NONE), so every value must stay identical. A
    natural-align-by-default (or MOD_COMMON-honored) impl would flip
    CURVE.STD_AXIS 25→26 and trip here.
    """
    assert _demo_char("ASAM.C.CURVE.STD_AXIS")["length"] == 25  # RED if MOD_COMMON honored → 26
    assert _demo_char("ASAM.C.MAP.STD_AXIS.STD_AXIS")["length"] == 51
    assert _demo_char("ASAM.C.CURVE.FIX_AXIS.PAR_DIST")["length"] == 12
    assert _demo_char("ASAM.C.CURVE.COM_AXIS")["length"] is None


def test_at115_alignment_is_the_sole_cause_of_the_delta(tmp_path: Path) -> None:
    """AT-115 (R-A isolation) — same components WITH vs WITHOUT ALIGNMENT → 16 > 13 ∧ 13.

    Intent: prove the ALIGNMENT declaration is the SOLE cause of the padding.
    Padding applied WITHOUT a declared ALIGNMENT_* (an ungated pad, the R-A
    violation) would make ``without`` 16 too → the ``without == 13`` clause fails.
    """
    with_align = _write_a2l(
        tmp_path, cname="C_W", char_type="CURVE", deposit="RL_W",
        layout_lines=_MULTI_CLASS_LINES, axes=[("STD_AXIS", 2)], name="w.a2l",
    )
    without = _write_a2l(
        tmp_path, cname="C_WO", char_type="CURVE", deposit="RL_WO",
        layout_lines=_PACKED_MULTI_LINES, axes=[("STD_AXIS", 2)], name="wo.a2l",
    )
    assert with_align["length"] == 16
    assert without["length"] == 13
    assert with_align["length"] > without["length"]


def test_at116_unmodeled_directive_still_forces_none(tmp_path: Path) -> None:
    """AT-116 (full-span-or-None preserved) — alignment CURVE + unmodeled directive → None.

    Intent: an ALIGNMENT-bearing layout that ALSO carries a genuinely-unmodeled
    non-alignment directive (AXIS_RESCALE_X) must still force None, not a fabricated
    span. Treating any unknown 2+-token line as 0-pad would under-report (false-green).
    No exception raised (a tag is returned).
    """
    layout = [
        "NO_AXIS_PTS_X 1 UBYTE",
        "ALIGNMENT_WORD 2",
        "AXIS_PTS_X 2 UWORD",
        "AXIS_RESCALE_X 3 UWORD 4",   # unmodeled non-alignment directive
        "FNC_VALUES 5 ULONG",
    ]
    tag = _write_a2l(
        tmp_path, cname="C_RESC", char_type="CURVE", deposit="RL_RESC",
        layout_lines=layout, axes=[("STD_AXIS", 2)], name="resc.a2l",
    )
    assert tag["length"] is None


def test_at117_already_aligned_pad_zero_length_10(tmp_path: Path) -> None:
    """AT-117 (boundary pad=0) — all-WORD layout + ALIGNMENT_WORD 2 → 10 (== packed).

    Intent: a declared alignment that produces zero padding because every offset is
    already aligned. A mutation that pads unconditionally (a phantom byte when
    already aligned) → >10.
    """
    layout = [
        "NO_AXIS_PTS_X 1 UWORD",
        "ALIGNMENT_WORD 2",
        "AXIS_PTS_X 2 UWORD",
        "FNC_VALUES 3 UWORD",
    ]
    tag = _write_a2l(
        tmp_path, cname="C_WORD", char_type="CURVE", deposit="RL_WORD",
        layout_lines=layout, axes=[("STD_AXIS", 2)], name="word.a2l",
    )
    assert tag["length"] == 10  # 2 + 2×2 + 2×2, no pad


def test_at118_over_align_uses_declared_value_length_16(tmp_path: Path) -> None:
    """AT-118 (boundary over-align, R-B) — ALIGNMENT_LONG 8 over-declared → 16, not 12.

    Intent: the walk aligns to the DECLARED value (8), not the datatype's natural
    LONG size (4). rup(1,8)=8; +4×2=8 → 16. Using natural size → rup(1,4)=4; +8=12.
    """
    layout = [
        "NO_AXIS_PTS_X 1 UBYTE",
        "FNC_VALUES 2 ULONG",
        "ALIGNMENT_LONG 8",       # over-declared (> natural LONG size 4)
    ]
    tag = _write_a2l(
        tmp_path, cname="C_OVER", char_type="CURVE", deposit="RL_OVER",
        layout_lines=layout, axes=[("FIX_AXIS", 2)], name="over.a2l",
    )
    assert tag["length"] == 16


def test_at119_no_trailing_pad_length_17(tmp_path: Path) -> None:
    """AT-119 (R-C = no trailing pad) — ends on a small component after a large-aligned one → 17.

    Intent: pins R-C reading (i). UBYTE→1; A_UINT64 aligned to 8 → 8..16; trailing
    UBYTE → 17. NO trailing pad-to-max (which would be align_up(17,8)=24). 24 is the
    RED that signals the wrong R-C reading.
    """
    layout = [
        "NO_AXIS_PTS_X 1 UBYTE",
        "AXIS_PTS_X 2 A_UINT64",
        "FNC_VALUES 3 UBYTE",
        "ALIGNMENT_INT64 8",
    ]
    tag = _write_a2l(
        tmp_path, cname="C_RC", char_type="CURVE", deposit="RL_RC",
        layout_lines=layout, axes=[("STD_AXIS", 1)], name="rc.a2l",
    )
    assert tag["length"] == 17


def test_at120_oversized_alignment_layout_clamps_to_none(tmp_path: Path) -> None:
    """AT-120 (DoS) — oversized axis + declared alignment → None, completes fast.

    Intent: the running padded offset is capped by MAX_A2L_DECODE_BYTES via pure
    arithmetic; no allocation, no @slow. A ~10M axis renders honest grey.
    """
    layout = [
        "NO_AXIS_PTS_X 1 UBYTE",
        "ALIGNMENT_WORD 2",
        "AXIS_PTS_X 2 SWORD",
        "FNC_VALUES 3 SWORD",
    ]
    started = time.perf_counter()
    tag = _write_a2l(
        tmp_path, cname="C_DOS", char_type="CURVE", deposit="RL_DOS",
        layout_lines=layout, axes=[("STD_AXIS", 10_000_000)], name="dos.a2l",
    )
    elapsed = time.perf_counter() - started
    assert tag["length"] is None
    assert elapsed < 2.0


def test_at122_hostile_alignment_value_forces_none(tmp_path: Path) -> None:
    """AT-122 (hostile alignment value) — ALIGNMENT_WORD x / 0 / -4 → None, no exception.

    Intent: a non-int, zero, or negative alignment value must fail closed to None
    without any exception — especially no ZeroDivisionError from ``o % 0`` (Phase-2
    sec-M3). Each parse completes and yields a grey tag.
    """
    base = ["NO_AXIS_PTS_X 1 UBYTE", "{alignment}", "AXIS_PTS_X 2 UWORD", "FNC_VALUES 3 ULONG"]
    for i, bad in enumerate(("ALIGNMENT_WORD x", "ALIGNMENT_WORD 0", "ALIGNMENT_WORD -4")):
        layout = [ln.format(alignment=bad) for ln in base]
        tag = _write_a2l(
            tmp_path, cname=f"C_BAD{i}", char_type="CURVE", deposit=f"RL_BAD{i}",
            layout_lines=layout, axes=[("STD_AXIS", 2)], name=f"bad{i}.a2l",
        )
        assert tag["length"] is None


# ===========================================================================
# White-box TC (LLR-A56.*) — the walk, the collector, align_up, the census.
# ===========================================================================


def test_tc143_alignment_directive_census_derived() -> None:
    """TC-143 (LLR-A56.2, C-31) — the datatype→directive census is complete AND correct.

    Intent: a hand-listed census is vacuous. The invariant is the oracle: every
    sizable datatype has a mapping (key-set == DATATYPE_SIZES), the value-set is the
    7 ALIGNMENT_* names, and each per-datatype mapping equals the derived directive.
    A DROPPED key or a MIS-map → RED.
    """
    assert set(_DATATYPE_ALIGNMENT_DIRECTIVE) == set(DATATYPE_SIZES)
    expected_names = {_expected_directive(dt, sz) for dt, sz in DATATYPE_SIZES.items()}
    assert len(expected_names) == 7
    assert set(_DATATYPE_ALIGNMENT_DIRECTIVE.values()) == expected_names
    # per-datatype correctness — catches a mis-map that keeps the value-set size
    for dt, size in DATATYPE_SIZES.items():
        assert _DATATYPE_ALIGNMENT_DIRECTIVE[dt] == _expected_directive(dt, size)
    # the directive set the walk skips == the census value-set (no drift)
    assert _ALIGNMENT_DIRECTIVES == frozenset(_DATATYPE_ALIGNMENT_DIRECTIVE.values())


def test_tc144_cumulative_offset_walk() -> None:
    """TC-144 (LLR-A56.1) — the walk pads correctly; multi-class 16, single-class 8.

    Intent: token[2] is the datatype and token[1] the position index (NOT a count),
    and the cumulative-offset walk applies per-class padding. An ignore-alignment
    mutation lands at the packed 13.
    """
    multi = {"lines": _MULTI_CLASS_LINES}
    assert _record_layout_full_span(multi, [2]) == 16
    # ignore-alignment mutation → packed 13
    assert _record_layout_full_span({"lines": _PACKED_MULTI_LINES}, [2]) == 13
    # secondary single-class fixture (§2.5): 1(UBYTE) + 2(SBYTE×2) + pad1 + 4(SWORD×2) = 8
    single = {
        "lines": ["NO_AXIS_PTS_X 1 UBYTE", "AXIS_PTS_X 2 SBYTE", "ALIGNMENT_WORD 2", "FNC_VALUES 3 SWORD"],
    }
    assert _record_layout_full_span(single, [2]) == 8
    assert _record_layout_full_span({"lines": [ln for ln in single["lines"] if not ln.startswith("ALIGNMENT_")]}, [2]) == 7
    # token[1] is a POSITION INDEX — misleading indices (99/7) must be ignored → still 16
    mislead = {
        "lines": ["NO_AXIS_PTS_X 99 UBYTE", "ALIGNMENT_WORD 2", "ALIGNMENT_LONG 4", "AXIS_PTS_X 7 UWORD", "FNC_VALUES 3 ULONG"],
    }
    assert _record_layout_full_span(mislead, [2]) == 16


def test_tc145_collect_declared_alignments() -> None:
    """TC-145 (LLR-A56.2) — the alignment collector: parse, default-1, 0-span, fail-closed.

    Intent: declared ALIGNMENT_* lines → {directive: N}; a packed layout → {}; an
    undeclared class → align 1; the ALIGNMENT_* line contributes 0 span; a non-int /
    zero / negative value → None (fail-closed, non-positive guard). Last wins on a dup.
    """
    assert _collect_declared_alignments(["ALIGNMENT_WORD 2", "ALIGNMENT_LONG 4"]) == {"ALIGNMENT_WORD": 2, "ALIGNMENT_LONG": 4}
    assert _collect_declared_alignments(["NO_AXIS_PTS_X 1 UBYTE", "FNC_VALUES 2 SWORD"]) == {}  # packed
    # undeclared class defaults to align 1 at the call site
    assert _collect_declared_alignments(["ALIGNMENT_WORD 2"]).get("ALIGNMENT_LONG", 1) == 1
    # the ALIGNMENT_* line contributes 0 span (governs no present datatype → no-op)
    assert _record_layout_full_span({"lines": ["FNC_VALUES 1 UBYTE", "ALIGNMENT_LONG 4"]}, [1]) == 1
    assert _record_layout_full_span({"lines": ["FNC_VALUES 1 UBYTE"]}, [1]) == 1
    # fail-closed: non-int / zero / negative → None (no exception, no ZeroDivisionError)
    assert _collect_declared_alignments(["ALIGNMENT_WORD x"]) is None
    assert _collect_declared_alignments(["ALIGNMENT_WORD 0"]) is None
    assert _collect_declared_alignments(["ALIGNMENT_WORD -4"]) is None
    # duplicate directive → last declared value wins
    assert _collect_declared_alignments(["ALIGNMENT_WORD 2", "ALIGNMENT_WORD 4"]) == {"ALIGNMENT_WORD": 4}


def test_tc146_align_up_primitive() -> None:
    """TC-146 (LLR-A56.1/.5) — align_up correctness and the a<=1 no-raise guard.

    Intent: the padding primitive in isolation, including the short-circuit for
    a <= 1 that returns BEFORE ``o % a`` so a non-positive alignment never raises.
    """
    assert align_up(0, 4) == 0
    assert align_up(1, 4) == 4
    assert align_up(6, 4) == 8
    assert align_up(8, 8) == 8
    assert align_up(5, 1) == 5  # identity when packed
    # a <= 1 short-circuits BEFORE the modulo → never ZeroDivisionError
    assert align_up(5, 0) == 5
    assert align_up(5, -4) == 5


def test_tc147_packed_no_regression_byte_identical() -> None:
    """TC-147 (LLR-A56.3) — no ALIGNMENT_* → byte-for-byte the batch-55 packed sum.

    Intent: the white-box mirror of AT-114. With no body-level ALIGNMENT_*, the
    walk is arithmetically the batch-55 running sum: the demo STD_AXIS layout → 25,
    the FIX_AXIS FNC layout → 12.
    """
    std = {"lines": ["NO_AXIS_PTS_X 1 UBYTE", "AXIS_PTS_X 2 SBYTE", "FNC_VALUES 3 SWORD"]}
    assert _record_layout_full_span(std, [8]) == 25  # 1 + 8×1 + 8×2
    fix = {"lines": ["FNC_VALUES 1 SWORD"]}
    assert _record_layout_full_span(fix, [6]) == 12  # 6×2


def test_tc148_mod_common_excluded_and_unmodeled_forces_none() -> None:
    """TC-148 (LLR-A56.4) — collector reads only layout["lines"]; unmodeled directive → None.

    Intent: alignment is derived ONLY from the RECORD_LAYOUT body — the collector
    has no module/MOD_COMMON input — and an alignment-bearing layout carrying a
    genuinely-unmodeled non-alignment directive still forces None.
    """
    bearing_unmodeled = {
        "lines": ["NO_AXIS_PTS_X 1 UBYTE", "ALIGNMENT_WORD 2", "AXIS_RESCALE_X 2 UWORD 4", "FNC_VALUES 3 ULONG"],
    }
    assert _record_layout_full_span(bearing_unmodeled, [2]) is None
    # the collector's ONLY input is the body lines — a MOD_COMMON-scoped default it
    # cannot see (not in these lines) has no effect; a packed body → {}.
    assert _collect_declared_alignments([]) == {}


def test_tc149_dos_clamp_includes_padding() -> None:
    """TC-149 (LLR-A56.5) — the padded running total clamps to None via the byte cap, <1s.

    Intent: a huge count + declared alignment returns None via a pure-arithmetic
    MAX_A2L_DECODE_BYTES compare that includes padding — no range/list materialized.
    """
    assert MAX_A2L_DECODE_BYTES == 1_048_576
    started = time.perf_counter()
    huge = _record_layout_full_span(
        {"lines": ["NO_AXIS_PTS_X 1 UBYTE", "ALIGNMENT_WORD 2", "AXIS_PTS_X 2 SWORD", "FNC_VALUES 3 SWORD"]},
        [10_000_000],
    )
    elapsed = time.perf_counter() - started
    assert huge is None
    assert elapsed < 1.0


def test_tc150_no_trailing_pad_r_c() -> None:
    """TC-150 (LLR-A56.1, R-C) — the AT-119 layout → 17 at helper level; 24 is the RED.

    Intent: white-box mirror of AT-119. reading (i) = last component's end offset,
    no post-loop align_up. Trailing-to-max would be align_up(17,8)=24.
    """
    rc = {
        "lines": ["NO_AXIS_PTS_X 1 UBYTE", "AXIS_PTS_X 2 A_UINT64", "FNC_VALUES 3 UBYTE", "ALIGNMENT_INT64 8"],
    }
    assert _record_layout_full_span(rc, [1]) == 17
    assert _record_layout_full_span(rc, [1]) != 24  # trailing-pad reading (ii)
