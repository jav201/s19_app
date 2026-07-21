"""Inline-axis length summer for CURVE/MAP CHARACTERISTICs — batch-55 (P-1b).

Requirements ``R-A2L-008`` (the inline-axis length summer), ``R-A2L-014`` (the
``MAX_A2L_DECODE_BYTES`` byte-decode clamp). A CURVE/MAP with inline STD_AXIS /
FIX_AXIS axes reports a correct byte ``length`` (summing the resolved
RECORD_LAYOUT on-disk span × inline axis point-counts) so its bytes become
memory-checkable; external-axis (COM_AXIS / RES_AXIS / CURVE_AXIS / AXIS_PTS_REF)
CURVE/MAP deliberately stay ``length is None`` (full-span-or-None: never
under-report, a too-short length would falsely pass the byte-range memory check).

Black-box ATs drive the shipped ``parse_a2l_file`` surface (+ ``enrich_tags_and_
render`` / ``_a2l_tag_row_severity`` for the view-row consumer) and assert THE
BYTE VALUE / the ``None`` — never "non-empty". White-box TCs pin the private
``_record_layout_full_span`` / ``_inline_axis_counts`` helpers and the census
constants directly. Oracle values (25 / 51 / 12 / None) were EXECUTED over the
real demo at draft time (C-35).

NON-frozen sibling on purpose: ``tests/test_tui_a2l.py`` is TC-032 / C-27 frozen,
so batch-55's new tests must NOT land there (LLR-P1b.7 / TC-141).
"""

from __future__ import annotations

import time
from pathlib import Path

from s19_app.tui.a2l import (
    ALL_AXIS_KINDS,
    MAX_A2L_DECODE_BYTES,
    _DERIVABLE_AXIS_KINDS,
    _EXTERNAL_AXIS_KINDS,
    _inline_axis_counts,
    _record_layout_full_span,
    parse_a2l_file,
)
from s19_app.tui.services.a2l_service import enrich_tags_and_render
from s19_app.tui.app import _a2l_tag_row_severity
from s19_app.validation.model import ValidationSeverity

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEMO_A2L = _REPO_ROOT / "examples" / "case_00_public" / "ASAP2_Demo_V161.a2l"
_CASE01_A2L = _REPO_ROOT / "examples" / "case_01_basic_valid" / "firmware.a2l"


def _axis_meta(kind: str, max_axis_points, external: bool = False) -> dict:
    """Build one ``axis_meta`` entry as ``extract_a2l_tags`` produces it."""
    return {
        "name": kind,
        "header_tokens": [kind, "NO_INPUT", "NO_COMPU_METHOD", str(max_axis_points), "0", "255"],
        "max_axis_points": max_axis_points,
        "external": external,
    }


def _write_a2l(
    tmp_path: Path,
    *,
    cname: str,
    char_type: str,
    deposit: str,
    layout_lines: list[str],
    axes: list[tuple[str, object]],
    extra_char_lines: str = "",
    address: str = "0x1000",
    name: str = "syn.a2l",
) -> dict:
    """Write a one-CHARACTERISTIC synthetic A2L and return the parsed tag.

    ``axes`` is a list of ``(kind, max_axis_points)`` — the AXIS_DESCR params sit
    on a BODY line (the real ASAM convention: ``/begin AXIS_DESCR`` alone), so the
    kind lands at ``header_tokens[0]`` and MaxAxisPoints at ``header_tokens[3]``.
    """
    rl = "\n".join("      " + ln for ln in layout_lines)
    axis_blocks = ""
    for kind, mp in axes:
        axis_blocks += (
            "      /begin AXIS_DESCR\n"
            f"        {kind} NO_INPUT NO_COMPU_METHOD {mp} 0 255\n"
            "      /end AXIS_DESCR\n"
        )
    text = (
        '/begin PROJECT P "syn"\n'
        '  /begin MODULE M "syn"\n'
        f"    /begin RECORD_LAYOUT {deposit}\n{rl}\n    /end RECORD_LAYOUT\n"
        f'    /begin CHARACTERISTIC {cname} "d"\n'
        f"      {char_type} {address} {deposit} 0 NO_COMPU_METHOD 0 255\n"
        f"{extra_char_lines}"
        f"{axis_blocks}"
        "    /end CHARACTERISTIC\n"
        "  /end MODULE\n"
        "/end PROJECT\n"
    )
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return next(t for t in parse_a2l_file(path)["tags"] if t["name"] == cname)


def _demo_char(name: str) -> dict:
    tags = parse_a2l_file(_DEMO_A2L)["tags"]
    return next(t for t in tags if t.get("section") == "CHARACTERISTIC" and t["name"] == name)


# ---------------------------------------------------------------------------
# TC-133 — _record_layout_full_span: token[2] datatype, position-not-count,
#          size-asymmetric MAP axis-order guard (LLR-P1b.1, arch-MAJ1).
# ---------------------------------------------------------------------------


def test_tc133_record_layout_full_span_datatype_and_axis_order() -> None:
    """The summer reads token[2] as datatype (not token[1]=position) and wires axes in order.

    Intent: guard MAJOR-1 (token[1] is the ASAM position index, NOT a count) and
    the axis-order wiring (``axis_counts[0]`` vs ``[1]``). A size-asymmetric MAP
    whose X/Y datatypes differ must produce a total that a swapped count
    assignment cannot reproduce.
    """
    # STD-CURVE shape: NO_AXIS_PTS_X(1×UBYTE) + AXIS_PTS_X(8×SBYTE) + FNC_VALUES(8×SWORD) = 25.
    # Position indices are deliberately misleading (99/1/7) — they must be IGNORED.
    curve_layout = {
        "lines": [
            "NO_AXIS_PTS_X 99 UBYTE",
            "AXIS_PTS_X 1 SBYTE",
            "FNC_VALUES 7 SWORD",
        ]
    }
    assert _record_layout_full_span(curve_layout, [8]) == 25
    # If token[1] were (wrongly) used as the count: 1×1 + 2×1 + 3×2 would give a
    # different figure — 25 can only arise from axis_counts + token[2] datatype.

    # Two-axis MAP with the demo oracle (both axes SBYTE → order-invariant): 51.
    map_layout = {
        "lines": [
            "NO_AXIS_PTS_X 1 UBYTE",
            "NO_AXIS_PTS_Y 2 UBYTE",
            "AXIS_PTS_X 3 SBYTE",
            "AXIS_PTS_Y 4 SBYTE",
            "FNC_VALUES 5 SWORD",
        ]
    }
    assert _record_layout_full_span(map_layout, [4, 5]) == 51

    # Size-asymmetric MAP (arch-MAJ1): AXIS_PTS_X SWORD, AXIS_PTS_Y SBYTE.
    #   correct [4,3] = 1 + 1 + 4×2 + 3×1 + (4·3)×1 = 25
    #   swapped [3,4] = 1 + 1 + 3×2 + 4×1 + (3·4)×1 = 24  → discriminates the swap.
    asym = {
        "lines": [
            "NO_AXIS_PTS_X 1 UBYTE",
            "NO_AXIS_PTS_Y 2 UBYTE",
            "AXIS_PTS_X 3 SWORD",
            "AXIS_PTS_Y 4 SBYTE",
            "FNC_VALUES 5 UBYTE",
        ]
    }
    assert _record_layout_full_span(asym, [4, 3]) == 25
    assert _record_layout_full_span(asym, [3, 4]) == 24
    assert _record_layout_full_span(asym, [4, 3]) != _record_layout_full_span(asym, [3, 4])


def test_tc133_full_span_or_none_on_unclassifiable() -> None:
    """A ≥3-token line outside the taxonomy forces the WHOLE span to None (not skip).

    Intent: LLR-P1b.1 / arch-MIN3 — the reference probe's ``continue``-skip
    under-reports (a false-green); the summer must return None on any
    unclassifiable component, unknown datatype, absent axis count, or empty
    contribution.
    """
    # unknown component name (≥3 tokens) → None, not a partial sum
    assert _record_layout_full_span({"lines": ["MYSTERY_COMP 1 UBYTE", "FNC_VALUES 2 SWORD"]}, [4]) is None
    # unknown datatype on a real component → None (DATATYPE_SIZES.get → None)
    assert _record_layout_full_span({"lines": ["FNC_VALUES 1 NOTADT"]}, [4]) is None
    # AXIS_PTS_Y needed but only one axis count present → None
    assert _record_layout_full_span({"lines": ["AXIS_PTS_Y 1 SBYTE"]}, [4]) is None
    # a non-component directive line (BYTE_ORDER) forces None; the blank is skipped
    assert _record_layout_full_span({"lines": ["BYTE_ORDER MSB_LAST", ""]}, [4]) is None
    # empty layout → None
    assert _record_layout_full_span({"lines": []}, [4]) is None


def test_tc133b_alignment_directive_forces_none() -> None:
    # TC-133b → superseded by batch-56 (LLR-SUP56.1 / §6.5 AMD-1): alignment-aware padding.
    """ALIGNMENT_* is consumed as a padding directive and pads component starts (batch-56).

    Intent: batch-55 authored this to lock the blanket force-``None`` on any
    ALIGNMENT_* line (code-review F1); batch-56 deliberately flips that to an
    alignment-aware cumulative-offset walk. ALIGNMENT_BYTE/WORD/LONG/INT64/FLOAT*
    now pad each component's start up to its datatype's declared alignment; only an
    unmodeled NON-alignment line still forces ``None`` (that false-green anchor role
    passes to test_a2l_alignment_sizing::AT-116). See §6.5 AMD-1 (Before→After).
    """
    summable = {
        "lines": ["NO_AXIS_PTS_X 1 UBYTE", "AXIS_PTS_X 2 UBYTE", "FNC_VALUES 3 SWORD"],
    }
    # No alignment declared → packed 13 (1 + 4×1 + 4×2). RETAINED from batch-55.
    assert _record_layout_full_span(summable, [4]) == 13
    # ALIGNMENT_WORD 2 pads FNC_VALUES (SWORD) start 5→6 → 14 (was None in batch-55).
    with_alignment = {
        "lines": [
            "NO_AXIS_PTS_X 1 UBYTE",
            "ALIGNMENT_WORD 2",
            "AXIS_PTS_X 2 UBYTE",
            "FNC_VALUES 3 SWORD",
        ],
    }
    assert _record_layout_full_span(with_alignment, [4]) == 14
    # ALIGNMENT_LONG 4 governs no present LONG-class datatype → zero effect → 13
    # (proves a declared alignment affects ONLY components of its governed class).
    trailing_align = {
        "lines": [
            "NO_AXIS_PTS_X 1 UBYTE",
            "AXIS_PTS_X 2 UBYTE",
            "FNC_VALUES 3 SWORD",
            "ALIGNMENT_LONG 4",
        ],
    }
    assert _record_layout_full_span(trailing_align, [4]) == 13


# ---------------------------------------------------------------------------
# TC-134 — _inline_axis_counts: base-10 cast, external gate (LLR-P1b.2).
# ---------------------------------------------------------------------------


def test_tc134_inline_axis_counts_base10_and_external_gate() -> None:
    """Inline STD/FIX axes → base-10 int counts; external / bad MaxAxisPoints → None, no raise.

    Intent: LLR-P1b.2 / sec-F2/F3/F4 — cast MaxAxisPoints (a STRING) via a
    base-10 ``int`` in a try/except (NOT base-0, NOT ``isdigit()``): ``'08'`` is a
    valid decimal 8 (base-0 would raise), and ``'9'*5000`` overflows py3.11's
    ``int()`` digit limit and must be caught, not propagated.
    """
    assert _inline_axis_counts([_axis_meta("STD_AXIS", "8")]) == [8]
    assert _inline_axis_counts([_axis_meta("STD_AXIS", "4"), _axis_meta("FIX_AXIS", "5")]) == [4, 5]
    # external axis kind / external flag → None (full-span-or-None external gate)
    assert _inline_axis_counts([_axis_meta("COM_AXIS", "8", external=True)]) is None
    assert _inline_axis_counts([_axis_meta("STD_AXIS", "8", external=True)]) is None
    assert _inline_axis_counts([_axis_meta("RES_AXIS", "8")]) is None
    # leading-zero '08' → 8 (base-10 accepts it; base-0 would RAISE — sec-F2)
    assert _inline_axis_counts([_axis_meta("STD_AXIS", "08")]) == [8]
    # non-numeric / huge-digit / non-positive → None, no exception
    assert _inline_axis_counts([_axis_meta("STD_AXIS", "x")]) is None
    assert _inline_axis_counts([_axis_meta("STD_AXIS", "9" * 5000)]) is None
    assert _inline_axis_counts([_axis_meta("STD_AXIS", "0")]) is None
    assert _inline_axis_counts([_axis_meta("STD_AXIS", None)]) is None
    # empty axis set → None
    assert _inline_axis_counts([]) is None


# ---------------------------------------------------------------------------
# TC-135 — axis-kind census constants + completeness invariant (LLR-P1b.3, C-31).
# ---------------------------------------------------------------------------


def test_tc135_axis_kind_census_completeness() -> None:
    """The census is code-derived (disjoint subsets, union == ALL) and the demo's
    observed kinds are DERIVED FROM THE PARSE (never hand-listed) and ⊆ ALL.

    Intent: C-31 / qa-M2 — a hand-listed ``{STD_AXIS, ...}`` is a vacuous input
    set that cannot notice a 6th kind. Deriving ``observed`` from the parse means
    a new axis kind absent from ``ALL_AXIS_KINDS`` would fail this test.
    """
    assert _DERIVABLE_AXIS_KINDS.isdisjoint(_EXTERNAL_AXIS_KINDS)
    assert ALL_AXIS_KINDS == _DERIVABLE_AXIS_KINDS | _EXTERNAL_AXIS_KINDS
    assert len(_DERIVABLE_AXIS_KINDS) >= 1 and len(_EXTERNAL_AXIS_KINDS) >= 1

    tags = parse_a2l_file(_DEMO_A2L)["tags"]
    observed = {
        am["header_tokens"][0]
        for tag in tags
        for am in tag.get("axis_meta", [])
        if am.get("header_tokens")
    }
    assert observed  # non-empty: the demo genuinely exercises axes
    assert observed <= ALL_AXIS_KINDS


# ---------------------------------------------------------------------------
# TC-136 — post-axis-walk ordering: length derives only from populated axis_meta
#          and never overrides an explicit LENGTH (LLR-P1b.4, R2).
# ---------------------------------------------------------------------------


def test_tc136_post_axis_pass_ordering_and_precedence(tmp_path: Path) -> None:
    """The summer runs AFTER axis_meta is built, and never overrides a non-None length.

    Intent: R2 ordering — ``_inline_axis_counts`` needs the populated
    ``axis_meta`` (built late in the walk), so a CURVE with NO AXIS_DESCR stays
    None (nothing to sum) while one WITH an inline axis derives; and an explicit
    ``LENGTH`` keeps precedence (the ``length is None`` guard).
    """
    layout = ["NO_AXIS_PTS_X 1 UBYTE", "AXIS_PTS_X 2 UBYTE", "FNC_VALUES 3 SWORD"]
    # inline axis present → derives (1 + 4×1 + 4×2 = 13)
    derived = _write_a2l(
        tmp_path, cname="C_D", char_type="CURVE", deposit="RL_D",
        layout_lines=layout, axes=[("STD_AXIS", 4)], name="d.a2l",
    )
    assert derived["length"] == 13
    # no AXIS_DESCR → axis_meta empty → nothing to sum → stays None
    no_axis = _write_a2l(
        tmp_path, cname="C_NA", char_type="CURVE", deposit="RL_NA",
        layout_lines=layout, axes=[], name="na.a2l",
    )
    assert no_axis["axis_meta"] == []
    assert no_axis["length"] is None
    # explicit LENGTH keeps precedence over the summer
    explicit = _write_a2l(
        tmp_path, cname="C_L", char_type="CURVE", deposit="RL_L",
        layout_lines=layout, axes=[("STD_AXIS", 4)],
        extra_char_lines="      LENGTH 999\n", name="l.a2l",
    )
    assert explicit["length"] == 999


# ---------------------------------------------------------------------------
# TC-137 — no-regression: scalar VALUE routes the existing path unchanged
#          (LLR-P1b.5).
# ---------------------------------------------------------------------------


def test_tc137_scalar_value_unchanged(tmp_path: Path) -> None:
    """A scalar VALUE is sized by the existing RECORD_LAYOUT path; the summer is not invoked.

    Intent: the CURVE/MAP gate excludes VALUE, so its length is the pre-existing
    ``_infer_length_characteristic`` value and no axis_meta is required.
    """
    value = _write_a2l(
        tmp_path, cname="V1", char_type="VALUE", deposit="RL_U8",
        layout_lines=["FNC_VALUES 1 UBYTE"], axes=[], name="v.a2l",
    )
    assert value["char_type"] == "VALUE"
    assert value["length"] == 1  # element size from the resolved layout, unchanged


# ---------------------------------------------------------------------------
# TC-138 — DoS clamp is pure arithmetic (LLR-DoS.1); no allocation, no @slow.
# ---------------------------------------------------------------------------


def test_tc138_dos_clamp_pure_arithmetic() -> None:
    """A huge axis count clamps to None via a MAX_A2L_DECODE_BYTES compare, in <1s.

    Intent: LLR-DoS.1 — the summer caps the running total; no ``range``/list is
    materialized. Includes the huge-digit token (sec-F4) which must be caught by
    ``_inline_axis_counts`` before any arithmetic.
    """
    assert MAX_A2L_DECODE_BYTES == 1_048_576
    started = time.perf_counter()
    huge = _record_layout_full_span(
        {"lines": ["AXIS_PTS_X 1 SWORD", "FNC_VALUES 2 SWORD"]}, [10_000_000]
    )
    elapsed = time.perf_counter() - started
    assert huge is None
    assert elapsed < 1.0
    # a span exactly at the cap is admitted; one over is refused
    assert _record_layout_full_span({"lines": ["FNC_VALUES 1 UBYTE"]}, [MAX_A2L_DECODE_BYTES]) == MAX_A2L_DECODE_BYTES
    assert _record_layout_full_span({"lines": ["FNC_VALUES 1 UBYTE"]}, [MAX_A2L_DECODE_BYTES + 1]) is None
    # huge-digit MaxAxisPoints token → None before arithmetic, no exception
    assert _inline_axis_counts([_axis_meta("STD_AXIS", "9" * 5000)]) is None


# ---------------------------------------------------------------------------
# TC-139 — fail-closed: .get() not subscript, len-guard, try/except cast
#          (LLR-P1b.6, sec-F3).
# ---------------------------------------------------------------------------


def test_tc139_fail_closed_no_raises() -> None:
    """Garbage datatype / bad MaxAxisPoints / truncated line degrade to None, never raise.

    Intent: LLR-P1b.6 / sec-F3 — ``DATATYPE_SIZES.get`` (never subscript, which
    would KeyError), a length-guard before ``token[2]``, and the numeric cast as a
    try/except around the real ``int()`` (NOT an ``isdigit()`` pre-predicate:
    ``'08'.isdigit()`` is True yet must parse to 8, while ``'9'*5000`` overflows).
    """
    # unknown datatype token → None, no KeyError
    assert _record_layout_full_span({"lines": ["FNC_VALUES 1 GARBAGE"]}, [4]) is None
    # truncated component line (< 3 tokens) is structural → skipped, not indexed
    assert _record_layout_full_span({"lines": ["FNC_VALUES 1"]}, [4]) is None  # recognised component, datatype token missing → None
    # bad MaxAxisPoints values → None, no exception (base-10 try/except)
    assert _inline_axis_counts([_axis_meta("STD_AXIS", "x")]) is None
    assert _inline_axis_counts([_axis_meta("STD_AXIS", "9" * 5000)]) is None
    assert _inline_axis_counts([_axis_meta("STD_AXIS", "0")]) is None
    # '08' is a valid base-10 decimal (8), NOT a base-0 raise (sec-F2)
    assert _inline_axis_counts([_axis_meta("STD_AXIS", "08")]) == [8]
    # missing header_tokens → None, no IndexError
    assert _inline_axis_counts([{"header_tokens": [], "max_axis_points": "8", "external": False}]) is None


# ---------------------------------------------------------------------------
# AT-104 / AT-105 / AT-106 / AT-107 — demo byte-value oracles through the surface.
# ---------------------------------------------------------------------------


def test_at104_demo_curve_std_axis_length_25() -> None:
    """Demo ASAM.C.CURVE.STD_AXIS → length == 25 (1×UBYTE + 8×SBYTE + 8×SWORD)."""
    assert _demo_char("ASAM.C.CURVE.STD_AXIS")["length"] == 25


def test_at105_demo_map_std_axis_length_51() -> None:
    """Demo ASAM.C.MAP.STD_AXIS.STD_AXIS (axes 4&5) → length == 51 (1+1+4+5 + 4·5·2)."""
    assert _demo_char("ASAM.C.MAP.STD_AXIS.STD_AXIS")["length"] == 51


def test_at106_demo_curve_com_axis_stays_none() -> None:
    """Demo ASAM.C.CURVE.COM_AXIS (external AXIS_PTS_REF) → length is None.

    The false-green anchor: an external axis stores its points in a separate
    AXIS_PTS record, so full-span-or-None keeps it honestly grey.
    """
    assert _demo_char("ASAM.C.CURVE.COM_AXIS")["length"] is None


def test_at107_demo_curve_fix_axis_length_12() -> None:
    """Demo ASAM.C.CURVE.FIX_AXIS.PAR_DIST → length == 12 (FNC_VALUES 6×SWORD).

    The distinct FIX_AXIS layout shape: axis points are NOT stored on-disk, so the
    layout carries FNC_VALUES only (no AXIS_PTS_X line).
    """
    assert _demo_char("ASAM.C.CURVE.FIX_AXIS.PAR_DIST")["length"] == 12


def test_at107b_synthetic_single_line_curve_length_13(tmp_path: Path) -> None:
    """A synthetic CURVE (demo-independent) → length == 13 (1×UBYTE + 4×UBYTE + 4×SWORD).

    Intent: demo-independence — the byte value is hand-computable from the in-test
    layout string, guarding against token[1]/token[2] confusion regardless of the
    demo's line numbers.
    """
    tag = _write_a2l(
        tmp_path, cname="C_SYN", char_type="CURVE", deposit="RL_SYN",
        layout_lines=["NO_AXIS_PTS_X 1 UBYTE", "AXIS_PTS_X 2 UBYTE", "FNC_VALUES 3 SWORD"],
        axes=[("STD_AXIS", 4)],
    )
    assert tag["char_type"] == "CURVE"
    assert tag["length"] == 13


# ---------------------------------------------------------------------------
# AT-108 — output-then-consume (C-12): the derived length flips the view row
#          grey→green through _a2l_tag_row_severity (LLR-P1b.4, qa-M1).
# ---------------------------------------------------------------------------


def test_at108_derived_length_makes_row_memory_checkable() -> None:
    """A covering mem_map + the derived length==25 → row severity OK (memory-checked present).

    Intent: C-12 output-then-consume — parse the demo, build a covering map over
    the CURVE.STD_AXIS 25-byte span, enrich, and assert the row goes OK. The
    counterfactual (length reverted to None) makes the memory check inapplicable
    (``memory_checked=False``) so the row is NOT OK — proving the derived length is
    what enabled the check.

    NOTE (draft-time execution, fail-loud): the requirement's AT-108 counterfactual
    said the reverted row is NEUTRAL; executed, this demo CURVE has a formula
    ``source`` so an un-memory-checkable row lands on INFO, not NEUTRAL. The
    load-bearing fact — ``memory_checked`` flips False and the row is NOT OK — is
    asserted directly rather than pinning the exact non-OK enum.
    """
    a2l_data = parse_a2l_file(_DEMO_A2L)
    curve = next(t for t in a2l_data["tags"] if t["name"] == "ASAM.C.CURVE.STD_AXIS")
    assert curve["length"] == 25
    addr = curve["address"]
    cover = {addr + i: 0 for i in range(25)}

    merged, _ = enrich_tags_and_render(a2l_data, cover)
    row = next(t for t in merged if t["name"] == "ASAM.C.CURVE.STD_AXIS")
    assert row.get("memory_checked") is True
    assert _a2l_tag_row_severity(row, {}) is ValidationSeverity.OK

    # Counterfactual: force the length back to None, re-enrich over the SAME map.
    for t in a2l_data["tags"]:
        if t["name"] == "ASAM.C.CURVE.STD_AXIS":
            t["length"] = None
    merged2, _ = enrich_tags_and_render(a2l_data, cover)
    row2 = next(t for t in merged2 if t["name"] == "ASAM.C.CURVE.STD_AXIS")
    assert row2.get("memory_checked") is False
    assert _a2l_tag_row_severity(row2, {}) is not ValidationSeverity.OK


# ---------------------------------------------------------------------------
# AT-109 — no-regression: scalar VALUE / MEASUREMENT / no-kind / CUBOID untouched.
# ---------------------------------------------------------------------------


def test_at109_no_regression_non_curve_map_untouched(tmp_path: Path) -> None:
    """The summer touches only CURVE/MAP: scalar VALUE, MEASUREMENT, no-kind, CUBOID unchanged.

    Intent: LLR-P1b.5 / arch-MIN2 — the ``char_type in {CURVE,MAP}`` gate excludes
    every other record; the demo CUBOID (the only 3-axis in-family tag) stays None.
    Snapshot drift is asserted only in canonical CI, NOT here.
    """
    # (a) case_01 scalar VALUE length unchanged (derived by the existing path)
    c01 = {t["name"]: t for t in parse_a2l_file(_CASE01_A2L)["tags"]}
    assert c01["CAL_BLOCK_A"]["char_type"] == "VALUE"
    assert c01["CAL_BLOCK_A"]["length"] == 1
    # (b) a demo MEASUREMENT length unchanged
    meas = next(
        t for t in parse_a2l_file(_DEMO_A2L)["tags"]
        if t["name"] == "ASAM.M.SCALAR.UBYTE.IDENTICAL"
    )
    assert meas["length"] == 1
    # (c) a synthetic CHARACTERISTIC whose header anchors no recognised kind →
    #     char_type None (not CURVE/MAP) so the summer is not invoked → length None
    no_kind = _write_a2l(
        tmp_path, cname="C_NK", char_type="NOTAKIND", deposit="RL_NK",
        layout_lines=["FNC_VALUES 1 UBYTE"], axes=[("STD_AXIS", 4)], name="nk.a2l",
    )
    assert no_kind["char_type"] is None
    assert no_kind["length"] is None
    # (d) the demo CUBOID (char_type-gate exclusion) stays None
    assert _demo_char("ASAM.C.CUBOID.COM_AXIS.FIX_AXIS.STD_AXIS")["length"] is None


# ---------------------------------------------------------------------------
# AT-110 — robustness: malformed CURVE parses to grey without aborting the load.
# ---------------------------------------------------------------------------


def test_at110_malformed_curve_fail_closed(tmp_path: Path) -> None:
    """Malformed MaxAxisPoints / datatype through parse_a2l_file → no raise; grey or base-10.

    Intent: LLR-P1b.6 / sec-F2/F3/F4 — the load must complete for every hostile
    input. Non-numeric / huge-digit / bad-datatype → length None; ``'08'`` is a
    valid base-10 decimal (8) so it DERIVES (proving base-10, not a base-0 raise).
    """
    layout = ["NO_AXIS_PTS_X 1 UBYTE", "AXIS_PTS_X 2 UBYTE", "FNC_VALUES 3 SWORD"]
    # (i) non-numeric MaxAxisPoints → None, no exception
    assert _write_a2l(tmp_path, cname="M_X", char_type="CURVE", deposit="RL_X",
                      layout_lines=layout, axes=[("STD_AXIS", "x")], name="mx.a2l")["length"] is None
    # (ii) leading-zero '08' → derives with count 8 (base-10); would RAISE under base-0.
    #      1×UBYTE + 8×UBYTE + 8×SWORD = 25.
    assert _write_a2l(tmp_path, cname="M_08", char_type="CURVE", deposit="RL_08",
                      layout_lines=layout, axes=[("STD_AXIS", "08")], name="m08.a2l")["length"] == 25
    # (iii) huge-digit MaxAxisPoints → None, no exception (py3.11 int() overflow caught)
    assert _write_a2l(tmp_path, cname="M_H", char_type="CURVE", deposit="RL_H",
                      layout_lines=layout, axes=[("STD_AXIS", "9" * 5000)], name="mh.a2l")["length"] is None
    # (iv) a layout with an unknown datatype token → None, no KeyError
    bad_layout = ["NO_AXIS_PTS_X 1 UBYTE", "AXIS_PTS_X 2 UBYTE", "FNC_VALUES 3 NOTADT"]
    assert _write_a2l(tmp_path, cname="M_DT", char_type="CURVE", deposit="RL_DT",
                      layout_lines=bad_layout, axes=[("STD_AXIS", 4)], name="mdt.a2l")["length"] is None


# ---------------------------------------------------------------------------
# AT-111 — DoS: an oversized inline axis clamps to None without runaway (LLR-DoS.1).
# ---------------------------------------------------------------------------


def test_at111_oversized_axis_clamps_to_none(tmp_path: Path) -> None:
    """A CURVE with a ~10M MaxAxisPoints parses fast to length None (clamped by the cap).

    Intent: HLR-DoS — the summer caps the running total against
    ``MAX_A2L_DECODE_BYTES`` via pure arithmetic (no per-byte allocation), so a
    hostile oversized layout renders honest grey rather than driving an unbounded
    span. Completes well under a wall-clock bound (no @slow marker needed).
    """
    layout = ["NO_AXIS_PTS_X 1 UBYTE", "AXIS_PTS_X 2 SWORD", "FNC_VALUES 3 SWORD"]
    started = time.perf_counter()
    tag = _write_a2l(
        tmp_path, cname="C_BIG", char_type="CURVE", deposit="RL_BIG",
        layout_lines=layout, axes=[("STD_AXIS", 10_000_000)], name="big.a2l",
    )
    elapsed = time.perf_counter() - started
    assert tag["length"] is None
    assert elapsed < 2.0
