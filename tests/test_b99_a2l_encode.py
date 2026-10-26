"""Batch-99 HLR-158: A2L values encode and decode as the A2L declares.

TC-B99-23 (LLR-158.1) — the effective byte order falls back tag → RECORD_LAYOUT
→ tag endian → the tag's own MODULE ``MOD_COMMON BYTE_ORDER`` → little, and
BOTH the encode and the decode use it (MSB_FIRST 2-byte: 4113 ↔ ``10 11``; the
``MSB_LAST`` control keeps ``0F 00`` under the MSB_FIRST module). In a
multi-MODULE A2L each module's own ``MOD_COMMON`` applies to its tags
(TC-B99-42).

TC-B99-24 (LLR-158.2) — RAT_FUNC encodes INT = f(PHYS) directly
(``RAT_FUNC_DIV_10``: 30 → raw 300, 25 → raw 250) and decodes by solving
INT = f(PHYS) for PHYS: the root inside the tag's limits when exactly one is,
else the smaller-magnitude root; no real root is a decode failure (``n/a``);
a root where the declared denominator d·P² + e·P + f is zero is spurious and
is rejected (TC-B99-43). LINEAR is unchanged (raw 15 → 30.0, encode 30 →
``0F 00``).

TC-B99-25 (LLR-158.3) — COMPU_TAB inversion refuses a ``TAB_NOINTP`` value
that is not exactly a table value, naming the two nearest (13.0 → 10.0 and
15.0) and a ``TAB_INTP`` value outside the table's physical range, naming the
exact range text (500.0 / −50.0 → ``[0.0, 62.5]``). An in-range
``TAB_INTP`` value is inverse-interpolated between the bracketing entries to
a fractional raw and written as the nearest integer raw: a grid value encodes
with no flag (5.0 → raw 2), an off-grid value flags the physical value that
will actually be written (3.4 → raw 1, flag names 2.5). The sparse corpus
table (raw 0→0.0, 25→10.0, 100→100.0) carries the arms the dense table
cannot see: both endpoints, an interior exact value (40.0 → raw 50, no flag)
and an interior fractional one (3.9 → raw 10, flag names the written 4.0).

AT-B99-09 (US-147) — black-box through the Textual pilot: both files load
through the shipped Load file dialog (``l`` → path → Load), and at 118x40
AND 80x24 the painted screen shows the A2L values — the wide table rows and,
at both widths, the describe-modal lines (``Scalar value: 30.0``,
``Scalar value: 4113``, ``Scalar value: n/a (rat_func_no_real_root)``) —
never a stored table cell.

AT-B99-14 (US-152) — the codec API surface (P-22's declared exception):
``encode_physical_to_raw_bytes`` on the corpus tags returns raw 300 for 30,
``10 11`` for 4113, and an error naming the exact range for 500 on the
``TAB_INTP`` symbol. Only the returned ``(raw_bytes, error, flags)`` is
observed.

Every byte/value oracle below is the committed corpus manifest
(``tests/fixtures/synth/manifest.json`` → ``a2l_expect``), read from disk, or
the independent reader (``tests/support/independent_reader.py``) for image
bytes — never ``s19_app``'s own loader.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from textual.widgets import DataTable

from s19_app.tui.a2l import (
    encode_physical_to_raw_bytes,
    enrich_a2l_tags_with_values,
    parse_a2l_file,
)
from s19_app.tui.app import S19TuiApp
from s19_app.tui.changes.io import emit_s19_from_mem_map
from tests.b97_probes import painted_rows, settle, settled
from tests.support.independent_reader import read_s19

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "tests" / "fixtures" / "synth"

#: The batch-99 pilot sizes: the 118 reference and the 80 narrow floor (UX-C8:
#: the ``n/a`` cell and the modal reason must survive both).
_SIZES = ((118, 40), (80, 24))

#: Injected into the corpus A2L for AT-B99-09: a RAT_FUNC with no real inverse
#: at raw 0 (INT = PHYS² + 1) and a symbol parked outside the image so the
#: blank (no-bytes) limb stays observable next to ``n/a``.
_UNDECODABLE_EXTRA = (
    '    /begin COMPU_METHOD RAT_FUNC_NOROOT "%6.2" RAT_FUNC "%6.2" ""\n'
    "      COEFFS 1 0 1 0 0 1\n"
    "    /end COMPU_METHOD\n"
    '    /begin CHARACTERISTIC NO_ROOT_SYM "no real inverse at raw 0"\n'
    "      VALUE 0x200A RL_U16_NO_BO 0 RAT_FUNC_NOROOT 0 100\n"
    "    /end CHARACTERISTIC\n"
    '    /begin CHARACTERISTIC OUTSIDE_SYM "parked outside the image"\n'
    "      VALUE 0x9000 RL_U16_NO_BO 0 RAT_FUNC_DIV_10 0 100\n"
    "    /end CHARACTERISTIC\n"
)

#: The quadratic-solve fixture for TC-B99-24/27: CM_P2 is INT = PHYS² (raw 16
#: → roots ±4), CM_P2C1 is INT = PHYS² + 1 (raw 0 → no real root) and
#: CM_HOLE is INT = (PHYS² − 4)/(PHYS − 2) — raw 5 solves to P = 2 or P = 3,
#: but P = 2 is a zero of the declared denominator, not of the conversion.
_QUAD_A2L = (
    '/begin PROJECT QUAD "quadratic roots"\n'
    "  /begin MODULE QUAD_MOD\n"
    '    /begin MOD_COMMON ""\n'
    "      BYTE_ORDER MSB_FIRST\n"
    "    /end MOD_COMMON\n"
    "    /begin RECORD_LAYOUT RL_U16\n"
    "      FNC_VALUES 1 UWORD COLUMN_DIR DIRECT\n"
    "    /end RECORD_LAYOUT\n"
    '    /begin COMPU_METHOD CM_P2 "%6.2" RAT_FUNC "%6.2" ""\n'
    "      COEFFS 1 0 0 0 0 1\n"
    "    /end COMPU_METHOD\n"
    '    /begin COMPU_METHOD CM_P2C1 "%6.2" RAT_FUNC "%6.2" ""\n'
    "      COEFFS 1 0 1 0 0 1\n"
    "    /end COMPU_METHOD\n"
    '    /begin COMPU_METHOD CM_HOLE "%6.2" RAT_FUNC "%6.2" ""\n'
    "      COEFFS 1 0 -4 0 1 -2\n"
    "    /end COMPU_METHOD\n"
    '    /begin CHARACTERISTIC QROOT_POS "roots ±4, limits keep +4"\n'
    "      VALUE 0x3000 RL_U16 0 CM_P2 0 100\n"
    "    /end CHARACTERISTIC\n"
    '    /begin CHARACTERISTIC QROOT_NEG "roots ±4, limits keep -4"\n'
    "      VALUE 0x3002 RL_U16 0 CM_P2 -100 -4\n"
    "    /end CHARACTERISTIC\n"
    '    /begin CHARACTERISTIC NOROOT "no real inverse at raw 0"\n'
    "      VALUE 0x3004 RL_U16 0 CM_P2C1 0 100\n"
    "    /end CHARACTERISTIC\n"
    '    /begin CHARACTERISTIC HOLE_SYM "spurious root 2 at zero denominator"\n'
    "      VALUE 0x3006 RL_U16 0 CM_HOLE 0 100\n"
    "    /end CHARACTERISTIC\n"
    "  /end MODULE\n"
    "/end PROJECT\n"
)

#: The two-module fixture for TC-B99-42: each MODULE declares its own
#: MOD_COMMON byte order and holds one UWORD tag with no byte order of its
#: own — module one's is MSB_FIRST, module two's MSB_LAST.
_TWO_MODULE_A2L = (
    '/begin PROJECT TWOMOD "two modules, own byte orders"\n'
    "  /begin MODULE MOD_BIG\n"
    '    /begin MOD_COMMON ""\n'
    "      BYTE_ORDER MSB_FIRST\n"
    "    /end MOD_COMMON\n"
    "    /begin RECORD_LAYOUT RL_U16\n"
    "      FNC_VALUES 1 UWORD COLUMN_DIR DIRECT\n"
    "    /end RECORD_LAYOUT\n"
    '    /begin CHARACTERISTIC BIG_SYM "big-endian module tag"\n'
    "      VALUE 0x4000 RL_U16 0 NO_COMPU_METHOD 0 65535\n"
    "    /end CHARACTERISTIC\n"
    "  /end MODULE\n"
    "  /begin MODULE MOD_LITTLE\n"
    '    /begin MOD_COMMON ""\n'
    "      BYTE_ORDER MSB_LAST\n"
    "    /end MOD_COMMON\n"
    '    /begin CHARACTERISTIC LITTLE_SYM "little-endian module tag"\n'
    "      VALUE 0x4002 RL_U16 0 NO_COMPU_METHOD 0 65535\n"
    "    /end CHARACTERISTIC\n"
    "  /end MODULE\n"
    "/end PROJECT\n"
)


def _manifest_expect() -> dict:
    """The corpus manifest's ``a2l_expect`` block (the pinned oracle)."""
    manifest = json.loads((CORPUS / "manifest.json").read_text(encoding="utf-8"))
    (entry,) = [e for e in manifest["files"] if e["name"] == "synth_a2l.s19"]
    return entry["a2l_expect"]


def _corpus_payload() -> dict:
    return parse_a2l_file(CORPUS / "synth_a2l.a2l")


def _corpus_mem_map() -> dict:
    """The corpus S19 image as an address→byte map via the independent reader."""
    return dict(read_s19(CORPUS / "synth_a2l.s19").data)


def _tags(payload: dict) -> dict:
    return {t["name"]: t for t in payload["tags"]}


def _encode(tag: dict, payload: dict, physical):
    return encode_physical_to_raw_bytes(
        tag,
        physical,
        payload["compu_methods_by_name"],
        payload["compu_tabs_by_name"],
        payload["record_layouts_by_name"],
    )


# --------------------------------------------------------------------------- #
# TC-B99-23 — LLR-158.1: byte-order fallback reads the module's MOD_COMMON
# --------------------------------------------------------------------------- #


def test_tc_b99_23_byte_order_falls_back_to_mod_common() -> None:
    """MSB_FIRST 2-byte: encode 4113 → ``10 11``, decode ``10 11`` → 4113; the
    tag-declared ``MSB_LAST`` keeps ``0F 00`` under the MSB_FIRST module."""
    expect = _manifest_expect()
    assert expect["byte_order"] == "MSB_FIRST"
    payload = _corpus_payload()
    tags = _tags(payload)

    msb = tags["SYM_U16_MSB"]
    assert msb["record_layout_name"] == "RL_U16_NO_BO"  # layout declares none
    assert msb["endian"] is None  # tag declares none
    assert msb["effective_byte_order"] == "big"  # MOD_COMMON MSB_FIRST

    # decode arm: the manifest bytes 10 11 at 0x2000 read as 4113
    msb_expect = expect["symbols"]["SYM_U16_MSB"]
    assert msb_expect["bytes"] == "1011"
    enriched = {
        t["name"]: t
        for t in enrich_a2l_tags_with_values(payload, _corpus_mem_map())
    }
    assert enriched["SYM_U16_MSB"]["raw_value"] == msb_expect["raw"] == 4113
    assert enriched["SYM_U16_MSB"]["physical_value"] == msb_expect["physical"]

    # encode arm: 4113 → 10 11 (the manifest's pinned byte string)
    encoded, error, flags = _encode(msb, payload, 4113)
    assert error is None, error
    assert flags == []
    assert encoded == tuple(bytes.fromhex(msb_expect["encode"][0]["bytes"]))
    assert encoded == (0x10, 0x11)

    # the MSB_LAST control: stays little-endian under the MSB_FIRST module
    lin_expect = expect["symbols"]["LINEAR_MUL_2"]
    assert lin_expect["byte_order"] == "MSB_LAST"
    lin = tags["LINEAR_MUL_2"]
    assert lin["effective_byte_order"] == "little"
    assert enriched["LINEAR_MUL_2"]["physical_value"] == lin_expect["physical"]
    encoded, error, flags = _encode(lin, payload, 30)
    assert error is None, error
    assert flags == []
    assert encoded == tuple(bytes.fromhex(lin_expect["encode"][0]["bytes"]))
    assert encoded == (0x0F, 0x00)


# --------------------------------------------------------------------------- #
# TC-B99-42 — review fix LOW (a): each MODULE's own MOD_COMMON applies
# --------------------------------------------------------------------------- #


def test_tc_b99_42_per_module_mod_common_byte_order(tmp_path: Path) -> None:
    """In a multi-MODULE A2L, module one's MSB_FIRST applies only to its own
    tags and module two's MSB_LAST to its: BIG_SYM encodes 4113 → ``10 11``
    and LITTLE_SYM → ``11 10`` — the first module's byte order must not leak
    across the module boundary."""
    two_path = tmp_path / "two_module.a2l"
    two_path.write_text(_TWO_MODULE_A2L, encoding="utf-8")
    two = parse_a2l_file(two_path)
    tags = _tags(two)

    big = tags["BIG_SYM"]
    little = tags["LITTLE_SYM"]
    assert big["effective_byte_order"] == "big"  # MOD_BIG MOD_COMMON MSB_FIRST
    assert little["effective_byte_order"] == "little"  # MOD_LITTLE MSB_LAST

    encoded, error, flags = _encode(big, two, 4113)
    assert (encoded, error, flags) == ((0x10, 0x11), None, [])
    encoded, error, flags = _encode(little, two, 4113)
    assert (encoded, error, flags) == ((0x11, 0x10), None, [])


# --------------------------------------------------------------------------- #
# TC-B99-24 — LLR-158.2: RAT_FUNC direction and root selection
# --------------------------------------------------------------------------- #


def test_tc_b99_24_rat_func_direction_and_root_selection(tmp_path: Path) -> None:
    """Encode computes INT = f(PHYS) (30 → 300, 25 → 250); decode solves for
    PHYS (raw 300 → 30.0); a quadratic picks the root inside the limits even
    when it is NOT the smaller-magnitude one; no real root is a decode
    failure; LINEAR is unchanged."""
    expect = _manifest_expect()
    payload = _corpus_payload()
    tags = _tags(payload)

    rat = tags["RAT_FUNC_SYM"]
    rat_expect = expect["symbols"]["RAT_FUNC_SYM"]
    for case in rat_expect["encode"]:
        encoded, error, flags = _encode(rat, payload, case["physical"])
        assert error is None, error
        assert flags == []
        assert encoded == tuple(case["raw"].to_bytes(2, "big"))
    assert rat_expect["encode"][0]["raw"] == 300

    enriched = {
        t["name"]: t
        for t in enrich_a2l_tags_with_values(payload, _corpus_mem_map())
    }
    assert enriched["RAT_FUNC_SYM"]["raw_value"] == rat_expect["raw"] == 300
    assert enriched["RAT_FUNC_SYM"]["physical_value"] == rat_expect["physical"] == 30.0
    # LINEAR control unchanged: raw 15 (0F 00, MSB_LAST) → 30.0
    assert enriched["LINEAR_MUL_2"]["physical_value"] == 30.0

    # quadratic root selection and the no-real-root failure
    quad_path = tmp_path / "quad.a2l"
    quad_path.write_text(_QUAD_A2L, encoding="utf-8")
    quad = parse_a2l_file(quad_path)
    # raw 16 big-endian (module MSB_FIRST): 00 10 at every address
    mem_map = {0x3000: 0x00, 0x3001: 0x10, 0x3002: 0x00, 0x3003: 0x10,
               0x3004: 0x00, 0x3005: 0x00, 0x3006: 0x00, 0x3007: 0x05}
    qenr = {t["name"]: t for t in enrich_a2l_tags_with_values(quad, mem_map)}
    assert qenr["QROOT_POS"]["raw_value"] == 16
    assert qenr["QROOT_POS"]["physical_value"] == 4.0  # only +4 inside 0..100
    # limits -100..-4 keep -4: the smaller-magnitude rule would pick +4
    assert qenr["QROOT_NEG"]["physical_value"] == -4.0
    # raw 0 with INT = PHYS² + 1 has no real inverse → decode failure
    noroot = qenr["NOROOT"]
    assert noroot["raw_value"] == 0
    assert noroot["physical_value"] is None
    assert noroot["conversion_status"] == "error"
    assert "no real root" in noroot["conversion_error"]


# --------------------------------------------------------------------------- #
# TC-B99-43 — review fix LOW (b): a RAT_FUNC root at a zero denominator is
# not a root of the declared conversion
# --------------------------------------------------------------------------- #


def test_tc_b99_43_rat_func_zero_denominator_root(tmp_path: Path) -> None:
    """INT = (P² − 4)/(P − 2) at raw 5 multiplies through to P² − 5P + 6 = 0 —
    roots 2 and 3 — but P = 2 zeroes the declared denominator d·P² + e·P + f,
    so it is spurious: the decode must return P = 3.0, not the smaller
    magnitude 2.0; with BOTH candidates spurious the decode fails."""
    quad_path = tmp_path / "quad.a2l"
    quad_path.write_text(_QUAD_A2L, encoding="utf-8")
    quad = parse_a2l_file(quad_path)
    # raw 5 big-endian: 00 05 at 0x3006
    mem_map = {0x3006: 0x00, 0x3007: 0x05}
    qenr = {t["name"]: t for t in enrich_a2l_tags_with_values(quad, mem_map)}
    hole = qenr["HOLE_SYM"]
    assert hole["raw_value"] == 5
    assert hole["physical_value"] == 3.0, (
        "P = 2 zeroes the denominator - the decode must take the other root"
    )
    assert hole["conversion_status"] == "ok"

    # INT = (P² − 4)/(P² − 4) ≡ 1 with the denominator's zeros at P = ±2:
    # raw 5 multiplies through to −4P² + 16 = 0 whose only candidates P = ±2
    # are both denominator zeros → no valid root, a decode failure (n/a).
    pole_path = tmp_path / "pole.a2l"
    pole_path.write_text(
        _QUAD_A2L.replace(
            "      COEFFS 1 0 -4 0 1 -2\n",
            "      COEFFS 1 0 -4 1 0 -4\n",
        ),
        encoding="utf-8",
    )
    pole = parse_a2l_file(pole_path)
    penr = {t["name"]: t for t in enrich_a2l_tags_with_values(pole, mem_map)}
    pole_tag = penr["HOLE_SYM"]
    assert pole_tag["raw_value"] == 5
    assert pole_tag["physical_value"] is None
    assert pole_tag["conversion_status"] == "error"
    assert "denominator" in pole_tag["conversion_error"]


# --------------------------------------------------------------------------- #
# TC-B99-25 — LLR-158.3: COMPU_TAB refusals name values, in-range flags
# --------------------------------------------------------------------------- #


def test_tc_b99_25_compu_tab_refusals_and_flags() -> None:
    """TAB_NOINTP 13.0 is refused naming 10.0 and 15.0; TAB_INTP 500.0 and
    −50.0 are refused naming the exact range text ``[0.0, 62.5]``; 3.4
    encodes raw 1 with a flag naming the written 2.5; 5.0 encodes raw 2 with
    no flag. On the sparse table the encode inverse-interpolates: both
    endpoints encode exactly, 40.0 → raw 50 with no flag, and 3.9 → raw 10
    with a flag naming the written 4.0."""
    expect = _manifest_expect()
    payload = _corpus_payload()
    tags = _tags(payload)

    # --- TAB_NOINTP ---------------------------------------------------------
    nointp_expect = expect["symbols"]["TAB_NOINTP_SYM"]
    assert nointp_expect["typed_refused"] == 13.0
    assert nointp_expect["named_nearest"] == [10.0, 15.0]
    nointp = tags["TAB_NOINTP_SYM"]
    for raw_x, table_y in ((0, 10.0), (1, 15.0), (2, 20.0)):
        encoded, error, flags = _encode(nointp, payload, table_y)
        assert error is None, f"{table_y} is a table value: {error}"
        assert flags == []
        assert encoded == (0x00, raw_x)
    encoded, error, flags = _encode(nointp, payload, 13.0)
    assert encoded is None
    assert flags == []
    assert error is not None
    assert "the nearest table values are 10.0 and 15.0" in error  # exact text

    # --- TAB_INTP (dense table) ----------------------------------------------
    intp_expect = expect["symbols"]["TAB_INTP_SYM"]
    assert intp_expect["refused"] == [-50.0, 500.0]
    intp = tags["TAB_INTP_SYM"]
    grid = intp_expect["grid"]
    assert grid == {"typed": 5.0, "expected_raw": 2, "written_physical": 5.0}
    encoded, error, flags = _encode(intp, payload, 5.0)
    assert error is None, error
    assert encoded == (0x00, 0x02)
    assert flags == []  # grid value: no flag

    off = intp_expect["off_grid"]
    assert off == {"typed": 3.4, "expected_raw": 1, "written_physical": 2.5,
                   "flag_names": "2.5"}
    encoded, error, flags = _encode(intp, payload, 3.4)
    assert error is None, error
    assert encoded == (0x00, 0x01)
    assert len(flags) == 1
    assert "2.5" in flags[0]  # the written physical value, by content
    assert "3.4" in flags[0]  # the typed value, by content

    for refused in intp_expect["refused"]:
        encoded, error, flags = _encode(intp, payload, refused)
        assert encoded is None
        assert flags == []
        assert error is not None
        assert "[0.0, 62.5]" in error  # the exact range text

    # --- TAB_INTP (sparse table: inverse interpolation between brackets) ----
    sparse_expect = expect["symbols"]["TAB_INTP_SPARSE_SYM"]
    sparse = tags["TAB_INTP_SPARSE_SYM"]
    enriched = {
        t["name"]: t
        for t in enrich_a2l_tags_with_values(payload, _corpus_mem_map())
    }
    decoded = enriched["TAB_INTP_SPARSE_SYM"]
    assert decoded["raw_value"] == sparse_expect["raw"] == 50
    assert decoded["physical_value"] == sparse_expect["physical"] == 40.0

    for arm in sparse_expect["endpoints"]:
        encoded, error, flags = _encode(sparse, payload, arm["typed"])
        assert error is None, error
        assert flags == []
        assert encoded == (0x00, arm["expected_raw"])
    exact = sparse_expect["interior_exact"]
    encoded, error, flags = _encode(sparse, payload, exact["typed"])
    assert (encoded, error, flags) == ((0x00, exact["expected_raw"]), None, [])
    frac = sparse_expect["interior_fractional"]
    encoded, error, flags = _encode(sparse, payload, frac["typed"])
    assert error is None, error
    assert encoded == (0x00, frac["expected_raw"])
    assert len(flags) == 1
    assert frac["flag_names"] in flags[0]  # the written value, by content
    assert str(frac["typed"]) in flags[0]  # the typed value, by content
    for refused in sparse_expect["refused"]:
        encoded, error, flags = _encode(sparse, payload, refused)
        assert encoded is None
        assert flags == []
        assert "[0.0, 100.0]" in error  # the exact range text


# --------------------------------------------------------------------------- #
# AT-B99-14 — US-152: the codec API surface
# --------------------------------------------------------------------------- #


def test_at_b99_14_codec_api_encode_surface() -> None:
    """The codec API (P-22's declared exception) returns raw 300 for 30 on the
    RAT_FUNC symbol, ``10 11`` for 4113 on the MSB symbol, and an error naming
    the exact range for 500 on the TAB_INTP symbol — only ``(raw_bytes, error,
    flags)`` is observed."""
    expect = _manifest_expect()
    payload = _corpus_payload()
    tags = _tags(payload)

    raw_bytes, error, flags = _encode(tags["RAT_FUNC_SYM"], payload, 30)
    assert raw_bytes == (0x01, 0x2C)  # raw 300, MSB_FIRST
    assert error is None
    assert flags == []

    msb_expect = expect["symbols"]["SYM_U16_MSB"]
    raw_bytes, error, flags = _encode(tags["SYM_U16_MSB"], payload, 4113)
    assert raw_bytes == tuple(bytes.fromhex(msb_expect["encode"][0]["bytes"]))
    assert error is None
    assert flags == []

    raw_bytes, error, flags = _encode(tags["TAB_INTP_SYM"], payload, 500)
    assert raw_bytes is None
    assert error is not None
    assert "[0.0, 62.5]" in error
    assert flags == []


# --------------------------------------------------------------------------- #
# AT-B99-09 — US-147: the A2L window's values paint, black-box (pilot)
# --------------------------------------------------------------------------- #


def _undecodable_pair(tmp_path: Path) -> tuple[Path, Path]:
    """The corpus A2L + S19 with one no-real-root symbol injected (in-image)
    and one symbol parked outside the image (no bytes → blank cell)."""
    a2l_text = (CORPUS / "synth_a2l.a2l").read_text(encoding="utf-8")
    anchor = "    /begin GROUP GRP_SYNTH_B99"
    assert anchor in a2l_text
    a2l_text = a2l_text.replace(anchor, _UNDECODABLE_EXTRA + anchor)
    a2l_path = tmp_path / "case.a2l"
    a2l_path.write_text(a2l_text, encoding="utf-8")
    mem_map = {0x2000 + i: b for i, b in enumerate(bytes.fromhex("1011012C000200010F0000000032"))}
    s19_path = tmp_path / "case.s19"
    s19_path.write_text(
        emit_s19_from_mem_map(mem_map, [(0x2000, 0x200E)]), encoding="ascii"
    )
    return s19_path, a2l_path


def _screen_text(app) -> str:
    """The current screen's painted text, one strip per row."""
    strips = app.screen._compositor.render_strips()
    return "\n".join("".join(segment.text for segment in strip) for strip in strips)


def _status_text(app) -> str:
    """The painted newest status line (the ``#log_line_4`` label)."""
    from textual.widgets import Label

    return str(app.query_one("#log_line_4", Label).render())


async def _load_through_dialog(app, pilot, path: Path, description: str) -> None:
    """Load ``path`` through the shipped Load file dialog: ``l``, click the
    ``#load_path`` input and TYPE the path, click ``#load_ok`` — the same
    controls a user drives — and wait on the painted newest log line
    (``#log_line_4`` naming the file), never an internal attribute."""
    await settle(pilot)
    await pilot.press("l")
    for _ in range(6):
        await pilot.pause()
    assert await pilot.click("#load_path"), "click missed #load_path"
    await pilot.press(*str(path))
    assert await pilot.click("#load_ok"), "click missed #load_ok"
    await settled(
        pilot,
        lambda: (
            f"Loaded {path.name}" in _status_text(app)
            or f"A2L loaded: {path.name}" in _status_text(app)
        ),
        description,
        attempts=200,
    )


async def _run_at_09(s19_path: Path, a2l_path: Path, size: tuple[int, int]) -> None:
    app = S19TuiApp(base_dir=s19_path.parent)
    async with app.run_test(size=size) as pilot:
        await pilot.pause()
        await _load_through_dialog(
            app, pilot, s19_path, "the S19 image loaded (log names case.s19)"
        )
        await _load_through_dialog(
            app, pilot, a2l_path, "the A2L loaded (log names case.a2l)"
        )
        await pilot.press("escape")
        await pilot.pause()
        await pilot.press("2")
        await settled(
            pilot,
            lambda: "A2L Explorer" in _screen_text(app),
            "the A2L screen paints",
        )

        # The painted arms differ by width; the describe-modal arms (below)
        # run at BOTH widths.
        if size[0] >= 118:
            table = app.query_one("#a2l_tags_list", DataTable)
            rows = painted_rows(app, table)
            rat_row = next(r for r in rows if "RAT_FUNC_SYM" in r)
            assert "30.0" in rat_row, f"RAT_FUNC_SYM row at {size}: {rat_row!r}"
            msb_row = next(r for r in rows if "SYM_U16_MSB" in r)
            # IDENTICAL passes the raw int through: "4113" paints in BOTH the
            # Raw and the Physical cell
            assert msb_row.count("4113") >= 2, f"SYM_U16_MSB row at {size}: {msb_row!r}"
            sparse_row = next(r for r in rows if "TAB_INTP_SPARSE_SYM" in r)
            assert "40.0" in sparse_row, f"TAB_INTP_SPARSE_SYM row at {size}: {sparse_row!r}"
            noroot_row = next(r for r in rows if "NO_ROOT_SYM" in r)
            assert "n/a" in noroot_row, f"NO_ROOT_SYM row at {size}: {noroot_row!r}"
            outside_row = next(r for r in rows if "OUTSIDE_SYM" in r)
            assert "n/a" not in outside_row, f"OUTSIDE_SYM row at {size}: {outside_row!r}"

        # UX-C8 (modal) at BOTH widths: the values paint through the describe
        # modal, never a stored table cell. Row order follows the corpus A2L
        # document order: the injected NO_ROOT_SYM lands after the six corpus
        # symbols, at row 6.
        table = app.query_one("#a2l_tags_list", DataTable)
        table.focus()
        await pilot.pause()
        cursor = 0
        for target, name, expected in (
            (0, "SYM_U16_MSB", "Scalar value: 4113"),
            # the modal formats a whole physical tight: "30" (the table cell
            # shows "30.0"; both paint)
            (1, "RAT_FUNC_SYM", "Scalar value: 30 "),
            (6, "NO_ROOT_SYM", "Scalar value: n/a (rat_func_no_real_root)"),
        ):
            while cursor < target:
                await pilot.press("down")
                await pilot.pause()
                cursor += 1
            if size[0] < 118:
                # the narrow list paints the selected tag itself
                assert name in _screen_text(app), (
                    f"{name} does not paint at {size}: {_screen_text(app)!r}"
                )
            await pilot.press("d")
            await settled(
                pilot,
                lambda: "Scalar value" in _screen_text(app),
                f"the describe modal paints for {name}",
            )
            painted = _screen_text(app)
            assert expected in painted, f"{name} at {size}: {expected!r} not in {painted!r}"
            await pilot.press("escape")
            await settled(
                pilot,
                lambda: "Scalar value" not in _screen_text(app),
                f"the describe modal dismissed for {name}",
            )


def test_at_b99_09_a2l_window_physical_column(tmp_path: Path) -> None:
    """AT-B99-09 (US-147): through the shipped Load dialog, the A2L window
    paints 30.0 for RAT_FUNC_SYM and 4113 for SYM_U16_MSB, ``40.0`` for the
    sparse-table symbol and ``n/a`` for the undecodable symbol — distinct from
    the blank cell of the no-bytes symbol — and the describe modal reads
    ``Scalar value: n/a (rat_func_no_real_root)``: at 118x40 AND 80x24, all
    from painted screen text (no clipping at either width)."""
    s19_path, a2l_path = _undecodable_pair(tmp_path)
    for size in _SIZES:
        asyncio.run(_run_at_09(s19_path, a2l_path, size))
