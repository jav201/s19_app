"""Batch-103 Inc 11 E5 — coverage completion for the reader audit.

This module discharges the 27 *missing* and 109 *partial* requirement cases of
``inc-11/E5-coverage-audit.md`` (136 case ids), plus the READ.52 protocol that
the audit flags. It never edits product code, ``tests/test_b103_a2l_reader.py``
or ``tests/test_b103_a2l_reader_e5.py``; it reuses their fixture builders and
helpers instead of duplicating them. The two real-app acceptance tests stay
unchanged and full.

Every case id maps to one or more test nodes below; the exact mapping is in
``inc-11/evidence-e5/coverage-completion-report.md``.
"""

from __future__ import annotations

import ast
import random
from pathlib import Path
from typing import Callable, List, Optional, Tuple

import pytest

from s19_app.tui.a2l import (
    build_section_tree,
    encode_physical_to_raw_bytes,
    enrich_a2l_tags_with_values,
    parse_a2l_file,
    parse_begin_meta,
    render_a2l_view,
)
from s19_app.tui.a2l_definition import describe_definition
from s19_app.validation.rules import validate_a2l_structure

from tests.test_b103_a2l_reader import (
    FULL,
    HDR,
    TAIL,
    REPO_ROOT,
    REF_MODULE,
    _assert_errors_equal,
    _assert_sections_equal,
    _assert_spans_equal,
    _assert_tags_equal,
    _body,
    _parse,
    _section_of,
    _six_fields,
    _spans,
    _tag,
    _tags_named,
    _tracked_a2l,
    char,
    meas,
)


# ---------------------------------------------------------------------------
# Reference oracle + static guard (E3A-08), reused per-module.
# ---------------------------------------------------------------------------

_REF_READ: Optional[Callable[[str], dict]] = None


def _ref_read() -> Callable[[str], dict]:
    """Import the independent oracle once and run its static guard once."""
    global _REF_READ
    if _REF_READ is not None:
        return _REF_READ
    import importlib.util

    ref_path = REF_MODULE
    a2l_path = REPO_ROOT / "s19_app" / "tui" / "a2l.py"
    ref_text = ref_path.read_text(encoding="utf-8")
    a2l_text = a2l_path.read_text(encoding="utf-8")
    tree = ast.parse(ref_text)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert not alias.name.startswith("s19_app"), alias.name
        if isinstance(node, ast.ImportFrom):
            assert not (node.module or "").startswith("s19_app"), node.module
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in ("compile", "match", "search", "finditer", "fullmatch", "sub"), node.func.attr
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and len(node.value) > 40:
            assert node.value not in a2l_text, f"REF string shared with a2l.py: {node.value[:40]!r}"
    spec = importlib.util.spec_from_file_location("b103_a2l_ref_cov", ref_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _REF_READ = module.ref_read_a2l
    return _REF_READ


def _line_of(text: str, needle: str) -> int:
    """1-based line number of the first line containing ``needle``."""
    for i, ln in enumerate(text.split("\n"), 1):
        if needle in ln:
            return i
    raise AssertionError(f"{needle!r} not found")


def _sections(data: dict, kind: str) -> List[dict]:
    """Return every section of ``kind``, including nested sections."""
    found: List[dict] = []

    def walk(items: List[dict]) -> None:
        for section in items:
            if section.get("name") == kind:
                found.append(section)
            walk(section.get("children") or [])

    walk(data["sections"])
    return found


def _assert_same_section_tree(left: List[dict], right: List[dict], context: tuple) -> None:
    """Assert equal section trees and identify any differing scalar field."""
    assert len(left) == len(right), context
    for index, (sec, bsec) in enumerate(zip(left, right)):
        route = context + (index,)
        differing = {
            key: (value, bsec.get(key))
            for key, value in sec.items()
            if key != "children" and value != bsec.get(key)
        }
        assert not differing, (route, differing)
        _assert_same_section_tree(sec["children"], bsec["children"], route)


# ===========================================================================
# A. Line ends, blanks, encodings.
# ===========================================================================


def test_cov_read_1_line_end_variants_equal_lf(tmp_path: Path) -> None:
    """R-A2L-READ.1/1..3: tags, sections (line numbers included) and errors
    equal the LF reading, not just the six tag fields."""
    for path in _tracked_a2l():
        text = path.read_text(encoding="utf-8", errors="replace")
        base = _parse(tmp_path, text, name="lf.a2l")
        for variant in ("crlf", "cr", "mixed"):
            if variant == "crlf":
                body = text.replace("\n", "\r\n")
            elif variant == "cr":
                body = text.replace("\n", "\r")
            else:
                parts = text.split("\n")
                mixed = []
                for i, line in enumerate(parts):
                    mixed.append(line)
                    if i + 1 < len(parts):
                        mixed.append("\r" if not line else ("\r\n", "\r", "\n")[i % 3])
                body = "".join(mixed)
            data = _parse(tmp_path, body, name="line.a2l")
            _assert_same_section_tree(data["sections"], base["sections"], (str(path), variant))
            assert data["tags"] == base["tags"], (path, variant)
            assert data["errors"] == base["errors"], (path, variant)


def test_cov_read_1_cr_cr_lf_full_equality(tmp_path: Path) -> None:
    """R-A2L-READ.1/4: every tag and error equal the LF reading, and every
    section line is 2*k-1 of the LF file's line."""
    text = _body(meas("X", " ECU_ADDRESS 0x1234"))
    base = _parse(tmp_path, text)
    data = _parse(tmp_path, text.replace("\n", "\r\r\n"))
    assert data["errors"] == base["errors"]
    assert data["tags"] == base["tags"]
    assert len(data["sections"]) == len(base["sections"])
    pairs = list(zip(data["sections"], base["sections"]))
    while pairs:
        sec, bsec = pairs.pop()
        assert sec["name"] == bsec["name"] and sec["meta"] == bsec["meta"]
        assert sec["start_line"] == 2 * bsec["start_line"] - 1
        assert sec["end_line"] == 2 * bsec["end_line"] - 1
        assert sec["lines"] == bsec["lines"]
        assert sec["line_numbers"] == [2 * n - 1 for n in bsec["line_numbers"]]
        assert len(sec["children"]) == len(bsec["children"])
        pairs.extend(zip(sec["children"], bsec["children"]))


@pytest.mark.parametrize(
    ("ch", "code"),
    [
        ("\u00a0", "00A0"), ("\u0085", "0085"), ("\u2028", "2028"), ("\u2029", "2029"),
        ("\u001c", "001C"), ("\u001e", "001E"), ("\ufeff", "FEFF"), ("\u200b", "200B"),
    ],
)
def test_cov_read_4_unexpected_character_exact(tmp_path: Path, ch: str, code: str) -> None:
    """R-A2L-READ.4/1: exactly one error on line 20 per character."""
    text = ("\n" * 19) + f"ECU_ADDRESS 0x1234{ch}\n"
    data = _parse(tmp_path, text)
    assert data["errors"] == [f"Line 20: unexpected character U+{code}"]


def test_cov_read_4_comment_string_zero_errors(tmp_path: Path) -> None:
    """R-A2L-READ.4/2: a comment/string character gives exactly zero errors."""
    text = _body(meas("X", " /* \u00b0 \u00b5 */", ' PHYS_UNIT "\u00b0C"', " ECU_ADDRESS 0x1234"))
    assert _parse(tmp_path, text)["errors"] == []


def test_cov_read_4_latin1_fffd_exact(tmp_path: Path) -> None:
    """R-A2L-READ.4/4: the Latin-1 0xB0 in a name word gives exactly one
    ``Line <n>: unexpected character U+FFFD``; the comment and the long
    identifier give none; XL1's long identifier reads ``Temp <U+FFFD>C``."""
    raw = (
        "/* 20 \u00b0C */\n"
        + meas("XL1", " ECU_ADDRESS 0x70", longid='"Temp \u00b0C"')
        + "\n"
        + meas("XL1_\u00b0", " ECU_ADDRESS 0x72")
    ).encode("latin-1")
    data = _parse(tmp_path, raw=raw)
    errs = [e for e in data["errors"] if "unexpected character U+FFFD" in e]
    assert len(errs) == 1
    name_line = _line_of(raw.decode("latin-1"), "XL1_")
    assert errs[0] == f"Line {name_line}: unexpected character U+FFFD"
    xl1 = _tag(data, "XL1")
    assert xl1["description"] == "Temp \ufffdC"


@pytest.mark.parametrize(
    ("ch", "code"),
    [
        ("\u00a0", "00A0"), ("\u0085", "0085"), ("\u2028", "2028"), ("\u2029", "2029"),
        ("\u001c", "001C"), ("\u001e", "001E"), ("\ufeff", "FEFF"), ("\u200b", "200B"),
    ],
)
def test_cov_read_4_after_address_length_matrix_exact(tmp_path: Path, ch: str, code: str) -> None:
    """R-A2L-READ.4/5: exactly one unexpected-character diagnostic per object,
    on line 20 for the header address and line 23 for LENGTH/MATRIX_DIM."""
    shapes = (
        (f'/begin CHARACTERISTIC CX "" VALUE 0x2000{ch} RL_U16 0 CM_ID 0 65535\n/end CHARACTERISTIC', 20),
        (meas("X", " ECU_ADDRESS 0x10", f" LENGTH 4{ch}"), 23),
        (meas("Y", " ECU_ADDRESS 0x10", f" MATRIX_DIM 4{ch}"), 23),
    )
    for shape, line in shapes:
        data = _parse(tmp_path, _body(shape))
        errs = [e for e in data["errors"] if "unexpected character" in e]
        assert errs == [f"Line {line}: unexpected character U+{code}"], data["errors"]


def test_cov_read_4_quoted_name_esc_exact(tmp_path: Path) -> None:
    """R-A2L-READ.4/6: exactly one ``Line 20: unexpected character U+001B``."""
    text = _body('/begin MEASUREMENT "Torque\x1bMax" ""\n UWORD CM_ID 0 0 0 65535\n ECU_ADDRESS 0x10\n/end MEASUREMENT')
    data = _parse(tmp_path, text)
    assert data["errors"] == ["Line 20: unexpected character U+001B"]


def test_cov_read_5_bom_before_version_equality(tmp_path: Path) -> None:
    """R-A2L-READ.5/1: the BOM reading equals the no-BOM reading on tags,
    sections and errors."""
    body = _body(meas("X", " ECU_ADDRESS 0x1234"))
    base = _parse(tmp_path, body)
    data = _parse(tmp_path, "\ufeff" + body)
    _assert_sections_equal(data["sections"], base["sections"])
    assert data["tags"] == base["tags"]
    assert data["errors"] == base["errors"]


def test_cov_read_5_bom_before_project_section(tmp_path: Path) -> None:
    """R-A2L-READ.5/2: a BOM before /begin PROJECT leaves PROJECT a section."""
    text = _body(meas("X", " ECU_ADDRESS 0x1234")).split("\n", 1)[1]
    data = _parse(tmp_path, "\ufeff" + text)
    assert data["errors"] == []
    assert any(s["name"] == "PROJECT" for s in data["sections"])
    assert _tag(data, "X")["address"] == 0x1234


def test_cov_read_55_zero_sections_and_tags(tmp_path: Path) -> None:
    """R-A2L-READ.55/2, /3, /4: the NUL / binary refusals also leave zero
    sections and zero tags."""
    rng = random.Random(1103)
    raw = bytes(rng.randrange(1, 256) for _ in range(5 * 1024 * 1024))
    raw = raw[:100] + b"\x00" + raw[101:]
    data = _parse(tmp_path, raw=raw)
    assert data["errors"] == ["File is not UTF-8 text; save it as UTF-8 and load it again."]
    assert data["sections"] == [] and data["tags"] == []

    data2 = _parse(tmp_path, _body(meas("X", " ECU_ADDRESS 0x1234\x00")))
    assert data2["errors"] == ["File is not UTF-8 text; save it as UTF-8 and load it again."]
    assert data2["sections"] == [] and data2["tags"] == []

    data3 = _parse(tmp_path, _body(meas("X", " /* a\x00b */", " ECU_ADDRESS 0x10")))
    assert data3["errors"] == ["File is not UTF-8 text; save it as UTF-8 and load it again."]
    assert data3["sections"] == [] and data3["tags"] == []


@pytest.mark.parametrize("nl", ["\r\n", "\r"])
def test_cov_read_9_lone_line_end_terminator(tmp_path: Path, nl: str) -> None:
    """R-A2L-READ.9/2, /3: a line comment is ended by a lone CRLF / CR, not
    converted into CR-CR-LF first."""
    # Build the file with regular LF everywhere except the single comment
    # terminator, which is the isolated ``nl`` under test (never CR-CR-LF).
    text = _body(meas("X", " // c", " ECU_ADDRESS 0x1234")).replace(" // c\n", f" // c{nl}")
    data = _parse(tmp_path, text)
    assert _tag(data, "X")["address"] == 0x1234


# ===========================================================================
# B. Comments.
# ===========================================================================


def test_cov_001_2_matrix_dim_comment_not_read(tmp_path: Path) -> None:
    """R-A2L-001.2/3: a commented MATRIX_DIM is not read (MATRIX_DIM 4)."""
    text = _body(meas("X", " ECU_ADDRESS 0x1234", " MATRIX_DIM 4", " /*", " MATRIX_DIM 1", " */"))
    t = _tag(_parse(tmp_path, text), "X")
    assert t["matrix_dim"] == 4 and t["length"] == 8


def test_cov_read_7_comment_between_digits_separate_word(tmp_path: Path) -> None:
    """R-A2L-READ.7/1: ``4026`` lands as its own header word (the deposit),
    proving the comment split the address from the trailing digits."""
    text = _body(
        '/begin CHARACTERISTIC Synthetic ""\n MAP 0x1C2D3E00/*c*/4026 RL_SYN_U16 0 CM_ID 0 65535\n/end CHARACTERISTIC\n'
        "/begin RECORD_LAYOUT RL_SYN_U16\nFNC_VALUES 1 UWORD ROW_DIR DIRECT\n/end RECORD_LAYOUT\n"
    )
    tag = _tag(_parse(tmp_path, text), "Synthetic", "CHARACTERISTIC")
    assert tag["address"] == 0x1C2D3E00
    assert tag["deposit"] == "4026"


def test_cov_read_7_multiline_comment_glued_both_sides(tmp_path: Path) -> None:
    """R-A2L-READ.7/2 (H2b): a multi-line comment glued on both sides of the
    address splits it — the digits after ``*/`` are not part of the address."""
    head = (
        "ASAP2_VERSION 1 71\n/begin PROJECT PSYN \"\"\n/begin MODULE MSYN \"\"\n"
        "/begin COMPU_METHOD CM_SYN \"\" IDENTICAL \"%.0\" \"rpm\"\n/end COMPU_METHOD\n"
        "/begin RECORD_LAYOUT RL_SYN_U16\nFNC_VALUES 1 UWORD COLUMN_DIR DIRECT\n/end RECORD_LAYOUT\n"
    )
    body = (
        '/begin CHARACTERISTIC "Synthetic map"\n'
        "  MAP 0x1C2D3E00/* moved\n  */4026 RL_SYN_U16 4095 CM_SYN 0 4095\n"
        "  /begin AXIS_DESCR\n    FIX_AXIS NO_INPUT_QUANTITY CM_SYN 33 0 32\n    FIX_AXIS_PAR 0 1 33\n  /end AXIS_DESCR\n"
        "  /begin AXIS_DESCR\n    FIX_AXIS NO_INPUT_QUANTITY CM_SYN 61 0 60\n    FIX_AXIS_PAR 0 1 61\n  /end AXIS_DESCR\n"
        "/end CHARACTERISTIC\n/end MODULE\n/end PROJECT\n"
    )
    tag = _tag(_parse(tmp_path, head + body), "Synthetic map", "CHARACTERISTIC")
    assert tag["address"] == 0x1C2D3E00


def test_cov_read_7_keyword_glued_comment_upper_limit(tmp_path: Path) -> None:
    """R-A2L-READ.7/6: a header word glued to a comment and a keyword splits —
    upper limit 65535 AND the BIT_MASK word 0x0FF0."""
    text = _body(meas("X", " ECU_ADDRESS 0x10", hdr=" UWORD CM_ID 0 0 0 65535/* upper */BIT_MASK 0x0FF0"))
    t = _tag(_parse(tmp_path, text), "X")
    assert t["upper_limit"] == "65535"
    assert t["bit_org"] == "0x0FF0"


def test_cov_read_8_comments_do_not_nest_word_c(tmp_path: Path) -> None:
    """R-A2L-READ.8/2 (RP-B40): ``c`` is an own word of X and the stray ``*/``
    gives the .11 error."""
    text = _body(meas("X", " /* a /* b */ c */", " ECU_ADDRESS 0x1234"))
    data = _parse(tmp_path, text)
    assert _tag(data, "X")["address"] == 0x1234
    assert any("*/ without /*" in e for e in data["errors"])
    sec = _sections(data, "MEASUREMENT")[0]
    flat = [w for w, _ in _iter_section_words(sec)]
    assert "c" in flat


def _iter_section_words(section: dict):
    """Yield (word, line) of a section's own words (meta + lines)."""
    from s19_app.tui.a2l import _section_words
    return _section_words(section)


def test_cov_read_10_comment_not_closed_line_20(tmp_path: Path) -> None:
    """R-A2L-READ.10/1: ``Line 20: comment not closed`` and no tag X."""
    text = ("\n" * 19) + "/* never closed\n" + meas("X", " ECU_ADDRESS 0x1234")
    data = _parse(tmp_path, text)
    assert "Line 20: comment not closed" in data["errors"]
    assert _tags_named(data, "X") == []


def test_cov_read_11_stray_close_line_20(tmp_path: Path) -> None:
    """R-A2L-READ.11/1: ``Line 20: */ without /*``."""
    text = ("\n" * 19) + "*/\n"
    assert "Line 20: */ without /*" in _parse(tmp_path, text)["errors"]


def test_cov_read_11_nested_stray_close_line_22(tmp_path: Path) -> None:
    """R-A2L-READ.11/2 (RP-B40): ``Line 22: */ without /*``."""
    text = _body(meas("X", " /* a /* b */ c */", " ECU_ADDRESS 0x1234"))
    data = _parse(tmp_path, text)
    assert "Line 22: */ without /*" in data["errors"]


# ===========================================================================
# C. Quoted strings.
# ===========================================================================


def test_cov_001_3_2_escape_long_identifier(tmp_path: Path) -> None:
    """R-A2L-001.3.2/1: ``C:\\`` ends the string; long identifier ``C:\\`` and
    address 0x2000."""
    text = _body('/begin CHARACTERISTIC X "C:\\\\"\n VALUE 0x2000 RL_U16 0 CM_ID 0 65535\n/end CHARACTERISTIC')
    t = _tag(_parse(tmp_path, text), "X", "CHARACTERISTIC")
    assert t["address"] == 0x2000
    assert t["description"] == "C:\\\\"


def test_cov_001_3_2_backslash_line_end_exact(tmp_path: Path) -> None:
    """R-A2L-001.3.2/4: the standalone three-line shape closes its string on
    line 2; the stray ``/end X`` on line 3 gives ``Line 3: /end without
    /begin``."""
    text = '"a\\\n"\n/end X\n'
    data = _parse(tmp_path, text)
    assert "Line 3: /end without /begin" in data["errors"]


def test_cov_read_13_multiline_string_end_closes_nothing(tmp_path: Path) -> None:
    """R-A2L-READ.13/4 (L7): a /end inside a multi-line string closes nothing;
    X's BIT_MASK word 0x0FF0; X ends at its own /end (no stray tag)."""
    text = _body(
        meas(
            "SX",
            " ECU_ADDRESS 0x10",
            " /begin ANNOTATION",
            "  /begin ANNOTATION_TEXT",
            '   "see:',
            "/end ANNOTATION_TEXT",
            "/end ANNOTATION",
            '/end MEASUREMENT"',
            "  /end ANNOTATION_TEXT",
            " /end ANNOTATION",
            " BIT_MASK 0x0FF0",
        )
    )
    data = _parse(tmp_path, text)
    t = _tag(data, "SX")
    assert t["bit_org"] == "0x0FF0"
    assert len(_tags_named(data, "SX")) == 1


def test_cov_read_13_exactly_one_tag(tmp_path: Path) -> None:
    """R-A2L-READ.13/3: exactly one tag; no tag Q."""
    text = _body(meas("X", ' PHYS_UNIT "/begin MEASUREMENT Q"', " ECU_ADDRESS 0x1234"))
    data = _parse(tmp_path, text)
    assert len(data["tags"]) == 1
    assert _tags_named(data, "Q") == []


def test_cov_read_14_multiline_string_one_word(tmp_path: Path) -> None:
    """R-A2L-READ.14/1: an ANNOTATION_TEXT string over two line ends is one
    word and the object's later BIT_MASK is read."""
    text = _body(
        meas(
            "X",
            " ECU_ADDRESS 0x10",
            " /begin ANNOTATION",
            " /begin ANNOTATION_TEXT",
            ' "a\nb\nc"',
            " /end ANNOTATION_TEXT",
            " /end ANNOTATION",
            " BIT_MASK 0x0FF0",
        )
    )
    data = _parse(tmp_path, text)
    assert _tag(data, "X")["bit_org"] == "0x0FF0"
    ann = _sections(data, "ANNOTATION_TEXT")[0]
    words = [w for w, _ in _iter_section_words(ann)]
    assert '"a\nb\nc"' in words
    assert "a" not in words and "b" not in words and "c" not in words


def test_cov_read_14_words_after_close_carry_end_line(tmp_path: Path) -> None:
    """R-A2L-READ.14/2: X's end_line is 5; the U+00E9 error names Line 5."""
    text = (
        '/begin MEASUREMENT X ""\n UWORD CM_ID 0 0 0 65535\n ECU_ADDRESS 0x10\n'
        ' FORMAT "a\nb" \u00e9 /end MEASUREMENT\n'
    )
    data = _parse(tmp_path, text)
    sec = _sections(data, "MEASUREMENT")[0]
    assert sec["end_line"] == 5
    assert any("Line 5: unexpected character U+00E9" in e for e in data["errors"])
    assert not any("Line 4" in e for e in data["errors"])


def test_cov_read_15_quoted_string_not_closed_line_22(tmp_path: Path) -> None:
    """R-A2L-READ.15/1: ``Line 22: quoted string not closed``."""
    text = _body(meas("X", ' FORMAT "%5.0', " ECU_ADDRESS 0x1234"))
    assert "Line 22: quoted string not closed" in _parse(tmp_path, text)["errors"]


# ===========================================================================
# D. Sections.
# ===========================================================================


def test_cov_001_1_if_data_parentage(tmp_path: Path) -> None:
    """R-A2L-001.1/1: IF_DATA is a child of SX and SX's BIT_MASK 0x0FF0."""
    data = _parse(
        tmp_path,
        _body(meas("SX", " ECU_ADDRESS 0x10 /begin IF_DATA XCP", "  KP_BLOB 0x10", " /end IF_DATA", " BIT_MASK 0x0FF0")),
    )
    sx = _tag(data, "SX")
    assert sx["bit_org"] == "0x0FF0"
    sec = _sections(data, "MEASUREMENT")[0]
    assert any(c.get("name") == "IF_DATA" for c in sec.get("children") or [])


def test_cov_001_1_end_after_words_closed_zero_errors(tmp_path: Path) -> None:
    """R-A2L-001.1/3: an /end after words on its line closes the tag; 0 errors."""
    text = _body(meas("X", " ECU_ADDRESS 0x1234 /end MEASUREMENT").replace("\n/end MEASUREMENT", ""))
    data = _parse(tmp_path, text)
    assert _tag(data, "X")["address"] == 0x1234
    assert data["errors"] == []
    sec = _sections(data, "MEASUREMENT")[0]
    assert sec["end_line"] == _line_of(text, "/end MEASUREMENT")


def test_cov_001_1_two_one_line_instances(tmp_path: Path) -> None:
    """R-A2L-001.1/4 ([K7b]): two INSTANCE sections, each start_line = end_line,
    spans at 0x20 and 0x40, tag XK7B at 0x60, 0 errors."""
    text = _body(
        '/begin INSTANCE IK7 "" T_U16 0x20 /end INSTANCE /begin INSTANCE IK7B "" T_U16 0x40 /end INSTANCE\n'
        + meas("XK7B", " ECU_ADDRESS 0x60")
    )
    data = _parse(tmp_path, text)
    assert _tag(data, "XK7B")["address"] == 0x60
    assert data["errors"] == []
    spans = _spans(data)
    for name, addr in (("IK7", 0x20), ("IK7B", 0x40)):
        s = [x for x in spans if x["name"] == name][0]
        assert s["address"] == addr
    inst = _sections(data, "INSTANCE")
    assert len(inst) == 2 and all(s["start_line"] == s["end_line"] for s in inst)


def test_cov_read_19_begin_glued_exact(tmp_path: Path) -> None:
    """R-A2L-READ.19/1: no section X; the /end diagnostic names the MODULE close."""
    text = _body('/beginMEASUREMENT X ""\n UWORD CM_ID 0 0 0 65535\n ECU_ADDRESS 0x1234\n/end MEASUREMENT')
    data = _parse(tmp_path, text)
    assert _tags_named(data, "X") == []
    assert any("/end MEASUREMENT does not close /begin MODULE" in e for e in data["errors"])


def test_cov_read_19_endx_closes_at_own_end(tmp_path: Path) -> None:
    """R-A2L-READ.19/2: /endX is a word of X; X closes at its own /end."""
    text = _body(meas("X", " /endX", " ECU_ADDRESS 0x10"))
    data = _parse(tmp_path, text)
    assert _tag(data, "X")["address"] == 0x10
    sec = _sections(data, "MEASUREMENT")[0]
    flat = [w for w, _ in _iter_section_words(sec)]
    assert "/endX" in flat
    assert sec["end_line"] == _line_of(text, "/end MEASUREMENT")


def test_cov_001_4_stray_end_exact_line_30(tmp_path: Path) -> None:
    """R-A2L-001.4/1, /2: a stray /end at or after other words on line 30 gives
    ``Line 30: /end without /begin``."""
    for line in ("/end X", "junk /end X"):
        text = _body("") + ("\n" * 7) + line + "\n"
        data = _parse(tmp_path, text)
        assert "Line 30: /end without /begin" in data["errors"]


def test_cov_001_5_end_name_mismatch_exact(tmp_path: Path) -> None:
    """R-A2L-001.5/1, /2: the /end name mismatch names Line 23 exactly."""
    text = _body(meas("X", " ECU_ADDRESS 0x10", " /end IF_DATA"))
    data = _parse(tmp_path, text)
    assert "Line 23: /end IF_DATA does not close /begin MEASUREMENT" in data["errors"]
    text2 = _body(meas("X", " /begin IF_DATA XCP"))
    data2 = _parse(tmp_path, text2)
    assert "Line 23: /end MEASUREMENT does not close /begin IF_DATA" in data2["errors"]


def test_cov_read_22_include_exactly_one(tmp_path: Path) -> None:
    """R-A2L-READ.22/1: exactly one /include error with the word without quotes."""
    data = parse_a2l_file(REPO_ROOT / "examples" / "case_00_public" / "merge_inc_test.a2l")
    errs = [e for e in data["errors"] if "is not read" in e]
    assert len(errs) == 1
    assert "included.a2l" in errs[0] and '"' not in errs[0].split(": ", 1)[1]


def test_cov_read_22_include_comment_zero_errors(tmp_path: Path) -> None:
    """R-A2L-READ.22/2: /include in a comment gives zero errors."""
    text = _body('/* /include "x.a2l" */')
    assert _parse(tmp_path, text)["errors"] == []


def test_cov_read_64_32_levels_exact(tmp_path: Path) -> None:
    """R-A2L-READ.64/1..3: 33 levels give exactly the one nesting error; 32
    levels give 32 nested sections and no error."""
    def nested(n: int, one_line: bool = False) -> str:
        if one_line:
            return "/begin A " * n + "/end A " * n
        return "".join("/begin A\n" for _ in range(n)) + "".join("/end A\n" for _ in range(n))

    data1 = _parse(tmp_path, nested(33))
    assert data1["errors"] == ["Line 33: sections nested deeper than 32"]
    assert data1["sections"] == [] and data1["tags"] == []
    data2 = _parse(tmp_path, nested(33, one_line=True))
    assert data2["errors"] == ["Line 1: sections nested deeper than 32"]
    assert data2["sections"] == []
    data3 = _parse(tmp_path, nested(32))
    assert data3["errors"] == []
    # 32 nested sections (a chain of single children).
    depth = 0
    nodes = data3["sections"]
    while nodes:
        depth += 1
        nodes = nodes[0].get("children") or [] if nodes else []
    assert depth == 32


def test_cov_read_65_nesting_renders(tmp_path: Path) -> None:
    """R-A2L-READ.65/1, /2: 5,000 levels and 50,000 unclosed /begin both parse
    and render without raising."""
    data = _parse(tmp_path, "".join("/begin A\n" for _ in range(5000)))
    assert data["errors"] == ["Line 33: sections nested deeper than 32"]
    render_a2l_view(data)
    data2 = _parse(tmp_path, "".join("/begin A\n" for _ in range(50_000)))
    assert data2["errors"] == ["Line 33: sections nested deeper than 32"]
    render_a2l_view(data2)


def test_cov_read_65_one_line_5000(tmp_path: Path) -> None:
    """R-A2L-READ.65/1: the 5,000-level one-line variant raises nothing."""
    text = "/begin A " * 5000
    data = _parse(tmp_path, text)
    assert data["errors"] == ["Line 1: sections nested deeper than 32"]
    render_a2l_view(data)


def test_cov_read_65_stray_end_flood_renders(tmp_path: Path) -> None:
    """R-A2L-READ.65/3: the 200,000 stray /end parse AND render raise nothing."""
    data = _parse(tmp_path, _body("") + "/end X\n" * 200_000)
    assert len(data["errors"]) == 101
    render_a2l_view(data)


def test_cov_read_65_one_line_string_one_word(tmp_path: Path) -> None:
    """R-A2L-READ.65/5: the 10 MB one-line string parses and renders, and is
    exactly one word (never split at its escaped-quote pairs)."""
    word = '"' + ("a" * 1000 + '\\"') * 10_000 + '"'
    text = _body(meas("X", f" ANNOTATION_TEXT {word}"))
    data = _parse(tmp_path, text)
    render_a2l_view(data)
    sec = _sections(data, "MEASUREMENT")[0]
    words = [w for w, _ in _iter_section_words(sec)]
    assert word in words
    assert not any(w == "a" * 1000 for w in words)


# ===========================================================================
# E. The words of a tag.
# ===========================================================================


def test_cov_read_23_two_measurements_full(tmp_path: Path) -> None:
    """R-A2L-READ.23/5 ([K1]): datatype, length, no UNKNOWN, no duplicate symbol."""
    def one(name: str, addr: str) -> str:
        return f"/begin MEASUREMENT\n{name}\n\"long id\"\nUWORD\nCM_ID\n0\n0\n0\n65535\nECU_ADDRESS\n{addr}\n/end MEASUREMENT"

    text = _body(one("XK1", "0x1234") + "\n" + one("XK1B", "0x1236"))
    data = _parse(tmp_path, text)
    for name, addr in (("XK1", 0x1234), ("XK1B", 0x1236)):
        t = _tag(data, name)
        assert t["address"] == addr and t["datatype"] == "UWORD" and t["length"] == 2
    assert _tags_named(data, "UNKNOWN") == []
    assert not [e for e in data["errors"] if "A2L_DUPLICATE_SYMBOL" in e]


def test_cov_read_25_header_address_k2(tmp_path: Path) -> None:
    """R-A2L-READ.25/5 ([K2]): a one-word-per-line header keeps address 0x1234."""
    text = _body('/begin MEASUREMENT XK2 ""\nUWORD\nCM_ID\n0\n0\n0\n65535\nECU_ADDRESS 0x1234\n/end MEASUREMENT')
    t = _tag(_parse(tmp_path, text), "XK2")
    assert t["datatype"] == "UWORD" and t["length"] == 2 and t["address"] == 0x1234


def test_cov_read_26_header_full(tmp_path: Path) -> None:
    """R-A2L-READ.26/3, /4: the deposit and length survive a glued-comment
    address ([K3], [K4]) with byte order little from the body BYTE_ORDER."""
    k3 = '/begin CHARACTERISTIC CK3 "d" VALUE 0x1000 RL_U16 0 CM_ID 100 10000\n ECU_ADDRESS_EXTENSION 0\n BYTE_ORDER MSB_LAST\n PHYS_UNIT "ms"\n STEP_SIZE 1\n/end CHARACTERISTIC'
    t3 = _tag(_parse(tmp_path, _body(k3)), "CK3", "CHARACTERISTIC")
    assert t3["char_type"] == "VALUE" and t3["address"] == 0x1000 and t3["deposit"] == "RL_U16"
    assert t3["length"] == 2
    assert t3["effective_byte_order"] == "little"


def test_cov_read_27_case07_full(tmp_path: Path) -> None:
    """R-A2L-READ.27/1: case 07's 12 tags keep their exact e07fb00 address,
    length, limits and unit."""
    data = parse_a2l_file(REPO_ROOT / "examples" / "case_07_stress_smoke" / "firmware.a2l")
    assert len(data["tags"]) == 12
    measurements = {
        "MEAS_000000": 0x08001400, "MEAS_000001": 0x08001404,
        "MEAS_000002": 0x08000008, "MEAS_000003": 0x0800000C,
        "MEAS_000004": 0x08000010, "MEAS_000005": 0x08000014,
        "MEAS_000006": 0x08001418, "MEAS_000007": 0x0800001C,
        "MEAS_000008": 0x08000020, "MEAS_000009": 0x08000024,
    }
    for name, addr in measurements.items():
        t = _tag(data, name, "MEASUREMENT")
        assert t["address"] == addr, name
        assert t["length"] == 2, name
        assert t["lower_limit"] == "0" and t["upper_limit"] == "65535", name
        assert t["unit"] == "unit", name
    characteristics = {"CHAR_000000": 0x08011400, "CHAR_000001": 0x08000006}
    for name, addr in characteristics.items():
        t = _tag(data, name, "CHARACTERISTIC")
        assert t["address"] == addr, name
        assert t["length"] == 4, name
        assert t["lower_limit"] is None and t["upper_limit"] is None, name
        assert t["unit"] is None, name


def test_cov_read_27_extension_byte_order_keywords(tmp_path: Path) -> None:
    """R-A2L-READ.27/4 ([K3]): ECU_ADDRESS_EXTENSION and BYTE_ORDER are body
    keywords — byte order little, not part of the header."""
    k3 = '/begin CHARACTERISTIC CK3 "d" VALUE 0x1000 RL_U16 0 CM_ID 100 10000\n ECU_ADDRESS_EXTENSION 0\n BYTE_ORDER MSB_LAST\n/end CHARACTERISTIC'
    t = _tag(_parse(tmp_path, _body(k3)), "CK3", "CHARACTERISTIC")
    assert t["char_type"] == "VALUE" and t["address"] == 0x1000 and t["deposit"] == "RL_U16"
    assert t["effective_byte_order"] == "little"


def test_cov_read_28_short_header_exact_lines(tmp_path: Path) -> None:
    """R-A2L-READ.28/1, /2, /4: the short-header errors name the /begin line
    exactly; the 6-word CHARACTERISTIC gives address/kind none."""
    text = _body(meas("SX", " ECU_ADDRESS 0x10", hdr=" UWORD CM_ID 0 0 0"))
    data = _parse(tmp_path, text)
    begin = _line_of(text, "/begin MEASUREMENT SX")
    assert f"Line {begin}: MEASUREMENT SX has 5 of its 6 header words" in data["errors"]
    text2 = _body('/begin CHARACTERISTIC Synthetic ""\n MAP 0x1C2D3E00 RL 0 CM 1\n/end CHARACTERISTIC')
    data2 = _parse(tmp_path, text2)
    begin2 = _line_of(text2, "/begin CHARACTERISTIC Synthetic")
    assert f"Line {begin2}: CHARACTERISTIC Synthetic has 6 of its 7 header words" in data2["errors"]
    t2 = _tag(data2, "Synthetic", "CHARACTERISTIC")
    assert t2["address"] is None and t2["char_type"] is None
    text3 = _body('/begin MEASUREMENT XK7 "" UWORD CM_ID 0 0\n ECU_ADDRESS 0x10\n/end MEASUREMENT')
    data3 = _parse(tmp_path, text3)
    begin3 = _line_of(text3, "/begin MEASUREMENT XK7")
    assert f"Line {begin3}: MEASUREMENT XK7 has 4 of its 6 header words" in data3["errors"]
    assert _tag(data3, "XK7")["length"] == 2


def test_cov_read_29_matrix_dim_product(tmp_path: Path) -> None:
    """R-A2L-READ.29/4: MATRIX_DIM numbers over two lines give MATRIX_DIM 6."""
    text = _body(meas("X", " ECU_ADDRESS 0x10", " MATRIX_DIM 2", " 3"))
    t = _tag(_parse(tmp_path, text), "X")
    assert t["matrix_dim"] == 6 and t["length"] == 12


def test_cov_read_29_keyword_not_argument_b8_b9(tmp_path: Path) -> None:
    """R-A2L-READ.29/5, /6 ([B8], [B9]): a keyword is never an argument — no
    own byte order, and the address from the following keyword."""
    text = _body(meas("XA1", " ECU_ADDRESS 0x60", " BYTE_ORDER", " BIT_MASK 0x0FF0"))
    t = _tag(_parse(tmp_path, text), "XA1")
    assert t["bit_org"] == "0x0FF0"
    assert t["endian"] is None  # no own BYTE_ORDER word
    assert t["effective_byte_order"] == "big"  # the module's MSB_FIRST applies
    text2 = _body(meas("XA2", " ECU_ADDRESS_EXTENSION", " ECU_ADDRESS 0x1234"))
    assert _tag(_parse(tmp_path, text2), "XA2")["address"] == 0x1234


def test_cov_read_30_byte_order_address(tmp_path: Path) -> None:
    """R-A2L-READ.30/1: two keywords on one line — address 0x1234 and byte order little."""
    text = _body(meas("X", " ECU_ADDRESS 0x1234 BYTE_ORDER MSB_LAST"))
    t = _tag(_parse(tmp_path, text), "X")
    assert t["address"] == 0x1234 and t["effective_byte_order"] == "little"


def test_cov_read_30_k5_zero_errors(tmp_path: Path) -> None:
    """R-A2L-READ.30/3 ([K5]): a one-line MEASUREMENT mid-line ECU_ADDRESS gives
    address 0x18 and zero errors."""
    k5 = '/begin MEASUREMENT XK5 "d" FLOAT64_IEEE NO_COMPU_METHOD 0 0 -100 100  ECU_ADDRESS 0x18 ECU_ADDRESS_EXTENSION 3 READ_WRITE /begin IF_DATA XCP /begin DAQ_EVENT FIXED_EVENT_LIST EVENT 0x0 /end DAQ_EVENT /end IF_DATA /end MEASUREMENT'
    data = _parse(tmp_path, _body(k5))
    assert _tag(data, "XK5")["address"] == 0x18
    assert data["errors"] == []


def test_cov_read_31_axis_descr_byte_order_not_tag(tmp_path: Path) -> None:
    """R-A2L-READ.31/3: an AXIS_DESCR-local BYTE_ORDER is not the tag's — the
    tag's byte order is the module's big."""
    text = (
        "ASAP2_VERSION 1 71\n/project P\n/begin MODULE M \"\"\n/begin MOD_COMMON \"\"\nBYTE_ORDER MSB_FIRST\n/end MOD_COMMON\n"
        "/begin COMPU_METHOD CM_ID \"\" IDENTICAL \"%.0\" \"\"\n/end COMPU_METHOD\n"
        "/begin RECORD_LAYOUT RL_U16\nFNC_VALUES 1 UWORD ROW_DIR DIRECT\n/end RECORD_LAYOUT\n"
        '/begin CHARACTERISTIC CUR ""\n CURVE 0x2000 RL_U16 0 CM_ID 0 65535\n'
        " /begin AXIS_DESCR\n  STD_AXIS NO_INPUT_QUANTITY CM_ID 4 0 3\n  BYTE_ORDER MSB_LAST\n /end AXIS_DESCR\n"
        "/end CHARACTERISTIC\n/end MODULE\n/end PROJECT\n"
    )
    t = _tag(_parse(tmp_path, text), "CUR", "CHARACTERISTIC")
    assert t["effective_byte_order"] == "big"


def test_cov_read_32_duplicate_exact_lines(tmp_path: Path) -> None:
    """R-A2L-READ.32/1..3: the duplicate and disagreeing-address diagnostics
    name the exact lines."""
    text = _body(meas("X", " ECU_ADDRESS 0x10", " ECU_ADDRESS 0x20"))
    data = _parse(tmp_path, text)
    assert "Line 23: ECU_ADDRESS is declared twice in MEASUREMENT X" in data["errors"]
    assert "Line 20: MEASUREMENT X declares the addresses 0x00000010 and 0x00000020" in data["errors"]
    assert _tag(data, "X")["address"] is None
    text2 = _body(meas("X", " ECU_ADDRESS 0x10 BYTE_ORDER MSB_FIRST", " BYTE_ORDER MSB_LAST"))
    data2 = _parse(tmp_path, text2)
    assert "Line 23: BYTE_ORDER is declared twice in MEASUREMENT X" in data2["errors"]
    assert _tag(data2, "X")["address"] is None
    text3 = _body(meas("SX", " BIT_MASK 0x000F", " BIT_MASK 0x0FF0", " ECU_ADDRESS 0x10"))
    data3 = _parse(tmp_path, text3)
    assert any("BIT_MASK is declared twice in MEASUREMENT SX" in e for e in data3["errors"])
    assert _tag(data3, "SX")["address"] is None


def test_cov_read_58_argument_count_exact_lines(tmp_path: Path) -> None:
    """R-A2L-READ.58/1..3, /5: the argument-count errors name the keyword's line."""
    text = _body(meas("XA1", " ECU_ADDRESS 0x60", " BYTE_ORDER", " BIT_MASK 0x0FF0"))
    data = _parse(tmp_path, text)
    assert "Line 23: BYTE_ORDER has 0 of its 1 arguments" in data["errors"]
    text2 = _body(meas("XA2", " ECU_ADDRESS_EXTENSION", " ECU_ADDRESS 0x1234"))
    data2 = _parse(tmp_path, text2)
    assert "Line 22: ECU_ADDRESS_EXTENSION has 0 of its 1 arguments" in data2["errors"]
    text3 = _body(
        meas("X", " ECU_ADDRESS", " BIT_MASK 0x0FF0") + "\n"
        + meas("Y", " MAX_REFRESH 1", " ECU_ADDRESS 0x10") + "\n"
        + meas("Z", " ECU_ADDRESS 0x10", " ECU_ADDRESS")
    )
    data3 = _parse(tmp_path, text3)
    assert "Line 22: ECU_ADDRESS has 0 of its 1 arguments" in data3["errors"]
    assert "Line 27: MAX_REFRESH has 1 of its 2 arguments" in data3["errors"]
    assert "Line 33: ECU_ADDRESS has 0 of its 1 arguments" in data3["errors"]


def test_cov_read_58_matrix_dim_exact_lines(tmp_path: Path) -> None:
    """R-A2L-READ.58/3: MATRIX_DIM's zero/four-argument errors name the
    keyword's line exactly."""
    text = _body(meas("X", " MATRIX_DIM", " ECU_ADDRESS 0x10"))
    data = _parse(tmp_path, text)
    assert "Line 22: MATRIX_DIM has 0 of its 1 to 3 arguments" in data["errors"]
    text2 = _body(meas("X", " ECU_ADDRESS 0x10", " MATRIX_DIM 2 3 4 5"))
    data2 = _parse(tmp_path, text2)
    assert "Line 23: MATRIX_DIM has 4 of its 1 to 3 arguments" in data2["errors"]


def test_cov_read_58_round2_surplus_exact(tmp_path: Path) -> None:
    """R-A2L-READ.58/5 round 2: the ECU_ADDRESS/LENGTH/BIT_MASK surplus
    diagnostics name Line 22 (the keyword's line) exactly."""
    shapes = [
        ("X", " ECU_ADDRESS 0x1C2D 0x3E00", "ECU_ADDRESS has 2 of its 1 arguments"),
        ("Y", " LENGTH 2 4", "LENGTH has 2 of its 1 arguments"),
        ("Z", " BIT_MASK 0x0FF0 0x00FF", "BIT_MASK has 2 of its 1 arguments"),
    ]
    for name, body, want in shapes:
        data = _parse(tmp_path, _body(meas(name, body)))
        assert f"Line 22: {want}" in data["errors"], name


def test_cov_read_58_hex_like_surplus_exact(tmp_path: Path) -> None:
    """R-A2L-READ.58/5 round 3: the five ECU_ADDRESS hex-like surplus shapes,
    the split one on the keyword's line, and BIT_MASK's own surplus."""
    shapes = [
        ("X0", " ECU_ADDRESS 0x1C2D 3E00", "ECU_ADDRESS has 2 of its 1 arguments"),
        ("X1", " ECU_ADDRESS 0x1C2D3 E00", "ECU_ADDRESS has 2 of its 1 arguments"),
        ("X2", " ECU_ADDRESS 0x1C 2D3E00", "ECU_ADDRESS has 2 of its 1 arguments"),
        ("X3", " ECU_ADDRESS 0x1C2D3E00 _4026", "ECU_ADDRESS has 2 of its 1 arguments"),
        ("X4", " ECU_ADDRESS 0x10 BIT_MASK 0x0F F0", "BIT_MASK has 2 of its 1 arguments"),
    ]
    for name, body, want in shapes:
        data = _parse(tmp_path, _body(meas(name, body)))
        assert f"Line 22: {want}" in data["errors"], name
        assert _tag(data, name)["address"] is None
    # The split one: address on line 22, 3E00 on line 23 -> the keyword's line 22.
    data = _parse(tmp_path, _body(meas("XS", " ECU_ADDRESS 0x1C2D", " 3E00")))
    assert "Line 22: ECU_ADDRESS has 2 of its 1 arguments" in data["errors"]
    # SIG_X is not hex-like: keeps 0x10, no error.
    data2 = _parse(tmp_path, _body(meas("SIG", " ECU_ADDRESS 0x10 SIG_X")))
    assert _tag(data2, "SIG")["address"] == 0x10
    assert not [e for e in data2["errors"] if "arguments" in e]


# ===========================================================================
# Sizes and lengths (R-A2L-READ.59..61).
# ===========================================================================


def test_cov_read_59_declares_exact_lines(tmp_path: Path) -> None:
    """R-A2L-READ.59/1, /2: the disagreeing-address/size errors name the /begin
    line (Line 20) exactly."""
    text = _body(meas("X", " ECU_ADDRESS 0x10", " ECU_ADDRESS 0x20"))
    data = _parse(tmp_path, text)
    assert "Line 20: MEASUREMENT X declares the addresses 0x00000010 and 0x00000020" in data["errors"]
    b3 = _body('/begin CHARACTERISTIC XD "" VALUE 0x2000 RL_U16 0 CM_ID 0 65535\n ECU_ADDRESS 0x3000\n/end CHARACTERISTIC')
    data2 = _parse(tmp_path, b3)
    assert "Line 20: CHARACTERISTIC XD declares the addresses 0x00002000 and 0x00003000" in data2["errors"]
    b5 = _body(meas("X", " DATA_SIZE 2", " LENGTH 8"))
    assert "Line 20: MEASUREMENT X declares the sizes 2 and 8" in _parse(tmp_path, b5)["errors"]


def test_cov_read_59_all_five_size_shapes(tmp_path: Path) -> None:
    """R-A2L-READ.59/2: all five size-disagreement shapes."""
    shapes = [
        (meas("X", " DATA_SIZE 2", " LENGTH 8"), "2 and 8"),
        ('/begin CHARACTERISTIC X ""\n VALUE 0x10 RL_U16 0 CM_ID 0 65535\n LENGTH 4\n/end CHARACTERISTIC', "2 and 4"),
        ('/begin CHARACTERISTIC X ""\n VAL_BLK 0x10 RL_U16 0 CM_ID 0 65535\n MATRIX_DIM 4\n NUMBER 5\n/end CHARACTERISTIC', "8 and 10"),
        (meas("X", " ARRAY_SIZE 4", " MATRIX_DIM 3"), "6 and 8"),
        ('/begin CHARACTERISTIC X ""\n ASCII 0x10 RL_U8 0 CM_ID 0 65535\n NUMBER 8\n MATRIX_DIM 4\n/end CHARACTERISTIC', "4 and 8"),
    ]
    for body, want in shapes:
        data = _parse(tmp_path, _body(body))
        assert any(f"declares the sizes {want}" in e for e in data["errors"]), body


def test_cov_read_59_undeclared_layout_val_blk(tmp_path: Path) -> None:
    """R-A2L-READ.59/3: a VAL_BLK on an undeclared layout compares element
    counts 4 and 5."""
    text = _body('/begin CHARACTERISTIC X ""\n VAL_BLK 0x3000 RL_NONE 0 CM_ID 0 65535\n MATRIX_DIM 4\n NUMBER 5\n/end CHARACTERISTIC')
    data = _parse(tmp_path, text)
    assert any("declares the sizes 4 and 5" in e for e in data["errors"])
    assert _tag(data, "X", "CHARACTERISTIC")["length"] is None


def test_cov_read_59_agreeing_pairs_no_error(tmp_path: Path) -> None:
    """R-A2L-READ.59/4: four agreeing pairs give zero ``declares the`` errors."""
    shapes = [
        meas("X", " ECU_ADDRESS 0x10", " ARRAY_SIZE 4", " MATRIX_DIM 4"),
        '/begin CHARACTERISTIC X ""\n VAL_BLK 0x10 RL_U16 0 CM_ID 0 65535\n MATRIX_DIM 4\n NUMBER 4\n/end CHARACTERISTIC',
        '/begin CHARACTERISTIC XD "" VALUE 0x2000 RL_U16 0 CM_ID 0 65535\n ECU_ADDRESS 0x2000\n/end CHARACTERISTIC',
        meas("X", " ECU_ADDRESS 0x10", " MATRIX_DIM 2", " LENGTH 4"),
    ]
    for body in shapes:
        data = _parse(tmp_path, _body(body))
        assert not [e for e in data["errors"] if "declares the" in e], body


def test_cov_read_59_no_datatype_size_shapes(tmp_path: Path) -> None:
    """R-A2L-READ.59/6: DATA_SIZE/LENGTH compared with no datatype size — four
    shapes, the two-LENGTH forms also emit .32's duplicate error."""
    shapes = [
        '/begin MEASUREMENT XN\n ECU_ADDRESS 0x10\n DATA_SIZE 2\n LENGTH 8\n/end MEASUREMENT',
        '/begin MEASUREMENT XN\n ECU_ADDRESS 0x10\n LENGTH 8\n DATA_SIZE 2\n/end MEASUREMENT',
        '/begin MEASUREMENT XN\n ECU_ADDRESS 0x10\n LENGTH 4\n LENGTH 8\n/end MEASUREMENT',
        '/begin CHARACTERISTIC XV "" VALUE 0x2000 RL_NONE 0 CM_ID 0 65535\n LENGTH 4\n LENGTH 8\n/end CHARACTERISTIC',
    ]
    want = [
        "Line 20: MEASUREMENT XN declares the sizes 2 and 8",
        "Line 20: MEASUREMENT XN declares the sizes 2 and 8",
        "Line 20: MEASUREMENT XN declares the sizes 4 and 8",
        "Line 20: CHARACTERISTIC XV declares the sizes 4 and 8",
    ]
    for body, w in zip(shapes, want):
        data = _parse(tmp_path, _body(body))
        assert w in data["errors"], (body, data["errors"])
    data = _parse(tmp_path, _body(shapes[2]))
    assert any("LENGTH is declared twice" in e for e in data["errors"])
    data4 = _parse(tmp_path, _body(shapes[3]))
    assert any("LENGTH is declared twice" in e for e in data4["errors"])


def _synmap(length: Optional[str] = None) -> str:
    nx, ny = 87, 13
    addr = 0x1C2D3E00
    length_line = f"  LENGTH {length}\n" if length is not None else ""
    return (
        "ASAP2_VERSION 1 71\n/begin PROJECT PSYN \"\"\n/begin MODULE MSYN \"\"\n"
        "/begin MOD_COMMON \"\"\nBYTE_ORDER MSB_LAST\n/end MOD_COMMON\n"
        "/begin COMPU_METHOD CM_SYN \"\" IDENTICAL \"%.0\" \"\"\n/end COMPU_METHOD\n"
        "/begin RECORD_LAYOUT RL_SYN_MAP\nNO_AXIS_PTS_X 1 UWORD\nNO_AXIS_PTS_Y 2 UWORD\n"
        "FNC_VALUES 3 UWORD COLUMN_DIR DIRECT\n/end RECORD_LAYOUT\n"
        f'/begin CHARACTERISTIC SYN_MAP_W "synthetic map"\n'
        f"  MAP 0x{addr:08X} RL_SYN_MAP 4095 CM_SYN 0 4095\n"
        + length_line
        + f"  /begin AXIS_DESCR\n    FIX_AXIS NO_INPUT_QUANTITY CM_SYN {nx} 0 {nx - 1}\n    FIX_AXIS_PAR 0 1 {nx}\n  /end AXIS_DESCR\n"
        f"  /begin AXIS_DESCR\n    FIX_AXIS NO_INPUT_QUANTITY CM_SYN {ny} 0 {ny - 1}\n    FIX_AXIS_PAR 0 1 {ny}\n  /end AXIS_DESCR\n"
        "/end CHARACTERISTIC\n/end MODULE\n/end PROJECT\n"
    )


def test_cov_read_59_synmap_length_span(tmp_path: Path) -> None:
    """R-A2L-READ.59/7: a MAP's LENGTH is compared with its span (2266), never
    with its axis counts (2)."""
    begin_line = _line_of(_synmap("2264"), "/begin CHARACTERISTIC SYN_MAP_W")
    data = _parse(tmp_path, _synmap("2264"))
    assert f"Line {begin_line}: CHARACTERISTIC SYN_MAP_W declares the sizes 2264 and 2266" in data["errors"]
    assert not any("2 and 2266" in e for e in data["errors"])
    data2 = _parse(tmp_path, _synmap("2266"))
    assert not [e for e in data2["errors"] if "declares the" in e]
    assert _tag(data2, "SYN_MAP_W", "CHARACTERISTIC")["length"] == 2266


def _external_axis_synmap(length: str) -> str:
    nx, ny = 87, 13
    addr = 0x1C2D3E00
    return (
        "ASAP2_VERSION 1 71\n/begin PROJECT PSYN \"\"\n/begin MODULE MSYN \"\"\n"
        "/begin MOD_COMMON \"\"\nBYTE_ORDER MSB_LAST\n/end MOD_COMMON\n"
        "/begin COMPU_METHOD CM_SYN \"\" IDENTICAL \"%.0\" \"\"\n/end COMPU_METHOD\n"
        "/begin RECORD_LAYOUT RL_SYN_MAP\nNO_AXIS_PTS_X 1 UWORD\nNO_AXIS_PTS_Y 2 UWORD\n"
        "FNC_VALUES 3 UWORD COLUMN_DIR DIRECT\n/end RECORD_LAYOUT\n"
        "/begin RECORD_LAYOUT RL_U16\nFNC_VALUES 1 UWORD ROW_DIR DIRECT\n/end RECORD_LAYOUT\n"
        f'/begin CHARACTERISTIC SYN_MAP_W "synthetic map"\n'
        f"  MAP 0x{addr:08X} RL_SYN_MAP 4095 CM_SYN 0 4095\n"
        f"  LENGTH {length}\n"
        "  /begin AXIS_DESCR\n    COM_AXIS NO_INPUT_QUANTITY CM_SYN 87 0 86 AXIS_PTS_REF AP_X\n  /end AXIS_DESCR\n"
        "  /begin AXIS_DESCR\n    COM_AXIS NO_INPUT_QUANTITY CM_SYN 13 0 12 AXIS_PTS_REF AP_Y\n  /end AXIS_DESCR\n"
        "/end CHARACTERISTIC\n"
        '/begin CHARACTERISTIC AP_X ""\n VALUE 0x3000 RL_U16 0 CM_SYN 0 65535\n'
        f" /begin AXIS_DESCR\n  STD_AXIS NO_INPUT_QUANTITY CM_SYN {nx} 0 {nx - 1}\n /end AXIS_DESCR\n/end CHARACTERISTIC\n"
        '/begin CHARACTERISTIC AP_Y ""\n VALUE 0x3000 RL_U16 0 CM_SYN 0 65535\n'
        f" /begin AXIS_DESCR\n  STD_AXIS NO_INPUT_QUANTITY CM_SYN {ny} 0 {ny - 1}\n /end AXIS_DESCR\n/end CHARACTERISTIC\n"
        "/end MODULE\n/end PROJECT\n"
    )


def test_cov_read_59_60_61_external_axis(tmp_path: Path) -> None:
    """R-A2L-READ.59/8 and R-A2L-READ.61/10: a standing LENGTH is compared with
    the span the external-axis pass resolves (2266)."""
    text = _external_axis_synmap("2264")
    begin_line = _line_of(text, "/begin CHARACTERISTIC SYN_MAP_W")
    data = _parse(tmp_path, text)
    assert f"Line {begin_line}: CHARACTERISTIC SYN_MAP_W declares the sizes 2264 and 2266" in data["errors"]
    assert _tag(data, "SYN_MAP_W", "CHARACTERISTIC")["length"] is None


def test_cov_read_60_no_address_all_shapes(tmp_path: Path) -> None:
    """R-A2L-READ.60/1..4, /6, /7: no address across the disagreeing/missing/
    invalid shapes; agreeing duplicates keep the address."""
    cases = [
        meas("X", " ECU_ADDRESS 0x10", " ECU_ADDRESS 0x20"),
        '/begin CHARACTERISTIC XD "" VALUE 0x2000 RL_U16 0 CM_ID 0 65535\n ECU_ADDRESS 0x3000\n/end CHARACTERISTIC',
        '/begin CHARACTERISTIC XD "" VALUE 0x2000 RL_U16 0 CM_ID 0 65535\n ECU_ADDRESS 0x30_00\n/end CHARACTERISTIC',
        meas("X", " ECU_ADDRESS", " BIT_MASK 0x0FF0"),
        meas("X", " ECU_ADDRESS 0x10", " BYTE_ORDER", " LENGTH 2"),
        meas("X", " ECU_ADDRESS 0x10", " BIT_MASK", " BYTE_ORDER MSB_FIRST"),
        '/begin CHARACTERISTIC XG "" VALUE 0x20_00 RL_U16 0 CM_ID 0 65535\n ECU_ADDRESS 0x3000\n/end CHARACTERISTIC',
    ]
    for body in cases:
        data = _parse(tmp_path, _body(body))
        name = [t["name"] for t in data["tags"] if t["name"] in ("X", "XD", "XG")][0]
        assert _tag(data, name, _section_of(data, name))["address"] is None, body
    # /2: the missing-argument shape still preserves its BIT_MASK word.
    t = _tag(_parse(tmp_path, _body(meas("X", " ECU_ADDRESS", " BIT_MASK 0x0FF0"))), "X")
    assert t["address"] is None and t["bit_org"] == "0x0FF0"
    # /6: the missing-argument shapes also emit .58's keyword-line error.
    d6a = _parse(tmp_path, _body(meas("X", " ECU_ADDRESS 0x10", " BYTE_ORDER", " LENGTH 2")))
    assert "Line 23: BYTE_ORDER has 0 of its 1 arguments" in d6a["errors"]
    d6b = _parse(tmp_path, _body(meas("X", " ECU_ADDRESS 0x10", " BIT_MASK", " BYTE_ORDER MSB_FIRST")))
    assert "Line 23: BIT_MASK has 0 of its 1 arguments" in d6b["errors"]
    # agreeing duplicates keep the address and still report the duplicate.
    text = _body(meas("X", " ECU_ADDRESS 0x10", " ECU_ADDRESS 0x10"))
    agreeing = _parse(tmp_path, text)
    assert _tag(agreeing, "X")["address"] == 0x10
    assert "Line 23: ECU_ADDRESS is declared twice in MEASUREMENT X" in agreeing["errors"]
    # /4: agreeing header-address and BIT_MASK pairs also keep their address,
    # with .32's duplicate error for the two BIT_MASK words.
    b3_agree = _body('/begin CHARACTERISTIC XD "" VALUE 0x2000 RL_U16 0 CM_ID 0 65535\n ECU_ADDRESS 0x2000\n/end CHARACTERISTIC')
    assert _tag(_parse(tmp_path, b3_agree), "XD", "CHARACTERISTIC")["address"] == 0x2000
    mask_agree = _parse(tmp_path, _body(meas("SX", " ECU_ADDRESS 0x10", " BIT_MASK 0x0FF0", " BIT_MASK 0x0FF0")))
    assert _tag(mask_agree, "SX")["address"] == 0x10
    assert any("BIT_MASK is declared twice in MEASUREMENT SX" in e for e in mask_agree["errors"])


def test_cov_read_60_hex_surplus_address_none(tmp_path: Path) -> None:
    """R-A2L-READ.60/8: the six round-3 hex-like surplus shapes give address
    none (never 0x1C2D, 0x1C2D3, 0x1C, 0x1C2D3E00); SIG_X keeps 0x10."""
    shapes = [
        " ECU_ADDRESS 0x1C2D 0x3E00",
        " ECU_ADDRESS 0x1C2D 3E00",
        " ECU_ADDRESS 0x1C2D3 E00",
        " ECU_ADDRESS 0x1C 2D3E00",
        " ECU_ADDRESS 0x1C2D3E00 _4026",
        " ECU_ADDRESS 0x10 BIT_MASK 0x0FF0 0x00FF",
    ]
    for i, body in enumerate(shapes):
        data = _parse(tmp_path, _body(meas(f"X{i}", body)))
        assert _tag(data, f"X{i}")["address"] is None, body
    data = _parse(tmp_path, _body(meas("XS", " ECU_ADDRESS 0x10 SIG_X")))
    assert _tag(data, "XS")["address"] == 0x10


def test_cov_read_60_byte_order_source_not_byte_order(tmp_path: Path) -> None:
    """R-A2L-READ.60/9 (E3S-27): no address when the byte-order source word is
    no byte-order word; the holding case (own word) keeps 0x10 with little."""
    cases = [
        (meas("X", " ECU_ADDRESS 0x10", " BYTE_ORDER MSB_FRIST"), None),
        (meas("X", " ECU_ADDRESS 0x10", " BYTE_ORDER MSB_LAST_MSW_FIRST"), None),
        ('/begin CHARACTERISTIC CB "" VALUE 0x10 RL_BO 0 CM_ID 0 65535\n/end CHARACTERISTIC', "RL_BO"),
    ]
    # cases[2] needs a layout RL_BO with an invalid BYTE_ORDER.
    layout = "/begin RECORD_LAYOUT RL_BO\nFNC_VALUES 1 UWORD ROW_DIR DIRECT\nBYTE_ORDER MSB_FRIST\n/end RECORD_LAYOUT\n"
    for body, _name in cases:
        text = _body(layout + body) if _name == "RL_BO" else _body(body)
        data = _parse(tmp_path, text)
        name = [t["name"] for t in data["tags"] if t["name"] in ("X", "CB")][0]
        assert _tag(data, name, _section_of(data, name))["address"] is None, body
    # inherited invalid MOD_COMMON source: no own BYTE_ORDER -> no address.
    hdr_bad = HDR.replace("BYTE_ORDER MSB_FIRST\n", "BYTE_ORDER MSB_FRIST\n")
    inherited = _parse(tmp_path, hdr_bad + meas("X", " ECU_ADDRESS 0x10") + "\n" + TAIL)
    assert _tag(inherited, "X")["address"] is None
    # holding case: own BYTE_ORDER MSB_LAST keeps 0x10 with little, even though
    # the enclosing MOD_COMMON source is invalid.
    holding = _parse(
        tmp_path, hdr_bad + meas("X", " ECU_ADDRESS 0x10", " BYTE_ORDER MSB_LAST") + "\n" + TAIL
    )
    t = _tag(holding, "X")
    assert t["address"] == 0x10 and t["effective_byte_order"] == "little"


def test_cov_read_62_deposit_none(tmp_path: Path) -> None:
    """R-A2L-READ.62/1, /2: short CHARACTERISTIC headers give address, kind AND
    deposit none."""
    text = _body('/begin CHARACTERISTIC Synthetic map ""\n MAP 0x1C2D3E00 RL 0 CM 0 1\n/end CHARACTERISTIC')
    t = _tag(_parse(tmp_path, text), "Synthetic", "CHARACTERISTIC")
    assert t["address"] is None and t["char_type"] is None and t["deposit"] is None
    text2 = _body('/begin CHARACTERISTIC CQ "" VALUE\n/end CHARACTERISTIC')
    t2 = _tag(_parse(tmp_path, text2), "CQ", "CHARACTERISTIC")
    assert t2["address"] is None and t2["char_type"] is None and t2["deposit"] is None


def test_cov_read_63_header_address_not_number(tmp_path: Path) -> None:
    """R-A2L-READ.63/2 (H2e): ``Line 21: address 0x1C2D3E00_4026 is not a number``."""
    head = HDR.replace("RL_U16", "RL_SYN_U16").replace("CM_ID", "CM_SYN")
    body = (
        '/begin CHARACTERISTIC "Synthetic map"\n'
        "  MAP 0x1C2D3E00_4026 RL_SYN_U16 4095 CM_SYN 0 4095\n"
        "  /begin AXIS_DESCR\n    FIX_AXIS NO_INPUT_QUANTITY CM_SYN 33 0 32\n    FIX_AXIS_PAR 0 1 33\n  /end AXIS_DESCR\n"
        "  /begin AXIS_DESCR\n    FIX_AXIS NO_INPUT_QUANTITY CM_SYN 61 0 60\n    FIX_AXIS_PAR 0 1 61\n  /end AXIS_DESCR\n"
        "/end CHARACTERISTIC"
    )
    data = _parse(tmp_path, _body(body))
    assert "Line 21: address 0x1C2D3E00_4026 is not a number" in data["errors"]


def test_cov_read_63_exact_words_and_lines(tmp_path: Path) -> None:
    """R-A2L-READ.63/1, /3, /4: the not-a-number errors echo the exact word and
    line; the fullwidth word echoes as U+FFFD."""
    for w in ("0x12_34", "0x1C2D3E00_4026", "-0x10", "+16", "0b101"):
        text = _body(meas("X", f" ECU_ADDRESS {w}"))
        assert f"Line 22: ECU_ADDRESS {w} is not a number" in _parse(tmp_path, text)["errors"], w
    text = _body(meas("X", " ECU_ADDRESS \uff11\uff12"))
    data = _parse(tmp_path, text)
    assert "Line 22: ECU_ADDRESS \ufffd\ufffd is not a number" in data["errors"]
    for kw, w in (("LENGTH", "-5"), ("DATA_SIZE", "0b10"), ("NUMBER", "x"), ("ARRAY_SIZE", "4.0")):
        assert f"Line 22: {kw} {w} is not a number" in _parse(tmp_path, _body(meas("X", f" {kw} {w}")))["errors"], kw
    text2 = _body(meas("X", " MATRIX_DIM x4"))
    assert "Line 22: MATRIX_DIM x4 is not a number" in _parse(tmp_path, text2)["errors"]
    text3 = _body(meas("X", " MATRIX_DIM 2 x 3"))
    assert "Line 22: MATRIX_DIM x is not a number" in _parse(tmp_path, text3)["errors"]


def test_cov_read_67_not_closed_exact_lines(tmp_path: Path) -> None:
    """R-A2L-READ.67/1, /2: the not-closed errors name the /begin line (20) and
    /2 gives zero X tags."""
    text = HDR + '/begin MEASUREMENT X ""\n UWORD CM_ID 0 0 0 65535\n ECU_ADDRESS 0x12'
    data = _parse(tmp_path, text)
    assert "Line 20: MEASUREMENT X is not closed" in data["errors"]
    assert "Unclosed /begin sections detected." in data["errors"]
    text2 = _body(meas("X", " ECU_ADDRESS 0x1234", " /* never closed"))
    data2 = _parse(tmp_path, text2)
    assert "Line 23: comment not closed" in data2["errors"]
    assert "Line 20: MEASUREMENT X is not closed" in data2["errors"]
    assert _tags_named(data2, "X") == []


def test_cov_read_68_byte_order_error_exact(tmp_path: Path) -> None:
    """R-A2L-READ.68/1: exactly one not-a-byte-order error each, on line 23."""
    for w in ("MSB_FRIST", "MSB_LAST_MSW_FIRST", '"MSB_FIRST"', "1"):
        text = _body(meas("X", " ECU_ADDRESS 0x10", f" BYTE_ORDER {w}"))
        data = _parse(tmp_path, text)
        errs = [e for e in data["errors"] if f"BYTE_ORDER {w} is not a byte order" in e]
        assert len(errs) == 1, w
        assert errs[0] == f"Line 23: BYTE_ORDER {w} is not a byte order", w
        assert _tag(data, "X")["address"] is None
        ref_data = _ref_read()(text)
        assert _tag(ref_data, "X")["address"] is None, w


def test_cov_read_68_inherited_byte_order_once(tmp_path: Path) -> None:
    """R-A2L-READ.68/2: an inherited invalid byte-order word is diagnosed once
    (never once per tag), from its source line."""
    text = (
        "ASAP2_VERSION 1 71\n/project P\n/begin MODULE M \"\"\n/begin MOD_COMMON \"\"\nBYTE_ORDER MSB_FRIST\n/end MOD_COMMON\n"
        "/begin COMPU_METHOD CM_ID \"\" IDENTICAL \"%.0\" \"\"\n/end COMPU_METHOD\n"
        "/begin RECORD_LAYOUT RL_U16\nFNC_VALUES 1 UWORD ROW_DIR DIRECT\n/end RECORD_LAYOUT\n"
        + meas("X", " ECU_ADDRESS 0x10") + "\n" + meas("Y", " ECU_ADDRESS 0x20") + "\n"
        "/end MODULE\n/end PROJECT\n"
    )
    data = _parse(tmp_path, text)
    errs = [e for e in data["errors"] if "BYTE_ORDER MSB_FRIST is not a byte order" in e]
    assert errs == ["Line 5: BYTE_ORDER MSB_FRIST is not a byte order"]
    # layout source, once for CB.
    text2 = (
        "ASAP2_VERSION 1 71\n/project P\n/begin MODULE M \"\"\n/begin MOD_COMMON \"\"\nBYTE_ORDER MSB_FIRST\n/end MOD_COMMON\n"
        "/begin COMPU_METHOD CM_ID \"\" IDENTICAL \"%.0\" \"\"\n/end COMPU_METHOD\n"
        "/begin RECORD_LAYOUT RL_BO\nFNC_VALUES 1 UWORD ROW_DIR DIRECT\nBYTE_ORDER MSB_FRIST\n/end RECORD_LAYOUT\n"
        '/begin CHARACTERISTIC CB "" VALUE 0x10 RL_BO 0 CM_ID 0 65535\n/end CHARACTERISTIC\n'
        "/end MODULE\n/end PROJECT\n"
    )
    data2 = _parse(tmp_path, text2)
    errs2 = [e for e in data2["errors"] if "BYTE_ORDER MSB_FRIST is not a byte order" in e]
    assert len(errs2) == 1
    layout_line = _line_of(text2, "BYTE_ORDER MSB_FRIST")
    assert f"Line {layout_line}: BYTE_ORDER MSB_FRIST is not a byte order" in errs2


# ===========================================================================
# F. Display identifier and hex/decimal words.
# ===========================================================================


def test_cov_read_33_six_tracked_display_identifiers(tmp_path: Path) -> None:
    """R-A2L-READ.33/1: the six ``/* optional display identifier */`` tags show
    only the identifier in the detail card's first line (no ``/*``)."""
    from s19_app.tui.app import _a2l_detail_card_text

    expected = {
        ("ASAP2_Demo_V161.a2l", "ASAM.M.SCALAR.UBYTE.IDENTICAL"): "DI.ASAM.M.SCALAR.UBYTE.IDENTICAL",
        ("ASAP2_Demo_V171.a2l", "ASAM.M.SCALAR.UBYTE.IDENTICAL"): "DI.ASAM.M.SCALAR.UBYTE.IDENTICAL",
        ("ASAP2_Demo_V171.a2l", "ASAM.M.SCALAR.UBYTE.IDENTICAL.STATUS_STRING"): "DI.ASAM.M.SCALAR.UBYTE.IDENTICAL.STATUS_STRING",
        ("ASAP2_Demo_V171.a2l", "ASAM.M.SCALAR.UBYTE.RAT_FUNC.IDENT.STATUS_STRING"): "DI.ASAM.M.SCALAR.UBYTE.IDENTICAL.STATUS_STRING",
        ("ASAP2_Demo_V171.a2l", "ASAM.M.SCALAR.UBYTE.RAT_FUNC.DIV_10"): "DI.ASAM.M.SCALAR.UBYTE.RAT_FUNC.DIV_10",
        ("ASAP2_Demo_V171.a2l", "ASAM.M.SCALAR.UBYTE.HYPERBOLIC"): "DI.ASAM.M.SCALAR.UBYTE.RAT_FUNC.HYPERBOLIC",
    }
    seen = 0
    for (fname, name), want in expected.items():
        data = parse_a2l_file(REPO_ROOT / "examples" / "case_00_public" / fname)
        tag = _tag(data, name)
        assert tag["display_identifier"] == want, (fname, name)
        card = _a2l_detail_card_text(tag)
        first_line = card.plain.split("\n")[0]
        assert "/*" not in first_line and "*/" not in first_line
        seen += 1
    assert seen == 6


def test_cov_read_34_36_number_word_shapes(tmp_path: Path) -> None:
    """R-A2L-READ.34/1, .35/1, /2, .36/1..3: hex, decimal and non-number words."""
    for w, want in (("0x1234", 0x1234), ("0X1234", 0x1234), ("0x0000000000001234", 0x1234), ("010", 10), ("4096", 4096)):
        assert _tag(_parse(tmp_path, _body(meas("X", f" ECU_ADDRESS {w}"))), "X")["address"] == want, w
    for w in ("0x12_34", "0x1C2D3E00_4026", "-0x10", "+16", "\uff11\uff12", "0b101"):
        assert _tag(_parse(tmp_path, _body(meas("X", f" ECU_ADDRESS {w}"))), "X")["address"] is None, w


def test_cov_read_69_above_64_bits_no_error(tmp_path: Path) -> None:
    """R-A2L-READ.69/1, /2, /3: addresses above 2^64-1 give no address and no
    ``is not a number`` error."""
    for w in ("18446744073709551616", "99999999999999999999"):
        data = _parse(tmp_path, _body(meas("X", f" ECU_ADDRESS {w}")))
        assert _tag(data, "X")["address"] is None
        assert not [e for e in data["errors"] if "is not a number" in e]
    data = _parse(tmp_path, _body(meas("X", " ECU_ADDRESS 18446744073709551615")))
    assert _tag(data, "X")["address"] == 0xFFFFFFFFFFFFFFFF
    text = _body('/begin CHARACTERISTIC CX "" VALUE 99999999999999999999 RL_U16 0 CM_ID 0 65535\n/end CHARACTERISTIC')
    data2 = _parse(tmp_path, text)
    assert _tag(data2, "CX", "CHARACTERISTIC")["address"] is None
    assert not [e for e in data2["errors"] if "is not a number" in e]


# ===========================================================================
# G. Lengths.
# ===========================================================================


def test_cov_read_37_matrix_dim_product_tracked(tmp_path: Path) -> None:
    """R-A2L-READ.37/2: MATRIX_DIM 2 2 gives MATRIX_DIM 4 and length 8."""
    t = _tag(_parse(tmp_path, _body(meas("X", " ECU_ADDRESS 0x1234", " MATRIX_DIM 2 2"))), "X")
    assert t["matrix_dim"] == 4 and t["length"] == 8


def test_cov_read_38_ascii_number_overflow(tmp_path: Path) -> None:
    """R-A2L-READ.38/2: an ASCII ``NUMBER 1000000000000`` gives no length."""
    text = _body('/begin CHARACTERISTIC SX ""\n ASCII 0x10 RL_U8 0 CM_ID 0 65535\n NUMBER 1000000000000\n/end CHARACTERISTIC')
    assert _tag(_parse(tmp_path, text), "SX", "CHARACTERISTIC")["length"] is None


def test_cov_read_39_ascii_number_error(tmp_path: Path) -> None:
    """R-A2L-READ.39/1: the four length-out-of-bounds errors name Line 20."""
    for w in ("0", "1048577", "99999999999"):
        text = _body(meas("X", " ECU_ADDRESS 0x10", f" LENGTH {w}", hdr=""))
        data = _parse(tmp_path, text)
        assert f"Line 20: MEASUREMENT X has the length {w}, outside 1 to 1048576 bytes" in data["errors"], w
    text = _body('/begin CHARACTERISTIC SX ""\n ASCII 0x10 RL_U8 0 CM_ID 0 65535\n NUMBER 1000000000000\n/end CHARACTERISTIC')
    assert "Line 20: CHARACTERISTIC SX has the length 1000000000000, outside 1 to 1048576 bytes" in _parse(tmp_path, text)["errors"]


def test_cov_read_013_agree_no_declares(tmp_path: Path) -> None:
    """R-A2L-013/2: a LENGTH agreeing with datatype x MATRIX_DIM keeps 4 with no
    ``declares the sizes`` error."""
    text = _body(meas("X", " ECU_ADDRESS 0x10", " MATRIX_DIM 2", " LENGTH 4"))
    data = _parse(tmp_path, text)
    assert _tag(data, "X")["length"] == 4
    assert not [e for e in data["errors"] if "declares the sizes" in e]


def test_cov_read_61_no_length_missing_invalid(tmp_path: Path) -> None:
    """R-A2L-READ.61/2: no length when a size keyword gives no number or no
    argument — five shapes."""
    shapes = [
        meas("X", " ECU_ADDRESS 0x10", " LENGTH x4"),
        meas("X", " ECU_ADDRESS 0x10", " MATRIX_DIM x4"),
        meas("X", " MATRIX_DIM", " ECU_ADDRESS 0x10"),
        meas("X", " ECU_ADDRESS 0x10", " MATRIX_DIM 2 3 4 5"),
        meas("X", " DATA_SIZE", " ECU_ADDRESS 0x10"),
    ]
    for body in shapes:
        assert _tag(_parse(tmp_path, _body(body)), "X")["length"] is None, body


def test_cov_read_61_agreeing_lengths(tmp_path: Path) -> None:
    """R-A2L-READ.61/3: four agreeing size sets keep their lengths."""
    cases = [
        (meas("X", " ECU_ADDRESS 0x10", " ARRAY_SIZE 4", " MATRIX_DIM 4"), 8),
        ('/begin CHARACTERISTIC X ""\n VAL_BLK 0x10 RL_U16 0 CM_ID 0 65535\n MATRIX_DIM 4\n NUMBER 4\n/end CHARACTERISTIC', 8),
        (meas("X", " ECU_ADDRESS 0x10", " MATRIX_DIM 2", " LENGTH 4"), 4),
        ('/begin CHARACTERISTIC X ""\n ASCII 0x10 RL_U8 0 CM_ID 0 65535\n NUMBER 8\n MATRIX_DIM 8\n/end CHARACTERISTIC', 8),
    ]
    for body, want in cases:
        data = _parse(tmp_path, _body(body))
        assert _tag(data, "X", _section_of(data, "X"))["length"] == want, body


def test_cov_read_61_definition_stays_refused(tmp_path: Path) -> None:
    """R-A2L-READ.61/4: describe_definition of a two-LENGTH tag stays refused."""
    text = _body(meas("X", " ECU_ADDRESS 0x10", " LENGTH 4", " LENGTH 8"))
    data = _parse(tmp_path, text)
    definition = describe_definition("X", data)
    assert definition.byte_length is None
    assert definition.refusal is not None
    assert "A2L-DEF-ADDRESS" in (definition.refusal.code or "")


def test_cov_read_61_no_datatype_size_no_length(tmp_path: Path) -> None:
    """R-A2L-READ.61/6: no length when DATA_SIZE and LENGTH disagree with no
    datatype size — four shapes, never 2 or 4."""
    shapes = [
        '/begin MEASUREMENT XN\n ECU_ADDRESS 0x10\n DATA_SIZE 2\n LENGTH 8\n/end MEASUREMENT',
        '/begin MEASUREMENT XN\n ECU_ADDRESS 0x10\n LENGTH 8\n DATA_SIZE 2\n/end MEASUREMENT',
        '/begin MEASUREMENT XN\n ECU_ADDRESS 0x10\n LENGTH 4\n LENGTH 8\n/end MEASUREMENT',
        '/begin CHARACTERISTIC XV "" VALUE 0x2000 RL_NONE 0 CM_ID 0 65535\n LENGTH 4\n LENGTH 8\n/end CHARACTERISTIC',
    ]
    for body in shapes:
        data = _parse(tmp_path, _body(body))
        name = "XN" if "XN" in body else "XV"
        assert _tag(data, name, _section_of(data, name))["length"] is None, body


def test_cov_read_61_synmap_final_refusal(tmp_path: Path) -> None:
    """R-A2L-READ.61/8: a MAP's refusal is final — LENGTH 2264 and x4 give no
    length (the span is never re-derived), LENGTH 2266 keeps 2266."""
    data = _parse(tmp_path, _synmap("2264"))
    assert _tag(data, "SYN_MAP_W", "CHARACTERISTIC")["length"] is None
    data2 = _parse(tmp_path, _synmap("x4"))
    assert _tag(data2, "SYN_MAP_W", "CHARACTERISTIC")["length"] is None
    data3 = _parse(tmp_path, _synmap("2266"))
    assert _tag(data3, "SYN_MAP_W", "CHARACTERISTIC")["length"] == 2266


def test_cov_read_61_no_enriched_byte_size_all_shapes(tmp_path: Path) -> None:
    """R-A2L-READ.61/9: four no-length shapes enrich with byte_size/raw_value/
    physical_value all None."""
    shapes = [
        '/begin CHARACTERISTIC X ""\n VALUE 0x10 RL_U16 0 CM_ID 0 65535\n LENGTH 4\n/end CHARACTERISTIC',
        '/begin CHARACTERISTIC X ""\n VAL_BLK 0x10 RL_U16 0 CM_ID 0 65535\n MATRIX_DIM 4\n NUMBER 5\n/end CHARACTERISTIC',
        '/begin CHARACTERISTIC X ""\n VALUE 0x10 RL_U16 0 CM_ID 0 65535\n LENGTH 0\n/end CHARACTERISTIC',
        '/begin CHARACTERISTIC X ""\n VAL_BLK 0x10 RL_U16 0 CM_ID 0 65535\n MATRIX_DIM x4\n/end CHARACTERISTIC',
    ]
    for body in shapes:
        data = _parse(tmp_path, _body(body))
        enriched = enrich_a2l_tags_with_values(data, {0x10: 0x11, 0x11: 0x11})
        row = [e for e in enriched if e.get("name") == "X"][0]
        assert row.get("byte_size") is None, body
        assert row.get("raw_value") is None, body
        assert row.get("physical_value") is None, body


def test_cov_read_61_09_patch_editor_refuses(tmp_path: Path) -> None:
    """R-A2L-READ.61/9 (Patch Editor route): all four no-length symbols are
    refused by ``resolve_symbol_entry`` (never prefills 2 bytes)."""
    from s19_app.tui.services.change_service import resolve_symbol_entry

    shapes = [
        '/begin CHARACTERISTIC X0 ""\n VALUE 0x10 RL_U16 0 CM_ID 0 65535\n LENGTH 4\n/end CHARACTERISTIC',
        '/begin CHARACTERISTIC X1 ""\n VAL_BLK 0x10 RL_U16 0 CM_ID 0 65535\n MATRIX_DIM 4\n NUMBER 5\n/end CHARACTERISTIC',
        '/begin CHARACTERISTIC X2 ""\n VALUE 0x10 RL_U16 0 CM_ID 0 65535\n LENGTH 0\n/end CHARACTERISTIC',
        '/begin CHARACTERISTIC X3 ""\n VAL_BLK 0x10 RL_U16 0 CM_ID 0 65535\n MATRIX_DIM x4\n/end CHARACTERISTIC',
    ]
    data = _parse(tmp_path, _body("\n".join(shapes)))
    for index in range(4):
        result = resolve_symbol_entry(f"X{index}", "4369", data)
        assert result.entry is None, index
        assert any("CHG-SYMBOL-UNRESOLVED" in issue.code for issue in result.issues), index


def test_cov_read_60_08_patch_editor_refuses_hex_surplus(tmp_path: Path) -> None:
    """R-A2L-READ.60/8 (Patch Editor route): the 8 fail-closed addresses are
    refused by ``resolve_symbol_entry``; SIG_X's 0x10 is not refused as
    unresolved."""
    from s19_app.tui.services.change_service import resolve_symbol_entry

    shapes = [
        " ECU_ADDRESS 0x1C2D 0x3E00",
        " ECU_ADDRESS 0x10 BIT_MASK 0x0FF0 0x00FF",
        " ECU_ADDRESS 0x1C2D 3E00",
        " ECU_ADDRESS 0x1C2D\n 3E00",
        " ECU_ADDRESS 0x1C2D3 E00",
        " ECU_ADDRESS 0x1C 2D3E00",
        " ECU_ADDRESS 0x1C2D3E00 _4026",
        " ECU_ADDRESS 0x10 BIT_MASK 0x0F F0",
    ]
    for i, body in enumerate(shapes):
        data = _parse(tmp_path, _body(meas(f"X{i}", body)))
        result = resolve_symbol_entry(f"X{i}", "4660", data)
        assert result.entry is None, body
        assert any("CHG-SYMBOL-UNRESOLVED" in i.code for i in result.issues), body
    data = _parse(tmp_path, _body(meas("XS", " ECU_ADDRESS 0x10 SIG_X")))
    result = resolve_symbol_entry("XS", "4660", data)
    assert not any("CHG-SYMBOL-UNRESOLVED" in i.code for i in result.issues)


# ===========================================================================
# H. Spans.
# ===========================================================================


def test_cov_read_70_unclosed_spans(tmp_path: Path) -> None:
    """R-A2L-READ.70/1..3: unclosed BLOB/INSTANCE and an INSTANCE whose typedef
    is unclosed all export no address and no length."""
    t1 = _body('/begin BLOB B1 "" 0x10 2')
    assert any(s["name"] == "B1" and s["address"] is None and s["length"] is None for s in _spans(_parse(tmp_path, t1)))
    t2 = _body('/begin INSTANCE I1 "" T_U16 0x10')
    assert any(s["name"] == "I1" and s["address"] is None and s["length"] is None for s in _spans(_parse(tmp_path, t2)))
    t3 = _body('/begin TYPEDEF_MEASUREMENT T_U2 "" UWORD CM_ID 0 0 0 65535\n/begin INSTANCE I2 "" T_U2 0x10\n/end INSTANCE')
    assert any(s["name"] == "I2" and s["address"] is None and s["length"] is None for s in _spans(_parse(tmp_path, t3)))


# ===========================================================================
# I. The hostile corpus: differential and mutation.
# ===========================================================================


def _corpus() -> List[dict]:
    """The 160-shape hostile corpus (the audit's "162" enumerations sum to 160:
    31 RP-A + 40 RP-B + 47 RP-C + 4 RP-D + 20 G/H + 9 K + 9 security)."""
    entries: List[dict] = []

    def add(key: str, label: str, text: str, raw: Optional[bytes] = None) -> None:
        entries.append({"key": key, "label": label, "text": text, "raw": raw})

    base_objs = (
        meas("XM", " ECU_ADDRESS 0x00001234", " BYTE_ORDER MSB_LAST") + "\n"
        + char("XC", "VALUE", "0x00002000", "RL_U16") + "\n"
        + '/begin CHARACTERISTIC XH "one-line header" VALUE 0x00003000 RL_U32 0 CM_ID 0 100\n/end CHARACTERISTIC\n'
        + meas("XA", " ECU_ADDRESS 0x00004000", " MATRIX_DIM 4")
    )
    lf = HDR + base_objs + "\n" + TAIL
    HV = "VALUE 0x00003000 RL_U32"

    # -- RP-A (31) -----------------------------------------------------------
    add("RP-A1", "CRLF everywhere", lf.replace("\n", "\r\n"))
    add("RP-A2", "lone CR everywhere", lf.replace("\n", "\r"))
    mixed = "".join(ln + ("\r\n" if i % 3 == 0 else "\r" if i % 3 == 1 else "\n") for i, ln in enumerate(lf.split("\n")))
    add("RP-A3", "mixed CRLF/CR/LF", mixed)
    add("RP-A4", "CR CR LF", lf.replace("\n", "\r\r\n"))
    add("RP-A5", "trailing CR on ECU_ADDRESS", lf.replace("ECU_ADDRESS 0x00001234\n", "ECU_ADDRESS 0x00001234\r\n"))
    add("RP-A6", "trailing blanks after every line", lf.replace("\n", " \t \n"))
    add("RP-A7", "tabs as separators", lf.replace(" ", "\t"))
    add("RP-A8", "UTF-8 BOM first line version", "\ufeff" + lf)
    add("RP-A9", "UTF-8 BOM before /begin PROJECT", "\ufeff" + lf.split("\n", 1)[1])
    add("RP-A10", "UTF-16 LE with BOM", lf, raw=b"\xff\xfe" + lf.encode("utf-16-le"))
    add("RP-A11", "UTF-16 LE with BOM CRLF", lf, raw=b"\xff\xfe" + lf.replace("\n", "\r\n").encode("utf-16-le"))
    add("RP-A12", "form feed between objects", lf.replace("/begin CHARACTERISTIC XC", "\x0c\n/begin CHARACTERISTIC XC"))
    add("RP-A13", "form feed before address", lf.replace("ECU_ADDRESS 0x00001234", "ECU_ADDRESS\x0c0x00001234"))
    add("RP-A14", "NBSP before address", lf.replace("ECU_ADDRESS 0x00001234", "ECU_ADDRESS\u00a00x00001234"))
    add("RP-A15", "cp1252 NBSP 0xA0", lf, raw=lf.replace("ECU_ADDRESS 0x00001234", "ECU_ADDRESS 0x00001234\u00a0").encode("cp1252"))
    add("RP-A16", "NUL after address", lf.replace("ECU_ADDRESS 0x00001234", "ECU_ADDRESS 0x00001234\x00"))
    add("RP-A17", "NUL padding at end", lf + "\x00" * 64)
    add("RP-A18", "U+2028 after address", lf.replace("ECU_ADDRESS 0x00001234", "ECU_ADDRESS 0x00001234\u2028"))
    add("RP-A19", "U+0085 in header", lf.replace(HV, "VALUE 0x00003000\u0085RL_U32"))
    add("RP-A20", "VT in header", lf.replace(HV, "VALUE 0x00003000\x0bRL_U32"))
    add("RP-A21", "U+001E in long id", lf.replace('"one-line header"', '"one-line\x1eheader"'))
    add("RP-A22", "U+FEFF after address", lf.replace("ECU_ADDRESS 0x00001234", "ECU_ADDRESS 0x00001234\ufeff"))
    add("RP-A23", "ESC in long id of XC", lf.replace('/begin CHARACTERISTIC XC ""', '/begin CHARACTERISTIC XC "a\x1b[2Jb"'))
    for key, label, sep in [("RP-A24", "FF", "\x0c"), ("RP-A25", "U+2028", "\u2028"), ("RP-A26", "U+001C", "\x1c"), ("RP-A26b", "VT", "\x0b"), ("RP-A26c", "NEL", "\x85")]:
        add(key, label + " header separator", lf.replace(HV, "VALUE 0x00003000" + sep + "RL_U32"))
    add("RP-A27", "comment glued after address", lf.replace(HV, "VALUE 0x00003000/*old 0x1000*/ RL_U32"))
    add("RP-A28", "CRLF file with lone CR in header", lf.replace("\n", "\r\n").replace(HV, "VALUE 0x00003000\rRL_U32"))
    add("RP-A29", "DISPLAY_IDENTIFIER with comment", lf.replace(" BYTE_ORDER MSB_LAST", " BYTE_ORDER MSB_LAST\n DISPLAY_IDENTIFIER XM_disp /* shown name */"))

    # -- RP-B (40) -----------------------------------------------------------
    b_shapes = [
        ("RP-B1", meas("X", " ECU_ADDRESS 0x1234/*c*/")),
        ("RP-B2", meas("X", " ECU_ADDRESS 0x1234//c")),
        ("RP-B3", meas("X", " ECU_ADDRESS /*c*/ 0x1234")),
        ("RP-B4", meas("X", " ECU_ADDRESS/*c*/0x1234")),
        ("RP-B5", meas("X", " ECU_ADDRESS", " 0x1234")),
        ("RP-B6", meas("X", " ECU_ADDRESS", " /* moved */", " 0x1234")),
        ("RP-B7", meas("X", " ECU_ADDRESS 0x1234", " /*", " ECU_ADDRESS 0x9999", " */")),
        ("RP-B8", meas("X", " ECU_ADDRESS 0x1234", " // ECU_ADDRESS 0x9999")),
        ("RP-B9", meas("X", " /* ECU_ADDRESS 0x9999 */ ECU_ADDRESS 0x1234")),
        ("RP-B10", meas("X", " ECU_ADDRESS 0x12/*c*/34")),
        ("RP-B11", meas("X", " ECU_ADDRESS 0x12\r34")),
        ("RP-B12", meas("X", " ECU_ADDRESS 0x1234 BYTE_ORDER MSB_LAST")),
        ("RP-B13", meas("X", " /begin IF_DATA ETK KP_BLOB 0x10 INTERN 1 RASTER 2 /end IF_DATA", " ECU_ADDRESS 0x1234")),
        ("RP-B14", '/begin MEASUREMENT X "" UWORD CM_ID 0 0 0 65535\n ECU_ADDRESS 0x1234\n/end MEASUREMENT'),
        ("RP-B15", '/begin MEASUREMENT X ""\n UWORD /* type */\n CM_ID /* conv */\n 0 /* res */\n 0 /* acc */\n 0 /* low */\n 65535 /* high */\n ECU_ADDRESS 0x1234\n/end MEASUREMENT'),
        ("RP-B16", '/begin MEASUREMENT\n X ""\n UWORD CM_ID 0 0 0 65535\n ECU_ADDRESS 0x1234\n/end MEASUREMENT'),
        ("RP-B17", '/begin MEASUREMENT X\n "long id"\n UWORD CM_ID 0 0 0 65535\n ECU_ADDRESS 0x1234\n/end MEASUREMENT'),
        ("RP-B18", '/begin MEASUREMENT X/*c*/ ""\n UWORD CM_ID 0 0 0 65535\n ECU_ADDRESS 0x1234\n/end MEASUREMENT'),
        ("RP-B19", '/begin MEASUREMENT /* c */ X ""\n UWORD CM_ID 0 0 0 65535\n ECU_ADDRESS 0x1234\n/end MEASUREMENT'),
        ("RP-B20", '/begin MEASUREMENT X"long"\n UWORD CM_ID 0 0 0 65535\n ECU_ADDRESS 0x1234\n/end MEASUREMENT'),
        ("RP-B21", '/begin CHARACTERISTIC X ""\n VALUE 0x2000/*c*/RL_U16 0 CM_ID 0 65535\n/end CHARACTERISTIC'),
        ("RP-B22", '/begin CHARACTERISTIC X ""\n VALUE 0x2000/* old 0x1000\n */RL_U16 0 CM_ID 0 65535\n/end CHARACTERISTIC'),
        ("RP-B23", '/begin CHARACTERISTIC X "d" VALUE 0x2000 RL_U16 0 CM_ID 0 65535\n/end CHARACTERISTIC'),
        ("RP-B24", '/begin CHARACTERISTIC X "C:\\\\"\n VALUE 0x2000 RL_U16 0 CM_ID 0 65535\n/end CHARACTERISTIC'),
        ("RP-B25", meas("X", " ECU_ADDRESS 0x1234", " DATA_SIZE 0x10/*c*/")),
        ("RP-B26", meas("X", " ECU_ADDRESS 0x1234", " MATRIX_DIM 2 2")),
        ("RP-B27", meas("X", " ECU_ADDRESS 0x1234", " MATRIX_DIM 4", " /*", " MATRIX_DIM 1", " */")),
        ("RP-B28", "/*\n" + meas("X", " ECU_ADDRESS 0x9999") + "\n*/\n" + meas("X", " ECU_ADDRESS 0x1234")),
        ("RP-B29", "/*\n" + meas("X", " ECU_ADDRESS 0x9999") + "\n*/"),
        ("RP-B30", "\n".join("// " + ln for ln in meas("X", " ECU_ADDRESS 0x9999").split("\n"))),
        ("RP-B31", '/beginMEASUREMENT X ""\n UWORD CM_ID 0 0 0 65535\n ECU_ADDRESS 0x1234\n/end MEASUREMENT'),
        ("RP-B32", meas("X", " ECU_ADDRESS 010")),
        ("RP-B33", meas("X", " ECU_ADDRESS 0x12_34")),
        ("RP-B34", meas("X", " ECU_ADDRESS \uff11\uff12")),
        ("RP-B35", meas("X", " ECU_ADDRESS -0x10")),
        ("RP-B36", meas("X", " ECU_ADDRESS 0X1234")),
        ("RP-B37", meas("X", " ECU_ADDRESS 0x1234", " BYTE_ORDER MSB_LAST", " /*", " BYTE_ORDER MSB_FIRST", " */")),
        ("RP-B38", meas("X", " ECU_ADDRESS 0x1234", " BIT_MASK 0x0FF0/*c*/")),
        ("RP-B39", meas("X", ' FORMAT "%5.0', " ECU_ADDRESS 0x1234")),
        ("RP-B40", meas("X", " /* a /* b */ c */", " ECU_ADDRESS 0x1234")),
    ]
    for key, body in b_shapes:
        add(key, key, HDR + body + "\n" + TAIL)

    # -- RP-C (47, the Inc 2 E3 security shapes) -----------------------------
    MN = meas("MN", " BIT_MASK 0x000F", " ECU_ADDRESS 0x10")
    p1 = {
        "A": meas("SX", " BIT_MASK 0x0FF0", " ECU_ADDRESS 0x10"),
        "B": meas("SX", " BIT_MASK 0x0FF0", " ECU_ADDRESS 0x10", hdr=" UWORD CM_ID 0 0 0"),
        "C": meas("SX", " ECU_ADDRESS 0x10", hdr=" UWORD CM_ID 0 0 0 BIT_MASK 0x0FF0"),
        "D": meas("SX", " /* mask */ BIT_MASK 0x0FF0", " ECU_ADDRESS 0x10", hdr=" UWORD CM_ID 0 0 0"),
        "E": '/begin MEASUREMENT SX "" UWORD CM_ID 0 0 0 65535 BIT_MASK 0x0FF0\n ECU_ADDRESS 0x10\n/end MEASUREMENT',
        "F": meas("SX", " ECU_ADDRESS 0x10", hdr=FULL + "/* upper */BIT_MASK 0x0FF0"),
        "G": meas("SX", " BIT_MASK/* bits */0x0FF0", " ECU_ADDRESS 0x10"),
        "H": meas("SX", " ECU_ADDRESS 0x10", ' FORMAT "%5.0', " BIT_MASK 0x0FF0"),
        "I": meas("SX", " ECU_ADDRESS 0x10", ' FORMAT "%5.0', " /* m */ BIT_MASK 0x0FF0"),
        "J": meas("SX", " ECU_ADDRESS 0x10", " /begin IF_DATA XCP", " BIT_MASK 0x0FF0"),
        "J1": meas("SX", " ECU_ADDRESS 0x10", " /begin IF_DATA ETK  KP_BLOB 0x10 INTERN 1 RASTER 2 /end IF_DATA", " BIT_MASK 0x0FF0"),
        "K": meas("SX", " ECU_ADDRESS 0x10", " /begin IF_DATA XCP", " BIT_MASK 0x0FF0", " /end IF_DATA"),
        "L": meas("SX", " ECU_ADDRESS 0x10", " /* old:", " /begin IF_DATA XCP", " */", " BIT_MASK 0x0FF0"),
        "L2": meas("SX", " ECU_ADDRESS 0x10", " /* /begin IF_DATA XCP", " /end IF_DATA */", " BIT_MASK 0x0FF0"),
        "L5": meas("SX", " ECU_ADDRESS 0x10", " // /begin IF_DATA XCP", " /end IF_DATA", " BIT_MASK 0x0FF0"),
        "M": meas("SX", " ECU_ADDRESS 0x10", " /* BIT_MASK 0x0FF0 */"),
        "N": meas("SX", " BIT_MASK", " 0x0FF0", " ECU_ADDRESS 0x10"),
        "O": meas("SX", ' PHYS_UNIT "BIT_MASK"', " ECU_ADDRESS 0x10"),
        "O2": meas("SX", ' PHYS_UNIT "BIT_MASK"', " BIT_MASK 0x0FF0", " ECU_ADDRESS 0x10"),
        "P": meas("SX", " BIT_MASK 0x000F", " BIT_MASK 0x0FF0", " ECU_ADDRESS 0x10"),
        "Q": meas("SX", " bit_mask 0x0FF0", " ECU_ADDRESS 0x10"),
        "R2": '/begin CHARACTERISTIC SX ""\n VALUE 0x10 RL_U16 0 CM_ID 0\n BIT_MASK 0x0FF0\n/end CHARACTERISTIC',
        "S": meas("SX", " BIT_MASK\t0x0FF0", " ECU_ADDRESS 0x10"),
        "T": meas("SX", " ECU_ADDRESS 0x10", hdr=FULL + "\x0cBIT_MASK 0x0FF0"),
        "U": meas("SX", ' FORMAT "%5.0"BIT_MASK 0x0FF0', " ECU_ADDRESS 0x10"),
        "W": meas("SX", " ECU_ADDRESS 0x10", " /begin ANNOTATION", " /begin ANNOTATION_TEXT", ' "BIT_MASK 0x0FF0"', " /end ANNOTATION_TEXT", " /end ANNOTATION"),
        "L2C": meas("SX", " ECU_ADDRESS 0x10", " /begin IF_DATA XCP", "  /* /begin DAQ_EVENT 1", "  /end DAQ_EVENT */", " /end IF_DATA", " BIT_MASK 0x0FF0"),
        "L2N": meas("SX", " ECU_ADDRESS 0x10", " /begin IF_DATA XCP", "  /begin DAQ", "   /* /begin EVENT_LIST", "   /end EVENT_LIST */", "  /end DAQ", " /end IF_DATA", " BIT_MASK 0x0FF0"),
        "L7": meas("SX", " ECU_ADDRESS 0x10", " /begin ANNOTATION", "  /begin ANNOTATION_TEXT", '   "see:', "/end ANNOTATION_TEXT", "/end ANNOTATION", '/end MEASUREMENT"', "  /end ANNOTATION_TEXT", " /end ANNOTATION", " BIT_MASK 0x0FF0"),
        "J2": meas("SX", " ECU_ADDRESS 0x10", " /begin IF_DATA ETK KP_BLOB 0x10 /end IF_DATA", " /begin IF_DATA CANAPE_EXT 100 /end IF_DATA", " BIT_MASK 0x0FF0"),
        "J3": meas("SX", " ECU_ADDRESS 0x10", " /begin IF_DATA ETK KP_BLOB 0x10 /end IF_DATA BIT_MASK 0x0FF0"),
        "J4": meas("SX", " ECU_ADDRESS 0x10 /begin IF_DATA XCP", "  KP_BLOB 0x10", " /end IF_DATA", " BIT_MASK 0x0FF0"),
        "J5": meas("SX", " ECU_ADDRESS 0x10 /begin IF_DATA XCP BIT_MASK 0x1 /end IF_DATA"),
        "X": meas("SX", " BIT_/* x */MASK 0x0FF0", " ECU_ADDRESS 0x10", hdr=" UWORD CM_ID 0 0 0"),
        "X2": meas("SX", " BIT_/* x */MASK 0x0FF0", " ECU_ADDRESS 0x10"),
        "N2": meas("SIG.BIT_MASK.A", " ECU_ADDRESS 0x10"),
        "C5": meas("SX", " ECU_ADDRESS 0x10", " BIT_MASK 0x000F/* nibble */0"),
        "B3": meas("SX", " ECU_ADDRESS 0x20", " /*", " ECU_ADDRESS 0x10", " */"),
        "A1": meas("SX", " ECU_ADDRESS 0x10/* moved */"),
        "A2": meas("SX", " ECU_ADDRESS /* new */ 0x10"),
        "A3": meas("SX", " /begin IF_DATA ETK KP_BLOB 0x10 INTERN 1 RASTER 2 /end IF_DATA", " ECU_ADDRESS 0x10"),
        "A4": '/begin CHARACTERISTIC SX ""\n VALUE 0x10/* c */RL_U16 0 CM_ID 0 65535\n/end CHARACTERISTIC',
        "C2": meas("SX", " ECU_ADDRESS 0x10", " BYTE_ORDER MSB_LAST", " /* alternative:", " BYTE_ORDER MSB_FIRST", " */"),
        "C1": meas("SX", " ECU_ADDRESS 0x10", " /begin IF_DATA ETK KP_BLOB 0x10 /end IF_DATA", " BYTE_ORDER MSB_LAST"),
        "B1": meas("SX", " ECU_ADDRESS 0x10", " MATRIX_DIM 1 4 1"),
        "H1": char("SX", "ASCII", "0x10", "RL_U8", " NUMBER 1000000000000"),
        "H3": meas("SX", " ECU_ADDRESS 0x10", " LENGTH 99999999999"),
    }
    for key, body in p1.items():
        xname = "SIG.BIT_MASK.A" if key == "N2" else "SX"
        add("RP-C-" + key, "Inc 2 E3 shape " + key, HDR + MN + "\n" + body + "\n" + TAIL)

    # -- RP-D (4) ------------------------------------------------------------
    for key, label, body in [
        ("RP-D1", "BLOB at 0x10 2 bytes", '/begin BLOB B1 "" 0x10 2\n/end BLOB'),
        ("RP-D2", "INSTANCE of T_U16 at 0x10", '/begin INSTANCE I1 "" T_U16 0x10\n/end INSTANCE'),
        ("RP-D3", "INSTANCE MATRIX_DIM 5", '/begin INSTANCE I2 "" T_U16 0x20\n MATRIX_DIM 5\n/end INSTANCE'),
        ("RP-D4", "commented-out BLOB", '/* /begin BLOB B9 "" 0x90 2\n/end BLOB */'),
    ]:
        add(key, label, HDR + body + "\n" + TAIL)

    # -- G/H (20) ------------------------------------------------------------
    head = (
        "ASAP2_VERSION 1 71\n/begin PROJECT PSYN \"\"\n/begin MODULE MSYN \"\"\n"
        "/begin COMPU_METHOD CM_SYN \"\" IDENTICAL \"%.0\" \"rpm\"\n/end COMPU_METHOD\n"
        "/begin RECORD_LAYOUT RL_SYN_U16\nFNC_VALUES 1 UWORD COLUMN_DIR DIRECT\n/end RECORD_LAYOUT\n"
    )
    AX = (
        "  /begin AXIS_DESCR\n    FIX_AXIS NO_INPUT_QUANTITY CM_SYN 33 0 32\n    FIX_AXIS_PAR 0 1 33\n  /end AXIS_DESCR\n"
        "  /begin AXIS_DESCR\n    FIX_AXIS NO_INPUT_QUANTITY CM_SYN 61 0 60\n    FIX_AXIS_PAR 0 1 61\n  /end AXIS_DESCR\n"
    )
    GOOD = "  MAP 0x1C2D3E00 RL_SYN_U16 4095 CM_SYN 0 4095"

    def mp(header, axes=AX, name='"Synthetic map"'):
        return f"/begin CHARACTERISTIC {name}\n{header}\n{axes}/end CHARACTERISTIC\n"

    g_shapes = [
        ("G0", mp(GOOD)),
        ("H1a", mp(GOOD.replace("0x1C2D3E00", "0x1C2D3E00\x004026"))),
        ("H1b", mp(GOOD.replace("0x1C2D3E00", "0x1C2D3E00\u200b4026"))),
        ("H1c", mp(GOOD.replace("0x1C2D3E00", "0x1C2D3E00\ufeff4026"))),
        ("H1d", mp(GOOD.replace("0x1C2D3E00", "0x1C2D3E00\r4026"))),
        ("H1e", mp(GOOD.replace("0x1C2D3E00", "0x1C2D3E00\x0b4026"))),
        ("H1f", mp(GOOD.replace("0x1C2D3E00", "0x1C2D3E00\u00a04026"))),
        ("H2a", mp(GOOD.replace("0x1C2D3E00", "0x1C2D3E00/*c*/4026"))),
        ("H2b", mp("  MAP 0x1C2D3E00/* moved\n  */4026 RL_SYN_U16 4095 CM_SYN 0 4095")),
        ("H2c", mp("  MAP 0x1C2D3E00//c\n4026 RL_SYN_U16 4095 CM_SYN 0 4095")),
        ("H2d", mp(GOOD.replace("0x1C2D3E00", '0x1C2D3E00"4026"'))),
        ("H2e", mp(GOOD.replace("0x1C2D3E00", "0x1C2D3E00_4026"))),
        ("H2f", mp(GOOD + "\n  ECU_ADDRESS 0x1C2D3E00/*c*/4026")),
        ("H3a", mp(GOOD)),
        ("H3b", mp('  "the long identifier"\n' + GOOD, name="SYN_MAP_B")),
        ("H3c", mp("  MAP 0x1C2D3E00 RL_SYN_U16 4095 CM_SYN 4095")),
        ("H3d", mp("  0x1C2D3E00 RL_SYN_U16 4095 CM_SYN 0 4095")),
        ("H3e", mp(GOOD, axes="  /begin AXIS_DESCR FIX_AXIS NO_INPUT_QUANTITY CM_SYN 33 0 32\n    FIX_AXIS_PAR 5 2 7\n  /end AXIS_DESCR\n  /begin AXIS_DESCR FIX_AXIS NO_INPUT_QUANTITY CM_SYN 61 0 60\n    FIX_AXIS_PAR 5 2 9\n  /end AXIS_DESCR\n")),
        ("H3f", mp(GOOD, axes=AX.replace("FIX_AXIS_PAR 0 1 33", "FIX_AXIS_PAR 0 1 7"))),
        ("H3g", mp(GOOD, axes=AX + "  /begin AXIS_DESCR\n    NO_INPUT_QUANTITY\n  /end AXIS_DESCR\n")),
    ]
    for key, body in g_shapes:
        add(key, "probe-glue", head + body + TAIL)

    # -- K (9) ----------------------------------------------------------------
    k_hdr = (
        "ASAP2_VERSION 1 71\n/begin PROJECT P \"\"\n/begin MODULE M \"\"\n/begin MOD_COMMON \"\"\nBYTE_ORDER MSB_FIRST\n/end MOD_COMMON\n"
        "/begin COMPU_METHOD CM_ID \"\" IDENTICAL \"%.0\" \"\"\n/end COMPU_METHOD\n"
        + "".join(f"/begin RECORD_LAYOUT RL_{k}\nFNC_VALUES 1 {v} ROW_DIR DIRECT\n/end RECORD_LAYOUT\n" for k, v in (("U8", "UBYTE"), ("U16", "UWORD"), ("U32", "ULONG")))
    )
    k_shapes = [
        ("K1", "".join("/begin MEASUREMENT\n" + f"{nm}\n" + '"long id"\nUWORD\nCM_ID\n0\n0\n0\n65535\nECU_ADDRESS\n' + f"{ad}\n" + "/end MEASUREMENT\n" for nm, ad in (("XK1", "0x1234"), ("XK1B", "0x1236")))),
        ("K1c", '/begin CHARACTERISTIC\nCK1\n"long id"\nVALUE\n0x2000\nRL_U16\n0\nCM_ID\n0\n65535\n/end CHARACTERISTIC\n'),
        ("K2", '/begin MEASUREMENT XK2 ""\nUWORD\nCM_ID\n0\n0\n0\n65535\nECU_ADDRESS 0x1234\n/end MEASUREMENT\n'),
        ("K3", '/begin CHARACTERISTIC CK3 "d" VALUE 0x1000 RL_U16 0 CM_ID 100 10000\nECU_ADDRESS_EXTENSION 0\nBYTE_ORDER MSB_LAST\nPHYS_UNIT "ms"\nSTEP_SIZE 1\n/end CHARACTERISTIC\n'),
        ("K4", '/begin CHARACTERISTIC CK4 "d" CUBE_5 0x123 RL_U16 1 CM_ID 0 10\nNUMBER 10000\nREAD_ONLY\nFORMAT "%3.3"\nSTEP_SIZE 1\n/end CHARACTERISTIC\n'),
        ("K5", '/begin MEASUREMENT XK5 "d" FLOAT64_IEEE NO_COMPU_METHOD 0 0 -100 100  ECU_ADDRESS 0x18 ECU_ADDRESS_EXTENSION 3 READ_WRITE /begin IF_DATA XCP /begin DAQ_EVENT FIXED_EVENT_LIST EVENT 0x0 /end DAQ_EVENT /end IF_DATA /end MEASUREMENT\n'),
        ("K5b", '/begin MEASUREMENT XK5B ""\nUWORD CM_ID 0 0 0 65535\n/* moved */ ECU_ADDRESS 0x1234\n/end MEASUREMENT\n'),
        ("K7", '/begin MEASUREMENT XK7 "" UWORD CM_ID 0 0\nECU_ADDRESS 0x10\n/end MEASUREMENT\n'),
        ("K7b", '/begin TYPEDEF_MEASUREMENT T_U16 "" UWORD CM_ID 0 0 0 65535\n/end TYPEDEF_MEASUREMENT\n/begin INSTANCE IK7 "" T_U16 0x20 /end INSTANCE /begin INSTANCE IK7B "" T_U16 0x40 /end INSTANCE\n/begin MEASUREMENT XK7B ""\nUWORD CM_ID 0 0 0 65535\nECU_ADDRESS 0x60\n/end MEASUREMENT\n'),
    ]
    for key, body in k_shapes:
        add(key, "E2 corpus-class reduction", k_hdr + body + TAIL)

    # -- security addenda (9) -------------------------------------------------
    add("B3", "E3S header address 0x2000 + ECU_ADDRESS 0x3000", HDR + '/begin CHARACTERISTIC XD "" VALUE 0x2000 RL_U16 0 CM_ID 0 65535\n ECU_ADDRESS 0x3000\n/end CHARACTERISTIC\n' + TAIL)
    add("B3b", "E3S header address 0x2000 + ECU_ADDRESS 0x30_00", HDR + '/begin CHARACTERISTIC XD "" VALUE 0x2000 RL_U16 0 CM_ID 0 65535\n ECU_ADDRESS 0x30_00\n/end CHARACTERISTIC\n' + TAIL)
    add("B5", "two LENGTH + DATA_SIZE", HDR + meas("X", " DATA_SIZE 2", " LENGTH 8") + "\n" + meas("Y", " LENGTH 4", " LENGTH 8") + "\n" + TAIL)
    add("B6", "VALUE RL_U16 + LENGTH 4", HDR + '/begin CHARACTERISTIC X ""\n VALUE 0x10 RL_U16 0 CM_ID 0 65535\n LENGTH 4\n/end CHARACTERISTIC\n' + TAIL)
    add("B7", "two BIT_MASK", HDR + meas("SX", " BIT_MASK 0x000F", " BIT_MASK 0x0FF0", " ECU_ADDRESS 0x10") + "\n" + TAIL)
    add("B8", "BYTE_ORDER alone then BIT_MASK", HDR + meas("XA1", " ECU_ADDRESS 0x60", " BYTE_ORDER", " BIT_MASK 0x0FF0") + "\n" + TAIL)
    add("B9", "ECU_ADDRESS_EXTENSION alone then ECU_ADDRESS", HDR + meas("XA2", " ECU_ADDRESS_EXTENSION", " ECU_ADDRESS 0x1234") + "\n" + TAIL)
    add("B13", "cut inside MEASUREMENT", HDR + '/begin MEASUREMENT X ""\n UWORD CM_ID 0 0 0 65535\n ECU_ADDRESS 0x12')
    add("BEGIN_END_X", "E3S-13 /begin /end X", "/begin /end X\n")

    return entries


def _corpus_bytes(entry: dict) -> bytes:
    return entry["raw"] if entry["raw"] is not None else entry["text"].encode("utf-8")


def _cov_errors_equal(reader_errors: List[str], ref_errors: List[tuple]) -> bool:
    """Compare reader error strings (``Line N: msg``) against the REF's
    ``(msg, line)`` tuples on both the message and its line."""
    import re as _re

    def norm_reader(e: str) -> tuple:
        m = _re.match(r"^Line (\d+): (.*)$", e)
        return (int(m.group(1)), m.group(2)) if m else (-1, e)

    reader = sorted(norm_reader(e) for e in reader_errors)
    ref = sorted(((ln if ln is not None else -1), msg) for msg, ln in ref_errors)
    return reader == ref


def test_cov_read_48_hostile_corpus_equal_ref(tmp_path: Path) -> None:
    """R-A2L-READ.48/2: the hostile corpus equals the reference reading."""
    ref = _ref_read()
    corpus = _corpus()
    assert len(corpus) == 160, f"hostile corpus has {len(corpus)} shapes, expected 160"
    checked = 0
    for entry in corpus:
        raw = _corpus_bytes(entry)
        path = tmp_path / f"{entry['key']}.a2l"
        path.write_bytes(raw)
        data = parse_a2l_file(path)
        if data["errors"] == ["File is UTF-16 encoded; save it as UTF-8 and load it again."]:
            # REF is a text oracle; the byte-level UTF-16 refusal is asserted
            # directly (R-A2L-READ.6/1, /2).
            assert data["tags"] == [] and data["sections"] == []
            continue
        if entry["key"] == "H3e":
            # CG-4 routes the AXIS_DESCR-on-/begin correction to Inc 3a.
            tag = _tag(data, "Synthetic map", "CHARACTERISTIC")
            assert tag["address"] == 0x1C2D3E00 and tag["length"] is None
            assert [axis["max_axis_points"] for axis in tag["axis_meta"]] == ["7", "9"]
            continue
        text_for_ref = raw.decode("utf-8", errors="replace")
        reading = ref(text_for_ref)
        _assert_sections_equal(data["sections"], reading["sections"])
        _assert_tags_equal(data["tags"], reading["tags"])
        _assert_spans_equal(_spans(data), reading["spans"])
        assert _cov_errors_equal(data["errors"], reading["errors"]), (
            entry["key"], data["errors"], reading["errors"]
        )
        checked += 1
    assert checked == 157


@pytest.mark.slow
def test_cov_read_65_hostile_corpus_mutations(tmp_path: Path) -> None:
    """R-A2L-READ.65/4: 1,000 seeded byte mutations per corpus shape raise no
    exception other than OSError from parse_a2l_file and render_a2l_view."""
    corpus = _corpus()
    path = tmp_path / "mut.a2l"
    executed = 0
    for entry in corpus:
        base = bytearray(_corpus_bytes(entry))
        rng = random.Random(1103)
        for _ in range(1000):
            buf = bytearray(base)
            if not buf:
                buf = bytearray(b" ")
            op = rng.randrange(3)
            idx = rng.randrange(len(buf))
            if op == 0:  # flip
                buf[idx] ^= 1 << rng.randrange(8)
            elif op == 1:  # insert
                buf.insert(idx, rng.randrange(256))
            else:  # delete
                del buf[idx]
            path.write_bytes(bytes(buf))
            try:
                data = parse_a2l_file(path)
                render_a2l_view(data)
            except OSError:
                pass
            executed += 1
    assert executed == 160 * 1000


# ===========================================================================
# J. Views: summary.
# ===========================================================================


def test_cov_read_50_summary_exact(tmp_path: Path) -> None:
    """R-A2L-READ.50/1..3: the summary section line keeps the quotes, drops the
    comment, and collapses two blanks to one."""
    text = _body('/begin CHARACTERISTIC XH "one-line header" VALUE 0x00003000/*old 0x1000*/ RL_U32 0 CM_ID 0 100\n/end CHARACTERISTIC')
    view = render_a2l_view(_parse(tmp_path, text))
    assert "0x00003000/*old 0x1000*/" not in view
    assert "VALUE 0x00003000 RL_U32 0 CM_ID 0 100 (lines 20-21)" in view
    assert '"one-line header"' in view
    assert (
        '- CHARACTERISTIC XH "one-line header" VALUE 0x00003000 RL_U32 0 CM_ID 0 100 (lines 20-21)'
        in view
    )
    text2 = _body('/begin CHARACTERISTIC XH "one-line header" VALUE  0x00003000 RL_U32 0 CM_ID 0 100\n/end CHARACTERISTIC')
    view2 = render_a2l_view(_parse(tmp_path, text2))
    assert "VALUE  0x00003000" not in view2
    assert "VALUE 0x00003000" in view2


def test_cov_read_50_v161_characteristic_summary() -> None:
    """R-A2L-READ.50/4: V161's later-named ASCII CHARACTERISTIC shows its name."""
    data = parse_a2l_file(REPO_ROOT / "examples" / "case_00_public" / "ASAP2_Demo_V161.a2l")
    view = render_a2l_view(data)
    assert "- CHARACTERISTIC ASAM.C.ASCII.UBYTE.NUMBER_42 " in view


def test_cov_read_076_077_exact(tmp_path: Path) -> None:
    """R-A2L-076/1, /2 and R-A2L-077/1: errors, then sections, then tags."""
    data = parse_a2l_file(REPO_ROOT / "examples" / "case_00_public" / "merge_inc_test.a2l")
    view = render_a2l_view(data)
    i_err = view.index("A2L parse errors:")
    i_sec = view.index("A2L Sections:")
    assert i_err < i_sec
    text = _body(meas("X", " ECU_ADDRESS 0x10")) + "\n/end X\n"
    data2 = _parse(tmp_path, text)
    view2 = render_a2l_view(data2)
    i_err2 = view2.index("A2L parse errors:")
    i_sec2 = view2.index("A2L Sections:")
    i_tags2 = view2.index("A2L Tags:")
    assert i_err2 < i_sec2 < i_tags2
    assert "MEASUREMENT X: 0x00000010 len=2 mem=unknown" in view2


def test_cov_read_076_mod_common_empty_meta(tmp_path: Path) -> None:
    """R-A2L-076/3: a MOD_COMMON with no begin words reads ``- MOD_COMMON (lines
    <first>-<last>)``."""
    text = (
        "ASAP2_VERSION 1 71\n/project P\n/begin MODULE M \"\"\n"
        "/begin MOD_COMMON\n\"\" BYTE_ORDER MSB_FIRST\n/end MOD_COMMON\n"
        "/end MODULE\n/end PROJECT\n"
    )
    view = render_a2l_view(_parse(tmp_path, text))
    assert "- MOD_COMMON (lines " in view


def test_cov_read_51_control_chars_fffd_and_no_broken_lines(tmp_path: Path) -> None:
    """R-A2L-READ.51/1: each control character shows as U+FFFD and every summary
    line starts at a marker the summary itself writes (0 broken lines)."""
    for ch in ("\x0b", "\x0c", "\x1c", "\x1e", "\x85", "\u2028", "\u2029", "\x1b", "\x07"):
        text = _body('/begin MEASUREMENT X "a' + ch + 'b"\n UWORD CM_ID 0 0 0 65535\n ECU_ADDRESS 0x10\n/end MEASUREMENT')
        view = render_a2l_view(_parse(tmp_path, text))
        assert "\ufffd" in view, repr(ch)
        broken = [ln for ln in view.split("\n") if ln and not ln.startswith(("  ", "- ", "A2L "))]
        assert broken == [], (repr(ch), broken)


def test_cov_read_56_cap_and_views(tmp_path: Path) -> None:
    """R-A2L-READ.56/1..4 and /3: the cap holds the exact ``… N more`` marker and
    the Workspace summary / Issues structure stay at 101 lines."""
    # /1: 100 errors and no marker, then 101 with the marker and the same
    # first 100 entries as the 100-error reading.
    def body(n: int) -> str:
        return _body("") + ("/end X\n" * n)

    data_100 = _parse(tmp_path, body(100))
    assert len(data_100["errors"]) == 100
    data = _parse(tmp_path, body(101))
    assert len(data["errors"]) == 101
    assert data["errors"][:100] == data_100["errors"]
    assert data["errors"][-1] == "\u2026 1 more parse errors"
    assert not any("\u2026" in e for e in data["errors"][:100])

    # /2: 400,000 word errors -> 101 entries with the exact marker; the first
    # 100 entries are all U+00E9 unexpected-character errors.
    body2 = _body(meas("X", " ECU_ADDRESS 0x10")) + ("\u00e9\n" * 400_000)
    data2 = _parse(tmp_path, body2)
    assert len(data2["errors"]) == 101
    assert data2["errors"][-1] == "\u2026 399900 more parse errors"
    assert all("unexpected character U+00E9" in e for e in data2["errors"][:100])

    # /3: 200,000 stray /end -> 101 entries + the views cap.
    data3 = _parse(tmp_path, _body("") + "/end X\n" * 200_000)
    assert len(data3["errors"]) == 101
    assert data3["errors"][-1] == "\u2026 199900 more parse errors"
    view = render_a2l_view(data3)
    err_lines = [ln for ln in view.split("A2L parse errors:\n")[1].split("\n\n")[0].split("\n") if ln.strip()]
    assert len(err_lines) == 101
    issues = validate_a2l_structure(data3)
    assert sum(1 for i in issues if i.code == "A2L_STRUCTURE_ERROR") == 101

    # /4: build_section_tree returns a plain list of 101 with the exact marker.
    path = _file_w(tmp_path, _body("") + ("/end X\n" * 150))
    sections, errors = build_section_tree(path)
    assert isinstance(errors, list)
    assert len(errors) == 101
    assert errors[-1] == "\u2026 50 more parse errors"
    from s19_app.tui.a2l import _CappedErrors

    assert not hasattr(_CappedErrors, "extend")
    assert not hasattr(_CappedErrors, "insert")
    assert not hasattr(_CappedErrors, "__iadd__")


def _file_w(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "cap.a2l"
    path.write_text(text, encoding="utf-8")
    return path


def test_cov_read_66_log_line(tmp_path: Path) -> None:
    """R-A2L-READ.66/1: the huge /include echo is capped in the parser error AND
    in the application log line (app.py `_log_a2l_parse_summary`)."""
    import logging
    import types

    big = "a" * 500_000 + "\n" + "b" * 500_000 + "\x1b" + "c" * 400_000
    text = _body(f'/include "{big}"')
    data = _parse(tmp_path, text)
    err = [e for e in data["errors"] if "is not read" in e]
    assert len(err) == 1
    assert len(err[0]) <= 312 and "\n" not in err[0] and "\x1b" not in err[0]

    logger = logging.getLogger("s19tui-cov")
    logger.handlers = []
    logger.setLevel(logging.INFO)
    logger.propagate = False
    records: List[logging.LogRecord] = []

    class _Handler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    logger.addHandler(_Handler())
    app = types.SimpleNamespace(logger=logger, slow_parse_warn_seconds=5.0)
    from s19_app.tui.app import S19TuiApp

    S19TuiApp._log_a2l_parse_summary(app, Path("x.a2l"), data, 0.0)
    warning = [r for r in records if r.levelno >= logging.WARNING and "structural errors" in r.getMessage()]
    assert warning, records
    sample = warning[0].getMessage()
    assert "\n" not in sample and "\x1b" not in sample
    assert len(sample) <= 400


def test_cov_read_66_esc_in_echoed_word_exact(tmp_path: Path) -> None:
    """R-A2L-READ.66/3: the ESC in the echoed /end word is U+FFFD and the
    diagnostic names Line 23 exactly."""
    text = _body(meas("X", " ECU_ADDRESS 0x10", " /end \x1bX"))
    data = _parse(tmp_path, text)
    assert "Line 23: /end \ufffdX does not close /begin MEASUREMENT" in data["errors"]


# ===========================================================================
# K. The READ.52 protocol tests (see tests/test_b103_a2l_reader_perf.py).
# ===========================================================================


def test_cov_read_54_compu_method_named_later_full(tmp_path: Path) -> None:
    """R-A2L-READ.54/1, /2: a later-named COMPU_METHOD converts; raw 5 -> physical
    10 (no identity fallback) and encode physical 10 -> raw bytes ``00 05``."""
    hdr = (
        "ASAP2_VERSION 1 71\n/begin PROJECT P \"\"\n/begin MODULE M \"\"\n/begin MOD_COMMON \"\"\nBYTE_ORDER MSB_FIRST\n/end MOD_COMMON\n"
        "/begin COMPU_METHOD\nCM_LIN \"\" LINEAR \"%.2\" \"rpm\"\nCOEFFS_LINEAR 2 0\n/end COMPU_METHOD\n"
        "/begin RECORD_LAYOUT RL_U16\nFNC_VALUES 1 UWORD ROW_DIR DIRECT\n/end RECORD_LAYOUT\n"
        "/begin TYPEDEF_MEASUREMENT T_U16 \"\" UWORD CM_ID 0 0 0 65535\n/end TYPEDEF_MEASUREMENT\n"
        '/begin MEASUREMENT XK1 ""\nUWORD\nCM_LIN\n0\n0\n0\n65535\nECU_ADDRESS\n0x1234\n/end MEASUREMENT\n'
        "/end MODULE\n/end PROJECT\n"
    )
    data = _parse(tmp_path, hdr)
    tag = _tag(data, "XK1")
    assert tag["conversion"] == "CM_LIN"
    assert tag["effective_byte_order"] == "big"
    method = data["compu_methods_by_name"]["CM_LIN"]
    assert method is not None and method["conversion_type"] == "LINEAR"
    enriched = enrich_a2l_tags_with_values(data, {0x1234: 0x00, 0x1235: 0x05})
    row = [e for e in enriched if e.get("name") == "XK1"][0]
    assert row["raw_value"] == 5 and row["physical_value"] == 10.0
    assert row["conversion_status"] == "ok"
    raw_bytes, reason, flags = encode_physical_to_raw_bytes(
        tag, 10, data["compu_methods_by_name"], data.get("compu_tabs_by_name"), data.get("record_layouts_by_name")
    )
    assert raw_bytes == (0, 5), (raw_bytes, reason, flags)
    assert reason is None


def test_cov_read_54_record_layout_named_later(tmp_path: Path) -> None:
    """R-A2L-READ.54/3: a later-named RECORD_LAYOUT's FNC_VALUES UWORD sizes 2."""
    hdr = (
        "ASAP2_VERSION 1 71\n/project P\n/begin MODULE M \"\"\n/begin MOD_COMMON \"\"\nBYTE_ORDER MSB_FIRST\n/end MOD_COMMON\n"
        "/begin COMPU_METHOD CM_ID \"\" IDENTICAL \"%.0\" \"\"\n/end COMPU_METHOD\n"
        "/begin RECORD_LAYOUT\nRL_K1\nFNC_VALUES 1 UWORD ROW_DIR DIRECT\n/end RECORD_LAYOUT\n"
        '/begin CHARACTERISTIC CRL "" VALUE 0x2000 RL_K1 0 CM_ID 0 65535\n/end CHARACTERISTIC\n'
        "/end MODULE\n/end PROJECT\n"
    )
    data = _parse(tmp_path, hdr)
    assert _tag(data, "CRL", "CHARACTERISTIC")["length"] == 2
    layout = data["record_layouts_by_name"]["RL_K1"]
    assert "FNC_VALUES 1 UWORD ROW_DIR DIRECT" in layout["lines"]


def test_cov_read_54_compu_vtab_named_later(tmp_path: Path) -> None:
    """R-A2L-READ.54/4: a later-named COMPU_VTAB resolves its entries."""
    hdr = (
        "ASAP2_VERSION 1 71\n/project P\n/begin MODULE M \"\"\n/begin MOD_COMMON \"\"\nBYTE_ORDER MSB_FIRST\n/end MOD_COMMON\n"
        "/begin COMPU_VTAB\nVT_K1 \"\"\nTAB_VERB 2\n0 \"off\"\n1 \"on\"\n/end COMPU_VTAB\n"
        "/begin COMPU_METHOD CM_VT \"\" TAB_VERB \"%.0\" \"\"\nCOMPU_TAB_REF VT_K1\n/end COMPU_METHOD\n"
        "/begin RECORD_LAYOUT RL_U16\nFNC_VALUES 1 UWORD ROW_DIR DIRECT\n/end RECORD_LAYOUT\n"
        "/begin TYPEDEF_MEASUREMENT T_U16 \"\" UWORD CM_ID 0 0 0 65535\n/end TYPEDEF_MEASUREMENT\n"
        '/begin MEASUREMENT XVT ""\nUWORD\nCM_VT\n0\n0\n0\n65535\nECU_ADDRESS\n0x1238\n/end MEASUREMENT\n'
        "/end MODULE\n/end PROJECT\n"
    )
    data = _parse(tmp_path, hdr)
    method = data["compu_methods_by_name"]["CM_VT"]
    assert method["conversion_type"] == "TAB_VERB"
    assert method["compu_tab_ref"] == "VT_K1"
    table = data["compu_tabs_by_name"].get("VT_K1")
    assert table is not None
    assert table["section"] == "COMPU_VTAB" and table["kind"] == "TAB_VERB"
    assert table["entries"] == [(0.0, "off"), (1.0, "on")]
    enriched = enrich_a2l_tags_with_values(data, {0x1238: 0x00, 0x1239: 0x01})
    row = [entry for entry in enriched if entry.get("name") == "XVT"][0]
    assert row["raw_value"] == 1
    assert row["physical_value"] == "on"
    assert row["conversion_status"] == "ok"

    unmatched = enrich_a2l_tags_with_values(data, {0x1238: 0x00, 0x1239: 0x02})[0]
    assert unmatched["raw_value"] == 2
    assert unmatched["physical_value"] is None
    assert unmatched["conversion_status"] == "error"

    method["compu_tab_ref"] = "MISSING"
    missing = enrich_a2l_tags_with_values(data, {0x1238: 0x00, 0x1239: 0x01})[0]
    assert missing["physical_value"] is None
    assert missing["conversion_status"] == "error"


def test_cov_read_54_compu_method_long_id(tmp_path: Path) -> None:
    """R-A2L-READ.24/3: a later-named COMPU_METHOD keeps its long identifier and
    conversion type."""
    hdr = (
        "ASAP2_VERSION 1 71\n/project P\n/begin MODULE M \"\"\n/begin MOD_COMMON \"\"\nBYTE_ORDER MSB_FIRST\n/end MOD_COMMON\n"
        "/begin COMPU_METHOD\nCM_LID \"engine speed\" LINEAR \"%.2\" \"rpm\"\nCOEFFS_LINEAR 1 0\n/end COMPU_METHOD\n"
        "/begin RECORD_LAYOUT RL_U16\nFNC_VALUES 1 UWORD ROW_DIR DIRECT\n/end RECORD_LAYOUT\n"
        "/begin TYPEDEF_MEASUREMENT T_U16 \"\" UWORD CM_ID 0 0 0 65535\n/end TYPEDEF_MEASUREMENT\n"
        '/begin MEASUREMENT XK1 ""\nUWORD\nCM_LID\n0\n0\n0\n65535\nECU_ADDRESS\n0x1234\n/end MEASUREMENT\n'
        "/end MODULE\n/end PROJECT\n"
    )
    data = _parse(tmp_path, hdr)
    method = data["compu_methods_by_name"].get("CM_LID")
    assert method is not None
    assert method["long_identifier"] == "engine speed"
    assert method["conversion_type"] == "LINEAR"


def test_cov_read_54_characteristic_display_format(tmp_path: Path) -> None:
    """R-A2L-READ.54/6: Inc 2a's CK1 keeps its FORMAT display format."""
    body = "/begin CHARACTERISTIC\nCK1\n\"long id\"\nVALUE\n0x2000\nRL_U16\n0\nCM_ID\n0\n65535\nFORMAT \"%5.1\"\n/end CHARACTERISTIC"
    data = _parse(tmp_path, _body(body))
    definition = describe_definition("CK1", data)
    assert definition.display_format == "%5.1"


def test_cov_read_21_innermost_close_line(tmp_path: Path) -> None:
    """R-A2L-READ.21/1: an /end closes the innermost section; X is closed at
    line 23 after the mismatch error."""
    text = _body(meas("X", " ECU_ADDRESS 0x10", " /end IF_DATA"))
    data = _parse(tmp_path, text)
    assert any("/end IF_DATA does not close /begin MEASUREMENT" in e for e in data["errors"])
    sec = _sections(data, "MEASUREMENT")[0]
    assert sec["end_line"] == 23


# ===========================================================================
# L. Real-app routes (Workspace / Issues / Patch picker / Check Editor).
# ===========================================================================


def test_cov_read_56_views_show_capped_errors(tmp_path: Path) -> None:
    """R-A2L-READ.56/3: the real Workspace summary and Issues screen show at
    most 101 error lines for 200,000 stray /end lines."""
    from textual.widgets import Static

    from s19_app.tui.app import S19TuiApp
    from s19_app.tui.changes.io import emit_s19_from_mem_map
    from s19_app.tui.issues_view import GroupedIssuesPanel, IssueRow

    from tests.support import b100_projects as projects
    from tests.support.b100_workers import settle_workers
    from tests.support.timing import wait_until

    image = tmp_path / "img.s19"
    image.write_text(
        emit_s19_from_mem_map({0x1234: 0xAA}, [(0x1234, 0x1235)]),
        encoding="ascii",
    )
    a2l = tmp_path / "flood.a2l"
    a2l.write_text(_body("") + "/end X\n" * 200_000, encoding="utf-8")

    def _painted(widget) -> str:
        rendered = widget.render()
        return getattr(rendered, "plain", str(rendered))

    async def scenario(app: S19TuiApp, pilot, log) -> None:
        app.load_selected_file(image)
        await wait_until(
            pilot,
            lambda: app.current_file is not None and app.current_file.path.name == image.name,
            f"the image load of {image.name}",
        )
        await settle_workers(pilot)
        app.load_a2l_from_path(a2l)
        await settle_workers(pilot)
        await wait_until(pilot, lambda: app.current_a2l_path is not None, "the A2L attach")

        app.action_show_screen("workspace")
        for _ in range(6):
            await pilot.pause()
        summary = _painted(app.query_one("#a2l_view", Static))
        err_lines = [
            ln for ln in summary.split("\n")
            if ln.startswith("- Line ") or ln.startswith("- \u2026 ")
        ]
        assert len(err_lines) <= 101, len(err_lines)

        app.action_show_screen("issues")
        for _ in range(6):
            await pilot.pause()
        panel = app.query_one("#validation_issues_groups", GroupedIssuesPanel)
        errors = [
            row for row in panel.query(IssueRow)
            if row.issue.code == "A2L_STRUCTURE_ERROR"
        ]
        assert len(errors) <= 101, len(errors)

    projects.run_app(tmp_path / "app", scenario, size=(160, 50))


def test_cov_read_60_08_picker_lists_only_usable_address(tmp_path: Path) -> None:
    """R-A2L-READ.60/8 real route: the Patch Editor "Use parameter" picker
    lists none of the eight fail-closed tags, only SIG_X's 0x10."""
    from textual.widgets import DataTable

    from s19_app.tui.app import S19TuiApp

    from tests.support import b100_projects as projects
    from tests.support.b100_workers import settle_workers
    from tests.support.timing import wait_until

    shapes = [
        " ECU_ADDRESS 0x1C2D 0x3E00",
        " ECU_ADDRESS 0x10 BIT_MASK 0x0FF0 0x00FF",
        " ECU_ADDRESS 0x1C2D 3E00",
        " ECU_ADDRESS 0x1C2D\n 3E00",
        " ECU_ADDRESS 0x1C2D3 E00",
        " ECU_ADDRESS 0x1C 2D3E00",
        " ECU_ADDRESS 0x1C2D3E00 _4026",
        " ECU_ADDRESS 0x10 BIT_MASK 0x0F F0",
    ]
    body = "\n".join(meas(f"X{i}", shape) for i, shape in enumerate(shapes))
    body += "\n" + meas("XS", " ECU_ADDRESS 0x10 SIG_X")
    a2l = tmp_path / "fail_closed.a2l"
    a2l.write_text(_body(body), encoding="utf-8")

    async def scenario(app: S19TuiApp, pilot, log) -> None:
        app.load_a2l_from_path(a2l)
        await settle_workers(pilot)
        await wait_until(pilot, lambda: app.current_a2l_path is not None, "the A2L attach")

        app.action_show_screen("patch")
        for _ in range(6):
            await pilot.pause()
        table = app.query_one("#patch_param_table", DataTable)
        names = [str(table.get_row_at(i)[1]) for i in range(table.row_count)]
        for i in range(8):
            assert f"X{i}" not in names, names
        assert "XS" in names, names

    projects.run_app(tmp_path / "app", scenario, size=(160, 50))


def test_cov_read_61_09_picker_and_check_editor_never_u16(tmp_path: Path) -> None:
    """R-A2L-READ.61/9 real routes: the Patch picker and Check Editor list each
    no-length tag as u8 (never u16)."""
    from textual.widgets import DataTable

    from s19_app.tui.app import S19TuiApp

    from tests.support import b100_projects as projects
    from tests.support.b100_workers import settle_workers
    from tests.support.timing import wait_until

    shapes = [
        '/begin CHARACTERISTIC X0 ""\n VALUE 0x10 RL_U16 0 CM_ID 0 65535\n LENGTH 4\n/end CHARACTERISTIC',
        '/begin CHARACTERISTIC X1 ""\n VAL_BLK 0x10 RL_U16 0 CM_ID 0 65535\n MATRIX_DIM 4\n NUMBER 5\n/end CHARACTERISTIC',
        '/begin CHARACTERISTIC X2 ""\n VALUE 0x10 RL_U16 0 CM_ID 0 65535\n LENGTH 0\n/end CHARACTERISTIC',
        '/begin CHARACTERISTIC X3 ""\n VAL_BLK 0x10 RL_U16 0 CM_ID 0 65535\n MATRIX_DIM x4\n/end CHARACTERISTIC',
    ]
    a2l = tmp_path / "no_length.a2l"
    a2l.write_text(_body("\n".join(shapes)), encoding="utf-8")

    def _fmt(table) -> dict:
        return {
            str(table.get_row_at(i)[1]): str(table.get_row_at(i)[3]).partition(" ")[0]
            for i in range(table.row_count)
        }

    expected = {f"X{index}": "u8" for index in range(4)}

    async def scenario(app: S19TuiApp, pilot, log) -> None:
        app.load_a2l_from_path(a2l)
        await settle_workers(pilot)
        await wait_until(pilot, lambda: app.current_a2l_path is not None, "the A2L attach")

        app.action_show_screen("patch")
        for _ in range(6):
            await pilot.pause()
        patch_fmt = _fmt(app.query_one("#patch_param_table", DataTable))
        assert patch_fmt == expected, patch_fmt

        app.action_show_screen("check_editor")
        for _ in range(6):
            await pilot.pause()
        check_fmt = _fmt(app.query_one("#check_param_table", DataTable))
        assert check_fmt == expected, check_fmt

    projects.run_app(tmp_path / "app", scenario, size=(160, 50))
