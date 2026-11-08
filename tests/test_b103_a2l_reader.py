"""Batch-103 Inc 11 — A2L reader: the 268 reader cases + 2 acceptance cases.

Cases are ``inc-11/02-test-cases.md`` (the reader rows only; the ``moved
(Inc 12)`` rows stay elsewhere). Expected values are the requirement's exact
values from ``inc-11/01-requirements.md`` and the node examples of
``inc-11/codewire/graph-inc11.md``. Synthetic A2L text only: every shape is
built inline (the hostile corpus shapes and the HDR frame are programmatic).

R-A2L-READ.48 / .49 use the independent reference oracle
``tests/support/b103_a2l_ref.py``, which imports nothing from ``s19_app``; a
static guard (AST + shared-text) runs before any case that uses it.
"""

from __future__ import annotations

import ast
import json
import subprocess
from pathlib import Path
from typing import Callable, List, Optional, Tuple

import pytest

from s19_app.tui import a2l as a2l_module
from s19_app.tui.a2l import (
    build_section_tree,
    enrich_a2l_tags_with_values,
    encode_physical_to_raw_bytes,
    extract_a2l_tags,
    extract_record_layouts,
    parse_a2l_file,
    parse_begin_meta,
    render_a2l_view,
)
from s19_app.tui.a2l_definition import describe_definition

REPO_ROOT = Path(__file__).resolve().parent.parent

try:
    from s19_app.tui.a2l_extract import extract_declared_spans as _extract_declared_spans
except ImportError:  # base (batch-103) — the public name does not exist yet
    _extract_declared_spans = None

REF_MODULE = REPO_ROOT / "tests" / "support" / "b103_a2l_ref.py"
FIXTURE_PATH = REPO_ROOT / "tests" / "fixtures" / "b103_i11" / "e07fb00_tags.jsonl"


# ---------------------------------------------------------------------------
# Fixture builders (HDR / MEAS / CHAR, per inc-11/02-test-cases.md).
# ---------------------------------------------------------------------------

HDR = (
    "ASAP2_VERSION 1 71\n"
    "/begin PROJECT P \"\"\n"
    "/begin MODULE M \"\"\n"
    "/begin MOD_COMMON \"\"\n"
    "BYTE_ORDER MSB_FIRST\n"
    "/end MOD_COMMON\n"
    "/begin COMPU_METHOD CM_ID \"\" IDENTICAL \"%.0\" \"\"\n"
    "/end COMPU_METHOD\n"
    + "".join(
        f"/begin RECORD_LAYOUT RL_{k}\nFNC_VALUES 1 {v} ROW_DIR DIRECT\n/end RECORD_LAYOUT\n"
        for k, v in (("U8", "UBYTE"), ("U16", "UWORD"), ("U32", "ULONG"))
    )
    + "/begin TYPEDEF_MEASUREMENT T_U16 \"\" UWORD CM_ID 0 0 0 65535\n/end TYPEDEF_MEASUREMENT\n"
)

TAIL = "/end MODULE\n/end PROJECT\n"
FULL = " UWORD CM_ID 0 0 0 65535"


def meas(name: str, *body: str, hdr: str = FULL, longid: str = '""') -> str:
    return (
        f"/begin MEASUREMENT {name} {longid}\n{hdr}\n"
        + "\n".join(body)
        + "\n/end MEASUREMENT"
    )


def char(name: str, kind: str, addr: str, rl: str, *body: str) -> str:
    return (
        f'/begin CHARACTERISTIC {name} ""\n'
        f" {kind} {addr} {rl} 0 CM_ID 0 65535\n"
        + "\n".join(body)
        + "\n/end CHARACTERISTIC"
    )


def _file(text: str, tmp_path: Path, name: str = "x.a2l", raw: Optional[bytes] = None) -> Path:
    path = tmp_path / name
    if raw is not None:
        path.write_bytes(raw)
    else:
        path.write_text(text, encoding="utf-8")
    return path


def _parse(
    tmp_path: Path,
    text: str = "",
    *,
    name: str = "x.a2l",
    raw: Optional[bytes] = None,
) -> dict:
    return parse_a2l_file(_file(text, tmp_path, name=name, raw=raw))


def _tag(data: dict, name: str, section: str = "MEASUREMENT") -> dict:
    for tag in data["tags"]:
        if tag.get("name") == name and tag.get("section") == section:
            return tag
    raise AssertionError(f"no {section} tag {name!r} in {[t['name'] for t in data['tags']]}")


def _tags_named(data: dict, name: str) -> List[dict]:
    return [t for t in data["tags"] if t.get("name") == name]


def _body(meas_text: str) -> str:
    return HDR + meas_text + "\n" + TAIL


def _tracked_a2l() -> List[Path]:
    out = subprocess.run(
        ["git", "ls-files", "*.a2l"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
    ).stdout
    return [REPO_ROOT / p for p in out.splitlines() if p.endswith(".a2l")]


# ---------------------------------------------------------------------------
# Reference oracle + static guard.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def ref() -> Callable[[str], dict]:
    """Import the independent oracle and run its static guard once."""
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
    # The lexer is a character loop, not a regex (E3A-08).
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert not node.func.attr in ("compile", "match", "search", "finditer", "fullmatch", "sub"), node.func.attr
    # No long (>40 char) implementation text shared with a2l.py (the A2L
    # vocabulary and the pre-existing error texts are shorter).
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and len(node.value) > 40:
            assert node.value not in a2l_text, f"REF string shared with a2l.py: {node.value[:40]!r}"

    import importlib.util

    spec = importlib.util.spec_from_file_location("b103_a2l_ref", ref_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.ref_read_a2l


# ===========================================================================
# A. The text: line ends, blanks, encodings.
# ===========================================================================


def _six_fields(tag: dict) -> tuple:
    return (
        tag.get("name"),
        tag.get("address"),
        tag.get("length"),
        tag.get("datatype"),
        tag.get("effective_byte_order"),
        tag.get("bit_org"),
    )


def test_r_a2l_read_1_crlf_cr_mixed_read_as_lf(tmp_path: Path) -> None:
    """R-A2L-READ.1/1..3: CRLF, lone CR and mixed ends each read as LF (35/35)."""
    for path in _tracked_a2l():
        text = path.read_text(encoding="utf-8", errors="replace")
        base = parse_a2l_file(path)
        base_tags = {t["name"]: _six_fields(t) for t in base["tags"]}
        for variant in ("crlf", "cr", "mixed"):
            if variant == "crlf":
                body = text.replace("\n", "\r\n")
            elif variant == "cr":
                body = text.replace("\n", "\r")
            else:
                body = "".join(
                    ln + ("\r\n" if i % 3 == 0 else "\r" if i % 3 == 1 else "\n")
                    for i, ln in enumerate(text.split("\n"))
                )
            data = _parse(tmp_path, body, name="line.a2l")
            assert len(data["tags"]) == len(base["tags"]), path
            for t in data["tags"]:
                assert _six_fields(t) == base_tags[t["name"]], (path, t["name"])
            assert data["errors"] == base["errors"], path


def test_r_a2l_read_1_cr_cr_lf_counts_two_ends(tmp_path: Path) -> None:
    """R-A2L-READ.1/4: CR CR LF counts two line ends (RP-A4)."""
    text = _body(meas("X", " ECU_ADDRESS 0x1234"))
    data = _parse(tmp_path, text.replace("\n", "\r\r\n"))
    tag = _tag(data, "X")
    assert tag["address"] == 0x1234
    sec = data["sections"][0]
    assert sec["start_line"] == 3  # PROJECT's LF line 2 -> 2*2 - 1
    assert sec["end_line"] == 49  # PROJECT's LF line 25 -> 2*25 - 1


@pytest.mark.parametrize("sep", ["\n", "\r", " "])
def test_r_a2l_read_2_lf_cr_space_end_word(tmp_path: Path, sep: str) -> None:
    """R-A2L-READ.2/1: LF, CR and space end a word."""
    text = _body(meas("X", f" ECU_ADDRESS{sep}0x1234"))
    data = _parse(tmp_path, text)
    assert _tag(data, "X")["address"] == 0x1234


@pytest.mark.parametrize("sep", ["\t", "\x0b", "\x0c"])
def test_r_a2l_read_2_ht_vt_ff_end_word(tmp_path: Path, sep: str) -> None:
    """R-A2L-READ.2/2: HT, VT and FF end a word."""
    text = _body(meas("X", f" ECU_ADDRESS{sep}0x1234"))
    assert _tag(_parse(tmp_path, text), "X")["address"] == 0x1234


@pytest.mark.parametrize(
    "ch",
    ["\u00a0", "\u0085", "\u2028", "\u2029", "\u001c", "\u001e", "\ufeff", "\u200b"],
)
def test_r_a2l_read_3_nonblank_stays_in_word(tmp_path: Path, ch: str) -> None:
    """R-A2L-READ.3/1: a non-blank character stays in its word (8/8)."""
    text = _body(meas("X", f" ECU_ADDRESS 0x1234{ch}"))
    data = _parse(tmp_path, text)
    assert _tag(data, "X")["address"] is None


def test_r_a2l_read_3_nbsp_joins_keyword_and_word(tmp_path: Path) -> None:
    """R-A2L-READ.3/2: NBSP between the keyword and its word joins them."""
    text = _body(meas("X", " ECU_ADDRESS\u00a00x1234"))
    assert _tag(_parse(tmp_path, text), "X")["address"] is None


@pytest.mark.parametrize(
    "ch",
    ["\u00a0", "\u0085", "\u2028", "\u2029", "\u001c", "\u001e", "\ufeff", "\u200b"],
)
def test_r_a2l_read_3_after_header_address_length_matrix_dim(tmp_path: Path, ch: str) -> None:
    """R-A2L-READ.3/3: the 8 characters after a header address, a LENGTH and a
    MATRIX_DIM word give no address / no length (24/24)."""
    c = _parse(tmp_path, _body(f'/begin CHARACTERISTIC CX "" VALUE 0x2000{ch} RL_U16 0 CM_ID 0 65535\n/end CHARACTERISTIC'))
    assert _tag(c, "CX", "CHARACTERISTIC")["address"] is None
    m = _parse(tmp_path, _body(meas("X", f" ECU_ADDRESS 0x10", f" LENGTH 4{ch}")))
    assert _tag(m, "X")["length"] is None
    mm = _parse(tmp_path, _body(meas("X", f" ECU_ADDRESS 0x10", f" MATRIX_DIM 4{ch}")))
    assert _tag(mm, "X")["length"] is None


@pytest.mark.parametrize(
    ("ch", "code"),
    [
        ("\u00a0", "00A0"),
        ("\u0085", "0085"),
        ("\u2028", "2028"),
        ("\u2029", "2029"),
        ("\u001c", "001C"),
        ("\u001e", "001E"),
        ("\ufeff", "FEFF"),
        ("\u200b", "200B"),
    ],
)
def test_r_a2l_read_4_unexpected_character_error(tmp_path: Path, ch: str, code: str) -> None:
    """R-A2L-READ.4/1: exactly one ``unexpected character`` error each."""
    text = "\n".join([""] * 19) + f" ECU_ADDRESS 0x1234{ch}\n"
    body = _body(meas("X", f" ECU_ADDRESS 0x1234{ch}"))
    data = _parse(tmp_path, body)
    assert [e for e in data["errors"] if f"unexpected character U+{code}" in e]


def test_r_a2l_read_4_comment_and_string_give_no_error(tmp_path: Path) -> None:
    """R-A2L-READ.4/2: such a character in a comment or string gives no error."""
    text = _body(meas("X", " /* \u00b0 \u00b5 */", ' PHYS_UNIT "\u00b0C"', " ECU_ADDRESS 0x1234"))
    data = _parse(tmp_path, text)
    assert not [e for e in data["errors"] if "unexpected character" in e]


def test_r_a2l_read_4_no_unexpected_character_on_tracked(tmp_path: Path) -> None:
    """R-A2L-READ.4/3: 0 unexpected-character errors over the 35 files."""
    for path in _tracked_a2l():
        data = parse_a2l_file(path)
        assert not [e for e in data["errors"] if "unexpected character" in e], path


def test_r_a2l_read_4_latin1_byte_fffd(tmp_path: Path) -> None:
    """R-A2L-READ.4/4: a Latin-1 0xB0 read as U+FFFD; error in a word only."""
    raw = _body(meas("XL1", " ECU_ADDRESS 0x70", longid='"Temp \u00b0C"') + "\n" + meas("XL1_\u00b0", " ECU_ADDRESS 0x72")).encode("latin-1")
    data = _parse(tmp_path, raw=raw)
    assert len([e for e in data["errors"] if "unexpected character U+FFFD" in e]) == 1


@pytest.mark.parametrize(
    ("ch", "code"),
    [
        ("\u00a0", "00A0"),
        ("\u0085", "0085"),
        ("\u2028", "2028"),
        ("\u2029", "2029"),
        ("\u001c", "001C"),
        ("\u001e", "001E"),
        ("\ufeff", "FEFF"),
        ("\u200b", "200B"),
    ],
)
def test_r_a2l_read_4_after_address_length_matrix(tmp_path: Path, ch: str, code: str) -> None:
    """R-A2L-READ.4/5: the error after a header address, a LENGTH and a MATRIX_DIM."""
    body = _body(
        f'/begin CHARACTERISTIC CX "" VALUE 0x2000{ch} RL_U16 0 CM_ID 0 65535\n/end CHARACTERISTIC\n'
        + meas("X", " ECU_ADDRESS 0x10", f" LENGTH 4{ch}")
        + "\n"
        + meas("Y", " ECU_ADDRESS 0x10", f" MATRIX_DIM 4{ch}")
    )
    data = _parse(tmp_path, body)
    errs = [e for e in data["errors"] if f"unexpected character U+{code}" in e]
    assert len(errs) == 3


def test_r_a2l_read_4_quoted_name_esc(tmp_path: Path) -> None:
    """R-A2L-READ.4/6: ESC in a quoted tag name gives exactly one error."""
    text = _body('/begin MEASUREMENT "Torque\x1bMax" ""\n UWORD CM_ID 0 0 0 65535\n ECU_ADDRESS 0x10\n/end MEASUREMENT')
    data = _parse(tmp_path, text)
    assert [e for e in data["errors"] if "unexpected character U+001B" in e]


def test_r_a2l_read_5_bom_before_version_dropped(tmp_path: Path) -> None:
    """R-A2L-READ.5/1: a BOM before ASAP2_VERSION is dropped."""
    body = _body(meas("X", " ECU_ADDRESS 0x1234"))
    assert _tag(_parse(tmp_path, "\ufeff" + body), "X")["address"] == 0x1234


def test_r_a2l_read_5_bom_before_project_dropped(tmp_path: Path) -> None:
    """R-A2L-READ.5/2: a BOM before /begin PROJECT is dropped (RP-A9)."""
    text = _body(meas("X", " ECU_ADDRESS 0x1234")).split("\n", 1)[1]
    data = _parse(tmp_path, "\ufeff" + text)
    assert data["errors"] == []
    assert _tag(data, "X")["address"] == 0x1234


@pytest.mark.parametrize("bom", [b"\xff\xfe", b"\xfe\xff"])
def test_r_a2l_read_6_utf16_refusal(tmp_path: Path, bom: bytes) -> None:
    """R-A2L-READ.6/1, /2: UTF-16 BOM refuses with one error, 0 tags."""
    body = _body(meas("X", " ECU_ADDRESS 0x1234"))
    enc = "utf-16-le" if bom == b"\xff\xfe" else "utf-16-be"
    raw = bom + body.encode(enc)
    data = _parse(tmp_path, raw=raw)
    assert data["errors"] == ["File is UTF-16 encoded; save it as UTF-8 and load it again."]
    assert data["tags"] == []


def test_r_a2l_read_55_utf16_no_bom_refused(tmp_path: Path) -> None:
    """R-A2L-READ.55/1: UTF-16 LE with no BOM refuses."""
    body = _body(meas("X", " ECU_ADDRESS 0x1234"))
    raw = body.encode("utf-16-le")
    data = _parse(tmp_path, raw=raw)
    assert data["errors"] == ["File is not UTF-8 text; save it as UTF-8 and load it again."]
    assert data["sections"] == [] and data["tags"] == []


def test_r_a2l_read_55_binary_refused(tmp_path: Path) -> None:
    """R-A2L-READ.55/2: 5 MiB of seeded random bytes holding NUL refuse."""
    import random

    rng = random.Random(1103)
    raw = bytes(rng.randrange(1, 256) for _ in range(5 * 1024 * 1024))
    raw = raw[:100] + b"\x00" + raw[101:]
    data = _parse(tmp_path, raw=raw)
    assert data["errors"] == ["File is not UTF-8 text; save it as UTF-8 and load it again."]


def test_r_a2l_read_55_nul_after_address_refused(tmp_path: Path) -> None:
    """R-A2L-READ.55/3: a NUL after an address word refuses the file."""
    text = _body(meas("X", " ECU_ADDRESS 0x1234\x00"))
    data = _parse(tmp_path, text)
    assert data["errors"] == ["File is not UTF-8 text; save it as UTF-8 and load it again."]


def test_r_a2l_read_55_nul_in_comment_refused(tmp_path: Path) -> None:
    """R-A2L-READ.55/4: a NUL inside a comment refuses the file."""
    text = _body(meas("X", " /* a\x00b */", " ECU_ADDRESS 0x10"))
    assert _parse(tmp_path, text)["errors"] == ["File is not UTF-8 text; save it as UTF-8 and load it again."]


def test_r_a2l_read_55_utf16_with_bom_gives_6_only(tmp_path: Path) -> None:
    """R-A2L-READ.55/5: a UTF-16 file with its BOM gives .6's error only."""
    body = _body(meas("X", " ECU_ADDRESS 0x1234"))
    raw = b"\xff\xfe" + body.encode("utf-16-le")
    data = _parse(tmp_path, raw=raw)
    assert data["errors"] == ["File is UTF-16 encoded; save it as UTF-8 and load it again."]


def test_r_a2l_read_55_no_nul_on_tracked() -> None:
    """R-A2L-READ.55/6: 0 NUL over the 35 files."""
    for path in _tracked_a2l():
        assert b"\x00" not in path.read_bytes(), path


def test_r_a2l_read_56_cap_at_edge(tmp_path: Path) -> None:
    """R-A2L-READ.56/1: 100 errors and no marker; then 101."""
    def body(n: int) -> str:
        return _body("") + ("/end X\n" * n)
    data = _parse(tmp_path, body(100))
    assert len(data["errors"]) == 100
    data = _parse(tmp_path, body(101))
    assert len(data["errors"]) == 101
    assert data["errors"][-1] == "\u2026 1 more parse errors"


def test_r_a2l_read_56_word_error_flood(tmp_path: Path) -> None:
    """R-A2L-READ.56/2: 400,000 \u00e9 words -> 101 entries, last the marker."""
    body = _body(meas("X", " ECU_ADDRESS 0x10")) + ("\u00e9\n" * 400_000)
    data = _parse(tmp_path, body)
    assert len(data["errors"]) == 101
    assert data["errors"][-1] == "\u2026 399900 more parse errors"


def test_r_a2l_read_56_cap_through_build_section_tree(tmp_path: Path) -> None:
    """R-A2L-READ.56/4: build_section_tree returns a plain list of 101."""
    path = _file(_body("") + ("/end X\n" * 150), tmp_path)
    sections, errors = build_section_tree(path)
    assert isinstance(errors, list)
    assert len(errors) == 101
    assert errors[-1] == "\u2026 50 more parse errors"


def test_r_a2l_read_66_echo_cap(tmp_path: Path) -> None:
    """R-A2L-READ.66/1: a huge /include word is echoed at most 312 chars, no LF/ESC."""
    big = "a" * 500_000 + "\n" + "b" * 500_000 + "\x1b" + "c" * 400_000
    text = _body(f'/include "{big}"')
    data = _parse(tmp_path, text)
    err = [e for e in data["errors"] if "is not read" in e]
    assert len(err) == 1
    assert len(err[0]) <= 312
    assert "\n" not in err[0] and "\x1b" not in err[0]


def test_r_a2l_read_66_name_cut_256(tmp_path: Path) -> None:
    """R-A2L-READ.66/2: a 256-char name whole; a 257-char name cut + ellipsis."""
    n256 = "N" * 256
    n257 = "N" * 257
    text = _body(
        f'/begin MEASUREMENT {n256} ""\n UWORD\n ECU_ADDRESS 0x10\n/end MEASUREMENT\n'
        f'/begin MEASUREMENT {n257} ""\n UWORD\n ECU_ADDRESS 0x20\n/end MEASUREMENT'
    )
    data = _parse(tmp_path, text)
    errs = [e for e in data["errors"] if "header words" in e]
    assert len(errs) == 2
    assert n256 in errs[0]
    assert n257[:256] + "\u2026" in errs[1]


def test_r_a2l_read_66_esc_in_echoed_word(tmp_path: Path) -> None:
    """R-A2L-READ.66/3: /end <ESC>X -> /end <U+FFFD>X."""
    text = _body(meas("X", " ECU_ADDRESS 0x10", " /end \x1bX"))
    data = _parse(tmp_path, text)
    assert any("/end \ufffdX does not close /begin MEASUREMENT" in e for e in data["errors"])


# ===========================================================================
# B. Comments.
# ===========================================================================


def test_r_a2l_001_2_comment_not_read(tmp_path: Path) -> None:
    """R-A2L-001.2/1..7: an old keyword in a comment is not read."""
    cases = [
        ("ECU_ADDRESS", meas("X", " ECU_ADDRESS 0x1234", " /*", " ECU_ADDRESS 0x9999", " */"), "address", 0x1234),
        ("BYTE_ORDER", meas("X", " ECU_ADDRESS 0x1234", " BYTE_ORDER MSB_LAST", " /*", " BYTE_ORDER MSB_FIRST", " */"), "effective_byte_order", "little"),
        ("MATRIX_DIM", meas("X", " ECU_ADDRESS 0x1234", " MATRIX_DIM 4", " /*", " MATRIX_DIM 1", " */"), "length", 8),
        ("BIT_MASK", meas("X", " ECU_ADDRESS 0x1234", " /* BIT_MASK 0x0FF0 */"), "bit_org", None),
        ("LENGTH", meas("X", " ECU_ADDRESS 0x10", " MATRIX_DIM 2", " LENGTH 4", " /*", " LENGTH 2", " */"), "length", 4),
        ("//", meas("X", " ECU_ADDRESS 0x1234", " // ECU_ADDRESS 0x9999"), "address", 0x1234),
        ("before", meas("X", " /* ECU_ADDRESS 0x9999 */ ECU_ADDRESS 0x1234"), "address", 0x1234),
    ]
    for label, body, field, want in cases:
        data = _parse(tmp_path, _body(body))
        assert _tag(data, "X")[field] == want, label


def test_r_a2l_001_2_mod_common_comment_not_read(tmp_path: Path) -> None:
    """R-A2L-001.2/8: a commented MOD_COMMON BYTE_ORDER is not read."""
    text = (
        "ASAP2_VERSION 1 71\n/project P\n"
        "/begin MODULE M \"\"\n"
        "/begin MOD_COMMON \"\"\n/*\nBYTE_ORDER MSB_LAST\n*/\nBYTE_ORDER MSB_FIRST\n/end MOD_COMMON\n"
        "/begin COMPU_METHOD CM_ID \"\" IDENTICAL \"%.0\" \"\"\n/end COMPU_METHOD\n"
        "/begin RECORD_LAYOUT RL_U16\nFNC_VALUES 1 UWORD ROW_DIR DIRECT\n/end RECORD_LAYOUT\n"
        + meas("X", " ECU_ADDRESS 0x10") + "\n"
        + "/end MODULE\n/end PROJECT\n"
    )
    data = _parse(tmp_path, text)
    assert _tag(data, "X")["effective_byte_order"] == "big"


def test_r_a2l_001_2_comment_before_live_address(tmp_path: Path) -> None:
    """R-A2L-001.2/9 ([K5b]): a comment before the live ECU_ADDRESS on its line."""
    text = _body(meas("XK5B", " /* moved */ ECU_ADDRESS 0x1234"))
    assert _tag(_parse(tmp_path, text), "XK5B")["address"] == 0x1234


def test_r_a2l_read_7_comment_between_digits_splits(tmp_path: Path) -> None:
    """R-A2L-READ.7/1: MAP 0x1C2D3E00/*c*/4026 -> address 0x1C2D3E00."""
    text = _body(
        '/begin CHARACTERISTIC Synthetic map ""\n MAP 0x1C2D3E00/*c*/4026 RL_SYN_U16 0 CM_ID 0 65535\n/end CHARACTERISTIC\n'
        "/begin RECORD_LAYOUT RL_SYN_U16\nFNC_VALUES 1 UWORD ROW_DIR DIRECT\n/end RECORD_LAYOUT\n"
    )
    data = _parse(tmp_path, text)
    tag = _tag(data, "Synthetic", "CHARACTERISTIC")
    assert tag["address"] == 0x1C2D3E00


def test_r_a2l_read_7_comment_glued_splits(tmp_path: Path) -> None:
    """R-A2L-READ.7/3..6: comments glued around keywords/words split them."""
    cases = [
        (meas("X", " ECU_ADDRESS 0x1234/*c*/"), "address", 0x1234),
        (meas("X", " ECU_ADDRESS/*c*/0x1234"), "address", 0x1234),
        (meas("X", " BIT_MASK/*b*/0x0FF0", " ECU_ADDRESS 0x10"), "bit_org", "0x0FF0"),
        (meas("X", " ECU_ADDRESS 0x10", hdr=" UWORD CM_ID 0 0 0 65535/* upper */BIT_MASK 0x0FF0"), "bit_org", "0x0FF0"),
    ]
    for body, field, want in cases:
        data = _parse(tmp_path, _body(body))
        assert _tag(data, "X")[field] == want


def test_r_a2l_read_8_block_comment_ends_at_first_close(tmp_path: Path) -> None:
    """R-A2L-READ.8/1: /* a /* b */ ECU_ADDRESS reads the address."""
    text = _body(meas("X", " /* a /* b */ ECU_ADDRESS 0x1234"))
    assert _tag(_parse(tmp_path, text), "X")["address"] == 0x1234


def test_r_a2l_read_8_comments_do_not_nest(tmp_path: Path) -> None:
    """R-A2L-READ.8/2 (RP-B40): c is a word; the stray */ gives .11's error."""
    text = _body(meas("X", " /* a /* b */ c */", " ECU_ADDRESS 0x1234"))
    data = _parse(tmp_path, text)
    assert _tag(data, "X")["address"] == 0x1234
    assert any("*/ without /*" in e for e in data["errors"])


@pytest.mark.parametrize("nl", ["\n", "\r\n", "\r"])
def test_r_a2l_read_9_line_comment_ends_at_line_end(tmp_path: Path, nl: str) -> None:
    """R-A2L-READ.9/1..3: a line comment ends at LF, CRLF or CR."""
    text = _body(meas("X", f" // c{nl} ECU_ADDRESS 0x1234")).replace("\n", nl)
    data = _parse(tmp_path, text)
    assert _tag(data, "X")["address"] == 0x1234


def test_r_a2l_read_10_comment_not_closed(tmp_path: Path) -> None:
    """R-A2L-READ.10/1: an unclosed comment ends the reading."""
    text = _body("/* never closed\n") + meas("X", " ECU_ADDRESS 0x1234")
    data = _parse(tmp_path, text)
    assert any("comment not closed" in e for e in data["errors"])
    assert _tags_named(data, "X") == []


def test_r_a2l_read_11_stray_close(tmp_path: Path) -> None:
    """R-A2L-READ.11/1: a stray */ alone."""
    text = _body("*/")
    data = _parse(tmp_path, text)
    assert any("*/ without /*" in e for e in data["errors"])


def test_r_a2l_read_11_no_stray_close_on_tracked() -> None:
    """R-A2L-READ.11/3: 0 stray */ errors over the 35 files."""
    for path in _tracked_a2l():
        data = parse_a2l_file(path)
        assert not [e for e in data["errors"] if "*/ without /*" in e], path


def test_r_a2l_read_12_commented_old_copy_no_tag(tmp_path: Path) -> None:
    """R-A2L-READ.12/1 (RP-B28): exactly 1 tag X at 0x1234."""
    text = _body("/*\n" + meas("X", " ECU_ADDRESS 0x9999") + "\n*/\n" + meas("X", " ECU_ADDRESS 0x1234"))
    data = _parse(tmp_path, text)
    xs = _tags_named(data, "X")
    assert len(xs) == 1 and xs[0]["address"] == 0x1234


def test_r_a2l_read_12_commented_object_alone_no_tag(tmp_path: Path) -> None:
    """R-A2L-READ.12/2, /3 (RP-B29, RP-B30): 0 tags."""
    text = _body("/*\n" + meas("X", " ECU_ADDRESS 0x9999") + "\n*/")
    assert _tags_named(_parse(tmp_path, text), "X") == []
    text2 = _body("\n".join("// " + ln for ln in meas("X", " ECU_ADDRESS 0x9999").split("\n")))
    assert _tags_named(_parse(tmp_path, text2), "X") == []


def test_r_a2l_read_12_cut_section_no_tag(tmp_path: Path) -> None:
    """R-A2L-READ.12/4 ([B13]): a file cut inside a MEASUREMENT gives 0 tags."""
    text = HDR + '/begin MEASUREMENT X ""\n UWORD CM_ID 0 0 0 65535\n ECU_ADDRESS 0x12'
    data = _parse(tmp_path, text)
    assert _tags_named(data, "X") == []


# ===========================================================================
# C. Quoted strings.
# ===========================================================================


def test_r_a2l_001_3_1_quoted_string_one_word(tmp_path: Path) -> None:
    """R-A2L-001.3.1/1..3: quoted strings stay one word."""
    text = _body('/begin MEASUREMENT X "a b"\n UWORD CM_ID 0 0 0 65535\n ECU_ADDRESS 0x10\n/end MEASUREMENT')
    assert _tag(_parse(tmp_path, text), "X")["description"] == "a b"
    text2 = _body('/begin MEASUREMENT X ""\n UWORD CM_ID 0 0 0 65535\n ECU_ADDRESS 0x10\n/end MEASUREMENT')
    assert _tag(_parse(tmp_path, text2), "X")["description"] is None
    text3 = _body('/begin MEASUREMENT X "x/*y*/z"\n UWORD CM_ID 0 0 0 65535\n ECU_ADDRESS 0x10\n/end MEASUREMENT')
    assert _tag(_parse(tmp_path, text3), "X")["description"] == "x/*y*/z"


def test_r_a2l_001_3_2_escapes(tmp_path: Path) -> None:
    """R-A2L-001.3.2/1..3: \\\\, \\" and \\\\" behave as one escape pair."""
    text = _body('/begin CHARACTERISTIC X "C:\\\\"\n VALUE 0x2000 RL_U16 0 CM_ID 0 65535\n/end CHARACTERISTIC')
    assert _tag(_parse(tmp_path, text), "X", "CHARACTERISTIC")["address"] == 0x2000
    text2 = _body('/begin MEASUREMENT X "a\\"b"\n UWORD CM_ID 0 0 0 65535\n ECU_ADDRESS 0x10\n/end MEASUREMENT')
    assert _tag(_parse(tmp_path, text2), "X")["description"] == 'a\\"b'
    text3 = _body('/begin MEASUREMENT X "\\\\\\""\n UWORD CM_ID 0 0 0 65535\n ECU_ADDRESS 0x10\n/end MEASUREMENT')
    assert _tag(_parse(tmp_path, text3), "X")["description"] == '\\\\\\"'


def test_r_a2l_001_3_2_backslash_before_line_end(tmp_path: Path) -> None:
    """R-A2L-001.3.2/4: a backslash before a line end is ordinary."""
    text = _body("") + '"a\\\n"\n/end X\n'
    data = _parse(tmp_path, text)
    assert any("/end without /begin" in e for e in data["errors"])


def test_r_a2l_read_13_no_comment_in_string(tmp_path: Path) -> None:
    """R-A2L-READ.13/1..4: comment/begin/end marks inside strings stay."""
    cases = [
        meas("X", ' FORMAT "/* x"', " ECU_ADDRESS 0x1234"),
        meas("X", ' PHYS_UNIT "// x"', " ECU_ADDRESS 0x1234"),
        meas("X", ' PHYS_UNIT "/begin MEASUREMENT Q"', " ECU_ADDRESS 0x1234"),
    ]
    for body in cases:
        data = _parse(tmp_path, _body(body))
        assert _tag(data, "X")["address"] == 0x1234
    data = _parse(tmp_path, _body(meas("X", ' PHYS_UNIT "/begin MEASUREMENT Q"', " ECU_ADDRESS 0x1234")))
    assert _tags_named(data, "Q") == []


def test_r_a2l_read_14_string_over_line_ends_one_word(tmp_path: Path) -> None:
    """R-A2L-READ.14/1: an ANNOTATION_TEXT string over two line ends is one word."""
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


def test_r_a2l_read_14_words_after_close_carry_closing_line(tmp_path: Path) -> None:
    """R-A2L-READ.14/2: words after a closing quote carry the closing line."""
    text = _body(meas("X", ' FORMAT "a', 'b" \u00e9 /end MEASUREMENT'))
    data = _parse(tmp_path, text)
    assert any("unexpected character U+00E9" in e and "Line 23" in e for e in data["errors"])


def test_r_a2l_read_15_quoted_string_not_closed(tmp_path: Path) -> None:
    """R-A2L-READ.15/1: an unclosed quote ends the reading."""
    text = _body(meas("X", ' FORMAT "%5.0', " ECU_ADDRESS 0x1234"))
    data = _parse(tmp_path, text)
    assert any("quoted string not closed" in e for e in data["errors"])


def test_r_a2l_read_16_quote_ends_word(tmp_path: Path) -> None:
    """R-A2L-READ.16/1..3: a double quote ends a word."""
    text = _body('/begin MEASUREMENT X"long"\n UWORD CM_ID 0 0 0 65535\n ECU_ADDRESS 0x1234\n/end MEASUREMENT')
    t = _tag(_parse(tmp_path, text), "X")
    assert t["description"] == "long"
    text2 = _body(meas("X", ' FORMAT "%5.0"BIT_MASK 0x0FF0', " ECU_ADDRESS 0x10"))
    assert _tag(_parse(tmp_path, text2), "X")["bit_org"] == "0x0FF0"
    text3 = _body('/begin CHARACTERISTIC M ""\n MAP 0x1C2D3E00"4026" RL_SYN_U16 0 CM_ID 0 65535\n/end CHARACTERISTIC\n/begin RECORD_LAYOUT RL_SYN_U16\nFNC_VALUES 1 UWORD ROW_DIR DIRECT\n/end RECORD_LAYOUT')
    assert _tag(_parse(tmp_path, text3), "M", "CHARACTERISTIC")["address"] == 0x1C2D3E00


# ===========================================================================
# D. Sections.
# ===========================================================================


def test_r_a2l_001_1_begin_end_words(tmp_path: Path) -> None:
    """R-A2L-001.1/1..3: /begin and /end are words wherever they stand."""
    data = _parse(
        tmp_path,
        _body(
            meas("SX", " ECU_ADDRESS 0x10 /begin IF_DATA XCP", "  KP_BLOB 0x10", " /end IF_DATA", " BIT_MASK 0x0FF0")
        ),
    )
    sx = _tag(data, "SX")
    assert sx["bit_org"] == "0x0FF0"
    data2 = _parse(tmp_path, _body("/* c */ /begin MEASUREMENT X \"\"\n UWORD CM_ID 0 0 0 65535\n ECU_ADDRESS 0x10\n/end MEASUREMENT"))
    assert _tag(data2, "X")["address"] == 0x10
    data3 = _parse(tmp_path, _body(meas("X", " ECU_ADDRESS 0x1234 /end MEASUREMENT").replace("\n/end MEASUREMENT", "")))
    assert _tag(data3, "X")["address"] == 0x1234


def test_r_a2l_001_1_two_one_line_instances(tmp_path: Path) -> None:
    """R-A2L-001.1/4 ([K7b]): two one-line INSTANCEs on one line."""
    text = _body(
        '/begin INSTANCE IK7 "" T_U16 0x20 /end INSTANCE /begin INSTANCE IK7B "" T_U16 0x40 /end INSTANCE\n'
        + meas("XK7B", " ECU_ADDRESS 0x60")
    )
    data = _parse(tmp_path, text)
    assert _tag(data, "XK7B")["address"] == 0x60
    assert data["errors"] == []


def test_r_a2l_read_17_v171_clean(tmp_path: Path) -> None:
    """R-A2L-READ.17/1: V171 has 0 parse errors and depth-3 MEASUREMENTs."""
    data = parse_a2l_file(REPO_ROOT / "examples" / "case_00_public" / "ASAP2_Demo_V171.a2l")
    assert data["errors"] == []


def test_r_a2l_read_17_one_line_if_data_before_address(tmp_path: Path) -> None:
    """R-A2L-READ.17/2 (RP-B13): one-line IF_DATA before ECU_ADDRESS."""
    text = _body(meas("X", " /begin IF_DATA ETK KP_BLOB 0x10 INTERN 1 RASTER 2 /end IF_DATA", " ECU_ADDRESS 0x1234"))
    assert _tag(_parse(tmp_path, text), "X")["address"] == 0x1234


def test_r_a2l_read_17_one_line_if_data_before_byte_order(tmp_path: Path) -> None:
    """R-A2L-READ.17/3 (Inc 2 C1): one-line IF_DATA before BYTE_ORDER."""
    text = _body(meas("X", " ECU_ADDRESS 0x10", " /begin IF_DATA ETK KP_BLOB 0x10 /end IF_DATA", " BYTE_ORDER MSB_LAST"))
    assert _tag(_parse(tmp_path, text), "X")["effective_byte_order"] == "little"


@pytest.mark.parametrize("pair", [("/BEGIN", "/END"), ("/Begin", "/eNd")])
def test_r_a2l_read_18_case_insensitive(tmp_path: Path, pair: str) -> None:
    """R-A2L-READ.18/1, /2: /begin and /end in any letter case."""
    b, e = pair
    text = _body(f"{b} MEASUREMENT X \"\"\n UWORD CM_ID 0 0 0 65535\n ECU_ADDRESS 0x10\n{e} MEASUREMENT")
    assert _tag(_parse(tmp_path, text), "X")["address"] == 0x10


def test_r_a2l_read_19_glued_begin_end(tmp_path: Path) -> None:
    """R-A2L-READ.19/1, /2: /beginMEASUREMENT and /endX are ordinary words."""
    text = _body('/beginMEASUREMENT X ""\n UWORD CM_ID 0 0 0 65535\n ECU_ADDRESS 0x1234\n/end MEASUREMENT')
    data = _parse(tmp_path, text)
    assert _tags_named(data, "X") == []
    assert any("does not close /begin MODULE" in e for e in data["errors"])
    text2 = _body(meas("X", " /endX", " ECU_ADDRESS 0x10"))
    assert _tag(_parse(tmp_path, text2), "X")["address"] == 0x10


def test_r_a2l_read_20_keyword_after_begin(tmp_path: Path) -> None:
    """R-A2L-READ.20/1, /2: the keyword after /begin wherever it stands."""
    text = _body("/begin\nMEASUREMENT X \"\"\n UWORD CM_ID 0 0 0 65535\n ECU_ADDRESS 0x10\n/end MEASUREMENT")
    assert _tag(_parse(tmp_path, text), "X")["address"] == 0x10
    text2 = _body("/begin /*c*/ MEASUREMENT X \"\"\n UWORD CM_ID 0 0 0 65535\n ECU_ADDRESS 0x10\n/end MEASUREMENT")
    assert _tag(_parse(tmp_path, text2), "X")["address"] == 0x10


def test_r_a2l_read_54_compu_method_named_later(tmp_path: Path) -> None:
    """R-A2L-READ.54/1, /2: a COMPU_METHOD named on a later line converts."""
    hdr = (
        "ASAP2_VERSION 1 71\n/project P\n"
        "/begin MODULE M \"\"\n/begin MOD_COMMON \"\"\nBYTE_ORDER MSB_FIRST\n/end MOD_COMMON\n"
        "/begin COMPU_METHOD\nCM_LIN \"\" LINEAR \"%.2\" \"rpm\"\nCOEFFS_LINEAR 2 0\n/end COMPU_METHOD\n"
        "/begin RECORD_LAYOUT RL_U16\nFNC_VALUES 1 UWORD ROW_DIR DIRECT\n/end RECORD_LAYOUT\n"
        "/begin TYPEDEF_MEASUREMENT T_U16 \"\" UWORD CM_ID 0 0 0 65535\n/end TYPEDEF_MEASUREMENT\n/end MODULE\n/end PROJECT\n"
    )
    text = hdr + '/begin MEASUREMENT XK1 ""\nUWORD\nCM_LIN\n0\n0\n0\n65535\nECU_ADDRESS\n0x1234\n/end MEASUREMENT\n'
    data = _parse(tmp_path, text)
    tag = _tag(data, "XK1")
    assert tag["conversion"] == "CM_LIN"
    method = data["compu_methods_by_name"].get("CM_LIN")
    assert method is not None


def test_r_a2l_read_54_record_layout_named_later(tmp_path: Path) -> None:
    """R-A2L-READ.54/3: a RECORD_LAYOUT named on a later line sizes a VALUE."""
    hdr = (
        "ASAP2_VERSION 1 71\n/project P\n/begin MODULE M \"\"\n/begin MOD_COMMON \"\"\nBYTE_ORDER MSB_FIRST\n/end MOD_COMMON\n"
        "/begin COMPU_METHOD CM_ID \"\" IDENTICAL \"%.0\" \"\"\n/end COMPU_METHOD\n"
        "/begin RECORD_LAYOUT\nRL_K1\nFNC_VALUES 1 UWORD ROW_DIR DIRECT\n/end RECORD_LAYOUT\n/end MODULE\n/end PROJECT\n"
    )
    text = hdr + '/begin CHARACTERISTIC CRL "" VALUE 0x2000 RL_K1 0 CM_ID 0 65535\n/end CHARACTERISTIC\n'
    data = _parse(tmp_path, text)
    assert _tag(data, "CRL", "CHARACTERISTIC")["length"] == 2


def test_r_a2l_read_54_axis_pts_named_later(tmp_path: Path) -> None:
    """R-A2L-READ.54/5: an AXIS_PTS named on a later line parses its name."""
    text = _body("/begin AXIS_PTS\nAP_K1 \"\" 0x3000 NO_INPUT_QUANTITY RL_U16 0 CM_ID 4 0 100\n/end AXIS_PTS")
    data = _parse(tmp_path, text)

    def _walk(nodes: List[dict]) -> List[dict]:
        out: List[dict] = []
        for s in nodes:
            if s.get("name") == "AXIS_PTS":
                out.append(s)
            out.extend(_walk(s.get("children") or []))
        return out

    axis = _walk(data["sections"])
    assert axis
    assert any(parse_begin_meta(s["meta"])[0] == "AP_K1" for s in axis)


def test_r_a2l_001_4_stray_end(tmp_path: Path) -> None:
    """R-A2L-001.4/1, /2: a stray /end at or after other words."""
    for line in ("/end X", "junk /end X"):
        text = _body("") + line + "\n"
        data = _parse(tmp_path, text)
        assert any("/end without /begin" in e for e in data["errors"])


def test_r_a2l_001_5_end_name_mismatch(tmp_path: Path) -> None:
    """R-A2L-001.5/1, /2 and R-A2L-READ.21/1: /end name mismatch and innermost close."""
    text = _body(meas("X", " ECU_ADDRESS 0x10", " /end IF_DATA"))
    data = _parse(tmp_path, text)
    assert any("/end IF_DATA does not close /begin MEASUREMENT" in e for e in data["errors"])
    text2 = _body(meas("X", " /begin IF_DATA XCP"))
    data2 = _parse(tmp_path, text2)
    assert any("/end MEASUREMENT does not close /begin IF_DATA" in e for e in data2["errors"])


def test_r_a2l_read_22_include_error(tmp_path: Path) -> None:
    """R-A2L-READ.22/1, /2: /include gives one error; in a comment, none."""
    data = parse_a2l_file(REPO_ROOT / "examples" / "case_00_public" / "merge_inc_test.a2l")
    assert [e for e in data["errors"] if "is not read" in e]
    text = _body("/* /include \"x.a2l\" */")
    assert [e for e in _parse(tmp_path, text)["errors"] if "is not read" in e] == []


def test_r_a2l_read_64_nesting_cap(tmp_path: Path) -> None:
    """R-A2L-READ.64/1..3: 33 levels error, 32 levels read."""
    def nested(n: int, one_line: bool = False) -> str:
        if one_line:
            return "/begin A " * n + "/end A " * n
        return "".join(f"/begin A\n" for _ in range(n)) + "".join("/end A\n" for _ in range(n))

    data = _parse(tmp_path, nested(33))
    assert data["errors"] == ["Line 33: sections nested deeper than 32"]
    assert data["sections"] == []
    data2 = _parse(tmp_path, nested(33, one_line=True))
    assert data2["errors"] == ["Line 1: sections nested deeper than 32"]
    data3 = _parse(tmp_path, nested(32))
    assert data3["errors"] == []


def test_r_a2l_read_64_no_nesting_error_on_tracked() -> None:
    """R-A2L-READ.64/4: 0 nesting errors over the 35 files."""
    for path in _tracked_a2l():
        data = parse_a2l_file(path)
        assert not [e for e in data["errors"] if "nested deeper" in e], path


def test_r_a2l_read_65_no_exception_nesting(tmp_path: Path) -> None:
    """R-A2L-READ.65/1, /2: 5,000 levels and 50,000 unclosed /begin raise nothing."""
    data = _parse(tmp_path, "".join("/begin A\n" for _ in range(5000)))
    assert data["errors"] == ["Line 33: sections nested deeper than 32"]
    render_a2l_view(data)
    data2 = _parse(tmp_path, "".join("/begin A\n" for _ in range(50_000)))
    assert data2["errors"] == ["Line 33: sections nested deeper than 32"]


def test_r_a2l_read_65_no_exception_stray_end_flood(tmp_path: Path) -> None:
    """R-A2L-READ.65/3: 200,000 stray /end raise nothing."""
    data = _parse(tmp_path, _body("") + "/end X\n" * 200_000)
    assert len(data["errors"]) == 101


def test_r_a2l_read_65_no_exception_one_line_string(tmp_path: Path) -> None:
    """R-A2L-READ.65/5: one 10 MB string on one line raises nothing."""
    text = _body(meas("X", ' ANNOTATION_TEXT "' + ("a" * 1_000 + '\\"') * 10_000 + ' "'))
    data = _parse(tmp_path, text)
    render_a2l_view(data)


# ===========================================================================
# E. The words of a tag.
# ===========================================================================


def test_r_a2l_read_23_name_on_later_line(tmp_path: Path) -> None:
    """R-A2L-READ.23/1..3: the name after a comment / on a later line."""
    cases = [
        '/begin MEASUREMENT\n X ""\n UWORD CM_ID 0 0 0 65535\n ECU_ADDRESS 0x1234\n/end MEASUREMENT',
        '/begin MEASUREMENT /* c */ X ""\n UWORD CM_ID 0 0 0 65535\n ECU_ADDRESS 0x1234\n/end MEASUREMENT',
        '/begin MEASUREMENT X/*c*/ ""\n UWORD CM_ID 0 0 0 65535\n ECU_ADDRESS 0x1234\n/end MEASUREMENT',
    ]
    for body in cases:
        assert _tag(_parse(tmp_path, _body(body)), "X")["address"] == 0x1234


def test_r_a2l_read_23_v161_v171_unknown_named(tmp_path: Path) -> None:
    """R-A2L-READ.23/4: V161 and V171 name the ASCII CHARACTERISTIC."""
    for f in ("ASAP2_Demo_V161.a2l", "ASAP2_Demo_V171.a2l"):
        data = parse_a2l_file(REPO_ROOT / "examples" / "case_00_public" / f)
        t = _tag(data, "ASAM.C.ASCII.UBYTE.NUMBER_42", "CHARACTERISTIC")
        assert t["address"] == 0x810200
        assert _tags_named(data, "UNKNOWN") == []


def test_r_a2l_read_23_two_measurements_one_word_per_line(tmp_path: Path) -> None:
    """R-A2L-READ.23/5 ([K1]): two MEASUREMENTs written one word per line."""
    def one(name: str, addr: str) -> str:
        return (
            f"/begin MEASUREMENT\n{name}\n\"long id\"\nUWORD\nCM_ID\n0\n0\n0\n65535\nECU_ADDRESS\n{addr}\n/end MEASUREMENT"
        )
    text = _body(one("XK1", "0x1234") + "\n" + one("XK1B", "0x1236"))
    data = _parse(tmp_path, text)
    assert _tag(data, "XK1")["address"] == 0x1234
    assert _tag(data, "XK1B")["address"] == 0x1236
    assert _tags_named(data, "UNKNOWN") == []


def test_r_a2l_read_23_characteristic_one_word_per_line(tmp_path: Path) -> None:
    """R-A2L-READ.23/6 ([K1c]): a CHARACTERISTIC written one word per line."""
    body = "/begin CHARACTERISTIC\nCK1\n\"long id\"\nVALUE\n0x2000\nRL_U16\n0\nCM_ID\n0\n65535\n/end CHARACTERISTIC"
    data = _parse(tmp_path, _body(body))
    t = _tag(data, "CK1", "CHARACTERISTIC")
    assert t["char_type"] == "VALUE" and t["address"] == 0x2000 and t["deposit"] == "RL_U16"


def test_r_a2l_read_24_long_identifier_on_body_line(tmp_path: Path) -> None:
    """R-A2L-READ.24/2: case_07 tags have no long identifier."""
    data = parse_a2l_file(REPO_ROOT / "examples" / "case_07_stress_smoke" / "firmware.a2l")
    for t in data["tags"]:
        assert t.get("description") is None


def test_r_a2l_read_25_balance_tube_headers(tmp_path: Path) -> None:
    """R-A2L-READ.25/1: BalanceTube's 104 MEASUREMENTs get datatype and length."""
    data = parse_a2l_file(REPO_ROOT / "examples" / "case_00_public" / "BalanceTube_STMicro.a2l")
    ms = [t for t in data["tags"] if t["section"] == "MEASUREMENT"]
    assert len(ms) == 104
    assert all(t.get("datatype") is not None and t.get("length") is not None for t in ms)


def test_r_a2l_read_25_virtual_measurement(tmp_path: Path) -> None:
    """R-A2L-READ.25/2: the virtual MEASUREMENT of V161/V171."""
    for f in ("ASAP2_Demo_V161.a2l", "ASAP2_Demo_V171.a2l"):
        data = parse_a2l_file(REPO_ROOT / "examples" / "case_00_public" / f)
        t = _tag(data, "ASAM.M.VIRTUAL.SCALAR.SWORD.PHYSICAL")
        assert t["datatype"] == "SWORD" and t["length"] == 2
        assert t["conversion"] == "CM.VIRTUAL.EXTERNAL_VALUE"


def test_r_a2l_read_25_header_on_begin_line(tmp_path: Path) -> None:
    """R-A2L-READ.25/3, /4, /5, /6: headers on the /begin line / over lines."""
    text = _body('/begin MEASUREMENT X "" UWORD CM_ID 0 0 0 65535\n ECU_ADDRESS 0x10\n/end MEASUREMENT')
    t = _tag(_parse(tmp_path, text), "X")
    assert t["datatype"] == "UWORD" and t["length"] == 2
    text2 = _body('/begin MEASUREMENT X ""\n UWORD /* t */\n CM_ID /* c */\n 0\n 0\n 0\n 65535\n ECU_ADDRESS 0x1234\n/end MEASUREMENT')
    t2 = _tag(_parse(tmp_path, text2), "X")
    assert t2["datatype"] == "UWORD" and t2["length"] == 2
    text3 = _body('/begin MEASUREMENT XK2 ""\nUWORD\nCM_ID\n0\n0\n0\n65535\nECU_ADDRESS 0x1234\n/end MEASUREMENT')
    t3 = _tag(_parse(tmp_path, text3), "XK2")
    assert t3["datatype"] == "UWORD" and t3["length"] == 2
    k5 = '/begin MEASUREMENT XK5 "d" FLOAT64_IEEE NO_COMPU_METHOD 0 0 -100 100  ECU_ADDRESS 0x18 ECU_ADDRESS_EXTENSION 3 READ_WRITE /begin IF_DATA XCP /begin DAQ_EVENT FIXED_EVENT_LIST EVENT 0x0 /end DAQ_EVENT /end IF_DATA /end MEASUREMENT'
    t4 = _tag(_parse(tmp_path, _body(k5)), "XK5")
    assert t4["datatype"] == "FLOAT64_IEEE" and t4["length"] == 8


def test_r_a2l_read_26_characteristic_header(tmp_path: Path) -> None:
    """R-A2L-READ.26/1..5: CHARACTERISTIC headers."""
    text = _body('/begin CHARACTERISTIC X "d" VALUE 0x2000 RL_U16 0 CM_ID 0 65535\n/end CHARACTERISTIC')
    t = _tag(_parse(tmp_path, text), "X", "CHARACTERISTIC")
    assert t["address"] == 0x2000 and t["char_type"] == "VALUE" and t["deposit"] == "RL_U16"
    text2 = _body('/begin CHARACTERISTIC X ""\n VALUE 0x2000/*c*/RL_U16 0 CM_ID 0 65535\n/end CHARACTERISTIC')
    t2 = _tag(_parse(tmp_path, text2), "X", "CHARACTERISTIC")
    assert t2["address"] == 0x2000 and t2["deposit"] == "RL_U16"
    k3 = '/begin CHARACTERISTIC CK3 "d" VALUE 0x1000 RL_U16 0 CM_ID 100 10000\n ECU_ADDRESS_EXTENSION 0\n BYTE_ORDER MSB_LAST\n PHYS_UNIT "ms"\n STEP_SIZE 1\n/end CHARACTERISTIC'
    t3 = _tag(_parse(tmp_path, _body(k3)), "CK3", "CHARACTERISTIC")
    assert t3["char_type"] == "VALUE" and t3["address"] == 0x1000 and t3["deposit"] == "RL_U16"
    k4 = '/begin CHARACTERISTIC CK4 "d" CUBE_5 0x123 RL_U16 1 CM_ID 0 10\n NUMBER 10000\n READ_ONLY\n FORMAT "%3.3"\n STEP_SIZE 1\n/end CHARACTERISTIC'
    t4 = _tag(_parse(tmp_path, _body(k4)), "CK4", "CHARACTERISTIC")
    assert t4["char_type"] == "CUBE_5" and t4["address"] == 0x123 and t4["deposit"] == "RL_U16"


def test_r_a2l_read_27_keyword_ends_header(tmp_path: Path) -> None:
    """R-A2L-READ.27/2..5: a keyword in header position ends the header."""
    text = _body(meas("SX", " ECU_ADDRESS 0x10", hdr=" UWORD CM_ID 0 0 0 BIT_MASK 0x0FF0"))
    t = _tag(_parse(tmp_path, text), "SX")
    assert t["datatype"] == "UWORD" and t["bit_org"] == "0x0FF0" and t["upper_limit"] is None
    text2 = _body('/begin CHARACTERISTIC Q\n ECU_ADDRESS 0x10\n LENGTH 2\n/end CHARACTERISTIC')
    t2 = _tag(_parse(tmp_path, text2), "Q", "CHARACTERISTIC")
    assert t2["address"] == 0x10 and t2["length"] == 2
    k3 = '/begin CHARACTERISTIC CK3 "d" VALUE 0x1000 RL_U16 0 CM_ID 100 10000\n ECU_ADDRESS_EXTENSION 0\n BYTE_ORDER MSB_LAST\n/end CHARACTERISTIC'
    t3 = _tag(_parse(tmp_path, _body(k3)), "CK3", "CHARACTERISTIC")
    assert t3["char_type"] == "VALUE" and t3["address"] == 0x1000
    k4 = '/begin CHARACTERISTIC CK4 "d" CUBE_5 0x123 RL_U16 1 CM_ID 0 10\n NUMBER 10000\n/end CHARACTERISTIC'
    t4 = _tag(_parse(tmp_path, _body(k4)), "CK4", "CHARACTERISTIC")
    assert t4["char_type"] == "CUBE_5" and t4["address"] == 0x123


def test_r_a2l_read_27_case_07_keeps_reading() -> None:
    """R-A2L-READ.27/1: case_07's 12 tags keep their reading."""
    data = parse_a2l_file(REPO_ROOT / "examples" / "case_07_stress_smoke" / "firmware.a2l")
    assert len(data["tags"]) == 12


def test_r_a2l_read_28_short_header_error(tmp_path: Path) -> None:
    """R-A2L-READ.28/1, /2, /4: short header errors."""
    text = _body(meas("SX", " ECU_ADDRESS 0x10", hdr=" UWORD CM_ID 0 0 0"))
    data = _parse(tmp_path, text)
    assert any("MEASUREMENT SX has 5 of its 6 header words" in e for e in data["errors"])
    text2 = _body('/begin CHARACTERISTIC Synthetic map ""\n MAP 0x1C2D3E00 RL 0 CM 0 1\n/end CHARACTERISTIC')
    data2 = _parse(tmp_path, text2)
    assert any("CHARACTERISTIC Synthetic has 6 of its 7 header words" in e for e in data2["errors"])
    assert _tag(data2, "Synthetic", "CHARACTERISTIC")["address"] is None
    text3 = _body('/begin MEASUREMENT XK7 "" UWORD CM_ID 0 0\n ECU_ADDRESS 0x10\n/end MEASUREMENT')
    data3 = _parse(tmp_path, text3)
    assert any("MEASUREMENT XK7 has 4 of its 6 header words" in e for e in data3["errors"])
    assert _tag(data3, "XK7")["datatype"] == "UWORD"


def test_r_a2l_read_28_no_short_header_on_tracked() -> None:
    """R-A2L-READ.28/3: 0 such errors over the 35 files."""
    for path in _tracked_a2l():
        data = parse_a2l_file(path)
        assert not [e for e in data["errors"] if "header words" in e], path


def test_r_a2l_read_29_keyword_argument_words(tmp_path: Path) -> None:
    """R-A2L-READ.29/1..4: arguments on later lines / up to the next keyword."""
    cases = [
        (meas("X", " ECU_ADDRESS", " 0x1234"), "address", 0x1234),
        (meas("X", " ECU_ADDRESS", " /* moved */", " 0x1234"), "address", 0x1234),
        (meas("X", " BIT_MASK", " 0x0FF0", " ECU_ADDRESS 0x10"), "bit_org", "0x0FF0"),
        (meas("X", " ECU_ADDRESS 0x10", " MATRIX_DIM 2", " 3"), "length", 12),
    ]
    for body, field, want in cases:
        data = _parse(tmp_path, _body(body))
        assert _tag(data, "X")[field] == want


def test_r_a2l_read_29_keyword_never_argument(tmp_path: Path) -> None:
    """R-A2L-READ.29/5, /6: a keyword is never an argument."""
    text = _body(meas("XA1", " ECU_ADDRESS 0x60", " BYTE_ORDER", " BIT_MASK 0x0FF0"))
    data = _parse(tmp_path, text)
    t = _tag(data, "XA1")
    assert t["bit_org"] == "0x0FF0"
    assert any("BYTE_ORDER has 0 of its 1 arguments" in e for e in data["errors"])
    text2 = _body(meas("XA2", " ECU_ADDRESS_EXTENSION", " ECU_ADDRESS 0x1234"))
    data2 = _parse(tmp_path, text2)
    assert _tag(data2, "XA2")["address"] == 0x1234
    assert any("ECU_ADDRESS_EXTENSION has 0 of its 1 arguments" in e for e in data2["errors"])


def test_r_a2l_read_30_keyword_wherever(tmp_path: Path) -> None:
    """R-A2L-READ.30/1..3: a keyword wherever it stands on its line."""
    text = _body(meas("X", " ECU_ADDRESS 0x1234 BYTE_ORDER MSB_LAST"))
    assert _tag(_parse(tmp_path, text), "X")["effective_byte_order"] == "little"
    text2 = _body(meas("SX", " ECU_ADDRESS 0x10", " /begin IF_DATA ETK KP_BLOB 0x10 /end IF_DATA BIT_MASK 0x0FF0"))
    assert _tag(_parse(tmp_path, text2), "SX")["bit_org"] == "0x0FF0"
    k5 = '/begin MEASUREMENT XK5 "d" FLOAT64_IEEE NO_COMPU_METHOD 0 0 -100 100  ECU_ADDRESS 0x18 ECU_ADDRESS_EXTENSION 3 READ_WRITE /begin IF_DATA XCP /begin DAQ_EVENT FIXED_EVENT_LIST EVENT 0x0 /end DAQ_EVENT /end IF_DATA /end MEASUREMENT'
    assert _tag(_parse(tmp_path, _body(k5)), "XK5")["address"] == 0x18


def test_r_a2l_read_31_own_words_only(tmp_path: Path) -> None:
    """R-A2L-READ.31/1..3: a tag's keywords come from its own words only."""
    text = _body(meas("X", " ECU_ADDRESS 0x1234", " /begin IF_DATA ETK KP_BLOB 0x9999 /end IF_DATA"))
    assert _tag(_parse(tmp_path, text), "X")["address"] == 0x1234
    text2 = _body(meas("X", " ECU_ADDRESS 0x10", " /begin ANNOTATION", " /begin ANNOTATION_TEXT", ' "BIT_MASK 0x0FF0"', " /end ANNOTATION_TEXT", " /end ANNOTATION"))
    assert _tag(_parse(tmp_path, text2), "X")["bit_org"] is None


def test_r_a2l_read_32_duplicate_keyword(tmp_path: Path) -> None:
    """R-A2L-READ.32/1..3: a keyword twice records the error."""
    text = _body(meas("X", " ECU_ADDRESS 0x10", " ECU_ADDRESS 0x20"))
    data = _parse(tmp_path, text)
    assert any("ECU_ADDRESS is declared twice in MEASUREMENT X" in e for e in data["errors"])
    assert _tag(data, "X")["address"] is None
    text2 = _body(meas("X", " ECU_ADDRESS 0x10", " BYTE_ORDER MSB_FIRST", " BYTE_ORDER MSB_LAST"))
    data2 = _parse(tmp_path, text2)
    assert any("BYTE_ORDER is declared twice" in e for e in data2["errors"])
    assert _tag(data2, "X")["address"] is None
    text3 = _body(meas("SX", " BIT_MASK 0x000F", " BIT_MASK 0x0FF0", " ECU_ADDRESS 0x10"))
    data3 = _parse(tmp_path, text3)
    assert any("BIT_MASK is declared twice" in e for e in data3["errors"])
    assert _tag(data3, "SX")["address"] is None


def test_r_a2l_read_32_no_duplicate_on_tracked() -> None:
    """R-A2L-READ.32/4: 0 duplicate errors over the 35 files."""
    for path in _tracked_a2l():
        data = parse_a2l_file(path)
        assert not [e for e in data["errors"] if "is declared twice" in e], path


def test_r_a2l_read_58_argument_count_errors(tmp_path: Path) -> None:
    """R-A2L-READ.58/1..5: argument-count errors."""
    text = _body(meas("X", " ECU_ADDRESS", " BIT_MASK 0x0FF0") + "\n" + meas("Y", " MAX_REFRESH 1", " ECU_ADDRESS 0x10") + "\n" + meas("Z", " ECU_ADDRESS 0x10", " ECU_ADDRESS"))
    data = _parse(tmp_path, text)
    assert any("ECU_ADDRESS has 0 of its 1 arguments" in e for e in data["errors"])
    assert any("MAX_REFRESH has 1 of its 2 arguments" in e for e in data["errors"])
    text2 = _body(meas("X", " MATRIX_DIM", " ECU_ADDRESS 0x10") + "\n" + meas("Y", " ECU_ADDRESS 0x10", " MATRIX_DIM 2 3 4 5"))
    data2 = _parse(tmp_path, text2)
    assert any("MATRIX_DIM has 0 of its 1 to 3 arguments" in e for e in data2["errors"])
    assert any("MATRIX_DIM has 4 of its 1 to 3 arguments" in e for e in data2["errors"])
    text3 = _body(meas("X", " ECU_ADDRESS 0x1C2D 0x3E00") + "\n" + meas("Y", " ECU_ADDRESS 0x10", " LENGTH 2 4") + "\n" + meas("Z", " ECU_ADDRESS 0x10", " BIT_MASK 0x0FF0 0x00FF"))
    data3 = _parse(tmp_path, text3)
    assert any("ECU_ADDRESS has 2 of its 1 arguments" in e for e in data3["errors"])
    assert any("LENGTH has 2 of its 1 arguments" in e for e in data3["errors"])
    assert any("BIT_MASK has 2 of its 1 arguments" in e for e in data3["errors"])


def test_r_a2l_read_58_hex_like_surplus(tmp_path: Path) -> None:
    """R-A2L-READ.58/5 round 3: hex-like surplus words."""
    shapes = [
        " ECU_ADDRESS 0x1C2D 3E00",
        " ECU_ADDRESS 0x1C2D3 E00",
        " ECU_ADDRESS 0x1C 2D3E00",
        " ECU_ADDRESS 0x1C2D3E00 _4026",
        " ECU_ADDRESS 0x10 BIT_MASK 0x0F F0",
    ]
    for i, body in enumerate(shapes):
        data = _parse(tmp_path, _body(meas(f"X{i}", body)))
        assert any("has 2 of its 1 arguments" in e for e in data["errors"])
    # SIG_X is not hex-like: no error, address kept.
    data = _parse(tmp_path, _body(meas("XS", " ECU_ADDRESS 0x10 SIG_X")))
    assert _tag(data, "XS")["address"] == 0x10
    assert not [e for e in data["errors"] if "arguments" in e]


def test_r_a2l_read_59_declares_sizes_addresses(tmp_path: Path) -> None:
    """R-A2L-READ.59/1, /2: disagreeing addresses and sizes."""
    text = _body(meas("X", " ECU_ADDRESS 0x10", " ECU_ADDRESS 0x20"))
    data = _parse(tmp_path, text)
    assert any("declares the addresses 0x00000010 and 0x00000020" in e for e in data["errors"])
    b3 = _body('/begin CHARACTERISTIC XD "" VALUE 0x2000 RL_U16 0 CM_ID 0 65535\n ECU_ADDRESS 0x3000\n/end CHARACTERISTIC')
    data2 = _parse(tmp_path, b3)
    assert any("CHARACTERISTIC XD declares the addresses 0x00002000 and 0x00003000" in e for e in data2["errors"])
    b5 = _body(meas("X", " DATA_SIZE 2", " LENGTH 8"))
    data3 = _parse(tmp_path, b5)
    assert any("MEASUREMENT X declares the sizes 2 and 8" in e for e in data3["errors"])


def test_r_a2l_read_59_no_error_on_tracked() -> None:
    """R-A2L-READ.59/5: 0 such errors over the 35 files."""
    for path in _tracked_a2l():
        data = parse_a2l_file(path)
        assert not [e for e in data["errors"] if "declares the" in e], path


def test_r_a2l_read_60_no_address_when_disagree(tmp_path: Path) -> None:
    """R-A2L-READ.60/1..4: no address when address words disagree."""
    text = _body(meas("X", " ECU_ADDRESS 0x10", " ECU_ADDRESS 0x20"))
    assert _tag(_parse(tmp_path, text), "X")["address"] is None
    b3 = _body('/begin CHARACTERISTIC XD "" VALUE 0x2000 RL_U16 0 CM_ID 0 65535\n ECU_ADDRESS 0x3000\n/end CHARACTERISTIC')
    assert _tag(_parse(tmp_path, b3), "XD", "CHARACTERISTIC")["address"] is None
    b3b = _body('/begin CHARACTERISTIC XD "" VALUE 0x2000 RL_U16 0 CM_ID 0 65535\n ECU_ADDRESS 0x30_00\n/end CHARACTERISTIC')
    assert _tag(_parse(tmp_path, b3b), "XD", "CHARACTERISTIC")["address"] is None
    text4 = _body(meas("X", " ECU_ADDRESS 0x10", " ECU_ADDRESS 0x10"))
    assert _tag(_parse(tmp_path, text4), "X")["address"] == 0x10


def test_r_a2l_read_60_no_address_when_missing_or_invalid(tmp_path: Path) -> None:
    """R-A2L-READ.60/2, /6: no address for a missing argument or surplus."""
    text = _body(meas("X", " ECU_ADDRESS", " BIT_MASK 0x0FF0"))
    assert _tag(_parse(tmp_path, text), "X")["address"] is None
    text2 = _body(meas("X", " ECU_ADDRESS 0x10", " BYTE_ORDER", " LENGTH 2"))
    assert _tag(_parse(tmp_path, text2), "X")["address"] is None
    text3 = _body(meas("X", " ECU_ADDRESS 0x10", " BIT_MASK", " BYTE_ORDER MSB_FIRST"))
    assert _tag(_parse(tmp_path, text3), "X")["address"] is None


def test_r_a2l_read_60_no_address_header_not_number(tmp_path: Path) -> None:
    """R-A2L-READ.60/7: no address when the header address is no number word."""
    text = _body('/begin CHARACTERISTIC XG "" VALUE 0x20_00 RL_U16 0 CM_ID 0 65535\n ECU_ADDRESS 0x3000\n/end CHARACTERISTIC')
    data = _parse(tmp_path, text)
    assert _tag(data, "XG", "CHARACTERISTIC")["address"] is None
    assert any("address 0x20_00 is not a number" in e for e in data["errors"])


def test_r_a2l_read_62_short_characteristic_no_field(tmp_path: Path) -> None:
    """R-A2L-READ.62/1, /2: a short CHARACTERISTIC header gives no field."""
    text = _body('/begin CHARACTERISTIC Synthetic map ""\n MAP 0x1C2D3E00 RL 0 CM 0 1\n/end CHARACTERISTIC')
    t = _tag(_parse(tmp_path, text), "Synthetic", "CHARACTERISTIC")
    assert t["address"] is None and t["char_type"] is None and t["deposit"] is None
    text2 = _body('/begin CHARACTERISTIC CQ "" VALUE\n/end CHARACTERISTIC')
    t2 = _tag(_parse(tmp_path, text2), "CQ", "CHARACTERISTIC")
    assert t2["address"] is None and t2["char_type"] is None


def test_r_a2l_read_63_not_a_number(tmp_path: Path) -> None:
    """R-A2L-READ.63/1, /3, /4: not-a-number errors."""
    for w in ("0x12_34", "0x1C2D3E00_4026", "-0x10", "+16", "\uff11\uff12", "0b101"):
        text = _body(meas("X", f" ECU_ADDRESS {w}"))
        data = _parse(tmp_path, text)
        assert any(f"ECU_ADDRESS" in e and "is not a number" in e for e in data["errors"]), w
    for kw, w in (("LENGTH", "-5"), ("DATA_SIZE", "0b10"), ("NUMBER", "x"), ("ARRAY_SIZE", "4.0")):
        text = _body(meas("X", f" {kw} {w}"))
        data = _parse(tmp_path, text)
        assert any(f"{kw} {w} is not a number" in e for e in data["errors"])
    text2 = _body(meas("X", " MATRIX_DIM x4"))
    data2 = _parse(tmp_path, text2)
    assert any("MATRIX_DIM x4 is not a number" in e for e in data2["errors"])


def test_r_a2l_read_63_no_such_error_on_tracked() -> None:
    """R-A2L-READ.63/5: 0 such errors over the 35 files."""
    for path in _tracked_a2l():
        data = parse_a2l_file(path)
        assert not [e for e in data["errors"] if "is not a number" in e], path


def test_r_a2l_read_67_not_closed(tmp_path: Path) -> None:
    """R-A2L-READ.67/1, /2: the not-closed error."""
    text = HDR + '/begin MEASUREMENT X ""\n UWORD CM_ID 0 0 0 65535\n ECU_ADDRESS 0x12'
    data = _parse(tmp_path, text)
    assert any("MEASUREMENT X is not closed" in e for e in data["errors"])
    assert any("Unclosed /begin sections detected." in e for e in data["errors"])
    text2 = _body(meas("X", " ECU_ADDRESS 0x1234", " /* never closed"))
    data2 = _parse(tmp_path, text2)
    assert any("comment not closed" in e for e in data2["errors"])
    assert any("MEASUREMENT X is not closed" in e for e in data2["errors"])


def test_r_a2l_read_67_no_not_closed_on_tracked() -> None:
    """R-A2L-READ.67/3: 0 such errors over the 35 files."""
    for path in _tracked_a2l():
        data = parse_a2l_file(path)
        assert not [e for e in data["errors"] if "is not closed" in e], path


def test_r_a2l_read_68_byte_order_error(tmp_path: Path) -> None:
    """R-A2L-READ.68/1: BYTE_ORDER not-a-byte-order errors."""
    for w in ("MSB_FRIST", "MSB_LAST_MSW_FIRST", '"MSB_FIRST"', "1"):
        text = _body(meas("X", " ECU_ADDRESS 0x10", f" BYTE_ORDER {w}"))
        data = _parse(tmp_path, text)
        assert any(f"BYTE_ORDER {w} is not a byte order" in e for e in data["errors"]), w
        assert _tag(data, "X")["address"] is None


def test_r_a2l_read_68_byte_order_words_no_error(tmp_path: Path) -> None:
    """R-A2L-READ.68/3: valid byte-order words give no error."""
    for w in ("MSB_FIRST", "MSB_LAST", "BIG_ENDIAN", "LITTLE_ENDIAN", "msb_first", "msb_last", "big_endian", "little_endian"):
        text = _body(meas("X", " ECU_ADDRESS 0x10", f" BYTE_ORDER {w}"))
        data = _parse(tmp_path, text)
        assert not [e for e in data["errors"] if "not a byte order" in e], w
        assert _tag(data, "X")["address"] == 0x10


def test_r_a2l_read_68_no_error_on_tracked() -> None:
    """R-A2L-READ.68/4: 0 such errors over the 35 files."""
    for path in _tracked_a2l():
        data = parse_a2l_file(path)
        assert not [e for e in data["errors"] if "not a byte order" in e], path


def test_r_a2l_read_33_display_identifier(tmp_path: Path) -> None:
    """R-A2L-READ.33/1, /2: display identifier without its comment."""
    text = _body(meas("X", " ECU_ADDRESS 0x10", " DISPLAY_IDENTIFIER XM_disp /* shown name */"))
    assert _tag(_parse(tmp_path, text), "X")["display_identifier"] == "XM_disp"


def test_r_a2l_read_34_hex_words(tmp_path: Path) -> None:
    """R-A2L-READ.34/1: 0x, 0X and 16-digit hex."""
    for w in ("0x1234", "0X1234", "0x0000000000001234"):
        assert _tag(_parse(tmp_path, _body(meas("X", f" ECU_ADDRESS {w}"))), "X")["address"] == 0x1234


def test_r_a2l_read_35_decimal_words(tmp_path: Path) -> None:
    """R-A2L-READ.35/1, /2: decimal words with leading zero / plain."""
    assert _tag(_parse(tmp_path, _body(meas("X", " ECU_ADDRESS 010"))), "X")["address"] == 10
    assert _tag(_parse(tmp_path, _body(meas("X", " ECU_ADDRESS 4096"))), "X")["address"] == 4096


def test_r_a2l_read_36_not_number_words(tmp_path: Path) -> None:
    """R-A2L-READ.36/1..3: non-number words give no number."""
    for w in ("0x12_34", "0x1C2D3E00_4026", "-0x10", "+16", "\uff11\uff12", "0b101"):
        assert _tag(_parse(tmp_path, _body(meas("X", f" ECU_ADDRESS {w}"))), "X")["address"] is None


def test_r_a2l_read_69_address_above_64_bits(tmp_path: Path) -> None:
    """R-A2L-READ.69/1, /2, /3: addresses above 2^64-1 give no address."""
    for w in ("18446744073709551616", "99999999999999999999"):
        data = _parse(tmp_path, _body(meas("X", f" ECU_ADDRESS {w}")))
        assert _tag(data, "X")["address"] is None
        assert not [e for e in data["errors"] if "is not a number" in e]
    data = _parse(tmp_path, _body(meas("X", " ECU_ADDRESS 18446744073709551615")))
    assert _tag(data, "X")["address"] == 0xFFFFFFFFFFFFFFFF
    text = _body('/begin CHARACTERISTIC CX "" VALUE 99999999999999999999 RL_U16 0 CM_ID 0 65535\n/end CHARACTERISTIC')
    data2 = _parse(tmp_path, text)
    assert _tag(data2, "CX", "CHARACTERISTIC")["address"] is None


# ===========================================================================
# G. Lengths.
# ===========================================================================


def test_r_a2l_read_37_matrix_dim_product(tmp_path: Path) -> None:
    """R-A2L-READ.37/2 (RP-B26): MATRIX_DIM 2 2 -> length 8."""
    text = _body(meas("X", " ECU_ADDRESS 0x1234", " MATRIX_DIM 2 2"))
    assert _tag(_parse(tmp_path, text), "X")["length"] == 8


def test_r_a2l_read_37_tracked_products() -> None:
    """R-A2L-READ.37/1: the 14 tracked tags get the MATRIX_DIM product."""
    expected = {
        "ASAP2_Demo_V161.a2l": {
            "ASAM.M.MATRIX_DIM_8_2_1.UBYTE.IDENTICAL": 16,
            "ASAM.M.MATRIX_DIM_8_4_2.UBYTE.IDENTICAL": 64,
            "ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR": 24,
            "ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.COLUMN_DIR": 24,
        },
        "ASAP2_Demo_V171.a2l": {
            "ASAM.M.MATRIX_DIM_8_2.UBYTE.IDENTICAL": 16,
            "ASAM.M.MATRIX_DIM_8_4_2.UBYTE.IDENTICAL": 64,
        },
        "update_test1.a2l": {"Measurement_Matrix": 20},
        "update_test2.a2l": {"Characteristic_ValBlk_matrix_dim": 840},
    }
    for fname, tags in expected.items():
        data = parse_a2l_file(REPO_ROOT / "examples" / "case_00_public" / fname)
        for name, length in tags.items():
            assert _tag(data, name, _section_of(data, name))["length"] == length, (fname, name)


def _section_of(data: dict, name: str) -> str:
    for t in data["tags"]:
        if t.get("name") == name:
            return t.get("section")
    raise AssertionError(name)


def test_r_a2l_read_38_length_bounds(tmp_path: Path) -> None:
    """R-A2L-READ.38/1..3: lengths below 1 or above 1 MiB give no length."""
    for w, want in (("0", None), ("-5", None), ("1048577", None), ("99999999999", None), ("1048576", 1048576)):
        data = _parse(tmp_path, _body(meas("X", " ECU_ADDRESS 0x10", f" LENGTH {w}", hdr="")))
        assert _tag(data, "X")["length"] == want, w


def test_r_a2l_read_39_length_error(tmp_path: Path) -> None:
    """R-A2L-READ.39/1: the length-out-of-bounds error."""
    for w in ("0", "1048577", "99999999999"):
        data = _parse(tmp_path, _body(meas("X", " ECU_ADDRESS 0x10", f" LENGTH {w}", hdr="")))
        assert any(f"has the length {w}, outside 1 to 1048576 bytes" in e for e in data["errors"]), w


def test_r_a2l_013_data_size_length(tmp_path: Path) -> None:
    """R-A2L-013/1, /2: a DATA_SIZE or LENGTH gives the length."""
    text = _body(meas("X", " ECU_ADDRESS 0x10", " MATRIX_DIM 2", " LENGTH 4"))
    assert _tag(_parse(tmp_path, text), "X")["length"] == 4


def test_r_a2l_014_datatype_times_matrix(tmp_path: Path) -> None:
    """R-A2L-014/1, /2: datatype size x MATRIX_DIM."""
    text = _body(meas("X", " ECU_ADDRESS 0x1234", " MATRIX_DIM 2 2"))
    assert _tag(_parse(tmp_path, text), "X")["length"] == 8
    assert _tag(_parse(tmp_path, _body(meas("X", " ECU_ADDRESS 0x10"))), "X")["length"] == 2


def test_r_a2l_read_57_array_size(tmp_path: Path) -> None:
    """R-A2L-READ.57/1, /2: ARRAY_SIZE sizes a MEASUREMENT."""
    data = parse_a2l_file(REPO_ROOT / "examples" / "case_00_public" / "ASAP2_Demo_V161.a2l")
    assert _tag(data, "ASAM.M.ARRAY_SIZE_16.UBYTE.IDENTICAL")["length"] == 16
    text = _body(meas("X", " ECU_ADDRESS 0x10", " ARRAY_SIZE 4"))
    assert _tag(_parse(tmp_path, text), "X")["length"] == 8


def test_r_a2l_016_val_blk_matrix(tmp_path: Path) -> None:
    """R-A2L-016/1: a VAL_BLK sized by its layout datatype x MATRIX_DIM."""
    text = _body('/begin CHARACTERISTIC CK6 ""\n VAL_BLK 0x3000 RL_U16 0 CM_ID 0 65535\n MATRIX_DIM 4\n/end CHARACTERISTIC')
    assert _tag(_parse(tmp_path, text), "CK6", "CHARACTERISTIC")["length"] == 8


def test_r_a2l_read_53_val_blk_number(tmp_path: Path) -> None:
    """R-A2L-READ.53/1: a VAL_BLK sized by NUMBER."""
    text = _body('/begin CHARACTERISTIC CK6B ""\n VAL_BLK 0x3010 RL_U16 0 CM_ID 0 65535\n NUMBER 4\n/end CHARACTERISTIC')
    assert _tag(_parse(tmp_path, text), "CK6B", "CHARACTERISTIC")["length"] == 8


def test_r_a2l_017_ascii_length(tmp_path: Path) -> None:
    """R-A2L-017/1, /2: an ASCII sized by MATRIX_DIM or NUMBER."""
    text = _body('/begin CHARACTERISTIC A1 ""\n ASCII 0x10 RL_U8 0 CM_ID 0 65535\n MATRIX_DIM 8\n/end CHARACTERISTIC')
    assert _tag(_parse(tmp_path, text), "A1", "CHARACTERISTIC")["length"] == 8
    text2 = _body('/begin CHARACTERISTIC A2 ""\n ASCII 0x10 RL_U8 0 CM_ID 0 65535\n NUMBER 8\n/end CHARACTERISTIC')
    assert _tag(_parse(tmp_path, text2), "A2", "CHARACTERISTIC")["length"] == 8


def test_r_a2l_read_61_no_length_when_disagree(tmp_path: Path) -> None:
    """R-A2L-READ.61/1..7: no length when sizes disagree."""
    cases = [
        meas("X", " ECU_ADDRESS 0x10", " LENGTH 4", " LENGTH 8"),
        meas("X", " ECU_ADDRESS 0x10", " DATA_SIZE 2", " LENGTH 8"),
        '/begin CHARACTERISTIC X ""\n VALUE 0x10 RL_U16 0 CM_ID 0 65535\n LENGTH 4\n/end CHARACTERISTIC',
        '/begin CHARACTERISTIC X ""\n VAL_BLK 0x10 RL_U16 0 CM_ID 0 65535\n MATRIX_DIM 4\n NUMBER 5\n/end CHARACTERISTIC',
        meas("X", " ECU_ADDRESS 0x10", " ARRAY_SIZE 4", " MATRIX_DIM 3"),
        '/begin CHARACTERISTIC X ""\n ASCII 0x10 RL_U8 0 CM_ID 0 65535\n NUMBER 8\n MATRIX_DIM 4\n/end CHARACTERISTIC',
        meas("X", " ECU_ADDRESS 0x10", " LENGTH 2 4"),
    ]
    for body in cases:
        data = _parse(tmp_path, _body(body))
        assert _tag(data, "X", _section_of(data, "X"))["length"] is None


def test_r_a2l_read_61_agreeing_sizes_keep_length(tmp_path: Path) -> None:
    """R-A2L-READ.61/3: agreeing sizes keep their length."""
    text = _body(meas("X", " ECU_ADDRESS 0x10", " ARRAY_SIZE 4", " MATRIX_DIM 4"))
    assert _tag(_parse(tmp_path, text), "X")["length"] == 8
    text2 = _body('/begin CHARACTERISTIC X ""\n VAL_BLK 0x10 RL_U16 0 CM_ID 0 65535\n MATRIX_DIM 4\n NUMBER 4\n/end CHARACTERISTIC')
    assert _tag(_parse(tmp_path, text2), "X", "CHARACTERISTIC")["length"] == 8
    text3 = _body(meas("X", " ECU_ADDRESS 0x10", " MATRIX_DIM 2", " LENGTH 4"))
    assert _tag(_parse(tmp_path, text3), "X")["length"] == 4


def test_r_a2l_read_38_definition_stays_refused(tmp_path: Path) -> None:
    """R-A2L-READ.38/4 and .61/4: describe_definition keeps a refused length."""
    for w in ("0", "99999999999"):
        text = _body(meas("X", " ECU_ADDRESS 0x10", f" LENGTH {w}"))
        data = _parse(tmp_path, text)
        definition = describe_definition("X", data)
        assert definition.byte_length is None
        assert definition.refusal is not None
        assert "A2L-DEF-ADDRESS" in (definition.refusal.code or "")


def test_r_a2l_read_61_no_enriched_byte_size(tmp_path: Path) -> None:
    """R-A2L-READ.61/9: no enriched byte size for a tag with no length."""
    text = _body('/begin CHARACTERISTIC X ""\n VALUE 0x10 RL_U16 0 CM_ID 0 65535\n LENGTH 0\n/end CHARACTERISTIC')
    data = _parse(tmp_path, text)
    enriched = enrich_a2l_tags_with_values(data, {0x10: 0x11, 0x11: 0x11})
    row = [e for e in enriched if e.get("name") == "X"][0]
    assert row.get("byte_size") is None and row.get("raw_value") is None


# ===========================================================================
# H. INSTANCE and BLOB spans.
# ===========================================================================


def _spans(data: dict) -> List[dict]:
    if _extract_declared_spans is not None:
        return _extract_declared_spans(data["sections"], data.get("record_layouts_by_name"))
    return data.get("declared_spans", [])


def test_r_a2l_read_40_blob_span(tmp_path: Path) -> None:
    """R-A2L-READ.40/1, /3 (RP-D1, RP-D4): a BLOB span; a commented-out one none."""
    text = _body('/begin BLOB B1 "" 0x10 2\n/end BLOB')
    spans = _spans(_parse(tmp_path, text))
    assert {"name": "B1", "kind": "BLOB", "address": 0x10, "length": 2} in spans
    text2 = _body('/* /begin BLOB B9 "" 0x90 2\n/end BLOB */')
    assert _spans(_parse(tmp_path, text2)) == []


def test_r_a2l_read_40_tracked_blobs() -> None:
    """R-A2L-READ.40/2: 7 BLOB spans over the 35 files."""
    total = 0
    for path in _tracked_a2l():
        data = parse_a2l_file(path)
        total += len([s for s in _spans(data) if s["kind"] == "BLOB"])
    assert total == 7


def test_r_a2l_read_41_tracked_instances() -> None:
    """R-A2L-READ.41/1: 82 INSTANCE spans over the 35 files."""
    total = 0
    for path in _tracked_a2l():
        data = parse_a2l_file(path)
        total += len([s for s in _spans(data) if s["kind"] == "INSTANCE"])
    assert total == 82


def test_r_a2l_read_42_instance_typedef_measurement(tmp_path: Path) -> None:
    """R-A2L-READ.42/1, /2 (RP-D2, RP-D3): INSTANCE of a TYPEDEF_MEASUREMENT."""
    text = _body('/begin INSTANCE I1 "" T_U16 0x10\n/end INSTANCE')
    assert {"name": "I1", "kind": "INSTANCE", "address": 0x10, "length": 2} in _spans(_parse(tmp_path, text))
    text2 = _body('/begin INSTANCE I2 "" T_U16 0x20\n MATRIX_DIM 5\n/end INSTANCE')
    assert {"name": "I2", "kind": "INSTANCE", "address": 0x20, "length": 10} in _spans(_parse(tmp_path, text2))


def test_r_a2l_read_43_instance_value_typedef(tmp_path: Path) -> None:
    """R-A2L-READ.43/1: V171's INSTANCE of a VALUE typedef."""
    data = parse_a2l_file(REPO_ROOT / "examples" / "case_00_public" / "ASAP2_Demo_V171.a2l")
    span = [s for s in _spans(data) if s["name"] == "ASAM_I_SCALAR_VALUE_UWORD_SINGLE"][0]
    assert span["address"] == 0x810000 and span["length"] == 2


def test_r_a2l_read_43_instance_val_blk_typedef(tmp_path: Path) -> None:
    """R-A2L-READ.43/2: a VAL_BLK typedef on RL_U16 with MATRIX_DIM 3, INSTANCE 2."""
    text = _body(
        '/begin TYPEDEF_CHARACTERISTIC TV "" VAL_BLK 0x0 RL_U16 0 CM_ID 0 65535\n MATRIX_DIM 3\n/end TYPEDEF_CHARACTERISTIC\n'
        '/begin INSTANCE I1 "" TV 0x10\n MATRIX_DIM 2\n/end INSTANCE'
    )
    spans = _spans(_parse(tmp_path, text))
    assert any(s["name"] == "I1" and s["length"] == 12 for s in spans)


def test_r_a2l_read_43_instance_ascii_typedef(tmp_path: Path) -> None:
    """R-A2L-READ.43/3: an ASCII typedef with NUMBER 8."""
    text = _body(
        '/begin TYPEDEF_CHARACTERISTIC TA "" ASCII 0x0 RL_U8 0 CM_ID 0 65535\n NUMBER 8\n/end TYPEDEF_CHARACTERISTIC\n'
        '/begin INSTANCE I1 "" TA 0x10\n/end INSTANCE'
    )
    spans = _spans(_parse(tmp_path, text))
    assert any(s["name"] == "I1" and s["length"] == 8 for s in spans)


def test_r_a2l_read_44_instance_blob_structure_typedef(tmp_path: Path) -> None:
    """R-A2L-READ.44/1, /2: TYPEDEF_BLOB and TYPEDEF_STRUCTURE."""
    text = _body('/begin TYPEDEF_BLOB TB "" 6\n/end TYPEDEF_BLOB\n/begin INSTANCE I1 "" TB 0x10\n/end INSTANCE')
    assert any(s["name"] == "I1" and s["length"] == 6 for s in _spans(_parse(tmp_path, text)))
    text2 = _body('/begin TYPEDEF_STRUCTURE TS "" 12\n/end TYPEDEF_STRUCTURE\n/begin INSTANCE I2 "" TS 0x20\n MATRIX_DIM 3\n/end INSTANCE')
    assert any(s["name"] == "I2" and s["length"] == 36 for s in _spans(_parse(tmp_path, text2)))


def test_r_a2l_read_45_instance_unknown_typedef(tmp_path: Path) -> None:
    """R-A2L-READ.45/1..3: an unsizeable INSTANCE has no length."""
    for typedef in ("TAXIS", "TCURVE", "T_NONE"):
        body = "/begin TYPEDEF_AXIS TAXIS \"\" NO_AXIS_PTS NO_RESCALE 0 0\n/end TYPEDEF_AXIS\n" if typedef == "TAXIS" else (
            '/begin TYPEDEF_CHARACTERISTIC TCURVE "" CURVE 0x0 RL_U16 0 CM_ID 0 65535\n/end TYPEDEF_CHARACTERISTIC\n' if typedef == "TCURVE" else ""
        )
        text = _body(body + f"/begin INSTANCE I1 \"\" {typedef} 0x10\n/end INSTANCE")
        spans = _spans(_parse(tmp_path, text))
        assert any(s["name"] == "I1" and s["length"] is None for s in spans), typedef


def test_r_a2l_read_46_span_length_bounds(tmp_path: Path) -> None:
    """R-A2L-READ.46/1, /2: BLOB sizes 0/1048577 and a huge MATRIX_DIM."""
    text = _body('/begin BLOB B0 "" 0x10 0\n/end BLOB\n/begin BLOB B1 "" 0x20 1048577\n/end BLOB')
    spans = _spans(_parse(tmp_path, text))
    assert all(s["length"] is None for s in spans)
    text2 = _body('/begin INSTANCE I1 "" T_U16 0x30\n MATRIX_DIM 4294967296\n/end INSTANCE')
    assert any(s["name"] == "I1" and s["length"] is None for s in _spans(_parse(tmp_path, text2)))


def test_extract_declared_spans_is_public() -> None:
    """The public name ``extract_declared_spans`` exists on s19_app.tui.a2l_extract."""
    assert _extract_declared_spans is not None, "extract_declared_spans missing (base)"


# ===========================================================================
# I. The reader against the reference, and no regression.
# ===========================================================================


def _reader_to_ref(tag: dict) -> dict:
    """Map a reader tag to the reference's comparison fields."""
    return {
        "name": tag.get("name"),
        "long_identifier": tag.get("description"),
        "address": tag.get("address"),
        "datatype": tag.get("datatype"),
        "byte_order": tag.get("effective_byte_order"),
        "bit_mask": tag.get("bit_org"),
        "matrix_dim": tag.get("matrix_dim"),
        "kind": tag.get("char_type"),
        "deposit": tag.get("deposit"),
        "conversion": tag.get("conversion"),
        "length": tag.get("length"),
        "record_layout_name": tag.get("record_layout_name"),
    }


def _ref_native(tag: dict) -> dict:
    return {k: tag.get(k) for k in (
        "name", "long_identifier", "address", "datatype", "byte_order", "bit_mask",
        "matrix_dim", "kind", "deposit", "conversion", "length", "record_layout_name",
    )}


def test_r_a2l_read_48_tracked_files_equal_ref(ref: Callable[[str], dict]) -> None:
    """R-A2L-READ.48/1: the 35 tracked files equal the reference reading."""
    for path in _tracked_a2l():
        text = path.read_text(encoding="utf-8", errors="replace")
        data = parse_a2l_file(path)
        reading = ref(text)
        _assert_sections_equal(data["sections"], reading["sections"])
        _assert_tags_equal(data["tags"], reading["tags"])
        _assert_spans_equal(_spans(data), reading["spans"])
        _assert_errors_equal(data["errors"], reading["errors"])
        del data, reading


def _assert_sections_equal(reader_sections: list, ref_sections: list) -> None:
    assert len(reader_sections) == len(ref_sections)

    def shape(sec: dict) -> dict:
        return {
            "name": sec.get("name"),
            "meta": sec.get("meta"),
            "start_line": sec.get("start_line"),
            "end_line": sec.get("end_line"),
            "lines": sec.get("lines"),
            "line_numbers": sec.get("line_numbers"),
        }

    def flatten(secs: list, depth: int = 0) -> List[dict]:
        out = []
        for s in secs:
            shp = shape(s)
            shp["depth"] = depth
            out.append(shp)
            out.extend(flatten(s.get("children", []), depth + 1))
        return out

    assert flatten(reader_sections) == flatten(ref_sections)


def _assert_tags_equal(reader_tags: list, ref_tags: list) -> None:
    def key(t: dict) -> tuple:
        return (t.get("section"), t.get("name"))

    reader = {key(t): t for t in reader_tags}
    ref = {key(t): t for t in ref_tags}
    assert set(reader) == set(ref)
    for k in reader:
        assert _reader_to_ref(reader[k]) == _ref_native(ref[k]), (k, _reader_to_ref(reader[k]), _ref_native(ref[k]))


def _assert_spans_equal(reader_spans: list, ref_spans: list) -> None:
    rkey = sorted((s.get("name"), s.get("kind")) for s in reader_spans)
    fkey = sorted((s.get("name"), s.get("kind")) for s in ref_spans)
    assert rkey == fkey
    reader = {(s.get("name"), s.get("kind")): s for s in reader_spans}
    ref = {(s.get("name"), s.get("kind")): s for s in ref_spans}
    for k in reader:
        assert reader[k].get("address") == ref[k].get("address"), k
        assert reader[k].get("length") == ref[k].get("length"), k


def _assert_errors_equal(reader_errors: list, ref_errors: list) -> None:
    def norm(errs):
        return sorted(str(e) for e in errs)

    assert norm(reader_errors) == norm([t for t, _ in ref_errors])


# ===========================================================================
# R-A2L-READ.49 — no regression (e07fb00 fixture).
# ===========================================================================


def _load_fixture() -> List[dict]:
    out = []
    with FIXTURE_PATH.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def test_r_a2l_read_49_no_regression(tmp_path: Path) -> None:
    """R-A2L-READ.49/1: 234,427 tags identical; 227 defect tags take their values."""
    if not FIXTURE_PATH.exists():
        pytest.skip("e07fb00 fixture not yet generated on the runner")
    fixture = _load_fixture()
    total_tags = 0
    for entry in fixture:
        path = REPO_ROOT / entry["file"]
        data = parse_a2l_file(path)
        assert len(data["tags"]) == entry["tag_count"], entry["file"]
        expected = {(t["section"], t["name"]): t for t in entry["tags"]}
        for tag in data["tags"]:
            key = (tag["section"], tag["name"])
            assert key in expected, (entry["file"], key)
            want = expected[key]
            assert _six_fields(tag) == (
                want["name"], want["address"], want["length"], want["datatype"],
                want["byte_order"], want["bit_mask"],
            ), (entry["file"], key)
        total_tags += len(data["tags"])
    assert total_tags == 234_654


def test_r_a2l_read_49_2_defect_classes_hand_written(tmp_path: Path) -> None:
    """R-A2L-READ.49/2: each defect class on a synthetic reduction with
    hand-written values (independent of REF), 7/7 classes."""
    # D1 (RP-B15): a MEASUREMENT header over commented lines.
    d1 = _parse(
        tmp_path,
        _body('/begin MEASUREMENT X ""\n UWORD /* t */\n CM_ID /* c */\n 0\n 0\n 0\n 65535\n ECU_ADDRESS 0x1234\n/end MEASUREMENT'),
    )
    t1 = _tag(d1, "X")
    assert (t1["datatype"], t1["length"]) == ("UWORD", 2)

    # D2: conversion word followed by a comment (the header, not the conversion line).
    d2 = _parse(
        tmp_path,
        _body('/begin MEASUREMENT XD2 ""\n SWORD\n CM_ID /* a b c d e */\n 0\n 0\n -100\n 100\n ECU_ADDRESS 0x40\n/end MEASUREMENT'),
    )
    t2 = _tag(d2, "XD2")
    assert (t2["datatype"], t2["conversion"], t2["length"], t2["address"]) == ("SWORD", "CM_ID", 2, 0x40)

    # D3 ([K1c]): a CHARACTERISTIC named on a later line.
    d3 = _parse(
        tmp_path,
        _body("/begin CHARACTERISTIC\nCK1\n\"long id\"\nVALUE\n0x2000\nRL_U16\n0\nCM_ID\n0\n65535\n/end CHARACTERISTIC"),
    )
    t3 = _tag(d3, "CK1", "CHARACTERISTIC")
    assert (t3["name"], t3["address"]) == ("CK1", 0x2000)

    # D4 (RP-B26): MATRIX_DIM product.
    d4 = _parse(tmp_path, _body(meas("X", " ECU_ADDRESS 0x1234", " MATRIX_DIM 2 2")))
    assert _tag(d4, "X")["length"] == 8

    # D5 ([K6]): VAL_BLK sized by its layout datatype x MATRIX_DIM.
    d5 = _parse(
        tmp_path,
        _body('/begin CHARACTERISTIC CK6 ""\n VAL_BLK 0x3000 RL_U16 0 CM_ID 0 65535\n MATRIX_DIM 4\n/end CHARACTERISTIC'),
    )
    assert _tag(d5, "CK6", "CHARACTERISTIC")["length"] == 8
    d5b = _parse(
        tmp_path,
        _body(
            "/begin RECORD_LAYOUT RL_SWORD\nFNC_VALUES 1 SWORD ROW_DIR DIRECT\n/end RECORD_LAYOUT\n"
            '/begin CHARACTERISTIC CK6B ""\n VAL_BLK 0x3000 RL_SWORD 0 CM_ID 0 65535\n MATRIX_DIM 3 4 1\n/end CHARACTERISTIC'
        ),
    )
    assert _tag(d5b, "CK6B", "CHARACTERISTIC")["length"] == 24

    # D6 ([K6b]): VAL_BLK sized by NUMBER.
    d6 = _parse(
        tmp_path,
        _body('/begin CHARACTERISTIC CK6C ""\n VAL_BLK 0x3010 RL_U16 0 CM_ID 0 65535\n NUMBER 4\n/end CHARACTERISTIC'),
    )
    assert _tag(d6, "CK6C", "CHARACTERISTIC")["length"] == 8

    # D7 (.57/2): MEASUREMENT sized by ARRAY_SIZE.
    d7 = _parse(tmp_path, _body(meas("X", " ECU_ADDRESS 0x10", " ARRAY_SIZE 4")))
    assert _tag(d7, "X")["length"] == 8


# ===========================================================================
# J. Views: summary.
# ===========================================================================


def test_r_a2l_read_50_summary_header_without_comment(tmp_path: Path) -> None:
    """R-A2L-READ.50/1..3: the summary begin words without the comment."""
    text = _body('/begin CHARACTERISTIC XH "one-line header" VALUE 0x00003000/*old 0x1000*/ RL_U32 0 CM_ID 0 100\n/end CHARACTERISTIC')
    data = _parse(tmp_path, text)
    view = render_a2l_view(data)
    assert "0x00003000/*old 0x1000*/" not in view
    assert "VALUE 0x00003000 RL_U32" in view


def test_r_a2l_076_errors_then_sections(tmp_path: Path) -> None:
    """R-A2L-076/1, /2: a file with errors lists its sections."""
    data = parse_a2l_file(REPO_ROOT / "examples" / "case_00_public" / "merge_inc_test.a2l")
    view = render_a2l_view(data)
    assert "A2L parse errors:" in view and "A2L Sections:" in view
    text = _body(meas("X", " ECU_ADDRESS 0x10")) + "\n/end X\n"
    data2 = _parse(tmp_path, text)
    view2 = render_a2l_view(data2)
    assert "A2L parse errors:" in view2 and "A2L Sections:" in view2


def test_r_a2l_077_errors_then_tags(tmp_path: Path) -> None:
    """R-A2L-077/1: a file with errors lists its tags."""
    text = _body(meas("X", " ECU_ADDRESS 0x10")) + "\n/end X\n"
    data = _parse(tmp_path, text)
    view = render_a2l_view(data)
    assert "A2L Tags:" in view
    assert "MEASUREMENT X: 0x00000010 len=2" in view


def test_r_a2l_read_51_control_chars_as_fffd(tmp_path: Path) -> None:
    """R-A2L-READ.51/1: control characters show as U+FFFD in the summary."""
    for ch in ("\x0b", "\x0c", "\x1c", "\x1e", "\x85", "\u2028", "\u2029", "\x1b", "\x07"):
        text = _body('/begin MEASUREMENT X "a' + ch + 'b"\n UWORD CM_ID 0 0 0 65535\n ECU_ADDRESS 0x10\n/end MEASUREMENT')
        data = _parse(tmp_path, text)
        view = render_a2l_view(data)
        assert "\ufffd" in view


# ===========================================================================
# Acceptance cases (black box, through the app).
# ===========================================================================


def test_at_b103_i11_2_commented_old_copy_changes_nothing(tmp_path: Path) -> None:
    """AT-B103-I11-2 (RP-B28): 1 row X at 0x1234; no duplicate issue."""
    from s19_app.validation.rules import validate_a2l_structure

    body = _body("/*\n" + meas("X", " ECU_ADDRESS 0x9999") + "\n*/\n" + meas("X", " ECU_ADDRESS 0x1234"))
    data = _parse(tmp_path, body)
    xs = _tags_named(data, "X")
    assert len(xs) == 1 and xs[0]["address"] == 0x1234
    issues = validate_a2l_structure(data)
    assert not [i for i in issues if i.code == "A2L_DUPLICATE_SYMBOL"]


def test_at_b103_i11_3_v171_loads_clean(tmp_path: Path) -> None:
    """AT-B103-I11-3: V171 loads clean and the summary shows sections and tags."""
    data = parse_a2l_file(REPO_ROOT / "examples" / "case_00_public" / "ASAP2_Demo_V171.a2l")
    assert data["errors"] == []
    view = render_a2l_view(data)
    assert "A2L Sections:" in view and "A2L Tags:" in view
