"""Engine-level tests of batch-101 Inc 11 (A2L validation and parsing).

Covers, through the shipped functions only (``parse_a2l_file``,
``validate_a2l_structure``, ``extract_memory_segments``, ``render_curve_description``):

- F-02: a valid A2L raises no ``A2L_UNRECOGNIZED_BLOCK`` for an ASAM block name
  or for a section inside an IF_DATA block; an unknown name outside IF_DATA stays
  a WARNING (rows R-VAL-032.1 .. .3).
- F-29: a MEMORY_SEGMENT record is read whatever line shape it has, and a broken
  record gives no base and no size instead of a plausible wrong value
  (rows R-A2L-036.1 .. .13, R-A2L-034).
- F-21: the CURVE index note is shown once above the table, not on each row
  (rows R-A2L-120 .. 123).

Every expected value is the requirement's exact value from
``.dev-flow/2026-11-01-batch-101/inc-11/01-requirements.md``. The ASAM block
list is typed here on purpose (never imported from the engine) so that a
shrunken engine list fails.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Iterable, List, Optional

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SYNTH_DIR = REPO_ROOT / "tools" / "synth"
if str(SYNTH_DIR) not in sys.path:
    sys.path.insert(0, str(SYNTH_DIR))

import make_release_case as gen  # noqa: E402

from s19_app.tui.a2l import (  # noqa: E402
    describe_curve_tag,
    extract_memory_segments,
    parse_a2l_file,
    render_curve_description,
)
from s19_app.validation import ValidationSeverity  # noqa: E402
from s19_app.validation.rules import validate_a2l_structure  # noqa: E402

from tests.test_a2l_curve_description import (  # noqa: E402
    _COMPU_LINEAR,
    _LAYOUT_NO_AXIS,
    _char_tags,
    _mem_map,
    _write,
)

SEED = 20260001
DEMO_SIZE_MB = 10.0
UNRECOGNIZED = "A2L_UNRECOGNIZED_BLOCK"

#: The 62 ASAM MCD-2 MC block names of 01-requirements.md (Definitions).
ASAM_BLOCK_NAMES = (
    "A2ML ANNOTATION ANNOTATION_TEXT AR_COMPONENT AXIS_DESCR AXIS_PTS BIT_OPERATION "
    "BLOB CALIBRATION_HANDLE CALIBRATION_METHOD CHARACTERISTIC COMPU_METHOD COMPU_TAB "
    "COMPU_VTAB COMPU_VTAB_RANGE DEF_CHARACTERISTIC DEPENDENT_CHARACTERISTIC "
    "FIX_AXIS_PAR_LIST FORMULA FRAME FUNCTION FUNCTION_LIST GROUP HEADER IF_DATA "
    "IN_MEASUREMENT INSTANCE LOC_MEASUREMENT MAP_LIST MEASUREMENT MEMORY_LAYOUT "
    "MEMORY_SEGMENT MOD_COMMON MOD_PAR MODULE OUT_MEASUREMENT OVERWRITE PROJECT "
    "RECORD_LAYOUT REF_CHARACTERISTIC REF_GROUP REF_MEASUREMENT STRUCTURE_COMPONENT "
    "SUB_FUNCTION SUB_GROUP TRANSFORMER TRANSFORMER_IN_OBJECTS TRANSFORMER_OUT_OBJECTS "
    "TYPEDEF_AXIS TYPEDEF_BLOB TYPEDEF_CHARACTERISTIC TYPEDEF_MEASUREMENT "
    "TYPEDEF_STRUCTURE UNIT USER_RIGHTS VAR_ADDRESS VAR_CHARACTERISTIC VAR_CRITERION "
    "VAR_FORBIDDEN_COMB VARIANT_CODING VIRTUAL VIRTUAL_CHARACTERISTIC"
).split()


def test_typed_asam_list_is_62_distinct_names() -> None:
    """The typed oracle list itself: 62 distinct upper-case names."""
    assert len(ASAM_BLOCK_NAMES) == 62
    assert len(set(ASAM_BLOCK_NAMES)) == 62
    assert all(n == n.upper() for n in ASAM_BLOCK_NAMES)


# ---------------------------------------------------------------------------
# Drivers
# ---------------------------------------------------------------------------


def _a2l_text(body: Iterable[str]) -> str:
    """PROJECT / MODULE wrapper; the body starts at line 3."""
    lines = ['/begin PROJECT P ""', '/begin MODULE M ""', *body, "/end MODULE", "/end PROJECT"]
    return "\n".join(lines) + "\n"


def _parse_body(tmp_path: Path, body: Iterable[str], name: str = "t.a2l") -> dict:
    path = tmp_path / name
    path.write_text(_a2l_text(body), encoding="utf-8")
    return parse_a2l_file(path)


def _issues(tmp_path: Path, body: Iterable[str]):
    return validate_a2l_structure(_parse_body(tmp_path, body))


def _unrecognized(issues) -> list:
    return [i for i in issues if i.code == UNRECOGNIZED]


def _segments(tmp_path: Path, body: Iterable[str]) -> List[dict]:
    return extract_memory_segments(_parse_body(tmp_path, body)["sections"])


def _one_segment(tmp_path: Path, begin_line: str, *more: str) -> dict:
    segs = _segments(tmp_path, [begin_line, *more, "/end MEMORY_SEGMENT"])
    assert len(segs) == 1, segs
    return segs[0]


@pytest.fixture(scope="module")
def demo_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The release demo from the repo's own generator (standard library only)."""
    d = tmp_path_factory.mktemp("b101_inc11_demo")
    gen.generate(d, SEED, DEMO_SIZE_MB)
    return d


# ---------------------------------------------------------------------------
# R-VAL-032.1 — an unknown name outside IF_DATA is a WARNING
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "case_id, body, expected_name",
    [
        ("top", ["/begin FROBNICATE x", "/end FROBNICATE"], "FROBNICATE"),
        ("lower", ["/begin frobnicate x", "/end frobnicate"], "FROBNICATE"),
        ("page-outside-if-data", ["/begin PAGE", "0x0", "/end PAGE"], "PAGE"),
    ],
    ids=["top", "lower", "page-outside-if-data"],
)
def test_r_val_032_1_unknown_block_warns(tmp_path: Path, case_id, body, expected_name) -> None:
    """Why: an unknown name must stay visible. Exactly one WARNING, exact message, line 3."""
    issues = _issues(tmp_path, body)
    assert len(issues) == 1, [(i.code, i.message) for i in issues]
    issue = issues[0]
    assert issue.code == UNRECOGNIZED
    assert issue.severity == ValidationSeverity.WARNING
    assert issue.message == f"Unrecognized A2L block '{expected_name}'."
    assert issue.line_number == 3


def test_r_val_032_1_unknown_block_warns_nested(tmp_path: Path) -> None:
    """Why: a walker that only checks the top level would hide a nested unknown block."""
    body = [
        '/begin CHARACTERISTIC C "" VALUE 0x100 RL 0 NO_COMPU_METHOD 0 1',
        "/begin FROBNICATE",
        "/end FROBNICATE",
        "/end CHARACTERISTIC",
    ]
    found = _unrecognized(_issues(tmp_path, body))
    assert len(found) == 1, [(i.code, i.message) for i in found]
    assert found[0].severity == ValidationSeverity.WARNING
    assert found[0].message == "Unrecognized A2L block 'FROBNICATE'."
    assert found[0].line_number == 4


# ---------------------------------------------------------------------------
# R-VAL-032.2 — an ASAM block name raises nothing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ASAM_BLOCK_NAMES)
def test_r_val_032_2_asam_block_names_raise_nothing(tmp_path: Path, name: str) -> None:
    """Why: a standard block is not a finding. 62/62 names give 0 unrecognized issues."""
    issues = _issues(tmp_path, [f"/begin {name}", f"/end {name}"])
    assert _unrecognized(issues) == [], [(i.code, i.message) for i in issues]


def _walk_names_outside_if_data(nodes: list, inside: bool = False) -> set:
    """Independent walker: the upper-case section names not inside an IF_DATA section."""
    names: set = set()
    for node in nodes:
        upper = str(node.get("name", "")).upper()
        if not inside:
            names.add(upper)
        names |= _walk_names_outside_if_data(
            node.get("children") or [], inside or upper == "IF_DATA"
        )
    return names


def _corpus_examples() -> List[Path]:
    return sorted((REPO_ROOT / "examples").rglob("*.a2l"))


_SYNTH_A2L = REPO_ROOT / "tests" / "fixtures" / "synth" / "synth_a2l.a2l"


def test_r_val_032_2_corpus_has_37_files(demo_dir: Path) -> None:
    """Why: the pin must really cover the 37-file corpus (34 + synth + 2 demo A2Ls)."""
    assert len(_corpus_examples()) == 34
    assert _SYNTH_A2L.is_file()
    assert (demo_dir / "firmware.a2l").is_file()
    assert (demo_dir / "firmware_issues.a2l").is_file()


def _corpus_ids() -> List[str]:
    return [p.relative_to(REPO_ROOT / "examples").as_posix() for p in _corpus_examples()] + [
        "synth_a2l.a2l",
        "demo:firmware.a2l",
        "demo:firmware_issues.a2l",
    ]


@pytest.mark.parametrize("corpus_id", _corpus_ids())
def test_r_val_032_2_shipped_fixtures_raise_no_unrecognized_block(
    corpus_id: str, demo_dir: Path
) -> None:
    """Why: the D-9 pin. Every section name outside IF_DATA of the 37-file corpus is
    in the typed 62-name list, and the engine raises 0 unrecognized-block issues."""
    if corpus_id == "synth_a2l.a2l":
        path = _SYNTH_A2L
    elif corpus_id.startswith("demo:"):
        path = demo_dir / corpus_id.split(":", 1)[1]
    else:
        path = REPO_ROOT / "examples" / corpus_id
    data = parse_a2l_file(path)
    outside = _walk_names_outside_if_data(data["sections"])
    assert outside <= set(ASAM_BLOCK_NAMES), sorted(outside - set(ASAM_BLOCK_NAMES))
    found = _unrecognized(validate_a2l_structure(data))
    assert found == [], [i.message for i in found[:5]]


# ---------------------------------------------------------------------------
# R-VAL-032.3 — inside IF_DATA nothing is judged
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "case_id, body",
    [
        (
            "page",
            [
                "/begin IF_DATA XCP",
                "/begin SEGMENT",
                "0x0",
                "/begin PAGE",
                "0x0",
                "/end PAGE",
                "/end SEGMENT",
                "/end IF_DATA",
            ],
        ),
        ("daq", ["/begin IF_DATA XCP", "/begin DAQ", "/end DAQ", "/end IF_DATA"]),
        (
            "deep",
            [
                "/begin IF_DATA X",
                "/begin A",
                "/begin B",
                "/begin FROBNICATE",
                "/end FROBNICATE",
                "/end B",
                "/end A",
                "/end IF_DATA",
            ],
        ),
    ],
    ids=["page", "daq", "deep"],
)
def test_r_val_032_3_inside_if_data_raises_nothing(tmp_path: Path, case_id, body) -> None:
    """Why: the interface block's grammar comes from the file's A2ML, not from MCD-2 MC.
    Direct children and descendants at any depth give 0 issues."""
    issues = _issues(tmp_path, body)
    assert issues == [], [(i.code, i.message) for i in issues]


def test_r_val_032_3_software_a_raises_no_unrecognized_block() -> None:
    """Why: the real fixture with IF_DATA > SEGMENT > PAGE (base: 1 023 issues)."""
    data = parse_a2l_file(REPO_ROOT / "examples" / "case_00_public" / "software_a.a2l")
    assert _unrecognized(validate_a2l_structure(data)) == []


def test_r_val_032_3_v171_one_line_if_data() -> None:
    """Why: a one-line IF_DATA closes on its line (R-A2L-READ.17), so V171 has
    0 parse errors; the IF_DATA exemption must still hold."""
    data = parse_a2l_file(REPO_ROOT / "examples" / "case_00_public" / "ASAP2_Demo_V171.a2l")
    issues = validate_a2l_structure(data)
    assert _unrecognized(issues) == []
    assert data["errors"] == []
    structure = [
        i
        for i in issues
        if i.code == "A2L_STRUCTURE_ERROR"
    ]
    assert structure == [], [(i.code, i.message) for i in issues]


# ---------------------------------------------------------------------------
# R-A2L-036 — MEMORY_SEGMENT record
# ---------------------------------------------------------------------------


def test_r_a2l_036_name_first_record_line_software_a() -> None:
    """Why: software_a.a2l writes the name first on the record line (base: UNKNOWN, no base).
    Rows 036.1/2, 036.2/2, 036.3/2, 036.6/3, 036.8/1, 036.9/1."""
    data = parse_a2l_file(REPO_ROOT / "examples" / "case_00_public" / "software_a.a2l")
    segs = extract_memory_segments(data["sections"])
    assert [s["block_name"] for s in segs] == [
        "SystemCalFLash",
        "SafetyCalFlash",
        "PerformanceCalFlash",
    ]
    assert [s["base"] for s in segs] == [0xA001C000, 0xA0038000, 0xA0050000]
    assert [s["size"] for s in segs] == [0x1000, 0x1000, 0x1000]
    assert [s["offset"] for s in segs] == [-1, -1, -1]
    assert [s["usage"] for s in segs] == ["DATA"] * 3
    assert [s["kind"] for s in segs] == ["FLASH"] * 3


@pytest.mark.parametrize("name", ["boot"])
def test_r_a2l_036_all_on_begin_line(tmp_path: Path, name: str) -> None:
    """Why: the release demo writes everything on the /begin line (base: no record line)."""
    seg = _one_segment(
        tmp_path,
        f"/begin MEMORY_SEGMENT {name} CODE FLASH INTERN FLASH 0x00000000 0x010000",
    )
    assert seg["block_name"] == name
    assert seg["base"] == 0x0
    assert seg["size"] == 0x10000


def test_r_a2l_036_release_demo_segments(demo_dir: Path) -> None:
    """Why: the 4 demo segments must all be read (base: 0 of 4 usable).
    Rows 036.2/3, 036.3/3, 036.8/2, 036.9/2."""
    data = parse_a2l_file(demo_dir / "firmware.a2l")
    segs = extract_memory_segments(data["sections"])
    got = [(s["block_name"], s["usage"], s["kind"], s["base"], s["size"]) for s in segs]
    assert got == [
        ("boot", "CODE", "FLASH", 0x0, 0x10000),
        ("app", "CODE", "FLASH", 0x40000, 0x2C9FA0),
        ("cal", "DATA", "FLASH", 0x800000, 0x131FC0),
        ("config", "DATA", "FLASH", 0xC00000, 0x1000),
    ]


def test_r_a2l_036_comment_words_are_skipped(tmp_path: Path) -> None:
    """Why: a comment is not a record word; `/* 0x10 0x20 */` must not become the base."""
    seg = _one_segment(
        tmp_path,
        '/begin MEMORY_SEGMENT S ""',
        "/* 0x10 0x20 */",
        "DATA FLASH INTERN 0x1000 0x200 -1",
    )
    assert (seg["base"], seg["size"], seg["offset"]) == (0x1000, 0x200, -1)


def test_r_a2l_036_2_leading_zero_decimal(tmp_path: Path) -> None:
    """Why: `0400` is decimal 400 under the ASCII Number pattern (ruling addendum)."""
    seg = _one_segment(
        tmp_path, '/begin MEMORY_SEGMENT S4 "" DATA RAM INTERN 0400 0x100 0x0'
    )
    assert (seg["base"], seg["size"], seg["offset"]) == (400, 0x100, 0)


def test_r_a2l_036_2_open_quote_ends_at_line(tmp_path: Path) -> None:
    """Why: an unterminated quote ends at its line; it must not swallow the next line's
    comment/words (carried quote state would give base 0x10, size 0x20)."""
    seg = _one_segment(
        tmp_path,
        '/begin MEMORY_SEGMENT S7 "oops',
        "/* 0x10 0x20 */ DATA FLASH INTERN 0x1000 0x200 -1",
    )
    assert (seg["base"], seg["size"], seg["offset"]) == (0x1000, 0x200, -1)


NO_BASE_RECORDS = [
    ("S1", '"" DATA FLASH INTERN 0x1000 BAD', "single"),
    ("S2", '"" DATA FLASH INTERN', "none"),
    ("S3", '"" 0x10 DATA 0x20', "split"),
    ("S1b", '"" DATA FLASH INTERN 0x1000 BAD -1 -1 -1 -1 -1', "bad_size_placeholders"),
    ("S1c", '"" DATA FLASH INTERN 0xZZ 0x1000 0x400 0x800 -1 -1 -1', "bad_address"),
    ("S5", '"" DATA FLASH INTERN -1 0x100', "negative_base"),
    ("S8", '"" DATA FLASH INTERN 0x1000 0x0', "zero_size"),
    ("S6", '"1" "0x10" DATA FLASH INTERN', "quoted_words"),
    ("S9", '"" DATA FLASH INTERN 0x1_000 0x10', "underscore"),
    ("S10", '"" DATA FLASH INTERN 0x123456789 0x10', "nine_hex_digits"),
    # E5 C-6: nine hex digits whose value is small, so the 2^32 bound cannot mask a
    # reader that drops the 8-digit limit (S10's value already exceeds the bound).
    ("S10b", '"" DATA FLASH INTERN 0x000001000 0x10', "nine_hex_digits_small"),
    ("S11", '"" DATA FLASH INTERN ٣ 0x10', "non_ascii_digit"),
]


@pytest.mark.parametrize("shape", ["begin-line", "own-line"])
@pytest.mark.parametrize(
    "name, record", [(n, r) for n, r, _ in NO_BASE_RECORDS], ids=[i for _, _, i in NO_BASE_RECORDS]
)
def test_r_a2l_036_4_no_base(tmp_path: Path, name: str, record: str, shape: str) -> None:
    """Why: a broken record must give NO base and NO size, never a plausible wrong pair
    taken from the offset words (E1 rule gave base -1 / 0x1000 silently). The record is
    written on the /begin line (the release-demo shape) and on its own line (the shipped
    ASAM shape), because the base reader only sees the second."""
    if shape == "begin-line":
        seg = _one_segment(tmp_path, f"/begin MEMORY_SEGMENT {name} {record}")
    else:
        seg = _one_segment(tmp_path, f"/begin MEMORY_SEGMENT {name}", record)
    assert seg["base"] is None, seg
    assert seg["size"] is None, seg


def test_r_a2l_036_4_non_ascii_digit_word_is_skipped_by_the_anchor(tmp_path: Path) -> None:
    """Why: pins the accepted residual N-2 (D-5): a word with a non-ASCII digit (U+0663) is
    not a Number and does not start with an ASCII digit or sign, so it is not the address
    word; the anchor is the next word, 0x10. S11 alone cannot show this (no word follows
    0x10 there), so a change to the anchor rule would pass it silently (F4, E5)."""
    seg = _one_segment(tmp_path, '/begin MEMORY_SEGMENT S11b "" DATA FLASH INTERN \u0663 0x10 0x20')
    assert (seg["base"], seg["size"]) == (0x10, 0x20), seg


def test_r_a2l_036_7_empty_segment_has_no_name(tmp_path: Path) -> None:
    """Why: an empty block has no record word, so no name (base: the text UNKNOWN)."""
    seg = _one_segment(tmp_path, "/begin MEMORY_SEGMENT")
    assert seg["block_name"] is None
    assert seg["base"] is None
    assert seg["size"] is None


def test_r_a2l_036_8_last_program_type_word_wins(tmp_path: Path) -> None:
    """Why: a long identifier that is itself a program-type word ("CODE") must not win."""
    seg = _one_segment(
        tmp_path, '/begin MEMORY_SEGMENT M3 "CODE" DATA FLASH INTERN 0x100 0x10'
    )
    assert seg["usage"] == "DATA"
    assert (seg["base"], seg["size"]) == (0x100, 0x10)


def test_r_a2l_036_9_last_memory_type_word_wins(tmp_path: Path) -> None:
    """Why: a long identifier that is a memory-type word ("FLASH") must not win."""
    seg = _one_segment(
        tmp_path, '/begin MEMORY_SEGMENT M2 "FLASH" DATA RAM INTERN 0x100 0x10'
    )
    assert seg["kind"] == "RAM"


def test_r_a2l_036_10_no_program_type_case_07() -> None:
    """Why: a record without a program-type word must give none (base: no base at all)."""
    data = parse_a2l_file(REPO_ROOT / "examples" / "case_07_stress_smoke" / "firmware.a2l")
    segs = extract_memory_segments(data["sections"])
    assert len(segs) == 1
    seg = segs[0]
    assert seg["usage"] is None
    assert seg["kind"] == "FLASH"
    assert (seg["base"], seg["size"]) == (0x08000000, 0x400)


def test_r_a2l_036_11_no_memory_type(tmp_path: Path) -> None:
    """Why: INTERN is not a memory-type word; the kind must be None, not INTERN."""
    seg = _one_segment(tmp_path, '/begin MEMORY_SEGMENT M1 "" CODE INTERN 0x100 0x10')
    assert seg["usage"] == "CODE"
    assert seg["kind"] is None
    assert (seg["base"], seg["size"]) == (0x100, 0x10)


def test_r_a2l_036_12_no_base_no_types(tmp_path: Path) -> None:
    """Why: types are read only for a segment that has a base (base: usage S2)."""
    seg = _one_segment(tmp_path, '/begin MEMORY_SEGMENT S2 "" DATA FLASH INTERN')
    assert seg["usage"] is None
    assert seg["kind"] is None


@pytest.mark.parametrize(
    "line, expected",
    [
        ('/begin MEMORY_SEGMENT S12 "" DATA FLASH INTERN 0xFFFFF000 0x2000', (None, None)),
        ('/begin MEMORY_SEGMENT S13 "" DATA FLASH INTERN 0xFFFFF000 0x1000', (0xFFFFF000, 0x1000)),
    ],
    ids=["over", "at"],
)
def test_r_a2l_036_13_end_above_4_gib(tmp_path: Path, line: str, expected) -> None:
    """Why: a segment ending above 2**32 is rejected; ending exactly at 2**32 is kept."""
    seg = _one_segment(tmp_path, line)
    assert (seg["base"], seg["size"]) == expected


# ---------------------------------------------------------------------------
# R-A2L-034 — the tags' memory region follows the segments
# ---------------------------------------------------------------------------


def test_r_a2l_034_release_demo_tags_are_flash(demo_dir: Path) -> None:
    """Why: with the 4 demo segments read, every tag lies in FLASH (base: 462 unknown)."""
    tags = parse_a2l_file(demo_dir / "firmware.a2l")["tags"]
    assert len(tags) == 462
    assert [t for t in tags if t.get("memory_region") != "flash"] == []


def test_r_a2l_034_case_07_regions() -> None:
    """Why: case_07 has one FLASH segment: 8 tags inside it, 4 outside (unknown)."""
    tags = parse_a2l_file(REPO_ROOT / "examples" / "case_07_stress_smoke" / "firmware.a2l")["tags"]
    regions = [t.get("memory_region") for t in tags]
    assert regions.count("flash") == 8, regions
    assert regions.count("unknown") == 4, regions


# ---------------------------------------------------------------------------
# R-A2L-120 .. 123 — the CURVE index note
# ---------------------------------------------------------------------------

NOTE_TEXT = "x: point index (axis points unavailable)"
ROW_SUFFIX = "(index (axis points unavailable))"


def _curve_c1_text(tmp_path: Path) -> str:
    """Curve C1 of TC-1820 (NO_AXIS_PTS, 3 points, y = 210 / 410 / 610), rendered."""
    body = (
        _LAYOUT_NO_AXIS
        + _COMPU_LINEAR
        + '    /begin CHARACTERISTIC C1 "curve one"\n'
        "      CURVE 0x9200 RL_NOAX 0 CM_lin 0 1000\n"
        "      /begin AXIS_DESCR\n"
        "        STD_AXIS NO_INPUT NO_COMPU_METHOD 3 0 255\n"
        "      /end AXIS_DESCR\n"
        "    /end CHARACTERISTIC\n"
    )
    data = _write(tmp_path, "inc11_noax.a2l", body)
    tag = _char_tags(data)["C1"]
    record = bytes([0xEE, 100, 0, 200, 0, 44, 1])
    description = describe_curve_tag(tag, data, _mem_map(0x9200, record))
    assert [p["y"] for p in description["points"]] == [210.0, 410.0, 610.0]
    return render_curve_description(description)


def _point_lines(text: str) -> List[str]:
    """The point-table rows: the lines after the `  x     y` header up to the blank line."""
    lines = text.split("\n")
    header = lines.index("  x     y")
    out: List[str] = []
    for line in lines[header + 1 :]:
        if not line.strip():
            break
        out.append(line)
    return out


def test_r_a2l_121_index_note_once_above_header(tmp_path: Path) -> None:
    """Why: the note is stated once, directly above the table, not on every row."""
    text = _curve_c1_text(tmp_path)
    assert text.count(NOTE_TEXT) == 1
    lines = text.split("\n")
    at = [i for i, line in enumerate(lines) if NOTE_TEXT in line]
    assert len(at) == 1
    assert lines[at[0]].strip() == NOTE_TEXT
    assert lines[at[0] + 1] == "  x     y"


def test_r_a2l_121_no_line_without_points() -> None:
    """Why: a table of 0 points gets no note line."""
    description = {
        "char_type": "CURVE",
        "name": "C0",
        "status": "ok",
        "points": [],
        "axes": [],
        "notes": [],
    }
    assert NOTE_TEXT not in render_curve_description(description)


def test_r_a2l_122_rows_carry_no_note(tmp_path: Path) -> None:
    """Why: with the note above the table, rows end at the y value."""
    text = _curve_c1_text(tmp_path)
    assert _point_lines(text) == ["  0   210", "  1   410", "  2   610"]
    assert text.count(ROW_SUFFIX) == 0


def test_r_a2l_123_mixed_points_keep_row_note() -> None:
    """Why: when only some points lack an axis value the reader must see which rows
    are indexes; the once-line of R-A2L-121 is then absent."""

    def point(x, y, note: Optional[str] = None) -> dict:
        return {"x": x, "y": y, "y_raw": y, "x_note": note, "outside_limits": False}

    description = {
        "char_type": "CURVE",
        "name": "CM",
        "status": "ok",
        "points": [
            point(10, 100.0),
            point(20, 200.0),
            point(2, 300.0, "index (axis points unavailable)"),
        ],
        "axes": [],
        "notes": [],
    }
    text = render_curve_description(description)
    point_rows = [line for line in text.split("\n") if line.strip().split(" ")[0] in {"10", "20", "2"}]
    assert len(point_rows) == 3, text
    assert not point_rows[0].endswith("   " + ROW_SUFFIX)
    assert not point_rows[1].endswith("   " + ROW_SUFFIX)
    assert point_rows[2].endswith("   " + ROW_SUFFIX)
    assert NOTE_TEXT not in text
