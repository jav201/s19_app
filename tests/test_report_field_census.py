"""batch-62 Inc-3b — the file-derived field census + AT-157 / AT-158.

Where `test_report_markup_safety.py` pins the ESCAPER, this file pins the
COMPOSER: it plants a hostile, individually-marked payload in every file-derived
field reachable through `generate_project_report` and asserts, over the produced
document, that none of them can reach the reader as markup.

Why a census and not per-field tests: this batch under-counted affected sites
**twice** (the review declared 2 sites in `test_report_service.py` where there
were 5, and the field list the kickoff supplied was short by four fields). A
sweep keyed on the emitted document does not depend on anyone's list being
right — a newly-added unescaped field shows up as a live token, not as a gap in
a table nobody re-read.

The oracle (`expected_display`) is imported from the Inc-1 battery rather than
re-derived, so there is exactly ONE definition of what a reader must see.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from markdown_it import MarkdownIt

from s19_app.tui.models import ProjectVariantSet, VariantDescriptor
from s19_app.tui.services.markdown_safety import redact_absolute_paths
from s19_app.tui.services.report_addendum import DeclaredRegion
from s19_app.tui.services.report_service import (
    ReportOptions,
    generate_project_report,
)
from s19_app.tui.services.variant_execution_service import VariantExecutionResult
from s19_app.validation.model import ValidationIssue, ValidationSeverity

from test_report_markup_safety import (
    DEFAULT,
    VIEWER,
    _walk,
    expected_display,
    live_tokens,
    rendered_text,
)
from test_report_service import _applied_entry, _summary

# --------------------------------------------------------------------------- #
# The planted corpus
# --------------------------------------------------------------------------- #

#: Grammar that must not survive, in one string: strikethrough, emphasis, an
#: inline link, a pipe (table shape), an HTML entity (renders as a character the
#: file does not contain) and a backtick (code span).
_ATTACK = "~~s~~**b**[l](http://evil.com)|&vert;`c`"


#: Same corpus minus the slash-bearing link, for values that are FILENAMES. A
#: `/` in a `Path` is a separator, not data — `Path("a/b").name` is `"b"` — so a
#: slash-bearing filename fixture would test the OS's path parser, not the
#: escaper, and would silently lose its own marker.
_ATTACK_FILENAME = "~~s~~**b**[l]|&vert;`c`"

#: Markers whose value is a filename.
_FILENAME_MARKERS = {"MKPATH"}


def _payload(marker: str) -> str:
    """A uniquely findable hostile value for one field."""
    attack = _ATTACK_FILENAME if marker in _FILENAME_MARKERS else _ATTACK
    return f"{marker}{attack}"


#: Every file-derived field this composer emits that a caller can reach through
#: the public entry point, with the mode the spec assigns it. The MARKER is what
#: makes each one individually locatable in the produced document.
PLANTED = [
    ("project_name", "MKPROJ", "A"),
    ("variant_id", "MKVAR", "A"),
    ("path_name", "MKPATH", "A"),
    ("file_type", "MKTYPE", "A"),
    ("status", "MKSTAT", "A"),
    ("linkage", "MKLINK", "A"),
    ("linkage_symbol", "MKSYM", "A"),
    ("issue_code", "MKCODE", "A"),
    ("issue_message", "MKMSG", "A"),
    ("issue_symbol", "MKISYM", "A"),
    ("related_artifact", "MKREL", "A"),
    ("region_name", "MKREGION", "A"),
    ("change_source_path", "MKSRC", "B"),
    ("saved_path", "MKSAVED", "B"),
]

_MARKERS = {name: marker for name, marker, _ in PLANTED}
_MODES = {name: mode for name, _, mode in PLANTED}


def _hostile_report(tmp_path: Path) -> str:
    """One report carrying a marked hostile value in every planted field."""
    issue = ValidationIssue(
        code=_payload(_MARKERS["issue_code"]),
        severity=ValidationSeverity.ERROR,
        message=_payload(_MARKERS["issue_message"]),
        artifact="changes",
        symbol=_payload(_MARKERS["issue_symbol"]),
        address=0x80040000,
        related_artifacts=[_payload(_MARKERS["related_artifact"])],
    )
    summary = _summary(
        [
            _applied_entry(
                0x1000,
                (0x01,),
                (0xAA,),
                _payload(_MARKERS["linkage"]),
                _payload(_MARKERS["linkage_symbol"]),
            )
        ],
        source=f"{_MARKERS['change_source_path']}`x.json",
        issues=[issue],
        saved_path=Path(f"{_MARKERS['saved_path']}`x.s19"),
    )
    results = [
        VariantExecutionResult(
            variant_id=_payload(_MARKERS["variant_id"]),
            status=_payload(_MARKERS["status"]),
            change_summaries=[summary],
        )
    ]
    variant_set = ProjectVariantSet(
        project_name=_payload(_MARKERS["project_name"]),
        variants=(
            VariantDescriptor(
                variant_id=_payload(_MARKERS["variant_id"]),
                path=Path(_payload(_MARKERS["path_name"])),
                file_type=_payload(_MARKERS["file_type"]),
            ),
        ),
        active_id=_payload(_MARKERS["variant_id"]),
    )
    path = generate_project_report(
        tmp_path,
        results,
        ReportOptions(
            declared_regions=(
                DeclaredRegion(_payload(_MARKERS["region_name"])[:79], 0x1000, 0x1FFF),
            ),
        ),
        variant_set=variant_set,
    )
    return path.read_text(encoding="utf-8")


def _benign_report(tmp_path: Path) -> str:
    """The same shape with harmless values — the structural reference."""
    summary = _summary(
        [_applied_entry(0x1000, (0x01,), (0xAA,), "standalone", "SYMA")],
        source="src.json",
        saved_path=Path("out.s19"),
    )
    results = [
        VariantExecutionResult(
            variant_id="a", status="ok", change_summaries=[summary]
        )
    ]
    variant_set = ProjectVariantSet(
        project_name="proj",
        variants=(
            VariantDescriptor(variant_id="a", path=Path("a.s19"), file_type="s19"),
        ),
        active_id="a",
    )
    path = generate_project_report(
        tmp_path, results, ReportOptions(), variant_set=variant_set
    )
    return path.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def hostile(tmp_path_factory) -> str:
    return _hostile_report(tmp_path_factory.mktemp("hostile"))


@pytest.fixture(scope="module")
def benign(tmp_path_factory) -> str:
    return _benign_report(tmp_path_factory.mktemp("benign"))


# --------------------------------------------------------------------------- #
# AT-157 / AT-158
# --------------------------------------------------------------------------- #


def _structural(md: MarkdownIt, document: str) -> set:
    """Live token types, minus the ones a benign report legitimately emits."""
    return live_tokens(md, document)


def test_at157_no_planted_field_produces_markup_in_the_app_viewer(
    hostile: str, benign: str
) -> None:
    """AT-157 (US-B62-1) — through the parser the APP actually renders with.

    The predicate is an ALLOW-LIST on structure, not a closed list of forbidden
    token types: the hostile document's live-token set must not exceed the
    benign one's. A closed enumeration was measured to miss an injected `hr`,
    which is the batch's own top-listed defect class.
    """
    assert _structural(VIEWER, hostile) <= _structural(VIEWER, benign), (
        "a planted field minted a construct the benign report does not have: "
        f"{sorted(_structural(VIEWER, hostile) - _structural(VIEWER, benign))}"
    )


def test_at158_exported_file_is_inert_under_a_default_reader(
    hostile: str, benign: str
) -> None:
    """AT-158 (US-B62-2) — the file once it LEAVES the app.

    Modelled as a default `markdown-it` `gfm-like` reader (linkify + html ON),
    which is deliberately narrower than "any GFM reader": reader extensions
    (`:emoji:`, `$…$`, `==mark==`) are a declared residual risk (RR-1), and an
    honest narrow claim beats a broad one the tests cannot support.
    """
    extra = _structural(DEFAULT, hostile) - _structural(DEFAULT, benign)
    assert not extra, f"the exported file is not inert under a default reader: {sorted(extra)}"
    live = _structural(DEFAULT, hostile)
    for forbidden in ("link_open", "html_inline", "html_block", "image"):
        assert forbidden not in live, f"{forbidden} survived into the exported file"


@pytest.mark.parametrize("field,marker,mode", PLANTED,
                         ids=[name for name, _, _ in PLANTED])
def test_census_every_planted_field_renders_verbatim(
    hostile: str, field: str, marker: str, mode: str
) -> None:
    """The fidelity half, per field: escaped is not the same as mangled.

    An escaper that neutralised by DELETING would pass every structural
    assertion above while quietly rewriting an audit record. Each field is
    therefore checked against `expected_display` — the survivor set computed
    from the design, not from the input.
    """
    shown = rendered_text(DEFAULT, hostile) + "".join(
        tok.content for tok in _walk(DEFAULT.parse(hostile))
        if tok.type in ("code_inline", "fence")
    )
    assert marker in shown, f"{field}: the planted marker never reached the reader"

    if mode == "A" and field not in ("region_name", "issue_message"):
        # region_name is capped at 80 upstream (its own cap is pinned in
        # test_report_service.py), so only marker presence is checked here.
        want = expected_display(_payload(marker), "A", limit=512)
        assert want in shown, f"{field}: rendered text != the specified survivor set"
    elif field == "issue_message":
        # D-11: this field passes redaction BEFORE escaping, so the survivor set
        # is computed over the redacted value. Asserting the raw payload here
        # would demand that redaction NOT happen — a test that would go green
        # only by removing the control.
        want = expected_display(
            redact_absolute_paths(_payload(marker)), "A", limit=500
        )
        assert want in shown, f"{field}: rendered text != the specified survivor set"


def test_census_covers_every_reachable_file_derived_field(hostile: str) -> None:
    """The census is only as good as its coverage — so state it and pin it.

    14 fields are reachable through the public entry point. The remainder of the
    24 escape-required sites are the SAME values emitted at additional sites
    (a variant id appears in five places), plus the filter file name, which has
    its own hostile node in `test_report_service.py::test_tc318_*`.
    """
    assert len(PLANTED) == 14
    missing = [m for _, m, _ in PLANTED if m not in hostile]
    assert not missing, f"planted fields that never reached the document: {missing}"


# --------------------------------------------------------------------------- #
# Structural guards
# --------------------------------------------------------------------------- #


def test_every_table_row_keeps_its_header_width(hostile: str) -> None:
    """A-15 — replaces LLR-097.2's source-text guard with a painted-result one.

    The original guard matched a `|` in the same source line as an `md_code(`
    call. That false-negatives the moment a row is built by `" | ".join([...])`
    or the template moves into a helper — both ordinary refactors. Parsing every
    table in a hostile document survives refactoring and covers BOTH hazards:
    a pipe injected into a Mode-A cell, and Mode B landing in a cell at all.
    """
    tokens = list(_walk(DEFAULT.parse(hostile)))
    header_width = None
    width = 0
    checked = 0
    in_head = in_body = False
    for tok in tokens:
        if tok.type == "thead_open":
            in_head, width = True, 0
        elif tok.type == "thead_close":
            in_head, header_width = False, width
        elif tok.type == "tbody_open":
            in_body, width = True, 0
        elif tok.type == "tr_close" and in_body:
            assert width == header_width, (
                f"a body row has {width} cells against a {header_width}-cell "
                "header — a field shifted the columns"
            )
            checked += 1
            width = 0
        elif tok.type == "tbody_close":
            in_body = False
        elif tok.type in ("th_open", "td_open") and (in_head or in_body):
            width += 1
    assert checked >= 2, f"the guard must actually see rows, saw {checked}"


def test_a16_canonicaliser_residue_guard_can_actually_fire(tmp_path: Path) -> None:
    """A-16 — the guard inside `canonical_report_bytes` is not decorative.

    It was measured to fire at ZERO real call sites, which is the point: it
    should be silent today. But a guard that has never been seen to fail is
    indistinguishable from one that cannot, so this drives it directly.

    R-1 is what it defends: escaping a path before it reaches the file makes the
    run-root substitution MISS, and an absolute operator path gets baked into a
    golden and committed.
    """
    from conftest import canonical_report_bytes

    # Benign: the run root is substituted, nothing survives.
    clean = canonical_report_bytes(f"- saved as `{tmp_path}/a.s19`".encode(), tmp_path)
    assert b"<RUN-ROOT>" in clean

    # Hostile: a path the substitution cannot match — exactly what Mode A would
    # produce by escaping the separators out of the run-root spelling.
    for planted in (rb"- see C:\\Users\\op\\x.s19", rb"- see /home/op/x.s19"):
        with pytest.raises(AssertionError, match="A-16"):
            canonical_report_bytes(planted, tmp_path)


# --------------------------------------------------------------------------- #
# AT-161 + F-17 — the two scope EXCLUSIONS, pinned rather than assumed
# --------------------------------------------------------------------------- #


def test_at161_an_all_backtick_image_cannot_close_the_hexdump_fence(
    tmp_path: Path,
) -> None:
    """AT-161 — the hexdump block is excluded from escaping, and that is SAFE.

    The ASCII gutter renders raw image bytes, so byte `0x60` is a literal
    backtick in the document. Escaping the gutter was rejected: it would corrupt
    the one part of the report that must reproduce memory verbatim.

    The exclusion is safe because every gutter line is prefixed by its
    `0x%08X` address (`hexview.py`), so no line can ever consist of the three
    backticks a closing fence needs. That is an argument, and arguments rot —
    so this pins it with the worst input the format allows: an image made
    ENTIRELY of `0x60`.
    """
    span = range(0x1000, 0x1040)
    mem_map = {addr: 0x60 for addr in span}
    summary = _summary(
        [_applied_entry(0x1000, (0x60,), (0x60,), "standalone", "SYMA")],
        source="src.json",
    )
    results = [
        VariantExecutionResult(
            variant_id="a",
            status="ok",
            change_summaries=[summary],
            mem_map=mem_map,
        )
    ]
    variant_set = ProjectVariantSet(
        project_name="proj",
        variants=(
            VariantDescriptor(variant_id="a", path=Path("a.s19"), file_type="s19"),
        ),
        active_id="a",
    )
    text = generate_project_report(
        tmp_path, results, ReportOptions(context_bytes=0), variant_set=variant_set
    ).read_text(encoding="utf-8")

    assert "`" in text, (
        "the fixture must actually plant backticks in the gutter, else this "
        "test proves nothing"
    )
    for md, label in ((VIEWER, "viewer"), (DEFAULT, "default")):
        fences = [t for t in _walk(md.parse(text)) if t.type == "fence"]
        assert len(fences) == 1, (
            f"{label}: expected exactly one hexdump fence, got {len(fences)} — "
            "the image closed the block and escaped into document scope"
        )


def test_f17_format_bytes_is_inert_by_construction(tmp_path: Path) -> None:
    """F-17 — the byte cells are excluded from escaping; pin WHY.

    `_format_bytes` emits two-hex-digit tokens and spaces, or `-`. None of those
    characters is in `MD_ESCAPE`, so the cells are inert no matter what the
    image contains — including `0x60`, whose ASCII form would be a backtick but
    whose HEX form is the harmless `60`.
    """
    from s19_app.tui.services.report_service import _format_bytes

    rendered = _format_bytes(range(256))
    assert set(rendered) <= set("0123456789ABCDEF "), (
        f"_format_bytes emitted a character outside the hex alphabet: "
        f"{sorted(set(rendered) - set('0123456789ABCDEF '))}"
    )
    assert _format_bytes(None) == "-"

    # And in a REAL table, not a bare line: a lone `| x |` is just a paragraph,
    # so asserting "no live tokens" on one proves nothing.
    table = f"| h1 | h2 |\n|---|---|\n| {rendered} | b |"
    cells = []
    in_body = in_cell = False
    for tok in _walk(DEFAULT.parse(table)):
        if tok.type == "tbody_open":
            in_body = True
        elif tok.type == "td_open" and in_body:
            in_cell = True
        elif tok.type == "inline" and in_cell:
            cells.append("".join(
                c.content for c in _walk([tok]) if c.type == "text"
            ))
            in_cell = False
    assert cells == [rendered, "b"], "the byte cell did not round-trip verbatim"


def test_no_escaped_field_is_emitted_at_the_head_of_its_line() -> None:
    """A-23 pin 3 — the column-0 precondition, as a static guard.

    `md_safe` does not escape `-`, `+` or `=` except in leading position, and
    the newline collapse keeps a value off column 0. Both arguments assume the
    emission site prefixes the value with a literal. This asserts that
    assumption directly on the source.

    Read the ASSEMBLED template, not the source line. A regex over source lines
    was tried first and immediately false-positived on
    `report_service.py:1022` — the third chunk of an implicitly-concatenated
    f-string whose assembled line begins `- [`, so the value is nowhere near
    column 0. Python merges adjacent literals into ONE `JoinedStr` at parse
    time, so the AST gives the assembled template for free and the guard asks
    the question that actually matters: is the escaped value the FIRST thing in
    its line?
    """
    source = (
        Path(__file__).resolve().parents[1]
        / "s19_app" / "tui" / "services" / "report_service.py"
    ).read_text(encoding="utf-8")

    offenders = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.JoinedStr) or not node.values:
            continue
        head = node.values[0]
        if not isinstance(head, ast.FormattedValue):
            continue
        call = head.value
        if isinstance(call, ast.Call) and isinstance(call.func, ast.Name):
            if call.func.id in ("md_safe", "md_code"):
                offenders.append(f"line {node.lineno}: {call.func.id}(...)")

    assert not offenders, (
        "a file-derived value is emitted at the head of its own line template, "
        "where a leading block starter is no longer defused by the caller's "
        f"literal prefix: {offenders}"
    )
