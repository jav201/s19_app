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
from pathlib import Path, PurePosixPath

import pytest
from markdown_it import MarkdownIt

from s19_app.tui.models import ProjectVariantSet, VariantDescriptor
from s19_app.tui.services.markdown_safety import redact_absolute_paths
from s19_app.tui.services.report_addendum import DeclaredRegion
from s19_app.tui.services.markdown_safety import TRUNCATION_MARKER
from s19_app.tui.services.report_service import (
    MAX_REPORT_ISSUES_PER_VARIANT,
    REPORT_CELL_CHARS,
    REPORT_MAX_REGIONS_PER_VARIANT,
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
from s19_app.tui.changes.model import CheckRunEntry
from test_report_service import _applied_entry, _check, _summary

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

#: Corpus for **Mode-B** (path) fields. Two properties matter and the first
#: version of this fixture had neither:
#:
#: 1. an **ODD** number of backticks. With an even count the injected content
#:    lands INSIDE a code span that re-pairs with the caller's own wrap, so the
#:    payload is inert for the wrong reason and the census scores it green
#:    against a *broken* implementation (measured: removing `md_code` from the
#:    site left 197 + 73 tests passing);
#: 2. a `|`, which is the D-6 hazard itself — Mode B escapes nothing, so a raw
#:    pipe inside its span still splits a table cell. Windows forbids `|` in a
#:    filename, which is precisely why a fixture built from a real path could
#:    never exercise the rule.
_ATTACK_PATH = "`[l](http://evil.com)|**b**"


def _payload(marker: str) -> str:
    """A uniquely findable hostile value for one field."""
    attack = _ATTACK_FILENAME if marker in _FILENAME_MARKERS else _ATTACK
    return f"{marker}{attack}"


def _path_payload(marker: str) -> str:
    """A hostile Mode-B value that can actually exercise both hazards."""
    return f"{marker}{_ATTACK_PATH}"


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
    # Added at Inc-6: the ENTIRE checklist section was outside census reach
    # because `_hostile_report` never populated `check_results`. `check.source_path`
    # is the batch-39 long-standing carry this batch closed, and it had no test
    # that could fail — removing its `md_code` left 197 + 106 tests passing while
    # a hostile check path broke out of the `#### Checklist:` heading's span.
    ("check_source_path", "MKCHKSRC", "B"),
    ("check_result", "MKRESULT", "A"),
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
        # Mode-B values are constructed strings, not real paths: the hazard
        # needs a `|`, which no filesystem would accept in a filename.
        source=_path_payload(_MARKERS["change_source_path"]),
        issues=[issue],
        saved_path=PurePosixPath(_path_payload(_MARKERS["saved_path"])),
    )
    check = _check(
        [
            CheckRunEntry(
                "bytes", 0x1000, 0x1002, (0xAA, 0xBB), (0xAA, 0xBB),
                _payload(_MARKERS["check_result"]), "standalone", None,
            )
        ],
        source=_path_payload(_MARKERS["check_source_path"]),
    )
    results = [
        VariantExecutionResult(
            variant_id=_payload(_MARKERS["variant_id"]),
            status=_payload(_MARKERS["status"]),
            change_summaries=[summary],
            check_results=[check],
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
    # The benign fixture must have the SAME SHAPE as the hostile one — same
    # sections, same table count — because the structural assertions compare the
    # two documents. A benign report missing the checklist section would make
    # "the hostile document grew a table" fire on a fixture asymmetry rather than
    # on an injection.
    check = _check(
        [
            CheckRunEntry(
                "bytes", 0x1000, 0x1002, (0xAA, 0xBB), (0xAA, 0xBB),
                "pass", "standalone", None,
            )
        ],
        source="chk.json",
    )
    results = [
        VariantExecutionResult(
            variant_id="a", status="ok", change_summaries=[summary],
            check_results=[check],
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


#: Every distinct expression `report_service` routes through the escaper, DERIVED
#: from the source by AST at test time, and the reason each one is or is not
#: planted in the census fixture. Adding an escape site — or removing one — makes
#: this test RED until it is triaged.
#:
#: This replaces `assert len(PLANTED) == 14`, which could only fail when someone
#: edited `PLANTED`, i.e. exactly when they would already be updating it. A
#: fixture-driven completeness test inherits the drift it was written to
#: eliminate: the first version missed `check.source_path` and `entry.result`
#: entirely, because the fixture built no `check_results` at all.
_ESCAPED_EXPRESSIONS = {
    ("md_code", "check.source_path"): "planted (check_source_path)",
    ("md_code", "summary.saved_path"): "planted (saved_path)",
    ("md_code", "summary.source_path"): "planted (change_source_path)",
    ("md_safe", "descriptor.file_type"): "planted (file_type)",
    ("md_safe", "descriptor.path.name"): "planted (path_name)",
    ("md_safe", "descriptor.variant_id"): "planted (variant_id)",
    ("md_safe", "entry.linkage"): "planted (linkage)",
    ("md_safe", "entry.linkage_symbol"): "planted (linkage_symbol)",
    ("md_safe", "entry.result"): "planted (check_result)",
    ("md_safe", "issue.code"): "planted (issue_code)",
    ("md_safe", "issue.symbol"): "planted (issue_symbol)",
    ("md_safe", "name"): "planted (related_artifact) — the per-element join",
    ("md_safe", "project_name"): "planted (project_name)",
    ("md_safe", "redact_absolute_paths(issue.message)"): "planted (issue_message)",
    ("md_safe", "region.name"): "planted (region_name)",
    ("md_safe", "result.status"): "planted (status)",
    ("md_safe", "result.variant_id"): "planted (variant_id, 7 sites)",
    # NOT planted here, and each with a live node elsewhere:
    ("md_safe", "filter_name"): (
        "NOT planted — needs a resolved ReportFilterMatcher; driven hostile by "
        "test_report_service.py::test_tc318_hostile_filter_name_and_patterns_sanitized"
    ),
}


def test_census_covers_every_escaped_expression_in_the_source() -> None:
    """Completeness DERIVED from the source, not asserted as a count."""
    source = (
        Path(__file__).resolve().parents[1]
        / "s19_app" / "tui" / "services" / "report_service.py"
    ).read_text(encoding="utf-8")

    found = set()
    for node in ast.walk(ast.parse(source)):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id in ("md_safe", "md_code")):
            found.add((node.func.id, ast.unparse(node.args[0])))

    known = set(_ESCAPED_EXPRESSIONS)
    new = found - known
    gone = known - found
    assert not new, (
        "a NEW escaper call site exists with no census entry — plant it in "
        f"`PLANTED` or record why it cannot be: {sorted(new)}"
    )
    assert not gone, (
        f"an escaper call site disappeared — was a field left unescaped? {sorted(gone)}"
    )


def test_every_planted_marker_reaches_the_document(hostile: str) -> None:
    """A planted field that never appears proves nothing about itself."""
    missing = [m for _, m, _ in PLANTED if m not in hostile]
    assert not missing, f"planted fields that never reached the document: {missing}"


# --------------------------------------------------------------------------- #
# Structural guards
# --------------------------------------------------------------------------- #


def test_every_table_row_keeps_its_header_content(hostile: str, benign: str) -> None:
    """A-15, CORRECTED — assert cell CONTENT, because cell COUNT cannot fail.

    The first version of this test compared each body row's cell COUNT to its
    header's. That assertion is **vacuous**: GFM normalises every row to the
    header width — it truncates over-wide rows and pads short ones — so the
    counts are equal by construction. Measured across 8 shapes (extra pipes,
    missing cells, no outer pipes, `\\|`), the guard never fired once.

    Worse, it had REPLACED LLR-097.2's source-text guard, which did have
    detection power — so A-15 traded a working guard for one that could not
    fail. That is this batch's own defect class, in the test written to enforce
    D-6.

    The property that DOES bite: the row's positional cell contents. GFM
    silently DISCARDS the overflow when a row is over-wide (`| 1 | 2\\|X | 3 |`
    renders cells `1, 2, X` — the `3` is gone), which is a content-replacement
    primitive, so comparing content per row is what catches it.
    """
    def rows(document: str) -> list:
        out: list = []
        current: list = []
        in_body = in_cell = False
        for tok in _walk(DEFAULT.parse(document)):
            if tok.type == "tbody_open":
                in_body = True
            elif tok.type == "tbody_close":
                in_body = False
            elif tok.type == "tr_open" and in_body:
                current = []
            elif tok.type == "tr_close" and in_body:
                out.append(current)
            elif tok.type == "td_open" and in_body:
                in_cell = True
            elif tok.type == "inline" and in_cell:
                current.append("".join(
                    c.content for c in _walk([tok]) if c.type == "text"
                ))
                in_cell = False
        return out

    hostile_rows, benign_rows = rows(hostile), rows(benign)
    assert hostile_rows, "the guard must actually see rows"
    assert len(hostile_rows) == len(benign_rows), (
        "the hostile document grew or lost a table row"
    )
    for index, (hostile_row, benign_row) in enumerate(zip(hostile_rows, benign_rows)):
        assert len(hostile_row) == len(benign_row), (
            f"row {index}: {len(hostile_row)} cells vs {len(benign_row)} benign"
        )
        for column, cell in enumerate(hostile_row):
            assert cell != "", (
                f"row {index} column {column} rendered EMPTY — a field's content "
                "was discarded by row normalisation"
            )

    # Inc-7: the assertions above compare SHAPE, and shape alone still cannot
    # fail — removing `|` from `MD_ESCAPE` left them green. So the variant
    # inventory row, whose three Mode-A values are all planted, is compared
    # CELL-BY-CELL against the specified survivor set. This is the assertion
    # that bites: a pipe injected into any of the three shifts the row and the
    # expected value stops matching.
    expected_inventory = [
        expected_display(_payload(_MARKERS["variant_id"]), "A", limit=512),
        expected_display(_payload(_MARKERS["path_name"]), "A", limit=512),
        expected_display(_payload(_MARKERS["file_type"]), "A", limit=512),
        "yes",
    ]
    inventory = next(
        (row for row in hostile_rows if row and row[0].startswith(_MARKERS["variant_id"])),
        None,
    )
    assert inventory is not None, (
        "the inventory row was not found — the fixture no longer reaches it, so "
        "this guard would pass vacuously"
    )
    assert inventory == expected_inventory, (
        "the inventory row's positional cell CONTENT diverged from the specified "
        "survivor set — a field shifted the columns"
    )


def test_a_pipe_injected_into_a_cell_is_caught_by_content_comparison() -> None:
    """The counterfactual for the guard above: prove the new form can fail.

    A raw pipe in a cell shifts every following value one column left and drops
    the last one, at an UNCHANGED cell count. This is the input the count-based
    version scored green.
    """
    header = "| a | b | c |\n|---|---|---|\n"
    benign = header + "| 1 | 2 | 3 |"
    hostile = header + "| 1 | 2|X | 3 |"

    def cells(document: str) -> list:
        out: list = []
        in_body = in_cell = False
        for tok in _walk(DEFAULT.parse(document)):
            if tok.type == "tbody_open":
                in_body = True
            elif tok.type == "td_open" and in_body:
                in_cell = True
            elif tok.type == "inline" and in_cell:
                out.append("".join(
                    c.content for c in _walk([tok]) if c.type == "text"
                ))
                in_cell = False
        return out

    assert len(cells(hostile)) == len(cells(benign)), (
        "the premise of this test: the COUNT is unchanged, which is why a "
        "count assertion is vacuous"
    )
    assert cells(hostile) != cells(benign), (
        "content comparison must see the shift a count assertion cannot"
    )
    assert cells(hostile) == ["1", "2", "X"], "the third column was discarded"


def test_mode_b_in_a_table_cell_is_still_forbidden_at_every_call_site() -> None:
    """D-6's static half, RESTORED (F1).

    A-15 replaced the source-text guard with a painted-result one; the painted
    form turned out vacuous, and even corrected it cannot see a hazard the
    fixture never plants. So the static rule comes back, in the form the batch
    learned to write it: over the **AST**, not over source lines.

    Mode B escapes nothing, so a raw `|` inside its code span still splits the
    cell. The rule is that no `md_code(...)` value may be emitted into a line
    template that contains a `|` column separator.
    """
    source = (
        Path(__file__).resolve().parents[1]
        / "s19_app" / "tui" / "services" / "report_service.py"
    ).read_text(encoding="utf-8")

    offenders = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.JoinedStr):
            continue
        literals = "".join(
            part.value for part in node.values if isinstance(part, ast.Constant)
            and isinstance(part.value, str)
        )
        if "|" not in literals:
            continue
        for part in node.values:
            if not isinstance(part, ast.FormattedValue):
                continue
            for inner in ast.walk(part.value):
                if (isinstance(inner, ast.Call)
                        and isinstance(inner.func, ast.Name)
                        and inner.func.id == "md_code"):
                    offenders.append(f"line {node.lineno}")
    assert not offenders, (
        "md_code (Mode B) is emitted into a table-row template, where a raw "
        f"pipe in its value still splits the cell: {offenders}"
    )


# --------------------------------------------------------------------------- #
# Caps and second-order paths (TC-385/389/396/397) — Inc-5, closing Phase 4
# --------------------------------------------------------------------------- #


def _one_variant_report(
    tmp_path: Path,
    *,
    variant_id: str = "a",
    path_name: str = "a.s19",
    issues=(),
    regions=(),
    entries=None,
    mem_map=None,
) -> str:
    summary = _summary(
        list(entries) if entries is not None
        else [_applied_entry(0x1000, (0x01,), (0xAA,), "standalone", "SYMA")],
        source="src.json",
        issues=list(issues),
    )
    results = [
        VariantExecutionResult(
            variant_id=variant_id,
            status="ok",
            change_summaries=[summary],
            mem_map=dict(mem_map or {}),
        )
    ]
    variant_set = ProjectVariantSet(
        project_name="proj",
        variants=(
            VariantDescriptor(
                variant_id=variant_id, path=Path(path_name), file_type="s19"
            ),
        ),
        active_id=variant_id,
    )
    return generate_project_report(
        tmp_path,
        results,
        ReportOptions(declared_regions=tuple(regions)),
        variant_set=variant_set,
    ).read_text(encoding="utf-8")


def test_tc397_declaration_errors_are_capped_with_a_visible_marker(
    tmp_path: Path,
) -> None:
    """TC-397 / D-20 — the one section outside the byte budget now has a cap.

    `_ByteBudget` is consumed at hexdump-block granularity only, so this section
    was unbounded — and batch-62 made it worse before better, raising
    `issue.message`'s escape limit 240 -> 500 and roughly doubling the per-issue
    cost.

    The fixture is deliberately **1.5x the cap** (300 issues against 200), stated
    here per the batch-60 lesson: that batch's byte budget was entirely unpinned
    because its fixture sat 2.8x UNDER the limit, so every test passed with the
    guard deleted. Deleting the cap turns this RED.
    """
    count = MAX_REPORT_ISSUES_PER_VARIANT + MAX_REPORT_ISSUES_PER_VARIANT // 2
    assert count > MAX_REPORT_ISSUES_PER_VARIANT, "the fixture must cross the cap"
    issues = [
        ValidationIssue(
            code="X-BULK",
            severity=ValidationSeverity.ERROR,
            message=f"bulk issue {index}",
            artifact="changes",
        )
        for index in range(count)
    ]
    text = _one_variant_report(tmp_path, issues=issues)

    emitted = [ln for ln in text.splitlines() if ln.startswith("- [X-BULK]")]
    assert len(emitted) == MAX_REPORT_ISSUES_PER_VARIANT, (
        f"expected the cap to hold at {MAX_REPORT_ISSUES_PER_VARIANT}, "
        f"got {len(emitted)} emitted lines"
    )
    assert "> TRUNCATED:" in text, "the cut must be stated, never silent"
    assert f"{count - MAX_REPORT_ISSUES_PER_VARIANT} of {count}" in text


def test_tc396_report_cell_cap_is_pinned_at_a_composer_site(tmp_path: Path) -> None:
    """TC-396 — the report's OWN Mode-A cap, pinned where it is applied.

    `descriptor.path.name` is the right subject: it is file-derived, lands in a
    table cell, and has **no** upstream cap of its own, so it is the field a cap
    can silently truncate. The flow report's 240 is pinned elsewhere, but that is
    a different constant for a different consumer — pinning it does not pin this.

    Inc-6 correction: the first version built BOTH fixtures from the constant
    (`"x" * REPORT_CELL_CHARS`), so the fixtures moved with the value and
    changing 512 → 240 left every test green. What it pinned was agreement
    between the constant and the site's `limit`, not the property B-2 was raised
    for. The floor below is what actually holds the value, with the reason the
    constant's own docstring gives, and the survive arm now uses a LITERAL
    length so it is independent of the constant.
    """
    assert REPORT_CELL_CHARS >= 255, (
        "a filesystem basename reaches 255 characters and `descriptor.path.name` "
        "has no upstream cap, so a cap below 255 silently truncates a real "
        "filename in an evidentiary document"
    )
    at_cap = "x" * 255                      # a full NTFS basename, literal
    over_cap = "y" * (REPORT_CELL_CHARS + 1)

    text_at = _one_variant_report(tmp_path / "at", path_name=at_cap)
    assert TRUNCATION_MARKER not in text_at, "a value exactly at the cap must survive"
    assert at_cap in rendered_text(DEFAULT, text_at)

    text_over = _one_variant_report(tmp_path / "over", path_name=over_cap)
    assert TRUNCATION_MARKER in text_over, (
        "one character over the cap must be truncated with a visible marker"
    )


def test_tc389_truncation_appendix_note_is_escaped(tmp_path: Path) -> None:
    """TC-389 — a second-order path that only fires under truncation.

    The region cap emits `Variant '<id>': …` notes. That bullet is easy to miss
    because it exists only when the cap fires, so a hostile `variant_id` is
    driven through it explicitly rather than trusted.
    """
    hostile = _payload("MKTRUNC")
    count = REPORT_MAX_REGIONS_PER_VARIANT + 5
    entries = [
        _applied_entry(0x1000 + (index * 0x100), (0x01,), (0xAA,), "standalone", None)
        for index in range(count)
    ]
    # A memory map is required: without mapped bytes there are no regions to
    # dump, so the cap never fires and the fixture would prove nothing.
    mem_map = {0x1000 + (index * 0x100): 0xAA for index in range(count)}
    text = _one_variant_report(
        tmp_path, variant_id=hostile, entries=entries, mem_map=mem_map
    )

    # The appendix emits the note as a bullet, so the prefix is "- Variant '".
    note = next(
        (ln for ln in text.splitlines() if ln.startswith("- Variant '")), None
    )
    assert note is not None, "the region cap did not fire — the fixture is vacuous"
    assert "## Truncation appendix" in text
    assert "MKTRUNC" in note

    # Assert the TOKEN STREAM, not a character list. A first draft of this test
    # checked `"](" not in note` and failed on a CORRECT implementation, because
    # the escaped form is `\](` — the `]` is escaped and the `(` needs no escape
    # (a link is already dead once the brackets are). That is this batch's own
    # recurring defect, committed here in its own census.
    assert live_tokens(VIEWER, note) == {
        "bullet_list_open", "bullet_list_close", "list_item_open", "list_item_close",
    }, "the note minted a construct beyond its own bullet"
    assert rendered_text(VIEWER, note).startswith(f"Variant '{hostile}'")


def test_tc385_a_hostile_heading_cannot_change_its_own_level(tmp_path: Path) -> None:
    """TC-385 — the heading LEVEL, which a token-type set cannot see.

    `live_tokens` returns a SET of types, so `heading_open` is already present in
    any benign report and a payload that promoted `## Variant:` to `#` would slip
    through every structural assertion in this file. The level is therefore read
    off the token's own `tag`.
    """
    text = _one_variant_report(tmp_path, variant_id=_payload("MKHEAD"))
    levels = [
        tok.tag for tok in _walk(DEFAULT.parse(text)) if tok.type == "heading_open"
    ]
    assert levels.count("h1") == 1, (
        f"exactly one H1 (the report title) must exist, got {levels.count('h1')} — "
        "a field promoted its own heading"
    )
    assert "h2" in levels, "the per-variant H2 must still be an H2"


def test_lone_surrogate_is_dropped_like_any_other_unrepresentable_char() -> None:
    """F6 — `Cs` belongs in the drop set, and the reason is the contract.

    A lone surrogate is reachable from a POSIX filename read with
    `surrogateescape`. Before Inc-6 it survived normalisation and then raised
    `UnicodeEncodeError` at write time — fail-CLOSED, so not a bypass, but by
    accident rather than by the design `_normalise` documents ("replace
    unrepresentable characters with a visible marker").

    Placed in this file rather than the escaper battery only to keep Inc-6
    inside its 5-file budget; it is an escaper-level property.
    """
    from s19_app.tui.services.markdown_safety import LOSS_MARKER, md_code, md_safe

    surrogate = "A\ud800B"
    assert md_safe(surrogate, limit=240) == f"A{LOSS_MARKER}B"
    assert md_code(surrogate) == f"A{LOSS_MARKER}B"
    # And the result is now writable, which it was not before.
    assert md_safe(surrogate, limit=240).encode("utf-8")


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
