"""US-033 / batch-24 I2 — A2L issue => red-row reconcile (HLR-037).

Layer B gates (AT-037a/b) drive the SHIPPED load chain under Textual Pilot —
sync ``asyncio.run`` wrappers (idiom: ``tests/test_tui_patch_layout.py``;
helpers mirror ``tests/test_validation_service_supplemental.py`` — tests/ is
not a package, so the small drive/read-back helpers are duplicated rather than
cross-imported) — and observe the rendered ``#a2l_tags_list`` DataTable (colour
oracle, untouched) plus the grouped ``IssueRow`` issue read-back (C-14
migration: the retired ``#validation_issues_list`` DataTable). Row styles are asserted against
``_severity_style(ValidationSeverity.ERROR)`` (semantic colour-policy anchor;
no raw ``"red"`` literal). Fixtures are deliberately MAC-LESS: AT-037a's map
source (``_validation_issues``) exists in no-MAC sessions only thanks to the
I1 LLR-037.4 retention fix — I1 -> I2 is a STRICT dependency (HLR-037
Acceptance); adding a MAC to green anything here is forbidden.

Layer A: TC-037.1 unit-tests ``_a2l_issue_severity_map`` (LLR-037.1);
TC-037.2 pins the precedence matrix on ``_a2l_tag_row_severity`` including
the WARNING-never-recolours GUARD over CONSTRUCTED issues (A-M1 split, D-2 —
unbuildable black-box, so it lives here, not in an AT); TC-037.3 pins
first-render freshness on the sync-fallback load path (LLR-037.3).

``_a2l_issue_severity_map`` and the re-signatured ``_a2l_tag_row_severity``
are imported lazily inside the Layer-A tests so this module collected (and
AT-037a ran RED) on the pre-fix tree.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Awaitable, Callable, Optional

from textual.widgets import DataTable

from s19_app.tui.app import S19TuiApp, _severity_style
from s19_app.tui.changes.io import emit_s19_from_mem_map
from s19_app.validation import ValidationIssue, ValidationSeverity

DUPLICATE_CODE = "A2L_DUPLICATE_SYMBOL"
BROKEN_REF_CODE = "A2L_BROKEN_REFERENCE"
SUPPLEMENTAL_CODE = "A2L_TAG_SCHEMA_INCOMPLETE"

# Grouped ``IssueRow.issue`` read-back layout (C-14 migration):
# (severity, code, artifact, symbol, message)
_SEV, _CODE, _SYMBOL = 0, 1, 3


# ---------------------------------------------------------------------------
# Fixtures (synthetic, public data only). AT-037a per 01b: the same symbol
# defined twice as a CASE VARIANT (``RPM`` + ``rpm``) — the engine keys
# duplicates on ``name.lower()`` (rules.py:458,470), so BOTH rows must red —
# plus a healthy memory-checked control tag (green candidate) proving
# per-symbol targeting. Both duplicate rows are retained by the parse path
# (a2l.py:912-1068) and carry valid distinct addresses (schema_ok=True), so
# pre-fix they render OK/green: the red is delivered by the issue map alone.
# ---------------------------------------------------------------------------

_DUP_CASE_A2L = (
    "/begin PROJECT Demo\n"
    "  /begin MODULE Engine\n"
    "    /begin CHARACTERISTIC RPM\n"
    "      ECU_ADDRESS 0x1000\n"
    "      LENGTH 2\n"
    "    /end CHARACTERISTIC\n"
    "    /begin CHARACTERISTIC rpm\n"
    "      ECU_ADDRESS 0x1002\n"
    "      LENGTH 2\n"
    "    /end CHARACTERISTIC\n"
    "    /begin MEASUREMENT TORQUE\n"
    "      ECU_ADDRESS 0x1004\n"
    "      DATA_SIZE 2\n"
    "    /end MEASUREMENT\n"
    "  /end MODULE\n"
    "/end PROJECT\n"
)

# AT-037b: a GROUP reference to a symbol that never renders as a tag row —
# the shipped chain emits A2L_BROKEN_REFERENCE (WARNING, symbol-bearing,
# rules.py:507), putting an absent-from-table symbol into the severity map.
_BROKEN_REF_A2L = (
    "/begin PROJECT Demo\n"
    "  /begin MODULE Engine\n"
    "    /begin MEASUREMENT RPM\n"
    "      ECU_ADDRESS 0x1000\n"
    "      DATA_SIZE 2\n"
    "    /end MEASUREMENT\n"
    "    /begin GROUP PANEL\n"
    "      REF_MEASUREMENT GHOST_TAG\n"
    "    /end GROUP\n"
    "  /end MODULE\n"
    "/end PROJECT\n"
)

# AT-043-c17 (C-17, file-derived): the SAME broken-reference shape, but each
# GROUP REF names a HOSTILE ghost symbol carrying Rich-markup metacharacters.
# Per qa M-1 a single whitespace-delimited REF token cannot carry spaces, so the
# two hostile tokens are TWO separate no-whitespace REF entries. Both round-trip
# VERBATIM through the frozen ``a2l.py`` lexer + ``validate_a2l_internal_issues``
# (rules.py:497 ``raw.strip().split()`` — whitespace split preserves brackets)
# into ``issue.symbol`` AND ``issue.message`` (probe-confirmed in Phase 3), so a
# genuine file-derived hostile symbol reaches the grouped panel's ``.issue-detail``
# node — no constructed ``ValidationIssue``.
_HOSTILE_MARKUP_REF = "MAP_Model[bold]"  # Rich style tag -> MarkupError if parsed
_HOSTILE_LINK_REF = "x[link=file:///etc]"  # OSC-8 link token -> consumed if parsed
_HOSTILE_REF_A2L = (
    "/begin PROJECT Demo\n"
    "  /begin MODULE Engine\n"
    "    /begin MEASUREMENT RPM\n"
    "      ECU_ADDRESS 0x1000\n"
    "      DATA_SIZE 2\n"
    "    /end MEASUREMENT\n"
    "    /begin GROUP PANEL\n"
    f"      REF_MEASUREMENT {_HOSTILE_MARKUP_REF}\n"
    f"      REF_MEASUREMENT {_HOSTILE_LINK_REF}\n"
    "    /end GROUP\n"
    "  /end MODULE\n"
    "/end PROJECT\n"
)


def _write_s19(tmp_path: Path) -> Path:
    """Emit a 16-byte synthetic S19 image at 0x1000 covering every fixture
    address (builder idiom: tests/test_tui_patch_editor_v2.py::_make_s19_image)."""
    mem_map = {0x1000 + offset: 0x00 for offset in range(16)}
    text = emit_s19_from_mem_map(mem_map, [(0x1000, 0x1010)])
    path = tmp_path / "img.s19"
    path.write_text(text, encoding="ascii")
    return path


def _write_a2l(tmp_path: Path, text: str, name: str = "tags.a2l") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Shipped-chain drive + widget read-back helpers (idiom:
# tests/test_validation_service_supplemental.py; worker path =
# _parse_loaded_file -> _prepare_load_payload -> _apply_prepared_load).
# ---------------------------------------------------------------------------


def _drive_load(
    tmp_path: Path,
    s19_path: Path,
    a2l_path: Path,
    observe: Callable[[S19TuiApp, object], Awaitable[None]],
) -> None:
    """Load S19 (+attached A2L) through the shipped worker-path chain under
    Pilot, then hand the app to ``observe`` for black-box asserts."""

    async def _run() -> None:
        app = S19TuiApp(base_dir=tmp_path)
        app.current_a2l_path = a2l_path
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            loaded = app._parse_loaded_file(s19_path)
            assert loaded is not None, "shipped parse chain returned no LoadedFile"
            prepared = app._prepare_load_payload(loaded)
            app._apply_prepared_load(prepared, s19_path, 0.0)
            for _ in range(8):
                await pilot.pause()
            await observe(app, pilot)

    asyncio.run(_run())


def _a2l_row_list(app: S19TuiApp) -> list[tuple[str, tuple]]:
    """Rendered ``#a2l_tags_list`` rows as ``(name_cell_text, cells)`` pairs
    (cells are the styled ``rich.text.Text`` objects; name is column 0)."""
    table = app.query_one("#a2l_tags_list", DataTable)
    rows: list[tuple[str, tuple]] = []
    for index in range(table.row_count):
        cells = table.get_row_at(index)
        rows.append((str(cells[0]), tuple(cells)))
    return rows


def _issue_rows(app: S19TuiApp) -> list[tuple]:
    """Grouped-panel issue read-back (C-14 migration): the ``ValidationIssue``
    each mounted ``IssueRow`` carries, as ``(severity, code, artifact, symbol,
    message)`` tuples. Replaces the retired ``#validation_issues_list``
    DataTable read; reading the issue object (not rendered cells) keeps the
    ``_SEV`` comparison on the ``ValidationSeverity`` enum (stronger typing)."""
    from s19_app.tui.issues_view import IssueRow

    return [
        (
            row.issue.severity,
            row.issue.code,
            row.issue.artifact,
            row.issue.symbol,
            row.issue.message,
        )
        for row in app.query(IssueRow)
    ]


def _assert_within_cap(app: S19TuiApp) -> None:
    """C-14 count-guard (v2): ``GroupedIssuesPanel`` caps mounted rows at
    ``_GROUP_DISPLAY_MAX`` regardless of ``page_size``, so a whole-list count
    or absence claim over ``query(IssueRow)`` is faithful only when the whole
    filtered list fits under the cap. These fixtures emit <=4 issues; this pins
    that so a future larger fixture cannot satisfy a claim vacuously."""
    from s19_app.tui.issues_view import _GROUP_DISPLAY_MAX

    assert len(app._filtered_validation_issues()) <= _GROUP_DISPLAY_MAX, (
        "fixture exceeds the grouped-panel row cap; the capped IssueRow read "
        "would no longer equal the whole filtered list"
    )


# ---------------------------------------------------------------------------
# Layer B — AT-037a (GATE): duplicate symbol -> ERROR issue reds BOTH rows;
# control row untouched; issue list content unchanged (render-side-only fix).
# Counterfactual (the reported bug): pre-fix both duplicate rows render
# non-red (schema_ok=True + memory-checked -> OK/green) while the
# A2L_DUPLICATE_SYMBOL ERROR sits on the Issues surface — captured verbatim
# in .dev-flow/2026-07-02-batch-24/03-increments/increment-2.md.
# ---------------------------------------------------------------------------


def test_at_037a_duplicate_symbol_error_issue_reds_both_rows(tmp_path: Path) -> None:
    s19_path = _write_s19(tmp_path)
    a2l_path = _write_a2l(tmp_path, _DUP_CASE_A2L)

    async def _observe(app: S19TuiApp, pilot: object) -> None:
        error_style = _severity_style(ValidationSeverity.ERROR)
        rows = _a2l_row_list(app)
        dup_rows = [cells for name, cells in rows if name.casefold() == "rpm"]
        assert len(dup_rows) == 2, (
            f"expected both case-variant duplicate rows rendered; "
            f"got names: {[name for name, _ in rows]}"
        )
        # Observable 1 — BOTH duplicate rows ERROR-styled (case-folded match,
        # mirroring the engine's name.lower() duplicate grouping).
        for cells in dup_rows:
            assert all(cell.style == error_style for cell in cells), (
                "duplicate-symbol row is not ERROR-styled "
                "(ERROR issue does not recolour its rows — the HLR-037 divergence)"
            )
        # Observable 2 — healthy control row unaffected (per-symbol targeting).
        torque_rows = [cells for name, cells in rows if name == "TORQUE"]
        assert torque_rows, "control tag TORQUE missing from the rendered table"
        assert all(cell.style != error_style for cell in torque_rows[0]), (
            "control tag TORQUE must not be recoloured"
        )
        # Observable 3 — issue list content unchanged (US-033 is render-side
        # only): exactly one A2L_DUPLICATE_SYMBOL ERROR, no supplemental code.
        app.action_show_screen("issues")
        await pilot.pause()
        # C-14 count-guard: the whole filtered list fits under the row cap, so
        # the capped IssueRow read below equals the whole list (both the
        # "exactly one" and the "not any" claims are then faithful).
        _assert_within_cap(app)
        issue_rows = _issue_rows(app)
        dup_issues = [row for row in issue_rows if row[_CODE] == DUPLICATE_CODE]
        assert len(dup_issues) == 1, (
            f"expected exactly ONE {DUPLICATE_CODE} issue; rows: {issue_rows!r}"
        )
        assert dup_issues[0][_SEV] == ValidationSeverity.ERROR
        assert dup_issues[0][_SYMBOL].casefold() == "rpm"
        assert not any(row[_CODE] == SUPPLEMENTAL_CODE for row in issue_rows), (
            "schema-complete duplicate tags must gain no supplemental issue"
        )

    _drive_load(tmp_path, s19_path, a2l_path, _observe)


# ---------------------------------------------------------------------------
# Layer B — AT-037b (boundary, A-M1 split): an issue symbol ABSENT from the
# rendered tag set (naturally produced via A2L_BROKEN_REFERENCE) is inert —
# no crash, no row change.
# ---------------------------------------------------------------------------


def test_at_037b_absent_from_table_issue_symbol_is_inert(tmp_path: Path) -> None:
    s19_path = _write_s19(tmp_path)
    a2l_path = _write_a2l(tmp_path, _BROKEN_REF_A2L)

    async def _observe(app: S19TuiApp, pilot: object) -> None:
        error_style = _severity_style(ValidationSeverity.ERROR)
        rows = dict(_a2l_row_list(app))
        assert "RPM" in rows, f"expected RPM rendered; got {sorted(rows)}"
        assert "GHOST_TAG" not in rows, "referenced-only symbol must not render as a tag row"
        # No row change: the healthy tag keeps its non-ERROR style.
        assert all(cell.style != error_style for cell in rows["RPM"]), (
            "absent-from-table issue symbol must not recolour other rows"
        )
        # Load-bearing positive assert: the shipped chain really produced the
        # absent-symbol issue (otherwise this boundary passes vacuously).
        app.action_show_screen("issues")
        await pilot.pause()
        # C-14 count-guard: whole filtered list fits under the row cap, so the
        # ghost issue (if produced) is guaranteed present in the capped read.
        _assert_within_cap(app)
        issue_rows = _issue_rows(app)
        ghost = [
            row
            for row in issue_rows
            if row[_CODE] == BROKEN_REF_CODE and row[_SYMBOL] == "GHOST_TAG"
        ]
        assert ghost, (
            f"fixture failed to produce the natural {BROKEN_REF_CODE} issue "
            f"for GHOST_TAG; rows: {issue_rows!r}"
        )

    _drive_load(tmp_path, s19_path, a2l_path, _observe)


# ---------------------------------------------------------------------------
# Layer B — AT-043-c17 (C-17 MANDATORY, FILE-DERIVED) / LLR-043.R6 + LLR-043.R8
# (US-043). Realizes the spec's file-derived C-17 AT (01-requirements.md §3):
# a hostile symbol must reach the grouped panel's rendered ``.issue-detail`` node
# by flowing through the REAL load chain (file -> frozen a2l.py lexer ->
# issue.symbol -> GroupedIssuesPanel), NOT a constructed ``ValidationIssue``.
# This is the file-derived counterpart to the retained SEEDED companion
# ``test_at_039e_c17_...`` (tests/test_tui_directionb.py), which proves the same
# literal-render invariant over a constructed hostile issue (+ ANSI byte + code
# field). Both are kept: C-17 discipline requires the hostile input be
# file-derived here, so the token survives the parser it will meet in production.
# ---------------------------------------------------------------------------


def test_at_043_c17_file_derived_hostile_ref_symbol_renders_literal(
    tmp_path: Path,
) -> None:
    """AT-043-c17 (C-17) / LLR-043.R6 + LLR-043.R8 (US-043) — a FILE-DERIVED
    hostile GROUP-REF symbol renders LITERAL in the grouped ``.issue-detail`` node.

    Intent: load an A2L whose GROUP names two hostile no-whitespace ghost symbols
    (``MAP_Model[bold]`` and ``x[link=file:///etc]``) through the SHIPPED load
    chain (``_parse_loaded_file`` -> ``_prepare_load_payload`` ->
    ``_apply_prepared_load`` -> ``update_validation_issues_view`` ->
    ``GroupedIssuesPanel``). The frozen ``a2l.py`` lexer +
    ``validate_a2l_internal_issues`` split the GROUP lines on whitespace
    (rules.py:497), so each bracket-bearing token round-trips VERBATIM into an
    ``A2L_BROKEN_REFERENCE`` issue's ``.symbol`` (and its ``.message``) — a
    genuine untrusted-file value, not a constructed ``ValidationIssue``. The
    ``IssueRow`` composes that value into its ``.issue-detail`` span
    (``symbol · address · message``) via ``safe_text`` (issues_view.py:186).

    Assert: the run raises NO ``rich.errors.MarkupError``, and the combined
    ``.issue-detail`` plain text contains the LITERAL ``MAP_Model[bold]``
    (brackets intact) and the LITERAL ``x[link=file:///etc]`` / ``[link=...]``
    token (NOT consumed -> no OSC-8 hyperlink, no style leak).

    Counterfactual (discriminates the fix): if ``.issue-detail`` parsed Rich
    markup instead of using ``safe_text``, mounting would either raise
    ``MarkupError`` on ``[bold]`` or SILENTLY CONSUME the ``[link=file:///etc]``
    token into an OSC-8 hyperlink — the literal-bracket assertions below would
    then fail. Asserting the brackets survive verbatim is exactly what makes this
    non-vacuous.

    Frozen-lexer note: Phase-3 probe confirmed the frozen ``a2l.py`` chain
    preserves BOTH hostile tokens verbatim (``issue.symbol ==
    'MAP_Model[bold]'`` and ``'x[link=file:///etc]'``), so no fallback token was
    needed — the strongest hostile tokens the spec names are the ones exercised.
    """
    s19_path = _write_s19(tmp_path)
    a2l_path = _write_a2l(tmp_path, _HOSTILE_REF_A2L)

    async def _observe(app: S19TuiApp, pilot: object) -> None:
        from s19_app.tui.issues_view import IssueRow

        # Load-bearing positive assert: the shipped chain really produced the
        # two file-derived hostile-symbol issues (otherwise the literal checks
        # below could pass vacuously over an empty detail set).
        app.action_show_screen("issues")
        await pilot.pause()
        _assert_within_cap(app)
        issue_rows = _issue_rows(app)
        ghost_symbols = {
            row[_SYMBOL]
            for row in issue_rows
            if row[_CODE] == BROKEN_REF_CODE
        }
        assert {_HOSTILE_MARKUP_REF, _HOSTILE_LINK_REF} <= ghost_symbols, (
            f"fixture failed to carry the hostile REF tokens verbatim into "
            f"issue.symbol via the frozen lexer; issues: {issue_rows!r}"
        )

        # Observe through the SHIPPED grouped surface: the rendered plain text of
        # every mounted ``.issue-detail`` node. ``render().plain`` yields the
        # literal, un-parsed text (the idiom used by the seeded companion
        # test_at_039e_c17_...); reaching this line at all proves compose/mount
        # raised no MarkupError over the hostile file-derived symbols.
        details = [row.query_one(".issue-detail").render().plain for row in app.query(IssueRow)]
        combined = "\n".join(details)
        assert _HOSTILE_MARKUP_REF in combined, (
            f"file-derived symbol must render brackets literally in "
            f".issue-detail; details={details!r}"
        )
        assert "[link=file:///etc]" in combined, (
            f"the [link=...] token must survive as literal text (no OSC-8 "
            f"parse); details={details!r}"
        )

    _drive_load(tmp_path, s19_path, a2l_path, _observe)


# ---------------------------------------------------------------------------
# Layer B — AT-066b (C-17 hostile-input, US-066/B-17, batch-38): a FILE-DERIVED
# hostile tag NAME on a >32-bit-address tag flows through the real load chain
# into the oversize WARNING (message + symbol) and renders LITERAL/neutralized
# in the grouped ``.issue-detail`` node. Bracket + [link=...] tokens survive
# VERBATIM (whitespace-split name parser a2l.py:218; safe_text render); the ANSI
# CSI is NEUTRALIZED, not verbatim (ValidationIssue.__post_init__ strips CSI from
# message, model.py:71; safe_text neutralizes any reaching symbol). No crash,
# no MarkupError, no style leak.
#
# Counterfactual: if the tag name were interpolated into a markup-parsed string
# the ``[red]`` would be consumed as styling (bracket chars absent) or raise
# MarkupError, and the raw ESC byte would leak — the assertions below fail RED.
# ---------------------------------------------------------------------------

OVERSIZED_CODE = "A2L_ADDRESS_EXCEEDS_32BIT"

# Three oversized (>0xFFFFFFFF) tags, each with a hostile no-whitespace NAME:
# brackets, an OSC-8-style [link=...] token, and a raw ANSI CSI escape. All
# survive the whitespace-split name parser; the addresses parse via int(_, 0).
_HOSTILE_BRACKET_NAME = "MARK_[red]evil[/red]"
_HOSTILE_LINK_NAME = "LINK_x[link=file:///etc]"
_HOSTILE_ANSI_NAME = "ANSI_\x1b[31mHACK"
_HOSTILE_OVERSIZED_A2L = (
    "/begin PROJECT Demo\n"
    "  /begin MODULE Engine\n"
    f"    /begin CHARACTERISTIC {_HOSTILE_BRACKET_NAME}\n"
    "      ECU_ADDRESS 0x100000000\n"
    "      LENGTH 2\n"
    "    /end CHARACTERISTIC\n"
    f"    /begin CHARACTERISTIC {_HOSTILE_LINK_NAME}\n"
    "      ECU_ADDRESS 0x100000001\n"
    "      LENGTH 2\n"
    "    /end CHARACTERISTIC\n"
    f"    /begin CHARACTERISTIC {_HOSTILE_ANSI_NAME}\n"
    "      ECU_ADDRESS 0x100000002\n"
    "      LENGTH 2\n"
    "    /end CHARACTERISTIC\n"
    "  /end MODULE\n"
    "/end PROJECT\n"
)


def test_at_066b_oversized_hostile_tag_name_renders_safely(tmp_path: Path) -> None:
    s19_path = _write_s19(tmp_path)
    a2l_path = _write_a2l(tmp_path, _HOSTILE_OVERSIZED_A2L)

    async def _observe(app: S19TuiApp, pilot: object) -> None:
        from s19_app.tui.issues_view import IssueRow

        # Load-bearing positive assert: the shipped chain produced the three
        # file-derived oversize WARNINGs (otherwise the checks below could pass
        # vacuously over an empty set).
        app.action_show_screen("issues")
        await pilot.pause()
        _assert_within_cap(app)
        oversize_widgets = [
            row for row in app.query(IssueRow) if row.issue.code == OVERSIZED_CODE
        ]
        assert len(oversize_widgets) == 3, (
            f"expected three {OVERSIZED_CODE} WARNINGs for the hostile oversized "
            f"tags; got codes: {[r.issue.code for r in app.query(IssueRow)]!r}"
        )
        by_symbol = {row.issue.symbol: row for row in oversize_widgets}

        # (i) Bracket + link payloads survive VERBATIM in the constructed
        # WARNING message (no markup pre-formatting) — model.py scrub keeps
        # ``[...]`` (only control/ANSI are stripped).
        bracket_msg = by_symbol[_HOSTILE_BRACKET_NAME].issue.message
        link_msg = by_symbol[_HOSTILE_LINK_NAME].issue.message
        assert "[red]evil[/red]" in bracket_msg, bracket_msg
        assert "[link=file:///etc]" in link_msg, link_msg

        # (ii) ANSI CSI is NEUTRALIZED (NOT verbatim): __post_init__ strips the
        # CSI from ``message`` (model.py:71), so neither the raw ESC nor the
        # ``[31m`` remnant survives; the readable name text still appears.
        ansi_msg = by_symbol[_HOSTILE_ANSI_NAME].issue.message
        assert "\x1b" not in ansi_msg, repr(ansi_msg)
        assert "[31m" not in ansi_msg, repr(ansi_msg)
        assert "ANSI_" in ansi_msg and "HACK" in ansi_msg, repr(ansi_msg)

        # Render safety (C-17): reaching a rendered ``.issue-detail`` at all
        # proves compose/mount raised no MarkupError over the hostile names, and
        # the brackets appear LITERAL in the rendered plain text (no style leak,
        # no OSC-8 parse) — the same literal-render oracle as AT-043-c17.
        bracket_detail = (
            by_symbol[_HOSTILE_BRACKET_NAME].query_one(".issue-detail").render().plain
        )
        link_detail = (
            by_symbol[_HOSTILE_LINK_NAME].query_one(".issue-detail").render().plain
        )
        assert "[red]evil[/red]" in bracket_detail, repr(bracket_detail)
        assert "[link=file:///etc]" in link_detail, repr(link_detail)

    _drive_load(tmp_path, s19_path, a2l_path, _observe)


# ---------------------------------------------------------------------------
# Layer B — AT-066a (US-066/B-17, batch-38): a >32-bit A2L tag address surfaces
# a WARNING naming the tag on the shipped issues surface; a sibling tag at the
# 32-bit max (0xFFFFFFFF) produces no such WARNING (boundary/negative control).
# Driven through the real app load handler (reuses the module-level ``_write_s19``
# / ``_drive_load`` / ``_issue_rows`` helpers — same shipped worker path).
# Relocated here from tests/test_tui_a2l.py (git-frozen engine test file); net
# test count unchanged, behavior byte-identical.
# RED counterfactual: at main there is 0 >32-bit handling in the service, so no
# A2L_ADDRESS_EXCEEDS_32BIT WARNING is produced and the assertion fails RED.
# ---------------------------------------------------------------------------

# Two schema-complete CHARACTERISTIC tags: BIG_TAG one past the 32-bit max
# (must warn), EDGE_TAG exactly at the 32-bit max (must NOT warn). The parser
# reads ECU_ADDRESS via int(token, 0) (a2l.py:984) so the addresses are genuine
# ints, not strings — the A-1 positive-branch guard (isinstance int) fires.
_OVERSIZED_A2L = (
    "/begin PROJECT Demo\n"
    "  /begin MODULE Engine\n"
    "    /begin CHARACTERISTIC BIG_TAG\n"
    "      ECU_ADDRESS 0x100000000\n"
    "      LENGTH 2\n"
    "    /end CHARACTERISTIC\n"
    "    /begin CHARACTERISTIC EDGE_TAG\n"
    "      ECU_ADDRESS 0xFFFFFFFF\n"
    "      LENGTH 2\n"
    "    /end CHARACTERISTIC\n"
    "  /end MODULE\n"
    "/end PROJECT\n"
)


def test_at_066a_oversized_a2l_address_warns_naming_tag(tmp_path: Path) -> None:
    s19_path = _write_s19(tmp_path)
    a2l_path = _write_a2l(tmp_path, _OVERSIZED_A2L, name="oversized.a2l")

    async def _observe(app: S19TuiApp, pilot: object) -> None:
        app.action_show_screen("issues")
        await pilot.pause()
        rows = _issue_rows(app)
        oversized = [row for row in rows if row[_CODE] == OVERSIZED_CODE]
        # Exactly one WARNING, naming BIG_TAG; EDGE_TAG at the 32-bit max does
        # not warn (boundary/negative control on the same load).
        assert len(oversized) == 1, (
            f"expected exactly one {OVERSIZED_CODE} WARNING; issue rows: {rows!r}"
        )
        row = oversized[0]
        assert row[_SEV] == ValidationSeverity.WARNING
        assert row[_SYMBOL] == "BIG_TAG"
        assert "BIG_TAG" in row[4]
        assert "EDGE_TAG" not in row[4]
        assert not any(
            row[_SYMBOL] == "EDGE_TAG" and row[_CODE] == OVERSIZED_CODE for row in rows
        ), "the 0xFFFFFFFF boundary tag must not produce an oversize WARNING"

    _drive_load(tmp_path, s19_path, a2l_path, _observe)


# ---------------------------------------------------------------------------
# Layer A — TC-037.1 (LLR-037.1): map build/filter semantics — a2l-only,
# non-empty symbol only, casefolded keys, max severity order-independent.
# ---------------------------------------------------------------------------


def _issue(
    code: str,
    severity: ValidationSeverity,
    artifact: str,
    symbol: Optional[str],
) -> ValidationIssue:
    return ValidationIssue(
        code=code, severity=severity, message="m", artifact=artifact, symbol=symbol
    )


def test_tc_037_1_issue_severity_map_build_and_filter_semantics() -> None:
    from s19_app.tui.app import _a2l_issue_severity_map

    issues = [
        _issue("A2L_DUPLICATE_SYMBOL", ValidationSeverity.ERROR, "a2l", "Dup_Sym"),
        _issue("A2L_BROKEN_REFERENCE", ValidationSeverity.WARNING, "a2l", "dup_sym"),
        _issue("A2L_BROKEN_REFERENCE", ValidationSeverity.WARNING, "a2l", "WARN_ONLY"),
        _issue("CROSS_MAC_S19_OUT_OF_RANGE", ValidationSeverity.ERROR, "mac", "MAC_SYM"),
        _issue("A2L_STRUCTURE_ERROR", ValidationSeverity.ERROR, "a2l", None),
        _issue("A2L_INVALID_ADDRESS", ValidationSeverity.ERROR, "a2l", ""),
    ]
    severity_map = _a2l_issue_severity_map(issues)
    assert severity_map == {
        "dup_sym": ValidationSeverity.ERROR,  # max wins over the later WARNING
        "warn_only": ValidationSeverity.WARNING,
    }, "map must filter non-a2l + symbol-less issues and casefold keys"

    # Order independence: WARNING first, ERROR second -> still ERROR.
    reordered = _a2l_issue_severity_map(
        [
            _issue("A2L_BROKEN_REFERENCE", ValidationSeverity.WARNING, "a2l", "sym"),
            _issue("A2L_DUPLICATE_SYMBOL", ValidationSeverity.ERROR, "a2l", "SYM"),
        ]
    )
    assert reordered == {"sym": ValidationSeverity.ERROR}

    assert _a2l_issue_severity_map([]) == {}


# ---------------------------------------------------------------------------
# Layer A — TC-037.2 (LLR-037.2): precedence matrix — ERROR-mapped symbol
# beats every ladder outcome (incl. green); empty map reduces to the existing
# ladder; unmapped symbol unchanged; and the WARNING-never-recolours GUARD
# over CONSTRUCTED issues (A-M1 / D-2: the A2L palette is Red/Green/White/
# Grey only — recolouring on WARNING would invent a fifth state).
# ---------------------------------------------------------------------------

_LADDER: list[tuple[dict, ValidationSeverity]] = [
    ({"name": "T", "schema_ok": False}, ValidationSeverity.ERROR),
    (
        {"name": "T", "schema_ok": True, "memory_checked": True, "in_memory": True},
        ValidationSeverity.OK,
    ),
    (
        {"name": "T", "schema_ok": True, "memory_checked": True, "in_memory": False},
        ValidationSeverity.INFO,
    ),
    (
        {"name": "T", "schema_ok": True, "memory_checked": False, "source": "formula"},
        ValidationSeverity.INFO,
    ),
    ({"name": "T", "schema_ok": True, "memory_checked": False}, ValidationSeverity.NEUTRAL),
]


def test_tc_037_2_row_severity_precedence_matrix_and_warning_guard() -> None:
    from s19_app.tui.app import _a2l_tag_row_severity

    # Empty map -> the function reduces to the pre-US-033 ladder exactly.
    for tag, expected in _LADDER:
        assert _a2l_tag_row_severity(tag, {}) == expected, f"empty-map ladder broke for {tag}"

    # ERROR-mapped symbol (casefolded lookup) -> ERROR wins over EVERY ladder
    # outcome, including the green memory-checked-present candidate.
    error_map = {"t": ValidationSeverity.ERROR}
    for tag, _ in _LADDER:
        assert _a2l_tag_row_severity(tag, error_map) == ValidationSeverity.ERROR, (
            f"ERROR issue must recolour {tag}"
        )

    # GUARD (D-2): WARNING-mapped symbol never recolours — ladder unchanged.
    warning_map = {"t": ValidationSeverity.WARNING}
    for tag, expected in _LADDER:
        assert _a2l_tag_row_severity(tag, warning_map) == expected, (
            f"WARNING issue must NOT recolour {tag} (A2L palette has no orange)"
        )

    # Unmapped symbol -> unchanged.
    other_map = {"other": ValidationSeverity.ERROR}
    for tag, expected in _LADDER:
        assert _a2l_tag_row_severity(tag, other_map) == expected

    # Nameless tag never consults the map.
    assert (
        _a2l_tag_row_severity({"schema_ok": True, "memory_checked": False}, {"": ValidationSeverity.ERROR})
        == ValidationSeverity.NEUTRAL
    )


# ---------------------------------------------------------------------------
# Layer A — TC-037.3 (LLR-037.3): first-render freshness on the SYNC-FALLBACK
# load path (no worker precompute): update_a2l_view must install the issue
# list (update_mac_view, post-enrichment) BEFORE tag rows render, so the
# duplicate rows are red on the FIRST rendered frame — the load chain never
# re-renders the tag table afterwards, so a stale first frame would persist.
# ---------------------------------------------------------------------------


def test_tc_037_3_sync_fallback_first_render_is_fresh(tmp_path: Path) -> None:
    s19_path = _write_s19(tmp_path)
    a2l_path = _write_a2l(tmp_path, _DUP_CASE_A2L)

    async def _run() -> None:
        app = S19TuiApp(base_dir=tmp_path)
        app.current_a2l_path = a2l_path
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            loaded = app._parse_loaded_file(s19_path)
            assert loaded is not None
            app._apply_loaded_file(loaded, s19_path, 0.0)
            for _ in range(8):
                await pilot.pause()
            error_style = _severity_style(ValidationSeverity.ERROR)
            dup_rows = [
                cells for name, cells in _a2l_row_list(app) if name.casefold() == "rpm"
            ]
            assert len(dup_rows) == 2
            for cells in dup_rows:
                assert all(cell.style == error_style for cell in cells), (
                    "stale first render on the sync-fallback path: issues were "
                    "installed AFTER the tag rows rendered (LLR-037.3 reorder)"
                )

    asyncio.run(_run())
