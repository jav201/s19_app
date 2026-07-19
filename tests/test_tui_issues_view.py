"""Issues Report view tests — batch-17 US-020a (HLR-020).

US-020a adds a hex pane (`#issues_hex_pane`) beside the validation issues list:
selecting an issue row that carries an address renders the bytes at that address;
selecting an issue with NO address shows a placeholder and clears any bytes from a
prior selection (no stale render).

AT-020a drives the SHIPPED VISIBLE surface — `action_show_screen("issues")` then
a real grouped-panel `IssueRow` selection (focus + Enter -> `IssueRow.on_key` ->
`IssueRow.Selected` -> `on_issue_row_selected` -> `_update_issues_hex_pane`; the
legacy DataTable is retired since batch-29) — and asserts the pane CONTENT (the
address row + a
known byte for the addressed issue; the exact placeholder for the address-less
one, with the prior bytes gone). It is value-discriminating: a blank/stale pane
or a dropped address fails.

Issues are injected via `app._validation_issues` + `update_validation_issues_view`
(the established `tests/test_tui_directionb.py::_seed_issues_screen` idiom); the
loaded fixture's mem_map carries the addressed issue's bytes so the render is real.
"""

from __future__ import annotations

import asyncio
import re
from collections import Counter
from pathlib import Path

from rich.text import Text
from textual.widgets import Label, Static

from s19_app.core import S19File
from s19_app.tui.app import S19TuiApp
from s19_app.tui.changes.io import emit_s19_from_mem_map
from s19_app.tui.insight_style import CYAN, RED, YELLOW
from s19_app.tui.issues_view import (
    _ISSUES_STRIP_BAR_WIDTH,
    _SEVERITY_GLYPH,
    SEVERITY_LABELS,
    SEVERITY_ORDER,
    IssueGroupHeader,
    IssueRow,
    build_issues_severity_strip,
)
from s19_app.tui.services.load_service import build_loaded_s19
from s19_app.validation import ValidationIssue, ValidationSeverity

#: Distinctive bytes at a known address so the rendered pane is unambiguous.
_ADDR = 0x1000
_BYTES = {0x1000: 0xAB, 0x1001: 0xCD, 0x1002: 0xEF, 0x1003: 0x12}

_NO_ADDRESS_PLACEHOLDER = "(issue has no address — nothing to show)"


def _render_issue_list(
    app: S19TuiApp, tmp_path: Path, issues: list[ValidationIssue]
) -> None:
    """Load a fixture (bytes at ``_ADDR``) and render ``issues`` into the table.

    Mirrors the directionb ``_seed_issues_screen`` setup: install ``current_file``
    so the empty state flips, set ``_validation_issues``, filter=all, render.
    """
    path = tmp_path / "issues_fixture.s19"
    path.write_text(
        emit_s19_from_mem_map(_BYTES, [(0x1000, 0x1004)]), encoding="utf-8"
    )
    s19 = S19File(str(path))
    app.current_file = build_loaded_s19(path, s19, a2l_path=None, a2l_data=None)
    app._apply_empty_state()
    app._validation_issues = issues
    app.validation_issue_filter_mode = "all"
    app._validation_issues_window_start = 0
    app.update_validation_issues_view()


def _seed_issues(app: S19TuiApp, tmp_path: Path) -> None:
    """Install the addressed + address-less issue pair (AT-020a)."""
    _render_issue_list(
        app,
        tmp_path,
        [
            ValidationIssue(
                code="ADDR_ISSUE",
                severity=ValidationSeverity.ERROR,
                message="addressed issue",
                artifact="s19",
                symbol="symA",
                address=_ADDR,
                line_number=1,
            ),
            ValidationIssue(
                code="NOADDR_ISSUE",
                severity=ValidationSeverity.WARNING,
                message="cross-artifact issue with no address",
                artifact="mac",
                symbol="symB",
                address=None,
                line_number=2,
            ),
        ],
    )


async def _select_issue_row(app: S19TuiApp, pilot, row: int) -> str:
    """Select issue ``row`` through the real grouped-panel ``IssueRow`` and
    return the hex pane text.

    Drives the shipped VISIBLE surface: the legacy Issues DataTable is retired
    (batch-29), so selection goes through the grouped ``GroupedIssuesPanel`` —
    focus the real ``IssueRow`` and press Enter (the C-16 real-mechanism path
    shared with AT-039c). Grouped render order is error→warning→info, so for the
    AT-020a seed the addressed error is row 0 and the address-less warning is
    row 1.
    """
    rows = list(app.query(IssueRow))
    rows[row].focus()
    await pilot.pause()
    await pilot.press("enter")
    await pilot.pause()
    return str(app.query_one("#issues_hex_pane", Static).render())


def test_at020a_issue_hex_pane_shows_bytes_and_clears_on_no_address(tmp_path: Path) -> None:
    """AT-020a / LLR-020.1/.2 — issue selection renders address bytes; no-address clears.

    Intent: selecting the addressed issue (row 0) renders its address row + bytes
    in `#issues_hex_pane`; then selecting the address-less issue (row 1) replaces
    that with the placeholder and leaves NO stale bytes. Both halves are asserted
    in one run so a stale-render regression (carrying row 0's bytes into row 1)
    fails. Driven through the real Issues screen + grouped-panel IssueRow selection.
    """

    async def _drive() -> tuple[str, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("issues")
            _seed_issues(app, tmp_path)
            await pilot.pause()
            addressed = await _select_issue_row(app, pilot, 0)
            no_address = await _select_issue_row(app, pilot, 1)
            return addressed, no_address

    addressed, no_address = asyncio.run(_drive())

    # Addressed issue -> the focus-row address + the real bytes at _ADDR render.
    assert "00001000" in addressed, (
        f"the addressed issue's hex window must show the 0x{_ADDR:08X} row; "
        f"pane={addressed!r}"
    )
    assert "AB" in addressed and "CD" in addressed, (
        f"the bytes at 0x{_ADDR:08X} (AB CD ...) must render; pane={addressed!r}"
    )

    # No-address issue -> the placeholder, and NO stale bytes from the prior row.
    assert _NO_ADDRESS_PLACEHOLDER in no_address, (
        f"an address-less issue must show the placeholder; pane={no_address!r}"
    )
    assert "00001000" not in no_address and "AB" not in no_address, (
        f"the prior selection's bytes must be cleared (no stale render); "
        f"pane={no_address!r}"
    )


def _static_content(node: Static) -> object:
    """Return the renderable a ``Static`` was built with, via its public API.

    ``Static.content`` returns the source renderable the widget was constructed
    with (the exact ``safe_text`` ``Text`` here) and is app-independent — no
    active-app console needed — so a white-box test can inspect the literal,
    un-rendered value without reaching into name-mangled internals.
    """
    return node.content


def _related_plain(node: Static) -> str:
    """Return the plain text of an ``.issue-related`` Static (literal, no markup)."""
    content = _static_content(node)
    return content.plain if isinstance(content, Text) else str(content)


def test_at021_issues_list_shows_related_artifacts(tmp_path: Path) -> None:
    """AT-021 (RESTORED) / LLR-043.R8 — the grouped row surfaces related artifacts.

    Intent: an issue carrying ``related_artifacts`` shows them on its row's restored
    ``.issue-related`` node; one without shows the ``-`` empty marker. Read through
    the SHIPPED grouped surface — the ``.issue-related`` node of each mounted
    ``IssueRow`` (batch-29 Inc2; the batch-28-hidden DataTable no longer read).
    Rows are ordered by ``SEVERITY_ORDER`` (error→warning), so the multi-artifact
    ERROR is row 0 and the bare WARNING is row 1. Content-discriminating: a dropped
    node fails, and the no-related row must NOT borrow the other row's artifacts.
    """

    async def _drive() -> tuple[str, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(140, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("issues")
            _render_issue_list(
                app,
                tmp_path,
                [
                    ValidationIssue(
                        code="WITH_REL",
                        severity=ValidationSeverity.ERROR,
                        message="has related",
                        artifact="s19",
                        related_artifacts=["a2l", "mac"],
                    ),
                    ValidationIssue(
                        code="NO_REL",
                        severity=ValidationSeverity.WARNING,
                        message="no related",
                        artifact="mac",
                        related_artifacts=[],
                    ),
                ],
            )
            await pilot.pause()
            rows = list(app.query(IssueRow))
            return (
                _related_plain(rows[0].query_one(".issue-related", Static)),
                _related_plain(rows[1].query_one(".issue-related", Static)),
            )

    with_rel, without_rel = asyncio.run(_drive())
    assert with_rel == "a2l, mac", (
        f"the .issue-related node must list both artifacts; got {with_rel!r}"
    )
    assert without_rel == "-", (
        f"an issue with no related artifacts shows '-'; got {without_rel!r}"
    )


def test_tc043_restore1_related_node_is_markup_safe() -> None:
    """TC-043-restore.1 / LLR-043.R8 — the ``.issue-related`` node is safe_text.

    White-box on ``IssueRow.compose``: it yields a dedicated ``.issue-related``
    node whose plain text is ``", ".join(related_artifacts) or "-"``; and a hostile
    payload injected into ``related_artifacts`` renders LITERAL — no
    ``rich.errors.MarkupError``, the brackets survive in ``.plain``, and the
    ``[link=...]`` token is NOT consumed (built via ``safe_text``, never
    markup-parsed). Pins the C-17 invariant on the restored node so a future
    file-derived ``related_artifacts`` value cannot become a silent injection sink.
    """

    def _related_node(issue: ValidationIssue) -> Static:
        row = IssueRow(issue)
        related = [
            w
            for w in row.compose()
            if isinstance(w, Static) and w.has_class("issue-related")
        ]
        assert len(related) == 1, (
            f"compose must yield exactly one .issue-related node; got {len(related)}"
        )
        return related[0]

    # Plain-text contract: comma-joined artifacts, and "-" when none.
    assert _related_plain(_related_node(
        ValidationIssue(
            code="C", severity=ValidationSeverity.ERROR, message="m",
            artifact="s19", related_artifacts=["a2l", "mac"],
        )
    )) == "a2l, mac"
    assert _related_plain(_related_node(
        ValidationIssue(
            code="C", severity=ValidationSeverity.INFO, message="m",
            artifact="s19", related_artifacts=[],
        )
    )) == "-"

    # Hostile payload — the whole thing must render LITERAL (no MarkupError,
    # brackets intact, [link=...] token not consumed).
    hostile = _related_node(
        ValidationIssue(
            code="C", severity=ValidationSeverity.ERROR, message="m",
            artifact="s19", related_artifacts=["a2l[bold]", "x[link=file:///etc]"],
        )
    )
    assert isinstance(_static_content(hostile), Text), (
        "the related node must carry a literal safe_text Text, never a "
        "markup-parsed string"
    )
    plain = _related_plain(hostile)
    assert plain == "a2l[bold], x[link=file:///etc]", plain
    assert "a2l[bold]" in plain and "[link=file:///etc]" in plain, (
        f"hostile markup must survive literal (no token consumption); got {plain!r}"
    )


# --------------------------------------------------------------------------- #
# batch-49 · US-082 · HLR-082 — Issues Report MID visual-insight layer          #
# --------------------------------------------------------------------------- #


def _issue(
    code: str, severity: ValidationSeverity, addr: object = None
) -> ValidationIssue:
    """Build a minimal issue for the severity-distribution tests."""
    return ValidationIssue(
        code=code,
        severity=severity,
        message="m",
        artifact="s19",
        address=addr if isinstance(addr, int) else None,
    )


def _slot_count(plain: str, label: str) -> int:
    """Extract the integer count following ``label`` in the strip's plain text."""
    match = re.search(rf"{label} (\d+) ", plain)
    assert match is not None, (label, plain)
    return int(match.group(1))


def _slot_filled(plain: str, label: str) -> int:
    """Count the filled micro-bar cells (``█``) in ``label``'s strip slot."""
    match = re.search(rf"{label} \d+ ([█░]+)", plain)
    assert match is not None, (label, plain)
    return match.group(1).count("█")


def test_tc082_1_severity_strip_counts_bars_and_slots() -> None:
    """TC-082.1 / LLR-082.1 — strip helper: exact counts, bounded slots, safe zero, monotone bars.

    Intent: ``build_issues_severity_strip`` reports each severity count verbatim,
    renders exactly one slot per ``SEVERITY_ORDER`` member (MIN-4 — a future 4th
    severity is not silently dropped), renders empty bars with no division when
    ``total == 0``, and its per-severity bar's filled-cell count is monotone
    non-decreasing in that severity's fraction.
    """
    plain = build_issues_severity_strip(3, 1, 2).plain
    assert _slot_count(plain, "Errors") == 3
    assert _slot_count(plain, "Warnings") == 1
    assert _slot_count(plain, "Info") == 2

    labels = {
        ValidationSeverity.ERROR: "Errors",
        ValidationSeverity.WARNING: "Warnings",
        ValidationSeverity.INFO: "Info",
    }
    for severity in SEVERITY_ORDER:
        assert re.search(
            rf"{labels[severity]} \d+ [█░]{{{_ISSUES_STRIP_BAR_WIDTH}}}", plain
        ), (severity, plain)

    zero = build_issues_severity_strip(0, 0, 0).plain
    assert "█" not in zero, zero
    assert zero.count("░") == len(SEVERITY_ORDER) * _ISSUES_STRIP_BAR_WIDTH, zero

    previous = -1
    for err in range(0, 7):
        filled = _slot_filled(build_issues_severity_strip(err, 6 - err, 0).plain, "Errors")
        assert filled >= previous, (err, filled, previous)
        previous = filled


def test_tc082_3_group_header_glyph_and_attrs_preserved() -> None:
    """TC-082.3 / LLR-082.3 — each header leads with its severity glyph; attrs unchanged.

    Intent: ``IssueGroupHeader`` prepends the mapped author glyph
    (``✗``/``⚠``/``•``) while the ``.severity_label`` / ``.issue_count`` attributes
    existing tests read stay exactly as before. The glyph map is closed over
    ``SEVERITY_ORDER`` (one glyph per member, no extras).
    """
    expected = {
        ValidationSeverity.ERROR: "✗",
        ValidationSeverity.WARNING: "⚠",
        ValidationSeverity.INFO: "•",
    }
    for severity in SEVERITY_ORDER:
        header = IssueGroupHeader(severity, 3)
        plain = _static_content(header).plain
        assert plain.startswith(expected[severity]), (severity, plain)
        assert header.severity_label == SEVERITY_LABELS[severity]
        assert header.issue_count == 3

    assert set(_SEVERITY_GLYPH) == set(SEVERITY_ORDER)


def test_tc082_2_strip_mounts_and_renders_two_digit_counts(tmp_path: Path) -> None:
    """TC-082.2 / LLR-082.2 — the strip mounts in #screen_issues and survives 2-digit counts.

    Intent: after driving the Issues screen, ``#issues_severity_strip`` is mounted
    and carries the whole-list counts; a >=10 count still renders in a
    fixed-width bar (no overflow / no crash).
    """

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("issues")
            issues = [
                _issue(f"E{i}", ValidationSeverity.ERROR) for i in range(12)
            ] + [_issue(f"W{i}", ValidationSeverity.WARNING) for i in range(3)]
            _render_issue_list(app, tmp_path, issues)
            await pilot.pause()
            return _static_content(app.query_one("#issues_severity_strip", Static)).plain

    plain = asyncio.run(_drive())
    assert "Errors 12" in plain and "Warnings 3" in plain and "Info 0" in plain, plain
    assert re.search(
        rf"Errors 12 [█░]{{{_ISSUES_STRIP_BAR_WIDTH}}}", plain
    ), plain
    assert _slot_filled(plain, "Errors") <= _ISSUES_STRIP_BAR_WIDTH, plain


def test_tc082_4_border_titles_and_summary_plain_and_spans(tmp_path: Path) -> None:
    """TC-082.4 / LLR-082.4/.5 — author border titles + summary .plain byte-identical + palette spans.

    Intent (inspection): the Issues panes carry the author-constant border
    titles/subtitles; the summary line is a ``Text`` whose ``.plain`` is
    byte-identical to the former " | ".join(...) string, and whose spans carry
    the RED/YELLOW/CYAN palette constants (colours flow from insight_style, not
    hard-coded hex in the view logic).
    """

    async def _drive() -> tuple[str, str, str, Text]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("issues")
            _render_issue_list(
                app,
                tmp_path,
                [
                    _issue("E1", ValidationSeverity.ERROR, addr=0x1000),
                    _issue("W1", ValidationSeverity.WARNING),
                    _issue("I1", ValidationSeverity.INFO),
                ],
            )
            await pilot.pause()
            stack = app.query_one("#issues_list_stack")
            hex_pane = app.query_one("#issues_hex_pane", Static)
            summary = _static_content(app.query_one("#validation_issues_summary", Label))
            return (
                str(stack.border_title),
                str(stack.border_subtitle),
                str(hex_pane.border_title),
                summary,
            )

    list_title, list_subtitle, hex_title, summary = asyncio.run(_drive())
    assert list_title == "Issues"
    assert list_subtitle == "grouped"
    assert hex_title == "Hex Peek"

    assert isinstance(summary, Text), type(summary)
    expected_plain = " | ".join(
        ["total=3", "errors=1", "warnings=1", "info=1", "filter=all", "page 1/1 rows 1-3/3"]
    )
    assert summary.plain == expected_plain, summary.plain

    styles = {str(span.style) for span in summary.spans}
    assert any(RED in style for style in styles), styles
    assert any(YELLOW in style for style in styles), styles
    assert any(CYAN in style for style in styles), styles


def test_at082a_strip_slots_match_independent_counter(tmp_path: Path) -> None:
    """AT-082a (GATE, C-31) / HLR-082 — each strip slot equals an independently derived count.

    Intent: with an ASYMMETRIC, all-distinct 3-error / 1-warning / 2-info set, each
    strip slot equals the count re-derived INDEPENDENTLY by bucketing
    ``_validation_issues`` per ``ValidationSeverity`` (``Counter``) — per-slot, NOT
    an aggregate compare against the view's own counters. A label/slot swap goes RED.
    """

    async def _drive() -> tuple[str, Counter]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("issues")
            _render_issue_list(
                app,
                tmp_path,
                [
                    _issue("E1", ValidationSeverity.ERROR),
                    _issue("E2", ValidationSeverity.ERROR),
                    _issue("E3", ValidationSeverity.ERROR),
                    _issue("W1", ValidationSeverity.WARNING),
                    _issue("I1", ValidationSeverity.INFO),
                    _issue("I2", ValidationSeverity.INFO),
                ],
            )
            await pilot.pause()
            plain = _static_content(
                app.query_one("#issues_severity_strip", Static)
            ).plain
            counter = Counter(issue.severity for issue in app._validation_issues)
            return plain, counter

    plain, counter = asyncio.run(_drive())
    # fixture integrity — the distribution is asymmetric and all-distinct.
    assert counter[ValidationSeverity.ERROR] == 3
    assert counter[ValidationSeverity.WARNING] == 1
    assert counter[ValidationSeverity.INFO] == 2
    # per-slot equality against the INDEPENDENT oracle.
    assert _slot_count(plain, "Errors") == counter[ValidationSeverity.ERROR], plain
    assert _slot_count(plain, "Warnings") == counter[ValidationSeverity.WARNING], plain
    assert _slot_count(plain, "Info") == counter[ValidationSeverity.INFO], plain


def test_at082b_bar_present_iff_count_positive(tmp_path: Path) -> None:
    """AT-082b / HLR-082 — a micro-bar is filled iff its count is > 0 (drives the 0-arm on WARNING)."""

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("issues")
            _render_issue_list(
                app,
                tmp_path,
                [
                    _issue("E1", ValidationSeverity.ERROR),
                    _issue("I1", ValidationSeverity.INFO),
                ],
            )
            await pilot.pause()
            return _static_content(app.query_one("#issues_severity_strip", Static)).plain

    plain = asyncio.run(_drive())
    assert _slot_filled(plain, "Warnings") == 0, plain
    assert _slot_filled(plain, "Errors") >= 1, plain
    assert _slot_filled(plain, "Info") >= 1, plain


def test_at082c_group_headers_lead_with_severity_glyph(tmp_path: Path) -> None:
    """AT-082c (GATE) / HLR-082 — every mounted group header begins with its severity glyph.

    Drives the shipped grouped surface (``IssueGroupHeader`` nodes under
    ``#validation_issues_groups``); each rendered header's plain text starts with
    the mapped author glyph.
    """

    async def _drive() -> list[tuple[str, str]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("issues")
            _render_issue_list(
                app,
                tmp_path,
                [
                    _issue("E1", ValidationSeverity.ERROR),
                    _issue("W1", ValidationSeverity.WARNING),
                    _issue("I1", ValidationSeverity.INFO),
                ],
            )
            await pilot.pause()
            return [
                (header.severity_label, _static_content(header).plain)
                for header in app.query(IssueGroupHeader)
            ]

    headers = asyncio.run(_drive())
    glyphs = {"ERRORS": "✗", "WARNINGS": "⚠", "INFO": "•"}
    assert headers, "grouped headers must be mounted"
    for label, plain in headers:
        assert plain.startswith(glyphs[label]), (label, plain)


def test_at082d_summary_line_carries_palette_spans(tmp_path: Path) -> None:
    """AT-082d / HLR-082 — the summary line carries the RED/YELLOW/CYAN palette spans."""

    async def _drive() -> object:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("issues")
            _render_issue_list(
                app,
                tmp_path,
                [
                    _issue("E1", ValidationSeverity.ERROR),
                    _issue("W1", ValidationSeverity.WARNING),
                    _issue("I1", ValidationSeverity.INFO),
                ],
            )
            await pilot.pause()
            return _static_content(app.query_one("#validation_issues_summary", Label))

    summary = asyncio.run(_drive())
    assert isinstance(summary, Text), type(summary)
    styles = {str(span.style) for span in summary.spans}
    assert any(RED in style for style in styles), styles
    assert any(YELLOW in style for style in styles), styles
    assert any(CYAN in style for style in styles), styles


def test_at082e_zero_issues_renders_zeros_no_crash(tmp_path: Path) -> None:
    """AT-082e / HLR-082 — a zero-issue load renders 0/0/0 with empty bars, no division-by-zero."""

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("issues")
            _render_issue_list(app, tmp_path, [])
            await pilot.pause()
            return _static_content(app.query_one("#issues_severity_strip", Static)).plain

    plain = asyncio.run(_drive())
    assert _slot_count(plain, "Errors") == 0
    assert _slot_count(plain, "Warnings") == 0
    assert _slot_count(plain, "Info") == 0
    assert "█" not in plain, plain


def test_at082f_hostile_issue_tokens_render_literal(tmp_path: Path) -> None:
    """AT-082f (GATE, C-17) / LLR-082.6 — hostile issue code/message render literal, no injection.

    Intent: a hostile ``code``/``message`` payload reaches the grouped row cells;
    the rendered cell ``.plain`` equals the payload verbatim, no injected
    link/bold span survives (``spans == []`` on the file-derived cell), and no
    ``MarkupError`` is raised during render. Crash-free alone is insufficient.
    """

    async def _drive() -> tuple[object, object]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("issues")
            _render_issue_list(
                app,
                tmp_path,
                [
                    ValidationIssue(
                        code="[bold]X[/]",
                        severity=ValidationSeverity.ERROR,
                        message="[link=http://x]click[/link] [/nope]",
                        artifact="s19",
                        symbol="[red]s[/]",
                    )
                ],
            )
            await pilot.pause()
            row = app.query(IssueRow).first()
            chip = row.query_one(".issue-code-chip", Static)
            detail = row.query_one(".issue-detail", Static)
            return _static_content(chip), _static_content(detail)

    chip, detail = asyncio.run(_drive())
    assert isinstance(chip, Text), type(chip)
    assert chip.plain == "[bold]X[/]", chip.plain
    assert list(chip.spans) == [], chip.spans

    assert isinstance(detail, Text), type(detail)
    assert "[link=http://x]click[/link] [/nope]" in detail.plain, detail.plain
    assert list(detail.spans) == [], detail.spans
