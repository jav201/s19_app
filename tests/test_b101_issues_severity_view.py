"""Issues screen tests of batch-101 Inc 11 (F-02 view part, F-03, F-39).

The Issues screen shows each issue under its own severity: the display triage
that re-labelled standard A2L block warnings as INFO at paint time is gone
(rows R-TUI-042b.1, .2, .4, .6, R-TUI-025.2, .6), and the filtered list runs
errors, warnings, info across pages (row R-TUI-042b.5). One further test pins
the Split / Join a2l source of ``software_a.a2l`` (row R-SEG-SRC.6).

Each test seeds ``app._validation_issues`` on the Issues screen (the established
directionb idiom) and reads what the screen paints: group headers, the rows
under each header, the severity strip, the summary line. Expected values are the
requirement's exact values. Waits use ``tests/support/timing.py::wait_until``.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import List, Tuple

from textual.widgets import Button, Static

from s19_app.core import S19File
from s19_app.tui.a2l import parse_a2l_file
from s19_app.tui.app import S19TuiApp
from s19_app.tui.changes.io import emit_s19_from_mem_map
from s19_app.tui.issues_view import GroupedIssuesPanel, IssueGroupHeader, IssueRow
from s19_app.tui.services.load_service import build_loaded_s19
from s19_app.validation import ValidationIssue, ValidationSeverity

from tests.support.timing import wait_until
from tests.test_segment_split_window import _demo_loaded, _open_window, _pause

REPO_ROOT = Path(__file__).resolve().parent.parent
SOFTWARE_A = REPO_ROOT / "examples" / "case_00_public" / "software_a.a2l"

E, W, I = ValidationSeverity.ERROR, ValidationSeverity.WARNING, ValidationSeverity.INFO
UNRECOGNIZED = "A2L_UNRECOGNIZED_BLOCK"

HDR_ERRORS = "✗ ERRORS  ({n})"
HDR_WARNINGS = "⚠ WARNINGS  ({n})"
HDR_INFO = "• INFO  ({n})"


# ---------------------------------------------------------------------------
# Builders and readers
# ---------------------------------------------------------------------------


def _a2l_block(name: str) -> ValidationIssue:
    return ValidationIssue(
        code=UNRECOGNIZED,
        severity=W,
        message=f"Unrecognized A2L block '{name}'.",
        artifact="a2l",
    )


def _mac_dup() -> ValidationIssue:
    return ValidationIssue(
        code="MAC_DUPLICATE_ADDRESS",
        severity=I,
        message="Address 0x00001000 has duplicate MAC symbols (bit-field sharing): A_FLAG, B_FLAG.",
        artifact="mac",
    )


def _issue(sev: ValidationSeverity, message: str) -> ValidationIssue:
    return ValidationIssue(code=f"T_{sev.value.upper()}", severity=sev, message=message, artifact="mac")


def _list_l4() -> List[ValidationIssue]:
    """List L4 of 02-test-cases.md: three A2L block WARNINGs then one INFO."""
    return [_a2l_block("PAGE"), _a2l_block("MOD_PAR"), _a2l_block("FROBNICATE"), _mac_dup()]


def _list_l45() -> List[ValidationIssue]:
    """List L45: 40 WARNING W_i, 3 ERROR E_i, 2 INFO I_i (i from 0 in each run)."""
    return (
        [_issue(W, f"W_{i}") for i in range(40)]
        + [_issue(E, f"E_{i}") for i in range(3)]
        + [_issue(I, f"I_{i}") for i in range(2)]
    )


def _plain(widget) -> str:
    rendered = widget.render()
    return getattr(rendered, "plain", str(rendered))


def _seed(app: S19TuiApp, tmp_path: Path, issues: List[ValidationIssue]) -> None:
    """Fixture bytes + issues + re-render (the established directionb idiom)."""
    path = tmp_path / "inc11_fixture.s19"
    path.write_text(emit_s19_from_mem_map({0x1000: 0xAB}, [(0x1000, 0x1001)]), encoding="utf-8")
    s19 = S19File(str(path))
    app.current_file = build_loaded_s19(path, s19, a2l_path=None, a2l_data=None)
    app._apply_empty_state()
    app._validation_issues = list(issues)
    app.validation_issue_filter_mode = "all"
    app._validation_issues_window_start = 0
    app.update_validation_issues_view()


Layout = List[Tuple[str, List[IssueRow]]]


def _layout(app: S19TuiApp) -> Layout:
    """The panel children in mount order: [(header text, [rows under it])]."""
    panel = app.query_one("#validation_issues_groups", GroupedIssuesPanel)
    groups: Layout = []
    for child in panel.children:
        if isinstance(child, IssueGroupHeader):
            groups.append((_plain(child), []))
        elif isinstance(child, IssueRow) and groups:
            groups[-1][1].append(child)
    return groups


def _messages(rows: List[IssueRow]) -> List[str]:
    return [r.issue.message for r in rows]


def _summary(app: S19TuiApp) -> str:
    return _plain(app.query_one("#validation_issues_summary"))


def _strip(app: S19TuiApp) -> str:
    return _plain(app.query_one("#issues_severity_strip", Static))


async def _show_issues(app: S19TuiApp, pilot, tmp_path: Path, issues) -> None:
    await pilot.pause()
    app.action_show_screen("issues")
    _seed(app, tmp_path, issues)
    await wait_until(
        pilot,
        lambda: _summary(app).startswith("total=") and len(_layout(app)) > 0,
        lambda: f"the Issues screen did not paint: {_summary(app)!r} {_layout(app)!r}",
    )


def _run(tmp_path: Path, issues, drive) -> None:
    async def _go() -> None:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await _show_issues(app, pilot, tmp_path, issues)
            await drive(app, pilot)

    asyncio.run(_go())


# ---------------------------------------------------------------------------
# R-TUI-042b.1 .. .6, R-TUI-025.2, .6 — each issue under its own severity
# ---------------------------------------------------------------------------


def test_r_tui_042b_1_groups_ordered_whatever_the_list_order(tmp_path: Path) -> None:
    """Why: the legend promises ERRORS, WARNINGS, INFO whatever order the list holds them in."""
    issues = [_issue(I, "I_0"), _issue(W, "W_0"), _issue(E, "E_0")]

    async def drive(app, pilot) -> None:
        assert [h for h, _ in _layout(app)] == [
            HDR_ERRORS.format(n=1),
            HDR_WARNINGS.format(n=1),
            HDR_INFO.format(n=1),
        ]

    _run(tmp_path, issues, drive)


def test_r_tui_042b_1_unrecognized_block_rows_stay_warnings(tmp_path: Path) -> None:
    """Why: a WARNING issue is shown as a warning. The PAGE, MOD_PAR and FROBNICATE rows
    sit under the WARNINGS header; the INFO group holds only the MAC row (base: moved to INFO)."""

    async def drive(app, pilot) -> None:
        assert [(h, _messages(rows)) for h, rows in _layout(app)] == [
            (
                HDR_WARNINGS.format(n=3),
                [
                    "Unrecognized A2L block 'PAGE'.",
                    "Unrecognized A2L block 'MOD_PAR'.",
                    "Unrecognized A2L block 'FROBNICATE'.",
                ],
            ),
            (HDR_INFO.format(n=1), [_mac_dup().message]),
        ]

    _run(tmp_path, _list_l4(), drive)


def test_r_tui_042b_2_headers_count_issue_severity(tmp_path: Path) -> None:
    """Why: a header counts the issues of its own severity (base: WARNINGS (1), INFO (3))."""

    async def drive(app, pilot) -> None:
        assert [h for h, _ in _layout(app)] == [HDR_WARNINGS.format(n=3), HDR_INFO.format(n=1)]

    _run(tmp_path, _list_l4(), drive)


#: The warning colour the row's threshold names (insight_style.YELLOW, styles.tcss .sev-warning).
WARNING_COLOUR = "#F6FF8F"


def _hex(color) -> str:
    return color.hex.upper()[:7]


def test_r_tui_042b_4_unrecognized_block_rows_paint_warning(tmp_path: Path) -> None:
    """Why: the row carries the colour class of its severity (base: sev-info), and the
    colour it is painted in is the warning colour #f6ff8f (C-4, E5): the class alone is
    not the painted style."""

    async def drive(app, pilot) -> None:
        rows = [r for _, rs in _layout(app) for r in rs if r.issue.code == UNRECOGNIZED]
        assert len(rows) == 3
        assert all(r.has_class("sev-warning") for r in rows), [r.classes for r in rows]
        assert not any(r.has_class("sev-info") for r in rows)
        # A row is queryable one frame before its compose children exist (SR-2, E4).
        await wait_until(
            pilot,
            lambda: all(
                len(list(r.query(".issue-code-chip"))) == 1 and len(list(r.query(".issue-detail"))) == 1
                for r in rows
            ),
            "the three rows composed",
        )
        # The row and its code chip are painted in the warning colour; the detail span
        # keeps the foreground colour by design (unchanged from base).
        painted = [
            (_hex(r.styles.color), _hex(r.query_one(".issue-code-chip").styles.color)) for r in rows
        ]
        assert painted == [(WARNING_COLOUR, WARNING_COLOUR)] * 3, painted

    _run(tmp_path, _list_l4(), drive)


def test_r_tui_042b_6_no_note_under_group_header(tmp_path: Path) -> None:
    """Why: nothing may sit between a group header and its first row (base: a justification
    note naming the Cambio4 triage)."""

    async def drive(app, pilot) -> None:
        panel = app.query_one("#validation_issues_groups", GroupedIssuesPanel)
        children = list(panel.children)
        info_at = [
            i
            for i, c in enumerate(children)
            if isinstance(c, IssueGroupHeader) and _plain(c).startswith("• INFO")
        ]
        assert len(info_at) == 1, [_plain(c) for c in children if isinstance(c, IssueGroupHeader)]
        assert _plain(children[info_at[0]]) == HDR_INFO.format(n=1)
        after = children[info_at[0] + 1]
        assert isinstance(after, IssueRow), type(after)
        assert after.issue.code == "MAC_DUPLICATE_ADDRESS"
        assert len(list(panel.query(".issue-reclassify-note"))) == 0
        screen_text = " ".join(_plain(s) for s in app.screen.query(Static))
        assert "Cambio4" not in screen_text

    _run(tmp_path, _list_l4(), drive)


def test_r_tui_025_2_strip_and_summary_count_issue_severity(tmp_path: Path) -> None:
    """Why: strip and summary count by the issue's own severity (base: Warnings 1, Info 3)."""

    async def drive(app, pilot) -> None:
        strip = _strip(app)
        assert "Errors 0" in strip and "Warnings 3" in strip and "Info 1" in strip, strip
        assert _summary(app) == (
            "total=4 | errors=0 | warnings=3 | info=1 | filter=all | page 1/1 rows 1-4/4"
        )

    _run(tmp_path, _list_l4(), drive)


def test_r_tui_025_6_warnings_filter_shows_warning_group_only(tmp_path: Path) -> None:
    """Why: the Warnings button shows only WARNING issues; no INFO group (base: the INFO header
    shows the re-labelled warnings)."""

    async def drive(app, pilot) -> None:
        button = app.query_one("#issues_filter_warning", Button)
        button.focus()
        await wait_until(pilot, lambda: app.focused is button, "the Warnings button focused")
        await pilot.press("enter")
        await wait_until(
            pilot,
            lambda: _summary(app).endswith("filter=warning | page 1/1 rows 1-3/3")
            and [h for h, _ in _layout(app)] == [HDR_WARNINGS.format(n=3)],
            lambda: f"{_summary(app)!r} {[h for h, _ in _layout(app)]!r}",
        )
        groups = _layout(app)
        assert len(groups) == 1 and len(groups[0][1]) == 3

    _run(tmp_path, _list_l4(), drive)


# ---------------------------------------------------------------------------
# R-TUI-042b.5 — the filtered list runs errors, warnings, info across pages
# ---------------------------------------------------------------------------


def test_r_tui_042b_5_list_ordered_by_severity_across_pages(tmp_path: Path) -> None:
    """Why: pages are slices of the filtered list, so the list itself must run
    ERROR, WARNING, INFO or an error can sit on a later page (base: page 1 holds 40 WARNINGs)."""

    async def drive(app, pilot) -> None:
        assert _summary(app).endswith("page 1/2 rows 1-40/45")
        page1 = _layout(app)
        assert [h for h, _ in page1] == [HDR_ERRORS.format(n=3), HDR_WARNINGS.format(n=40)]
        assert _messages(page1[0][1]) == ["E_0", "E_1", "E_2"]
        assert _messages(page1[1][1]) == [f"W_{i}" for i in range(37)]

        await pilot.press("pagedown")
        await wait_until(
            pilot,
            lambda: _summary(app).endswith("page 2/2 rows 41-45/45")
            and [h for h, _ in _layout(app)] == [HDR_WARNINGS.format(n=40), HDR_INFO.format(n=2)],
            lambda: f"{_summary(app)!r} {[h for h, _ in _layout(app)]!r}",
        )
        page2 = _layout(app)
        assert _messages(page2[0][1]) == ["W_37", "W_38", "W_39"]
        assert _messages(page2[1][1]) == ["I_0", "I_1"]

    _run(tmp_path, _list_l45(), drive)


def test_r_tui_042b_5_order_is_stable_within_severity(tmp_path: Path) -> None:
    """Why: a sort by severity must keep the list order inside one severity; the error
    filter keeps the list order too."""
    issues = [_issue(W, "W_a"), _issue(E, "E_b"), _issue(W, "W_c"), _issue(E, "E_d")]

    async def drive(app, pilot) -> None:
        assert [i.message for i in app._filtered_validation_issues()] == [
            "E_b",
            "E_d",
            "W_a",
            "W_c",
        ]
        app.validation_issue_filter_mode = "error"
        assert [i.message for i in app._filtered_validation_issues()] == ["E_b", "E_d"]
        app.validation_issue_filter_mode = "warning"
        assert [i.message for i in app._filtered_validation_issues()] == ["W_a", "W_c"]

    _run(tmp_path, issues, drive)


def test_r_tui_042b_5_other_severity_sorts_after_info(tmp_path: Path) -> None:
    """Why: a severity outside ERROR, WARNING, INFO (OK, NEUTRAL) sorts last, without error."""
    issues = [
        _issue(W, "W_a"),
        _issue(ValidationSeverity.OK, "O_b"),
        _issue(E, "E_c"),
        _issue(I, "I_d"),
    ]

    async def drive(app, pilot) -> None:
        assert [i.message for i in app._filtered_validation_issues()] == [
            "E_c",
            "W_a",
            "I_d",
            "O_b",
        ]

    _run(tmp_path, issues, drive)


# ---------------------------------------------------------------------------
# R-SEG-SRC.6 — the Split / Join a2l source of software_a.a2l
# ---------------------------------------------------------------------------


def test_r_a2l_036_7_split_join_lists_no_row_for_empty_segment(tmp_path: Path) -> None:
    """Why: an empty MEMORY_SEGMENT has no name and no base, so the a2l source must not
    list a row for it (R-A2L-036.7 threshold, C-5 / C-7 of E5); the one segment with a
    base and a size beside it is listed."""
    a2l = tmp_path / "empty_segment.a2l"
    a2l.write_text(
        "\n".join(
            [
                '/begin PROJECT P ""',
                '/begin MODULE M ""',
                "/begin MOD_PAR \"\"",
                "/begin MEMORY_SEGMENT",
                "/end MEMORY_SEGMENT",
                '/begin MEMORY_SEGMENT Good ""',
                "DATA FLASH INTERN 0x1000 0x100 -1 -1 -1 -1 -1",
                "/end MEMORY_SEGMENT",
                "/end MOD_PAR",
                "/end MODULE",
                "/end PROJECT",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    async def _go() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await _pause(pilot)
            loaded = _demo_loaded()
            loaded.a2l_data = parse_a2l_file(a2l)
            app.current_file = loaded
            app.current_a2l_data = loaded.a2l_data
            await _pause(pilot)
            window = await _open_window(app, pilot)
            window.action_cycle_tab()  # ranges -> manual
            window.action_cycle_tab()  # manual -> a2l
            await _pause(pilot)
            from s19_app.tui.segment_split_view import _SegTable

            table = window.query_one("#sje_table", _SegTable)
            return {
                "tabs": _plain(app.query_one("#sje_tabs")),
                "body": _plain(table.query_one(Static)),
                "rows": [(r.name, r.base, r.size) for r in window._a2l_rows()],
            }

    seen = asyncio.run(_go())
    assert "a2l(1)" in seen["tabs"], seen["tabs"]
    assert seen["rows"] == [("Good", 0x1000, 0x100)], seen["rows"]
    painted = [line for line in seen["body"].split("\n") if "0x" in line]
    assert len(painted) == 1 and "Good" in painted[0] and "0x00001000" in painted[0], seen["body"]


def test_r_seg_src_6_software_a_rows(tmp_path: Path) -> None:
    """Why: software_a.a2l writes the segment name first on the record line; the a2l source
    must list its 3 segments (base: a2l(0))."""

    async def _go() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await _pause(pilot)
            loaded = _demo_loaded()
            loaded.a2l_data = parse_a2l_file(SOFTWARE_A)
            app.current_file = loaded
            app.current_a2l_data = loaded.a2l_data
            await _pause(pilot)
            window = await _open_window(app, pilot)
            window.action_cycle_tab()  # ranges -> manual
            window.action_cycle_tab()  # manual -> a2l
            await _pause(pilot)
            from s19_app.tui.segment_split_view import _SegTable

            table = window.query_one("#sje_table", _SegTable)
            return {
                "tabs": _plain(app.query_one("#sje_tabs")),
                "body": _plain(table.query_one(Static)),
                "rows": [(r.name, r.base, r.size) for r in window._a2l_rows()],
            }

    seen = asyncio.run(_go())
    assert "a2l(3)" in seen["tabs"], seen["tabs"]
    assert seen["rows"] == [
        ("SystemCalFLash", 0xA001C000, 0x1000),
        ("SafetyCalFlash", 0xA0038000, 0x1000),
        ("PerformanceCalFlash", 0xA0050000, 0x1000),
    ]
    for base in ("0xA001C000", "0xA0038000", "0xA0050000"):
        assert base in seen["body"], seen["body"]
