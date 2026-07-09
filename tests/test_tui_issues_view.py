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
from pathlib import Path

from rich.text import Text
from textual.widgets import Static

from s19_app.core import S19File
from s19_app.tui.app import S19TuiApp, precompute_issue_datatable_payload
from s19_app.tui.changes.io import emit_s19_from_mem_map
from s19_app.tui.issues_view import IssueRow
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
    so the empty state flips, set ``_validation_issues``, clear the precompute
    caches (format on the fly), filter=all, render.
    """
    path = tmp_path / "issues_fixture.s19"
    path.write_text(
        emit_s19_from_mem_map(_BYTES, [(0x1000, 0x1004)]), encoding="utf-8"
    )
    s19 = S19File(str(path))
    app.current_file = build_loaded_s19(path, s19, a2l_path=None, a2l_data=None)
    app._apply_empty_state()
    app._validation_issues = issues
    app._validation_issue_cell_rows = []
    app._validation_issue_cell_styles = []
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


def test_tc021_precompute_payload_emits_related_cell() -> None:
    """TC-021.1 / LLR-021.1 — the payload formatter emits an 8-tuple with Related.

    White-box: ``precompute_issue_datatable_payload`` returns 8-column rows; the
    Related cell (index 3) is the comma-joined ``related_artifacts`` (or ``-``);
    rows + styles stay parallel and index-aligned (a no-related issue must not
    borrow another's artifacts).
    """
    issues = [
        ValidationIssue(
            code="A",
            severity=ValidationSeverity.ERROR,
            message="m",
            artifact="s19",
            related_artifacts=["a2l", "mac"],
        ),
        ValidationIssue(
            code="B",
            severity=ValidationSeverity.WARNING,
            message="m2",
            artifact="mac",
            related_artifacts=[],
        ),
    ]
    rows, styles = precompute_issue_datatable_payload(issues)

    assert len(rows) == 2 and len(styles) == 2
    assert all(len(r) == 8 for r in rows), (
        f"each cell row must be an 8-tuple (Related added); got {[len(r) for r in rows]}"
    )
    assert rows[0][3] == "a2l, mac", rows[0]
    assert rows[1][3] == "-", rows[1]
