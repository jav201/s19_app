"""Issues severity tests — batch-94 increment 004, re-pinned by batch-101 Inc 11 (D3-12).

Batch-94 Inc 004 (the "Cambio4 triage") re-labelled ``A2L_UNRECOGNIZED_BLOCK``
warnings for standard ASAP2 keywords as INFO at paint time. Batch-101 Inc 11
removes that view triage: the guarantee now lives in the engine
(``validate_a2l_structure``) — a section whose name is an ASAM block name
(R-VAL-032.2) or that sits inside an IF_DATA block (R-VAL-032.3) raises no
issue, a genuinely unknown name stays a WARNING (R-VAL-032.1) — and an issue's
severity is final: the Issues screen shows every issue under its own severity
(R-TUI-042b.1, .2, .4, .6; R-TUI-025.2). No row is dropped or re-labelled.

- **AT-B94-14** (layer B) loads the fixture ``examples/case_00_public/software_a.a2l``
  through the real engine (``parse_a2l_file`` + ``validate_a2l_structure``): 0
  ``A2L_UNRECOGNIZED_BLOCK`` issues (it was 1 023 before Inc 11). The shipped
  Issues screen shows ``info=0`` and no INFO group, and a planted ``FROBNICATE``
  (the executed negative control) stays exactly one WARNING row.
- **TC-B94-18** (layer A) pins, through the engine, that each of the 21 names the
  retired curated set held raises no issue inside IF_DATA, that the 11 ASAM names
  among them raise none at the top level either, and that the other 10 (XCP
  interface names) are WARNINGs at the top level. The engine freeze arm is kept:
  ``git diff --name-only main`` over ``validation/rules.py`` / ``tui/a2l.py`` is
  empty and the worktree bytes equal ``main``'s blob (CRLF-aware). It is RED on
  the Inc 11 branch and GREEN again once the merge puts the new bytes on ``main``
  (re-freeze by merge, ruling OR-3).
- **TC-B94-19** (layer A) is the panel matrix: a WARNING whose block name was once
  curated renders under WARNINGS (``sev-warning``) with no note, header counts are
  the caller's verbatim, the empty state, the caller's list never mutated, and the
  C-17 hostile message rendering literal.
"""

from __future__ import annotations

import asyncio
import hashlib
import subprocess
from pathlib import Path

import pytest
from textual.widgets import Static

import s19_app
from s19_app.core import S19File
from s19_app.tui.app import S19TuiApp
from s19_app.tui.changes.io import emit_s19_from_mem_map
from s19_app.tui.issues_view import (
    GroupedIssuesPanel,
    IssueGroupHeader,
    IssueRow,
)
from s19_app.tui.services.load_service import build_loaded_s19
from s19_app.validation import ValidationIssue, ValidationSeverity

from tests.support.timing import wait_until

#: The 21 names the retired curated set held (batch-94 executed 2026-10-13 tally).
FORMER_CURATED_ASAM = (
    "REF_CHARACTERISTIC",
    "REF_MEASUREMENT",
    "AXIS_DESCR",
    "COMPU_VTAB_RANGE",
    "SUB_GROUP",
    "DEF_CHARACTERISTIC",
    "SUB_FUNCTION",
    "A2ML",
    "FORMULA",
    "MOD_COMMON",
    "MOD_PAR",
)
FORMER_CURATED_INTERFACE = (
    "PAGE",
    "SEGMENT",
    "PROTOCOL_LAYER",
    "CAN_FD",
    "DAQ",
    "EVENT",
    "PAG",
    "STIM",
    "TIMESTAMP_SUPPORTED",
    "XCP_ON_CAN",
)

_WARNING = ValidationSeverity.WARNING

_FROBNICATE = ValidationIssue(
    code="A2L_UNRECOGNIZED_BLOCK",
    severity=ValidationSeverity.WARNING,
    message="Unrecognized A2L block 'FROBNICATE'.",
    artifact="a2l",
)

_REPO_ROOT = Path(s19_app.__file__).resolve().parents[1]
_FIXTURE = _REPO_ROOT / "examples" / "case_00_public" / "software_a.a2l"


def _unrecognized_issue(name: str) -> ValidationIssue:
    """Build one synthetic ``A2L_UNRECOGNIZED_BLOCK`` WARNING in the emitter's shape."""
    return ValidationIssue(
        code="A2L_UNRECOGNIZED_BLOCK",
        severity=ValidationSeverity.WARNING,
        message=f"Unrecognized A2L block '{name}'.",
        artifact="a2l",
    )


def _engine_issues_of_fixture() -> list[ValidationIssue]:
    """Run the real engine over the stand-in fixture (the P1 probe's exact path)."""
    from s19_app.tui.a2l import parse_a2l_file
    from s19_app.validation.rules import validate_a2l_structure

    if not _FIXTURE.exists():
        pytest.skip("examples/case_00_public/software_a.a2l not present")
    data = parse_a2l_file(_FIXTURE)
    assert data.get("errors") == [], data.get("errors")
    return list(validate_a2l_structure(data))


def _engine_issues_of_text(tmp_path: Path, body: list[str]) -> list[ValidationIssue]:
    """Engine issues of a small A2L: PROJECT / MODULE wrapper around ``body``."""
    from s19_app.tui.a2l import parse_a2l_file
    from s19_app.validation.rules import validate_a2l_structure

    path = tmp_path / "former_curated.a2l"
    lines = ['/begin PROJECT P ""', '/begin MODULE M ""', *body, "/end MODULE", "/end PROJECT"]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return list(validate_a2l_structure(parse_a2l_file(path)))


def _mount_panel(app: S19TuiApp, issues, counts, truncated=False) -> GroupedIssuesPanel:
    """Render ``issues`` + ``counts`` through the shipped grouped panel."""
    panel = app.query_one("#validation_issues_groups", GroupedIssuesPanel)
    panel.render_groups(issues, counts, truncated=truncated)
    return panel


def _headers(panel: GroupedIssuesPanel) -> dict[str, IssueGroupHeader]:
    return {h.severity_label: h for h in panel.query(IssueGroupHeader)}


def _note_count(panel: GroupedIssuesPanel) -> int:
    """Widgets of the removed justification note (class ``issue-reclassify-note``)."""
    return len(list(panel.query(".issue-reclassify-note")))


def _rows_composed(panel: GroupedIssuesPanel, count: int) -> bool:
    """``count`` rows are mounted AND each has composed its code chip.

    A row is counted by ``query(IssueRow)`` as soon as it mounts, one frame before its
    ``compose`` children exist; reading the chip in that frame raises ``NoMatches``
    (E4 integration, LAN Linux host under load)."""
    rows = list(panel.query(IssueRow))
    return len(rows) == count and all(len(row.query(".issue-code-chip")) == 1 for row in rows)


def _row_codes(panel: GroupedIssuesPanel) -> list[tuple[str, str]]:
    """Return ``(severity css class, chip code)`` for every mounted row."""
    return [
        (row._sev_class, row.query_one(".issue-code-chip", Static).render().plain)
        for row in panel.query(IssueRow)
    ]


def _seed_app_and_show_issues(app: S19TuiApp, tmp_path: Path, issues) -> None:
    """The established directionb seed idiom: fixture bytes + issues + re-render."""
    path = tmp_path / "triage_fixture.s19"
    path.write_text(
        emit_s19_from_mem_map({0x1000: 0xAB}, [(0x1000, 0x1001)]),
        encoding="utf-8",
    )
    s19 = S19File(str(path))
    app.current_file = build_loaded_s19(path, s19, a2l_path=None, a2l_data=None)
    app._apply_empty_state()
    app._validation_issues = list(issues)
    app.validation_issue_filter_mode = "all"
    app._validation_issues_window_start = 0
    app.update_validation_issues_view()


# ---------------------------------------------------------------------------
# AT-B94-14 — fixture load through the engine, the shipped surface unfiltered.
# ---------------------------------------------------------------------------


def test_at_b94_14_fixture_triage_through_surface(tmp_path: Path) -> None:
    """AT-B94-14 / R-VAL-032.3 — software_a.a2l raises no unrecognized-block issue; the screen
    shows no INFO group from A2L blocks; an unknown block still warns.

    Intent: the stand-in fixture (IF_DATA > SEGMENT > PAGE and the ASAM names the base
    did not know) loads through the real engine with 0 ``A2L_UNRECOGNIZED_BLOCK`` issues
    (base: 1 023). The live Issues screen then shows ``info=0`` and no INFO header from
    A2L blocks, and a planted ``FROBNICATE`` (the executed negative control) is exactly
    one WARNING row — the engine fix must not silence a genuinely unknown block.
    """
    engine_issues = _engine_issues_of_fixture()
    unrecognized = [i for i in engine_issues if i.code == "A2L_UNRECOGNIZED_BLOCK"]
    assert unrecognized == [], [i.message for i in unrecognized[:5]]

    async def _drive_app_chrome() -> None:
        app = S19TuiApp(base_dir=tmp_path)

        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("issues")

            _seed_app_and_show_issues(app, tmp_path, engine_issues + [_FROBNICATE])
            panel = app.query_one("#validation_issues_groups", GroupedIssuesPanel)
            await wait_until(
                pilot,
                lambda: "WARNINGS" in _headers(panel) and _rows_composed(panel, 1),
                lambda: f"no WARNINGS group painted: {list(_headers(panel))}",
            )
            headers = _headers(panel)
            assert "INFO" not in headers, list(headers)
            assert headers["WARNINGS"].issue_count == 1
            assert _row_codes(panel) == [("sev-warning", "A2L_UNRECOGNIZED_BLOCK")]
            strip_plain = panel.app.query_one("#issues_severity_strip", Static).render().plain
            assert "Warnings 1" in strip_plain and "Info 0" in strip_plain, strip_plain
            summary_plain = panel.app.query_one("#validation_issues_summary").render().plain
            assert "warnings=1" in summary_plain and "info=0" in summary_plain, summary_plain
            assert _note_count(panel) == 0

    asyncio.run(_drive_app_chrome())


# ---------------------------------------------------------------------------
# TC-B94-18 — the former curated names through the engine, and the engine freeze.
# ---------------------------------------------------------------------------


def test_tc_b94_18_curated_set_and_engine_freeze(tmp_path: Path) -> None:
    """TC-B94-18 / R-VAL-032.2, .3 — the 21 former curated names raise no issue; engine freeze.

    Intent: the guarantee the view constant used to give now sits in the engine. Each of
    the 21 names raises no issue inside an IF_DATA block; the 11 ASAM names among them
    raise none at the top level either; the 10 interface names (PAGE, SEGMENT, DAQ …) are
    a WARNING at the top level, so the exemption is by IF_DATA, not by name. In the SAME
    run the engine freeze holds: no diff vs ``main`` over ``validation/rules.py`` and
    ``tui/a2l.py`` and the worktree bytes equal ``main``'s blobs (CRLF-aware). On the
    Inc 11 branch that arm is RED by plan (the unfreeze) and GREEN after the merge (OR-3).
    The freeze arm rides the proven TC-027 idiom: where the ``main`` ref is absent it
    SKIPS instead of erroring.
    """
    names = FORMER_CURATED_ASAM + FORMER_CURATED_INTERFACE
    assert len(names) == 21 and len(set(names)) == 21

    inside = ["/begin IF_DATA XCP"]
    for name in names:
        inside += [f"/begin {name}", f"/end {name}"]
    inside += ["/end IF_DATA"]
    issues = _engine_issues_of_text(tmp_path, inside)
    assert issues == [], [(i.code, i.message) for i in issues]

    for name in FORMER_CURATED_ASAM:
        top = _engine_issues_of_text(tmp_path, [f"/begin {name}", f"/end {name}"])
        assert [i for i in top if i.code == "A2L_UNRECOGNIZED_BLOCK"] == [], name
    for name in FORMER_CURATED_INTERFACE:
        top = _engine_issues_of_text(tmp_path, [f"/begin {name}", f"/end {name}"])
        found = [i for i in top if i.code == "A2L_UNRECOGNIZED_BLOCK"]
        assert [(i.severity, i.message) for i in found] == [
            (ValidationSeverity.WARNING, f"Unrecognized A2L block '{name}'.")
        ], name

    # Engine freeze, same run — the proven TC-027 idiom (check=True, skip on
    # CalledProcessError / FileNotFoundError) plus a CRLF-aware byte-equality
    # against ``main``'s blobs (the checkout may carry CRLF). The CI PR
    # checkout fetches the PR head only, so ``main`` does not resolve there:
    # the arm skips instead of dying with exit 128 — exactly how
    # tests/test_engine_unchanged.py stays green on CI. Where ``main`` exists
    # (local runs, the post-merge gate) both assertions still bite, same run.
    frozen_paths = ["s19_app/validation/rules.py", "s19_app/tui/a2l.py"]
    try:
        completed = subprocess.run(
            ["git", "diff", "--name-only", "main", "--", *frozen_paths],
            cwd=_REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        changed = [line for line in completed.stdout.splitlines() if line.strip()]
        assert changed == [], changed
        for frozen in frozen_paths:
            blob = subprocess.run(
                ["git", "show", f"main:{frozen}"],
                cwd=_REPO_ROOT,
                capture_output=True,
                check=True,
            ).stdout
            worktree = (_REPO_ROOT / frozen).read_bytes().replace(b"\r\n", b"\n")
            assert hashlib.sha256(worktree).hexdigest() == hashlib.sha256(
                blob.replace(b"\r\n", b"\n")
            ).hexdigest(), frozen
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        pytest.skip(
            "git is unavailable or the 'main' ref is missing in this "
            "environment — TC-B94-18's engine-freeze arm cannot run: "
            f"{exc}"
        )


# ---------------------------------------------------------------------------
# TC-B94-19 — the panel matrix: severity is final.
# ---------------------------------------------------------------------------


def test_tc_b94_19_panel_reclassification_matrix(tmp_path: Path) -> None:
    """TC-B94-19 / R-TUI-042b.1, .2, .4, .6 — WARNING stays WARNING, no note, C-17.

    Intent (white-box over ``GroupedIssuesPanel.render_groups``): a WARNING for a block
    name once curated (REF_CHARACTERISTIC, PAGE) renders under WARNINGS with the
    ``sev-warning`` class and no justification note; the header counts are the caller's
    verbatim; the empty state renders; the caller's issues are never mutated; a hostile
    file-derived block name renders literal — 0 markup spans.
    """
    error_row = ValidationIssue(
        code="MAC_DUPLICATE",
        severity=ValidationSeverity.ERROR,
        message="dup",
        artifact="mac",
    )
    plain_warning = ValidationIssue(
        code="RANGE_GAP",
        severity=ValidationSeverity.WARNING,
        message="gap",
        artifact="s19",
    )
    plain_info = ValidationIssue(
        code="NOTE",
        severity=ValidationSeverity.INFO,
        message="note",
        artifact="s19",
    )

    async def _drive() -> None:
        app = S19TuiApp(base_dir=tmp_path)

        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("issues")
            panel = app.query_one("#validation_issues_groups", GroupedIssuesPanel)

            # --- a curated-name WARNING stays a WARNING; no note; counts verbatim ---
            mixed = [
                _unrecognized_issue("REF_CHARACTERISTIC"),
                _unrecognized_issue("PAGE"),
                _FROBNICATE,
                plain_warning,
                error_row,
                plain_info,
            ]
            counts = {
                ValidationSeverity.ERROR: 1,
                ValidationSeverity.WARNING: 4,
                ValidationSeverity.INFO: 1,
            }
            _mount_panel(app, mixed, counts)
            await wait_until(
                pilot,
                lambda: _rows_composed(panel, 6),
                lambda: f"rows mounted: {len(list(panel.query(IssueRow)))}",
            )
            headers = _headers(panel)
            assert headers["ERRORS"].issue_count == 1
            assert headers["WARNINGS"].issue_count == 4, headers["WARNINGS"].issue_count
            assert headers["INFO"].issue_count == 1, headers["INFO"].issue_count
            assert _note_count(panel) == 0
            rows = _row_codes(panel)
            assert rows.count(("sev-warning", "A2L_UNRECOGNIZED_BLOCK")) == 3, rows
            assert ("sev-info", "A2L_UNRECOGNIZED_BLOCK") not in rows, rows
            assert ("sev-warning", "RANGE_GAP") in rows, rows
            assert ("sev-error", "MAC_DUPLICATE") in rows, rows
            assert ("sev-info", "NOTE") in rows, rows
            warn_rows = [
                row
                for row in panel.query(IssueRow)
                if row._sev_class == "sev-warning" and row.issue.code == "A2L_UNRECOGNIZED_BLOCK"
            ]
            assert {row.issue.message for row in warn_rows} == {
                "Unrecognized A2L block 'REF_CHARACTERISTIC'.",
                "Unrecognized A2L block 'PAGE'.",
                "Unrecognized A2L block 'FROBNICATE'.",
            }
            # the caller's list is unmutated (raw severities preserved)
            assert [issue.severity for issue in mixed] == [
                _WARNING,
                _WARNING,
                _WARNING,
                _WARNING,
                ValidationSeverity.ERROR,
                ValidationSeverity.INFO,
            ]

            # --- empty state: no A2L, nothing to group ---
            panel.render_groups([], {})
            await wait_until(
                pilot,
                lambda: len(list(panel.query(IssueGroupHeader))) == 0
                and len(list(panel.query(".issues-empty-note"))) == 1,
                "the empty note",
            )
            empty = panel.query_one(".issues-empty-note")
            assert empty.render().plain == GroupedIssuesPanel.EMPTY_TEXT

            # --- C-17 hostile arm: a markup-laden block name renders literal ---
            hostile = _unrecognized_issue("EVIL[red]")
            _mount_panel(app, [hostile], {_WARNING: 1})
            await wait_until(
                pilot,
                lambda: _rows_composed(panel, 1),
                "the hostile row",
            )
            headers = _headers(panel)
            assert headers["WARNINGS"].issue_count == 1
            assert _note_count(panel) == 0
            hostile_row = panel.query_one(IssueRow)
            detail = hostile_row.query_one(".issue-detail")
            rendered = detail.render()
            assert "[red]" in rendered.plain, rendered.plain
            assert rendered.spans == [], rendered.spans
            assert hostile_row.query_one(".issue-code-chip").render().plain == (
                "A2L_UNRECOGNIZED_BLOCK"
            )

    asyncio.run(_drive())
