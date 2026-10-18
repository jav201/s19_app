"""Issues warnings triage tests — batch-94 increment 004 (US-004 / HLR-012 / LLR-012.1/.2).

The Cambio4 triage: ``A2L_UNRECOGNIZED_BLOCK`` findings whose block name belongs to the
curated ASAP2 standard-keyword set (``CURATED_STANDARD_A2L_BLOCKS`` in ``s19_app/tui/issues_view.py``,
seeded from the executed 2026-10-13 tally) are presented as INFO with a stated justification
— never as warnings — and genuinely unknown blocks (the executed ``FROBNICATE`` negative
control, ``evidence/p1_probe_a2l_negative.txt``) stay warnings. Reclassification, never
suppression (D-6): no row is dropped.

- **AT-B94-14** (layer B) drives the shipped surface: the fixture
  ``examples/case_00_public/software_a.a2l`` loads through the real engine
  (``parse_a2l_file`` + ``validate_a2l_structure`` — the same path
  ``evidence/p1_probe_a2l_unrecognized.py`` probed: 13 990 tags, 1 023
  ``A2L_UNRECOGNIZED_BLOCK`` findings, per-family tally pinned here), then renders
  through ``GroupedIssuesPanel`` — the surface HLR-012 names. Counts are
  CALLER-owned: ``app.py`` triages the strip / summary / ``group_counts`` through
  ``adjust_counts_for_a2l_triage`` (the fold round — HLR-012 binds every
  presentation), so the shipped chrome arm asserts the painted strip + summary
  counts on a fixture-scale drive (the 1 023-arm: Warnings 0 / Info 1 023), the
  panel fed the full list reads the exact ``WARNING == 0 / INFO == 1 023`` census,
  and ``FROBNICATE`` still warns.
- **TC-B94-18** (layer A) pins the curated-set constant (21 seeded families, every
  member uppercase A2L vocabulary, ``FROBNICATE`` absent) AND the engine freeze in
  the SAME run: ``git diff --name-only main`` over ``validation/rules.py`` /
  ``tui/a2l.py`` is empty and the worktree bytes equal ``main``'s blob (CRLF-aware).
- **TC-B94-19** (layer A) is the panel matrix: mixed curated/unknown split across
  INFO/WARNING, the empty state, the no-reclassification no-op (byte-identical to
  the pre-Inc-004 grouping), the caller's list never mutated, and the C-17 hostile
  message rendering literal.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import subprocess
from collections import Counter
from pathlib import Path

import pytest
from textual.widgets import Static

import s19_app
from s19_app.core import S19File
from s19_app.tui.app import S19TuiApp
from s19_app.tui.changes.io import emit_s19_from_mem_map
from s19_app.tui.issues_view import (
    A2L_BLOCK_RECLASSIFICATION_JUSTIFICATION,
    CURATED_STANDARD_A2L_BLOCKS,
    GroupedIssuesPanel,
    IssueGroupHeader,
    IssueRow,
)
from s19_app.tui.services.load_service import build_loaded_s19
from s19_app.validation import ValidationIssue, ValidationSeverity

#: The executed 2026-10-13 census (``evidence/p1_probe_a2l_unrecognized.txt``) —
#: per-family tally over the stand-in fixture; the curated set's lineage.
EXPECTED_TALLY: dict[str, int] = {
    "REF_CHARACTERISTIC": 437,
    "REF_MEASUREMENT": 221,
    "AXIS_DESCR": 180,
    "COMPU_VTAB_RANGE": 69,
    "SUB_GROUP": 69,
    "DEF_CHARACTERISTIC": 22,
    "PAGE": 6,
    "SEGMENT": 3,
    "SUB_FUNCTION": 3,
    "PROTOCOL_LAYER": 2,
    "A2ML": 1,
    "CAN_FD": 1,
    "DAQ": 1,
    "EVENT": 1,
    "FORMULA": 1,
    "MOD_COMMON": 1,
    "MOD_PAR": 1,
    "PAG": 1,
    "STIM": 1,
    "TIMESTAMP_SUPPORTED": 1,
    "XCP_ON_CAN": 1,
}

#: The 21 seeded families, pasted from the executed tally (LLR-012.1's seed set).
EXPECTED_SEED_SET = frozenset(EXPECTED_TALLY)

_BLOCK_NAME_RE = re.compile(r"^Unrecognized A2L block '([A-Z0-9_]+)'\.$")

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


def _load_fixture_unrecognized() -> list[ValidationIssue]:
    """Run the real engine over the stand-in fixture (the P1 probe's exact path)."""
    from s19_app.tui.a2l import parse_a2l_file
    from s19_app.validation.rules import validate_a2l_structure

    if not _FIXTURE.exists():
        pytest.skip("examples/case_00_public/software_a.a2l not present")
    data = parse_a2l_file(_FIXTURE)
    assert data.get("errors") == [], data.get("errors")
    return [
        issue
        for issue in validate_a2l_structure(data)
        if issue.code == "A2L_UNRECOGNIZED_BLOCK"
    ]


def _names(issues: list[ValidationIssue]) -> list[str]:
    names = []
    for issue in issues:
        match = _BLOCK_NAME_RE.match(issue.message)
        assert match is not None, issue.message
        names.append(match.group(1))
    return names


def _mount_panel(app: S19TuiApp, issues, counts, truncated=False) -> GroupedIssuesPanel:
    """Render ``issues`` + ``counts`` through the shipped grouped panel."""
    panel = app.query_one("#validation_issues_groups", GroupedIssuesPanel)
    panel.render_groups(issues, counts, truncated=truncated)
    return panel


def _headers(panel: GroupedIssuesPanel) -> dict[ValidationSeverity, IssueGroupHeader]:
    return {h.severity_label: h for h in panel.query(IssueGroupHeader)}


def _justification_count(panel: GroupedIssuesPanel) -> int:
    return sum(
        1
        for static in panel.query(Static)
        if static.render().plain == A2L_BLOCK_RECLASSIFICATION_JUSTIFICATION
    )


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
# AT-B94-14 — fixture load through the engine, the shipped surface triaged.
# ---------------------------------------------------------------------------


def test_at_b94_14_fixture_triage_through_surface(tmp_path: Path) -> None:
    """AT-B94-14 / HLR-012 — the 1 023-finding census moves WARNING → INFO, 0 lost.

    Intent: the stand-in fixture loads through the real engine; the shipped
    ``GroupedIssuesPanel`` presents every curated-name finding as INFO with the
    justification (the WARNING group drops to zero), no row is dropped or
    mutated, and the ``FROBNICATE`` negative control still warns. The app-chrome
    arm proves the same on the live screen through ``update_validation_issues_view``.
    A silent no-op (nothing reclassified) or a suppression (rows vanish) fails.
    """
    unrecognized = _load_fixture_unrecognized()

    # --- census: the executed baseline, re-derived and pinned ---
    assert len(unrecognized) == 1023
    assert all(issue.severity is _WARNING for issue in unrecognized)
    assert Counter(_names(unrecognized)) == EXPECTED_TALLY

    async def _drive_panel() -> None:
        app = S19TuiApp(base_dir=tmp_path)

        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("issues")
            await pilot.pause()

            # --- shipped surface, full fixture list, caller-triaged counts ---
            # (exactly what app.py hands the panel after
            # ``adjust_counts_for_a2l_triage``: the 1 023 census moved.)
            triaged_counts = {
                ValidationSeverity.ERROR: 0,
                ValidationSeverity.WARNING: 0,
                ValidationSeverity.INFO: 1023,
            }
            panel = _mount_panel(app, unrecognized, triaged_counts, truncated=True)
            await pilot.pause()
            headers = _headers(panel)
            assert "WARNINGS" not in headers, list(headers)
            info = headers["INFO"]
            assert info.issue_count == 1023, info.issue_count
            assert _justification_count(panel) == 1
            rows = _row_codes(panel)
            assert len(rows) == 40  # the pre-existing LLR-042.6 display cap
            assert {sev for sev, _ in rows} == {"sev-info"}, rows
            # no row dropped: the tail of the list renders INFO too
            panel.render_groups(
                unrecognized[-40:],
                {ValidationSeverity.ERROR: 0, ValidationSeverity.WARNING: 0, ValidationSeverity.INFO: 40},
                truncated=False,
            )
            await pilot.pause()
            tail = _row_codes(panel)
            assert len(tail) == 40 and {sev for sev, _ in tail} == {"sev-info"}, tail
            assert _headers(panel)["INFO"].issue_count == 40

            # --- negative control: a genuinely unknown block still warns ---
            mixed = unrecognized + [_FROBNICATE]
            mixed_counts = {
                ValidationSeverity.ERROR: 0,
                ValidationSeverity.WARNING: 1,
                ValidationSeverity.INFO: 1023,
            }
            panel.render_groups(mixed, mixed_counts, truncated=True)
            await pilot.pause()
            headers = _headers(panel)
            assert headers["WARNINGS"].issue_count == 1, headers["WARNINGS"].issue_count
            assert headers["INFO"].issue_count == 1023
            rows = _row_codes(panel)
            warning_rows = [code for sev, code in rows if sev == "sev-warning"]
            assert warning_rows == ["A2L_UNRECOGNIZED_BLOCK"], rows
            assert _justification_count(panel) == 1

            # --- the caller's engine list is untouched (presentation-only copy) ---
            assert all(issue.severity is _WARNING for issue in unrecognized)

    asyncio.run(_drive_panel())

    # --- app chrome arm: the LIVE chrome triages strip + summary + panel ---
    async def _drive_app_chrome() -> None:
        chrome_dir = tmp_path / "chrome"
        chrome_dir.mkdir(exist_ok=True)
        app = S19TuiApp(base_dir=chrome_dir)

        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("issues")

            # fixture-scale drive: the 1 023-census flood leaves the headline
            # counters — strip, summary line and group headers alike.
            _seed_app_and_show_issues(app, tmp_path, unrecognized)
            await pilot.pause()
            panel = app.query_one("#validation_issues_groups", GroupedIssuesPanel)
            headers = _headers(panel)
            assert "WARNINGS" not in headers, list(headers)
            assert headers["INFO"].issue_count == 1023, (
                [h.issue_count for h in headers.values()]
            )
            strip_plain = panel.app.query_one("#issues_severity_strip", Static).render().plain
            assert "Warnings 0" in strip_plain, strip_plain
            assert "Info 1023" in strip_plain, strip_plain
            summary_plain = panel.app.query_one(
                "#validation_issues_summary"
            ).render().plain
            assert "errors=0" in summary_plain, summary_plain
            assert "warnings=0" in summary_plain, summary_plain
            assert "info=1023" in summary_plain, summary_plain
            assert _justification_count(panel) == 1
            rows = _row_codes(panel)
            assert {sev for sev, _ in rows} == {"sev-info"}, rows

            # mixed drive: 38 curated + FROBNICATE + one error — the strip,
            # summary and panel agree on the same triaged census.
            seeded = unrecognized[:38] + [_FROBNICATE] + [
                ValidationIssue(
                    code="MAC_DUPLICATE",
                    severity=ValidationSeverity.ERROR,
                    message="dup",
                    artifact="mac",
                )
            ]
            _seed_app_and_show_issues(app, tmp_path, seeded)
            await pilot.pause()
            panel = app.query_one("#validation_issues_groups", GroupedIssuesPanel)
            headers = _headers(panel)
            assert headers["ERRORS"].issue_count == 1
            assert headers["WARNINGS"].issue_count == 1, headers["WARNINGS"].issue_count
            assert headers["INFO"].issue_count == 38, headers["INFO"].issue_count
            assert _justification_count(panel) == 1
            rows = _row_codes(panel)
            by_class: dict[str, list[str]] = {}
            for sev, code in rows:
                by_class.setdefault(sev, []).append(code)
            assert by_class.get("sev-warning") == ["A2L_UNRECOGNIZED_BLOCK"], rows
            assert set(by_class.get("sev-info", [])) == {"A2L_UNRECOGNIZED_BLOCK"}
            assert by_class.get("sev-error") == ["MAC_DUPLICATE"]
            strip_plain = panel.app.query_one("#issues_severity_strip", Static).render().plain
            assert "Errors 1" in strip_plain and "Warnings 1" in strip_plain, strip_plain
            assert "Info 38" in strip_plain, strip_plain
            summary_plain = panel.app.query_one(
                "#validation_issues_summary"
            ).render().plain
            assert "errors=1" in summary_plain and "warnings=1" in summary_plain, (
                summary_plain
            )
            assert "info=38" in summary_plain, summary_plain
            # the reclassified rows carry the justification beside the INFO header
            note = panel.query_one(".issue-reclassify-note")
            assert note.render().plain == A2L_BLOCK_RECLASSIFICATION_JUSTIFICATION

    asyncio.run(_drive_app_chrome())


# ---------------------------------------------------------------------------
# TC-B94-18 — the curated set and the engine freeze, in the same run.
# ---------------------------------------------------------------------------


def test_tc_b94_18_curated_set_and_engine_freeze() -> None:
    """TC-B94-18 / LLR-012.1 — curated-set membership + ``rules.py`` byte-unchanged.

    Intent: the view-owned constant holds exactly the 21 executed tally families
    (a superset or a subset fails), every member is uppercase A2L vocabulary, and
    ``FROBNICATE`` — the executed negative control — is not a member. In the SAME
    run the engine freeze holds: no diff vs ``main`` over ``validation/rules.py``
    and ``tui/a2l.py`` and the worktree bytes equal ``main``'s blobs (CRLF-aware).
    Adding a non-standard name to the set, or any engine edit, turns this RED.
    """
    assert CURATED_STANDARD_A2L_BLOCKS == EXPECTED_SEED_SET, (
        set(CURATED_STANDARD_A2L_BLOCKS) ^ set(EXPECTED_SEED_SET)
    )
    assert len(CURATED_STANDARD_A2L_BLOCKS) == 21
    for name in CURATED_STANDARD_A2L_BLOCKS:
        assert re.fullmatch(r"[A-Z0-9_]+", name), name
        assert name == name.upper(), name
    assert "FROBNICATE" not in CURATED_STANDARD_A2L_BLOCKS
    assert "" not in CURATED_STANDARD_A2L_BLOCKS

    # Engine freeze, same run — the proven TC-027 idiom plus a CRLF-aware
    # byte-equality against ``main``'s blobs (the checkout may carry CRLF).
    frozen_paths = ["s19_app/validation/rules.py", "s19_app/tui/a2l.py"]
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


# ---------------------------------------------------------------------------
# TC-B94-19 — the panel reclassification matrix.
# ---------------------------------------------------------------------------


def test_tc_b94_19_panel_reclassification_matrix(tmp_path: Path) -> None:
    """TC-B94-19 / LLR-012.2 — INFO/WARNING split, empty state, no-op, C-17.

    Intent (white-box over ``GroupedIssuesPanel.render_groups``): a mixed file
    splits curated → INFO and unknown → WARNING with the justification at the
    INFO group; the empty state renders; with no reclassifiable row the render
    is the pre-Inc-004 grouping verbatim (counts untouched, no justification);
    the caller's issues are never mutated; a hostile file-derived block name
    fails closed (stays a warning) and renders literal — 0 markup spans.
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
            await pilot.pause()
            panel = app.query_one("#validation_issues_groups", GroupedIssuesPanel)

            # --- mixed split: curated + unknown + other severities ---
            mixed = [
                _unrecognized_issue("REF_CHARACTERISTIC"),
                _unrecognized_issue("PAGE"),
                _FROBNICATE,
                plain_warning,
                error_row,
                plain_info,
            ]
            # caller-triaged counts (what app.py hands the panel after
            # ``adjust_counts_for_a2l_triage``): the two curated rows moved.
            triaged_counts = {
                ValidationSeverity.ERROR: 1,
                ValidationSeverity.WARNING: 2,
                ValidationSeverity.INFO: 3,
            }
            _mount_panel(app, mixed, triaged_counts)
            await pilot.pause()
            headers = _headers(panel)
            assert headers["ERRORS"].issue_count == 1
            assert headers["WARNINGS"].issue_count == 2, headers["WARNINGS"].issue_count
            assert headers["INFO"].issue_count == 3, headers["INFO"].issue_count
            assert _justification_count(panel) == 1
            rows = _row_codes(panel)
            assert rows.count(("sev-info", "A2L_UNRECOGNIZED_BLOCK")) == 2, rows
            assert rows.count(("sev-warning", "A2L_UNRECOGNIZED_BLOCK")) == 1, rows
            assert ("sev-warning", "RANGE_GAP") in rows, rows
            assert ("sev-error", "MAC_DUPLICATE") in rows, rows
            assert ("sev-info", "NOTE") in rows, rows
            # reclassified rows keep their message/address payload (no row dropped)
            info_rows = [
                row
                for row in panel.query(IssueRow)
                if row._sev_class == "sev-info"
                and row.issue.code == "A2L_UNRECOGNIZED_BLOCK"
            ]
            assert {row.issue.message for row in info_rows} == {
                "Unrecognized A2L block 'REF_CHARACTERISTIC'.",
                "Unrecognized A2L block 'PAGE'.",
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
            await pilot.pause()
            assert len(list(panel.query(IssueGroupHeader))) == 0
            empty = panel.query_one(".issues-empty-note")
            assert empty.render().plain == GroupedIssuesPanel.EMPTY_TEXT

            # --- no-op degenerate: zero reclassifiable rows, pre-Inc-004 render ---
            inert = [_FROBNICATE, plain_warning, error_row, plain_info]
            inert_counts = {
                ValidationSeverity.ERROR: 1,
                ValidationSeverity.WARNING: 2,
                ValidationSeverity.INFO: 1,
            }
            _mount_panel(app, inert, inert_counts)
            await pilot.pause()
            headers = _headers(panel)
            assert headers["WARNINGS"].issue_count == 2
            assert headers["INFO"].issue_count == 1
            assert _justification_count(panel) == 0
            assert Counter(_row_codes(panel)) == Counter(
                {
                    ("sev-warning", "A2L_UNRECOGNIZED_BLOCK"): 1,
                    ("sev-warning", "RANGE_GAP"): 1,
                    ("sev-error", "MAC_DUPLICATE"): 1,
                    ("sev-info", "NOTE"): 1,
                }
            )

            # --- C-17 hostile arm: a markup-laden block name fails closed ---
            hostile = _unrecognized_issue("EVIL[red]")
            _mount_panel(app, [hostile], {_WARNING: 1})
            await pilot.pause()
            headers = _headers(panel)
            assert headers["WARNINGS"].issue_count == 1
            assert _justification_count(panel) == 0
            hostile_row = panel.query_one(IssueRow)
            detail = hostile_row.query_one(".issue-detail")
            rendered = detail.render()
            assert "[red]" in rendered.plain, rendered.plain
            assert rendered.spans == [], rendered.spans
            # and the code chip renders the code literal too
            assert hostile_row.query_one(".issue-code-chip").render().plain == (
                "A2L_UNRECOGNIZED_BLOCK"
            )

    asyncio.run(_drive())
