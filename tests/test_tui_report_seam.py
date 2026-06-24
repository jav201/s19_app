"""Black-box e2e acceptance for the in-TUI report-generation seam.

Audit-gaps follow-up (gap #3, batch-07 HLR-008 / LLR-008.5). Spec
``.fast-dev-flow/spec.md`` §3 AC-A1/A2/A3.

This is the Pilot e2e the 2026-06-23 audit found missing: the report
*service* (file write) and the ``ReportViewerScreen`` (render) were each
proven white-box, but the SEAM that fuses them — operator opens Reports,
triggers generation, the app runs the REAL ``generate_project_report``,
the path is surfaced, and the deliverable is rendered back through the
shipped viewer — had no end-to-end test that drives the real service.
``tests/test_tui_report_view.py::test_generate_trigger_calls_service_and
_drops_results`` deliberately monkeypatches ``generate_project_report``
with a fake, so it never observes a real file on disk.

This module drives the WHOLE seam with the real service and observes the
deliverable through the surface only:

- AC-A1 (``test_report_seam_writes_real_file_on_disk``): triggering
  generation via the real screen button writes a real
  ``<timestamp>-report.md`` under ``.s19tool/workarea/<project>/reports/``
  that exists and is non-empty on disk.
- AC-A2 (``test_report_seam_surfaces_written_path_in_status``): after
  generation the status line shows the written report path
  (``reports/<file>.md``).
- AC-A3 (``test_report_seam_renders_generated_report_in_viewer``):
  re-opening Reports and selecting the just-generated file renders ITS
  real content through ``ReportViewerScreen`` (observed through the
  screen, not a hand-built fixture).

Outcome: the seam is exercised end-to-end with no faked service, so these
tests LOCK the deliverable as a regression observed through the shipped
surface (closing the audit's black-box-acceptance gap). No production
change was required.

Harness: the ``asyncio.run`` + ``App.run_test()`` Pilot pattern of
``tests/test_tui_report_view.py`` / ``tests/test_tui_variants.py``.
Fixture data is synthetic / public-only and lives under ``tmp_path``
(F-S-07): the test never writes into the repo.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Tuple

from textual.widgets import Button, Markdown

from s19_app.tui.app import S19TuiApp
from s19_app.tui.screens import ReportViewerScreen
from s19_app.tui.services.report_service import (
    REPORT_FILENAME_REGEX,
    list_project_reports,
)

# Two minimal valid S19 images (checksums verified against
# s19_app.core.S19File) — a 2-variant project per the spec, so the seam is
# exercised on a real multi-variant inventory.
S19_A = "S107100001020304DE\nS9030000FC\n"  # 4 bytes at 0x1000
S19_B = "S10720000A0B0C0DAA\nS9030000FC\n"  # 4 bytes at 0x2000


def _write_change_document(path: Path) -> Path:
    """Write a minimal v2 ``s19app-changeset`` change document.

    One ``bytes`` entry at 0x1000 — applies on variant ``a`` (4 bytes at
    0x1000), giving the report a real modified region to hexdump.
    """
    path.write_text(
        json.dumps(
            {
                "format": "s19app-changeset",
                "version": "2.0",
                "kind": "change",
                "encoding": "utf-8",
                "value_mode": "text",
                "entries": [
                    {"type": "bytes", "address": "0x1000", "bytes": "AA"}
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def _make_report_project(app: S19TuiApp, name: str) -> Path:
    """Build a loadable, REPORTABLE 2-variant project on disk.

    Mirrors the established on-disk shape (``tests/test_tui_variants.py``
    project layout + the ``project.json`` manifest of
    ``tests/test_variant_execution.py``): two S19 variants, a change
    document, and a ``project.json`` whose ``batch`` references that change
    doc — so a project load populates ``_variant_set`` AND the seam's
    active-scope run has real work to report (the manifest is what makes
    ``_trigger_generate_report`` proceed instead of bailing with
    "nothing to report").
    """
    project_dir = app.workarea / name
    project_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "a.s19").write_text(S19_A, encoding="utf-8")
    (project_dir / "b.s19").write_text(S19_B, encoding="utf-8")
    _write_change_document(project_dir / "chg.json")
    (project_dir / "project.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "active_variant": "a",
                "batch": ["chg.json"],
                "assignments": {},
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return project_dir


async def _flush(pilot, count: int = 12) -> None:
    """Pump the event loop so deferred screen/message/apply work runs."""
    for _ in range(count):
        await pilot.pause()


async def _generate_through_surface(app: S19TuiApp, pilot) -> None:
    """Open Reports and trigger generation through the real screen control.

    Drives the same path the operator does and that
    ``on_report_viewer_screen_generate_requested`` handles: open the modal
    via ``action_view_reports``, press the real ``#report_generate`` button
    (which posts ``ReportViewerScreen.GenerateRequested`` and dismisses),
    then drain the background ``generate_report`` worker so the real
    ``generate_project_report`` runs to completion. ``_trigger_generate_
    report`` is NOT called directly — the surface control drives it.
    """
    app.action_view_reports()
    await _flush(pilot)
    screen = app.screen_stack[-1]
    assert isinstance(screen, ReportViewerScreen), (
        "action_view_reports must push the real ReportViewerScreen"
    )
    screen.query_one("#report_generate", Button).press()
    await _flush(pilot)
    await app.workers.wait_for_complete()
    await _flush(pilot)


# ---------------------------------------------------------------------------
# AC-A1 — a real report file is written under reports/ and is non-empty
# ---------------------------------------------------------------------------


def test_report_seam_writes_real_file_on_disk(tmp_path: Path) -> None:
    """Triggering generation writes a real, non-empty report on disk.

    Intent (AC-A1): the seam — operator opens Reports and presses Generate
    on a loaded 2-variant project — runs the REAL ``generate_project_
    report`` (no faked service) and produces a ``<timestamp>-report.md``
    under ``.s19tool/workarea/<project>/reports/`` that exists and is
    non-empty when read back off disk. This is the deliverable the audit
    needs observed end-to-end, not assumed.
    """

    async def _drive() -> Path:
        app = S19TuiApp(base_dir=tmp_path)
        _make_report_project(app, "proj")
        async with app.run_test() as pilot:
            await pilot.pause()
            app._handle_load_project("proj")
            await _flush(pilot)
            await app.workers.wait_for_complete()
            await _flush(pilot)
            await _generate_through_surface(app, pilot)
            project_dir = app._active_project_dir()
            assert project_dir is not None
            return project_dir

    project_dir = asyncio.run(_drive())
    reports = list_project_reports(project_dir)
    assert reports, (
        "AC-A1: the seam must write at least one report file under "
        f"reports/ — found none in {project_dir / 'reports'}"
    )
    report = reports[0]
    assert report.parent == project_dir / "reports", (
        "AC-A1: the report must land in the project's reports/ dir"
    )
    assert REPORT_FILENAME_REGEX.match(report.name), (
        f"AC-A1: report name must match the timestamp pattern, got {report.name!r}"
    )
    assert report.stat().st_size > 0, "AC-A1: the report file must be non-empty"
    assert report.read_text(encoding="utf-8").strip(), (
        "AC-A1: the report file must have real content on disk"
    )


# ---------------------------------------------------------------------------
# AC-A2 — the written report path is surfaced in the status line
# ---------------------------------------------------------------------------


def test_report_seam_surfaces_written_path_in_status(tmp_path: Path) -> None:
    """After generation the status line shows the written report path.

    Intent (AC-A2): ``_finish_generate_report`` surfaces the deliverable's
    location through the shipped status surface as ``reports/<file>.md``
    (project-relative because the status log trims to 50 chars). The
    operator sees WHERE the report landed without leaving the app.
    """

    async def _drive() -> Tuple[list[str], str]:
        app = S19TuiApp(base_dir=tmp_path)
        _make_report_project(app, "proj")
        async with app.run_test() as pilot:
            await pilot.pause()
            app._handle_load_project("proj")
            await _flush(pilot)
            await app.workers.wait_for_complete()
            await _flush(pilot)
            await _generate_through_surface(app, pilot)
            project_dir = app._active_project_dir()
            assert project_dir is not None
            report_name = list_project_reports(project_dir)[0].name
            return list(app.log_lines), report_name

    log_lines, report_name = asyncio.run(_drive())
    assert any(report_name in line for line in log_lines), (
        "AC-A2: the status line must surface the written report filename "
        f"{report_name!r}; status was {log_lines!r}"
    )
    assert any(
        f"reports/{report_name}" in line for line in log_lines
    ), (
        "AC-A2: the surfaced path must be the project-relative "
        f"reports/{report_name}; status was {log_lines!r}"
    )


# ---------------------------------------------------------------------------
# AC-A3 — the just-generated report renders through ReportViewerScreen
# ---------------------------------------------------------------------------


def test_report_seam_renders_generated_report_in_viewer(tmp_path: Path) -> None:
    """The just-generated report renders through the real viewer.

    Intent (AC-A3): the deliverable is observed THROUGH the shipped
    surface — the Generate button dismisses the modal (screens.py), so the
    operator re-opens Reports (the same ``action_view_reports`` surface)
    and selects the new file; ``ReportViewerScreen`` renders its REAL
    on-disk content into the ``Markdown`` widget. The rendered source is
    the generated file's bytes (the report header line), never a hand-built
    fixture.
    """

    async def _drive() -> Tuple[str, str, Path, object]:
        app = S19TuiApp(base_dir=tmp_path)
        _make_report_project(app, "proj")
        async with app.run_test() as pilot:
            await pilot.pause()
            app._handle_load_project("proj")
            await _flush(pilot)
            await app.workers.wait_for_complete()
            await _flush(pilot)
            await _generate_through_surface(app, pilot)
            project_dir = app._active_project_dir()
            assert project_dir is not None
            report = list_project_reports(project_dir)[0]
            disk_text = report.read_text(encoding="utf-8")

            # Re-open Reports through the real surface; the newest report is
            # first in the list, so selecting index 0 renders it.
            app.action_view_reports()
            await _flush(pilot)
            screen = app.screen_stack[-1]
            assert isinstance(screen, ReportViewerScreen)
            await pilot.press("enter")
            await _flush(pilot)
            markdown = screen.query_one("#report_markdown", Markdown)
            return markdown.source, disk_text, report, screen.selected_path

    rendered, disk_text, report, selected = asyncio.run(_drive())
    assert selected == report, (
        "AC-A3: the viewer must have selected the just-generated report, "
        f"got {selected!r}"
    )
    assert "# Project report: proj" in rendered, (
        "AC-A3: the rendered viewer content must be the real generated "
        f"report header; got source starting {rendered[:80]!r}"
    )
    assert rendered == disk_text, (
        "AC-A3: the viewer must render the report's real on-disk bytes, "
        "not a hand-built fixture"
    )
