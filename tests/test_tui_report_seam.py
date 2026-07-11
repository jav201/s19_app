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
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Tuple

import pytest
from textual.widgets import Button, Markdown, TextArea

import s19_app.tui.app as app_module
from s19_app.tui.app import S19TuiApp
from s19_app.tui.screens import ReportViewerScreen, _parse_declared_regions
from s19_app.tui.services.report_addendum import DeclaredRegion
from s19_app.tui.services.report_service import (
    REPORT_FILENAME_REGEX,
    list_project_reports,
)
from s19_app.tui.services.variant_execution_service import read_project_manifest

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


def _notices(app: S19TuiApp) -> list[tuple[str, str]]:
    """Capture ``(title, message)`` for every ``notify`` call on the app.

    Ported from ``tests/test_tui_manifest_save.py`` (carry C-P3a). Returns the
    mutable list the patched ``notify`` appends to so a test can assert on the
    skip-count notice surface (LLR-029.3). ``ReportViewerScreen.notify`` (a
    ``Widget.notify``) delegates to ``app.notify``, so patching the app's
    method observes the screen's ``self.notify`` — install BEFORE the Generate
    press.
    """
    captured: list[tuple[str, str]] = []
    original = app.notify

    def _patched(message: str, *, title: str = "", **kwargs):
        captured.append((title, message))
        return original(message, title=title, **kwargs)

    app.notify = _patched  # type: ignore[method-assign]
    return captured


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


# ---------------------------------------------------------------------------
# US-020c (batch-19) — declared-region input through the report dialog
# ---------------------------------------------------------------------------


def test_declared_region_in_dialog_reaches_report_addendum(tmp_path: Path) -> None:
    """AT-024c — a region typed into the ReportViewerScreen input reaches the
    PRODUCED report's addendum (C-12: observed over the handler-produced file,
    not a direct ReportOptions write).

    The change document modifies 0x1000, so the declared region
    ``calzone,0x1000,0x10FF`` contains that modification and the addendum must
    list it.
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
            app.action_view_reports()
            await _flush(pilot)
            screen = app.screen_stack[-1]
            assert isinstance(screen, ReportViewerScreen)
            screen.query_one("#report_declared_regions", TextArea).text = (
                "calzone,0x1000,0x10FF"
            )
            screen.query_one("#report_generate", Button).press()
            await _flush(pilot)
            await app.workers.wait_for_complete()
            await _flush(pilot)
            project_dir = app._active_project_dir()
            assert project_dir is not None
            return project_dir

    project_dir = asyncio.run(_drive())
    report = list_project_reports(project_dir)[0]
    text = report.read_text(encoding="utf-8")
    assert "## Addendum: declared regions" in text
    assert "calzone" in text
    assert "modification @ 0x1000" in text


def test_parse_declared_regions_handles_hex_dec_and_skips_malformed() -> None:
    """TC-024.5 — the dialog parser accepts hex/decimal bounds and skips blank
    or malformed/invalid lines (never aborts on a bad line).

    Updated for batch-20 LLR-029.1: ``_parse_declared_regions`` now returns
    ``(regions, skipped)`` — this unpacks the new shape (the return-shape change
    is the fail-loud signal the contract moved). The three non-blank bad lines
    (wrong-arity + two invalid) are counted; the blank line is not.
    """
    regions, skipped = _parse_declared_regions(
        "cal,0x1000,0x10FF\n"  # hex
        "ram,4096,8191\n"  # decimal
        "\n"  # blank → skipped, NOT counted
        "bad line\n"  # wrong arity → skipped + counted
        "neg,-1,0x10\n"  # start < 0 → DeclaredRegion rejects → counted
        "rev,0x20,0x10\n"  # start > end → rejected → counted
    )
    assert len(regions) == 2
    assert regions[0] == DeclaredRegion("cal", 0x1000, 0x10FF)
    assert regions[1].start == 4096 and regions[1].end == 8191
    assert skipped == 3, "three non-blank bad lines counted; blank excluded"


def test_report_dialog_with_region_input_fits_80_and_120_cols(tmp_path: Path) -> None:
    """TC-024.6 — C-13 geometry: with the declared-region input added, the
    report dialog still fits within the terminal and the input is reachable at
    the 80- and 120-col regimes."""

    async def _measure(width: int) -> tuple[int, int, int, int, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(width, 24)) as pilot:
            await pilot.pause()
            app.push_screen(ReportViewerScreen("proj", []))
            await pilot.pause()
            screen = app.screen
            dlg = screen.query_one("#report_dialog")
            ta = screen.query_one("#report_declared_regions", TextArea)
            return (
                dlg.region.bottom,
                dlg.region.right,
                ta.region.height,
                app.size.width,
                app.size.height,
            )

    for width in (80, 120):
        bottom, right, ta_height, sw, sh = asyncio.run(_measure(width))
        assert bottom <= sh and right <= sw, (
            f"report dialog clipped at {width}x24: bottom={bottom}/{sh}, "
            f"right={right}/{sw}"
        )
        assert ta_height > 0, "declared-region input not visible"


# ---------------------------------------------------------------------------
# batch-20 / HLR-027 (US-024 SAVE half) — declared regions persist to
# project.json on project SAVE. Capture point = Option A (on Generate).
# ---------------------------------------------------------------------------
#
# Coverage map (test -> AT/TC -> LLR):
# - AT-027a (test_save_persists_declared_regions): Generate+Save ⇒ the on-disk
#   project.json carries the EXACT declared-region tuple. THE on-disk gate.
# - AT-027b (test_typed_but_not_generated_not_saved): type-without-Generate ⇒
#   nothing captured ⇒ manifest declared_regions == () (Option-A boundary).
# - AT-027c (test_save_without_regions_byte_identical): no regions ever ⇒ the
#   raw project.json has NO declared_regions key + a legacy no-key project.json
#   still loads (back-compat, byte-identical to pre-batch-20).
# - TC-027.1 (test_save_threads_declared_regions_to_writer): white-box — the
#   save path reaches write_project_manifest with the captured regions
#   (on-disk oracle).
# - TC-027.2 (test_write_and_verify_manifest_accepts_declared_regions_default):
#   white-box — _write_and_verify_manifest callable with and without
#   declared_regions (defaulted; existing callers stay valid).
# - TC-027.3 (test_empty_regions_omits_key): white-box — empty
#   self._declared_regions ⇒ serialized project.json omits the key (0-byte
#   delta vs a no-regions baseline).


async def _type_regions_and_generate(
    app: S19TuiApp, pilot, region_text: str, *, generate: bool
) -> None:
    """Open Reports, type ``region_text`` into the region TextArea, optionally Generate.

    Drives the operator path: ``action_view_reports`` pushes the real
    ``ReportViewerScreen``; the region lines are typed into the
    ``#report_declared_regions`` ``TextArea``; when ``generate`` is True the
    real ``#report_generate`` button is pressed (which posts
    ``GenerateRequested`` → the app captures into ``self._declared_regions``)
    and the worker is drained. When ``generate`` is False the dialog is left as
    typed-but-not-generated (the Option-A capture boundary).
    """
    app.action_view_reports()
    await _flush(pilot)
    screen = app.screen_stack[-1]
    assert isinstance(screen, ReportViewerScreen)
    screen.query_one("#report_declared_regions", TextArea).text = region_text
    if generate:
        screen.query_one("#report_generate", Button).press()
        await _flush(pilot)
        await app.workers.wait_for_complete()
        await _flush(pilot)


def _save_loaded_project(app: S19TuiApp, pilot_unused=None) -> Path:
    """Save the currently-loaded project through the real save handler.

    Invokes ``_handle_save_dialog`` with the same minimal
    ``SaveProjectPayload`` shape ``tests/test_tui_manifest_save.py`` uses
    (parent_folder = workarea, project_name = "proj"). Returns the project dir.
    """
    payload = app_module.SaveProjectPayload(
        parent_folder=str(app.workarea), project_name="proj"
    )
    app._handle_save_dialog(payload)
    return app.workarea / "proj"


def test_save_persists_declared_regions(tmp_path: Path) -> None:
    """AT-027a — Generate+Save persists the EXACT declared-region tuple to disk.

    Intent (HLR-027): the operator declares two non-default named regions in
    the Reports dialog, presses Generate (capture, Option A), then saves the
    project through the real ``_handle_save_dialog``. The on-disk
    ``project.json`` — re-read via the ``read_project_manifest`` oracle — must
    carry EXACTLY those two regions, in order (C-10 exact content, not
    ``len > 0``). RED pre-fix: the save handler did not thread
    ``self._declared_regions``, so the oracle returned ``()``.
    """

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        _make_report_project(app, "proj")
        async with app.run_test() as pilot:
            await pilot.pause()
            app._handle_load_project("proj")
            await _flush(pilot)
            await app.workers.wait_for_complete()
            await _flush(pilot)
            await _type_regions_and_generate(
                app,
                pilot,
                "bootblk,0x1000,0x10FF\ncal,0x8000,0x80FF",
                generate=True,
            )
            project_dir = _save_loaded_project(app)
            await _flush(pilot)
            return read_project_manifest(project_dir).declared_regions

    declared = asyncio.run(_drive())
    assert declared == (
        DeclaredRegion("bootblk", 0x1000, 0x10FF),
        DeclaredRegion("cal", 0x8000, 0x80FF),
    ), (
        "AT-027a: the saved project.json must carry the exact declared-region "
        f"tuple in order; oracle returned {declared!r}"
    )


def test_typed_but_not_generated_not_saved(tmp_path: Path) -> None:
    """AT-027b — a region typed but NOT generated with is not persisted.

    Intent (HLR-027 capture boundary, Option A): capture happens ON Generate.
    If the operator types a region into the dialog but never presses Generate,
    then saves, the on-disk ``project.json`` carries NO regions. This locks the
    accepted edge in the DoR decision (D1). RED if capture moved to
    save/keystroke.
    """

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        _make_report_project(app, "proj")
        async with app.run_test() as pilot:
            await pilot.pause()
            app._handle_load_project("proj")
            await _flush(pilot)
            await app.workers.wait_for_complete()
            await _flush(pilot)
            await _type_regions_and_generate(
                app, pilot, "bootblk,0x1000,0x10FF", generate=False
            )
            project_dir = _save_loaded_project(app)
            await _flush(pilot)
            return read_project_manifest(project_dir).declared_regions

    declared = asyncio.run(_drive())
    assert declared == (), (
        "AT-027b: a region typed but never generated with must NOT persist; "
        f"oracle returned {declared!r}"
    )


def test_save_without_regions_byte_identical(tmp_path: Path) -> None:
    """AT-027c — no regions ⇒ the project.json omits the key + legacy loads.

    Intent (HLR-027 back-compat): when no regions are ever generated, the
    save writes a ``project.json`` whose RAW JSON has NO ``declared_regions``
    key (byte-identical to pre-batch-20 output), and a hand-written legacy
    ``project.json`` with no key still re-reads with zero reader issues. RED if
    the save wrote ``declared_regions: []`` when empty.
    """

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        _make_report_project(app, "proj")
        async with app.run_test() as pilot:
            await pilot.pause()
            app._handle_load_project("proj")
            await _flush(pilot)
            await app.workers.wait_for_complete()
            await _flush(pilot)
            # No Reports dialog opened, no Generate ⇒ no capture.
            project_dir = _save_loaded_project(app)
            await _flush(pilot)
            raw = (project_dir / "project.json").read_text(encoding="utf-8")
            manifest = read_project_manifest(project_dir)
            return raw, json.loads(raw), manifest.declared_regions, manifest.issues

    raw, payload, declared, issues = asyncio.run(_drive())
    assert "declared_regions" not in payload, (
        "AT-027c: an empty-regions save must OMIT the declared_regions key; "
        f"raw project.json was {raw!r}"
    )
    assert declared == (), "AT-027c: the no-key manifest must re-read as no regions"
    assert issues == [], (
        f"AT-027c: a legacy no-key project.json must load without error; got {issues}"
    )


def test_save_threads_declared_regions_to_writer(tmp_path: Path) -> None:
    """TC-027.1 — the save path reaches write_project_manifest with the regions.

    Intent (white-box, LLR-027.2/.3/.4): after capture (regions set on
    ``self._declared_regions`` via the GenerateRequested handler), the save
    threads them through ``_handle_save_dialog`` → ``_write_and_verify_manifest``
    → ``write_project_manifest``. Asserted via the on-disk oracle (preferred
    over mocking the substrate): the regions reach the writer iff they appear in
    the written manifest.
    """

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        _make_report_project(app, "proj")
        async with app.run_test() as pilot:
            await pilot.pause()
            app._handle_load_project("proj")
            await _flush(pilot)
            await app.workers.wait_for_complete()
            await _flush(pilot)
            # Capture directly via the handler's message contract (the same
            # path the Generate button drives).
            app.on_report_viewer_screen_generate_requested(
                ReportViewerScreen.GenerateRequested(
                    0, (DeclaredRegion("ram", 0x2000, 0x20FF),)
                )
            )
            await _flush(pilot)
            await app.workers.wait_for_complete()
            await _flush(pilot)
            project_dir = _save_loaded_project(app)
            await _flush(pilot)
            return read_project_manifest(project_dir).declared_regions

    declared = asyncio.run(_drive())
    assert declared == (DeclaredRegion("ram", 0x2000, 0x20FF),), (
        "TC-027.1: the captured region must reach write_project_manifest and "
        f"land in the written manifest; oracle returned {declared!r}"
    )


def test_write_and_verify_manifest_accepts_declared_regions_default(
    tmp_path: Path,
) -> None:
    """TC-027.2 — _write_and_verify_manifest is callable with AND without regions.

    Intent (white-box, LLR-027.4): the new ``declared_regions`` param is
    keyword-only and DEFAULTED — existing 2-kwarg callers (batch / assignments
    only) stay valid, and the new caller can pass regions. We drive both call
    shapes against a loaded project and assert each writes a project.json the
    oracle can re-read.
    """

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        _make_report_project(app, "proj")
        async with app.run_test() as pilot:
            await pilot.pause()
            app._handle_load_project("proj")
            await _flush(pilot)
            await app.workers.wait_for_complete()
            await _flush(pilot)
            project_dir = app.workarea / "proj"
            # Without declared_regions (existing-caller shape).
            app._write_and_verify_manifest(project_dir)
            await _flush(pilot)
            without = read_project_manifest(project_dir).declared_regions
            # With declared_regions (new-caller shape).
            app._write_and_verify_manifest(
                project_dir,
                declared_regions=(DeclaredRegion("cal", 0x8000, 0x80FF),),
            )
            await _flush(pilot)
            with_ = read_project_manifest(project_dir).declared_regions
            return without, with_

    without, with_ = asyncio.run(_drive())
    assert without == (), "TC-027.2: the defaulted call must write no regions"
    assert with_ == (DeclaredRegion("cal", 0x8000, 0x80FF),), (
        "TC-027.2: the explicit call must thread regions to the writer; "
        f"got {with_!r}"
    )


def test_empty_regions_omits_key(tmp_path: Path) -> None:
    """TC-027.3 — empty self._declared_regions ⇒ serialized project.json omits the key.

    Intent (white-box, LLR-027.1 back-compat): an empty capture must produce a
    project.json byte-identical to the no-regions baseline (the
    ``declared_regions`` key is omitted, not written as ``[]``). We compare the
    raw bytes of a save with ``self._declared_regions = ()`` against a save with
    a populated-then-cleared capture — the bytes must be identical (0-byte
    delta) and neither must contain the key.
    """

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        _make_report_project(app, "proj")
        async with app.run_test() as pilot:
            await pilot.pause()
            app._handle_load_project("proj")
            await _flush(pilot)
            await app.workers.wait_for_complete()
            await _flush(pilot)
            project_dir = app.workarea / "proj"
            # Baseline: empty capture (the default).
            assert app._declared_regions == ()
            app._write_and_verify_manifest(project_dir)
            await _flush(pilot)
            baseline = (project_dir / "project.json").read_bytes()
            # Populate then clear ⇒ empty again ⇒ must reproduce the baseline.
            app._declared_regions = (DeclaredRegion("x", 0x10, 0x1F),)
            app._declared_regions = ()
            app._write_and_verify_manifest(project_dir)
            await _flush(pilot)
            after = (project_dir / "project.json").read_bytes()
            return baseline, after

    baseline, after = asyncio.run(_drive())
    assert b"declared_regions" not in baseline, (
        "TC-027.3: an empty-capture save must OMIT the declared_regions key"
    )
    assert after == baseline, (
        "TC-027.3: clearing the capture back to empty must reproduce the "
        "byte-identical no-regions project.json (0-byte delta)"
    )


# ---------------------------------------------------------------------------
# batch-20 / HLR-028 (US-024 LOAD half) — declared regions pre-fill the
# Reports dialog on project LOAD. Seed = inverse of _parse_declared_regions.
# ---------------------------------------------------------------------------
#
# Coverage map (test -> AT/TC -> LLR):
# - AT-028a (test_load_prefills_declared_regions): THE GATE (C-12). One
#   through-surface chain: type+Generate+real-save ⇒ fresh app load ⇒ open
#   Reports ⇒ the TextArea text equals a hand-computed LITERAL string. Reverts
#   RED if EITHER the Inc-A save thread OR this increment's load-seed breaks.
# - AT-028b (test_load_seed_guard): GUARD (never the gate) — a project.json
#   written DIRECTLY on disk (bypassing the save handler) seeds the TextArea.
#   Stays green under a reverted save handler ⇒ cannot be the gate.
# - TC-028.1 (test_load_sets_declared_regions_state): white-box — load sets
#   app._declared_regions to the manifest tuple.
# - TC-028.2 (test_seed_format_is_parser_inverse): white-box idempotence — the
#   production seed text re-parses to the identical tuple.


async def _open_reports_text(app: S19TuiApp, pilot) -> str:
    """Open the Reports dialog through the real surface; return the seed text.

    Drives ``action_view_reports`` (which threads ``self._declared_regions``
    into ``ReportViewerScreen``), then reads the ``#report_declared_regions``
    TextArea ``.text`` — the LOAD-seed observable.
    """
    app.action_view_reports()
    await _flush(pilot)
    screen = app.screen_stack[-1]
    assert isinstance(screen, ReportViewerScreen)
    return screen.query_one("#report_declared_regions", TextArea).text


def test_load_prefills_declared_regions(tmp_path: Path) -> None:
    """AT-028a (THE GATE, C-12) — save then fresh-load pre-fills the dialog.

    Intent (HLR-028 + HLR-027 fused): the operator declares two regions in the
    Reports dialog, presses Generate (capture, Inc A), saves through the REAL
    ``_handle_save_dialog``; then a FRESH ``S19TuiApp`` loads the SAME project
    and re-opens Reports — the region TextArea shows EXACTLY those regions,
    decimal-rendered, in order. The expected string is HAND-COMPUTED
    (0x1000=4096, 0x10FF=4351, 0x8000=32768, 0x80FF=33023), NOT derived via the
    production seed helper (anti-tautology, qa minor-2). RED if either the
    save-thread (Inc A) or the load-seed (this increment) breaks.
    """

    async def _drive() -> str:
        # Phase 1: save a project carrying two declared regions.
        app = S19TuiApp(base_dir=tmp_path)
        _make_report_project(app, "proj")
        async with app.run_test() as pilot:
            await pilot.pause()
            app._handle_load_project("proj")
            await _flush(pilot)
            await app.workers.wait_for_complete()
            await _flush(pilot)
            await _type_regions_and_generate(
                app,
                pilot,
                "bootblk,0x1000,0x10FF\ncal,0x8000,0x80FF",
                generate=True,
            )
            _save_loaded_project(app)
            await _flush(pilot)

        # Phase 2: a FRESH app instance loads the SAME project off disk.
        fresh = S19TuiApp(base_dir=tmp_path)
        async with fresh.run_test() as pilot:
            await pilot.pause()
            fresh._handle_load_project("proj")
            await _flush(pilot)
            await fresh.workers.wait_for_complete()
            await _flush(pilot)
            return await _open_reports_text(fresh, pilot)

    seed_text = asyncio.run(_drive())
    assert seed_text == "bootblk,4096,4351\ncal,32768,33023", (
        "AT-028a: a fresh load must pre-fill the region TextArea with the saved "
        "regions, decimal-rendered in stored order; "
        f"TextArea text was {seed_text!r}"
    )


def test_load_seed_guard(tmp_path: Path) -> None:
    """AT-028b (GUARD, never the gate) — a hand-written manifest seeds the dialog.

    Intent (HLR-028 load-seed in isolation): a ``project.json`` written
    DIRECTLY on disk (bypassing the save handler) with a ``declared_regions``
    entry, when loaded and re-opened, seeds the region TextArea so the text
    round-trips to ``DeclaredRegion("ram", 8192, 12287)``. Because no save
    handler runs, this stays GREEN even if the Inc-A save thread is reverted —
    which is exactly why it is the guard, not the gate.
    """

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        project_dir = _make_report_project(app, "proj")
        # Inject declared_regions directly into the on-disk manifest, bypassing
        # the save handler entirely (this is what makes it a guard, not a gate).
        manifest_path = project_dir / "project.json"
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        payload["declared_regions"] = [
            {"name": "ram", "start": 8192, "end": 12287}
        ]
        manifest_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        async with app.run_test() as pilot:
            await pilot.pause()
            app._handle_load_project("proj")
            await _flush(pilot)
            await app.workers.wait_for_complete()
            await _flush(pilot)
            return await _open_reports_text(app, pilot)

    seed_text = asyncio.run(_drive())
    assert seed_text == "ram,8192,12287", (
        "AT-028b: a hand-written manifest's region must seed the TextArea; "
        f"text was {seed_text!r}"
    )
    # The seed must round-trip back to the identical region (batch-20: the
    # parser now returns ``(regions, skipped)`` — unpack regions, no skips).
    reparsed, skipped = _parse_declared_regions(seed_text)
    assert reparsed == (
        DeclaredRegion("ram", 8192, 12287),
    ), "AT-028b: the seeded text must re-parse to the same region"
    assert skipped == 0, "AT-028b: a clean seed must not register any skips"


def test_load_sets_declared_regions_state(tmp_path: Path) -> None:
    """TC-028.1 — load sets app._declared_regions to the manifest tuple.

    Intent (white-box, LLR-028.1): after ``_handle_load_project`` on a project
    whose manifest carries regions, ``app._declared_regions`` equals the exact
    expected tuple (the seed source for LLR-028.2/.4).
    """

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        project_dir = _make_report_project(app, "proj")
        manifest_path = project_dir / "project.json"
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        payload["declared_regions"] = [
            {"name": "bootblk", "start": 4096, "end": 4351},
            {"name": "cal", "start": 32768, "end": 33023},
        ]
        manifest_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        async with app.run_test() as pilot:
            await pilot.pause()
            app._handle_load_project("proj")
            await _flush(pilot)
            await app.workers.wait_for_complete()
            await _flush(pilot)
            return app._declared_regions

    declared = asyncio.run(_drive())
    assert declared == (
        DeclaredRegion("bootblk", 4096, 4351),
        DeclaredRegion("cal", 32768, 33023),
    ), (
        "TC-028.1: load must set app._declared_regions to the manifest's "
        f"region tuple; got {declared!r}"
    )


def test_seed_format_is_parser_inverse() -> None:
    """TC-028.2 — the seed format is the inverse of _parse_declared_regions.

    Intent (white-box idempotence, LLR-028.4): render a tuple of regions with
    the SAME format the production ``compose`` seed uses, then re-parse it with
    ``_parse_declared_regions`` — the result must equal the original tuple. This
    is the ONE place the seed format may appear on both sides: it is explicitly
    a round-trip test, not AT-028a's deliverable.
    """
    regions = (
        DeclaredRegion("bootblk", 0x1000, 0x10FF),
        DeclaredRegion("cal", 0x8000, 0x80FF),
    )
    # Same expression as compose's TextArea seed (LLR-028.4).
    seeded = "\n".join(
        f"{region.name},{region.start},{region.end}" for region in regions
    )
    # batch-20: parser returns ``(regions, skipped)`` — unpack and check both.
    reparsed, skipped = _parse_declared_regions(seeded)
    assert reparsed == regions, (
        "TC-028.2: the seed text must re-parse to the identical region tuple "
        f"(idempotence); re-parse of {seeded!r} did not round-trip"
    )
    assert skipped == 0, "TC-028.2: a clean seed must not register any skips"


# ---------------------------------------------------------------------------
# batch-20 / HLR-029 (US-025 / D-2) — operator sees a COUNT of skipped region
# lines. ``_parse_declared_regions`` returns ``(regions, skipped)``;
# ``on_button_pressed`` surfaces the count via ``self.notify`` when skipped>=1
# (count-only, carry C-P3b) and stays silent when skipped==0.
# ---------------------------------------------------------------------------
#
# Coverage map (test -> AT/TC -> LLR):
# - AT-029a (test_skipped_malformed_line_counted): wrong-arity line ⇒ notify
#   carries the standalone token ``1``; the valid region still flows.
# - AT-029b (test_skipped_invalid_line_counted): start>end line ⇒ notify ``1``.
# - AT-029c (test_skipped_count_excludes_blank): valid+malformed+blank+invalid
#   ⇒ notify count ``2`` (blank excluded), NOT 3.
# - AT-029d (test_all_valid_no_skip_message): all-valid AND empty input ⇒ NO
#   skip message (absence assertion).
# - TC-029.1 (test_parse_returns_skip_count): white-box parser return values.
# - TC-029.2 (test_zero_skip_suppresses_notify): white-box/seam zero-guard.


async def _generate_capturing_notices(
    app: S19TuiApp, pilot, region_text: str
) -> list[tuple[str, str]]:
    """Drive the operator path and return every ``notify`` raised by Generate.

    Opens Reports (real ``action_view_reports``), types ``region_text`` into
    the region TextArea, installs the ``_notices`` capture on ``app.notify``
    BEFORE pressing ``#report_generate`` (carry C-P3a — the Screen's
    ``self.notify`` delegates to ``app.notify``), then drains the worker.
    Returns the captured ``(title, message)`` list.
    """
    app.action_view_reports()
    await _flush(pilot)
    screen = app.screen_stack[-1]
    assert isinstance(screen, ReportViewerScreen)
    screen.query_one("#report_declared_regions", TextArea).text = region_text
    captured = _notices(app)  # install BEFORE the press (C-P3a)
    screen.query_one("#report_generate", Button).press()
    await _flush(pilot)
    await app.workers.wait_for_complete()
    await _flush(pilot)
    return captured


def _skip_messages(captured: list[tuple[str, str]]) -> list[str]:
    """Return the messages mentioning a skip (case-insensitive)."""
    return [msg for _title, msg in captured if "skip" in msg.lower()]


def test_skipped_malformed_line_counted(tmp_path: Path) -> None:
    """AT-029a — a wrong-arity line is surfaced as a count-of-1 notify.

    Intent (HLR-029 surface, malformed branch): the operator types one valid
    region plus one wrong-arity line, presses Generate; the notify channel
    carries a message whose count token is the standalone ``1`` (regex
    ``\\b1\\b``, qa minor-1 — guards against e.g. "0 of 1" passing). The valid
    region still flows to capture.
    """

    async def _drive() -> tuple[list[tuple[str, str]], tuple]:
        app = S19TuiApp(base_dir=tmp_path)
        _make_report_project(app, "proj")
        async with app.run_test() as pilot:
            await pilot.pause()
            app._handle_load_project("proj")
            await _flush(pilot)
            await app.workers.wait_for_complete()
            await _flush(pilot)
            captured = await _generate_capturing_notices(
                app, pilot, "good,0x1000,0x10FF\nbad line"
            )
            return captured, app._declared_regions

    captured, declared = asyncio.run(_drive())
    skips = _skip_messages(captured)
    assert skips, "AT-029a: a malformed line must surface a skip notify"
    assert any(re.search(r"\b1\b", msg) for msg in skips), (
        "AT-029a: the skip notify must report the standalone count 1; "
        f"messages were {skips!r}"
    )
    assert declared == (DeclaredRegion("good", 0x1000, 0x10FF),), (
        "AT-029a: the valid region must still flow despite the skipped line"
    )


def test_skipped_invalid_line_counted(tmp_path: Path) -> None:
    """AT-029b — a start>end line (invalid branch) is surfaced as count-of-1.

    Intent (HLR-029 surface, invalid branch): ``rev,0x20,0x10`` has start>end
    so ``DeclaredRegion`` raises ``ValueError`` → the invalid skip site fires.
    The notify must carry the standalone ``1``.
    """

    async def _drive() -> list[tuple[str, str]]:
        app = S19TuiApp(base_dir=tmp_path)
        _make_report_project(app, "proj")
        async with app.run_test() as pilot:
            await pilot.pause()
            app._handle_load_project("proj")
            await _flush(pilot)
            await app.workers.wait_for_complete()
            await _flush(pilot)
            return await _generate_capturing_notices(
                app, pilot, "good,0x1000,0x10FF\nrev,0x20,0x10"
            )

    skips = _skip_messages(asyncio.run(_drive()))
    assert skips, "AT-029b: an invalid line must surface a skip notify"
    assert any(re.search(r"\b1\b", msg) for msg in skips), (
        "AT-029b: the skip notify must report the standalone count 1; "
        f"messages were {skips!r}"
    )


def test_skipped_count_excludes_blank(tmp_path: Path) -> None:
    """AT-029c — blank lines are NOT counted; one malformed + one invalid ⇒ 2.

    Intent (HLR-029 blank-exclusion boundary): input = valid + malformed +
    blank + invalid. The blank is intentional spacing and must NOT count, so
    the notify reports the standalone ``2`` (regex ``\\b2\\b``), NOT 3.
    """

    async def _drive() -> list[tuple[str, str]]:
        app = S19TuiApp(base_dir=tmp_path)
        _make_report_project(app, "proj")
        async with app.run_test() as pilot:
            await pilot.pause()
            app._handle_load_project("proj")
            await _flush(pilot)
            await app.workers.wait_for_complete()
            await _flush(pilot)
            return await _generate_capturing_notices(
                app, pilot, "good,0x1000,0x10FF\nbad line\n\nrev,0x20,0x10"
            )

    skips = _skip_messages(asyncio.run(_drive()))
    assert skips, "AT-029c: malformed+invalid lines must surface a skip notify"
    assert any(re.search(r"\b2\b", msg) for msg in skips), (
        "AT-029c: the count must be 2 (blank excluded), not 3; "
        f"messages were {skips!r}"
    )
    assert not any(re.search(r"\b3\b", msg) for msg in skips), (
        "AT-029c: the blank line must NOT be counted (count 3 would be wrong); "
        f"messages were {skips!r}"
    )


def test_all_valid_no_skip_message(tmp_path: Path) -> None:
    """AT-029d (negative) — all-valid AND empty input emit NO skip message.

    Intent (HLR-029 clean case): two valid regions ⇒ no skip notify; and an
    empty TextArea ⇒ no skip notify. Asserts ABSENCE (no captured notice
    mentions "skip"), not a "0 skipped" message.
    """

    async def _drive(region_text: str) -> list[tuple[str, str]]:
        app = S19TuiApp(base_dir=tmp_path)
        _make_report_project(app, "proj")
        async with app.run_test() as pilot:
            await pilot.pause()
            app._handle_load_project("proj")
            await _flush(pilot)
            await app.workers.wait_for_complete()
            await _flush(pilot)
            return await _generate_capturing_notices(app, pilot, region_text)

    all_valid = asyncio.run(_drive("a,0x1000,0x10FF\nb,0x2000,0x20FF"))
    assert not _skip_messages(all_valid), (
        "AT-029d: all-valid input must NOT surface any skip message; "
        f"captured {all_valid!r}"
    )

    empty = asyncio.run(_drive(""))
    assert not _skip_messages(empty), (
        "AT-029d: empty input must NOT surface any skip message; "
        f"captured {empty!r}"
    )


def test_parse_returns_skip_count() -> None:
    """TC-029.1 — white-box: ``_parse_declared_regions`` returns (regions, skipped).

    Intent (LLR-029.1): malformed (wrong-arity) and invalid (start>end) lines
    each increment ``skipped``; blank lines do not; all-valid ⇒ 0. Asserts the
    tuple values directly.
    """
    # Malformed only.
    regions, skipped = _parse_declared_regions("good,0x1000,0x10FF\nbad line")
    assert regions == (DeclaredRegion("good", 0x1000, 0x10FF),)
    assert skipped == 1, "TC-029.1: a wrong-arity line must be counted"

    # Invalid only (start>end).
    regions, skipped = _parse_declared_regions("good,0x1000,0x10FF\nrev,0x20,0x10")
    assert regions == (DeclaredRegion("good", 0x1000, 0x10FF),)
    assert skipped == 1, "TC-029.1: an invalid (start>end) line must be counted"

    # Blank lines are NOT counted.
    regions, skipped = _parse_declared_regions("good,0x1000,0x10FF\n\n\n")
    assert regions == (DeclaredRegion("good", 0x1000, 0x10FF),)
    assert skipped == 0, "TC-029.1: blank lines must NOT be counted"

    # All valid ⇒ 0.
    regions, skipped = _parse_declared_regions("a,0x1000,0x10FF\nb,0x2000,0x20FF")
    assert len(regions) == 2
    assert skipped == 0, "TC-029.1: all-valid input must yield skipped == 0"


def test_zero_skip_suppresses_notify(tmp_path: Path) -> None:
    """TC-029.2 — white-box/seam: skipped==0 ⇒ ``self.notify`` is NOT called.

    Intent (LLR-029.3 zero-suppression guard): pressing Generate on all-valid
    input must raise ZERO notify calls (the guard suppresses the count message
    when nothing was skipped) — asserts the capture list is empty.
    """

    async def _drive() -> list[tuple[str, str]]:
        app = S19TuiApp(base_dir=tmp_path)
        _make_report_project(app, "proj")
        async with app.run_test() as pilot:
            await pilot.pause()
            app._handle_load_project("proj")
            await _flush(pilot)
            await app.workers.wait_for_complete()
            await _flush(pilot)
            return await _generate_capturing_notices(
                app, pilot, "a,0x1000,0x10FF\nb,0x2000,0x20FF"
            )

    captured = asyncio.run(_drive())
    assert captured == [], (
        "TC-029.2: a clean (zero-skip) Generate must not call notify at all; "
        f"captured {captured!r}"
    )


# ---------------------------------------------------------------------------
# AT-055b — batch-35 Inc-0 byte-identity guard golden (LLR-055.3 / HLR-055)
# ---------------------------------------------------------------------------

#: Golden fixture for the batch-35 project-report byte-identity guard,
#: captured at the batch base revision ``79699a5`` by driving the shipped
#: Generate flow under the environment pin declared in
#: :func:`_drive_generate_report_bytes` (golden home:
#: ``tests/goldens/batch35/`` — canonical form, see
#: :func:`_canonical_report_bytes`).
_GOLDEN_DIR = Path(__file__).parent / "goldens" / "batch35"
_AT055B_GOLDEN = _GOLDEN_DIR / "at055b-project-report.md"

#: The LLR-055.3 fixed-clock environment-pin instant (UTC).
_FIXED_REPORT_INSTANT = datetime(2026, 7, 10, 12, 0, 0, tzinfo=timezone.utc)

#: Placeholder replacing every spelling of the per-run pytest tmp root
#: inside canonical report bytes.
_RUN_ROOT_TOKEN = b"<RUN-ROOT>"

#: A run-root path span: the token plus its path remainder, stopping at the
#: delimiters the report places around paths — separator normalization
#: applies ONLY inside these spans, never to report content.
_RUN_ROOT_SPAN = re.compile(rb"<RUN-ROOT>[^\s`\"'|)\]]*")


def _canonical_report_bytes(raw: bytes, run_root: Path | None = None) -> bytes:
    """
    Summary:
        Map report bytes to the canonical golden form of the LLR-055.3
        byte-identity pin: platform newline translation undone (CRLF -> LF,
        the ``Path.write_text`` seam — ``generate_project_report`` joins
        with ``"\\n"`` and lets the platform translate), every spelling of
        the per-run pytest tmp root replaced by ``<RUN-ROOT>``, and path
        separators normalized to ``/`` ONLY inside run-root path spans —
        content bytes are never rewritten. Twin of the AT-054b helper in
        ``tests/test_before_after_report.py`` (duplicated per file to keep
        the increment additive; no shared test util module exists).

    Args:
        raw (bytes): Report bytes as read from disk (a freshly written
            report, or a stored golden).
        run_root (Path | None): The per-run root whose spellings are
            tokenized; ``None`` for stored goldens (already tokenized at
            capture time — only the CRLF undo applies, shielding the golden
            from git working-tree newline translation).

    Returns:
        bytes: The canonical byte form compared by AT-055b.

    Data Flow:
        - written report bytes + ``tmp_path`` -> canonical bytes;
        - golden bytes (``run_root=None``) -> canonical bytes;
        - equality of the two IS the LLR-055.3 byte-identity gate (raw
          bytes cannot be run/platform-stable: the Modifications section
          embeds the absolute run root in its change-doc/saved-as line).

    Dependencies:
        Uses:
            - _RUN_ROOT_TOKEN / _RUN_ROOT_SPAN
        Used by:
            - test_at_055b_no_filter_generate_report_byte_identical_to_golden
            - the batch-35 golden-capture procedure (increment-000)
    """
    data = raw.replace(b"\r\n", b"\n")
    if run_root is not None:
        forms = {str(run_root), str(run_root.resolve())}
        for form in sorted(forms, key=len, reverse=True):
            data = data.replace(form.encode("utf-8"), _RUN_ROOT_TOKEN)
    return _RUN_ROOT_SPAN.sub(
        lambda match: match.group(0).replace(b"\\", b"/"), data
    )


def _drive_generate_report_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> dict[str, bytes]:
    """
    Summary:
        Drive the SHIPPED project-report Generate flow (the AC-A1 seam:
        load the 2-variant project, open Reports, press the real
        ``#report_generate`` button, drain the worker) under the LLR-055.3
        environment pin and return the written report files' raw bytes
        keyed by filename.

    Args:
        tmp_path (Path): Per-test root (app ``base_dir``); the project lives
            at ``.s19tool/workarea/proj`` beneath it.
        monkeypatch (pytest.MonkeyPatch): Applies the environment pin on the
            SERVICE module attribute (auto-undone per test):
            ``report_service._default_now`` — the default-clock seam
            ``generate_project_report`` resolves when the worker passes no
            ``now_fn`` (the shipped worker passes none).

    Returns:
        dict[str, bytes]: ``{filename: raw bytes}`` for every file under
        ``<project>/reports/`` after the Generate press.

    Data Flow:
        - pin clock -> pilot drive (project load -> Generate through the
          real screen control -> worker completes) -> the real
          ``generate_project_report`` writes the report -> raw bytes read
          back from disk for the golden comparison.

    Dependencies:
        Uses:
            - _make_report_project / _generate_through_surface / _flush
            - _FIXED_REPORT_INSTANT
        Used by:
            - test_at_055b_no_filter_generate_report_byte_identical_to_golden
            - the batch-35 golden-capture procedure (increment-000)
    """
    import s19_app.tui.services.report_service as report_service_module

    monkeypatch.setattr(
        report_service_module, "_default_now", lambda: _FIXED_REPORT_INSTANT
    )

    async def _drive() -> dict[str, bytes]:
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
            reports_dir = project_dir / "reports"
            return {
                p.name: p.read_bytes()
                for p in reports_dir.iterdir()
                if p.is_file()
            }

    return asyncio.run(_drive())


def test_at_055b_no_filter_generate_report_byte_identical_to_golden(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AT-055b / LLR-055.3 (HLR-055): with NO filter selected, the shipped
    Generate flow writes a project report byte-identical to the golden
    captured at the batch base revision ``79699a5`` under the declared
    environment pin.

    Intent: the batch-35 guard golden — every later increment must keep the
    unfiltered project-report output byte-for-byte untouched; any generator
    byte drift flips this equality RED.

    Environment pin (test-side monkeypatch on the SERVICE module attribute,
    never a shipped-path change):
    - ``s19_app.tui.services.report_service._default_now`` -> fixed
      2026-07-10T12:00:00Z — the ``NowFn`` default-clock seam
      (``report_service.py:125-140``) ``generate_project_report`` resolves
      when no ``now_fn`` is passed (the shipped worker passes none).
    Comparison runs on :func:`_canonical_report_bytes` (CRLF undo +
    per-run tmp-root tokenization); all other bytes are compared exact.
    Golden: ``tests/goldens/batch35/at055b-project-report.md``.
    Double-proof (batch-24 control): a one-byte golden perturbation makes
    this AT RED — captured in increment-000.md.
    """
    written = _drive_generate_report_bytes(tmp_path, monkeypatch)

    report_name = "20260710T120000Z-report.md"
    assert sorted(written) == [report_name], (
        f"AT-055b: expected exactly the pinned-clock report file, "
        f"got {sorted(written)}"
    )
    assert _AT055B_GOLDEN.is_file(), (
        f"AT-055b: golden fixture missing: {_AT055B_GOLDEN} (captured in "
        f"batch-35 increment-000 at base revision 79699a5)"
    )
    observed = _canonical_report_bytes(written[report_name], tmp_path)
    golden = _canonical_report_bytes(_AT055B_GOLDEN.read_bytes())
    assert observed == golden, (
        f"AT-055b: unfiltered project-report bytes drifted from golden "
        f"{_AT055B_GOLDEN.name} (LLR-055.3 byte-identity, canonical form)"
    )
