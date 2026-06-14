"""A↔B Diff screen tests — s19_app batch-09, increment I4 (HLR-005).

Completes the A↔B Diff rail screen (``AbDiffPanel``): inline image-pair
selection (G-6), service-routed comparison + report (LLR-005.1), Rich-coloured
run render with per-image artifact-usage notes (LLR-005.2), the relocated
display caps (G-9 / LLR-005.2), failure surfacing (LLR-005.3) and report-trigger
feedback (LLR-005.4).

Test -> TC -> LLR map:
    test_tc021_compare_routes_through_service        TC-021  LLR-005.1
    test_tc022_render_shows_runs_and_hex_windows     TC-022  LLR-005.2
    test_tc023_refused_compare_surfaces_diagnostic   TC-023  LLR-005.3
    test_tc024_report_trigger_surfaces_paths         TC-024  LLR-005.4
    test_tc024_report_trigger_invalid_dest_refused   TC-024  LLR-005.4
    test_tc029_display_caps_bound_on_screen_runs     TC-029  LLR-005.2 (G-9)

The placeholder-supersession tests (the rewritten TC-027 family + the TC-028
activation test) live in ``tests/test_tui_directionb.py`` next to the rest of
the Direction B scaffold suite; this file holds the NEW HLR-005 behavior.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from s19_app.tui.app import S19TuiApp


def _diff_result(runs_kinds, *, refused=False, diagnostics=None):
    """Build a fake ComparisonResult for the view-layer tests.

    runs_kinds: list of (start, end, kind). The maps are synthetic and only
    used for the panel's hex windows (display-only).
    """
    from s19_app.compare import (
        ComparisonResult,
        DiffRun,
        DiffStats,
        ImageRef,
    )
    from s19_app.tui.services.compare_service import ArtifactNote, ArtifactUsage

    runs = [DiffRun(start, end, kind) for start, end, kind in runs_kinds]
    stats = DiffStats(
        run_counts={"changed": 0, "only_a": 0, "only_b": 0},
        byte_counts={"changed": 0, "only_a": 0, "only_b": 0},
    )
    usage = ArtifactUsage(
        a2l=ArtifactNote(status="absent"),
        mac=ArtifactNote(status="absent"),
        summary="none",
    )
    return ComparisonResult(
        image_a=ImageRef(label="A.s19", path=None, source_kind="external"),
        image_b=ImageRef(label="B.s19", path=None, source_kind="external"),
        runs=runs,
        stats=stats,
        notes={"image_a": usage, "image_b": usage},
        diagnostics=list(diagnostics or []),
        refused=refused,
    )


def test_tc021_compare_routes_through_service(tmp_path: Path) -> None:
    """A compare request invokes the service entry point exactly once (LLR-005.1).

    Intent: the app obtains the comparison result EXCLUSIVELY by calling
    ``compare_service.compare_images`` — never by classifying runs itself. A
    spy substituted for the app-imported entry point is invoked exactly once
    per request, and the rendered output reflects its injected result.
    """
    import s19_app.tui.app as app_mod

    calls: list[int] = []
    fake = _diff_result([(0x10, 0x14, "changed")])

    def _spy(*_args, **_kwargs):
        calls.append(1)
        return fake

    async def _drive() -> tuple[int, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("diff")
            await pilot.pause()
            app.query_one("#diff_compare_button").press()
            await pilot.pause()
            range_text = str(app.query_one("#diff_range_list").render())
            return len(calls), range_text

    monkey = pytest.MonkeyPatch()
    monkey.setattr(app_mod, "compare_images", _spy)
    try:
        n_calls, range_text = asyncio.run(_drive())
    finally:
        monkey.undo()

    assert n_calls == 1, "compare_images must be invoked exactly once per request"
    assert "Runs: 1" in range_text, (
        "the rendered run list must reflect the injected service result"
    )


def test_tc022_render_shows_runs_and_hex_windows(tmp_path: Path) -> None:
    """A completed comparison renders the run list + per-run hex windows (LLR-005.2).

    Intent: the range-list column shows the classified runs (Rich-coloured per
    kind) and the hex-A / hex-B columns show bounded hex windows of the first
    run for each image. The static placeholder is gone.
    """

    async def _drive() -> tuple[str, str, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("diff")
            await pilot.pause()
            panel = app.query_one("#ab_diff_panel")
            panel.render_comparison(
                [(0x10, 0x14, "changed"), (0x20, 0x24, "only_a")],
                {0x10: 0xAA, 0x11: 0xBB, 0x12: 0xCC, 0x13: 0xDD},
                {0x10: 0x01, 0x11: 0x02, 0x12: 0x03, 0x13: 0x04},
                "both",
                "none",
            )
            await pilot.pause()
            return (
                str(app.query_one("#diff_range_list").render()),
                str(app.query_one("#diff_hex_a").render()),
                str(app.query_one("#diff_hex_b").render()),
            )

    range_text, hex_a, hex_b = asyncio.run(_drive())
    assert "Runs: 2" in range_text
    assert "changed" in range_text and "only A" in range_text
    assert "A artifacts: both" in range_text
    # Hex windows show the run's bytes for each image (distinct content).
    assert "AA BB CC DD" in hex_a
    assert "01 02 03 04" in hex_b


def test_tc023_refused_compare_surfaces_diagnostic(tmp_path: Path) -> None:
    """A refused comparison surfaces its diagnostic and keeps running (LLR-005.3).

    Intent: when the service refuses (unresolvable path / parse failure / <2
    valid images), the panel status carries the diagnostic, no exception
    propagates, and the screen keeps running with its result columns intact.
    """
    import s19_app.tui.app as app_mod

    refused = _diff_result([], refused=True, diagnostics=["Could not resolve X"])

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("diff")
            await pilot.pause()
            app.query_one("#diff_compare_button").press()
            await pilot.pause()
            return str(app.query_one("#diff_status").render())

    monkey = pytest.MonkeyPatch()
    monkey.setattr(app_mod, "compare_images", lambda *a, **k: refused)
    try:
        status = asyncio.run(_drive())
    finally:
        monkey.undo()

    assert "Could not resolve X" in status, (
        "the refusal diagnostic must surface in the panel status line"
    )
    assert "refused" in status.lower()


def test_tc024_report_trigger_surfaces_paths(tmp_path: Path) -> None:
    """A successful report trigger surfaces both written paths (LLR-005.4).

    Intent: after a comparison, the Report button generates BOTH the Markdown
    and HTML reports via the diff-report service and the status line shows a
    filename matching each regex.
    """
    import s19_app.tui.app as app_mod
    from s19_app.tui.services.diff_report_service import (
        DIFF_REPORT_FILENAME_REGEX,
        DIFF_REPORT_HTML_FILENAME_REGEX,
        DiffReportResult,
    )

    fake = _diff_result([(0x10, 0x14, "changed")])
    md_path = tmp_path / "20260101T000000Z-diff-report.md"
    html_path = tmp_path / "20260101T000000Z-diff-report.html"

    def _gen_md(*_a, **_k):
        md_path.write_text("md", encoding="utf-8")
        return DiffReportResult(path=md_path, written=True)

    def _gen_html(*_a, **_k):
        html_path.write_text("html", encoding="utf-8")
        return DiffReportResult(path=html_path, written=True)

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("diff")
            await pilot.pause()
            app.query_one("#diff_compare_button").press()
            await pilot.pause()
            app.query_one("#diff_report_button").press()
            await pilot.pause()
            return str(app.query_one("#diff_status").render())

    monkey = pytest.MonkeyPatch()
    monkey.setattr(app_mod, "compare_images", lambda *a, **k: fake)
    monkey.setattr(app_mod, "generate_diff_report", _gen_md)
    monkey.setattr(app_mod, "generate_diff_report_html", _gen_html)
    try:
        status = asyncio.run(_drive())
    finally:
        monkey.undo()

    assert DIFF_REPORT_FILENAME_REGEX.search(md_path.name)
    assert DIFF_REPORT_HTML_FILENAME_REGEX.search(html_path.name)
    assert md_path.name in status and html_path.name in status, (
        f"the status must show both written report paths; status was {status!r}"
    )


def test_tc024_report_trigger_invalid_dest_refused(tmp_path: Path) -> None:
    """A refused report (invalid no-project dest) surfaces the diagnostic (LLR-005.4).

    Intent: the LLR-004.6 invalid-destination refusal writes 0 files and the
    status carries the diagnostic; the screen keeps running.
    """
    import s19_app.tui.app as app_mod
    from s19_app.tui.services.diff_report_service import DiffReportResult

    fake = _diff_result([(0x10, 0x14, "changed")])

    def _gen_refuse(*_a, **_k):
        return DiffReportResult(
            path=None, written=False, diagnostics=["bad destination"]
        )

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("diff")
            await pilot.pause()
            app.query_one("#diff_compare_button").press()
            await pilot.pause()
            app.query_one("#diff_report_button").press()
            await pilot.pause()
            return str(app.query_one("#diff_status").render())

    monkey = pytest.MonkeyPatch()
    monkey.setattr(app_mod, "compare_images", lambda *a, **k: fake)
    monkey.setattr(app_mod, "generate_diff_report", _gen_refuse)
    try:
        status = asyncio.run(_drive())
    finally:
        monkey.undo()

    assert "bad destination" in status
    assert "refused" in status.lower()


def test_tc029_display_caps_bound_on_screen_runs(tmp_path: Path) -> None:
    """The on-screen run list is bounded by the relocated display caps (LLR-005.2/G-9).

    Intent: an over-cap comparison shows a bounded display (<= DISPLAY_MAX_RUNS)
    while the persisted report files (I3) stay complete. The range list must
    show the COMPLETE count and a "showing N of M" notice.
    """
    from s19_app.tui.screens_directionb import AbDiffPanel

    over = AbDiffPanel.DISPLAY_MAX_RUNS + 50
    runs = [(i * 16, i * 16 + 4, "changed") for i in range(over)]

    async def _drive() -> tuple[int, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("diff")
            await pilot.pause()
            panel = app.query_one("#ab_diff_panel", AbDiffPanel)
            panel.render_comparison(runs, {}, {}, "none", "none")
            await pilot.pause()
            return len(panel._runs), str(app.query_one("#diff_range_list").render())

    n_displayed, range_text = asyncio.run(_drive())
    assert n_displayed <= AbDiffPanel.DISPLAY_MAX_RUNS, (
        "the on-screen run list must be bounded by DISPLAY_MAX_RUNS"
    )
    assert f"Runs: {over}" in range_text, (
        "the header must report the COMPLETE run count (the file stays complete)"
    )
    assert "showing" in range_text and "of" in range_text, (
        "the panel must note that the display is capped while the report is full"
    )
