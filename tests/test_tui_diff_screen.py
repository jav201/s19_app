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

batch-78 Inc-1 (HLR-125 — the control rows do not starve the result area):

    test_at_b78_33_compaction_enlarges_the_result_area   AT-B78-33 / TC-B78-35
                                                        LLR-125.1, LLR-125.2
    test_tc_b78_34_control_rows_are_one_row_at_80x24     TC-B78-34  LLR-125.1
    test_tc_b78_36_long_external_path_does_not_reexpand  TC-B78-36  LLR-125.1
    test_tc_b78_37_selects_survive_compaction_no_project TC-B78-37  LLR-125.1

The placeholder-supersession tests (the rewritten TC-027 family + the TC-028
activation test) live in ``tests/test_tui_directionb.py`` next to the rest of
the Direction B scaffold suite; this file holds the NEW HLR-005 behavior.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from s19_app.tui.app import S19TuiApp

# --------------------------------------------------------------------------
# batch-78 Inc-1 — shared geometry harness for HLR-125
# --------------------------------------------------------------------------

#: Inc-0's committed pre-change freeze. `AT-B78-33` is an INVARIANCE-BREAKING
#: claim ("compaction strictly enlarges the result area"), so its baseline must
#: come from a capture taken BEFORE any production edit — never from an inline
#: literal (spec Sec.5.1 rule 10) and never from the live producer, which after
#: this increment can only report the post-change number. The pre-change height
#: is unrecoverable once `styles.tcss` is edited; that is why Inc-0 froze it.
_B78_GOLDEN_DIR = Path(__file__).resolve().parent / "goldens" / "batch78"
_B78_DIFF_HEIGHT_ARTIFACT = _B78_GOLDEN_DIR / "at-b78-33-diff-hex-a-height.json"

#: The three control rows HLR-125 compacts, plus the two surfaces they starve.
_B78_CONTROL_ROWS = ("#diff_select_row_a", "#diff_select_row_b", "#diff_action_row")
_B78_RESULT_SURFACES = ("#diff_status", "#diff_columns", "#diff_hex_a")


def _b78_diff_height_baseline() -> dict:
    """Read the Inc-0 pre-change geometry artifact from disk.

    Deliberately has no fallback: if the artifact is missing the consuming test
    must go RED, not silently substitute a producer-derived number. That
    substitution is exactly the defect (BL-1) that made ``AT-B78-03`` inert.
    """
    assert _B78_DIFF_HEIGHT_ARTIFACT.is_file(), (
        f"the Inc-0 pre-change artifact is missing at {_B78_DIFF_HEIGHT_ARTIFACT}; "
        "AT-B78-33 has no other oracle - the pre-change height cannot be "
        "re-measured once styles.tcss is edited"
    )
    return json.loads(_B78_DIFF_HEIGHT_ARTIFACT.read_text(encoding="utf-8"))


def _b78_painted_content_height(widget) -> int:
    """Rows of this widget's OWN CONTENT that actually reach the screen.

    Two corrections over the metric spec Sec.5.1 rule 1 prescribes
    (``widget.region.intersection(screen_host.region)``), both measured on this
    branch rather than reasoned about:

    1. **It does not clip through intermediate ancestors.** A widget nested
       below the screen host is clipped by every container between them, not
       just by the host. Executed at 120x30 on the compacted tree, the
       prescribed form reads ``#diff_columns`` 3 and its own child
       ``#diff_hex_a`` **4** - a child cannot paint more rows than its parent,
       so 4 is not a painted count of anything. Intersecting through the full
       ancestor chain reads 3.

    2. **It measures the BORDER box, so it counts chrome as content.** Each
       ``#diff_*`` result box spends 4 rows on border and padding. At 120x30
       ``#diff_hex_a`` has a content height of **0** - not one hex row reaches
       the operator - while the ancestor-corrected border box still reads 3,
       because three rows of BORDER are painted. Clipping the
       ``content_region`` reads **0**, which is what LLR-125.2's "shall render
       at least one hex row of content" is actually about.

    Both layers stay available to callers: ``size.height`` is the height the
    layout gave the content, and this is how much of it survives clipping. They
    differ exactly where the C-32 trap lives - at 80x24 ``#diff_status`` has
    ``size.height`` 1 and a painted content height of 0.

    Reported as a requirements finding (carry C-78-vi), not silently absorbed:
    Sec.5.1 rule 1's wording needs amending, and ``AT-B78-26``'s 120x30
    ">= 1 hex row" clause at Inc-10 lands on exactly this coordinate.
    """
    from textual.widget import Widget

    region = widget.content_region
    node = widget.parent
    while isinstance(node, Widget):
        region = region.intersection(node.region)
        node = node.parent
    return region.height


def _b78_diff_geometry(
    base_dir: Path,
    size: tuple[int, int],
    *,
    prepare=None,
) -> dict[str, tuple[int, int]]:
    """Measure the diff panel's widgets at BOTH layers (C-32/C-37).

    Returns ``{selector: (content_height, painted_content_height)}``. See
    ``_b78_painted_content_height`` for why the second element is NOT the
    metric spec Sec.5.1 rule 1 prescribes.

    ``prepare`` is an optional ``async (app, pilot) -> None`` hook run after the
    diff screen is active and before the measurement.
    """
    selectors = _B78_CONTROL_ROWS + _B78_RESULT_SURFACES

    async def _drive() -> dict[str, tuple[int, int]]:
        app = S19TuiApp(base_dir=base_dir)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            app.action_show_screen("diff")
            await pilot.pause()
            if prepare is not None:
                await prepare(app, pilot)
                await pilot.pause()
            measured = {}
            for selector in selectors:
                widget = app.query_one(selector)
                measured[selector] = (
                    widget.size.height,
                    _b78_painted_content_height(widget),
                )
            return measured

    return asyncio.run(_drive())


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
            # batch-68 N5: the two generators now run on a worker thread, so
            # the status is written after this handler returns. A bare pause()
            # passed only because the fake generators are instant — a race this
            # suite must not depend on.
            await app.workers.wait_for_complete()
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
            # batch-68 N5: the two generators now run on a worker thread, so
            # the status is written after this handler returns. A bare pause()
            # passed only because the fake generators are instant — a race this
            # suite must not depend on.
            await app.workers.wait_for_complete()
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


# --------------------------------------------------------------------------
# batch-78 Inc-1 - HLR-125: the control rows do not starve the result area
# --------------------------------------------------------------------------


def test_at_b78_33_compaction_enlarges_the_result_area(tmp_path: Path) -> None:
    """AT-B78-33 / TC-B78-35 - compaction actually gives rows to the results.

    Intent (WHY this is a gate and the row-height clause alone is not): an
    implementation that shrinks the three control rows to one line each and
    leaves the result area at zero satisfies every "height == 1" predicate and
    delivers NOTHING to the operator - that is the precise state LLR-125.2
    exists to forbid. So the load-bearing clause here is the strict INCREASE of
    ``#diff_hex_a``'s content height against Inc-0's frozen pre-change capture,
    and the three 1-row clauses ride in the SAME run so neither half can be
    green while the other is false.

    132x44 is the size at which this is observable with no Lane-1 work: the
    result area already has content rows there today, so compaction alone moves
    a number that is not zero on either side of the change.

    The threshold is read from disk. An inline literal would be a C-36 phantom
    the moment anything upstream of the panel's row budget moves, and - worse -
    the pre-change value can never be re-measured after this increment edits
    ``styles.tcss``.
    """
    baseline = _b78_diff_height_baseline()

    # The artifact must be about the widget and the terminal this test drives;
    # otherwise "greater than baseline" compares two different layouts (Inc-0
    # captured three artifacts at three different sizes).
    assert baseline["widget"] == "#diff_hex_a", (
        "the Inc-0 artifact describes a different widget than AT-B78-33 observes"
    )
    size = tuple(baseline["terminal"])
    assert len(size) == 2, "the artifact's terminal must be a (width, height) pair"

    geometry = _b78_diff_geometry(tmp_path, size)
    observed_content, observed_painted = geometry["#diff_hex_a"]

    # The gate, asserted on the PAINTED content layer.
    #
    # `baseline["clipped_height"]` (11) is deliberately NOT used. Inc-0 captured
    # it with the metric spec Sec.5.1 rule 1 prescribes, which this module no
    # longer uses because it is wrong twice over (see
    # `_b78_painted_content_height`): 11 is a border-box figure that counts this
    # widget's 4 rows of chrome, and comparing a corrected observation against
    # it would compare two different quantities and call the difference a gain.
    # `content_height` IS metric-independent - it is `widget.size.height` - so
    # the pre-change 7 is a sound baseline for both clauses below.
    assert observed_content > baseline["content_height"], (
        f"compaction must give the freed rows to the result area: "
        f"#diff_hex_a content height {observed_content} is not greater than the "
        f"pre-change {baseline['content_height']} captured at {size} by Inc-0"
    )
    assert observed_painted > baseline["content_height"], (
        f"the gained rows must actually be PAINTED, not merely laid out: "
        f"#diff_hex_a painted content height {observed_painted} is not greater "
        f"than the pre-change content height {baseline['content_height']}. This "
        f"is the strictly stronger clause - painted <= content always, so a "
        f"layout that grows while the operator still sees nothing fails here "
        f"and passes the clause above"
    )
    assert observed_painted == observed_content, (
        f"at {size} nothing should clip the result area: painted "
        f"{observed_painted} != content {observed_content}"
    )

    # Same run, per the increment's gate: the three control rows each occupy one
    # painted row and the status line is visible.
    for row_id in _B78_CONTROL_ROWS:
        assert geometry[row_id][1] == 1, (
            f"{row_id} must paint exactly one row at {size}, measured "
            f"{geometry[row_id][1]}"
        )
    assert geometry["#diff_status"][1] >= 1, (
        f"the panel status line must be visible at {size}, measured "
        f"{geometry['#diff_status'][1]}"
    )

    # Non-vacuity: the increase must be an increase in a result area that is
    # actually painted, not in a box whose region grew while it paints nothing.
    assert geometry["#diff_columns"][1] >= 3, (
        f"the results row must paint at {size}, measured "
        f"{geometry['#diff_columns'][1]}"
    )


def test_tc_b78_34_control_rows_are_one_row_at_80x24(tmp_path: Path) -> None:
    """TC-B78-34 - the 1-row clause holds at the narrowest supported regime.

    Intent: 80x24 is where the overflow is worst and where the shipped panel
    degrades most dishonestly - measured on the pre-change tree the action row
    paints ZERO rows, so the operator loses the Compare button itself rather
    than merely losing results. The 1-row requirement is not a 120x30
    convenience; it must hold at the smallest regime the snapshot matrix
    supports.

    Scope note, stated rather than implied: this node asserts ONLY the row
    clause. At 80x24 the panel's whole content budget is 5 rows and the three
    compacted rows plus their separators already spend 6, so ``#diff_status``
    and ``#diff_columns`` still paint zero here. Making that case honest is
    HLR-124's notice regime, built at Inc-5 - it is deliberately NOT asserted
    here, because a node that pins today's zero would false-fail Inc-5.
    """
    geometry = _b78_diff_geometry(tmp_path, (80, 24))

    for row_id in _B78_CONTROL_ROWS:
        assert geometry[row_id][1] == 1, (
            f"{row_id} must paint exactly one row at 80x24, measured "
            f"{geometry[row_id][1]} (pre-change: 3 / 2 / 0 respectively)"
        )


def test_tc_b78_36_long_external_path_does_not_reexpand(tmp_path: Path) -> None:
    """TC-B78-36 - a long external path does not win the row back. **PIN.**

    Intent: the compacted rows hold a free-text path input. If the row's height
    were content-derived, a path longer than the pane would wrap and silently
    restore the three-row starvation this increment removes - and it would do so
    only for operators who actually use external images, i.e. exactly the ones
    the diff panel exists for.

    Labelled a PIN rather than a gate, measured not assumed. Executed at Inc-1:
    substituting `#diff_path_a/_b/_report_dest`'s `height` VALUE `1` -> `3`
    while the row keeps `height: 1` leaves this node GREEN, because an explicit
    row height clips the child rather than growing with it. The only mutation
    that reddens it is one that also reverts the row height, which is
    `AT-B78-33`'s subject, not this one. So this node cannot fail for a reason
    peculiar to path length; it guards against a future implementation that
    makes the row's height content-derived again. Recorded here so a later
    reader meets the limit as a stated property rather than mistaking a green
    tick for evidence about long paths.
    """
    size = (132, 44)
    long_path = "/" + "/".join(f"very_long_directory_segment_{i:03d}" for i in range(12))

    async def _fill(app, pilot) -> None:
        app.query_one("#diff_path_a").value = long_path

    geometry = _b78_diff_geometry(tmp_path, size, prepare=_fill)

    # Applied-check: a value that never landed, or one that fits, would make the
    # assertion below true for the wrong reason. The width comes from the size
    # this run actually drove, not a second copy of the number.
    assert len(long_path) > size[0], (
        "the fixture path must exceed the terminal width or this node proves "
        f"nothing: {len(long_path)} <= {size[0]}"
    )
    assert geometry["#diff_select_row_a"][1] == 1, (
        "a long external path must not re-expand the A selection row, measured "
        f"{geometry['#diff_select_row_a'][1]}"
    )
    assert geometry["#diff_hex_a"][1] > 0, (
        "the result area must still paint while the long path is in the input"
    )


def test_tc_b78_37_selects_survive_compaction_no_project(tmp_path: Path) -> None:
    """TC-B78-37 - with no project loaded the variant dropdowns still work.

    Two clauses of different kinds, labelled so neither is mistaken for the
    other. The row-height clause is a GATE (red on the pre-change tree: the row
    paints 3). The dropdown-survival clauses are PINs - green before and after
    the change - and their mutation is discharged and DISCRIMINATING:
    substituting `display: none` onto `#diff_select_a/_b` reddens this node
    alone (1 failed / 3 passed) while leaving `AT-B78-33` green, which is the
    whole point. Compaction that deletes the control passes every height
    predicate in this file except this one.

    Intent, and this is the discriminating half: the cheapest way to buy two
    rows back is to stop rendering the ``Select`` widgets altogether. That
    passes every height predicate and removes the only affordance for choosing
    an in-project variant. This node asserts the dropdown is still mounted, is
    still displayed, still holds the external-path sentinel, and still OPENS -
    an overlay clipped away by a one-row parent would be a compaction that
    reports success and delivers an unusable control.

    **The glyph clause generalises that hazard to every compacted child.**
    Height predicates measure the row; they say nothing about what the row's one
    painted line CONTAINS. Executed on this branch: restore ``border: tall`` to
    the two Buttons and ``#diff_compare_button`` becomes ``y=12 h=2`` inside a
    ``height: 1`` row with ``size.height`` **0** - its first line is blank
    chrome and the word ``Compare`` lands on the clipped second row. Every
    height assertion in this file stays GREEN. So each compacted child's first
    painted line must carry its own declared text, and the expected text is read
    FROM THE WIDGET (``Button.label`` / ``Input.placeholder`` / the Label's
    rendered content) rather than from a hand-written list that can drift.

    ``#diff_select_a/_b`` are excluded from the glyph clause with cause, not by
    omission: they lay out at a content width of ONE column, so no glyph fits.
    That is a pre-existing defect (measured identical on the pre-change tree,
    carry C-78-iv) and it is out of HLR-125's vertical-budget scope. Their
    survival is covered by the display / option-set / overlay clauses above.
    """
    from textual.widgets._select import SelectOverlay

    from s19_app.tui.screens_directionb import AbDiffPanel

    #: Compacted children excluded from the glyph clause, and why. Named so the
    #: exclusion is auditable rather than an absence.
    glyph_exempt = {"#diff_select_a", "#diff_select_b"}

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(132, 44)) as pilot:
            await pilot.pause()
            app.action_show_screen("diff")
            await pilot.pause()
            select = app.query_one("#diff_select_a")
            overlay = select.query_one(SelectOverlay)

            # Sample the screen with the dropdown CLOSED, and only then open it.
            # The expanded overlay is drawn on the screen layer and covers the
            # rows below it - measured here: with A's dropdown open, the
            # overlay paints over columns 29-31 of row B and `#diff_path_b`
            # reads '▎ternal path B'. Sampling the composited screen means
            # sampling it in the state the clause is about.
            #
            # Every child of the three compacted rows, with the text the widget
            # itself declares and what the COMPOSITED SCREEN actually shows in
            # the row's one painted line, over that child's column span.
            #
            # Read off the compositor, not `child.render_line(0)`. Measured on
            # this branch: with `.diff-field-label` reverted to `padding: 1 1 0 1`
            # the widget's own `render_line(0)` still returns 'A' while the
            # screen at that coordinate is blank, because `render_line` indexes
            # the widget's rendered lines and not its position on screen. A
            # predicate on it is green for a control the operator cannot read -
            # the same layer confusion as C-32, one level down.
            strips = app.screen._compositor.render_strips()
            glyphs = []
            for row_id in _B78_CONTROL_ROWS:
                row = app.query_one(row_id)
                row_line = strips[row.region.y]
                for child in row.children:
                    name = f"#{child.id}" if child.id else f"{type(child).__name__}"
                    if name in glyph_exempt:
                        continue
                    declared = getattr(child, "label", None)
                    if declared is None:
                        declared = getattr(child, "placeholder", None)
                    if not declared:
                        declared = str(child.render())
                    span = child.region
                    painted = "".join(
                        seg.text
                        for seg in row_line.crop(span.x, span.x + span.width)
                    )
                    glyphs.append(
                        (name, str(declared), painted, child.size.width,
                         child.size.height)
                    )

            select.expanded = True
            await pilot.pause()

            return (
                select.display,
                overlay.display,
                overlay.option_count,
                str(overlay.get_option_at_index(0).prompt),
                str(select.value),
                _b78_painted_content_height(app.query_one("#diff_select_row_a")),
                glyphs,
            )

    (
        select_shown,
        overlay_shown,
        option_count,
        first_prompt,
        value,
        row_height,
        glyphs,
    ) = asyncio.run(_drive())

    assert select_shown, (
        "compaction must not hide the A variant dropdown - that would buy rows "
        "by deleting the only in-project variant affordance"
    )
    assert row_height == 1, (
        f"the A selection row must still paint one row, measured {row_height}"
    )
    assert value == AbDiffPanel._EXTERNAL_OPTION, (
        "with no project loaded the dropdown must hold the external-path sentinel"
    )
    assert option_count == 1 and "external path" in first_prompt, (
        f"the no-project option set must be the sentinel alone, got "
        f"{option_count} option(s), first={first_prompt!r}"
    )
    assert overlay_shown, (
        "the dropdown must still open under a one-row parent; an overlay the "
        "compacted row clips away is an unusable control that passes every "
        "height predicate"
    )

    # C-40: the sweep must have found children, or "every child paints its
    # glyph" is vacuously true over an empty set.
    assert len(glyphs) >= 6, (
        f"the compacted-child sweep found only {len(glyphs)} children across "
        f"{_B78_CONTROL_ROWS}; the glyph clause below would be near-vacuous"
    )

    for name, declared, painted, width, height in glyphs:
        assert height >= 1, (
            f"{name} has a content height of {height} inside a one-row row - its "
            f"chrome has eaten the line the operator sees"
        )
        expected = declared[: max(width, 1)]
        assert expected and expected in painted, (
            f"the row's one painted line must show {name}'s own text, not its "
            f"chrome: expected {expected!r} (the widget's declared {declared!r} "
            f"truncated to its {width}-column content width) but the screen at "
            f"that span reads {painted!r}"
        )
