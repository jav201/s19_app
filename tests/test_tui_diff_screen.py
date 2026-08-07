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


# --------------------------------------------------------------------------
# batch-78 Inc-2 — shared run-list harness for HLR-122
# --------------------------------------------------------------------------

#: The class the panel puts on a SELECTABLE run row, and the one it puts on the
#: non-selectable header / notice rows. Read from the DOM, never re-derived
#: from the panel's own run list, so a swap that renders context rows as
#: selectable entries fails the reachability ATs instead of passing them.
_B78_RUN_ENTRY = ".diff-run-entry"
_B78_RUN_NOTE = ".diff-run-note"

#: ``AT-B78-18``'s fixture size. Fixed INDEPENDENTLY of
#: ``AbDiffPanel.DISPLAY_MAX_RUNS``: a cap predicate whose fixture and
#: expectation both read the constant moves with it and certifies the constant
#: rather than the capping (spec F-6 / LLR-122.3). The constant appears in this
#: module only inside a guard, and that guard is evaluated AFTER the capture so
#: a mutation reddens an assertion instead of raising.
_B78_OVER_CAP_RUNS = 200


def _b78_run_list(app):
    """The ``#diff_range_list`` widget, resolved as the ``ListView`` it now is."""
    from textual.widgets import ListView

    return app.query_one("#diff_range_list", ListView)


def _b78_item_text(item) -> str:
    """The rendered text of one run-list row (its child ``Label``s)."""
    return " ".join(str(child.render()) for child in item.children)


def _b78_run_list_text(app) -> str:
    """The whole run-list column as text, one row per line.

    C-38 re-point: ``#diff_range_list`` was a ``Static``, so every consumer read
    ``str(widget.render())``. A ``ListView`` renders nothing of its own — its
    text lives in its ``ListItem`` children — so a consumer left on the old form
    silently observes an empty string and keeps passing on ``in`` assertions
    only by accident. Every reader in this module and in
    ``test_tui_diff_compare_realpath.py`` goes through this form instead.
    """
    from textual.widgets import ListItem

    return "\n".join(_b78_item_text(item) for item in _b78_run_list(app).query(ListItem))


def _b78_run_index(item) -> int | None:
    """The run index an entry stands for, taken from its shipped DOM id."""
    if item is None or item.id is None or not item.id.startswith("diff_run_"):
        return None
    return int(item.id[len("diff_run_") :])


async def _b78_press_compare(app, pilot) -> None:
    """Press the shipped Compare button and wait for the HANDLER to finish.

    Not a pause, and not padding (batch-78 Inc-2 gate review F7).
    ``Pilot.pause()`` waits for message-queue IDLENESS, and
    ``on_ab_diff_panel_compare_requested`` is now a coroutine that suspends on
    an awaited widget removal. A handler parked on ``AwaitRemove`` has already
    DEQUEUED its message, so the queue is idle while the handler is still
    running: ``pause()`` returns and the caller reads the un-rendered panel.

    Measured under a 20 ms suspension, that race broke **14 nodes** across the
    two diff modules. An extra ``pause()`` would not fix it — it absorbs 20 ms
    and 200 ms alike, so it buys margin, not determinism. This waits on
    ``app._diff_compare_generation``, which the handler bumps in a ``finally``
    on every exit path, so the wait is TOTAL: it also returns on the REFUSAL
    branch, where ``_diff_last_result`` is never written.

    ⚠️ This is also the C-40 presence co-assertion for every node built on it.
    The lost-race state is the UN-RENDERED panel, in which presence clauses
    fail loudly but **absence clauses pass vacuously** (``assert "showing" not
    in text`` is true of an empty column). Timing out here is a loud, named
    failure, so no node downstream can be green because nothing rendered.
    """
    before = app._diff_compare_generation
    app.query_one("#diff_compare_button").press()
    for _ in range(500):
        if app._diff_compare_generation > before:
            return
        await pilot.pause()
    raise AssertionError(
        "the compare handler never completed: _diff_compare_generation stayed "
        f"at {before} across 500 pumped turns. Every assertion after this "
        "point would be reading the UN-RENDERED panel, where absence clauses "
        "pass vacuously."
    )


def _b78_drive_compare(tmp_path: Path, size, result, *, after):
    """Drive a real Compare through the SHIPPED button, then run ``after``.

    ``compare_images`` is substituted at the app's import site so the run set is
    the test's own fixture, but everything downstream — the button press, the
    message, ``render_comparison``, the widget tree — is the shipped path. The
    ATs never call ``_render_run_list`` or ``_render_run_windows``.

    ``after`` is ``async (app, pilot) -> T`` and its return value is returned.
    """
    import s19_app.tui.app as app_mod

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            app.action_show_screen("diff")
            await pilot.pause()
            await _b78_press_compare(app, pilot)
            return await after(app, pilot)

    monkey = pytest.MonkeyPatch()
    monkey.setattr(app_mod, "compare_images", lambda *a, **k: result)
    try:
        return asyncio.run(_drive())
    finally:
        monkey.undo()


def _diff_result(runs_kinds, *, refused=False, diagnostics=None, summary="none"):
    """Build a fake ComparisonResult for the view-layer tests.

    runs_kinds: list of (start, end, kind). The maps are synthetic and only
    used for the panel's hex windows (display-only).

    ``summary`` is the per-image artifact-usage string the panel renders into
    the run-list header. It is a parameter (batch-78 Inc-2) so ``TC-B78-48``
    can drive a hostile value through the SHIPPED path rather than calling
    ``_render_run_list`` behind the app's back.
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
        summary=summary,
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
            await _b78_press_compare(app, pilot)
            range_text = _b78_run_list_text(app)
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
            await panel.render_comparison(
                [(0x10, 0x14, "changed"), (0x20, 0x24, "only_a")],
                {0x10: 0xAA, 0x11: 0xBB, 0x12: 0xCC, 0x13: 0xDD},
                {0x10: 0x01, 0x11: 0x02, 0x12: 0x03, 0x13: 0x04},
                "both",
                "none",
            )
            await pilot.pause()
            return (
                _b78_run_list_text(app),
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
            await _b78_press_compare(app, pilot)
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
            await _b78_press_compare(app, pilot)
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
            await _b78_press_compare(app, pilot)
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
    """The panel's STORED run list is bounded while the header stays complete
    (LLR-005.2 / G-9).

    Intent: an over-cap comparison must leave the panel holding strictly fewer
    runs than the comparison produced, while the header still names the
    complete count — the display is bounded, the report is not.

    REWRITTEN at batch-78 Inc-2 (spec Q-M2 / LLR-122.3), and the rewrite is the
    point of the node. The pre-batch body read ``DISPLAY_MAX_RUNS`` on BOTH
    sides — ``over = DISPLAY_MAX_RUNS + 50`` for the fixture and
    ``n_displayed <= DISPLAY_MAX_RUNS`` for the expectation — so the fixture and
    the expectation moved together and the node stayed GREEN under
    ``DISPLAY_MAX_RUNS 128 -> 100000``::

        PRE  cap=128    -> (assertion True, over=178,    stored=128)
        MUT  cap=100000 -> (assertion True, over=100050, stored=100000)  INERT
        POST cap=128    -> (assertion True, over=178,    stored=128)

    A cap predicate that takes its expected value from the class under test
    certifies the constant, not the capping. The fixture is now fixed at a
    literal independent of the constant and the expectation is the
    constant-free ``stored < total``, which the same mutation reddens.

    Subject split against ``AT-B78-18``, which lands in the same increment on
    the same clause: this node observes the panel's MODEL (``panel._runs`` and
    the header's complete count); ``AT-B78-18`` observes the VIEW (the count of
    selectable rows actually rendered, and the notice's own two numbers). An
    implementation that caps its model but paints every run passes this and
    fails that.
    """
    from s19_app.tui.screens_directionb import AbDiffPanel

    total = _B78_OVER_CAP_RUNS
    result = _diff_result([(i * 16, i * 16 + 4, "changed") for i in range(total)])

    async def _after(app, pilot):
        panel = app.query_one("#ab_diff_panel", AbDiffPanel)
        return len(panel._runs), _b78_run_list_text(app)

    n_stored, range_text = _b78_drive_compare(
        tmp_path, (120, 30), result, after=_after
    )

    # ORDER IS NORMATIVE (spec Q-m2, sharpened here by execution). The
    # substantive clauses come FIRST so the `DISPLAY_MAX_RUNS 128 -> 100000`
    # mutation reddens THEM. Executed with the guard placed first — as spec
    # Q-m2's wording ("evaluated after the capture") literally permits — this
    # node went red on `fixture (200) must exceed the display cap (100000)`,
    # which certifies only that the reader noticed the constant move. Failing
    # after the capture is not enough; the failure has to be the CLAUSE.
    assert n_stored < total, (
        f"the panel must store strictly fewer runs than the comparison "
        f"produced; stored {n_stored} of {total}"
    )
    assert f"Runs: {total}" in range_text, (
        "the header must report the COMPLETE run count (the file stays complete)"
    )
    assert "showing" in range_text and "of" in range_text, (
        "the panel must note that the display is capped while the report is full"
    )
    # C-39 applies to the GUARD, never to the expectation: nothing above reads
    # the constant. This trailing guard exists so a fixture that no longer
    # exceeds the cap is a loud, named failure rather than a quiet one.
    assert total > AbDiffPanel.DISPLAY_MAX_RUNS, (
        f"this node's fixture ({total} runs) must exceed the display cap "
        f"({AbDiffPanel.DISPLAY_MAX_RUNS}) or it tests nothing"
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


# --------------------------------------------------------------------------
# batch-78 Inc-2 - HLR-122: every displayed run is reachable, and visibly so
#
# Node map (spec Sec.3 HLR-122 / Sec.5.3 / Sec.7 Inc-2):
#   AT-B78-15  test_at_b78_15_every_run_reachable_by_keyboard          GATE
#   AT-B78-16  test_at_b78_16_every_run_reachable_by_mouse             GATE  (+TC-B78-20)
#   AT-B78-17  test_at_b78_17_exactly_one_entry_is_visibly_selected    GATE
#   AT-B78-18  test_at_b78_18_display_caps_and_notice_survive          PIN
#   AT-B78-19  test_at_b78_19_app_keys_survive_run_list_focus          see docstring
#   TC-B78-17  test_tc_b78_17_empty_comparison_has_no_selectable_entry
#   TC-B78-18  test_tc_b78_18_exactly_cap_runs_shows_no_notice
#   TC-B78-19  test_tc_b78_19_single_run_is_selectable
#   TC-B78-21  test_tc_b78_21_zero_length_run_is_selectable
#   TC-B78-22  test_tc_b78_22_keys_before_any_comparison_do_not_crash
#   TC-B78-47  test_tc_b78_47_arrows_at_the_ends_do_not_wrap
#   TC-B78-48  test_tc_b78_48_hostile_artifact_summary_renders_verbatim
#
# All of these run at 132x44. That is not a convenience: Inc-1 measured the
# diff result area at a CONTENT height of 0 at both 80x24 and 120x30 (the
# command-bar rows are still there until Inc-10), so at those sizes no run row
# is painted at all and a mouse or scroll acceptance would be unfalsifiable.
# 132x44 is the size at which HLR-122's observables exist today.
# --------------------------------------------------------------------------

_B78_AT_SIZE = (132, 44)


def _b78_focus_run_list(app, listing) -> None:
    """Put focus on the run list and ASSERT it took (spec LLR-122.2 / rule 5).

    The blur discipline runs in its mirror-image form: blur first and assert the
    blur, then focus the list and assert the focus. Both halves are load-bearing
    - executed on the pre-change tree, ``set_focus`` on the ``Static`` run list
    silently did NOT take (focus landed on ``RailItem(id='rail_item_workspace')``)
    and every key pressed afterwards was being pressed at the rail. A focus
    acceptance with no asserted precondition is green for a reason that has
    nothing to do with its subject.
    """
    app.set_focus(None)
    assert app.focused is None, (
        f"blur precondition: focus must be released before the list is focused, "
        f"but it is on {app.focused!r}"
    )
    app.set_focus(listing)
    assert app.focused is listing, (
        f"focus precondition: the run list must be focusable and must actually "
        f"hold focus; focus is on {app.focused!r}"
    )


def test_at_b78_15_every_run_reachable_by_keyboard(tmp_path: Path) -> None:
    """AT-B78-15 (GATE) - the arrow keys alone reach EVERY displayed run.

    Intent: HLR-122 - "the set of run indices reachable by keyboard alone shall
    equal the full set of displayed run indices". Pre-change the run list was a
    ``Static`` (``can_focus = False``, 0 selectable entries), so no run was
    reachable by any means; ``_render_run_windows`` was called once with the
    literal ``0``.

    ``R`` is taken from the FIXTURE's own run list (C-31), never from the panel,
    so an implementation that drops runs on the floor shrinks the reachable set
    without shrinking the expectation.

    Real ``pilot.press`` only - no ``.focus()`` in the assertion path, no call to
    ``_render_run_windows``. The walk starts by pressing ``up`` past the top so
    the first index is REACHED by a key press rather than inherited from the
    initial selection.
    """
    runs = [(i * 0x100, i * 0x100 + 4, "changed" if i % 2 else "only_a") for i in range(6)]
    expected = set(range(len(runs)))

    async def _after(app, pilot):
        listing = _b78_run_list(app)
        _b78_focus_run_list(app, listing)
        for _ in range(len(runs) + 4):
            await pilot.press("up")
        reached = [_b78_run_index(listing.highlighted_child)]
        for _ in range(len(runs) + 3):
            await pilot.press("down")
            reached.append(_b78_run_index(listing.highlighted_child))
        note_ids = {item.id for item in listing.query(_B78_RUN_NOTE)}
        return reached, len(list(listing.query(_B78_RUN_ENTRY))), note_ids

    reached, n_entries, note_ids = _b78_drive_compare(
        tmp_path, _B78_AT_SIZE, _diff_result(runs), after=_after
    )

    # C-40 presence co-assertion: with no rows at all the reachable set would be
    # empty and every other clause here vacuous. Assert the rows exist first.
    assert n_entries == len(runs), (
        f"the list must present one selectable entry per displayed run; "
        f"{n_entries} entries for {len(runs)} runs"
    )
    assert None not in reached, (
        f"every keyboard stop must land on a run entry, never on a header or "
        f"notice row; walk was {reached}"
    )
    assert set(reached) == expected, (
        f"the keyboard-reachable run set must equal the displayed run set; "
        f"reached {sorted(set(reached))}, displayed {sorted(expected)}"
    )
    assert note_ids == {None}, (
        "the header / notice rows must not masquerade as run entries (they "
        "carry no run id)"
    )


def test_at_b78_16_every_run_reachable_by_mouse(tmp_path: Path) -> None:
    """AT-B78-16 (GATE) + TC-B78-20 - the mouse alone reaches every run,
    including rows past the viewport.

    Intent: HLR-122 - "the set of run indices reachable by mouse alone shall
    equal the full set of displayed run indices", and its boundary case,
    "entries beyond the viewport shall be reachable by scrolling". Pre-change
    there were 0 ``ListView`` descendants under ``#diff_columns`` and nothing to
    click.

    A distinct observable from ``AT-B78-15``: real ``pilot.click`` on the row's
    own region, with focus explicitly released first so a keyboard path cannot
    stand in for the mouse path.

    TC-B78-20 rides in this node rather than duplicating the whole 20-run drive:
    the off-viewport clause is asserted, not assumed - the test records how many
    targets lay OUTSIDE the list's content region before scrolling and requires
    that count to be non-zero, so a fixture that happens to fit on screen fails
    loudly instead of quietly testing nothing.
    """
    runs = [(i * 0x100, i * 0x100 + 4, "changed") for i in range(20)]

    async def _after(app, pilot):
        listing = _b78_run_list(app)
        app.set_focus(None)
        assert app.focused is None, "the mouse path must not start from a focused list"
        reached, off_viewport = [], 0
        for item in list(listing.query(_B78_RUN_ENTRY)):
            if not listing.content_region.contains_region(item.region):
                off_viewport += 1
            item.scroll_visible(animate=False)
            await pilot.pause()
            await pilot.pause()
            await pilot.click(item)
            await pilot.pause()
            reached.append(_b78_run_index(listing.highlighted_child))
        # The mouse half's NEGATIVE (review F2). Clicking only `.diff-run-entry`
        # makes `reached` note-free by construction, so the walk above cannot
        # tell "notes are unclickable" from "notes were never clicked" — and
        # the mutation that makes note rows selectable left this node GREEN
        # while reddening the keyboard node. The guarantee rests on ONE
        # framework layer (`Widget.check_message_enabled` refusing mouse events
        # to disabled widgets; `ListView._on_list_item__child_clicked` has no
        # disabled check of its own), which is exactly why it needs a node.
        before_notes = _b78_run_index(listing.highlighted_child)
        for note in list(listing.query(_B78_RUN_NOTE)):
            note.scroll_visible(animate=False)
            await pilot.pause()
            await pilot.click(note)
            await pilot.pause()
        after_notes = _b78_run_index(listing.highlighted_child)
        return (
            reached,
            off_viewport,
            listing.content_region.height,
            before_notes,
            after_notes,
        )

    (
        reached, off_viewport, viewport_rows, before_notes, after_notes
    ) = _b78_drive_compare(tmp_path, _B78_AT_SIZE, _diff_result(runs), after=_after)

    assert len(reached) == len(runs), (
        f"one clickable entry per displayed run; clicked {len(reached)} of {len(runs)}"
    )
    assert set(reached) == set(range(len(runs))), (
        f"the mouse-reachable run set must equal the displayed run set; "
        f"reached {sorted(set(reached))}"
    )
    assert after_notes == before_notes, (
        f"a header / notice row must not be mouse-selectable; clicking every "
        f"note row moved the selection from {before_notes} to {after_notes}"
    )
    assert off_viewport > 0, (
        f"TC-B78-20 needs at least one row outside the {viewport_rows}-row "
        f"viewport before scrolling, otherwise the scroll clause is untested; "
        f"all {len(runs)} runs fit"
    )


def test_at_b78_17_exactly_one_entry_is_visibly_selected(tmp_path: Path) -> None:
    """AT-B78-17 (GATE) - exactly one entry carries the selection, and it is
    VISIBLY distinguished.

    Intent: HLR-122 - "the entry holding the selection shall be visually
    distinguished from every other entry". A selection index that changes
    nothing the operator can see satisfies AT-B78-15/16 completely.

    The observation is the RESOLVED ``(background, color, text_style)`` triple
    (C-37: read the layer that holds the fact - colour intent is not in the
    rendered text), read while the list holds focus, which is the state the
    operator is in when they are walking it.

    The >= 2-row guard is asserted rather than assumed: with a single row
    "differs from every unselected entry" is vacuously true.
    """
    runs = [(i * 0x100, i * 0x100 + 4, "changed") for i in range(5)]

    def _triple(widget):
        return (
            str(widget.styles.background),
            str(widget.styles.color),
            str(widget.styles.text_style),
        )

    async def _after(app, pilot):
        listing = _b78_run_list(app)
        _b78_focus_run_list(app, listing)
        await pilot.press("down")
        entries = list(listing.query(_B78_RUN_ENTRY))
        marked = [item for item in entries if item.has_class("-highlight")]
        selected = listing.highlighted_child
        return (
            len(entries),
            [_b78_run_index(m) for m in marked],
            _b78_run_index(selected),
            _triple(selected),
            [_triple(item) for item in entries if item is not selected],
        )

    n_entries, marked, selected, sel_triple, other_triples = _b78_drive_compare(
        tmp_path, _B78_AT_SIZE, _diff_result(runs), after=_after
    )

    assert n_entries >= 2, (
        f"the style clause needs at least two rows to discriminate; got {n_entries}"
    )
    assert marked == [selected], (
        f"exactly one entry must carry the selection marker; marked {marked}, "
        f"selection index {selected}"
    )
    assert all(other != sel_triple for other in other_triples), (
        f"the selected entry must be visually distinguished: its resolved "
        f"(background, color, text_style) is {sel_triple}, which is not "
        f"distinct from every unselected entry's {sorted(set(other_triples))}"
    )


def test_at_b78_18_display_caps_and_notice_survive(tmp_path: Path) -> None:
    """AT-B78-18 (PIN, green today) - the widget swap keeps the G-9 display
    caps and the "showing N of M" notice.

    Intent: HLR-122's preservation clause. The swap from a text ``Static`` to a
    selectable list is exactly where a caps branch gets dropped, because the
    capping and the notice live in the same method the swap rewrites.

    Falsifiability, spec F-6 / LLR-122.3: the fixture size is fixed at a literal
    INDEPENDENT of ``DISPLAY_MAX_RUNS``, the guard quoting the constant runs
    AFTER the capture, and NOTHING in the expectation reads the constant. The
    predicate is "the painted rows are fewer than the runs, and the notice's own
    two numbers are the painted count and the total". A cap AT that expects the
    constant certifies the constant, not the capping.

    Subject split against the rewritten ``test_tc029`` (same clause, same file,
    same increment): that node observes ``panel._runs`` and the header; this one
    observes the RENDERED rows and the notice text.
    """
    import re

    from s19_app.tui.screens_directionb import AbDiffPanel

    total = _B78_OVER_CAP_RUNS
    result = _diff_result([(i * 16, i * 16 + 4, "changed") for i in range(total)])

    async def _after(app, pilot):
        listing = _b78_run_list(app)
        return len(list(listing.query(_B78_RUN_ENTRY))), _b78_run_list_text(app)

    painted, range_text = _b78_drive_compare(
        tmp_path, _B78_AT_SIZE, result, after=_after
    )

    # ORDER IS NORMATIVE — see the same note on `test_tc029`. The guard goes
    # LAST so the cap mutation reddens the capping clause, not the guard.
    assert 0 < painted < total, (
        f"the panel must paint some but not all runs; painted {painted} of {total}"
    )
    notice = re.search(r"showing (\d+) of (\d+) runs", range_text)
    assert notice is not None, (
        f"the capped display must carry its 'showing N of M runs' notice; "
        f"the column's first rows read {range_text.splitlines()[:4]!r} and its "
        f"last {range_text.splitlines()[-2:]!r}"
    )
    assert (int(notice.group(1)), int(notice.group(2))) == (painted, total), (
        f"the notice must name the painted count and the complete count; it "
        f"says {notice.group(0)!r} while {painted} of {total} were painted"
    )
    assert total > AbDiffPanel.DISPLAY_MAX_RUNS, (
        f"this node's fixture ({total} runs) must exceed the display cap "
        f"({AbDiffPanel.DISPLAY_MAX_RUNS}) or it tests nothing"
    )


def test_at_b78_19_app_keys_survive_run_list_focus(tmp_path: Path) -> None:
    """AT-B78-19 - with the run list focused, the application keys still fire,
    and the list binds none of them.

    Intent: HLR-122's final clause and ruling R-2/D-4. ``j`` and ``p`` are frozen
    in ``_PRE_BATCH_BINDINGS`` under live ``TC-011`` and ``k`` is a ``show=True``
    Footer chip, so the navigation bindings go on the WIDGET, never on the App.
    This node is what makes that a checked property instead of an intention.

    A-4 / P-47 (the spec's honest UNDECIDABLE, owned by this increment): whether
    stock ``ListView`` bindings interact correctly with the four ``priority=True``
    App bindings is settled here BY EXECUTION - ``ctrl+k`` is pressed with the
    list focused and the palette must still open, and in the same run the list's
    own ``down`` must still move the selection. Both directions are asserted, so
    "nothing is shadowed" cannot be satisfied by a list that is simply inert.

    Precondition (spec LLR-122.2, restored at revision 2): ``app.focused is``
    the run list is ASSERTED before any key is pressed. On the pre-change tree
    that precondition was silently FALSE - ``set_focus`` on the ``Static``
    did not take, focus landed on ``RailItem(id='rail_item_workspace')`` and
    ``k`` opened the Legend from there. The predicate was green without ever
    reaching its subject.
    """
    runs = [(i * 0x100, i * 0x100 + 4, "changed") for i in range(4)]
    forbidden = {"j", "k", "p", "o"}

    async def _after(app, pilot):
        listing = _b78_run_list(app)
        _b78_focus_run_list(app, listing)

        # The list's own binding surface, read from the LIVE widget's resolved
        # binding map rather than from a class attribute: `BINDINGS` is merged
        # at class creation into `_merged_bindings` and copied per instance, so
        # a class-attribute read would miss everything inherited.
        bound = set(listing._bindings.key_to_bindings)

        # (1) the list's own navigation still works with focus on it
        before = _b78_run_index(listing.highlighted_child)
        await pilot.press("down")
        after_down = _b78_run_index(listing.highlighted_child)

        # (2) an App `show=True` chip key
        await pilot.press("k")
        await pilot.pause()
        legend_open = type(app.screen).__name__ == "LegendScreen"
        if legend_open:
            app.pop_screen()
            await pilot.pause()
        _b78_focus_run_list(app, listing)

        # (3) a frozen `show=False` App key - `j` -> `action_dump_a2l_json`,
        # which with no A2L loaded appends exactly one log line (P-40b:
        # `set_status` writes the log tail, NOT `#status_text`).
        n_before = len(app.log_lines)
        await pilot.press("j")
        await pilot.pause()
        log_delta = len(app.log_lines) - n_before
        log_tail = app.log_lines[-1] if app.log_lines else ""

        # (4) a `priority=True` App binding (A-4 / P-47)
        _b78_focus_run_list(app, listing)
        await pilot.press("ctrl+k")
        await pilot.pause()
        palette_open = app.query_one("#command_bar").palette_is_open

        return bound, before, after_down, legend_open, log_delta, log_tail, palette_open

    (
        bound,
        before,
        after_down,
        legend_open,
        log_delta,
        log_tail,
        palette_open,
    ) = _b78_drive_compare(tmp_path, _B78_AT_SIZE, _diff_result(runs), after=_after)

    # ORDER IS NORMATIVE. The BEHAVIOURAL clauses go first so this node's
    # declared mutation — binding `k` on the run list — reddens "the Legend no
    # longer opens", which is the requirement. Executed with the structural
    # census first, the mutation reddened only the census, leaving the Legend
    # clause unproven: a node can fail for the right reason and still leave its
    # load-bearing clause inert. Same defect as the guard ordering on
    # `test_tc029`, one node over.
    assert legend_open, (
        "'k' must still open the Legend while the run list holds focus"
    )
    assert log_delta == 1 and "A2L" in log_tail, (
        f"'j' must still reach its App action while the run list holds focus; "
        f"the log grew by {log_delta}, tail was {log_tail!r}"
    )
    assert palette_open, (
        "the priority=True 'ctrl+k' binding must still open the palette while "
        "the run list holds focus (A-4 / P-47)"
    )
    # C-40 presence co-assertion: "the App keys still work" is satisfied by a
    # list that swallows nothing because it does nothing. The list's own
    # navigation must move in the same run.
    assert after_down == before + 1, (
        f"'down' must move the list's own selection while it holds focus; "
        f"{before} -> {after_down}"
    )
    # The structural census, last: it is `inspection` evidence for LLR-122.2's
    # "shall not include j/k/p/o", not the behaviour the requirement is about.
    assert bound & forbidden == set(), (
        f"the run list must bind no application-level key; it binds "
        f"{sorted(bound & forbidden)} out of {sorted(bound)}"
    )
    assert {"up", "down"} <= bound, (
        f"the run list must own its own navigation keys; it binds {sorted(bound)}"
    )


def test_tc_b78_17_empty_comparison_has_no_selectable_entry(tmp_path: Path) -> None:
    """TC-B78-17 - a comparison with 0 runs renders context and nothing to select.

    Intent: the empty boundary must degrade to "Runs: 0" plus the no-differing-
    runs windows, with no phantom selectable row and no crash.
    """

    async def _after(app, pilot):
        listing = _b78_run_list(app)
        return (
            len(list(listing.query(_B78_RUN_ENTRY))),
            listing.highlighted_child,
            _b78_run_list_text(app),
            str(app.query_one("#diff_hex_a").render()),
        )

    n_entries, highlighted, range_text, hex_a = _b78_drive_compare(
        tmp_path, _B78_AT_SIZE, _diff_result([]), after=_after
    )

    assert n_entries == 0, f"0 runs must yield 0 selectable entries, got {n_entries}"
    assert highlighted is None, "0 runs must leave nothing selected"
    assert "Runs: 0" in range_text, f"the header must still render; got {range_text!r}"
    assert "no differing runs" in hex_a


def test_tc_b78_18_exactly_cap_runs_shows_no_notice(tmp_path: Path) -> None:
    """TC-B78-18 - exactly ``DISPLAY_MAX_RUNS`` runs paint in full, with NO notice.

    Intent: the off-by-one boundary of the cap. The notice branch is
    ``len(self._runs) < total_runs``; a ``<=`` there would emit a "showing 128
    of 128" notice, which is both wrong and alarming.

    This is the one node where quoting the constant IS the right form (C-39):
    the subject is the cap's exact boundary, so the fixture must be exactly the
    cap whatever its value. The expectation - "no notice, and every run painted"
    - still reads nothing from the constant.
    """
    from s19_app.tui.screens_directionb import AbDiffPanel

    total = AbDiffPanel.DISPLAY_MAX_RUNS
    result = _diff_result([(i * 16, i * 16 + 4, "changed") for i in range(total)])

    async def _after(app, pilot):
        listing = _b78_run_list(app)
        return len(list(listing.query(_B78_RUN_ENTRY))), _b78_run_list_text(app)

    painted, range_text = _b78_drive_compare(
        tmp_path, _B78_AT_SIZE, result, after=_after
    )

    assert painted == total, (
        f"at exactly the cap every run must paint; painted {painted} of {total}"
    )
    assert "showing" not in range_text, (
        f"no elision means no notice; the column reads {range_text!r}"
    )


def test_tc_b78_19_single_run_is_selectable(tmp_path: Path) -> None:
    """TC-B78-19 - a one-run comparison is still selectable.

    Intent: the lower boundary. AT-B78-17's style clause is explicitly SKIPPED
    here (it needs >= 2 rows to discriminate); what this node owns is that one
    run still produces one reachable, highlightable entry.
    """

    async def _after(app, pilot):
        listing = _b78_run_list(app)
        _b78_focus_run_list(app, listing)
        await pilot.press("down")
        await pilot.press("up")
        entries = list(listing.query(_B78_RUN_ENTRY))
        return (
            len(entries),
            _b78_run_index(listing.highlighted_child),
            [item.has_class("-highlight") for item in entries],
        )

    n_entries, selected, marks = _b78_drive_compare(
        tmp_path, _B78_AT_SIZE, _diff_result([(0x10, 0x14, "changed")]), after=_after
    )

    assert n_entries == 1
    assert selected == 0, f"the only run must be the selection, got {selected}"
    assert marks == [True], "the only run must carry the selection marker"


def test_tc_b78_21_zero_length_run_is_selectable(tmp_path: Path) -> None:
    """TC-B78-21 - a run with ``end == start`` renders and is selectable.

    Intent: the degenerate run. ``_apply_display_caps`` accumulates
    ``end - start`` and the entry label formats both endpoints; a zero-length
    run must not vanish from the list.
    """
    runs = [(0x20, 0x20, "changed"), (0x40, 0x44, "only_b")]

    async def _after(app, pilot):
        listing = _b78_run_list(app)
        _b78_focus_run_list(app, listing)
        reached = [_b78_run_index(listing.highlighted_child)]
        await pilot.press("down")
        reached.append(_b78_run_index(listing.highlighted_child))
        return len(list(listing.query(_B78_RUN_ENTRY))), reached, _b78_run_list_text(app)

    n_entries, reached, range_text = _b78_drive_compare(
        tmp_path, _B78_AT_SIZE, _diff_result(runs), after=_after
    )

    assert n_entries == 2, f"both runs must render, got {n_entries}"
    assert set(reached) == {0, 1}, f"both must be reachable, reached {reached}"
    assert "0x00000020-0x00000020" in range_text, (
        f"the zero-length run must render both endpoints; got {range_text!r}"
    )


def test_tc_b78_22_keys_before_any_comparison_do_not_crash(tmp_path: Path) -> None:
    """TC-B78-22 - arrow keys with NO comparison yet: no exception, no phantom
    selection.

    Intent: the negative case. The list exists from ``compose``, so it can be
    focused and driven before ``render_comparison`` has ever run. It must have
    nothing to select rather than an index into an empty model.
    """

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=_B78_AT_SIZE) as pilot:
            await pilot.pause()
            app.action_show_screen("diff")
            await pilot.pause()
            listing = _b78_run_list(app)
            _b78_focus_run_list(app, listing)
            for key in ("down", "down", "up", "enter"):
                await pilot.press(key)
            await pilot.pause()
            return (
                len(list(listing.query(_B78_RUN_ENTRY))),
                listing.highlighted_child,
                listing.index,
            )

    n_entries, highlighted, index = asyncio.run(_drive())

    assert n_entries == 0, "no comparison means no run entries"
    assert highlighted is None, f"no comparison means no selection, got {highlighted!r}"
    assert index is None, f"no comparison means no selection index, got {index!r}"


def test_tc_b78_47_arrows_at_the_ends_do_not_wrap(tmp_path: Path) -> None:
    """TC-B78-47 - ``up`` on the first entry and ``down`` on the last are
    no-ops that neither crash nor wrap.

    Intent: silent wrapping in a list the operator is walking to audit every
    differing run is worse than a dead key - it makes "I have seen them all"
    unknowable. Restored to the boundary catalog at spec revision 2 (Sec.5.6.2).
    """
    runs = [(i * 0x100, i * 0x100 + 4, "changed") for i in range(4)]

    async def _after(app, pilot):
        listing = _b78_run_list(app)
        _b78_focus_run_list(app, listing)
        for _ in range(len(runs) + 3):
            await pilot.press("up")
        first = _b78_run_index(listing.highlighted_child)
        await pilot.press("up")
        first_again = _b78_run_index(listing.highlighted_child)
        for _ in range(len(runs) + 3):
            await pilot.press("down")
        last = _b78_run_index(listing.highlighted_child)
        await pilot.press("down")
        last_again = _b78_run_index(listing.highlighted_child)
        return first, first_again, last, last_again

    first, first_again, last, last_again = _b78_drive_compare(
        tmp_path, _B78_AT_SIZE, _diff_result(runs), after=_after
    )

    assert first == 0 and last == len(runs) - 1, (
        f"the walk must pin at both ends; reached {first} and {last}"
    )
    assert first_again == first, (
        f"'up' at the first entry must be a no-op, not a wrap to {first_again}"
    )
    assert last_again == last, (
        f"'down' at the last entry must be a no-op, not a wrap to {last_again}"
    )


def test_tc_b78_48_hostile_artifact_summary_renders_verbatim(tmp_path: Path) -> None:
    """TC-B78-48 - a markup-shaped artifact summary renders verbatim, with no
    ``MarkupError``.

    Intent: C-17 / LLR-122.1. The artifact-usage summaries are the one
    file-derived string reaching this column. Pre-change they were passed
    through ``rich.markup.escape`` into a ``markup=True`` ``Static``; the
    widget-type swap is exactly where an escape call gets lost. The panel now
    renders them ``markup=False`` AT CONSTRUCTION (C11), which is a sink that
    cannot lose it.

    ``[/nope]`` is included deliberately: it is an unmatched CLOSING tag, which
    is what raises ``MarkupError`` at render rather than merely injecting a span.
    """
    hostile = "[red]evil[/] [/nope] [link=http://x]t[/link]"
    result = _diff_result([(0x10, 0x14, "changed")], summary=hostile)

    async def _after(app, pilot):
        return _b78_run_list_text(app)

    range_text = _b78_drive_compare(tmp_path, _B78_AT_SIZE, result, after=_after)

    assert f"A artifacts: {hostile}" in range_text, (
        f"the hostile summary must render VERBATIM, tags and all; the column "
        f"reads {range_text!r}"
    )
    assert "evil" in range_text and "[red]" in range_text, (
        "the markup must survive as literal text, not be consumed as a span"
    )


def test_tc_b78_49_a_second_compare_rebuilds_the_list(tmp_path: Path) -> None:
    """TC-B78-49 - pressing Compare a SECOND time rebuilds the run list cleanly.

    Intent: this is the regression node for the Inc-2 gate's HIGH finding, and
    the defect it guards was a real product crash that twelve other new nodes
    could not see because **not one of them pressed Compare twice**. Changing
    the A/B selection and comparing again is the panel's primary workflow.

    What went wrong, executed on the first Inc-2 implementation::

        textual._node_list.DuplicateIds: Tried to insert a widget with ID
          'diff_run_0', but a widget already exists with that ID

    ``ListView.clear()`` routes to ``App._prune``, which only POSTS a ``Prune``
    message, so the previous rows were still registered when ``extend()``
    mounted the new ones carrying the same DOM ids. It is a REGRESSION, not a
    latent defect: on the pre-change tree ``Static.update()`` is idempotent and
    mints no ids, and the same double drive completes cleanly.

    Removing the ids would not have been sufficient, which is why this node
    asserts the selection too. With the rows anonymous the crash goes away but
    ``index`` is assigned while the stale rows are still in ``_nodes``, so
    ``watch_index`` highlights a row that is then pruned; because the VALUE does
    not change the watcher never fires again and **no row is highlighted after
    any re-render** - HLR-122's visual-distinction clause, silently violated.

    The two fixtures have DIFFERENT run counts on purpose: with equal counts the
    entry-count assertion is satisfied by a list that was never rebuilt at all.
    """
    import s19_app.tui.app as app_mod
    from textual.widgets import ListItem

    first_runs = [(i * 0x100, i * 0x100 + 4, "changed") for i in range(7)]
    second_runs = [(i * 0x100, i * 0x100 + 4, "only_b") for i in range(3)]
    assert len(first_runs) != len(second_runs), (
        "the two fixtures must differ in run count or the count assertion below "
        "cannot distinguish a rebuilt list from an untouched one"
    )
    pending = [_diff_result(first_runs), _diff_result(second_runs)]

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=_B78_AT_SIZE) as pilot:
            await pilot.pause()
            app.action_show_screen("diff")
            await pilot.pause()
            listing = _b78_run_list(app)

            await _b78_press_compare(app, pilot)
            first_entries = len(list(listing.query(_B78_RUN_ENTRY)))

            # the SECOND compare - the press that used to raise DuplicateIds
            await _b78_press_compare(app, pilot)

            # captured BEFORE any key press, so these describe the state the
            # second Compare left behind rather than the state the walk created
            entries = len(list(listing.query(_B78_RUN_ENTRY)))
            selected = _b78_run_index(listing.highlighted_child)
            marked = [
                _b78_run_index(item)
                for item in listing.query(ListItem)
                if item.has_class("-highlight")
            ]

            # pin to the top first, so index 0 is REACHED by a key press rather
            # than inherited from the selection the re-render left behind
            _b78_focus_run_list(app, listing)
            for _ in range(len(second_runs) + 4):
                await pilot.press("up")
            walk = [_b78_run_index(listing.highlighted_child)]
            for _ in range(len(second_runs) + 2):
                await pilot.press("down")
                walk.append(_b78_run_index(listing.highlighted_child))
            return first_entries, entries, selected, marked, walk

    monkey = pytest.MonkeyPatch()
    monkey.setattr(app_mod, "compare_images", lambda *a, **k: pending.pop(0))
    try:
        first_entries, entries, selected, marked, walk = asyncio.run(_drive())
    finally:
        monkey.undo()

    assert first_entries == len(first_runs), (
        f"the first Compare must render its own run count; {first_entries} "
        f"entries for {len(first_runs)} runs"
    )
    assert entries == len(second_runs), (
        f"the second Compare must REBUILD the list to its own run count; "
        f"{entries} entries for {len(second_runs)} runs"
    )
    assert selected == 0, (
        f"after the second Compare the selection must be the first run of the "
        f"NEW comparison, got {selected}"
    )
    assert marked == [0], (
        f"exactly one row must carry the selection marker after a re-render, "
        f"and it must be run 0; marked {marked}"
    )
    assert set(walk) == set(range(len(second_runs))), (
        f"every run of the SECOND comparison must still be keyboard-reachable; "
        f"the walk reached {walk}"
    )


# --------------------------------------------------------------------------
# batch-78 Inc-3 - LLR-122.4: the PERSISTED report stays complete
#
# Node map (spec Sec.3 HLR-122 / Sec.4 LLR-122.4 / Sec.5.3 / Sec.7 Inc-3):
#   AT-B78-31  test_at_b78_31_written_report_is_complete_under_display_caps
#
# Why this node exists at all. G-9's caps (`DISPLAY_MAX_RUNS`,
# `DISPLAY_MAX_TOTAL_BYTES`) bound the PANEL and never the report (spec C8 /
# P-50), and that is a fact about two lines of `app.py`. Inc-2 hardened the
# panel side; the report side had NO observer, so an edit that made the report
# inherit the panel's capped view would have been invisible to the whole suite.
#
# C-12 (output-then-consume) is what makes this a control instead of a citation:
# the node drives the SHIPPED Report button with the REAL generators, then
# re-reads the files those generators actually wrote FROM DISK and counts the
# runs in them. `panel._runs` is the capped view and is therefore never the
# oracle here - it is only read as the "and the cap really was active in this
# same run" co-assertion, which is what makes the completeness clause
# discriminating rather than trivially true on a fixture that never capped.
# --------------------------------------------------------------------------

#: The success sentinel `_start_diff_report_worker` marshals back to the UI
#: thread AFTER both files are closed (`app.py`, the `ok` arm).
_B78_REPORT_OK = "Diff report written:"

#: Every failure arm of that same worker. Each is a LOUD stop, never a timeout:
#: a refused or crashed report leaves no file, and a node that waited its budget
#: out and then failed on `FileNotFoundError` would be reporting the wrong fact.
_B78_REPORT_FAILED = (
    "Report refused:",
    "HTML report refused:",
    "Diff report failed:",
    "No comparison yet",
)


async def _b78_press_report(app, pilot, dest_dir: Path) -> tuple[Path, Path]:
    """Press the shipped Report button and wait for THIS press's worker to finish.

    Not a pause, and not ``workers.wait_for_complete()`` either (C-78-xii, one
    layer further out than Inc-2's compare driver). ``Button.press()`` only
    POSTS ``Pressed``; the handler that starts the ``@work(thread=True)`` worker
    has not run yet, so a worker-set wait taken immediately after the press
    observes an EMPTY set and returns at once - the same shape as waiting on
    queue idleness for a suspended coroutine. Measured: worker set **0**
    immediately after ``press()``, and ``wait_for_complete()`` returning in
    **0.8 ms** against a generator sleeping 1000 ms.

    EDGE, NOT LEVEL (Inc-3 addendum F1). The first form of this driver polled
    ``#diff_status`` for the success sentinel, which is a LEVEL: on a second
    press the PREVIOUS press's success line already satisfies it, so the wait
    returned after 0.8 ms with the generators still running and both globs
    empty. The wait is now armed on an EDGE - a strictly increasing count of
    status messages emitted AFTER the observer is installed, which is after the
    comparison and immediately before the press. A line written by an earlier
    press is therefore not merely unlikely to satisfy this wait; it is
    unreachable by it.

    The observer wraps ``panel.set_status`` and DELEGATES to it - it substitutes
    nothing, and the app still writes its own surface. ``set_status`` is the
    right signal because ``_start_diff_report_worker`` writes it through
    ``call_from_thread``, and ``call_from_thread`` blocks the worker until the
    callback has run on the UI thread. Observing the message therefore
    happens-after both files are written and closed, which is exactly the
    precondition a re-read needs.

    The wait is TOTAL: every failure arm of the worker is a named, loud raise,
    so the caller can never proceed on a stale or missing file.

    GUARANTEE, stated exactly (C-78-xiii). For each call, this driver either
    returns the two paths written by THAT call's worker, or raises. It holds per
    press and is re-armed on every call, so repeated presses against one panel
    are covered. It does NOT serialise concurrent presses: the group is
    ``exclusive=True``, so a second press while the first worker runs cancels
    the first, and this driver would report the surviving worker's message.
    Nothing in this suite presses twice concurrently, and a caller that needs
    that must arm its own wait rather than assume this one covers it.
    """
    from s19_app.tui.screens_directionb import AbDiffPanel

    panel = app.query_one("#ab_diff_panel", AbDiffPanel)
    app.query_one("#diff_report_dest").value = str(dest_dir)

    emitted: list[str] = []
    shipped_set_status = panel.set_status

    def _observe(message, *args, **kwargs):
        emitted.append(str(message))
        return shipped_set_status(message, *args, **kwargs)

    # The FILE check is an edge too. Its first form asserted the destination
    # holds exactly one report of each kind, which silently assumes the
    # destination started empty - the same level-vs-edge mistake as the status
    # wait, one clause down, and it fired on a CORRECT second press.
    md_before = set(dest_dir.glob("*-diff-report.md"))
    html_before = set(dest_dir.glob("*-diff-report.html"))

    panel.set_status = _observe
    try:
        before = len(emitted)
        app.query_one("#diff_report_button").press()
        for _ in range(750):
            if len(emitted) > before:
                break
            await pilot.pause(0.02)
        else:
            raise AssertionError(
                f"the report worker never completed: `panel.set_status` was not "
                f"called once across 750 pumped turns after the Report press. "
                f"#diff_status still reads "
                f"{str(app.query_one('#diff_status').render())!r}, which is the "
                f"line that was there BEFORE this press. Every assertion after "
                f"this point would be reading a file that was never written."
            )
    finally:
        del panel.set_status

    message = emitted[before]
    for arm in _B78_REPORT_FAILED:
        if arm in message:
            raise AssertionError(
                f"the report worker took a FAILURE arm, so no complete file "
                f"exists to observe; it emitted {message!r}"
            )
    assert _B78_REPORT_OK in message, (
        f"the report worker emitted a status this driver does not classify, so "
        f"it cannot know whether a complete file exists: {message!r}"
    )
    new_md = sorted(set(dest_dir.glob("*-diff-report.md")) - md_before)
    new_html = sorted(set(dest_dir.glob("*-diff-report.html")) - html_before)
    assert len(new_md) == 1 and len(new_html) == 1, (
        f"the success status was emitted but THIS press did not add exactly one "
        f"report of each kind to the destination: new md={new_md}, new "
        f"html={new_html} (it already held {len(md_before)} md and "
        f"{len(html_before)} html before the press)"
    )
    return new_md[0], new_html[0]


def _b78_section(text: str, heading: str, stop: str) -> str:
    """The slice of ``text`` from ``heading`` up to the next ``stop`` marker.

    Why the run table is read section-scoped, stated as MEASURED rather than as
    assumed (Inc-3 addendum LOW-2). The first version of this comment claimed a
    whole-document regex "would count rows that are not run entries" because the
    hex-window dumps also carry ``0x``-prefixed addresses. **That is false for
    these two regexes.** Executed on a real 82 157-byte report with non-empty
    memory maps, so the windows actually render: whole-document **200**,
    section-scoped **200**, in both the Markdown and the HTML document. The
    window section's ``0x`` addresses live in ``###`` headers and in hex rows,
    and neither can match a pattern anchored on a line-initial ``| 0x`` /
    ``<tr><td>0x``.

    The scoping is kept, for the reason that survives measurement: it bounds
    what the node can be reading to the ONE table the requirement is about, so a
    future report layout that grows a second address table cannot silently
    inflate the count into a false pass. That is defence in depth, not a
    correction of a real over-count.
    """
    start = text.find(heading)
    assert start >= 0, (
        f"the written report does not contain the section heading {heading!r}, "
        f"so this node cannot locate the run table. The report layout has "
        f"changed and this parser must be updated before its verdict means "
        f"anything. Document begins: {text[:200]!r}"
    )
    after = start + len(heading)
    return text[start : text.index(stop, after)] if stop in text[after:] else text[start:]


def _b78_md_report_run_starts(text: str) -> list[int]:
    """Every run-table start address in a written MARKDOWN diff report."""
    import re

    section = _b78_section(text, "## Runs", "\n## ")
    return [
        int(m.group(1), 16)
        for m in re.finditer(
            r"^\| 0x([0-9A-F]{8}) \| 0x[0-9A-F]{8} \|", section, re.MULTILINE
        )
    ]


def _b78_html_report_run_starts(text: str) -> list[int]:
    """Every run-table start address in a written HTML diff report."""
    import re

    section = _b78_section(text, "<h2>Runs</h2>", "</table>")
    return [
        int(m.group(1), 16)
        for m in re.finditer(r"<tr><td>0x([0-9A-F]{8})</td><td>0x", section)
    ]


def test_at_b78_31_written_report_is_complete_under_display_caps(
    tmp_path: Path,
) -> None:
    """AT-B78-31 (PIN, green today) - the WRITTEN report holds every run of the
    comparison while the panel paints only the capped subset (LLR-122.4, G-9).

    Intent: the operator's evidence artifact must not silently inherit a
    DISPLAY budget. The panel caps because a terminal has finite rows; the
    report has no such constraint and is the thing that gets attached to a
    change record. An implementation that fed the report the panel's stored
    runs - the shortest possible edit, `runs=panel._runs` - would still render
    a correct-looking panel, still write a well-formed report, and silently drop
    every run past the cap.

    Falsifiability: the observation is C-12 output-then-consume. Both files are
    produced by the REAL generators through the shipped Report button and then
    RE-READ FROM DISK; nothing in the expectation comes from `panel._runs`, from
    the generators, or from `DISPLAY_MAX_RUNS`. The expectation is the fixture's
    own run list, which the test authored before the app ever saw it. The
    declared mutation (route the report off the panel's capped runs) drops the
    written count to the cap and reddens the completeness clause itself.

    Non-vacuity: a completeness claim proves nothing on a fixture that never
    capped, so the painted count is captured IN THE SAME RUN and asserted
    strictly smaller. The constant-quoting guard is asserted LAST (Inc-2 F-1:
    a guard placed ahead of the substantive clauses reddens first and the
    subject never runs).
    """
    from s19_app.tui.screens_directionb import AbDiffPanel

    total = _B78_OVER_CAP_RUNS
    runs = [(i * 16, i * 16 + 4, "changed") for i in range(total)]
    expected_starts = [start for start, _end, _kind in runs]
    dest_dir = tmp_path / "b78_report_dest"
    dest_dir.mkdir()

    async def _after(app, pilot):
        md_path, html_path = await _b78_press_report(app, pilot, dest_dir)
        painted = len(list(_b78_run_list(app).query(_B78_RUN_ENTRY)))
        return (
            md_path.read_text(encoding="utf-8"),
            html_path.read_text(encoding="utf-8"),
            painted,
        )

    md_text, html_text, painted = _b78_drive_compare(
        tmp_path, _B78_AT_SIZE, _diff_result(runs), after=_after
    )

    md_starts = _b78_md_report_run_starts(md_text)
    assert md_starts == expected_starts, (
        f"the written Markdown report must list EVERY run of the comparison, "
        f"in order; it lists {len(md_starts)} of {total}. First missing start "
        f"address: "
        f"{next((s for s in expected_starts if s not in set(md_starts)), None)}"
    )
    html_starts = _b78_html_report_run_starts(html_text)
    assert html_starts == expected_starts, (
        f"the written HTML report must list EVERY run of the comparison, in "
        f"order; it lists {len(html_starts)} of {total}. First missing start "
        f"address: "
        f"{next((s for s in expected_starts if s not in set(html_starts)), None)}"
    )
    assert 0 < painted < total, (
        f"this node is only discriminating while the PANEL is actually capping "
        f"in the same run: it painted {painted} of {total} runs, so the "
        f"completeness clauses above would hold trivially"
    )
    assert total > AbDiffPanel.DISPLAY_MAX_RUNS, (
        f"this node's fixture ({total} runs) must exceed the display cap "
        f"({AbDiffPanel.DISPLAY_MAX_RUNS}) or it tests nothing"
    )
