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
import re
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


async def _b78_open_run_list(app, pilot) -> None:
    """Make the run list VISIBLE, through whichever surface the regime ships.

    batch-78 Inc-5: below ``_DIFF_WIDE_MIN`` the run list is no longer a column
    — it is an overlay on ``f`` that reserves no permanent width (LLR-124.3), so
    it starts hidden. ``_B78_AT_SIZE`` is 132x44, which is on the FALLBACK side
    of the 139 breakpoint, so every Inc-2 node that observes the list must open
    it first.

    This is not cosmetic. Without it ``AT-B78-16`` goes RED (nothing to click)
    while ``AT-B78-15`` and ``AT-B78-17`` stay GREEN against a
    ``display: none`` list, because ``Widget.focusable`` does not consult
    ``display`` — the keyboard and style nodes would have kept passing over a
    list the operator cannot see. Opened through a real ``pilot.press("f")`` on
    the shipped panel binding, never by setting the class.
    """
    listing = _b78_run_list(app)
    if listing.display:
        return
    # The binding lives on `AbDiffPanel`, so focus has to be inside the panel
    # for the press to reach it. The Compare button is the panel's own shipped
    # control and is where the operator's focus already is after a comparison.
    app.set_focus(app.query_one("#diff_compare_button"))
    await pilot.press("f")
    await pilot.pause()
    assert listing.display, (
        "the run-list overlay must open on 'f' in the fallback regime; "
        f"#diff_range_list.display is {listing.display}. NOTE for triage: this "
        "is the DRIVER's guard, not the failing node's own subject - every node "
        "built on _b78_drive_compare reddens here when the overlay breaks, "
        "including AT-B78-15 / -16 / -17, whose subjects are run REACHABILITY "
        "and selection, not the overlay. Fix the overlay first, then re-read"
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
            await _b78_open_run_list(app, pilot)
            return await after(app, pilot)

    monkey = pytest.MonkeyPatch()
    monkey.setattr(app_mod, "compare_images", lambda *a, **k: result)
    try:
        return asyncio.run(_drive())
    finally:
        monkey.undo()


def _diff_result(
    runs_kinds, *, refused=False, diagnostics=None, summary="none", paths=(None, None)
):
    """Build a fake ComparisonResult for the view-layer tests.

    runs_kinds: list of (start, end, kind). The maps are synthetic and only
    used for the panel's hex windows (display-only).

    ``summary`` is the per-image artifact-usage string the panel renders into
    the run-list header. It is a parameter (batch-78 Inc-2) so ``TC-B78-48``
    can drive a hostile value through the SHIPPED path rather than calling
    ``_render_run_list`` behind the app's back.

    ``paths`` is the ``(path_a, path_b)`` pair the app re-parses into the hex
    windows' memory maps (``S19TuiApp._diff_load_maps``). It is a parameter
    (batch-78 Inc-4) so ``TC-B78-26`` can give the two sides DIFFERENT byte
    coverage through the shipped loader; the default ``(None, None)`` leaves
    both maps empty, which is what every pre-Inc-4 node here already assumes.
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
    path_a, path_b = paths
    return ComparisonResult(
        image_a=ImageRef(label="A.s19", path=path_a, source_kind="external"),
        image_b=ImageRef(label="B.s19", path=path_b, source_kind="external"),
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


# --------------------------------------------------------------------------
# batch-78 Inc-4 - HLR-123: the hex windows follow the selection and are sized
# by the pane
#
# Node map (spec Sec.3 HLR-123 / Sec.4 LLR-123.1-.3 / Sec.5.3 / Sec.7 Inc-4):
#   AT-B78-20  test_at_b78_20_selection_re_renders_both_windows        GATE
#   AT-B78-21  test_at_b78_21_row_count_derives_from_pane_height       GATE
#   AT-B78-22  test_at_b78_22_window_spans_the_run_plus_context        GATE
#   TC-B78-23  test_tc_b78_23_zero_runs_keeps_the_no_runs_text
#   TC-B78-24  test_tc_b78_24_address_zero_clamp_and_unaligned_start
#   TC-B78-25  test_tc_b78_25_run_longer_than_the_pane_still_renders
#   TC-B78-26  test_tc_b78_26_bytes_absent_from_one_map_render_blank
#   TC-B78-27  test_tc_b78_27_stale_high_selection_after_a_shorter_compare
#   TC-B78-28  test_tc_b78_28_zero_height_pane_does_not_raise
#   TC-B78-45  test_tc_b78_45_row_count_is_not_a_function_of_the_constant
#   TC-B78-50  test_tc_b78_50_the_surplus_rows_are_split_around_the_run  (A-6)
#
# Pre-change, `_render_run_windows` had ONE call site - `render_comparison`'s
# literal 0 - and its row count came from `DISPLAY_CONTEXT_BYTES` alone, so the
# window was byte-identical at every terminal height. Executed on this branch
# before the change: 132x44 emitted 4 lines into a 13-row pane and 132x60
# emitted 4 lines into a 29-row pane. 4 == 4, RED.
# --------------------------------------------------------------------------

#: `AT-B78-21`'s two sizes, named by spec Sec.7's Inc-4 gate. SAME WIDTH, so the
#: only thing that can move the row count is the height: a width-driven
#: implementation, or a hard-coded count, fails the strict inequality. A
#: single-size test proves nothing here - `return 40` passes it.
_B78_INC4_TALL = (132, 60)
_B78_INC4_WIDE = (132, 44)

#: A pane whose derived CAPACITY is 0, so the mandatory run +/- context floor is
#: the whole window - the only regime in which `AT-B78-22`'s "exactly three
#: addresses" is satisfiable at all. See that node's docstring: HLR-123's two
#: clauses are jointly exact only where the pane cannot grow the window.
#:
#: batch-78 Inc-5 moved this from 132x24, and the Inc-5 gate moved it again.
#: 132x24 still has capacity 0, but as of HLR-124 it has it for a DIFFERENT
#: reason: 24 is below `_DIFF_MIN_H`, so the whole result area is `display: none`
#: behind the notice and the "pane" whose height this node names no longer
#: exists. The first draft used 132x26; raising the floor to 28 (gate F-1) put
#: that back in the notice regime, so it moves once more to **132x28** - the
#: first row at which the fallback regime renders under the corrected floor.
#:
#: Capacity is still 0 there, executed both sides of Inc-10: `132x28` gives
#: content height 0 / capacity 0 with the command bar present and 2 / 1 without
#: it. Either way `capacity <= 3`, and the window only GROWS when
#: `capacity > rows`, so the run +/- context floor of 3 rows is still the whole
#: window and `AT-B78-22`'s exact three addresses hold on both sides of Inc-10.
_B78_INC4_SHORT = (132, 28)

#: `AT-B78-22`'s fixture and its expected addresses, as LITERALS. Spec F-6 /
#: Q-M1: rev-1 computed this span from `AbDiffPanel.DISPLAY_CONTEXT_BYTES` - the
#: class under test - and stayed GREEN under a 4x change to it. The constant
#: appears in this module's Inc-4 block only inside a guard, and that guard is
#: evaluated AFTER the capture so a mutation reddens an assertion rather than
#: raising before one runs.
_B78_AT22_RUN = (0x1000, 0x1004, "changed")
_B78_AT22_ADDRESSES = [0x00000FF0, 0x00001000, 0x00001010]

#: One emitted hex row: `0x` + 8 upper-case hex digits + two spaces. The row
#: address is the observable HLR-123 is about - `render_hex_view` emits exactly
#: one such line per requested row base, so counting these counts the rows the
#: producer was asked for, without reading the producer's inputs.
_B78_HEX_ROW = re.compile(r"^0x([0-9A-F]{8})  ")


def _b78_window_text(app, selector: str) -> str:
    """The rendered text of one hex window (`#diff_hex_a` / `#diff_hex_b`)."""
    from textual.widgets import Static

    return str(app.query_one(selector, Static).render())


def _b78_window_rows(text: str) -> list[int]:
    """The row-base addresses a hex window emitted, in emitted order.

    Only data rows count. `render_hex_view` also emits `... showing from ...` /
    `... window limited to N rows ...` notices, and the panel prepends its own
    `Image A - Run #n ...` header; none of those is a hex row and none matches.
    """
    rows = []
    for line in text.splitlines():
        match = _B78_HEX_ROW.match(line)
        if match is not None:
            rows.append(int(match.group(1), 16))
    return rows


def _b78_window_geometry(app) -> dict:
    """Both windows' emitted rows + the CONTENT height each was rendered into.

    Returns the two layers HLR-123 keeps apart (spec Sec.3, C-32): `rows` is
    what the PRODUCER emitted, read off the rendered text; `content_h` is
    `size.height`, the rows the layout gave the widget. LLR-123.2's bound is on
    the content layer - `<= clipped` would admit four rows of invisible
    overflow, because for these bordered boxes `clipped == content + 4`.
    """
    from textual.widgets import Static

    text_a = _b78_window_text(app, "#diff_hex_a")
    text_b = _b78_window_text(app, "#diff_hex_b")
    return {
        "rows_a": _b78_window_rows(text_a),
        "rows_b": _b78_window_rows(text_b),
        "lines_a": len(text_a.splitlines()),
        "header_a": text_a.splitlines()[0] if text_a else "",
        "header_b": text_b.splitlines()[0] if text_b else "",
        "content_h": app.query_one("#diff_hex_a", Static).size.height,
        "text_a": text_a,
        "text_b": text_b,
    }


async def _b78_select_run(app, pilot, listing, presses: int) -> None:
    """Walk the run-list highlight down `presses` rows with REAL key presses.

    No `.focus()` in the assertion path and no call to `_render_run_windows`:
    LLR-123.1's whole point is that the shipped selection surface drives the
    renderer, and calling the renderer directly already worked pre-change.
    """
    _b78_focus_run_list(app, listing)
    for _ in range(presses):
        await pilot.press("down")


def test_at_b78_20_selection_re_renders_both_windows(tmp_path: Path) -> None:
    """AT-B78-20 (GATE) - selecting run 3 re-renders BOTH windows onto run 3.

    Intent: HLR-123 / LLR-123.1 - "when the operator changes the run-list
    selection through the shipped selection surface, both hex windows shall
    re-render to the selected run with a header naming its index, address range
    and classification". Pre-change `_render_run_windows` had a single call site
    carrying the literal `0`, so runs 1..N were unreachable no matter how the
    list was driven - Inc-2 made the list selectable and deliberately left this
    wire unconnected.

    The header clause is asserted on an EDGE, not a level (C-78-xvi): the header
    is captured BEFORE the presses and the node requires a transition. A level
    assertion ("the header names run 3") is also satisfied by a window that
    never re-rendered, had the initial selection happened to be run 3, and by a
    stale capture if the key presses never landed.

    C-40 co-assertion: "the header names run 3" is green on a window that
    rendered a header and nothing else, so the same read requires at least one
    emitted hex row, and requires the A and B windows to have been asked for the
    SAME addresses - a diff whose two columns disagree about which byte is on
    which line is not a diff.
    """
    runs = [(i * 0x100, i * 0x100 + 4, "changed" if i % 2 else "only_a") for i in range(6)]
    target = 3
    start, end, kind = runs[target]

    async def _after(app, pilot):
        listing = _b78_run_list(app)
        before = _b78_window_geometry(app)
        await _b78_select_run(app, pilot, listing, target)
        after = _b78_window_geometry(app)
        at_target = _b78_run_index(listing.highlighted_child)
        # LLR-123.3 says "the header contains the kind label for a run of each of
        # the three kinds". Run 3 is `changed`, and `changed` is the one key
        # `_KIND_LABEL` maps to ITSELF - so asserting it alone leaves the mapping
        # untested: `self._KIND_LABEL.get(kind, kind)` -> `kind` keeps that clause
        # green. One more press lands on run 4, whose kind is `only_a` and whose
        # label is `only A`, and that arm cannot survive the same mutation.
        await pilot.press("down")
        mapped = _b78_window_geometry(app)
        return before, after, at_target, mapped, _b78_run_index(listing.highlighted_child)

    before, after, highlighted, mapped, mapped_index = _b78_drive_compare(
        tmp_path, _B78_INC4_WIDE, _diff_result(runs), after=_after
    )

    assert highlighted == target, (
        f"precondition: the key presses must land on run {target}; the run list "
        f"highlight is on {highlighted}"
    )
    assert before["header_a"] != after["header_a"], (
        f"the A window must RE-RENDER on a selection change; its header did not "
        f"move off {before['header_a']!r}"
    )
    assert before["header_b"] != after["header_b"], (
        f"the B window must RE-RENDER on a selection change; its header did not "
        f"move off {before['header_b']!r}"
    )
    for side, header in (("A", after["header_a"]), ("B", after["header_b"])):
        assert f"Run #{target}" in header, (
            f"the {side} window header must name the selected run index; "
            f"header={header!r}"
        )
        assert f"0x{start:08X}-0x{end:08X}" in header, (
            f"the {side} window header must name the selected run's address "
            f"range; header={header!r}"
        )
        assert "changed" in header, (
            f"the {side} window header must name the run's classification "
            f"(LLR-123.3); run kind is {kind!r} and header={header!r}"
        )
    # LLR-123.3's second kind - the one whose LABEL differs from its KEY, so the
    # mapping itself is under test rather than an identity. Both literals are
    # written out here; deriving either from `_KIND_LABEL` would be reading the
    # expectation off the class under test (spec F-6).
    mapped_kind, mapped_label = "only_a", "only A"
    assert runs[target + 1][2] == mapped_kind and mapped_label != mapped_kind, (
        f"precondition: this arm needs a run whose kind label DIFFERS from its "
        f"kind key, or it re-tests the identity mapping; run {target + 1} is "
        f"{runs[target + 1][2]!r}"
    )
    assert mapped_index == target + 1, (
        f"precondition: the extra press must land on run {target + 1}; the "
        f"highlight is on {mapped_index}"
    )
    for side, header in (("A", mapped["header_a"]), ("B", mapped["header_b"])):
        assert mapped_label in header, (
            f"the {side} window header must name the run's classification "
            f"through the kind LABEL, not its raw key; expected "
            f"{mapped_label!r} in header={header!r}"
        )
        assert mapped_kind not in header, (
            f"the {side} window header must not leak the raw kind key; "
            f"{mapped_kind!r} is in header={header!r}"
        )
    # C-40: a header-only window would satisfy every clause above.
    assert after["rows_a"] and after["rows_b"], (
        f"both windows must emit at least one hex row; "
        f"A={len(after['rows_a'])} rows, B={len(after['rows_b'])} rows"
    )
    assert after["rows_a"] == after["rows_b"], (
        "the A and B windows must be asked for the SAME row addresses, or the "
        "two columns cannot be read against each other"
    )
    row_base = start - (start % 16)
    assert row_base in after["rows_a"], (
        f"the window must include the selected run's own row 0x{row_base:08X}; "
        f"emitted 0x{after['rows_a'][0]:08X}..0x{after['rows_a'][-1]:08X}"
    )
    assert after["rows_a"][0] != before["rows_a"][0], (
        f"the window must move to the selected run's neighbourhood; it still "
        f"starts at 0x{before['rows_a'][0]:08X}"
    )


def test_at_b78_21_row_count_derives_from_pane_height(tmp_path: Path) -> None:
    """AT-B78-21 (GATE) - the row count differs between two pane HEIGHTS.

    Intent: HLR-123 / LLR-123.2 - "the number of hex rows each window renders
    shall be derived from that window's rendered height at render time, shall
    not be a compile-time constant, and shall not exceed the window's rendered
    content height". Pre-change the count came from `DISPLAY_CONTEXT_BYTES`
    alone, so it was a function of the RUN, not of the pane: executed on this
    branch at the two sizes below, 4 emitted lines into a 13-row pane and 4 into
    a 29-row pane. 4 == 4.

    The gate is the STRICT INEQUALITY, and it is what "the floor is a floor, not
    the value" means in a predicate (spec LLR-123.2): an implementation that
    keeps the +/-16 span and ALSO reads the height passes any ">= floor" test,
    and cannot pass this one. The `<= content height` clause is the other half -
    it is what kills a "just render 40 rows" fix.

    Both sizes are 132 columns WIDE. Only the height differs, so a count derived
    from the width, or from the run, or from a literal, fails.
    """
    runs = [_B78_AT22_RUN]

    async def _after(app, pilot):
        return _b78_window_geometry(app)

    wide = _b78_drive_compare(tmp_path, _B78_INC4_WIDE, _diff_result(runs), after=_after)
    tall = _b78_drive_compare(tmp_path, _B78_INC4_TALL, _diff_result(runs), after=_after)

    # Precondition: the two panes really are different heights in this run. If
    # they were not, the inequality below would be a claim about nothing.
    assert tall["content_h"] > wide["content_h"] > 0, (
        f"precondition: {_B78_INC4_TALL} must give the window a taller CONTENT "
        f"pane than {_B78_INC4_WIDE}; measured {tall['content_h']} and "
        f"{wide['content_h']}"
    )
    assert len(wide["rows_a"]) < len(tall["rows_a"]), (
        f"the emitted row count must DERIVE from the pane height: same width, "
        f"panes of {wide['content_h']} and {tall['content_h']} content rows, "
        f"but the windows emitted {len(wide['rows_a'])} and "
        f"{len(tall['rows_a'])} rows"
    )
    # Per-arm verdicts (CC-1): the two sizes differ by 16 pane rows, and a
    # single aggregate would hide which arm moved.
    for label, measured in ((_B78_INC4_WIDE, wide), (_B78_INC4_TALL, tall)):
        assert len(measured["rows_a"]) <= measured["content_h"], (
            f"{label}: the window emitted {len(measured['rows_a'])} hex rows "
            f"into a content pane of {measured['content_h']} rows - the count "
            f"must not exceed the pane it is rendered into"
        )
        assert measured["lines_a"] <= measured["content_h"], (
            f"{label}: the window emitted {measured['lines_a']} lines (header "
            f"included) into a content pane of {measured['content_h']} rows; "
            f"the header shares the widget with the hex rows"
        )
        assert measured["rows_a"] == measured["rows_b"], (
            f"{label}: A and B must be asked for the same row addresses"
        )


def test_at_b78_22_window_spans_the_run_plus_context(tmp_path: Path) -> None:
    """AT-B78-22 (GATE) - the window covers the run +/- the context, exactly.

    Intent: HLR-123 - "the rendered window shall always include the selected
    run's bytes plus `DISPLAY_CONTEXT_BYTES` of context on each side". For a run
    at 0x1000-0x1004 that is the three row bases 0x00000FF0, 0x00001000 and
    0x00001010, written here as LITERALS.

    Why literals, and why they are the whole point (spec F-6 / Q-M1): rev-1
    computed the expected span from `AbDiffPanel.DISPLAY_CONTEXT_BYTES` - the
    class under test - and stayed GREEN under `16 -> 64`, because expectation
    and observation moved together. The constant appears below only in a guard,
    and the guard is evaluated AFTER the capture so a mutation on it reddens an
    assertion rather than raising before one runs.

    Why the exact arm runs at a pane of ZERO content rows (a spec conflict,
    reported at the Inc-4 gate): HLR-123 requires BOTH "always include the run
    +/- context" AND "the row count derives from the pane height". Wherever the
    pane is taller than the +/-context floor those clauses cannot both be exact
    - the derived count is 12 rows at 132x44 - so the "exactly three addresses"
    threshold is satisfiable only where the pane cannot grow the window. 132x24
    is that place (`#diff_hex_a.size.height == 0`, executed), and it is the size
    the spec's own HLR-123 rationale measured. The second read below covers the
    tall pane with the CONTAINMENT form, which is what the requirement's
    "include" actually says; it is a co-assertion, not the gate.
    """
    from s19_app.tui.screens_directionb import AbDiffPanel

    async def _after(app, pilot):
        return _b78_window_geometry(app)

    short = _b78_drive_compare(
        tmp_path, _B78_INC4_SHORT, _diff_result([_B78_AT22_RUN]), after=_after
    )
    wide = _b78_drive_compare(
        tmp_path, _B78_INC4_WIDE, _diff_result([_B78_AT22_RUN]), after=_after
    )

    # The guard is AFTER the capture and BEFORE the assertions (spec Q-m2): this
    # node's declared reddening mutation is on the IMPLEMENTATION
    # (`high = end + ctx` -> `high = end`), and this guard stays true under it,
    # so the node reddens on the assertion below rather than on an error.
    assert AbDiffPanel.DISPLAY_CONTEXT_BYTES == 16, (
        f"this node's expected addresses are literals derived from a 16-byte "
        f"context; the constant is now {AbDiffPanel.DISPLAY_CONTEXT_BYTES} and "
        f"the literals must be re-derived rather than the assertion relaxed"
    )
    assert short["content_h"] == 0, (
        f"precondition: {_B78_INC4_SHORT} must give the window a content height "
        f"of 0 so the derived capacity cannot grow the window past the run +/- "
        f"context floor; measured {short['content_h']}"
    )
    assert short["rows_a"] == _B78_AT22_ADDRESSES, (
        f"the window must span exactly the run plus one context row on each "
        f"side; expected {[f'0x{a:08X}' for a in _B78_AT22_ADDRESSES]}, emitted "
        f"{[f'0x{a:08X}' for a in short['rows_a']]}"
    )
    assert short["rows_b"] == _B78_AT22_ADDRESSES, (
        f"the B window must span the same rows; emitted "
        f"{[f'0x{a:08X}' for a in short['rows_b']]}"
    )
    # Co-assertion, not the gate: on a pane that CAN grow the window, the same
    # mandatory span must still be there, contiguously and in order.
    assert _B78_AT22_ADDRESSES[0] in wide["rows_a"], (
        f"growing the window to the pane must not drop the mandatory low "
        f"context row; emitted {[f'0x{a:08X}' for a in wide['rows_a']]}"
    )
    index = wide["rows_a"].index(_B78_AT22_ADDRESSES[0])
    assert wide["rows_a"][index : index + 3] == _B78_AT22_ADDRESSES, (
        f"growing the window to the pane must not disturb the mandatory run "
        f"+/- context span; emitted {[f'0x{a:08X}' for a in wide['rows_a']]}"
    )


def test_tc_b78_45_row_count_is_not_a_function_of_the_constant(tmp_path: Path) -> None:
    """TC-B78-45 - two pane heights, ONE constant, two different row counts.

    Intent: HLR-123's mechanism clause - "the emitted row count is no longer a
    pure function of `DISPLAY_CONTEXT_BYTES`". AT-B78-21 asserts the counts
    differ; this asserts the OTHER half, that nothing about the constant or the
    run differed between the two measurements. Without it, "the counts differ"
    is also consistent with the two arms having been given different runs.
    """
    from s19_app.tui.screens_directionb import AbDiffPanel

    runs = [_B78_AT22_RUN]
    seen_constant = []

    async def _after(app, pilot):
        seen_constant.append(AbDiffPanel.DISPLAY_CONTEXT_BYTES)
        return _b78_window_geometry(app)

    wide = _b78_drive_compare(tmp_path, _B78_INC4_WIDE, _diff_result(runs), after=_after)
    tall = _b78_drive_compare(tmp_path, _B78_INC4_TALL, _diff_result(runs), after=_after)

    assert len(set(seen_constant)) == 1, (
        f"the context constant must be identical across both arms, or the row "
        f"counts below are explained by it after all; observed {seen_constant}"
    )
    assert wide["header_a"] == tall["header_a"], (
        f"both arms must window the SAME run, or a differing row count says "
        f"nothing about the pane; headers {wide['header_a']!r} vs "
        f"{tall['header_a']!r}"
    )
    assert len(wide["rows_a"]) != len(tall["rows_a"]), (
        f"same run, same constant, different pane heights ({wide['content_h']} "
        f"vs {tall['content_h']}) must produce different row counts; both "
        f"emitted {len(wide['rows_a'])}"
    )


def test_tc_b78_23_zero_runs_keeps_the_no_runs_text(tmp_path: Path) -> None:
    """TC-B78-23 (empty) - a comparison with 0 runs still says so.

    Intent: HLR-123's empty boundary. The selection wire must not turn the
    no-runs branch of `render_comparison` into a blank pane or a crash: with no
    runs there is no selectable entry, so nothing highlights and nothing renders
    a window.
    """

    async def _after(app, pilot):
        return _b78_window_geometry(app)

    measured = _b78_drive_compare(
        tmp_path, _B78_INC4_WIDE, _diff_result([]), after=_after
    )

    assert "no differing runs" in measured["text_a"], (
        f"the A window must state that there are no differing runs; "
        f"text={measured['text_a']!r}"
    )
    assert "no differing runs" in measured["text_b"], (
        f"the B window must state that there are no differing runs; "
        f"text={measured['text_b']!r}"
    )
    assert measured["rows_a"] == [] and measured["rows_b"] == [], (
        "a comparison with no runs must not window anything"
    )


def test_tc_b78_24_address_zero_clamp_and_unaligned_start(tmp_path: Path) -> None:
    """TC-B78-24 (boundary) - the address-0 clamp and the alignment step.

    Intent: HLR-123's two arithmetic boundaries, both of which are otherwise
    covered by nothing (spec architect NEW-11 - the mutation on the alignment
    line came back inert precisely because no acceptance exercised an unaligned
    start).

    Arm 1, the clamp: a run at address 0 has no room for a context row below it,
    and the window must start AT 0 rather than at a negative base - while still
    filling the pane, because the rows the clamp refuses above the run are owed
    below it, not dropped.

    Arm 2, the alignment step: a run starting at 0x1007 is not on a 16-byte row
    boundary. Its window must still be built from aligned row bases, so the
    emitted addresses are the same three as for an aligned 0x1000 run.
    """

    async def _after(app, pilot):
        return _b78_window_geometry(app)

    at_zero = _b78_drive_compare(
        tmp_path,
        _B78_INC4_WIDE,
        _diff_result([(0x0000, 0x0004, "only_b")]),
        after=_after,
    )
    unaligned = _b78_drive_compare(
        tmp_path,
        _B78_INC4_SHORT,
        _diff_result([(0x1007, 0x100B, "changed")]),
        after=_after,
    )

    assert at_zero["rows_a"][0] == 0, (
        f"a run at address 0 must window from 0x00000000, not from a clamped-"
        f"then-shifted base; first row is 0x{at_zero['rows_a'][0]:08X}"
    )
    assert len(at_zero["rows_a"]) <= at_zero["content_h"], (
        f"the clamp must not push the row count past the pane; "
        f"{len(at_zero['rows_a'])} rows into {at_zero['content_h']}"
    )
    assert len(at_zero["rows_a"]) == at_zero["content_h"] - 1, (
        f"the rows the address-0 clamp refuses ABOVE the run are owed BELOW it: "
        f"the window must still fill the pane. Pane {at_zero['content_h']}, "
        f"header 1, emitted {len(at_zero['rows_a'])} hex rows"
    )
    assert unaligned["rows_a"] == _B78_AT22_ADDRESSES, (
        f"an unaligned run start must be aligned down to a 16-byte row base; a "
        f"run at 0x00001007 must window the same rows as one at 0x00001000, but "
        f"emitted {[f'0x{a:08X}' for a in unaligned['rows_a']]}"
    )


def test_tc_b78_25_run_longer_than_the_pane_still_renders(tmp_path: Path) -> None:
    """TC-B78-25 (boundary) - a run larger than the pane keeps its header.

    Intent: HLR-123's overflow boundary. The floor is a floor: when the run
    +/- context spans more rows than the pane can paint, the derived capacity
    does NOT shrink the window - the mandatory span survives and the surplus
    overflows. Bounding that overflow into a paginable viewport is HLR-124's
    fallback regime, built at Inc-5; what this node pins is that Inc-4 does not
    silently truncate the run in the meantime, and that the header still names
    it.
    """

    async def _after(app, pilot):
        return _b78_window_geometry(app)

    start, end = 0x1000, 0x2000
    measured = _b78_drive_compare(
        tmp_path, _B78_INC4_WIDE, _diff_result([(start, end, "changed")]), after=_after
    )

    assert f"0x{start:08X}-0x{end:08X}" in measured["header_a"], (
        f"the header must still name the run it could not fit; "
        f"header={measured['header_a']!r}"
    )
    assert len(measured["rows_a"]) > measured["content_h"], (
        f"precondition: this run must overflow the pane, or the node tests "
        f"nothing; {len(measured['rows_a'])} rows into {measured['content_h']}"
    )
    assert measured["rows_a"][0] <= start - (start % 16), (
        f"the mandatory low context row must survive the overflow; first row is "
        f"0x{measured['rows_a'][0]:08X}"
    )
    assert measured["rows_a"][-1] >= end, (
        f"the mandatory high context row must survive the overflow; last row is "
        f"0x{measured['rows_a'][-1]:08X} for a run ending at 0x{end:08X}"
    )


def test_tc_b78_26_bytes_absent_from_one_map_render_blank(tmp_path: Path) -> None:
    """TC-B78-26 (boundary) - a run mapped in A only renders a blank B gutter.

    Intent: HLR-123's asymmetric boundary - an `only_a` run has no bytes on the
    B side. Both windows are asked for the SAME row addresses (that is what
    makes the two columns readable against each other), so B must render those
    rows with an empty hex gutter rather than dropping them, going blank, or
    falling back to A's bytes.

    Driven through the shipped loader: the two sides are real on-disk S19 files,
    re-parsed by `S19TuiApp._diff_load_maps` exactly as a real compare does.
    """
    from s19_app.tui.changes.io import emit_s19_from_mem_map

    start, end = 0x1000, 0x1004
    map_a = {start + i: 0xA0 + i for i in range(end - start)}
    path_a = tmp_path / "only_a.s19"
    path_b = tmp_path / "empty_b.s19"
    path_a.write_text(emit_s19_from_mem_map(map_a, [(start, end)]), encoding="utf-8")
    # B carries bytes somewhere else entirely, so its map is non-empty (an empty
    # map is a load FAILURE to the app) but covers none of the run.
    path_b.write_text(
        emit_s19_from_mem_map({0x9000 + i: 0x11 for i in range(4)}, [(0x9000, 0x9004)]),
        encoding="utf-8",
    )

    async def _after(app, pilot):
        return _b78_window_geometry(app)

    measured = _b78_drive_compare(
        tmp_path,
        _B78_INC4_SHORT,
        _diff_result([(start, end, "only_a")], paths=(path_a, path_b)),
        after=_after,
    )

    assert "A0 A1 A2 A3" in measured["text_a"], (
        f"the A window must render the run's real bytes; "
        f"text={measured['text_a']!r}"
    )
    assert measured["rows_a"] == measured["rows_b"], (
        f"both windows must be asked for the same rows even when only one side "
        f"has bytes there; A={[f'0x{a:08X}' for a in measured['rows_a']]}, "
        f"B={[f'0x{a:08X}' for a in measured['rows_b']]}"
    )
    assert "A0 A1 A2 A3" not in measured["text_b"], (
        f"the B window must not carry A's bytes; text={measured['text_b']!r}"
    )
    b_run_row = next(
        line
        for line in measured["text_b"].splitlines()
        if line.startswith(f"0x{start:08X}  ")
    )
    assert b_run_row.split("  ")[1].strip() == "", (
        f"the row B does not map must render an EMPTY hex gutter, not a dropped "
        f"row and not other bytes; row={b_run_row!r}"
    )


def test_tc_b78_27_stale_high_selection_after_a_shorter_compare(tmp_path: Path) -> None:
    """TC-B78-27 (invalid) - a selection index outside `_runs` renders nothing.

    Intent: HLR-123's invalid boundary - `_render_run_windows`'s bounds guard.
    The reachable way to aim an out-of-range index at it through the shipped
    surface is a SECOND comparison with fewer runs while the highlight sits on a
    high index: the list is rebuilt and every highlight event it emits while
    doing so must land on a valid run or on nothing at all.
    """
    import s19_app.tui.app as app_mod

    many = [(i * 0x100, i * 0x100 + 4, "changed") for i in range(8)]
    few = [(0x5000, 0x5004, "only_b")]
    injected = {"result": _diff_result(many)}

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=_B78_INC4_WIDE) as pilot:
            await pilot.pause()
            app.action_show_screen("diff")
            await pilot.pause()
            await _b78_press_compare(app, pilot)
            listing = _b78_run_list(app)
            await _b78_select_run(app, pilot, listing, 7)
            high = _b78_run_index(listing.highlighted_child)
            injected["result"] = _diff_result(few)
            await _b78_press_compare(app, pilot)
            listing = _b78_run_list(app)
            return high, _b78_run_index(listing.highlighted_child), _b78_window_geometry(app)

    monkey = pytest.MonkeyPatch()
    monkey.setattr(app_mod, "compare_images", lambda *a, **k: injected["result"])
    try:
        high, highlighted, measured = asyncio.run(_drive())
    finally:
        monkey.undo()

    assert high == 7, (
        f"precondition: the first comparison's highlight must reach run 7, or "
        f"the second comparison is not shrinking past anything; it is on {high}"
    )
    assert highlighted == 0, (
        f"after a comparison with 1 run the highlight must be on run 0; it is "
        f"on {highlighted}"
    )
    assert f"Run #0 0x{few[0][0]:08X}-0x{few[0][1]:08X}" in measured["header_a"], (
        f"the window must show the SECOND comparison's only run, not a stale "
        f"one; header={measured['header_a']!r}"
    )
    assert measured["rows_a"], "the rebuilt window must still emit hex rows"


def test_tc_b78_28_zero_height_pane_does_not_raise(tmp_path: Path) -> None:
    """TC-B78-28 (error) - selecting a run into a zero-height pane does not raise.

    Intent: HLR-123's error boundary. The derived capacity is read from a live
    widget, and at 132x24 that widget's content height is 0 - so the derivation
    must produce a well-formed window rather than an empty row list, a negative
    count or a raise. Selection still works; the rows are simply not painted,
    which is the hole HLR-124's notice regime closes at Inc-5.
    """
    runs = [(i * 0x100, i * 0x100 + 4, "changed") for i in range(4)]

    async def _after(app, pilot):
        listing = _b78_run_list(app)
        await _b78_select_run(app, pilot, listing, 2)
        return _b78_run_index(listing.highlighted_child), _b78_window_geometry(app)

    highlighted, measured = _b78_drive_compare(
        tmp_path, _B78_INC4_SHORT, _diff_result(runs), after=_after
    )

    assert measured["content_h"] == 0, (
        f"precondition: {_B78_INC4_SHORT} must give the window a content height "
        f"of 0; measured {measured['content_h']}"
    )
    assert highlighted == 2, (
        f"selection must still work with nothing painted; highlight is on "
        f"{highlighted}"
    )
    assert "Run #2" in measured["header_a"], (
        f"the producer must still emit the selected run's window into an "
        f"unpainted pane; header={measured['header_a']!r}"
    )
    assert len(measured["rows_a"]) == 3, (
        f"with no pane to fill, the mandatory run +/- context floor is the whole "
        f"window; emitted {[f'0x{a:08X}' for a in measured['rows_a']]}"
    )


def test_tc_b78_50_the_surplus_rows_are_split_around_the_run(tmp_path: Path) -> None:
    """TC-B78-50 - the growth CENTRES the run instead of piling the surplus.

    Intent: spec Sec.8's `A-6` - `LLR-123.2`'s row-centring arithmetic, which the
    document flags `assumed - measure in Phase 3` and for which it states no
    formula. This is the predicate that discharges it.

    Why it exists as its own node, and why the Inc-4 gate review was right to
    demand it: `TC-B78-24` pins the row COUNT (`len(rows) == content_h - 1`), and
    BOTH one-sided splits preserve the count. Executed at the gate review,
    `(capacity - rows) // 2` -> all surplus ABOVE and -> all surplus BELOW each
    left **10 of 10** Inc-4 nodes GREEN. A measured number in a report is not a
    control; the count clause pins nothing about POSITION, and position is the
    whole of what `A-6` asks about.

    The observable is the imbalance `|above - below|` around the run's own row.
    Centred to within one row it is <= 1 (a surplus of odd size cannot split
    evenly); either one-sided split drives it to the full surplus.

    The fixture's run sits at 0x1000 - far enough from address 0 that the
    address-0 clamp cannot bind and mask the split, which is asserted rather
    than assumed. Both gate sizes are read, per-arm (CC-1).
    """
    runs = [_B78_AT22_RUN]
    start = _B78_AT22_RUN[0]
    run_row = start - (start % 16)

    async def _after(app, pilot):
        return _b78_window_geometry(app)

    wide = _b78_drive_compare(tmp_path, _B78_INC4_WIDE, _diff_result(runs), after=_after)
    tall = _b78_drive_compare(tmp_path, _B78_INC4_TALL, _diff_result(runs), after=_after)

    for label, measured in ((_B78_INC4_WIDE, wide), (_B78_INC4_TALL, tall)):
        rows = measured["rows_a"]
        # Precondition 1: the window actually GREW. With no surplus there is
        # nothing to split and every clause below is vacuous.
        assert len(rows) > len(_B78_AT22_ADDRESSES), (
            f"{label}: precondition - the pane must have grown the window past "
            f"the run +/- context floor of {len(_B78_AT22_ADDRESSES)} rows; it "
            f"emitted {len(rows)}"
        )
        # Precondition 2: the address-0 clamp is NOT binding here. If it were,
        # the window would be pinned to 0 and a one-sided split would be
        # indistinguishable from a centred one.
        assert rows[0] > 0, (
            f"{label}: precondition - the address-0 clamp must not bind in this "
            f"fixture, or the split is unobservable; window starts at "
            f"0x{rows[0]:08X}"
        )
        assert run_row in rows, (
            f"{label}: the run's own row 0x{run_row:08X} must be in the window; "
            f"emitted 0x{rows[0]:08X}..0x{rows[-1]:08X}"
        )
        above = rows.index(run_row)
        below = len(rows) - above - 1
        assert abs(above - below) <= 1, (
            f"{label}: the surplus rows must be SPLIT around the selected run, "
            f"not piled on one side; the run's row 0x{run_row:08X} sits at "
            f"index {above} of {len(rows)} - {above} rows above it and {below} "
            f"below. A one-sided split preserves the row count, so the count "
            f"clause in TC-B78-24 cannot see this"
        )


# --------------------------------------------------------------------------
# batch-78 Inc-5 - HLR-124: three width/height regimes, and no silently empty
# panel
#
# Node map (spec Sec.3 HLR-124 / Sec.4 LLR-124.1-.4 / Sec.5.3 / Sec.7 Inc-5):
#   AT-B78-23  test_at_b78_23_no_wrapped_row_in_the_wide_regime        GATE
#   AT-B78-29  test_at_b78_29_notice_names_every_unsatisfied_axis      GATE
#   TC-B78-29  test_tc_b78_29_the_layout_flips_exactly_once
#   TC-B78-30  test_tc_b78_30_a_resize_across_the_breakpoint_follows
#   TC-B78-31  test_tc_b78_31_the_width_floor_is_the_notice_boundary
#   TC-B78-32  test_tc_b78_32_a_single_axis_failure_names_that_axis
#   TC-B78-33  test_tc_b78_33_the_regime_applies_with_no_comparison
#   TC-B78-51  test_tc_b78_51_escape_dismisses_without_shadowing        (A-2)
#   TC-B78-52  test_tc_b78_52_pagination_reaches_bytes_past_the_pane
#   TC-B78-53  test_tc_b78_53_the_overlay_reserves_no_width
#
# AT-B78-24 (fallback, 120x30), AT-B78-25 (the regimes are observably different)
# and AT-B78-26 land at Inc-10, where the command-bar rows are gone and the
# 120x30 arms have a non-zero pane to observe (spec Sec.7 BL-2).
#
# Sizes that stand for a REGIME BOUNDARY are written from the constants
# (_DIFF_WIDE_MIN, _DIFF_MIN_W, _DIFF_MIN_H) and never as bare integers
# (LLR-124.1 / spec m6): a literal here is a phantom the day a measurement moves,
# and it is the same defect as a threshold quoting a value instead of its name.
# 80x24 and 160x40 ARE written as literals - they are the snapshot matrix's own
# terminal sizes (C1), not regime constants.
# --------------------------------------------------------------------------

from s19_app.tui.screens_directionb import (  # noqa: E402
    _DIFF_MIN_H,
    _DIFF_MIN_W,
    _DIFF_WIDE_MIN,
)

#: The snapshot matrix's wide cell. _DIFF_WIDE_MIN <= 160, so this is the wide
#: regime, and it is a size the operator's terminal actually takes.
_B78_INC5_WIDE = (160, 40)

#: The snapshot matrix's floor cell. Fails BOTH axes, which is why it is
#: AT-B78-29's subject: a notice naming "the" unsatisfied axis in the singular
#: would be wrong precisely here.
_B78_INC5_FLOOR = (80, 24)

#: Screen lines each hex window spends on its own header before the first byte.
#: `_render_run_windows` writes `f"Image A - {header}\n{text}"`, so line 0 is the
#: `Image A - Run #n 0x... changed` header. Named rather than written as a bare
#: `+ 1` because it is the entire reason a painted content height of 1 delivers
#: ZERO bytes - the defect behind the Inc-5 gate's F-1 and F-3, which were the
#: same one-row error in the constant and in the acceptance that should have
#: caught it.
_B78_WINDOW_HEADER_ROWS = 1


async def _b78_hide_command_bar(app, pilot) -> None:
    """Reclaim the command-bar row's three screen rows, as Inc-10 will.

    `_DIFF_MIN_H` is defined in the POST-Inc-10 end state (spec Sec.8 A-1's own
    quantity: "post-US-78-8 + US-78-1"), and Inc-10 is the increment that deletes
    `#command_bar_row` from `CommandBar.compose`. Until it lands, a node that
    asserts what the floor DELIVERS has to reach that state, and hiding the row
    reclaims exactly the rows deleting it will.

    The reclaim is ASSERTED, not assumed: a simulation that silently fails to
    apply is a vacuous precondition, and this batch has now watched ten mutations
    fail to apply. When Inc-10 lands, `#command_bar_row` no longer resolves and
    this hook becomes the no-op branch below - the node then measures the real
    tree with no simulation at all.
    """
    rows = app.query("#command_bar_row")
    if not rows:
        return
    slot_before = app.query_one("#command_bar_slot").size.height
    rows.first().display = False
    await pilot.pause()
    slot_after = app.query_one("#command_bar_slot").size.height
    assert slot_after < slot_before, (
        f"the Inc-10 simulation must actually reclaim the command bar's rows; "
        f"#command_bar_slot height stayed at {slot_before}"
    )


def _b78_widest_emitted_hex_row() -> int:
    """The width of the widest row `hexview.render_hex_view` emits.

    DERIVED by calling the producer at test time, never written as 79 (spec
    Sec.3 HLR-124 / C-36 / C-39). The panel renders through `render_hex_view`,
    not `render_hex_view_text` - the two differ by a two-space indent, and
    reading the wrong one is the batch's own F-1, found independently by three
    lanes. Importing the same function the panel imports is what makes that
    impossible to get wrong here.
    """
    from s19_app.tui.hexview import HEX_WIDTH, MAX_HEX_ROWS, render_hex_view

    base = 0x1000
    mem_map = {address: 0xAB for address in range(base, base + 4 * HEX_WIDTH)}
    text = render_hex_view(
        mem_map,
        row_bases=[base + index * HEX_WIDTH for index in range(4)],
        max_rows=MAX_HEX_ROWS,
    )
    rows = [line for line in text.splitlines() if _B78_HEX_ROW.match(line)]
    assert rows, "the width oracle must actually emit hex rows, or it measures nothing"
    return max(len(line) for line in rows)


def _b78_regime_probe(base_dir: Path, size, *, prepare=None):
    """Read the regime, the notice and the result geometry at one terminal size.

    No comparison is driven: HLR-124 is a LAYOUT requirement and its observables
    - the class, the notice, `#diff_hex_a`'s width - exist with the panel empty.
    TC-B78-33 is the node that says so explicitly.
    """

    async def _drive():
        app = S19TuiApp(base_dir=base_dir)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            app.action_show_screen("diff")
            await pilot.pause()
            if prepare is not None:
                await prepare(app, pilot)
                await pilot.pause()
            panel = app.query_one("#ab_diff_panel")
            notice = app.query_one("#diff_size_notice")
            hex_a = app.query_one("#diff_hex_a")
            listing = _b78_run_list(app)
            return {
                "regimes": sorted(
                    name for name in panel.classes if name.startswith("diff-")
                ),
                "notice_shown": notice.display,
                "notice_text": str(notice.render()),
                "columns_shown": app.query_one("#diff_columns").display,
                "list_shown": listing.display,
                "list_width": listing.size.width,
                "hex_a_width": hex_a.size.width,
                "hex_a_painted": _b78_painted_content_height(hex_a),
                "hex_a_painted_width": hex_a.content_region.intersection(
                    app.query_one("#screen_diff").region
                ).width,
            }

    return asyncio.run(_drive())


def test_at_b78_23_no_wrapped_row_in_the_wide_regime(tmp_path: Path) -> None:
    """AT-B78-23 (GATE) - at 160x40 no emitted hex row wraps.

    Intent: HLR-124 / LLR-124.2 - "in the first two regimes each hex window's
    content width shall be at least the width of the widest row
    `hexview.render_hex_view` emits". The shipped three-way `1fr` split gave
    `#diff_hex_a` 39 cells at 160x40 against a 79-cell row, so every hex row
    wrapped at every supported width and a byte column lined up nowhere.

    Both quantities are MEASURED, neither is a literal: the window's width off
    the live widget, the row width by calling the producer. A hard-coded 79 would
    be a phantom the day HEX_WIDTH changes, and it would also hide the F-1
    producer confusion that cost this batch three lanes' work.

    C-40, and M3 is the specific trap: a width clause alone is invariant under
    total vertical invisibility - at 120x30 on the shipped tree `#diff_hex_a`'s
    clipped region is (width 30, height 0), so a window can be "unwrapped" while
    painting nothing at all. The painted height >= 1 co-assertion is what makes
    the width clause mean the operator can see a row.

    The wide regime's own property rides here too: the run list is BESIDE the
    window (LLR-124.2), which is what distinguishes this regime from the
    fallback one where the same width clause also holds.
    """
    widest = _b78_widest_emitted_hex_row()
    measured = _b78_regime_probe(tmp_path, _B78_INC5_WIDE)

    assert measured["regimes"] == ["diff-wide"], (
        f"{_B78_INC5_WIDE} is at or above the wide breakpoint and must select "
        f"exactly the wide regime; classes are {measured['regimes']}"
    )
    assert measured["hex_a_width"] >= widest, (
        f"at {_B78_INC5_WIDE} the hex window must fit an unwrapped emitted row: "
        f"#diff_hex_a content width {measured['hex_a_width']} < widest emitted "
        f"row {widest} (measured by calling render_hex_view at test time)"
    )
    assert measured["hex_a_painted"] >= _B78_WINDOW_HEADER_ROWS + 1, (
        f"an unwrapped window that paints no HEX ROW delivers nothing: screen "
        f"line 0 is the 'Image A - Run #...' header, so a painted content height "
        f"of 1 is ZERO bytes on the operator's screen. Painted height is "
        f"{measured['hex_a_painted']}. (Gate F-3: the `>= 1` form this replaces "
        f"was green at zero bytes, and passed only because 160x40 happens to "
        f"paint 2 - a one-row margin, not a property the assertion pinned)"
    )
    assert measured["hex_a_painted_width"] >= widest, (
        f"the window must be unwrapped ON SCREEN, not merely in the layout: "
        f"painted width {measured['hex_a_painted_width']} < {widest}"
    )
    assert measured["list_shown"] and measured["list_width"] > 0, (
        f"the wide regime puts the run list BESIDE the window column "
        f"(LLR-124.2); it is shown={measured['list_shown']} at width "
        f"{measured['list_width']}"
    )
    assert not measured["notice_shown"], (
        "a deliverable terminal must not show the too-small notice"
    )


def test_at_b78_29_notice_names_every_unsatisfied_axis(tmp_path: Path) -> None:
    """AT-B78-29 (GATE) - at 80x24 the notice names BOTH failed axes.

    Intent: HLR-124 / LLR-124.4 - "when the terminal does not satisfy the
    deliverability condition, the panel shall render a notice naming EVERY
    unsatisfied axis and the value each requires". On the shipped tree 80x24
    renders nothing in its results area and says nothing about why (spec P-33 /
    P-33b: the 120x30 golden contains no `Runs` / `Image A` / `Image B` text at
    all). The notice closes that hole.

    Why "every" and not "the": the two axes are INDEPENDENT. 80x24 fails both,
    which is what this node tests; TC-B78-32 covers the two single-axis cases
    where a message naming the wrong axis would be actively misleading.

    The required values are quoted from the constants, never as literals (rule
    4). The discriminating mutation is therefore NOT "blank the notice" - that
    is the trivial one - but the MAPPING mutation C-78-xxiii names: make the
    width branch name the height axis and confirm this node reddens.

    C-40: the notice's presence is co-asserted with the results area's ABSENCE,
    so "the panel says it is too small" cannot be green beside an empty results
    box that is still on screen.
    """
    measured = _b78_regime_probe(tmp_path, _B78_INC5_FLOOR)
    width, height = _B78_INC5_FLOOR
    text = measured["notice_text"]

    assert width < _DIFF_MIN_W and height < _DIFF_MIN_H, (
        f"precondition: {_B78_INC5_FLOOR} must fail BOTH axes for this node to "
        f"be about 'every' axis; floors are {_DIFF_MIN_W} x {_DIFF_MIN_H}"
    )
    assert measured["regimes"] == ["diff-notice"], (
        f"a terminal failing both axes must select the notice regime; classes "
        f"are {measured['regimes']}"
    )
    assert measured["notice_shown"], f"the notice must be rendered at {_B78_INC5_FLOOR}"
    assert not measured["columns_shown"], (
        "LLR-124.4: the notice replaces the results area, it does not sit above "
        "an empty one"
    )
    assert "width" in text, f"the notice must name the failed WIDTH axis; text={text!r}"
    assert "height" in text, (
        f"the notice must name the failed HEIGHT axis; text={text!r}"
    )
    assert str(_DIFF_MIN_W) in text, (
        f"the notice must name the columns the width axis requires; text={text!r}"
    )
    assert str(_DIFF_MIN_H) in text, (
        f"the notice must name the rows the height axis requires; text={text!r}"
    )
    # SEC-F2 (LLR-124.4, normative): author-constant text and geometry integers
    # only. The panel's own file-derived strings are the two image labels and the
    # external path inputs; none of them may reach this sink.
    assert "A.s19" not in text and "B.s19" not in text, (
        f"no file-derived string may be interpolated into the notice; text={text!r}"
    )


def test_tc_b78_29_the_layout_flips_exactly_once(tmp_path: Path) -> None:
    """TC-B78-29 - one column below the wide breakpoint, and one at it.

    Intent: HLR-124's boundary catalog - the layout flips EXACTLY once, at
    _DIFF_WIDE_MIN. Both sizes are written from the constant, so this node
    cannot drift when the measurement does; what it pins is that the flip is
    where the constant says, not three columns either side of it.

    Both regimes keep the unwrapped-row guarantee - that is the point of the
    breakpoint being about the LIST rather than about the window - so the
    discriminating observable is the list, not the window width.
    """
    widest = _b78_widest_emitted_hex_row()
    at = _b78_regime_probe(tmp_path, (_DIFF_WIDE_MIN, 40))
    below = _b78_regime_probe(tmp_path, (_DIFF_WIDE_MIN - 1, 40))

    assert at["regimes"] == ["diff-wide"], (
        f"at exactly _DIFF_WIDE_MIN the layout must be wide; {at['regimes']}"
    )
    assert below["regimes"] == ["diff-fallback"], (
        f"one column below _DIFF_WIDE_MIN the layout must be the fallback; "
        f"{below['regimes']}"
    )
    assert at["list_shown"] and at["list_width"] > 0, (
        "the wide regime reserves a run-list column"
    )
    assert not below["list_shown"], (
        "the fallback regime reserves NO run-list column - the list is an "
        "overlay (LLR-124.3)"
    )
    for label, measured in ((_DIFF_WIDE_MIN, at), (_DIFF_WIDE_MIN - 1, below)):
        assert measured["hex_a_width"] >= widest, (
            f"width {label}: the window must stay unwrapped on BOTH sides of the "
            f"breakpoint; {measured['hex_a_width']} < {widest}. That is what the "
            f"breakpoint is for - it moves the LIST, never the guarantee"
        )


def test_tc_b78_30_a_resize_across_the_breakpoint_follows(tmp_path: Path) -> None:
    """TC-B78-30 - a resize across the breakpoint moves the layout with it.

    Intent: HLR-124's boundary catalog - "a resize ACROSS the breakpoint after a
    comparison is rendered: the layout follows and the windows do not blank".
    Inc-4 deliberately added no resize handling, so this is the node that says
    the regime is driven by the live terminal size rather than fixed at mount.

    The windows-do-not-blank clause is asserted on the rendered TEXT, because a
    regime change that dropped the hex windows' content would satisfy every
    geometry clause in this file.
    """

    async def _after(app, pilot):
        before_regimes = sorted(
            name
            for name in app.query_one("#ab_diff_panel").classes
            if name.startswith("diff-")
        )
        before_rows = _b78_window_rows(_b78_window_text(app, "#diff_hex_a"))
        await pilot.resize_terminal(_DIFF_WIDE_MIN - 1, 40)
        after_regimes = sorted(
            name
            for name in app.query_one("#ab_diff_panel").classes
            if name.startswith("diff-")
        )
        after_rows = _b78_window_rows(_b78_window_text(app, "#diff_hex_a"))
        after_capacity = app.query_one("#ab_diff_panel")._window_row_capacity()
        return (
            before_regimes, before_rows, after_regimes, after_rows, after_capacity
        )

    runs = [(0x1000, 0x1004, "changed")]
    (
        before_regimes, before_rows, after_regimes, after_rows, after_capacity
    ) = _b78_drive_compare(
        tmp_path, (_DIFF_WIDE_MIN, 40), _diff_result(runs), after=_after
    )

    assert before_regimes == ["diff-wide"], (
        f"precondition: the comparison must be rendered in the WIDE regime, "
        f"otherwise the resize crosses nothing; {before_regimes}"
    )
    assert after_regimes == ["diff-fallback"], (
        f"the layout must follow a resize across the breakpoint; after the "
        f"resize the classes are {after_regimes}"
    )
    assert before_rows, "precondition: the window must have emitted rows to keep"
    assert after_rows, (
        "the windows must not blank across a regime change; #diff_hex_a emitted "
        "no hex row after the resize"
    )
    # Gate F-5: the layout following is not enough - the row count is derived
    # from the pane AT RENDER TIME (LLR-123.2), so a regime change that moves the
    # pane and does not re-render leaves a window sized for the OLD geometry.
    # Measured before the fix: 139x40 -> 138x40 moved capacity 1 -> 5 while the
    # rendered window did not change at all.
    assert len(after_rows) == after_capacity, (
        f"a regime change must RE-DERIVE the window's row count, not only swap "
        f"the layout class: the new pane has a capacity of {after_capacity} rows "
        f"and the window is still rendering {len(after_rows)}. This clause is "
        f"the one that distinguishes 'the layout followed' from 'the window "
        f"followed'"
    )


def test_tc_b78_31_the_width_floor_is_the_notice_boundary(tmp_path: Path) -> None:
    """TC-B78-31 - the notice appears exactly once, one column below the floor.

    Intent: HLR-124's boundary catalog - `size=(_DIFF_MIN_W, ...)` and
    `(_DIFF_MIN_W - 1, ...)`. _DIFF_MIN_W is the measured width at which a
    full-width window first fits an unwrapped row (93 -> 78, 94 -> 79), so the
    node also asserts the consequence, not only the class: AT the floor the
    window is unwrapped, which is what makes the floor the right number rather
    than merely a number the code and the test agree on.
    """
    widest = _b78_widest_emitted_hex_row()
    at = _b78_regime_probe(tmp_path, (_DIFF_MIN_W, 40))
    below = _b78_regime_probe(tmp_path, (_DIFF_MIN_W - 1, 40))

    assert not at["notice_shown"], (
        f"at exactly _DIFF_MIN_W the terminal is deliverable and must NOT show "
        f"the notice; regimes {at['regimes']}"
    )
    assert at["hex_a_width"] >= widest, (
        f"_DIFF_MIN_W is only the right floor if the window is unwrapped AT it: "
        f"{at['hex_a_width']} < {widest}"
    )
    assert below["notice_shown"], (
        f"one column below _DIFF_MIN_W the terminal is not deliverable and must "
        f"show the notice; regimes {below['regimes']}"
    )
    assert "width" in below["notice_text"], (
        f"the notice at the width boundary must name the width axis; "
        f"text={below['notice_text']!r}"
    )


def test_tc_b78_32_a_single_axis_failure_names_that_axis(tmp_path: Path) -> None:
    """TC-B78-32 - a one-axis failure names THAT axis and not the other.

    Intent: LLR-124.4 - the two conditions are independent, so a terminal that
    passes height and fails width must not be told about its height, and vice
    versa. This is the node that makes "every unsatisfied axis" mean something
    stronger than "all of them, always": it is the mapping, and C-78-xxiii is
    explicit that a mapping is tested by mutating to the WRONG element, not by
    blanking the output.

    Both arms are read per-arm (CC-1) - a single aggregate verdict over a
    predicate whose whole content is "these two cases differ" destroys exactly
    the information the node carries.
    """
    height_only = _b78_regime_probe(tmp_path, (120, _DIFF_MIN_H - 1))
    width_only = _b78_regime_probe(tmp_path, (_DIFF_MIN_W - 1, 40))

    assert 120 >= _DIFF_MIN_W, (
        f"precondition: the height-only arm must PASS the width axis, or it is "
        f"not a single-axis case; 120 < {_DIFF_MIN_W}"
    )
    assert 40 >= _DIFF_MIN_H, (
        f"precondition: the width-only arm must PASS the height axis; "
        f"40 < {_DIFF_MIN_H}"
    )

    height_text = height_only["notice_text"]
    assert height_only["notice_shown"], "the height-only arm must show the notice"
    assert "height" in height_text, (
        f"height-only arm: the notice must name the height axis; {height_text!r}"
    )
    assert "width" not in height_text, (
        f"height-only arm: the notice must NOT name the width axis, which this "
        f"terminal satisfies; {height_text!r}"
    )

    width_text = width_only["notice_text"]
    assert width_only["notice_shown"], "the width-only arm must show the notice"
    assert "width" in width_text, (
        f"width-only arm: the notice must name the width axis; {width_text!r}"
    )
    assert "height" not in width_text, (
        f"width-only arm: the notice must NOT name the height axis, which this "
        f"terminal satisfies; {width_text!r}"
    )


def test_tc_b78_33_the_regime_applies_with_no_comparison(tmp_path: Path) -> None:
    """TC-B78-33 - the regime applies before any comparison, and nothing raises.

    Intent: HLR-124's boundary catalog - "no comparison rendered: the regime
    still applies, nothing raises". The regime is a property of the terminal, not
    of the panel's contents, and the notice regime in particular has to be right
    on the empty panel: an operator who opens the diff screen at 80x24 and sees
    an empty box has been told nothing, which is the defect HLR-124 exists to
    fix - and that operator has not compared anything yet.

    Every other node in this block also runs without a comparison; this one says
    so as its subject rather than relying on it silently.
    """
    for size, expected in (
        (_B78_INC5_WIDE, "diff-wide"),
        ((_DIFF_WIDE_MIN - 1, 40), "diff-fallback"),
        (_B78_INC5_FLOOR, "diff-notice"),
    ):
        measured = _b78_regime_probe(tmp_path, size)
        assert measured["regimes"] == [expected], (
            f"{size} with no comparison rendered must select {expected}; "
            f"classes are {measured['regimes']}"
        )
        assert measured["notice_shown"] == (expected == "diff-notice"), (
            f"{size}: notice shown={measured['notice_shown']} for regime {expected}"
        )


def test_tc_b78_51_escape_dismisses_without_shadowing(tmp_path: Path) -> None:
    """TC-B78-51 - `escape` dismisses the overlay, and only where it should.

    Intent: spec Sec.8's A-2 - "the fallback overlay's dismissal mechanism,
    which must not shadow the palette's `escape`". Flagged `assumed - verify in
    target framework at Phase 3`, and C-78-xxii is explicit that an assumed item
    is closed by a predicate that can go red or it is not closed.

    Two directions, both executed:

    1. GATE. Focus inside the panel, overlay open -> `escape` dismisses it, and
       focus returns to where it was. The focus clause is not a courtesy: these
       bindings live on the panel, so they fire only while focus is inside it,
       and dismissing blurs the list. Executed without the restore, `f` after
       `escape` did nothing at all.
    2. PIN, and labelled one. With the command palette open its input holds
       focus, and `#palette_input` is not a descendant of `#ab_diff_panel`, so
       the panel's binding is not in that focus chain and the overlay stays open.
       This is invariant BY CONSTRUCTION - the reddening mutation would have to
       move the binding to the App or the Screen, which is a structural change,
       not a value substitution - so it is recorded as a regression pin and never
       counted as a discharged gate.

    Executed premise correction, reported rather than absorbed: A-2 and LLR-119.3
    both speak of "the palette's `escape`-to-close". THERE IS NONE.
    `command_bar.py` binds no key and handles no `escape`; the palette closes
    only via `_dispatch_palette_entry` and `on_list_view_selected`
    (`command_bar.py:279`, `:295`). Arm 2 therefore asserts what is actually
    true - that the panel's `escape` does not reach outside the panel - which is
    the property A-2 wanted, over a premise that does not hold.
    """
    from s19_app.tui.command_bar import CommandBar

    async def _after(app, pilot):
        panel = app.query_one("#ab_diff_panel")
        bar = app.query_one(CommandBar)
        listing = _b78_run_list(app)
        assert panel.has_class("diff-fallback"), (
            "precondition: the overlay exists only in the fallback regime"
        )
        assert listing.display, (
            "precondition: the driver must have opened the overlay through 'f'"
        )
        assert app.focused is listing, (
            f"precondition: opening the overlay must focus the list, or the "
            f"panel's bindings are not in the focus chain; focus is {app.focused!r}"
        )

        # Arm 1 - the gate.
        await pilot.press("escape")
        await pilot.pause()
        arm1 = (
            panel.has_class("runs-open"),
            listing.display,
            None if app.focused is None else app.focused.id,
            bar.palette_is_open,
        )

        # Arm 2 - the pin. Re-open, then hand focus to the palette.
        await _b78_open_run_list(app, pilot)
        await pilot.press("ctrl+k")
        await pilot.pause()
        focus_id = None if app.focused is None else app.focused.id
        await pilot.press("escape")
        await pilot.pause()
        arm2 = (focus_id, panel.has_class("runs-open"), bar.palette_is_open)
        return arm1, arm2

    runs = [(i * 0x100, i * 0x100 + 4, "changed") for i in range(4)]
    arm1, arm2 = _b78_drive_compare(
        tmp_path, _B78_AT_SIZE, _diff_result(runs), after=_after
    )

    open_after, shown_after, focus_after, palette_after = arm1
    assert not open_after, "escape must dismiss the run-list overlay"
    assert not shown_after, (
        "dismissing must actually hide the list, not only drop the class"
    )
    assert focus_after == "diff_compare_button", (
        f"dismissing must hand focus back to what held it, or the key that "
        f"opened the overlay can never reopen it; focus is {focus_after!r}"
    )
    assert not palette_after, (
        "the panel's escape must not have touched the command palette"
    )

    palette_focus, open_after_palette, palette_open = arm2
    assert palette_focus == "palette_input", (
        f"precondition: the palette must hold focus for this arm to be about "
        f"shadowing at all; focus is {palette_focus!r}"
    )
    assert open_after_palette, (
        "with focus in the palette the panel's escape binding must not fire - "
        "the overlay must still be open"
    )
    assert palette_open, (
        "executed premise: the palette has no escape-to-close on this branch, "
        "so there is nothing for the overlay's escape to shadow"
    )


def test_tc_b78_52_pagination_reaches_bytes_past_the_pane(tmp_path: Path) -> None:
    """TC-B78-52 - the selected run's bytes past the visible rows are reachable.

    Intent: LLR-124.3 - "the selected run's bytes beyond the visible rows shall
    be reachable by pagination". Inc-4 left this open by design (its R-6: a run
    longer than the pane overflows invisibly) and named Inc-5 as the owner.

    The fixture's run is deliberately far longer than any supported pane, so the
    un-paged window is bounded by the run +/- context FLOOR rather than by the
    pane, which is the only state in which anything is out of reach. The
    precondition is asserted: with a short run the whole window fits and every
    clause below would be vacuously true.

    Page 0 is asserted to be unchanged, because that is the clause that keeps
    every HLR-123 acceptance sound - AT-B78-22's exact address set is read from
    an un-paged window, and a pagination that re-based page 0 would silently
    move it.

    **Run at BOTH regimes, per-arm (CC-1), from the Inc-5 gate's F-2.** The first
    draft gated `[` / `]` on the fallback regime, which was a capability
    INVERSION: measured on this same run, the wide regime's capacity is 1 at both
    160x40 and 139x40 while 132x44's is 7, so the operator on the WIDEST
    supported terminal could see 1 of 66 rows with no key to reach the rest,
    while the one on a narrower terminal reached all of them. Overflow is a
    property of the run against the pane, never of the regime - so the fix
    REMOVED a condition, and this arm is what keeps it removed.
    """
    long_run = (0x1000, 0x1000 + 0x400, "changed")

    async def _after(app, pilot):
        first = _b78_window_rows(_b78_window_text(app, "#diff_hex_a"))
        capacity = app.query_one("#ab_diff_panel")._window_row_capacity()
        app.set_focus(app.query_one("#diff_compare_button"))
        await pilot.press("right_square_bracket")
        await pilot.pause()
        paged = _b78_window_rows(_b78_window_text(app, "#diff_hex_a"))
        paged_b = _b78_window_rows(_b78_window_text(app, "#diff_hex_b"))
        await pilot.press("left_square_bracket")
        await pilot.pause()
        back = _b78_window_rows(_b78_window_text(app, "#diff_hex_a"))
        # Paging past the end must be a no-op, not an empty window.
        for _ in range(200):
            await pilot.press("right_square_bracket")
        await pilot.pause()
        far = _b78_window_rows(_b78_window_text(app, "#diff_hex_a"))
        regimes = sorted(
            name
            for name in app.query_one("#ab_diff_panel").classes
            if name.startswith("diff-")
        )
        return first, capacity, paged, paged_b, back, far, regimes

    # Both regimes. The wide arm is the one F-2 added: same run, same clauses.
    for size, expected_regime in ((_B78_AT_SIZE, "diff-fallback"), (_B78_INC5_WIDE, "diff-wide")):
        (
            first, capacity, paged, paged_b, back, far, regimes
        ) = _b78_drive_compare(tmp_path, size, _diff_result([long_run]), after=_after)

        assert regimes == [expected_regime], (
            f"{size}: precondition - this arm must exercise the {expected_regime} "
            f"regime, or it is not the arm it claims to be; classes {regimes}"
        )
        assert capacity > 0, (
            f"{size}: precondition - the pane must have a positive row capacity, "
            f"or paging has no page size to move by"
        )
        assert len(first) > capacity, (
            f"{size}: precondition - the run must overflow the pane, or nothing "
            f"is out of reach and this arm tests nothing; the window emitted "
            f"{len(first)} rows into a capacity of {capacity}"
        )
        assert paged, f"{size}: a paged window must still render rows"
        assert paged[0] > first[0], (
            f"{size}: paging forward must move the window onto later bytes; "
            f"first row went 0x{first[0]:08X} -> 0x{paged[0]:08X}. A regime in "
            f"which ']' is inactive strands {len(first) - capacity} of "
            f"{len(first)} rows"
        )
        assert paged_b == paged, (
            f"{size}: both windows must page in lockstep - a diff whose columns "
            f"disagree on the address of a screen line is not a diff"
        )
        assert set(paged) - set(first[:capacity]), (
            f"{size}: paging must reach rows the first page did not show"
        )
        assert back == first, (
            f"{size}: paging back must return the un-paged window exactly; got "
            f"0x{back[0]:08X}..0x{back[-1]:08X} against 0x{first[0]:08X}.."
            f"0x{first[-1]:08X}"
        )
        assert far, f"{size}: paging past the last page must be a no-op, not empty"
        assert far[-1] <= first[-1], (
            f"{size}: paging must stay inside the run's own window; it reached "
            f"0x{far[-1]:08X} against a window ending at 0x{first[-1]:08X}"
        )


def test_tc_b78_53_the_overlay_reserves_no_width(tmp_path: Path) -> None:
    """TC-B78-53 - the run-list overlay costs the window nothing, open or shut.

    Intent: LLR-124.3 - "the run list shall be presented without permanently
    reserving columns or rows from it". The word doing the work is *permanently*,
    but the honest reading is stronger and is what is implemented: the overlay
    sits on its own CSS layer, so the window column keeps the full content width
    even while the list is on top of it.

    Asserted as an EQUALITY between the closed and open states, not as a
    threshold. A `>= widest` clause in both states would pass an implementation
    that shrinks the window by ten columns while the overlay is open, which is
    exactly the "temporarily reserves" design this clause rules out.
    """
    widest = _b78_widest_emitted_hex_row()

    async def _opened(app, pilot):
        panel = app.query_one("#ab_diff_panel")
        panel.action_close_run_overlay()
        await pilot.pause()
        closed_width = app.query_one("#diff_hex_a").size.width
        await _b78_open_run_list(app, pilot)
        listing = _b78_run_list(app)
        return (
            closed_width,
            app.query_one("#diff_hex_a").size.width,
            listing.display,
            listing.size.width,
        )

    runs = [(i * 0x100, i * 0x100 + 4, "changed") for i in range(4)]
    closed_width, open_width, list_shown, list_width = _b78_drive_compare(
        tmp_path, _B78_AT_SIZE, _diff_result(runs), after=_opened
    )

    assert list_shown and list_width > 0, (
        f"precondition: the overlay must actually be showing something, or "
        f"'costs nothing' is trivially true; shown={list_shown} "
        f"width={list_width}"
    )
    assert open_width == closed_width, (
        f"the overlay must not take columns from the window: #diff_hex_a is "
        f"{closed_width} closed and {open_width} open"
    )
    assert open_width >= widest, (
        f"and the width it keeps must still be an unwrapped one: {open_width} "
        f"< {widest}"
    )


def test_tc_b78_54_the_height_floor_delivers_a_hex_row(tmp_path: Path) -> None:
    """TC-B78-54 - the height floor is only right if a HEX ROW is visible AT it.

    Intent: the sibling clause for `_DIFF_MIN_H` that `TC-B78-31` already carries
    for `_DIFF_MIN_W` ("the floor is only the right floor if the window is
    unwrapped AT it"). Minted at the Inc-5 gate, where its absence was the
    compounding half of F-1: **the height axis was the one axis this increment
    changed and the only regime axis with no boundary node**, and `TC-B78-32`'s
    height arm sits at `_DIFF_MIN_H - 1` and asserts only that a notice appears.
    Applying `TC-B78-31`'s own standard to the height axis is what surfaces the
    defect, and it would have failed.

    Why the metric is HEX ROWS and not painted content rows: `_render_run_windows`
    writes `f"Image A - {header}\\n{text}"`, so screen line 0 is the header and a
    painted content height of 1 delivers ZERO bytes. Shipped against the weaker
    metric, heights 26-27 declared the terminal deliverable, HID the notice, and
    showed a header and nothing else - strictly worse than 25, where the operator
    is at least told why. The spec carries both metrics (Sec.2.8 D-1's "one
    visible content row" against normative `LLR-125.2`'s "one hex row of
    content"); `LLR-125.2` governs and this node is what holds the line.

    The fixture's run is longer than any supported pane, so the window is never
    the binding limit and what is measured is the PANE's budget, not the run's.
    Both sides are read, as `TC-B78-31` does for the width axis.
    """
    long_run = [(0x1000, 0x1000 + 0x400, "changed")]

    async def _measure(app, pilot):
        from textual.widgets import Static

        window = app.query_one("#diff_hex_a", Static)
        rows = _b78_window_rows(str(window.render()))
        painted = _b78_painted_content_height(window)
        return {
            "regimes": sorted(
                name
                for name in app.query_one("#ab_diff_panel").classes
                if name.startswith("diff-")
            ),
            "notice_shown": app.query_one("#diff_size_notice").display,
            "painted": painted,
            "emitted": len(rows),
            "visible_hex": max(0, min(painted - _B78_WINDOW_HEADER_ROWS, len(rows))),
        }

    async def _after(app, pilot):
        await _b78_hide_command_bar(app, pilot)
        return await _measure(app, pilot)

    at = _b78_drive_compare(
        tmp_path, (120, _DIFF_MIN_H), _diff_result(long_run), after=_after
    )
    below = _b78_regime_probe(tmp_path, (120, _DIFF_MIN_H - 1))

    # Precondition: the run must overflow the pane, or the pane is not what is
    # being measured and the floor could be an artefact of a short fixture.
    assert at["emitted"] > at["visible_hex"], (
        f"precondition: the fixture's run must exceed the pane at the floor, or "
        f"this node measures the RUN and not the pane; emitted {at['emitted']}, "
        f"visible {at['visible_hex']}"
    )

    # --- AT the floor: deliverable, and it actually delivers ---
    assert at["regimes"] == ["diff-fallback"], (
        f"at exactly _DIFF_MIN_H the terminal must be deliverable; classes are "
        f"{at['regimes']}"
    )
    assert not at["notice_shown"], (
        "at exactly _DIFF_MIN_H the terminal is deliverable and must NOT show "
        "the notice"
    )
    assert at["visible_hex"] >= 1, (
        f"_DIFF_MIN_H is only the right floor if at least one HEX ROW is visible "
        f"AT it: painted content height {at['painted']}, of which "
        f"{_B78_WINDOW_HEADER_ROWS} is the 'Image A - Run #...' header, leaving "
        f"{at['visible_hex']} hex rows. A floor that declares a terminal "
        f"deliverable and then shows a header and nothing else is WORSE than the "
        f"notice it replaces"
    )

    # --- BELOW the floor: the notice, naming this axis ---
    assert below["notice_shown"], (
        f"one row below _DIFF_MIN_H the terminal is not deliverable and must "
        f"show the notice; regimes {below['regimes']}"
    )
    assert "height" in below["notice_text"], (
        f"the notice at the height boundary must name the height axis; "
        f"text={below['notice_text']!r}"
    )


# ---------------------------------------------------------------------------
# batch-79 Inc-6 -- HLR-126 discoverability (LLR-126.1)
# ---------------------------------------------------------------------------


def _b79_painted_text(app, widget) -> str:
    """The text actually PAINTED in a widget's region, read from the compositor.

    ``str(widget.render())`` is not usable here: the ``HelpPanel`` renders a
    ``rich.table.Table`` object, so the string form is a repr and every ``in``
    assertion over it is vacuous. This reads the composited screen and slices
    the widget's own region out of it, which is what the operator sees.
    """
    strips = app.screen._compositor.render_strips()
    region = widget.region
    lines = []
    for y in range(region.y, min(region.y + region.height, len(strips))):
        row = "".join(segment.text for segment in strips[y])
        lines.append(row[region.x : region.x + region.width].rstrip())
    return "\n".join(lines)


def _b79_help_focused_section(app) -> str:
    """The FIRST block of the help panel -- the FOCUSED widget's own bindings.

    Measured, not assumed (C-35): with the run list focused the panel paints the
    list's own three bindings first, then a blank line, then the ancestor
    panel's ``[`` / ``]``, then screen- and app-level blocks. The blank line is
    the section boundary, so the negative co-assertion has something real to be
    absent FROM -- ``AT-B78-28`` would otherwise be green on a panel that lists
    every binding in the application.
    """
    from textual.widgets import HelpPanel

    panel = app.screen.query_one(HelpPanel)
    text = _b79_painted_text(app, panel)
    # Strip the panel's painted left border before looking for blank lines. The
    # glyph is U+258F LEFT ONE EIGHTH BLOCK, not the U+2502 box-drawing bar a
    # reader reaches for first -- and with the wrong glyph NO line is ever
    # blank, the whole panel reads as one section, and the positive clauses go
    # green against every binding in the application. Not hypothetical: that is
    # what this helper did on its first run, and the negative co-assertion in
    # `AT-B78-28` is what caught it.
    body = [
        line.lstrip("▏│┃▕▐| \t").rstrip()
        for line in text.splitlines()
    ]
    section: list[str] = []
    started = False
    for line in body:
        if not line:
            if started:
                break
            continue
        started = True
        section.append(line)
    return "\n".join(section)


def _b79_shown_keys(app) -> list[str]:
    """The model key set: bindings that are both ``show`` and ``enabled``."""
    return sorted(
        key
        for key, active in app.active_bindings.items()
        if getattr(active.binding, "show", False) and getattr(active, "enabled", True)
    )


#: LLR-126.1's committed pre-change chip set (spec P-51), frozen here rather
#: than recomputed, so the assertion is SET-EQUALITY against a constant. A
#: containment predicate is satisfied by a superset -- executed at batch-78:
#: ``+1 chip -> contains-all True, set-equality False`` -- so containment cannot
#: gate "the footer-visible binding set shall be unchanged".
_B79_COMMITTED_SHOWN_KEYS: tuple[str, ...] = (
    "comma",
    "ctrl+d",
    "ctrl+k",
    "ctrl+l",
    "ctrl+s",
    "g",
    "k",
    "minus",
    "period",
    "plus",
    "q",
    "question_mark",
    "slash",
    "x",
)


def _b79_app_binding_rows() -> frozenset:
    """The App ``BINDINGS`` block as a comparable set of rows.

    Resolved from the CLASS, not from a line range. See
    ``test_at_b78_32_app_bindings_block_is_untouched`` for why that distinction
    is the whole point of this node.
    """
    from textual.binding import Binding

    from s19_app.tui.app import S19TuiApp

    rows = set()
    for entry in S19TuiApp.BINDINGS:
        if isinstance(entry, Binding):
            rows.add((entry.key, entry.action, entry.description, bool(entry.show)))
        else:
            key, action, description = entry
            rows.add((key, action, description, True))
    return frozenset(rows)


#: The committed App binding set: 38 entries -- 31 written as ``Binding(...)``
#: and 7 as bare tuples. Frozen as a COUNT plus the shown-key projection rather
#: than 38 literal rows, because the full row set is `app.py`'s business and
#: this batch's claim is only that Lane 1 does not disturb it.
#: The committed App binding set, FULL ROWS. See the assertion in
#: `test_at_b78_32_...` for why a count plus a key-only projection was not
#: enough. 38 entries: 31 written as `Binding(...)`, 7 as bare tuples.
_B79_COMMITTED_APP_BINDING_ROWS: frozenset = frozenset({
    ('0', "show_screen('crc_designer')", 'CRC Designer', False),
    ('1', "show_screen('workspace')", 'Workspace', False),
    ('2', "show_screen('a2l')", 'A2L Explorer', False),
    ('3', "show_screen('mac')", 'MAC View', False),
    ('4', "show_screen('map')", 'Memory Map', False),
    ('5', "show_screen('issues')", 'Issues Report', False),
    ('6', "show_screen('patch')", 'Patch Editor', False),
    ('7', "show_screen('diff')", 'A2B Diff', False),
    ('8', "show_screen('flow')", 'Flow Builder', False),
    ('9', "show_screen('checks')", 'Checks', False),
    ('U', 'unload_all', 'Unload all', False),
    ('b', 'before_after_report', 'Before/After report', False),
    ('comma', 'hex_page_prev', 'Hex-', True),
    ('ctrl+d', 'cycle_density', 'Density', True),
    ('ctrl+k', 'focus_palette', 'Palette', True),
    ('ctrl+l', 'load_file', 'Load', True),
    ('ctrl+s', 'save_project', 'Save', True),
    ('ctrl+y', 'patch_redo', 'Redo', False),
    ('ctrl+z', 'patch_undo', 'Undo', False),
    ('g', 'focus_goto', 'Go-to', True),
    ('j', 'dump_a2l_json', 'Dump A2L JSON', False),
    ('k', 'show_legend', 'Legend', True),
    ('l', 'load_file', 'Load file', False),
    ('minus', 'page_prev_context', 'Page-', True),
    ('o', 'open_workarea', 'Open workarea', False),
    ('p', 'load_project', 'Load project', False),
    ('pagedown', 'page_down_context', 'Page+', False),
    ('pageup', 'page_up_context', 'Page-', False),
    ('period', 'hex_page_next', 'Hex+', True),
    ('plus', 'page_next_context', 'Page+', True),
    ('q', 'quit', 'Quit', True),
    ('question_mark', 'show_help_panel', 'Help', True),
    ('r', 'refresh_files', 'Refresh workarea', False),
    ('s', 'save_project', 'Save project', False),
    ('slash', 'focus_find', 'Find', True),
    ('t', 'view_reports', 'View reports', False),
    ('v', 'select_variant', 'Select variant', False),
    ('x', 'operations_view', 'Operations', True),
})

_B79_COMMITTED_APP_BINDING_COUNT = 38


def test_at_b78_28_run_list_keys_are_discoverable(tmp_path: Path) -> None:
    """AT-B78-28 (GATE) -- LLR-126.1, all three clauses.

    The operator who has never used the diff screen can find out how to walk the
    runs without reading source: the list itself names the keys, and the help
    panel lists them under the FOCUSED widget -- while the Footer's chip set is
    untouched.

    C-40, and it is the reason this node is shaped the way it is:

    * *"the help panel names the keys"* is GREEN on a panel that lists every
      binding in the application, so the arm reads only the FOCUSED SECTION and
      co-asserts that a key the run list does NOT bind is absent from it. The
      ancestor panel's ``]`` (*Window page +*) is exactly such a key: it is
      reachable while the list is focused, it IS in the panel, and it is NOT in
      the list's own section.
    * The chip clause is SET-EQUALITY, never containment -- a superset satisfies
      containment, which is the failure mode a new shown binding would produce.
    * Assertions are on the binding DESCRIPTIONS, not on the key column: the
      key column paints arrow GLYPHS, and a predicate over those is a predicate
      over the emitted encoding rather than over the behaviour.
    """
    from s19_app.tui.screens_directionb import AbDiffPanel

    async def _after(app, pilot):
        listing = _b78_run_list(app)
        listing.focus()
        await pilot.pause()
        assert app.focused is listing, (
            f"the run list must hold focus for this AT to mean anything; "
            f"focused={app.focused!r}"
        )

        list_text = _b78_run_list_text(app)
        shown_before = _b79_shown_keys(app)

        await pilot.press("question_mark")
        await pilot.pause()
        from textual.widgets import HelpPanel

        section = _b79_help_focused_section(app)
        full_panel = _b79_painted_text(app, app.screen.query_one(HelpPanel))
        return list_text, shown_before, section, full_panel

    list_text, shown_keys, section, full_panel = _b78_drive_compare(
        tmp_path,
        (160, 40),
        _diff_result([(0x00, 0x0F, "changed"), (0x20, 0x2F, "added")]),
        after=_after,
    )

    # Clause 1 -- the list carries the visible affordance, asserted against the
    # EMITTED constant rather than a re-typed copy of the requirement's wording.
    #
    # C-31: reading the constant is what keeps the predicate honest about the
    # emitted string, but it also makes the constant an ORACLE -- and an
    # unguarded oracle is where this predicate could go vacuous. Emptied to
    # `""`, `"" in list_text` is trivially True and the affordance could vanish
    # with the node still green. So the oracle is guarded before it is used,
    # against the REQUIREMENT ("naming its navigation keys"), not against its
    # own current wording.
    affordance = AbDiffPanel._RUN_LIST_AFFORDANCE
    assert affordance.strip(), "the affordance constant is empty -- clause 1 would be vacuous"
    # `Enter` was in this tuple until the independent review. It made the node
    # REQUIRE a false claim: `Enter` is a no-op on this list and the spec
    # excludes the capability three times over (P-43, HLR-126's rationale, §1.2
    # Scope Out). A guard that pins the wrong contract actively resists its own
    # correction, which is worse than no guard.
    for key_word in ("Up", "Down"):
        assert key_word in affordance, (
            f"LLR-126.1's affordance must NAME the navigation keys; "
            f"{key_word!r} missing from {affordance!r}"
        )

    assert affordance in list_text, (
        f"the run list must carry LLR-126.1's affordance; "
        f"expected {AbDiffPanel._RUN_LIST_AFFORDANCE!r} in:\n{list_text}"
    )

    # Clause 2 -- the help panel names the FOCUSED list's own navigation keys...
    for description in ("Cursor up", "Cursor down", "Select"):
        assert description in section, (
            f"the help panel's focused section must name the run list's "
            f"{description!r} binding; section=\n{section}"
        )

    # ...and the negative co-assertion, without which clause 2 is vacuous.
    # The PRECONDITION comes first, and it is what makes the guard
    # self-checking instead of size-dependent. The independent review measured
    # this helper at all three supported sizes: at 120x30 the separator line
    # carries a scrollbar glyph so it is NOT blank and the boundary is MISSED;
    # at 80x24 the panel is clipped and `Window page` is absent from it
    # entirely, so `not in section` is trivially true. A discriminator that is
    # not present cannot discriminate — asserting it IS in the full panel turns
    # both failure modes loud instead of silently green.
    assert "Window page" in full_panel, (
        "the co-assertion below is vacuous: its discriminator is not in the "
        f"panel at all, so 'not in section' proves nothing.\npanel=\n{full_panel}"
    )
    assert "Window page" not in section, (
        "the focused section must list the RUN LIST's bindings, not its "
        "ancestor panel's window paging -- if 'Window page' appears here the "
        "section boundary was not found and the positive clauses above are "
        f"green against the whole panel; section=\n{section}"
    )

    # Clause 3 -- the footer-visible set is UNCHANGED, by set-equality.
    assert tuple(shown_keys) == _B79_COMMITTED_SHOWN_KEYS, (
        f"the shown+enabled key set must be SET-EQUAL to its committed "
        f"pre-change set of {len(_B79_COMMITTED_SHOWN_KEYS)}; "
        f"observed {len(shown_keys)}: {shown_keys}"
    )


def test_at_b78_32_app_bindings_block_is_untouched(tmp_path: Path) -> None:
    """AT-B78-32 (PIN) -- Lane 1 does not disturb the App ``BINDINGS`` block.

    RE-AUTHORED at batch-79 Phase 0, and the reason is the point of the node.

    The batch-78 spec realizes this as *"a zero-line ``git diff`` over
    ``app.py:1338-1375``"*. Executed against the tree, the block is
    ``app.py:1338-1392``: line 1375 is ``("minus", "page_prev_context",
    "Page-")``, MID-BLOCK, and lines 1376-1392 hold six real bindings --
    ``comma`` / ``period`` hex paging, ``pagedown`` / ``pageup`` from batch-31
    AC-3, and ``ctrl+z`` / ``ctrl+y`` from batch-40 S2. A binding added or
    removed among those six leaves the range-based predicate GREEN, so the guard
    would report "untouched" for a block that was touched. It fails in the
    safe-looking direction.

    It is not drift: at ``f6ff1d3`` the block was ALREADY 1338-1392 and batch-78
    added zero ``Binding(`` lines. The range was wrong when it was written and
    survived three Phase-2 rounds -- because a line range looks like a
    measurement. ``screens_directionb.py:6712`` carries the CORRECT extent in a
    code comment, so the two artifacts disagreed and the code was right.

    A corrected range would not fix this. Any edit ABOVE the block shifts it, so
    ``1338-1392`` is one insertion away from failing the same silent way. This
    resolves the block from the CLASS instead, which no line movement can blind,
    and pins two independent projections of it.
    """
    rows = _b79_app_binding_rows()

    # The FULL row set, frozen. The node pinned only a count plus a key-only
    # projection of the shown bindings until the independent review measured the
    # blind spot: 24 of the 38 entries are `show=False`, so their key, action
    # and description were certified by the count alone. Executed, all three of
    # these stayed GREEN — a hidden binding's action rebound, a hidden binding's
    # key changed, and one hidden removed while another was added. The shown
    # projection kept only `key`, so **re-pointing `slash` or `g` to a different
    # action — precisely what Lane 1 does at Inc-9 — was invisible too.**
    #
    # The spec's line-range predicate would have caught every one of those. The
    # re-authoring is still right about range fragility, but it was not the
    # strict improvement the Inc-6 record claimed: its counterfactual was an
    # ADDITION, the one class a count can see. A frozen row set is a superset of
    # both old projections and no line movement blinds it.
    assert rows == _B79_COMMITTED_APP_BINDING_ROWS, (
        "the App BINDINGS block must be byte-for-byte the committed set. "
        f"Added: {sorted(rows - _B79_COMMITTED_APP_BINDING_ROWS)!r}; "
        f"removed: {sorted(_B79_COMMITTED_APP_BINDING_ROWS - rows)!r}"
    )

    assert len(rows) == _B79_COMMITTED_APP_BINDING_COUNT, (
        f"the App BINDINGS block must still carry "
        f"{_B79_COMMITTED_APP_BINDING_COUNT} entries; observed {len(rows)}. "
        f"Lane 1 re-homes `/` and `g` onto the SCREENS (HLR-119) and deletes "
        f"the command bar (HLR-118) -- neither touches this block."
    )

    shown = tuple(sorted(key for key, _action, _desc, show in rows if show))
    assert shown == _B79_COMMITTED_SHOWN_KEYS, (
        f"the App block's shown-key projection must be SET-EQUAL to the "
        f"committed set; observed {list(shown)}"
    )


def test_tc_b78_38_help_panel_before_any_comparison_does_not_raise(
    tmp_path: Path,
) -> None:
    """TC-B78-38 -- boundary: the help panel opens with no comparison rendered.

    The run list is empty before the first Compare, so the affordance row does
    not exist yet -- LLR-126.1's affordance rides with the runs it describes.
    What is asserted here is that the discoverability surface is still SAFE in
    that state: the panel mounts, paints, and lists the app's bindings.
    """
    from textual.widgets import HelpPanel

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("diff")
            await pilot.pause()
            _b78_run_list(app).focus()
            await pilot.pause()
            await pilot.press("question_mark")
            await pilot.pause()
            panel = app.screen.query_one(HelpPanel)
            return _b79_painted_text(app, panel), _b79_shown_keys(app)

    text, shown = asyncio.run(_drive())

    assert text.strip(), "the help panel painted nothing over an empty run list"
    assert tuple(shown) == _B79_COMMITTED_SHOWN_KEYS, (
        f"the chip set must be unchanged in the pre-comparison state too; "
        f"observed {shown}"
    )


def test_tc_b78_39_help_panel_toggles_closed_and_reopens(tmp_path: Path) -> None:
    """TC-B78-39 -- boundary: opened, dismissed, re-opened.

    ``action_show_help_panel`` is this project's TOGGLE override (`app.py:5877`,
    not the `:5836` the spec cites) rather than the stock mount-only action, so
    the second press must REMOVE the panel and the third must bring it back. A
    node that only opened it would leave the override's whole reason untested.
    """
    from textual.widgets import HelpPanel

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("diff")
            await pilot.pause()
            counts = []
            for _ in range(3):
                await pilot.press("question_mark")
                await pilot.pause()
                counts.append(len(app.screen.query(HelpPanel)))
            return counts

    counts = asyncio.run(_drive())

    assert counts == [1, 0, 1], (
        f"`?` must toggle the help panel open/closed/open; mounted counts "
        f"across three presses were {counts}"
    )
