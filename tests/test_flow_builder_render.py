"""Flow Builder Direction-A "Pipeline Ledger" render — batch-51 Inc-2 (R-TUI-088).

Black-box ATs drive the SHIPPED panel surface (the rail-8 ``#screen_flow`` Run
button → ``run_flow`` → ``FlowBuilderPanel.render_result``) through a Textual
``Pilot``; white-box TCs pin the LLR-088.* mechanisms. The engine keel is Inc-1
(``test_flow_execution_service.py``); this file observes the RENDER.

Reuses the Inc-1 fixture helpers (``_make_project`` / ``_S19_CLEAN`` /
``_S19_ONE_ERROR`` / ``_check_doc``) so the panel renders exactly the runs the
engine tests exercise. Rail-nav Pilot idiom mirrors ``test_tui_checks_screen``.
"""

from __future__ import annotations

import ast
import asyncio
import inspect
import textwrap
from pathlib import Path

from textual.widgets import Button, Select, Static

from s19_app.tui.app import S19TuiApp
from s19_app.tui.screens_directionb import (
    FlowBuilderPanel,
    _BLOCK_STATUS_SEV_CLASS,
    _flow_block_label,
    _make_flow_block,
    _memory_ribbon_text,
)
from s19_app.tui.services.flow_execution_service import run_flow
from s19_app.tui.services.flow_model import (
    BLOCK_CHECK,
    BLOCK_SOURCE,
    BLOCK_STATUS_ERROR,
    BLOCK_STATUS_NOTICES,
    BLOCK_STATUS_OK,
    BLOCK_STATUS_SKIPPED,
    CHECK_GATING_BLOCK_OWN,
    FLOW_STATUS_ERROR,
    FLOW_STATUS_ISSUES,
    FLOW_STATUS_OK,
    BlockResult,
    CheckBlock,
    Finding,
    Flow,
    FlowContext,
    FlowRunResult,
    PatchBlock,
    SourceBlock,
    WriteOutBlock,
)
from tests.test_flow_execution_service import (
    _S19_CLEAN,
    _S19_ONE_ERROR,
    _check_doc,
    _make_project,
)

_HOSTILE = "[bold red]sensor\x1b[31m[/]x[link=file:///etc/passwd]"


# ---------------------------------------------------------------------------
# Pilot driver: mount the app, activate rail-8, set the project, run a flow
# through the REAL #flow_run button, return the mounted app for querying.
# ---------------------------------------------------------------------------


async def _run_in_panel(app: S19TuiApp, pilot, project: Path, blocks) -> None:
    """Compose ``blocks`` into the panel and press the real Run button."""
    app.current_project_dir = project
    await pilot.press("8")
    await pilot.pause()
    panel = app.query_one("#flow_panel", FlowBuilderPanel)
    panel._blocks = list(blocks)
    app.query_one("#flow_run", Button).press()  # the real Run button
    await pilot.pause()
    await pilot.pause()


def _nodes(app: S19TuiApp):
    return list(app.query("#flow_result .flow-node"))


def _seps(app: S19TuiApp):
    return list(app.query("#flow_result .flow-sep"))


# ===========================================================================
# LLR-088.1 — block-status → sev-* class map (unit, no app)
# ===========================================================================


def test_tc088_1_status_class_map_covers_every_status() -> None:
    """TC-088.1 (LLR-088.1): every ``BLOCK_STATUS_*`` token maps to an existing
    frozen ``.sev-*`` class; the map lives in ``screens_directionb`` (not the
    frozen ``color_policy.py``)."""
    frozen_sev = {"sev-ok", "sev-warning", "sev-error", "sev-neutral"}
    for status in (
        BLOCK_STATUS_OK,
        BLOCK_STATUS_NOTICES,
        BLOCK_STATUS_ERROR,
        BLOCK_STATUS_SKIPPED,
    ):
        assert status in _BLOCK_STATUS_SEV_CLASS, status
        assert _BLOCK_STATUS_SEV_CLASS[status] in frozen_sev
    assert _BLOCK_STATUS_SEV_CLASS[BLOCK_STATUS_OK] == "sev-ok"
    assert _BLOCK_STATUS_SEV_CLASS[BLOCK_STATUS_NOTICES] == "sev-warning"
    assert _BLOCK_STATUS_SEV_CLASS[BLOCK_STATUS_ERROR] == "sev-error"
    assert _BLOCK_STATUS_SEV_CLASS[BLOCK_STATUS_SKIPPED] == "sev-neutral"


# ===========================================================================
# AT-088a — full Direction-A structure over a real run, all 3 banner states
# ===========================================================================


def test_at088a_pipeline_ledger_structure_all_three_banners(tmp_path: Path) -> None:
    """AT-088a (black-box, US-088): over a real run the panel renders one node
    per BlockResult (count derived from ``block_results``, C-31), an ``N-1``
    separator run, each node's correct ``sev-*`` gutter class, the ribbon, and a
    banner whose text + class match the run status — driven for CLEAN, ISSUES
    (LOAD→CHECK→WRITE-OUT), and FAILED (LLR-088.2/.3/.4/.5).
    """
    project = _make_project(
        tmp_path,
        {
            "clean.s19": _S19_CLEAN,
            "warn.s19": _S19_ONE_ERROR,
            "checks.json": _check_doc(
                [{"type": "bytes", "address": "0x9000", "bytes": "AA"}]
            ),
        },
    )

    cases = {
        FLOW_STATUS_OK: (
            [SourceBlock("clean.s19"), WriteOutBlock("out_ok.s19")],
            "CLEAN",
            "sev-ok",
        ),
        FLOW_STATUS_ISSUES: (
            [
                SourceBlock("warn.s19"),
                CheckBlock("missing.json", gating=CHECK_GATING_BLOCK_OWN),
                WriteOutBlock("out_iss.s19"),
            ],
            "ISSUES",
            "sev-warning",
        ),
        FLOW_STATUS_ERROR: (
            [
                SourceBlock("clean.s19"),
                PatchBlock("missing.json"),
                WriteOutBlock("out_fail.s19"),
            ],
            "FAILED",
            "sev-error",
        ),
    }

    async def _drive(blocks):
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            await _run_in_panel(app, pilot, project, blocks)
            nodes = _nodes(app)
            node_sev = [
                next(
                    (c for c in n.classes if c.startswith("sev-")), None
                )
                for n in nodes
            ]
            sep_count = len(_seps(app))
            banner = app.query_one("#flow_result .flow-banner", Static)
            banner_text = banner.render().plain
            banner_sev = next(
                (c for c in banner.classes if c.startswith("sev-")), None
            )
            ribbon = app.query("#flow_result .flow-ribbon")
            return (
                len(nodes),
                node_sev,
                sep_count,
                banner_text,
                banner_sev,
                len(ribbon),
            )

    for status, (blocks, want_text, want_class) in cases.items():
        expected = run_flow(
            Flow(name="e", blocks=blocks), FlowContext(project_dir=project)
        )
        assert expected.status == status  # fixture sanity — the intended run
        (
            node_count,
            node_sev,
            sep_count,
            banner_text,
            banner_sev,
            ribbon_count,
        ) = asyncio.run(_drive(blocks))

        # LLR-088.2 — one node per BlockResult (count derived, not hand-typed).
        assert node_count == len(expected.block_results), status
        # LLR-088.3 — exactly N-1 separators.
        assert sep_count == len(expected.block_results) - 1, status
        # LLR-088.1/.2 — each node's gutter carries the mapped sev-* class.
        want_node_sev = [
            _BLOCK_STATUS_SEV_CLASS[br.status] for br in expected.block_results
        ]
        assert node_sev == want_node_sev, status
        # LLR-088.4 — the single ribbon renders.
        assert ribbon_count == 1, status
        # LLR-088.5 — banner text + class match the run status.
        assert banner_text == want_text, status
        assert banner_sev == want_class, status


def test_at088a_single_block_has_no_dangling_separator(tmp_path: Path) -> None:
    """AT-088a boundary (LLR-088.3): a single-block flow renders one node and
    ZERO separators (no trailing separator after the last node)."""
    project = _make_project(tmp_path, {"prg.s19": _S19_CLEAN})

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            await _run_in_panel(app, pilot, project, [SourceBlock("prg.s19")])
            return len(_nodes(app)), len(_seps(app))

    node_count, sep_count = asyncio.run(_drive())
    assert node_count == 1
    assert sep_count == 0


def test_at085a_notices_load_shows_warning_gutter(tmp_path: Path) -> None:
    """AT-085a re-observed THROUGH the render (US-085): a LOAD over an
    integrity-flagged image shows the LOAD node with the ``sev-warning`` gutter
    and a finding line carrying the WARN text — the notices cue is visible."""
    project = _make_project(tmp_path, {"warn.s19": _S19_ONE_ERROR})

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            await _run_in_panel(
                app,
                pilot,
                project,
                [SourceBlock("warn.s19"), WriteOutBlock("out.s19")],
            )
            load_node = _nodes(app)[0]
            findings = list(
                load_node.query(".flow-finding")
            )
            finding_text = findings[0].render().plain if findings else ""
            banner = app.query_one("#flow_result .flow-banner", Static)
            return (
                load_node.has_class("sev-warning"),
                len(findings),
                finding_text,
                banner.render().plain,
            )

    warn_gutter, n_findings, finding_text, banner_text = asyncio.run(_drive())
    assert warn_gutter, "the notices LOAD node must carry sev-warning"
    assert n_findings >= 1
    assert "line" in finding_text  # the WARN message names the numeric line
    assert banner_text == "ISSUES"  # AT-087a observation surface


# ===========================================================================
# LLR-088.4 — ribbon geometry, MEASURED at 80×24 and wide (C-13/C-23/C-29)
# ===========================================================================


def test_ribbon_geometry_measured_no_overflow(tmp_path: Path) -> None:
    """LLR-088.4 (C-29): the ribbon strip fits the MEASURED ``#flow_result``
    content width at the 80×24 floor AND a wide regime with no horizontal
    overflow — re-measured in the mounted panel, not inherited (C-16)."""
    project = _make_project(tmp_path, {"prg.s19": _S19_CLEAN})

    async def _drive(size):
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            await _run_in_panel(
                app,
                pilot,
                project,
                [SourceBlock("prg.s19"), WriteOutBlock("out.s19")],
            )
            box = app.query_one("#flow_result")
            ribbon = app.query_one("#flow_result .flow-ribbon", Static)
            return box.content_size.width, ribbon.region.width

    for size in ((80, 24), (120, 30)):
        content_w, ribbon_w = asyncio.run(_drive(size))
        assert ribbon_w <= content_w, (size, ribbon_w, content_w)
        assert ribbon_w > 0, size


def test_tc088_4_ribbon_encodes_footprint() -> None:
    """TC-088.4 (LLR-088.4): the ribbon strip is the measured cell width, is all
    filled for one contiguous range, and is empty for no image (int-derived —
    no markup sink)."""
    full = _memory_ribbon_text([(0x1000, 0x2000)], cells=48)
    assert len(full.plain) == 48
    assert set(full.plain) == {"█"}  # one contiguous range → fully mapped
    assert full.spans == []
    # a gap between two ranges shows at least one gap glyph.
    gapped = _memory_ribbon_text([(0x0, 0x10), (0xF000, 0xF010)], cells=48)
    assert "░" in gapped.plain
    # no image → empty strip.
    assert _memory_ribbon_text([], cells=48).plain == ""


# ===========================================================================
# AT-088b — per-sink markup safety (C-17 / C-31), spans==[] AND plain verbatim
# ===========================================================================


def test_at088b_every_render_sink_renders_hostile_literally(tmp_path: Path) -> None:
    """AT-088b (black-box, US-088, C-17): a hostile bracket/ANSI payload placed
    in EACH file-derived render sink renders literally — ``plain`` verbatim AND
    ``spans == []`` per sink. The sink set is CODE-DERIVED (C-31): the number of
    ``# SINK:`` call-site markers in ``render_result`` must equal the number of
    sink categories this test exercises, so a new unswept sink fails the count.
    """
    # crafted result carrying the payload in every file-derived sink at once.
    # The written-path sink renders ``str(Path(...))``; on Windows ``Path``
    # normalises the separators, so its EXPECTED plain is the stringified path
    # (the markup chars — brackets + ANSI — still survive, so the spans==[]
    # neutralisation is what that sink proves).
    hostile_path = Path(_HOSTILE)
    expected = {
        "summary": _HOSTILE,
        "finding": _HOSTILE,
        "diagnostic": _HOSTILE,
        "written-path": str(hostile_path),
        "flow-diagnostic": _HOSTILE,
    }
    result = FlowRunResult(
        status=FLOW_STATUS_ISSUES,
        block_results=[
            BlockResult(
                index=0,
                kind="check",
                status=BLOCK_STATUS_NOTICES,
                summary=_HOSTILE,  # SINK: summary (the CHECK-report node)
                diagnostics=[_HOSTILE],  # SINK: diagnostic
                findings=[Finding("warn", _HOSTILE)],  # SINK: finding message
            )
        ],
        written_paths=[hostile_path],  # SINK: written path
        diagnostics=[_HOSTILE],  # SINK: flow-diagnostic
    )

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            await pilot.press("8")
            await pilot.pause()
            panel = app.query_one("#flow_panel", FlowBuilderPanel)
            panel.render_result(result)
            await pilot.pause()
            await pilot.pause()
            sinks = {
                "summary": ".flow-node-summary",
                "finding": ".flow-finding",
                "diagnostic": ".flow-diag",
                "written-path": ".flow-wrote",
                "flow-diagnostic": ".flow-run-diag",
            }
            out = {}
            for name, selector in sinks.items():
                widget = app.query_one(f"#flow_result {selector}", Static)
                out[name] = (widget.render().plain, list(widget.render().spans))
            return out

    rendered = asyncio.run(_drive())

    # C-31 sink-completeness — THREE guards so NEITHER a marked-but-untested sink
    # NOR an unmarked-AND-unwrapped injection sink can ship (the batch-33/43/48
    # miss). Guard A alone (count of markers) misses a future
    # `Static(block_result.summary)` added with no marker AND no safe_text — the
    # count stays 5, A stays green, an injection sink ships. Guards B+C close it.
    src = inspect.getsource(FlowBuilderPanel.render_result)
    tree = ast.parse(textwrap.dedent(src))
    render_fn = tree.body[0]

    # (A) every MARKED sink is exercised by this test.
    assert src.count("# SINK:") == len(rendered), (
        src.count("# SINK:"),
        len(rendered),
    )
    # (B) every real `safe_text(...)` CALL carries a `# SINK:` marker. Count the
    #     CALLS via AST (which ignores the docstring's prose `safe_text(...)`
    #     reference — a raw string count would over-count it) and compare with
    #     the marker count in the raw source; a wrapped-but-unmarked sink fails.
    safe_text_calls = [
        n
        for n in ast.walk(render_fn)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name)
        and n.func.id == "safe_text"
    ]
    assert len(safe_text_calls) == src.count("# SINK:"), (
        len(safe_text_calls),
        src.count("# SINK:"),
    )
    # (C) the STRONG guard (AST): no `Static(...)` in the render body may pass a
    #     FILE-DERIVED value that is NOT wrapped in `safe_text` — this catches an
    #     unmarked AND unwrapped sink that A+B would both miss. File-derived =
    #     the arg subtree references a run-derived attribute (summary/message/
    #     diagnostic(s)) or the `path`/`diagnostic` loop names; enum/int-derived
    #     args (banner text, `head`, the ribbon calls over `image_ranges`) are
    #     correctly NOT flagged.
    risky_attrs = {"summary", "message", "diagnostics"}
    risky_names = {"path", "diagnostic"}
    static_calls = [
        n
        for n in ast.walk(render_fn)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name)
        and n.func.id == "Static"
        and n.args
    ]
    assert static_calls, "no Static() calls found in render_result — parse broke"
    for call in static_calls:
        arg = call.args[0]
        attrs = {a.attr for a in ast.walk(arg) if isinstance(a, ast.Attribute)}
        names = {a.id for a in ast.walk(arg) if isinstance(a, ast.Name)}
        file_derived = bool(attrs & risky_attrs) or bool(names & risky_names)
        wrapped = (
            isinstance(arg, ast.Call)
            and isinstance(arg.func, ast.Name)
            and arg.func.id == "safe_text"
        )
        assert not (file_derived and not wrapped), (
            "file-derived Static() arg not wrapped in safe_text: "
            f"{ast.dump(arg)}"
        )

    # per-sink: literal plain AND no injected markup span (crash-only is
    # insufficient — the batch-33/43/48 miss).
    assert set(rendered) == set(expected)
    for name, (plain, spans) in rendered.items():
        assert plain == expected[name], (name, plain)
        assert spans == [], (name, spans)


def test_at088b_check_ref_label_renders_literally(tmp_path: Path) -> None:
    """AT-088b (LLR-088.6): the compose-list block ref-label sink
    (``_flow_block_label`` via ``#flow_blocks``) neutralises a hostile CHECK
    ``check_doc_ref`` — the payload appears literally and injects no span."""

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            await pilot.press("8")
            await pilot.pause()
            app.query_one("#flow_kind", Select).value = BLOCK_CHECK
            app.query_one("#flow_ref").value = _HOSTILE
            app.query_one("#flow_add", Button).press()
            await pilot.pause()
            blocks_widget = app.query_one("#flow_blocks", Static)
            return blocks_widget.render().plain, list(
                blocks_widget.render().spans
            )

    plain, spans = asyncio.run(_drive())
    assert _HOSTILE in plain
    assert spans == []


# ===========================================================================
# LLR-088.7 — CHECK/LOAD dropdown + _make_flow_block; gating UI setter
# ===========================================================================


def test_tc088_7_dropdown_offers_check_and_load_keeps_source_tag() -> None:
    """TC-088.7 (LLR-088.7): the dropdown offers CHECK and surfaces SOURCE as
    "Load", while the SOURCE discriminator string stays ``"source"`` (batch-53
    JSON tag preserved)."""
    labels = {label for label, _ in FlowBuilderPanel._KIND_OPTIONS}
    kinds = {kind for _, kind in FlowBuilderPanel._KIND_OPTIONS}
    assert "Load (image)" in labels  # SOURCE relabelled LOAD
    assert not any(label.startswith("Source") for label in labels)
    assert BLOCK_CHECK in kinds  # CHECK added
    assert BLOCK_SOURCE == "source"  # discriminator unchanged
    # _make_flow_block builds a CheckBlock and honours the gating flag.
    block = _make_flow_block(BLOCK_CHECK, "c.json", CHECK_GATING_BLOCK_OWN)
    assert isinstance(block, CheckBlock)
    assert block.gating == CHECK_GATING_BLOCK_OWN
    assert block.kind == "check"
    # SOURCE stays a SourceBlock with the "source" discriminator.
    src = _make_flow_block(BLOCK_SOURCE, "img.s19")
    assert isinstance(src, SourceBlock)
    assert src.kind == "source"


def test_at088_gating_selector_appends_block_own_op_check(tmp_path: Path) -> None:
    """Gating UI (the OPEN flag, LLR-086.1): selecting CHECK + gating
    ``block-own-op`` through the panel Add surface appends a ``CheckBlock`` whose
    gating is the non-default value — the user-visible gating setter works."""

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            await pilot.press("8")
            await pilot.pause()
            panel = app.query_one("#flow_panel", FlowBuilderPanel)
            app.query_one("#flow_kind", Select).value = BLOCK_CHECK
            app.query_one("#flow_gating", Select).value = CHECK_GATING_BLOCK_OWN
            app.query_one("#flow_ref").value = "gaps.json"
            app.query_one("#flow_add", Button).press()
            await pilot.pause()
            return list(panel._blocks)

    blocks = asyncio.run(_drive())
    assert len(blocks) == 1
    assert isinstance(blocks[0], CheckBlock)
    assert blocks[0].gating == CHECK_GATING_BLOCK_OWN


def test_flow_block_label_covers_check(tmp_path: Path) -> None:
    """_flow_block_label handles CheckBlock (was ``"?"`` pre-Inc-2) and labels
    SOURCE as LOAD."""
    assert _flow_block_label(CheckBlock("c.json")).startswith("CHECK")
    assert _flow_block_label(SourceBlock("img.s19")).startswith("LOAD")
