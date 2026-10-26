"""Batch-97 Flow Execution arms (HLR-147).

Inc-2 arms only: the service scope of LLR-147.5 (TC-B97-25 service arm) — the
11 strings of ``services/flow_execution_service.py`` that the flow screens
paint (A.2 ``ES_48_9C7BEAF``, scope ``flow_execution_service``). The module
constant ``flow_screens.py:235`` lands at Inc-5 and the ``FlowExecutionPanel``
scope at Inc-6, with the lane arms of TC-B97-21..26.

Two censuses over the service's string constants (docstrings excluded): (a)
``ES_MARKER`` and (b) the frozen values; a reach guard proves census (a) finds
exactly those 11 on ``9c7beaf``. A painted arm runs the service and matches
every block summary, diagnostic and finding against ``ES_MARKER``. Each test
names the mutation that turns it RED (PC-11: every clause is observable on
``main``).
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import List

import pytest

from s19_app.tui.services.flow_execution_service import ChainSpec, run_chain_set, run_flow
from s19_app.tui.services.flow_model import (
    BLOCK_STATUS_ERROR,
    BLOCK_STATUS_NOTICES,
    BLOCK_STATUS_OK,
    BLOCK_STATUS_WAITING,
    EXTERNAL_MODE_MANUAL,
    EXTERNAL_MODE_TERMINAL,
    ExternalStepBlock,
    ExternalStepConfirmation,
    Flow,
    FlowContext,
    SourceBlock,
    WriteOutBlock,
)
from tests.b97_fixtures import ES_48_9C7BEAF, ES_MARKER_RE, REPO_ROOT
from tests.b97_probes import string_constants
from tests.test_flow_funnel_b96 import _BASE16, _flow_blocks, _funnel_doc

SERVICE = "s19_app/tui/services/flow_execution_service.py"
SERVICE_SCOPE = "flow_execution_service"
FROZEN_SERVICE = [value for scope, value in ES_48_9C7BEAF if scope == SERVICE_SCOPE]
_S19 = "S107100001020304DE\nS9030000FC\n"


def _spanish(lines: List[str]) -> List[str]:
    return [line for line in lines if ES_MARKER_RE.search(line)]


def _project(tmp_path: Path, files: dict) -> Path:
    project_dir = tmp_path / ".s19tool" / "workarea" / "proj"
    project_dir.mkdir(parents=True)
    for name, text in files.items():
        (project_dir / name).write_text(text, encoding="utf-8")
    return project_dir


def _ext_spec(tmp_path: Path, mode: str = EXTERNAL_MODE_TERMINAL) -> ChainSpec:
    ext_dir = tmp_path / "ext"
    ext_dir.mkdir(exist_ok=True)
    block = ExternalStepBlock(
        mode=mode,
        instruction="python flash.py --release",
        log_ref="run.log",
        output_path=str(ext_dir / "flashed.s19"),
    )
    flow = Flow(name="ext", blocks=[SourceBlock("base.s19"), block, WriteOutBlock("out.s19")])
    return ChainSpec(name="ext", template="ext", flow=flow)


def _painted(record) -> List[str]:
    lines: List[str] = []
    for outcome in record.outcomes:
        for result in outcome.block_results:
            lines.append(result.summary)
            lines.extend(result.diagnostics)
            lines.extend(finding.message for finding in result.findings)
    return lines


def test_tc_b97_25_service_reach_guard_on_9c7beaf() -> None:
    """Census (a) on ``git show 9c7beaf:<service>`` returns exactly the 11
    frozen values, so a census that finds 0 on this tree is reaching the
    strings, not missing them.

    Reddening mutation: a census that skips f-string parts (``JoinedStr``)
    finds 5 of the 11 → RED.
    """
    try:
        source = subprocess.run(
            ["git", "show", f"9c7beaf:{SERVICE}"],
            cwd=REPO_ROOT, capture_output=True, check=True,
        ).stdout.decode("utf-8")
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        pytest.skip(f"git or commit 9c7beaf unavailable — reach guard cannot run: {exc}")
    found = [value for value in string_constants(source) if ES_MARKER_RE.search(value)]
    assert len(FROZEN_SERVICE) == 11
    assert sorted(found) == sorted(FROZEN_SERVICE), found


def test_tc_b97_25_service_constants_carry_no_spanish() -> None:
    """(a) 0 ``ES_MARKER`` constants and (b) 0 frozen values in the service.

    Reddening mutation: any one service string reverted to its Spanish value
    (e.g. ``"instruction"`` back to ``"instruccion"``) → both censuses RED.
    """
    constants = string_constants((REPO_ROOT / SERVICE).read_text(encoding="utf-8"))
    still_frozen = [value for value in FROZEN_SERVICE if value in constants]
    assert still_frozen == [], still_frozen
    assert _spanish(constants) == [], _spanish(constants)


@pytest.mark.parametrize(
    "mode,noun", [(EXTERNAL_MODE_TERMINAL, "command"), (EXTERNAL_MODE_MANUAL, "instruction")]
)
def test_tc_b97_25_pause_summary_in_english(tmp_path: Path, mode: str, noun: str) -> None:
    """The waiting summary names the step's noun, the pending LOG and OUTPUT
    once, in English.

    Reddening mutation: the noun kept as ``"comando"`` (the string the
    round-2 marker missed, LLR-147.5 NC) → RED.
    """
    project_dir = _project(tmp_path, {"base.s19": _S19})
    record = run_chain_set([_ext_spec(tmp_path, mode)], FlowContext(project_dir=project_dir))
    ext = record.outcomes[0].block_results[1]
    assert ext.status == BLOCK_STATUS_WAITING
    assert ext.summary.startswith(f"paused - waiting for a human: {noun} "), ext.summary
    assert ext.summary.count("pending") == 1, ext.summary
    assert _spanish(_painted(record)) == []


def test_tc_b97_25_confirm_and_refusal_lines_in_english(tmp_path: Path) -> None:
    """The confirm arms: a missing log, a missing output, then an accepted
    confirmation — every summary and diagnostic in English.

    Reddening mutation: the missing-output diagnostic reverted to
    ``"salida '…' no existe - correr el paso externo antes de confirmar"`` → RED.
    """
    project_dir = _project(tmp_path, {"base.s19": _S19})
    spec = _ext_spec(tmp_path)
    block = spec.flow.blocks[1]
    confirm = {
        1: ExternalStepConfirmation(
            block_index=1, log_ref=block.log_ref, source_path=block.output_path
        )
    }

    def run():
        return run_chain_set([spec], FlowContext(project_dir=project_dir, external_confirmations=confirm))

    no_log = run()
    assert no_log.outcomes[0].block_results[1].status == BLOCK_STATUS_ERROR
    assert any("mandatory evidence" in d for d in no_log.outcomes[0].block_results[1].diagnostics)

    (project_dir / "run.log").write_text("flashed OK\n", encoding="utf-8")
    no_output = run()
    assert any(
        "run the external step before confirming" in d
        for d in no_output.outcomes[0].block_results[1].diagnostics
    )

    Path(block.output_path).write_text(_S19, encoding="utf-8")
    done = run()
    ext = done.outcomes[0].block_results[1]
    assert ext.status == BLOCK_STATUS_OK
    assert ext.summary == "log 'run.log' received · output copied to flashed.s19 (session)"
    assert _spanish(_painted(no_log) + _painted(no_output) + _painted(done)) == []


def test_tc_b97_25_funnel_notice_in_english(tmp_path: Path) -> None:
    """The undeclared-variable notice names the variable in English.

    Reddening mutation: the notice reverted to ``"… no declarada en el flow —
    el placeholder queda intacto"`` → RED.
    """
    project_dir = _project(tmp_path, {"base.s19": _BASE16, "ch.json": _funnel_doc()})
    flow = Flow(name="partial", blocks=_flow_blocks(), funnel=(("BOOST", "AB"),))
    result = run_flow(flow, FlowContext(project_dir=project_dir))
    patch = result.block_results[1]
    assert patch.status == BLOCK_STATUS_NOTICES
    messages = [finding.message for finding in patch.findings]
    assert messages == [
        "funnel: ${MISSING} is not declared in the flow — the placeholder stays intact"
    ], messages


# --------------------------------------------------------------------------- #
# Inc-5 — TC-B97-25 module scope: the constant at flow_screens.py:235
# --------------------------------------------------------------------------- #

FLOW_SCREENS = "s19_app/tui/flow_screens.py"
FROZEN_MODULE = [value for scope, value in ES_48_9C7BEAF if scope == "module:235"]


def _module_level_constants(source: str) -> List[str]:
    """String constants outside every class of ``source`` (docstrings
    excluded): the module scope of LLR-147.5, keyed on the AST, never on line
    numbers."""
    import ast

    tree = ast.parse(source)
    module_only = ast.Module(
        body=[node for node in tree.body if not isinstance(node, ast.ClassDef)], type_ignores=[]
    )
    return string_constants(ast.unparse(module_only))


def test_tc_b97_25_module_constant_in_english() -> None:
    """TC-B97-25 (LLR-147.5, module scope, Inc-5): the frozen
    ``'PAUSED - ESPERANDO HUMANO'`` banner (``flow_screens.py:235`` on
    ``9c7beaf``) is gone, and no module-level constant of ``flow_screens.py``
    matches ``ES_MARKER``; the reach guard finds the frozen value on
    ``9c7beaf`` with the same census.

    RED on HEAD ``09e44de``: the banner is still Spanish. Mutation: the banner
    reverted.
    """
    assert FROZEN_MODULE == ["PAUSED - ESPERANDO HUMANO"]
    constants = _module_level_constants((REPO_ROOT / FLOW_SCREENS).read_text(encoding="utf-8"))
    assert [v for v in FROZEN_MODULE if v in constants] == []
    assert _spanish(constants) == [], _spanish(constants)
    try:
        old = subprocess.run(
            ["git", "show", f"9c7beaf:{FLOW_SCREENS}"], cwd=REPO_ROOT, capture_output=True, check=True,
        ).stdout.decode("utf-8")
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        pytest.skip(f"git or commit 9c7beaf unavailable — reach guard cannot run: {exc}")
    assert _spanish(_module_level_constants(old)) == FROZEN_MODULE


# =========================================================================== #
# Inc-6 — Flow Execution as one pipeline per lane (HLR-147, fx_A)
#
# TC-B97-21..26, -52..56, -63, -64 and AT-B97-09, -10, -11, -20, -22. Every
# wait is a bounded poll (``settled`` / ``poll``), never one fixed
# ``pilot.pause()`` before an assertion; the dwell arms keep the contract's
# ``pilot.pause(0.6)`` as their time step and then poll on the outcome. Every
# colour claim reads the compositor strips (``span_colours``, PC-7). Every
# test whose RED is a run on ``main`` asserts its main-observable clause before
# any new-id lookup (PC-11). PC-24: the vertical arms run at 118x54 and
# 118x53.
# =========================================================================== #

import asyncio  # noqa: E402
import re  # noqa: E402

from textual.widgets import Button, Input, Select, Static  # noqa: E402

from s19_app.tui import flow_screens as fs  # noqa: E402
from s19_app.tui import insight_style  # noqa: E402
from s19_app.tui.app import S19TuiApp  # noqa: E402
from s19_app.tui.services import flow_execution_service as fes  # noqa: E402
from tests.b97_fixtures import (  # noqa: E402
    FLASH2_STEPS,
    HOSTILE_C1,
    HOSTILE_CONTENT,
    HOSTILE_NAME,
    flash_evidence,
    fx_project,
    hostile_flow_file,
    hostile_set_file,
    import_flow,
    import_lanes,
    nul_flow,
    nul_set,
    open_flow_execution,
    run_lanes,
)
from tests.b97_probes import (  # noqa: E402
    blank_panel_rows,
    chip_style,
    clipped_overflow,
    displayed_descendants,
    hue_distance,
    hue_matches,
    is_displayed,
    painted_rows,
    settle,
    span_colours,
)

THREE = ("patch_chain", "flash_chain", "err_chain")
SIX = ("six_ok_a", "six_ok_b", "six_wait")
#: Five 6-block lanes, the last one waiting: its card lies past the lanes
#: viewport on BOTH axes at 118x54 (wait_third_6 fits vertically there with
#: Inc-6's 5-row cards; the y-axis arm needs a taller set — packet §6).
#: batch-99 Inc 3b (HLR-155 D7 re-pin): four DISTINCT templates — the
#: duplicated ``six_ok_a``/``six_ok_b`` pair shared one WRITE-OUT name per
#: pair and the set is refused at start now (the twins ride ``six_ok_c`` /
#: ``six_ok_d``, own names, same blocks).
DEEP = ("six_ok_a", "six_ok_b", "six_ok_c", "six_ok_d", "six_wait")
#: batch-99 Inc 3b (HLR-155 D7 re-pin): two waiting lanes need two output
#: names — ``flash_b`` is ``flash_chain`` with its own WRITE-OUT name.
TWO_WAIT = ("flash_chain", "flash_b")
VERTICAL = ((118, 54), (118, 53))
CABLE_VOCAB = set("▓░✗◇□")
REPORTS = "reports"


async def poll(pilot, predicate, attempts: int = 60) -> bool:
    """Bounded pump-until that returns the outcome (the assertion stays in the
    test body, so a RED names its own clause)."""
    for _ in range(attempts):
        await pilot.pause()
        if predicate():
            return True
    return False


def run_fx(tmp_path: Path, size, body, *, stems=(), run: bool = False, evidence: bool = False, project: bool = True):
    """Open Flow Execution at ``size`` with the A.5 project (opened through
    the app's own load) and ``stems`` imported through ``#fx_import``; with
    ``run`` press Run by ``enter`` with the focus on it; return ``await
    body(app, pilot, panel, project_dir)``."""

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await settle(pilot)
            project_dir = fx_project(app) if project else None
            if evidence:
                flash_evidence(project_dir)
            if stems:
                panel = await import_lanes(app, pilot, *stems)
            else:
                panel = await open_flow_execution(app, pilot)
            if run:
                await run_lanes(app, pilot, panel, key=True)
                await settle(pilot, 4)
            return await body(app, pilot, panel, project_dir)

    return asyncio.run(_drive())


def cable_marks(app, panel, lane: int, n_blocks: int, painted: bool = True) -> List[str]:
    """The status mark on each cable of ``lane`` — ``─`` and ``▶`` excluded —
    read from the compositor strips over the cable's own cells, or (``painted
    = False``) from the cable's emitted content, for cables scrolled past the
    lanes viewport (C-42: the whole lane, not only its visible part)."""
    marks = []
    for j in range(n_blocks - 1):
        cable = panel.query_one(f"#fx_cable_{lane}_{j}")
        cells = "".join(painted_rows(app, cable)) if painted else cable.render().plain
        marks.append("".join(c for c in cells if c not in "─▶ \n"))
    return marks


def strip_runs(app, widget) -> list:
    return [run for run in span_colours(app, widget) if run.source == "strip"]


def reports_of(project_dir: Path) -> List[Path]:
    return sorted((project_dir / REPORTS).glob("*-chain-set-report.md")) if project_dir else []


class RunSpy:
    """Wraps ``flow_execution_service.run_chain_set`` (the handlers import it
    at call time, so the module attribute is the seam): counts calls, keeps
    each call's ``external_confirmations`` keys and runs ``during`` inside the
    synchronous run."""

    def __init__(self, monkeypatch, during=None, raises=None):
        self.calls: List[tuple] = []
        self.during = during
        self.raises = raises
        original = fes.run_chain_set

        def wrapper(chains, ctx, **kwargs):
            self.calls.append(tuple(sorted(ctx.external_confirmations or {})))
            if self.during is not None:
                self.during()
            if self.raises is not None:
                raise self.raises
            return original(chains, ctx, **kwargs)

        monkeypatch.setattr(fes, "run_chain_set", wrapper)


class ConfirmSpy:
    """Counts ``ExternalStepConfirmed`` messages reaching the app handler."""

    def __init__(self, monkeypatch):
        self.posts: List[tuple] = []
        original = S19TuiApp.on_flow_execution_panel_external_step_confirmed

        def wrapper(app, event):
            self.posts.append((event.lane_index, event.block_index))
            return original(app, event)

        monkeypatch.setattr(S19TuiApp, "on_flow_execution_panel_external_step_confirmed", wrapper)


# --------------------------------------------------------------------------- #
# TC-B97-21 — LLR-147.1, cables from the retained record
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "status,next_status,glyph",
    [
        ("ok", "waiting", "□"),
        ("notices", "waiting", "□"),
        ("ok", "ok", "▓"),
        ("notices", "skipped", "◇"),
        ("error", "skipped", "✗"),
        ("skipped", "ok", "░"),
        ("waiting", "skipped", "░"),
        (None, None, "░"),
    ],
)
def test_tc_b97_21_cable_glyph_truth_table(status, next_status, glyph) -> None:
    """TC-B97-21 (LLR-147.1, layer 0): the five rows of the cable table —
    ``□`` into a waiting block whatever came before, else ``▓`` ok, ``◇``
    notices, ``✗`` error, ``░`` skipped / waiting / no record.

    Why: the cable is the only place a lane says how each block ran without
    opening anything. RED on main: no ``cable_glyph`` (a progress bar).
    Mutation: the waiting row checked after the status rows.
    """
    cable_glyph = getattr(fs, "cable_glyph", None)
    assert cable_glyph is not None, "a cable_glyph renderer exists"
    assert cable_glyph(status, next_status) == glyph
    assert set(getattr(fs, "FX_CABLE_GLYPHS", {})) == CABLE_VOCAB


def test_tc_b97_21_three_lane_run_paints_each_cable(tmp_path: Path) -> None:
    """TC-B97-21 (LLR-147.1, painted arm): after the 3-lane run at 118x54 the
    cables read lane 0 ``▓ ▓ ◇`` (``ok ok notices ok``), lane 1 ``▓ □ ░``
    (waiting at block 3) and lane 2 ``▓ ✗ ░`` (the patch block errs) — read
    off the painted cells; before the run every cable is ``░``.

    RED on main: the lane paints a progress bar, no ``◇`` (main-observable
    clause, asserted first). Mutation: the cable painted from block j+1's
    status.
    """

    async def body(app, pilot, panel, project_dir):
        before = [cable_marks(app, panel, i, 4) for i in range(3)] if panel.query("#fx_cable_0_0") else None
        await run_lanes(app, pilot, panel, key=True)
        await settle(pilot, 4)
        plain = panel.lane_paint_plain(0)
        statuses = [[r.status for r in o.block_results] for o in panel.last_run_record.outcomes]
        assert "◇" in plain, f"lane 0 paints its notices cable: {plain!r}"
        return plain, before, [cable_marks(app, panel, i, 4) for i in range(3)], statuses

    plain, before, after, statuses = run_fx(tmp_path, (118, 54), body, stems=THREE)
    assert "◇" in plain, f"lane 0 paints its notices cable: {plain!r}"
    assert statuses == [
        ["ok", "ok", "notices", "ok"],
        ["ok", "ok", "waiting", "skipped"],
        ["ok", "error", "skipped", "skipped"],
    ], statuses
    assert before == [["░"] * 3] * 3, before
    assert after == [["▓", "▓", "◇"], ["▓", "□", "░"], ["▓", "✗", "░"]], after


def test_tc_b97_21_wait_third_6_cables(tmp_path: Path) -> None:
    """TC-B97-21 (LLR-147.1, P-41): on ``wait_third_6`` the waiting lane reads
    ``▓ ▓ ◇ □ ░`` and the two clean lanes ``▓ ▓ ◇ ▓ ▓`` — a 6-block lane
    paints five cables, the ones scrolled past the viewport included.

    RED on main: no cable widget. Mutation: the cable painted from block
    j+1's status.
    """

    async def body(app, pilot, panel, project_dir):
        return [cable_marks(app, panel, i, 6, painted=False) for i in range(3)]

    marks = run_fx(tmp_path, (118, 54), body, stems=SIX, run=True)
    assert marks == [["▓", "▓", "◇", "▓", "▓"]] * 2 + [["▓", "▓", "◇", "□", "░"]], marks


# --------------------------------------------------------------------------- #
# TC-B97-22 — LLR-147.2, the rebind input and Bind inside the SOURCE card
# --------------------------------------------------------------------------- #


def test_tc_b97_22_rebind_input_and_bind_inside_the_source_card(tmp_path: Path) -> None:
    """TC-B97-22 (LLR-147.2): every ``#fx_in_<i>_<j>`` and its
    ``#fx_bind_<i>_<j>`` lie inside lane *i*'s SOURCE card *j* region at
    118x54, and Bind comes right after its input in the focus chain; a lane
    with two SOURCE blocks (``two_source``) holds both pairs in their own
    cards.

    Why: the press that makes a rebind take effect (P-50) must sit with the
    ref it binds. RED by mutation only (no card region on main): the input or
    its Bind re-parented to the lane row.
    """
    from tests.b97_fixtures import patch_chain_blocks, write_flow
    from s19_app.tui.services.flow_model import SourceBlock

    async def body(app, pilot, panel, project_dir):
        blocks = patch_chain_blocks()
        write_flow(project_dir, "two_source", blocks[:2] + [SourceBlock("prg_v2.s19")] + blocks[3:])
        await import_flow(app, pilot, "two_source")
        await poll(pilot, lambda: bool(panel.query("#fx_bind_3_2")) and panel.query_one("#fx_bind_3_2").region.width > 0)
        await settle(pilot, 2)
        pairs = [(0, 0), (1, 0), (2, 0), (3, 0), (3, 2)]
        outside = []
        for i, j in pairs:
            card = panel.query_one(f"#fx_card_{i}_{j}").region
            for wid in (f"fx_in_{i}_{j}", f"fx_bind_{i}_{j}"):
                if not card.contains_region(panel.query_one(f"#{wid}").region):
                    outside.append(wid)
        chain = [w.id for w in app.screen.focus_chain if w.id]
        adjacency = {
            (i, j): chain.index(f"fx_bind_{i}_{j}") - chain.index(f"fx_in_{i}_{j}") for i, j in pairs
        }
        return outside, adjacency

    outside, adjacency = run_fx(tmp_path, (118, 54), body, stems=THREE)
    assert outside == [], f"rebind controls outside their SOURCE card: {outside}"
    assert set(adjacency.values()) == {1}, adjacency


# --------------------------------------------------------------------------- #
# TC-B97-23 — LLR-147.3, the paused lane
# --------------------------------------------------------------------------- #


def _inside(region, view) -> bool:
    return view.contains_region(region)


@pytest.mark.parametrize("size", VERTICAL)
def test_tc_b97_23_three_lane_pause_waiting_lane_in_view_focus_kept(
    tmp_path: Path, size, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TC-B97-23 (LLR-147.3, 3-lane fixture; PC-24 at 118x53): after Run by
    ``enter`` lane 1 waits — its waiting card and ``#fx_confirm_1`` lie in
    the lanes viewport, the focus is still on ``#fx_run``, lanes 0 and 2 show
    no Confirm, two red pending lines lead with a glyph outside the cable
    vocabulary, the REQUIRED line names ``flash_chain`` and the confirm key;
    the attention Confirm paints differently from ``#fx_run`` (compositor
    strips); after a confirm the REQUIRED line is gone.

    Why: the human must see what is owed, and the key that answers it, without
    the focus jumping (a repeated key must not attest work, U2-3). RED on
    main: no REQUIRED line. Mutations: Confirm auto-focused; the REQUIRED
    line not cleared.
    """
    confirms = ConfirmSpy(monkeypatch)

    async def body(app, pilot, panel, project_dir):
        required_main = [w for w in panel.query("#fx_required") if is_displayed(w)]
        assert required_main, "a REQUIRED line is shown while a lane waits"
        view = panel.query_one("#fx_lanes_scroll").scrollable_content_region
        card = panel.query_one("#fx_card_1_2").region
        confirm = panel.query_one("#fx_confirm_1")
        pending = [r.strip() for r in painted_rows(app, panel.query_one("#fx_lane_1_pending")) if r.strip()]
        pending_colours = {run.fg for run in strip_runs(app, panel.query_one("#fx_lane_1_pending"))}
        required = [r.strip() for r in painted_rows(app, panel.query_one("#fx_required")) if r.strip()]
        confirm_runs = strip_runs(app, confirm)
        run_runs = strip_runs(app, panel.query_one("#fx_run"))
        state = dict(
            card_in=_inside(card, view),
            confirm_in=_inside(confirm.region, view),
            focused=app.focused.id if app.focused else None,
            others=[panel.query_one(f"#fx_confirm_{i}").display for i in (0, 2)],
            pending=pending,
            pending_colours=pending_colours,
            required=required,
            confirm_style={(r.fg, r.bg, r.bold) for r in confirm_runs},
            run_style={(r.fg, r.bg, r.bold) for r in run_runs},
        )
        # F3 (gate fold): the dwell base is stamped after the attention paint;
        # wait for it, so the 0.6 s step measures the dwell, not the paint.
        await poll(pilot, lambda: panel._attention is None or panel._attention_since is not None, 200)
        await pilot.pause(0.6)
        await pilot.press("c")
        await poll(pilot, lambda: len(confirms.posts) == 1 and not panel.query_one("#fx_required").display, 200)
        state["required_after"] = [w for w in panel.query("#fx_required") if is_displayed(w)]
        return state

    state = run_fx(tmp_path, size, body, stems=THREE, run=True, evidence=True)
    assert state["card_in"] and state["confirm_in"], state
    assert state["focused"] == "fx_run", state["focused"]
    assert state["others"] == [False, False]
    assert len(state["pending"]) == 2, state["pending"]
    assert all(line[0] not in CABLE_VOCAB for line in state["pending"]), state["pending"]
    assert state["pending"][0].startswith("▪ log 'flash_log.txt'"), state["pending"]
    assert all(hue_matches(fg, insight_style.RED) for fg in state["pending_colours"]), state["pending_colours"]
    assert len(state["required"]) == 1 and "flash_chain" in state["required"][0], state["required"]
    assert "press c to confirm" in state["required"][0]
    assert state["confirm_style"] and state["confirm_style"].isdisjoint(state["run_style"]), state
    assert state["required_after"] == []


def test_tc_b97_23_two_waiting_lanes_one_attention(tmp_path: Path) -> None:
    """TC-B97-23 (LLR-147.3 boundary: two lanes waiting): one REQUIRED line
    naming the attention lane (the first in lane order), two Confirms shown,
    and only the attention Confirm in the attention style — its painted
    cells differ from the other waiting Confirm's and from ``#fx_run``'s.

    RED by mutation: ``fx-attention`` left on every waiting Confirm → the two
    Confirms paint equal styles.
    """

    async def body(app, pilot, panel, project_dir):
        styles = {}
        for wid in ("fx_confirm_0", "fx_confirm_1", "fx_run"):
            styles[wid] = {(r.fg, r.bg, r.bold) for r in strip_runs(app, panel.query_one(f"#{wid}"))}
        required = [r.strip() for r in painted_rows(app, panel.query_one("#fx_required")) if r.strip()]
        shown = [panel.query_one(f"#fx_confirm_{i}").display for i in (0, 1)]
        classes = [panel.query_one(f"#fx_confirm_{i}").has_class("fx-attention") for i in (0, 1)]
        return styles, required, shown, classes

    styles, required, shown, classes = run_fx(tmp_path, (118, 54), body, stems=TWO_WAIT, run=True)
    assert shown == [True, True]
    assert classes == [True, False]
    assert len(required) == 1 and required[0].startswith("log + output file: REQUIRED for flash_chain ·"), required
    assert styles["fx_confirm_0"] != styles["fx_confirm_1"], styles
    assert styles["fx_confirm_0"].isdisjoint(styles["fx_run"]) and styles["fx_confirm_1"].isdisjoint(styles["fx_run"])


@pytest.mark.parametrize("size", VERTICAL)
@pytest.mark.parametrize("fixture", ["wait_third_6", "deep"])
def test_tc_b97_23_waiting_card_past_the_viewport_is_brought_into_view(tmp_path: Path, size, fixture) -> None:
    """TC-B97-23 (LLR-147.3, the waiting lane past the viewport; PC-24): on
    ``wait_third_6`` the waiting card would lie past the viewport's right
    edge at scroll 0 (fixture guard) and on ``deep`` past its right AND
    bottom edges; after the pause the waiting card and its Confirm lie inside
    the viewport and the focus is still on ``#fx_run``.

    RED by mutation: the scroll step removed → the card outside the
    viewport.
    """
    stems = SIX if fixture == "wait_third_6" else DEEP
    lane = len(stems) - 1

    async def body(app, pilot, panel, project_dir):
        scroll = panel.query_one("#fx_lanes_scroll")
        view = scroll.scrollable_content_region
        card = panel.query_one(f"#fx_card_{lane}_4")
        confirm = panel.query_one(f"#fx_confirm_{lane}")
        await poll(pilot, lambda: _inside(card.region, view) and _inside(confirm.region, view))
        at_zero = (card.region.right + int(scroll.scroll_x), card.region.bottom + int(scroll.scroll_y))
        return (
            at_zero, (view.right, view.bottom), _inside(card.region, view), _inside(confirm.region, view),
            app.focused.id if app.focused else None,
        )

    at_zero, edges, card_in, confirm_in, focused = run_fx(tmp_path, size, body, stems=stems, run=True)
    assert at_zero[0] > edges[0], f"guard: the card lies past the right edge at scroll 0: {at_zero} {edges}"
    if fixture == "deep":
        assert at_zero[1] > edges[1], f"guard: the card lies past the bottom edge at scroll 0: {at_zero} {edges}"
    assert card_in and confirm_in
    assert focused == "fx_run", focused


def test_tc_b97_23_focus_in_the_lanes_stays_in_view(tmp_path: Path) -> None:
    """TC-B97-23 (LLR-147.3, focus-in-lanes arm): on ``wait_third_6`` with the
    focus in ``#fx_in_0_0`` and Run started by ``press()`` (so the focus stays
    in the input), the lanes scroll toward the waiting card only as far as
    keeps the focused input inside the viewport, and the focus stays there.

    RED by mutation: a scroll step that ignores the focused widget → the
    input scrolled out.
    """

    async def body(app, pilot, panel, project_dir):
        field = panel.query_one("#fx_in_0_0")
        field.focus()
        await poll(pilot, lambda: app.focused is field)
        await run_lanes(app, pilot, panel)
        scroll = panel.query_one("#fx_lanes_scroll")
        await settle(pilot, 6)
        view = scroll.scrollable_content_region
        return _inside(field.region, view), app.focused.id if app.focused else None, scroll.scroll_x

    inside, focused, scroll_x = run_fx(tmp_path, (118, 54), body, stems=SIX)
    assert focused == "fx_in_0_0"
    assert inside, f"the focused input left the viewport (scroll_x {scroll_x})"


# --------------------------------------------------------------------------- #
# TC-B97-24 — LLR-147.4, two-row header; the two-word mode control
# --------------------------------------------------------------------------- #

HEADER_IDS = ("fx_name_strip", "fx_import", "fx_mode", "fx_run", "fx_set_name", "fx_save", "fx_set_select", "fx_load")


@pytest.mark.parametrize("size", VERTICAL)
def test_tc_b97_24_header_rows_inside_and_mode_control_narrow(tmp_path: Path, size) -> None:
    """TC-B97-24 (LLR-147.4; PC-24 at 118x53): the eight ribbon and set-row
    ids lie inside the panel region at scroll 0 on two single rows, and the
    mode control is at most 30 cells wide.

    RED on main (P-11): ``#fx_mode`` is 80 cells wide (main-observable,
    asserted first) and Save Set / Load Set lie outside the panel.
    """

    async def body(app, pilot, panel, project_dir):
        panel.scroll_home(animate=False)
        await poll(pilot, lambda: panel.scroll_y == 0)
        width = panel.query_one("#fx_mode").region.width
        regions = {wid: panel.query_one(f"#{wid}").region for wid in HEADER_IDS}
        return width, regions, panel.region

    width, regions, panel_region = run_fx(tmp_path, size, body, stems=THREE)
    assert width <= 30, f"the mode control is {width} cells wide"
    outside = [wid for wid, region in regions.items() if not panel_region.contains_region(region)]
    assert outside == [], outside
    assert {region.height for region in regions.values()} == {1}, regions
    assert len({region.y for region in regions.values()}) == 2, "a ribbon row and a set row"


def test_tc_b97_24_mode_click_selects_the_word_keys_toggle_report_records_it(tmp_path: Path) -> None:
    """TC-B97-24 (LLR-147.4, D13): a click on the middle of ``parallel``
    selects it and a second click there keeps it; a click on ``sequential``
    selects that; ``enter`` and ``space`` on the focused control toggle; with
    ``parallel`` chosen by key, Run writes a chain-set report whose ``-
    **Mode:**`` line reads ``parallel`` (C-10 non-default).

    RED on main: ``#fx_mode`` is an 80-cell ``Select`` (no ``mode``).
    Mutations: a click that toggles; ``space`` unbound on the chip class.
    """

    async def body(app, pilot, panel, project_dir):
        mode = panel.query_one("#fx_mode")
        assert mode.region.width <= 30, f"the mode control is {mode.region.width} cells wide"
        readings = []
        for offset in (18, 18, 5):
            await pilot.click("#fx_mode", offset=(offset, 0))
            await settle(pilot, 2)
            readings.append(mode.mode)
        for key in ("enter", "space"):
            mode.focus()
            await poll(pilot, lambda: app.focused is mode)
            before = mode.mode
            await pilot.press(key)
            await poll(pilot, lambda: mode.mode != before)
            readings.append(mode.mode)
        if mode.mode != "parallel":
            await pilot.press("enter")
            await poll(pilot, lambda: mode.mode == "parallel")
        before_reports = reports_of(project_dir)
        await run_lanes(app, pilot, panel)
        new = [p for p in reports_of(project_dir) if p not in before_reports]
        return readings, [p.read_text(encoding="utf-8") for p in new]

    readings, reports = run_fx(tmp_path, (118, 54), body, stems=("patch_chain",))
    assert readings == ["parallel", "parallel", "sequential", "parallel", "sequential"], readings
    assert len(reports) == 1 and "- **Mode:** parallel" in reports[0]


# --------------------------------------------------------------------------- #
# TC-B97-25 — LLR-147.5, the panel scope in English
# --------------------------------------------------------------------------- #

FROZEN_PANEL = [value for scope, value in ES_48_9C7BEAF if scope == "FlowExecutionPanel"]


def test_tc_b97_25_panel_constants_carry_no_spanish() -> None:
    """TC-B97-25 (LLR-147.5, panel scope): no string constant of
    ``FlowExecutionPanel`` (docstrings excluded) matches ``ES_MARKER`` and
    none of its nine frozen values (A.2) is left; the reach guard finds
    exactly those nine on ``9c7beaf`` with the same census.

    RED on HEAD ``b514b07``: the nine Spanish constants. Mutation: one
    reverted (``· re-run tras confirmar paso externo``).
    """
    assert len(FROZEN_PANEL) == 9
    constants = string_constants((REPO_ROOT / FLOW_SCREENS).read_text(encoding="utf-8"), "FlowExecutionPanel")
    assert [v for v in FROZEN_PANEL if v in constants] == []
    assert _spanish(constants) == [], _spanish(constants)
    try:
        old = subprocess.run(
            ["git", "show", f"9c7beaf:{FLOW_SCREENS}"], cwd=REPO_ROOT, capture_output=True, check=True,
        ).stdout.decode("utf-8")
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        pytest.skip(f"git or commit 9c7beaf unavailable — reach guard cannot run: {exc}")
    assert sorted(_spanish(string_constants(old, "FlowExecutionPanel"))) == sorted(FROZEN_PANEL)


def test_tc_b97_25_painted_lanes_log_and_rerun_in_english(tmp_path: Path) -> None:
    """TC-B97-25 (LLR-147.5, painted arm): the painted lanes and run log of
    the 3-lane run and of the confirmed re-run, and every block summary and
    diagnostic of both records, hold 0 ``ES_MARKER`` matches.

    RED on HEAD ``b514b07`` (P-17): ``· ESPERANDO HUMANO — paso externo
    (block 3/4) · LOG 'flash_log.txt' pendiente``. Mutation: the re-run line
    reverted to Spanish.
    """

    async def body(app, pilot, panel, project_dir):
        records = [panel.last_run_record]
        texts = ["\n".join(painted_rows(app, panel))]
        texts += [panel.lane_paint_plain(i) for i in range(3)]
        # F3 (gate fold): the dwell base is stamped after the attention paint;
        # wait for it, so the 0.6 s step measures the dwell, not the paint.
        await poll(pilot, lambda: panel._attention is None or panel._attention_since is not None, 200)
        await pilot.pause(0.6)
        await pilot.press("c")
        await poll(pilot, lambda: "re-run" in panel.run_log_plain(), 200)
        await settle(pilot, 4)
        texts.append("\n".join(painted_rows(app, panel)))
        texts.append(panel.run_log_plain())
        lines = [line for text in texts for line in text.splitlines()]
        for record in records:
            lines += _painted(record)
        return lines

    lines = run_fx(tmp_path, (118, 54), body, stems=THREE, run=True, evidence=True)
    assert any("re-run" in line for line in lines), "the confirmed re-run is painted"
    assert _spanish(lines) == [], _spanish(lines)


# --------------------------------------------------------------------------- #
# TC-B97-26 — LLR-147.6, file-derived text renders literally
# --------------------------------------------------------------------------- #

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def _payload_spans(renderable) -> List[str]:
    """Spans a markup parser would create from the payload: ``bold``,
    ``red``, a link or an ``@click`` action."""
    from rich.text import Text as _Text
    from textual.content import Content

    if isinstance(renderable, str):
        try:
            renderable = Content.from_markup(renderable)
        except Exception as exc:  # noqa: BLE001 - a markup error is a payload effect
            return [f"markup error: {type(exc).__name__}"]
    if not isinstance(renderable, (_Text, Content)):
        return []
    found = []
    for span in renderable.spans:
        style = str(span.style)
        if style in ("bold", "red") or "link" in style or "@click" in style or "meta" in style:
            found.append(style)
    return found


def test_tc_b97_26_hostile_text_renders_literally(tmp_path: Path) -> None:
    """TC-B97-26 (LLR-147.6): with ``hostile_flow`` (file ``HOSTILE_NAME.json``,
    payload in ``change_doc_ref``, ``instruction``, ``log_ref``, ``HOSTILE_NAME``
    the ``output_path``) imported and run to its pause, and
    ``flowsets/HOSTILE_NAME.json`` on disk when the screen is entered: the
    lane head, pending lines, cards, run log, REQUIRED line and the set
    picker's options paint the brackets literally, with 0 spans from the
    payload and 0 control characters; nothing raised.

    RED on main (P-37): the set picker's option is a markup string — its
    ``@click`` / ``bold`` spans (main-observable, asserted first). Mutation:
    the chain name interpolated into a markup string.
    """

    async def body(app, pilot, panel, project_dir):
        hostile_flow_file(project_dir)
        hostile_set_file(project_dir)
        app.action_show_screen("workspace")
        await settle(pilot, 2)
        app.action_show_screen("flow_execution")
        await settle(pilot, 4)
        select = panel.query_one("#fx_set_select", Select)
        prompts = [prompt for prompt, _value in select._options]
        picker_spans = [s for prompt in prompts for s in _payload_spans(prompt)]
        assert picker_spans == [], f"the set picker parses its option as markup: {picker_spans}"
        await import_flow(app, pilot, HOSTILE_NAME)
        await run_lanes(app, pilot, panel)
        await settle(pilot, 4)
        widgets = [panel.query_one(w) for w in ("#fx_lane_0_head", "#fx_lane_0_pending", "#fx_log", "#fx_required")]
        widgets += list(panel.query(".fx-card-body")) + list(panel.query(".fx-card-status"))
        spans = [s for w in widgets for s in _payload_spans(w.render())]
        painted = "\n".join(painted_rows(app, panel)) + "\n" + "\n".join(painted_rows(app, select))
        return picker_spans, spans, painted, [str(p) for p in prompts], panel.lane_paint_plain(0)

    picker_spans, spans, painted, prompts, plain = run_fx(tmp_path, (220, 60), body)
    assert picker_spans == [], f"the set picker parses its option as markup: {picker_spans}"
    assert spans == [], spans
    assert any("[bold]" in prompt and "[@click=app.quit]" in prompt for prompt in prompts), prompts
    assert "[bold]x[red]y" in plain, "the lane name paints its brackets"
    assert "[bold]" in painted and "[@click=app.quit]" in painted
    assert _CONTROL.findall(painted) == []
    assert HOSTILE_CONTENT[:12] in painted or HOSTILE_CONTENT[:12] in plain
    assert "\x1b" not in plain and HOSTILE_C1[:4] not in ""


# --------------------------------------------------------------------------- #
# TC-B97-52 — LLR-147.7, the waiting colour on the waiting-human elements
# --------------------------------------------------------------------------- #

WAITING = insight_style.WAITING_HUMAN


def _accents(runs) -> set:
    from tests.b97_probes import _hsv

    colours = set()
    for run in runs:
        for colour in (run.fg, run.bg):
            if colour and _hsv(colour)[1] >= 0.15:
                colours.add(colour)
    return colours


def test_tc_b97_52_waiting_colour_only_on_waiting_human_elements(tmp_path: Path) -> None:
    """TC-B97-52 (LLR-147.7): over the 3-lane paused run every painted cell
    in the waiting colour (within 4°) belongs to a waiting-human element —
    the waiting card, the cable into it, the paused lane's status text, a
    waiting lane's Confirm, the REQUIRED line, the run log's ``□`` line — and
    each of the six kinds carries at least one; every other accent painted on
    the four screens lies at least 20° from the waiting hue (39.3°); at least
    three distinct accents are collected; the Builder, Check Editor and Patch
    Editor paint 0 waiting cells.

    RED on main (P-16): the waiting state paints ``.sev-warning`` (no
    waiting-colour cell, the guard). Mutation: a notices glyph in the
    waiting colour.
    """
    from tests.b97_fixtures import calib_hotfix, load_change_file, load_flow, open_check_editor, open_flow_builder, open_patch_editor

    async def body(app, pilot, panel, project_dir):
        assert any(
            hue_matches(r.fg, WAITING) or hue_matches(r.bg, WAITING) for r in strip_runs(app, panel)
        ), "guard: at least one cell paints the waiting colour while a lane waits"
        owners = {
            "card": [panel.query_one("#fx_card_1_2")],
            "cable": [panel.query_one("#fx_cable_1_1")],
            "status": [panel.query_one("#fx_lane_1_head")],
            "confirm": [panel.query_one("#fx_confirm_1")],
            "required": [panel.query_one("#fx_required")],
        }
        log = panel.query_one("#fx_log")
        log_rows = painted_rows(app, log)
        wait_rows = [log.region.y + i for i, row in enumerate(log_rows) if "□" in row]
        stray, kinds = [], set()
        runs = strip_runs(app, panel)
        for run in runs:
            if not (hue_matches(run.fg, WAITING) or hue_matches(run.bg, WAITING)):
                continue
            kind = next(
                (k for k, ws in owners.items() for w in ws if w.region.contains(run.x, run.y)), None
            )
            if kind is None and run.y in wait_rows and "□" in run.text:
                kind = "log"
            if kind is None:
                stray.append(run)
            else:
                kinds.add(kind)
        accents = _accents(runs)
        others = {}
        builder = await open_flow_builder(app, pilot)
        await load_flow(app, pilot, "crc_chain")
        builder.query_one("#flow_run").press()
        await poll(pilot, lambda: bool(builder.query("#flow_result .flow-banner")))
        await settle(pilot, 2)
        others["flow"] = strip_runs(app, builder)
        check = await open_check_editor(app, pilot)
        others["check_editor"] = strip_runs(app, check)
        patch = await open_patch_editor(app, pilot, image=False)
        await load_change_file(app, pilot, patch, calib_hotfix(project_dir, "dirty.json"))
        patch.query_one("#patch_entry_address_input").value = "0xEB20"
        patch.query_one("#patch_entry_bytes_input").value = "01"
        patch.query_one("#patch_entry_add_button").press()
        await settle(pilot, 4)
        others["patch"] = strip_runs(app, patch)
        return stray, kinds, accents, others

    stray, kinds, accents, others = run_fx(tmp_path, (118, 54), body, stems=THREE, run=True)
    assert kinds == {"card", "cable", "status", "confirm", "required", "log"}, kinds
    assert stray == [], [(r.text, r.fg, r.bg, r.x, r.y) for r in stray][:6]
    for screen, runs in others.items():
        waiting = [r for r in runs if hue_matches(r.fg, WAITING) or hue_matches(r.bg, WAITING)]
        assert waiting == [], (screen, [(r.text, r.fg, r.bg) for r in waiting][:4])
        accents |= _accents(runs)
    near = sorted(c for c in accents if not hue_matches(c, WAITING) and hue_distance(c, WAITING) < 20.0)
    assert near == [], [(c, round(hue_distance(c, WAITING), 1)) for c in near]
    assert len(accents) >= 3, accents


def test_tc_b97_52_crc_card_beside_the_waiting_card_keeps_its_colour(tmp_path: Path) -> None:
    """TC-B97-52 / AT-B97-09 (LLR-147.7 boundary: ``crc_wait_chain``): the
    CRC card beside the waiting card paints its title in the CRC token (within
    4°) and the waiting card in the waiting token — the two never share a hue.

    RED by mutation: the CRC kind in the waiting colour.
    """

    async def body(app, pilot, panel, project_dir):
        crc = panel.query_one("#fx_card_0_1")
        title = [r for r in strip_runs(app, crc) if "CRC" in r.text]
        waiting = panel.query_one("#fx_card_0_2")
        border = [r for r in strip_runs(app, waiting) if set(r.text) <= set("╭╮╰╯─│ ")]
        return [r.fg for r in title], [r.fg for r in border]

    crc, border = run_fx(tmp_path, (118, 54), body, stems=("crc_wait_chain",), run=True)
    assert crc and all(hue_matches(fg, insight_style.CRC_FAMILY) for fg in crc), crc
    assert border and all(hue_matches(fg, WAITING) for fg in border), border


# --------------------------------------------------------------------------- #
# TC-B97-53 — LLR-147.8, no dead rows; the lanes take the height
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("size", [(118, 54), (118, 53), (220, 60)])
def test_tc_b97_53_no_blank_row_outside_or_between_lanes(tmp_path: Path, size) -> None:
    """TC-B97-53 (LLR-147.8; PC-24 at 118x53): after the 3-lane run no panel
    row outside ``#fx_lanes_scroll`` is blank, no blank row lies between two
    consecutive lanes, and the lanes frame ends on the REQUIRED line's row
    (the first shown of ``#fx_required`` / ``#fx_log``).

    RED on main (P-32): 3 blank rows outside the lanes frame
    (main-observable, asserted first).
    """

    async def body(app, pilot, panel, project_dir):
        scroll = panel.query_one("#fx_lanes_scroll")
        blank = blank_panel_rows(app, panel, outside=scroll)
        lanes = [panel.query_one(f"#fx_lane_{i}") for i in range(3)] if panel.query("#fx_lane_2") else []
        gaps = [lanes[i + 1].region.y - lanes[i].region.bottom for i in range(len(lanes) - 1)]
        first = next(w for w in (panel.query_one("#fx_required"), panel.query_one("#fx_log")) if w.display)
        return blank, gaps, scroll.region.bottom, first.region.y, first.id

    blank, gaps, bottom, first_y, first_id = run_fx(tmp_path, size, body, stems=THREE, run=True)
    assert blank == [], f"blank panel rows outside the lanes frame: {blank}"
    assert gaps == [0, 0], gaps
    assert first_id == "fx_required" and bottom == first_y, (bottom, first_y, first_id)


@pytest.mark.parametrize("size", [(118, 54), (220, 60)])
def test_tc_b97_53_no_lanes_one_line_and_no_blank_row_outside(tmp_path: Path, size) -> None:
    """TC-B97-53 / LLR-148.9 (empty arm): with no lanes the frame paints one
    line (``No chains yet — Import… …``), the log one line (``No run yet …``),
    and no panel row outside the frame is blank; the frame ends on the log's
    row.

    RED on main: 3 blank rows outside.
    """

    async def body(app, pilot, panel, project_dir):
        scroll = panel.query_one("#fx_lanes_scroll")
        lines = [r.strip() for r in painted_rows(app, scroll, scroll.scrollable_content_region) if r.strip()]
        log = [r.strip() for r in painted_rows(app, panel.query_one("#fx_log")) if r.strip()]
        return blank_panel_rows(app, panel, outside=scroll), lines, log, scroll.region.bottom, panel.query_one("#fx_log").region.y

    blank, lines, log, bottom, log_y = run_fx(tmp_path, size, body)
    assert blank == [], blank
    assert lines == ["No chains yet — Import… adds a lane from a saved flow."], lines
    assert log == ["No run yet — Run executes every lane."], log
    assert bottom == log_y


def test_tc_b97_53_run_log_paints_at_most_eight_lines(tmp_path: Path) -> None:
    """TC-B97-53 (LLR-147.8, design §3 ``FX_LOG_MAX_ROWS = 8``): five lanes
    run (10 log lines) paint exactly 8 log rows — ``… 3 earlier lines — the
    full log is in the run report`` then the newest 7 — and the lanes frame
    keeps the rest of the height; the run report keeps every chain.

    Why: an unbounded log would eat the lanes, the screen's hero. RED on
    HEAD ``b514b07``: the log paints all 10 lines. Mutation: the cap
    raised.
    """

    async def body(app, pilot, panel, project_dir):
        rows = [r.strip() for r in painted_rows(app, panel.query_one("#fx_log")) if r.strip()]
        report = panel.last_run_record.report_path.read_text(encoding="utf-8")
        return rows, report

    # batch-99 Inc 3b (HLR-155 D7 re-pin): five lanes need five output names
    # — one template imported five times mounts five lanes resolving to one
    # file, and that set is refused at start now. The five ``cap_*``
    # templates differ only in the WRITE-OUT name.
    from dataclasses import replace

    from tests.b97_fixtures import patch_chain_demo, write_flow

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(118, 54)) as pilot:
            await settle(pilot)
            project_dir = fx_project(app)
            for i in range(5):
                blocks = patch_chain_demo()
                blocks[3] = replace(blocks[3], output_name=f"cap_{i}.s19")
                write_flow(project_dir, f"cap_{i}", blocks)
            panel = await import_lanes(app, pilot, *(f"cap_{i}" for i in range(5)))
            await run_lanes(app, pilot, panel, key=True)
            await settle(pilot, 4)
            return await body(app, pilot, panel, project_dir)

    rows, report = asyncio.run(_drive())
    assert len(rows) == 8, rows
    assert rows[0] == "… 3 earlier lines — the full log is in the run report", rows[0]
    assert "cap_4 · done with notices" in rows[-1], rows[-1]
    report = report.replace("\\_", "_")  # the report escapes Markdown underscores
    assert all(f"cap_{n}" in report for n in (1, 2, 3, 4)), "the report keeps every chain"


# --------------------------------------------------------------------------- #
# TC-B97-54 — LLR-147.9, the filled elements
# --------------------------------------------------------------------------- #


def _filled(panel) -> List[str]:
    return sorted(
        w.id for w in panel.query("*")
        if w.id and is_displayed(w) and (w.has_class("fill-accent") or (isinstance(w, Button) and w.variant == "primary"))
    )


@pytest.mark.parametrize("stems,expected", [(THREE, ["fx_confirm_1", "fx_run"]), (TWO_WAIT, ["fx_confirm_0", "fx_confirm_1", "fx_run"])])
def test_tc_b97_54_run_and_each_waiting_confirm_are_the_filled_elements(tmp_path: Path, stems, expected) -> None:
    """TC-B97-54 (LLR-147.9): before the run ``#fx_run`` is the one filled
    element; while lanes wait, each waiting lane's Confirm joins it (two
    lanes waiting → two Confirms).

    RED by mutation: a primary Import.
    """

    async def body(app, pilot, panel, project_dir):
        before = _filled(panel)
        await run_lanes(app, pilot, panel, key=True)
        await settle(pilot, 4)
        return before, _filled(panel)

    before, waiting = run_fx(tmp_path, (118, 54), body, stems=stems)
    assert before == ["fx_run"], before
    assert waiting == expected, waiting


# --------------------------------------------------------------------------- #
# TC-B97-55 — LLR-147.10, one run at a time (the confirm re-run is a run)
# --------------------------------------------------------------------------- #


def test_tc_b97_55_input_queued_during_a_run_starts_no_second_run(tmp_path: Path, monkeypatch) -> None:
    """TC-B97-55 (LLR-147.10, in-flight arm): during the synchronous run one
    more ``#fx_run`` press and one queued ``enter`` start no second run — 1
    ``run_chain_set`` call, 1 new chain-set report; ``#fx_run`` is disabled
    inside the run, enabled after, and keeps the focus.

    Why: a press queued during a run must not start a run the operator did
    not ask for (P-44). RED on main: 2 calls (no disable). Mutation: the
    disable dropped.
    """
    holder = {}

    def during():
        run = holder["panel"].query_one("#fx_run")
        holder["inside"] = run.disabled
        run.press()
        holder["app"].simulate_key("enter")

    spy = RunSpy(monkeypatch, during=during)

    async def body(app, pilot, panel, project_dir):
        holder.update(app=app, panel=panel)
        before = reports_of(project_dir)
        await run_lanes(app, pilot, panel, key=True)
        await settle(pilot, 10)
        run = panel.query_one("#fx_run")
        new = [p for p in reports_of(project_dir) if p not in before]
        return len(spy.calls), len(new), holder.get("inside"), run.disabled, app.focused.id if app.focused else None

    calls, new, inside, after, focused = run_fx(tmp_path, (118, 54), body, stems=("patch_chain",))
    assert calls == 1, f"{calls} run_chain_set calls for one Run"
    assert new == 1, new
    assert inside is True and after is False
    assert focused == "fx_run"


def test_tc_b97_55_a_run_that_raises_paints_one_english_line(tmp_path: Path, monkeypatch) -> None:
    """TC-B97-55 (LLR-147.10 error arm, LLR-148.9): a run that raises paints
    one English line in the log (``✗ run failed - RuntimeError: boom``), no
    traceback, and Run is enabled again.

    RED on main: the raise escapes the handler (the app run ends with it).
    """
    RunSpy(monkeypatch, raises=RuntimeError("boom"))
    escaped = {}

    async def body(app, pilot, panel, project_dir):
        panel.query_one("#fx_run").press()
        await poll(pilot, lambda: "boom" in panel.run_log_plain(), 120)
        await settle(pilot, 4)
        return panel.run_log_plain(), panel.query_one("#fx_run").disabled

    try:
        log, disabled = run_fx(tmp_path, (118, 54), body, stems=("patch_chain",))
    except Exception as exc:  # noqa: BLE001 - the main-RED arm: the raise escapes
        escaped["exc"] = exc
        log, disabled = "", True
    assert "exc" not in escaped, f"the run's raise escaped the handler: {escaped.get('exc')!r}"
    assert log.splitlines() == ["✗ run failed - RuntimeError: boom"], log
    assert "Traceback" not in log and disabled is False


def test_tc_b97_55_confirm_rerun_is_one_run_at_a_time(tmp_path: Path, monkeypatch) -> None:
    """TC-B97-55 (LLR-147.10 confirm arm, LED-…97.29): during the confirm
    re-run of ``flash_chain``, one more press of ``#fx_confirm_1`` and one of
    ``#fx_run`` → 1 ``ExternalStepConfirmed``, 1 ``run_chain_set`` call, 1 new
    report; ``#fx_run`` and the Confirm are disabled inside the re-run; after
    it Run is enabled and the Confirm hidden (the lane finished).

    Why: a second Confirm queued during its own re-run would confirm the
    lane's NEXT waiting entry with no human. RED on main: 2 confirms.
    Mutation: the Confirm left enabled during the re-run.
    """
    holder = {"armed": False}

    def during():
        if not holder["armed"]:
            return
        panel = holder["panel"]
        holder["inside"] = (panel.query_one("#fx_run").disabled, panel.query_one("#fx_confirm_1").disabled)
        panel.query_one("#fx_confirm_1").press()
        panel.query_one("#fx_run").press()

    spy = RunSpy(monkeypatch, during=during)
    confirms = ConfirmSpy(monkeypatch)

    async def body(app, pilot, panel, project_dir):
        holder["panel"] = panel
        calls_before = len(spy.calls)
        before = reports_of(project_dir)
        holder["armed"] = True
        panel.query_one("#fx_confirm_1").press()
        await poll(pilot, lambda: len(spy.calls) > calls_before and not panel.query_one("#fx_run").disabled, 200)
        await settle(pilot, 10)
        new = [p for p in reports_of(project_dir) if p not in before]
        return (
            len(confirms.posts), len(spy.calls) - calls_before, len(new), holder.get("inside"),
            panel.query_one("#fx_run").disabled, panel.query_one("#fx_confirm_1").display,
        )

    posts, calls, new, inside, run_disabled, confirm_shown = run_fx(
        tmp_path, (118, 54), body, stems=THREE, run=True, evidence=True
    )
    assert posts == 1 and calls == 1, (posts, calls)
    assert new == 1, new
    assert inside == (True, True), inside
    assert run_disabled is False and confirm_shown is False


def test_tc_b97_55_confirm_rerun_that_raises_leaves_the_entry_unconfirmed(tmp_path: Path, monkeypatch) -> None:
    """TC-B97-55 (LLR-147.10 confirm error arm, PC-15): a confirm re-run that
    raises appends exactly one line naming the chain and ``RuntimeError:
    boom`` (no traceback); lane 1 still waits at block 3 with its Confirm
    shown and enabled; after the dwell one more ``c`` re-runs it.

    RED on main: the raise escapes the confirm handler. Mutation: an error
    painter that leaves the block confirmed → the retry confirms 0.
    """
    holder = {"raise": False}
    spy = RunSpy(monkeypatch)
    original = fes.run_chain_set

    def flaky(chains, ctx, **kwargs):
        if holder["raise"]:
            holder["raise"] = False
            spy.calls.append(("raised",))
            raise RuntimeError("boom")
        return original(chains, ctx, **kwargs)

    monkeypatch.setattr(fes, "run_chain_set", flaky)
    escaped = {}

    async def body(app, pilot, panel, project_dir):
        await run_lanes(app, pilot, panel, key=True)
        await settle(pilot, 4)
        log_before = panel.run_log_plain().splitlines()
        holder["raise"] = True
        panel.query_one("#fx_confirm_1").press()
        await poll(pilot, lambda: "boom" in panel.run_log_plain(), 200)
        await settle(pilot, 6)
        log_after = panel.run_log_plain().splitlines()
        lane = panel._lanes[1]
        state = (lane.paused_block, panel.query_one("#fx_confirm_1").display, panel.query_one("#fx_confirm_1").disabled)
        calls = len(spy.calls)
        # F3 (gate fold): the dwell base is stamped after the attention paint;
        # wait for it, so the 0.6 s step measures the dwell, not the paint.
        await poll(pilot, lambda: panel._attention is None or panel._attention_since is not None, 200)
        await pilot.pause(0.6)
        await pilot.press("c")
        await poll(pilot, lambda: len(spy.calls) > calls, 200)
        return log_before, log_after, state, len(spy.calls) - calls

    try:
        before, after, state, retried = run_fx(tmp_path, (118, 54), body, stems=THREE, evidence=True)
    except Exception as exc:  # noqa: BLE001 - the main-RED arm: the raise escapes
        escaped["exc"] = exc
        before, after, state, retried = [], [], None, 0
    assert "exc" not in escaped, f"the confirm re-run's raise escaped the handler: {escaped.get('exc')!r}"
    added = after[len(before):]
    assert len(added) == 1 and "flash_chain" in added[0] and "RuntimeError: boom" in added[0], added
    assert not any("Traceback" in line for line in after)
    assert state == (2, True, False), state
    assert retried == 1, "the entry was left unconfirmed, so it can be confirmed again"


# --------------------------------------------------------------------------- #
# TC-B97-56 — LLR-147.11, the keyboard order
# --------------------------------------------------------------------------- #

KEY_GROUPS = (
    ("open_folder_session", "window_help_flow_execution"),
    ("fx_import", "fx_mode", "fx_run"),
    ("fx_set_name", "fx_save", "fx_set_select", "fx_load"),
)


def test_tc_b97_56_focus_order_keys_and_chip_states(tmp_path: Path, monkeypatch) -> None:
    """TC-B97-56 (LLR-147.11): after the 3-lane run the focus chain runs
    header chips → Import… → mode → Run → set row → lanes (``#fx_lanes_scroll``,
    then per lane its rebind input, its Bind, its Confirm) with no group
    inversion and no displayed control left out; ``enter`` and ``space`` act
    on one member of each button group (Import…, the mode switch, Save Set,
    Bind, Confirm); a focused chip paints differently from its unfocused
    self.

    RED on main (P-33): no header chip on the screen — counted by TYPE
    (main-observable, asserted first). Mutation: ``space`` unbound on the chip
    class.
    """
    from s19_app.tui.open_folder_chip import OpenFolderChip
    from s19_app.tui.window_help import WindowHelpChip

    confirms = ConfirmSpy(monkeypatch)

    async def body(app, pilot, panel, project_dir):
        screen = app.query_one("#screen_flow_execution")
        chips = (len(screen.query(OpenFolderChip)), len(screen.query(WindowHelpChip)))
        assert chips == (1, 1), f"one folder chip and one help chip in the header: {chips}"
        chain = [w.id for w in app.screen.focus_chain if w.id]
        groups = {wid: g for g, ids in enumerate(KEY_GROUPS) for wid in ids}
        lanes_group = len(KEY_GROUPS)
        seq = [groups.get(w, lanes_group) for w in chain if w in groups or w.startswith(("fx_lanes_scroll", "fx_in_", "fx_bind_", "fx_confirm_"))]
        reference = {
            w.id for w in screen.query("*")
            if w.id and isinstance(w, (Button, Input, Select)) and is_displayed(w) and not w.disabled
        }
        index = {wid: chain.index(wid) for wid in ("fx_lanes_scroll", "fx_in_0_0", "fx_in_1_0", "fx_bind_1_0", "fx_confirm_1", "fx_in_2_0")}
        acted = {}

        async def key_on(wid, key, predicate):
            widget = panel.query_one(f"#{wid}")
            widget.focus()
            await poll(pilot, lambda: app.focused is widget and not widget.has_class("-active"), 120)
            await pilot.press(key)
            acted[(wid, key)] = await poll(pilot, predicate, 120)

        for key in ("enter", "space"):
            await key_on("fx_import", key, lambda: bool(app.screen.query("#flow_load_cancel")))
            app.screen.query_one("#flow_load_cancel").press()
            await poll(pilot, lambda: not app.screen.query("#flow_load_cancel"))
            mode = panel.query_one("#fx_mode")
            before = mode.mode
            await key_on("fx_mode", key, lambda: mode.mode != before)
            panel.query_one("#fx_set_name").value = f"keyed_{key}"
            await key_on("fx_save", key, lambda: (project_dir / "flowsets" / f"keyed_{key}.json").exists())
            panel.query_one("#fx_in_0_0").value = f"prg_v2.s19" if key == "enter" else "prg.s19"
            await key_on("fx_bind_0_0", key, lambda: panel.lane_bindings("patch_chain").get(0) == panel.query_one("#fx_in_0_0").value)
        await key_on("fx_confirm_1", "space", lambda: len(confirms.posts) == 1)
        states = {}
        anchor = panel.query_one("#fx_set_name")
        for wid in ("fx_import", "fx_run", "fx_bind_2_0"):
            chip = panel.query_one(f"#{wid}")
            anchor.focus()
            await poll(pilot, lambda: app.focused is anchor)
            await settle(pilot, 2)
            unfocused = chip_style(app, chip)
            chip.focus()
            await poll(pilot, lambda: app.focused is chip)
            await settle(pilot, 2)
            states[wid] = (unfocused, chip_style(app, chip))
        return seq, sorted(reference - set(chain)), index, acted, states

    seq, missing, index, acted, states = run_fx(tmp_path, (118, 54), body, stems=THREE, run=True, evidence=True)
    assert seq == sorted(seq), f"group order inverted: {seq}"
    assert missing == [], f"displayed controls outside the focus chain: {missing}"
    assert index["fx_lanes_scroll"] < index["fx_in_0_0"]
    assert index["fx_bind_1_0"] == index["fx_in_1_0"] + 1
    assert index["fx_bind_1_0"] < index["fx_confirm_1"] < index["fx_in_2_0"], index
    assert all(acted.values()), {k: v for k, v in acted.items() if not v}
    assert len(acted) == 9
    assert all(a != b for a, b in states.values()), states


# --------------------------------------------------------------------------- #
# TC-B97-63 — LLR-147.12, a lane wider than the viewport scrolls inside it
# --------------------------------------------------------------------------- #


def test_tc_b97_63_wide_lanes_scroll_inside_the_lanes_area(tmp_path: Path) -> None:
    """TC-B97-63 (LLR-147.12): on ``wait_third_6`` at 118x54 the panel itself
    does not scroll sideways (``#fx_panel.max_scroll_x == 0``), the lanes
    frame does (``max_scroll_x > 0``), 0 displayed descendants leave the
    panel over their clipped regions; ``tab`` reaches ``#fx_lanes_scroll`` and
    ``right`` scrolls it to its end, where every lane's 6th card is inside the
    viewport; at scroll 0 each lane head opens with its worst-status mark:
    ``◇ ◇ □``.

    RED on main (P-11): ``#fx_panel.max_scroll_x`` 77 (main-observable,
    asserted first). Mutation: the region predicate counting a scrolled card.
    """

    async def body(app, pilot, panel, project_dir):
        assert panel.max_scroll_x == 0, f"the panel scrolls sideways: {panel.max_scroll_x}"
        scroll = panel.query_one("#fx_lanes_scroll")
        offenders = [w.id or type(w).__name__ for w in clipped_overflow(panel)]
        population = len(displayed_descendants(panel))
        scroll.scroll_to(0, 0, animate=False, immediate=True)
        await poll(pilot, lambda: scroll.scroll_x == 0)
        await settle(pilot, 2)
        marks = [painted_rows(app, panel.query_one(f"#fx_lane_{i}_head"))[0].strip()[:1] for i in range(3)]
        app.query_one("#window_help_flow_execution").focus()
        presses = 0
        while (app.focused is None or app.focused.id != "fx_lanes_scroll") and presses < 200:
            await pilot.press("tab")
            presses += 1
        rights = 0
        while scroll.scroll_x < scroll.max_scroll_x and rights < 200:
            await pilot.press("right")
            await settle(pilot, 1)
            rights += 1
        view = scroll.scrollable_content_region
        last_in = [view.contains_region(panel.query_one(f"#fx_card_{i}_5").region) for i in range(3)]
        return scroll.max_scroll_x, offenders, population, marks, presses, last_in

    max_x, offenders, population, marks, presses, last_in = run_fx(tmp_path, (118, 54), body, stems=SIX, run=True)
    assert max_x > 0
    assert offenders == [] and population >= 10, (offenders, population)
    assert marks == ["◇", "◇", "□"], marks
    assert presses < 200
    assert last_in == [True, True, True], last_in


def test_tc_b97_63_three_lane_head_marks(tmp_path: Path) -> None:
    """TC-B97-63 (LLR-147.12, header marks on the 3-lane run): ``◇ □ ✗`` —
    notices, waiting, error — the worst status of each lane read at scroll 0.

    RED on main: no lane head (the main-observable clause reads the first
    glyph of the painted lane box: ``╭``).
    """

    async def body(app, pilot, panel, project_dir):
        heads = panel.query(".fx-lane-head")
        rows = [painted_rows(app, h)[0].strip() for h in heads]
        return [row[:1] for row in rows] or [panel.lane_paint_plain(i).strip()[:1] for i in range(3)]

    marks = run_fx(tmp_path, (118, 54), body, stems=THREE, run=True)
    assert marks == ["◇", "□", "✗"], marks


# --------------------------------------------------------------------------- #
# TC-B97-64 — LLR-147.13, `c` confirms the attention lane once per entry
# --------------------------------------------------------------------------- #


def _c_bound(app) -> bool:
    """``c`` is an app binding (main-observable: unbound on main, P-43)."""
    return "c" in app._bindings.key_to_bindings


def test_tc_b97_64_c_after_the_dwell_confirms_the_attention_lane(tmp_path: Path, monkeypatch) -> None:
    """TC-B97-64 (LLR-147.13): with lane 1 waiting (its log and output file
    present) and the focus on ``#fx_run``, ``c`` after ``CONFIRM_DWELL_S``
    re-runs lane 1 with its waiting block confirmed: the lane ends without
    waiting, the REQUIRED line is gone and the status line reads ``Confirmed
    flash_chain — re-running from block 3/4.``; the help entry and the
    REQUIRED line both name ``c``.

    Named supersession (gate fold, ux M2): I-9's ``Confirmed <chain> — the
    run continues.`` claimed an outcome before the re-run ran; the line now
    says what happens next.

    RED on main (P-43): ``c`` is unbound (main-observable, asserted first) →
    0 re-runs.
    """
    from s19_app.tui.window_help import section_body_text

    spy = RunSpy(monkeypatch)
    confirms = ConfirmSpy(monkeypatch)

    async def body(app, pilot, panel, project_dir):
        assert _c_bound(app), "c is bound on the app"
        required = [r.strip() for r in painted_rows(app, panel.query_one("#fx_required")) if r.strip()]
        calls = len(spy.calls)
        # F3 (gate fold): the dwell base is stamped after the attention paint;
        # wait for it, so the 0.6 s step measures the dwell, not the paint.
        await poll(pilot, lambda: panel._attention is None or panel._attention_since is not None, 200)
        await pilot.pause(0.6)
        await pilot.press("c")
        await poll(pilot, lambda: len(spy.calls) > calls and not panel.query_one("#fx_run").disabled, 200)
        await settle(pilot, 4)
        from s19_app.tui.window_help import window_keys_text

        return (
            required, list(confirms.posts), spy.calls[calls:], panel._lanes[1].last_status,
            panel.query_one("#fx_required").display, list(app.log_lines)[-1:],
            window_keys_text(app, "flow_execution"),
        )

    required, posts, calls, status, shown, status_line, keys_text = run_fx(
        tmp_path, (118, 54), body, stems=THREE, run=True, evidence=True
    )
    assert posts == [(1, 2)], posts
    assert calls == [(2,)], calls
    assert status != "paused" and shown is False, (status, shown)
    assert status_line == ["Confirmed flash_chain — re-running from block 3/4."], status_line
    assert "press c to confirm" in required[0]
    # batch-97 Inc-8 (D27, named supersession): the `c` line is the generated
    # keys block now, and no longer a hand-typed step.
    assert "c — Confirm" in keys_text.split("\n"), keys_text
    assert "c — Confirm" not in section_body_text("flow_execution")


def test_tc_b97_64_burst_on_two_waiting_lanes_confirms_one(tmp_path: Path, monkeypatch) -> None:
    """TC-B97-64 (LLR-147.13 boundary, P-60): ``two_wait`` — after the dwell,
    ``press("c", "c")`` confirms one lane (the attention lane) and the other
    still waits: the attention moves to it and its dwell restarts when its
    attention class is painted; one more ``c`` after the dwell confirms it.

    RED by mutation: no dwell → the burst confirms 2; the dwell stamped when
    the record arrived (not after the attention paint) → 2.
    """
    confirms = ConfirmSpy(monkeypatch)

    async def body(app, pilot, panel, project_dir):
        assert _c_bound(app), "c is bound on the app"
        # F3 (gate fold): the dwell base is stamped after the attention paint;
        # wait for it, so the 0.6 s step measures the dwell, not the paint.
        await poll(pilot, lambda: panel._attention is None or panel._attention_since is not None, 200)
        await pilot.pause(0.6)
        await pilot.press("c", "c")
        await poll(pilot, lambda: not panel.query_one("#fx_run").disabled, 200)
        await settle(pilot, 6)
        after_burst = (list(confirms.posts), panel._lanes[1].paused_block, panel.query_one("#fx_confirm_1").has_class("fx-attention"))
        # F3 (gate fold): the dwell base is stamped after the attention paint;
        # wait for it, so the 0.6 s step measures the dwell, not the paint.
        await poll(pilot, lambda: panel._attention is None or panel._attention_since is not None, 200)
        await pilot.pause(0.6)
        await pilot.press("c")
        await poll(pilot, lambda: len(confirms.posts) == 2, 200)
        return after_burst, list(confirms.posts)

    after_burst, posts = run_fx(tmp_path, (118, 54), body, stems=TWO_WAIT, run=True, evidence=True)
    assert after_burst == ([(0, 2)], 2, True), after_burst
    assert posts == [(0, 2), (1, 2)], posts


def test_tc_b97_64_two_external_steps_end_ok(tmp_path: Path, monkeypatch) -> None:
    """TC-B97-64 (LLR-147.13, ``flash2_chain``, LED-…97.29 — the HIGH fix):
    after the dwell ``press("c", "c")`` confirms once and the lane waits at
    its SECOND external step with ``#fx_confirm_0`` shown in the attention
    style; after the dwell one more ``c`` re-runs it with the confirmations
    of BOTH external steps and the lane ends ``ok`` with both blocks ``ok`` —
    it does not wait again at its first.

    RED on HEAD ``b514b07`` (shipped): ``apply_confirmed_run`` keeps
    ``paused_block = None`` → no Confirm after the first confirm; with that
    fixed alone, the re-run built from the current block only → the lane
    waits again at block 2 (``{3}`` alone, executed on the service, P-60).
    """
    spy = RunSpy(monkeypatch)
    confirms = ConfirmSpy(monkeypatch)

    async def body(app, pilot, panel, project_dir):
        flash_evidence(project_dir, FLASH2_STEPS)
        await run_lanes(app, pilot, panel, key=True)
        await settle(pilot, 4)
        # F3 (gate fold): the dwell base is stamped after the attention paint;
        # wait for it, so the 0.6 s step measures the dwell, not the paint.
        await poll(pilot, lambda: panel._attention is None or panel._attention_since is not None, 200)
        await pilot.pause(0.6)
        await pilot.press("c", "c")
        await poll(pilot, lambda: len(spy.calls) >= 2 and not panel.query_one("#fx_run").disabled, 200)
        await settle(pilot, 6)
        lane = panel._lanes[0]
        confirm = panel.query_one("#fx_confirm_0")
        first = (len(confirms.posts), lane.paused_block, confirm.display, confirm.has_class("fx-attention"))
        # F3 (gate fold): the dwell base is stamped after the attention paint;
        # wait for it, so the 0.6 s step measures the dwell, not the paint.
        await poll(pilot, lambda: panel._attention is None or panel._attention_since is not None, 200)
        await pilot.pause(0.6)
        await pilot.press("c")
        await poll(pilot, lambda: len(spy.calls) >= 3 and not panel.query_one("#fx_run").disabled, 200)
        await settle(pilot, 4)
        statuses = [r.status for r in panel.last_run_record.outcomes[0].block_results]
        return first, spy.calls, lane.last_status, getattr(lane, "block_status", {2: None, 3: None}), lane.paused_block, confirm.display

    first, calls, status, block_status, paused, shown = run_fx(tmp_path, (118, 54), body, stems=("flash2_chain",))
    assert first == (1, 3, True, True), f"waiting at the second external step after one confirm: {first}"
    assert calls == [(), (2,), (2, 3)], calls
    assert status == "ok" and paused is None and shown is False, (status, paused, shown)
    assert block_status[2] == "ok" and block_status[3] == "ok", block_status


@pytest.mark.parametrize("arrival", ["rail", "none"])
def test_tc_b97_64_arriving_with_bracket_c_confirms(tmp_path: Path, monkeypatch, arrival) -> None:
    """TC-B97-64 (LLR-147.13, PC-13 arrival arms): with lane 1 waiting, show
    the Workspace, then arrive with ``]`` — the focus left on the rail, or
    with no focus at all — and ``c`` after the dwell confirms 1.

    Why: ``]`` moves no focus, so a binding on the screen's section would be
    dead on the commonest arrival path while the REQUIRED line says ``press
    c``. RED by mutation: ``c`` bound on the section (the sealed D10) → 0.
    """
    confirms = ConfirmSpy(monkeypatch)

    async def body(app, pilot, panel, project_dir):
        assert _c_bound(app), "c is bound on the app"
        app.action_show_screen("workspace")
        await settle(pilot, 2)
        if arrival == "rail":
            rail = app.query_one("#rail_item_workspace")
            rail.focus()
            await poll(pilot, lambda: app.focused is rail)
        else:
            app.set_focus(None)
            await poll(pilot, lambda: app.focused is None)
        await pilot.press("right_square_bracket")
        await poll(pilot, lambda: not app.query_one("#screen_flow_execution").has_class("hidden"))
        focused = app.focused.id if app.focused else None
        # F3 (gate fold): the dwell base is stamped after the attention paint;
        # wait for it, so the 0.6 s step measures the dwell, not the paint.
        await poll(pilot, lambda: panel._attention is None or panel._attention_since is not None, 200)
        await pilot.pause(0.6)
        await pilot.press("c")
        await poll(pilot, lambda: len(confirms.posts) == 1, 200)
        return focused, list(confirms.posts)

    focused, posts = run_fx(tmp_path, (118, 54), body, stems=THREE, run=True, evidence=True)
    assert focused == ("rail_item_workspace" if arrival == "rail" else None), focused
    assert posts == [(1, 2)], posts


@pytest.mark.parametrize("scope", ["hidden", "modal", "input", "nothing_waits"])
def test_tc_b97_64_c_confirms_nothing_out_of_scope(tmp_path: Path, monkeypatch, scope) -> None:
    """TC-B97-64 (LLR-147.13 scope and invalid arms): ``c`` confirms nothing
    while the Workspace is shown (``check_action``), under the ``?`` help
    modal, with the focus in ``#fx_in_0_0`` (the input's value gains ``c``),
    or with no lane waiting (the status line says so). The modal arm carries
    its positive control (gate fold, code-reviewer F4): once the modal is
    closed, the same ``c`` confirms once — so its 0 is the modal's doing.

    RED by mutation: the ``check_action`` arm removed → the hidden arm
    confirms 1.
    """
    confirms = ConfirmSpy(monkeypatch)
    stems = ("patch_chain",) if scope == "nothing_waits" else THREE

    async def body(app, pilot, panel, project_dir):
        assert _c_bound(app), "c is bound on the app"
        # F3 (gate fold): the dwell base is stamped after the attention paint;
        # wait for it, so the 0.6 s step measures the dwell, not the paint.
        await poll(pilot, lambda: panel._attention is None or panel._attention_since is not None, 200)
        await pilot.pause(0.6)
        note = None
        if scope == "hidden":
            app.action_show_screen("workspace")
            await settle(pilot, 2)
        elif scope == "modal":
            app.query_one("#window_help_flow_execution").press()
            await poll(pilot, lambda: type(app.screen).__name__ == "WindowHelpScreen")
        elif scope == "input":
            field = panel.query_one("#fx_in_0_0")
            field.focus()
            await poll(pilot, lambda: app.focused is field)
            field.cursor_position = len(field.value)
        await pilot.press("c")
        await settle(pilot, 10)
        if scope == "input":
            note = panel.query_one("#fx_in_0_0").value
        if scope == "nothing_waits":
            note = list(app.log_lines)[-1:]
        posts = list(confirms.posts)
        if scope == "modal":
            app.screen.dismiss()
            await poll(pilot, lambda: type(app.screen).__name__ != "WindowHelpScreen")
            await pilot.press("c")
            await poll(pilot, lambda: len(confirms.posts) == 1, 200)
            note = list(confirms.posts)
        return posts, note

    posts, note = run_fx(tmp_path, (118, 54), body, stems=stems, run=True, evidence=True)
    assert posts == [], posts
    if scope == "modal":
        assert note == [(1, 2)], f"positive control: with the modal closed, c confirms once: {note}"
    if scope == "input":
        assert note.endswith("c"), note
    if scope == "nothing_waits":
        assert note == ["c: no lane is waiting for confirmation."], note


def test_tc_b97_64_stray_enter_on_run_runs_again_and_confirms_nothing(tmp_path: Path, monkeypatch) -> None:
    """TC-B97-64 (LLR-147.13 invalid arm, P-60): with lane 1 waiting and the
    focus on ``#fx_run``, a second ``enter`` starts one more run (1 more
    ``run_chain_set`` call, 1 more report) and confirms nothing — lane 1 waits
    again.

    RED by mutation: Confirm auto-focused → the second ``enter`` confirms.
    """
    spy = RunSpy(monkeypatch)
    confirms = ConfirmSpy(monkeypatch)

    async def body(app, pilot, panel, project_dir):
        calls = len(spy.calls)
        before = reports_of(project_dir)
        assert app.focused is not None and app.focused.id == "fx_run", app.focused
        await pilot.press("enter")
        await poll(pilot, lambda: len(spy.calls) > calls and not panel.query_one("#fx_run").disabled, 200)
        await settle(pilot, 4)
        new = [p for p in reports_of(project_dir) if p not in before]
        return len(spy.calls) - calls, len(new), list(confirms.posts), panel._lanes[1].paused_block

    more, reports, posts, paused = run_fx(tmp_path, (118, 54), body, stems=THREE, run=True, evidence=True)
    assert more == 1 and reports == 1, (more, reports)
    assert posts == [] and paused == 2, (posts, paused)


def test_tc_b97_64_a_failed_rerun_says_so_on_the_status_line(tmp_path: Path, monkeypatch) -> None:
    """TC-B97-64 / LLR-148.9 (gate fold, ux M2): when a confirmed re-run ends
    in error — here the human wrote the log but left no output file — the
    status line reads ``flash_chain failed at block 3/4 — <reason>; Run
    re-runs the set.``, after the confirm line said ``re-running from block
    3/4``.

    Why: the confirm line no longer claims success, so the failure must be
    said where the confirm was. RED on the pre-fold tree: the status line
    keeps ``Confirmed flash_chain — the run continues.``.
    """
    from tests.b97_probes import record_statuses

    confirms = ConfirmSpy(monkeypatch)
    statuses = record_statuses(monkeypatch)

    async def body(app, pilot, panel, project_dir):
        (project_dir / "flash_log.txt").write_text("flashed OK\n", encoding="utf-8")
        await poll(pilot, lambda: panel._attention is None or panel._attention_since is not None, 200)
        await pilot.pause(0.6)
        await pilot.press("c")
        await poll(pilot, lambda: len(confirms.posts) == 1 and not panel.query_one("#fx_run").disabled, 200)
        await settle(pilot, 4)
        return list(statuses)[-2:], panel._lanes[1].last_status

    lines, status = run_fx(tmp_path, (118, 54), body, stems=THREE, run=True)
    assert status == "error", status
    assert lines[0] == "Confirmed flash_chain — re-running from block 3/4.", lines
    assert lines[1].startswith("flash_chain failed at block 3/4 — ") and lines[1].endswith("; Run re-runs the set."), lines


def test_tc_b97_64_a_new_set_run_restarts_the_dwell(tmp_path: Path, monkeypatch) -> None:
    """TC-B97-64 / I-7 (c) (gate fold, code-reviewer F1): a new set run
    restarts the attention even when the same lane waits at the same block,
    through ``_rearm_attention(restart=True)`` — so a ``c`` right after the
    run ends is a ``c`` inside the dwell and confirms nothing.

    Why: the old lane's dwell base was taken before the run; reusing it would
    let a ``c`` typed during the run confirm the moment the run ends.
    Mutation: the restart arm removed → the ``c`` confirms 1.
    """
    from tests.b97_probes import record_statuses

    confirms = ConfirmSpy(monkeypatch)
    statuses = record_statuses(monkeypatch)

    async def body(app, pilot, panel, project_dir):
        await poll(pilot, lambda: panel._attention_since is not None, 200)
        await pilot.pause(0.6)
        await run_lanes(app, pilot, panel, key=True)
        await pilot.press("c")
        await settle(pilot, 6)
        return list(confirms.posts), list(statuses)[-1:], panel._lanes[1].paused_block

    posts, last, paused = run_fx(tmp_path, (118, 54), body, stems=THREE, run=True, evidence=True)
    assert posts == [] and paused == 2, (posts, paused)
    assert last and last[0].startswith("c ignored — flash_chain"), last


def test_tc_b97_64_a_restart_with_no_lane_waiting_clears_the_attention(tmp_path: Path) -> None:
    """TC-B97-64 / I-7 (c) (Inc-6 gate re-read, code-reviewer F6): a new set
    run after which no lane waits clears the attention — the REQUIRED line is
    hidden and no Confirm keeps ``fx-attention``.

    Why: ``restart`` clears the attention first, so the old ``target ==
    current`` early return (both ``None``) skipped the clean-up and left
    "press c to confirm" on screen with nothing to confirm.
    Mutation: ``and not restart`` removed from the early return → the
    REQUIRED line stays shown.
    """

    async def body(app, pilot, panel, project_dir):
        await poll(pilot, lambda: panel._attention is not None, 200)
        before = panel.query_one("#fx_required").display
        for lane in panel._lanes:
            lane.paused_block = None
        panel._rearm_attention(restart=True)
        await settle(pilot, 4)
        return (
            before,
            panel.query_one("#fx_required").display,
            [c.id for c in panel.query(".fx-confirm") if c.has_class("fx-attention")],
            panel._attention,
        )

    before, shown, lit, attention = run_fx(tmp_path, (118, 54), body, stems=THREE, run=True, evidence=True)
    assert before is True, "the fixture starts with a lane waiting"
    assert shown is False and lit == [] and attention is None, (shown, lit, attention)


def test_tc_b97_55_c_during_a_run_says_a_run_is_in_progress(tmp_path: Path, monkeypatch) -> None:
    """TC-B97-55 / LLR-147.10 (gate fold, code-reviewer F5): ``c`` while a run
    is in flight confirms nothing and says so in its own words — ``c: a run is
    in progress — wait for it to finish.`` — not the dwell line.

    RED on the pre-fold tree: the dwell line ``c ignored — … a moment ago``.
    Mutation: the in-flight arm removed.
    """
    holder = {}

    def during():
        panel = holder.get("panel")
        if panel is not None and "line" not in holder:
            holder["line"] = panel.confirm_attention()

    RunSpy(monkeypatch, during=during)
    confirms = ConfirmSpy(monkeypatch)

    async def body(app, pilot, panel, project_dir):
        await poll(pilot, lambda: panel._attention_since is not None, 200)
        await pilot.pause(0.6)
        holder["panel"] = panel
        await run_lanes(app, pilot, panel, key=True)
        return holder.get("line"), list(confirms.posts)

    line, posts = run_fx(tmp_path, (118, 54), body, stems=THREE, run=True, evidence=True)
    assert line == "c: a run is in progress — wait for it to finish.", line
    assert posts == []


def test_tc_b97_23_lanes_return_home_when_no_lane_waits(tmp_path: Path, monkeypatch) -> None:
    """TC-B97-23 / LLR-147.3 (gate fold, ux M1, option b): the 5-block
    ``flash2_chain`` lane at 118x54 waits past the viewport, so the lanes
    scroll sideways to its Confirm; once both steps are confirmed and the lane
    ends ``ok``, the lanes are back at ``scroll_x == 0`` and the lane head
    paints in full from its worst-status mark.

    Why: a finished lane read from its middle (the LOAD card cut, the head
    starting mid-word) hides which chain it is. RED on the pre-fold tree:
    ``scroll_x`` stays at the attention offset. Mutation: the scroll-home
    step removed.
    """
    confirms = ConfirmSpy(monkeypatch)

    async def body(app, pilot, panel, project_dir):
        flash_evidence(project_dir, FLASH2_STEPS)
        await run_lanes(app, pilot, panel, key=True)
        scroll = panel.query_one("#fx_lanes_scroll")
        await poll(pilot, lambda: scroll.scroll_x > 0, 200)
        scrolled = scroll.scroll_x
        for n in (1, 2):
            await poll(pilot, lambda: panel._attention_since is not None, 200)
            await pilot.pause(0.6)
            await pilot.press("c")
            await poll(pilot, lambda: len(confirms.posts) == n and not panel.query_one("#fx_run").disabled, 200)
            await settle(pilot, 4)
        await poll(pilot, lambda: scroll.scroll_x == 0, 200)
        head = painted_rows(app, panel.query_one("#fx_lane_0_head"))[0].strip()
        return scrolled, scroll.scroll_x, head, panel._lanes[0].last_status

    scrolled, scroll_x, head, status = run_fx(tmp_path, (118, 54), body, stems=("flash2_chain",))
    assert scrolled > 0, "guard: the waiting lane scrolled the lanes sideways"
    assert status == "ok"
    assert scroll_x == 0, scroll_x
    assert head.startswith("▓ flash2_chain · done"), head


def test_tc_b97_63_lane_head_time_is_on_the_set_clock(tmp_path: Path) -> None:
    """TC-B97-63 / LLR-147.12 (gate fold, ux L2): a lane head's time is the
    log's clock — the time since the set run began, ``mm:ss.mmm`` — so a
    later lane never reads as faster than it was: each head's time equals its
    terminal log line's stamp.

    RED on the pre-fold tree: the head paints the lane's own duration
    (``0.031s``).
    """

    async def body(app, pilot, panel, project_dir):
        heads = [painted_rows(app, panel.query_one(f"#fx_lane_{i}_head"))[0] for i in (0, 2)]
        log = panel.run_log_plain().splitlines()
        return heads, log

    heads, log = run_fx(tmp_path, (118, 54), body, stems=THREE, run=True)
    for head, chain in zip(heads, ("patch_chain", "err_chain")):
        terminal = next(line for line in log if f" {chain} · " in line and "started" not in line)
        assert terminal.split(" ")[0] in head, (head, terminal)


# --------------------------------------------------------------------------- #
# Layer 0 — the Confirm reserve, the error line, the chip census
# --------------------------------------------------------------------------- #


def test_tc_b97_34_lane_layout_is_the_builder_rule_minus_the_confirm_reserve() -> None:
    """TC-B97-34 (LLR-149.1, Execution arm, layer 0; D24 / PC-4):
    ``lane_layout(viewport_w, n_max) == pipeline_layout(viewport_w −
    CONFIRM_RESERVE, n_max)`` with ``CONFIRM_RESERVE == 10`` (a gap + the
    9-cell ``Confirm``); the design's readings: 4 blocks at 107 → card 21,
    spare 1; at 191 → 42, spare 1; 6 blocks at 107 → 21 (the lanes scroll);
    at 191 → 26.

    RED on main: no ``lane_layout``. Mutation: the reserve taken only while a
    lane waits (the painted arm in ``test_b97_width.py``).
    """
    lane_layout = getattr(fs, "lane_layout", None)
    assert lane_layout is not None
    assert fs.CONFIRM_RESERVE == 10
    for viewport in range(40, 261):
        for n in range(1, 8):
            assert tuple(lane_layout(viewport, n)) == tuple(fs.pipeline_layout(viewport - 10, n)), (viewport, n)
    assert tuple(lane_layout(107, 4)) == (21, 1)
    assert tuple(lane_layout(191, 4)) == (42, 1)
    assert lane_layout(107, 6).card_w == 21
    assert lane_layout(191, 6).card_w == 26


def test_tc_b97_55_error_line_is_one_english_line_without_a_traceback() -> None:
    """D14 (4) / LLR-148.9 (layer 0): ``fx_run_error_line`` names the
    exception type and the first line of its message, scrubbed and clipped
    to 160 cells — never a traceback, never a second line.

    RED on main: no ``fx_run_error_line``.
    """
    line_of = getattr(fs, "fx_run_error_line", None)
    assert line_of is not None
    assert line_of(RuntimeError("boom")) == "run failed - RuntimeError: boom"
    long = line_of(ValueError("x" * 400 + "\nTraceback (most recent call last):"))
    assert "\n" not in long and "Traceback" not in long and len(long) <= 160, long
    hostile = line_of(OSError("[bold]x[/] \x07"))
    assert "[bold]x[/]" in hostile and "\x07" not in hostile, hostile


def test_tc_b97_56_every_flow_button_is_a_space_chip() -> None:
    """TC-B97-56 / TC-B97-51 (LLR-147.11, LLR-146.13; D13, PC-3): no
    ``Button(`` constructor is left in ``flow_screens.py`` — every button of
    both flow screens is a ``FlowChip``, whose class binds ``space``.

    RED on HEAD ``b514b07``: 15 ``Button(`` constructors (the Builder's foot
    row and strip, the Execution header, Bind, Confirm). Mutation: one
    ``Button(`` put back.
    """
    import ast

    tree = ast.parse((REPO_ROOT / FLOW_SCREENS).read_text(encoding="utf-8"))
    calls = [
        node.lineno for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "Button"
    ]
    assert calls == [], f"Button( constructors at lines {calls}"
    chip = getattr(fs, "FlowChip", None)
    assert chip is not None and any(b.key == "space" and b.action == "press" for b in chip.BINDINGS)


def test_tc_b97_flow_execution_css_section_is_scoped() -> None:
    """D23 / design §6.1 Inc-6 (11): every rule of the ``/* batch-97
    flow_execution */`` section is rooted at ``#fx_panel`` or
    ``#screen_flow_execution``; the shared ``.flow-name-strip``, the
    ``.sev-*`` rules, ``.modal-hint``, ``.patch-docked-row,
    .patch-docked-group`` and the ``/* batch-97 flow_builder */`` section are
    byte-equal to HEAD ``b514b07``.

    RED on HEAD: no section. Mutation: an unscoped ``.flow-name-strip {
    margin-bottom: 0; }``.
    """
    sheet = (REPO_ROOT / "s19_app/tui/styles.tcss").read_text(encoding="utf-8").replace("\r\n", "\n")
    marker = "/* batch-97 flow_execution"
    assert marker in sheet, "a scoped flow_execution section exists"
    section = sheet[sheet.index(marker):]
    # batch-97 Inc-8 (named supersession): the key bar's section is appended
    # after this one, so this section ends at the next batch-97 section.
    later = section.find("/* batch-97 ", len(marker))
    section = section if later < 0 else section[:later]
    section = re.sub(r"/\*.*?\*/", "", section, flags=re.S)
    selectors = [s.strip() for block in re.findall(r"([^{}]+)\{", section) for s in block.split(",")]
    assert selectors, "the section holds rules"
    unscoped = [s for s in selectors if not s.startswith(("#fx_panel", "#screen_flow_execution"))]
    assert unscoped == [], unscoped
    try:
        old = subprocess.run(
            ["git", "show", "b514b07:s19_app/tui/styles.tcss"], cwd=REPO_ROOT, capture_output=True, check=True,
        ).stdout.decode("utf-8").replace("\r\n", "\n")
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        pytest.skip(f"git or commit b514b07 unavailable — byte-equality arm cannot run: {exc}")

    def block(text: str, head: str) -> str:
        start = text.index(head)
        return text[start:text.index("}", start) + 1]

    # batch-97 Inc-8 gate fold (named supersession, operator decision at the
    # Inc-8 gate 2026-10-23, LED-…97.37): the one shipped rule Inc-8 edits is
    # `.map-region-scroll`'s floor (2 -> 1) and its comment; every other byte
    # of the b514b07 sheet is still a prefix.
    map_old = re.search(r" \* remaining height; the scrollbar renders.*?min-height: 2;\n\}", old, re.S)
    map_new = re.search(r" \* remaining height; the scrollbar renders.*?min-height: 1;\n\}", sheet, re.S)
    assert map_old and map_new, "the .map-region-scroll block is located in both sheets"
    old = old.replace(map_old.group(0), map_new.group(0))
    assert sheet.startswith(old.rstrip()), "every rule shipped at b514b07 is byte-equal; Inc-6 only appends"
    for head in (".flow-name-strip {", ".modal-hint", ".patch-docked-row, .patch-docked-group", ".sev-ok", ".sev-warning", ".sev-error", ".sev-neutral"):
        assert block(sheet, head) == block(old, head), head
    builder = old[old.index("/* batch-97 flow_builder"):]
    assert builder in sheet, "the flow_builder section is byte-equal"


# --------------------------------------------------------------------------- #
# AT-B97-09, -10, -11, -20, -22 — HLR-147 through the shipped controls
# --------------------------------------------------------------------------- #


def test_at_b97_09_three_lanes_run_paused_lane_in_view_english_log(tmp_path: Path) -> None:
    """AT-B97-09 (US-137 / HLR-147, black-box): rail key ``]`` → Flow
    Execution; Import… ×3 (``patch_chain``, ``flash_chain``, ``err_chain``);
    click Run → cables ``▓▓◇`` / ``▓□░`` / ``▓✗░``; lane 1's card and Confirm
    inside the lanes viewport, the Confirm painted unlike Run, the focus left
    on Run; 0 ``ES_MARKER`` in the log; every waiting-colour cell inside a
    waiting-human element; then ``crc_wait_chain`` imported and run: its CRC
    card in the CRC token beside the waiting card.

    RED on main (P-17): a progress bar and a Spanish log (main-observable:
    the log matches ``ES_MARKER``, asserted first).
    """

    async def body(app, pilot, panel, project_dir):
        app.action_show_screen("workspace")
        await settle(pilot, 2)
        await pilot.press("right_square_bracket")
        await poll(pilot, lambda: not app.query_one("#screen_flow_execution").has_class("hidden"))
        for stem in THREE:
            await import_flow(app, pilot, stem)
        await poll(pilot, lambda: panel.query_one("#fx_lane_2").region.width > 0)
        await settle(pilot, 2)
        await pilot.click("#fx_run")
        await poll(pilot, lambda: panel.last_run_record is not None and not panel.query_one("#fx_run").disabled, 200)
        await settle(pilot, 6)
        log = panel.run_log_plain()
        assert _spanish(log.splitlines()) == [], f"the run log is in English: {log!r}"
        marks = [cable_marks(app, panel, i, 4) for i in range(3)]
        view = panel.query_one("#fx_lanes_scroll").scrollable_content_region
        inside = (view.contains_region(panel.query_one("#fx_card_1_2").region), view.contains_region(panel.query_one("#fx_confirm_1").region))
        confirm = {(r.fg, r.bg) for r in strip_runs(app, panel.query_one("#fx_confirm_1"))}
        run = {(r.fg, r.bg) for r in strip_runs(app, panel.query_one("#fx_run"))}
        focused = app.focused.id if app.focused else None
        owners = [panel.query_one(w) for w in ("#fx_card_1_2", "#fx_cable_1_1", "#fx_lane_1_head", "#fx_confirm_1", "#fx_required")]
        log_widget = panel.query_one("#fx_log")
        stray = [
            r for r in strip_runs(app, panel)
            if (hue_matches(r.fg, WAITING) or hue_matches(r.bg, WAITING))
            and not any(w.region.contains(r.x, r.y) for w in owners)
            and not (log_widget.region.contains(r.x, r.y) and "□" in r.text)
        ]
        await import_flow(app, pilot, "crc_wait_chain")
        await poll(pilot, lambda: panel.query_one("#fx_lane_3").region.width > 0)
        await run_lanes(app, pilot, panel)
        await settle(pilot, 6)
        crc = [r.fg for r in strip_runs(app, panel.query_one("#fx_card_3_1")) if "CRC" in r.text]
        return marks, inside, confirm, run, focused, stray, crc

    marks, inside, confirm, run, focused, stray, crc = run_fx(tmp_path, (118, 54), body)
    assert marks == [["▓", "▓", "◇"], ["▓", "□", "░"], ["▓", "✗", "░"]], marks
    assert inside == (True, True), inside
    assert confirm and confirm.isdisjoint(run), (confirm, run)
    assert focused == "fx_run", focused
    assert stray == [], [(r.text, r.fg, r.bg) for r in stray][:4]
    assert crc and all(hue_matches(fg, insight_style.CRC_FAMILY) for fg in crc), crc


@pytest.mark.parametrize("size", VERTICAL)
def test_at_b97_10_save_set_then_load_it_in_a_new_app(tmp_path: Path, size) -> None:
    """AT-B97-10 (US-137 / HLR-147, black-box; PC-24 at 118x53): type a set
    name, click Save Set → ``flowsets/<name>.json`` parses with 3 chains in
    lane order; a new ``S19TuiApp`` on the same ``tmp_path`` picks it in the
    saved-sets select and clicks Load Set → the 3 lanes restored in order;
    the eight header ids lie inside the panel; Run with no lanes paints one
    English line.

    RED on main (P-11): ``#fx_save`` / ``#fx_load`` outside the panel
    (main-observable, asserted first).
    """
    import json

    from tests.b97_fixtures import load_project

    async def first(app, pilot, panel, project_dir):
        regions = {wid: panel.query_one(f"#{wid}").region for wid in HEADER_IDS}
        outside = [wid for wid, region in regions.items() if not panel.region.contains_region(region)]
        assert outside == [], f"header ids outside the panel: {outside}"
        field = panel.query_one("#fx_set_name", Input)
        await pilot.click("#fx_set_name")
        field.value = ""
        await pilot.press(*"lanes_q4")
        await pilot.click("#fx_save")
        path = project_dir / "flowsets" / "lanes_q4.json"
        await poll(pilot, path.exists)
        return json.loads(path.read_text(encoding="utf-8"))

    saved = run_fx(tmp_path, size, first, stems=THREE)
    assert [c["chain"] for c in saved["chains"]] == list(THREE), saved

    async def second():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await settle(pilot)
            load_project(app)
            panel = await open_flow_execution(app, pilot)
            empty = []
            await pilot.click("#fx_run")
            await settle(pilot, 4)
            empty = [r.strip() for r in painted_rows(app, panel.query_one("#fx_log")) if r.strip()]
            select = panel.query_one("#fx_set_select", Select)
            await poll(pilot, lambda: select.value == "lanes_q4")
            await pilot.click("#fx_load")
            await poll(pilot, lambda: panel.lane_count() == 3 and bool(panel.query("#fx_lane_2")), 120)
            return empty, panel.lane_names()

    empty, names = asyncio.run(second())
    assert empty == ["No chains to run — Import… adds a lane first."], empty
    assert names == list(THREE), names


def test_at_b97_11_hostile_and_nul_inputs_render_literally_or_are_refused(tmp_path: Path) -> None:
    """AT-B97-11 (US-137 / HLR-147, black-box): ``hostile_flow`` imported and
    run to its pause, the screen entered with ``flowsets/HOSTILE_NAME.json``
    present: lane, pending lines, header, log and set picker paint the
    payload literally (0 markup spans, 0 control characters); Import of
    ``nul_flow`` paints one refusal naming ``FLOW-UNSAFE-REF`` and adds no
    lane; Load of ``nul_set`` paints one refusal naming
    ``CHAIN-SET-UNSAFE-REF``; nothing raised.

    RED on main (P-37, P-36): the set picker's markup spans; the NUL refusals
    carry no code.
    """

    async def body(app, pilot, panel, project_dir):
        hostile_flow_file(project_dir)
        hostile_set_file(project_dir)
        nul_flow(project_dir)
        nul_set(project_dir)
        app.action_show_screen("workspace")
        await settle(pilot, 2)
        app.action_show_screen("flow_execution")
        await settle(pilot, 4)
        select = panel.query_one("#fx_set_select", Select)
        picker = [s for prompt, _ in select._options for s in _payload_spans(prompt)]
        await import_flow(app, pilot, HOSTILE_NAME)
        await run_lanes(app, pilot, panel)
        await settle(pilot, 4)
        widgets = [panel.query_one(w) for w in ("#fx_lane_0_head", "#fx_lane_0_pending", "#fx_log", "#fx_name_strip")]
        spans = [s for w in widgets for s in _payload_spans(w.render())]
        painted = "\n".join(painted_rows(app, panel))
        lanes = panel.lane_count()
        await import_flow(app, pilot, "nul_flow")
        notice_flow = panel.query_one("#fx_notice").render().plain
        lanes_after = panel.lane_count()
        select.value = "nul_set"
        await poll(pilot, lambda: select.value == "nul_set")
        await pilot.click("#fx_load")
        await poll(pilot, lambda: "CHAIN-SET" in panel.query_one("#fx_notice").render().plain or "nul_set" in panel.query_one("#fx_notice").render().plain)
        notice_set = panel.query_one("#fx_notice").render().plain
        return picker, spans, painted, lanes, notice_flow, lanes_after, notice_set, panel.lane_count()

    picker, spans, painted, lanes, notice_flow, lanes_after, notice_set, final = run_fx(tmp_path, (220, 60), body)
    assert picker == [], picker
    assert spans == [] and _CONTROL.findall(painted) == [], spans
    assert "[@click=app.quit]" in painted
    assert "FLOW-UNSAFE-REF" in notice_flow and lanes_after == lanes, notice_flow
    assert "CHAIN-SET-UNSAFE-REF" in notice_set and final == lanes, notice_set


async def _import_by_keys(app, pilot, panel, stem: str) -> None:
    """Import… by ``enter``, the stem picked with ``down`` and Load by
    ``tab`` + ``enter`` — keys only."""
    from textual.widgets import ListView

    before = panel.lane_count()
    button = panel.query_one("#fx_import")
    button.focus()
    await poll(pilot, lambda: app.focused is button and not button.has_class("-active"), 120)
    await pilot.press("enter")
    await poll(pilot, lambda: bool(app.screen.query("#flow_list ListItem")))
    listing = app.screen.query_one("#flow_list", ListView)
    if app.focused is not listing:
        listing.focus()
        await poll(pilot, lambda: app.focused is listing)
    for _ in range(30):
        child = listing.highlighted_child
        if child is not None and child.name == stem:
            break
        await pilot.press("down")
        await settle(pilot, 1)
    for _ in range(6):
        if app.focused is not None and app.focused.id == "flow_load_ok":
            break
        await pilot.press("tab")
        await settle(pilot, 1)
    assert app.focused is not None and app.focused.id == "flow_load_ok", app.focused
    await pilot.press("enter")
    await poll(pilot, lambda: panel.lane_count() == before + 1 and bool(app.query(f"#fx_lane_{before}")), 120)
    await settle(pilot, 2)


def test_at_b97_20_keys_only_run_pause_confirm(tmp_path: Path, monkeypatch) -> None:
    """AT-B97-20 (US-137 / HLR-147, black-box, keys only): Import… ×3 by
    ``enter`` and the picker's keys; the mode by key; ``enter`` on Run → lane
    1 waits; ``enter`` again → one more report, lane 1 waiting again, 0
    confirms; ``tab`` into ``#fx_in_0_0`` and ``c`` → the input ends with
    ``c``, 0 confirms; ``tab`` out, wait 0.6 s, ``c`` → lane 1 re-runs
    confirmed and the REQUIRED line clears; the REQUIRED line named
    ``flash_chain``.

    RED on main (P-43): ``c`` unbound (main-observable). Mutations: Confirm
    auto-focused → the second ``enter`` confirms; no dwell.
    """
    confirms = ConfirmSpy(monkeypatch)

    async def body(app, pilot, panel, project_dir):
        assert _c_bound(app), "c is bound on the app"
        for stem in THREE:
            await _import_by_keys(app, pilot, panel, stem)
        mode = panel.query_one("#fx_mode")
        mode.focus()
        await poll(pilot, lambda: app.focused is mode)
        await pilot.press("space")
        await poll(pilot, lambda: mode.mode == "parallel")
        await pilot.press("space")
        await poll(pilot, lambda: mode.mode == "sequential")
        await pilot.press("tab")
        await poll(pilot, lambda: app.focused is not None and app.focused.id == "fx_run")
        before = reports_of(project_dir)
        await pilot.press("enter")
        await poll(pilot, lambda: panel.last_run_record is not None and not panel.query_one("#fx_run").disabled, 200)
        await settle(pilot, 4)
        required = [r.strip() for r in painted_rows(app, panel.query_one("#fx_required")) if r.strip()]
        await pilot.press("enter")
        await poll(pilot, lambda: len(reports_of(project_dir)) == len(before) + 2 and not panel.query_one("#fx_run").disabled, 200)
        await settle(pilot, 4)
        stray = (len(reports_of(project_dir)) - len(before), list(confirms.posts), panel._lanes[1].paused_block)
        for _ in range(60):
            if app.focused is not None and app.focused.id == "fx_in_0_0":
                break
            await pilot.press("tab")
        field = panel.query_one("#fx_in_0_0")
        field.cursor_position = len(field.value)
        await pilot.press("c")
        await settle(pilot, 4)
        typed = (field.value, list(confirms.posts))
        await pilot.press("tab")
        await poll(pilot, lambda: app.focused is not field)
        # F3 (gate fold): the dwell base is stamped after the attention paint;
        # wait for it, so the 0.6 s step measures the dwell, not the paint.
        await poll(pilot, lambda: panel._attention is None or panel._attention_since is not None, 200)
        await pilot.pause(0.6)
        await pilot.press("c")
        await poll(pilot, lambda: len(confirms.posts) == 1 and not panel.query_one("#fx_required").display, 200)
        return required, stray, typed, list(confirms.posts), panel._lanes[1].last_status

    required, stray, typed, posts, status = run_fx(tmp_path, (118, 54), body, evidence=True)
    assert len(required) == 1 and "flash_chain" in required[0], required
    assert stray == (2, [], 2), stray
    assert typed[0].endswith("c") and typed[1] == [], typed
    assert posts == [(1, 2)] and status != "paused", (posts, status)


def test_at_b97_22_parallel_rebind_runs_each_lane_on_its_own_image(tmp_path: Path) -> None:
    """AT-B97-22 (US-137 / HLR-147, black-box): choose ``parallel`` in the
    mode control, type ``prg_v2.s19`` into ``#fx_in_1_0`` and press
    ``#fx_bind_1_0`` (both inside lane 1's SOURCE card), Run → the new
    chain-set report reads ``- **Mode:** parallel`` and lane 1's ``fw_b.s19``
    differs from lane 0's output at the flipped byte.

    RED on main (P-11): ``#fx_mode`` 80 cells wide and no SOURCE card region
    (main-observable, asserted first).
    """

    async def body(app, pilot, panel, project_dir):
        assert panel.query_one("#fx_mode").region.width <= 30, "the mode control is narrow"
        card = panel.query_one("#fx_card_1_0").region
        inside = all(card.contains_region(panel.query_one(f"#{w}").region) for w in ("fx_in_1_0", "fx_bind_1_0"))
        await pilot.click("#fx_mode", offset=(18, 0))
        await poll(pilot, lambda: panel.query_one("#fx_mode").mode == "parallel")
        panel.query_one("#fx_in_1_0", Input).value = "prg_v2.s19"
        await pilot.click("#fx_bind_1_0")
        await poll(pilot, lambda: panel.lane_bindings("patch_chain_b").get(0) == "prg_v2.s19")
        before = reports_of(project_dir)
        await run_lanes(app, pilot, panel)
        new = [p for p in reports_of(project_dir) if p not in before]
        a = (project_dir / "fw_app_patched.s19").read_text(encoding="ascii")
        b = (project_dir / "fw_b.s19").read_text(encoding="ascii")
        return inside, [p.read_text(encoding="utf-8") for p in new], a != b

    inside, reports, differ = run_fx(tmp_path, (118, 54), body, stems=("patch_chain", "patch_chain_b"))
    assert inside, "the rebind input and Bind lie inside lane 1's SOURCE card"
    assert len(reports) == 1 and "- **Mode:** parallel" in reports[0]
    assert differ, "lane 1 ran on prg_v2.s19"
