"""Batch-101 Inc 12b (G-T4) - every widget of the Flow Builder and Flow
Execution is shown in some state; the kind chips are the only holder of the
block kind.

Design under test: ``.dev-flow/2026-11-01-batch-101/inc-12b/01-requirements.md``
rows R-TUI-059.25 and R-FX-SCR.4, the cited canon row R-FB-ADD.1 (E3 S-1: a
press that names no block kind changes nothing) and the acceptance case
AT-I12b-1, one node per case of ``inc-12b/02-test-cases.md``.

The two walks drive the product's own controls (chip presses, Variables, Add,
Import, Run, Save Set), collect after every state the ids of the window's
widgets that are shown (``tests.b97_probes.is_displayed``) and assert that no
id of the population (the union of the ids mounted over the walked states) is
never shown. Each walk asserts its population size first, so a vacuous walk
fails. Everything is read off what the app paints or its widgets display; the
kind is read through the kind tag, the chip marks and the inputs shown, never
through the panel's own attribute. No product file is edited here and the OS
clipboard is never touched (the per-test ``LOCALAPPDATA`` isolation is the
shared one).

Traceability (E4): test names start ``test_r_<row id>_...`` or ``test_at_i12b_...``
so the registry binds them.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

from textual.widgets import Button, Input

from s19_app.tui import flow_screens as fs
from s19_app.tui.app import S19TuiApp
from s19_app.tui.services.flow_model import (
    BLOCK_A2B,
    BLOCK_CHECK,
    BLOCK_CRC,
    BLOCK_EXTERNAL_STEP,
    BLOCK_PATCH,
    BLOCK_SOURCE,
    BLOCK_WRITE_OUT,
)
from tests.b97_fixtures import (
    fx_project,
    import_flow,
    open_flow_builder,
    open_flow_execution,
)
from tests.b97_probes import is_displayed, painted_rows, settle, settled

SIZE = (118, 54)

#: The seven kinds and the kind tag each chip paints (glyph, space, name).
KIND_TAGS = (
    (BLOCK_SOURCE, "◉ LOAD"),
    (BLOCK_PATCH, "▣ PATCH"),
    (BLOCK_CHECK, "✓ CHECK"),
    (BLOCK_CRC, "⊕ CRC"),
    (BLOCK_WRITE_OUT, "▼ WRITE-OUT"),
    (BLOCK_A2B, "⏚ A2B-DIFF"),
    (BLOCK_EXTERNAL_STEP, "» EXT-STEP"),
)
CHECK_TAG = "✓ CHECK"


# --------------------------------------------------------------------------- #
# drivers and readers
# --------------------------------------------------------------------------- #


def _drive(tmp_path: Path, body):
    """Open the app at 118x54 on the Flow Execution project (``fx_project``,
    opened through the app's own load) and return
    ``await body(app, pilot, project_dir)``."""

    async def _run():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=SIZE) as pilot:
            await settle(pilot)
            project_dir = await fx_project(app)
            return await body(app, pilot, project_dir)

    return asyncio.run(_run())


def _population(panel) -> set:
    """The ids of the widgets mounted in the window now (panel included)."""
    return {w.id for w in (panel, *panel.query("*")) if w.id}


def _shown(panel) -> set:
    """The ids of the window's widgets that are shown now."""
    return {w.id for w in (panel, *panel.query("*")) if w.id and is_displayed(w)}


class _Walk:
    """Accumulates the population and the shown set over the walked states."""

    def __init__(self, panel) -> None:
        self.panel = panel
        self.population: set = set()
        self.shown: set = set()
        self.states: list = []

    def collect(self, state: str) -> None:
        self.population |= _population(self.panel)
        self.shown |= _shown(self.panel)
        self.states.append(state)

    def never_shown(self) -> list:
        return sorted(self.population - self.shown)


def _painted(app, widget) -> str:
    return "\n".join(row.rstrip() for row in painted_rows(app, widget))


def _tag(app, panel) -> str:
    return _painted(app, panel.query_one(".flow-kind-tag")).strip()


def _chain_title(panel) -> str:
    return str(panel.query_one("#flow_pipeline_scroll").border_title)


async def _press_kind_chip(app, pilot, panel, kind: str, tag: str) -> None:
    panel.query_one(f"#flow_palette_{kind}", Button).press()
    await settled(
        pilot,
        lambda: tag in _tag(app, panel) and panel.query_one(f"#flow_palette_{kind}").has_class("chip-selected"),
        f"the {tag} chip is chosen: tag painted and chip marked",
    )


# --------------------------------------------------------------------------- #
# R-TUI-059.25 - the Flow Builder walk
# --------------------------------------------------------------------------- #


def test_r_tui_059_25_1_every_flow_builder_widget_is_shown_in_a_state(tmp_path: Path) -> None:
    """R-TUI-059.25 (case /1): walk [opened; each of the 7 kind chips pressed;
    Variables opened and closed; the Add notice (LOAD, empty image file, Add);
    3 x (prg.s19, Add)] -> 0 ids never shown, at least 45 ids in the
    population.

    RED on base: five widgets (the help sentence, the grid canvas, the
    numbered list, the kind dropdown and the session line) are mounted and
    never shown; the failure message lists their ids.
    """

    async def body(app, pilot, project_dir):
        panel = await open_flow_builder(app, pilot)
        walk = _Walk(panel)
        await settled(pilot, lambda: _tag(app, panel) != "", "the kind tag is painted")
        walk.collect("opened")

        for kind, tag in KIND_TAGS:
            await _press_kind_chip(app, pilot, panel, kind, tag)
            walk.collect(f"chip {kind}")

        toggle = panel.query_one("#flow_funnel_toggle", Button)
        toggle.press()
        await settled(pilot, lambda: is_displayed(panel.query_one("#flow_funnel_editor")), "Variables open")
        walk.collect("variables open")
        toggle.press()
        await settled(pilot, lambda: not is_displayed(panel.query_one("#flow_funnel_editor")), "Variables closed")
        walk.collect("variables closed")

        await _press_kind_chip(app, pilot, panel, BLOCK_SOURCE, "◉ LOAD")
        assert panel.query_one("#flow_ref", Input).value == ""
        panel.query_one("#flow_add", Button).press()
        notice = panel.query_one("#flow_wiring_notice")
        await settled(
            pilot,
            lambda: is_displayed(notice) and "Add needs" in _painted(app, notice),
            "the Add notice is shown",
        )
        walk.collect("add notice")

        for count in (1, 2, 3):
            panel.query_one("#flow_ref", Input).value = "prg.s19"
            panel.query_one("#flow_add", Button).press()
            title = f"chain · {count} block" + ("" if count == 1 else "s")
            await settled(pilot, lambda: _chain_title(panel) == title, f"the chain reads {title}")
            walk.collect(f"{count} LOAD block(s)")
        assert _painted(app, panel.query_one("#flow_pipeline")).count("◉ LOAD") == 3

        return len(walk.population), walk.never_shown(), walk.states

    size, never, states = _drive(tmp_path, body)
    assert size >= 45, (size, states)
    assert never == [], f"mounted and never shown: {never}"


# --------------------------------------------------------------------------- #
# R-FX-SCR.4 - the Flow Execution walk
# --------------------------------------------------------------------------- #


def test_r_fx_scr_4_1_every_flow_execution_widget_is_shown_in_a_state(tmp_path: Path) -> None:
    """R-FX-SCR.4 (case /1): walk [Flow Execution shown, no lane;
    ``flash_chain`` imported; Run, until ``#fx_required`` is shown; set name
    ``s``, Save Set, until ``#fx_notice`` is shown] -> 0 ids never shown, at
    least 30 ids in the population (the lane widgets mount on the import).

    RED on base: the help sentence is mounted and never shown; the failure
    message lists its id.
    """

    async def body(app, pilot, project_dir):
        panel = await open_flow_execution(app, pilot)
        walk = _Walk(panel)
        await settled(pilot, lambda: panel.lane_count() == 0, "no lane yet")
        walk.collect("no lane")

        await import_flow(app, pilot, "flash_chain")
        await settled(pilot, lambda: panel.lane_count() == 1, "flash_chain is imported as a lane")
        await settled(
            pilot,
            lambda: app.query_one("#fx_lane_0").region.width > 0,
            "the lane is laid out",
        )
        walk.collect("flash_chain imported")

        panel.query_one("#fx_run", Button).press()
        await settled(
            pilot,
            lambda: is_displayed(panel.query_one("#fx_required")),
            "the run waits at the external step: required line shown",
        )
        walk.collect("run waiting")

        panel.query_one("#fx_set_name", Input).value = "s"
        set_file = project_dir / "flowsets" / "s.json"
        panel.query_one("#fx_save", Button).press()
        await settled(pilot, set_file.exists, "the set file s.json is on disk")
        await settled(
            pilot,
            lambda: is_displayed(panel.query_one("#fx_notice")),
            "the set notice is shown",
        )
        walk.collect("set saved")

        return len(walk.population), walk.never_shown(), walk.states

    size, never, states = _drive(tmp_path, body)
    assert size >= 30, (size, states)
    assert never == [], f"mounted and never shown: {never}"


# --------------------------------------------------------------------------- #
# R-FB-ADD.1 (E3 S-1) - a press naming no block kind changes nothing
# --------------------------------------------------------------------------- #


def test_r_fb_add_1_2_a_press_naming_no_kind_changes_nothing(tmp_path: Path, monkeypatch) -> None:
    """R-FB-ADD.1 (case /2, E3 S-1): with the CHECK chip chosen, a button
    whose id is ``flow_palette_bogus`` mounted into the palette row and pressed
    leaves the kind tag at ``CHECK``, the CHECK chip marked (and it alone), the
    inputs shown unchanged (the gating control among them) and raises nothing;
    then ``baseline.chk.json`` and Add paint one CHECK card and no notice.

    RED on base: the hidden kind select refuses the value with
    ``InvalidSelectValueError`` at the stray press. A mutant that stores the
    suffix unchecked also fails: the later Add gives ``Add needs ...`` and
    adds nothing.
    """
    seen: list = []
    original = fs.FlowBuilderPanel.on_button_pressed

    def spying(self, event):
        seen.append(event.button.id)
        return original(self, event)

    monkeypatch.setattr(fs.FlowBuilderPanel, "on_button_pressed", spying)

    async def body(app, pilot, project_dir):
        panel = await open_flow_builder(app, pilot)
        await _press_kind_chip(app, pilot, panel, BLOCK_CHECK, CHECK_TAG)
        gating = panel.query_one("#flow_gating")
        assert is_displayed(gating)
        before_shown = _shown(panel)
        before_marked = sorted(c.id for c in panel.query(".chip-selected"))
        assert before_marked == [f"flow_palette_{BLOCK_CHECK}"], before_marked

        stray = Button("bogus", id="flow_palette_bogus")
        await panel.query_one("#flow_palette").mount(stray)
        await settled(pilot, lambda: stray.region.width > 0, "the stray button is laid out")
        stray.press()
        await settled(pilot, lambda: "flow_palette_bogus" in seen, "the stray press reached the panel")
        await settle(pilot, 4)

        after = {
            "tag": _tag(app, panel),
            "marked": sorted(c.id for c in panel.query(".chip-selected")),
            "shown": _shown(panel) - {"flow_palette_bogus"},
            "gating": is_displayed(gating),
            "notice": is_displayed(panel.query_one("#flow_wiring_notice")),
        }

        panel.query_one("#flow_ref", Input).value = "baseline.chk.json"
        panel.query_one("#flow_add", Button).press()
        await settled(
            pilot,
            lambda: _chain_title(panel) == "chain · 1 block"
            or is_displayed(panel.query_one("#flow_wiring_notice")),
            "Add added a block or refused",
        )
        await settle(pilot, 2)
        return (
            before_shown,
            before_marked,
            after,
            _painted(app, panel.query_one("#flow_pipeline")),
            _chain_title(panel),
            _painted(app, panel.query_one("#flow_wiring_notice")) if is_displayed(panel.query_one("#flow_wiring_notice")) else "",
        )

    before_shown, before_marked, after, pipeline, title, notice = _drive(tmp_path, body)
    assert CHECK_TAG in after["tag"], after["tag"]
    assert after["marked"] == before_marked, after["marked"]
    assert after["shown"] == before_shown, sorted(after["shown"] ^ before_shown)
    assert after["gating"] is True
    assert after["notice"] is False
    assert notice == "", notice
    assert title == "chain · 1 block", title
    assert pipeline.count(CHECK_TAG) == 1, pipeline


# --------------------------------------------------------------------------- #
# AT-I12b-1 - the visible controls do what the removed mirrors did
# --------------------------------------------------------------------------- #


def test_at_i12b_1_kind_chip_add_and_ribbon_by_keys(tmp_path: Path) -> None:
    """AT-I12b-1 (US-I12b-1; R-TUI-059.25 with the cited R-FB-ADD.1, .3 and
    R-FB-RIB.2): rail key ``8`` shows the Flow Builder; ``tab`` until the CHECK
    chip has the focus; ``space``; type ``baseline.chk.json`` into the image
    field; ``tab`` to ``+ Add``; ``enter``. The kind tag reads ``CHECK``, the
    gating control is shown, the pipeline paints one CHECK card, and the
    ribbon ``#flow_name_strip`` shows ``session`` with the project folder's
    path tail.

    The ribbon part holds on base; the walk nodes carry the removed widgets.
    """

    async def body(app, pilot, project_dir):
        await pilot.press("8")
        panel = app.query_one("#flow_panel")
        await settled(pilot, lambda: panel.region.height > 0, "rail key 8 shows the Flow Builder")
        chip = panel.query_one(f"#flow_palette_{BLOCK_CHECK}")
        field = panel.query_one("#flow_ref", Input)
        add = panel.query_one("#flow_add")

        async def tab_to(target, what: str) -> None:
            for _ in range(150):
                if app.focused is target:
                    return
                await pilot.press("tab")
                await settle(pilot, 1)
            raise AssertionError(f"tab did not reach {what} in 150 presses; focus is {app.focused!r}")

        await tab_to(chip, "the CHECK chip")
        await pilot.press("space")
        await settled(
            pilot,
            lambda: CHECK_TAG in _tag(app, panel) and chip.has_class("chip-selected"),
            "space chose the CHECK kind",
        )
        gating_shown = is_displayed(panel.query_one("#flow_gating"))
        tag = _tag(app, panel)

        await tab_to(field, "the image field")
        for char in "baseline.chk.json":
            await pilot.press(char)
        await settled(pilot, lambda: field.value == "baseline.chk.json", "the name is typed")
        await tab_to(add, "+ Add")
        await pilot.press("enter")
        await settled(pilot, lambda: _chain_title(panel) == "chain · 1 block", "Add put one block in the chain")
        await settle(pilot, 2)
        return (
            tag,
            gating_shown,
            _painted(app, panel.query_one("#flow_pipeline")),
            _painted(app, panel.query_one("#flow_name_strip")),
            # The ribbon paints the OS path string (backslashes on Windows).
            str(project_dir),
        )

    tag, gating_shown, pipeline, ribbon, project = _drive(tmp_path, body)
    assert CHECK_TAG in tag, tag
    assert gating_shown is True
    assert pipeline.count(CHECK_TAG) == 1, pipeline
    assert "session" in ribbon, ribbon
    # The ribbon keeps the tail of the project folder's path (clipped with an
    # ellipsis at the head, and by the painted width at the end): what follows
    # ``session`` is a stretch of that path.
    shown_path = ribbon.split("session", 1)[1].strip().strip("…").strip()
    assert len(shown_path) >= 8 and shown_path in project, (shown_path, project)
