"""Batch-101 Inc 9 (G-T2) - flow and chain-set names, report mode line and
refused saves, driven through the shipped keys, buttons and dialogs.

Design under test: ``.dev-flow/2026-11-01-batch-101/inc-9/01-requirements.md``
rows R-FLOW-CHAIN.19, .20, R-FLOW-FILE.12 (the Builder and lane-report arm),
R-FB-SAVE.8, R-FX-SET.15 and the acceptance cases AT-I9-1 .. AT-I9-3 of
``inc-9/02-test-cases.md``. Every node reads what the app paints (the status
line ``#log_line_4``, the notice and ribbon widgets) or what lands on disk
(``flows/``, ``flowsets/``, ``reports/``), and waits through ``settled`` for
the action's own sign. No product file is edited here and the OS clipboard is
never touched (the per-test ``LOCALAPPDATA`` isolation is the shared one).

Traceability (E4): test names start ``test_r_<row id>_...`` or
``test_at_i9_...`` so the registry binds them.
"""
from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path

from textual.widgets import Button, Input, Label, ListView, Select

from s19_app.tui import flow_screens as fs
from s19_app.tui.app import S19TuiApp
from s19_app.tui.services.flow_model import BLOCK_SOURCE, ReportBlock, SourceBlock
from tests.b97_fixtures import (
    flash_evidence,
    flow_project,
    fx_project,
    import_lanes,
    load_flow,
    make_junction,
    open_flow_builder,
    open_flow_execution,
    run_lanes,
    write_flow,
)
from tests.b97_probes import painted_rows, settle, settled
from tests.support.b100_projects import StatusLog

SIZE = (118, 54)
SET_P = ("patch_chain", "flash_chain", "patch_chain_b")
SET_S = SET_P

#: The exact I-3 refusal texts of the graph.
FLOW_REFUSED = "Flow not saved - the project's flows folder is a link or is outside the work area."
SET_REFUSED = "Chain set not saved - the project's flowsets folder is a link or is outside the work area."

#: The report writer escapes an underscore for markdown.
MD_UNDERSCORE = chr(92) + "_"
#: First line of the flow report of the lane ``rep_b`` (em dash, escaped underscore).
REP_B_TITLE = "# Flow report " + chr(0x2014) + " rep" + MD_UNDERSCORE + "b"

_LEDGER_ROW = re.compile(r"^\|\s*\d+\s*\|\s*(.+?)\s*\|")


# --------------------------------------------------------------------------- #
# drivers and readers
# --------------------------------------------------------------------------- #


def _drive(tmp_path: Path, body, *, builder: bool = False):
    """Open the app at 118x54 on the Builder project (``flow_project``) or the
    Flow Execution project (``fx_project``), both opened through the app's own
    load, and return ``await body(app, pilot, project_dir)``."""

    async def _run():
        app = S19TuiApp(base_dir=tmp_path)
        log = StatusLog(app)
        async with app.run_test(size=SIZE) as pilot:
            await settle(pilot)
            project_dir = await (flow_project(app) if builder else fx_project(app))
            return await body(app, pilot, project_dir, log)

    return asyncio.run(_run())


def _painted_status(app) -> str:
    """The status line as painted in ``#log_line_4`` (read once, after the
    action's own sign was waited for through ``StatusLog.since``)."""
    label = app.query_one("#log_line_4", Label)
    return " ".join(row.strip() for row in painted_rows(app, label) if row.strip())


def _painted(app, widget) -> str:
    return " ".join(row.strip() for row in painted_rows(app, widget) if row.strip())


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _chain_set_reports(project_dir: Path) -> list:
    return sorted((project_dir / "reports").glob("*-chain-set-report.md"))


def _flow_reports(project_dir: Path) -> list:
    return sorted(
        path
        for path in (project_dir / "reports").glob("*-report.md")
        if not path.name.endswith("-chain-set-report.md")
    )


def _ledger_chains(report: str) -> list:
    """The Chain cell of every row of the report's Chain ledger table."""
    lines = report.splitlines()
    start = lines.index("## Chain ledger")
    rows = []
    for line in lines[start + 4 :]:
        match = _LEDGER_ROW.match(line)
        if match is None:
            break
        rows.append(match.group(1).replace(MD_UNDERSCORE, "_"))
    return rows


def _link_home(tmp_path: Path, project_dir: Path, folder: str) -> Path:
    """Replace ``<project>/<folder>`` by a link (junction on Windows, symlink
    elsewhere) to ``<tmp>/outside/<folder>`` (Folder O); an existing folder is
    moved aside first. Returns the outside folder."""
    target = tmp_path / "outside" / folder
    home = project_dir / folder
    if home.exists() or home.is_symlink():
        aside = tmp_path / "aside"
        aside.mkdir(exist_ok=True)
        home.rename(aside / folder)
    make_junction(home, target)
    return target


def _entries(folder: Path) -> list:
    return sorted(path.name for path in folder.iterdir())


# --------------------------------------------------------------------------- #
# Builder and Flow Execution controls (the shipped buttons, picker and dialogs)
# --------------------------------------------------------------------------- #


async def _add_load_block(app, pilot, panel) -> None:
    """A LOAD ``prg.s19`` through the palette chip, ``#flow_ref`` and Add."""
    before = len(panel._blocks)
    await pilot.click(f"#flow_palette_{BLOCK_SOURCE}")
    await settled(
        pilot,
        lambda: str(panel.query_one("#flow_kind", Select).value) == BLOCK_SOURCE,
        "the LOAD kind is chosen in the palette",
    )
    panel.query_one("#flow_ref", Input).value = "prg.s19"
    panel.query_one("#flow_add", Button).press()
    await settled(pilot, lambda: len(panel._blocks) == before + 1, "the LOAD block is added")


async def _clear(app, pilot, panel) -> None:
    panel.query_one("#flow_clear", Button).press()
    await settled(pilot, lambda: not panel._blocks, "Clear emptied the canvas")


async def _open_save_dialog(app, pilot, panel, name: str) -> None:
    """Save..., wait for the dialog and its prefill, type ``name``, press Save."""
    panel.query_one("#flow_save", Button).press()
    await settled(
        pilot,
        lambda: bool(app.screen.query("#flow_save_name")),
        "the Save flow dialog is composed",
    )
    await settled(
        pilot,
        lambda: app.screen.query_one("#flow_save_name", Input).value == panel.current_flow.name,
        "the save-name prefill landed",
    )
    app.screen.query_one("#flow_save_name", Input).value = name
    app.screen.query_one("#flow_save_ok", Button).press()


async def _builder_save(app, pilot, panel, name: str, done) -> None:
    await _open_save_dialog(app, pilot, panel, name)
    await settled(pilot, done, f"the save of {name!r} reached its sign")
    await settle(pilot, 2)


async def _set_mode_parallel(app, pilot, panel) -> None:
    mode = panel.query_one("#fx_mode")
    assert mode.mode == "sequential", mode.mode
    mode.focus()
    await settled(pilot, lambda: app.focused is mode, "the mode switch has the focus")
    await pilot.press("enter")
    await settled(pilot, lambda: mode.mode == "parallel", "the mode switch reads parallel")


async def _import_by_keys(app, pilot, panel, stem: str) -> None:
    """Import... by ``enter``, the stem picked with ``down`` and Load by ``tab``
    + ``enter`` - keys only."""
    before = panel.lane_count()
    button = panel.query_one("#fx_import")
    button.focus()
    await settled(
        pilot,
        lambda: app.focused is button and not button.has_class("-active"),
        "Import focused",
    )
    await pilot.press("enter")
    await settled(
        pilot,
        lambda: bool(app.screen.query("#flow_list ListItem")),
        "the flow picker lists flows",
    )
    listing = app.screen.query_one("#flow_list", ListView)
    if app.focused is not listing:
        listing.focus()
        await settled(pilot, lambda: app.focused is listing, "the picker list has the focus")
    for _ in range(40):
        child = listing.highlighted_child
        if child is not None and child.name == stem:
            break
        await pilot.press("down")
        await settle(pilot, 1)
    assert listing.highlighted_child is not None and listing.highlighted_child.name == stem
    for _ in range(8):
        if app.focused is not None and app.focused.id == "flow_load_ok":
            break
        await pilot.press("tab")
        await settle(pilot, 1)
    assert app.focused is not None and app.focused.id == "flow_load_ok", app.focused
    await pilot.press("enter")
    await settled(
        pilot,
        lambda: panel.lane_count() == before + 1 and bool(app.query(f"#fx_lane_{before}")),
        f"flows/{stem}.json imported as a lane",
    )
    await settle(pilot, 2)


async def _dwell(pilot, panel) -> None:
    """Wait until the attention lane has held the attention for the confirm
    dwell (the clock the panel itself reads)."""
    await settled(
        pilot,
        lambda: panel._attention_since is not None
        and fs._fx_clock() - panel._attention_since > fs.CONFIRM_DWELL_S + 0.1,
        "the attention lane held the attention past the confirm dwell",
    )


async def _run_set_then_confirm(app, pilot, project_dir, panel):
    """Run the lanes (the mode is already chosen), write the Evidence, confirm
    lane 1 by its button and wait until the confirm re-run ended. Returns the
    texts of (the Run's report, the new reports after the re-run)."""
    before = _chain_set_reports(project_dir)
    await run_lanes(app, pilot, panel)
    after_run = [p for p in _chain_set_reports(project_dir) if p not in before]
    assert len(after_run) == 1, after_run
    confirm = panel.query_one("#fx_confirm_1")
    await settled(
        pilot,
        lambda: confirm.display and not confirm.disabled,
        "lane 1 waits and offers Confirm",
    )
    flash_evidence(project_dir)
    known = _chain_set_reports(project_dir)
    confirm.press()
    await settled(
        pilot,
        lambda: len(_chain_set_reports(project_dir)) == len(known) + 1
        and "re-run" in panel.run_log_plain()
        and not panel.query_one("#fx_run").disabled,
        "the confirm re-run wrote its report and Run is enabled again",
    )
    await settle(pilot, 2)
    run_text = after_run[0].read_text(encoding="utf-8")
    new = [p for p in _chain_set_reports(project_dir) if p not in known]
    return run_text, [p.read_text(encoding="utf-8") for p in new]


# --------------------------------------------------------------------------- #
# R-FLOW-CHAIN.19, .20 - the confirm re-run's chain-set report
# --------------------------------------------------------------------------- #


def test_r_flow_chain_19_1_confirm_writes_one_lane_report(tmp_path: Path) -> None:
    """R-FLOW-CHAIN.19 (case /1): after a parallel Run of three lanes, Confirm
    on the waiting lane 1 writes exactly one new chain-set report of that lane
    alone: ``- **Chains:** 1`` and one Chain ledger row, ``flash_chain``.

    Standing guard on base (the re-run already reports its one lane); it fails
    if the re-run ever reports the whole set or none.
    """

    async def body(app, pilot, project_dir, log):
        panel = await import_lanes(app, pilot, *SET_P)
        await _set_mode_parallel(app, pilot, panel)
        return await _run_set_then_confirm(app, pilot, project_dir, panel)

    _, new = _drive(tmp_path, body)
    assert len(new) == 1, f"expected exactly 1 new report, got {len(new)}"
    assert "- **Chains:** 1" in new[0].splitlines(), new[0]
    assert _ledger_chains(new[0]) == ["flash_chain"], _ledger_chains(new[0])


def test_r_flow_chain_20_1_parallel_confirm_mode_line(tmp_path: Path) -> None:
    """R-FLOW-CHAIN.20 (case /1): after a parallel Run, the confirm re-run's
    report holds the line ``- **Mode:** confirm re-run`` and no line
    ``- **Mode:** sequential``; the Run's report holds ``- **Mode:** parallel``.

    RED on base: the re-run's report reads ``- **Mode:** sequential``.
    """

    async def body(app, pilot, project_dir, log):
        panel = await import_lanes(app, pilot, *SET_P)
        await _set_mode_parallel(app, pilot, panel)
        return await _run_set_then_confirm(app, pilot, project_dir, panel)

    run_text, new = _drive(tmp_path, body)
    assert "- **Mode:** parallel" in run_text.splitlines(), run_text
    assert len(new) == 1, f"expected exactly 1 new report, got {len(new)}"
    lines = new[0].splitlines()
    assert "- **Mode:** confirm re-run" in lines, lines[:8]
    assert "- **Mode:** sequential" not in lines, lines[:8]


def test_r_flow_chain_20_2_sequential_confirm_mode_line(tmp_path: Path) -> None:
    """R-FLOW-CHAIN.20 (case /2): after a sequential Run, the Run's report
    holds ``- **Mode:** sequential`` and the confirm re-run's report holds
    ``- **Mode:** confirm re-run``.

    RED on base: both reports read ``- **Mode:** sequential``.
    """

    async def body(app, pilot, project_dir, log):
        panel = await import_lanes(app, pilot, *SET_S)
        assert panel.query_one("#fx_mode").mode == "sequential"
        return await _run_set_then_confirm(app, pilot, project_dir, panel)

    run_text, new = _drive(tmp_path, body)
    assert "- **Mode:** sequential" in run_text.splitlines(), run_text
    assert len(new) == 1, f"expected exactly 1 new report, got {len(new)}"
    assert "- **Mode:** confirm re-run" in new[0].splitlines(), new[0].splitlines()[:8]


# --------------------------------------------------------------------------- #
# R-FLOW-FILE.12 - the name a Builder save writes and a lane reads
# --------------------------------------------------------------------------- #


def test_r_flow_file_12_1_save_after_clear_holds_own_name(tmp_path: Path) -> None:
    """R-FLOW-FILE.12 (case /1): a flow loaded as ``patch_chain``, cleared,
    given a LOAD block and saved under ``tune_b`` is stored with
    ``"name": "tune_b"``, the stem of its file.

    RED on base: the stored name is the stale ``patch_chain``.
    """

    async def body(app, pilot, project_dir, log):
        panel = await open_flow_builder(app, pilot)
        await load_flow(app, pilot, "patch_chain")
        assert panel._flow_name == "patch_chain"
        await _clear(app, pilot, panel)
        await _add_load_block(app, pilot, panel)
        target = project_dir / "flows" / "tune_b.json"
        await _builder_save(app, pilot, panel, "tune_b", target.exists)
        return _read_json(target)

    saved = _drive(tmp_path, body, builder=True)
    assert saved["name"] == "tune_b", saved["name"]


def test_r_flow_file_12_5_lane_report_reads_the_saved_name(tmp_path: Path) -> None:
    """R-FLOW-FILE.12 (case /5, output then consume): a REPORT-bearing flow
    ``rep_a`` loaded through Load..., saved as ``rep_b`` and imported and run as
    a lane writes ``flows/rep_b.json`` holding ``"name": "rep_b"`` and exactly
    one new flow report whose first line is ``# Flow report - rep\\_b``.

    RED on base: the file holds ``rep_a`` and the report title reads ``rep\\_a``.
    """

    async def body(app, pilot, project_dir, log):
        write_flow(project_dir, "rep_a", [SourceBlock("prg.s19"), ReportBlock()])
        panel = await open_flow_builder(app, pilot)
        await load_flow(app, pilot, "rep_a")
        target = project_dir / "flows" / "rep_b.json"
        await _builder_save(app, pilot, panel, "rep_b", target.exists)
        saved = _read_json(target)
        before = _flow_reports(project_dir)
        fx_panel = await import_lanes(app, pilot, "rep_b")
        await run_lanes(app, pilot, fx_panel)
        await settled(
            pilot,
            lambda: len([p for p in _flow_reports(project_dir) if p not in before]) >= 1,
            "the lane's flow report is on disk",
        )
        new = [p for p in _flow_reports(project_dir) if p not in before]
        return saved, [p.read_text(encoding="utf-8") for p in new]

    saved, reports = _drive(tmp_path, body, builder=True)
    assert saved["name"] == "rep_b", saved["name"]
    assert len(reports) == 1, f"expected exactly 1 new flow report, got {len(reports)}"
    assert reports[0].splitlines()[0] == REP_B_TITLE, reports[0].splitlines()[0]


# --------------------------------------------------------------------------- #
# R-FB-SAVE.8, R-FX-SET.15 - the status line of a save refused for its home
# --------------------------------------------------------------------------- #


def test_r_fb_save_8_1_refused_home_status(tmp_path: Path) -> None:
    """R-FB-SAVE.8 (case /1): with ``flows/`` replaced by a link to a folder
    outside the work area, Save... under ``x`` paints exactly
    ``Flow not saved - the project's flows folder is a link or is outside the
    work area.`` on the status line, writes nothing outside, and the result
    area shows no ``saved`` line.

    RED on base: the file lands in the outside folder and the result shows
    ``saved flows/x.json``.
    """

    async def body(app, pilot, project_dir, log):
        panel = await open_flow_builder(app, pilot)
        outside = _link_home(tmp_path, project_dir, "flows")
        await _add_load_block(app, pilot, panel)
        mark = len(log.messages)
        await _open_save_dialog(app, pilot, panel, "x")
        await settled(
            pilot,
            lambda: FLOW_REFUSED in log.since(mark)
            or bool(_entries(outside))
            or "saved flows/" in _painted(app, panel.query_one("#flow_result")),
            "the refusal status is painted, or the file landed (base)",
        )
        await settle(pilot, 2)
        return (
            _painted_status(app),
            _entries(outside),
            _painted(app, panel.query_one("#flow_result")),
        )

    status, outside_files, result = _drive(tmp_path, body, builder=True)
    assert status == FLOW_REFUSED, status
    assert outside_files == [], outside_files
    assert "saved flows/" not in result, result


def test_r_fx_set_15_1_refused_home_status(tmp_path: Path) -> None:
    """R-FX-SET.15 (case /1): with one lane imported and ``flowsets/`` replaced
    by a link to a folder outside the work area, Save Set under ``s`` paints
    exactly ``Chain set not saved - the project's flowsets folder is a link or
    is outside the work area.``, writes nothing outside and the ribbon keeps
    ``unsaved``.

    RED on base: the file lands outside and the ribbon shows ``saved``.
    """

    async def body(app, pilot, project_dir, log):
        panel = await import_lanes(app, pilot, "patch_chain")
        outside = _link_home(tmp_path, project_dir, "flowsets")
        panel.query_one("#fx_set_name", Input).value = "s"
        mark = len(log.messages)
        panel.query_one("#fx_save", Button).press()
        await settled(
            pilot,
            lambda: SET_REFUSED in log.since(mark) or bool(_entries(outside)),
            "the refusal status is painted, or the file landed (base)",
        )
        await settle(pilot, 2)
        return (
            _painted_status(app),
            _entries(outside),
            _painted(app, panel.query_one("#fx_name_strip")),
        )

    status, outside_files, ribbon = _drive(tmp_path, body)
    assert status == SET_REFUSED, status
    assert outside_files == [], outside_files
    assert "unsaved" in ribbon and (chr(0xB7) + " saved") not in ribbon, ribbon


# --------------------------------------------------------------------------- #
# Acceptance cases AT-I9-1 .. AT-I9-3
# --------------------------------------------------------------------------- #


def test_at_i9_1_confirm_report_says_confirm_rerun(tmp_path: Path) -> None:
    """AT-I9-1 (US-I9-1, rows R-FLOW-CHAIN.19 and .20, black-box, keys only):
    three lanes imported through Import... and the picker, the mode switch on
    ``parallel`` by ``enter``, Run by ``enter`` with the focus on it, Evidence
    written, the dwell waited, ``c``: ``reports/`` holds two new chain-set
    reports - one ``- **Mode:** parallel`` with ``- **Chains:** 3``, one
    ``- **Mode:** confirm re-run`` with ``- **Chains:** 1`` and the ledger row
    ``flash_chain`` - and none says ``- **Mode:** sequential``.

    RED on base: the second report reads ``- **Mode:** sequential``.
    """

    async def body(app, pilot, project_dir, log):
        panel = await open_flow_execution(app, pilot)
        for stem in SET_P:
            await _import_by_keys(app, pilot, panel, stem)
        await _set_mode_parallel(app, pilot, panel)
        before = _chain_set_reports(project_dir)
        await run_lanes(app, pilot, panel, key=True)
        run_reports = [p for p in _chain_set_reports(project_dir) if p not in before]
        assert len(run_reports) == 1, run_reports
        flash_evidence(project_dir)
        await _dwell(pilot, panel)
        await pilot.press("c")
        await settled(
            pilot,
            lambda: len(_chain_set_reports(project_dir)) == len(before) + 2
            and "re-run" in panel.run_log_plain()
            and not panel.query_one("#fx_run").disabled,
            "the confirm re-run wrote its report and Run is enabled again",
        )
        await settle(pilot, 2)
        return [p.read_text(encoding="utf-8") for p in _chain_set_reports(project_dir) if p not in before]

    texts = _drive(tmp_path, body)
    assert len(texts) == 2, f"expected 2 new reports, got {len(texts)}"
    parallel = [t for t in texts if "- **Mode:** parallel" in t.splitlines()]
    confirm = [t for t in texts if "- **Mode:** confirm re-run" in t.splitlines()]
    sequential = [t for t in texts if "- **Mode:** sequential" in t.splitlines()]
    assert len(parallel) == 1 and "- **Chains:** 3" in parallel[0].splitlines(), parallel
    assert len(confirm) == 1, [t.splitlines()[3] for t in texts]
    assert "- **Chains:** 1" in confirm[0].splitlines(), confirm[0]
    assert _ledger_chains(confirm[0]) == ["flash_chain"], _ledger_chains(confirm[0])
    assert sequential == [], "a report still says sequential"


def test_at_i9_2_resaved_flow_and_long_set_keep_own_names(tmp_path: Path) -> None:
    """AT-I9-2 (US-I9-2, rows R-FLOW-FILE.12, R-FLOW-SET.9 and .10, output then
    consume; E3 addendum N-1): ``rep_a`` loaded and saved as ``rep_b``,
    imported and run as a lane, a 70-character set name saved through Save Set
    and reloaded through Load Set: ``flows/rep_b.json`` holds ``"name":
    "rep_b"``, the lane's flow report starts ``# Flow report - rep\\_b``,
    ``flowsets/<70 S>.json`` holds a 64-character name, and Load Set paints
    ``1 chain(s) restored`` with the one lane ``rep_b`` and no ``Chain set load
    refused`` status.

    RED on base: the flow keeps ``rep_a``, the report reads ``rep\\_a``, and Load
    Set paints a refusal (``chain-set name exceeds 64 characters``).
    """
    set_name = "S" * 70

    async def body(app, pilot, project_dir, log):
        write_flow(project_dir, "rep_a", [SourceBlock("prg.s19"), ReportBlock()])
        panel = await open_flow_builder(app, pilot)
        await load_flow(app, pilot, "rep_a")
        flow_file = project_dir / "flows" / "rep_b.json"
        await _builder_save(app, pilot, panel, "rep_b", flow_file.exists)
        flow_saved = _read_json(flow_file)
        before = _flow_reports(project_dir)
        fx_panel = await import_lanes(app, pilot, "rep_b")
        await run_lanes(app, pilot, fx_panel)
        await settled(
            pilot,
            lambda: len([p for p in _flow_reports(project_dir) if p not in before]) >= 1,
            "the lane's flow report is on disk",
        )
        reports = [
            p.read_text(encoding="utf-8") for p in _flow_reports(project_dir) if p not in before
        ]
        set_file = project_dir / "flowsets" / f"{set_name}.json"
        fx_panel.query_one("#fx_set_name", Input).value = set_name
        fx_panel.query_one("#fx_save", Button).press()
        await settled(pilot, set_file.exists, "the set file is on disk")
        select = fx_panel.query_one("#fx_set_select", Select)
        await settled(pilot, lambda: select.value == set_name, "the set picker offers the saved set")
        set_saved = _read_json(set_file)
        notice = fx_panel.query_one("#fx_notice")
        mark = len(log.messages)
        fx_panel.query_one("#fx_load", Button).press()
        await settled(
            pilot,
            lambda: "chain(s) restored" in _painted(app, notice)
            or any(m.startswith("Chain set load refused") for m in log.since(mark)),
            "Load Set restored the lanes or was refused",
        )
        await settle(pilot, 2)
        return (
            flow_saved,
            reports,
            set_saved,
            _painted(app, notice),
            _painted_status(app),
            fx_panel.lane_names(),
        )

    flow_saved, reports, set_saved, notice, status, lanes = _drive(tmp_path, body, builder=True)
    # every clause is checked before the verdict, so a RED names each failing one
    problems = []
    if flow_saved["name"] != "rep_b":
        problems.append(f"flows/rep_b.json name = {flow_saved['name']!r}")
    if len(reports) != 1:
        problems.append(f"{len(reports)} new flow reports, expected 1")
    elif reports[0].splitlines()[0] != REP_B_TITLE:
        problems.append(f"flow report title = {reports[0].splitlines()[0]!r}")
    if set_saved["name"] != "S" * 64:
        problems.append(f"set name has {len(set_saved['name'])} characters, expected 64")
    if "1 chain(s) restored" not in notice:
        problems.append(f"Load Set notice = {notice!r}")
    if status.startswith("Chain set load refused"):
        problems.append(f"status line = {status!r}")
    if lanes != ["rep_b"]:
        problems.append(f"lanes after Load Set = {lanes!r}")
    assert problems == [], problems


def test_at_i9_3_linked_homes_refuse_saves(tmp_path: Path) -> None:
    """AT-I9-3 (US-I9-3, rows R-FLOW-FILE.11, R-FLOW-SET.7, R-FB-SAVE.8 and
    R-FX-SET.15): with ``patch_chain`` imported as a lane and then ``flows/``
    and ``flowsets/`` replaced by links to folders outside the work area, the
    Builder Save... under ``x`` and Flow Execution Save Set under ``s`` each
    paint their exact refusal line and leave both outside folders empty.

    RED on base: one file lands in each outside folder.
    """

    async def body(app, pilot, project_dir, log):
        fx_panel = await import_lanes(app, pilot, "patch_chain")
        outside_flows = _link_home(tmp_path, project_dir, "flows")
        outside_sets = _link_home(tmp_path, project_dir, "flowsets")
        builder = await open_flow_builder(app, pilot)
        await _add_load_block(app, pilot, builder)
        mark = len(log.messages)
        await _open_save_dialog(app, pilot, builder, "x")
        await settled(
            pilot,
            lambda: FLOW_REFUSED in log.since(mark) or bool(_entries(outside_flows)),
            "the Builder refusal is painted, or the file landed (base)",
        )
        await settle(pilot, 2)
        flow_status = _painted_status(app)
        await open_flow_execution(app, pilot)
        mark = len(log.messages)
        fx_panel.query_one("#fx_set_name", Input).value = "s"
        fx_panel.query_one("#fx_save", Button).press()
        await settled(
            pilot,
            lambda: SET_REFUSED in log.since(mark) or bool(_entries(outside_sets)),
            "the Save Set refusal is painted, or the file landed (base)",
        )
        await settle(pilot, 2)
        return flow_status, _painted_status(app), _entries(outside_flows), _entries(outside_sets)

    flow_status, set_status, flows_files, sets_files = _drive(tmp_path, body)
    problems = []
    if flow_status != FLOW_REFUSED:
        problems.append(f"Builder status line = {flow_status!r}")
    if set_status != SET_REFUSED:
        problems.append(f"Save Set status line = {set_status!r}")
    if flows_files != []:
        problems.append(f"outside flows folder holds {flows_files!r}")
    if sets_files != []:
        problems.append(f"outside flowsets folder holds {sets_files!r}")
    assert problems == [], problems
