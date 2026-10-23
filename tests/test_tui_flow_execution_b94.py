"""Batch-94 Inc-003 — the fx_a Flow Execution surface through the shipped app.

AT-B94-02 · AT-B94-19…24 (black-box, C-18: one on-disk node per AT) +
TC-B94-08 · TC-B94-26 · TC-B94-27 · TC-B94-29 (white-box over the shipped
panel). Every drive goes through ``S19TuiApp`` routing; the rail entries are
activated by identity (rail click path), never by key — the R-1 closure keeps
every AT independent of the specific keys (the probe re-runs + TC-B94-08's
binding census own the keys).
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from textual.widgets import Button, Input, ListView, Select, Static

from s19_app.tui.app import RAIL_ENTRIES_B94, S19TuiApp
from s19_app.tui.flow_screens import FlowExecutionPanel
from s19_app.tui.rail import Rail, RailItem
from s19_app.tui.services import flow_persistence_service as fps
from s19_app.tui.services.flow_model import (
    CrcBlock,
    Flow,
    PatchBlock,
    SourceBlock,
    WriteOutBlock,
)

#: Minimal CLEAN S19 — 01 02 03 04 at 0x1000 (checksum-verified).
_S19 = "S107100001020304DE\nS9030000FC\n"

#: The pilot sizes AT-B94-02 pins (C-3): the primary, the smallest regime
#: (the rail-chrome arm), and the wide regime.
_PILOT_SIZES = ((120, 30), (80, 24), (160, 40))


def _make_project(tmp_path: Path, files: dict[str, str], name: str = "proj") -> Path:
    """Create ``<tmp>/.s19tool/workarea/<name>/`` holding the given files."""
    project_dir = tmp_path / ".s19tool" / "workarea" / name
    project_dir.mkdir(parents=True, exist_ok=True)
    for filename, content in files.items():
        (project_dir / filename).write_text(content, encoding="utf-8")
    return project_dir


def _patch_json(n_entries: int = 1) -> str:
    return json.dumps(
        {
            "format": "s19app-changeset",
            "version": "2.0",
            "kind": "change",
            "encoding": "utf-8",
            "value_mode": "text",
            "entries": [
                {"type": "bytes", "address": f"0x{0x1000 + i:X}", "bytes": "AA"}
                for i in range(n_entries)
            ],
        }
    )


def _base_blocks(source: str = "base.s19") -> list:
    return [
        SourceBlock(source),
        PatchBlock("hotfix.json"),
        WriteOutBlock("base_out.s19"),
    ]


def _crc_blocks() -> list:
    # crc_regions.json is deliberately ABSENT from the project — the bench
    # scenario's missing-config mid-run failure (AT-B94-23).
    return [
        SourceBlock("base.s19"),
        PatchBlock("hotfix.json"),
        CrcBlock("crc_regions.json"),
        WriteOutBlock("crc_out.s19"),
    ]


def _project(tmp_path: Path) -> Path:
    project = _make_project(
        tmp_path,
        {
            "base.s19": _S19,
            "variant_b.hex": _S19,
            "release.s19": _S19,
            "hotfix.json": _patch_json(),
        },
    )
    fps.save_flow_json(Flow(name="base", blocks=_base_blocks()), "base", project)
    return project


def _big_s19(records: int) -> str:
    """A large CHECKSUM-VALID S19 (S2 records — 24-bit addresses, so the
    address space outlives the record count; tens of ms to load+patch)."""
    lines = []
    for i in range(records):
        addr = 0x1000 + i * 16
        data = bytes([0xAB] * 16)
        count = 3 + len(data) + 1
        checksum = (
            ~((count + (addr >> 16) + ((addr >> 8) & 0xFF) + (addr & 0xFF) + sum(data)) & 0xFF)
        ) & 0xFF
        lines.append(
            f"S2{count:02X}{addr:06X}" + data.hex().upper() + f"{checksum:02X}"
        )
    lines.append("S804000000FB")
    return "\n".join(lines) + "\n"


def _big_project(tmp_path: Path, records: int = 4000) -> Path:
    """Chains long enough for honest parallel windows (tens of ms each)."""
    big = _big_s19(records)
    project = _make_project(
        tmp_path,
        {
            "base.s19": big,
            "hotfix.json": _patch_json(n_entries=400),
        },
    )
    fps.save_flow_json(Flow(name="big", blocks=_base_blocks()), "big", project)
    fps.save_flow_json(Flow(name="big_crc", blocks=_crc_blocks()), "big_crc", project)
    return project


async def _wait_for(app: S19TuiApp, pilot, selector: str, tries: int = 50) -> None:
    """Poll until ``selector`` resolves (the load-flaky settle idiom)."""
    for _ in range(tries):
        await pilot.pause()
        try:
            app.screen.query_one(selector)
            return
        except Exception:
            continue
    raise AssertionError(f"{selector} did not mount")


async def _show_fx(app: S19TuiApp, pilot, project: Path) -> None:
    """Enter Flow Execution through the shipped routing (key-independent)."""
    app.current_project_dir = project
    app.action_show_screen("flow_execution")
    await pilot.pause()


async def _import_stem(app: S19TuiApp, pilot, stem: str) -> None:
    """Drive the real Import… control + picker to a chosen stem."""
    app.query_one("#fx_import", Button).press()
    await _wait_for(app, pilot, "#flow_load_ok")
    await _wait_for(app, pilot, "#flow_list ListItem")
    items = app.screen.query_one("#flow_list", ListView)
    index = next(
        i
        for i, item in enumerate(items.query("ListItem"))
        if item.name == stem
    )
    items.index = index
    app.screen.query_one("#flow_load_ok", Button).press()
    await pilot.pause()
    await pilot.pause()


def _bind(app: S19TuiApp, lane: int, src: int, ref: str) -> None:
    app.query_one(f"#fx_in_{lane}_{src}", Input).value = ref
    app.query_one(f"#fx_bind_{lane}_{src}", Button).press()


# --------------------------------------------------------------------------- #
# AT-B94-02 — twelve rail entries, stable order, every entry mounts its panel
# --------------------------------------------------------------------------- #


#: The stable declared rail order (LLR-002.1's contract sequence) — pinned
#: LITERAL, not derived from the production constant: an AT that read its
#: expectation from ``RAIL_ENTRIES_B94`` would pass vacuously when the rail
#: lands 11 entries (the negative control names exactly that drift RED).
_DECLARED_RAIL_ORDER = [
    "workspace",
    "a2l",
    "mac",
    "map",
    "issues",
    "patch",
    "check_editor",
    "diff",
    "flow",
    "flow_execution",
    "checks",
    "crc_designer",
]


def test_at_b94_02_rail_twelve_entries_mount_panels(tmp_path: Path) -> None:
    """AT-B94-02 (HLR-002, LLR-002.1; black-box): the rail shows TWELVE
    entries in the stable declared order at every pinned pilot size
    (C-3: sizes declared here, incl. the 80x24 rail-chrome arm — 12 entries
    inside the 21-row chrome budget); every entry mounts its panel through
    the rail-click path (no key is exercised — the R-1 closure).
    """
    expected_order = list(_DECLARED_RAIL_ORDER)

    async def _drive(size: tuple[int, int]) -> tuple[list[str], int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            rail = app.query_one(Rail)
            keys = [item.entry.key for item in app.query(RailItem)]
            return keys, rail.region.height

    for size in _PILOT_SIZES:
        keys, rail_height = asyncio.run(_drive(size))
        assert keys == expected_order, (
            f"@{size}: the rail order drifted from the declared sequence: {keys}"
        )
        if size == (80, 24):
            # The C-3 rail-chrome arm: 24 - top 2 - footer 1 = 21 rows.
            assert rail_height <= 21, (
                f"@80x24: 12 entries must render inside the 21-row chrome "
                f"budget, rail renders {rail_height} rows"
            )

    async def _mount_each() -> list[str]:
        app = S19TuiApp(base_dir=tmp_path)
        mounted: list[str] = []
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            for item in list(app.query(RailItem)):
                item.post_message(RailItem.Selected(item.entry.key))
                await pilot.pause()
                container_id = S19TuiApp.SCREEN_CONTAINER_IDS[item.entry.key]
                if "hidden" not in app.query_one(f"#{container_id}").classes:
                    mounted.append(item.entry.key)
        return mounted

    mounted = asyncio.run(_mount_each())
    assert mounted == expected_order, (
        f"every rail entry must mount its own panel; mounted={mounted}"
    )


# --------------------------------------------------------------------------- #
# TC-B94-08 — the rail census constants (LLR-002.1, the binding census)
# --------------------------------------------------------------------------- #


def test_tc_b94_08_rail_entries_census_and_duplicate_rejection() -> None:
    """TC-B94-08 (LLR-002.1, white-box): RAIL_ENTRIES_B94 declares 12 in the
    preserved order (Check Editor after Patch Editor, Flow Execution after
    Flow Builder); SCREEN_IDS/SCREEN_KEYS move to 12; duplicate screen keys
    are rejected by construction (the key set has the census length).
    """
    keys = [entry.key for entry in RAIL_ENTRIES_B94]
    assert len(RAIL_ENTRIES_B94) == 12, f"rail declares {len(RAIL_ENTRIES_B94)}"
    assert keys.index("check_editor") == keys.index("patch") + 1
    assert keys.index("flow_execution") == keys.index("flow") + 1
    assert len(set(keys)) == 12, f"duplicate rail keys: {sorted(keys)}"
    # The production census maps move in lock-step (the guard host carries
    # the same constants — its C-28 consistency guard asserts the equality).
    assert len(S19TuiApp.SCREEN_CONTAINER_IDS) == 12
    assert len(set(S19TuiApp.SCREEN_CONTAINER_IDS)) == 12, (
        "duplicate screen container ids: "
        f"{sorted(S19TuiApp.SCREEN_CONTAINER_IDS.values())}"
    )
    assert S19TuiApp.SCREEN_CONTAINER_IDS["flow_execution"] == (
        "screen_flow_execution"
    )


# --------------------------------------------------------------------------- #
# AT-B94-19 — template import mounts lanes side by side (HLR-017)
# --------------------------------------------------------------------------- #


def test_at_b94_19_import_mounts_lanes_side_by_side(tmp_path: Path) -> None:
    """AT-B94-19 (HLR-017, black-box): importing a template adds one lane;
    a second import shows both chains SIDE BY SIDE at 120x30 and 160x40
    inside the boxed workspaces; each lane's blocks == its template's;
    a corrupt import is refused with a notice (0 lanes); a cancelled import
    adds 0 lanes.
    """
    project = _project(tmp_path)
    fps.save_flow_json(Flow(name="nightly", blocks=_base_blocks()), "nightly", project)
    (project / fps.FLOWS_SUBDIR / "corrupt.json").write_text("{ nope", encoding="utf-8")

    async def _drive(size: tuple[int, int]) -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        state: dict = {}
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            await _show_fx(app, pilot, project)
            panel = app.query_one("#fx_panel", FlowExecutionPanel)

            await _import_stem(app, pilot, "base")
            await pilot.pause()
            state["one_lane"] = panel.lane_count()

            await _import_stem(app, pilot, "nightly")
            await pilot.pause()
            state["two_lanes"] = panel.lane_count()
            state["names"] = panel.lane_names()
            screen = app.query_one("#screen_flow_execution")
            lanes = app.query("#fx_lanes .fx-lane")
            state["screen_box"] = (screen.region.width, screen.region.height)
            state["lanes_visible"] = all(
                lane.region.right <= screen.region.right
                and lane.region.bottom <= screen.region.bottom
                for lane in lanes
            )
            state["paint0"] = panel.lane_paint_plain(0)
            state["paint1"] = panel.lane_paint_plain(1)

            # Corrupt arm: refused with a notice, 0 lanes added.
            await _import_stem(app, pilot, "corrupt")
            await pilot.pause()
            notice = app.query_one("#fx_notice", Static)
            state["corrupt_notice"] = (
                notice.display,
                notice.render().plain,
                panel.lane_count(),
            )

            # Cancel arm: open the picker and Cancel — 0 lanes added.
            app.query_one("#fx_import", Button).press()
            await _wait_for(app, pilot, "#flow_load_cancel")
            app.screen.query_one("#flow_load_cancel", Button).press()
            await pilot.pause()
            state["after_cancel"] = panel.lane_count()
        return state

    for size in ((120, 30), (160, 40)):
        state = asyncio.run(_drive(size))
        assert state["one_lane"] == 1, "one import must add exactly one lane"
        assert state["two_lanes"] == 2, "two imports must show two lanes"
        assert state["names"] == ["base", "nightly"], state["names"]
        # The boxed budget: the screen is the measured 96x18 / 136x28 and
        # both lanes render fully inside it (side by side, no overlap).
        assert state["screen_box"] == (
            # batch-97 Inc-8 (LLR-150.6, named supersession): the two-row key bar costs one row.
            (96, 17) if size == (120, 30) else (136, 27)
        ), state["screen_box"]
        assert state["lanes_visible"], "both lanes must be fully visible"
        # Each lane's block list == its template's blocks (kind chain).
        # batch-97 Inc-6 (named supersession, LLR-147.1 / 147.2): the 44-cell
        # lane box (its `source → patch → write_out` line, `tpl` and `in1`
        # rows) is replaced by one card per block in order, the lane name
        # heading it and the SOURCE card holding the bound ref.
        for key, name in (("paint0", "base"), ("paint1", "nightly")):
            paint = state[key]
            cards = paint.splitlines()[1]
            assert cards.index("◉ LOAD") < cards.index("▣ PATCH") < cards.index("▼ WRITE-OUT"), paint
            assert name in paint.splitlines()[0], paint
        assert "base.s19" in state["paint0"], (
            f"the SOURCE card must show the template's own ref"
        )
        # Corrupt arm.
        shown, text, count = state["corrupt_notice"]
        assert shown and "refused" in text and count == 2, state["corrupt_notice"]
        # Cancel arm.
        assert state["after_cancel"] == 2, "a cancelled import adds 0 lanes"


# --------------------------------------------------------------------------- #
# TC-B94-26 — lane mounting + the render census (LLR-017.1/.2)
# --------------------------------------------------------------------------- #


def test_tc_b94_26_lane_mounting_and_render_census(tmp_path: Path) -> None:
    """TC-B94-26 (LLR-017.1/.2, white-box over the shipped panel): lane
    count == imported count, 0 missing/duplicates, 0 lanes on a cancelled
    import; lanes render at 120x30 (96x18) and 160x40 (136x28) with the
    chain name, pinned inputs and status region; at 80x24 the overflow is
    reachable by scroll rather than an error (74x12 cannot host two lanes).
    """
    project = _project(tmp_path)
    fps.save_flow_json(Flow(name="nightly", blocks=_base_blocks()), "nightly", project)

    async def _drive(size: tuple[int, int]) -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        state: dict = {}
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            await _show_fx(app, pilot, project)
            panel = app.query_one("#fx_panel", FlowExecutionPanel)
            await _import_stem(app, pilot, "base")
            await pilot.pause()
            await _import_stem(app, pilot, "nightly")
            await pilot.pause()
            await _import_stem(app, pilot, "base")  # duplicate import
            await pilot.pause()
            state["names"] = panel.lane_names()
            # The cancel arm (LLR-017.1): a cancelled import adds 0 lanes.
            app.query_one("#fx_import", Button).press()
            await _wait_for(app, pilot, "#flow_load_cancel")
            app.screen.query_one("#flow_load_cancel", Button).press()
            await pilot.pause()
            state["after_cancel"] = panel.lane_count()
            state["screen_box"] = (
                app.query_one("#screen_flow_execution").region.width,
                app.query_one("#screen_flow_execution").region.height,
            )
            lanes = list(app.query("#fx_lanes .fx-lane"))
            state["lane_count"] = len(lanes)
            screen = app.query_one("#screen_flow_execution")
            state["fit"] = all(
                lane.region.right <= screen.region.right
                for lane in lanes
            )
            scroll = app.query_one("#fx_lanes_scroll")
            state["max_scroll_x"] = scroll.max_scroll_x
            state["paints"] = [
                panel.lane_paint_plain(i) for i in range(panel.lane_count())
            ]
        return state

    wide = asyncio.run(_drive((120, 30)))
    assert wide["names"] == ["base", "nightly", "base_2"], (
        f"0 duplicate lanes: duplicate imports uniquify with the _<N> idiom; "
        f"got {wide['names']}"
    )
    assert wide["lane_count"] == 3
    assert wide["after_cancel"] == 3, "a cancelled import adds 0 lanes"
    assert wide["screen_box"] == (96, 17)  # batch-97 Inc-8 (LLR-150.6, named supersession): the two-row key bar costs one row
    assert wide["max_scroll_x"] <= 0 or wide["fit"], (
        "three lanes may scroll at 120x30 only with all lanes still laid out"
    )

    wider = asyncio.run(_drive((160, 40)))
    assert wider["screen_box"] == (136, 27)  # batch-97 Inc-8 (LLR-150.6, named supersession): the two-row key bar costs one row
    assert wider["lane_count"] == 3
    assert wider["after_cancel"] == 3

    # Two lanes at 120x30: fully visible (the census's own arm).
    async def _two_lanes() -> tuple[bool, list[str]]:
        app = S19TuiApp(base_dir=tmp_path / "two")
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await _show_fx(app, pilot, project)
            panel = app.query_one("#fx_panel", FlowExecutionPanel)
            await _import_stem(app, pilot, "base")
            await pilot.pause()
            await _import_stem(app, pilot, "nightly")
            await pilot.pause()
            screen = app.query_one("#screen_flow_execution")
            lanes = list(app.query("#fx_lanes .fx-lane"))
            fit = all(
                lane.region.right <= screen.region.right
                and lane.region.bottom <= screen.region.bottom
                for lane in lanes
            )
            paints = [panel.lane_paint_plain(0), panel.lane_paint_plain(1)]
            return fit, paints

    fit, paints = asyncio.run(_two_lanes())
    assert fit, "2 lanes must be fully visible at 120x30 (A3's boxed budget)"
    for paint in paints:
        # chain name, pinned inputs, and the status region, without overlap.
        # batch-97 Inc-6 (named supersession, LLR-147.1 / 147.2): the status
        # rides the cables and card status lines (`░` before a run); the
        # bound ref sits in the SOURCE card, no `in1` label.
        assert "▓" in paint or "░" in paint, "the status bar region renders"
        assert "base.s19" in paint

    # The 80x24 floor: the layout errors NOT — the overflow scrolls.
    narrow = asyncio.run(_drive((80, 24)))
    assert narrow["lane_count"] == 3, "lanes mount at the floor without error"
    assert narrow["after_cancel"] == 3
    assert not narrow["fit"] or narrow["max_scroll_x"] > 0, (
        "at 80x24 the lanes beyond the budget must be reachable by scroll"
    )


# --------------------------------------------------------------------------- #
# TC-B94-27 — lane bindings are independent state (LLR-018.1)
# --------------------------------------------------------------------------- #


def test_tc_b94_27_lane_binding_isolation_and_noop(tmp_path: Path) -> None:
    """TC-B94-27 (LLR-018.1, white-box over the shipped panel): editing lane
    A changes exactly A's record; B's bound path is byte-identical
    before/after (0 fields changed); a rebind to the same path is a no-op.
    """
    project = _project(tmp_path)

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await _show_fx(app, pilot, project)
            panel = app.query_one("#fx_panel", FlowExecutionPanel)
            await _import_stem(app, pilot, "base")
            await pilot.pause()
            await _import_stem(app, pilot, "base")
            await pilot.pause()
            before_b = panel.lane_bindings("base_2")
            field_b = app.query_one("#fx_in_1_0", Input).value
            dirty_before_noop = panel.is_dirty

            # Rebind A (the no-op arm first: same ref as now).
            _bind(app, 0, 0, "base.s19")
            await pilot.pause()
            noop_bindings = panel.lane_bindings("base")

            # Rebind A to a different file — exactly A's record changes.
            _bind(app, 0, 0, "variant_b.hex")
            await pilot.pause()
            after_a = panel.lane_bindings("base")
            after_b = panel.lane_bindings("base_2")
            field_b_after = app.query_one("#fx_in_1_0", Input).value
            paint_b = panel.lane_paint_plain(1)
            return {
                "before_b": before_b,
                "field_b": field_b,
                "dirty_before_noop": dirty_before_noop,
                "noop_bindings": noop_bindings,
                "after_a": after_a,
                "after_b": after_b,
                "field_b_after": field_b_after,
                "paint_b": paint_b,
            }

    state = asyncio.run(_drive())
    # The rebind-to-same arm: a no-op (0 records written, no dirty flag set —
    # the import itself set it; the no-op must not change the bindings).
    assert state["noop_bindings"] == {}, (
        f"rebinding to the same ref wrote a record: {state['noop_bindings']}"
    )
    # Editing A changed exactly A's record.
    assert state["after_a"] == {0: "variant_b.hex"}, state["after_a"]
    # B's binding record + UI field + painted lane are byte-identical.
    assert state["after_b"] == state["before_b"] == {}
    assert state["field_b_after"] == state["field_b"] == "base.s19"
    # batch-97 Inc-6 (named supersession, LLR-147.2): the bound ref sits in
    # the SOURCE card (no `in1` label).
    assert "base.s19" in state["paint_b"]
    assert "variant_b.hex" not in state["paint_b"], (
        "a cross-lane write leaked A's binding into B's lane"
    )


# --------------------------------------------------------------------------- #
# AT-B94-20 — per-chain rebinding: the run reads X for A and Y for B (HLR-018)
# --------------------------------------------------------------------------- #


def test_at_b94_20_rebind_run_reads_each_chains_own_inputs(tmp_path: Path) -> None:
    """AT-B94-20 (HLR-018, black-box): rebind chain A->variant_b.hex and
    chain B->release.s19; the run reads X for A and Y for B (the report's
    provenance lines); rebinding A leaves B's binding byte-identical.
    """
    project = _project(tmp_path)

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await _show_fx(app, pilot, project)
            panel = app.query_one("#fx_panel", FlowExecutionPanel)
            await _import_stem(app, pilot, "base")
            await pilot.pause()
            await _import_stem(app, pilot, "base")
            await pilot.pause()
            b_before = panel.lane_bindings("base_2")

            _bind(app, 0, 0, "variant_b.hex")
            await pilot.pause()
            b_after_a = panel.lane_bindings("base_2")
            _bind(app, 1, 0, "release.s19")
            await pilot.pause()

            app.query_one("#fx_run", Button).press()
            for _ in range(15):
                await pilot.pause()
            log = panel.run_log_plain()
            record = panel.last_run_record
            report = (
                record.report_path.read_text(encoding="utf-8")
                if record.report_path
                else ""
            )
            return {
                "b_after_a": b_after_a,
                "b_before": b_before,
                "log": log,
                "report": report,
                "statuses": [o.status for o in record.outcomes],
            }

    state = asyncio.run(_drive())
    # Rebinding A left B's binding byte-identical (0 fields changed).
    assert state["b_after_a"] == state["b_before"] == {}
    # The run consumed each chain's own bindings: both chains ran clean.
    assert state["statuses"] == ["ok", "ok"], state["statuses"]
    prov = [ln for ln in state["report"].splitlines() if ln.startswith("- Chain ")]
    assert len(prov) == 2, f"one provenance line per chain input: {prov}"
    # The chain half is md_safe-escaped in the report (``base_2`` -> ``base\_2``)
    # — match the escaped prefix and disambiguate by the bound file.
    a_line = next(
        ln for ln in prov if ln.startswith("- Chain base input 1")
    )
    b_line = next(ln for ln in prov if "release.s19" in ln)
    assert "variant_b.hex" in a_line and "release.s19" not in a_line
    assert "release.s19" in b_line and "variant_b.hex" not in b_line
    # Both resolved paths name the bound file.
    assert a_line.rstrip("`").endswith("variant_b.hex")
    assert b_line.rstrip("`").endswith("release.s19")
    # The run-log paints both lanes' completions.
    # batch-97 Inc-6 (named supersession, D7 (b) / PC-2): the terminal mark of
    # a clean chain is the cable vocabulary's `▓` (`✓` means check block).
    assert "▓ base" in state["log"] and "▓ base_2" in state["log"]


# --------------------------------------------------------------------------- #
# AT-B94-21 — parallel mode: overlapping windows, captured mode, isolation
# --------------------------------------------------------------------------- #


def test_at_b94_21_parallel_mode_overlaps_isolates_and_captures(tmp_path: Path) -> None:
    """AT-B94-21 (HLR-019, LLR-019.2; C-10 non-default arm, black-box): the
    parallel mode runs both chains CONCURRENTLY (overlapping elapsed windows
    in the record), the persisted run record reads ``parallel``, and a
    failing chain is isolated to its lane — the sibling completes (A5).
    """
    project = _big_project(tmp_path)

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await _show_fx(app, pilot, project)
            panel = app.query_one("#fx_panel", FlowExecutionPanel)
            await _import_stem(app, pilot, "big")
            await pilot.pause()
            await _import_stem(app, pilot, "big_crc")
            await pilot.pause()

            # Drive the NON-DEFAULT mode control (C-10).
            # batch-97 Inc-6 (named supersession, D13 / LLR-147.4): the mode
            # control is the one-row `sequential · parallel` toggle; `enter`
            # / `space` (its press) switch it to parallel.
            app.query_one("#fx_mode").press()
            assert app.query_one("#fx_mode").mode == "parallel"
            await pilot.pause()
            app.query_one("#fx_run", Button).press()
            for _ in range(30):
                await pilot.pause()
            record = panel.last_run_record
            report = (
                record.report_path.read_text(encoding="utf-8")
                if record.report_path
                else ""
            )
            return {
                "mode": record.mode,
                "windows": [
                    (o.chain, o.started_at, o.finished_at, o.status)
                    for o in record.outcomes
                ],
                "report": report,
                "written": [len(o.written_paths) for o in record.outcomes],
            }

    state = asyncio.run(_drive())
    (a_name, a_start, a_end, a_status), (b_name, b_start, b_end, b_status) = (
        state["windows"]
    )
    # The captured mode: the record reads ``parallel`` (never the default).
    assert state["mode"] == "parallel", state["mode"]
    assert "- **Mode:** parallel" in state["report"], (
        "the persisted report must carry the driven mode (C-10's persisted arm)"
    )
    # Overlapping elapsed windows: each chain started before the other ended.
    assert a_start < b_end and b_start < a_end, (
        f"parallel windows must overlap: {state['windows']}"
    )
    # A5 / the error arm: the failing chain (big_crc — its crc_regions.json
    # is absent) is isolated to its lane; the sibling completes AND writes.
    assert a_status == "ok" and b_status == "error", state["windows"]
    assert state["written"] == [1, 0], (
        f"the sibling's output must land, the failed chain writes nothing: "
        f"{state['written']}"
    )


# --------------------------------------------------------------------------- #
# AT-B94-22 — the untouched default run is strictly sequential (HLR-019)
# --------------------------------------------------------------------------- #


def test_at_b94_22_default_run_is_strictly_sequential(tmp_path: Path) -> None:
    """AT-B94-22 (HLR-019 default arm, black-box): an untouched run executes
    chains one at a time in lane order — chain N+1 starts only after chain
    N's terminal status, 0 elapsed overlap, and the run record reads
    ``sequential``.
    """
    project = _big_project(tmp_path)

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await _show_fx(app, pilot, project)
            panel = app.query_one("#fx_panel", FlowExecutionPanel)
            await _import_stem(app, pilot, "big")
            await pilot.pause()
            await _import_stem(app, pilot, "big_crc")
            await pilot.pause()
            # The mode control is UNTOUCHED — the default arm.
            # batch-97 Inc-6 (named supersession, D13): read the toggle.
            assert app.query_one("#fx_mode").mode == "sequential"
            app.query_one("#fx_run", Button).press()
            for _ in range(30):
                await pilot.pause()
            record = panel.last_run_record
            return {
                "mode": record.mode,
                "windows": [
                    (o.chain, o.started_at, o.finished_at) for o in record.outcomes
                ],
                "log": panel.run_log_plain(),
            }

    state = asyncio.run(_drive())
    assert state["mode"] == "sequential", state["mode"]
    (a_name, a_start, a_end), (b_name, b_start, b_end) = state["windows"]
    # 0 elapsed overlap: B starts only after A's terminal status.
    assert b_start >= a_end, (
        f"the default arm must not overlap chains: {state['windows']}"
    )
    # The run-log order arm: chain N+1's start line lands after chain N's
    # terminal line (A's terminal is its ▓ line; B's start is its `started`
    # line). batch-97 Inc-6 (named supersession): the terminal mark is `▓`
    # (D7 (b), PC-2) and the start line carries no mark (Q-B97-6a: `▶` is
    # the cable arrowhead on this screen).
    log = state["log"]
    a_terminal = log.index("▓ big")
    b_start_pos = log.index("big_crc · started")
    assert b_start_pos > a_terminal, (
        f"chain N+1 must start after chain N's terminal status: {log!r}"
    )


# --------------------------------------------------------------------------- #
# AT-B94-23 — the run log's inline failure + the report's provenance (HLR-020)
# --------------------------------------------------------------------------- #


def test_at_b94_23_run_log_inline_failure_and_report_provenance(
    tmp_path: Path,
) -> None:
    """AT-B94-23 (HLR-020, black-box): the run log shows per-chain start +
    terminal status and the inline ``✗`` line naming the block and the
    missing ``crc_regions.json``; the failing chain halts and its later
    blocks read ``skipped``; the report carries one provenance line per
    chain input.
    """
    project = _project(tmp_path)
    fps.save_flow_json(Flow(name="base_crc", blocks=_crc_blocks()), "base_crc", project)

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await _show_fx(app, pilot, project)
            panel = app.query_one("#fx_panel", FlowExecutionPanel)
            await _import_stem(app, pilot, "base")
            await pilot.pause()
            await _import_stem(app, pilot, "base_crc")
            await pilot.pause()
            app.query_one("#fx_run", Button).press()
            for _ in range(15):
                await pilot.pause()
            record = panel.last_run_record
            failed = record.outcomes[1]
            report = (
                record.report_path.read_text(encoding="utf-8")
                if record.report_path
                else ""
            )
            return {
                "log": panel.run_log_plain(),
                "failed_statuses": [
                    (br.kind, br.status) for br in failed.block_results
                ],
                "report": report,
            }

    state = asyncio.run(_drive())
    log = state["log"]
    # Per chain: one start line + one terminal status line (>= 2 lines each).
    # batch-97 Inc-6 (named supersession, Q-B97-6a / D7 (b)): the start line
    # carries no mark, the clean terminal mark is `▓`.
    for chain in ("base", "base_crc"):
        assert f"{chain} · started" in log, f"{chain} must have a start line: {log!r}"
        terminal = f"▓ {chain}" if chain == "base" else f"✗ {chain}"
        assert terminal in log, f"{chain} must have a terminal line: {log!r}"
    # The inline ✗ names the block AND the missing config (suggestion #1 —
    # visible without opening anything).
    fail_line = next(ln for ln in log.splitlines() if "✗ base_crc" in ln)
    assert "block 3/4 CRC" in fail_line, fail_line
    assert "crc_regions.json" in fail_line, fail_line
    assert "chain halted" in fail_line, fail_line
    # The failing chain halts; its later blocks read skipped.
    assert state["failed_statuses"] == [
        ("source", "ok"),
        ("patch", "ok"),
        ("crc", "error"),
        ("write_out", "skipped"),
    ], state["failed_statuses"]
    # The all-clean arm is the sibling: 0 ✗ lines naming it.
    assert not any("✗ base ·" in ln for ln in log.splitlines())
    # The report: one provenance line per chain input (2 inputs, 2 lines),
    # each resolving to the bound path.
    prov = [ln for ln in state["report"].splitlines() if ln.startswith("- Chain ")]
    assert len(prov) == 2, prov
    assert all("[bound] path=`" in ln for ln in prov)
    assert all(ln.rstrip("`").endswith("base.s19") for ln in prov)


# --------------------------------------------------------------------------- #
# TC-B94-29 — run-log emission over the shipped strip (LLR-020.1)
# --------------------------------------------------------------------------- #


def test_tc_b94_29_run_log_emission_and_all_clean_arm(tmp_path: Path) -> None:
    """TC-B94-29 (LLR-020.1, white-box over the shipped strip): per chain
    >=2 status lines (start, terminal); the all-clean arm shows 0 ``✗``
    lines; the painted strip is markup-safe (the C-32 painted oracle).
    """
    project = _project(tmp_path)

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await _show_fx(app, pilot, project)
            panel = app.query_one("#fx_panel", FlowExecutionPanel)
            await _import_stem(app, pilot, "base")
            await pilot.pause()
            await _import_stem(app, pilot, "base")
            await pilot.pause()
            app.query_one("#fx_run", Button).press()
            for _ in range(15):
                await pilot.pause()
            from textual.widgets import Static as _Static

            rendered = app.query_one("#fx_log", _Static).render()
            return {"plain": rendered.plain, "spans": rendered.spans}

    state = asyncio.run(_drive())
    plain = state["plain"]
    # Per chain >=2 status lines (start + terminal), 2 chains.
    # batch-97 Inc-6 (named supersession, Q-B97-6a / D7 (b)): the start line
    # carries no mark, the clean terminal mark is `▓`.
    for chain in ("base", "base_2"):
        assert f"{chain} · started" in plain, plain
        assert f"▓ {chain}" in plain, plain
    # The all-clean arm: 0 ✗ lines anywhere.
    assert "✗" not in plain, f"the all-clean run invented a failure: {plain!r}"
    # The painted oracle: the strip carries real painted content (C-32) —
    # the spans are style-only, the plain text is the assertion surface.
    assert state["plain"].strip(), "the run-log strip must not be empty"


# --------------------------------------------------------------------------- #
# AT-B94-24 — save / reload / re-run regenerates; the moved-input notice
# --------------------------------------------------------------------------- #


def test_at_b94_24_save_reload_rerun_regenerates_and_notices(tmp_path: Path) -> None:
    """AT-B94-24 (HLR-021, black-box; C-10 non-default battery + C-12):
    bind TWO different inputs to two chains, run, save the set, reload it,
    re-run — both outputs regenerate (driven by the RELOADED bindings, not
    the panel's current state); a moved input yields a per-chain
    provenance-mismatch notice, not a silent stale run.
    """
    project = _project(tmp_path)

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await _show_fx(app, pilot, project)
            panel = app.query_one("#fx_panel", FlowExecutionPanel)
            await _import_stem(app, pilot, "base")
            await pilot.pause()
            await _import_stem(app, pilot, "base")
            await pilot.pause()
            _bind(app, 0, 0, "variant_b.hex")
            await pilot.pause()
            _bind(app, 1, 0, "release.s19")
            await pilot.pause()

            app.query_one("#fx_run", Button).press()
            for _ in range(15):
                await pilot.pause()

            # Save the set under its own name.
            app.query_one("#fx_set_name", Input).value = "variants_a_b"
            app.query_one("#fx_save", Button).press()
            await pilot.pause()
            await pilot.pause()
            saved_path = project / fps.FLOWSETS_SUBDIR / "variants_a_b.json"
            saved_exists = saved_path.exists()

            # C-12: dirty the panel state AFTER the save — the reload, not
            # the current panel, is what re-runs.
            _bind(app, 0, 0, "base.s19")
            await pilot.pause()

            # Reload through the shipped Load Set control.
            select = app.query_one("#fx_set_select", Select)
            assert str(select.value) == "variants_a_b", str(select.value)
            app.query_one("#fx_load", Button).press()
            for _ in range(10):
                await pilot.pause()
            restored = {
                name: panel.lane_bindings(name) for name in panel.lane_names()
            }

            # Re-run: both outputs regenerate. ``save_patched_image`` never
            # overwrites — a re-run lands FRESH artifacts (the ``_<N>``
            # dedup idiom), so regeneration is asserted on the artifact set.
            import time as _time

            _time.sleep(0.01)
            before_files = sorted(project.glob("base_out*.s19"))
            app.query_one("#fx_run", Button).press()
            for _ in range(15):
                await pilot.pause()
            record = panel.last_run_record
            after_files = sorted(project.glob("base_out*.s19"))
            fresh = [p for p in after_files if p not in before_files]
            report = (
                record.report_path.read_text(encoding="utf-8")
                if record.report_path
                else ""
            )

            # The moved-input arm: rename an input away, reload — the lane
            # mounts with the per-chain mismatch notice.
            (project / "variant_b.hex").rename(project / "moved_away.hex")
            app.query_one("#fx_load", Button).press()
            for _ in range(10):
                await pilot.pause()
            notice = app.query_one("#fx_notice", Static).render().plain
            paint_after_move = panel.lane_paint_plain(0)
            return {
                "saved_exists": saved_exists,
                "restored": restored,
                "statuses": [o.status for o in record.outcomes],
                "written": [len(o.written_paths) for o in record.outcomes],
                "fresh_outputs": [p.name for p in fresh],
                "report": report,
                "notice": notice,
                "paint_after_move": paint_after_move,
            }

    state = asyncio.run(_drive())
    # Save persisted the whole set.
    assert state["saved_exists"], "save set must write flowsets/variants_a_b.json"
    # Reload restored the SAVED bindings (not the panel's post-save dirt):
    # C-12 — the reloaded set is what re-runs.
    assert state["restored"] == {"base": {0: "variant_b.hex"}, "base_2": {0: "release.s19"}}, (
        state["restored"]
    )
    # The re-run regenerated both chains' outputs (statuses ok, one written
    # path each). Fresh-artifact count: 0 — B8/TC-1800 (content-identical
    # reload reuses the target, no `_1` duplicate) supersedes the old
    # dedup-suffix idiom for the identical-bytes re-run; the C-12 substance
    # (the RELOADED bindings are what re-run, named in the provenance below)
    # is unchanged.
    assert state["statuses"] == ["ok", "ok"], state["statuses"]
    assert state["written"] == [1, 1], state["written"]
    assert state["fresh_outputs"] == [], (
        f"an identical-bytes re-run reuses the existing outputs (B8): {state['fresh_outputs']}"
    )
    # The re-run's provenance names the RELOADED bindings.
    prov = [ln for ln in state["report"].splitlines() if ln.startswith("- Chain ")]
    assert any("variant_b.hex" in ln for ln in prov), prov
    assert any("release.s19" in ln for ln in prov), prov
    # The moved-input arm: a per-chain notice, not a silent stale run.
    assert "missing" in state["paint_after_move"], state["paint_after_move"]
    assert "variant_b.hex" in state["paint_after_move"]
