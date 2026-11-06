"""Batch-101 increment 13 - the timing arms: the CRC Designer and the Split/Join
preview stay usable with the 10 MB demo image (finding F-23, user guide ch12.4
and ch14.6).

Written by the independent tester (E4) from the approved design only
(``inc-13/01-requirements.md``, ``02-test-cases.md``, ``E1-rulings.md`` E1-D9
and section 5, ``codewire/graph-inc13.md``). No line of the Inc 13
implementation was read.

Every node is ``serial_timing``: run it ALONE on the LAN Linux host
(``-m serial_timing``, never under ``-n``). The bounds are the requirement's
numbers through ``timing_bound`` and ``report_margin`` (the QC-TM margin
section). Each arm starts at the statement that triggers the work and stops at
a stamp the product emits: the first (or last, for the template load) call of
the result widget's ``update`` after the trigger, recorded by a wrapper of that
widget's ``update`` (engineering rule 3). A fast WRONG answer fails: the texts
are compared with oracles written here (``zlib.crc32`` over the demo image's
bytes; the engine's ``gap_conflict`` detector for the conflict size).

The demo image is built from the generator (``tests/support/b101_demo_image.py``).
On the base tree the arms are RED: about 5 s for the Join gaps change, about
2 min for the template load, about 10 s for the Ranges edit and about 25 s for
the Split/Join preview.
"""
from __future__ import annotations

import asyncio
import time
import zlib
from pathlib import Path
from typing import List, Tuple

import pytest
from textual.widgets import Button, Input, Select, Static

from s19_app.tui import crc_designer_view
from s19_app.tui.app import S19TuiApp
from s19_app.tui.operations import crc_designer_model
from s19_app.tui.operations.crc_designer_model import (
    CrcTarget,
    CrcTemplate,
    emit_template,
    gap_conflict,
)
from s19_app.tui.operations.crc_kernel import CrcAlgorithm
from s19_app.tui.segment_split_view import SplitJoinWindow, fmtB
from tests.support.b101_demo_image import (
    demo_loaded_file,
    demo_mem_map,
    demo_region_bytes,
)
from tests.support.b101_designer import (  # noqa: F401  (the fixture is used by name)
    designer_recompute_counter,
    designer_recomputes,
    wait_designer_recompute,
)
from tests.support.timing import report_margin, timing_bound, wait_until

pytestmark = pytest.mark.usefixtures("designer_recompute_counter")

F23_RANGES_SPACED = "0x00800000-0x00931FBF, 0x00C00000-0x00C00FFF"
F23_RANGES_COMPACT = "0x00800000-0x00931FBF,0x00C00000-0x00C00FFF"
#: Wall-clock ceiling of any wait inside an arm (the base tree needs minutes).
ARM_WAIT_S = 900.0
SHIPPED_QUIET_S = 0.150


class _Stamps:
    """Record ``time.perf_counter()`` and the content of every ``update`` call of
    one widget (a wrapper of that widget's ``update``)."""

    def __init__(self, widget: Static) -> None:
        self.items: List[Tuple[float, object]] = []
        original = widget.update

        def spy(*args, **kwargs):
            self.items.append((time.perf_counter(), args[0] if args else None))
            return original(*args, **kwargs)

        widget.update = spy

    def after(self, t0: float) -> List[Tuple[float, object]]:
        return [item for item in self.items if item[0] >= t0]


def _f23_window_crcs() -> Tuple[int, int]:
    """``zlib.crc32`` of the concat and the fill(0xFF) windows of the F-23 CRC
    scene (cal ``0x800000``-``0x931FBE`` plus config ``0xC00000``-``0xC00FFE``;
    the fill window pads the gap between them), from the demo image's bytes."""
    cal_base, cal = demo_region_bytes("cal")
    cfg_base, cfg = demo_region_bytes("config")
    assert (cal_base, cfg_base) == (0x800000, 0xC00000)
    first = cal[: 0x931FBF - cal_base]
    second = cfg[: 0xC00FFF - cfg_base]
    gap = b"\xff" * (cfg_base - 0x931FBF)
    return zlib.crc32(first + second), zlib.crc32(first + gap + second)


#: The values the user guide (ch12.4) prints for the same two windows.
GUIDE_CONCAT, GUIDE_FILL = 0x6CD65EAE, 0xA7B4C7F5


async def _crc_scene(pilot, app: S19TuiApp) -> None:
    """The F-23 CRC scene: the demo image loaded, the CRC Designer shown with the
    form it first shows, Ranges holding the scene's ranges, no change pending."""
    app.current_file = demo_loaded_file()
    await pilot.pause()
    await pilot.press("0")
    await pilot.pause()
    before = designer_recomputes()
    app.query_one("#crc_coverage_ranges", Input).value = F23_RANGES_SPACED
    await wait_designer_recompute(pilot, app, before, timeout=ARM_WAIT_S)


def _window_line2(content: object) -> str:
    return str(content).split("\n")[1]


# ---------------------------------------------------------------------------
# R-CRC-PREVIEW-002.2 - Join gaps concat -> fill in the F-23 CRC scene
# ---------------------------------------------------------------------------
@pytest.mark.serial_timing
def test_r_crc_preview_002_2_join_change_in_the_f23_scene_within_3_s(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Join gaps := fill (clock starts at the statement): the first update of
    ``#crc_coverage_window`` after it comes within ``timing_bound(3.0)``, the QC-TM
    margin is reported, window line 2 is ``concat <c>   fill <f>`` with ``<c>``
    and ``<f>`` the ``zlib.crc32`` of the two windows (and the guide's printed
    values), and a recompute reads at most two windows from the image.

    Why: about 10 s per recompute froze the screen with the demo image. Negative
    controls: the two renderers computing their own CRCs again -> the read count
    and the time RED; the per-byte input reflection restored in the CRC engine
    -> over the bound on the LAN host. Base: about 5 s measured (the fill is
    refused under On conflict abort: two window reads and two gap walks)."""
    concat, fill = _f23_window_crcs()
    assert (concat, fill) == (GUIDE_CONCAT, GUIDE_FILL), (hex(concat), hex(fill))
    reads = [0]
    original = crc_designer_model.gather_target

    def spy(*args, **kwargs):
        reads[0] += 1
        return original(*args, **kwargs)

    async def arm() -> Tuple[float, object, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await _crc_scene(pilot, app)
            stamps = _Stamps(app.query_one("#crc_coverage_window", Static))
            monkeypatch.setattr(crc_designer_model, "gather_target", spy)
            reads[0] = 0
            t0 = time.perf_counter()
            app.query_one("#crc_coverage_join", Select).value = "fill"
            await wait_until(
                pilot,
                lambda: bool(stamps.after(t0)),
                "the coverage window was never updated after the trigger",
                timeout=ARM_WAIT_S,
            )
            first = stamps.after(t0)[0]
            monkeypatch.setattr(crc_designer_model, "gather_target", original)
            return first[0] - t0, first[1], reads[0]

    elapsed, content, window_reads = asyncio.run(arm())
    assert elapsed < report_margin("R-CRC-PREVIEW-002.2/1", elapsed, timing_bound(3.0)), elapsed
    assert _window_line2(content) == f"concat 0x{concat:08X}   fill 0x{fill:08X}"
    assert window_reads <= 2, f"a recompute read the window {window_reads} times"


# ---------------------------------------------------------------------------
# R-CRC-PREVIEW-002.3 - the F-23 template load
# ---------------------------------------------------------------------------
@pytest.mark.serial_timing
def test_r_crc_preview_002_3_template_load_in_the_f23_scene_within_3_s(
    tmp_path: Path,
) -> None:
    """The F-23 template loaded in the F-23 CRC scene (Load path set and its
    recompute settled; clock starts at the Load press): the LAST update of
    ``#crc_coverage_window`` after the press comes within ``timing_bound(3.0)``
    and the load costs exactly one recompute.

    Why: a load set up to eleven widgets and each changed one recomputed the
    whole scene (about 2 min). Negative control: the fill's change events left on
    -> about eleven recomputes, about 2 min -> RED."""
    template = tmp_path / "demo-modbus.crc.json"
    algo = CrcAlgorithm("demo-modbus", 16, 0x8005, 0xFFFF, True, True, 0x0000, 0x4B37)
    template.write_text(
        emit_template(CrcTemplate(algorithm=algo, aliases=("a", "b"))), encoding="utf-8"
    )

    async def arm() -> Tuple[float, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await _crc_scene(pilot, app)
            before = designer_recomputes()
            app.query_one("#crc_load_path", Input).value = str(template)
            await wait_designer_recompute(pilot, app, before, timeout=ARM_WAIT_S)
            stamps = _Stamps(app.query_one("#crc_coverage_window", Static))
            before = designer_recomputes()
            t0 = time.perf_counter()
            app.query_one("#crc_load_btn", Button).press()
            await wait_designer_recompute(pilot, app, before, timeout=ARM_WAIT_S)
            await pilot.pause(0.5)
            updates = stamps.after(t0)
            assert updates, "the coverage window was never updated after Load"
            return updates[-1][0] - t0, designer_recomputes() - before

    elapsed, recomputes = asyncio.run(arm())
    assert elapsed < report_margin("R-CRC-PREVIEW-002.3/1", elapsed, timing_bound(3.0)), elapsed
    assert recomputes == 1, f"a template load must recompute once, got {recomputes}"


# ---------------------------------------------------------------------------
# R-CRC-PREVIEW-002.4 - a Ranges edit in the F-23 CRC scene
# ---------------------------------------------------------------------------
@pytest.mark.serial_timing
def test_r_crc_preview_002_4_ranges_edit_in_the_f23_scene_within_3_s(
    tmp_path: Path,
) -> None:
    """Ranges := the scene's ranges without the space (the same coverage, Join
    gaps concat; clock starts at the statement, t0): the first update of
    ``#crc_coverage_window`` after t0, minus (t0 + the shipped quiet time), comes
    within ``timing_bound(3.0)``; window line 2 is ``concat <c>   fill <f>`` with
    the ``zlib.crc32`` oracles.

    Why: typing in Ranges recomputed about 10 s per keystroke (six window reads
    with concat active). Negative controls: the per-byte input reflection restored
    in the CRC engine -> over the bound on the LAN host; the renderers computing
    their own CRCs again -> the read count of the previous arm RED."""
    concat, fill = _f23_window_crcs()
    quiet = getattr(crc_designer_view, "CRC_RECOMPUTE_S", SHIPPED_QUIET_S)

    async def arm() -> Tuple[float, object]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await _crc_scene(pilot, app)
            stamps = _Stamps(app.query_one("#crc_coverage_window", Static))
            t0 = time.perf_counter()
            app.query_one("#crc_coverage_ranges", Input).value = F23_RANGES_COMPACT
            await wait_until(
                pilot,
                lambda: bool(stamps.after(t0)),
                "the coverage window was never updated after the Ranges edit",
                timeout=ARM_WAIT_S,
            )
            first = stamps.after(t0)[0]
            return first[0] - (t0 + quiet), first[1]

    elapsed, content = asyncio.run(arm())
    assert elapsed < report_margin("R-CRC-PREVIEW-002.4/1", elapsed, timing_bound(3.0)), elapsed
    assert _window_line2(content) == f"concat 0x{concat:08X}   fill 0x{fill:08X}"


# ---------------------------------------------------------------------------
# R-SEG-PREV.20 and R-SEG-PREV.7 - the F-23 Split/Join scene
# ---------------------------------------------------------------------------
@pytest.mark.serial_timing
def test_r_seg_prev_20_join_fill_in_the_f23_scene_within_2_5_s(tmp_path: Path) -> None:
    """The demo image, Split / Join / Export open on ``ranges(4)``, ``range_00``
    and ``range_02`` ticked, ``m`` pressed (join, concat), then ``g`` (clock
    starts at the press): the first update of ``#sje_stats`` after it comes within
    ``timing_bound(2.5)``. The stats line is ``packed 1.26 MiB  ·  span 9.20 MiB
    ·  fill <pct>%`` and the state line GUARD state line
    ``⚠ GUARD  9.20 MiB span — e will ask`` (the base rendering; see the
    ambiguity note in the code), with ``<pct>`` derived from the engine
    detector's count (fill = span - packed - conflict bytes).

    Why: switching a join to fill took about 25 s because the band classified
    every interval against every conflict run. Negative control: the base
    ``_sweep`` restored -> about 25 s -> RED. Also R-SEG-PREV.7's state line."""
    mem = demo_mem_map()
    picked = ((0x0, 0x10000), (0x800000, 0x931FC0))
    conflicts = len(
        gap_conflict(mem, CrcTarget(picked, "skip", "fill", 0x00, 0, 1, "little"))
    )
    assert conflicts > 0
    packed = (0x10000 - 0x0) + (0x931FC0 - 0x800000)
    span = 0x931FC0
    fill_pct = 100 * (span - packed - conflicts) / span
    stats_line = (
        f"packed {fmtB(packed)}  ·  span {fmtB(span)}  ·  fill {fill_pct:.2f}%"
    )
    # Ambiguity (see E4-tester-notes): the case text expects the "would clobber
    # source" state line, but in this scene the span guard (span >= 1 MiB and
    # fill >= the guard fraction) takes the state line first, on the base tree
    # and by the rule "the increment changes no render". The conflict census
    # still feeds the fill percentage above.
    state_line = f"⚠ GUARD  {fmtB(span)} span — e will ask"
    assert stats_line.startswith("packed 1.26 MiB  ·  span 9.20 MiB")

    async def arm() -> Tuple[float, str, Tuple[str, str, set]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            app.current_file = demo_loaded_file()
            for _ in range(4):
                await pilot.pause()
            app.action_open_split_join_export()
            for _ in range(4):
                await pilot.pause()
            window = app.query_one("#screen_split_join", SplitJoinWindow)
            window._sel["ranges"] = {0, 2}
            await pilot.press("m")
            for _ in range(4):
                await pilot.pause()
            setup = (window._mode, window._gap, set(window._sel["ranges"]))
            stamps = _Stamps(app.query_one("#sje_stats", Static))
            t0 = time.perf_counter()
            await pilot.press("g")
            await wait_until(
                pilot,
                lambda: bool(stamps.after(t0)),
                "the stats line was never updated after g",
                timeout=ARM_WAIT_S,
            )
            first = stamps.after(t0)[0]
            return first[0] - t0, str(first[1]), setup

    elapsed, stats, setup = asyncio.run(arm())
    assert setup == ("join", "concat", {0, 2}), setup
    assert elapsed < report_margin("R-SEG-PREV.20/1", elapsed, timing_bound(2.5)), elapsed
    lines = [line.rstrip() for line in stats.split("\n")]
    assert lines[0] == stats_line, lines
    assert lines[1] == state_line, lines
