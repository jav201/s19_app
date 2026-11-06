"""Batch-101 increment 13 - when the CRC Designer recomputes, and what it shows
after the shared computation (findings F-23 and F-24).

Written by the independent tester (E4) from the approved design only
(``inc-13/01-requirements.md``, ``02-test-cases.md``, ``E1-slice.md``,
``codewire/graph-inc13.md``, ``E1-rulings.md`` and the ``E3-rulings.md``
addenda). No line of the Inc 13 implementation was read.

Every node drives the shipped surface (the rail key ``0``, the form widgets,
the Load button, the loaded image) through a Textual ``Pilot`` and asserts the
painted text of the result surfaces, or the count of recomputes. The count is
``CrcDesignerPanel._recompute`` calls, counted by the class-level wrapper of
``tests/support/b101_designer.py``; it is a requirement's own unit (the plan's
target is "one recompute per burst", "one per template load").

Quiet time and cap are module constants read at use, so the nodes replace them
with ``monkeypatch.setattr(..., raising=False)``: on a tree that does not have
the constant yet the node still collects and fails on its assertion (a
behavioural reason), not on an ``AttributeError`` of the patch. No node decides
by sampling the wall clock: "not before the quiet time" is a quiet time of 10 s
with the count and the pending timer read after two pauses; "after" is a short
quiet time and a wait on the count.

Base (``origin/main`` before Inc 13): rows that state a NEW behaviour fail
there (recompute counts, the image watcher, the cap, the line-1 scale);
rows that state an UNCHANGED behaviour (the field-state matrix, the dropdown
and toggle limbs of the immediate recompute) pass there and pin it.

The file also holds the integrity check of decision D-2 (the waits inserted
into ``tests/test_crc_designer_view.py`` change nothing else) and the control
that proves that check can fail.
"""
from __future__ import annotations

import ast
import asyncio
import subprocess
import zlib
from pathlib import Path
from typing import Dict, List, Optional

import pytest
from textual.widgets import Button, Input, Select, Static, Switch

from s19_app.tui import crc_designer_view
from s19_app.tui.app import S19TuiApp
from s19_app.tui.insight_style import MICROBAR_EMPTY, MICROBAR_FILLED
from s19_app.tui.operations import crc_designer_model
from s19_app.tui.operations.crc_designer_model import CrcTemplate, emit_template
from s19_app.tui.operations.crc_kernel import CrcAlgorithm
from tests.support.b101_designer import (  # noqa: F401  (the fixture is used by name)
    EMPTY_STATE,
    FIXTURE_CONCAT,
    FIXTURE_FILL,
    FIXTURE_PREVIEW,
    designer_pending,
    designer_recompute_counter,
    designer_recomputes,
    dirty_mem,
    fixture_mem,
    loaded,
    wait_designer_recompute,
)
from tests.support.timing import wait_until

pytestmark = pytest.mark.usefixtures("designer_recompute_counter")

REPO_ROOT = Path(__file__).resolve().parents[1]
REPS = 3  # the "3/3" of the requirement thresholds: three fresh apps per limb
GLYPHS = (MICROBAR_FILLED, MICROBAR_EMPTY)

#: The shipped cap and the shipped quiet time the design fixes (E3 round 2).
SHIPPED_CAP = 16777216
SHIPPED_QUIET_S = 0.150

REFUSAL_DIRTY_ABORT = (
    "Preview refused (on_gap_conflict=abort): 1 present byte(s) at 0x800B "
    "conflict with a filled gap; no CRC shown."
)
GAP_NOTE_WARN = (
    "gap-safety: 1 present byte(s) at 0x800B in a filled gap differ from "
    "pad_byte 0xFF — proceeding (on_gap_conflict=warn)"
)
HOSTILE_RANGES = "[link=evil]0x8000-0x8008[/], ["
HOSTILE_TEXT = (
    "Invalid coverage: invalid literal for int() with base 16: '[link=evil]0x8000'"
)
#: The first-shown Ranges, spelled without the space after the comma: the same
#: coverage, a different text, so setting it is an operator edit of a text field.
RANGES_NO_SPACE = "0x00008000-0x00008008,0x00008010-0x00008018"
F23_RANGES = "0x00800000-0x00931FBF, 0x00C00000-0x00C00FFF"


# ---------------------------------------------------------------------------
# Small readers
# ---------------------------------------------------------------------------
def _preview(app: S19TuiApp) -> str:
    return str(app.query_one("#crc_coverage_preview", Static).content)


def _window(app: S19TuiApp):
    return app.query_one("#crc_coverage_window", Static).render()


def _window_lines(app: S19TuiApp) -> List[str]:
    return str(_window(app)).split("\n")


def _verdict(app: S19TuiApp) -> str:
    return str(app.query_one("#crc_kat_verdict", Static).content)


def _glyphs(line: str) -> int:
    return sum(1 for ch in line if ch in GLYPHS)


def _set_quiet(monkeypatch: pytest.MonkeyPatch, seconds: float) -> None:
    monkeypatch.setattr(crc_designer_view, "CRC_RECOMPUTE_S", seconds, raising=False)


def _set_cap(monkeypatch: pytest.MonkeyPatch, size: int) -> None:
    monkeypatch.setattr(crc_designer_view, "_COVERAGE_CAP_BYTES", size, raising=False)


def _count_gathers(monkeypatch: pytest.MonkeyPatch) -> List[int]:
    """Count the calls of ``crc_designer_model.gather_target`` (one window read
    each); the list holds the running total in ``[0]``."""
    calls = [0]
    original = crc_designer_model.gather_target

    def spy(*args, **kwargs):
        calls[0] += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(crc_designer_model, "gather_target", spy)
    return calls


async def _load_and_recompute(
    pilot, app: S19TuiApp, mem: Dict[int, int], ranges: Optional[str] = RANGES_NO_SPACE
) -> None:
    """Install ``mem`` as the loaded image and make the panel recompute over it
    by an operator edit of Ranges (an edit that works before and after Inc 13),
    then wait for that recompute."""
    before = designer_recomputes()
    app.current_file = loaded(mem)
    if ranges is not None:
        app.query_one("#crc_coverage_ranges", Input).value = ranges
    await wait_designer_recompute(pilot, app, before)


def _run(coro_factory, reps: int = REPS) -> list:
    return [asyncio.run(coro_factory()) for _ in range(reps)]


# ---------------------------------------------------------------------------
# R-CRC-DESIGNER-001.2.1 - a toggle or a dropdown recomputes at once
# ---------------------------------------------------------------------------
def test_r_crc_designer_001_2_1_toggle_and_dropdown_recompute_at_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Join gaps concat -> fill (a dropdown) and Reflection in on -> off (a
    toggle) update the result surfaces after ONE pause, with the quiet time
    injected as 10 s, and cost exactly one recompute each (3 of 3).

    Why: a discrete choice has no burst to wait for; if it waited for the quiet
    time the screen would show a fresh verdict beside stale coverage, and every
    flip would wait 150 ms for nothing. Negative control: the dropdown/toggle
    handlers routed to the quiet-time timer -> the preview still reads
    ``join=concat`` after the pause -> RED. Passes on the base tree (it already
    recomputes at once): the node pins the behaviour the design keeps."""
    _set_quiet(monkeypatch, 10.0)

    async def dropdown():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.current_file = loaded(fixture_mem())
            await pilot.press("0")
            await pilot.pause()
            before = designer_recomputes()
            app.query_one("#crc_coverage_join", Select).value = "fill"
            await pilot.pause()
            return (
                _preview(app).split("\n")[0],
                designer_recomputes() - before,
                designer_pending(app),
            )

    async def toggle():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause()
            seed = _verdict(app)
            before = designer_recomputes()
            app.query_one("#crc_field_refin", Switch).value = False
            await pilot.pause()
            return seed, _verdict(app), designer_recomputes() - before

    for first_line, delta, pending in _run(dropdown):
        assert first_line == "Active policy: join=fill", first_line
        assert delta == 1, f"a dropdown change must cost one recompute, got {delta}"
        assert pending is None, "a dropdown change leaves no pending recompute"
    for seed, after, delta in _run(toggle):
        assert "✓ MATCH" in seed, seed
        assert "✗ MISMATCH" in after, after
        assert delta == 1, f"a toggle must cost one recompute, got {delta}"


# ---------------------------------------------------------------------------
# R-CRC-DESIGNER-001.2.2 - a text edit or an image change waits for the quiet time
# ---------------------------------------------------------------------------
def test_r_crc_designer_001_2_2_text_edit_recomputes_after_the_quiet_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """XOR out := 0x00000000 (a text field).

    (a) quiet time injected as 10 s: after two pauses there is no recompute, a
    recompute is pending and the verdict still reads ``MATCH``. (b) quiet time
    injected as 0.05 s on a fresh app: the same edit, then a wait on the count:
    exactly one recompute, none pending, the verdict ``MISMATCH``. 3 of 3.

    Why: the plan's target is one recompute per burst of typing; the wait must
    be the module's quiet time, and a decision that samples the clock would
    flake. Negative controls: a recompute at once on the edit -> (a) counts one
    -> RED; the timer never started -> (b) the wait times out -> RED."""

    async def scenario(quiet: float, wait: bool):
        _set_quiet(monkeypatch, quiet)
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause()
            before = designer_recomputes()
            app.query_one("#crc_field_xorout", Input).value = "0x00000000"
            if wait:
                await wait_designer_recompute(pilot, app, before)
            else:
                await pilot.pause()
                await pilot.pause()
            return (
                designer_recomputes() - before,
                designer_pending(app),
                _verdict(app),
            )

    for _ in range(REPS):
        delta, pending, verdict = asyncio.run(scenario(10.0, wait=False))
        assert delta == 0, f"no recompute before the quiet time, got {delta}"
        assert pending is not None, "a recompute must be pending for the edit"
        assert "✓ MATCH" in verdict and "MISMATCH" not in verdict, verdict
    for _ in range(REPS):
        delta, pending, verdict = asyncio.run(scenario(0.05, wait=True))
        assert delta == 1, f"exactly one recompute after the quiet time, got {delta}"
        assert pending is None, "nothing may stay pending after the recompute"
        assert "✗ MISMATCH" in verdict, verdict


def test_r_crc_designer_001_2_2_image_change_is_a_pending_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The loaded image set while the CRC Designer is displayed (F-24).

    (a) quiet time 10 s: after two pauses no recompute ran, one is pending and
    the preview still shows the empty-state note. (b) quiet time 0.05 s on a
    fresh app: after a wait on the count, exactly one recompute and the three
    preview lines. 3 of 3.

    Why: an image change is a pending change, so a project load that sets the
    image twice recomputes once and a load paints its own status first.
    Negative controls: the image watcher not registered -> (a) finds nothing
    pending, (b) the wait times out -> RED."""

    async def scenario(quiet: float, wait: bool):
        _set_quiet(monkeypatch, quiet)
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause()
            before = designer_recomputes()
            app.current_file = loaded(fixture_mem())
            if wait:
                await wait_designer_recompute(pilot, app, before)
            else:
                await pilot.pause()
                await pilot.pause()
            return designer_recomputes() - before, designer_pending(app), _preview(app)

    for _ in range(REPS):
        delta, pending, preview = asyncio.run(scenario(10.0, wait=False))
        assert delta == 0, f"no recompute before the quiet time, got {delta}"
        assert pending is not None, "the image change must leave a recompute pending"
        assert preview == EMPTY_STATE, preview
    for _ in range(REPS):
        delta, pending, preview = asyncio.run(scenario(0.05, wait=True))
        assert delta == 1, f"exactly one recompute after the quiet time, got {delta}"
        assert pending is None
        assert preview == FIXTURE_PREVIEW, preview


def test_r_crc_designer_001_2_2_quiet_time_is_150_ms() -> None:
    """The shipped quiet time is 150 ms (partial: the constant, not the wall
    clock). Why: the plan's ruled target is one recompute per 150 ms burst."""
    assert getattr(crc_designer_view, "CRC_RECOMPUTE_S", None) == SHIPPED_QUIET_S


# ---------------------------------------------------------------------------
# R-CRC-DESIGNER-007.1 .. 007.3 - one recompute per burst, per template, per preset
# ---------------------------------------------------------------------------
def test_r_crc_designer_007_1_edit_burst_recomputes_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Five edits of XOR out set back to back (``0x1`` ... ``0x00000000``),
    quiet time 0.6 s: after the wait on the count and 0.8 s more there is
    exactly one recompute and the verdict shows the LAST value's result. 3 of 3.

    Why: typing in a field must not cost one recompute per keystroke (about 10 s
    each with the 10 MB image). Negative controls: no timer -> five recomputes
    -> RED; a recompute on the first edit plus the trailing one -> two -> RED."""
    _set_quiet(monkeypatch, 0.6)

    async def scenario():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause()
            before = designer_recomputes()
            field = app.query_one("#crc_field_xorout", Input)
            for value in ("0x1", "0x2", "0x3", "0x4", "0x00000000"):
                field.value = value
            await wait_designer_recompute(pilot, app, before)
            await pilot.pause(0.8)
            return designer_recomputes() - before, _verdict(app)

    for delta, verdict in _run(scenario):
        assert delta == 1, f"an edit burst must recompute once, got {delta}"
        assert "✗ MISMATCH" in verdict, verdict


def _f23_template(path: Path) -> None:
    algo = CrcAlgorithm("demo-modbus", 16, 0x8005, 0xFFFF, True, True, 0x0000, 0x4B37)
    path.write_text(
        emit_template(CrcTemplate(algorithm=algo, aliases=("a", "b"))), encoding="utf-8"
    )


F23_TEMPLATE_FIELDS = {
    "crc_field_width": "16",
    "crc_field_poly": "0x8005",
    "crc_field_init": "0xFFFF",
    "crc_field_xorout": "0x0000",
    "crc_field_check": "0x4B37",
    "crc_field_name": "demo-modbus",
    "crc_field_aliases": "a, b",
}


def test_r_crc_designer_007_2_template_load_recomputes_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The F-23 template (CRC-16/MODBUS parameters, Check ``0x4B37``, Name
    ``demo-modbus``, Aliases ``a, b``) loaded from the first-shown form with
    Reflection in and out switched off first (E5 corrective C-4: the
    first-shown CRC-32/ISO-HDLC already has both on, so the start form must
    differ from the template in every asserted field), quiet time 0.6 s: 1.5 s
    after Load exactly one recompute, every algorithm field, Name and Aliases
    hold the template's values (Reflection in/out on again), and the status
    reads ``Loaded template from file.``. 3 of 3.

    Why: a load sets up to eleven widgets and each changed one used to post its
    own recompute (about 2 min with the 10 MB image). Negative control: the
    per-field change events of the fill left on -> 2 recomputes on head (N-3;
    about 11 on base) -> RED."""
    _set_quiet(monkeypatch, 0.6)
    template = tmp_path / "demo-modbus.crc.json"
    _f23_template(template)

    async def scenario():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause()
            for switch_id in ("#crc_field_refin", "#crc_field_refout"):
                before = designer_recomputes()
                app.query_one(switch_id, Switch).value = False
                await wait_designer_recompute(pilot, app, before)
            start = (
                {fid: app.query_one(f"#{fid}", Input).value for fid in F23_TEMPLATE_FIELDS},
                app.query_one("#crc_field_refin", Switch).value,
                app.query_one("#crc_field_refout", Switch).value,
            )
            before = designer_recomputes()
            app.query_one("#crc_load_path", Input).value = str(template)
            await wait_designer_recompute(pilot, app, before)
            before = designer_recomputes()
            app.query_one("#crc_load_btn", Button).press()
            await pilot.pause(1.5)
            fields = {
                fid: app.query_one(f"#{fid}", Input).value for fid in F23_TEMPLATE_FIELDS
            }
            reflects = (
                app.query_one("#crc_field_refin", Switch).value,
                app.query_one("#crc_field_refout", Switch).value,
            )
            status = str(app.query_one("#crc_loadsave_status", Static).content)
            return designer_recomputes() - before, fields, reflects, status, start

    for delta, fields, reflects, status, start in _run(scenario):
        start_fields, start_refin, start_refout = start
        assert (start_refin, start_refout) == (False, False)
        assert all(start_fields[f] != v for f, v in F23_TEMPLATE_FIELDS.items()), start_fields
        assert delta == 1, f"a template load must recompute once, got {delta}"
        assert fields == F23_TEMPLATE_FIELDS, fields
        assert reflects == (True, True)
        assert status == "Loaded template from file.", status


def test_r_crc_designer_007_3_preset_pick_recomputes_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CRC-16/MODBUS picked from the first-shown form, quiet time 0.6 s: 1.5 s
    after the pick exactly one recompute, the verdict reads ``MATCH``, and
    Width, Polynomial and Init hold the preset's ``16``, ``0x8005``, ``0xFFFF``
    (E5 corrective C-4: the first-shown CRC-32/ISO-HDLC also reads ``MATCH``,
    so the fields are what shows the pick was applied). 3 of 3.

    Why: the preset fill is the same function as the template fill and had the
    same defect (about nine recomputes). Negative control: the fill's change
    events left on -> 2 recomputes on head (N-3; about nine on base) -> RED."""
    _set_quiet(monkeypatch, 0.6)
    ids = ("#crc_field_width", "#crc_field_poly", "#crc_field_init")

    async def scenario():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause()
            start = tuple(app.query_one(i, Input).value for i in ids)
            before = designer_recomputes()
            app.query_one("#crc_preset_select", Select).value = "CRC-16/MODBUS"
            await pilot.pause(1.5)
            fields = tuple(app.query_one(i, Input).value for i in ids)
            return designer_recomputes() - before, _verdict(app), start, fields

    for delta, verdict, start, fields in _run(scenario):
        assert start == ("32", "0x04C11DB7", "0xFFFFFFFF"), start
        assert delta == 1, f"a preset pick must recompute once, got {delta}"
        assert "✓ MATCH" in verdict and "MISMATCH" not in verdict, verdict
        assert fields == ("16", "0x8005", "0xFFFF"), fields


# ---------------------------------------------------------------------------
# R-CRC-PREVIEW-002.1 / .5 and R-CRC-PREVIEW-001.1 (F-24) - the coverage follows the image
# ---------------------------------------------------------------------------
def test_r_crc_preview_002_1_image_set_cleared_replaced(tmp_path: Path) -> None:
    """With the CRC Designer displayed (key ``0``): (a) the fixture image set ->
    within 1 s the preview is exactly the three lines and window line 2 is
    ``concat 0x9C5BCBBD   fill 0x2A8A3950``; (b) the image cleared -> within 1 s
    preview and window both read the empty-state note exactly; (c) a second
    image (byte ``0x8000`` = ``0xAA``) -> within 1 s ``concat: 0x<crc32 of its
    16 range bytes>``. 3 of 3.

    Why (F-24): the panel said ``Load an image to preview coverage CRCs over
    real bytes.`` while an image was loaded, and kept stale CRCs after an
    unload. Negative control: the image watcher not registered -> (a) shows the
    empty-state note -> RED."""
    changed = fixture_mem()
    changed[0x8000] = 0xAA
    changed_crc = zlib.crc32(b"\xaa" + bytes(range(1, 8)) + bytes(range(0x10, 0x18)))

    async def scenario():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause()
            app.current_file = loaded(fixture_mem())
            await wait_until(
                pilot,
                lambda: _preview(app) == FIXTURE_PREVIEW,
                lambda: f"preview after the image was set: {_preview(app)!r}",
                timeout=1.0,
                pause_first=True,
            )
            window_set = _window_lines(app)
            app.current_file = None
            await wait_until(
                pilot,
                lambda: _preview(app) == EMPTY_STATE and str(_window(app)) == EMPTY_STATE,
                lambda: f"after the clear: {_preview(app)!r} / {str(_window(app))!r}",
                timeout=1.0,
                pause_first=True,
            )
            app.current_file = loaded(changed)
            await wait_until(
                pilot,
                lambda: _preview(app).split("\n")[1:2] == [f"concat: 0x{changed_crc:08X}"],
                lambda: f"preview after the image was replaced: {_preview(app)!r}",
                timeout=1.0,
                pause_first=True,
            )
            return window_set

    for window_set in _run(scenario):
        assert window_set[1] == (
            f"concat 0x{FIXTURE_CONCAT:08X}   fill 0x{FIXTURE_FILL:08X}"
        ), window_set


def test_r_crc_preview_002_5_stale_coverage_recomputes_once_on_display(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Quiet time 0.05 s; app started, the CRC Designer NOT displayed; the
    fixture image set -> after two pauses: no recompute and none pending; key
    ``0`` -> once the count advances: exactly one recompute and the exact three
    preview lines; then key ``1`` and key ``0`` again with no image change ->
    after 0.3 s no further recompute. 3 of 3.

    Why: a load on another view costs nothing here, and a clean display costs
    nothing either. Negative controls: the watcher scheduling while the panel
    is hidden -> a recompute before key ``0`` -> RED; no recompute on display
    -> the wait times out -> RED; a recompute on every display -> one more on
    the clean re-display -> RED."""
    _set_quiet(monkeypatch, 0.05)

    async def scenario():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            before = designer_recomputes()
            app.current_file = loaded(fixture_mem())
            await pilot.pause()
            await pilot.pause()
            hidden = (designer_recomputes() - before, designer_pending(app))
            await pilot.press("0")
            await wait_designer_recompute(pilot, app, before, timeout=10.0)
            shown = (designer_recomputes() - before, _preview(app))
            await pilot.press("1")
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause(0.3)
            return hidden, shown, designer_recomputes() - before

    for hidden, shown, after_redisplay in _run(scenario):
        assert hidden == (0, None), f"a hidden panel must not recompute: {hidden}"
        assert shown == (1, FIXTURE_PREVIEW), shown
        assert after_redisplay == 1, "a clean display must not recompute"


# ---------------------------------------------------------------------------
# R-CRC-PREVIEW-001.2 .. 001.8 - the results after the shared computation (24 states + hostile)
# ---------------------------------------------------------------------------
def _expected_state(image: str, width: str, join: str, conflict: str) -> dict:
    """The preview text and window lines 2 and 3 (and the lines after) a field
    state must show, built from the canon formats and ``zlib.crc32`` oracles."""
    dirty = image == "dirty"
    refused = dirty and join == "fill" and conflict == "abort"
    warned = dirty and join == "fill" and conflict == "warn"
    if width == "4":
        return {
            "preview": REFUSAL_DIRTY_ABORT
            if refused
            else "Cannot preview: width 4 out of range [8, 64]",
            "line2": "Cannot compute: width 4 out of range [8, 64]",
            "tail": [],
        }
    active = FIXTURE_CONCAT if join == "concat" else FIXTURE_FILL
    if refused:
        preview = REFUSAL_DIRTY_ABORT
        tail = ["store — refused (on_gap_conflict=abort)"]
    else:
        preview = (
            f"Active policy: join={join}\n"
            f"concat: 0x{FIXTURE_CONCAT:08X}\n"
            f"fill:   0x{FIXTURE_FILL:08X}"
        )
        tail = ["store " + active.to_bytes(4, "little").hex(" ").upper()]
        if warned:
            preview += "\n" + GAP_NOTE_WARN
            tail.append(GAP_NOTE_WARN)
    return {
        "preview": preview,
        "line2": f"concat 0x{FIXTURE_CONCAT:08X}   fill 0x{FIXTURE_FILL:08X}",
        "tail": tail,
    }


_MATRIX = [
    (image, width, join, conflict)
    for image in ("fixture", "dirty")
    for width in ("32", "4")
    for join in ("concat", "fill")
    for conflict in ("abort", "warn", "ignore")
]


async def _drive_state(tmp_path: Path, mem, width: str, join: str, conflict: str, ranges: str):
    app = S19TuiApp(base_dir=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("0")
        await pilot.pause()
        before = designer_recomputes()
        app.current_file = loaded(mem)
        app.query_one("#crc_coverage_ranges", Input).value = ranges
        if width != "32":
            app.query_one("#crc_field_width", Input).value = width
        await wait_designer_recompute(pilot, app, before)
        app.query_one("#crc_coverage_join", Select).value = join
        app.query_one("#crc_coverage_on_gap_conflict", Select).value = conflict
        await pilot.pause()
        window = _window(app)
        return (
            _preview(app),
            str(window).split("\n"),
            [str(span.style) for span in window.spans],
            app.query_one("#crc_coverage_window", Static)._render_markup,
        )


@pytest.mark.parametrize(
    "state", _MATRIX + [("fixture", "32", "concat", "abort", "hostile")],
    ids=lambda s: "-".join(
        [s[0], "w" + s[1], s[2], s[3]] + (["hostile-ranges"] if len(s) == 5 else [])
    ),
)
def test_r_crc_preview_001_2_coverage_field_state_matrix(
    tmp_path: Path, state: tuple
) -> None:
    """Preview (R-CRC-PREVIEW-001.2, R-CRC-PREVIEW-001.4, R-CRC-PREVIEW-001.6,
    R-CRC-PREVIEW-001.7, R-CRC-PREVIEW-001.8) and coverage window
    (R-CRC-PREVIEW-001.3, R-CRC-PREVIEW-001.5) over the field-state matrix: image (fixture /
    dirty) x Width (32 / 4) x Join gaps (concat / fill) x On conflict (abort /
    warn / ignore) = 24 states, plus the hostile Ranges state. Width is set
    first (a text edit, then a wait on the recompute), then the two dropdowns.

    Every text equals the expected text built from the canon formats and
    ``zlib.crc32`` oracles. Width 4 shows the non-canon fault lines as the base
    shows them (``Cannot preview:`` / ``Cannot compute:``, line 1 still drawn),
    except a dirty fill under abort, which is refused before any CRC. The
    hostile state (E3 ruling SEC-9) must show the payload verbatim in both
    surfaces, with no span styled ``link``.

    Why: the preview and the window now share one computation; these states pin
    that no text changed. Negative controls: the shared result swapped (concat
    shown as fill) -> RED; the active CRC for the store line taken from the other
    policy -> RED; the diagnostics dropped from the shared result -> RED. Passes
    on the base tree (the texts are unchanged by design)."""
    hostile = len(state) == 5
    image, width, join, conflict = state[:4]
    mem = dirty_mem() if image == "dirty" else fixture_mem()
    preview, lines, styles, markup = asyncio.run(
        _drive_state(
            tmp_path, mem, width, join, conflict,
            HOSTILE_RANGES if hostile else RANGES_NO_SPACE,
        )
    )
    assert markup is False, "the coverage window must render markup=False"
    if hostile:
        assert preview == HOSTILE_TEXT, preview
        assert lines == [HOSTILE_TEXT], lines
        assert not any("link" in style for style in styles), styles
        return
    expected = _expected_state(image, width, join, conflict)
    assert preview == expected["preview"], preview
    assert lines[1] == expected["line2"], lines
    assert lines[2:] == expected["tail"], lines
    assert _glyphs(lines[0]) > 0 and set(lines[0]) <= set(GLYPHS), (
        "line 1 must still draw the coverage glyphs: " + repr(lines[0])
    )


def test_r_crc_preview_001_8_inverted_range_names_the_reason(tmp_path: Path) -> None:
    """Ranges ``0x8008-0x8000`` -> both surfaces start ``Invalid coverage: ``
    (R-CRC-PREVIEW-001.8, 1 of 1), after a wait on the recompute."""

    async def scenario():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause()
            await _load_and_recompute(pilot, app, fixture_mem(), "0x8008-0x8000")
            return _preview(app), str(_window(app))

    preview, window = asyncio.run(scenario())
    assert preview.startswith("Invalid coverage: "), preview
    assert window.startswith("Invalid coverage: "), window


# ---------------------------------------------------------------------------
# R-CRC-PREVIEW-002.2/2 - at most two window reads per recompute
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("image", ["fixture", "dirty"])
@pytest.mark.parametrize("conflict", ["abort", "warn", "ignore"])
def test_r_crc_preview_002_2_one_recompute_reads_the_window_at_most_twice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, image: str, conflict: str
) -> None:
    """Join gaps := fill (a dropdown) over the fixture image and over the dirty
    fixture, with On conflict abort, warn and ignore (6 states): the one
    recompute reads a coverage window from the image at most twice (count of
    ``crc_designer_model.gather_target`` calls; base: 6 in the five states that
    are not refused, 2 in dirty-abort). Partial: the count bounds the cost, not
    the time (the timing arms in ``test_b101_inc13_perf.py`` bound the time).

    Why: the preview and the window each evaluated the coverage again; the
    shared computation reads once for the evaluation and once for the other
    policy. Negative control: the renderers computing their own CRCs again, or
    the shared computation taking all three CRCs -> three or more reads -> RED."""
    calls = _count_gathers(monkeypatch)

    async def scenario():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause()
            mem = dirty_mem() if image == "dirty" else fixture_mem()
            await _load_and_recompute(pilot, app, mem)
            if conflict != "abort":
                app.query_one("#crc_coverage_on_gap_conflict", Select).value = conflict
                await pilot.pause()
            calls[0] = 0
            before = designer_recomputes()
            app.query_one("#crc_coverage_join", Select).value = "fill"
            await pilot.pause()
            return designer_recomputes() - before, calls[0]

    recomputes, reads = asyncio.run(scenario())
    assert recomputes == 1, f"one dropdown change is one recompute, got {recomputes}"
    assert reads <= 2, f"a recompute may read the window at most twice, read {reads}"


# ---------------------------------------------------------------------------
# R-CRC-PREVIEW-001.11 - the coverage cap
# ---------------------------------------------------------------------------
def test_r_crc_preview_001_11_coverage_over_the_cap_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """(a) The shipped cap (16777216): Ranges ``0x00000000-0x01000001`` (coverage
    size 16777217) over the fixture image -> preview exactly ``Cannot preview:
    coverage exceeds 16777216 bytes``, window line 1 drawn (48 glyphs), line 2
    exactly that text, no line 3, and 0 ``gather_target`` calls in that
    recompute. (b) cap injected as 23, the first-shown Ranges (coverage size 24,
    concat size 16) -> both surfaces ``Cannot preview: coverage exceeds 23
    bytes``. (c) cap injected as 24 -> the three preview lines. 3 of 3.

    Why: a coverage of up to 4 GiB was materialised on the UI thread, and the
    image watcher would make that reachable on a load. Negative controls: no
    size check -> (a) reads the window (2 or more ``gather_target`` calls) ->
    RED; ``>=`` in place of ``>`` -> (c) refused -> RED; the concat size checked
    in place of the coverage size -> (b) not refused -> RED."""
    calls = _count_gathers(monkeypatch)

    async def over_shipped_cap():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause()
            calls[0] = 0
            await _load_and_recompute(pilot, app, fixture_mem(), "0x00000000-0x01000001")
            return _preview(app), _window_lines(app), calls[0]

    note = f"Cannot preview: coverage exceeds {SHIPPED_CAP} bytes"
    for preview, lines, reads in _run(over_shipped_cap):
        assert preview == note, preview
        assert _glyphs(lines[0]) == 48, lines
        assert lines[1:] == [note], lines
        assert reads == 0, f"a refused coverage reads no window, read {reads}"

    async def under_injected_cap():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause()
            await _load_and_recompute(pilot, app, fixture_mem())
            return _preview(app), _window_lines(app)

    _set_cap(monkeypatch, 23)
    for preview, lines in _run(under_injected_cap):
        assert preview == "Cannot preview: coverage exceeds 23 bytes", preview
        assert lines[1] == "Cannot preview: coverage exceeds 23 bytes", lines
    _set_cap(monkeypatch, 24)
    for preview, lines in _run(under_injected_cap):
        assert preview == FIXTURE_PREVIEW, preview
        assert lines[1] == f"concat 0x{FIXTURE_CONCAT:08X}   fill 0x{FIXTURE_FILL:08X}"


# ---------------------------------------------------------------------------
# R-CRC-PREVIEW-001.12 - out-of-order Ranges draw a bounded line 1
# ---------------------------------------------------------------------------
async def _line1_after(tmp_path: Path, ranges: List[str]) -> List[List[str]]:
    """Window lines after each of ``ranges`` is typed into the fixture image."""
    app = S19TuiApp(base_dir=tmp_path)
    out: List[List[str]] = []
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("0")
        await pilot.pause()
        await _load_and_recompute(pilot, app, fixture_mem())
        for text in ranges:
            before = designer_recomputes()
            app.query_one("#crc_coverage_ranges", Input).value = text
            await wait_designer_recompute(pilot, app, before)
            out.append(_window_lines(app))
    return out


def test_r_crc_preview_001_12_out_of_order_ranges_draw_a_bounded_line(
    tmp_path: Path,
) -> None:
    """(a) The F-23 CRC scene's ranges typed in reverse, ``0x00C00000-0x00C00FFF,
    0x00800000-0x00931FBF`` -> line 1 exactly 15 glyphs (1 + 14) and line 2
    ``concat 0x00000000   fill 0x00000000`` (the fixture holds no byte there:
    ``zlib.crc32(b"")``). (c) Ascending Ranges draw as on base: the first-shown
    Ranges 24 glyphs (8 + 8 + 8), then the F-23 CRC scene's ranges 49 glyphs
    (14 + 34 + 1). 3 of 3.

    Why: the line was scaled by (last range's end - first range's start), which
    for out-of-order Ranges is negative or tiny, so the line grew to one glyph
    per byte (1257406 glyphs here). Negative control: the base scale restored ->
    (a) draws 1257406 glyphs -> RED. The hostile three-range input is the next
    node (it must not run against the base tree)."""
    first_shown = "0x00008000-0x00008008, 0x00008010-0x00008018"
    reverse = "0x00C00000-0x00C00FFF, 0x00800000-0x00931FBF"
    for lines_a, lines_c1, lines_c2 in (
        asyncio.run(_line1_after(tmp_path, [reverse, first_shown, F23_RANGES]))
        for _ in range(REPS)
    ):
        assert _glyphs(lines_a[0]) == 15, _glyphs(lines_a[0])
        assert lines_a[1] == "concat 0x00000000   fill 0x00000000", lines_a
        assert _glyphs(lines_c1[0]) == 24, _glyphs(lines_c1[0])
        assert _glyphs(lines_c2[0]) == 49, _glyphs(lines_c2[0])


def test_r_crc_preview_001_12_hostile_three_range_input_draws_a_bounded_line(
    tmp_path: Path,
) -> None:
    """(b) Ranges ``0x0-0x1, 0xFFFFFFF0-0xFFFFFFFF, 0x10-0x11`` (coverage size
    4294967296) -> line 1 exactly 51 glyphs (1, a gap run of 48 empty glyphs,
    1, 1) and line 2 ``Cannot preview: coverage exceeds 16777216 bytes``.
    3 of 3.

    Why: with the base scale this input builds about 4.29 G glyphs (a
    MemoryError or a hang), so this node is NOT run against the base tree."""
    hostile = "0x0-0x1, 0xFFFFFFF0-0xFFFFFFFF, 0x10-0x11"
    for (lines,) in (
        asyncio.run(_line1_after(tmp_path, [hostile])) for _ in range(REPS)
    ):
        assert _glyphs(lines[0]) == 51, _glyphs(lines[0])
        assert lines[0].count(MICROBAR_EMPTY) == 48, lines[0]
        assert lines[1] == f"Cannot preview: coverage exceeds {SHIPPED_CAP} bytes", lines


# ---------------------------------------------------------------------------
# E5 integrity check (decision D-2, E3 rulings A-1, N-1, N-5)
# ---------------------------------------------------------------------------
_DESIGNER_MODULE = "tests.support.b101_designer"


def _is_snapshot(node: ast.AST) -> bool:
    # E5-CR-4: only the inserted name is stripped, so a snapshot that rebinds a
    # name a later assertion reads stays visible to the check.
    return (
        isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "recomputes_before"
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "designer_recomputes"
        and not node.value.args
    )


def _is_wait(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Await)
        and isinstance(node.value.value, ast.Call)
        and isinstance(node.value.value.func, ast.Name)
        and node.value.value.func.id == "wait_designer_recompute"
    )


class _StripInsertedWaits(ast.NodeTransformer):
    """Remove the two inserted statement shapes from every statement list."""

    def generic_visit(self, node):
        super().generic_visit(node)
        for field in ("body", "orelse", "finalbody"):
            stmts = getattr(node, field, None)
            if isinstance(stmts, list):
                setattr(
                    node, field, [s for s in stmts if not (_is_snapshot(s) or _is_wait(s))]
                )
        return node


def _top_key(node: ast.stmt):
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return ("def", node.name)
    if isinstance(node, ast.ClassDef):
        return ("class", node.name)
    if isinstance(node, ast.Assign):
        return ("assign", tuple(ast.unparse(t) for t in node.targets))
    if isinstance(node, ast.AnnAssign):
        return ("assign", (ast.unparse(node.target),))
    return ("stmt", ast.unparse(node))


def _d2_drift(base_src: str, head_src: str) -> List[str]:
    """Names of base statements (a test, a helper, a module constant, an import)
    that are missing or different at head once the inserted waits and the
    module-level additions of the D-2 decision are removed. A statement that is
    new at head is not a drift."""
    base = ast.parse(base_src)
    head = _StripInsertedWaits().visit(ast.parse(head_src))
    base_has_pytest = any(
        isinstance(s, ast.Import) and any(a.name == "pytest" for a in s.names)
        for s in base.body
    )

    def allowed_addition(stmt: ast.stmt) -> bool:
        if isinstance(stmt, ast.ImportFrom) and stmt.module == _DESIGNER_MODULE:
            return True
        if isinstance(stmt, ast.Import) and not base_has_pytest:
            return [a.name for a in stmt.names] == ["pytest"]
        return ast.unparse(stmt) == (
            "pytestmark = pytest.mark.usefixtures('designer_recompute_counter')"
        )

    head_by_key = {_top_key(s): s for s in head.body if not allowed_addition(s)}
    drift = []
    for stmt in base.body:
        key = _top_key(stmt)
        other = head_by_key.get(key)
        if other is None:
            drift.append(f"missing at head: {key[0]} {key[1]}")
        elif ast.dump(stmt) != ast.dump(other):
            drift.append(f"changed at head: {key[0]} {key[1]}")
    return drift


def _git(*args: str) -> Optional[bytes]:
    try:
        proc = subprocess.run(
            ["git", *args], cwd=REPO_ROOT, capture_output=True, timeout=120
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return proc.stdout if proc.returncode == 0 else None


def _merge_base_with_main() -> Optional[str]:
    for ref in ("main", "origin/main"):
        out = _git("merge-base", "HEAD", ref)
        if out:
            return out.decode().strip()
    return None


def test_inc13_d2_touched_nodes_differ_from_base_only_by_the_waits() -> None:
    """Every statement of ``tests/test_crc_designer_view.py`` at the merge-base
    with main equals its body at head once the inserted ``recomputes_before =
    designer_recomputes()`` / ``await wait_designer_recompute(...)`` statements,
    the module-level fixture import, ``import pytest`` and ``pytestmark`` are
    removed (the whole module is compared, E3 round 2 N-1: a deleted or renamed
    test and a changed module constant are named too). A skip is NOT a pass
    (N-5): without a merge-base the node is reported not-run.

    Why: the existing nodes were edited by the author of the increment's tests,
    and a wait is the only change decision D-2 allows. After the merge the diff
    against the merge-base is empty and this passes trivially."""
    base = _merge_base_with_main()
    if base is None:
        pytest.skip("no merge-base with main in this checkout (not-run)")
    old = _git("show", f"{base}:tests/test_crc_designer_view.py")
    if old is None:
        pytest.skip(f"git history holding {base} is not available (not-run)")
    head = (REPO_ROOT / "tests" / "test_crc_designer_view.py").read_text(encoding="utf-8")
    drift = _d2_drift(old.decode("utf-8"), head)
    assert drift == [], "changes beyond the inserted waits: " + "; ".join(drift)


_D2_BASE = '''
LIMIT = 4


def helper(x):
    return x + LIMIT


async def test_a():
    app = make()
    app.field.value = "1"
    assert helper(app.field.value) == 5
    assert app.other == 2
'''

_D2_HEAD_CLEAN = '''
import pytest
from tests.support.b101_designer import designer_recomputes, wait_designer_recompute

pytestmark = pytest.mark.usefixtures("designer_recompute_counter")

LIMIT = 4


def helper(x):
    return x + LIMIT


async def test_a():
    app = make()
    recomputes_before = designer_recomputes()
    app.field.value = "1"
    await wait_designer_recompute(pilot, app, recomputes_before)
    assert helper(app.field.value) == 5
    assert app.other == 2
'''


def test_inc13_d2_check_names_a_dropped_assertion_a_constant_and_a_deleted_test() -> None:
    """Control for the check above (it must be able to FAIL): the clean head has
    no drift; a head that also drops one assertion names the test; a changed
    module constant is named; a deleted test is named; a new test is not."""
    assert _d2_drift(_D2_BASE, _D2_HEAD_CLEAN) == []
    dropped = _D2_HEAD_CLEAN.replace("    assert app.other == 2\n", "")
    assert _d2_drift(_D2_BASE, dropped) == ["changed at head: def test_a"]
    constant = _D2_HEAD_CLEAN.replace("LIMIT = 4", "LIMIT = 5")
    assert _d2_drift(_D2_BASE, constant) == ["changed at head: assign ('LIMIT',)"]
    deleted = _D2_HEAD_CLEAN.replace("async def test_a", "async def test_b")
    assert _d2_drift(_D2_BASE, deleted) == ["missing at head: def test_a"]
    added = _D2_HEAD_CLEAN + "\n\ndef test_new():\n    assert True\n"
    assert _d2_drift(_D2_BASE, added) == []


def test_inc13_d2_check_names_a_snapshot_bound_to_another_name() -> None:
    """Control for E5-CR-4: only ``recomputes_before = designer_recomputes()``
    is an allowed insertion. A snapshot bound to any other name (here one that
    rebinds a name a later assertion could read) is a drift and is named.

    Why: the check stripped a snapshot under any name, so an inserted
    ``expected = designer_recomputes()`` could change what an assertion reads
    and stay invisible. Negative control: the name test removed from
    ``_is_snapshot`` -> this returns no drift -> RED."""
    other = _D2_HEAD_CLEAN.replace(
        "    recomputes_before = designer_recomputes()\n",
        "    expected = designer_recomputes()\n",
    )
    assert other != _D2_HEAD_CLEAN
    assert _d2_drift(_D2_BASE, other) == ["changed at head: def test_a"]


# ---------------------------------------------------------------------------
# E5 corrective (C-4) - R-CRC-PREVIEW-001.1/1: the exact empty state, both surfaces
# ---------------------------------------------------------------------------
def test_r_crc_preview_001_1_no_image_at_start_exact_note_on_both_surfaces(
    tmp_path: Path,
) -> None:
    """App started with no image, key ``0``: the coverage preview and the
    coverage window's plain text are both exactly ``Load an image to preview
    coverage CRCs over real bytes.`` (1 of 1).

    Why: the two cited base nodes check a substring on one surface each, so a
    note with extra text, or one surface left blank, would pass them. Negative
    control: the window rendering anything else at start -> RED."""

    async def scenario():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("0")
            await wait_until(
                pilot,
                lambda: _preview(app) == EMPTY_STATE,
                lambda: f"preview {_preview(app)!r}",
                pause_first=True,
            )
            return _preview(app), str(_window(app))

    preview, window = asyncio.run(scenario())
    assert preview == EMPTY_STATE
    assert window == EMPTY_STATE


# ---------------------------------------------------------------------------
# E5 corrective (C-7, clause 1) - a recompute updates every result surface once
# ---------------------------------------------------------------------------
SURFACE_IDS = (
    "crc_kat_verdict",
    "crc_custom_vector_result",
    "crc_json_preview",
    "crc_warnings",
    "crc_coverage_preview",
    "crc_coverage_window",
)


def _count_surface_updates(app: S19TuiApp) -> Dict[str, int]:
    """Wrap the ``update`` of each of the six result-surface widgets of S13
    CTX-DESIGNER (one instance each) and count the calls per id."""
    counts = {sid: 0 for sid in SURFACE_IDS}
    for sid in SURFACE_IDS:
        widget = app.query_one(f"#{sid}", Static)
        original = widget.update

        def spy(*args, _sid=sid, _original=original, **kwargs):
            counts[_sid] += 1
            return _original(*args, **kwargs)

        widget.update = spy
    return counts


def test_r_crc_designer_recompute_updates_each_of_the_six_surfaces_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The definition of "recompute" (01-requirements.md Definitions: each of
    the six result-surface widgets is updated once), observed on the widgets:
    with the fixture image and key ``0``, (a) Join gaps concat -> fill (a
    dropdown, at once) -> each of the six widgets updated exactly once; (b) an
    edit burst of XOR out (5 values back to back, quiet time 0.6 s) -> each
    updated exactly once more; (c) the image replaced while displayed -> each
    exactly once more. 1 of 1.

    Why: the other cases count ``_recompute`` calls; this one shows that a
    recompute reaches every surface (verdict, custom vector, JSON, Warnings,
    coverage preview and window) and that no surface is refreshed twice or
    skipped. Negative control: a surface dropped from ``_recompute`` (or the
    coverage rendered twice) -> its count differs from 1 -> RED."""
    _set_quiet(monkeypatch, 0.6)

    async def scenario():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause()
            before = designer_recomputes()
            app.current_file = loaded(fixture_mem())
            await wait_designer_recompute(pilot, app, before)
            counts = _count_surface_updates(app)
            steps = []
            before = designer_recomputes()
            app.query_one("#crc_coverage_join", Select).value = "fill"
            await wait_designer_recompute(pilot, app, before)
            await pilot.pause(0.3)
            steps.append((dict(counts), designer_recomputes() - before))
            before = designer_recomputes()
            for value in ("0x1", "0x2", "0x3", "0x4", "0x00000000"):
                app.query_one("#crc_field_xorout", Input).value = value
            await wait_designer_recompute(pilot, app, before)
            await pilot.pause(0.8)
            steps.append((dict(counts), designer_recomputes() - before))
            before = designer_recomputes()
            replaced = fixture_mem()
            replaced[0x8000] = 0xAA
            app.current_file = loaded(replaced)
            await wait_designer_recompute(pilot, app, before)
            await pilot.pause(0.8)
            steps.append((dict(counts), designer_recomputes() - before))
            return steps

    steps = asyncio.run(scenario())
    for n, (counts, recomputes) in enumerate(steps, start=1):
        assert recomputes == 1, (n, recomputes)
        assert counts == {sid: n for sid in SURFACE_IDS}, (n, counts)


# ---------------------------------------------------------------------------
# E5 corrective (C-8, E5-CR-3) - a CRC fault after a clean evaluation is named
# ---------------------------------------------------------------------------
def test_r_crc_preview_coverage_crc_error_after_a_clean_evaluation_is_named(
    tmp_path: Path,
) -> None:
    """A shared run whose evaluation is clean (not refused) but whose other
    policy's CRC faulted (``crc_error`` set, both CRCs ``None``): the preview
    reads exactly ``Cannot preview: <reason>`` and the window's line 2 exactly
    ``Cannot compute: <reason>``. The run is built directly: no reachable form
    produces it today (the only ``ValueError`` on that path is the width check,
    which the evaluation raises first), so this pins the renderers' branch
    order, as E5-CR-3 asks.

    Why: without the branch the preview formatted ``None`` as a CRC and raised
    ``TypeError`` inside the recompute. Negative control: the ``crc_error``
    branch removed from ``_coverage_preview_text`` -> ``TypeError`` -> RED."""

    async def scenario():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause()
            panel = app.query_one(crc_designer_view.CrcDesignerPanel)
            run = crc_designer_view._CoverageRun(
                target=panel._build_coverage_target(),
                evaluation=crc_designer_model.TargetEvaluation(
                    crc=0x1234, refused=False, conflicts=(), diagnostics=()
                ),
                crc_error="width 99 out of range [8, 64]",
            )
            preview = panel._coverage_preview_text(run)
            window = str(panel._render_coverage_window(run)).split("\n")
            return preview, window

    preview, window = asyncio.run(scenario())
    assert preview == "Cannot preview: width 99 out of range [8, 64]"
    assert window[1:] == ["Cannot compute: width 99 out of range [8, 64]"], window


# ---------------------------------------------------------------------------
# E5 corrective (C-7) - black-box acceptance: keys, dialogs and the shipped
# load / project / unload routes (coverage audit section 5, items 1 to 5)
# ---------------------------------------------------------------------------
def _s19_record(address: int, data: bytes) -> str:
    body = bytes([len(data) + 3]) + address.to_bytes(2, "big") + data
    return "S1" + body.hex().upper() + f"{(~sum(body)) & 0xFF:02X}"


def _write_fixture_s19(path: Path) -> Path:
    """The fixture image as an S19 file (two S1 records, ``0x8000``-``0x8007``
    = ``00``..``07`` and ``0x8010``-``0x8017`` = ``10``..``17``)."""
    lines = [
        "S0030000FC",
        _s19_record(0x8000, bytes(range(8))),
        _s19_record(0x8010, bytes(range(0x10, 0x18))),
        "S9030000FC",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="ascii")
    return path


async def _focus(pilot, app: S19TuiApp, selector: str):
    widget = app.query_one(selector)
    widget.focus()
    await wait_until(pilot, lambda: app.focused is widget, f"{selector} focused", pause_first=True)
    return widget


async def _clear_and_type(pilot, app: S19TuiApp, selector: str, text: str) -> None:
    """Focus a text field, clear it by keys (``end``, then one ``backspace`` per
    character) and type ``text`` key by key."""
    field = await _focus(pilot, app, selector)
    await pilot.press("end")
    await pilot.press(*(["backspace"] * len(field.value)))
    await pilot.press(*text)


async def _pick_by_keys(pilot, app: S19TuiApp, selector: str, moves: List[str], want: str) -> None:
    """Open a dropdown by keys (``enter``), move the highlight, pick (``enter``)."""
    select = await _focus(pilot, app, selector)
    await pilot.press("enter")
    for key in moves:
        await pilot.press(key)
    await pilot.press("enter")
    await wait_until(
        pilot,
        lambda: str(select.value) == want,
        lambda: f"{selector} reads {select.value!r}, not {want!r}",
        pause_first=True,
    )


def test_r_crc_designer_at_typing_burst_by_keys_recomputes_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Black-box (audit AT 1; R-CRC-DESIGNER-007.1 / 001.2.2): key ``0``, XOR
    out focused, cleared by ``end`` and ten ``backspace`` and ``0x0`` typed key
    by key (13 edits back to back; quiet time 2 s so the burst is one burst on
    a loaded host) -> none during the keys, then exactly one recompute after
    the quiet time, XOR out reads ``0x0`` and the verdict is ``✗ MISMATCH``.
    1 of 1.

    Why: the other nodes set ``Input.value``; this is the operator's route,
    one ``Input.Changed`` per key. Negative control: no timer (a recompute per
    key) -> 13 -> RED."""
    _set_quiet(monkeypatch, 2.0)

    async def scenario():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause()
            before = designer_recomputes()
            await _clear_and_type(pilot, app, "#crc_field_xorout", "0x0")
            pending_after_keys = designer_pending(app) is not None
            count_after_keys = designer_recomputes() - before
            await wait_designer_recompute(pilot, app, before, timeout=30)
            await pilot.pause(0.5)
            value = app.query_one("#crc_field_xorout", Input).value
            return pending_after_keys, count_after_keys, designer_recomputes() - before, value, _verdict(app)

    pending, early, delta, value, verdict = asyncio.run(scenario())
    assert pending is True and early == 0, (pending, early)
    assert value == "0x0"
    assert delta == 1, f"a typed burst must recompute once, got {delta}"
    assert "✗ MISMATCH" in verdict, verdict


def test_r_crc_designer_at_preset_and_coverage_dropdowns_by_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Black-box (audit ATs 2 and 5; R-CRC-DESIGNER-007.3, -001.2.1): the
    fixture image set, key ``0``; then by keys only (focus, ``enter``, arrows,
    ``enter``): (a) Preset ``CRC-32/ISO-HDLC`` -> ``CRC-16/MODBUS`` (two ``up``)
    -> 1.5 s later exactly one recompute, Width ``16``, Polynomial ``0x8005``,
    Init ``0xFFFF``, verdict ``✓ MATCH``; (b) the image is the dirty fixture:
    On conflict ``abort`` -> ``warn`` (one ``down``) -> one recompute at once,
    the preview keeps three lines (``Active policy: join=concat``, no gap
    note under concat); (c) Join gaps ``concat`` -> ``fill`` (one ``down``) ->
    one recompute at once, preview line 1 ``Active policy: join=fill`` and line
    4 exactly the warn diagnostic. Quiet time 10 s, so a recompute seen here is
    the at-once one. 1 of 1.

    Why: the other nodes set ``Select.value``; the dropdown overlay is the
    operator's route. Negative control: the select handlers routed to the timer
    -> no recompute within the waits -> RED."""
    _set_quiet(monkeypatch, 10.0)

    async def scenario():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause()
            await _load_and_recompute(pilot, app, dirty_mem(), ranges=None)
            out = {}
            before = designer_recomputes()
            await _pick_by_keys(pilot, app, "#crc_preset_select", ["up", "up"], "CRC-16/MODBUS")
            await pilot.pause(1.5)
            out["preset"] = (
                designer_recomputes() - before,
                tuple(
                    app.query_one(i, Input).value
                    for i in ("#crc_field_width", "#crc_field_poly", "#crc_field_init")
                ),
                _verdict(app),
            )
            before = designer_recomputes()
            await _pick_by_keys(pilot, app, "#crc_coverage_on_gap_conflict", ["down"], "warn")
            await wait_until(
                pilot, lambda: designer_recomputes() > before, "no at-once recompute", pause_first=True
            )
            await pilot.pause(0.3)
            out["conflict"] = (designer_recomputes() - before, _preview(app).split("\n"))
            before = designer_recomputes()
            await _pick_by_keys(pilot, app, "#crc_coverage_join", ["down"], "fill")
            await wait_until(
                pilot, lambda: designer_recomputes() > before, "no at-once recompute", pause_first=True
            )
            await pilot.pause(0.3)
            out["join"] = (designer_recomputes() - before, _preview(app).split("\n"))
            return out

    out = asyncio.run(scenario())
    delta, fields, verdict = out["preset"]
    assert delta == 1, delta
    assert fields == ("16", "0x8005", "0xFFFF"), fields
    assert "✓ MATCH" in verdict and "MISMATCH" not in verdict, verdict
    delta, lines = out["conflict"]
    assert delta == 1, delta
    assert len(lines) == 3 and lines[0] == "Active policy: join=concat", lines
    delta, lines = out["join"]
    assert delta == 1, delta
    assert lines[0] == "Active policy: join=fill", lines
    assert lines[3:] == [GAP_NOTE_WARN], lines


def test_r_crc_designer_at_template_load_by_keys_recomputes_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Black-box (audit AT 3; R-CRC-DESIGNER-007.2): key ``0``, the Load path
    typed key by key (one burst), its recompute waited, then the Load button
    pressed by keys (focus, ``enter``) -> 1.5 s later exactly one recompute,
    every template field filled and the status ``Loaded template from file.``.
    Quiet time 0.6 s. 1 of 1.

    Why: the operator types the path and presses the button; a typed path is a
    burst of text edits and the load must still recompute once. Negative
    control: the fill's change events left on -> 2 -> RED."""
    _set_quiet(monkeypatch, 0.6)
    template = tmp_path / "t.crc.json"
    _f23_template(template)

    async def scenario():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause()
            before = designer_recomputes()
            await _clear_and_type(pilot, app, "#crc_load_path", str(template))
            await wait_designer_recompute(pilot, app, before, timeout=30)
            typed = app.query_one("#crc_load_path", Input).value
            before = designer_recomputes()
            await _focus(pilot, app, "#crc_load_btn")
            await pilot.press("enter")
            await pilot.pause(1.5)
            fields = {
                fid: app.query_one(f"#{fid}", Input).value for fid in F23_TEMPLATE_FIELDS
            }
            status = str(app.query_one("#crc_loadsave_status", Static).content)
            return typed, designer_recomputes() - before, fields, status

    typed, delta, fields, status = asyncio.run(scenario())
    assert typed == str(template)
    assert delta == 1, f"a template load must recompute once, got {delta}"
    assert fields == F23_TEMPLATE_FIELDS, fields
    assert status == "Loaded template from file.", status


def test_r_crc_preview_at_image_load_and_unload_through_the_shipped_routes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Black-box (audit AT 4, file and unload halves; R-CRC-PREVIEW-002.1,
    -002.5, -001.1/2): the fixture image written as an S19 file. (a) Designer
    hidden (key ``1``): the file loaded through the Load dialog (``l``, the path
    typed, ``#load_ok``) -> no recompute and nothing pending; key ``0`` -> one
    recompute, preview exactly the three fixture lines. (b) Designer displayed:
    ``U`` (Unload all) -> one recompute, preview and window exactly the
    empty-state note. (c) Designer displayed: the file loaded again through the
    dialog opened with ``ctrl+l`` -> one recompute, the three lines. Quiet time
    0.6 s. 1 of 1.

    Why: the other nodes assign ``app.current_file``; these are the routes that
    assign it (a load, an unload) as the operator runs them. Negative control:
    the image watcher not registered -> (c) keeps the empty-state note -> RED."""
    from tests.support import b100_load_dialog as ld
    from tests.support.b100_workers import settle_workers

    _set_quiet(monkeypatch, 0.6)
    image = _write_fixture_s19(tmp_path / "fixture.s19")

    async def scenario():
        app = S19TuiApp(base_dir=tmp_path / "home")
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause()
            await pilot.press("1")
            await pilot.pause()
            out = {}
            before = designer_recomputes()
            await ld.load_path_through_dialog(
                pilot, app, image, until=lambda: app.current_file is not None
                and app.current_file.path.name == "fixture.s19", what="the hidden load",
            )
            await settle_workers(pilot)
            await pilot.pause(0.8)
            out["hidden"] = (designer_recomputes() - before, designer_pending(app))
            await pilot.press("0")
            await wait_designer_recompute(pilot, app, before)
            await pilot.pause(0.8)
            out["shown"] = (designer_recomputes() - before, _preview(app))
            await _focus(pilot, app, "#crc_designer_panel")
            before = designer_recomputes()
            await pilot.press("U")
            await wait_until(pilot, lambda: app.current_file is None, "Unload all", pause_first=True)
            await wait_designer_recompute(pilot, app, before)
            await pilot.pause(0.8)
            out["unload"] = (designer_recomputes() - before, _preview(app), str(_window(app)))
            await _focus(pilot, app, "#crc_designer_panel")
            before = designer_recomputes()
            await ld.load_path_through_dialog(
                pilot, app, image, open_key="ctrl+l", until=lambda: app.current_file is not None,
                what="the displayed load",
            )
            await settle_workers(pilot)
            await wait_designer_recompute(pilot, app, before)
            await pilot.pause(0.8)
            out["displayed"] = (designer_recomputes() - before, _preview(app), app._active_screen_key)
            return out

    out = asyncio.run(scenario())
    assert out["hidden"] == (0, None), out["hidden"]
    assert out["shown"] == (1, FIXTURE_PREVIEW), out["shown"]
    assert out["unload"] == (1, EMPTY_STATE, EMPTY_STATE), out["unload"]
    assert out["displayed"] == (1, FIXTURE_PREVIEW, "crc_designer"), out["displayed"]


def test_r_crc_preview_at_project_load_through_the_dialog_recomputes_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Black-box (audit AT 4, project half; R-CRC-PREVIEW-002.1, the 001.2.2/2
    rationale "a project load that sets the image twice recomputes once"): a
    project ``P`` holding case_01's ``firmware.s19`` saved through the shipped
    Save handler; a fresh app, key ``0``, Ranges typed ``0x80000000-0x80000010``
    (bytes the image holds; no gap) and its recompute waited; then ``p``, row
    ``P``, ``#load_ok``, the Load-result panel closed with ``esc`` -> exactly
    one recompute after the load, preview exactly ``Active policy:
    join=concat`` / ``concat: 0x<c>`` / ``fill:   0x<c>`` with ``<c>`` the
    ``zlib.crc32`` of the image's 16 bytes at ``0x80000000``. Quiet time 0.6 s.
    1 of 1.

    Why: the project load resets the image to ``None`` and then installs the
    new one; both are image changes and must cost one recompute. Negative
    control: the watcher recomputing at once on every change -> 2 -> RED."""
    from s19_app.core import S19File
    from tests.support import b100_load_dialog as ld
    from tests.support import b100_projects as projects
    from tests.support.b100_workers import settle_workers

    _set_quiet(monkeypatch, 0.6)
    base = tmp_path / "home"
    project_dir = projects.save_case01_project(base, "P", files=("firmware.s19",))
    mem = S19File(str(project_dir / "firmware.s19")).get_memory_map()
    window_bytes = bytes(mem[0x80000000 + i] for i in range(16))
    crc = zlib.crc32(window_bytes)
    want = f"Active policy: join=concat\nconcat: 0x{crc:08X}\nfill:   0x{crc:08X}"

    async def scenario():
        app = S19TuiApp(base_dir=base)
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            await pilot.press("0")
            await pilot.pause()
            before = designer_recomputes()
            app.query_one("#crc_coverage_ranges", Input).value = "0x80000000-0x80000010"
            await wait_designer_recompute(pilot, app, before)
            await _focus(pilot, app, "#crc_designer_panel")
            before = designer_recomputes()
            await ld.open_project_through_dialog(pilot, app, "P")
            await projects.dismiss_load_result_panel(pilot, app)
            await settle_workers(pilot)
            await wait_designer_recompute(pilot, app, before)
            await pilot.pause(0.8)
            return designer_recomputes() - before, _preview(app), app.current_project

    delta, preview, project = asyncio.run(scenario())
    assert project == "P"
    assert delta == 1, f"a project load must recompute once, got {delta}"
    assert preview == want, preview
