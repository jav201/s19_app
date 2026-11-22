"""P-279 I1f, group G-NAV: start and resize styling (R-TUI-023.8 .. .13).

The start puts the width layout and the comfortable density on the workspace
containers at compose time, so neither the first resize nor the mount handler
restyles the workspace. A later regime change makes one restyle. The layout a
user sees is the same whether the app started at a size or was resized to it.

A "workspace restyle" is one ``App.update_styles(node)`` call whose node is
``#workspace_shell``, ``#workspace_body`` or an ancestor of them (interfaces.md
I-2). "For the width layout" = made while ``_apply_width_regime`` runs; "for the
density" = made while ``on_mount`` runs. Both are counted by wrapping, not timed.

R-TUI-023.14 (startup timing) is a host arm and has no test here.
"""
from __future__ import annotations

import asyncio
import functools
import hashlib
import json

import pytest
from textual.geometry import Size

from s19_app.tui.app import S19TuiApp

SIZES = [(80, 24), (118, 54), (220, 54)]
START_FROM = (160, 40)
ROUNDS = 6


class Probe:
    """What one app run recorded (filled by the wrappers below)."""

    def __init__(self) -> None:
        self.phase = None  # "width" while _apply_width_regime runs, "mount" in on_mount
        self.composing = False
        self.compose_size = None
        self.resize_widths = []
        self.styles = []  # (phase, node)
        self.regime_calls = 0
        self.pre_regime = None  # (shell classes, body classes) at the first regime call
        self.mount_calls = 0


def _install_class_probes(monkeypatch, probe, compose_width):
    """Wrap compose, on_mount, on_resize (and fake the compose-time width)."""
    real_size = S19TuiApp.size

    def size_get(self):
        real = real_size.fget(self)
        if probe.composing and compose_width is not None:
            return Size(compose_width, real.height)
        return real

    monkeypatch.setattr(S19TuiApp, "size", property(size_get))
    real_compose = S19TuiApp.compose
    real_mount = S19TuiApp.on_mount
    real_resize = S19TuiApp.on_resize

    @functools.wraps(real_compose)
    def compose(self):
        probe.composing = True
        probe.compose_size = tuple(real_size.fget(self))
        try:
            yield from real_compose(self)
        finally:
            probe.composing = False

    @functools.wraps(real_mount)
    def on_mount(self):
        probe.phase, probe.mount_calls = "mount", probe.mount_calls + 1
        try:
            return real_mount(self)
        finally:
            probe.phase = None

    @functools.wraps(real_resize)
    def on_resize(self, event):
        probe.resize_widths.append(event.size.width)
        return real_resize(self, event)

    monkeypatch.setattr(S19TuiApp, "compose", compose)
    monkeypatch.setattr(S19TuiApp, "on_mount", on_mount)
    monkeypatch.setattr(S19TuiApp, "on_resize", on_resize)


def _install_instance_probes(app, probe):
    real_update = app.update_styles
    real_regime = app._apply_width_regime

    def update_styles(node, *args, **kwargs):
        probe.styles.append((probe.phase, node))
        return real_update(node, *args, **kwargs)

    def regime(width):
        probe.regime_calls += 1
        if probe.pre_regime is None:
            probe.pre_regime = (_classes(app, "#workspace_shell"), _classes(app, "#workspace_body"))
        probe.phase = "width"
        try:
            return real_regime(width)
        finally:
            probe.phase = None

    app.update_styles = update_styles
    app._apply_width_regime = regime


def _classes(app, selector):
    return set(app.query_one(selector).classes)


async def _settle(pilot):
    for _ in range(ROUNDS):
        await pilot.pause()


def _drive(monkeypatch, tmp_path, size, scenario, compose_width=None):
    probe = Probe()

    async def go():
        app = S19TuiApp(base_dir=tmp_path)
        _install_instance_probes(app, probe)
        async with app.run_test(size=size) as pilot:
            await _settle(pilot)
            return await scenario(app, pilot, probe)

    with monkeypatch.context() as mp:  # wrappers live for this one run only
        _install_class_probes(mp, probe, compose_width)
        return asyncio.run(go())


def _workspace_restyles(app, probe, phase):
    """Count update_styles calls of ``phase`` aimed at the shell, the body or an ancestor."""
    shell = app.query_one("#workspace_shell")
    body = app.query_one("#workspace_body")
    targets = {id(n) for n in (shell, body, *shell.ancestors)}
    return sum(1 for ph, node in probe.styles if ph == phase and id(node) in targets)


def _snapshot(app):
    """Painted screen text and the region of every widget with an id."""
    strips = app.screen._compositor.render_strips()
    text = "\n".join("".join(seg.text for seg in strip) for strip in strips)
    regions = sorted((str(w.id), tuple(w.region)) for w in app.screen.query("*") if w.id)
    return {"text": text, "regions": regions}


async def _all_screens(app, pilot):
    """Snapshot each of the 13 rail screens (12 rail keys plus Split / Join / Export)."""
    out = {}
    for key in list(app.SCREEN_CONTAINER_IDS) + ["split_join"]:
        if key == "split_join":
            app.action_open_split_join_export()
        else:
            app.action_show_screen(key)
        await _settle(pilot)
        out[key] = _snapshot(app)
    return out


def _digest(shots):
    return hashlib.sha256(json.dumps(shots, sort_keys=True).encode()).hexdigest()[:16]


def _diff(a, b):
    """Short description of where two screen snapshots differ ('' when equal)."""
    bad = []
    for key in a:
        if a[key] == b[key]:
            continue
        why = "text" if a[key]["text"] != b[key]["text"] else "regions"
        if why == "regions":
            ra, rb = dict(a[key]["regions"]), dict(b[key]["regions"])
            moved = [i for i in ra if rb.get(i) != ra[i]][:3]
            why += f" {[(i, ra[i], rb.get(i)) for i in moved]}"
        bad.append(f"{key}: {why}")
    return "; ".join(bad)


def _reference(monkeypatch, tmp_path, size, compose_width=None):
    async def scen(app, pilot, probe):
        return await _all_screens(app, pilot)

    return _drive(monkeypatch, tmp_path, size, scen, compose_width)


def _ws_left_width(app):
    """The left pane's applied width rule: (value, is_cells). Its region is 0 while
    no file is loaded, so the rule itself is read: it is what a restyle must update."""
    scalar = app.query_one("#ws_left").styles.width
    return (scalar.value, scalar.unit.name == "CELLS")


# --------------------------------------------------------------------------- #
# Q-1 probe (K-1): App.size inside compose is the start size
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("size", SIZES, ids=lambda s: f"{s[0]}x{s[1]}")
def test_q1_compose_reads_start_size_headless(monkeypatch, tmp_path, size):
    """Q-1/K-1: under run_test(size=...) the size read inside compose equals the
    start size, and the first Resize carries the same width."""

    async def scen(app, pilot, probe):
        return probe.compose_size, list(probe.resize_widths)

    compose_size, widths = _drive(monkeypatch, tmp_path, size, scen)
    assert compose_size == size, f"compose saw {compose_size}, start was {size}"
    assert widths, "no Resize event reached on_resize"
    assert widths[0] == size[0], f"first Resize width {widths[0]} != start {size[0]}"


# --------------------------------------------------------------------------- #
# R-TUI-023.8 / .11: start classes, zero restyles from construction to idle
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("size", SIZES, ids=lambda s: f"{s[0]}x{s[1]}")
def test_r_tui_023_8_start_layout_without_width_restyle(monkeypatch, tmp_path, size):
    """R-TUI-023.8: shell and body carry width-narrow iff start width < 120 at the
    first idle frame, and the first Resize (a real regime call) restyles nothing."""

    async def scen(app, pilot, probe):
        return (
            _classes(app, "#workspace_shell"),
            _classes(app, "#workspace_body"),
            probe.regime_calls,
            _workspace_restyles(app, probe, "width"),
        )

    shell, body, calls, restyles = _drive(monkeypatch, tmp_path, size, scen)
    narrow = {"width-narrow"} if size[0] < 120 else set()
    assert shell == narrow
    assert body == narrow | {"density-comfortable"}
    assert calls >= 1, "the first Resize never reached _apply_width_regime (vacuous)"
    assert restyles == 0, f"{restyles} width-layout workspace restyles from construction to idle"


@pytest.mark.parametrize("size", SIZES, ids=lambda s: f"{s[0]}x{s[1]}")
def test_r_tui_023_11_start_density_without_restyle(monkeypatch, tmp_path, size):
    """R-TUI-023.11: density-comfortable is on the body at first idle and the mount
    handler makes no workspace restyle."""

    async def scen(app, pilot, probe):
        return (
            "density-comfortable" in _classes(app, "#workspace_body"),
            probe.mount_calls,
            _workspace_restyles(app, probe, "mount"),
        )

    has, mounts, restyles = _drive(monkeypatch, tmp_path, size, scen)
    assert has
    assert mounts == 1, "on_mount probe did not run exactly once (vacuous)"
    assert restyles == 0, f"{restyles} density workspace restyles while on_mount ran"


# --------------------------------------------------------------------------- #
# R-TUI-023.9 / .10: resize across and within the 120 boundary
# --------------------------------------------------------------------------- #

CROSS = [((118, 54), (160, 54)), ((160, 40), (118, 40)), ((220, 54), (80, 24))]


@pytest.mark.parametrize("start,end", CROSS, ids=lambda s: f"{s[0]}x{s[1]}")
def test_r_tui_023_9_crossing_resize_makes_one_restyle(monkeypatch, tmp_path, start, end):
    """R-TUI-023.9: a resize across 120 makes exactly 1 width-layout restyle and both
    containers show the new layout (pane widths of R-TUI-029.1/.2, rail of R-TUI-021.9)."""
    async def scen(app, pilot, probe):
        probe.styles.clear()
        before = probe.regime_calls
        await pilot.resize_terminal(*end)
        await _settle(pilot)
        return (
            probe.regime_calls - before,
            _workspace_restyles(app, probe, "width"),
            _classes(app, "#workspace_shell"),
            _classes(app, "#workspace_body"),
            _ws_left_width(app),
            app.query_one("#rail_slot").region.width,
        )

    calls, restyles, shell, body, left, rail = _drive(monkeypatch, tmp_path, start, scen)
    narrow = {"width-narrow"} if end[0] < 120 else set()
    assert calls >= 1, "resize never reached _apply_width_regime (vacuous)"
    assert restyles == 1, f"{restyles} width-layout restyles"
    assert shell == narrow and body == narrow | {"density-comfortable"}
    assert left == ((24.0, False) if end[0] < 120 else (22.0, True)), left  # R-TUI-029.2 (24 %) / .1 (22 cells)
    if end == (80, 24):
        assert rail == 4  # R-TUI-021.9


NO_CROSS = [((118, 54), [(100, 54), (119, 54)]), ((160, 54), [(220, 54), (120, 54)])]


@pytest.mark.parametrize("start,steps", NO_CROSS, ids=["118-100-119", "160-220-120"])
def test_r_tui_023_10_non_crossing_resize_makes_no_restyle(monkeypatch, tmp_path, start, steps):
    """R-TUI-023.10: resizes that stay on one side of 120 make 0 width-layout restyles."""

    async def scen(app, pilot, probe):
        out = []
        for step in steps:
            probe.styles.clear()
            before = probe.regime_calls
            await pilot.resize_terminal(*step)
            await _settle(pilot)
            out.append((probe.regime_calls - before, _workspace_restyles(app, probe, "width")))
        return out

    for calls, restyles in _drive(monkeypatch, tmp_path, start, scen):
        assert calls >= 1, "resize never reached _apply_width_regime (vacuous)"
        assert restyles == 0


# --------------------------------------------------------------------------- #
# R-TUI-023.12: start at a size == resize to that size, 13 screens
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("size", SIZES, ids=lambda s: f"{s[0]}x{s[1]}")
def test_r_tui_023_12_started_layout_equals_resized_layout(monkeypatch, tmp_path, size):
    """R-TUI-023.12: for each of 13 screens the painted text and every id'd widget
    region are equal between a start at the size and a start at 160x40 resized to it.
    The digest of the started-at snapshots is printed to compare against base."""
    started = _reference(monkeypatch, tmp_path, size)

    async def scen(app, pilot, probe):
        await pilot.resize_terminal(*size)
        await _settle(pilot)
        return await _all_screens(app, pilot)

    resized = _drive(monkeypatch, tmp_path, START_FROM, scen)
    print(f"STARTED_DIGEST {size[0]}x{size[1]} {_digest(started)}")
    assert len(started) == 13 and set(started) == set(resized)
    assert _diff(started, resized) == ""


# --------------------------------------------------------------------------- #
# R-TUI-023.13: compose width on the other side of 120 than the first Resize
# --------------------------------------------------------------------------- #

MISMATCH = [(0, (220, 54)), (220, (118, 54))]


@pytest.mark.parametrize("compose_width,size", MISMATCH, ids=["compose0-resize220", "compose220-resize118"])
def test_r_tui_023_13_compose_width_disagrees_with_first_resize(
    monkeypatch, tmp_path, compose_width, size
):
    """R-TUI-023.13: composed on one side of 120, first Resize on the other: the
    classes composed from the compose width, then exactly 1 width-layout restyle,
    and the layout equals a plain start at the Resize size (13 screens)."""

    async def scen(app, pilot, probe):
        shots = await _all_screens(app, pilot)
        return probe.pre_regime, probe.resize_widths[0], _first_regime_restyles(app, probe), shots

    pre, first_w, restyles, shots = _drive(monkeypatch, tmp_path, size, scen, compose_width)
    assert first_w == size[0]
    composed_narrow = compose_width < 120
    assert ("width-narrow" in pre[0]) == composed_narrow, f"shell classes at first regime call: {pre[0]}"
    assert ("width-narrow" in pre[1]) == composed_narrow, f"body classes at first regime call: {pre[1]}"
    assert restyles == 1, f"{restyles} width-layout restyles"
    started = _reference(monkeypatch, tmp_path, size)
    assert _diff(started, shots) == ""


def _first_regime_restyles(app, probe):
    return _workspace_restyles(app, probe, "width")
