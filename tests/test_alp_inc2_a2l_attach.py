"""Batch 2026-11-18-a2l-load-performance Inc 2 E4 — responsive direct A2L attach.

Independent tester lane G-T-I2. Every oracle below comes from the Inc 2
ledger ``.dev-flow/2026-11-18-a2l-load-performance/inc-2/02-test-cases.md``,
the requirements ``01-requirements.md`` (R-A2L-REFRESH.029..038), the frozen
interfaces ``../../interfaces.md`` (I-ALP-2.1..2.4) and the E1 slice/graph —
never from an implementation.

Product-route rule: every acceptance arm instantiates the shipping
``S19TuiApp`` and drives the typed-path, Workarea Files or start-up route
through Textual ``run_test()``/Pilot, and reads visible widget content at
the outcome. No arm substitutes a direct call to ``_install_attached_a2l``,
``_replace_current_a2l`` or a renderer for an acceptance route.

RED contract: every new seam name is accessed lazily inside the test body
(``importlib`` + ``getattr`` defaults), so each node fails RED on the base
revision 7402840c with a behavioural assertion, never a collection error.
The expensive arms (the real ``case_06`` attach and the 1,000,000-byte
image arms) open with a fast seam guard so the base RED never runs their
full route. No assertion is raised inside a UI callback (Textual swallows
callback exceptions): callbacks record, the test asserts afterwards.
"""

from __future__ import annotations

import ast
import asyncio
import copy
import dataclasses
import gc
import hashlib
import importlib
import json
import re
import sys
import threading
import time
from pathlib import Path
from types import MappingProxyType, SimpleNamespace
from typing import Optional

import pytest
from textual.widgets import Button, DataTable, Input, Label, ProgressBar, Static

import s19_app.tui.app as app_module
from s19_app.tui.app import S19TuiApp
from s19_app.tui.changes.io import emit_s19_from_mem_map
from s19_app.tui.screens import ConfirmQuestionScreen
from s19_app.tui.screens_directionb import (
    CheckEditorPanel,
    LoadedArtifactsPanel,
    MemoryMapPanel,
    PatchEditorPanel,
)
from s19_app.tui.segment_split_view import SplitJoinWindow
from s19_app.tui.workspace import WORKAREA_DIRNAME, WORKAREA_SUBDIR, WORKAREA_TEMP
from tests.support.b100_workers import settle_workers
from tests.support.b103_a2l_arrays import BASE_LAYOUTS, characteristic, cm, inline, meas
from tests.support.timing import report_margin, timing_bound, wait_until

ROOT = Path(__file__).resolve().parents[1]
CASE06 = ROOT / "examples" / "case_06_large_nested_a2l" / "firmware.a2l"
SIZE = (118, 54)

#: The spinner glyphs of the existing busy progress line (shell._BUSY_FRAMES):
#: the real format is ``<glyph> Loading <name>  ·  step n/m <label>  ·  mm:ss``
#: and never contains a ``busy:`` token (that is the refusal status line).
_BUSY_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


def _assert_busy_progress(text: str, *, name: str, step: str, step_label: str) -> None:
    """The exact preserved busy progress line for one attach phase."""
    assert text and text[0] in _BUSY_FRAMES, text
    assert re.match(
        rf"^ Loading {re.escape(name)}  ·  {re.escape(step)} {re.escape(step_label)}  ·  \d\d:\d\d$",
        text[1:],
    ), text


def _is_busy_progress(text: str, *, name: str) -> bool:
    return text.startswith(tuple(_BUSY_FRAMES)) and f" Loading {name}  ·  " in text

# ---------------------------------------------------------------------------
# Frozen contract literals (interfaces I-ALP-2.1..2.4; never derived).
# ---------------------------------------------------------------------------

SUPERSEDED_OUTCOME = "Load superseded — current state kept."
FAILURE_OUTCOME = (
    "File NOT loaded: '{name}' could not be read — check that the file can "
    "be opened, then load again."
)

#: The Inc 2 fixture contract (graph "Concrete design fixtures"): OLD has
#: OLD_SCALAR (length 2, u16), ARR12 (declared length 12, u16) and AUX2
#: (length 2, u16); NEW at the same path changes ARR12 to declared length 8,
#: f32, and retains AUX2. No OLD cell is a valid NEW expectation.
IMG1 = {0x1000: 0x10, 0x1001: 0x20, 0x1002: 0x30}
IMG2 = {0x1000: 0x70, 0x1001: 0x80, 0x1002: 0x90}

OLD_ROWS = (
    ("OLD_SCALAR", 0x1000, 2, "u16"),
    ("ARR12", 0x2000, 12, "u16"),
    ("AUX2", 0x4000, 2, "u16"),
)
NEW_ROWS = (
    ("OLD_SCALAR", 0x1000, 2, "u16"),
    ("ARR12", 0x2000, 8, "f32"),
    ("AUX2", 0x4000, 2, "u16"),
)

#: The 1,000,000-byte image: the deterministic conftest generator sized so
#: the emitted S19 file lands within a few bytes of 1,000,000 (21,276
#: records: 4 ranges x 85,104 bytes -> 1,000,010 bytes on disk).
BIG_IMAGE_RANGES = 4
BIG_IMAGE_BYTES_PER_RANGE = 85_104


# ---------------------------------------------------------------------------
# Lazy seam access — every Inc 2 name is resolved inside the test body.
# ---------------------------------------------------------------------------


def _fl_module():
    return importlib.import_module("s19_app.tui.app.file_load")


def _definition_module():
    return importlib.import_module("s19_app.tui.a2l_definition")


def _picker_module():
    return importlib.import_module("s19_app.tui.a2l_parameter_picker")


def _service_module():
    return importlib.import_module("s19_app.tui.services.a2l_service")


def _attach_snapshot_cls():
    return getattr(_fl_module(), "A2LAttachSnapshot", None)


def _picker_snapshot_cls():
    return getattr(_fl_module(), "A2LPickerSnapshot", None)


def _accepted_snapshots(app):
    return getattr(app, "_accepted_a2l_picker_snapshots", None)


def _guard_attach_snapshot_seams():
    """The fast RED guard: the increment's data contracts must exist before
    any arm runs its full route (the base fails here in one step)."""
    assert _attach_snapshot_cls() is not None, (
        "A2LAttachSnapshot is missing — the Inc 2 attach snapshot is not implemented"
    )
    assert _picker_snapshot_cls() is not None, (
        "A2LPickerSnapshot is missing — the Inc 2 picker snapshot is not implemented"
    )


# ---------------------------------------------------------------------------
# Synthetic fixtures (non-palindromic OLD/NEW, IMG1/IMG2, MAC).
# ---------------------------------------------------------------------------


def _write_a2l(path: Path, *blocks: str) -> Path:
    lines = [
        "ASAP2_VERSION 1 71",
        '/begin PROJECT P ""',
        '  /begin MODULE M ""',
        '    /begin MOD_COMMON ""',
        "      BYTE_ORDER LITTLE_ENDIAN",
        "    /end MOD_COMMON",
    ]
    for name, datatype in BASE_LAYOUTS:
        lines += [
            f"    /begin RECORD_LAYOUT {name}",
            f"      FNC_VALUES 1 {datatype} ROW_DIR DIRECT",
            "    /end RECORD_LAYOUT",
        ]
    lines.append(cm("CM_IDENT", "IDENTICAL"))
    lines.extend(blocks)
    lines.extend(["  /end MODULE", "/end PROJECT", ""])
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def _segment_block(name: str, address: int, size: int) -> str:
    """The house MEMORY_SEGMENT block (tests/test_b103_a2l_refresh.py): the
    Split/Join window's A2L tab reads ``extract_memory_segments`` from the
    parsed payload, so the fixture declares one segment per tag."""
    return (
        f'    /begin MEMORY_SEGMENT {name} ""\n'
        f"      DATA FLASH INTERN 0x{address:04X} 0x{size:04X} -1 -1 -1 -1 -1\n"
        "    /end MEMORY_SEGMENT"
    )


def _old_a2l(path: Path) -> Path:
    return _write_a2l(
        path,
        *[_segment_block(name, address, size) for name, address, size, _fmt in OLD_ROWS],
        characteristic("OLD_SCALAR", "VALUE", "0x1000", "RL_U16", "CM_IDENT", "0", "65535"),
        meas("ARR12", "UWORD", addr="0x2000", extras=("MATRIX_DIM 2 3",)),
        characteristic("AUX2", "VALUE", "0x4000", "RL_U16", "CM_IDENT", "0", "65535"),
    )


def _new_a2l(path: Path) -> Path:
    return _write_a2l(
        path,
        *[_segment_block(name, address, size) for name, address, size, _fmt in NEW_ROWS],
        characteristic("OLD_SCALAR", "VALUE", "0x1000", "RL_U16", "CM_IDENT", "0", "65535"),
        meas("ARR12", "FLOAT32_IEEE", addr="0x2000", extras=("MATRIX_DIM 2",)),
        characteristic("AUX2", "VALUE", "0x4000", "RL_U16", "CM_IDENT", "0", "65535"),
    )


def _project_a2l(path: Path) -> Path:
    """A different A2L source (never the attached OLD/NEW object): ARR12
    declared length 6, u16, so a stale 12/u16 definition cannot pass."""
    return _write_a2l(
        path,
        characteristic("OLD_SCALAR", "VALUE", "0x1000", "RL_U16", "CM_IDENT", "0", "65535"),
        meas("ARR12", "UWORD", addr="0x2000", extras=("MATRIX_DIM 1 3",)),
        characteristic("AUX2", "VALUE", "0x4000", "RL_U16", "CM_IDENT", "0", "65535"),
    )


def _big_a2l(path: Path, n: int = 2200) -> Path:
    """A many-definition A2L for the .037 filter/page arm: ``n`` distinct
    ``BIG_`` characteristics (u16, unique addresses) so the 200-row picker
    pages span ``ceil(n / 200)`` pages and every Next press rebuilds."""
    blocks = [
        characteristic(
            f"BIG_{i:04d}", "VALUE", f"0x{0x5000 + i * 8:X}", "RL_U16", "CM_IDENT", "0", "65535"
        )
        for i in range(n)
    ]
    return _write_a2l(path, *blocks)


def _mid_a2l(tmp_path: Path, count: int = 2000) -> Path:
    """A generated mid-size A2L (``count`` disjoint VALUE characteristics)
    written through the batch-103 ``inline`` builder and parsed once, so an
    attach/install route carries ~2,000 objects of describe/refresh work."""
    blocks = [
        characteristic(
            f"MID_{i:04d}", "VALUE", f"0x{0x1000 + i * 0x40 + (i % 7) * 4:X}",
            "RL_U8", "NO_COMPU_METHOD", "0", "255",
        )
        for i in range(count)
    ]
    data = inline(tmp_path, *blocks)
    assert len(data["tags"]) == count and len(data.get("errors") or []) == 0
    return Path(data["path"])


def _write_image(path: Path, mem: dict[int, int]) -> Path:
    path.write_text(emit_s19_from_mem_map(mem, [(min(mem), max(mem) + 1)]), encoding="ascii")
    return path


def _write_mac(path: Path) -> Path:
    lines = ["BROKEN=not-hex"]
    lines += [f"FILL_{i:03d}=0x{i + 0x80:04X}" for i in range(4)]
    lines += ["OLD_SCALAR=0x1000", "ARR12=0x2000", "NO_MATCH=0x0070"]
    path.write_text("\n".join(lines) + "\n", encoding="ascii")
    return path


def _write_big_image(path: Path) -> Path:
    from tests.conftest import make_large_s19

    image = make_large_s19(
        path,
        num_ranges=BIG_IMAGE_RANGES,
        bytes_per_range=BIG_IMAGE_BYTES_PER_RANGE,
    )
    assert abs(image.stat().st_size - 1_000_000) < 100, image.stat().st_size
    return image


def _seed_project(workarea: Path, name: str, *, a2l: Path, image: Optional[Path] = None) -> Path:
    folder = workarea / name
    folder.mkdir(parents=True, exist_ok=True)
    active = None
    if image is not None:
        (folder / image.name).write_bytes(image.read_bytes())
        active = image.stem
    (folder / a2l.name).write_bytes(a2l.read_bytes())
    (folder / "project.json").write_text(
        json.dumps({"schema_version": 1, "active_variant": active}), encoding="utf-8"
    )
    return folder


def _project_digests(folder: Path) -> dict[str, str]:
    return {
        str(path.relative_to(folder)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in folder.rglob("*")
        if path.is_file()
    }


# ---------------------------------------------------------------------------
# App runners and route drivers (the three direct-attach routes).
# ---------------------------------------------------------------------------


def _run(tmp_path: Path, body, *, load_path: Optional[Path] = None, size=SIZE, base_dir=None):
    async def drive():
        app = S19TuiApp(base_dir=base_dir or tmp_path, load_path=load_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            return await body(app, pilot)

    return asyncio.run(drive())


async def _submit_typed(app: S19TuiApp, pilot, value: str) -> None:
    await pilot.press("ctrl+l")
    await wait_until(pilot, lambda: len(app.screen.query("#load_path")) > 0, "Load dialog did not open")
    assert await pilot.click("#load_path")
    await pilot.press("ctrl+a", "delete")
    await pilot.press(*value)
    assert await pilot.click("#load_ok")
    await pilot.pause()


async def _load_image(app: S19TuiApp, pilot, path: Path) -> None:
    await _submit_typed(app, pilot, str(path))
    # The confirmation modal can open a beat after the typed submission
    # under load; poll for it instead of a single isinstance check so the
    # "y" is never missed (E4-INC2-F3, flake hardening).
    try:
        await wait_until(
            pilot,
            lambda: isinstance(app.screen, ConfirmQuestionScreen),
            "image confirm modal",
            timeout=10.0,
        )
        await pilot.press("y")
    except AssertionError:
        pass  # no confirmation modal on this route
    await settle_workers(pilot)
    assert app.current_file is not None and app.current_file.mem_map, list(app.log_lines)


async def _typed_attach(app: S19TuiApp, pilot, path: Path) -> None:
    """Typed route; waits for the attach outcome (generation bump + any
    current name, since a copying route may land on ``name_1.a2l``)."""
    generation = app._a2l_view_generation
    await _submit_typed(app, pilot, str(path))
    if isinstance(app.screen, ConfirmQuestionScreen):
        await pilot.press("y")
    await settle_workers(pilot)
    await wait_until(
        pilot,
        lambda: app.current_a2l_path is not None and app._a2l_view_generation > generation,
        f"the typed attach of {path.name}",
    )


async def _workarea_attach(app: S19TuiApp, pilot, name: str) -> None:
    generation = app._a2l_view_generation
    app._load_workarea_file(name)
    await settle_workers(pilot)
    await wait_until(
        pilot,
        lambda: app.current_a2l_path is not None
        and Path(app.current_a2l_path).name == name
        and app._a2l_view_generation > generation,
        f"the Workarea Files attach of {name}",
    )


async def _load_project(app: S19TuiApp, pilot, name: str) -> None:
    from tests.support import b100_load_dialog as ld

    await pilot.press("p")
    await wait_until(pilot, lambda: len(app.screen.query("#load_path")) > 0, "Load dialog did not open")
    await ld.highlight_row(pilot, app, name)
    await pilot.press("enter")
    await wait_until(pilot, lambda: not ld.is_load_dialog(app.screen), "the Load dialog to close")
    if isinstance(app.screen, ConfirmQuestionScreen):
        await pilot.press("y")
    await settle_workers(pilot)
    assert app.current_project == name, list(app.log_lines)
    if len(app.screen.query("#result_ok")) > 0:
        await pilot.press("escape")
        await wait_until(pilot, lambda: len(app.screen.query("#result_ok")) == 0, "Load result did not close")


def _mount_views(app: S19TuiApp) -> None:
    app.action_show_screen("check_editor")
    app.action_show_screen("patch")
    app.action_show_screen("map")
    app.action_open_split_join_export()
    app.action_show_screen("a2l")


def _plain(value) -> str:
    return value.plain if hasattr(value, "plain") else str(value)


def _picker_of(panel):
    return panel._picker if isinstance(panel, CheckEditorPanel) else panel._a2l_picker


def _check_panel(app: S19TuiApp) -> CheckEditorPanel:
    return app.query_one("#check_editor_panel", CheckEditorPanel)


def _patch_panel(app: S19TuiApp) -> PatchEditorPanel:
    return app.query_one("#patch_editor_panel", PatchEditorPanel)


def _param_rows(panel):
    return dict(_picker_of(panel).param_rows)


def _picker_visible_shape(panel) -> list[tuple[str, str, str]]:
    table_id = "#check_param_table" if isinstance(panel, CheckEditorPanel) else "#patch_param_table"
    table = panel.query_one(table_id, DataTable)
    return [tuple(_plain(cell) for cell in table.get_row_at(i)[1:4]) for i in range(table.row_count)]


def _a2l_viewer_names(app: S19TuiApp) -> list[str]:
    table = app.query_one("#a2l_tags_list", DataTable)
    index = next(i for i, col in enumerate(table.ordered_columns) if str(col.label) == "Tag")
    return [
        _plain(table.get_row_at(row)[index]).removeprefix("✓ ").removeprefix("· ")
        for row in range(table.row_count)
    ]


def _status_text(app: S19TuiApp) -> str:
    return str(app.query_one("#status_text", Label).render())


def _bar(app: S19TuiApp) -> float:
    return app.query_one("#progress_bar", ProgressBar).progress


def _log_lines(app: S19TuiApp) -> list[str]:
    return [_plain(app.query_one(f"#log_line_{i}", Label).render()) for i in range(1, 5)]


def _loaded_text(app: S19TuiApp) -> list[str]:
    return [
        _plain(cell.render())
        for cell in app.query_one("#loaded_panel", LoadedArtifactsPanel).query(".loaded-detail")
    ]


def _assert_panel_state(panel, rows) -> None:
    """Exact picker state: (address, size, fmt) per name and painted cells."""
    got = _param_rows(panel)
    expected = {name: (address, size, fmt) for name, address, size, fmt in rows}
    assert got == expected, (type(panel).__name__, got, expected)
    visible = _picker_visible_shape(panel)
    assert visible == [
        (name, f"0x{address:08X}", fmt) for name, address, _size, fmt in rows
    ], (type(panel).__name__, visible)


def _state_snapshot(app: S19TuiApp) -> tuple:
    """The A2L-dependent session/state surface .032/.038 must preserve."""
    return (
        app.current_a2l_path,
        copy.deepcopy(app.current_a2l_data),
        copy.deepcopy(app.current_file),
        app._a2l_view_generation,
        app._image_generation,
        copy.deepcopy(app._a2l_enriched_tags),
        app._a2l_enriched_key,
        app._mac_window_start,
        copy.deepcopy(app._mac_view_cache_summary),
        _a2l_viewer_names(app),
        _param_rows(_check_panel(app)),
        _param_rows(_patch_panel(app)),
        _picker_of(_check_panel(app))._signature,
        _picker_of(_patch_panel(app))._signature,
    )


# ---------------------------------------------------------------------------
# Spy / Hold / sampler instruments (thread-recording, like the b100 spies).
# ---------------------------------------------------------------------------


class Spy:
    """Record (thread, args, kwargs) per call and run the real function."""

    def __init__(self, monkeypatch, owner, name, *, raising=False, before=None, after=None) -> None:
        self.calls: list = []
        self.name = name
        real = getattr(owner, name, None)
        spy = self

        def _wrapped(*args, **kwargs):
            if before is not None:
                before(*args, **kwargs)
            spy.calls.append(SimpleNamespace(thread=threading.get_ident(), args=args, kwargs=kwargs))
            result = real(*args, **kwargs) if real is not None else None
            if after is not None:
                after(*args, **kwargs)
            return result

        monkeypatch.setattr(owner, name, _wrapped, raising=raising)

    def threads(self) -> set:
        return {c.thread for c in self.calls}


class Hold:
    """A forced slow step shared by one or more bindings.

    Off the event-loop thread the first matching call blocks on
    ``release`` (then raises ``raise_on_release`` when given, else runs the
    real function); later calls pass through. On the event-loop thread it
    never blocks and records the call in ``main_calls``, so ``reached``
    fails at once when the phase runs on the UI thread.
    """

    def __init__(self, monkeypatch, targets, *, timeout: float = 180.0, raise_on_release=None) -> None:
        if isinstance(targets, tuple) and len(targets) == 2 and not isinstance(targets[0], tuple):
            targets = [targets]
        self.main = threading.get_ident()
        self.entered = threading.Event()
        self.release = threading.Event()
        self.main_calls: list = []
        self.worker_calls: list = []
        self.raise_on_release = raise_on_release
        self.timeout = timeout
        for owner, name in targets:
            real = getattr(owner, name, None)
            monkeypatch.setattr(owner, name, self._wrap(real, name), raising=False)

    def _wrap(self, real, name):
        hold = self

        def _held(*args, **kwargs):
            ident = threading.get_ident()
            if ident == hold.main:
                hold.main_calls.append(name)
                return real(*args, **kwargs) if real is not None else None
            hold.worker_calls.append(name)
            if not hold.entered.is_set():
                hold.entered.set()
                if not hold.release.wait(hold.timeout):
                    raise TimeoutError(f"the forced slow step {name} was never released")
                if hold.raise_on_release is not None:
                    raise hold.raise_on_release
            return real(*args, **kwargs) if real is not None else None

        return _held


async def reached(pilot, hold, what: str, timeout: float = 60.0) -> None:
    """Wait until the phase blocks on a worker; fail at once when it ran on
    the event-loop thread (the base's synchronous action)."""
    deadline = time.monotonic() + timeout
    while not hold.entered.is_set():
        if hold.main_calls:
            raise AssertionError(
                f"{what}: the held phase ran on the main (event-loop) thread — no worker"
            )
        if time.monotonic() > deadline:
            raise AssertionError(f"{what} never reached its held phase")
        await pilot.pause(0.01)
    await pilot.pause()


async def release(pilot, hold) -> None:
    hold.release.set()
    await settle_workers(pilot)


class Sampler:
    """Continuous wall-clock samples of the visible busy line (and bar)."""

    def __init__(self) -> None:
        self.frames: list = []
        self.stop = threading.Event()

    async def run(self, pilot, app: S19TuiApp, *, bar: bool = False) -> None:
        while not self.stop.is_set():
            self.frames.append(
                (
                    time.monotonic(),
                    str(app.query_one("#status_text", Label).render()),
                    app.query_one("#progress_bar", ProgressBar).progress if bar else None,
                )
            )
            # 50 ms poll: enough resolution for the 1.0 s gap bound, and a
            # 20 ms poll measurably delays key acknowledgements on the same
            # UI loop under full-suite load (E4-INC2-F2).
            await pilot.pause(0.05)

    def start(self, pilot, app: S19TuiApp, *, bar: bool = False) -> asyncio.Task:
        return asyncio.create_task(self.run(pilot, app, bar=bar))

    def text_changes(self) -> list[tuple[float, str]]:
        """(elapsed, text) at every visible status change; first frame at 0."""
        if not self.frames:
            return []
        t0 = self.frames[0][0]
        out = [(0.0, self.frames[0][1])]
        for t, text, _bar in self.frames[1:]:
            if text != out[-1][1]:
                out.append((t - t0, text))
        return out


def _deliver_key(app: S19TuiApp, key: str) -> float:
    """
    Summary:
        Build and deliver one key event exactly as Textual 8.2.8
        ``App._press_keys`` does, without its ``wait_for_idle`` and animator
        waits, and return the delivery timestamp.

    Args:
        app (S19TuiApp): The app whose driver receives the event.
        key (str): The key string (e.g. ``"tab"`` or ``"shift+tab"``).

    Returns:
        float: ``time.monotonic()`` taken immediately before the message is
        sent, i.e. the delivery instant the acknowledgement latency is
        measured from.

    Raises:
        AssertionError: If the app has no driver.

    Data Flow:
        - Replicate the ``_press_keys`` character rule for the key name.
        - Build the ``events.Key`` and set its sender to the app.
        - Hand the event to ``driver.send_message`` (non-blocking headless
          ``run_coroutine_threadsafe`` path) so a busy worker is never
          awaited inside the delivery.

    Dependencies:
        Uses:
            - ``textual.events.Key`` / ``textual.keys`` helpers
            - ``unicodedata``
        Used by:
            - ``_key_ack_latency``
            - the ``request-snapshot`` capture arm
    """
    import unicodedata

    from textual import events
    from textual.keys import REPLACED_KEYS, _character_to_key, _get_unicode_name_from_key

    driver = app._driver
    assert driver is not None
    effective_key = key
    if len(effective_key) == 1 and not effective_key.isalnum():
        effective_key = _character_to_key(effective_key)
    original_key = REPLACED_KEYS.get(effective_key, effective_key)
    try:
        char = unicodedata.lookup(_get_unicode_name_from_key(original_key))
    except KeyError:
        char = effective_key if len(effective_key) == 1 else None
    key_event = events.Key(effective_key, char)
    key_event.set_sender(app)
    t0 = time.monotonic()
    driver.send_message(key_event)
    return t0


async def _poll_ack(pilot, key: str, acked, t0: float, *, timeout: float = 20.0) -> float:
    """
    Summary:
        Poll the acknowledgement predicate every 5 ms from the delivery
        instant and return the wall-clock latency once it becomes truthy.

    Args:
        pilot: The Textual pilot (kept for call-site symmetry; not used here
            because polling must not go through ``pilot.pause``).
        key (str): The key string, used only for the timeout message.
        acked: A zero-argument predicate for the key's acknowledgement.
        t0 (float): The ``time.monotonic()`` delivery instant.
        timeout (float): Seconds before the acknowledgement must arrive.

    Returns:
        float: ``time.monotonic() - t0`` at the acknowledgement.

    Raises:
        AssertionError: If the acknowledgement never arrives within ``timeout``.

    Data Flow:
        - Loop with a 5 ms ``asyncio.sleep`` yield (never ``pilot.pause``).
        - Fail at the timeout deadline.
        - Return the measured delivery-to-acknowledgement latency.

    Dependencies:
        Uses: ``asyncio.sleep`` / ``time.monotonic``
        Used by: ``_key_ack_latency`` and the ``request-snapshot`` capture arm
    """
    while not acked():
        await asyncio.sleep(0.005)
        if time.monotonic() - t0 > timeout:
            raise AssertionError(f"key {key!r} never acknowledged")
    return time.monotonic() - t0


async def _key_ack_latency(
    pilot, app: S19TuiApp, key: str, acked, *, bound: float, timeout: float = 20.0
) -> float:
    """
    Summary:
        Measure the wall-clock latency from delivering one key to its
        acknowledgement, never through ``pilot.press``.

    Args:
        pilot: The Textual pilot (kept for call-site symmetry; the delivery
            path below must not use ``pilot.press``/``pilot.pause``).
        app (S19TuiApp): The app the key is delivered to.
        key (str): The key string to deliver.
        acked: A zero-argument predicate for the key's acknowledgement.
        bound (float): The upper latency bound asserted against.
        timeout (float): Seconds before the acknowledgement must arrive.

    Returns:
        float: The measured delivery-to-acknowledgement latency.

    Raises:
        AssertionError: If the acknowledgement never arrives, or the latency
            exceeds ``bound``.

    Data Flow:
        - Deliver the key through ``_deliver_key`` (no ``wait_for_idle``).
        - Poll the acknowledgement from the delivery instant.
        - Assert the latency against ``bound`` and report its margin.

    Dependencies:
        Uses: ``_deliver_key`` / ``_poll_ack`` / ``report_margin``
        Used by: ``_focus_key_pair`` and ``test_r033_key_ack_instrument_controls``
    """
    t0 = _deliver_key(app, key)
    elapsed = await _poll_ack(pilot, key, acked, t0, timeout=timeout)
    assert elapsed <= report_margin(f"key {key}", elapsed, bound), (
        f"key {key!r} not acknowledged within {bound:.1f} s ({elapsed:.3f} s)"
    )
    return elapsed


async def _focus_key_pair(pilot, app: S19TuiApp, *, bound: float = 1.0) -> tuple[float, float]:
    """``tab`` then ``shift+tab``; each latency measured from delivery to
    the existing focus acknowledgement, individually recorded."""
    latencies = []
    for key in ("tab", "shift+tab"):
        before = app.focused
        lat = await _key_ack_latency(
            pilot, app, key, lambda: app.focused is not None and app.focused != before, bound=bound
        )
        latencies.append(lat)
    return tuple(latencies)


# ---------------------------------------------------------------------------
# Shared instrument arms
# ---------------------------------------------------------------------------


def _arm_pipeline_spies(owner, monkeypatch, events: list, main: int) -> dict:
    """Thread/order spies over the worker preparation and the install.
    ``owner`` is the app instance (route arms) or the app class (start-up)."""
    fl = _fl_module()
    service = _service_module()
    definition = _definition_module()
    picker = _picker_module()
    spies = {}

    def _record(name):
        def _before(*_a, **_k):
            events.append((name, threading.get_ident()))

        return _before

    spies["enrichment"] = Spy(monkeypatch, fl, "enrich_tags_and_render", before=_record("enrichment"))
    Spy(monkeypatch, service, "enrich_tags_and_render", before=_record("enrichment"))
    Spy(monkeypatch, service, "render_a2l_view", before=_record("summary"))
    spies["describe"] = Spy(monkeypatch, definition, "describe_definitions", before=_record("describe"))
    Spy(monkeypatch, picker, "describe_definitions", raising=False, before=_record("describe"))
    Spy(monkeypatch, fl, "describe_definitions", raising=False, before=_record("describe"))
    spies["context"] = Spy(monkeypatch, definition, "build_describe_context", before=_record("context"))
    Spy(monkeypatch, fl, "build_describe_context", raising=False, before=_record("context"))
    spies["install"] = Spy(monkeypatch, owner, "_install_attached_a2l", before=_record("install"))
    events.append(("UI", main))
    return spies


def _arm_install_fanout_outcome(app: S19TuiApp, monkeypatch, events: list) -> None:
    """install -> common refresh -> outcome timeline for .035/AT-I2-1.

    The real methods are captured from the class so re-arming on the same
    app instance (AT-I2-1's two routes) never wraps the previous arm's
    wrapper — one event per phase per attach."""
    real_install = S19TuiApp._install_attached_a2l
    real_fanout = S19TuiApp._refresh_a2l_dependent_views
    real_end = S19TuiApp.end_busy

    def install(result):
        events.append(("install", threading.get_ident()))
        return real_install(app, result)

    def fanout():
        events.append(("refresh", threading.get_ident()))
        return real_fanout(app)

    def end(key, gen, outcome):
        events.append(("outcome", threading.get_ident(), str(outcome)))
        return real_end(app, key, gen, outcome)

    monkeypatch.setattr(app, "_install_attached_a2l", install, raising=False)
    monkeypatch.setattr(app, "_refresh_a2l_dependent_views", fanout, raising=False)
    monkeypatch.setattr(app, "end_busy", end)


def _arm_zero_call_spies(app: S19TuiApp, monkeypatch, *, include_install: bool = True) -> dict:
    """The mutation seams .032/.038 assert stay at zero.

    ``include_install=False`` leaves the install seam to the arm's own single
    observing mechanism (the .032 class-level mutation spy); an instance spy
    on the same seam would shadow it and make the two assertions mutually
    exclusive.
    """
    fl = _fl_module()
    spies = {
        "recent": Spy(monkeypatch, fl, "record_recent_source"),
        "files": Spy(monkeypatch, app, "refresh_files"),
        "cache": Spy(monkeypatch, app, "_store_a2l_cache"),
        "replace": Spy(monkeypatch, app, "_replace_current_a2l"),
        "fanout": Spy(monkeypatch, app, "_refresh_a2l_dependent_views"),
        "sync": Spy(monkeypatch, app, "_sync_loaded_a2l_to_project"),
    }
    if include_install:
        spies["install"] = Spy(monkeypatch, app, "_install_attached_a2l")
    return spies


# ===========================================================================
# R-A2L-REFRESH.029 — one immutable attach snapshot before install (3/3).
# ===========================================================================


@pytest.mark.parametrize("route", ["typed", "workarea", "startup"], ids=lambda x: x)
def test_r029_worker_snapshot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, route: str) -> None:
    """R-A2L-REFRESH.029/1-/3: enrichment, summary and the one shared
    describe context complete off the UI thread before the install, with 0
    bulk describes in preparation; visible NEW cells exact."""
    _guard_attach_snapshot_seams()

    base = tmp_path / "app"
    src = tmp_path / "src"
    src.mkdir(parents=True)
    new = _new_a2l(src / "new.a2l")

    if route == "workarea":
        workarea_temp = base / WORKAREA_DIRNAME / WORKAREA_SUBDIR / WORKAREA_TEMP
        workarea_temp.mkdir(parents=True, exist_ok=True)
        (workarea_temp / "new.a2l").write_bytes(new.read_bytes())

    events: list = []
    copies = Spy(monkeypatch, app_module.deps, "copy_into_workarea")
    main_box: list = []

    async def typed_body(app, pilot):
        main = threading.get_ident()
        main_box.append(main)
        _mount_views(app)
        await pilot.pause()
        _arm_pipeline_spies(app, monkeypatch, events, main)
        await _typed_attach(app, pilot, new)
        await settle_workers(pilot)
        snapshot_map = _accepted_snapshots(app)
        assert snapshot_map is not None and set(snapshot_map) == {"check", "patch"}, snapshot_map
        _assert_panel_state(_check_panel(app), NEW_ROWS)
        _assert_panel_state(_patch_panel(app), NEW_ROWS)
        assert _a2l_viewer_names(app) == [name for name, *_ in NEW_ROWS]
        return None

    async def workarea_body(app, pilot):
        main = threading.get_ident()
        main_box.append(main)
        _mount_views(app)
        await pilot.pause()
        _arm_pipeline_spies(app, monkeypatch, events, main)
        await _workarea_attach(app, pilot, "new.a2l")
        await settle_workers(pilot)
        assert len(copies.calls) == 0, copies.calls
        snapshot_map = _accepted_snapshots(app)
        assert snapshot_map is not None and set(snapshot_map) == {"check", "patch"}, snapshot_map
        _assert_panel_state(_check_panel(app), NEW_ROWS)
        _assert_panel_state(_patch_panel(app), NEW_ROWS)
        assert _a2l_viewer_names(app) == [name for name, *_ in NEW_ROWS]
        return None

    async def startup_body(app, pilot):
        _mount_views(app)
        await pilot.pause()
        await wait_until(
            pilot,
            lambda: app.current_a2l_path is not None
            and Path(app.current_a2l_path).name == "new.a2l",
            "the start-up attach of new.a2l",
        )
        await settle_workers(pilot)
        snapshot_map = _accepted_snapshots(app)
        assert snapshot_map is not None and set(snapshot_map) == {"check", "patch"}, snapshot_map
        _assert_panel_state(_check_panel(app), NEW_ROWS)
        _assert_panel_state(_patch_panel(app), NEW_ROWS)
        assert _a2l_viewer_names(app) == [name for name, *_ in NEW_ROWS]
        return None

    if route == "typed":
        _run(base, typed_body)
    elif route == "workarea":
        _run(base, workarea_body)
    else:
        main = threading.get_ident()
        # Class-level spies: the start-up attach begins during app start.
        _arm_pipeline_spies(S19TuiApp, monkeypatch, events, main)
        _run(base, startup_body, load_path=src / "new.a2l", base_dir=base)
    if route != "startup":
        main = main_box[0]
    names = [e[0] for e in events]
    assert names.count("enrichment") == 1, events
    assert names.count("summary") == 1, events
    assert names.count("context") == 1, events
    assert names.count("describe") == 0, events
    assert names.count("install") == 1, events
    prep = [e for e in events if e[0] in {"enrichment", "summary", "context"}]
    installs = [e for e in events if e[0] == "install"]
    assert all(thread != main for _, thread in prep), events
    assert max(i for i, e in enumerate(events) if e[0] in {"enrichment", "summary", "context"}) < min(
        i for i, e in enumerate(events) if e[0] == "install"
    ), events
    assert installs[0][1] == main, events


# ===========================================================================
# R-A2L-REFRESH.030 — request isolation (2/2 runtime + 1/1 static).
# ===========================================================================


@pytest.mark.parametrize("arm", ["no-image", "with-image"], ids=lambda x: x)
def test_r030_request_isolation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: str) -> None:
    """R-A2L-REFRESH.030/1-/2: the request carries the expected pair and an
    independent read-only image copy; containers reject writes; a later
    source-byte change cannot alter the captured snapshot."""
    base = tmp_path / "app"
    src = tmp_path / "src"
    src.mkdir(parents=True)
    old = _old_a2l(src / "old.a2l")
    img = _write_image(src / "img1.s19", dict(IMG1))
    requests: list = []

    real_worker = S19TuiApp._a2l_attach_worker

    def worker_spy(self, request):
        requests.append(request)
        return real_worker(self, request)

    monkeypatch.setattr(S19TuiApp, "_a2l_attach_worker", worker_spy)

    async def body(app, pilot):
        _mount_views(app)
        await pilot.pause()
        a2l_before = app._a2l_view_generation
        image_before = app._image_generation
        if arm == "with-image":
            await _load_image(app, pilot, img)
            image_before = app._image_generation
            live_map = app.current_file.mem_map
            live_identity = app.current_file
        else:
            live_map = None
            live_identity = None
        await _typed_attach(app, pilot, old)
        request = requests[-1]
        assert getattr(request, "expected_a2l_generation", None) == a2l_before + 1, request
        assert getattr(request, "expected_image_generation", None) == image_before, request
        with pytest.raises(Exception):
            request.expected_a2l_generation = 999
        if arm == "with-image":
            mapping = getattr(request, "image_mem_map", None)
            assert mapping is not None, "request.image_mem_map is None despite a loaded image"
            assert dict(mapping) == IMG1, dict(mapping)
            assert len(mapping) == 3
            with pytest.raises(Exception):
                mapping[0x1000] = 0xFF
            # Change one original map byte through the live reference AFTER
            # capture: the request's independent copy keeps the original byte.
            live_map[0x1000] = 0xFF
            assert mapping[0x1000] == 0x10, mapping[0x1000]
            assert dict(mapping) == IMG1, dict(mapping)
            assert live_map[0x1000] == 0xFF, "the test-controlled source change did not land"
            assert app.current_file is live_identity
        else:
            assert getattr(request, "image_mem_map", "unset") is None, request
        assert getattr(requests[-1], "source") == old
        _assert_panel_state(_check_panel(app), OLD_ROWS)
        _assert_panel_state(_patch_panel(app), OLD_ROWS)
        assert _a2l_viewer_names(app) == [name for name, *_ in OLD_ROWS]
        return None

    _run(base, body)


#: Widget/session names the attach worker and its helper may never read.
FORBIDDEN_WORKER_READS = frozenset({
    "current_file", "current_project", "current_project_dir",
    "current_a2l_path", "current_a2l_data", "_variant_set", "_change_service",
    "_a2l_cache_key", "_a2l_cache_data", "_declared_regions",
    "_last_template_path", "_parsed_paste_text", "workarea", "base_dir",
    "_a2l_view_generation", "_image_generation", "_a2l_enriched_tags",
    "_a2l_enriched_key", "_a2l_summary_lines", "_a2l_summary_start",
    "_a2l_filtered_tags", "_a2l_row_key_to_tag", "_busy", "screen",
    "focused", "query_one", "_active_screen_key",
    "_accepted_a2l_picker_snapshots", "app",
})

#: The allowed infrastructure the design pins for the worker/helper.
ALLOWED_WORKER_INFRA = frozenset({"logger", "call_from_thread", "_progress_forwarder"})


def _worker_self_reads(source: str, func_names: frozenset) -> dict[str, set]:
    """``{func: set(self.<attr>)}`` for the named functions in ``source``."""
    tree = ast.parse(source)
    out: dict[str, set] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name not in func_names:
            continue
        reads = set()
        for inner in ast.walk(node):
            if (
                isinstance(inner, ast.Attribute)
                and isinstance(inner.value, ast.Name)
                and inner.value.id == "self"
            ):
                reads.add(inner.attr)
        out[node.name] = reads
    return out


def test_r030_worker_input_census() -> None:
    """R-A2L-REFRESH.030/3 (static census): both worker/helper nodes resolve;
    0 forbidden widget/session reads; a synthetic forbidden read is
    detected; the allowed logger/progress/thread-dispatch infra stays
    visible in the real worker."""
    fl = _fl_module()
    source = Path(fl.__file__).read_text(encoding="utf-8")
    names = frozenset(
        {
            "_a2l_attach_worker",
            "_prepare_a2l_attach_snapshot",
            # D-13 split the producer into a gc-managed wrapper and this
            # body; the census must cover both or a forbidden read in the
            # body would go undetected.
            "_prepare_a2l_attach_snapshot_inner",
        }
    )
    found = _worker_self_reads(source, names)
    assert set(found) == names, (
        f"every worker/helper node must resolve: missing {sorted(names - set(found))}"
    )
    for func, reads in found.items():
        forbidden = reads & FORBIDDEN_WORKER_READS
        assert not forbidden, f"{func} reads forbidden session/widget state: {sorted(forbidden)}"
    worker_reads = found["_a2l_attach_worker"]
    assert ALLOWED_WORKER_INFRA <= worker_reads, (
        f"allowed infra not visible in the worker: {sorted(ALLOWED_WORKER_INFRA - worker_reads)}"
    )
    # Negative control: one synthetic forbidden read is detected.
    synthetic = (
        "def _prepare_a2l_attach_snapshot(self, *, a2l_path, a2l_data, image_mem_map,\n"
        "    expected_a2l_generation, expected_image_generation):\n"
        "    return self.current_file\n"
    )
    synth_found = _worker_self_reads(synthetic, frozenset({"_prepare_a2l_attach_snapshot"}))
    assert synth_found["_prepare_a2l_attach_snapshot"] & FORBIDDEN_WORKER_READS == {"current_file"}


# ===========================================================================
# R-A2L-REFRESH.031 — matching pair installs coherently (3/3).
# ===========================================================================


@pytest.mark.parametrize("arm", ["no-image", "with-image", "same-path"], ids=lambda x: x)
def test_r031_matching_snapshot_installs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: str) -> None:
    """R-A2L-REFRESH.031/1-/3: the installed enrichment key is exactly
    (a2l_before + 1, image_before, mem_size); image bytes never change."""
    base = tmp_path / "app"
    src = tmp_path / "src"
    src.mkdir(parents=True)
    old = _old_a2l(src / "old.a2l")
    new = _new_a2l(src / "new.a2l")
    img = _write_image(src / "img1.s19", dict(IMG1))
    same = src / "same.a2l"
    same.write_bytes(old.read_bytes())

    async def body(app, pilot):
        _mount_views(app)
        await pilot.pause()
        # The negative control ("install only part of the snapshot") can
        # only discriminate if the key is observed BEFORE the common refresh
        # consumes or recomputes it: record the key at every refresh entry
        # and require the final entry to already be the expected key.
        refresh_entry_keys: list = []
        real_refresh = app._refresh_a2l_dependent_views

        def refresh_spy():
            refresh_entry_keys.append(app._a2l_enriched_key)
            return real_refresh()

        monkeypatch.setattr(app, "_refresh_a2l_dependent_views", refresh_spy)
        a2l_before = app._a2l_view_generation
        image_before = app._image_generation
        if arm == "with-image":
            await _load_image(app, pilot, img)
            image_before = app._image_generation
            mem_size = len(app.current_file.mem_map)
            live_map = dict(app.current_file.mem_map)
        elif arm == "same-path":
            await _load_image(app, pilot, img)
            image_before = app._image_generation
            mem_size = len(app.current_file.mem_map)
            live_map = dict(app.current_file.mem_map)
        else:
            mem_size = -1
            live_map = None
        if arm == "same-path":
            await _typed_attach(app, pilot, same)
            a2l_before = app._a2l_view_generation
            same.write_bytes(new.read_bytes())
            await _typed_attach(app, pilot, same)
            rows = NEW_ROWS
        else:
            await _typed_attach(app, pilot, old)
            rows = OLD_ROWS
        expected_key = (a2l_before + 1, image_before, mem_size)
        assert app._a2l_enriched_key == expected_key, (app._a2l_enriched_key, expected_key)
        assert refresh_entry_keys and refresh_entry_keys[-1] == expected_key, (
            refresh_entry_keys,
            expected_key,
        )
        assert app._a2l_enriched_key[0] == app._a2l_view_generation
        assert app._a2l_enriched_key[1] == app._image_generation
        snapshot_map = _accepted_snapshots(app)
        assert snapshot_map is not None and set(snapshot_map) == {"check", "patch"}, snapshot_map
        if arm in {"with-image", "same-path"}:
            assert app.current_file.mem_map == live_map, "image bytes changed"
        if arm == "with-image":
            tag = next(t for t in app._a2l_enriched_tags if t["name"] == "OLD_SCALAR")
            assert tag.get("raw_value") == 0x2010, tag
        _assert_panel_state(_check_panel(app), rows)
        _assert_panel_state(_patch_panel(app), rows)
        assert _a2l_viewer_names(app) == [name for name, *_ in rows]
        if arm == "same-path":
            for panel in (_check_panel(app), _patch_panel(app)):
                assert _param_rows(panel)["ARR12"] == (0x2000, 8, "f32"), _param_rows(panel)
        return None

    _run(base, body)


# ===========================================================================
# R-A2L-REFRESH.032 — stale generation discards the whole result (2/2).
# ===========================================================================


@pytest.mark.parametrize("arm", ["a2l-generation", "image-generation"], ids=lambda x: x)
def test_r032_stale_direct_attach(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: str) -> None:
    """R-A2L-REFRESH.032/1-/2: a real NEW result whose recorded generation
    is decremented after the real worker finishes and before the real
    install is refused whole, with the exact superseded outcome and 0
    install-side mutations."""
    _guard_attach_snapshot_seams()

    base = tmp_path / "app"
    src = tmp_path / "src"
    src.mkdir(parents=True)
    old = _old_a2l(src / "old.a2l")
    new = _new_a2l(src / "new.a2l")
    img = _write_image(src / "img1.s19", dict(IMG1))
    mac = _write_mac(src / "records.mac")

    real_install = S19TuiApp._install_attached_a2l
    mutations: list = []

    def install_spy(self, result):
        preparation = getattr(result, "preparation", None)
        # The arm mutates only the NEW result, after the real worker.
        if preparation is None or Path(result.request.source).name != "new.a2l":
            return real_install(self, result)
        new_preparation = dataclasses.replace(
            preparation,
            **{
                "expected_a2l_generation": preparation.expected_a2l_generation - 1
                if arm == "a2l-generation"
                else preparation.expected_a2l_generation,
                "expected_image_generation": preparation.expected_image_generation - 1
                if arm == "image-generation"
                else preparation.expected_image_generation,
            },
        )
        mutated = dataclasses.replace(result, preparation=new_preparation)
        mutations.append(("mutated", threading.get_ident()))
        return real_install(self, mutated)

    monkeypatch.setattr(S19TuiApp, "_install_attached_a2l", install_spy)

    async def body(app, pilot):
        _mount_views(app)
        await pilot.pause()
        await _load_image(app, pilot, img)
        await _load_image(app, pilot, mac)
        await _typed_attach(app, pilot, old)
        before = _state_snapshot(app)
        zero = _arm_zero_call_spies(app, monkeypatch, include_install=False)
        outcomes: list = []

        real_end = app.end_busy

        def end(key, gen, outcome):
            outcomes.append((key, str(outcome)))
            return real_end(key, gen, outcome)

        monkeypatch.setattr(app, "end_busy", end)
        await _submit_typed(app, pilot, str(new))
        await settle_workers(pilot)
        await wait_until(
            pilot,
            lambda: outcomes or mutations,
            "the superseded outcome of the stale direct attach",
            timeout=30.0,
        )
        # One single install observation: the class-level spy mutated the NEW
        # result and the real install ran exactly once (the install call is
        # the rejection path, not a forbidden mutation).
        assert len(mutations) == 1, mutations
        assert len(outcomes) == 1 and outcomes[0][1] == SUPERSEDED_OUTCOME, outcomes
        assert SUPERSEDED_OUTCOME in _log_lines(app), _log_lines(app)
        after = _state_snapshot(app)
        assert after == before, f"previous state changed: {before} -> {after}"
        assert len(zero["recent"].calls) == 0, zero["recent"].calls
        assert len(zero["cache"].calls) == 0, zero["cache"].calls
        assert len(zero["replace"].calls) == 0, zero["replace"].calls
        assert len(zero["fanout"].calls) == 0, zero["fanout"].calls
        assert len(zero["sync"].calls) == 0, zero["sync"].calls
        return None

    _run(base, body)


# ===========================================================================
# R-A2L-REFRESH.033 — key acknowledgement <= 1.0 s through every phase (6/6).
# ===========================================================================


@pytest.mark.serial_timing
@pytest.mark.parametrize(
    "arm",
    [
        "copy",
        "parse",
        "enrichment",
        "context",
        pytest.param("case06-full-processing", marks=pytest.mark.slow),
        "request-snapshot",
    ],
    ids=lambda x: x,
)
def test_r033_key_latency(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: str) -> None:
    """R-A2L-REFRESH.033/1-/6: two existing navigation keys are acknowledged
    within 1.0 s during the named phase, each latency recorded; no median
    substitution. The ``request-snapshot`` arm adds R-A2L-REFRESH.049 (the
    1.0 s capture bound) and keeps R-A2L-REFRESH.030 (the read-only image
    mapping independence)."""
    _guard_attach_snapshot_seams()

    base = tmp_path / "app"
    src = tmp_path / "src"
    src.mkdir(parents=True)
    old = _old_a2l(src / "old.a2l")
    bound = timing_bound(1.0)
    latencies: list = []

    if arm == "case06-full-processing":
        async def body(app, pilot):
            app.set_focus(app.query_one("#files_list"))
            await pilot.pause()
            deadline = time.monotonic() + 240
            app.load_a2l_from_path(CASE06)
            phase_keys = await _focus_key_pair(pilot, app, bound=bound)
            latencies.extend(phase_keys)
            while not (
                app.current_a2l_path is not None
                and Path(app.current_a2l_path).name == "firmware.a2l"
            ):
                if time.monotonic() > deadline:
                    raise AssertionError("the case_06 attach never installed")
                await pilot.pause(0.05)
            await settle_workers(pilot)
            assert any("A2L loaded" in line for line in _log_lines(app))
            snapshot_map = _accepted_snapshots(app)
            assert snapshot_map is not None and set(snapshot_map) == {"check", "patch"}, snapshot_map
            return None

        _run(base, body)
        assert len(latencies) == 2, latencies
        assert all(lat <= bound for lat in latencies), latencies
        return

    if arm == "request-snapshot":
        big = _write_big_image(src / "big1m.s19")
        fl = _fl_module()
        service = _service_module()
        enrich_calls: list = []
        real_enrich = getattr(fl, "enrich_tags_and_render", None)

        def enrich_spy(*args, **kwargs):
            enrich_calls.append(threading.get_ident())
            return real_enrich(*args, **kwargs) if real_enrich is not None else None

        monkeypatch.setattr(fl, "enrich_tags_and_render", enrich_spy, raising=False)
        monkeypatch.setattr(service, "enrich_tags_and_render", enrich_spy, raising=False)
        # The worker blocks at parse until released, so preparation cannot
        # start while the keys acknowledge (D-11 phase assertion).
        hold = Hold(monkeypatch, [(app_module.deps, "parse_a2l_cached")])

        async def body(app, pilot):
            app.set_focus(app.query_one("#files_list"))
            await pilot.pause()
            await _load_image(app, pilot, big)
            live_map = app.current_file.mem_map
            live_len = len(live_map)
            first_byte = next(iter(live_map))
            original_value = live_map[first_byte]
            requests: list = []

            real_worker = app._a2l_attach_worker

            def worker_spy(request):
                requests.append(request)
                return real_worker(request)

            monkeypatch.setattr(app, "_a2l_attach_worker", worker_spy)
            # R-A2L-REFRESH.049: ``tab`` is delivered immediately before the
            # synchronous request-snapshot capture and its acknowledgement is
            # polled only after ``load_a2l_from_path`` returns, measured from
            # the delivery instant — the capture window is bounded at 1.0 s.
            before_tab = app.focused
            tab_t0 = _deliver_key(app, "tab")
            app.load_a2l_from_path(old)
            # The existing busy progress line was painted before the capture
            # and stays visible through it.
            _assert_busy_progress(
                _status_text(app), name="old.a2l", step="step 1/3", step_label="Copy into the work area"
            )
            tab_latency = await _poll_ack(
                pilot,
                "tab",
                lambda: app.focused is not None and app.focused != before_tab,
                tab_t0,
                timeout=30.0,
            )
            assert tab_latency <= report_margin("key tab (capture)", tab_latency, bound), (
                f"key 'tab' not acknowledged within {bound:.1f} s ({tab_latency:.3f} s)"
            )
            before_shift = app.focused
            shift_t0 = _deliver_key(app, "shift+tab")
            shift_latency = await _poll_ack(
                pilot,
                "shift+tab",
                lambda: app.focused is not None and app.focused != before_shift,
                shift_t0,
                timeout=30.0,
            )
            assert shift_latency <= report_margin("key shift+tab (capture)", shift_latency, bound), (
                f"key 'shift+tab' not acknowledged within {bound:.1f} s ({shift_latency:.3f} s)"
            )
            latencies.extend([tab_latency, shift_latency])
            # Phase assertions: both keys acknowledged while the parse was
            # still held and preparation had not started — the
            # acknowledgements did not wait for parse or preparation (D-11).
            assert len(requests) == 1, requests
            assert enrich_calls == [], enrich_calls
            hold.release.set()
            await settle_workers(pilot)
            mapping = getattr(requests[0], "image_mem_map", None)
            assert mapping is not None and len(mapping) == live_len, (
                "the worker did not receive an independent read-only image copy"
            )
            with pytest.raises(Exception):
                mapping[first_byte] = 0xFF
            # Source-mutation control: the captured copy is independent of
            # the live map — a later live-byte change cannot alter it.
            live_map[first_byte] = 0xFF
            assert mapping[first_byte] == original_value, (mapping[first_byte], original_value)
            assert live_map[first_byte] == 0xFF, "the test-controlled source change did not land"
            assert app.current_a2l_path is not None
            return None

        _run(base, body)
        assert len(latencies) == 2, latencies
        return

    # The four held-phase arms.
    async def typed_submit(app, pilot):
        await _submit_typed(app, pilot, str(old))

    if arm == "copy":
        hold = Hold(monkeypatch, [(app_module.deps, "copy_into_workarea")])

        async def copy_body(app, pilot):
            app.set_focus(app.query_one("#files_list"))
            await pilot.pause()
            await typed_submit(app, pilot)
            await reached(pilot, hold, "the held copy phase")
            assert app.current_a2l_path is None, "an install/outcome happened during the hold"
            phase_keys = await _focus_key_pair(pilot, app, bound=bound)
            latencies.extend(phase_keys)
            _assert_busy_progress(
                _status_text(app), name="old.a2l", step="step 1/3", step_label="Copy into the work area"
            )
            await release(pilot, hold)
            await wait_until(
                pilot,
                lambda: app.current_a2l_path is not None
                and Path(app.current_a2l_path).name == "old.a2l",
                "the held copy outcome",
            )
            return None

        _run(base, copy_body)
    elif arm == "parse":
        entered = threading.Event()
        release_parse = threading.Event()
        progress_reports: list = []
        real_parse = app_module.deps.parse_a2l_cached

        def gated(path, *args, **kwargs):
            progress = kwargs.get("progress")

            def wrapped(done, total):
                progress_reports.append((done, total))
                if not entered.is_set():
                    entered.set()
                    assert release_parse.wait(180), "the held parse was never released"
                if progress is not None:
                    return progress(done, total)
                return None

            kwargs["progress"] = wrapped
            return real_parse(path, *args, **kwargs)

        monkeypatch.setattr(app_module.deps, "parse_a2l_cached", gated)

        async def parse_body(app, pilot):
            app.set_focus(app.query_one("#files_list"))
            await pilot.pause()
            await typed_submit(app, pilot)
            await reached(pilot, _ParsedHold(entered), "the held parse phase")
            assert progress_reports, "the parse made no byte-progress report"
            assert app.current_a2l_path is None, "an install/outcome happened during the hold"
            phase_keys = await _focus_key_pair(pilot, app, bound=bound)
            latencies.extend(phase_keys)
            assert 33 <= _bar(app) <= 66, _bar(app)
            _assert_busy_progress(_status_text(app), name="old.a2l", step="step 2/3", step_label="Parse")
            release_parse.set()
            await settle_workers(pilot)
            await wait_until(
                pilot,
                lambda: app.current_a2l_path is not None
                and Path(app.current_a2l_path).name == "old.a2l",
                "the held parse outcome",
            )
            return None

        _run(base, parse_body)
    else:
        fl = _fl_module()
        if arm == "enrichment":
            service = _service_module()
            hold = Hold(monkeypatch, [(fl, "enrich_tags_and_render"), (service, "enrich_tags_and_render")])
        else:
            definition = _definition_module()
            hold = Hold(
                monkeypatch,
                [
                    (definition, "build_describe_context"),
                    (fl, "build_describe_context"),
                ],
            )

        async def held_body(app, pilot):
            app.set_focus(app.query_one("#files_list"))
            await pilot.pause()
            await typed_submit(app, pilot)
            await reached(pilot, hold, f"the held {arm} phase")
            assert app.current_a2l_path is None, "an install/outcome happened during the hold"
            phase_keys = await _focus_key_pair(pilot, app, bound=bound)
            latencies.extend(phase_keys)
            _assert_busy_progress(_status_text(app), name="old.a2l", step="step 2/3", step_label="Parse")
            await release(pilot, hold)
            await wait_until(
                pilot,
                lambda: app.current_a2l_path is not None
                and Path(app.current_a2l_path).name == "old.a2l",
                f"the held {arm} outcome",
            )
            return None

        _run(base, held_body)

    assert len(latencies) == 2, latencies
    assert all(lat <= bound for lat in latencies), latencies


@pytest.mark.serial_timing
@pytest.mark.parametrize(
    "arm",
    ["ui-block-detected", "busy-worker-not-penalized"],
    ids=lambda x: x,
)
def test_r033_key_ack_instrument_controls(tmp_path: Path, arm: str) -> None:
    """R-A2L-REFRESH.033 negative control: the delivery-to-acknowledgement
    instrument reports a UI-thread block >= 1.5 s (arm 1) and does not
    penalize a GIL-holding busy worker thread (arm 2), so it measures the
    acknowledgement latency without the ``pilot.press`` idle waits."""
    _guard_attach_snapshot_seams()

    base = tmp_path / "app"
    bound = timing_bound(1.0)

    async def body(app, pilot):
        app.set_focus(app.query_one("#files_list"))
        await pilot.pause()
        before = app.focused
        acked = lambda: app.focused is not None and app.focused != before
        if arm == "ui-block-detected":
            # A UI-thread block scheduled right after delivery must surface
            # as a latency >= 1.5 s (a lower bound, robust to host load).
            # The helper's own upper bound is deliberately generous here so
            # it returns the measurement for the lower-bound assertion.
            def block_ui() -> None:
                time.sleep(1.5)

            app.call_later(block_ui)
            latency = await _key_ack_latency(pilot, app, "tab", acked, bound=10.0)
            assert latency >= 1.5, latency
        else:
            # A daemon thread holding the GIL with a pure-Python loop (DX's
            # synthetic busy-worker case) must not add the ~2 s
            # ``wait_for_idle`` penalty: the helper reports <= bound.
            stop = threading.Event()

            def spin() -> None:
                deadline = time.monotonic() + 3.0
                while not stop.is_set() and time.monotonic() < deadline:
                    pass

            thread = threading.Thread(target=spin, daemon=True)
            thread.start()
            try:
                latency = await _key_ack_latency(pilot, app, "tab", acked, bound=bound)
            finally:
                stop.set()
                thread.join(timeout=10.0)
            assert latency <= report_margin(f"key tab ({arm})", latency, bound), latency
        return None

    _run(base, body)


class _ParsedHold:
    """A ``reached``-compatible handle for the gated parse."""

    def __init__(self, event: threading.Event) -> None:
        self.entered = event
        self.main_calls: list = []


# ===========================================================================
# R-A2L-REFRESH.034 — visible progress continuity (4/4).
# ===========================================================================


def _assert_progress_continuous(sampler: Sampler, what: str) -> None:
    changes = sampler.text_changes()
    assert len(changes) >= 2, f"{what}: fewer than 2 spinner/elapsed changes ({len(changes)})"
    times = [t for t, _ in changes]
    gaps = [b - a for a, b in zip(times, times[1:])]
    assert all(gap <= 1.0 for gap in gaps), f"{what}: progress gaps {gaps}"


@pytest.mark.serial_timing
@pytest.mark.parametrize(
    "arm",
    [
        "enrichment",
        "context",
        pytest.param("case06-full-processing", marks=pytest.mark.slow),
        "request-snapshot",
    ],
    ids=lambda x: x,
)
def test_r034_progress_throughout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: str) -> None:
    """R-A2L-REFRESH.034/1-/4: the existing busy line stays visible and every
    inter-update gap is <= 1.0 s through the named phase until the outcome."""
    _guard_attach_snapshot_seams()

    base = tmp_path / "app"
    src = tmp_path / "src"
    src.mkdir(parents=True)
    old = _old_a2l(src / "old.a2l")

    if arm == "case06-full-processing":
        async def body(app, pilot):
            sampler = Sampler()
            task = sampler.start(pilot, app, bar=True)
            await pilot.pause(0.1)
            # D-12: the sampling window ends when post-parse preparation and
            # installation complete, i.e. when the preserved common refresh
            # begins; the preserved-refresh gap is recorded unasserted.
            refresh_entry: list = []
            real_refresh = app._refresh_a2l_dependent_views

            def refresh_spy():
                refresh_entry.append(time.monotonic())
                return real_refresh()

            monkeypatch.setattr(app, "_refresh_a2l_dependent_views", refresh_spy)
            deadline = time.monotonic() + 300
            app.load_a2l_from_path(CASE06)
            while True:
                if (
                    app.current_a2l_path is not None
                    and Path(app.current_a2l_path).name == "firmware.a2l"
                    and "a2l_load" not in app._busy.runs
                ):
                    break
                if time.monotonic() > deadline:
                    raise AssertionError("the case_06 attach never reached its terminal outcome")
                await pilot.pause(0.05)
            sampler.stop.set()
            await task
            changes = sampler.text_changes()
            texts = [text for _, text in changes]
            assert any(_is_busy_progress(text, name="firmware.a2l") for text in texts), texts
            assert any("Build the tag table" in text for text in texts), texts
            times = [t for t, _ in changes]
            gaps = [b - a for a, b in zip(times, times[1:])]
            # D-12: every gap inside the commissioned window (before the
            # preserved common refresh starts) is <= 1.0 s; the gaps at or
            # after the refresh entry are the preserved-refresh territory
            # and are recorded unasserted (the refresh is a held step, CTX-BUSY).
            assert refresh_entry, "the preserved common refresh never started"
            t0_abs = sampler.frames[0][0]
            refresh_rel = refresh_entry[0] - t0_abs
            window_gaps = [
                gap for (a, b), gap in zip(zip(times, times[1:]), gaps)
                if b <= refresh_rel
            ]
            assert window_gaps, (times, refresh_rel)
            assert all(gap <= 1.0 for gap in window_gaps), f"{arm}: progress gaps {window_gaps}"
            bars = [bar for _t, _x, bar in sampler.frames if bar is not None]
            assert all(0 <= value <= 100 for value in bars), "out-of-range bar value"
            assert any("A2L loaded" in line for line in _log_lines(app))
            return None

        _run(base, body)
        return

    if arm == "request-snapshot":
        big = _write_big_image(src / "big1m.s19")
        # The worker blocks at parse until released, keeping the busy run
        # alive while the post-capture timer check runs (D-11 no freeze).
        hold = Hold(monkeypatch, [(app_module.deps, "parse_a2l_cached")])

        async def body(app, pilot):
            await _load_image(app, pilot, big)
            sampler = Sampler()
            task = sampler.start(pilot, app, bar=True)
            await pilot.pause(0.1)
            started = threading.Event()

            real_worker = app._a2l_attach_worker

            def worker_spy(request):
                started.set()
                return real_worker(request)

            monkeypatch.setattr(app, "_a2l_attach_worker", worker_spy)
            # The synchronous request-snapshot capture: its wall time is
            # recorded, and the visible-progress interval that spans it is
            # asserted <= 1.0 s (R-A2L-REFRESH.034).
            capture_t0 = time.monotonic()
            app.load_a2l_from_path(old)
            capture_end = time.monotonic()
            capture_elapsed = capture_end - capture_t0
            # The existing busy line was painted before the capture and
            # stays visible right after it.
            _assert_busy_progress(
                _status_text(app), name="old.a2l", step="step 1/3", step_label="Copy into the work area"
            )
            assert started.is_set(), "the attach worker never started"
            await pilot.pause(0.4)
            # No timer freeze: the painted elapsed clock kept counting
            # through the capture (wall-clock elapsed, not a frozen 00:00).
            mmss = _status_text(app).split("  ·  ")[-1]
            elapsed_shown = int(mmss.split(":")[1])
            assert elapsed_shown >= int(capture_elapsed), (elapsed_shown, capture_elapsed)
            hold.release.set()
            await settle_workers(pilot)
            sampler.stop.set()
            await task
            changes = sampler.text_changes()
            # Every visible-progress interval that spans the synchronous
            # capture is <= 1.0 s (the capture window is bounded).
            abs_t0 = sampler.frames[0][0]
            abs_times = [abs_t0 + t for t, _ in changes]
            capture_gaps = [
                b - a
                for a, b in zip(abs_times, abs_times[1:])
                if a <= capture_t0 and b >= capture_end
            ]
            assert capture_gaps, (capture_t0, capture_end, abs_times)
            assert all(
                gap <= timing_bound(1.0) for gap in capture_gaps
            ), f"{arm}: capture-span gaps {capture_gaps}"
            assert any(_is_busy_progress(text, name="old.a2l") for _, text in changes), changes
            bars = [bar for _t, _x, bar in sampler.frames if bar is not None]
            assert all(0 <= value <= 100 for value in bars), "out-of-range bar value"
            assert app.current_a2l_path is not None
            return None

        _run(base, body)
        return

    # The two 1.5 s held arms.
    fl = _fl_module()
    if arm == "enrichment":
        service = _service_module()
        hold = Hold(monkeypatch, [(fl, "enrich_tags_and_render"), (service, "enrich_tags_and_render")])
    else:
        definition = _definition_module()
        hold = Hold(
            monkeypatch,
            [
                (definition, "build_describe_context"),
                (fl, "build_describe_context"),
            ],
        )

    async def held_progress_body(app, pilot):
        sampler = Sampler()
        await _submit_typed(app, pilot, str(old))
        await reached(pilot, hold, f"the held {arm} phase")
        task = sampler.start(pilot, app)
        await asyncio.sleep(1.5)
        sampler.stop.set()
        await task
        _assert_progress_continuous(sampler, arm)
        texts = [text for _, text in sampler.text_changes()]
        assert any(_is_busy_progress(text, name="old.a2l") for text in texts), texts
        assert not any("A2L loaded" in text or "NOT loaded" in text for text in texts), texts
        await release(pilot, hold)
        await wait_until(
            pilot,
            lambda: app.current_a2l_path is not None
            and Path(app.current_a2l_path).name == "old.a2l",
            f"the held {arm} attach outcome",
        )
        return None

    _run(base, held_progress_body)


# ===========================================================================
# R-A2L-REFRESH.035 — one UI common refresh between install and outcome (3/3).
# ===========================================================================


@pytest.mark.parametrize("arm", ["first", "replacement", "confirmed-same-path"], ids=lambda x: x)
def test_r035_refresh_before_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: str) -> None:
    """R-A2L-REFRESH.035/1-/3: install -> one common refresh(UI) -> outcome;
    no OLD value or intermediate empty state at the outcome."""
    _guard_attach_snapshot_seams()

    base = tmp_path / "app"
    src = tmp_path / "src"
    src.mkdir(parents=True)
    old = _old_a2l(src / "old.a2l")
    new = _new_a2l(src / "new.a2l")
    same = src / "same.a2l"
    same.write_bytes(old.read_bytes())

    async def body(app, pilot):
        main = threading.get_ident()
        _mount_views(app)
        await pilot.pause()
        hashes = None
        listed = None
        if arm == "replacement":
            await _typed_attach(app, pilot, old)
        elif arm == "confirmed-same-path":
            project = _seed_project(app.workarea, "P_OLD", a2l=same)
            await _load_project(app, pilot, "P_OLD")
            app.current_project = "Proj One"
            app.current_project_dir = project
            listed = app.current_a2l_path
        events: list = []
        _arm_install_fanout_outcome(app, monkeypatch, events)
        workers = Spy(monkeypatch, app, "_a2l_attach_worker")
        if arm == "confirmed-same-path":
            listed.write_bytes(new.read_bytes())
            # The digests capture the project bytes as the attach finds them
            # (after the test's own replacement write): sync_project=False
            # means the confirmed attach must not change them further.
            hashes = _project_digests(app.current_project_dir)
            await _submit_typed(app, pilot, str(listed))
            assert isinstance(app.screen, ConfirmQuestionScreen), list(app.log_lines)
            await pilot.press("y")
        else:
            await _typed_attach(app, pilot, old if arm == "first" else new)
        await settle_workers(pilot)
        kind = [e[0] for e in events]
        assert kind.count("install") == 1 and kind.count("refresh") == 1, events
        order = [e[0] for e in events if e[0] in {"install", "refresh", "outcome"}]
        assert order == ["install", "refresh", "outcome"], events
        refresh_thread = [e[1] for e in events if e[0] == "refresh"]
        assert refresh_thread == [main], events
        outcome = [e[2] for e in events if e[0] == "outcome"]
        assert len(outcome) == 1 and outcome[0].startswith("A2L loaded"), outcome
        assert len(workers.calls) == 1, workers.calls
        rows = OLD_ROWS if arm == "first" else NEW_ROWS
        _assert_panel_state(_check_panel(app), rows)
        _assert_panel_state(_patch_panel(app), rows)
        assert _a2l_viewer_names(app) == [name for name, *_ in rows]
        if arm == "confirmed-same-path":
            assert workers.calls[0].args[0].sync_project is False, workers.calls[0]
            assert _project_digests(app.current_project_dir) == hashes
        snapshot_map = _accepted_snapshots(app)
        assert snapshot_map is not None and set(snapshot_map) == {"check", "patch"}, snapshot_map
        return None

    _run(base, body)


# ===========================================================================
# R-A2L-REFRESH.036 — common refresh reuses the snapshot (2/2).
# ===========================================================================


@pytest.mark.parametrize("arm", ["no-image", "with-image"], ids=lambda x: x)
def test_r036_refresh_reuses_snapshot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: str) -> None:
    """R-A2L-REFRESH.036/1-/2: exactly one enrichment and one summary
    construction on the worker, 0 on the UI thread; the common refresh
    consumes the installed tags/summary and paints the exact OLD rows."""
    base = tmp_path / "app"
    src = tmp_path / "src"
    src.mkdir(parents=True)
    old = _old_a2l(src / "old.a2l")
    img = _write_image(src / "img1.s19", dict(IMG1))

    fl = _fl_module()
    service = _service_module()
    enrichment_calls: list = []
    summary_calls: list = []
    real_enrich = getattr(fl, "enrich_tags_and_render", None)

    def enrich_spy(*args, **kwargs):
        enrichment_calls.append(threading.get_ident())
        return real_enrich(*args, **kwargs) if real_enrich is not None else None

    monkeypatch.setattr(fl, "enrich_tags_and_render", enrich_spy, raising=False)
    monkeypatch.setattr(service, "enrich_tags_and_render", enrich_spy, raising=False)
    real_render = getattr(service, "render_a2l_view", None)

    def render_spy(*args, **kwargs):
        summary_calls.append(threading.get_ident())
        return real_render(*args, **kwargs) if real_render is not None else None

    monkeypatch.setattr(service, "render_a2l_view", render_spy)

    async def body(app, pilot):
        main = threading.get_ident()
        _mount_views(app)
        await pilot.pause()
        if arm == "with-image":
            await _load_image(app, pilot, img)
        await _typed_attach(app, pilot, old)
        await settle_workers(pilot)
        assert len(enrichment_calls) == 1, enrichment_calls
        assert len(summary_calls) == 1, summary_calls
        assert main not in enrichment_calls, enrichment_calls
        assert main not in summary_calls, summary_calls
        _assert_panel_state(_check_panel(app), OLD_ROWS)
        _assert_panel_state(_patch_panel(app), OLD_ROWS)
        assert _a2l_viewer_names(app) == [name for name, *_ in OLD_ROWS]
        if arm == "with-image":
            tag = next(t for t in app._a2l_enriched_tags if t["name"] == "OLD_SCALAR")
            assert tag.get("raw_value") == 0x2010, tag
        else:
            assert all(t.get("raw_value") in (None, "") for t in app._a2l_enriched_tags)
        return None

    _run(base, body)


# ===========================================================================
# R-A2L-REFRESH.037 — picker snapshot reuse (5/5).
# ===========================================================================


def _describe_spies(monkeypatch) -> list:
    """One describe record across the picker bindings and the attach-worker
    binding (thread-tagged)."""
    definition = _definition_module()
    picker = _picker_module()
    fl = _fl_module()
    calls: list = []
    real = definition.describe_definitions

    def spy(names, a2l_data):
        materialized = list(names)
        result = real(materialized, a2l_data)
        calls.append(
            {"names": materialized, "data": a2l_data, "thread": threading.get_ident(), "count": len(result)}
        )
        return result

    monkeypatch.setattr(definition, "describe_definitions", spy)
    monkeypatch.setattr(picker, "describe_definitions", spy, raising=False)
    monkeypatch.setattr(fl, "describe_definitions", spy, raising=False)
    return calls


def _build_spies(monkeypatch) -> list:
    """One record of every describe-context build across the attach-worker
    binding and the definition module (thread-tagged, names kept)."""
    definition = _definition_module()
    fl = _fl_module()
    calls: list = []
    real = definition.build_describe_context

    def spy(a2l_data, names):
        materialized = list(names)
        result = real(a2l_data, materialized)
        calls.append({"names": materialized, "data": a2l_data, "thread": threading.get_ident()})
        return result

    monkeypatch.setattr(definition, "build_describe_context", spy)
    monkeypatch.setattr(fl, "build_describe_context", spy, raising=False)
    return calls


@pytest.mark.parametrize(
    "arm",
    ["initial", "changed-generation", "filter-page-noop", "adapter-mismatch", "headless-unmounted"],
    ids=lambda x: x,
)
def test_r037_picker_snapshot_reuse(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: str) -> None:
    """R-A2L-REFRESH.037/1-/5 (E4R): one shared worker describe per accepted
    generation, zero for rebuilds/no-ops, and unmounted-call preservation.
    D-15 (I-ALP-3): the adapter-mismatch arm asserts replacement semantics
    on image reload / project install (fresh snapshot with the live source
    and signature wins, 0 UI describes, no stale paints) and covers the
    adapter's mismatch -> empty -> describe guard by constructing the
    mismatch state directly. Ruling R3: the Patch half of the adapter
    (match / consume / invalidate the whole mapping before the fallback;
    unmounted -> legacy) drives the app caller ``_prefill_patch_editor``
    instead of ``patch.set_a2l_parameters``; the Check half still drives
    the panel directly."""
    _guard_attach_snapshot_seams()

    base = tmp_path / "app"
    src = tmp_path / "src"
    src.mkdir(parents=True)
    old = _old_a2l(src / "old.a2l")
    new = _new_a2l(src / "new.a2l")
    img = _write_image(src / "img1.s19", dict(IMG1))
    img2 = _write_image(src / "img2.s19", dict(IMG2))
    same = src / "same.a2l"
    same.write_bytes(old.read_bytes())

    describes = _describe_spies(monkeypatch)
    builds = _build_spies(monkeypatch)
    main = threading.get_ident()

    if arm == "initial":
        definition = _definition_module()
        picker_module = _picker_module()
        real_describe_one = definition._describe_one
        real_set_parameters = picker_module.A2LParameterPicker.set_parameters
        population_ui_describe_one: list = []
        in_population: list = []

        def counted_describe_one(name, *args, **kwargs):
            if in_population and threading.get_ident() == main:
                population_ui_describe_one.append(name)
            return real_describe_one(name, *args, **kwargs)

        def marked_set_parameters(self, *args, **kwargs):
            in_population.append(1)
            try:
                return real_set_parameters(self, *args, **kwargs)
            finally:
                in_population.pop()

        monkeypatch.setattr(definition, "_describe_one", counted_describe_one)
        monkeypatch.setattr(picker_module.A2LParameterPicker, "set_parameters", marked_set_parameters)

        async def body(app, pilot):
            _mount_views(app)
            await pilot.pause()
            describes.clear()
            builds.clear()
            del population_ui_describe_one[:]
            await _typed_attach(app, pilot, old)
            await settle_workers(pilot)
            worker_builds = [c for c in builds if c["thread"] != main]
            ui_builds = [c for c in builds if c["thread"] == main]
            assert len(worker_builds) == 1, builds
            assert len(ui_builds) == 0, builds
            expected_names = [name for name, *_ in OLD_ROWS]
            assert all(c["names"] == expected_names for c in worker_builds), builds
            assert describes == [], describes
            assert population_ui_describe_one == [], population_ui_describe_one
            snapshot_map = _accepted_snapshots(app)
            assert snapshot_map is not None and set(snapshot_map) == {"check", "patch"}, snapshot_map
            context = snapshot_map["check"].describe_context
            assert context is not None and context is snapshot_map["patch"].describe_context
            _assert_panel_state(_check_panel(app), OLD_ROWS)
            _assert_panel_state(_patch_panel(app), OLD_ROWS)
            return None

        _run(base, body)

    elif arm == "changed-generation":
        async def body(app, pilot):
            _mount_views(app)
            await pilot.pause()
            await _typed_attach(app, pilot, same)
            await settle_workers(pilot)
            describes.clear()
            builds.clear()
            same.write_bytes(new.read_bytes())
            await _typed_attach(app, pilot, same)
            await settle_workers(pilot)
            worker_builds = [c for c in builds if c["thread"] != main]
            ui_builds = [c for c in builds if c["thread"] == main]
            assert len(worker_builds) == 1, builds
            assert len(ui_builds) == 0, builds
            assert all(c["names"] == [name for name, *_ in NEW_ROWS] for c in worker_builds), builds
            assert describes == [], describes
            for panel in (_check_panel(app), _patch_panel(app)):
                assert _param_rows(panel)["ARR12"] == (0x2000, 8, "f32"), _param_rows(panel)
                visible = _picker_visible_shape(panel)
                assert ("ARR12", "0x00002000", "f32") in visible, visible
                assert not any(fmt == "u16" for name, _addr, fmt in visible if name == "ARR12"), visible
            return None

        _run(base, body)

    elif arm == "filter-page-noop":
        big = _big_a2l(src / "big.a2l", 4200)

        async def body(app, pilot):
            _mount_views(app)
            await pilot.pause()
            await _typed_attach(app, pilot, big)
            await settle_workers(pilot)
            describes.clear()
            builds.clear()
            picker_module = _picker_module()
            rebuilds: list = []
            real_rebuild = picker_module.A2LParameterPicker._rebuild_ledger

            def counting_rebuild(self):
                result = real_rebuild(self)
                rebuilds.append(self.query_one(f"#{self._ids.table}", DataTable).row_count)
                return result

            monkeypatch.setattr(picker_module.A2LParameterPicker, "_rebuild_ledger", counting_rebuild)
            check = _check_panel(app)
            patch = _patch_panel(app)
            # 4,200 mounted definitions -> 21 pages of 200 rows: every Next
            # press turns a real page and rebuilds (the 3-row graph fixture
            # would leave Next disabled on its single page).
            for index in range(10):
                check.query_one("#check_param_filter", Input).value = "BIG" if index % 2 == 0 else ""
                await pilot.pause(0.2)
                check.query_one("#check_param_page_next_button", Button).press()
                await pilot.pause(0.2)
            key = app._a2l_enriched_key
            rows = [t for t in app._a2l_enriched_tags if isinstance(t.get("address"), int)]
            assert _picker_of(check).set_parameters(rows, key, a2l_data=app.current_a2l_data) is False
            assert _picker_of(patch).set_parameters(rows, key, a2l_data=app.current_a2l_data) is False
            assert len(rebuilds) >= 20, rebuilds
            assert all(0 < count <= 200 for count in rebuilds), rebuilds
            assert describes == [], describes
            assert builds == [], builds
            assert _param_rows(check)["BIG_0000"] == (0x5000, 2, "u16"), _param_rows(check)["BIG_0000"]
            assert _param_rows(patch)["BIG_4199"] == (0x5000 + 4199 * 8, 2, "u16"), _param_rows(patch)["BIG_4199"]
            return None

        _run(base, body)

    elif arm == "adapter-mismatch":
        async def body(app, pilot):
            _mount_views(app)
            await pilot.pause()
            describes.clear()
            builds.clear()
            await _typed_attach(app, pilot, old)
            await settle_workers(pilot)
            first_snapshot = _accepted_snapshots(app)
            assert first_snapshot is not None and set(first_snapshot) == {"check", "patch"}, first_snapshot
            check = _check_panel(app)
            patch = _patch_panel(app)
            # Variant (a): image reload with the attached A2L. I-ALP-3/D-15
            # replacement semantics: L1 REPLACES the accepted mapping with
            # the fresh snapshot of this prepared load (live A2L source +
            # live signature) and the mounted panels consume it with 0 UI
            # describes — no invalidation, no stale definition paints.
            describes.clear()
            builds.clear()
            await _load_image(app, pilot, img2)
            await settle_workers(pilot)
            replaced = _accepted_snapshots(app)
            assert replaced is not None and set(replaced) == {"check", "patch"}, replaced
            assert replaced is not first_snapshot, "the image reload did not replace the accepted mapping"
            fresh = replaced["check"]
            assert fresh.a2l_source is app.current_a2l_data, "the fresh snapshot does not carry the live A2L source"
            assert fresh.signature == app._a2l_enriched_key, (fresh.signature, app._a2l_enriched_key)
            assert len([c for c in builds if c["thread"] != main]) == 1, builds
            assert [c for c in builds if c["thread"] == main] == [], builds
            assert describes == [], describes
            _assert_panel_state(check, OLD_ROWS)
            _assert_panel_state(patch, OLD_ROWS)
            tag = next(t for t in app._a2l_enriched_tags if t["name"] == "OLD_SCALAR")
            assert tag.get("raw_value") == 0x8070, tag
            image_snapshot = replaced
            # Variant (b): project install. D-15: P5 replaces the mapping
            # with the project route's fresh snapshot (live source +
            # signature); the mounted panels consume it with 0 UI describes
            # and the current ARR12 cells (length 6, u16) paint — never a
            # stale 12/u16 definition.
            proj_a2l = _project_a2l(src / "proj.a2l")
            _seed_project(app.workarea, "P_MIX", a2l=proj_a2l, image=img)
            describes.clear()
            builds.clear()
            await _load_project(app, pilot, "P_MIX")
            await settle_workers(pilot)
            replaced = _accepted_snapshots(app)
            assert replaced is not None and set(replaced) == {"check", "patch"}, replaced
            assert replaced is not image_snapshot, "the project install did not replace the accepted mapping"
            fresh = replaced["check"]
            assert fresh.a2l_source is app.current_a2l_data, "the project snapshot does not carry the live A2L source"
            assert fresh.signature == app._a2l_enriched_key, (fresh.signature, app._a2l_enriched_key)
            assert len([c for c in builds if c["thread"] != main]) == 1, builds
            assert [c for c in builds if c["thread"] == main] == [], builds
            assert describes == [], describes
            for panel in (check, patch):
                assert _param_rows(panel)["ARR12"] == (0x2000, 6, "u16"), _param_rows(panel)
            # Matching control: an accepted direct attach repopulates the
            # mapping and the mounted panels consume the worker snapshot.
            describes.clear()
            builds.clear()
            await _typed_attach(app, pilot, new)
            await settle_workers(pilot)
            worker_builds = [c for c in builds if c["thread"] != main]
            ui_builds = [c for c in builds if c["thread"] == main]
            assert len(worker_builds) == 1, builds
            assert len(ui_builds) == 0, builds
            assert describes == [], describes
            repopulated = _accepted_snapshots(app)
            assert repopulated is not None and set(repopulated) == {"check", "patch"}, repopulated
            _assert_panel_state(check, NEW_ROWS)
            _assert_panel_state(patch, NEW_ROWS)
            # Adapter guard coverage (D-15 / ruling R3): the mismatch -> empty
            # -> describe guard is exercised by constructing the mismatch
            # state directly — an accepted mapping whose snapshot source and
            # signature do NOT match the live population. The Check half
            # (unchanged) drives the panel directly; the Patch half drives the
            # app caller ``_prefill_patch_editor`` against the same
            # constructed mismatch. Source mismatch first: the entry signature
            # equals the live key but its source object is not the live parse
            # payload.
            describes.clear()
            snapshot_cls = _picker_snapshot_cls()
            assert snapshot_cls is not None, "A2LPickerSnapshot missing (guarded)"
            rows = [t for t in app._a2l_enriched_tags if isinstance(t.get("address"), int)]
            key = app._a2l_enriched_key
            stale_sig = ("stale-source", 0, 0)
            stale_source_map = MappingProxyType(
                {
                    "check": snapshot_cls(
                        picker="check",
                        signature=stale_sig,
                        a2l_source={"stale": True},
                        definitions=MappingProxyType({}),
                    ),
                    "patch": snapshot_cls(
                        picker="patch",
                        signature=stale_sig,
                        a2l_source={"stale": True},
                        definitions=MappingProxyType({}),
                    ),
                }
            )
            app._accepted_a2l_picker_snapshots = stale_source_map
            check.set_a2l_parameters(rows, stale_sig)
            await pilot.pause()
            invalidated = _accepted_snapshots(app)
            assert invalidated is not None and len(invalidated) == 0, invalidated
            app._accepted_a2l_picker_snapshots = stale_source_map
            app._prefill_patch_editor()
            await pilot.pause()
            invalidated = _accepted_snapshots(app)
            assert invalidated is not None and len(invalidated) == 0, invalidated
            ui_describes = [c for c in describes if c["thread"] == main]
            assert ui_describes, "the existing route describe did not run after the constructed source mismatch"
            assert all(c["names"] == [name for name, *_ in NEW_ROWS] for c in ui_describes), describes
            _assert_panel_state(check, NEW_ROWS)
            _assert_panel_state(patch, NEW_ROWS)
            # Signature mismatch: the entry source IS the live payload but
            # its signature is not the live enrichment key; the mounted
            # adapter invalidates to empty and describes again. The Patch
            # half drives the app caller the same way (ruling R3).
            describes.clear()
            stale_sig2 = ("stale-signature", 0, 0)
            stale_sig_map = MappingProxyType(
                {
                    "check": snapshot_cls(
                        picker="check",
                        signature=stale_sig2,
                        a2l_source=app.current_a2l_data,
                        definitions=MappingProxyType({}),
                    ),
                    "patch": snapshot_cls(
                        picker="patch",
                        signature=stale_sig2,
                        a2l_source=app.current_a2l_data,
                        definitions=MappingProxyType({}),
                    ),
                }
            )
            app._accepted_a2l_picker_snapshots = stale_sig_map
            check.set_a2l_parameters(rows, key)
            await pilot.pause()
            invalidated = _accepted_snapshots(app)
            assert invalidated is not None and len(invalidated) == 0, invalidated
            app._accepted_a2l_picker_snapshots = stale_sig_map
            app._prefill_patch_editor()
            await pilot.pause()
            invalidated = _accepted_snapshots(app)
            assert invalidated is not None and len(invalidated) == 0, invalidated
            ui_describes = [c for c in describes if c["thread"] == main]
            assert ui_describes, "the existing route describe did not run after the constructed signature mismatch"
            assert all(c["names"] == [name for name, *_ in NEW_ROWS] for c in ui_describes), describes
            _assert_panel_state(check, NEW_ROWS)
            _assert_panel_state(patch, NEW_ROWS)
            return None

        _run(base, body)

    else:  # headless-unmounted
        async def body(app, pilot):
            # An accepted mapping exists; the panels stay unmounted first.
            await _typed_attach(app, pilot, old)
            await settle_workers(pilot)
            snapshot_map = _accepted_snapshots(app)
            assert snapshot_map is not None and set(snapshot_map) == {"check", "patch"}, snapshot_map
            identity = snapshot_map
            # Check half (unchanged): the bare Check panel forwards its own
            # unmounted legacy call. Patch half (ruling R3): the app caller
            # keeps the legacy no-data call for a not-yet-mounted panel — it
            # reads no mapping and never invalidates, so the accepted
            # snapshot survives for a later mount. The caller is driven with
            # the app's patch panel forced unmounted, exactly as the bare
            # panel path in tests/test_b103_picker_editor.py:846-870 does.
            describes.clear()
            rows = [t for t in app._a2l_enriched_tags if isinstance(t.get("address"), int)]
            bare_check = CheckEditorPanel()
            check_kwargs: list = []
            real_check_set = bare_check._picker.set_parameters

            def check_set(*args, **kwargs):
                check_kwargs.append(kwargs)
                return real_check_set(*args, **kwargs)

            monkeypatch.setattr(bare_check._picker, "set_parameters", check_set)
            bare_check.set_a2l_parameters(rows, ("legacy", 1))
            patch_panel = _patch_panel(app)
            patch_kwargs: list = []
            real_patch_set = patch_panel._a2l_picker.set_parameters

            def patch_set(*args, **kwargs):
                patch_kwargs.append(kwargs)
                return real_patch_set(*args, **kwargs)

            monkeypatch.setattr(patch_panel._a2l_picker, "set_parameters", patch_set)
            was_mounted = patch_panel._is_mounted
            patch_panel._is_mounted = False
            try:
                app._prefill_patch_editor()
            finally:
                patch_panel._is_mounted = was_mounted
            for kwargs, kind in ((check_kwargs, "check"), (patch_kwargs, "patch")):
                assert len(kwargs) == 1, (kind, kwargs)
                assert kwargs[0].get("a2l_data") is None, (kind, kwargs)
                assert "prepared_definitions" not in kwargs[0], (kind, kwargs)
                assert "describe_context" not in kwargs[0], (kind, kwargs)
            assert describes == [], describes
            assert _accepted_snapshots(app) is identity, "an unmounted call invalidated the accepted mapping"
            # Mount both against the same matching generation: each panel
            # consumes its own surviving worker map with 0 UI describes.
            _mount_views(app)
            await pilot.pause()
            key = app._a2l_enriched_key
            check = _check_panel(app)
            patch = _patch_panel(app)
            check.set_a2l_parameters(rows, key)
            app._prefill_patch_editor()
            await pilot.pause()
            assert describes == [], describes
            _assert_panel_state(check, OLD_ROWS)
            _assert_panel_state(patch, OLD_ROWS)
            return None

        _run(base, body)


# ===========================================================================
# R-A2L-REFRESH.038 — preparation failure preserves state (3/3).
# ===========================================================================


@pytest.mark.parametrize("arm", ["enrichment", "summary", "context"], ids=lambda x: x)
def test_r038_preparation_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: str) -> None:
    """R-A2L-REFRESH.038/1-/3: an injected exception in one real preparation
    stage (enrichment, summary, describe-context build) ends with the exact
    existing failure outcome, keeps the current image and every A2L-dependent
    state/view, still refreshes Workarea Files (copy=True), runs no
    install/refresh/sync/success, no describe or context build on the UI
    thread, and leaves the collector enabled."""
    _guard_attach_snapshot_seams()

    base = tmp_path / "app"
    src = tmp_path / "src"
    src.mkdir(parents=True)
    old = _old_a2l(src / "old.a2l")
    new = _new_a2l(src / "new.a2l")
    img = _write_image(src / "img1.s19", dict(IMG1))
    mac = _write_mac(src / "records.mac")

    fl = _fl_module()
    service = _service_module()
    definition = _definition_module()
    picker = _picker_module()
    main = threading.get_ident()
    fired: list = []
    armed: dict = {"on": False}
    timeline: list = []
    ui_calls: list = []

    if arm == "enrichment":
        real_enrich = getattr(fl, "enrich_tags_and_render", None)

        def boom(*args, **kwargs):
            if armed["on"] and threading.get_ident() != main and not fired:
                fired.append(True)
                raise ValueError("enrichment boom")
            return real_enrich(*args, **kwargs) if real_enrich is not None else None

        monkeypatch.setattr(fl, "enrich_tags_and_render", boom, raising=False)
        monkeypatch.setattr(service, "enrich_tags_and_render", boom, raising=False)
    elif arm == "summary":
        real_enrich = getattr(fl, "enrich_tags_and_render", None)

        def enrich_ok(*args, **kwargs):
            if armed["on"] and threading.get_ident() != main:
                timeline.append("enrichment")
            return real_enrich(*args, **kwargs) if real_enrich is not None else None

        monkeypatch.setattr(fl, "enrich_tags_and_render", enrich_ok, raising=False)
        real_render = getattr(service, "render_a2l_view", None)

        def render_boom(*args, **kwargs):
            if armed["on"] and threading.get_ident() != main:
                timeline.append("summary")
                if not fired:
                    fired.append(True)
                    raise ValueError("summary boom")
            return real_render(*args, **kwargs) if real_render is not None else None

        monkeypatch.setattr(service, "render_a2l_view", render_boom)
    else:  # context
        real_build = definition.build_describe_context
        real_describe = definition.describe_definitions

        def build_boom(a2l_data, names):
            if armed["on"] and threading.get_ident() != main:
                timeline.append("context")
                if not fired:
                    fired.append(True)
                    raise ValueError("context boom")
            elif armed["on"]:
                ui_calls.append("context")
            return real_build(a2l_data, names)

        def describe_spy(names, a2l_data):
            if armed["on"] and threading.get_ident() == main:
                ui_calls.append("describe")
            return real_describe(names, a2l_data)

        monkeypatch.setattr(definition, "build_describe_context", build_boom)
        monkeypatch.setattr(fl, "build_describe_context", build_boom, raising=False)
        monkeypatch.setattr(definition, "describe_definitions", describe_spy)
        monkeypatch.setattr(picker, "describe_definitions", describe_spy, raising=False)
        monkeypatch.setattr(fl, "describe_definitions", describe_spy, raising=False)

    async def body(app, pilot):
        _mount_views(app)
        await pilot.pause()
        await _load_image(app, pilot, img)
        await _load_image(app, pilot, mac)
        await _typed_attach(app, pilot, old)
        before = _state_snapshot(app)
        zero = _arm_zero_call_spies(app, monkeypatch)
        outcomes: list = []

        real_end = app.end_busy

        def end(key, gen, outcome):
            outcomes.append((key, str(outcome)))
            return real_end(key, gen, outcome)

        monkeypatch.setattr(app, "end_busy", end)
        armed["on"] = True
        await _submit_typed(app, pilot, str(new))
        await settle_workers(pilot)
        await wait_until(pilot, lambda: outcomes, "the preparation-failure outcome", timeout=30.0)
        expected = FAILURE_OUTCOME.format(name="new.a2l")
        assert len(outcomes) == 1 and outcomes[0][1] == expected, outcomes
        assert expected in _log_lines(app), _log_lines(app)
        assert len(fired) == 1, fired
        after = _state_snapshot(app)
        assert after == before, f"previous state changed: {before} -> {after}"
        assert len(zero["files"].calls) >= 1, zero["files"].calls
        assert len(zero["install"].calls) == 0, zero["install"].calls
        assert len(zero["fanout"].calls) == 0, zero["fanout"].calls
        assert len(zero["sync"].calls) == 0, zero["sync"].calls
        assert len(zero["cache"].calls) == 0, zero["cache"].calls
        assert len(zero["recent"].calls) == 0, zero["recent"].calls
        # No "A2L loaded" line is asserted here: the previous OLD attach's
        # success line legitimately stays in the 4-line window. The exact
        # failure outcome (above) plus the preserved state is the .038
        # contract — a success line can only come from the OLD attach.
        if arm == "summary":
            assert timeline.count("enrichment") == 1 and timeline.count("summary") == 1, timeline
        if arm == "context":
            assert timeline == ["context"], timeline
            assert ui_calls == [], ui_calls
            assert gc.isenabled(), "the collector stayed disabled after the failed preparation"
        return None

    _run(base, body)


@pytest.mark.parametrize("size", ["small", "large"])
def test_r038_install_exception_reenables_gc(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, size: str
) -> None:
    """R-A2L-REFRESH.051 (E4R) — attach install-exception arm (reviewer
    MAJOR E5-INC2-F3): an injected exception in the last attach-install step
    ends through the failure route AND leaves the cycle collector enabled,
    which the attach producer deliberately disabled for the worker window.
    I1f (R-A2L-REFRESH.071/.073, E4-1): the producer holds it for every
    size, so both the small and the large (exactly 1 MiB) arm see it
    disabled at the injected exception and both end enabled. Every
    observation is recorded inside the route and asserted after Textual's
    exception re-raise, so the assertion cannot be masked by the re-raised
    install exception."""
    import gc

    from tests.test_p279_i1f_gc import MIB, write_a2l_of_size

    _guard_attach_snapshot_seams()

    base = tmp_path / "app"
    src = tmp_path / "src"
    src.mkdir(parents=True)
    old = _old_a2l(src / "old.a2l")
    if size == "large":
        new = write_a2l_of_size(src / "new.a2l", MIB)
    else:
        new = _new_a2l(src / "new.a2l")
    img = _write_image(src / "img1.s19", dict(IMG1))

    armed: dict = {"on": False}
    raised: list = []
    outcomes: list = []
    gc_at_boom: list = []
    gc_at_end: list = []

    async def body(app, pilot):
        _mount_views(app)
        await pilot.pause()
        await _load_image(app, pilot, img)
        await _typed_attach(app, pilot, old)

        real_refresh = app._refresh_a2l_dependent_views

        def refresh_boom():
            if armed["on"]:
                raised.append(True)
                gc_at_boom.append(gc.isenabled())
                raise ValueError("install boom")
            return real_refresh()

        monkeypatch.setattr(app, "_refresh_a2l_dependent_views", refresh_boom)
        real_end = app.end_busy

        def end(key, gen, outcome):
            outcomes.append(key)
            return real_end(key, gen, outcome)

        monkeypatch.setattr(app, "end_busy", end)
        armed["on"] = True
        await _typed_attach(app, pilot, new)
        await settle_workers(pilot)
        await wait_until(
            pilot, lambda: bool(raised), "the install exception", timeout=30.0
        )
        await pilot.pause()
        await pilot.pause()
        gc_at_end.append(gc.isenabled())
        return None

    with pytest.raises(Exception, match="install boom"):
        _run(base, body)
    assert raised, "the install exception never fired"
    assert gc_at_boom == [False], (
        "the producer left the cycle collector disabled for the install "
        f"window ({size} load): {gc_at_boom}"
    )
    assert gc_at_end == [True], (
        "R-A2L-REFRESH.051: the cycle collector stayed disabled after the "
        f"install exception: {gc_at_end}"
    )
    assert "a2l_load" in outcomes, outcomes


# ===========================================================================
# R-A2L-REFRESH.051 — every attach/image/project outcome leaves GC enabled.
# ===========================================================================


@pytest.mark.parametrize(
    "arm",
    ["success", "failure", "superseded"],
    ids=[f"R-A2L-REFRESH.051/{i}" for i in range(1, 4)],
)
def test_r_a2l_refresh_051_attach_outcomes_gc_enabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: str
) -> None:
    """R-A2L-REFRESH.051/1-/3 (E4R): after a direct A2L attach ends with
    success, failure or superseded, the cycle collector is enabled. The
    observation is recorded inside the route and asserted after it ends."""
    import gc

    _guard_attach_snapshot_seams()

    base = tmp_path / "app"
    src = tmp_path / "src"
    src.mkdir(parents=True)
    old = _old_a2l(src / "old.a2l")
    new = _new_a2l(src / "new.a2l")
    img = _write_image(src / "img1.s19", dict(IMG1))

    outcomes: list = []
    fired: list = []
    armed: dict = {"on": False}
    gc_at_end: list = []
    mutations: list = []

    if arm == "failure":
        fl = _fl_module()
        service = _service_module()
        main = threading.get_ident()
        real_enrich = getattr(fl, "enrich_tags_and_render", None)

        def boom(*args, **kwargs):
            if armed["on"] and threading.get_ident() != main and not fired:
                fired.append(True)
                raise ValueError("enrichment boom")
            return real_enrich(*args, **kwargs) if real_enrich is not None else None

        monkeypatch.setattr(fl, "enrich_tags_and_render", boom, raising=False)
        monkeypatch.setattr(service, "enrich_tags_and_render", boom, raising=False)

    if arm == "superseded":
        real_install = S19TuiApp._install_attached_a2l

        def install_spy(self, result):
            preparation = getattr(result, "preparation", None)
            if preparation is None or Path(result.request.source).name != "new.a2l":
                return real_install(self, result)
            new_preparation = dataclasses.replace(
                preparation,
                expected_a2l_generation=preparation.expected_a2l_generation - 1,
            )
            mutated = dataclasses.replace(result, preparation=new_preparation)
            mutations.append(("mutated", threading.get_ident()))
            return real_install(self, mutated)

        monkeypatch.setattr(S19TuiApp, "_install_attached_a2l", install_spy)

    async def body(app, pilot):
        _mount_views(app)
        await pilot.pause()
        real_end = app.end_busy

        def end(key, gen, outcome):
            outcomes.append((key, str(outcome)))
            return real_end(key, gen, outcome)

        monkeypatch.setattr(app, "end_busy", end)
        if arm == "success":
            await _typed_attach(app, pilot, new)
            await settle_workers(pilot)
        elif arm == "failure":
            armed["on"] = True
            await _submit_typed(app, pilot, str(new))
            await settle_workers(pilot)
            await wait_until(
                pilot, lambda: bool(outcomes), "the attach-failure outcome", timeout=30.0
            )
        else:  # superseded
            await _load_image(app, pilot, img)
            await _typed_attach(app, pilot, old)
            await _submit_typed(app, pilot, str(new))
            await settle_workers(pilot)
            await wait_until(
                pilot, lambda: bool(outcomes), "the superseded outcome", timeout=30.0
            )
        gc_at_end.append(gc.isenabled())
        return None

    _run(base, body)
    assert gc_at_end == [True], (
        f"R-A2L-REFRESH.051: gc disabled after the {arm} attach outcome: "
        f"{gc_at_end}"
    )
    if arm == "failure":
        assert len(fired) == 1, fired
        expected = FAILURE_OUTCOME.format(name="new.a2l")
        assert outcomes == [("a2l_load", expected)], outcomes
    elif arm == "superseded":
        assert len(mutations) == 1, mutations
        assert outcomes and outcomes[-1] == ("a2l_load", SUPERSEDED_OUTCOME), outcomes
    else:  # success
        assert outcomes and outcomes[-1][1].startswith("A2L loaded"), outcomes


@pytest.mark.parametrize("size", ["small", "large"])
def test_r_a2l_refresh_052_install_runs_no_full_collection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, size: str
) -> None:
    """R-A2L-REFRESH.052/.054 (E4R, operator D-GC = A) — attach install
    arm: an attach install runs at most one full gc.collect() from a product
    module and every collection is logged one-to-one. I1f: the small arm (a
    generated ~0.2 MB A2L) runs none (R-A2L-REFRESH.072); the large arm (a
    generated A2L of exactly 1 MiB) makes that single collection, and the
    ``s19tui`` logger logs it with the ``attach`` route and its duration in
    seconds (.054 logs only a completed collection)."""
    import gc
    import sys

    from tests.test_p279_i1f_gc import MIB, write_a2l_of_size

    _guard_attach_snapshot_seams()

    base = tmp_path / "app"
    src = tmp_path / "src"
    src.mkdir(parents=True)
    if size == "large":
        a2l = write_a2l_of_size(src / "large.a2l", MIB)
    else:
        a2l = _mid_a2l(src, count=2000)

    real_collect = gc.collect
    product_collects: list = []

    def collect_spy(*args, **kwargs):
        caller = sys._getframe(1).f_globals.get("__name__")
        if caller in {
            "s19_app.tui.app.file_load",
            "s19_app.tui.app.loaded_state",
            "s19_app.tui.app.project_load",
        }:
            product_collects.append((caller, threading.get_ident()))
        return real_collect(*args, **kwargs)

    monkeypatch.setattr(gc, "collect", collect_spy)

    outcomes: list = []
    gc_log_lines: list = []

    async def body(app, pilot):
        _mount_views(app)
        await pilot.pause()
        real_end = app.end_busy

        def end(key, gen, outcome):
            outcomes.append((key, str(outcome)))
            return real_end(key, gen, outcome)

        real_info = app.logger.info

        def info_spy(msg, *args, **kwargs):
            if isinstance(msg, str) and msg.startswith("A2L load GC:"):
                gc_log_lines.append((msg, args))
            return real_info(msg, *args, **kwargs)

        monkeypatch.setattr(app.logger, "info", info_spy)
        monkeypatch.setattr(app, "end_busy", end)
        await _typed_attach(app, pilot, a2l)
        await settle_workers(pilot)
        await wait_until(
            pilot, lambda: bool(outcomes), "the attach outcome", timeout=60.0
        )
        return None

    _run(base, body)
    assert outcomes and outcomes[-1][0] == "a2l_load", outcomes
    assert len(product_collects) <= 1, (
        "R-A2L-REFRESH.052: the attach install ran more than one full "
        f"gc.collect() from a product module: {product_collects}"
    )
    assert len(product_collects) == len(gc_log_lines), (
        "R-A2L-REFRESH.052/.054: the attach install's full collections are "
        "not one-to-one with the logged GC lines: "
        f"collects={product_collects} logs={gc_log_lines}"
    )
    if size == "large":
        assert len(gc_log_lines) == 1 and all(
            args and args[0] == "attach" for _msg, args in gc_log_lines
        ), (
            "R-A2L-REFRESH.054: the attach install's GC log line does not carry "
            f"the attach route: {gc_log_lines}"
        )


@pytest.mark.parametrize("size", ["small", "large"])
def test_r_a2l_refresh_053_reloads_do_not_accumulate_objects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, size: str
) -> None:
    """R-A2L-REFRESH.053 (E4R): attach the same generated A2L five times
    through the product route; after each outcome run gc.collect() and
    record len(gc.get_objects()) + gc.get_freeze_count(); loads 3-5 keep at
    most 1.10 x load 2. I1f: the small arm (mid-size, held during
    preparation and no install collection, R-A2L-REFRESH.072) and the large
    arm (exactly 1 MiB, D-13 hold and collection) keep the same bound."""

    import gc

    from tests.test_p279_i1f_gc import MIB, write_a2l_of_size

    _guard_attach_snapshot_seams()

    base = tmp_path / "app"
    src = tmp_path / "src"
    src.mkdir(parents=True)
    if size == "large":
        a2l = write_a2l_of_size(src / "large.a2l", MIB)
    else:
        a2l = _mid_a2l(src, count=2000)
    counts: list = []

    async def body(app, pilot):
        _mount_views(app)
        await pilot.pause()
        for _ in range(5):
            await _typed_attach(app, pilot, a2l)
            await settle_workers(pilot)
            gc.collect()
            counts.append(len(gc.get_objects()) + gc.get_freeze_count())
        return None

    _run(base, body)
    assert len(counts) == 5, counts
    load2 = counts[1]
    for i in (2, 3, 4):
        assert counts[i] <= 1.10 * load2, (
            f"R-A2L-REFRESH.053: load {i + 1} retained {counts[i]} objects "
            f"> 1.10 x load 2 ({load2}); counts={counts}"
        )


# ===========================================================================
# AT-ALP-I2-1 — the three direct-attach routes publish snapshots end to end.
# ===========================================================================


def _assert_full_views(app: S19TuiApp, rows, a2l_name: str, image: bool, *, mac: bool) -> None:
    _assert_panel_state(_check_panel(app), rows)
    _assert_panel_state(_patch_panel(app), rows)
    assert _a2l_viewer_names(app) == [name for name, *_ in rows]
    memory = app.query_one("#memory_map_panel", MemoryMapPanel)
    if image:
        assert memory.rendered_text != memory._EMPTY_TEXT
        # House pattern (tests/test_b103_a2l_refresh.py): the visible memory
        # surface is rendered_text + the region rows + the detail body. The
        # band-summary header never carries A2L names (security B3); the
        # A2L tags reach the panel through the tag receipt instead.
        parts = [memory.rendered_text]
        parts.extend(_plain(row.render()) for row in memory.query(".map-region-row"))
        if len(memory.query("#map_detail_body")) > 0:
            parts.append(_plain(memory.query_one("#map_detail_body", Static).render()))
        visible_text = "\n".join(parts)
        assert visible_text.strip(), "the visible memory surface is empty"
        assert [t["name"] for t in memory._a2l_tags] == [name for name, *_ in rows], (
            [t["name"] for t in memory._a2l_tags],
        )
    split = app.query_one("#screen_split_join", SplitJoinWindow)
    assert [(r.name, r.base, r.size) for r in split._a2l_rows_cache] == [
        (name, address, size) for name, address, size, _fmt in rows
    ]
    loaded = _loaded_text(app)
    assert loaded[2] == f"{a2l_name}  {len(rows)} tags", loaded
    assert isinstance(app._validation_issues, list), "no Issues state"
    if mac:
        assert app.current_file is not None and app.current_file.mac_records, "no MAC state"
    else:
        assert app.current_file is None, "an image/MAC file appeared on the A2L-only start-up route"


def test_at_alp_i2_1_direct_attach_routes_publish_snapshots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """AT-ALP-I2-1: typed, Workarea Files and start-up attaches each finish
    with current viewer, Check, Patch, Memory Map, Split/Join, Loaded, MAC
    and Issues state, with the common refresh before each outcome.
    Rows: R-A2L-REFRESH.031 (each route installs the parsed A2L and its
    snapshots before the common refresh starts) and R-A2L-REFRESH.035
    (exactly one common refresh between the install and the outcome; the
    thread is recorded, not asserted)."""
    _guard_attach_snapshot_seams()

    base = tmp_path / "app"
    src = tmp_path / "src"
    src.mkdir(parents=True)
    old = _old_a2l(src / "old.a2l")
    new = _new_a2l(src / "new.a2l")
    img = _write_image(src / "img1.s19", dict(IMG1))
    mac = _write_mac(src / "records.mac")
    workarea_temp = base / WORKAREA_DIRNAME / WORKAREA_SUBDIR / WORKAREA_TEMP
    workarea_temp.mkdir(parents=True, exist_ok=True)
    (workarea_temp / "new.a2l").write_bytes(new.read_bytes())

    async def body(app, pilot):
        _mount_views(app)
        await pilot.pause()
        await _load_image(app, pilot, img)
        await _load_image(app, pilot, mac)
        events: list = []
        _arm_install_fanout_outcome(app, monkeypatch, events)
        await _typed_attach(app, pilot, old)
        await settle_workers(pilot)
        kind = [e[0] for e in events if e[0] in {"install", "refresh", "outcome"}]
        assert kind == ["install", "refresh", "outcome"], events
        snapshot_map = _accepted_snapshots(app)
        assert snapshot_map is not None and set(snapshot_map) == {"check", "patch"}, snapshot_map
        _assert_full_views(app, OLD_ROWS, "old.a2l", image=True, mac=True)
        events.clear()
        _arm_install_fanout_outcome(app, monkeypatch, events)
        await _workarea_attach(app, pilot, "new.a2l")
        await settle_workers(pilot)
        kind = [e[0] for e in events if e[0] in {"install", "refresh", "outcome"}]
        assert kind == ["install", "refresh", "outcome"], events
        snapshot_map = _accepted_snapshots(app)
        assert snapshot_map is not None and set(snapshot_map) == {"check", "patch"}, snapshot_map
        _assert_full_views(app, NEW_ROWS, "new.a2l", image=True, mac=True)
        return None

    _run(base, body)

    # The start-up route: a fresh app with load_path=OLD. The attach begins
    # during app start, so the timeline spies are armed at class level
    # before the app exists (the .029 start-up pattern).
    startup_events: list = []
    real_install = S19TuiApp._install_attached_a2l
    real_fanout = S19TuiApp._refresh_a2l_dependent_views
    real_end = S19TuiApp.end_busy

    def install(self, result):
        startup_events.append(("install", threading.get_ident()))
        return real_install(self, result)

    def fanout(self):
        startup_events.append(("refresh", threading.get_ident()))
        return real_fanout(self)

    def end(self, key, gen, outcome):
        startup_events.append(("outcome", threading.get_ident(), str(outcome)))
        return real_end(self, key, gen, outcome)

    monkeypatch.setattr(S19TuiApp, "_install_attached_a2l", install, raising=False)
    monkeypatch.setattr(S19TuiApp, "_refresh_a2l_dependent_views", fanout, raising=False)
    monkeypatch.setattr(S19TuiApp, "end_busy", end)

    async def startup_body(app, pilot):
        _mount_views(app)
        await pilot.pause()
        await wait_until(
            pilot,
            lambda: app.current_a2l_path is not None
            and Path(app.current_a2l_path).name == "old.a2l"
            and "a2l_load" not in app._busy.runs,
            "the start-up attach of old.a2l",
        )
        await settle_workers(pilot)
        kind = [e[0] for e in startup_events if e[0] in {"install", "refresh", "outcome"}]
        assert kind == ["install", "refresh", "outcome"], startup_events
        snapshot_map = _accepted_snapshots(app)
        assert snapshot_map is not None and set(snapshot_map) == {"check", "patch"}, snapshot_map
        _assert_full_views(app, OLD_ROWS, "old.a2l", image=False, mac=False)
        return None

    _run(base, startup_body, load_path=src / "old.a2l", base_dir=base)


# ===========================================================================
# AT-ALP-I2-2 — the real case_06 attach stays key-responsive and progressive.
# ===========================================================================


@pytest.mark.serial_timing
@pytest.mark.slow
def test_at_alp_i2_2_case06_keys_and_progress(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """AT-ALP-I2-2: the real case_06 direct attach keeps every key
    (R-A2L-REFRESH.033) and every visible progress gap within 1.0 s from
    request through post-parse preparation and installation; the
    preserved-refresh gap is recorded unasserted (D-12); the terminal
    outcome follows."""
    _guard_attach_snapshot_seams()

    base = tmp_path / "app"
    bound = timing_bound(1.0)
    latencies: list = []

    async def body(app, pilot):
        app.set_focus(app.query_one("#files_list"))
        await pilot.pause()
        sampler = Sampler()
        task = sampler.start(pilot, app, bar=True)
        await pilot.pause(0.1)
        # D-12: the sampling window ends when post-parse preparation and
        # installation complete, i.e. when the preserved common refresh
        # begins; the preserved-refresh gap is recorded unasserted.
        refresh_entry: list = []
        real_refresh = app._refresh_a2l_dependent_views

        def refresh_spy():
            refresh_entry.append(time.monotonic())
            return real_refresh()

        monkeypatch.setattr(app, "_refresh_a2l_dependent_views", refresh_spy)
        deadline = time.monotonic() + 300
        app.load_a2l_from_path(CASE06)
        phase_keys = await _focus_key_pair(pilot, app, bound=bound)
        latencies.extend(phase_keys)
        while True:
            if (
                app.current_a2l_path is not None
                and Path(app.current_a2l_path).name == "firmware.a2l"
                and "a2l_load" not in app._busy.runs
            ):
                break
            if time.monotonic() > deadline:
                raise AssertionError("the case_06 attach never reached its terminal outcome")
            await pilot.pause(0.05)
        sampler.stop.set()
        await task
        changes = sampler.text_changes()
        times = [t for t, _ in changes]
        gaps = [b - a for a, b in zip(times, times[1:])]
        # D-12: every gap inside the commissioned window (before the
        # preserved common refresh starts) is <= 1.0 s; the preserved-refresh
        # gap is recorded unasserted (the refresh is a held step, CTX-BUSY).
        assert refresh_entry, "the preserved common refresh never started"
        t0_abs = sampler.frames[0][0]
        refresh_rel = refresh_entry[0] - t0_abs
        window_gaps = [gap for (a, b), gap in zip(zip(times, times[1:]), gaps) if b <= refresh_rel]
        assert window_gaps, (times, refresh_rel)
        assert all(gap <= 1.0 for gap in window_gaps), window_gaps
        assert any(_is_busy_progress(text, name="firmware.a2l") for _, text in changes), changes
        assert any("A2L loaded" in line for line in _log_lines(app)), _log_lines(app)
        assert Path(app.current_a2l_path).name == "firmware.a2l"
        assert app._a2l_enriched_tags, "no enriched tags at the outcome"
        snapshot_map = _accepted_snapshots(app)
        assert snapshot_map is not None and set(snapshot_map) == {"check", "patch"}, snapshot_map
        return None

    _run(base, body)
    assert len(latencies) == 2, latencies
    assert all(lat <= bound for lat in latencies), latencies


# ===========================================================================
# AT-ALP-I2-3 — same-path replacement describes once (shared) per generation.
# ===========================================================================


def test_at_alp_i2_3_same_path_picker_generations(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """AT-ALP-I2-3: the real same-path OLD->NEW replacement builds one shared
    read-only describe context per generation, paints the exact NEW formats
    before success and runs 0 builds and 0 bulk describes during later
    filter/page/no-op actions.
    Row: R-A2L-REFRESH.037 (one worker-built context per generation, used by
    both mounted pickers; 0 describes on later filter/page/no-op requests)."""
    _guard_attach_snapshot_seams()

    base = tmp_path / "app"
    src = tmp_path / "src"
    src.mkdir(parents=True)
    same = src / "same.a2l"
    _old_a2l(same)
    new_text = _new_a2l(src / "new.a2l").read_text(encoding="utf-8")
    describes = _describe_spies(monkeypatch)
    builds = _build_spies(monkeypatch)
    main = threading.get_ident()

    async def body(app, pilot):
        _mount_views(app)
        await pilot.pause()
        describes.clear()
        builds.clear()
        await _typed_attach(app, pilot, same)
        await settle_workers(pilot)
        first_round = [c for c in builds if c["thread"] != main]
        assert len(first_round) == 1, builds
        assert [c for c in builds if c["thread"] == main] == [], builds
        check = _check_panel(app)
        patch = _patch_panel(app)
        _assert_panel_state(check, OLD_ROWS)
        _assert_panel_state(patch, OLD_ROWS)
        describes.clear()
        builds.clear()
        same.write_text(new_text, encoding="utf-8")
        formats_at_outcome: dict = {}

        real_end = app.end_busy

        def end(key, gen, outcome):
            if key == "a2l_load" and "A2L loaded" in str(outcome):
                formats_at_outcome["check"] = _param_rows(check)["ARR12"]
                formats_at_outcome["patch"] = _param_rows(patch)["ARR12"]
            return real_end(key, gen, outcome)

        monkeypatch.setattr(app, "end_busy", end)
        await _typed_attach(app, pilot, same)
        await settle_workers(pilot)
        second_round = [c for c in builds if c["thread"] != main]
        assert len(second_round) == 1, builds
        assert [c for c in builds if c["thread"] == main] == [], builds
        assert all(c["names"] == [name for name, *_ in NEW_ROWS] for c in second_round), builds
        assert formats_at_outcome == {
            "check": (0x2000, 8, "f32"),
            "patch": (0x2000, 8, "f32"),
        }, formats_at_outcome
        _assert_panel_state(check, NEW_ROWS)
        _assert_panel_state(patch, NEW_ROWS)
        # Zero describes and builds during subsequent filter/page/no-op actions.
        describes.clear()
        builds.clear()
        picker_module = _picker_module()
        real_rebuild = picker_module.A2LParameterPicker._rebuild_ledger

        def counting_rebuild(self):
            return real_rebuild(self)

        monkeypatch.setattr(picker_module.A2LParameterPicker, "_rebuild_ledger", counting_rebuild)
        for index in range(10):
            check.query_one("#check_param_filter", Input).value = "ARR" if index % 2 == 0 else ""
            await pilot.pause(0.2)
            check.query_one("#check_param_page_next_button", Button).press()
            await pilot.pause(0.2)
        key = app._a2l_enriched_key
        rows = [t for t in app._a2l_enriched_tags if isinstance(t.get("address"), int)]
        assert _picker_of(check).set_parameters(rows, key, a2l_data=app.current_a2l_data) is False
        assert _picker_of(patch).set_parameters(rows, key, a2l_data=app.current_a2l_data) is False
        assert describes == [], describes
        assert builds == [], builds
        return None

    _run(base, body)


# ===========================================================================
# R-A2L-REFRESH.049 — the attach worker is admitted with a fixed
# description, so Textual never renders the request on the UI thread.
# ===========================================================================


def test_r_a2l_refresh_049_attach_worker_never_reprs_its_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R-A2L-REFRESH.049 (E4R): the A2L attach worker is admitted on the UI
    thread right after the request snapshot is captured; its fixed
    ``description=`` keeps Textual from calling ``repr()`` on the request
    (which carries the parsed A2L) at admission. ``__repr__`` of the three
    request classes is replaced with a counting recorder and must stay
    untouched through the attach's success outcome."""
    _guard_attach_snapshot_seams()

    fl = _fl_module()
    pl = importlib.import_module("s19_app.tui.app.project_load")
    request_classes = [
        getattr(fl, "FileLoadRequest"),
        getattr(fl, "A2LAttachRequest"),
        getattr(pl, "ProjectLoadRequest"),
    ]
    rendered: list = []

    def counting_repr(self) -> str:
        rendered.append(type(self).__name__)
        return "<request>"

    for cls in request_classes:
        monkeypatch.setattr(cls, "__repr__", counting_repr)

    base = tmp_path / "app"
    src = tmp_path / "src"
    src.mkdir(parents=True)
    old = _old_a2l(src / "old.a2l")

    async def body(app, pilot):
        _mount_views(app)
        await pilot.pause()
        rendered.clear()
        await _typed_attach(app, pilot, old)
        await settle_workers(pilot)
        return None

    _run(base, body)
    assert rendered == [], (
        f"R-A2L-REFRESH.049: the attach worker admission rendered its "
        f"request: {rendered}"
    )
