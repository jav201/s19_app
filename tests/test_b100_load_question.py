"""Batch-100 increment 10 — one short question before unsaved work is lost
(HLR-174, HLR-174a … HLR-174d).

Written by the independent tester (E4) from the approved design only:
``inc-10/E1-requirements-draft.md`` (thresholds and negative controls),
``inc-10/E1-scope.md`` and ``E2-rulings.md`` (test notes and census), the
fixed interfaces of ``inc-10/codewire/interfaces-10.md``, every example line
of ``codewire/proto-10-dialog.md`` (Q… / P… / C1-…) and
``codewire/proto-10-app.md`` (C01 …), and the rulings ``E1-rulings.md``,
``E2-rulings.md`` and ``E3-rulings.md`` (the round-2 rows marked T bind
these tests: S10-06, A10-R2-3). No line of the Inc 10 implementation was
read.

Covers:
  - TC-B100-44 — LLR-174.1, .1a, .1b, .1c (when the guard asks; the public
    reader of the Patch Editor flag).
  - TC-B100-45 — LLR-174.2, .2a … .2t (the modal, its focus, keys, clicks,
    painted text, layout, a second answer, the change-file dropdown).
  - TC-B100-46 — LLR-174.3, .3a … .3d (the reset after the answer; a refused
    project load keeps the work; a cancelled variant switch keeps the
    pending selection).
  - TC-B100-72 — LLR-174.4, .4a, .4b, .4c (one seam, every route, one
    question per request, the load kind of each route).
  - Inc 10 arms of TC-B100-12 (LLR-166.1), TC-B100-70 (LLR-167.8) and
    TC-B100-66 (LLR-173.7).
  - AT-B100-15 — HLR-174 … HLR-174d, black-box through keys and widget ids.

Base: every Inc 10 symbol (``ConfirmQuestionScreen``,
``PatchEditorPanel.is_dirty``, ``_load_would_lose``, ``_confirm_then_load``)
is imported or read inside its test, so the file collects on the base
revision and each test fails there on its own: the load question never
appears (a timed-out wait), an assertion on the session, or the
``ImportError`` / ``AttributeError`` of a symbol the design adds.

A test whose main arms are "0 questions" also carries a live-guard control
(one request that must ask in the same session): a 0-question assertion
proves nothing about a guard that does not exist.

Oracles are observable: the screen stack, the focused widget id, the painted
text of ``#confirm_title`` / ``#confirm_body`` / the two buttons, the
session (current file, image bytes, project, A2L, MAC), the Patch Editor
entry count and flag, the Flow Builder blocks and flag, the recent store
bytes and the status log.
"""
from __future__ import annotations

import ast
import asyncio
import hashlib
import os
import re
import shutil
import sys
import types
from pathlib import Path

import pytest
from textual import events

import s19_app.tui.app as app_module
from s19_app.tui.workspace import WORKAREA_DIRNAME, WORKAREA_SUBDIR, WORKAREA_TEMP

from tests.support import b100_load_dialog as ld
from tests.support import b100_save_dialog as sd
from tests.support import b100_projects as projects

ROOT = Path(__file__).resolve().parents[1]
CASE01 = ROOT / "examples" / "case_01_basic_valid"
CASE02 = ROOT / "examples" / "case_02_gaps_and_patch_targets"
WIN = sys.platform == "win32"
SIZE = (118, 54)
PATCH_ADDRESS = 0x8000007C

DECISION_ID = re.compile(r"\bD\d+\b|\bO-\d+|VS-|LLR-|HLR-")
LONG120 = "n" * 119 + "…"
#: The 1-item load question as the composer builds it (interfaces Q-3).
LOADQ = (
    "Replace fw.s19?",
    "There are unsaved changes in fw.s19. Load b.s19 anyway?",
    "Replace (y)",
    "Cancel (n)",
)
#: LLR-174.2a's quit arm (Inc 12 reuses the modal).
QUITQ = ("Quit?", "A save is running.", "Quit (y)", "Stay (n)")
HOSTILE = ("[b]Quit?", "A save is [red]running[/red].", "[b]Quit (y)", "Stay (n)")
#: The 3-item, longest-name question (LLR-174.2r).
LONGQ = (
    "Replace " + LONG120 + "?",
    "There are unsaved changes in "
    + LONG120
    + ", Patch Editor entries and flow "
    + LONG120
    + ". Load project "
    + LONG120
    + " anyway?",
    "Replace (y)",
    "Cancel (n)",
)

WINDOWS_ONLY = pytest.mark.skipif(
    not WIN, reason="an exclusively held file is a Windows-only arm (reported not run elsewhere)"
)


# ---------------------------------------------------------------------------
# the new symbols, read lazily (the file collects on the base revision)
# ---------------------------------------------------------------------------


def _question_cls():
    """``s19_app.tui.screens.ConfirmQuestionScreen``, or None before Inc 10."""
    try:
        from s19_app.tui.screens import ConfirmQuestionScreen
    except ImportError:
        return None
    return ConfirmQuestionScreen


def _new_question(*args):
    """Build the question modal (ImportError on the base: the class is new)."""
    from s19_app.tui.screens import ConfirmQuestionScreen

    return ConfirmQuestionScreen(*args)


def is_question(screen) -> bool:
    cls = _question_cls()
    return cls is not None and isinstance(screen, cls)


def LC(kind: str, value: str):
    return ld.load_choice_cls()(kind, value)


# ---------------------------------------------------------------------------
# fixtures (synthetic: the shipped example images only)
# ---------------------------------------------------------------------------


def _wa(base: Path) -> Path:
    return base / WORKAREA_DIRNAME / WORKAREA_SUBDIR


def _hex_bytes() -> bytes:
    """A small, valid Intel HEX image (two data records and EOF)."""

    def record(address: int, data: bytes) -> str:
        total = len(data) + (address >> 8) + (address & 0xFF) + sum(data)
        return f":{len(data):02X}{address:04X}00{data.hex().upper()}{(-total) & 0xFF:02X}"

    lines = [record(0x0000, bytes(range(16))), record(0x0010, bytes(range(16, 32))), ":00000001FF"]
    return ("\n".join(lines) + "\n").encode("ascii")


def _project(wa: Path, name: str, files: dict) -> Path:
    folder = wa / name
    folder.mkdir(parents=True, exist_ok=True)
    for file_name, payload in files.items():
        (folder / file_name).write_bytes(payload)
    return folder


def _scene(root: Path) -> types.SimpleNamespace:
    """A scratch app base plus a source folder outside it.

    ``src``: ``fw.s19``, ``b.s19``, ``other.s19`` (case_01 bytes, so the
    patch address exists in each), ``typed.mac``, ``typed2.MAC``,
    ``cal.a2l``. Work area ``temp/``: ``x.s19``, ``x.hex``, ``x.mac``,
    ``c.a2l``, ``U.MAC`` (the upper-case arm; ``X.MAC`` would collide with
    ``x.mac`` on a case-insensitive volume), ``other.s19``. Projects: ``PV``
    (``firmware_a.s19`` = case_01, ``firmware_b.s19`` = case_02), ``P`` and
    ``Q`` (case_01 ``firmware.s19``), ``M2`` (1 data file, 2 MAC files)."""
    base = root / "app"
    src = root / "src"
    src.mkdir(parents=True, exist_ok=True)
    s19 = (CASE01 / "firmware.s19").read_bytes()
    mac = (CASE01 / "firmware.mac").read_bytes()
    a2l = (CASE01 / "firmware.a2l").read_bytes()
    for name in ("fw.s19", "b.s19", "other.s19"):
        (src / name).write_bytes(s19)
    (src / "typed.mac").write_bytes(mac)
    (src / "typed2.MAC").write_bytes(mac)
    (src / "cal.a2l").write_bytes(a2l)
    temp = _wa(base) / WORKAREA_TEMP
    temp.mkdir(parents=True, exist_ok=True)
    (temp / "x.s19").write_bytes(s19)
    (temp / "other.s19").write_bytes(s19)
    (temp / "x.hex").write_bytes(_hex_bytes())
    (temp / "x.mac").write_bytes(mac)
    (temp / "U.MAC").write_bytes(mac)
    (temp / "c.a2l").write_bytes(a2l)
    wa = _wa(base)
    _project(wa, "PV", {"firmware_a.s19": s19, "firmware_b.s19": (CASE02 / "firmware.s19").read_bytes()})
    _project(wa, "P", {"firmware.s19": s19})
    _project(wa, "Q", {"firmware.s19": s19})
    _project(wa, "M2", {"a.s19": s19, "m1.mac": mac, "m2.mac": mac})
    return types.SimpleNamespace(base=base, src=src, temp=temp, wa=wa)


def _run(base: Path, scenario, size: tuple = SIZE):
    return projects.run_app(base, scenario, size=size)


# ---------------------------------------------------------------------------
# readers and drivers
# ---------------------------------------------------------------------------


async def _settle(pilot, n: int = 8) -> None:
    for _ in range(n):
        await pilot.pause()


async def _wait_question(pilot, app, attempts: int = 150) -> None:
    await ld.wait_for(pilot, lambda: is_question(app.screen), "the load question", attempts)
    await _settle(pilot, 4)


async def _wait_closed(pilot, app) -> None:
    await ld.wait_for(pilot, lambda: not is_question(app.screen), "the question to close")
    await _settle(pilot, 4)


def _panel(app):
    from s19_app.tui.screens_directionb import PatchEditorPanel

    return app.query_one("#patch_editor_panel", PatchEditorPanel)


def _flow(app):
    from s19_app.tui.flow_screens import FlowBuilderPanel

    return app.query_one("#flow_panel", FlowBuilderPanel)


def _D(app) -> bool:
    """D: the image differs from the copy last loaded or written."""
    cur = app.current_file
    return app._change_service.differs_from_last_saved(cur.mem_map if cur is not None else None)


async def _load(pilot, app, path: Path) -> None:
    """Setup only (nothing unsaved yet): install ``path`` through the loader."""
    app.load_selected_file(path)
    await ld.wait_for(
        pilot,
        lambda: app.current_file is not None and Path(app.current_file.path).name == path.name,
        f"the load of {path.name}",
    )
    await _settle(pilot, 6)


async def _open_project(pilot, app, name: str) -> None:
    """Setup only: open ``name`` through the project-load handler."""
    await projects.load_project(pilot, app, name)


async def _patch(pilot, app, same: bool = False) -> int:
    """Make D true with one real applied entry (a fresh address each call);
    ``same`` writes the byte already there (D stays false). Returns the
    address."""
    cur = app.current_file
    used = len(app._change_service.document.entries)
    addresses = sorted(cur.mem_map)
    address = PATCH_ADDRESS if used == 0 and PATCH_ADDRESS in cur.mem_map else addresses[used]
    old = cur.mem_map[address]
    new = old if same else (old + 1) & 0xFF
    app._change_service.add_entry(f"0x{address:08X}", "", f"{new:02X}")
    app._change_service.apply(cur.mem_map, cur.ranges, cur.mac_records, None)
    await _settle(pilot, 4)
    if not same:
        assert _D(app), "setup: the applied patch did not make the image unsaved"
    return address


async def _set_w(pilot, app) -> None:
    _panel(app).request_action("add_entry")
    await _settle(pilot, 4)
    assert _panel(app)._dirty, "setup: writer w1 did not set the Patch Editor flag"


async def _set_f(pilot, app, name: str | None = None) -> None:
    flow = _flow(app)
    if name is not None:
        flow._flow_name = name
    flow._mark_dirty()
    await _settle(pilot, 2)
    assert flow.is_dirty, "setup: the Flow Builder flag is not set"


class PushSpy:
    """Every screen pushed while installed, in order (by class name)."""

    def __init__(self, app) -> None:
        self.names: list = []
        original = app.push_screen

        def _spy(screen, *args, **kwargs):
            self.names.append(screen if isinstance(screen, str) else type(screen).__name__)
            return original(screen, *args, **kwargs)

        app.push_screen = _spy

    def questions(self) -> int:
        return self.names.count("ConfirmQuestionScreen")


def _image_sha(app):
    cur = app.current_file
    if cur is None:
        return None
    return hashlib.sha256(repr(sorted(cur.mem_map.items())).encode("ascii")).hexdigest()


def _digest(app) -> tuple:
    """The session digest: (current file, SHA-256 of the installed image
    bytes, current project, current A2L, MAC path)."""
    cur = app.current_file
    return (
        str(cur.path) if cur is not None else None,
        _image_sha(app),
        app.current_project,
        str(app.current_a2l_path) if app.current_a2l_path is not None else None,
        str(cur.mac_path) if cur is not None and cur.mac_path is not None else None,
    )


def _store_sha():
    store = Path(os.environ["LOCALAPPDATA"]) / "s19_app" / "recent_sources.json"
    try:
        return hashlib.sha256(store.read_bytes()).hexdigest()
    except OSError:
        return None


def _kept(app) -> tuple:
    """The digest plus the kept work: Patch Editor entries and flag, Flow
    Builder blocks and flag, the recent store bytes."""
    flow = _flow(app)
    return (
        _digest(app),
        len(app._change_service.document.entries),
        bool(_panel(app)._dirty),
        [block.kind for block in flow.current_flow.blocks],
        bool(flow.is_dirty),
        _store_sha(),
    )


def _visual(widget):
    visual = getattr(widget, "visual", None)
    if visual is None:
        visual = widget.render()
    return visual


def _plain(widget) -> str:
    visual = _visual(widget)
    return str(getattr(visual, "plain", visual))


def _spans(widget) -> list:
    return list(getattr(_visual(widget), "spans", None) or [])


def q_title(app) -> str:
    return _plain(app.screen.query_one("#confirm_title"))


def q_body(app) -> str:
    return _plain(app.screen.query_one("#confirm_body"))


def q_buttons(app) -> list:
    from textual.widgets import Button

    return [(b.id, b.label.plain) for b in app.screen.query(Button)]


def _focused_id(app):
    return getattr(app.focused, "id", None)


def _stack(app) -> list:
    return [type(s).__name__ for s in app.screen_stack]


async def _answer(pilot, app, key: str) -> None:
    await pilot.press(key)
    await _wait_closed(pilot, app)


async def _ask(pilot, app, trigger) -> None:
    trigger()
    await _wait_question(pilot, app)


async def _close_result_panel(pilot, app) -> None:
    await projects.dismiss_load_result_panel(pilot, app)
    await _settle(pilot, 4)


def _sentence_ends(body: str, names) -> int:
    text = body
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "")
    return text.count(".") + text.count("?")


async def _modal_alone(pilot, app, args=LOADQ):
    """Push the question alone on the real app; return (screen, answers)."""
    answers: list = []
    screen = _new_question(*args)
    app.push_screen(screen, answers.append)
    await _wait_question(pilot, app)
    return screen, answers


# ---------------------------------------------------------------------------
# TC-B100-44 — when the guard asks (LLR-174.1, .1a, .1b, .1c)
# ---------------------------------------------------------------------------


def test_tc_b100_44_twenty_four_cells_ask_by_kind(tmp_path: Path) -> None:
    """LLR-174.1, LLR-174.1a, LLR-174.1b (C10, C14): for each load kind x D x
    F x W, ``_load_would_lose(kind)`` is non-empty exactly when the guard
    must ask: image iff D (4 of 8), attach never (0 of 8), project unless
    D = F = W = 0 (7 of 8) → 11 ask, 13 load, 24 of 24. An attach reads no
    flag (0 calls of the saved-state predicate).

    Why: the question must interrupt exactly the loads that replace or move
    unsaved work and no other; an attach keeps the patch, so asking there
    is a false alarm.
    Negative control (LED .17 enumeration): drop D → 5 cells wrong; drop F
    → 1; drop W → 1; an attach that asks on D → 4. RED (base): no
    ``_load_would_lose``."""
    scene = _scene(tmp_path)

    async def scenario(app, pilot, log):
        await _load(pilot, app, scene.src / "fw.s19")
        panel, flow = _panel(app), _flow(app)
        cells = {}
        for d in (0, 1):
            if d:
                await _patch(pilot, app)
            for f in (0, 1):
                for w in (0, 1):
                    if w:
                        await _set_w(pilot, app)
                    else:
                        panel.mark_saved()
                    if f:
                        await _set_f(pilot, app)
                    else:
                        flow.mark_saved("flow")
                    await _settle(pilot, 2)
                    assert (_D(app), bool(panel._dirty), bool(flow.is_dirty)) == (bool(d), bool(w), bool(f))
                    for kind in ("image", "attach", "project"):
                        cells[(kind, d, f, w)] = bool(app._load_would_lose(kind))
        calls = []
        real = app._change_service.differs_from_last_saved

        def spy(mem_map):
            calls.append(1)
            return real(mem_map)

        app._change_service.differs_from_last_saved = spy
        attach_items = app._load_would_lose("attach")
        del app._change_service.differs_from_last_saved
        return cells, attach_items, len(calls)

    cells, attach_items, attach_reads = _run(scene.base, scenario)
    expected = {}
    for (kind, d, f, w) in cells:
        if kind == "image":
            expected[(kind, d, f, w)] = bool(d)
        elif kind == "attach":
            expected[(kind, d, f, w)] = False
        else:
            expected[(kind, d, f, w)] = bool(d or f or w)
    wrong = {cell: got for cell, got in cells.items() if got != expected[cell]}
    assert len(cells) == 24
    assert wrong == {}, f"cells that ask wrongly: {wrong}"
    assert sum(cells.values()) == 11
    assert attach_items == [] and attach_reads == 0, (attach_items, attach_reads)


def _saved_state_arm(root: Path, arm: str) -> tuple:
    """One HLR-174a boundary: the scene, then a data load of ``b.s19``.
    Returns (questions, loaded file name, D before the request)."""
    from s19_app.tui.screens_directionb import PatchEditorPanel

    scene = _scene(root)

    async def scenario(app, pilot, log):
        await _load(pilot, app, scene.src / "fw.s19")
        if arm == "unsaved":
            await _patch(pilot, app)
        elif arm == "same-byte":
            await _patch(pilot, app, same=True)
        elif arm == "save-project":
            await _patch(pilot, app)
            messages = await projects.save_project(pilot, app, log, "S1")
            assert any(m.startswith("Saved project to") for m in messages), messages
        elif arm == "save-back":
            await _patch(pilot, app)
            app.on_patch_editor_panel_save_back_decision(
                PatchEditorPanel.SaveBackDecision("fw_saved.s19", 32)
            )
            await ld.wait_for(
                pilot,
                lambda: any("Saved + verified" in m for m in log.messages),
                "the save-back outcome",
            )
        elif arm == "undo-apply":
            await _patch(pilot, app)
            app._change_service.undo()
            cur = app.current_file
            app._change_service.apply(cur.mem_map, cur.ranges, cur.mac_records, None)
            await _settle(pilot, 4)
        d_before = _D(app)
        spy = PushSpy(app)
        app._handle_load_dialog(LC("path", str(scene.src / "b.s19")))
        await ld.wait_for(
            pilot,
            lambda: is_question(app.screen)
            or (app.current_file is not None and Path(app.current_file.path).name == "b.s19"),
            "the load or the question",
        )
        await _settle(pilot, 6)
        asked = spy.questions()
        if is_question(app.screen):
            await _answer(pilot, app, "n")
        return asked, Path(app.current_file.path).name, d_before

    return _run(scene.base, scenario)


def test_tc_b100_44_saved_states_load_without_asking(tmp_path: Path) -> None:
    """HLR-174a, LLR-174.1 boundaries (C12): 0 questions and the file loads
    after a same-byte patch, after Save project, after a save-back, and
    after undo then Apply (the byte restored) (4 of 4). Live-guard control:
    the same scene with the patch left unsaved asks 1 question.

    Why: once the work is safe on disk (or the image equals what was last
    loaded) a question would be noise, and noise trains the engineer to
    press ``y`` blindly.
    Negative control: a guard keyed on "a document has entries" asks in the
    save-project and save-back arms → RED. RED (base): the control arm
    asks nothing."""
    control = _saved_state_arm(tmp_path / "control", "unsaved")
    assert control[0] == 1 and control[2] is True, f"live-guard control: {control}"
    results = {arm: _saved_state_arm(tmp_path / arm, arm)
               for arm in ("same-byte", "save-project", "save-back", "undo-apply")}
    for arm, (asked, loaded, d_before) in results.items():
        assert d_before is False, f"{arm}: setup left D true"
        assert asked == 0, f"{arm}: {asked} question(s)"
        assert loaded == "b.s19", f"{arm}: loaded {loaded}"


def _unsaved_again_arm(root: Path, arm: str) -> tuple:
    scene = _scene(root)

    async def scenario(app, pilot, log):
        await _load(pilot, app, scene.src / "fw.s19")
        address = await _patch(pilot, app)
        if arm == "undo-alone":
            app._change_service.undo()
            await _settle(pilot, 4)
        else:
            messages = await projects.save_project(pilot, app, log, "S1")
            assert any(m.startswith("Saved project to") for m in messages), messages
            assert not _D(app), "setup: Save project left D true"
            await _patch(pilot, app)
        byte = app.current_file.mem_map[address]
        spy = PushSpy(app)
        before = _digest(app)
        app._handle_load_dialog(LC("path", str(scene.src / "b.s19")))
        await _wait_question(pilot, app)
        on_top = _digest(app)
        body = q_body(app)
        await _answer(pilot, app, "n")
        return spy.questions(), before == on_top, body, byte

    return _run(scene.base, scenario)


def test_tc_b100_44_undo_alone_and_repatch_after_save_ask(tmp_path: Path) -> None:
    """LLR-174.1 boundaries (C13): undo alone leaves the patched byte, so the
    data load asks 1 question naming ``fw.s19``; patched → Save project →
    patched again → 1 question (2 of 2).

    Why: undo edits the document, not the image; only the image bytes
    decide whether work would be lost.
    Negative control: a guard keyed on the document entry count → the
    undo-alone arm finds 0 entries and loads → RED. RED (base): no
    question."""
    for arm in ("undo-alone", "save-then-repatch"):
        asked, unchanged, body, byte = _unsaved_again_arm(tmp_path / arm, arm)
        assert asked == 1, f"{arm}: {asked} questions"
        assert unchanged, f"{arm}: the session changed while the question was on top"
        assert "fw.s19" in body, f"{arm}: {body!r}"


def test_tc_b100_44_attach_asks_nothing_and_keeps_the_patch(tmp_path: Path) -> None:
    """LLR-174.1a, HLR-174a (C14, p10b U3): with an unsaved patch, a typed MAC
    attach and a typed A2L attach each load with 0 questions, the patched
    byte unchanged and D still true (2 of 2). Live-guard control: a data
    load in the same session asks 1 question.

    Why: an attach keeps the image, so a question there is a false alarm.
    Negative control: the round-2 rule (an attach asks on D) → both arms
    ask → RED. RED (base): the control asks nothing."""
    scene = _scene(tmp_path)

    async def scenario(app, pilot, log):
        await _load(pilot, app, scene.src / "fw.s19")
        address = await _patch(pilot, app)
        byte = app.current_file.mem_map[address]
        spy = PushSpy(app)
        app._handle_load_dialog(LC("path", str(scene.src / "typed.mac")))
        await ld.wait_for(
            pilot,
            lambda: app.current_file.mac_path is not None
            and Path(app.current_file.mac_path).name == "typed.mac",
            "the MAC attach",
        )
        await _settle(pilot, 6)
        mac_arm = (spy.questions(), app.current_file.mem_map.get(address) == byte, _D(app))
        app._handle_load_dialog(LC("path", str(scene.src / "cal.a2l")))
        await ld.wait_for(
            pilot,
            lambda: app.current_a2l_path is not None and Path(app.current_a2l_path).name == "cal.a2l",
            "the A2L attach",
        )
        await _settle(pilot, 6)
        a2l_arm = (spy.questions(), app.current_file.mem_map.get(address) == byte, _D(app))
        app._handle_load_dialog(LC("path", str(scene.src / "b.s19")))
        await _wait_question(pilot, app)
        control = spy.questions()
        await _answer(pilot, app, "n")
        return mac_arm, a2l_arm, control

    mac_arm, a2l_arm, control = _run(scene.base, scenario)
    assert mac_arm == (0, True, True), f"MAC attach: {mac_arm}"
    assert a2l_arm == (0, True, True), f"A2L attach: {a2l_arm}"
    assert control == 1


def test_tc_b100_44_project_load_asks_iff_a_flag_is_set(tmp_path: Path) -> None:
    """LLR-174.1b, HLR-174a: project P open and nothing unsaved → a project
    load of Q asks 0 questions and opens Q; a patch plus a Patch Editor
    entry (through the panel's inputs) → Save project → a project load asks
    0; with D only, W only and F only → 1 question each (5 of 5).

    Why: a project load replaces the image and resets the Patch Editor, so
    any of the three unsaved flags must be asked about, and an open project
    alone must not be (the ``pb_A`` prototype asked whenever a project was
    open).
    Negative control: the ``pb_A`` rule → the first arm asks → RED;
    dropping F or W → that arm loads silently → RED. RED (base): the
    single-flag arms ask nothing."""
    scene = _scene(tmp_path)

    async def scenario(app, pilot, log):
        out = {}
        await _open_project(pilot, app, "P")
        spy = PushSpy(app)
        app._handle_load_dialog(LC("project", "Q"))
        await ld.wait_for(pilot, lambda: app.current_project == "Q" or is_question(app.screen), "Q or the question")
        await _settle(pilot, 6)
        out["open, nothing unsaved"] = (spy.questions(), app.current_project)
        if is_question(app.screen):
            await _answer(pilot, app, "n")
        else:
            await _close_result_panel(pilot, app)
        await _patch(pilot, app)
        await pilot.press("6")
        await ld.wait_for(pilot, lambda: len(app.query("#patch_entry_add_button")) > 0, "the Patch Editor")
        await _settle(pilot, 4)
        assert await pilot.click("#patch_entry_address_input")
        await pilot.press("ctrl+a", "delete", *"0x80000010")
        assert await pilot.click("#patch_entry_bytes_input")
        await pilot.press("ctrl+a", "delete", *"AB")
        assert await pilot.click("#patch_entry_add_button")
        await ld.wait_for(pilot, lambda: _panel(app)._dirty, "the panel flag")
        messages = await projects.save_project(pilot, app, log, "S1")
        assert any(m.startswith("Saved project to") for m in messages), messages
        assert not _D(app) and not _panel(app)._dirty, "setup: Save project left a flag set"
        mark = spy.questions()
        app._handle_load_dialog(LC("project", "P"))
        await ld.wait_for(pilot, lambda: app.current_project == "P" or is_question(app.screen), "P or the question")
        await _settle(pilot, 6)
        out["saved"] = (spy.questions() - mark, app.current_project)
        if is_question(app.screen):
            await _answer(pilot, app, "n")
        else:
            await _close_result_panel(pilot, app)
        for flag in ("D", "W", "F"):
            if flag == "D":
                await _patch(pilot, app)
            elif flag == "W":
                await _set_w(pilot, app)
            else:
                await _set_f(pilot, app)
            mark = spy.questions()
            app._handle_load_dialog(LC("project", "Q"))
            await _wait_question(pilot, app)
            out[flag] = spy.questions() - mark
            await _answer(pilot, app, "n")
            # back to nothing unsaved for the next single-flag arm
            if flag == "D":
                app._change_service.mark_saved(app.current_file.mem_map)
            elif flag == "W":
                _panel(app).mark_saved()
            else:
                _flow(app).mark_saved("flow")
            await _settle(pilot, 2)
        return out

    out = _run(scene.base, scenario)
    assert out["open, nothing unsaved"] == (0, "Q"), out
    assert out["saved"] == (0, "P"), out
    assert (out["D"], out["W"], out["F"]) == (1, 1, 1), out


def test_tc_b100_44_patch_editor_reader_follows_its_writers(tmp_path: Path) -> None:
    """LLR-174.1c (P1-1 … P1-3, K10): ``PatchEditorPanel.is_dirty`` is
    False fresh; True after an entry edit (w1); False after ``mark_saved``
    (w3); False after a non-writer action; True after typing in the paste
    buffer (w2); False after ``mark_loaded`` (w4) even with text left in the
    buffer; True after ``mark_pasted`` (w5); False after ``mark_loaded`` +
    ``clear_paste_buffer``; it has no setter (assignment raises
    ``AttributeError``, ``_dirty`` unchanged).

    Why: the load guard reads W only through this reader, so it must follow
    every writer and must not be writable from outside.
    Negative control: a reader cached at construction stays False after w1
    → RED; a setter → the assignment flips the flag → RED. RED (base): the
    property does not exist."""
    from textual.widgets import TextArea

    from s19_app.tui.screens_directionb import PatchEditorPanel

    scene = _scene(tmp_path)

    async def scenario(app, pilot, log):
        panel = _panel(app)
        trail = [("fresh", panel.is_dirty)]
        panel.request_action("add_entry")
        await _settle(pilot, 3)
        trail.append(("w1 entry edit", panel.is_dirty))
        panel.mark_saved()
        trail.append(("w3 mark_saved", panel.is_dirty))
        panel.request_action("validate_doc")
        await _settle(pilot, 3)
        trail.append(("validate (not a writer)", panel.is_dirty))
        panel.query_one("#patch_paste_text", TextArea).insert("x")
        await _settle(pilot, 4)
        trail.append(("w2 paste typing", panel.is_dirty))
        panel.mark_loaded()
        trail.append(("w4 mark_loaded, text left", panel.is_dirty))
        panel.mark_pasted()
        trail.append(("w5 mark_pasted", panel.is_dirty))
        panel.mark_loaded()
        panel.clear_paste_buffer()
        await _settle(pilot, 4)
        trail.append(("mark_loaded + clear (not a writer)", panel.is_dirty))
        before = panel._dirty
        try:
            panel.is_dirty = True
            raised = None
        except AttributeError as exc:
            raised = type(exc).__name__
        return trail, raised, before, panel._dirty

    trail, raised, before, after = _run(scene.base, scenario)
    assert trail == [
        ("fresh", False),
        ("w1 entry edit", True),
        ("w3 mark_saved", False),
        ("validate (not a writer)", False),
        ("w2 paste typing", True),
        ("w4 mark_loaded, text left", False),
        ("w5 mark_pasted", True),
        ("mark_loaded + clear (not a writer)", False),
    ], trail
    assert raised == "AttributeError" and after == before, (raised, before, after)
    assert PatchEditorPanel.is_dirty.fset is None


def _private_dirty_reads() -> list:
    """Every ``<x>._dirty`` load in ``s19_app/`` outside
    ``screens_directionb.py`` whose ``<x>`` is not ``self`` (a panel's
    flag read from outside its own class)."""
    package = Path(app_module.__file__).resolve().parents[1]
    hits = []
    for path in sorted(package.rglob("*.py")):
        if path.name == "screens_directionb.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Attribute)
                and node.attr == "_dirty"
                and isinstance(node.ctx, ast.Load)
                and not (isinstance(node.value, ast.Name) and node.value.id == "self")
            ):
                hits.append(f"{path.name}:{node.lineno}")
    return hits


def test_tc_b100_44_no_private_dirty_read_outside_the_panel() -> None:
    """LLR-174.1c census (C52, P1-5): 0 reads of another object's ``_dirty``
    in ``s19_app/`` outside ``screens_directionb.py``, and the reader the
    app uses instead exists.

    Why: a private read bypasses the one reader whose behaviour TC-B100-44
    pins; the next writer added to the panel would silently disagree.
    Negative control: the base line ``panel._dirty`` (``_handle_save_dialog``)
    → 1 hit → RED."""
    from s19_app.tui.screens_directionb import PatchEditorPanel

    hits = _private_dirty_reads()
    assert hits == [], f"private _dirty reads outside the panel: {hits}"
    assert isinstance(getattr(PatchEditorPanel, "is_dirty", None), property)


def test_tc_b100_44_guard_reads_the_public_reader(tmp_path: Path, monkeypatch) -> None:
    """LLR-174.1c, LLR-174.1b (C16): with ``PatchEditorPanel.is_dirty``
    replaced by a property that answers True while ``_dirty`` is False, a
    project load asks 1 question naming ``Patch Editor entries``.

    Why: proves the guard consults the public reader, not the private flag.
    Negative control: a guard reading ``panel._dirty`` → 0 questions → RED.
    RED (base): no question."""
    from s19_app.tui.screens_directionb import PatchEditorPanel

    monkeypatch.setattr(PatchEditorPanel, "is_dirty", property(lambda self: True), raising=False)
    scene = _scene(tmp_path)

    async def scenario(app, pilot, log):
        await _load(pilot, app, scene.src / "fw.s19")
        assert _panel(app)._dirty is False and not _D(app)
        spy = PushSpy(app)
        app._handle_load_dialog(LC("project", "Q"))
        await _wait_question(pilot, app)
        body = q_body(app)
        await _answer(pilot, app, "n")
        return spy.questions(), body

    asked, body = _run(scene.base, scenario)
    assert asked == 1
    assert "Patch Editor entries" in body, body


# ---------------------------------------------------------------------------
# TC-B100-45 — the modal (LLR-174.2 … LLR-174.2t)
# ---------------------------------------------------------------------------


def test_tc_b100_45_one_modal_with_replace_and_cancel(tmp_path: Path) -> None:
    """LLR-174.2, LLR-174.2p, HLR-174 (Q1-1, Q1-3, C02): one guarded data
    load with D → the stack grows by 1, the top screen holds exactly the
    buttons ``confirm_yes`` "Replace (y)" and ``confirm_no`` "Cancel (n)",
    0 ``Input`` / ``TextArea``; while it is open ``s`` (a "save first" key)
    pushes 0 screens; each shown key acts: ``n`` cancels and ``y`` loads
    ``b.s19``.

    Why: one short question with two answers (VS-PB-1/2); every key the
    labels show must work.
    Negative control: the ``pb_B`` variant (a third "Save first" button on
    ``s``) → 3 buttons → RED. RED (base): no question."""
    from textual.widgets import Input, TextArea

    scene = _scene(tmp_path)

    async def scenario(app, pilot, log):
        await _load(pilot, app, scene.src / "fw.s19")
        await _patch(pilot, app)
        depth = len(app.screen_stack)
        app._handle_load_dialog(LC("path", str(scene.src / "b.s19")))
        await _wait_question(pilot, app)
        grown = len(app.screen_stack) - depth
        buttons = q_buttons(app)
        inputs = len(app.screen.query(Input)) + len(app.screen.query(TextArea))
        spy = PushSpy(app)
        await pilot.press("s")
        await _settle(pilot, 4)
        pushed_by_s = list(spy.names)
        still = is_question(app.screen)
        await _answer(pilot, app, "n")
        after_n = Path(app.current_file.path).name
        app._handle_load_dialog(LC("path", str(scene.src / "b.s19")))
        await _wait_question(pilot, app)
        await pilot.press("y")
        await ld.wait_for(pilot, lambda: Path(app.current_file.path).name == "b.s19", "the load of b.s19")
        return grown, buttons, inputs, pushed_by_s, still, after_n, _stack(app)

    grown, buttons, inputs, pushed, still, after_n, stack = _run(scene.base, scenario)
    assert grown == 1
    assert buttons == [("confirm_yes", "Replace (y)"), ("confirm_no", "Cancel (n)")], buttons
    assert inputs == 0
    assert pushed == [] and still, (pushed, still)
    assert after_n == "fw.s19"
    assert not any(name == "ConfirmQuestionScreen" for name in stack), stack


def test_tc_b100_45_modal_builds_from_its_parameters(tmp_path: Path) -> None:
    """LLR-174.2a, LLR-174.2i (G-A share) (Q1-5, Q2-2, Q2-3, Q4-3): built
    with the quit strings, the modal paints exactly ``Quit?``,
    ``A save is running.``, ``Quit (y)``, ``Stay (n)`` and 0 ``Replace``;
    ``y`` → True and ``n`` → False; the screen's ``title`` reactive is not
    set; hostile strings paint literally with 0 markup spans.

    Why: Inc 12 builds its quit question from the same modal, so nothing in
    it may be hard-coded to the load question, and a name holding ``[``
    must never be read as markup.
    Negative control: a hard-coded ``Replace (y)`` → the quit arm paints it
    → RED; a ``str`` button label → ``[b]Quit (y)`` paints as ``Quit (y)``
    with 1 span → RED. RED (base): no ``ConfirmQuestionScreen``."""

    async def scenario(app, pilot, log):
        screen, answers = await _modal_alone(pilot, app, QUITQ)
        painted = [q_title(app), q_body(app)] + [label for _, label in q_buttons(app)]
        title_reactive = screen.title
        await _answer(pilot, app, "y")
        _, answers_n = await _modal_alone(pilot, app, QUITQ)
        await _answer(pilot, app, "n")
        await _modal_alone(pilot, app, HOSTILE)
        from textual.widgets import Button

        hostile = (
            q_title(app), len(_spans(app.screen.query_one("#confirm_title"))),
            q_body(app), len(_spans(app.screen.query_one("#confirm_body"))),
            app.screen.query_one("#confirm_yes", Button).label.plain,
            len(app.screen.query_one("#confirm_yes", Button).label.spans),
        )
        await _answer(pilot, app, "n")
        return painted, title_reactive, answers, answers_n, hostile

    painted, title_reactive, answers_y, answers_n, hostile = _run(tmp_path / "app", scenario)
    assert painted == ["Quit?", "A save is running.", "Quit (y)", "Stay (n)"], painted
    assert sum(text.count("Replace") for text in painted) == 0
    assert answers_y == [True] and answers_n == [False], (answers_y, answers_n)
    assert title_reactive != "Quit?", "the question title was written to Screen.title"
    assert hostile == ("[b]Quit?", 0, "A save is [red]running[/red].", 0, "[b]Quit (y)", 0), hostile


def test_tc_b100_45_focus_starts_on_cancel_on_every_route(tmp_path: Path) -> None:
    """LLR-174.2b, HLR-174c (Q1-2): the question opened from a data load, a
    Workarea pick, a project row and a variant switch → the focus is on
    ``#confirm_no`` each time (4 of 4).

    Why: an engineer who presses ``enter`` without reading keeps the work.
    Negative control: ``AUTO_FOCUS = "#confirm_yes"`` (or none, the
    ``ConfirmDiscardScreen`` shape) → ``confirm_yes`` → RED. RED (base): no
    question."""
    scene = _scene(tmp_path)

    async def scenario(app, pilot, log):
        await _open_project(pilot, app, "PV")
        await _patch(pilot, app)
        focus = {}
        triggers = {
            "data": lambda: app._handle_load_dialog(LC("path", str(scene.src / "b.s19"))),
            "workarea": lambda: app._load_from_item(types.SimpleNamespace(data="x.s19")),
            "project": lambda: app._handle_load_dialog(LC("project", "Q")),
            "variant": lambda: app._handle_select_variant("firmware_b"),
        }
        for name, trigger in triggers.items():
            await _ask(pilot, app, trigger)
            focus[name] = _focused_id(app)
            await _answer(pilot, app, "n")
        return focus

    focus = _run(scene.base, scenario)
    assert focus == {k: "confirm_no" for k in ("data", "workarea", "project", "variant")}, focus


def test_tc_b100_45_y_replaces_with_the_focus_on_either_button(tmp_path: Path) -> None:
    """LLR-174.2c, HLR-174b (Q4-1, Q3-4): ``y`` with the focus on
    ``#confirm_no`` → True; ``tab`` then ``y`` (focus on ``#confirm_yes``) →
    True (2 of 2); each answer is a ``bool``.

    Why: ``y`` is the shown replace key wherever the focus sits.
    Negative control: no ``y`` binding → the question stays open → RED.
    RED (base): no ``ConfirmQuestionScreen``."""

    async def scenario(app, pilot, log):
        out = []
        for moves in ((), ("tab",)):
            _, answers = await _modal_alone(pilot, app)
            for key in moves:
                await pilot.press(key)
                await _settle(pilot, 2)
            focus = _focused_id(app)
            await _answer(pilot, app, "y")
            out.append((focus, answers))
        return out

    out = _run(tmp_path / "app", scenario)
    assert out == [("confirm_no", [True]), ("confirm_yes", [True])], out
    assert all(type(a[0]) is bool for _, a in out)


def test_tc_b100_45_n_and_escape_cancel_with_the_focus_on_either_button(tmp_path: Path) -> None:
    """LLR-174.2d, HLR-174c (Q4-2): ``n`` and ``escape``, each with the focus
    on ``#confirm_no`` and on ``#confirm_yes`` → False 4 times, the stack
    back to the main screen each time (Q5-3: ``escape`` returns).

    Why: both cancel keys must work from either button, and ``escape`` must
    close (the ``ConfirmDiscardScreen`` P-18 shape ignored it).
    Negative control: no ``escape`` binding → the question stays → RED.
    RED (base): no ``ConfirmQuestionScreen``."""

    async def scenario(app, pilot, log):
        out = []
        for key in ("n", "escape"):
            for moves in ((), ("tab",)):
                _, answers = await _modal_alone(pilot, app)
                for move in moves:
                    await pilot.press(move)
                    await _settle(pilot, 2)
                focus = _focused_id(app)
                await _answer(pilot, app, key)
                out.append((key, focus, list(answers), len(app.screen_stack)))
        return out

    out = _run(tmp_path / "app", scenario)
    assert out == [
        ("n", "confirm_no", [False], 1),
        ("n", "confirm_yes", [False], 1),
        ("escape", "confirm_no", [False], 1),
        ("escape", "confirm_yes", [False], 1),
    ], out


def test_tc_b100_45_enter_answers_with_the_focused_button(tmp_path: Path) -> None:
    """LLR-174.2e, HLR-174b, HLR-174c (Q3-2, Q3-3): an immediate ``enter`` →
    False; ``tab``, ``enter`` → True; ``tab``, ``tab``, ``enter`` → False
    (the focus wraps over the two buttons); ``shift+tab``, ``enter`` → True.

    Why: ``enter`` acts on the focused button, and the initial focus is
    Cancel, so a reflexive ``enter`` keeps the work.
    Negative control: a screen-level ``enter`` → replace → the immediate
    ``enter`` gives True → RED. RED (base): no ``ConfirmQuestionScreen``."""

    async def scenario(app, pilot, log):
        out = []
        for moves in ((), ("tab",), ("tab", "tab"), ("shift+tab",)):
            _, answers = await _modal_alone(pilot, app)
            for move in moves:
                await pilot.press(move)
                await _settle(pilot, 2)
            await _answer(pilot, app, "enter")
            out.append((moves, list(answers)))
        return out

    out = _run(tmp_path / "app", scenario)
    assert out == [
        ((), [False]),
        (("tab",), [True]),
        (("tab", "tab"), [False]),
        (("shift+tab",), [True]),
    ], out


def test_tc_b100_45_click_answers_with_the_clicked_button(tmp_path: Path) -> None:
    """LLR-174.2f (Q3-1): a click on ``#confirm_yes`` → True, a click on
    ``#confirm_no`` → False, the question closed each time (2 of 2).

    Why: the mouse is a shipped way to answer.
    Negative control: ``Button.Pressed`` ignored → the click leaves the
    question open → RED. RED (base): no ``ConfirmQuestionScreen``."""

    async def scenario(app, pilot, log):
        out = []
        for target in ("#confirm_yes", "#confirm_no"):
            _, answers = await _modal_alone(pilot, app)
            assert await pilot.click(target), f"click missed {target}"
            await _wait_closed(pilot, app)
            out.append((target, list(answers)))
        return out

    out = _run(tmp_path / "app", scenario)
    assert out == [("#confirm_yes", [True]), ("#confirm_no", [False])], out


def test_tc_b100_45_other_keys_leave_the_question_open(tmp_path: Path) -> None:
    """LLR-174.2g, LLR-174.2 VS-PB-2 (Q1-3, K4): with a data load asking,
    ``a``, ``l``, ``p``, ``s``, ``q``, ``space``, ``?`` and ``v`` → the
    question still on top, 0 screens pushed, the focus still on
    ``#confirm_no`` and the session digest unchanged (8 of 8).

    Why: an app key typed while the question waits must neither answer it
    nor start another action underneath.
    Negative control: the ``pb_B`` binding of ``s`` (save first) → ``s``
    leaves the question → RED. RED (base): no question."""
    scene = _scene(tmp_path)

    async def scenario(app, pilot, log):
        await _load(pilot, app, scene.src / "fw.s19")
        await _patch(pilot, app)
        app._handle_load_dialog(LC("path", str(scene.src / "b.s19")))
        await _wait_question(pilot, app)
        before = _digest(app)
        spy = PushSpy(app)
        out = []
        for key in ("a", "l", "p", "s", "q", "space", "question_mark", "v"):
            await pilot.press(key)
            await _settle(pilot, 3)
            out.append((key, is_question(app.screen), _focused_id(app)))
        result = (out, list(spy.names), before == _digest(app))
        await _answer(pilot, app, "n")
        return result

    out, pushed, unchanged = _run(scene.base, scenario)
    assert all(on_top and focus == "confirm_no" for _, on_top, focus in out), out
    assert pushed == [] and unchanged, (pushed, unchanged)


def test_tc_b100_45_priority_keys_are_inert_under_the_question(tmp_path: Path) -> None:
    """LLR-174.2h (C45, C46, C47, Q1-4): with the question on top, ``ctrl+l``,
    ``ctrl+s``, ``ctrl+k``, ``ctrl+d``, with the focus on each button → the
    stack depth unchanged, the question on top, 0 calls of
    ``action_load_file`` / ``action_save_project`` / ``action_focus_palette``
    / ``action_cycle_density`` (2 x 4). With a palette over the question,
    ``ctrl+s`` and ``ctrl+l`` still push nothing. After ``n``, ``ctrl+l``
    opens 1 Load dialog and ``ctrl+d`` cycles the density once (no
    over-reach).

    Why: priority keys walk the whole chain through a modal; under the
    question they would stack a dialog or save over unanswered work.
    Negative control: 9b's guard alone (``LoadDialog`` only) → ``ctrl+l``
    pushes a Load dialog over the question → RED. RED (base): no
    question."""
    scene = _scene(tmp_path)

    async def scenario(app, pilot, log):
        await _load(pilot, app, scene.src / "fw.s19")
        await _patch(pilot, app)
        ran = []
        for name in ("load_file", "save_project", "focus_palette", "cycle_density"):
            real = getattr(app, f"action_{name}")

            def wrap(real=real, name=name):
                ran.append(name)
                return real()

            setattr(app, f"action_{name}", wrap)
        app._handle_load_dialog(LC("path", str(scene.src / "b.s19")))
        await _wait_question(pilot, app)
        depth = len(app.screen_stack)
        arms = []
        for moves in ((), ("tab",)):
            for move in moves:
                await pilot.press(move)
                await _settle(pilot, 2)
            for key in ("ctrl+l", "ctrl+s", "ctrl+k", "ctrl+d"):
                await pilot.press(key)
                await _settle(pilot, 4)
                arms.append((key, _focused_id(app), len(app.screen_stack), is_question(app.screen)))
        ran_under = list(ran)
        await pilot.press("ctrl+p")
        await _settle(pilot, 6)
        palette_open = not is_question(app.screen)
        await pilot.press("ctrl+s")
        await _settle(pilot, 4)
        await pilot.press("ctrl+l")
        await _settle(pilot, 4)
        over_palette = (list(ran), _stack(app))
        if palette_open:
            await pilot.press("escape")
            await _settle(pilot, 6)
        await ld.wait_for(pilot, lambda: is_question(app.screen), "the question back on top")
        await _answer(pilot, app, "n")
        await pilot.press("ctrl+l")
        await ld.wait_for_dialog(pilot, app)
        dialogs = sum(ld.is_load_dialog(s) for s in app.screen_stack)
        await pilot.press("escape")
        await ld.wait_for_dialog_closed(pilot, app)
        await pilot.press("ctrl+d")
        await _settle(pilot, 4)
        return depth, arms, ran_under, over_palette, dialogs, list(ran)

    depth, arms, ran_under, over_palette, dialogs, ran_after = _run(scene.base, scenario)
    assert all(d == depth and on_top for _, _, d, on_top in arms), arms
    assert [focus for _, focus, _, _ in arms] == ["confirm_no"] * 4 + ["confirm_yes"] * 4, arms
    assert ran_under == [], ran_under
    ran_palette, stack_palette = over_palette
    assert ran_palette == [], ran_palette
    assert "SaveProjectScreen" not in stack_palette and "LoadDialog" not in stack_palette, stack_palette
    assert dialogs == 1
    assert ran_after == ["load_file", "cycle_density"], ran_after


def test_tc_b100_45_names_paint_literally(tmp_path: Path) -> None:
    """LLR-174.2i, HLR-174d (C26, Q2-3, Q2-4): an image ``[b]x.s19`` →
    title ``Replace [b]x.s19?`` and the body names ``[b]x.s19``; an image
    whose name holds U+202E → ``painted_names`` of it, 0 U+202E; project
    ``[i]P`` open and as the target with a flow ``[red]f`` → title
    ``Replace [i]P?``, body ``flow [red]f`` and ``Load project [i]P
    anyway?``; a 130-character flow name → clipped to 120 ending ``…``;
    every title and body with 0 markup spans (5 of 5).

    Why: names come from disk and from the engineer; a bracket must never
    style the question, and a bidirectional control must never reverse it.
    Negative control: markup on → ``[b]x.s19`` paints as ``x.s19`` → RED;
    a raw name → U+202E survives → RED. RED (base): no question."""
    from s19_app.tui.services.project_gather_service import painted_names

    scene = _scene(tmp_path)
    s19 = (CASE01 / "firmware.s19").read_bytes()
    (scene.src / "[b]x.s19").write_bytes(s19)
    bidi = "a‮b.s19"
    (scene.src / bidi).write_bytes(s19)
    _project(scene.wa, "[i]P", {"firmware.s19": s19})
    long_flow = "n" * 130

    async def scenario(app, pilot, log):
        out = {}

        async def read():
            await _wait_question(pilot, app)
            title_w = app.screen.query_one("#confirm_title")
            body_w = app.screen.query_one("#confirm_body")
            got = (q_title(app), q_body(app), len(_spans(title_w)) + len(_spans(body_w)))
            await _answer(pilot, app, "n")
            return got

        await _load(pilot, app, scene.src / "[b]x.s19")
        await _patch(pilot, app)
        app._handle_load_dialog(LC("path", str(scene.src / "b.s19")))
        out["markup image"] = await read()
        await _load(pilot, app, scene.src / bidi)
        await _patch(pilot, app)
        app._handle_load_dialog(LC("path", str(scene.src / "b.s19")))
        out["bidi image"] = await read()
        await _open_project(pilot, app, "[i]P")
        await _set_f(pilot, app, "[red]f")
        app._handle_load_dialog(LC("project", "[i]P"))
        out["markup project"] = await read()
        await _set_f(pilot, app, long_flow)
        app._handle_load_dialog(LC("project", "[i]P"))
        out["long flow"] = await read()
        return out

    out = _run(scene.base, scenario)
    title, body, spans = out["markup image"]
    assert title == "Replace [b]x.s19?" and "[b]x.s19" in body and spans == 0, out["markup image"]
    title, body, spans = out["bidi image"]
    shown = painted_names([bidi])
    assert title == f"Replace {shown}?" and "‮" not in title + body and spans == 0, out["bidi image"]
    title, body, spans = out["markup project"]
    assert title == "Replace [i]P?", title
    assert "flow [red]f" in body and body.endswith("Load project [i]P anyway?") and spans == 0, body
    clipped = painted_names([long_flow])
    assert len(clipped) == 120 and clipped.endswith("…")
    assert f"flow {clipped}" in out["long flow"][1], out["long flow"]


def test_tc_b100_45_patch_editor_load_keeps_its_own_guard(tmp_path: Path) -> None:
    """LLR-174.2j (C54, P1-7): a dirty Patch Editor, then its Load button →
    1 ``LoadGuardScreen`` and 0 load questions; in the same session a data
    load with D → the load question and 0 ``LoadGuardScreen`` (the two
    guards stay distinct).

    Why: the Patch Editor's own document load replaces document entries, not
    the image; it keeps the warning it already has.
    Negative control: ``DirtyLoadRequested`` routed through the load
    question → 0 ``LoadGuardScreen`` → RED. RED (base): the data load asks
    nothing."""
    from textual.widgets import Button

    from s19_app.tui.screens_directionb import LoadGuardScreen

    scene = _scene(tmp_path)

    async def scenario(app, pilot, log):
        await _load(pilot, app, scene.src / "fw.s19")
        await pilot.press("6")
        await ld.wait_for(pilot, lambda: len(app.query("#patch_doc_load_button")) > 0, "the Patch Editor")
        await _set_w(pilot, app)
        spy = PushSpy(app)
        _panel(app).query_one("#patch_doc_load_button", Button).press()
        await ld.wait_for(pilot, lambda: isinstance(app.screen, LoadGuardScreen), "the Patch Editor guard")
        own = list(spy.names)
        await pilot.press("escape")
        await ld.wait_for(pilot, lambda: not isinstance(app.screen, LoadGuardScreen), "the guard closed")
        await _patch(pilot, app)
        mark = len(spy.names)
        app._handle_load_dialog(LC("path", str(scene.src / "b.s19")))
        await _wait_question(pilot, app)
        route = spy.names[mark:]
        await _answer(pilot, app, "n")
        return own, route

    own, route = _run(scene.base, scenario)
    assert own == ["LoadGuardScreen"], own
    assert route == ["ConfirmQuestionScreen"], route


def test_tc_b100_45_title_names_what_is_replaced(tmp_path: Path) -> None:
    """LLR-174.2k (C17, C18, C21): project P open → ``Replace P?``; no
    project, image ``fw.s19`` → ``Replace fw.s19?``; neither, a dirty Flow
    Builder, then a project load → ``Replace the current session?`` (3 of
    3).

    Why: the title says what the engineer is about to lose.
    Negative control: always the image name → the P arm paints ``Replace
    firmware.s19?`` → RED. RED (base): no question."""
    scene = _scene(tmp_path)

    async def project_open(app, pilot, log):
        await _open_project(pilot, app, "P")
        await _patch(pilot, app)
        await _ask(pilot, app, lambda: app._handle_load_dialog(LC("project", "Q")))
        title = q_title(app)
        await _answer(pilot, app, "n")
        return title

    async def image_only(app, pilot, log):
        await _load(pilot, app, scene.src / "fw.s19")
        await _patch(pilot, app)
        await _ask(pilot, app, lambda: app._handle_load_dialog(LC("path", str(scene.src / "b.s19"))))
        title = q_title(app)
        await _answer(pilot, app, "n")
        return title

    async def neither(app, pilot, log):
        assert app.current_file is None and app.current_project is None
        await _set_f(pilot, app)
        await _ask(pilot, app, lambda: app._handle_load_dialog(LC("project", "Q")))
        title = q_title(app)
        await _answer(pilot, app, "n")
        return title

    assert _run(scene.base, project_open) == "Replace P?"
    assert _run(scene.base, image_only) == "Replace fw.s19?"
    assert _run(scene.base, neither) == "Replace the current session?"


def test_tc_b100_45_unsaved_image_is_named_by_its_file_name(tmp_path: Path) -> None:
    """LLR-174.2l (C17, C23): D with ``fw.s19`` loaded and no project → the
    body names ``fw.s19`` for a data load and for a project load (2 of 2).

    Why: the engineer recognises the work by the file it lives in.
    Negative control: the project named instead of the image → the
    data-load arm (no project) misses ``fw.s19`` → RED. RED (base): no
    question."""
    scene = _scene(tmp_path)

    async def scenario(app, pilot, log):
        await _load(pilot, app, scene.src / "fw.s19")
        await _patch(pilot, app)
        bodies = []
        for trigger in (
            lambda: app._handle_load_dialog(LC("path", str(scene.src / "b.s19"))),
            lambda: app._handle_load_dialog(LC("project", "Q")),
        ):
            await _ask(pilot, app, trigger)
            bodies.append(q_body(app))
            await _answer(pilot, app, "n")
        return bodies

    bodies = _run(scene.base, scenario)
    assert bodies[0] == "There are unsaved changes in fw.s19. Load b.s19 anyway?", bodies
    assert bodies[1] == "There are unsaved changes in fw.s19. Load project Q anyway?", bodies


def test_tc_b100_45_patch_editor_entries_named_only_when_w(tmp_path: Path) -> None:
    """LLR-174.2m (C20, C24): a project load with W only (an entry edit) →
    ``Patch Editor entries`` named; W only from an unparsed paste buffer →
    named; D only → not named (3 arms).

    Why: unsaved Patch Editor work is lost by a project load, and only
    then is it named.
    Negative control: the document item named on D → present in the D-only
    arm → RED. RED (base): no question."""
    from textual.widgets import TextArea

    scene = _scene(tmp_path)

    async def scenario(app, pilot, log):
        await _load(pilot, app, scene.src / "fw.s19")
        out = {}
        await _set_w(pilot, app)
        await _ask(pilot, app, lambda: app._handle_load_dialog(LC("project", "Q")))
        out["W entry"] = q_body(app)
        await _answer(pilot, app, "n")
        _panel(app).mark_saved()
        _panel(app).query_one("#patch_paste_text", TextArea).insert("draft")
        await _settle(pilot, 4)
        assert _panel(app)._dirty, "setup: the paste buffer did not set W"
        await _ask(pilot, app, lambda: app._handle_load_dialog(LC("project", "Q")))
        out["W paste"] = q_body(app)
        await _answer(pilot, app, "n")
        _panel(app).mark_loaded()
        await _patch(pilot, app)
        await _ask(pilot, app, lambda: app._handle_load_dialog(LC("project", "Q")))
        out["D only"] = q_body(app)
        await _answer(pilot, app, "n")
        return out

    out = _run(scene.base, scenario)
    assert out["W entry"] == "There are unsaved changes in Patch Editor entries. Load project Q anyway?", out
    assert "Patch Editor entries" in out["W paste"], out
    assert "Patch Editor entries" not in out["D only"], out


def test_tc_b100_45_flow_item_named_with_its_flow_name(tmp_path: Path) -> None:
    """LLR-174.2n (C18, C19): a project load with F and the flow
    ``patch_chain`` → ``flow patch_chain``; F with the default name →
    ``flow flow``; D only → no ``flow `` item (3 of 3).

    Why: the Flow Builder keeps its edits across a project load (ruling
    Q1), but they are unsaved, and the engineer must know which flow.
    Negative control: the flow item dropped → the F arm misses it → RED.
    RED (base): no question."""
    scene = _scene(tmp_path)

    async def scenario(app, pilot, log):
        await _load(pilot, app, scene.src / "fw.s19")
        out = {}
        for label, name in (("named", "patch_chain"), ("default", None)):
            if name is None:
                _flow(app)._flow_name = "flow"
            await _set_f(pilot, app, name)
            await _ask(pilot, app, lambda: app._handle_load_dialog(LC("project", "Q")))
            out[label] = q_body(app)
            await _answer(pilot, app, "n")
        _flow(app).mark_saved("flow")
        await _patch(pilot, app)
        await _ask(pilot, app, lambda: app._handle_load_dialog(LC("project", "Q")))
        out["D only"] = q_body(app)
        await _answer(pilot, app, "n")
        return out

    out = _run(scene.base, scenario)
    assert out["named"] == "There are unsaved changes in flow patch_chain. Load project Q anyway?", out
    assert out["default"] == "There are unsaved changes in flow flow. Load project Q anyway?", out
    assert "flow " not in out["D only"], out


def test_tc_b100_45_load_target_named_per_route(tmp_path: Path) -> None:
    """LLR-174.2o (C22): a project row ``Q`` → ``Load project Q anyway?``; a
    typed ``<tmp>/b.s19`` → ``Load b.s19 anyway?``; a Workarea pick
    ``x.hex`` → ``Load x.hex anyway?``; a variant switch to ``firmware_b`` →
    ``Load firmware_b.s19 anyway?`` (4 of 4).

    Why: the question must say what replaces the work.
    Negative control: the current file named as the target → the typed arm
    paints the old name → RED. RED (base): no question."""
    scene = _scene(tmp_path)

    async def scenario(app, pilot, log):
        await _open_project(pilot, app, "PV")
        await _patch(pilot, app)
        ends = {}
        triggers = {
            "project": lambda: app._handle_load_dialog(LC("project", "Q")),
            "typed": lambda: app._handle_load_dialog(LC("path", str(scene.src / "b.s19"))),
            "workarea": lambda: app._load_from_item(types.SimpleNamespace(data="x.hex")),
            "variant": lambda: app._handle_select_variant("firmware_b"),
        }
        for name, trigger in triggers.items():
            await _ask(pilot, app, trigger)
            ends[name] = q_body(app).split(". ", 1)[-1]
            await _answer(pilot, app, "n")
        return ends

    ends = _run(scene.base, scenario)
    assert ends == {
        "project": "Load project Q anyway?",
        "typed": "Load b.s19 anyway?",
        "workarea": "Load x.hex anyway?",
        "variant": "Load firmware_b.s19 anyway?",
    }, ends


def test_tc_b100_45_body_says_unsaved_changes_once_in_two_sentences(tmp_path: Path) -> None:
    """LLR-174.2q, HLR-174d (C18, C19, C25): with 1, 2 and 3 items the body
    holds ``unsaved changes`` once and 2 sentence ends outside the names;
    the 2- and 3-item bodies read exactly ``There are unsaved changes in
    fw.s19 and flow patch_chain. Load project Q anyway?`` and ``There are
    unsaved changes in fw.s19, Patch Editor entries and flow patch_chain.
    Load project Q anyway?`` (ruling Q-3), in one question each.

    Why: "short" made measurable — every item in one question, two
    sentences.
    Negative control: one sentence per item → the 3-item arm has 4 ends →
    RED; only the first item named → RED. RED (base): no question."""
    scene = _scene(tmp_path)

    async def scenario(app, pilot, log):
        await _load(pilot, app, scene.src / "fw.s19")
        await _patch(pilot, app)
        spy = PushSpy(app)
        bodies = []
        await _ask(pilot, app, lambda: app._handle_load_dialog(LC("path", str(scene.src / "b.s19"))))
        bodies.append(q_body(app))
        await _answer(pilot, app, "n")
        await _set_f(pilot, app, "patch_chain")
        await _ask(pilot, app, lambda: app._handle_load_dialog(LC("project", "Q")))
        bodies.append(q_body(app))
        await _answer(pilot, app, "n")
        await _set_w(pilot, app)
        await _ask(pilot, app, lambda: app._handle_load_dialog(LC("project", "Q")))
        bodies.append(q_body(app))
        await _answer(pilot, app, "n")
        return bodies, spy.questions()

    bodies, asked = _run(scene.base, scenario)
    assert asked == 3
    names = ["fw.s19", "b.s19", "patch_chain", "Q"]
    for body in bodies:
        assert body.count("unsaved changes") == 1, body
        assert _sentence_ends(body, names) == 2, body
    assert bodies[1] == "There are unsaved changes in fw.s19 and flow patch_chain. Load project Q anyway?"
    assert bodies[2] == (
        "There are unsaved changes in fw.s19, Patch Editor entries and flow patch_chain. "
        "Load project Q anyway?"
    )


@pytest.mark.parametrize(
    "size,which",
    [((99, 54), "long"), ((118, 54), "long"), ((220, 60), "long"), ((118, 54), "short")],
)
def test_tc_b100_45_buttons_and_body_stay_fully_visible(tmp_path: Path, size: tuple, which: str) -> None:
    """LLR-174.2r (Q2-5, C1-2): three 120-character names at 99x54, 118x54
    and 220x60, and one short item at 118x54 → ``#confirm_yes``,
    ``#confirm_no`` and ``#confirm_body`` each fully visible: the region
    equals its clipped region, lies inside the screen region and is not
    empty.

    Why: a button the engineer cannot see cannot be pressed, and a body cut
    short hides what would be lost.
    Negative control: ``min-width: 120`` on ``#confirm_box`` → at 99
    columns ``#confirm_no`` has 0 visible columns → RED; height 7 with the
    buttons undocked → 0 visible rows → RED. RED (base): no
    ``ConfirmQuestionScreen``."""
    args = LONGQ if which == "long" else LOADQ

    async def scenario(app, pilot, log):
        await _modal_alone(pilot, app, args)
        await _settle(pilot, 6)
        screen = app.screen
        out = {}
        for selector in ("#confirm_yes", "#confirm_no", "#confirm_body"):
            geo = screen.find_widget(screen.query_one(selector))
            out[selector] = (
                geo.region == geo.region.intersection(geo.clip),
                screen.region.contains_region(geo.region),
                geo.region.area > 0,
                tuple(geo.region),
            )
        return out

    out = _run(tmp_path / "app", scenario, size=size)
    bad = {k: v for k, v in out.items() if v[:3] != (True, True, True)}
    assert bad == {}, f"not fully visible at {size}: {bad}"


def test_tc_b100_45_a_second_answer_is_ignored(tmp_path: Path) -> None:
    """LLR-174.2s (Q5-1, Q5-2, A10-03): two answers in one tick
    (``action_answer(True)`` then ``action_answer(False)``) → 1 callback
    ``True``, 1 pop, 0 exceptions; ``y`` then ``n`` posted back to back → 1
    answer ``True`` and the main screen still on the stack.

    Why: a second dismiss pops the screen under the question (or raises);
    a double key must never close two screens or load twice.
    Negative control: the ``_dismissed`` guard removed → ``ScreenStackError``
    (K7) → RED. RED (base): no ``ConfirmQuestionScreen``."""

    async def scenario(app, pilot, log):
        screen, answers = await _modal_alone(pilot, app)
        errors = []
        try:
            screen.action_answer(True)
            screen.action_answer(False)
        except Exception as exc:  # the double-pop shape
            errors.append(repr(exc))
        await _settle(pilot, 10)
        first = (list(answers), errors, _stack(app))
        _, answers2 = await _modal_alone(pilot, app)
        app.post_message(events.Key("y", "y"))
        app.post_message(events.Key("n", "n"))
        await _settle(pilot, 12)
        return first, (list(answers2), _stack(app))

    first, second = _run(tmp_path / "app", scenario)
    assert first == ([True], [], ["Screen"]), first
    assert second == ([True], ["Screen"]), second


def test_tc_b100_45_change_file_dropdown_keeps_the_guard(tmp_path: Path) -> None:
    """LLR-174.2t (C59, S10-02, A10-R2-3): 2 unsaved entries, a pick of
    ``second.json`` in ``#patch_doc_file_select`` → 1 ``LoadGuardScreen``, 0
    loads, the entry count and the flag unchanged; cancel → the same, and
    the dropdown is blank again, so a pick of the same file fires the guard
    again; a clean panel → the same pick loads with 0 guards (the document
    becomes the file's 1 entry, the flag clear).

    Why: the dropdown is a second way into the Patch Editor's document
    load; without the guard it replaces unsaved entries silently.
    Negative control: no ``is_dirty`` read → the dirty pick replaces the
    entries with 0 guards → RED (the base). A cancel that leaves the
    dropdown on ``second.json`` → the second pick fires nothing → RED."""
    from textual.widgets import Select

    from s19_app.tui.screens_directionb import LoadGuardScreen

    scene = _scene(tmp_path)

    async def scenario(app, pilot, log):
        patches = app._patches_dir()
        patches.mkdir(parents=True, exist_ok=True)
        (patches / "second.json").write_bytes(projects.change_document_bytes())
        await _load(pilot, app, scene.src / "fw.s19")
        await pilot.press("6")
        await ld.wait_for(pilot, lambda: len(app.query("#patch_doc_file_select")) > 0, "the Patch Editor")
        await _settle(pilot, 6)
        app._change_service.add_entry("0x80000010", "", "01")
        app._change_service.add_entry("0x80000020", "", "02")
        await _set_w(pilot, app)
        loads = []
        real_load = app._patch_editor_load

        def spy_load(panel, path_text):
            loads.append(Path(path_text).name)
            return real_load(panel, path_text)

        app._patch_editor_load = spy_load
        select = _panel(app).query_one("#patch_doc_file_select", Select)
        spy = PushSpy(app)
        out = {}
        for attempt in ("first", "again"):
            select.value = "second.json"
            await _settle(pilot, 8)
            guarded = isinstance(app.screen, LoadGuardScreen)
            out[attempt] = (guarded, list(loads), len(app._change_service.document.entries), _panel(app)._dirty)
            if guarded:
                await pilot.press("escape")
                await ld.wait_for(pilot, lambda: not isinstance(app.screen, LoadGuardScreen), "the guard closed")
                await _settle(pilot, 4)
            out[attempt + " after cancel"] = (
                select.is_blank(),
                len(app._change_service.document.entries),
                _panel(app)._dirty,
            )
        guards_dirty = spy.names.count("LoadGuardScreen")
        _panel(app).mark_saved()
        select.value = "second.json"
        await _settle(pilot, 10)
        out["clean"] = (
            isinstance(app.screen, LoadGuardScreen),
            list(loads),
            len(app._change_service.document.entries),
            _panel(app)._dirty,
        )
        return out, guards_dirty

    out, guards_dirty = _run(scene.base, scenario)
    assert out["first"] == (True, [], 2, True), out
    assert out["first after cancel"] == (True, 2, True), out
    assert out["again"] == (True, [], 2, True), out
    assert guards_dirty == 2, out
    assert out["clean"] == (False, ["second.json"], 1, False), out


def test_tc_b100_45_modal_imports_nothing_from_the_app() -> None:
    """S-a (Q1-6, D-GA10-2): the ``ConfirmQuestionScreen`` class body uses 0
    names imported from ``s19_app.tui.app``, ``.services`` or
    ``.workspace``, and holds 0 string literals matching a decision id.

    Why: Inc 12 reuses the modal for its quit question; the modal paints
    only its parameters, so the scrub and the wording stay in one place.
    Negative control: ``painted_names`` called inside the screen → census 1
    → RED. RED (base): the class does not exist."""
    screens_path = Path(app_module.__file__).resolve().parent / "screens.py"
    tree = ast.parse(screens_path.read_text(encoding="utf-8"))
    banned = set()
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            # Only the project's own modules (a relative import or an
            # ``s19_app`` path): ``textual.app`` is a library, not the app.
            if node.level == 0 and not (node.module or "").startswith("s19_app"):
                continue
            module = ("." * node.level) + (node.module or "")
            if re.search(r"(^|\.)(app|services|workspace)(\.|$)", module):
                banned.update(alias.asname or alias.name for alias in node.names)
    classes = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "ConfirmQuestionScreen"]
    assert len(classes) == 1, "ConfirmQuestionScreen is not defined once in screens.py"
    used = {n.id for n in ast.walk(classes[0]) if isinstance(n, ast.Name)}
    assert used & banned == set(), sorted(used & banned)
    docstrings = set()
    for node in ast.walk(classes[0]):
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                docstrings.add(id(first.value))
    literals = [
        n.value for n in ast.walk(classes[0])
        if isinstance(n, ast.Constant) and isinstance(n.value, str)
        and id(n) not in docstrings and DECISION_ID.search(n.value)
    ]
    assert literals == [], literals


# ---------------------------------------------------------------------------
# TC-B100-46 — the answer comes before the reset (LLR-174.3 … LLR-174.3d)
# ---------------------------------------------------------------------------


def _spy_reset(app, events_list: list) -> None:
    real = app._reset_project_session

    def spy():
        events_list.append(("reset", any(is_question(s) for s in app.screen_stack)))
        return real()

    app._reset_project_session = spy


def test_tc_b100_46_reset_runs_after_the_answer(tmp_path: Path) -> None:
    """LLR-174.3 (C07): P open with W; a project load of Q → ``y`` → the
    order is [question pushed, reset] with no question on the stack at the
    reset, 1 reset; re-loading the open project with W → the same (2 of 2).

    Why: the reset discards the Patch Editor document; running it before
    the engineer answers loses the work even when the answer is cancel.
    Negative control: the reset before asking → [reset, question] → RED.
    RED (base): no question."""
    scene = _scene(tmp_path)

    async def scenario(app, pilot, log):
        await _open_project(pilot, app, "P")
        order: list = []
        _spy_reset(app, order)
        real_push = app.push_screen

        def push(screen, *args, **kwargs):
            if is_question(screen):
                order.append(("question", True))
            return real_push(screen, *args, **kwargs)

        app.push_screen = push
        out = []
        for target in ("Q", "Q"):
            await _set_w(pilot, app)
            mark = len(order)
            await _ask(pilot, app, lambda target=target: app._handle_load_dialog(LC("project", target)))
            await pilot.press("y")
            await ld.wait_for(pilot, lambda: any(e[0] == "reset" for e in order[mark:]), "the reset")
            await _close_result_panel(pilot, app)
            out.append(order[mark:])
        return out, app.current_project

    out, project = _run(scene.base, scenario)
    assert out == [[("question", True), ("reset", False)]] * 2, out
    assert project == "Q"


def test_tc_b100_46_cancel_keeps_the_session_and_runs_no_reset(tmp_path: Path) -> None:
    """LLR-174.3a, HLR-174c (C04): a project load with D, F and W, and a
    data load with D; each cancelled by ``n``, ``escape`` and an immediate
    ``enter`` → the session digest and the kept work (entries, Patch
    Editor flag, Flow Builder blocks and flag, recent store) unchanged, 0
    resets, 0 status lines (6 of 6).

    Why: cancel means nothing happened.
    Negative control: a mutation that runs ``go`` (or the reset) before
    pushing → the cancelled project arm finds the Patch Editor empty → RED.
    RED (base): no question."""
    scene = _scene(tmp_path)

    async def scenario(app, pilot, log):
        await _load(pilot, app, scene.src / "fw.s19")
        await _patch(pilot, app)
        await _set_w(pilot, app)
        await _set_f(pilot, app, "patch_chain")
        resets: list = []
        _spy_reset(app, resets)
        out = []
        for route in ("project", "data"):
            for key in ("n", "escape", "enter"):
                before = _kept(app)
                mark = len(log.messages)
                if route == "project":
                    trigger = lambda: app._handle_load_dialog(LC("project", "Q"))  # noqa: E731
                else:
                    trigger = lambda: app._handle_load_dialog(LC("path", str(scene.src / "b.s19")))  # noqa: E731
                await _ask(pilot, app, trigger)
                await _answer(pilot, app, key)
                await _settle(pilot, 6)
                out.append((route, key, before == _kept(app), log.since(mark)))
        return out, resets

    out, resets = _run(scene.base, scenario)
    assert resets == [], resets
    bad = [arm for arm in out if not arm[2] or arm[3]]
    assert len(out) == 6 and bad == [], bad


def test_tc_b100_46_project_load_handler_asks_nothing(tmp_path: Path) -> None:
    """LLR-174.3b (C49): a direct ``_handle_load_project("P")`` with D, F and
    W → 0 questions and P loaded; the same state through the project route
    → 1 question (the guard lives in the route); the handler's body holds 0
    calls of ``push_screen`` and of ``_confirm_then_load``.

    Why: 13 test files and the fixtures call the handler directly; a guard
    inside it would leave them waiting on a modal.
    Negative control: the guard moved into the handler → the direct call
    pushes 1 question → RED. RED (base): the route asks nothing."""
    scene = _scene(tmp_path)

    async def scenario(app, pilot, log):
        await _load(pilot, app, scene.src / "fw.s19")
        await _patch(pilot, app)
        await _set_w(pilot, app)
        await _set_f(pilot, app)
        spy = PushSpy(app)
        await _open_project(pilot, app, "P")
        direct = (spy.questions(), app.current_project)
        await _patch(pilot, app)
        await _set_w(pilot, app)
        await _ask(pilot, app, lambda: app._route_load_project("Q"))
        route = spy.questions()
        await _answer(pilot, app, "n")
        return direct, route

    direct, route = _run(scene.base, scenario)
    assert direct == (0, "P"), direct
    assert route == 1, route
    tree = ast.parse(Path(app_module.__file__).read_text(encoding="utf-8"))
    handler = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.name == "_handle_load_project"
    )
    calls = [
        n.func.attr for n in ast.walk(handler)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
        and n.func.attr in ("push_screen", "_confirm_then_load")
    ]
    assert calls == [], calls
    assert hasattr(app_module.S19TuiApp, "_confirm_then_load")


def test_tc_b100_46_refused_project_after_yes_keeps_the_work(tmp_path: Path) -> None:
    """LLR-174.3c (C30): a listed project ``M2`` (1 data file, 2 MAC files)
    with D and W → 1 question → ``y`` → 1 new status line (the refusal), 0
    resets, the session digest unchanged, D still true, W still true, the
    entry count unchanged, 0 Load-result panels (5 of 5).

    Why: a load the engineer confirmed but the project then refuses must
    not have thrown the work away first.
    Negative control: the flags cleared or the reset run on ``y`` → D or W
    false after the refusal → RED. RED (base): no question."""
    scene = _scene(tmp_path)

    async def scenario(app, pilot, log):
        await _load(pilot, app, scene.src / "fw.s19")
        await _patch(pilot, app)
        await _set_w(pilot, app)
        resets: list = []
        _spy_reset(app, resets)
        spy = PushSpy(app)
        before = _digest(app)
        entries = len(app._change_service.document.entries)
        await _ask(pilot, app, lambda: app._handle_load_dialog(LC("project", "M2")))
        mark = len(log.messages)
        await pilot.press("y")
        await ld.wait_for(pilot, lambda: len(log.since(mark)) > 0, "the refusal line")
        await _settle(pilot, 10)
        return (
            log.since(mark), resets, before == _digest(app), _D(app), _panel(app)._dirty,
            len(app._change_service.document.entries) == entries, spy.names.count("LoadResultScreen"),
        )

    lines, resets, same, d, w, entries_same, panels = _run(scene.base, scenario)
    assert len(lines) == 1, lines
    assert resets == [] and same and d and w and entries_same and panels == 0, (
        resets, same, d, w, entries_same, panels
    )


@WINDOWS_ONLY
def test_tc_b100_46_unreadable_a2l_project_after_yes_keeps_the_work(tmp_path: Path) -> None:
    """LLR-174.3c S10-01 arm (C58 with S10-06): image ``fw.s19`` with 2
    unsaved Patch Editor entries applied (D) and the panel flag (W); a
    project ``A2LONLY`` whose one A2L is held exclusively (unreadable) → 1
    question → ``y`` → 1 line ``No supported files in project: A2LONLY``, 0
    resets, ``current_file`` still ``fw.s19``, the entry count still 2, W
    still true, D still true (5 of 5).

    Why: the A2L read and the all-``None`` check must run before the reset,
    or a confirmed load that is then refused has already emptied the
    session.
    Negative control: the base order (the reset before the A2L read) →
    after ``y`` ``current_file`` is ``None``, 0 entries, W false → RED.
    RED (base): no question."""
    scene = _scene(tmp_path)
    a2l_only = _project(scene.wa, "A2LONLY", {"cal.a2l": (CASE01 / "firmware.a2l").read_bytes()})

    async def scenario(app, pilot, log):
        await _load(pilot, app, scene.src / "fw.s19")
        app._change_service.add_entry("0x80000010", "", "01")
        app._change_service.add_entry("0x80000020", "", "02")
        cur = app.current_file
        app._change_service.apply(cur.mem_map, cur.ranges, cur.mac_records, None)
        await _settle(pilot, 4)
        assert _D(app), "setup: the Apply did not make D true (S10-06)"
        await _set_w(pilot, app)
        resets: list = []
        _spy_reset(app, resets)
        with projects.held_exclusively(a2l_only / "cal.a2l"):
            await _ask(pilot, app, lambda: app._handle_load_dialog(LC("project", "A2LONLY")))
            mark = len(log.messages)
            await pilot.press("y")
            await ld.wait_for(
                pilot,
                lambda: any("No supported files in project" in m for m in log.since(mark)),
                "the refusal line",
            )
            await _settle(pilot, 10)
        return (
            [m for m in log.since(mark) if "No supported files in project" in m], resets,
            None if app.current_file is None else Path(app.current_file.path).name,
            len(app._change_service.document.entries), _panel(app)._dirty, _D(app),
        )

    lines, resets, current, entries, w, d = _run(scene.base, scenario)
    assert lines == ["No supported files in project: A2LONLY"], lines
    assert (resets, current, entries, w, d) == ([], "fw.s19", 2, True, True), (resets, current, entries, w, d)


def test_tc_b100_46_cancelled_variant_switch_keeps_the_pending_selection(tmp_path: Path) -> None:
    """LLR-174.3d (C42, E2-rulings P-3): project PV (``firmware_a`` active)
    patched; a switch to ``firmware_b`` → ``n`` → ``_pending_variant_id``
    still ``None``, 0 ``load_from_path`` calls, ``firmware_a`` still active;
    then a Workarea pick of ``other.s19`` answered ``y`` → after the install
    ``current_file.variant_id`` is ``None`` and ``firmware_a`` still active
    (2 of 2).

    Why: a stamp left by a cancelled switch labels the next unrelated file
    as that variant and makes it active.
    Negative control: the stamp set before the seam (the base order) →
    ``firmware_b`` after ``n`` and ``other.s19`` stamped → RED. RED (base):
    no question."""
    scene = _scene(tmp_path)

    async def scenario(app, pilot, log):
        await _open_project(pilot, app, "PV")
        assert app._variant_set.active_id == "firmware_a"
        await _patch(pilot, app)
        calls = []
        real = app.load_from_path

        def spy(path, *args, **kwargs):
            calls.append(Path(path).name)
            return real(path, *args, **kwargs)

        app.load_from_path = spy
        await _ask(pilot, app, lambda: app._handle_select_variant("firmware_b"))
        await _answer(pilot, app, "n")
        await _settle(pilot, 6)
        cancelled = (app._pending_variant_id, list(calls), app._variant_set.active_id)
        await _ask(pilot, app, lambda: app._load_from_item(types.SimpleNamespace(data="other.s19")))
        await pilot.press("y")
        await ld.wait_for(pilot, lambda: Path(app.current_file.path).name == "other.s19", "the install of other.s19")
        await _settle(pilot, 8)
        return cancelled, (app.current_file.variant_id, app._variant_set.active_id)

    cancelled, after = _run(scene.base, scenario)
    assert cancelled == (None, [], "firmware_a"), cancelled
    assert after == (None, "firmware_a"), after


# ---------------------------------------------------------------------------
# TC-B100-72 — one seam for every route (LLR-174.4 … LLR-174.4c)
# ---------------------------------------------------------------------------


async def _pick_in_files_list(pilot, app, name: str) -> None:
    """Workspace (``1``), ``tab`` until ``#files_list`` holds the focus,
    then the arrow keys and ``enter`` (keys only: a click on a row would
    itself select it)."""
    from textual.widgets import ListItem, ListView

    await pilot.press("1")
    await _settle(pilot, 4)
    for _ in range(40):
        if _focused_id(app) == "files_list":
            break
        await pilot.press("tab")
        await pilot.pause()
    lst = app.query_one("#files_list", ListView)
    assert _focused_id(app) == "files_list", _focused_id(app)
    names = [getattr(item, "data", None) for item in lst.query(ListItem)]
    assert name in names, names
    target = names.index(name)
    for _ in range(2 * len(names) + 2):
        if lst.index == target:
            break
        await pilot.press("down" if lst.index is None or lst.index < target else "up")
        await pilot.pause()
    await pilot.press("enter")


async def _switch_variant_by_keys(pilot, app) -> None:
    """``v``, the arrow key to the second variant, then Activate."""
    await pilot.press("v")
    await ld.wait_for(pilot, lambda: type(app.screen).__name__ == "SelectVariantScreen", "the variant selector")
    await _settle(pilot, 4)
    await pilot.press("down")
    await pilot.pause()
    assert await pilot.click("#variant_ok"), "click missed #variant_ok"


def test_tc_b100_72_every_route_asks_and_cancel_keeps_the_session(tmp_path: Path) -> None:
    """LLR-174.4, HLR-174 (C02, C41): with an unsaved patch, the Load dialog
    (typed path), a Workarea Files pick and ``v``, all by keys, and the
    Load-result panel's ``v`` with D forced through a private call
    (declared, ruling Q5: by keys the panel opens only right after a
    project load, which records the image as saved) → 4 questions, each
    pushed before the session changed; ``n`` on each → the digest
    unchanged (4 + 4).

    Why: B-02 / QA R2-03: the Workarea pick and the variant switch bypassed
    the dialog's route and replaced a patched image silently.
    Negative control: the base tree → each route replaces the image with
    the stack ``['Screen']`` → RED."""
    scene = _scene(tmp_path)

    async def scenario(app, pilot, log):
        out = {}
        spy = PushSpy(app)
        app._route_load_project("PV")
        await ld.wait_for(pilot, lambda: len(app.screen.query("#result_ok")) > 0, "the Load-result panel")
        await _settle(pilot, 4)
        service = app._change_service
        service.differs_from_last_saved = lambda mem_map: True  # forced D (declared)
        before = _digest(app)
        await pilot.press("v")
        await ld.wait_for(pilot, lambda: type(app.screen).__name__ == "SelectVariantScreen", "the variant selector")
        await _settle(pilot, 4)
        await pilot.press("down")
        await pilot.pause()
        assert await pilot.click("#variant_ok")
        await _wait_question(pilot, app)
        on_top = _digest(app)
        await _answer(pilot, app, "n")
        out["panel v"] = (on_top == before, _digest(app) == before, app._variant_set.active_id)
        del service.differs_from_last_saved
        await _patch(pilot, app)
        for route in ("load dialog", "workarea", "v"):
            before = _digest(app)
            mark = spy.questions()
            if route == "load dialog":
                await pilot.press("ctrl+l")
                await ld.wait_for_dialog(pilot, app)
                await ld.type_into_path(pilot, app, str(scene.src / "b.s19"))
                assert await pilot.click("#load_ok")
            elif route == "workarea":
                await _pick_in_files_list(pilot, app, "x.s19")
            else:
                await pilot.press("1")
                await _settle(pilot, 4)
                await _switch_variant_by_keys(pilot, app)
            await _wait_question(pilot, app)
            on_top = _digest(app)
            await _answer(pilot, app, "n")
            await _settle(pilot, 6)
            out[route] = (on_top == before, _digest(app) == before, spy.questions() - mark)
        return out

    out = _run(scene.base, scenario)
    assert out["panel v"] == (True, True, "firmware_a"), out
    for route in ("load dialog", "workarea", "v"):
        assert out[route] == (True, True, 1), (route, out[route])


def _replace_arm(root: Path, route: str) -> tuple:
    scene = _scene(root)

    async def scenario(app, pilot, log):
        if route in ("v", "panel v"):
            await _open_project(pilot, app, "PV")
        else:
            await _load(pilot, app, scene.src / "fw.s19")
        if route == "panel v":
            app._route_load_project("PV")
            await ld.wait_for(pilot, lambda: len(app.screen.query("#result_ok")) > 0, "the Load-result panel")
            await _settle(pilot, 4)
            app._change_service.differs_from_last_saved = lambda mem_map: True  # forced D (declared)
            await pilot.press("v")
            await ld.wait_for(pilot, lambda: type(app.screen).__name__ == "SelectVariantScreen", "the selector")
            await _settle(pilot, 4)
            await pilot.press("down")
            await pilot.pause()
            assert await pilot.click("#variant_ok")
        else:
            await _patch(pilot, app)
            if route == "load dialog":
                app._handle_load_dialog(LC("path", str(scene.src / "b.s19")))
            elif route == "workarea":
                app._load_from_item(types.SimpleNamespace(data="x.s19"))
            elif route == "project":
                app._handle_load_dialog(LC("project", "Q"))
            else:
                app._handle_select_variant("firmware_b")
        await _wait_question(pilot, app)
        await pilot.press("y")
        expected = {"load dialog": "b.s19", "workarea": "x.s19", "v": "firmware_b.s19",
                    "panel v": "firmware_b.s19", "project": "Q"}[route]
        if route == "project":
            await ld.wait_for(pilot, lambda: app.current_project == "Q", "the project load of Q")
            got = app.current_project
        else:
            await ld.wait_for(
                pilot, lambda: Path(app.current_file.path).name == expected, f"the load of {expected}"
            )
            got = Path(app.current_file.path).name
        await _settle(pilot, 4)
        return got, expected, any(is_question(s) for s in app.screen_stack)

    return _run(scene.base, scenario)


@pytest.mark.parametrize("route", ["load dialog", "workarea", "v", "panel v", "project"])
def test_tc_b100_72_replace_runs_the_load_on_every_route(tmp_path: Path, route: str) -> None:
    """HLR-174b, LLR-174.4 (C03): ``y`` on each route → 1 load of the
    requested item (``current_file.path.name`` or ``current_project`` equals
    the request) and the question closed (the 4 routes plus a project row).

    Why: replace must do exactly what the engineer asked for, once.
    Negative control: an answer that drops ``go`` on True → 0 loads → RED.
    RED (base): no question."""
    got, expected, open_after = _replace_arm(tmp_path, route)
    assert got == expected and not open_after, (got, expected, open_after)


def _seam_bypasses() -> list:
    """LLR-174.4 census (E2 P-2 / A10-08): every call of the three loaders
    and ``_handle_load_project`` in ``app.py`` must be inside a function
    passed as ``go`` to ``_confirm_then_load``, inside
    ``_handle_load_project``, or inside ``load_from_path`` (its worker
    start). ``_route_load_project`` is the project seam: its callers are
    exempt."""
    loaders = {"load_selected_file", "load_from_path", "load_a2l_from_path", "_handle_load_project"}
    tree = ast.parse(Path(app_module.__file__).read_text(encoding="utf-8"))
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "S19TuiApp")
    bypasses = []

    def go_nodes(func: ast.AST) -> set:
        """The lambdas / nested defs / names passed as ``go`` in ``func``."""
        lambdas, names = set(), set()
        for call in ast.walk(func):
            if (
                isinstance(call, ast.Call)
                and isinstance(call.func, ast.Attribute)
                and call.func.attr == "_confirm_then_load"
            ):
                args = list(call.args[2:3]) + [k.value for k in call.keywords if k.arg == "go"]
                for arg in args:
                    if isinstance(arg, ast.Lambda):
                        lambdas.add(arg)
                    elif isinstance(arg, ast.Name):
                        names.add(arg.id)
        allowed = set(lambdas)
        for node in ast.walk(func):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in names and node is not func:
                allowed.add(node)
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Lambda):
                if any(isinstance(t, ast.Name) and t.id in names for t in node.targets):
                    allowed.add(node.value)
        return allowed

    for method in cls.body:
        if not isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if method.name in ("_handle_load_project", "load_from_path"):
            continue
        allowed = go_nodes(method)

        def visit(node, inside: bool):
            if node in allowed:
                inside = True
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in loaders
                and not inside
            ):
                bypasses.append(f"{method.name}:{node.lineno}:{node.func.attr}")
            for child in ast.iter_child_nodes(node):
                visit(child, inside)

        visit(method, False)
    return bypasses


def test_tc_b100_72_every_load_call_passes_the_seam() -> None:
    """LLR-174.4 (C05, C01): AST census of ``app.py`` → 0 bypasses; each of
    the four leaves (``_route_load_project``, ``_load_path_from_user_input``,
    ``_load_workarea_file``, ``_handle_select_variant``) calls the seam, and
    the 9b router ``_handle_load_dialog`` does not (S-d: the seam sits in
    the leaves, so one request meets it once).

    Why: a loader called outside the seam is a route that replaces work
    without asking — the B-02 class of defect.
    Negative control: the base tree → 6 bypasses (``_route_load_project``,
    ``_handle_select_variant``, ``_load_path_from_user_input`` x2,
    ``_load_workarea_file`` x2) → RED."""
    bypasses = _seam_bypasses()
    assert bypasses == [], bypasses
    tree = ast.parse(Path(app_module.__file__).read_text(encoding="utf-8"))
    funcs = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}

    def seam_calls(name: str) -> int:
        return sum(
            1 for n in ast.walk(funcs[name])
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            and n.func.attr == "_confirm_then_load"
        )

    leaves = {name: seam_calls(name) for name in (
        "_route_load_project", "_load_path_from_user_input", "_load_workarea_file", "_handle_select_variant")}
    assert all(count >= 1 for count in leaves.values()), leaves
    assert seam_calls("_handle_load_dialog") == 0


def test_tc_b100_72_one_question_per_request(tmp_path: Path) -> None:
    """LLR-174.4a (C06): with D and W, a recent data path → 1 question; a
    typed absolute project folder ``<W>/P`` (router, typed-path route, then
    the project route) → 1; a project row → 1 (3 of 3); after ``y`` on
    each, 0 further questions until the load ends.

    Why: a request that passes two routing functions must not ask twice.
    Negative control: the dialog router and the project route both guarded
    → the typed project folder asks twice → RED. RED (base): no
    question."""
    scene = _scene(tmp_path)

    async def scenario(app, pilot, log):
        await _load(pilot, app, scene.src / "other.s19")
        spy = PushSpy(app)
        out = {}
        requests = {
            "recent": (lambda: app._handle_load_dialog(LC("recent", str(scene.src / "fw.s19"))),
                       lambda: Path(app.current_file.path).name == "fw.s19"),
            "typed project": (lambda: app._handle_load_dialog(LC("path", str(scene.wa / "P"))),
                              lambda: app.current_project == "P"),
            "project row": (lambda: app._handle_load_dialog(LC("project", "Q")),
                            lambda: app.current_project == "Q"),
        }
        for name, (trigger, landed) in requests.items():
            await _patch(pilot, app)
            await _set_w(pilot, app)
            mark = spy.questions()
            await _ask(pilot, app, trigger)
            await pilot.press("y")
            await ld.wait_for(pilot, landed, f"the {name} load")
            await _settle(pilot, 10)
            out[name] = spy.questions() - mark
            if len(app.screen.query("#result_ok")) > 0:
                await _close_result_panel(pilot, app)
        return out

    out = _run(scene.base, scenario)
    assert out == {"recent": 1, "typed project": 1, "project row": 1}, out


def test_tc_b100_72_typed_path_takes_its_kind_from_the_classification(tmp_path: Path) -> None:
    """LLR-174.4b (C33, C34, C35): with D and W, typed through the dialog:
    ``typed.mac`` → 0 questions (attach, the patched byte kept, D true);
    ``typed2.MAC`` → 0; the quoted ``"<src>/typed.mac"`` → 0; ``cal.a2l``
    → 0; ``b.s19`` → 1 question ``There are unsaved changes in fw.s19.
    Load b.s19 anyway?``; ``  <src>/b.s19  `` (padded) → 1, ending ``Load
    b.s19 anyway?``; ``<W>/P`` → 1 naming ``Patch Editor entries``; a typed
    file removed before routing → 0 questions and 1 ``not found`` line.

    Why: the kind comes from what the typed text names, not from how it was
    typed; a MAC attach keeps the image.
    Negative control: the kind keyed on the dismiss kind (``path`` →
    image) → the ``.mac`` arm asks → RED; the MAC test on the raw quoted
    text → the quoted MAC asks → RED. RED (base): the ``.s19`` arm asks
    nothing."""
    scene = _scene(tmp_path)
    gone = scene.src / "gone.s19"

    async def scenario(app, pilot, log):
        await _load(pilot, app, scene.src / "fw.s19")
        address = await _patch(pilot, app)
        byte = app.current_file.mem_map[address]
        await _set_w(pilot, app)
        spy = PushSpy(app)
        out = {}
        attaches = {
            "typed.mac": (str(scene.src / "typed.mac"), lambda: _mac_name(app) == "typed.mac"),
            "typed2.MAC": (str(scene.src / "typed2.MAC"), lambda: _mac_name(app) == "typed2.MAC"),
            "quoted mac": ('"' + str(scene.src / "typed.mac") + '"', lambda: _mac_name(app) == "typed.mac"),
            "cal.a2l": (str(scene.src / "cal.a2l"), lambda: app.current_a2l_path is not None),
        }
        for name, (text, landed) in attaches.items():
            if name == "quoted mac":
                app._handle_load_dialog(LC("path", str(scene.src / "typed2.MAC")))
                await ld.wait_for(pilot, lambda: _mac_name(app) == "typed2.MAC", "reset the MAC")
                await _settle(pilot, 4)
            mark = spy.questions()
            app._handle_load_dialog(LC("path", text))
            await ld.wait_for(pilot, lambda: landed() or is_question(app.screen), f"the {name} attach")
            await _settle(pilot, 6)
            asked = spy.questions() - mark
            if is_question(app.screen):
                await _answer(pilot, app, "n")
            out[name] = (asked, app.current_file.mem_map.get(address) == byte, _D(app))
        for name, text in (
            ("b.s19", str(scene.src / "b.s19")),
            ("padded", "  " + str(scene.src / "b.s19") + "  "),
            ("project", str(scene.wa / "P")),
        ):
            mark = spy.questions()
            await _ask(pilot, app, lambda text=text: app._handle_load_dialog(LC("path", text)))
            out[name] = (spy.questions() - mark, q_body(app))
            await _answer(pilot, app, "n")
        gone.write_bytes(b"S9030000FC\n")
        gone.unlink()
        mark, line_mark = spy.questions(), len(log.messages)
        app._handle_load_dialog(LC("path", str(gone)))
        await ld.wait_for(pilot, lambda: len(log.since(line_mark)) > 0, "the refusal line")
        await _settle(pilot, 4)
        out["removed"] = (spy.questions() - mark, log.since(line_mark))
        return out

    out = _run(scene.base, scenario)
    for name in ("typed.mac", "typed2.MAC", "quoted mac", "cal.a2l"):
        assert out[name] == (0, True, True), (name, out[name])
    assert out["b.s19"] == (1, "There are unsaved changes in fw.s19. Load b.s19 anyway?"), out["b.s19"]
    assert out["padded"][0] == 1 and out["padded"][1].endswith("Load b.s19 anyway?"), out["padded"]
    assert out["project"][0] == 1 and "Patch Editor entries" in out["project"][1], out["project"]
    asked, lines = out["removed"]
    assert asked == 0 and len(lines) == 1 and "not found" in lines[0], out["removed"]


def _mac_name(app):
    cur = app.current_file
    if cur is None or cur.mac_path is None:
        return None
    return Path(cur.mac_path).name


def test_tc_b100_72_workarea_file_takes_its_kind_from_its_suffix(tmp_path: Path) -> None:
    """LLR-174.4c (C38): with D, ``x.mac``, ``U.MAC``, ``c.a2l``, ``x.s19``
    and ``x.hex``, from the Load dialog's work-area rows and from the
    Workarea Files list → 0, 0, 0, 1 and 1 questions on each surface (10 of
    10).

    Why: a MAC or A2L pick attaches and keeps the image; any other file
    replaces it.
    Negative control: a suffix-blind rule (every pick an image) → the MAC
    and A2L arms ask → RED. RED (base): the ``.s19`` / ``.hex`` arms ask
    nothing."""
    scene = _scene(tmp_path)

    async def scenario(app, pilot, log):
        await _load(pilot, app, scene.src / "fw.s19")
        await _patch(pilot, app)
        spy = PushSpy(app)
        out = {}
        for surface in ("dialog", "list"):
            for name in ("x.mac", "U.MAC", "c.a2l", "x.s19", "x.hex"):
                mark = spy.questions()
                if surface == "dialog":
                    app._handle_load_dialog(LC("workarea", name))
                else:
                    app._load_from_item(types.SimpleNamespace(data=name))
                if name.lower().endswith(".mac"):
                    landed = lambda name=name: _mac_name(app) == name  # noqa: E731
                elif name.endswith(".a2l"):
                    landed = lambda: (  # noqa: E731
                        app.current_a2l_path is not None and Path(app.current_a2l_path).name == "c.a2l"
                    )
                else:
                    landed = lambda name=name: Path(app.current_file.path).name == name  # noqa: E731
                await ld.wait_for(pilot, lambda: is_question(app.screen) or landed(), f"{surface} {name}")
                await _settle(pilot, 6)
                out[(surface, name)] = spy.questions() - mark
                if is_question(app.screen):
                    await _answer(pilot, app, "n")
        return out

    out = _run(scene.base, scenario)
    expected = {}
    for surface in ("dialog", "list"):
        expected.update({(surface, "x.mac"): 0, (surface, "U.MAC"): 0, (surface, "c.a2l"): 0,
                         (surface, "x.s19"): 1, (surface, "x.hex"): 1})
    assert out == expected, out


# ---------------------------------------------------------------------------
# Inc 10 arms of TC-B100-12, TC-B100-70, TC-B100-66
# ---------------------------------------------------------------------------


def test_tc_b100_12_cancelled_question_rehomes_the_focus(tmp_path: Path) -> None:
    """LLR-166.1 Inc 10 arm (C08, §C.2, corrected by orchestrator ruling 7):
    after a cancelled question the focus follows ``_rehome_focus_after_load``
    — a visible, healthy focus is kept. Patch window with the focus on the
    visible ``#patch_entry_address_input`` and D set; ``ctrl+l``, a typed
    data file, ``enter`` → the question → ``n`` → the re-home rule ran once
    and the focus is still on ``patch_entry_address_input``. Workspace with
    the focus on ``#files_list`` and D set; a pick of ``x.s19`` → the
    question → ``escape`` → the re-home rule ran once and the focus is still
    on ``files_list`` (2 of 2).

    Why: after a cancelled question the engineer must keep working where
    they were; LLR-166.1 keeps a visible input in the active window and
    moves only a stale focus.
    Negative control: the cancel branch skips ``_rehome_focus_after_load`` →
    the re-home count is 0 → RED. A cancel that moves a healthy input onto
    the window target → the first arm lands on ``patch_editor_panel`` →
    RED. RED (base): no question."""
    scene = _scene(tmp_path)

    def spy_rehome(app, calls: list) -> None:
        real = app._rehome_focus_after_load

        def spy():
            calls.append(1)
            return real()

        app._rehome_focus_after_load = spy

    async def patch_window(app, pilot, log):
        await _load(pilot, app, scene.src / "fw.s19")
        await _patch(pilot, app)
        await pilot.press("6")
        await ld.wait_for(pilot, lambda: len(app.query("#patch_entry_address_input")) > 0, "the Patch Editor")
        await _settle(pilot, 4)
        assert await pilot.click("#patch_entry_address_input")
        assert _focused_id(app) == "patch_entry_address_input"
        await pilot.press("ctrl+l")
        await ld.wait_for_dialog(pilot, app)
        await ld.type_into_path(pilot, app, str(scene.src / "b.s19"))
        await pilot.press("enter")
        await _wait_question(pilot, app)
        calls: list = []
        spy_rehome(app, calls)
        await _answer(pilot, app, "n")
        await _settle(pilot, 6)
        return len(calls), _focused_id(app)

    async def workspace(app, pilot, log):
        await _load(pilot, app, scene.src / "fw.s19")
        await _patch(pilot, app)
        await _pick_in_files_list(pilot, app, "x.s19")
        await _wait_question(pilot, app)
        calls: list = []
        spy_rehome(app, calls)
        await _answer(pilot, app, "escape")
        await _settle(pilot, 6)
        return len(calls), _focused_id(app)

    assert _run(scene.base, patch_window) == (1, "patch_entry_address_input")
    scene = _scene(tmp_path / "second")
    assert _run(scene.base, workspace) == (1, "files_list")


def test_tc_b100_70_project_load_asks_only_while_the_document_is_unsaved(tmp_path: Path) -> None:
    """LLR-167.8 Inc 10 arm (C31, §C.3): an entry added through the panel,
    Save project (the file holds every entry) → a project load asks 0
    questions; an entry added again and a refused Save project (empty name,
    the flag stays set) → a project load asks 1 question naming ``Patch
    Editor entries`` (2 of 2).

    Why: Save project is the way to make Patch Editor work safe; the
    question must believe it, and must not believe a refused save.
    Negative control: Save project skips the panel's ``mark_saved`` → the
    first arm asks → RED. RED (base): the second arm asks nothing."""
    from s19_app.tui.screens import SaveProjectPayload

    scene = _scene(tmp_path)

    async def add_entry(pilot, app, address: str) -> None:
        await pilot.press("6")
        await ld.wait_for(pilot, lambda: len(app.query("#patch_entry_add_button")) > 0, "the Patch Editor")
        await _settle(pilot, 4)
        assert await pilot.click("#patch_entry_address_input")
        await pilot.press("ctrl+a", "delete", *address)
        assert await pilot.click("#patch_entry_bytes_input")
        await pilot.press("ctrl+a", "delete", *"DE AD")
        assert await pilot.click("#patch_entry_add_button")
        await ld.wait_for(pilot, lambda: _panel(app)._dirty, "the panel flag")

    async def scenario(app, pilot, log):
        await _load(pilot, app, scene.src / "fw.s19")
        await add_entry(pilot, app, "0x8000007C")
        messages = await projects.save_project(pilot, app, log, "S1")
        assert any(m.startswith("Saved project to") for m in messages), messages
        assert not _panel(app)._dirty, "setup: Save project left the flag set"
        spy = PushSpy(app)
        app._handle_load_dialog(LC("project", "Q"))
        await ld.wait_for(pilot, lambda: app.current_project == "Q" or is_question(app.screen), "Q or the question")
        await _settle(pilot, 6)
        saved = spy.questions()
        if is_question(app.screen):
            await _answer(pilot, app, "n")
        else:
            await _close_result_panel(pilot, app)
        await add_entry(pilot, app, "0x80000010")
        mark = len(log.messages)
        app._handle_save_dialog(SaveProjectPayload(parent_folder=str(app.workarea), project_name=""))
        await _settle(pilot, 4)
        refused = [m for m in log.since(mark) if "NOT saved" in m]
        assert refused and _panel(app)._dirty, (refused, _panel(app)._dirty)
        mark = spy.questions()
        await _ask(pilot, app, lambda: app._handle_load_dialog(LC("project", "P")))
        body = q_body(app)
        await _answer(pilot, app, "n")
        return saved, spy.questions() - mark, body

    saved, refused_asks, body = _run(scene.base, scenario)
    assert saved == 0
    assert refused_asks == 1 and "Patch Editor entries" in body, (refused_asks, body)


def test_tc_b100_66_question_text_holds_no_decision_ids(tmp_path: Path) -> None:
    """LLR-173.7 Inc 10 arm (C27, Q2-8, §C.4): the painted title, body and
    labels of the load question in 3 scenes (1 item; 3 items; a project
    target) and of the quit-parameter modal → 0 matches of ``\\bD\\d+\\b``,
    ``\\bO-\\d+``, ``VS-``, ``LLR-``, ``HLR-``.

    Why: design ids mean nothing to the engineer reading the question.
    Negative control: a prototype decision id (UX-18) copied into the body
    → RED. RED (base): no question."""
    scene = _scene(tmp_path)

    async def scenario(app, pilot, log):
        texts = []

        async def grab():
            await _wait_question(pilot, app)
            texts.extend([q_title(app), q_body(app)] + [label for _, label in q_buttons(app)])
            await _answer(pilot, app, "n")

        await _load(pilot, app, scene.src / "fw.s19")
        await _patch(pilot, app)
        app._handle_load_dialog(LC("path", str(scene.src / "b.s19")))
        await grab()
        await _set_w(pilot, app)
        await _set_f(pilot, app, "patch_chain")
        app._handle_load_dialog(LC("project", "Q"))
        await grab()
        await _open_project(pilot, app, "P")
        await _set_w(pilot, app)
        app._handle_load_dialog(LC("project", "Q"))
        await grab()
        await _modal_alone(pilot, app, QUITQ)
        texts.extend([q_title(app), q_body(app)] + [label for _, label in q_buttons(app)])
        await _answer(pilot, app, "n")
        return texts

    texts = _run(scene.base, scenario)
    assert len(texts) == 16, texts
    assert [t for t in texts if DECISION_ID.search(t)] == [], texts


# ---------------------------------------------------------------------------
# AT-B100-15 — black-box (HLR-174 … HLR-174d)
# ---------------------------------------------------------------------------


def test_at_b100_15_load_over_unsaved_work_asks_one_question_per_route(tmp_path: Path) -> None:
    """AT-B100-15 (HLR-174, HLR-174a, HLR-174b, HLR-174c, HLR-174d), by keys
    and widget ids only, in a scratch work area at 118x54:

      - question + keep halves: Load ``fw.s19``; a patch added and applied
        in the Patch Editor; Load ``b.s19`` → one question titled
        ``Replace fw.s19?`` naming the image, the focus on Cancel; ``enter``
        keeps the patched image (the Loaded panel still names ``fw.s19``,
        the patched byte still in the session image). A Workarea Files pick
        of ``x.s19`` asks the same; ``escape`` keeps it.
      - replace half: Load ``b.s19`` again, ``y`` → ``b.s19`` loads.
      - after-save half: Apply on ``b.s19`` → Load ``fw.s19`` asks (``n``);
        Save project ``PA`` → the same Load asks nothing and loads.
      - ``v`` route: open ``PV``, patch, ``v`` to ``firmware_b`` → the
        question naming ``firmware_b.s19``; ``n`` keeps ``firmware_a``.
      - items half: Flow Builder edits plus the patched image, then a
        project pick → one question naming the image and ``flow flow``.

    The panel's ``v`` is TC-B100-72's forced-state arm (ruling Q5).
    Declared: the hex view does not repaint the applied bytes on the base
    either (probe in the tester notes), so the kept patch is read from the
    session image and the painted Loaded panel, not the hex view.

    Negative control: the base tree → Load over the patched image loads
    with no question (P-17) → RED at the first question."""
    from textual.widgets import Label

    from s19_app.tui.screens import SaveProjectScreen

    scene = _scene(tmp_path)

    def status(app) -> str:
        return str(app.query_one("#log_line_4", Label).render())

    def loaded_names(app) -> str:
        panel = app.screen_stack[0].query_one("#loaded_panel")
        return " ".join(str(getattr(c.render(), "plain", c.render())) for c in panel.query(".loaded-detail"))

    async def load_by_keys(pilot, app, path: Path) -> None:
        await pilot.press("l")
        await ld.wait_for_dialog(pilot, app)
        await ld.type_into_path(pilot, app, str(path))
        assert await pilot.click("#load_ok"), "click missed #load_ok"
        await ld.wait_for_dialog_closed(pilot, app)

    async def add_and_apply(pilot, app, add: bool = True) -> None:
        await pilot.press("6")
        await ld.wait_for(pilot, lambda: len(app.query("#patch_entry_add_button")) > 0, "the Patch Editor")
        await _settle(pilot, 4)
        if add:
            # A second add keeps the first add's text, and ``ctrl+a`` moves to
            # the start rather than selecting it: clear both inputs first
            # (the ``test_b100_document.py`` helper's pattern).
            from textual.widgets import Input

            app.query_one("#patch_entry_address_input", Input).value = ""
            app.query_one("#patch_entry_bytes_input", Input).value = ""
            assert await pilot.click("#patch_entry_address_input")
            await pilot.press("ctrl+a", "delete", *"0x8000007C")
            assert await pilot.click("#patch_entry_bytes_input")
            await pilot.press("ctrl+a", "delete", *"DE AD BE EF")
            assert await pilot.click("#patch_entry_add_button")
            await ld.wait_for(pilot, lambda: "entry added" in status(app), "the entry added")
        assert await pilot.click("#patch_doc_apply_button")
        await ld.wait_for(pilot, lambda: "1 applied" in status(app), "the apply")
        await _settle(pilot, 4)

    async def scenario(app, pilot, log):
        spy = PushSpy(app)
        out = {}
        # Load fw.s19 and patch it by keys.
        await load_by_keys(pilot, app, scene.src / "fw.s19")
        await ld.wait_for(pilot, lambda: app.current_file is not None, "the load of fw.s19")
        await add_and_apply(pilot, app)
        # Question + keep (Load route, enter).
        await load_by_keys(pilot, app, scene.src / "b.s19")
        await _wait_question(pilot, app)
        out["load question"] = (q_title(app), q_body(app), _focused_id(app))
        await _answer(pilot, app, "enter")
        await _settle(pilot, 6)
        out["kept"] = (
            Path(app.current_file.path).name,
            app.current_file.mem_map.get(PATCH_ADDRESS),
            "fw.s19" in loaded_names(app),
        )
        # Workarea Files pick (escape).
        await _pick_in_files_list(pilot, app, "x.s19")
        await _wait_question(pilot, app)
        out["workarea question"] = q_body(app)
        await _answer(pilot, app, "escape")
        await _settle(pilot, 6)
        out["kept after workarea"] = Path(app.current_file.path).name
        # Replace (y).
        await load_by_keys(pilot, app, scene.src / "b.s19")
        await _wait_question(pilot, app)
        await pilot.press("y")
        await ld.wait_for(pilot, lambda: Path(app.current_file.path).name == "b.s19", "the load of b.s19")
        await _settle(pilot, 6)
        out["replaced"] = ("b.s19" in loaded_names(app), is_question(app.screen))
        # After-save: asks before the save, not after.
        await add_and_apply(pilot, app, add=False)
        await load_by_keys(pilot, app, scene.src / "fw.s19")
        await _wait_question(pilot, app)
        await _answer(pilot, app, "n")
        await pilot.press("ctrl+s")
        await ld.wait_for(pilot, lambda: isinstance(app.screen, SaveProjectScreen), "the Save project dialog")
        assert await pilot.click("#project_name")
        # Inc 11 re-pin (census D / F, LLR-175.3h / .4b): clear the prefilled
        # name, type it, and wait for its painted summary before Save.
        await sd.type_and_await_summary(pilot, app, "PA")
        assert await pilot.click("#save_ok")
        await ld.wait_for(pilot, lambda: "Saved project" in status(app), "the save")
        mark = spy.questions()
        await load_by_keys(pilot, app, scene.src / "fw.s19")
        await ld.wait_for(
            pilot,
            lambda: is_question(app.screen) or Path(app.current_file.path).name == "fw.s19",
            "the load of fw.s19 after the save",
        )
        await _settle(pilot, 6)
        out["after save"] = (spy.questions() - mark, Path(app.current_file.path).name)
        if is_question(app.screen):
            await _answer(pilot, app, "n")
        # v route.
        await pilot.press("1")
        await _settle(pilot, 4)
        await ld.open_project_through_dialog(pilot, app, "PV")
        await projects.dismiss_load_result_panel(pilot, app)
        await add_and_apply(pilot, app)
        await pilot.press("1")
        await _settle(pilot, 4)
        await _switch_variant_by_keys(pilot, app)
        await _wait_question(pilot, app)
        out["v question"] = (q_title(app), q_body(app))
        await _answer(pilot, app, "n")
        await _settle(pilot, 6)
        out["v kept"] = (app._variant_set.active_id, Path(app.current_file.path).name)
        # Items: Flow Builder edits + the patched image, then a project pick.
        await pilot.press("8")
        await _settle(pilot, 6)
        assert await pilot.click("#flow_ref")
        await pilot.press(*"fw.s19")
        assert await pilot.click("#flow_add")
        await ld.wait_for(
            pilot, lambda: "sev-warning" in app.query_one("#flow_name_strip").classes, "the flow marked unsaved"
        )
        await pilot.press("1")
        await _settle(pilot, 4)
        mark = spy.questions()
        await ld.open_project_through_dialog(pilot, app, "PA")
        await _wait_question(pilot, app)
        out["items question"] = (spy.questions() - mark, q_body(app))
        await _answer(pilot, app, "n")
        return out

    out = _run(scene.base, scenario)
    title, body, focus = out["load question"]
    assert title == "Replace fw.s19?" and "fw.s19" in body and focus == "confirm_no", out["load question"]
    assert out["kept"] == ("fw.s19", 0xDE, True), out["kept"]
    assert out["workarea question"].endswith("Load x.s19 anyway?"), out["workarea question"]
    assert out["kept after workarea"] == "fw.s19"
    assert out["replaced"] == (True, False), out["replaced"]
    assert out["after save"] == (0, "fw.s19"), out["after save"]
    assert out["v question"][0] == "Replace PV?", out["v question"]
    assert out["v question"][1].endswith("Load firmware_b.s19 anyway?"), out["v question"]
    assert out["v kept"] == ("firmware_a", "firmware_a.s19"), out["v kept"]
    asked, items_body = out["items question"]
    assert asked == 1 and "firmware_a.s19" in items_body and "flow flow" in items_body, out["items question"]
