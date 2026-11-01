"""batch-100 Inc 12b — project load, Save project and the A2L attach on workers.

Summary:
    Independent tests (E4 tester) for TC-B100-53, TC-B100-54, the four
    halves of AT-B100-18 and the parse half of AT-B100-17. Every oracle comes
    from the Inc 12b design files
    (``.dev-flow/2026-10-26-batch-100/inc-12b``: ``E1-requirements-draft.md``,
    ``E1-scope.md``, the E1/E2/E3 rulings, ``codewire/interfaces-12b.md``,
    ``codewire/proto-12b-load-save.md`` (examples ``P1-NN``) and
    ``codewire/proto-12b-a2l-refusal.md`` (examples ``C12b-NN``)); the
    implementation was never read.

    Why this matters (US-167): on the base the case_06 A2L attach blocks the
    event loop for 8.76 s and the case_06 project load for 5.81 s (P12b-4,
    P12b-5) — the app looks frozen. Moving the work onto threads brings a new
    defect class: two writers of the session at once, a worker that reads the
    previous project's image, a quit that cuts a save in half. The tests read
    what the user sees (the status log, ``#status_text``, ``#progress_bar``,
    the screen stack, the files on disk) and use spies only to record which
    thread did the work and in which order.

    Forced slow step (E1 glossary): a module function reached through
    ``app_module`` is replaced by a stand-in that blocks on a
    ``threading.Event`` when it is called OFF the event-loop thread, until
    the test releases it. Called on the event-loop thread (the base, where
    the action is synchronous) it does not block and records the call, so a
    "during" arm fails at once on the base with "ran on the main thread"
    instead of hanging.

Dependencies:
    Uses:
        - ``tests.support.b100_workers.settle_workers`` (ruling Q6's one wait)
        - ``tests.support.b100_projects`` (fixtures, ``StatusLog``)
        - ``tests.support.b100_load_dialog`` (the Load dialog drivers)
        - ``tests.support.b100_save_dialog`` (the Save dialog drivers)
"""

from __future__ import annotations

import ast
import asyncio
import dataclasses
import hashlib
import json
import os
import pathlib
import re
import shutil
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Callable, Optional

import pytest

import s19_app.tui.app as app_module
from s19_app.tui.app import S19TuiApp
from s19_app.tui.workspace import WORKAREA_DIRNAME, WORKAREA_SUBDIR, WORKAREA_TEMP

from tests.support import b100_load_dialog as ld
from tests.support import b100_projects as projects
from tests.support import b100_save_dialog as sd
from tests.support.b100_workers import settle_workers

ROOT = Path(__file__).resolve().parents[1]
CASE01 = ROOT / "examples" / "case_01_basic_valid"
CASE06 = ROOT / "examples" / "case_06_large_nested_a2l"
APP_SOURCE = Path(app_module.__file__)
SIZE = (118, 54)
WIN = sys.platform == "win32"

FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
DOT = "  ·  "
LINE_RE = re.compile(r"^([" + FRAMES + r"]) (.+)  ·  step (\d+)/(\d+) (.+)  ·  (\d{2,}:\d{2})$")
PATCH_ADDRESS = 0x8000007C
DECISION_ID = re.compile(r"\bD\d+\b|\bO-\d+|VS-|LLR-|HLR-|US-|TC-|AT-")
REPORT_STEPS = ("Prepare the results", "Write the report")

#: LLR-177.1e / P1-25: the session names no worker (nor any app method a
#: worker calls) may read from ``self``.
SESSION_READS = (
    "current_file", "current_project", "current_project_dir", "current_a2l_path",
    "current_a2l_data", "_variant_set", "_change_service", "_a2l_cache_key",
    "_a2l_cache_data", "_declared_regions", "_last_template_path",
    "_parsed_paste_text", "workarea", "base_dir",
)
WORKERS = ("_project_load_worker", "_save_project_worker", "_a2l_attach_worker")
REQUESTS = {
    "_project_load_worker": "ProjectLoadRequest",
    "_save_project_worker": "SaveRequest",
    "_a2l_attach_worker": "A2LAttachRequest",
}

SAVE_FAILED_UNEXPECTED = (
    "Project NOT saved: could not save — an unexpected error stopped the save. check the folder."
)
NO_SPACE_LINE = "Project NOT saved: could not save — [Errno 28] synthetic no space. check the folder."


def on_disk_records(project_dir: Path, recorded: dict) -> dict:
    """Size and SHA-256 (``hashlib``) of each file a manifest records,
    read from the disk (a missing file reads ``None``)."""
    out = {}
    for relative in recorded:
        path = project_dir.joinpath(*relative.split("/"))
        out[relative] = (
            {"size": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            if path.is_file() else None
        )
    return out


def busy(label: str) -> str:
    """LLR-177.3f's exact busy line."""
    return f"busy: {label} is running — wait for it to finish."


def quit_body(label: str) -> str:
    """LLR-177.4a's quit question text."""
    return f"still working: {label} — wait, or quit after it finishes"


# ---------------------------------------------------------------------------
# fixtures (synthetic: the shipped example files only)
# ---------------------------------------------------------------------------


def W(base: Path) -> Path:
    return base / WORKAREA_DIRNAME / WORKAREA_SUBDIR


def trio(folder: Path, case: Path = CASE01, names=("firmware.s19", "firmware.mac", "firmware.a2l")) -> Path:
    """A project folder holding ``case``'s files and no ``project.json``
    (the P2 / P6 fixtures of proto-12b-load-save)."""
    folder.mkdir(parents=True, exist_ok=True)
    for name in names:
        shutil.copyfile(case / name, folder / name)
    return folder


def image16(mem_map) -> Optional[str]:
    """The baseline-notes image hash: first 16 hex digits of SHA-256 over
    (address as 8 bytes big-endian + byte) for each sorted pair."""
    if not mem_map:
        return None
    h = hashlib.sha256()
    for addr, value in sorted(mem_map.items()):
        h.update(int(addr).to_bytes(8, "big"))
        h.update(bytes([value & 0xFF]))
    return h.hexdigest()[:16]


def digest(app) -> tuple:
    """E1's session digest, as probe p12b U1 computes it."""
    cf = app.current_file
    wa = app.workarea

    def rel(p):
        if p is None:
            return None
        p = Path(p)
        try:
            return str(p.relative_to(wa))
        except ValueError:
            return str(p)

    return (
        rel(cf.path) if cf else None,
        image16(cf.mem_map) if cf else None,
        app.current_project,
        rel(app.current_a2l_path),
        rel(cf.mac_path) if cf and cf.mac_path else None,
        len(app._change_service.document.entries),
    )


def D(project: str, a2l: bool = True, mac: bool = True, sha: str = "f254f33fe5405d40") -> tuple:
    """The base digest of a case_01 trio project (baseline p12b U1)."""
    return (
        str(Path(project) / "firmware.s19"),
        sha,
        project,
        str(Path(project) / "firmware.a2l") if a2l else None,
        str(Path(project) / "firmware.mac") if mac else None,
        0,
    )


D6 = (str(Path("P6") / "firmware.s19"), "f917cd2dca22da9a", "P6",
      str(Path("P6") / "firmware.a2l"), str(Path("P6") / "firmware.mac"), 0)


def status(app) -> str:
    return str(app.query_one("#status_text").render())


def bar(app) -> float:
    from textual.widgets import ProgressBar

    return app.query_one("#progress_bar", ProgressBar).progress


def stack(app) -> list:
    return [type(s).__name__ for s in app.screen_stack]


def on_stack(app, name: str) -> int:
    return sum(1 for s in app.screen_stack if type(s).__name__ == name)


def log_tail(app, n: int = 1) -> list:
    return list(app.log_lines)[-n:]


def entries(app) -> list:
    """The document's entries as comparable values (field dicts)."""
    return [dataclasses.asdict(e) if dataclasses.is_dataclass(e) else repr(vars(e))
            for e in app._change_service.document.entries]


def _main_ident() -> int:
    return threading.get_ident()


class Spy:
    """Wrap ``owner.name``: record (thread id, args) per call and call the
    real one. ``raising=False`` so a name the base lacks is installed and
    simply never called there (the RED is the missing call, not a setup
    error)."""

    def __init__(self, monkeypatch, owner, name: str, *, before=None, after=None) -> None:
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

        monkeypatch.setattr(owner, name, _wrapped, raising=False)

    def threads(self) -> set:
        return {c.thread for c in self.calls}


class Hold:
    """A forced slow step (E1 glossary) on ``owner.name``.

    Off the event-loop thread the first matching call blocks on
    ``release`` (then raises ``raise_on_release`` when given, else runs the
    real function); later calls pass through. On the event-loop thread (the
    base's synchronous action) it never blocks and records the call in
    ``main_calls``, so :func:`reached` fails at once there."""

    def __init__(self, monkeypatch, owner, name: str, *, match=None, raise_on_release=None,
                 timeout: float = 180.0) -> None:
        self.name = name
        self.main = threading.get_ident()
        self.entered = threading.Event()
        self.release = threading.Event()
        self.main_calls: list = []
        self.worker_calls: list = []
        self.raise_on_release = raise_on_release
        real = getattr(owner, name)
        hold = self

        def _held(*args, **kwargs):
            ident = threading.get_ident()
            if match is not None and not match(*args, **kwargs):
                return real(*args, **kwargs)
            if ident == hold.main:
                hold.main_calls.append(args)
                return real(*args, **kwargs)
            hold.worker_calls.append(ident)
            if not hold.entered.is_set():
                hold.entered.set()
                if not hold.release.wait(timeout):
                    raise TimeoutError(f"the forced slow step {name} was never released")
                if hold.raise_on_release is not None:
                    raise hold.raise_on_release
            return real(*args, **kwargs)

        monkeypatch.setattr(owner, name, _held)


async def reached(pilot, hold: Hold, what: str, timeout: float = 60.0) -> None:
    """Wait until ``what`` blocks inside its forced slow step on a worker.
    Fails at once when the step ran on the event-loop thread (no worker)."""
    deadline = time.monotonic() + timeout
    while not hold.entered.is_set():
        if hold.main_calls:
            raise AssertionError(
                f"{what}: {hold.name} ran on the main (event-loop) thread — the action has no worker"
            )
        if time.monotonic() > deadline:
            raise AssertionError(f"{what} never reached its worker step {hold.name}")
        await pilot.pause(0.01)
    await pilot.pause()


async def release(pilot, hold: Hold) -> None:
    hold.release.set()
    await settle_workers(pilot)


class Ticks:
    """A 0.1 s interval counter started on the app (LLR-177.1c's oracle)."""

    def __init__(self, app) -> None:
        self.count = 0
        app.set_interval(0.1, self._tick)

    def _tick(self) -> None:
        self.count += 1


def run(base: Path, scenario, *, size: tuple = SIZE, notifications: bool = False,
        app_cls=S19TuiApp, **app_kwargs):
    """Run ``await scenario(app, pilot, log)`` in a fresh app rooted at
    ``base``; return what it returns."""

    async def _drive():
        app = app_cls(base_dir=base, **app_kwargs)
        log = projects.StatusLog(app)
        async with app.run_test(size=size, notifications=notifications) as pilot:
            await pilot.pause()
            return await scenario(app, pilot, log)

    return asyncio.run(_drive())


async def wait(pilot, predicate, what: str, timeout: float = 90.0) -> None:
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError(f"timed out waiting for {what}")
        await pilot.pause(0.01)


async def wait_exit(app, timeout: float = 90.0) -> bool:
    """Wait (by the wall clock, not the app) until the app has exited."""
    deadline = time.monotonic() + timeout
    while app.return_code is None:
        if time.monotonic() > deadline:
            return False
        await asyncio.sleep(0.02)
    return True


def running(app) -> bool:
    return app.return_code is None and app.is_running


async def open_trio_project(app, pilot, name: str = "P2") -> None:
    """Setup: open a trio project through the shipped handler and wait for
    its install (ruling Q6)."""
    app._handle_load_project(name)
    await settle_workers(pilot)
    await wait(pilot, lambda: app.current_project == name and app.current_file is not None,
               f"the project load of {name}")


async def patch_one_byte(app, pilot, address: int = PATCH_ADDRESS) -> int:
    """Setup: one real applied entry that changes the image (the Inc 10
    ``_patch`` idiom of test_b100_load_question)."""
    cur = app.current_file
    if address not in cur.mem_map:
        address = sorted(cur.mem_map)[0]
    new = (cur.mem_map[address] + 1) & 0xFF
    app._change_service.add_entry(f"0x{address:08X}", "", f"{new:02X}")
    app._change_service.apply(cur.mem_map, cur.ranges, cur.mac_records, None)
    for _ in range(4):
        await pilot.pause()
    return address


def save(app, name: str) -> None:
    from s19_app.tui.screens import SaveProjectPayload

    app._handle_save_dialog(SaveProjectPayload(parent_folder=str(app.workarea), project_name=name))


def neutral_focus(app) -> None:
    """Put the focus on the Workspace files list, so a letter key is a
    binding, not typing."""
    app.set_focus(app.query_one("#files_list"))


def held_save_scene(tmp_path: Path, monkeypatch, *, patch: bool = False, name: str = "P1", **hold_kw):
    """Base folder with the trio project ``P2`` and a forced slow step on
    the Save worker's first placement (``app_module.place_into_workarea``)."""
    base = tmp_path / "app"
    trio(W(base) / "P2")
    hold = Hold(monkeypatch, app_module, "place_into_workarea", **hold_kw)
    return base, hold


async def start_held_save(app, pilot, hold: Hold, *, patch: bool = False, name: str = "P1") -> None:
    await open_trio_project(app, pilot, "P2")
    if patch:
        await patch_one_byte(app, pilot)
    save(app, name)
    await reached(pilot, hold, f"Save project {name}")


def source_census() -> set:
    """Every ``self.<name> =`` target in ``S19TuiApp`` (LLR-165.2's domain)."""
    tree = ast.parse(APP_SOURCE.read_text(encoding="utf-8"))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "S19TuiApp":
            for inner in ast.walk(node):
                targets = []
                if isinstance(inner, ast.Assign):
                    targets = inner.targets
                elif isinstance(inner, (ast.AnnAssign, ast.AugAssign)):
                    targets = [inner.target]
                for target in targets:
                    for t in ast.walk(target):
                        if (isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name)
                                and t.value.id == "self"):
                            names.add(t.attr)
    return names


# ===========================================================================
# TC-B100-53 — the three worker steps and the work-area pick off the main
# thread (HLR-177, LLR-177.1, LLR-177.1a, LLR-177.1b, LLR-177.1k)
# ===========================================================================


def test_tc_b100_53_project_load_refuses_cheaply_then_returns_before_the_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-177.1, LLR-177.1f, LLR-178.2 (P1-10, P1-11, P1-28).

    The refusals that need no file content (a missing folder, outside the
    work area, no data or A2L file) paint in the frame of the request and begin nothing; an
    admissible project begins ``Loading project P2`` and the call returns
    BEFORE the install (``current_project`` still ``None``), with one worker
    started on a ``ProjectLoadRequest``. After the one Q6 wait the session
    equals the base's cold load (digest ``D2``), the three base lines are
    painted, ``#status_text`` reads the project line, the variant id is
    stamped and the indicator has ended.

    Why: a refusal that started a worker would flash a progress line for
    nothing; an install inside the request frame is exactly the 5.81 s
    freeze HLR-177 removes.
    Negative control (P12b-5, executed): the base load is synchronous →
    ``current_project == "P2"`` when the call returns → RED."""
    base = tmp_path / "app"
    wa = W(base)
    trio(wa / "P2")
    (wa / "Q").mkdir(parents=True)
    (wa / "Q" / "project.json").write_text(json.dumps({"schema_version": 1}), encoding="utf-8")
    outside = base / WORKAREA_DIRNAME / "X"
    trio(outside, names=("firmware.s19",))
    begins = Spy(monkeypatch, S19TuiApp, "begin_busy")
    worker = Spy(monkeypatch, S19TuiApp, "_project_load_worker")

    async def scenario(app, pilot, log):
        refusals = []
        for name, expected in (
            ("Z", "Project not found: Z"),
            ("Q", "Project NOT loaded: 'Q' has no data or A2L file — load a file and Save project."),
            (str(Path("..") / "X"), "is outside the work area — copy the folder into the work area."),
        ):
            app._handle_load_project(name)
            refusals.append((name, log_tail(app)[0], expected, len(begins.calls), len(worker.calls),
                             dict(app._busy.runs)))
        app._handle_load_project("P2")
        frame = SimpleNamespace(
            project=app.current_project,
            runs={k: v.label for k, v in app._busy.runs.items()},
            gen=app._busy.runs["project_load"].gen if "project_load" in app._busy.runs else None,
            status=status(app),
            worker=[c.args for c in worker.calls],
        )
        await settle_workers(pilot)
        await wait(pilot, lambda: app.current_project == "P2", "the install of P2")
        after = SimpleNamespace(
            digest=digest(app), lines=log_tail(app, 3), status=status(app),
            variant=app.current_file.variant_id, runs=dict(app._busy.runs),
        )
        return refusals, frame, after

    refusals, frame, after = run(base, scenario)
    for name, line, expected, n_begins, n_workers, runs in refusals:
        assert line.endswith(expected) if name.startswith("..") else line == expected, (name, line)
        assert (n_begins, n_workers, runs) == (0, 0, {}), (name, n_begins, n_workers, runs)
    assert frame.project is None, (
        "the project was installed inside the request frame (no worker): "
        f"current_project={frame.project!r} when _handle_load_project returned"
    )
    assert frame.runs == {"project_load": "Loading project P2"}, frame.runs
    assert re.match(r"^[" + FRAMES + r"] Loading project P2  ·  step 1/4 Check the files  ·  00:0\d$",
                    frame.status), frame.status
    assert len(frame.worker) == 1, frame.worker
    request = frame.worker[0][-1]
    assert type(request).__name__ == "ProjectLoadRequest", type(request)
    assert (request.name, request.routed, request.gen) == ("P2", False, frame.gen), request
    assert tuple(Path(p) for p in request.a2l_files) == (W(base) / "P2" / "firmware.a2l",), request.a2l_files
    assert after.digest == D("P2"), after.digest
    assert after.lines == [
        "Loaded firmware.s19 (S19 only)",
        "Loaded firmware.mac (S19+MAC)",
        "Loaded project 'P2' -> firmware.s19 + firmware.mac - variant 1 of 1, 1 problem - details: p",
    ], after.lines
    assert after.status == "Loaded project 'P2' -> firmware.s19 + firmware.mac", after.status
    assert after.variant == "firmware" and after.runs == {}, (after.variant, after.runs)


def test_tc_b100_53_project_load_reads_every_file_on_a_worker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-177.1, HLR-177 (P1-15): a project with data, MAC, A2L and a
    recorded change document, loaded from the Load dialog by keys (``p``,
    the row, ``enter``) → the digest check, the manifest read, the A2L
    parse, the image parse and the document read each record a thread other
    than the main thread (5 of 5).

    Why: any one of these left on the main thread is a freeze the user
    sees (the case_06 A2L parse alone is 5.01 s, P12b-7).
    Negative control (P12b-5, executed): ``ran on main thread True`` → RED."""
    base = tmp_path / "app"
    projects.seed_document_project(
        W(base), "P2", data_files=("firmware.s19", "firmware.mac", "firmware.a2l")
    )
    spies = {
        name: Spy(monkeypatch, app_module, name)
        for name in ("check_project_files", "read_project_manifest", "parse_a2l_file",
                     "build_loaded_s19", "recorded_document_state")
    }
    # E4 integration re-pin: count only the reads the project load makes.
    # The Load dialog's preview of the highlighted row reads the manifest on
    # the main thread before the load starts (Inc 9b, out of 12b's scope).
    marks: dict = {}

    def _mark(*_a, **_k):
        for name, spy in spies.items():
            marks.setdefault(name, len(spy.calls))

    Spy(monkeypatch, S19TuiApp, "_handle_load_project", before=_mark)

    async def scenario(app, pilot, log):
        main = _main_ident()
        await ld.open_project_through_dialog(pilot, app, "P2", confirm="enter")
        await settle_workers(pilot)
        await wait(pilot, lambda: app.current_project == "P2", "the install of P2")
        return main, len(app._change_service.document.entries)

    main, n_entries = run(base, scenario)
    assert marks, "the project load never started"
    seen = {name: (len(s.calls[marks[name]:]), main in {c.thread for c in s.calls[marks[name]:]})
            for name, s in spies.items()}
    assert all(count >= 1 for count, _ in seen.values()), seen
    on_main = sorted(name for name, (_, m) in seen.items() if m)
    assert on_main == [], f"read on the main thread: {on_main} ({seen})"
    assert n_entries == 1, n_entries


def test_tc_b100_53_save_refuses_before_any_worker_then_writes_on_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-177.1a, HLR-177 (P1-54 subset, P1-58).

    The Inc 11 preparation refusals (empty name, device name ``CON``,
    reserved ``temp``, a 300-character name) paint before any worker starts and
    create no folder; an emitting save of a patched trio session as ``Q``
    returns BEFORE ``project.json`` exists, with one Save worker started on
    a ``SaveRequest``; the folder creation, each placement, the image emit
    and the manifest write then record non-main threads (4 of 4).

    Why: a save of 2 000 files on the main thread is the 14 s freeze of
    the R12 backlog row.
    Negative control (P12b-6, executed): ``_handle_save_dialog('Q') … ran
    on main thread True`` → ``project.json`` exists when the call returns
    → RED."""
    base = tmp_path / "app"
    trio(W(base) / "P2")
    target = W(base) / "Q"
    worker = Spy(monkeypatch, S19TuiApp, "_save_project_worker")
    begins = Spy(monkeypatch, S19TuiApp, "begin_busy")
    places = Spy(monkeypatch, app_module, "place_into_workarea")
    emits = Spy(monkeypatch, app_module, "save_patched_image")
    manifests = Spy(monkeypatch, app_module, "write_project_manifest")
    mkdirs: list = []
    real_mkdir = pathlib.Path.mkdir

    def _mkdir(self, *args, **kwargs):
        if os.path.normcase(str(self)) == os.path.normcase(str(target)):
            mkdirs.append(threading.get_ident())
        return real_mkdir(self, *args, **kwargs)

    monkeypatch.setattr(pathlib.Path, "mkdir", _mkdir)

    async def scenario(app, pilot, log):
        main = _main_ident()
        await open_trio_project(app, pilot, "P2")
        await patch_one_byte(app, pilot)
        listing = sd.workarea_listing(app.workarea)
        refused = []
        for name in ("", "CON", "temp", "n" * 300):
            n_begins = len(begins.calls)
            save(app, name)
            refused.append((name, len(worker.calls), len(begins.calls) - n_begins,
                            sd.workarea_listing(app.workarea) == listing))
        save(app, "Q")
        frame = ((target / "project.json").exists(), {k: v.label for k, v in app._busy.runs.items()},
                 [type(c.args[-1]).__name__ for c in worker.calls])
        await settle_workers(pilot)
        await wait(pilot, lambda: (target / "project.json").exists(), "the save of Q")
        return main, refused, frame

    main, refused, (manifest_in_frame, runs, requests) = run(base, scenario)
    for name, n_workers, n_begins, unchanged in refused:
        assert (n_workers, n_begins, unchanged) == (0, 0, True), (name, n_workers, n_begins, unchanged)
    assert manifest_in_frame is False, "project.json was written inside the request frame (no Save worker)"
    assert runs == {"save_project": "Saving project Q"}, runs
    assert requests == ["SaveRequest"], requests
    threads = {
        "mkdir": set(mkdirs), "place_into_workarea": places.threads(),
        "save_patched_image": emits.threads(), "write_project_manifest": manifests.threads(),
    }
    assert all(threads.values()), f"a write was never seen: {threads}"
    on_main = sorted(k for k, v in threads.items() if main in v)
    assert on_main == [], f"written on the main thread: {on_main}"


def test_tc_b100_53_every_a2l_attach_route_parses_on_a_worker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-177.1b, HLR-177 (C12b-29): a typed ``.a2l`` path in the Load
    dialog, a Workarea Files pick of ``c.a2l`` (in place) and the start-up
    ``load_path`` → the parse runs off the main thread on each route (3 of
    3); the two copying routes copy off the main thread; the pick makes 0
    copies. Each ends with ``A2L loaded: <name>``.

    Why: the attach is the slowest action of all (8.76 s for case_06); a
    route left synchronous keeps the freeze on that route.
    Negative control (P12b-4, executed): ``ran on main thread True`` → RED.
    The recent-entry route of the example is not driven here (declared in
    the tester notes)."""
    base = tmp_path / "app"
    src = tmp_path / "src"
    src.mkdir()
    for name in ("cal.a2l", "cal3.a2l"):
        shutil.copyfile(CASE01 / "firmware.a2l", src / name)
    temp = W(base) / WORKAREA_TEMP
    temp.mkdir(parents=True)
    shutil.copyfile(CASE01 / "firmware.a2l", temp / "c.a2l")
    parses = Spy(monkeypatch, app_module, "parse_a2l_file")
    copies = Spy(monkeypatch, app_module, "copy_into_workarea")

    def by_name(spy, name):
        return [c.thread for c in spy.calls if c.args and Path(c.args[0]).name == name]

    async def typed_and_pick(app, pilot, log):
        main = _main_ident()
        await ld.load_path_through_dialog(
            pilot, app, src / "cal.a2l",
            until=lambda: app.current_a2l_path is not None and Path(app.current_a2l_path).name == "cal.a2l",
            what="the typed attach of cal.a2l",
        )
        await settle_workers(pilot)
        typed_copies = list(copies.calls)
        app._load_workarea_file("c.a2l")
        await settle_workers(pilot)
        await wait(pilot, lambda: Path(app.current_a2l_path or "").name == "c.a2l", "the pick of c.a2l")
        pick_copies = copies.calls[len(typed_copies):]
        return main, [c.thread for c in typed_copies], len(pick_copies), log_tail(app)[0]

    main1, typed_copy_threads, pick_copy_count, last = run(base, typed_and_pick)

    async def startup(app, pilot, log):
        main = _main_ident()
        await wait(pilot, lambda: Path(app.current_a2l_path or "").name == "cal3.a2l", "the start-up attach")
        await settle_workers(pilot)
        return main

    copies_before = len(copies.calls)
    main2 = run(tmp_path / "app2", startup, load_path=src / "cal3.a2l")
    startup_copy_threads = [c.thread for c in copies.calls[copies_before:]]
    routes = {
        "typed": (by_name(parses, "cal.a2l"), main1),
        "pick": (by_name(parses, "c.a2l"), main1),
        "startup": (by_name(parses, "cal3.a2l"), main2),
    }
    assert all(threads for threads, _ in routes.values()), {k: len(v[0]) for k, v in routes.items()}
    on_main = sorted(route for route, (threads, main) in routes.items() if main in threads)
    assert on_main == [], f"A2L parsed on the main thread on: {on_main}"
    assert typed_copy_threads and main1 not in typed_copy_threads, typed_copy_threads
    assert startup_copy_threads and main2 not in startup_copy_threads, startup_copy_threads
    assert pick_copy_count == 0, pick_copy_count
    assert last == "A2L loaded: c.a2l", last


def _big8(path: Path) -> Path:
    """12a's generated S19 with 8 MiB of data (2 048 ranges of 4 KiB)."""
    from tests.conftest import make_large_s19

    return make_large_s19(path, num_ranges=2048, bytes_per_range=4096)


@pytest.mark.parametrize("surface", ["files_list", "load_dialog"])
def test_tc_b100_53_workarea_data_pick_parses_on_the_file_load_worker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, surface: str
) -> None:
    """LLR-177.1k, LLR-177.1c (C12b-44): ``big8.s19`` (8 MiB of data) in the
    work area, picked from (a) the Workarea Files list and (b) the Load
    dialog's ``workarea`` row → the parse records a non-main thread, a
    0.1 s timer ticks ≥ 10 times during it, 0 ``copy_into_workarea`` calls,
    and the session digest equals a twin app's synchronous
    ``load_selected_file`` of the same file (4 of 4 per surface).

    Why: the pick parsed on the main thread for 2.38 s (12a P12a-3).
    Negative control (code read, base): ``_load_from_item`` →
    ``load_selected_file`` parses on the main thread → 0 ticks → RED."""
    base = tmp_path / "app"
    temp = W(base) / WORKAREA_TEMP
    temp.mkdir(parents=True)
    _big8(temp / "big8.s19")
    copies = Spy(monkeypatch, app_module, "copy_into_workarea")
    window = {}
    holder = {}

    def _enter(*_a, **_k):
        window.setdefault("start", holder["ticks"].count)

    def _exit(*_a, **_k):
        window["end"] = holder["ticks"].count

    parses = Spy(monkeypatch, S19TuiApp, "_parse_loaded_file", before=_enter, after=_exit)

    async def scenario(app, pilot, log):
        main = _main_ident()
        holder["ticks"] = Ticks(app)
        await pilot.pause(0.3)
        if surface == "files_list":
            app._load_workarea_file("big8.s19")
        else:
            app._handle_load_dialog(ld.load_choice_cls()("workarea", "big8.s19"))
        await wait(pilot, lambda: app.current_file is not None
                   and Path(app.current_file.path).name == "big8.s19", "the pick of big8.s19", 180)
        await settle_workers(pilot)
        return main, digest(app)

    main, picked = run(base, scenario)
    picked_threads = parses.threads()

    async def twin(app, pilot, log):
        app.load_selected_file(W(tmp_path / "twin") / WORKAREA_TEMP / "big8.s19")
        await settle_workers(pilot)
        await wait(pilot, lambda: app.current_file is not None, "the twin load", 180)
        return digest(app)

    temp2 = W(tmp_path / "twin") / WORKAREA_TEMP
    temp2.mkdir(parents=True)
    shutil.copyfile(temp / "big8.s19", temp2 / "big8.s19")
    copies_before = len(copies.calls)
    twin_digest = run(tmp_path / "twin", twin)
    assert picked_threads and main not in picked_threads, "the pick parsed on the main thread"
    assert window.get("end", 0) - window.get("start", 0) >= 10, window
    assert copies_before == 0, f"the pick copied the file: {copies_before} copy_into_workarea calls"
    assert picked == twin_digest, (picked, twin_digest)


def test_tc_b100_53_workarea_pick_begins_a_file_load_and_never_syncs_the_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-177.1k, P2-2 (C12b-46, C12b-45): a pick of ``W/temp/x.s19`` →
    one begin ``Loading x.s19``, step 2 painted on the main thread and step
    3 posted from the worker, the log gains ``Loaded x.s19 (S19 only)`` and
    the outcome ``Loaded x.s19``, one effective end. With project ``P``
    open the pick makes 0 ``_sync_loaded_file_to_project`` calls and leaves
    ``W/P``'s listing and ``project.json`` bytes unchanged.

    Why: the pick is now a session action (it must show progress and be
    refused against); routed through the file-load worker unchanged it
    would append the file to the open project (finding F-2).
    Negative control: 12a's body (``load_selected_file``) → 0 begins → RED."""
    base = tmp_path / "app"
    wa = W(base)
    temp = wa / WORKAREA_TEMP
    temp.mkdir(parents=True)
    shutil.copyfile(CASE01 / "firmware.s19", temp / "x.s19")
    p = trio(wa / "P", names=("firmware.s19",))
    (p / "project.json").write_text(json.dumps({"schema_version": 1}), encoding="utf-8")
    begins = Spy(monkeypatch, S19TuiApp, "begin_busy")
    steps = Spy(monkeypatch, S19TuiApp, "step_busy")
    syncs = Spy(monkeypatch, S19TuiApp, "_sync_loaded_file_to_project")
    posts = StepPosts(monkeypatch)

    async def scenario(app, pilot, log):
        main = _main_ident()
        mark = len(app.log_lines)
        app._load_workarea_file("x.s19")
        await settle_workers(pilot)
        await wait(pilot, lambda: app.current_file is not None, "the pick of x.s19")
        first = (log_tail(app, 2), status(app), [(c.args[1], c.args[3], c.thread) for c in steps.calls
                                                 if c.args[1] == "file_load"],
                 [c.args[1:3] for c in begins.calls], posts.phases("file_load"))
        await open_trio_project(app, pilot, "P")
        listing = sorted(x.name for x in p.iterdir())
        manifest = (p / "project.json").read_bytes()
        n_sync = len(syncs.calls)
        app._load_workarea_file("x.s19")
        await settle_workers(pilot)
        await wait(pilot, lambda: Path(app.current_file.path).name == "x.s19", "the second pick")
        return main, first, (sorted(x.name for x in p.iterdir()) == listing,
                             (p / "project.json").read_bytes() == manifest, len(syncs.calls) - n_sync)

    main, (lines, final, file_steps, begun, posted), (same_listing, same_manifest, n_sync) = run(base, scenario)
    assert begun[:1] == [("file_load", "Loading x.s19")], begun
    assert [n for n, _t in [(s[1], s[2]) for s in file_steps]] == [2, 3], file_steps
    # E4 integration re-pin: both steps RUN on main (LLR-176.1q); step 2 is
    # called there directly and step 3 is POSTED by the worker.
    assert all(s[2] == main for s in file_steps), file_steps
    assert [n for n, _t in posted] == [3] and posted[0][1] != main, posted
    assert lines == ["Loaded x.s19 (S19 only)", "Loaded x.s19"], lines
    assert final == "Loaded x.s19 (S19 only)", final
    assert (same_listing, same_manifest, n_sync) == (True, True, 0), (same_listing, same_manifest, n_sync)


# ===========================================================================
# TC-B100-53 — the event loop stays free and the parse / placements report
# progress (LLR-177.1c, LLR-177.5, LLR-177.5a)
# ===========================================================================


class Progress:
    """Class-level recorder of ``step_busy`` and ``set_progress``, in one
    ordered event list with the writing thread (LLR-177.5, LLR-176.1q)."""

    def __init__(self, monkeypatch) -> None:
        self.events: list = []
        rec = self
        real_step = getattr(S19TuiApp, "step_busy", None)
        real_bar = S19TuiApp.set_progress

        if real_step is not None:
            def _step(app, key, gen, n, done=None, total=None):
                rec.events.append(("step", key, n, done, total, threading.get_ident()))
                return real_step(app, key, gen, n, done, total)

            monkeypatch.setattr(S19TuiApp, "step_busy", _step)

        def _bar(app, value, message=None):
            rec.events.append(("bar", value, threading.get_ident()))
            return real_bar(app, value, message)

        monkeypatch.setattr(S19TuiApp, "set_progress", _bar)

    def clear(self) -> None:
        self.events.clear()

    def bars(self) -> list:
        return [e[1] for e in self.events if e[0] == "bar"]

    def within_step(self, key: str, n: int) -> list:
        """The bar values painted after ``key`` entered step ``n`` (a step
        call with no amount) and before it left that step."""
        out: list = []
        inside = False
        for e in self.events:
            if e[0] == "step" and e[1] == key:
                if e[2] == n and e[3] is None and not inside:
                    inside = True
                    continue
                if inside and e[2] != n:
                    break
            elif e[0] == "bar" and inside:
                out.append(e[1])
        return out

    def forwards(self, key: str, n: int) -> list:
        return [(e[3], e[4]) for e in self.events if e[0] == "step" and e[1] == key and e[2] == n
                and e[3] is not None]


def increases(values: list) -> int:
    return sum(1 for a, b in zip(values, values[1:]) if b > a)


class StepPosts:
    """E4 integration re-pin: the ``step_busy`` calls a thread posts through
    ``call_from_thread``, as ``(key, n, done, posting thread)``. A posted
    step RUNS on the main thread (LLR-176.1q: widgets are written on main
    only), so "posted from the worker" is read at the post, never from the
    thread that executes ``step_busy``."""

    def __init__(self, monkeypatch) -> None:
        self.posts: list = []
        rec = self
        real = S19TuiApp.call_from_thread

        def _post(app, callback, *args, **kwargs):
            if getattr(callback, "__func__", None) is S19TuiApp.__dict__.get("step_busy"):
                done = args[3] if len(args) > 3 else None
                rec.posts.append((args[0], args[2], done, threading.get_ident()))
            return real(app, callback, *args, **kwargs)

        monkeypatch.setattr(S19TuiApp, "call_from_thread", _post)

    def phases(self, key: str) -> list:
        return [(n, t) for k, n, done, t in self.posts if k == key and done is None]


def test_tc_b100_53_case06_project_load_keeps_the_loop_free_and_reports_parse_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-177.1c (project arm), LLR-177.5 (project half), HLR-177 (P1-16,
    P1-21, P1-28 ``D6``): ``P6`` (case_06 ``firmware.s19`` + ``.mac`` +
    ``.a2l``) → a 0.1 s timer started before the request ticks ≥ 10 times
    before the install; within step 2 (``Parse the A2L``) the bar takes ≥ 2
    increasing values in ``(25, 50]`` and ends the step at ``50``; the byte
    reports forwarded number at most 101; the session equals the base's
    cold load ``D6``.

    Why: a free event loop is what keeps the spinner and the elapsed time
    moving; byte reports are what make the bar move inside the 5 s parse.
    Negative control (P12b-5, executed): 0 ticks in 5.81 s → RED; a worker
    that passes no ``progress=`` → the bar sits at 25 → RED."""
    base = tmp_path / "app"
    trio(W(base) / "P6", CASE06)
    progress = Progress(monkeypatch)

    async def scenario(app, pilot, log):
        ticks = Ticks(app)
        await pilot.pause(0.3)
        progress.clear()
        start = ticks.count
        app._handle_load_project("P6")
        deadline = time.monotonic() + 240
        while app.current_project != "P6":
            if time.monotonic() > deadline:
                raise AssertionError("the P6 load never installed")
            await pilot.pause(0.02)
        seen_at_install = ticks.count - start
        await settle_workers(pilot)
        return seen_at_install, digest(app)

    ticks_before_install, got = run(base, scenario)
    assert ticks_before_install >= 10, f"{ticks_before_install} ticks before the install (event loop blocked)"
    step2 = progress.within_step("project_load", 2)
    assert increases(step2) >= 2, step2
    # E4 integration re-pin (P1-21 reads "≥ 2 increasing values in (25, 50]"):
    # the step opens at 25 and the first byte forwards (under 4 % of the
    # file) still floor to 25, so 25 is inside the step's range.
    assert all(25 <= v <= 50 for v in step2), step2
    assert len({v for v in step2 if v > 25}) >= 2, step2
    assert step2[-1] == 50, step2
    assert len(progress.forwards("project_load", 2)) <= 101, len(progress.forwards("project_load", 2))
    assert got == D6, got


def test_tc_b100_53_case06_a2l_attach_keeps_the_loop_free_and_reports_parse_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-177.1c (A2L arm), LLR-177.5 (A2L half), LLR-177.1b (C12b-31,
    C12b-32): the case_06 A2L attach → ≥ 10 ticks of a 0.1 s timer before
    the install; within step 2 (``Parse``) the bar increases ≥ 2 times
    from 33 towards 66 and never goes above 66; at most 101 forwarded
    reports; the attach lands (``current_a2l_path`` is the work-area copy).

    Why: the attach was the longest freeze (8.76 s, P12b-4).
    Negative control (P12b-4, executed): 0 ticks → RED; no callback → 0
    increases within step 2 → RED."""
    base = tmp_path / "app"
    progress = Progress(monkeypatch)

    async def scenario(app, pilot, log):
        ticks = Ticks(app)
        await pilot.pause(0.3)
        progress.clear()
        start = ticks.count
        app.load_a2l_from_path(CASE06 / "firmware.a2l")
        deadline = time.monotonic() + 300
        while app.current_a2l_path is None:
            if time.monotonic() > deadline:
                raise AssertionError("the case_06 attach never installed")
            await pilot.pause(0.02)
        n = ticks.count - start
        await settle_workers(pilot)
        return n, app.current_a2l_path

    n_ticks, path = run(base, scenario)
    assert n_ticks >= 10, f"{n_ticks} ticks before the install (event loop blocked)"
    step2 = progress.within_step("a2l_load", 2)
    assert increases(step2) >= 2, step2
    assert all(33 <= v <= 66 for v in step2), step2
    assert len(progress.forwards("a2l_load", 2)) <= 101, len(progress.forwards("a2l_load", 2))
    assert Path(path) == W(base) / WORKAREA_TEMP / "firmware.a2l", path


def test_tc_b100_53_held_save_keeps_the_loop_free(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """LLR-177.1c (Save arm) (P1-59): a Save held at its first placement for
    1.5 s → a 0.1 s timer ticks ≥ 10 times during the hold.

    Why: the case_06 save is faster than one tick, so only a held step can
    show the loop is free during a save (E1 §1 note).
    Negative control (P12b-6, executed): the save holds the main thread →
    RED (here: the held step runs on the main thread)."""
    base, hold = held_save_scene(tmp_path, monkeypatch)

    async def scenario(app, pilot, log):
        ticks = Ticks(app)
        try:
            await start_held_save(app, pilot, hold)
            start = ticks.count
            await pilot.pause(1.5)
            during = ticks.count - start
        finally:
            hold.release.set()
        await settle_workers(pilot)
        return during

    assert run(base, scenario) >= 10


def test_tc_b100_53_save_reports_each_file_placed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """LLR-177.5a, LLR-176.2d (P1-62, P1-63): (a) the trio ``P2`` saved as
    ``Q`` (copy-only, 3 placements) → step-2 forwards ``(1, 3)``,
    ``(2, 3)``, ``(3, 3)``, bar ``[0, 25, 33, 41, 50, 50, 75, 0]``, the
    steps 2, 3, 4 posted from the worker, the lines added end
    ``Project saved + manifest verified`` then ``Saved project to <W>\\Q
    (variant 'firmware')``; (b) a save of the open ``S`` (the trio plus
    ``flows/f1.json``) as ``S2`` → 4 placements, bar ``31, 37, 43, 50``
    within step 2; (c) a save of ``firmware.s19`` alone → 1 forward
    ``(1, 1)``, bar ``50`` once.

    Why: a save of many files must move the bar per file, not only per
    phase. Negative control (12a P12a-1): no save step is reported within
    the placement step → RED."""
    base = tmp_path / "app"
    wa = W(base)
    trio(wa / "P2")
    s = trio(wa / "S")
    projects.write_tree(s, {"flows/f1.json": projects.SUBFOLDER_FILES["flows/f1.json"]})
    trio(wa / "ONE", names=("firmware.s19",))
    progress = Progress(monkeypatch)
    posts = StepPosts(monkeypatch)

    async def scenario(app, pilot, log):
        main = _main_ident()
        out = {}
        for project, target in (("P2", "Q"), ("S", "S2"), ("ONE", "ONE2")):
            await open_trio_project(app, pilot, project)
            progress.clear()
            posts.posts.clear()
            save(app, target)
            await settle_workers(pilot)
            await wait(pilot, lambda: (wa / target / "project.json").exists(), f"the save of {target}")
            # E4 integration re-pin: the full lines (``log_lines`` is width-capped).
            out[target] = (list(progress.events), log.messages[-2:], posts.phases("save_project"))
        return main, out

    main, out = run(base, scenario)

    def view(events):
        progress.events[:] = events
        return progress

    q = view(out["Q"][0])
    assert q.forwards("save_project", 2) == [(1, 3), (2, 3), (3, 3)], q.forwards("save_project", 2)
    assert q.bars() == [0, 25, 33, 41, 50, 50, 75, 0], q.bars()
    phase_steps = [(e[2], e[5]) for e in q.events if e[0] == "step" and e[1] == "save_project" and e[3] is None]
    assert [n for n, _t in phase_steps] == [2, 3, 4], phase_steps
    posted = out["Q"][2]
    assert [n for n, _t in posted] == [2, 3, 4], posted
    assert all(t != main for _n, t in posted), "a save step was posted from the main thread"
    assert out["Q"][1] == ["Project saved + manifest verified",
                           f"Saved project to {wa / 'Q'} (variant 'firmware')"], out["Q"][1]
    s2 = view(out["S2"][0])
    assert s2.forwards("save_project", 2) == [(1, 4), (2, 4), (3, 4), (4, 4)], s2.forwards("save_project", 2)
    # E4 integration re-pin: ``within_step`` also records the step's own
    # entry paint (25, written by ``step_busy`` itself); P1-63's values are
    # the placements after it.
    assert s2.within_step("save_project", 2) == [25, 31, 37, 43, 50], s2.within_step("save_project", 2)
    one = view(out["ONE2"][0])
    assert one.forwards("save_project", 2) == [(1, 1)], one.forwards("save_project", 2)
    assert one.within_step("save_project", 2) == [25, 50], one.within_step("save_project", 2)


def test_tc_b100_53_a_two_thousand_file_save_moves_the_bar_ten_times(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-177.5a (2 000-file arm) (P1-63): the open ``S`` holding 2 000
    files under ``flows/`` saved as ``S2`` → the bar increases ≥ 10 times
    within the placement step, and at most 101 forwards reach the main
    thread.

    Why: the R12 save-as of 2 000 files took 14 s with a bar that never
    moved. Negative control: a forwarder that reports only after the copies
    → 1 increase → RED; base (12a P12a-1): no report → RED."""
    base = tmp_path / "app"
    wa = W(base)
    s = trio(wa / "S")
    projects.bulk_files(s, "flows", 2000)
    progress = Progress(monkeypatch)

    async def scenario(app, pilot, log):
        await open_trio_project(app, pilot, "S")
        progress.clear()
        save(app, "S2")
        await settle_workers(pilot)
        await wait(pilot, lambda: (wa / "S2" / "project.json").exists(), "the save of S2", 300)
        return None

    run(base, scenario)
    step2 = progress.within_step("save_project", 2)
    assert increases(step2) >= 10, step2
    assert len(progress.forwards("save_project", 2)) <= 101, len(progress.forwards("save_project", 2))


# ===========================================================================
# TC-B100-53 — the session is written only on the main thread and the
# workers read only their request (LLR-177.1d, LLR-177.1e)
# ===========================================================================


def _recording_app_cls(record: list, names: set):
    css = getattr(S19TuiApp, "CSS_PATH", None)
    if isinstance(css, (str, Path)) and not Path(css).is_absolute():
        css = str(Path(app_module.__file__).parent / css)

    class RecordingApp(S19TuiApp):
        CSS_PATH = css

        def __setattr__(self, name, value):
            if name in names:
                record.append((name, threading.get_ident()))
            super().__setattr__(name, value)

    return RecordingApp


def test_tc_b100_53_session_is_written_only_on_the_main_thread(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-177.1d (P1-32, P1-67, C12b-35, C12b-47): a test subclass records
    the thread of every write of a session-census name (the ``self.<name> =``
    targets of ``S19TuiApp``) and the change service's state writes
    (``record_save_entries``, ``adopt_rederived``, ``mark_saved``), during a
    project load, a forced project-load failure, an emitting Save project,
    a forced Save failure, an A2L attach, a forced A2L failure and a file
    load that misses the A2L cache → 0 writes off the main thread; the cache
    miss writes ``_a2l_cache_key`` / ``_a2l_cache_data`` once each, on main.

    Why: two threads writing the session is the race the increment must
    not introduce (a torn ``current_file`` / A2L pair).
    Negative control (code read, base): the file-load worker writes
    ``_a2l_cache_key`` / ``_a2l_cache_data`` (``_load_a2l_data_with_cache``)
    → off-main writes → RED."""
    from s19_app.tui.services.change_service import ChangeService

    base = tmp_path / "app"
    wa = W(base)
    trio(wa / "P2")
    trio(wa / "PF")
    temp = wa / WORKAREA_TEMP
    temp.mkdir(parents=True)
    shutil.copyfile(CASE01 / "firmware.s19", temp / "x.s19")
    shutil.copyfile(CASE01 / "firmware.a2l", tmp_path / "bad.a2l")
    record: list = []
    names = source_census()
    service = {m: Spy(monkeypatch, ChangeService, m) for m in ("record_save_entries", "adopt_rederived", "mark_saved")}
    real_manifest = app_module.read_project_manifest
    real_parse = app_module.parse_a2l_file
    has_verify = hasattr(app_module, "verify_written_image")

    def _manifest(project_dir, *a, **k):
        if Path(project_dir).name == "PF":
            raise PermissionError("synthetic")
        return real_manifest(project_dir, *a, **k)

    def _parse(path, *a, **k):
        if Path(path).name == "bad.a2l":
            raise ValueError("synthetic parse")
        return real_parse(path, *a, **k)

    monkeypatch.setattr(app_module, "read_project_manifest", _manifest)
    monkeypatch.setattr(app_module, "parse_a2l_file", _parse)

    async def scenario(app, pilot, log):
        main = _main_ident()
        await open_trio_project(app, pilot, "P2")
        try:
            app._handle_load_project("PF")
        except Exception:  # noqa: BLE001 — the base raises in the request frame
            pass
        await settle_workers(pilot)
        await patch_one_byte(app, pilot)
        save(app, "Q")
        await settle_workers(pilot)
        await wait(pilot, lambda: (wa / "Q" / "project.json").exists(), "the save of Q")
        if has_verify:
            def _boom(*_a, **_k):
                raise ValueError("forced defect")

            monkeypatch.setattr(app_module, "verify_written_image", _boom)
        await patch_one_byte(app, pilot, PATCH_ADDRESS - 1)
        try:
            save(app, "Q2")
        except Exception:  # noqa: BLE001 — the base re-raises after its rollback
            pass
        await settle_workers(pilot)
        app.load_a2l_from_path(CASE01 / "firmware.a2l")
        await settle_workers(pilot)
        try:
            app.load_a2l_from_path(tmp_path / "bad.a2l")
        except Exception:  # noqa: BLE001 — the base raises in the request frame
            pass
        await settle_workers(pilot)
        app._a2l_cache_key = None
        mark = len(record)
        app.load_from_path(temp / "x.s19")
        await settle_workers(pilot)
        await wait(pilot, lambda: Path(app.current_file.path).name == "x.s19", "the load of x.s19")
        return main, record[mark:]

    main, miss = run(base, scenario, app_cls=_recording_app_cls(record, names))
    off_main = sorted({name for name, thread in record if thread != main})
    assert off_main == [], f"session written off the main thread: {off_main}"
    service_off = {m: sorted(s.threads() - {main}) for m, s in service.items() if s.threads() - {main}}
    assert service_off == {}, service_off
    cache_writes = [(n, t) for n, t in miss if n in ("_a2l_cache_key", "_a2l_cache_data")]
    assert sorted(n for n, _t in cache_writes) == ["_a2l_cache_data", "_a2l_cache_key"], cache_writes
    assert all(t == main for _n, t in cache_writes), cache_writes


def _class_methods(tree: ast.Module, cls: str = "S19TuiApp") -> dict:
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == cls:
            return {
                item.name: item for item in node.body
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
    return {}


def _self_calls(func) -> set:
    """Names of ``self.<method>(...)`` calls in ``func`` (callables passed
    as values, such as ``call_from_thread``'s target, are not calls)."""
    out = set()
    for node in ast.walk(func):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name) and node.func.value.id == "self"):
            out.add(node.func.attr)
    return out


def _session_reads(func) -> list:
    return sorted({
        node.attr for node in ast.walk(func)
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
        and node.value.id == "self" and node.attr in SESSION_READS
        and isinstance(node.ctx, ast.Load)
    })


def test_tc_b100_53_workers_read_only_their_frozen_request() -> None:
    """LLR-177.1e (P1-04, P1-08, P1-25, P1-66, C12b-36, C12b-54): an AST
    census of ``app.py`` — the three workers exist, each takes one
    parameter after ``self`` annotated with its request class, each request
    class is a frozen dataclass, and the body of each worker and of every
    ``app.py`` method it reaches by calls holds 0 reads of the session
    names (``current_file``, ``current_project``, ``current_project_dir``,
    ``current_a2l_*``, ``_variant_set``, ``_change_service``, the A2L
    cache, the declared regions, the template, the paste text,
    ``workarea``, ``base_dir``); the module-level ``parse_a2l_cached``
    reads no ``self``.

    Why: a worker that reads the live session parses against the previous
    project's image (probe p12b U2: P2's MAC merged into P1's image).
    Negative control (code read, base): no worker exists; the base body of
    ``_parse_loaded_file`` reads ``current_file`` / ``current_a2l_*`` →
    RED."""
    tree = ast.parse(APP_SOURCE.read_text(encoding="utf-8"))
    methods = _class_methods(tree)
    missing = [w for w in WORKERS if w not in methods]
    assert missing == [], f"worker functions not found in app.py: {missing}"
    hits: dict = {}
    for worker in WORKERS:
        node = methods[worker]
        params = list(node.args.args[1:]) + list(node.args.kwonlyargs)
        assert len(params) == 1, (worker, [a.arg for a in params])
        annotation = ast.unparse(params[0].annotation) if params[0].annotation is not None else ""
        assert annotation.strip("'\"") == REQUESTS[worker], (worker, annotation)
        seen, todo = set(), [worker]
        while todo:
            name = todo.pop()
            if name in seen or name not in methods:
                continue
            seen.add(name)
            reads = _session_reads(methods[name])
            if reads:
                hits[f"{worker} -> {name}"] = reads
            todo.extend(_self_calls(methods[name]) - {"call_from_thread"})
    assert hits == {}, f"session reads reachable from a worker: {hits}"
    for cls_name in REQUESTS.values():
        cls = getattr(app_module, cls_name, None)
        assert cls is not None and dataclasses.is_dataclass(cls), cls_name
        assert cls.__dataclass_params__.frozen, f"{cls_name} is not frozen"
    cached = next((n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "parse_a2l_cached"), None)
    assert cached is not None, "parse_a2l_cached (module level) not found"
    assert not [n for n in ast.walk(cached) if isinstance(n, ast.Name) and n.id == "self"]


# ===========================================================================
# TC-B100-53 — the project install (LLR-177.1f, LLR-177.1g, LLR-177.1h)
# ===========================================================================


def test_tc_b100_53_project_over_an_open_image_equals_a_cold_load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-177.1f, TC-B100-09 P2-over-P1 on the worker path (P1-19 arm C,
    P1-20): ``P2`` (data + MAC + A2L) loaded over an open ``p1img.s19`` with
    one patch applied → the call returns before the install; after it the
    digest is ``D2`` (the base's cold digest, baseline p12b U1), the
    snapshot differs from a cold ``P2`` load only inside LLR-165.2's
    allow-list, and ``current_file.variant_id == "firmware"``.

    Why: the worker must parse P2's MAC against P2's own image, never the
    live one (probe p12b U2), and the merged MAC must keep the variant id
    (finding F-1).
    Negative control: a worker that merges with the live ``current_file``
    installs P1's image under P2 → digest path ``p1img.s19`` → RED; the
    base installs inside the request frame → RED."""
    from tests.test_b100_session_reset import SNAPSHOT_ALLOW_LIST

    cold_base = tmp_path / "cold"
    trio(W(cold_base) / "P2")

    async def cold(app, pilot, log):
        await open_trio_project(app, pilot, "P2")
        return digest(app), app._session_snapshot()

    cold_digest, cold_snap = run(cold_base, cold)
    base = tmp_path / "over"
    trio(W(base) / "P2")
    shutil.copyfile(CASE01 / "firmware.s19", base.parent / "p1img.s19")

    async def over(app, pilot, log):
        await projects.load_image(pilot, app, base.parent / "p1img.s19")
        await patch_one_byte(app, pilot)
        app._handle_load_project("P2")
        in_frame = app.current_project
        await settle_workers(pilot)
        await wait(pilot, lambda: app.current_project == "P2", "the install of P2")
        return in_frame, digest(app), app._session_snapshot(), app.current_file.variant_id

    in_frame, got, snap, variant = run(base, over)
    assert in_frame is None, f"installed inside the request frame (current_project={in_frame!r})"
    assert got == D("P2") == cold_digest, (got, cold_digest)
    differing = {k for k in set(cold_snap) | set(snap) if cold_snap.get(k) != snap.get(k)}
    assert differing - SNAPSHOT_ALLOW_LIST == set(), sorted(differing - SNAPSHOT_ALLOW_LIST)
    assert variant == "firmware", variant


def test_tc_b100_53_reset_runs_after_the_worker_and_before_the_first_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-177.1g, LLR-165.1 (P1-29): a call-order spy over the end of the
    worker step (``_prepare_project_load``), ``_reset_project_session`` and
    ``_apply_loaded_file`` → ``["worker_end", "reset@main", "install",
    "install"]`` for ``P2``; a ``PermissionError`` forced into
    ``read_project_manifest`` → 0 resets and the session kept.

    Why: a reset before the worker leaves an empty session when the worker
    fails (LLR-177.2); a reset after the first install wipes it.
    Negative control: a reset in ``_handle_load_project`` before the
    worker → the failure arm leaves ``current_file is None`` → RED; the
    base (no worker step) → no ``worker_end`` → RED."""
    base = tmp_path / "app"
    trio(W(base) / "P2")
    trio(W(base) / "PF")
    events: list = []
    main_box = [threading.get_ident()]

    def _end(*_a, **_k):
        events.append("worker_end" if threading.get_ident() != main_box[0] else "worker_end@main")

    def _reset(*_a, **_k):
        events.append("reset@main" if threading.get_ident() == main_box[0] else "reset@worker")

    Spy(monkeypatch, S19TuiApp, "_prepare_project_load", after=_end)
    Spy(monkeypatch, S19TuiApp, "_reset_project_session", before=_reset)
    Spy(monkeypatch, S19TuiApp, "_apply_loaded_file", before=lambda *_a, **_k: events.append("install"))
    real_manifest = app_module.read_project_manifest

    def _manifest(project_dir, *a, **k):
        if Path(project_dir).name == "PF":
            raise PermissionError("synthetic")
        return real_manifest(project_dir, *a, **k)

    monkeypatch.setattr(app_module, "read_project_manifest", _manifest)

    async def scenario(app, pilot, log):
        await open_trio_project(app, pilot, "P2")
        ok = list(events)
        events.clear()
        try:
            app._handle_load_project("PF")
        except Exception:  # noqa: BLE001 — the base raises in the request frame
            pass
        await settle_workers(pilot)
        return ok, list(events), app.current_project, app.current_file is not None

    ok, failed, project, has_image = run(base, scenario)
    assert ok == ["worker_end", "reset@main", "install", "install"], ok
    assert "reset@main" not in failed and "reset@worker" not in failed, failed
    assert (project, has_image) == ("P2", True), (project, has_image)


def test_tc_b100_53_load_result_panel_opens_after_the_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-177.1h, LLR-178.3 (P1-31): the Load dialog's ``P2`` row,
    ``enter``, with ``read_project_manifest`` held → 0 ``LoadResultScreen``
    while held, exactly 1 after the install; a typed absolute ``<W>\\P2`` in
    the Load dialog → 1 panel after the install; a direct
    ``_handle_load_project("P2")`` → 0 panels (LLR-174.3b).

    Why: the panel reports what was installed; opened before the install
    it would describe nothing, and the base's post-return check would open
    none at all under a worker.
    Negative control: the base ``_route_load_project`` identity check after
    the call → 0 panels → RED (on the base the held step runs on the main
    thread)."""
    base = tmp_path / "app"
    trio(W(base) / "P2")
    hold = Hold(monkeypatch, app_module, "read_project_manifest")

    async def scenario(app, pilot, log):
        try:
            await ld.open_project_through_dialog(pilot, app, "P2", confirm="enter")
            await reached(pilot, hold, "the project load of P2")
            while_held = on_stack(app, "LoadResultScreen")
        finally:
            hold.release.set()
        await settle_workers(pilot)
        await wait(pilot, lambda: on_stack(app, "LoadResultScreen") >= 1, "the Load-result panel")
        after = on_stack(app, "LoadResultScreen")
        await projects.dismiss_load_result_panel(pilot, app)
        await ld.load_path_through_dialog(pilot, app, W(base) / "P2", what="the typed project path")
        await settle_workers(pilot)
        await wait(pilot, lambda: on_stack(app, "LoadResultScreen") >= 1, "the panel of the typed path")
        typed = on_stack(app, "LoadResultScreen")
        await projects.dismiss_load_result_panel(pilot, app)
        app._handle_load_project("P2")
        await settle_workers(pilot)
        direct = on_stack(app, "LoadResultScreen")
        return while_held, after, typed, direct

    assert run(base, scenario) == (0, 1, 1, 0)


# ===========================================================================
# TC-B100-53 — Save project: re-derive before, adopt after (LLR-177.1i,
# LLR-177.1j)
# ===========================================================================


def test_tc_b100_53_save_rederives_on_main_before_the_worker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-177.1i, ruling Q1 (P1-55): an emitting save of a patched trio
    session → ``ChangeService.rederive_for_save`` and
    ``render_patched_image`` each record the main thread, and both precede
    the Save worker's start in one order log; a copy-only save → 0 calls of
    either.

    Why: the re-derive reads the change service; on the worker it would
    read live session state (LLR-177.1e).
    Negative control: a re-derive inside the worker → the thread arm RED;
    the base (no Save worker) → no worker start in the log → RED."""
    from s19_app.tui.services.change_service import ChangeService

    base = tmp_path / "app"
    trio(W(base) / "P2")
    order: list = []
    main_box = [threading.get_ident()]

    def mark(name):
        return lambda *_a, **_k: order.append((name, threading.get_ident() == main_box[0]))

    Spy(monkeypatch, ChangeService, "rederive_for_save", before=mark("rederive"))
    Spy(monkeypatch, app_module, "render_patched_image", before=mark("render"))
    Spy(monkeypatch, S19TuiApp, "_save_project_worker", before=mark("worker"))

    async def scenario(app, pilot, log):
        await open_trio_project(app, pilot, "P2")
        save(app, "COPY")
        await settle_workers(pilot)
        await wait(pilot, lambda: (W(base) / "COPY" / "project.json").exists(), "the copy-only save")
        copy_only = list(order)
        order.clear()
        await patch_one_byte(app, pilot)
        save(app, "EMIT")
        await settle_workers(pilot)
        await wait(pilot, lambda: (W(base) / "EMIT" / "project.json").exists(), "the emitting save")
        return copy_only, list(order)

    copy_only, emitting = run(base, scenario)
    assert [n for n, _m in copy_only if n != "worker"] == [], copy_only
    names = [n for n, _m in emitting]
    assert "worker" in names, f"no Save worker started: {emitting}"
    worker_at = names.index("worker")
    for step in ("rederive", "render"):
        assert step in names[:worker_at], (step, emitting)
        assert all(m for n, m in emitting if n == step), (step, emitting)


def test_tc_b100_53_save_adopts_only_after_the_commit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """LLR-177.1j, LLR-167.2 / review F4 (P1-69): an emitting save of a
    patched session as ``Q`` → 0 ``adopt_rederived`` calls when the
    request returns, then exactly 1, on the main thread, made after
    ``W/Q/project.json`` exists; a forced manifest-write failure
    (``_write_manifest_for_save`` returns ``(None, "forced refusal")``) →
    0 adopts, ``project.json was not written`` in the last log line, ``W/Q2``
    absent.

    Why: adopting before ``project.json`` is on disk shows an image no
    file holds (F4).
    Negative control: an adopt in the kickoff (the old "apply before"
    text) → 1 adopt in the request frame and in the failure arm → RED."""
    from s19_app.tui.services.change_service import ChangeService

    base = tmp_path / "app"
    trio(W(base) / "P2")
    target = W(base) / "Q"
    seen: list = []
    main_box = [threading.get_ident()]
    Spy(monkeypatch, ChangeService, "adopt_rederived",
        before=lambda *_a, **_k: seen.append((threading.get_ident() == main_box[0],
                                               (target / "project.json").exists())))

    async def scenario(app, pilot, log):
        await open_trio_project(app, pilot, "P2")
        await patch_one_byte(app, pilot)
        save(app, "Q")
        in_frame = len(seen)
        await settle_workers(pilot)
        await wait(pilot, lambda: (target / "project.json").exists(), "the save of Q")
        committed = list(seen)
        seen.clear()
        monkeypatch.setattr(S19TuiApp, "_write_manifest_for_save",
                            lambda self, *a, **k: (None, "forced refusal"), raising=False)
        await patch_one_byte(app, pilot, PATCH_ADDRESS - 1)
        save(app, "Q2")
        await settle_workers(pilot)
        return in_frame, committed, list(seen), log_tail(app)[0], (W(base) / "Q2").exists()

    in_frame, committed, failed, last, q2 = run(base, scenario)
    assert in_frame == 0, f"{in_frame} adopt(s) inside the request frame (before the worker committed)"
    assert committed == [(True, True)], committed
    assert failed == [], failed
    assert "project.json was not written" in last, last
    assert q2 is False


# ===========================================================================
# TC-B100-53 — the busy refusal (HLR-177a, LLR-177.3 … LLR-177.3h, Q-a1)
# ===========================================================================


def busy_count(log, label: str, mark: int = 0) -> int:
    return log.since(mark).count(busy(label))


async def press_refused(app, pilot, log, label: str, gesture) -> tuple:
    """Run one refused gesture; return (busy lines added, digest changed,
    stack depth changed)."""
    before = (digest(app), len(app.screen_stack))
    mark = len(log.messages)
    result = gesture()
    if asyncio.iscoroutine(result):
        await result
    for _ in range(3):
        await pilot.pause()
    return (busy_count(log, label, mark), digest(app) != before[0], len(app.screen_stack) != before[1])


def test_tc_b100_53_session_writers_are_refused_during_a_save(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """HLR-177a, LLR-177.3g (C12b-05): during a Save of ``P1`` held at its
    first placement, with a patched trio session and ``W/temp/x.s19``
    listed: ``l``; a Workarea Files pick of ``x.s19``; ``v``; ``U``; a
    save-back decision; a Patch apply; a Patch undo; ``ctrl+s`` → 8 lines
    ``busy: Saving project P1 is running — wait for it to finish.``, the
    session digest and the screen-stack depth unchanged after each (8 of
    8); released, the save completes.

    Why: two writers of the session at once is the defect class HLR-177a
    removes (an exclusive worker group lets a cancelled worker's install
    still land, P12b-1).
    Negative control (code read, base): no busy state, and the save runs
    synchronously (P12b-6) so no key reaches the app during it → RED.
    Mutation: ``v`` left out of the refused set → the selector opens →
    depth 2 → RED."""
    from s19_app.tui.screens_directionb import PatchEditorPanel

    base, hold = held_save_scene(tmp_path, monkeypatch)
    temp = W(base) / WORKAREA_TEMP
    temp.mkdir(parents=True)
    shutil.copyfile(CASE01 / "firmware.s19", temp / "x.s19")
    label = "Saving project P1"

    async def scenario(app, pilot, log):
        try:
            await start_held_save(app, pilot, hold, patch=True)
            neutral_focus(app)
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            gestures = {
                "l": lambda: pilot.press("l"),
                "pick x.s19": lambda: app._load_workarea_file("x.s19"),
                "v": lambda: pilot.press("v"),
                "U": lambda: pilot.press("U"),
                "save-back": lambda: app.on_patch_editor_panel_save_back_decision(
                    PatchEditorPanel.SaveBackDecision("firmware.s19", 32)),
                "apply": lambda: panel.request_action("apply_doc"),
                "undo": lambda: app.action_patch_undo(),
                "ctrl+s": lambda: pilot.press("ctrl+s"),
            }
            results = {}
            for name, gesture in gestures.items():
                if name in ("l", "v", "U", "ctrl+s"):
                    neutral_focus(app)
                results[name] = await press_refused(app, pilot, log, label, gesture)
        finally:
            hold.release.set()
        await settle_workers(pilot)
        await wait(pilot, lambda: (W(base) / "P1" / "project.json").exists(), "the held save to finish")
        return results, any(m.startswith("Saved project to") for m in log.messages)

    results, saved = run(base, scenario)
    assert results == {name: (1, False, False) for name in results}, results
    assert saved is True


def test_tc_b100_53_load_requests_are_refused_during_a_project_load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-177.3, LLR-177.3h (C12b-06, C12b-16 success arm): during a
    project load of ``P2`` held at ``read_project_manifest``: ``l``,
    ``ctrl+l``, ``p``, a click on ``#ws_load_project_button`` and the
    palette entries ``load_file`` and ``load_project`` (dispatched as
    actions) → 6 lines ``busy: Loading project P2 is running — wait for it
    to finish.`` and 0 ``LoadDialog`` on the stack; after the install,
    ``l`` opens the Load dialog.

    Why: a Load dialog opened during a load would start a second session
    writer. Negative control (code read, base): ``action_load_file``
    pushes the dialog unconditionally → RED."""
    base = tmp_path / "app"
    trio(W(base) / "P2")
    hold = Hold(monkeypatch, app_module, "read_project_manifest")
    label = "Loading project P2"

    async def scenario(app, pilot, log):
        try:
            app._handle_load_project("P2")
            await reached(pilot, hold, "the project load of P2")
            out = {}
            for name, gesture in (
                ("l", lambda: pilot.press("l")),
                ("ctrl+l", lambda: pilot.press("ctrl+l")),
                ("p", lambda: pilot.press("p")),
                # E4 integration re-pin: the Workspace button has a zero region at
                # start-up (a click lands on the screen), so it is pressed through
                # ``Button.press()``, which posts the same ``Button.Pressed``.
                ("button", lambda: app.query_one("#ws_load_project_button").press()),
                ("palette load_file", lambda: app.run_action("load_file")),
                ("palette load_project", lambda: app.run_action("load_project")),
            ):
                neutral_focus(app)
                mark = len(log.messages)
                result = gesture()
                if asyncio.iscoroutine(result):
                    await result
                for _ in range(3):
                    await pilot.pause()
                out[name] = (busy_count(log, label, mark), on_stack(app, "LoadDialog"))
        finally:
            hold.release.set()
        await settle_workers(pilot)
        await wait(pilot, lambda: app.current_project == "P2", "the install of P2")
        neutral_focus(app)
        await pilot.press("l")
        await ld.wait_for_dialog(pilot, app)
        return out, on_stack(app, "LoadDialog")

    out, after = run(base, scenario)
    assert out == {name: (1, 0) for name in out}, out
    assert after == 1


def test_tc_b100_53_variant_unload_and_save_are_refused_while_busy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-177.3b, LLR-177.3c, LLR-177.3d (C12b-09, C12b-10, C12b-11):
    during a held Save of ``P1``: ``v`` and the palette entry
    ``select_variant`` → 2 busy lines, 0 ``SelectVariantScreen``; ``U`` and
    the Loaded panel's unload of the A2L slot → 2 busy lines, the digest and
    ``current_a2l_path`` unchanged; ``ctrl+s`` → 1 busy line. Then, during
    a project load of ``P2`` held at its worker step: ``ctrl+s``, ``s`` and
    the palette entry ``save_project`` → 3 lines naming the project load,
    0 ``SaveProjectScreen``.

    Why: each of these would replace or rewrite the session under the
    running action. Negative control (code read, base):
    ``action_select_variant``, ``action_unload_all`` and
    ``action_save_project`` have no state check → RED."""
    from s19_app.tui.screens_directionb import LoadedArtifactsPanel

    base, hold = held_save_scene(tmp_path, monkeypatch)
    hold2 = Hold(monkeypatch, app_module, "read_project_manifest",
                 match=lambda project_dir, *a, **k: Path(project_dir).name == "P2")

    async def scenario(app, pilot, log):
        save_label = "Saving project P1"
        try:
            # E4 integration re-pin: released BEFORE the setup open of P2;
            # released after it, the open waits on this hold until the
            # 90 s setup timeout (the P2 open is setup, never held).
            hold2.release.set()
            await start_held_save(app, pilot, hold)
            a2l = app.current_a2l_path
            res = {}
            for name, gesture in (
                ("v", lambda: pilot.press("v")),
                ("palette select_variant", lambda: app.run_action("select_variant")),
                ("U", lambda: pilot.press("U")),
                ("unload a2l", lambda: app.on_loaded_artifacts_panel_unload_requested(
                    LoadedArtifactsPanel.UnloadRequested("a2l"))),
                ("ctrl+s during save", lambda: pilot.press("ctrl+s")),
            ):
                neutral_focus(app)
                res[name] = await press_refused(app, pilot, log, save_label, gesture)
            selectors = on_stack(app, "SelectVariantScreen")
            a2l_kept = app.current_a2l_path == a2l
        finally:
            hold.release.set()
        await settle_workers(pilot)
        return res, selectors, a2l_kept

    res, selectors, a2l_kept = run(base, scenario)
    assert res == {name: (1, False, False) for name in res}, res
    assert selectors == 0 and a2l_kept, (selectors, a2l_kept)

    base2 = tmp_path / "app2"
    trio(W(base2) / "P2")
    hold3 = Hold(monkeypatch, app_module, "read_project_manifest")

    async def during_load(app, pilot, log):
        label = "Loading project P2"
        try:
            await projects.load_image(pilot, app, CASE01 / "firmware.s19")
            app._handle_load_project("P2")
            await reached(pilot, hold3, "the project load of P2")
            out = {}
            for name, gesture in (
                ("ctrl+s", lambda: pilot.press("ctrl+s")),
                ("s", lambda: pilot.press("s")),
                ("palette save_project", lambda: app.run_action("save_project")),
            ):
                neutral_focus(app)
                mark = len(log.messages)
                result = gesture()
                if asyncio.iscoroutine(result):
                    await result
                for _ in range(3):
                    await pilot.pause()
                out[name] = (busy_count(log, label, mark), on_stack(app, "SaveProjectScreen"))
        finally:
            hold3.release.set()
        await settle_workers(pilot)
        return out

    out = run(base2, during_load)
    assert out == {name: (1, 0) for name in out}, out


PATCH_ACTIONS = (
    "apply_doc", "add_entry", "edit_entry", "remove_entry", "load_doc", "parse_paste",
    "refresh_doc", "validate_doc", "run_checks", "save_doc", "execute_scope",
)


def test_tc_b100_53_patch_editor_changes_are_refused_while_busy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-177.3e, ruling Q3 (C12b-12): during a held Save of ``P1`` with
    one document entry and a patched image: the 11 dispatcher actions,
    ``UndoRequested``, ``RedoRequested``, a ``SaveBackDecision``,
    ``EditJsonRequested`` and ``EntryEditJsonRequested`` → 16 busy lines;
    after each the image digest and the document's serialised entries are
    unchanged and no screen was pushed (16 of 16).

    Why: the save's commit marks the panel saved; a change made during
    the save would be marked saved although no file holds it (silent loss).
    Negative control: a refusal of only ``apply_doc`` and undo (the old
    list) → ``add_entry`` adds an entry → RED."""
    from s19_app.tui.screens_directionb import PatchEditorPanel

    base, hold = held_save_scene(tmp_path, monkeypatch)
    label = "Saving project P1"

    async def scenario(app, pilot, log):
        try:
            await start_held_save(app, pilot, hold, patch=True)
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            out = {}
            gestures = [(a, (lambda a=a: panel.request_action(a))) for a in PATCH_ACTIONS] + [
                ("undo", lambda: app.on_patch_editor_panel_undo_requested(PatchEditorPanel.UndoRequested())),
                ("redo", lambda: app.on_patch_editor_panel_redo_requested(PatchEditorPanel.RedoRequested())),
                ("save-back", lambda: app.on_patch_editor_panel_save_back_decision(
                    PatchEditorPanel.SaveBackDecision("firmware.s19", 32))),
                ("edit json", lambda: app.on_patch_editor_panel_edit_json_requested(
                    PatchEditorPanel.EditJsonRequested(""))),
                ("entry edit json", lambda: app.on_patch_editor_panel_entry_edit_json_requested(
                    PatchEditorPanel.EntryEditJsonRequested(0))),
            ]
            for name, gesture in gestures:
                before = (image16(app.current_file.mem_map), entries(app), len(app.screen_stack))
                mark = len(log.messages)
                gesture()
                for _ in range(3):
                    await pilot.pause()
                after = (image16(app.current_file.mem_map), entries(app), len(app.screen_stack))
                out[name] = (busy_count(log, label, mark), before == after)
        finally:
            hold.release.set()
        await settle_workers(pilot)
        return out

    out = run(base, scenario)
    assert len(out) == 16
    assert out == {name: (1, True) for name in out}, out


def test_tc_b100_53_patch_editor_continuations_are_refused_while_busy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-177.3e continuations, P2-5 (C12b-13 arms a, b, c): a save
    started while the result of a modal opened idle is still pending, held
    → (a) the ``ChangeSetJsonScreen`` result ``'{"entries": []}'`` reaching
    ``_apply_changeset_json_edit`` → 1 busy line, the entries unchanged;
    (b) the ``EntryJsonScreen`` result reaching ``_apply_entry_json_edit``
    → 1 line, the entry unchanged; (c) the dirty-load ``LoadGuardScreen``
    accepted → 1 line, 0 ``_patch_editor_load`` calls.

    Why: those modals do not make ``ctrl+s`` inert, so their results can
    arrive during a save (finding F-3).
    Negative control: no continuation check → arm (a) empties the document
    during the save → RED. Arm (d) (the dropdown guard) is not driven here
    (declared in the tester notes)."""
    from s19_app.tui.screens_directionb import PatchEditorPanel

    base, hold = held_save_scene(tmp_path, monkeypatch)
    label = "Saving project P1"
    loads = Spy(monkeypatch, S19TuiApp, "_patch_editor_load")

    async def scenario(app, pilot, log):
        await open_trio_project(app, pilot, "P2")
        await patch_one_byte(app, pilot)
        app.on_patch_editor_panel_dirty_load_requested(PatchEditorPanel.DirtyLoadRequested("x.json"))
        await wait(pilot, lambda: type(app.screen).__name__ == "LoadGuardScreen", "the load guard")
        guard = app.screen
        try:
            save(app, "P1")
            await reached(pilot, hold, "Save project P1")
            out = {}
            entry = entries(app)[0]
            mark = len(log.messages)
            app._apply_changeset_json_edit('{"entries": []}')
            await pilot.pause()
            out["a"] = (busy_count(log, label, mark), len(entries(app)) == 1)
            mark = len(log.messages)
            app._apply_entry_json_edit(0, json.dumps({"type": "bytes", "address": "0x80000000", "bytes": "00"}))
            await pilot.pause()
            out["b"] = (busy_count(log, label, mark), entries(app)[0] == entry)
            mark = len(log.messages)
            n_loads = len(loads.calls)
            guard.dismiss(True)
            for _ in range(3):
                await pilot.pause()
            out["c"] = (busy_count(log, label, mark), len(loads.calls) == n_loads)
        finally:
            hold.release.set()
        await settle_workers(pilot)
        return out

    assert run(base, scenario) == {"a": (1, True), "b": (1, True), "c": (1, True)}


def test_tc_b100_53_busy_line_names_the_action_and_changes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-177.3f, LLR-177.3g, HLR-177a boundary (C12b-02, C12b-03,
    C12b-14): idle, ``_refuse_if_busy()`` is ``False`` and paints nothing;
    a report held alone (not a session action) → ``l`` opens the Load
    dialog with 0 busy lines. During a held Save of ``P1``: the check is
    ``True``, the log grows by exactly 1 line (the busy line),
    ``#status_text`` keeps the progress line ``Saving project P1 · step 2/4
    Place the files``, no toast; the focus on ``#files_list`` then ``l``,
    and on ``#search_input`` then ``ctrl+l`` → each refused with the same
    focused widget, stack depth 1 and the digest unchanged; 0 decision ids
    in the line.

    Why: a refusal that moved the focus or opened anything would change
    the session it protects. Negative control: a mutant that paints with
    ``set_file_status`` → ``#status_text`` changes → RED; base: no check."""
    base, hold = held_save_scene(tmp_path, monkeypatch)

    async def scenario(app, pilot, log):
        check = getattr(app, "_refuse_if_busy", None)
        idle = (check() if check is not None else None, len(log.messages))
        gen = app.begin_busy("report", "Generating the project report", REPORT_STEPS)
        neutral_focus(app)
        mark = len(log.messages)
        await pilot.press("l")
        await ld.wait_for_dialog(pilot, app)
        report_only = (on_stack(app, "LoadDialog"), sum("busy:" in m for m in log.since(mark)))
        await pilot.press("escape")
        await ld.wait_for_dialog_closed(pilot, app)
        app.end_busy("report", gen, "")
        try:
            await start_held_save(app, pilot, hold)
            mark = len(log.messages)
            notes = len(list(getattr(app, "_notifications", [])))
            refused = check() if check is not None else None
            during = (refused, log.since(mark), status(app),
                      len(list(getattr(app, "_notifications", []))) - notes)
            focus = {}
            for widget_id, key in (("#files_list", "l"), ("#search_input", "ctrl+l")):
                widget = app.query_one(widget_id)
                app.set_focus(widget)
                await pilot.pause()
                before = digest(app)
                await pilot.press(key)
                for _ in range(3):
                    await pilot.pause()
                focus[widget_id] = (app.focused is widget, len(app.screen_stack), digest(app) == before)
        finally:
            hold.release.set()
        await settle_workers(pilot)
        return idle, report_only, during, focus

    idle, report_only, (refused, added, text, toasts), focus = run(base, scenario)
    assert idle == (False, idle[1]), idle
    assert report_only == (1, 0), report_only
    assert refused is True, refused
    assert added == [busy("Saving project P1")], added
    assert not DECISION_ID.search(added[0]), added
    assert re.match(r"^[" + FRAMES + r"] Saving project P1  ·  step 2/4 Place the files  ·  \d\d:\d\d$",
                    text), text
    assert toasts == 0, toasts
    assert focus == {"#files_list": (True, 1, True), "#search_input": (True, 1, True)}, focus


@pytest.mark.parametrize("folder,label", [("[b]P", "[b]P"), ("A\u202eB", "AB")])
def test_tc_b100_53_busy_line_paints_a_hostile_name_literally(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, folder: str, label: str
) -> None:
    """LLR-177.3f boundary (C12b-04): a project ``[b]P`` (and one named with
    a U+202E override) held at its worker step → ``l`` paints ``busy:
    Loading project [b]P is running — wait for it to finish.`` (and ``…
    project AB …``) with 0 markup spans in ``#log_line_4``.

    Why: a project name is user data; painted as markup it would restyle
    the status log or hide its text. Negative control: a fixed ``busy``
    with no label → RED; base: no busy line at all → RED."""
    base = tmp_path / "app"
    try:
        trio(W(base) / folder)
    except OSError as exc:  # pragma: no cover - platform refuses the name
        pytest.skip(f"the folder name cannot be created here: {exc}")
    hold = Hold(monkeypatch, app_module, "read_project_manifest")

    async def scenario(app, pilot, log):
        try:
            app._handle_load_project(folder)
            await reached(pilot, hold, f"the project load of {folder!r}")
            neutral_focus(app)
            await pilot.press("l")
            for _ in range(3):
                await pilot.pause()
            line = app.query_one("#log_line_4")
            visual = getattr(line, "visual", None) or line.render()
            spans = list(getattr(visual, "spans", None) or [])
            return log_tail(app)[0], str(getattr(visual, "plain", visual)), spans
        finally:
            hold.release.set()
            await settle_workers(pilot)

    last, painted, spans = run(base, scenario)
    assert last == busy(f"Loading project {label}"), last
    assert painted == busy(f"Loading project {label}"), painted
    assert spans == [], spans


def test_tc_b100_53_refusals_stop_after_each_project_load_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-177.3h, LLR-177.2 (C12b-16, P1-27, P1-36): a project load that
    installs, one of ``A2LONLY`` whose A2L does not parse (the refusal
    ``No supported files in project: A2LONLY``) and one whose
    ``read_project_manifest`` raises ``ValueError`` (``could not be read``)
    → each ends in its outcome line and, after each, ``l`` opens the Load
    dialog (3 of 3); no exception leaves the request.

    Why: a run left set after a failure would refuse every later request.
    Negative control: a failure arm that never ends its run → ``l`` paints
    the busy line → RED; base: the forced exception leaves the request →
    RED."""
    base = tmp_path / "app"
    wa = W(base)
    trio(wa / "P2")
    trio(wa / "A2LONLY", names=("firmware.a2l",))
    trio(wa / "PF")
    real_manifest = app_module.read_project_manifest
    real_parse = app_module.parse_a2l_file

    def _manifest(project_dir, *a, **k):
        if Path(project_dir).name == "PF":
            raise ValueError("synthetic")
        return real_manifest(project_dir, *a, **k)

    def _parse(path, *a, **k):
        if Path(path).parent.name == "A2LONLY":
            raise ValueError("synthetic")
        return real_parse(path, *a, **k)

    monkeypatch.setattr(app_module, "read_project_manifest", _manifest)
    monkeypatch.setattr(app_module, "parse_a2l_file", _parse)

    async def scenario(app, pilot, log):
        out = []
        for name in ("P2", "A2LONLY", "PF"):
            raised = None
            try:
                app._handle_load_project(name)
            except Exception as exc:  # noqa: BLE001 — recorded, the base raises here
                raised = type(exc).__name__
            await settle_workers(pilot)
            last = log_tail(app)[0]
            neutral_focus(app)
            mark = len(log.messages)
            await pilot.press("l")
            for _ in range(6):
                await pilot.pause()
            opened = on_stack(app, "LoadDialog")
            refused = sum("busy:" in m for m in log.since(mark))
            if opened:
                await pilot.press("escape")
                await ld.wait_for_dialog_closed(pilot, app)
            out.append((name, raised, last, opened, refused))
        return out

    out = run(base, scenario)
    assert [r[1] for r in out] == [None, None, None], out
    assert out[0][2].startswith("Loaded project 'P2'"), out[0]
    assert out[1][2] == "No supported files in project: A2LONLY", out[1]
    assert out[2][2] == ("Project NOT loaded: 'PF' could not be read — check that the folder can be "
                         "opened, then load again."), out[2]
    assert [(r[3], r[4]) for r in out] == [(1, 0)] * 3, out


def test_tc_b100_53_action_starts_refuse_while_another_session_action_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """HLR-177a, interfaces Q-a1 (C12b-17, P1-12, P1-56, C12b-41): during an
    A2L attach of case_01 held at its parse: ``load_from_path``,
    ``load_a2l_from_path``, ``_handle_load_project`` and
    ``_handle_save_dialog`` → 4 lines ``busy: Loading firmware.a2l is
    running — wait for it to finish.``; after each, the run state still
    holds only ``a2l_load``, ``W/S9`` does not exist and
    ``current_project`` is unchanged; the ``load_a2l_from_path`` refusal
    resolves no path (the check comes first).

    Why: a direct start (a helper, a chained test, a future route) must not
    race two session writers either. Negative control: only the 17 entry
    points check → ``load_from_path`` begins ``file_load`` beside
    ``a2l_load`` → RED."""
    base = tmp_path / "app"
    trio(W(base) / "P")
    shutil.copyfile(CASE01 / "firmware.a2l", tmp_path / "other.a2l")
    hold = Hold(monkeypatch, app_module, "parse_a2l_file")
    resolves = Spy(monkeypatch, app_module, "resolve_input_path")
    label = "Loading firmware.a2l"

    async def scenario(app, pilot, log):
        await projects.load_image(pilot, app, CASE01 / "firmware.s19")
        try:
            app.load_a2l_from_path(CASE01 / "firmware.a2l")
            await reached(pilot, hold, "the A2L attach")
            out = {}
            for name, gesture in (
                ("load_from_path", lambda: app.load_from_path(CASE01 / "firmware.s19")),
                ("load_a2l_from_path", lambda: app.load_a2l_from_path(tmp_path / "other.a2l")),
                ("_handle_load_project", lambda: app._handle_load_project("P")),
                ("_handle_save_dialog", lambda: save(app, "S9")),
            ):
                mark = len(log.messages)
                n_resolve = len(resolves.calls)
                gesture()
                await pilot.pause()
                out[name] = (busy_count(log, label, mark), list(app._busy.runs),
                             (W(base) / "S9").exists(), app.current_project,
                             len(resolves.calls) - n_resolve)
        finally:
            hold.release.set()
        await settle_workers(pilot)
        return out

    out = run(base, scenario)
    for name, (lines, runs, s9, project, n_resolve) in out.items():
        assert (lines, runs, s9, project) == (1, ["a2l_load"], False, None), (name, out[name])
    assert out["load_a2l_from_path"][4] == 0, out["load_a2l_from_path"]


def test_tc_b100_53_running_session_action_ignores_reports(tmp_path: Path) -> None:
    """HLR-177a, ruling Q2 (C12b-01): over synthetic runs begun with 12a's
    labels, ``_running_session_action()`` returns (a) the ``save_project``
    run after ``report`` then ``save_project``; (b) still that run after
    ``save_project`` then ``report``; (c) ``None`` for a report alone; (d)
    ``None`` with no run; (e) the ``a2l_load`` run after ``file_load`` then
    ``a2l_load`` (5 of 5).

    Why: reports may overlap a session action; the busy line must never
    name a report. Negative control: the newest run of any key → arm (b)
    names the report → RED; base: no such method → RED."""

    async def scenario(app, pilot, log):
        get = getattr(app, "_running_session_action", None)
        assert get is not None, "S19TuiApp has no _running_session_action (no busy check)"
        out = []

        def label():
            run_ = get()
            return None if run_ is None else run_.label

        out.append(label())  # (d)
        g_r = app.begin_busy("report", "Generating the project report", REPORT_STEPS)
        out.append(label())  # (c)
        g_s = app._busy_begin_action("save_project", "P1")
        out.append(label())  # (a)
        app.end_busy("report", g_r, "")
        g_r = app.begin_busy("report", "Generating the project report", REPORT_STEPS)
        out.append(label())  # (b)
        app.end_busy("report", g_r, "")
        app.end_busy("save_project", g_s, "")
        g_f = app._busy_begin_action("file_load", "x.s19")
        g_a = app._busy_begin_action("a2l_load", "firmware.a2l")
        out.append(label())  # (e)
        app.end_busy("a2l_load", g_a, "")
        app.end_busy("file_load", g_f, "")
        return out

    assert run(tmp_path / "app", scenario) == [
        None, None, "Saving project P1", "Saving project P1", "Loading firmware.a2l",
    ]


def test_tc_b100_53_paste_box_is_read_only_during_a_project_load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """E3 S12b-04, R2-02 (C12b-55): while a ``project_load`` run exists the
    Patch Editor's ``#patch_paste_text`` is read-only — keys typed into it
    during a held load insert nothing and the panel does not turn dirty;
    after the install ``read_only`` is ``False`` and typing inserts; after a
    load that FAILS on its worker ``read_only`` is ``False`` too.

    Why: the install's reset would empty a paste typed during the 5.8 s
    worker step with no question asked (the load question was already
    answered). Negative control: an editable box during the load → the
    typed text is inserted → RED; base: no worker (the held step runs on
    the main thread) → RED."""
    from textual.widgets import TextArea

    base = tmp_path / "app"
    trio(W(base) / "P2")
    trio(W(base) / "PF")
    hold = Hold(monkeypatch, app_module, "read_project_manifest",
                match=lambda project_dir, *a, **k: Path(project_dir).name == "P2")
    hold_f = Hold(monkeypatch, app_module, "read_project_manifest",
                  match=lambda project_dir, *a, **k: Path(project_dir).name == "PF",
                  raise_on_release=PermissionError("synthetic"))

    async def type_into(app, pilot, text: str) -> None:
        box = app.query_one("#patch_paste_text", TextArea)
        app.set_focus(box)
        await pilot.pause()
        await pilot.press(*text)
        await pilot.pause()

    async def scenario(app, pilot, log):
        await pilot.press("6")
        for _ in range(4):
            await pilot.pause()
        box = app.query_one("#patch_paste_text", TextArea)
        try:
            app._handle_load_project("P2")
            await reached(pilot, hold, "the project load of P2")
            before = box.text
            await type_into(app, pilot, "zq")
            during = (box.read_only, box.text == before)
        finally:
            hold.release.set()
        await settle_workers(pilot)
        after_ok = box.read_only
        before = box.text
        await type_into(app, pilot, "zq")
        typed_after = box.text != before
        try:
            app._handle_load_project("PF")
            await reached(pilot, hold_f, "the project load of PF")
            failing = box.read_only
        finally:
            hold_f.release.set()
        await settle_workers(pilot)
        return during, after_ok, typed_after, failing, box.read_only

    during, after_ok, typed_after, failing, after_fail = run(base, scenario)
    assert during == (True, True), during
    assert (after_ok, typed_after) == (False, True), (after_ok, typed_after)
    assert (failing, after_fail) == (True, False), (failing, after_fail)


def test_tc_b100_53_a_load_queued_under_the_save_dialog_is_refused_at_its_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SE5-11-3 (Inc 11 E5, routed to Inc 12b), HLR-177a, Q-a1: the Save
    project dialog open with ``P`` typed and its summary painted; a file
    load of ``other.s19`` is then running (held in its worker at
    ``_parse_loaded_file``) when the engineer confirms → the Save router
    reaches its commit while a session action runs → the busy line naming
    ``Loading other.s19`` is painted and nothing is committed (``W/P`` does
    not exist); released, the load lands.

    Why: a load landing between the confirm and the router would commit a
    plan the engineer never saw (SE5-11-3); the busy rule at the commit is
    the 12b mitigation the Inc 11 ruling asked for.
    Negative control (base): no busy rule → the router commits → ``W/P``
    exists → RED."""
    base = tmp_path / "app"
    src = tmp_path / "src"
    src.mkdir()
    shutil.copyfile(CASE01 / "firmware.s19", src / "other.s19")
    hold = Hold(monkeypatch, S19TuiApp, "_parse_loaded_file",
                match=lambda self, path, *a, **k: Path(path).name == "other.s19")

    async def scenario(app, pilot, log):
        await projects.load_image(pilot, app, CASE01 / "firmware.s19")
        await sd.open_save_dialog(pilot, app)
        await sd.type_name(pilot, app, "P")
        await sd.wait_painted(pilot, app, "P")
        try:
            app.load_from_path(src / "other.s19")
            await reached(pilot, hold, "the load of other.s19")
            mark = len(log.messages)
            await pilot.click("#save_ok")
            for _ in range(8):
                await pilot.pause()
            refused = busy_count(log, "Loading other.s19", mark)
            committed = (W(base) / "P").exists()
        finally:
            hold.release.set()
        await settle_workers(pilot)
        return refused, committed, Path(app.current_file.path).name

    refused, committed, name = run(base, scenario)
    assert committed is False, "the Save committed while a file load was running"
    assert refused == 1, refused
    assert name == "other.s19", name


@pytest.mark.xfail(reason="design silent: Inc 11 O-1", strict=False)
def test_tc_b100_53_a_source_that_vanished_under_the_dialog_is_refused_by_the_save_worker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Inc 11 O-1 (routed): the trio ``P2`` open, the Save dialog open on
    ``Q2`` with its summary painted, then ``W/P2/firmware.mac`` is deleted
    and the save confirmed → the Save worker refuses with the base
    ``source file missing`` wording and creates no ``W/Q2``.

    The Inc 12b design (E1 draft, interfaces, both prototypes) is silent on
    this case, so the arm is an expected failure (brief: "design silent:
    Inc 11 O-1")."""
    base = tmp_path / "app"
    trio(W(base) / "P2")

    async def scenario(app, pilot, log):
        await open_trio_project(app, pilot, "P2")
        await sd.open_save_dialog(pilot, app)
        await sd.type_name(pilot, app, "Q2")
        await sd.wait_painted(pilot, app, "Q2")
        (W(base) / "P2" / "firmware.mac").unlink()
        mark = len(log.messages)
        await pilot.click("#save_ok")
        await settle_workers(pilot)
        for _ in range(6):
            await pilot.pause()
        return log.since(mark), (W(base) / "Q2").exists()

    added, exists = run(base, scenario)
    assert any("source file missing" in m for m in added), added
    assert exists is False


# ===========================================================================
# TC-B100-53 — quit (HLR-177b, HLR-177c, LLR-177.4 … LLR-177.4d)
# ===========================================================================


def is_quit_question(screen) -> bool:
    try:
        return str(screen.query_one("#confirm_title").render()) == "Quit?"
    except Exception:  # noqa: BLE001 — not a question screen
        return False


def quit_texts(app) -> tuple:
    def plain(widget_id):
        widget = app.screen.query_one(widget_id)
        visual = getattr(widget, "visual", None) or widget.render()
        text = getattr(widget, "label", None)
        if text is not None:
            return getattr(text, "plain", str(text))
        return str(getattr(visual, "plain", visual))

    return tuple(plain(i) for i in ("#confirm_title", "#confirm_body", "#confirm_yes", "#confirm_no"))


def test_tc_b100_53_quit_asks_only_while_a_session_action_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """HLR-177b, LLR-177.4, LLR-177.4a, LLR-177.4d, Q-c2 (C12b-18, C12b-19,
    C12b-20, C12b-27): idle ``q`` and idle ``ctrl+q`` exit at once with no
    question; a report held alone does not make ``q`` ask. During a held
    Save of ``P1``: ``q``, ``ctrl+q`` and the palette entry ``quit`` each
    open the quit question — title ``Quit?``, text ``still working: Saving
    project P1 — wait, or quit after it finishes``, buttons ``Quit (y)`` /
    ``Stay (n)``, the focus on ``#confirm_no``, the app running, no
    ``Replace`` and no decision id; a second ``ctrl+q`` while it is open
    stacks nothing.

    Why: quitting mid-save leaves a partial project; idle quit must stay
    one key. Negative control (code read, base): no ``action_quit``
    override → ``q`` exits at once during the save → RED."""

    for key in ("q", "ctrl+q"):
        exited, questions = run(tmp_path / f"idle-{key}", _idle_scene(key))
        assert (exited, questions) == (True, 0), (key, exited, questions)

    async def report_only(app, pilot, log):
        app.begin_busy("report", "Generating the project report", REPORT_STEPS)
        neutral_focus(app)
        await pilot.press("q")
        return await wait_exit(app, 15)

    assert run(tmp_path / "report", report_only) is True

    base, hold = held_save_scene(tmp_path, monkeypatch)

    async def scenario(app, pilot, log):
        out = {}
        try:
            await start_held_save(app, pilot, hold)
            for name, gesture in (
                ("q", lambda: pilot.press("q")),
                ("ctrl+q", lambda: pilot.press("ctrl+q")),
                ("palette quit", lambda: app.run_action("quit")),
            ):
                neutral_focus(app)
                result = gesture()
                if asyncio.iscoroutine(result):
                    await result
                await wait(pilot, lambda: is_quit_question(app.screen) or not running(app), f"{name} to ask", 10)
                texts = quit_texts(app) if is_quit_question(app.screen) else None
                focused = getattr(app.focused, "id", None)
                depth = len(app.screen_stack)
                again = None
                if name == "ctrl+q":
                    await pilot.press("ctrl+q")
                    for _ in range(3):
                        await pilot.pause()
                    again = len(app.screen_stack)
                out[name] = (texts, focused, running(app), depth, again)
                await pilot.press("n")
                await wait(pilot, lambda: not is_quit_question(app.screen), "the question to close", 10)
        finally:
            hold.release.set()
        await settle_workers(pilot)
        return out, running(app)

    out, still_running = run(base, scenario)
    expected = ("Quit?", quit_body("Saving project P1"), "Quit (y)", "Stay (n)")
    for name, (texts, focused, alive, depth, again) in out.items():
        assert texts == expected, (name, texts)
        assert (focused, alive) == ("confirm_no", True), (name, focused, alive)
        assert not any("Replace" in t for t in texts) and not any(DECISION_ID.search(t) for t in texts)
    assert out["ctrl+q"][4] == out["ctrl+q"][3], out["ctrl+q"]
    assert still_running is True


def _idle_scene(key: str):
    async def scenario(app, pilot, log):
        neutral_focus(app)
        await pilot.press(key)
        exited = await wait_exit(app, 15)
        return exited, sum(1 for s in app.screen_stack if is_quit_question(s))

    return scenario


def test_tc_b100_53_idle_quit_under_the_load_question_keeps_the_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-177.4d boundary, LLR-174.2g (C12b-27): with the Inc 10 load
    question open and no session action running, ``q`` is kept by the
    question (0 exits, the question still open); during a held load the
    same app would ask (covered above). Here the base and 12b agree, so the
    arm is paired with a busy arm: a project load held at its worker step,
    ``q`` asks the quit question instead of exiting.

    Why: the override must not turn ``q`` under a modal into an exit.
    Negative control: an override that always exits on idle → 1 exit → RED;
    base: the held load runs on the main thread → RED."""
    base = tmp_path / "app"
    trio(W(base) / "P2")
    temp = W(base) / WORKAREA_TEMP
    temp.mkdir(parents=True)
    shutil.copyfile(CASE01 / "firmware.s19", temp / "x.s19")
    hold = Hold(monkeypatch, app_module, "read_project_manifest")

    async def scenario(app, pilot, log):
        await projects.load_image(pilot, app, CASE01 / "firmware.s19")
        await patch_one_byte(app, pilot)
        app._load_workarea_file("x.s19")
        await wait(pilot, lambda: type(app.screen).__name__ == "ConfirmQuestionScreen", "the load question", 10)
        await pilot.press("q")
        for _ in range(4):
            await pilot.pause()
        kept = (running(app), type(app.screen).__name__)
        await pilot.press("n")
        await wait(pilot, lambda: type(app.screen).__name__ != "ConfirmQuestionScreen", "the question to close", 10)
        try:
            app._handle_load_project("P2")
            await reached(pilot, hold, "the project load of P2")
            neutral_focus(app)
            await pilot.press("q")
            await wait(pilot, lambda: is_quit_question(app.screen) or not running(app), "the quit question", 10)
            busy_q = (is_quit_question(app.screen), running(app))
            if busy_q[0]:
                await pilot.press("n")
        finally:
            hold.release.set()
        await settle_workers(pilot)
        return kept, busy_q

    assert run(base, scenario) == ((True, "ConfirmQuestionScreen"), (True, True))


def test_tc_b100_53_stay_keeps_the_save_running(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """LLR-177.4b (C12b-21): during a held Save of ``P1``, three quit
    questions answered ``n``, ``escape`` and an immediate ``enter`` → each
    closes, the app runs and ``_quit_pending`` is ``False``; released, the
    save's outcome ``Saved project to …P1 (variant 'firmware')`` paints and
    the app still runs.

    Why: Stay must never quit, and must not leave a pending quit behind.
    Negative control: an exit on any answer → the ``n`` arm stops the app →
    RED; base: ``q`` exits at once → RED."""
    base, hold = held_save_scene(tmp_path, monkeypatch)

    async def scenario(app, pilot, log):
        out = []
        try:
            await start_held_save(app, pilot, hold)
            for answer in ("n", "escape", "enter"):
                neutral_focus(app)
                await pilot.press("q")
                await wait(pilot, lambda: is_quit_question(app.screen) or not running(app), "the question", 10)
                asked = is_quit_question(app.screen)
                await pilot.press(answer)
                for _ in range(4):
                    await pilot.pause()
                out.append((asked, is_quit_question(app.screen), running(app),
                            getattr(app, "_quit_pending", None)))
        finally:
            hold.release.set()
        await settle_workers(pilot)
        # E4 integration re-pin: the full outcome line from the status
        # messages; ``log_lines`` is capped to the window width (N2) and the
        # scratch path is longer than 118 columns.
        return out, log.messages[-1], running(app)

    out, last, alive = run(base, scenario)
    assert out == [(True, False, True, False)] * 3, out
    assert last.startswith("Saved project to ") and last.endswith("P1 (variant 'firmware')"), last
    assert alive is True


@pytest.mark.parametrize("arm", ["save", "save_fails", "project", "a2l"])
def test_tc_b100_53_confirmed_quit_waits_for_the_end(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: str
) -> None:
    """LLR-177.4c, HLR-177c, E3 S12b-01 (C12b-22, C12b-23, C12b-24,
    C12b-25, P1-33, P1-73, P1-85): ``q`` then ``y`` while an action is held
    → the app keeps running while held; released:
    - ``save``: the app exits, and ``W/P1/project.json`` records exactly
      the files on disk (hashlib, never the app's reader);
    - ``save_fails`` (the held placement raises ``OSError(28)``): the app
      KEEPS running, the failure line is the last log line, the failure
      toast is shown, ``W/P1`` is absent, the entries are kept and the quit
      is no longer pending;
    - ``project``: the app exits after the install (at exit
      ``current_project == "P2"`` and the announcement is composed);
    - ``a2l``: the app exits after the tag-table build ran once.

    Why: exiting at once runs the worker's end handler on a stopped app
    (P12b-3) and can leave a half-written project; a failed save must stay
    on screen so the engineer sees it failed.
    Negative control: an exit on ``y`` → the app stops while held → RED;
    base: ``q`` exits at once with no question → RED."""
    base = tmp_path / "app"
    trio(W(base) / "P2")
    at_exit: list = []
    views = Spy(monkeypatch, S19TuiApp, "update_a2l_view")
    real_exit = S19TuiApp.exit

    def _exit(self, *args, **kwargs):
        at_exit.append(SimpleNamespace(project=self.current_project,
                                       announcement=getattr(self, "_last_load_announcement", None),
                                       views=len(views.calls),
                                       a2l=self.current_a2l_path))
        return real_exit(self, *args, **kwargs)

    monkeypatch.setattr(S19TuiApp, "exit", _exit)
    # E4 integration re-pin: the toast is read from a ``notify`` spy; the
    # ``save_fails`` arm first waits 60 s for an exit that must not come, and
    # the 10 s toast has expired from ``_notifications`` by then.
    toasts = Spy(monkeypatch, S19TuiApp, "notify")
    if arm in ("save", "save_fails"):
        hold = Hold(monkeypatch, app_module, "place_into_workarea",
                    raise_on_release=OSError(28, "synthetic no space") if arm == "save_fails" else None)
    elif arm == "project":
        hold = Hold(monkeypatch, app_module, "read_project_manifest")
    else:
        hold = Hold(monkeypatch, app_module, "parse_a2l_file")

    async def scenario(app, pilot, log):
        if arm in ("save", "save_fails"):
            await open_trio_project(app, pilot, "P2")
            await patch_one_byte(app, pilot)
            n_entries = len(entries(app))
            save(app, "P1")
            await reached(pilot, hold, "Save project P1")
        elif arm == "project":
            n_entries = 0
            app._handle_load_project("P2")
            await reached(pilot, hold, "the project load of P2")
        else:
            n_entries = 0
            app.load_a2l_from_path(CASE01 / "firmware.a2l")
            await reached(pilot, hold, "the A2L attach")
        try:
            neutral_focus(app)
            await pilot.press("q")
            await wait(pilot, lambda: is_quit_question(app.screen) or not running(app), "the quit question", 10)
            asked = is_quit_question(app.screen)
            await pilot.press("y")
            for _ in range(6):
                await pilot.pause()
            held_alive = running(app)
        finally:
            hold.release.set()
        exited = await wait_exit(app, 60)
        if exited:
            return SimpleNamespace(asked=asked, held_alive=held_alive, exited=True)
        await settle_workers(pilot)
        notes = [(c.kwargs.get("title"), c.args[1] if len(c.args) > 1 else c.kwargs.get("message"))
                 for c in toasts.calls]
        return SimpleNamespace(asked=asked, held_alive=held_alive, exited=False, last=log_tail(app)[0],
                               notes=notes, entries=len(entries(app)) == n_entries,
                               pending=getattr(app, "_quit_pending", None))

    got = run(base, scenario, notifications=True)
    assert got.asked is True, "q did not ask during the held action"
    assert got.held_alive is True, "the app stopped while the action was still held"
    if arm == "save":
        assert got.exited is True, "the app did not exit after the save ended"
        target = W(base) / "P1"
        manifest = projects.read_manifest(target)
        # E4 integration re-pin: the patched session's pasted document lands
        # as ``patches/changes.json`` and the manifest records it (Inc 8a);
        # ``file_records`` lists only the top-level data/A2L files.
        recorded = manifest.get("files") or {}
        assert recorded == on_disk_records(target, recorded), recorded
        assert projects.file_records(target).items() <= recorded.items(), recorded
    elif arm == "save_fails":
        assert got.exited is False, "a failed save exited the app (the failure line was never shown)"
        assert got.last == NO_SPACE_LINE, got.last
        assert any(t == "Project not saved" for t, _m in got.notes), got.notes
        assert not (W(base) / "P1").exists()
        assert (got.entries, got.pending) == (True, False), (got.entries, got.pending)
    elif arm == "project":
        assert got.exited is True
        assert at_exit and at_exit[-1].project == "P2" and at_exit[-1].announcement is not None, at_exit
    else:
        assert got.exited is True
        assert at_exit and at_exit[-1].views == 1 and at_exit[-1].a2l is not None, at_exit


def test_tc_b100_53_quit_boundaries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """LLR-177.4c, LLR-177.4b boundaries (C12b-26, C12b-28): (1) ``q``,
    the action ends while the question is open, then ``y`` → the app exits
    at once; (2) ``q``, ``y`` (pending), ``q`` again, ``n`` → the quit is no
    longer pending, the save completes and the app keeps running; (3) over
    synthetic runs with a quit pending: a report ending while a Save run
    remains → no exit; a stale ``end_busy("save_project", 99, …)`` →
    ``False`` and no exit; the Save run ending while a report remains → the
    app exits.

    Why: the quit check must live at every effective end of a session
    action and nowhere else. Negative control: the check placed only in the
    Save handler → arm (3)'s exit is missed → RED; base: no quit flag →
    RED."""
    base, hold = held_save_scene(tmp_path, monkeypatch)

    async def ends_under_question(app, pilot, log):
        try:
            await start_held_save(app, pilot, hold)
            neutral_focus(app)
            await pilot.press("q")
            await wait(pilot, lambda: is_quit_question(app.screen) or not running(app), "the question", 10)
            asked = is_quit_question(app.screen)
        finally:
            hold.release.set()
        await app.workers.wait_for_complete()
        for _ in range(3):
            await pilot.pause()
        alive_before_y = running(app)
        await pilot.press("y")
        return asked, alive_before_y, await wait_exit(app, 15)

    assert run(base, ends_under_question) == (True, True, True)

    base2, hold2 = held_save_scene(tmp_path / "b", monkeypatch)

    async def stay_cancels(app, pilot, log):
        try:
            await start_held_save(app, pilot, hold2)
            for answer in ("y", "n"):
                neutral_focus(app)
                await pilot.press("q")
                await wait(pilot, lambda: is_quit_question(app.screen) or not running(app), "the question", 10)
                await pilot.press(answer)
                for _ in range(3):
                    await pilot.pause()
            pending = getattr(app, "_quit_pending", None)
        finally:
            hold2.release.set()
        await settle_workers(pilot)
        return pending, running(app), (W(base2) / "P1" / "project.json").exists()

    assert run(base2, stay_cancels) == (False, True, True)

    async def synthetic(app, pilot, log):
        gen_s = app._busy_begin_action("save_project", "P1")
        gen_r = app.begin_busy("report", "Generating the project report", REPORT_STEPS)
        app._quit_pending = True
        app.end_busy("report", gen_r, "")
        after_report = running(app)
        stale = app.end_busy("save_project", 99, "x")
        after_stale = running(app)
        gen_r = app.begin_busy("report", "Generating the project report", REPORT_STEPS)
        app.end_busy("save_project", gen_s, "")
        return after_report, stale, after_stale, await wait_exit(app, 10)

    assert run(tmp_path / "syn", synthetic) == (True, False, True, True)


# ===========================================================================
# TC-B100-54 — one forced raise per action (LLR-177.2, LLR-177.2a,
# LLR-177.2b)
# ===========================================================================


@pytest.mark.parametrize("exc", [PermissionError("synthetic"), ValueError("synthetic")],
                         ids=["PermissionError", "ValueError"])
def test_tc_b100_54_project_worker_failure_keeps_the_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, exc: Exception
) -> None:
    """LLR-177.2 (P1-35): ``fw.s19`` open with 1 Patch Editor entry;
    ``read_project_manifest`` raising (an ``OSError`` and a non-``OSError``)
    → ``Project NOT loaded: 'P2' could not be read — check that the folder
    can be opened, then load again.`` as the last log line, the session
    digest equal to before the request, 0 resets, the app running, the
    indicator ended, and nothing raised out of the request.

    Why: an exception escaping a ``@work(thread=True)`` body ends the app
    (P12b-2); a failed load must leave the engineer's work as it was.
    Negative control (P12b-2, executed): no catch in the worker →
    ``WorkerFailed`` → RED; base: the exception leaves the request → RED."""
    base = tmp_path / "app"
    trio(W(base) / "P2")
    shutil.copyfile(CASE01 / "firmware.s19", tmp_path / "fw.s19")
    resets = Spy(monkeypatch, S19TuiApp, "_reset_project_session")

    def _raise(*_a, **_k):
        raise exc

    async def scenario(app, pilot, log):
        await projects.load_image(pilot, app, tmp_path / "fw.s19")
        await patch_one_byte(app, pilot)
        before = digest(app)
        monkeypatch.setattr(app_module, "read_project_manifest", _raise)
        raised = None
        try:
            app._handle_load_project("P2")
        except Exception as e:  # noqa: BLE001 — recorded: the base raises here
            raised = type(e).__name__
        await settle_workers(pilot)
        return raised, before, digest(app), log_tail(app)[0], running(app), dict(app._busy.runs)

    raised, before, after, last, alive, runs = run(base, scenario)
    assert raised is None, f"{raised} left the request (a worker would have ended the app)"
    assert last == ("Project NOT loaded: 'P2' could not be read — check that the folder can be "
                    "opened, then load again."), last
    assert after == before, (before, after)
    assert len(resets.calls) == 0, len(resets.calls)
    assert (alive, runs) == (True, {}), (alive, runs)


def test_tc_b100_54_save_worker_non_os_error_rolls_back_and_reports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-177.2a, ruling Q4 (P1-64, P1-70): a patched session saved as
    ``Q`` with ``verify_written_image`` (the app module's name the Save
    worker calls, Q-b2) raising ``ValueError`` → after the wait ``W/Q`` is
    absent, the work-area tree digest equals before, the last log line is
    ``Project NOT saved: could not save — an unexpected error stopped the
    save. check the folder.`` (no exception text, S12b-02), the app runs,
    nothing raised out of the request, and the session digest,
    ``current_project`` and the variant set are unchanged.

    Why: SEC-7's "roll back, then let it surface" ends the app on a worker
    (P12b-2); the rollback must still leave no partial project.
    Negative control (code read, base): the handler re-raises after the
    rollback → RED (here the base Save never calls the app module's
    ``verify_written_image``, so ``W/Q`` is written → RED)."""
    base = tmp_path / "app"
    trio(W(base) / "P2")

    def _boom(*_a, **_k):
        raise ValueError("forced defect")

    async def scenario(app, pilot, log):
        await open_trio_project(app, pilot, "P2")
        await patch_one_byte(app, pilot)
        before = (digest(app), sd.tree_digests(app.workarea), app.current_project,
                  getattr(app._variant_set, "active_id", None))
        monkeypatch.setattr(app_module, "verify_written_image", _boom, raising=False)
        raised = None
        try:
            save(app, "Q")
        except Exception as e:  # noqa: BLE001 — recorded: the base re-raises here
            raised = type(e).__name__
        await settle_workers(pilot)
        after = (digest(app), sd.tree_digests(app.workarea), app.current_project,
                 getattr(app._variant_set, "active_id", None))
        return raised, before, after, log_tail(app)[0], running(app)

    raised, before, after, last, alive = run(base, scenario)
    assert raised is None, f"{raised} left the request"
    assert not (W(base) / "Q").exists() or not (W(base) / "Q" / "project.json").exists()
    assert last == SAVE_FAILED_UNEXPECTED, last
    assert "forced defect" not in last
    assert after == before, (before, after)
    assert alive is True


@pytest.mark.parametrize("stage", ["parse", "copy", "containment"])
def test_tc_b100_54_a2l_worker_failure_keeps_the_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    """LLR-177.2b (C12b-37, C12b-38, C12b-39): with ``p0.a2l`` attached,
    an attach of case_01's ``firmware.a2l`` whose parse raises
    ``ValueError``, whose copy raises ``PermissionError`` → ``File NOT
    loaded: 'firmware.a2l' could not be read — check that the file can be
    opened, then load again.`` as the last line, ``current_a2l_path`` and
    ``current_a2l_data`` still those of ``p0.a2l`` (identity), the app
    running, nothing raised out of the request; a containment refusal of
    the copy keeps its own line ``Cannot load A2L: …`` and paints no
    ``could not be read``.

    Why: a failed attach must not drop the A2L the engineer already had.
    Negative control (P12b-2): an escaping exception ends the app → RED;
    base: the exception leaves ``load_a2l_from_path`` → RED."""
    from s19_app.tui.workspace import WorkareaContainmentError

    base = tmp_path / "app"
    shutil.copyfile(CASE01 / "firmware.a2l", tmp_path / "p0.a2l")

    def _parse_fail(path, *a, **k):
        raise ValueError("synthetic parse")

    def _copy_fail(*_a, **_k):
        raise PermissionError(13, "synthetic denied")

    copy_threads: list = []

    def _contain(*_a, **_k):
        copy_threads.append(threading.get_ident())
        raise WorkareaContainmentError("synthetic containment refusal")

    async def scenario(app, pilot, log):
        app.load_a2l_from_path(tmp_path / "p0.a2l")
        await settle_workers(pilot)
        await wait(pilot, lambda: app.current_a2l_path is not None, "the attach of p0.a2l")
        path, data = app.current_a2l_path, app.current_a2l_data
        if stage == "parse":
            monkeypatch.setattr(app_module, "parse_a2l_file", _parse_fail)
        elif stage == "copy":
            monkeypatch.setattr(app_module, "copy_into_workarea", _copy_fail)
        else:
            monkeypatch.setattr(app_module, "copy_into_workarea", _contain)
        raised = None
        try:
            app.load_a2l_from_path(CASE01 / "firmware.a2l")
        except Exception as e:  # noqa: BLE001 — recorded: the base raises here
            raised = type(e).__name__
        await settle_workers(pilot)
        return (raised, log_tail(app)[0], app.current_a2l_path == path, app.current_a2l_data is data,
                running(app), dict(app._busy.runs), log.messages)

    main = threading.get_ident()
    raised, last, same_path, same_data, alive, runs, messages = run(base, scenario)
    assert raised is None, f"{raised} left the request"
    if stage == "containment":
        assert copy_threads and main not in copy_threads, "the A2L copy ran on the main thread (no worker)"
        assert last == "Cannot load A2L: synthetic containment refusal", last
        assert not any("could not be read" in m for m in messages), messages
    else:
        assert last == ("File NOT loaded: 'firmware.a2l' could not be read — check that the file can "
                        "be opened, then load again."), last
    assert (same_path, same_data, alive, runs) == (True, True, True, {}), (same_path, same_data, alive, runs)


# ===========================================================================
# AT-B100-18 — four halves, by keys and widget ids only
# ===========================================================================


def painted_log(app) -> list:
    out = []
    for i in range(1, 5):
        widget = app.query_one(f"#log_line_{i}")
        visual = getattr(widget, "visual", None) or widget.render()
        out.append(str(getattr(visual, "plain", visual)))
    return out


def test_at_b100_18_worker_half_case06_project_load_by_keys(tmp_path: Path) -> None:
    """AT-B100-18 worker half, HLR-177 (P1-84): the engineer presses ``p``,
    moves to the ``P6`` row (case_06 image, MAC and 37.7 MB A2L) and
    presses ``enter`` → while the load runs, ``#status_text`` shows the
    progress line and its elapsed time changes at least once; when it ends
    the status log's last line starts ``Loaded project 'P6' ->
    firmware.s19 + firmware.mac - variant 1 of 1`` and ``#status_text``
    reads ``Loaded project 'P6' -> firmware.s19 + firmware.mac``.

    Why: an elapsed time that moves is what tells the engineer the app is
    working, not frozen. Negative control (P12b-5, executed): the load
    blocks the loop for 5.81 s → no progress line is ever sampled → RED."""
    base = tmp_path / "app"
    trio(W(base) / "P6", CASE06)
    pattern = re.compile(r"^[" + FRAMES + r"] Loading project P6  ·  step [1-4]/4 .+  ·  (\d\d:\d\d)$")

    async def scenario(app, pilot, log):
        await ld.open_project_through_dialog(pilot, app, "P6", confirm="enter", wait_closed=False)
        elapsed = []
        deadline = time.monotonic() + 300
        while True:
            text = status(app)
            m = pattern.match(text)
            if m:
                elapsed.append(m.group(1))
            elif elapsed or text.startswith("Loaded project"):
                break
            if time.monotonic() > deadline:
                raise AssertionError("the P6 load never ended")
            await pilot.pause(0.05)
        await wait(pilot, lambda: status(app).startswith("Loaded project"), "the end of the P6 load", 300)
        for _ in range(4):
            await pilot.pause()
        return elapsed, painted_log(app)[-1], status(app)

    elapsed, last, final = run(base, scenario)
    assert len(set(elapsed)) >= 2, f"elapsed texts sampled during the load: {sorted(set(elapsed))}"
    assert last.startswith("Loaded project 'P6' -> firmware.s19 + firmware.mac - variant 1 of 1"), last
    assert final == "Loaded project 'P6' -> firmware.s19 + firmware.mac", final


def test_at_b100_18_refusal_half_l_during_a_save_by_keys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """AT-B100-18 refusal half, HLR-177a: the engineer opens project ``P2``
    with ``p``, saves it as ``P1`` through the Save dialog (``ctrl+s``, the
    name typed, Save) — the save held at its first placement — and, once
    ``#status_text`` shows ``Saving project P1``, presses ``l`` → the
    status log's last painted line is ``busy: Saving project P1 is running
    — wait for it to finish.`` and no Load dialog opens; released, the save
    completes.

    Why: the refusal is what keeps a second writer out while the save runs.
    Negative control (code read, base): no busy state; the save runs inside
    the click → RED."""
    base, hold = held_save_scene(tmp_path, monkeypatch)

    async def scenario(app, pilot, log):
        await ld.open_project_through_dialog(pilot, app, "P2", confirm="enter")
        await projects.dismiss_load_result_panel(pilot, app)
        try:
            await sd.save_through_dialog(pilot, app, "P1")
            await reached(pilot, hold, "Save project P1")
            await wait(pilot, lambda: "Saving project P1" in status(app), "the save's progress line", 10)
            neutral_focus(app)
            await pilot.press("l")
            for _ in range(4):
                await pilot.pause()
            out = (painted_log(app)[-1], on_stack(app, "LoadDialog"))
        finally:
            hold.release.set()
        await settle_workers(pilot)
        await wait(pilot, lambda: painted_log(app)[-1].startswith("Saved project to"), "the save to end", 30)
        return out

    assert run(base, scenario) == (busy("Saving project P1"), 0)


def test_at_b100_18_quit_half_q_during_a_save_asks_with_stay_focused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AT-B100-18 quit half, HLR-177b: during a save started by keys and
    held at its first placement, the engineer presses ``q`` → the quit
    question is on screen (``#confirm_title`` ``Quit?``), the focus is on
    ``#confirm_no`` (Stay) and the app is running; ``n`` closes it and the
    save then completes.

    Why: quitting mid-save would cut it in half. Negative control (code
    read, base): ``q`` runs Textual's ``action_quit`` → exits → RED."""
    base, hold = held_save_scene(tmp_path, monkeypatch)

    async def scenario(app, pilot, log):
        await ld.open_project_through_dialog(pilot, app, "P2", confirm="enter")
        await projects.dismiss_load_result_panel(pilot, app)
        try:
            await sd.save_through_dialog(pilot, app, "P1")
            await reached(pilot, hold, "Save project P1")
            neutral_focus(app)
            await pilot.press("q")
            await wait(pilot, lambda: is_quit_question(app.screen) or not running(app), "the quit question", 10)
            out = (is_quit_question(app.screen), getattr(app.focused, "id", None), running(app))
            if out[0]:
                await pilot.press("n")
        finally:
            hold.release.set()
        if not running(app):
            return out, False
        await settle_workers(pilot)
        return out, painted_log(app)[-1].startswith("Saved project to")

    assert run(base, scenario) == ((True, "confirm_no", True), True)


def test_at_b100_18_quit_confirm_half_slow_save_as_leaves_no_partial_folder(tmp_path: Path) -> None:
    """AT-B100-18 quit-confirm half, HLR-177c: the engineer opens project
    ``S`` (case_01 trio plus 2 000 files under ``flows/``), saves it as
    ``S9`` through the Save dialog, and while the save-as runs presses
    ``q`` then ``y`` → the app is still running right after ``y``; it exits
    once the save ends, and the work area then holds ``S9`` complete (its
    ``project.json`` records exactly the files on disk) — no partial
    project folder.

    Why: closing the app mid-copy left a partial project (the R12 backlog
    row). Negative control: an exit on ``y`` stops the app mid-copy → RED;
    base: the save-as runs inside the click, so ``q`` arrives after it and
    exits with no question → RED."""
    base = tmp_path / "app"
    s = trio(W(base) / "S")
    projects.bulk_files(s, "flows", 2000)

    async def scenario(app, pilot, log):
        await ld.open_project_through_dialog(pilot, app, "S", confirm="enter")
        await projects.dismiss_load_result_panel(pilot, app)
        await sd.save_through_dialog(pilot, app, "S9")
        neutral_focus(app)
        await pilot.press("q")
        await wait(pilot, lambda: is_quit_question(app.screen) or not running(app), "the quit question", 10)
        asked = is_quit_question(app.screen)
        if asked:
            await pilot.press("y")
            for _ in range(4):
                await pilot.pause()
        alive_after_y = running(app)
        exited = await wait_exit(app, 300)
        return asked, alive_after_y, exited

    asked, alive_after_y, exited = run(base, scenario)
    assert asked is True, "q during the save-as exited without asking"
    assert alive_after_y is True, "the app stopped right after y, with the save still running"
    assert exited is True, "the app did not exit when the save ended"
    # E4 integration re-pin: ``ensure_workarea`` creates the common
    # ``patches`` folder at start-up; it is not a project.
    folders = sorted(p.name for p in W(base).iterdir()
                     if p.is_dir() and p.name not in ("S", WORKAREA_TEMP, "patches"))
    assert folders == ["S9"], folders
    target = W(base) / "S9"
    manifest = projects.read_manifest(target)
    assert manifest.get("files") == projects.file_records(target), "S9 is a partial project"
    assert len(list((target / "flows").iterdir())) == 2000


# ===========================================================================
# AT-B100-17 — parse half (LLR-177.5, LLR-176.4)
# ===========================================================================


def test_at_b100_17_parse_half_case06_a2l_by_keys(tmp_path: Path) -> None:
    """AT-B100-17 parse half, LLR-177.5, LLR-176.4: the engineer types the
    case_06 A2L path into the Load dialog (``l``, the path, ``enter``) →
    while ``#status_text`` shows ``step 2/3 Parse`` the bar
    (``#progress_bar``) rises at least 2 times and the elapsed time
    advances; the attach then ends with ``A2L loaded: firmware.a2l`` in the
    status log.

    Why: the parse is 5 s of the 8.76 s attach; a bar frozen through it
    reads as a hang (the bar then holds while tags are extracted, E2 ruling
    P2-8). Negative control (P12b-4, executed): the loop is blocked → no
    step-2 sample → RED; no parser callback → 0 rises → RED."""
    base = tmp_path / "app"
    step2 = re.compile(r"^[" + FRAMES + r"] Loading firmware\.a2l  ·  step 2/3 Parse  ·  (\d\d:\d\d)$")

    async def scenario(app, pilot, log):
        neutral_focus(app)
        await pilot.press("l")
        await ld.wait_for_dialog(pilot, app)
        await ld.type_into_path(pilot, app, str(CASE06 / "firmware.a2l"))
        await pilot.press("enter")
        samples = []
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            m = step2.match(status(app))
            if m:
                samples.append((bar(app), m.group(1)))
            elif samples:
                break
            if painted_log(app)[-1].startswith("A2L loaded"):
                break
            await pilot.pause(0.05)
        await wait(pilot, lambda: painted_log(app)[-1] == "A2L loaded: firmware.a2l", "the attach to end", 300)
        return samples

    samples = run(base, scenario)
    values = [v for v, _e in samples]
    assert increases(values) >= 2, f"bar values sampled in step 2: {values}"
    assert len({e for _v, e in samples}) >= 2, f"elapsed texts in step 2: {sorted({e for _v, e in samples})}"



# ===========================================================================
# Inc 12b E5 corrective arms (CR12b-2, CR12b-3, SE5-12b-1)
# ===========================================================================


async def ended_or_exited(app, key: str, timeout: float = 90.0) -> bool:
    """Wait by the wall clock (never through the pilot, which needs a
    running app) until the run ``key`` is gone or the app has exited;
    then let a few frames pass. Returns ``True`` when the app exited."""
    deadline = time.monotonic() + timeout
    while app.return_code is None and key in app._busy.runs:
        if time.monotonic() > deadline:
            raise AssertionError(f"the {key} run never ended")
        await asyncio.sleep(0.02)
    for _ in range(25):
        if app.return_code is not None:
            break
        await asyncio.sleep(0.02)
    return app.return_code is not None


async def confirm_quit(app, pilot) -> bool:
    """``quit`` (the palette entry, so no focus question), then ``y``.
    Returns whether the quit question was asked."""
    await app.run_action("quit")
    await wait(pilot, lambda: is_quit_question(app.screen) or not running(app), "the quit question", 10)
    asked = is_quit_question(app.screen)
    await pilot.press("y")
    for _ in range(4):
        await pilot.pause()
    return asked


@pytest.mark.parametrize("gone", ["project_folder", "a2l_size"])
def test_tc_b100_54_a2l_attach_refuses_when_its_folder_or_file_vanished(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, gone: str
) -> None:
    """CR12b-2 / SE5-12b-2 (ruling E5, split by subject): before any busy
    run begins, ``load_a2l_from_path`` reads the open project's folder
    (``validate_project_files``) and the A2L's size (``stat``).
    - ``project_folder``: the open project ``gone`` was removed outside the
      app -> 1 line ``A2L NOT loaded: project 'gone' could not be read —
      check that the folder can be opened, then load again.``;
    - ``a2l_size``: the size ``stat`` raises ``OSError`` -> 1 line ``A2L
      file not found: <typed>``.
    Both: nothing raised out of the request, 0 begins, no run left, the app
    running.

    Why: from the Load dialog or a deferred callback the raise ends the app
    and the unsaved session is lost; a size read as 0 would skip the
    over-cap rule. Negative control (81ac4c0): both calls are unguarded ->
    ``FileNotFoundError`` / ``OSError`` leaves the request -> RED."""
    base = tmp_path / "app"
    a2l = tmp_path / "src" / "firmware.a2l"
    a2l.parent.mkdir(parents=True)
    shutil.copyfile(CASE01 / "firmware.a2l", a2l)
    begins = Spy(monkeypatch, S19TuiApp, "_busy_begin_action")
    if gone == "a2l_size":
        real_stat = pathlib.Path.stat

        def _stat(self, *args, **kwargs):
            if sys._getframe(1).f_code.co_name == "load_a2l_from_path":
                raise OSError(5, "synthetic size read failure")
            return real_stat(self, *args, **kwargs)

        monkeypatch.setattr(pathlib.Path, "stat", _stat)

    async def scenario(app, pilot, log):
        if gone == "project_folder":
            app.current_project = "gone"
            app.current_project_dir = app.workarea / "gone"
        mark = len(log.messages)
        try:
            app.load_a2l_from_path(a2l)
            raised = None
        except BaseException as exc:  # noqa: BLE001 — the RED shape
            raised = type(exc).__name__
        for _ in range(3):
            await pilot.pause()
        return raised, log.since(mark), list(app._busy.runs), running(app)

    raised, lines, runs, alive = run(base, scenario)
    expected = (
        "A2L NOT loaded: project 'gone' could not be read — check that the folder "
        "can be opened, then load again."
        if gone == "project_folder"
        else f"A2L file not found: {a2l}"
    )
    assert raised is None, f"{raised} left load_a2l_from_path"
    assert lines == [expected], lines
    assert (len(begins.calls), runs, alive) == (0, [], True), (len(begins.calls), runs, alive)


def test_tc_b100_53_report_generate_keeps_the_regions_of_a_running_save(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CR12b-3: during a held Save of ``P1`` the report viewer's Generate
    (regions R) still asks for the report (reports overlap, Q2), but leaves
    the session's ``_declared_regions`` as it was; once idle, the same
    Generate stores R.

    Why: Save records the regions in ``project.json`` and a project load
    replaces them, so regions written mid-run are lost or saved apart from
    the session without a line. Negative control (81ac4c0): Generate stores
    R while the Save runs -> RED."""
    from s19_app.tui.screens import ReportViewerScreen
    from s19_app.tui.services.report_addendum import DeclaredRegion

    base, hold = held_save_scene(tmp_path, monkeypatch)
    asked: list = []
    monkeypatch.setattr(
        S19TuiApp, "_trigger_generate_report",
        lambda self, context_bytes, declared_regions=(): asked.append(tuple(declared_regions)),
    )
    regions = (DeclaredRegion(name="R", start=0x100, end=0x1FF),)

    async def scenario(app, pilot, log):
        try:
            await start_held_save(app, pilot, hold)
            before = app._declared_regions
            app.on_report_viewer_screen_generate_requested(
                ReportViewerScreen.GenerateRequested(16, regions)
            )
            during = app._declared_regions
        finally:
            hold.release.set()
        await settle_workers(pilot)
        await wait(pilot, lambda: "save_project" not in app._busy.runs, "the save to end")
        app.on_report_viewer_screen_generate_requested(
            ReportViewerScreen.GenerateRequested(16, regions)
        )
        return before, during, app._declared_regions

    before, during, idle = run(base, scenario)
    assert during == before, f"Generate wrote the regions during the Save: {during!r}"
    assert asked == [regions, regions], asked
    assert idle == regions, idle


def test_tc_b100_53_confirmed_quit_is_withdrawn_when_pasted_entries_were_not_saved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SE5-12b-1 scenario B: a pasted entry is in the Patch Editor; ``quit``
    then ``y`` while Save project ``P1`` is held; the document write fails
    (``OSError(28)`` placing into ``P1/patches``) and the save commits
    without it -> the app KEEPS running, the last line is ``Change document
    changes.json was not saved into the project — the file could not be
    written; its entries stay in the Patch Editor``, the entry is kept and
    the quit is no longer pending.

    Why: the entries live only in memory; exiting in the same callback that
    paints the line loses them unseen. Negative control (81ac4c0): the
    committed arm keeps the pending quit -> the app exits -> RED."""
    base = tmp_path / "app"
    trio(W(base) / "P2")
    real_place = app_module.place_into_workarea

    def _patches_full(source, destination, *args, **kwargs):
        if Path(destination).name == "patches":
            raise OSError(28, "synthetic no space")
        return real_place(source, destination, *args, **kwargs)

    async def scenario(app, pilot, log):
        await open_trio_project(app, pilot, "P2")
        await patch_one_byte(app, pilot)
        monkeypatch.setattr(app_module, "place_into_workarea", _patches_full)
        hold = Hold(monkeypatch, S19TuiApp, "_write_manifest_for_save")
        save(app, "P1")
        try:
            await reached(pilot, hold, "Save project P1")
            asked = await confirm_quit(app, pilot)
        finally:
            hold.release.set()
        exited = await ended_or_exited(app, "save_project")
        if exited:
            return asked, True, None, None, None
        return (asked, False, log.messages[-1], len(entries(app)),
                getattr(app, "_quit_pending", None))

    asked, exited, last, kept, pending = run(base, scenario)
    assert asked is True
    assert exited is False, "the app exited over a save that left the pasted entries unsaved"
    assert last == (
        "Change document changes.json was not saved into the project — the file "
        "could not be written; its entries stay in the Patch Editor"
    ), last
    assert (kept, pending) == (1, False), (kept, pending)
    assert (W(base) / "P1" / "project.json").is_file(), "the save did not commit"


def test_tc_b100_53_confirmed_quit_is_withdrawn_when_editor_edits_stay_unsaved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SE5-12b-1 scenario A: the editor document is bound to
    ``P/patches/changes.json`` by a first Save project; a second entry is
    added through the Patch Editor (unsaved edits); ``quit`` then ``y``
    while the second Save of ``P`` is held -> the save commits, the last
    line names the unsaved edits and the Patch Editor save, the app KEEPS
    running, the panel is still dirty, both entries are kept and the quit
    is no longer pending.

    Why: the project records the file as it is on disk; the second entry
    lives only in the editor, and an exit loses it unseen. Negative control
    (81ac4c0): the committed arm keeps the pending quit -> exit -> RED."""
    from tests.test_b100_document import _add_through_the_panel, _panel

    base = tmp_path / "app"
    src = projects.copy_sources(tmp_path / "sources", projects.CASE01_DIR, "firmware.s19") / "firmware.s19"

    async def scenario(app, pilot, log):
        await projects.load_image(pilot, app, src)
        await _add_through_the_panel(pilot, app, "0x8000007C", "DE AD BE EF", entries_after=1)
        await projects.save_project(pilot, app, log, "P")
        await _add_through_the_panel(pilot, app, "0x80000060", "AA", entries_after=2)
        hold = Hold(monkeypatch, S19TuiApp, "_write_manifest_for_save")
        save(app, "P")
        try:
            await reached(pilot, hold, "Save project P")
            asked = await confirm_quit(app, pilot)
        finally:
            hold.release.set()
        exited = await ended_or_exited(app, "save_project")
        if exited:
            return asked, True, None, None, None, None
        return (asked, False, log.messages[-1], _panel(app)._dirty, len(entries(app)),
                getattr(app, "_quit_pending", None))

    asked, exited, last, dirty, kept, pending = run(base, scenario, size=(220, 60))
    assert asked is True
    assert exited is False, "the app exited over a save that left editor edits unsaved"
    assert last.startswith("Change document changes.json has unsaved edits") and last.endswith(
        "save it from the Patch Editor to keep them"), last
    assert (dirty, kept, pending) == (True, 2, False), (dirty, kept, pending)
