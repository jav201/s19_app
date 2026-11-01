"""Batch-100 increment 9b — the one Load dialog (HLR-173, HLR-173a … HLR-173e).

Written by the independent tester (E4) from the approved design only:
``inc-9b/E1-requirements-draft.md`` (thresholds and negative controls),
``inc-9b/E1-scope.md`` (test notes), the fixed interfaces of
``inc-9b/codewire/interfaces-9b.md``, every example line of
``codewire/proto-9b-dialog.md`` (S1-… / C1-…) and ``codewire/proto-9b-app.md``
(B01 …), and the rulings ``E1-rulings.md``, ``E2-rulings.md`` and
``E3-rulings.md`` (round-3 rows marked T bind these tests). No line of the
implementation was read.

Covers:
  - TC-B100-40 — LLR-173.1, .1a, .1b, .1c, .1e, .1f, .1g (one result, one
    router, each kind routed).
  - TC-B100-41 — LLR-173.2, .2a … .2l (opening, focus, keys, clicks), plus
    the E3 arms A9b-01 (posted ``alt+l`` with ``character="l"``), A9b-02
    (a double Enter), A9b-06 (type-ahead ``C`` + Enter, Escape + Enter),
    A9b-R2-2 and S9b-1 (``ctrl+p`` then ``ctrl+s`` over the dialog).
  - TC-B100-42 — LLR-173.3, .3a … .3d (literal names; a pick loads the
    on-disk name).
  - TC-B100-43 — LLR-173.4, .4a … .4m (the three sections).
  - TC-B100-63 — LLR-173.5, .5a … .5e (typed refusals in ``#load_reason``),
    plus S9b-4 (a pasted NUL) and S9b-7 / R3-2 (a folder named ``x.s19``).
  - TC-B100-64 — LLR-173.6, .6a, .6b, .6c, .6d, .6f, .6k, .6l, .6m, .6n and
    LLR-173.4n, plus S9b-2 (a link named ``project.json``), S9b-8 (a
    300-character preview line) and B78 (more than one MAC).
  - TC-B100-66 — LLR-173.7 (no decision id in the painted text).
  - AT-B100-14 — HLR-173 … HLR-173e, black-box through keys and the
    dialog's widget ids in a scratch work area.

Base: every new symbol (``LoadChoice``, ``LoadDialog``, the app's new
helpers) is imported or patched inside its test, so the file collects on the
base revision and each test fails there on its own: an assertion (the Load
dialog of the base has no list, ignores ``escape``, and Enter loads nothing),
or the ``ImportError`` / ``AttributeError`` of a symbol the 9b design adds.

Oracles are observable: the screen stack, the focused widget id, the painted
text of ``#load_list`` / ``#load_preview`` / ``#load_reason``, the dismiss
value a dialog hands its callback, the session (current file, project, A2L,
MAC), the Loaded panel's three slots, the store bytes and the status log.

Platform: the junction arms are Windows only; the file-symlink arms skip
where ``os.symlink`` raises (Windows without Developer Mode, R3-3); a name
the volume refuses is reported not run. Store WRITE arms need a
drive-rooted ``LOCALAPPDATA`` (LLR-172.1f), so they are Windows only.
"""
from __future__ import annotations

import ast
import asyncio
import builtins
import hashlib
import json
import os
import pathlib
import re
import shutil
import sys
import unicodedata
from pathlib import Path, PureWindowsPath

import pytest
from textual import events

import s19_app.tui.app as app_module
from s19_app.tui.workspace import WORKAREA_DIRNAME, WORKAREA_SUBDIR, WORKAREA_TEMP

from tests.support import b100_links
from tests.support import b100_load_dialog as ld
from tests.support import b100_projects as projects

ROOT = Path(__file__).resolve().parents[1]
CASE01_DIR = ROOT / "examples" / "case_01_basic_valid"
CASE02_DIR = ROOT / "examples" / "case_02_gaps_and_patch_targets"
WIN = sys.platform == "win32"
SIZE = (118, 54)

JUNCTION_ARM = pytest.mark.skipif(
    not WIN, reason="directory junctions are a Windows-only test arm (PDR C-QA-6)"
)
STORE_WRITE = pytest.mark.skipif(
    not WIN,
    reason="store write arm: LLR-172.1f needs a drive-rooted LOCALAPPDATA; Windows only",
)
CASE_ARM = pytest.mark.skipif(not WIN, reason="case-insensitive file system arm; Windows only")

MARK = "\u25cf"
DASH = "\u2014"
NOTHING = ("nothing selected", "pick a row or type a path")
READ_STEP = "check that the folder can be opened, then load again"
DECISION_ID = re.compile(r"\bD\d+\b|\bO-\d+|VS-|LLR-|HLR-")


# ---------------------------------------------------------------------------
# fixtures and readers (stdlib + the shared support modules)
# ---------------------------------------------------------------------------


def LC(kind: str, value: str):
    """``LoadChoice(kind, value)`` (lazy: the type is new at 9b)."""
    return ld.load_choice_cls()(kind, value)


def _wa(base: Path) -> Path:
    return base / WORKAREA_DIRNAME / WORKAREA_SUBDIR


def _temp(base: Path) -> Path:
    path = _wa(base) / WORKAREA_TEMP
    path.mkdir(parents=True, exist_ok=True)
    return path


def _s19() -> bytes:
    return (CASE01_DIR / "firmware.s19").read_bytes()


def _s19_other() -> bytes:
    return (CASE02_DIR / "firmware.s19").read_bytes()


def _mac() -> bytes:
    return (CASE01_DIR / "firmware.mac").read_bytes()


def _a2l() -> bytes:
    return (CASE01_DIR / "firmware.a2l").read_bytes()


def _hex() -> bytes:
    """A small, valid Intel HEX image (two data records and EOF)."""

    def record(address: int, data: bytes) -> str:
        total = len(data) + (address >> 8) + (address & 0xFF) + sum(data)
        return f":{len(data):02X}{address:04X}00{data.hex().upper()}{(-total) & 0xFF:02X}"

    lines = [record(0x0000, bytes(range(16))), record(0x0010, bytes(range(16, 32))), ":00000001FF"]
    return ("\n".join(lines) + "\n").encode("ascii")


def _project(base: Path, name: str, files: dict, manifest=None) -> Path:
    """Project folder ``name`` in the work area holding ``files`` (name ->
    bytes) and, when given, a ``project.json`` written from ``manifest``."""
    folder = _wa(base) / name
    folder.mkdir(parents=True, exist_ok=True)
    for file_name, payload in files.items():
        (folder / file_name).write_bytes(payload)
    if manifest is not None:
        (folder / "project.json").write_text(json.dumps(manifest), encoding="utf-8")
    return folder


def _temp_files(temp: Path) -> list:
    """The file names in ``temp/`` (the private ``.staging`` home, which the
    copy step may create, is not a work-area file)."""
    return sorted(p.name for p in temp.iterdir() if p.name != ".staging")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _store(lad: Path) -> Path:
    return lad / "s19_app" / "recent_sources.json"


def _kind(path_text: str) -> str:
    suffix = PureWindowsPath(path_text).suffix.casefold()
    return {".s19": "s19", ".hex": "hex", ".mac": "mac", ".a2l": "a2l"}[suffix]


def _seed_store(lad: Path, paths: list) -> Path:
    """Write the store document LLR-172.1m names (by the test, never by the
    code under test) holding ``paths`` newest first; return the store."""
    store = _store(lad)
    store.parent.mkdir(parents=True, exist_ok=True)
    doc = {"schema_version": 1, "sources": [{"path": p, "kind": _kind(p)} for p in paths]}
    store.write_bytes(json.dumps(doc, ensure_ascii=True, separators=(",", ":")).encode("ascii"))
    return store


def _lad(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    lad = tmp_path / "lad"
    lad.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("LOCALAPPDATA", str(lad))
    return lad


def _digest(app) -> tuple:
    """The E1 session digest: (current file path, SHA-256 of the installed
    image bytes, current project, current A2L path, MAC path)."""
    cur = app.current_file
    image = None
    if cur is not None and cur.path is not None and Path(cur.path).is_file():
        image = _sha(Path(cur.path))
    return (
        str(cur.path) if cur is not None else None,
        image,
        app.current_project,
        str(app.current_a2l_path) if app.current_a2l_path is not None else None,
        str(cur.mac_path) if cur is not None and cur.mac_path is not None else None,
    )


def _flat(text: str) -> str:
    return " ".join(text.split())


def _statics(screen, selector: str) -> list:
    from textual.widgets import Static

    found = list(screen.query(f"{selector} Static"))
    if not found:
        widget = screen.query_one(selector)
        if isinstance(widget, Static):
            found = [widget]
    return found


def _plain(widget) -> str:
    """The plain text of a ``Static``'s content (not clipped by the width)."""
    visual = getattr(widget, "visual", None)
    if visual is None:
        visual = widget.render()
    return str(getattr(visual, "plain", visual))


def preview_lines(screen) -> list:
    """The preview's content lines, in order (the ``● `` prefix kept)."""
    lines: list = []
    for widget in _statics(screen, "#load_preview"):
        text = _plain(widget)
        if text:
            lines.extend(text.split("\n"))
    return lines


def marked(lines: list) -> list:
    """The marked preview lines, without the ``● `` prefix."""
    return [line[len(MARK):].strip() for line in lines if line.startswith(MARK)]


def marked_names(lines: list) -> list:
    """The file name each marked line names (its last word)."""
    return sorted(line.split()[-1] for line in marked(lines) if line.split())


def reason_text(screen) -> str:
    return _flat(" ".join(_plain(w) for w in _statics(screen, "#load_reason")))


def path_value(screen) -> str:
    from textual.widgets import Input

    return screen.query_one("#load_path", Input).value


def focused_id(app):
    focused = app.focused
    return getattr(focused, "id", None)


def loaded_panel(app) -> list:
    """The Loaded panel's three slot readouts ``[image, MAC, A2L]`` as the
    user reads them (``(none)`` when a slot is absent)."""
    panel = app.screen_stack[0].query_one("#loaded_panel")
    texts = []
    for cell in panel.query(".loaded-detail"):
        content = cell.render()
        texts.append(str(getattr(content, "plain", content)))
    return texts


def panel_names(app) -> list:
    """The file names the Loaded panel names (present slots only)."""
    names = []
    for text in loaded_panel(app):
        words = text.split()
        if words and text.strip() != "(none)" and "(none)" not in text:
            names.append(words[0])
    return sorted(names)


def _status_lines(log, mark: int, *tokens: str) -> list:
    return [m for m in log.since(mark) if all(t in m for t in tokens)]


async def _settle(pilot, n: int = 6) -> None:
    for _ in range(n):
        await pilot.pause()


def _run(base: Path, scenario, size: tuple = SIZE):
    return projects.run_app(base, scenario, size=size)


async def _open(pilot, app, key: str) -> None:
    await pilot.press(key)
    await ld.wait_for_dialog(pilot, app)
    await _settle(pilot, 4)


async def _home(pilot) -> None:
    await pilot.press("1")
    await _settle(pilot, 4)


async def _wait_panel_and_close(pilot, app) -> str:
    text = await projects.read_load_result_panel(pilot, app)
    await projects.dismiss_load_result_panel(pilot, app)
    await _settle(pilot, 6)
    return text


async def _highlight_index(pilot, app, index: int) -> None:
    from textual.widgets import OptionList

    lst = app.screen.query_one("#load_list", OptionList)
    for _ in range(lst.option_count * 2 + 2):
        if lst.highlighted == index:
            return
        await pilot.press("down" if lst.highlighted is None or lst.highlighted < index else "up")
        await pilot.pause()
    raise AssertionError(f"the arrow keys did not reach row {index}")


def _section_index(screen, heading: str, position: int = 0) -> int:
    """The ``#load_list`` index of the ``position``-th loadable row under
    ``heading``."""
    from textual.widgets import OptionList

    lst = screen.query_one("#load_list", OptionList)
    inside = False
    seen = 0
    for i in range(lst.option_count):
        option = lst.get_option_at_index(i)
        prompt = str(option.prompt)
        if prompt in ld.HEADINGS and option.disabled:
            inside = prompt == heading
            continue
        if inside and not option.disabled:
            if seen == position:
                return i
            seen += 1
    raise AssertionError(f"no loadable row {position} under {heading!r}: {ld.option_prompts(screen)!r}")


def _bad_categories(text: str) -> list:
    return [hex(ord(ch)) for ch in text if unicodedata.category(ch) in ("Cc", "Cf", "Cs")]


def _scrubbed(name: str) -> str:
    """LLR-172.6's wording: every Cc / Cf / Zl / Zp character removed, an
    unpaired surrogate as U+FFFD, clipped to 120 characters ending in "…"."""
    out = []
    for ch in name:
        if 0xD800 <= ord(ch) <= 0xDFFF:
            out.append("\ufffd")
        elif unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp"):
            continue
        else:
            out.append(ch)
    text = "".join(out)
    if len(text) > 120:
        text = text[:119] + "\u2026"
    return text


def _make_or_skip(path: Path, payload: bytes = b"", folder: bool = False) -> None:
    try:
        if folder:
            path.mkdir(parents=True)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
    except (OSError, UnicodeError, ValueError) as exc:
        pytest.skip(f"the volume refuses this name (reported not run): {exc}")


def _symlink_or_skip(link: Path, target: Path) -> None:
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"os.symlink is unavailable here (R3-3, reported not run): {exc}")


# --- the dialog alone, fed by fakes (the G-A examples) ----------------------


def ROWS_A() -> list:
    return [
        ("projects", "Projects", None),
        ("projects", "ab", LC("project", "ab")),
        ("projects", "cd", LC("project", "cd")),
        ("workarea", "Work area", None),
        ("workarea", "a.s19", LC("workarea", "a.s19")),
        ("workarea", "c.a2l", LC("workarea", "c.a2l")),
        ("recent", "Recent", None),
        ("recent", "fw.s19 (s19)", LC("recent", "C:\\src\\fw.s19")),
    ]


def ROWS_EMPTY() -> list:
    return [
        ("projects", "Projects", None),
        ("projects", f"no projects {DASH} ctrl+s saves a project", None),
        ("workarea", "Work area", None),
        ("workarea", f"no work-area files {DASH} l loads a file", None),
        ("recent", "Recent", None),
        ("recent", "no recent sources", None),
    ]


def ROWS_FILEONLY() -> list:
    return [
        ("projects", "Projects", None),
        ("projects", f"no projects {DASH} ctrl+s saves a project", None),
        ("workarea", "Work area", None),
        ("workarea", "x.s19", LC("workarea", "x.s19")),
    ]


def ROWS_LONG() -> list:
    return [
        ("projects", "Projects", None),
        ("projects", "P" * 119 + "\u2026", LC("project", "P" * 130)),
        ("workarea", "Work area", None),
        ("workarea", "f" * 119 + "\u2026", LC("workarea", "f" * 130 + ".s19")),
        ("recent", "Recent", None),
        ("recent", "r" * 120 + " (s19)", LC("recent", "C:\\" + "r" * 296 + ".s19")),
    ]


class Fakes:
    """The verdict / preview fakes of the G-A fixtures: every call recorded;
    ``refuse`` (a token pair) makes the verdict refuse every load."""

    def __init__(self, refuse=None, preview=None) -> None:
        self.verdicts: list = []
        self.previews: list = []
        self.refuse = refuse
        self._preview = preview

    def verdict(self, choice):
        self.verdicts.append(choice)
        return self.refuse

    def preview(self, choice):
        self.previews.append(choice)
        if self._preview is not None:
            return self._preview(choice)
        return [(f"{choice.kind}:{choice.value}", True), ("note", False)]


def dialog_scene(tmp_path: Path, scenario, *, size: tuple = SIZE, **dialog_kwargs):
    """Run ``await scenario(app, pilot, results, fakes)`` with a
    ``LoadDialog`` pushed over a fresh app; ``results`` collects every value
    the dialog hands its dismiss callback."""
    LoadDialog = ld.load_dialog_cls()
    fakes = dialog_kwargs.pop("fakes", None) or Fakes()
    rows = dialog_kwargs.pop("rows", ROWS_A)
    kwargs = dict(mode="list", highlight=None, rows=rows, verdict=fakes.verdict, preview=fakes.preview)
    kwargs.update(dialog_kwargs)

    async def _scenario(app, pilot, log):
        results: list = []
        app.push_screen(LoadDialog(**kwargs), results.append)
        await ld.wait_for_dialog(pilot, app)
        await _settle(pilot, 4)
        return await scenario(app, pilot, results, fakes)

    return _run(tmp_path / "host", _scenario, size=size)


# ===========================================================================
# TC-B100-40 — one result, one router (LLR-173.1 … LLR-173.1g)
# ===========================================================================


def test_tc_b100_40_load_choice_is_a_frozen_value_of_four_kinds() -> None:
    """LLR-173.1 (S1-1 … S1-4): ``LoadChoice`` is the one result type — a
    frozen value of a kind and a ``str`` value. Equal by value and hashable
    (two equal choices are one set element), immutable (an assignment
    raises), and it keeps the on-disk name byte for byte (U+009B kept: the
    painting is the app's, the value must be the name a load opens).

    Why: the router dispatches on ``kind`` / ``value`` alone; a mutable or
    rewritten value would load another file than the row named.
    RED (base): ``LoadChoice`` does not exist (the base dialogs dismiss a
    ``Path`` or a ``str``)."""
    import dataclasses

    LoadChoice = ld.load_choice_cls()
    assert LoadChoice("project", "ab") == LoadChoice("project", "ab")
    assert hash(LoadChoice("project", "ab")) == hash(LoadChoice("project", "ab"))
    assert len({LoadChoice("path", "x"), LoadChoice("path", "x")}) == 1
    c = LoadChoice("recent", "C:\\src\\fw.s19")
    with pytest.raises(dataclasses.FrozenInstanceError):
        c.value = "y"  # type: ignore[misc]
    assert c.value == "C:\\src\\fw.s19"
    assert LoadChoice("workarea", "a\x9bS.s19").value == "a\x9bS.s19"
    for kind in ("project", "workarea", "recent", "path"):
        assert LoadChoice(kind, "v").kind == kind


def test_tc_b100_40_retired_load_screens_are_gone() -> None:
    """LLR-173.1, VS-PA-3, ruling Q9 (R1-1, R2-1, C2-1, P1-1): the two old
    dialogs that dismissed a ``Path`` and a ``str`` are deleted, the package
    exports ``LoadChoice`` and ``LoadDialog`` instead, and no stylesheet rule
    or screen code names ``#project_list`` / ``#project_ok`` /
    ``#project_cancel`` any more.

    Why: two result types and two callbacks are what the one router
    replaces; a kept alias would let tests pass against the old contract.
    RED (base): both classes exist and are exported."""
    import s19_app.tui as tui
    import s19_app.tui.screens as screens

    assert not hasattr(screens, "LoadFileScreen")
    assert not hasattr(screens, "LoadProjectScreen")
    assert "LoadChoice" in tui.__all__ and "LoadDialog" in tui.__all__
    assert "LoadFileScreen" not in tui.__all__ and "LoadProjectScreen" not in tui.__all__
    styles = (ROOT / "s19_app" / "tui" / "styles.tcss").read_text(encoding="utf-8")
    code = (ROOT / "s19_app" / "tui" / "screens.py").read_text(encoding="utf-8")
    for retired in ("project_list", "project_ok", "project_cancel"):
        assert retired not in styles and retired not in code, retired


def test_tc_b100_40_dialog_dismisses_a_load_choice_per_kind_or_none(tmp_path: Path) -> None:
    """LLR-173.1 (4 kinds + ``None``; S6-7): a load from each section and
    from the path field hands the callback one ``LoadChoice`` of the matching
    kind, its value the on-disk project name, the on-disk work-area file
    name, the recorded path text and the typed text; ``escape`` hands
    ``None``. Never a ``Path`` or a ``str``.

    RED (base): no ``LoadDialog``."""

    def run(position: str):
        async def scenario(app, pilot, results, fakes):
            if position == "escape":
                await pilot.press("escape")
            elif position == "path":
                await ld.type_into_path(pilot, app, "C:\\t\\a.s19")
                await pilot.press("enter")
            else:
                index = {"project": 1, "workarea": 4, "recent": 7}[position]
                await _highlight_index(pilot, app, index)
                await pilot.press("enter")
            await _settle(pilot)
            return list(results)

        return dialog_scene(tmp_path / position, scenario)

    LoadChoice = ld.load_choice_cls()
    assert run("project") == [LoadChoice("project", "ab")]
    assert run("workarea") == [LoadChoice("workarea", "a.s19")]
    assert run("recent") == [LoadChoice("recent", "C:\\src\\fw.s19")]
    assert run("path") == [LoadChoice("path", "C:\\t\\a.s19")]
    assert run("escape") == [None]


def test_tc_b100_40_project_choice_opens_the_load_result_panel(tmp_path: Path) -> None:
    """LLR-173.1a, LLR-178.3 (B07): ``LoadChoice("project", "ab")`` handed to
    the router → after the refresh ``current_project == "ab"``, 1
    Load-result panel on the stack, and the status log names ``Loaded
    project 'ab'`` (2 of 2).

    Why: a project pick must take the route that opens the Load-result
    panel, which states the problems of what was opened.
    Negative control: a router that calls ``_handle_load_project`` directly
    → 0 panels → RED. RED (base): ``LoadChoice`` does not exist."""
    base = tmp_path / "app"
    _project(base, "ab", {"a.s19": _s19()})

    async def scenario(app, pilot, log):
        mark = len(log.messages)
        app._handle_load_dialog(LC("project", "ab"))
        await ld.wait_for(pilot, lambda: len(app.screen.query("#result_ok")) > 0, "the Load-result panel")
        screens = [type(s).__name__ for s in app.screen_stack]
        return app.current_project, screens, log.since(mark)

    project, screens, messages = _run(base, scenario)
    assert project == "ab"
    assert screens.count("LoadResultScreen") == 1, screens
    assert any("Loaded project 'ab'" in m for m in messages), messages


def test_tc_b100_40_workarea_data_choice_loads_in_place_with_no_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-173.1b data arm (B09): ``LoadChoice("workarea", "x.s19")`` →
    ``current_file.path == <workarea>/temp/x.s19``, 0 calls of
    ``copy_into_workarea`` (spy) and the names in ``temp/`` unchanged.

    Why: a work-area file is already the work copy; loading it as the
    Workarea Files list does keeps one copy per file.
    Negative control: the choice routed through ``load_from_path`` → 1
    ``copy_into_workarea`` call → RED (declared: the name-set arm alone
    passes on that mutant, G-005). RED (base): ``LoadChoice`` does not
    exist."""
    base = tmp_path / "app"
    temp = _temp(base)
    (temp / "x.s19").write_bytes(_s19())
    calls: list = []
    real = app_module.copy_into_workarea

    def spy(*args, **kwargs):
        calls.append(args)
        return real(*args, **kwargs)

    monkeypatch.setattr(app_module, "copy_into_workarea", spy)
    before = _temp_files(temp)

    async def scenario(app, pilot, log):
        app._handle_load_dialog(LC("workarea", "x.s19"))
        await ld.wait_for(pilot, lambda: app.current_file is not None, "the work-area load")
        return Path(app.current_file.path)

    loaded = _run(base, scenario)
    assert loaded == temp / "x.s19", loaded
    assert calls == [], calls
    assert _temp_files(temp) == before


def test_tc_b100_40_workarea_a2l_choice_equals_the_files_list_pick(tmp_path: Path) -> None:
    """LLR-173.1b A2L arm (B10, B87; A9b-05): ``LoadChoice("workarea",
    "c.a2l")`` → the same session digest as a Workarea Files pick of
    ``c.a2l`` on a twin fixture, the status ``A2L loaded: c.a2l``, and the
    names in ``temp/`` unchanged (2 of 2 with the data arm).

    Why: the dialog's work-area row must load exactly as the Workarea Files
    list does (the A2L keeps the 9a route: cap and link re-check).
    RED (base): ``LoadChoice`` does not exist."""
    import types

    def twin(name: str, route: str):
        base = tmp_path / name
        temp = _temp(base)
        (temp / "c.a2l").write_bytes(_a2l())
        before = _temp_files(temp)

        async def scenario(app, pilot, log):
            mark = len(log.messages)
            if route == "dialog":
                app._handle_load_dialog(LC("workarea", "c.a2l"))
            else:
                app._load_from_item(types.SimpleNamespace(data="c.a2l"))
            await ld.wait_for(pilot, lambda: app.current_a2l_path is not None, "the A2L attach")
            await _settle(pilot)
            digest = _digest(app)
            return (
                tuple(None if v is None else v.replace(str(base), "<base>") for v in digest),
                log.since(mark),
            )

        digest, messages = _run(base, scenario)
        after = _temp_files(temp)
        return digest, messages, before, after

    pick = twin("pick", "list")
    dialog = twin("dialog", "dialog")
    assert dialog[0] == pick[0], (dialog[0], pick[0])
    assert any("A2L loaded: c.a2l" in m for m in dialog[1]), dialog[1]
    assert dialog[2] == dialog[3], (dialog[2], dialog[3])


def test_tc_b100_40_a2l_status_line_paints_the_name_scrubbed(tmp_path: Path) -> None:
    """LLR-173.1b A2L arm, S9b-5 (E5, M95): a work-area A2L named
    ``c<U+202E>x.a2l`` (a bidi override in the name) picked from the dialog
    → the attach status line reads ``A2L loaded: cx.a2l``, with no U+202E.

    Why: a format character in a file name reorders or hides the painted
    text; every painted name goes through ``painted_names``.
    Negative control: the status line painting ``copied.name`` raw → the
    U+202E is painted → RED (M95)."""
    name = "c‮x.a2l"
    base = tmp_path / "app"
    temp = _temp(base)
    try:
        (temp / name).write_bytes(_a2l())
    except OSError as exc:
        pytest.skip(f"not run: the volume refuses the name ({exc})")

    async def scenario(app, pilot, log):
        mark = len(log.messages)
        app._handle_load_dialog(LC("workarea", name))
        await ld.wait_for(pilot, lambda: app.current_a2l_path is not None, "the A2L attach")
        await _settle(pilot)
        return [m for m in log.since(mark) if "A2L loaded:" in m]

    lines = _run(base, scenario)
    assert len(lines) == 1 and "A2L loaded: cx.a2l" in lines[0], [ascii(m) for m in lines]
    assert "‮" not in lines[0], ascii(lines[0])


def test_tc_b100_40_path_choice_takes_the_typed_route(tmp_path: Path) -> None:
    """LLR-173.1c (B11, 3 of 3): typed ``<tmp>/a.s19`` → 1 data load;
    ``<tmp>/b.a2l`` → 1 A2L attach (``A2L loaded: b.a2l``); the absolute
    ``<workarea>/ab`` → project ``ab`` loaded and 1 Load-result panel.

    Why: a typed path must go through the one typed-path classifier, which
    opens a project folder as a project.
    Negative control: ``path`` routed to ``load_from_path`` → the
    ``<workarea>/ab`` arm loads nothing → RED. RED (base): no
    ``LoadChoice``."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.s19").write_bytes(_s19())
    (src / "b.a2l").write_bytes(_a2l())
    base = tmp_path / "app"
    _project(base, "ab", {"a.s19": _s19()})

    async def scenario(app, pilot, log):
        mark = len(log.messages)
        app._handle_load_dialog(LC("path", str(src / "a.s19")))
        await ld.wait_for(pilot, lambda: app.current_file is not None, "the data load")
        data = Path(app.current_file.path).name
        app._handle_load_dialog(LC("path", str(src / "b.a2l")))
        await ld.wait_for(pilot, lambda: app.current_a2l_path is not None, "the A2L attach")
        app._handle_load_dialog(LC("path", str(_wa(base) / "ab")))
        await ld.wait_for(pilot, lambda: len(app.screen.query("#result_ok")) > 0, "the project load panel")
        return data, app.current_project, log.since(mark)

    data, project, messages = _run(base, scenario)
    assert data == "a.s19", data
    assert any("A2L loaded: b.a2l" in m for m in messages), messages
    assert project == "ab", (project, messages)


def _load_dialog_push_sites(source: str) -> list:
    """(enclosing function, callback text) for every ``push_screen`` call
    whose first argument constructs ``LoadDialog``."""
    tree = ast.parse(source)
    sites = []
    for function in ast.walk(tree):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for call in ast.walk(function):
            if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)):
                continue
            if call.func.attr != "push_screen" or not call.args:
                continue
            first = call.args[0]
            if isinstance(first, ast.Call) and getattr(first.func, "id", getattr(first.func, "attr", None)) == "LoadDialog":
                callback = call.args[1] if len(call.args) > 1 else next(
                    (k.value for k in call.keywords if k.arg == "callback"), None
                )
                sites.append((function.name, ast.unparse(callback) if callback is not None else None))
    return sites


def test_tc_b100_40_one_router_receives_every_dialog_result() -> None:
    """LLR-173.1e (B02, an AST census of ``app.py``): every ``push_screen``
    whose first argument constructs ``LoadDialog`` passes
    ``self._handle_load_dialog`` as its callback → 2 sites
    (``action_load_file``, ``action_load_project``), 0 other callbacks.

    Why: one router is the one seam where Inc 10 inserts the load question;
    a second callback would bypass it.
    RED (base): ``action_load_project`` pushes ``LoadProjectScreen`` with
    ``_route_load_project`` → 0 ``LoadDialog`` sites. Negative control: a
    mutation giving ``action_load_project`` its own callback → RED."""
    source = (ROOT / "s19_app" / "tui" / "app.py").read_text(encoding="utf-8")
    sites = _load_dialog_push_sites(source)
    assert sorted(sites) == [
        ("action_load_file", "self._handle_load_dialog"),
        ("action_load_project", "self._handle_load_dialog"),
    ], sites


@STORE_WRITE
def test_tc_b100_40_recent_choice_loads_the_recorded_text_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-173.1f (B13, 4 of 4): a recent ``<src>\\fw.s19`` → 1 data load
    whose work copy holds the source bytes, and that path is then the
    store's first entry; a recent ``<src>\\cal.a2l`` → 1 A2L attach; a
    recent ``<gone>\\fw.s19`` that is missing while ``<base>\\fw.s19``
    exists → 0 loads (a recorded path is drive-rooted, so the base-folder
    fallback never runs).

    Why: a recent row must reopen exactly the recorded file, never a file
    of the same name elsewhere.
    Negative control: the recent loaded by its file name relative to the
    base → the ``gone`` arm loads ``<base>\\fw.s19`` → RED; a recent load
    that skips ``record_recent_source`` leaves ``fw`` (seeded last) last →
    RED (CR9b-02). RED (base): no ``LoadChoice``."""
    lad = _lad(tmp_path, monkeypatch)
    src = tmp_path / "src"
    src.mkdir()
    (src / "fw.s19").write_bytes(_s19())
    (src / "cal.a2l").write_bytes(_a2l())
    base = tmp_path / "app"
    base.mkdir()
    (base / "fw.s19").write_bytes(_s19_other())
    gone = str(tmp_path / "gone" / "fw.s19")
    # CR9b-02: ``fw`` is seeded LAST, so only a fresh record of the ``fw``
    # load can make it the first entry (read before the ``cal`` load).
    store = _seed_store(lad, [gone, str(src / "cal.a2l"), str(src / "fw.s19")])

    def store_paths() -> list:
        doc = json.loads(store.read_text(encoding="utf-8"))
        return [e["path"] for e in doc["sources"]]

    async def scenario(app, pilot, log):
        mark = len(log.messages)
        app._handle_load_dialog(LC("recent", gone))
        await _settle(pilot, 20)
        after_gone = app.current_file
        app._handle_load_dialog(LC("recent", str(src / "fw.s19")))
        await ld.wait_for(pilot, lambda: app.current_file is not None, "the recent data load")
        await _settle(pilot)
        after_fw = store_paths()
        copy = Path(app.current_file.path)
        app._handle_load_dialog(LC("recent", str(src / "cal.a2l")))
        await ld.wait_for(pilot, lambda: app.current_a2l_path is not None, "the recent A2L attach")
        await _settle(pilot)
        return after_gone, copy.read_bytes(), log.since(mark), after_fw

    after_gone, copied, messages, after_fw = _run(base, scenario)
    assert after_gone is None, "the missing recent loaded a file (the base-folder fallback ran)"
    assert copied == _s19()
    assert any("A2L loaded: cal.a2l" in m for m in messages), messages
    assert after_fw[0] == str(src / "fw.s19"), after_fw


def test_tc_b100_40_unreadable_picked_project_paints_one_status_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-173.1g (B96, F-12): a project listed fail-open (it holds
    ``firmware.s19`` and no ``project.json``) whose file listing raises
    ``PermissionError`` (injected into the one link-safe lister,
    ``_list_project_files``, R2-N2), picked with ``p`` + ``enter`` → 1
    status line holding ``could not be read``, 0 raises (the app keeps
    running), the session digest unchanged.

    Why: an unreadable folder must be explained, never crash the app from
    the dialog's dismiss callback.
    Negative control: no catch around the listing → the ``OSError`` leaves
    the callback and the app stops → RED. RED (base): the lister does not
    exist (``AttributeError``), and the base dialog is not the Load
    dialog."""
    base = tmp_path / "app"
    _project(base, "cd", {"firmware.s19": _s19()})

    def boom(self, folder, *args, **kwargs):
        raise PermissionError(13, "injected: access denied", str(folder))

    monkeypatch.setattr(app_module.S19TuiApp, "_list_project_files", boom)

    async def scenario(app, pilot, log):
        await _home(pilot)
        before = _digest(app)
        mark = len(log.messages)
        await _open(pilot, app, "p")
        await ld.highlight_row(pilot, app, "cd")
        await pilot.press("enter")
        await ld.wait_for_dialog_closed(pilot, app)
        await ld.wait_for(
            pilot, lambda: _status_lines(log, mark, "could not be read"), "the could-not-be-read line"
        )
        await _settle(pilot)
        return before, _digest(app), _status_lines(log, mark, "could not be read")

    before, after, lines = _run(base, scenario)
    assert len(lines) == 1, lines
    assert after == before


# ===========================================================================
# TC-B100-41 — opening, focus, keys, clicks (LLR-173.2 … LLR-173.2l)
# ===========================================================================


def test_tc_b100_41_l_and_ctrl_l_open_the_dialog_on_the_path_field(tmp_path: Path) -> None:
    """LLR-173.2 (B01, 3 of 3): ``l`` → the Load dialog on top (stack depth
    2), the focus on ``#load_path``; ``escape``, then ``ctrl+l`` → the same;
    ``#load_list`` exists in that dialog.

    Why: Load opens on the typed-path field, and the one dialog also holds
    the list (P-20).
    RED (base): ``LoadFileScreen`` is not the Load dialog and has no
    ``#load_list``. Negative control: every Load opened on ``#load_list`` →
    the ``l`` arm RED."""
    base = tmp_path / "app"

    async def scenario(app, pilot, log):
        out = []
        for key in ("l", "ctrl+l"):
            await _open(pilot, app, key)
            out.append((len(app.screen_stack), focused_id(app), len(app.screen.query("#load_list"))))
            await pilot.press("escape")
            await ld.wait_for_dialog_closed(pilot, app)
        return out

    assert _run(base, scenario) == [(2, "load_path", 1), (2, "load_path", 1)]


def test_tc_b100_41_p_and_the_button_open_the_dialog_on_the_list(tmp_path: Path) -> None:
    """LLR-173.2a (B04, 3 of 3): projects ``ab`` and ``cd``: ``p`` → the
    focus on ``#load_list``; a click on ``#ws_load_project_button`` → the
    same; a work area with 0 projects, ``p`` → the dialog opens, its
    projects section holds the disabled line ``no projects`` / ``ctrl+s
    saves a project``, and 0 status lines ``No saved projects found.``.

    Why: Load project is the same dialog on the list, and an empty work area
    still opens it (with the next step) instead of a status line.
    RED (base): ``LoadProjectScreen``; with 0 projects the base paints ``No
    saved projects found.`` and opens nothing."""
    base = tmp_path / "app"
    _project(base, "ab", {"a.s19": _s19()})
    _project(base, "cd", {"a.s19": _s19()})

    src = tmp_path / "src"
    src.mkdir()
    (src / "fw.s19").write_bytes(_s19())

    async def scenario(app, pilot, log):
        # The Workspace shows the button once a file is loaded (AT-B99-13).
        await projects.load_image(pilot, app, src / "fw.s19")
        await _home(pilot)
        await _open(pilot, app, "p")
        key_focus = focused_id(app)
        await pilot.press("escape")
        await ld.wait_for_dialog_closed(pilot, app)
        await _home(pilot)
        assert await pilot.click("#ws_load_project_button"), "click missed #ws_load_project_button"
        await ld.wait_for_dialog(pilot, app)
        await _settle(pilot, 4)
        return key_focus, focused_id(app)

    assert _run(base, scenario) == ("load_list", "load_list")

    empty = tmp_path / "empty"

    async def empty_scenario(app, pilot, log):
        await _home(pilot)
        mark = len(log.messages)
        await _open(pilot, app, "p")
        lines = ld.section_prompts(app.screen, "Projects", loadable_only=False)
        loadable = ld.section_prompts(app.screen, "Projects")
        return lines, loadable, _status_lines(log, mark, "No saved projects found.")

    lines, loadable, old = _run(empty, empty_scenario)
    assert loadable == [], loadable
    assert len(lines) == 1 and "no projects" in lines[0] and "ctrl+s saves a project" in lines[0], lines
    assert old == []


def test_tc_b100_41_list_opens_on_the_open_project(tmp_path: Path) -> None:
    """LLR-173.2b (B05, 3 of 3): projects ``A``, ``P``, ``Z`` with ``P`` open,
    then ``p`` → ``P``'s row highlighted; no project open → ``A``; 0
    projects and ``temp/x.s19`` → the ``x.s19`` row.

    Why: the engineer reopens or switches from where they are; the list
    must start on the open project, never on a heading.
    Negative control: a dialog that always highlights row 0 → the ``P`` arm
    highlights the ``Projects`` heading → RED. RED (base): no Load
    dialog list."""
    base = tmp_path / "app"
    for name in ("A", "P", "Z"):
        _project(base, name, {"a.s19": _s19()})

    async def open_scene(app, pilot, log):
        await projects.load_project(pilot, app, "P")
        for _ in range(60):
            if len(app.screen.query("#result_ok")) > 0:
                await projects.dismiss_load_result_panel(pilot, app)
                break
            await pilot.pause()
        await _home(pilot)
        await _open(pilot, app, "p")
        return ld.highlighted_prompt(app.screen)

    async def closed_scene(app, pilot, log):
        await _home(pilot)
        await _open(pilot, app, "p")
        return ld.highlighted_prompt(app.screen)

    assert _run(base, open_scene) == "P"
    base2 = tmp_path / "noopen"
    for name in ("A", "P", "Z"):
        _project(base2, name, {"a.s19": _s19()})
    assert _run(base2, closed_scene) == "A"
    base3 = tmp_path / "fileonly"
    (_temp(base3) / "x.s19").write_bytes(_s19())
    assert _run(base3, closed_scene) == "x.s19"


def test_tc_b100_41_open_project_highlight_falls_back_to_the_first_project(tmp_path: Path) -> None:
    """LLR-173.2b (S3-1 … S3-4, H-1): ``highlight="cd"`` → row ``cd``
    highlighted with the focus on ``#load_list``; ``highlight=None`` →
    ``ab``; ``highlight="gone"`` (not listed) → ``ab``; 0 projects → the
    first loadable row (``x.s19``), the disabled ``no projects`` line
    skipped.

    RED (base): no ``LoadDialog``. Negative control: ``highlighted = 0`` →
    the ``Projects`` heading → RED."""

    def run(highlight, rows):
        async def scenario(app, pilot, results, fakes):
            return focused_id(app), ld.highlighted_prompt(app.screen)

        return dialog_scene(tmp_path / f"h{highlight}{rows.__name__}", scenario, highlight=highlight, rows=rows)

    assert run("cd", ROWS_A) == ("load_list", "cd")
    assert run(None, ROWS_A) == ("load_list", "ab")
    assert run("gone", ROWS_A) == ("load_list", "ab")
    assert run(None, ROWS_FILEONLY) == ("load_list", "x.s19")


def test_tc_b100_41_tab_order_wraps_both_ways(tmp_path: Path) -> None:
    """LLR-173.2c (S2-4, 5 + 5): from ``#load_path``, 5 ``tab`` →
    ``load_list``, ``load_preview``, ``load_ok``, ``load_cancel``,
    ``load_path``; 5 ``shift+tab`` → the reverse.

    Why: the preview must be reachable by keys (it scrolls), and the order
    must be predictable.
    Negative control: an unfocusable preview → the 2nd ``tab`` lands on
    ``load_ok`` → RED. RED (base): no ``LoadDialog``."""

    async def scenario(app, pilot, results, fakes):
        assert focused_id(app) == "load_path"
        forward, backward = [], []
        for _ in range(5):
            await pilot.press("tab")
            await pilot.pause()
            forward.append(focused_id(app))
        for _ in range(5):
            await pilot.press("shift+tab")
            await pilot.pause()
            backward.append(focused_id(app))
        return forward, backward

    forward, backward = dialog_scene(tmp_path, scenario, mode="path")
    assert forward == ["load_list", "load_preview", "load_ok", "load_cancel", "load_path"]
    assert backward == ["load_cancel", "load_ok", "load_preview", "load_list", "load_path"]


@pytest.mark.parametrize("key,char", [("p", "p"), ("l", "l"), ("q", "q"), ("s", "s"), ("r", "r"), ("question_mark", "?")])
def test_tc_b100_41_printable_key_in_the_list_types_into_the_path_field(
    tmp_path: Path, key: str, char: str
) -> None:
    """LLR-173.2d (S4-1, 6 of 6): with the list focused and the field empty,
    each of ``p``, ``l``, ``q``, ``s``, ``r``, ``?`` → ``#load_path`` holds
    that one character and has the focus, the stack depth stays 2, and 0
    app actions run (``run_action`` spy).

    Why: typing in the list starts a path; a letter must never fire an app
    key (``q`` would quit) behind the modal.
    Negative control: no redirect → ``p`` leaves the field empty → RED
    (declared: the "0 app actions" arm also holds on that mutant, a modal
    stops non-priority app keys). RED (base): no ``LoadDialog``."""

    async def scenario(app, pilot, results, fakes):
        actions: list = []
        real = app.run_action

        async def spy(action, *args, **kwargs):
            actions.append(action)
            return await real(action, *args, **kwargs)

        app.run_action = spy
        await pilot.press(key)
        await _settle(pilot, 4)
        return path_value(app.screen), focused_id(app), len(app.screen_stack), actions

    value, focus, depth, actions = dialog_scene(tmp_path, scenario)
    assert (value, focus, depth) == (char, "load_path", 2)
    assert actions == [], actions


def test_tc_b100_41_navigation_keys_in_the_list_are_not_redirected(tmp_path: Path) -> None:
    """LLR-173.2d (S4-2, S4-3; 4 of 4): list focused: ``down``, ``up`` keep
    the focus on the list with the field empty; ``tab`` → ``load_preview``;
    ``enter`` loads the highlighted row (the load path, not the field). A
    printable key with ``C:\\t`` already typed appends: ``x`` →
    ``C:\\tx`` with the cursor at 5.

    RED (base): no ``LoadDialog``."""

    async def scenario(app, pilot, results, fakes):
        out = []
        for key in ("down", "up", "tab"):
            await pilot.press(key)
            await pilot.pause()
            out.append((path_value(app.screen), focused_id(app)))
        await pilot.press("shift+tab")
        await pilot.pause()
        await pilot.press("enter")
        await _settle(pilot)
        return out, list(results)

    out, results = dialog_scene(tmp_path / "nav", scenario)
    assert out == [("", "load_list"), ("", "load_list"), ("", "load_preview")], out
    assert results == [LC("project", "ab")], results

    async def append(app, pilot, results, fakes):
        from textual.widgets import Input

        await ld.type_into_path(pilot, app, "C:\\t")
        await pilot.press("tab")
        await pilot.pause()
        await pilot.press("x")
        await _settle(pilot)
        field = app.screen.query_one("#load_path", Input)
        return field.value, field.cursor_position, focused_id(app)

    assert dialog_scene(tmp_path / "append", append) == ("C:\\tx", 5, "load_path")


def _density(app) -> tuple:
    body = app.screen_stack[0].query_one("#workspace_body")
    return tuple(sorted(c for c in body.classes if c.startswith("density")))


def test_tc_b100_41_priority_keys_are_inert_while_the_dialog_is_open(tmp_path: Path) -> None:
    """LLR-173.2e (B90, S9b-1; 6 of 6): with the dialog open, ``ctrl+l`` →
    stack depth 2, 0 second dialogs; ``ctrl+s`` → depth 2, 0 Save dialogs;
    ``ctrl+k`` → the focus stays inside the dialog AND the main screen under
    it is untouched (its focused widget unchanged, its command-bar palette
    still closed — CR9b-01: ``action_focus_palette`` opens the palette on
    the main screen, under the modal, so the dialog's own focus cannot show
    it); ``ctrl+d`` → the density
    unchanged; ``ctrl+p`` over the dialog (the command palette opens over
    it), then ``ctrl+s`` → 0 Save pushes, then ``ctrl+l`` → 0 second
    dialogs (the guard reads the whole screen stack). Also B91 (no
    over-reach): with the dialog closed, ``ctrl+d`` still cycles the
    density.

    Why: the app's priority keys reach through a modal (Textual 8.2.8);
    a Save or a second Load stacked under the dialog would act on a session
    the engineer is about to replace.
    Negative control (executed S9b-1 probe): a guard that reads only the top
    screen stacks ``Save`` after ``ctrl+p``, ``ctrl+s`` → RED; a guard
    without ``focus_palette`` opens the main screen's palette on ``ctrl+k``
    → RED (CR9b-01 mutant, executed). RED (base): the base dialog is not the
    Load dialog (and ``ctrl+l`` stacks a second one)."""
    base = tmp_path / "app"

    async def scenario(app, pilot, log):
        await _home(pilot)
        density0 = _density(app)
        await pilot.press("ctrl+d")
        await _settle(pilot)
        cycled = _density(app) != density0
        await _open(pilot, app, "l")
        out = {}
        await pilot.press("ctrl+l")
        await _settle(pilot)
        out["ctrl+l"] = [type(s).__name__ for s in app.screen_stack]
        await pilot.press("ctrl+s")
        await _settle(pilot)
        out["ctrl+s"] = [type(s).__name__ for s in app.screen_stack]
        from s19_app.tui.command_bar import CommandBar

        main = app.screen_stack[0]
        main_focus0 = main.focused
        await pilot.press("ctrl+k")
        await _settle(pilot)
        focused = app.focused
        out["ctrl+k"] = focused is not None and ld.is_load_dialog(focused.screen)
        out["ctrl+k main focus kept"] = main.focused is main_focus0
        out["ctrl+k palette open"] = main.query_one(CommandBar).palette_is_open
        density1 = _density(app)
        await pilot.press("ctrl+d")
        await _settle(pilot)
        out["ctrl+d"] = _density(app) == density1
        await pilot.press("ctrl+p")
        await _settle(pilot, 10)
        out["palette"] = [type(s).__name__ for s in app.screen_stack]
        await pilot.press("ctrl+s")
        await _settle(pilot, 10)
        await pilot.press("ctrl+l")
        await _settle(pilot, 10)
        out["after palette"] = [type(s).__name__ for s in app.screen_stack]
        return cycled, out

    cycled, out = _run(base, scenario)
    assert cycled, "ctrl+d must still cycle the density with the dialog closed (B91)"
    dialog = ld.load_dialog_cls().__name__
    assert len(out["ctrl+l"]) == 2 and out["ctrl+l"][-1] == dialog, out
    assert len(out["ctrl+s"]) == 2 and "SaveProjectScreen" not in out["ctrl+s"], out
    assert out["ctrl+k"] is True, out
    assert out["ctrl+k main focus kept"] is True, out
    assert out["ctrl+k palette open"] is False, out
    assert out["ctrl+d"] is True, out
    assert out["palette"][-1] == "CommandPalette", out
    assert "SaveProjectScreen" not in out["after palette"], out
    assert out["after palette"].count(dialog) == 1, out


def _post(app, key: str, character=None) -> None:
    """Post one key event the way the terminal driver does (to the app)."""
    app.post_message(events.Key(key, character))


@pytest.mark.parametrize("trigger", ["enter", "alt+l", "load_ok"])
@pytest.mark.parametrize("index,expected", [(2, ("project", "cd")), (5, ("workarea", "c.a2l")), (7, ("recent", "C:\\src\\fw.s19"))])
def test_tc_b100_41_load_with_the_list_last_takes_the_highlighted_row(
    tmp_path: Path, trigger: str, index: int, expected: tuple
) -> None:
    """LLR-173.2f, HLR-173c (S5-6, 9 of 9): list mode, the 3 triggers ×
    ``cd`` / ``c.a2l`` / ``fw.s19 (s19)`` highlighted → one dismiss with the
    row's ``LoadChoice``, after one verdict call with that choice.

    Negative control: a dialog that always takes the field → the field is
    empty → ``nothing selected`` and 0 dismisses → RED. RED (base): no
    ``LoadDialog``."""

    async def scenario(app, pilot, results, fakes):
        await _highlight_index(pilot, app, index)
        if trigger == "enter":
            await pilot.press("enter")
        elif trigger == "alt+l":
            _post(app, "alt+l", "l")
        else:
            assert await pilot.click("#load_ok"), "click missed #load_ok"
        await _settle(pilot)
        return list(results), list(fakes.verdicts)

    results, verdicts = dialog_scene(tmp_path, scenario)
    assert results == [LC(*expected)], results
    assert verdicts == [LC(*expected)], verdicts


def test_tc_b100_41_text_in_the_field_then_tab_into_the_list_loads_the_row(tmp_path: Path) -> None:
    """LLR-173.2f boundary (S5-5): path mode, ``C:\\x.s19`` typed, ``tab``
    (into the list, ``ab`` highlighted), ``enter`` → ``LoadChoice("project",
    "ab")``: the list held the focus more recently than the field.

    RED (base): no ``LoadDialog``."""

    async def scenario(app, pilot, results, fakes):
        await ld.type_into_path(pilot, app, "C:\\x.s19")
        await pilot.press("tab")
        await pilot.pause()
        await pilot.press("enter")
        await _settle(pilot)
        return list(results)

    assert dialog_scene(tmp_path, scenario, mode="path") == [LC("project", "ab")]


@pytest.mark.parametrize("mode", ["path", "list"])
@pytest.mark.parametrize("trigger", ["enter", "alt+l", "load_ok"])
def test_tc_b100_41_load_with_the_path_last_takes_the_typed_text(
    tmp_path: Path, trigger: str, mode: str
) -> None:
    """LLR-173.2g, HLR-173c (S5-1 … S5-3, 3 of 3): row ``ab`` highlighted,
    ``C:\\t\\a.s19`` typed → each trigger dismisses ``LoadChoice("path",
    "C:\\t\\a.s19")``, never the row. Run in path mode, and in list mode
    (E5, M35), where the click into the field moves the source from the
    list to the field.

    Negative control: a dialog that always takes the highlighted row →
    ``LoadChoice("project", "ab")`` → RED; a source tracker that ignores
    focus on ``#load_path`` → the list-mode arms take the row → RED (M35).
    RED (base): no ``LoadDialog``."""

    async def scenario(app, pilot, results, fakes):
        await ld.type_into_path(pilot, app, "C:\\t\\a.s19")
        if trigger == "enter":
            await pilot.press("enter")
        elif trigger == "alt+l":
            _post(app, "alt+l", "l")
        else:
            assert await pilot.click("#load_ok"), "click missed #load_ok"
        await _settle(pilot)
        return list(results), len(app.screen_stack)

    results, depth = dialog_scene(tmp_path, scenario, mode=mode)
    assert results == [LC("path", "C:\\t\\a.s19")], results
    assert depth == 1


def test_tc_b100_41_enter_on_the_preview_loads_the_highlighted_row(tmp_path: Path) -> None:
    """LLR-173.2d (S4-2; E5, M17): list mode, ``tab`` to ``#load_preview``,
    ``enter`` → ``LoadChoice("project", "ab")``: Enter on the preview loads
    the row it previews.

    Negative control: the enter arm limited to ``#load_list`` → Enter on the
    preview does nothing, 0 dismisses → RED (M17)."""

    async def scenario(app, pilot, results, fakes):
        await pilot.press("tab")
        await pilot.pause()
        where = focused_id(app)
        await pilot.press("enter")
        await _settle(pilot)
        return where, list(results)

    where, results = dialog_scene(tmp_path, scenario)
    assert where == "load_preview", where
    assert results == [LC("project", "ab")], results


def test_tc_b100_41_headings_cannot_be_reached_by_keys(tmp_path: Path) -> None:
    """LLR-173.2c (E5, M09): list mode on ``ab`` (the first loadable row,
    under the ``Projects`` heading) → ``up``, then ``home`` → the highlighted
    row is a loadable row each time, never a heading.

    Why: a heading holds no choice; landing on it turns Enter into
    ``nothing selected`` for a row the engineer can see.
    Negative control: the rows with no choice left enabled → ``up`` lands on
    the ``Projects`` heading → RED (M09)."""
    from textual.widgets import OptionList

    async def scenario(app, pilot, results, fakes):
        lst = app.screen.query_one("#load_list", OptionList)
        out = [lst.highlighted]
        for key in ("up", "home"):
            await pilot.press(key)
            await pilot.pause()
            out.append(lst.highlighted)
        return out

    rows = ROWS_A()
    out = dialog_scene(tmp_path, scenario)
    assert out[0] == 1, out
    for index in out:
        assert index is not None and rows[index][2] is not None, (out, [r[1] for r in rows])


def test_tc_b100_41_typed_text_reaches_the_verdict_verbatim(tmp_path: Path) -> None:
    """LLR-173.2g (S-a; E5, M32): ``  C:\\t\\a.s19 `` (leading and trailing
    spaces) in ``#load_path``, ``enter`` → the verdict and the dismiss both
    receive ``LoadChoice("path", "  C:\\t\\a.s19 ")``, byte for byte.

    Why: the app's classifier owns the trimming; a dialog that trims first
    would route a different text than the one the router logs and the
    status line quotes.
    Negative control: the dialog strips the text → ``C:\\t\\a.s19`` → RED
    (M32)."""
    from textual.widgets import Input

    text = "  C:\\t\\a.s19 "

    async def scenario(app, pilot, results, fakes):
        inp = app.screen.query_one("#load_path", Input)
        inp.focus()
        await pilot.pause()
        inp.value = text
        await pilot.pause()
        await pilot.press("enter")
        await _settle(pilot)
        return list(fakes.verdicts), list(results)

    verdicts, results = dialog_scene(tmp_path, scenario, mode="path")
    assert verdicts == [LC("path", text)], verdicts
    assert results == [LC("path", text)], results


def test_tc_b100_41_path_mode_opens_with_an_empty_preview(tmp_path: Path) -> None:
    """LLR-173.6 / S-f (E5, M38): path mode with row ``ab`` highlighted on
    open → the preview is empty and ``preview`` was called 0 times: the
    path field is the source, so the highlighted row is not the load target.

    Negative control: the highlight handler that ignores the source → the
    open-time highlight paints ``ab``'s preview → RED (M38)."""

    async def scenario(app, pilot, results, fakes):
        await _settle(pilot)
        return preview_lines(app.screen), list(fakes.previews), focused_id(app)

    lines, previews, focus = dialog_scene(tmp_path, scenario, mode="path")
    assert focus == "load_path", focus
    assert [line for line in lines if line.strip()] == [], lines
    assert previews == [], previews


def test_tc_b100_41_moving_to_the_path_field_clears_the_list_preview(tmp_path: Path) -> None:
    """LLR-173.6 / S-f (E5, M39): list mode → ``ab``'s preview is painted;
    a click into ``#load_path`` → the preview is empty (no ``●`` of the row
    stays beside a typed path).

    Negative control: ``_schedule_preview`` without its clear → the row's
    preview stays → RED (M39)."""

    async def scenario(app, pilot, results, fakes):
        await _settle(pilot)
        before = preview_lines(app.screen)
        assert await pilot.click("#load_path"), "click missed #load_path"
        await _settle(pilot)
        return before, preview_lines(app.screen), focused_id(app)

    before, after, focus = dialog_scene(tmp_path, scenario)
    assert any("project:ab" in line for line in before), before
    assert focus == "load_path", focus
    assert [line for line in after if line.strip()] == [], after


def test_tc_b100_41_alt_l_with_the_focus_on_the_path_field_loads_and_types_nothing(tmp_path: Path) -> None:
    """A9b-01 (S2-9), LLR-173.2g: the terminal's shape of ``alt+l`` — a
    posted ``events.Key("alt+l", character="l")`` — with the focus on
    ``#load_path`` holding ``C:\\t\\a.s19`` → the load runs (one dismiss with
    that path) and 0 characters are typed into the field.

    Why: a terminal reports ``alt+l`` with the printable character ``l``; a
    non-priority binding loses that key to the focused ``Input``, which
    types ``l`` instead of loading.
    Negative control: ``alt+l`` bound without ``priority=True`` → the field
    becomes ``C:\\t\\a.s19l`` and 0 dismisses → RED. RED (base): no
    ``LoadDialog``."""

    async def scenario(app, pilot, results, fakes):
        await ld.type_into_path(pilot, app, "C:\\t\\a.s19")
        assert focused_id(app) == "load_path"
        _post(app, "alt+l", "l")
        await _settle(pilot)
        field = path_value(app.screen) if ld.is_load_dialog(app.screen) else None
        return list(results), field

    results, field = dialog_scene(tmp_path, scenario, mode="path")
    # A typed "l" would show as "C:\t\a.s19l" in the field (dialog still
    # open) or in the dismissed value; both are excluded here.
    assert results == [LC("path", "C:\\t\\a.s19")], (results, field)


@pytest.mark.parametrize("text", ["", "   "])
def test_tc_b100_41_empty_or_spaces_text_is_explained(tmp_path: Path, text: str) -> None:
    """LLR-173.2h, HLR-173d (S5-8, 2 of 2): path mode, field ``""`` or
    ``"   "``, ``enter`` → ``#load_reason`` paints ``nothing selected`` and
    ``pick a row or type a path``, 0 dismisses, the field text unchanged,
    0 verdict calls.

    Why: an empty Load said nothing at all (P-19).
    Negative control: a silent return on empty text → ``#load_reason``
    empty → RED. RED (base): no ``LoadDialog``."""

    async def scenario(app, pilot, results, fakes):
        if text:
            await ld.type_into_path(pilot, app, text)
        await pilot.press("enter")
        await _settle(pilot)
        return reason_text(app.screen), path_value(app.screen), list(results), len(fakes.verdicts)

    reason, field, results, verdicts = dialog_scene(tmp_path, scenario, mode="path")
    assert NOTHING[0] in reason and NOTHING[1] in reason, reason
    assert field == text and results == [] and verdicts == 0


def test_tc_b100_41_no_loadable_row_highlighted_is_explained(tmp_path: Path) -> None:
    """LLR-173.2i, LLR-173.4d (S5-10, S5-11; 2 of 2 + the app arm): list mode
    with every section empty, ``enter`` → the ``nothing selected`` pair, 0
    dismisses, 0 verdict calls; a heading highlighted by code (``ROWS_A``
    index 0) → the same; an app with an empty work area, an empty temp
    folder and no store: ``p``, ``enter`` → the pair, the dialog open.

    Why: a heading or a token line is not a load target.
    Negative control: a dismiss with the heading's text → 1 dismiss → RED.
    RED (base): no Load dialog."""
    from textual.widgets import OptionList

    async def empty(app, pilot, results, fakes):
        await pilot.press("enter")
        await _settle(pilot)
        return reason_text(app.screen), list(results), len(fakes.verdicts)

    reason, results, verdicts = dialog_scene(tmp_path / "empty", empty, rows=ROWS_EMPTY)
    assert NOTHING[0] in reason and NOTHING[1] in reason and results == [] and verdicts == 0

    async def heading(app, pilot, results, fakes):
        app.screen.query_one("#load_list", OptionList).highlighted = 0
        await pilot.pause()
        await pilot.press("enter")
        await _settle(pilot)
        return reason_text(app.screen), list(results)

    reason, results = dialog_scene(tmp_path / "heading", heading)
    assert NOTHING[0] in reason and results == [], (reason, results)

    async def app_scene(app, pilot, log):
        await _home(pilot)
        await _open(pilot, app, "p")
        await pilot.press("enter")
        await _settle(pilot)
        return reason_text(app.screen), ld.is_load_dialog(app.screen)

    reason, still_open = _run(tmp_path / "app", app_scene)
    assert NOTHING[0] in reason and NOTHING[1] in reason and still_open, reason


def test_tc_b100_41_click_highlights_and_never_loads(tmp_path: Path) -> None:
    """LLR-173.2j (S7-4, S7-5; 2 of 2): one click on row 2 (``cd``) →
    ``cd`` highlighted, the dialog open; a double click on it → still open,
    0 verdict calls; a click on the disabled ``Work area`` heading → the
    highlight unchanged, 0 dismisses.

    Why: Textual posts the same ``Selected`` for a click as for ``enter``; a
    dialog loading on it would load on a mere click (VS-PA-2).
    Negative control: loading on ``OptionList.OptionSelected`` → the first
    click dismisses → RED. RED (base): no ``LoadDialog``."""

    async def scenario(app, pilot, results, fakes):
        assert await ld.click_row(pilot, app, "cd"), "click missed the cd row"
        await _settle(pilot)
        single = (ld.highlighted_prompt(app.screen), len(app.screen_stack), list(results))
        assert await ld.click_row(pilot, app, "cd", times=2), "double click missed the cd row"
        await _settle(pilot)
        double = (ld.highlighted_prompt(app.screen), len(app.screen_stack), list(results), len(fakes.verdicts))
        assert await ld.click_row(pilot, app, "Work area"), "click missed the heading"
        await _settle(pilot)
        heading = (ld.highlighted_prompt(app.screen), list(results))
        return single, double, heading

    single, double, heading = dialog_scene(tmp_path, scenario)
    assert single == ("cd", 2, [])
    assert double == ("cd", 2, [], 0)
    assert heading == ("cd", [])


def test_tc_b100_41_escape_closes_with_no_result_from_every_focus(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-173.2k, HLR-173e (B14, S6-1; 4 of 4): ``escape`` with the focus on
    ``#load_path``, ``#load_list``, ``#load_preview`` and ``#load_ok`` → the
    dialog closes (stack depth 1), the session digest unchanged and the
    store bytes unchanged.

    Why: ``escape`` is the way out; it must change nothing (P-18: the base
    dialog ignored it).
    RED (base): ``escape`` on ``LoadFileScreen`` leaves it open (P-18)."""
    lad = _lad(tmp_path, monkeypatch)
    src = tmp_path / "src"
    src.mkdir()
    (src / "fw.s19").write_bytes(_s19())
    store = _seed_store(lad, [str(src / "fw.s19")])
    store_sha = _sha(store)
    base = tmp_path / "app"
    _project(base, "ab", {"a.s19": _s19()})

    async def scenario(app, pilot, log):
        await projects.load_image(pilot, app, src / "fw.s19")
        await _home(pilot)
        out = []
        for tabs, expected in ((0, "load_path"), (1, "load_list"), (2, "load_preview"), (3, "load_ok")):
            before = _digest(app)
            await _open(pilot, app, "l")
            for _ in range(tabs):
                await pilot.press("tab")
                await pilot.pause()
            where = focused_id(app)
            await pilot.press("escape")
            await _settle(pilot, 8)
            out.append((expected, where, len(app.screen_stack), _digest(app) == before))
        return out

    out = _run(base, scenario)
    for expected, where, depth, same in out:
        assert where == expected and depth == 1 and same, out
    assert _sha(store) == store_sha


def test_tc_b100_41_cancel_closes_with_no_result(tmp_path: Path) -> None:
    """LLR-173.2l (S6-2, 2 of 2): ``enter`` on the focused ``#load_cancel``
    and a click on it → each dismisses ``None``.

    Negative control: ``#load_cancel`` mapped to the load action → the
    empty-Load pair and 0 dismisses → RED. RED (base): no ``LoadDialog``."""

    async def by_key(app, pilot, results, fakes):
        for _ in range(4):
            await pilot.press("tab")
            await pilot.pause()
        assert focused_id(app) == "load_cancel"
        await pilot.press("enter")
        await _settle(pilot)
        return list(results)

    async def by_click(app, pilot, results, fakes):
        assert await pilot.click("#load_cancel"), "click missed #load_cancel"
        await _settle(pilot)
        return list(results)

    assert dialog_scene(tmp_path / "key", by_key, mode="path") == [None]
    assert dialog_scene(tmp_path / "click", by_click, mode="path") == [None]


@pytest.mark.parametrize("second", ["enter", "escape"])
def test_tc_b100_41_double_enter_dismisses_once(tmp_path: Path, second: str) -> None:
    """A9b-02 (S6-8; the ``escape`` arm added at E5, M34): ``enter`` and a
    second ``enter`` (or an ``escape``) queued back to back on the list →
    exactly 1 dismiss (``LoadChoice("project", "ab")``), 0 exceptions (the
    app keeps running), the stack back to the main screen.

    Why: a second queued load or cancel must never dismiss a dismissed
    dialog (a second ``dismiss`` pops the main screen or raises).
    Negative control: ``_close`` without the early ``_dismissed`` return →
    the queued ``escape`` dismisses again (``action_cancel`` has no guard of
    its own) → a ``ScreenStackError`` or the main screen popped → RED (M34);
    ``action_load`` without its early return → the second ``enter`` runs the
    verdict again on the dismissed dialog (2 verdict calls) → RED (M26).
    RED (base): no ``LoadDialog``."""

    async def scenario(app, pilot, results, fakes):
        _post(app, "enter")
        _post(app, second)
        await _settle(pilot, 10)
        return list(results), len(app.screen_stack), app.is_running, list(fakes.verdicts)

    results, depth, running, verdicts = dialog_scene(tmp_path, scenario)
    assert results == [LC("project", "ab")], results
    assert depth == 1 and running, (depth, running)
    # E5, M26: the queued second request returns before it asks the verdict.
    assert verdicts == [LC("project", "ab")], verdicts


def test_tc_b100_41_type_ahead_c_then_enter_loads_the_typed_text(tmp_path: Path) -> None:
    """A9b-06a (S4-8): list focused, field empty, ``C`` and ``enter`` queued
    back to back → the dismiss is ``LoadChoice("path", "C")``, not the
    highlighted row.

    Why: the redirect of a printable key is itself the decision to type a
    path; a source switched only when the focus message lands loads the row
    the engineer typed over.
    Negative control: ``_source`` set only in ``on_descendant_focus`` →
    ``LoadChoice("project", "ab")`` → RED. RED (base): no ``LoadDialog``."""

    async def scenario(app, pilot, results, fakes):
        _post(app, "C", "C")
        _post(app, "enter")
        await _settle(pilot, 10)
        return list(results)

    assert dialog_scene(tmp_path, scenario) == [LC("path", "C")]


def test_tc_b100_41_type_ahead_escape_then_enter_closes_with_none(tmp_path: Path) -> None:
    """A9b-06b (S4-9): list mode (``ab`` highlighted), ``escape`` and
    ``enter`` queued back to back → ``escape`` is taken first: exactly one
    dismiss, ``None``; 0 verdict calls; 0 exceptions.

    Why: keys must act in the order typed; Escape then Enter must not load.
    Negative control: ``escape`` handled only as a binding (after the
    screen's ``on_key``) → the ``enter`` loads ``ab`` first → RED. RED
    (base): no ``LoadDialog``."""

    async def scenario(app, pilot, results, fakes):
        _post(app, "escape")
        _post(app, "enter")
        await _settle(pilot, 10)
        return list(results), len(fakes.verdicts), len(app.screen_stack)

    assert dialog_scene(tmp_path, scenario) == ([None], 0, 1)


def test_tc_b100_41_printable_key_clears_the_preview(tmp_path: Path) -> None:
    """A9b-R2-2 (S4-10), HLR-173a: list mode, ``ab`` previewed (``●
    project:ab`` painted); ``C`` → the preview body is empty and the preview
    callable is called 0 more times.

    Why: once Enter would load the typed text, ``●`` marks of the row would
    describe a load that will not happen.
    Negative control: no clear on the redirect → ``● project:ab`` stays →
    RED. RED (base): no ``LoadDialog``."""

    async def scenario(app, pilot, results, fakes):
        before = preview_lines(app.screen)
        calls = len(fakes.previews)
        await pilot.press("C")
        await _settle(pilot)
        return before, preview_lines(app.screen), len(fakes.previews) - calls

    before, after, more = dialog_scene(tmp_path, scenario)
    assert f"{MARK} project:ab" in before, before
    assert [line for line in after if line.strip()] == [], after
    assert more == 0


def test_tc_b100_41_preview_follows_the_load_target(tmp_path: Path) -> None:
    """HLR-173a, D-GA-2 (S7-1, S7-6 … S7-9): list mode with ``highlight="cd"``
    → 1 preview call (``LoadChoice("project", "cd")``) and ``● project:cd``
    painted; ``down`` → the preview of ``a.s19``'s row replaces it; in path
    mode the preview is empty and 0 preview calls are made, also after
    typing (no typed-file preview, A9b-07); ``tab`` into the list → 1 call
    for the highlighted row.

    RED (base): no ``LoadDialog``."""

    async def listing(app, pilot, results, fakes):
        first = (list(fakes.previews), preview_lines(app.screen))
        await pilot.press("down")
        await _settle(pilot)
        return first, (list(fakes.previews), preview_lines(app.screen))

    first, second = dialog_scene(tmp_path / "list", listing, highlight="cd")
    assert first[0] == [LC("project", "cd")], first
    assert first[1] == [f"{MARK} project:cd", "note"], first
    assert second[0][-1] == LC("workarea", "a.s19"), second
    assert second[1] == [f"{MARK} workarea:a.s19", "note"], second

    async def path_mode(app, pilot, results, fakes):
        empty = (len(fakes.previews), preview_lines(app.screen))
        await ld.type_into_path(pilot, app, "C:\\t\\a.s19")
        await _settle(pilot)
        typed = (len(fakes.previews), preview_lines(app.screen))
        await pilot.press("tab")
        await _settle(pilot)
        return empty, typed, (list(fakes.previews), preview_lines(app.screen))

    empty, typed, tabbed = dialog_scene(tmp_path / "path", path_mode, mode="path")
    assert empty[0] == 0 and [x for x in empty[1] if x.strip()] == [], empty
    assert typed[0] == 0 and [x for x in typed[1] if x.strip()] == [], typed
    assert tabbed[0] == [LC("project", "ab")], tabbed
    assert tabbed[1] == [f"{MARK} project:ab", "note"], tabbed


def test_tc_b100_41_labels_key_bar_and_palette_say_load_and_projects(tmp_path: Path) -> None:
    """LLR-173.2m (Inc 12a, 9b ruling Q8 restored; B12-01, B12-02, B12-03):
    at 118×54 the key bar's row 1 holds ``^l Load`` and no row holds
    ``Load file``; the Workspace row 2 holds ``p Projects`` and no
    ``p Load project``; the palette holds the entries ``("Load",
    "load_file")`` and ``("Projects", "load_project")`` and 0 entries
    ``Load file`` or ``Load project``. The Workspace button keeps
    ``Load project (p)`` (ruling Q6), so the painted rows are read from the
    key bar only.

    Why: VS-PA-4 — the two entry points to the one Load dialog are named
    for what the user picks, a file to load or one of the projects.
    Negative control (code read on base): ``Binding(..., "Load file")`` and
    ``Binding("p", ..., "Load project")`` → RED."""
    from tests.test_b97_key_bar import bar_rows, pieces

    base = tmp_path / "app"

    async def scenario(app, pilot, log):
        await _home(pilot)
        await _settle(pilot, 3)
        rows = bar_rows(app)
        entries = [(entry.label, entry.action) for entry in app._build_palette_entries()]
        return rows, entries

    rows, entries = _run(base, scenario)
    tokens = [pieces(row) for row in rows]
    assert "^l Load" in tokens[0], tokens
    assert not any("Load file" in row for row in rows), rows
    assert any("p Projects" in row_tokens for row_tokens in tokens[1:]), tokens
    assert not any("p Load project" in row for row in rows), rows
    assert ("Load", "load_file") in entries, entries
    assert ("Projects", "load_project") in entries, entries
    assert [e for e in entries if e[0] in ("Load file", "Load project")] == [], entries


# ===========================================================================
# TC-B100-42 — literal names (LLR-173.3 … LLR-173.3d)
# ===========================================================================

HOSTILE_PROJECTS = {
    "markup bold": "[b]P",
    "markup action": "[@click=app.bell]Q",
    "bidi override U+202E": "x\u202eR",
    "C1 control U+009B": "a\x9bS",
}


@pytest.mark.parametrize("label", list(HOSTILE_PROJECTS))
def test_tc_b100_42_project_rows_are_painted_literally(tmp_path: Path, label: str) -> None:
    """LLR-173.3 (B33, S3-12; 4 of 4): projects named ``[b]P``,
    ``[@click=app.bell]Q``, ``x`` + U+202E + ``R`` and ``a`` + U+009B +
    ``S`` → the painted row equals the name with Cc / Cf characters removed
    (``[b]P`` keeps its brackets: 0 markup parsed), 0 characters of category
    Cc, Cf or Cs, 0 raises. The U+009B arm is reported not run where the
    volume refuses the folder name.

    Why: a folder name is the operator's own disk text; markup in it must
    not style or act, and a bidi control must not reorder the row.
    Negative controls: rows with markup on → ``[b]P`` paints ``P`` → RED;
    ``safe_text`` only (C0 / C1) → U+202E kept → RED. RED (base): the Load
    dialog has no list."""
    name = HOSTILE_PROJECTS[label]
    base = tmp_path / "app"
    _make_or_skip(_wa(base) / name / "a.s19", _s19())

    async def scenario(app, pilot, log):
        await _home(pilot)
        await _open(pilot, app, "p")
        prompts = ld.section_prompts(app.screen, "Projects")
        painted = [line for line in projects.painted_lines(app.screen.query_one("#load_list"))]
        return prompts, painted

    prompts, painted = _run(base, scenario)
    expected = _scrubbed(name)
    assert prompts == [expected], (ascii(prompts), ascii(expected))
    assert _bad_categories(prompts[0]) == []
    assert any(expected in line for line in painted), [ascii(p) for p in painted]


HOSTILE_FILES = {
    "markup bold": "[bold]x.s19",
    "markup link": "[link=x]a.s19",
    "markup action": "[@click=app.bell]x.s19",
    "C1 control U+009B": "a\x9bb.s19",
    "bidi override U+202E": "x\u202egpj.s19",
    "unpaired surrogate U+DC80": "a\udc80b.s19",
    "130 characters": "n" * 126 + ".s19",
}


@pytest.mark.parametrize("label", list(HOSTILE_FILES))
def test_tc_b100_42_work_area_file_rows_are_painted_literally(tmp_path: Path, label: str) -> None:
    """LLR-173.3a (B34; 7 of 7): the six hostile names of LLR-172.6 and a
    130-character name in ``temp/`` → the work-area row equals the name
    scrubbed (Cc / Cf / Zl / Zp removed, a surrogate as U+FFFD) and clipped
    to 120 characters ending in ``…``; 0 Cc / Cf / Cs characters. The
    surrogate arm is reported not run where the name cannot be made.

    Negative control: a row built as ``Label(name)`` → ``[bold]x.s19``
    paints styled ``x.s19`` → RED. RED (base): no list in the Load
    dialog."""
    name = HOSTILE_FILES[label]
    base = tmp_path / "app"
    _make_or_skip(_temp(base) / name, _s19())

    async def scenario(app, pilot, log):
        await _open(pilot, app, "l")
        return ld.section_prompts(app.screen, "Work area")

    prompts = _run(base, scenario)
    assert prompts == [_scrubbed(name)], (ascii(prompts), ascii(_scrubbed(name)))
    assert _bad_categories(prompts[0]) == []


@pytest.mark.parametrize(
    "recorded,file_name",
    [
        ("C:\\x\\[bold]a.s19", "[bold]a.s19"),
        ("C:\\x\\[link=y]b.hex", "[link=y]b.hex"),
        ("C:\\x\\[@click=app.bell]c.a2l", "[@click=app.bell]c.a2l"),
    ],
)
def test_tc_b100_42_recent_rows_are_painted_literally(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recorded: str, file_name: str
) -> None:
    """LLR-173.3b (B35; 3 of 3): store entries ``C:\\x\\[bold]a.s19``,
    ``C:\\x\\[link=y]b.hex`` and ``C:\\x\\[@click=app.bell]c.a2l`` (each
    accepted by the 9a read) → a recent row whose painted text holds the
    literal file name, brackets included (0 markup parsed).

    Negative control: a row built as ``Label(path)`` → the markup is parsed
    → RED. RED (base): no list in the Load dialog."""
    lad = _lad(tmp_path, monkeypatch)
    if not WIN:
        monkeypatch.setattr("s19_app.tui.workspace.recent_store_path", lambda: _store(lad))
    _seed_store(lad, [recorded])
    base = tmp_path / "app"

    async def scenario(app, pilot, log):
        await _open(pilot, app, "l")
        rows = ld.section_prompts(app.screen, "Recent")
        painted = projects.painted_lines(app.screen.query_one("#load_list"))
        return rows, painted

    rows, painted = _run(base, scenario)
    assert len(rows) == 1 and rows[0].startswith(file_name), rows
    assert any(file_name in line for line in painted), painted


def test_tc_b100_42_preview_names_are_painted_literally(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-173.3c (B76, B60, S8-6; 4 of 4): project ``P`` holding
    ``[b]v.s19``, ``[i]m.mac`` and ``[u]c.a2l`` highlighted → the preview's
    text holds the 3 literal names (brackets kept); a recent
    ``C:\\x\\[bold]a.s19`` highlighted → its preview holds the literal path.

    Negative control: the preview written with markup on → ``[b]v.s19``
    paints ``v.s19`` bold → RED. RED (base): no preview."""
    lad = _lad(tmp_path, monkeypatch)
    if not WIN:
        monkeypatch.setattr("s19_app.tui.workspace.recent_store_path", lambda: _store(lad))
    _seed_store(lad, ["C:\\x\\[bold]a.s19"])
    base = tmp_path / "app"
    _project(base, "P", {"[b]v.s19": _s19(), "[i]m.mac": _mac(), "[u]c.a2l": _a2l()})

    async def scenario(app, pilot, log):
        await _home(pilot)
        await _open(pilot, app, "p")
        await ld.highlight_row(pilot, app, "P")
        await _settle(pilot)
        project = "\n".join(preview_lines(app.screen))
        await _highlight_index(pilot, app, _section_index(app.screen, "Recent"))
        await _settle(pilot)
        recent = "\n".join(preview_lines(app.screen))
        return project, recent

    project, recent = _run(base, scenario)
    for name in ("[b]v.s19", "[i]m.mac", "[u]c.a2l"):
        assert name in project, project
    assert "C:\\x\\[bold]a.s19" in recent, recent


def test_tc_b100_42_a_pick_loads_the_on_disk_name(tmp_path: Path) -> None:
    """LLR-173.3d (B36, S5-22; 3 of 3): the ``[b]P`` project row loaded →
    ``current_project == "[b]P"``; the work-area row of ``a`` + U+009B +
    ``S.s19`` (painted ``aS.s19``) loaded → ``current_file.path.name`` is the
    on-disk name; a dialog row whose label is clipped (``f``×119 + ``…``)
    dismisses the full value (``f``×130 + ``.s19``), the very object the
    row held.

    Negative control: the painted label stored as the value → the U+009B and
    clipped arms load nothing → RED. RED (base): no list in the Load
    dialog."""
    base = tmp_path / "app"
    _project(base, "[b]P", {"a.s19": _s19()})

    async def project_scene(app, pilot, log):
        await _home(pilot)
        await ld.open_project_through_dialog(pilot, app, "[b]P", confirm="enter")
        await ld.wait_for(pilot, lambda: app.current_project is not None, "the project load")
        return app.current_project

    assert _run(base, project_scene) == "[b]P"

    base2 = tmp_path / "file"
    name = "a\x9bS.s19"
    _make_or_skip(_temp(base2) / name, _s19())

    async def file_scene(app, pilot, log):
        await _open(pilot, app, "l")
        await pilot.press("tab")
        await pilot.pause()
        await ld.highlight_row(pilot, app, _scrubbed(name))
        await pilot.press("enter")
        await ld.wait_for(pilot, lambda: app.current_file is not None, "the work-area load")
        return Path(app.current_file.path).name

    assert _run(base2, file_scene) == name

    rows = ROWS_LONG()

    async def long_scene(app, pilot, results, fakes):
        await _highlight_index(pilot, app, 3)
        await pilot.press("enter")
        await _settle(pilot)
        return list(results)

    results = dialog_scene(tmp_path / "long", long_scene, rows=lambda: rows)
    assert results == [LC("workarea", "f" * 130 + ".s19")], results
    assert results[0] is rows[3][2]


# ===========================================================================
# TC-B100-43 — the three sections (LLR-173.4 … LLR-173.4m)
# ===========================================================================


def _store_on_any_host(lad: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    if not WIN:
        monkeypatch.setattr("s19_app.tui.workspace.recent_store_path", lambda: _store(lad))


@JUNCTION_ARM
def test_tc_b100_43_sections_hold_the_projects_files_and_recents(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """HLR-173 list half, LLR-173.4, LLR-173.4l (B18, B31, B45): projects
    ``ab`` and ``cd``, the reserved ``temp`` and ``patches``, a junction
    ``jx`` to ``ab``, ``temp/`` holding ``a.s19`` and ``c.a2l``, and a store
    of 3 entries → the list reads, in order, ``Projects``, ``ab``, ``cd``,
    ``Work area``, ``a.s19``, ``c.a2l``, ``Recent`` and 3 recent rows
    (2 + 2 + 3 loadable rows, 3 sections); the headings are disabled.

    Why: one dialog lists everything that can be loaded (P-20); a reserved
    home or a junction is never a project.
    Negative control: the work area listed without ``list_projects`` →
    ``temp``, ``patches``, ``jx`` listed → RED. RED (base): no list."""
    lad = _lad(tmp_path, monkeypatch)
    _store_on_any_host(lad, monkeypatch)
    _seed_store(lad, ["C:\\s\\fw.s19", "C:\\s\\cal.a2l", "C:\\s\\m.mac"])
    base = tmp_path / "app"
    _project(base, "ab", {"a.s19": _s19()})
    _project(base, "cd", {"a.s19": _s19()})
    (_wa(base) / "patches").mkdir(parents=True, exist_ok=True)
    temp = _temp(base)
    (temp / "a.s19").write_bytes(_s19())
    (temp / "c.a2l").write_bytes(_a2l())
    b100_links.create_junction(_wa(base) / "jx", _wa(base) / "ab")

    async def scenario(app, pilot, log):
        await _open(pilot, app, "l")
        from textual.widgets import OptionList

        lst = app.screen.query_one("#load_list", OptionList)
        prompts = ld.option_prompts(app.screen)
        disabled = [i for i in range(lst.option_count) if lst.get_option_at_index(i).disabled]
        return prompts, disabled, len(app.screen_stack)

    prompts, disabled, depth = _run(base, scenario)
    assert depth == 2
    assert prompts[:7] == ["Projects", "ab", "cd", "Work area", "a.s19", "c.a2l", "Recent"], prompts
    assert len(prompts) == 10, prompts
    assert [p.split()[0] for p in prompts[7:]] == ["fw.s19", "cal.a2l", "m.mac"], prompts
    assert disabled == [0, 3, 6], disabled


@pytest.mark.parametrize(
    "contents,listed",
    [
        ({}, False),
        ({"notes.txt": b"x"}, False),
        ({"project.json": b'{"schema_version": 1}'}, True),
        ({"x.s19": None}, True),
        ({"c.a2l": None}, True),
    ],
    ids=["empty", "notes only", "project.json only", "s19 only", "a2l only"],
)
def test_tc_b100_43_a_folder_that_is_not_a_project_is_not_listed(
    tmp_path: Path, contents: dict, listed: bool
) -> None:
    """LLR-173.4a (B17; 5 of 5): an empty folder and a folder holding only
    ``notes.txt`` → 0 project rows; a folder holding only ``project.json``,
    only ``x.s19`` or only ``c.a2l`` → 1 row.

    Why: §1.3 — a folder with no manifest, data or A2L file is not a
    project, and listing it offers a load that can only fail.
    RED (base): the base dialog has no list (and the base ``list_projects``
    lists the empty folder)."""
    base = tmp_path / "app"
    folder = _wa(base) / "f1"
    folder.mkdir(parents=True)
    for name, payload in contents.items():
        if payload is None:
            payload = _a2l() if name.endswith(".a2l") else _s19()
        (folder / name).write_bytes(payload)

    async def scenario(app, pilot, log):
        await _open(pilot, app, "l")
        return ld.section_prompts(app.screen, "Projects")

    assert _run(base, scenario) == (["f1"] if listed else [])


def test_tc_b100_43_a_reparse_project_json_alone_is_not_a_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-173.4a, S9b-2 (E5, M81): folder ``f1`` holding only a
    ``project.json`` that ``lstat`` reports as a regular file but
    ``_is_reparse_point`` reports as a reparse point (a cloud placeholder),
    and folder ``f2`` holding only a plain ``project.json`` → the Projects
    section lists ``f2`` only.

    Why: a placeholder manifest is not read (S9b-2), so on its own it does
    not make a folder a project; listing it offers a load that can only be
    refused.
    Negative control: the content test without ``_is_reparse_point`` →
    ``f1`` listed → RED (M81)."""
    base = tmp_path / "app"
    for name in ("f1", "f2"):
        folder = _wa(base) / name
        folder.mkdir(parents=True)
        (folder / "project.json").write_text('{"schema_version": 1}', encoding="utf-8")
    real = app_module._is_reparse_point
    f1_manifest = os.path.normcase(str(_wa(base) / "f1" / "project.json"))
    monkeypatch.setattr(
        app_module,
        "_is_reparse_point",
        lambda path: os.path.normcase(os.fspath(path)) == f1_manifest or real(path),
    )

    async def scenario(app, pilot, log):
        await _open(pilot, app, "l")
        return ld.section_prompts(app.screen, "Projects")

    assert _run(base, scenario) == ["f2"]


def test_tc_b100_43_files_section_is_the_one_lister_filtered_to_loadable_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-173.4b, LLR-172.4 (B37; 2 of 3 here, the census arm in
    ``test_b100_recents.py``): ``temp/`` holding ``a.s19``, ``b.hex``,
    ``c.a2l``, ``d.a2l.json``, ``e.txt`` and the folder ``.staging/`` → 3
    rows ``a.s19``, ``b.hex``, ``c.a2l`` in lister order; a runtime spy on
    ``os.scandir``, ``os.listdir``, ``Path.iterdir`` and ``Path.glob``
    during one dialog open → ``temp/`` is enumerated once.

    Why: one lister means the dialog and the Workarea Files list can never
    disagree (CR9-11); an ``.a2l.json`` dump is not a loadable file (C7).
    Negative controls: a second enumeration ``(workarea / "temp").iterdir()``
    → 2 enumerations → RED; no suffix filter → 5 rows → RED. RED (base): no
    list (0 enumerations at dialog open)."""
    base = tmp_path / "app"
    temp = _temp(base)
    for name in ("a.s19", "b.hex", "c.a2l", "d.a2l.json", "e.txt"):
        payload = _hex() if name.endswith(".hex") else (_a2l() if "a2l" in name else _s19())
        (temp / name).write_bytes(payload)
    (temp / ".staging").mkdir(exist_ok=True)
    key = os.path.normcase(str(temp))
    seen: list = []
    real_scandir, real_listdir = os.scandir, os.listdir
    real_iterdir, real_glob = pathlib.Path.iterdir, pathlib.Path.glob

    def note(target, how):
        try:
            if os.path.normcase(os.fspath(target)) == key:
                seen.append(how)
        except TypeError:
            pass

    def scandir(path=".", *a, **k):
        note(path, "scandir")
        return real_scandir(path, *a, **k)

    def listdir(path=".", *a, **k):
        note(path, "listdir")
        return real_listdir(path, *a, **k)

    def iterdir(self):
        note(self, "iterdir")
        return real_iterdir(self)

    def glob(self, *a, **k):
        note(self, "glob")
        return real_glob(self, *a, **k)

    async def scenario(app, pilot, log):
        seen.clear()
        monkeypatch.setattr(os, "scandir", scandir)
        monkeypatch.setattr(os, "listdir", listdir)
        monkeypatch.setattr(pathlib.Path, "iterdir", iterdir)
        monkeypatch.setattr(pathlib.Path, "glob", glob)
        await pilot.press("l")
        await ld.wait_for_dialog(pilot, app)
        await _settle(pilot, 6)
        monkeypatch.undo()
        return ld.section_prompts(app.screen, "Work area"), list(seen)

    rows, enumerations = _run(base, scenario)
    assert rows == ["a.s19", "b.hex", "c.a2l"], rows
    assert len(enumerations) == 1, enumerations


@pytest.mark.parametrize("arm", ["3 in order", "20 entries", "2 valid of 3"])
def test_tc_b100_43_recents_section_is_the_store_read_in_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: str
) -> None:
    """LLR-173.4c (B38; 3 of 3): a store of 3 entries → 3 rows in stored
    order; a store of 20 → 20 rows; a store of 3 where the read refuses 1
    (not drive-rooted) → 2 rows.

    Negative control: rows sorted by path → the 3-entry order differs → RED.
    RED (base): no list."""
    lad = _lad(tmp_path, monkeypatch)
    _store_on_any_host(lad, monkeypatch)
    if arm == "3 in order":
        paths = ["C:\\z\\zz.s19", "C:\\a\\aa.a2l", "C:\\m\\mm.mac"]
        _seed_store(lad, paths)
        expected = ["zz.s19", "aa.a2l", "mm.mac"]
    elif arm == "20 entries":
        paths = [f"C:\\r\\f{i:02d}.s19" for i in range(20)]
        _seed_store(lad, paths)
        expected = [f"f{i:02d}.s19" for i in range(20)]
    else:
        store = _store(lad)
        store.parent.mkdir(parents=True, exist_ok=True)
        doc = {"schema_version": 1, "sources": [
            {"path": "C:\\a\\one.s19", "kind": "s19"},
            {"path": "relative\\two.s19", "kind": "s19"},
            {"path": "C:\\a\\three.hex", "kind": "hex"},
        ]}
        store.write_text(json.dumps(doc), encoding="ascii")
        expected = ["one.s19", "three.hex"]

    async def scenario(app, pilot, log):
        await _open(pilot, app, "l")
        return ld.section_prompts(app.screen, "Recent")

    rows = _run(tmp_path / "app", scenario)
    assert [r.split()[0] for r in rows] == expected, rows


def test_tc_b100_43_empty_projects_section_paints_its_tokens(tmp_path: Path) -> None:
    """LLR-173.4d (B39, 1 of 1): 0 projects → exactly one line under
    ``Projects`` holding ``no projects`` and ``ctrl+s saves a project``, and
    that line cannot be loaded (disabled).

    Negative control: nothing painted → 0 lines → RED. RED (base): no
    list."""

    async def scenario(app, pilot, log):
        await _open(pilot, app, "l")
        return (
            ld.section_prompts(app.screen, "Projects", loadable_only=False),
            ld.section_prompts(app.screen, "Projects"),
        )

    lines, loadable = _run(tmp_path / "app", scenario)
    assert len(lines) == 1 and "no projects" in lines[0] and "ctrl+s saves a project" in lines[0], lines
    assert loadable == []


@pytest.mark.parametrize("contents", [[], ["d.a2l.json"]], ids=["empty temp", "only an A2L dump"])
def test_tc_b100_43_empty_files_section_paints_its_tokens(tmp_path: Path, contents: list) -> None:
    """LLR-173.4e (B40, 2 of 2): an empty ``temp/``, and a ``temp/`` holding
    only ``d.a2l.json`` → one line holding ``no work-area files`` and ``l
    loads a file``, not loadable.

    Negative control: the tokens painted only when the lister returns
    nothing → the ``d.a2l.json`` arm paints no line → RED. RED (base): no
    list."""
    base = tmp_path / "app"
    temp = _temp(base)
    for name in contents:
        (temp / name).write_text("{}", encoding="utf-8")

    async def scenario(app, pilot, log):
        await _open(pilot, app, "l")
        return (
            ld.section_prompts(app.screen, "Work area", loadable_only=False),
            ld.section_prompts(app.screen, "Work area"),
        )

    lines, loadable = _run(base, scenario)
    assert len(lines) == 1 and "no work-area files" in lines[0] and "l loads a file" in lines[0], lines
    assert loadable == []


@pytest.mark.parametrize("arm", ["no store file", "LOCALAPPDATA unset"])
def test_tc_b100_43_empty_recents_section_paints_its_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: str
) -> None:
    """LLR-173.4f (B41, 2 of 2): no store file, and an unset
    ``LOCALAPPDATA`` → one line ``no recent sources``, not loadable.

    Negative control: nothing painted → RED. RED (base): no list."""
    if arm == "no store file":
        _lad(tmp_path, monkeypatch)
    else:
        monkeypatch.delenv("LOCALAPPDATA", raising=False)

    async def scenario(app, pilot, log):
        await _open(pilot, app, "l")
        return (
            ld.section_prompts(app.screen, "Recent", loadable_only=False),
            ld.section_prompts(app.screen, "Recent"),
        )

    lines, loadable = _run(tmp_path / "app", scenario)
    assert lines == ["no recent sources"], lines
    assert loadable == []


@pytest.mark.parametrize("arm", ["too large", "could not be read"])
def test_tc_b100_43_store_problem_is_painted_in_the_recents_section(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: str
) -> None:
    """LLR-173.4g (B42, 2 of 2): a 65 537-byte store → one line holding
    ``too large`` and ``the next load starts a new list``; a store whose
    open raises ``PermissionError`` (injected) → one line holding ``could
    not be read`` and ``check that the recent-sources file can be opened``;
    0 recent rows each, and no part of the store path painted (Q5).

    Why: a broken store must say what happened and what to do, not look
    like an empty history.
    Negative control: the problem ignored → ``no recent sources`` → RED.
    RED (base): no list."""
    lad = _lad(tmp_path, monkeypatch)
    _store_on_any_host(lad, monkeypatch)
    store = _store(lad)
    store.parent.mkdir(parents=True, exist_ok=True)
    if arm == "too large":
        store.write_bytes(b" " * 65_537)
        tokens = ("too large", "the next load starts a new list")
    else:
        store.write_bytes(b'{"schema_version":1,"sources":[]}')
        tokens = ("could not be read", "check that the recent-sources file can be opened")
        real_open = builtins.open
        key = os.path.normcase(str(store))

        def guarded(file, *args, **kwargs):
            if not isinstance(file, int) and os.path.normcase(os.fspath(file)) == key:
                raise PermissionError(13, "injected: access denied", os.fspath(file))
            return real_open(file, *args, **kwargs)

        monkeypatch.setattr(builtins, "open", guarded)

    async def scenario(app, pilot, log):
        await _open(pilot, app, "l")
        return (
            ld.section_prompts(app.screen, "Recent", loadable_only=False),
            ld.section_prompts(app.screen, "Recent"),
        )

    lines, loadable = _run(tmp_path / "app", scenario)
    assert len(lines) == 1 and all(t in lines[0] for t in tokens), lines
    assert loadable == []
    assert str(lad) not in lines[0] and "recent_sources.json" not in lines[0], lines


def test_tc_b100_43_recent_row_shows_the_file_name_and_kind_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-173.4h (B43; 1 + 1): ``C:\\cal\\v2\\fw.s19`` (kind ``s19``) → a
    row whose plain text is ``fw.s19`` followed by ``s19``, with no folder
    text and no ``●``; a 300-character recorded path whose file is
    ``fw.s19`` → the same short row on one line.

    Why: a recent may sit on a slow or absent drive; the row shows only
    what the store recorded (a size or a date needs a filesystem call).
    Negative control: a size or a date added → the text differs → RED. RED
    (base): no list."""
    lad = _lad(tmp_path, monkeypatch)
    _store_on_any_host(lad, monkeypatch)
    long_path = "C:\\" + "\\".join(["d" * 40] * 6) + "\\" + "e" * 40 + "\\fw.s19"
    _seed_store(lad, ["C:\\cal\\v2\\fw.s19", long_path])

    async def scenario(app, pilot, log):
        await _open(pilot, app, "l")
        from textual.widgets import OptionList

        lst = app.screen.query_one("#load_list", OptionList)
        return ld.section_prompts(app.screen, "Recent"), lst.virtual_size.height, lst.option_count

    rows, height, count = _run(tmp_path / "app", scenario)
    assert len(rows) == 2, rows
    for row in rows:
        assert re.fullmatch(r"fw\.s19\W+s19\W*", row), row
        assert "cal" not in row and MARK not in row and "\\" not in row, row
    assert height == count, (height, count)


def test_tc_b100_43_recent_preview_shows_the_store_facts_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-173.4i (B58; 3 of 3, plus E5 M61): recents ``C:\\cal\\v2\\fw.s19``,
    ``C:\\cal\\c.a2l``, ``C:\\cal\\m.mac`` and a 200-character
    ``C:\\cal\\ddd…\\long.s19`` highlighted in turn → each preview holds the
    full recorded path (the long one not clipped), its kind and ``checked
    when loaded``, with 0 ``●``.

    Why: nothing is read before Enter, so the preview cannot claim what a
    load installs; it says when the check happens. The row label is
    clipped, so the preview is the one place the whole path is shown.
    Negative control: a preview that reads the file (size, "same bytes")
    → RED here and on LLR-173.4j; the path clipped at 120 → the long path is
    not in the preview → RED (M61). RED (base): no preview."""
    lad = _lad(tmp_path, monkeypatch)
    _store_on_any_host(lad, monkeypatch)
    long_path = "C:\\cal\\" + "d" * 184 + "\\long.s19"
    assert len(long_path) == 200
    paths = ["C:\\cal\\v2\\fw.s19", "C:\\cal\\c.a2l", "C:\\cal\\m.mac", long_path]
    _seed_store(lad, paths)

    async def scenario(app, pilot, log):
        await _open(pilot, app, "l")
        await pilot.press("tab")
        await pilot.pause()
        out = []
        for position in range(len(paths)):
            await _highlight_index(pilot, app, _section_index(app.screen, "Recent", position))
            await _settle(pilot)
            out.append(preview_lines(app.screen))
        return out

    previews = _run(tmp_path / "app", scenario)
    for path, lines in zip(paths, previews):
        text = "\n".join(lines)
        assert path in text, lines
        assert _kind(path) in text, lines
        assert "checked when loaded" in text, lines
        assert marked(lines) == [], lines


def test_tc_b100_43_no_filesystem_call_touches_a_recent_before_load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-173.4j (B44, B59): the dialog opened and 3 recents highlighted
    (one present, one missing, one on the unassigned drive ``Q:``) → 0 calls
    naming any of the 3 paths among ``os.stat``, ``os.lstat``,
    ``os.scandir``, ``os.listdir``, ``open``, ``os.path.exists`` and
    ``Path.exists`` / ``is_file`` / ``resolve`` (a counting spy).

    Why: a recent on a network or removable drive must not hang or wake
    the drive before the engineer asks to load it (S-07).
    Negative control: a preview that adds the recent's size → 1 call per
    highlight → RED. RED (base): no list to highlight."""
    lad = _lad(tmp_path, monkeypatch)
    _store_on_any_host(lad, monkeypatch)
    src = tmp_path / "src"
    src.mkdir()
    (src / "here.s19").write_bytes(_s19())
    recents = [str(src / "here.s19"), str(tmp_path / "missing" / "gone.s19"), "Q:\\nowhere\\fw.s19"]
    _seed_store(lad, recents)
    keys = {os.path.normcase(p) for p in recents}
    hits: list = []

    def check(target, how):
        try:
            text = os.path.normcase(os.fspath(target))
        except TypeError:
            return
        if text in keys:
            hits.append((how, text))

    def wrap_fn(module, name):
        real = getattr(module, name)

        def wrapper(path, *a, **k):
            check(path, name)
            return real(path, *a, **k)

        monkeypatch.setattr(module, name, wrapper)

    def wrap_method(name):
        real = getattr(pathlib.Path, name)

        def wrapper(self, *a, **k):
            check(self, f"Path.{name}")
            return real(self, *a, **k)

        monkeypatch.setattr(pathlib.Path, name, wrapper)

    async def scenario(app, pilot, log):
        for name in ("stat", "lstat", "scandir", "listdir"):
            wrap_fn(os, name)
        wrap_fn(os.path, "exists")
        wrap_fn(builtins, "open")
        for name in ("exists", "is_file", "resolve"):
            wrap_method(name)
        await pilot.press("l")
        await ld.wait_for_dialog(pilot, app)
        await _settle(pilot, 4)
        await pilot.press("tab")
        await pilot.pause()
        rows = 0
        for position in range(3):
            await _highlight_index(pilot, app, _section_index(app.screen, "Recent", position))
            await _settle(pilot, 3)
            rows += 1
        monkeypatch.undo()
        return rows

    assert _run(tmp_path / "app", scenario) == 3
    assert hits == [], hits


@STORE_WRITE
def test_tc_b100_43_missing_recent_is_explained_inside_the_dialog(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-173.4k, HLR-173b boundary (B54, 1 of 1): a recent whose file was
    deleted, highlighted, then ``enter`` → ``#load_reason`` paints ``not
    found`` and ``check the path``; the dialog stays open (0 dismisses), 0
    loads, the store bytes unchanged (the entry stays, Q3).

    Negative control: a dialog that dismisses and lets the router paint a
    status line → the dialog closes → RED. RED (base): no recent row."""
    lad = _lad(tmp_path, monkeypatch)
    gone = tmp_path / "src" / "gone.s19"
    store = _seed_store(lad, [str(gone)])
    store_sha = _sha(store)

    async def scenario(app, pilot, log):
        await _open(pilot, app, "l")
        await pilot.press("tab")
        await pilot.pause()
        await _highlight_index(pilot, app, _section_index(app.screen, "Recent"))
        await pilot.press("enter")
        await _settle(pilot, 8)
        return reason_text(app.screen) if ld.is_load_dialog(app.screen) else None, app.current_file

    reason, current = _run(tmp_path / "app", scenario)
    assert reason is not None, "the dialog closed on a missing recent"
    assert "not found" in reason and "check the path" in reason, reason
    assert current is None
    assert _sha(store) == store_sha


def test_tc_b100_43_unreadable_project_list_says_so(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """LLR-173.4m (B46, 1 of 1): ``PermissionError`` injected into
    ``list_projects`` → the dialog opens; its projects section holds one line
    with ``could not be read`` and ``check that the folder can be opened,
    then load again``; the files section is built as usual (``a.s19``); 0
    raises.

    Why: one unreadable folder must not take the files and recents away.
    Negative control: no catch in the rows builder → the exception leaves
    the mount and the app stops → RED. RED (base): no list."""
    base = tmp_path / "app"
    (_temp(base) / "a.s19").write_bytes(_s19())

    def boom(self):
        raise PermissionError(13, "injected: access denied", "workarea")

    async def scenario(app, pilot, log):
        monkeypatch.setattr(app_module.S19TuiApp, "list_projects", boom)
        await _open(pilot, app, "l")
        return (
            ld.section_prompts(app.screen, "Projects", loadable_only=False),
            ld.section_prompts(app.screen, "Work area"),
            ld.section_prompts(app.screen, "Recent", loadable_only=False),
        )

    lines, files, recents = _run(base, scenario)
    assert len(lines) == 1 and "could not be read" in lines[0] and READ_STEP in lines[0], lines
    assert files == ["a.s19"], files
    assert len(recents) >= 1, recents


# ===========================================================================
# TC-B100-63 — typed refusals in ``#load_reason`` (LLR-173.5 … LLR-173.5e)
# ===========================================================================


def _refusal_scene(base: Path, text: str, patch=None):
    """Open Load (``l``), type ``text``, press ``enter``; return (reason,
    field text, dialog still open, new status lines, project, file)."""

    async def scenario(app, pilot, log):
        if patch is not None:
            patch()
        await _open(pilot, app, "l")
        await ld.type_into_path(pilot, app, text)
        mark = len(log.messages)
        await pilot.press("enter")
        await _settle(pilot, 10)
        open_ = ld.is_load_dialog(app.screen)
        return (
            reason_text(app.screen) if open_ else None,
            path_value(app.screen) if open_ else None,
            open_,
            [m for m in log.since(mark) if "NOT loaded" in m],
            app.current_project,
            app.current_file,
        )

    return _run(base, scenario)


def _assert_refused(result, text: str, reason: str, step: str) -> None:
    painted, field, open_, status, project, current = result
    assert open_, f"the dialog closed on a refused path: {status}"
    # E5 (M33, M59): the exact painted line — reason first, U+2014 between.
    assert painted == f"{reason} {DASH} {step}", painted
    assert field == text, (field, text)
    assert status == [], status
    assert project is None and current is None


@pytest.mark.parametrize("arm", ["missing file", "missing folder"])
def test_tc_b100_63_typed_path_not_found_is_explained(tmp_path: Path, arm: str) -> None:
    """LLR-173.5 (B48, 2 of 2): ``<tmp>/missing.s19`` and ``<workarea>/nope``
    → ``not found`` / ``check the path`` in ``#load_reason``, the dialog
    open, the text unchanged, 0 status lines.

    Why: a refused path is explained where it was typed (UX-06), and the
    engineer can correct it in place.
    RED (base): ``LoadFileScreen`` dismisses and paints a status line after
    the close."""
    base = tmp_path / "app"
    _wa(base).mkdir(parents=True)
    text = str(tmp_path / "missing.s19") if arm == "missing file" else str(_wa(base) / "nope")
    _assert_refused(_refusal_scene(base, text), text, "not found", "check the path")


@pytest.mark.parametrize("arm", ["unsupported suffix", "trailing dot", "relative folder"])
def test_tc_b100_63_typed_unsupported_file_is_explained(tmp_path: Path, arm: str) -> None:
    """LLR-173.5a (B49, 3 of 3): ``<tmp>/notes.txt``, ``<tmp>/fw.s19.``
    (trailing dot, CR9-3) and the relative ``.s19tool/workarea/ab`` → ``not
    a supported file`` / ``check the path``, 0 dismisses, the text
    unchanged.

    RED (base): the base dismisses and refuses on the status line."""
    base = tmp_path / "app"
    _project(base, "ab", {"a.s19": _s19()})
    (tmp_path / "notes.txt").write_text("x", encoding="utf-8")
    (tmp_path / "fw.s19").write_bytes(_s19())
    text = {
        "unsupported suffix": str(tmp_path / "notes.txt"),
        "trailing dot": str(tmp_path / "fw.s19") + ".",
        "relative folder": ".s19tool/workarea/ab",
    }[arm]
    _assert_refused(_refusal_scene(base, text), text, "not a supported file", "check the path")


@pytest.mark.parametrize(
    "arm", ["temp", pytest.param("TEMP", marks=CASE_ARM), "empty folder", "sub-folder"]
)
def test_tc_b100_63_typed_folder_that_is_not_a_project_is_explained(tmp_path: Path, arm: str) -> None:
    """LLR-173.5b (B50, 4 of 4): ``<workarea>/temp``, ``<workarea>/TEMP``
    (Windows), an empty ``<workarea>/e`` and ``<workarea>/ab/flows`` →
    ``not a project`` / ``pick a project in the list``, 0 dismisses, 0
    project loads.

    RED (base): the base dismisses and refuses on the status line."""
    base = tmp_path / "app"
    _project(base, "ab", {"a.s19": _s19()})
    (_wa(base) / "ab" / "flows").mkdir()
    (_wa(base) / "e").mkdir()
    _temp(base)
    text = {
        "temp": str(_wa(base) / "temp"),
        "TEMP": str(_wa(base) / "TEMP"),
        "empty folder": str(_wa(base) / "e"),
        "sub-folder": str(_wa(base) / "ab" / "flows"),
    }[arm]
    _assert_refused(_refusal_scene(base, text), text, "not a project", "pick a project in the list")


@pytest.mark.parametrize("arm", ["folder", "manifest"])
def test_tc_b100_63_typed_folder_outside_the_work_area_is_explained(tmp_path: Path, arm: str) -> None:
    """LLR-173.5c (B51, 2 of 2): ``<tmp>/P`` and ``<tmp>/P/project.json`` →
    ``outside the work area`` / ``copy the folder into the work area``, 0
    dismisses.

    RED (base): the base dismisses and refuses on the status line."""
    base = tmp_path / "app"
    _wa(base).mkdir(parents=True)
    outside = tmp_path / "P"
    outside.mkdir()
    (outside / "a.s19").write_bytes(_s19())
    (outside / "project.json").write_text('{"schema_version": 1}', encoding="utf-8")
    text = str(outside) if arm == "folder" else str(outside / "project.json")
    _assert_refused(
        _refusal_scene(base, text), text, "outside the work area", "copy the folder into the work area"
    )


@JUNCTION_ARM
@pytest.mark.parametrize("arm", ["junction folder", "manifest through it"])
def test_tc_b100_63_typed_path_through_a_junction_is_explained(tmp_path: Path, arm: str) -> None:
    """LLR-173.5d (B52, 2 of 2; Windows only): ``<workarea>/jx`` (a junction
    to ``ab``) and ``<workarea>/jx/project.json`` → ``link or junction`` /
    ``pick a project in the list``, 0 dismisses, 0 project loads.

    RED (base): the base dismisses and refuses on the status line."""
    base = tmp_path / "app"
    _project(base, "ab", {"a.s19": _s19()}, manifest={"schema_version": 1})
    b100_links.create_junction(_wa(base) / "jx", _wa(base) / "ab")
    text = str(_wa(base) / "jx") if arm == "junction folder" else str(_wa(base) / "jx" / "project.json")
    _assert_refused(_refusal_scene(base, text), text, "link or junction", "pick a project in the list")


@pytest.mark.parametrize("arm", ["walk lstat", "list_projects", "content listing"])
def test_tc_b100_63_typed_folder_that_cannot_be_read_is_explained(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: str
) -> None:
    """LLR-173.5e (B53, 2 of 2, plus E5 M89): ``PermissionError`` injected
    into ``os.lstat`` of the walk prefix ``<workarea>/ab``, separately into
    ``list_projects``, and separately into the project content listing
    (``_list_project_files``: ``ab`` stays listed fail-open, so the typed
    route reaches the content test, which cannot read it) → ``could not be
    read`` / ``check that the folder can be opened, then load again``, 0
    dismisses, 0 raises (the app keeps running).

    Negative control: the classifier's ``OSError`` catch removed → the error
    leaves the dialog's key handler → the app stops → RED; an unreadable
    content test refused ``not a project`` → RED (M89). RED (base): the
    base dismisses and refuses on the status line."""
    base = tmp_path / "app"
    _project(base, "ab", {"a.s19": _s19()})
    target = _wa(base) / "ab"
    key = os.path.normcase(str(target))
    real_lstat = os.lstat

    def lstat(path, *args, **kwargs):
        if not isinstance(path, int) and os.path.normcase(os.fspath(path)) == key:
            raise PermissionError(13, "injected: access denied", os.fspath(path))
        return real_lstat(path, *args, **kwargs)

    def boom(self):
        raise PermissionError(13, "injected: access denied", "workarea")

    def listing_boom(self, folder):
        raise PermissionError(13, "injected: access denied", str(folder))

    def patch():
        if arm == "walk lstat":
            monkeypatch.setattr(app_module.os, "lstat", lstat)
        elif arm == "list_projects":
            monkeypatch.setattr(app_module.S19TuiApp, "list_projects", boom)
        else:
            monkeypatch.setattr(app_module.S19TuiApp, "_list_project_files", listing_boom)

    result = _refusal_scene(base, str(target), patch=patch)
    monkeypatch.undo()
    _assert_refused(result, str(target), "could not be read", READ_STEP)


def test_tc_b100_63_folder_named_like_a_data_file(tmp_path: Path) -> None:
    """S9b-7, R3-2 (B97): a typed ``<workarea>/ab.s19`` that is a FOLDER
    holding a data file (so listed) → the dialog closes and project
    ``ab.s19`` loads; a typed ``<workarea>/e.s19`` that is an empty,
    unlisted folder → ``not a project`` / ``pick a project in the list``, 0
    dismisses, 0 loads.

    Why: a data or A2L kind is returned only for a regular file; a folder
    named ``x.s19`` must never be opened as an image.
    RED (base): the base takes the suffix and dismisses."""
    base = tmp_path / "app"
    _project(base, "ab.s19", {"a.s19": _s19()})
    (_wa(base) / "e.s19").mkdir()

    async def listed(app, pilot, log):
        await _open(pilot, app, "l")
        await ld.type_into_path(pilot, app, str(_wa(base) / "ab.s19"))
        await pilot.press("enter")
        await ld.wait_for(pilot, lambda: app.current_project is not None, "the project ab.s19")
        return app.current_project

    assert _run(base, listed) == "ab.s19"
    text = str(_wa(base) / "e.s19")
    _assert_refused(_refusal_scene(base, text), text, "not a project", "pick a project in the list")


def test_tc_b100_63_pasted_nul_is_not_inserted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """S9b-4 (S2-10): clipboard text ``a\\x00.s19`` pasted into
    ``#load_path`` (``ctrl+v``) → the field holds no NUL (the ``restrict=``
    rejects C0 controls and U+007F), and 0 raises.

    Why: a NUL in a typed path crashes the path functions later or splits
    the name the engineer sees from the one opened.
    Negative control: ``#load_path`` without ``restrict=`` → the field holds
    ``a\\x00.s19`` → RED; a ``restrict=`` that drops U+007F → the second
    paste, ``b\\x7f.s19``, is inserted → RED (M04). RED (base): no
    ``LoadDialog``."""
    from s19_app.tui import os_clipboard_input as os_clip_mod

    clip = {"text": "a\x00.s19"}
    monkeypatch.setattr(os_clip_mod, "read_os_clipboard", lambda: clip["text"])

    async def scenario(app, pilot, log):
        app.push_screen(ld.bare_path_dialog())
        await ld.wait_for_dialog(pilot, app)
        await _settle(pilot, 4)
        await pilot.press("ctrl+v")
        await _settle(pilot)
        after_nul = path_value(app.screen)
        clip["text"] = "b\x7f.s19"
        await pilot.press("ctrl+v")
        await _settle(pilot)
        return after_nul, path_value(app.screen)

    after_nul, value = _run(tmp_path / "app", scenario)
    assert "\x00" not in after_nul, ascii(after_nul)
    assert "\x7f" not in value, ascii(value)
    assert all(ord(ch) >= 0x20 and ord(ch) != 0x7F for ch in value), ascii(value)


LINK_FILE = ("is a link or junction", "open the file it points to")


@pytest.mark.parametrize(
    "arm", ["linked s19", pytest.param("a2l through a junction", marks=JUNCTION_ARM)]
)
def test_tc_b100_63_typed_linked_file_is_explained_as_a_file(tmp_path: Path, arm: str) -> None:
    """CR9b-03 (S9b-7 follow-up): a typed ``<workarea>/temp/fw.s19`` that is
    a symbolic link to a real S19, and a typed ``<workarea>/jx/c.a2l`` where
    ``jx`` is a junction to project ``ab`` → ``is a link or junction`` /
    ``open the file it points to`` in ``#load_reason``, the dialog open, the
    text unchanged, 0 loads; routed with no dialog (the start-up path) → 1
    status line ``File NOT loaded: … is a link or junction — open the file
    it points to.`` that does not say ``Project``.

    Why: the engineer typed a file, so the project wording (``pick a project
    in the list``) points at the wrong remedy.
    Negative control: the classifier returning ``link`` for a file → the
    project tokens and a ``Project NOT loaded`` line → RED. RED (base): the
    base paints ``link or junction`` / ``pick a project in the list``."""
    base = tmp_path / "app"
    _project(base, "ab", {"a.s19": _s19(), "c.a2l": _a2l()})
    if arm == "linked s19":
        real = tmp_path / "real" / "fw.s19"
        real.parent.mkdir()
        real.write_bytes(_s19())
        _symlink_or_skip(_temp(base) / "fw.s19", real)
        text = str(_wa(base) / WORKAREA_TEMP / "fw.s19")
    else:
        b100_links.create_junction(_wa(base) / "jx", _wa(base) / "ab")
        text = str(_wa(base) / "jx" / "c.a2l")

    result = _refusal_scene(base, text)
    _assert_refused(result, text, *LINK_FILE)
    assert "pick a project" not in result[0], result[0]

    async def routed(app, pilot, log):
        mark = len(log.messages)
        app._load_path_from_user_input(Path(text))
        await _settle(pilot, 10)
        return [m for m in log.since(mark) if "NOT loaded" in m], app.current_file, app.current_a2l_path

    status, current, a2l = _run(base, routed)
    assert len(status) == 1, status
    assert status[0].startswith("File NOT loaded:"), status
    assert f"{LINK_FILE[0]} {DASH} {LINK_FILE[1]}" in status[0], status
    assert "Project" not in status[0], status
    assert current is None and a2l is None, (current, a2l)


def test_tc_b100_63_over_long_paste_is_refused_and_the_app_stays_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SEC9b-1, ruling B (refuse, not truncate): ``#load_path`` holds at most
    4096 characters. A 40 000-character one-line clipboard (a base64 blob)
    pasted with ``ctrl+v`` → the edit is refused, so the field is unchanged
    (empty), the dialog stays open and the app keeps running; a paste of
    exactly 4096 characters → accepted whole (the limit is 4096, not less).

    Why: a path longer than the OS accepts made ``resolve_input_path`` raise
    inside the dialog's key handler, so the app exited and unsaved patch
    edits were lost.
    Negative control: ``#load_path`` without ``max_length`` → the field holds
    40 000 characters → RED. RED (base): no ``max_length``."""
    from s19_app.tui import os_clipboard_input as os_clip_mod

    long_text = "A" * 40000
    at_limit = "C:\\" + "a" * 4093
    clip = {"text": long_text}
    monkeypatch.setattr(os_clip_mod, "read_os_clipboard", lambda: clip["text"])

    async def scenario(app, pilot, log):
        await _open(pilot, app, "l")
        await pilot.press("ctrl+v")
        await _settle(pilot)
        after_long = path_value(app.screen)
        clip["text"] = at_limit
        await pilot.press("ctrl+v")
        await _settle(pilot)
        return after_long, path_value(app.screen), ld.is_load_dialog(app.screen), app.is_running

    after_long, after_limit, open_, running = _run(tmp_path / "app", scenario)
    assert after_long == "", len(after_long)
    assert after_limit == at_limit, len(after_limit)
    assert open_ and running, (open_, running)


@pytest.mark.parametrize(
    "error, typed",
    [("ValueError", "relative"), ("ValueError", "absolute"), ("RuntimeError", "relative")],
)
def test_tc_b100_63_resolve_error_is_refused_not_raised(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: str, typed: str
) -> None:
    """SEC9b-1: ``resolve_input_path`` raising ``ValueError`` (a path too long
    for Windows) or ``RuntimeError`` (a POSIX ``~user`` with no home) for a
    typed relative or absolute path, then ``enter`` → ``not found`` /
    ``check the path`` in ``#load_reason``, the dialog open, the text
    unchanged, 0 status lines, 0 loads, and the app keeps running.

    Why: R-5 rests on "the classifier never raises"; an exception in the
    dialog's key handler stops the app.
    Negative control: no catch around ``resolve_input_path`` → the error
    leaves the key handler, the app stops → RED. RED (base): no catch."""
    base = tmp_path / "app"
    _wa(base).mkdir(parents=True)
    text = "fw.s19" if typed == "relative" else str(tmp_path / "fw.s19")
    exc_type = {"ValueError": ValueError, "RuntimeError": RuntimeError}[error]

    def boom(path, base_dir):
        raise exc_type("injected: stat: path too long for Windows")

    async def scenario(app, pilot, log):
        monkeypatch.setattr(app_module, "resolve_input_path", boom)
        await _open(pilot, app, "l")
        await ld.type_into_path(pilot, app, text)
        mark = len(log.messages)
        await pilot.press("enter")
        await _settle(pilot, 10)
        running = app.is_running
        open_ = ld.is_load_dialog(app.screen)
        result = (
            reason_text(app.screen) if open_ else None,
            path_value(app.screen) if open_ else None,
            open_,
            [m for m in log.since(mark) if "NOT loaded" in m],
            app.current_project,
            app.current_file,
        )
        monkeypatch.undo()
        return running, result

    running, result = _run(base, scenario)
    assert running, "the app stopped on a resolve error"
    _assert_refused(result, text, "not found", "check the path")


# ===========================================================================
# TC-B100-64 — marks = install, preview content, layout (LLR-173.6 …, .4n)
# ===========================================================================


async def _preview_of_project(pilot, app, name: str) -> list:
    await _home(pilot)
    await _open(pilot, app, "p")
    await ld.highlight_row(pilot, app, name)
    await _settle(pilot)
    return preview_lines(app.screen)


async def _enter_and_read_panel(pilot, app) -> tuple:
    await pilot.press("enter")
    await ld.wait_for_dialog_closed(pilot, app)
    text = await _wait_panel_and_close(pilot, app)
    return text, panel_names(app)


PROJECT_CASES = {
    "clean": (
        {"a.s19": "s19", "m.mac": "mac", "c.a2l": "a2l"},
        {"schema_version": 1, "active_variant": "a"},
        ["a.s19", "c.a2l", "m.mac"],
    ),
    "save-back": (
        {"a.s19": "s19other", "b.s19": "s19"},
        {"schema_version": 1, "active_variant": "b"},
        ["b.s19"],
    ),
    "recorded active missing": (
        {"a.s19": "s19", "c.hex": "hex"},
        {"schema_version": 1, "active_variant": "zz"},
        ["a.s19"],
    ),
    "A2L-only": (
        {"c.a2l": "a2l"},
        {"schema_version": 1},
        ["c.a2l"],
    ),
}

_PAYLOAD = {"s19": _s19, "s19other": _s19_other, "mac": _mac, "a2l": _a2l, "hex": _hex}


@pytest.mark.parametrize("case", list(PROJECT_CASES))
def test_tc_b100_64_project_preview_marks_equal_the_install(tmp_path: Path, case: str) -> None:
    """LLR-173.6, HLR-173a (B64 … B67, 4 of 4): a clean project, a project
    whose recorded active variant is not first by name (after a save-back),
    a project whose recorded active variant is missing, and an A2L-only
    project: each highlighted, then ``enter`` → the file names the ``●``
    lines name equal the names the Loaded panel shows (image, MAC, A2L).
    The A2L-only project marks the A2L only.

    Why: the ``●`` set is a promise of what Enter installs; a different
    install would change the engineer's session behind the mark.
    Negative control: the mark computed from the first variant by name →
    the save-back arm marks ``a.s19`` while ``b.s19`` installs → RED. RED
    (base): no preview."""
    files, manifest, expected = PROJECT_CASES[case]
    base = tmp_path / "app"
    _project(base, "P", {name: _PAYLOAD[kind]() for name, kind in files.items()}, manifest=manifest)

    async def scenario(app, pilot, log):
        lines = await _preview_of_project(pilot, app, "P")
        _, names = await _enter_and_read_panel(pilot, app)
        return lines, names

    lines, names = _run(base, scenario)
    assert marked_names(lines) == expected, lines
    assert names == expected, (names, lines)


def test_tc_b100_64_preview_does_not_mark_an_a2l_the_install_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-173.6, A9b-R2-6 (E5, M64): project ``P`` with ``a.s19`` and
    ``c.a2l``, the copy cap lowered between the two sizes (the A2L over it)
    → the preview marks ``a.s19`` only; after ``enter`` the Loaded panel
    names ``a.s19`` only (the install left the A2L out).

    Why: the mark promises what Enter installs; an A2L the admission refuses
    must not carry a ``●``.
    Negative control: the preview skips the admission → ``● … c.a2l`` while
    the panel has no A2L → RED (M64)."""
    import s19_app.tui.workspace as workspace_module

    base = tmp_path / "app"
    _project(base, "P", {"a.s19": _s19(), "c.a2l": _a2l()}, manifest={"schema_version": 1})
    a2l_size, s19_size = len(_a2l()), len(_s19())
    assert s19_size < a2l_size - 1, "fixture: the cap must sit between the two sizes"
    monkeypatch.setattr(workspace_module, "DEFAULT_COPY_SIZE_CAP_BYTES", a2l_size - 1)

    async def scenario(app, pilot, log):
        lines = await _preview_of_project(pilot, app, "P")
        _, names = await _enter_and_read_panel(pilot, app)
        return lines, names

    lines, names = _run(base, scenario)
    assert marked_names(lines) == ["a.s19"], lines
    assert names == ["a.s19"], (names, lines)


def test_tc_b100_64_a_load_that_installs_another_variant_names_it(tmp_path: Path) -> None:
    """LLR-173.6a (B68, 2 of 2): project ``z0`` whose recorded active
    ``b.s19`` is a 0-byte file beside ``a.s19`` → the preview marks
    ``b.s19`` (no image is read before Enter); after ``enter`` the
    Load-result panel names ``not readable`` on ``b.s19`` and the session
    opens ``a.s19``.

    Declared: the panel behaviour holds since Inc 7, so on its own this arm
    is RED only as a mutation (the reason line dropped); on the base it is
    RED because there is no preview."""
    base = tmp_path / "app"
    _project(base, "z0", {"a.s19": _s19(), "b.s19": b""}, manifest={"schema_version": 1, "active_variant": "b"})

    async def scenario(app, pilot, log):
        lines = await _preview_of_project(pilot, app, "z0")
        text, names = await _enter_and_read_panel(pilot, app)
        return lines, projects.flat(text), names

    lines, text, names = _run(base, scenario)
    assert "b.s19" in marked_names(lines), lines
    assert "not readable" in text and "b.s19" in text, text
    assert "a.s19" in names, names


FILE_CASES = {
    "nothing loaded, S19 row": ([], "a.s19", ["a.s19"]),
    "A2L loaded, S19 row": (["cal.a2l"], "a.s19", ["a.s19", "cal.a2l"]),
    "S19 + MAC loaded, HEX row": (["f.s19", "m.mac"], "b.hex", ["b.hex", "m.mac"]),
    "S19 loaded, A2L row": (["f.s19"], "c.a2l", ["c.a2l", "f.s19"]),
    # E5, M71: a MAC row keeps the loaded image, and the preview must say so.
    "S19 loaded, MAC row": (["f.s19"], "d.mac", ["d.mac", "f.s19"]),
}


@pytest.mark.parametrize("case", list(FILE_CASES))
def test_tc_b100_64_file_row_preview_marks_what_the_session_keeps(tmp_path: Path, case: str) -> None:
    """LLR-173.6b, HLR-173a (B80 … B83, 4 of 4): each case highlighted, then
    ``enter`` → the ``●`` names equal the Loaded panel's names: nothing
    loaded + S19 row → 1 ``●``; an A2L loaded + S19 row → 2; an S19 and a
    MAC loaded + HEX row → the HEX and the kept MAC; an S19 loaded + A2L row
    → 2; an S19 loaded + MAC row → the MAC and the kept image (E5, M71).

    Negative control: only the highlighted file marked → the A2L-kept arm
    has 1 ``●`` against 2 panel slots → RED; a MAC row that omits the image
    line → 1 ``●`` against 2 → RED (M71). RED (base): no preview."""
    preload, row, expected = FILE_CASES[case]
    base = tmp_path / "app"
    src = tmp_path / "src"
    src.mkdir()
    payload = {"cal.a2l": _a2l(), "f.s19": _s19(), "m.mac": _mac()}
    for name in preload:
        (src / name).write_bytes(payload[name])
    temp = _temp(base)
    (temp / "a.s19").write_bytes(_s19())
    (temp / "b.hex").write_bytes(_hex())
    (temp / "c.a2l").write_bytes(_a2l())
    (temp / "d.mac").write_bytes(_mac())

    async def scenario(app, pilot, log):
        for name in preload:
            if name.endswith(".a2l"):
                app.load_a2l_from_path(src / name)
                await ld.wait_for(pilot, lambda: app.current_a2l_path is not None, "the preload A2L")
            elif name.endswith(".mac"):
                app.load_from_path(src / name)
                await ld.wait_for(
                    pilot,
                    lambda: app.current_file is not None and app.current_file.mac_path is not None,
                    "the preload MAC",
                )
            else:
                await projects.load_image(pilot, app, src / name)
            await _settle(pilot)
        await _home(pilot)
        await _open(pilot, app, "l")
        await pilot.press("tab")
        await pilot.pause()
        await ld.highlight_row(pilot, app, row)
        await _settle(pilot)
        lines = preview_lines(app.screen)
        await pilot.press("enter")
        await ld.wait_for_dialog_closed(pilot, app)
        await ld.wait_for(
            pilot,
            lambda: row in panel_names(app),
            f"the Loaded panel naming {row}",
        )
        await _settle(pilot, 10)
        return lines, panel_names(app)

    lines, names = _run(base, scenario)
    assert marked_names(lines) == sorted(expected), lines
    assert names == sorted(expected), (names, lines)


def test_tc_b100_64_open_project_note_on_a_data_file_row(tmp_path: Path) -> None:
    """LLR-173.6c (B84, 3 of 3): project ``[b]Pn`` open, S19 row → one
    unmarked line naming ``[b]Pn`` (literally) and the active variant; no
    project open → 0 such lines; ``[b]Pn`` open, A2L row → 0 such lines.

    Why: loading a data file while a project is open makes it that
    project's active variant; the engineer must see that before Enter.
    Negative control: the note painted whatever the state → the
    no-project arm RED. RED (base): no preview."""

    def scene(open_project: bool, row: str):
        base = tmp_path / f"{open_project}{row}"
        temp = _temp(base)
        (temp / "a.s19").write_bytes(_s19())
        (temp / "c.a2l").write_bytes(_a2l())
        _project(base, "[b]Pn", {"p.s19": _s19()}, manifest={"schema_version": 1, "active_variant": "p"})

        async def scenario(app, pilot, log):
            if open_project:
                await projects.load_project(pilot, app, "[b]Pn")
                for _ in range(60):
                    if len(app.screen.query("#result_ok")) > 0:
                        await projects.dismiss_load_result_panel(pilot, app)
                        break
                    await pilot.pause()
            await _home(pilot)
            await _open(pilot, app, "l")
            await pilot.press("tab")
            await pilot.pause()
            await ld.highlight_row(pilot, app, row)
            await _settle(pilot)
            return preview_lines(app.screen)

        lines = _run(base, scenario)
        return [line for line in lines if not line.startswith(MARK) and "active variant" in line]

    notes = scene(True, "a.s19")
    assert len(notes) == 1 and "[b]Pn" in notes[0], notes
    assert scene(False, "a.s19") == []
    assert scene(True, "c.a2l") == []


def test_tc_b100_64_project_preview_lists_every_variant(tmp_path: Path) -> None:
    """LLR-173.6d (B69, 1 of 1): a project with ``b.s19``, ``a.s19`` and
    ``c.hex`` → 3 variant lines in ``build_variant_set`` order (``a.s19``,
    ``b.s19``, ``c.hex``), exactly one carrying ``●``.

    Negative control: only the marked variant listed → 1 line → RED. RED
    (base): no preview."""
    base = tmp_path / "app"
    _project(base, "V", {"b.s19": _s19(), "a.s19": _s19_other(), "c.hex": _hex()})

    async def scenario(app, pilot, log):
        return await _preview_of_project(pilot, app, "V")

    lines = _run(base, scenario)
    variant_lines = [line for line in lines if any(n in line for n in ("a.s19", "b.s19", "c.hex"))]
    order = [next(n for n in ("a.s19", "b.s19", "c.hex") if n in line) for line in variant_lines]
    assert order == ["a.s19", "b.s19", "c.hex"], lines
    assert sum(1 for line in variant_lines if line.startswith(MARK)) == 1, lines


@pytest.mark.parametrize("arm", ["valid", "absent", "over the cap"])
def test_tc_b100_64_project_preview_states_the_manifest(tmp_path: Path, arm: str) -> None:
    """LLR-173.6f (B71, 3 of 3; R3-1): a valid manifest → the preview states
    ``ok``; no ``project.json`` → ``no project.json`` (an absent manifest is
    not a refusal: the variant is still marked); a 1 MiB + 1 byte manifest →
    ``manifest damaged``.

    Negative control: ``ok`` whenever the file exists → the over-cap arm
    paints ``ok`` → RED. RED (base): no preview."""
    base = tmp_path / "app"
    folder = _project(base, "M", {"a.s19": _s19()})
    if arm == "valid":
        (folder / "project.json").write_text('{"schema_version": 1, "active_variant": "a"}', encoding="utf-8")
        token = "ok"
    elif arm == "over the cap":
        (folder / "project.json").write_bytes(b" " * (1024 * 1024 + 1))
        token = "manifest damaged"
    else:
        token = "no project.json"

    async def scenario(app, pilot, log):
        return await _preview_of_project(pilot, app, "M")

    lines = _run(base, scenario)
    state = [line for line in lines if "project" in line.casefold() and not line.startswith(MARK)]
    assert any(re.search(rf"(^|\W){re.escape(token)}($|\W)", line) for line in state), lines
    if arm != "over the cap":
        assert "a.s19" in marked_names(lines), lines
    if arm == "over the cap":
        assert not any(re.search(r"(^|\W)ok($|\W)", line) for line in state), lines


@pytest.mark.parametrize("arm", ["listing", "manifest read"])
def test_tc_b100_64_project_preview_read_error_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: str
) -> None:
    """LLR-173.6k (B73, 2 of 2; F-5, R2-N4): ``PermissionError`` injected into
    the project's link-safe file listing (``_list_project_files``), and
    separately into ``read_project_manifest`` → the preview paints ``could
    not be read`` and ``check that the folder can be opened, then load
    again``, 0 ``●``, 0 raises, the dialog open.

    Negative control: no catch in the preview builder → the error ends the
    app's run → RED. RED (base): the lister does not exist
    (``AttributeError``) / no preview."""
    base = tmp_path / "app"
    _project(base, "E", {"a.s19": _s19()}, manifest={"schema_version": 1, "active_variant": "a"})
    folder = _wa(base) / "E"
    key = os.path.normcase(str(folder))

    def raise_for(folder_arg):
        if os.path.normcase(os.fspath(folder_arg)) == key:
            raise PermissionError(13, "injected: access denied", os.fspath(folder_arg))

    if arm == "listing":
        real = app_module.S19TuiApp._list_project_files

        def listing(self, folder_arg, *a, **k):
            raise_for(folder_arg)
            return real(self, folder_arg, *a, **k)

        monkeypatch.setattr(app_module.S19TuiApp, "_list_project_files", listing)
    else:

        def manifest(*args, **kwargs):
            raise PermissionError(13, "injected: access denied", "project.json")

        monkeypatch.setattr(app_module, "read_project_manifest", manifest)

    async def scenario(app, pilot, log):
        lines = await _preview_of_project(pilot, app, "E")
        return lines, ld.is_load_dialog(app.screen)

    lines, open_ = _run(base, scenario)
    text = _flat(" ".join(lines))
    assert "could not be read" in text and READ_STEP in text, lines
    assert marked(lines) == [], lines
    assert open_


def _imported_names(tree: ast.Module, prefixes: tuple) -> set:
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = ("." * node.level) + (node.module or "")
            if module.startswith(prefixes) or module.lstrip(".").startswith(("services", "workspace")):
                for alias in node.names:
                    names.add(alias.asname or alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in ("os", "pathlib"):
                    names.add((alias.asname or alias.name).split(".")[0])
    return names


#: ``screens.py``'s imported modules at the base revision ``8947666``
#: (read by AST in the E4 run): LLR-173.6l allows 0 new ones.
SCREENS_MODULES_AT_BASE = frozenset({
    "..render.hexview", "..utils", ".capped_text_area", ".changes.verify", ".color_policy",
    ".insight_style", ".legend", ".models", ".open_folder_chip", ".operations.crc",
    ".operations.crc_config", ".operations.model", ".os_clipboard_input", ".services",
    ".services.entropy_service", ".services.flow_persistence_service", ".services.report_addendum",
    ".services.report_service", ".services.variant_execution_service", ".window_help", ".workspace",
    "__future__", "dataclasses", "logging", "markdown_it", "pathlib", "rich.markup", "rich.table",
    "rich.text", "textual", "textual.app", "textual.binding", "textual.containers",
    "textual.message", "textual.screen", "textual.widget", "textual.widgets", "tkinter", "typing",
})


def test_tc_b100_64_the_dialog_reads_nothing_itself() -> None:
    """LLR-173.6l (S2-6, 2 of 2): an AST census of the ``LoadDialog`` class
    body → 0 references to names imported from ``s19_app.tui.services``,
    ``s19_app.tui.workspace``, ``os`` or ``pathlib`` (``Path`` included);
    and ``screens.py``'s set of imported modules gains 0 modules over the
    base.

    Why: the dialog gets its rows, previews and verdicts only from the app,
    so the filesystem rules live in one place.
    Negative control: the dialog calling ``list_workarea_files`` itself →
    census 1 and 1 new import → RED. RED (base): no ``LoadDialog`` class."""
    source = (ROOT / "s19_app" / "tui" / "screens.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            modules.add(("." * node.level) + (node.module or ""))
    classes = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "LoadDialog"]
    assert len(classes) == 1, "screens.py defines no LoadDialog class"
    forbidden = _imported_names(tree, (".services", ".workspace", "s19_app.tui.services", "s19_app.tui.workspace"))
    forbidden |= {"Path", "PurePath", "PureWindowsPath", "os", "pathlib"}
    used = set()
    for node in ast.walk(classes[0]):
        if isinstance(node, ast.Name) and node.id in forbidden:
            used.add(node.id)
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id in forbidden:
            used.add(node.value.id)
    assert used == set(), used
    assert modules - SCREENS_MODULES_AT_BASE == set(), modules - SCREENS_MODULES_AT_BASE


def _regions(screen) -> tuple:
    lst = screen.query_one("#load_list").region
    pre = screen.query_one("#load_preview").region
    return lst, pre


@pytest.mark.parametrize("width,stacked", [(99, True), (100, False), (118, False)])
def test_tc_b100_64_panes_stack_below_100_columns(tmp_path: Path, width: int, stacked: bool) -> None:
    """LLR-173.6m (S9-1, S9-2; 3 of 3): at 99 columns the preview's region
    starts below the list's (``preview.y >= list.y + list.height``); at 100
    and 118 it starts right of the list (``preview.x >= list.x +
    list.width``).

    Negative control: the break set at 118 → 100 columns stacks → RED. RED
    (base): no ``#load_list`` / ``#load_preview``."""

    async def scenario(app, pilot, log):
        await _open(pilot, app, "l")
        return _regions(app.screen)

    lst, pre = _run(tmp_path / "app", scenario, size=(width, 54))
    if stacked:
        assert pre.y >= lst.y + lst.height, (lst, pre)
    else:
        assert pre.x >= lst.x + lst.width, (lst, pre)


def test_tc_b100_64_panes_restack_on_a_live_resize(tmp_path: Path) -> None:
    """LLR-173.6m (S9-3, 1 of 1): open at 118×54, resize to 99×54 with the
    dialog open → stacked.

    RED (base): no ``#load_list`` / ``#load_preview``."""

    async def scenario(app, pilot, log):
        await _open(pilot, app, "l")
        side = _regions(app.screen)
        await pilot.resize_terminal(99, 54)
        await _settle(pilot, 10)
        return side, _regions(app.screen)

    (lst0, pre0), (lst1, pre1) = _run(tmp_path / "app", scenario)
    assert pre0.x >= lst0.x + lst0.width, (lst0, pre0)
    assert pre1.y >= lst1.y + lst1.height, (lst1, pre1)


@pytest.mark.parametrize("width", [99, 100, 118])
def test_tc_b100_64_list_rows_never_wrap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, width: int) -> None:
    """LLR-173.6n (C4-1, 9 of 9: 3 rows × 3 widths): a 120-character project
    name, a 130-character file name and a 300-character recorded path → at
    99, 100 and 118 columns every ``#load_list`` row is one line (the list's
    content height equals its option count).

    Negative control: wrapping allowed → the 130-character row is 2 lines
    at 99 columns → RED. RED (base): no ``#load_list``."""
    lad = _lad(tmp_path, monkeypatch)
    _store_on_any_host(lad, monkeypatch)
    _seed_store(lad, ["C:\\" + "\\".join(["r" * 50] * 5) + "\\" + "q" * 40 + ".s19"])
    base = tmp_path / "b"
    _make_or_skip(_wa(base) / ("P" * 120) / "a.s19", _s19())
    _make_or_skip(_temp(base) / ("f" * 126 + ".s19"), _s19())

    async def scenario(app, pilot, log):
        from textual.widgets import OptionList

        await _open(pilot, app, "l")
        lst = app.screen.query_one("#load_list", OptionList)
        return lst.virtual_size.height, lst.option_count, ld.option_prompts(app.screen)

    height, count, prompts = _run(base, scenario, size=(width, 54))
    assert count == 6, prompts
    assert height == count, (height, count)


def test_tc_b100_64_preview_line_never_wraps(tmp_path: Path) -> None:
    """S9b-8 (S8-9, C4-5): a preview line of 300 characters → one painted
    line (nowrap with an ellipsis), so a continuation line can never start
    with ``●``.

    Negative control: preview lines that wrap → the line paints 2+ rows →
    RED. RED (base): no ``LoadDialog``."""
    fakes = Fakes(preview=lambda choice: [("r" * 300, False)])

    async def scenario(app, pilot, results, fakes):
        statics = _statics(app.screen, "#load_preview")
        return [w.size.height for w in statics], [_plain(w) for w in statics]

    heights, texts = dialog_scene(tmp_path, scenario, fakes=fakes)
    assert texts == ["r" * 300], texts
    assert heights == [1], heights


def test_tc_b100_64_linked_file_in_a_project_is_neither_listed_nor_installed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-173.4n (B101, R2-N2, R3-3; 1 of 1): project ``P`` holding
    ``a.s19`` and a symbolic link ``b.s19`` (to a regular S19 outside), with
    ``active_variant`` ``b`` → the preview lists 1 variant (``a.s19``) with
    1 ``●``; after ``enter`` the image installed is ``a.s19``, and the link
    target is opened 0 times. Skipped where ``os.symlink`` raises.

    Why: a link in a project folder can point anywhere; following it would
    load a file outside the project the mark never named.
    Negative control: a lister that follows links → 2 variant rows → RED.
    RED (base): no preview."""
    base = tmp_path / "app"
    folder = _project(base, "P", {"a.s19": _s19()}, manifest={"schema_version": 1, "active_variant": "b"})
    outside = tmp_path / "outside" / "real.s19"
    outside.parent.mkdir()
    outside.write_bytes(_s19_other())
    _symlink_or_skip(folder / "b.s19", outside)
    key = os.path.normcase(str(outside))
    opened: list = []
    real_open = builtins.open
    real_os_open = os.open

    def spy_open(file, *a, **k):
        if not isinstance(file, int) and os.path.normcase(os.path.realpath(os.fspath(file))) == key:
            opened.append(os.fspath(file))
        return real_open(file, *a, **k)

    def spy_os_open(path, *a, **k):
        if os.path.normcase(os.path.realpath(os.fspath(path))) == key:
            opened.append(os.fspath(path))
        return real_os_open(path, *a, **k)

    async def scenario(app, pilot, log):
        monkeypatch.setattr(builtins, "open", spy_open)
        monkeypatch.setattr(os, "open", spy_os_open)
        lines = await _preview_of_project(pilot, app, "P")
        _, names = await _enter_and_read_panel(pilot, app)
        monkeypatch.undo()
        return lines, names, Path(app.current_file.path).name if app.current_file else None

    lines, names, image = _run(base, scenario)
    variants = [line for line in lines if ".s19" in line]
    assert len(variants) == 1 and "a.s19" in variants[0], lines
    assert marked_names(lines) == ["a.s19"], lines
    assert image == "a.s19", (image, names)
    assert opened == [], opened


def _manifest_link_or_skip(folder: Path, tmp_path: Path) -> Path:
    """``folder/project.json`` made a non-regular file: a FIFO off Windows, a
    symbolic link to a real manifest on Windows (S9b-2). Returns the path
    whose opening the test counts."""
    if hasattr(os, "mkfifo") and not WIN:
        os.mkfifo(folder / "project.json")
        return folder / "project.json"
    real = tmp_path / "real_manifest" / "project.json"
    real.parent.mkdir(parents=True, exist_ok=True)
    real.write_text('{"schema_version": 1, "active_variant": "a"}', encoding="utf-8")
    _symlink_or_skip(folder / "project.json", real)
    return real


def test_tc_b100_64_project_json_that_is_not_a_regular_file_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """S9b-2, R2-N5, R3-1 (B98, B99): a listed project whose ``project.json``
    is a link (a FIFO off Windows) → highlighted, the preview paints ``could
    not be read`` and every mark is ``False`` (0 ``●``), with 0 opens of the
    link's target; ``enter`` → 1 status line holding ``could not be read``,
    0 opens, the session unchanged, the app running.

    Why: a link or a FIFO named ``project.json`` can block the event loop or
    read a file outside the project before the engineer chose to load.
    Negative control: the manifest read with no regular-file check → the
    target is opened → RED; the gate moved after the session reset → the
    preloaded image is dropped, the digest changes → RED (E5, M78). RED
    (base): no preview."""
    base = tmp_path / "app"
    folder = _project(base, "L", {"a.s19": _s19()})
    target = _manifest_link_or_skip(folder, tmp_path)
    key = os.path.normcase(str(target))
    opened: list = []
    real_open = builtins.open

    def spy_open(file, *a, **k):
        if not isinstance(file, int) and os.path.normcase(os.path.realpath(os.fspath(file))) == key:
            opened.append(os.fspath(file))
        return real_open(file, *a, **k)

    preload = tmp_path / "src" / "fw.s19"
    preload.parent.mkdir()
    preload.write_bytes(_s19())

    async def scenario(app, pilot, log):
        # E5, M78: a loaded image, so a reset before the refusal shows.
        await projects.load_image(pilot, app, preload)
        monkeypatch.setattr(builtins, "open", spy_open)
        lines = await _preview_of_project(pilot, app, "L")
        preview_opens = list(opened)
        before = _digest(app)
        mark = len(log.messages)
        await pilot.press("enter")
        await ld.wait_for_dialog_closed(pilot, app)
        await ld.wait_for(pilot, lambda: _status_lines(log, mark, "could not be read"), "the refusal line")
        await _settle(pilot, 10)
        monkeypatch.undo()
        return lines, preview_opens, list(opened), before, _digest(app), _status_lines(log, mark, "could not be read")

    lines, preview_opens, opens, before, after, status = _run(base, scenario)
    assert "could not be read" in _flat(" ".join(lines)), lines
    assert marked(lines) == [], lines
    assert preview_opens == [] and opens == [], (preview_opens, opens)
    assert len(status) == 1, status
    assert after == before


def _reparse_names(monkeypatch: pytest.MonkeyPatch, *names: str) -> None:
    """Make ``_is_reparse_point`` report True for files called ``names``
    (a stand-in for a reparse point that ``lstat`` reports as a regular
    file, such as a cloud placeholder, which a test host cannot create)."""
    real = app_module._is_reparse_point
    folded = {name.casefold() for name in names}

    def fake(path) -> bool:
        return Path(path).name.casefold() in folded or real(path)

    monkeypatch.setattr(app_module, "_is_reparse_point", fake)


def test_tc_b100_64_project_json_that_is_a_reparse_point_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SEC9b-2: a listed project whose ``project.json`` is a regular file to
    ``lstat`` but a reparse point to ``_is_reparse_point`` (a cloud
    placeholder) → the preview paints ``could not be read`` with 0 marks and
    0 opens of ``project.json``; ``enter`` → 1 status line holding ``could
    not be read``, 0 opens, the session unchanged.

    Why: opening a placeholder hydrates it over the network on the event
    loop; the gate must use the same test as ``_folder_holds_project``.
    Negative control: a gate on ``S_ISREG`` alone → the manifest is opened
    → RED. RED (base): the base gate tests ``S_ISREG`` only."""
    base = tmp_path / "app"
    folder = _project(
        base, "L", {"a.s19": _s19()}, manifest={"schema_version": 1, "active_variant": "a"}
    )
    key = os.path.normcase(str(folder / "project.json"))
    opened: list = []
    real_open = builtins.open

    def spy_open(file, *a, **k):
        if not isinstance(file, int) and os.path.normcase(os.path.realpath(os.fspath(file))) == key:
            opened.append(os.fspath(file))
        return real_open(file, *a, **k)

    preload = tmp_path / "src" / "fw.s19"
    preload.parent.mkdir()
    preload.write_bytes(_s19())

    async def scenario(app, pilot, log):
        await projects.load_image(pilot, app, preload)
        _reparse_names(monkeypatch, "project.json")
        monkeypatch.setattr(builtins, "open", spy_open)
        lines = await _preview_of_project(pilot, app, "L")
        preview_opens = list(opened)
        before = _digest(app)
        mark = len(log.messages)
        await pilot.press("enter")
        await ld.wait_for_dialog_closed(pilot, app)
        await ld.wait_for(pilot, lambda: _status_lines(log, mark, "could not be read"), "the refusal line")
        await _settle(pilot, 10)
        monkeypatch.undo()
        return lines, preview_opens, list(opened), before, _digest(app), _status_lines(log, mark, "could not be read")

    lines, preview_opens, opens, before, after, status = _run(base, scenario)
    assert "could not be read" in _flat(" ".join(lines)), lines
    assert marked(lines) == [], lines
    assert preview_opens == [] and opens == [], (preview_opens, opens)
    assert len(status) == 1, status
    assert after == before


def test_tc_b100_64_reparse_file_in_a_project_is_neither_listed_nor_installed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SEC9b-3 (LLR-173.4n covers every reparse point): project ``P``
    holding ``a.s19`` and ``b.s19``, where ``b.s19`` is a regular file to
    ``DirEntry.is_file(follow_symlinks=False)`` but a reparse point to
    ``_is_reparse_point`` (a WSL link or a cloud placeholder), with
    ``active_variant`` ``b`` → the preview lists 1 variant (``a.s19``) with
    1 ``●``; after ``enter`` the image installed is ``a.s19``.

    Why: on Windows ``is_file(follow_symlinks=False)`` is False only for a
    true symlink; any other reparse file would be listed, marked and opened
    at Enter.
    Negative control: the lister without the ``_is_reparse_point`` test → 2
    variant rows, ``b.s19`` marked → RED. RED (base): 2 variant rows."""
    base = tmp_path / "app"
    _project(
        base,
        "P",
        {"a.s19": _s19(), "b.s19": _s19_other()},
        manifest={"schema_version": 1, "active_variant": "b"},
    )

    async def scenario(app, pilot, log):
        _reparse_names(monkeypatch, "b.s19")
        lines = await _preview_of_project(pilot, app, "P")
        _, names = await _enter_and_read_panel(pilot, app)
        monkeypatch.undo()
        return lines, names, Path(app.current_file.path).name if app.current_file else None

    lines, names, image = _run(base, scenario)
    variants = [line for line in lines if ".s19" in line]
    assert len(variants) == 1 and "a.s19" in variants[0], lines
    assert marked_names(lines) == ["a.s19"], lines
    assert image == "a.s19", (image, names)


@pytest.mark.parametrize("kind", ["MAC", "A2L"])
def test_tc_b100_64_more_than_one_mac_marks_nothing(tmp_path: Path, kind: str) -> None:
    """A9b-R2-3, A9b-R3-5 (B78; the A2L arm added at E5, M85): project
    ``mm`` with ``a.s19`` and two MAC files (``m1.mac``, ``m2.mac``), or
    two A2L files (``c1.a2l``, ``c2.a2l``) → the preview marks nothing (0
    ``●``); after ``enter`` a status line names the refusal (``MAC`` /
    ``A2L``), no Load-result panel opens, and the session is unchanged.

    Why: the install refuses a project with two MAC or two A2L files; a mark
    would promise an install that will not happen.
    Negative control: marks computed without the cardinality rule → ``●
    a.s19`` / ``● m1.mac`` → RED; the more-than-one-A2L arm deleted → ``●
    a.s19`` / ``● c1.a2l`` → RED (M85). RED (base): no preview."""
    base = tmp_path / "app"
    if kind == "MAC":
        files = {"a.s19": _s19(), "m1.mac": _mac(), "m2.mac": _mac()}
    else:
        files = {"a.s19": _s19(), "c1.a2l": _a2l(), "c2.a2l": _a2l()}
    _project(base, "mm", files)

    async def scenario(app, pilot, log):
        lines = await _preview_of_project(pilot, app, "mm")
        before = _digest(app)
        mark = len(log.messages)
        await pilot.press("enter")
        await ld.wait_for_dialog_closed(pilot, app)
        await ld.wait_for(pilot, lambda: len(log.since(mark)) > 0, "the refusal line")
        await _settle(pilot, 20)
        panel = len(app.screen.query("#result_ok"))
        return lines, before, _digest(app), log.since(mark), panel

    lines, before, after, messages, panel = _run(base, scenario)
    assert marked(lines) == [], lines
    assert any(kind in m for m in messages), messages
    assert panel == 0, messages
    assert after == before


# ===========================================================================
# TC-B100-66 — no decision id in the painted text (LLR-173.7)
# ===========================================================================


@STORE_WRITE
def test_tc_b100_66_painted_text_carries_no_decision_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-173.7 (B47, S2-3; the Inc 9b share): the Load dialog painted in 6
    scenarios — a project, a work-area file and a recent row highlighted, an
    empty Load, a refused typed path, a store problem — and the Load-result
    panel of a project load → 0 matches of ``\\bD\\d+\\b``, ``\\bO-\\d+``,
    ``VS-``, ``LLR-``, ``HLR-`` in any painted line.

    Why: internal decision ids mean nothing to the engineer (the prototypes
    painted "D10: click loads OFF").
    RED (base): no Load dialog to scan (the scan needs ``#load_list``)."""
    lad = _lad(tmp_path, monkeypatch)
    src = tmp_path / "src"
    src.mkdir()
    (src / "fw.s19").write_bytes(_s19())
    _seed_store(lad, [str(src / "fw.s19")])
    base = tmp_path / "app"
    _project(base, "ab", {"a.s19": _s19()})
    (_temp(base) / "w.s19").write_bytes(_s19())

    def painted(screen) -> list:
        lines = []
        for widget in screen.query("*"):
            if widget.size.height <= 0 or not hasattr(widget, "render_line"):
                continue
            try:
                lines.extend(projects.painted_lines(widget))
            except Exception:  # noqa: BLE001 — a container has no own strips
                continue
        return lines

    async def scenario(app, pilot, log):
        texts = []
        await _home(pilot)
        await _open(pilot, app, "p")
        for heading in ld.HEADINGS:
            await _highlight_index(pilot, app, _section_index(app.screen, heading))
            await _settle(pilot)
            texts += painted(app.screen)
        await pilot.press("escape")
        await ld.wait_for_dialog_closed(pilot, app)
        await _open(pilot, app, "l")
        await pilot.press("enter")
        await _settle(pilot)
        texts += painted(app.screen)
        await ld.type_into_path(pilot, app, str(tmp_path / "missing.s19"))
        await pilot.press("enter")
        await _settle(pilot)
        texts += painted(app.screen)
        await pilot.press("escape")
        await ld.wait_for_dialog_closed(pilot, app)
        _store(lad).write_bytes(b" " * 65_537)
        await _open(pilot, app, "l")
        texts += painted(app.screen)
        await pilot.press("escape")
        await ld.wait_for_dialog_closed(pilot, app)
        await ld.open_project_through_dialog(pilot, app, "ab", confirm="enter")
        await projects.read_load_result_panel(pilot, app)
        texts += painted(app.screen)
        return texts

    texts = _run(base, scenario)
    assert any("nothing selected" in t for t in texts), "the empty-Load scenario was not painted"
    assert [t for t in texts if DECISION_ID.search(t)] == []


#: Example A12-27's wider scan for the progress strings (every internal id
#: family of the batch, not only the LLR-173.7 five).
PROGRESS_ID = re.compile(r"\bD\d+\b|\bO-\d+|VS-|LLR-|HLR-|US-|AT-|TC-|LED|UX-|\bCR\d|\bSEC\d")
#: A painted progress line starts with one of the ten spinner frames.
LINE_START = re.compile("^[⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏] ")


def test_tc_b100_66_progress_lines_carry_no_decision_id(tmp_path: Path) -> None:
    """LLR-173.7 (Inc 12a extension; A12-27, X-5): each of the 7 long
    actions begun through its table row (with the name ``x.s19``) and
    stepped through every step paints 19 progress lines (7 labels, 19 step
    names; A12-27's "18" is an arithmetic slip, E4 integration SR-12a-1),
    and each failure end writes ``<label> failed`` (7 log lines) → 0
    matches of a decision id in any of the 26 texts.

    Why: internal ids mean nothing to the engineer; the progress line is the
    most-read text while an action runs.
    RED (base): no action table and no progress seam."""
    base = tmp_path / "app"

    async def scenario(app, pilot, log):
        painted = []
        mark = len(log.messages)
        for key, row in app_module._BUSY_ACTIONS.items():
            gen = app._busy_begin_action(key, "x.s19")
            painted.append(str(app.query_one("#status_text").render()))
            for n in range(2, len(row.steps) + 1):
                app.step_busy(key, gen, n)
                painted.append(str(app.query_one("#status_text").render()))
            app._busy_fail(key, gen)
        await _settle(pilot, 2)
        return painted, log.since(mark)

    painted, failed = _run(base, scenario)
    assert len(painted) == 19, painted
    assert all(LINE_START.match(t) for t in painted), painted
    assert len(failed) == 7 and all(line.endswith(" failed") for line in failed), failed
    assert [t for t in painted + failed if PROGRESS_ID.search(t)] == []


def test_tc_b100_66_pick_refusal_tokens_carry_no_decision_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-173.7 (Inc 12a extension; B12-36, §D.2): the two new Workarea
    Files pick refusals — an entry that is no longer a regular file, and a
    file over the copy cap — each paint one line holding their token pair
    verbatim (``not a regular file`` + ``pick another file``; ``too large to
    open`` + the name + ``load a smaller file``) and 0 decision ids.

    Why: new refusal sentences enter the same painted surface the scan
    guards. RED (base): neither refusal exists (the pick parses)."""
    base = tmp_path / "app"
    temp = _temp(base)
    (temp / "fw.s19").mkdir()
    (temp / "big.s19").write_bytes(b"S" * 1025)
    monkeypatch.setattr(app_module.workspace, "DEFAULT_COPY_SIZE_CAP_BYTES", 1024)

    async def scenario(app, pilot, log):
        mark = len(log.messages)
        app._load_workarea_file("fw.s19")
        await _settle(pilot)
        app._load_workarea_file("big.s19")
        await _settle(pilot)
        return log.since(mark)

    lines = _run(base, scenario)
    regular = [m for m in lines if "not a regular file" in m and "pick another file" in m]
    large = [m for m in lines if "too large to open" in m and "big.s19" in m and "load a smaller file" in m]
    assert len(regular) == 1 and len(large) == 1, lines
    assert [t for t in lines if PROGRESS_ID.search(t)] == []


# ===========================================================================
# AT-B100-14 — black-box: keys and the dialog's widget ids
# ===========================================================================


@STORE_WRITE
def test_at_b100_14_one_load_dialog_from_record_to_reopen(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """HLR-173, HLR-173a, HLR-173b, HLR-173c, HLR-173d, HLR-173e — one chain
    at 118×54, driven only by keys, clicks and the dialog's widget ids, in a
    scratch work area with ``LOCALAPPDATA`` at a scratch folder:

    1. (record) ``l``, type the absolute path of
       ``examples/case_01_basic_valid/firmware.s19``, ``enter`` → loaded.
    2. (restart) a new app instance on the same work area and store; ``l``
       → the Recent section holds ``firmware.s19``; ``tab`` into the list,
       arrows to that recent row, ``enter`` → the file loads: the work copy
       holds the example's bytes, and the store's first entry is that path
       (HLR-173b, HLR-173c).
    3. (list half) ``p`` → the Projects section lists ``[b]P`` exactly as
       written and the save-back project ``sb`` (HLR-173).
    4. (preview half) highlight ``sb`` (its recorded active variant ``b`` is
       not first by name) → ``●`` on ``b.s19``, ``m.mac`` and ``c.a2l``;
       ``enter`` → the Loaded panel names exactly those three (HLR-173a).
    5. (escape half) ``l``, ``escape`` → the dialog closes and the session
       digest is unchanged (HLR-173e).
    6. (empty half) ``l``, ``enter`` with nothing typed → ``#load_reason``
       paints ``nothing selected`` and ``pick a row or type a path``, and the
       dialog stays (HLR-173d).

    RED (base, executed P-18 … P-20): the base Load dialog has no list, no
    preview, ignores ``escape`` and says nothing on an empty Load."""
    lad = _lad(tmp_path, monkeypatch)
    example = (CASE01_DIR / "firmware.s19").resolve()
    base = tmp_path / "work"
    _project(base, "[b]P", {"a.s19": _s19()})
    _project(
        base,
        "sb",
        {"a.s19": _s19_other(), "b.s19": _s19(), "m.mac": _mac(), "c.a2l": _a2l()},
        manifest={"schema_version": 1, "active_variant": "b"},
    )

    async def record(app, pilot, log):
        await _home(pilot)
        await ld.load_path_through_dialog(
            pilot, app, str(example), confirm="enter",
            until=lambda: app.current_file is not None, what="the recorded load",
        )
        await _settle(pilot, 10)
        return Path(app.current_file.path).name

    assert _run(base, record) == "firmware.s19"
    doc = json.loads(_store(lad).read_text(encoding="utf-8"))
    assert doc["sources"][0]["path"] == str(example), doc

    async def reopen(app, pilot, log):
        out = {}
        await _home(pilot)
        # 2. the recent reopens
        await _open(pilot, app, "l")
        recents = ld.section_prompts(app.screen, "Recent")
        out["recent rows"] = recents
        await pilot.press("tab")
        await pilot.pause()
        await _highlight_index(pilot, app, _section_index(app.screen, "Recent"))
        await pilot.press("enter")
        await ld.wait_for_dialog_closed(pilot, app)
        await ld.wait_for(pilot, lambda: app.current_file is not None, "the recent load")
        await _settle(pilot, 10)
        out["recent bytes"] = Path(app.current_file.path).read_bytes()
        # 3. + 4. the list and the preview
        await _home(pilot)
        await _open(pilot, app, "p")
        out["projects"] = ld.section_prompts(app.screen, "Projects")
        out["painted"] = projects.painted_lines(app.screen.query_one("#load_list"))
        await ld.highlight_row(pilot, app, "sb")
        await _settle(pilot)
        out["marks"] = marked_names(preview_lines(app.screen))
        await pilot.press("enter")
        await ld.wait_for_dialog_closed(pilot, app)
        await _wait_panel_and_close(pilot, app)
        out["panel"] = panel_names(app)
        # 5. escape changes nothing
        await _home(pilot)
        before = _digest(app)
        await _open(pilot, app, "l")
        await pilot.press("escape")
        await _settle(pilot, 8)
        out["escape"] = (ld.is_load_dialog(app.screen), _digest(app) == before)
        # 6. the empty Load
        await _open(pilot, app, "l")
        await pilot.press("enter")
        await _settle(pilot)
        out["empty"] = (ld.is_load_dialog(app.screen), reason_text(app.screen))
        return out

    out = _run(base, reopen)
    assert len(out["recent rows"]) == 1 and out["recent rows"][0].startswith("firmware.s19"), out["recent rows"]
    assert out["recent bytes"] == example.read_bytes()
    doc = json.loads(_store(lad).read_text(encoding="utf-8"))
    assert doc["sources"][0]["path"] == str(example), doc
    assert out["projects"] == ["[b]P", "sb"], out["projects"]
    assert any("[b]P" in line for line in out["painted"]), out["painted"]
    assert out["marks"] == ["b.s19", "c.a2l", "m.mac"], out["marks"]
    assert out["panel"] == out["marks"], (out["panel"], out["marks"])
    assert out["escape"] == (False, True), out["escape"]
    is_open, reason = out["empty"]
    assert is_open and NOTHING[0] in reason and NOTHING[1] in reason, out["empty"]
