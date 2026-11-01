"""Batch-100 increment 9a — recent sources remembered per user, a typed
project path opens the project, and work-area file names render literally
(HLR-172, HLR-172a, HLR-172b).

Covers (E4 test design, written from the approved Code-Wire examples of
``inc-9a/codewire/proto-9a-workspace.md`` / ``proto-9a-app.md``, the
interfaces and rulings of ``inc-9a/codewire/interfaces-9a.md`` ("Applied
after E3 r1"), ``inc-9a/E3-rulings.md`` R1–R17 and the thresholds and
negative controls of ``01-requirements.md``, independently of the
implementation):

  - TC-B100-34 — LLR-172.1, .1a … .1m (the per-user store write).
  - TC-B100-35 — LLR-172.2, .2a … .2j (the store read).
  - TC-B100-36 — LLR-172.3 (no recent path in any file under the base).
  - TC-B100-37 — LLR-172.4, .4a, .4b, .4c (one temp-folder lister).
  - TC-B100-38 — LLR-172.5, .5a … .5h (the typed route; R14's
    ``list_projects`` arm).
  - TC-B100-39 — LLR-172.6, .6a (literal Workarea Files rows).
  - AT-B100-12, AT-B100-13 — black-box through keys and dialogs at 118 and
    220 columns.

New Inc 9a symbols are imported inside their node, so every node runs and
fails on its own (assertion or ImportError of the new symbol) at the base.

Platform (E3 R12, P9a-G1-6): LLR-172.1f turns the store off unless
``LOCALAPPDATA`` is a drive letter followed by a root, so every store WRITE
arm runs on Windows only and skips elsewhere with a named reason (reported
not run, never passed). The store READ arms run everywhere: off Windows the
store location is pinned by patching ``recent_store_path`` to a temporary
file (the entry checks are text checks, host-independent). Case-spelling,
Win32-name, junction and 8.3 arms are Windows only, each with its reason.

Oracles: store bytes with ``json`` / ``hashlib``; expected row labels from
``unicodedata`` per LLR-172.6's wording; status oracles read the full
``set_status`` message (``StatusLog``); the temp-enumeration census is an
``ast`` walk of ``s19_app/``.
"""
from __future__ import annotations

import ast
import asyncio
import builtins
import hashlib
import io
import json
import logging
import os
import pathlib
import random
import shutil
import sys
import tempfile
import unicodedata
from contextlib import contextmanager
from pathlib import Path

import pytest

import s19_app.tui.app as app_module
import s19_app.tui.workspace as workspace_module
from s19_app.tui.workspace import WORKAREA_DIRNAME
from s19_app.tui.workspace import WORKAREA_SUBDIR

from tests.support import b100_links
from tests.support import b100_projects as projects
from tests.support.b100_projects import LOAD_RESULT_CLOSE
from tests.support.b100_workers import settle_workers

AT_SIZES = [(118, 54), (220, 60)]
WIN = sys.platform == "win32"

#: Store write arms (E3 R12, P9a-G1-6): a POSIX ``LOCALAPPDATA`` turns the
#: store off by requirement (LLR-172.1f), so these arms cannot run off
#: Windows.
STORE_WRITE = pytest.mark.skipif(
    not WIN,
    reason="store write arm: LLR-172.1f needs a drive-rooted LOCALAPPDATA; Windows only (E3 R12, P9a-G1-6)",
)
CASE_ARM = pytest.mark.skipif(
    not WIN, reason="case-insensitive file system arm; Windows only (E3 R12)"
)
WIN32_NAME_ARM = pytest.mark.skipif(
    not WIN, reason="Win32 name rule arm (stream / 8.3 / trailing dot or space); Windows only (E3 R12)"
)
JUNCTION_ARM = pytest.mark.skipif(
    not WIN, reason="directory junctions are a Windows-only test arm (PDR C-QA-6)"
)
ROOT_RELATIVE_ARM = pytest.mark.skipif(
    not WIN, reason="Win32 root-relative path arm; Windows only (E3 R12)"
)

STORE_DIRNAME = "s19_app"
STORE_FILENAME = "recent_sources.json"
STORE_CAP = 65_536
UNREADABLE = "could not be read"
TOO_LARGE = "too large"


# ---------------------------------------------------------------------------
# helpers — store fixtures and oracles (stdlib only)
# ---------------------------------------------------------------------------


def _workarea(base: Path) -> Path:
    return base / WORKAREA_DIRNAME / WORKAREA_SUBDIR


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _with(messages: list, *tokens: str) -> list:
    """The messages that hold every token."""
    return [m for m in messages if all(token in m for token in tokens)]


def _lad(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str = "lad") -> Path:
    """A fresh, existing ``LOCALAPPDATA`` folder for this test (C8: always
    derived from ``tmp_path``, never a literal drive path)."""
    lad = tmp_path / name
    lad.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("LOCALAPPDATA", str(lad))
    return lad


def _store_of(lad: Path) -> Path:
    """LLR-172.1: ``%LOCALAPPDATA%\\s19_app\\recent_sources.json``."""
    return lad / STORE_DIRNAME / STORE_FILENAME


def _encode(sources: list) -> bytes:
    """A store document in the form LLR-172.1m's note names (compact,
    ``ensure_ascii``), written by the test — never by the code under test."""
    doc = {"schema_version": 1, "sources": sources}
    return json.dumps(doc, ensure_ascii=True, separators=(",", ":")).encode("ascii")


def _seed(store: Path, sources: list) -> str:
    store.parent.mkdir(parents=True, exist_ok=True)
    store.write_bytes(_encode(sources))
    return _sha(store)


def _entry(path, kind: str = "s19") -> dict:
    return {"path": str(path), "kind": kind}


def _entries(store: Path) -> list:
    """(path, kind) pairs of the store on disk, read with ``json``; [] when
    the store file does not exist."""
    if not store.exists():
        return []
    doc = json.loads(store.read_bytes().decode("utf-8"))
    assert doc.get("schema_version") == 1, doc
    return [(item["path"], item["kind"]) for item in doc["sources"]]


def _leftovers(store: Path) -> list:
    """Every name in the store folder other than the store itself (a staging
    file left behind shows here)."""
    folder = store.parent
    if not folder.exists():
        return []
    return sorted(p.name for p in folder.iterdir() if p.name != STORE_FILENAME)


def _named_store_files(root: Path) -> list:
    return sorted(str(p) for p in root.rglob(STORE_FILENAME))


def _read_arm_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Where a READ arm puts its store: on Windows the real location under
    a test ``LOCALAPPDATA``; elsewhere the location is pinned by patching
    ``recent_store_path`` (P9a-G1-6: read arms run on every platform). The
    caller has already imported the 9a symbol it tests."""
    lad = _lad(tmp_path, monkeypatch)
    store = _store_of(lad)
    if not WIN:
        monkeypatch.setattr(workspace_module, "recent_store_path", lambda: store)
    return store


def _pairs(result) -> list:
    return [(entry.path, entry.kind) for entry in result.entries]


class _ReadProxy:
    """A file object that records every ``read`` size and can fail a read."""

    def __init__(self, handle, sizes: list, error) -> None:
        self._handle = handle
        self._sizes = sizes
        self._error = error

    def read(self, size=-1):
        self._sizes.append(size)
        if self._error is not None:
            raise self._error
        return self._handle.read(size)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self._handle.close()
        return False

    def __iter__(self):
        return iter(self._handle)

    def __getattr__(self, name):
        return getattr(self._handle, name)


class _OpenSpy:
    """Wraps ``builtins.open`` and ``io.open`` (``Path.open`` goes through
    ``io.open``); acts only on READ opens of ``target`` (or, with
    ``folder``, of anything under it)."""

    def __init__(self, monkeypatch, target: Path, *, folder: bool = False,
                 raise_on_open=None, read_error=None) -> None:
        self.opens: list = []
        self.read_sizes: list = []
        original = io.open
        key = os.path.normcase(os.path.abspath(str(target)))

        def _matches(file) -> bool:
            if isinstance(file, int):
                return False
            try:
                text = os.fspath(file)
            except TypeError:
                return False
            if isinstance(text, bytes):
                text = os.fsdecode(text)
            candidate = os.path.normcase(os.path.abspath(text))
            return candidate == key or (folder and candidate.startswith(key + os.sep))

        def _open(file, mode="r", *args, **kwargs):
            if _matches(file) and not any(flag in str(mode) for flag in "wax+"):
                self.opens.append(str(file))
                if raise_on_open is not None:
                    raise raise_on_open
                return _ReadProxy(original(file, mode, *args, **kwargs), self.read_sizes, read_error)
            return original(file, mode, *args, **kwargs)

        monkeypatch.setattr(builtins, "open", _open)
        monkeypatch.setattr(io, "open", _open)


def _spy_replace(monkeypatch: pytest.MonkeyPatch, fail_onto=None) -> list:
    """Every ``os.replace`` (``Path.replace`` calls it) as (src, dst); when
    ``fail_onto`` is given a replace onto it raises ``PermissionError``."""
    calls: list = []
    original = os.replace
    fail_key = None if fail_onto is None else os.path.normcase(os.path.abspath(str(fail_onto)))

    def _replace(src, dst, *args, **kwargs):
        calls.append((os.fsdecode(os.fspath(src)), os.fsdecode(os.fspath(dst))))
        if fail_key is not None and os.path.normcase(os.path.abspath(os.fspath(dst))) == fail_key:
            raise PermissionError(13, "injected: replace refused", os.fspath(dst))
        return original(src, dst, *args, **kwargs)

    monkeypatch.setattr(os, "replace", _replace)
    return calls


def _fail_staging_creation(monkeypatch: pytest.MonkeyPatch) -> None:
    """The staging creation (``mkstemp``, interfaces-9a) raises ``OSError``."""

    def _refuse(*args, **kwargs):
        raise OSError(28, "injected: staging creation refused")

    monkeypatch.setattr(tempfile, "mkstemp", _refuse)
    monkeypatch.setattr(workspace_module, "mkstemp", _refuse, raising=False)


def _fail_staging_open(monkeypatch: pytest.MonkeyPatch) -> None:
    """The staging file is created, then wrapping its descriptor
    (``os.fdopen``) raises ``OSError`` (E5 SEC9-5)."""

    def _refuse(*args, **kwargs):
        raise OSError(24, "injected: staging open refused")

    monkeypatch.setattr(os, "fdopen", _refuse)


class _WarningRecords(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.WARNING)
        self.records: list = []
        self._seen: set = set()

    def emit(self, record) -> None:
        if id(record) not in self._seen:
            self._seen.add(id(record))
            self.records.append(record)


@contextmanager
def _captured_warnings():
    """WARNING-or-above records from the app logger (``s19tui``, which does
    not propagate) and from every propagating logger (root)."""
    handler = _WarningRecords()
    loggers = [logging.getLogger(), logging.getLogger("s19tui")]
    for logger in loggers:
        logger.addHandler(handler)
    try:
        yield handler
    finally:
        for logger in loggers:
            logger.removeHandler(handler)


def _store_lines(messages: list) -> list:
    """Status lines about the store (Q5: a failed store write paints none)."""
    return [m for m in messages if "recent" in m.casefold()]


def _outside(tmp_path: Path, name: str = "firmware.s19", folder: str = "src",
             source: str = "firmware.s19") -> Path:
    """An outside copy of case_01's ``source`` named ``name``."""
    target = tmp_path / folder
    target.mkdir(parents=True, exist_ok=True)
    path = target / name
    shutil.copyfile(projects.CASE01_DIR / source, path)
    return path


def _drive_root(tmp_path: Path) -> str:
    """The drive root of the test's temporary folder (``C:\\``), so a long
    synthetic path never names another volume."""
    return tmp_path.anchor


async def _wait_image(pilot, app, name: str) -> None:
    await projects.wait_for(
        pilot,
        lambda: app.current_file is not None and app.current_file.path.name == name,
        f"the image {name} installed",
    )


async def _wait_a2l(pilot, app) -> None:
    await projects.wait_for(pilot, lambda: app.current_a2l_path is not None, "the A2L attached")


def _digests_outside_logs(base: Path) -> dict:
    """Every regular file under ``base`` except the app log folder."""
    logs = (WORKAREA_DIRNAME + "/logs/").casefold()
    return {
        relative: digest
        for relative, digest in projects.tree_digests(base).items()
        if not relative.casefold().startswith(logs)
    } if base.exists() else {}


def _expected_label(name: str) -> str:
    """LLR-172.6's label: every Cc / Cf / Zl / Zp character removed, an
    unpaired surrogate as U+FFFD, clipped to 120 characters ending in "…"."""
    kept = []
    for char in name:
        category = unicodedata.category(char)
        if category in ("Cc", "Cf", "Zl", "Zp"):
            continue
        kept.append("\ufffd" if category == "Cs" else char)
    text = "".join(kept)
    return text if len(text) <= 120 else text[:119] + "\u2026"


def _row_facts(app) -> list:
    """(plain text, styled spans, item.data) for each ``#files_list`` row, as
    the row's Label paints it."""
    from textual.widgets import Label, ListView

    rows = []
    for item in app.query_one("#files_list", ListView).children:
        visual = item.query_one(Label).render()
        plain = getattr(visual, "plain", str(visual))
        spans = [s for s in getattr(visual, "spans", []) if str(getattr(s, "style", "")).strip()]
        rows.append((plain, spans, getattr(item, "data", None)))
    return rows


def _scrubbed_categories(text: str) -> list:
    return [c for c in text if unicodedata.category(c) in ("Cc", "Cf", "Cs")]


# ---------------------------------------------------------------------------
# a saved project ``ab`` (shipped Save project, LED .42), built once and
# copied per test
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def ab_template(tmp_path_factory) -> Path:
    """A base folder holding project ``ab`` (``project.json`` +
    ``firmware.s19``) saved by the shipped Save project handler. Built with
    ``LOCALAPPDATA`` pointed at a folder that does not exist, so the build
    records nothing anywhere (C8; R7)."""
    root = tmp_path_factory.mktemp("ab_template")
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("LOCALAPPDATA", str(root / "absent-lad"))
        base = root / "app"
        projects.save_case01_project(base, "ab", files=("firmware.s19",))
    return base


def _base_with_ab(tmp_path: Path, template: Path) -> Path:
    base = tmp_path / "app"
    shutil.copytree(template, base, ignore=shutil.ignore_patterns("logs"))
    return base


def _spy_resets(monkeypatch: pytest.MonkeyPatch) -> list:
    calls: list = []
    original = app_module.S19TuiApp._reset_project_session

    def _reset(self, *args, **kwargs):
        calls.append(1)
        return original(self, *args, **kwargs)

    monkeypatch.setattr(app_module.S19TuiApp, "_reset_project_session", _reset)
    return calls


#: Every outcome line a typed load can paint, the base's own texts included,
#: so a RED at the base is read from its line, not from a timed-out wait.
TYPED_OUTCOMES = (
    "Loaded project", "NOT loaded", "not found", "Unsupported", "Cannot load",
    "Project not found", "No supported files", "Project validation", "A2L loaded",
)


async def _close_panel_if_open(pilot, app) -> None:
    if len(app.screen.query(LOAD_RESULT_CLOSE)) > 0:
        await projects.dismiss_load_result_panel(pilot, app)


async def _typed(pilot, app, log, text: str) -> list:
    """Run the shipped typed-path dispatcher (the Load dialog's deferred
    call) for ``text``; wait for an outcome line or a project; close a
    Load-result panel that opened (Q3)."""
    mark = len(log.messages)
    app._load_path_from_user_input(Path(text))
    for _ in range(300):
        if any(token in m for m in log.since(mark) for token in TYPED_OUTCOMES):
            break
        await pilot.pause()
    for _ in range(10):
        await pilot.pause()
    await _close_panel_if_open(pilot, app)
    return log.since(mark)


async def _project_load(pilot, app, log, name: str) -> list:
    mark = len(log.messages)
    app._handle_load_project(name)
    for _ in range(200):
        if any(token in m for m in log.since(mark) for token in TYPED_OUTCOMES):
            break
        await pilot.pause()
    for _ in range(10):
        await pilot.pause()
    return log.since(mark)


def _loaded_ab(messages: list) -> list:
    return _with(messages, "Loaded project", "'ab'")


# ===========================================================================
# TC-B100-34 — the per-user store write
# ===========================================================================


@STORE_WRITE
def test_tc_b100_34_store_lives_under_localappdata(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """LLR-172.1 (and seam S9): ``LOCALAPPDATA`` = ``<tmp>/lad`` →
    ``recent_store_path()`` is ``<tmp>/lad/s19_app/recent_sources.json`` and
    the call creates nothing; 1 outside load → 1 file at that path and 0
    files named ``recent_sources.json`` under the base folder (``.s19tool``
    included); ``LOCALAPPDATA`` changed after import → the next call names
    the new folder (read at call time, never cached).

    RED (base): no ``recent_store_path``; ``grep LOCALAPPDATA s19_app`` → 0
    hits, no store after the load. Negative controls: a store under
    ``<base>/.s19tool`` → the base arm RED; reading ``APPDATA`` → 0 files at
    the ``LOCALAPPDATA`` path → RED; an import-time cache → the S9 arm RED."""
    from s19_app.tui.workspace import recent_store_path

    lad = _lad(tmp_path, monkeypatch)
    assert recent_store_path() == _store_of(lad)
    assert list(lad.iterdir()) == [], "recent_store_path must create nothing"

    base = tmp_path / "app"
    source = _outside(tmp_path)

    async def _scenario(app, pilot, log):
        app._load_path_from_user_input(source)
        await _wait_image(pilot, app, source.name)

    projects.run_app(base, _scenario)
    assert _store_of(lad).is_file(), _named_store_files(tmp_path)
    assert _named_store_files(base) == [], _named_store_files(base)

    lad2 = _lad(tmp_path, monkeypatch, "lad2")
    assert recent_store_path() == _store_of(lad2)


@pytest.mark.parametrize(
    "value",
    ["unset", "empty", "relative", "posix absolute", "drive without root", "UNC"],
)
def test_tc_b100_34_unusable_localappdata_gives_no_store_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    """LLR-172.1f (the text test ``^[A-Za-z]:[\\/]`` on every platform, R5;
    D-1): ``LOCALAPPDATA`` unset, ``""``, ``relative\\lad``, a POSIX
    absolute path, ``C:lad`` (drive, no root) and a UNC path →
    ``recent_store_path()`` is None; 0 files created.

    RED (base): no ``recent_store_path``. Negative control: a relative value
    used as a folder → a path is returned → RED."""
    from s19_app.tui.workspace import recent_store_path

    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    texts = {
        "empty": "",
        "relative": "relative\\lad",
        "posix absolute": "/" + (tmp_path / "posix_lad").relative_to(tmp_path.anchor).as_posix(),
        "drive without root": "C:lad",
        "UNC": "\\\\host\\profiles\\lad",
    }
    if value == "unset":
        monkeypatch.delenv("LOCALAPPDATA", raising=False)
    else:
        monkeypatch.setenv("LOCALAPPDATA", texts[value])
    assert recent_store_path() is None
    assert list(work.iterdir()) == []


@pytest.mark.parametrize(
    "value",
    [
        "unset",
        "empty",
        "relative",
        "posix absolute",
        pytest.param("absent folder", marks=STORE_WRITE),
    ],
)
def test_tc_b100_34_no_usable_localappdata_writes_no_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    """LLR-172.1f (5 arms): ``LOCALAPPDATA`` unset, ``""``, ``relative\\lad``,
    a POSIX absolute path (derived from ``tmp_path``) and ``<tmp>/absent``
    (drive-rooted, no such folder; R7), working folder ``<tmp>/work`` →
    ``record_recent_source`` returns False; an outside load installs the
    image with 0 raises; 0 files named ``recent_sources.json`` and 0
    ``s19_app`` folders anywhere under ``<tmp>``; ``<tmp>/absent`` still
    absent; ``APPDATA`` and the home folder (pointed into ``<tmp>``) hold 0
    files after the load.

    RED (base): no ``record_recent_source``. Negative controls: a relative
    value used as a folder → ``<tmp>/work/relative/lad/s19_app/...`` written
    → RED; a ``Path.home()`` fallback → a file under ``<tmp>/home`` → RED;
    ``mkdir(parents=True)`` → ``<tmp>/absent/s19_app/...`` written → RED;
    an ``APPDATA`` fallback → a file under ``<tmp>/roam`` → RED."""
    from s19_app.tui.workspace import record_recent_source

    work = tmp_path / "work"
    work.mkdir()
    roam = tmp_path / "roam"
    roam.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.chdir(work)
    monkeypatch.setenv("APPDATA", str(roam))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("HOME", str(home))
    texts = {
        "empty": "",
        "relative": "relative\\lad",
        "posix absolute": "/" + (tmp_path / "posix_lad").relative_to(tmp_path.anchor).as_posix(),
        "absent folder": str(tmp_path / "absent"),
    }
    if value == "unset":
        monkeypatch.delenv("LOCALAPPDATA", raising=False)
    else:
        monkeypatch.setenv("LOCALAPPDATA", texts[value])

    source = _outside(tmp_path)
    assert record_recent_source(source) is False
    base = tmp_path / "app"

    async def _scenario(app, pilot, log):
        app._load_path_from_user_input(source)
        await _wait_image(pilot, app, source.name)
        return app.current_file is not None

    assert projects.run_app(base, _scenario) is True
    assert _named_store_files(tmp_path) == [], _named_store_files(tmp_path)
    assert sorted(str(p) for p in tmp_path.rglob(STORE_DIRNAME)) == []
    assert not (tmp_path / "absent").exists()
    assert list(roam.rglob("*")) == [] and list(home.rglob("*")) == []


@pytest.mark.parametrize(
    "path_text, kind",
    [
        ("C:\\x\\a.s19", "s19"),
        ("C:\\x\\a.srec", "s19"),
        ("C:\\x\\a.hex", "hex"),
        ("C:\\x\\a.ihex", "hex"),
        ("C:\\x\\a.mac", "mac"),
        ("C:\\x\\a.a2l", "a2l"),
        ("C:\\t\\A.SREC", "s19"),
        ("C:\\x\\a.exe", None),
        ("C:\\x\\a.s19:ads", None),
        ("C:\\x\\a.s19.", None),
        ("C:\\x\\a.s19 ", None),
        ("C:\\x\\firmware", None),
        ("C:\\x\\x.a2l.json", None),
    ],
)
def test_tc_b100_34_recent_kind_follows_the_loaders_suffix_sets(path_text: str, kind) -> None:
    """LLR-172.1a / LLR-172.2h (ruling C6): the kind follows the suffix,
    case-folded, with the loader's own sets — ``.s19`` / ``.srec`` → s19,
    ``.hex`` / ``.ihex`` → hex, ``.mac`` → mac, ``.a2l`` → a2l, ``A.SREC``
    → s19; a stream suffix, a trailing dot or space, no suffix, ``.exe`` and
    the A2L dump ``.a2l.json`` → no kind (never recorded, dropped on read).

    RED (base): no ``recent_kind``. Negative control: ``.srec`` mapped to
    "srec" → the ``.srec`` and ``A.SREC`` arms RED."""
    from s19_app.tui.workspace import recent_kind

    assert recent_kind(Path(path_text)) == kind


@STORE_WRITE
def test_tc_b100_34_record_puts_newest_first_with_its_kind(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """LLR-172.1a: outside ``.s19``, then ``.a2l``, ``.mac``, ``.hex`` →
    4 entries, newest first, kinds hex, mac, a2l, s19, each path the
    source's absolute path; then ``A.SREC`` → first, kind s19. (The record
    reads no source, so the files need not exist.)

    RED (base): no ``record_recent_source``. Negative control: the entry
    appended last → the order arm RED."""
    from s19_app.tui.workspace import record_recent_source

    store = _store_of(_lad(tmp_path, monkeypatch))
    src = tmp_path / "src"
    sources = [src / "m.s19", src / "m.a2l", src / "m.mac", src / "m.hex"]
    for source in sources:
        assert record_recent_source(source) is True, source
    assert _entries(store) == [
        (str(src / "m.hex"), "hex"),
        (str(src / "m.mac"), "mac"),
        (str(src / "m.a2l"), "a2l"),
        (str(src / "m.s19"), "s19"),
    ]
    assert record_recent_source(tmp_path / "A.SREC") is True
    assert _entries(store)[0] == (str(tmp_path / "A.SREC"), "s19")


@STORE_WRITE
def test_tc_b100_34_record_stores_the_lexical_absolute_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """LLR-172.1a (R1, seam S7): a relative ``firmware.s19`` found in the
    working folder ``<src>`` → the entry path is ``<src>\\firmware.s19``,
    not the typed relative text.

    RED (base): no ``record_recent_source``. Negative control: storing the
    argument's text → ``firmware.s19`` → RED."""
    from s19_app.tui.workspace import record_recent_source

    store = _store_of(_lad(tmp_path, monkeypatch))
    src = _outside(tmp_path).parent
    monkeypatch.chdir(src)
    assert record_recent_source(Path("firmware.s19")) is True
    assert _entries(store) == [(str(src / "firmware.s19"), "s19")]


@STORE_WRITE
@JUNCTION_ARM
def test_tc_b100_34_record_does_not_resolve_a_junction(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """LLR-172.1a (R1): ``<tmp>/j/x.s19`` with ``<tmp>/j`` a junction to
    ``<tmp>/real`` → the entry path is ``<tmp>\\j\\x.s19`` (no link resolved,
    so a mapped drive keeps its letter).

    RED (base): no ``record_recent_source``. Negative control: recording
    ``Path.resolve()`` → ``<tmp>\\real\\x.s19`` → RED."""
    from s19_app.tui.workspace import record_recent_source

    store = _store_of(_lad(tmp_path, monkeypatch))
    real = tmp_path / "real"
    real.mkdir()
    shutil.copyfile(projects.CASE01_DIR / "firmware.s19", real / "x.s19")
    b100_links.create_junction(tmp_path / "j", real)
    assert record_recent_source(tmp_path / "j" / "x.s19") is True
    assert _entries(store) == [(str(tmp_path / "j" / "x.s19"), "s19")]


@STORE_WRITE
def test_tc_b100_34_outside_load_records_the_source_not_the_work_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-172.1a, HLR-172 (seams S1, S7): through the shipped dispatcher an
    outside ``firmware.s19`` then an outside ``firmware.a2l`` → the store
    holds 2 entries, newest first: the A2L source then the S19 source, each
    the ORIGINAL absolute path (never ``workarea/temp/...``), kinds a2l and
    s19; the image and the A2L are both installed.

    RED (base): no store file. Negative control: recording the work copy →
    the paths name ``workarea\\temp`` → RED."""
    store = _store_of(_lad(tmp_path, monkeypatch))
    s19 = _outside(tmp_path)
    a2l = _outside(tmp_path, "firmware.a2l", source="firmware.a2l")
    base = tmp_path / "app"

    async def _scenario(app, pilot, log):
        app._load_path_from_user_input(s19)
        await _wait_image(pilot, app, s19.name)
        app._load_path_from_user_input(a2l)
        await _wait_a2l(pilot, app)

    projects.run_app(base, _scenario)
    assert _entries(store) == [(str(a2l), "a2l"), (str(s19), "s19")]


@STORE_WRITE
def test_tc_b100_34_same_source_keeps_one_entry_in_first_place(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """LLR-172.1b: the same file twice → 1 entry; ``<d>\\sub\\..\\A.s19``
    after ``<d>\\A.s19`` → 1 entry; A, then B, then A → 2 entries, A first.

    RED (base): no ``record_recent_source``. Negative controls: no de-dup →
    2 entries for one file → RED; the old position kept → B first → RED."""
    from s19_app.tui.workspace import record_recent_source

    store = _store_of(_lad(tmp_path, monkeypatch))
    d = tmp_path / "d"
    a, b = d / "A.s19", d / "B.s19"
    record_recent_source(a)
    record_recent_source(a)
    assert _entries(store) == [(str(a), "s19")]
    record_recent_source(Path(str(d / "sub" / ".." / "A.s19")))
    assert _entries(store) == [(str(a), "s19")]
    record_recent_source(b)
    record_recent_source(a)
    assert _entries(store) == [(str(a), "s19"), (str(b), "s19")]


@STORE_WRITE
@CASE_ARM
def test_tc_b100_34_case_spelling_of_one_source_keeps_one_entry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """LLR-172.1b (Windows only: ``normcase`` folds case only there):
    ``<d>\\A.s19`` then ``<D>\\a.S19`` → 1 entry whose text is the second
    call's.

    RED (base): no ``record_recent_source``. Negative control: a
    case-sensitive comparison → 2 entries → RED."""
    from s19_app.tui.workspace import record_recent_source

    store = _store_of(_lad(tmp_path, monkeypatch))
    first = tmp_path / "d" / "A.s19"
    second = Path(str(tmp_path / "d").upper()) / "a.S19"
    record_recent_source(first)
    record_recent_source(second)
    assert _entries(store) == [(str(second), "s19")]


@STORE_WRITE
def test_tc_b100_34_store_holds_at_most_twenty_entries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """LLR-172.1c: 20 distinct sources → 20 entries, source 1 last; the
    21st → 20 entries, source 1 gone, source 21 first; up to 25 → 20
    entries, entry 1 = source 25, entry 20 = source 6.

    RED (base): no ``record_recent_source``. Negative controls: a cap of 21
    or none → 21 entries → RED; dropping the newest → source 21 missing →
    RED."""
    from s19_app.tui.workspace import record_recent_source

    store = _store_of(_lad(tmp_path, monkeypatch))
    src = tmp_path / "src"
    sources = [src / f"s{n:02d}.s19" for n in range(1, 26)]
    for source in sources[:20]:
        assert record_recent_source(source) is True
    paths = [p for p, _ in _entries(store)]
    assert len(paths) == 20 and paths[-1] == str(sources[0]), paths
    record_recent_source(sources[20])
    paths = [p for p, _ in _entries(store)]
    assert len(paths) == 20 and paths[0] == str(sources[20]) and str(sources[0]) not in paths, paths
    for source in sources[21:]:
        record_recent_source(source)
    paths = [p for p, _ in _entries(store)]
    assert len(paths) == 20 and paths[0] == str(sources[24]) and paths[19] == str(sources[5]), paths


@STORE_WRITE
def test_tc_b100_34_load_failing_before_its_copy_records_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-172.1d (4 arms): a store holding 1 entry, then a path that does
    not exist, a file with an unsupported suffix, an outside source over the
    placement's per-file cap (the cap lowered through
    ``copy_into_workarea``'s default, finding F-3; ``Cannot load file:``) and
    an outside A2L while the open project already holds an A2L (``Project
    already has an A2L file.``) → the store's SHA-256 unchanged after each.
    Control (proves the store is live, so "unchanged" means something): an
    outside load that copies → 2 entries, the new source first.

    RED (base): the control records nothing. Negative control: recording
    before the copy → the over-cap arm adds 1 entry → RED."""
    base = tmp_path / "app"
    projects.save_case01_project(base, "pa", files=("firmware.s19", "firmware.a2l"))
    store = _store_of(_lad(tmp_path, monkeypatch))
    seeded = tmp_path / "seed" / "old.s19"
    digest = _seed(store, [_entry(seeded)])
    missing = tmp_path / "src" / "missing.s19"
    notes = tmp_path / "src" / "notes.txt"
    notes.parent.mkdir(parents=True, exist_ok=True)
    notes.write_text("not firmware", encoding="utf-8")
    big = tmp_path / "src" / "big.s19"
    big.write_bytes((projects.CASE01_DIR / "firmware.s19").read_bytes() * 8)
    other_a2l = _outside(tmp_path, "y.a2l", source="firmware.a2l")
    good = _outside(tmp_path, "good.s19")
    copy = workspace_module.copy_into_workarea
    real_defaults = copy.__defaults__

    async def _scenario(app, pilot, log):
        after = {}
        app._load_path_from_user_input(missing)
        for _ in range(10):
            await pilot.pause()
        after["missing"] = _sha(store)
        app._load_path_from_user_input(notes)
        for _ in range(10):
            await pilot.pause()
        after["unsupported"] = _sha(store)
        monkeypatch.setattr(copy, "__defaults__", (1024,) + tuple(real_defaults[1:]))
        mark = len(log.messages)
        app.load_from_path(big)
        for _ in range(20):
            await pilot.pause()
        monkeypatch.setattr(copy, "__defaults__", real_defaults)
        after["over cap"] = (_sha(store), _with(log.since(mark), "Cannot load file:"))
        await projects.load_project(pilot, app, "pa")
        mark = len(log.messages)
        app.load_a2l_from_path(other_a2l)
        for _ in range(20):
            await pilot.pause()
        await settle_workers(pilot)  # Inc 12b R-4: the A2L attach is a worker
        after["project has an A2L"] = (_sha(store), _with(log.since(mark), "Project already has an A2L file."))
        app.load_from_path(good)
        await _wait_image(pilot, app, good.name)
        return after

    after = projects.run_app(base, _scenario)
    assert after["missing"] == digest and after["unsupported"] == digest, after
    assert after["over cap"][0] == digest and len(after["over cap"][1]) == 1, after
    assert after["project has an A2L"][0] == digest and len(after["project has an A2L"][1]) == 1, after
    assert _entries(store) == [(str(good), "s19"), (str(seeded), "s19")]


@STORE_WRITE
def test_tc_b100_34_source_that_copies_then_fails_to_parse_is_recorded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-172.1d declared arm (ruling Q1): an outside ``bad.s19`` that
    copies into the work area and then fails to parse → 1 entry for it (the
    engineer did pick that source; the parse failure is the load's own
    report).

    The bytes are not text in any encoding the parser opens with, so the
    parse raises and nothing is installed: 1 ``Load failed:`` line,
    ``current_file`` still None, the work copy in ``temp/`` (E5 M19: a
    text file of non-records installs with record errors, which could not
    tell "record after copy" from "record after install").

    RED (base): no store file. Negative control: recording only after a
    successful install → 0 entries → RED (M19)."""
    store = _store_of(_lad(tmp_path, monkeypatch))
    bad = tmp_path / "src" / "bad.s19"
    bad.parent.mkdir(parents=True)
    bad.write_bytes(b"\xff\xfe\x00not records\x80\x81\r\n")
    base = tmp_path / "app"

    async def _scenario(app, pilot, log):
        mark = len(log.messages)
        app.load_from_path(bad)
        for _ in range(300):
            if _with(log.since(mark), "Load failed:"):
                break
            await pilot.pause()
        for _ in range(10):
            await pilot.pause()
        return _with(log.since(mark), "Load failed:"), app.current_file

    failed, current_file = projects.run_app(base, _scenario)
    assert len(failed) == 1, failed
    assert current_file is None, current_file
    assert (_workarea(base) / "temp" / "bad.s19").is_file()
    assert _entries(store) == [(str(bad), "s19")]


@STORE_WRITE
def test_tc_b100_34_source_inside_the_work_area_is_not_recorded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ab_template: Path
) -> None:
    """LLR-172.1e (3 arms; seam S2): typed ``<workarea>/ab/firmware.s19``, a
    Workarea Files pick of an ``.a2l`` work copy (``_load_from_item`` →
    ``load_a2l_from_path``) and a variant switch (``_handle_select_variant``
    → ``load_from_path`` with the project's variant) → 0 entries after each.
    Control: an outside load → 1 entry (the store is live).

    RED (base): the control records nothing. Negative control: no inside
    check → the typed arm adds 1 entry → RED."""
    from textual.widgets import ListView

    base = _base_with_ab(tmp_path, ab_template)
    variant_src = _outside(tmp_path, "other.s19", folder="vsrc")
    projects.append_variant(base, variant_src, "ab")
    store = _store_of(_lad(tmp_path, monkeypatch))
    workarea = _workarea(base)
    outside = _outside(tmp_path, "outside.s19")

    async def _scenario(app, pilot, log):
        counts = {}
        await projects.load_project(pilot, app, "ab")
        variant_ids = [v.variant_id for v in app._variant_set.variants if v.path.name == "other.s19"]
        app._handle_select_variant(variant_ids[0])
        await _wait_image(pilot, app, "other.s19")
        counts["variant switch"] = len(_entries(store))
        app._load_path_from_user_input(workarea / "ab" / "firmware.s19")
        await projects.wait_for(
            pilot,
            lambda: app.current_file is not None and app.current_file.path.name.startswith("firmware"),
            "the inside image",
        )
        counts["typed inside file"] = len(_entries(store))
        shutil.copyfile(projects.CASE01_DIR / "firmware.a2l", workarea / "temp" / "work.a2l")
        app.refresh_files()
        await pilot.pause()
        row = next(i for i in app.query_one("#files_list", ListView).children if i.data == "work.a2l")
        app._load_from_item(row)
        await settle_workers(pilot)  # Inc 12b R-5: the A2L pick is a worker
        await _wait_a2l(pilot, app)
        counts["a2l work copy pick"] = len(_entries(store))
        app._load_path_from_user_input(outside)
        await _wait_image(pilot, app, outside.name)
        counts["control: outside"] = len(_entries(store))
        return counts

    counts = projects.run_app(base, _scenario)
    assert counts == {
        "variant switch": 0,
        "typed inside file": 0,
        "a2l work copy pick": 0,
        "control: outside": 1,
    }, counts


@STORE_WRITE
@JUNCTION_ARM
def test_tc_b100_34_linked_store_folder_is_not_written(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """LLR-172.1g: ``<tmp>/lad/s19_app`` a junction to ``<tmp>/elsewhere`` →
    ``record_recent_source`` False with 0 raises and 0 WARNING records of
    its own (seam S6); an outside load installs the image with 0 raises;
    0 files in ``<tmp>/elsewhere``. Control: the junction removed → True.

    RED (base): no ``record_recent_source``. Negative control: no reparse
    check → 1 file in ``<tmp>/elsewhere`` → RED."""
    from s19_app.tui.workspace import record_recent_source

    lad = _lad(tmp_path, monkeypatch)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    b100_links.create_junction(lad / STORE_DIRNAME, elsewhere)
    source = _outside(tmp_path)
    with _captured_warnings() as warnings:
        written = record_recent_source(source)
    assert written is False
    assert warnings.records == [], [r.getMessage() for r in warnings.records]
    base = tmp_path / "app"

    async def _scenario(app, pilot, log):
        app._load_path_from_user_input(source)
        await _wait_image(pilot, app, source.name)
        return app.current_file is not None

    assert projects.run_app(base, _scenario) is True
    assert list(elsewhere.iterdir()) == []
    os.rmdir(lad / STORE_DIRNAME)
    assert record_recent_source(source) is True


@STORE_WRITE
def test_tc_b100_34_store_is_replaced_through_unique_staging_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-172.1h: 100 distinct records → 100 ``os.replace`` calls onto
    ``recent_sources.json``, from 100 distinct staging names, each in
    ``%LOCALAPPDATA%\\s19_app``; a read of the store after each record parses
    as version 1 (100 of 100, 0 partial files); 0 staging files left.

    RED (base): no ``record_recent_source``. Negative controls: a fixed
    staging name → 1 distinct name → RED; writing the store in place → 0
    replace calls → RED."""
    from s19_app.tui.workspace import record_recent_source

    store = _store_of(_lad(tmp_path, monkeypatch))
    calls = _spy_replace(monkeypatch)
    parsed = 0
    for n in range(100):
        assert record_recent_source(tmp_path / "src" / f"f{n:03d}.s19") is True
        if json.loads(store.read_bytes().decode("utf-8")).get("schema_version") == 1:
            parsed += 1
    key = os.path.normcase(str(store))
    onto_store = [(src, dst) for src, dst in calls if os.path.normcase(os.path.abspath(dst)) == key]
    assert len(onto_store) == 100, len(onto_store)
    staging = {os.path.normcase(os.path.abspath(src)) for src, _ in onto_store}
    assert len(staging) == 100, len(staging)
    folder = os.path.normcase(str(store.parent))
    assert all(os.path.dirname(name) == folder for name in staging), sorted(staging)[:3]
    assert key not in staging
    assert parsed == 100
    assert _leftovers(store) == []


@STORE_WRITE
@pytest.mark.parametrize(
    "failure", ["replace refused", "staging creation refused", "staging open refused"]
)
def test_tc_b100_34_failed_store_write_returns_false_and_keeps_the_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    """LLR-172.1i (unit half; seam S6): a store holding 1 entry; ``os.replace``
    raising ``PermissionError`` / the staging creation raising ``OSError`` /
    ``os.fdopen`` of the created staging file raising ``OSError`` (injected)
    → ``record_recent_source`` returns False, 0 raises, the store's SHA-256
    unchanged, 0 staging files left, 0 WARNING records from the record
    itself (the caller logs the one warning).

    RED (base): no ``record_recent_source``. Negative controls: the
    ``OSError`` let out → the call raises → RED; the staging descriptor not
    closed when ``fdopen`` fails → Windows refuses the staging unlink while
    it is open → 1 staging file left → RED (E5 SEC9-5)."""
    from s19_app.tui.workspace import record_recent_source

    store = _store_of(_lad(tmp_path, monkeypatch))
    digest = _seed(store, [_entry(tmp_path / "seed" / "old.s19")])
    if failure == "replace refused":
        _spy_replace(monkeypatch, fail_onto=store)
    elif failure == "staging creation refused":
        _fail_staging_creation(monkeypatch)
    else:
        _fail_staging_open(monkeypatch)
    with _captured_warnings() as warnings:
        written = record_recent_source(tmp_path / "src" / "new.s19")
    assert written is False
    assert _sha(store) == digest
    assert _leftovers(store) == []
    assert warnings.records == [], [r.getMessage() for r in warnings.records]


@STORE_WRITE
@pytest.mark.parametrize("kind", ["data", "a2l"])
@pytest.mark.parametrize("failure", ["replace refused", "staging creation refused"])
def test_tc_b100_34_failed_store_write_never_fails_the_load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str, failure: str
) -> None:
    """LLR-172.1i (4 of 4: 2 injected failures × data and A2L; Q5): in one
    session a first outside load records normally (control), then the
    failure is injected and a second outside load runs → the file is
    installed as without the store, 0 raises out of the load, the store's
    SHA-256 unchanged by the second load, 0 staging files left, exactly 1
    more WARNING record than the control load produced, and 0 status lines
    about the store.

    RED (base): no store at all — the control writes nothing and the second
    load logs no warning. Negative control: the record's ``OSError`` let out
    → the load stops before the install → RED."""
    store = _store_of(_lad(tmp_path, monkeypatch))
    if kind == "data":
        first, second = _outside(tmp_path, "first.s19"), _outside(tmp_path, "second.s19")
    else:
        first = _outside(tmp_path, "first.a2l", source="firmware.a2l")
        second = _outside(tmp_path, "second.a2l", folder="src2", source="firmware.a2l")
    base = tmp_path / "app"

    async def _install(pilot, app, path: Path) -> None:
        if kind == "data":
            app.load_from_path(path)
            await _wait_image(pilot, app, path.name)
        else:
            app.load_a2l_from_path(path)
            await projects.wait_for(
                pilot,
                lambda: app.current_a2l_path is not None and app.current_a2l_path.name == path.name,
                f"the A2L {path.name} attached",
            )
        for _ in range(10):
            await pilot.pause()

    async def _scenario(app, pilot, log):
        with _captured_warnings() as control:
            await _install(pilot, app, first)
        control_warnings = len(control.records)
        digest = _sha(store) if store.exists() else None
        if failure == "replace refused":
            _spy_replace(monkeypatch, fail_onto=store)
        else:
            _fail_staging_creation(monkeypatch)
        mark = len(log.messages)
        with _captured_warnings() as injected:
            await _install(pilot, app, second)
        installed = (
            app.current_file.path.name if kind == "data" else app.current_a2l_path.name
        )
        return (
            digest,
            _sha(store) if store.exists() else None,
            control_warnings,
            len(injected.records),
            log.since(mark),
            installed,
        )

    digest_before, digest_after, control_warnings, injected_warnings, messages, installed = (
        projects.run_app(base, _scenario)
    )
    assert digest_before is not None, "the control load wrote no store"
    assert digest_after == digest_before
    assert installed == second.name, installed
    assert _leftovers(store) == []
    assert injected_warnings - control_warnings == 1, (control_warnings, injected_warnings)
    assert _store_lines(messages) == [], messages


@STORE_WRITE
def test_tc_b100_34_record_writes_back_only_accepted_entries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """LLR-172.1j: a store holding 2 accepted entries and 3 refused ones
    (``\\\\host\\share\\x.s19``, ``kind: exe``, a path holding ``\\x1b[2J``)
    → after 1 record of ``<src>\\n.s19``: 3 entries, the new one first, 0
    refused; an unparseable store and a 65 537-byte store → after 1 record:
    1 entry each.

    RED (base): no ``record_recent_source``. Negative control: carrying the
    raw entries forward → the UNC entry written back → RED."""
    from s19_app.tui.workspace import record_recent_source

    store = _store_of(_lad(tmp_path, monkeypatch))
    acc1, acc2 = tmp_path / "s" / "a.s19", tmp_path / "s" / "b.hex"
    _seed(store, [
        _entry(acc1),
        _entry("\\\\host\\share\\x.s19"),
        _entry(tmp_path / "s" / "c.s19", "exe"),
        _entry(acc2, "hex"),
        _entry(str(tmp_path / "s") + "\\\x1b[2Ja.s19"),
    ])
    new = tmp_path / "src" / "n.s19"
    assert record_recent_source(new) is True
    assert _entries(store) == [(str(new), "s19"), (str(acc1), "s19"), (str(acc2), "hex")]

    store.write_bytes(b"{not json")
    assert record_recent_source(new) is True
    assert _entries(store) == [(str(new), "s19")]

    oversized = _encode([_entry(acc1)])
    store.write_bytes(oversized + b" " * (STORE_CAP + 1 - len(oversized)))
    assert store.stat().st_size == STORE_CAP + 1
    assert record_recent_source(new) is True
    assert _entries(store) == [(str(new), "s19")]


@STORE_WRITE
@pytest.mark.parametrize("failure", ["open refused", "read failed"])
def test_tc_b100_34_unreadable_store_is_left_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    """LLR-172.1k (2 of 2): a store holding 3 accepted entries; the store's
    open raising ``PermissionError`` (injected, a transient sharing
    violation) / its read raising ``OSError`` (injected) → 1 record returns
    False with 0 raises, the store's SHA-256 unchanged, 0 staging files.

    RED (base): no ``record_recent_source``. Negative control: "could not be
    read" treated as an empty store → the store rewritten with 1 entry →
    RED (a transient read failure must not wipe 20 entries to 1)."""
    from s19_app.tui.workspace import record_recent_source

    store = _store_of(_lad(tmp_path, monkeypatch))
    digest = _seed(store, [_entry(tmp_path / "s" / f"{n}.s19") for n in range(3)])
    if failure == "open refused":
        _OpenSpy(monkeypatch, store, raise_on_open=PermissionError(32, "injected: sharing violation"))
    else:
        _OpenSpy(monkeypatch, store, read_error=OSError(5, "injected: read failed"))
    written = record_recent_source(tmp_path / "src" / "n.s19")
    monkeypatch.undo()
    assert written is False
    assert _sha(store) == digest
    assert _leftovers(store) == []


@STORE_WRITE
def test_tc_b100_34_source_the_read_would_drop_is_not_recorded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """LLR-172.1l (3 of 3): a store holding 1 accepted entry, then records
    of ``\\\\host\\share\\x.s19`` (UNC), ``<src>\\a`` + U+009B + ``.s19`` (a
    control character) and ``C:\\CON\\a.s19`` (a device component) → False
    each, the store's SHA-256 unchanged, 0 staging files, 0 raises; control
    ``<src>\\b.s19`` → True, 2 entries.

    RED (base): no ``record_recent_source``. Negative control: writing
    without the entry check → the UNC entry written (SHA-256 changed) →
    RED."""
    from s19_app.tui.workspace import record_recent_source

    store = _store_of(_lad(tmp_path, monkeypatch))
    digest = _seed(store, [_entry(tmp_path / "s" / "kept.s19")])
    src = tmp_path / "src"
    refused = [
        Path("\\\\host\\share\\x.s19"),
        Path(str(src) + "\\a\x9b.s19"),
        Path(_drive_root(tmp_path) + "CON\\a.s19"),
    ]
    results = [record_recent_source(path) for path in refused]
    assert results == [False, False, False], results
    assert _sha(store) == digest
    assert _leftovers(store) == []
    assert record_recent_source(src / "b.s19") is True
    assert [p for p, _ in _entries(store)] == [str(src / "b.s19"), str(tmp_path / "s" / "kept.s19")]


#: LLR-172.2k: paths no Win32 file name can hold after the drive prefix, or
#: hostile to paint (E5 SEC9-3).
WIN32_FORBIDDEN_TAILS = {
    "stream a:b": "a:b.s19",
    "device CON:": "CON:.s19",
    "stream ::$DATA": "a::$DATA.s19",
    "bidi override U+202E": "a\u202eb.s19",
    "line separator U+2028": "a\u2028b.s19",
    "unpaired surrogate U+DC80": "a\udc80b.s19",
}


@STORE_WRITE
def test_tc_b100_34_source_with_a_win32_forbidden_character_is_not_recorded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-172.2k (record half, 7 of 7): a store holding 2 accepted entries,
    then records of ``<src>\\a:b.s19``, ``<src>\\CON:.s19``,
    ``<src>\\a::$DATA.s19``, ``<src>\\a`` + U+202E / U+2028 / U+DC80 +
    ``b.s19``, and the typed ``\\??\\<src>\\x.s19`` (SEC9-4: ``abspath``
    makes it ``C:\\??\\C:\\…``) → False each, the store's SHA-256
    unchanged, 0 staging files, 0 raises; control ``<src>\\c.s19`` → True,
    3 entries.

    RED (pre-fix): each of the 7 records returns True and rewrites the
    store. Negative control: the check removed → the store's SHA-256
    changes → RED."""
    from s19_app.tui.workspace import record_recent_source

    store = _store_of(_lad(tmp_path, monkeypatch))
    kept = [tmp_path / "s" / "k1.s19", tmp_path / "s" / "k2.s19"]
    digest = _seed(store, [_entry(path) for path in kept])
    src = tmp_path / "src"
    refused = {label: Path(str(src) + "\\" + tail) for label, tail in WIN32_FORBIDDEN_TAILS.items()}
    refused["NT prefix \\??\\"] = Path("\\??\\" + str(src / "x.s19"))
    results = {label: record_recent_source(path) for label, path in refused.items()}
    assert results == {label: False for label in refused}, results
    assert _sha(store) == digest
    assert _leftovers(store) == []
    assert record_recent_source(src / "c.s19") is True
    assert [p for p, _ in _entries(store)] == [str(src / "c.s19")] + [str(p) for p in kept]


@STORE_WRITE
def test_tc_b100_34_written_store_fits_the_read_cap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """LLR-172.1m (3 of 3; the record reads no source, so the paths need
    not exist): 20 records of ``<drive>\\`` + 3 240 characters + ``.s19`` →
    20 entries kept, file ≤ 65 536 bytes; a store of 19 entries of 3 245
    characters, then a 20th → True, 19 entries, the new one first and the
    oldest dropped, file ≤ 65 536 bytes; 1 record of ``<drive>\\`` + 11 000
    × ``é`` + ``.s19`` (66 008 bytes escaped) → False, SHA-256 unchanged.

    RED (base): no ``record_recent_source``. Negative controls: no size rule
    → the 3 245 arm writes 65 592 bytes, which the next read reports "too
    large" → RED; dropping the newest → the new entry missing → RED."""
    from s19_app.tui.workspace import record_recent_source

    store = _store_of(_lad(tmp_path, monkeypatch))
    root = _drive_root(tmp_path)

    def _long(index: int, n: int) -> str:
        stem = f"{index:02d}"
        return root + stem + "p" * (n - len(stem)) + ".s19"

    for index in range(20):
        assert record_recent_source(Path(_long(index, 3240))) is True, index
    assert len(_entries(store)) == 20
    assert store.stat().st_size <= STORE_CAP

    seeded = [_long(index, 3245) for index in range(19)]
    _seed(store, [_entry(text) for text in seeded])
    newest = _long(99, 3245)
    assert record_recent_source(Path(newest)) is True
    paths = [p for p, _ in _entries(store)]
    assert paths == [newest] + seeded[:18], (len(paths), paths[:1])
    assert store.stat().st_size <= STORE_CAP

    digest = _sha(store)
    assert record_recent_source(Path(root + "\u00e9" * 11000 + ".s19")) is False
    assert _sha(store) == digest


@STORE_WRITE
def test_tc_b100_34_record_with_an_embedded_nul_never_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """LLR-172.1i (never raises): a source path holding an embedded NUL →
    False, 0 raises, 0 store files. The refusing arm is
    ``_recent_entry_ok``'s control-character check (LLR-172.1l /
    LLR-172.2g): on Windows, Python 3.11 ``os.path.abspath`` does not raise
    for a NUL, so the ``ValueError`` catch around it is not reached here
    (M28 is an equivalent mutant, E5 CR9-4).

    RED (base): no ``record_recent_source``. Negative control: the
    control-character check removed → the NUL path is written (or raises)
    → RED."""
    from s19_app.tui.workspace import record_recent_source

    lad = _lad(tmp_path, monkeypatch)
    assert record_recent_source(Path(str(tmp_path / "a\x00.s19"))) is False
    assert _named_store_files(lad) == []


@STORE_WRITE
def test_tc_b100_34_twenty_five_outside_loads_keep_twenty_newest_first(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """HLR-172: 25 distinct outside sources loaded through the shipped
    dispatcher → 20 entries, newest first (entry 1 = source 25, entry 20 =
    source 6), in ``<LOCALAPPDATA>/s19_app/recent_sources.json``; 0 files
    named ``recent_sources.json`` under the base folder.

    RED (base, code read): ``grep LOCALAPPDATA s19_app`` → 0 hits → no
    store file."""
    store = _store_of(_lad(tmp_path, monkeypatch))
    sources = [_outside(tmp_path, f"s{n:02d}.s19") for n in range(1, 26)]
    base = tmp_path / "app"

    async def _scenario(app, pilot, log):
        for source in sources:
            app._load_path_from_user_input(source)
            await _wait_image(pilot, app, source.name)

    projects.run_app(base, _scenario)
    paths = [p for p, _ in _entries(store)]
    assert paths == [str(s) for s in reversed(sources[5:])], paths
    assert _named_store_files(base) == []


# ===========================================================================
# TC-B100-35 — the store read
# ===========================================================================


def test_tc_b100_35_read_returns_the_first_twenty_accepted_in_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-172.2: 1 000 distinct accepted entries ``C:\\NNN.s19`` (about
    41 KB) → exactly the first 20, in order; 5 accepted entries with 2
    refused ones between them → the 5, in stored order; problem None in
    both arms.

    RED (base): no ``read_recent_sources``. Negative controls: no cap →
    1 000 entries → RED; sorting → the order arm RED."""
    from s19_app.tui.workspace import read_recent_sources

    store = _read_arm_store(tmp_path, monkeypatch)
    _seed(store, [_entry(f"C:\\{n:03d}.s19") for n in range(1000)])
    assert store.stat().st_size < STORE_CAP
    result = read_recent_sources()
    assert _pairs(result) == [(f"C:\\{n:03d}.s19", "s19") for n in range(20)]
    assert result.problem is None

    kept = ["C:\\z\\e.s19", "C:\\z\\a.s19", "C:\\z\\d.hex", "C:\\z\\b.s19", "C:\\z\\c.a2l"]
    kinds = ["s19", "s19", "hex", "s19", "a2l"]
    _seed(store, [
        _entry(kept[0]), _entry(kept[1]), _entry("\\\\host\\share\\x.s19"),
        _entry(kept[2], "hex"), _entry("C:\\z\\f.s19", "exe"), _entry(kept[3]), _entry(kept[4], "a2l"),
    ])
    result = read_recent_sources()
    assert _pairs(result) == list(zip(kept, kinds))
    assert result.problem is None


def test_tc_b100_35_oversized_store_reads_as_too_large(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """LLR-172.2a (S-12): exactly 65 536 bytes of a valid store (padded with
    trailing spaces) → parsed; 65 537 bytes → 0 entries, problem "too
    large"; every read of the store is bounded (no unbounded ``read()``)
    and reads at most 65 537 bytes in all (a spy on the read size).

    RED (base): no ``read_recent_sources``. Negative controls: ``>=`` → the
    65 536 arm "too large" → RED; a stat then a full read → an unbounded
    read seen → RED."""
    from s19_app.tui.workspace import read_recent_sources

    store = _read_arm_store(tmp_path, monkeypatch)
    doc = _encode([_entry("C:\\x\\a.s19")])
    store.parent.mkdir(parents=True, exist_ok=True)
    store.write_bytes(doc + b" " * (STORE_CAP - len(doc)))
    assert store.stat().st_size == STORE_CAP
    result = read_recent_sources()
    assert _pairs(result) == [("C:\\x\\a.s19", "s19")] and result.problem is None

    store.write_bytes(doc + b" " * (STORE_CAP + 1 - len(doc)))
    spy = _OpenSpy(monkeypatch, store)
    result = read_recent_sources()
    sizes = list(spy.read_sizes)
    monkeypatch.undo()
    assert result.entries == () and result.problem == TOO_LARGE, result
    assert sizes, "no read of the store was observed through open()"
    assert all(isinstance(n, int) and n >= 0 for n in sizes), sizes
    assert sum(sizes) <= STORE_CAP + 1, sizes


@pytest.mark.parametrize(
    "payload",
    [
        b"{not json",
        b"\xff\xfe\x00\x01",
        b"[]",
        b'{"schema_version": 2, "sources": []}',
        b'{"schema_version": 1, "sources": "C:\\\\x.s19"}',
        b'{"schema_version": true, "sources": [{"path": "C:\\\\x\\\\a.s19", "kind": "s19"}]}',
        b'{"schema_version": 1.0, "sources": [{"path": "C:\\\\x\\\\a.s19", "kind": "s19"}]}',
        b'{"schema_version": 2, "sources": [{"path": "C:\\\\x\\\\a.s19", "kind": "s19"}]}',
        b"\xef\xbb\xbf" + _encode([_entry("C:\\x\\a.s19")]),
    ],
    ids=["not json", "not utf-8", "top-level list", "version 2", "sources a string",
         "version true", "version 1.0", "version 2 with an entry", "utf-8 bom"],
)
def test_tc_b100_35_store_of_the_wrong_shape_reads_as_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, payload: bytes
) -> None:
    """LLR-172.2b: ``{not json``, bytes that are not UTF-8, a top-level
    list, ``schema_version`` 2, ``sources`` a string (5 of 5), and the
    schema-version spellings ``true`` / ``1.0`` (R-5) and a BOM (U-4) → 0
    entries, problem None, 0 raises.

    RED (base): no ``read_recent_sources``. Negative controls: no shape
    check → the top-level list raises → RED; any ``schema_version``
    accepted → the version-2 arm returns its entry → RED."""
    from s19_app.tui.workspace import read_recent_sources

    store = _read_arm_store(tmp_path, monkeypatch)
    store.parent.mkdir(parents=True, exist_ok=True)
    store.write_bytes(payload)
    result = read_recent_sources()
    assert result.entries == () and result.problem is None, result


@pytest.mark.parametrize(
    "arm",
    [
        "open refused",
        "directory at the store path",
        "store file a symbolic link",
        pytest.param("store folder a junction", marks=JUNCTION_ARM),
    ],
)
def test_tc_b100_35_unreadable_store_reads_as_could_not_be_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: str
) -> None:
    """LLR-172.2c (4 of 4; Q6; E3 R6): the open raising ``PermissionError``
    (injected), a directory at the store path, the store file a symbolic
    link to a valid store ``<tmp>/other.json`` and the store folder a
    junction to ``<tmp>/elsewhere`` holding a valid store → 0 entries,
    problem "could not be read", 0 raises; the link arms open nothing
    through the link (a spy on the open: 0 opens). The file-link arm is
    reported not run when the platform refuses a file symbolic link.

    RED (base): no ``read_recent_sources``. Negative controls: no catch →
    ``PermissionError`` raised → RED; problem None → RED; no link check →
    the link arms return the target's 2 entries → RED."""
    from s19_app.tui.workspace import read_recent_sources

    store = _read_arm_store(tmp_path, monkeypatch)
    valid = _encode([_entry("C:\\x\\a.s19"), _entry("C:\\x\\b.s19")])
    spy = None
    if arm == "open refused":
        _seed(store, [_entry("C:\\x\\a.s19")])
        spy = _OpenSpy(monkeypatch, store, raise_on_open=PermissionError(13, "injected: open refused"))
    elif arm == "directory at the store path":
        store.mkdir(parents=True)
    elif arm == "store file a symbolic link":
        other = tmp_path / "other.json"
        other.write_bytes(valid)
        store.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.symlink(other, store)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"file symbolic links cannot be created here (not run): {exc}")
        spy = _OpenSpy(monkeypatch, store)
    else:
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        (elsewhere / STORE_FILENAME).write_bytes(valid)
        b100_links.create_junction(store.parent, elsewhere)
        spy = _OpenSpy(monkeypatch, store.parent, folder=True)
    result = read_recent_sources()
    opens = list(spy.opens) if spy is not None else []
    monkeypatch.undo()
    assert result.entries == () and result.problem == UNREADABLE, result
    if arm in ("store file a symbolic link", "store folder a junction"):
        assert opens == [], opens


def test_tc_b100_35_missing_store_reads_as_empty_with_no_problem(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-172.2d (2 of 2): no store file → 0 entries, problem None;
    ``LOCALAPPDATA`` unset → 0 entries, problem None, 0 files or folders
    created under the test ``LOCALAPPDATA`` or the working folder.

    RED (base): no ``read_recent_sources``. Negative controls: "could not be
    read" for a missing file → RED; ``FileNotFoundError`` raised → RED."""
    from s19_app.tui.workspace import read_recent_sources
    from s19_app.tui.workspace import recent_store_path

    store = _read_arm_store(tmp_path, monkeypatch)
    lad = tmp_path / "lad"
    result = read_recent_sources()
    assert result.entries == () and result.problem is None, result
    assert not store.exists()

    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    monkeypatch.setattr(workspace_module, "recent_store_path", recent_store_path)
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    result = read_recent_sources()
    assert result.entries == () and result.problem is None, result
    assert list(lad.iterdir()) == [] and list(work.iterdir()) == []


def _entry_checks_store(store: Path, refused: list, accepted: list) -> list:
    """A store with each ``refused`` entry between two distinct accepted
    fillers, then the ``accepted`` entries under test; returns the expected
    (path, kind) list — every filler and accepted entry, in stored order."""
    fillers = [_entry(f"C:\\ok\\f{n:02d}.s19") for n in range(len(refused) + 1)]
    sources = [fillers[0]]
    for index, item in enumerate(refused):
        sources += [item, fillers[index + 1]]
    sources += accepted
    _seed(store, sources)
    return [(item["path"], item["kind"]) for item in fillers + accepted]


@pytest.mark.parametrize(
    "requirement, refused, accepted",
    [
        (
            "LLR-172.2e drive and root",
            ["x.s19", "C:x.s19", "\\x.s19", "\\\\host\\share\\x.s19",
             "\\\\?\\GLOBALROOT\\x.s19", "\\\\.\\C:\\x.s19"],
            ["C:\\x\\a.s19", "C:/x/b.s19"],
        ),
        (
            "LLR-172.2f device names",
            ["C:\\x\\NUL.s19", "C:\\CON\\a.s19", "C:\\x\\com1.s19"],
            ["C:\\x\\console.s19"],
        ),
        (
            "LLR-172.2g control characters",
            ["C:\\x\\a\x00.s19", "C:\\x\\\x1b[2Ja.s19", "C:\\x\\a\x7f.s19", "C:\\x\\a\x9b.s19"],
            ["C:\\x\\a.s19"],
        ),
    ],
)
def test_tc_b100_35_entry_path_checks_drop_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, requirement: str, refused: list, accepted: list
) -> None:
    """LLR-172.2e (6 of 6 dropped: a relative path, a drive without root, a
    root without drive, UNC, ``\\\\?\\`` and ``\\\\.\\``; ``C:\\x\\a.s19``
    returned), LLR-172.2f (``NUL.s19``, a ``CON`` folder, ``com1.s19``
    dropped; ``console.s19`` returned) and LLR-172.2g (NUL, ``\\x1b[2J``,
    U+007F and U+009B dropped) — each refused entry stored between accepted
    ones; only the accepted ones come back, in order.

    RED (base): no ``read_recent_sources``. Negative controls: an
    ``is_absolute()`` filter → the UNC arm returned (S-07) → RED; the last
    component only → ``C:\\CON\\a.s19`` returned → RED; NUL only → the
    ``\\x1b[2J`` arm returned (S-06) → RED."""
    from s19_app.tui.workspace import read_recent_sources

    store = _read_arm_store(tmp_path, monkeypatch)
    expected = _entry_checks_store(store, [_entry(p) for p in refused], [_entry(p) for p in accepted])
    result = read_recent_sources()
    assert _pairs(result) == expected, (requirement, _pairs(result))
    assert result.problem is None


def test_tc_b100_35_entry_with_a_win32_forbidden_character_is_dropped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-172.2k (read half): a store of 8 entries — ``C:\\x\\a.s19``, the
    6 refused ``C:\\x\\a:b.s19``, ``C:\\x\\CON:.s19``,
    ``C:\\x\\a::$DATA.s19``, ``C:\\x\\a`` + U+202E / U+2028 / U+DC80 +
    ``b.s19``, then ``C:/x/../TEMPLA~1/b.s19`` → the 2 valid entries, in
    order (a ``..`` segment and an 8.3 spelling stay legal), problem None.

    RED (pre-fix): 8 entries read (SEC9-3 probe A3). Negative control: the
    check removed → 8 entries → RED."""
    from s19_app.tui.workspace import read_recent_sources

    store = _read_arm_store(tmp_path, monkeypatch)
    first, last = _entry("C:\\x\\a.s19"), _entry("C:/x/../TEMPLA~1/b.s19")
    _seed(store, [first] + [_entry("C:\\x\\" + tail) for tail in WIN32_FORBIDDEN_TAILS.values()] + [last])
    result = read_recent_sources()
    assert _pairs(result) == [(first["path"], "s19"), (last["path"], "s19")], _pairs(result)
    assert result.problem is None


def test_tc_b100_35_entry_whose_kind_does_not_match_its_suffix_is_dropped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-172.2h (5 of 5 dropped): ``kind: exe``; ``C:\\x\\a.s19`` with
    a2l; ``C:\\x\\a.s19:ads`` (a stream) with s19; ``C:\\x\\a.s19.`` (a
    trailing dot) with s19; ``C:\\x\\a.exe`` with s19 — ``C:\\x\\A.SREC``
    with s19 returned.

    RED (base): no ``read_recent_sources``. Negative control: the kind not
    compared with the suffix → the a2l arm returned (S-07) → RED."""
    from s19_app.tui.workspace import read_recent_sources

    store = _read_arm_store(tmp_path, monkeypatch)
    refused = [
        _entry("C:\\x\\a.s19", "exe"),
        _entry("C:\\x\\a.s19", "a2l"),
        _entry("C:\\x\\a.s19:ads", "s19"),
        _entry("C:\\x\\a.s19.", "s19"),
        _entry("C:\\x\\a.exe", "s19"),
    ]
    expected = _entry_checks_store(store, refused, [_entry("C:\\x\\A.SREC", "s19")])
    result = read_recent_sources()
    assert _pairs(result) == expected, _pairs(result)


def test_tc_b100_35_malformed_entry_is_dropped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """LLR-172.2i: ``null``, ``"C:\\\\x.s19"``, ``{"path": 7, "kind":
    "s19"}`` and ``{"path": "C:\\\\x.s19"}`` between 2 accepted entries →
    the 2 accepted entries, 0 of the 4, 0 raises; (LLR-172.2j) an entry of
    a list path and an object kind → dropped, 0 raises.

    RED (base): no ``read_recent_sources``. Negative control: indexing the
    entry without the type check → ``null`` raises → RED."""
    from s19_app.tui.workspace import read_recent_sources

    store = _read_arm_store(tmp_path, monkeypatch)
    first, last = _entry("C:\\x\\a.s19"), _entry("C:\\x\\b.s19")
    _seed(store, [first, None, "C:\\x.s19", {"path": 7, "kind": "s19"}, {"path": "C:\\x.s19"},
                  {"path": ["C:\\x"], "kind": {"k": 1}}, last])
    result = read_recent_sources()
    assert _pairs(result) == [("C:\\x\\a.s19", "s19"), ("C:\\x\\b.s19", "s19")]


def test_tc_b100_35_store_read_never_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """LLR-172.2j: 65 536 bytes of ``[`` (``json`` raises ``RecursionError``,
    not a ``ValueError``; R-4) → 0 entries, problem None; then 200 seeded
    random byte strings of 0 to 70 000 bytes → 0 raises, and every result
    keeps ``problem is not None ⇒ entries == ()`` and ``len(entries) ≤ 20``.

    RED (base): no ``read_recent_sources``. Negative controls: a catch of
    ``ValueError`` alone → the ``[`` arm raises → RED; no decode guard → the
    non-UTF-8 arm of LLR-172.2b raises → RED."""
    from s19_app.tui.workspace import read_recent_sources

    store = _read_arm_store(tmp_path, monkeypatch)
    store.parent.mkdir(parents=True, exist_ok=True)
    store.write_bytes(b"[" * STORE_CAP)
    result = read_recent_sources()
    assert result.entries == () and result.problem is None, result

    rng = random.Random(9_172)
    raised = []
    broken = []
    for index in range(200):
        size = rng.randint(0, 70_000)
        store.write_bytes(bytes(rng.getrandbits(8) for _ in range(size)))
        try:
            result = read_recent_sources()
        except Exception as exc:  # noqa: BLE001 — the threshold counts raises
            raised.append((index, size, type(exc).__name__))
            continue
        if (result.problem is not None and result.entries != ()) or len(result.entries) > 20:
            broken.append((index, size))
    assert raised == [] and broken == [], (raised[:3], broken[:3])


@STORE_WRITE
def test_tc_b100_35_read_logs_no_entry_and_writes_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """LLR-172.3 arm 1 at the read (R-9): a store with 3 entries under
    ``<tmp>\\m4rk3r-9a\\`` read once → 0 log records holding ``m4rk3r-9a``
    at any level; 0 files written (the store folder unchanged).

    RED (base): no ``read_recent_sources``."""
    from s19_app.tui.workspace import read_recent_sources

    store = _store_of(_lad(tmp_path, monkeypatch))
    marker = tmp_path / "m4rk3r-9a"
    _seed(store, [_entry(marker / f"f{n}.s19") for n in range(3)])
    before = sorted(p.name for p in store.parent.iterdir())

    records: list = []

    class _All(logging.Handler):
        def emit(self, record) -> None:
            records.append(record.getMessage())

    handler = _All(logging.DEBUG)
    loggers = [logging.getLogger(), logging.getLogger("s19tui")]
    levels = [logger.level for logger in loggers]
    for logger in loggers:
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
    try:
        result = read_recent_sources()
    finally:
        for logger, level in zip(loggers, levels):
            logger.removeHandler(handler)
            logger.setLevel(level)
    assert len(result.entries) == 3
    assert [m for m in records if "m4rk3r-9a" in m] == []
    assert sorted(p.name for p in store.parent.iterdir()) == before


# ===========================================================================
# TC-B100-36 — recent paths stay out of every file under the base folder
# ===========================================================================


async def _save_and_report(pilot, app, log, base: Path, name: str = "ab") -> None:
    await projects.save_project(pilot, app, log, name)
    reports = _workarea(base) / name / "reports"
    app._trigger_generate_report(16)
    await projects.wait_for(
        pilot, lambda: reports.is_dir() and any(reports.iterdir()), "the report file", attempts=800
    )
    for _ in range(10):
        await pilot.pause()


def _marker_hits(base: Path, marker: str, skip_logs: bool) -> list:
    hits = []
    needle = marker.encode("ascii")
    logs = (WORKAREA_DIRNAME + "/logs/").casefold()
    for path in base.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(base).as_posix()
        if skip_logs and relative.casefold().startswith(logs):
            continue
        if needle in path.read_bytes():
            hits.append(relative)
    return hits


@STORE_WRITE
def test_tc_b100_36_seeded_recent_entries_never_reach_the_base_folder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-172.3 arm 1: a store seeded with 3 entries under ``<tmp>/m4rk3r-9a/``
    (never loaded in the session; the read returns all 3, so the app could
    see them), then an outside load of another file, Save project and a
    report → 0 occurrences of ``m4rk3r-9a`` in any file under the base
    folder, the log included.

    Declared (requirement): the leak arm holds at the base (no store
    exists); the node's RED at the base is the liveness precondition (no
    ``read_recent_sources``). Negative control: the store's entries added to
    ``project.json`` → 3 occurrences → RED."""
    from s19_app.tui.workspace import read_recent_sources

    store = _store_of(_lad(tmp_path, monkeypatch))
    marker = tmp_path / "m4rk3r-9a"
    _seed(store, [_entry(marker / f"f{n}.s19") for n in range(3)])
    assert len(read_recent_sources().entries) == 3
    source = _outside(tmp_path, "firmware.s19", folder="plain")
    base = tmp_path / "app"

    async def _scenario(app, pilot, log):
        app._load_path_from_user_input(source)
        await _wait_image(pilot, app, source.name)
        await _save_and_report(pilot, app, log, base)

    projects.run_app(base, _scenario)
    assert _marker_hits(base, "m4rk3r-9a", skip_logs=False) == []


@STORE_WRITE
def test_tc_b100_36_loaded_source_path_stays_out_of_project_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-172.3 arm 2: an outside load from ``<tmp>/m4rk3r-9b/firmware.s19``
    (recorded: the store holds it, so a leak has something to copy), Save
    project and a report → 0 occurrences of ``m4rk3r-9b`` in any file under
    the base folder other than ``.s19tool/logs/``.

    RED (base): the store does not hold the source (no record). Negative
    control: the store's entries copied into ``project.json`` → RED."""
    store = _store_of(_lad(tmp_path, monkeypatch))
    source = _outside(tmp_path, "firmware.s19", folder="m4rk3r-9b")
    base = tmp_path / "app"

    async def _scenario(app, pilot, log):
        app._load_path_from_user_input(source)
        await _wait_image(pilot, app, source.name)
        await _save_and_report(pilot, app, log, base)

    projects.run_app(base, _scenario)
    assert _entries(store) == [(str(source), "s19")]
    assert _marker_hits(base, "m4rk3r-9b", skip_logs=True) == []


# ===========================================================================
# TC-B100-37 — one lister of the temp folder
# ===========================================================================

_ENUM_METHODS = {"iterdir", "glob", "rglob"}
_ENUM_FUNCTIONS = {"scandir", "listdir", "walk"}


def _refers_to_temp(node, names: set) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and (sub.id == "WORKAREA_TEMP" or sub.id in names):
            return True
        if isinstance(sub, ast.Attribute) and sub.attr == "WORKAREA_TEMP":
            return True
    return False


def _temp_enumerators(root: Path) -> list:
    """(file, function) for every function of ``s19_app/`` that calls
    ``iterdir`` / ``glob`` / ``rglob`` on, or ``scandir`` / ``listdir`` /
    ``walk`` with, a path built from ``WORKAREA_TEMP`` (directly, or through
    a name bound to such a path in the same function)."""
    found = []
    for path in sorted((root / "s19_app").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for function in ast.walk(tree):
            if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            names: set = set()
            changed = True
            while changed:
                changed = False
                for sub in ast.walk(function):
                    if isinstance(sub, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                        targets = sub.targets if isinstance(sub, ast.Assign) else [sub.target]
                        if sub.value is not None and _refers_to_temp(sub.value, names):
                            for target in targets:
                                for leaf in ast.walk(target):
                                    if isinstance(leaf, ast.Name) and leaf.id not in names:
                                        names.add(leaf.id)
                                        changed = True
            for sub in ast.walk(function):
                if not isinstance(sub, ast.Call):
                    continue
                func = sub.func
                callee = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
                hit = (
                    isinstance(func, ast.Attribute) and func.attr in _ENUM_METHODS
                    and _refers_to_temp(func.value, names)
                ) or (callee in _ENUM_FUNCTIONS and any(_refers_to_temp(a, names) for a in sub.args))
                if hit:
                    entry = (path.relative_to(root).as_posix(), function.name)
                    if entry not in found:
                        found.append(entry)
    return found


def test_tc_b100_37_one_function_enumerates_the_temp_folder() -> None:
    """LLR-172.4 (an AST census of ``s19_app/``): calls of ``iterdir`` /
    ``glob`` / ``rglob`` / ``scandir`` / ``listdir`` / ``walk`` on a path
    built from ``WORKAREA_TEMP`` → exactly 1 function,
    ``list_workarea_files`` in ``workspace.py``, and 0 in ``app.py``.

    RED (base): the census finds ``refresh_files`` (``app.py``,
    ``temp_dir.glob("*")``). Negative control: a second enumeration added
    in ``app.py`` → 2 functions → RED."""
    found = _temp_enumerators(projects.ROOT)
    assert found == [("s19_app/tui/workspace.py", "list_workarea_files")], found


def _temp_with(base: Path, names: list) -> Path:
    temp = _workarea(base) / workspace_module.WORKAREA_TEMP
    temp.mkdir(parents=True, exist_ok=True)
    for name in names:
        (temp / name).write_bytes((projects.CASE01_DIR / "firmware.s19").read_bytes())
    return temp


def test_tc_b100_37_lister_returns_the_regular_files_sorted(tmp_path: Path) -> None:
    """LLR-172.4a: ``temp`` holding ``b.s19``, ``a.hex``, ``c.a2l``, the
    private ``.staging`` folder with 1 file and ``sub/x.s19`` →
    ``[temp/a.hex, temp/b.s19, temp/c.a2l]`` (Paths, on-disk names, 0
    for ``.staging`` or ``sub``); an empty ``temp`` → ``[]``.

    RED (base): no ``list_workarea_files``. Negative controls: a recursive
    listing → the ``.staging`` and ``sub`` files returned → RED; no sort →
    the order arm RED."""
    from s19_app.tui.workspace import list_workarea_files

    base = tmp_path / "app"
    workarea = _workarea(base)
    temp = _temp_with(base, ["b.s19", "a.hex", "c.a2l"])
    (temp / ".staging").mkdir()
    (temp / ".staging" / "s.s19").write_bytes(b"S0")
    (temp / "sub").mkdir()
    (temp / "sub" / "x.s19").write_bytes(b"S0")
    listed = list_workarea_files(workarea)
    assert [Path(p) for p in listed] == [temp / "a.hex", temp / "b.s19", temp / "c.a2l"], listed

    empty_base = tmp_path / "empty"
    _temp_with(empty_base, [])
    assert list_workarea_files(_workarea(empty_base)) == []


def test_tc_b100_37_lister_sorts_whatever_order_the_folder_yields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-172.4a (order arm, E5 M57): ``temp`` holding ``a.hex``, ``B.s19``
    and ``c.a2l``, with ``os.scandir`` yielding its entries in reverse
    (injected) → ``[a.hex, B.s19, c.a2l]``, the ``(casefold, name)`` order
    (a plain name sort would put ``B.s19`` first).

    Negative control: no sort → the reversed order comes back → RED (M57;
    NTFS already yields this folder sorted, so without the injection the
    mutant survived)."""
    from s19_app.tui.workspace import list_workarea_files

    base = tmp_path / "app"
    temp = _temp_with(base, ["c.a2l", "B.s19", "a.hex"])
    original = os.scandir
    key = os.path.normcase(os.path.abspath(str(temp)))
    reversed_calls: list = []

    class _Reversed:
        def __init__(self, entries) -> None:
            self._entries = entries

        def __enter__(self):
            return iter(self._entries)

        def __exit__(self, *exc):
            return False

        def __iter__(self):
            return iter(self._entries)

    def _scandir(path="."):
        if not isinstance(path, int) and os.path.normcase(os.path.abspath(os.fspath(path))) == key:
            with original(path) as it:
                entries = list(it)
            reversed_calls.append([e.name for e in entries])
            return _Reversed(entries[::-1])
        return original(path)

    monkeypatch.setattr(workspace_module.os, "scandir", _scandir)
    listed = [p.name for p in list_workarea_files(_workarea(base))]
    monkeypatch.undo()
    assert len(reversed_calls) == 1, reversed_calls
    assert listed == ["a.hex", "B.s19", "c.a2l"], listed


@WIN32_NAME_ARM
@pytest.mark.parametrize("on_disk", ["a.s19.", "b.s19 "])
def test_tc_b100_37_lister_skips_a_name_ending_in_a_dot_or_space(tmp_path: Path, on_disk: str) -> None:
    """LLR-172.4d (E5 SEC9-1): ``temp`` holding the regular file ``c.s19``
    and a file whose on-disk name ends in a dot (``a.s19.``) or a space
    (``b.s19 ``), made through a ``\\\\?\\`` path → the lister returns
    ``[temp/c.s19]`` and the list shows 1 row ``c.s19``, 0 rows naming the
    other (Win32 opens ``a.s19.`` as ``a.s19``, so a pick would load
    another file).

    RED (pre-fix): the lister and the list name it. Negative control: the
    skip removed → 1 extra row → RED."""
    from s19_app.tui.workspace import list_workarea_files

    base = tmp_path / "app"
    temp = _temp_with(base, ["c.s19"])
    odd = projects.EXTENDED_PREFIX + str(temp) + "\\" + on_disk
    with open(odd, "wb") as handle:
        handle.write(b"S0")
    try:
        listed = [p.name for p in list_workarea_files(_workarea(base))]

        async def _scenario(app, pilot, log):
            app.refresh_files()
            await pilot.pause()
            return [plain for plain, _, _ in _row_facts(app)]

        rows = projects.run_app(base, _scenario)
    finally:
        try:
            os.remove(odd)
        except OSError:
            pass
    assert listed == ["c.s19"], listed
    assert rows == ["c.s19"], rows


def test_tc_b100_37_rows_equal_the_lister(tmp_path: Path) -> None:
    """LLR-172.4a (app half): ``temp`` holding ``b.s19``, ``a.hex``,
    ``c.a2l``, ``.staging/s.s19`` and ``sub/x.s19``, then ``r`` (refresh)
    → 3 rows ``a.hex``, ``b.s19``, ``c.a2l``, equal to the lister's names
    (0 differences); an emptied ``temp`` → 0 rows.

    RED (base): no ``list_workarea_files``."""
    from s19_app.tui.workspace import list_workarea_files

    base = tmp_path / "app"
    temp = _temp_with(base, ["b.s19", "a.hex", "c.a2l"])
    (temp / ".staging").mkdir()
    (temp / ".staging" / "s.s19").write_bytes(b"S0")
    (temp / "sub").mkdir()
    (temp / "sub" / "x.s19").write_bytes(b"S0")

    async def _scenario(app, pilot, log):
        await pilot.press("r")
        for _ in range(4):
            await pilot.pause()
        rows = [plain for plain, _, _ in _row_facts(app)]
        listed = [p.name for p in list_workarea_files(app.workarea)]
        for name in ("a.hex", "b.s19", "c.a2l"):
            (temp / name).unlink()
        app.refresh_files()
        await pilot.pause()
        return rows, listed, [plain for plain, _, _ in _row_facts(app)]

    rows, listed, emptied = projects.run_app(base, _scenario)
    assert rows == ["a.hex", "b.s19", "c.a2l"], rows
    assert rows == listed, (rows, listed)
    assert emptied == [], emptied


def test_tc_b100_37_file_link_in_temp_is_not_listed(tmp_path: Path) -> None:
    """LLR-172.4b: ``temp/l.s19``, a file symbolic link to an outside file,
    beside ``a.s19`` → the lister returns ``[temp/a.s19]`` and the list
    shows 1 row ``a.s19``, 0 rows ``l.s19``. Reported not run when the
    platform refuses a file symbolic link.

    RED (base): ``refresh_files`` tests ``is_file()``, which follows the
    link → ``l.s19`` listed. Negative control: ``is_file()`` without the
    link gate → RED."""
    base = tmp_path / "app"
    temp = _temp_with(base, ["a.s19"])
    outside = _outside(tmp_path, "out.s19", folder="outside")
    try:
        os.symlink(outside, temp / "l.s19")
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"file symbolic links cannot be created here (not run): {exc}")

    async def _scenario(app, pilot, log):
        app.refresh_files()
        await pilot.pause()
        return [plain for plain, _, _ in _row_facts(app)]

    rows = projects.run_app(base, _scenario)
    assert rows == ["a.s19"], rows
    from s19_app.tui.workspace import list_workarea_files

    assert [p.name for p in list_workarea_files(_workarea(base))] == ["a.s19"]


def _refuse_temp_listing(monkeypatch: pytest.MonkeyPatch, temp: Path) -> None:
    key = os.path.normcase(os.path.abspath(str(temp)))
    for name in ("scandir", "listdir"):
        original = getattr(os, name)

        def _refuse(path=".", _original=original):
            if not isinstance(path, int) and os.path.normcase(os.path.abspath(os.fspath(path))) == key:
                raise PermissionError(13, "injected: listing refused", str(path))
            return _original(path)

        monkeypatch.setattr(os, name, _refuse)


@pytest.mark.parametrize(
    "arm",
    [
        "temp removed",
        "listing refused",
        "temp a regular file",
        pytest.param("temp a junction", marks=JUNCTION_ARM),
    ],
)
def test_tc_b100_37_unlistable_temp_gives_an_empty_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: str
) -> None:
    """LLR-172.4c (lister): ``temp`` removed, the listing raising
    ``PermissionError`` (injected), ``temp`` a regular file, and ``temp`` a
    junction to ``<tmp>/elsewhere`` holding ``z.s19`` (R11) → ``[]``, 0
    raises, never a partial list.

    RED (base): no ``list_workarea_files``. Negative controls: no catch →
    the injected arm raises → RED; no folder link check → ``z.s19``
    returned → RED."""
    from s19_app.tui.workspace import list_workarea_files

    base = tmp_path / "app"
    workarea = _workarea(base)
    temp = _temp_with(base, ["a.s19"])
    if arm == "temp removed":
        shutil.rmtree(temp)
    elif arm == "listing refused":
        _refuse_temp_listing(monkeypatch, temp)
    elif arm == "temp a regular file":
        shutil.rmtree(temp)
        temp.write_bytes(b"not a folder")
    else:
        shutil.rmtree(temp)
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        (elsewhere / "z.s19").write_bytes(b"S0")
        b100_links.create_junction(temp, elsewhere)
    assert list_workarea_files(workarea) == []


@pytest.mark.parametrize(
    "arm",
    ["temp removed", "listing refused", pytest.param("temp a junction", marks=JUNCTION_ARM)],
)
def test_tc_b100_37_unlistable_temp_shows_no_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: str
) -> None:
    """LLR-172.4c (3 of 3 through the list): after start-up ``temp`` is
    removed, its listing raises ``PermissionError`` (injected), or ``temp``
    is a junction to ``<tmp>/elsewhere`` holding ``z.s19``; then a refresh
    → 0 rows, 0 raises out of ``refresh_files``.

    RED (base): the junctioned ``temp`` is followed and ``z.s19`` listed.
    Declared: the removed and the listing-refused arms PASS at the base
    (``red-01-vs-base.txt``: ``glob`` returns nothing for a missing folder,
    and pathlib's glob swallows the injected ``PermissionError``), so for
    them a mutation is the only RED (M59: the lister's catch removed)."""
    base = tmp_path / "app"
    temp = _workarea(base) / workspace_module.WORKAREA_TEMP

    async def _scenario(app, pilot, log):
        (temp / "a.s19").write_bytes(b"S0")
        if arm == "temp removed":
            shutil.rmtree(temp)
        elif arm == "listing refused":
            _refuse_temp_listing(monkeypatch, temp)
        else:
            shutil.rmtree(temp)
            elsewhere = tmp_path / "elsewhere"
            elsewhere.mkdir()
            (elsewhere / "z.s19").write_bytes(b"S0")
            b100_links.create_junction(temp, elsewhere)
        try:
            app.refresh_files()
            raised = None
        except Exception as exc:  # noqa: BLE001 — the threshold counts raises
            raised = type(exc).__name__
        await pilot.pause()
        rows = [plain for plain, _, _ in _row_facts(app)]
        monkeypatch.undo()
        return raised, rows

    raised, rows = projects.run_app(base, _scenario)
    assert raised is None, raised
    assert rows == [], rows


# ===========================================================================
# TC-B100-38 — a typed project path opens the project
# ===========================================================================


@pytest.mark.parametrize(
    "spelling",
    [
        "plain",
        "dot-dot through temp",
        pytest.param("work area in upper case", marks=CASE_ARM),
        pytest.param("name in upper case", marks=CASE_ARM),
    ],
)
def test_tc_b100_38_typed_project_folder_loads_the_project(
    tmp_path: Path, ab_template: Path, spelling: str
) -> None:
    """LLR-172.5 (4 of 4): ``<workarea>/ab``, ``<workarea>/temp/../ab``,
    ``<workarea>`` in upper case + ``/ab`` and ``<workarea>/AB`` typed into
    Load → project ``ab`` loaded each time (``current_project == "ab"``,
    the on-disk name from the listing; 1 line naming ``ab`` loaded).

    RED (base, e1 probe): ``['Unsupported file type: ']``, no project.
    Negative control: the typed spelling loaded instead of the listed name
    → ``current_project == "AB"`` → RED."""
    base = _base_with_ab(tmp_path, ab_template)
    workarea = _workarea(base)
    texts = {
        "plain": str(workarea / "ab"),
        "dot-dot through temp": str(workarea) + os.sep + "temp" + os.sep + ".." + os.sep + "ab",
        "work area in upper case": str(workarea).upper() + os.sep + "ab",
        "name in upper case": str(workarea / "AB"),
    }

    async def _scenario(app, pilot, log):
        messages = await _typed(pilot, app, log, texts[spelling])
        return messages, app.current_project

    messages, project = projects.run_app(base, _scenario)
    assert project == "ab", (project, messages)
    assert len(_loaded_ab(messages)) == 1, messages


@pytest.mark.parametrize(
    "arm",
    ["project.json", pytest.param("PROJECT.JSON", marks=CASE_ARM), "project.json below a project"],
)
def test_tc_b100_38_typed_project_json_loads_its_project(tmp_path: Path, ab_template: Path, arm: str) -> None:
    """LLR-172.5a: ``<workarea>/ab/project.json`` and
    ``<workarea>/ab/PROJECT.JSON`` → project ``ab`` loaded (2 of 2);
    ``<workarea>/ab/flows/project.json`` → 0 loads, 1 line holding ``not a
    project`` and ``pick a project in the list``.

    RED (base, e1 probe): ``['Unsupported file type: .json']``."""
    base = _base_with_ab(tmp_path, ab_template)
    project_dir = _workarea(base) / "ab"
    flows = project_dir / "flows"
    flows.mkdir(exist_ok=True)
    shutil.copyfile(project_dir / "project.json", flows / "project.json")
    texts = {
        "project.json": project_dir / "project.json",
        "PROJECT.JSON": project_dir / "PROJECT.JSON",
        "project.json below a project": flows / "project.json",
    }

    async def _scenario(app, pilot, log):
        messages = await _typed(pilot, app, log, str(texts[arm]))
        return messages, app.current_project

    messages, project = projects.run_app(base, _scenario)
    if arm == "project.json below a project":
        assert project is None, (project, messages)
        assert len(_with(messages, "not a project", "pick a project in the list")) == 1, messages
    else:
        assert project == "ab", (project, messages)
        assert len(_loaded_ab(messages)) == 1, messages


def _refusal_scene(base: Path, monkeypatch, text_or_name, *, typed: bool = True):
    """Run one typed path (or one ``_handle_load_project`` name) in a fresh
    app; return (messages, current_project, resets, files written outside
    the log folder)."""

    async def _scenario(app, pilot, log):
        resets = _spy_resets(monkeypatch)
        before = _digests_outside_logs(base)
        if typed:
            messages = await _typed(pilot, app, log, str(text_or_name))
        else:
            messages = await _project_load(pilot, app, log, text_or_name)
        after = _digests_outside_logs(base)
        written = sorted(set(after.items()) - set(before.items()))
        return messages, app.current_project, len(resets), written, app.current_file

    return projects.run_app(base, _scenario)


def _reserved_fixture(base: Path) -> Path:
    """``temp`` holding a work copy, ``patches`` and ``templates`` (holding
    ``t.s19``), an empty folder ``empty`` and ``ab/flows``."""
    workarea = _workarea(base)
    temp = workarea / "temp"
    temp.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(projects.CASE01_DIR / "firmware.s19", temp / "firmware.s19")
    (workarea / "patches").mkdir(exist_ok=True)
    (workarea / "templates").mkdir(exist_ok=True)
    shutil.copyfile(projects.CASE01_DIR / "firmware.s19", workarea / "templates" / "t.s19")
    (workarea / "empty").mkdir(exist_ok=True)
    (workarea / "ab" / "flows").mkdir(exist_ok=True)
    return workarea


def _short_name_of_templates(workarea: Path) -> str:
    short = b100_links.short_path_name(workarea / "templates")
    if short is None or short.name.casefold() == "templates":
        pytest.skip("the volume makes no 8.3 names (8.3 arm not run)")
    return short.name


@pytest.mark.parametrize(
    "arm",
    [
        "temp",
        pytest.param("TEMP", marks=CASE_ARM),
        "patches",
        pytest.param("temp::$INDEX_ALLOCATION", marks=WIN32_NAME_ARM),
        pytest.param("8.3 name of templates", marks=WIN32_NAME_ARM),
        pytest.param("temp.", marks=WIN32_NAME_ARM),
        "empty",
        "ab/flows",
        "the work area itself",
    ],
)
def test_tc_b100_38_typed_folder_that_is_not_a_project_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ab_template: Path, arm: str
) -> None:
    """LLR-172.5b (9 of 9; E3 R3, S9-1): ``<workarea>/temp`` (holding a work
    copy), ``TEMP``, ``patches``, ``temp::$INDEX_ALLOCATION``, the 8.3 name
    of ``templates`` (holding a file), ``temp.``, an empty folder, the
    sub-folder ``ab/flows`` and ``<workarea>`` itself → 0 project loads, 0
    files written, 1 line holding ``not a project`` and ``pick a project in
    the list``.

    RED (base, e1 probe): ``['Unsupported file type: ']``, neither token.
    Negative control: a case-folded reserved-home test instead of the
    listing match → ``temp::$INDEX_ALLOCATION`` loads ``temp`` → RED."""
    base = _base_with_ab(tmp_path, ab_template)
    workarea = _reserved_fixture(base)
    texts = {
        "temp": str(workarea / "temp"),
        "TEMP": str(workarea / "TEMP"),
        "patches": str(workarea / "patches"),
        "temp::$INDEX_ALLOCATION": str(workarea) + os.sep + "temp::$INDEX_ALLOCATION",
        "temp.": str(workarea) + os.sep + "temp.",
        "empty": str(workarea / "empty"),
        "ab/flows": str(workarea / "ab" / "flows"),
        "the work area itself": str(workarea),
    }
    text = texts.get(arm) or str(workarea / _short_name_of_templates(workarea))
    messages, project, resets, written, _ = _refusal_scene(base, monkeypatch, text)
    assert project is None and resets == 0, (project, resets, messages)
    assert written == [], written
    assert len(_with(messages, "not a project", "pick a project in the list")) == 1, messages


@pytest.mark.parametrize(
    "arm", ["outside folder", "outside project.json", "another work area", "the base folder"]
)
def test_tc_b100_38_typed_folder_outside_the_work_area_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ab_template: Path, arm: str
) -> None:
    """LLR-172.5c (4 of 4): ``<tmp>/elsewhere/P`` holding a ``project.json``
    and an image, that folder's ``project.json``, another work area's
    project ``<tmp>/other/.s19tool/workarea/R`` and the base folder → 0
    project loads, 0 files written, 1 line holding ``outside the work area``
    and ``copy the folder into the work area``.

    RED (base): ``Unsupported file type: ``, neither token. Negative
    control: loading any folder that holds a ``project.json`` →
    ``<tmp>/elsewhere/P`` loads → RED."""
    base = _base_with_ab(tmp_path, ab_template)
    template_ab = _workarea(ab_template) / "ab"
    elsewhere = tmp_path / "elsewhere" / "P"
    shutil.copytree(template_ab, elsewhere)
    other = _workarea(tmp_path / "other") / "R"
    shutil.copytree(template_ab, other)
    texts = {
        "outside folder": elsewhere,
        "outside project.json": elsewhere / "project.json",
        "another work area": other,
        "the base folder": base,
    }
    messages, project, resets, written, _ = _refusal_scene(base, monkeypatch, texts[arm])
    assert project is None and resets == 0, (project, resets, messages)
    assert written == [], written
    assert len(_with(messages, "outside the work area", "copy the folder into the work area")) == 1, messages


@JUNCTION_ARM
@pytest.mark.parametrize("arm", ["junction folder", "junction project.json", "junction above"])
def test_tc_b100_38_typed_path_through_a_junction_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ab_template: Path, arm: str
) -> None:
    """LLR-172.5d (3 of 3): ``<workarea>/alias`` (a junction to
    ``<workarea>/ab``), ``<workarea>/alias/project.json`` and
    ``<workarea>/sub/P`` with ``<workarea>/sub`` a junction to another work
    area → 0 project loads, 0 session resets, 1 line holding ``link or
    junction`` and ``pick a project in the list``.

    RED (base): ``exists()`` follows the junction → ``Unsupported file
    type: ``, neither token. Negative control: ``resolve()`` before the
    link check → ``alias`` loads ``ab`` → RED."""
    base = _base_with_ab(tmp_path, ab_template)
    workarea = _workarea(base)
    b100_links.create_junction(workarea / "alias", workarea / "ab")
    other_workarea = _workarea(tmp_path / "other")
    shutil.copytree(_workarea(ab_template) / "ab", other_workarea / "P")
    b100_links.create_junction(workarea / "sub", other_workarea)
    texts = {
        "junction folder": workarea / "alias",
        "junction project.json": workarea / "alias" / "project.json",
        "junction above": workarea / "sub" / "P",
    }
    messages, project, resets, _, _ = _refusal_scene(base, monkeypatch, texts[arm])
    assert project is None and resets == 0, (project, resets, messages)
    assert len(_with(messages, "link or junction", "pick a project in the list")) == 1, messages


@pytest.mark.parametrize(
    "name", ["firmware", "notes.txt", "x.json", pytest.param("fw.s19.", marks=WIN32_NAME_ARM)]
)
def test_tc_b100_38_typed_unsupported_file_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ab_template: Path, name: str
) -> None:
    """LLR-172.5e (4 of 4): ``<tmp>/firmware`` (no suffix), ``<tmp>/notes.txt``,
    ``<tmp>/x.json`` and ``<tmp>/fw.s19.`` typed while ``<tmp>/fw.s19``
    exists (Win32 opens the trailing-dot spelling as ``fw.s19``; the
    loaders see the suffix ``""``) → 0 loads, 0 files copied into
    ``temp/``, 1 line holding ``not a supported file`` and ``check the
    path``.

    RED (base): ``Unsupported file type: <suffix>``, neither token. RED
    (pre-fix, ``fw.s19.``): the route decides from the ``abspath`` suffix
    ``.s19`` and the loader paints ``Unsupported file type: `` (E5 CR9-3)."""
    base = _base_with_ab(tmp_path, ab_template)
    on_disk = name.rstrip(".")
    path = tmp_path / "src" / on_disk
    path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(projects.CASE01_DIR / "firmware.s19", path)
    typed = str(path) + name[len(on_disk):]
    temp = _workarea(base) / "temp"
    before = sorted(p.name for p in temp.iterdir()) if temp.exists() else []
    messages, project, _, _, current_file = _refusal_scene(base, monkeypatch, typed)
    after = sorted(p.name for p in temp.iterdir()) if temp.exists() else []
    assert project is None and current_file is None, (project, current_file, messages)
    assert after == before, (before, after)
    assert len(_with(messages, "not a supported file", "check the path")) == 1, messages


@pytest.mark.parametrize("arm", ["missing file", "missing folder"])
def test_tc_b100_38_typed_path_that_does_not_exist_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ab_template: Path, arm: str
) -> None:
    """LLR-172.5f (2 of 2): ``<tmp>/missing.s19`` and ``<workarea>/nope`` →
    0 loads, 1 line holding ``not found`` and ``check the path``.

    RED (base): ``File not found: <path>`` holds ``not found`` but not
    ``check the path``."""
    base = _base_with_ab(tmp_path, ab_template)
    text = tmp_path / "missing.s19" if arm == "missing file" else _workarea(base) / "nope"
    messages, project, _, _, current_file = _refusal_scene(base, monkeypatch, text)
    assert project is None and current_file is None, (project, current_file, messages)
    assert len(_with(messages, "not found", "check the path")) == 1, messages


@pytest.mark.parametrize(
    "name",
    [
        "temp",
        pytest.param("TEMP", marks=CASE_ARM),
        "patches",
        pytest.param("temp::$INDEX_ALLOCATION", marks=WIN32_NAME_ARM),
        pytest.param("8.3 name of templates", marks=WIN32_NAME_ARM),
        pytest.param("temp.", marks=WIN32_NAME_ARM),
    ],
)
def test_tc_b100_38_project_load_of_an_unlisted_name_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ab_template: Path, name: str
) -> None:
    """LLR-172.5g (6 of 6; E3 R3): with a work copy in ``temp/``,
    ``_handle_load_project("temp")``, ``("TEMP")``, ``("patches")``,
    ``("temp::$INDEX_ALLOCATION")``, the 8.3 name of ``templates`` (holding
    a file) and ``("temp.")`` → 0 project loads, 0 session resets, 0 files
    written (``temp/project.json`` and ``templates/project.json`` absent),
    1 line holding ``not a project`` and ``pick a project in the list``.

    RED (base, e1 probe): ``_handle_load_project('temp')`` →
    ``Loaded project 'temp' …``. Negative control: a case-folded
    reserved-home test instead of the listing → the stream and 8.3
    spellings load → RED."""
    base = _base_with_ab(tmp_path, ab_template)
    workarea = _reserved_fixture(base)
    if name == "8.3 name of templates":
        name = _short_name_of_templates(workarea)
    messages, project, resets, written, _ = _refusal_scene(base, monkeypatch, name, typed=False)
    assert project is None and resets == 0, (project, resets, messages)
    assert written == [], written
    assert not (workarea / "temp" / "project.json").exists()
    assert not (workarea / "templates" / "project.json").exists()
    assert len(_with(messages, "not a project", "pick a project in the list")) == 1, messages


@CASE_ARM
def test_tc_b100_38_project_load_of_another_case_loads_the_listed_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ab_template: Path
) -> None:
    """LLR-172.5g control: ``_handle_load_project("AB")`` for the project
    ``ab`` → 1 load, ``current_project == "ab"`` (the on-disk name).

    RED (base): the typed spelling is loaded → ``current_project == "AB"``."""
    base = _base_with_ab(tmp_path, ab_template)

    async def _scenario(app, pilot, log):
        messages = await _project_load(pilot, app, log, "AB")
        return messages, app.current_project

    messages, project = projects.run_app(base, _scenario)
    assert project == "ab", (project, messages)


@WIN32_NAME_ARM
@pytest.mark.parametrize("on_disk", ["temp.", "ab "])
def test_tc_b100_38_project_list_skips_a_name_ending_in_a_dot_or_space(
    tmp_path: Path, ab_template: Path, on_disk: str
) -> None:
    """E3 R14 (S9R2-1): a folder whose on-disk name ends in a dot (``temp.``)
    or a space (``ab ``), created through a ``\\\\?\\`` path and holding a
    data file → ``list_projects`` does not list it (Win32 opens ``temp.``
    as ``temp``, so a pick would load another folder).

    RED (base): ``list_projects`` lists it."""
    base = _base_with_ab(tmp_path, ab_template)
    workarea = _workarea(base)
    (workarea / "temp").mkdir(exist_ok=True)
    folder = projects.EXTENDED_PREFIX + str(workarea) + "\\" + on_disk
    inner = folder + "\\firmware.s19"
    os.mkdir(folder)
    with open(inner, "wb") as handle:
        handle.write((projects.CASE01_DIR / "firmware.s19").read_bytes())
    try:
        async def _scenario(app, pilot, log):
            return app.list_projects()

        listed = projects.run_app(base, _scenario)
    finally:
        for remove, target in ((os.remove, inner), (os.rmdir, folder)):
            try:
                remove(target)
            except OSError:
                pass
    assert on_disk not in listed, listed
    assert "ab" in listed, listed


class _OsAsPosix:
    """``app.py``'s view of ``os`` with ``os.name == "posix"``; every other
    attribute is the real module's."""

    name = "posix"

    def __getattr__(self, attr):
        return getattr(os, attr)


def test_tc_b100_38_project_list_leaves_a_trailing_dot_name_out_off_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ab_template: Path
) -> None:
    """Inc 12a re-pin (census C1; was
    ``test_tc_b100_38_project_list_keeps_a_trailing_dot_name_off_windows``):
    LLR-172.4e supersedes the CR9-9 platform scope. A project folder
    ``fw-v1.`` holding a data file → ``list_projects`` leaves it out where
    ``os.name == "nt"`` AND where it is not (the lister skips it on every
    platform, LLR-172.4d). On Windows the folder is made through a
    ``\\\\?\\`` path beside a plain ``fw-v1`` (so its ``lstat`` finds a
    folder), and the off-Windows half runs with ``app.py``'s ``os.name``
    seen as ``posix``.

    Why: one rule for the lister and the project list; on ext4 a pick of
    ``fw-v1.`` would load a folder Windows cannot open by that name.
    Negative control: the gate put back → the ``posix`` reading lists
    ``fw-v1.`` → RED."""
    base = _base_with_ab(tmp_path, ab_template)
    workarea = _workarea(base)
    firmware = (projects.CASE01_DIR / "firmware.s19").read_bytes()
    created = []
    if WIN:
        (workarea / "fw-v1").mkdir()
        (workarea / "fw-v1" / "firmware.s19").write_bytes(firmware)
        folder = projects.EXTENDED_PREFIX + str(workarea) + "\\fw-v1."
    else:
        folder = str(workarea / "fw-v1.")
    os.mkdir(folder)
    created.append(folder)
    inner = folder + os.sep + "firmware.s19"
    with open(inner, "wb") as handle:
        handle.write(firmware)
    created.insert(0, inner)
    try:
        async def _scenario(app, pilot, log):
            native = app.list_projects()
            with monkeypatch.context() as patch:
                patch.setattr(app_module, "os", _OsAsPosix())
                off_windows = app.list_projects()
            return native, off_windows

        native, off_windows = projects.run_app(base, _scenario)
    finally:
        for target in created:
            try:
                (os.remove if target == inner else os.rmdir)(target)
            except OSError:
                pass
    assert "fw-v1." not in native, native
    assert "fw-v1." not in off_windows, off_windows
    assert "ab" in native and "ab" in off_windows, (native, off_windows)


@pytest.mark.parametrize(
    "arm",
    [
        pytest.param("name in upper case", marks=CASE_ARM),
        "temp",
        pytest.param("temp::$INDEX_ALLOCATION", marks=WIN32_NAME_ARM),
        pytest.param("8.3 name of templates", marks=WIN32_NAME_ARM),
    ],
)
def test_tc_b100_38_route_matches_the_typed_folder_against_the_listing(
    tmp_path: Path, ab_template: Path, arm: str
) -> None:
    """LLR-172.5 / LLR-172.5b at the route itself (E5 M61, M64, M65):
    ``app._typed_load_route`` of ``<workarea>/AB`` → ``("project", "ab")``
    (the on-disk name); of ``<workarea>/temp`` (holding a work copy),
    ``<workarea>/temp::$INDEX_ALLOCATION`` and the 8.3 name of
    ``templates`` (holding a file) → ``("refuse", "not a project")``.
    ``_handle_load_project`` re-checks the listing (defence in depth), so
    only a direct call shows what the route decided.

    Negative controls: the typed spelling returned → ``("project", "AB")``
    → RED (M61); a case-folded reserved-home test instead of the listing →
    the stream and 8.3 spellings route as projects → RED (M64); the listing
    step removed → ``temp`` routes as a project → RED (M65)."""
    base = _base_with_ab(tmp_path, ab_template)
    workarea = _reserved_fixture(base)
    texts = {
        "name in upper case": str(workarea / "AB"),
        "temp": str(workarea / "temp"),
        "temp::$INDEX_ALLOCATION": str(workarea) + os.sep + "temp::$INDEX_ALLOCATION",
    }
    text = texts.get(arm) or str(workarea / _short_name_of_templates(workarea))
    expected = ("project", "ab") if arm == "name in upper case" else ("refuse", "not a project")

    async def _scenario(app, pilot, log):
        return app._typed_load_route(Path(text))

    assert projects.run_app(base, _scenario) == expected


def _raise_permission(*args, **kwargs):
    raise PermissionError(13, "injected: access denied")


@pytest.mark.parametrize(
    "arm",
    [
        "route: walk lstat",
        "route: list_projects",
        "route: _list_project_files",
        "project load: list_projects",
    ],
)
def test_tc_b100_38_unreadable_folder_paints_could_not_be_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ab_template: Path, arm: str
) -> None:
    """LLR-172.5 family, the four ``OSError`` arms (E5 CR9-6): a
    ``PermissionError`` injected into the typed route's ``os.lstat`` of
    ``<workarea>/ab``, its ``list_projects``, its project-folder listing
    (project ``cd`` holds a data file and no ``project.json``; Inc 9b
    re-pin A9b-R3-1: the listing is ``_list_project_files``, which replaced
    ``validate_project_files`` on this route, R2-N2/R2-N4 — the folder is
    listed fail-open and the route's step 11 refuses it ``unreadable``),
    and ``_handle_load_project``'s ``list_projects`` →
    0 raises, 0 project loads, 0 session resets, 1 line holding ``could not
    be read`` and ``check that the folder can be opened, then load again``.

    Negative control: any of the four catches removed → the
    ``PermissionError`` leaves the dispatcher (the TUI stops) → RED."""
    base = _base_with_ab(tmp_path, ab_template)
    workarea = _workarea(base)
    (workarea / "cd").mkdir()
    shutil.copyfile(projects.CASE01_DIR / "firmware.s19", workarea / "cd" / "firmware.s19")
    target = workarea / ("cd" if arm == "route: _list_project_files" else "ab")
    real_lstat = os.lstat
    key = os.path.normcase(str(target))

    def _lstat(path, *args, **kwargs):
        if not isinstance(path, int) and os.path.normcase(os.fspath(path)) == key:
            raise PermissionError(13, "injected: access denied", os.fspath(path))
        return real_lstat(path, *args, **kwargs)

    async def _scenario(app, pilot, log):
        resets = _spy_resets(monkeypatch)
        mark = len(log.messages)
        with monkeypatch.context() as patch:
            if arm == "route: walk lstat":
                patch.setattr(app_module.os, "lstat", _lstat)
            elif arm == "route: _list_project_files":
                patch.setattr(app_module.S19TuiApp, "_list_project_files", _raise_permission)
            else:
                patch.setattr(app_module.S19TuiApp, "list_projects", _raise_permission)
            try:
                if arm.startswith("route"):
                    app._load_path_from_user_input(Path(str(target)))
                else:
                    app._handle_load_project("ab")
                raised = None
            except Exception as exc:  # noqa: BLE001 — the threshold counts raises
                raised = type(exc).__name__
        for _ in range(10):
            await pilot.pause()
        return raised, log.since(mark), app.current_project, len(resets)

    raised, messages, project, resets = projects.run_app(base, _scenario)
    assert raised is None, (raised, messages)
    assert project is None and resets == 0, (project, resets, messages)
    lines = _with(messages, "could not be read", "check that the folder can be opened, then load again")
    assert len(lines) == 1, messages


@pytest.mark.parametrize(
    "arm",
    [
        "relative found by the base fallback",
        pytest.param("relative junction", marks=JUNCTION_ARM),
        pytest.param("root-relative", marks=ROOT_RELATIVE_ARM),
    ],
)
def test_tc_b100_38_typed_relative_folder_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ab_template: Path, arm: str
) -> None:
    """LLR-172.5h (3 of 3; E3 R2): with a working folder other than the base
    folder, ``.s19tool/workarea/ab`` (found by the base-folder fallback),
    ``.s19tool/workarea/alias`` (a junction to ``ab``, which the fallback's
    ``resolve()`` follows) and the root-relative ``\\…\\.s19tool\\workarea\\ab``
    → 0 project loads, 0 session resets, 0 files copied into ``temp/``, 1
    line holding ``not a supported file`` and ``check the path``.

    RED (base): ``Unsupported file type: `` (an empty suffix), neither
    token. Negative controls: a relative folder sent to the project route →
    ``ab`` loads → RED; ``os.path.isabs`` (true for ``\\x``) → the
    root-relative arm routes as a project → RED."""
    base = _base_with_ab(tmp_path, ab_template)
    workarea = _workarea(base)
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    if arm == "relative found by the base fallback":
        text = os.path.join(WORKAREA_DIRNAME, WORKAREA_SUBDIR, "ab")
    elif arm == "relative junction":
        b100_links.create_junction(workarea / "alias", workarea / "ab")
        text = os.path.join(WORKAREA_DIRNAME, WORKAREA_SUBDIR, "alias")
    else:
        text = "\\" + str((workarea / "ab").relative_to(workarea.anchor))
    temp = workarea / "temp"
    before = sorted(p.name for p in temp.iterdir()) if temp.exists() else []
    messages, project, resets, _, _ = _refusal_scene(base, monkeypatch, text)
    after = sorted(p.name for p in temp.iterdir()) if temp.exists() else []
    assert project is None and resets == 0, (project, resets, messages)
    assert after == before, (before, after)
    assert len(_with(messages, "not a supported file", "check the path")) == 1, messages


# ===========================================================================
# TC-B100-39 — literal Workarea Files rows
# ===========================================================================

HOSTILE_NAMES = {
    "markup bold": "[bold]x.s19",
    "markup link": "[link=x]a.s19",
    "markup action": "[@click=app.bell]x.s19",
    "C1 control U+009B": "a\x9bb.s19",
    "bidi override U+202E": "x\u202egpj.s19",
    "unpaired surrogate U+DC80": "a\udc80b.s19",
    "130 characters": "n" * 126 + ".s19",
}


def _make_named(temp: Path, name: str) -> None:
    temp.mkdir(parents=True, exist_ok=True)
    try:
        (temp / name).write_bytes((projects.CASE01_DIR / "firmware.s19").read_bytes())
    except (OSError, UnicodeError, ValueError) as exc:
        pytest.skip(f"the file name cannot be created here (not run): {exc}")


@pytest.mark.parametrize("label", list(HOSTILE_NAMES))
def test_tc_b100_39_rows_paint_names_literally(tmp_path: Path, label: str) -> None:
    """LLR-172.6 (7 of 7): ``[bold]x.s19``, ``[link=x]a.s19``,
    ``[@click=app.bell]x.s19``, a name holding U+009B, ``x`` + U+202E +
    ``gpj.s19``, ``a`` + U+DC80 + ``b.s19`` and a 130-character name → the
    row's plain text equals the name with every Cc / Cf / Zl / Zp character
    removed and the surrogate as U+FFFD, clipped to 120 characters ending
    in "…"; 0 styled spans; 0 characters of category Cc, Cf or Cs; 0
    raises. The surrogate arm is reported not run where the name cannot be
    created.

    RED (base, e1 probe): the ``[bold]x.s19`` row paints
    ``Content('x.s19', spans=[Span(0, 5, style='bold')])``; the control
    characters are painted. Negative control: ``safe_text(name)`` (C0 / C1
    only) → the U+202E and U+DC80 rows RED."""
    name = HOSTILE_NAMES[label]
    base = tmp_path / "app"
    _make_named(_workarea(base) / "temp", name)

    async def _scenario(app, pilot, log):
        app.refresh_files()
        await pilot.pause()
        return _row_facts(app)

    rows = projects.run_app(base, _scenario)
    assert len(rows) == 1, rows
    plain, spans, _ = rows[0]
    assert plain == _expected_label(name), (ascii(plain), ascii(_expected_label(name)))
    assert spans == [], spans
    assert _scrubbed_categories(plain) == [], ascii(plain)


@pytest.mark.parametrize(
    "label", ["markup bold", "C1 control U+009B", "bidi override U+202E", "130 characters"]
)
def test_tc_b100_39_picked_row_loads_the_file_as_named(tmp_path: Path, label: str) -> None:
    """LLR-172.6a (4 of 4): picking the ``[bold]x.s19`` row, the U+009B
    row, the U+202E row and the 130-character row (its label clipped) →
    ``current_file.path.name`` equals the on-disk name.

    Declared (requirement): holds at the base (``item.data`` is the on-disk
    name), so the mutation is the only RED: the painted label stored as the
    row's name → the U+009B pick finds no file → RED."""
    name = HOSTILE_NAMES[label]
    base = tmp_path / "app"
    _make_named(_workarea(base) / "temp", name)

    async def _scenario(app, pilot, log):
        from textual.widgets import ListView

        app.refresh_files()
        await pilot.pause()
        rows = list(app.query_one("#files_list", ListView).children)
        app._load_from_item(rows[0])
        await settle_workers(pilot)  # Inc 12b R-5: the data pick is a worker
        for _ in range(300):
            if app.current_file is not None:
                break
            await pilot.pause()
        return len(rows), (app.current_file.path.name if app.current_file else None)

    count, loaded = projects.run_app(base, _scenario)
    assert count == 1
    assert loaded == name, (ascii(loaded), ascii(name))


# ===========================================================================
# Acceptance — AT-B100-12 / AT-B100-13 through keys and dialogs
# ===========================================================================


async def _at_load_file(pilot, app, text: str) -> None:
    """``l`` (Load file), type ``text`` into the path field, click OK."""
    from tests.support.b100_load_dialog import highlight_row, is_load_dialog

    await pilot.press("l")
    await projects.wait_for(pilot, lambda: is_load_dialog(app.screen), "the Load dialog")
    assert await pilot.click("#load_path"), "click missed #load_path"
    await pilot.press("ctrl+a")
    await pilot.press("delete")
    await pilot.press(*text)
    assert await pilot.click("#load_ok"), "click missed #load_ok"
    await projects.wait_for(
        pilot, lambda: not is_load_dialog(app.screen), "the Load dialog to close"
    )


@STORE_WRITE
@pytest.mark.parametrize("size", AT_SIZES)
def test_at_b100_12_outside_load_is_remembered_and_typed_project_path_opens(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ab_template: Path, size: tuple
) -> None:
    """HLR-172 / HLR-172a acceptance scene by keys and dialogs (two
    independent halves at 9a, E3 R13). Store half: Load (``l``) typed the
    absolute path of ``examples/case_01_basic_valid/firmware.s19`` → the
    per-user store on disk (``LOCALAPPDATA`` pointed at a temporary folder)
    reads ``{"schema_version": 1, "sources": [{"path": <that absolute path>,
    "kind": "s19"}]}`` and 0 files named ``recent_sources.json`` are under
    the base folder. Typed half: Load (``l``) typed the absolute work-area
    path of project ``ab`` → the status log names project ``ab`` loaded and
    the Load-result panel opens on top (ruling Q3); ``esc`` closes it; the
    store still holds the one entry. Both reference sizes. Windows only:
    the store half needs a drive-rooted ``LOCALAPPDATA`` (E3 R12).

    RED (base): no store file after the load; typed ``<workarea>/ab`` →
    ``['Unsupported file type: ']``, no project."""
    base = _base_with_ab(tmp_path, ab_template)
    store = _store_of(_lad(tmp_path, monkeypatch))
    example = projects.CASE01_DIR / "firmware.s19"
    typed_example = os.path.abspath(str(example))

    async def _scene():
        from s19_app.tui.app import S19TuiApp
        from s19_app.tui.screens import LoadResultScreen

        app = S19TuiApp(base_dir=base)
        log = projects.StatusLog(app)
        async with app.run_test(size=size, notifications=True) as pilot:
            await pilot.pause()
            await _at_load_file(pilot, app, typed_example)
            await _wait_image(pilot, app, "firmware.s19")
            store_half = _entries(store)
            mark = len(log.messages)
            await _at_load_file(pilot, app, str(_workarea(base) / "ab"))
            for _ in range(300):
                if isinstance(app.screen, LoadResultScreen) or _with(log.since(mark), "NOT loaded") or _with(
                    log.since(mark), "Unsupported"
                ):
                    break
                await pilot.pause()
            panel = isinstance(app.screen, LoadResultScreen)
            if panel:
                await projects.dismiss_load_result_panel(pilot, app)
            return store_half, log.since(mark), app.current_project, panel

    store_half, typed_messages, project, panel = asyncio.run(_scene())
    assert store_half == [(typed_example, "s19")], store_half
    assert _named_store_files(base) == []
    assert project == "ab", (project, typed_messages)
    assert len(_loaded_ab(typed_messages)) == 1, typed_messages
    assert panel, "the Load-result panel did not open for the typed project (Q3)"
    assert _entries(store) == [(typed_example, "s19")]


@pytest.mark.parametrize("size", AT_SIZES)
def test_at_b100_13_workarea_files_show_names_as_named(tmp_path: Path, size: tuple) -> None:
    """HLR-172b acceptance scene by keys: files named ``[bold]x.s19``,
    ``[link=x]a.s19``, ``[@click=app.bell]x.s19`` and one with U+009B in the
    work area; ``r`` (refresh) → the Workarea Files list (``#files_list``)
    shows 4 rows whose plain text equals each name minus control
    characters, with 0 styled spans and 0 control characters. Both
    reference sizes.

    RED (base, e1 probe): the ``[bold]x.s19`` row paints ``x.s19`` in bold;
    U+009B is painted."""
    names = ["[bold]x.s19", "[link=x]a.s19", "[@click=app.bell]x.s19", "a\x9bb.s19"]
    base = tmp_path / "app"
    temp = _workarea(base) / "temp"
    for name in names:
        _make_named(temp, name)

    async def _scene():
        from s19_app.tui.app import S19TuiApp

        app = S19TuiApp(base_dir=base)
        async with app.run_test(size=size, notifications=True) as pilot:
            await pilot.pause()
            await pilot.press("r")
            for _ in range(6):
                await pilot.pause()
            return _row_facts(app)

    rows = asyncio.run(_scene())
    assert len(rows) == 4, rows
    painted = sorted(plain for plain, _, _ in rows)
    assert painted == sorted(_expected_label(n) for n in names), [ascii(p) for p in painted]
    assert [spans for _, spans, _ in rows] == [[], [], [], []], rows
    assert all(_scrubbed_categories(plain) == [] for plain, _, _ in rows), [ascii(p) for p, _, _ in rows]


# ===========================================================================
# Inc 9b — TC-B100-34 (LLR-172.1n, CR9-1) and TC-B100-37 widened (LLR-173.4b,
# CR9-11). Written by the Inc 9b tester from inc-9b/E1-requirements-draft.md
# and inc-9b/codewire/proto-9b-app.md (B24 … B30, B37).
# ===========================================================================


def _fallback_scene(base: Path, monkeypatch: pytest.MonkeyPatch, cwd: Path, typed: str, a2l: bool = False):
    """With the working folder ``cwd``, run the shipped typed-path dispatcher
    on ``typed``; return (status messages, installed file name or A2L name)."""
    monkeypatch.chdir(cwd)

    async def _scenario(app, pilot, log):
        mark = len(log.messages)
        app._load_path_from_user_input(Path(typed))
        if a2l:
            await _wait_a2l(pilot, app)
            name = app.current_a2l_path.name
        else:
            await projects.wait_for(pilot, lambda: app.current_file is not None, "the typed load")
            name = app.current_file.path.name
        for _ in range(8):
            await pilot.pause()
        return log.since(mark), name

    return projects.run_app(base, _scenario)


@STORE_WRITE
@JUNCTION_ARM
def test_tc_b100_34_source_found_through_a_junction_fallback_is_not_recorded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-172.1n arm 1 + control arm 4 (B24, B27; CR9-1; Windows only): the
    working folder ``Wd`` is not the base folder ``B``, and ``B\\j`` is a
    junction to ``R`` holding ``x.s19``. Typed ``j\\x.s19`` (relative, found
    only through the base-folder fallback, whose ``resolve()`` follows the
    junction) → 1 load, the store bytes unchanged, 0 ``Recent sources not
    updated`` lines. Control: typed absolute ``B\\j\\x.s19`` → 1 entry
    ``B\\j\\x.s19`` (the link not followed, LLR-172.1a).

    Why: the fallback's resolved path follows links (against LLR-172.1a),
    and on a mapped drive it records a UNC path the store refuses with a
    warning on every load.
    RED (base, executed probe CR9-1): the store gains ``R\\x.s19``."""
    store = _store_of(_lad(tmp_path, monkeypatch))
    seed = _seed(store, [_entry("C:\\seed\\s.s19")])
    base = tmp_path / "B"
    base.mkdir()
    real = tmp_path / "R"
    real.mkdir()
    shutil.copyfile(projects.CASE01_DIR / "firmware.s19", real / "x.s19")
    b100_links.create_junction(base / "j", real)
    work = tmp_path / "Wd"
    work.mkdir()
    messages, name = _fallback_scene(base, monkeypatch, work, os.path.join("j", "x.s19"))
    assert name == "x.s19", messages
    assert _sha(store) == seed, _entries(store)
    assert _with(messages, "Recent sources not updated") == [], messages
    _, name = _fallback_scene(tmp_path / "B2", monkeypatch, work, str(base / "j" / "x.s19"))
    assert name == "x.s19"
    assert _entries(store)[0] == (str(base / "j" / "x.s19"), "s19"), _entries(store)


@STORE_WRITE
def test_tc_b100_34_source_found_only_in_the_base_folder_is_not_recorded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-172.1n arm 2 + control arm 3 (B25, B26): typed ``fw.s19`` from a
    working folder ``Wd`` where it does not exist, present only in the base
    folder ``B`` → 1 load, the store bytes unchanged. Control: the same
    typed ``fw.s19`` with the working folder ``B`` (found as typed) → 1
    entry whose path is ``os.path.abspath("fw.s19")`` = ``B\\fw.s19``.

    Why: "found only through the fallback" means the typed text is relative
    and does not exist relative to the working folder; such a source is not
    the file the engineer named, so it is not remembered (ruling Q1).
    Negative control: the ``via_fallback`` condition dropped → arm 2
    records ``B\\fw.s19`` → RED. RED (base): arm 2 records it."""
    store = _store_of(_lad(tmp_path, monkeypatch))
    seed = _seed(store, [_entry("C:\\seed\\s.s19")])
    base = tmp_path / "B"
    base.mkdir()
    shutil.copyfile(projects.CASE01_DIR / "firmware.s19", base / "fw.s19")
    work = tmp_path / "Wd"
    work.mkdir()
    messages, name = _fallback_scene(base, monkeypatch, work, "fw.s19")
    assert name == "fw.s19", messages
    assert _sha(store) == seed, _entries(store)
    assert _with(messages, "Recent sources not updated") == [], messages
    _, name = _fallback_scene(base, monkeypatch, base, "fw.s19")
    assert name == "fw.s19"
    assert _entries(store)[0] == (os.path.abspath(str(base / "fw.s19")), "s19"), _entries(store)


@STORE_WRITE
def test_tc_b100_34_a2l_found_only_through_the_fallback_is_not_recorded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-172.1n, the A2L arm (B30, F-6 — proposed as arm 5 of TC-B100-34):
    typed relative ``cal.a2l``, present only in the base folder, from a
    working folder ``Wd`` → ``A2L loaded: cal.a2l`` and the store bytes
    unchanged; the same file typed absolute → 1 entry ``B\\cal.a2l``, kind
    ``a2l``.

    Negative control: the condition removed from ``load_a2l_from_path``
    only → 1 entry after the relative load → RED. RED (base): the relative
    load records ``B\\cal.a2l``."""
    store = _store_of(_lad(tmp_path, monkeypatch))
    seed = _seed(store, [_entry("C:\\seed\\s.s19")])
    base = tmp_path / "B"
    base.mkdir()
    shutil.copyfile(projects.CASE01_DIR / "firmware.a2l", base / "cal.a2l")
    work = tmp_path / "Wd"
    work.mkdir()
    messages, name = _fallback_scene(base, monkeypatch, work, "cal.a2l", a2l=True)
    assert name == "cal.a2l" and _with(messages, "A2L loaded: cal.a2l"), messages
    assert _sha(store) == seed, _entries(store)
    _fallback_scene(tmp_path / "B2", monkeypatch, work, str(base / "cal.a2l"), a2l=True)
    assert _entries(store)[0] == (str(base / "cal.a2l"), "a2l"), _entries(store)


def _refers_to_temp_widened(node, names: set) -> bool:
    """``_refers_to_temp`` plus CR9-11's reach: a string literal equal to
    ``temp`` in any letter case."""
    if _refers_to_temp(node, names):
        return True
    for sub in ast.walk(node):
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str) and sub.value.casefold() == "temp":
            return True
    return False


def _temp_enumerators_widened(root: Path) -> list:
    """The TC-B100-37 census of ``_temp_enumerators`` with the widened temp
    test (a literal ``"temp"`` joined to a path expression counts)."""
    found = []
    for path in sorted((root / "s19_app").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for function in ast.walk(tree):
            if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            names: set = set()
            changed = True
            while changed:
                changed = False
                for sub in ast.walk(function):
                    if isinstance(sub, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                        targets = sub.targets if isinstance(sub, ast.Assign) else [sub.target]
                        value = sub.value
                        if (
                            value is not None
                            and isinstance(value, (ast.BinOp, ast.Call, ast.Attribute, ast.Name))
                            and _refers_to_temp_widened(value, names)
                        ):
                            for target in targets:
                                for leaf in ast.walk(target):
                                    if isinstance(leaf, ast.Name) and leaf.id not in names:
                                        names.add(leaf.id)
                                        changed = True
            for sub in ast.walk(function):
                if not isinstance(sub, ast.Call):
                    continue
                func = sub.func
                callee = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
                target_expr = None
                if isinstance(func, ast.Attribute) and func.attr in _ENUM_METHODS:
                    target_expr = func.value
                elif callee in _ENUM_FUNCTIONS and sub.args:
                    target_expr = sub.args[0]
                if target_expr is None or isinstance(target_expr, ast.Constant):
                    continue
                if _refers_to_temp_widened(target_expr, names):
                    entry = (path.relative_to(root).as_posix(), function.name)
                    if entry not in found:
                        found.append(entry)
    return found


def test_tc_b100_37_widened_census_and_one_enumeration_at_dialog_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-173.4b, LLR-172.4 widened (B37, CR9-11; 2 of the 3 arms, the row
    arm is in ``test_b100_load_dialog.py``): (1) the TC-B100-37 census
    widened to count a string literal equal to ``temp`` in any letter case
    joined to a path expression → exactly 1 enumerating function,
    ``list_workarea_files`` in ``workspace.py``; (2) a runtime spy on
    ``os.scandir``, ``os.listdir``, ``Path.iterdir`` and ``Path.glob``
    during one Load dialog open (``l``) → ``temp/`` enumerated exactly once,
    from inside ``list_workarea_files``.

    Why: the 9a census saw only ``WORKAREA_TEMP``; a second lister written
    with the literal ``"temp"`` escaped it (CR9-11), and two listers can
    disagree about what the work area holds.
    Negative control: a dialog section built as ``(self.workarea /
    "temp").iterdir()`` → census 2 functions and spy 2 enumerations → RED.
    RED (base): the base Load dialog has no files section, so the spy sees
    0 enumerations at dialog open (arm 1 holds on the base and is RED only
    as that mutation)."""
    found = _temp_enumerators_widened(projects.ROOT)
    assert found == [("s19_app/tui/workspace.py", "list_workarea_files")], found

    from tests.support import b100_load_dialog as ld

    base = tmp_path / "app"
    temp = _workarea(base) / workspace_module.WORKAREA_TEMP
    temp.mkdir(parents=True)
    shutil.copyfile(projects.CASE01_DIR / "firmware.s19", temp / "a.s19")
    key = os.path.normcase(str(temp))
    seen: list = []
    real = {
        "scandir": os.scandir,
        "listdir": os.listdir,
        "iterdir": pathlib.Path.iterdir,
        "glob": pathlib.Path.glob,
    }

    def note(target, how) -> None:
        try:
            if os.path.normcase(os.fspath(target)) != key:
                return
        except TypeError:
            return
        frames, frame = [], sys._getframe(2)
        while frame is not None:
            frames.append(frame.f_code.co_name)
            frame = frame.f_back
        seen.append((how, "list_workarea_files" in frames))

    def scandir(path=".", *a, **k):
        note(path, "scandir")
        return real["scandir"](path, *a, **k)

    def listdir(path=".", *a, **k):
        note(path, "listdir")
        return real["listdir"](path, *a, **k)

    def iterdir(self):
        note(self, "iterdir")
        return real["iterdir"](self)

    def glob(self, *a, **k):
        note(self, "glob")
        return real["glob"](self, *a, **k)

    async def _scenario(app, pilot, log):
        await pilot.press("1")
        for _ in range(4):
            await pilot.pause()
        with monkeypatch.context() as patch:
            patch.setattr(os, "scandir", scandir)
            patch.setattr(os, "listdir", listdir)
            patch.setattr(pathlib.Path, "iterdir", iterdir)
            patch.setattr(pathlib.Path, "glob", glob)
            await pilot.press("l")
            for _ in range(12):
                await pilot.pause()
        return ld.is_load_dialog(app.screen), list(seen)

    opened, enumerations = projects.run_app(base, _scenario, size=(118, 54))
    assert opened, "l did not open the Load dialog"
    assert len(enumerations) == 1 and enumerations[0][1], enumerations


# ===========================================================================
# Inc 12a — the backlog sweep (TC-B100-37, TC-B100-38, TC-B100-39 new arms)
# LLR-172.4e, LLR-172.4f, LLR-172.5i, LLR-172.5j, LLR-172.5k, LLR-172.6b,
# LLR-172.6c. Oracles: inc-12a codewire/proto-12a-sweep.md (B12-NN).
# ===========================================================================

_APP_SOURCE = Path(app_module.__file__)
NOT_REGULAR = "File NOT loaded: '{name}' is not a regular file — pick another file."
TOO_LARGE_LINE = "File NOT loaded: '{name}' is too large to open — load a smaller file."


def _sweep_methods() -> dict:
    tree = ast.parse(_APP_SOURCE.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "S19TuiApp":
            return {
                item.name: item for item in node.body
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
    raise AssertionError("S19TuiApp not found")


def _calls_named(node, name: str) -> int:
    count = 0
    for inner in ast.walk(node):
        if isinstance(inner, ast.Call):
            func = inner.func
            callee = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
            if callee == name:
                count += 1
    return count


def test_tc_b100_37_project_list_skips_a_trailing_dot_on_every_platform(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-172.4e (B12-07, E2 ruling G-B P-B1): ``fw-v1.`` and ``fw-v2 ``,
    each holding ``project.json`` and ``firmware.s19``, beside project ``P``
    → neither is listed, natively and with ``app.py``'s ``os`` seen as
    ``posix`` (the Linux arm, run on this host too); ``P`` is listed. On
    Windows the two folders are made through ``\\\\?\\`` beside plain
    ``fw-v1`` / ``fw-v2`` folders holding a data file (so their ``lstat``
    finds a folder; the plain ones are ordinary projects and may be listed);
    on Linux the list is exactly ``["P"]``.

    Why: Win32 opens ``fw-v1.`` as ``fw-v1``, so a listed dot name loads
    another folder; one rule on every platform matches the lister
    (LLR-172.4d).
    Negative control (P12a-4): the ``os.name == "nt"`` gate present → the
    ``posix`` reading lists both → RED on every host."""
    import json

    base = tmp_path / "app"
    workarea = _workarea(base)
    firmware = (projects.CASE01_DIR / "firmware.s19").read_bytes()
    manifest = json.dumps({"schema_version": 1}).encode("utf-8")
    p_dir = workarea / "P"
    p_dir.mkdir(parents=True)
    (p_dir / "firmware.s19").write_bytes(firmware)
    (p_dir / "project.json").write_bytes(manifest)
    created: list = []
    for name in ("fw-v1.", "fw-v2 "):
        if WIN:
            plain = workarea / name.rstrip(". ")
            plain.mkdir()
            (plain / "firmware.s19").write_bytes(firmware)
            folder = projects.EXTENDED_PREFIX + str(workarea) + "\\" + name
        else:
            folder = str(workarea / name)
        os.mkdir(folder)
        created.append(("dir", folder))
        for inner_name, payload in (("firmware.s19", firmware), ("project.json", manifest)):
            inner = folder + os.sep + inner_name
            with open(inner, "wb") as handle:
                handle.write(payload)
            created.insert(0, ("file", inner))
    try:
        async def _scenario(app, pilot, log):
            native = app.list_projects()
            with monkeypatch.context() as patch:
                patch.setattr(app_module, "os", _OsAsPosix())
                posix = app.list_projects()
            return native, posix

        native, posix = projects.run_app(base, _scenario)
    finally:
        for kind, target in created:
            try:
                (os.remove if kind == "file" else os.rmdir)(target)
            except OSError:
                pass
    for listed in (native, posix):
        assert "P" in listed, listed
        assert "fw-v1." not in listed and "fw-v2 " not in listed, listed
    if not WIN:
        assert native == ["P"] and posix == ["P"], (native, posix)


def _files_rows(app) -> list:
    from textual.widgets import ListView

    return [getattr(item, "data", None) for item in app.query_one("#files_list", ListView).children]


@pytest.mark.parametrize(
    "contents, expected",
    [
        (["a.s19", "b.hex", "c.mac", "d.a2l", "d.a2l.json", "e.txt"], ["a.s19", "b.hex", "c.mac", "d.a2l"]),
        (["F.S19", "g.srec", "h.ihex", "notes", "x.a2l.json"], ["F.S19", "g.srec", "h.ihex"]),
        (["d.a2l.json"], []),
    ],
    ids=["mixed", "suffix boundaries", "only a sidecar"],
)
def test_tc_b100_37_files_list_shows_loadable_suffixes_only(
    tmp_path: Path, contents: list, expected: list
) -> None:
    """LLR-172.4f, C7 (B12-11, B12-12): ``temp`` holding ``a.s19``,
    ``b.hex``, ``c.mac``, ``d.a2l``, ``d.a2l.json`` and ``e.txt`` → the
    Workarea Files rows are the 4 loadable names, 0 rows for the sidecar or
    the text file; ``F.S19`` (upper case), ``g.srec`` and ``h.ihex`` are
    listed and ``notes`` / ``x.a2l.json`` are not; a ``temp`` holding only
    a sidecar dump → 0 rows.

    Why: a row the loaders refuse invites a pick that can only fail.
    RED (base, C7, probe p12a U2.1): every regular file is listed (6 rows)."""
    base = tmp_path / "app"
    temp = _workarea(base) / "temp"
    temp.mkdir(parents=True)
    for name in contents:
        (temp / name).write_bytes(b"x")

    async def _scenario(app, pilot, log):
        app.refresh_files()
        await pilot.pause()
        return _files_rows(app)

    rows = projects.run_app(base, _scenario)
    assert sorted(rows, key=str.casefold) == sorted(expected, key=str.casefold), rows


def test_tc_b100_37_files_list_shows_loadable_suffixes_only_through_one_predicate() -> None:
    """LLR-172.4f (B12-13, interfaces S-h): an AST read of ``app.py`` finds
    a ``recent_kind(...)`` call in ``refresh_files`` and in
    ``_load_dialog_rows`` (2 of 2), and ``refresh_files`` compares nothing
    against a literal collection (no second suffix set).

    Why: two suffix rules drift; the row count alone passes a mutant that
    copies the suffix set into ``refresh_files``.
    RED (base): ``refresh_files`` has no ``recent_kind`` call."""
    methods = _sweep_methods()
    assert _calls_named(methods["refresh_files"], "recent_kind") >= 1, "refresh_files"
    assert _calls_named(methods["_load_dialog_rows"], "recent_kind") >= 1, "_load_dialog_rows"
    literal_suffix_tests = [
        node.lineno for node in ast.walk(methods["refresh_files"])
        if isinstance(node, ast.Compare)
        and any(isinstance(c, (ast.Set, ast.Tuple, ast.List)) for c in node.comparators)
    ]
    assert literal_suffix_tests == [], literal_suffix_tests


def _load_reason(screen) -> str:
    from textual.widgets import Static

    found = list(screen.query("#load_reason Static")) or [screen.query_one("#load_reason")]
    texts = []
    for widget in found:
        if isinstance(widget, Static):
            visual = getattr(widget, "visual", None) or widget.render()
            texts.append(str(getattr(visual, "plain", visual)))
    return " ".join(" ".join(texts).split())


@pytest.mark.parametrize(
    "arm, route",
    [
        ("relative NUL", "status"),
        ("absolute NUL", "status"),
        ("relative NUL", "dialog"),
        ("absolute NUL", "dialog"),
        ("EACCES", "status"),
        ("ENAMETOOLONG", "status"),
        ("EACCES", "dialog"),
        ("ENAMETOOLONG", "dialog"),
    ],
)
def test_tc_b100_38_nul_in_typed_path_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: str, route: str
) -> None:
    """LLR-172.5i, S12a-01 (B12-15, B12-16, B12-21, B12-22, B12-38): a typed
    text that the operating system's path calls refuse — a NUL (relative
    and absolute), or a text whose ``Path.exists`` raises ``PermissionError``
    (EACCES) or ``OSError(ENAMETOOLONG)`` — through the status-line route
    (``_load_path_from_user_input``) and through the Load dialog
    (``#load_reason``) → 0 exceptions, 0 loads, the ``not found`` and
    ``check the path`` tokens painted, the dialog left open.

    The NUL arms are regression arms, declared GREEN on the post-9b base
    (E3 S12a-01, interfaces S-j); the EACCES / ENAMETOOLONG arms are the
    requirement's RED.
    Why: a typed text must never stop the app.
    Negative control: the catch narrowed to ``ValueError`` /
    ``RuntimeError`` → the ``PermissionError`` leaves the classifier."""
    import errno
    import pathlib

    from tests.support import b100_load_dialog as ld

    base = tmp_path / "app"
    texts = {
        "relative NUL": "fw\x00.s19",
        "absolute NUL": str(tmp_path / "src") + os.sep + "fw\x00.s19",
        "EACCES": "fw_eacces.s19",
        "ENAMETOOLONG": "fw_toolong.s19",
    }
    text = texts[arm]
    if arm in ("EACCES", "ENAMETOOLONG"):
        error = (
            PermissionError(errno.EACCES, "injected: access denied", text)
            if arm == "EACCES"
            else OSError(errno.ENAMETOOLONG, "injected: name too long", text)
        )
        real_exists = pathlib.Path.exists

        def _exists(self, *args, **kwargs):
            if str(self) == text:
                raise error
            return real_exists(self, *args, **kwargs)

        monkeypatch.setattr(pathlib.Path, "exists", _exists)
    loads: list = []
    monkeypatch.setattr(app_module.S19TuiApp, "load_from_path", lambda self, p: loads.append(p))
    monkeypatch.setattr(app_module.S19TuiApp, "load_a2l_from_path", lambda self, p: loads.append(p))

    async def _scenario(app, pilot, log):
        from textual.widgets import Input

        mark = len(log.messages)
        raised = None
        if route == "status":
            try:
                app._load_path_from_user_input(Path(text))
            except Exception as exc:  # noqa: BLE001 — the threshold counts raises
                raised = repr(exc)
            for _ in range(6):
                await pilot.pause()
            return raised, log.since(mark), None, None, app.current_file
        await pilot.press("l")
        await ld.wait_for_dialog(pilot, app)
        for _ in range(3):
            await pilot.pause()
        app.screen.query_one("#load_path", Input).value = text
        await pilot.press("enter")
        for _ in range(6):
            await pilot.pause()
        return raised, log.since(mark), ld.is_load_dialog(app.screen), _load_reason(app.screen), app.current_file

    raised, messages, still_open, reason, current = projects.run_app(base, _scenario, size=(118, 54))
    assert raised is None, (raised, messages)
    assert loads == [] and current is None, (loads, current)
    if route == "status":
        lines = [m for m in messages if "not found" in m and "check the path" in m]
        assert len(lines) == 1 and lines[0].startswith("File NOT loaded: "), messages
    else:
        assert still_open is True, "the dialog closed on a refused text"
        assert "not found" in reason and "check the path" in reason, reason
        assert messages == [], messages


def test_tc_b100_38_one_project_match() -> None:
    """LLR-172.5j (B12-20): exactly one function in ``app.py`` compares a
    name against the project list — every method that calls both
    ``list_projects`` and ``os.path.normcase`` is ``_listed_project_name``.

    Why: two copies of the match drift (CR9-7).
    RED (base, P12a-4): ``_handle_load_project`` and ``_typed_load_route``."""
    holders = []
    for name, node in _sweep_methods().items():
        if _calls_named(node, "list_projects") and _calls_named(node, "normcase"):
            holders.append(name)
    assert holders == ["_listed_project_name"], holders


def test_tc_b100_38_one_project_match_returns_the_listed_spelling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-172.5j (B12-19): with ``ab`` and ``cd`` listed,
    ``_listed_project_name`` maps ``ab`` → ``ab``, ``AB`` → ``ab`` on
    Windows and ``None`` elsewhere, ``ab.`` → ``None``, ``zz`` → ``None``,
    ``""`` → ``None``; an ``OSError`` from the listing propagates.

    Why: the one match returns the on-disk spelling (E3 R3), never the typed
    one, and never matches a trailing-dot alias.
    RED (base): no ``_listed_project_name``."""
    base = tmp_path / "app"
    for name in ("ab", "cd"):
        folder = _workarea(base) / name
        folder.mkdir(parents=True)
        (folder / "firmware.s19").write_bytes((projects.CASE01_DIR / "firmware.s19").read_bytes())

    async def _scenario(app, pilot, log):
        out = {text: app._listed_project_name(text) for text in ("ab", "AB", "ab.", "zz", "")}
        with monkeypatch.context() as patch:
            patch.setattr(app, "list_projects", _raise_permission)
            try:
                app._listed_project_name("ab")
                raised = None
            except PermissionError as exc:
                raised = type(exc).__name__
        return out, raised

    out, raised = projects.run_app(base, _scenario)
    assert out == {"ab": "ab", "AB": "ab" if WIN else None, "ab.": None, "zz": None, "": None}, out
    assert raised == "PermissionError", raised


def test_tc_b100_38_one_project_match_prefers_the_exact_listed_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-172.5j (SE5-12a-3): with ``Proj`` and ``proj`` both listed (a
    case-sensitive folder), ``_listed_project_name`` maps ``proj`` → ``proj``
    and ``Proj`` → ``Proj``; ``PROJ`` → the first ``normcase`` match
    ``Proj`` on Windows, ``None`` elsewhere.

    Why: the picked row carries the exact on-disk name; the first
    case-insensitive hit would open a different project from the one picked.
    The listing is injected so the arm runs on a case-insensitive volume.
    RED (71376a3, Windows): ``proj`` → ``Proj``."""
    base = tmp_path / "app"

    async def _scenario(app, pilot, log):
        monkeypatch.setattr(app, "list_projects", lambda: ["Proj", "proj"])
        return {text: app._listed_project_name(text) for text in ("proj", "Proj", "PROJ")}

    out = projects.run_app(base, _scenario)
    assert out == {"proj": "proj", "Proj": "Proj", "PROJ": "Proj" if WIN else None}, out


def test_tc_b100_38_picking_proj_loads_proj_when_proj_differs_by_case(tmp_path: Path) -> None:
    """LLR-172.5j (SE5-12a-3), on disk: folders ``Proj`` and ``proj`` both
    hold a data file; picking ``proj`` → ``current_project == "proj"``.

    Skipped (reported not run) when the volume is case-insensitive and
    cannot hold both folders — the default on NTFS.
    RED (71376a3, a case-sensitive Windows folder): ``Proj`` is loaded."""
    base = tmp_path / "app"
    workarea = _workarea(base)
    upper = workarea / "Proj"
    upper.mkdir(parents=True)
    lower = workarea / "proj"
    try:
        lower.mkdir()
    except FileExistsError:
        pytest.skip("the volume is case-insensitive: Proj and proj cannot both exist (not run)")
    if os.path.samefile(upper, lower):
        pytest.skip("the volume is case-insensitive: Proj and proj are one folder (not run)")
    for folder in (upper, lower):
        (folder / "firmware.s19").write_bytes((projects.CASE01_DIR / "firmware.s19").read_bytes())

    async def _scenario(app, pilot, log):
        messages = await _project_load(pilot, app, log, "proj")
        return messages, app.current_project

    messages, project = projects.run_app(base, _scenario)
    assert project == "proj", (project, messages)


def _literal_texts(function) -> list:
    """Every ``str`` literal text in ``function`` (docstring excluded); an
    f-string reads with its placeholders written ``{}``."""
    body = list(function.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant):
        body = body[1:]
    texts: list = []
    inside: set = set()
    module = ast.Module(body=body, type_ignores=[])
    for node in ast.walk(module):
        if isinstance(node, ast.JoinedStr):
            parts = []
            for value in node.values:
                inside.add(id(value))
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    parts.append(value.value)
                else:
                    parts.append("{}")
            texts.append("".join(parts))
    for node in ast.walk(module):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in inside:
            texts.append(node.value)
    return texts


def _token_reads(function, key: str) -> int:
    count = 0
    for node in ast.walk(function):
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Name)
            and node.value.id == "_TYPED_REFUSAL_TOKENS"
            and isinstance(node.slice, ast.Constant)
            and node.slice.value == key
        ):
            count += 1
    return count


def test_tc_b100_38_one_wording_table() -> None:
    """LLR-172.5k, A12a-01, ruling Q-7 (B12-37): in ``_handle_load_project``,
    ``_load_path_from_user_input`` and ``_typed_load_route``, 0 literal
    texts hold ``Project NOT loaded`` together with ``not a project`` or
    ``could not be read``; the module defines each of the two token pairs
    once; and the two painting functions read both pairs from
    ``_TYPED_REFUSAL_TOKENS``. No exact site count is asserted (A12a-01).

    Why: hand-written copies of one refusal drift apart (CR9-7).
    RED (base, P12a-4): 5 to 7 literal sentences."""
    methods = _sweep_methods()
    literal = []
    for name in ("_handle_load_project", "_load_path_from_user_input", "_typed_load_route"):
        for text in _literal_texts(methods[name]):
            if "Project NOT loaded" in text and ("not a project" in text or "could not be read" in text):
                literal.append((name, text))
    assert literal == [], literal
    tree = ast.parse(_APP_SOURCE.read_text(encoding="utf-8"))
    pairs = {
        ("not a project", "pick a project in the list"): 0,
        ("could not be read", "check that the folder can be opened, then load again"): 0,
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Tuple) and len(node.elts) == 2 and all(
            isinstance(e, ast.Constant) and isinstance(e.value, str) for e in node.elts
        ):
            key = (node.elts[0].value, node.elts[1].value)
            if key in pairs:
                pairs[key] += 1
    assert list(pairs.values()) == [1, 1], pairs
    for name in ("_handle_load_project", "_load_path_from_user_input"):
        assert _token_reads(methods[name], "not a project") >= 1, name
        assert _token_reads(methods[name], "unreadable") >= 1, name


def _parse_spy(monkeypatch: pytest.MonkeyPatch) -> list:
    calls: list = []
    original = app_module.S19TuiApp._parse_loaded_file

    def _parse(self, path, *args, **kwargs):
        calls.append(Path(path).name)
        return original(self, path, *args, **kwargs)

    monkeypatch.setattr(app_module.S19TuiApp, "_parse_loaded_file", _parse)
    return calls


def _replace_entry(temp: Path, outside: Path, arm: str) -> None:
    """Replace ``temp/fw.s19`` by a folder, a junction (a directory link off
    Windows) or a file link to a file outside the work area."""
    entry = temp / "fw.s19"
    entry.unlink()
    if arm == "folder":
        entry.mkdir()
    elif arm == "junction":
        target = outside / "dir"
        target.mkdir(exist_ok=True)
        if WIN:
            b100_links.create_junction(entry, target)
        else:
            os.symlink(target, entry, target_is_directory=True)
    else:
        target = outside / "outside.s19"
        target.write_bytes((projects.CASE01_DIR / "firmware.s19").read_bytes())
        try:
            os.symlink(target, entry)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"file symbolic link cannot be made here (arm (c) reported not run): {exc}")


@pytest.mark.parametrize("route", ["files list", "load dialog"])
@pytest.mark.parametrize("arm", ["folder", "junction", "file link"])
def test_tc_b100_39_pick_rechecks_the_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: str, route: str
) -> None:
    """LLR-172.6b, SEC9-2 (B12-27, B12-28, B12-29, B12-30): ``fw.s19`` is
    listed (Workarea Files, or the Load dialog's Work area row), then
    replaced before the pick by a folder, a junction (a directory link off
    Windows) or a file link to a file outside the work area → 1 status line
    ``File NOT loaded: 'fw.s19' is not a regular file — pick another file.``,
    0 parses of ``fw.s19``, nothing installed. The dialog route refuses
    after the dialog closed (E2 ruling B5: a status line, never
    ``#load_reason``). The file-link arm needs the symbolic-link privilege;
    where it cannot be made it is reported not run, never passed.

    Why: the row was painted before the entry changed; ``exists()`` follows a
    link, so the pick would parse a file outside the work area.
    RED (base, probe p12a U2.2–U2.4): the pick parses the swapped entry."""
    from textual.widgets import ListView

    from tests.support import b100_load_dialog as ld

    base = tmp_path / "app"
    temp = _workarea(base) / "temp"
    temp.mkdir(parents=True)
    (temp / "fw.s19").write_bytes((projects.CASE01_DIR / "firmware.s19").read_bytes())
    outside = tmp_path / "outside"
    outside.mkdir()
    parses = _parse_spy(monkeypatch)

    async def _scenario(app, pilot, log):
        mark = len(log.messages)
        if route == "files list":
            app.refresh_files()
            await pilot.pause()
            rows = list(app.query_one("#files_list", ListView).children)
            _replace_entry(temp, outside, arm)
            app._load_from_item(rows[0])
        else:
            await pilot.press("p")
            await ld.wait_for_dialog(pilot, app)
            for _ in range(4):
                await pilot.pause()
            await ld.highlight_row(pilot, app, "fw.s19")
            _replace_entry(temp, outside, arm)
            await pilot.press("enter")
            await ld.wait_for_dialog_closed(pilot, app)
        for _ in range(12):
            await pilot.pause()
        return log.since(mark), app.current_file

    messages, current = projects.run_app(base, _scenario, size=(118, 54))
    refusal = NOT_REGULAR.format(name="fw.s19")
    assert "fw.s19" not in parses, parses
    assert current is None, current
    assert [m for m in messages if m == refusal] == [refusal], messages


def test_tc_b100_39_pick_rechecks_the_entry_after_the_question(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-172.6b, S12a-03 (B12-39): with an unsaved patched byte (the Inc 10
    question's trigger), ``fw.s19`` is regular when picked, so the question
    is asked; before ``y`` the entry is swapped for a folder → the re-check
    inside the continuation refuses it: 1 ``not a regular file`` line, 0
    parses of ``fw.s19``, the loaded image unchanged.

    Why: the check must run at use, after the question, or a swap while the
    question is open slips through.
    RED (base): the continuation parses the folder."""
    from textual.widgets import ListView

    from tests.test_b100_load_question import _patch, is_question

    base = tmp_path / "app"
    temp = _workarea(base) / "temp"
    temp.mkdir(parents=True)
    (temp / "fw.s19").write_bytes((projects.CASE01_DIR / "firmware.s19").read_bytes())
    (temp / "x.s19").write_bytes((projects.CASE01_DIR / "firmware.s19").read_bytes())
    parses = _parse_spy(monkeypatch)

    async def _scenario(app, pilot, log):
        await projects.load_image(pilot, app, temp / "x.s19")
        for _ in range(4):
            await pilot.pause()
        await _patch(pilot, app)
        app.refresh_files()
        await pilot.pause()
        rows = {getattr(r, "data", None): r for r in app.query_one("#files_list", ListView).children}
        parses.clear()
        mark = len(log.messages)
        app._load_from_item(rows["fw.s19"])
        await projects.wait_for(pilot, lambda: is_question(app.screen), "the load question")
        (temp / "fw.s19").unlink()
        (temp / "fw.s19").mkdir()
        await pilot.press("y")
        for _ in range(12):
            await pilot.pause()
        await settle_workers(pilot)  # Inc 12b R-5: the data pick is a worker
        return log.since(mark), Path(app.current_file.path).name

    messages, current = projects.run_app(base, _scenario, size=(118, 54))
    assert "fw.s19" not in parses, parses
    assert current == "x.s19", current
    assert messages.count(NOT_REGULAR.format(name="fw.s19")) == 1, messages


@pytest.mark.parametrize("arm", ["lstat refused", "vanished"])
def test_tc_b100_39_pick_rechecks_the_entry_and_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: str
) -> None:
    """LLR-172.6b failure paths (B12-33, B12-32): ``os.lstat`` inside the
    pick raising ``PermissionError`` for ``x.s19`` (from its second call on,
    so the pre-question vanish look passes) → 1 ``not a regular file``
    line, 0 parses, 0 raises; ``x.s19`` deleted after it was listed → 0
    loads and 0 status lines (9b B88 kept).

    Why: an entry the re-check cannot read is refused, never loaded.
    RED (base, lstat arm): the base pick never calls ``os.lstat`` and parses
    ``x.s19``. The vanished arm holds on base (regression)."""
    from textual.widgets import ListView

    base = tmp_path / "app"
    temp = _workarea(base) / "temp"
    temp.mkdir(parents=True)
    (temp / "x.s19").write_bytes((projects.CASE01_DIR / "firmware.s19").read_bytes())
    parses = _parse_spy(monkeypatch)
    key = os.path.normcase(str(temp / "x.s19"))
    real_lstat = os.lstat
    seen: list = []

    def _lstat(path, *args, **kwargs):
        if not isinstance(path, int) and os.path.normcase(os.fspath(path)) == key:
            seen.append(1)
            if len(seen) >= 2:
                raise PermissionError(13, "injected: access denied", os.fspath(path))
        return real_lstat(path, *args, **kwargs)

    async def _scenario(app, pilot, log):
        app.refresh_files()
        await pilot.pause()
        rows = list(app.query_one("#files_list", ListView).children)
        mark = len(log.messages)
        raised = None
        if arm == "vanished":
            (temp / "x.s19").unlink()
            app._load_from_item(rows[0])
        else:
            with monkeypatch.context() as patch:
                patch.setattr(app_module.os, "lstat", _lstat)
                try:
                    app._load_from_item(rows[0])
                except Exception as exc:  # noqa: BLE001 — the threshold counts raises
                    raised = repr(exc)
                for _ in range(12):
                    await pilot.pause()
        for _ in range(6):
            await pilot.pause()
        return raised, log.since(mark), app.current_file

    raised, messages, current = projects.run_app(base, _scenario, size=(118, 54))
    assert raised is None, raised
    assert "x.s19" not in parses and current is None, (parses, current)
    if arm == "vanished":
        assert messages == [], messages
    else:
        assert messages == [NOT_REGULAR.format(name="x.s19")], messages


@pytest.mark.parametrize("arm", ["over the cap", "at the cap", "A2L over the cap"])
def test_tc_b100_39_pick_over_cap_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: str) -> None:
    """LLR-172.6c (B12-31): the copy cap read at call time and patched to
    1 024 bytes → a 1 025-byte ``big.s19`` pick paints ``File NOT loaded:
    'big.s19' is too large to open — load a smaller file.`` with 0 parses; a
    1 024-byte ``edge.s19`` is parsed; a 1 025-byte ``c.a2l`` is refused the
    same way with 0 calls of ``load_a2l_from_path``.

    Why: the data arm of a work-area pick had no size check, so an
    over-cap file was parsed in place.
    Negative control: the cap read at import → the patch is not seen.
    RED (base, probe p12a U2.5): the over-cap data pick parses. The
    ``at the cap`` arm holds on base (its boundary twin)."""
    from textual.widgets import ListView

    from s19_app.tui import workspace

    name = {"over the cap": "big.s19", "at the cap": "edge.s19", "A2L over the cap": "c.a2l"}[arm]
    size = 1024 if arm == "at the cap" else 1025
    base = tmp_path / "app"
    temp = _workarea(base) / "temp"
    temp.mkdir(parents=True)
    (temp / name).write_bytes(b"S" * size)
    monkeypatch.setattr(workspace, "DEFAULT_COPY_SIZE_CAP_BYTES", 1024)
    parses = _parse_spy(monkeypatch)
    a2l_loads: list = []
    monkeypatch.setattr(app_module.S19TuiApp, "load_a2l_from_path", lambda self, p: a2l_loads.append(Path(p).name))

    async def _scenario(app, pilot, log):
        app.refresh_files()
        await pilot.pause()
        rows = list(app.query_one("#files_list", ListView).children)
        mark = len(log.messages)
        app._load_from_item(rows[0])
        for _ in range(12):
            await pilot.pause()
        await settle_workers(pilot)  # Inc 12b R-5: the data pick is a worker
        return log.since(mark)

    messages = projects.run_app(base, _scenario, size=(118, 54))
    refusal = TOO_LARGE_LINE.format(name=name)
    if arm == "at the cap":
        assert parses == [name], parses
        assert refusal not in messages, messages
    else:
        assert parses == [] and a2l_loads == [], (parses, a2l_loads)
        assert messages.count(refusal) == 1, messages

# ---------------------------------------------------------------------------
# Inc 12a E5 corrective, round 2 — arms that kill the surviving mutants
# (evidence/inc-12a/mutation-summary.md; ids MUT12a-M-NN in E5-rulings.md)
# ---------------------------------------------------------------------------


def test_tc_b100_39_pick_of_a_vanished_entry_asks_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F-11 / 9b B88, LLR-172.6b (MUT12a-M-101): with an unsaved patched
    byte (the Inc 10 question's trigger), ``fw.s19`` is listed and then
    deleted before it is picked → the pick opens no question, writes 0
    status lines and parses nothing; ``x.s19`` stays loaded.

    Why: the pre-question look exists so a file that is already gone does
    not ask the user to give up unsaved work for nothing.
    Negative control (M-101, the vanished look falls through): the question
    opens for a file that does not exist."""
    from textual.widgets import ListView

    from tests.test_b100_load_question import _patch, is_question

    base = tmp_path / "app"
    temp = _workarea(base) / "temp"
    temp.mkdir(parents=True)
    (temp / "fw.s19").write_bytes((projects.CASE01_DIR / "firmware.s19").read_bytes())
    (temp / "x.s19").write_bytes((projects.CASE01_DIR / "firmware.s19").read_bytes())
    parses = _parse_spy(monkeypatch)

    async def _scenario(app, pilot, log):
        await projects.load_image(pilot, app, temp / "x.s19")
        for _ in range(4):
            await pilot.pause()
        await _patch(pilot, app)
        app.refresh_files()
        await pilot.pause()
        rows = {getattr(r, "data", None): r for r in app.query_one("#files_list", ListView).children}
        parses.clear()
        (temp / "fw.s19").unlink()
        mark = len(log.messages)
        app._load_from_item(rows["fw.s19"])
        asked = False
        for _ in range(12):
            await pilot.pause()
            asked = asked or is_question(app.screen)
        return asked, log.since(mark), Path(app.current_file.path).name

    asked, messages, current = projects.run_app(base, _scenario, size=(118, 54))
    assert asked is False, "a question opened for a vanished file"
    assert messages == [], messages
    assert "fw.s19" not in parses and current == "x.s19", (parses, current)


def test_tc_b100_39_pick_survives_an_error_at_the_first_look(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """S12a-R2-1 (MUT12a-M-102): ``os.lstat`` raising ``PermissionError``
    for ``x.s19`` only at its FIRST call (the pre-question look) → the pick
    goes on; the re-check inside the continuation reads the file and it is
    loaded (``current_file`` is ``x.s19``, 0 refusal lines).

    Why: an error at the look is not a verdict — the re-check at use decides
    (it refuses an entry it cannot read, see the ``lstat refused`` arm).
    Negative control (M-102, the look returns on ``OSError``): nothing is
    loaded and nothing is said."""
    from textual.widgets import ListView

    base = tmp_path / "app"
    temp = _workarea(base) / "temp"
    temp.mkdir(parents=True)
    (temp / "x.s19").write_bytes((projects.CASE01_DIR / "firmware.s19").read_bytes())
    key = os.path.normcase(str(temp / "x.s19"))
    real_lstat = os.lstat
    seen: list = []

    def _lstat(path, *args, **kwargs):
        if not isinstance(path, int) and os.path.normcase(os.fspath(path)) == key:
            seen.append(1)
            if len(seen) == 1:
                raise PermissionError(13, "injected: access denied", os.fspath(path))
        return real_lstat(path, *args, **kwargs)

    async def _scenario(app, pilot, log):
        app.refresh_files()
        await pilot.pause()
        rows = list(app.query_one("#files_list", ListView).children)
        mark = len(log.messages)
        with monkeypatch.context() as patch:
            patch.setattr(app_module.os, "lstat", _lstat)
            app._load_from_item(rows[0])
            for _ in range(40):
                if app.current_file is not None:
                    break
                await pilot.pause()
        for _ in range(6):
            await pilot.pause()
        current = None if app.current_file is None else Path(app.current_file.path).name
        return len(seen), log.since(mark), current

    calls, messages, current = projects.run_app(base, _scenario, size=(118, 54))
    assert calls >= 2, calls
    assert current == "x.s19", (current, messages)
    assert NOT_REGULAR.format(name="x.s19") not in messages, messages


def test_tc_b100_39_pick_of_a_reparse_point_file_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-172.6b (MUT12a-M-105): ``x.s19`` is a regular file that
    ``_is_reparse_point`` reports as a reparse point (a symlink-like file
    entry a junction test cannot reach, since a junction is a folder) → 1
    ``not a regular file`` line, 0 parses, nothing loaded.

    Why: a reparse point that ``lstat`` sees as a regular file can still
    redirect the open; the re-check refuses it on that test alone.
    Negative control (M-105, the reparse test dropped): ``x.s19`` loads."""
    from textual.widgets import ListView

    base = tmp_path / "app"
    temp = _workarea(base) / "temp"
    temp.mkdir(parents=True)
    (temp / "x.s19").write_bytes((projects.CASE01_DIR / "firmware.s19").read_bytes())
    parses = _parse_spy(monkeypatch)
    key = os.path.normcase(str(temp / "x.s19"))
    real_reparse = app_module._is_reparse_point

    def _reparse(path, *args, **kwargs):
        if os.path.normcase(os.fspath(path)) == key:
            return True
        return real_reparse(path, *args, **kwargs)

    monkeypatch.setattr(app_module, "_is_reparse_point", _reparse)

    async def _scenario(app, pilot, log):
        app.refresh_files()
        await pilot.pause()
        rows = list(app.query_one("#files_list", ListView).children)
        mark = len(log.messages)
        app._load_from_item(rows[0])
        for _ in range(12):
            await pilot.pause()
        return log.since(mark), app.current_file

    messages, current = projects.run_app(base, _scenario, size=(118, 54))
    assert "x.s19" not in parses and current is None, (parses, current)
    assert messages == [NOT_REGULAR.format(name="x.s19")], messages
