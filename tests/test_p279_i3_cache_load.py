"""P-279 I3, group G-LOAD: the parse seam, the start option, the comment fast path, the user guide.

Requirements (``R-A2L-CACHE.001`` ... ``.062`` of the G-LOAD group, ``R-A2L-READ.73`` and ``.74``): the seam
``parse_a2l_cached`` (``s19_app/tui/app/deps.py``) consults the stored parse behind the unchanged in-memory entry,
writes the fixed ``A2L parse cache ...`` log lines, holds the cyclic collector around the cache work and never
lets a cache failure fail a load; ``main`` (``core.py``) carries ``--clear-a2l-cache``; ``_strip_a2l_comments``
(``a2l.py``) returns a text without ``/*`` and ``//`` unchanged; ``docs/user-guide/ch02-load.md`` names the cache.

Every expectation is computed here from the committed example files, from a fresh parse, or from the formulas
the definitions fix (entry name, entry format); nothing is retyped from the implementation. The private seams
(``s19_app.tui.a2l_cache``, ``s19_app.tui.a2l_cache_codec``) are reached lazily inside each test body, so the
module collects on the base revision and each node fails on its own. Every test isolates ``LOCALAPPDATA``,
``XDG_CACHE_HOME`` and ``HOME`` to temporary folders outside ``tmp_path`` that hold no repository marker.
Host arms H-1 and H-2 (case_06, CACHE.052 and .053) are here as nodes skipped unless ``S19_P279_HOST_CASE06``
names case_06's A2L; H-3 .. H-7 are not here.
"""

from __future__ import annotations

import builtins
import contextlib
import errno
import gc
import hashlib
import importlib
import io
import logging
import marshal
import math
import os
import pickle
import re
import shutil
import statistics
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Callable, Optional

import pytest

from s19_app.tui.app import S19TuiApp
from tests.support.b100_workers import settle_workers
from tests.support.timing import report_margin, timing_bound, wait_until
from tests.test_alp_inc2_a2l_attach import (
    _load_image,
    _load_project,
    _mount_views,
    _run,
    _seed_project,
    _typed_attach,
)
from tests.test_alp_inc3_snapshot_parity import _drive_typed_no_assert

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
CASE01_A2L = EXAMPLES / "case_01_basic_valid" / "firmware.a2l"
CASE01_IMAGE = EXAMPLES / "case_01_basic_valid" / "firmware.s19"
V171_A2L = EXAMPLES / "case_00_public" / "ASAP2_Demo_V171.a2l"
SOFTWARE_A = EXAMPLES / "case_00_public" / "software_a.a2l"
CASE06_REL = "examples/case_06_large_nested_a2l/firmware.a2l"
DOC = ROOT / "docs" / "user-guide" / "ch02-load.md"

PREFIX = "A2L parse cache"
HEADER_LEN = 88
CHUNK_PREFIX_LEN = 36
MIB = 1 << 20
A2L_1 = b'/begin PROJECT Demo ""\n/begin MODULE M ""\n/end MODULE\n/end PROJECT\n'
A2L_2 = A2L_1.replace(b"Demo", b"Demp")

F_HIT = re.compile(r"^A2L parse cache hit: entry_bytes=(\d+) read_seconds=(\d+\.\d{3})$")
F_MISS = re.compile(r"^A2L parse cache miss: file_bytes=(\d+) hash_seconds=(\d+\.\d{3})$")
F_STORED = re.compile(r"^A2L parse cache stored: entry_bytes=(\d+) write_seconds=(\d+\.\d{3})$")
F_EVICTED = re.compile(r"^A2L parse cache evicted: files=(\d+) bytes=(\d+)$")
F_UNUSABLE = re.compile(r"^A2L parse cache entry unusable: (damaged|not a regular file)\.$")
F_OFF = re.compile(
    r"^A2L parse cache off: (setting|setting not recognised|no cache folder|cache folder is a link|"
    r"cache folder inside a repository or work area|cache folder not private|parser source unreadable)\.$"
)
F_SIZE = "A2L parse cache size setting not recognised: 2048 MiB used."
F_NOT_STORED = re.compile(r"^A2L parse cache not stored: (entry larger than the size cap|file changed during the parse)\.$")
F_READ_FAILED = re.compile(r"^A2L parse cache read failed: ([A-Za-z_][A-Za-z0-9_]*)\.$")
F_WRITE_FAILED = re.compile(r"^A2L parse cache write failed: ([A-Za-z_][A-Za-z0-9_]*)\.$")
F_FAILED = re.compile(r"^A2L parse cache failed: ([A-Za-z_][A-Za-z0-9_]*)\.$")
FIXED_FORMATS = (F_HIT, F_MISS, F_STORED, F_EVICTED, F_UNUSABLE, F_OFF, F_NOT_STORED, F_READ_FAILED, F_WRITE_FAILED, F_FAILED)


# ---------------------------------------------------------------------------
# Lazy seams and small helpers.
# ---------------------------------------------------------------------------


def _cache():
    return importlib.import_module("s19_app.tui.a2l_cache")


def _codec():
    return importlib.import_module("s19_app.tui.a2l_cache_codec")


def _deps():
    return importlib.import_module("s19_app.tui.app.deps")


def _core():
    return importlib.import_module("s19_app.tui.app.core")


def _a2lmod():
    return importlib.import_module("s19_app.tui.a2l")


def _fresh(path: Path) -> dict:
    """The parser's own payload for ``path`` (not through the seam)."""
    return importlib.import_module("s19_app.tui.a2l_parse").parse_a2l_file(Path(path))


def _same(a, b) -> bool:
    """NaN-aware deep equality: strict on types, order-blind on dict keys (key order is a separate check)."""
    if isinstance(a, float) and isinstance(b, float):
        return a == b or (math.isnan(a) and math.isnan(b))
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return set(a) == set(b) and all(_same(a[k], b[k]) for k in a)
    if isinstance(a, (list, tuple)):
        return len(a) == len(b) and all(_same(x, y) for x, y in zip(a, b))
    return a == b


def _containers(obj) -> set:
    """ids of the distinct dict, list and set objects reachable from ``obj``."""
    seen: set = set()
    stack = [obj]
    while stack:
        item = stack.pop()
        if isinstance(item, (dict, list, set, tuple)):
            if isinstance(item, tuple):
                stack.extend(item)
                continue
            if id(item) in seen:
                continue
            seen.add(id(item))
            stack.extend(item.values() if isinstance(item, dict) else item)
    return seen


def _write(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def _snapshot(root: Path) -> dict:
    """Names, kinds, sizes, mtimes, link targets and content digests under ``root`` (links not followed)."""
    out: dict = {}
    if not os.path.lexists(root):
        return out
    for dirpath, dirs, files in os.walk(root, followlinks=False):
        for name in sorted(dirs + files):
            p = Path(dirpath) / name
            st = os.lstat(p)
            rel = str(p.relative_to(root))
            if os.path.islink(p):
                out[rel] = ("link", os.readlink(p))
            elif p.is_dir():
                out[rel] = ("dir", st.st_mtime_ns)
            else:
                out[rel] = ("file", st.st_size, st.st_mtime_ns, hashlib.sha256(p.read_bytes()).hexdigest())
    return out


class _Catch(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.messages: list = []

    def emit(self, record) -> None:  # noqa: D401
        self.messages.append(record.getMessage())

    def cache_lines(self) -> list:
        return [m for m in self.messages if m.startswith(PREFIX)]

    def matching(self, regex) -> list:
        return [m for m in self.cache_lines() if regex.match(m)]


# ---------------------------------------------------------------------------
# Isolation: every test gets its own cache base, HOME and LOCALAPPDATA outside tmp_path.
# ---------------------------------------------------------------------------


def _make_env(tpf, mp) -> SimpleNamespace:
    base = tpf.mktemp("xdgc")
    home = tpf.mktemp("homec")
    lad = tpf.mktemp("ladc")
    outside = tpf.mktemp("outc")
    (home / ".cache").mkdir(exist_ok=True)
    for p in (base, home, home / ".cache", lad, outside):
        os.chmod(p, 0o700)
    mp.setenv("XDG_CACHE_HOME", str(base))
    mp.setenv("HOME", str(home))
    mp.setenv("LOCALAPPDATA", str(lad))
    mp.delenv("S19_A2L_CACHE", raising=False)
    mp.delenv("S19_A2L_CACHE_MAX_MB", raising=False)
    return SimpleNamespace(base=base, home=home, lad=lad, outside=outside, folder=base / "s19_app" / "a2l", tpf=tpf, mp=mp)


@pytest.fixture(autouse=True)
def env(tmp_path_factory, monkeypatch):
    return _make_env(tmp_path_factory, monkeypatch)


@pytest.fixture(autouse=True)
def log():
    logger = logging.getLogger("s19tui")
    handler = _Catch()
    old = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    yield handler
    logger.removeHandler(handler)
    logger.setLevel(old)


def _mk_private_folder(env) -> Path:
    """Create the cache folder chain with mode 0700 (what a store would make)."""
    for p in (env.base / "s19_app", env.folder):
        p.mkdir(exist_ok=True)
        os.chmod(p, 0o700)
    return env.folder


def _entry_files(env) -> list:
    if not env.folder.is_dir():
        return []
    return sorted(p.name for p in env.folder.iterdir())


def _state():
    st = _cache().cache_state()
    assert hasattr(st, "fingerprint"), f"the parse cache is not on in this test: {st!r}"
    return st


def _entry_name(path: Path) -> str:
    """The definition's formula: SHA-256(content digest + parser fingerprint), 64 hex digits."""
    digest = hashlib.sha256(Path(path).read_bytes()).digest()
    return hashlib.sha256(digest + _state().fingerprint).hexdigest()


class _Parse:
    """Counts (and optionally intercepts) the parser calls of the seam (the deps-global ``parse_a2l_file``)."""

    def __init__(self, mp) -> None:
        deps = _deps()
        self.real = deps.parse_a2l_file
        self.calls: list = []
        self.hook: Optional[Callable] = None
        parse = self

        def spy(path, *args, **kwargs):
            parse.calls.append((str(path), threading.get_ident()))
            if parse.hook is not None:
                return parse.hook(parse.real, path, *args, **kwargs)
            return parse.real(path, *args, **kwargs)

        mp.setattr(deps, "parse_a2l_file", spy)


def _seam(path: Path, cached=None, progress=None):
    deps = _deps()
    if progress is not None:
        return deps.parse_a2l_cached(Path(path), cached, progress)
    return deps.parse_a2l_cached(Path(path), cached)


def _patch_cache(mp, name: str, fn) -> None:
    """Patch ``name`` in every module the seam may reach it through (a2l_cache, deps)."""
    patched = False
    for mod in (_cache(), _deps()):
        if hasattr(mod, name):
            mp.setattr(mod, name, fn)
            patched = True
    assert patched, f"no module exposes {name}"


def _assert_all_fixed(lines: list) -> None:
    for line in lines:
        assert line == F_SIZE or any(f.match(line) for f in FIXED_FORMATS), f"not a fixed format: {line!r}"


class _EnvSpy:
    """Counts reads of ``S19_A2L_CACHE*`` through ``os.environ`` (class-level wrappers, restored by monkeypatch)."""

    def __init__(self, mp) -> None:
        self.reads: list = []
        cls = type(os.environ)
        spy = self
        for name in ("get", "__getitem__", "__contains__"):
            real = getattr(cls, name)

            def wrapper(self_, key, *a, _real=real, **k):
                if isinstance(key, str) and key.startswith("S19_A2L_CACHE"):
                    spy.reads.append(key)
                return _real(self_, key, *a, **k)

            mp.setattr(cls, name, wrapper)


class _FsSpy:
    """Records the file-system calls that touch the cache base (by path or through a descriptor) with their thread."""

    def __init__(self, mp, base: Path) -> None:
        self.events: list = []
        self.fds: set = set()
        prefixes = {str(base), os.path.realpath(base)}
        spy = self

        def under(p) -> bool:
            if isinstance(p, int):
                return p in spy.fds
            try:
                s = os.fsdecode(os.fspath(p))
            except TypeError:
                return False
            return any(s == x or s.startswith(x + os.sep) for x in prefixes)

        def wrap(owner, name, label):
            real = getattr(owner, name)

            def w(path, *a, **k):
                rel = any(k.get(x) is not None for x in ("dir_fd", "src_dir_fd", "dst_dir_fd"))
                hit = rel or under(path)
                if hit:
                    spy.events.append((label, threading.get_ident()))
                res = real(path, *a, **k)
                if hit and label == "open" and isinstance(res, int):
                    spy.fds.add(res)
                return res

            mp.setattr(owner, name, w)

        for label, name in (("open", "open"), ("replace", "replace"), ("replace", "rename"), ("delete", "unlink"),
                            ("delete", "remove"), ("mkdir", "mkdir"), ("list", "scandir"), ("list", "listdir"),
                            ("utime", "utime"), ("stat", "stat"), ("stat", "lstat"), ("read", "read"), ("write", "write")):
            wrap(os, name, label)
        wrap(builtins, "open", "open")
        wrap(io, "open", "open")

    def threads(self) -> set:
        return {t for _l, t in self.events}

    def labels(self) -> set:
        return {l for l, _t in self.events}


def _set_utime_ns(path: Path, ns: int) -> None:
    os.utime(path, ns=(ns, ns))


@pytest.fixture(scope="module")
def committed_set() -> list:
    """Every tracked ``*.a2l`` of the repository except case_06 (the committed A2L set), as repo-relative names."""
    try:
        out = subprocess.run(["git", "-C", str(ROOT), "ls-files", "*.a2l"], capture_output=True, text=True, check=True).stdout
        names = [n for n in out.splitlines() if n and n != CASE06_REL]
    except (OSError, subprocess.CalledProcessError):
        names = [str(p.relative_to(ROOT)).replace("\\", "/") for p in ROOT.rglob("*.a2l")
                 if ".git" not in p.parts and str(p.relative_to(ROOT)).replace("\\", "/") != CASE06_REL]
    names = sorted(names)
    assert len(names) >= 34, f"the committed A2L set has {len(names)} files, expected at least 34"
    return names


@pytest.fixture(scope="module")
def fresh_set(committed_set) -> dict:
    """name -> the parser's own payload of each committed A2L (parsed once per module)."""
    return {name: _fresh(ROOT / name) for name in committed_set}


# ---------------------------------------------------------------------------
# Arms shared by CACHE.007, .021, .022, .025, .034, .037, .039, .043 (each arm: one cold seam call, own isolation).
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def _fresh_ctx(tpf):
    with pytest.MonkeyPatch.context() as mp:
        yield mp, _make_env(tpf, mp)


def _valid_entry_path(c) -> Path:
    return c.env.folder / _entry_name(c.a2l)


def _body_chunk(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + hashlib.sha256(data).digest() + data


def _rebuild(raw: bytes, chunks: list) -> bytes:
    body = b"".join(_body_chunk(d) for d in chunks)
    return raw[:76] + struct.pack(">I", len(chunks)) + struct.pack(">Q", len(body)) + body


class _PickleBomb:
    sentinel = ""

    def __reduce__(self):
        return (open, (self.sentinel, "w"))


def _f_pickle(raw: bytes, c) -> bytes:
    bomb = _PickleBomb()
    bomb.sentinel = str(c.sentinel)
    return pickle.dumps(bomb) + raw[8:]


_SECTIONS_INT = marshal.dumps(((), 0, [("sections", 5), ("errors", []), ("tags", []), ("declared_spans", [])]))
DAMAGED_FORMS = {
    "empty": lambda raw, c: b"",
    "40-bytes": lambda raw, c: raw[:40],
    "cut-mid-chunk": lambda raw, c: raw[: len(raw) - 5],
    "one-byte-appended": lambda raw, c: raw + b"x",
    "pickle-stream": _f_pickle,
    "format-version-0": lambda raw, c: raw[:8] + struct.pack(">I", 0) + raw[12:],
    "format-version-2": lambda raw, c: raw[:8] + struct.pack(">I", 2) + raw[12:],
    "other-content-digest": lambda raw, c: raw[:12] + hashlib.sha256(b"another a2l").digest() + raw[44:],
    "other-fingerprint": lambda raw, c: raw[:44] + bytes([0x11]) * 32 + raw[76:],
    "flipped-data-byte": lambda raw, c: raw[:-1] + bytes([raw[-1] ^ 1]),
    "chunk-length-ffffffff": lambda raw, c: raw[:HEADER_LEN] + b"\xff\xff\xff\xff" + raw[HEADER_LEN + 4:],
    "not-marshal-matching-digest": lambda raw, c: _rebuild(raw, [b"this is not marshal data"]),
    "record-path-names-no-container": lambda raw, c: _rebuild(raw, [marshal.dumps((("nope",), 1, [1]))]),
    "chunk-count-over-limit": lambda raw, c: raw[:76]
    + struct.pack(">I", struct.unpack(">Q", raw[80:HEADER_LEN])[0] // CHUNK_PREFIX_LEN + 1)
    + raw[80:],
    "sections-is-an-int": lambda raw, c: _rebuild(raw, [_SECTIONS_INT]),
}


def _setup_damaged(form: str):
    def setup(c) -> None:
        path = _valid_entry_path(c)
        raw = path.read_bytes()
        path.write_bytes(DAMAGED_FORMS[form](raw, c))

    return setup


def _setup_link_entry(c) -> None:
    path = _valid_entry_path(c)
    target = c.env.outside / path.name
    shutil.copy2(path, target)
    path.unlink()
    os.symlink(target, path)


def _setup_dir_entry(c) -> None:
    path = _valid_entry_path(c)
    path.unlink()
    path.mkdir()


def _setup_link_swapped_before_open(c) -> None:
    """The entry is a regular file at the check; a link to a copy of it replaces the name right before the open."""
    path = _valid_entry_path(c)
    target = c.env.outside / path.name
    shutil.copy2(path, target)
    name = path.name

    def install() -> None:
        real_os_open = os.open

        def os_open(p, flags, *a, **k):
            if _is_name_path(p, name) and not flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT) and not path.is_symlink():
                path.unlink()
                os.symlink(target, path)
            return real_os_open(p, flags, *a, **k)

        c.mp.setattr(os, "open", os_open)

    c.deferred.append(install)


ENTRY_ARMS = [(f"damaged-{form}", _setup_damaged(form), "damaged") for form in DAMAGED_FORMS] + [
    ("link-to-valid-entry", _setup_link_entry, "not a regular file"),
    ("folder-of-entry-name", _setup_dir_entry, "not a regular file"),
    ("link-swapped-before-open", _setup_link_swapped_before_open, "not a regular file"),
]


def _setup_setting(value: str):
    return lambda c: c.mp.setenv("S19_A2L_CACHE", value)


def _setup_xdg_missing(c) -> None:
    c.mp.setenv("XDG_CACHE_HOME", str(c.env.base / "missing-abs"))


def _setup_no_base(c) -> None:
    c.mp.delenv("XDG_CACHE_HOME", raising=False)
    c.mp.delenv("HOME", raising=False)


def _setup_link(c) -> None:
    os.symlink(c.env.outside, c.env.base / "s19_app")


def _setup_repo(c) -> None:
    repo = c.tpf.mktemp("repoc")
    (repo / ".git").mkdir()
    (repo / "c").mkdir(mode=0o700)
    c.mp.setenv("XDG_CACHE_HOME", str(repo / "c"))


def _setup_workarea(c) -> None:
    wa = c.tpf.mktemp("wac") / ".s19tool" / "workarea" / "proj"
    wa.mkdir(parents=True)
    os.chmod(wa, 0o700)
    c.mp.setenv("XDG_CACHE_HOME", str(wa))


def _setup_mode(folder_attr: str, mode: int):
    def setup(c) -> None:
        _mk_private_folder(c.env)
        target = {"a2l": c.env.folder, "s19_app": c.env.base / "s19_app", "base": c.env.base}[folder_attr]
        os.chmod(target, mode)

    return setup


def _setup_no_parser_source(c) -> None:
    _patch_cache(c.mp, "parser_fingerprint", lambda: None)


OFF_ARMS = [
    ("setting-off", _setup_setting("off"), "setting"),
    ("setting-OFF", _setup_setting("OFF"), "setting"),
    ("setting-blanks", _setup_setting(" off\t"), "setting"),
    ("setting-0", _setup_setting("0"), "setting not recognised"),
    ("setting-disable", _setup_setting("disable"), "setting not recognised"),
    ("setting-escape", _setup_setting("\x1b[31moff"), "setting not recognised"),
    ("setting-long", _setup_setting("o" * 32750), "setting not recognised"),
    ("xdg-missing-absolute", _setup_xdg_missing, "no cache folder"),
    ("no-base-at-all", _setup_no_base, "no cache folder"),
    ("s19_app-is-a-link", _setup_link, "cache folder is a link"),
    ("base-inside-repository", _setup_repo, "cache folder inside a repository or work area"),
    ("base-inside-work-area", _setup_workarea, "cache folder inside a repository or work area"),
    ("a2l-mode-0755", _setup_mode("a2l", 0o755), "cache folder not private"),
    ("s19_app-mode-0777", _setup_mode("s19_app", 0o777), "cache folder not private"),
    ("base-mode-0777-no-sticky", _setup_mode("base", 0o777), "cache folder not private"),
    ("parser-source-unreadable", _setup_no_parser_source, "parser source unreadable"),
]
FOLDER_ARM_IDS = {a[0] for a in OFF_ARMS if not a[0].startswith("setting") and a[0] != "parser-source-unreadable"}


CACHE_MODULES = ("s19_app.tui.a2l_cache", "s19_app.tui.a2l_cache_codec", "s19_app.tui.app.deps")


def _run_arm(tpf, log, setup, *, a2l: Path = CASE01_A2L, prime: bool = False, gc_before: Optional[bool] = None):
    """One arm: own isolation, optional priming cold load, ``setup``, then one cold-memory seam call (with the
    collector set to ``gc_before`` when given; its state after the call and the collections the cache code made
    are in the result)."""
    with _fresh_ctx(tpf) as (mp, e):
        c = SimpleNamespace(mp=mp, env=e, tpf=tpf, a2l=a2l, tmp=tpf.mktemp("armtmp"), parse=None, sentinel=None,
                            deferred=[])
        c.sentinel = c.tmp / "sentinel"
        c.parse = _Parse(mp)
        collects: list = []
        real_collect = gc.collect

        def collect_spy(*a, **k):
            collects.append(sys._getframe(1).f_globals.get("__name__", ""))
            return real_collect(*a, **k)

        mp.setattr(gc, "collect", collect_spy)
        if prime:
            _seam(a2l)
        setup_result = setup(c)
        before = {"base": _snapshot(c.env.base), "outside": _snapshot(c.env.outside)}
        log.messages.clear()
        c.parse.calls.clear()
        collects.clear()
        late = pytest.MonkeyPatch()
        c.mp = late
        for install in c.deferred:
            install()
        if gc_before is not None:
            (gc.enable if gc_before else gc.disable)()
        try:
            entry = _seam(a2l)
            gc_after = gc.isenabled()
        finally:
            gc.enable()
            late.undo()
            c.mp = mp
        after = {"base": _snapshot(c.env.base), "outside": _snapshot(c.env.outside)}
        try:
            name = _entry_name(a2l)
        except Exception:  # noqa: BLE001 - the cache is off, or a fault is installed in the state
            name = None
        result = SimpleNamespace(c=c, entry=entry, lines=log.cache_lines(), calls=list(c.parse.calls), before=before,
                                 after=after, name=name, folder=c.env.folder, setup=setup_result,
                                 messages=list(log.messages), gc_after=gc_after,
                                 collects=[m for m in collects if m in CACHE_MODULES])
        with contextlib.suppress(OSError):
            os.chmod(c.env.folder, 0o700)
        return result


# ---------------------------------------------------------------------------
# The route harness: one load through the shipped routes (fresh app per call).
# ---------------------------------------------------------------------------

ROUTES = ("attach", "image", "project-pair", "project-a2l-only")
_KEY = {"attach": "a2l_load", "image": "file_load", "project-pair": "project_load", "project-a2l-only": "project_load"}
_PROJECT = "proj_i3"


def _clear_entries(env) -> None:
    if env.folder.is_dir():
        for p in env.folder.iterdir():
            if p.is_file():
                p.unlink()


def _run_route(tmp_path: Path, mp, env, route: str, a2l: Path, *, arm: Optional[Callable] = None, cold_image: bool = False):
    """Run one load on ``route``; the image route installs ``a2l`` first and forgets the in-memory entry (so
    the seam reaches the cache, cold when ``cold_image``). ``arm(app)`` runs right before the observed action."""

    async def body(app, pilot):
        _mount_views(app)
        await pilot.pause()
        if route == "image":
            await _typed_attach(app, pilot, a2l)
            await settle_workers(pilot)
            if cold_image:
                _clear_entries(env)
            app._a2l_cache_key = None
            app._a2l_cache_data = None
        outcomes: list = []
        real_end = S19TuiApp.end_busy

        def end(key, gen, outcome):
            outcomes.append((key, str(outcome)))
            return real_end(app, key, gen, outcome)

        mp.setattr(app, "end_busy", end)
        ctx = arm(app) if arm is not None else None
        if route == "attach":
            await _typed_attach(app, pilot, a2l)
        elif route == "image":
            await _load_image(app, pilot, CASE01_IMAGE)
        else:
            _seed_project(app.workarea, _PROJECT, a2l=a2l, image=None if route == "project-a2l-only" else CASE01_IMAGE)
            await _load_project(app, pilot, _PROJECT)
        await settle_workers(pilot)
        await wait_until(pilot, lambda: any(k == _KEY[route] for k, _t in outcomes), f"the {route} outcome", timeout=120.0)
        await pilot.pause()
        data = app.current_a2l_data
        return SimpleNamespace(outcomes=outcomes, ctx=ctx, tags=len(data["tags"]) if data else None,
                               a2l_path=app.current_a2l_path)

    return _run(tmp_path, body)


def _assert_ok(res, route: str, a2l: Optional[Path] = None) -> None:
    texts = [t for k, t in res.outcomes if k == _KEY[route]]
    assert texts, res.outcomes
    assert not any("failed" in t or "NOT loaded" in t for t in texts), texts
    if route == "attach" and a2l is not None:
        assert any(f"A2L loaded: {a2l.name}" in t for t in texts), texts


# ---------------------------------------------------------------------------
# Module A - reuse.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("a2l", [CASE01_A2L, V171_A2L], ids=["case_01", "d171"])
def test_r_a2l_cache_001_in_memory_match_does_no_cache_work(a2l, env, monkeypatch, log) -> None:
    """R-A2L-CACHE.001: a matching in-memory entry is returned itself, with no read of the cache setting, no
    open of the A2L file and no file-system call under the cache base."""
    parse = _Parse(monkeypatch)
    first = _seam(a2l)
    assert _entry_files(env), "the first load stored nothing: the arm would be vacuous"
    parse.calls.clear()
    log.messages.clear()
    env_spy = _EnvSpy(monkeypatch)
    fs = _FsSpy(monkeypatch, env.base)
    a2l_fs = _FsSpy(monkeypatch, a2l)
    second = _seam(a2l, first)
    assert second is first
    assert env_spy.reads == []
    assert fs.events == [], fs.events
    assert [l for l, _t in a2l_fs.events if l == "open"] == []
    assert parse.calls == []
    assert any(m.startswith("A2L cache hit: path=") for m in log.messages)
    assert log.cache_lines() == []


_THREE = [("case_01", CASE01_A2L), ("d171", V171_A2L), ("software_a", SOFTWARE_A)]


@pytest.mark.parametrize("route", ["attach", "project-pair"])
@pytest.mark.parametrize("name,a2l", _THREE, ids=[n for n, _p in _THREE])
def test_r_a2l_cache_002_second_app_gets_the_stored_parse(tmp_path, monkeypatch, env, log, route, name, a2l) -> None:
    """R-A2L-CACHE.002 (6 arms): after a first app has loaded the file, a second app (no in-memory entry) gets the
    stored parse on the direct-attach and project-pair routes: 0 parser calls, the load ends ok."""
    parse = _Parse(monkeypatch)
    first = _run_route(tmp_path / "app1", monkeypatch, env, route, a2l)
    _assert_ok(first, route, a2l)
    assert len(parse.calls) >= 1
    assert _entry_files(env), "the first app stored no entry"
    parse.calls.clear()
    second = _run_route(tmp_path / "app2", monkeypatch, env, route, a2l)
    _assert_ok(second, route, a2l)
    assert parse.calls == [], parse.calls
    assert second.tags == first.tags


def _shared_line_ids(sections) -> set:
    ids: set = set()

    def walk(nodes) -> None:
        for node in nodes:
            ids.add(id(node.get("lines")))
            walk(node.get("children") or [])

    walk(sections)
    return ids


def _assert_maps_share_lines(payload: dict, label: str) -> None:
    ids = _shared_line_ids(payload["sections"])
    for mapname in ("record_layouts_by_name", "compu_methods_by_name", "compu_tabs_by_name"):
        for key, item in payload[mapname].items():
            if item.get("lines"):
                assert id(item["lines"]) in ids, f"{label}: {mapname}[{key!r}]['lines'] is not its section's lines list"


def test_r_a2l_cache_003_hit_payload_equals_fresh_parse_for_every_committed_file(committed_set, fresh_set, env, monkeypatch) -> None:
    """R-A2L-CACHE.003 (34 files): the payload of the second load equals a fresh parse at the same path (NaN-aware),
    in the parser's key order, with the same number of distinct containers and the maps sharing their sections'
    ``lines`` lists."""
    parse = _Parse(monkeypatch)
    for name in committed_set:
        path = ROOT / name
        _seam(path)
        parse.calls.clear()
        payload = _seam(path)[1]
        fresh = fresh_set[name]
        assert parse.calls == [], f"{name}: the second load parsed instead of reading the stored parse"
        assert list(payload) == list(fresh), name
        assert list(payload)[0] == "path" and list(payload)[-3:] == ["record_layouts_by_name", "compu_methods_by_name", "compu_tabs_by_name"], name
        assert payload["path"] == str(path), name
        assert _same(payload, fresh), name
        assert len(_containers(payload)) == len(_containers(fresh)), name
        _assert_maps_share_lines(fresh, f"{name} (fresh parse control)")
        _assert_maps_share_lines(payload, name)


def test_r_a2l_cache_003_second_path_gets_its_own_path_and_the_rest_equal(tmp_path, env, monkeypatch) -> None:
    """R-A2L-CACHE.003 second-path arm: case_01 copied to another folder is a hit whose ``path`` is the copy and
    whose other keys equal the first load's."""
    parse = _Parse(monkeypatch)
    first = _seam(CASE01_A2L)[1]
    copy = _write(tmp_path / "p2" / "firmware.a2l", CASE01_A2L.read_bytes())
    parse.calls.clear()
    second = _seam(copy)[1]
    assert parse.calls == []
    assert second["path"] == str(copy) and first["path"] == str(CASE01_A2L)
    assert _same({k: v for k, v in second.items() if k != "path"}, {k: v for k, v in first.items() if k != "path"})


@pytest.mark.parametrize("order", ["p1-then-p2", "p2-then-p1"])
def test_r_a2l_cache_005_same_bytes_in_two_places_share_one_entry(tmp_path, env, monkeypatch, log, order) -> None:
    """R-A2L-CACHE.005: case_01 placed in two project folders is served from one entry: 1 parser call, 1 entry,
    the later load a stored-parse hit, in both orders."""
    parse = _Parse(monkeypatch)
    p1 = _write(tmp_path / "P1" / "firmware.a2l", CASE01_A2L.read_bytes())
    p2 = _write(tmp_path / "P2" / "firmware.a2l", CASE01_A2L.read_bytes())
    first, second = (p1, p2) if order == "p1-then-p2" else (p2, p1)
    _seam(first)
    log.messages.clear()
    payload = _seam(second)[1]
    assert len(parse.calls) == 1
    assert len(_entry_files(env)) == 1
    assert len(log.matching(F_HIT)) == 1
    assert payload["path"] == str(second)


def _fingerprint(source_hex: str, fmt: str, minor: str) -> bytes:
    return hashlib.sha256(f"s19-a2l-cache/{fmt}/{source_hex}/{minor}".encode("ascii")).digest()


def test_r_a2l_cache_006_fingerprint_formula_matches_the_running_system() -> None:
    """R-A2L-CACHE.006 guard: the definition's fingerprint formula, computed here from the running parser source,
    equals the state's fingerprint (so the fingerprint arms below change a real factor)."""
    source = Path(_a2lmod().__file__).read_bytes()
    expected = _fingerprint(hashlib.sha256(source).hexdigest(), "1", f"{sys.version_info.major}.{sys.version_info.minor}")
    assert _state().fingerprint == expected


@pytest.mark.parametrize("arm", ["one-byte-same-length", "parser-source", "format-version", "python-minor"])
def test_r_a2l_cache_006_changed_key_part_parses_again_and_adds_an_entry(tmp_path, env, monkeypatch, arm) -> None:
    """R-A2L-CACHE.006 (4 arms): after one stored load, a changed content byte, parser source digest, format
    version or Python minor gives a parser call and a second entry."""
    a2l = _write(tmp_path / "k.a2l", A2L_1)
    parse = _Parse(monkeypatch)
    _seam(a2l)
    assert len(parse.calls) == 1 and len(_entry_files(env)) == 1
    assert len(A2L_1) == len(A2L_2)
    source_hex = hashlib.sha256(Path(_a2lmod().__file__).read_bytes()).hexdigest()
    minor = f"{sys.version_info.major}.{sys.version_info.minor}"
    if arm == "one-byte-same-length":
        a2l.write_bytes(A2L_2)
    else:
        changed = {
            "parser-source": _fingerprint(hashlib.sha256(b"another parser source").hexdigest(), "1", minor),
            "format-version": _fingerprint(source_hex, "2", minor),
            "python-minor": _fingerprint(source_hex, "1", f"{sys.version_info.major}.{sys.version_info.minor + 1}"),
        }[arm]
        _patch_cache(monkeypatch, "parser_fingerprint", lambda: changed)
    parse.calls.clear()
    _seam(a2l)
    assert len(parse.calls) == 1, arm
    assert len(_entry_files(env)) == 2, (arm, _entry_files(env))


# ---------------------------------------------------------------------------
# Fault arms (CACHE.007, .043, .046, .055): each installs one fault inside the arm's own isolation.
# ---------------------------------------------------------------------------

_SECRET = "SECRET_TOKEN_I3"


def _is_name_path(p, name: str, *, prefix: bool = False) -> bool:
    if isinstance(p, int):
        return False
    try:
        base = os.path.basename(os.fsdecode(os.fspath(p)))
    except TypeError:
        return False
    return base.startswith(name + ".tmp-") if prefix else base == name


def _install_open_fault(c, exc: BaseException, *, write: bool = False) -> None:
    """Raise ``exc`` when the entry (read) or its temporary file (write) is opened."""
    name = _entry_name(c.a2l)
    real_os_open = os.open

    def os_open(path, flags, *a, **k):
        if write:
            if _is_name_path(path, name, prefix=True) and flags & os.O_CREAT:
                raise exc
        elif _is_name_path(path, name) and not flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT):
            raise exc
        return real_os_open(path, flags, *a, **k)

    c.mp.setattr(os, "open", os_open)
    for owner in (builtins, io):
        real = owner.open

        def opener(file, mode="r", *a, _real=real, **k):
            writing = any(x in mode for x in "wax+")
            if write and writing and _is_name_path(file, name, prefix=True):
                raise exc
            if not write and not writing and _is_name_path(file, name):
                raise exc
            return _real(file, mode, *a, **k)

        c.mp.setattr(owner, "open", opener)


def _install_replace_fault(c, exc: BaseException) -> None:
    name = _entry_name(c.a2l)
    for fname in ("replace", "rename"):
        real = getattr(os, fname)

        def rep(src, dst, *a, _real=real, **k):
            if _is_name_path(dst, name) or _is_name_path(src, name, prefix=True):
                raise exc
            return _real(src, dst, *a, **k)

        c.mp.setattr(os, fname, rep)


def _install_stream_fault(c, exc: BaseException) -> None:
    """The store's record stream raises ``exc`` after its first record (a write fault in the middle of a store)."""
    real = _codec().encode_records

    def encode(*a, **k):
        it = iter(real(*a, **k))
        yield next(it)
        raise exc

    for mod in (_codec(), _cache()):
        if hasattr(mod, "encode_records"):
            c.mp.setattr(mod, "encode_records", encode)


def _install_unmarshallable(c) -> dict:
    produced: dict = {}

    def hook(real, path, *a, **k):
        payload = real(path, *a, **k)
        payload["errors"] = list(payload["errors"]) + [object()]
        produced["payload"] = payload
        return payload

    c.parse.hook = hook
    return {"parser_object": produced}


def _install_readonly_folder(c) -> None:
    _mk_private_folder(c.env)
    os.chmod(c.env.folder, 0o500)


def _install_wrapper_fault(name: str, exc: BaseException):
    def install(c) -> None:
        def raiser(*a, **k):
            raise exc

        _patch_cache(c.mp, name, raiser)

    return install


def _deferred(install):
    """The fault is installed right before the seam call and removed right after it, so the arm's own snapshots
    (which read the cache folder) never meet it."""

    def setup(c) -> None:
        c.deferred.append(lambda: install(c))

    return setup


def _fault_installer(kind: str):
    secret = lambda cls: cls(errno.EACCES, _SECRET) if cls is PermissionError else cls(errno.EIO, _SECRET)  # noqa: E731
    table = {
        "open-permission": lambda c: _install_open_fault(c, secret(PermissionError)),
        "read-eio": _install_wrapper_fault("read_entry", OSError(errno.EIO, _SECRET)),
        "listing-permission": _install_wrapper_fault("read_entry", PermissionError(errno.EACCES, _SECRET)),
        "rename-permission": lambda c: _install_replace_fault(c, PermissionError(errno.EACCES, _SECRET)),
        "stream-enospc": lambda c: _install_stream_fault(c, OSError(errno.ENOSPC, _SECRET)),
        "unmarshallable": _install_unmarshallable,
        "readonly-folder": _install_readonly_folder,
        "temp-open-erofs": lambda c: _install_open_fault(c, OSError(errno.EROFS, _SECRET), write=True),
        "state-runtime-error": _install_wrapper_fault("cache_state", RuntimeError(_SECRET)),
        "entry-name-key-error": _install_wrapper_fault("entry_name", KeyError(_SECRET)),
        "read-memory-error": _install_wrapper_fault("read_entry", MemoryError(_SECRET)),
    }
    if kind in ("unmarshallable", "readonly-folder"):
        return table[kind]
    return _deferred(table[kind])


# (arm id, prime first, expected line regex, expected exception class name)
FAULT_ARMS = [
    ("open-permission", True, F_READ_FAILED, "PermissionError"),
    ("read-eio", True, F_READ_FAILED, "OSError"),
    ("listing-permission", True, F_READ_FAILED, "PermissionError"),
    ("rename-permission", False, F_WRITE_FAILED, "PermissionError"),
    ("stream-enospc", False, F_WRITE_FAILED, "OSError"),
    ("unmarshallable", False, F_WRITE_FAILED, "ValueError"),
    ("readonly-folder", False, F_WRITE_FAILED, "PermissionError"),
    ("temp-open-erofs", False, F_WRITE_FAILED, "OSError"),
]
OTHER_ARMS = [
    ("state-runtime-error", False, F_FAILED, "RuntimeError"),
    ("entry-name-key-error", False, F_FAILED, "KeyError"),
    ("read-memory-error", True, F_FAILED, "MemoryError"),
]


def _run_fault(tpf, log, kind: str, prime: bool):
    return _run_arm(tpf, log, _fault_installer(kind), prime=prime)


def _check_payload_is_fresh(res, a2l: Path = CASE01_A2L) -> None:
    ref = res.setup.get("parser_object") if isinstance(res.setup, dict) else None
    if ref is not None:
        assert res.entry[1] is ref["payload"]
    else:
        assert _same(res.entry[1], _fresh(a2l))


def _rewrite_hook(st0, restore_mtime: bool):
    def hook(real, path, *a, **k):
        payload = real(path, *a, **k)
        Path(path).write_bytes(A2L_2)
        ns = st0.st_mtime_ns if restore_mtime else st0.st_mtime_ns + 5 * 10**9
        os.utime(path, ns=(ns, ns))
        return payload

    return hook


def _rewrite_setup(st0, restore_mtime: bool):
    def setup(c) -> None:
        c.parse.hook = _rewrite_hook(st0, restore_mtime)

    return setup


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="a read-only folder does not stop root")
def test_r_a2l_cache_007_every_cache_failure_completes_the_load_as_with_the_cache_off(tmp_path_factory, log) -> None:
    """R-A2L-CACHE.007: every off arm, every damaged or non-regular entry, every read or store fault and every
    other exception of the cache work still gives the parser's payload and raises nothing."""
    count = 0
    for arm_id, setup, _reason in OFF_ARMS:
        res = _run_arm(tmp_path_factory, log, setup)
        assert _same(res.entry[1], _fresh(CASE01_A2L)), arm_id
        count += 1
    for arm_id, setup, _reason in ENTRY_ARMS:
        res = _run_arm(tmp_path_factory, log, setup, prime=True)
        assert _same(res.entry[1], _fresh(CASE01_A2L)), arm_id
        count += 1
    for arm_id, prime, _regex, _cls in FAULT_ARMS + OTHER_ARMS:
        res = _run_fault(tmp_path_factory, log, arm_id, prime)
        _check_payload_is_fresh(res)
        count += 1
    res = _run_arm(tmp_path_factory, log, lambda c: c.mp.setenv("S19_A2L_CACHE_MAX_MB", "1"), a2l=SOFTWARE_A)
    assert _same(res.entry[1], _fresh(SOFTWARE_A))
    count += 1
    for restore in (False, True):
        path = _write(tmp_path_factory.mktemp("rw") / "w.a2l", A2L_1)
        res = _run_arm(tmp_path_factory, log, _rewrite_setup(os.stat(path), restore), a2l=path)
        assert res.entry[1]["sections"] is not None
        count += 1
    assert count >= 47, count


# ---------------------------------------------------------------------------
# Module B/C - settings and refusals as the load sees them.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("arm_id,setup,reason", OFF_ARMS, ids=[a[0] for a in OFF_ARMS])
def test_r_a2l_cache_022_off_arms_log_one_reason_and_touch_nothing(tmp_path_factory, log, monkeypatch, arm_id, setup, reason) -> None:
    """R-A2L-CACHE.021 + R-A2L-CACHE.022 (16 of the 24 arms, the Linux-reachable ones): the load completes with the
    parser's payload, exactly one ``A2L parse cache off: <reason>.`` line with that arm's reason and no byte of
    any environment value, the cache base and the link target unchanged, no hash of the A2L file."""
    hashed: list = []

    def counting_setup(c) -> None:
        setup(c)
        real = _cache().content_digest

        def digest(*a, **k):
            hashed.append(1)
            return real(*a, **k)

        _patch_cache(c.mp, "content_digest", digest)

    res = _run_arm(tmp_path_factory, log, counting_setup)
    assert hashed == [], "the A2L file was hashed although the cache is off"
    assert _same(res.entry[1], _fresh(CASE01_A2L))
    assert res.lines == [f"A2L parse cache off: {reason}."], res.lines
    assert len(res.calls) == 1
    assert res.after == res.before, "something under the cache base or the link target changed"


def test_r_a2l_cache_021_sticky_base_with_private_folders_is_usable(tmp_path_factory, log) -> None:
    """R-A2L-CACHE.021 control: a cache base of mode 1777 with private app cache folders is usable: one entry."""

    def setup(c) -> None:
        _mk_private_folder(c.env)
        os.chmod(c.env.base, 0o1777)

    res = _run_arm(tmp_path_factory, log, setup)
    assert len(res.lines) == 2 and F_MISS.match(res.lines[0]) and F_STORED.match(res.lines[1]), res.lines
    assert len([p for p in res.folder.iterdir()]) == 1


@pytest.mark.parametrize("value", ["off", "OFF"])
def test_r_a2l_cache_022_setting_off_keeps_stored_parses_and_creates_nothing(tmp_path, env, monkeypatch, log, value) -> None:
    """R-A2L-CACHE.022: ``S19_A2L_CACHE`` off logs exactly one ``off: setting.`` line, parses once, creates no file
    under the cache base."""
    parse = _Parse(monkeypatch)
    monkeypatch.setenv("S19_A2L_CACHE", value)
    before = _snapshot(env.base)
    log.messages.clear()
    _seam(CASE01_A2L)
    assert log.cache_lines() == ["A2L parse cache off: setting."]
    assert len(parse.calls) == 1
    assert _snapshot(env.base) == before == {}


_INVALID_SIZES = ["0", "-5", "+5", "5.0", "1e3", " 5", "1048577", "\x1b5", "9" * 32750, "٣", "5\n"]


@pytest.mark.parametrize("value", _INVALID_SIZES, ids=[f"invalid-{i}" for i in range(len(_INVALID_SIZES))])
def test_r_a2l_cache_017_invalid_size_setting_is_logged_once_per_store_without_the_value(tmp_path, env, monkeypatch, log, value) -> None:
    """R-A2L-CACHE.017: a non-empty invalid ``S19_A2L_CACHE_MAX_MB`` logs ``size setting not recognised: 2048 MiB
    used.`` once for the store, and no byte of the value appears in any log line."""
    monkeypatch.setenv("S19_A2L_CACHE_MAX_MB", value)
    a2l = _write(tmp_path / "s.a2l", A2L_1)
    log.messages.clear()
    _seam(a2l)
    assert log.cache_lines().count(F_SIZE) == 1, log.cache_lines()
    assert len(log.matching(F_STORED)) == 1
    for line in log.messages:
        assert "\x1b" not in line and "٣" not in line and "9" * 20 not in line, line[:80]
    assert [l for l in log.cache_lines() if "size setting" in l] == [F_SIZE]


@pytest.mark.parametrize("value", [None, ""], ids=["unset", "empty"])
def test_r_a2l_cache_017_unset_and_empty_size_setting_log_nothing(tmp_path, env, monkeypatch, log, value) -> None:
    """R-A2L-CACHE.017: an unset or empty size setting logs no size line."""
    if value is not None:
        monkeypatch.setenv("S19_A2L_CACHE_MAX_MB", value)
    log.messages.clear()
    _seam(_write(tmp_path / "s.a2l", A2L_1))
    assert F_SIZE not in log.cache_lines()
    assert len(log.matching(F_STORED)) == 1


def test_r_a2l_cache_010_entry_holds_no_path_and_no_name(tmp_path, env, monkeypatch) -> None:
    """R-A2L-CACHE.010 (2 arms): case_01 loaded from a folder named ``zz-path-probe`` and from a file named
    ``zzprobe.a2l``: the entry's bytes hold neither marker, nor the start folder, nor the HOME folder name."""
    cache_dir_markers = (b"zz-path-probe", b"zzprobe")
    content = CASE01_A2L.read_bytes()
    assert not any(m in content for m in cache_dir_markers)
    for rel in ("zz-path-probe/firmware.a2l", "zzprobe.a2l"):
        _clear_entries(env)
        path = _write(tmp_path / rel, content)
        _seam(path)
        files = list(env.folder.iterdir())
        assert len(files) == 1, files
        data = files[0].read_bytes()
        for marker in (*cache_dir_markers, str(tmp_path).encode(), env.home.name.encode(), str(env.home).encode()):
            assert marker not in data, (rel, marker)


# ---------------------------------------------------------------------------
# Module E - log lines.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name,a2l", _THREE, ids=[n for n, _p in _THREE])
def test_r_a2l_cache_033_each_hit_logs_one_line_with_the_entry_size(env, monkeypatch, log, name, a2l) -> None:
    """R-A2L-CACHE.033 (3 files x 2 hits = 6): each stored-parse hit logs exactly one hit line whose entry_bytes is
    the entry's size; a miss or a store logs no hit line."""
    _seam(a2l)
    assert log.matching(F_HIT) == [], "the cold load logged a hit"
    entry = env.folder / _entry_name(a2l)
    for _ in range(2):
        log.messages.clear()
        _seam(a2l)
        hits = log.matching(F_HIT)
        assert len(hits) == 1, log.cache_lines()
        n, seconds = F_HIT.match(hits[0]).groups()
        assert int(n) == entry.stat().st_size and float(seconds) >= 0.0


@pytest.mark.parametrize("name,a2l", _THREE, ids=[n for n, _p in _THREE])
def test_r_a2l_cache_034_035_cold_load_logs_one_miss_then_one_stored(env, monkeypatch, log, name, a2l) -> None:
    """R-A2L-CACHE.034 + R-A2L-CACHE.035 (3 cold loads): exactly one miss line with the A2L file size, then exactly
    one stored line with the entry's size."""
    _seam(a2l)
    lines = log.cache_lines()
    assert len(lines) == 2 and F_MISS.match(lines[0]) and F_STORED.match(lines[1]), lines
    assert int(F_MISS.match(lines[0]).group(1)) == a2l.stat().st_size
    assert int(F_STORED.match(lines[1]).group(1)) == (env.folder / _entry_name(a2l)).stat().st_size


@pytest.mark.parametrize("arm_id,setup,reason", ENTRY_ARMS, ids=[a[0] for a in ENTRY_ARMS])
def test_r_a2l_cache_039_unusable_entry_logs_its_reason_and_damaged_ones_are_replaced(tmp_path_factory, log, arm_id, setup, reason) -> None:
    """R-A2L-CACHE.034 + R-A2L-CACHE.037 (load side) + R-A2L-CACHE.038 + R-A2L-CACHE.039 (17 of the 19 arms): exactly
    one ``entry unusable: <reason>.`` line, then exactly one miss line with the A2L file size (no usable entry
    holds the name, CACHE.034, E4-3); a damaged entry is parsed once and replaced by a usable entry, and no
    pickle sentinel is written; a link or folder of the entry name is left unchanged and nothing is stored over
    it."""
    res = _run_arm(tmp_path_factory, log, setup, prime=True)
    unusable = [l for l in res.lines if F_UNUSABLE.match(l)]
    assert unusable == [f"A2L parse cache entry unusable: {reason}."], res.lines
    assert len(res.calls) == 1
    assert _same(res.entry[1], _fresh(CASE01_A2L))
    assert not res.c.sentinel.exists()
    path = res.folder / res.name
    misses = [l for l in res.lines if F_MISS.match(l)]
    assert len(misses) == 1, res.lines
    assert res.lines.index(unusable[0]) < res.lines.index(misses[0])
    assert int(F_MISS.match(misses[0]).group(1)) == CASE01_A2L.stat().st_size
    if reason == "damaged":
        assert len([l for l in res.lines if F_STORED.match(l)]) == 1
        assert path.is_file() and not path.is_symlink() and path.read_bytes()[:8] == b"S19A2LC\n"
    else:
        assert [l for l in res.lines if F_STORED.match(l)] == []
        assert path.is_symlink() or path.is_dir()
        assert res.after["outside"] == res.before["outside"]


@pytest.mark.parametrize("arm_id,prime,regex,cls", FAULT_ARMS, ids=[a[0] for a in FAULT_ARMS])
@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="a read-only folder does not stop root")
def test_r_a2l_cache_043_read_and_store_failures_log_the_class_name_only(tmp_path_factory, log, arm_id, prime, regex, cls) -> None:
    """R-A2L-CACHE.041 + R-A2L-CACHE.042 + R-A2L-CACHE.043 + R-A2L-CACHE.035 (8 arms): exactly one read failed or write
    failed line carrying the exception class name only (never the exception text, which names a path), a store
    failure logs no stored line, leaves no temporary file, the parser ran once and the load completed; a read
    failure is followed by exactly one miss line with the A2L file size (CACHE.034: no usable entry served the
    load; E5 E4-3-G1 option b)."""
    res = _run_fault(tmp_path_factory, log, arm_id, prime)
    matching = [l for l in res.lines if regex.match(l)]
    assert len(matching) == 1 and regex.match(matching[0]).group(1) == cls, res.lines
    assert not any(_SECRET in m for m in res.messages)
    assert [l for l in res.lines if F_STORED.match(l)] == []
    assert len(res.calls) == 1
    _check_payload_is_fresh(res)
    names = sorted(p.name for p in res.folder.iterdir()) if res.folder.is_dir() else []
    assert not any(".tmp-" in n for n in names), names
    if regex is F_READ_FAILED:
        assert res.after == res.before, "a read failure changed the cache folder"
        misses = [l for l in res.lines if F_MISS.match(l)]
        assert len(misses) == 1, res.lines
        assert res.lines.index(matching[0]) < res.lines.index(misses[0])
        assert int(F_MISS.match(misses[0]).group(1)) == CASE01_A2L.stat().st_size


@pytest.mark.parametrize("arm_id,prime,regex,cls", OTHER_ARMS, ids=[a[0] for a in OTHER_ARMS])
def test_r_a2l_cache_046_055_other_exceptions_complete_the_load_and_log_the_class(tmp_path_factory, log, arm_id, prime, regex, cls) -> None:
    """R-A2L-CACHE.046 + R-A2L-CACHE.055 (3 arms): a RuntimeError in the state, a KeyError in the entry-name
    computation and a MemoryError in the read complete the load as with the cache off (payload equals a fresh
    parse) and log exactly one ``A2L parse cache failed: <class>.`` line without the exception text."""
    res = _run_fault(tmp_path_factory, log, arm_id, prime)
    assert [l for l in res.lines if F_FAILED.match(l)] == [f"A2L parse cache failed: {cls}."], res.lines
    assert not any(_SECRET in m for m in res.messages)
    assert _same(res.entry[1], _fresh(CASE01_A2L))
    assert len(res.calls) == 1


def test_r_a2l_cache_046_keyboard_interrupt_in_the_state_is_not_swallowed(env, monkeypatch) -> None:
    """R-A2L-CACHE.046: a KeyboardInterrupt from the cache work propagates; the cache never catches BaseException."""
    _Parse(monkeypatch)

    def interrupt(*a, **k):
        raise KeyboardInterrupt

    _patch_cache(monkeypatch, "cache_state", interrupt)
    with pytest.raises(KeyboardInterrupt):
        _seam(CASE01_A2L)


def test_r_a2l_cache_036_eviction_is_logged_once_with_the_deleted_count_and_bytes(tmp_path, env, monkeypatch, log) -> None:
    """R-A2L-CACHE.036: a store that deletes two older entries logs one ``evicted`` line with the deleted count and
    bytes; stores that delete nothing log none."""
    monkeypatch.setenv("S19_A2L_CACHE_MAX_MB", "1")
    folder = _mk_private_folder(env)
    sizes = {"a": 450_000, "b": 450_000, "c": 900_000}
    now = time.time_ns()
    for i, (key, size) in enumerate(sizes.items()):
        p = folder / hashlib.sha256(key.encode()).hexdigest()
        p.write_bytes(b"x" * size)
        os.chmod(p, 0o600)
        _set_utime_ns(p, now - (10 - i) * 10**9)
    log.messages.clear()
    _seam(_write(tmp_path / "e.a2l", A2L_1))
    evicted = log.matching(F_EVICTED)
    assert len(evicted) == 1, log.cache_lines()
    files, size = map(int, F_EVICTED.match(evicted[0]).groups())
    assert (files, size) == (2, sizes["a"] + sizes["b"])
    assert (folder / hashlib.sha256(b"c").hexdigest()).exists()
    assert not (folder / hashlib.sha256(b"a").hexdigest()).exists()


def test_r_a2l_cache_036_stores_that_delete_nothing_log_no_evicted_line(tmp_path, env, log) -> None:
    """R-A2L-CACHE.036: a cold store into an empty cache folder logs no evicted line."""
    _seam(_write(tmp_path / "e.a2l", A2L_1))
    assert log.matching(F_EVICTED) == []


# ---------------------------------------------------------------------------
# CACHE.044 / .045 - nothing is stored when the parse or the file is not what the digest named.
# ---------------------------------------------------------------------------


def test_r_a2l_cache_044_045_stored_parse_over_the_size_cap_is_not_stored(env, monkeypatch, log) -> None:
    """R-A2L-CACHE.044 + R-A2L-CACHE.045: with a size cap of 1 MiB the stored parse of software_a is larger than the
    cap: no entry, no temporary file, one ``not stored: entry larger than the size cap.`` line."""
    monkeypatch.setenv("S19_A2L_CACHE_MAX_MB", "1")
    _seam(SOFTWARE_A)
    assert [l for l in log.cache_lines() if F_NOT_STORED.match(l)] == [
        "A2L parse cache not stored: entry larger than the size cap."
    ]
    assert _entry_files(env) == []
    assert log.matching(F_STORED) == []


@pytest.mark.parametrize("restore_mtime", [False, True], ids=["new-mtime", "mtime-restored"])
def test_r_a2l_cache_044_045_rewrite_during_the_parse_is_not_stored(tmp_path, env, monkeypatch, log, restore_mtime) -> None:
    """R-A2L-CACHE.044 + R-A2L-CACHE.045 (2 arms): the A2L rewritten with other content of the same size during the
    parse (a new mtime; or its ``mtime_ns`` restored by ``os.utime``, which only a re-digest sees) is not stored,
    one ``not stored: file changed during the parse.`` line, no entry, and a later load parses again."""
    a2l = _write(tmp_path / "w.a2l", A2L_1)
    parse = _Parse(monkeypatch)
    parse.hook = _rewrite_hook(os.stat(a2l), restore_mtime)
    log.messages.clear()
    _seam(a2l)
    assert [l for l in log.cache_lines() if F_NOT_STORED.match(l)] == [
        "A2L parse cache not stored: file changed during the parse."
    ], log.cache_lines()
    assert log.matching(F_STORED) == []
    assert _entry_files(env) == []
    parse.hook = None
    _seam(a2l)
    assert len(parse.calls) == 2


# ---------------------------------------------------------------------------
# Module G - the collector around the cache work (CACHE.057, seam level).
# ---------------------------------------------------------------------------

_GC_OUTCOMES = {
    "hit": (True, lambda c: None),
    "absent-then-stored": (False, lambda c: None),
    "damaged": (True, _setup_damaged("40-bytes")),
    "open-permission": (True, _fault_installer("open-permission")),
    "enospc-mid-store": (False, _fault_installer("stream-enospc")),
}


@pytest.mark.parametrize("gc_before", [True, False], ids=["collector-on", "collector-off"])
@pytest.mark.parametrize("outcome", sorted(_GC_OUTCOMES))
def test_r_a2l_cache_057_collector_state_is_restored_on_every_outcome(tmp_path_factory, log, outcome, gc_before) -> None:
    """R-A2L-CACHE.057 (10 arms): after a hit, an absent entry then a store, a damaged entry, a PermissionError on the
    open and an ENOSPC in the middle of a store, with the collector on or off before the call, the collector is in the
    state it had before; the cache code never calls ``gc.collect``; the load still completes."""
    prime, setup = _GC_OUTCOMES[outcome]
    res = _run_arm(tmp_path_factory, log, setup, prime=prime, gc_before=gc_before)
    assert res.gc_after is gc_before, f"{outcome}: collector {res.gc_after} after the seam, {gc_before} before"
    assert res.collects == [], res.collects
    assert _same(res.entry[1], _fresh(CASE01_A2L))


# ---------------------------------------------------------------------------
# The route arms: threads (CACHE.048), progress (CACHE.049), ticks (CACHE.051), collector (CACHE.056).
# ---------------------------------------------------------------------------


def _warm_up(a2l: Path) -> None:
    """Store the entry of ``a2l`` through the seam, as an earlier app would have."""
    _seam(a2l)


def _wrap_cache_calls(mp, record: Callable) -> None:
    """Wrap ``content_digest``, ``read_entry`` and ``store_entry``: ``record(name, "start"|"end", args, kwargs)``."""
    cache = _cache()
    for name in ("content_digest", "read_entry", "store_entry"):
        real = getattr(cache, name)

        def wrapper(*a, _real=real, _name=name, **k):
            record(_name, "start", a, k)
            try:
                return _real(*a, **k)
            finally:
                record(_name, "end", a, k)

        _patch_cache(mp, name, wrapper)


@pytest.mark.parametrize("warm", [False, True], ids=["cold", "warm"])
@pytest.mark.parametrize("route", ROUTES)
def test_r_a2l_cache_048_cache_work_runs_on_the_loads_worker_thread(tmp_path, env, monkeypatch, route, warm) -> None:
    """R-A2L-CACHE.048 (4 routes x cold/warm = 8 arms): every hash, open, read, write, rename and delete of the
    cache for a load runs on a thread other than the UI thread."""
    main = threading.get_ident()
    if warm:
        _warm_up(CASE01_A2L)
    calls: list = []

    def arm(app):
        fs = _FsSpy(monkeypatch, env.base)
        _wrap_cache_calls(monkeypatch, lambda name, phase, a, k: calls.append((name, threading.get_ident())))
        return fs

    res = _run_route(tmp_path, monkeypatch, env, route, CASE01_A2L, arm=arm, cold_image=not warm)
    _assert_ok(res, route)
    fs = res.ctx
    names = {n for n, _t in calls}
    assert {"content_digest"} <= names and ("read_entry" in names if warm else "store_entry" in names), (route, warm, names)
    assert main not in {t for _n, t in calls}, (route, warm, calls)
    assert fs.events, "no cache file-system call was recorded"
    assert main not in fs.threads(), (route, warm, sorted(fs.labels()))
    assert "open" in fs.labels(), sorted(fs.labels())


@pytest.mark.parametrize("warm", [False, True], ids=["cold", "warm"])
@pytest.mark.parametrize("route", ROUTES)
def test_r_a2l_cache_056_collector_is_off_during_every_read_and_store(tmp_path, env, monkeypatch, route, warm) -> None:
    """R-A2L-CACHE.056 (4 routes x cold/warm = 8 arms): ``gc.isenabled()`` sampled at the start of ``read_entry`` and
    ``store_entry`` and after each chunk read or written is False every time, including on the image+A2L route whose
    worker parses with the collector on."""
    if warm:
        _warm_up(CASE01_A2L)
    samples: list = []
    cache, codec = _cache(), _codec()
    real_read = cache.read_entry

    def read_w(*a, **k):
        samples.append(("read-start", gc.isenabled()))
        args = list(a)
        progress = args[3] if len(args) > 3 else k.get("progress")

        def sampling(done, total):
            samples.append(("read-chunk", gc.isenabled()))
            if progress is not None:
                progress(done, total)

        if len(args) > 3:
            args[3] = sampling
        else:
            k["progress"] = sampling
        return real_read(*args, **k)

    real_store = cache.store_entry

    def store_w(*a, **k):
        samples.append(("store-start", gc.isenabled()))
        return real_store(*a, **k)

    real_encode = codec.encode_records

    def encode_w(*a, **k):
        for record in real_encode(*a, **k):
            samples.append(("store-chunk", gc.isenabled()))
            yield record

    def arm(app):
        _patch_cache(monkeypatch, "read_entry", read_w)
        _patch_cache(monkeypatch, "store_entry", store_w)
        for mod in (codec, cache):
            if hasattr(mod, "encode_records"):
                monkeypatch.setattr(mod, "encode_records", encode_w)

    res = _run_route(tmp_path, monkeypatch, env, route, CASE01_A2L, arm=arm, cold_image=not warm)
    _assert_ok(res, route)
    kinds = {k for k, _v in samples}
    assert ("read-start" in kinds) and ("store-start" in kinds if not warm else "read-chunk" in kinds), (route, warm, kinds)
    assert len(samples) >= 2 and all(v is False for _k, v in samples), (route, warm, [x for x in samples if x[1]])


_IMAGE_GC_OUTCOMES = ("success", "parse-raises", "unsupported", "prepare-raises")


@pytest.mark.parametrize("outcome", _IMAGE_GC_OUTCOMES)
def test_r_a2l_cache_051_r_a2l_refresh_051_image_worker_holds_the_collector_for_the_whole_worker(
        tmp_path, env, monkeypatch, log, outcome) -> None:
    """R-A2L-CACHE.051, .056 (P-H3-1) and R-A2L-REFRESH.051 (4 arms): an image load with case_01's A2L installed
    and its stored parse on disk (no in-memory entry) has the collector off at the seam's start, at its return and
    at the image parse - the whole worker, not only inside the cache's own hold - and, whether the load is
    installed or fails in the image parse, on an unsupported payload or in the preparation, the collector is
    enabled at the outcome and after the worker.
    Why: with the collector on around the read, the first allocation after it pays a 331-424 ms collection on
    the worker (E4-H3 cause B) and a due UI tick fires 390 ms late on case_06. Negative controls: 1f4e4a73a
    samples True at the seam's start (RED); a hold that the unsupported-payload exit does not undo leaves the
    collector off at that outcome (RED)."""
    deps = _deps()
    samples: list = []
    real_seam, real_parse = deps.parse_a2l_cached, S19TuiApp._parse_data_file

    def seam(*a, **k):
        samples.append(("seam-start", gc.isenabled()))
        try:
            return real_seam(*a, **k)
        finally:
            samples.append(("seam-return", gc.isenabled()))

    def parse(self_, *a, **k):
        samples.append(("image-parse", gc.isenabled()))
        if outcome == "parse-raises":
            raise ValueError("H3_CONTROL")
        return None if outcome == "unsupported" else real_parse(self_, *a, **k)

    def boom(self_, *a, **k):
        raise ValueError("H3_CONTROL")

    async def body(app, pilot):
        _mount_views(app)
        await pilot.pause()
        await _typed_attach(app, pilot, CASE01_A2L)
        await settle_workers(pilot)
        app._a2l_cache_key = None
        app._a2l_cache_data = None
        log.messages.clear()
        outcomes: list = []
        real_end = S19TuiApp.end_busy

        def end(key, gen, text):
            outcomes.append((key, str(text), gc.isenabled()))
            return real_end(app, key, gen, text)

        monkeypatch.setattr(app, "end_busy", end)
        monkeypatch.setattr(deps, "parse_a2l_cached", seam)
        monkeypatch.setattr(S19TuiApp, "_parse_data_file", parse)
        if outcome == "prepare-raises":
            monkeypatch.setattr(S19TuiApp, "_prepare_load_payload", boom)
        await _drive_typed_no_assert(app, pilot, CASE01_IMAGE)
        await settle_workers(pilot)
        await wait_until(pilot, lambda: any(o[0] == "file_load" for o in outcomes), "the image outcome", timeout=120.0)
        await settle_workers(pilot)
        await pilot.pause()
        return outcomes, gc.isenabled()

    outcomes, gc_after = _run(tmp_path, body)
    assert log.matching(F_HIT), "the image worker never read the stored parse: the arm would be vacuous"
    assert [k for k, _v in samples][:3] == ["seam-start", "seam-return", "image-parse"], samples
    assert all(v is False for _k, v in samples), (outcome, samples)
    mine = [o for o in outcomes if o[0] == "file_load"]
    assert len(mine) == 1 and mine[0][1].startswith("Loaded") is (outcome == "success"), (outcome, outcomes)
    assert mine[0][2] is True and gc_after is True, (outcome, outcomes, gc_after)


class _Ticks:
    """A self-re-arming 50 ms timer on the UI loop: (due, fired, lateness) per tick."""

    def __init__(self, app) -> None:
        self.app = app
        self.observations: list = []
        self.stopped = False
        self._due = time.perf_counter() + 0.05
        app.set_timer(0.05, self._fire)

    def _fire(self) -> None:
        if self.stopped:
            return
        fired = time.perf_counter()
        self.observations.append((self._due, fired, fired - self._due))
        self._due = fired + 0.05
        self.app.set_timer(0.05, self._fire)


@pytest.mark.serial_timing
@pytest.mark.parametrize("warm", [False, True], ids=["cold", "warm"])
@pytest.mark.parametrize("route", ["attach", "image"])
@pytest.mark.parametrize("name,a2l", [("software_a", SOFTWARE_A), ("d171", V171_A2L)], ids=["software_a", "d171"])
def test_r_a2l_cache_051_ui_ticks_stay_within_100ms_during_cache_work(tmp_path, env, monkeypatch, name, a2l, route, warm) -> None:
    """R-A2L-CACHE.051 (CI arms, 8): every due tick of a 50 ms UI timer inside a hash, read or store of the cache
    (the parse between them is not bounded by this row) fires at most 100 ms late, on the direct-attach and image+A2L routes, cold and warm.
    The whole-body negative control goes RED only on the host (E3 F-14): these arms are partial."""
    if warm:
        _warm_up(a2l)
    spans: list = []
    open_calls: dict = {}

    def record(call, phase, a, k) -> None:
        key = (call, threading.get_ident())
        if phase == "start":
            open_calls[key] = time.perf_counter()
        else:
            spans.append((open_calls.pop(key), time.perf_counter()))

    def arm(app):
        _wrap_cache_calls(monkeypatch, record)
        return _Ticks(app)

    res = _run_route(tmp_path, monkeypatch, env, route, a2l, arm=arm, cold_image=not warm)
    _assert_ok(res, route)
    ticks = res.ctx
    ticks.stopped = True
    assert spans, "the cache work was never reached"
    inside = [(due, l) for due, _f, l in ticks.observations if any(s <= due <= e for s, e in spans)]
    assert [round(l, 3) for _due, l in inside if l > timing_bound(0.100)] == [], (
        f"late ticks inside the hash, read and store spans: {[round(l, 3) for _due, l in inside if l > timing_bound(0.100)]}")
    assert ticks.observations, "the timer never fired during the load"
    if name == "software_a":
        assert inside, "no tick fell inside the cache spans of the largest committed file: the arm would be vacuous"
    print(f"R-A2L-CACHE.051 {route}/{name}/{'warm' if warm else 'cold'}: spans={len(spans)} "
          f"span_ms={sum(e - s for s, e in spans) * 1000:.1f} ticks_inside={len(inside)} ticks_total={len(ticks.observations)}")


HOST_CASE06_ENV = "S19_P279_HOST_CASE06"


def _host_case06() -> Path:
    """The case_06 A2L a host arm is given through ``S19_P279_HOST_CASE06``; without it the node skips."""
    raw = os.environ.get(HOST_CASE06_ENV, "")
    if not raw:
        pytest.skip(f"host arm on case_06: set {HOST_CASE06_ENV} to its A2L path (reference host only)")
    path = Path(raw)
    assert path.is_file(), f"{HOST_CASE06_ENV} names no file"
    return path


class _StepClock:
    """Times every call of the seam ``parse_a2l_cached`` (the parse step) and of the hit-payload rebuild."""

    def __init__(self, mp) -> None:
        deps = _deps()
        self.steps: list = []
        self.rebuilds: list = []
        self.parse = _Parse(mp)
        mp.setattr(deps, "parse_a2l_cached", self._timed(deps.parse_a2l_cached, self.steps))
        if hasattr(deps, "_hit_payload"):
            mp.setattr(deps, "_hit_payload", self._timed(deps._hit_payload, self.rebuilds))

    @staticmethod
    def _timed(real, sink: list):
        def timed(*a, **k):
            started = time.perf_counter()
            try:
                return real(*a, **k)
            finally:
                sink.append(time.perf_counter() - started)

        return timed

    def reset(self) -> None:
        self.steps.clear()
        self.rebuilds.clear()
        self.parse.calls.clear()


def _host_run(tmp_path: Path, env, clock: _StepClock, route: str, a2l: Path, *, warm: bool, label: str):
    """One load of ``a2l`` on ``route`` in a fresh app (no in-memory entry) under its own cache base, stored
    first through the seam when ``warm``; the cache base is deleted before returning."""
    base = env.tpf.mktemp("xdgh")
    os.chmod(base, 0o700)
    env.mp.setenv("XDG_CACHE_HOME", str(base))
    folder = base / "s19_app" / "a2l"
    try:
        if warm:
            _seam(a2l)
            assert folder.is_dir() and any(folder.iterdir()), f"{label}: the warm-up stored no entry"
        clock.reset()
        res = _run_route(tmp_path / label, env.mp, env, route, a2l)
        _assert_ok(res, route)
        assert len(clock.steps) == 1, f"{label}: {len(clock.steps)} parse steps in one load"
        stored = folder.is_dir() and any(folder.iterdir())
        return SimpleNamespace(step=clock.steps[0], parses=len(clock.parse.calls), rebuild=sum(clock.rebuilds),
                               stored=stored)
    finally:
        shutil.rmtree(base, ignore_errors=True)


@pytest.mark.serial_timing
def test_r_a2l_cache_052_host_case_06_hit_parse_step_within_3s(tmp_path, env, monkeypatch) -> None:
    """R-A2L-CACHE.052 (host arm H-1; skipped unless ``S19_P279_HOST_CASE06`` names case_06's A2L): with a usable
    entry and no in-memory entry, the parse step (the seam call on the load's worker) on the pair and attach routes
    has a median of 3 runs <= 3.0 s and no run >= 4.0 s; each run has its own cache base, deleted after it."""
    a2l = _host_case06()
    clock = _StepClock(monkeypatch)
    runs = {route: [_host_run(tmp_path, env, clock, route, a2l, warm=True, label=f"h1-{route}-{i}") for i in range(3)]
            for route in ("project-pair", "attach")}
    for route, rs in runs.items():
        print(f"R-A2L-CACHE.052 {route}: step_s={[round(r.step, 3) for r in rs]} "
              f"rebuild_s={[round(r.rebuild, 3) for r in rs]} parses={[r.parses for r in rs]}")
    for route, rs in runs.items():
        assert [r.parses for r in rs] == [0, 0, 0], f"{route}: a load with a usable entry parsed"
        steps = [r.step for r in rs]
        median = statistics.median(steps)
        assert median <= report_margin(f"CACHE.052 {route} median", median, timing_bound(3.0)), (route, steps)
        assert max(steps) < timing_bound(4.0), (route, steps)


@pytest.mark.serial_timing
def test_r_a2l_cache_053_host_case_06_cold_store_costs_at_most_1_5s(tmp_path, env, monkeypatch) -> None:
    """R-A2L-CACHE.053 (host arm H-2; skipped unless ``S19_P279_HOST_CASE06`` names case_06's A2L): the cold parse
    step on the pair route with the cache setting on is at most 1.5 s longer than with it off, median of 3 runs
    each (interleaved); every run, the off runs included, has its own cache base, deleted after it."""
    a2l = _host_case06()
    clock = _StepClock(monkeypatch)
    on, off = [], []
    for i in range(3):
        monkeypatch.delenv("S19_A2L_CACHE", raising=False)
        on.append(_host_run(tmp_path, env, clock, "project-pair", a2l, warm=False, label=f"h2-on-{i}"))
        monkeypatch.setenv("S19_A2L_CACHE", "off")
        off.append(_host_run(tmp_path, env, clock, "project-pair", a2l, warm=False, label=f"h2-off-{i}"))
    monkeypatch.delenv("S19_A2L_CACHE", raising=False)
    print(f"R-A2L-CACHE.053 pair: on_s={[round(r.step, 3) for r in on]} off_s={[round(r.step, 3) for r in off]}")
    assert [r.parses for r in on + off] == [1] * 6, "a cold load did not parse exactly once"
    assert all(r.stored for r in on) and not any(r.stored for r in off), "the on runs must store and the off runs not"
    delta = statistics.median(r.step for r in on) - statistics.median(r.step for r in off)
    assert delta <= report_margin("CACHE.053 pair on minus off", delta, timing_bound(1.5)), (on, off)


def test_r_a2l_cache_049_progress_rises_in_proportion_to_the_entry_bytes_read(tmp_path, env, monkeypatch) -> None:
    """R-A2L-CACHE.049: software_a warm with the chunk bound at 64 KiB (an entry of at least 8 chunks): the parse
    step's reports rise monotonically, the last equals the entry size, at least 8 distinct amounts are forwarded,
    and the bar never falls."""
    codec, cache = _codec(), _cache()
    real_encode = codec.encode_records

    def small_chunks(stored_parse, bound=65_536, *a, **k):
        return real_encode(stored_parse, 65_536)

    for mod in (codec, cache):
        if hasattr(mod, "encode_records"):
            monkeypatch.setattr(mod, "encode_records", small_chunks)
    _warm_up(SOFTWARE_A)
    entry = env.folder / _entry_name(SOFTWARE_A)
    raw = entry.read_bytes()
    chunk_count = struct.unpack(">I", raw[76:80])[0]
    assert chunk_count >= 8, chunk_count
    records: list = []

    def arm(app):
        real = S19TuiApp.step_busy

        def step(self_, key, gen, n, done=None, total=None):
            real(self_, key, gen, n, done, total)
            records.append((key, n, done, total, app.query_one("#progress_bar").progress))

        monkeypatch.setattr(S19TuiApp, "step_busy", step)

    res = _run_route(tmp_path, monkeypatch, env, "attach", SOFTWARE_A, arm=arm)
    _assert_ok(res, "attach")
    mine = [r for r in records if r[2] is not None and r[3] == len(raw)]
    amounts = [r[2] for r in mine]
    assert amounts == sorted(amounts) and len(set(amounts)) >= 8, amounts
    assert amounts[-1] == len(raw)
    bars = [r[4] for r in mine]
    assert bars == sorted(bars), bars
    for _key, n, done, total, bar in mine:
        assert bar == int(100 * (n - 1 + done / total) // 3), (n, done, total, bar)


# ---------------------------------------------------------------------------
# Module D - the start option (main), in-process and as a subprocess.
# ---------------------------------------------------------------------------


def _plant_files(folder: Path, sizes: list, *, temporary: int = 0) -> dict:
    """Put regular entry files of the given sizes in the existing ``folder`` (the last ``temporary`` of them as
    temporary files, the very last one stale, the others fresh). Returns name -> size."""
    out: dict = {}
    for i, size in enumerate(sizes):
        name = hashlib.sha256(f"entry-{i}".encode()).hexdigest()
        if i >= len(sizes) - temporary:
            name += f".tmp-{i:016x}"
        p = folder / name
        p.write_bytes(b"x" * size)
        os.chmod(p, 0o600)
        if i == len(sizes) - 1 and temporary:
            old = time.time_ns() - 3 * 3600 * 10**9
            _set_utime_ns(p, old)
        out[name] = size
    return out


def _plant_foreign(folder: Path) -> dict:
    """The four foreign files of CACHE.014: they are never read, counted or deleted."""
    (folder / "x").mkdir()
    (folder / "notes.txt").write_bytes(b"n" * 5000)
    (folder / hashlib.sha256(b"upper").hexdigest().upper()).write_bytes(b"U" * 20)
    (folder / hashlib.sha256(b"short").hexdigest()[:63]).write_bytes(b"S" * 20)
    return _snapshot(folder)


def _run_main(monkeypatch, capsys, argv: list, cwd: Path):
    """``main`` in-process with ``sys.argv`` set, in ``cwd``; ``S19TuiApp`` construction is a counting failure."""
    core = _core()
    constructed: list = []

    class _NoApp:
        def __init__(self, *a, **k) -> None:
            constructed.append(1)
            raise AssertionError("S19TuiApp was built for a start option that must not start the TUI")

    monkeypatch.chdir(cwd)
    monkeypatch.setattr(sys, "argv", ["s19tui", *argv])
    monkeypatch.setattr(core, "S19TuiApp", _NoApp)
    code = None
    try:
        core.main()
    except SystemExit as exc:
        code = exc.code
    out, err = capsys.readouterr()
    return code, out, err, constructed


def _sub_env(env) -> dict:
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(env.home),
        "XDG_CACHE_HOME": str(env.base),
        "LOCALAPPDATA": str(env.lad),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONIOENCODING": "utf-8",
        "LANG": "C.UTF-8",
        "COLUMNS": "500",
    }


def _run_cli(env, cwd: Path, *args: str):
    """``python -c "from s19_app.tui import main; main()" <args>`` in a fresh cwd with an isolated environment."""
    code = f"import sys; sys.path.insert(0, {str(ROOT)!r}); from s19_app.tui import main; main()"
    return subprocess.run([sys.executable, "-c", code, *args], cwd=cwd, env=_sub_env(env), capture_output=True,
                          text=True, timeout=180)


def test_r_a2l_cache_027_clear_prints_count_and_bytes_and_exits_zero(tmp_path, env, monkeypatch, capsys) -> None:
    """R-A2L-CACHE.027 (+ R-A2L-CACHE.026 load side): 7 removable files (5 entries, a fresh and a stale temporary
    file) and the 4 foreign files: stdout is exactly ``A2L cache cleared: 7 files, <sum of their sizes> bytes.``,
    exit 0, the removable files gone, the foreign files unchanged."""
    folder = _mk_private_folder(env)
    planted = _plant_files(folder, [1000, 100, 100, 20, 10, 2, 2], temporary=2)
    foreign = {k: v for k, v in _plant_foreign(folder).items() if k not in planted}
    start = tmp_path / "start"
    start.mkdir()
    code, out, err, built = _run_main(monkeypatch, capsys, ["--clear-a2l-cache"], start)
    assert (code, built) == (0, []), (code, err)
    assert out == f"A2L cache cleared: 7 files, {sum(planted.values())} bytes.\n"
    assert not any((folder / n).exists() for n in planted)
    assert _snapshot(folder) == foreign


def test_r_a2l_cache_027_clear_with_no_cache_folder_prints_zero_and_creates_nothing(tmp_path, env, monkeypatch, capsys) -> None:
    """R-A2L-CACHE.027 / R-A2L-CACHE.028 (no cache folder arm): ``A2L cache cleared: 0 files, 0 bytes.``, exit 0, no
    folder created under the cache base, no ``.s19tool`` and no log in the start folder, no TUI built."""
    start = tmp_path / "start"
    start.mkdir()
    before_start, before_base = _snapshot(start), _snapshot(env.base)
    code, out, err, built = _run_main(monkeypatch, capsys, ["--clear-a2l-cache"], start)
    assert (code, built) == (0, []), (code, err)
    assert out == "A2L cache cleared: 0 files, 0 bytes.\n"
    assert _snapshot(start) == before_start == {} and _snapshot(env.base) == before_base == {}


def test_r_a2l_cache_028_clear_starts_no_tui_and_creates_no_work_area(tmp_path, env, monkeypatch, capsys) -> None:
    """R-A2L-CACHE.028 (with a cache folder arm): in a fresh start folder the run leaves the folder's listing
    unchanged (no ``.s19tool/``, no log), the cache base gains nothing, and no ``S19TuiApp`` is built."""
    folder = _mk_private_folder(env)
    _plant_files(folder, [300, 300])
    start = tmp_path / "start"
    start.mkdir()
    before = _snapshot(start)
    base_before = set(_snapshot(env.base))
    code, _out, _err, built = _run_main(monkeypatch, capsys, ["--clear-a2l-cache"], start)
    assert code == 0 and built == []
    assert _snapshot(start) == before and not (start / ".s19tool").exists()
    assert set(_snapshot(env.base)) <= base_before


def test_r_a2l_cache_029_undeletable_entry_is_counted_and_exits_one(tmp_path, env, monkeypatch, capsys) -> None:
    """R-A2L-CACHE.029: 3 entries with ``os.unlink`` raising PermissionError for one: that file is kept, stdout is
    ``A2L cache cleared: 2 files, <bytes> bytes; 1 could not be removed.``, exit 1."""
    folder = _mk_private_folder(env)
    planted = _plant_files(folder, [111, 222, 333])
    victim = sorted(planted)[1]
    for fname in ("unlink", "remove"):
        real = getattr(os, fname)

        def failing(path, *a, _real=real, **k):
            if not isinstance(path, int) and os.path.basename(os.fsdecode(os.fspath(path))) == victim:
                raise PermissionError(errno.EACCES, "denied")
            return _real(path, *a, **k)

        monkeypatch.setattr(os, fname, failing)
    start = tmp_path / "start"
    start.mkdir()
    code, out, _err, _b = _run_main(monkeypatch, capsys, ["--clear-a2l-cache"], start)
    removed = sum(size for name, size in planted.items() if name != victim)
    assert code == 1
    assert out == f"A2L cache cleared: 2 files, {removed} bytes; 1 could not be removed.\n"
    assert (folder / victim).exists() and sorted(p.name for p in folder.iterdir()) == [victim]


def test_r_a2l_cache_029_entry_that_is_a_link_is_not_followed(tmp_path, env, monkeypatch, capsys) -> None:
    """R-A2L-CACHE.029 (link arm): an entry that is a symbolic link counts as could not be removed, its target is
    unchanged, the other entries are deleted, exit 1."""
    folder = _mk_private_folder(env)
    planted = _plant_files(folder, [111, 222, 333])
    victim = sorted(planted)[0]
    target = env.outside / "target.bin"
    target.write_bytes(b"precious")
    (folder / victim).unlink()
    os.symlink(target, folder / victim)
    before = _snapshot(env.outside)
    start = tmp_path / "start"
    start.mkdir()
    code, out, _err, _b = _run_main(monkeypatch, capsys, ["--clear-a2l-cache"], start)
    assert code == 1
    assert out == f"A2L cache cleared: 2 files, {sum(s for n, s in planted.items() if n != victim)} bytes; 1 could not be removed.\n"
    assert os.path.islink(folder / victim) and _snapshot(env.outside) == before


def _plant_after(c) -> dict:
    """Plant removable entries where the arm's cache folder would be (when its parents exist) so a deletion through
    a refused folder would show; returns the combined snapshot of everything reachable."""
    xdg = Path(os.environ.get("XDG_CACHE_HOME", ""))
    if not (xdg.is_absolute() and xdg.is_dir()):
        return {}
    folder = xdg / "s19_app" / "a2l"
    parts = [p for p in (xdg / "s19_app", folder) if not os.path.lexists(p)]
    for p in parts:
        p.mkdir()
        os.chmod(p, 0o700)
    if not folder.is_dir():
        return {}
    for i in range(2):
        f = folder / hashlib.sha256(f"plant-{i}".encode()).hexdigest()
        f.write_bytes(b"p" * 50)
        os.chmod(f, 0o600)
    return {"folder": _snapshot(folder)}


@pytest.mark.parametrize("arm_id,setup,reason", [a for a in OFF_ARMS if a[0] in FOLDER_ARM_IDS], ids=[a[0] for a in OFF_ARMS if a[0] in FOLDER_ARM_IDS])
def test_r_a2l_cache_030_unusable_folder_is_not_cleared(tmp_path, tmp_path_factory, monkeypatch, capsys, arm_id, setup, reason) -> None:
    """R-A2L-CACHE.030 (the Linux-reachable folder arms): the run ends ``A2L cache not cleared: <reason>.`` with exit 1
    and deletes nothing anywhere (cache base, link target and the entries planted in the refused folder unchanged)."""
    with _fresh_ctx(tmp_path_factory) as (mp, e):
        c = SimpleNamespace(mp=mp, env=e, tpf=tmp_path_factory, a2l=CASE01_A2L, tmp=tmp_path_factory.mktemp("c30"),
                            parse=None, sentinel=None)
        setup(c)
        planted = _plant_after(c)
        before = {"base": _snapshot(e.base), "outside": _snapshot(e.outside), "planted": planted}
        start = tmp_path / "start"
        start.mkdir()
        code, out, _err, built = _run_main(mp, capsys, ["--clear-a2l-cache"], start)
        after_planted = {"folder": _snapshot(Path(os.environ["XDG_CACHE_HOME"]) / "s19_app" / "a2l")} if planted else {}
        after = {"base": _snapshot(e.base), "outside": _snapshot(e.outside), "planted": after_planted}
    assert (code, built) == (1, []), (code, out)
    assert out == f"A2L cache not cleared: {reason}.\n"
    assert after == before


def test_r_a2l_cache_030_setting_off_does_not_stop_a_clear(tmp_path, env, monkeypatch, capsys) -> None:
    """R-A2L-CACHE.030 (control): ``S19_A2L_CACHE=off`` does not stop ``--clear-a2l-cache``: the entries are deleted."""
    folder = _mk_private_folder(env)
    planted = _plant_files(folder, [10, 20, 30])
    monkeypatch.setenv("S19_A2L_CACHE", "off")
    start = tmp_path / "start"
    start.mkdir()
    code, out, _err, _b = _run_main(monkeypatch, capsys, ["--clear-a2l-cache"], start)
    assert code == 0 and out == f"A2L cache cleared: 3 files, {sum(planted.values())} bytes.\n"
    assert list(folder.iterdir()) == []


@pytest.mark.parametrize("order", [["--load", "x.s19", "--clear-a2l-cache"], ["--clear-a2l-cache", "--load", "x.s19"]],
                         ids=["load-first", "clear-first"])
def test_r_a2l_cache_031_both_options_are_refused_in_either_order(tmp_path, env, order) -> None:
    """R-A2L-CACHE.031 (both argument orders): argparse's ``argument <second>: not allowed with argument <first>``
    on stderr, exit 2, the entries unchanged."""
    folder = _mk_private_folder(env)
    _plant_files(folder, [10, 20, 30])
    before = _snapshot(env.base)
    start = tmp_path / "start"
    start.mkdir()
    proc = _run_cli(env, start, *order)
    expected = f"argument {order[2] if order[0] == '--load' else order[1]}: not allowed with argument {order[0]}"
    assert proc.returncode == 2, (proc.returncode, proc.stderr[-400:])
    assert expected in proc.stderr, proc.stderr[-400:]
    assert _snapshot(env.base) == before
    assert list(start.iterdir()) == []


def test_r_a2l_cache_032_help_describes_the_option(tmp_path, env) -> None:
    """R-A2L-CACHE.032: ``s19tui --help`` lists ``--clear-a2l-cache`` with ``delete every stored A2L parse of this user,
    then exit`` and exits 0."""
    proc = _run_cli(env, tmp_path, "--help")
    assert proc.returncode == 0, proc.stderr[-400:]
    text = " ".join(proc.stdout.split())
    assert "--clear-a2l-cache" in text
    assert "delete every stored A2L parse of this user, then exit" in text


def test_r_a2l_cache_027_subprocess_clear_in_a_fresh_start_folder(tmp_path, env) -> None:
    """R-A2L-CACHE.027 / R-A2L-CACHE.028 (shipped command line, subprocess): the clear prints the fixed text, exits 0,
    and leaves the fresh start folder empty."""
    folder = _mk_private_folder(env)
    planted = _plant_files(folder, [700, 534])
    start = tmp_path / "start"
    start.mkdir()
    proc = _run_cli(env, start, "--clear-a2l-cache")
    assert proc.returncode == 0, proc.stderr[-400:]
    assert proc.stdout == f"A2L cache cleared: 2 files, {sum(planted.values())} bytes.\n"
    assert list(start.iterdir()) == []


# ---------------------------------------------------------------------------
# Module I - the user guide (CACHE.054) and the log census (CACHE.025).
# ---------------------------------------------------------------------------

DOC_STRINGS = (
    "%LOCALAPPDATA%\\s19_app\\cache\\a2l",
    "$XDG_CACHE_HOME/s19_app/a2l",
    "S19_A2L_CACHE=off",
    "S19_A2L_CACHE_MAX_MB",
    "--clear-a2l-cache",
    "S19_A2L_CACHE=off stops reading and writing but keeps the stored parses; s19tui --clear-a2l-cache removes them.",
    "The cache folder must be private to you; on Windows it inherits the %LOCALAPPDATA% permissions.",
)


@pytest.mark.parametrize("needle", DOC_STRINGS, ids=[f"string-{i}" for i in range(len(DOC_STRINGS))])
def test_r_a2l_cache_054_user_guide_load_chapter_states_the_cache(needle) -> None:
    """R-A2L-CACHE.054 (7 strings): ``docs/user-guide/ch02-load.md`` holds each of the seven required strings (runs of
    white space in the guide collapse to one space first, so a wrapped sentence still counts)."""
    text = " ".join(DOC.read_text(encoding="utf-8").split())
    assert needle in text


def test_r_a2l_cache_025_no_log_line_holds_a_path_a_name_an_entry_name_a_digest_or_a2l_text(tmp_path_factory, log) -> None:
    """R-A2L-CACHE.025 (census, at least 60 lines): every ``A2L parse cache`` line of the off arms, the damaged and
    non-regular entry arms, the fault arms and the cold, warm and evicting loads matches one fixed format and holds
    none of the arm's A2L path, file name, entry name, content digest or the first 16 characters of any A2L line."""
    a2l_lines = [ln.strip()[:16] for ln in CASE01_A2L.read_text(encoding="utf-8", errors="replace").splitlines() if len(ln.strip()) >= 8]
    digest_hex = hashlib.sha256(CASE01_A2L.read_bytes()).hexdigest()
    census: list = []

    def check(res) -> None:
        tokens = [str(CASE01_A2L), CASE01_A2L.name, digest_hex, *a2l_lines]
        if res.name:
            tokens.append(res.name)
        _assert_all_fixed(res.lines)
        for line in res.lines:
            for token in tokens:
                assert token not in line, (token, line)
        census.extend(res.lines)

    for _id, setup, _reason in OFF_ARMS:
        check(_run_arm(tmp_path_factory, log, setup))
    for _id, setup, _reason in ENTRY_ARMS:
        check(_run_arm(tmp_path_factory, log, setup, prime=True))
    for kind, prime, _regex, _cls in FAULT_ARMS + OTHER_ARMS:
        check(_run_fault(tmp_path_factory, log, kind, prime))
    check(_run_arm(tmp_path_factory, log, lambda c: c.mp.setenv("S19_A2L_CACHE_MAX_MB", "1"), a2l=SOFTWARE_A))
    check(_run_arm(tmp_path_factory, log, lambda c: c.mp.setenv("S19_A2L_CACHE_MAX_MB", "x1")))
    check(_run_arm(tmp_path_factory, log, lambda c: None, prime=True))
    check(_run_arm(tmp_path_factory, log, lambda c: None))
    assert len(census) >= 60, len(census)
    assert any(F_HIT.match(l) for l in census) and any(F_STORED.match(l) for l in census) and any(F_FAILED.match(l) for l in census)


# ---------------------------------------------------------------------------
# Module H - the comment-removal fast path (READ.73, READ.74), against a verbatim copy of the base scan.
# ---------------------------------------------------------------------------


def _base_strip_a2l_comments(text: str) -> str:
    """Verbatim copy of ``_strip_a2l_comments`` at 436f49dc2 (the base character scan): the oracle."""
    out: list[str] = []
    i = 0
    n = len(text)
    in_string = False
    while i < n:
        c = text[i]
        if in_string:
            out.append(c)
            if c == '"':
                k = i - 1
                backslashes = 0
                while k >= 0 and text[k] == "\\":
                    backslashes += 1
                    k -= 1
                if backslashes % 2 == 0:
                    in_string = False
            i += 1
            continue
        if c == '"':
            in_string = True
            out.append(c)
            i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            if not out or out[-1] not in " \t\x0b\x0c\r\n":
                out.append(" ")
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i = i + 2 if i + 1 < n else n
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            if not out or out[-1] not in " \t\x0b\x0c\r\n":
                out.append(" ")
            i += 2
            while i < n and text[i] not in "\r\n":
                i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


READ74_TEXTS = [
    'CURVE /* c */ 0x1  // tail\nRL',
    '"//" x',
    '"/*" x "*/"',
    "a /* never ends",
    'a "never closes // x',
    'q "a\\"//b" // tail',
    'q "a\\\\" // tail\nnext',
    "*/",
    "a /",
    "a //",
    "l1\r\nl2 // c\r\nl3",
    "",
    "//",
    "/*/",
    "x */ y /* z */ w",
]


def _section_bodies(payload: dict):
    def walk(nodes):
        for node in nodes:
            yield "\n".join(node.get("lines") or [])
            yield from walk(node.get("children") or [])

    yield from walk(payload["sections"])


def test_r_a2l_read_74_equals_the_base_scan_on_every_section_body_and_edge_text(fresh_set) -> None:
    """R-A2L-READ.74: ``_strip_a2l_comments`` returns exactly what the base character scan returns for every section
    body (``"\\n".join(lines)``) of every committed A2L file and for 15 in-test edge texts."""
    strip = _a2lmod()._strip_a2l_comments
    checked = 0
    for text in READ74_TEXTS:
        assert strip(text) == _base_strip_a2l_comments(text), repr(text)
        checked += 1
    for name, payload in fresh_set.items():
        for body in _section_bodies(payload):
            assert strip(body) == _base_strip_a2l_comments(body), (name, body[:60])
            checked += 1
    assert checked > 1000, checked


def test_r_a2l_read_74_example_values() -> None:
    """R-A2L-READ.74 examples: the comment, quoted-comment and unterminated-comment texts give the values the base
    scan gives."""
    strip = _a2lmod()._strip_a2l_comments
    assert strip('CURVE /* c */ 0x1  // tail\nRL') == "CURVE  0x1  \nRL"
    assert strip('"//" x') == '"//" x'
    assert strip("/*/") == _base_strip_a2l_comments("/*/")


def test_r_a2l_read_74_oracle_controls_wrong_fast_paths_differ_on_the_edge_texts() -> None:
    """R-A2L-READ.74 oracle control: the edge texts expose both wrong fast paths of the requirement's negative control
    (fast path on ``/*`` alone; fast path when ``/`` or ``*`` is missing), so the equality arm can fail."""

    def only_block(text):
        return text if "/*" not in text else _base_strip_a2l_comments(text)

    def slash_and_star(text):
        return text if ("/" not in text or "*" not in text) else _base_strip_a2l_comments(text)

    assert any(only_block(t) != _base_strip_a2l_comments(t) for t in READ74_TEXTS)
    assert any(slash_and_star(t) != _base_strip_a2l_comments(t) for t in READ74_TEXTS)


def _median_seconds(fn, text: str, reps: int) -> float:
    runs = []
    for _ in range(5):
        t0 = time.perf_counter()
        for _ in range(reps):
            fn(text)
        runs.append(time.perf_counter() - t0)
    return statistics.median(runs)


def _read73_text(kind: str) -> str:
    if kind == "200-lines":
        return "\n".join(f"  ELEMENT_{i:04d} 0x{i * 4:08X} UBYTE a / b * c {i}" for i in range(200))
    if kind == "1-MiB":
        line = "  ELEMENT_0000 0x00000000 UBYTE a / b * c 0 CM_IDENT 0 255\n"
        return (line * (MIB // len(line) + 1))[:MIB]
    return 'a / b * c "x/y"'


@pytest.mark.serial_timing
@pytest.mark.parametrize("kind", ["200-lines", "1-MiB", "slash-star-quote"])
def test_r_a2l_read_73_text_without_comment_markers_is_returned_at_a_tenth_of_the_scan_time(kind) -> None:
    """R-A2L-READ.73 (3 texts): for a text holding neither ``/*`` nor ``//`` the output equals the input and the median
    of 5 timings is at most 10 % of the median of 5 timings of the base character scan."""
    text = _read73_text(kind)
    assert "/*" not in text and "//" not in text
    strip = _a2lmod()._strip_a2l_comments
    assert strip(text) == text and _base_strip_a2l_comments(text) == text
    reps = max(1, 20_000 // len(text))
    fast = _median_seconds(strip, text, reps)
    base = _median_seconds(_base_strip_a2l_comments, text, reps)
    assert fast <= report_margin(f"READ.73 {kind}", fast, 0.10 * base), (
        f"{kind}: fast path {fast:.6f} s against the base scan {base:.6f} s")
