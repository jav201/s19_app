"""P-279 I3: the per-user A2L parse cache, codec and store sections.

Section CODEC covers ``s19_app/tui/a2l_cache_codec.py`` (R-A2L-CACHE.040, .050,
.062). Section STORE covers ``s19_app/tui/a2l_cache.py`` (R-A2L-CACHE.004, .008,
.009, .011-.016, .018-.021, .023, .024, .026, .037, .038, .041, .042, .047,
.058-.061). Both modules are reached lazily inside each test body, so this file
collects on a tree that lacks them and each node fails on its own.

Every test runs against the autouse per-test ``XDG_CACHE_HOME`` and
``LOCALAPPDATA`` of ``tests/conftest.py`` or against folders it makes itself;
none touches the real user cache. Host arms on case_06 belong to the conductor.
"""

from __future__ import annotations

import errno
import hashlib
import importlib
import json
import marshal
import math
import multiprocessing
import os
import pickle
import re
import stat
import struct
import subprocess
import sys
import threading
import types
from functools import lru_cache
from pathlib import Path
from typing import Callable, Optional

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
HEADER_LEN = 88
PREFIX_LEN = 36
MAGIC = b"S19A2LC\n"
NAME_RE = re.compile(r"^[0-9a-f]{64}$")
TEMP_RE = re.compile(r"^[0-9a-f]{64}\.tmp-[0-9a-f]{16}$")
MAPS = ("path", "record_layouts_by_name", "compu_methods_by_name", "compu_tabs_by_name")
CASE_01 = REPO_ROOT / "examples" / "case_01_basic_valid" / "firmware.a2l"
SOFTWARE_A = REPO_ROOT / "examples" / "case_00_public" / "software_a.a2l"
D171 = REPO_ROOT / "examples" / "case_00_public" / "ASAP2_Demo_V171.a2l"
POSIX_ONLY = pytest.mark.skipif(os.name == "nt", reason="Linux folder-chain arm; the Windows rules run by resolver seam")
WINDOWS_ONLY = pytest.mark.skipif(os.name != "nt", reason="junction arm: needs a Windows job (partial on Linux)")


# ---------------------------------------------------------------------------
# Lazy module access and shared helpers
# ---------------------------------------------------------------------------


def _store():
    return importlib.import_module("s19_app.tui.a2l_cache")


def _codec():
    return importlib.import_module("s19_app.tui.a2l_cache_codec")


def _same(a, b) -> bool:
    """Strict value equality: same types (a tuple is not a list), NaN equal to NaN."""
    if type(a) is not type(b):
        return False
    if isinstance(a, float):
        return (math.isnan(a) and math.isnan(b)) or (a == b and math.copysign(1, a) == math.copysign(1, b))
    if isinstance(a, dict):
        return list(a) == list(b) and all(_same(a[k], b[k]) for k in a)
    if isinstance(a, (list, tuple)):
        return len(a) == len(b) and all(_same(x, y) for x, y in zip(a, b))
    return a == b


def _single_text(record: bytes) -> bool:
    """True when a record holds one str/bytes item and nothing else (the bound's exception)."""
    items = marshal.loads(record)[2]
    if len(items) != 1:
        return False
    item = items[0]
    if isinstance(item, (str, bytes)):
        return True
    return isinstance(item, tuple) and len(item) == 2 and isinstance(item[1], (str, bytes))


def _assert_bound(records: list, bound: int) -> None:
    over = [len(r) for r in records if len(r) > bound and not _single_text(r)]
    assert over == [], f"{len(over)} records larger than {bound} bytes, e.g. {over[:3]}"


def _decode(records) -> dict:
    return _codec().decode_records(list(records))


@lru_cache(maxsize=None)
def _real_parse(path_text: str) -> dict:
    """The stored parse of an A2L file: the parser's payload without ``path`` and the three maps."""
    a2l = importlib.import_module("s19_app.tui.a2l")
    payload = a2l.parse_a2l_file(Path(path_text))
    return {k: v for k, v in payload.items() if k not in MAPS}


def _committed_a2l_set() -> list:
    found = []
    for path in sorted(REPO_ROOT.rglob("*.a2l")):
        rel = path.relative_to(REPO_ROOT).parts
        if "case_06_large_nested_a2l" in rel or ".git" in rel or ".s19tool" in rel:
            continue
        found.append(path)
    return found


def _walk_containers(root):
    """Yield every dict and list of a tree, iteratively."""
    stack = [root]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            yield node
            stack.extend(node.values())
        elif isinstance(node, list):
            yield node
            stack.extend(node)
        elif isinstance(node, tuple):
            stack.extend(node)


def _section(name: str, children=None, **extra) -> dict:
    return {"name": name, "children": list(children or []), **extra}


def _tag(i) -> dict:
    n = i if isinstance(i, int) else sum(map(ord, str(i)))
    return {"name": f"T{i}", "address": 4096 + n, "scale": float(n) / 8.0, "kind": "MEASUREMENT"}


def _stored(tags=None, sections=None, **extra) -> dict:
    return {"sections": list(sections or []), "errors": [], "tags": list(tags or []), "declared_spans": [], **extra}


def _module_tree(modules: int, per_module: int) -> dict:
    """A stored parse of one PROJECT with ``modules`` MODULEs of ``per_module`` MEASUREMENTs each."""
    mods = []
    for m in range(modules):
        meas = [
            _section("MEASUREMENT", [], identifier=f"M{m}_{i}", header="/begin MEASUREMENT",
                     lines=[f"  LONGIDENTIFIER {m} {i} " + "descriptive text " * 8, f"  DATATYPE UWORD 0 0 0 {i}", f"  ECU_ADDRESS 0x{i:08X}"])
            for i in range(per_module)
        ]
        mods.append(_section("MODULE", meas, identifier=f"MOD{m}"))
    return _stored(tags=[_tag(0), _tag(1)], sections=[_section("PROJECT", mods, identifier="PROJECT")])


# ---------------------------------------------------------------------------
# Section CODEC
# ---------------------------------------------------------------------------


def test_r_a2l_cache_050_record_example_tags_split_into_slices_of_1024():
    codec = _codec()
    tags = [_tag(i) for i in range(10_000)]
    parse = {"tags": tags, "errors": []}
    bound = len(marshal.dumps(tags[:4000])) + 1024
    records = list(codec.encode_records(parse, bound))
    decoded = [marshal.loads(r) for r in records]
    assert len(decoded) == 11
    assert decoded[0] == ((), 0, [("tags", []), ("errors", [])])
    expected_slices = [(a, min(a + 1024, 10_000)) for a in range(0, 10_000, 1024)]
    assert [b - a for a, b in expected_slices] == [1024] * 9 + [784]
    assert decoded[1:] == [(("tags",), 1, tags[a:b]) for a, b in expected_slices]
    assert _same(codec.decode_records(records), parse)


@pytest.mark.parametrize("arm", ["tags_and_lines", "twenty_modules", "pair_tuples"])
def test_r_a2l_cache_050_chunks_stay_within_the_bound_and_round_trip(arm):
    codec = _codec()
    bound = 65_536
    if arm == "tags_and_lines":
        parse = _stored(
            tags=[_tag(i) for i in range(30_000)],
            sections=[_section("PROJECT", [_section("MODULE", [], lines=[f"line {i}" for i in range(300_000)])])],
        )
    elif arm == "twenty_modules":
        parse = _module_tree(20, 2_000)
    else:
        parse = {"t": [(float(i), 2.0) for i in range(10_000)]}
    records = list(codec.encode_records(parse, bound))
    _assert_bound(records, bound)
    assert len(records) > 1
    decoded = _decode(records)
    assert _same(decoded, parse)
    if arm == "pair_tuples":
        assert all(type(item) is tuple for item in decoded["t"])


def test_r_a2l_cache_050_software_a_chunks_stay_within_the_bound_and_round_trip():
    codec = _codec()
    stored = _real_parse(str(SOFTWARE_A))
    records = list(codec.encode_records(stored, 65_536))
    _assert_bound(records, 65_536)
    assert _same(_decode(records), stored)


def test_r_a2l_cache_050_tuple_larger_than_the_bound_raises_value_error_and_writes_no_oversize_chunk():
    codec = _codec()
    bound = 65_536
    seen = []
    with pytest.raises(ValueError):
        for record in codec.encode_records({"t": tuple(range(100_000))}, bound):
            seen.append(record)
    assert [len(r) for r in seen if len(r) > bound] == []


def test_r_a2l_cache_050_default_chunk_bound_is_two_mebibytes_and_applies():
    codec = _codec()
    assert codec.CHUNK_BOUND == 2_097_152
    stored = _real_parse(str(CASE_01))
    records = list(codec.encode_records(stored))
    _assert_bound(records, codec.CHUNK_BOUND)
    assert _same(_decode(records), stored)


def test_r_a2l_cache_050_round_trip_of_generated_trees_at_the_smallest_bound():
    codec = _codec()
    deep = [0, 1, 2]
    for level in range(100):
        deep = {"k": deep, "n": level}
    trees = [
        {"chain": deep},
        {"big": list(range(100_000))},
        {"d": {f"key{i}": i for i in range(50_000)}},
        {"empty": [], "e2": {}, "e3": (), "e4": "", "e5": b""},
        {"mix": [(1, 2.5), (None, True, False), b"\x00\xff", "text", -7, 2**200, -(2**70), 1.5e300]},
        {"floats": [float("nan"), float("inf"), -0.0, 0.0, 1e-320], "nested": [[[]], [{}], [[1, [2, [3]]]]]},
        {"bytes": [bytes(range(256)) * 10] * 40},
    ]
    for tree in trees:
        records = list(codec.encode_records(tree, 1_024))
        decoded = codec.decode_records(records)
        assert _same(decoded, tree), list(tree)
        _assert_bound(records, 1_024)


def test_r_a2l_cache_050_stored_parse_of_the_committed_set_is_a_tree_and_round_trips():
    codec = _codec()
    files = _committed_a2l_set()
    assert len(files) >= 30
    for path in files:
        stored = _real_parse(str(path))
        seen = {}
        for node in _walk_containers(stored):
            seen[id(node)] = seen.get(id(node), 0) + 1
        shared = [n for n in seen.values() if n > 1]
        assert shared == [], f"{path.name}: {len(shared)} containers reachable twice"
        records = list(codec.encode_records(stored))
        _assert_bound(records, codec.CHUNK_BOUND)
        assert _same(codec.decode_records(records), stored), path.name


def _holds_branch_with_children(obj) -> bool:
    def is_section(x):
        return isinstance(x, dict) and isinstance(x.get("children"), list)

    def is_branch(section):
        secs = [c for c in section["children"] if is_section(c)]
        return len(secs) > 16 or any(c["children"] for c in secs)

    return any(is_section(n) and is_branch(n) and n["children"] for n in _walk_containers(obj))


@pytest.mark.parametrize("arm", ["twenty_modules", "tags_chain"])
def test_r_a2l_cache_062_no_marshal_call_takes_a_branch_section_with_its_children(arm, monkeypatch):
    codec = _codec()
    real_dumps = marshal.dumps
    if arm == "twenty_modules":
        parse = _module_tree(20, 2_000)
    else:
        mod = _section("MODULE", [_section("MEASUREMENT", [], lines=["x"]) for _ in range(40)])
        parse = _stored(tags=[_tag(i) for i in range(30_000)], sections=[_section("PROJECT", [mod])])
    whole = len(real_dumps(parse))
    results = []
    offending = []

    def spy(value, *args, **kwargs):
        data = real_dumps(value, *args, **kwargs)
        results.append(len(data))
        if _holds_branch_with_children(value):
            offending.append(len(data))
        return data

    monkeypatch.setattr(marshal, "dumps", spy)
    records = list(codec.encode_records(parse, 65_536))
    monkeypatch.undo()
    assert results, "the spy saw no marshal.dumps call: it is not on the path"
    assert offending == []
    assert _same(_decode(records), parse)
    if arm == "twenty_modules":
        assert max(results) <= 2_097_152
        assert whole > 8_388_608


def test_r_a2l_cache_062_example_project_with_two_modules_is_four_records():
    codec = _codec()
    t0, t1 = _tag(0), _tag(1)
    mods = [_section("MODULE", [_section("MEASUREMENT", [])]) for _ in range(2)]
    project = {"name": "PROJECT", "children": mods}
    parse = {"sections": [project], "errors": [], "tags": [t0, t1], "declared_spans": []}
    records = [marshal.loads(r) for r in codec.encode_records(parse, 65_536)]
    assert records == [
        ((), 0, [("sections", []), ("errors", []), ("tags", [t0, t1]), ("declared_spans", [])]),
        (("sections",), 1, [{}]),
        (("sections", 0), 0, [("name", "PROJECT"), ("children", [])]),
        (("sections", 0, "children"), 1, mods),
    ]


def _record(path, kind, items) -> bytes:
    return marshal.dumps((path, kind, items))


def test_r_a2l_cache_040_code_object_is_never_run_and_on_313_is_refused(tmp_path):
    codec = _codec()
    sentinel = tmp_path / "SENTINEL"
    code = compile(f"open({str(sentinel)!r}, 'w').write('ran')", "<crafted>", "exec")
    chunk = _record((), 0, [("x", code)])
    if sys.version_info >= (3, 13):
        with pytest.raises(codec.RecordDamaged):
            codec.decode_records([chunk])
    else:
        decoded = codec.decode_records([chunk])
        assert isinstance(decoded["x"], types.CodeType)
    assert not sentinel.exists()
    assert list(tmp_path.iterdir()) == []


def test_r_a2l_cache_040_source_text_in_a_record_is_data_not_executed(tmp_path):
    codec = _codec()
    sentinel = tmp_path / "SENTINEL"
    text = f"__import__('os').system('touch {sentinel}')"
    decoded = codec.decode_records([_record((), 0, [("x", text)])])
    assert decoded == {"x": text}
    assert not sentinel.exists()


def test_r_a2l_cache_040_a_pickle_stream_is_not_decoded_as_pickle(tmp_path):
    codec = _codec()
    sentinel = tmp_path / "SENTINEL"

    class Evil:
        def __reduce__(self):
            return (open, (str(sentinel), "w"))

    with pytest.raises(codec.RecordDamaged):
        codec.decode_records([pickle.dumps(Evil())])
    assert not sentinel.exists()


def test_r_a2l_cache_037_codec_pickle_and_path_errors_become_record_damaged():
    codec = _codec()
    assert issubclass(codec.RecordDamaged, ValueError)
    root = _record((), 0, [("a", [])])
    bad_inputs = [
        [b"\x80\x04K\x01."],
        [root, _record(("nope",), 1, [1])],
        [root, _record(("a",), 0, [("k", 1)])],
        [_record((), 7, [])],
        [marshal.dumps("not a record")],
        [b""],
    ]
    for chunks in bad_inputs:
        with pytest.raises(codec.RecordDamaged):
            codec.decode_records(chunks)


def _bomb_data() -> bytes:
    """marshal data of a list that declares 2**31-1 items (examples.json "chunk_marshal_list_bomb_hex")."""
    return b"[" + struct.pack("<i", 2**31 - 1)


def _limited_python(code: str, extra_env: Optional[dict] = None, limit: int = 2 << 30) -> subprocess.CompletedProcess:
    """Run ``code`` in a fresh interpreter that sets a ``limit``-byte address-space limit AFTER its imports."""
    prelude = (
        "import importlib, json, os, resource, sys\n"
        "sys.path.insert(0, %r)\n"
        "importlib.import_module('s19_app.tui.a2l_cache_codec')\n"
        "importlib.import_module('s19_app.tui.a2l_cache')\n"
        "resource.setrlimit(resource.RLIMIT_AS, (%d, %d))\n" % (str(REPO_ROOT), limit, limit)
    )
    env = {**os.environ, **(extra_env or {})}
    return subprocess.run(
        [sys.executable, "-B", "-c", prelude + code], capture_output=True, text=True, timeout=240, cwd=REPO_ROOT, env=env
    )


@POSIX_ONLY
def test_r_a2l_cache_037_codec_memory_error_chunk_becomes_record_damaged_under_a_2_gib_limit():
    code = (
        "import struct\n"
        "codec = importlib.import_module('s19_app.tui.a2l_cache_codec')\n"
        "data = b'[' + struct.pack('<i', 2**31 - 1)\n"
        "try:\n"
        "    codec.decode_records([data])\n"
        "    print(json.dumps('no error'))\n"
        "except codec.RecordDamaged:\n"
        "    print(json.dumps('RecordDamaged'))\n"
    )
    done = _limited_python(code)
    assert done.returncode == 0, done.stderr[-800:]
    assert json.loads(done.stdout.strip().splitlines()[-1]) == "RecordDamaged"


def test_r_a2l_cache_050_host_case_06_chunk_bound_and_decode_time():
    pytest.skip("host arm H-4 (CACHE.050, case_06 chunk bound and ms/MiB): the conductor, on the reference host")


# ---------------------------------------------------------------------------
# Section STORE: helpers
# ---------------------------------------------------------------------------

_OS_FUNCS = ("open", "stat", "lstat", "fstat", "replace", "rename", "unlink", "remove", "utime", "mkdir",
             "scandir", "listdir", "read", "write")
_SUPPORT_SETS = ("supports_dir_fd", "supports_fd", "supports_follow_symlinks", "supports_effective_ids")


def _called_from(modules, depth: int = 6) -> bool:
    frame = sys._getframe(2)
    for _ in range(depth):
        if frame is None:
            return False
        if frame.f_globals.get("__name__") in modules:
            return True
        frame = frame.f_back
    return False


_CACHE_MODULES = ("s19_app.tui.a2l_cache",)


class OsSpy:
    """Records (and optionally intercepts) the ``os`` calls made from ``a2l_cache``.

    ``hooks[name](a, k)`` runs just before the real call and may raise or change the disk.
    The wrappers join the ``os.supports_*`` sets so a ``dir_fd`` capability test still passes.
    """

    def __init__(self, monkeypatch):
        self.calls: list = []
        self.hooks: dict = {}
        self._mp = monkeypatch
        self._added: list = []
        for name in _OS_FUNCS:
            real = getattr(os, name)
            wrapper = self._wrap(name, real)
            monkeypatch.setattr(os, name, wrapper)
            for set_name in _SUPPORT_SETS:
                members = getattr(os, set_name)
                if real in members:
                    members.add(wrapper)
                    self._added.append((members, wrapper))

    def _wrap(self, name, real):
        spy = self

        def wrapper(*a, **k):
            if _called_from(_CACHE_MODULES):
                spy.calls.append((name, a, k))
                hook = spy.hooks.get(name)
                if hook is not None:
                    hook(a, k)
            return real(*a, **k)

        wrapper.__name__ = name
        return wrapper

    def close(self):
        for members, wrapper in self._added:
            members.discard(wrapper)
        self._added.clear()

    def named(self, name):
        return [(a, k) for n, a, k in self.calls if n == name]


@pytest.fixture
def os_spy(monkeypatch):
    spy = OsSpy(monkeypatch)
    yield spy
    spy.close()


@pytest.fixture
def cenv(tmp_path_factory) -> dict:
    """Environment mapping for ``cache_state``: the per-test XDG base of conftest and a private HOME."""
    return {"XDG_CACHE_HOME": os.environ["XDG_CACHE_HOME"], "HOME": str(tmp_path_factory.mktemp("home"))}


def _state(env: dict, **extra):
    state = _store().cache_state({**env, **extra}, "posix")
    assert type(state).__name__ == "CacheOn", state
    return state


def _mkdir_private(path: Path) -> None:
    path.mkdir(mode=0o700)
    path.chmod(0o700)


def _ensure_folders(state) -> None:
    for folder in (state.folder.parent, state.folder):
        if not folder.exists():
            _mkdir_private(folder)


def _digest(seed) -> bytes:
    return hashlib.sha256(f"digest-{seed}".encode()).digest()


def _blob_parse(i: int, size: int = 300_000) -> dict:
    return _stored(tags=[_tag(i)], blob=str(i).rjust(6, "0") + "a" * size)


def _put(state, seed, parse=None, digest=None):
    digest = digest or _digest(seed)
    name = _store().entry_name(digest, state.fingerprint)
    result = _store().store_entry(state, name, digest, parse if parse is not None else _blob_parse(seed))
    return name, digest, result


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tree_snapshot(root: Path) -> dict:
    """Relative path -> what the tree holds there (kind, size/target, mode, mtime_ns, sha) without following links."""
    out: dict = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in dirnames + filenames:
            p = Path(dirpath) / name
            st = os.lstat(p)
            rel = str(p.relative_to(root))
            if stat.S_ISLNK(st.st_mode):
                out[rel] = ("link", os.readlink(p))
            elif stat.S_ISDIR(st.st_mode):
                out[rel] = ("dir", stat.S_IMODE(st.st_mode))
            else:
                out[rel] = ("file", st.st_size, stat.S_IMODE(st.st_mode), st.st_mtime_ns, _sha(p))
    return out


def _names(folder: Path) -> list:
    return sorted(os.listdir(folder))


def _record(path, kind, items) -> bytes:
    return marshal.dumps((path, kind, items))


def _root_record(**extra) -> bytes:
    items = [("sections", []), ("errors", []), ("tags", []), ("declared_spans", [])] + list(extra.items())
    return _record((), 0, items)


def _build_entry(digest: bytes, fp: bytes, datas: list, *, version: int = 1, magic: bytes = MAGIC,
                 count: Optional[int] = None, body_len: Optional[int] = None, pad: int = 0) -> bytes:
    body = b"".join(struct.pack(">I", len(d)) + hashlib.sha256(d).digest() + d for d in datas) + b"\0" * pad
    header = (magic + struct.pack(">I", version) + digest + fp +
              struct.pack(">I", len(datas) if count is None else count) +
              struct.pack(">Q", len(body) if body_len is None else body_len))
    assert len(header) == HEADER_LEN
    return header + body


def _write_entry(state, name: str, data: bytes) -> Path:
    path = state.folder / name
    path.write_bytes(data)
    path.chmod(0o600)
    return path


def _set_mtime(path: Path, seconds_ago: float) -> None:
    import time

    t = time.time_ns() - int(seconds_ago * 1e9)
    os.utime(path, ns=(t, t))


def _entries(state) -> list:
    return [n for n in _names(state.folder) if NAME_RE.match(n)]


def _case_01_inputs(state):
    digest = hashlib.sha256(CASE_01.read_bytes()).digest()
    return _store().entry_name(digest, state.fingerprint), digest, _real_parse(str(CASE_01))


# ---------------------------------------------------------------------------
# Section STORE: cache_state (015, 016, 018-021)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["1", "2048", "1048576", "0000005"])
def test_r_a2l_cache_015_valid_size_setting_is_mebibytes(value, cenv):
    state = _state(cenv, S19_A2L_CACHE_MAX_MB=value)
    assert state.size_cap == int(value) * 1_048_576
    assert state.size_setting_valid is True


@pytest.mark.parametrize("value", [None, "", "0", "-5", "+5", "5.0", "1e3", " 5", "1048577", "\x1b5", "9" * 32_750, "\u0663", "5\n"])
def test_r_a2l_cache_016_unset_or_invalid_size_setting_gives_the_default_cap(value, cenv):
    extra = {} if value is None else {"S19_A2L_CACHE_MAX_MB": value}
    state = _state(cenv, **extra)
    assert state.size_cap == 2_147_483_648
    assert state.size_setting_valid is (value in (None, ""))


def test_r_a2l_cache_018_windows_resolver_names_localappdata_s19_app_cache_a2l(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "C:" / "lad").mkdir(parents=True)
    state = _store().cache_state({"LOCALAPPDATA": "C:/lad"}, "nt")
    assert type(state).__name__ == "CacheOn", state
    assert str(state.folder).replace("\\", "/") == "C:/lad/s19_app/cache/a2l"
    assert state.size_cap == 2_147_483_648
    assert not (tmp_path / "C:" / "lad" / "s19_app").exists()


def test_r_a2l_cache_019_linux_folder_is_xdg_s19_app_a2l_and_a_store_creates_only_that(cenv):
    base = Path(cenv["XDG_CACHE_HOME"])
    state = _state(cenv)
    assert state.folder.resolve() == (base / "s19_app" / "a2l").resolve()
    assert _names(base) == []
    name, _, result = _put(state, 1, _stored())
    assert result.outcome == "stored"
    assert _names(base) == ["s19_app"]
    assert _names(base / "s19_app") == ["a2l"]
    assert _names(base / "s19_app" / "a2l") == [name]


@pytest.mark.parametrize("xdg", [None, "", "rel/cache"])
def test_r_a2l_cache_020_unset_empty_or_relative_xdg_falls_back_to_home_cache(xdg, cenv, tmp_path, monkeypatch):
    home = Path(cenv["HOME"])
    _mkdir_private(home / ".cache")
    start = tmp_path / "start"
    start.mkdir()
    monkeypatch.chdir(start)
    env = {"HOME": str(home)}
    if xdg is not None:
        env["XDG_CACHE_HOME"] = xdg
    state = _store().cache_state(env, "posix")
    assert type(state).__name__ == "CacheOn", state
    assert state.folder.resolve() == (home / ".cache" / "s19_app" / "a2l").resolve()
    _put(state, 1, _stored())
    assert _names(start) == []
    assert _names(home / ".cache" / "s19_app" / "a2l") != []


def _refusal_arms():
    """(arm id, setup(tmp, env) -> (env, platform), expected reason); 23 arms run on Linux, 1 junction arm on Windows."""
    arms = []
    for value, reason in [("off", "setting"), ("OFF", "setting"), (" off\t", "setting"), ("0", "setting not recognised"),
                          ("disable", "setting not recognised"), ("\x1b[31moff", "setting not recognised"),
                          ("o" * 32_750, "setting not recognised")]:
        arms.append((f"setting-{value[:6]!r}", lambda t, e, v=value: ({**e, "S19_A2L_CACHE": v}, "posix"), reason))
    for label, env in [("unset", {}), ("empty", {"LOCALAPPDATA": ""}), ("relative", {"LOCALAPPDATA": "AppData"}),
                       ("unc", {"LOCALAPPDATA": "\\\\server\\share"}), ("missing", {"LOCALAPPDATA": "C:/missing-zz"})]:
        arms.append((f"nt-{label}", lambda t, e, v=env: (dict(v), "nt"), "no cache folder"))
    arms.append(("xdg-missing-no-home-fallback", lambda t, e: (_with_home_cache(e, {"XDG_CACHE_HOME": "/nonexistent-zz"}), "posix"), "no cache folder"))
    arms.append(("no-home-no-xdg", lambda t, e: ({}, "posix"), "no cache folder"))
    return arms


def _with_home_cache(env: dict, extra: dict) -> dict:
    home = Path(env["HOME"])
    if not (home / ".cache").exists():
        _mkdir_private(home / ".cache")
    return {"HOME": env["HOME"], **extra}


@pytest.mark.parametrize("arm", _refusal_arms(), ids=lambda a: a[0])
def test_r_a2l_cache_021_refusal_arms_without_a_folder_setup_create_nothing(arm, cenv, tmp_path, monkeypatch):
    _, build, reason = arm
    monkeypatch.chdir(tmp_path)
    env, platform = build(tmp_path, cenv)
    before = (_tree_snapshot(Path(cenv["XDG_CACHE_HOME"])), _tree_snapshot(tmp_path), _tree_snapshot(Path(cenv["HOME"])))
    state = _store().cache_state(env, platform)
    assert type(state).__name__ == "CacheOff"
    assert state.reason == reason
    after = (_tree_snapshot(Path(cenv["XDG_CACHE_HOME"])), _tree_snapshot(tmp_path), _tree_snapshot(Path(cenv["HOME"])))
    assert after == before


def _private_folders(base: Path) -> Path:
    _mkdir_private(base / "s19_app")
    _mkdir_private(base / "s19_app" / "a2l")
    return base / "s19_app" / "a2l"


@POSIX_ONLY
@pytest.mark.parametrize("arm", ["symlink", "git", "work_area", "mode_0755", "s19_app_0777", "base_0777", "other_uid"])
def test_r_a2l_cache_021_refusal_arms_with_a_folder_setup_write_nothing(arm, cenv, tmp_path, monkeypatch):
    base = Path(cenv["XDG_CACHE_HOME"])
    env = dict(cenv)
    expected = "cache folder not private"
    if arm == "symlink":
        outside = tmp_path / "target"
        outside.mkdir()
        (base / "s19_app").symlink_to(outside)
        expected = "cache folder is a link"
    elif arm == "git":
        repo = tmp_path / "repo"
        (repo / ".git").mkdir(parents=True)
        (repo / "c").mkdir()
        env["XDG_CACHE_HOME"] = str(repo / "c")
        expected = "cache folder inside a repository or work area"
    elif arm == "work_area":
        area = tmp_path / "start" / ".s19tool" / "workarea" / "proj" / "xdg"
        area.mkdir(parents=True)
        env["XDG_CACHE_HOME"] = str(area)
        expected = "cache folder inside a repository or work area"
    elif arm == "mode_0755":
        _private_folders(base).chmod(0o755)
    elif arm == "s19_app_0777":
        _private_folders(base)
        (base / "s19_app").chmod(0o777)
    elif arm == "base_0777":
        _private_folders(base)
        base.chmod(0o777)
    elif arm == "other_uid":
        _private_folders(base)
        monkeypatch.setattr(os, "geteuid", lambda: os.getuid() + 1)
    roots = [Path(env["XDG_CACHE_HOME"]), tmp_path / "target"]
    before = [_tree_snapshot(r) if r.exists() else None for r in roots]
    state = _store().cache_state(env, "posix")
    assert type(state).__name__ == "CacheOff", state
    assert state.reason == expected
    assert [_tree_snapshot(r) if r.exists() else None for r in roots] == before


@POSIX_ONLY
def test_r_a2l_cache_021_parser_source_unreadable_refuses_the_cache(cenv, monkeypatch):
    mod = _store()
    monkeypatch.setattr(mod, "parser_fingerprint", lambda: None)
    base = Path(cenv["XDG_CACHE_HOME"])
    state = mod.cache_state(cenv, "posix")
    assert type(state).__name__ == "CacheOff" and state.reason == "parser source unreadable"
    assert _names(base) == []


@WINDOWS_ONLY
def test_r_a2l_cache_021_junction_arm_on_a_windows_job(cenv, tmp_path):
    outside = tmp_path / "target"
    outside.mkdir()
    base = Path(cenv["XDG_CACHE_HOME"])
    subprocess.run(["cmd", "/c", "mklink", "/J", str(base / "s19_app"), str(outside)], check=True, capture_output=True)
    state = _store().cache_state(cenv, "nt")
    assert type(state).__name__ == "CacheOff" and state.reason == "cache folder is a link"


@POSIX_ONLY
def test_r_a2l_cache_021_sticky_base_with_private_folders_is_usable_and_stores_one_entry(cenv):
    base = Path(cenv["XDG_CACHE_HOME"])
    _private_folders(base)
    base.chmod(0o1777)
    state = _store().cache_state(cenv, "posix")
    assert type(state).__name__ == "CacheOn", state
    _, _, result = _put(state, 1, _stored())
    assert result.outcome == "stored"
    assert len(_entries(state)) == 1


def test_r_a2l_cache_021_default_environment_reads_os_environ_at_call_time(cenv, monkeypatch):
    base = Path(cenv["XDG_CACHE_HOME"])
    monkeypatch.setenv("S19_A2L_CACHE", "off")
    off = _store().cache_state()
    assert type(off).__name__ == "CacheOff" and off.reason == "setting"
    monkeypatch.delenv("S19_A2L_CACHE")
    on = _store().cache_state()
    assert type(on).__name__ == "CacheOn"
    assert on.folder.resolve() == (base / "s19_app" / "a2l").resolve()


# ---------------------------------------------------------------------------
# Section STORE: content_digest, entry_name, store_entry, read_entry (004, 008, 009, 023, 024, 042, 044)
# ---------------------------------------------------------------------------


def test_r_a2l_cache_004_digest_and_entry_name_follow_the_formula(tmp_path, cenv):
    mod = _store()
    state = _state(cenv)
    a2l_1 = b'/begin PROJECT Demo ""\n/begin MODULE M ""\n/end MODULE\n/end PROJECT\n'
    a2l_2 = a2l_1.replace(b"Demo", b"Demp")
    assert len(a2l_1) == len(a2l_2) and a2l_1 != a2l_2
    first, second = tmp_path / "one" / "a.a2l", tmp_path / "two" / "other_name.a2l"
    for path, data in ((first, a2l_1), (second, a2l_1)):
        path.parent.mkdir()
        path.write_bytes(data)
    digest, size, mtime_ns = mod.content_digest(first)
    assert digest == hashlib.sha256(a2l_1).digest()
    assert size == len(a2l_1) and mtime_ns == first.stat().st_mtime_ns
    name = mod.entry_name(digest, state.fingerprint)
    assert name == hashlib.sha256(digest + state.fingerprint).hexdigest()
    assert NAME_RE.match(name)
    assert mod.entry_name(mod.content_digest(second)[0], state.fingerprint) == name
    assert mod.entry_name(hashlib.sha256(a2l_2).digest(), state.fingerprint) != name
    assert mod.entry_name(digest, hashlib.sha256(b"another fingerprint").digest()) != name


@pytest.mark.parametrize("a2l_path", [CASE_01, D171, SOFTWARE_A], ids=["case_01", "d171", "software_a"])
def test_r_a2l_cache_004_cold_store_makes_one_entry_named_from_the_bytes_with_its_header(a2l_path, cenv):
    mod = _store()
    state = _state(cenv)
    content = a2l_path.read_bytes()
    digest = hashlib.sha256(content).digest()
    name = hashlib.sha256(digest + state.fingerprint).hexdigest()
    parse = _real_parse(str(a2l_path))
    result = mod.store_entry(state, name, digest, parse)
    assert result.outcome == "stored"
    assert _names(state.folder) == [name]
    data = (state.folder / name).read_bytes()
    assert result.entry_bytes == len(data)
    assert data[:8] == MAGIC
    assert struct.unpack(">I", data[8:12])[0] == 1
    assert data[12:44] == digest and data[44:76] == state.fingerprint
    count, body = struct.unpack(">IQ", data[76:HEADER_LEN])
    assert len(data) == HEADER_LEN + body and count * PREFIX_LEN <= body
    read = mod.read_entry(state, name, digest)
    assert read.outcome == "hit" and read.entry_bytes == len(data)
    assert _same(read.stored_parse, parse)
    assert "path" not in read.stored_parse


def test_r_a2l_cache_008_failures_leave_no_entry_and_no_temporary_file(cenv, os_spy):
    mod = _store()
    state = _state(cenv)
    unmarshallable_after_first = _stored(tags=[_tag(i) for i in range(3_000)] + [{"bad": object()}])
    unmarshallable_in_root = {**_stored(), "bad": object()}
    arms = {"after_first_chunk": unmarshallable_after_first, "after_header": unmarshallable_in_root, "at_rename": _stored()}
    for label, parse in arms.items():
        digest = _digest(label)
        name = mod.entry_name(digest, state.fingerprint)
        os_spy.hooks.clear()
        if label == "at_rename":
            def fail_rename(a, k):
                raise OSError(errno.EIO, "injected at the rename")
            os_spy.hooks["replace"] = fail_rename
        with pytest.raises((ValueError, OSError)):
            mod.store_entry(state, name, digest, parse)
        assert _names(state.folder) == [], label


def test_r_a2l_cache_008_a_reader_polling_during_stores_never_sees_a_partial_entry(cenv, os_spy):
    mod = _store()
    state = _state(cenv)
    digest = _digest("poll")
    name = mod.entry_name(digest, state.fingerprint)
    seen = []

    def observe(a, k):
        target = state.folder / name
        if target.exists():
            seen.append(mod.read_entry(state, name, digest).outcome)

    parse = _blob_parse(7)
    for _ in range(5):
        os_spy.hooks["write"] = observe
        mod.store_entry(state, name, digest, parse)
    assert seen, "the polling hook never ran after the first store"
    assert set(seen) == {"hit"}


def test_r_a2l_cache_009_every_file_created_has_an_entry_name_or_an_entry_name_dot_tmp(cenv, os_spy, tmp_path):
    mod = _store()
    state = _state(cenv)
    created = []

    def record_open(a, k):
        flags = a[1] if len(a) > 1 else k.get("flags", 0)
        if flags & os.O_CREAT:
            created.append(os.path.basename(os.fsdecode(a[0])))

    os_spy.hooks["open"] = record_open
    digest = hashlib.sha256(CASE_01.read_bytes()).digest()
    name = mod.entry_name(digest, state.fingerprint)
    mod.store_entry(state, name, digest, _real_parse(str(CASE_01)))
    for label, parse in (("a", _stored(tags=[{"b": object()}])), ("b", {**_stored(), "x": object()})):
        with pytest.raises(ValueError):
            mod.store_entry(state, mod.entry_name(_digest(label), state.fingerprint), _digest(label), parse)
    for i in range(3):
        _put(state, i, _stored(tags=[_tag(i)]))
    assert len(created) >= 6
    for file_name in created:
        assert re.match(r"^[0-9a-f]{64}(\.tmp-[0-9a-f]{16})?$", file_name), file_name
        assert "firmware" not in file_name and ".a2l" not in file_name


@POSIX_ONLY
@pytest.mark.parametrize("mask", [0o022, 0o000])
def test_r_a2l_cache_023_linux_modes_are_0700_for_folders_0600_for_files(mask, cenv, os_spy):
    old = os.umask(mask)
    try:
        state = _state(cenv)
        temp_modes = []

        def at_rename(a, k):
            src = a[0]
            temp_modes.append(stat.S_IMODE(os.stat(src, dir_fd=k.get("src_dir_fd")).st_mode))

        os_spy.hooks["replace"] = at_rename
        name, _, _ = _put(state, 1, _stored())
    finally:
        os.umask(old)
    assert stat.S_IMODE(os.stat(state.folder.parent).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(state.folder).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(state.folder / name).st_mode) == 0o600
    assert temp_modes == [0o600]


def test_r_a2l_cache_024_a_store_writes_only_inside_the_cache_folder(cenv, tmp_path, monkeypatch):
    import tempfile

    start = tmp_path / "start"
    systmp = tmp_path / "systmp"
    start.mkdir()
    systmp.mkdir()
    monkeypatch.chdir(start)
    monkeypatch.setattr(tempfile, "tempdir", str(systmp))
    base = Path(cenv["XDG_CACHE_HOME"])
    state = _state(cenv)
    before = (_tree_snapshot(start), _tree_snapshot(systmp), _tree_snapshot(Path(cenv["HOME"])))
    name, _, _ = _put(state, 1)
    _put(state, 2)
    assert (_tree_snapshot(start), _tree_snapshot(systmp), _tree_snapshot(Path(cenv["HOME"]))) == before
    snap = _tree_snapshot(base)
    outside = [rel for rel in snap if not rel.startswith(os.path.join("s19_app", "a2l")) and rel != "s19_app"]
    assert outside == []
    assert name in _names(state.folder)


def test_r_a2l_cache_044_entry_larger_than_the_size_cap_is_not_stored(cenv):
    state = _state(cenv, S19_A2L_CACHE_MAX_MB="1")
    assert state.size_cap == 1_048_576
    parse = _real_parse(str(SOFTWARE_A))
    name = _store().entry_name(_digest("big"), state.fingerprint)
    result = _store().store_entry(state, name, _digest("big"), parse)
    assert result.outcome == "entry larger than the size cap"
    assert _names(state.folder) == []


@POSIX_ONLY
def test_r_a2l_cache_042_write_fault_after_two_chunks_keeps_the_folder_and_the_previous_entry(cenv, tmp_path):
    mod = _store()
    state = _state(cenv)
    name, digest, _ = _put(state, "prev", _blob_parse(0, 50_000))
    previous = (state.folder / name).read_bytes()
    parse = _stored(tags=[_tag(0)], **{f"b{i}": "z" * 100_000 for i in range(5)})
    store_dir = tmp_path / "scratch-store"
    store_dir.mkdir()
    marshal_file = store_dir / "parse.bin"
    marshal_file.write_bytes(marshal.dumps(parse))
    code = (
        "import signal, marshal, resource\n"
        "signal.signal(signal.SIGXFSZ, signal.SIG_IGN)\n"
        "resource.setrlimit(resource.RLIMIT_FSIZE, (250_000, 250_000))\n"
        "mod = importlib.import_module('s19_app.tui.a2l_cache')\n"
        "parse = marshal.loads(open(%r, 'rb').read())\n"
        "state = mod.cache_state({'XDG_CACHE_HOME': %r, 'HOME': %r}, 'posix')\n"
        "try:\n"
        "    mod.store_entry(state, %r, bytes.fromhex(%r), parse)\n"
        "    print(json.dumps('stored'))\n"
        "except OSError as exc:\n"
        "    print(json.dumps(type(exc).__name__ + ':' + str(exc.errno)))\n"
    ) % (str(marshal_file), cenv["XDG_CACHE_HOME"], cenv["HOME"], name, digest.hex())
    done = _limited_python(code, limit=64 << 30)
    assert done.returncode == 0, done.stderr[-800:]
    assert json.loads(done.stdout.strip().splitlines()[-1]).startswith("OSError:" + str(errno.EFBIG))
    assert _names(state.folder) == [name]
    assert (state.folder / name).read_bytes() == previous


@POSIX_ONLY
@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root ignores directory permissions")
def test_r_a2l_cache_042_read_only_cache_folder_raises_and_changes_nothing(cenv):
    mod = _store()
    state = _state(cenv)
    name, digest, _ = _put(state, "a", _stored())
    before = _tree_snapshot(Path(cenv["XDG_CACHE_HOME"]))
    state.folder.chmod(0o500)
    try:
        with pytest.raises(OSError):
            mod.store_entry(state, mod.entry_name(_digest("b"), state.fingerprint), _digest("b"), _stored())
    finally:
        state.folder.chmod(0o700)
    after = _tree_snapshot(Path(cenv["XDG_CACHE_HOME"]))
    assert {k: v for k, v in after.items() if k != "s19_app/a2l"} == {k: v for k, v in before.items() if k != "s19_app/a2l"}


def test_r_a2l_cache_042_rename_refused_unmarshallable_payload_and_kept_entry(cenv, os_spy):
    mod = _store()
    state = _state(cenv)
    name, digest, _ = _put(state, "kept", _stored(tags=[_tag(1)]))
    previous = (state.folder / name).read_bytes()
    before_mtime = os.stat(state.folder / name).st_mtime_ns

    def refuse(a, k):
        raise PermissionError(errno.EACCES, "the file is held by a second instance")

    os_spy.hooks["replace"] = refuse
    with pytest.raises(PermissionError):
        mod.store_entry(state, name, digest, _stored(tags=[_tag(2)]))
    os_spy.hooks.clear()
    assert _names(state.folder) == [name]
    assert (state.folder / name).read_bytes() == previous
    assert os.stat(state.folder / name).st_mtime_ns == before_mtime
    with pytest.raises(ValueError):
        mod.store_entry(state, name, digest, _stored(tags=[{"unmarshallable": object()}]))
    assert _names(state.folder) == [name]
    assert (state.folder / name).read_bytes() == previous


# ---------------------------------------------------------------------------
# Section STORE: eviction (011, 012, 013, 014)
# ---------------------------------------------------------------------------


def test_r_a2l_cache_011_oldest_entries_go_first_until_the_total_fits_the_cap(cenv):
    mod = _store()
    state = _state(cenv, S19_A2L_CACHE_MAX_MB="1")
    stored = []
    evicted = 0
    for i in range(5):
        for j, earlier in enumerate(stored):
            _set_mtime(state.folder / earlier, 1_000 - j)
        name, _, result = _put(state, i)
        stored.append(name)
        evicted += result.evicted_files
        files = [state.folder / n for n in _names(state.folder)]
        total = sum(f.stat().st_size for f in files)
        assert total <= state.size_cap
        assert name in _names(state.folder)
        stored = [n for n in stored if n in _names(state.folder)]
    one = (state.folder / stored[0]).stat().st_size
    assert 3 * one <= state.size_cap < 4 * one
    assert stored == [mod.entry_name(_digest(i), state.fingerprint) for i in (2, 3, 4)]
    assert evicted == 2


def test_r_a2l_cache_011_temporary_file_larger_than_the_cap_does_not_loop_or_hit_the_kept_entry(cenv, os_spy):
    state = _state(cenv, S19_A2L_CACHE_MAX_MB="1")
    old = [_put(state, i, _stored(tags=[_tag(i)]))[0] for i in range(3)]
    temp = state.folder / (hashlib.sha256(b"other").hexdigest() + ".tmp-0123456789abcdef")
    temp.write_bytes(b"t" * 1_100_000)
    _set_mtime(temp, 10)
    for n in old:
        _set_mtime(state.folder / n, 500)
    unlinks = []
    os_spy.hooks["unlink"] = lambda a, k: unlinks.append(os.fsdecode(a[0]))
    box = {}

    def run():
        box["name"] = _put(state, "keep", _stored(tags=[_tag(9)]))[0]

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(5)
    assert not worker.is_alive(), "eviction did not return within 5 s"
    assert _names(state.folder) == sorted([box["name"], temp.name])
    assert len([u for u in unlinks if NAME_RE.match(u)]) <= 4
    assert all(unlinks.count(u) <= 1 for u in unlinks)


def test_r_a2l_cache_012_stale_temporary_files_go_and_fresh_ones_stay(cenv):
    state = _state(cenv)
    _put(state, 0, _stored())
    stale = state.folder / (hashlib.sha256(b"s").hexdigest() + ".tmp-aaaaaaaaaaaaaaaa")
    fresh = state.folder / (hashlib.sha256(b"f").hexdigest() + ".tmp-bbbbbbbbbbbbbbbb")
    for path, age in ((stale, 7_200), (fresh, 10)):
        path.write_bytes(b"x" * 10)
        _set_mtime(path, age)
    _put(state, 1, _stored())
    assert not stale.exists()
    assert fresh.exists()


@POSIX_ONLY
def test_r_a2l_cache_013_a_hit_makes_the_entry_the_most_recently_used(cenv):
    mod = _store()
    state = _state(cenv, S19_A2L_CACHE_MAX_MB="1")
    a, da, _ = _put(state, "A")
    b, _, _ = _put(state, "B")
    c, _, _ = _put(state, "C")
    for name, age in ((a, 300), (b, 200), (c, 100)):
        _set_mtime(state.folder / name, age)
    assert mod.read_entry(state, a, da).outcome == "hit"
    assert (state.folder / a).stat().st_mtime_ns > (state.folder / b).stat().st_mtime_ns
    d, _, _ = _put(state, "D")
    names = _names(state.folder)
    assert b not in names and a in names and d in names


@POSIX_ONLY
def test_r_a2l_cache_013_a_failing_time_update_leaves_the_hit_intact(cenv, os_spy):
    mod = _store()
    state = _state(cenv)
    parse = _stored(tags=[_tag(3)])
    name, digest, _ = _put(state, "t", parse)

    def refuse(a, k):
        raise OSError(errno.EPERM, "injected")

    os_spy.hooks["utime"] = refuse
    result = mod.read_entry(state, name, digest)
    assert result.outcome == "hit" and _same(result.stored_parse, parse)
    assert os_spy.named("utime"), "the recency update never reached os.utime"


@POSIX_ONLY
def test_r_a2l_cache_013_the_time_update_never_follows_a_link_swapped_in_after_the_read(cenv, tmp_path, os_spy):
    mod = _store()
    state = _state(cenv)
    name, digest, _ = _put(state, "t", _stored(tags=[_tag(3)]))
    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "f"
    target.write_bytes(b"outside bytes")
    _set_mtime(target, 5_000)
    before = (target.stat().st_mtime_ns, target.read_bytes())
    swapped = []

    def swap(a, k):
        dir_fd = k.get("dir_fd") if a and isinstance(a[0], str) else None
        os.unlink(state.folder / name)
        os.symlink(target, state.folder / name)
        swapped.append(True)

    os_spy.hooks["utime"] = swap
    result = mod.read_entry(state, name, digest)
    assert swapped, "the swap seam never ran: os.utime was not reached"
    assert result.outcome in ("hit", "not a regular file")
    assert (target.stat().st_mtime_ns, target.read_bytes()) == before


def test_r_a2l_cache_014_foreign_files_are_never_counted_read_or_deleted(cenv):
    mod = _store()
    state = _state(cenv, S19_A2L_CACHE_MAX_MB="1")
    _ensure_folders(state)
    foreign = {
        "notes.txt": b"n" * 1_200_000,
        "ABC" + "D" * 61: b"upper case",
        "e" * 63: b"short name",
    }
    for name, data in foreign.items():
        (state.folder / name).write_bytes(data)
        _set_mtime(state.folder / name, 9_000)
    (state.folder / "x").mkdir()
    snapshot = {n: _tree_snapshot(state.folder)[n] for n in list(foreign) + ["x"]}
    a, _, _ = _put(state, 0)
    b, _, _ = _put(state, 1)
    assert {a, b} <= set(_names(state.folder)), "foreign bytes were counted toward the cap"
    for i in range(2, 5):
        for existing in _entries(state):
            _set_mtime(state.folder / existing, 900 - i)
        _put(state, i)
    result = mod.clear_cache(cenv, "posix")
    assert type(result).__name__ == "ClearResult" and result.failed == 0
    now = _tree_snapshot(state.folder)
    assert {n: now[n] for n in snapshot} == snapshot
    assert [n for n in now if NAME_RE.match(n) or TEMP_RE.match(n)] == []


# ---------------------------------------------------------------------------
# Section STORE: clear_cache (026)
# ---------------------------------------------------------------------------


def _plant(state, name: str, size: int, age: float = 100) -> Path:
    path = state.folder / name
    path.write_bytes(b"p" * size)
    path.chmod(0o600)
    _set_mtime(path, age)
    return path


def test_r_a2l_cache_026_clear_deletes_every_entry_and_temporary_file_and_nothing_foreign(cenv):
    mod = _store()
    state = _state(cenv)
    _ensure_folders(state)
    other_fp = hashlib.sha256(b"another parser").digest()
    sizes = []
    for i in range(3):
        sizes.append(_plant(state, mod.entry_name(_digest(i), state.fingerprint), 100 + i).stat().st_size)
    for i in range(2):
        sizes.append(_plant(state, mod.entry_name(_digest(10 + i), other_fp), 200 + i).stat().st_size)
    sizes.append(_plant(state, hashlib.sha256(b"t1").hexdigest() + ".tmp-0123456789abcdef", 50, age=10).stat().st_size)
    sizes.append(_plant(state, hashlib.sha256(b"t2").hexdigest() + ".tmp-fedcba9876543210", 60, age=7_200).stat().st_size)
    foreign = {"notes.txt": 20, "ABC" + "D" * 61: 21, "f" * 63: 22}
    for name, size in foreign.items():
        _plant(state, name, size)
    (state.folder / "x").mkdir()
    keep = {n: _tree_snapshot(state.folder)[n] for n in list(foreign) + ["x"]}
    result = mod.clear_cache(cenv, "posix")
    assert (result.files, result.bytes, result.failed) == (7, sum(sizes), 0)
    now = _tree_snapshot(state.folder)
    assert now == keep


def test_r_a2l_cache_026_clear_ignores_the_cache_setting_and_creates_no_folder(cenv):
    mod = _store()
    base = Path(cenv["XDG_CACHE_HOME"])
    result = mod.clear_cache({**cenv, "S19_A2L_CACHE": "off"}, "posix")
    assert (result.files, result.bytes, result.failed) == (0, 0, 0)
    assert _names(base) == []
    state = _state(cenv)
    _plant_name = mod.entry_name(_digest(1), state.fingerprint)
    _ensure_folders(state)
    _plant(state, _plant_name, 10)
    result = mod.clear_cache({**cenv, "S19_A2L_CACHE": "off"}, "posix")
    assert result.files == 1 and _names(state.folder) == []


@POSIX_ONLY
def test_r_a2l_cache_026_a_link_of_the_cache_folder_is_refused_with_nothing_deleted(cenv, tmp_path):
    mod = _store()
    base = Path(cenv["XDG_CACHE_HOME"])
    outside = tmp_path / "outside" / "a2l"
    outside.mkdir(parents=True)
    victim = outside / hashlib.sha256(b"v").hexdigest()
    victim.write_bytes(b"victim")
    (base / "s19_app").symlink_to(outside.parent)
    result = mod.clear_cache(cenv, "posix")
    assert type(result).__name__ == "CacheOff" and result.reason == "cache folder is a link"
    assert victim.read_bytes() == b"victim"


@POSIX_ONLY
def test_r_a2l_cache_026_an_unlink_failure_is_counted_and_the_rest_deleted(cenv, os_spy):
    mod = _store()
    state = _state(cenv)
    _ensure_folders(state)
    for i in range(3):
        _plant(state, mod.entry_name(_digest(i), state.fingerprint), 10)
    refused = []

    def refuse_one(a, k):
        if not refused:
            refused.append(a[0])
            raise PermissionError(errno.EACCES, "injected")

    os_spy.hooks["unlink"] = refuse_one
    result = mod.clear_cache(cenv, "posix")
    assert (result.files, result.failed) == (2, 1)
    assert len(_names(state.folder)) == 1


# ---------------------------------------------------------------------------
# Section STORE: read_entry (037, 038, 041)
# ---------------------------------------------------------------------------


def _calls_spy(monkeypatch, owner, attr, modules=("s19_app.tui.a2l_cache", "s19_app.tui.a2l_cache_codec")):
    """Count the calls to ``owner.attr`` made from the cache modules."""
    real = getattr(owner, attr)
    calls = []

    def wrapper(*a, **k):
        if _called_from(modules):
            calls.append(a)
        return real(*a, **k)

    monkeypatch.setattr(owner, attr, wrapper)
    return calls


def _valid_entry(state):
    """A valid case_01 entry in the folder: returns (name, digest, parse, bytes)."""
    name, digest, parse = _case_01_inputs(state)
    _store().store_entry(state, name, digest, parse)
    return name, digest, parse, (state.folder / name).read_bytes()


def _mut_empty(d, ctx):
    return b""


def _mut_40(d, ctx):
    return d[:40]


def _mut_mid_chunk(d, ctx):
    length = struct.unpack(">I", d[HEADER_LEN:HEADER_LEN + 4])[0]
    return d[:HEADER_LEN + PREFIX_LEN + length // 2]


def _mut_appended(d, ctx):
    return d + b"\x00"


def _mut_pickle_magic(d, ctx):
    class Evil:
        def __reduce__(self):
            return (open, (str(ctx["sentinel"]), "w"))

    return pickle.dumps(Evil()) + d[8:]


def _mut_version(version):
    return lambda d, ctx: d[:8] + struct.pack(">I", version) + d[12:]


def _mut_other_fingerprint(d, ctx):
    return d[:44] + bytes([0xAB]) * 32 + d[76:]


def _mut_flip_first_data_byte(d, ctx):
    at = HEADER_LEN + PREFIX_LEN
    return d[:at] + bytes([d[at] ^ 0xFF]) + d[at + 1:]


def _mut_huge_length(d, ctx):
    return d[:HEADER_LEN] + b"\xff\xff\xff\xff" + d[HEADER_LEN + 4:]


def _mut_not_marshal(d, ctx):
    return _build_entry(ctx["digest"], ctx["fp"], [b"\x80\x04K\x01."])


def _mut_path_names_no_container(d, ctx):
    return _build_entry(ctx["digest"], ctx["fp"], [_root_record(), _record(("nope",), 1, [1])])


def _mut_sections_int(d, ctx):
    items = [("sections", 5), ("errors", []), ("tags", []), ("declared_spans", [])]
    return _build_entry(ctx["digest"], ctx["fp"], [_record((), 0, items)])


def _mut_count_over_body_limit(d, ctx):
    first = _root_record()
    body_len = 408
    pad = body_len - (PREFIX_LEN + len(first))
    assert pad > 0
    return _build_entry(ctx["digest"], ctx["fp"], [first], count=12, body_len=body_len, pad=pad)


_DAMAGED_FORMS = {
    "empty": _mut_empty,
    "forty_bytes": _mut_40,
    "cut_mid_chunk": _mut_mid_chunk,
    "one_byte_appended": _mut_appended,
    "pickle_in_place_of_magic": _mut_pickle_magic,
    "version_0": _mut_version(0),
    "version_2": _mut_version(2),
    "other_parser_fingerprint": _mut_other_fingerprint,
    "flipped_data_byte": _mut_flip_first_data_byte,
    "chunk_length_ffffffff": _mut_huge_length,
    "data_not_marshal_digest_valid": _mut_not_marshal,
    "record_path_names_no_container": _mut_path_names_no_container,
    "sections_is_an_int": _mut_sections_int,
    "chunk_count_over_body_over_36": _mut_count_over_body_limit,
}


@pytest.mark.parametrize("form", sorted(_DAMAGED_FORMS))
def test_r_a2l_cache_037_damaged_entry_is_deleted_and_a_fresh_one_can_be_stored(form, cenv, tmp_path, monkeypatch):
    mod = _store()
    state = _state(cenv)
    name, digest, parse, data = _valid_entry(state)
    ctx = {"digest": digest, "fp": state.fingerprint, "sentinel": tmp_path / "SENTINEL"}
    (state.folder / name).write_bytes(_DAMAGED_FORMS[form](data, ctx))
    hashes = _calls_spy(monkeypatch, hashlib, "sha256")
    loads = _calls_spy(monkeypatch, marshal, "loads")
    result = mod.read_entry(state, name, digest)
    assert result.outcome == "damaged" and result.stored_parse is None
    assert not (state.folder / name).exists()
    assert not ctx["sentinel"].exists()
    if form in ("chunk_count_over_body_over_36", "chunk_length_ffffffff"):
        assert hashes == [], "a chunk was read before the length checks refused the entry"
    if form == "flipped_data_byte":
        assert loads == [], "marshal ran on a chunk whose digest did not match"
    monkeypatch.undo()
    assert mod.store_entry(state, name, digest, parse).outcome == "stored"
    assert mod.read_entry(state, name, digest).outcome == "hit"


def test_r_a2l_cache_037_an_entry_of_another_a2l_renamed_to_this_name_is_damaged(cenv):
    mod = _store()
    state = _state(cenv)
    _, _, _, data = _valid_entry(state)
    other_digest = hashlib.sha256(b"another a2l").digest()
    other_name = mod.entry_name(other_digest, state.fingerprint)
    _write_entry(state, other_name, data)
    result = mod.read_entry(state, other_name, other_digest)
    assert result.outcome == "damaged"
    assert not (state.folder / other_name).exists()


@POSIX_ONLY
def test_r_a2l_cache_037_memory_error_chunk_with_a_valid_digest_is_damaged_under_a_2_gib_limit(cenv):
    mod = _store()
    state = _state(cenv)
    digest = _digest("bomb")
    name = mod.entry_name(digest, state.fingerprint)
    bomb = _bomb_data()
    assert len(struct.pack(">I", len(bomb)) + hashlib.sha256(bomb).digest() + bomb) == 41
    _ensure_folders(state)
    _write_entry(state, name, _build_entry(digest, state.fingerprint, [bomb]))
    code = (
        "mod = importlib.import_module('s19_app.tui.a2l_cache')\n"
        "state = mod.cache_state({'XDG_CACHE_HOME': %r, 'HOME': %r}, 'posix')\n"
        "result = mod.read_entry(state, %r, bytes.fromhex(%r))\n"
        "print(json.dumps(result.outcome))\n"
    ) % (cenv["XDG_CACHE_HOME"], cenv["HOME"], name, digest.hex())
    done = _limited_python(code)
    assert done.returncode == 0, done.stderr[-800:]
    assert json.loads(done.stdout.strip().splitlines()[-1]) == "damaged"
    assert not (state.folder / name).exists()


def test_r_a2l_cache_037_pickle_and_source_text_entries_never_run_code(cenv, tmp_path):
    mod = _store()
    state = _state(cenv)
    sentinel = tmp_path / "SENTINEL"
    digest = _digest("text")
    name = mod.entry_name(digest, state.fingerprint)
    text = f"__import__('os').system('touch {sentinel}')"
    _ensure_folders(state)
    _write_entry(state, name, _build_entry(digest, state.fingerprint, [_root_record(source=text)]))
    result = mod.read_entry(state, name, digest)
    assert result.outcome == "hit" and result.stored_parse["source"] == text
    code = compile(f"open({str(sentinel)!r}, 'w').write('ran')", "<crafted>", "exec")
    _write_entry(state, name, _build_entry(digest, state.fingerprint, [_root_record(x=code)]))
    result = mod.read_entry(state, name, digest)
    assert result.outcome == ("damaged" if sys.version_info >= (3, 13) else "hit")
    assert not sentinel.exists()


def test_r_a2l_cache_037_progress_is_reported_after_each_chunk_and_ends_at_the_entry_size(cenv):
    mod = _store()
    state = _state(cenv)
    digest = _digest("progress")
    name = mod.entry_name(digest, state.fingerprint)
    items = [("sections", []), ("errors", []), ("tags", []), ("declared_spans", [])]
    datas = [_record((), 0, items)] + [_record(("tags",), 1, [_tag(i), _tag(i + 100)]) for i in range(9)]
    _ensure_folders(state)
    path = _write_entry(state, name, _build_entry(digest, state.fingerprint, datas))
    seen = []
    result = mod.read_entry(state, name, digest, lambda done, total: seen.append((done, total)))
    assert result.outcome == "hit"
    assert len(seen) == 10
    assert [a for a, _ in seen] == sorted(a for a, _ in seen) and len({a for a, _ in seen}) == 10
    assert seen[-1] == (path.stat().st_size, path.stat().st_size)
    assert {t for _, t in seen} == {path.stat().st_size}


class _CallbackFault(RuntimeError):
    pass


@pytest.mark.parametrize("fault", [_CallbackFault, PermissionError], ids=["runtime-error", "os-error"])
def test_r_a2l_cache_037_041_a_raising_progress_callback_reaches_the_caller_and_keeps_the_entry(cenv, fault):
    """R-A2L-CACHE.037 + R-A2L-CACHE.041 + R-A2L-CACHE.046 (E4-1): an exception raised by the progress callback is
    not a damaged entry (its bytes verify and decode): it reaches the caller of ``read_entry`` and the entry stays
    byte-equal, so the next read is a hit."""
    mod = _store()
    state = _state(cenv)
    name, digest, _parse, data = _valid_entry(state)
    calls = []

    def raising(done, total):
        calls.append(done)
        raise fault("the bar is gone")

    with pytest.raises(fault):
        mod.read_entry(state, name, digest, raising)
    assert len(calls) == 1, calls
    assert (state.folder / name).read_bytes() == data
    assert mod.read_entry(state, name, digest).outcome == "hit"


@POSIX_ONLY
def test_r_a2l_cache_038_a_symlink_of_the_entry_name_is_left_alone(cenv, tmp_path):
    mod = _store()
    state = _state(cenv)
    name, digest, parse, data = _valid_entry(state)
    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "valid-entry"
    target.write_bytes(data)
    (state.folder / name).unlink()
    (state.folder / name).symlink_to(target)
    before = (target.read_bytes(), target.stat().st_mtime_ns, os.readlink(state.folder / name))
    result = mod.read_entry(state, name, digest)
    assert result.outcome == "not a regular file" and result.stored_parse is None
    assert os.path.islink(state.folder / name)
    assert (target.read_bytes(), target.stat().st_mtime_ns, os.readlink(state.folder / name)) == before


@POSIX_ONLY
def test_r_a2l_cache_038_a_folder_of_the_entry_name_is_left_alone(cenv):
    mod = _store()
    state = _state(cenv)
    _ensure_folders(state)
    digest = _digest("dir")
    name = mod.entry_name(digest, state.fingerprint)
    (state.folder / name).mkdir()
    (state.folder / name / "inner").write_bytes(b"inner")
    result = mod.read_entry(state, name, digest)
    assert result.outcome == "not a regular file"
    assert (state.folder / name / "inner").read_bytes() == b"inner"


@POSIX_ONLY
def test_r_a2l_cache_038_a_link_swapped_in_between_the_check_and_the_open_is_never_followed(cenv, tmp_path, os_spy):
    mod = _store()
    state = _state(cenv)
    name, digest, parse, data = _valid_entry(state)
    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "valid-entry"
    target.write_bytes(data)
    swapped = []

    def swap(a, k):
        if os.fsdecode(a[0]) == name and not swapped:
            os.unlink(state.folder / name)
            os.symlink(target, state.folder / name)
            swapped.append(True)

    os_spy.hooks["open"] = swap
    result = mod.read_entry(state, name, digest)
    assert swapped, "the swap seam never ran: the entry was not opened by its name"
    assert result.outcome == "not a regular file"
    assert os.path.islink(state.folder / name)
    assert target.read_bytes() == data


@POSIX_ONLY
def test_r_a2l_cache_041_an_open_fault_raises_and_leaves_the_folder_unchanged(cenv, os_spy):
    mod = _store()
    state = _state(cenv)
    name, digest, _, _ = _valid_entry(state)
    before = _tree_snapshot(Path(cenv["XDG_CACHE_HOME"]))

    def fault(a, k):
        if os.fsdecode(a[0]) == name:
            raise PermissionError(errno.EACCES, "injected")

    os_spy.hooks["open"] = fault
    with pytest.raises(PermissionError):
        mod.read_entry(state, name, digest)
    os_spy.hooks.clear()
    assert _tree_snapshot(Path(cenv["XDG_CACHE_HOME"])) == before


@POSIX_ONLY
def test_r_a2l_cache_041_a_read_fault_on_the_third_chunk_raises_and_leaves_the_folder_unchanged(cenv, os_spy):
    mod = _store()
    state = _state(cenv)
    digest = _digest("eio")
    name = mod.entry_name(digest, state.fingerprint)
    items = [("sections", []), ("errors", []), ("tags", []), ("declared_spans", [])]
    datas = [_record((), 0, items)] + [_record(("tags",), 1, [_tag(i)]) for i in range(5)]
    _ensure_folders(state)
    _write_entry(state, name, _build_entry(digest, state.fingerprint, datas))
    before = _tree_snapshot(Path(cenv["XDG_CACHE_HOME"]))
    count = []

    def fault(a, k):
        count.append(1)
        if len(count) == 4:
            raise OSError(errno.EIO, "injected")

    os_spy.hooks["read"] = fault
    with pytest.raises(OSError):
        mod.read_entry(state, name, digest)
    os_spy.hooks.clear()
    assert len(count) >= 4, "the entry was not read through os.read"
    assert _tree_snapshot(Path(cenv["XDG_CACHE_HOME"])) == before


def test_r_a2l_cache_046_055_memory_error_in_the_chunk_read_propagates_and_keeps_the_entry(cenv, monkeypatch):
    """R-A2L-CACHE.046 + R-A2L-CACHE.055 (E5 F-1): a ``MemoryError`` raised by the read of the second chunk is not
    a damaged entry: it reaches the caller of ``read_entry`` as itself and the valid entry stays byte-equal."""
    mod = _store()
    state = _state(cenv)
    digest = _digest("memory-error")
    name = mod.entry_name(digest, state.fingerprint)
    items = [("sections", []), ("errors", []), ("tags", []), ("declared_spans", [])]
    datas = [_record((), 0, items)] + [_record(("tags",), 1, [_tag(i)]) for i in range(5)]
    _ensure_folders(state)
    path = _write_entry(state, name, _build_entry(digest, state.fingerprint, datas))
    data = path.read_bytes()
    real, calls = mod._read_exact, []

    def faulty(fd, count):
        calls.append(count)
        if len(calls) == 4:
            raise MemoryError()
        return real(fd, count)

    monkeypatch.setattr(mod, "_read_exact", faulty)
    with pytest.raises(MemoryError):
        mod.read_entry(state, name, digest)
    assert len(calls) == 4, "the fault did not land in the second chunk's read"
    assert path.read_bytes() == data


# ---------------------------------------------------------------------------
# Section STORE: concurrency (047)
# ---------------------------------------------------------------------------


def _shared_parse() -> dict:
    return _real_parse(str(SOFTWARE_A))


def _proc_store_worker(env: dict, rounds: int, queue, parse_file: str) -> None:
    mod = importlib.import_module("s19_app.tui.a2l_cache")
    state = mod.cache_state(env, "posix")
    digest = hashlib.sha256(b"shared name").digest()
    name = mod.entry_name(digest, state.fingerprint)
    with open(parse_file, "rb") as handle:
        parse = marshal.loads(handle.read())
    stored = oserrors = 0
    other = []
    for _ in range(rounds):
        try:
            mod.store_entry(state, name, digest, parse)
            stored += 1
        except OSError:
            oserrors += 1
        except Exception as exc:  # noqa: BLE001 - reported to the parent
            other.append(type(exc).__name__)
    queue.put((stored, oserrors, other))


def _assert_one_usable_entry(state, env) -> None:
    mod = _store()
    digest = hashlib.sha256(b"shared name").digest()
    name = mod.entry_name(digest, state.fingerprint)
    assert _names(state.folder) == [name]
    result = mod.read_entry(state, name, digest)
    assert result.outcome == "hit"
    assert _same(result.stored_parse, _shared_parse())


def test_r_a2l_cache_047_two_threads_storing_one_name_leave_one_usable_entry(cenv):
    mod = _store()
    state = _state(cenv)
    digest = hashlib.sha256(b"shared name").digest()
    name = mod.entry_name(digest, state.fingerprint)
    parse = _shared_parse()
    barrier = threading.Barrier(2)
    outcomes: list = []

    def worker():
        barrier.wait()
        for _ in range(20):
            try:
                mod.store_entry(state, name, digest, parse)
                outcomes.append("stored")
            except OSError:
                outcomes.append("oserror")
            except Exception as exc:  # noqa: BLE001
                outcomes.append(type(exc).__name__)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(300)
    assert len(outcomes) == 40 and set(outcomes) <= {"stored", "oserror"}, set(outcomes)
    assert outcomes.count("stored") >= 1
    _assert_one_usable_entry(state, cenv)


@POSIX_ONLY
def test_r_a2l_cache_047_two_spawned_processes_storing_one_name_leave_one_usable_entry(cenv, tmp_path):
    state = _state(cenv)
    parse_file = tmp_path / "software_a.parse"
    parse_file.write_bytes(marshal.dumps(_shared_parse()))
    ctx = multiprocessing.get_context("spawn")
    queue = ctx.Queue()
    env = {"XDG_CACHE_HOME": cenv["XDG_CACHE_HOME"], "HOME": cenv["HOME"]}
    procs = [ctx.Process(target=_proc_store_worker, args=(env, 20, queue, str(parse_file))) for _ in range(2)]
    for p in procs:
        p.start()
    results = [queue.get(timeout=600) for _ in procs]
    for p in procs:
        p.join(60)
        assert p.exitcode == 0
    assert all(other == [] for _, _, other in results), results
    assert sum(stored for stored, _, _ in results) >= 1
    _assert_one_usable_entry(state, cenv)


def test_r_a2l_cache_047_host_case_06_is_not_part_of_this_section():
    pytest.skip("host arm: not applicable to the store tests")


# ---------------------------------------------------------------------------
# Section STORE: the folder chain (058, 059, 060)
# ---------------------------------------------------------------------------


def _is_cache_file_name(text: str) -> bool:
    base = os.path.basename(text)
    return bool(NAME_RE.match(base) or TEMP_RE.match(base))


def _spy_violations(spy: OsSpy, state) -> list:
    folder, base = str(state.folder), str(state.base)
    bad = []
    for name, a, k in spy.calls:
        if name in ("fstat", "read", "write"):
            continue
        first = a[0] if a else k.get("path")
        if isinstance(first, int):
            continue
        text = os.fsdecode(first)
        if name in ("replace", "rename"):
            if k.get("src_dir_fd") is None or k.get("dst_dir_fd") is None:
                bad.append((name, text))
            continue
        if name == "open":
            flags = a[1] if len(a) > 1 else k.get("flags", 0)
            if k.get("dir_fd") is None and text == base:
                assert flags & os.O_DIRECTORY
                continue
            if k.get("dir_fd") is None:
                bad.append((name, text))
            elif flags & os.O_DIRECTORY:
                assert flags & os.O_NOFOLLOW, ("a folder open without O_NOFOLLOW", text)
            continue
        if k.get("dir_fd") is None and (_is_cache_file_name(text) or name == "mkdir"):
            bad.append((name, text))
    return bad


@POSIX_ONLY
def test_r_a2l_cache_058_every_cache_file_call_is_relative_to_a_descriptor(cenv, os_spy):
    mod = _store()
    state = _state(cenv, S19_A2L_CACHE_MAX_MB="1")
    os_spy.calls.clear()
    names = []
    for i in range(5):
        name, digest, _ = _put(state, i)
        names.append((name, digest))
        if i == 1:
            assert mod.read_entry(state, *names[0]).outcome == "hit"
    assert mod.read_entry(state, *names[-1]).outcome == "hit"
    cleared = mod.clear_cache(cenv, "posix")
    assert cleared.files >= 1
    assert len(os_spy.calls) >= 20
    assert _spy_violations(os_spy, state) == []
    opens = os_spy.named("open")
    assert any(k.get("dir_fd") is not None for _, k in opens)


@POSIX_ONLY
def test_r_a2l_cache_058_a_cold_store_reaches_the_temporary_file_and_the_entry_by_descriptor(cenv, os_spy):
    state = _state(cenv)
    os_spy.calls.clear()
    name, _, _ = _put(state, 1)
    creates = [(a, k) for a, k in os_spy.named("open") if (a[1] if len(a) > 1 else k.get("flags", 0)) & os.O_CREAT]
    assert creates and all(k.get("dir_fd") is not None for _, k in creates)
    assert _spy_violations(os_spy, state) == []
    assert name in _names(state.folder)


def _plant_valid(state, digest: bytes, folder: Path) -> str:
    name = _store().entry_name(digest, state.fingerprint)
    data = _build_entry(digest, state.fingerprint, [_root_record(planted="planted")])
    folder.mkdir(parents=True, exist_ok=True)
    (folder / name).write_bytes(data)
    return name


def _swap_for_link(state, which: str, outside: Path) -> Path:
    """Rename ``a2l`` or ``s19_app`` away and put a link to ``outside`` in its place; returns the renamed folder."""
    target = state.folder if which == "a2l" else state.folder.parent
    moved = target.with_name(target.name + ".old")
    target.rename(moved)
    target.symlink_to(outside)
    return moved


def _prepare_swap(cenv, tmp_path, which):
    state = _state(cenv)
    name, digest, _ = _put(state, "inside", _stored(tags=[_tag(1)]))
    outside = tmp_path / "outside"
    if which == "a2l":
        planted = _plant_valid(state, digest, outside)
        old = [_plant_valid(state, _digest(f"o{i}"), outside) for i in range(3)]
    else:
        planted = _plant_valid(state, digest, outside / "a2l")
        old = [_plant_valid(state, _digest(f"o{i}"), outside / "a2l") for i in range(3)]
    for p in outside.rglob("*"):
        if p.is_file():
            _set_mtime(p, 5_000)
    return state, name, digest, planted, outside


@POSIX_ONLY
@pytest.mark.parametrize("which", ["a2l", "s19_app"])
@pytest.mark.parametrize("operation", ["read", "store", "evict"])
def test_r_a2l_cache_059_a_swapped_folder_is_never_read_written_or_evicted_through(operation, which, cenv, tmp_path):
    mod = _store()
    state, name, digest, planted, outside = _prepare_swap(cenv, tmp_path, which)
    before = _tree_snapshot(outside)
    _swap_for_link(state, which, outside)
    if operation == "read":
        with pytest.raises(OSError) as raised:
            mod.read_entry(state, name, digest)
        assert isinstance(raised.value, (NotADirectoryError, OSError))
    elif operation == "store":
        with pytest.raises(OSError):
            mod.store_entry(state, _store().entry_name(_digest("new"), state.fingerprint), _digest("new"), _stored())
    else:
        small = state.__class__(state.folder, state.base, 1, True, state.fingerprint)
        try:
            mod._evict(small, planted)
        except OSError:
            pass
    assert _tree_snapshot(outside) == before


@POSIX_ONLY
@pytest.mark.parametrize("which", ["a2l", "s19_app"])
def test_r_a2l_cache_059_a_swap_before_clear_is_refused_and_a_swap_after_the_chain_opens_deletes_inside(which, cenv, tmp_path, os_spy):
    mod = _store()
    state = _state(cenv)
    for i in range(3):
        _put(state, i, _stored(tags=[_tag(i)]))
    outside = tmp_path / "outside"
    for i in range(3):
        _plant_valid(state, _digest(f"o{i}"), outside if which == "a2l" else outside / "a2l")
    for p in outside.rglob("*"):
        if p.is_file():
            _set_mtime(p, 5_000)
    before = _tree_snapshot(outside)
    moved = {}

    def swap(a, k):
        if "moved" not in moved:
            moved["moved"] = _swap_for_link(state, which, outside)

    os_spy.hooks["scandir"] = swap
    result = mod.clear_cache(cenv, "posix")
    os_spy.hooks.clear()
    assert "moved" in moved, "the swap seam never ran: clear_cache did not list through os.scandir"
    assert type(result).__name__ in ("ClearResult", "CacheOff")
    assert _tree_snapshot(outside) == before
    inside = moved["moved"] if which == "a2l" else moved["moved"] / "a2l"
    assert [n for n in _names(inside) if NAME_RE.match(n)] == []


@POSIX_ONLY
@pytest.mark.parametrize("which", ["a2l", "s19_app"])
def test_r_a2l_cache_059_a_link_met_before_a_clear_is_refused_as_a_link(which, cenv, tmp_path):
    mod = _store()
    state, name, digest, planted, outside = _prepare_swap(cenv, tmp_path, which)
    before = _tree_snapshot(outside)
    _swap_for_link(state, which, outside)
    result = mod.clear_cache(cenv, "posix")
    assert type(result).__name__ == "CacheOff" and result.reason == "cache folder is a link"
    assert _tree_snapshot(outside) == before


@POSIX_ONLY
def test_r_a2l_cache_058_the_folder_chain_returns_the_cache_folder_descriptor(cenv):
    state = _state(cenv)
    _ensure_folders(state)
    fd = _store()._open_folder_chain(state)
    try:
        assert os.fstat(fd).st_ino == os.stat(state.folder).st_ino
    finally:
        os.close(fd)


@WINDOWS_ONLY
def test_r_a2l_cache_059_junction_arms_on_a_windows_job():
    pytest.skip("junction arms need a Windows job; not run on Linux (partial)")


@POSIX_ONLY
def test_r_a2l_cache_060_a_folder_made_with_open_permissions_is_refused_before_any_file(cenv, os_spy):
    mod = _store()
    state = _state(cenv)
    base = Path(cenv["XDG_CACHE_HOME"])
    real_mkdir = os.mkdir

    def open_up(a, k):
        if os.fsdecode(a[0]) == "a2l":
            real_mkdir(*a, **k)
            os.chmod(a[0], 0o777, dir_fd=k.get("dir_fd"))
            raise FileExistsError(errno.EEXIST, "made by the seam")

    os_spy.hooks["mkdir"] = open_up
    name = mod.entry_name(_digest("m"), state.fingerprint)
    with pytest.raises(PermissionError):
        mod.store_entry(state, name, _digest("m"), _stored())
    files = [rel for rel, entry in _tree_snapshot(base).items() if entry[0] == "file"]
    assert files == []
    assert os_spy.named("mkdir"), "the mkdir seam never ran"


@POSIX_ONLY
def test_r_a2l_cache_060_a_folder_owned_by_another_uid_is_refused_before_any_file(cenv, monkeypatch):
    mod = _store()
    state = _state(cenv)
    base = Path(cenv["XDG_CACHE_HOME"])
    monkeypatch.setattr(os, "geteuid", lambda: os.getuid() + 1)
    name = mod.entry_name(_digest("m"), state.fingerprint)
    with pytest.raises(PermissionError):
        mod.store_entry(state, name, _digest("m"), _stored())
    assert [rel for rel, entry in _tree_snapshot(base).items() if entry[0] == "file"] == []


@POSIX_ONLY
def test_r_a2l_cache_060_an_existing_open_a2l_made_by_another_instance_is_refused(cenv, os_spy):
    mod = _store()
    state = _state(cenv)
    _mkdir_private(state.folder.parent)
    real_mkdir = os.mkdir

    def other_instance_made_it_open(a, k):
        if os.fsdecode(a[0]) == "a2l":
            real_mkdir(*a, **k)
            os.chmod(a[0], 0o755, dir_fd=k.get("dir_fd"))
            raise FileExistsError(errno.EEXIST, "a second instance made it")

    os_spy.hooks["mkdir"] = other_instance_made_it_open
    name = mod.entry_name(_digest("m"), state.fingerprint)
    with pytest.raises(PermissionError):
        mod.store_entry(state, name, _digest("m"), _stored())
    assert _names(state.folder) == []


@POSIX_ONLY
def test_r_a2l_cache_060_file_exists_for_an_own_private_a2l_lets_the_store_proceed(cenv, os_spy):
    mod = _store()
    state = _state(cenv)
    _mkdir_private(state.folder.parent)
    real_mkdir = os.mkdir

    def other_instance_made_it(a, k):
        if os.fsdecode(a[0]) == "a2l":
            real_mkdir(*a, **k)
            os.chmod(a[0], 0o700, dir_fd=k.get("dir_fd"))
            raise FileExistsError(errno.EEXIST, "a second instance made it")

    os_spy.hooks["mkdir"] = other_instance_made_it
    name = mod.entry_name(_digest("m"), state.fingerprint)
    result = mod.store_entry(state, name, _digest("m"), _stored())
    assert result.outcome == "stored"
    assert _names(state.folder) == [name]
    assert os_spy.named("mkdir"), "the mkdir seam never ran"


# ---------------------------------------------------------------------------
# Section STORE: Windows rules by resolver seam (061)
# ---------------------------------------------------------------------------


class _NtSeam:
    """Runs cache calls with the store's ``_on_windows()`` seam true and logs reparse checks in the order of the
    os calls."""

    def __init__(self, monkeypatch, spy: OsSpy):
        self.mp, self.spy = monkeypatch, spy
        workspace = importlib.import_module("s19_app.tui.workspace")
        real = workspace._path_traverses_reparse_point
        log = self

        def checked(path, *a, **k):
            log.spy.calls.append(("check", (str(path),), dict(k, positional=a)))
            return real(path, *a, **k)

        monkeypatch.setattr(workspace, "_path_traverses_reparse_point", checked)
        mod = _store()
        if hasattr(mod, "_path_traverses_reparse_point"):
            monkeypatch.setattr(mod, "_path_traverses_reparse_point", checked)

    def on(self):
        self.mp.setattr(_store(), "_on_windows", lambda: True)

    def off(self):
        self.mp.setattr(_store(), "_on_windows", lambda: False)


_GUARDED_OPS = ("open", "replace", "rename", "unlink", "utime")


def _unguarded(calls: list, base) -> list:
    """The guarded os calls whose directly preceding call is not a reparse check of that file below ``base``."""
    bad, checked = [], 0
    for index, (name, a, k) in enumerate(calls):
        if name not in _GUARDED_OPS:
            continue
        first = os.fsdecode(a[0]) if a and not isinstance(a[0], int) else None
        if first is not None and os.path.dirname(first.replace("\\", "/")).rstrip("/") == str(base).replace("\\", "/").rstrip("/"):
            continue
        checked += 1
        before = calls[index - 1] if index else None
        stop_at = None if before is None else (before[2].get("stop_at") or (before[2].get("positional") or [None])[0])
        if before is None or before[0] != "check" or stop_at is None or str(stop_at) != str(base):
            bad.append((name, first))
    return bad, checked


@POSIX_ONLY
def test_r_a2l_cache_061_windows_rules_check_for_a_reparse_point_right_before_each_file_operation(tmp_path, monkeypatch, os_spy):
    mod = _store()
    monkeypatch.chdir(tmp_path)
    (tmp_path / "C:" / "lad").mkdir(parents=True)
    env = {"LOCALAPPDATA": "C:/lad", "S19_A2L_CACHE_MAX_MB": "1"}
    state = mod.cache_state(env, "nt")
    assert type(state).__name__ == "CacheOn", state
    seam = _NtSeam(monkeypatch, os_spy)
    os_spy.calls.clear()
    seam.on()
    try:
        entries = []
        for i in range(5):
            entries.append(_put(state, i)[:2])
            if i == 1:
                assert mod.read_entry(state, *entries[0]).outcome == "hit"
        assert mod.read_entry(state, *entries[-1]).outcome == "hit"
    finally:
        seam.off()
    assert mod.clear_cache(env, "nt").files >= 1
    bad, checked = _unguarded(os_spy.calls, state.base)
    assert checked >= 12, f"only {checked} guarded operations were seen"
    assert bad == []


@WINDOWS_ONLY
def test_r_a2l_cache_061_windows_job_cold_warm_evict_clear_with_a_real_junction():
    pytest.skip("Windows job only (partial on Linux)")
