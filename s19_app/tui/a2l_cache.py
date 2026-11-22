"""Per-user disk cache of the A2L parse: folder rules, entries, eviction and clear."""

from __future__ import annotations

import errno
import hashlib
import importlib
import os
import re
import secrets
import stat
import struct
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Mapping, Optional

from s19_app.tui.a2l_cache_codec import decode_records, encode_records
from s19_app.tui.workspace import _DRIVE_ROOTED_RE, _path_traverses_reparse_point

if TYPE_CHECKING:
    from s19_app.tui.a2l import A2LProgress

OFF_REASONS = ("setting", "setting not recognised", "no cache folder", "cache folder is a link",
               "cache folder inside a repository or work area", "cache folder not private",
               "parser source unreadable")
UNUSABLE_REASONS = ("damaged", "not a regular file")
NOT_STORED_REASONS = ("entry larger than the size cap", "file changed during the parse")
CLEAR_HELP = "delete every stored A2L parse of this user, then exit"

_MAGIC = b"S19A2LC\n"
_FORMAT_VERSION = 1
_HEADER = struct.Struct(">8sI32s32sIQ")
_PREFIX = struct.Struct(">I32s")
_DEFAULT_CAP = 2_147_483_648
_STALE_SECONDS = 3600
_NAME_RE = re.compile(r"[0-9a-f]{64}(\.tmp-[0-9a-f]{16})?")
_NOT_REGULAR = "not a regular file"
_O_BINARY = getattr(os, "O_BINARY", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_FINGERPRINT: list = []


@dataclass(frozen=True)
class CacheOn:
    folder: Path
    base: Path
    size_cap: int
    size_setting_valid: bool
    fingerprint: bytes


@dataclass(frozen=True)
class CacheOff:
    reason: str


@dataclass(frozen=True)
class ReadResult:
    outcome: str
    stored_parse: Optional[dict]
    entry_bytes: int
    seconds: float


@dataclass(frozen=True)
class StoreResult:
    outcome: str
    entry_bytes: int
    seconds: float
    evicted_files: int
    evicted_bytes: int


@dataclass(frozen=True)
class ClearResult:
    files: int
    bytes: int
    failed: int


class _LinkMet(OSError):
    pass


class _OverCap(Exception):
    pass


class _FaultRaised(Exception):
    pass


def _on_windows() -> bool:
    return os.name == "nt"


def _is_foreign_owner(st: os.stat_result) -> bool:
    geteuid = getattr(os, "geteuid", None)
    return geteuid is not None and st.st_uid != geteuid()


def _parser_source() -> Optional[bytes]:
    try:
        return Path(importlib.import_module("s19_app.tui.a2l").__file__).read_bytes()
    except (OSError, TypeError, ImportError):
        return None


def parser_fingerprint() -> Optional[bytes]:
    if not _FINGERPRINT:
        source = _parser_source()
        if source is None:
            _FINGERPRINT.append(None)
        else:
            text = (f"s19-a2l-cache/{_FORMAT_VERSION}/{hashlib.sha256(source).hexdigest()}/"
                    f"{sys.version_info[0]}.{sys.version_info[1]}")
            _FINGERPRINT.append(hashlib.sha256(text.encode("ascii")).digest())
    return _FINGERPRINT[0]


def content_digest(path: Path) -> tuple[bytes, int, int]:
    st = os.stat(path)
    sha = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1_048_576), b""):
            sha.update(block)
    return sha.digest(), st.st_size, st.st_mtime_ns


def entry_name(digest: bytes, fingerprint: bytes) -> str:
    return hashlib.sha256(digest + fingerprint).hexdigest()


def _setting_word(raw: Optional[str]) -> Optional[str]:
    if raw is None:
        return "on"
    word = raw.strip(" \t\r\n")
    if not word.isascii():
        return None
    word = word.lower()
    return "on" if word in ("", "on") else word if word == "off" else None


def _size_cap(setting: Optional[str]) -> tuple[int, bool]:
    if not setting:
        return _DEFAULT_CAP, True
    if len(setting) <= 7 and setting.isascii() and setting.isdigit() and 1 <= int(setting) <= 1_048_576:
        return int(setting) * 1_048_576, True
    return _DEFAULT_CAP, False


def _app_parts(windows: bool) -> tuple[str, ...]:
    return ("s19_app", "cache", "a2l") if windows else ("s19_app", "a2l")


def _cache_base(env: Mapping[str, str], windows: bool) -> Optional[Path]:
    if windows:
        local = env.get("LOCALAPPDATA")
        usable = bool(local) and _DRIVE_ROOTED_RE.match(local) and os.path.isdir(local)
        return Path(local) if usable else None
    xdg = env.get("XDG_CACHE_HOME")
    if xdg and xdg.startswith("/"):
        return Path(xdg) if os.path.isdir(xdg) else None
    home = env.get("HOME")
    if home and home.startswith("/") and os.path.isdir(os.path.join(home, ".cache")):
        return Path(home) / ".cache"
    return None


def _in_repository(folder: Path, windows: bool) -> bool:
    real = Path(os.path.realpath(folder))
    for ancestor in (real, *real.parents):
        name = ancestor.name.lower() if windows else ancestor.name
        if name == ".s19tool":
            return True
        if any(os.path.lexists(ancestor / marker) for marker in (".git", "pyproject.toml", "project.toml")):
            return True
    return False


def _base_ok(st: os.stat_result) -> bool:
    return not st.st_mode & 0o022 or bool(st.st_mode & stat.S_ISVTX)


def _folder_ok(st: os.stat_result, last: bool) -> bool:
    return not _is_foreign_owner(st) and not st.st_mode & (0o077 if last else 0o022)


def _folders_private(base: Path, folder: Path) -> bool:
    if not _base_ok(os.stat(base)):
        return False
    parts = folder.relative_to(base).parts
    current = base
    for index, part in enumerate(parts):
        current = current / part
        try:
            st = os.stat(current)
        except FileNotFoundError:
            return True
        if not stat.S_ISDIR(st.st_mode):
            raise NotADirectoryError(str(current))
        if not _folder_ok(st, index == len(parts) - 1):
            return False
    return True


def _refusal(base: Path, folder: Path, windows: bool) -> Optional[str]:
    if _path_traverses_reparse_point(folder, stop_at=base):
        return "cache folder is a link"
    if _in_repository(folder, windows):
        return "cache folder inside a repository or work area"
    if not windows and not _folders_private(base, folder):
        return "cache folder not private"
    return None


def _find_folder(env: Mapping[str, str], windows: bool) -> CacheOff | tuple[Path, Path]:
    base = _cache_base(env, windows)
    if base is None:
        return CacheOff("no cache folder")
    folder = base.joinpath(*_app_parts(windows))
    reason = _refusal(base, folder, windows)
    return CacheOff(reason) if reason else (base, folder)


def _is_nt(platform: Optional[str]) -> bool:
    return (os.name if platform is None else platform) == "nt"


def cache_state(env: Optional[Mapping[str, str]] = None, platform: Optional[str] = None) -> CacheOn | CacheOff:
    env = os.environ if env is None else env
    word = _setting_word(env.get("S19_A2L_CACHE"))
    if word == "off":
        return CacheOff("setting")
    if word is None:
        return CacheOff("setting not recognised")
    try:
        found = _find_folder(env, _is_nt(platform))
    except OSError:
        return CacheOff("no cache folder")
    if isinstance(found, CacheOff):
        return found
    fingerprint = parser_fingerprint()
    if fingerprint is None:
        return CacheOff("parser source unreadable")
    cap, valid = _size_cap(env.get("S19_A2L_CACHE_MAX_MB"))
    return CacheOn(found[1], found[0], cap, valid, fingerprint)


def _check_folder_fd(fd: int, last: bool) -> None:
    if not _folder_ok(os.fstat(fd), last):
        raise PermissionError(errno.EACCES, "cache folder not private")


def _open_child(parent: int, name: str, create: bool) -> int:
    flags = os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW
    try:
        return os.open(name, flags, dir_fd=parent)
    except FileNotFoundError:
        if not create:
            raise
    try:
        os.mkdir(name, 0o700, dir_fd=parent)
    except FileExistsError:
        pass
    return os.open(name, flags, dir_fd=parent)


def _open_folder_chain(state: CacheOn, create: bool = False) -> int:
    fd = os.open(state.base, os.O_RDONLY | _O_DIRECTORY)
    try:
        if not _base_ok(os.fstat(fd)):
            raise PermissionError(errno.EACCES, "cache base not private")
        parts = state.folder.relative_to(state.base).parts
        for index, part in enumerate(parts):
            child = _open_child(fd, part, create)
            os.close(fd)
            fd = child
            _check_folder_fd(fd, index == len(parts) - 1)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _ensure_folders(state: CacheOn) -> None:
    current = state.base
    for part in state.folder.relative_to(state.base).parts:
        current = current / part
        try:
            os.mkdir(current, 0o700)
        except FileExistsError:
            pass


class _Dir:
    """The files of one cache folder: descriptor-relative on Linux, reparse-checked paths on Windows."""

    def __init__(self, state: CacheOn, fd: Optional[int], owned: bool = True) -> None:
        self.state, self.fd, self.owned = state, fd, owned

    @classmethod
    def open(cls, state: CacheOn, create: bool = False, windows: Optional[bool] = None) -> "_Dir":
        if not (_on_windows() if windows is None else windows):
            return cls(state, _open_folder_chain(state, create))
        if create:
            _ensure_folders(state)
        elif not os.path.isdir(state.folder):
            raise FileNotFoundError(str(state.folder))
        found = cls(state, None)
        found._guard(None)
        return found

    def _guard(self, name: Optional[str]) -> None:
        if self.fd is None:
            target = self.state.folder if name is None else self.state.folder / name
            if _path_traverses_reparse_point(target, stop_at=self.state.base):
                raise _LinkMet(errno.ELOOP, "link in the cache path")

    def _path(self, name: str) -> str:
        return name if self.fd is not None else str(self.state.folder / name)

    def lstat(self, name: str) -> os.stat_result:
        self._guard(name)
        return os.stat(self._path(name), dir_fd=self.fd, follow_symlinks=False)

    def open_read(self, name: str) -> int:
        self._guard(name)
        return os.open(self._path(name), os.O_RDONLY | _O_BINARY | _O_NOFOLLOW, dir_fd=self.fd)

    def open_new(self, name: str) -> int:
        self._guard(name)
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | _O_BINARY | _O_NOFOLLOW
        return os.open(self._path(name), flags, 0o600, dir_fd=self.fd)

    def replace(self, src: str, dst: str) -> None:
        self._guard(dst)
        os.replace(self._path(src), self._path(dst), src_dir_fd=self.fd, dst_dir_fd=self.fd)

    def unlink(self, name: str) -> None:
        self._guard(name)
        os.unlink(self._path(name), dir_fd=self.fd)

    def touch(self, name: str, fd: int) -> None:
        if self.fd is not None:
            os.utime(fd)
        else:
            self._guard(name)
            os.utime(self._path(name))

    def scan(self) -> list[tuple[str, os.stat_result]]:
        self._guard(None)
        found = []
        with os.scandir(self.fd if self.fd is not None else self.state.folder) as entries:
            for entry in entries:
                if _NAME_RE.fullmatch(entry.name):
                    try:
                        found.append((entry.name, entry.stat(follow_symlinks=False)))
                    except OSError:
                        continue
        return found

    def close(self) -> None:
        if self.fd is not None and self.owned:
            os.close(self.fd)


def _unlink_quiet(folder: _Dir, name: str) -> None:
    try:
        folder.unlink(name)
    except OSError:
        pass


def _read_exact(fd: int, count: int) -> bytes:
    parts, got = [], 0
    while got < count:
        block = os.read(fd, min(count - got, 1_048_576))
        if not block:
            break
        parts.append(block)
        got += len(block)
    return b"".join(parts)


def _passed_on(work, *args):
    try:
        return work(*args)
    except OSError:
        raise
    except Exception as exc:
        raise _FaultRaised() from exc


def _sha256_of(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _chunks(fd: int, count: int, size: int, progress):
    position = _HEADER.size
    for _ in range(count):
        prefix = _passed_on(_read_exact, fd, _PREFIX.size)
        if len(prefix) != _PREFIX.size:
            raise ValueError("chunk prefix cut")
        length, want = _PREFIX.unpack(prefix)
        if length > size - position - _PREFIX.size:
            raise ValueError("chunk runs past the end of the entry")
        data = _passed_on(_read_exact, fd, length)
        if len(data) != length or _passed_on(_sha256_of, data) != want:
            raise ValueError("chunk digest differs")
        position += _PREFIX.size + length
        if progress is not None:
            try:
                progress(position, size)
            except Exception as exc:
                raise _FaultRaised() from exc
        yield data
    if position != size:
        raise ValueError("chunks do not end at the end of the entry")


def _shape_ok(parsed: object) -> bool:
    keys = ("sections", "errors", "tags", "declared_spans")
    return isinstance(parsed, dict) and all(isinstance(parsed.get(key), list) for key in keys)


def _decode_entry(fd: int, size: int, state: CacheOn, digest: bytes, progress) -> Optional[dict]:
    if size < _HEADER.size:
        return None
    magic, version, h_digest, h_print, count, body = _HEADER.unpack(_read_exact(fd, _HEADER.size))
    if (magic != _MAGIC or version != _FORMAT_VERSION or h_digest != digest or h_print != state.fingerprint
            or size != _HEADER.size + body or count * _PREFIX.size > body):
        return None
    try:
        parsed = decode_records(_chunks(fd, count, size, progress))
    except OSError:
        raise
    except _FaultRaised as exc:
        raise exc.__cause__
    except Exception:
        return None
    return parsed if _shape_ok(parsed) else None


def _read_in(folder: _Dir, state: CacheOn, name: str, digest: bytes, progress) -> tuple[str, Optional[dict], int]:
    try:
        st = folder.lstat(name)
        if not stat.S_ISREG(st.st_mode):
            return _NOT_REGULAR, None, 0
        fd = folder.open_read(name)
    except FileNotFoundError:
        return "absent", None, 0
    except _LinkMet:
        return _NOT_REGULAR, None, 0
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            return _NOT_REGULAR, None, 0
        raise
    try:
        fst = os.fstat(fd)
        if (fst.st_dev, fst.st_ino) != (st.st_dev, st.st_ino):
            return _NOT_REGULAR, None, 0
        parsed = _decode_entry(fd, fst.st_size, state, digest, progress)
        if parsed is None:
            return "damaged", None, fst.st_size
        try:
            folder.touch(name, fd)
        except OSError:
            pass
        return "hit", parsed, fst.st_size
    finally:
        os.close(fd)


def read_entry(state: CacheOn, name: str, digest: bytes, progress: Optional["A2LProgress"] = None) -> ReadResult:
    started = time.perf_counter()
    try:
        folder = _Dir.open(state)
    except FileNotFoundError:
        return ReadResult("absent", None, 0, time.perf_counter() - started)
    except _LinkMet:
        return ReadResult(_NOT_REGULAR, None, 0, time.perf_counter() - started)
    try:
        outcome, parsed, size = _read_in(folder, state, name, digest, progress)
        if outcome == "damaged":
            _unlink_quiet(folder, name)
    finally:
        folder.close()
    return ReadResult(outcome, parsed, size, time.perf_counter() - started)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]


def _pack_header(digest: bytes, fingerprint: bytes, count: int, body: int) -> bytes:
    return _HEADER.pack(_MAGIC, _FORMAT_VERSION, digest, fingerprint, count, body)


def _write_entry(folder: _Dir, state: CacheOn, tmp: str, name: str, digest: bytes, stored: dict) -> Optional[int]:
    fd = folder.open_new(tmp)
    try:
        _write_all(fd, _pack_header(digest, state.fingerprint, 0, 0))
        written, count = _HEADER.size, 0
        for record in encode_records(stored):
            frame = _PREFIX.pack(len(record), hashlib.sha256(record).digest()) + record
            if written + len(frame) > state.size_cap:
                raise _OverCap()
            _write_all(fd, frame)
            written += len(frame)
            count += 1
        os.lseek(fd, 0, os.SEEK_SET)
        _write_all(fd, _pack_header(digest, state.fingerprint, count, written - _HEADER.size))
        os.close(fd)
        fd = -1
        folder.replace(tmp, name)
        return written
    except BaseException as exc:
        if fd >= 0:
            os.close(fd)
        _unlink_quiet(folder, tmp)
        if isinstance(exc, _OverCap):
            return None
        raise


def _evict(state: CacheOn, keep: str, folder_fd: Optional[int] = None) -> tuple[int, int]:
    folder = _Dir.open(state) if folder_fd is None else _Dir(state, folder_fd, owned=False)
    try:
        return _evict_in(folder, state, keep)
    finally:
        folder.close()


def _evict_in(folder: _Dir, state: CacheOn, keep: str) -> tuple[int, int]:
    files = freed = total = 0
    candidates = []
    cutoff = time.time() - _STALE_SECONDS
    for name, st in folder.scan():
        if not stat.S_ISREG(st.st_mode):
            continue
        if ".tmp-" in name and st.st_mtime < cutoff:
            try:
                folder.unlink(name)
                files, freed = files + 1, freed + st.st_size
                continue
            except OSError:
                pass
        total += st.st_size
        if ".tmp-" not in name and name != keep:
            candidates.append((st.st_mtime_ns, name, st.st_size))
    for _, name, size in sorted(candidates):
        if total <= state.size_cap:
            break
        try:
            folder.unlink(name)
        except OSError:
            continue
        total, files, freed = total - size, files + 1, freed + size
    return files, freed


def store_entry(state: CacheOn, name: str, digest: bytes, stored_parse: dict) -> StoreResult:
    started = time.perf_counter()
    folder = _Dir.open(state, create=True)
    try:
        tmp = f"{name}.tmp-{secrets.token_hex(8)}"
        written = _write_entry(folder, state, tmp, name, digest, stored_parse)
        if written is None:
            return StoreResult("entry larger than the size cap", 0, time.perf_counter() - started, 0, 0)
        files, freed = _evict(state, name, folder.fd) if folder.fd is not None else _evict(state, name)
    finally:
        folder.close()
    return StoreResult("stored", written, time.perf_counter() - started, files, freed)


def _clear_in(folder: _Dir) -> ClearResult:
    files = size = failed = 0
    for name, st in folder.scan():
        if not stat.S_ISREG(st.st_mode):
            failed += 1
            continue
        try:
            folder.unlink(name)
            files, size = files + 1, size + st.st_size
        except OSError:
            failed += 1
    return ClearResult(files, size, failed)


def clear_cache(env: Optional[Mapping[str, str]] = None, platform: Optional[str] = None) -> ClearResult | CacheOff:
    env = os.environ if env is None else env
    windows = _is_nt(platform)
    try:
        found = _find_folder(env, windows)
    except OSError:
        return CacheOff("no cache folder")
    if isinstance(found, CacheOff):
        return found
    state = CacheOn(found[1], found[0], 0, True, b"")
    try:
        folder = _Dir.open(state, windows=windows)
        try:
            return _clear_in(folder)
        finally:
            folder.close()
    except FileNotFoundError:
        return ClearResult(0, 0, 0)
    except PermissionError:
        return CacheOff("cache folder not private")
    except OSError as exc:
        return CacheOff("cache folder is a link" if exc.errno in (errno.ELOOP, errno.ENOTDIR) else "no cache folder")
