"""
The old -> new requirement-id map: its format, its checks and the helpers the
rename tool, the law test and the record tools share.

The map is ``docs/requirements/id-map.tsv``: UTF-8, LF, one header line
``old_id<TAB>new_id<TAB>change<TAB>origin`` and one entry per line. Everything
that reads it goes through :func:`read_map`; nothing else parses the file.
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

MAP_CAP = 1_048_576
FILE_CAP = 8_388_608
MAP_RELPATH = "docs/requirements/id-map.tsv"
HEADER = "old_id\tnew_id\tchange\torigin"
CHANGES = ("rename", "fold", "retire")
_FAM = r"[A-Z][A-Z0-9]*(?:-[A-Z][A-Z0-9]*)*"
_BATCH = r"\d{4}-\d{2}-\d{2}-[a-z0-9]+(?:-[a-z0-9]+)*"
OLD_R_RE = re.compile(rf"R-{_FAM}-\d+[a-z]?")
NEW_R_RE = re.compile(rf"R-{_FAM}\.[1-9]\d*")
_QUAL_RE = re.compile(rf"{_BATCH}/[A-Z]+-[A-Za-z0-9.-]*[A-Za-z0-9]")
_ORIGIN_RE = re.compile(r"[^\t]+:[1-9]\d*@[0-9a-f]{7,40}")
_DECISION_RE = re.compile(r"(?<![A-Za-z0-9])[A-Z]+-?\d+(?![A-Za-z0-9])")
_CTRL_RE = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")
_ID_RE = re.compile(rf"(?<![A-Za-z0-9.-])R-{_FAM}-\d+[a-z]?(?![A-Za-z0-9]|\.\d)")
_SHORT_RE = re.compile(
    r"\s*(?:/|\.\.|…|–|,)\s*-?\d{3}[a-z]?(?![0-9A-Za-z])"
    r"|-[a-z](?:/[a-z])*(?![A-Za-z0-9])" r"|\*")
_CANON_HEADER = "| Id | Form | Requirement |"
_POINTER_HEADER = "| Id | Where it lives now | Note |"
_SEPARATOR_RE = re.compile(r"^\|[\s:|-]+$")
_UNESCAPED_PIPE_RE = re.compile(r"(?<!\\)\|")
_NOT_LIVE_PREFIXES = ("docs/requirements/history/", ".dev-flow/")
_NOT_LIVE_FILES = ("AT-TC-REGISTRY.jsonl", "tools/seed_id_registry.py")


class MapError(Exception):
    """The map is unreadable or breaks one of its own rules."""


class RepoError(Exception):
    """The named folder is not the top level of a git work tree."""


@dataclass(frozen=True)
class MapEntry:
    """One map entry with its 1-based file line number."""
    line: int
    old_id: str
    new_id: str
    change: str
    origin: str


def _check_fields(old: str, new: str, change: str, origin: str) -> Optional[str]:
    """Return the first reason a 4-field line breaks the map forms, else None."""
    if change not in CHANGES:
        return f"unknown change `{change}`"
    if change == "fold":
        if not _QUAL_RE.fullmatch(old):
            return f"fold needs a qualified old id `{old}`"
    elif not (OLD_R_RE.fullmatch(old) or (change == "retire" and _QUAL_RE.fullmatch(old))):
        return f"bad old id `{old}`"
    if change == "retire":
        if new != "-":
            return "retire needs new id `-`"
    elif not NEW_R_RE.fullmatch(new):
        return f"bad new id `{new}`"
    if origin == "":
        return "empty origin"
    if change == "retire":
        return None if _DECISION_RE.search(origin) else "retire origin names no decision id"
    return None if _ORIGIN_RE.fullmatch(origin) else f"bad origin `{origin}`"


def parse_map(data: bytes) -> Tuple[List[MapEntry], List[str]]:
    """Parse map bytes into entries and one ``line <n>: <reason>`` error per bad line."""
    if len(data) > MAP_CAP:
        return [], [f"line 0: map larger than {MAP_CAP} bytes"]
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return [], ["line 0: not valid UTF-8"]
    lines = text[:-1].split("\n") if text.endswith("\n") else text.split("\n")
    entries, errors = [], []
    for number, line in enumerate(lines, start=1):
        if _CTRL_RE.search(line):
            errors.append(f"line {number}: control character")
        elif number == 1:
            if line != HEADER:
                errors.append("line 1: bad header")
        else:
            fields = line.split("\t")
            if len(fields) != 4:
                errors.append(f"line {number}: {len(fields)} fields, expected 4")
                continue
            entries.append(MapEntry(number, *fields))
            reason = _check_fields(*fields)
            if reason:
                errors.append(f"line {number}: {reason}")
    return entries, errors


def map_offenders(entries: List[MapEntry]) -> List[str]:
    """Cross-entry checks: duplicate old id, reused new id, new id equal to an old id."""
    all_old = {e.old_id for e in entries}
    seen_old: Set[str] = set()
    seen_new: Set[str] = set()
    offenders: List[str] = []
    for entry in entries:
        reason = None
        if entry.old_id in seen_old:
            reason = f"duplicate old id `{entry.old_id}`"
        elif entry.new_id in seen_new:
            reason = f"new id `{entry.new_id}` reused"
        elif entry.new_id in all_old:
            reason = f"new id `{entry.new_id}` is an old id"
        seen_old.add(entry.old_id)
        if entry.new_id != "-":
            seen_new.add(entry.new_id)
        if reason:
            offenders.append(f"line {entry.line}: {reason}")
    return offenders


def read_limited(path: Path, cap: int) -> bytes:
    """Read at most ``cap + 1`` bytes of ``path`` so an oversized file is never read whole."""
    with open(path, "rb") as handle:
        return handle.read(cap + 1)


def read_map(path: Path) -> List[MapEntry]:
    """Read and validate the map; raise :class:`MapError` with the first problem."""
    entries, errors = parse_map(read_limited(path, MAP_CAP))
    problems = errors or map_offenders(entries)
    if problems:
        raise MapError(f"id-map: {problems[0]}")
    return entries


def _table_rows(text: str, header: str) -> List[Tuple[int, str]]:
    """``(line, first cell)`` of each row of the tables headed exactly ``header``."""
    rows: List[Tuple[int, str]] = []
    in_table = False
    for number, line in enumerate(text.split("\n"), start=1):
        if line.rstrip() == header:
            in_table = True
        elif not in_table:
            continue
        elif not line.startswith("|"):
            in_table = False
        elif not _SEPARATOR_RE.match(line):
            parts = _UNESCAPED_PIPE_RE.split(line.strip())
            cells = [p.strip() for p in (parts[1:] if parts and parts[0] == "" else parts)]
            rows.append((number, cells[0] if cells else ""))
    return rows


def canon_rows(canon_text: str) -> List[Tuple[int, str]]:
    """``(line, id)`` of each canon row, in file order."""
    return _table_rows(canon_text, _CANON_HEADER)


def canon_row_ids(canon_text: str) -> List[str]:
    """The ids in the first cell of each canon row, in file order."""
    return [row_id for _, row_id in canon_rows(canon_text)]


def pointer_ids(canon_text: str) -> List[str]:
    """The ids in the first cell of each pointer-table row, in file order."""
    return [row_id for _, row_id in _table_rows(canon_text, _POINTER_HEADER)]


def canon_offenders(
    entries: List[MapEntry], row_ids: List[str], pointer_ids: List[str]
) -> List[str]:
    """Canon checks: new id without a row, old id still a row, old id a pointer-table id."""
    rows, pointers = set(row_ids), set(pointer_ids)
    offenders: List[str] = []
    for entry in entries:
        if entry.change != "retire" and entry.new_id not in rows:
            offenders.append(f"missing row `{entry.new_id}` (line {entry.line})")
        if entry.old_id in rows:
            offenders.append(f"old row `{entry.old_id}` still defined (line {entry.line})")
        if entry.old_id in pointers:
            offenders.append(f"old id `{entry.old_id}` resolved by S0.2 (line {entry.line})")
    return offenders


def scan_ids(text: str, old_ids: Iterable[str]) -> List[Tuple[int, int, int, str, str]]:
    """Citations ``(line, start, end, id, kind)`` of ``old_ids`` in ``text``; kind is token or shorthand."""
    wanted = set(old_ids)
    found: List[Tuple[int, int, int, str, str]] = []
    for match in _ID_RE.finditer(text):
        if match.group(0) not in wanted:
            continue
        end = match.end()
        if _SHORT_RE.match(text, end):
            kind = "shorthand"
        elif text[end:end + 1] == "-" and text[end + 1:end + 2].isalnum():
            continue
        else:
            kind = "token"
        line = text.count("\n", 0, match.start()) + 1
        found.append((line, match.start(), end, match.group(0), kind))
    return found


def _git(repo: Path, *args: str) -> bytes:
    """Run git in ``repo`` with list arguments; raise RepoError when it fails."""
    done = subprocess.run(["git", "-C", str(repo), *args], capture_output=True)
    if done.returncode != 0:
        raise RepoError(f"id-map: not a git work tree: {repo}")
    return done.stdout


def require_top_level(repo: Path) -> None:
    """Raise RepoError unless ``repo`` is the top level of a git work tree."""
    top = _git(repo, "rev-parse", "--show-toplevel").decode("utf-8").rstrip("\r\n")
    if os.path.normcase(str(Path(top).resolve())) != os.path.normcase(str(Path(repo).resolve())):
        raise RepoError(f"id-map: not a git work tree: {repo}")

def _tracked(repo: Path) -> List[Tuple[str, str]]:
    """``(mode, path)`` of each index entry, once per path, in git order."""
    modes: Dict[str, str] = {}
    for record in _git(repo, "ls-files", "-s", "-z").split(b"\0"):
        meta, _, raw = record.partition(b"\t")
        if raw:
            modes.setdefault(raw.decode("utf-8", "surrogateescape"), meta.split()[0].decode("ascii"))
    return [(mode, path) for path, mode in modes.items()]


def _skip_class(full: str, root: str, mode: str) -> Optional[str]:
    """``not-a-file`` for a symlink, gitlink or path leaving the tree, ``missing`` if absent."""
    if mode in ("120000", "160000") or os.path.islink(full):
        return "not-a-file"
    if not os.path.lexists(full):
        return "missing"
    real = os.path.normcase(os.path.realpath(full))
    return None if real == root or real.startswith(root + os.sep) else "not-a-file"


def git_live_files(repo: Path, map_path: Path) -> Tuple[List[str], List[str]]:
    """The tracked regular files the tools may touch, and the skip lines for the rest."""
    require_top_level(repo)
    base = str(Path(repo).resolve())
    root = os.path.normcase(os.path.realpath(base))
    maps = {os.path.normcase(str(Path(map_path).resolve())),
            os.path.normcase(os.path.normpath(os.path.join(base, MAP_RELPATH)))}
    paths: List[str] = []
    skips: List[str] = []
    for mode, path in _tracked(repo):
        full = os.path.join(base, path)
        if path.startswith(_NOT_LIVE_PREFIXES) or path in _NOT_LIVE_FILES:
            continue
        if os.path.normcase(os.path.normpath(full)) in maps:
            continue
        skip = _skip_class(full, root, mode)
        paths.append(path) if skip is None else skips.append(f"{path}\t{skip}")
    return paths, skips

def _holds_ids(path: Path, needles: List[bytes]) -> bool:
    """True when any needle occurs in the file, streamed in chunks."""
    keep = max(len(n) for n in needles) - 1
    tail = b""
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            buf = tail + chunk
            if any(n in buf for n in needles):
                return True
            tail = buf[-keep:]
    return False


def _file_offenders(repo: Path, path: str, ids: Set[str], needles: List[bytes]) -> List[str]:
    """Offender lines for one live file."""
    data = read_limited(repo / path, FILE_CAP)
    try:
        text = data.decode("utf-8") if len(data) <= FILE_CAP else None
    except UnicodeDecodeError:
        text = None
    if text is None:
        return [f"{path}: unreadable"] if _holds_ids(repo / path, needles) else []
    return [f"{path}:{c[0]}: `{c[3]}`" for c in scan_ids(text, ids)]


def live_citation_offenders(repo: Path, entries: List[MapEntry]) -> List[str]:
    """Every citation of an R-form old id of the map in a live file."""
    paths, _ = git_live_files(repo, repo / MAP_RELPATH)
    ids = {e.old_id for e in entries if OLD_R_RE.fullmatch(e.old_id)}
    if not ids:
        return []
    needles = [i.encode("utf-8") for i in ids]
    return [o for path in paths for o in _file_offenders(repo, path, ids, needles)]
