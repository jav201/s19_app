"""
The id rename tool: plan new ids for old canon rows, and rewrite the id tokens
of the map's rename entries in the tracked files.

``python -m tools.id_rename plan --module S0``   print proposed map entries.
``python -m tools.id_rename rename [--apply]``   list (or make) the replacements.

Every new file content is computed before the first file is written. Shorthand
citations, runtime-read files, binary and oversized files are listed in the
skip report and never changed.
"""

from __future__ import annotations

import argparse
import fnmatch
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple

from tools.id_map import (
    FILE_CAP,
    MAP_CAP,
    MAP_RELPATH,
    NEW_R_RE,
    OLD_R_RE,
    MapEntry,
    MapError,
    RepoError,
    canon_rows,
    require_top_level,
    git_live_files,
    read_limited,
    read_map,
    scan_ids,
)

RUNTIME_READ_FILES = ("tests/test_suite_hygiene.py",)

Hit = str

_OLD_PARTS = re.compile(r"R-(.+)-(\d+)([a-z]?)")
_NEW_PARTS = re.compile(r"R-(.+)\.(\d+)")
_MODULE_RE = re.compile(r"^## (S\d+) · ")


class ExcludedError(Exception):
    """An excluded file holds an old id while ``--apply`` runs."""


class ExclusionError(Exception):
    """The exclusion list is oversized or not valid UTF-8."""


def _used_numbers(ids: Sequence[str]) -> Dict[str, Set[int]]:
    """Numbers already taken per family among new-form ids."""
    used: Dict[str, Set[int]] = {}
    for new_id in ids:
        if NEW_R_RE.fullmatch(new_id):
            family, number = _NEW_PARTS.fullmatch(new_id).groups()
            used.setdefault(family, set()).add(int(number))
    return used


def plan_new_ids(
    old_ids: List[str], row_ids: List[str], entries: List[MapEntry]
) -> Dict[str, str]:
    """Plan ``R-FAM.n`` for each old id: its own number when free, else highest + 1."""
    used = _used_numbers(row_ids + [e.new_id for e in entries])
    parsed = [(o, _OLD_PARTS.fullmatch(o)) for o in old_ids if OLD_R_RE.fullmatch(o)]
    planned: Dict[str, str] = {}
    rest: List[Tuple[str, str]] = []
    for old, match in parsed:
        family, digits, letter = match.groups()
        number = int(digits)
        if letter == "" and number >= 1 and number not in used.get(family, set()):
            used.setdefault(family, set()).add(number)
            planned[old] = f"R-{family}.{number}"
        else:
            rest.append((old, family))
    for old, family in rest:
        number = max(used.get(family, set()), default=0) + 1
        used.setdefault(family, set()).add(number)
        planned[old] = f"R-{family}.{number}"
    return {o: planned[o] for o, _ in parsed if o in planned}


def load_exclusions(path: Path) -> List[str]:
    """Paths and globs of an exclusion list, ``/``-separated, without ``#`` comments or blanks."""
    data = read_limited(path, MAP_CAP)
    try:
        if len(data) > MAP_CAP:
            raise ExclusionError(f"id-map: bad exclusion list {path}: larger than {MAP_CAP} bytes")
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ExclusionError(f"id-map: bad exclusion list {path}: not valid UTF-8") from None
    globs: List[str] = []
    for line in (raw.strip().replace("\\", "/") for raw in text.splitlines()):
        while line.startswith("./"):
            line = line[2:]
        if line and not line.startswith("#"):
            globs.append(line)
    return globs

def _excluded(path: str, globs: List[str]) -> bool:
    return any(path == g or fnmatch.fnmatchcase(path, g) for g in globs)


def rewrite_file(
    path: str, data: bytes, mapping: Dict[str, str], old_ids: Set[str]
) -> Tuple[bytes, List[Hit], List[Hit]]:
    """Return the new bytes, the replacements made and the skip lines for one file."""
    if len(data) > FILE_CAP:
        return data, [], [f"{path}\ttoo-large"]
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return data, [], [f"{path}\tbinary"]
    cites = scan_ids(text, old_ids)
    if path in RUNTIME_READ_FILES:
        return data, [], [f"{path}:{c[0]}\truntime-read\t{c[3]}" for c in cites]
    pieces: List[str] = []
    hits: List[Hit] = []
    skips: List[Hit] = []
    cursor = 0
    for line, start, end, old, kind in cites:
        if kind == "shorthand":
            skips.append(f"{path}:{line}\tshorthand\t{old}")
        elif old in mapping:
            pieces.append(text[cursor:start])
            pieces.append(mapping[old])
            cursor = end
            hits.append(f"{path}:{line}\t{old}\t{mapping[old]}")
    if not hits:
        return data, hits, skips
    pieces.append(text[cursor:])
    return "".join(pieces).encode("utf-8"), hits, skips


def _read_live(repo: Path, path: str) -> bytes:
    """Read one live file; an OSError carries the repo-relative path."""
    try:
        return read_limited(repo / path, FILE_CAP)
    except OSError as exc:
        exc.filename = path
        raise


def _cites_of(data: bytes, old_ids: Set[str]) -> List[Tuple[int, int, int, str, str]]:
    """Citations in ``data``; none when it is oversized or not UTF-8."""
    if len(data) > FILE_CAP:
        return []
    try:
        return scan_ids(data.decode("utf-8"), old_ids)
    except UnicodeDecodeError:
        return []


def run(
    repo: Path, map_path: Path, exclude: Optional[Path], apply: bool
) -> Tuple[List[str], List[str]]:
    """Rewrite (or, without ``apply``, only report) the rename entries' tokens."""
    repo = Path(repo)
    paths, skips = git_live_files(repo, map_path)
    entries = read_map(map_path)
    globs = load_exclusions(exclude) if exclude else []
    old_ids = {e.old_id for e in entries if OLD_R_RE.fullmatch(e.old_id)}
    mapping = {e.old_id: e.new_id for e in entries if e.change == "rename"}
    report: List[str] = []
    changed: Dict[str, bytes] = {}
    for path in paths:
        data = _read_live(repo, path)
        if _excluded(path, globs):
            for line, _, _, old, _ in _cites_of(data, old_ids):
                if apply:
                    raise ExcludedError(f"id-map: excluded file {path} holds {old}")
                skips.append(f"{path}:{line}\texcluded\t{old}")
            continue
        new_data, hits, file_skips = rewrite_file(path, data, mapping, old_ids)
        skips.extend(file_skips)
        if hits:
            report.append(f"{path}\t{len(hits)}")
            changed[path] = new_data
    if apply:
        for path, new_data in changed.items():
            (repo / path).write_bytes(new_data)
    return report, skips


def _head_short(repo: Path) -> str:
    done = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--short=7", "HEAD"], capture_output=True
    )
    if done.returncode != 0:
        raise RepoError(f"id-map: not a git work tree: {repo}")
    return done.stdout.decode("ascii").strip()


def _old_rows(text: str, modules: Set[str]) -> List[Tuple[int, str]]:
    """``(line, id)`` of the R-form old canon rows under the named modules."""
    section: Dict[int, str] = {}
    current = ""
    for number, line in enumerate(text.split("\n"), start=1):
        heading = _MODULE_RE.match(line)
        current = heading.group(1) if heading else current
        section[number] = current
    return [
        (n, i) for n, i in canon_rows(text) if section[n] in modules and OLD_R_RE.fullmatch(i)
    ]


def _cited_in(repo: Path, old_ids: Set[str], globs: List[str], map_path: Path) -> Dict[str, str]:
    """First live file matching ``globs`` that cites each old id."""
    cited: Dict[str, str] = {}
    if not globs:
        return cited
    paths, _ = git_live_files(repo, map_path)
    for path in (p for p in paths if _excluded(p, globs)):
        for _, _, _, old, _ in _cites_of(_read_live(repo, path), old_ids):
            cited.setdefault(old, path)
    return cited


def plan_command(
    repo: Path, modules: List[str], globs: List[str], map_path: Optional[Path] = None
) -> List[str]:
    """Proposed map entry lines for the old canon rows of ``modules``; writes nothing."""
    repo = Path(repo)
    require_top_level(repo)
    map_path = Path(map_path) if map_path else repo / MAP_RELPATH
    text = read_limited(repo / "REQUIREMENTS.md", FILE_CAP).decode("utf-8")
    rows = _old_rows(text, set(modules))
    if not rows:
        return []
    entries = read_map(map_path) if map_path.exists() else []
    cited = _cited_in(repo, {i for _, i in rows}, globs, map_path)
    todo = [i for _, i in rows if i not in cited]
    planned = plan_new_ids(todo, [i for _, i in canon_rows(text)], entries)
    sha = _head_short(repo) if planned else ""
    lines: List[str] = []
    for number, old in rows:
        if old in cited:
            lines.append(f"# deferred: {old} cited in {cited[old]}")
        else:
            lines.append(f"{old}\t{planned[old]}\trename\tREQUIREMENTS.md:{number}@{sha}")
    return lines


def _build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--repo", default=".", help="top level of the git work tree (default: current folder)")
    common.add_argument("--map", default=None, help="old-to-new id map file (default: <repo>/docs/requirements/id-map.tsv)")
    common.add_argument("--exclude", default=None, help="text file of paths and globs the tool must not change")
    parser = argparse.ArgumentParser(prog="id_rename", description="Plan and apply requirement id renames.")
    sub = parser.add_subparsers(dest="command", required=True)
    plan = sub.add_parser("plan", parents=[common], help="print proposed map entries for old canon rows")
    plan.add_argument("--module", nargs="+", required=True, help="module names to plan, for example S0 S3")
    rename = sub.add_parser("rename", parents=[common], help="list or make the token replacements")
    rename.add_argument("--apply", action="store_true", help="write the replacements; without it nothing is changed")
    return parser


def _execute(args: argparse.Namespace) -> List[str]:
    repo = Path(args.repo)
    exclude = Path(args.exclude) if args.exclude else None
    if args.command == "plan":
        globs = load_exclusions(exclude) if exclude else []
        return plan_command(repo, args.module, globs, Path(args.map) if args.map else None)
    map_path = Path(args.map) if args.map else repo / MAP_RELPATH
    report, skips = run(repo, map_path, exclude, args.apply)
    return report + (["# skipped"] + skips if skips else [])


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Command line entry point; status 2 on a stop case, else 0."""
    args = _build_parser().parse_args(argv)
    try:
        lines = _execute(args)
    except (MapError, RepoError, ExcludedError, ExclusionError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"id-map: cannot read {exc.filename}: {exc.strerror or exc}", file=sys.stderr)
        return 2
    for line in lines:
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
