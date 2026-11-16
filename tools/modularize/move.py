"""The mover: split two old TUI modules into two packages, verbatim.

Reads ``design/spec-move.md`` and ``design/interfaces.md`` (I-1..I-7). The
mover never imports ``s19_app`` in its own process; every check that needs the
product runs in a subprocess under ``--py``. Standard library only.
"""
from __future__ import annotations

import sys
from pathlib import Path

# ``python -I`` does not put the script's directory on ``sys.path``.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import argparse
import json
import subprocess
import types

from move_common import (APP_MODULE_ORDER, APP_OLD, APP_PKG, SDB_MODULE_ORDER,
                         SDB_OLD, SDB_PKG, MoveError)
from move_derive import derive_package
from move_emit import build_files
from move_check import run_acceptance


def import_plan_map() -> types.ModuleType:
    """Import ``plan_map`` with a stub ``textual`` so its module guard passes."""
    textual = types.ModuleType("textual")
    textual.__path__ = []
    textual_app = types.ModuleType("textual.app")
    class _App:  # only ``dir`` is read at import time; contents are irrelevant
        pass
    textual_app.App = _App
    sys.modules.setdefault("textual", textual)
    sys.modules.setdefault("textual.app", textual_app)
    tools_dir = Path(__file__).resolve().parent
    sys.path.insert(0, str(tools_dir))
    import plan_map
    return plan_map


def git(args: list[str], cwd: str) -> str:
    proc = subprocess.run(["git", "-C", cwd, *args], capture_output=True)
    if proc.returncode != 0:
        raise MoveError("USAGE", f"git {' '.join(args)} failed: "
                        f"{proc.stderr.decode('utf-8', 'replace').strip()}")
    return proc.stdout.decode("utf-8").strip()


def resolve_rev(repo: str, rev: str) -> str:
    return git(["rev-parse", "--verify", f"{rev}^{{commit}}"], repo)


def make_isolated_env(tree: str) -> dict[str, str]:
    """Build the minimal isolated env (RU-12) plus the import path."""
    state = (Path.cwd() / ".." / "state").resolve()
    for sub in ("zq_iso_user", "x/c", "x/d", "x/k", "tmp"):
        (state / sub).mkdir(parents=True, exist_ok=True)
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(state / "zq_iso_user"),
        "XDG_CONFIG_HOME": str(state / "x" / "c"),
        "XDG_DATA_HOME": str(state / "x" / "d"),
        "XDG_CACHE_HOME": str(state / "x" / "k"),
        "TMPDIR": str(state / "tmp"),
        "PYTHONDONTWRITEBYTECODE": "1",
        "LANG": "C.UTF-8",
        "PYTHONPATH": tree,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="move.py", description="Split the two old TUI modules.")
    parser.add_argument("--repo", required=True, help="git work tree (scratch clone)")
    parser.add_argument("--rev", required=True, help="base revision")
    parser.add_argument("--map", required=True, help="module-map.json")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--py", default=sys.executable, help="interpreter for s19_app subprocesses")
    return parser.parse_args(argv)


def _fail(code: str, detail: str) -> int:
    print(f"MOVE FAIL {code}: {detail}")
    return 1


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    repo = str(Path(args.repo).resolve())
    map_path = Path(args.map).resolve()

    try:
        data = json.loads(map_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"MOVE FAIL USAGE: cannot read map: {exc}")
        return 2

    try:
        rev_full = resolve_rev(repo, args.rev)
    except MoveError as exc:
        print(f"MOVE FAIL USAGE: {exc.detail}")
        return 2

    map_base = data.get("base")
    try:
        map_base_full = resolve_rev(repo, str(map_base))
    except MoveError:
        return _fail("E1", f"map base {map_base!r} does not resolve in the repo")
    if map_base_full != rev_full:
        return _fail("E1", f"map base {map_base_full} != rev {rev_full}")

    plan_map = import_plan_map()
    app_map = data["app"]
    sdb_map = data["screens_directionb"]
    mixin_order = list(app_map["mixin_order"])
    app_module_order = APP_MODULE_ORDER + mixin_order

    try:
        app = derive_package(repo, rev_full, APP_OLD, APP_PKG, app_map, plan_map,
                             is_app=True, mixin_order=mixin_order)
        sdb = derive_package(repo, rev_full, SDB_OLD, SDB_PKG, sdb_map, plan_map,
                             is_app=False, mixin_order=None)
        files, deletions, edits, counters = build_files(
            app, sdb, rev_full, app_module_order, SDB_MODULE_ORDER)
    except MoveError as exc:
        return _fail(exc.code, exc.detail)

    if args.dry_run:
        import shutil
        import tempfile
        tmp = Path(tempfile.mkdtemp(prefix="move-dry-run-"))
        try:
            shutil.copytree(Path(repo) / "s19_app", tmp / "s19_app")
            _write_files(tmp, files, deletions, edits)
            ok, metrics, fails = run_acceptance(files, str(tmp), args.py,
                                                make_isolated_env(str(tmp)),
                                                app, sdb)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    else:
        _write_files(Path(repo), files, deletions, edits)
        ok, metrics, fails = run_acceptance(files, repo, args.py, make_isolated_env(repo),
                                            app, sdb)

    app_count = len([f for f in files if f.startswith("s19_app/tui/app/")])
    sdb_count = len([f for f in files if f.startswith("s19_app/tui/screens_directionb/")])
    print(f"MOVE base={rev_full} app_files={app_count} sdb_files={sdb_count} "
          f"units={counters['units']} d1_rewrites={counters['d1']} "
          f"relimport_rewrites={counters['relimport']} css_rewrites={counters['css']}")
    print(f"MOVE imports_fresh={metrics['imports_ok']}/{metrics['imports_total']} "
          f"cycles={metrics['cycles']} reexports_missing={metrics['reexports_missing']} "
          f"caps_over={metrics['caps_over']}")
    for _pkg_name, matched, used in metrics["deps_bound"]:
        print(f"SELF deps-bound {matched}/{used}")
    for line in fails:
        print(line)
    if ok:
        print("MOVE OK")
        return 0
    return 1


def _write_files(root: Path, files: dict[str, str], deletions: list[str],
                 edits: dict) -> None:
    mod_dir = root / ".modularize"
    mod_dir.mkdir(parents=True, exist_ok=True)
    for rel, text in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8", newline="\n")
    for rel in deletions:
        (root / rel).unlink(missing_ok=True)
    (mod_dir / "move-edits.json").write_text(
        json.dumps(edits, indent=1, ensure_ascii=False, sort_keys=True),
        encoding="utf-8", newline="\n")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
