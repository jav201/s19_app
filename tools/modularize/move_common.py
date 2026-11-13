"""Shared constants and the mover error type (never run as ``__main__``)."""
from __future__ import annotations

import subprocess

APP_OLD = "s19_app/tui/app.py"
SDB_OLD = "s19_app/tui/screens_directionb.py"
APP_PKG = "s19_app.tui.app"
SDB_PKG = "s19_app.tui.screens_directionb"

APP_MODULE_ORDER = ["deps", "shared", "shared_io", "core"]
SDB_MODULE_ORDER = ["deps", "shared", "map_parts", "memory_map",
                    "loaded_artifacts", "patch_editor", "check_editor", "ab_diff"]

APP_BASE_MODULES = {"core", "deps", "shared", "shared_io"}
SDB_BASE_MODULES = {"__init__", "deps", "shared", "map_parts", "memory_map",
                    "loaded_artifacts", "patch_editor", "check_editor", "ab_diff"}


class MoveError(Exception):
    """A pre-write mover error (E1..E13)."""

    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def git(args: list[str], cwd: str) -> str:
    proc = subprocess.run(["git", "-C", cwd, *args], capture_output=True)
    if proc.returncode != 0:
        raise MoveError("USAGE", f"git {' '.join(args)} failed: "
                        f"{proc.stderr.decode('utf-8', 'replace').strip()}")
    return proc.stdout.decode("utf-8").strip()


def read_base(repo: str, rev: str, rel: str) -> str:
    return git(["show", f"{rev}:{rel}"], repo)
