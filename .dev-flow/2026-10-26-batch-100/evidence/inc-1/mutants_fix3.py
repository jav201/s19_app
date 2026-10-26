"""Fix-pass-3 mutation scripts (N1 revert + census root-drop).

Each applies one declared mutation with an exact anchor, runs nothing itself.
CRLF is preserved: replacements are done on bytes.
"""
from __future__ import annotations

import hashlib
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[4]


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def apply_mutation(path: Path, old: bytes, new: bytes) -> None:
    data = path.read_bytes()
    if data.count(old) != 1:
        raise SystemExit(f"anchor not unique in {path}: {old[:60]!r} count={data.count(old)}")
    backup = path.with_suffix(path.suffix + ".mutbak")
    shutil.copy2(path, backup)
    path.write_bytes(data.replace(old, new))
    print(f"mutated {path}: {sha(path)}")


def restore(path: Path) -> None:
    backup = path.with_suffix(path.suffix + ".mutbak")
    shutil.copy2(backup, path)
    backup.unlink()
    print(f"restored {path}: {sha(path)}")


def main() -> None:
    which = sys.argv[1]
    if which == "n1":
        path = REPO / "s19_app" / "tui" / "workspace.py"
        old = (
            b"    while True:\r\n"
            b"        parts = candidate.parts\r\n"
            b"        if same_anchor(parts):\r\n"
            b"            found = candidate\r\n"
        )
        new = (
            b"    while True:\r\n"
            b"        parts = candidate.parts\r\n"
            b"        if same_anchor(parts):\r\n"
            b"            return candidate  # MUTANT N1: nearest anchor wins\r\n"
        )
        apply_mutation(path, old, new)
    elif which == "census":
        path = REPO / "s19_app" / "tui" / "app.py"
        old = (
            b"            copy_into_workarea(self.current_a2l_path, project_dir,"
            b" workarea_root=self.workarea)\r\n"
        )
        new = (
            b"            copy_into_workarea(self.current_a2l_path, project_dir)"
            b"  # MUTANT: root dropped\r\n"
        )
        apply_mutation(path, old, new)
    elif which.startswith("restore-"):
        which = which[len("restore-"):]
        path = {
            "n1": REPO / "s19_app" / "tui" / "workspace.py",
            "census": REPO / "s19_app" / "tui" / "app.py",
        }[which]
        restore(path)
    else:
        raise SystemExit(f"unknown mutation {which!r}")


if __name__ == "__main__":
    main()
