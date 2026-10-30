"""Inc 6 corrective pass 2 mutation harness (C-40): apply one declared
mutation (one exact single-occurrence edit), run the named test selection,
restore the file byte-exactly and verify its SHA-256. One transcript per
mutation: ``fix2-mut-<id>.txt``.

Usage: python fix2_mutation_harness.py <worktree> <mutation-id> [...]

Anchors are written with LF line ends; the source files are CRLF, so the
harness normalises to LF, edits, and writes CRLF back (the restore writes
the original bytes).
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

PYTHON = r"C:\Users\jjgh8\anaconda3\envs\s19env\python.exe"
APP = "s19_app/tui/app.py"
SVC = "s19_app/tui/services/variant_execution_service.py"
SCREENS = "s19_app/tui/screens.py"
ACTIVE = "tests/test_b100_active_variant.py"
ANNOUNCE = "tests/test_b100_announce.py"

# id -> (finding, file, old, new, description, pytest selection)
MUTATIONS = {
    "SEC6-7-no-resolve-catch": (
        "SEC6-7 (LLR-168.1 / LLR-178.1)",
        SVC,
        "    except (OSError, ValueError) as exc:\n",
        "    except () as exc:\n",
        "the resolver no longer catches OSError / ValueError around resolve() and the reparse walk",
        [ANNOUNCE, ACTIVE, "-k", "overlong"],
    ),
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(worktree: Path, mid: str, out_dir: Path) -> None:
    finding, rel, old, new, description, selection = MUTATIONS[mid]
    path = worktree / rel
    original = path.read_bytes()
    before = sha(path)
    text = original.decode("utf-8").replace("\r\n", "\n")
    assert text.count(old) == 1, f"{mid}: anchor occurs {text.count(old)} times"
    path.write_bytes(text.replace(old, new).replace("\n", "\r\n").encode("utf-8"))
    env = dict(os.environ)
    env.pop("NO_COLOR", None)
    env.update(
        PYTHONUTF8="1",
        PYTHONDONTWRITEBYTECODE="1",
        PYTHONIOENCODING="utf-8",
        PYTHONPATH=str(worktree),
    )
    command = [PYTHON, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-rfE",
               f"--basetemp={os.environ.get('TEMP', '.')}\\f2mut-{mid}", *selection]
    try:
        probe = subprocess.run(
            [PYTHON, "-c", "import s19_app; print(s19_app.__file__)"],
            cwd=worktree, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        result = subprocess.run(command, cwd=worktree, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace")
    finally:
        path.write_bytes(original)
    restored = sha(path) == before
    verdict = "KILLED" if result.returncode != 0 else "SURVIVED"
    lines = [
        f"# mutation: {mid} — {finding}: {description}",
        f"# file: {rel} (sha256 before {before[:16]})",
        f"# command: {' '.join(command[1:])}",
        f"# tree: {worktree} (corrective pass 2, mutated in place, then restored)",
        f"# PYTHONPATH={worktree} ; NO_COLOR=unset ; PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8",
        f"# s19_app.__file__ = {probe.stdout.strip()}",
        f"# date: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        "# --- old",
        *("#   " + line for line in old.splitlines()),
        "# --- new",
        *("#   " + line for line in new.splitlines()),
        result.stdout,
        result.stderr,
        f"VERDICT: {verdict} (pytest exit {result.returncode})",
        f"RESTORE {'OK' if restored else 'FAILED'} (sha256 {sha(path)[:16]})",
    ]
    (out_dir / f"fix2-mut-{mid}.txt").write_text("\n".join(lines), encoding="utf-8")
    print(mid, verdict, "RESTORE", "OK" if restored else "FAILED")
    if not restored:
        sys.exit(2)


if __name__ == "__main__":
    tree = Path(sys.argv[1]).resolve()
    here = Path(__file__).resolve().parent
    for mutation_id in sys.argv[2:]:
        run(tree, mutation_id, here)
