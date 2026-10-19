"""Inc-004 C-20 move-aside — the trigger-absent RED counterfactual for the
net-new test file ``tests/test_tui_issues_triage_b94.py``.

The file is MOVED ASIDE (never stashed — ``git stash`` silently ignores
untracked files), the minted nodes are collected (they must fail at
collection: ``file or directory not found``, the trigger-absent state), then
the file is restored and the restore is proven by SHA-256.

Run from the repo root:

    PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 python -B \
        .dev-flow/2026-10-12-batch-94/evidence/inc004_move_aside.py
"""
from __future__ import annotations

import hashlib
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[3]
TARGET = ROOT / "tests" / "test_tui_issues_triage_b94.py"
ASIDE = TARGET.with_suffix(TARGET.suffix + ".ASIDE")


def sha(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    before = sha(TARGET)
    print("before:", before, flush=True)
    TARGET.rename(ASIDE)
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
             "--color=no", "tests/test_tui_issues_triage_b94.py"],
            env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1",
                     PYTHONIOENCODING="utf-8", PY_COLORS="0"),
            capture_output=True, text=True,
        )
    finally:
        ASIDE.rename(TARGET)
    after = sha(TARGET)
    print("after: ", after, flush=True)
    print("restore proven:", before == after, flush=True)
    tail = (result.stdout or "").strip().splitlines()
    print("run tail:", tail[-1] if tail else "(no output)", flush=True)
    # pytest exit 4 (usage/collection error — the file is absent) is the RED.
    verdict = {4: "RED (KILLED — trigger absent, collection failed)"}.get(
        result.returncode
    )
    print(f"verdict: {verdict or 'CRASH/BAD (exit %d)' % result.returncode}",
          flush=True)
    return 0 if (before == after and result.returncode == 4) else 1


if __name__ == "__main__":
    sys.exit(main())
