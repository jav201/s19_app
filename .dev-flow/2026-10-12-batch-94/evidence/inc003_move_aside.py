"""inc003 C-20 move-aside — the trigger-absent RED counterfactual for the two
NET-NEW test files (tests/test_tui_flow_execution_b94.py,
tests/test_flow_chainset_b94.py). Move-aside per C-20 (rename out of the
tree — NEVER git stash, which silently stashes nothing for untracked paths),
run the minted nodes, restore, and prove the restore by sha256.

Expected outcome: with both files absent, collecting the minted nodes fails
(ModuleNotFoundError / errors-during-collection) — the run is RED by
construction, which is the counterfactual's whole point: the battery's
clean-tree baseline (phase 2 of inc003_battery.py) is the same harness seeing
GREEN on the present tree.

Run from the repo root:
    PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 \
        python -B .dev-flow/2026-10-12-batch-94/evidence/inc003_move_aside.py
"""

from __future__ import annotations

import hashlib
import os
import pathlib
import shutil
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[3]
os.chdir(REPO)

ENV = dict(
    os.environ,
    PY_COLORS="0",
    PYTHONDONTWRITEBYTECODE="1",
    PYTHONIOENCODING="utf-8",
)

FILES = [
    "tests/test_tui_flow_execution_b94.py",
    "tests/test_flow_chainset_b94.py",
]
ASIDE_DIR = pathlib.Path(".dev-flow/2026-10-12-batch-94/evidence/_aside_inc003")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    print("=" * 78)
    print("inc003 C-20 move-aside — the trigger-absent RED for the 2 net-new files")
    print("cwd:", REPO)
    print("=" * 78)

    originals = {rel: pathlib.Path(rel).read_bytes() for rel in FILES}
    for rel, data in originals.items():
        print(f"before-hash {rel}: {sha256(data)}", flush=True)

    ASIDE_DIR.mkdir(parents=True, exist_ok=True)
    moved = []
    try:
        for rel in FILES:
            target = ASIDE_DIR / pathlib.Path(rel).name
            if target.exists():
                target.unlink()
            shutil.move(rel, target)
            moved.append((rel, target))
            print(f"moved aside: {rel} -> {target}", flush=True)

        cmd = [sys.executable, "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider",
               "--color=no", *FILES]
        print(f"$ pytest [{' '.join(FILES)}]  (the moved-aside run)", flush=True)
        proc = subprocess.run(cmd, env=ENV, capture_output=True, text=True,
                              timeout=180)
        out = proc.stdout + proc.stderr
        print("---- run output (tail) ----")
        print(out[-2000:])
        print(f"---- exit {proc.returncode} ----")
        red = proc.returncode != 0
        if red:
            print("verdict: RED (KILLED) — collection of the minted nodes "
                  "fails with the files absent")
        else:
            print("verdict: GREEN (SURVIVED) — UNEXPECTED: the nodes ran "
                  "without the files")
    finally:
        for rel, target in moved:
            shutil.move(str(target), rel)
            restored = pathlib.Path(rel).read_bytes()
            ok = restored == originals[rel]
            print(f"restored: {rel} — hash {'identical' if ok else 'MISMATCH!'} "
                  f"({sha256(restored)})", flush=True)
            assert ok, "the restore is not proven"

    for rel, data in originals.items():
        now = pathlib.Path(rel).read_bytes()
        print(f"after-hash  {rel}: {sha256(now)}", flush=True)
        assert now == data, f"{rel} did not restore byte-identically"

    print("\nRESTORE PROVEN (hash identical) for every moved-aside file")
    return 0


if __name__ == "__main__":
    sys.exit(main())
