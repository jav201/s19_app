"""Inc 5 corrective pass 1 mutation harness (C-40): apply one mutation by
exact byte anchor (CRLF), run the FULL test module, restore the file
byte-exactly and verify its SHA-256. One transcript per mutation:
``fix1-mut-<id>.txt``.

MB / MC / ME / MG are the code-reviewer's survivors
(``review-increment-005.md`` F1, F3, F4, F5) re-anchored on the corrected
code; MX, MF2 and MK pin the corrective pass's own new decisions.

Usage: python fix1-mutation_harness.py <worktree> <mutation-id> [...]
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

APP = "s19_app/tui/app.py"

# id -> (finding / requirement, file, [(old, new)], description)
MUTATIONS = {
    "MB-mismatch-silenced": (
        "review F3 (LLR-163.7, LLR-167.6)",
        APP,
        [
            ("                mismatch = _plan_row_mismatch(row, placed)\r\n",
             "                mismatch = None\r\n"),
        ],
        "the plan-row landing check is silenced",
    ),
    "MC-emit-not-recorded": (
        "review F1 / SEC-7 (LLR-167.4, LED .53)",
        APP,
        [
            ("                        landed.append(placed)\r\n"
             "                        if not placed.reused:\r\n"
             "                            placed_files.append(placed.path)\r\n",
             "                        landed.append(placed)\r\n"),
        ],
        "the emitted image is never recorded for rollback",
    ),
    "ME-adopt-before-folder": (
        "review F4 (LLR-167.2, LLR-167.4)",
        APP,
        [
            ("        # Review findings F6(a)/S-F5: remember whether THIS call creates the\r\n",
             "        if image_step.emit:\r\n"
             "            self._change_service.adopt_rederived(\r\n"
             "                self.current_file.mem_map, image_step.derived, image_step.summary\r\n"
             "            )\r\n"
             "        # Review findings F6(a)/S-F5: remember whether THIS call creates the\r\n"),
        ],
        "the re-derived image is adopted before the project folder exists",
    ),
    "MG-install-always-marks": (
        "review F5 (LLR-167.5)",
        APP,
        [
            ("        if loaded.mem_map is not previous_map:\r\n"
             "            self._change_service.mark_saved(loaded.mem_map)\r\n",
             "        if True:\r\n"
             "            self._change_service.mark_saved(loaded.mem_map)\r\n"),
        ],
        "every install (a MAC attach included) records the saved state",
    ),
    "MX-no-rollback-on-defect": (
        "review F1 / SEC-7 (non-OSError half)",
        APP,
        [
            ("        except Exception:\r\n"
             "            # SEC-7: any other error after the folder's creation is a\r\n",
             "        except ZeroDivisionError:\r\n"
             "            # SEC-7: any other error after the folder's creation is a\r\n"),
        ],
        "a non-OSError after the folder's creation escapes without rollback",
    ),
    "MF2-read-error-escapes": (
        "review F2 (LLR-164.4)",
        APP,
        [
            ("        except OSError as exc:\r\n"
             "            unreadable = (\r\n",
             "        except ZeroDivisionError as exc:\r\n"
             "            unreadable = (\r\n"),
        ],
        "an unreadable source escapes the decide/plan block",
    ),
    "MK-manifest-keys-drift": (
        "review F8 (LED .45)",
        APP,
        [
            ("    return tuple(json.loads(text))\r\n",
             "    return tuple(json.loads(text)) + (\"gathered\",)\r\n"),
        ],
        "the plan's manifest keys drift from the keys project.json carries",
    ),
}

PYTHON = r"C:\Users\jjgh8\anaconda3\envs\s19env\python.exe"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(worktree: Path, mutation_id: str) -> None:
    finding, rel, edits, description = MUTATIONS[mutation_id]
    target = worktree / rel
    original = target.read_bytes()
    pre_hash = hashlib.sha256(original).hexdigest()
    data = original
    for old, new in edits:
        anchor = old.encode("utf-8")
        assert data.count(anchor) == 1, f"{mutation_id}: anchor count {data.count(anchor)}"
        data = data.replace(anchor, new.encode("utf-8"))
    out = worktree / ".dev-flow/2026-10-26-batch-100/evidence/inc-5" / f"fix1-mut-{mutation_id}.txt"
    env = dict(os.environ)
    env.pop("NO_COLOR", None)
    env.update(
        PYTHONUTF8="1",
        PYTHONDONTWRITEBYTECODE="1",
        PYTHONIOENCODING="utf-8",
        PYTHONPATH=str(worktree),
    )
    cmd = [PYTHON, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-rfE",
           "tests/test_b100_save_image.py"]
    try:
        target.write_bytes(data)
        mutant_hash = sha(target)
        proc = subprocess.run(cmd, cwd=worktree, env=env, capture_output=True, text=True,
                              encoding="utf-8", errors="replace")
    finally:
        target.write_bytes(original)
    restored = sha(target)
    header = [
        "# command: python -m pytest -q -p no:cacheprovider -rfE tests/test_b100_save_image.py",
        f"# tree: {worktree} (base 8d6056f + Inc 5 working tree + corrective pass 1) with mutation {mutation_id}",
        f"# PYTHONPATH={worktree} ; NO_COLOR=unset ; PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8",
        f"# date: {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        f"# finding: {finding}",
        f"# mutation: {description} — file {rel}",
        f"# pre-mutation sha256: {pre_hash}",
        f"# mutant sha256: {mutant_hash}",
        f"# restored sha256: {restored}",
        "# RESTORE OK" if restored == pre_hash else "# RESTORE FAILED",
        "",
    ]
    out.write_text("\n".join(header) + proc.stdout + proc.stderr + f"\n# exit: {proc.returncode}\n",
                   encoding="utf-8")
    tail = [line for line in proc.stdout.splitlines() if "passed" in line or "failed" in line]
    print(mutation_id, tail[-1] if tail else "?", "RESTORE OK" if restored == pre_hash else "RESTORE FAILED")
    if restored != pre_hash:
        sys.exit(2)


if __name__ == "__main__":
    tree = Path(sys.argv[1])
    for mid in sys.argv[2:]:
        run(tree, mid)
