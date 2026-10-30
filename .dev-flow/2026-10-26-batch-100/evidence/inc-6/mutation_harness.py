"""Inc 6 mutation harness (C-40): apply one declared mutation by position +
operation, run the named test selection, restore the file byte-exactly and
verify its SHA-256. One transcript per mutation: ``mut-<id>.txt``.

Usage: python mutation_harness.py <worktree> <mutation-id> [<mutation-id> ...]

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
PART_A_TCS = "tc_b100_18 or tc_b100_19 or tc_b100_20"

# id -> (requirement, file, [(old, new)], description, pytest selection)
MUTATIONS = {
    "168.1-ignore-gathered": (
        "LLR-168.1",
        SVC,
        [('    gathered_raw = payload.get("gathered", {})\n',
          "    gathered_raw = {}\n")],
        "the reader ignores the gathered key (the rewrite then drops it)",
        [ACTIVE, "-k", PART_A_TCS],
    ),
    "168.2-saveback-not-activated": (
        "LLR-168.2",
        APP,
        [("                if self._activate_project_file(project_dir, saved) is not None:\n",
          "                if False:\n")],
        "the save-back no longer activates the written file nor rewrites the manifest",
        [ACTIVE, "-k", PART_A_TCS],
    ),
    "168.3-append-no-seam-call": (
        "LLR-168.3",
        APP,
        [("                        # LLR-168.3: the appended file is the project's\n"
          "                        # active variant on disk too, and the status says\n"
          "                        # which file Load now opens.\n"
          "                        self._write_and_verify_manifest(\n"
          "                            project_dir, **self._manifest_carry(project_dir)\n"
          "                        )\n",
          "")],
        "the seam call is removed from the variant append",
        [ACTIVE, "-k", PART_A_TCS],
    ),
    "168.3-absolute-batch": (
        "LLR-168.3",
        APP,
        [('            "batch": _relative(manifest.batch),\n',
          '            "batch": [str(path) for path in manifest.batch],\n')],
        "the carry passes the reader's absolute batch paths (A-03 probe)",
        [ACTIVE, "-k", PART_A_TCS],
    ),
    "178.1-fallback-called-recorded": (
        "LLR-178.1",
        SVC,
        [("        else:\n"
          "            reason = LOAD_REASON_NEXT_VALID\n",
          "        else:\n"
          "            reason = LOAD_REASON_RECORDED\n")],
        "the composer reports 'recorded active' for the fallback (next valid) case",
        [ANNOUNCE],
    ),
    "178.2-markup-on": (
        "LLR-178.2",
        APP,
        [("        self.set_file_status(safe_text(announcement.status_line()))\n",
          "        self.set_file_status(Text.from_markup(announcement.status_line()))\n")],
        "the final #status_text line is painted with markup on",
        [ANNOUNCE, "-k", "tc_b100_56"],
    ),
    "178.2-status-before-load": (
        "LLR-178.2",
        APP,
        [("        self.set_file_status(safe_text(announcement.status_line()))\n",
          ""),
         ("        self.load_selected_file(selected_file, a2l_files)\n"
          "        if primary_file and mac_file:\n",
          "        self.set_file_status(f\"Loaded project '{name}' -> {selected_file.name}\")\n"
          "        self.load_selected_file(selected_file, a2l_files)\n"
          "        if primary_file and mac_file:\n")],
        "the project + file line is written BEFORE the loads (not the final writer)",
        [ANNOUNCE, "-k", "tc_b100_56"],
    ),
    "178.3-focus-on-close": (
        "LLR-178.3",
        SCREENS,
        [('        self.query_one("#result_body", VerticalScroll).focus()\n',
          '        self.query_one("#result_ok", Button).focus()\n')],
        "the panel's focus starts on #result_ok",
        [ANNOUNCE, "-k", "tc_b100_67"],
    ),
    "178.3-truncate-10": (
        "LLR-178.3",
        SCREENS,
        [("                    for problem in announcement.problems\n",
          "                    for problem in announcement.problems[:10]\n")],
        "the problem list is truncated at 10 rows",
        [ANNOUNCE, "-k", "tc_b100_67"],
    ),
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(worktree: Path, mutation_id: str) -> None:
    requirement, rel, edits, description, selection = MUTATIONS[mutation_id]
    target = worktree / rel
    original = target.read_bytes()
    pre_hash = hashlib.sha256(original).hexdigest()
    text = original.decode("utf-8").replace("\r\n", "\n")
    for old, new in edits:
        assert text.count(old) == 1, f"{mutation_id}: anchor count {text.count(old)}"
        text = text.replace(old, new)
    out = worktree / ".dev-flow/2026-10-26-batch-100/evidence/inc-6" / f"mut-{mutation_id}.txt"
    env = dict(os.environ)
    env.pop("NO_COLOR", None)
    env.update(
        PYTHONUTF8="1",
        PYTHONDONTWRITEBYTECODE="1",
        PYTHONIOENCODING="utf-8",
        PYTHONPATH=str(worktree),
    )
    cmd = [PYTHON, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-rfE", *selection]
    try:
        target.write_bytes(text.replace("\n", "\r\n").encode("utf-8"))
        mutant_hash = sha(target)
        proc = subprocess.run(cmd, cwd=worktree, env=env, capture_output=True, text=True,
                              encoding="utf-8", errors="replace")
    finally:
        target.write_bytes(original)
    restored = sha(target)
    header = [
        f"# command: python -m pytest -q -p no:cacheprovider -rfE {' '.join(selection)}",
        f"# tree: {worktree} (base 093a7c0 + Inc 6 working tree) with mutation {mutation_id}",
        f"# PYTHONPATH={worktree} ; NO_COLOR=unset ; PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1",
        f"# date: {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        f"# requirement: {requirement}",
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
