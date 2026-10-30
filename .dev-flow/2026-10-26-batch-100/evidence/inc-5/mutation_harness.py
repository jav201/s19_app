"""Inc 5 mutation harness (C-40): apply one declared mutation by position +
operation, run the FULL new test module, restore the file byte-exactly and
verify its SHA-256. One transcript per mutation: ``mut-<id>.txt``.

Usage: python mutation_harness.py <worktree> <mutation-id> [<mutation-id> ...]
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

APP = "s19_app/tui/app.py"
SVC = "s19_app/tui/services/change_service.py"
APPLY = "s19_app/tui/changes/apply.py"

# id -> (LLR, file, old, new, description)
MUTATIONS = {
    "167.1-round2-rule": (
        "LLR-167.1",
        APP,
        [
            ('        if document.kind != "change" or not (\r\n'
             "            service.image_differs_from_source(mem_map) or document.entries\r\n"
             "        ):\r\n",
             "        if not (\r\n"
             "            service.image_differs_from_source(mem_map) or document.entries\r\n"
             "        ):\r\n"),
            ("        if not service.rederived_differs_from_source(mem_map, derived):\r\n"
             "            return _ProjectImageStep(emit=False)\r\n",
             ""),
        ],
        "the round-2 rule: any document kind counts and emit whenever the "
        "document holds an entry (the data comparison removed)",
    ),
    "167.1-precheck-decides": (
        "LLR-167.1",
        APP,
        [
            ('        if document.kind != "change" or not (\r\n'
             "            service.image_differs_from_source(mem_map) or document.entries\r\n"
             "        ):\r\n",
             '        if document.kind != "change" or not (\r\n'
             "            service.image_differs_from_source(mem_map)\r\n"
             "        ):\r\n"),
        ],
        "the pre-check decides copy: a false pre-check skips the comparison",
    ),
    "167.2-decide-on-saved-state": (
        "LLR-167.2",
        APP,
        [
            ("        if not service.rederived_differs_from_source(mem_map, derived):\r\n",
             "        if not service.differs_from_last_saved(mem_map):\r\n"),
        ],
        "emit-or-copy decided on differs_from_last_saved (A-08)",
    ),
    "167.3-drop-suffix": (
        "LLR-167.3",
        APP,
        [
            ('        image_clause = f" — {plan.image}" if image_step.emit else ""\r\n',
             '        image_clause = ""\r\n'),
        ],
        "the success line drops the entry-count clause",
    ),
    "167.4-ignore-blocked": (
        "LLR-167.4",
        APP,
        [
            ("        if blocked:\r\n            names = ",
             "        if False:\r\n            names = "),
        ],
        "the blocked re-derive is ignored (ok=False not honoured)",
    ),
    "167.5-saveback-only": (
        "LLR-167.5",
        APP,
        [
            ("            self._change_service.mark_saved(mem_map)\r\n"
             "        # F1: the success line paints only after the manifest is on\r\n",
             "            pass\r\n"
             "        # F1: the success line paints only after the manifest is on\r\n"),
        ],
        "mark_saved called on the save-back path only (Save project's call removed)",
    ),
    "167.6-unplanned-file": (
        "LLR-167.6",
        APP,
        [
            ('                if row.role == "image" and image_step.emit:\r\n'
             "                    landed: list[PlacementResult] = []\r\n",
             '                if row.role == "image" and image_step.emit:\r\n'
             "                    place_into_workarea(\r\n"
             "                        self.current_file.path, project_dir,\r\n"
             "                        workarea_root=self.workarea,\r\n"
             "                    )\r\n"
             "                    landed: list[PlacementResult] = []\r\n"),
        ],
        "the handler places a file the plan did not name (the source copy "
        "beside the emitted image)",
    ),
    "167.7-rederive-writes-session": (
        "LLR-167.7",
        SVC,
        [
            ("            for address, byte in self._journal.items():\r\n"
             "                copy[address] = byte\r\n",
             "            for address, byte in self._journal.items():\r\n"
             "                copy[address] = byte\r\n"
             "                session_map[address] = byte\r\n"),
        ],
        "rederive_for_save writes the session map",
    ),
    "167.8-inverse-clears-flag": (
        "LLR-167.8",
        APP,
        [
            ("            self._change_service.mark_saved(mem_map)\r\n"
             "        # F1: the success line paints only after the manifest is on\r\n",
             "            self._change_service.mark_saved(mem_map)\r\n"
             "        self.query_one(\"#patch_editor_panel\", PatchEditorPanel).mark_saved()\r\n"
             "        # F1: the success line paints only after the manifest is on\r\n"),
        ],
        "INVERSE probe for the STOP item: Save project clears the panel's "
        "dirty flag unconditionally",
    ),
    "sec4-resolved-staging": (
        "LLR-167.7 (SEC-4, LED .56)",
        APPLY,
        [
            ("        _resolved_destination, staging_root = _guarded_destination(\r\n"
             "            dest_dir, workarea_root\r\n"
             "        )\r\n",
             "        staging_root = next(\r\n"
             "            candidate\r\n"
             "            for candidate in (dest_dir.resolve(), *dest_dir.resolve().parents)\r\n"
             "            if candidate.name == WORKAREA_SUBDIR\r\n"
             "            and candidate.parent.name == WORKAREA_DIRNAME\r\n"
             "        )\r\n"),
        ],
        "the staging root resolves dest_dir again (the pre-SEC-4 walk)",
    ),
}

PYTHON = r"C:\Users\jjgh8\anaconda3\envs\s19env\python.exe"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(worktree: Path, mutation_id: str) -> None:
    llr, rel, edits, description = MUTATIONS[mutation_id]
    target = worktree / rel
    original = target.read_bytes()
    pre_hash = hashlib.sha256(original).hexdigest()
    text = original.decode("utf-8")
    for old, new in edits:
        assert text.count(old) == 1, f"{mutation_id}: anchor count {text.count(old)}"
        text = text.replace(old, new)
    out = worktree / ".dev-flow/2026-10-26-batch-100/evidence/inc-5" / f"mut-{mutation_id}.txt"
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
        target.write_bytes(text.encode("utf-8"))
        mutant_hash = sha(target)
        proc = subprocess.run(cmd, cwd=worktree, env=env, capture_output=True, text=True,
                              encoding="utf-8", errors="replace")
    finally:
        target.write_bytes(original)
    restored = sha(target)
    header = [
        f"# command: python -m pytest -q -p no:cacheprovider -rfE tests/test_b100_save_image.py",
        f"# tree: {worktree} (base 8d6056f + Inc 5 working tree) with mutation {mutation_id}",
        f"# PYTHONPATH={worktree} ; NO_COLOR=unset ; PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1",
        f"# date: {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        f"# requirement: {llr}",
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
