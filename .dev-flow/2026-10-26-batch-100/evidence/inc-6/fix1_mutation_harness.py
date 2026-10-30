"""Inc 6 corrective pass 1 mutation harness (C-40): apply one declared
mutation (one exact single-occurrence edit), run the named test selection,
restore the file byte-exactly and verify its SHA-256. One transcript per
mutation: ``fix1-mut-<id>.txt``.

Usage: python fix1_mutation_harness.py <worktree> <mutation-id> [...]

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
    "F1-no-damaged-check": (
        "F1 / SEC6-1 (LLR-168.3, OQ-1 (b))",
        APP,
        "        if manifest is not None and manifest_is_damaged(manifest):\n",
        "        if False:\n",
        "the rewrite helper drops the damaged-manifest check",
        [ACTIVE, "-k", "damaged_manifest_is_never"],
    ),
    "F5b-scope-mark-ignored": (
        "F5b (LLR-178.1)",
        SVC,
        "        or issue.details.get(_ISSUE_SCOPE) == _SCOPE_MANIFEST\n"
        "        for issue in manifest.issues\n",
        "        or False\n"
        "        for issue in manifest.issues\n",
        "manifest_is_damaged ignores the whole-manifest mark (a top level that is not an object)",
        [ACTIVE, "-k", "damaged_manifest_is_never and not-an-object"],
    ),
    "F2-now-opens-unconditional": (
        "F2 / SEC6-4 (LLR-168.3)",
        APP,
        "                        if self._rewrite_project_manifest(project_dir, saved):\n",
        "                        if self._rewrite_project_manifest(project_dir, saved) or True:\n",
        "the append paints 'now opens' whatever the rewrite returned",
        [ACTIVE, "-k", "now_opens_only or (damaged_manifest_is_never and variant-append)"],
    ),
    "168.3-append-no-rewrite": (
        "LLR-168.3",
        APP,
        "                        if self._rewrite_project_manifest(project_dir, saved):\n",
        "                        if False:\n",
        "the variant append no longer rewrites project.json",
        [ACTIVE, "-k", "tc_b100_20"],
    ),
    "SEC6-6-raw-active-variant": (
        "SEC6-6 (LLR-178.2)",
        APP,
        "                self.set_status(\n"
        "                    safe_text(\n"
        "                        f\"Manifest active_variant '{manifest.active_variant}' \"\n"
        "                        \"not found - activating the first variant.\"\n"
        "                    ).plain\n"
        "                )\n",
        "                self.set_status(\n"
        "                    f\"Manifest active_variant '{manifest.active_variant}' \"\n"
        "                    \"not found - activating the first variant.\"\n"
        "                )\n",
        "the recorded active_variant reaches the status log unscrubbed",
        [ANNOUNCE, "-k", "control_bytes"],
    ),
    "UX2-entry-not-named": (
        "UX-2 (LLR-178.3)",
        SVC,
        "                issue.details.get(_ISSUE_ENTRY, PROJECT_MANIFEST_NAME),\n",
        "                PROJECT_MANIFEST_NAME,\n",
        "every manifest problem row names project.json instead of its entry",
        [ANNOUNCE, "-k", "thirty"],
    ),
    "UX1-label-uncoloured": (
        "UX-1 (LLR-178.3)",
        SCREENS,
        "        text.append_text(safe_text(f\"{problem.label}: \", YELLOW))\n",
        "        text.append_text(safe_text(f\"{problem.label}: \"))\n",
        "the problem label loses the warning colour",
        [ANNOUNCE, "-k", "colour"],
    ),
    "UX1-reason-always-ok": (
        "UX-1 (LLR-178.3)",
        SCREENS,
        "                style=GREEN if announcement.latest else YELLOW,\n",
        "                style=GREEN,\n",
        "the fallback reason paints in the OK colour",
        [ANNOUNCE, "-k", "colour"],
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
               f"--basetemp={os.environ.get('TEMP', '.')}\\f1mut-{mid}", *selection]
    try:
        probe = subprocess.run(
            [PYTHON, "-c", "import s19_app; print(s19_app.__file__)"],
            cwd=worktree, env=env, capture_output=True, text=True,
        )
        result = subprocess.run(command, cwd=worktree, env=env, capture_output=True, text=True)
    finally:
        path.write_bytes(original)
    restored = sha(path) == before
    verdict = "KILLED" if result.returncode != 0 else "SURVIVED"
    lines = [
        f"# mutation: {mid} — {finding}: {description}",
        f"# file: {rel} (sha256 before {before[:16]})",
        f"# command: {' '.join(command[1:])}",
        f"# tree: {worktree} (corrective pass 1, mutated in place, then restored)",
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
    (out_dir / f"fix1-mut-{mid}.txt").write_text("\n".join(lines), encoding="utf-8")
    print(mid, verdict, "RESTORE", "OK" if restored else "FAILED")
    if not restored:
        sys.exit(2)


if __name__ == "__main__":
    tree = Path(sys.argv[1]).resolve()
    here = Path(__file__).resolve().parent
    for mutation_id in sys.argv[2:]:
        run(tree, mutation_id, here)
