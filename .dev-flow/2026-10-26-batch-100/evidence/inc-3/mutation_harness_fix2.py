"""One-off mutation harness for Inc 3 FIX PASS 2 (C-40).

Usage (from the worktree root, s19env):
    python .dev-flow/2026-10-26-batch-100/evidence/inc-3/mutation_harness_fix2.py <id>

<id> is one of: m7-no-buffer-clear, r8b-no-repaint. Applies the mutation
to s19_app/tui/app.py, prints the pre-mutation SHA-256, runs the FULL
tests/test_b100_session_reset.py module, then restores the byte copy and
prints the post-restore SHA-256. A mutant is never left in place.

m7 is the new mutant the fix-pass-2 brief declares for R2-1 (LED .55(b)'s
buffer clear skipped): the AT's paste-buffer assertions must go RED.
r8b is the reviewer's round-2 mutant for R2-2 (the seam's refresh_entries
repaint deleted): it SURVIVES, recorded in the packet as an EQUIVALENT
mutant — the install's deferred chain repaints the ledger anyway, so the
AT's ledger check pins HLR-165's observable, not LLR-165.1's repaint.
"""
from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
APP = ROOT / "s19_app" / "tui" / "app.py"
PY = r"C:/Users/jjgh8/anaconda3/envs/s19env/python.exe"
ENV = {
    "PYTHONUTF8": "1",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONIOENCODING": "utf-8",
    "PYTHONPATH": str(ROOT),
    "PATH": r"C:\Windows\system32;C:\Windows;C:\Program Files\Git\bin;C:\Users\jjgh8\anaconda3\envs\s19env;C:\Users\jjgh8\anaconda3\envs\s19env\Scripts",
    "SYSTEMROOT": r"C:\Windows",
}

FULL = ["tests/test_b100_session_reset.py"]

MUTATIONS = {
    # R2-1 / LED .55(b): the paste-buffer clear skipped — the buffer keeps
    # P1's draft into P2's session, so the AT's buffer-empty wait dies.
    "m7-no-buffer-clear": {
        "replacements": [
            (
                '            self.query_one("#patch_paste_text", TextArea).text = ""\r\n'
                "            self.call_after_refresh(panel.mark_loaded)",
                "            self.call_after_refresh(panel.mark_loaded)",
            ),
        ],
        "pytest": FULL,
    },
    # R2-2: the reviewer's R8b — the seam's refresh_entries repaint
    # deleted. EQUIVALENT mutant: the suite stays green because the
    # install's deferred chain repaints the ledger anyway.
    "r8b-no-repaint": {
        "replacements": [
            (
                "            panel.refresh_entries(\r\n"
                "                self._change_service.rows(None),\r\n"
                "                mem_map=self._strip_source_map(None),\r\n"
                "                document=self._patch_document_view(),\r\n"
                "            )\r\n",
                "",
            ),
        ],
        "pytest": FULL,
    },
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    mutation_id = sys.argv[1]
    spec = MUTATIONS[mutation_id]
    original = APP.read_bytes()
    print(f"pre-mutation sha256: {sha256(original)}")
    try:
        text = original.decode("utf-8")
        for old, new in spec["replacements"]:
            assert text.count(old) == 1, (
                f"mutation anchor not unique/found ({text.count(old)}): {old[:70]!r}"
            )
            text = text.replace(old, new, 1)
        APP.write_bytes(text.encode("utf-8"))
        print(f"mutant sha256: {sha256(APP.read_bytes())}")
        cmd = [PY, "-m", "pytest", "-q", "-p", "no:cacheprovider", *spec["pytest"]]
        print("cmd:", " ".join(cmd))
        proc = subprocess.run(cmd, cwd=ROOT, env=ENV, capture_output=True, timeout=900)
        sys.stdout.write(proc.stdout.decode("utf-8", errors="replace")[-6000:])
        sys.stderr.write(proc.stderr.decode("utf-8", errors="replace")[-2000:])
        print(f"mutant run exit: {proc.returncode}")
    finally:
        APP.write_bytes(original)
    restored = APP.read_bytes()
    print(f"restored sha256: {sha256(restored)}")
    print("RESTORE OK" if restored == original else "RESTORE MISMATCH")
    return 0


if __name__ == "__main__":
    sys.exit(main())
