"""One-off mutation harness for Inc 3 FIX PASS 1 (C-40).

Usage (from the worktree root, s19env):
    python .dev-flow/2026-10-26-batch-100/evidence/inc-3/mutation_harness_fix1.py <id>

<id> is one of: r6-drop-s7-s11, r10-no-key-normaliser, m6-notice-after-rebind,
m4-service, m1-order. Applies the mutation to s19_app/tui/app.py, prints the
pre-mutation SHA-256, runs the FULL tests/test_b100_session_reset.py module,
then restores the byte copy and prints the post-restore SHA-256. A mutant is
never left in place. r6/r10 are the reviewer's own mutants re-run under the
F1-seeded suite; m6 is the new notice-count mutant (reviewer F4).
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
    # The reviewer's R6 (finding F1): the 7 reset lines of S7-S11 deleted.
    # Under the F1-seeded suite this must go RED (round 1 it survived).
    "r6-drop-s7-s11": {
        "replacements": [
            (
                '        self._last_template_path = None\r\n'
                '        # S8: the last comparison and check spec.\r\n'
                '        self._diff_last_result = None\r\n'
                '        self._diff_check_spec = None\r\n'
                '        self._diff_check_spec_name = ""\r\n'
                '        # S9/S10: the last flow run and execution.\r\n'
                '        self._last_flow_run = None\r\n'
                '        self._last_execution = None\r\n'
                '        # S11: the sticky report-filter selection.\r\n'
                '        self._report_filter_path = None\r\n',
                '        # S8: the last comparison and check spec.\r\n'
                '        # S9/S10: the last flow run and execution.\r\n'
                '        # S11: the sticky report-filter selection.\r\n',
            ),
        ],
        "pytest": FULL,
    },
    # The reviewer's R10: LLR-165.2's third negative control — the three
    # keyed-cache reductions bypassed (recorded for finding F7).
    "r10-no-key-normaliser": {
        "replacements": [
            (
                '            if name == "_mac_view_cache_key":',
                '            if False:',
            ),
            (
                '            elif name == "_a2l_cache_key":',
                '            elif False:',
            ),
            (
                '            elif name == "_a2l_enriched_key":',
                '            elif False:',
            ),
        ],
        "pytest": FULL,
    },
    # Finding F4: the notice count read AFTER the rebind — the new service
    # holds 0 entries, so no line is painted and both notice arms must die.
    "m6-notice-after-rebind": {
        "replacements": [
            (
                "        discarded_unsaved = len(self._change_service.document.entries)\r\n"
                "        # S1: the loaded image",
                "        # S1: the loaded image",
            ),
            (
                "        self._change_service.set_image_generation(self._image_generation)\r\n"
                "        # Repaint the Patch panel through refresh_entries",
                "        self._change_service.set_image_generation(self._image_generation)\r\n"
                "        discarded_unsaved = len(self._change_service.document.entries)\r\n"
                "        # Repaint the Patch panel through refresh_entries",
            ),
        ],
        "pytest": FULL,
    },
    # LLR-165.3: the old ChangeService object is kept (no rebind) — the
    # full-module re-run the corrected m4 record needs (reviewer F4).
    "m4-service": {
        "replacements": [
            (
                "        self._change_service = ChangeService()\r\n"
                "        self._change_service.set_image_generation(self._image_generation)\r\n"
                "        # Repaint the Patch panel through refresh_entries",
                "        self._change_service.set_image_generation(self._image_generation)\r\n"
                "        # Repaint the Patch panel through refresh_entries",
            ),
        ],
        "pytest": FULL,
    },
    # LLR-165.1: the reset seam moved AFTER the first install — full-module
    # re-run so the AT kills the round-1 record omitted are evidenced (F4).
    "m1-order": {
        "replacements": [
            (
                "        discarded_unsaved = self._reset_project_session()\r\n"
                "        # Multi-variant model",
                "        # Multi-variant model",
            ),
            (
                "        self.load_selected_file(selected_file, a2l_files)\r\n"
                "        if primary_file and mac_file:",
                "        self.load_selected_file(selected_file, a2l_files)\r\n"
                "        discarded_unsaved = self._reset_project_session()\r\n"
                "        if primary_file and mac_file:",
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
