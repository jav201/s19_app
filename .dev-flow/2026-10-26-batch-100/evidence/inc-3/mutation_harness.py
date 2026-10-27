"""One-off mutation harness for Inc 3 (C-40).

Usage (from the worktree root, s19env):
    python .dev-flow/2026-10-26-batch-100/evidence/inc-3/mutation_harness.py <id>

<id> is one of: m1-order, m2-reset-line, m3-domain, m4-service, m5-unload.
Applies the mutation to s19_app/tui/app.py, prints the pre-mutation
SHA-256, runs the pinned pytest selection, then restores the byte copy and
prints the post-restore SHA-256. A mutant is never left in place.
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

# Each mutation: a list of (old, new) replacements applied in order.
MUTATIONS = {
    # LLR-165.1: the reset seam moved AFTER the first install — the MAC
    # merge and the A2L fallbacks see the outgoing session.
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
        "pytest": ["tests/test_b100_session_reset.py", "-k", "tc_b100_08 or tc_b100_09_load_over"],
    },
    # LLR-165.2: one reset line dropped (current_a2l_path stays outgoing).
    "m2-reset-line": {
        "replacements": [
            (
                "        self.current_a2l_path = None\r\n"
                "        self.current_a2l_data = None\r\n"
                "        # S5: variant ids",
                "        self.current_a2l_data = None\r\n"
                "        # S5: variant ids",
            ),
        ],
        "pytest": ["tests/test_b100_session_reset.py", "-k", "tc_b100_09_load_over"],
    },
    # LLR-165.2 (set mutation): one census name dropped from the domain
    # without an exclusion.
    "m3-domain": {
        "replacements": [
            (
                '    "_last_template_path",\r\n    "_mac_first_visible_address",',
                '    "_mac_first_visible_address",',
            ),
        ],
        "pytest": ["tests/test_b100_session_reset.py", "-k", "tc_b100_09_domain"],
    },
    # LLR-165.3: the old ChangeService object is kept (no rebind).
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
        "pytest": ["tests/test_b100_session_reset.py", "-k", "tc_b100_10 or tc_b100_09_load_over"],
    },
    # LLR-165.4: no A2L clear on unload.
    "m5-unload": {
        "replacements": [
            (
                "            self.current_a2l_path = None\r\n"
                "            # LLR-165.4 (P-25): the PARSED payload is the other half of",
                "            self.current_a2l_path = None\r\n"
                "            # MUTANT: the parsed payload clear removed",
            ),
            (
                "            # MUTANT: the parsed payload clear removed\r\n"
                "            # the artifact being unloaded \u2014 it is the fallback the next\r\n"
                "            # S19/HEX/MAC parse re-attaches (`else self.current_a2l_data`\r\n"
                "            # at the parse branches), so clearing the path alone left the\r\n"
                "            # tags alive after an unload. Cleared beside the path, for\r\n"
                "            # the kinds that drop the artifact.\r\n"
                "            self.current_a2l_data = None\r\n",
                "            # MUTANT: the parsed payload clear removed\r\n",
            ),
        ],
        "pytest": ["tests/test_b100_session_reset.py", "-k", "tc_b100_11"],
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
        proc = subprocess.run(cmd, cwd=ROOT, env=ENV, capture_output=True, text=True, timeout=600)
        sys.stdout.write(proc.stdout[-6000:])
        sys.stderr.write(proc.stderr[-2000:])
        print(f"mutant run exit: {proc.returncode}")
    finally:
        APP.write_bytes(original)
    restored = APP.read_bytes()
    print(f"restored sha256: {sha256(restored)}")
    print("RESTORE OK" if restored == original else "RESTORE MISMATCH")
    return 0


if __name__ == "__main__":
    sys.exit(main())
