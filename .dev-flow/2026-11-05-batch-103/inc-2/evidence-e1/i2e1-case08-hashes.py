"""Inc 2 E1: SHA-256 pin of the release case 08 outputs on the base tree.

Runs ``tools/synth/make_release_case.py`` of the read-only clone (stdlib only,
imports no ``s19_app``) with seed 20260001 at the two sizes the tests use
(10 MiB: the shipped case and ``tests/support/b101_demo_image.py``; 1 MiB:
``tests/test_synth_release_case.py`` and the batch-101 Inc 10/11/12 tests),
twice each into separate folders, and prints one SHA-256 per file. The second
run proves the pin is deterministic before it becomes a requirement.

Usage: python i2e1-case08-hashes.py <repo clone> <out dir>
"""
from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

SEED = 20260001
SIZES = ("10", "1")
FILES = [
    "firmware.s19",
    "firmware.hex",
    "firmware_v2.s19",
    "firmware.a2l",
    "firmware.mac",
    "demo_patch.changes.json",
    "demo_check.chk.json",
    "demo_check_fails.chk.json",
    "firmware_issues.a2l",
    "firmware_issues.mac",
    "README.txt",
]


def main(argv: list[str]) -> int:
    repo, out = Path(argv[1]), Path(argv[2])
    tool = repo / "tools" / "synth" / "make_release_case.py"
    print(f"tool: {tool}")
    print(f"tool sha256: {hashlib.sha256(tool.read_bytes()).hexdigest()}")
    digests: dict[tuple[str, str, str], str] = {}
    for size in SIZES:
        for run in ("a", "b"):
            target = out / f"size{size}-{run}"
            result = subprocess.run(
                [sys.executable, "-I", str(tool), "--out", str(target),
                 "--seed", str(SEED), "--size-mb", size],
                capture_output=True, text=True, check=True,
            )
            print(f"\n# --size-mb {size} run {run}: exit {result.returncode}")
            print(result.stdout.rstrip())
            for name in FILES:
                data = (target / name).read_bytes()
                digests[(size, run, name)] = hashlib.sha256(data).hexdigest()
    print("\n# pin: size | file | bytes | sha256 | run b equal")
    mismatches = 0
    for size in SIZES:
        for name in FILES:
            a = digests[(size, "a", name)]
            b = digests[(size, "b", name)]
            mismatches += a != b
            length = (out / f"size{size}-a" / name).stat().st_size
            print(f"{size} | {name} | {length} | {a} | {'yes' if a == b else 'NO'}")
    print(f"\nfiles pinned: {len(SIZES) * len(FILES)}; run-to-run mismatches: {mismatches}")
    return 1 if mismatches else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
