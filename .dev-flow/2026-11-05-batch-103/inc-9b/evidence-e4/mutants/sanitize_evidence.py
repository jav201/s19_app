"""Reapply the M9b byte sanitizer and verify host-specific tokens are absent."""

import os
from pathlib import Path
import socket
import sys

sys.dont_write_bytecode = True
ROOT = Path.home() / "work" / "zq-m9b"
sys.path.insert(0, str(ROOT))
import m9b_driver as driver  # noqa: E402


def main():
    files = [path for path in sorted(driver.OUT.iterdir()) if path.is_file()]
    for path in files:
        driver.write_text(path, path.read_text(encoding="utf-8"))
    needles = (Path.home().name, os.environ["RUNNER_HOME_NAME"], socket.gethostname())
    hits = sum(
        sum(path.read_text(encoding="utf-8").count(needle) for needle in needles)
        for path in files
    )
    report = driver.OUT / "sanitization.txt"
    report.write_text(
        f"FILES_SCANNED {len(files)}\nPRIVATE_TOKEN_HITS {hits}\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"FILES_SCANNED {len(files)}")
    print(f"PRIVATE_TOKEN_HITS {hits}")
    return 1 if hits else 0


if __name__ == "__main__":
    raise SystemExit(main())
