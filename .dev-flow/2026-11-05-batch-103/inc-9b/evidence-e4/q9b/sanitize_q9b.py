from __future__ import annotations

import os
import sys
from pathlib import Path


def main() -> int:
    root = Path(sys.argv[1])
    account = os.environ["USER"].encode()
    changed = 0
    for path in sorted(root.glob("*.txt")):
        data = path.read_bytes()
        clean = data.replace(account, b"<user>")
        if clean != data:
            path.write_bytes(clean)
            changed += 1
    print(f"sanitized_account_occurrences_files={changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
