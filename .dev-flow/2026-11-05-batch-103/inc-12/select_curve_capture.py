"""Select a tracked CURVE-without-length capture file by counts only."""
from __future__ import annotations

import collections
import subprocess
import sys
from pathlib import Path


def main() -> None:
    root = Path(sys.argv[1]).resolve()
    sys.path.insert(0, str(root))
    import s19_app
    from s19_app.tui.a2l import enrich_a2l_tags_with_values, parse_a2l_file

    print(s19_app.__file__)
    files = subprocess.run(
        ["git", "-C", str(root), "ls-files", "*.a2l"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    counts: collections.Counter[str] = collections.Counter()
    for rel in files:
        data = parse_a2l_file(root / rel)
        for tag in enrich_a2l_tags_with_values(data, {}):
            if (
                tag.get("char_type") == "CURVE"
                and tag.get("length") is None
                and tag.get("byte_size") is not None
            ):
                counts[rel] += 1
    for rel, count in sorted(counts.items(), key=lambda item: (-item[1], item[0])):
        print(f"{count} {rel}")
    print(f"total={sum(counts.values())} files={len(counts)}")


if __name__ == "__main__":
    main()
