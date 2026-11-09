"""Select an image-backed CURVE-without-length capture by counts only."""
from __future__ import annotations

import collections
import subprocess
import sys
from pathlib import Path


def main() -> None:
    root = Path(sys.argv[1]).resolve()
    sys.path.insert(0, str(root))
    import s19_app
    from s19_app.core import S19File
    from s19_app.tui.a2l import (
        _extract_raw_bytes,
        enrich_a2l_tags_with_values,
        parse_a2l_file,
    )

    print(s19_app.__file__)
    mem_map = S19File(str(root / "examples" / "case_00_public" / "prg.s19")).get_memory_map()
    files = subprocess.run(
        ["git", "-C", str(root), "ls-files", "*.a2l"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    totals: collections.Counter[str] = collections.Counter()
    backed: collections.Counter[str] = collections.Counter()
    first_rows: dict[str, int] = {}
    for rel in files:
        data = parse_a2l_file(root / rel)
        for index, tag in enumerate(enrich_a2l_tags_with_values(data, {})):
            if (
                tag.get("char_type") != "CURVE"
                or tag.get("length") is not None
                or tag.get("byte_size") is None
            ):
                continue
            totals[rel] += 1
            raw = _extract_raw_bytes(mem_map, tag.get("address"), tag.get("byte_size"))
            if raw["raw_available"]:
                backed[rel] += 1
                first_rows.setdefault(rel, index)
    for rel in sorted(totals, key=lambda item: (-backed[item], item)):
        print(f"backed={backed[rel]} population={totals[rel]} file={rel}")
    if backed:
        selected = max(backed, key=lambda rel: (backed[rel], rel))
        print(
            f"selected={selected} backed={backed[selected]} "
            f"row={first_rows[selected]} total_population={sum(totals.values())}"
        )
    else:
        print("selected=none")


if __name__ == "__main__":
    main()
