"""List synthetic case-08 page-2 tags that retain decoded values."""
from __future__ import annotations

import sys
from pathlib import Path


def main() -> None:
    root = Path(sys.argv[1]).resolve()
    case = Path(sys.argv[2]).resolve()
    sys.path.insert(0, str(root))
    import s19_app
    from s19_app.core import S19File
    from s19_app.tui.a2l import enrich_a2l_tags_with_values, parse_a2l_file

    print(s19_app.__file__)
    mem = S19File(str(case / "firmware.s19")).get_memory_map()
    tags = enrich_a2l_tags_with_values(parse_a2l_file(case / "firmware.a2l"), mem)
    for index, tag in enumerate(tags[200:260], start=200):
        if tag.get("length") is not None and tag.get("raw_value") is not None:
            print(index, tag.get("name"), tag.get("address"), tag.get("length"), tag.get("raw_value"), tag.get("physical_value"))


if __name__ == "__main__":
    main()
