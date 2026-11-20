from __future__ import annotations

import hashlib
from pathlib import Path
import sys
import traceback

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
from redaction import redact

ROOT = Path(__file__).resolve().parents[4]


def main() -> None:
    import s19_app
    from s19_app.tui.a2l import parse_a2l_file

    path = ROOT / "examples" / "case_06_large_nested_a2l" / "firmware.a2l"
    package = Path(s19_app.__file__).resolve()
    print(f"s19_app.__file__={redact(str(package), ROOT)}")
    print(f"path={redact(str(path.resolve()), ROOT)}")
    print(f"size_bytes={path.stat().st_size}")
    print(f"sha256={hashlib.sha256(path.read_bytes()).hexdigest()}")
    data = parse_a2l_file(path)
    print(f"tags={len(data['tags'])}")
    print(f"distinct_names={len({tag.get('name') for tag in data['tags']})}")
    print(f"errors={len(data.get('errors', []))}")
    print(f"first_name={data['tags'][0].get('name')}")
    print(f"last_name={data['tags'][-1].get('name')}")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print(redact(traceback.format_exc(), ROOT), end="")
        raise SystemExit(1)
