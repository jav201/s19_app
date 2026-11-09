"""Run pytest from an isolated interpreter against an explicit checkout."""
from __future__ import annotations

import sys
from pathlib import Path


def main() -> int:
    checkout = Path(sys.argv[1]).resolve()
    sys.path.insert(0, str(checkout))
    import s19_app

    print(s19_app.__file__, flush=True)
    import pytest

    return pytest.main(sys.argv[2:])


if __name__ == "__main__":
    raise SystemExit(main())
