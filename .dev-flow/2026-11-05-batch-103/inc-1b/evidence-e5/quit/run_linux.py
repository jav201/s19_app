from __future__ import annotations

import runpy
import sys
from pathlib import Path

sys.path.insert(0, str(Path.cwd()))
import s19_app

print(f"s19_app.__file__ = {s19_app.__file__}", flush=True)

if len(sys.argv) != 2 or sys.argv[1] not in {"audit", "pytest"}:
    raise SystemExit("usage: run_linux.py audit|pytest")

if sys.argv[1] == "audit":
    sys.argv = ["validate_routes.py", "tests/test_b103_copy_quit_dialog.py"]
    runpy.run_path(str(Path.cwd().parent / "validate_routes.py"), run_name="__main__")
else:
    import pytest

    raise SystemExit(
        pytest.main(
            [
                "-p",
                "no:cacheprovider",
                "-vv",
                "--tb=short",
                "--durations=0",
                "tests/test_b103_copy_quit_dialog.py",
            ]
        )
    )
