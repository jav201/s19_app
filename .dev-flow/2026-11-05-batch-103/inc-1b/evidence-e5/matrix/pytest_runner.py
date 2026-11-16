from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path.cwd()))

import s19_app
import textual

print(f"s19_app.__file__ = {s19_app.__file__}", flush=True)
print(f"textual.__version__ = {textual.__version__}", flush=True)
assert textual.__version__ == "8.2.8", textual.__version__

import pytest

raise SystemExit(pytest.main(sys.argv[1:]))
