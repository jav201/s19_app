import sys
from pathlib import Path

sys.path.insert(0, str(Path.cwd()))
import s19_app

print(s19_app.__file__, flush=True)

import pytest

raise SystemExit(
    pytest.main(
        [
            "-q",
            "-p",
            "no:cacheprovider",
            "tests/test_b103_clipboard_tail.py::test_e5_powershell_preserves_lf_and_emits_bom_free_readers",
        ]
    )
)
