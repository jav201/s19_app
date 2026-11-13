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
            "tests/test_b103_copy_views.py",
            "tests/test_b103_clipboard_tail.py",
            "tests/test_b103_copy_quit_dialog.py",
            "tests/test_b103_copy_paste_matrix.py",
        ]
    )
)
