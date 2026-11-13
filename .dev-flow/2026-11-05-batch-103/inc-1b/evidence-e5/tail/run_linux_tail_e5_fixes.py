import hashlib
import platform
import sys
from pathlib import Path

sys.path.insert(0, str(Path.cwd()))
import s19_app

print(s19_app.__file__, flush=True)
print(f"platform={sys.platform} python={platform.python_version()}", flush=True)
for name in ("tests/test_b103_clipboard_tail.py", "tests/support/b103_clipboard.py"):
    digest = hashlib.sha256(Path(name).read_bytes()).hexdigest()
    print(f"sha256 {name} {digest}", flush=True)

import pytest
import textual

print(f"pytest={pytest.__version__} textual={textual.__version__}", flush=True)
raise SystemExit(
    pytest.main(
        [
            "-q",
            "-rs",
            "-p",
            "no:cacheprovider",
            "--deselect=tests/test_b103_clipboard_tail.py::test_e5_powershell_preserves_lf_and_emits_bom_free_readers",
            "tests/test_b103_clipboard_tail.py",
        ]
    )
)
