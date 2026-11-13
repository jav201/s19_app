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
            "tests/test_engine_unchanged.py",
            "tests/test_tui_directionb.py",
            "tests/test_suite_hygiene.py",
            "tests/test_requirements_canon.py",
            "tests/test_id_registry.py",
            "tests/test_address_census.py",
            "tests/test_filename_markup_safety.py",
            "tests/test_report_markup_safety.py",
            "tests/test_b101_reach_and_reports_escape.py",
            "tests/test_b97_key_bar.py",
            "tests/test_tui_patch_json.py",
            "tests/test_b102_clipboard.py",
            "tests/test_b103_clipboard_core.py",
            "tests/test_loadfilescreen_input.py",
        ]
    )
)
