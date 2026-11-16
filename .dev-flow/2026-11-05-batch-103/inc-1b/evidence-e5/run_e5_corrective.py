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
            "tests/test_b103_e5_safety.py",
            "tests/test_b103_winci_gate.py",
            "tests/test_b103_clipboard_tail.py::test_e5_powershell_preserves_lf_and_emits_bom_free_readers",
            "tests/test_b103_clipboard_tail.py::test_r_tui_043_13_102_hostile_exact_payload_transport_and_logs",
            "tests/test_b103_clipboard_windows.py::test_r_paste_16_1_read_rescue_starts_system_powershell",
            "tests/test_b103_clipboard_windows.py::test_r_paste_21_5_direct_win32_call_opens_nothing_and_fails",
            "tests/test_b103_copy_quit_dialog.py::test_r_dlg_14_101_copy_quit_has_reachable_shared_opener",
        ]
    )
)
