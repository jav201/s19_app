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
            "--junitxml=.dev-flow/2026-11-05-batch-103/inc-1b/evidence-e5/final-targeted-junit.xml",
            "tests/test_b103_e5_safety.py",
            "tests/test_b103_winci_gate.py",
            "tests/test_b102_clipboard.py",
            "tests/test_loadfilescreen_input.py::test_powershell_layer_does_not_require_wt_or_windows_terminal",
            "tests/test_b103_clipboard_core.py::test_r_paste_20_1_windows_workflow_runs_os_clipboard_tests",
            "tests/test_suite_hygiene.py::test_r_tst_002_every_timing_arm_carries_serial_timing",
            "tests/test_suite_hygiene.py::test_r_tst_040_041_every_upper_timing_bound_is_reported",
            "tests/test_id_registry.py::test_tc607_scanned_corpus_matches_the_declared_bound",
            "tests/test_b103_clipboard_tail.py::test_e5_powershell_preserves_lf_and_emits_bom_free_readers",
            "tests/test_b103_clipboard_tail.py::test_r_tui_043_13_102_hostile_exact_payload_transport_and_logs",
            "tests/test_b103_clipboard_windows.py::test_r_paste_16_1_read_rescue_starts_system_powershell",
            "tests/test_b103_clipboard_windows.py::test_r_paste_21_5_direct_win32_call_opens_nothing_and_fails",
            "tests/test_b103_copy_quit_dialog.py::test_r_dlg_14_101_copy_quit_has_reachable_shared_opener",
            "tests/test_b97_key_bar.py::test_tc_b97_72_clicks_run_the_action_and_type_nothing",
        ]
    )
)
