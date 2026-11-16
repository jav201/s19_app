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
            "--tb=short",
            "tests/test_suite_hygiene.py::test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses",
            "tests/test_requirements_canon.py::test_canon_rows_hold_the_obligation_word_once",
            "tests/test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors",
            "tests/test_b101_reach_and_reports_escape.py::test_r_shell_keys_3_1_every_action_has_a_reach",
            "tests/test_b101_reach_and_reports_escape.py::test_at_i12_2_rail_keys_and_issue_peek_after_the_aliases_go",
            "tests/test_b97_key_bar.py::test_tc_b97_72_clicks_run_the_action_and_type_nothing",
        ]
    )
)
