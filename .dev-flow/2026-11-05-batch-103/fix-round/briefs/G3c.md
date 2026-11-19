# Unit G3c — R-SHELL-KEYS.3/1 control and the selector census (R2-F8)
Fixed diagnosis:
1. `tests/test_b101_reach_and_reports_escape.py::test_r_shell_keys_3_1_every_action_has_a_reach`: its own negative-control mutant `PlainCard.action_copy` is no longer reported (probable cause: the action moved or was renamed in batch-103 — find where `action_copy` lives now and re-pin the control so the mutant is reported again).
2. `tests/test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors` is red because batch-103's own tests assemble selectors (`tests/test_b103_a2l_refresh.py:218,282`, `tests/test_b103_picker_model.py:94,186`): rewrite those lines to the census-conform form (read the rule in `tests/test_address_census.py`; do NOT edit the census).
Files you may edit: `tests/test_b101_reach_and_reports_escape.py`, `tests/test_b103_a2l_refresh.py`, `tests/test_b103_picker_model.py`.
Negative controls: (1) remove that action's reach in a scratch copy → RED; (2) show the census RED on the unmodified files (`git show HEAD:<file>` into the scratch copy) and GREEN on yours.
Nodes: `tests/test_b101_reach_and_reports_escape.py::test_r_shell_keys_3_1_every_action_has_a_reach` (`-n 0`), `tests/test_address_census.py` (whole, `-n 0`), then `tests/test_b103_a2l_refresh.py` and `tests/test_b103_picker_model.py` (`-n 4`).
