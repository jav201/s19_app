#!/bin/bash
P=/mnt/c/Users/jjgh8/AppData/Local/Temp/claude/C--Users-jjgh8-clde/a8feab43-c248-4ccb-86cf-122b894659b2/scratchpad/fix3
cd ~/s19fix3; unset NO_COLOR; export PYTHONDONTWRITEBYTECODE=1
echo "== M-dwell: render_run without the restart arm"
~/s19venv/bin/python $P/mutate.py s19_app/tui/flow_screens.py "        self._rearm_attention(restart=True)" "        self._rearm_attention()"
timeout 600 ~/s19venv/bin/python -m pytest -q -p no:cacheprovider tests/test_b97_flow_execution.py::test_tc_b97_64_a_new_set_run_restarts_the_dwell 2>&1 | grep -E "^E |passed|failed" | head -4
bash $P/sync.sh s19_app/tui/flow_screens.py
echo "== M-quit: a confirmed quit exits at once"
~/s19venv/bin/python $P/mutate.py s19_app/tui/app.py "        self._quit_pending = bool(quit)
        self._exit_if_quit_pending()" "        self._quit_pending = bool(quit)
        if quit:
            self.exit()"
timeout 900 ~/s19venv/bin/python -m pytest -q -p no:cacheprovider tests/test_b100_workers.py::test_at_b100_18_quit_confirm_half_slow_save_as_leaves_no_partial_folder 2>&1 | grep -E "^E |passed|failed" | head -4
bash $P/sync.sh s19_app/tui/app.py
echo "== M-size: the parser's total off by one"
grep -n "progress(" s19_app/tui/a2l.py | head -5
