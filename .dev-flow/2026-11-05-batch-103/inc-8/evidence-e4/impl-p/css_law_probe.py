"""impl-p probe: does the Inc 8 stylesheet satisfy test_tc_b97_flow_execution_css_section_is_scoped
once the proposed Inc 8 supersessions are added? Runs a scratch copy of the law; the repo's test is untouched.

python -B css_law_probe.py <b514b07.tcss> <with|without>
"""
from __future__ import annotations

import subprocess
import sys
import types
from pathlib import Path

OLD = Path(sys.argv[1]).read_text(encoding="utf-8")
MODE = sys.argv[2]

INC8 = '''
    # batch-103 Inc 8 (R-TUI-063.1, .3, R-PE-DEF.1.1, .2, .4, .74 - the staging sheet over LANDS IN):
    # #patch_main becomes #patch_sheet_win, the ledger loses its border, the inspector
    # becomes the 9-row landing pane, the focus rule follows the sheet, the A2L tab leaves
    # the tab-window height rule, and the filter-row / bench block is inserted at the end
    # of the patch section. (The `.ce-*` re-scope sits inside db1a8f7's inserted block.)
    old = supersede(old, INC8_REGION_BEFORE, INC8_REGION_AFTER, "Inc 8 sheet over LANDS IN")
    old = supersede(
        old,
        "#patch_editor_panel #patch_win_checks,\\n#patch_editor_panel #patch_win_a2l {\\n    height: 100%;",
        "#patch_editor_panel #patch_win_checks {\\n    height: 100%;",
        "Inc 8 #patch_win_a2l heights out",
    )
    inc8 = inserted("/* --- Filter row and bench state (batch-103 Inc 8", "#patch_editor_panel.-bench #patch_inspector", "Inc 8 block")
    old = supersede(old, "/* batch-97 flow_builder", inc8 + "/* batch-97 flow_builder", "Inc 8 anchor")
'''

INC8_REGION_BEFORE = """#patch_editor_panel #patch_main {
    height: 1fr;
    min-height: 12;
}

#patch_editor_panel #patch_win_script {
    width: 3fr;
    height: 100%;
    padding: 0;
    border: round $rule;
    border-title-color: #969aad;      /* insight_style.DGRAY */
    border-subtitle-color: #969aad;   /* insight_style.DGRAY */
}

/* The 45-cell floor keeps the pane's 41 content cells, so the execute row
 * and the strip's 8-byte rows fit at 120-133 columns too, where the rail
 * widens; the ledger then pays (its table scrolls sideways there). */
#patch_editor_panel #patch_inspector {
    width: 2fr;
    min-width: 45;
    height: 100%;
    padding: 0 1;
    border: round $rule;
    border-title-color: #969aad;      /* insight_style.DGRAY */
}

#patch_editor_panel #patch_win_script:focus-within,
"""

INC8_REGION_AFTER = """/* batch-103 Inc 8: the STAGING SHEET window takes every row the other
 * regions leave, never fewer than 12 (R-PE-DEF.1.1, .74); it scrolls with
 * the panel below that. */
#patch_editor_panel #patch_sheet_win {
    height: 1fr;
    min-height: 12;
    padding: 0;
    border: round $rule;
    border-title-color: #969aad;      /* insight_style.DGRAY */
    border-subtitle-color: #969aad;   /* insight_style.DGRAY */
}

/* batch-103 Inc 8: the ledger is the Patch script tab, with no border of
 * its own; its subtitle rides the landing pane (R-PE-041). */
#patch_editor_panel #patch_win_script {
    height: 100%;
    padding: 0;
}

/* batch-103 Inc 8: LANDS IN, the landing pane, spans the panel in 9 rows
 * (R-PE-DEF.1.1): the chips and 6 content rows inside its border. */
#patch_editor_panel #patch_inspector {
    width: 100%;
    height: 9;
    padding: 0 1;
    border: round $rule;
    border-title-color: #969aad;      /* insight_style.DGRAY */
    border-subtitle-color: #969aad;   /* insight_style.DGRAY */
}

#patch_editor_panel #patch_sheet_win:focus-within,
"""

source = Path("tests/test_b97_flow_execution.py").read_text(encoding="utf-8")
anchor = '    assert sheet.startswith(old.rstrip()), "every rule shipped at b514b07 is byte-equal; Inc-6 only appends"\n'
assert source.count(anchor) == 1
if MODE == "with":
    source = source.replace(anchor, INC8 + anchor)
module = types.ModuleType("zq_law")
module.__file__ = str(Path("tests/test_b97_flow_execution.py").resolve())
sys.path.insert(0, ".")
exec(compile(source, "zq_law", "exec"), module.__dict__)
module.INC8_REGION_BEFORE = INC8_REGION_BEFORE
module.INC8_REGION_AFTER = INC8_REGION_AFTER
if len(sys.argv) > 3:  # control: another root whose s19_app/tui/styles.tcss is read instead
    module.REPO_ROOT = Path(sys.argv[3])
real_run = subprocess.run


def fake_run(args, *a, **k):
    if args[:2] == ["git", "show"] and args[2] == "b514b07:s19_app/tui/styles.tcss":
        return subprocess.CompletedProcess(args, 0, OLD.encode("utf-8"), b"")
    return real_run(args, *a, **k)


module.subprocess.run = fake_run
try:
    module.test_tc_b97_flow_execution_css_section_is_scoped()
    print(f"LAW.{MODE} = PASS")
except AssertionError as exc:
    print(f"LAW.{MODE} = FAIL: {str(exc)[:200]}")
