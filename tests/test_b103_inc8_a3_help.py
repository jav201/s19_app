"""Batch-103 Inc 8, group A: the Patch Editor's help section (R-PE-DEF.83 ... .87; E4, tester ``test-a``).

Design under test: ``inc-8/01-requirements.md`` rows R-PE-DEF.83 ... .87 and node ``WINDOW_HELP_SECTIONS["patch"]``
of ``codewire/graph-inc8.md``. Cases: ``inc-8/02-test-cases-A.md``.

The help body is read the way TC-B97-32 reads it (``tests/test_b97_chips_help.py::_help_lines``): the section's
numbered steps, split at `` — `` into ``label — effect``. The section is pure data
(``s19_app.tui.window_help.section_body_text``), so no app is needed and every test here runs on base:
RED on base ``d5d48685`` is the point of these tests.
"""
from __future__ import annotations

from s19_app.tui.window_help import WINDOW_HELP_SECTIONS, section_body_text

REGIONS = ("filter row", "STAGING SHEET", "LANDS IN")
TABS = ("Patch script", "Inspector", "JSON", "Checks")
STALE_PHRASES = ("A2L tab", "A2L PARAMETERS", "on the left", "on the right")


def help_lines(body: str) -> dict:
    """``label -> effect`` of every ``label — effect`` line (the parser of TC-B97-32)."""
    lines = {}
    for raw in body.split("\n"):
        text = raw.strip()
        text = text.split(". ", 1)[1] if text[:1].isdigit() and ". " in text else text
        if " — " in text:
            label, effect = text.split(" — ", 1)
            lines[label.strip()] = effect.strip()
    return lines


def patch_lines() -> dict:
    return help_lines(section_body_text("patch"))


def step_one() -> str:
    steps = WINDOW_HELP_SECTIONS["patch"]["steps"]
    return steps[0]


def test_r_pe_def_83_1_step_one_names_the_regions_and_four_tabs():
    first = step_one()
    missing = [word for word in REGIONS + TABS if word not in first]
    assert not missing, f"step 1 does not name {missing}: {first!r}"


def test_r_pe_def_83_2_no_step_names_the_a2l_tab_or_a_side():
    body = section_body_text("patch")
    found = [phrase for phrase in STALE_PHRASES if phrase in body]
    assert not found, f"the help still names {found}"
    # the A2L tab leaves with R-TUI-063.3: no `A2L — …` tab line either
    assert "A2L" not in patch_lines(), "a help line still describes an A2L tab"


def test_r_pe_def_84_1_patch_script_line_names_entries():
    lines = patch_lines()
    assert "Patch script" in lines, sorted(lines)
    assert lines["Patch script"], "the Patch script line has no effect"
    assert "entries" in lines["Patch script"]


def test_r_pe_def_85_1_staging_sheet_line_names_the_keys():
    lines = patch_lines()
    assert "STAGING SHEET" in lines, sorted(lines)
    effect = lines["STAGING SHEET"]
    for word in ("↑↓", "←→"):
        assert word in effect, (word, effect)
    # Inc 8b (R-PE-DEF.85, changed at E1): Home and End scroll the grid, which is wider than the view at 118 columns.
    for word in ("home", "end"):
        assert word in effect.lower(), (word, effect)
    for word in ("enter", "esc"):
        assert word in effect.lower(), (word, effect)


def _formula_label_line(label: str):
    lines = patch_lines()
    assert label in lines, f"no `{label} — …` line: {sorted(lines)}"
    assert "enter" in lines[label].lower(), lines[label]


def test_r_pe_def_86_1_new_label_line():
    _formula_label_line("new =")


def test_r_pe_def_86_2_field_label_line():
    _formula_label_line("field =")


def test_r_pe_def_86_3_text_label_line():
    _formula_label_line("text =")


def test_r_pe_def_87_1_use_parameter_uses_the_selected_row():
    lines = patch_lines()
    assert "Use parameter" in lines, sorted(lines)
    effect = lines["Use parameter"]
    assert "Inspector" in effect and "selected row" in effect, effect
    assert "A2L tab" not in effect, effect


def test_control_the_parser_sees_a_missing_line_and_a_stale_phrase():
    """Negative control (runs on any tree): the checks above are not vacuous. A body without the new lines
    gives no ``STAGING SHEET`` label, and a stale step is caught by the phrase list."""
    stale = help_lines("1. Edit — the PATCH SCRIPT ledger on the left lists its entries.\n\n2. A2L — lists parameters.")
    assert "STAGING SHEET" not in stale and "new =" not in stale and "A2L" in stale
    assert any(phrase in "the ledger on the left" for phrase in STALE_PHRASES)
