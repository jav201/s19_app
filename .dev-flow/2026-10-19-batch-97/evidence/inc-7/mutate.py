"""Inc-7 mutation battery (batch-97: the width sweep and the Inc-8 leftovers).

Each mutant is ONE textual edit of a source file (or, for the two instrument
mutants, of the snapshot harness); the anchor must occur exactly once and the
edit is asserted applied. The named test nodes run against the mutant; a
non-zero pytest exit is KILLED. Every file is restored and its SHA-256
re-checked against the GREEN digest before the next mutant.

    python mutate.py <tree>            # all mutants
    python mutate.py <tree> M3 M7      # a subset
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path

PY = r"C:\Users\jjgh8\anaconda3\envs\s19env\python.exe"
KB = "tests/test_b97_key_bar.py::"
WD = "tests/test_b97_width.py::"
SPLIT = "tests/test_segment_split_window.py::test_export_cues_name_the_bound_export_key"
HELP = "tests/test_window_usage_help.py::test_help_modal_fits_and_every_line_is_reachable_by_key"
HELP_SCROLL = "tests/test_window_usage_help.py::test_help_modal_scrolls_by_key_while_close_keeps_the_focus"
HELP_LABEL = "tests/test_window_usage_help.py::test_help_modal_close_names_its_key_and_the_keys_block_stands_apart"
HARNESS ="tests/test_tui_snapshot.py::test_tc016s_harness_paints_the_a2l_context_itself"
AT15 = WD + "test_at_b97_15_four_screens_with_the_widest_values"
AT16 = WD + "test_at_b97_16_in_session_resize_grows_and_returns"
AT24 = WD + "test_at_b97_24_breakpoint_and_below_the_range_by_key"
HEIGHT = KB + "test_tc_b97_69_diff_keys_follow_a_height_only_regime_switch"

WH = "s19_app/tui/window_help.py"
CSS = "s19_app/tui/styles.tcss"
SDB = "s19_app/tui/screens_directionb.py"
SJV = "s19_app/tui/segment_split_view.py"
FS = "s19_app/tui/flow_screens.py"
SNAP = "tests/test_tui_snapshot.py"

MUTANTS = [
    # ---- the Inc-7 behaviour changes ----
    ("M1", "no refresh_bindings on a Diff regime switch", SDB,
     "        if regime != previous:\n            # batch-97 Inc-7",
     "        if False:\n            # batch-97 Inc-7",
     [HEIGHT]),
    ("M2", "the EXPORT button names ^E again", SJV,
     'yield Button("EXPORT  e", id="sje_export")', 'yield Button("EXPORT  ^E", id="sje_export")', [SPLIT]),
    ("M3", "the ready cue names ^E again", SJV,
     't.append("ready — e exports", style=S_DIM)', 't.append("ready — ^E exports", style=S_DIM)', [SPLIT]),
    ("M4", "the arming toast names ^E again", SJV,
     '" — press e again to confirm"', '" — press ^E again to confirm"', [SPLIT]),
    ("M5", "the help body unwrapped from its scroll container", WH,
     '            VerticalScroll(*body, id="window_help_scroll"),', "            *body,", [HELP]),
    # M6 (first battery: the dialog's own `max-height: 100%`) SURVIVED: the
    # ModalScreen already bounds the dialog (measured, same geometry with the
    # rule removed), so the rule was dropped; M6b mutates the cap that acts.
    ("M6b", "the help scroll not capped (it grows to its content)", CSS,
     "#window_help_scroll {\n    height: auto;\n    max-height: 100%;\n}", "#window_help_scroll {\n    height: auto;\n}", [HELP]),
    ("M7", "the help title not docked (the scroll's 100% cap runs under Close)", CSS,
     "#window_help_dialog .modal-title {\n    dock: top;\n}", "#window_help_dialog .modal-title {\n    margin-bottom: 1;\n}", [HELP]),
    # ---- fix round (ux UX-F1, UX-F3, UX-F4) ----
    ("M17", "the help screen's scroll bindings removed (keys dead until a tab)", WH,
     '        Binding("up", "scroll_help(\'scroll_up\')", "Scroll up", show=False),\n'
     '        Binding("down", "scroll_help(\'scroll_down\')", "Scroll down", show=False),\n'
     '        Binding("pageup", "scroll_help(\'page_up\')", "Page up", show=False),\n'
     '        Binding("pagedown", "scroll_help(\'page_down\')", "Page down", show=False),\n'
     '        Binding("home", "scroll_help(\'scroll_home\')", "Top", show=False),\n'
     '        Binding("end", "scroll_help(\'scroll_end\')", "Bottom", show=False),\n',
     "", [HELP_SCROLL, HELP]),
    ("M18", "Close no longer shows its key", WH,
     '"Close  esc",', '"Close",', [HELP_LABEL]),
    ("M19", "the keys block sits directly under the last step", CSS,
     "#window_help_keys {\n    margin-top: 1;\n}", "#window_help_keys {\n    margin-top: 0;\n}", [HELP_LABEL]),
    # ---- instrument (the snapshot harness, test code) ----
    ("M8", "the harness drops its update_project_labels (the PC-10 race back)", SNAP,
     "    # callback ran before this install (the long-run cell drift).\n    app.update_project_labels()",
     "    # callback ran before this install (the long-run cell drift).\n    pass",
     [HARNESS]),
    # ---- AT-B97-15 / -16 / -24 over the shipped Inc-3..6 behaviour ----
    ("M9", "a parameter name left unclipped (Textual's hard clip, no …)", SDB,
     "    if cell_len(name) <= width:\n        return name\n    first = name.split",
     "    if True:\n        return name\n    first = name.split",
     [AT15]),
    ("M10", "the Parameter column fixed (not derived from the width)", SDB,
     "    param = max(8, usable - 19 - fmt)", "    param = 30", [AT16]),
    ("M11", "Builder cards fixed at 24 cells", FS,
     "    card_w = room // n_cards", "    card_w = 24", [AT16]),
    ("M12", "lane cards laid out for a fixed 96-cell viewport", FS,
     "card_w, spare = pipeline_layout(viewport_w - CONFIRM_RESERVE, max(1, n_max))",
     "card_w, spare = pipeline_layout(96 - CONFIRM_RESERVE, max(1, n_max))", [AT16]),
    ("M13", "the Check Editor panel does not scroll (overflow hidden)", CSS,
     "#check_editor_panel {\n    width: 100%;\n    height: 1fr;\n    padding: 0;\n    overflow-x: hidden;\n    overflow-y: auto;",
     "#check_editor_panel {\n    width: 100%;\n    height: 1fr;\n    padding: 0;\n    overflow-x: hidden;\n    overflow-y: hidden;",
     [AT24]),
    ("M14", "the Patch Editor panel does not scroll (overflow hidden)", CSS,
     "#patch_editor_panel {\n    width: 100%;\n    height: 1fr;\n    padding: 0;\n    layout: vertical;\n    overflow-x: hidden;\n    overflow-y: auto;",
     "#patch_editor_panel {\n    width: 100%;\n    height: 1fr;\n    padding: 0;\n    layout: vertical;\n    overflow-x: hidden;\n    overflow-y: hidden;",
     [AT24]),
    ("M15", "a no-wrap hint allowed to wrap", CSS,
     "#check_editor_panel .ce-hint {\n    text-wrap: nowrap;", "#check_editor_panel .ce-hint {\n    text-wrap: wrap;",
     [AT15]),
    ("M16", "the Flow Execution ribbon fixed at 300 cells (overflow)", CSS,
     "#fx_panel #fx_ribbon {\n    height: 1;", "#fx_panel #fx_ribbon {\n    width: 300;\n    height: 1;",
     [AT15, AT24]),
]


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    tree = Path(sys.argv[1]).resolve()
    wanted = set(sys.argv[2:])
    files = {rel: tree / rel for rel in (WH, CSS, SDB, SJV, FS, SNAP)}
    green = {rel: sha(p) for rel, p in files.items()}
    print("GREEN digests:", {rel: d[:16] for rel, d in green.items()})
    env = dict(os.environ, PYTHONUTF8="1", PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8")
    env.pop("NO_COLOR", None)
    tally = {"KILLED": 0, "SURVIVED": 0, "BAD": 0}
    for mid, what, rel, old, new, nodes in MUTANTS:
        if wanted and mid not in wanted:
            continue
        path = files[rel]
        original = path.read_bytes()
        text = original.decode("utf-8")
        if "\r\n" in text:
            old = old.replace("\r\n", "\n").replace("\n", "\r\n")
            new = new.replace("\r\n", "\n").replace("\n", "\r\n")
        if text.count(old) != 1:
            print(f"{mid} BAD anchor count {text.count(old)} — {what}", flush=True)
            tally["BAD"] += 1
            continue
        mutated = text.replace(old, new)
        assert mutated != text
        path.write_bytes(mutated.encode("utf-8"))
        try:
            for node in nodes:
                proc = subprocess.run(
                    [PY, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", "--tb=line", node],
                    cwd=tree, env=env, capture_output=True, text=True, encoding="utf-8",
                )
                last = [line for line in proc.stdout.splitlines() if line.strip()][-1:] or ["?"]
                verdict = "KILLED" if proc.returncode != 0 else "SURVIVED"
                tally[verdict] += 1
                reason = next((l for l in proc.stdout.splitlines() if "Error" in l or "assert" in l), "")
                print(f"{mid} {verdict} {node.split('::')[-1]} | {last[0]} | {reason[-200:]} — {what}", flush=True)
        finally:
            path.write_bytes(original)
            assert sha(path) == green[rel], f"{mid}: restore failed"
    print("RESTORED digests:", {rel: sha(p)[:16] for rel, p in files.items()})
    print("TALLY", tally)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
