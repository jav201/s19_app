"""H-13 law mutants (TC-MOD-7L).  Usage: nc_law_mut.py <tree> <row>.  Every touched file gets a NEW inode (unlink first)."""
import os
import re
import sys
from pathlib import Path

tree, row = Path(sys.argv[1]), sys.argv[2]
T = tree / "s19_app/tui"
APP = T / "app"


def rd(p):
    return Path(p).read_text(encoding="utf-8")


def wr(p, text):
    p = Path(p)
    if p.exists():
        os.unlink(p)
    p.write_text(text, encoding="utf-8", newline="\n")


def append(p, text):
    wr(p, rd(p).rstrip("\n") + "\n\n\n" + text)


def sub1(p, old, new):
    t = rd(p)
    assert t.count(old) == 1, (str(p), old, t.count(old))
    wr(p, t.replace(old, new))


def r1():   # a 2-arg parse_a2l_file call in a services file
    append(T / "services/flow_execution_service.py", "def _nc_two_arg(a2l_path):\n    return parse_a2l_file(a2l_path, None)\n")


def r10():  # a byte-identity comparison in another mixin
    append(APP / "navigation.py", "def _nc_byte_identity(a, b):\n    return a.read_bytes() == b.read_bytes()\n")


def r15():  # a second caller of _reset_project_session in another file
    append(APP / "a2l_view.py", "def _nc_second_caller(self):\n    self._reset_project_session()\n")


def r20():  # a private _dirty read outside the panel
    append(T / "color_policy.py", "def _nc_panel_dirty(panel):\n    return panel._dirty\n")


def r32():  # an unlink in an unlisted function
    append(T / "color_policy.py", "def _nc_unlink(p):\n    p.unlink()\n")


def r33():  # the shared copy-quit opener is no longer constructed
    sub1(APP / "core.py", "_CopyQuitScreen(_QUIT_TITLE, _COPY_QUIT_BODY,", "_QuitQuestionScreen(_QUIT_TITLE, _COPY_QUIT_BODY,")


def r39():  # a stock Input( constructed in a mixin
    append(APP / "shell.py", "def _nc_stock_input():\n    return Input(placeholder=\"x\")\n")


def r43():  # a duplicated palette entry
    line = '        ("Split / Join / Export", "open_split_join_export"),\n'
    sub1(APP / "core.py", line, line + line)


def r44():  # an old module path left in a tracked doc
    p = tree / "CLAUDE.md"
    wr(p, rd(p).rstrip("\n") + "\n\nThe shell lives in `s19_app/tui/app.py`.\n")


def r69():  # an unsanctioned Binding( in core
    append(APP / "core.py", '_NC_BINDING = Binding("x", "y")\n')


def r74():  # a second safe_text definition in a panel module
    append(tree / "s19_app/tui/screens_directionb/ab_diff.py", "def safe_text(value: str):\n    return value\n")


def r75():  # an extra importer of render.hexview
    append(APP / "flow.py", "from ...render.hexview import render_hex_view_text  # noqa: E402\n")


def r76():  # the range_index primitives are no longer imported by the app package
    n = 0
    for name in ("__init__.py", "file_load.py", "hex_view.py", "mac_view.py"):
        p = APP / name
        t = rd(p)
        t2, c = re.subn(r"^from \.\.\.range_index import [^\n(]*\n", "", t, flags=re.M)
        if c:
            wr(p, t2)
            n += c
    assert n >= 3, n
    print(f"removed {n} range_index import lines")


{"1": r1, "10": r10, "15": r15, "20": r20, "32": r32, "33": r33, "39": r39, "43": r43, "44": r44, "69": r69,
 "74": r74, "75": r75, "76": r76}[row]()
