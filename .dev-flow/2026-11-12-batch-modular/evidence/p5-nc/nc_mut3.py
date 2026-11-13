"""Extra verifier mutations NC-VF-17..25 (cases with no NC-VF number).  Usage: nc_mut3.py <tree> <k> <scratch-dir>
Mutates files of <tree> in place, always through a NEW inode (unlink first) so hard-linked copies are never changed."""
import ast
import json
import os
import re
import sys
from pathlib import Path

tree, k, scr = Path(sys.argv[1]), int(sys.argv[2]), Path(sys.argv[3])
APP = tree / "s19_app/tui/app"
SDB = tree / "s19_app/tui/screens_directionb"


def rd(p):
    return Path(p).read_text(encoding="utf-8")


def wr(p, text):
    p = Path(p)
    if p.exists():
        os.unlink(p)
    p.write_text(text, encoding="utf-8", newline="\n")


def m17():  # TC-04 -> V3: an unmapped top-level def in shell.py
    wr(APP / "shell.py", rd(APP / "shell.py").rstrip("\n") + "\n\n\ndef _helper():\n    pass\n")


def m18():  # TC-13 -> V10: swap two mixins in the core class header
    t = rd(APP / "core.py")
    m = re.search(r"class S19TuiApp\(\s*(\w+),\s*(\w+),", t)
    a, b = m.group(1), m.group(2)
    t = t[:m.start(1)] + b + ", " + a + t[m.end(2):]
    wr(APP / "core.py", t)
    print(f"TARGET={a}<->{b}")


def m19():  # TC-15 -> V11: delete CHECK_GLYPHS from the sdb __init__
    p = SDB / "__init__.py"
    t = rd(p)
    t2, n = re.subn(r"\(CHECK_GLYPHS,\s*", "(", t, count=1)
    assert n == 1, "CHECK_GLYPHS import not found"
    wr(p, t2)
    print("TARGET=CHECK_GLYPHS")


def m20():  # TC-16 -> V11 identity: a re-exported function replaced by a wrapper (not the same object)
    p = APP / "__init__.py"
    t = rd(p)
    for n in ast.parse(t).body:
        if isinstance(n, ast.ImportFrom) and n.level == 1 and n.module:
            home = APP / (n.module + ".py")
            if not home.exists():
                continue
            defs = {d.name for d in ast.parse(rd(home)).body if isinstance(d, ast.FunctionDef)}
            for a in n.names:
                if a.name in defs and not a.asname:
                    wr(p, t.rstrip("\n") + f"\n_nc16_orig = {a.name}\n\n\ndef {a.name}(*a, **k):\n    return _nc16_orig(*a, **k)\n")
                    print(f"TARGET={a.name}")
                    return
    raise SystemExit("no re-exported function found")


def m21():  # TC-19 -> V14 direction: a leaf module imports FlowMixin
    p = APP / "patch.py"
    t = rd(p)
    mm = re.search(r"^from __future__ import annotations\n", t, re.M)
    wr(p, t[:mm.end()] + "from .flow import FlowMixin\n" + t[mm.end():])
    print("TARGET=FlowMixin")


def m22():  # TC-21 -> V15: a module grows past the physical-line cap (2200 / largest class + 500)
    wr(APP / "shell.py", rd(APP / "shell.py").rstrip("\n") + "\n" + "# nc-vf-22 padding\n" * 2400)


def m23():  # TC-25 (verifier side): delete one package __init__.py
    os.unlink(SDB / "__init__.py")


def m24():  # TC-27 scratch half -> V8: scratch map places `_is_link_stat` in `shared`
    mp = json.loads(rd(tree / ".dev-flow/2026-11-12-batch-modular/design/module-map.json"))
    hit = [u for u in mp["app"]["top"] if u.get("name") == "_is_link_stat" or str(u.get("key", "")).endswith("_is_link_stat")]
    assert len(hit) == 1 and hit[0]["module"] == "deps", hit
    hit[0]["module"] = "shared"
    out = scr / "nc24-map.json"
    out.write_text(json.dumps(mp, indent=1), encoding="utf-8")
    print(f"TARGET=_is_link_stat MAP={out}")


def m25():  # TC-28 scratch half -> V9: an @on(...) handler decorates a mixin method
    p = APP / "navigation.py"
    t = rd(p)
    mod = ast.parse(t)
    cls = next(n for n in mod.body if isinstance(n, ast.ClassDef) and n.name == "NavigationMixin")
    fn = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and not n.decorator_list and n.name.startswith("_"))
    lines = t.splitlines(keepends=True)
    lines.insert(fn.lineno - 1, "    @on(Button.Pressed)\n")
    t = "".join(lines)
    mm = re.search(r"^from __future__ import annotations\n", t, re.M)
    t = t[:mm.end()] + "from textual import on\nfrom textual.widgets import Button\n" + t[mm.end():]
    wr(p, t)
    print(f"TARGET={fn.name}")


{17: m17, 18: m18, 19: m19, 20: m20, 21: m21, 22: m22, 23: m23, 24: m24, 25: m25}[k]()
