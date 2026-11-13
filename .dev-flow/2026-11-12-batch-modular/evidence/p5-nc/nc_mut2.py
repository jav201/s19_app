"""Mutations for NC-VF-1..13.  Usage: nc_mut.py <tree> <k>   (mutates the files of <tree> in place,
replacing each touched file by a NEW inode so hard-linked copies of the original are never changed)."""
import ast
import os
import re
import sys
from pathlib import Path

tree, k = Path(sys.argv[1]), int(sys.argv[2])
APP = tree / "s19_app/tui/app"


def rd(p):
    return Path(p).read_text(encoding="utf-8")


def wr(p, text):
    p = Path(p)
    if p.exists():
        os.unlink(p)
    p.write_text(text, encoding="utf-8", newline="\n")


def find_func(path, name, in_class=None):
    mod = ast.parse(rd(path))
    for n in ast.walk(mod):
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return n
    raise SystemExit(f"{name} not found in {path}")


def seg(path, node):
    lines = rd(path).splitlines(keepends=True)
    start = min([d.lineno for d in node.decorator_list] + [node.lineno])
    return start, node.end_lineno, lines


def cut(path, node):
    a, b, lines = seg(path, node)
    text = "".join(lines[a - 1:b])
    wr(path, "".join(lines[:a - 1] + lines[b:]))
    return text


def class_end(path, clsname):
    for n in ast.parse(rd(path)).body:
        if isinstance(n, ast.ClassDef) and n.name == clsname:
            return n.end_lineno
    raise SystemExit(f"class {clsname} not found in {path}")


def insert_in_class(path, clsname, method_text):
    e = class_end(path, clsname)
    lines = rd(path).splitlines(keepends=True)
    wr(path, "".join(lines[:e]) + "\n" + method_text.rstrip("\n") + "\n" + "".join(lines[e:]))


def after_future(path, line):
    t = rd(path)
    m = re.search(r"^from __future__ import annotations\n", t, re.M)
    wr(path, t[:m.end()] + line + "\n" + t[m.end():])


def byte_edit(path, lineno, col, old, new):
    lines = rd(path).splitlines(keepends=True)
    b = lines[lineno - 1].encode("utf-8")
    assert b[col:col + len(old)] == old.encode(), (path, lineno, col, old)
    lines[lineno - 1] = (b[:col] + new.encode() + b[col + len(old):]).decode("utf-8")
    wr(path, "".join(lines))


def m1():
    cut(APP / "navigation.py", find_func(APP / "navigation.py", "_land_focus"))


def m2():
    n = find_func(APP / "navigation.py", "_land_focus")
    a, b, lines = seg(APP / "navigation.py", n)
    insert_in_class(APP / "shell.py", "ShellMixin", "".join(lines[a - 1:b]))


def m3():
    p = APP / "shell.py"
    fn = find_func(p, "_busy_tick")
    for n in ast.walk(fn):
        if isinstance(n, ast.Constant) and type(n.value) is int:
            byte_edit(p, n.lineno, n.col_offset, str(n.value), str(n.value + 7))
            return
    raise SystemExit("no int constant in _busy_tick")


def m4():
    for p in sorted(APP.glob("*.py")):
        if p.stem in ("deps", "__init__", "shared"):
            continue
        for n in ast.walk(ast.parse(rd(p))):
            if isinstance(n, ast.Name) and n.id == "Path" and isinstance(n.ctx, ast.Load):
                byte_edit(p, n.lineno, n.col_offset, "Path", "deps.Path")
                if "from . import deps" not in rd(p):
                    after_future(p, "from . import deps")
                after_future(APP / "deps.py", "from pathlib import Path")
                return
    raise SystemExit("no Path load found")


def m5():
    for p in sorted(APP.glob("*.py")):
        if p.stem in ("deps", "__init__"):
            continue
        for n in ast.walk(ast.parse(rd(p))):
            if (isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "deps"
                    and n.attr == "os" and isinstance(n.ctx, ast.Load)):
                byte_edit(p, n.lineno, n.col_offset, "deps.os", "os")
                after_future(p, "import os")
                return
    raise SystemExit("no deps.os found")


def m6():
    mod = ast.parse(rd(APP / "shared.py"))
    fn = next(n for n in mod.body if isinstance(n, ast.FunctionDef))
    text = cut(APP / "shared.py", fn)
    wr(APP / "shell.py", rd(APP / "shell.py").rstrip("\n") + "\n\n\n" + text)


def m7():
    text = cut(APP / "core.py", find_func(APP / "core.py", "on_button_pressed"))
    insert_in_class(APP / "navigation.py", "NavigationMixin", text)


def m8():
    p = APP / "__init__.py"
    for n in ast.parse(rd(p)).body:
        if isinstance(n, ast.ImportFrom) and n.level == 1 and n.module == "shared" and len(n.names) >= 2:
            a = n.names[0]
            lines = rd(p).splitlines(keepends=True)
            seg_ = lines[a.lineno - 1]
            b = seg_.encode()
            tail = b[a.end_col_offset:]
            tail = re.sub(rb"^\s*,\s*", b"", tail, count=1)
            lines[a.lineno - 1] = (b[:a.col_offset] + tail).decode()
            wr(p, "".join(lines))
            return
    raise SystemExit("no multi-name 'from .shared import' in __init__")


def m9():
    after_future(APP / "shared.py", "from .navigation import NavigationMixin")


def m10():
    p = APP / "core.py"
    t = rd(p)
    assert "../styles.tcss" in t
    wr(p, t.replace("../styles.tcss", "styles.tcss", 1))


def m11():
    (tree / "s19_app/tui/app.py").write_text("", encoding="utf-8")


def m12():
    for p in sorted(APP.glob("*.py")):
        if p.stem == "__init__":
            continue
        for n in ast.parse(rd(p)).body:
            if isinstance(n, ast.ImportFrom) and n.level == 2 and n.module and n.names[0].name != "*":
                x = n.names[0].asname or n.names[0].name
                wr(tree / "s19_app/tui/_nc12.py", f"{x} = object()\n")
                lines = rd(p).splitlines(keepends=True)
                lines.insert(n.end_lineno, f"from .._nc12 import {x}\n")
                wr(p, "".join(lines))
                return
    raise SystemExit("no level-2 import found")


def m13():
    for p in sorted(APP.glob("*.py")):
        if p.stem == "__init__":
            continue
        for fn in ast.walk(ast.parse(rd(p))):
            if isinstance(fn, ast.FunctionDef):
                for n in ast.walk(fn):
                    if isinstance(n, ast.ImportFrom) and n.level >= 2:
                        lines = rd(p).splitlines(keepends=True)
                        s = lines[n.lineno - 1]
                        lines[n.lineno - 1] = s.replace("from " + "." * n.level, "from " + "." * (n.level + 2), 1)
                        wr(p, "".join(lines))
                        return
    raise SystemExit("no function-level relative import found")


# appended to a copy of nc_mut.py: NC-VF-14..16
def m14():
    p = APP / "deps.py"
    t = rd(p)
    for pat in (r"(import\s+)Label,\s*", r"(,\s*)Label\b(?=[,\s)\n])"):
        t2, n = re.subn(pat, lambda m: m.group(1) if pat.startswith("(import") else "", t, count=1)
        if n:
            wr(p, t2); print("TARGET=Label"); return
    raise SystemExit("Label import not found in deps.py")


def m15():
    for p in sorted(APP.glob("*.py")):
        if p.stem in ("deps", "__init__", "core", "shared", "shared_io"):
            continue
        mod = ast.parse(rd(p))
        loads = {n.id for n in ast.walk(mod) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
        for n in mod.body:
            if isinstance(n, ast.ImportFrom) and n.module not in (None, "__future__") and len(n.names) == 1 and n.level >= 1:
                a = n.names[0]
                if (a.asname or a.name) in loads and a.name != "*":
                    lines = rd(p).splitlines(keepends=True)
                    del lines[n.lineno - 1:n.end_lineno]
                    wr(p, "".join(lines)); print(f"TARGET={a.asname or a.name} MODULE={p.stem}"); return
    raise SystemExit("no single-name top-level import found")


def m16():
    after_future(APP / "shared.py", "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from os import PathLike\nelse:\n    NC16_X = 1")
    print("TARGET=TYPE_CHECKING")

{1: m1, 2: m2, 3: m3, 4: m4, 5: m5, 6: m6, 7: m7, 8: m8, 9: m9, 10: m10, 11: m11, 12: m12, 13: m13, 14: m14, 15: m15, 16: m16}[k]()
