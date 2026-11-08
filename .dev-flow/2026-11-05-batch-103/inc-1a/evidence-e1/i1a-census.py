"""Inc 1a E1 census: every text field of s19_app, its class, and the window or dialog that holds it.

Part A (static, AST): every construction of a text-field class in s19_app/, with the enclosing
class and function, the `id=` and `read_only=` keywords, and the resolved field class.
Part B (runtime, headless): the app mounted at 160x48; for each rail window of
SCREEN_CONTAINER_IDS, the Input / TextArea widgets mounted under its container, with their
class, read_only flag and whether they are shown after `action_show_screen`.

Touches no clipboard: no copy, cut or paste key is pressed, no Tk root is created
(DISPLAY and WAYLAND_DISPLAY are unset by the runner command), the headless driver writes nothing.
Run from the repo clone (cwd) so `s19_app` is imported from it; prints `s19_app.__file__` first.
"""
from __future__ import annotations

import ast
import asyncio
import os
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

import s19_app

print(f"s19_app.__file__ = {s19_app.__file__}")
print(f"python = {sys.version.split()[0]}; DISPLAY={os.environ.get('DISPLAY')!r}; "
      f"WAYLAND_DISPLAY={os.environ.get('WAYLAND_DISPLAY')!r}")
import textual

print(f"textual = {textual.__version__}")

PKG = Path(s19_app.__file__).resolve().parent
FIELD_BASES = {"Input", "TextArea", "MaskedInput"}

# --- Part A: static census --------------------------------------------------------------
print("\n== Part A: static census of text-field constructions ==")
sources = {p: p.read_text(encoding="utf-8") for p in sorted(PKG.rglob("*.py"))}
trees = {p: ast.parse(t) for p, t in sources.items()}

# class name -> base names (bare), over the whole package
bases: dict[str, set[str]] = defaultdict(set)
for tree in trees.values():
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for b in node.bases:
                name = b.id if isinstance(b, ast.Name) else (b.attr if isinstance(b, ast.Attribute) else None)
                if isinstance(b, ast.Subscript):
                    v = b.value
                    name = v.id if isinstance(v, ast.Name) else (v.attr if isinstance(v, ast.Attribute) else None)
                if name:
                    bases[node.name].add(name)


def lineage(name: str, seen=None) -> list[str]:
    seen = seen or set()
    out = [name]
    for b in sorted(bases.get(name, ())):
        if b not in seen:
            seen.add(b)
            out += lineage(b, seen)
    return out


def field_class(name: str) -> str | None:
    lin = lineage(name)
    if "OsClipboardInput" in lin:
        return "OsClipboardInput"
    if "CappedTextArea" in lin:
        return "CappedTextArea"
    if "Input" in lin or "MaskedInput" in lin:
        return "stock Input"
    if "TextArea" in lin:
        return "stock TextArea"
    return None


field_ctor_names = {n for n in set(bases) | FIELD_BASES | {"OsClipboardInput", "CappedTextArea"} if field_class(n)}
print("field classes known (constructor name -> class):")
for n in sorted(field_ctor_names):
    print(f"  {n} -> {field_class(n)}  (lineage {' > '.join(lineage(n))})")


def kw(node: ast.Call, key: str):
    for k in node.keywords:
        if k.arg == key:
            try:
                return ast.literal_eval(k.value)
            except Exception:
                return ast.unparse(k.value)
    return None


rows = []
for path, tree in trees.items():
    rel = path.relative_to(PKG.parent).as_posix()

    def walk(node, cls, fn):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                walk(child, child.name, fn)
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                walk(child, cls, child.name)
            else:
                if isinstance(child, ast.Call):
                    f = child.func
                    name = f.id if isinstance(f, ast.Name) else None
                    if name in field_ctor_names:
                        rows.append((rel, child.lineno, cls, fn, name, field_class(name),
                                     kw(child, "id"), kw(child, "read_only")))
                walk(child, cls, fn)

    walk(tree, None, None)

rows.sort()
print(f"\nconstructions found: {len(rows)}")
print("file:line | enclosing class | function | constructor | field class | id | read_only")
for r in rows:
    print(f"{r[0]}:{r[1]} | {r[2]} | {r[3]} | {r[4]} | {r[5]} | {r[6]!r} | {r[7]!r}")

by_class = defaultdict(list)
for r in rows:
    by_class[r[5]].append(r)
print("\ncount by field class:")
for k in sorted(by_class):
    print(f"  {k}: {len(by_class[k])}")

dialog_names = {n for n in bases if "ModalScreen" in lineage(n)}
by_holder = defaultdict(lambda: defaultdict(int))
for r in rows:
    holder = r[2] or "<module>"
    kind = "dialog" if holder in dialog_names else "widget/window"
    by_holder[(kind, holder)][r[5]] += 1
print("\nholders (enclosing class) with their field classes:")
for (kind, holder), counts in sorted(by_holder.items()):
    print(f"  [{kind}] {holder}: " + ", ".join(f"{k} x{v}" for k, v in sorted(counts.items())))
print(f"\ndialog classes (ModalScreen subclasses): {len(dialog_names)}")
for n in sorted(dialog_names):
    held = by_holder.get(("dialog", n))
    print(f"  {n}: " + (", ".join(f"{k} x{v}" for k, v in sorted(held.items())) if held else "no text field constructed in its body"))

# --- Part B: runtime census of the rail windows -----------------------------------------
print("\n== Part B: runtime census of the rail windows (headless, 160x48) ==")
from textual.widgets import Input, TextArea  # noqa: E402

from s19_app.tui.app import S19TuiApp  # noqa: E402
from s19_app.tui.capped_text_area import CappedTextArea  # noqa: E402
from s19_app.tui.os_clipboard_input import OsClipboardInput  # noqa: E402


def cls_name(w) -> str:
    if isinstance(w, OsClipboardInput):
        return "OsClipboardInput"
    if isinstance(w, CappedTextArea):
        return "CappedTextArea"
    if isinstance(w, Input):
        return "stock Input"
    if isinstance(w, TextArea):
        return "stock TextArea"
    return type(w).__name__


async def runtime() -> None:
    base = Path(tempfile.mkdtemp(prefix="i1a-census-", dir=os.environ.get("TMPDIR", "/tmp")))
    app = S19TuiApp(base_dir=base)
    async with app.run_test(size=(160, 48)) as pilot:
        await pilot.pause()
        keys = list(app.SCREEN_CONTAINER_IDS)
        print(f"rail windows: {len(keys)} -> {keys}")
        seen_ids = set()
        for key in keys:
            app.action_show_screen(key)
            for _ in range(3):
                await pilot.pause()
            container = app.query_one(f"#{app.SCREEN_CONTAINER_IDS[key]}")
            fields = [w for w in container.query("*") if isinstance(w, (Input, TextArea))]
            print(f"\n[{key}] #{container.id}: {len(fields)} text field(s)")
            for w in fields:
                seen_ids.add(id(w))
                ro = getattr(w, "read_only", None)
                print(f"   #{w.id} | {cls_name(w)} ({type(w).__name__}) | read_only={ro} | displayed={w.display and w.visible} | shown_region={w.region.area > 0}")
        others = [w for w in app.screen.query("*") if isinstance(w, (Input, TextArea)) and id(w) not in seen_ids]
        print(f"\n[outside the rail windows, main screen]: {len(others)} text field(s)")
        for w in others:
            anc = [a.id for a in w.ancestors_with_self if getattr(a, "id", None)][:4]
            print(f"   #{w.id} | {cls_name(w)} ({type(w).__name__}) | read_only={getattr(w, 'read_only', None)} | ancestors={anc}")


asyncio.run(runtime())
print("\ncensus done")
