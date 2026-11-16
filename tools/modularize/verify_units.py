"""Unit discovery for the identity verifier (old text from git, new text from the work tree).

Independent of ``move.py`` and ``plan_map.py``: a *unit* is a top-level statement (an attribute
docstring joins the previous unit), or, for ``S19TuiApp``, one class-body statement / method.
Identity key: ``name`` for top units, ``S19TuiApp.<name>`` for class members.
"""
from __future__ import annotations

import ast
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

OLD_PATHS = {"app": "s19_app/tui/app.py", "screens_directionb": "s19_app/tui/screens_directionb.py"}
NEW_DIRS = {"app": "s19_app/tui/app", "screens_directionb": "s19_app/tui/screens_directionb"}
CLASS = "S19TuiApp"
DOC_KEY = "module-docstring"


@dataclass
class Unit:
    pkg: str
    key: str
    kind: str
    stem: str
    nodes: list
    line: int
    extra: dict = field(default_factory=dict)


def git_show(tree: Path, rev: str, rel: str) -> str:
    out = subprocess.run(["git", "-C", str(tree), "show", f"{rev}:{rel}"], capture_output=True, check=True)
    return out.stdout.decode("utf-8")


def mixin_class(stem: str) -> str:
    return "".join(p.capitalize() for p in stem.split("_")) + "Mixin"


def is_str_expr(n: ast.stmt) -> bool:
    return isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str)


def is_import_like(n: ast.stmt) -> bool:
    if isinstance(n, (ast.Import, ast.ImportFrom)):
        return True
    return isinstance(n, ast.If) and isinstance(n.test, ast.Name) and n.test.id == "TYPE_CHECKING"


def bound_names(n: ast.stmt) -> list[str]:
    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return [n.name]
    targets: list[ast.AST] = []
    if isinstance(n, ast.Assign):
        targets = list(n.targets)
    elif isinstance(n, ast.AnnAssign):
        targets = [n.target]
    return [x.id for t in targets for x in ast.walk(t) if isinstance(x, ast.Name)]


def _top_key(n: ast.stmt, first: bool) -> str:
    if first and is_str_expr(n):
        return DOC_KEY
    names = bound_names(n)
    return names[0] if names else f"{type(n).__name__}@{n.lineno}"


def group_top(body: list[ast.stmt]) -> list[tuple[str, str, list[ast.stmt]]]:
    """(key, kind, nodes) per top-level unit; imports are skipped, attribute docstrings merged."""
    out: list[tuple[str, str, list[ast.stmt]]] = []
    prev_is_unit = False
    for i, n in enumerate(body):
        if is_import_like(n):
            prev_is_unit = False
            continue
        if is_str_expr(n) and out and prev_is_unit:
            out[-1][2].append(n)
            continue
        out.append((_top_key(n, i == 0), type(n).__name__, [n]))
        prev_is_unit = True
    return out


def class_members(cls: ast.ClassDef) -> list[tuple[str, str, ast.stmt]]:
    """(key, kind, node) per class-body statement, ``S19TuiApp.``-qualified."""
    out = []
    for i, n in enumerate(cls.body):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.append((f"{CLASS}.{n.name}", "method", n))
            continue
        label = "docstring" if (i == 0 and is_str_expr(n)) else (",".join(bound_names(n)) or type(n).__name__)
        out.append((f"{CLASS}.{label}", "class_stmt", n))
    return out


def inventory_old(tree: Path, rev: str, pkg: str) -> tuple[list[Unit], str]:
    text = git_show(tree, rev, OLD_PATHS[pkg])
    mod = ast.parse(text)
    units: list[Unit] = []
    for key, kind, nodes in group_top(mod.body):
        if kind == "ClassDef" and key == CLASS:
            for k, kd, node in class_members(nodes[0]):
                units.append(Unit(pkg, k, kd, "old", [node], node.lineno))
            continue
        units.append(Unit(pkg, key, kind, "old", nodes, nodes[0].lineno))
    return units, text


def _expand_core_class(pkg: str, stem: str, cls: ast.ClassDef, units: list[Unit], extras: list[str]) -> None:
    for k, kd, node in class_members(cls):
        units.append(Unit(pkg, k, kd, stem, [node], node.lineno))


def _expand_mixin(pkg: str, stem: str, cls: ast.ClassDef, units: list[Unit], extras: list[str]) -> None:
    if not is_plain_mixin(cls):
        extras.append(f"{cls.name} ({stem}.py:{cls.lineno}): mixin class must have no bases, keywords or decorators")
    for i, n in enumerate(cls.body):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            units.append(Unit(pkg, f"{CLASS}.{n.name}", "method", stem, [n], n.lineno))
        else:
            extras.append(f"{cls.name}.<{type(n).__name__}@{n.lineno}> ({stem}.py): non-method statement in a mixin")


def is_plain_mixin(cls: ast.ClassDef) -> bool:
    return not cls.bases and not cls.keywords and not cls.decorator_list


def parse_new_file(pkg: str, stem: str, text: str, mixin_stems: list[str]) -> tuple[list[Unit], list[str], ast.Module]:
    """Units of one new file, plus `extra` descriptions for statements that are never allowed."""
    mod = ast.parse(text)
    body = mod.body
    units: list[Unit] = []
    extras: list[str] = []
    allowed_doc = bool(body) and is_str_expr(body[0])
    for key, kind, nodes in group_top(body):
        if key == DOC_KEY:
            if stem == "__init__" and pkg == "screens_directionb":
                units.append(Unit(pkg, DOC_KEY, kind, stem, nodes, nodes[0].lineno))
            elif not allowed_doc:
                extras.append(f"{key} ({stem}.py)")
            continue
        if stem == "__init__":
            extras.append(f"{key} ({stem}.py:{nodes[0].lineno}): only re-exports are allowed in __init__")
            continue
        node = nodes[0]
        if kind == "ClassDef" and key == CLASS and stem == "core":
            _expand_core_class(pkg, stem, node, units, extras)
        elif kind == "ClassDef" and stem in mixin_stems and key == mixin_class(stem):
            _expand_mixin(pkg, stem, node, units, extras)
        else:
            units.append(Unit(pkg, key, kind, stem, nodes, node.lineno))
    return units, extras, mod


def find_core_class(mod: ast.Module) -> ast.ClassDef | None:
    for n in mod.body:
        if isinstance(n, ast.ClassDef) and n.name == CLASS:
            return n
    return None
