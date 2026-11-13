"""Normalisation of a NEW unit (the closed list of I-6 rewrites) and the V4/V5 comparison."""
from __future__ import annotations

import ast
import copy
import difflib
from dataclasses import dataclass, field

from verify_units import Unit

CSS_NEW = "../styles.tcss"
CSS_OLD = "styles.tcss"


@dataclass
class NormReport:
    d1: int = 0
    relimport: int = 0
    css: int = 0
    unlisted: list[str] = field(default_factory=list)


class Normaliser(ast.NodeTransformer):
    """Undo D1 `deps.X` and the `+1` relative-import level; annotations are never touched."""

    def __init__(self, d1: set[str], in_deps: bool, rep: NormReport) -> None:
        self.d1, self.in_deps, self.rep = d1, in_deps, rep

    def visit_Attribute(self, node: ast.Attribute):
        self.generic_visit(node)
        v = node.value
        if not (isinstance(v, ast.Name) and v.id == "deps" and isinstance(node.ctx, ast.Load)):
            return node
        if self.in_deps:
            self.rep.unlisted.append(f"deps.{node.attr} inside deps.py (line {node.lineno})")
            return node
        if node.attr not in self.d1:
            return node
        self.rep.d1 += 1
        return ast.copy_location(ast.Name(id=node.attr, ctx=ast.Load()), node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.level >= 2:
            node.level -= 1
            self.rep.relimport += 1
        elif node.level == 1:
            self.rep.unlisted.append(f"relative import level 1 not bumped (line {node.lineno})")
        return node

    def visit_arg(self, node: ast.arg):
        return node

    def visit_AnnAssign(self, node: ast.AnnAssign):
        node.target = self.visit(node.target)
        if node.value is not None:
            node.value = self.visit(node.value)
        return node

    def _func(self, node):
        node.decorator_list = [self.visit(d) for d in node.decorator_list]
        node.args = self.visit(node.args)
        node.body = [self.visit(s) for s in node.body]
        return node

    visit_FunctionDef = _func
    visit_AsyncFunctionDef = _func


def _fix_css(u: Unit, nodes: list[ast.stmt], rep: NormReport) -> str | None:
    n = nodes[0]
    ok = (isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.value, ast.Constant)
          and n.value.value == CSS_NEW)
    if not ok:
        return f"CSS_PATH is not the rewritten constant {CSS_NEW!r}"
    n.value = ast.copy_location(ast.Constant(value=CSS_OLD), n.value)
    rep.css += 1
    return None


def normalise(u: Unit, d1: set[str]) -> tuple[list[ast.stmt], NormReport, str | None]:
    rep = NormReport()
    nodes = [copy.deepcopy(n) for n in u.nodes]
    pre = None
    if u.stem == "core" and u.key == "S19TuiApp.CSS_PATH":
        pre = _fix_css(u, nodes, rep)
    if u.stem != "deps":
        for n in nodes:
            for x in ast.walk(n):
                if (isinstance(x, ast.Attribute) and isinstance(x.value, ast.Name) and x.value.id == "deps"
                        and isinstance(x.ctx, ast.Load) and x.attr not in d1):
                    rep.unlisted.append(f"deps.{x.attr}: not a D1 name (line {x.lineno})")
    norm = Normaliser(d1, u.stem == "deps", rep)
    nodes = [norm.visit(n) for n in nodes]
    return nodes, rep, pre


def dump(nodes: list[ast.stmt]) -> str:
    return "|".join(ast.dump(n, annotate_fields=True, include_attributes=False) for n in nodes)


def first_diff(old: list[ast.stmt], new: list[ast.stmt]) -> str:
    a = "\n".join(ast.unparse(n) for n in old).splitlines()
    b = "\n".join(ast.unparse(n) for n in new).splitlines()
    minus = plus = None
    for ln in difflib.unified_diff(a, b, lineterm="", n=0):
        if ln.startswith(("+++", "---", "@@")):
            continue
        if ln[0] == "-" and minus is None:
            minus = ln[1:].strip()[:80]
        elif ln[0] == "+" and plus is None:
            plus = ln[1:].strip()[:80]
        if minus is not None and plus is not None:
            break
    if minus is None and plus is None:
        return "AST differs (no source-visible diff)"
    return f"first diff old={minus!r} new={plus!r}"
