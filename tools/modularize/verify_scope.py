"""Scope-aware counting of D1 names (V6/V7): `symtable` decides which Loads are module-global."""
from __future__ import annotations

import ast
import symtable
from collections import Counter, defaultdict, deque


def _norm_name(name: str) -> str:
    return name.strip("<>")


class _Walk:
    def __init__(self, d1: set[str] | None) -> None:
        self.d1 = d1
        self.count: Counter[str] = Counter()
        self.sites: dict[str, list[int]] = defaultdict(list)
        self._kids: dict[int, tuple] = {}

    def child(self, tab: symtable.SymbolTable, name: str, line: int, inlined_ok: bool = False) -> symtable.SymbolTable:
        entry = self._kids.get(id(tab))
        kids = entry[1] if entry else None
        if kids is None:
            kids = defaultdict(deque)
            for c in tab.get_children():
                kids[(_norm_name(c.get_name()), c.get_lineno())].append(c)
            self._kids[id(tab)] = (tab, kids)  # keep tab alive so its id is not reused
        q = kids.get((_norm_name(name), line))
        if not q and inlined_ok:
            return tab  # PEP 709: an inlined comprehension has no table of its own
        if not q:
            raise RuntimeError(f"symtable scope not found for {name!r} at line {line}")
        return q.popleft()

    def visit(self, node: ast.AST, tab: symtable.SymbolTable) -> None:
        if isinstance(node, ast.Name):
            self._name(node, tab)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._func(node, tab)
        elif isinstance(node, ast.ClassDef):
            for x in node.decorator_list + node.bases + [k.value for k in node.keywords]:
                self.visit(x, tab)
            sub = self.child(tab, node.name, node.lineno)
            for s in node.body:
                self.visit(s, sub)
        elif isinstance(node, ast.Lambda):
            for x in node.args.defaults + [d for d in node.args.kw_defaults if d is not None]:
                self.visit(x, tab)
            self.visit(node.body, self.child(tab, "lambda", node.lineno))
        elif isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            self._comp(node, tab)
        elif isinstance(node, ast.AnnAssign):
            self.visit(node.target, tab)
            if node.value is not None:
                self.visit(node.value, tab)
        else:
            for c in ast.iter_child_nodes(node):
                self.visit(c, tab)

    def _name(self, node: ast.Name, tab: symtable.SymbolTable) -> None:
        if not isinstance(node.ctx, ast.Load) or (self.d1 is not None and node.id not in self.d1):
            return
        try:
            is_global = tab.lookup(node.id).is_global()
        except KeyError:
            is_global = True
        if is_global:
            self.count[node.id] += 1
            self.sites[node.id].append(node.lineno)

    def _func(self, node, tab) -> None:
        for x in node.decorator_list + node.args.defaults + [d for d in node.args.kw_defaults if d is not None]:
            self.visit(x, tab)
        sub = self.child(tab, node.name, node.lineno)
        for s in node.body:
            self.visit(s, sub)

    def _comp(self, node, tab) -> None:
        kind = {ast.ListComp: "listcomp", ast.SetComp: "setcomp", ast.DictComp: "dictcomp",
                ast.GeneratorExp: "genexpr"}[type(node)]
        gens = node.generators
        self.visit(gens[0].iter, tab)
        sub = self.child(tab, kind, node.lineno, inlined_ok=True)
        for i, g in enumerate(gens):
            self.visit(g.target, sub)
            if i:
                self.visit(g.iter, sub)
            for cond in g.ifs:
                self.visit(cond, sub)
        for part in ([node.key, node.value] if isinstance(node, ast.DictComp) else [node.elt]):
            self.visit(part, sub)


def global_loads(text: str, d1: set[str] | None) -> tuple[Counter, dict[str, list[int]]]:
    """`d1=None` counts every name (V18). Per D1 name: number of module-global `Name` Loads outside annotations (and their line numbers)."""
    tree = ast.parse(text)
    top = symtable.symtable(text, "<module>", "exec")
    w = _Walk(d1)
    for stmt in tree.body:
        w.visit(stmt, top)
    return w.count, dict(w.sites)


def deps_attr_loads(tree: ast.AST, d1: set[str]) -> Counter:
    """Per D1 name: number of `deps.<name>` Attribute Loads anywhere in `tree`."""
    c: Counter[str] = Counter()
    for n in ast.walk(tree):
        if (isinstance(n, ast.Attribute) and isinstance(n.ctx, ast.Load) and n.attr in d1
                and isinstance(n.value, ast.Name) and n.value.id == "deps"):
            c[n.attr] += 1
    return c
