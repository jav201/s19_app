"""AST/symtable scope resolution for the mover (no s19_app import).

Builds the parent map and pairs AST scope nodes with ``symtable`` tables so a
Name can be classified as a module-global reference (needs an import) or a
local/parameter/free/class-body reference (self-contained).
"""
from __future__ import annotations

import ast
from symtable import SymbolTable, symtable as _symtable

SCOPE_TYPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda,
               ast.ClassDef, ast.GeneratorExp)


def build_symtable(text: str, path: str) -> SymbolTable:
    return _symtable(text, path, "exec")


def _walk_tables(root: SymbolTable):
    out = []
    def rec(table):
        out.append(table)
        for child in table.get_children():
            rec(child)
    rec(root)
    return out


def build_table_maps(root: SymbolTable) -> tuple[dict[int, SymbolTable], dict]:
    """Return ``(by_lineno, parent)`` for every non-module table."""
    by_lineno: dict[int, SymbolTable] = {}
    parent: dict[SymbolTable, SymbolTable] = {}
    def rec(table):
        for child in table.get_children():
            by_lineno.setdefault(child.get_lineno(), child)
            parent[child] = table
            rec(child)
    rec(root)
    return by_lineno, parent


def build_parent_map(root: ast.AST) -> dict[ast.AST, tuple[ast.AST, str]]:
    parent: dict[ast.AST, tuple[ast.AST, str]] = {}
    for node in ast.walk(root):
        for field, value in ast.iter_fields(node):
            if isinstance(value, ast.AST):
                parent[value] = (node, field)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        parent[item] = (node, field)
    return parent


def _is_body_field(scope: ast.AST, field: str) -> bool:
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda,
                          ast.ClassDef)):
        return field == "body"
    if isinstance(scope, ast.GeneratorExp):
        return field in ("elt", "generators")
    return True


class ScopeResolver:
    """Classify Name nodes against one old module's symtable."""

    def __init__(self, tree: ast.AST, module_table: SymbolTable):
        self.parent = build_parent_map(tree)
        self.by_lineno, self.table_parent = build_table_maps(module_table)
        self.module_table = module_table
        self.comp_local_ids = self._mark_comp_locals(tree)

    def _mark_comp_locals(self, tree: ast.AST) -> set[int]:
        """PEP 709 inlines list/set/dict comprehensions: their target Loads
        are locals of the enclosing scope, invisible to symtable at module
        level (where is_local == is_global). Mark them as non-global."""
        local_ids: set[int] = set()
        for node in ast.walk(tree):
            if not isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp,
                                     ast.GeneratorExp)):
                continue
            targets = {n.id for g in node.generators
                       for n in ast.walk(g.target) if isinstance(n, ast.Name)}
            if isinstance(node, ast.DictComp):
                subtrees: list[ast.AST] = [node.key, node.value]
            else:
                subtrees = [node.elt]
            for g in node.generators:
                subtrees.extend(g.ifs)
                if g is not node.generators[0]:
                    subtrees.append(g.iter)
            for subtree in subtrees:
                for n in ast.walk(subtree):
                    if (isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)
                            and n.id in targets):
                        local_ids.add(id(n))
        return local_ids

    @staticmethod
    def _lookup(table: SymbolTable, name: str):
        try:
            return table.lookup(name)
        except KeyError:
            return None

    def enclosing_scope(self, node: ast.AST):
        cur = node
        while cur in self.parent:
            scope, field = self.parent[cur]
            if isinstance(scope, SCOPE_TYPES):
                if _is_body_field(scope, field):
                    return scope
            cur = scope
        return None

    def symbol_flags(self, node: ast.Name):
        """Return ``("module", None)``, ``("sym", sym)`` or ``("none", None)``."""
        scope = self.enclosing_scope(node)
        if scope is None:
            return ("module", None)
        table = self.by_lineno.get(scope.lineno)
        cur = table
        while cur is not None:
            sym = self._lookup(cur, node.id)
            if sym is not None:
                return ("sym", sym)
            cur = self.table_parent.get(cur)
        return ("none", None)

    def is_module_global(self, node: ast.Name) -> bool:
        if not (isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)):
            return False
        if id(node) in self.comp_local_ids:
            return False
        kind, sym = self.symbol_flags(node)
        if kind == "module":
            return True
        if kind == "sym":
            return bool(sym.is_global())
        return True

    def in_annotation(self, node: ast.AST) -> bool:
        cur = node
        while cur in self.parent:
            parent, field = self.parent[cur]
            if isinstance(parent, ast.FunctionDef) and field == "returns":
                return True
            if isinstance(parent, ast.arg) and field == "annotation":
                return True
            if isinstance(parent, ast.AnnAssign) and field == "annotation":
                return True
            cur = parent
        return False


def check_e6(module_table: SymbolTable, d1_names: set[str]) -> str | None:
    """Return a description if a D1 name is bound in a non-module scope."""
    for table in _walk_tables(module_table):
        if table.get_type() == "module":
            continue
        for name in d1_names:
            try:
                sym = table.lookup(name)
            except KeyError:
                continue
            if (sym.is_local() or sym.is_parameter() or sym.is_free()
                    or sym.is_nonlocal() or sym.is_declared_global()):
                return (f"D1 name {name!r} bound in non-module scope "
                        f"{table.get_name()!r} at line {table.get_lineno()}")
    return None
