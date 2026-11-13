"""Name analysis: which names a new module uses and binds."""
from __future__ import annotations

import ast

_TOP_SKIP = ("Import", "ImportFrom", "If", "Expr")


def _mixin_class(module: str) -> str:
    return "".join(p.capitalize() for p in module.split("_")) + "Mixin"


def _bound_name(alias: ast.alias) -> str:
    return (alias.asname or alias.name).split(".")[0]


def _nodes_of(unit: dict) -> list[ast.AST]:
    if "nodes" in unit and unit["nodes"]:
        return unit["nodes"]
    return [unit["node"]]


def role(pkg, module: str) -> str:
    if pkg.is_app:
        if module == "core":
            return "S19TuiApp core"
        if module in pkg.mixin_order:
            return f"S19TuiApp mixin: {module}"
        if module == "deps":
            return "test seam (D1)"
        if module == "shared":
            return "shared helpers"
        if module == "shared_io":
            return "shared helpers that read the D1 seam"
    else:
        roles = {
            "deps": "test seam (D1)",
            "shared": "shared helpers",
            "map_parts": "memory-map parts",
            "memory_map": "MemoryMapPanel",
            "loaded_artifacts": "LoadedArtifactsPanel",
            "patch_editor": "PatchEditorPanel",
            "check_editor": "CheckEditorPanel",
            "ab_diff": "AbDiffPanel",
        }
        return roles[module]
    raise AssertionError(f"no role for {pkg.name}.{module}")


def module_units(pkg, module: str) -> list[dict]:
    units: list[dict] = []
    for u in pkg.top_units:
        if u["kind"] in _TOP_SKIP or u["module"] != module:
            continue
        if pkg.is_app and module == "core" and u["key"] == "S19TuiApp":
            continue
        units.append(u)
    if pkg.is_app and module == "core":
        units.extend(u for u in pkg.class_stmt_units if u["module"] == "core")
        units.extend(u for u in pkg.method_units if u["module"] == "core")
    elif pkg.is_app and module in pkg.mixin_order:
        units.extend(u for u in pkg.method_units if u["module"] == module)
    return units


def header_base_names(pkg, module: str) -> set[str]:
    if pkg.is_app and module == "core":
        dummy = ast.parse(pkg.class_header + "\n    pass\n")
        cls = dummy.body[0]
        return {n.id for n in ast.walk(cls)
                if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
    return set()


def used_names(pkg, module: str) -> tuple[set[str], set[str], bool]:
    """Return ``(runtime_used, annotation_used, has_d1)``."""
    runtime: set[str] = set()
    annotation: set[str] = set()
    has_d1 = False
    for unit in module_units(pkg, module):
        for node in _nodes_of(unit):
            for name in ast.walk(node):
                if not (isinstance(name, ast.Name) and isinstance(name.ctx, ast.Load)):
                    continue
                if not pkg.resolver.is_module_global(name):
                    continue
                in_ann = pkg.resolver.in_annotation(name)
                if name.id in pkg.d1_names and not in_ann:
                    if module == "deps":
                        runtime.add(name.id)
                    else:
                        has_d1 = True
                elif in_ann:
                    annotation.add(name.id)
                else:
                    runtime.add(name.id)
    runtime.update(header_base_names(pkg, module))
    return runtime, annotation, has_d1


def self_bound(pkg, module: str) -> set[str]:
    names: set[str] = set()
    for unit in module_units(pkg, module):
        for node in _nodes_of(unit):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.add(node.name)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    names.add(_bound_name(alias))
            else:
                for target in (node.targets if isinstance(node, ast.Assign)
                               else [node.target] if isinstance(node, ast.AnnAssign) else []):
                    names.update(x.id for x in ast.walk(target) if isinstance(x, ast.Name))
    if pkg.is_app and module == "core":
        names.add("S19TuiApp")
    if pkg.is_app and module in pkg.mixin_order:
        names.add(_mixin_class(module))
    return names


def string_annotation_names(pkg, module: str) -> set[str]:
    """Return names mentioned inside string-constant annotations (F5).

    A name written only as a string literal inside an annotation
    (e.g. ``Optional["LoadedFile"]``) produces no ``ast.Name`` Load, so
    ``used_names`` cannot see it.  Parse each annotation string with
    ``ast.parse(s, mode="eval")`` and collect the Load names so the
    emitter can route them to the ``if TYPE_CHECKING:`` source only.
    """
    names: set[str] = set()
    for unit in module_units(pkg, module):
        for node in _nodes_of(unit):
            for const in ast.walk(node):
                if not (isinstance(const, ast.Constant) and isinstance(const.value, str)):
                    continue
                if not pkg.resolver.in_annotation(const):
                    continue
                try:
                    expr = ast.parse(const.value, mode="eval")
                except SyntaxError:
                    continue
                for name in ast.walk(expr):
                    if isinstance(name, ast.Name) and isinstance(name.ctx, ast.Load):
                        names.add(name.id)
    return names
