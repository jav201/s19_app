"""Re-derive and validate the module map against a base revision."""
from __future__ import annotations

import ast
import builtins as _builtins

from move_common import MoveError
from move_scope import ScopeResolver, build_symtable, check_e6

_IMPORT_KINDS = ("Import", "ImportFrom")


class Package:
    """Everything the emitter needs for one old module."""

    def __init__(self):
        self.name = ""
        self.old_path = ""
        self.is_app = False
        self.text = ""
        self.lines: list[str] = []
        self.tree: ast.Module | None = None
        self.cls: ast.ClassDef | None = None
        self.module_table = None
        self.resolver: ScopeResolver | None = None
        self.d1_names: frozenset = frozenset()
        self.deps_defined: frozenset = frozenset()
        self.reexports: list[str] = []
        self.mixin_order: list[str] = []
        self.class_header = ""
        self.top_units: list[dict] = []
        self.method_units: list[dict] = []
        self.class_stmt_units: list[dict] = []
        self.import_units: list[dict] = []
        self.if_units: list[dict] = []
        self.docstring_unit: dict | None = None
        self.home_by_name: dict[str, tuple[str, int]] = {}
        self.import_by_name: dict[str, tuple[ast.AST, ast.alias]] = {}
        self.typechecking_names: frozenset = frozenset()
        self.typechecking_nodes: list[ast.ImportFrom] = []
        self.old_top_level_bound: set[str] = set()
        self.builtins: frozenset = frozenset(dir(_builtins))


def _bound_names(node: ast.stmt) -> list[str]:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return [node.name]
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        return [(a.asname or a.name).split(".")[0] for a in node.names]
    targets: list[ast.AST] = []
    if isinstance(node, ast.Assign):
        targets = node.targets
    elif isinstance(node, ast.AnnAssign):
        targets = [node.target]
    return [x.id for t in targets for x in ast.walk(t) if isinstance(x, ast.Name)]


def _bound_name(alias: ast.alias) -> str:
    return (alias.asname or alias.name).split(".")[0]


def _mixin_class(module: str) -> str:
    return "".join(p.capitalize() for p in module.split("_")) + "Mixin"


def _property_group(units: list[dict]) -> bool:
    if len(units) != 2:
        return False
    getter = next((u for u in units if any(
        isinstance(d, ast.Name) and d.id == "property" for d in u["node"].decorator_list)), None)
    setter = next((u for u in units if u is not getter and any(
        isinstance(d, ast.Attribute) and d.attr in ("setter", "deleter")
        and isinstance(d.value, ast.Name) for d in u["node"].decorator_list)), None)
    return getter is not None and setter is not None


def _match_span(actual: tuple[int, int], expected: list[int], label: str) -> None:
    if list(actual) != list(expected):
        raise MoveError("E2", f"{label}: recomputed span {list(actual)} != map span {expected}")


def _init_package(repo: str, rev: str, old_path: str, name: str, map_pkg: dict,
                  plan_map, is_app: bool, mixin_order: list[str] | None) -> Package:
    from move_common import read_base
    pkg = Package()
    pkg.name = name
    pkg.old_path = old_path
    pkg.is_app = is_app
    pkg.text = read_base(repo, rev, old_path)
    pkg.lines = pkg.text.splitlines(keepends=True)
    pkg.tree = ast.parse(pkg.text)
    pkg.module_table = build_symtable(pkg.text, old_path)
    pkg.resolver = ScopeResolver(pkg.tree, pkg.module_table)
    pkg.d1_names = frozenset(map_pkg["d1_names"])
    pkg.deps_defined = frozenset(map_pkg["deps_defined"])
    pkg.reexports = list(map_pkg["reexports"])
    pkg.mixin_order = list(mixin_order or [])
    pkg.class_header = map_pkg.get("class_header", "")
    return pkg


def _derive_top_units(pkg: Package, plan_map, map_pkg: dict,
                      allowed_top: set[str]) -> None:
    units = plan_map.top_units(pkg.tree)
    top_by_key: dict[str, list[dict]] = {}
    for entry in map_pkg["top"]:
        top_by_key.setdefault(entry["key"], []).append(entry)
    for unit in units:
        entries = top_by_key.get(unit["key"], [])
        if not entries:
            raise MoveError("E3", f"top unit {unit['key']!r} missing from map")
        if len(entries) > 1:
            raise MoveError("E4", f"top unit {unit['key']!r} duplicated in map")
        entry = entries[0]
        _match_span((unit["start"], unit["end"]), entry["span"],
                    f"top unit {unit['key']!r}")
        if entry["module"] not in allowed_top:
            raise MoveError("E5", f"top unit {unit['key']!r}: unknown module {entry['module']!r}")
        unit["module"] = entry["module"]
        unit["map_entry"] = entry
    recomputed = {u["key"] for u in units}
    for key in top_by_key:
        if key not in recomputed:
            raise MoveError("E3", f"map top unit {key!r} has no base unit")
    pkg.top_units = units

    for unit in units:
        for node in unit["nodes"]:
            pkg.old_top_level_bound.update(_bound_names(node))
            for sub in ast.walk(node):
                if isinstance(sub, (ast.Import, ast.ImportFrom)):
                    for alias in sub.names:
                        pkg.old_top_level_bound.add(_bound_name(alias))
        if unit["kind"] in _IMPORT_KINDS:
            pkg.import_units.append(unit)
            for node in unit["nodes"]:
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    for alias in node.names:
                        pkg.import_by_name[_bound_name(alias)] = (node, alias)
        elif unit["kind"] == "If":
            pkg.if_units.append(unit)
            for node in unit["nodes"]:
                for sub in ast.walk(node):
                    if isinstance(sub, ast.ImportFrom):
                        pkg.typechecking_nodes.append(sub)
                        for alias in sub.names:
                            pkg.typechecking_names |= {_bound_name(alias)}
        elif unit["kind"] == "Expr":
            pkg.docstring_unit = unit

    for unit in units:
        if unit["kind"] in _IMPORT_KINDS or unit["kind"] in ("If", "Expr"):
            continue
        for name in unit["names"]:
            pkg.home_by_name[name] = (unit["module"], unit["start"])
    for idx, module in enumerate(pkg.mixin_order):
        pkg.home_by_name[_mixin_class(module)] = (module, idx)


def _check_mixin_methods(pkg: Package, plan_map) -> None:
    for unit in pkg.method_units:
        module = unit["module"]
        if module not in pkg.mixin_order:
            continue
        node = unit["node"]
        for name in ast.walk(node):
            if (isinstance(name, ast.Name) and name.id == "S19TuiApp"
                    and isinstance(name.ctx, ast.Load)
                    and not pkg.resolver.in_annotation(name)):
                raise MoveError("E7", f"method {unit['name']!r} loads S19TuiApp at line {name.lineno}")
        for decorator in node.decorator_list:
            is_on = (isinstance(decorator, ast.Call)
                     and isinstance(decorator.func, ast.Name)
                     and decorator.func.id == "on")
            is_textual_on = (isinstance(decorator, ast.Call)
                             and isinstance(decorator.func, ast.Attribute)
                             and decorator.func.attr == "on"
                             and isinstance(decorator.func.value, ast.Name)
                             and decorator.func.value.id == "textual")
            if is_on or is_textual_on:
                raise MoveError("E8", f"method {unit['name']!r} has a Textual @on decorator")
        if plan_map.has_zero_arg_super(node):
            raise MoveError("E9", f"method {unit['name']!r} has a zero-argument super()")


def _check_handler_split(pkg: Package) -> None:
    modules = {u["name"]: u["module"] for u in pkg.method_units}
    for name, module in modules.items():
        other = "_" + name if name.startswith("on_") else \
            name[1:] if name.startswith("_on_") else None
        if other and other in modules and modules[other] != module:
            raise MoveError("E10", f"{name!r} and {other!r} are assigned to different classes")


def _check_unique_names(pkg: Package) -> None:
    by_name: dict[str, list[dict]] = {}
    for unit in pkg.method_units + pkg.class_stmt_units:
        by_name.setdefault(unit["name"], []).append(unit)
    for name, group in by_name.items():
        if len(group) == 1:
            continue
        same_module = len({u["module"] for u in group}) == 1
        if _property_group(group) and same_module:
            continue
        raise MoveError("E11", f"name {name!r} bound in multiple classes "
                        f"({', '.join(sorted({u['module'] for u in group}))})")


def _derive_class_body(pkg: Package, plan_map, map_pkg: dict,
                       allowed_body: set[str]) -> None:
    cls_unit = next(u for u in pkg.top_units if u["key"] == "S19TuiApp")
    cls = cls_unit["nodes"][0]
    pkg.cls = cls
    munits = plan_map.method_units(cls)
    methods_by_key: dict[tuple[str, int], list[dict]] = {}
    for entry in map_pkg["methods"]:
        methods_by_key.setdefault((entry["name"], entry["line"]), []).append(entry)
    stmts_by_key: dict[tuple[str, int], list[dict]] = {}
    for entry in map_pkg["class_statements"]:
        stmts_by_key.setdefault((entry["name"], entry["line"]), []).append(entry)

    for unit in munits:
        key = (unit["name"], unit["node"].lineno)
        entries = methods_by_key.get(key, []) if unit["kind"] == "method" \
            else stmts_by_key.get(key, [])
        if not entries:
            raise MoveError("E3", f"class unit {unit['name']!r}@{unit['node'].lineno} missing from map")
        if len(entries) > 1:
            raise MoveError("E4", f"class unit {unit['name']!r}@{unit['node'].lineno} duplicated in map")
        entry = entries[0]
        _match_span((unit["start"], unit["end"]), entry["span"],
                    f"class unit {unit['name']!r}")
        if entry["module"] not in allowed_body:
            raise MoveError("E5", f"class unit {unit['name']!r}: unknown module {entry['module']!r}")
        unit["module"] = entry["module"]

    pkg.method_units = [u for u in munits if u["kind"] == "method"]
    pkg.class_stmt_units = [u for u in munits if u["kind"] == "class_stmt"]
    recomputed_methods = {(u["name"], u["node"].lineno) for u in pkg.method_units}
    for key in methods_by_key:
        if key not in recomputed_methods:
            raise MoveError("E3", f"map method {key[0]!r}@{key[1]} has no base unit")
    recomputed_stmts = {(u["name"], u["node"].lineno) for u in pkg.class_stmt_units}
    for key in stmts_by_key:
        if key not in recomputed_stmts:
            raise MoveError("E3", f"map class statement {key[0]!r}@{key[1]} has no base unit")

    err = check_e6(pkg.module_table, set(pkg.d1_names))
    if err:
        raise MoveError("E6", err)
    _check_mixin_methods(pkg, plan_map)
    _check_handler_split(pkg)
    _check_unique_names(pkg)


def derive_package(repo: str, rev: str, old_path: str, name: str, map_pkg: dict,
                   plan_map, is_app: bool, mixin_order: list[str] | None) -> Package:
    from move_common import APP_BASE_MODULES, SDB_BASE_MODULES
    pkg = _init_package(repo, rev, old_path, name, map_pkg, plan_map, is_app, mixin_order)
    allowed_top = set(APP_BASE_MODULES) | set(pkg.mixin_order) | {"imports"} \
        if is_app else set(SDB_BASE_MODULES) | {"imports"}
    allowed_body = {"core"} | set(pkg.mixin_order) if is_app else set(SDB_BASE_MODULES)
    _derive_top_units(pkg, plan_map, map_pkg, allowed_top)
    if is_app:
        _derive_class_body(pkg, plan_map, map_pkg, allowed_body)
    return pkg
