"""Generate the new package files from two validated Packages."""
from __future__ import annotations

import ast

from move_common import MoveError
from move_names import (module_units, role, self_bound, used_names, _bound_name,
                        _mixin_class, string_annotation_names)
from move_rewrite import rewrite_unit

_TOP_SKIP = ("Import", "ImportFrom", "If", "Expr")


def _strip_leading_blanks(text: str) -> str:
    lines = text.splitlines(keepends=True)
    i = 0
    while i < len(lines) and not lines[i].strip():
        i += 1
    return "".join(lines[i:])


def _set_leading_blanks(text: str, n: int) -> str:
    lines = text.splitlines(keepends=True)
    i = 0
    while i < len(lines) and not lines[i].strip():
        i += 1
    return "\n" * n + "".join(lines[i:])


def _alias_text(alias: ast.alias) -> str:
    return alias.name + (f" as {alias.asname}" if alias.asname else "")


def _wrap_from(prefix: str, names: list[str]) -> str:
    line = prefix + ", ".join(names)
    if len(line) <= 99:
        return line
    body = ",\n".join("    " + n for n in names)
    return f"{prefix}(\n{body},\n)"


def _render_import(node: ast.AST, aliases: list[ast.alias]) -> str:
    if isinstance(node, ast.Import):
        return "import " + ", ".join(_alias_text(a) for a in aliases)
    level = node.level + 1 if node.level >= 1 else 0
    dots = "." * level
    module = node.module or ""
    prefix = f"from {dots}{module} import "
    return _wrap_from(prefix, [_alias_text(a) for a in aliases])


def _render_home_import(home: str, names: list[str]) -> str:
    prefix = f"from .{home} import "
    line = prefix + "(" + ", ".join(names) + ")"
    if len(line) <= 99:
        return line
    body = ",\n".join("    " + n for n in names)
    return f"{prefix}(\n{body},\n)"


def _resolve(pkg, module: str, runtime: set[str], annotation: set[str],
             has_d1: bool, module_order: list[str],
             str_ann: set[str] | None = None) -> list[str]:
    import_nodes: dict[int, tuple[ast.AST, set[str]]] = {}
    typechecking_used: set[str] = {n for n in (str_ann or ()) if n in pkg.typechecking_names}
    home_groups: dict[str, list[tuple[str, int]]] = {}

    def place(name: str, strict: bool) -> None:
        if name in pkg.import_by_name:
            node, _alias = pkg.import_by_name[name]
            key = id(node)
            if key not in import_nodes:
                import_nodes[key] = (node, set())
            import_nodes[key][1].add(name)
        elif name in pkg.typechecking_names:
            typechecking_used.add(name)
        elif name in pkg.home_by_name:
            home, line = pkg.home_by_name[name]
            if pkg.is_app and module in pkg.mixin_order and home == "core":
                raise MoveError("E13", f"mixin {module!r} would import {name!r} from core")
            home_groups.setdefault(home, []).append((name, line))
        elif strict:
            raise MoveError("E12", f"module {module!r}: unresolvable name {name!r}")

    for name in runtime:
        place(name, True)
    for name in annotation - runtime:
        place(name, False)

    lines: list[str] = []
    imported_names: set[str] = set()
    for unit in pkg.import_units:
        for node in unit["nodes"]:
            if not isinstance(node, (ast.Import, ast.ImportFrom)):
                continue
            if id(node) not in import_nodes:
                continue
            kept = [a for a in node.names if _bound_name(a) in import_nodes[id(node)][1]]
            if kept:
                lines.append(_render_import(node, kept) + "\n")
                imported_names.update(_bound_name(a) for a in kept)
    if has_d1:
        lines.append("from . import deps\n")
    if typechecking_used:
        if "TYPE_CHECKING" not in imported_names:
            lines.append("from typing import TYPE_CHECKING\n")
        for node in pkg.typechecking_nodes:
            kept = [a for a in node.names if _bound_name(a) in typechecking_used]
            if kept:
                lines.append("if TYPE_CHECKING:\n")
                lines.append("    " + _render_import(node, kept) + "\n")
    for home in module_order:
        if home in home_groups:
            names = [n for n, _ in sorted(home_groups[home], key=lambda nl: nl[1])]
            lines.append(_render_home_import(home, names) + "\n")
    return lines


def _header(pkg, module: str, base_short: str) -> str:
    doc = f'"""{pkg.name}.{module} — {role(pkg, module)} (moved verbatim from {pkg.old_path} at {base_short})."""'
    return doc + "\nfrom __future__ import annotations\n\n"


def _join_top_units(pkg, units: list[dict], module: str) -> tuple[str, list[dict]]:
    out: list[str] = []
    records: list[dict] = []
    for idx, unit in enumerate(units):
        text, recs = rewrite_unit(pkg, unit, module)
        records.extend(recs)
        if idx == 0:
            text = _strip_leading_blanks(text)
        elif unit["kind"] in ("FunctionDef", "AsyncFunctionDef", "ClassDef"):
            text = _set_leading_blanks(text, 2)
        out.append(text)
    return "".join(out), records


def _emit_module(pkg, module: str, base_short: str,
                 module_order: list[str]) -> tuple[str, list[dict]]:
    runtime, annotation, has_d1 = used_names(pkg, module)
    if module == "deps":
        runtime |= {n for n in pkg.d1_names if n in pkg.import_by_name}
    str_ann = string_annotation_names(pkg, module)
    bound = self_bound(pkg, module)
    runtime -= bound
    annotation -= bound
    for name in list(runtime) + list(annotation):
        if name in pkg.builtins and name not in pkg.old_top_level_bound:
            runtime.discard(name)
            annotation.discard(name)
    imports = _resolve(pkg, module, runtime, annotation, has_d1, module_order, str_ann)

    records: list[dict] = []
    if pkg.is_app and module == "core":
        body, records = _core_body(pkg, module)
    elif pkg.is_app and module in pkg.mixin_order:
        top_units = [u for u in pkg.top_units
                     if u["kind"] not in _TOP_SKIP and u["module"] == module]
        body, records = _join_top_units(pkg, top_units, module)
        if top_units:
            body += "\n\n"
        body += f"class {_mixin_class(module)}:\n"
        methods = [u for u in pkg.method_units if u["module"] == module]
        for unit in methods:
            text, recs = rewrite_unit(pkg, unit, module)
            records.extend(recs)
            body += text
    else:
        top_units = [u for u in pkg.top_units
                     if u["kind"] not in _TOP_SKIP and u["module"] == module]
        body, records = _join_top_units(pkg, top_units, module)

    text = _header(pkg, module, base_short) + "".join(imports) + "\n\n" + body
    return text.rstrip("\n") + "\n", records


def _core_body(pkg, module: str) -> tuple[str, list[dict]]:
    records: list[dict] = []
    top_units = [u for u in pkg.top_units
                 if u["kind"] not in _TOP_SKIP and u["module"] == module
                 and u["key"] not in ("S19TuiApp", "main")]
    body, recs = _join_top_units(pkg, top_units, module)
    records.extend(recs)

    cls_unit = next(u for u in pkg.top_units if u["key"] == "S19TuiApp")
    body += "".join(pkg.lines[cls_unit["start"] - 1: pkg.cls.lineno - 1])
    body += pkg.class_header + "\n"

    class_units = sorted(
        [u for u in pkg.method_units + pkg.class_stmt_units if u["module"] == "core"],
        key=lambda u: u["start"])
    for unit in class_units:
        text, recs = rewrite_unit(pkg, unit, module)
        records.extend(recs)
        body += text

    main_unit = next(u for u in pkg.top_units if u["key"] == "main")
    text, recs = rewrite_unit(pkg, main_unit, module)
    records.extend(recs)
    body += text
    return body, records


def _emit_init(pkg, base_short: str, module_order: list[str]) -> tuple[str, list[dict]]:
    if pkg.docstring_unit is not None:
        doc = "".join(pkg.lines[pkg.docstring_unit["start"] - 1: pkg.docstring_unit["end"]])
        doc = doc.rstrip("\n") + "\n"
    else:
        doc = f'"""{pkg.name} — re-exports (moved from {pkg.old_path} at {base_short})."""\n'

    reexport_set = set(pkg.reexports)
    lines: list[str] = []
    home_groups: dict[str, list[tuple[str, int]]] = {}
    for unit in pkg.import_units:
        for node in unit["nodes"]:
            if not isinstance(node, (ast.Import, ast.ImportFrom)):
                continue
            kept = [a for a in node.names if _bound_name(a) in reexport_set]
            if kept:
                lines.append(_render_import(node, kept) + "\n")
    covered = set()
    for unit in pkg.import_units:
        for node in unit["nodes"]:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                covered.update(_bound_name(a) for a in node.names)
    for name in pkg.reexports:
        if name in covered:
            continue
        home, line = pkg.home_by_name[name]
        home_groups.setdefault(home, []).append((name, line))
    for home in module_order:
        if home in home_groups:
            names = [n for n, _ in sorted(home_groups[home], key=lambda nl: nl[1])]
            lines.append(_render_home_import(home, names) + "\n")

    text = doc + "from __future__ import annotations\n\n" + "".join(lines)
    return text.rstrip("\n") + "\n", []


def _module_set(pkg) -> list[str]:
    if pkg.is_app:
        return ["deps", "shared", "shared_io", "core"] + pkg.mixin_order
    return ["deps", "shared", "map_parts", "memory_map", "loaded_artifacts",
            "patch_editor", "check_editor", "ab_diff"]


def build_files(app, sdb, base_sha: str, app_order: list[str],
                sdb_order: list[str]) -> tuple[dict, list, dict, dict]:
    from move_common import APP_OLD, SDB_OLD
    base_short = base_sha[:8]
    files: dict[str, str] = {}
    edits_by_file: dict[str, list[dict]] = {}
    units_total = 0

    for pkg, order, pkg_dir in ((app, app_order, "s19_app/tui/app"),
                                (sdb, sdb_order, "s19_app/tui/screens_directionb")):
        for module in _module_set(pkg):
            text, records = _emit_module(pkg, module, base_short, order)
            rel = f"{pkg_dir}/{module}.py"
            files[rel] = text
            edits_by_file[rel] = records
        init_text, _ = _emit_init(pkg, base_short, order)
        files[f"{pkg_dir}/__init__.py"] = init_text
        edits_by_file[f"{pkg_dir}/__init__.py"] = []
        units_total += len(pkg.top_units)
        units_total += len(pkg.method_units) + len(pkg.class_stmt_units)

    deletions = [APP_OLD, SDB_OLD]

    flat: dict[str, list[dict]] = {}
    for rel, records in edits_by_file.items():
        if records:
            flat[rel] = sorted(records, key=lambda r: (r["line"], r["kind"], r["unit"]))

    counters = {
        "units": units_total,
        "d1": sum(1 for recs in flat.values() for r in recs if r["kind"] == "d1"),
        "relimport": sum(1 for recs in flat.values() for r in recs if r["kind"] == "relimport"),
        "css": sum(1 for recs in flat.values() for r in recs if r["kind"] == "css"),
    }
    if counters["css"] != 1:
        raise MoveError("ECSS", f"expected exactly one CSS_PATH rewrite, found {counters['css']}")
    return files, deletions, flat, counters
