"""Acceptance self-check for the mover (parse, fresh imports, graph, re-exports, caps)."""
from __future__ import annotations

import ast
import json
import subprocess

CAP_BASE = 2200
CAP_CLASS_EXTRA = 500


def _package_modules(files: dict[str, str], pkg_dir: str) -> list[str]:
    prefix = pkg_dir + "/"
    return sorted(
        rel[len(prefix): -len(".py")]
        for rel in files
        if rel.startswith(prefix) and not rel.endswith("__init__.py")
    )


def _allowed_targets(pkg, module: str) -> set[str]:
    if pkg.is_app:
        if module == "core":
            return {"deps", "shared", "shared_io"} | set(pkg.mixin_order)
        if module in pkg.mixin_order:
            return {"deps", "shared", "shared_io"}
        if module == "deps":
            return {"shared"}
        if module == "shared":
            return set()
        if module == "shared_io":
            return {"deps", "shared"}
    else:
        if module in ("deps", "shared"):
            return set()
        if module == "map_parts":
            return {"shared", "deps"}
        if module == "memory_map":
            return {"shared", "deps", "map_parts"}
        return {"shared", "deps"}
    return set()


def _static_graph(files: dict[str, str], pkg, pkg_dir: str):
    modules = _package_modules(files, pkg_dir)
    graph: dict[str, set[str]] = {m: set() for m in modules}
    for module in modules:
        tree = ast.parse(files[f"{pkg_dir}/{module}.py"])
        for node in tree.body:
            if isinstance(node, ast.ImportFrom) and node.level == 1:
                target = node.module or node.names[0].name
                graph[module].add(target)
    return graph, modules


def _find_cycle(graph: dict[str, set[str]]) -> list[str] | None:
    color: dict[str, int] = {}
    stack: list[str] = []

    def visit(v):
        color[v] = 1
        stack.append(v)
        for w in sorted(graph.get(v, ())):
            if color.get(w) == 1:
                return stack[stack.index(w):] + [w]
            if w not in color:
                found = visit(w)
                if found:
                    return found
        stack.pop()
        color[v] = 2
        return None

    for v in sorted(graph):
        if v not in color:
            found = visit(v)
            if found:
                return found
    return None


def _fresh_imports(files, tree: str, py: str, env: dict, pkg, pkg_dir: str):
    dotted = pkg.name
    modules = _package_modules(files, pkg_dir)
    targets = [dotted] + [f"{dotted}.{m}" for m in modules]
    ok = 0
    failures: list[str] = []
    for target in targets:
        proc = subprocess.run(
            [py, "-c", f"import {target}"], cwd=tree, env=env,
            stdin=subprocess.DEVNULL, capture_output=True)
        if proc.returncode == 0:
            ok += 1
        else:
            failures.append(target)
    return ok, len(targets), failures


def _reexport_missing(files, tree: str, py: str, env: dict, pkg, pkg_dir: str) -> int:
    names = json.dumps(pkg.reexports)
    code = (f"import {pkg.name} as p, json; "
            f"ns = json.loads({names!r}); "
            f"print(sum(1 for n in ns if not hasattr(p, n)))")
    proc = subprocess.run([py, "-c", code], cwd=tree, env=env,
                          stdin=subprocess.DEVNULL, capture_output=True)
    if proc.returncode != 0:
        return len(pkg.reexports)
    try:
        return int(proc.stdout.decode().strip())
    except ValueError:
        return len(pkg.reexports)


def _caps_over(files: dict[str, str], pkg, pkg_dir: str) -> list[str]:
    modules = _package_modules(files, pkg_dir) + ["__init__"]
    over: list[str] = []
    for module in modules:
        rel = f"{pkg_dir}/{module}.py"
        text = files[rel]
        lines = text.count("\n")
        cap = CAP_BASE
        try:
            tree = ast.parse(text)
            biggest = 0
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    biggest = max(biggest, node.end_lineno - node.lineno + 1)
            cap = max(CAP_BASE, biggest + CAP_CLASS_EXTRA)
        except SyntaxError:
            cap = CAP_BASE
        if lines > cap:
            over.append(f"{rel}: {lines} > {cap}")
    return over


def _bound_name(alias: ast.alias) -> str:
    return (alias.asname or alias.name).split(".")[0]


def _deps_used_and_bound(files: dict[str, str], pkg_dir: str) -> tuple[set[str], set[str]]:
    """Return ``(used, bound)`` for one package's deps seam (static, ast)."""
    used: set[str] = set()
    for rel, text in files.items():
        if not rel.startswith(pkg_dir + "/") or not rel.endswith(".py"):
            continue
        tree = ast.parse(text)
        for node in ast.walk(tree):
            if (isinstance(node, ast.Attribute)
                    and isinstance(node.value, ast.Name)
                    and node.value.id == "deps"
                    and isinstance(node.ctx, ast.Load)):
                used.add(node.attr)

    deps_text = files[f"{pkg_dir}/deps.py"]
    bound: set[str] = set()
    tree = ast.parse(deps_text)
    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(stmt.name)
        elif isinstance(stmt, (ast.Import, ast.ImportFrom)):
            bound.update(_bound_name(a) for a in stmt.names)
        else:
            targets = (stmt.targets if isinstance(stmt, ast.Assign)
                       else [stmt.target] if isinstance(stmt, ast.AnnAssign) else [])
            for target in targets:
                bound.update(n.id for n in ast.walk(target) if isinstance(n, ast.Name))
    return used, bound


def run_acceptance(files: dict[str, str], tree: str, py: str, env: dict,
                   app, sdb):
    """Return ``(ok, metrics, fail_lines)``."""
    metrics = {"imports_ok": 0, "imports_total": 0, "cycles": 0,
               "reexports_missing": 0, "caps_over": 0,
               "deps_bound": []}
    fails: list[str] = []

    for rel, text in sorted(files.items()):
        try:
            ast.parse(text)
        except SyntaxError as exc:
            fails.append(f"MOVE FAIL E14: {rel}: {exc}")

    imports_ok = imports_total = 0
    for pkg, pkg_dir in ((app, "s19_app/tui/app"),
                         (sdb, "s19_app/tui/screens_directionb")):
        graph, modules = _static_graph(files, pkg, pkg_dir)
        cyc = _find_cycle(graph)
        if cyc:
            metrics["cycles"] += 1
            fails.append(f"MOVE FAIL cycle: {' -> '.join(cyc)}")
        for module in modules:
            for target in sorted(graph[module] - _allowed_targets(pkg, module)):
                fails.append(f"MOVE FAIL direction: {module} -> {target}")

        ok, total, bad = _fresh_imports(files, tree, py, env, pkg, pkg_dir)
        imports_ok += ok
        imports_total += total
        for target in bad:
            fails.append(f"MOVE FAIL fresh import: {target}")

        metrics["reexports_missing"] += _reexport_missing(files, tree, py, env, pkg, pkg_dir)
        caps = _caps_over(files, pkg, pkg_dir)
        metrics["caps_over"] += len(caps)
        for item in caps:
            fails.append(f"MOVE FAIL cap: {item}")

        used, bound = _deps_used_and_bound(files, pkg_dir)
        matched = used & bound
        for name in sorted(used - bound):
            fails.append(f"MOVE FAIL deps-bound: {pkg.name} deps.{name} used but not bound in deps.py")
        metrics["deps_bound"].append((pkg.name, len(matched), len(used)))

    metrics["imports_ok"] = imports_ok
    metrics["imports_total"] = imports_total
    if metrics["reexports_missing"]:
        fails.append(f"MOVE FAIL reexports: {metrics['reexports_missing']} missing")
    ok = not fails
    return ok, metrics, fails
