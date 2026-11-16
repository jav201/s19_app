"""Static checks: V8 placement, V10 header, V12 old files, V14 acyclic + direction, V15 caps."""
from __future__ import annotations

import ast
from pathlib import Path

from verify_units import CLASS, DOC_KEY, NEW_DIRS, Unit

OLD_FILES = ("s19_app/tui/app.py", "s19_app/tui/screens_directionb.py")
CAP_MODULE_LINES = 2200
CAP_CLASS_PLUS = 500


def placement_index(mapd: dict, pkg: str) -> dict[str, list[str]]:
    """unit key -> target module(s), straight from the module map."""
    sec = mapd[pkg]
    idx: dict[str, list[str]] = {}
    for m in sec.get("methods", []):
        idx.setdefault(f"{CLASS}.{m['name']}", []).append(m["module"])
    for m in sec.get("class_statements", []):
        idx.setdefault(f"{CLASS}.{m['name']}", []).append(m["module"])
    for t in sec["top"]:
        key = DOC_KEY if (t["kind"] == "Expr" and t["module"] == "__init__") else t["key"]
        idx.setdefault(key, []).append(t["module"])
    return idx


def check_placement(pairs: list[tuple[Unit, Unit]], idx: dict[str, list[str]]) -> list[str]:
    out = []
    seen: dict[str, int] = {}
    for old, new in pairs:
        want = idx.get(old.key)
        if not want:
            out.append(f"{old.key}: not listed in module-map.json")
            continue
        i = seen.get(old.key, 0)
        seen[old.key] = i + 1
        wanted = want[min(i, len(want) - 1)]
        if wanted != new.stem:
            out.append(f"{old.key}: sits in {new.stem}.py (line {new.line}), map says {wanted}.py")
    return out


def old_files_present(tree: Path) -> list[str]:
    return [f for f in OLD_FILES if (tree / f).exists()]


def header_bases(mapd: dict) -> list[str]:
    mod = ast.parse(mapd["app"]["class_header"] + "\n    pass\n")
    return [ast.unparse(b) for b in mod.body[0].bases]


def check_header(core_cls: ast.ClassDef | None, mapd: dict) -> list[str]:
    if core_cls is None:
        return [f"class {CLASS} not found in core.py"]
    want = header_bases(mapd)
    got = [ast.unparse(b) for b in core_cls.bases]
    bad = []
    if got != want:
        bad.append(f"{CLASS} bases {got} != map header {want}")
    if core_cls.keywords or core_cls.decorator_list:
        bad.append(f"{CLASS} has keywords or decorators")
    return bad


def _resolve(pkg_dotted: str, node: ast.ImportFrom, files: set[str]) -> tuple[str | None, str | None]:
    """(internal stem or None, problem or None) for one top-level ImportFrom."""
    if node.level == 1 and node.module:
        return node.module.split(".")[0], None
    if node.level == 0 and node.module and node.module.startswith(pkg_dotted):
        rest = node.module[len(pkg_dotted):].lstrip(".")
        return (rest.split(".")[0], None) if rest else (None, "imports from the package __init__")
    return None, None


def import_edges(pkg_dotted: str, mod: ast.Module, files: set[str]) -> tuple[set[str], list[str]]:
    edges: set[str] = set()
    probs: list[str] = []
    for n in mod.body:
        if not isinstance(n, ast.ImportFrom):
            continue
        if n.level == 1 and not n.module:
            for a in n.names:
                (edges.add(a.name) if a.name in files else probs.append(f"imports {a.name!r} from the package __init__"))
            continue
        stem, prob = _resolve(pkg_dotted, n, files)
        if prob:
            probs.append(prob)
        if stem:
            edges.add(stem)
    return edges, probs


def allowed_targets(stem: str) -> set[str] | None:
    if stem in ("__init__", "core"):
        return None
    table = {"shared": set(), "deps": {"shared"}, "shared_io": {"shared", "deps"}, "map_parts": {"shared"}}
    if stem in table:
        return table[stem]
    base = {"shared", "shared_io", "deps"}
    return base | {"map_parts"} if stem == "memory_map" else base


def find_cycle(g: dict[str, set[str]]) -> list[str] | None:
    state: dict[str, int] = {}
    stack: list[str] = []

    def dfs(v: str) -> list[str] | None:
        state[v] = 1
        stack.append(v)
        for w in sorted(g.get(v, ())):
            if state.get(w) == 1:
                return stack[stack.index(w):] + [w]
            if state.get(w) is None and (c := dfs(w)):
                return c
        stack.pop()
        state[v] = 2
        return None

    for v in sorted(g):
        if state.get(v) is None and (c := dfs(v)):
            return c
    return None


def check_graph(pkg: str, parsed: dict[str, ast.Module]) -> list[str]:
    dotted = f"s19_app.tui.{pkg}"
    files = set(parsed)
    graph: dict[str, set[str]] = {}
    out: list[str] = []
    for stem, mod in sorted(parsed.items()):
        edges, probs = import_edges(dotted, mod, files)
        graph[stem] = edges
        out += [f"{stem}.py {p}" for p in probs]
        allowed = allowed_targets(stem)
        for e in sorted(edges):
            if e == "__init__" or (allowed is not None and e not in allowed):
                out.append(f"{stem}.py imports {e}: breaks the I-1 direction rule")
    cyc = find_cycle(graph)
    return out + ([f"cycle: {' -> '.join(cyc)}"] if cyc else [])


def check_caps(pkg: str, texts: dict[str, str], parsed: dict[str, ast.Module]) -> list[str]:
    out = []
    for stem, text in sorted(texts.items()):
        lines = len(text.splitlines())
        biggest = max([(n.end_lineno - n.lineno + 1) for n in parsed[stem].body if isinstance(n, ast.ClassDef)] or [0])
        cap = max(CAP_MODULE_LINES, biggest + CAP_CLASS_PLUS)
        if lines > cap:
            out.append(f"{pkg}/{stem}.py has {lines} lines > cap {cap} (largest class {biggest})")
    return out


def new_dir(tree: Path, pkg: str) -> Path:
    return tree / NEW_DIRS[pkg]
