"""V18 (names resolve) and V19 (TYPE_CHECKING shape) - review F2 / F5, spec-verify.md A.3.

Static half of V18: every module-global Load (any scope, annotations excluded) of a new module is bound at its
top level, or is a builtin the old module did not shadow; every `deps.X` used in a package is bound by deps.py.
The runtime half (hasattr / identity on the imported deps module) is run by verify_runtime.equivalence_checks.
"""
from __future__ import annotations

import ast
import builtins
import symtable
from collections import defaultdict

import verify_scope as scope

Fail = tuple[str, str]
BUILTINS = set(dir(builtins)) | {"__name__", "__file__", "__doc__", "__package__", "__spec__", "__loader__",
                                 "__builtins__", "__path__", "__annotations__"}


def top_bound(text: str) -> tuple[set[str], bool]:
    """Names bound at module top level (binding, import, def/class, `global` declaration); has `import *`?"""
    top = symtable.symtable(text, "<module>", "exec")
    names = {s.get_name() for s in top.get_symbols() if s.is_assigned() or s.is_imported() or s.is_namespace()}
    tree = ast.parse(text)
    names |= {n for g in ast.walk(tree) if isinstance(g, ast.Global) for n in g.names}
    star = any(isinstance(n, ast.ImportFrom) and any(a.name == "*" for a in n.names) for n in tree.body)
    return names, star


def unresolved(text: str, old_bound: set[str]) -> dict[str, list[int]]:
    bound, star = top_bound(text)
    if star:
        return {}
    _, sites = scope.global_loads(text, None)
    return {n: ls for n, ls in sites.items() if n not in bound and not (n in BUILTINS and n not in old_bound)}


def deps_attr_sites(parsed: dict) -> dict[str, list[tuple[str, int]]]:
    """Every `deps.<X>` Load in the non-deps modules: X -> [(stem, line)]."""
    out: dict[str, list[tuple[str, int]]] = defaultdict(list)
    for stem, mod in parsed.items():
        if stem == "deps":
            continue
        for n in ast.walk(mod):
            if (isinstance(n, ast.Attribute) and isinstance(n.ctx, ast.Load)
                    and isinstance(n.value, ast.Name) and n.value.id == "deps"):
                out[n.attr].append((stem, n.lineno))
    return out


def names_checks(pkg: str, old_text: str, texts: dict[str, str], parsed: dict) -> tuple[list[Fail], set[str]]:
    """Static V18. Returns (fails, deps attribute names already reported missing)."""
    old_bound, _ = top_bound(old_text)
    fails: list[Fail] = []
    for stem in sorted(parsed):
        for name, lines in sorted(unresolved(texts[stem], old_bound).items()):
            fails.append(("V18", f"{pkg}/{stem}.py:{lines[0]}: global name {name} is used ({len(lines)} sites) "
                                 f"but is not bound at the module's top level"))
    missing: set[str] = set()
    if "deps" in parsed:
        dbound, dstar = top_bound(texts["deps"])
        for attr, sites in sorted(deps_attr_sites(parsed).items()):
            if attr in dbound or dstar:
                continue
            missing.add(attr)
            stem, line = sites[0]
            fails.append(("V18", f"{pkg}/deps.py binds no {attr}, but deps.{attr} is loaded ({len(sites)} sites, "
                                 f"first {stem}.py:{line})"))
    return fails, missing


def imported_names(text: str) -> set[str]:
    out: set[str] = set()
    for n in ast.parse(text).body:
        if isinstance(n, ast.Import):
            out |= {(a.asname or a.name).split(".")[0] for a in n.names}
        elif isinstance(n, ast.ImportFrom):
            out |= {a.asname or a.name for a in n.names if a.name != "*"}
    return out


def runtime_spec(pkg: str, old_text: str, parsed: dict, d1: set[str], already_missing: set[str]) -> dict:
    """Probe spec for the runtime half of V18 (deps_module is empty when the package has no deps.py)."""
    if "deps" not in parsed:
        return {}
    attrs = sorted(set(deps_attr_sites(parsed)) - already_missing)
    return {"deps_module": f"s19_app.tui.{pkg}.deps", "deps_attrs": attrs,
            "imported_d1": sorted((imported_names(old_text) & d1) - already_missing)}


def _is_tc(n: ast.stmt) -> bool:
    if not isinstance(n, ast.If):
        return False
    t = n.test
    return (isinstance(t, ast.Name) and t.id == "TYPE_CHECKING") or (isinstance(t, ast.Attribute) and t.attr == "TYPE_CHECKING")


def type_checking_shape(label: str, mod: ast.Module) -> list[Fail]:
    """V19: top-level `if TYPE_CHECKING:` blocks are import-only with no else branch (the inventory skips them whole)."""
    out: list[Fail] = []
    for n in mod.body:
        if not _is_tc(n):
            continue
        if n.orelse:
            out.append(("V19", f"{label}:{n.lineno}: `if TYPE_CHECKING:` has an else branch"))
        bad = [x for x in n.body if not isinstance(x, (ast.Import, ast.ImportFrom))]
        out += [("V19", f"{label}:{x.lineno}: non-import statement ({type(x).__name__}) under TYPE_CHECKING") for x in bad]
    return out
