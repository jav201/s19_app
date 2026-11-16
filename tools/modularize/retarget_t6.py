"""T6 detection shared by ``test_patch_census`` and ``retarget_tests``.

T6 covers a module alias passed as an ARGUMENT to a patching helper: a callable
defined in the same test file whose body ``setattr``/``delattr``/``patch.object``
one of its parameters (the owner) with another parameter (the name).  The patch
census counts each string-constant name passed together with the alias as a
patch site of that name (RC-B); the retargeter rewrites the alias to ``.deps``
when the name is a D1 name of the alias's package and refuses R5 otherwise.

Pure AST helpers: no ``s19_app`` import, no dependency on ``test_patch_census``,
``retarget_scan`` or ``retarget_t5``.  The module-alias resolution is injected by
the caller so this leaf stays importable by the census itself.
"""
from __future__ import annotations

import ast
from collections import namedtuple

# ``node`` is the callable a test invokes (FunctionDef / AsyncFunctionDef /
# ClassDef); ``call_params`` is the positional parameter list as seen at a call
# site (``self``/``cls`` of a helper method dropped).
HelperInfo = namedtuple("HelperInfo", "node owner_param name_param call_params")

_PATCH_FUNCS = {"setattr", "delattr", "object"}  # "object" -> patch.object


def dotted(node: ast.AST) -> str | None:
    """The dotted name of an attribute chain / Name, or None."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _is_patch_func(func: ast.AST) -> bool:
    last = (dotted(func) or "").rsplit(".", 1)[-1]
    if last in ("setattr", "delattr"):
        return True
    return last == "object" and isinstance(func, ast.Attribute)


def _call_params(fn: ast.AST, is_method: bool) -> list[str]:
    a = fn.args
    names = [x.arg for x in (*a.posonlyargs, *a.args)]
    if is_method and names and names[0] in ("self", "cls"):
        names = names[1:]
    return names


def _patch_param_pair(fn: ast.AST, param_set: set[str]) -> tuple[str, str] | None:
    """The (owner, name) parameters of the first patch call on parameters."""
    for node in ast.walk(fn):
        if (isinstance(node, ast.Call) and _is_patch_func(node.func)
                and len(node.args) >= 2):
            a0, a1 = node.args[0], node.args[1]
            if (isinstance(a0, ast.Name) and a0.id in param_set
                    and isinstance(a1, ast.Name) and a1.id in param_set):
                return a0.id, a1.id
    return None


def patching_helpers(tree: ast.AST) -> dict[str, HelperInfo]:
    """Callables defined in ``tree`` that patch ``owner.<name>`` on parameters.

    First definition of a name wins (module-level defs are walked first).
    """
    helpers: dict[str, HelperInfo] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            params = set(_call_params(node, False))
            pair = _patch_param_pair(node, params)
            if pair:
                helpers.setdefault(
                    node.name,
                    HelperInfo(node, pair[0], pair[1], _call_params(node, False)))
        elif isinstance(node, ast.ClassDef):
            init = next((m for m in node.body
                         if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))
                         and m.name == "__init__"), None)
            if init is not None:
                params = set(_call_params(init, True))
                pair = _patch_param_pair(init, params)
                if pair:
                    helpers.setdefault(
                        node.name,
                        HelperInfo(node, pair[0], pair[1], _call_params(init, True)))
    return helpers


def arg_for_param(call: ast.Call, info: HelperInfo, param_name: str) -> ast.expr | None:
    """The argument node bound to ``param_name`` at ``call``, or None.

    None also signals "undetermined" (``*args`` / ``**kwargs`` could supply it)
    or a missing argument, both of which the T6 resolver treats as refusing.
    Positional arguments win over a trailing ``**kwargs`` so that
    ``Hold(mp, app_module, "X", **kw)`` still resolves its owner and name.
    """
    for kw in call.keywords:
        if kw.arg == param_name:
            return kw.value
    idx = info.call_params.index(param_name) if param_name in info.call_params else None
    if idx is not None and idx < len(call.args):
        if not any(isinstance(a, ast.Starred) for a in call.args[:idx + 1]):
            return call.args[idx]
    if any(isinstance(a, ast.Starred) for a in call.args):
        return None
    if any(kw.arg is None for kw in call.keywords):
        return None
    return None


def parent_map(tree: ast.AST) -> dict:
    """Map every AST node to its parent."""
    parents: dict = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    return parents


def _target_binds(target: ast.AST, name: str) -> bool:
    return any(isinstance(n, ast.Name) and n.id == name for n in ast.walk(target))


def _iterable_constants(iter_node: ast.AST) -> set[str] | None:
    """All string constants of a literal tuple/list/set iterable, or None."""
    if isinstance(iter_node, (ast.Tuple, ast.List, ast.Set)):
        vals: set[str] = set()
        for elt in iter_node.elts:
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                vals.add(elt.value)
            else:
                return None
        return vals
    if isinstance(iter_node, ast.Constant) and isinstance(iter_node.value, str):
        return {iter_node.value}
    return None


def name_bindings(tree: ast.AST) -> dict[str, ast.expr]:
    """Simple-name assignment targets -> value expression (first wins)."""
    out: dict[str, ast.expr] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                and isinstance(node.targets[0], ast.Name):
            out.setdefault(node.targets[0].id, node.value)
    return out


def resolve_name_values(node: ast.AST, parents: dict, bindings: dict) -> set[str] | None:
    """The set of string constants ``node`` can name, or None if unresolvable.

    Covers a string constant, a comprehension/for-loop variable iterating over a
    literal tuple/list/set of constants, and (one step) a simple-name assignment
    to any of those.  Anything else is None (non-constant).
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return {node.value}
    if isinstance(node, ast.Name):
        cur: ast.AST = node
        while cur in parents:
            parent = parents[cur]
            if isinstance(parent, (ast.ListComp, ast.SetComp, ast.DictComp,
                                   ast.GeneratorExp)):
                for gen in parent.generators:
                    if _target_binds(gen.target, node.id):
                        return _iterable_constants(gen.iter)
                cur = parent
                continue
            if isinstance(parent, (ast.For, ast.AsyncFor)):
                if _target_binds(parent.target, node.id):
                    return _iterable_constants(parent.iter)
                cur = parent
                continue
            cur = parent
        if node.id in bindings:
            return resolve_name_values(bindings[node.id], parents, bindings)
    return None


def find_t6_calls(tree: ast.AST, resolve):
    """Yield ``(call, info, mod, owner_arg, name_values)`` for every T6 call.

    ``resolve(expr)`` maps an expression to a package module string (or None);
    the caller supplies it from its alias table.  ``name_values`` is the
    ``resolve_name_values`` result (a set, or None when non-constant).
    """
    helpers = patching_helpers(tree)
    parents = parent_map(tree)
    bindings = name_bindings(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        info = helpers.get(node.func.id)
        if info is None:
            continue
        owner_arg = arg_for_param(node, info, info.owner_param)
        if owner_arg is None:
            continue
        mod = resolve(owner_arg)
        if mod is None:
            continue
        name_arg = arg_for_param(node, info, info.name_param)
        name_values = resolve_name_values(name_arg, parents, bindings) \
            if name_arg is not None else None
        yield node, info, mod, owner_arg, name_values
