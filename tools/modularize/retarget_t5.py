"""T5 rewrite detection and resolution for ``retarget_tests`` (read-only).

T5 covers a ``setattr`` / ``getattr`` / ``delattr`` / ``patch.object`` call whose
second argument is a parameter of the enclosing named function: the module
alias is rewritten to ``.deps`` only when every direct (simple-name) call of
that function in the same file passes a D1 string constant for the parameter.
Mixed D1/non-D1 constants, a non-constant argument, any other reference to the
function, or zero calls all refuse.

Pure AST helpers: no ``s19_app`` import and no dependency on ``retarget_scan``.
``process_t5`` returns plain call nodes; the caller turns them into edits and
refusals with its own source/position primitives.
"""
from __future__ import annotations

import ast
from collections import namedtuple

T5Candidate = namedtuple("T5Candidate", "func pname call mod")


def parent_map(tree: ast.AST) -> dict:
    """Map every AST node to its parent."""
    parents: dict = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    return parents


def _param_names(node: ast.AST) -> list[str]:
    """Parameter names of a function/lambda signature."""
    a = node.args
    ids = [x.arg for x in (*a.posonlyargs, *a.args, *a.kwonlyargs)]
    if a.vararg:
        ids.append(a.vararg.arg)
    if a.kwarg:
        ids.append(a.kwarg.arg)
    return ids


def declaring_function(name: ast.Name, parents: dict):
    """The named function whose signature declares ``name``, or ``None``.

    ``None`` means either the name is not a parameter of any enclosing scope or
    its declaring scope is a lambda (which cannot be collected by simple name),
    so the site is not a T5 candidate.
    """
    node: ast.AST = name
    while node in parents:
        node = parents[node]
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if name.id in _param_names(node):
                return node
        elif isinstance(node, ast.Lambda):
            if name.id in _param_names(node):
                return None
    return None


def _arg_for_param(call: ast.Call, pname: str, pos_index: int | None):
    """Return the argument node bound to ``pname`` at ``call``, or ``None``.

    ``None`` also signals "undetermined" (``*args``/``**kwargs``) or a missing
    argument, both of which T5 refuses.
    """
    for kw in call.keywords:
        if kw.arg == pname:
            return kw.value
    for kw in call.keywords:
        if kw.arg is None:
            return None
    for a in call.args:
        if isinstance(a, ast.Starred):
            return None
    if pos_index is not None and pos_index < len(call.args):
        return call.args[pos_index]
    return None


def process_t5(tree: ast.AST, parents: dict, candidates: list, d1: dict[str, set[str]]):
    """Resolve T5 candidates into ``(rewrite_calls, refusal_nodes)``.

    Group candidate sites by ``(enclosing function, parameter)``. For each
    group, collect every direct (simple-name) call of the function in the file
    and look at the value each call passes for the parameter. All-D1 constants
    rewrite every candidate of the group; all non-D1 leaves them unchanged;
    anything else refuses R1.
    """
    groups: dict = {}
    for cand in candidates:
        groups.setdefault((id(cand.func), cand.pname), []).append(cand)

    rewrite_calls: list = []
    refusal_nodes: list = []

    for (_, pname), cands in groups.items():
        func = cands[0].func
        mod = cands[0].mod
        pos_names = [a.arg for a in (*func.args.posonlyargs, *func.args.args)]
        pos_index = pos_names.index(pname) if pname in pos_names else None

        direct_calls: list = []
        other_refs: list = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id == func.name:
                parent = parents.get(node)
                if (isinstance(node.ctx, ast.Load) and isinstance(parent, ast.Call)
                        and parent.func is node):
                    direct_calls.append(parent)
                else:
                    other_refs.append(node)
            elif isinstance(node, ast.Attribute) and node.attr == func.name:
                other_refs.append(node)

        if not direct_calls:
            refusal_nodes.append(cands[0].call)
            continue
        if other_refs:
            refusal_nodes.append(other_refs[0])
            continue

        values: list = []
        ok = True
        for call in direct_calls:
            arg = _arg_for_param(call, pname, pos_index)
            if not (isinstance(arg, ast.Constant) and isinstance(arg.value, str)):
                refusal_nodes.append(call)
                ok = False
                break
            values.append(arg.value)
        if not ok:
            continue

        in_d1 = [v in d1[mod] for v in values]
        if all(in_d1):
            rewrite_calls.extend(cand.call for cand in cands)
        elif any(in_d1):
            refusal_nodes.append(cands[0].call)

    return rewrite_calls, refusal_nodes
