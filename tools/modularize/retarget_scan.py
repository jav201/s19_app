"""AST scanning and text rewriting for ``retarget_tests`` (read-only helpers).

Every function here is a pure detector/rewriter for the D1 seam of the two god
modules; it never imports ``s19_app``. The retargeter CLI in
``retarget_tests.py`` orchestrates the scans and applies the edits. T5
(parameter-driven getattr/setattr/delattr/patch.object) lives in
``retarget_t5.py``.
"""
from __future__ import annotations

import ast
import json
import sys
from collections import defaultdict, namedtuple
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_patch_census as census  # noqa: E402
import retarget_t6 as t6  # noqa: E402
from retarget_t5 import T5Candidate, declaring_function, parent_map, process_t5  # noqa: E402

Edit = namedtuple("Edit", "start end repl kind lineno anchor")
Refusal = namedtuple("Refusal", "code rel lineno src")

_PREFIX_CHARS = set("rubfRUBF")


def load_d1(map_path: Path) -> dict[str, set[str]]:
    """Return ``{package: set(d1_names)}`` for the two packages of the map."""
    data = json.loads(map_path.read_text(encoding="utf-8"))
    return {
        data["app"]["package"]: set(data["app"]["d1_names"]),
        data["screens_directionb"]["package"]: set(data["screens_directionb"]["d1_names"]),
    }


def _byte_to_char(line: str, byte_col: int) -> int:
    """Map an AST byte column to a character column on ``line``."""
    total = 0
    for i, ch in enumerate(line):
        if total >= byte_col:
            return i
        total += len(ch.encode("utf-8"))
    return len(line)


class Source:
    """Turn AST byte positions into character offsets in one file's text."""

    def __init__(self, text: str):
        self.text = text
        self.lines = text.split("\n")
        self.starts = [0]
        for i, ch in enumerate(text):
            if ch == "\n":
                self.starts.append(i + 1)

    def char(self, lineno: int, byte_col: int) -> int:
        return self.starts[lineno - 1] + _byte_to_char(self.lines[lineno - 1], byte_col)

    def line(self, lineno: int) -> str:
        return self.lines[lineno - 1] if 1 <= lineno <= len(self.lines) else ""


def _refusal(code: str, node: ast.AST, source: Source) -> Refusal:
    return Refusal(code, "", node.lineno, source.line(node.lineno))


def _insert_after(source: Source, node: ast.AST, repl: str, kind: str) -> Edit:
    anchor = ast.get_source_segment(source.text, node) or ""
    pos = source.char(node.end_lineno, node.end_col_offset)
    return Edit(pos, pos, repl, kind, node.end_lineno, anchor)


def _value_start(seg: str) -> int:
    """Index of the first value character of a string-literal source segment."""
    i = 0
    while i < len(seg) and seg[i] in _PREFIX_CHARS:
        i += 1
    if seg.startswith('"""', i) or seg.startswith("'''", i):
        return i + 3
    return i + 1


def _insert_in_string(source: Source, node: ast.AST, prefix: str, kind: str) -> Edit:
    seg = ast.get_source_segment(source.text, node) or ""
    idx = seg.find(prefix)
    if idx < 0:
        idx = _value_start(seg)
    start = source.char(node.lineno, node.col_offset)
    pos = start + idx + len(prefix)
    return Edit(pos, pos, "deps.", kind, node.lineno, prefix)


def _is_t1_func(func: ast.AST) -> bool:
    fname = census._dotted(func) or ""
    last = fname.rsplit(".", 1)[-1]
    if last in ("setattr", "delattr"):
        return True
    return last == "object" and isinstance(func, ast.Attribute)


def _is_globals_dict(expr: ast.AST) -> bool:
    return isinstance(expr, ast.Attribute) and expr.attr == "__globals__"


def _globals_base_resolves(expr: ast.AST, aliases: dict[str, str],
                           classes: set[str], bindings: dict) -> bool:
    """True when ``expr`` is (or resolves to) an attribute of P or S19TuiApp.

    Covers ``S19TuiApp.copy_to_clipboard``, ``app_module.copy_to_clipboard`` and
    a simple-name assignment to either (the test_b103_copy_views.py fixture
    binds ``original_entry = S19TuiApp.copy_to_clipboard``).
    """
    if isinstance(expr, ast.Name) and expr.id in bindings:
        return _globals_base_resolves(bindings[expr.id], aliases, classes, bindings)
    d = census._dotted(expr) or ""
    if not d:
        return False
    head = d.split(".", 1)[0]
    return head in classes or head == "S19TuiApp" or head in aliases


def _scan_call(node, source, aliases, classes, bindings, parents, d1, edits,
               refusals, counts, t2_nodes, t5_candidates, dynamic_reads) -> None:
    args = node.args
    if not args:
        return
    fname = census._dotted(node.func) or ""
    last = fname.rsplit(".", 1)[-1]

    # R1 extension: writes through ``<fn>.__globals__`` (RC-C).
    if last in ("setitem", "setattr", "delitem") and args and _is_globals_dict(args[0]):
        if _globals_base_resolves(args[0].value, aliases, classes, bindings):
            refusals.append(_refusal("R1", node, source))

    if last == "vars" and census._resolve(args[0], aliases):
        refusals.append(_refusal("R1", node, source))
    if last == "multiple" and census._resolve(args[0], aliases):
        refusals.append(_refusal("R1", node, source))
    if last == "dict" and census._resolve(args[0], aliases):
        refusals.append(_refusal("R1", node, source))

    mod = census._resolve(args[0], aliases)

    if last == "getattr" and mod and len(args) >= 2:
        arg1 = args[1]
        if isinstance(arg1, ast.Constant) and isinstance(arg1.value, str):
            if arg1.value in d1[mod]:
                refusals.append(_refusal("R1", node, source))
        elif isinstance(arg1, ast.Name):
            fn = declaring_function(arg1, parents)
            if fn is not None:
                t5_candidates.append(T5Candidate(fn, arg1.id, node, mod))
            else:
                dynamic_reads.append(node)
        else:
            refusals.append(_refusal("R1", node, source))

    if _is_t1_func(node.func) and mod is not None and len(args) >= 2:
        arg1 = args[1]
        if isinstance(arg1, ast.Constant) and isinstance(arg1.value, str):
            if arg1.value in d1[mod]:
                counts["T1"] += 1
                edits.append(_insert_after(source, args[0], ".deps", "T1"))
        elif isinstance(arg1, ast.Name):
            fn = declaring_function(arg1, parents)
            if fn is not None:
                t5_candidates.append(T5Candidate(fn, arg1.id, node, mod))
            else:
                refusals.append(_refusal("R1", node, source))
        else:
            refusals.append(_refusal("R1", node, source))

    if (last in census.PATCH_FUNCS and isinstance(args[0], ast.Constant)
            and isinstance(args[0].value, str)):
        s = args[0].value
        for mod_, names in d1.items():
            prefix = mod_ + "."
            if s.startswith(prefix):
                first = s[len(prefix):].split(".", 1)[0]
                if first in names:
                    counts["T2"] += 1
                    edits.append(_insert_in_string(source, args[0], prefix, "T2"))
                    t2_nodes.add(args[0])
                break


def _scan_assign(node, source, aliases, d1, edits, counts) -> None:
    targets = node.targets if isinstance(node, (ast.Assign, ast.Delete)) else [node.target]
    for t in targets:
        if isinstance(t, ast.Attribute):
            mod = census._resolve(t.value, aliases)
            if mod is not None and t.attr in d1[mod]:
                counts["T3"] += 1
                edits.append(_insert_after(source, t.value, ".deps", "T3"))


def _scan_attribute(node, source, aliases, d1, edits, refusals, counts) -> None:
    if node.attr == "__dict__":
        if census._resolve(node.value, aliases):
            refusals.append(_refusal("R1", node, source))
        return
    if not isinstance(node.ctx, ast.Load):
        return
    mod = census._resolve(node.value, aliases)
    if mod is not None and node.attr in d1[mod]:
        counts["T4"] += 1
        edits.append(_insert_after(source, node.value, ".deps", "T4"))


def _scan_subscript(node, source, aliases, classes, bindings, refusals) -> None:
    if (census._dotted(node.value) == "sys.modules" and isinstance(node.slice, ast.Constant)
            and isinstance(node.slice.value, str) and node.slice.value in census.MODULES):
        refusals.append(_refusal("R1", node, source))
    # R1 extension: ``<fn>.__globals__[...] = ...`` subscript writes (RC-C).
    if isinstance(node.ctx, ast.Store) and _is_globals_dict(node.value):
        if _globals_base_resolves(node.value.value, aliases, classes, bindings):
            refusals.append(_refusal("R1", node, source))


def _scan_r2(tree, source, d1, t2_nodes, refusals) -> None:
    for node in ast.walk(tree):
        if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                and node not in t2_nodes):
            s = node.value
            for mod, names in d1.items():
                prefix = mod + "."
                if s.startswith(prefix):
                    first = s[len(prefix):].split(".", 1)[0]
                    if first in names:
                        refusals.append(_refusal("R2", node, source))
                    break


def _scan_t6(tree, source, aliases, d1, edits, refusals, counts) -> None:
    """T6 rewrite: a module alias passed to a patching helper -> ``.deps``.

    All-or-nothing per helper (mirrors T5's ``process_t5``): every call of a
    helper that passes a module alias must also pass a D1 name, else the
    non-compliant calls are refused R5 and nothing of the group is rewritten.
    """
    def resolve(node):
        return census._resolve(node, aliases)

    def good(name_values, mod):
        return (name_values is not None and bool(name_values)
                and all(v in d1[mod] for v in name_values))

    groups: dict = {}
    for call, info, mod, owner_arg, name_values in t6.find_t6_calls(tree, resolve):
        groups.setdefault(info.node, []).append((call, mod, owner_arg, name_values))
    for _, items in groups.items():
        if all(good(nv, m) for (_c, m, _o, nv) in items):
            for call, _m, owner_arg, _nv in items:
                counts["T6"] += 1
                edits.append(_insert_after(source, owner_arg, ".deps", "T6"))
        else:
            for call, m, _owner_arg, nv in items:
                if not good(nv, m):
                    refusals.append(_refusal("R5", call, source))


def analyze(text: str, tree: ast.AST, rel: str, d1: dict[str, set[str]]) -> tuple:
    """Find the rewrites and refusals of one test file.

    Returns ``(edits, refusals, counts, dynamic_reads)`` where counts holds the
    T1..T6 totals and ``dynamic_reads`` are the carve-out #1 getattr sites.
    """
    source = Source(text)
    aliases, classes = census._aliases(tree)
    parents = parent_map(tree)
    bindings = t6.name_bindings(tree)
    edits: list = []
    refusals: list = []
    counts = {"T1": 0, "T2": 0, "T3": 0, "T4": 0, "T5": 0, "T6": 0}
    t2_nodes: set = set()
    t5_candidates: list = []
    dynamic_reads: list = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            _scan_call(node, source, aliases, classes, bindings, parents, d1, edits,
                       refusals, counts, t2_nodes, t5_candidates, dynamic_reads)
        elif isinstance(node, (ast.Assign, ast.AugAssign, ast.Delete)):
            _scan_assign(node, source, aliases, d1, edits, counts)
        elif isinstance(node, ast.Attribute):
            _scan_attribute(node, source, aliases, d1, edits, refusals, counts)
        elif isinstance(node, ast.Subscript):
            _scan_subscript(node, source, aliases, classes, bindings, refusals)

    _scan_r2(tree, source, d1, t2_nodes, refusals)
    _scan_t6(tree, source, aliases, d1, edits, refusals, counts)
    rewrite_calls, t5_refusals = process_t5(tree, parents, t5_candidates, d1)
    for call in rewrite_calls:
        counts["T5"] += 1
        edits.append(_insert_after(source, call.args[0], ".deps", "T5"))
    for node in t5_refusals:
        refusals.append(_refusal("R1", node, source))

    return edits, [r._replace(rel=rel) for r in refusals], counts, dynamic_reads


def find_r3(path: Path, rel: str, tree: ast.AST, d1: dict[str, set[str]],
            source: Source) -> list:
    """Refuse a by-value D1 import the same file patches on its module (R3)."""
    by_value = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module in d1:
            for a in node.names:
                if a.name in d1[node.module]:
                    by_value.append((node.module, a.name, node))
    if not by_value:
        return []
    acc = {m: {"module_patches": defaultdict(list), "class_patches": defaultdict(list)}
           for m in census.MODULES}
    acc["_source_readers"] = defaultdict(list)
    census.scan_file(path, rel, acc)
    out = []
    for mod, name, node in by_value:
        if name in acc[mod]["module_patches"]:
            out.append(Refusal("R3", rel, node.lineno, source.line(node.lineno)))
    return out


def apply_edits(text: str, edits: list) -> tuple[str, list]:
    """Apply the insertions and return ``(new_text, [(pos, repl), ...])``."""
    ordered = sorted(edits, key=lambda e: (e.start, e.end))
    parts = []
    placements = []
    pos = 0
    length = 0
    for e in ordered:
        chunk = text[pos:e.start]
        parts.append(chunk)
        length += len(chunk)
        placements.append((length, e.repl))
        parts.append(e.repl)
        length += len(e.repl)
        pos = e.end
    parts.append(text[pos:])
    return "".join(parts), placements


def verify_census(root: Path, d1: dict[str, set[str]]) -> None:
    """Re-run the census and fail if any D1 name still targets the package root."""
    acc = {m: {"module_patches": defaultdict(list), "class_patches": defaultdict(list)}
           for m in census.MODULES}
    acc["_source_readers"] = defaultdict(list)
    for path in sorted((root / "tests").rglob("*.py")):
        census.scan_file(path, path.relative_to(root).as_posix(), acc)
    leftovers = [f"{m}.{n}" for m, names in d1.items()
                 for n in names if acc[m]["module_patches"].get(n)]
    if leftovers:
        for item in leftovers:
            print(f"RETARGET FAIL census leftover {item}")
        sys.exit(1)
