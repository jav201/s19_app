"""AST census of how tests touch the two god modules (read-only).

Finds, per old module (``s19_app.tui.app``, ``s19_app.tui.screens_directionb``):
  * module patches  -- names a test rebinds on the module object
    (monkeypatch.setattr / patch.object / mocker.patch.object / setattr /
    delattr / ``alias.X = ...`` / string targets ``"s19_app.tui.app.X"`` /
    a module alias passed to a patching helper together with a string-constant
    name — T6, ``retarget_t6.py``);
  * class patches   -- names a test rebinds on ``S19TuiApp`` (or a subclass
    imported under that name);
  * source readers  -- tests that read the module's source text
    (``alias.__file__``, ``inspect.getsource``, a literal ``app.py`` /
    ``screens_directionb.py`` path).

Usage: python -I test_patch_census.py <repo_root> <out_json>
Prints one summary line per module; the JSON is the input of the D1 list.
"""
from __future__ import annotations

import ast
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import retarget_t6 as t6  # noqa: E402

MODULES = {"s19_app.tui.app": "app.py", "s19_app.tui.screens_directionb": "screens_directionb.py"}
PATCH_FUNCS = {"setattr", "delattr", "object", "patch", "setitem", "delitem"}
CLASS_NAMES = {"S19TuiApp"}


def _dotted(node: ast.AST) -> str | None:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _aliases(tree: ast.AST) -> tuple[dict[str, str], set[str]]:
    """Return {local name -> module} and the local names bound to S19TuiApp."""
    out: dict[str, str] = {}
    classes: set[str] = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name in MODULES:
                    out[a.asname or a.name] = a.name
        elif isinstance(n, ast.ImportFrom) and n.module:
            for a in n.names:
                full = f"{n.module}.{a.name}"
                if full in MODULES:
                    out[a.asname or a.name] = full
                if n.module == "s19_app.tui.app" and a.name in CLASS_NAMES:
                    classes.add(a.asname or a.name)
        elif isinstance(n, ast.Assign) and isinstance(n.value, ast.Call):
            f = _dotted(n.value.func) or ""
            args = n.value.args
            if f.endswith("import_module") and args and isinstance(args[0], ast.Constant) and args[0].value in MODULES:
                for t in n.targets:
                    if isinstance(t, ast.Name):
                        out[t.id] = args[0].value
    return out, classes


def _resolve(node: ast.AST, aliases: dict[str, str]) -> str | None:
    d = _dotted(node)
    if d is None:
        return None
    if d in aliases:
        return aliases[d]
    if d in MODULES:
        return d
    return None


def _scan_t6_sites(tree: ast.AST, aliases: dict[str, str], rel: str, acc: dict) -> None:
    """Census rule for T6: a module alias passed to a patching helper together
    with a string-constant name is a patch site of that name (RC-B)."""
    def resolve(node: ast.AST) -> str | None:
        return _resolve(node, aliases)
    for call, _info, mod, _owner, name_values in t6.find_t6_calls(tree, resolve):
        if not name_values:
            continue
        for name in name_values:
            acc[mod]["module_patches"][name].append(f"{rel}:{call.lineno}:{call.func.id}")


def scan_file(path: Path, rel: str, acc: dict) -> None:
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return
    aliases, classes = _aliases(tree)
    _scan_t6_sites(tree, aliases, rel, acc)
    for n in ast.walk(tree):
        if isinstance(n, ast.Call):
            fname = _dotted(n.func) or ""
            last = fname.rsplit(".", 1)[-1]
            args = n.args
            if last in PATCH_FUNCS and len(args) >= 2 and isinstance(args[1], ast.Constant) and isinstance(args[1].value, str):
                mod = _resolve(args[0], aliases)
                if mod and last not in {"setitem", "delitem"}:
                    acc[mod]["module_patches"][args[1].value].append(f"{rel}:{n.lineno}:{fname}")
                d0 = _dotted(args[0]) or ""
                if d0 in classes or d0.endswith(".S19TuiApp"):
                    acc["s19_app.tui.app"]["class_patches"][args[1].value].append(f"{rel}:{n.lineno}:{fname}")
            if last in PATCH_FUNCS and args and isinstance(args[0], ast.Constant) and isinstance(args[0].value, str):
                tgt = args[0].value
                for mod in MODULES:
                    if tgt.startswith(mod + "."):
                        rest = tgt[len(mod) + 1:]
                        if rest.startswith("S19TuiApp."):
                            acc[mod]["class_patches"][rest.split(".", 1)[1]].append(f"{rel}:{n.lineno}:{fname}:string")
                        else:
                            acc[mod]["module_patches"][rest].append(f"{rel}:{n.lineno}:{fname}:string")
            if fname.endswith("getsource") or fname.endswith("getsourcelines") or fname.endswith("getfile"):
                acc["_source_readers"][rel].append(f"{n.lineno}:{fname}")
        elif isinstance(n, (ast.Assign, ast.AugAssign, ast.Delete)):
            targets = n.targets if isinstance(n, (ast.Assign, ast.Delete)) else [n.target]
            for t in targets:
                if isinstance(t, ast.Attribute):
                    mod = _resolve(t.value, aliases)
                    if mod:
                        acc[mod]["module_patches"][t.attr].append(f"{rel}:{n.lineno}:assign")
                    d0 = _dotted(t.value) or ""
                    if d0 in classes:
                        acc["s19_app.tui.app"]["class_patches"][t.attr].append(f"{rel}:{n.lineno}:assign")
        elif isinstance(n, ast.Attribute) and n.attr == "__file__":
            mod = _resolve(n.value, aliases)
            if mod:
                acc["_source_readers"][rel].append(f"{n.lineno}:{mod}.__file__")
        elif isinstance(n, ast.Constant) and isinstance(n.value, str):
            for short in MODULES.values():
                if n.value == short or n.value.endswith("/" + short) or n.value.endswith("\\" + short):
                    acc["_source_readers"][rel].append(f"{n.lineno}:literal {n.value!r}")


def main() -> None:
    root, out = Path(sys.argv[1]), Path(sys.argv[2])
    acc: dict = {m: {"module_patches": defaultdict(list), "class_patches": defaultdict(list)} for m in MODULES}
    acc["_source_readers"] = defaultdict(list)
    for p in sorted((root / "tests").rglob("*.py")):
        scan_file(p, p.relative_to(root).as_posix(), acc)
    result = {
        m: {k: {n: v for n, v in sorted(acc[m][k].items())} for k in ("module_patches", "class_patches")}
        for m in MODULES
    }
    result["source_readers"] = {f: v for f, v in sorted(acc["_source_readers"].items())}
    out.write_text(json.dumps(result, indent=1), encoding="utf-8")
    for m in MODULES:
        print(m, "module_patches:", len(result[m]["module_patches"]), "class_patches:", len(result[m]["class_patches"]))
    print("source_reader files:", len(result["source_readers"]))


if __name__ == "__main__":
    main()
