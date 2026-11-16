"""AST census of god files for the modularization plan (read-only).

Usage: python -I census.py <repo_root> <out_json>
"""
import ast
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(sys.argv[1])
OUT = Path(sys.argv[2])
TARGETS = ["s19_app/tui/app.py", "s19_app/tui/screens_directionb.py"]


def method_info(fn: ast.AST, src_lines: list[str]) -> dict:
    calls, reads, writes, ext = set(), set(), set(), set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name) and n.func.value.id == "self":
            calls.add(n.func.attr)
        if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "self":
            (writes if isinstance(n.ctx, ast.Store) else reads).add(n.attr)
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
            ext.add(n.id)
    return {
        "name": fn.name,
        "start": fn.lineno,
        "end": fn.end_lineno,
        "lines": fn.end_lineno - fn.lineno + 1,
        "decorators": [ast.unparse(d) for d in fn.decorator_list],
        "self_calls": sorted(calls),
        "self_reads": sorted(reads - calls),
        "self_writes": sorted(writes),
        "names": sorted(ext),
    }


def census_file(rel: str) -> dict:
    path = ROOT / rel
    text = path.read_text(encoding="utf-8")
    tree = ast.parse(text)
    lines = text.splitlines()
    top = []
    for node in tree.body:
        kind = type(node).__name__
        entry = {"kind": kind, "start": node.lineno, "end": node.end_lineno, "lines": node.end_lineno - node.lineno + 1}
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            entry["name"] = node.name
        if isinstance(node, ast.ClassDef):
            entry["bases"] = [ast.unparse(b) for b in node.bases]
            entry["methods"] = [method_info(m, lines) for m in node.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))]
            entry["class_attrs"] = [ast.unparse(t) for m in node.body if isinstance(m, (ast.Assign, ast.AnnAssign)) for t in ([m.target] if isinstance(m, ast.AnnAssign) else m.targets)]
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = [node.target] if isinstance(node, ast.AnnAssign) else node.targets
            entry["name"] = ",".join(ast.unparse(t) for t in targets)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            entry["name"] = ast.unparse(node)
        top.append(entry)
    return {"file": rel, "total_lines": len(lines), "top": top}


def test_coupling() -> dict:
    """Which names of each target module do tests patch or import."""
    out = {}
    for rel in TARGETS:
        mod = rel[:-3].replace("/", ".")
        patched, imported, attr_use = Counter(), Counter(), Counter()
        files = set()
        for t in (ROOT / "tests").rglob("*.py"):
            s = t.read_text(encoding="utf-8", errors="replace")
            if mod not in s and mod.rsplit(".", 1)[1] not in s:
                continue
            for m in re.finditer(rf'["\']{re.escape(mod)}\.([A-Za-z_][\w.]*)["\']', s):
                patched[m.group(1)] += 1
                files.add(t.name)
            for m in re.finditer(rf"from {re.escape(mod)} import \(?([^)\n]*(?:\n[^)]*)*?)\)?\n", s):
                for name in re.findall(r"[A-Za-z_]\w*(?:\s+as\s+\w+)?", m.group(1)):
                    imported[name.split()[0]] += 1
                files.add(t.name)
            aliases = re.findall(rf"import {re.escape(mod)} as (\w+)", s) + re.findall(rf"from {re.escape(mod.rsplit('.', 1)[0])} import {mod.rsplit('.', 1)[1]} as (\w+)", s)
            for a in aliases:
                for m in re.finditer(rf"\b{a}\.([A-Za-z_]\w*)", s):
                    attr_use[m.group(1)] += 1
                files.add(t.name)
        out[rel] = {"test_files": len(files), "string_targets": dict(patched.most_common()), "imported_names": dict(imported.most_common()), "module_alias_attrs": dict(attr_use.most_common())}
    return out


def prod_importers() -> dict:
    out = defaultdict(list)
    for p in (ROOT / "s19_app").rglob("*.py"):
        s = p.read_text(encoding="utf-8", errors="replace")
        for rel in TARGETS:
            mod = rel[:-3].replace("/", ".")
            short = mod.rsplit(".", 1)[1]
            if re.search(rf"(from {re.escape(mod)} import|import {re.escape(mod)}|from \.{short} import|from \.\.tui\.{short} import)", s):
                out[rel].append(str(p.relative_to(ROOT)).replace("\\", "/"))
    return dict(out)


result = {"files": [census_file(r) for r in TARGETS], "tests": test_coupling(), "prod_importers": prod_importers()}
OUT.write_text(json.dumps(result, indent=1), encoding="utf-8")
for f in result["files"]:
    print(f["file"], f["total_lines"], "lines;", Counter(e["kind"] for e in f["top"]))
for rel, c in result["tests"].items():
    print(rel, "tests:", c["test_files"], "files; string targets", len(c["string_targets"]), "imported", len(c["imported_names"]), "alias attrs", len(c["module_alias_attrs"]))
print("prod importers:", {k: len(v) for k, v in result["prod_importers"].items()})
