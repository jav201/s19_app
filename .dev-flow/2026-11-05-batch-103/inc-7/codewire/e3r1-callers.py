"""e3r1-callers.py -- name the enclosing function of every call site the Code-Wire extractor lists (Inc 7 E3R1).

usage: python e3r1-callers.py <marked copy> <extract.json>
The extractor attributes a site to the nearest `# node:` mark above it; this script re-reads each site's file in
the marked copy with `ast` and prints the real enclosing `Class.function` (or `<module>`), the site line in the
marked copy, and the line at 2dbd7d5a (the marked line minus the marks above it in the same file).
"""
import ast
import json
import sys
from pathlib import Path

COPY = Path(sys.argv[1])
DATA = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
MARK = "# node:"


def defs_of(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    spans = []

    def walk(node, prefix):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = prefix + child.name
                if not isinstance(child, ast.ClassDef):
                    spans.append((child.lineno, child.end_lineno, name))
                walk(child, name + ".")
    walk(tree, "")
    return spans


def enclosing(spans, line):
    best = None
    for start, end, name in spans:
        if start <= line <= end and (best is None or start >= best[0]):
            best = (start, name)
    return best[1] if best else "<module>"


cache = {}
sites = {}
for call in DATA["calls"]:
    for site in call["sites"]:
        sites.setdefault(call["callee"], set()).add(site)
for callee, lst in DATA["top_level_sites"].items():
    for site in lst:
        sites.setdefault(callee, set()).add(site)
for callee in sorted(sites):
    print(f"== {callee}")
    for site in sorted(sites[callee], key=lambda s: (s.split(":")[0], int(s.split(":")[1]))):
        rel, line = site.rsplit(":", 1)
        line = int(line)
        path = COPY / rel
        if rel not in cache:
            text = path.read_text(encoding="utf-8").splitlines()
            cache[rel] = (defs_of(path), [i + 1 for i, t in enumerate(text) if t.strip().startswith(MARK)])
        spans, marks = cache[rel]
        base = line - sum(1 for m in marks if m < line)
        print(f"   {rel}:{base} (marked copy :{line})  in {enclosing(spans, line)}")
