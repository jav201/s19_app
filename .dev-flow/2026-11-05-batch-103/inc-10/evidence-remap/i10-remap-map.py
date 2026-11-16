"""batch-103 Inc 10 re-map (relevo-8): map cited old lines to the new base by their enclosing function (read only).

Usage: python -I -B i10-remap-map.py <scratch dir of i10-remap-census.py> <old-file>:<line>[-<end>] ...

<scratch>/old and <scratch>/new are the `git archive` trees that i10-remap-census.py wrote (287b9dc3 and a95d0ea9).
For each citation, finds the innermost def (or class) that holds the old line at the old commit, finds the def of
the same qualname tail at the new commit (the class part may change: app.py -> app/*.py mixins, screens_directionb.py
-> patch_editor/*.py mixins; the moved save-back blocks of compose -> ActionsMixin._compose_action_bar /
_compose_doc_controls), adds the line's offset inside the def, and checks that the stripped text of the old line
equals the stripped text of the new line ("text=" or "TEXT-DIFFERS"). A citation outside every def is reported
as such. Stdlib only.
"""
import ast, sys
from pathlib import Path

scratch = Path(sys.argv[1])
OLD = {"app.py": "s19_app/tui/app.py", "screens_directionb.py": "s19_app/tui/screens_directionb.py"}
NEW_ROOT = {"app.py": "s19_app/tui/app", "screens_directionb.py": "s19_app/tui/screens_directionb/patch_editor"}
# compose was split by batch-modular: the blocks Inc 10 cites, by their first line at the old commit, and the
# helper that holds each one at the new commit.
COMPOSE_BLOCKS = {"patch_saveback_row": "_compose_action_bar", "patch_before_after_row": "_compose_action_bar",
                  "patch_doc_controls": "_compose_doc_controls", "patch_legend": "compose"}


def defs(path):
    out = []

    def walk(node, prefix):
        for ch in ast.iter_child_nodes(node):
            if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                out.append((prefix + ch.name, ch.lineno, ch.end_lineno, ch))
                walk(ch, prefix + ch.name + ".")
    walk(ast.parse(path.read_text(encoding="utf-8")), "")
    return out


def innermost(ds, line):
    best = None
    for q, a, b, n in ds:
        if a <= line <= b and (best is None or a >= best[1]):
            best = (q, a, b, n)
    return best


def tail(q):
    return ".".join(q.split(".")[1:]) if "." in q else q


cache = {}


def new_defs(key):
    if key not in cache:
        cache[key] = [(p, d) for p in sorted((scratch / "new" / NEW_ROOT[key]).rglob("*.py")) for d in defs(p)]
    return cache[key]


def map_line(key, line):
    old_path = scratch / "old" / OLD[key]
    old_lines = old_path.read_text(encoding="utf-8").splitlines()
    hit = innermost(defs(old_path), line)
    if hit is None:
        return f"outside every def"
    q, a, _b, node = hit
    text = old_lines[line - 1].strip()
    cands = [(p, d) for p, d in new_defs(key) if (tail(d[0]) == tail(q) and "." in q) or d[0] == q]
    if q.endswith(".compose") and key == "screens_directionb.py":
        # the split compose: find the helper whose body holds the same stripped text
        cands = [(p, d) for p, d in new_defs(key) if d[0].split(".")[-1] in set(COMPOSE_BLOCKS.values())]
        for p, d in cands:
            nl = p.read_text(encoding="utf-8").splitlines()
            for i in range(d[1], d[2] + 1):
                if nl[i - 1].strip() == text and text:
                    return f"{p.relative_to(scratch / 'new').as_posix()}:{i} ({d[0]}; compose split) text="
        return f"compose:{line} -> no helper holds the text {text[:40]!r}"
    if len(cands) != 1:
        return f"{q}: {len(cands)} candidates"
    p, d = cands[0]
    new_line = d[1] + (line - a)
    nl = p.read_text(encoding="utf-8").splitlines()
    ok = "text=" if nl[new_line - 1].strip() == text else "TEXT-DIFFERS"
    return f"{p.relative_to(scratch / 'new').as_posix()}:{new_line} ({d[0]}) {ok}"


for arg in sys.argv[2:]:
    f, _, rng = arg.rpartition(":")
    parts = [int(x) for x in rng.split("-")]
    print(f"{arg:34} -> " + " .. ".join(map_line(f, n) for n in parts))
