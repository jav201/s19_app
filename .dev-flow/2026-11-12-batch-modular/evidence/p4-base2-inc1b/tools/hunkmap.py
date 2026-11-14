"""Hunk -> module table and member-level AST identity for the Inc 1b app.py port.

python -I -B hunkmap.py <repo> <base_old> <twin> <tip> <modular> <merged_tree_rev_or_INDEX> <out_tsv>
Reads git blobs only; imports nothing from the product.
"""
import ast
import re
import subprocess
import sys
from pathlib import Path

repo, base_old, twin, tip, modular, merged, out = sys.argv[1:8]


def git(*args):
    return subprocess.run(["git", "-C", repo, *args], capture_output=True, check=True).stdout.decode("utf-8")


def blob(rev, path):
    spec = f":{path}" if rev == "INDEX" else f"{rev}:{path}"
    return git("show", spec)


def ls(rev, prefix):
    if rev == "INDEX":
        names = git("ls-files", "--", prefix).split()
    else:
        names = git("ls-tree", "-r", "--name-only", rev, "--", prefix).split()
    return [n for n in names if n.endswith(".py")]


def members_old(text):
    tree = ast.parse(text)
    out = {}
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "S19TuiApp":
            for m in node.body:
                if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    out[m.name] = m
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out["<module>." + node.name] = node
    return out


def members_pkg(rev):
    out = {}
    for path in ls(rev, "s19_app/tui/app/"):
        tree = ast.parse(blob(rev, path))
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                for m in node.body:
                    if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        out.setdefault(m.name, (path, m))
                if node.name != "S19TuiApp" and not node.name.endswith("Mixin"):
                    out.setdefault("<module>." + node.name, (path, node))
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                out.setdefault("<module>." + node.name, (path, node))
    return out


def norm(node):
    text = ast.dump(node, include_attributes=False)
    # batch-modular rewrote D1 reads `X` -> `deps.X`; undo for comparison.
    return re.sub(r"Attribute\(value=Name\(id='deps', ctx=Load\(\)\), attr='([^']+)', ctx=Load\(\)\)",
                  r"Name(id='\1', ctx=Load())", text)


tip_text = blob(tip, "s19_app/tui/app.py")
old_tip = members_old(tip_text)
old_twin = members_old(blob(twin, "s19_app/tui/app.py"))
pkg_mod = members_pkg(modular)
pkg_new = members_pkg(merged)

# 1) hunk -> enclosing member on the tip side -> package module on the merged side
diff = git("diff", "-U0", base_old, tip, "--", "s19_app/tui/app.py")
spans = []
for name, node in old_tip.items():
    spans.append((node.lineno, node.end_lineno, name))
rows = []
for m in re.finditer(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", diff, re.M):
    start = int(m.group(3)); count = int(m.group(4) or 1)
    end = start + max(count, 1) - 1
    hit = [n for a, b, n in spans if a <= start and end <= b]
    if not hit:
        hit = sorted({n for a, b, n in spans if not (b < start or end < a)}) or ["<module-level/imports>"]
    for name in hit:
        where = pkg_new.get(name, (None,))[0]
        rows.append((f"+{start},{count}", name, where or "-"))

# 2) member-level identity: the port delta equals the Inc 1b late delta
late_old = {n for n in set(old_tip) | set(old_twin)
            if (n in old_tip) != (n in old_twin) or (n in old_tip and norm(old_tip[n]) != norm(old_twin[n]))}
late_new = {n for n in set(pkg_new) | set(pkg_mod)
            if (n in pkg_new) != (n in pkg_mod) or (n in pkg_new and norm(pkg_new[n][1]) != norm(pkg_mod[n][1]))}
mismatch_tip = sorted(n for n in old_tip if n in pkg_new and norm(old_tip[n]) != norm(pkg_new[n][1]))
mismatch_twin = sorted(n for n in old_twin if n in pkg_mod and norm(old_twin[n]) != norm(pkg_mod[n][1]))
missing_tip = sorted(n for n in old_tip if n not in pkg_new)
missing_twin = sorted(n for n in old_twin if n not in pkg_mod)

with open(out, "w", encoding="utf-8", newline="\n") as fh:
    fh.write("hunk_new_side\tmember_in_tip_app.py\tpackage_module_on_merged_tree\n")
    for r in rows:
        fh.write("\t".join(r) + "\n")
print(f"hunks={len(re.findall(r'^@@', diff, re.M))} rows={len(rows)} unplaced={sum(1 for r in rows if r[2] == '-')}")
print(f"members tip={len(old_tip)} twin={len(old_twin)} pkg_modular={len(pkg_mod)} pkg_merged={len(pkg_new)}")
print(f"late delta (twin->tip app.py): {sorted(late_old)}")
print(f"port delta (a95d0ea9->merged package): {sorted(late_new)}")
print(f"equal_delta={late_old == late_new}")
print(f"AST mismatches tip vs merged ({len(mismatch_tip)}): {mismatch_tip}")
print(f"AST mismatches twin vs a95d0ea9 ({len(mismatch_twin)}): {mismatch_twin}")
print(f"same_mismatch_set={mismatch_tip == mismatch_twin}")
print(f"missing tip->merged ({len(missing_tip)}): {missing_tip[:20]}")
print(f"missing twin->a95 ({len(missing_twin)}): {missing_twin[:20]}")
print(f"same_missing_set={missing_tip == missing_twin}")
