"""batch-103 Inc 7 re-map (relevo-11): locate every Inc 7 graph node and every cited file:line at the new base (read only).

Usage: python -I -B i7-remap-census.py <repo> <old commit> <new commit> <scratch dir> <inc-7 record dir>

`git archive`s s19_app/ and tests/ of both commits into <scratch>/old and <scratch>/new (throwaway, outside every
work tree; no work tree is touched; nothing from s19_app is imported).
  1. byte identity of every source and test file, old -> new (the list of files that differ);
  2. every node of codewire/graph-inc7.md (name, module:, state): `changed` nodes are found by qualname in their
     module at both commits (lines, AST equality, docstring included); `new` nodes are checked for absence at both
     commits and for the existence of the module / class that will receive them;
  3. every `file.py:line[-line]` citation of the Inc 7 records (requirements, slice, graph, rulings, E3 reviews,
     cases) that names a file under s19_app/ or tests/: the line at the old commit is mapped to the new commit by
     its enclosing def + offset and the stripped text of the line is compared ("text=" or "TEXT-DIFFERS");
     a bare `:NNN` citation carries the file named earlier on the same line.
Stdlib only.
"""
import ast, hashlib, io, re, shutil, subprocess, sys, tarfile
from collections import Counter
from pathlib import Path

repo, old, new, scratch, rec = sys.argv[1], sys.argv[2], sys.argv[3], Path(sys.argv[4]), Path(sys.argv[5])
OLD, NEW = scratch / "old", scratch / "new"
DOCS = ["01-requirements.md", "E1-slice.md", "E1-rulings.md", "E3-rulings.md", "E3-architect.md", "E3-security.md",
        "02-test-cases-L.md", "02-test-cases-V.md", "02-test-cases-AT.md", "codewire/graph-inc7.md"]


def extract(commit, dest):
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    data = subprocess.run(["git", "-C", repo, "archive", commit, "s19_app", "tests"], check=True,
                          capture_output=True).stdout
    tarfile.open(fileobj=io.BytesIO(data)).extractall(dest, filter="data")


def h(node):
    return hashlib.sha1(ast.dump(node).encode()).hexdigest()[:10]


_cache = {}


def index(path):
    """qualname -> (lineno, end_lineno, ast hash) for every def and class."""
    if path in _cache:
        return _cache[path]
    out = {}

    def walk(node, prefix):
        for ch in ast.iter_child_nodes(node):
            if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = prefix + ch.name
                out[name] = (ch.lineno, ch.end_lineno, h(ch))
                walk(ch, name + ".")
    walk(ast.parse(path.read_text(encoding="utf-8")), "")
    _cache[path] = out
    return out


def innermost(idx, line):
    best = None
    for q, (a, b, _h) in idx.items():
        if a <= line <= b and (best is None or a >= best[1]):
            best = (q, a, b)
    return best


rev = lambda c: subprocess.run(["git", "-C", repo, "rev-parse", "--short=8", c], capture_output=True,
                               text=True).stdout.strip()
extract(old, OLD)
extract(new, NEW)
print(f"# i7-remap-census: old {rev(old)} new {rev(new)}; python {sys.version.split()[0]}")

# 1. files
oldf = {p.relative_to(OLD).as_posix() for p in OLD.rglob("*") if p.is_file()}
newf = {p.relative_to(NEW).as_posix() for p in NEW.rglob("*") if p.is_file()}
differ = sorted(f for f in oldf & newf if (OLD / f).read_bytes() != (NEW / f).read_bytes())
print(f"## files: {len(oldf)} old, {len(newf)} new; removed {sorted(oldf - newf)}; "
      f"added {len(newf - oldf)} ({len([f for f in newf - oldf if f.startswith('s19_app/')])} under s19_app/)")
print(f"## files that differ (same path, other bytes): {len(differ)}")
for f in differ:
    print(f"  {f}")
print("## added under s19_app/: " + ", ".join(sorted(f for f in newf - oldf if f.startswith("s19_app/"))))
print("## added under tests/: " + ", ".join(sorted(f for f in newf - oldf if f.startswith("tests/"))))

# 2. graph nodes
text = (rec / "codewire/graph-inc7.md").read_text(encoding="utf-8")
body = text.split("\n## Nodes\n", 1)[1].split("\n## Entities", 1)[0]
nodes = []
for blk in re.split(r"\n\s*\n", body):
    ls = [l for l in blk.strip().splitlines() if l.strip()]
    if not ls or ls[0].startswith(("#", "-", "|")) or not any(l.startswith("func:") for l in ls):
        continue
    mod = next((l.split(":", 1)[1].strip() for l in ls if l.startswith("module:")), "?")
    st = next(l.split(":", 1)[1].strip().split()[0].strip(";.,") for l in ls if l.startswith("func:"))
    nodes.append((ls[0].strip(), mod, st))
print(f"## graph nodes: {len(nodes)} ({Counter(s for _, _, s in nodes)})")
print("## node: module | state | old lines | new lines | AST")
diffs = []
for name, mod, st in nodes:
    op, np_ = OLD / mod, NEW / mod
    om = index(op) if op.exists() else {}
    nm = index(np_) if np_.exists() else {}
    cls = {"ComposeScreensMixin", "A2lViewMixin", "OsClipboardInput"}
    q = name
    if st == "changed":
        o, n = om.get(q), nm.get(q)
        if o is None or n is None:
            print(f"{name:52} {mod.split('tui/')[-1]:28} changed  NOT FOUND old={o} new={n}")
            continue
        eq = "same-ast" if o[2] == n[2] else "DIFF"
        if eq == "DIFF":
            diffs.append(name)
        print(f"{name:52} {mod.split('tui/')[-1]:28} changed  {o[0]}-{o[1]} -> {n[0]}-{n[1]} {eq}")
    else:
        pre = name.split(".")[0] if "." in name else None
        where = ("module exists at old and new" if op.exists() and np_.exists() else
                 "module absent at old and new" if not op.exists() and not np_.exists() else "MODULE STATE DIFFERS")
        clash = [x for x in (om, nm) if name in x]
        cls_ok = (pre in nm) if (pre and op.exists()) else None
        print(f"{name:52} {mod.split('tui/')[-1]:28} new      {where}; name absent={not clash}"
              + (f"; class {pre} at new {nm[pre][0]}-{nm[pre][1]}" if cls_ok else ""))
print(f"## changed nodes whose AST differs old -> new: {diffs or 'none'}")

# 3. citations
paths = sorted(oldf)
by_base = {}
for p in paths:
    by_base.setdefault(p.rsplit("/", 1)[-1], []).append(p)


def resolve(token):
    token = token.strip("`")
    if "/" in token:
        return [p for p in paths if p.endswith(token)]
    c = by_base.get(token, [])
    if len(c) > 1:
        for pref in ("s19_app/tui/app/", "s19_app/tui/", "tests/"):
            pc = [p for p in c if p.startswith(pref)]
            if len(pc) == 1:
                return pc
    return c


CITE = re.compile(r"(?P<f>[A-Za-z0-9_./]+\.(?:py|tcss|json))`?:(?P<a>\d+)(?:-(?P<b>\d+))?"
                  r"|(?<![\w:])`?:(?P<ba>\d{3,5})(?:-(?P<bb>\d+))?"
                  r"|(?P<f2>[A-Za-z0-9_./]+\.(?:py|tcss|json))(?!`?:\d)")
cites = []
for d in DOCS:
    f = rec / d
    if not f.exists():
        continue
    for ln, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
        cur = None
        for m in CITE.finditer(line):
            if m.group("f2"):
                cands = resolve(m.group("f2"))
                cur = cands[0] if len(cands) == 1 else cur
                continue
            if m.group("f"):
                cands = resolve(m.group("f"))
                cur = cands[0] if len(cands) == 1 else None
                tok, a, b = m.group("f"), int(m.group("a")), m.group("b")
                if not cands:
                    continue
                if len(cands) > 1:
                    cites.append((d, ln, tok, None, a, b, "AMBIGUOUS " + ",".join(cands)))
                    continue
            else:
                if cur is None:
                    continue
                tok, a, b = cur + " (carried)", int(m.group("ba")), m.group("bb")
            cites.append((d, ln, tok, cur if "(carried)" in tok else resolve(tok.replace(" (carried)", ""))[0],
                          a, b, ""))
print(f"## citations: {len(cites)} file:line citations naming a file under s19_app/ or tests/")
stat = Counter()
rows = []
for d, ln, tok, f, a, b, note in cites:
    if f is None:
        stat["ambiguous"] += 1
        rows.append(f"{d}:{ln} {tok}:{a} -> {note}")
        continue
    ends = [a] + ([int(b)] if b and int(b) > a else [])
    if f not in newf:
        stat["file-gone"] += 1
        rows.append(f"{d}:{ln} {f}:{a} -> FILE ABSENT AT NEW")
        continue
    if f not in differ:
        stat["same-file"] += 1
        continue
    oi, ni = index(OLD / f) if f.endswith(".py") else {}, index(NEW / f) if f.endswith(".py") else {}
    ol = (OLD / f).read_text(encoding="utf-8").splitlines()
    nl = (NEW / f).read_text(encoding="utf-8").splitlines()
    res = []
    for n in ends:
        if n > len(ol):
            res.append(f"{n}: beyond EOF"); continue
        t = ol[n - 1].strip()
        hit = innermost(oi, n)
        if hit and hit[0] in ni:
            m_ = ni[hit[0]][0] + (n - hit[1])
            ok = 0 < m_ <= len(nl) and nl[m_ - 1].strip() == t
            if not ok and t:
                near = [i for i in range(ni[hit[0]][0], ni[hit[0]][1] + 1) if nl[i - 1].strip() == t]
                m2 = near[0] if len(near) == 1 else None
                res.append(f"{n}->{m2 or m_} ({hit[0]}) {'text=' if m2 else 'TEXT-DIFFERS'}")
            else:
                res.append(f"{n}->{m_} ({hit[0]}) text=")
        else:
            near = [i for i, l in enumerate(nl, 1) if l.strip() == t and t]
            res.append(f"{n}->{near[0] if len(near) == 1 else '?'} (outside every def; unique text match "
                       f"{'yes' if len(near) == 1 else 'no'})")
    kind = "moved" if any("->" in r and r.split("->")[0] != r.split("->")[1].split()[0] for r in res) else "same-line"
    stat["differs-file/" + kind] += 1
    rows.append(f"{d}:{ln} {f}:{a}{'-' + b if b else ''} -> " + " .. ".join(res))
print("## citation status: " + ", ".join(f"{k}={v}" for k, v in sorted(stat.items())))
print("## citations into files that differ, or not resolvable (each: record:line cited -> new)")
for r in rows:
    print("  " + r)
