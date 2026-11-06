"""AST census: trigger statement -> exactly one `await pilot.pause()` -> next statement.
Reads test files as text only (ast.parse); imports nothing from the project."""
import ast, sys, pathlib, collections

root = pathlib.Path(sys.argv[1])
WAIT_NAMES = {"settled", "_settled", "wait_until", "_wait_for", "settle", "_wait", "wait_for"}

def is_pause(stmt):
    return (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Await)
            and isinstance(stmt.value.value, ast.Call)
            and isinstance(stmt.value.value.func, ast.Attribute)
            and stmt.value.value.func.attr == "pause")

def call_of(stmt):
    v = stmt.value if isinstance(stmt, ast.Expr) else None
    if isinstance(v, ast.Await):
        v = v.value
    return v if isinstance(v, ast.Call) else None

def trigger_kind(stmt):
    if isinstance(stmt, ast.Assign) and any(isinstance(t, ast.Attribute) and t.attr == "value" for t in stmt.targets):
        return "value="
    c = call_of(stmt)
    if c is None:
        return None
    f = c.func
    name = f.attr if isinstance(f, ast.Attribute) else (f.id if isinstance(f, ast.Name) else None)
    if name == "press" and isinstance(f, ast.Attribute):
        base = f.value
        if isinstance(base, ast.Name) and base.id == "pilot":
            return "pilot.press"
        return ".press()"
    if name == "click" and isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id == "pilot":
        return "pilot.click"
    if name in ("request_action", "post_message"):
        return name
    return None

def next_kind(stmt):
    if stmt is None:
        return "end-of-block"
    if is_pause(stmt):
        return "pause"
    c = call_of(stmt)
    if c is not None:
        f = c.func
        name = f.attr if isinstance(f, ast.Attribute) else (f.id if isinstance(f, ast.Name) else None)
        if name in WAIT_NAMES:
            return "wait-helper"
    if trigger_kind(stmt):
        return "another-trigger"
    if isinstance(stmt, (ast.Assert,)):
        return "READ:assert"
    if isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
        return "READ:assign"
    if isinstance(stmt, ast.Return):
        return "READ:return"
    return "other:" + type(stmt).__name__

sites = collections.Counter(); files = collections.Counter(); triggers = collections.Counter()
examples = collections.defaultdict(list)
for path in sorted(root.glob("test_*.py")):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        for field in ("body", "orelse", "finalbody"):
            block = getattr(node, field, None)
            if not isinstance(block, list):
                continue
            for i, stmt in enumerate(block):
                tk = trigger_kind(stmt)
                if not tk:
                    continue
                if tk in ("pilot.press", "pilot.click"):
                    # these await idle themselves; count what follows directly
                    nxt = block[i + 1] if i + 1 < len(block) else None
                    k = "SELF-PAUSING:" + next_kind(nxt)
                else:
                    if i + 1 < len(block) and is_pause(block[i + 1]):
                        nxt = block[i + 2] if i + 2 < len(block) else None
                        k = "one-pause->" + next_kind(nxt)
                    else:
                        nxt = block[i + 1] if i + 1 < len(block) else None
                        k = "no-pause->" + next_kind(nxt)
                sites[k] += 1; triggers[tk] += 1
                if k.startswith("one-pause->READ"):
                    files[path.name] += 1
                    if len(examples[k]) < 400:
                        examples[k].append(f"{path.name}:{stmt.lineno}")
print("triggers:", dict(triggers))
for k, v in sorted(sites.items(), key=lambda kv: -kv[1]):
    print(f"{v:5d}  {k}")
print("files with one-pause->READ:", len(files), "sites:", sum(files.values()))
for f, n in files.most_common(15):
    print(f"   {n:4d} {f}")
if len(sys.argv) > 2:
    for k, ex in examples.items():
        print(k, " ".join(ex))
