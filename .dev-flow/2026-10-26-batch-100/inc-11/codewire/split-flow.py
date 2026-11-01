"""Which locals of _handle_save_dialog cross from the guard-and-plan half (9447-9855)
into the commit half (9856-10606)? AST read of a throwaway copy; no edit."""
import ast, sys
from pathlib import Path
src = Path(sys.argv[1]).read_text(encoding="utf-8")
fn = next(n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef) and n.name == "_handle_save_dialog")
print("def", fn.lineno, "end", fn.end_lineno)
CUT = 9856
stores, loads, self_reads_commit, self_writes_prep = {}, {}, set(), set()
for n in ast.walk(fn):
    if isinstance(n, ast.Name):
        d = stores if isinstance(n.ctx, ast.Store) else loads
        d.setdefault(n.id, []).append(n.lineno)
    if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "self":
        if n.lineno >= CUT and isinstance(n.ctx, ast.Load):
            self_reads_commit.add(n.attr)
        if n.lineno < CUT and isinstance(n.ctx, ast.Store):
            self_writes_prep.add(n.attr)
args = [a.arg for a in fn.args.args]
cross = sorted(v for v in loads if any(l >= CUT for l in loads[v]) and (
    any(s < CUT for s in stores.get(v, [])) or v in args))
print("crossing names:", cross)
for v in cross:
    print(f"  {v}: stored {[s for s in stores.get(v, []) if s < CUT] or 'arg'} read-after-cut {[l for l in loads[v] if l >= CUT][:6]}")
print("prep-only names:", sorted(v for v in stores if all(s < CUT for s in stores[v]) and not any(l >= CUT for l in loads.get(v, []))))
print("self writes in prep half:", sorted(self_writes_prep))
rets = [n.lineno for n in ast.walk(fn) if isinstance(n, ast.Return)]
print("returns before cut:", len([r for r in rets if r < CUT]), "after:", len([r for r in rets if r >= CUT]))
st = [n.lineno for n in ast.walk(fn) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "set_status"]
print("set_status before cut:", len([r for r in st if r < CUT]), "after:", len([r for r in st if r >= CUT]))
nt = [n.lineno for n in ast.walk(fn) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "notify"]
print("notify before cut:", [r for r in nt if r < CUT], "after:", [r for r in nt if r >= CUT])
