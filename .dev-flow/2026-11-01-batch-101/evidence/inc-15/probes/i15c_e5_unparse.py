"""i15c: unparse each table-D wait's trigger/description/predicate under this interpreter and compare with the guard table (pure AST, imports nothing from the repo)."""
import ast, sys, pathlib
root = pathlib.Path(sys.argv[1])
hy = ast.parse((root / "tests/test_suite_hygiene.py").read_text(encoding="utf-8"))
table = next(n for n in hy.body if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "_INC15_WAIT_SITES")
rows = ast.literal_eval(table.value)
ok = 0
for module, arm, helper, trigger, desc, pred in rows:
    t = ast.parse((root / module).read_text(encoding="utf-8"))
    fn = next(n for n in t.body if getattr(n, "name", "") == arm)
    drive = next(n for n in ast.walk(fn) if isinstance(n, ast.AsyncFunctionDef) and n.name == "_drive")
    if helper:
        body = next(n for n in ast.walk(drive) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == helper).body
    else:
        body = next(s for s in drive.body if isinstance(s, ast.AsyncWith)).body
    idx = max(i for i, s in enumerate(body) if ast.unparse(s) == trigger)
    call = body[idx + 1].value.value
    good = call.args[2].value == desc and ast.unparse(call.args[1]) == pred
    ok += good
    print("OK " if good else "BAD", desc, "" if good else ast.unparse(call.args[1]))
print(f"python {sys.version.split()[0]}: {ok}/{len(rows)} sites match")
