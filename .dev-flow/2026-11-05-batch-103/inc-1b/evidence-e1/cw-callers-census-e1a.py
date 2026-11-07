"""batch-103 Inc 1b E1 addendum (keys and quit dialog): Code-Wire v3.1.0 callers census (throwaway copy; marks never in a work tree).

Usage: python cw-callers-census.py <base copy of e07fb00 s19_app/> <scratch dir> <graph out> <report out>
1. copies <base> to <scratch>/repo and inserts `# node:` marks above the chosen defs;
2. writes the context graph (in:/out: from the real signatures) to <graph out>;
3. runs code-wire/tools/codewire_extract.py; 4. maps each call site back to its e07fb00 line.
"""
import ast, json, re, shutil, subprocess, sys
from pathlib import Path

base, scratch, graph_out, report_out = (Path(a) for a in sys.argv[1:5])
TARGETS = {
    "s19_app/tui/app.py": ["S19TuiApp._compose_screen_a2l", "S19TuiApp._compose_screen_mac",
                           "S19TuiApp.action_quit", "S19TuiApp._answer_quit",
                           "S19TuiApp._running_session_action", "S19TuiApp.on_data_table_row_selected"],
}
repo = scratch / "repo"
if repo.exists():
    shutil.rmtree(repo)
shutil.copytree(base, repo)
nodes, inserted = [], {}
for rel, quals in TARGETS.items():
    p = repo / rel
    lines = p.read_text(encoding="utf-8").splitlines(keepends=True)
    tree = ast.parse("".join(lines))
    found = {}
    def walk(node, prefix):
        for ch in ast.iter_child_nodes(node):
            if isinstance(ch, ast.ClassDef):
                walk(ch, prefix + ch.name + ".")
            elif isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef)) and prefix + ch.name in quals:
                found[prefix + ch.name] = ch
    walk(tree, "")
    for q, fn in found.items():
        a = fn.args
        pos = a.posonlyargs + a.args
        defaults = [None] * (len(pos) - len(a.defaults)) + list(a.defaults)
        parts = []
        for arg, d in list(zip(pos, defaults)) + list(zip(a.kwonlyargs, a.kw_defaults)):
            if arg.arg in ("self", "cls"):
                continue
            t = ast.unparse(arg.annotation) if arg.annotation else "Any"
            parts.append(f"{t} {arg.arg}" + (f" = {ast.unparse(d)}" if d is not None else ""))
        out = ast.unparse(fn.returns) if fn.returns else "None"
        nodes.append((q, rel, "; ".join(parts), out, fn.lineno))
    marks = sorted(((min([fn.lineno] + [d.lineno for d in fn.decorator_list]), fn.col_offset, q) for q, fn in found.items()), reverse=True)
    for ln, col, q in marks:
        lines.insert(ln - 1, " " * col + f"# node: {q}\n")
    inserted[rel] = sorted(ln for ln, _, _ in marks)
    p.write_text("".join(lines), encoding="utf-8")
g = ["# Code-Wire callers census — batch-103 Inc 1b E1 addendum (throwaway context graph; not the E2 prototype)", "",
     "Context nodes Inc 1b reads or overrides beside; contracts copied from the e07fb00 signatures.", "", "## Nodes", ""]
for q, rel, inp, out, ln in nodes:
    g += [q, "req: to trace", f"in: {inp}", f"out: {out} result" if out != "None" else "out: None",
          f"func: unchanged (census context; e07fb00 {rel}:{ln})", f"module: {rel}", ""]
graph_out.write_text("\n".join(g), encoding="utf-8")
outdir = scratch / "out"
if outdir.exists():
    shutil.rmtree(outdir)
cw = Path(r"C:\Users\jjgh8\Github\code-wire\tools\codewire_extract.py")
r = subprocess.run([sys.executable, str(cw), "--repo", str(repo), "--graph", str(graph_out), "--out", str(outdir)],
                   capture_output=True, text=True)
data = json.loads((outdir / "extract.json").read_text(encoding="utf-8"))

def to_base(site):
    m = re.match(r"(.+?):(\d+)(.*)", site)
    rel, ln, rest = m.group(1), int(m.group(2)), m.group(3)
    shift = sum(1 for x in inserted.get(rel, []) if x + sum(1 for y in inserted.get(rel, []) if y < x) <= ln)
    return f"{rel}:{ln - shift}{rest}"

rep = [f"codewire_extract.py exit={r.returncode}; stdout: {r.stdout.strip()}", "",
       "Line numbers below are mapped back to e07fb00 (the marks shift the copy).", "",
       "## Real calls between marked nodes (caller -> callee: sites)"]
for c in data["calls"]:
    rep.append(f"- {c.get('from', c.get('caller'))} -> {c.get('to', c.get('callee'))}: " + ", ".join(to_base(s) for s in c.get("sites", [])))
rep += ["", "## Callers outside the marked set (top-level sites)"]
for y, sites in sorted(data["top_level_sites"].items()):
    rep.append(f"- {y}: " + ", ".join(to_base(s) for s in sites))
rep += ["", "## Findings (drift lines, expected only if a contract above is wrong)"]
for f in data.get("findings", []):
    rep.append(f"- {f.get('kind')}: {f.get('node', '')} {f.get('detail', '')}")
report_out.write_text("\n".join(rep) + "\n", encoding="utf-8")
print("\n".join(rep))
