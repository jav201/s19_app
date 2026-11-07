"""batch-101 Inc 12 E1 census: the static half of reproducing F-33, F-34, F-35, F-51.

Reads the base tree's source with ``ast`` only (it imports no ``s19_app``). Run
from the worktree root. Prints, per finding, the definitions, their product
call sites and the test nodes that name them (the QC-BC census of the slice).
"""
import ast
import os
import re
import sys
from pathlib import Path

ROOT = Path.cwd()
SRC = ROOT / "s19_app"
TESTS = ROOT / "tests"


def py_files(base: Path):
    for path in sorted(base.rglob("*.py")):
        if "__pycache__" not in path.parts:
            yield path


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


MODULES = {rel(p): (p.read_text(encoding="utf-8"), ast.parse(p.read_text(encoding="utf-8"))) for p in py_files(SRC)}


def enclosing_defs(tree):
    """-> {node id: qualified name of the def/class that encloses it}."""
    owner = {}

    def walk(node, stack):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                walk(child, stack + [child.name])
            else:
                owner[id(child)] = ".".join(stack) or "<module>"
                walk(child, stack)

    walk(tree, [])
    return owner


OWNERS = {name: enclosing_defs(tree) for name, (_text, tree) in MODULES.items()}


CALL_INDEX = {}
for _mod, (_text, _tree) in MODULES.items():
    for _node in ast.walk(_tree):
        if isinstance(_node, ast.Call):
            _f = _node.func
            if isinstance(_f, ast.Attribute):
                CALL_INDEX.setdefault(_f.attr, []).append((_mod, _node.lineno, OWNERS[_mod].get(id(_node), "?"), "attr"))
            elif isinstance(_f, ast.Name):
                CALL_INDEX.setdefault(_f.id, []).append((_mod, _node.lineno, OWNERS[_mod].get(id(_node), "?"), "name"))


def calls_to(name: str, attr_only: bool = False):
    """Every Call whose callee is ``name`` (a Name, or an Attribute ending in it)."""
    return [(m, l, o) for m, l, o, k in CALL_INDEX.get(name, ()) if not (attr_only and k == "name")]


NODE_BODIES = []


def node_bodies():
    """-> [(file::test, text)]: a test function's own source plus the source of the
    module-level helpers it names, two hops deep (functions and classes only)."""
    if NODE_BODIES:
        return NODE_BODIES
    for path in py_files(TESTS):
        text = path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue
        helpers = {}
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                helpers[node.name] = ast.get_source_segment(text, node) or ""
        words = {name: set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", src)) & set(helpers) for name, src in helpers.items()}
        for node in tree.body:
            if not (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test")):
                continue
            seen = {node.name}
            frontier = words[node.name]
            for _hop in range(2):
                frontier = {n for n in frontier if n not in seen}
                seen |= frontier
                frontier = set().union(*(words[n] for n in frontier)) if frontier else set()
            body = "\n".join(helpers[n] for n in sorted(seen))
            NODE_BODIES.append((f"{rel(path)}::{node.name}", body))
    return NODE_BODIES


def test_nodes(patterns):
    """-> {pattern: [file::test]} over :func:`node_bodies`."""
    compiled = {p: re.compile(p) for p in patterns}
    return {p: [n for n, body in node_bodies() if c.search(body)] for p, c in compiled.items()}


def show_nodes(title, patterns):
    print(f"-- test nodes naming {title}")
    nodes = test_nodes(patterns)
    for p in patterns:
        print(f"   {p}: {len(nodes[p])}")
        for n in nodes[p]:
            print(f"      {n}")


print("commit:", os.popen("git rev-parse --short=8 HEAD").read().strip())
print("python:", sys.version.split()[0])
print("modules parsed:", len(MODULES))

# --------------------------------------------------------------------- F-33
print("\n== F-33: dialogs (ModalScreen subclasses) and their product construction sites")
modal = {}
class_bases = {}
for mod, (_text, tree) in MODULES.items():
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            bases = set()
            for b in node.bases:
                v = b.value if isinstance(b, ast.Subscript) else b
                bases.add(v.id if isinstance(v, ast.Name) else getattr(v, "attr", None))
            class_bases[node.name] = (mod, node.lineno, node.end_lineno, bases)
changed = True
while changed:
    changed = False
    for cname, (mod, line, end, bases) in class_bases.items():
        if cname not in modal and ("ModalScreen" in bases or bases & set(modal)):
            modal[cname] = (mod, line, end)
            changed = True
orphans = []
for cls, (mod, line, end) in sorted(modal.items(), key=lambda kv: (kv[1][0], kv[1][1])):
    sites = [s for s in calls_to(cls) if not s[2].split(".")[0] == cls]
    subclassed = [c for c in modal if c != cls and cls in class_bases[c][3]]
    print(f"{cls:28s} {mod}:{line}-{end}  product construction sites: {len(sites)}"
          + (f"  (subclassed by {subclassed})" if subclassed else ""))
    if not sites and not subclassed:
        orphans.append(cls)
print("dialogs with no product construction site:", orphans)
for name in ("VariantHelpScreen", "VARIANT_HELP_TEXT"):
    hits = [(m, i + 1) for m, (t, _tr) in MODULES.items() for i, l in enumerate(t.splitlines()) if name in l]
    print(f"source lines naming {name}:", [f"{m}:{n}" for m, n in hits])
show_nodes("F-33", [r"VariantHelpScreen", r"_VARIANT_HELP_TOKENS", r"VARIANT_HELP_TEXT", r"variant_help_"])

# --------------------------------------------------------------------- F-34
print("\n== F-34: S19TuiApp actions and how each is reached")
app_text, app_tree = MODULES["s19_app/tui/app.py"]
app_cls = next(n for n in app_tree.body if isinstance(n, ast.ClassDef) and n.name == "S19TuiApp")
actions = [n.name[len("action_"):] for n in app_cls.body
           if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name.startswith("action_")]
literals = []
for mod, (_text, tree) in MODULES.items():
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            literals.append((mod, node.lineno, node.value))
TOKEN_SITES = {}
for m, l, v in literals:
    if len(v) >= 120:
        continue
    for tok in re.findall(r"(?:^|[\s:=.])(?:app\.)?([A-Za-z_][A-Za-z0-9_]*)(?=\(|$|\s)", v):
        TOKEN_SITES.setdefault(tok, []).append(f"{m}:{l}")
print("actions defined on S19TuiApp:", len(actions))
unreached = []
for a in actions:
    strings = TOKEN_SITES.get(a, [])
    direct = [f"{m}:{l} in {o}" for m, l, o in calls_to("action_" + a, attr_only=True) if o.split(".")[-1] != "action_" + a]
    if not strings:
        print(f"   {a:32s} action strings: 0  direct calls: {len(direct)} {direct}")
        unreached.append((a, direct))
print("actions with no action string (no key, palette entry, button or markup link):",
      [a for a, _d in unreached])
print("... of these, with no direct product call either:", [a for a, d in unreached if not d])
print("-- every action_* method of every class in s19_app (string literals that are not docstrings)")
docstring_ids = set()
for mod, (_text, tree) in MODULES.items():
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
                docstring_ids.add(id(first.value))
code_tokens = {}
for mod, (_text, tree) in MODULES.items():
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstring_ids and len(node.value) < 120:
            for tok in re.findall(r"(?:^|[\s:=.])(?:app\.|screen\.)?([A-Za-z_][A-Za-z0-9_]*)(?=\(|$|\s)", node.value):
                code_tokens.setdefault(tok, []).append(f"{mod}:{node.lineno}")
all_actions = [(mod, c.name, f.name[len("action_"):], f.lineno) for mod, (_t, tree) in MODULES.items()
               for c in ast.walk(tree) if isinstance(c, ast.ClassDef)
               for f in c.body if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef)) and f.name.startswith("action_")]
print("action methods in s19_app:", len(all_actions))
import importlib.util  # noqa: E402  (the framework's own bindings; textual is not s19_app)
framework_actions = {}
for location in importlib.util.find_spec("textual").submodule_search_locations:
    for path in sorted(Path(location).rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        for m in re.finditer(r'Binding\(\s*"[^"]*",\s*"([A-Za-z_][A-Za-z0-9_]*)', text):
            framework_actions.setdefault(m.group(1), path.name)
        for m in re.finditer(r'^\s*\(\s*"[^"]*",\s*"([A-Za-z_][A-Za-z0-9_]*)"', text, re.M):
            framework_actions.setdefault(m.group(1), path.name)
no_reach = []
for mod, cls, a, line in all_actions:
    direct = [f"{m}:{l}" for m, l, o in calls_to("action_" + a, attr_only=True) if o.split(".")[-1] != "action_" + a]
    if a not in code_tokens:
        inherited = framework_actions.get(a)
        print(f"   {cls}.action_{a} ({mod}:{line}): no action string in s19_app; direct calls {direct}"
              + (f"; bound by the framework ({inherited})" if inherited else ""))
        if not direct and not inherited:
            no_reach.append(f"{cls}.action_{a}")
print("action methods with no action string, no framework binding and no direct call:", no_reach)
print("-- one-hop caller census of the direct callers (D3-7 co-location)")
for fn in ("_jump_to_validation_issue_object", "_jump_to_validation_issue", "_format_validation_issue_line"):
    sites = [f"{m}:{l} in {o}" for m, l, o in calls_to(fn, attr_only=True)]
    print(f"   {fn}: product call sites {len(sites)} {sites}")
for key in ("1", "2", "3"):
    m = re.search(r'Binding\("%s", "([^"]+)"' % key, app_text)
    print(f"   key {key} -> {m.group(1) if m else None}")
show_nodes("F-34 / D3-7", [r"action_view_main|\"view_main\"", r"action_view_alt|\"view_alt\"",
                           r"action_view_mac|\"view_mac\"", r"_jump_to_validation_issue", r"_format_validation_issue_line"])

# --------------------------------------------------------------------- F-35
print("\n== F-35: widgets hidden at mount (display = False in compose / on_mount) and their readers")
hidden = []
for mod, (text, tree) in MODULES.items():
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or node.name not in ("compose", "on_mount"):
            continue
        seg = ast.get_source_segment(text, node) or ""
        cls = OWNERS[mod].get(id(node.body[0]), "?").split(".")[0]
        for m in re.finditer(r'for hidden in \(([^)]*)\)', seg):
            for wid in re.findall(r'"#([a-z0-9_]+)"', m.group(1)):
                hidden.append((mod, cls, node.name, wid))
        for m in re.finditer(r'query_one\("#([a-z0-9_]+)"[^)]*\)\.display = False', seg):
            hidden.append((mod, cls, node.name, m.group(1)))
        for m in re.finditer(r'(\w+) = Button\(\s*"[^"]*",\s*id="([a-z0-9_]+)"[^)]*\)\s*\n\s*\1\.display = False', seg):
            hidden.append((mod, cls, node.name, m.group(2)))
for mod, cls, fn, wid in hidden:
    q = re.compile(r'["\']#' + re.escape(wid) + r'["\'\s,)]')
    readers = [f"{m}:{i + 1}" for m, (t, _tr) in MODULES.items() for i, l in enumerate(t.splitlines())
               if q.search(l) and "display = False" not in l]
    print(f"{wid:30s} {cls}.{fn} ({mod})  product query sites: {len(readers)} {readers}")
show_nodes("F-35 ids (as a query selector or a quoted id)", [
    r'#check_preview_toggle_button\b|"check_preview_toggle_button"|CE_IDS_9C7BEAF',
    r'#flow_help\b|"flow_help"', r'#flow_canvas\b|"flow_canvas"', r'#flow_blocks\b|"flow_blocks"',
    r'#flow_kind\b|"flow_kind"', r'#flow_ext_session\b|"flow_ext_session"', r'#fx_help\b|"fx_help"'])
print("-- the Flow Builder canvas painter family (D16-6): definitions and every name reference")
fs_text, fs_tree = MODULES["s19_app/tui/flow_screens.py"]
family = ["_canvas_text", "_blocks_text", "_flow_block_label", "_layout", "_block_rows", "_Grid", "_plc_block",
          "_chip", "_wire_bend", "_wire_drop", "_block_width", "_short_ext", "_CANVAS_COLS", "_BLOCK_W", "_EXT_BLOCK_W",
          "_S_WIRE", "_S_LABEL", "_S_VALUE", "_S_HEAD"]
defs = {}
for node in ast.walk(fs_tree):
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name in family:
        defs.setdefault(node.name, []).append((node.lineno, node.end_lineno, OWNERS["s19_app/tui/flow_screens.py"].get(id(node.body[0]), "?").rsplit(".", 1)[0]))
    if isinstance(node, ast.Assign):
        for t in node.targets:
            if isinstance(t, ast.Name) and t.id in family:
                defs.setdefault(t.id, []).append((node.lineno, node.end_lineno, "<module>"))
methods = {"_canvas_text", "_blocks_text", "_layout", "_block_rows"}  # FlowBuilderPanel methods: count their calls
called = {id(n.func) for n in ast.walk(fs_tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
for name in family:
    refs = []
    for node in ast.walk(fs_tree):
        if name in methods:
            if isinstance(node, ast.Attribute) and node.attr == name and (id(node) in called or isinstance(node.ctx, ast.Load)
                                                                           and OWNERS["s19_app/tui/flow_screens.py"].get(id(node), "?").startswith("FlowBuilderPanel")):
                refs.append((node.lineno, OWNERS["s19_app/tui/flow_screens.py"].get(id(node), "?")))
        elif (isinstance(node, ast.Name) and node.id == name) or (isinstance(node, ast.Attribute) and node.attr == name):
            refs.append((node.lineno, OWNERS["s19_app/tui/flow_screens.py"].get(id(node), "?")))
    other = [f"{m}" for m, (t, _tr) in MODULES.items() if m != "s19_app/tui/flow_screens.py" and re.search(r"\b" + re.escape(name) + r"\b", t)]
    owners = sorted({o for _l, o in refs})
    print(f"   {name:18s} def {defs.get(name)}  referenced from {owners}" + (f"  other modules {other}" if other else ""))
print("   (for the four FlowBuilderPanel methods: calls, and loads inside FlowBuilderPanel; FlowExecutionPanel's own"
      " attribute of the same name `_layout` is not the method)")
show_nodes("the painter family", [r"_canvas_text", r"_blocks_text", r"_flow_block_label", r"_Grid\b"])

# --------------------------------------------------------------------- F-51
print("\n== F-51: the Reports dialog's bindings, and test nodes that open it and press escape")
scr_text, scr_tree = MODULES["s19_app/tui/screens.py"]
rv = next(n for n in scr_tree.body if isinstance(n, ast.ClassDef) and n.name == "ReportViewerScreen")
for n in rv.body:
    if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "BINDINGS" for t in n.targets):
        print(f"ReportViewerScreen.BINDINGS (screens.py:{n.lineno}):", ast.get_source_segment(scr_text, n.value).replace("\n", " "))
print("ReportViewerScreen action_* methods:", [n.name for n in rv.body if isinstance(n, ast.FunctionDef) and n.name.startswith("action_")])
openers = r'ReportViewerScreen|press\("t"\)|_open_reports_with_t|view_reports|screen_key == "reports"'
nodes = test_nodes([openers, r'press\(\s*"escape"|"escape"'])
both = sorted(set(nodes[openers]) & set(nodes[r'press\(\s*"escape"|"escape"']))
print(f"test nodes that open Reports (or name its seat): {len(nodes[openers])}; of these, pressing escape: {len(both)}")
for n in both:
    print("   ", n)
show_nodes("the Reports binding census", [r"ReportViewerScreen\.BINDINGS"])
