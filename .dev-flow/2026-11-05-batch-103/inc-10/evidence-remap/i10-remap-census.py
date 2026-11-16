"""batch-103 Inc 10 re-map (relevo-8): locate every slice and context function of Inc 10 at the new base (read only).

Usage: python -I -B i10-remap-census.py <repo> <old commit> <new commit> <scratch dir>

`git archive`s s19_app/ of both commits into <scratch>/old and <scratch>/new (throwaway, outside every work tree;
no work tree is touched). For each function of the Inc 10 slice and context (E1-slice.md §2, §3, §6; graph-inc10.md
baseline), finds its definition at the old commit by qualname in its old file, and at the new commit by the same
qualname tail (the class part may change: batch-modular moved S19TuiApp's methods into app/*.py mixins and the
patch_editor split moved PatchEditorPanel's methods into patch_editor/*.py mixins) inside the new package. Prints
old file:lines -> new file:class.method:lines and whether the AST (docstring included) is identical. Then:
  - the moved save-back rows: the AST of each `with Container(id=...)` block of the prompt, old compose vs new;
  - the call sites of the slice's callees at the new commit, with the enclosing def found by `ast`;
  - byte identity of the files the slice reads but does not move.
Stdlib only; imports nothing from s19_app.
"""
import ast, hashlib, io, re, shutil, subprocess, sys, tarfile
from pathlib import Path

repo, old, new, scratch = sys.argv[1], sys.argv[2], sys.argv[3], Path(sys.argv[4])
OLD_SDB, OLD_APP = "s19_app/tui/screens_directionb.py", "s19_app/tui/app.py"
NEW_PE, NEW_APP = "s19_app/tui/screens_directionb/patch_editor", "s19_app/tui/app"
SAME = ["s19_app/tui/changes/io.py", "s19_app/tui/changes/apply.py", "s19_app/tui/changes/verify.py",
        "s19_app/tui/services/change_service.py", "s19_app/tui/services/flow_execution_service.py",
        "s19_app/tui/services/variant_execution_service.py", "s19_app/segment_ops.py", "s19_app/hexfile.py",
        "s19_app/tui/styles.tcss"]
# (old file, old qualname, new search root)
TARGETS = [(OLD_SDB, q, NEW_PE) for q in (
    "PatchEditorPanel.SAVEBACK_WIDTHS", "PatchEditorPanel.__init__", "PatchEditorPanel.SaveBackDecision",
    "PatchEditorPanel.SaveBackDecision.__init__", "PatchEditorPanel.compose", "PatchEditorPanel.on_button_pressed",
    "PatchEditorPanel.show_save_prompt", "PatchEditorPanel.hide_save_prompt",
    "PatchEditorPanel.show_before_after_prompt", "PatchEditorPanel.hide_before_after_prompt",
    "PatchEditorPanel._show_tab")] + [(OLD_APP, q, NEW_APP) for q in (
    "_synth_s0_header_from_filename", "S19TuiApp.on_patch_editor_panel_action_requested",
    "S19TuiApp.on_patch_editor_panel_save_back_decision", "S19TuiApp._hide_replaced_document_controls",
    "S19TuiApp._apply_entry_json_edit", "S19TuiApp.on_patch_editor_panel_entry_edit_json_requested",
    "S19TuiApp._compose_screen_patch", "S19TuiApp._patch_editor_load", "S19TuiApp.action_patch_undo",
    "S19TuiApp.action_patch_redo", "S19TuiApp._reset_project_session", "S19TuiApp._apply_prepared_load",
    "S19TuiApp._save_project_files", "S19TuiApp._decide_project_image", "S19TuiApp._activate_project_file")] + [
    ("s19_app/tui/services/change_service.py", "ChangeService.save_patched", None),
    ("s19_app/tui/services/change_service.py", "ChangeService.emit_and_verify", None),
    ("s19_app/tui/changes/apply.py", "save_patched_image", None),
    ("s19_app/tui/changes/apply.py", "render_patched_image", None),
    ("s19_app/tui/changes/verify.py", "verify_written_image", None),
    ("s19_app/tui/changes/io.py", "emit_intel_hex_from_mem_map", None)]
ROW_IDS = ("patch_saveback_row", "patch_before_after_row", "patch_doc_controls")
SITES = re.compile(r"show_save_prompt\(|hide_save_prompt\(|_hide_replaced_document_controls\(|\._show_tab\(|"
                   r"SaveBackDecision\(|\.save_patched\(|emit_and_verify\(|save_patched_image\(|"
                   r"render_patched_image\(|_synth_s0_header_from_filename\(|PatchEditorPanel\(\)|"
                   r"show_before_after_prompt\(|hide_before_after_prompt\(|_compose_doc_controls\(|"
                   r"_compose_action_bar\(|_apply_entry_json_edit\b|emit_intel_hex_from_mem_map\b")


def extract(commit, dest):
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    data = subprocess.run(["git", "-C", repo, "archive", commit, "s19_app"], check=True, capture_output=True).stdout
    tarfile.open(fileobj=io.BytesIO(data)).extractall(dest, filter="data")


def index(path):
    """qualname -> (lineno, end_lineno, ast hash, node) for every def, class and class-level assignment."""
    out = {}

    def walk(node, prefix):
        for ch in ast.iter_child_nodes(node):
            if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = prefix + ch.name
                out[name] = (ch.lineno, ch.end_lineno, hashlib.sha1(ast.dump(ch).encode()).hexdigest()[:10], ch)
                walk(ch, name + ".")
            elif isinstance(ch, (ast.Assign, ast.AnnAssign)) and prefix:
                for t in (ch.targets if isinstance(ch, ast.Assign) else [ch.target]):
                    if isinstance(t, ast.Name):
                        out[prefix + t.id] = (ch.lineno, ch.end_lineno,
                                              hashlib.sha1(ast.dump(ch).encode()).hexdigest()[:10], ch)
    walk(ast.parse(path.read_text(encoding="utf-8")), "")
    return out


def tail(q):
    """The qualname without its outermost class (module-level names stay whole)."""
    parts = q.split(".")
    return ".".join(parts[1:]) if len(parts) > 1 else q


def find_new(root, q):
    hits = []
    for p in sorted((scratch / "new" / root).rglob("*.py")):
        for name, v in index(p).items():
            if name == q or (len(q.split(".")) > 1 and len(name.split(".")) == len(q.split("."))
                             and tail(name) == tail(q)):
                hits.append((p.relative_to(scratch / "new").as_posix(), name, v))
    return hits


def row_blocks(fnode):
    """id -> ast hash of each `with Container/Horizontal(id=<ROW_IDS>)` block inside a function node."""
    out = {}
    for n in ast.walk(fnode):
        if isinstance(n, ast.With):
            for item in n.items:
                c = item.context_expr
                if isinstance(c, ast.Call):
                    for kw in c.keywords:
                        if kw.arg == "id" and isinstance(kw.value, ast.Constant) and kw.value.value in ROW_IDS:
                            out[kw.value.value] = (n.lineno, n.end_lineno,
                                                   hashlib.sha1(ast.dump(n).encode()).hexdigest()[:10])
    return out


def enclosing(tree_index, line):
    best = None
    for name, (a, b, _h, node) in tree_index.items():
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and a <= line <= b:
            if best is None or a >= best[1]:
                best = (name, a)
    return best[0] if best else "<module>"


extract(old, scratch / "old")
extract(new, scratch / "new")
rev = lambda c: subprocess.run(["git", "-C", repo, "rev-parse", "--short=8", c], capture_output=True,
                               text=True).stdout.strip()
print(f"# i10-remap-census: old {rev(old)} new {rev(new)}; python {sys.version.split()[0]}")
print("## files read by the slice, not moved: byte identity old -> new")
for rel in SAME:
    a, b = scratch / "old" / rel, scratch / "new" / rel
    print(f"{rel}: {'identical' if a.exists() and b.exists() and a.read_bytes() == b.read_bytes() else 'DIFFERS'}")
print("## functions: old file:lines -> new file:qualname:lines (AST equality, docstring included)")
moved = {}
for f, q, root in TARGETS:
    o = index(scratch / "old" / f).get(q)
    os_ = f"{f.split('/')[-1]}:{o[0]}-{o[1]}" if o else "-"
    hits = find_new(root, q) if root else [(f, q, index(scratch / "new" / f).get(q))]
    hits = [h for h in hits if h[2]]
    if not hits:
        print(f"{q:58} {os_:32} -> NOT FOUND")
    for rel, name, n in hits:
        eq = "same-ast" if o and n[2] == o[2] else "DIFF"
        print(f"{q:58} {os_:32} -> {rel.split('tui/')[-1]}:{name}:{n[0]}-{n[1]} {eq}"
              + (" (AMBIGUOUS)" if len(hits) > 1 else ""))
        moved[q] = (rel, name, n)
print("## the prompt's blocks: old PatchEditorPanel.compose vs the new compose helpers")
old_compose = index(scratch / "old" / OLD_SDB)["PatchEditorPanel.compose"][3]
ob = row_blocks(old_compose)
new_blocks = {}
for p in sorted((scratch / "new" / NEW_PE).glob("*.py")):
    for name, v in index(p).items():
        if isinstance(v[3], ast.FunctionDef):
            for rid, b in row_blocks(v[3]).items():
                new_blocks.setdefault(rid, []).append((p.name, name, b))
for rid in ROW_IDS:
    o = ob.get(rid)
    for fn, name, b in new_blocks.get(rid, []):
        print(f"#{rid:24} old compose:{o[0]}-{o[1]} -> {fn}:{name}:{b[0]}-{b[1]} "
              f"{'same-ast' if o and o[2] == b[2] else 'DIFF'}")
print("## call sites at the new commit (file:line enclosing-def: text; def/class/comment lines excluded)")
for p in sorted((scratch / "new" / "s19_app").rglob("*.py")):
    lines = p.read_text(encoding="utf-8").splitlines()
    hit = [(i, l) for i, l in enumerate(lines, 1)
           if SITES.search(l) and not l.lstrip().startswith(("def ", "class ", "#", ">>>", "-", "``", "*"))]
    if hit:
        ti = index(p)
        for i, l in hit:
            print(f"{p.relative_to(scratch / 'new').as_posix().split('s19_app/')[-1]}:{i} "
                  f"{enclosing(ti, i)}: {l.strip()[:80]}")
