"""batch-103 Inc 10 E2: rebase census of the E1 slice from e07fb00 to the E2 base (read only).

Usage: python -I i10e2-rebase-census.py <repo> <old commit> <new commit> <scratch dir>
`git archive`s s19_app/ of both commits into <scratch>/old and <scratch>/new (throwaway; no work tree is touched),
locates every slice function and context function by its qualname with `ast`, prints its def..end lines at
both commits and whether its AST is identical (same-ast) or not (DIFF); then prints every call site of the
callers list of E1-slice.md §3 at both commits (a regex over the source, `def` lines excluded).
"""
import ast, hashlib, re, shutil, subprocess, sys, tarfile, io
from pathlib import Path

repo, old, new, scratch = sys.argv[1], sys.argv[2], sys.argv[3], Path(sys.argv[4])
FILES = {"sdb": "s19_app/tui/screens_directionb.py", "app": "s19_app/tui/app.py",
         "cs": "s19_app/tui/services/change_service.py", "apply": "s19_app/tui/changes/apply.py",
         "verify": "s19_app/tui/changes/verify.py", "fes": "s19_app/tui/services/flow_execution_service.py",
         "ves": "s19_app/tui/services/variant_execution_service.py", "css": "s19_app/tui/styles.tcss"}
TARGETS = [("sdb", "PatchEditorPanel.SAVEBACK_WIDTHS"), ("sdb", "PatchEditorPanel.__init__"),
           ("sdb", "PatchEditorPanel.SaveBackDecision.__init__"), ("sdb", "PatchEditorPanel.compose"),
           ("sdb", "PatchEditorPanel.on_button_pressed"), ("sdb", "PatchEditorPanel.show_save_prompt"),
           ("sdb", "PatchEditorPanel.hide_save_prompt"), ("sdb", "PatchEditorPanel.show_before_after_prompt"),
           ("sdb", "PatchEditorPanel.hide_before_after_prompt"), ("sdb", "PatchEditorPanel._show_tab"),
           ("app", "S19TuiApp.on_patch_editor_panel_action_requested"),
           ("app", "S19TuiApp.on_patch_editor_panel_save_back_decision"),
           ("app", "S19TuiApp._hide_replaced_document_controls"), ("app", "_synth_s0_header_from_filename"),
           ("app", "S19TuiApp._compose_screen_patch"), ("app", "S19TuiApp._patch_editor_load"),
           ("app", "S19TuiApp.action_patch_undo"), ("app", "S19TuiApp.action_patch_redo"),
           ("app", "S19TuiApp._reset_project_session"), ("app", "S19TuiApp._apply_prepared_load"),
           ("app", "S19TuiApp._save_project_files"), ("app", "S19TuiApp._decide_project_image"),
           ("cs", "ChangeService.save_patched"), ("cs", "ChangeService.emit_and_verify"),
           ("apply", "save_patched_image"), ("apply", "render_patched_image"), ("verify", "verify_written_image"),
           ("fes", "run_flow"), ("ves", "_execute_one_variant")]
SITES = re.compile(r"show_save_prompt\(|hide_save_prompt\(|_hide_replaced_document_controls\(|\._show_tab\(|"
                   r"SaveBackDecision\(|\.save_patched\(|emit_and_verify\(|save_patched_image\(|"
                   r"render_patched_image\(|_synth_s0_header_from_filename\(|PatchEditorPanel\(\)|"
                   r"show_before_after_prompt\(|hide_before_after_prompt\(")


def extract(commit, dest):
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    data = subprocess.run(["git", "-C", repo, "archive", commit, "s19_app"], check=True, capture_output=True).stdout
    tarfile.open(fileobj=io.BytesIO(data)).extractall(dest, filter="data")


def index(root, rel):
    src = (root / rel).read_text(encoding="utf-8")
    out = {}

    def walk(node, prefix):
        for ch in ast.iter_child_nodes(node):
            if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = prefix + ch.name
                out[name] = (ch.lineno, ch.end_lineno, hashlib.sha1(ast.dump(ch).encode()).hexdigest()[:10])
                walk(ch, name + ".")
            elif isinstance(ch, (ast.Assign, ast.AnnAssign)) and prefix:
                for t in (ch.targets if isinstance(ch, ast.Assign) else [ch.target]):
                    if isinstance(t, ast.Name):
                        out[prefix + t.id] = (ch.lineno, ch.end_lineno, hashlib.sha1(ast.dump(ch).encode()).hexdigest()[:10])
    walk(ast.parse(src), "")
    return out


extract(old, scratch / "old")
extract(new, scratch / "new")
rev = lambda c: subprocess.run(["git", "-C", repo, "rev-parse", "--short=8", c], capture_output=True, text=True).stdout.strip()
print(f"# i10e2-rebase-census: old {rev(old)} new {rev(new)}; python {sys.version.split()[0]}")
print("## files identical at both commits")
for k, rel in FILES.items():
    a, b = (scratch / "old" / rel).read_bytes(), (scratch / "new" / rel).read_bytes()
    print(f"{rel}: {'identical' if a == b else 'differs'}")
print("## functions (def line - end line; AST equality)")
idx = {(r, k): index(scratch / r, v) for r in ("old", "new") for k, v in FILES.items() if k != "css"}
for f, name in TARGETS:
    o, n = idx[("old", f)].get(name), idx[("new", f)].get(name)
    os_, ns = (f"{o[0]}-{o[1]}" if o else "-"), (f"{n[0]}-{n[1]}" if n else "-")
    print(f"{FILES[f].split('/')[-1]:30} {name:52} {os_:12} -> {ns:12} {'same-ast' if o and n and o[2] == n[2] else 'DIFF'}")
print("## call sites (file:line, def lines excluded)")
for r in ("old", "new"):
    print(f"### {r}")
    for k in ("app", "sdb", "cs", "apply", "fes", "ves"):
        rel = FILES[k]
        for i, line in enumerate((scratch / r / rel).read_text(encoding="utf-8").splitlines(), 1):
            if SITES.search(line) and not line.lstrip().startswith(("def ", "class ", "#", ">>>", "-")):
                print(f"{rel.split('/')[-1]}:{i}: {line.strip()[:90]}")
