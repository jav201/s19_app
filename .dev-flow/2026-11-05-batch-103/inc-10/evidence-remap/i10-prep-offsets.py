"""batch-103 Inc 10 prep onto Inc 8 final (relevo-10): per-function line offsets between two commits (read only).

Usage: python -I -B i10-prep-offsets.py <repo> <old commit> <new commit>

For each (file, qualname) of Inc 10's slice and context at the package layout, reads the file at both commits with
`git show`, parses it with `ast` (nothing is imported from s19_app), and prints old lines, new lines, the offset of
the first line and whether the function's AST (docstring included) is identical. Stdlib only.
"""
import ast
import subprocess
import sys

repo, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
PE = "s19_app/tui/screens_directionb/patch_editor/"
AP = "s19_app/tui/app/"
TARGETS = [
    (PE + "panel.py", "PatchEditorPanel.SAVEBACK_WIDTHS"),
    (PE + "panel.py", "PatchEditorPanel._TABS"),
    (PE + "panel.py", "PatchEditorPanel.__init__"),
    (PE + "panel.py", "PatchEditorPanel.SaveBackDecision"),
    (PE + "panel.py", "PatchEditorPanel.SaveBackDecision.__init__"),
    (PE + "panel.py", "PatchEditorPanel._show_tab"),
    (PE + "layout.py", "LayoutMixin.compose"),
    (PE + "actions.py", "ActionsMixin._compose_action_bar"),
    (PE + "actions.py", "ActionsMixin._compose_doc_controls"),
    (PE + "actions.py", "ActionsMixin.on_button_pressed"),
    (PE + "actions.py", "ActionsMixin.show_save_prompt"),
    (PE + "actions.py", "ActionsMixin.hide_save_prompt"),
    (PE + "actions.py", "ActionsMixin.show_before_after_prompt"),
    (PE + "actions.py", "ActionsMixin.hide_before_after_prompt"),
    (AP + "patch.py", "_synth_s0_header_from_filename"),
    (AP + "patch.py", "PatchMixin.on_patch_editor_panel_action_requested"),
    (AP + "patch.py", "PatchMixin.on_staging_sheet_stage_requested"),
    (AP + "patch.py", "PatchMixin.on_patch_editor_panel_save_back_decision"),
    (AP + "patch.py", "PatchMixin._hide_replaced_document_controls"),
    (AP + "patch.py", "PatchMixin.action_patch_undo"),
    (AP + "patch.py", "PatchMixin.action_patch_redo"),
    (AP + "patch.py", "PatchMixin.on_patch_editor_panel_entry_edit_json_requested"),
    (AP + "patch.py", "PatchMixin._apply_entry_json_edit"),
    (AP + "patch.py", "PatchMixin._patch_editor_load"),
    (AP + "compose_screens.py", "ComposeScreensMixin._compose_screen_patch"),
    (AP + "project_load.py", "ProjectLoadMixin._reset_project_session"),
    (AP + "loaded_state.py", "LoadedStateMixin._apply_prepared_load"),
    ("s19_app/tui/services/change_service.py", "ChangeService.save_patched"),
    ("s19_app/tui/services/change_service.py", "ChangeService.emit_and_verify"),
]


def source(commit, path):
    out = subprocess.run(["git", "-C", repo, "show", f"{commit}:{path}"], capture_output=True)
    return out.stdout.decode("utf-8") if out.returncode == 0 else None


def find(tree, qual):
    node = tree
    for part in qual.split("."):
        found = None
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and child.name == part:
                found = child
                break
            if isinstance(child, ast.Assign) and any(isinstance(t, ast.Name) and t.id == part for t in child.targets):
                found = child
                break
            if isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name) and child.target.id == part:
                found = child
                break
        if found is None:
            return None
        node = found
    return node


print(f"# i10-prep-offsets: old {old} new {new}; python {sys.version.split()[0]}")
for path, qual in TARGETS:
    row = [qual]
    trees = []
    for commit in (old, new):
        text = source(commit, path)
        node = find(ast.parse(text), qual) if text is not None else None
        trees.append(node)
    a, b = trees
    if a is None or b is None:
        print(f"{path.split('/')[-1]}:{qual}: old={'-' if a is None else a.lineno} new={'-' if b is None else b.lineno} MISSING")
        continue
    same = ast.dump(a) == ast.dump(b)
    print(
        f"{path.split('/')[-1]}:{qual}: old {a.lineno}-{a.end_lineno} new {b.lineno}-{b.end_lineno} "
        f"offset {b.lineno - a.lineno:+d} {'same-ast' if same else 'DIFF'}"
    )
