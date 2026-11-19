"""Retire 13 tests + TC-678 for the batch-103 fix round (unit U2-retire).

Stdlib only. Dry run unless ``--apply``. All-or-nothing write.

Edits exactly 8 test files, ``AT-TC-REGISTRY.jsonl`` and
``docs/requirements/review/S10-ears-strict.md``. No product file.

Exit codes: 0 ok (or already applied), 2 a listed name is wrong / still
referenced, 3 a write guard failed (nothing written).
"""

import argparse
import ast
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent / "repo"

# ---------------------------------------------------------------------------
# The fixed spec — step 1: functions deleted by AST name.
# ---------------------------------------------------------------------------
DELETE_FUNCS = {
    "tests/test_tui_helpers.py": [
        "test_resolve_input_path_falls_back_to_repo_root",
        "test_find_repo_root_detects_marker",
        "test_render_hex_view_includes_focus_context",
    ],
    "tests/test_validation_mac.py": [
        "test_validate_mac_records_duplicate_address_info_when_allow_policy",
    ],
    "tests/test_tui_operations_view.py": [
        "test_operations_view_executes_via_service",
    ],
    "tests/test_diff_report_service.py": [
        "test_self_contained_listing_newest_first",
    ],
    "tests/test_change_service.py": [
        "test_retired_method_names_absent",
    ],
    "tests/test_tui_patch_editor_b94.py": [
        "test_at_b94_08_variant_machinery_retired",
    ],
    "tests/test_command_bar_interlock.py": [
        "test_tc678_interlock_arm_shipped_surface_is_clean",
    ],
    "tests/test_loadfilescreen_input.py": [
        "test_os_clipboard_input_is_input_subclass",
        "test_read_os_clipboard_happy_path_uses_only_first_strategy",
        "test_powershell_layer_returns_none_on_non_windows",
        "test_ctypes_layer_returns_none_on_non_windows",
    ],
}

# ---------------------------------------------------------------------------
# Step 2 — allowlisted names removed only once they carry zero references
# (AST Name/Attribute loads). Kinds: import, func (definition), assign.
# ---------------------------------------------------------------------------
ALLOWLIST = {
    "tests/test_tui_helpers.py": [
        ("import", "find_repo_root"),
        ("import", "FOCUS_CONTEXT_ROWS"),
        ("import", "HEX_WIDTH"),
    ],
    "tests/test_tui_operations_view.py": [
        ("import", "LoadedFile"),
    ],
    "tests/test_diff_report_service.py": [
        ("import", "list_diff_reports"),
    ],
    "tests/test_command_bar_interlock.py": [
        ("func", "_shipped_surface_files"),
        ("assign", "_TUI_DIR"),
        ("import", "s19_app"),
    ],
    "tests/test_loadfilescreen_input.py": [
        ("import", "OsClipboardInput"),
    ],
}

REGISTRY = "AT-TC-REGISTRY.jsonl"
S10_DOC = "docs/requirements/review/S10-ears-strict.md"

# Docstring coverage-map bullets naming a retired test (removed so the
# step-5 grep sees only the TC-678 retired_reason). Rule 3 sanctions updating
# docstring wording that names an old seam.
COVERAGE_REMOVALS = {
    "tests/test_tui_patch_editor_b94.py": ["test_at_b94_08_variant_machinery_retired"],
}

# Step 3 — registry node removals and the TC-678 replacement.
REGISTRY_EDITS = {
    "TC-638": {
        "remove": [
            "tests/test_tui_helpers.py::test_find_repo_root_detects_marker",
            "tests/test_tui_helpers.py::test_render_hex_view_includes_focus_context",
            "tests/test_tui_helpers.py::test_resolve_input_path_falls_back_to_repo_root",
        ],
    },
    "TC-628": {
        "remove": [
            "tests/test_validation_mac.py::test_validate_mac_records_duplicate_address_info_when_allow_policy",
        ],
    },
    "TC-011": {
        "remove": [
            "tests/test_tui_operations_view.py::test_operations_view_executes_via_service",
        ],
        "statement_sub": [("(+11 more)", "(+10 more)")],
    },
    "TC-017": {
        "remove": [
            "tests/test_diff_report_service.py::test_self_contained_listing_newest_first",
        ],
        "statement": (
            "Seeded from the existing verifier(s): _install_prg_loaded_file, "
            "test_tc017_address_is_the_canonical_hex_string_field (+6 more)."
        ),
    },
}

TC678_NEW = {
    "id": "TC-678",
    "space": "TC",
    "status": "RETIRED",
    "conforming": True,
    "origin": "batch-93",
    "retired_reason": (
        "Retired in the batch-103 fix round (TR-01): its verifier "
        "tests/test_command_bar_interlock.py::test_tc678_interlock_arm_shipped_surface_is_clean "
        "was removed because the requirement it verified, HLR-133 / LLR-133.1, is retired as "
        "history in REQUIREMENTS.md S0.2 (a rule on one batch's diff: no command bar on the map). "
        "TC-679 and AT-295 were not part of this retirement."
    ),
}

# Step 4 — S10-ears-strict.md line 375 (D10-4), exact substring swap.
S10_OLD = "; `test_at_b94_08_variant_machinery_retired` pins their absence."
S10_NEW = "; the batch-103 fix round retired their absence test (TR-01: D10-4 leaves no row to verify)."


def fail(code, msg):
    """Print an error and exit with the given code (2 or 3)."""
    print(f"retire_apply: {msg}", file=sys.stderr)
    sys.exit(code)


def load_lines(path):
    raw = path.read_text(encoding="utf-8")
    if "\r" in raw:
        fail(3, f"{path}: CR found, refusing (LF-only rule)")
    if not raw.endswith("\n"):
        fail(3, f"{path}: missing trailing newline")
    lines = raw.split("\n")
    assert lines[-1] == ""
    return lines[:-1]


def dump_lines(lines):
    return "\n".join(lines) + "\n"


def collapse_blanks(lines):
    """Collapse every run of 3+ blank lines down to 2."""
    out, run = [], 0
    for line in lines:
        if line.strip() == "":
            run += 1
            if run <= 2:
                out.append(line)
        else:
            run = 0
            out.append(line)
    return out


def name_load_count(source, name):
    """Count AST Name/Attribute *loads* of ``name`` in a module source."""
    tree = ast.parse(source)
    count = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == name and isinstance(node.ctx, ast.Load):
            count += 1
        elif isinstance(node, ast.Attribute) and node.attr == name and isinstance(node.ctx, ast.Load):
            count += 1
    return count


def comment_indices_above(lines, start_line):
    """0-based indices of the contiguous comment block directly above
    ``start_line`` (1-based). Stops at the first non-comment line."""
    idxs, i = [], start_line - 2
    while i >= 0 and lines[i].lstrip().startswith("#"):
        idxs.append(i)
        i -= 1
    return sorted(idxs)


def locate_function(tree, name):
    """Top-level FunctionDef/AsyncFunctionDef named ``name``, else exit 2."""
    matches = [
        n for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name
    ]
    if not matches:
        fail(2, f"{name}: missing (no such top-level function)")
    if len(matches) > 1:
        fail(2, f"{name}: defined twice")
    node = matches[0]
    if not any(node is stmt for stmt in tree.body):
        fail(2, f"{name}: nested in a class, not top-level")
    return node


def func_block(lines, tree, name):
    """(start_idx, end_idx) to delete for a top-level function, incl. the
    contiguous comment block directly above it."""
    node = locate_function(tree, name)
    start_line = min([d.lineno for d in node.decorator_list] + [node.lineno])
    above = comment_indices_above(lines, start_line)
    start = above[0] if above else start_line - 1
    return start, node.end_lineno - 1


def locate_assign(tree, name):
    """Top-level single-target ``Assign`` of ``name``, else exit 2."""
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            t = stmt.targets[0]
            if isinstance(t, ast.Name) and t.id == name:
                return stmt
    fail(2, f"{name}: missing (no such top-level assignment)")


def assign_block(lines, tree, name):
    node = locate_assign(tree, name)
    above = comment_indices_above(lines, node.lineno)
    start = above[0] if above else node.lineno - 1
    return start, node.end_lineno - 1


def locate_import(tree, name):
    """Top-level Import/ImportFrom binding ``name``, else exit 2."""
    for stmt in tree.body:
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            for alias in stmt.names:
                bound = alias.asname or alias.name
                if bound == name:
                    return stmt
    fail(2, f"{name}: missing (no such import)")


def remove_coverage_bullet(lines, name):
    """Remove the module-docstring coverage-map bullet (and its indented
    continuation lines) that names a retired test. Returns True if removed."""
    for i, line in enumerate(lines):
        if name in line and line.lstrip().startswith("- "):
            j = i + 1
            while j < len(lines) and lines[j].strip() and not lines[j].lstrip().startswith("- "):
                j += 1
            del lines[i:j]
            return True
    return False


def remove_import_name(lines, tree, name):
    """Remove ``name`` from its import; drop the whole statement if it is the
    only imported name, otherwise drop the single line that holds it."""
    stmt = locate_import(tree, name)
    start, end = stmt.lineno - 1, stmt.end_lineno - 1
    if len(stmt.names) == 1:
        del lines[start:end + 1]
        return
    pat = re.compile(r"^\s*" + re.escape(name) + r"\s*,?\s*(?:#.*)?$")
    for i in range(start, end + 1):
        if pat.match(lines[i]):
            del lines[i]
            return
    fail(2, f"{name}: import name not found on its own line")


def top_level_names(source):
    """Return (functions, classes) as sets of top-level names."""
    tree = ast.parse(source)
    funcs = {n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    classes = {n.name for n in tree.body if isinstance(n, ast.ClassDef)}
    tests = {n for n in funcs if n.startswith("test_")}
    return funcs, classes, tests


def unused_module_imports(source):
    """Module-level import names with zero Name/Attribute loads (report-only)."""
    tree = ast.parse(source)
    imported = {}
    for stmt in tree.body:
        if isinstance(stmt, ast.Import):
            for a in stmt.names:
                imported[a.asname or a.name] = stmt.lineno
        elif isinstance(stmt, ast.ImportFrom) and stmt.module != "__future__":
            for a in stmt.names:
                imported[a.asname or a.name] = stmt.lineno
    loads = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
            loads.add(n.id)
        elif isinstance(n, ast.Attribute) and isinstance(n.ctx, ast.Load):
            loads.add(n.attr)
    return {name: line for name, line in imported.items() if name not in loads}


# ---------------------------------------------------------------------------
# Step 1 — delete the 13 test functions.
# ---------------------------------------------------------------------------
def delete_functions(lines, rel, names):
    tree = ast.parse("\n".join(lines))
    blocks = [func_block(lines, tree, name) for name in names]
    for start, end in sorted(blocks, reverse=True):
        del lines[start:end + 1]
    return collapse_blanks(lines)


# ---------------------------------------------------------------------------
# Step 2 — remove allowlisted names left with zero references.
# ---------------------------------------------------------------------------
def remove_allowlist(lines, rel, allowlist):
    removed = set()
    changed = True
    while changed:
        changed = False
        source = "\n".join(lines)
        for kind, name in allowlist:
            if (kind, name) in removed:
                continue
            if name_load_count(source, name) != 0:
                continue
            tree = ast.parse(source)
            if kind == "func":
                start, end = func_block(lines, tree, name)
                del lines[start:end + 1]
            elif kind == "assign":
                start, end = assign_block(lines, tree, name)
                del lines[start:end + 1]
            else:
                remove_import_name(lines, tree, name)
            removed.add((kind, name))
            changed = True
            break
    source = "\n".join(lines)
    for kind, name in allowlist:
        if (kind, name) not in removed and name_load_count(source, name) > 0:
            fail(2, f"{rel}: {name} still referenced")
    return collapse_blanks(lines)


# ---------------------------------------------------------------------------
# Step 3 — registry line edits (untouched lines stay byte-identical).
# ---------------------------------------------------------------------------
def registry_roundtrip_ok(entry_lines):
    for line in entry_lines:
        if json.dumps(json.loads(line), ensure_ascii=False) != line:
            return False
    return True


def apply_registry(lines):
    report = []
    target_ids = set(REGISTRY_EDITS) | {"TC-678"}
    targets = []
    for idx, line in enumerate(lines):
        if not line.strip():
            continue
        entry = json.loads(line)
        if entry.get("id") in target_ids:
            targets.append((idx, line, entry))
    if not registry_roundtrip_ok([ln for _, ln, _ in targets]):
        fail(3, "registry re-serialisation would not be byte-identical")
    for idx, _line, entry in targets:
        eid = entry["id"]
        if eid == "TC-678":
            lines[idx] = json.dumps(TC678_NEW, ensure_ascii=False)
            report.append("TC-678 -> RETIRED (statement/nodes dropped, retired_reason added)")
            continue
        spec = REGISTRY_EDITS[eid]
        before = len(entry["nodes"])
        entry["nodes"] = [n for n in entry["nodes"] if n not in set(spec["remove"])]
        if "statement_sub" in spec:
            for old, new in spec["statement_sub"]:
                entry["statement"] = entry["statement"].replace(old, new)
        if "statement" in spec:
            entry["statement"] = spec["statement"]
        after = len(entry["nodes"])
        lines[idx] = json.dumps(entry, ensure_ascii=False)
        report.append(f"{eid}: {before} -> {after} nodes")
    return lines, report


# ---------------------------------------------------------------------------
# Step 4 — S10 doc line 375 (D10-4) substring swap, once.
# ---------------------------------------------------------------------------
def apply_doc(text):
    count = text.count(S10_OLD)
    if count != 1:
        fail(2, f"S10 doc: old substring found {count} times (expected 1)")
    return text.replace(S10_OLD, S10_NEW, 1)


def is_already_applied():
    reg = (ROOT / REGISTRY).read_text(encoding="utf-8")
    for line in reg.split("\n"):
        if not line.strip():
            continue
        entry = json.loads(line)
        if entry.get("id") == "TC-678":
            return entry.get("status") == "RETIRED"
    return False


def report_already():
    for step in ("STEP 1: delete functions", "STEP 2: remove allowlisted names",
                 "STEP 3: registry", "STEP 4: doc"):
        print(f"{step} — already")


def compute():
    """Compute every new file content in memory (no writes) and a report."""
    report = []
    new_files = {}

    for rel, names in DELETE_FUNCS.items():
        path = ROOT / rel
        orig = path.read_text(encoding="utf-8")
        lines = load_lines(path)
        before_funcs, before_classes, before_tests = top_level_names(orig)
        lines = delete_functions(lines, rel, names)
        for name in names:
            report.append(f"DELETE {rel}::{name}")
        if rel in ALLOWLIST:
            lines = remove_allowlist(lines, rel, ALLOWLIST[rel])
            for _kind, name in ALLOWLIST[rel]:
                report.append(f"REMOVE {rel}: {name}")
        if rel in COVERAGE_REMOVALS:
            for name in COVERAGE_REMOVALS[rel]:
                if not remove_coverage_bullet(lines, name):
                    fail(2, f"{rel}: coverage bullet naming {name} not found")
                report.append(f"COVERAGE {rel}: drop bullet naming {name}")
        new_src = dump_lines(lines)
        # Guards (per .py file) before accepting this file's content.
        compile(new_src, rel, "exec")
        after_funcs, after_classes, after_tests = top_level_names(new_src)
        removed_tests = set(names)
        removed_funcs = removed_tests | ({"_shipped_surface_files"} if rel in ALLOWLIST else set())
        if after_tests != before_tests - removed_tests:
            fail(3, f"{rel}: test_* set mismatch after edit")
        if after_funcs != before_funcs - removed_funcs:
            fail(3, f"{rel}: a non-allowlisted function was removed")
        if after_classes != before_classes:
            fail(3, f"{rel}: a class was removed")
        new_files[rel] = new_src
        unused = unused_module_imports(new_src)
        if unused:
            report.append(f"  other unused imports {rel}: {sorted(unused.items())}")

    reg_path = ROOT / REGISTRY
    reg_lines = load_lines(reg_path)
    reg_lines, reg_report = apply_registry(reg_lines)
    report.extend(f"REGISTRY {r}" for r in reg_report)
    new_files[REGISTRY] = dump_lines(reg_lines)

    doc_path = ROOT / S10_DOC
    doc_text = doc_path.read_text(encoding="utf-8")
    new_files[S10_DOC] = apply_doc(doc_text)
    report.append(f"DOC {S10_DOC} D10-4 substring swapped")

    return new_files, report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", help="write the edits")
    args = parser.parse_args()

    if is_already_applied():
        report_already()
        return

    new_files, report = compute()
    print("\n".join(report))
    if not args.apply:
        print("DRY RUN — no files written (use --apply).")
        return
    for rel, content in new_files.items():
        (ROOT / rel).write_text(content, encoding="utf-8")
    print("APPLIED — wrote", len(new_files), "files.")


if __name__ == "__main__":
    main()
