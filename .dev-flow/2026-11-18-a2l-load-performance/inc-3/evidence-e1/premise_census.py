from __future__ import annotations

import ast
import hashlib
from pathlib import Path
import re
import subprocess
import sys
import traceback

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
from redaction import redact

ROOT = Path(__file__).resolve().parents[4]
SOURCE = ROOT / "s19_app"
APP = SOURCE / "tui" / "app"
TARGET_CALLS = {
    "PreparedLoad",
    "_prepare_load_payload",
    "_apply_prepared_load",
    "_refresh_a2l_dependent_views",
    "_replace_current_a2l",
    "enrich_tags_and_render",
}


def call_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def census_tree(
    tree: ast.AST, relative: str, targets: set[str] = TARGET_CALLS
) -> list[tuple[str, str, int]]:
    found: list[tuple[str, str, int]] = []

    def visit(node: ast.AST, enclosing: str) -> None:
        current = enclosing
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            current = node.name
        if isinstance(node, ast.Call):
            name = call_name(node)
            if name in targets:
                found.append((relative, f"{current}:{name}", node.lineno))
        for child in ast.iter_child_nodes(node):
            visit(child, current)

    visit(tree, "<module>")
    return found


def reference_census(
    tree: ast.AST, relative: str, targets: set[str]
) -> list[tuple[str, str, int]]:
    found: list[tuple[str, str, int]] = []

    def visit(node: ast.AST, enclosing: str) -> None:
        current = enclosing
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            current = node.name
        name = None
        if isinstance(node, ast.Name) and node.id in targets:
            name = node.id
        elif isinstance(node, ast.Attribute) and node.attr in targets:
            name = node.attr
        elif isinstance(node, ast.Constant) and node.value in targets:
            name = node.value
        if name is not None:
            found.append((relative, f"{current}:{name}", node.lineno))
        for child in ast.iter_child_nodes(node):
            visit(child, current)

    visit(tree, "<module>")
    return found


def definition(tree: ast.AST, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    raise AssertionError(f"missing definition {name}")


def attribute_reads(node: ast.AST, names: set[str]) -> list[tuple[str, int]]:
    return sorted(
        (item.attr, item.lineno)
        for item in ast.walk(node)
        if isinstance(item, ast.Attribute)
        and isinstance(item.value, ast.Name)
        and item.value.id == "self"
        and item.attr in names
        and isinstance(item.ctx, ast.Load)
    )


def main(fault: str | None = None) -> None:
    head = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    base = "f44e8bc4266b6dead6ff24adef71fdb0b7b0154c"
    subprocess.run(
        ["git", "merge-base", "--is-ancestor", base, head], cwd=ROOT, check=True
    )
    print(f"P01 TRUE HEAD={head} base_ancestor={base}")

    canon = (ROOT / "REQUIREMENTS.md").read_text(encoding="utf-8")
    preserved = ("002", "003", "004", "005", "014", "023", "026", "028")
    present = {
        suffix: len(re.findall(rf"R-A2L-REFRESH\.{suffix}\b", canon))
        for suffix in preserved
    }
    assert set(present.values()) == {1}, present
    new_ids = [
        f"R-A2L-REFRESH.{number:03d}"
        for number in range(39, 49)
        if re.search(rf"R-A2L-REFRESH\.{number:03d}\b", canon)
    ]
    assert new_ids == [], new_ids
    print(f"P02 TRUE preserved_canon_rows={present} new_id_collisions=0")

    trees: dict[str, ast.AST] = {}
    census: list[tuple[str, str, int]] = []
    for path in sorted(SOURCE.rglob("*.py")):
        relative = path.relative_to(ROOT).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
        trees[relative] = tree
        census.extend(census_tree(tree, relative))
    print(f"CENSUS scope=s19_app/**/*.py python_files={len(trees)}")
    for name in sorted(TARGET_CALLS):
        rows = [row for row in census if row[1].endswith(f":{name}")]
        print(f"CALL {name} count={len(rows)}")
        for relative, site, line in rows:
            print(f"  {relative}:{line} {site}")
    expected_counts = {
        "PreparedLoad": 5,
        "_prepare_load_payload": 1,
        "_apply_prepared_load": 4,
        "_refresh_a2l_dependent_views": 4,
        "_replace_current_a2l": 5,
        "enrich_tags_and_render": 6,
    }
    observed_counts = {
        name: sum(row[1].endswith(f":{name}") for row in census)
        for name in TARGET_CALLS
    }
    assert observed_counts == expected_counts, observed_counts
    control = census_tree(ast.parse("def known_present():\n    PreparedLoad()\n"), "control.py")
    assert len(control) == 1 and control[0][1] == "known_present:PreparedLoad"
    assert census_tree(ast.parse("def known_absent():\n    pass\n"), "control.py") == []
    print("CENSUS_CONTROL TRUE known_present=1 known_absent=0")

    file_tree = trees["s19_app/tui/app/file_load.py"]
    project_tree = trees["s19_app/tui/app/project_load.py"]
    loaded_tree = trees["s19_app/tui/app/loaded_state.py"]
    parse_file = definition(file_tree, "_parse_loaded_file")
    start_file = definition(file_tree, "_start_load_worker")
    parse_reads = attribute_reads(
        parse_file, {"current_a2l_path", "current_a2l_data", "current_file"}
    )
    start_reads = attribute_reads(
        start_file, {"_a2l_view_generation", "_image_generation"}
    )
    expected_start_reads = 4 if fault == "initial" else 3
    assert len(parse_reads) == 3 and len(start_reads) == expected_start_reads
    print(f"P03 TRUE file_worker_mutable_reads parse={parse_reads} start={start_reads}")

    prepare_project = definition(project_tree, "_prepare_project_load")
    prepare_calls = [
        node.lineno
        for node in ast.walk(prepare_project)
        if isinstance(node, ast.Call) and call_name(node) == "_prepare_load_payload"
    ]
    assert prepare_calls == []
    install_project = definition(project_tree, "_install_prepared_project")
    constructors = [
        node.lineno
        for node in ast.walk(install_project)
        if isinstance(node, ast.Call) and call_name(node) == "PreparedLoad"
    ]
    assert constructors == [1590, 1593]
    print(
        f"P04 TRUE project_worker_prepare_load_payload_calls=0 "
        f"install_nonprecomputed_constructors={constructors}"
    )

    apply_load = definition(loaded_tree, "_apply_prepared_load")
    executable_body = (
        apply_load.body[1:]
        if isinstance(apply_load.body[0], ast.Expr)
        and isinstance(apply_load.body[0].value, ast.Constant)
        and isinstance(apply_load.body[0].value.value, str)
        else apply_load.body
    )
    preflight = apply_load.body[0] if fault == "second" else executable_body[0]
    assert isinstance(preflight, ast.If)
    preflight_line = preflight.lineno
    current_file_writes = [
        node.lineno
        for node in ast.walk(apply_load)
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Attribute)
            and isinstance(target.value, ast.Name)
            and target.value.id == "self"
            and target.attr == "current_file"
            for target in node.targets
        )
    ]
    assert preflight_line == 589 and current_file_writes == [619]
    print(
        f"P05 TRUE apply_preflight_line={preflight_line} "
        f"first_current_file_write={current_file_writes[0]}"
    )

    reset = definition(project_tree, "_reset_project_session")
    reset_a2l = [
        node.lineno
        for node in ast.walk(reset)
        if isinstance(node, ast.Call) and call_name(node) == "_replace_current_a2l"
    ]
    apply_image_bumps = [
        node.lineno
        for node in ast.walk(apply_load)
        if isinstance(node, ast.AugAssign)
        and isinstance(node.target, ast.Attribute)
        and node.target.attr == "_image_generation"
    ]
    assert reset_a2l == [963] and apply_image_bumps == [642]
    print(
        f"P06 TRUE project_reset_a2l_writer={reset_a2l[0]} "
        f"apply_image_increment={apply_image_bumps[0]} stage_specific_expectations_required=True"
    )

    route_targets = {
        "load_from_path",
        "_load_workarea_file",
        "_parse_loaded_file",
        "_prepare_load_payload",
        "_start_load_worker",
        "_handle_load_project",
        "_prepare_project_load",
        "_install_prepared_project",
        "_apply_prepared_load",
        "ProjectLoadRequest",
        "PreparedProjectLoad",
        "PreparedLoad",
    }
    route_reader = census_tree if fault == "route" else reference_census
    route_census = [
        row
        for relative, tree in trees.items()
        for row in route_reader(tree, relative, route_targets)
    ]
    test_root = ROOT / "tests"
    test_files = sorted(test_root.rglob("*.py"))
    for path in test_files:
        relative = path.relative_to(ROOT).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
        route_census.extend(route_reader(tree, relative, route_targets))
    observed_route_names = {row[1].rsplit(":", 1)[1] for row in route_census}
    assert observed_route_names == route_targets, route_targets - observed_route_names
    print(
        f"ROUTE_REFERENCE_CENSUS kind=name,attribute,exact-string "
        f"scope=s19_app/**/*.py,tests/**/*.py "
        f"python_files={len(trees) + len(test_files)}"
    )
    for name in sorted(route_targets):
        rows = [row for row in route_census if row[1].endswith(f":{name}")]
        print(f"ROUTE_REF {name} count={len(rows)}")
        for relative, site, line in rows:
            print(f"  {relative}:{line} {site}")

    for relative in (
        "s19_app/tui/app/file_load.py",
        "s19_app/tui/app/project_load.py",
        "s19_app/tui/app/loaded_state.py",
        "s19_app/tui/app/shared.py",
        "s19_app/tui/app/a2l_view.py",
    ):
        digest = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
        print(f"SHA256 {relative} {digest}")
    print("SLICE planned_changed_SOURCE=4 limit=4 files=file_load.py,project_load.py,loaded_state.py,shared.py")
    print("RESULT all_executed_static_premises=TRUE; no runtime compliance or performance verdict")


if __name__ == "__main__":
    fault = None
    if len(sys.argv) > 1:
        if len(sys.argv) != 2 or not sys.argv[1].startswith("--red-case="):
            raise SystemExit("usage: premise_census.py [--red-case=initial|second|route]")
        fault = sys.argv[1].split("=", 1)[1]
        if fault not in {"initial", "second", "route"}:
            raise SystemExit("unknown RED case")
    try:
        main(fault)
    except Exception:
        print(redact(traceback.format_exc(), ROOT), end="")
        raise SystemExit(1)
