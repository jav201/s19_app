from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
SLICE = (
    "s19_app/tui/app/file_load.py",
    "s19_app/tui/a2l_parameter_picker.py",
    "s19_app/tui/screens_directionb/check_editor.py",
    "s19_app/tui/screens_directionb/patch_editor/a2l_picker.py",
)
NODE_NAMES = {
    "A2LAttachRequest",
    "A2LAttachResult",
    "_start_a2l_load",
    "_a2l_attach_worker",
    "_on_a2l_attached",
    "_install_attached_a2l",
    "_on_a2l_attach_failed",
    "_replace_current_a2l",
    "_compute_a2l_enriched_tags",
    "_refresh_a2l_dependent_views",
    "update_a2l_view",
    "_prefill_check_editor",
    "_prefill_patch_editor",
    "set_a2l_parameters",
    "set_parameters",
    "describe_definitions",
}
CALL_NAMES = (
    "_start_a2l_load",
    "_a2l_attach_worker",
    "_on_a2l_attached",
    "_install_attached_a2l",
    "_on_a2l_attach_failed",
    "_replace_current_a2l",
    "_compute_a2l_enriched_tags",
    "_refresh_a2l_dependent_views",
    "update_a2l_view",
    "_prefill_check_editor",
    "_prefill_patch_editor",
    "set_a2l_parameters",
    "set_parameters",
    "describe_definitions",
    "enrich_tags_and_render",
)


def call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def main() -> None:
    print("root=<repo>  # redacted at generation")
    print("qwen_attribution=none; Qwen exited 55 before producing a census")
    print("source_budget=4")
    for relative in SLICE:
        print(f"slice_file={relative} exists={(ROOT / relative).is_file()}")

    files = sorted((ROOT / "s19_app").rglob("*.py"))
    parsed: dict[Path, ast.AST] = {}
    for path in files:
        parsed[path] = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

    print("\nDEFINITIONS")
    for relative in SLICE + (
        "s19_app/tui/app/a2l_view.py",
        "s19_app/tui/app/checks_diff.py",
        "s19_app/tui/app/patch.py",
        "s19_app/tui/a2l_definition.py",
    ):
        path = ROOT / relative
        tree = parsed[path]
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name in NODE_NAMES:
                print(f"{relative}:{min([node.lineno] + [decorator.lineno for decorator in node.decorator_list])}-{node.end_lineno} {type(node).__name__} {node.name}")

    print("\nREVERSE_CALLS")
    for name in CALL_NAMES:
        sites = []
        for path, tree in parsed.items():
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and call_name(node.func) == name:
                    sites.append(f"{path.relative_to(ROOT).as_posix()}:{node.lineno}")
        print(f"{name} count={len(sites)} sites={', '.join(sites)}")

    print("\nDIRECT_ATTACH_BODY_CALLS")
    path = ROOT / "s19_app/tui/app/file_load.py"
    tree = parsed[path]
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in {
            "_start_a2l_load",
            "_a2l_attach_worker",
            "_on_a2l_attached",
            "_install_attached_a2l",
            "_on_a2l_attach_failed",
        }:
            calls = sorted({call_name(call.func) for call in ast.walk(node) if isinstance(call, ast.Call) and call_name(call.func)})
            print(f"{node.name}:{min([node.lineno] + [decorator.lineno for decorator in node.decorator_list])}-{node.end_lineno} calls={', '.join(calls)}")

    print("\nENRICHED_TAG_MUTATION_CENSUS")
    hits = []
    for path, tree in parsed.items():
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    for part in ast.walk(target):
                        if isinstance(part, ast.Subscript) and isinstance(part.value, ast.Name) and part.value.id in {"tag", "tags", "enriched", "a2l_enriched_tags"}:
                            hits.append(f"{path.relative_to(ROOT).as_posix()}:{part.lineno}")
                        if isinstance(part, ast.Attribute) and part.attr in {"_a2l_enriched_tags", "_a2l_summary_lines"}:
                            hits.append(f"{path.relative_to(ROOT).as_posix()}:{part.lineno} whole-cache-write")
    print(f"count={len(hits)}")
    for hit in hits:
        print(hit)

    print("\nCASE06_DISCRIMINATING_FIXTURE")
    fixture = ROOT / "examples/case_06_large_nested_a2l/firmware.a2l"
    print(f"exists={fixture.is_file()} size_bytes={fixture.stat().st_size}")
    test_path = ROOT / "tests/test_b100_workers.py"
    test_tree = ast.parse(test_path.read_text(encoding="utf-8"), filename=str(test_path))
    for node in test_tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "test_tc_b100_53_case06_a2l_attach_keeps_the_loop_free_and_reports_parse_bytes":
            print(f"tests/test_b100_workers.py:{min([node.lineno] + [decorator.lineno for decorator in node.decorator_list])}-{node.end_lineno} {node.name}; not executed in E1")


if __name__ == "__main__":
    main()
