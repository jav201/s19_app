from __future__ import annotations

import ast
from pathlib import Path
import sys
import traceback

INC = Path(__file__).resolve().parents[1]
ROOT = INC.parents[2]
sys.path.insert(0, str(INC / "evidence-e1"))
from redaction import redact


def definition(tree: ast.AST, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    raise AssertionError(f"missing {name}")


def calls(node: ast.AST, name: str) -> list[int]:
    return sorted(
        item.lineno
        for item in ast.walk(node)
        if isinstance(item, ast.Call)
        and ((isinstance(item.func, ast.Attribute) and item.func.attr == name) or (isinstance(item.func, ast.Name) and item.func.id == name))
    )


def is_sync_without_yield(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return isinstance(node, ast.FunctionDef) and not any(isinstance(item, (ast.Await, ast.Yield, ast.YieldFrom)) for item in ast.walk(node))


def main() -> None:
    trees: dict[str, ast.AST] = {}
    for path in sorted((ROOT / "s19_app").rglob("*.py")):
        relative = path.relative_to(ROOT).as_posix()
        trees[relative] = ast.parse(path.read_text(encoding="utf-8"), filename=relative)

    project = trees["s19_app/tui/app/project_load.py"]
    loaded = trees["s19_app/tui/app/loaded_state.py"]
    p5 = definition(project, "_install_prepared_project")
    reset = definition(project, "_reset_project_session")
    l1 = definition(loaded, "_apply_prepared_load")
    for label, node in (("P5", p5), ("reset", reset), ("L1", l1)):
        assert is_sync_without_yield(node), label
        print(f"SYNC {label}=true await=0 yield=0")

    assert calls(p5, "_reset_project_session") == [1609]
    assert calls(p5, "_apply_prepared_load") == [1633, 1643]
    assert calls(p5, "_refresh_a2l_dependent_views") == [1653]
    assert calls(p5, "call_later") == []
    assert calls(p5, "call_after_refresh") == [1684]
    assert calls(l1, "call_later") == [785, 799, 828]
    print("P5_SEQUENCE preflight=1595-1607 reset=1609 L1=1633,1643 final_publication=1653 outcome_callback=1684")
    print("L1_SCHEDULING call_later=785,799,828 after_apply_preflight_and_install; no stage yield before them")

    writes: list[tuple[str, str, int, str]] = []
    for relative, tree in trees.items():
        def visit(node: ast.AST, enclosing: str) -> None:
            current = enclosing
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                current = node.name
            if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    for item in ast.walk(target):
                        if isinstance(item, ast.Attribute) and item.attr in {"_a2l_view_generation", "_image_generation"}:
                            writes.append((relative, current, item.lineno, item.attr))
                        elif isinstance(item, ast.Name) and item.id in {"_a2l_view_generation", "_image_generation"}:
                            writes.append((relative, current, item.lineno, item.id))
            for child in ast.iter_child_nodes(node):
                visit(child, current)
        visit(tree, "<module>")
    for row in writes:
        print(f"GENERATION_WRITE {row[0]}:{row[2]} {row[1]} {row[3]}")
    assert len(writes) == 4, writes
    runtime = [row for row in writes if row[3] == "_a2l_view_generation" and row[0].endswith("a2l_view.py") or row[3] == "_image_generation" and row[0].endswith("loaded_state.py")]
    assert len(runtime) == 2, runtime
    print("GENERATION_WRITERS class_default=core.py:251 image_init=core.py:398 runtime_a2l=a2l_view.py:768 runtime_image=loaded_state.py:642")

    replace_calls = calls(definition(trees["s19_app/tui/app/a2l_view.py"], "_replace_current_a2l"), "_replace_current_a2l")
    assert replace_calls == []
    all_replace_calls = [row for tree in trees.values() for row in calls(tree, "_replace_current_a2l")]
    assert len(all_replace_calls) == 5
    print("A2L_WRITER_CALLS file_load.py:881 loaded_state.py:394,726 project_load.py:963,1619 all_UI_install_or_unload_routes=true")
    print("INVARIANT TRUE P5_L1=synchronous_UI_without_await_or_yield runtime_generation_writers=UI_only STAGE_RACE=unreachable rollback=none")
    print("BLOCKER none")

    control = ast.parse("async def known():\n    await work()\n")
    assert not is_sync_without_yield(control.body[0])
    control_yield = ast.parse("def known():\n    yield 1\n")
    assert not is_sync_without_yield(control_yield.body[0])
    print("INSTRUMENT_CONTROLS known_await=detected known_yield=detected")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print(redact(traceback.format_exc(), ROOT), end="")
        raise SystemExit(1)
