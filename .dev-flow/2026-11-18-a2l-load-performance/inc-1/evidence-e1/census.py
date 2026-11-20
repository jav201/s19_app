from __future__ import annotations

import ast
import hashlib
import json
import platform
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
SOURCE = ROOT / "s19_app/tui/a2l_definition.py"
SYMBOLS = (
    "span_entries",
    "span_index",
    "entry_cache",
    "materialize",
    "describe_name",
    "describe_definition",
    "describe_definitions",
    "_shared_with",
    "_entry_overlaps",
    "_pair_exempt",
)
PRESERVED = {
    "R-A2L-DEF.58.1": r"test_r_a2l_def_58_1_",
    "R-A2L-DEF.58.2": r"test_r_a2l_def_58_2_",
    "R-A2L-DEF.136": r"test_r_a2l_def_136_",
    "R-A2L-DEF.138": r"test_r_a2l_def_138_",
    "R-A2L-DEF.139": r"test_r_a2l_def_139_",
    "R-A2L-DEF.140": r"test_r_a2l_def_140_",
    "R-A2L-DEF.148": r"test_r_a2l_def_148_",
    "R-A2L-DEF.149": r"test_r_a2l_def_149_",
}


def called_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def main() -> None:
    source_bytes = SOURCE.read_bytes()
    source_text = source_bytes.decode("utf-8")
    tree = ast.parse(source_text, filename=str(SOURCE))
    occurrences: dict[str, list[dict[str, object]]] = {name: [] for name in SYMBOLS}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in occurrences:
            occurrences[node.name].append({"line": node.lineno, "kind": "definition"})
        elif isinstance(node, ast.Name) and node.id in occurrences:
            kind = "store" if isinstance(node.ctx, (ast.Store, ast.Del)) else "load"
            occurrences[node.id].append({"line": node.lineno, "kind": kind})
    for rows in occurrences.values():
        rows.sort(key=lambda row: (row["line"], row["kind"]))

    production_calls: list[dict[str, object]] = []
    production_imports: list[dict[str, object]] = []
    for path in sorted((ROOT / "s19_app").rglob("*.py")):
        relative = path.relative_to(ROOT).as_posix()
        parsed = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
        public_aliases = {
            "describe_definition": "describe_definition",
            "describe_definitions": "describe_definitions",
        }
        for node in ast.walk(parsed):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.endswith("a2l_definition"):
                production_imports.append(
                    {
                        "path": relative,
                        "line": node.lineno,
                        "names": [alias.name for alias in node.names],
                        "asnames": [alias.asname for alias in node.names],
                    }
                )
                for alias in node.names:
                    if alias.name in public_aliases:
                        public_aliases[alias.asname or alias.name] = alias.name
        for node in ast.walk(parsed):
            local_name = called_name(node.func) if isinstance(node, ast.Call) else None
            if local_name in public_aliases and isinstance(node, ast.Call):
                production_calls.append(
                    {
                        "path": relative,
                        "line": node.lineno,
                        "name": local_name,
                        "public_name": public_aliases[local_name],
                    }
                )

    test_paths = sorted((ROOT / "tests").rglob("*.py"))
    test_functions: dict[str, list[str]] = {requirement: [] for requirement in PRESERVED}
    picker_test_functions = {"R-PICKER-CORRECT.018": [], "R-PICKER-CORRECT.019": []}
    for path in test_paths:
        relative = path.relative_to(ROOT).as_posix()
        parsed = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
        for node in ast.walk(parsed):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for requirement, prefix in PRESERVED.items():
                if node.name.startswith(prefix):
                    test_functions[requirement].append(f"{relative}::{node.name}")
            docstring = ast.get_docstring(node) or ""
            for requirement in picker_test_functions:
                if requirement in docstring:
                    picker_test_functions[requirement].append(f"{relative}::{node.name}")

    canon = (ROOT / "REQUIREMENTS.md").read_text(encoding="utf-8")
    new_ids = {
        f"R-A2L-DEF.{number}": len(re.findall(rf"\bR-A2L-DEF\.{number}\b", canon))
        for number in range(156, 166)
    }
    preserved_canon = {
        requirement: len(re.findall(rf"\b{re.escape(requirement)}\b", canon))
        for requirement in PRESERVED
    }
    picker_canon = {
        requirement: len(re.findall(rf"\b{re.escape(requirement)}\b", canon))
        for requirement in ("R-PICKER-CORRECT.018", "R-PICKER-CORRECT.019")
    }
    predecessor_canon_count = len(re.findall(r"\bR-A2L-DEF\.155\b", canon))
    case06 = ROOT / "examples/case_06_large_nested_a2l/firmware.a2l"
    report = {
        "schema": "a2l-load-performance/inc-1/e1-census/v1",
        "root": "<repo>",
        "python": sys.version,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "logical_cpus": __import__("os").cpu_count(),
        "head": subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip(),
        "base": subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "f44e8bc4"], text=True).strip(),
        "source": {
            "path": SOURCE.relative_to(ROOT).as_posix(),
            "sha256": hashlib.sha256(source_bytes).hexdigest(),
            "lines": len(source_text.splitlines()),
        },
        "symbol_census": {
            name: {
                "count": len(rows),
                "kinds": dict(sorted(Counter(row["kind"] for row in rows).items())),
                "occurrences": rows,
            }
            for name, rows in occurrences.items()
        },
        "production_public_calls": production_calls,
        "production_public_call_count": len(production_calls),
        "production_definition_imports": production_imports,
        "preserved_test_functions": test_functions,
        "preserved_test_counts": {key: len(value) for key, value in test_functions.items()},
        "new_id_canon_counts": new_ids,
        "predecessor_id_canon_count": predecessor_canon_count,
        "preserved_id_canon_counts": preserved_canon,
        "picker_id_canon_counts": picker_canon,
        "picker_test_functions": picker_test_functions,
        "picker_test_counts": {key: len(value) for key, value in picker_test_functions.items()},
        "case06_file": {
            "path": case06.relative_to(ROOT).as_posix(),
            "bytes": case06.stat().st_size,
            "sha256": hashlib.sha256(case06.read_bytes()).hexdigest(),
        },
    }
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
