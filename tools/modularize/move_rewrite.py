"""Text rewrites applied to one unit's span (D1, relative import, CSS)."""
from __future__ import annotations

import ast
import re


def _char_offsets(line: str, node: ast.AST) -> tuple[int, int]:
    raw = line.encode("utf-8")
    start = len(raw[: node.col_offset].decode("utf-8"))
    end = len(raw[: node.end_col_offset].decode("utf-8"))
    return start, end


def _nodes_of(unit: dict) -> list[ast.AST]:
    if "nodes" in unit and unit["nodes"]:
        return unit["nodes"]
    return [unit["node"]]


def _unit_label(pkg, unit: dict) -> str:
    if "node" in unit and unit.get("kind") in ("method", "class_stmt"):
        return f"{pkg.name}:S19TuiApp.{unit['name']}"
    return f"{pkg.name}:{unit['key']}"


def _apply_edits(span_lines: list[str], start_line: int,
                 edits: list[tuple[int, int, int, str]]) -> str:
    by_line: dict[int, list[tuple[int, int, str]]] = {}
    for file_line, c0, c1, new in edits:
        by_line.setdefault(file_line, []).append((c0, c1, new))
    out = list(span_lines)
    for file_line, line_edits in by_line.items():
        idx = file_line - start_line
        if idx < 0 or idx >= len(out):
            continue
        text = out[idx]
        for c0, c1, new in sorted(line_edits, key=lambda e: e[0], reverse=True):
            text = text[:c0] + new + text[c1:]
        out[idx] = text
    return "".join(out)


def rewrite_unit(pkg, unit: dict, module: str) -> tuple[str, list[dict]]:
    """Rewrite one unit's span text; return ``(text, edit_records)``."""
    span_lines = pkg.lines[unit["start"] - 1: unit["end"]]
    start_line = unit["start"]
    edits: list[tuple[int, int, int, str]] = []
    records: list[dict] = []
    label = _unit_label(pkg, unit)

    for node in _nodes_of(unit):
        # D1 rewrite (skip in deps)
        if module != "deps":
            for name in ast.walk(node):
                if not (isinstance(name, ast.Name) and name.id in pkg.d1_names
                        and isinstance(name.ctx, ast.Load)):
                    continue
                if pkg.resolver.in_annotation(name):
                    continue
                if not pkg.resolver.is_module_global(name):
                    continue
                assert name.lineno == name.end_lineno, "multiline Name node"
                c0, c1 = _char_offsets(pkg.lines[name.lineno - 1], name)
                before = pkg.lines[name.lineno - 1][c0:c1]
                new = f"deps.{name.id}"
                edits.append((name.lineno, c0, c1, new))
                records.append({"kind": "d1", "unit": label, "line": name.lineno,
                                "before": before, "after": new})

        # relative ImportFrom level + 1 (wherever it occurs)
        for imp in ast.walk(node):
            if not (isinstance(imp, ast.ImportFrom) and imp.level >= 1):
                continue
            line = pkg.lines[imp.lineno - 1]
            c0, _ = _char_offsets(line, imp)
            match = re.match(r"from\s+(\.+)", line[c0:])
            if not match:
                continue
            dots = match.group(1)
            d0 = c0 + match.start(1)
            d1 = c0 + match.end(1)
            edits.append((imp.lineno, d0, d1, dots + "."))
            records.append({"kind": "relimport", "unit": label, "line": imp.lineno,
                            "before": dots, "after": dots + "."})

        # CSS_PATH rewrite (app core only)
        if (pkg.is_app and module == "core"
                and unit.get("kind") == "class_stmt" and unit["name"] == "CSS_PATH"):
            const = next((n for n in ast.walk(node)
                          if isinstance(n, ast.Constant) and n.value == "styles.tcss"), None)
            if const is not None:
                line = pkg.lines[const.lineno - 1]
                c0, c1 = _char_offsets(line, const)
                before = line[c0:c1]
                new = '"../styles.tcss"'
                edits.append((const.lineno, c0, c1, new))
                records.append({"kind": "css", "unit": label, "line": const.lineno,
                                "before": before, "after": new})

    text = _apply_edits(span_lines, start_line, edits)
    return text, records
