"""Inc 2 E1 caller census (batch-103): the real callers of the functions the
definition model reuses or cites, from the Code-Wire v3.1.0 extractor.

Runs on a THROWAWAY copy of the base tree (``git archive e07fb00 s19_app``),
never on the worktree: it writes one ``# node: <qualname>`` mark above every
function of the copy (the extractor's own qualname walk), runs
``codewire_extract.py`` over the copy with an empty graph, and prints, for each
target, every marked caller with its call sites. Imports no ``s19_app``.

Usage: python i2e1-callers.py <copy root> <code-wire repo> <out dir>
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

TARGETS = [
    "encode_physical_to_raw_bytes",
    "_invert_physical_to_raw",
    "_apply_compu_method",
    "_table_lookup",
    "_decode_raw_value",
    "_decode_scalar",
    "_extract_raw_bytes",
    "_resolve_record_layout",
    "extract_compu_methods",
    "extract_compu_tables",
    "enrich_a2l_tags_with_values",
    "describe_curve_tag",
    "_short_decode_reason",
    "parse_parameter_list",
    "resolve_symbol_entry",
    "ChangeService.add_symbol_entry",
    "A2LParameterPicker.set_parameters",
]


def main(argv: list[str]) -> int:
    root, cw_repo, out = (Path(a) for a in argv[1:4])
    sys.path.insert(0, str(cw_repo / "tools"))
    import codewire_extract as cw  # noqa: E402

    parsed, failed = cw.parse_files(root)
    print(f"files parsed: {len(parsed)}; parse failures: {len(failed)}")
    marked = 0
    origin: dict[str, list[int]] = {}  # marked-copy line (1-based) -> base line, per file
    for rel, (_src, tree) in parsed.items():
        path = root / rel
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
        starts: dict[int, str] = {}
        for qual, fn, _cls in cw.defs_with_qualnames(tree):
            first = min([fn.lineno] + [d.lineno for d in fn.decorator_list])
            indent = len(lines[first - 1]) - len(lines[first - 1].lstrip())
            starts[first] = " " * indent + f"# node: {qual}\n"
        out_lines: list[str] = []
        mapping: list[int] = [0]
        for number, text in enumerate(lines, start=1):
            if number in starts:
                out_lines.append(starts[number])
                mapping.append(number)
            out_lines.append(text)
            mapping.append(number)
        path.write_text("".join(out_lines), encoding="utf-8")
        origin[rel] = mapping
        marked += len(starts)
    print(f"marks written: {marked}")
    graph = out / "empty-graph.md"
    graph.write_text("# empty graph (caller census only)\n\n## Nodes\n", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(cw_repo / "tools" / "codewire_extract.py"),
         "--repo", str(root), "--graph", str(graph), "--out", str(out / "cw-out")],
        capture_output=True, text=True,
    )
    print("extractor:", result.stdout.strip())
    data = json.loads((out / "cw-out" / "extract.json").read_text(encoding="utf-8"))
    calls = data["calls"]
    top = data["top_level_sites"]

    def base(site: str) -> str:
        loc, _, tail = site.partition(" ")
        rel, _, line = loc.rpartition(":")
        return f"{rel}:{origin[rel][int(line)]}" + (f" {tail}" if tail else "")

    for target in TARGETS:
        callers = [c for c in calls if c["callee"] == target]
        print(f"\n== {target}: {len(callers)} marked caller(s)")
        for c in callers:
            print(f"   {c['caller']}  <-  {', '.join(base(x) for x in c['sites'])}")
        if target in top:
            print(f"   top-level sites: {', '.join(base(x) for x in top[target])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
