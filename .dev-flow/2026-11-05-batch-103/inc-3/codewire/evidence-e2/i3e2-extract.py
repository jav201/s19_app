"""Inc 3 E2 extractor runs (batch-103): Code-Wire v3.1.0 `codewire_extract.py` over THROWAWAY copies of
the base tree (``git archive e07fb00 s19_app tools/synth``), never over the worktree or the clone.
Copied from Inc 2's i2e2-extract.py; the BASELINE and CENSUS lists and the census print differ.

- ``census <copy> <cw tools> <out>`` marks every def of the copy, runs the extractor with an empty graph and
  prints the real callers (base line numbers) of every function in CENSUS.
- ``check <copy> <cw tools> <out> <graph.md>`` marks ONLY the defs the Inc 3 graph shows as existing nodes
  (BASELINE), runs the extractor with the graph and ``--path`` on the slice files, and prints the report.
  New and Inc 2 nodes have no code yet: they report as "Graph node without mark (no code yet)".

Usage: python i3e2-extract.py census|check <copy root> <code-wire tools dir> <out dir> [graph.md]
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

BASELINE = [
    ("s19_app/tui/a2l.py", "_walk_record_layout_components"),
    ("s19_app/tui/a2l.py", "_strip_a2l_comments"),
    ("s19_app/tui/a2l.py", "_split_line_respecting_quotes"),
    ("s19_app/tui/a2l.py", "_byte_order_from_section_lines"),
    ("s19_app/tui/a2l.py", "_encode_curve_record_bytes"),
]
CENSUS = BASELINE + [
    ("s19_app/tui/a2l.py", "_collect_sections_by_name"),
    ("s19_app/tui/a2l.py", "_flatten_body_tokens"),
    ("s19_app/tui/a2l.py", "_decode_scalar"),
    ("s19_app/tui/a2l.py", "_normalize_byte_order"),
    ("s19_app/tui/a2l.py", "_collect_declared_alignments"),
    ("s19_app/tui/a2l.py", "describe_curve_tag"),
    ("s19_app/tui/a2l.py", "encode_physical_to_raw_bytes"),
    ("s19_app/tui/a2l_parameter_picker.py", "A2LParameterPicker.set_parameters"),
]
SLICE_PATHS = ["s19_app/tui/a2l.py", "tools/synth/make_release_case.py", "s19_app/tui/a2l_definition.py"]


def write_marks(cw, root: Path, keep) -> tuple[int, dict[str, list[int]]]:
    parsed, failed = cw.parse_files(root)
    if failed:
        print("parse failures:", failed)
    marked = 0
    origin: dict[str, list[int]] = {}
    for rel, (_src, tree) in parsed.items():
        path = root / rel
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
        starts: dict[int, str] = {}
        for qual, fn, _cls in cw.defs_with_qualnames(tree):
            if not keep(rel, qual):
                continue
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
        if starts:
            path.write_text("".join(out_lines), encoding="utf-8")
        origin[rel] = mapping
        marked += len(starts)
    return marked, origin


def main(argv: list[str]) -> int:
    mode, root, cw_dir, out = argv[1], Path(argv[2]), Path(argv[3]), Path(argv[4])
    sys.path.insert(0, str(cw_dir))
    import codewire_extract as cw  # noqa: E402

    out.mkdir(parents=True, exist_ok=True)
    if mode == "census":
        marked, origin = write_marks(cw, root, lambda rel, qual: True)
        graph = out / "census-empty-graph.md"
        graph.write_text("# empty graph (caller census only)\n\n## Nodes\n", encoding="utf-8")
        result = subprocess.run([sys.executable, "-I", str(cw_dir / "codewire_extract.py"), "--repo", str(root),
                                 "--graph", str(graph), "--out", str(out / "cw-census")],
                                capture_output=True, text=True)
        print(f"marks written: {marked}")
        print("extractor:", result.stdout.strip(), "exit", result.returncode, "(drift expected: no graph)")
        data = json.loads((out / "cw-census" / "extract.json").read_text(encoding="utf-8"))

        def base(site: str) -> str:
            loc, _, tail = site.partition(" ")
            rel, _, line = loc.rpartition(":")
            return f"{rel}:{origin[rel][int(line)]}" + (f" {tail}" if tail else "")

        for rel, target in CENSUS:
            callers = [c for c in data["calls"] if c["callee"] == target]
            print(f"\n== {rel} :: {target}: {len(callers)} marked caller(s)")
            for c in callers:
                print(f"   {c['caller']}  <-  {', '.join(base(x) for x in c['sites'])}")
            if target in data["top_level_sites"]:
                print(f"   top-level sites: {', '.join(base(x) for x in data['top_level_sites'][target])}")
        return 0

    graph = Path(argv[5])
    wanted = set(BASELINE)
    marked, _origin = write_marks(cw, root, lambda rel, qual: (rel, qual) in wanted)
    print(f"marks written: {marked} (the baseline nodes of the graph)")
    cmd = [sys.executable, "-I", str(cw_dir / "codewire_extract.py"), "--repo", str(root), "--graph", str(graph),
           "--out", str(out / "cw-check")]
    for p in SLICE_PATHS:
        cmd += ["--path", p]
    result = subprocess.run(cmd, capture_output=True, text=True)
    print("extractor:", result.stdout.strip(), "exit", result.returncode)
    report = (out / "cw-check" / "diff-report.md").read_text(encoding="utf-8")
    print(report)
    data = json.loads((out / "cw-check" / "extract.json").read_text(encoding="utf-8"))
    kinds: dict[str, int] = {}
    for f in data["findings"]:
        kinds[f["kind"]] = kinds.get(f["kind"], 0) + 1
    other = {k: v for k, v in kinds.items() if k != "graph_node_without_mark" and not k.startswith("info_")}
    print("finding kinds:", kinds)
    print("drift other than 'graph node without mark (no code yet)':", other or "none")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
