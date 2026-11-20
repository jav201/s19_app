"""Mutant runner for INC 1 E4 — runs every planned negative control as a real
source mutant in a copy of the tree and records KILLED (test turns RED) or
SURVIVED (test stays green; a finding). Generated evidence, never typed by
hand: output goes to mutant-run.txt beside this script.

Each mutant starts from the pristine working-tree copy of
s19_app/tui/a2l_definition.py.  A replacement whose anchor is missing is
recorded as ANCHOR-MISSING and never counted as a verdict.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[4]
SCRATCH = Path(sys.argv[1]) if len(sys.argv) > 1 else (
    Path(__import__("tempfile").gettempdir()) / "inc1-mutants"
)
TREE = SCRATCH / "tree"
PY = sys.executable
OUT = REPO / ".dev-flow/2026-11-18-a2l-load-performance/inc-1/evidence-e4/mutant-run.txt"

OCC = "tests/test_alp_a2l_occupancy.py"
PERF = "tests/test_alp_a2l_occupancy_perf.py"

# name, replacements [(old, new), ...], pytest -k expression, file
MUTANTS = [
    ("156-rebuild-per-name", [(
        "    index = _build_occupancy_index(\n"
        "        span_entries, is_array_entry, definitions_by_position, entry_cache\n"
        "    )\n"
        "    result: dict[str, Definition] = {}\n"
        "    for name in requested:\n"
        "        definition = definitions[name]",
        "    result: dict[str, Definition] = {}\n"
        "    for name in requested:\n"
        "        index = _build_occupancy_index(\n"
        "            span_entries, is_array_entry, definitions_by_position, entry_cache\n"
        "        )\n"
        "        definition = definitions[name]",
    )], "156_2", OCC),
    ("157-page-expansion", [(
        "        records.append((first, last, entry))",
        "        if last is None:\n"
        "            records.append((first, last, entry))\n"
        "        else:\n"
        "            page_first = (first >> 4) << 4\n"
        "            page_last = (last >> 4) << 4\n"
        "            records.extend(\n"
        "                (page, page + 15, entry)\n"
        "                for page in range(page_first, page_last + 1, 16)\n"
        "            )",
    )], "157_2 or 157_3", OCC),
    ("158-force-open-valblk", [(
        "        if byte_length is not None and byte_length >= 1:\n"
        "            last = first + byte_length - 1",
        "        if byte_length is not None and byte_length >= 1:\n"
        "            if is_array_entry(entry):\n"
        "                last = None\n"
        "            else:\n"
        "                last = first + byte_length - 1",
    )], "158", PERF),
    ("158-restore-global-scan", [(
        "    for entry in _occupancy_candidates(index, definition, own_position):",
        "    for entry in (record[2] for record in index.records\n"
        "                  if record[2][0] != own_position):",
    )], "158", PERF),
    ("159-select-by-address", [(
        "    count = len(records)",
        "    records.sort(key=lambda record: record[0])\n"
        "    count = len(records)",
    )], "159_1", OCC),
    ("159-gather-without-sort", [(
        "    stack = [1]",
        "    gathered = list(records)\n"
        "    for _record in gathered:\n"
        "        if _record[2][0] == own_position:\n"
        "            continue\n"
        "        yield _record[2]\n"
        "    return\n"
        "    stack = [1]",
    )], "159_1", OCC),
    ("159-consume-after-answer", [(
        "    for entry in _occupancy_candidates(index, definition, own_position):",
        "    answer: Optional[str] = None\n"
        "    for entry in _occupancy_candidates(index, definition, own_position):",
    ), (
        "        if _pair_exempt(definition, entry, mask_of):\n"
        "            continue\n"
        "        return entry[1]\n"
        "    return None",
        "        if _pair_exempt(definition, entry, mask_of):\n"
        "            continue\n"
        "        if answer is None:\n"
        "            answer = entry[1]\n"
        "    return answer",
    )], "159_1", OCC),
    ("160-exclude-by-name-or-address", [(
        "            record = records[leaf]\n"
        "            if record[2][0] == own_position:\n"
        "                continue",
        "            record = records[leaf]\n"
        "            if record[2][0] == own_position:\n"
        "                continue\n"
        "            if (\n"
        "                record[2][1] == definition.name\n"
        "                or record[2][3] == definition.address\n"
        "            ):\n"
        "                continue",
    )], "160_1 or 160_2", OCC),
    ("161-eager-describe-all", [(
        "    index = _build_occupancy_index(\n"
        "        span_entries, is_array_entry, definitions_by_position, entry_cache\n"
        "    )",
        "    for entry in span_entries:\n"
        "        describe_name(entry[1])\n"
        "    index = _build_occupancy_index(\n"
        "        span_entries, is_array_entry, definitions_by_position, entry_cache\n"
        "    )",
    )], "161_1", OCC),
    ("162-rescan-per-record", [(
        "        records.append((first, last, entry))",
        "        for _other in span_entries[:20000]:\n"
        "            _ = _other[3] + 1\n"
        "        records.append((first, last, entry))",
    )], "162_1", PERF),
    ("163-restore-global-route", [(
        "    for entry in _occupancy_candidates(index, definition, own_position):",
        "    for entry in (record[2] for record in index.records\n"
        "                  if record[2][0] != own_position):",
    )], "163_1", PERF),
    ("164-retained-512b-per-entry", [(
        "        records.append((first, last, entry))",
        "        records.append((first, last, entry, bytearray(512)))",
    )], "164_1", PERF),
    ("165-restore-global-route", [(
        "    for entry in _occupancy_candidates(index, definition, own_position):",
        "    for entry in (record[2] for record in index.records\n"
        "                  if record[2][0] != own_position):",
    )], "165_1", PERF),
    ("165-partial-mapping", [(
        "    return result",
        "    return {name: result[name] for name in list(result)[:1000]}",
    )], "165_1", PERF),
]


def prepare_tree() -> None:
    if TREE.exists():
        shutil.rmtree(TREE)
    TREE.mkdir(parents=True)
    for name in ("s19_app", "tests", "examples"):
        shutil.copytree(
            REPO / name, TREE / name,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
    shutil.copy2(REPO / "pyproject.toml", TREE / "pyproject.toml")
    (TREE / "s19_app/tui/a2l_definition.py").write_bytes(
        (REPO / "s19_app/tui/a2l_definition.py").read_bytes()
    )


def run_pytest(k: str, testfile: str, timeout: int = 600) -> tuple[int, str]:
    proc = subprocess.run(
        [PY, "-m", "pytest", "-p", "no:cacheprovider", "-q", testfile, "-k", k],
        cwd=TREE, capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=timeout,
    )
    tail = "\n".join(proc.stdout.strip().splitlines()[-3:])
    return proc.returncode, tail


def main() -> int:
    prepare_tree()
    source = TREE / "s19_app/tui/a2l_definition.py"
    pristine = source.read_text(encoding="utf-8")
    lines: list[str] = [
        f"mutant-run: repo base 905e9b99; {len(MUTANTS)} mutants from the "
        "planned E1 negative controls; python {sys.version.split()[0]}",
        "",
    ]
    for name, replacements, k, testfile in MUTANTS:
        text = pristine
        missing = []
        for old, new in replacements:
            if old not in text:
                missing.append(old[:60])
                continue
            text = text.replace(old, new, 1)
        if missing:
            lines.append(f"{name}: ANCHOR-MISSING {missing}")
            continue
        source.write_text(text, encoding="utf-8")
        try:
            code, tail = run_pytest(k, testfile)
        except subprocess.TimeoutExpired:
            lines.append(f"{name}: TIMEOUT (needs ruling)")
            continue
        verdict = "KILLED" if code != 0 else "SURVIVED"
        lines.append(f"{name}: {verdict} (exit {code}) target -k {k} in {testfile}")
        for tail_line in tail.splitlines():
            lines.append(f"    {tail_line}")
        lines.append("")
    source.write_text(pristine, encoding="utf-8")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))
    print(f"TRANSCRIPT {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
