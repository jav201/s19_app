"""Inc 10 E4 integrator: fold T10's case -> test map (``02-test-cases-T.md``) and the integrator's own rows into the
Tests / Coverage / Result columns of ``02-test-cases.md``.  Stdlib only; reads the test files with ``ast`` (never
imports them).  Run from the repo root:  python -I -B <this> [--failed FILE]  (FILE: one failing node id per line,
from the GREEN run; every other mapped node is ``pass``).  Prints a summary; rewrites ``02-test-cases.md`` in place.
"""
import argparse
import ast
import re
from pathlib import Path

INC = Path(".dev-flow/2026-11-05-batch-103/inc-10")
TESTS = Path("tests")
CASE_RE = re.compile(r"^(R-[A-Z0-9-]+(?:\.\d+)+)/(\d+)$")
# Rows the integrator adds (not in T10's map): case -> (nodes, coverage).
EXTRA = {
    "R-S19-S0HEADER-001.2/5": ([
        "test_b103_inc10_s0_written_name.py::test_r_s19_s0header_001_2_5_the_header_is_the_written_name_never_the_typed_path",
        "test_b103_inc10_s0_written_name.py::test_r_s19_s0header_001_2_5_a_numbered_written_name_wins_over_the_typed_one",
    ], "partial"),
}


def functions(file_name):
    tree = ast.parse((TESTS / file_name).read_text(encoding="utf-8"))
    return [n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name.startswith("test_")]


PIPE = re.compile(r"(?<!\\)\|")
ID_TOKEN = re.compile(r"^(?:R-[A-Z0-9-]+(?:\.\d+)+/\d+|AT-[A-Z0-9-]+)$")


def param_id(file_name, case):
    """The pytest param id that carries ``case``: the first token of the module string made only of case ids
    that names ``case`` (``ids=[c[0].split()[0] ...]`` in T10's files)."""
    tree = ast.parse((TESTS / file_name).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            tokens = node.value.split()
            if tokens and all(ID_TOKEN.match(tok) for tok in tokens) and case in tokens:
                return tokens[0]
    raise SystemExit(f"no param id for {case} in {file_name}")


def resolve(spec, last_file):
    """``…g1_controls.py::test_x_…[param]`` or ``::…14_2_…`` -> (file, function, param)."""
    spec = spec.strip("`").strip()
    param = ""
    if spec.endswith("]") and "[" in spec:
        spec, param = spec[:-1].split("[", 1)
    head, func = spec.split("::", 1)
    head = head.replace("…", "")
    file_name = last_file if not head else next(p.name for p in TESTS.glob("test_*.py") if p.name.endswith(head))
    pattern = re.compile("^" + ".*".join(re.escape(part) for part in func.split("…")) + "$")
    hits = [f for f in functions(file_name) if pattern.match(f)]
    if len(hits) != 1:
        raise SystemExit(f"cannot resolve {spec!r} in {file_name}: {hits}")
    return file_name, hits[0], param


def expand(spec):
    """Case ids named by a map row's first cell."""
    out, req, family = [], None, None
    for token in re.split(r"\s*(?:,|;|·|\+)\s*", spec.replace("**", "")):
        token = token.strip()
        if not token:
            continue
        if token.startswith("AT-"):
            out.append(token)
            continue
        if token.startswith("R-"):
            req, nums = token.split("/", 1)
            family = req.rsplit(".", 1)[0]
        elif token.startswith("."):
            sub, nums = token.split("/", 1)
            req = family + sub
        else:
            nums = token.lstrip("/")
        if ".." in nums:
            lo, hi = (int(n) for n in nums.split(".."))
            out += [f"{req}/{n}" for n in range(lo, hi + 1)]
        else:
            out.append(f"{req}/{nums}")
    return out


def tmap():
    """case id -> (list of node ids, coverage) from T10's map."""
    mapping, last_file = {}, None
    for line in (INC / "02-test-cases-T.md").read_text(encoding="utf-8").splitlines():
        cells = [c.strip() for c in PIPE.split(line.strip().strip("|"))]
        if len(cells) != 4 or not cells[0].startswith(("R-", "AT-")):
            continue
        nodes = []
        for spec in re.findall(r"`([^`]*::[^`]*)`", cells[1]):
            file_name, func, param = resolve(spec, last_file)
            last_file = file_name
            nodes.append((file_name, func, param))
        coverage = "partial" if cells[3].lstrip("*").startswith("partial") else "full"
        cases = expand(cells[0])
        for i, case in enumerate(cases):
            one_each = len(nodes) == len(cases) > 1 and not any(n[2] for n in nodes)
            picked = [nodes[i]] if one_each else nodes
            ids = []
            for file_name, func, param in picked:
                if param:
                    ids.append(f"{file_name}::{func}[{param_id(file_name, case)}]")
                else:
                    ids.append(f"{file_name}::{func}")
            mapping[case] = (ids, coverage)
    return mapping


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--failed", help="file with one failing node id per line")
    a = ap.parse_args()
    failed = set()
    if a.failed:
        failed = {l.strip().removeprefix("tests/") for l in Path(a.failed).read_text().splitlines() if l.strip()}
    mapping = tmap()
    for case, (nodes, cov) in EXTRA.items():
        mapping[case] = (nodes, cov)
    path = INC / "02-test-cases.md"
    lines = path.read_text(encoding="utf-8").split("\n")
    seen, out = set(), []
    for line in lines:
        cells = PIPE.split(line)
        first = cells[1].strip() if line.startswith("| ") and len(cells) > 2 else ""
        if first in mapping and len(cells) == 11 and cells[-1] == "":
            nodes, cov = mapping[first]
            result = "fail" if any(n.split("[")[0] in failed or n in failed for n in nodes) else "pass"
            cells[-4] = " " + "; ".join(f"`{n}`" for n in nodes) + " "
            cells[-3] = f" {cov} "
            cells[-2] = f" {result} "
            line = "|".join(cells)  # the escaped pipes were never split
            seen.add(first)
        out.append(line)
    path.write_text("\n".join(out), encoding="utf-8", newline="\n")
    case_rows = [l[2:].split(" | ", 1)[0] for l in lines if l.startswith(("| R-", "| AT-"))]
    missing = [c for c in case_rows if c not in seen]
    unknown = sorted(set(mapping) - set(case_rows))
    print(f"fold: {len(case_rows)} case rows, {len(seen)} filled, not filled: {missing}, map ids with no row: {unknown}")


if __name__ == "__main__":
    main()
