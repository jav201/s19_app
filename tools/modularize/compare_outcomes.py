"""Suite node-set equality for the modularization (spec-verify.md Part B, R-MOD.4).

python -I tools/modularize/compare_outcomes.py <before outcomes.tsv> <after outcomes.tsv>
       --before-rc <file> --after-rc <file> [--flaky <file>] [--families <file> (--tree <repo> | --family-new-count N)]

outcomes.tsv: `nodeid<TAB>outcome` (run_suite.sh). Rules: B1 node sets equal; B2 outcomes equal (except ids in
--flaky: `id<TAB>reason` per line); B3 no collection errors; B4 the file-swept family (prefix in --families,
exactly one) is compared as a family: after size = before size - 2 + <number of .py files in the two new
packages>, every after id `passed`. B3 also: a pytest exit code (run_suite.sh `rc` file) outside {0, 1} on either
side. B6: a side with 0 node ids (no run happened). A duplicate node id in one TSV is exit 2 (no silent merge).
Exit 0 OK, 1 FAIL, 2 usage/input error.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

PACKAGES = ("s19_app/tui/app", "s19_app/tui/screens_directionb")
Fail = tuple[str, str]


def read_tsv(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        if "\t" not in line:
            raise ValueError(f"{path}:{n}: expected <nodeid><TAB><outcome>")
        node, outcome = line.rsplit("\t", 1)
        if node in out:
            raise ValueError(f"{path}:{n}: duplicate node id {node!r} (first {out[node]}, again {outcome.strip()})")
        out[node] = outcome.strip()
    return out


def read_rc(path: Path) -> int:
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except ValueError:
        raise ValueError(f"{path}: expected one integer (pytest exit code)") from None


def read_flaky(path: Path | None) -> dict[str, str]:
    if path is None:
        return {}
    out: dict[str, str] = {}
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        node, tab, reason = line.partition("\t")
        if not tab or not reason.strip():
            raise ValueError(f"{path}:{n}: a flaky entry needs `<nodeid><TAB><reason>`")
        out[node] = reason.strip()
    return out


def read_family(path: Path | None) -> str | None:
    if path is None:
        return None
    prefixes = [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip() and not ln.startswith("#")]
    if len(prefixes) != 1:
        raise ValueError(f"{path}: must hold exactly one prefix, found {len(prefixes)}")
    return prefixes[0]


def count_new_files(tree: Path) -> int:
    return sum(1 for pkg in PACKAGES for _ in (tree / pkg).rglob("*.py"))


def is_collection_error(node: str, outcome: str) -> bool:
    return outcome == "error" and ("::" not in node or node.endswith(".py"))


def split_family(d: dict[str, str], prefix: str | None) -> tuple[dict[str, str], dict[str, str]]:
    if prefix is None:
        return d, {}
    fam = {k: v for k, v in d.items() if k.startswith(prefix)}
    return {k: v for k, v in d.items() if k not in fam}, fam


def run_integrity(before: dict[str, str], after: dict[str, str], rcs: tuple[int, int]) -> list[Fail]:
    out: list[Fail] = []
    for side, d, rc in ("before", before, rcs[0]), ("after", after, rcs[1]):
        if rc not in (0, 1):
            out.append(("B3", f"{side}: pytest exit code {rc} (only 0 and 1 mean the suite ran)"))
        if not d:
            out.append(("B6", f"{side}: empty outcomes (0 node ids, no run happened)"))
    return out


def compare(before: dict[str, str], after: dict[str, str], flaky: dict[str, str], prefix: str | None,
            new_py: int | None, rcs: tuple[int, int]) -> tuple[dict[str, int], list[Fail]]:
    b, bf = split_family(before, prefix)
    a, af = split_family(after, prefix)
    fails: list[Fail] = run_integrity(before, after, rcs)
    missing, new = sorted(b.keys() - a.keys()), sorted(a.keys() - b.keys())
    fails += [("B1", f"{i} {b[i]} -> (absent)") for i in missing]
    fails += [("B1", f"{i} (absent) -> {a[i]}") for i in new]
    excused = diff = 0
    for i in sorted(b.keys() & a.keys()):
        if b[i] != a[i]:
            if i in flaky:
                excused += 1
            else:
                diff += 1
                fails.append(("B2", f"{i} {b[i]} -> {a[i]}"))
    for side, d in (("before", before), ("after", after)):
        fails += [("B3", f"{i} {side}: collection error") for i, o in sorted(d.items()) if is_collection_error(i, o)]
    if prefix is not None:
        fails += family_fails(prefix, bf, af, new_py)
    counts = {"before": len(before), "after": len(after), "missing": len(missing), "new": len(new),
              "outcome_diff": diff, "flaky_excused": excused}
    return counts, fails


def family_fails(prefix: str, bf: dict[str, str], af: dict[str, str], new_py: int | None) -> list[Fail]:
    want = len(bf) - 2 + new_py
    out: list[Fail] = []
    if len(af) != want:
        out.append(("B4", f"{prefix}*: after-family has {len(af)} ids, expected {len(bf)} - 2 + {new_py} = {want}"))
    out += [("B4", f"{i} {o}: family id is not passed") for i, o in sorted(af.items()) if o != "passed"]
    return out


def parse_args(argv: list[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(prog="compare_outcomes.py")
    ap.add_argument("before", type=Path)
    ap.add_argument("after", type=Path)
    ap.add_argument("--before-rc", type=Path, required=True, help="pytest exit code of the before run (run_suite.sh rc)")
    ap.add_argument("--after-rc", type=Path, required=True, help="pytest exit code of the after run")
    ap.add_argument("--flaky", type=Path, default=None)
    ap.add_argument("--families", type=Path, default=None)
    ap.add_argument("--tree", type=Path, default=None, help="repo whose two new packages are counted for B4")
    ap.add_argument("--family-new-count", type=int, default=None, help="explicit .py count for B4 (tests)")
    return ap.parse_args(argv)


def main(argv: list[str]) -> int:
    a = parse_args(argv)
    try:
        before, after, flaky, prefix = read_tsv(a.before), read_tsv(a.after), read_flaky(a.flaky), read_family(a.families)
        rcs = (read_rc(a.before_rc), read_rc(a.after_rc))
        new_py = a.family_new_count if a.family_new_count is not None else (count_new_files(a.tree) if a.tree else None)
        if prefix is not None and new_py is None:
            raise ValueError("--families needs --tree <repo> or --family-new-count N")
    except (OSError, ValueError) as e:
        print(f"COMPARE ERROR: {e}")
        return 2
    c, fails = compare(before, after, flaky, prefix, new_py, rcs)
    print("COMPARE " + " ".join(f"{k}={v}" for k, v in c.items()))
    print("COMPARE FAIL" if fails else "COMPARE OK")
    for rule, msg in fails:
        print(f"{rule} {msg}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
