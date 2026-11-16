"""Retarget test patches of the two god modules from the package root to ``.deps``.

Reads ``app.d1_names`` and ``screens_directionb.d1_names`` from ``module-map.json``
and rewrites, in every ``tests/**/*.py``, the six site classes of the D1 seam
(``design/spec-retarget-tests.md``): T1 setattr/delattr/patch.object calls whose
first argument is a module alias and whose second argument is a D1 name string;
T2 string targets ``"P.X..."``; T3 assignment/aug-assign/``del`` targets ``A.X``;
T4 every other attribute read ``A.X`` with ``X`` in D1; T5 a getattr/setattr/
delattr/patch.object whose second argument is a parameter of the enclosing
function, rewritten only when every call of that function passes a D1 constant;
T6 a module alias passed as an argument to a patching helper (rewritten when the
same call passes a D1 name, refused R5 otherwise). Each rewrite redirects the
target from the package root to the package's ``deps`` module.

Uncovered forms that reach a D1 name are refused (exit 1, nothing written):
``vars(A)``, ``A.__dict__``, ``getattr(A, "X")`` with a D1 name, ``patch.multiple``
/ ``patch.dict``, ``sys.modules["P"]``, a dynamic setattr/delattr name, a write
through ``<fn>.__globals__`` (R1 extension), and a T6 helper call with a non-D1 /
non-constant / missing name (R5). ``--accept-refusal FILE`` tolerates exactly the
refusals listed in FILE (lines ``path:line CODE reason``); any other refusal still
fails. A non-constant ``getattr(A, name)`` read outside a named-function parameter
is allowed (carve-out #1) and reported as a ``dynamic-read`` NOTE.

Usage: python -I tools/modularize/retarget_tests.py --repo <tree> --map <module-map.json> [--check] [--accept-refusal FILE]
"""
from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import retarget_scan as scan  # noqa: E402


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", required=True, help="repo root containing tests/")
    parser.add_argument("--map", required=True, help="module-map.json path")
    parser.add_argument("--check", action="store_true",
                        help="report remaining sites and exit 1 if any; never write")
    parser.add_argument("--accept-refusal", metavar="FILE", default=None,
                        help="allowlist of known hand-adapted refusals (lines: path:line CODE reason)")
    return parser.parse_args(argv)


def _print_summary(scanned: int, changed: int, counts: dict, refused: int,
                   accepted: int = 0) -> None:
    print(f"RETARGET files_scanned={scanned} files_changed={changed} "
          f"T1={counts['T1']} T2={counts['T2']} T3={counts['T3']} T4={counts['T4']} "
          f"T5={counts['T5']} T6={counts['T6']} refused={refused} accepted={accepted}")


def _load_accept(path: Path | None) -> set[tuple[str, int, str]]:
    """Parse the accept-refusal allowlist into {(rel, lineno, code), ...}."""
    if path is None:
        return set()
    out: set[tuple[str, int, str]] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        head, code, _reason = line.split(None, 2)
        rel, lineno_s = head.rsplit(":", 1)
        out.add((rel, int(lineno_s), code))
    return out


def _rewrite(results: list, d1: dict[str, set[str]],
             accept: set[tuple[str, int, str]]) -> int:
    """Write the rewrites after the in-memory acceptance checks (2, 3, 4)."""
    changed = 0
    for path, rel, text, edits in results:
        if not edits:
            continue
        for e in edits:
            if text[e.start - len(e.anchor):e.start] != e.anchor:
                sys.exit(f"anchor mismatch {rel}:{e.lineno} {e.kind}")
        new_text, placements = scan.apply_edits(text, edits)
        undone = new_text
        for pos, repl in sorted(placements, reverse=True):
            if undone[pos:pos + len(repl)] != repl:
                sys.exit(f"undo mismatch {rel}")
            undone = undone[:pos] + undone[pos + len(repl):]
        if undone != text:
            sys.exit(f"diff-outside-spans {rel}")
        new_tree = ast.parse(new_text)
        re_edits, re_refusals, _, _ = scan.analyze(new_text, new_tree, rel, d1)
        leftover_refusals = [r for r in re_refusals
                             if (r.rel, r.lineno, r.code) not in accept]
        if re_edits or leftover_refusals:
            sys.exit(f"not idempotent {rel}")
        path.write_text(new_text, encoding="utf-8", newline="\n")
        changed += 1
    return changed


def main(argv: list[str] | None = None) -> None:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    root = Path(args.repo)
    d1 = scan.load_d1(Path(args.map))
    test_files = sorted((root / "tests").rglob("*.py"))

    results = []
    all_refusals: list = []
    dynamic_reads: list = []
    counts = {"T1": 0, "T2": 0, "T3": 0, "T4": 0, "T5": 0, "T6": 0}
    accept = _load_accept(Path(args.accept_refusal) if args.accept_refusal else None)
    for path in test_files:
        rel = path.relative_to(root).as_posix()
        text = path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(text)
        except SyntaxError as exc:
            lineno = exc.lineno or 0
            src = text.split("\n")[lineno - 1] if lineno else ""
            all_refusals.append(scan.Refusal("R4", rel, lineno, src))
            continue
        edits, refusals, c, reads = scan.analyze(text, tree, rel, d1)
        refusals.extend(scan.find_r3(path, rel, tree, d1, scan.Source(text)))
        results.append((path, rel, text, edits))
        all_refusals.extend(refusals)
        dynamic_reads.extend((rel, node.lineno) for node in reads)
        for key in counts:
            counts[key] += c[key]

    accepted_refusals = [r for r in all_refusals if (r.rel, r.lineno, r.code) in accept]
    remaining_refusals = [r for r in all_refusals if (r.rel, r.lineno, r.code) not in accept]
    for r in sorted(accepted_refusals, key=lambda r: (r.rel, r.lineno)):
        print(f"RETARGET NOTE accepted-refusal {r.code} {r.rel}:{r.lineno} {r.src}")
    if remaining_refusals:
        for r in sorted(remaining_refusals, key=lambda r: (r.rel, r.lineno)):
            print(f"RETARGET REFUSE {r.code} {r.rel}:{r.lineno} {r.src}")
        sys.exit(1)

    for rel, lineno in sorted(dynamic_reads):
        print(f"RETARGET NOTE dynamic-read {rel}:{lineno}")

    if args.check:
        for _, rel, _, edits in results:
            for e in sorted(edits, key=lambda e: (e.lineno, e.start)):
                print(f"RETARGET SITE {rel}:{e.lineno} {e.kind}")
        remaining = sum(counts.values())
        _print_summary(len(test_files), 0, counts, len(remaining_refusals),
                       len(accepted_refusals))
        print(f"RETARGET CHECK remaining={remaining}")
        sys.exit(1 if remaining else 0)

    changed = _rewrite(results, d1, accept)
    scan.verify_census(root, d1)
    _print_summary(len(test_files), changed, counts, len(remaining_refusals),
                   len(accepted_refusals))
    print("RETARGET CHECK remaining=0")
    print("RETARGET OK")


if __name__ == "__main__":
    main()
