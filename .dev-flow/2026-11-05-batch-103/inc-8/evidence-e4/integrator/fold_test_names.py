"""Fold the E4 group case files into 02-test-cases.md's two E4 columns (integrator, Inc 8).

usage: python -I -B fold_test_names.py <inc-8 folder>
Reads 02-test-cases-{A,AT,P,S1,S2}.md; for every case row of 02-test-cases.md fills
"Test name (E4)" (names joined with "; ") and "full / partial (E4)" (full when any group marks it
full). Rows no group names keep "—" and are listed. Tester-added rows absent from the E1 list are
counted, not added (they stay in their group file).
"""
import re
import sys
from pathlib import Path

GROUPS = ("A", "AT", "P", "S1", "S2")


def cells(line):
    return [c.strip() for c in line.strip().strip("|").split("|")]


def expand(raw):
    token = raw.split()[0] if raw.split() else ""
    req, _, alts = token.partition("/")
    if not (req.startswith("R-") or req.startswith("AT-")):
        return []
    if not alts:
        return [req]
    out = []
    for part in alts.split(","):
        part = part.lstrip("/")
        if not part:
            continue
        if ".." in part:
            lo, hi = part.split("..")
            out += [f"{req}/{n}" for n in range(int(lo), int(hi) + 1)]
        else:
            out.append(f"{req}/{part}")
    return out


def at_nodes(text):
    nodes = {}
    for line in text.splitlines():
        c = cells(line) if line.startswith("| AT-") else None
        if c and len(c) == 3:
            short = "AT-" + c[0].rsplit("-", 1)[1]
            nodes[short] = c[2].strip("`")
    return nodes


def main(folder):
    folder = Path(folder)
    found, added = {}, []
    for g in GROUPS:
        text = (folder / f"02-test-cases-{g}.md").read_text(encoding="utf-8")
        nodes = at_nodes(text) if g == "AT" else {}
        for line in text.splitlines():
            if not line.startswith("| R-"):
                continue
            c = cells(line)
            test, mark = c[-2], c[-1].split()[0].strip("*").lower()
            if nodes:
                test = "; ".join(nodes.get(t.strip(), t.strip()) for t in test.split(","))
            for case in expand(c[0]):
                names, marks = found.setdefault(case, ([], []))
                names.append(f"{g}: {test}")
                marks.append(mark)
    target = folder / "02-test-cases.md"
    lines = target.read_text(encoding="utf-8").split("\n")
    known, missing = set(), []
    for i, line in enumerate(lines):
        if not line.startswith("| R-"):
            continue
        c = cells(line)
        known.add(c[0])
        if c[0] not in found:
            missing.append(c[0])
            continue
        names, marks = found[c[0]]
        c[-2] = "; ".join(names).replace("|", chr(92) + "|")
        c[-1] = "full" if "full" in marks else "partial"
        lines[i] = "| " + " | ".join(c) + " |"
    added = sorted(k for k in found if k not in known)
    target.write_text("\n".join(lines), encoding="utf-8", newline="\n")
    print(f"rows folded: {len(known) - len(missing)} of {len(known)}")
    print(f"rows with no E4 test name ({len(missing)}): {', '.join(missing) or '-'}")
    print(f"tester-added cases kept in their group files ({len(added)}): {', '.join(added) or '-'}")


if __name__ == "__main__":
    main(sys.argv[1])
