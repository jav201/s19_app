"""TC-MOD-52 independent check of retargeter acceptance 2.  Usage: rt_undo_check.py <work-tree> <old-tests-rev>
For every tests/*.py that differs from <old-tests-rev>: same number of lines, and each differing line equals the old line once
the inserted `.deps` tokens are removed.  Prints the number of lines that differ outside the rewritten spans."""
import subprocess
import sys
from pathlib import Path

work, rev = Path(sys.argv[1]), sys.argv[2]
names = subprocess.run(["git", "-C", str(work), "ls-tree", "-r", "--name-only", rev, "tests"], capture_output=True, text=True, check=True).stdout.split()
changed = lines_changed = outside = 0
for rel in names:
    if not rel.endswith(".py"):
        continue
    old = subprocess.run(["git", "-C", str(work), "show", f"{rev}:{rel}"], capture_output=True, check=True).stdout.decode("utf-8")
    new = (work / rel).read_bytes().decode("utf-8")  # bytes: a CRLF -> LF conversion must stay visible
    if old == new:
        continue
    changed += 1
    ol, nl = old.split("\n"), new.split("\n")
    if len(ol) != len(nl):
        outside += abs(len(ol) - len(nl))
        print(f"LINECOUNT {rel} {len(ol)} -> {len(nl)}")
        continue
    for i, (a, b) in enumerate(zip(ol, nl), 1):
        if a != b:
            lines_changed += 1
            if b.replace(".deps", "") != a.replace(".deps", "") or ".deps" not in b:
                outside += 1
                print(f"OUTSIDE {rel}:{i}\n  old: {a}\n  new: {b}")
print(f"UNDO-CHECK files_changed={changed} lines_changed={lines_changed} lines_outside_spans={outside}")
sys.exit(1 if outside else 0)
