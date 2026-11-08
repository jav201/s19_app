"""batch-103 Inc 1b E1 addendum: records trace check (reads the two .md records only; imports nothing of s19_app).

Usage: python trace-check-e1a.py <inc-1b folder>
"""
import re
import sys
from pathlib import Path

d = Path(sys.argv[1])
req = (d / "01-requirements.md").read_text(encoding="utf-8")
tc = (d / "02-test-cases.md").read_text(encoding="utf-8")


def cells(line):
    # split on '|' not inside backticks
    out, cur, tick = [], "", False
    for ch in line:
        if ch == "`":
            tick = not tick
        if ch == "|" and not tick:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    out.append(cur)
    return out[1:-1]


rows = {}
for line in req.splitlines():
    m = re.match(r"^\| (R-COPY\.\d+) \|", line)
    if m:
        c = cells(line)
        rows[m.group(1)] = (len(c), c[6].strip().startswith("**withdrawn**"), c[2])
print("rows:", len(rows), "cells per row:", sorted({v[0] for v in rows.values()}))
active = [r for r, v in rows.items() if not v[1]]
print("active", len(active), "withdrawn", [r for r, v in rows.items() if v[1]])
nums = sorted(int(r.split(".")[1]) for r in rows)
print("ids 1..22 complete:", nums == list(range(1, 23)))
for r in active:
    n = rows[r][2].count(" shall ")
    if n != 1:
        print("shall count", r, n)
cases = set(re.findall(r"^\| (R-COPY\.\d+)/\d+", tc, re.M))
print("active rows without a case:", [r for r in active if r not in cases])
print("cases naming a non-active row:", sorted(c for c in cases if c not in active))
bad = []
for line in tc.splitlines():
    if re.match(r"^\| (~~)?R-", line):
        n = len(cells(line))
        if n != 9:
            bad.append((line[:45], n))
print("case rows with cell count != 9:", bad)
