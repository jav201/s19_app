"""A C16 analogue for UI threads: each literal anchor of an `examples:` line must
appear in the recorded output of the step that the line names.

Anchors (Metodologia.md §3.1 item 7): text in backticks, in "…" or in «…».
Source `(U1.3)` -> the block of `u01.out.txt` that starts at `== U1.3` and ends at
the next `== `. `inferred` lines are skipped. An anchor that is a code identifier
of the graph itself (a qualname) is not checked.
Usage: python check_anchors.py ../graph-ui-flows.md > ../extract/anchors-report.md
"""
import re, sys
from pathlib import Path

HERE = Path(__file__).parent
graph = Path(sys.argv[1]).read_text(encoding="utf-8")
blocks = {}
for out in sorted(HERE.glob("u0*.out.txt")):
    text = out.read_text(encoding="utf-8")
    parts = re.split(r"(?m)^== ", text)
    for part in parts[1:]:
        m = re.match(r"(U\d+\.\d+)", part)
        if m:
            blocks.setdefault(m.group(1), "")
            blocks[m.group(1)] += part

anchor_re = re.compile(r"`([^`]+)`|\"([^\"]+)\"|«([^»]+)»")
rows, bad = [], 0
for line in graph.splitlines():
    if not line.startswith("examples:"):
        continue
    src = re.match(r"examples: \(([^)]*)\)", line)
    if not src:
        continue
    if "inferred" in src.group(1):
        rows.append(("skip", src.group(1), "inferred", line[:90])); continue
    ids = re.findall(r"U\d+\.\d+", src.group(1))
    hay = "".join(blocks.get(i, "") for i in ids)
    body = line[src.end():]
    anchors = [a or b or c for a, b, c in anchor_re.findall(body)]
    if not anchors:
        rows.append(("no_anchor", src.group(1), "-", line[:90])); continue
    # the recorder escapes backslashes in repr(); compare on a normalised form
    norm = hay.replace("\\\\", "\\")
    miss = [a for a in anchors if a not in hay and a not in norm and a.replace("…", "") not in norm]
    # an anchor with … is a cut value: check each piece
    miss2 = []
    for a in miss:
        pieces = [x.strip() for x in a.split("…") if x.strip()]
        if not pieces or any(pc not in norm for pc in pieces):
            miss2.append(a)
    status = "ok" if not miss2 else "drift"
    bad += status == "drift"
    rows.append((status, src.group(1), "; ".join(miss2) or f"{len(anchors)} anchors", line[:90]))

print("# Anchor check of the UI threads (C16 analogue)\n")
print("| Status | Source | Missing anchors / count | Line |")
print("|---|---|---|---|")
for r in rows:
    print("| " + " | ".join(x.replace("|", "\\|") for x in r) + " |")
print(f"\nlines: {len(rows)} · ok: {sum(r[0]=='ok' for r in rows)} · drift: {bad} · no_anchor: {sum(r[0]=='no_anchor' for r in rows)} · inferred: {sum(r[0]=='skip' for r in rows)}")
