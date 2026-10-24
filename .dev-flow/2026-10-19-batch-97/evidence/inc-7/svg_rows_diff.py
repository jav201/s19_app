"""Inc-7 snapshot regen: the before / after cell diff, row by row.

For every ``tests/__snapshots__/test_tui_snapshot/*.svg`` the committed
baseline (``git show <ref>:<path>``) and the working-tree file are reduced to
their painted text rows (the Rich SVG export puts each terminal row's text in
``<text ... clip-path="url(#<id>-line-N)">`` elements) and compared. Output:
one line per cell with the differing row indices, then the differing rows of
each cell (``-`` before, ``+`` after). Styles are compared separately as the
set of ``.terminal-rN { ... }`` rule bodies, so a colour-only change shows too.

    python svg_rows_diff.py <repo> [ref]      # ref defaults to HEAD
"""
from __future__ import annotations

import html
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

TEXT = re.compile(r'<text class="[^"]*" x="([\d.]+)" y="[\d.]+" textLength="[\d.]+" clip-path="url\(#[\w-]+-line-(\d+)\)">(.*?)</text>')
STYLE = re.compile(r"\.[\w-]+-r\d+ \{ ([^}]*) \}")


def rows(svg: str) -> list:
    lines = defaultdict(list)
    for x, n, body in TEXT.findall(svg):
        lines[int(n)].append((float(x), html.unescape(body).replace(" ", " ")))
    if not lines:
        return []
    return ["".join(t for _x, t in sorted(lines[i])).rstrip() for i in range(max(lines) + 1)]


def styles(svg: str) -> set:
    return set(STYLE.findall(svg))


def main() -> int:
    repo = Path(sys.argv[1]).resolve()
    ref = sys.argv[2] if len(sys.argv) > 2 else "HEAD"
    folder = repo / "tests" / "__snapshots__" / "test_tui_snapshot"
    details = []
    for path in sorted(folder.glob("*.svg")):
        rel = path.relative_to(repo).as_posix()
        old = subprocess.run(["git", "show", f"{ref}:{rel}"], cwd=repo, capture_output=True).stdout.decode("utf-8")
        new = path.read_text(encoding="utf-8")
        a, b = rows(old), rows(new)
        changed = [i for i in range(max(len(a), len(b))) if (a[i] if i < len(a) else None) != (b[i] if i < len(b) else None)]
        style_delta = len(styles(old) ^ styles(new))
        cell = path.stem.split("[", 1)[1].rstrip("]")
        print(f"{cell:32s} rows {len(a)}->{len(b)}  changed {len(changed):2d}  {changed}  style-rules-delta {style_delta}")
        details.append((cell, a, b, changed))
    print()
    for cell, a, b, changed in details:
        print(f"===== {cell}")
        for i in changed:
            print(f"  {i:2d} - {a[i] if i < len(a) else '<none>'}")
            print(f"  {i:2d} + {b[i] if i < len(b) else '<none>'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
