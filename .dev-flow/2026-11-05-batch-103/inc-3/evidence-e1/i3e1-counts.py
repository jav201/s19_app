"""Inc 3 E1 count census (batch-103): for every CURVE and MAP of the tracked
A2L files, the point count each axis gets under the rows (STD/FIX: the
AXIS_DESCR max axis points; COM: the AXIS_PTS header's), the AXIS_DESCR's own
count for COM axes (to show whether the two differ), FIX_NO_AXIS_PTS lines
against the point count, and the expected element count. Text only (comments
left out by the clone's ``_strip_a2l_comments``); no decode, no image.

Usage: python i3e1-counts.py <repo clone>
"""
from __future__ import annotations

import subprocess
import sys
from collections import Counter
from pathlib import Path


def main(argv: list[str]) -> int:
    repo = Path(argv[1]).resolve()
    sys.path.insert(0, str(repo))
    import s19_app  # noqa: E402
    from s19_app.tui import a2l  # noqa: E402

    print(f"s19_app.__file__ = {s19_app.__file__}")
    files = subprocess.run(["git", "-C", str(repo), "ls-files", "*.a2l"],
                           capture_output=True, text=True, check=True).stdout.split()

    def toks(s):
        head = a2l._split_line_respecting_quotes(a2l._strip_a2l_comments(s.get("meta") or ""))
        return head + a2l._flatten_body_tokens(s.get("lines") or [])

    def walk(secs, out):
        for s in secs:
            out.append(s)
            walk(s.get("children") or [], out)

    def lines_of(s):
        text = a2l._A2L_LINE_SENTINEL.join(s.get("lines") or [])
        return [ln.split() for ln in a2l._strip_a2l_comments(text).split(a2l._A2L_LINE_SENTINEL) if ln.split()]

    for rel in files:
        secs, _ = a2l.build_section_tree(repo / rel)
        flat: list[dict] = []
        walk(secs, flat)
        ap = {}
        lay = {}
        for s in flat:
            if s.get("name") == "AXIS_PTS":
                t = toks(s)
                if t:
                    ap[t[0]] = t
            if s.get("name") == "RECORD_LAYOUT":
                t = (s.get("meta") or "").split()
                if t:
                    lay[t[0]] = lines_of(s)
        stats = Counter()
        samples = []
        for s in flat:
            if s.get("name") != "CHARACTERISTIC":
                continue
            t = toks(s)
            if len(t) < 5 or t[2] not in ("CURVE", "MAP"):
                continue
            axes = [c for c in (s.get("children") or []) if c.get("name") == "AXIS_DESCR"]
            counts = []
            for i, ax in enumerate(axes):
                at = a2l._flatten_body_tokens(ax.get("lines") or [])
                kind = at[0] if at else "?"
                own = at[3] if len(at) > 3 else None
                if kind == "COM_AXIS" and "AXIS_PTS_REF" in at:
                    ref = at[at.index("AXIS_PTS_REF") + 1]
                    if ref in ap and len(ap[ref]) > 7:
                        n = ap[ref][7]
                        stats["COM: AXIS_DESCR max == AXIS_PTS max" if n == own else "COM: AXIS_DESCR max != AXIS_PTS max"] += 1
                        if n != own and len(samples) < 6:
                            samples.append(f"{rel}: {t[0]} axis {i + 1}: AXIS_DESCR {own}, AXIS_PTS {ref} {n}")
                        counts.append(n)
                    else:
                        counts.append(None)
                else:
                    counts.append(own)
                letter = "XY"[i] if i < 2 else "?"
                fixno = [ln[1] for ln in lay.get(t[4], []) if ln[0] == f"FIX_NO_AXIS_PTS_{letter}" and len(ln) > 1]
                if fixno:
                    stats["FIX_NO == point count" if fixno[0] == counts[-1] else "FIX_NO != point count"] += 1
                    if fixno[0] != counts[-1] and len(samples) < 12:
                        samples.append(f"{rel}: {t[0]} axis {i + 1}: FIX_NO_AXIS_PTS_{letter} {fixno[0]}, point count {counts[-1]}")
            try:
                prod = 1
                for c in counts:
                    prod *= int(c)
                stats[f"{t[2]} element count readable"] += 1
            except (TypeError, ValueError):
                stats[f"{t[2]} element count NOT readable"] += 1
        if stats:
            print(f"\n== {rel}")
            for k, v in sorted(stats.items()):
                print(f"   {v:5d}  {k}")
            for x in samples:
                print(f"   sample: {x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
