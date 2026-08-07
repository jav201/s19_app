#!/usr/bin/env python
"""batch-78 §6.4a propagation register — a GATE, not a report.

Revision 2's register failed at the INPUT SET (hand-recalled sites).
Revision 3 derived the input set but still dispositioned it BY HAND, so the
table's counts stopped reproducing against the file it shipped with.

This script closes the third stage: it derives the input set AND the
disposition, prints §6.4a's table from its own output, and **exits non-zero**
on any undispositioned hit or any surviving stale form.

    python .dev-flow/2026-08-06-batch-78/enum.py            # gate + census
    python .dev-flow/2026-08-06-batch-78/enum.py --table    # emit §6.4a markdown

Exit 0 = every hit of every tracked term sits in a section that term is
allowed to appear in, and no superseded form survives anywhere.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

DOC = Path(__file__).with_name("01-requirements.md")

# ---------------------------------------------------------------- stale forms
# Each must have ZERO matches. These are the superseded spellings; a match means
# a fix was reverted or a new site was written in the old form.
STALE: list[tuple[str, str]] = [
    ("OWNING guard as THE guard",   r"with `assert len\(OWNING\) == 3`"),
    ("status-bar == 7",             r"size\.height == 7"),
    ("footer painted 7 baseline",   r"unchanged at \*\*7\*\*|is 7, not 14|7 fully painted"),
    ("footer containment claim",    r"contains all \*\*14\*\*"),
    ("six symbols",                 r"(?i)the six symbols"),
    ("clipped as the row bound",    r"≤\*?\*? its clipped height"),
    ("16 _project_label sites",     r"16 re-pointed `_project_label"),
    ("singular unsatisfied axis",   r"naming the unsatisfied axis|names the \*\*width\*\* axis"),
    ("markup=False as sufficient",  r"shall\*?\*? be constructed with `markup=False`"),
    ("_DIFF_MIN_ROWS_H",            r"_DIFF_MIN_ROWS_H"),
    ("26 as a sentinel",            r"`139`, `94`, `29`, `26`"),
    ("superset premise asserted",   r"\*\*Rule applied:\*\* the architect allocation is canonical \(superset"),
    ("136 as a breakpoint",         r"breakpoint to 136|136 \(CSS box\)"),
    ("ctx mutation for AT-B78-22",  r"reddens under `ctx 16 → 64`"),
    ("AT-B78-33 inline baseline",   r"pre-change baseline of 7\*?\*? \(executed: 13\)"),
]

# ------------------------------------------------------- tracked terms + scope
# section prefix -> the term may legitimately appear there.
TERMS: list[tuple[str, str, tuple[str, ...]]] = [
    ("OWNING length guard",      r"len\(OWNING\) == 3",                    ("3.", "5.1", "5.5")),
    ("status-bar height",        r"status_bar\.size\.height|<= 7\b",       ("3.", "4.", "5.3", "6.4a")),
    ("unsatisfied axis",         r"unsatisfied axis",                      ("2.8", "3.", "4.", "5.3", "6.4a")),
    ("clipped vs content bound", r"≤\*?\*? its (clipped|\*\*content\*\*)", ("3.", "4.", "5.5", "6.4a")),
    ("footer painted count",     r"painted|none truncated|contains all",   ("1.3", "2.4", "3.", "4.", "5.3", "5.4", "6.4a")),
    ("footer numeral",           r"\b(7|8|12|13|14|15|16)\b(?=[^|]{0,60}(chip|Footer|painted))",
                                                                          ("1.3", "2.4", "2.7", "2.8", "3.", "4.", "5.3", "5.5", "6.4a", "9.")),
    ("fallback layout",          r"fallback",                              ("1.3", "2.6", "2.8", "3.", "4.", "5.3", "5.5", "6.4a", "7.", "8.")),
    ("symbol count",             r"\b(six|seven)\b[^|]{0,20}symbols?",     ("3.", "4.", "5.3", "5.6", "6.4a", "7.")),
    ("_project_label sites",     r"_project_label",                        ("2.7", "3.", "4.", "5.3", "6.4a", "6.5", "7.")),
    ("_KIND_LABEL",              r"_KIND_LABEL",                           ("4.", "6.4a", "8.")),
    ("superset premise",         r"superset",                              ("3.", "5.3", "5.5", "5.6", "6.3", "6.4a", "9.", "10.")),
    ("26 sentinel",              r"`26`",                                  ("3.", "4.", "6.4a")),
    ("regime constants",         r"_DIFF_MIN_H|_DIFF_WIDE_MIN|_DIFF_MIN_W", ("1.3", "2.4", "2.8", "3.", "4.", "6.4a", "8.")),
    ("markup=False",             r"markup=False",                          ("2.4", "3.", "4.", "5.6", "6.4a")),
    ("AT-B78-27 retirement",     r"AT-B78-27",                             ("3.", "5.3", "5.5", "5.6", "5.7", "6.4a", "7.", "10.")),
    ("135 / 136",                r"\b13[56]\b",                            ("0", "2.7", "4.", "6.3", "6.4a", "10.")),
    ("test_tc029",               r"test_tc029",                            ("4.", "5.6", "6.4a", "7.")),
    # §6.5 added at the Inc-4 gate (2026-08-06). A DELIBERATE widening, recorded
    # rather than made silently, because widening an allowlist so a red goes away
    # is exactly how a gate stops gating. Justification: §6.5 is where requirement
    # amendments live, and Amendment D changes a threshold whose discharge IS this
    # mutation ("reddens the exact arm, not the containment one"). The hit is
    # current, correct content in a section the term list never anticipated — the
    # same shape as C-78-xi, where the tracked terms did not cover §7's cells.
    # Widening the RULE, not excusing the instance.
    ("AT-B78-22 mutation",       r"DISPLAY_CONTEXT_BYTES == 16|high = end", ("3.", "6.4a", "6.5", "7.")),
    ("AT-B78-33 baseline",       r"AT-B78-33",                             ("3.", "5.3", "5.4", "5.7", "6.4a", "7.")),
    ("shall outside Statements", r"\bshall\b",                             ("0", "3.", "4.", "5.3", "5.6", "6.4a", "6.5", "9.")),
]

HEAD = re.compile(r"^#{2,4}\s+(?:§)?([0-9]+(?:\.[0-9a-z]+)*)")


def sections(lines: list[str]) -> list[str]:
    """Section id in force at each line."""
    out, cur = [], "0"
    for line in lines:
        m = HEAD.match(line)
        if m:
            cur = m.group(1)
        out.append(cur)
    return out


def in_scope(sec: str, allowed: tuple[str, ...]) -> bool:
    return any(sec == a.rstrip(".") or sec.startswith(a.rstrip(".") + ".") or sec == a
               or sec.split(".")[0] + "." == a for a in allowed)


def main() -> int:
    lines = DOC.read_text(encoding="utf-8").split("\n")
    secs = sections(lines)
    table = "--table" in sys.argv
    failures = 0

    print(f"§6.4a propagation gate — {DOC.name}, {len(lines)} lines")
    print("=" * 78)
    print("STALE FORMS (each must be 0)")
    for label, pat in STALE:
        rx = re.compile(pat)
        hits = [i + 1 for i, l in enumerate(lines) if rx.search(l)]
        # the gate's own source and §6.4a's quoted patterns are not violations
        hits = [h for h in hits if not secs[h - 1].startswith("6.4a")]
        status = "ok" if not hits else f"FAIL {hits}"
        if hits:
            failures += 1
        print(f"  {label:<32} {len(hits):>2}  {status}")

    print()
    print("TRACKED TERMS — every hit must sit in an allowed section")
    rows = []
    for label, pat, allowed in TERMS:
        rx = re.compile(pat)
        hits = [(i + 1, secs[i]) for i, l in enumerate(lines) if rx.search(l)]
        bad = [(n, s) for n, s in hits if not in_scope(s, allowed)]
        if bad:
            failures += 1
        secset = sorted({s for _, s in hits}, key=lambda x: [int(p) if p.isdigit() else 99
                                                            for p in x.split(".")])
        print(f"  {label:<28} {len(hits):>3} hit(s)  §{','.join(secset)}"
              + ("" if not bad else f"   UNDISPOSITIONED -> {bad}"))
        for n, s in bad:
            print(f"      UNDISPOSITIONED  line {n}  §{s}: {lines[n-1].strip()[:90]}")
        rows.append((label, pat, len(hits), secset, bad))

    if table:
        print()
        print("| Changed term | grep pattern | Hits | Sections carrying them |")
        print("|---|---|:-:|---|")
        for label, pat, n, secset, _ in rows:
            print(f"| **{label}** | `{pat}` | **{n}** | {' · '.join('§' + s for s in secset)} |")

    print()
    print("=" * 78)
    if failures:
        print(f"GATE: FAIL — {failures} term(s) with a stale form or an undispositioned hit")
        return 1
    print("GATE: PASS — 0 stale forms, 0 undispositioned hits")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
