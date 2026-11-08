#!/usr/bin/env python3
"""batch-103 Inc 4 E1 census: the A2L name shapes the label matcher must handle.

Run on <runner> only (it imports s19_app). Reads the read-only clone at
REPO; writes nothing but its stdout and the case-08 output under OUT.

1. Generates the release case 08 (tools/synth/make_release_case.py, seed
   20260001) into OUT (never into the clone).
2. Parses every A2L it censuses with the app's own parser
   (s19_app.tui.a2l.parse_a2l_file) and takes each tag's "name" -- the names
   the A2L views list.
3. Classifies every name by shape and prints counts and samples, plus the
   inline A2L names written in tests/*.py (regex on the source text).
4. Writes the case-08 CHARACTERISTIC / MEASUREMENT names, one per line, to
   OUT/case08-names.txt and OUT/case08-issues-names.txt.

The tokeniser below is the E1 PROPOSAL (01-requirements.md, R-A2L-MATCH.1-.4):
a token is a maximal run of letters or of digits; every other character ends
a token; a lower->upper step splits; an upper run followed by a lower letter
gives its last upper letter to the next token.
"""
from __future__ import annotations

import collections
import os
import re
import statistics
import subprocess
import sys
from pathlib import Path

REPO = Path(os.environ.get("REPO", str(Path.home() / "work" / "s19_app")))
OUT = Path(os.environ.get("OUT", "/tmp/b103-e1-4/out"))
PY = sys.executable

import s19_app  # noqa: E402
from s19_app.tui.a2l import parse_a2l_file  # noqa: E402

print(f"s19_app.__file__ = {s19_app.__file__}")
print(f"python = {sys.version.split()[0]}  executable = {PY}")
print(f"repo HEAD = {subprocess.run(['git', '-C', str(REPO), 'rev-parse', '--short', 'HEAD'], capture_output=True, text=True).stdout.strip()}")
print(f"HOME = {os.environ.get('HOME')}  LOCALAPPDATA = {os.environ.get('LOCALAPPDATA')}")
print()


def _up(c: str) -> bool:
    return "A" <= c <= "Z"


def _lo(c: str) -> bool:
    return "a" <= c <= "z"


def _dig(c: str) -> bool:
    return "0" <= c <= "9"


def _let(c: str) -> bool:
    # ASCII letters, and every non-ASCII character as a caseless letter.
    return _up(c) or _lo(c) or ord(c) > 127


def tokens(name: str) -> list[tuple[int, int]]:
    """Proposed tokeniser: list of (start, end) spans."""
    spans: list[tuple[int, int]] = []
    n = len(name)
    i = 0
    while i < n:
        c = name[i]
        if not (_let(c) or _dig(c)):
            i += 1
            continue
        start = i
        if _dig(c):
            while i < n and _dig(name[i]):
                i += 1
            spans.append((start, i))
            continue
        i += 1
        while i < n and _let(name[i]):
            prev, cur = name[i - 1], name[i]
            if _lo(prev) and _up(cur):
                break
            if _up(prev) and _up(cur) and i + 1 < n and _lo(name[i + 1]):
                break
            i += 1
        spans.append((start, i))
    return spans


SHAPES = {
    "underscore": lambda s: "_" in s,
    "underscore_run_ge2": lambda s: "__" in s,
    "lead_or_trail_underscore": lambda s: s.startswith("_") or s.endswith("_"),
    "camel_lower_upper": lambda s: re.search(r"[a-z][A-Z]", s) is not None,
    "acronym_then_lower": lambda s: re.search(r"[A-Z]{2,}[a-z]", s) is not None,
    "letter_digit_boundary": lambda s: re.search(r"[A-Za-z][0-9]|[0-9][A-Za-z]", s) is not None,
    "dot": lambda s: "." in s,
    "bracket": lambda s: "[" in s or "]" in s,
    "other_char": lambda s: re.search(r"[^A-Za-z0-9_.\[\]]", s) is not None,
    "non_ascii": lambda s: any(ord(ch) > 127 for ch in s),
    "all_upper_letters": lambda s: s.upper() == s and any(ch.isalpha() for ch in s),
    "all_lower_letters": lambda s: s.lower() == s and any(ch.isalpha() for ch in s),
    "mixed_case": lambda s: s.upper() != s and s.lower() != s,
    "starts_with_digit": lambda s: s[:1].isdigit(),
}


def census(label: str, names: list[str]) -> None:
    print(f"=== {label}: {len(names)} names")
    if not names:
        print()
        return
    counter = collections.Counter(names)
    dups = sorted((n, c) for n, c in counter.items() if c > 1)
    folded: dict[str, set[str]] = collections.defaultdict(set)
    for n in counter:
        folded["".join(chr(ord(ch) + 32) if _up(ch) else ch for ch in n)].add(n)
    twins = sorted(sorted(v) for v in folded.values() if len(v) > 1)
    lengths = [len(n) for n in names]
    tok_counts = [len(tokens(n)) for n in names]
    print(f"unique = {len(counter)}  duplicates (exact, >1 occurrence) = {len(dups)}  case-twins (equal after ASCII folding) = {len(twins)}")
    print(f"length: min {min(lengths)}  median {statistics.median(lengths)}  max {max(lengths)}")
    print(f"tokens/name: min {min(tok_counts)}  median {statistics.median(tok_counts)}  max {max(tok_counts)}")
    for shape, pred in SHAPES.items():
        hits = [n for n in counter if pred(n)]
        sample = ", ".join(hits[:6])
        print(f"  {shape:26s} {len(hits):6d}  {sample}")
    if dups:
        print(f"  duplicates sample: {dups[:6]}")
    if twins:
        print(f"  case-twins sample: {twins[:6]}")
    print()


def a2l_names(path: Path) -> list[str]:
    data = parse_a2l_file(path)
    return [str(t.get("name")) for t in data.get("tags", []) if t.get("name") is not None]


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    gen = subprocess.run(
        [PY, str(REPO / "tools" / "synth" / "make_release_case.py"), "--out", str(OUT), "--seed", "20260001"],
        capture_output=True,
        text=True,
        cwd=str(OUT),
    )
    print("--- make_release_case.py --out", OUT, "--seed 20260001  rc =", gen.returncode)
    print(gen.stdout.rstrip())
    if gen.stderr.strip():
        print("stderr:", gen.stderr.strip()[:2000])
    print()

    case08 = a2l_names(OUT / "firmware.a2l")
    issues = a2l_names(OUT / "firmware_issues.a2l")
    (OUT / "case08-names.txt").write_text("\n".join(case08) + "\n", encoding="utf-8")
    (OUT / "case08-issues-names.txt").write_text("\n".join(issues) + "\n", encoding="utf-8")
    census("case08 firmware.a2l (parser)", case08)
    census("case08 firmware_issues.a2l (parser)", issues)
    kinds = collections.Counter(re.sub(r"_?\d+$", "", n) for n in case08 + issues)
    print("case08 name families (name without its trailing number):", dict(sorted(kinds.items())))
    print()

    tracked = subprocess.run(
        ["git", "-C", str(REPO), "ls-files", "*.a2l", "*.A2L"], capture_output=True, text=True
    ).stdout.split()
    union: list[str] = []
    for rel in tracked:
        try:
            names = a2l_names(REPO / rel)
        except Exception as exc:  # census must not stop on one file
            print(f"=== {rel}: PARSE FAILED {type(exc).__name__}: {exc}")
            continue
        union.extend(names)
        census(rel, names)

    inline: list[str] = []
    pat = re.compile(r"/begin\s+(?:CHARACTERISTIC|MEASUREMENT)\s+([^\s\"]+)")
    for py in sorted((REPO / "tests").glob("*.py")):
        text = py.read_text(encoding="utf-8", errors="replace")
        for m in pat.finditer(text):
            tok = m.group(1)
            if "{" in tok or "}" in tok:  # f-string templates
                tok = "<template>" + tok
            inline.append(tok)
    census("inline A2L names in tests/*.py (regex, templates marked)", [n for n in inline if not n.startswith("<template>")])
    templates = sorted({n for n in inline if n.startswith("<template>")})
    print("inline templates:", templates[:40])
    print()
    census("UNION of every tracked .a2l (parser)", union)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
