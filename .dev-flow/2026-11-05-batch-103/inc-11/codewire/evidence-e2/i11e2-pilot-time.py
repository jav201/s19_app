"""Inc 11 E2 pilot (batch-103): the parse time and peak memory the e07fb00 reader takes, and the time and memory a
one-pass word lexer + word-built section tree of the graph's contract shape takes, on the same files, same host,
interleaved runs, one fresh process per run (R-A2L-READ.52's base is owed by E1 to E2).

NOT product code and NOT a stub: a throwaway feasibility model of the graph's `_lex_a2l_words` / `build_section_tree`
contract shape, written here, importing nothing from s19_app in the candidate path. It answers two design questions:
  Q1  can a lexer with these rules (ASCII blanks, comments as word breaks, strings across lines, every line end) and a
      word-built tree stay within 1.5x of the e07fb00 parse on case_06 (36.7 MB) and software_a (5.1 MB)?
  Q2  what does storing every section's own words (variant W) cost in memory against storing only the canonical
      lines plus their line numbers (variant L)?

Usage (<runner> only):  python -I i11e2-pilot-time.py drive <repo> <runs>
                           python -I i11e2-pilot-time.py base|candW|candL <repo> <file>     (one run, JSON line)
"""
from __future__ import annotations

import json
import re
import resource
import statistics
import subprocess
import sys
import time
from pathlib import Path

BLANK_RUN = re.compile(r"[^ \t\x0b\x0c]+")          # an ASCII-blank-separated run (fast lines only)
TOK = re.compile(
    r'[ \t\x0b\x0c]*(?:'
    r'(\n)'                                        # 1 line end (already normalised to LF)
    r'|"((?:[^"\\]|\\.)*)"'                        # 2 quoted string, escape pairs kept, may span lines
    r'|(/\*.*?\*/)'                                # 3 block comment, first */ closes it
    r'|(//[^\n]*)'                                 # 4 line comment
    r'|((?:[^ \t\x0b\x0c\n"/]|/(?![/*]))+)'        # 5 word
    r'|(/\*|")'                                    # 6 an opener with no closer
    r'|$)',
    re.S,
)


def lex(text: str):
    """-> (word lines [(line, [canonical words]), ...], errors). Canonical word: a quoted string keeps its quotes."""
    if text.startswith("﻿"):
        text = text[1:]
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    out: list = []
    errors: list = []
    lines = text.split("\n")
    pos = 0
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        if '"' not in line and "/*" not in line and "//" not in line and "*/" not in line:
            ws = BLANK_RUN.findall(line)
            if ws:
                if not (line.isascii() and line.translate(_BLANK_TO_SPACE).isprintable()):
                    for w in ws:
                        if not (w.isascii() and w.isprintable()):
                            bad = next(c for c in w if not (" " < c <= "~"))
                            errors.append(f"Line {i + 1}: unexpected character U+{ord(bad):04X}")
                            break
                out.append((i + 1, ws))
            pos += len(line) + 1
            i += 1
            continue
        # slow path: regex from this line's start, across lines while a string or comment is open
        ln = i + 1
        cur: list = []
        cur_ln = ln
        p = pos
        while True:
            m = TOK.match(text, p)
            if m is None or m.end() == p and m.lastindex is None:
                # end of text
                if cur:
                    out.append((cur_ln, cur))
                return out, errors
            p = m.end()
            g = m.lastindex
            if g == 1:
                if cur:
                    out.append((cur_ln, cur))
                ln += 1
                i = ln - 1
                pos = p
                break
            if g == 2:
                if not cur:
                    cur_ln = ln
                cur.append('"' + m.group(2) + '"')
                ln += m.group(2).count("\n")
            elif g == 3:
                ln += m.group(3).count("\n")
            elif g == 4:
                pass
            elif g == 5:
                w = m.group(5)
                if not cur:
                    cur_ln = ln
                if "*/" in w:
                    errors.append(f"Line {ln}: */ without /*")
                cur.append(w)
            elif g == 6:
                errors.append(f"Line {ln}: " + ("comment not closed" if m.group(6) == "/*" else "quoted string not closed"))
                if cur:
                    out.append((cur_ln, cur))
                return out, errors
    return out, errors


_BLANK_TO_SPACE = str.maketrans("\t\x0b\x0c", "   ")


def build(path: Path, keep_words: bool):
    raw = path.read_bytes()
    text = raw.decode("utf-8", errors="replace")
    wordlines, errors = lex(text)
    roots: list = []
    stack: list = []
    want_kw = None  # a /begin waiting for its keyword
    for ln, ws in wordlines:
        if stack and want_kw is None and not any(w[0] == "/" for w in ws):
            sec = stack[-1]
            if sec["_meta_open"] and ln == sec["_kw_line"]:
                sec["meta"] = (sec["meta"] + " " + " ".join(ws)).strip()
            else:
                sec["_meta_open"] = False
                sec["lines"].append(" ".join(ws))
                if keep_words:
                    sec["words"].extend((w, ln) for w in ws)
                else:
                    sec["line_numbers"].append(ln)
            continue
        run: list = []

        def flush():
            if run and stack:
                sec = stack[-1]
                if sec["_meta_open"] and ln == sec["_kw_line"]:
                    sec["meta"] = (sec["meta"] + " " + " ".join(run)).strip()
                else:
                    sec["_meta_open"] = False
                    sec["lines"].append(" ".join(run))
                    if keep_words:
                        sec["words"].extend((w, ln) for w in run)
                    else:
                        sec["line_numbers"].append(ln)
            run.clear()

        k = 0
        while k < len(ws):
            w = ws[k]
            lw = w.lower() if w[0] == "/" else ""
            if want_kw is not None:
                want_kw["name"] = w
                want_kw["_kw_line"] = ln
                want_kw = None
                k += 1
                continue
            if lw == "/begin":
                flush()
                entry = {"name": "UNKNOWN", "meta": "", "start_line": ln, "lines": [], "children": [],
                         "_meta_open": True, "_kw_line": ln}
                if keep_words:
                    entry["words"] = []
                else:
                    entry["line_numbers"] = []
                (stack[-1]["children"] if stack else roots).append(entry)
                stack.append(entry)
                want_kw = entry
                k += 1
                continue
            if lw == "/end":
                flush()
                if stack:
                    sec = stack.pop()
                    sec["end_line"] = ln
                    nm = ws[k + 1] if k + 1 < len(ws) else None
                    if nm is not None and nm != sec["name"]:
                        errors.append(f"Line {ln}: /end {nm} does not close /begin {sec['name']}")
                else:
                    errors.append(f"Line {ln}: /end without /begin")
                k += 2
                continue
            if lw == "/include":
                errors.append(f"Line {ln}: /include {ws[k + 1] if k + 1 < len(ws) else ''} is not read")
            run.append(w)
            k += 1
        flush()
    if stack:
        errors.append("Unclosed /begin sections detected.")
    return roots, errors


def count(secs, names=("MEASUREMENT", "CHARACTERISTIC")):
    c = 0
    total = 0
    stack = list(secs)
    while stack:
        s = stack.pop()
        total += 1
        if s["name"] in names:
            c += 1
        stack.extend(s["children"])
    return c, total


def one(mode: str, repo: Path, f: Path) -> dict:
    if mode in ("baseTree", "baseFull"):
        sys.path.insert(0, str(repo))
        import s19_app.tui.a2l as a  # noqa: E402
        t0 = time.perf_counter()
        if mode == "baseTree":
            secs, errs = a.build_section_tree(f)
            dt = time.perf_counter() - t0
            objs, total = count(secs)
            res = {"mode": mode, "s": round(dt, 3), "objects": objs, "sections": total, "errors": errs[:2]}
        else:
            data = a.parse_a2l_file(f)
            dt = time.perf_counter() - t0
            res = {"mode": mode, "s": round(dt, 3), "tags": len(data["tags"]), "errors": data["errors"][:2]}
        res["file"] = a.__file__
    else:
        t0 = time.perf_counter()
        secs, errs = build(f, keep_words=(mode == "candW"))
        dt = time.perf_counter() - t0
        objs, total = count(secs)
        res = {"mode": mode, "s": round(dt, 3), "objects": objs, "sections": total, "errors": errs[:2]}
    res["maxrss_mb"] = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1)
    return res


def drive(repo: Path, runs: int) -> int:
    files = [repo / "examples/case_06_large_nested_a2l/firmware.a2l", repo / "examples/case_00_public/software_a.a2l"]
    modes = ("baseTree", "baseFull", "candL", "candW")
    print(f"python {sys.version.split()[0]}; runs per mode {runs}; interleaved {', '.join(modes)}; one process per run")
    for f in files:
        rows: dict = {m: [] for m in modes}
        for r in range(runs):
            for mode in modes:
                cp = subprocess.run([sys.executable, "-I", __file__, mode, str(repo), str(f)],
                                    capture_output=True, text=True, timeout=600, stdin=subprocess.DEVNULL)
                line = cp.stdout.strip().splitlines()[-1] if cp.stdout.strip() else "{}"
                d = json.loads(line)
                rows[mode].append(d)
                print(f"[run {r + 1}] {f.name} {json.dumps(d)}" + (f" STDERR {cp.stderr[-300:]}" if cp.returncode else ""))
        med = {m: statistics.median(x["s"] for x in v) for m, v in rows.items()}
        rss = {m: statistics.median(x["maxrss_mb"] for x in v) for m, v in rows.items()}
        rest = med["baseFull"] - med["baseTree"]
        print(f"[median s] {f.name}: " + ", ".join(f"{m} {med[m]}" for m in modes) + f"; base rest (full - tree) {rest:.3f}")
        for m in ("candL", "candW"):
            proj = med[m] + rest
            print(f"[projection] {f.name} {m}: tree + base rest = {proj:.3f} s = {proj / med['baseFull']:.2f} x base parse "
                  f"(bound 1.50); tree alone = {med[m] / med['baseTree']:.2f} x base tree")
        print(f"[maxrss median MB] {f.name}: " + ", ".join(f"{m} {rss[m]}" for m in modes))
    return 0


if __name__ == "__main__":
    if sys.argv[1] == "drive":
        raise SystemExit(drive(Path(sys.argv[2]), int(sys.argv[3])))
    print(json.dumps(one(sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3]))))
