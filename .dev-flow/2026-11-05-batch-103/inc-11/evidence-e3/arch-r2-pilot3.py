"""Inc 11 E3 architect round 2: pilot2 (E2's lexer + builder model, unchanged otherwise) with the E3 correction's
per-line and per-section rules added, to time what the correction adds (R-A2L-READ.52). Added, as the graph writes them:
  - tier 1 only for a printable-ASCII line (isascii and isprintable); every other line goes to tier 2/3, which tests
    for U+0000 first (READ.55: the reading ends, errors reset to one text);
  - the named-kind rule (DE-3 revised, READ.54): a named kind whose keyword line holds no own word takes its first
    run as meta, and the next run when the first is the name alone and the next starts with a quote;
  - the nesting cap (READ.64): a /begin that would open a 33rd level ends the reading with one error;
  - errors through a capped list (READ.56): 100 texts, then a count.
NOT product code and NOT a stub: a throwaway feasibility model; the candidate path imports nothing from s19_app.
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

_BLANKS = " \t\x0b\x0c"
_MEDIUM = re.compile(r'"(?:[^"\\\n]|\\.)*"|[^ \t\x0b\x0c"]+')   # quoted string | run of word characters
_CANON = re.compile(r'"(?:[^"\\]|\\.)*"|[^ "]+', re.S)           # split one canonical line into its words
TOK = re.compile(
    r'[ \t\x0b\x0c]*(?:'
    r'(\n)'
    r'|("(?:[^"\\]|\\.)*")'
    r'|(/\*.*?\*/)'
    r'|(//[^\n]*)'
    r'|((?:[^ \t\x0b\x0c\n"/]|/(?![/*]))+)'
    r'|(/\*|")'
    r'|$)',
    re.S,
)


NUL_STOP = [False]
NAMED = {"AXIS_PTS", "BLOB", "CHARACTERISTIC", "COMPU_METHOD", "COMPU_TAB", "COMPU_VTAB", "COMPU_VTAB_RANGE", "FRAME",
         "FUNCTION", "GROUP", "INSTANCE", "MEASUREMENT", "MEMORY_SEGMENT", "MODULE", "PROJECT", "RECORD_LAYOUT",
         "TRANSFORMER", "UNIT"}


class Capped(list):
    def __init__(self):
        super().__init__()
        self.dropped = 0

    def append(self, x):
        if len(self) < 100:
            super().append(x)
        else:
            self.dropped += 1


def _bad_char(word: str):
    for c in word:
        if not ("!" <= c <= "~"):
            return c
    return None


def lex_lines(text: str, errors: list):
    if text.startswith("\ufeff"):
        text = text[1:]
    if "\r" in text:
        text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = text.split("\n")
    n = len(lines)
    i = 0
    pos = 0
    while i < n:
        raw = lines[i]
        s = raw.strip(_BLANKS)
        if not s:
            pos += len(raw) + 1
            i += 1
            continue
        if '"' not in s and "/" not in s and "  " not in s and "\t" not in s and "\x0b" not in s and "\x0c" not in s and s.isascii() and s.isprintable():
            yield i + 1, s
            pos += len(raw) + 1
            i += 1
            continue
        if "\x00" in s:
            errors.clear()
            errors.append("File is not UTF-8 text; save it as UTF-8 and load it again.")
            NUL_STOP[0] = True
            return
        if "/*" not in s and "//" not in s and "*/" not in s and "\\" not in s and s.count('"') % 2 == 0:
            words = _MEDIUM.findall(s)
            if not s.isascii() or not s.isprintable():
                for w in words:
                    if w[0] != '"':
                        b = _bad_char(w)
                        if b is not None:
                            errors.append(f"Line {i + 1}: unexpected character U+{ord(b):04X}")
                            break
            yield i + 1, " ".join(words)
            pos += len(raw) + 1
            i += 1
            continue
        # full path: token regex from this line's start; a string or a block comment may run over line ends
        ln = i + 1
        cur: list = []
        cur_ln = ln
        p = pos
        while True:
            m = TOK.match(text, p)
            if m is None or (m.end() == p and m.lastindex is None):
                if cur:
                    yield cur_ln, " ".join(cur)
                return
            p = m.end()
            g = m.lastindex
            if g == 1:
                if cur:
                    yield cur_ln, " ".join(cur)
                i = ln
                pos = p
                break
            if g == 2:
                if not cur:
                    cur_ln = ln
                cur.append(m.group(2))
                ln += m.group(2).count("\n")
            elif g == 3:
                ln += m.group(3).count("\n")
            elif g == 5:
                w = m.group(5)
                if not cur:
                    cur_ln = ln
                if "*/" in w:
                    errors.append(f"Line {ln}: */ without /*")
                b = _bad_char(w)
                if b is not None:
                    errors.append(f"Line {ln}: unexpected character U+{ord(b):04X}")
                cur.append(w)
            elif g == 6:
                errors.append(f"Line {ln}: " + ("comment not closed" if m.group(6) == "/*" else "quoted string not closed"))
                if cur:
                    yield cur_ln, " ".join(cur)
                return


def line_words(c: str) -> list:
    return c.split(" ") if '"' not in c else _CANON.findall(c)


def build(path: Path):
    text = path.read_bytes().decode("utf-8", errors="replace")
    errors: list = Capped()
    roots: list = []
    stack: list = []
    top = None          # stack[-1]
    want_kw = None      # a /begin whose keyword is on a later line
    for ln, c in lex_lines(text, errors):
        if want_kw is None and top is not None and ("/" not in c or not _struct(c)):
            if top["_kw_line"] == ln and top["_meta_open"]:
                top["meta"] = c if not top["meta"] else top["meta"] + " " + c
            else:
                top["_meta_open"] = False
                nm = top["_named"]
                if nm:
                    if nm == 1 and not top["meta"]:
                        top["meta"] = c
                        top["meta_line"] = ln
                        top["_named"] = 2 if " " not in c else 0
                        continue
                    top["_named"] = 0
                    if nm == 2 and c[:1] == '"':
                        top["meta"] += " " + c
                        continue
                top["lines"].append(c)
                top["line_numbers"].append(ln)
            continue
        words = line_words(c)
        # the common /begin KW rest... and /end KW lines, without a word loop
        w0 = words[0].lower()
        if want_kw is None and w0 == "/begin" and len(words) >= 2 and not any(w[:1] == "/" for w in words[2:]):
            if len(stack) >= 32:
                errors.clear()
                errors.append(f"Line {ln}: sections nested deeper than 32")
                return [], errors
            k1 = words[1]
            entry = {"name": k1, "meta": " ".join(words[2:]), "start_line": ln, "lines": [], "children": [],
                     "line_numbers": [], "_kw_line": ln, "_meta_open": True,
                     "_named": 1 if (len(words) == 2 and (k1 in NAMED or k1.startswith("TYPEDEF_"))) else 0}
            (top["children"] if top is not None else roots).append(entry)
            stack.append(entry)
            top = entry
            continue
        if want_kw is None and w0 == "/end" and len(words) == 2:
            if top is not None:
                top["end_line"] = ln
                if words[1] != top["name"]:
                    errors.append(f"Line {ln}: /end {words[1]} does not close /begin {top['name']}")
                stack.pop()
                top = stack[-1] if stack else None
            else:
                errors.append(f"Line {ln}: /end without /begin")
            continue
        # general word loop (rare)
        run: list = []
        k = 0
        while k < len(words):
            w = words[k]
            lw = w.lower() if w[:1] == "/" else ""
            if want_kw is not None:
                want_kw["name"] = w
                want_kw["_kw_line"] = ln
                want_kw["_named"] = 1 if (w in NAMED or w.startswith("TYPEDEF_")) else 0
                want_kw = None
                k += 1
                continue
            if lw in ("/begin", "/end"):
                if run and top is not None:
                    _put(top, ln, " ".join(run))
                run = []
                if lw == "/begin":
                    if len(stack) >= 32:
                        errors.clear()
                        errors.append(f"Line {ln}: sections nested deeper than 32")
                        return [], errors
                    entry = {"name": "UNKNOWN", "meta": "", "start_line": ln, "lines": [], "children": [],
                             "line_numbers": [], "_kw_line": ln, "_meta_open": True, "_named": 0}
                    (top["children"] if top is not None else roots).append(entry)
                    stack.append(entry)
                    top = entry
                    want_kw = entry
                    k += 1
                    continue
                nm = words[k + 1] if k + 1 < len(words) else None
                if top is not None:
                    top["end_line"] = ln
                    if nm is not None and nm != top["name"]:
                        errors.append(f"Line {ln}: /end {nm} does not close /begin {top['name']}")
                    stack.pop()
                    top = stack[-1] if stack else None
                else:
                    errors.append(f"Line {ln}: /end without /begin")
                k += 2
                continue
            if lw == "/include":
                errors.append(f"Line {ln}: /include {words[k + 1].strip(chr(34)) if k + 1 < len(words) else ''} is not read")
            run.append(w)
            k += 1
        if run and top is not None:
            _put(top, ln, " ".join(run))
    if stack:
        errors.append("Unclosed /begin sections detected.")
    return roots, errors


def _put(sec, ln, c):
    if sec["_kw_line"] == ln and sec["_meta_open"]:
        sec["meta"] = c if not sec["meta"] else sec["meta"] + " " + c
        sec["_named"] = 0
    else:
        sec["_meta_open"] = False
        nm = sec["_named"]
        if nm:
            if nm == 1 and not sec["meta"]:
                sec["meta"] = c
                sec["meta_line"] = ln
                sec["_named"] = 2 if " " not in c else 0
                return
            sec["_named"] = 0
            if nm == 2 and c[:1] == '"':
                sec["meta"] += " " + c
                return
        sec["lines"].append(c)
        sec["line_numbers"].append(ln)


def _struct(c: str) -> bool:
    cl = c.lower()
    return "/begin" in cl or "/end" in cl or "/include" in cl


def count(secs, names=("MEASUREMENT", "CHARACTERISTIC")):
    c = total = 0
    stack = list(secs)
    while stack:
        s = stack.pop()
        total += 1
        c += s["name"] in names
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
        secs, errs = build(f)
        dt = time.perf_counter() - t0
        objs, total = count(secs)
        res = {"mode": mode, "s": round(dt, 3), "objects": objs, "sections": total, "errors": errs[:2]}
    res["maxrss_mb"] = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1)
    return res


def drive(repo: Path, runs: int) -> int:
    files = [repo / "examples/case_06_large_nested_a2l/firmware.a2l", repo / "examples/case_00_public/software_a.a2l"]
    modes = ("baseTree", "baseFull", "cand")
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
        proj = med["cand"] + rest
        print(f"[median s] {f.name}: " + ", ".join(f"{m} {med[m]}" for m in modes) + f"; base rest (full - tree) {rest:.3f}")
        print(f"[projection] {f.name}: cand tree + base rest = {proj:.3f} s = {proj / med['baseFull']:.2f} x base parse "
              f"(bound 1.50); cand tree alone = {med['cand'] / med['baseTree']:.2f} x base tree; "
              f"budget left for the new tag walk at 1.50x: {1.5 * med['baseFull'] - med['cand']:.3f} s (base rest {rest:.3f} s)")
        print(f"[maxrss median MB] {f.name}: " + ", ".join(f"{m} {rss[m]}" for m in modes))
    return 0


def shapes() -> int:
    """The lexer's contract examples, as the graph writes them (synthetic shapes only)."""
    cases = [
        ("READ.7/1", 'MAP 0x1C2D3E00/*c*/4026 RL 0 CM 0 1'),
        ("READ.7/2", 'MAP 0x1C2D3E00/* old\n */4026 RL'),
        ("READ.2/2", 'ECU_ADDRESS\t0x1234\nECU_ADDRESS\x0b0x1234\nECU_ADDRESS\x0c0x1234'),
        ("READ.3/1", 'ECU_ADDRESS 0x1234\u00a0\nECU_ADDRESS 0x1234\u2028'),
        ("READ.1/4", 'A\r\r\nB\r\nC\rD'),
        ("001.3.2/1", '/begin CHARACTERISTIC X "C:\\\\"\n VALUE 0x2000'),
        ("001.3.2/2", '"a\\"b" X'),
        ("READ.14/1", 'A "x\n/end ANNOTATION_TEXT\ny" BIT_MASK 0x0FF0'),
        ("READ.16/1", '/begin MEASUREMENT X"long"'),
        ("READ.8/2", '/* a /* b */ c */ ECU_ADDRESS 0x1234'),
        ("READ.9/3", '// c\rECU_ADDRESS 0x1234'),
        ("READ.10/1", 'A\n/* never closed\nECU_ADDRESS 0x1234'),
        ("READ.15/1", 'A\nFORMAT "%5.0\nB'),
        ("READ.13/1", 'FORMAT "/* x" ECU_ADDRESS 0x1234'),
        ("BOM", '\ufeffASAP2_VERSION 1 71'),
    ]
    for key, text in cases:
        errs: list = []
        out = list(lex_lines(text, errs))
        print(f"[{key}] {text!r} -> {out!r} errors={errs!r}")
    return 0


if __name__ == "__main__":
    if sys.argv[1] == "drive":
        raise SystemExit(drive(Path(sys.argv[2]), int(sys.argv[3])))
    if sys.argv[1] == "shapes":
        raise SystemExit(shapes())
    print(json.dumps(one(sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3]))))
