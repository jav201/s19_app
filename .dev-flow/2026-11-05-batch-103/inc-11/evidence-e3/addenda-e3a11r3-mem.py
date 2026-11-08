"""Inc 11 E3 addenda (batch-103), E3S-28: peak memory of the corrected reader design against e07fb00 (R-A2L-READ.52's
memory clause, 2x). NOT product code and NOT a stub: a throwaway stdlib model of the graph's line-driven lexer and
builder (`_lex_a2l_lines`, `_build_section_tree_into`) and of the tag front with the round-3 streaming change
(`_section_words` and `_line_words` yield; `_tag_header` and `_tag_keyword_lines` consume one word stream; each
keyword item carries at most arity argument words, 4 for MATRIX_DIM, and the first surplus word; the per-tag checks run
inside that one pass, E3A-23). The tag dicts (29 keys) and the downstream tables come from e07fb00's own readers run on
the candidate's canonical tree (DE-3), so the held tag list is the base's.

Modes (one fresh process each; RSS = ru_maxrss of this process, MB; baseline = after the imports, before the read):
  gen-multi <out>   E3S-28's file: one MEASUREMENT whose own words fill 600,000 lines (19,800,291 bytes)
  gen-line <out>    the same words on ONE body line of that MEASUREMENT (the per-line hold)
  gen-string <out>  R-A2L-READ.52/3's file: one quoted string over 200,000 lines (E3S-14)
  base <file>       e07fb00 parse_a2l_file
  design <file>     the corrected design (streaming tag front)
  design-list <file>  the same with `_section_words` materialised as a list per tag section (the round-2 design)
  drive <runs> <file>...  interleave base, design, design-list per file; medians; ratios
Every A2L text written here is synthetic; a corpus file is only opened for reading.
"""
from __future__ import annotations

import json
import os
import re
import resource
import statistics
import subprocess
import sys
import time
from itertools import chain
from pathlib import Path

RH = os.environ.get("B103_RUNNER_HOME", "")
CLONE = RH + "/work/s19_app"


def rss_mb() -> float:
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024


# ------------------------------------------------------------------ generators (synthetic)
HDR_HEAD = ('ASAP2_VERSION 1 71\n/begin PROJECT P ""\n/begin MODULE M ""\n/begin MOD_COMMON ""\nBYTE_ORDER MSB_FIRST\n'
            '/end MOD_COMMON\n/begin COMPU_METHOD CM_ID "" IDENTICAL "%.0" ""\n/end COMPU_METHOD\n')
HDR_TAIL = "/end MODULE\n/end PROJECT\n"
ROW = " ab1 ab2 ab3 ab4 ab5 ab6 ab7 ab8"


def gen(mode: str, out: str) -> None:
    with open(out, "w", encoding="ascii", newline="\n") as fh:
        if mode == "gen-string":
            body = "\n".join(f"line {k} of one synthetic quoted string" for k in range(1, 200001))
            fh.write('ASAP2_VERSION 1 71\n/begin PROJECT P ""\n/begin MODULE M ""\n/begin MEASUREMENT X ""\n'
                     " UWORD CM_ID 0 0 0 65535\n ECU_ADDRESS 0x1234\n /begin ANNOTATION\n  /begin ANNOTATION_TEXT\n"
                     '   "' + body + '"\n  /end ANNOTATION_TEXT\n /end ANNOTATION\n/end MEASUREMENT\n/end MODULE\n'
                     "/end PROJECT\n")
        else:
            fh.write(HDR_HEAD + '/begin MEASUREMENT BIG ""\nUWORD CM_ID 0 0 0 65535\nECU_ADDRESS 0x10\n')
            for _ in range(600000):
                fh.write(ROW + ("\n" if mode == "gen-multi" else ""))
            fh.write(("" if mode == "gen-multi" else "\n") + "/end MEASUREMENT\n" + HDR_TAIL)
    print(json.dumps({"gen": mode, "bytes": os.path.getsize(out)}))


# ------------------------------------------------------------------ the candidate lexer, line-driven (DE-1, DE-2)
_WORD = re.compile(r'(?:[^ \t\x0b\x0c"/]|/(?![/*]))+')
_SKIP = re.compile(r"[ \t\x0b\x0c]*")


def _bad(w: str):
    for c in w:
        if not ("!" <= c <= "~"):
            return c
    return None


class Acc:
    """The words of one item, joined in blocks of 4,096 so no per-word list outlives a block."""
    __slots__ = ("cur", "blocks", "line")

    def __init__(self, line: int):
        self.cur: list = []
        self.blocks: list = []
        self.line = line

    def add(self, w: str) -> None:
        self.cur.append(w)
        if len(self.cur) >= 4096:
            self.blocks.append(" ".join(self.cur))
            self.cur = []

    def text(self) -> str:
        if self.cur:
            self.blocks.append(" ".join(self.cur))
            self.cur = []
        return self.blocks[0] if len(self.blocks) == 1 else " ".join(self.blocks)

    def empty(self) -> bool:
        return not self.cur and not self.blocks


class Capped:
    def __init__(self):
        self.texts: list = []
        self.dropped = 0

    def append(self, t: str) -> None:
        if len(self.texts) < 100:
            self.texts.append(t)
        else:
            self.dropped += 1

    def reset(self, t: str) -> None:
        self.texts = [t]
        self.dropped = 0

    def as_list(self) -> list:
        return self.texts + ([f"... {self.dropped} more parse errors"] if self.dropped else [])


def lex_lines(handle, errors: Capped):
    """Yield (line, canonical text) per line holding words; nothing held but the line, an open item and an open
    string's parts."""
    comment_line = 0          # > 0 while a block comment is open
    sparts = None             # an open string's parts
    item = None               # the open item (words starting on item.line)
    for ln, raw in enumerate(handle, 1):
        body = raw[:-1] if raw.endswith("\n") else raw
        if not comment_line and sparts is None:
            s = body.strip(" ")
            if not s:
                continue
            if ('"' not in s and "/" not in s and "  " not in s and s.isascii() and s.isprintable()):
                yield ln, s                            # tier 1
                continue
            if "\x00" in s:
                errors.reset("File is not UTF-8 text; save it as UTF-8 and load it again.")
                return
        elif "\x00" in body:
            errors.reset("File is not UTF-8 text; save it as UTF-8 and load it again.")
            return
        i, n = 0, len(body)
        while i < n:
            if comment_line:
                j = body.find("*/", i)
                if j < 0:
                    i = n
                    break
                comment_line = 0
                i = j + 2
                continue
            if sparts is not None:                     # an open string: str.find plus a backslash count (E3A-18)
                j = body.find('"', i)
                while j >= 0:
                    k = j - 1
                    bs = 0
                    while k >= i and body[k] == "\\":
                        bs += 1
                        k -= 1
                    if bs % 2 == 0:
                        break
                    j = body.find('"', j + 1)
                if j < 0:
                    sparts.append(body[i:])
                    sparts.append("\n")
                    i = n
                    break
                sparts.append(body[i:j + 1])
                item.add("".join(sparts))
                sparts = None
                i = j + 1
                if item.line != ln:                    # E3S-25: words after the closing quote are their own item
                    yield item.line, item.text()
                    item = None
                continue
            m = _SKIP.match(body, i)
            i = m.end()
            if i >= n:
                break
            c = body[i]
            if c == "/" and body.startswith("/*", i):
                comment_line = ln
                i += 2
                continue
            if c == "/" and body.startswith("//", i):
                break
            if c == '"':
                if item is None:
                    item = Acc(ln)
                sparts = ['"']
                i += 1
                continue
            m = _WORD.match(body, i)
            w = m.group()
            i = m.end()
            if item is None:
                item = Acc(ln)
            if "*/" in w:
                errors.append(f"Line {ln}: */ without /*")
            if not (w.isascii() and w.isprintable()):
                b = _bad(w)
                if b is not None:
                    errors.append(f"Line {ln}: unexpected character U+{ord(b):04X}")
            item.add(w)
        if sparts is None and item is not None:
            yield item.line, item.text()
            item = None
    if comment_line:
        errors.append(f"Line {comment_line}: comment not closed")
    if sparts is not None:
        errors.append(f"Line {item.line}: quoted string not closed")
    if item is not None and not item.empty():
        yield item.line, item.text()


_CANON = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"|[^ "]+', re.S)   # unrolled: no per-character alternation
_RUN = re.compile(r"[^ ]+")


def iter_words(c: str):
    """`_line_words` as a generator (round 3): no per-line word list."""
    pat = _RUN if '"' not in c else _CANON
    for m in pat.finditer(c):
        yield m.group()


NAMED = {"AXIS_PTS", "BLOB", "CHARACTERISTIC", "COMPU_METHOD", "COMPU_TAB", "COMPU_VTAB", "COMPU_VTAB_RANGE", "FRAME",
         "FUNCTION", "GROUP", "INSTANCE", "MEASUREMENT", "MEMORY_SEGMENT", "MODULE", "PROJECT", "RECORD_LAYOUT",
         "TRANSFORMER", "UNIT"}


def _named(k: str) -> int:
    return 1 if (k in NAMED or k.startswith("TYPEDEF_")) else 0


def _new(k: str, ln: int) -> dict:
    return {"name": k, "meta": "", "meta_line": ln, "start_line": ln, "lines": [], "line_numbers": [], "children": [],
            "_open": True, "_named": _named(k)}


def _put(sec: dict, ln: int, c: str) -> None:
    if sec["meta_line"] == ln and sec["_open"]:
        sec["meta"] = c if not sec["meta"] else sec["meta"] + " " + c
        sec["_named"] = 0
        return
    sec["_open"] = False
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


def _close(sec: dict, ln: int) -> None:
    sec["end_line"] = ln
    sec.pop("_open", None)
    sec.pop("_named", None)


def build(path: Path, errors: Capped):
    roots: list = []
    stack: list = []
    want = None
    with path.open("r", encoding="utf-8-sig", errors="replace") as fh:
        head = fh.buffer.peek(2)[:2] if hasattr(fh.buffer, "peek") else b""
        if head in (b"\xff\xfe", b"\xfe\xff"):
            errors.reset("File is UTF-16 encoded; save it as UTF-8 and load it again.")
            return []
        for ln, c in lex_lines(fh, errors):
            if want is None and stack and "/" not in c:
                _put(stack[-1], ln, c)
                continue
            if want is None and "/" not in c:
                continue
            run = None
            words = iter_words(c)
            for w in words:
                if want is not None:
                    want["name"] = w
                    want["meta_line"] = ln
                    want["_named"] = _named(w)
                    want = None
                    continue
                lw = w.lower() if w[:1] == "/" else ""
                if lw in ("/begin", "/end"):
                    if run is not None and stack:
                        _put(stack[-1], ln, run.text())
                    run = None
                    if lw == "/begin":
                        if len(stack) >= 32:
                            errors.reset(f"Line {ln}: sections nested deeper than 32")
                            return []
                        entry = _new("UNKNOWN", ln)
                        (stack[-1]["children"] if stack else roots).append(entry)
                        if stack:
                            stack[-1]["lines"].append("")
                            stack[-1]["line_numbers"].append(ln)
                            stack[-1]["_open"] = False
                        stack.append(entry)
                        want = entry
                        continue
                    nm = next(words, None)
                    if stack:
                        top = stack.pop()
                        _close(top, ln)
                        if nm is not None and nm != top["name"]:
                            errors.append(f"Line {ln}: /end {nm[:64]} does not close /begin {top['name']}")
                    else:
                        errors.append(f"Line {ln}: /end without /begin")
                    continue
                if lw == "/include":
                    errors.append(f"Line {ln}: /include is not read")
                if run is None:
                    run = Acc(ln)
                run.add(w)
            if run is not None and stack:
                _put(stack[-1], ln, run.text())
    if stack:
        errors.append("Unclosed /begin sections detected.")
    return roots


# ------------------------------------------------------------------ the tag front (round 3: one word stream)
ARITY = {
    "ADDRESS_TYPE": 1, "ARRAY_SIZE": 1, "BIT_MASK": 1, "BYTE_ORDER": 1, "CALIBRATION_ACCESS": 1,
    "COMPARISON_QUANTITY": 1, "DISCRETE": 0, "DISPLAY_IDENTIFIER": 1, "ECU_ADDRESS": 1, "ECU_ADDRESS_EXTENSION": 1,
    "ENCODING": 1, "ERROR_MASK": 1, "EXTENDED_LIMITS": 2, "FORMAT": 1, "GUARD_RAILS": 0, "LAYOUT": 1,
    "MATRIX_DIM": -1, "MAX_REFRESH": 2, "MODEL_LINK": 1, "NUMBER": 1, "PHYS_UNIT": 1, "READ_ONLY": 0,
    "READ_WRITE": 0, "REF_MEMORY_SEGMENT": 1, "STEP_SIZE": 1, "SYMBOL_LINK": 2, "DATA_SIZE": 1, "LENGTH": 1,
    "DATA_TYPE": 1, "FUNCTION": 1, "COMPU_METHOD": 1, "FORMULA": 1, "UNIT": 1, "LOWER_LIMIT": 1, "UPPER_LIMIT": 1,
    "VIRTUAL": 0, "CALIBRATABLE": 0, "DEPOSIT": 1,
}
SURPLUS_KW = {"ECU_ADDRESS", "DATA_SIZE", "LENGTH", "NUMBER", "ARRAY_SIZE", "BIT_MASK"}
HDR = {"MEASUREMENT": 6, "CHARACTERISTIC": 7}
ORDERS = {"MSB_FIRST", "MSB_LAST", "BIG_ENDIAN", "LITTLE_ENDIAN"}
DTS = {"UBYTE": 1, "SBYTE": 1, "UWORD": 2, "SWORD": 2, "ULONG": 4, "SLONG": 4, "A_UINT64": 8, "A_INT64": 8,
       "FLOAT16_IEEE": 2, "FLOAT32_IEEE": 4, "FLOAT64_IEEE": 8}
_NUM = re.compile(r"0[xX][0-9A-Fa-f]{1,16}|[0-9]{1,20}")
_HEXLIKE = re.compile(r"[0-9A-Fa-f_]+|[0-9].*", re.S)


def number_word(w: str):
    if w.isascii() and _NUM.fullmatch(w):
        return int(w, 16) if w[:2] in ("0x", "0X") else int(w, 10)
    return None


def hexlike(w: str) -> bool:
    """Round 3 (E3S-24): a number word, a word starting with a decimal digit, or one made only of hex digits and _."""
    return w[:1] != '"' and w.isascii() and _HEXLIKE.fullmatch(w) is not None


def section_words(sec: dict):
    """`_section_words` as a generator (round 3)."""
    if sec["meta"]:
        ml = sec.get("meta_line", sec["start_line"])
        for w in iter_words(sec["meta"]):
            yield w, ml
    for text, ln in zip(sec["lines"], sec["line_numbers"]):
        if text == "":
            yield "", ln
        else:
            for w in iter_words(text):
                yield w, ln


def front_one(kind: str, sec: dict, errors: Capped, as_list: bool):
    words = section_words(sec)
    held = 0
    if as_list:                                   # the round-2 design (negative control)
        words = list(words)
        held = len(words)
        words = iter(words)
    first = next(words, None)
    name, lid, header = "UNKNOWN", None, []
    pending = None
    if first is not None and first[0] != "":
        name = first[0].strip('"')
        nxt = next(words, None)
        if nxt is not None and nxt[0][:1] == '"':
            lid = nxt[0][1:-1] or None
            nxt = next(words, None)
        while nxt is not None and len(header) < HDR[kind]:
            w = nxt[0]
            if w == "" or (w[:1] != '"' and w in ARITY):
                break
            header.append(w)
            nxt = next(words, None)
        pending = nxt
    elif first is not None:
        pending = first
    # one keyword pass with the per-tag checks inside it (E3A-23)
    items: list = []
    seen: dict = {}
    addrs: list = []
    sizes: list = []
    no_number = False
    no_address = False
    kw = None
    args: list = []
    surplus = 0
    surplus_word = None
    kw_line = 0

    def close():
        nonlocal no_number, no_address
        if kw is None:
            return
        k = ARITY[kw]
        if (k < 0 and not (1 <= len(args) <= 3)) or (k >= 0 and len(args) < k) or surplus:
            errors.append(f"Line {kw_line}: {kw} has {len(args) + surplus} of its {'1 to 3' if k < 0 else k} arguments")
            if kw in ("ECU_ADDRESS", "BIT_MASK", "BYTE_ORDER"):
                no_address = True
            if kw in ("DATA_SIZE", "LENGTH", "NUMBER", "ARRAY_SIZE", "MATRIX_DIM"):
                no_number = True
        text = " ".join([kw] + args + ([surplus_word] if surplus_word is not None else []))
        if kw in seen and seen[kw] != text:
            if kw in ("BIT_MASK", "BYTE_ORDER"):
                no_address = True
        if kw in seen:
            errors.append(f"Line {kw_line}: {kw} is declared twice")
        seen[kw] = text
        if kw == "BYTE_ORDER" and args and args[0].upper() not in ORDERS:
            errors.append(f"Line {kw_line}: BYTE_ORDER {args[0][:64]} is not a byte order")
            no_address = True
        if kw == "ECU_ADDRESS" and len(args) == 1 and not surplus:
            v = number_word(args[0])
            if v is None:
                no_address = True
                errors.append(f"Line {kw_line}: ECU_ADDRESS {args[0][:64]} is not a number")
            else:
                addrs.append(v)
        elif kw in ("DATA_SIZE", "LENGTH", "NUMBER", "ARRAY_SIZE") and len(args) == 1 and not surplus:
            v = number_word(args[0])
            if v is None:
                no_number = True
            else:
                sizes.append((kw, v))
        items.append((text, kw_line))

    it = chain([pending], words) if pending is not None else words
    for w, ln in it:
        if w == "":
            close()
            kw = None
            continue
        if w[:1] != '"' and w in ARITY:
            close()
            kw, args, surplus, surplus_word, kw_line = w, [], 0, None, ln
            continue
        if kw is None:
            continue
        lim = 4 if ARITY[kw] < 0 else ARITY[kw]
        if len(args) < lim:
            args.append(w)
        elif kw in SURPLUS_KW and hexlike(w):
            surplus += 1
            if surplus_word is None:
                surplus_word = w
    close()
    if len(set(addrs)) > 1:
        no_address = True
    el = DTS.get(header[0]) if kind == "MEASUREMENT" and header else None
    b = [v if k in ("DATA_SIZE", "LENGTH") else v * (el or 1) for k, v in sizes]
    agree = len(set(b)) <= 1
    return {"name": name, "lid": lid, "header": header, "items": items, "no_address": no_address,
            "no_length": no_number or not agree, "held_words": held}


def front(A, secs: list, errors: Capped, as_list: bool, rl: dict, cm: dict):
    """The design's extract_a2l_tags: per tag section, the one word stream gives the name, the header and the keyword
    texts; e07fb00's own field rules then build the 29-key tag dict from those texts (DE-4), so the held tag list is
    the base's and no section's words are held."""
    stack = list(secs)
    tags: list = []
    n = held = items = no_addr = 0
    while stack:
        s = stack.pop()
        stack.extend(s["children"])
        if s["name"] in HDR:
            r = front_one(s["name"], s, errors, as_list)
            n += 1
            held = max(held, r["held_words"])
            items = max(items, len(r["items"]))
            no_addr += r["no_address"]
            meta = r["name"] + (' "' + r["lid"] + '"' if r["lid"] else "")
            shadow = {"name": s["name"], "meta": meta, "start_line": s["start_line"], "end_line": s.get("end_line"),
                      "lines": [" ".join(r["header"])] + [t for t, _ in r["items"]], "children": s["children"]}
            tags.extend(A.extract_a2l_tags([shadow], record_layouts_by_name=rl, compu_methods_by_name=cm))
    return tags, n, held, items, no_addr


# ------------------------------------------------------------------ one measurement
def one(mode: str, f: Path) -> dict:
    sys.path.insert(0, CLONE)
    from s19_app.tui import a2l as A  # noqa: E402  (the read-only e07fb00 clone)
    assert A.__file__.startswith(CLONE + "/")
    base_mb = rss_mb()
    t0 = time.perf_counter()
    res = {"mode": mode, "file": f.name, "bytes": f.stat().st_size}
    if mode == "base":
        d = A.parse_a2l_file(f)
        res.update(tags=len(d["tags"]), errors=len(d["errors"]))
    else:
        errors = Capped()
        secs = build(f, errors)
        tree_mb = rss_mb()
        t1 = time.perf_counter()
        rl = A.extract_record_layouts(secs)
        cm = A.extract_compu_methods(secs)
        A.extract_compu_tables(secs)
        t1 = time.perf_counter()
        tags, n, held, items, no_addr = front(A, secs, errors, mode == "design-list", rl, cm)
        front_s = time.perf_counter() - t1
        front_mb = rss_mb()
        A.extract_memory_segments(secs)
        res.update(tags=len(tags), tag_sections=n, errors=len(errors.as_list()), first_errors=errors.as_list()[:2],
                   held_words=held, max_items=items, no_address=no_addr, tree_mb=round(tree_mb, 1),
                   after_front_mb=round(front_mb, 1), front_s=round(front_s, 3))
    res["s"] = round(time.perf_counter() - t0, 3)
    peak = rss_mb()
    res.update(baseline_mb=round(base_mb, 1), peak_mb=round(peak, 1), net_mb=round(peak - base_mb, 1))
    return res


def drive(runs: int, files: list) -> int:
    modes = ("base", "design", "design-list")
    print(f"python {sys.version.split()[0]}; {runs} runs per mode, interleaved {', '.join(modes)}; one process per run")
    for f in files:
        rows = {m: [] for m in modes}
        for r in range(runs):
            for m in modes:
                cp = subprocess.run([sys.executable, "-I", __file__, m, f], capture_output=True, text=True,
                                    timeout=1800, stdin=subprocess.DEVNULL)
                out = cp.stdout.strip().splitlines()
                d = json.loads(out[-1]) if out else {"mode": m, "peak_mb": float("nan"), "net_mb": float("nan"),
                                                     "s": float("nan"), "rc": cp.returncode}
                rows[m].append(d)
                print(f"[run {r + 1}] {json.dumps(d)}" + (f" STDERR {cp.stderr[-400:]!r}" if cp.returncode else ""),
                      flush=True)
        med = {m: {k: statistics.median(x[k] for x in rows[m]) for k in ("peak_mb", "net_mb", "s")} for m in modes}
        b = med["base"]
        line = f"[median] {Path(f).name}: " + "; ".join(
            f"{m} peak {med[m]['peak_mb']:.1f} MB net {med[m]['net_mb']:.1f} MB {med[m]['s']:.2f} s" for m in modes)
        print(line)
        for m in ("design", "design-list"):
            print(f"[ratio] {Path(f).name} {m}: peak {med[m]['peak_mb'] / b['peak_mb']:.2f}x base "
                  f"(bound 2.00 -> {'within' if med[m]['peak_mb'] <= 2 * b['peak_mb'] else 'OVER'}); "
                  f"net {med[m]['net_mb'] / b['net_mb']:.2f}x base net", flush=True)
    return 0


if __name__ == "__main__":
    a = sys.argv[1]
    if a.startswith("gen-"):
        gen(a, sys.argv[2])
    elif a == "drive":
        raise SystemExit(drive(int(sys.argv[2]), sys.argv[3:]))
    else:
        print(json.dumps(one(a, Path(sys.argv[2]))))
