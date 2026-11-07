"""Inc 11 E3 architect (batch-103): re-measure the E2 timing pilot (R-A2L-READ.52) and model the new tag walk.

The E2 pilot 2 (i11e2-pilot-time2.py, copied beside this script as pilot2.py, unchanged) timed only the new lexer +
section builder ("cand") and projected the parse as cand tree + (base parse - base tree), i.e. it assumed the new tag
walk costs exactly what the base tag walk costs. This script re-runs the three modes on the files given and adds two:

  baseFront  the base tree, then the part of the base tag walk the graph replaces, timed alone, over every MEASUREMENT /
             CHARACTERISTIC: parse_begin_meta(meta); MEASUREMENT: _first_header_line + parse_measurement_header;
             CHARACTERISTIC: assemble_characteristic_header(lines); the base field loop over the raw lines
             (strip + split + the 20 first-word tests); the AXIS_DESCR capture (_flatten_body_tokens of each child).
  candFront  the candidate tree (pilot2.build), then the graph's replacement, timed alone, over the same objects:
             _section_words (meta at its line, every run by _line_words) -> _tag_header (name, long identifier, up to
             6/7 header words ending at a keyword) -> _tag_keyword_lines (keyword + arity arguments; MATRIX_DIM 1-3
             number words) -> the header dict -> the same field loop over the keyword texts (split(" ") + the tests);
             the AXIS_DESCR capture as the graph writes it (the child's canonical lines through the lexer and _line_words).

Model: new parse = cand tree + (base parse - base tree) - baseFront + candFront. Not product code, not a stub: a
throwaway feasibility model run on cachyos-rtx only; the candidate path imports nothing from s19_app.

Usage: python -I e3a-time.py drive <repo> <runs> <file> [<file> ...]
       python -I e3a-time.py <mode> <repo> <file>          (one run, JSON on the last line)
"""
from __future__ import annotations

import importlib.util
import json
import re
import resource
import statistics
import subprocess
import sys
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("pilot2", _HERE / "pilot2.py")
pilot2 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pilot2)

ARITY = {
    "ADDRESS_TYPE": 1, "ARRAY_SIZE": 1, "BIT_MASK": 1, "BYTE_ORDER": 1, "CALIBRATION_ACCESS": 1,
    "COMPARISON_QUANTITY": 1, "DISCRETE": 0, "DISPLAY_IDENTIFIER": 1, "ECU_ADDRESS": 1, "ECU_ADDRESS_EXTENSION": 1,
    "ENCODING": 1, "ERROR_MASK": 1, "EXTENDED_LIMITS": 2, "FORMAT": 1, "GUARD_RAILS": 0, "LAYOUT": 1,
    "MATRIX_DIM": -1, "MAX_REFRESH": 2, "MODEL_LINK": 1, "NUMBER": 1, "PHYS_UNIT": 1, "READ_ONLY": 0,
    "READ_WRITE": 0, "REF_MEMORY_SEGMENT": 1, "STEP_SIZE": 1, "SYMBOL_LINK": 2, "DATA_SIZE": 1, "LENGTH": 1,
    "DATA_TYPE": 1, "FUNCTION": 1, "COMPU_METHOD": 1, "FORMULA": 1, "UNIT": 1, "LOWER_LIMIT": 1, "UPPER_LIMIT": 1,
    "VIRTUAL": 0, "CALIBRATABLE": 0, "DEPOSIT": 1,
}
HDR = {"MEASUREMENT": 6, "CHARACTERISTIC": 7}
_NUM = re.compile(r"0[xX][0-9A-Fa-f]{1,16}|[0-9]{1,20}")


def number_word(w: str):
    if w.isascii() and _NUM.fullmatch(w):
        return int(w, 16) if w[:2] in ("0x", "0X") else int(w, 10)
    return None


def field_loop(texts, tag):
    """The base field loop's first-word tests, over a list of texts (base: raw lines; new: keyword texts)."""
    for text in texts:
        parts = text.split()
        if not parts:
            continue
        p0 = parts[0]
        n = len(parts)
        if n >= 2 and p0 == "ECU_ADDRESS":
            tag["address"] = parts[1]
        if n >= 2 and p0 in {"DATA_SIZE", "LENGTH"}:
            tag["length"] = parts[1]
        if n >= 2 and p0 == "LOWER_LIMIT":
            tag["lower_limit"] = parts[1]
        if n >= 2 and p0 == "UPPER_LIMIT":
            tag["upper_limit"] = parts[1]
        if n >= 2 and p0 == "UNIT":
            tag["unit"] = parts[1]
        if n >= 2 and p0 == "BYTE_ORDER":
            tag["endian"] = parts[1]
        if n >= 2 and p0 == "BIT_MASK":
            tag["bit_org"] = parts[1]
        if n >= 2 and p0 == "DATA_TYPE":
            tag["datatype"] = parts[1]
        if n >= 2 and p0 == "FUNCTION":
            tag["function_group"] = parts[1]
        if n >= 1 and p0 == "VIRTUAL":
            tag["virtual"] = True
        if n >= 2 and p0 == "COMPU_METHOD":
            tag["conversion"] = parts[1]
        if n >= 1 and p0 == "FORMULA":
            tag["source"] = "formula"
        if n >= 1 and p0 == "READ_ONLY":
            tag["access"] = "read_only"
        if n >= 1 and p0 == "CALIBRATABLE":
            tag["access"] = "calibratable"
        if n >= 2 and p0 == "MATRIX_DIM":
            tag["matrix_dim"] = parts[1:]
        if n >= 2 and p0 == "DISPLAY_IDENTIFIER":
            tag["display_identifier"] = parts[1]
        if n >= 2 and p0 == "SYMBOL_LINK":
            tag["symbol_link"] = parts[1]


def objects(secs):
    stack = list(secs)
    while stack:
        s = stack.pop()
        if s["name"] in HDR:
            yield s
        stack.extend(s["children"])


# ------------------------------------------------------------------------------------------- the graph's new walk
def section_words(sec):
    out = []
    lw = pilot2.line_words
    if sec["meta"]:
        ml = sec["_kw_line"]
        out.extend((w, ml) for w in lw(sec["meta"]))
    for text, ln in zip(sec["lines"], sec["line_numbers"]):
        if text == "":
            out.append(("", ln))
        else:
            out.extend((w, ln) for w in lw(text))
    return out


def tag_header(kind, words):
    n = len(words)
    i = 0
    name, lid = "UNKNOWN", None
    if n and words[0][0] != "":
        w = words[0][0]
        name = w[1:-1] if w[:1] == '"' else w
        i = 1
        if i < n and words[i][0][:1] == '"':
            lid = words[i][0][1:-1] or None
            i += 1
    header = []
    m = HDR[kind]
    while i < n and len(header) < m:
        w = words[i][0]
        if w == "" or (w[:1] != '"' and w in ARITY):
            break
        header.append(w)
        i += 1
    return name, lid, header, i


def keyword_lines(words, start):
    out = []
    i = start
    n = len(words)
    while i < n:
        w = words[i][0]
        if w and w[:1] != '"' and w in ARITY:
            k = ARITY[w]
            if k < 0:
                j = i + 1
                args = []
                while j < n and len(args) < 3 and number_word(words[j][0]) is not None:
                    args.append(words[j][0])
                    j += 1
            else:
                args = [x[0] for x in words[i + 1:i + 1 + k]]
                j = i + 1 + k
            out.append((" ".join([w] + args), words[i][1]))
            i = j
        else:
            i += 1
    return out


def cand_front(secs):
    count = 0
    for sec in objects(secs):
        kind = sec["name"]
        words = section_words(sec)
        name, lid, header, rest = tag_header(kind, words)
        tag = {"name": name, "description": lid}
        if kind == "MEASUREMENT":
            parts = " ".join(header).split(" ")
            tag["datatype"] = parts[0] if parts and parts[0] else None
        elif len(header) == 7:
            tag["char_type"] = header[0]
            tag["address"] = number_word(header[1])
        kws = keyword_lines(words, rest)
        field_loop([t for t, _ in kws], tag)
        for ch in sec["children"]:
            if ch["name"] == "AXIS_DESCR":
                errs: list = []
                toks = [w for _, c in pilot2.lex_lines("\n".join([ch["meta"]] + ch["lines"]), errs)
                        for w in pilot2.line_words(c)]
                tag.setdefault("axis", []).append(toks[3] if len(toks) > 3 else None)
        count += 1
    return count


def base_front(a, secs):
    count = 0
    for sec in objects(secs):
        kind = sec["name"]
        lines = sec.get("lines") or []
        name, lid = a.parse_begin_meta(sec.get("meta", ""))
        tag = {"name": name, "description": lid}
        if kind == "MEASUREMENT":
            hdr, _ = a._first_header_line(kind, lines)
            tag["h"] = a.parse_measurement_header(hdr) if hdr else None
        else:
            tag["h"] = a.assemble_characteristic_header(lines)
        field_loop(lines, tag)
        for ch in sec.get("children") or []:
            if ch.get("name") == "AXIS_DESCR":
                toks = a._flatten_body_tokens(ch.get("lines") or [])
                tag.setdefault("axis", []).append(toks[3] if len(toks) > 3 else None)
        count += 1
    return count


def one(mode: str, repo: Path, f: Path) -> dict:
    if mode in ("baseTree", "baseFull", "cand"):
        res = pilot2.one(mode, repo, f)
        res.pop("file", None)
        return res
    if mode == "baseFront":
        sys.path.insert(0, str(repo))
        import s19_app.tui.a2l as a  # noqa: E402
        secs, _ = a.build_section_tree(f)
        t0 = time.perf_counter()
        n = base_front(a, secs)
        dt = time.perf_counter() - t0
        res = {"mode": mode, "front_s": round(dt, 3), "objects": n, "a2l_file": a.__file__}
    elif mode == "candFront":
        secs, _ = pilot2.build(f)
        t0 = time.perf_counter()
        n = cand_front(secs)
        dt = time.perf_counter() - t0
        res = {"mode": mode, "front_s": round(dt, 3), "objects": n}
    else:
        raise SystemExit("mode?")
    res["maxrss_mb"] = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1)
    return res


def drive(repo: Path, runs: int, files: list) -> int:
    modes = ("baseTree", "baseFull", "cand", "baseFront", "candFront")
    print(f"python {sys.version.split()[0]}; runs per mode {runs}; interleaved {', '.join(modes)}; one process per run")
    for f in files:
        f = Path(f)
        rows: dict = {m: [] for m in modes}
        for r in range(runs):
            for mode in modes:
                cp = subprocess.run([sys.executable, "-I", __file__, mode, str(repo), str(f)],
                                    capture_output=True, text=True, timeout=900, stdin=subprocess.DEVNULL)
                line = cp.stdout.strip().splitlines()[-1] if cp.stdout.strip() else "{}"
                d = json.loads(line)
                rows[mode].append(d)
                print(f"[run {r + 1}] {f.name} {json.dumps(d)}" + (f" STDERR {cp.stderr[-300:]}" if cp.returncode else ""))
        med = {m: statistics.median(x["s"] for x in rows[m]) for m in ("baseTree", "baseFull", "cand")}
        fr = {m: statistics.median(x["front_s"] for x in rows[m]) for m in ("baseFront", "candFront")}
        rest = med["baseFull"] - med["baseTree"]
        e2 = med["cand"] + rest
        model = e2 - fr["baseFront"] + fr["candFront"]
        print(f"[median s] {f.name}: baseTree {med['baseTree']}, baseFull {med['baseFull']}, cand {med['cand']}, "
              f"baseFront {fr['baseFront']}, candFront {fr['candFront']}")
        print(f"[E2 projection] {f.name}: cand + (baseFull - baseTree) = {e2:.3f} s = {e2 / med['baseFull']:.2f} x base parse")
        print(f"[E3 model] {f.name}: E2 projection - baseFront + candFront = {model:.3f} s = "
              f"{model / med['baseFull']:.2f} x base parse (bound 1.50; bound time {1.5 * med['baseFull']:.3f} s)")
    return 0


if __name__ == "__main__":
    if sys.argv[1] == "drive":
        raise SystemExit(drive(Path(sys.argv[2]), int(sys.argv[3]), sys.argv[4:]))
    print(json.dumps(one(sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3]))))
