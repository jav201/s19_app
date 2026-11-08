"""Inc 11 E3 architect round 2 (batch-103): R-A2L-READ.52 with the E3 correction's rules, re-measured.

Round 1's model (e3a-time.py, unchanged in its modes) plus two modes for what the correction adds:
  cand3       pilot3.build: the candidate tree with the correction's per-line and per-section rules (printable-ASCII
              tier 1, the NUL test on every other line, the named-kind rule, the nesting cap, capped errors);
  candFront2  candFront plus the correction's tag rules: a keyword is never an argument (DE-9), the arity shortfall
              test (READ.58), duplicate keywords (READ.32) kept per tag, the address words compared (READ.60), the sizes
              of CTX *sizes* collected and compared (_tag_sizes, READ.59/.61), every size/address argument through the
              number word (READ.63), and the quoted-name character test (READ.4).
Model: new parse = cand3 + (baseFull - baseTree) - baseFront + candFront2. Not product code, not a stub; the candidate
path imports nothing from s19_app.

Usage: python -I e3a2-time.py drive <repo> <runs> <file> [<file> ...]
       python -I e3a2-time.py <mode> <repo> <file>
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
_spec3 = importlib.util.spec_from_file_location("pilot3", _HERE / "pilot3.py")
pilot3 = importlib.util.module_from_spec(_spec3)
_spec3.loader.exec_module(pilot3)
DTS = {"UBYTE": 1, "SBYTE": 1, "UWORD": 2, "SWORD": 2, "ULONG": 4, "SLONG": 4, "A_UINT64": 8, "A_INT64": 8,
       "FLOAT16_IEEE": 2, "FLOAT32_IEEE": 4, "FLOAT64_IEEE": 8}
SIZE_KW = ("DATA_SIZE", "LENGTH", "NUMBER", "ARRAY_SIZE")

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


def keyword_lines2(words, start, errors):
    """DE-9: a keyword's arguments end at the next unquoted keyword or a place mark; READ.58's shortfall test."""
    out = []
    i = start
    n = len(words)
    while i < n:
        w = words[i][0]
        if w and w[:1] != '"' and w in ARITY:
            k = ARITY[w]
            j = i + 1
            args = []
            lim = 4 if k < 0 else k
            while j < n and len(args) < lim:
                x = words[j][0]
                if x == "" or (x[:1] != '"' and x in ARITY):
                    break
                args.append(x)
                j += 1
            if (k < 0 and not (1 <= len(args) <= 3)) or (k >= 0 and len(args) < k):
                errors.append(f"Line {words[i][1]}: {w} has {len(args)} of its {k} arguments")
            out.append((" ".join([w] + args), words[i][1]))
            i = j
        else:
            i += 1
    return out


def tag_rules(kind, header, kws, name_word, errors):
    """The correction's per-tag checks: duplicates, address words, sizes, number words, quoted-name characters."""
    seen = {}
    addrs = []
    sizes = []
    no_number = False
    if kind == "CHARACTERISTIC" and len(header) == 7:
        v = number_word(header[1])
        if v is None:
            errors.append(f"Line 0: address {header[1]} is not a number")
        else:
            addrs.append(v)
    el = DTS.get(header[0]) if kind == "MEASUREMENT" and header else None
    md = None
    has_len = False
    for text, ln in kws:
        parts = text.split(" ")
        kw = parts[0]
        if kw in seen:
            errors.append(f"Line {ln}: {kw} is declared twice")
        seen[kw] = parts[1:]
        if kw == "ECU_ADDRESS" or kw in SIZE_KW or kw == "MATRIX_DIM":
            vals = [number_word(p) for p in parts[1:]]
            if not vals or any(v is None for v in vals):
                no_number = True
                errors.append(f"Line {ln}: {kw} is not a number")
                continue
            if kw == "ECU_ADDRESS":
                addrs.append(vals[0])
            elif kw == "MATRIX_DIM":
                p = 1
                for v in vals:
                    p *= v
                md = p
            else:
                has_len = has_len or kw in ("DATA_SIZE", "LENGTH")
                sizes.append((kw, vals[0]))
    if el is not None:
        b = [v if k in ("DATA_SIZE", "LENGTH") else v * el for k, v in sizes]
        if md is not None:
            b.append(md * el)
        if has_len:
            b.append(el * (md or 1))
    else:
        b = [v for k, v in sizes if k not in ("DATA_SIZE", "LENGTH")] + ([md] if md is not None else [])
    agree = len(set(b)) <= 1
    if not agree:
        errors.append(f"Line 0: declares the sizes {min(b)} and {max(b)}")
    if len(set(addrs)) > 1:
        errors.append(f"Line 0: declares the addresses {min(addrs)} and {max(addrs)}")
    if name_word[:1] == '"' and not (name_word.isascii() and name_word.isprintable()):
        errors.append("Line 0: unexpected character")
    return agree, no_number


def cand_front2(secs):
    count = 0
    errors = pilot3.Capped()
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
        kws = keyword_lines2(words, rest, errors)
        field_loop([t for t, _ in kws], tag)
        tag["_agree"] = tag_rules(kind, header, kws, words[0][0] if words else "", errors)
        for ch in sec["children"]:
            if ch["name"] == "AXIS_DESCR":
                errs: list = []
                toks = [w for _, c in pilot3.lex_lines("\n".join([ch["meta"]] + ch["lines"]), errs)
                        for w in pilot3.line_words(c)]
                tag.setdefault("axis", []).append(toks[3] if len(toks) > 3 else None)
        count += 1
    return count, len(errors), errors.dropped


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
    if mode == "cand3":
        t0 = time.perf_counter()
        secs, errs = pilot3.build(f)
        dt = time.perf_counter() - t0
        objs, total = pilot3.count(secs)
        res = {"mode": mode, "s": round(dt, 3), "objects": objs, "sections": total, "errors": list(errs)[:2],
               "named_meta_filled": sum(1 for s in _all(secs) if s.get("meta_line") is not None)}
        res["maxrss_mb"] = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1)
        return res
    if mode == "candFront2":
        secs, _ = pilot3.build(f)
        t0 = time.perf_counter()
        n, ne, nd = cand_front2(secs)
        dt = time.perf_counter() - t0
        res = {"mode": mode, "front_s": round(dt, 3), "objects": n, "tag_errors_kept": ne, "tag_errors_dropped": nd}
        res["maxrss_mb"] = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1)
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


def _all(secs):
    stack = list(secs)
    while stack:
        s = stack.pop()
        yield s
        stack.extend(s["children"])


def drive(repo: Path, runs: int, files: list) -> int:
    modes = ("baseTree", "baseFull", "cand", "cand3", "baseFront", "candFront", "candFront2")
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
        med = {m: statistics.median(x["s"] for x in rows[m]) for m in ("baseTree", "baseFull", "cand", "cand3")}
        fr = {m: statistics.median(x["front_s"] for x in rows[m]) for m in ("baseFront", "candFront", "candFront2")}
        rss = {m: statistics.median(x["maxrss_mb"] for x in rows[m]) for m in modes}
        rest = med["baseFull"] - med["baseTree"]
        e2 = med["cand"] + rest
        model = e2 - fr["baseFront"] + fr["candFront"]
        print(f"[median s] {f.name}: baseTree {med['baseTree']}, baseFull {med['baseFull']}, cand {med['cand']}, "
              f"baseFront {fr['baseFront']}, candFront {fr['candFront']}")
        print(f"[E2 projection] {f.name}: cand + (baseFull - baseTree) = {e2:.3f} s = {e2 / med['baseFull']:.2f} x base parse")
        print(f"[E3 model] {f.name}: E2 projection - baseFront + candFront = {model:.3f} s = "
              f"{model / med['baseFull']:.2f} x base parse (bound 1.50; bound time {1.5 * med['baseFull']:.3f} s)")
        model2 = med["cand3"] + rest - fr["baseFront"] + fr["candFront2"]
        print(f"[E3 round-2 model] {f.name}: cand3 {med['cand3']} (cand {med['cand']}, +{med['cand3'] - med['cand']:.3f}); "
              f"candFront2 {fr['candFront2']} (candFront {fr['candFront']}, +{fr['candFront2'] - fr['candFront']:.3f}); "
              f"cand3 + (baseFull - baseTree) - baseFront + candFront2 = {model2:.3f} s = "
              f"{model2 / med['baseFull']:.2f} x base parse (bound 1.50; bound time {1.5 * med['baseFull']:.3f} s)")
        print(f"[maxrss median MB] {f.name}: " + ", ".join(f"{m} {rss[m]}" for m in modes))
    return 0


if __name__ == "__main__":
    if sys.argv[1] == "drive":
        raise SystemExit(drive(Path(sys.argv[2]), int(sys.argv[3]), sys.argv[4:]))
    print(json.dumps(one(sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3]))))
