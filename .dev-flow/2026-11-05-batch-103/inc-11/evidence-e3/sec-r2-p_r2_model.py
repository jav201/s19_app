"""E3 round-2 security probe (Inc 11), runner only. A stdlib MODEL of the corrected graph (graph-inc11.md at 0b0a7239):
_lex_a2l_lines, build_section_tree (nesting cap 32, NUL refusal, _CappedErrors, named kinds not needed here),
_section_words, _tag_header, _tag_keyword_lines (a keyword is never an argument), _number_word, _tag_sizes, the
address / length rules of extract_a2l_tags (R-A2L-READ.58-.63, .67) and _echo_word. Written from the graph and
01-requirements.md text only; it is NOT product code and NOT the E4 REF. Mode 'shapes': synthetic texts only. Mode
'corpus': each public-corpus file read as bytes (never copied), the model run on it, and the e07fb00 reader
(read-only clone) run on it for comparison; only counts and manifest n numbers are printed, never file content."""
import sys, re, time, collections, hashlib, random

MODE = sys.argv[1] if len(sys.argv) > 1 else "shapes"
BLANKS = " \t\x0b\x0c"
BAD = re.compile(r"[^\x21-\x7e]")
NUMRE = re.compile(r"0[xX][0-9A-Fa-f]{1,16}|[0-9]{1,20}")
ARITY = {"ADDRESS_TYPE": 1, "ARRAY_SIZE": 1, "BIT_MASK": 1, "BYTE_ORDER": 1, "CALIBRATION_ACCESS": 1,
         "COMPARISON_QUANTITY": 1, "DISCRETE": 0, "DISPLAY_IDENTIFIER": 1, "ECU_ADDRESS": 1,
         "ECU_ADDRESS_EXTENSION": 1, "ENCODING": 1, "ERROR_MASK": 1, "EXTENDED_LIMITS": 2, "FORMAT": 1,
         "GUARD_RAILS": 0, "LAYOUT": 1, "MATRIX_DIM": None, "MAX_REFRESH": 2, "MODEL_LINK": 1, "NUMBER": 1,
         "PHYS_UNIT": 1, "READ_ONLY": 0, "READ_WRITE": 0, "REF_MEMORY_SEGMENT": 1, "STEP_SIZE": 1, "SYMBOL_LINK": 2,
         "DATA_SIZE": 1, "LENGTH": 1, "DATA_TYPE": 1, "FUNCTION": 1, "COMPU_METHOD": 1, "FORMULA": 1, "UNIT": 1,
         "LOWER_LIMIT": 1, "UPPER_LIMIT": 1, "VIRTUAL": 0, "CALIBRATABLE": 0, "DEPOSIT": 1}
DT = {"UBYTE": 1, "SBYTE": 1, "BYTE": 1, "UWORD": 2, "SWORD": 2, "WORD": 2, "ULONG": 4, "SLONG": 4, "LONG": 4,
      "A_UINT64": 8, "A_INT64": 8, "FLOAT16_IEEE": 2, "FLOAT32_IEEE": 4, "FLOAT64_IEEE": 8}
SIZE_KW = ("DATA_SIZE", "LENGTH", "NUMBER", "MATRIX_DIM", "ARRAY_SIZE")
CAP_DEPTH, CAP_ERR, MAXLEN = 32, 100, 1048576
DIAG = None  # mode 'diag': shape classes only (no names, no addresses, no file text)


def wclass(w):
    if w.startswith('"'):
        return "quoted"
    if re.fullmatch(r"0[xX][0-9A-Fa-f]{1,16}", w):
        return "hex<=16"
    if re.fullmatch(r"0[xX][0-9A-Fa-f]{17,}", w):
        return "hex>16"
    if re.fullmatch(r"[0-9]{1,20}", w):
        return "dec"
    if re.fullmatch(r"[+-][0-9xXa-fA-F]+", w):
        return "signed"
    if re.fullmatch(r"[0-9][0-9A-Fa-fxX_]*", w) and "_" in w:
        return "num_with_underscore"
    if re.fullmatch(r"[+-]?[0-9]*\.[0-9]*([eE][+-]?[0-9]+)?", w) or re.fullmatch(r"[+-]?[0-9]+[eE][+-]?[0-9]+", w):
        return "float"
    if re.fullmatch(r"0[xX][0-9A-Fa-f]+[A-Za-z]+", w):
        return "hex_with_suffix"
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.\[\]]*", w):
        return "ident" + ("_UPPER_KWLIKE" if w.isupper() else "")
    return "other"


class Capped(list):
    def __init__(self):
        super().__init__(); self.dropped = 0; self.total = 0
    def append(self, t):
        self.total += 1
        if len(self) < CAP_ERR:
            super().append(t)
        else:
            self.dropped += 1
    def reset(self, t):
        self.clear(); self.dropped = 0; super().append(t)
    def as_list(self):
        return list(self) + ([f"… {self.dropped} more parse errors"] if self.dropped else [])


class Refused(Exception):
    pass


def echo(w):
    s = "".join(c if "\x21" <= c <= "\x7e" else "�" for c in w[:64])
    return s + ("…" if len(w) > 64 else "")


def unq(w):
    return w[1:-1] if len(w) >= 2 and w[0] == '"' and w[-1] == '"' else w


def numword(w):
    if w is None or w.startswith('"') or not NUMRE.fullmatch(w):
        return None
    return int(w, 16) if w[:2] in ("0x", "0X") else int(w, 10)


def split_lines(text):
    return re.split(r"\r\n|\r|\n", text)


def lex(lines, errors):
    """Yield (line, [words]); a word after a string that closes on a later line keeps the string's start line."""
    state = None
    pend = None
    for ln, line in enumerate(lines, 1):
        if "\x00" in line:
            errors.reset("File is not UTF-8 text; save it as UTF-8 and load it again.")
            raise Refused()
        words, start = (pend[1], pend[0]) if pend else ([], ln)
        pend = None
        i, n = 0, len(line)
        while True:
            if state and state[0] == "c":
                j = line.find("*/", i)
                if j < 0:
                    i = n; break
                state = None; i = j + 2; continue
            if state and state[0] == "s":
                parts = state[2]; j = i
                while j < n:
                    c = line[j]
                    if c == "\\" and j + 1 < n:
                        j += 2; continue
                    if c == '"':
                        break
                    j += 1
                if j < n:
                    parts.append(line[i:j + 1]); words.append("".join(parts)); state = None; i = j + 1; continue
                parts.append(line[i:]); parts.append("\n"); i = n; break
            while i < n and line[i] in BLANKS:
                i += 1
            if i >= n:
                break
            if line.startswith("/*", i):
                state = ("c", ln); i += 2; continue
            if line.startswith("//", i):
                break
            if line[i] == '"':
                state = ("s", ln, ['"']); i += 1; continue
            j = i
            while j < n:
                c = line[j]
                if c in BLANKS or c == '"' or (c == "/" and j + 1 < n and line[j + 1] in "*/"):
                    break
                j += 1
            w = line[i:j]
            if "*/" in w:
                errors.append(f"Line {ln}: */ without /*")
            b = BAD.search(w)
            if b:
                errors.append(f"Line {ln}: unexpected character U+{ord(b.group(0)):04X}")
            words.append(w); i = j
        if state and state[0] == "s":
            pend = (start, words); continue
        if words:
            yield start, words
    if state:
        if state[0] == "c":
            errors.append(f"Line {state[1]}: comment not closed")
        else:
            errors.append(f"Line {state[1]}: quoted string not closed")
            if pend and pend[1]:
                yield pend[0], pend[1]


def build(text, stats=None):
    errors = Capped()
    if text[:1] == "﻿":
        text = text[1:]
    roots, stack, pending = [], [], None
    maxd = 0
    try:
        for ln, words in lex(split_lines(text), errors):
            for w in words:
                if pending is not None:
                    kind, pln = pending[0], pending[1]
                    if kind == "begin":
                        if len(stack) >= CAP_DEPTH:
                            errors.reset(f"Line {pln}: sections nested deeper than {CAP_DEPTH}")
                            return [], errors, "depth"
                        sec = {"name": unq(w), "start": pln, "own": [], "children": [], "end": None}
                        if stack:
                            stack[-1]["children"].append(sec); stack[-1]["own"].append(("", pln))
                        else:
                            roots.append(sec)
                        stack.append(sec); maxd = max(maxd, len(stack)); pending = None; continue
                    if kind == "end":
                        if stack:
                            sec = stack.pop(); sec["end"] = pln
                            if unq(w) != sec["name"]:
                                errors.append(f"Line {pln}: /end {echo(unq(w))} does not close /begin {echo(sec['name'])}")
                        else:
                            errors.append(f"Line {pln}: /end without /begin")
                        pending = None; continue
                    if kind == "include":
                        errors.append(f"Line {pln}: /include {echo(unq(w))} is not read")
                        pending = None  # the /include word stays a word; this word is processed below
                lw = w.lower()
                if lw == "/begin" and not w.startswith('"'):
                    pending = ("begin", ln); continue
                if lw == "/end" and not w.startswith('"'):
                    pending = ("end", ln); continue
                if lw == "/include" and not w.startswith('"'):
                    pending = ("include", ln)
                if stack:
                    stack[-1]["own"].append((w, ln))
    except Refused:
        return [], errors, "nul"
    if pending is not None and pending[0] in ("begin", "end") and stack:
        stack[-1]["own"].append(("/begin" if pending[0] == "begin" else "/end", pending[1]))
    if stack:
        errors.append("Unclosed /begin sections detected.")
    if stats is not None:
        stats["maxdepth"] = max(stats.get("maxdepth", 0), maxd)
    return roots, errors, None


def walk(secs):
    for s in secs:
        yield s
        yield from walk(s["children"])


def is_kw(w):
    return w in ARITY and not w.startswith('"')


def tag_header(section, words):
    i, name, long_id = 0, "UNKNOWN", None
    if i < len(words) and words[i][0] != "":
        name = unq(words[i][0]); i += 1
    if i < len(words) and words[i][0].startswith('"'):
        long_id = unq(words[i][0]) or None; i += 1
    hdr = []
    while i < len(words) and len(hdr) < {"MEASUREMENT": 6, "CHARACTERISTIC": 7}[section]:
        w = words[i][0]
        if w == "" or is_kw(w):
            break
        hdr.append(w); i += 1
    return name, long_id, hdr, i


def kw_lines(words, start, errors, st):
    items, i = [], start
    while i < len(words):
        w, ln = words[i]
        if w == "":
            i += 1; continue
        if not is_kw(w):
            st["dropped_before_kw"] += 1
            if DIAG is not None:
                DIAG[("dropped_not_after_args", "first" if not items else "later", wclass(w), w if wclass(w).endswith("KWLIKE") else "")] += 1
            i += 1; continue
        j, args = i + 1, []
        while j < len(words) and words[j][0] != "" and not is_kw(words[j][0]):
            args.append(words[j][0]); j += 1
        ar = ARITY[w]
        if ar is None:
            take = args
            if not args or len(args) > 3:
                errors.append(f"Line {ln}: MATRIX_DIM has {len(args)} of its 1 to 3 arguments"); st["missing_arg"] += 1
        else:
            take = args[:ar]
            if len(args) < ar:
                errors.append(f"Line {ln}: {w} has {len(args)} of its {ar} arguments"); st["missing_arg"] += 1
                st["missing_arg_" + w] += 1
            if len(args) > ar:
                st["dropped_after_args"] += len(args) - ar
                if w in ("ECU_ADDRESS", "DATA_SIZE", "LENGTH", "NUMBER", "ARRAY_SIZE", "BIT_MASK", "BYTE_ORDER"):
                    st["dropped_after_" + w] += 1
                if DIAG is not None:
                    DIAG[("dropped_after_args", w, tuple(wclass(a) for a in args[ar:ar + 2]))] += 1
        items.append((w, take, ln))
        i = j
    return items


def read_tags(roots, errors, st):
    layouts = {}
    for s in walk(roots):
        if s["name"] == "RECORD_LAYOUT" and s["own"]:
            ws = [w for w, _ in s["own"] if w]
            for k, w in enumerate(ws):
                if w == "FNC_VALUES" and k + 2 < len(ws):
                    layouts[unq(ws[0])] = DT.get(ws[k + 2]); break
    tags = []
    for s in walk(roots):
        sec = s["name"]
        if sec not in ("MEASUREMENT", "CHARACTERISTIC"):
            continue
        words = s["own"]
        name, long_id, hdr, rest = tag_header(sec, words)
        if s["end"] is None:
            errors.append(f"Line {s['start']}: {sec} {echo(name)} is not closed"); st["not_closed"] += 1
            continue
        t = {"section": sec, "name": name, "address": None, "length": None, "bit_mask": None, "byte_order": None,
             "kind": None, "datatype": None, "flags": set()}
        hdr_addr, el = None, None
        if sec == "MEASUREMENT":
            if 1 <= len(hdr) <= 5:
                errors.append(f"Line {s['start']}: MEASUREMENT {echo(name)} has {len(hdr)} of its 6 header words")
            t["datatype"] = hdr[0] if hdr else None
            el = DT.get(t["datatype"])
        else:
            if 1 <= len(hdr) <= 6:
                errors.append(f"Line {s['start']}: CHARACTERISTIC {echo(name)} has {len(hdr)} of its 7 header words")
                st["short_char_header"] += 1
            elif len(hdr) == 7:
                t["kind"], t["deposit"] = hdr[0], hdr[2]
                hdr_addr = numword(hdr[1])
                if hdr_addr is None and DIAG is not None:
                    DIAG[("hdr_addr_nonnum", wclass(hdr[1]), "has_ECU_ADDRESS" if any(w == "ECU_ADDRESS" for w, _ in words) else "no_ECU_ADDRESS")] += 1
                if hdr_addr is None:
                    errors.append(f"Line {s['start']}: address {echo(hdr[1])} is not a number"); t["flags"].add("hdr_addr_nonnum")
                el = layouts.get(hdr[2]) or DT.get(hdr[2].upper())
        items = kw_lines(words, rest, errors, st)
        seen = collections.defaultdict(list)
        for kw, args, ln in items:
            if kw in seen:
                errors.append(f"Line {ln}: {kw} is declared twice in {sec} {echo(name)}"); st["dup_kw"] += 1
            seen[kw].append((args, ln))
        # number words of the size and address keywords
        for kw in ("ECU_ADDRESS",) + SIZE_KW:
            for args, ln in seen.get(kw, []):
                for a in args:
                    if numword(a) is None:
                        errors.append(f"Line {ln}: {kw} {echo(a)} is not a number"); st["nonnum_" + kw] += 1
        # --- address (R-A2L-READ.60)
        addrs, nonum = [], False
        if hdr_addr is not None:
            addrs.append(hdr_addr)
        for args, _ in seen.get("ECU_ADDRESS", []):
            v = numword(args[0]) if args else None
            if v is None:
                nonum = True
            else:
                addrs.append(v)
        if "hdr_addr_nonnum" in t["flags"] and seen.get("ECU_ADDRESS"):
            t["flags"].add("hdr_nonnum_but_ecu")
        address = None
        if not nonum and len(set(addrs)) == 1:
            address = addrs[0]
        if len(set(addrs)) > 1:
            errors.append(f"Line {s['start']}: {sec} {echo(name)} declares the addresses 0x{min(addrs):08X} and 0x{max(addrs):08X}")
            st["disagree_addr"] += 1
        for kw in ("BIT_MASK", "BYTE_ORDER"):
            vals = {tuple(a) for a, _ in seen.get(kw, [])}
            if len(vals) > 1:
                address = None; t["flags"].add("dup_" + kw)
        t["address"] = address
        bm = seen.get("BIT_MASK")
        t["bit_mask"] = bm[0][0][0] if bm and bm[0][0] else None
        if bm and not bm[0][0]:
            t["flags"].add("bitmask_missing_arg")
        bo = seen.get("BYTE_ORDER")
        t["byte_order"] = bo[0][0][0] if bo and bo[0][0] else None
        if bo and not bo[0][0]:
            t["flags"].add("byteorder_missing_arg")
        # --- sizes (R-A2L-READ.59/.61) and length (R-A2L-013 ... 017, .53, .57)
        no_number = False
        vals = {}
        for kw in SIZE_KW:
            for args, _ in seen.get(kw, []):
                if kw == "MATRIX_DIM":
                    nums = [numword(a) for a in args]
                    if not args or len(args) > 3 or None in nums:
                        no_number = True
                    else:
                        p = 1
                        for x in nums:
                            p *= x
                        vals.setdefault(kw, []).append(p)
                else:
                    v = numword(args[0]) if args else None
                    if v is None:
                        no_number = True
                    else:
                        vals.setdefault(kw, []).append(v)
        md = vals.get("MATRIX_DIM", [1])[0] if vals.get("MATRIX_DIM") else 1
        sizes = []
        has_ds = bool(seen.get("DATA_SIZE") or seen.get("LENGTH"))
        for kw in ("DATA_SIZE", "LENGTH"):
            if el is not None:
                sizes += vals.get(kw, [])
        for kw in ("NUMBER", "ARRAY_SIZE", "MATRIX_DIM"):
            sizes += [v * el if el is not None else v for v in vals.get(kw, [])]
        if has_ds and el is not None:
            sizes.append(el * md)
        agree = len(set(sizes)) <= 1
        family = t["kind"] in ("CURVE", "MAP", "CUBOID", "CUBE_4", "CUBE_5")
        if family and has_ds:
            st["curvemap_with_length"] += 1
            if not agree:
                st["curvemap_with_length_disagree"] += 1
        length = None
        if not agree:
            errors.append(f"Line {s['start']}: {sec} {echo(name)} declares the sizes {min(sizes)} and {max(sizes)}")
            st["disagree_size"] += 1
            if DIAG is not None:
                DIAG[("disagree_size", sec, t["kind"], el, tuple(sorted((k, tuple(v)) for k, v in vals.items())))] += 1
        if agree and not no_number:
            if vals.get("DATA_SIZE") or vals.get("LENGTH"):
                length = (vals.get("DATA_SIZE") or vals.get("LENGTH"))[0]
            elif sec == "MEASUREMENT":
                if vals.get("ARRAY_SIZE") and el is not None:
                    length = el * vals["ARRAY_SIZE"][0]
                elif el is not None:
                    length = el * md
            else:
                k = t["kind"]
                if k == "VALUE" and el is not None:
                    length = el * md
                elif k == "VAL_BLK" and el is not None:
                    if vals.get("MATRIX_DIM"):
                        length = el * md
                    elif vals.get("NUMBER"):
                        length = el * vals["NUMBER"][0]
                elif k == "ASCII":
                    length = vals["NUMBER"][0] if vals.get("NUMBER") else (md if vals.get("MATRIX_DIM") else None)
                elif family:
                    t["flags"].add("span_by_layout")
        elif family:
            t["flags"].add("refused_but_span_pass_as_base")
        if length is not None and not 1 <= length <= MAXLEN:
            errors.append(f"Line {s['start']}: {sec} {echo(name)} has the length {length}, outside 1 to 1048576 bytes")
            length = None
            if family:
                t["flags"].add("refused_but_span_pass_as_base")
        t["length"] = length
        t["no_number"] = no_number
        tags.append(t)
    return tags


def read(text):
    st = collections.Counter()
    roots, errors, refusal = build(text, st)
    tags = read_tags(roots, errors, st) if roots else []
    return {"roots": roots, "errors": errors, "refusal": refusal, "tags": tags, "st": st}


def meas(name, body, dt="UWORD", begin=20):
    pre = "\n" * (begin - 1)
    return pre + f'/begin MEASUREMENT {name} ""\n {dt} CM_ID 0 0 0 65535\n' + body + "\n/end MEASUREMENT\n"


def char(name, body, kind="VALUE", addr="0x2000", dep="RL_U16", begin=20):
    pre = "/begin RECORD_LAYOUT RL_U16 FNC_VALUES 1 UWORD ROW_DIR DIRECT /end RECORD_LAYOUT\n"
    pre += "\n" * (begin - 2)
    return pre + f'/begin CHARACTERISTIC {name} "" {kind} {addr} {dep} 0 CM_ID 0 65535\n' + body + "\n/end CHARACTERISTIC\n"


def show(tag, text):
    r = read(text)
    t = r["tags"][0] if r["tags"] else None
    a = (f"0x{t['address']:X}" if isinstance(t["address"], int) else None) if t else "-"
    out = (f"address={a} length={t['length'] if t else '-'} bit_mask={t['bit_mask'] if t else '-'} "
           f"byte_order(own)={t['byte_order'] if t else '-'} flags={sorted(t['flags']) if t else '-'}")
    print(f"[{tag}] {out} | errors={r['errors'].as_list()}")
    return r


def shapes():
    print("== [S-ARG] missing argument shapes (E3S-02; READ.29, .58, .60, .61) ==")
    show("S-ARG B8", meas("X", " ECU_ADDRESS 0x10\n BYTE_ORDER\n BIT_MASK 0x0FF0"))
    show("S-ARG B9", meas("X", " ECU_ADDRESS_EXTENSION\n ECU_ADDRESS 0x1234"))
    show("S-ARG ecu->bitmask", meas("X", " ECU_ADDRESS\n BIT_MASK 0x0FF0"))
    show("S-ARG maxrefresh", meas("X", " MAX_REFRESH 1\n ECU_ADDRESS 0x10"))
    show("S-ARG ecu-last", meas("X", " BIT_MASK 0x0FF0\n ECU_ADDRESS"))
    show("S-ARG mdim->ecu", meas("X", " MATRIX_DIM\n ECU_ADDRESS 0x10"))
    show("S-ARG mdim-4", meas("X", " ECU_ADDRESS 0x10\n MATRIX_DIM 2 3 4 5"))
    show("S-ARG length->ecu", meas("X", " LENGTH\n ECU_ADDRESS 0x10"))
    show("S-ARG datasize->ecu", meas("X", " DATA_SIZE\n ECU_ADDRESS 0x10"))
    show("S-ARG extlimits", meas("X", " EXTENDED_LIMITS 0\n ECU_ADDRESS 0x10"))
    show("S-ARG symlink", meas("X", ' SYMBOL_LINK "x"\n ECU_ADDRESS 0x10'))
    show("S-ARG ecu-child-ecu", meas("X", " ECU_ADDRESS /begin IF_DATA XCP /end IF_DATA 0x10"))
    show("S-ARG bitmask-missing", meas("X", " ECU_ADDRESS 0x10\n BIT_MASK\n BYTE_ORDER MSB_FIRST"))
    show("S-ARG byteorder-missing", meas("X", " ECU_ADDRESS 0x10\n BYTE_ORDER\n LENGTH 2"))
    show("S-ARG quoted-arg", meas("X", ' ECU_ADDRESS "0x10"'))
    show("S-ARG unknown-kw-arg", meas("X", " ECU_ADDRESS\n MY_VENDOR_KW 0x10"))
    print("== [S-PAIR] disagreeing and agreeing pairs (E3S-03; D-6 revised; READ.59-.61) ==")
    show("S-PAIR ecu x2 diff", meas("X", " ECU_ADDRESS 0x10\n ECU_ADDRESS 0x20"))
    show("S-PAIR ecu x2 same", meas("X", " ECU_ADDRESS 0x10\n ECU_ADDRESS 0x10"))
    show("S-PAIR ecu ok + ecu nonnum", meas("X", " ECU_ADDRESS 0x10\n ECU_ADDRESS 0x10_00"))
    show("S-PAIR B5 datasize2 length8", meas("X", " ECU_ADDRESS 0x10\n DATA_SIZE 2\n LENGTH 8"))
    nohdr = lambda body: "\n" * 19 + '/begin MEASUREMENT X ""\n' + body + "\n/end MEASUREMENT\n"
    show("S-PAIR no-datatype datasize2 length8", nohdr(" ECU_ADDRESS 0x10\n DATA_SIZE 2\n LENGTH 8"))
    show("S-PAIR no-datatype length4 length8", nohdr(" ECU_ADDRESS 0x10\n LENGTH 4\n LENGTH 8"))
    show("S-PAIR no-datatype length8 datasize2", nohdr(" ECU_ADDRESS 0x10\n LENGTH 8\n DATA_SIZE 2"))
    show("S-PAIR undeclared-layout VALUE length4 length8", char("C", " LENGTH 4\n LENGTH 8", dep="RL_NONE"))
    show("S-PAIR length4 length8", meas("X", " ECU_ADDRESS 0x10\n LENGTH 4\n LENGTH 8"))
    show("S-PAIR B3 hdr 2000 ecu 3000", char("C", " ECU_ADDRESS 0x3000"))
    show("S-PAIR hdr 2000 ecu 2000", char("C", " ECU_ADDRESS 0x2000"))
    show("S-PAIR B3b hdr 2000 ecu 30_00", char("C", " ECU_ADDRESS 0x30_00"))
    show("S-PAIR hdr 20_00 ecu 3000", char("C", " ECU_ADDRESS 0x3000", addr="0x20_00"))
    show("S-PAIR B7 bitmask x2 diff", meas("X", " ECU_ADDRESS 0x10\n BIT_MASK 0x000F\n BIT_MASK 0x0FF0"))
    show("S-PAIR bitmask x2 same", meas("X", " ECU_ADDRESS 0x10\n BIT_MASK 0x0FF0\n BIT_MASK 0x0FF0"))
    show("S-PAIR byteorder x2 diff", meas("X", " ECU_ADDRESS 0x10\n BYTE_ORDER MSB_FIRST\n BYTE_ORDER MSB_LAST"))
    show("S-PAIR byteorder x2 same", meas("X", " ECU_ADDRESS 0x10\n BYTE_ORDER MSB_FIRST\n BYTE_ORDER MSB_FIRST"))
    show("S-PAIR B6 VALUE RL_U16 LENGTH 4", char("C", " LENGTH 4"))
    show("S-PAIR VALBLK mdim4 number5", char("C", " MATRIX_DIM 4\n NUMBER 5", kind="VAL_BLK"))
    show("S-PAIR VALBLK mdim4 number4", char("C", " MATRIX_DIM 4\n NUMBER 4", kind="VAL_BLK"))
    show("S-PAIR arraysize4 mdim3", meas("X", " ECU_ADDRESS 0x10\n ARRAY_SIZE 4\n MATRIX_DIM 3"))
    show("S-PAIR MAP LENGTH = span", char("M", " LENGTH 2266", kind="MAP"))
    show("S-PAIR MAP LENGTH x4", char("M", " LENGTH x4", kind="MAP"))
    show("S-PAIR ecu surplus word", meas("X", " ECU_ADDRESS 0x1C2D 3E00"))
    show("S-PAIR length surplus word", meas("X", " ECU_ADDRESS 0x10\n LENGTH 2 4"))
    print("== [S-DEPTH] nesting cap (E3S-04; READ.64, .65) ==")
    for d in (31, 32, 33):
        r = read("\n".join(["/begin A"] * d + ["/end A"] * d) + "\n")
        print(f"[S-DEPTH {d} one per line] sections={len(list(walk(r['roots'])))} refusal={r['refusal']} errors={r['errors'].as_list()}")
        r = read(" ".join(["/begin A"] * d + ["/end A"] * d) + "\n")
        print(f"[S-DEPTH {d} one line] sections={len(list(walk(r['roots'])))} refusal={r['refusal']} errors={r['errors'].as_list()}")
    for label, txt in (("5000 nested", "\n".join(["/begin A"] * 5000 + ["/end A"] * 5000)),
                       ("50000 /begin unclosed", "\n".join(["/begin MEASUREMENT X \"\""] * 50000))):
        t0 = time.perf_counter(); r = read(txt); dt = time.perf_counter() - t0
        print(f"[S-DEPTH {label}] sections={len(list(walk(r['roots'])))} refusal={r['refusal']} errors={r['errors'].as_list()} s={dt:.3f}")
    print("== [S-ENC] NUL and UTF-16 without a BOM (READ.55, .6) ==")
    hdr = 'ASAP2_VERSION 1 71\n/begin PROJECT P ""\n/begin MODULE M ""\n' + meas("X", " ECU_ADDRESS 0x1234", begin=4) + "/end MODULE\n/end PROJECT\n"
    for enc in ("utf-16-le", "utf-16-be", "utf-32-le"):
        b = hdr.encode(enc)
        r = read(b.decode("utf-8", errors="replace"))
        print(f"[S-ENC {enc} no BOM] bytes={len(b)} sections={len(r['roots'])} tags={len(r['tags'])} errors={r['errors'].as_list()}")
    for label, txt in (("NUL after addr", hdr.replace("0x1234", "0x1234\x00")),
                       ("NUL in comment", hdr + "/* a\x00b */\n"),
                       ("NUL in string", hdr.replace('X ""', 'X "a\x00b"')),
                       ("NUL last byte", hdr + "\x00"),
                       ("NUL after 300 errors", "\n".join(["/end X"] * 300) + "\n" + hdr + "\x00")):
        r = read(txt)
        print(f"[S-ENC {label}] sections={len(r['roots'])} tags={len(r['tags'])} errors={r['errors'].as_list()}")
    rnd = random.Random(103)
    blob = bytes(rnd.randrange(256) for _ in range(5 * 1024 * 1024))
    t0 = time.perf_counter(); r = read(blob.decode("utf-8", errors="replace")); dt = time.perf_counter() - t0
    print(f"[S-ENC 5 MiB random] nul_in={blob.count(0)} sections={len(r['roots'])} errors={r['errors'].as_list()} s={dt:.2f}")
    print("== [S-CAP] error cap (READ.56; E3A-02, E3S-11) ==")
    for n in (100, 101, 200000):
        r = read("\n".join(["/end X"] * n) + "\n")
        el = r["errors"].as_list()
        print(f"[S-CAP {n} stray /end] entries={len(el)} last={el[-1]!r} raw_total={r['errors'].total}")
    r = read("/begin PROJECT P \"\"\n" + "\n".join(["Xé 0x10"] * 400000) + "\n/end PROJECT\n")
    el = r["errors"].as_list()
    print(f"[S-CAP 400000 U+00E9 words] entries={len(el)} last={el[-1]!r}")
    # the cap must not hide a value: a tag whose disagreement error lands past the cap still gets no address
    txt = "/begin PROJECT P \"\"\n" + "\n".join(["/end X"] * 0) + "\n".join(["Qé"] * 150) + "\n" + meas("X", " ECU_ADDRESS 0x10\n ECU_ADDRESS 0x20", begin=1) + "/end PROJECT\n"
    r = read(txt)
    t = r["tags"][0]
    print(f"[S-CAP disagreement past the cap] address={t['address']} entries={len(r['errors'].as_list())} last={r['errors'].as_list()[-1]!r}")
    print("== [S-ECHO] echoed words (READ.66) ==")
    r = read('/begin PROJECT P ""\n/include "' + ("A\nB\x1bC" * 200000) + '"\n/end PROJECT\n')
    el = r["errors"].as_list()
    print(f"[S-ECHO 1 MB include word] lens={[len(e) for e in el]} has_LF={any(chr(10) in e for e in el)} has_ESC={any(chr(27) in e for e in el)}")
    print("== [S-LINE] a word after a string that closes on a later line (line attribution) ==")
    r = read('/begin PROJECT P ""\n/begin MEASUREMENT X ""\n UWORD CM_ID 0 0 0 65535\n FORMAT "a\nb" /end MEASUREMENT\n/end PROJECT\n')
    x = [s for s in walk(r["roots"]) if s["name"] == "MEASUREMENT"][0]
    print(f"[S-LINE] MEASUREMENT /end on line 5 -> end_line={x['end']} (the string opened on line 4)")


def corpus():
    sys.path.insert(0, "/home/<user>/work/s19_app")
    import s19_app
    from s19_app.tui import a2l as A
    from pathlib import Path
    print("s19_app.__file__ =", s19_app.__file__)
    man = {}
    for row in Path("/home/<user>/a2l-corpus/manifest.tsv").read_text(encoding="utf-8", errors="replace").splitlines()[1:]:
        parts = row.split("\t")
        if len(parts) > 2:
            man[parts[2] if len(parts[2]) == 64 else parts[-1]] = parts[0]
    agg = collections.Counter(); per = collections.defaultdict(list); seen_sha = set()
    files = sorted(Path("/home/<user>/a2l-corpus/files").iterdir())
    for k, f in enumerate(files):
        if not f.is_file():
            continue
        raw = f.read_bytes(); sha = hashlib.sha256(raw).hexdigest()
        if sha in seen_sha:
            agg["dup_files"] += 1; continue
        seen_sha.add(sha); fid = man.get(sha, f"#{k}")
        agg["files"] += 1
        if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
            agg["utf16_bom"] += 1; continue
        text = raw.decode("utf-8", errors="replace")
        t0 = time.perf_counter()
        try:
            r = read(text)
        except Exception as e:
            agg["model_exc"] += 1; print(f"[CORP-exc] n={fid} model {type(e).__name__}"); continue
        st = r["st"]
        if r["refusal"]:
            agg["refused_" + r["refusal"]] += 1; per["refused"].append(fid)
        agg["errors_raw"] += r["errors"].total
        per["errors_raw"].append((r["errors"].total, fid))
        if r["errors"].dropped:
            agg["files_over_cap"] += 1
        per["maxdepth"].append((st.get("maxdepth", 0), fid))
        for key in ("missing_arg", "dup_kw", "disagree_addr", "disagree_size", "not_closed", "short_char_header",
                    "dropped_after_args", "dropped_before_kw", "curvemap_with_length", "curvemap_with_length_disagree"):
            agg[key] += st[key]
            if st[key]:
                per[key].append((st[key], fid))
        for key in st:
            if key.startswith(("missing_arg_", "dropped_after_", "nonnum_")):
                agg[key] += st[key]
        for t in r["tags"]:
            agg["tags"] += 1
            for fl in t["flags"]:
                agg["flag_" + fl] += 1
        # e07fb00 reading of the same file, matched by (section, name, occurrence)
        try:
            d = A.parse_a2l_file(f)
        except BaseException as e:
            agg["base_exc"] += 1; continue
        base = collections.defaultdict(list)
        for t in d.get("tags", []):
            base[(t.get("section"), t.get("name"))].append(t)
        occ = collections.Counter()
        for t in r["tags"]:
            key = (t["section"], t["name"]); i = occ[key]; occ[key] += 1
            b = base.get(key, [])
            if i >= len(b):
                agg["cmp_unmatched"] += 1; continue
            b = b[i]
            ba, bl = b.get("address"), b.get("length")
            ma, ml = t["address"], t["length"]
            agg["cmp_tags"] += 1
            if ma == ba:
                agg["addr_same"] += 1
            elif ma is None:
                agg["addr_model_none_base_value"] += 1; per["addr_model_none"].append(fid)
            elif ba is None:
                agg["addr_model_value_base_none"] += 1
            else:
                agg["addr_both_differ"] += 1; per["addr_differ"].append(fid)
            if "span_by_layout" in t["flags"] or "refused_but_span_pass_as_base" in t["flags"]:
                agg["len_curvemap_not_modeled"] += 1; continue
            if ml == bl:
                agg["len_same"] += 1
            elif ml is None:
                agg["len_model_none_base_value"] += 1; per["len_model_none"].append(fid)
            elif bl is None:
                agg["len_model_value_base_none"] += 1
            else:
                agg["len_both_differ"] += 1; per["len_differ"].append(fid)
    print("[CORP] " + " ".join(f"{k}={agg[k]}" for k in sorted(agg)))
    for key in ("maxdepth", "errors_raw", "missing_arg", "dup_kw", "disagree_addr", "disagree_size", "not_closed",
                "dropped_after_args", "dropped_before_kw", "curvemap_with_length"):
        v = sorted(per[key], reverse=True)
        print(f"[CORP-{key}] files>0={sum(1 for x in v if x[0])} top5={v[:5]}")
    for key in ("refused", "addr_model_none", "addr_differ", "len_model_none", "len_differ"):
        c = collections.Counter(per[key])
        print(f"[CORP-{key}] files={len(c)} top5={c.most_common(5)}")


def diag():
    global DIAG
    from pathlib import Path
    DIAG = collections.Counter(); seen = set()
    for f in sorted(Path("/home/<user>/a2l-corpus/files").iterdir()):
        raw = f.read_bytes(); sha = hashlib.sha256(raw).hexdigest()
        if sha in seen or raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
            continue
        seen.add(sha)
        read(raw.decode("utf-8", errors="replace"))
    for k, v in sorted(DIAG.items(), key=lambda kv: (kv[0][0], -kv[1])):
        print(f"[DIAG] {v} x {k}")


if MODE == "diag":
    diag()
elif MODE == "shapes":
    shapes()
else:
    corpus()
