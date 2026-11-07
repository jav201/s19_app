"""E3 round-3 security probe (Inc 11), runner only. A stdlib MODEL of the graph as corrected at round 2
(graph-inc11.md / 01-requirements.md at d1e1ebb8): the round-2 model (sec-r2-p_r2_model.py) with the round-2
corrections applied as the records word them:
  - E3S-25: a word after a quoted string that closes on a later line carries the closing line (_lex_a2l_lines);
  - E3S-24: a SURPLUS NUMBER WORD after ECU_ADDRESS, DATA_SIZE, LENGTH, NUMBER, ARRAY_SIZE or BIT_MASK gives .58's
    error and no value; any other surplus word is dropped silently (as the records say; '3E00' is the open case);
  - E3S-21: BIT_MASK or BYTE_ORDER with a missing argument -> no address;
  - E3S-22: any address word that is no number word (a CHARACTERISTIC's header address included) -> no address;
  - E3S-19 / E3S-23: CTX *sizes* in two groups (byte sizes DATA_SIZE/LENGTH; counts NUMBER/ARRAY_SIZE/MATRIX_DIM
    product, or the one count 1), always compared within each group, across in bytes only when the element size is
    known; the CURVE/MAP family compares its byte sizes with its span only (span given per shape here).
It is NOT product code and NOT the E4 REF. Mode 'shapes': synthetic texts only, each under four candidate rules
for the surplus word (RULES). Mode 'corpus': each public-corpus file read as bytes (never copied); only counts and
classes are printed -- never file content, names, addresses or keyword words.
"""
import os, sys, re, time, collections, hashlib

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
# ASAP2 1.7.1 keywords that may stand in a MEASUREMENT or CHARACTERISTIC body (for the corpus CLASS only)
ASAP2_BODY_KW = set(ARITY) | {"ANNOTATION", "AXIS_DESCR", "BIT_OPERATION", "COMPARISON_QUANTITY", "DEPENDENT_CHARACTERISTIC",
                              "FUNCTION_LIST", "IF_DATA", "MAP_LIST", "VIRTUAL_CHARACTERISTIC", "MONOTONY",
                              "NUMBER", "STATIC_RECORD_LAYOUT", "STATIC_ADDRESS_OFFSETS", "MODEL_LINK", "VAR_VIRTUAL",
                              "CALIBRATION_ACCESS", "ALIGNMENT_BYTE", "MATRIX_DIM", "EXTENDED_LIMITS"}
BYTE_ORDER_OK = {"MSB_FIRST", "MSB_LAST", "BIG_ENDIAN", "LITTLE_ENDIAN"}
BYTE_ORDER_MIXED = {"MSB_FIRST_MSW_LAST", "MSB_LAST_MSW_FIRST"}
DT = {"UBYTE": 1, "SBYTE": 1, "BYTE": 1, "UWORD": 2, "SWORD": 2, "WORD": 2, "ULONG": 4, "SLONG": 4, "LONG": 4,
      "A_UINT64": 8, "A_INT64": 8, "FLOAT16_IEEE": 2, "FLOAT32_IEEE": 4, "FLOAT64_IEEE": 8}
SIZE_KW = ("DATA_SIZE", "LENGTH", "NUMBER", "MATRIX_DIM", "ARRAY_SIZE")
SURPLUS_KW = ("ECU_ADDRESS", "DATA_SIZE", "LENGTH", "NUMBER", "ARRAY_SIZE", "BIT_MASK")
FAMILY = ("CURVE", "MAP", "CUBOID", "CUBE_4", "CUBE_5")
CAP_DEPTH, CAP_ERR, MAXLEN = 32, 100, 1048576
RULES = ("number", "digit", "hexlike", "any")
RULE = "number"          # the records' rule (E3S-24 as corrected)
SPAN = {}                # name -> layout span, for CURVE/MAP-family shapes (the model computes no span)
DIAG = None


def numword(w):
    if w is None or w.startswith('"') or not NUMRE.fullmatch(w):
        return None
    return int(w, 16) if w[:2] in ("0x", "0X") else int(w, 10)


def sclass(w):
    """Class of a surplus word (corpus counts only)."""
    if w.startswith('"'):
        return "quoted"
    if numword(w) is not None:
        return "number_word"
    if w[:1] in "0123456789":
        return "digit_leading_not_number"
    if re.fullmatch(r"[0-9A-Fa-f_]+", w):
        return "hex_letters_only"
    if w in ASAP2_BODY_KW:
        return "asap2_keyword_not_in_arity_list"
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.\[\]]*", w):
        return "identifier"
    return "other"


def caught(w, rule):
    """Does the surplus-word rule refuse the keyword for this surplus word?"""
    if w.startswith('"'):
        return False
    if numword(w) is not None:
        return True
    if rule == "number":
        return False
    if rule == "digit":
        return w[:1] in "0123456789"
    if rule == "hexlike":
        return w[:1] in "0123456789" or bool(re.fullmatch(r"[0-9A-Fa-f_]+", w))
    return True  # 'any' unquoted non-keyword word


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


def split_lines(text):
    return re.split(r"\r\n|\r|\n", text)


def lex(lines, errors):
    """Yield (line, [words]); E3S-25: the words after a string that closes on a later line form their own item
    with the closing line."""
    state = None
    pend = None
    for ln, line in enumerate(lines, 1):
        if "\x00" in line:
            errors.reset("File is not UTF-8 text; save it as UTF-8 and load it again.")
            raise Refused()
        words, start = (pend[1], pend[0]) if pend else ([], ln)
        pend = None
        emit = []
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
                    parts.append(line[i:j + 1]); words.append("".join(parts)); state = None; i = j + 1
                    if start != ln:                      # E3S-25
                        emit.append((start, words)); words, start = [], ln
                    continue
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
        yield from emit
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
                        pending = None
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
    """Items (keyword, taken words, line, flags). E3S-24 as corrected, under RULE."""
    items, i = [], start
    while i < len(words):
        w, ln = words[i]
        if w == "":
            i += 1; continue
        if not is_kw(w):
            i += 1; continue
        j, args = i + 1, []
        while j < len(words) and words[j][0] != "" and not is_kw(words[j][0]):
            args.append(words[j][0]); j += 1
        ar = ARITY[w]
        flags = set()
        if ar is None:
            take = args
            if not args or len(args) > 3:
                errors.append(f"Line {ln}: MATRIX_DIM has {len(args)} of its 1 to 3 arguments"); flags.add("bad_count")
        else:
            take = args[:ar]
            surplus = args[ar:]
            if len(args) < ar:
                errors.append(f"Line {ln}: {w} has {len(args)} of its {ar} arguments"); flags.add("missing")
            if surplus and w in SURPLUS_KW:
                hit = [a for a in surplus if caught(a, RULE)]
                for a in surplus:
                    st[("surplus_word", w, sclass(a))] += 1
                if hit:
                    errors.append(f"Line {ln}: {w} has {len(take) + len(hit)} of its {ar} arguments")
                    flags.add("surplus")
                    take = take + hit   # "the item carries it too ... so the keyword gives no number"
                elif DIAG is not None:
                    DIAG[("surplus_dropped_silently", w, tuple(sclass(a) for a in surplus[:2]))] += 1
            if w == "BYTE_ORDER" and take:
                cls = ("ok" if take[0].upper() in BYTE_ORDER_OK else
                       "mixed_msw" if take[0].upper() in BYTE_ORDER_MIXED else
                       "quoted" if take[0].startswith('"') else "other")
                st[("byte_order_arg", cls)] += 1
        items.append((w, take, ln, flags))
        i = j
    return items


def tag_sizes(seen, el, kind, span):
    """CTX *sizes* as regrouped at round 2 (E3S-19, E3S-23). Returns (agree, smallest, largest)."""
    byte = []
    for kw in ("DATA_SIZE", "LENGTH"):
        for args, _ in seen.get(kw, []):
            v = numword(args[0]) if len(args) == 1 else None
            if v is not None:
                byte.append(v)
    counts = []
    for kw in ("NUMBER", "ARRAY_SIZE"):
        for args, _ in seen.get(kw, []):
            v = numword(args[0]) if len(args) == 1 else None
            if v is not None:
                counts.append(v)
    for args, _ in seen.get("MATRIX_DIM", []):
        nums = [numword(a) for a in args]
        if args and len(args) <= 3 and None not in nums:
            p = 1
            for x in nums:
                p *= x
            counts.append(p)
    if byte and not counts:
        counts = [1]
    if kind in FAMILY:
        cmp = byte + ([span] if (span is not None and byte) else [])
        agree = len(set(cmp)) <= 1
        vals = cmp
    else:
        agree = len(set(byte)) <= 1 and len(set(counts)) <= 1
        if el is not None and byte and counts:
            agree = agree and len(set(byte + [c * el for c in counts])) <= 1
            vals = byte + [c * el for c in counts]
        elif el is not None:
            vals = byte + [c * el for c in counts]
        else:
            # no element size: the groups are not compared with each other; the text names the group that disagrees
            vals = ((byte if len(set(byte)) > 1 else []) + (counts if len(set(counts)) > 1 else [])) or byte
    return agree, (min(vals) if vals else None), (max(vals) if vals else None), byte, counts


def read_tags(roots, errors, st):
    layouts = {}
    for s in walk(roots):
        if s["name"] == "RECORD_LAYOUT" and s["own"]:
            ws = [w for w, _ in s["own"] if w]
            for k, w in enumerate(ws):
                if w == "FNC_VALUES" and k + 2 < len(ws):
                    layouts[unq(ws[0])] = DT.get(ws[k + 2]); break
        if s["name"] not in ("MEASUREMENT", "CHARACTERISTIC") and s["own"]:
            ws = [w for w, _ in s["own"] if w]
            for k, w in enumerate(ws):
                if w == "BYTE_ORDER" and k + 1 < len(ws):
                    a = ws[k + 1].upper()
                    st[("byte_order_arg_in_" + ("RECORD_LAYOUT" if s["name"] == "RECORD_LAYOUT" else
                                                 "MOD_COMMON" if s["name"] == "MOD_COMMON" else "other_section"),
                        "ok" if a in BYTE_ORDER_OK else "mixed_msw" if a in BYTE_ORDER_MIXED else "other")] += 1
    tags = []
    for s in walk(roots):
        sec = s["name"]
        if sec not in ("MEASUREMENT", "CHARACTERISTIC"):
            continue
        words = s["own"]
        st["own_words_max"] = max(st.get("own_words_max", 0), len(words))
        name, long_id, hdr, rest = tag_header(sec, words)
        if s["end"] is None:
            errors.append(f"Line {s['start']}: {sec} {echo(name)} is not closed")
            continue
        t = {"section": sec, "name": name, "address": None, "length": None, "kind": None, "flags": set(),
             "end": s["end"]}
        hdr_addr, hdr_addr_bad, el = None, False, None
        if sec == "MEASUREMENT":
            el = DT.get(hdr[0]) if hdr else None
        elif len(hdr) == 7:
            t["kind"] = hdr[0]
            hdr_addr = numword(hdr[1])
            if hdr_addr is None:
                hdr_addr_bad = True
                errors.append(f"Line {s['start']}: address {echo(hdr[1])} is not a number")
            el = layouts.get(hdr[2]) or DT.get(hdr[2].upper())
        items = kw_lines(words, rest, errors, st)
        seen = collections.defaultdict(list)
        iflags = collections.defaultdict(set)
        for kw, args, ln, fl in items:
            if kw in seen:
                errors.append(f"Line {ln}: {kw} is declared twice in {sec} {echo(name)}")
            seen[kw].append((args, ln))
            iflags[kw] |= fl
        # address (READ.60 as corrected: E3S-21, -22, -24)
        addrs, no_addr = [], hdr_addr_bad
        if hdr_addr is not None:
            addrs.append(hdr_addr)
        for args, _ in seen.get("ECU_ADDRESS", []):
            v = numword(args[0]) if len(args) == 1 else None
            if v is None:
                no_addr = True
            else:
                addrs.append(v)
        if len(set(addrs)) > 1:
            errors.append(f"Line {s['start']}: {sec} {echo(name)} declares the addresses 0x{min(addrs):08X} and 0x{max(addrs):08X}")
            no_addr = True
        for kw in ("BIT_MASK", "BYTE_ORDER"):
            if len({tuple(a) for a, _ in seen.get(kw, [])}) > 1 or iflags[kw] & {"missing", "surplus"}:
                no_addr = True
        t["address"] = None if (no_addr or not addrs) else addrs[0]
        bo = seen.get("BYTE_ORDER")
        t["byte_order_word"] = bo[0][0][0] if bo and bo[0][0] else None
        # sizes and length (READ.59, .61; R-A2L-013 ... 017)
        no_number = any(iflags[kw] & {"missing", "surplus", "bad_count"} for kw in SIZE_KW)
        for kw in SIZE_KW:
            for args, _ in seen.get(kw, []):
                if any(numword(a) is None for a in args):
                    no_number = True
        agree, lo, hi, byte, counts = tag_sizes(seen, el, t["kind"], SPAN.get(name))
        if not agree:
            errors.append(f"Line {s['start']}: {sec} {echo(name)} declares the sizes {lo} and {hi}")
        length = None
        if agree and not no_number:
            if byte:
                length = byte[0]
            elif t["kind"] in FAMILY:
                length = SPAN.get(name)
                t["flags"].add("span_by_layout")
            elif sec == "MEASUREMENT" and el is not None:
                arr = [numword(a[0]) for a, _ in seen.get("ARRAY_SIZE", []) if a]
                md = [c for c in counts]
                length = el * (arr[0] if arr else (md[0] if md else 1))
            elif t["kind"] == "VALUE" and el is not None:
                length = el * (counts[0] if counts else 1)
            elif t["kind"] == "VAL_BLK" and el is not None and counts and counts != [1]:
                length = el * counts[0]
            elif t["kind"] == "ASCII":
                nums = [numword(a[0]) for a, _ in seen.get("NUMBER", []) if a]
                length = nums[0] if nums else (counts[0] if seen.get("MATRIX_DIM") else None)
        if length is not None and not 1 <= length <= MAXLEN:
            errors.append(f"Line {s['start']}: {sec} {echo(name)} has the length {length}, outside 1 to 1048576 bytes")
            length = None
        t["length"] = length
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


def nohdr(body, begin=20):
    return "\n" * (begin - 1) + '/begin MEASUREMENT XN\n' + body + "\n/end MEASUREMENT\n"


def show(tag, text, rules=("number",)):
    global RULE
    outs, last = [], None
    for rule in rules:
        RULE = rule
        r = read(text)
        t = r["tags"][0] if r["tags"] else None
        a = (f"0x{t['address']:X}" if isinstance(t["address"], int) else None) if t else "-"
        outs.append(f"{rule}: address={a} length={t['length'] if t else '-'}")
        last = r if rule == rules[0] else last
    RULE = "number"
    errs = last["errors"].as_list()
    print(f"[{tag}] " + " | ".join(outs) + f" || errors({rules[0]})={errs}")
    return last


def shapes():
    print("== [S3-SURPLUS] the split-address family against E3S-24 as corrected ('number') and three wider rules ==")
    for label, body in (
            ("ecu 0x1C2D 3E00 (one line)", " ECU_ADDRESS 0x1C2D 3E00"),
            ("ecu 0x1C2D / 3E00 (next line)", " ECU_ADDRESS 0x1C2D\n 3E00"),
            ("ecu 0x1C2D 3e00", " ECU_ADDRESS 0x1C2D 3e00"),
            ("ecu 0x1C2D3 E00", " ECU_ADDRESS 0x1C2D3 E00"),
            ("ecu 0x1C 2D3E00", " ECU_ADDRESS 0x1C 2D3E00"),
            ("ecu 0x1C2D3E0 0 (number word)", " ECU_ADDRESS 0x1C2D3E0 0"),
            ("ecu 0x1C2D 0x3E00 (number word)", " ECU_ADDRESS 0x1C2D 0x3E00"),
            ("ecu 0x1C2D3E00 \"4026\" (quoted)", ' ECU_ADDRESS 0x1C2D3E00 "4026"'),
            ("ecu 0x1C2D 3E00 then BIT_MASK", " ECU_ADDRESS 0x1C2D 3E00\n BIT_MASK 0x0FF0"),
            ("bitmask 0x0F F0", " ECU_ADDRESS 0x10\n BIT_MASK 0x0F F0"),
            ("length 1 6K", " ECU_ADDRESS 0x10\n LENGTH 1 6K"),
            ("length 2 4 (number word)", " ECU_ADDRESS 0x10\n LENGTH 2 4")):
        show("S3-SURPLUS " + label, meas("X", body), rules=RULES)
    print("== [S3-SIZES] E3S-19 (no datatype size) and E3S-23 (CURVE/MAP family) as regrouped ==")
    show("S3-SIZES no-dt DATA_SIZE 2 + LENGTH 8", nohdr(" ECU_ADDRESS 0x10\n DATA_SIZE 2\n LENGTH 8"))
    show("S3-SIZES no-dt LENGTH 8 + DATA_SIZE 2", nohdr(" ECU_ADDRESS 0x10\n LENGTH 8\n DATA_SIZE 2"))
    show("S3-SIZES no-dt LENGTH 4 + LENGTH 8", nohdr(" ECU_ADDRESS 0x10\n LENGTH 4\n LENGTH 8"))
    show("S3-SIZES no-dt DATA_SIZE 4 + LENGTH 4 (agree)", nohdr(" ECU_ADDRESS 0x10\n DATA_SIZE 4\n LENGTH 4"))
    show("S3-SIZES no-dt LENGTH 8 + ARRAY_SIZE 4 (counts alone)", nohdr(" ECU_ADDRESS 0x10\n LENGTH 8\n ARRAY_SIZE 4"))
    show("S3-SIZES no-dt LENGTH 8 + NUMBER 4 + ARRAY_SIZE 5", nohdr(" ECU_ADDRESS 0x10\n LENGTH 8\n NUMBER 4\n ARRAY_SIZE 5"))
    show("S3-SIZES undeclared VALUE LENGTH 4 + LENGTH 8", char("C", " LENGTH 4\n LENGTH 8", dep="RL_NONE"))
    show("S3-SIZES UWORD LENGTH 4 (one count 1 x 2)", meas("X", " ECU_ADDRESS 0x10\n LENGTH 4"))
    show("S3-SIZES UWORD LENGTH 2 (agree)", meas("X", " ECU_ADDRESS 0x10\n LENGTH 2"))
    show("S3-SIZES ASCII NUMBER 8 + LENGTH 8 on RL_U8", char("C", " NUMBER 8\n LENGTH 8", kind="ASCII", dep="UBYTE"))
    SPAN["M"] = 2266
    show("S3-SIZES MAP LENGTH 2264 (span 2266)", char("M", " LENGTH 2264", kind="MAP"))
    show("S3-SIZES MAP LENGTH 2266 (span 2266)", char("M", " LENGTH 2266", kind="MAP"))
    show("S3-SIZES MAP DATA_SIZE 2266 + LENGTH 2264", char("M", " DATA_SIZE 2266\n LENGTH 2264", kind="MAP"))
    show("S3-SIZES MAP MATRIX_DIM 4 + NUMBER 5 (counts not compared)", char("M", " MATRIX_DIM 4\n NUMBER 5", kind="MAP"))
    show("S3-SIZES MAP LENGTH x4", char("M", " LENGTH x4", kind="MAP"))
    SPAN.pop("M")
    show("S3-SIZES MAP LENGTH 2264, span unknown", char("M", " LENGTH 2264", kind="MAP"))
    print("== [S3-ADDR] E3S-21, E3S-22 as corrected; byte-order words outside the four ==")
    show("S3-ADDR BYTE_ORDER missing then LENGTH 2", meas("X", " ECU_ADDRESS 0x10\n BYTE_ORDER\n LENGTH 2"))
    show("S3-ADDR BIT_MASK missing then BYTE_ORDER", meas("X", " ECU_ADDRESS 0x10\n BIT_MASK\n BYTE_ORDER MSB_FIRST"))
    show("S3-ADDR hdr 0x20_00 + ECU_ADDRESS 0x3000", char("C", " ECU_ADDRESS 0x3000", addr="0x20_00"))
    show("S3-ADDR hdr 0x20_00 alone", char("C", " LENGTH 2", addr="0x20_00"))
    for word in ("MSB_FRIST", "MSB_FIRST_MSW_LAST", '"MSB_FIRST"', "1"):
        r = show(f"S3-ADDR BYTE_ORDER {word}", meas("X", f" ECU_ADDRESS 0x10\n BYTE_ORDER {word}"))
    print("== [S3-LINE] E3S-25: the words after a multi-line string carry the closing line ==")
    r = read('/begin PROJECT P ""\n/begin MEASUREMENT X ""\n UWORD CM_ID 0 0 0 65535\n FORMAT "a\nb" é /end MEASUREMENT\n/end PROJECT\n')
    x = [s for s in walk(r["roots"]) if s["name"] == "MEASUREMENT"][0]
    print(f"[S3-LINE] /end on line 5 -> end_line={x['end']}; errors={r['errors'].as_list()}")
    r = read('/begin PROJECT P ""\n/begin MEASUREMENT X ""\n UWORD CM_ID 0 0 0 65535\n FORMAT "a\nb" ECU_ADDRESS 0x10 FORMAT "c\nd" LENGTH 2\n/end MEASUREMENT\n/end PROJECT\n')
    print(f"[S3-LINE] two multi-line strings: tag address={r['tags'][0]['address']} length={r['tags'][0]['length']} "
          f"own-word lines={sorted({ln for w, ln in [s for s in walk(r['roots']) if s['name'] == 'MEASUREMENT'][0]['own']})}")


def corpus():
    global RULE
    from pathlib import Path
    agg = collections.Counter(); seen_sha = set()
    rule_cost = collections.Counter()
    t0 = time.perf_counter()
    if MODE == "tracked":  # the 35 tracked A2L files of the read-only e07fb00 clone
        import subprocess
        clone = Path(os.environ["B103_RUNNER_HOME"]) / "work" / "s19_app"
        files = [clone / p for p in subprocess.run(["git", "-C", str(clone), "ls-files", "*.a2l"], capture_output=True, text=True, check=True).stdout.split()]
    else:
        files = sorted((Path(os.environ["B103_RUNNER_HOME"]) / "a2l-corpus" / "files").iterdir())
    for f in files:
        if not f.is_file():
            continue
        raw = f.read_bytes(); sha = hashlib.sha256(raw).hexdigest()
        if sha in seen_sha:
            continue
        seen_sha.add(sha)
        agg["files"] += 1
        if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
            agg["utf16_bom"] += 1; continue
        text = raw.decode("utf-8", errors="replace")
        per_rule = {}
        for rule in RULES:
            RULE = rule
            try:
                r = read(text)
            except Exception as e:
                agg["model_exc_" + type(e).__name__] += 1; per_rule = None; break
            per_rule[rule] = r
        RULE = "number"
        if per_rule is None:
            continue
        r = per_rule["number"]
        if r["refusal"]:
            agg["refused_" + r["refusal"]] += 1
        for k, v in r["st"].items():
            if isinstance(k, tuple):
                agg[k] += v
        agg["own_words_max"] = max(agg["own_words_max"], r["st"].get("own_words_max", 0))
        agg["tags"] += len(r["tags"])
        agg["tags_with_address"] += sum(1 for t in r["tags"] if t["address"] is not None)
        agg["tags_with_length"] += sum(1 for t in r["tags"] if t["length"] is not None)
        for rule in RULES[1:]:
            o = per_rule[rule]
            for a, b in zip(r["tags"], o["tags"]):
                if a["address"] is not None and b["address"] is None:
                    rule_cost[(rule, "address_lost")] += 1
                if a["length"] is not None and b["length"] is None:
                    rule_cost[(rule, "length_lost")] += 1
    print(f"[CORP3] files={agg['files']} utf16_bom={agg['utf16_bom']} tags={agg['tags']} "
          f"with_address={agg['tags_with_address']} with_length={agg['tags_with_length']} own_words_max={agg['own_words_max']} "
          f"refused={ {k: v for k, v in agg.items() if isinstance(k, str) and k.startswith('refused_')} } "
          f"exceptions={ {k: v for k, v in agg.items() if isinstance(k, str) and k.startswith('model_exc')} or 0} s={time.perf_counter() - t0:.0f}")
    for k in sorted((k for k in agg if isinstance(k, tuple)), key=str):
        print(f"[CORP3] {agg[k]} x {k}")
    for rule in RULES[1:]:
        print(f"[CORP3-rule {rule}] tags that lose an address: {rule_cost[(rule, 'address_lost')]}; "
              f"lose a length: {rule_cost[(rule, 'length_lost')]} (against the records' rule 'number')")


if MODE == "shapes":
    shapes()
else:
    corpus()
