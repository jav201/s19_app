"""E3 correction pass 4b, Inc 2 (batch-103): census of R-A2L-DEF.138 with the round-4 census ruling's index.

Round-4 census ruling (E3-rulings.md, "Round 4 census ruling"): the span index of R-A2L-DEF.138 holds only
objects whose address the A2L DECLARES - a CHARACTERISTIC's header address word, or an ECU_ADDRESS line of a
MEASUREMENT - and 0x0 is a valid declared address (not special). This script is corr4-overlap-census.py
(predecessor; the same helpers, copied unchanged: the text of the object, reading W; the mask reading of
R-A2L-DEF.18/.19; the bits an object selects) with these changes only:

  declared    read from the section text here, not from tag["address"]. Two readings, both run:
              "applied" (the records): the address the A2L declares as the tag table reads it - a
              CHARACTERISTIC's header address word (assemble_characteristic_header(lines)["address_inline"], the
              word after the kind word), replaced by the last ECU_ADDRESS line of the object's own lines when it
              has one (int(word, 0)); a MEASUREMENT's last ECU_ADDRESS line. It is checked equal to
              tag["address"] (the address the definition writes at) for every object ("applied-vs-tag", expected
              0: the tag table never fills an address).
              "literal" (the ruling's list word for word): a CHARACTERISTIC's header address word only; a
              MEASUREMENT's ECU_ADDRESS line. Objects whose literal address differs from the tag's are listed
              ("literal-vs-tag"), and the literal reading's refusals are given per file where they differ.
  index       only objects with a declared address (None left out; 0 kept) and a length (the tag's, else
              R-A2L-014's fill for a MEASUREMENT); "undeclared" counts the objects left out for no declared
              address (they are refused A2L-DEF-ADDRESS and are never encoded).
  reason      for each refused object: "declared overlap" - some partner of a non-exempt pair where at least
              one of the two masks was not read (no BIT_MASK, or a refusal of R-A2L-DEF.19); "shared mask bits"
              - refused only by partners where both masks were read and select a common bit.
  at 0x0      refused objects whose span starts at 0x0, per file.
  AXIS_PTS    informational (the tag table holds no AXIS_PTS and the model has no AXIS_PTS length rule): per
              file the AXIS_PTS sections, those with a readable header address word (the third word of the
              record), those with an ECU_ADDRESS line, and those whose header address byte lies inside the span
              of an indexed object (a lower bound of what an index with AXIS_PTS would add).

Read only: the base parser is imported from the clone; nothing is written but the list file (argv[3]) and
the release case 08 that the clone's own generator writes into argv[2] (seed 20260001, 1 MiB).
"""
import bisect
import collections
import pathlib
import re
import subprocess
import sys
import time

repo = pathlib.Path(sys.argv[1]); scratch = pathlib.Path(sys.argv[2]); list_path = pathlib.Path(sys.argv[3])
sys.path.insert(0, str(repo))
import s19_app  # noqa: E402
import s19_app.tui.a2l as a  # noqa: E402

print("s19_app.__file__ =", s19_app.__file__)

# ---- text of the object, reading W (copied from sec-r4-probe.py) ----------------------------------
OBJECT_SECTIONS = {"MEASUREMENT", "CHARACTERISTIC", "AXIS_PTS", "INSTANCE", "BLOB", "TYPEDEF_MEASUREMENT",
                   "TYPEDEF_CHARACTERISTIC", "TYPEDEF_AXIS", "TYPEDEF_BLOB", "TYPEDEF_STRUCTURE"}
HEX = re.compile(r"0x[0-9A-Fa-f]{1,16}", re.ASCII); DEC = re.compile(r"[0-9]{1,20}", re.ASCII)


def readable(w):
    return w is not None and (HEX.fullmatch(w) or DEC.fullmatch(w)) is not None


def open_state(text):
    i, n, s = 0, len(text), None
    while i < n:
        c = text[i]
        if s == "quote":
            if c == '"' and text[i - 1] != "\\":
                s = None
            i += 1; continue
        if s == "comment":
            if c == "*" and i + 1 < n and text[i + 1] == "/":
                s = None; i += 2; continue
            i += 1; continue
        if c == '"':
            s = "quote"; i += 1; continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            s = "comment"; i += 2; continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        i += 1
    return s


def ref_tokens(text):
    toks, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1; continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            if j < 0:
                toks.append(("ERR", "unterminated comment")); break
            i = j + 2; continue
        if text.startswith("//", i):
            j = text.find("\n", i); i = n if j < 0 else j; continue
        if c == '"':
            j = i + 1
            while j < n and not (text[j] == '"' and text[j - 1] != "\\"):
                j += 1
            if j >= n:
                toks.append(("ERR", "unterminated string")); break
            toks.append(("STR", text[i + 1:j])); i = j + 1; continue
        j = i
        while j < n and not text[j].isspace() and text[j] != '"' and not text.startswith("/*", j) and not text.startswith("//", j):
            j += 1
        toks.append(("ID", text[i:j])); i = j
    return toks


def begin_after_name_longid(meta):
    _name, rest = a._parse_first_field(meta or "")
    _longid, rest2 = a._parse_first_field(rest or "")
    return rest2 or ""


def nonobj_desc(s):
    for c in s.get("children") or []:
        if c.get("name") in OBJECT_SECTIONS:
            continue
        yield c
        yield from nonobj_desc(c)


def text_W(s):
    parts = [begin_after_name_longid(s["meta"])] + list(s.get("lines") or [])
    for c in nonobj_desc(s):
        parts += [c.get("meta", "")] + list(c.get("lines") or [])
    return "\n".join(parts)


def pieces_open(s):
    if open_state("\n".join([s["meta"]] + list(s["lines"]))):
        return True
    return any(open_state("\n".join([c.get("meta", "")] + list(c.get("lines") or []))) for c in nonobj_desc(s))


def midline_begin(s):
    pieces = [s["meta"]] + list(s["lines"]) + [x for c in nonobj_desc(s) for x in [c.get("meta", "")] + list(c.get("lines") or [])]
    if not any("/begin" in p.lower() for p in pieces):   # fast path, same result
        return False
    return any(k == "ID" and v.lower() == "/begin" for piece in pieces for k, v in ref_tokens(piece))


# ---- the model's reading of one object (as the records state it after this pass) ---------------------
SIGNED = {"SBYTE", "SWORD", "SLONG", "A_INT64"}
FLOATS = {"FLOAT16_IEEE", "FLOAT32_IEEE", "FLOAT64_IEEE"}


def walk(secs):
    for s in secs:
        yield s
        yield from walk(s.get("children") or [])


def scalar_kind(tag):
    if tag["section"] == "CHARACTERISTIC":
        ct = str(tag.get("char_type") or "").upper()
        return {"VALUE": "number/enum", "ASCII": "text"}.get(ct)
    md = tag.get("matrix_dim")
    return "number/enum" if md in (None, 1) else None


def datatype(tag, sec, data):
    dt = str(tag.get("datatype") or "").upper()
    if dt in a.DATATYPE_SIZES:
        return dt
    if tag["section"] == "MEASUREMENT":
        words = a._flatten_body_tokens([sec["meta"]] + list(sec["lines"]))
        if len(words) > 2 and words[2].upper() in a.DATATYPE_SIZES:
            return words[2].upper()
        return None
    lay = a._resolve_record_layout(tag.get("record_layout_name"), data["record_layouts_by_name"]) or {}
    dt = str(lay.get("decode_type") or "").upper()
    return dt if dt in a.DATATYPE_SIZES else None


def check_bit_mask(m, dt):
    if m <= 0 or dt in FLOATS:
        return False
    width = 8 * a.DATATYPE_SIZES[dt]
    if m >= 1 << width:
        return False
    if dt in SIGNED and (m & 1) and (m >> (width - 1)) & 1:
        return False
    return True


def mask_reading(tag, sec, dt, kind):
    """(mask or None, mask refusal True/False)."""
    raw = "\n".join([sec["meta"]] + list(sec["lines"]))
    letters = text_W(sec).upper().count("BIT_MASK")
    words = None
    word = None
    if "BIT_MASK" in raw or letters:
        words = a._flatten_body_tokens([sec["meta"]] + list(sec["lines"]))
        n = 8 if tag["section"] == "MEASUREMENT" else 9
        rest = words[n:]
        if "BIT_MASK" in rest:
            i = rest.index("BIT_MASK")
            word = rest[i + 1] if i + 1 < len(rest) else None
            if word is None:
                word = ""
    # the text clauses of R-A2L-DEF.19 (they refuse whatever the kind)
    if pieces_open(sec) or midline_begin(sec):
        return None, True
    if letters > 1 or (letters == 1 and word is None) or (letters == 0 and word is not None):
        return None, True
    if word is None:
        return None, False                    # no BIT_MASK: unmasked, no mask read
    if kind == "text" or not readable(word):
        return None, True                     # a text object with a mask; an unreadable word
    if kind != "number/enum" or dt is None:
        return None, False                    # refused earlier (KIND / DATATYPE): no mask recorded
    m = int(word, 16) if word[:2].lower() == "0x" else int(word)
    if not check_bit_mask(m, dt):
        return None, True
    return m, False


def selected_bits(address, length, order, mask):
    """address -> the bits of that byte the object selects (every bit when mask is None)."""
    if mask is None:
        return None
    out = {}
    for i in range(length):           # i = 0 is the least significant byte of the span
        b = (mask >> (8 * i)) & 0xFF
        if b:
            addr = address + i if order == "little" else address + length - 1 - i
            out[addr] = b
    return out



def ecu_address_line(sec):
    """(has an ECU_ADDRESS line, the value of the last one or None) - the tag table's rule."""
    has, addr = False, None
    for line in sec.get("lines") or []:
        parts = line.strip().split()
        if len(parts) >= 2 and parts[0] == "ECU_ADDRESS":
            has = True
            try:
                addr = int(parts[1], 0)
            except ValueError:
                addr = None
    return has, addr


def declared_address(tag, sec, mode):
    has_line, line_addr = ecu_address_line(sec)
    if tag["section"] == "CHARACTERISTIC":
        hdr = a.assemble_characteristic_header(list(sec.get("lines") or []))
        header = None if hdr is None else hdr.get("address_inline")
        if mode == "applied" and has_line:
            return line_addr
        return header
    return line_addr


def axis_pts_info(data, objs):
    axs = [s for s in walk(data["sections"]) if s["name"] == "AXIS_PTS"]
    readable_addr = ecu_line = inside = 0
    spans = sorted((o["start"], o["end"]) for o in objs)
    keys = [s for s, _e in spans]
    max_len = max((e - s + 1 for s, e in spans), default=0)
    for s in axs:
        words = a._flatten_body_tokens([s["meta"]] + list(s.get("lines") or []))
        if ecu_address_line(s)[0]:
            ecu_line += 1
        w = words[2] if len(words) > 2 else None
        if not readable(w):
            continue
        readable_addr += 1
        ad = int(w, 16) if w[:2].lower() == "0x" else int(w)
        lo = bisect.bisect_left(keys, ad - max_len + 1)
        hi = bisect.bisect_right(keys, ad)
        if any(spans[k][0] <= ad <= spans[k][1] for k in range(lo, hi)):
            inside += 1
    return len(axs), readable_addr, ecu_line, inside


def census(path, label, data, report, listing, mode="applied", quiet=False):
    tags = data["tags"]
    secs = [s for s in walk(data["sections"]) if s["name"] in ("MEASUREMENT", "CHARACTERISTIC")]
    if len(secs) != len(tags):
        print(f"[FX] {label}: tag/section count mismatch {len(tags)} vs {len(secs)} - SKIPPED")
        return None
    objs = []
    undeclared = addr_no_len = vs_tag = declared_zero = 0
    for idx, (tag, sec) in enumerate(zip(tags, secs)):
        decl = declared_address(tag, sec, mode)
        if decl != tag.get("address"):
            vs_tag += 1
            if vs_tag <= 10:
                print(f"    {mode}-vs-tag: {label} | {tag['section']} {tag['name']} | tag {tag.get('address')!r} | "
                      f"{mode} {decl!r}")
        if decl is None:
            undeclared += 1
            continue
        if decl == 0:
            declared_zero += 1
        kind = scalar_kind(tag)
        dt = datatype(tag, sec, data) if (kind == "number/enum" or tag["section"] == "MEASUREMENT") else None
        length = tag.get("length")
        if length is None and tag["section"] == "MEASUREMENT" and dt:
            length = a.DATATYPE_SIZES[dt] * (tag.get("matrix_dim") or 1)
        if not length or length < 1:
            addr_no_len += 1
            continue
        mask, mask_refused = mask_reading(tag, sec, dt, kind)
        order = tag.get("effective_byte_order") or "little"
        clean = (kind == "text" or (kind == "number/enum" and dt is not None and a.DATATYPE_SIZES[dt] == length)) and not mask_refused
        objs.append(dict(i=idx, name=tag["name"], start=decl, end=decl + length - 1, length=length, order=order,
                         mask=mask, bits=selected_bits(decl, length, order, mask), clean=clean,
                         catA=False, catB=False, first=None))
    order_ix = sorted(range(len(objs)), key=lambda k: (objs[k]["start"], objs[k]["i"]))
    starts = [objs[k]["start"] for k in order_ix]
    pairs = exempt = 0
    for pos, k in enumerate(order_ix):
        o = objs[k]
        hi = bisect.bisect_right(starts, o["end"])
        for q in order_ix[pos + 1:hi]:
            p = objs[q]
            pairs += 1
            if o["bits"] is not None and p["bits"] is not None and not any(
                    (o["bits"].get(ad, 0) & b) for ad, b in p["bits"].items()):
                exempt += 1
                continue
            cat = "catA" if (o["mask"] is None or p["mask"] is None) else "catB"
            for x, y in ((o, p), (p, o)):
                x[cat] = True
                if x["first"] is None or y["i"] < x["first"][0]:
                    x["first"] = (y["i"], y["name"])
    refused = [o for o in objs if o["catA"] or o["catB"]]
    cat_a = sum(1 for o in refused if o["catA"])
    cat_b = sum(1 for o in refused if o["catB"] and not o["catA"])
    at_zero = sum(1 for o in refused if o["start"] == 0)
    clean_ref = [o for o in refused if o["clean"]]
    masked = sum(1 for o in objs if o["mask"] is not None)
    dup = sum(1 for _n, c in collections.Counter(t["name"] for t in tags).items() if c > 1)
    ax = axis_pts_info(data, objs)
    report.append((label, len(tags), len(objs), undeclared, addr_no_len, vs_tag, declared_zero, masked, pairs,
                   exempt, len(refused), cat_a, cat_b, at_zero, len(clean_ref), dup) + ax)
    if not quiet:
        print(f"[FX] {label}: tags={len(tags)} indexed={len(objs)} undeclared={undeclared} declared-no-len={addr_no_len} "
              f"{mode}-vs-tag={vs_tag} declared-0x0={declared_zero} masks-read={masked} overlapping-pairs={pairs} "
              f"exempt-pairs={exempt} | refused={len(refused)} (declared-overlap={cat_a}, shared-mask-bits-only={cat_b}, "
              f"at-0x0={at_zero}) describe-clean-refused={len(clean_ref)} | duplicate-names={dup} | "
              f"AXIS_PTS={ax[0]} (header-address={ax[1]}, ECU_ADDRESS-line={ax[2]}, address-inside-an-indexed-span={ax[3]})")
    if refused and listing is not None:
        groups = collections.OrderedDict()
        for o in sorted(refused, key=lambda o: (o["start"], o["i"])):
            groups.setdefault(o["start"], []).append(o)
        listing.append(f"## {label}: {len(refused)} refused ({cat_a} declared overlap, {cat_b} shared mask bits only, "
                       f"{at_zero} at 0x0), {len(clean_ref)} describe-clean")
        full = len(refused) <= 400
        for start, os_ in groups.items():
            if full:
                for o in os_:
                    listing.append(f"{label} | {o['name']} | 0x{o['start']:X} | {o['length']} | "
                                   f"{'declared overlap' if o['catA'] else 'shared mask bits'} | "
                                   f"mask={'-' if o['mask'] is None else hex(o['mask'])} | "
                                   f"clean={'y' if o['clean'] else 'n'} | shared with {o['first'][1]}")
            else:
                listing.append(f"{label} | start 0x{start:X} | {len(os_)} objects | declared overlap="
                               f"{sum(1 for o in os_ if o['catA'])} | clean={sum(1 for o in os_ if o['clean'])} | "
                               f"first: {', '.join(o['name'] for o in os_[:3])}")
    return refused


def total_line(tag, report, secs):
    tot = [sum(r[k] for r in report) for k in range(1, len(report[0]))]
    print(f"[{tag}] files={len(report)} tags={tot[0]} indexed={tot[1]} undeclared={tot[2]} declared-no-len={tot[3]} "
          f"vs-tag={tot[4]} declared-0x0={tot[5]} masks-read={tot[6]} overlapping-pairs={tot[7]} exempt-pairs={tot[8]} "
          f"| refused={tot[9]} (declared-overlap={tot[10]}, shared-mask-bits-only={tot[11]}, at-0x0={tot[12]}) "
          f"describe-clean-refused={tot[13]} | duplicate-names={tot[14]} | AXIS_PTS={tot[15]} (header-address={tot[16]}, "
          f"ECU_ADDRESS-line={tot[17]}, address-inside-an-indexed-span={tot[18]}) | {secs:.1f} s")
    print(f"[{tag}] files with refusals: {sum(1 for r in report if r[10])}")


files = subprocess.run(["git", "-C", str(repo), "ls-files", "*.a2l"], capture_output=True, text=True, check=True).stdout.split()
print(f"tracked .a2l files: {len(files)}")
print("\n== applied reading (the records): the tag table's declared address ==")
report, listing, parsed = [], [], {}
t0 = time.perf_counter()
for f in files:
    parsed[f] = a.parse_a2l_file(repo / f)
    census(repo / f, f, parsed[f], report, listing, "applied")
t1 = time.perf_counter()
total_line("FX-total applied", report, t1 - t0)

print("\n== literal reading (the ruling's list word for word): files whose refusals differ ==")
lit = []
t2 = time.perf_counter()
for f in files:
    census(repo / f, f, parsed[f], lit, None, "literal", quiet=True)
t3 = time.perf_counter()
for r_app, r_lit in zip(report, lit):
    if r_app[10] != r_lit[10] or r_app[2] != r_lit[2]:
        print(f"[FX-literal] {r_lit[0]}: indexed={r_lit[2]} (applied {r_app[2]}), refused={r_lit[10]} (applied {r_app[10]})")
total_line("FX-total literal", lit, t3 - t2)

print("\n== extra: release case 08 (generator of the clone, seed 20260001, 1 MiB) ==")
out = scratch / "case08"
gen = subprocess.run([sys.executable, "-I", str(repo / "tools/synth/make_release_case.py"), "--out", str(out),
                      "--seed", "20260001", "--size-mb", "1"], capture_output=True, text=True, cwd=str(scratch))
print("generator exit", gen.returncode, (gen.stderr or "").strip()[-200:])
for name in ("firmware.a2l", "firmware_issues.a2l"):
    p = out / name
    if p.exists():
        census(p, "case08/" + name, a.parse_a2l_file(p), [], listing, "applied")
list_path.write_text("\n".join(listing) + "\n", encoding="utf-8")
print(f"list written: {list_path.name}, {len(listing)} lines")
