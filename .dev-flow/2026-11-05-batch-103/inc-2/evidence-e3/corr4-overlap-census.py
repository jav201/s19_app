"""E3 correction pass 4, Inc 2 (batch-103): census of R-A2L-DEF.138 over the tracked fixtures.

R-A2L-DEF.138 (round-4 ruling): an encode is refused A2L-DEF-OVERLAP when the bytes it would write
overlap the span of another object of the A2L file, unless both objects' bit masks were read and do
not overlap. This script counts, per tracked .a2l file, the objects whose encode the row refuses:

  object      every MEASUREMENT and CHARACTERISTIC tag of the file, in file order (the tag table);
  span        [address, address + length - 1]; length = the tag's, else, for a MEASUREMENT, the
              size of its datatype x its MATRIX_DIM (R-A2L-014, the E2-1 fill); no address or no
              length -> no span (the object is counted apart as "address, no length");
  mask read   the bit mask the records after this pass read (R-A2L-DEF.18/.19): the record holds the
              word BIT_MASK and a readable word after it; the text of the object (reading W) holds
              the letters BIT_MASK exactly once; no section of that text ends inside an open
              comment or quote; no /begin word outside comments and quotes in that text; the kind
              is number or enum; the datatype is known and the mask fits it (_check_bit_mask);
              anything else -> no mask read;
  exempt      both masks read and the two objects select no common memory bit (each mask mapped
              onto the bytes of its span in its byte order);
  refused     the object's span overlaps the span of another object, and that pair is not exempt.
              Category A: some non-exempt partner where at least one of the two has no mask read
              ("overlap without both masks read"); category B: refused only by partners where both
              masks were read but select a common bit.
  describe-clean (approx.)  the object would otherwise reach an encode: a scalar kind (VALUE,
              ASCII, MEASUREMENT with MATRIX_DIM 1 or none), an address and a length, a datatype
              whose size equals the length (number/enum), no mask refusal. Method and table checks
              are not emulated, so this is an upper bound of the encodes the row refuses.

The text-of-the-object helpers are copied from evidence-e3/sec-r4-probe.py (round-4 security probe,
reading W and its "pieces open" and "mid-line /begin" rules = the records after this pass). Read only:
the base parser is imported from the clone; nothing is written but the list file named in argv[3].
Extra (not one of the 35): the release case 08 written by the clone's own generator at 1 MiB, seed
20260001, into argv[2] (clean and issues A2L).
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


def census(path, label, data, report, listing):
    tags = data["tags"]
    secs = [s for s in walk(data["sections"]) if s["name"] in ("MEASUREMENT", "CHARACTERISTIC")]
    if len(secs) != len(tags):
        print(f"[FX] {label}: tag/section count mismatch {len(tags)} vs {len(secs)} - SKIPPED")
        return None
    objs = []
    addr_no_len = 0
    for idx, (tag, sec) in enumerate(zip(tags, secs)):
        kind = scalar_kind(tag)
        dt = datatype(tag, sec, data) if (kind == "number/enum" or tag["section"] == "MEASUREMENT") else None
        length = tag.get("length")
        if length is None and tag["section"] == "MEASUREMENT" and dt:
            length = a.DATATYPE_SIZES[dt] * (tag.get("matrix_dim") or 1)
        addr = tag.get("address")
        if addr is None:
            continue
        if not length or length < 1:
            addr_no_len += 1
            continue
        mask, mask_refused = mask_reading(tag, sec, dt, kind)
        order = tag.get("effective_byte_order") or "little"
        clean = (kind == "text" or (kind == "number/enum" and dt is not None and a.DATATYPE_SIZES[dt] == length)) and not mask_refused
        objs.append(dict(i=idx, name=tag["name"], start=addr, end=addr + length - 1, length=length, order=order,
                         mask=mask, bits=selected_bits(addr, length, order, mask), clean=clean,
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
    clean_ref = [o for o in refused if o["clean"]]
    masked = sum(1 for o in objs if o["mask"] is not None)
    dup = sum(1 for _n, c in collections.Counter(t["name"] for t in tags).items() if c > 1)
    report.append((label, len(tags), len(objs), addr_no_len, masked, pairs, exempt, len(refused), cat_a, cat_b, len(clean_ref), dup))
    print(f"[FX] {label}: tags={len(tags)} spans={len(objs)} addr-no-len={addr_no_len} masks-read={masked} "
          f"overlapping-pairs={pairs} exempt-pairs={exempt} | refused={len(refused)} (A={cat_a}, B-only={cat_b}) "
          f"describe-clean-refused={len(clean_ref)} | duplicate-names={dup}")
    if refused:
        groups = collections.OrderedDict()
        for o in sorted(refused, key=lambda o: (o["start"], o["i"])):
            groups.setdefault(o["start"], []).append(o)
        listing.append(f"## {label}: {len(refused)} refused ({cat_a} A, {cat_b} B-only), {len(clean_ref)} describe-clean")
        full = len(refused) <= 400
        for start, os_ in groups.items():
            if full:
                for o in os_:
                    listing.append(f"{label} | {o['name']} | 0x{o['start']:X} | {o['length']} | "
                                   f"{'A' if o['catA'] else 'B'} | mask={'-' if o['mask'] is None else hex(o['mask'])} | "
                                   f"clean={'y' if o['clean'] else 'n'} | shared with {o['first'][1]}")
            else:
                listing.append(f"{label} | start 0x{start:X} | {len(os_)} objects | A={sum(1 for o in os_ if o['catA'])} | "
                               f"clean={sum(1 for o in os_ if o['clean'])} | first: {', '.join(o['name'] for o in os_[:3])}")
    return refused


files = subprocess.run(["git", "-C", str(repo), "ls-files", "*.a2l"], capture_output=True, text=True, check=True).stdout.split()
print(f"tracked .a2l files: {len(files)}")
report, listing = [], []
t0 = time.perf_counter()
for f in files:
    data = a.parse_a2l_file(repo / f)
    census(repo / f, f, data, report, listing)
t1 = time.perf_counter()
tot = [sum(r[k] for r in report) for k in range(1, 12)]
print(f"[FX-total] files={len(report)} tags={tot[0]} spans={tot[1]} addr-no-len={tot[2]} masks-read={tot[3]} "
      f"overlapping-pairs={tot[4]} exempt-pairs={tot[5]} | refused={tot[6]} (A={tot[7]}, B-only={tot[8]}) "
      f"describe-clean-refused={tot[9]} | duplicate-names={tot[10]} | {t1 - t0:.1f} s")
print("files with refusals:", sum(1 for r in report if r[7]))

print("\n== extra: release case 08 (generator of the clone, seed 20260001, 1 MiB) ==")
out = scratch / "case08"
gen = subprocess.run([sys.executable, "-I", str(repo / "tools/synth/make_release_case.py"), "--out", str(out),
                      "--seed", "20260001", "--size-mb", "1"], capture_output=True, text=True, cwd=str(scratch))
print("generator exit", gen.returncode, (gen.stderr or "").strip()[-200:])
for name in ("firmware.a2l", "firmware_issues.a2l"):
    p = out / name
    if p.exists():
        census(p, "case08/" + name, a.parse_a2l_file(p), [], listing)
list_path.write_text("\n".join(listing) + "\n", encoding="utf-8")
print(f"list written: {list_path.name}, {len(listing)} lines")
