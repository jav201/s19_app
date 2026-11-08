"""E5 security probe, batch-103 Inc 2a, on the REAL code: fail-closed describe/decode (R-A2L-DEF.58.2), the echo cap and
message bound (R-A2L-DEF.151), control characters and markup (R-A2L-DEF.137, .151), immutability (.149/5) and
independence of decodes.

Modes:
  shapes             hand-built hostile shapes (the .58.2 corpus re-run on the real code, plus E5's own: hex numbers past
                     Python's 4,300-digit int-to-str limit in LENGTH / DATA_SIZE / NUMBER / MATRIX_DIM, a hex address of
                     1,500 digits, lower-case table type words, bidi / format / separator characters, markup, control
                     characters)
  nest               nesting depth: parse_a2l_file at the base stack, describe_definitions at the base stack + k frames
  corpus <lists>     the 203 files clean: every message / display text checked; immutability of every stored form and
                     definition; a2l_data unchanged; describing names together equals each alone (a seeded sample);
                     decode order independence
  mutate <lists>     seeded mutations (seed 20261107 + file index) of every file, describe all + decode all on 4 images
Every describe and decode outcome is checked: exceptions (type and the a2l_definition function:line they left from),
refusal messages <= 1,024 characters, the longest space-free run of a message (an echoed word is <= 257 characters with
no space), characters outside printable ASCII / U+FFFD / U+2026 in a message, control characters (U+0000-U+001F,
U+007F-U+009F) and other Cc / Cf / Zl / Zp characters and markup brackets in a display text.
Only derived counts leave the runner (no file content). THROWAWAY. Usage: python -I -B sec-e5-hostile.py <tree> <scratch> <mode> [lists]
"""
import dataclasses, hashlib, os, pathlib, pickle, random, sys, threading, traceback, types, unicodedata
from collections import Counter
from concurrent.futures import ProcessPoolExecutor

sys.dont_write_bytecode = True
TREE, SCR, MODE = sys.argv[1], pathlib.Path(sys.argv[2]), sys.argv[3]
LISTS = sys.argv[4:]
sys.path.insert(0, TREE)
import s19_app  # noqa: E402
import s19_app.tui.a2l as a  # noqa: E402
import s19_app.tui.a2l_definition as D  # noqa: E402

W = SCR / "work"
W.mkdir(parents=True, exist_ok=True)
MSG_OK = set(chr(c) for c in range(0x20, 0x7F)) | {"�", "…"}


class Fill(dict):
    """An image holding every address, each byte `b`."""

    def __init__(self, b):
        super().__init__(); self.b = b
    def __contains__(self, k): return isinstance(k, int)
    def __getitem__(self, k): return self.b


IMAGES = (Fill(0x00), Fill(0xFF), Fill(0xA5), {})


def where(ex):
    tb = traceback.extract_tb(ex.__traceback__)
    ours = [fr for fr in tb if fr.filename.endswith("a2l_definition.py")]
    fr = (ours or tb)[-1]
    return f"{type(ex).__name__} at {pathlib.Path(fr.filename).name}:{fr.name}:{fr.lineno}"


def check_msg(m, out, tag):
    out[f"{tag} messages"] += 1
    if len(m) > 1024:
        out[f"{tag} message > 1024"] += 1
    run = max((len(w) for w in m.split(" ")), default=0)
    out[f"{tag} longest word max"] = max(out[f"{tag} longest word max"], run)
    out[f"{tag} message max"] = max(out[f"{tag} message max"], len(m))
    if run > 260:
        out[f"{tag} word > 260"] += 1
    bad = [ch for ch in m if ch not in MSG_OK]
    if bad:
        out[f"{tag} message foreign chars"] += 1
    if "[" in m:
        out[f"{tag} message with ["] += 1


def check_text(t, out, tag):
    out[f"{tag} texts"] += 1
    if any(ord(ch) <= 0x1F or 0x7F <= ord(ch) <= 0x9F for ch in t):
        out[f"{tag} text control (.137)"] += 1
    cats = {unicodedata.category(ch) for ch in t if ord(ch) > 0x9F}
    for c in ("Cf", "Zl", "Zp"):
        if c in cats:
            out[f"{tag} text {c}"] += 1
    if "[" in t:
        out[f"{tag} text with ["] += 1


def run_data(data, out, tag, names=None):
    names = names if names is not None else [t.get("name") for t in data.get("tags") or [] if t.get("name") is not None]
    try:
        defs = D.describe_definitions(names, data)
    except Exception as ex:  # noqa: BLE001 - counted: an exception is the finding
        out[f"{tag} describe exception"] += 1
        out[f"EXC describe {where(ex)}"] += 1
        return None
    out[f"{tag} definitions"] += len(defs)
    for d in defs.values():
        if d.refusal is not None:
            out[f"{tag} refused"] += 1
            check_msg(d.refusal.message, out, tag)
        for img in IMAGES:
            try:
                r = D.decode_definition(d, data, img)
            except Exception as ex:  # noqa: BLE001
                out[f"{tag} decode exception"] += 1
                out[f"EXC decode {where(ex)}"] += 1
                continue
            out[f"{tag} decodes"] += 1
            if isinstance(r, D.Refusal):
                check_msg(r.message, out, tag)
            else:
                check_text(r.text, out, tag)
    return defs


def parse_text(txt, tag):
    p = W / f"{os.getpid()}_{tag}.a2l"
    p.write_text(txt, encoding="utf-8")
    try:
        return a.parse_a2l_file(p)
    finally:
        p.unlink()


# ------------------------------------------------------------------ shapes
HEAD = 'ASAP2_VERSION 1 71\n/begin PROJECT P ""\n/begin MODULE M ""\n/begin MOD_COMMON ""\nBYTE_ORDER MSB_LAST\n/end MOD_COMMON\n'
TAIL = "/end MODULE\n/end PROJECT\n"
RL = '/begin RECORD_LAYOUT RL_U8\n FNC_VALUES 1 UBYTE ROW_DIR DIRECT\n/end RECORD_LAYOUT\n' \
     '/begin RECORD_LAYOUT RL_F32\n FNC_VALUES 1 FLOAT32_IEEE ROW_DIR DIRECT\n/end RECORD_LAYOUT\n'
HX = "0x" + "F" * 3700          # 16^3700 > 10^4300: str() of it raises ValueError on Python 3.11 (int max str digits)


def meas(name, extra, dt="UBYTE", cm="NO_COMPU_METHOD", addr="0x1000"):
    return f'/begin MEASUREMENT {name} "" {dt} {cm} 0 0 0 255\n ECU_ADDRESS {addr}\n{extra}/end MEASUREMENT\n'


def val(name, cm="NO_COMPU_METHOD", extra="", addr="0x1000", layout="RL_U8", kind="VALUE"):
    return f'/begin CHARACTERISTIC {name} ""\n {kind} {addr} {layout} 0 {cm} 0 255\n{extra}/end CHARACTERISTIC\n'


def cm(name, typ, body="", fmt='"%.3"'): return f'/begin COMPU_METHOD {name} "" {typ} {fmt} ""\n{body}/end COMPU_METHOD\n'
def vt(name, count, body): return f'/begin COMPU_VTAB {name} "" TAB_VERB {count}\n{body}/end COMPU_VTAB\n'
def ctab(name, body, kind="TAB_INTP"): return f'/begin COMPU_TAB {name} "" {kind} 2\n{body}/end COMPU_TAB\n'


SHAPES = {
    # E5's own: numbers past the int-to-str limit (the frozen reader parses them with int(x, 0), base 16 has no limit)
    "LEN-hex3700": meas("X", f" LENGTH {HX}\n"),
    "DATASIZE-hex3700": meas("X", f" DATA_SIZE {HX}\n"),
    "NUMBER-hex3700": val("T", extra=f" NUMBER {HX}\n", kind="ASCII"),
    "MATRIXDIM-hex3700": meas("X", f" MATRIX_DIM {HX}\n"),
    "MATRIXDIM-hex1000": meas("X", " MATRIX_DIM 0x" + "F" * 1000 + "\n"),
    "ADDR-hex1500": meas("X", "", addr="0x" + "F" * 1500),
    "ADDR-neg-hex1500": meas("X", "", addr="-0x" + "F" * 1500),
    "CHARADDR-hex1500": val("V", addr="0x" + "F" * 1500),
    # lower-case table type words (the frozen views upper-case them)
    "CASE-tab_intp": cm("CMI", "tab_intp", " COMPU_TAB_REF CT\n") + ctab("CT", " 0 0\n 100 100\n") + val("V", "CMI"),
    "CASE-TAB_INTP": cm("CMI", "TAB_INTP", " COMPU_TAB_REF CT\n") + ctab("CT", " 0 0\n 100 100\n") + val("V", "CMI"),
    "CASE-tab_verb": cm("CMV", "tab_verb", " COMPU_TAB_REF VT\n") + vt("VT", 1, ' 165 "x"\n') + val("V", "CMV"),
    # characters in texts and names
    "TEXT-bidi-sep": cm("CMV", "TAB_VERB", " COMPU_TAB_REF VT\n") + vt(
        "VT", 4, ' 0 "a‮bc"\n 255 "l1 l2"\n 165 "z​w﻿"\n 1 "p q؜"\n') + val("V", "CMV"),
    "TEXT-markup": cm("CMV", "TAB_VERB", " COMPU_TAB_REF VT\n") + vt(
        "VT", 2, ' 0 "[bold red]x[/]"\n 255 "[link=file:///x]y[/link]"\n') + val("V", "CMV")
        + val("[bold]N[/bold]", "CM_MISSING"),
    "TEXT-control": cm("CMV", "TAB_VERB", " COMPU_TAB_REF VT\n") + vt(
        "VT", 3, ' 0 "a\x1b[31mb"\n 255 "n\x00l\x7f"\n 165 "c\x85d\x9be"\n') + val("V", "CMV")
        + val("N\x1b[2Jx", "CM_MISSING"),
    # the .58.2 corpus (19 shapes), re-run on the real code
    "count-1e400": cm("CMV", "TAB_VERB", " COMPU_TAB_REF VT\n") + vt("VT", "1e400", ' 0 "a"\n') + val("V", "CMV"),
    "count-nan": cm("CMV", "TAB_VERB", " COMPU_TAB_REF VT\n") + vt("VT", "nan", ' 0 "a"\n') + val("V", "CMV"),
    "count-minus3": cm("CMV", "TAB_VERB", " COMPU_TAB_REF VT\n") + vt("VT", "-3", ' 0 "a"\n') + val("V", "CMV"),
    "count-2.5": cm("CMV", "TAB_VERB", " COMPU_TAB_REF VT\n") + vt("VT", "2.5", ' 0 "a"\n') + val("V", "CMV"),
    "mask-5000digits": val("V", extra=" BIT_MASK " + "9" * 5000 + "\n"),
    "format-5000digits": val("V", extra=' FORMAT "%.' + "9" * 5000 + '"\n', cm="CML") + cm("CML", "LINEAR", " COEFFS_LINEAR 1 0\n"),
    "mask-0xZZ": val("V", extra=" BIT_MASK 0xZZ\n"),
    "number-minus5": val("T", extra=" NUMBER -5\n", kind="ASCII"),
    "number-1048577": val("T", extra=" NUMBER 1048577\n", kind="ASCII"),
    "ecuaddr-minus0x10": meas("X", "", addr="-0x10"),
    "extlimits-nan": val("V", extra=" EXTENDED_LIMITS nan nan\n"),
    "coeffs-nan-inf": cm("CMR", "RAT_FUNC", " COEFFS nan inf 0 0 0 1\n") + val("V", "CMR"),
    "ratfunc-zero": cm("CMR", "RAT_FUNC", " COEFFS 0 0 0 0 0 0\n") + val("V", "CMR"),
    "vtab-esc-unterminated": cm("CMV", "TAB_VERB", " COMPU_TAB_REF VT\n") + vt("VT", 2, ' 0 "a\x1bb"\n 1 "open\n') + val("V", "CMV"),
    "float-enum-nonfinite": cm("CMV", "TAB_VERB", " COMPU_TAB_REF VT\n") + vt("VT", 1, ' 0 "z"\n') + val("F", "CMV", layout="RL_F32"),
    "mask-no-datatype": val("V", extra=" BIT_MASK 0x0F\n", layout="RL_NONE"),
    "nointp-names-vtab": cm("CMN", "TAB_NOINTP", " COMPU_TAB_REF VT\n") + vt("VT", 1, ' 0 "z"\n') + val("V", "CMN"),
    "intp-names-vtab": cm("CMI", "TAB_INTP", " COMPU_TAB_REF VT\n") + vt("VT", 1, ' 0 "z"\n') + val("V", "CMI"),
    "nan-x": cm("CMI", "TAB_INTP", " COMPU_TAB_REF CT\n") + ctab("CT", " 0 0\n nan 7\n 10 100\n") + val("V", "CMI"),
    "V171": None,
}


def shapes():
    out = Counter()
    for sid, body in SHAPES.items():
        if body is None:
            p = pathlib.Path(TREE) / "examples" / "case_00_public" / "ASAP2_Demo_V171.a2l"
            data = a.parse_a2l_file(p) if p.exists() else None
        else:
            try:
                data = parse_text(HEAD + RL + body + TAIL, sid)
            except Exception as ex:  # noqa: BLE001
                print(f"  {sid:22} parse exception {type(ex).__name__} (frozen reader)", flush=True)
                continue
        if data is None:
            print(f"  {sid:22} not found", flush=True)
            continue
        o = Counter()
        defs = run_data(data, o, "s")
        out.update(o)
        exc = {k[4:]: v for k, v in o.items() if k.startswith("EXC ")}
        lines = []
        if defs is not None and body is not None:
            for n, d in defs.items():
                r = d.refusal.code if d.refusal else "-"
                ml = len(d.refusal.message) if d.refusal else 0
                dec = []
                for img in IMAGES[:2]:
                    try:
                        x = D.decode_definition(d, data, img)
                        dec.append(x.code if isinstance(x, D.Refusal) else
                                   f"value {x.value!r:.24} text-len {len(x.text)}")
                    except Exception as ex:  # noqa: BLE001
                        dec.append(type(ex).__name__)
                nm = n.encode("unicode_escape").decode()[:24]
                lines.append(f"{nm}: {r} msg {ml} chars; decode 0x00 / 0xFF: {' | '.join(dec)}")
        print(f"  {sid:22} definitions {o['s definitions']}, refused {o['s refused']}, decodes {o['s decodes']}, "
              f"exceptions {sum(exc.values())} {exc or ''}; msg max {o['s message max']}, longest word "
              f"{o['s longest word max']}, msg>1024 {o['s message > 1024']}, foreign {o['s message foreign chars']}; "
              f"texts control {o['s text control (.137)']} Cf {o['s text Cf']} Zl {o['s text Zl']} Zp {o['s text Zp']}"
              f" [ {o['s text with [']}, msgs [ {o['s message with [']}" + ("".join("\n      " + ln for ln in lines)
                                                                            if lines else ""), flush=True)
    case_value_check()
    tot = {k: v for k, v in out.items() if k.startswith("EXC ")}
    print(f"[shapes] {len(SHAPES)} shapes; describe exceptions {out['s describe exception']}, decode exceptions "
          f"{out['s decode exception']}; messages > 1,024 chars {out['s message > 1024']}; words > 260 "
          f"{out['s word > 260']}; exceptions by place {tot}", flush=True)


def case_value_check():
    """The lower-case `tab_intp` method: 2a's decode against the frozen _apply_compu_method on the frozen record."""
    for sid in ("CASE-tab_intp", "CASE-TAB_INTP"):
        data = parse_text(HEAD + RL + SHAPES[sid] + TAIL, sid)
        d = D.describe_definition("V", data)
        img = Fill(50)
        got = D.decode_definition(d, data, img)
        v, st, err = a._apply_compu_method(50, data["compu_methods_by_name"].get("CMI"), data["compu_tabs_by_name"])
        print(f"  [case] {sid}: 2a decode of stored 50 -> {got.value if hasattr(got, 'value') else got.code!r} "
              f"(type_verdict path {type(d._table_form).__name__}, conversion_type {d.conversion_type!r}); frozen "
              f"_apply_compu_method -> {v!r} ({st})", flush=True)


# ------------------------------------------------------------------ nesting
def nested(depth):
    return (HEAD + RL + "".join(f"/begin IF_DATA L{k}\n" for k in range(depth)) + meas("X", "")
            + "/end IF_DATA\n" * depth + TAIL)


def at_depth(k, fn):
    if k == 0:
        return fn()
    return at_depth(k - 1, fn)


def nest():
    print(f"  recursion limit {sys.getrecursionlimit()}", flush=True)
    for depth in (900, 950, 970, 980, 985, 990, 995, 1000, 2000):
        p = W / f"nest_{depth}.a2l"
        p.write_text(nested(depth), encoding="utf-8")
        res = {}
        try:
            data = a.parse_a2l_file(p); res["parse main"] = "ok"
        except RecursionError:
            data = None; res["parse main"] = "RecursionError"
        holder = {}

        def worker():
            try:
                holder["data"] = a.parse_a2l_file(p); holder["r"] = "ok"
            except RecursionError:
                holder["r"] = "RecursionError"
        th = threading.Thread(target=worker); th.start(); th.join()
        res["parse thread"] = holder["r"]
        data = data or holder.get("data")
        if data is not None:
            for k in (0, 10, 25, 50, 100):
                try:
                    dd = at_depth(k, lambda: D.describe_definitions(["X"], data))
                    res[f"describe +{k}"] = dd["X"].refusal.code if dd["X"].refusal else "ok"
                except RecursionError:
                    res[f"describe +{k}"] = "RecursionError"
        p.unlink()
        print(f"  depth {depth}: " + ", ".join(f"{k} {v}" for k, v in res.items()), flush=True)


# ------------------------------------------------------------------ immutability
IMMUT = (str, int, float, bool, type(None), bytes, frozenset)


def walk_value(v, out, owner, seen):
    if id(v) in seen:
        return
    seen.add(id(v))
    if isinstance(v, IMMUT):
        return
    if isinstance(v, tuple):
        for x in v:
            walk_value(x, out, owner, seen)
        return
    if isinstance(v, types.MappingProxyType):
        try:
            v["__e5__"] = 1
            out[f"I write accepted ({owner} mappingproxy)"] += 1
        except TypeError:
            out["I writes refused"] += 1
        for x in v.values():
            walk_value(x, out, owner, seen)
        return
    if dataclasses.is_dataclass(v) and not isinstance(v, type):
        if not type(v).__dataclass_params__.frozen:
            out[f"I mutable dataclass {type(v).__name__} ({owner})"] += 1   # never written: a write would change it
        else:
            try:
                setattr(v, dataclasses.fields(v)[0].name, None)
                out[f"I write accepted ({owner} {type(v).__name__})"] += 1
            except dataclasses.FrozenInstanceError:
                out["I writes refused"] += 1
        for fl in dataclasses.fields(v):
            walk_value(getattr(v, fl.name), out, owner, seen)
        return
    out[f"I mutable {type(v).__name__} ({owner})"] += 1


def form_digest(f):
    if isinstance(f, D._EnumForm):
        return repr((f.section_kind, f.entries, f.default_text, f.texts, f.default_display, sorted(f.first_of.items(),
                     key=repr), f.ends, f.at_end, f.between))
    if isinstance(f, D._TabForm):
        return repr((f.xs, f.ys, f.x_nan, f.ref_echo))
    return repr(f)


def defs_digest(defs):
    return hashlib.md5("".join(repr(d) + repr(d._name_echo) + form_digest(d._table_form)
                               for d in defs.values()).encode("utf-8", "surrogatepass")).hexdigest()


def corpus_one(p):
    out = Counter()
    try:
        data = a.parse_a2l_file(pathlib.Path(p))
    except Exception as ex:  # noqa: BLE001
        out[f"parse exception {type(ex).__name__}"] += 1
        return out
    out["files"] += 1
    before = hashlib.md5(pickle.dumps(data, protocol=4)).hexdigest()
    captured = []
    orig = D._describe_one

    def spy(*args, **kw):
        if not captured or captured[-1] is not args[-1]:
            captured.append(args[-1])
        return orig(*args, **kw)
    D._describe_one = spy
    try:
        defs = run_data(data, out, "c")
    finally:
        D._describe_one = orig
    if defs is None:
        return out
    for reads in captured:
        for v in reads.values():
            out[f"I stored {type(v).__name__}"] += 1
            walk_value(v, out, "stored form", set())
    for d in defs.values():
        walk_value(d, out, "definition", set())
    d1 = defs_digest(defs)
    names = list(defs)
    for img in IMAGES:
        fwd = [repr(D.decode_definition(defs[n], data, img)) for n in names]
        rev = [repr(D.decode_definition(defs[n], data, img)) for n in reversed(names)]
        out["O decode order differs"] += fwd != rev[::-1]
    out["O definitions changed by decoding"] += defs_digest(defs) != d1
    out["O a2l_data changed"] += hashlib.md5(pickle.dumps(data, protocol=4)).hexdigest() != before
    rnd = random.Random(20261107 + len(names))
    sample = rnd.sample(names, min(30, len(names)))
    together = D.describe_definitions(sample, data)
    for n in sample:
        alone = D.describe_definition(n, data)
        t = together[n]
        out["O together-vs-alone compared"] += 1
        if not (t == alone and t._name_echo == alone._name_echo and form_digest(t._table_form) == form_digest(alone._table_form)):
            out["O together-vs-alone differs"] += 1
        if t._table_form is not None and t._table_form is defs[n]._table_form:
            out["O form shared across walks"] += 1
    return out


# ------------------------------------------------------------------ mutation
HOSTILE_WORDS = ["nan", "inf", "-inf", "1e400", "-1e400", HX, "0x" + "F" * 1200, "9" * 5000, "-0x10", "0x", "0xZZ",
                 "2.5", "-3", '"', '"open', "/*", "*/", "\x1b[31m", "\x00", "[bold]x[/bold]", "‮", "TAB_VERB",
                 "TAB_INTP", "tab_intp", "TAB_NOINTP", "COMPU_TAB_REF", "DEFAULT_VALUE", "BIT_MASK", "FORMAT",
                 '"%.99999"', '"%' + "9" * 3000 + '.2"', "X" * 300, "MATRIX_DIM", "1", "0", "-1", "4294967295",
                 "18446744073709551615", "FLOAT16_IEEE", "A_UINT64", "SBYTE", "ASCII", "VALUE", "NO_COMPU_METHOD"]
HOSTILE_LINES = ["BIT_MASK 0xZZ", "BIT_MASK " + "9" * 5000, "BIT_MASK 0x8000000000000001", 'FORMAT "%.99999"',
                 "MATRIX_DIM " + HX, "MATRIX_DIM 0", "MATRIX_DIM -1", "MATRIX_DIM 1 4 1", "ECU_ADDRESS 0x" + "F" * 1500,
                 "ECU_ADDRESS -0x10", "LENGTH " + HX, "LENGTH 0", "NUMBER 1048577", "NUMBER " + HX, "DATA_SIZE " + HX,
                 "COEFFS nan inf 0 0 0 1", "COEFFS 0 0 0 0 0 0", "COEFFS_LINEAR 1e400 nan", "COMPU_TAB_REF " + "G" * 300,
                 'DEFAULT_VALUE "\x1b"', "EXTENDED_LIMITS nan inf", "/* open", '"open', ' 1e400 "x"', ' nan nan "y"',
                 " nan 7", " inf 1", " -inf -1", "BYTE_ORDER MSB_FIRST", "DATA_TYPE FLOAT16_IEEE", "/begin IF_DATA X",
                 "/end IF_DATA", "/end CHARACTERISTIC"]
TARGETS = ("CHARACTERISTIC", "MEASUREMENT", "COMPU_METHOD", "COMPU_VTAB", "COMPU_VTAB_RANGE", "COMPU_TAB", "RECORD_LAYOUT")


def mutate(lines, rnd, ops):
    begins = [i for i, ln in enumerate(lines) if ln.strip().startswith("/begin") and
              len(ln.split()) > 1 and ln.split()[1] in TARGETS]
    if not begins:
        return lines
    lines = list(lines)
    for _ in range(ops):
        b = rnd.choice(begins)
        e = b + 1
        while e < len(lines) and e - b < 40 and not lines[e].strip().startswith("/end"):
            e += 1
        op = rnd.random()
        j = rnd.randint(b, max(b, e - 1))
        if op < 0.45 and j < len(lines):
            toks = lines[j].split(" ")
            k = rnd.randrange(len(toks))
            toks[k] = rnd.choice(HOSTILE_WORDS)
            lines[j] = " ".join(toks)
        elif op < 0.80:
            lines.insert(b + 1, " " + rnd.choice(HOSTILE_LINES))
        elif op < 0.90 and j < len(lines) and j != b:
            del lines[j]
        elif j < len(lines):
            lines.insert(j, lines[j])
    return lines


def mutate_one(arg):
    idx, p = arg
    out = Counter()
    try:
        text = pathlib.Path(p).read_text(encoding="utf-8", errors="replace")
    except OSError:
        out["read error"] += 1
        return out
    size = len(text)
    m = 1 if size > 2_000_000 else (3 if size > 200_000 else 8)
    base = text.split("\n")
    for k in range(m):
        rnd = random.Random(20261107 + 1000 * idx + k)
        mut = mutate(base, rnd, rnd.randint(1, 8) if size < 200_000 else rnd.randint(5, 30))
        mp = W / f"mut_{os.getpid()}_{idx}_{k}.a2l"
        mp.write_text("\n".join(mut), encoding="utf-8", errors="surrogatepass")
        try:
            data = a.parse_a2l_file(mp)
        except Exception as ex:  # noqa: BLE001 - the frozen reader's, counted apart
            out[f"parse exception {type(ex).__name__} (frozen)"] += 1
            continue
        finally:
            mp.unlink()
        out["mutants"] += 1
        run_data(data, out, "m")
    return out


def pool_run(fn, items):
    total = Counter()
    with ProcessPoolExecutor(int(os.environ.get("E5_WORKERS", "6"))) as ex:
        for r in ex.map(fn, items, chunksize=1):
            total.update(r)
    return total


def report(total, tag):
    keys = sorted(k for k in total if k.startswith(f"{tag} ") or k.startswith("EXC ") or k.startswith("I ")
                  or k.startswith("O ") or "exception" in k or k in ("files", "mutants"))
    for k in keys:
        print(f"  {k}: {total[k]}", flush=True)


print("s19_app.__file__ =", s19_app.__file__, "| python", sys.version.split()[0], "| a2l_definition md5",
      hashlib.md5(open(D.__file__, "rb").read()).hexdigest()[:8], "| load",
      " ".join(f"{x:.2f}" for x in os.getloadavg()), "| mode", MODE, flush=True)
if MODE == "shapes":
    shapes()
elif MODE == "nest":
    nest()
elif MODE == "corpus":
    files = [ln.strip() for lf in LISTS for ln in open(lf) if ln.strip()]
    report(pool_run(corpus_one, files), "c")
elif MODE == "mutate":
    files = [ln.strip() for lf in LISTS for ln in open(lf) if ln.strip()]
    report(pool_run(mutate_one, list(enumerate(files))), "m")
print("end | load", " ".join(f"{x:.2f}" for x in os.getloadavg()), flush=True)
