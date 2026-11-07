"""E5 security re-review (round 2), batch-103 Inc 2a, on the FIXED code (HEAD 26d3e309, product a856fab3): fail-closed
describe/decode (R-A2L-DEF.58.2), the number rule and the message bound (R-A2L-DEF.151), the exact type word (.12/4),
the iterative walk (.58.2/24), and the two runs owed from round 1 (corpus immutability and order; seeded mutation).

Modes:
  shapes          round 1's 34 hand-built shapes (sec-e5-hostile.py) plus round 2's: the .58.2/20-23 shapes (5,000 hex
                  digits in LENGTH / DATA_SIZE / NUMBER / MATRIX_DIM), 4,000 decimal digits in MATRIX_DIM, huge NEGATIVE
                  numbers, the 2^64 - 1 / 2^64 bound, a quoted kind word that starts with `MATRIX_DIM ` (CR-5), every
                  supported type word in another letter case (CR-4)
  numtext         `_number_text` over magnitudes 0 ... 2^400000, both signs, both forms: no exception, <= 257 characters,
                  decimal at <= 2^64 - 1, else the .151 echo of the 0x word
  nest            nesting depth: parse in a fresh thread, describe + decode in a fresh thread at the base stack + k frames;
                  and depth 5,000 parsed with a raised recursion limit, then described at the DEFAULT limit
  corpus <lists>  the 203 files: (I) a2l_data digest (non-recursive, every container and scalar) before, after describe
                  and after decode; every stored form and definition immutable; (O) every name in one walk in file order,
                  in one walk in reversed order and in a second fresh walk: equal name by name (public fields, the private
                  name echo, the table form's content); a seeded sample described alone equals the walk; decode in file
                  order equals decode in reversed order; (B) the fixed code against 069171cd (round 1's code), name by
                  name, describe and decode on 4 images: the differences are counted by refusal code
  mutate <lists>  round 1's seeded mutations (seed 20261107 + 1000 * file index + k, the same word and line lists, so the
                  same mutants), describe all + decode all on 4 images
Every describe and decode outcome is checked: exceptions (type and the a2l_definition function:line they left from),
refusal messages <= 1,024 characters, the longest space-free run of a message, characters outside printable ASCII /
U+FFFD / U+2026 in a message, control characters (.137) and Cf / Zl / Zp characters and markup brackets in a display text.
Only derived counts leave the runner (no file content). THROWAWAY.
Usage: python -I -B sec-e5r2-hostile.py <tree> <scratch> <mode> [lists]
"""
import dataclasses, hashlib, importlib, os, pathlib, random, sys, threading, traceback, types, unicodedata
from collections import Counter
from concurrent.futures import ProcessPoolExecutor

sys.dont_write_bytecode = True
TREE, SCR, MODE = sys.argv[1], pathlib.Path(sys.argv[2]), sys.argv[3]
LISTS = sys.argv[4:]
sys.path.insert(0, TREE)
import s19_app  # noqa: E402
import s19_app.tui.a2l as a  # noqa: E402
import s19_app.tui.a2l_definition as D  # noqa: E402
OLD = importlib.import_module("s19_app.tui.a2l_definition_0691")

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
    if any(ch not in MSG_OK for ch in m):
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


def tag_names(data):
    return list(dict.fromkeys(t.get("name") for t in data.get("tags") or [] if t.get("name") is not None))


def run_data(data, out, tag, names=None):
    names = names if names is not None else tag_names(data)
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


def merge(total, part):
    """Counter.update sums; a " max" key is a maximum, so it is merged with max()."""
    for k, v in part.items():
        total[k] = max(total[k], v) if k.endswith(" max") else total[k] + v


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
     '/begin RECORD_LAYOUT RL_U16\n FNC_VALUES 1 UWORD ROW_DIR DIRECT\n/end RECORD_LAYOUT\n' \
     '/begin RECORD_LAYOUT RL_F32\n FNC_VALUES 1 FLOAT32_IEEE ROW_DIR DIRECT\n/end RECORD_LAYOUT\n'
HX = "0x" + "F" * 3700          # 16^3700 > 10^4300: str() of it raises ValueError on Python 3.11 (int max str digits)
H5 = "0x" + "F" * 5000          # the .58.2/20-23 shapes


def meas(name, extra, dt="UBYTE", cm="NO_COMPU_METHOD", addr="0x1000"):
    return f'/begin MEASUREMENT {name} "" {dt} {cm} 0 0 0 255\n ECU_ADDRESS {addr}\n{extra}/end MEASUREMENT\n'


def val(name, cm="NO_COMPU_METHOD", extra="", addr="0x1000", layout="RL_U8", kind="VALUE"):
    return f'/begin CHARACTERISTIC {name} ""\n {kind} {addr} {layout} 0 {cm} 0 255\n{extra}/end CHARACTERISTIC\n'


def cm(name, typ, body="", fmt='"%.3"'): return f'/begin COMPU_METHOD {name} "" {typ} {fmt} ""\n{body}/end COMPU_METHOD\n'
def vt(name, count, body): return f'/begin COMPU_VTAB {name} "" TAB_VERB {count}\n{body}/end COMPU_VTAB\n'
def ctab(name, body, kind="TAB_INTP"): return f'/begin COMPU_TAB {name} "" {kind} 2\n{body}/end COMPU_TAB\n'


SHAPES = {
    # round 1: numbers past the int-to-str limit (the frozen reader parses them with int(x, 0), base 16 has no limit)
    "LEN-hex3700": meas("X", f" LENGTH {HX}\n"),
    "DATASIZE-hex3700": meas("X", f" DATA_SIZE {HX}\n"),
    "NUMBER-hex3700": val("T", extra=f" NUMBER {HX}\n", kind="ASCII"),
    "MATRIXDIM-hex3700": meas("X", f" MATRIX_DIM {HX}\n"),
    "MATRIXDIM-hex1000": meas("X", " MATRIX_DIM 0x" + "F" * 1000 + "\n"),
    "ADDR-hex1500": meas("X", "", addr="0x" + "F" * 1500),
    "ADDR-neg-hex1500": meas("X", "", addr="-0x" + "F" * 1500),
    "CHARADDR-hex1500": val("V", addr="0x" + "F" * 1500),
    # round 1: letter case of a type word
    "CASE-tab_intp": cm("CMI", "tab_intp", " COMPU_TAB_REF CT\n") + ctab("CT", " 0 0\n 100 100\n") + val("V", "CMI"),
    "CASE-TAB_INTP": cm("CMI", "TAB_INTP", " COMPU_TAB_REF CT\n") + ctab("CT", " 0 0\n 100 100\n") + val("V", "CMI"),
    "CASE-tab_verb": cm("CMV", "tab_verb", " COMPU_TAB_REF VT\n") + vt("VT", 1, ' 165 "x"\n') + val("V", "CMV"),
    # round 1: characters in texts and names
    "TEXT-bidi-sep": cm("CMV", "TAB_VERB", " COMPU_TAB_REF VT\n") + vt(
        "VT", 4, ' 0 "a‮bc"\n 255 "l1 l2"\n 165 "z​w﻿"\n 1 "p q؜"\n') + val("V", "CMV"),
    "TEXT-markup": cm("CMV", "TAB_VERB", " COMPU_TAB_REF VT\n") + vt(
        "VT", 2, ' 0 "[bold red]x[/]"\n 255 "[link=file:///x]y[/link]"\n') + val("V", "CMV")
        + val("[bold]N[/bold]", "CM_MISSING"),
    "TEXT-control": cm("CMV", "TAB_VERB", " COMPU_TAB_REF VT\n") + vt(
        "VT", 3, ' 0 "a\x1b[31mb"\n 255 "n\x00l\x7f"\n 165 "c\x85d\x9be"\n') + val("V", "CMV")
        + val("N\x1b[2Jx", "CM_MISSING"),
    # round 1: the .58.2 corpus (19 shapes), re-run
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
    # round 2: the .58.2/20-23 shapes, as the cases write them
    "r2-LEN-hex5000-VALUE": val("HL", extra=f" LENGTH {H5}\n", layout="RL_U16", addr="0x10"),
    "r2-DATASIZE-hex5000": meas("HD", f" DATA_SIZE {H5}\n", addr="0x10"),
    "r2-NUMBER-hex5000": val("HN", extra=f" NUMBER {H5}\n", kind="ASCII", addr="0x10"),
    "r2-MATRIXDIM-hex5000": meas("MD", f" MATRIX_DIM {H5}\n", addr="0x10"),
    # round 2: decimal and negative huge numbers, the bound, an object with every number huge
    "r2-MATRIXDIM-dec4000": meas("M4", " MATRIX_DIM " + "9" * 4000 + "\n"),
    "r2-MATRIXDIM-neg-hex3700": meas("MN", f" MATRIX_DIM -{HX}\n"),
    "r2-LEN-neg-hex3700": val("LN", extra=f" LENGTH -{HX}\n"),
    "r2-DATASIZE-neg-hex3700": meas("DN", f" DATA_SIZE -{HX}\n"),
    "r2-LEN-2^64-1": val("B1", extra=" LENGTH 18446744073709551615\n", kind="ASCII"),
    "r2-LEN-2^64": val("B2", extra=" LENGTH 18446744073709551616\n", kind="ASCII"),
    "r2-NUMBER-2^64": val("B3", extra=" NUMBER 0x10000000000000000\n", kind="ASCII"),
    "r2-ADDR-2^64": meas("A6", "", addr="0x10000000000000000"),
    "r2-ADDR-and-LEN-huge": val("AL", extra=f" LENGTH {HX}\n", addr="0x" + "F" * 3700, kind="ASCII"),
    "r2-MATRIXDIM-and-ADDR-huge": meas("MA", f" MATRIX_DIM {HX}\n", addr="-0x" + "F" * 3700),
    # round 2: CR-5, a quoted kind word that starts with `MATRIX_DIM ` (and one of 5,000 characters unquoted)
    "r2-KIND-quoted-MATRIX_DIM": val("QK", kind='"MATRIX_DIM ' + "Z" * 2000 + '"', addr="0x10"),
    "r2-KIND-long-word": val("QL", kind="K" * 5000, addr="0x10"),
    # round 2: CR-4, every supported type word in another letter case
    **{f"r2-CASE-{t}": cm("CC", t, " COMPU_TAB_REF CT\n COEFFS_LINEAR 1 0\n COEFFS 0 1 0 0 0 1\n")
       + ctab("CT", " 0 0\n 100 100\n") + val("V", "CC")
       for t in ("tab_intp", "tab_nointp", "tab_verb", "identical", "linear", "rat_func", "Tab_Intp", "TAB_intp")},
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
                print(f"  {sid:28} parse exception {type(ex).__name__} (frozen reader)", flush=True)
                continue
        if data is None:
            print(f"  {sid:28} not found", flush=True)
            continue
        o = Counter()
        defs = run_data(data, o, "s")
        merge(out, o)
        exc = {k[4:]: v for k, v in o.items() if k.startswith("EXC ")}
        lines = []
        if defs is not None and body is not None:
            for n, d in defs.items():
                r = d.refusal.code if d.refusal else "-"
                ml = len(d.refusal.message) if d.refusal else 0
                head = ""
                if d.refusal:
                    msg = d.refusal.message
                    head = (msg[:72] + " ... " + msg[-40:]) if len(msg) > 120 else msg
                dec = []
                for img in IMAGES[:2]:
                    try:
                        x = D.decode_definition(d, data, img)
                        dec.append(x.code if isinstance(x, D.Refusal) else f"value {x.value!r:.24} text-len {len(x.text)}")
                    except Exception as ex:  # noqa: BLE001
                        dec.append(type(ex).__name__)
                nm = n.encode("unicode_escape").decode()[:24]
                lines.append(f"{nm}: {r} msg {ml} chars [{head.encode('unicode_escape').decode()}]; decode 0x00 / 0xFF: "
                             f"{' | '.join(dec)}")
        print(f"  {sid:28} definitions {o['s definitions']}, refused {o['s refused']}, decodes {o['s decodes']}, "
              f"exceptions {sum(exc.values())} {exc or ''}; msg max {o['s message max']}, longest word "
              f"{o['s longest word max']}, msg>1024 {o['s message > 1024']}, foreign {o['s message foreign chars']}; "
              f"texts control {o['s text control (.137)']} Cf {o['s text Cf']} Zl {o['s text Zl']} Zp {o['s text Zp']}"
              f" [ {o['s text with [']}, msgs [ {o['s message with [']}" + ("".join("\n      " + ln for ln in lines)
                                                                            if lines else ""), flush=True)
    case_value_check()
    tot = {k: v for k, v in out.items() if k.startswith("EXC ")}
    print(f"[shapes] {len(SHAPES)} shapes; describe exceptions {out['s describe exception']}, decode exceptions "
          f"{out['s decode exception']}; messages {out['s messages']}, > 1,024 chars {out['s message > 1024']} (max "
          f"{out['s message max']}); words > 260 {out['s word > 260']}; foreign chars {out['s message foreign chars']}; "
          f"exceptions by place {tot}", flush=True)


def case_value_check():
    """CR-4: the lower-case `tab_intp` method is refused at describe and at decode; TAB_INTP decodes 50.0 as frozen."""
    for sid in ("CASE-tab_intp", "CASE-TAB_INTP"):
        data = parse_text(HEAD + RL + SHAPES[sid] + TAIL, sid)
        d = D.describe_definition("V", data)
        got = D.decode_definition(d, data, Fill(50))
        v, st, err = a._apply_compu_method(50, data["compu_methods_by_name"].get("CMI"), data["compu_tabs_by_name"])
        print(f"  [case] {sid}: describe {d.refusal.code if d.refusal else 'no refusal'}; 2a decode of stored 50 -> "
              f"{got.value if hasattr(got, 'value') else got.code!r} (table form {type(d._table_form).__name__}, "
              f"conversion_type {d.conversion_type!r}); frozen _apply_compu_method -> {v!r} ({st})", flush=True)


# ------------------------------------------------------------------ the number writer
def numtext():
    out = Counter()
    mags = [0, 1, 255, 2 ** 32, 2 ** 63, 2 ** 64 - 1, 2 ** 64, 2 ** 64 + 1, 10 ** 20, 10 ** 4299, 10 ** 4300, 10 ** 5000,
            16 ** 3700, 2 ** 20000, 2 ** 400000]
    for m in mags:
        for n in (m, -m):
            for address in (False, True):
                out["calls"] += 1
                try:
                    t = D._number_text(n, address=address)
                except Exception as ex:  # noqa: BLE001
                    out[f"exception {type(ex).__name__}"] += 1
                    continue
                out["max len"] = max(out["max len"], len(t))
                hexw = ("-0x" if n < 0 else "0x") + format(abs(n), "X")
                if abs(n) <= 2 ** 64 - 1:
                    want = hexw if address else str(n)
                else:
                    want = hexw[:256] + ("…" if len(hexw) > 256 else "")
                out["equal to the rule"] += t == want
                out["differs from the rule"] += t != want
                out["over 257"] += len(t) > 257
    print(f"[numtext] {out['calls']} calls over {len(mags)} magnitudes x 2 signs x 2 forms: exceptions "
          f"{sum(v for k, v in out.items() if k.startswith('exception'))}, equal to the rule {out['equal to the rule']}, "
          f"differs {out['differs from the rule']}, longest {out['max len']} chars, over 257 {out['over 257']}", flush=True)


# ------------------------------------------------------------------ nesting
def nested(depth):
    return (HEAD + RL + "".join(f"/begin IF_DATA L{k}\n" for k in range(depth)) + meas("X", "")
            + "/end IF_DATA\n" * depth + TAIL)


def in_thread(fn, padding=0, stack=None, limit=None):
    box = {}

    def deeper(k):
        if k:
            return deeper(k - 1)
        try:
            box["v"] = fn()
        except BaseException as ex:  # noqa: BLE001 - reported
            box["e"] = ex

    old_limit = sys.getrecursionlimit()
    old_stack = threading.stack_size()
    if stack:
        threading.stack_size(stack)
    if limit:
        sys.setrecursionlimit(limit)
    try:
        th = threading.Thread(target=deeper, args=(padding,)); th.start(); th.join()
    finally:
        sys.setrecursionlimit(old_limit)
        threading.stack_size(old_stack)
    return box


def nest():
    print(f"  recursion limit {sys.getrecursionlimit()}", flush=True)
    for depth in (900, 950, 970, 980, 985, 990):
        p = W / f"nest_{depth}.a2l"
        p.write_text(nested(depth), encoding="utf-8")
        res = {}
        box = in_thread(lambda: a.parse_a2l_file(p))
        res["parse thread"] = "ok" if "v" in box else type(box["e"]).__name__
        data = box.get("v")
        if data is not None:
            for k in (0, 10, 25, 50, 100, 500, 900):
                b = in_thread(lambda: D.describe_definitions(["X"], data)["X"], padding=k)
                if "e" in b:
                    res[f"describe +{k}"] = type(b["e"]).__name__
                    continue
                d = b["v"]
                c = in_thread(lambda: D.decode_definition(d, data, Fill(7)), padding=k)
                res[f"describe +{k}"] = (d.refusal.code if d.refusal else "ok") + "/decode " + (
                    type(c["e"]).__name__ if "e" in c else (c["v"].code if isinstance(c["v"], D.Refusal) else "ok"))
        p.unlink()
        print(f"  depth {depth}: " + ", ".join(f"{k} {v}" for k, v in res.items()), flush=True)
    # past the frozen parser's own limit: parse with a raised limit and a large stack, describe at the DEFAULT limit
    depth = 5000
    p = W / f"nest_{depth}.a2l"
    p.write_text(nested(depth), encoding="utf-8")
    box = in_thread(lambda: a.parse_a2l_file(p), stack=512 * 1024 * 1024, limit=60000)
    p.unlink()
    res = {"parse (limit 60000, 512 MiB stack)": "ok" if "v" in box else type(box["e"]).__name__}
    data = box.get("v")
    if data is not None:
        flat = parse_text(HEAD + RL + meas("X", "") + TAIL, "flat")
        alone = D.describe_definition("X", flat)
        for k in (0, 900):
            b = in_thread(lambda: D.describe_definitions(["X"], data)["X"], padding=k)
            res[f"describe at limit {sys.getrecursionlimit()} +{k}"] = (
                type(b["e"]).__name__ if "e" in b else ("equal to the flat file" if b["v"] == alone else "DIFFERS"))
    print(f"  depth {depth}: " + ", ".join(f"{k} {v}" for k, v in res.items()), flush=True)


# ------------------------------------------------------------------ immutability and order
IMMUT = (str, int, float, bool, type(None), bytes, frozenset)
_END = object()


def digest(root):
    """A content digest of a parse payload, without recursion: every dict (keys in order), list, tuple, set and scalar;
    a container seen before is written as a back reference (so a shared object is one node)."""
    h = hashlib.blake2b(digest_size=16)
    upd = h.update
    seen = {}
    stack = [root]
    nodes = 0
    while stack:
        v = stack.pop()
        if v is _END:
            upd(b")"); continue
        nodes += 1
        t = type(v)
        if t is str:
            b = v.encode("utf-8", "surrogatepass"); upd(b"s%d:" % len(b)); upd(b)
        elif t is bool:
            upd(b"T" if v else b"F")
        elif t is int:
            upd(b"i" + format(v, "x").encode() + b";")
        elif t is float:
            upd(b"f" + v.hex().encode() + b";")
        elif v is None:
            upd(b"N")
        elif t is bytes:
            upd(b"b%d:" % len(v)); upd(v)
        elif t in (dict, list, tuple, set, frozenset):
            k = id(v)
            if k in seen:
                upd(b"@%d;" % seen[k]); continue
            seen[k] = len(seen)
            if t is dict:
                items = list(v.items())
                upd(b"{%d" % len(items)); stack.append(_END)
                for key, val in reversed(items):
                    stack.append(val); stack.append(key)
            elif t in (set, frozenset):
                upd(b"<%d" % len(v)); stack.append(_END)
                for x in reversed(sorted(v, key=repr)):
                    stack.append(x)
            else:
                upd((b"[" if t is list else b"(") + b"%d" % len(v)); stack.append(_END)
                for x in reversed(v):
                    stack.append(x)
        else:
            upd(b"o" + t.__name__.encode() + b":" + repr(v).encode("utf-8", "surrogatepass") + b";")
    return h.hexdigest(), nodes


def walk_value(v, out, owner, seen):
    stack = [v]
    while stack:
        v = stack.pop()
        if id(v) in seen:
            continue
        seen.add(id(v))
        if isinstance(v, IMMUT):
            continue
        if isinstance(v, tuple):
            stack.extend(v); continue
        if isinstance(v, types.MappingProxyType):
            try:
                v["__e5__"] = 1
                out[f"I write accepted ({owner} mappingproxy)"] += 1
            except TypeError:
                out["I writes refused"] += 1
            stack.extend(v.values()); continue
        if dataclasses.is_dataclass(v) and not isinstance(v, type):
            if not type(v).__dataclass_params__.frozen:
                out[f"I mutable dataclass {type(v).__name__} ({owner})"] += 1
            else:
                try:
                    setattr(v, dataclasses.fields(v)[0].name, None)
                    out[f"I write accepted ({owner} {type(v).__name__})"] += 1
                except dataclasses.FrozenInstanceError:
                    out["I writes refused"] += 1
            stack.extend(getattr(v, fl.name) for fl in dataclasses.fields(v)); continue
        out[f"I mutable {type(v).__name__} ({owner})"] += 1


def form_digest(f):
    if isinstance(f, (D._EnumForm, OLD._EnumForm)):
        return repr((f.section_kind, f.entries, f.default_text, f.texts, f.default_display, sorted(f.first_of.items(),
                     key=repr), f.ends, f.at_end, f.between))
    if isinstance(f, (D._TabForm, OLD._TabForm)):
        return repr((f.xs, f.ys, f.x_nan, f.ref_echo))
    return repr(f)


def full_key(d):
    return repr(d) + "|" + repr(d._name_echo) + "|" + form_digest(d._table_form)


def corpus_one(p):
    out = Counter()
    try:
        data = a.parse_a2l_file(pathlib.Path(p))
    except Exception as ex:  # noqa: BLE001
        out[f"parse exception {type(ex).__name__}"] += 1
        return out
    out["files"] += 1
    before, nodes = digest(data)
    out["I digest nodes"] += nodes
    captured = []
    orig = D._describe_one

    def spy(*args, **kw):
        if not captured or captured[-1] is not args[-1]:
            captured.append(args[-1])
        return orig(*args, **kw)
    D._describe_one = spy
    names = tag_names(data)
    try:
        fwd_defs = D.describe_definitions(names, data)                      # walk A: file order
    finally:
        D._describe_one = orig
    out["O names"] += len(names)
    out["I a2l_data changed by describe"] += digest(data)[0] != before
    o2 = Counter()
    run_data(data, o2, "c", names)                                          # messages, texts, exceptions (4 images)
    merge(out, o2)
    for reads in captured:
        for v in reads.values():
            out[f"I stored {type(v).__name__}"] += 1
            walk_value(v, out, "stored form", set())
    for d in fwd_defs.values():
        walk_value(d, out, "definition", set())
    k_fwd = {n: full_key(d) for n, d in fwd_defs.items()}
    for img in IMAGES:
        fwd = [repr(D.decode_definition(fwd_defs[n], data, img)) for n in names]
        rev = [repr(D.decode_definition(fwd_defs[n], data, img)) for n in reversed(names)]
        out["O decode order differs"] += fwd != rev[::-1]
    out["O definitions changed by decoding"] += {n: full_key(d) for n, d in fwd_defs.items()} != k_fwd
    out["I a2l_data changed by decode"] += digest(data)[0] != before
    rev_defs = D.describe_definitions(list(reversed(names)), data)         # walk B: reversed order
    fresh = D.describe_definitions(names, data)                             # walk C: a second fresh walk
    for n in names:
        kb, kc = full_key(rev_defs[n]), full_key(fresh[n])
        out["O reversed walk differs"] += kb != k_fwd[n]
        out["O fresh walk differs"] += kc != k_fwd[n]
        tf = fwd_defs[n]._table_form
        out["O form shared across walks"] += tf is not None and (tf is fresh[n]._table_form or tf is rev_defs[n]._table_form)
    rnd = random.Random(20261107 + len(names))
    sample = rnd.sample(names, min(10 if len(names) > 20000 else 40, len(names)))
    for n in sample:
        out["O alone compared"] += 1
        out["O alone differs"] += full_key(D.describe_definition(n, data)) != k_fwd[n]
    # (B) the fixed code against 069171cd, name by name
    try:
        old_defs = OLD.describe_definitions(names, data)
    except Exception as ex:  # noqa: BLE001
        out[f"B old describe exception {type(ex).__name__}"] += 1
        old_defs = None
    if old_defs is not None:
        for n in names:
            d, od = fwd_defs[n], old_defs[n]
            out["B compared"] += 1
            if full_key(d) != full_key(od):
                out[f"B describe differs: old {od.refusal.code if od.refusal else '-'} -> new "
                    f"{d.refusal.code if d.refusal else '-'}"] += 1
            for img in IMAGES:
                r, orr = D.decode_definition(d, data, img), OLD.decode_definition(od, data, img)
                out["B decodes compared"] += 1
                if repr(r) != repr(orr):
                    out[f"B decode differs: old {getattr(orr, 'code', 'Decoded')} -> new {getattr(r, 'code', 'Decoded')}"] += 1
    out["I a2l_data changed (end)"] += digest(data)[0] != before
    return out


# ------------------------------------------------------------------ mutation (round 1's lists, unchanged)
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
LISTS_DIGEST = hashlib.md5(repr((HOSTILE_WORDS, HOSTILE_LINES, TARGETS)).encode("utf-8", "surrogatepass")).hexdigest()[:8]


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
    with ProcessPoolExecutor(int(os.environ.get("E5_WORKERS", "4"))) as ex:
        for r in ex.map(fn, items, chunksize=1):
            merge(total, r)
    return total


def report(total, tag):
    keys = sorted(k for k in total if k.startswith(f"{tag} ") or k.startswith("EXC ") or k.startswith("I ")
                  or k.startswith("O ") or k.startswith("B ") or "exception" in k or k in ("files", "mutants"))
    for k in keys:
        print(f"  {k}: {total[k]}", flush=True)


print("s19_app.__file__ =", s19_app.__file__, "| python", sys.version.split()[0], "| a2l_definition md5",
      hashlib.md5(open(D.__file__, "rb").read()).hexdigest()[:8], "| control 0691 md5",
      hashlib.md5(open(OLD.__file__, "rb").read()).hexdigest()[:8], "| mutation lists md5", LISTS_DIGEST, "| load",
      " ".join(f"{x:.2f}" for x in os.getloadavg()), "| mode", MODE, flush=True)
if MODE == "shapes":
    shapes()
elif MODE == "numtext":
    numtext()
elif MODE == "nest":
    nest()
elif MODE == "corpus":
    files = [ln.strip() for lf in LISTS for ln in open(lf) if ln.strip()]
    print(f"  files {len(files)}", flush=True)
    report(pool_run(corpus_one, files), "c")
elif MODE == "mutate":
    files = [ln.strip() for lf in LISTS for ln in open(lf) if ln.strip()]
    print(f"  files {len(files)}", flush=True)
    report(pool_run(mutate_one, list(enumerate(files))), "m")
print("end | load", " ".join(f"{x:.2f}" for x in os.getloadavg()), flush=True)
