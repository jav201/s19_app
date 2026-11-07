"""Inc 2 E3 architect probe (batch-103): facts the architect review cites, read from the base tree.

Runs on the LAN host (cachyos-rtx) against the read-only clone at e07fb00. Imports ``s19_app`` from the
clone and drives PURE functions only (parse, tokenizer, section walk, the reused conversion): no Textual
app, no display, no clipboard, no write anywhere. It does not implement the definition model.

Usage: python i2e3a-probe.py <clone root> <out dir>
"""
from __future__ import annotations

import re
import struct
import subprocess
import sys
import time
from decimal import Decimal
from pathlib import Path

INT_TYPES = {"UBYTE": 1, "SBYTE": 1, "UWORD": 2, "SWORD": 2, "ULONG": 4, "SLONG": 4,
             "A_UINT64": 8, "A_INT64": 8}
SIGNED = {"SBYTE", "SWORD", "SLONG", "A_INT64"}
FLOATS = {"FLOAT16_IEEE", "FLOAT32_IEEE", "FLOAT64_IEEE"}
MASK_RE = re.compile(r"^(0x[0-9A-Fa-f]+|[0-9]+)$")
DEC_RE = re.compile(r"^%(\d*)(?:\.(\d+))?f?$")


def line(tag: str, value) -> None:
    print(f"[{tag}] {value}")


def walk(sections):
    for s in sections:
        yield s
        yield from walk(s.get("children") or [])


def decimals_of(fmt):
    if not fmt:
        return None
    m = DEC_RE.match(fmt)
    if not m or m.group(2) is None:
        return None
    return min(int(m.group(2)), 17)


def main(argv: list[str]) -> int:
    clone = Path(argv[1])
    sys.path.insert(0, str(clone))
    import s19_app
    print("s19_app.__file__ =", s19_app.__file__)
    from s19_app.tui import a2l

    files = subprocess.run(["git", "-C", str(clone), "ls-files", "*.a2l"], capture_output=True,
                           text=True, check=True).stdout.split()
    line("P0 tracked a2l files", len(files))

    # ---------------- P1 cost: per-call lookups vs one index walk (software_a) ----------------
    softa_path = clone / "examples" / "case_00_public" / "software_a.a2l"
    t0 = time.perf_counter()
    softa = a2l.parse_a2l_file(softa_path)
    t1 = time.perf_counter()
    secs = softa["sections"]
    tags = softa["tags"]
    line("P1a SOFTA parse ms / tags / tags with address and length",
         (round((t1 - t0) * 1000, 1), len(tags),
          sum(1 for t in tags if t.get("address") is not None and t.get("length") is not None)))
    # one pre-order walk building first-by-name maps for objects, methods and enum tables
    t0 = time.perf_counter()
    for _ in range(5):
        objects, methods, tables = {}, {}, {}
        for s in walk(secs):
            n = s.get("name")
            if n in ("MEASUREMENT", "CHARACTERISTIC"):
                objects.setdefault(a2l.parse_begin_meta(s.get("meta", ""))[0], s)
            elif n == "COMPU_METHOD":
                methods.setdefault(a2l.parse_begin_meta(s.get("meta", ""))[0], s)
            elif n in ("COMPU_VTAB", "COMPU_VTAB_RANGE"):
                tables.setdefault(a2l.parse_begin_meta(s.get("meta", ""))[0], s)
    t1 = time.perf_counter()
    line("P1b SOFTA one index walk ms (objects / methods / tables mapped)",
         (round((t1 - t0) * 200, 2), len(objects), len(methods), len(tables)))
    # tokenizing every object's record, its method record and its table record once (batch describe body)
    t0 = time.perf_counter()
    n_tok = 0
    for t in tags:
        s = objects.get(t["name"])
        if s is None:
            continue
        a2l._flatten_body_tokens([s.get("meta", "")] + (s.get("lines") or []))
        n_tok += 1
        m = methods.get(str(t.get("conversion") or ""))
        if m is not None:
            mt = a2l._flatten_body_tokens([m.get("meta", "")] + (m.get("lines") or []))
            if "COMPU_TAB_REF" in mt:
                i = mt.index("COMPU_TAB_REF")
                tb = tables.get(mt[i + 1] if i + 1 < len(mt) else "")
                if tb is not None:
                    a2l._flatten_body_tokens([tb.get("meta", "")] + (tb.get("lines") or []))
    t1 = time.perf_counter()
    line("P1c SOFTA tokenize every object + its method + its table, ms total / objects",
         (round((t1 - t0) * 1000, 1), n_tok))
    # the graph's per-call lookups: object walk+sort, one method walk, two table walks
    sample = [t["name"] for t in tags[:: max(1, len(tags) // 20)]][:20]
    t0 = time.perf_counter()
    for name in sample:
        objs = sorted(a2l._collect_sections_by_name(secs, "MEASUREMENT")
                      + a2l._collect_sections_by_name(secs, "CHARACTERISTIC"),
                      key=lambda s: s.get("start_line", 0))
        idx = next(i for i, t in enumerate(tags) if t["name"] == name)
        _ = objs[idx]
        a2l._collect_sections_by_name(secs, "COMPU_METHOD")
        a2l._collect_sections_by_name(secs, "COMPU_VTAB")
        a2l._collect_sections_by_name(secs, "COMPU_VTAB_RANGE")
    t1 = time.perf_counter()
    line("P1d SOFTA graph per-call lookups (enum path), ms per describe",
         round((t1 - t0) * 1000 / len(sample), 2))
    t0 = time.perf_counter()
    for _ in range(10):
        a2l._collect_sections_by_name(secs, "COMPU_METHOD")
    t1 = time.perf_counter()
    line("P1e SOFTA one method-record walk (each decode; each encode does two), ms",
         round((t1 - t0) * 100, 2))

    # ---------------- P2 shapes over the tracked files ----------------
    nonnum, signed_full, leading0, notype, text_mask, float_enum, float_range = [], [], [], [], [], [], []
    lin_int_hi, flt_hi = 0, 0
    lin_int_hi_softa, flt_hi_softa = 0, 0
    for rel in files:
        data = a2l.parse_a2l_file(clone / rel)
        layouts = data.get("record_layouts_by_name") or {}
        meth = {}
        for s in walk(data["sections"]):
            if s.get("name") == "COMPU_METHOD":
                tok = a2l._flatten_body_tokens([s.get("meta", "")] + (s.get("lines") or []))
                if tok:
                    meth.setdefault(tok[0], tok)
        rng = {a2l.parse_begin_meta(s.get("meta", ""))[0] for s in walk(data["sections"])
               if s.get("name") == "COMPU_VTAB_RANGE"}
        objs = {}
        for s in walk(data["sections"]):
            if s.get("name") in ("MEASUREMENT", "CHARACTERISTIC"):
                objs.setdefault(a2l.parse_begin_meta(s.get("meta", ""))[0], s)
        for t in data["tags"]:
            dt = t.get("datatype")
            if dt not in INT_TYPES and dt not in FLOATS:
                lay = a2l._resolve_record_layout(t.get("record_layout_name"), layouts)
                dt = (lay or {}).get("decode_type")
            if t.get("section") == "CHARACTERISTIC" and t.get("char_type") is None:
                notype.append((rel, t["name"]))
            word = t.get("bit_org")
            if word is not None:
                if not MASK_RE.match(word):
                    nonnum.append((rel, t["name"], word))
                elif re.match(r"^0[0-9]+$", word):
                    leading0.append((rel, t["name"], word))
                else:
                    mask = int(word, 16) if word.lower().startswith("0x") else int(word)
                    if dt in SIGNED and mask & 1 and (mask >> (8 * INT_TYPES[dt] - 1)) & 1:
                        signed_full.append((rel, t["name"], dt, word))
                if t.get("char_type") == "ASCII":
                    text_mask.append((rel, t["name"]))
            mtok = meth.get(str(t.get("conversion") or ""))
            mtype = mtok[2] if mtok and len(mtok) > 2 else None
            if mtype == "TAB_VERB" and dt in FLOATS:
                float_enum.append((rel, t["name"], dt))
                if "COMPU_TAB_REF" in mtok:
                    i = mtok.index("COMPU_TAB_REF")
                    if i + 1 < len(mtok) and mtok[i + 1] in rng:
                        float_range.append((rel, t["name"], dt))
            s = objs.get(t["name"])
            fmt = None
            if s is not None:
                otok = a2l._flatten_body_tokens([s.get("meta", "")] + (s.get("lines") or []))
                if "FORMAT" in otok:
                    i = otok.index("FORMAT")
                    fmt = otok[i + 1] if i + 1 < len(otok) else None
            if fmt is None and mtok and len(mtok) > 3:
                fmt = mtok[3]
            d = decimals_of(fmt)
            if d is not None and d >= 13 and t.get("address") is not None:
                if dt in INT_TYPES and mtype in ("LINEAR", "RAT_FUNC"):
                    lin_int_hi += 1
                    lin_int_hi_softa += rel.endswith("software_a.a2l")
                if dt in ("FLOAT32_IEEE",) and mtype in ("IDENTICAL", None, "LINEAR") :
                    flt_hi += 1
                    flt_hi_softa += rel.endswith("software_a.a2l")
    line("P2a BIT_MASK words not 0x-hex or decimal digits (count, first 3)", (len(nonnum), nonnum[:3]))
    line("P2b BIT_MASK words decimal with a leading 0 (count, first 3)", (len(leading0), leading0[:3]))
    line("P2c masks on a signed datatype holding bit 0 and the sign bit (count, first 5)",
         (len(signed_full), signed_full[:5]))
    line("P2d CHARACTERISTIC tags with char_type None (count, first 3)", (len(notype), notype[:3]))
    line("P2e ASCII CHARACTERISTICs with a BIT_MASK (count, first 3)", (len(text_mask), text_mask[:3]))
    line("P2f TAB_VERB objects on a float datatype (count, first 3)", (len(float_enum), float_enum[:3]))
    line("P2g of them on a COMPU_VTAB_RANGE (count, first 3)", (len(float_range), float_range[:3]))
    line("P2h addressed integer LINEAR/RAT_FUNC objects with >= 13 decimals (all files / software_a)",
         (lin_int_hi, lin_int_hi_softa))
    line("P2i addressed FLOAT32 objects (IDENTICAL/none/LINEAR) with >= 13 decimals (all / software_a)",
         (flt_hi, flt_hi_softa))

    # ---------------- P3 the precision rule against binary arithmetic ----------------
    # decoded p = the reused conversion of stored k; typed x = the exact decimal of k*a as a number text
    for a in ("0.1", "0.01", "0.05", "0.2", "0.3", "0.125"):
        meth_rec = {"conversion_type": "LINEAR", "coeffs_linear": [float(a), 0.0]}
        counts = {}
        for d in (6, 12, 15, 17):
            bad = 0
            bad_g15 = 0
            noise = 0
            for k in range(0, 20001):
                p = a2l._apply_compu_method(k, meth_rec, {})[0]
                x_text = format((Decimal(a) * k).normalize(), "f")
                x = float(x_text)
                if abs(p - x) > 0.5 * 10 ** (-d):
                    bad += 1
                    if ("%.15g" % p) != ("%.15g" % x):
                        bad_g15 += 1
                if f"{p:.{d}f}" != format(Decimal(x_text).quantize(Decimal(1).scaleb(-d)), "f"):
                    noise += 1
            counts[d] = (bad, bad_g15, noise)
        line(f"P3 LINEAR a={a}, k=0..20000: per d (refused by |p-x|<=0.5e-d, still refused if %.15g "
             f"also agrees, display text != exact decimal)", counts)
    p = a2l._apply_compu_method(123, {"conversion_type": "LINEAR", "coeffs_linear": [0.1, 0.0]}, {})[0]
    line("P3x stored 123, a=0.1: repr(p), p == 12.3, |p-12.3|, f'{p:.15f}'",
         (repr(p), p == 12.3, abs(p - 12.3), f"{p:.15f}"))
    f32 = struct.unpack(">f", struct.pack(">f", 0.1))[0]
    line("P3y FLOAT32 0.1 stored: repr, '%.15g', f'{:.15f}', '%.9g'",
         (repr(f32), "%.15g" % f32, f"{f32:.15f}", "%.9g" % f32))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
