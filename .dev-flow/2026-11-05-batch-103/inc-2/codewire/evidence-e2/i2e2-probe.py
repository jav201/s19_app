"""Inc 2 E2 probe (batch-103): the facts the Code-Wire graph's examples cite, read from the base tree.

Runs on the LAN host (cachyos-rtx) against the read-only clone at e07fb00. It imports ``s19_app`` and the
synth generator from the clone and drives PURE functions only: no Textual app, no display, no clipboard,
no write outside ``<out dir>``. It does not implement the definition model; it prints the inputs the
graph's examples name (tags, object records, method and table records, case 08 objects, the reused
encode direction's results and reasons, number-formatting facts) and simulates the pinned draw order of
the definitions case (graph node ``build_definition_objects``) with ``random.Random(20260001)``.

Usage: python i2e2-probe.py <clone root> <out dir>
"""
from __future__ import annotations

import math
import random
import struct
import sys
import time
from pathlib import Path

KEYS = ("section", "name", "char_type", "address", "length", "datatype", "deposit", "compu_method_name",
        "conversion", "effective_byte_order", "lower_limit", "upper_limit", "bit_org", "matrix_dim", "unit")


def line(tag: str, value) -> None:
    print(f"[{tag}] {value}")


def main(argv: list[str]) -> int:
    clone, out = Path(argv[1]), Path(argv[2])
    sys.path.insert(0, str(clone))
    sys.path.insert(0, str(clone / "tools" / "synth"))
    import s19_app
    print("s19_app.__file__ =", s19_app.__file__)
    from s19_app.tui import a2l
    from s19_app.core import S19File
    import make_release_case as gen
    print("make_release_case.__file__ =", gen.__file__)
    ex = clone / "examples" / "case_00_public"

    def objects_of(payload: dict) -> list[dict]:
        found = (a2l._collect_sections_by_name(payload["sections"], "MEASUREMENT")
                 + a2l._collect_sections_by_name(payload["sections"], "CHARACTERISTIC"))
        return sorted(found, key=lambda s: s["start_line"])

    def record(section: dict) -> list[str]:
        return a2l._flatten_body_tokens([section.get("meta") or ""] + list(section.get("lines") or []))

    def fields(t: dict) -> dict:
        return {k: (hex(t[k]) if k == "address" and isinstance(t[k], int) else t[k]) for k in KEYS}

    def first_tag(payload: dict, name: str) -> tuple[int, dict] | None:
        for i, t in enumerate(payload["tags"]):
            if t.get("name") == name:
                return i, t
        return None

    def sections_named(payload: dict, kind: str, name: str) -> list[dict]:
        return [s for s in a2l._collect_sections_by_name(payload["sections"], kind)
                if (record(s) or [""])[0] == name]

    # ---------------- P0 pairing: i-th tag <-> i-th object section ----------------
    payloads = {}
    for label, file in (("V171", "ASAP2_Demo_V171.a2l"), ("SOFTA", "software_a.a2l"),
                        ("TUBE", "BalanceTube_STMicro.a2l")):
        t0 = time.perf_counter()
        payloads[label] = a2l.parse_a2l_file(ex / file)
        parse_ms = (time.perf_counter() - t0) * 1000
        p = payloads[label]
        objs = objects_of(p)
        same = sum(1 for t, s in zip(p["tags"], objs) if a2l.parse_begin_meta(s.get("meta") or "")[0] == t["name"])
        line(f"P0 {label} tags / object sections / same name at same position / parse ms",
             (len(p["tags"]), len(objs), same, round(parse_ms)))
    v171, softa, tube = payloads["V171"], payloads["SOFTA"], payloads["TUBE"]

    # ---------------- P1 BalanceTube: the commented MEASUREMENT header ----------------
    method = "esdl_model_GameControllerStatemachineStates"
    for i, s in enumerate(objects_of(tube)):
        if method in record(s):
            t = tube["tags"][i]
            line("P1a TUBE first object naming the enum method: tag fields", fields(t))
            line("P1b its record words (comments left out), first 10", record(s)[:10])
            break
    m = sections_named(tube, "COMPU_METHOD", method)[0]
    line("P1c TUBE method record words", record(m))
    line("P1d TUBE side-table method (a2l.py)", {k: tube["compu_methods_by_name"][method].get(k)
                                                for k in ("conversion_type", "format", "unit", "compu_tab_ref")})
    vt = sections_named(tube, "COMPU_VTAB", method + "_vtab")[0]
    line("P1e TUBE table record words", record(vt))

    # ---------------- P2 V171 objects ----------------
    names = ["ASAM.C.SCALAR.SWORD.IDENTICAL", "ASAM.M.SCALAR.UBYTE.IDENTICAL", "ASAM.C.SCALAR.UBYTE.IDENTICAL",
             "ASAM.C.SCALAR.SBYTE.IDENTICAL", "ASAM.C.SCALAR.SWORD.TAB_VERB_DEFAULT_VALUE",
             "ASAM.C.SCALAR.SWORD.TAB_VERB_NO_DEFAULT_VALUE", "ASAM.C.SCALAR.SWORD.VTAB_RANGE_DEFAULT_VALUE",
             "ASAM.C.SCALAR.SWORD.VTAB_RANGE_NO_DEFAULT_VALUE", "ASAM.M.SCALAR.UBYTE.VTAB_RANGE_NO_DEFAULT_VALUE",
             "ASAM.C.SCALAR.UWORD.IDENTICAL.BITMASK_0FF0", "ASAM.C.SCALAR.UWORD.IDENTICAL.BITMASK_0001",
             "ASAM.C.SCALAR.UWORD.IDENTICAL.BITMASK_0010", "UNKNOWN", "ASAM.M.MATRIX_DIM_16_1.UBYTE.IDENTICAL",
             "ASAM.C.SCALAR.FLOAT64_IEEE.IDENTICAL"]
    v_objs = objects_of(v171)
    for n in names:
        hit = first_tag(v171, n)
        if hit is None:
            line(f"P2 V171 {n}", "NO TAG")
            continue
        i, t = hit
        words = record(v_objs[i])
        head = 8 if t["section"] == "MEASUREMENT" else 9
        layout = a2l._resolve_record_layout(t.get("record_layout_name"), v171["record_layouts_by_name"])
        line(f"P2 V171 {n}", fields(t))
        line(f"P2 V171 {n} words after the header", words[head:head + 12])
        line(f"P2 V171 {n} record layout", layout)
    line("P2x V171 tags named UNKNOWN", sum(1 for t in v171["tags"] if t["name"] == "UNKNOWN"))
    line("P2y V171 first CUBOID", next(t["name"] for t in v171["tags"] if t.get("char_type") == "CUBOID"))
    for i, s in enumerate(v_objs):
        w = record(s)
        if "EXTENDED_LIMITS" in w:
            k = w.index("EXTENDED_LIMITS")
            if w[k + 1:k + 3] == ["-10000.0", "20000.0"]:
                line("P2z V171 first object with EXTENDED_LIMITS -10000.0 20000.0", v171["tags"][i]["name"])
                break
    for mname in ("CM.TAB_VERB.DEFAULT_VALUE", "CM.IDENTICAL", "CM.VTAB_RANGE.DEFAULT_VALUE"):
        line(f"P3 V171 method record {mname}", record(sections_named(v171, "COMPU_METHOD", mname)[0]))
    line("P3 V171 table record CM.TAB_VERB.DEFAULT_VALUE.REF",
         record(sections_named(v171, "COMPU_VTAB", "CM.TAB_VERB.DEFAULT_VALUE.REF")[0]))
    line("P3 V171 table record CM.VTAB_RANGE.DEFAULT_VALUE.REF",
         record(sections_named(v171, "COMPU_VTAB_RANGE", "CM.VTAB_RANGE.DEFAULT_VALUE.REF")[0]))

    # ---------------- P4 software_a ----------------
    s_objs = objects_of(softa)
    meth_type = {}
    meth_ref = {}
    for s in a2l._collect_sections_by_name(softa["sections"], "COMPU_METHOD"):
        w = record(s)
        if w:
            meth_type.setdefault(w[0], w[2] if len(w) > 2 else None)
            if "COMPU_TAB_REF" in w:
                meth_ref.setdefault(w[0], w[w.index("COMPU_TAB_REF") + 1])
    for i, t in enumerate(softa["tags"]):
        if t["section"] == "MEASUREMENT" and t.get("conversion") == "NO_COMPU_METHOD":
            w = record(s_objs[i])
            fmt = w[w.index("FORMAT") + 1] if "FORMAT" in w else None
            line("P4a SOFTA first NO_COMPU_METHOD MEASUREMENT", {**fields(t), "FORMAT": fmt})
            break
    for i, t in enumerate(softa["tags"]):
        mn = t.get("compu_method_name") or t.get("conversion")
        if meth_type.get(mn) == "TAB_VERB":
            tbl = meth_ref.get(mn)
            tw = record(sections_named(softa, "COMPU_VTAB", tbl)[0]) if sections_named(softa, "COMPU_VTAB", tbl) else None
            line("P4b SOFTA first object whose method record type is TAB_VERB",
                 {**fields(t), "method": mn, "table": tbl, "table words": (tw or [])[:10]})
            break
    vtabs = a2l._collect_sections_by_name(softa["sections"], "COMPU_VTAB")
    neg = next(s for s in vtabs if len(record(s)) > 4 and record(s)[4] == "-1")
    negname = record(neg)[0]
    user = next((t["name"] for t in softa["tags"]
                 if meth_ref.get(t.get("compu_method_name") or t.get("conversion")) == negname), None)
    line("P4c SOFTA first COMPU_VTAB whose first pair raw is -1: name / words / first object using it",
         (negname, record(neg)[:8], user))
    rng_tabs = a2l._collect_sections_by_name(softa["sections"], "COMPU_VTAB_RANGE")
    r0 = record(rng_tabs[0])
    user = next((t["name"] for t in softa["tags"]
                 if meth_ref.get(t.get("compu_method_name") or t.get("conversion")) == r0[0]), None)
    line("P4d SOFTA first COMPU_VTAB_RANGE: words / first object using it", (r0, user))
    for i, t in enumerate(softa["tags"]):
        if t["section"] == "MEASUREMENT" and t.get("bit_org") == "0xFFFFFF":
            line("P4e SOFTA first MEASUREMENT with BIT_MASK 0xFFFFFF", fields(t))
            break
    for i, s in enumerate(s_objs):
        w = record(s)
        if "PHYS_UNIT" in w and w[w.index("PHYS_UNIT") + 1] == "V":
            line("P4f SOFTA first object with PHYS_UNIT V", fields(softa["tags"][i]))
            break
    line("P4h SOFTA MEASUREMENTs with an address / all MEASUREMENTs",
         (sum(1 for t in softa["tags"] if t["section"] == "MEASUREMENT" and t["address"] is not None),
          sum(1 for t in softa["tags"] if t["section"] == "MEASUREMENT")))
    layouts = softa["record_layouts_by_name"]
    for i, t in enumerate(softa["tags"]):
        if t.get("char_type") != "VALUE" or t.get("conversion") != "NO_COMPU_METHOD" or t["address"] is None:
            continue
        lay = a2l._resolve_record_layout(t.get("record_layout_name"), layouts)
        w = record(s_objs[i])
        if lay and lay["decode_type"] == "SWORD" and "FORMAT" in w and w[w.index("FORMAT") + 1] == "%.15":
            line("P4i SOFTA first SWORD VALUE, NO_COMPU_METHOD, FORMAT %.15, with an address",
                 {**fields(t), "layout": lay})
            break
    for i, t in enumerate(softa["tags"]):
        if t.get("bit_org") == "0xFFFFFF" and t["address"] is not None:
            lay = a2l._resolve_record_layout(t.get("record_layout_name"), layouts)
            line("P4j SOFTA first object with BIT_MASK 0xFFFFFF and an address", {**fields(t), "layout": lay})
            break
    else:
        line("P4j SOFTA first object with BIT_MASK 0xFFFFFF and an address", "none")
    for label, name in (("P4b user", "ACN_ULWY.FVH_MUGP_O_SBW_RTD_NJZ_MKE_WODEYLMQXZ46_OXATIRMZ_YOQJZI"),
                        ("P4c user", "QUUU_Ywjznkkjwj.AuooouPgqj"),
                        ("P4d user", "MhiH.Szymzt_WN_MDB_PifFJDjfo_ZHE_2_Kvypjld_EgdrylBxtq.RPI_BfgPPFcmu"),
                        ("P4f user", "BcpGxvlbvneyoAudnMhl.DRCDJ_XNIFM_DSURLVD_VSJMQJBMW")):
        hit = first_tag(softa, name)
        if hit:
            t = hit[1]
            line(f"P4k SOFTA {label}", {**fields(t),
                                       "layout": a2l._resolve_record_layout(t.get("record_layout_name"), layouts)})
    line("P4l SOFTA table CXP_GM_YQTODIW record",
         record(sections_named(softa, "COMPU_VTAB_RANGE", "CXP_GM_YQTODIW")[0]))
    secs = softa["sections"]
    t0 = time.perf_counter()
    for _ in range(10):
        objects_of(softa)
    t1 = time.perf_counter()
    for _ in range(10):
        a2l._collect_sections_by_name(secs, "COMPU_METHOD")
    t2 = time.perf_counter()
    line("P4g SOFTA ms per call: object-section walk+sort / one _collect_sections_by_name",
         (round((t1 - t0) * 100, 2), round((t2 - t1) * 100, 2)))

    # ---------------- P5 case 08 (1 MiB, seed 20260001) ----------------
    c08 = out / "c08"
    gen.generate(c08, 20260001, 1.0)
    regions = gen.compute_region_sizes(1.0)
    objects = gen.build_objects(regions, random.Random(20260001))
    counts = {}
    for o in objects:
        counts[o["kind"]] = counts.get(o["kind"], 0) + 1
    line("P5a C08 object counts by kind", counts)
    clean = a2l.parse_a2l_file(c08 / "firmware.a2l")
    issues = a2l.parse_a2l_file(c08 / "firmware_issues.a2l")
    image = S19File(str(c08 / "firmware.s19")).get_memory_map()
    line("P5b C08 image bytes", len(image))

    def pick(pred):
        return next(o for o in objects if pred(o))

    chosen = {
        "VALUE_0001": pick(lambda o: o["name"] == "VALUE_0001"),
        "ASCII_0001": pick(lambda o: o["name"] == "ASCII_0001"),
        "VAL_BLK_0001": pick(lambda o: o["name"] == "VAL_BLK_0001"),
        "CURVE_0001": pick(lambda o: o["name"] == "CURVE_0001"),
        "MAP_0001": pick(lambda o: o["name"] == "MAP_0001"),
        "LIN_OFF_UWORD": pick(lambda o: o["conversion"] == "CM_LIN_OFF" and o["datatype"] == "UWORD"),
        "RAT_FIRST": pick(lambda o: o["conversion"] == "CM_RAT"),
        "TAB_NOINTP": pick(lambda o: o["conversion"] == "CM_TAB_NOINTP"),
        "TAB_INTP": pick(lambda o: o["conversion"] == "CM_TAB_INTP"),
        "LIN_10_FLOAT32": pick(lambda o: o["conversion"] == "CM_LIN_10" and o["datatype"] == "FLOAT32_IEEE"),
    }
    for dt in ("UBYTE", "UWORD", "ULONG", "SWORD"):
        chosen[f"LIN_10_{dt}"] = pick(lambda o, dt=dt: o["conversion"] == "CM_LIN_10" and o["datatype"] == dt)
    for label, o in chosen.items():
        hit = first_tag(clean, o["name"])
        t = hit[1] if hit else {}
        on_image = bytes(image.get(o["address"] + k, -1) & 0xFF for k in range(o["length"])) == bytes(o["raw_bytes"])
        line(f"P5c C08 {label}", {"name": o["name"], "section": o["section"], "kind": o["kind"],
                                  "datatype": o["datatype"], "conversion": o["conversion"],
                                  "address": hex(o["address"]), "length": o["length"], "big_endian": o["big_endian"],
                                  "low": o["low"], "high": o["high"], "physical": o["physical"],
                                  "raw_bytes": bytes(o["raw_bytes"][:8]).hex(" "),
                                  "tag byte order": t.get("effective_byte_order"), "tag length": t.get("length"),
                                  "bytes on image": on_image})
    line("P5d C08 ASCII_0001 planned string", bytes(chosen["ASCII_0001"]["raw_bytes"]).split(b"\x00")[0])
    line("P5e C08 the 10 planned ASCII strings",
         [bytes(o["raw_bytes"]).split(b"\x00")[0].decode() for o in objects if o["kind"] == "ASCII"])
    defined = [t for t in clean["tags"]
               if (t["section"] == "MEASUREMENT" and t.get("matrix_dim") in (None, 1))
               or t.get("char_type") in ("VALUE", "ASCII")]
    line("P5f C08 clean: defined objects (VALUE, ASCII, scalar MEASUREMENT) / all tags", (len(defined), len(clean["tags"])))
    for n in ("MISSING_CM", "OUT_OF_RANGE_1", "OUT_OF_RANGE_2", "OUT_OF_RANGE_3", "SPAN_OVER_1", "SPAN_OVER_2",
              "LIMIT_BREAKER"):
        t = first_tag(issues, n)[1]
        miss = sum(1 for k in range(t["length"] or 0) if (t["address"] + k) not in image)
        line(f"P5g C08 issues {n}", {**fields(t), "bytes missing in the image": miss})
    dups = [hex(t["address"]) for t in issues["tags"] if t["name"] == "VALUE_0001"]
    line("P5h C08 issues VALUE_0001 addresses in file order", dups)
    line("P5i C08 issues tags named value_0001 (lower case)", sum(1 for t in issues["tags"] if t["name"] == "value_0001"))

    # the reused encode direction (unchanged a2l.py) on case 08 tags, limits removed
    def enc(name: str, value: float, payload: dict = clean):
        t = dict(first_tag(payload, name)[1])
        t["lower_limit"] = t["upper_limit"] = None
        return a2l.encode_physical_to_raw_bytes(t, value, payload["compu_methods_by_name"],
                                                payload["compu_tabs_by_name"], payload["record_layouts_by_name"])

    for label, value in (("LIN_OFF_UWORD", 150.0), ("RAT_FIRST", 100.0), ("TAB_NOINTP", 15.0),
                         ("TAB_NOINTP", 12.0), ("TAB_INTP", 20.0), ("TAB_INTP", 45.0), ("TAB_INTP", 5.07),
                         ("LIN_10_FLOAT32", 0.5), ("LIN_10_FLOAT32", 1.0), ("LIN_10_UWORD", 0.5),
                         ("LIN_10_UWORD", 1.0), ("LIN_10_UWORD", 10.0)):
        line(f"P5j C08 encode {value} on {label} {chosen[label]['name']}", enc(chosen[label]["name"], value))
    meth = clean["compu_methods_by_name"]
    tabs = clean["compu_tabs_by_name"]
    line("P5k C08 decode TAB_INTP stored 500 / stored 51", (a2l._apply_compu_method(500, meth["CM_TAB_INTP"], tabs),
                                                            a2l._apply_compu_method(51, meth["CM_TAB_INTP"], tabs)))
    line("P5l C08 decode TAB_NOINTP stored 6", a2l._apply_compu_method(6, meth["CM_TAB_NOINTP"], tabs))
    line("P5m C08 TBL_NOINTP side table / TBL_INTP side table", (tabs["TBL_NOINTP"]["entries"], tabs["TBL_INTP"]["entries"]))
    for label in ("LIN_OFF_UWORD", "RAT_FIRST", "TAB_INTP"):
        o = chosen[label]
        t = first_tag(clean, o["name"])[1]
        raw = a2l._decode_scalar(bytes(o["raw_bytes"]), o["datatype"], t["effective_byte_order"])
        line(f"P5n C08 decode {label} stored / physical / planned",
             (raw, a2l._apply_compu_method(raw, meth[o["conversion"]], tabs,
                                           (a2l._to_float(t["lower_limit"]), a2l._to_float(t["upper_limit"]))),
              o["physical"]))

    # ---------------- P6 the reused encode's reasons on synthetic tags ----------------
    def tag(dt: str, lo=None, hi=None) -> dict:
        return {"char_type": "VALUE", "datatype": dt, "length": a2l.DATATYPE_SIZES[dt], "effective_byte_order": "big",
                "compu_method_name": "CM", "lower_limit": lo, "upper_limit": hi}

    lin = lambda a, b: {"CM": {"conversion_type": "LINEAR", "coeffs_linear": [a, b]}}
    rat = lambda *c: {"CM": {"conversion_type": "RAT_FUNC", "coeffs": list(c)}}
    cases = [
        ("42/1 LINEAR 0 5, 5", tag("SWORD"), 5.0, lin(0.0, 5.0), {}),
        ("42/2 RAT 0 1 0 0 0 0, 3", tag("UWORD"), 3.0, rat(0, 1, 0, 0, 0, 0), {}),
        ("42/3 TAB_NOINTP TB_GONE, 1", tag("UWORD"), 1.0,
         {"CM": {"conversion_type": "TAB_NOINTP", "compu_tab_ref": "TB_GONE"}}, {}),
        ("42/4 TAB_INTP non-numeric, 1", tag("UWORD"), 1.0, {"CM": {"conversion_type": "TAB_INTP", "compu_tab_ref": "T"}},
         {"T": {"entries": [(0.0, "a"), (1.0, "b")]}}),
        ("42/7 FLOAT64 LINEAR 1e-300, 1e300", tag("FLOAT64_IEEE"), 1e300, lin(1e-300, 0.0), {}),
        ("42/8 SWORD LINEAR 2, 3", tag("SWORD"), 3.0, lin(2.0, 0.0), {}),
        ("42/9 SWORD LINEAR 2, 1e9", tag("SWORD"), 1e9, lin(2.0, 0.0), {}),
        ("42/10 FLOAT16 none, 1", {**tag("FLOAT16_IEEE"), "compu_method_name": "NO_COMPU_METHOD"}, 1.0, {}, {}),
        ("42/11 FLOAT32 none, 1e39", {**tag("FLOAT32_IEEE"), "compu_method_name": "NO_COMPU_METHOD"}, 1e39, {}, {}),
        ("41/1 UBYTE none, 7", {**tag("UBYTE"), "compu_method_name": "NO_COMPU_METHOD"}, 7.0, {}, {}),
        ("53/1 UWORD big none, 4660", {**tag("UWORD"), "compu_method_name": "NO_COMPU_METHOD"}, 4660.0, {}, {}),
        ("53/2 UWORD little none, 4660", {**tag("UWORD"), "compu_method_name": "NO_COMPU_METHOD",
                                          "effective_byte_order": "little"}, 4660.0, {}, {}),
        ("41/2 SWORD little IDENTICAL, -5", {**tag("SWORD"), "effective_byte_order": "little"}, -5.0,
         {"CM": {"conversion_type": "IDENTICAL"}}, {}),
        ("47/2 SWORD none, -1 (the encode's bytes)", {**tag("SWORD"), "compu_method_name": "NO_COMPU_METHOD"}, -1.0, {}, {}),
        ("46/1 UWORD little IDENTICAL, 35 (base: whole word)", {**tag("UWORD"), "effective_byte_order": "little"}, 35.0,
         {"CM": {"conversion_type": "IDENTICAL"}}, {}),
        ("44/1 SBYTE IDENTICAL, 120", {**tag("SBYTE"), "effective_byte_order": "little"}, 120.0,
         {"CM": {"conversion_type": "IDENTICAL"}}, {}),
        ("44/2 SBYTE IDENTICAL, -128", {**tag("SBYTE"), "effective_byte_order": "little"}, -128.0,
         {"CM": {"conversion_type": "IDENTICAL"}}, {}),
    ]
    for label, t, v, m, tb in cases:
        line(f"P6 encode {label}", a2l.encode_physical_to_raw_bytes(t, v, m, tb, None))
    for label, raw, c in (("28/1", 7, (0, 0, 5, 0, 0, 1)), ("28/2", 0, (1, 0, 1, 0, 0, 1)),
                          ("28/3", 1, (0, 1, 0, 0, 1, 0))):
        line(f"P6 decode RAT_FUNC {label} stored {raw}",
             a2l._apply_compu_method(raw, {"conversion_type": "RAT_FUNC", "coeffs": list(c)}, {}))
    line("P6 decode R-A2L-057 RAT 1 0 0 0 0 1 stored 9 limits 0..10",
         a2l._apply_compu_method(9, {"conversion_type": "RAT_FUNC", "coeffs": [1, 0, 0, 0, 0, 1]}, {}, (0.0, 10.0)))
    line("P6 decode R-A2L-055 LINEAR [2, None] stored 3",
         a2l._apply_compu_method(3, {"conversion_type": "LINEAR", "coeffs_linear": [2.0, None]}, {}))
    line("P6 decode LINEAR 0.1 stored 123 / stored 3",
         (a2l._apply_compu_method(123, {"conversion_type": "LINEAR", "coeffs_linear": [0.1, 0.0]}, {}),
          a2l._apply_compu_method(3, {"conversion_type": "LINEAR", "coeffs_linear": [0.1, 0.0]}, {})))
    line("P6 _decode_scalar SWORD little FB FF / UWORD big 12 34 / FLOAT16 3C 00",
         (a2l._decode_scalar(b"\xfb\xff", "SWORD", "little"), a2l._decode_scalar(b"\x12\x34", "UWORD", "big"),
          a2l._decode_scalar(b"\x3c\x00", "FLOAT16_IEEE", "big")))

    # ---------------- P7 number formatting (stdlib facts the display rules rest on) ----------------
    facts = {
        "f'{0.1*123:.2f}'": f"{0.1 * 123:.2f}", "repr(0.1*123)": repr(0.1 * 123),
        "f'{2.5:.0f}'": f"{2.5:.0f}", "f'{3.14159:.4f}'": f"{3.14159:.4f}", "f'{0.125:.2f}'": f"{0.125:.2f}",
        "f'{0.1:.17f}'": f"{0.1:.17f}", "'%.15g' % (0.1*3)": "%.15g" % (0.1 * 3),
        "'%.15g' % 1234567.0": "%.15g" % 1234567.0, "'%.15g' % 1e-07": "%.15g" % 1e-07,
        "'%.15g' % 12.5": "%.15g" % 12.5, "f'{5.1:.3f}'": f"{5.1:.3f}", "f'{12.5:.1f}'": f"{12.5:.1f}",
        "unpack >e 3C00": struct.unpack(">e", b"\x3c\x00")[0],
        "unpack >f 7FC00000 / 7F800000 / FF800000": [struct.unpack(">f", bytes.fromhex(h))[0]
                                                    for h in ("7fc00000", "7f800000", "ff800000")],
        "str(nan), str(inf), str(-inf)": (str(math.nan), str(math.inf), str(-math.inf)),
        "float32(0.1) %.6g / %.15g": ("%.6g" % struct.unpack("<f", struct.pack("<f", 0.1))[0],
                                      "%.15g" % struct.unpack("<f", struct.pack("<f", 0.1))[0]),
        "(0x1234 & 0x0FF0) >> 4": (0x1234 & 0x0FF0) >> 4, "(0xF0F0 & 0xFF00) >> 8": (0xF0F0 & 0xFF00) >> 8,
        "(0xF00F & ~0x0FF0) | (35 << 4)": hex((0xF00F & ~0x0FF0 & 0xFFFF) | (35 << 4)),
        "(0x1234 & ~0x0001) | 1": hex((0x1234 & ~0x0001 & 0xFFFF) | 1),
        "abs(5.1-5.07) vs 0.5e-3 / 0.5e-1": (abs(5.1 - 5.07), 0.5e-3, 0.5e-1),
    }
    for k, v in facts.items():
        line(f"P7 {k}", v)

    # ---------------- P8 the definitions case: the pinned draw order, simulated ----------------
    rng = random.Random(20260001)
    fill = bytearray(rng.randrange(256) for _ in range(256))
    enum_raw = rng.choice([0, 1, 2, 3])
    bit = rng.randrange(2)
    field = rng.randrange(256)
    disp_raw = rng.randint(-80, 300)
    buf = bytearray(fill)
    buf[0x00] = enum_raw
    word_before = int.from_bytes(fill[0x10:0x12], "big")
    word = (word_before & ~0x0FF1 & 0xFFFF) | (field << 4) | bit
    buf[0x10:0x12] = word.to_bytes(2, "big")
    buf[0x20:0x22] = struct.pack(">h", disp_raw)
    line("P8 DEFC planned: enum raw / bit / field / display raw / display physical",
         (enum_raw, bit, field, disp_raw, disp_raw * 0.5))
    line("P8 DEFC fill word at +0x10 / planned word / bytes +0x00, +0x10..+0x11, +0x20..+0x21",
         (hex(word_before), hex(word), buf[0x00:0x01].hex(), buf[0x10:0x12].hex(" "), buf[0x20:0x22].hex(" ")))
    print("# exit 0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
