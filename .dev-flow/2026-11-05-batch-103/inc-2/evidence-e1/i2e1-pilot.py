"""Inc 2 E1 pilot (batch-103): what the base tree does today with the scalar
kinds of the definition model, on real A2L shapes.

Imports ``s19_app`` from the read-only clone given on the command line and
drives only pure functions (no app, no screen, no clipboard): the parse of
the ASAM demo files and the a2ltool / Simulink shapes, the decode the tag
table uses (``enrich_a2l_tags_with_values``) and the encode the change path
uses (``encode_physical_to_raw_bytes``). Each probe prints the fact a "Base"
cell of ``01-requirements.md`` cites as ``B line <n>``.

Usage: python i2e1-pilot.py <repo clone>
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path


def main(argv: list[str]) -> int:
    repo = Path(argv[1]).resolve()
    sys.path.insert(0, str(repo))
    import s19_app  # noqa: E402
    from s19_app.tui import a2l  # noqa: E402

    print(f"s19_app.__file__ = {s19_app.__file__}")
    demo = repo / "examples" / "case_00_public"
    v171 = a2l.parse_a2l_file(demo / "ASAP2_Demo_V171.a2l")
    v161 = a2l.parse_a2l_file(demo / "ASAP2_Demo_V161.a2l")
    soft_a = a2l.parse_a2l_file(demo / "software_a.a2l")
    tube = a2l.parse_a2l_file(demo / "BalanceTube_STMicro.a2l")
    by_name = {t["name"]: t for t in v171["tags"]}

    def probe(label: str, value: object) -> None:
        print(f"[{label}] {value!r}")

    # P1 TAB_VERB conversion methods: the type a2l.py reads.
    m = v171["compu_methods_by_name"]
    probe("P1a V171 CM.TAB_VERB.DEFAULT_VALUE conversion_type/format/unit/ref",
          (m["CM.TAB_VERB.DEFAULT_VALUE"]["conversion_type"], m["CM.TAB_VERB.DEFAULT_VALUE"]["format"],
           m["CM.TAB_VERB.DEFAULT_VALUE"]["unit"], m["CM.TAB_VERB.DEFAULT_VALUE"]["compu_tab_ref"]))
    probe("P1b V171 CM.VTAB_RANGE.DEFAULT_VALUE conversion_type/ref",
          (m["CM.VTAB_RANGE.DEFAULT_VALUE"]["conversion_type"], m["CM.VTAB_RANGE.DEFAULT_VALUE"]["compu_tab_ref"]))
    tab_verb_a = [n for n, d in soft_a["compu_methods_by_name"].items()
                  if any(l.strip().startswith("TAB_VERB") for l in d["lines"])]
    probe("P1c software_a TAB_VERB methods (by body line) / with conversion_type TAB_VERB",
          (len(tab_verb_a), sum(1 for n in tab_verb_a
                                if soft_a["compu_methods_by_name"][n]["conversion_type"] == "TAB_VERB")))
    gm = tube["compu_methods_by_name"].get("esdl_model_GameControllerStatemachineStates", {})
    probe("P1d BalanceTube esdl_model_GameControllerStatemachineStates conversion_type/format/ref",
          (gm.get("conversion_type"), gm.get("format"), gm.get("compu_tab_ref")))
    probe("P1e TAB_VERB in COMPU_CONVERSION_KEYWORDS", "TAB_VERB" in a2l.COMPU_CONVERSION_KEYWORDS)

    # P2 the tag-table decode of a TAB_VERB VALUE (raw 2 = "Square").
    tag = by_name["ASAM.C.SCALAR.SWORD.TAB_VERB_DEFAULT_VALUE"]
    mem = {tag["address"] + i: b for i, b in enumerate(struct.pack("<h", 2))}
    row = a2l.enrich_a2l_tags_with_values({**v171, "tags": [tag]}, mem)[0]
    probe("P2 TAB_VERB VALUE raw 2: raw/physical/status/error",
          (row["raw_value"], row["physical_value"], row["conversion_status"], row["conversion_error"]))

    # P3 the COMPU_VTAB side table: texts kept, DEFAULT_VALUE dropped; COMPU_VTAB_RANGE absent.
    tabs = v171["compu_tabs_by_name"]
    probe("P3a V171 COMPU_VTAB CM.TAB_VERB.DEFAULT_VALUE.REF entries/kind",
          (tabs["CM.TAB_VERB.DEFAULT_VALUE.REF"]["entries"], tabs["CM.TAB_VERB.DEFAULT_VALUE.REF"]["kind"]))
    probe("P3b DEFAULT_VALUE text kept anywhere in the side table",
          any("unknown signal type" == str(y) for _x, y in tabs["CM.TAB_VERB.DEFAULT_VALUE.REF"]["entries"]))
    probe("P3c COMPU_VTAB_RANGE CM.VTAB_RANGE.DEFAULT_VALUE.REF in compu_tabs_by_name",
          "CM.VTAB_RANGE.DEFAULT_VALUE.REF" in tabs)
    probe("P3d sections named COMPU_VTAB_RANGE in V171 / V161 / software_a",
          tuple(len(a2l._collect_sections_by_name(p["sections"], "COMPU_VTAB_RANGE"))
                for p in (v171, v161, soft_a)))

    # P4 BIT_MASK: the tag keeps the text, the decode ignores it.
    tag = by_name["ASAM.C.SCALAR.UWORD.IDENTICAL.BITMASK_0FF0"]
    mem = {tag["address"] + i: b for i, b in enumerate(struct.pack("<H", 0x1234))}
    row = a2l.enrich_a2l_tags_with_values({**v171, "tags": [tag]}, mem)[0]
    probe("P4 BITMASK_0FF0 word 0x1234: bit_org/raw/physical (masked field would be 0x23 = 35)",
          (tag["bit_org"], row["raw_value"], row["physical_value"]))

    # P5 the encode on a BIT_MASK tag: the whole word is written.
    raw, err, flags = a2l.encode_physical_to_raw_bytes(
        tag, 35, v171["compu_methods_by_name"], v171["compu_tabs_by_name"], v171["record_layouts_by_name"])
    probe("P5 encode 35 on BITMASK_0FF0: bytes/error/flags (bits outside 0x0FF0 not kept)", (raw, err, flags))

    # P6 PHYS_UNIT: the unit a2l.py gives a tag with a PHYS_UNIT line.
    soft_by = {t["name"]: t for t in soft_a["tags"]}
    t6 = soft_by.get("BcpGxvlbvneyoAudnMhl.DRCDJ_XNIFM_DSURLVD_VSJMQJBMW", {})
    probe("P6 software_a tag with PHYS_UNIT \"V\": unit", t6.get("unit"))

    # P7 FORMAT: no tag field; the method format.
    t7 = by_name["ASAM.C.SCALAR.SBYTE.IDENTICAL"]
    probe("P7a tag keys holding a format (FORMAT \"%6.1\" in the file)", [k for k in t7 if "format" in k.lower()])
    probe("P7b V171 CM.IDENTICAL format/unit", (m["CM.IDENTICAL"]["format"], m["CM.IDENTICAL"]["unit"]))

    # P8 EXTENDED_LIMITS: no tag field.
    probe("P8 tag keys holding extended limits (EXTENDED_LIMITS -128 127 in the file)",
          [k for k in t7 if "extend" in k.lower()])
    probe("P8b limits as the tag holds them", (t7["lower_limit"], t7["upper_limit"]))

    # P9 ASCII: the V171 string (name on the line after /begin) and its decode.
    asc = [t for t in v171["tags"] if t.get("char_type") == "ASCII"]
    probe("P9a V171 ASCII tags: name/length/address", [(t["name"], t["length"], t["address"]) for t in asc])
    if asc:
        text = b"Hello ASAM\x00" + b"\x00" * 31
        mem = {asc[0]["address"] + i: b for i, b in enumerate(text)} if asc[0]["address"] is not None else {}
        row = a2l.enrich_a2l_tags_with_values({**v171, "tags": [asc[0]]}, mem)[0]
        probe("P9b ASCII decode of 'Hello ASAM': raw/physical/byte_size",
              (row["raw_value"], row["physical_value"], row["byte_size"]))

    # P10 FLOAT16: the decode gives no value.
    probe("P10 _decode_scalar(FLOAT16 0x3C00 = 1.0)", a2l._decode_scalar(bytes([0x00, 0x3C]), "FLOAT16_IEEE", "little"))

    # P11 encode refusal texts on real tags.
    lin = dict(by_name["ASAM.C.SCALAR.SWORD.IDENTICAL"]) if "ASAM.C.SCALAR.SWORD.IDENTICAL" in by_name else None
    if lin is not None:
        lin["compu_method_name"] = "CM.LINEAR.MUL_2"
        lin["lower_limit"], lin["upper_limit"] = "-100", "100"
        for value in (3, 200, 1e9):
            probe(f"P11a encode {value} with LINEAR a=2 on SWORD (limits -100..100)",
                  a2l.encode_physical_to_raw_bytes(lin, value, v171["compu_methods_by_name"],
                                                   v171["compu_tabs_by_name"], v171["record_layouts_by_name"]))
    tv = by_name["ASAM.C.SCALAR.SWORD.TAB_VERB_DEFAULT_VALUE"]
    probe("P11b encode 2 on the TAB_VERB VALUE",
          a2l.encode_physical_to_raw_bytes(tv, 2, v171["compu_methods_by_name"], v171["compu_tabs_by_name"],
                                           v171["record_layouts_by_name"]))
    if asc:
        probe("P11c encode on the ASCII tag",
              a2l.encode_physical_to_raw_bytes(asc[0], 1, v171["compu_methods_by_name"],
                                               v171["compu_tabs_by_name"], v171["record_layouts_by_name"]))
    f16 = {"name": "F16", "datatype": "FLOAT16_IEEE", "length": 2, "char_type": "VALUE"}
    probe("P11d encode 1.0 on FLOAT16", a2l.encode_physical_to_raw_bytes(f16, 1.0))
    miss = {"name": "MISS", "datatype": "UBYTE", "length": 1, "char_type": "VALUE", "compu_method_name": "CM_NOT_THERE"}
    probe("P11e encode 7 with an undeclared COMPU_METHOD (identity)", a2l.encode_physical_to_raw_bytes(miss, 7, {}, {}))
    f32 = {"name": "F32", "datatype": "FLOAT32_IEEE", "length": 4, "char_type": "VALUE",
           "effective_byte_order": "little"}
    packed, _e, _f = a2l.encode_physical_to_raw_bytes(f32, 0.1)
    probe("P11f encode 0.1 on FLOAT32 identity -> decoded back",
          (packed, struct.unpack("<f", bytes(packed))[0] if packed else None))

    # P12 decode of the undeclared COMPU_METHOD (tag table: identity fallback).
    row = a2l.enrich_a2l_tags_with_values({"tags": [miss]}, {0: 7})[0] if miss.get("address") else None
    miss_addr = dict(miss, address=0)
    row = a2l.enrich_a2l_tags_with_values({"tags": [miss_addr]}, {0: 7})[0]
    probe("P12 decode with an undeclared COMPU_METHOD: physical/status/error",
          (row["physical_value"], row["conversion_status"], row["conversion_error"]))

    # P13 the format strings the fixtures carry (census for the display-format grammar).
    formats: dict[str, int] = {}
    for parsed in (v171, v161, soft_a, tube):
        for method in parsed["compu_methods_by_name"].values():
            fmt = method.get("format")
            formats[str(fmt)] = formats.get(str(fmt), 0) + 1
    probe("P13 method formats as a2l.py reads them (V171, V161, software_a, BalanceTube)",
          sorted(formats.items(), key=lambda kv: -kv[1])[:12])
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
