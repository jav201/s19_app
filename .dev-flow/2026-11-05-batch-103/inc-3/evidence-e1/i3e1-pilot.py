"""Inc 3 E1 pilot (batch-103): what the base tree does today with arrays,
curves, maps and their axes, on real A2L shapes and on case 08.

Imports ``s19_app`` from the read-only clone given on the command line and
drives only pure functions (no app, no screen, no clipboard): the parse
(``parse_a2l_file``), the tag-table decode (``enrich_a2l_tags_with_values``),
the description window's model (``describe_curve_tag``), the record-layout
walk and the curve encode (``encode_physical_to_raw_bytes`` with a list).
Each probe prints one fact a "Base" cell of ``01-requirements.md`` cites as
``B line <n>``. Case 08 is generated into the out dir (seed 20260001, 1 MiB).

Usage: python i3e1-pilot.py <repo clone> <out dir>
"""
from __future__ import annotations

import struct
import sys
from collections import Counter
from pathlib import Path


def main(argv: list[str]) -> int:
    repo = Path(argv[1]).resolve()
    out = Path(argv[2]).resolve()
    sys.path.insert(0, str(repo))
    sys.path.insert(0, str(repo / "tools" / "synth"))
    import s19_app  # noqa: E402
    from s19_app.tui import a2l  # noqa: E402
    import make_release_case as synth  # noqa: E402

    print(f"s19_app.__file__ = {s19_app.__file__}")
    print(f"make_release_case.__file__ = {synth.__file__}")
    demo = repo / "examples" / "case_00_public"
    v171 = a2l.parse_a2l_file(demo / "ASAP2_Demo_V171.a2l")
    soft_a = a2l.parse_a2l_file(demo / "software_a.a2l")
    by = {t["name"]: t for t in v171["tags"]}

    def probe(label: str, value: object) -> None:
        print(f"[{label}] {value!r}")

    def image(addr: int, data: bytes) -> dict[int, int]:
        return {addr + i: b for i, b in enumerate(data)}

    # P1-P3 MATRIX_DIM with more than one number: what the tag keeps.
    for n in ("ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR", "ASAM.C.ARRAY.SWORD.MATRIX_DIM_6.ROW_DIR",
              "ASAM.M.MATRIX_DIM_8_4_2.UBYTE.IDENTICAL", "ASAM.M.MATRIX_DIM_16_1.UBYTE.IDENTICAL"):
        t = by[n]
        probe(f"P1 {n}: matrix_dim/length/datatype", (t["matrix_dim"], t["length"], t["datatype"]))

    # P4 a2ltool VAL_BLKs sized by NUMBER: the tag length.
    vb_a = [t for t in soft_a["tags"] if t.get("char_type") == "VAL_BLK"]
    probe("P4 software_a VAL_BLK: count / with length None / matrix_dim None",
          (len(vb_a), sum(1 for t in vb_a if t["length"] is None), sum(1 for t in vb_a if t["matrix_dim"] is None)))

    # P5 the tag-table decode of a VAL_BLK (3x4 SWORD, ROW_DIR): 12 values 1..12 in the image.
    t = by["ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR"]
    mem = image(t["address"], b"".join(struct.pack("<h", v) for v in range(1, 13)))
    row = a2l.enrich_a2l_tags_with_values({**v171, "tags": [t]}, mem)[0]
    probe("P5 V171 VAL_BLK 3x4 values 1..12: raw/physical/element_count/byte_size",
          (row["raw_value"], row["physical_value"], row["element_count"], row["byte_size"]))

    # P6 a STD_AXIS curve with NO_AXIS_PTS_X and an INDEX_DECR axis (V171 RL.CURVE.SWORD.SBYTE.DECR).
    t = by["ASAM.C.CURVE.STD_AXIS"]
    probe("P6a V171 CURVE.STD_AXIS tag length / axis_meta max points", (t["length"], [a["max_axis_points"] for a in t["axis_meta"]]))
    rec = bytes([8]) + bytes((x & 0xFF) for x in (70, 60, 50, 40, 30, 20, 10, 0)) + b"".join(struct.pack("<h", 100 * i) for i in range(8))
    d = a2l.describe_curve_tag(t, v171, image(t["address"], rec))
    probe("P6b describe status / axis points_raw (memory order 70..0, INDEX_DECR) / values_raw",
          (d["status"], d["axes"][0].get("points_raw"), d.get("values_raw")))
    rec5 = bytes([5]) + rec[1:]
    d5 = a2l.describe_curve_tag(t, v171, image(t["address"], rec5))
    probe("P6c same record with NO_AXIS_PTS_X = 5: status / points count / values count",
          (d5["status"], len(d5["axes"][0].get("points_raw") or []), len(d5.get("values_raw") or [])))

    # P7 COM_AXIS curve: the AXIS_PTS section is not a tag.
    t = by["ASAM.C.CURVE.COM_AXIS"]
    probe("P7a V171 CURVE.COM_AXIS tag length", t["length"])
    probe("P7b AXIS_PTS ASAM.C.AXIS_PTS.UBYTE_8 is a tag", "ASAM.C.AXIS_PTS.UBYTE_8" in by)
    d = a2l.describe_curve_tag(t, v171, {})
    probe("P7c describe status / notes", (d["status"], d["notes"]))

    # P8 FIX_AXIS curves: points computed?
    for n in ("ASAM.C.CURVE.FIX_AXIS.PAR_DIST", "ASAM.C.CURVE.FIX_AXIS.PAR_LIST"):
        t = by[n]
        mem = image(t["address"], b"".join(struct.pack("<h", 10 * i) for i in range(6)))
        d = a2l.describe_curve_tag(t, v171, mem)
        probe(f"P8 {n}: status / x of the points / notes",
              (d["status"], [p["x"] for p in (d.get("points") or [])], d["notes"]))

    # P9 a MAP with an enum (TAB_VERB) second axis.
    t = by["ASAM.C.MAP.STD_AXIS.STD_AXIS"]
    rec = bytes([4, 5]) + bytes([1, 2, 3, 4]) + bytes([1, 2, 3, 4, 5]) + b"".join(struct.pack("<h", i) for i in range(20))
    d = a2l.describe_curve_tag(t, v171, image(t["address"], rec))
    probe("P9 V171 MAP.STD_AXIS.STD_AXIS: tag length / status / axis 2 points_phys / notes",
          (t["length"], d["status"], d["axes"][1].get("points_phys"), d["notes"]))

    # P10 software_a: the description model's shape resolution over every CURVE/MAP (no image).
    stat = Counter()
    for tg in soft_a["tags"]:
        if tg.get("char_type") in ("CURVE", "MAP"):
            stat[(tg["char_type"], a2l.describe_curve_tag(tg, soft_a, {})["status"], tg["length"] is None)] += 1
    probe("P10 software_a CURVE/MAP describe status (kind, status, length None) counts", sorted(stat.items()))

    # P11 the walk of an a2ltool layout with FIX_NO_AXIS_PTS_X.
    lay = {"lines": ["AXIS_PTS_X 1 SWORD INDEX_INCR DIRECT", "FNC_VALUES 2 SWORD ROW_DIR DIRECT", "FIX_NO_AXIS_PTS_X 5"]}
    probe("P11 walk of [AXIS_PTS_X, FNC_VALUES, FIX_NO_AXIS_PTS_X 5] with counts [5]",
          a2l._walk_record_layout_components(lay, [5]))
    probe("P11b walk of V171 RL.AXIS_PTS.RES_AXIS (RESERVED with a comment)",
          a2l._walk_record_layout_components(v171["record_layouts_by_name"]["RL.AXIS_PTS.RES_AXIS"], [5]))

    # P12 the curve encode on the V171 STD_AXIS curve: what lands in NO_AXIS_PTS_X, axis order, monotony.
    t = by["ASAM.C.CURVE.STD_AXIS"]
    args = (v171["compu_methods_by_name"], v171["compu_tabs_by_name"], v171["record_layouts_by_name"])
    data, err, flags = a2l.encode_physical_to_raw_bytes(t, [0, 10, 20, 30, 40, 50, 60, 70] + [1] * 8, *args)
    probe("P12a encode 8 increasing axis points + 8 values: error / first 9 bytes", (err, data[:9] if data else None))
    data, err, flags = a2l.encode_physical_to_raw_bytes(t, [0, 50, 20, 20, 40, 50, 60, 70] + [1] * 8, *args)
    probe("P12b encode a non-monotonic axis (0 50 20 20 ...): error / accepted", (err, data is not None))
    t = by["ASAM.C.CURVE.COM_AXIS"]
    data, err, flags = a2l.encode_physical_to_raw_bytes(t, [1] * 8, *args)
    probe("P12c encode on the COM_AXIS curve: error", err)
    t = by["ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR"]
    probe("P12d encode a list on a VAL_BLK: error", a2l.encode_physical_to_raw_bytes(t, [1] * 12, *args)[1])
    probe("P12e encode a number on a VAL_BLK: error", a2l.encode_physical_to_raw_bytes(t, 1, *args)[1])

    # P13 case 08: arrays as generated.
    c08 = out / "c08"
    synth.generate(c08, 20260001, 1.0)
    p = a2l.parse_a2l_file(c08 / "firmware.a2l")
    cby = {t["name"]: t for t in p["tags"]}
    for n in ("VAL_BLK_0001", "CURVE_0001", "MAP_0001"):
        t = cby[n]
        probe(f"P13a case 08 {n}: length / matrix_dim / layout lines / axis_meta",
              (t["length"], t["matrix_dim"], p["record_layouts_by_name"][t["record_layout_name"]]["lines"],
               [a["header_tokens"] for a in t["axis_meta"]]))
    objs = synth.build_objects(synth.compute_region_sizes(1.0), __import__("random").Random(20260001))
    o = {x["name"]: x for x in objs}
    for n in ("CURVE_0001", "MAP_0001"):
        t = cby[n]
        mem = image(o[n]["address"], o[n]["raw_bytes"])
        d = a2l.describe_curve_tag(t, p, mem)
        probe(f"P13b case 08 {n}: describe status / notes / first 3 values_raw",
              (d["status"], d["notes"], (d.get("values_raw") or [])[:3]))
    issues = a2l.parse_a2l_file(c08 / "firmware_issues.a2l")
    kinds = Counter((t.get("char_type") or t["section"]) for t in issues["tags"])
    probe("P13c case 08 firmware_issues.a2l tag kinds", sorted(kinds.items()))

    # P14 the datatype the tag table reads for a curve whose layout starts with NO_AXIS_PTS_X.
    t = by["ASAM.C.CURVE.STD_AXIS"]
    row = a2l.enrich_a2l_tags_with_values({**v171, "tags": [t]}, {})[0]
    probe("P14 V171 CURVE.STD_AXIS (FNC_VALUES SWORD): tag-table decode_type / element_count / byte_size",
          (row["decode_type"], row["element_count"], row["byte_size"]))
    # P15 a VAL_BLK with NUMBER (a2ltool shape) and one with LENGTH only (case 08 shape): tag length.
    t = next(x for x in soft_a["tags"] if x.get("char_type") == "VAL_BLK")
    probe("P15 software_a first VAL_BLK (NUMBER 4): length / matrix_dim", (t["length"], t["matrix_dim"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
