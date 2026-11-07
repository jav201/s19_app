#!/usr/bin/env python3
"""batch-103 Inc 4 E1: ranked lists of the curated cases of 02-test-cases.md.

THROWAWAY EVIDENCE. Run on <runner> next to i4e1-pilot.py (v1), whose
naive oracle (the proposed rules written directly) it loads with runpy. The
expected results in 02-test-cases.md were derived from the rules by hand and
then compared with this transcript; a difference is a defect of the rules'
wording or of the derivation, resolved in the record, never by copying.
"""
from __future__ import annotations

import os
import runpy
from pathlib import Path

HERE = Path(os.environ.get("PILOT_DIR", "/tmp/b103-e1-4"))
P1 = runpy.run_path(str(HERE / "i4e1-pilot.py"), run_name="i4e1_pilot_v1")
naive_rank = P1["naive_rank"]
names_of = P1["names_of"]
osa_prefix = P1["osa_prefix"]
REPO, OUT, s19_app = P1["REPO"], P1["OUT"], P1["s19_app"]


def show(label, names, q, lim):
    rows = naive_rank(q, names, lim)
    print(f"[{label}] query={q!r} limit={lim}")
    if not rows:
        print("    (empty)")
    for name, rule, key, spans in rows:
        print(f"    {name!r:52s} {rule:11s} key={key} spans={spans}")


def main() -> int:
    print(f"s19_app.__file__ = {s19_app.__file__}")
    case08 = names_of(OUT / "firmware.a2l")
    issues = names_of(OUT / "firmware_issues.a2l")
    bal = names_of(REPO / "examples/case_00_public/BalanceTube_STMicro.a2l")
    src = names_of(REPO / "examples/case_00_public/from_source.a2l")
    print(f"case08 {len(case08)} names; case08_issues {len(issues)} (VALUE_0001 x{issues.count('VALUE_0001')})")
    cases = [
        ("case08", case08, "\tVALUE_0001\n", 20),
        ("case08", case08, " value_000 ", 5),
        ("case08", case08, "\t\n", 20),
        ("case08", case08, "map_0020", 20),
        ("case08", case08, "VALUE-0001", 20),
        ("case08", case08, "_0001", 20),
        ("case08", case08, "cvure", 20),
        ("case08", case08, "valuexx_0001", 20),
        ("case08", case08, "valuexxx_0001", 20),
        ("case08", case08, "VALUE_0001_VALUE_0001", 20),
        ("case08", case08, "maesu", 3),
        ("case08", case08, "temp_sensor_max", 20),
        ("case08", case08, "0001", 20),
        ("case08_rev", list(reversed(case08)), "0001", 20),
        ("case08_issues", issues, "value_000", 20),
        ("curated", ["BA_X"], "ab", 20),
        ("curated", ["abc"], "ca", 20),
        ("curated", ["timeCounter", "Encounter"], "counter", 20),
        ("curated", ["DiscountCount"], "count", 20),
        ("curated", ["CUVE", "CURVE_0001"], "curvee", 20),
        ("curated", ["Curve_Map_X"], "cuvre maq", 20),
        ("curated", ["rpm_x", "RPMX"], "rpm", 20),
        ("curated", ["Rpm", "rpm", "RPM"], "rpm", 20),
        ("curated", ["", "   ", "VALUE_0001"], "v", 20),
        ("curated", ["ABSValue", "AValue", "engineSpeed", "Map3D"], "abs value", 20),
        ("curated", ["ABSValue", "AValue", "engineSpeed", "Map3D"], "a value", 20),
        ("curated", ["ABSValue", "AValue", "engineSpeed", "Map3D"], "engine speed", 20),
        ("curated", ["ABSValue", "AValue", "engineSpeed", "Map3D"], "map 3 d", 20),
        ("BalanceTube", bal, "gamecontroller timer", 3),
        ("from_source", src, "Fork.y", 20),
        ("from_source", src, "knife 1 x", 20),
    ]
    for c in cases:
        show(*c)
    print("\nOSA prefix distances used by the cases")
    for q, t in [("cvure", "curve"), ("valuexx", "value"), ("valuexxx", "value"), ("curvee", "curve"), ("curvee", "cuve"),
                 ("maesu", "measurement"), ("cuvre", "curve"), ("maq", "map"), ("ab", "ba"), ("ca", "abc")]:
        print(f"  d({q!r}, {t!r}) = {osa_prefix(q, t)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
