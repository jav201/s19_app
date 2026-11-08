#!/usr/bin/env python3
"""batch-103 Inc 4 E2: _classify (folded and case-sensitive) and _order_key values the graph quotes.

THROWAWAY EVIDENCE, NOT PRODUCT CODE. Run on <runner> in PILOT_DIR next to
the E1 pilots. Uses the E1 oracle's evaluate_b only: evaluate_b(q, name) is
the graph's _classify on the folded query, evaluate_b(q, name, folded=False)
its case-sensitive call; case-exact = the two give the same rule.
"""
from __future__ import annotations

import os
import runpy
import sys
from pathlib import Path

HERE = Path(os.environ.get("PILOT_DIR", "/tmp/b103-e2-4"))
P3 = runpy.run_path(str(HERE / "i4e1-pilot3.py"), run_name="i4e1_pilot_v3")
evaluate_b, RULES_B, s19_app = P3["evaluate_b"], P3["RULES_B"], P3["s19_app"]


def main() -> int:
    print(f"s19_app.__file__ = {s19_app.__file__}")
    print(f"python = {sys.version.split()[0]}  host = {os.uname().nodename}")
    cases = [
        ("value_000", "VALUE_0001"), ("vale_0001", "VALUE_0001"), ("valu_0001", "VAL_BLK_0001"), ("count", "DiscountCount"),
        ("ounter", "model.MainClass.ledController.sw.timeCounter"), ("counter", "timeCounter"), ("counter", "Encounter"),
        ("drück", "druck_max"), ("drück", "DRÜCK_MAX"), ("drück", "Drück_Max"), ("rpm", "RPMX"), ("rpm", "rpm_x"),
        ("RPM", "RPM"), ("RPM", "Rpm"), ("RPM", "rpm"), ("curvee", "CURVE_0001"), ("curvee", "CUVE"), ("mp", "MAP_0001"),
        ("map 20", "MAP_0020"), ("temp_sensor_max", "VALUE_0001"), ("knife 1 x", "parameter_instance[1].Knife[0].x"),
    ]
    print("\n=== query, name -> folded (rule, key, spans) | case-sensitive (rule, key, spans) | case-exact | order key")
    for q, name in cases:
        f = evaluate_b(q, name)
        c = evaluate_b(q, name, folded=False)
        fs = None if f is None else (RULES_B[f[0]], f[1], f[2])
        cs = None if c is None else (RULES_B[c[0]], c[1], c[2])
        ce = f is not None and c is not None and c[0] == f[0]
        key = None if f is None else (f[0], f[1], len(name), 0 if ce else 1, name)
        print(f"  {q!r:18s} {name!r:48s} -> {fs} | {cs} | case-exact {ce} | order key {key}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
