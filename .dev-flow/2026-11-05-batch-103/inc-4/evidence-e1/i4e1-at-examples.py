#!/usr/bin/env python3
"""batch-103 Inc 4 E1: ranked lists of the two black-box cases AT-B103-I4-1 and -2.

THROWAWAY EVIDENCE. Run on cachyos-rtx next to i4e1-pilot.py (v1); uses its
naive oracle. AT-1: a typing sequence over the case-08 names. AT-2: the
operator's words (start, middle, end of a name, words, a typo) over the
13,990 real-shape names of software_a.a2l.
"""
import os
import runpy
from pathlib import Path

HERE = Path(os.environ.get("PILOT_DIR", "/tmp/b103-e1-4"))
P1 = runpy.run_path(str(HERE / "i4e1-pilot.py"), run_name="i4e1_pilot_v1")
naive_rank, names_of, REPO, OUT, s19_app = P1["naive_rank"], P1["names_of"], P1["REPO"], P1["OUT"], P1["s19_app"]
print(f"s19_app.__file__ = {s19_app.__file__}")
case08 = names_of(OUT / "firmware.a2l")
sw_a = names_of(REPO / "examples/case_00_public/software_a.a2l")
print(f"case08 {len(case08)}  software_a {len(sw_a)}  software_a[1234] = {sw_a[1234]!r}")
print("\n=== AT-1 typing over case08, limit 5")
for q in ["m", "ma", "map", "map_", "map_00", "map_002", "map_0020", "map 20", "map20"]:
    print(f"query={q!r}")
    for row in naive_rank(q, case08, 5):
        print(f"    {row}")
print("\n=== AT-2 operator's words over software_a, limit 5")
target = sw_a[1234]
for q in ["JotafVod_msrqlLzL_kh2C_rWl_pfue._0_", "jotafvod", "msrqlLzL", "rWl_pfue", "pfue._0_", "jotaf vod", "vod jotaf", "jotfa vod", "jtfvd"]:
    rows = naive_rank(q, sw_a, 5)
    pos = next((i for i, r in enumerate(rows) if r[0] == target), None)
    print(f"query={q!r}  target position = {pos}")
    for row in rows:
        print(f"    {row}")
