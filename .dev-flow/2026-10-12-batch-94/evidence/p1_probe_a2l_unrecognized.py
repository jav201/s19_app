"""P1 C-39 probe — count A2L_UNRECOGNIZED_BLOCK findings over the closest
in-repo stand-in for the operator's software_a_2.a2l.

The operator's file (13 990 tags, 4 489 warnings) is NOT in the repo.
examples/case_00_public/software_a.a2l carries 13 990 tags (10 538
MEASUREMENT + 3 452 CHARACTERISTIC) and is the closest in-repo fixture.
Run headless from the repo root:

    PYTHONUTF8=1 python -B .dev-flow/2026-10-12-batch-94/evidence/p1_probe_a2l_unrecognized.py
"""
from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from s19_app.tui.a2l import parse_a2l_file
from s19_app.validation.rules import RECOGNIZED_A2L_BLOCKS, validate_a2l_structure

FIXTURE = ROOT / "examples" / "case_00_public" / "software_a.a2l"

data = parse_a2l_file(FIXTURE)
issues = validate_a2l_structure(data)

tags = data.get("tags", [])
sections = data.get("sections", [])
sev = Counter(i.severity.name for i in issues)
by_code = Counter(i.code for i in issues)
unrec = [i for i in issues if i.code == "A2L_UNRECOGNIZED_BLOCK"]
tally = Counter(i.message for i in unrec)

print(f"fixture          : {FIXTURE.relative_to(ROOT)} ({FIXTURE.stat().st_size} bytes)")
print(f"tags             : {len(tags)}")
print(f"top-level sections: {len(sections)}")
print(f"issues total     : {len(issues)}  by severity: {dict(sev)}")
print(f"issues by code   : {dict(by_code)}")
print(f"A2L_UNRECOGNIZED_BLOCK count: {len(unrec)}")
print("per-block tally  :")
for msg, n in sorted(tally.items(), key=lambda kv: (-kv[1], kv[0])):
    print(f"  {n:5d}  {msg}")
print(f"RECOGNIZED_A2L_BLOCKS has {len(RECOGNIZED_A2L_BLOCKS)} entries")
print(f"parse errors     : {len(data.get('errors', []))}")
