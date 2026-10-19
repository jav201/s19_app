"""P1 C-39 probe — rail census and binding space (threshold material for
the rail 10 -> 12 HLR; key binding stays OPEN to PDR per R11).

Run headless from the repo root:

    PYTHONUTF8=1 python -B .dev-flow/2026-10-12-batch-94/evidence/p1_probe_rail_census.py
"""
from __future__ import annotations

import sys
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from s19_app.tui.rail import RAIL_ENTRIES

print(f"RAIL_ENTRIES count: {len(RAIL_ENTRIES)}")
for i, entry in enumerate(RAIL_ENTRIES, 1):
    d = asdict(entry)
    key = d.get("key") or d.get("binding") or "?"
    label = d.get("label") or d.get("title") or "?"
    print(f"  {i:2d}. key={key!r:6} label={label!r}")
print(f"binding key space consumed: {len(RAIL_ENTRIES)} of '1'..'0' (10 slots)")
print("\nPROBE OK")
