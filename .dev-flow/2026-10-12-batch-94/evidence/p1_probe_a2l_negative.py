"""P1 executed negative control for US-004 — a genuinely unknown A2L block
must STILL warn after the triage lands (reclassify/recognize the standard
blocks, never silence the class).

Run headless from the repo root:

    PYTHONUTF8=1 python -B .dev-flow/2026-10-12-batch-94/evidence/p1_probe_a2l_negative.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from s19_app.validation.rules import validate_a2l_structure

synthetic = {
    "sections": [
        {"name": "FROBNICATE", "start_line": 3, "lines": []},
        {"name": "MODULE", "start_line": 1, "lines": []},
    ],
    "errors": [],
    "tags": [],
}
issues = validate_a2l_structure(synthetic)
for i in issues:
    print(f"{i.severity.name:7} {i.code:25} {i.message}")
unrec = [i for i in issues if i.code == "A2L_UNRECOGNIZED_BLOCK"]
print(f"unknown-block warnings on synthetic fixture: {len(unrec)}")
assert len(unrec) == 1 and "FROBNICATE" in unrec[0].message
print("NEGATIVE CONTROL OK: the unknown block warns; the recognized one does not")
