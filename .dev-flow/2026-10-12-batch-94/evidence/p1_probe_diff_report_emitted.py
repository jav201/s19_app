"""P1 C-35/C-42 probe — emit a REAL A2B diff report headless over two
in-repo S19 fixtures and print the producer's actual emitted header form.

The US-005 acceptance that keys on "the report states each input's
provenance" must be written against THIS emitted form (the `- Image A:`
/ `- Image B:` lines of _header_lines), not a rendering of it.

Run headless from the repo root:

    PYTHONUTF8=1 python -B .dev-flow/2026-10-12-batch-94/evidence/p1_probe_diff_report_emitted.py
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from s19_app.core import S19File
from s19_app.tui.services.compare_service import SOURCE_EXTERNAL, ImageSource, compare_images
from s19_app.tui.services.diff_report_service import generate_diff_report
from s19_app.tui.services.load_service import build_loaded_s19

ROOT = Path(__file__).resolve().parents[3]
FIX_A = ROOT / "examples" / "case_00_public" / "prg.s19"
FIX_B = ROOT / "examples" / "case_00_public" / "s19_sample.s19"

cmp_res = compare_images(
    ImageSource(kind=SOURCE_EXTERNAL, raw_path=str(FIX_A), label="prg"),
    ImageSource(kind=SOURCE_EXTERNAL, raw_path=str(FIX_B), label="sample"),
)
print(f"compare_images status: {cmp_res.status!r}" if hasattr(cmp_res, "status") else f"compare result fields: {[f for f in dir(cmp_res) if not f.startswith('_')]}")

loaded_a = build_loaded_s19(FIX_A, S19File(str(FIX_A)), None, None)
loaded_b = build_loaded_s19(FIX_B, S19File(str(FIX_B)), None, None)

with tempfile.TemporaryDirectory() as tmp:
    result = generate_diff_report(
        cmp_res,
        mem_map_a=loaded_a.mem_map,
        mem_map_b=loaded_b.mem_map,
        dest_input=tmp,
        filename_stem="p1_probe",
    )
    print(f"generate_diff_report -> written={result.written!r} path={result.path}")
    text = Path(result.path).read_text(encoding="utf-8")
    lines = text.splitlines()
    print(f"report line count: {len(lines)}")
    print("== emitted header (first 30 lines, verbatim) ==")
    for i, line in enumerate(lines[:30], 1):
        print(f"{i:03d}| {line}")
    probe = [ln for ln in lines if ln.startswith("- Image")]
    print("== the provenance-addressable lines ==")
    for ln in probe:
        print(f"  {ln!r}")

print("\nPROBE OK")
