"""Probe: real cost of the frozen Inc 2 producer on the E1 host with the
case_06 fixture — enrich + 2 bulk describes over 220,040 tags."""
import time
from pathlib import Path

from s19_app.tui.a2l import parse_a2l_file
from s19_app.tui.services.a2l_service import enrich_tags_and_render
from s19_app.tui.a2l_definition import describe_definitions

ROOT = Path(__file__).resolve().parents[4]
CASE06 = ROOT / "examples" / "case_06_large_nested_a2l" / "firmware.a2l"
IMAGE = ROOT / "examples" / "case_06_large_nested_a2l" / "firmware.s19"

t0 = time.perf_counter()
data = parse_a2l_file(CASE06)
t1 = time.perf_counter()
print(f"parse: {t1 - t0:.3f}s tags={len(data['tags'])} errors={len(data['errors'])}")

enriched, _summary = enrich_tags_and_render(data, None, max_tag_lines=500)
t2 = time.perf_counter()
print(f"enrich (no image): {t2 - t1:.3f}s tags={len(enriched)}")

names = [tag["name"] for tag in enriched if isinstance(tag.get("address"), int)]
t3 = time.perf_counter()
check = describe_definitions(names, data)
t4 = time.perf_counter()
patch = describe_definitions(names, data)
t5 = time.perf_counter()
print(f"names={len(names)} check-describe: {t4 - t3:.3f}s patch-describe: {t5 - t4:.3f}s")
print(f"definitions check={len(check)} patch={len(patch)}")
print(f"producer-equivalent total: {t5 - t0:.3f}s")
