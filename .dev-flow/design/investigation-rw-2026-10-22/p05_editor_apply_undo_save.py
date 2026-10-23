"""P05: Patch Editor service path (ChangeService) — apply mutates the loaded
image in place; does undo/remove + re-apply leave earlier writes in the saved
file while the summary/verify say otherwise? Also: verify-on-save vs the S0
header injection."""
from common import *
from pathlib import Path
from s19_app.core import S19File
from s19_app.tui.services.load_service import build_loaded_s19
from s19_app.tui.services.change_service import ChangeService

proj = new_project(src=EX / "case_00_public" / "prg.s19")
src_mem, _, _ = mini_s19(proj / "prg.s19")
loaded = build_loaded_s19(proj / "prg.s19", S19File(str(proj / "prg.s19")), None, None)
svc = ChangeService()
svc.add_entry("0xEB10", "", "DE AD BE EF")
s1 = svc.apply(loaded.mem_map, loaded.ranges, None, None)
print("apply#1 counts:", {k: v for k, v in s1.counts.items() if v})
svc.undo()
print("after undo: entries =", len(svc.document.entries), "| last_summary =", svc.last_summary)
svc.add_entry("0xEB40", "", "01 02")
s2 = svc.apply(loaded.mem_map, loaded.ranges, None, None)
print("apply#2 counts:", {k: v for k, v in s2.counts.items() if v}, "entries:", [hex(e.address_start) for e in s2.entries])
res = svc.save_patched(loaded.mem_map, loaded.ranges, proj, "edited.s19", source_kind="s19")
out = proj / "edited.s19"
mem, errs, _ = mini_s19(out)
print("save:", res.ok, res.message, "| verify:", svc.last_summary.verify_result.status)
print("file @0xEB10 =", bytes(mem[a] for a in range(0xEB10, 0xEB14)).hex(), "(source:", bytes(src_mem[a] for a in range(0xEB10, 0xEB14)).hex(), ") — summary of the saved apply lists only", [hex(e.address_start) for e in svc.last_summary.entries])

# Straddle + gap entries in the editor
svc2 = ChangeService()
svc2.add_entry("0xFFFF", "", "AA BB")        # straddles image end (0x10000)
svc2.add_entry("0xEB02", "", "11 22 33")     # spans the gap 0xEB02..0xEB04
s3 = svc2.apply(loaded.mem_map, loaded.ranges, None, None)
print("straddle/gap counts:", {k: v for k, v in s3.counts.items() if v})

# S0 header round-trip through the editor save with verify
proj2 = new_project(src=EX / "case_01_basic_valid" / "firmware.s19", dst_name="fw.s19")
src2, _, _ = mini_s19(proj2 / "fw.s19")
l2 = build_loaded_s19(proj2 / "fw.s19", S19File(str(proj2 / "fw.s19")), None, None)
svc3 = ChangeService(); svc3.add_entry("0x80000000", "", "00")
svc3.apply(l2.mem_map, l2.ranges, None, None)
r = svc3.save_patched(l2.mem_map, l2.ranges, proj2, "fw_out.s19", source_kind="s19", s0_header=l2.source_s0_header)
m3, _, meta = mini_s19(proj2 / "fw_out.s19")
extra = sorted(set(m3) - set(src2))
print("editor save fw: verify =", svc3.last_summary.verify_result.status, "| extra data bytes in file:", len(extra), [hex(a) for a in extra[:3]], "=", bytes(m3[a] for a in extra))
print("loaded.mem_map has 0x0..:", 0 in l2.mem_map, "| ranges[0] =", [hex(x) for x in l2.ranges[0]])
