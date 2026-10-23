"""P14: does the repo's own diff (diff_mem_maps over the repo loader, used by
verify-on-save, A2B and before/after reports) see the injected 0x0 data
record? Source vs identity WRITE-OUT of case_01."""
from common import *
from s19_app.core import S19File
from s19_app.tui.services.flow_model import Flow, FlowContext, SourceBlock, WriteOutBlock
from s19_app.tui.services.flow_execution_service import run_flow
from s19_app.tui.services.compare_service import diff_mem_maps
from s19_app.tui.changes.verify import verify_written_image
proj = new_project(src=EX / "case_01_basic_valid" / "firmware.s19", dst_name="fw.s19")
r = run_flow(Flow(name="i", blocks=[SourceBlock("fw.s19"), WriteOutBlock("i.s19")]), FlowContext(project_dir=proj))
a = S19File(str(proj / "fw.s19")).get_memory_map(); b = S19File(str(r.written_paths[0])).get_memory_map()
runs, stats = diff_mem_maps(a, b)
print("repo diff source vs written: runs =", len(runs), "| verify_written_image:", verify_written_image(r.written_paths[0], a, "s19").status)
ia, ib = mini_s19(proj / "fw.s19")[0], mini_s19(r.written_paths[0])[0]
print("independent parser: written-only addresses =", len(set(ib) - set(ia)))
