"""p11b U4b: why a MAC-only session's change entry is neither blocked nor emitted (LLR-175.1n)."""
import shutil, sys
from pathlib import Path
tree = Path(sys.argv[1]); work = Path(sys.argv[2]); sys.path.insert(0, str(tree))
from tests.support import b100_projects as projects
CASE01 = tree / "examples" / "case_01_basic_valid"

async def scen(app, pilot, log):
    app._load_path_from_user_input(CASE01 / "firmware.mac")
    await projects.wait_for(pilot, lambda: app.current_file is not None, "mac load")
    cf = app.current_file; svc = app._change_service
    svc.add_entry("0x80000000", "", "5A")
    print("== U4b differs_from_source", svc.image_differs_from_source(cf.mem_map))
    derived, summary = svc.rederive_for_save(dict(cf.mem_map), ranges=cf.ranges, session_map=cf.mem_map,
                                             mac_records=cf.mac_records, a2l_tags=None)
    print("== U4b dispositions", [(hex(r.address_start), r.disposition) for r in summary.entries])
    print("== U4b derived", {hex(k): v for k, v in derived.items()})
    print("== U4b rederived_differs", svc.rederived_differs_from_source(cf.mem_map, derived))
    res = svc.apply(cf.mem_map, cf.ranges, cf.mac_records, None)
    print("== U4b apply result", getattr(res, "message", res))

base = work / "p11b" / "u4b"; shutil.rmtree(base, ignore_errors=True); base.mkdir(parents=True)
projects.run_app(base, scen)
