"""P07: multi-variant projects (S19 + a HEX variant) — is the selected active
variant restored, is each variant's image byte-exact after Load, and does
selecting a variant re-copy anything?"""
from common import *
from s19_app.core import S19File
from s19_app.hexfile import IntelHexFile


async def main():
    base = new_base()
    # a HEX made by the repo's own flow writer from case_00 prg.s19
    from s19_app.tui.services.flow_model import Flow, FlowContext, SourceBlock, WriteOutBlock
    from s19_app.tui.services.flow_execution_service import run_flow
    gen = base / ".s19tool" / "workarea" / "gen"; gen.mkdir(parents=True)
    shutil.copyfile(EX / "case_00_public/prg.s19", gen / "prg.s19")
    r = run_flow(Flow(name="g", blocks=[SourceBlock("prg.s19"), WriteOutBlock("prghex.hex", fmt="hex")]), FlowContext(project_dir=gen))
    hexsrc = base / "prghex.hex"; shutil.copyfile(r.written_paths[0], hexsrc); shutil.rmtree(gen)
    app = new_app(base)
    async with app.run_test(size=(160, 50)) as pilot:
        await settle(app, pilot)
        await load_path(app, pilot, C1 / "firmware.s19")
        save_project(app, app.workarea, "V"); await settle(app, pilot)
        await load_path(app, pilot, hexsrc)                      # appended as variant (project open)
        await load_path(app, pilot, EX / "case_00_public/prg.s19")  # appended as variant
        print("variants:", [v.variant_id for v in app._variant_set.variants], "active:", app._variant_set.active_id)
        app._handle_select_variant("prghex"); await settle(app, pilot)
        print("after select prghex -> current:", app.current_file.path.name, "active:", app._variant_set.active_id)
        mem_hex = mem_digest(app.current_file.mem_map)
        save_project(app, app.workarea, "V"); await settle(app, pilot)
        proj = app.workarea / "V"
        print("V tree:", [l.split('  ')[0] for l in tree(proj)], "| project.json active:", json.loads((proj / "project.json").read_text())["active_variant"])
        print("temp:", sorted(p.name for p in (app.workarea / "temp").iterdir()))
    app2 = new_app(base)
    async with app2.run_test(size=(160, 50)) as pilot:
        await settle(app2, pilot)
        app2._handle_load_project("V"); await settle(app2, pilot)
        print("RELOAD active:", app2._variant_set.active_id, "file:", app2.current_file.path.name, "image == pre-save HEX image:", mem_digest(app2.current_file.mem_map) == mem_hex)
        for v in app2._variant_set.variants:
            disk = S19File(str(v.path)).get_memory_map() if v.file_type == "s19" else dict(IntelHexFile(str(v.path)).memory)
            print("   variant", v.variant_id, v.file_type, mem_digest(disk))
        tb = sorted(p.name for p in (app2.workarea / "temp").iterdir())
        app2._handle_select_variant("prg"); await settle(app2, pilot)
        print("select prg after reload -> status:", app2._probe_status[-1:], "| temp grew:", sorted(p.name for p in (app2.workarea / "temp").iterdir()) != tb,
              "| project files:", [l.split('  ')[0] for l in tree(app2.workarea / "V")])


asyncio.run(main())
