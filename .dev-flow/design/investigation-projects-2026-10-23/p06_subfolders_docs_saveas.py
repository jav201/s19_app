"""P06: artifacts that live in project sub-folders (flows/, patches/, checks/,
reports/, flowsets/) and the Patch Editor document.

A: a FILE-BACKED change doc from the common patches folder is open in the Patch
   Editor at save time -> gathered into P/patches/? -> re-opened on Load?
B: a flow saved into P/flows -> listed after Load in a fresh app?
C: "Save as": Load P, save it under a new name Q -> what reaches Q?
"""
from common import *


async def main():
    base = new_base()
    app = new_app(base)
    async with app.run_test(size=(160, 50)) as pilot:
        await settle(app, pilot)
        await load_path(app, pilot, C1 / "firmware.s19")
        await load_path(app, pilot, C1 / "firmware.a2l")
        # A: file-backed change doc in the COMMON patches folder, opened in the editor
        addr = max(app.current_file.mem_map) - 1
        doc = write_doc_common(app.workarea / "patches" / "boost.json", [(addr, (0xAA, 0xBB))])
        from s19_app.tui.screens_directionb import PatchEditorPanel as Pn
        app.on_patch_editor_panel_action_requested(Pn.ActionRequested("load_doc", path_text=str(doc)))
        await settle(app, pilot)
        print("[A] editor doc before save:", app._change_service.document.source_path, len(app._change_service.document.entries))
        save_project(app, app.workarea, "P"); await settle(app, pilot)
        proj = app.workarea / "P"
        # B: a flow saved into the project
        from s19_app.tui.services.flow_model import Flow, SourceBlock, WriteOutBlock
        from s19_app.tui.services.flow_persistence_service import save_flow_json, list_saved_flows
        save_flow_json(Flow(name="f1", blocks=[SourceBlock("firmware.s19"), WriteOutBlock("out.s19", fmt="s19")]), "f1", proj)
        (proj / "reports").mkdir(exist_ok=True); (proj / "reports" / "r.md").write_text("report")
        print("[A/B] P tree after save + flow:", [l.split('  ')[0] for l in tree(proj)])
        print("[A] project.json:", json.loads((proj / "project.json").read_text()))
    app2 = new_app(base)
    async with app2.run_test(size=(160, 50)) as pilot:
        await settle(app2, pilot)
        app2._handle_load_project("P"); await settle(app2, pilot)
        print("[A] after Load: editor doc =", app2._change_service.document.source_path, "entries =", len(app2._change_service.document.entries))
        print("[B] after Load: list_saved_flows(active project) =", list_saved_flows(app2.active_project_dir()))
        # C: save-as
        save_project(app2, app2.workarea, "Q"); await settle(app2, pilot)
        q = app2.workarea / "Q"
        print("[C] Save-as P -> Q status:", app2._probe_status[-2:])
        print("[C] Q tree:", [l.split('  ')[0] for l in tree(q)])
        print("[C] active project now:", app2.current_project, "| flows visible:", list_saved_flows(app2.active_project_dir()))


def write_doc_common(path, entries):
    from s19_app.tui.changes.model import ChangeDocument, ChangeEntry
    from s19_app.tui.changes.io import serialize_change_document
    d = ChangeDocument(format="s19app-changeset", version="2.0", kind="change", encoding="utf-8", value_mode="text",
                       entries=[ChangeEntry(entry_type="bytes", address=a, encoded_bytes=tuple(b)) for a, b in entries])
    path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(serialize_change_document(d)); return path


asyncio.run(main())
