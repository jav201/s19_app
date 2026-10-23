"""T5 threads: project save -> load -> default re-save: what project.json carries (Code-Wire data audit).

The re-save payload is what SaveProjectScreen yields when the operator changes nothing: its
SelectionLists start unselected (screens.py:572-590), so `batch=()` and `assignments={}`.
"""
import json
import shutil

from cwh import C1, new_base, out, run_app, load_path, settle


def test_t5a_save_load_resave_case01():
    base = new_base()
    src = base / "src"
    src.mkdir()
    for f in ("firmware.s19", "firmware.mac", "firmware.a2l"):
        shutil.copyfile(C1 / f, src / f)
    state = {}

    async def first(app, pilot):
        from s19_app.tui.screens import SaveProjectPayload
        from s19_app.tui.services.report_addendum import DeclaredRegion
        await load_path(app, pilot, src / "firmware.s19")
        await load_path(app, pilot, src / "firmware.mac")
        await load_path(app, pilot, src / "firmware.a2l")
        app._declared_regions = (DeclaredRegion(name="cal", start=0x80000000, end=0x80000010),)
        app._handle_save_dialog(SaveProjectPayload(parent_folder=str(app.workarea), project_name="P",
                                                   batch=(), assignments={}))
        await settle(app, pilot)
        proj = app.workarea / "P"
        (proj / "patch.json").write_text((src / "firmware.s19").read_text()[:0] + json.dumps(
            {"format": "s19app-changeset", "version": "2.0", "kind": "change", "entries": []}))
        # second save: the operator selects patch.json as batch + per-variant assignment
        app._handle_save_dialog(SaveProjectPayload(parent_folder=str(app.workarea), project_name="P",
                                                   batch=("patch.json",), assignments={"firmware": ("patch.json",)}))
        await settle(app, pilot)
        m = json.loads((proj / "project.json").read_text())
        out("T5a-save", files=sorted(p.name for p in proj.iterdir()), batch=m.get("batch"),
            assignments=m.get("assignments"), regions=m.get("declared_regions"), status=app._probe_status[-1])
        state["proj"] = proj

    run_app(first, base)

    async def second(app, pilot):
        from s19_app.tui.screens import SaveProjectPayload
        app._handle_load_project("P")
        await settle(app, pilot)
        f = app.current_file
        out("T5a-load", file=f.path.name, mac=getattr(f.mac_path, "name", None), regions=app._declared_regions,
            status=app._probe_status[-1])
        app._handle_save_dialog(SaveProjectPayload(parent_folder=str(app.workarea), project_name="P",
                                                   batch=(), assignments={}))
        await settle(app, pilot)
        m = json.loads((state["proj"] / "project.json").read_text())
        out("T5a-resave", batch=m.get("batch"), assignments=m.get("assignments"), regions=m.get("declared_regions"),
            status=app._probe_status[-2:], notes=app._probe_notes[-2:])

    run_app(second, base)


def test_t5b_resave_without_a2l_drops_batch():
    """T5b: S19-only project: save with batch + assignment, load, default re-save."""
    base = new_base()
    src = base / "src"
    src.mkdir()
    shutil.copyfile(C1 / "firmware.s19", src / "firmware.s19")
    state = {}

    async def first(app, pilot):
        from s19_app.tui.screens import SaveProjectPayload
        await load_path(app, pilot, src / "firmware.s19")
        app._handle_save_dialog(SaveProjectPayload(parent_folder=str(app.workarea), project_name="Q",
                                                   batch=(), assignments={}))
        await settle(app, pilot)
        proj = app.workarea / "Q"
        (proj / "patch.json").write_text(json.dumps(
            {"format": "s19app-changeset", "version": "2.0", "kind": "change", "entries": []}))
        app._handle_save_dialog(SaveProjectPayload(parent_folder=str(app.workarea), project_name="Q",
                                                   batch=("patch.json",), assignments={"firmware": ("patch.json",)}))
        await settle(app, pilot)
        m = json.loads((proj / "project.json").read_text())
        out("T5b-save", batch=m.get("batch"), assignments=m.get("assignments"), status=app._probe_status[-1])
        state["proj"] = proj

    run_app(first, base)

    async def second(app, pilot):
        from s19_app.tui.screens import SaveProjectPayload
        app._handle_load_project("Q")
        await settle(app, pilot)
        app._handle_save_dialog(SaveProjectPayload(parent_folder=str(app.workarea), project_name="Q",
                                                   batch=(), assignments={}))
        await settle(app, pilot)
        m = json.loads((state["proj"] / "project.json").read_text())
        out("T5b-resave", batch=m.get("batch"), assignments=m.get("assignments"),
            status=app._probe_status[-1], notes=app._probe_notes[-2:])

    run_app(second, base)
