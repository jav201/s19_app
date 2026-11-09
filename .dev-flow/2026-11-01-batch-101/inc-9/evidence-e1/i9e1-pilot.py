"""batch-101 Inc 9 E1 pilot: reproduce F-45, F-46 and D15-18 on the base tree.

Run from the worktree root with PYTHONPATH set to it; prints the package path
first. Every path printed is relative to its own temporary base.
"""
import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.getcwd())

import s19_app  # noqa: E402

print("s19_app.__file__ =", Path(s19_app.__file__).resolve().relative_to(Path.cwd().resolve()))

from s19_app.tui.app import S19TuiApp  # noqa: E402
from s19_app.tui.services import flow_persistence_service as fps  # noqa: E402
from s19_app.tui.services.flow_execution_service import ChainSpec, run_chain_set  # noqa: E402
from s19_app.tui.services.flow_model import (  # noqa: E402
    Flow,
    FlowContext,
    ReportBlock,
    SourceBlock,
    WriteOutBlock,
)
from s19_app.tui.workspace import WorkareaContainmentError, _guarded_destination  # noqa: E402
from tests.b97_fixtures import (  # noqa: E402
    flash_evidence,
    fx_project,
    flow_project,
    import_lanes,
    load_flow,
    open_flow_builder,
    run_lanes,
)
from tests.b97_probes import settle, settled  # noqa: E402


def rel(path: Path, base: Path) -> str:
    try:
        return str(Path(path).relative_to(base))
    except ValueError:
        return "<outside base>"


# --------------------------------------------------------------------- F-45
def pilot_f45(base: Path) -> None:
    print("\n== F-45: a confirm re-run in a parallel set")

    async def drive():
        app = S19TuiApp(base_dir=base)
        async with app.run_test(size=(118, 54)) as pilot:
            await settle(pilot)
            project = await fx_project(app)
            panel = await import_lanes(app, pilot, "patch_chain", "flash_chain", "patch_chain_b")
            panel.query_one("#fx_mode").set_mode("parallel")
            await settle(pilot, 2)
            reports_dir = project / "reports"
            before = set(reports_dir.glob("*-chain-set-report.md")) if reports_dir.is_dir() else set()
            await run_lanes(app, pilot, panel)
            await settle(pilot, 4)
            after_run = set(reports_dir.glob("*-chain-set-report.md"))
            print("lanes:", [lane.name for lane in panel._lanes])
            print("run mode on record:", panel.last_run_record.mode)
            print("lane statuses after Run:", [lane.last_status for lane in panel._lanes])
            print("chain-set reports written by Run:", len(after_run - before))
            flash_evidence(project)
            await settled(pilot, lambda: panel.query_one("#fx_confirm_1").display, "confirm shown")
            panel.query_one("#fx_confirm_1").press()
            await settled(
                pilot,
                lambda: "re-run" in panel.run_log_plain() and not panel.query_one("#fx_run").disabled,
                "confirm re-run painted",
                attempts=200,
            )
            await settle(pilot, 4)
            after_confirm = set(reports_dir.glob("*-chain-set-report.md"))
            new = sorted(after_confirm - after_run)
            print("lane statuses after confirm:", [lane.last_status for lane in panel._lanes])
            print("chain-set reports written by the confirm re-run:", len(new))
            for path in sorted(after_confirm):
                text = path.read_text(encoding="utf-8").splitlines()
                head = [line for line in text if line.startswith("- **Mode:**") or line.startswith("- **Chains:**")]
                ledger = [line for line in text if line.startswith("| ") and "Chain" not in line and "---" not in line]
                print(" ", rel(path, project), head, "ledger rows:", len(ledger))

    asyncio.run(drive())


# --------------------------------------------------------------------- F-46
def pilot_f46(base: Path) -> None:
    print("\n== F-46: Save after Clear")

    async def drive():
        app = S19TuiApp(base_dir=base)
        async with app.run_test(size=(118, 54)) as pilot:
            await settle(pilot)
            project = await flow_project(app)
            panel = await open_flow_builder(app, pilot)
            await load_flow(app, pilot, "patch_chain")
            print("ribbon after load:", panel._name_strip_text().plain.split("  ")[0])
            panel.query_one("#flow_clear").press()
            await settle(pilot, 2)
            print("ribbon after Clear:", panel._name_strip_text().plain.split("  ")[0])
            panel.query_one("#flow_palette_source").press()
            await settle(pilot, 2)
            panel.query_one("#flow_ref").value = "prg.s19"
            panel.query_one("#flow_add").press()
            await settle(pilot, 2)
            print("blocks after Add:", [block.kind for block in panel._blocks])
            panel.query_one("#flow_save").press()
            await settled(pilot, lambda: bool(app.screen.query("#flow_save_name")), "save dialog")
            box = app.screen.query_one("#flow_save_name")
            print("Save dialog prefill:", repr(box.value))
            box.value = "tune_b"
            await settle(pilot, 2)
            app.screen.query_one("#flow_save_ok").press()
            await settled(pilot, lambda: (project / "flows" / "tune_b.json").is_file(), "tune_b saved")
            payload = json.loads((project / "flows" / "tune_b.json").read_text(encoding="utf-8"))
            print("flows/tune_b.json name field:", repr(payload["name"]))
            print("ribbon after Save:", panel._name_strip_text().plain.split("  ")[0])

    asyncio.run(drive())

    print("-- consequence in Flow Execution: a lane of a file whose name is stale")
    project = base / "svc" / ".s19tool" / "workarea" / "p"
    project.mkdir(parents=True)
    (project / "prg.s19").write_bytes((Path.cwd() / "examples" / "case_00_public" / "prg.s19").read_bytes())
    fps.save_flow_json(Flow(name="tune_a", blocks=[SourceBlock("prg.s19"), ReportBlock()]), "tune_b", project)
    loaded, findings = fps.load_flow_json(project / "flows" / "tune_b.json", project)
    print("load findings:", findings, "loaded.name:", repr(loaded.name))
    run_chain_set([ChainSpec(name="tune_b", template="tune_b", flow=loaded, bindings={})],
                  FlowContext(project_dir=project), set_name="s")
    for path in sorted((project / "reports").glob("*-report.md")):
        if "chain-set" in path.name:
            continue
        print("flow report header:", path.read_text(encoding="utf-8").splitlines()[0])
    print("-- a clash: second save of the same typed name")
    second = fps.save_flow_json(Flow(name="tune_a", blocks=[SourceBlock("prg.s19")]), "tune_b", project)
    print("second save:", second.name, "name field:", repr(json.loads(second.read_text(encoding="utf-8"))["name"]))
    long_name = "L" * 70
    third = fps.save_flow_json(Flow(name=long_name, blocks=[SourceBlock("prg.s19")]), "x", project)
    _flow, long_findings = fps.load_flow_json(third, project)
    print("a 70-character embedded name loads with:", [f.code for f in long_findings])


# --------------------------------------------------------------------- D15-18
def pilot_d1518(base: Path) -> None:
    print("\n== D15-18: a linked flows/ or flowsets/ home")
    project = base / "d" / ".s19tool" / "workarea" / "p"
    project.mkdir(parents=True)
    outside = base / "outside"
    (outside / "flows").mkdir(parents=True)
    (outside / "flowsets").mkdir(parents=True)
    os.symlink(outside / "flows", project / "flows", target_is_directory=True)
    os.symlink(outside / "flowsets", project / "flowsets", target_is_directory=True)
    saved = fps.save_flow_json(Flow(name="x", blocks=[SourceBlock("prg.s19")]), "x", project)
    print("save_flow_json returned:", rel(saved, project) if saved else None,
          "| file outside the work area:", (outside / "flows" / "x.json").is_file())
    chain_set = fps.ChainSet(name="s", chains=(fps.ChainSetEntry(chain="x", template="x", inputs=((0, "prg.s19"),), outputs=()),))
    saved_set = fps.save_chain_set(chain_set, "s", project)
    print("save_chain_set returned:", rel(saved_set, project) if saved_set else None,
          "| file outside the work area:", (outside / "flowsets" / "s.json").is_file())
    for home in ("flows", "flowsets"):
        try:
            _guarded_destination(project / home)
            print(f"_guarded_destination({home}): passes")
        except WorkareaContainmentError as exc:
            print(f"_guarded_destination({home}): refuses -", str(exc).split(":")[0])
    picked = base / "pick.json"
    picked.write_text(json.dumps(fps.flow_to_dict(Flow(name="y", blocks=[SourceBlock("prg.s19")]))), encoding="utf-8")
    try:
        fps.import_flow_file(picked, project)
        print("import_flow_file through the linked flows/: accepted")
    except WorkareaContainmentError as exc:
        print("import_flow_file through the linked flows/: refused -", str(exc).split(":")[0])

    print("-- a plain flows/ holding a dangling link named like the saved file")
    project2 = base / "d2" / ".s19tool" / "workarea" / "p"
    (project2 / "flows").mkdir(parents=True)
    (outside / "dangling").mkdir()
    os.symlink(outside / "dangling" / "z.json", project2 / "flows" / "z.json")
    saved2 = fps.save_flow_json(Flow(name="z", blocks=[SourceBlock("prg.s19")]), "z", project2)
    print("save_flow_json returned:", rel(saved2, project2) if saved2 else None,
          "| file created outside through the link:", (outside / "dangling" / "z.json").is_file())
    try:
        _guarded_destination(project2 / "flows")
        print("_guarded_destination(flows) on the plain home: passes")
    except WorkareaContainmentError as exc:
        print("_guarded_destination(flows) on the plain home: refuses -", str(exc).split(":")[0])


if __name__ == "__main__":
    for name, fn in (("f45", pilot_f45), ("f46", pilot_f46), ("d1518", pilot_d1518)):
        with tempfile.TemporaryDirectory(prefix=f"i9e1-{name}-", dir="/tmp/i9e1/runs") as tmp:
            fn(Path(tmp))
