"""R2-T3: a legitimate project whose existing entries need more than the
2 000-call ceiling (batch: 1 000 real files in folder chain A; assignments:
1 000 real files in a second chain B). Load reports the unchecked entries;
what does Save project then write, and does it keep the previous manifest?"""
import asyncio, json, sys, time
from common import *
import r2_probe_t as RT
from s19_app.tui.services.variant_execution_service import read_project_manifest, manifest_keep_reason


async def main():
    tmp = fresh("T3"); base = tmp / "app"
    P = RT.projects.seed_project_with_every_key(RT.T._workarea(base))
    m = RT.projects.read_manifest(P)
    lists = {}
    for tag in ("A", "B"):
        chain = [f"{tag}{i}" for i in range(20)]
        folder = P.joinpath(*chain); folder.mkdir(parents=True)
        for i in range(1000):
            (folder / f"c{i}.json").write_text('{"entries": []}')
        lists[tag] = ["/".join(chain) + f"/c{i}.json" for i in range(1000)]
    m["batch"] = lists["A"]
    m["assignments"] = {"firmware": lists["B"]}
    (P / "project.json").write_text(json.dumps(m, separators=(",", ":")), encoding="utf-8")
    before = read_project_manifest(P)
    print("[T3 read] batch:", len(before.batch), "| assignments:", {k: len(v) for k, v in before.assignments.items()},
          "| fold:", [i.message for i in before.issues if "more manifest" in i.message], "| keep reason:", manifest_keep_reason(before))
    statuses = []
    app = RT.S19TuiApp(base_dir=base)
    real = app.set_status
    app.set_status = lambda s, *a, **k: (statuses.append(str(s)), real(s, *a, **k))[1]
    async with app.run_test(size=(118, 54)) as pilot:
        await pilot.pause()
        await RT.T._open_seeded_project(pilot, app)
        statuses.clear()
        app._handle_save_dialog(RT.SaveProjectPayload(parent_folder=str(app.workarea), project_name="P"))
        for _ in range(4000):
            if any(RT.OUTCOME.search(s) for s in statuses): break
            await pilot.pause()
    after = json.loads((P / "project.json").read_text(encoding="utf-8"))
    print("[T3 after Save project] batch:", len(after.get("batch", [])), "| assignments:",
          {k: len(v) for k, v in after.get("assignments", {}).items()},
          "| previous-* copies:", sorted(x.name for x in P.iterdir() if ".previous-" in x.name))
    print("   statuses:", [s[:120] for s in statuses])

asyncio.run(main())
