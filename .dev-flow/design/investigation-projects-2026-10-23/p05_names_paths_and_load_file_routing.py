"""P05: project names (spaces, `..`, unicode, collisions after sanitizing),
a parent folder outside the work area, a corrupt image's load honesty, and
what happens when a project path is typed into Load file."""
from common import *


async def main():
    base = new_base()
    app = new_app(base)
    async with app.run_test(size=(160, 50)) as pilot:
        await settle(app, pilot)
        await load_path(app, pilot, C1 / "firmware.s19")
        wa = app.workarea
        for name in ["my proj", "../evil", "..", "Δelta-ñ_1", "a b", "ab", "CON", "x" * 300]:
            app._probe_status.clear()
            exc = save_project(app, wa, name)
            await settle(app, pilot)
            print(f"name {name[:20]!r:24} -> project={app.current_project!r:.30} status={[s[:90] for s in app._probe_status[-2:]]}")
        print("workarea dirs:", sorted(p.name[:20] for p in wa.iterdir() if p.is_dir()))
        print("list_projects():", [n[:20] for n in app.list_projects()])
        # 'a b' and 'ab' collapse to the same folder: the second save merges into the first
        print("ab/ files:", [l.split('  ')[0] for l in tree(wa / "ab")])

        # parent outside the work area
        outside = base / "elsewhere"; outside.mkdir()
        app._probe_status.clear()
        save_project(app, outside, "Ext"); await settle(app, pilot)
        print("parent outside workarea -> status:", app._probe_status[-1:], "| left behind:", [p.relative_to(base).as_posix() for p in outside.rglob("*")])
        print("   current_project after refused save:", app.current_project)
        # parent under ANOTHER .s19tool/workarea: accepted, but never listed by Load project
        other = base / "other" / ".s19tool" / "workarea"; other.mkdir(parents=True)
        app._probe_status.clear()
        save_project(app, other, "Other"); await settle(app, pilot)
        print("parent = another workarea -> status:", [s[:80] for s in app._probe_status[-2:]])
        print("   files there:", [l.split('  ')[0] for l in tree(other / "Other")], "| listed by Load project?", "Other" in app.list_projects())

        # Load file with project paths
        proj = wa / "ab"
        for typed in [proj, proj / "project.json", proj / "firmware.s19"]:
            app._probe_status.clear()
            temp_before = sorted(p.name for p in (wa / "temp").iterdir())
            await load_path(app, pilot, typed)
            temp_after = sorted(p.name for p in (wa / "temp").iterdir())
            print(f"Load file '{typed.relative_to(wa).as_posix()}' -> status={app._probe_status[:3]} project={app.current_project} "
                  f"current_file={app.current_file.path.relative_to(wa).as_posix()} temp {temp_before}->{temp_after}")

    # corrupt image in a project: does anything say so?
    base = new_base(); app = new_app(base)
    async with app.run_test(size=(160, 50)) as pilot:
        await settle(app, pilot)
        p = app.workarea / "Bad"; p.mkdir(); (p / "firmware.s19").write_text("S3FFgarbage\n")
        app._handle_load_project("Bad"); await settle(app, pilot)
        f = app.current_file
        from textual.widgets import Label
        try:
            file_status = str(app.query_one("#status_text", Label).render())
        except Exception as e:  # noqa: BLE001
            file_status = f"<{e}>"
        print("corrupt project image -> status:", app._probe_status[-1:], "| mem bytes:", len(f.mem_map), "| errors:", [str(e)[:60] for e in f.errors][:2], "| file-status line:", file_status[:100])


asyncio.run(main())
