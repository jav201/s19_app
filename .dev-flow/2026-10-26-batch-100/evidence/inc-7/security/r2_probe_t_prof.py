"""R2-T profile: where the T2 (valid-heavy) MAC-sync writer spends its 6-7 s,
plus a T0 baseline (the seeded manifest, no chain) for the Load dialog's
click -> panel overhead."""
import asyncio, cProfile, io, pstats, sys, time
from common import *
import r2_probe_t as RT

which = sys.argv[1:] or ["T0", "PROF"]
if "T0" in which:
    async def base_load():
        tmp = fresh("T0"); base = tmp / "app"
        RT.projects.seed_project_with_every_key(RT.T._workarea(base))
        app = RT.S19TuiApp(base_dir=base)
        async with app.run_test(size=(118, 54)) as pilot:
            await pilot.pause()
            t0 = time.perf_counter()
            await RT.PC._open_panel_through_the_dialog(pilot, app)
            await RT.PC._wait_for(pilot, lambda: len(app.screen.query("#result_summary")) > 0
                                  and app.screen.query_one("#result_summary").size.height > 0, "panel", attempts=8000)
            return round(time.perf_counter() - t0, 3)
    print("[T0 baseline, seeded manifest] click->panel s:", asyncio.run(base_load()))
if "PROF" in which:
    prof = cProfile.Profile()
    prof.enable()
    r = asyncio.run(RT.run("T2", "mac-sync"))
    prof.disable()
    print("[T2 mac-sync under the profiler]", r)
    s = io.StringIO()
    pstats.Stats(prof, stream=s).sort_stats("cumulative").print_stats(r"s19_app|ntpath|pathlib|nt\.|lstat|resolve|realpath", 40)
    print("\n".join(line[:170] for line in s.getvalue().splitlines()[:80]))
