"""E: the real Load dialog route with a capped manifest whose entries need
filesystem calls (no '../', nothing over a cap), then a variant append.
Measures the main-thread time of _handle_load_project, the panel paint, the
panel row count, and scans painted rows for internal codes / exception names."""
import asyncio, json, re, shutil, sys, time
from common import *
sys.path.insert(0, str(WT))
from tests.support import b100_projects as projects
import tests.test_b100_project_check as PC
from s19_app.tui.app import S19TuiApp

seg = "sub/" * 36
payload = {"schema_version": 1, "active_variant": "firmware",
    "batch": [f"{seg}b{i}.json" for i in range(1000)],
    "assignments": {"firmware": [f"{seg}a{i}.json" for i in range(1000)]},
    "gathered": {"patches": [f"{seg}g{i}.json" for i in range(1000)]},
    "files": {f"{seg}f{i}.s19": {"size": 1, "sha256": "0" * 64} for i in range(1000)},
    "derived_from": {f"{seg}d{i}.s19": {"base": "firmware.s19", "sha256": "0" * 64, "differ": 1} for i in range(1000)}}
tmp = fresh("E"); base = tmp / "app"
pdir = projects.copy_sources(wa(base) / "P", projects.CASE01_DIR, "firmware.s19")
text = json.dumps(payload, separators=(",", ":"))
(pdir / "project.json").write_text(text, encoding="utf-8")
print("manifest bytes:", len(text))
src = projects.copy_sources(tmp / "src", projects.CASE02_DIR, "firmware.s19") / "firmware.s19"
CODE = re.compile(r"MANIFEST-[A-Z-]+"); EXC = re.compile(r"\b[A-Z][A-Za-z]*(Error|Exception)\b")

async def drive():
    app = S19TuiApp(base_dir=base)
    timing = []
    real_load = app._handle_load_project
    def timed(name):
        t = time.perf_counter(); real_load(name); timing.append(time.perf_counter() - t)
    app._handle_load_project = timed
    statuses = []
    real = app.set_status
    app.set_status = lambda s, *a, **k: (statuses.append(str(s)), real(s, *a, **k))[1]
    async with app.run_test(size=(118, 54)) as pilot:
        await pilot.pause()
        t0 = time.perf_counter()
        await PC._open_panel_through_the_dialog(pilot, app)
        await PC._wait_for(pilot, lambda: len(app.screen.query("#result_summary")) > 0 and app.screen.query_one("#result_summary").size.height > 0, "panel", attempts=8000)
        painted = time.perf_counter() - t0
        rows = app.screen.query("#result_body .result-problem")
        texts = [" ".join(projects.painted_lines(r)) for r in rows]
        print(f"[E load] _handle_load_project={timing[0]:.2f}s  click->panel painted={painted:.2f}s  rows={len(texts)}")
        print("   rows with an internal code:", sum(bool(CODE.search(t)) for t in texts), "| with an exception name:", sum(bool(EXC.search(t)) for t in texts))
        print("   first row:", texts[0][:110] if texts else None, "\n   last row:", texts[-1][:110] if texts else None)
        await pilot.press("escape")
        for _ in range(10): await pilot.pause()
        statuses.clear()
        t1 = time.perf_counter()
        app.load_from_path(src)
        for _ in range(4000):
            if any(s.startswith("Added variant") for s in statuses): break
            await pilot.pause()
        print(f"[E append] load_from_path -> 'Added variant' = {time.perf_counter() - t1:.2f}s; statuses:", [s[:90] for s in statuses if 'rewritten' in s or 'verified' in s])
asyncio.run(drive())
