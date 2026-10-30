"""R2-T: SEC6-5 time bound under the cp1 caps, worst cases the new rules
still allow (<= 32 components, so the 32-component text rule does not
decide them; the walk has to run).
T1 ceiling: a real 31-folder chain; 3 x 1 000 entries with distinct missing
   leaves under it -> 31 + 1 969 lstat calls, then unchecked.
T2 valid-heavy: the same chain holding 1 000 real files; batch,
   assignments and gathered each list all 1 000 (no finding, so every
   in-project writer rewrites and verifies).
For each: the Load dialog (handler time, click -> panel), then each writer
(variant append, MAC sync, A2L sync, save-back, Save project) from trigger to
its manifest outcome line, with every read_project_manifest call timed."""
import asyncio, json, re, sys, time
from pathlib import Path
from common import *
sys.path.insert(0, str(WT))
import s19_app.tui.app as A
from s19_app.tui.app import S19TuiApp, SaveProjectPayload
import tests.test_b100_active_variant as T
import tests.test_b100_project_check as PC
from tests.support import b100_projects as projects

CHAIN = [chr(ord("a") + i % 26) + ("" if i < 26 else "2") for i in range(31)]
OUTCOME = re.compile(r"not rewritten|manifest verified|Manifest write failed|Saved project|NOT saved")
reads = []
real_read = A.read_project_manifest


def timed_read(*a, **k):
    t = time.perf_counter()
    try:
        return real_read(*a, **k)
    finally:
        reads.append(time.perf_counter() - t)
A.read_project_manifest = timed_read


def build(tag, kind):
    tmp = fresh(tag); base = tmp / "app"
    P = projects.seed_project_with_every_key(T._workarea(base))
    chain = P.joinpath(*CHAIN); chain.mkdir(parents=True)
    rel = "/".join(CHAIN)
    m = projects.read_manifest(P)
    if kind == "T1":
        m["batch"] = [f"{rel}/f{i}.json" for i in range(1000)]
        m["assignments"] = {"firmware": [f"{rel}/g{i}.json" for i in range(1000)]}
        m["gathered"] = {"patches": [f"{rel}/h{i}.json" for i in range(1000)]}
    else:
        for i in range(1000):
            (chain / f"f{i}.json").write_text('{"entries": []}')
        names = [f"{rel}/f{i}.json" for i in range(1000)]
        m["batch"] = list(names)
        m["assignments"] = {"firmware": list(names)}
        m["gathered"] = {"patches": list(names)}
    text = json.dumps(m, separators=(",", ":"))
    (P / "project.json").write_text(text, encoding="utf-8")
    longest = max(len(str(P / x)) for x in m["batch"])
    return tmp, base, P, len(text), longest


async def run(kind, writer):
    tmp, base, P, size, longest = build(f"{kind}_{writer}", kind)
    statuses = []
    app = S19TuiApp(base_dir=base)
    real = app.set_status
    app.set_status = lambda s, *a, **k: (statuses.append(str(s)), real(s, *a, **k))[1]
    out = {"bytes": size, "longest path": longest}
    async with app.run_test(size=(118, 54)) as pilot:
        await pilot.pause()
        if writer == "load":
            timing = []
            real_load = app._handle_load_project

            def tl(name):
                t = time.perf_counter(); real_load(name); timing.append(time.perf_counter() - t)
            app._handle_load_project = tl
            reads.clear()
            t0 = time.perf_counter()
            await PC._open_panel_through_the_dialog(pilot, app)
            await PC._wait_for(pilot, lambda: len(app.screen.query("#result_summary")) > 0
                               and app.screen.query_one("#result_summary").size.height > 0, "panel", attempts=8000)
            out["handler s"] = round(timing[0], 3)
            out["click->panel s"] = round(time.perf_counter() - t0, 3)
            out["rows"] = len(app.screen.query("#result_body .result-problem"))
            out["reads s"] = [round(r, 3) for r in reads]
            return out
        await T._open_seeded_project(pilot, app)
        statuses.clear(); reads.clear()
        t0 = time.perf_counter()
        if writer == "save-back":
            T._apply_patch(app)
            app.on_patch_editor_panel_save_back_decision(A.PatchEditorPanel.SaveBackDecision("firmware.s19", 32))
        elif writer == "variant-append":
            app.load_from_path(projects.copy_sources(tmp / "src", projects.CASE02_DIR, "firmware.s19") / "firmware.s19")
        elif writer == "mac-sync":
            app.load_from_path(projects.copy_sources(tmp / "src", projects.CASE01_DIR, "firmware.mac") / "firmware.mac")
        elif writer == "a2l-sync":
            app.load_a2l_from_path(projects.copy_sources(tmp / "src", projects.CASE01_DIR, "firmware.a2l") / "firmware.a2l")
        elif writer == "save-project":
            app._handle_save_dialog(SaveProjectPayload(parent_folder=str(app.workarea), project_name="P"))
        for _ in range(8000):
            if any(OUTCOME.search(s) for s in statuses):
                break
            await pilot.pause()
        out["trigger->outcome s"] = round(time.perf_counter() - t0, 3)
        out["reads s"] = [round(r, 3) for r in reads]
        out["outcome"] = next((s[:110] for s in statuses if OUTCOME.search(s)), None)
        return out

if __name__ == "__main__":
    for kind in (sys.argv[1:] or ["T1", "T2"]):
        for writer in ("load", "variant-append", "mac-sync", "a2l-sync", "save-back", "save-project"):
            try:
                print(f"[{kind} {writer:14}]", asyncio.run(run(kind, writer)))
            except Exception as e:
                print(f"[{kind} {writer:14}] DRIVER ERROR {type(e).__name__}: {str(e)[:150]}")
