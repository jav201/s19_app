"""Inc 6 E1 reproduction pilot (batch-101). Headless; run from the worktree root.

  F05   save-back offer with no project / with a project (D14-14)
  D1030 before/after control and save-back prompt after a dropdown pick,
        a guarded load and undo (D10-30)
  F06   with a project: Patch Editor Save, its dropdown, Check Editor Write,
        its Spec list, the A2B Diff check list (D10-25, D9-15, D14-17)
  F40   Checks tab and Checks screen after another load, an image load and a
        project load (D9-10); a 0-entry run's subtitle
  F47   start + project load + Flow Builder key sweep: which keys reach the
        before/after action
Prints one transcript; writes only under the run folder (argv[1]).
"""
from __future__ import annotations

import asyncio
import shutil
import sys
from pathlib import Path

ROOT = Path.cwd()
sys.path.insert(0, str(ROOT))
import s19_app  # noqa: E402

print("s19_app.__file__ =", s19_app.__file__)

from textual.widgets import Select  # noqa: E402

from s19_app.tui.app import S19TuiApp  # noqa: E402
from s19_app.tui.screens_directionb import PatchEditorPanel  # noqa: E402
from tests.support import b100_projects as projects  # noqa: E402
from tests.support.b100_projects import StatusLog  # noqa: E402
from tests.support.timing import wait_until  # noqa: E402

RUN = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/tmp/i6e1/run")
REFUSED = "Before/after report refused"


def s1(addr: int, data: bytes) -> str:
    body = bytes([len(data) + 3, addr >> 8, addr & 0xFF]) + data
    return "S1" + body.hex().upper() + f"{(~sum(body)) & 0xFF:02X}"


def image(path: Path, fill: int = 0) -> Path:
    data = bytes((fill + i) & 0xFF for i in range(16))
    path.write_text("\n".join(["S0030000FC", s1(0x8000, data), "S9030000FC"]) + "\n", encoding="ascii")
    return path


def doc(path: Path, entries, kind="change") -> Path:
    path.write_bytes(projects.change_document_bytes(entries, kind=kind))
    return path


CHG = [projects.address_entry(0x8003, b"\xAA")]
CHG2 = [projects.address_entry(0x8005, b"\xBB")]
CHK = [projects.address_entry(0x8000, b"\x00"), projects.address_entry(0x8001, b"\xFF")]


async def settle(pilot, n=8):
    for _ in range(n):
        await pilot.pause()


def panel(app) -> PatchEditorPanel:
    return app.query_one("#patch_editor_panel", PatchEditorPanel)


def visible(app, wid: str) -> bool:
    return not panel(app).query_one(f"#{wid}").has_class("hidden")


def checks_tab(app) -> dict:
    p = panel(app)
    return {
        "status": str(p.query_one("#patch_checks_status").render()),
        "rows": len(p.query_one("#patch_checks_results").children),
        "subtitle": p.query_one("#patch_win_checks").border_subtitle,
        "strip": str(p.query_one("#patch_checks_strip").render()).replace("\n", " / "),
    }


def checks_screen(app) -> str:
    app.update_checks_view()
    return " | ".join(
        str(w.render()).replace("\n", " ")
        for w in app.query_one("#checks_grouped").query("Static")
    )[:160]


async def load_path(app, pilot, path: Path):
    p = panel(app)
    p.query_one("#patch_doc_path_input").value = str(path)
    p.request_action("load_doc")
    await wait_until(pilot, lambda: app._change_service.document.source_path is not None
                     and app._change_service.document.source_path.name == path.name, f"load {path.name}")
    await settle(pilot)


async def apply_and_save(app, pilot):
    panel(app).request_action("apply_doc")
    await wait_until(pilot, lambda: visible(app, "patch_saveback_row"), "save prompt")
    panel(app).query_one("#patch_saveback_confirm_button").press()
    await wait_until(pilot, lambda: not visible(app, "patch_saveback_row"), "save-back")
    await app.workers.wait_for_complete()
    await settle(pilot)


async def run_checks(app, pilot):
    panel(app).request_action("run_checks")
    await wait_until(pilot, lambda: app._change_service.last_check_result is not None, "check run")
    await settle(pilot)


def notices(app) -> list:
    seen: list = []
    orig = app.notify

    def rec(message, *a, **k):
        seen.append(str(message))
        return orig(message, *a, **k)

    app.notify = rec
    return seen


async def start(app, pilot, base: Path):
    await settle(pilot)
    await projects.load_image(pilot, app, image(base / "img.s19"))
    app.action_show_screen("patch")
    await settle(pilot)


def run(name: str, scenario):
    base = RUN / name
    if base.exists():
        shutil.rmtree(base)
    base.mkdir(parents=True)
    projects.run_app(base, lambda app, pilot, log: scenario(app, pilot, log, base))


async def f05(app, pilot, log, base):
    seen = notices(app)
    await start(app, pilot, base)
    await load_path(app, pilot, doc(base / "c.json", CHG))
    await apply_and_save(app, pilot)
    print("F05 no-project offers:", [m for m in seen if "Before/after report ready" in m])
    print("F05 no-project control visible:", visible(app, "patch_before_after_row"))
    mark = len(log.messages)
    app.action_before_after_report()
    await app.workers.wait_for_complete()
    await settle(pilot)
    print("F05 no-project b:", [m for m in log.since(mark) if "Before/after" in m])


async def f05p(app, pilot, log, base):
    seen = notices(app)
    (app.workarea / "proj").mkdir(parents=True, exist_ok=True)
    app.current_project = "proj"
    await start(app, pilot, base)
    await load_path(app, pilot, doc(base / "c.json", CHG))
    await apply_and_save(app, pilot)
    print("F05 project offers:", [m for m in seen if "Before/after report ready" in m])


async def d1030(app, pilot, log, base):
    await start(app, pilot, base)
    patches = app._patches_dir()
    patches.mkdir(parents=True, exist_ok=True)
    doc(patches / "a.json", CHG)
    doc(patches / "b.json", CHG2)
    app._prefill_patch_change_files()
    await load_path(app, pilot, patches / "a.json")
    await apply_and_save(app, pilot)
    print("D1030 control after save-back:", visible(app, "patch_before_after_row"))
    panel(app).query_one("#patch_doc_file_select", Select).value = "b.json"
    await wait_until(pilot, lambda: app._change_service.document.source_path.name == "b.json", "pick b")
    await settle(pilot)
    print("D1030 control after dropdown pick:", visible(app, "patch_before_after_row"))
    panel(app).request_action("apply_doc")
    await wait_until(pilot, lambda: visible(app, "patch_saveback_row"), "prompt 2")
    panel(app).query_one("#patch_doc_file_select", Select).value = "a.json"
    await wait_until(pilot, lambda: app._change_service.document.source_path.name == "a.json", "pick a")
    await settle(pilot)
    print("D1030 save-back prompt after dropdown pick:", visible(app, "patch_saveback_row"))
    # draft + apply + undo
    p = panel(app)
    p.query_one("#patch_doc_path_input").value = ""
    app._change_service.load_text(projects.change_document_bytes(CHG2).decode())
    p.request_action("apply_doc")
    await wait_until(pilot, lambda: visible(app, "patch_saveback_row"), "prompt 3")
    app.action_patch_undo()
    await settle(pilot)
    print("D1030 save-back prompt after undo:", visible(app, "patch_saveback_row"))


async def f06(app, pilot, log, base):
    (app.workarea / "proj").mkdir(parents=True, exist_ok=True)
    app.current_project = "proj"
    await start(app, pilot, base)
    p = panel(app)
    p.query_one("#patch_entry_address_input").value = "0x8002"
    p.query_one("#patch_entry_bytes_input").value = "11"
    p.request_action("add_entry")
    await settle(pilot)
    p.request_action("save_doc")
    await settle(pilot)
    saved = sorted(str(x.relative_to(app.workarea)) for x in app.workarea.rglob("*.json"))
    print("F06 files after Patch Save:", saved)
    opts = [str(o[1]) for o in p.query_one("#patch_doc_file_select", Select)._options if o[1] is not Select.BLANK]
    print("F06 Patch dropdown values:", opts)
    app.action_show_screen("check_editor")
    await settle(pilot)
    ce = app.query_one("#check_editor_panel")
    ce.query_one("#check_file_name_input").value = "s1.chk.json"
    ce.query_one("#check_write_button").press()
    await settle(pilot)
    print("F06 Check Write status:", [m for m in log.messages if m.startswith("Check Editor:")][-1:])
    print("F06 spec files:", sorted(str(x.relative_to(app.workarea)) for x in app.workarea.rglob("*.chk.json")))
    print("F06 Check Spec values:", [str(o[1]) for o in ce.query_one("#check_spec_file_select", Select)._options if o[1] is not Select.BLANK])
    print("F06 A2B check-list scan:", app._scan_patch_change_files())


async def f40(app, pilot, log, base):
    await start(app, pilot, base)
    await load_path(app, pilot, doc(base / "k.chk.json", CHK, kind="check"))
    p = panel(app)
    p._show_tab("patch_tab_checks")
    await run_checks(app, pilot)
    print("F40 after run:", checks_tab(app), "| screen:", checks_screen(app))
    await load_path(app, pilot, doc(base / "c.json", CHG))
    print("F40 after another document load:", checks_tab(app), "| screen:", checks_screen(app))
    await load_path(app, pilot, base / "k.chk.json")
    await run_checks(app, pilot)
    await projects.load_image(pilot, app, image(base / "img2.s19", fill=0x40))
    await settle(pilot)
    print("F40 after image load:", checks_tab(app), "| screen:", checks_screen(app))
    await load_path(app, pilot, base / "k.chk.json")
    await run_checks(app, pilot)
    pd = app.workarea / "proj"
    pd.mkdir(parents=True, exist_ok=True)
    image(pd / "v.s19", fill=0x10)
    app._handle_load_project("proj")
    await wait_until(pilot, lambda: app.current_project == "proj" and app.current_file is not None, "project load")
    await app.workers.wait_for_complete()
    await settle(pilot, 12)
    print("F40 after project load:", checks_tab(app), "| last_check_result:", app._change_service.last_check_result is not None, "| screen:", checks_screen(app))
    await load_path(app, pilot, doc(base / "e.chk.json", [], kind="check"))
    await run_checks(app, pilot)
    print("F40 0-entry run:", checks_tab(app))


async def f47(app, pilot, log, base):
    pd = app.workarea / "demo"
    pd.mkdir(parents=True, exist_ok=True)
    image(pd / "firmware.s19")
    await settle(pilot, 12)
    print("F47 refusals after start:", sum(REFUSED in m for m in log.messages))
    app._handle_load_project("demo")
    await wait_until(pilot, lambda: app.current_project == "demo", "project load")
    await app.workers.wait_for_complete()
    await settle(pilot, 12)
    print("F47 refusals after project load:", sum(REFUSED in m for m in log.messages))
    await pilot.press("8")
    await settle(pilot)
    for key in ["p", "slash", "g", "tab", "enter", "space", "ctrl+z", "right_square_bracket", "B", "b"]:
        app.set_focus(None)
        mark = len(log.messages)
        await pilot.press(key)
        await app.workers.wait_for_complete()
        await settle(pilot)
        while len(app.screen_stack) > 1:
            app.pop_screen()
            await settle(pilot)
        print(f"F47 key {key!r}: refusals={sum(REFUSED in m for m in log.since(mark))}")


for name, sc in [("f05", f05), ("f05p", f05p), ("d1030", d1030), ("f06", f06), ("f40", f40), ("f47", f47)]:
    try:
        run(name, sc)
    except Exception as exc:  # noqa: BLE001 - a probe reports, never hides
        print(f"{name}: PROBE ERROR {type(exc).__name__}: {exc}")
