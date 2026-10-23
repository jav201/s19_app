"""Thread U2: Save project / Load project dialogs, driven by keys and clicks.

case_01 firmware.s19 + firmware.mac + firmware.a2l -> `s` -> Save as P1.
`U` (unload all) -> load case_00 prg.s19 -> `s` -> Save as P2.
`p` -> the Load project dialog -> highlight P1 -> click Load.  Then `p` -> P2 (load over P1).
"""
from ucommon import *  # noqa: F403


async def main():
    base = new_base()
    app = new_app(base)
    async with app.run_test(size=SIZE) as pilot:
        await settle(app, pilot)

        async def load(path):
            app._load_path_from_user_input(Path(path))
            await settle(app, pilot)

        async def save(name):
            await pilot.press("s")
            await settle(app, pilot, 3)
            scr = app.screen
            from textual.widgets import Label, Button
            p(f"   save dialog = {type(scr).__name__}; labels={[text_of(w) for w in scr.query(Label)]}; buttons={[text_of(b) for b in scr.query(Button)]}")
            p("   parent prefill =", scr.query_one("#project_parent_path").value)
            scr.query_one("#project_name").value = name
            await pilot.click("#save_ok")
            await settle(app, pilot)
            p("   after save: screen =", type(app.screen).__name__)
            p("   recorded =", take(app))
            p("   painted status =", q_text(app, "#status_text"))

        async def open_load_dialog(pick, via="button"):
            p("   focused before `p` =", type(app.focused).__name__ if app.focused else None, getattr(app.focused, "id", None))
            await pilot.press("p")
            await settle(app, pilot, 3)
            scr = app.screen
            p(f"   load dialog after `p` = {type(scr).__name__}")
            if type(scr).__name__ != "LoadProjectScreen":
                await pilot.click("#ws_load_project_button")
                await settle(app, pilot, 3)
                scr = app.screen
                p(f"   load dialog after clicking 'Load project (p)' button = {type(scr).__name__}")
            if type(scr).__name__ != "LoadProjectScreen":
                app.action_load_project(); await settle(app, pilot, 3); scr = app.screen
                p(f"   load dialog after action_load_project() = {type(scr).__name__}")
            if type(scr).__name__ != "LoadProjectScreen":
                p("   recorded =", take(app)); return
            items = listview_items(scr, "#project_list") if False else None
            from textual.widgets import ListView, Label
            lv = scr.query_one("#project_list", ListView)
            names = [text_of(li.query_one(Label)) for li in lv.children]
            p("   listed projects =", names)
            lv.index = names.index(pick)
            await pilot.pause()
            dismissed = []
            orig = scr.dismiss

            def spy(result=None):
                dismissed.append(result)
                return orig(result)
            scr.dismiss = spy
            if via == "button":
                await pilot.click("#project_ok")
            else:
                lv.focus(); await pilot.pause(); await pilot.press("enter")
            await settle(app, pilot)
            p(f"   via={via}: dismiss value = {dismissed!r}; screen now = {type(app.screen).__name__}")
            p("   recorded =", take(app))
            p("   painted status =", q_text(app, "#status_text"))
            if type(app.screen).__name__ == "LoadProjectScreen":
                await pilot.click("#project_cancel"); await settle(app, pilot, 2)

        def state(tag):
            f = app.current_file
            p(f"   [{tag}] project={app.current_project!r} file={f.path.parent.name + '/' + f.path.name if f else None} "
              f"mac={(f.mac_path.name if f and f.mac_path else None)} a2l={app.current_a2l_path.parent.name + '/' + app.current_a2l_path.name if app.current_a2l_path else None} "
              f"entries={len(app._change_service.document.entries)}")
            p(f"   [{tag}] #status_context =", q_text(app, "#status_context"))

        p("== U2.1 load case_01 s19 + mac + a2l, Save as P1")
        await load(C1 / "firmware.s19"); await load(C1 / "firmware.mac"); await load(C1 / "firmware.a2l")
        take(app); state("before save")
        await save("P1")
        p("== U2.2 `U` unload all")
        await pilot.press("U"); await settle(app, pilot)
        p("   recorded =", take(app)); state("after U")
        p("== U2.3 load case_00 prg.s19, Save as P2")
        await load(EX / "case_00_public" / "prg.s19"); p("   recorded (load prg) =", take(app)); state("after load prg")
        p("   P1 tree after loose load =", sorted(x.name for x in (app.workarea / "P1").iterdir()))
        await save("P2")
        p("   P2 tree =", sorted(x.name for x in (app.workarea / "P2").iterdir()))
        p("   P1 tree =", sorted(x.name for x in (app.workarea / "P1").iterdir()))
        p("== U2.4 `p` -> pick P1 -> Load button")
        await open_load_dialog("P1", "button"); state("after Load P1 via button")
        p("== U2.5 `p` -> pick P1 -> enter on the list")
        await open_load_dialog("P1", "enter"); state("after Load P1 via enter")
        p("== U2.6 direct handler (what tests call): _handle_load_project('P1')")
        app._handle_load_project("P1"); await settle(app, pilot)
        p("   recorded =", take(app)); state("after handler P1")
        p("== U2.7 `p` -> P2 over P1 (load over an open project)")
        await open_load_dialog("P2", "button")
        app._handle_load_project("P2"); await settle(app, pilot)
        p("   recorded (handler P2) =", take(app)); state("after handler P2")
        p("   A2L screen title =", q_text(app, "#a2l_title") , "| ws a2l view head =", q_text(app, "#a2l_view")[:160])
        p("== U2.8 Save dialog with an empty name, Save clicked")
        await pilot.press("s"); await settle(app, pilot, 3)
        scr = app.screen; scr.query_one("#project_name").value = ""
        await pilot.click("#save_ok"); await settle(app, pilot, 3)
        p("   screen now =", type(app.screen).__name__, "recorded =", take(app))


run(main)
