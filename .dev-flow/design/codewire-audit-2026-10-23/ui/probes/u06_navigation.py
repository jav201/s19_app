"""Thread U6: navigation — bindings vs actions, the key bar, focus after a load, help.

1. Static: every App/Screen binding names an action method that exists.
2. Footer (key bar at 9793fcd) text at 160 cols.
3. After a file load on the Workspace: who has the focus, and what the single
   keys `p`, `t`, `d`, `a`, `e`, `k` do (the SJE window is hidden).
4. Rail: each rail item reaches its screen.
"""
from ucommon import *  # noqa: F403


def plain(w):
    try:
        r = w.render(); return str(getattr(r, "plain", r))
    except Exception as exc:  # noqa: BLE001
        return f"<{exc}>"


async def main():
    from s19_app.tui.app import S19TuiApp
    from textual.binding import Binding
    missing = []
    for b in S19TuiApp.BINDINGS:
        key, action = (b.key, b.action) if isinstance(b, Binding) else (b[0], b[1])
        name = action.split("(")[0]
        if not hasattr(S19TuiApp, "action_" + name):
            missing.append((key, action))
    p("== U6.0 app bindings with no action method =", missing)
    base = new_base()
    app = new_app(base)
    async with app.run_test(size=SIZE) as pilot:
        await settle(app, pilot)
        from textual.widgets import Footer
        p("== U6.1 Footer keys shown =", [(k.key, k.description) for k in app.query("FooterKey")] if app.query("FooterKey") else plain(app.query_one(Footer)))
        p("   focus at start =", type(app.focused).__name__ if app.focused else None, getattr(app.focused, "id", None))
        app._load_path_from_user_input(C1 / "firmware.s19"); await settle(app, pilot); take(app)
        p("== U6.2 after load: screen =", app._active_screen_key, "| focused =", type(app.focused).__name__ if app.focused else None, getattr(app.focused, "id", None))
        sje = app.query_one("#screen_split_join")
        p("   SJE window hidden? =", sje.has_class("hidden"), "| sje display =", sje.display)
        splits_before = sorted(str(x.relative_to(app.workarea)) for x in app.workarea.rglob("*") if "split" in str(x).lower())
        for key in ["p", "t", "a", "e", "e", "k"]:
            scr_before = type(app.screen).__name__
            await pilot.press(key); await settle(app, pilot, 3)
            p(f"   key `{key}`: screen {scr_before} -> {type(app.screen).__name__}; active={app._active_screen_key}; recorded={take(app)}")
            if type(app.screen).__name__ != "Screen":
                await pilot.press("escape"); await settle(app, pilot, 2)
        splits_after = sorted(str(x.relative_to(app.workarea)) for x in app.workarea.rglob("*") if x.is_file() and x.parent.name != "temp")
        p("   files in workarea (not temp) after the keys =", splits_after)
        p("== U6.3 the same keys with the focus moved to the hex view")
        try:
            app.query_one("#hex_scroll").focus(); await pilot.pause()
        except Exception as exc:  # noqa: BLE001
            p("   focus move failed", exc)
        p("   focused =", type(app.focused).__name__ if app.focused else None, getattr(app.focused, "id", None))
        await pilot.press("p"); await settle(app, pilot, 3)
        p(f"   key `p`: screen -> {type(app.screen).__name__}; recorded={take(app)}")
        if type(app.screen).__name__ != "Screen":
            await pilot.press("escape"); await settle(app, pilot, 2)
            p(f"   after `escape`: screen = {type(app.screen).__name__}")
            if type(app.screen).__name__ == "LoadProjectScreen":
                await pilot.click("#project_cancel"); await settle(app, pilot, 2)
        for opener, name in (("l", "LoadFileScreen"), ("s", "SaveProjectScreen")):
            app.query_one("#hex_scroll").focus(); await pilot.pause()
            await pilot.press(opener); await settle(app, pilot, 2)
            got = type(app.screen).__name__
            await pilot.press("escape"); await settle(app, pilot, 2)
            p(f"   `{opener}` opened {got}; after `escape`: {type(app.screen).__name__}")
            if type(app.screen).__name__ != "Screen":
                for cid in ("#load_cancel", "#save_cancel"):
                    try:
                        await pilot.click(cid); await settle(app, pilot, 2); break
                    except Exception:
                        pass
        p("== U6.4 rail items")
        from s19_app.tui.rail import RailItem
        items = list(app.query(RailItem))
        p("   rail items =", [(getattr(i, "id", None), plain(i)[:24].replace("\n", " ")) for i in items])
        p("== U6.5 `?` help panel")
        await pilot.press("question_mark"); await settle(app, pilot, 3)
        p("   screen =", type(app.screen).__name__, "| help panel shown =", bool(app.query("HelpPanel")))
        hp = app.query("HelpPanel")
        if hp:
            txt = " ".join(plain(w) for w in hp.first().query("*") if hasattr(w, "render"))
            p("   help mentions 'Load project' =", "Load project" in txt, "| 'Unload all' =", "Unload all" in txt, "| 'Export' =", "Export" in txt, "| 'Split' =", "Split" in txt)
        p("   help screen text head =", " ".join(plain(w) for w in app.screen.query("*") if hasattr(w, "render"))[:600] if type(app.screen).__name__ != "Screen" else "-")


run(main)
