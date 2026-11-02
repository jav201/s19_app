"""Scratch UX probe (batch-100 P4 expert inspection). Drives the shipped app
headless through real keys and saves SVG + a text report. Never writes under
the repo: the work area lives under --base (scratch)."""
import asyncio, os, sys, time, json
from pathlib import Path

ROOT = Path(os.environ["PYTHONPATH"].split(os.pathsep)[0]).resolve()
sys.path.insert(0, str(ROOT / "tools" / "e13"))
import run as e13  # read-only reuse of the E13 seeders

scen, cols, rows = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
base, out = Path(sys.argv[4]), Path(sys.argv[5])
base.mkdir(parents=True, exist_ok=True)
os.chdir(base)
seed_as = {
    "panel-saveback": "pe-patched", "panel-problems": "pe-problems",
    "panel-a2l": "pe-a2l-only", "panel-unreadable": "pe-unreadable",
    "load-p": "ld-dialog", "load-l": "ld-dialog", "load-recent": "ld-dialog",
    "load-wa": "ld-dialog", "load-refused": "ld-dialog", "load-empty": "ld-dialog",
    "save-new": "ld-dialog", "save-open": "ld-dialog", "save-other": "ld-dialog",
    "save-con": "ld-dialog", "save-empty": "ld-dialog", "save-long": "ld-dialog",
    "replace-q": "lq-question", "walk-saveback": "pe-clean", "busy-refuse": "ld-dialog", "idle-after": "pe-patched", "panel-details": "pe-unreadable",
}[scen]
from s19_app.tui.workspace import WORKAREA_DIRNAME, WORKAREA_SUBDIR, record_recent_source

wa = base / WORKAREA_DIRNAME / WORKAREA_SUBDIR
e13.seed(wa, seed_as)
from s19_app.tui.app import S19TuiApp


class App(S19TuiApp):
    CSS_PATH = str(ROOT / "s19_app" / "tui" / "styles.tcss")


app = App(base_dir=base)
report = {"scenario": scen, "size": f"{cols}x{rows}"}


def txt(sel):
    try:
        w = app.screen.query_one(sel)
    except Exception:
        return f"<no {sel}>"
    v = getattr(w, "label", None)
    if v is not None:
        return getattr(v, "plain", str(v))
    r = w.render()
    return str(getattr(r, "plain", r))


async def wait_screen(name, pilot, n=100):
    for _ in range(n):
        if type(app.screen).__name__ == name:
            return True
        await pilot.pause(0.1)
    return False


async def main():
    async with app.run_test(size=(cols, rows)) as pilot:
        await pilot.pause(0.5)
        s = scen
        if s.startswith("panel") or s == "idle-after":
            await pilot.press("p")
            await wait_screen("LoadDialog", pilot)
            await pilot.pause(0.3)
            await pilot.press("enter")
            await wait_screen("LoadResultScreen", pilot)
            await pilot.pause(0.5)
            report["focused"] = getattr(app.focused, "id", None)
            report["title"] = txt(".modal-title")
            if s == "panel-problems":
                await pilot.press("end")
                await pilot.pause(0.3)
                body = app.screen.query_one("#result_body")
                last = list(app.screen.query(".result-problem"))[-1]
                report["body_region"] = str(body.region)
                report["last_region"] = str(last.region)
                report["scroll_y"] = body.scroll_y
                report["max_scroll_y"] = body.max_scroll_y
            if s == "panel-details":
                await pilot.press("escape")
                await pilot.pause(0.5)
                await pilot.press("p")
                await wait_screen("LoadDialog", pilot)
                await pilot.pause(0.5)
                report["details_preview"] = txt("#load_preview Static")
            if s == "idle-after":
                await pilot.press("escape")
                await pilot.pause(0.5)
                report["focused_after"] = getattr(app.focused, "id", None)
                report["status_text"] = str(app.query_one("#status_text").render())
                from textual.widgets import ProgressBar

                pb = app.query_one("#progress_bar", ProgressBar)
                report["bar"] = {"progress": pb.progress, "total": pb.total,
                                 "display": pb.display, "visibility": str(pb.styles.visibility)}
                report["log_tail"] = list(app.log_lines)[-2:]
        elif s.startswith("load"):
            record_recent_source(e13.CASE02)
            await pilot.press("l" if s in ("load-l", "load-refused", "load-empty") else "p")
            await wait_screen("LoadDialog", pilot)
            await pilot.pause(0.4)
            if s == "load-recent":
                for _ in range(4):
                    await pilot.press("down")
                await pilot.pause(0.3)
            if s == "load-wa":
                for _ in range(3):
                    await pilot.press("down")
                await pilot.pause(0.3)
            if s == "load-refused":
                await pilot.press(*list("C:\\nope\\x.s19"))
                await pilot.press("enter")
                await pilot.pause(0.5)
            if s == "load-empty":
                await pilot.press("enter")
                await pilot.pause(0.5)
            report["focused"] = getattr(app.focused, "id", None)
            report["load_reason"] = txt("#load_reason")
            report["preview"] = txt("#load_preview Static")
            from textual.widgets import OptionList

            lst = app.screen.query_one("#load_list", OptionList)
            report["highlighted"] = lst.highlighted
            report["rows"] = [str(lst.get_option_at_index(i).prompt) for i in range(lst.option_count)]
            report["stacked"] = "stacked" in app.screen.query_one("#load_panes").classes
        elif s.startswith("save") or s == "busy-refuse":
            await pilot.press("p")
            await wait_screen("LoadDialog", pilot)
            await pilot.pause(0.3)
            await pilot.press("enter")
            await wait_screen("LoadResultScreen", pilot)
            await pilot.pause(0.4)
            await pilot.press("escape")
            await pilot.pause(0.5)
            if s == "busy-refuse":
                import s19_app.tui.app as am

                real = am.place_into_workarea

                def slow(*a, **k):
                    time.sleep(30)
                    return real(*a, **k)

                am.place_into_workarea = slow
            await pilot.press("ctrl+s")
            await wait_screen("SaveProjectScreen", pilot)
            await pilot.pause(1.2)
            report["prefill"] = txt("#project_name") if False else app.screen.query_one("#project_name").value
            report["prefill_summary"] = [str(getattr(w.render(), "plain", w.render())) for w in app.screen.query("#save_summary Static")]
            report["prefill_where"] = txt("#save_where")
            report["focused_on_open"] = getattr(app.focused, "id", None)
            name = {"save-new": "P2", "save-open": "P", "save-other": "Q", "save-con": "CON",
                    "save-empty": "", "save-long": "a_rather_long_project_name_for_the_calibration_review",
                    "busy-refuse": "P9"}[s]
            from textual.widgets import Input

            f = app.screen.query_one("#project_name", Input)
            f.focus()
            await pilot.pause(0.1)
            f.value = ""
            if name:
                await pilot.press(*list(name))
            await pilot.pause(1.5)
            if s == "save-empty":
                await pilot.press("alt+s")
                await pilot.pause(0.5)
            if s == "busy-refuse":
                await pilot.press("alt+s")
                for _ in range(50):
                    if "step" in str(app.query_one("#status_text").render()):
                        break
                    await pilot.pause(0.1)
                await pilot.pause(0.5)
                report["status_during"] = str(app.query_one("#status_text").render())
                await pilot.press("l")
                await pilot.pause(0.5)
                report["screen_after_l"] = type(app.screen).__name__
                report["log_tail"] = list(app.log_lines)[-3:]
            else:
                report["save_where"] = txt("#save_where")
                report["summary_rows"] = [str(getattr(w.render(), "plain", w.render())) for w in app.screen.query("#save_summary Static")]
                report["focused"] = getattr(app.focused, "id", None)
                report["titles"] = [str(getattr(w.render(), "plain", w.render())) for w in app.screen.query(".modal-title")]
        elif s == "walk-saveback":
            from textual.widgets import Input
            await pilot.press("p"); await wait_screen("LoadDialog", pilot); await pilot.pause(0.3)
            await pilot.press("enter"); await wait_screen("LoadResultScreen", pilot); await pilot.pause(0.4)
            await pilot.press("escape"); await pilot.pause(0.5)
            app.action_show_screen("patch"); await pilot.pause(0.8)
            app.query_one("#patch_entry_address_input", Input).value = "0x8000007C"
            app.query_one("#patch_entry_bytes_input", Input).value = "DE AD BE EF"
            app.query_one("#patch_entry_add_button").press(); await pilot.pause(0.5)
            app.query_one("#patch_doc_apply_button").press(); await pilot.pause(0.8)
            await pilot.press("ctrl+s"); await wait_screen("SaveProjectScreen", pilot); await pilot.pause(1.5)
            report["save_where"] = txt("#save_where")
            report["summary_rows"] = [str(getattr(w.render(), "plain", w.render())) for w in app.screen.query("#save_summary Static")]
            (out / f"{scen}-1save.{cols}x{rows}.svg").write_text(app.export_screenshot(), encoding="utf-8")
            await pilot.press("alt+s")
            for _ in range(100):
                if type(app.screen).__name__ == "Screen" and "Saving" not in str(app.query_one("#status_text").render()):
                    break
                await pilot.pause(0.1)
            await pilot.pause(1.0)
            report["after_save_status"] = str(app.query_one("#status_text").render())
            report["after_save_log"] = list(app.log_lines)[-4:]
            report["current_file_after_save"] = str(getattr(app.current_file, "path", None))
            report["current_project_after_save"] = app.current_project
            (out / f"{scen}-2saved.{cols}x{rows}.svg").write_text(app.export_screenshot(), encoding="utf-8")
            await pilot.press("p"); await wait_screen("LoadDialog", pilot); await pilot.pause(0.4)
            report["dialog_preview"] = txt("#load_preview Static")
            (out / f"{scen}-3dialog.{cols}x{rows}.svg").write_text(app.export_screenshot(), encoding="utf-8")
            await pilot.press("enter")
            for _ in range(100):
                if type(app.screen).__name__ in ("LoadResultScreen", "ConfirmQuestionScreen"):
                    break
                await pilot.pause(0.1)
            await pilot.pause(0.6)
            report["reopen_screen"] = type(app.screen).__name__
            if report["reopen_screen"] == "ConfirmQuestionScreen":
                report["q_body"] = txt("#confirm_body")
        elif s == "replace-q":
            from textual.widgets import Input

            app.load_from_path(e13.CASE01)
            for _ in range(80):
                cur = app.current_file
                if cur is not None and Path(cur.path).name == "firmware.s19":
                    break
                await pilot.pause(0.1)
            await pilot.pause(0.4)
            app.action_show_screen("patch")
            await pilot.pause(0.8)
            app.query_one("#patch_entry_address_input", Input).value = "0x8000007C"
            app.query_one("#patch_entry_bytes_input", Input).value = "DE AD BE EF"
            app.query_one("#patch_entry_add_button").press()
            await pilot.pause(0.5)
            app.query_one("#patch_doc_apply_button").press()
            await pilot.pause(0.8)
            await pilot.press("p")
            await wait_screen("LoadDialog", pilot)
            await pilot.pause(0.3)
            await pilot.press("enter")
            await wait_screen("ConfirmQuestionScreen", pilot)
            await pilot.pause(0.4)
            report["focused"] = getattr(app.focused, "id", None)
            report["title"] = txt("#confirm_title")
            report["body"] = txt("#confirm_body")
            report["yes_primary"] = "modal-confirm" in app.screen.query_one("#confirm_yes").classes
            report["no_primary"] = "modal-confirm" in app.screen.query_one("#confirm_no").classes
        report["screen"] = type(app.screen).__name__
        svg = app.export_screenshot(title=f"{scen} {cols}x{rows}")
        (out / f"{scen}.{cols}x{rows}.svg").write_text(svg, encoding="utf-8")
        (out / f"{scen}.{cols}x{rows}.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=1, default=str), encoding="utf-8")
        sys.stdout.flush()
        os._exit(0)


asyncio.run(main())
