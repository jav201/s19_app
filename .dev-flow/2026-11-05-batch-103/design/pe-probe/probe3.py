import asyncio, os, sys, shutil, glob
from pathlib import Path
ROOT = Path.home()/"work"/"s19_app"
sys.path.insert(0, str(ROOT))
import s19_app
print("s19_app.__file__ =", s19_app.__file__)
from textual.widgets import Button, Label, Input
from tests.test_b100_save_image import (_load_file_through_dialog, _add_entry_through_the_panel,
    _wait_for, _status_text, CASE01_DIR)
from s19_app.tui.app import S19TuiApp
from s19_app.tui.changes.io import emit_intel_hex_from_mem_map
from tests.support.independent_reader import read_s19

W = Path(os.environ["PROBE"])
def geom(app, sel):
    ws = list(app.query(sel))
    if not ws: return "ABSENT"
    w = ws[0]
    # visible = all ancestors displayed and region intersects the screen & parent clip
    anc = []
    n = w
    vis = True
    while n is not None:
        if not n.display: vis=False; anc.append(f"hidden:{n.id or type(n).__name__}")
        n = n.parent
    return dict(region=str(w.region), visible_region=str(w.visible_region) if hasattr(w,'visible_region') else None,
                displayed=w.display, ancestors_all_displayed=vis, bad=anc, screen=str(app.screen.size),
                disabled=getattr(w,'disabled',None), label=str(getattr(w,'label','')))


def _ranges(data):
    ks = sorted(data); rs=[]; s=p=None
    for k in ks:
        if s is None: s=p=k
        elif k==p+1: p=k
        else: rs.append((s,p+1)); s=p=k
    if s is not None: rs.append((s,p+1))
    return rs

async def scene2(kind, size):
    tag=f"p2-{kind}-{size[0]}"
    base = W/f"app-{tag}"; src_dir = W/f"src-{tag}"
    shutil.rmtree(base, ignore_errors=True); shutil.rmtree(src_dir, ignore_errors=True)
    src_dir.mkdir(parents=True)
    s19 = src_dir/"firmware.s19"; shutil.copy2(CASE01_DIR/"firmware.s19", s19); src=s19
    if kind=="hex":
        d=read_s19(s19); src=src_dir/"firmware.hex"
        src.write_text(emit_intel_hex_from_mem_map(dict(d.data), _ranges(d.data)))
    app = S19TuiApp(base_dir=base); o={}
    async with app.run_test(size=size, notifications=True) as pilot:
        await pilot.pause()
        await _load_file_through_dialog(pilot, app, src)
        cf=app.current_file
        o["loaded"]=(cf.file_type, cf.path.name, len(cf.mem_map), cf.ranges[:2])
        o["byte_before"]=cf.mem_map.get(0x8000007C)
        await _add_entry_through_the_panel(pilot, app, "0x8000007C", "DE AD BE EF")
        o["tab_before_apply"]=app.query_one("#patch_tab_switcher").current
        await pilot.click("#patch_doc_apply_button")
        for _ in range(15): await pilot.pause()
        o["status"]=_status_text(app)
        o["byte_after"]=app.current_file.mem_map.get(0x8000007C)
        o["tab_after_apply"]=app.query_one("#patch_tab_switcher").current
        o["saveback_hidden_class"]=app.query_one("#patch_saveback_row").has_class("hidden")
        o["saveback_geom_on_inspector_tab"]=geom(app,"#patch_saveback_row")
        o["notifications"]=[str(n.message) for n in app._notifications] if hasattr(app,"_notifications") else None
        # strip / hex text
        for sel in ("#patch_before_after_strip","#patch_strip","#patch_history_strip"):
            ws=list(app.query(sel)); o["static:"+sel]=str(ws[0].render()) if ws else "ABSENT"
        ids=[w.id for w in app.query("*") if w.id and ("strip" in w.id or "before" in w.id or "hex" in w.id)]
        o["ids_strip_hex"]=ids
        await pilot.click("#patch_tab_json"); 
        for _ in range(5): await pilot.pause()
        o["tab_now"]=app.query_one("#patch_tab_switcher").current
        o["saveback_geom_on_json_tab"]=geom(app,"#patch_saveback_row")
        o["write_btn_geom"]=geom(app,"#patch_saveback_confirm_button")
        o["width_btn_geom"]=geom(app,"#patch_saveback_width_button")
        o["json_win"]=geom(app,"#patch_win_json")
        o["w1"]=await pilot.click("#patch_saveback_width_button"); await pilot.pause()
        o["width_label_after_click"]=str(app.query_one("#patch_saveback_width_button").label)
        o["name"]=app.query_one("#patch_saveback_name_input").value
        o["w2"]=await pilot.click("#patch_saveback_confirm_button")
        for _ in range(25): await pilot.pause()
        o["status_after_write"]=_status_text(app)
        o["files_after_write"]=sorted(str(p.relative_to(base)) for p in base.rglob("*") if p.is_file())
        o["notif2"]=[ (n.title,n.message) for n in getattr(app,"_notifications",[])]
        wd=base/".s19tool/workarea"
        for f in wd.glob("firmware-patched.*"):
            ls=f.read_text().splitlines(); o["out_file"]=(f.name,len(ls),ls[0][:40],ls[1][:60],ls[-1][:30])
        # Save button
        await pilot.click("#patch_doc_save_button")
        for _ in range(25): await pilot.pause()
        o["status_after_Save"]=_status_text(app)
        o["files_after_Save"]=sorted(str(p.relative_to(base)) for p in base.rglob("*") if p.is_file())
    return o

async def main():
    for kind,size in (("hex",(118,54)),("hex",(220,60))):
        print("=== P2",kind,size)
        try:
            for k,v in (await scene2(kind,size)).items(): print(" ",k,"=",v)
        except Exception:
            import traceback; traceback.print_exc()
asyncio.run(main())
