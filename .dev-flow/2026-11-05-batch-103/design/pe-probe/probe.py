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

async def scene(kind, size, tag, mutate=None, load=True, entry=True):
    base = W/f"app-{tag}"; src_dir = W/f"src-{tag}"
    shutil.rmtree(base, ignore_errors=True); shutil.rmtree(src_dir, ignore_errors=True)
    src_dir.mkdir(parents=True)
    s19 = src_dir/"firmware.s19"; shutil.copy2(CASE01_DIR/"firmware.s19", s19)
    src = s19
    if kind == "hex":
        d = read_s19(s19)
        src = src_dir/"firmware.hex"
        src.write_text(emit_intel_hex_from_mem_map(dict(d.data), sorted([(a,a) for a in []]) or _ranges(d.data)))
    app = S19TuiApp(base_dir=base)
    out = {}
    async with app.run_test(size=size, notifications=True) as pilot:
        await pilot.pause()
        if load: await _load_file_through_dialog(pilot, app, src)
        if mutate: await mutate(pilot, app)
        if entry:
            await _add_entry_through_the_panel(pilot, app, "0x8000007C", "DE AD BE EF")
        else:
            await pilot.press("6"); await pilot.pause()
        out["apply_btn"] = geom(app, "#patch_doc_apply_button")
        out["validate_btn"] = geom(app, "#patch_doc_validate_button")
        out["save_btn"] = geom(app, "#patch_doc_save_button")
        ok = await pilot.click("#patch_doc_apply_button")
        out["click_ok"] = ok
        for _ in range(15): await pilot.pause()
        out["status_after_apply"] = _status_text(app)
        out["saveback_row"] = geom(app, "#patch_saveback_row")
        row = list(app.query("#patch_saveback_row"))
        out["saveback_hidden_class"] = row[0].has_class("hidden") if row else None
        if row and not row[0].has_class("hidden"):
            out["name_input"] = app.query_one("#patch_saveback_name_input", Input).value
            out["width_label0"] = str(app.query_one("#patch_saveback_width_button", Button).label)
            out["confirm_geom"] = geom(app, "#patch_saveback_confirm_button")
            ok2 = await pilot.click("#patch_saveback_width_button")
            await pilot.pause()
            out["width_label1"] = str(app.query_one("#patch_saveback_width_button", Button).label)
            ok3 = await pilot.click("#patch_saveback_confirm_button")
            for _ in range(20): await pilot.pause()
            out["status_after_confirm"] = _status_text(app)
        out["files"] = sorted(str(p.relative_to(base)) for p in base.rglob("*") if p.is_file())
        out["project_active"] = str(app._active_project_dir())
    return out

def _ranges(data):
    ks = sorted(data); rs=[]; s=p=None
    for k in ks:
        if s is None: s=p=k
        elif k==p+1: p=k
        else: rs.append((s,p)); s=p=k
    if s is not None: rs.append((s,p))
    return rs

async def main():
    import json
    for kind in ("s19","hex"):
        for size in ((118,54),(220,60)):
            tag=f"{kind}-{size[0]}"
            print("=== SCENE", tag)
            try:
                r = await scene(kind,size,tag)
                for k,v in r.items(): print(" ",k,"=",v)
            except Exception as e:
                import traceback; traceback.print_exc()
    # refusals
    print("=== NO IMAGE loaded, entry added, apply")
    try:
        r = await scene("s19",(118,54),"noimg",load=False)
        for k,v in r.items(): print(" ",k,"=",v)
    except Exception:
        import traceback; traceback.print_exc()
asyncio.run(main())
