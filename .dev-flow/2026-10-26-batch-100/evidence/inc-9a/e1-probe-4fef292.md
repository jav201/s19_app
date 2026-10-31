# Inc 9a E1 base probe at 4fef292 (worktree b100-inc9a; s19env; script below, output after it)
```python
import sys, shutil, tempfile, asyncio
from pathlib import Path
WT = Path(r"<worktree>")
sys.path.insert(0, str(WT))
import s19_app
print("s19_app from", s19_app.__file__)
from s19_app.tui.app import S19TuiApp
from textual.widgets import Label, ListView

base = Path(tempfile.mkdtemp(prefix="probe9a_"))
src = WT / "examples" / "case_01_basic_valid" / "firmware.s19"

async def main():
    app = S19TuiApp(base_dir=base)
    msgs = []
    orig = app.set_status
    def rec(m, *a, **k):
        msgs.append(str(m)); return orig(m, *a, **k)
    app.set_status = rec
    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        wa = app.workarea
        (wa / "ab").mkdir()
        shutil.copy(src, wa / "ab" / "firmware.s19")
        (wa / "ab" / "project.json").write_text('{"schema_version": 1}', encoding="utf-8")
        shutil.copy(src, wa / "temp" / "firmware.s19")
        (wa / "temp" / "[bold]x.s19").write_bytes(src.read_bytes())
        for typed in [wa / "ab", wa / "ab" / "project.json", wa / "temp", wa / "temp" / ".." / "ab"]:
            m = len(msgs)
            app._load_path_from_user_input(typed)
            for _ in range(20): await pilot.pause()
            print("typed", typed.relative_to(base), "->", msgs[m:], "project=", app.current_project)
        m = len(msgs)
        before = sorted(p.name for p in (wa/"temp").iterdir())
        app._handle_load_project("temp")
        for _ in range(40): await pilot.pause()
        print("_handle_load_project('temp') ->", msgs[m:][:3], "project=", app.current_project,
              "temp/project.json exists:", (wa/"temp"/"project.json").exists())
        app.refresh_files()
        await pilot.pause()
        lv = app.query_one("#files_list", ListView)
        for item in lv.children:
            lab = item.query_one(Label)
            vis = lab.visual if hasattr(lab, "visual") else None
            print("row data=", item.data, "visual=", repr(vis)[:160])
asyncio.run(main())
```
## Output
```
s19_app from <worktree>\s19_app\__init__.py
typed .s19tool\workarea\ab -> ['Unsupported file type: '] project= None
typed .s19tool\workarea\ab\project.json -> ['Unsupported file type: .json'] project= None
typed .s19tool\workarea\temp -> ['Unsupported file type: '] project= None
typed .s19tool\workarea\temp\..\ab -> ['Unsupported file type: '] project= None
_handle_load_project('temp') -> ["Loaded project 'temp' -> [bold]x.s19 - variant 1 of 2, 1 problem - details: p"] project= temp temp/project.json exists: False
row data= [bold]x.s19 visual= Content('x.s19', spans=[Span(0, 5, style='bold')])
row data= firmware.s19 visual= Content('firmware.s19')
```
