import sys, asyncio
root = sys.argv[1]
sys.path.insert(0, root)
sys.path.insert(1, r"C:\Users\jjgh8\Github\s19_app")
import tempfile, pathlib
from s19_app.tui.app import S19TuiApp
import s19_app; print("module from", s19_app.__file__)
from tests.b97_fixtures import PE_IDS_9C7BEAF
from textual.widgets import Button, Input, Select, TextArea
from collections import Counter
async def main():
    d = tempfile.mkdtemp()
    app = S19TuiApp(base_dir=pathlib.Path(d))
    async with app.run_test(size=(118,54)) as pilot:
        await pilot.pause(); app.action_show_screen("patch"); await pilot.pause(); await pilot.pause()
        c = Counter(); per = {}
        for i in sorted(PE_IDS_9C7BEAF):
            w = app.query_one("#"+i)
            for t in (Button, Input, Select, TextArea):
                if isinstance(w, t):
                    c[t.__name__] += 1; per.setdefault(t.__name__, []).append(f"{i}:{type(w).__name__}"); break
        print(dict(c), "total(B+I+S)=", c["Button"]+c["Input"]+c["Select"])
        for k,v in per.items(): print(k, v)
asyncio.run(main())
