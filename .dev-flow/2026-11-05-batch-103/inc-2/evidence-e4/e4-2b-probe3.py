import sys
from pathlib import Path
sys.path.insert(0, ".")
from s19_app.tui.a2l_parse import parse_a2l_file
print("s19_app.__file__ =", __import__("s19_app").__file__)
for f in ["ASAP2_Demo_V171.a2l", "software_a.a2l", "BalanceTube_STMicro.a2l"]:
    a = parse_a2l_file(Path("examples/case_00_public") / f)
    print(f"== {f} errors ({len(a.get('errors') or [])}) ==")
    for e in (a.get("errors") or [])[:8]:
        print("   ", repr(e))
