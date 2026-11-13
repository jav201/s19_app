"""Map mutations for the mover controls.  Usage: mv_mapmut.py <map-in> <map-out> <case>
case: 1 (drop a method entry) 2 (duplicate a method entry) 3 (check_action -> navigation) 4 (_variant_set getter/setter
in two modules) 5 (base changed) 34 (unit -> ../x) 37 (on_button_pressed -> mixin) base:<rev> (set the map base)."""
import copy
import json
import sys

src, dst, case = sys.argv[1], sys.argv[2], sys.argv[3]
m = json.load(open(src, encoding="utf-8"))
meth = m["app"]["methods"]


def entries(name):
    return [e for e in meth if e["name"] == name]


if case == "1":
    e = entries("_land_focus")[0]
    meth.remove(e)
    print("dropped", e["name"], e["line"])
elif case == "2":
    e = copy.deepcopy(entries("_land_focus")[0])
    e["module"] = "shell"
    meth.append(e)
    print("duplicated _land_focus -> shell")
elif case == "3":
    entries("check_action")[0]["module"] = "navigation"
    print("check_action -> navigation")
elif case == "4":
    e = entries("_variant_set")
    assert len(e) == 2, e
    e[1]["module"] = "shell"
    print("_variant_set getter projects / setter shell")
elif case == "5":
    m["base"] = "287b9dc3"
    print("base -> 287b9dc3")
elif case == "34":
    entries("_land_focus")[0]["module"] = "../x"
    print("_land_focus -> ../x")
elif case == "37":
    entries("on_button_pressed")[0]["module"] = "navigation"
    print("on_button_pressed -> navigation")
elif case.startswith("base:"):
    m["base"] = case.split(":", 1)[1]
else:
    raise SystemExit("unknown case " + case)
json.dump(m, open(dst, "w", encoding="utf-8", newline="\n"), indent=1)
