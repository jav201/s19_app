"""Mover mutations in a scratch copy of move_emit.py.  Usage: mv_toolmut.py <move_emit.py> <8|9|10>
8  : a generated mixin (navigation) imports S19TuiApp from core          (NC-MV-8: fresh-import / cycle / direction check must fail)
9  : deps no longer binds the imported D1 names                           (NC-MV-9: deps-bound self-check must fail)
10 : string-annotation names no longer feed the TYPE_CHECKING source      (NC-MV-10: F5)"""
import sys
from pathlib import Path

p, case = Path(sys.argv[1]), sys.argv[2]
t = p.read_text(encoding="utf-8")
if case == "8":
    a = "    imports = _resolve(pkg, module, runtime, annotation, has_d1, module_order, str_ann)\n"
    b = a + '    if module == "navigation":\n        imports.append("from .core import S19TuiApp\\n")\n'
elif case == "9":
    a = "runtime |= {n for n in pkg.d1_names if n in pkg.import_by_name}"
    b = "runtime |= {n for n in pkg.d1_names if n in ()}"
else:
    a = "    str_ann = string_annotation_names(pkg, module)\n"
    b = "    str_ann = set()\n"
assert t.count(a) == 1, (case, t.count(a))
p.write_text(t.replace(a, b), encoding="utf-8", newline="\n")
