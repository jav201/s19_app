"""E3 security bench 2, Inc 3a: split of the per-element decode cost (replace of the extended Definition vs Inc 2a's
read + conversion on the object's own definition). V171 ordinary scalar; read-only trees."""
import pathlib, sys, time
from dataclasses import dataclass, replace
sys.path.insert(0, "/home/<user>/work/b103-int2a")
import s19_app, s19_app.tui.a2l as a, s19_app.tui.a2l_definition as d2
print("s19_app.__file__ =", s19_app.__file__)
@dataclass(frozen=True)
class Def3(d2.Definition):
    shape: tuple = (); element_count: int = 1; index_mode: object = None; values_offset: int = 0
    record_layout: object = None; axes: tuple = ()
data = a.parse_a2l_file(pathlib.Path("/home/<user>/work/b103-int2a/examples/case_00_public/ASAP2_Demo_V171.a2l"))
base = d2.describe_definition("ASAM.C.SCALAR.SWORD.LINEAR_MUL_2", data)
obj = Def3(**{f: getattr(base, f) for f in d2.Definition.__dataclass_fields__})
n = 50_000; size = base.byte_length
image = {base.address + i: (i * 7) & 0xFF for i in range(n * size)}
def med(fn):
    ts = []
    for _ in range(3):
        t0 = time.perf_counter(); fn(); ts.append(time.perf_counter() - t0)
    return sorted(ts)[1] / n * 1e6
r_only = med(lambda: [replace(obj, name=f"{obj.name}[{i}]", address=base.address + i * size, byte_length=size, kind=base.kind,
                             shape=(), element_count=1, index_mode=None, values_offset=0, record_layout=None, axes=(), refusal=None) for i in range(n)])
moved = [replace(base, address=base.address + i * size) for i in range(n)]
dec_only = med(lambda: [d2.decode_definition(moved[i], data, image) for i in range(n)])
print(f"[B7] per element: replace of the 30-field Definition {r_only:.2f} us; Inc 2a read + conversion + display {dec_only:.2f} us")
