"""E3 security bench, Inc 3a (batch-103): per-element cost of the decode loop the graph gives `decode_values`
(one `_element_definition` = dataclasses.replace of the extended Definition, then Inc 2a's read + conversion), measured
on V171's ordinary scalar objects; the IEEE arithmetic `_fixed_points` relies on; determinism of the 3a model.
Read-only trees; no file is written outside /tmp/b103-e3-3-security.
"""
import gc, hashlib, math, os, pathlib, subprocess, sys, time, tracemalloc
from dataclasses import dataclass, replace

TREE = "/home/<user>/work/b103-int2a"
sys.path.insert(0, TREE)
sys.path.insert(1, "/tmp/b103-e3-3-security")
import s19_app, s19_app.tui.a2l as a  # noqa: E402
import s19_app.tui.a2l_definition as d2  # noqa: E402
import m3a  # noqa: E402

m3a.bind(a)
mode = sys.argv[1] if len(sys.argv) > 1 else "all"
V171 = pathlib.Path(TREE) / "examples/case_00_public/ASAP2_Demo_V171.a2l"
SOFTA = pathlib.Path(TREE) / "examples/case_00_public/software_a.a2l"

if mode == "digest":  # determinism: one digest of the model's output per run
    out = []
    for p in (V171, SOFTA):
        res = m3a.describe_all(a.parse_a2l_file(p))
        out.append(repr(sorted((k, v["refusal"], v["shape"], v["element_count"], v["byte_length"],
                                [sorted((kk, repr(vv)) for kk, vv in ax.items()) for ax in v["axes"]])
                               for k, v in res.items())))
    print(hashlib.sha256("\n".join(out).encode()).hexdigest())
    sys.exit(0)

print("s19_app.__file__ =", s19_app.__file__)
print("python", sys.version.split()[0])


@dataclass(frozen=True)
class Def3(d2.Definition):  # Inc 2a's Definition plus Inc 3a's six defaulted fields (I-2 extension)
    shape: tuple = ()
    element_count: int = 1
    index_mode: object = None
    values_offset: int = 0
    record_layout: object = None
    axes: tuple = ()


data = a.parse_a2l_file(V171)
print(f"[B0] Definition fields: Inc 2a {len(d2.Definition.__dataclass_fields__)}, with Inc 3a's {len(Def3.__dataclass_fields__)}")
for obj in ("ASAM.C.SCALAR.UBYTE.IDENTICAL", "ASAM.C.SCALAR.SWORD.IDENTICAL", "ASAM.C.SCALAR.SWORD.LINEAR_MUL_2"):
    base = d2.describe_definition(obj, data)
    if base.refusal is not None:
        print(f"[B1] {obj}: refusal {base.refusal.code}, skipped")
        continue
    obj3 = Def3(**{f: getattr(base, f) for f in d2.Definition.__dataclass_fields__}, shape=(1048576,),
                element_count=1048576, index_mode="ROW_DIR")
    size = base.byte_length
    n = 50_000
    image = {base.address + i: (i * 7) & 0xFF for i in range(n * size)}

    def loop(count):
        vals = []
        for i in range(count):
            ed = replace(obj3, name=f"{obj3.name}[{i}]", kind=base.kind, address=base.address + i * size,
                         byte_length=size, shape=(), element_count=1, index_mode=None, values_offset=0,
                         record_layout=None, axes=(), refusal=None)
            vals.append(d2.decode_definition(ed, data, image))
        return tuple(vals)

    loop(1000)
    runs = []
    for _ in range(3):
        gc.collect()
        t0 = time.perf_counter()
        r = loop(n)
        runs.append(time.perf_counter() - t0)
        del r
    per = sorted(runs)[1] / n
    gc.collect()
    tracemalloc.start()
    r = loop(n)
    cur, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    bad = sum(1 for x in r if not isinstance(x, d2.Decoded))
    print(f"[B1] {obj}: {per * 1e6:.2f} us per element (median of 3 x {n:,}); result kept {cur / n:.0f} B per element "
          f"(peak {peak / n:.0f} B); non-Decoded {bad}; extrapolated to 1,048,576 elements: "
          f"{per * 1048576:.1f} s, {cur / n * 1048576 / 2**20:.0f} MiB kept")
    del r

print("[B2] IEEE checks used by _fixed_points:")
for expr in ("2.0 ** 1023.9999999999999", "2.0 ** 1023", "2.0 ** -1e9", "2.0 ** -1075", "1e308 + 1e308",
             "(4 - 1) * 2.0 ** 1023", "2.0 ** 1024"):
    try:
        v = eval(expr)
        print(f"   {expr} -> {v!r} finite={math.isfinite(v)}")
    except Exception as e:  # expected for the last one
        print(f"   {expr} -> {type(e).__name__}: {e}")
print("[B3] sizes:", {"float": sys.getsizeof(0.5), "int 1000": sys.getsizeof(1000), "int 2**62": sys.getsizeof(2**62),
                      "int(1e300)": sys.getsizeof(int(1e300)), "tuple slot": 8})
print("[B4] _decode_scalar on a FLOAT16_IEEE count word:", repr(a._decode_scalar(b"\x44\x00", "FLOAT16_IEEE", "big")))
try:
    c = a._decode_scalar(b"\x44\x00", "FLOAT16_IEEE", "big")
    print("   the count rule '0 or above point_count':", c == 0 or c > 8)
except Exception as e:
    print(f"   the count rule '0 or above point_count' -> {type(e).__name__}: {e}")
nan = a._decode_scalar(b"\x7f\xc0\x00\x00", "FLOAT32_IEEE", "big")
print(f"[B5] FLOAT32 count word 7F C0 00 00 -> {nan!r}: '0 or above 8' {nan == 0 or nan > 8}, 'below 8' {nan < 8} "
      f"(so the rule gives neither refusal)")

hashes = set()
for seed in ("0", "1", "4242"):
    env = dict(os.environ, PYTHONHASHSEED=seed)
    p = subprocess.run([sys.executable, "-s", "-P", __file__, "digest"], capture_output=True, text=True, env=env,
                       stdin=subprocess.DEVNULL, timeout=600)
    hashes.add(p.stdout.strip())
    print(f"[B6] model digest over V171 + software_a, PYTHONHASHSEED={seed}: {p.stdout.strip()[:16]}")
print(f"[B6] distinct digests: {len(hashes)}")
