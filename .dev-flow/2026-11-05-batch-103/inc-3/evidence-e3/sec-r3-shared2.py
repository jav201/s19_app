"""E3 round-3 security probe, Inc 3a (batch-103): the other sections many objects share -- a COMPU_METHOD and a
COMPU_VTAB -- through Inc 2a's REAL `describe_definitions` (its `_read_method_record` and `_read_enum_table` run per
object, `a2l_definition.py:657`, `:716`); 3a moves the method read into `_conversion_fields` and calls it once per
object and once per axis. Measures whether the describe cost grows as (shared section size) x (objects).
THROWAWAY; read-only. Usage: python -I sec-r3-shared2.py <inc2a tree> <scratch>
"""
import gc, pathlib, sys, time

TREE, S = sys.argv[1], pathlib.Path(sys.argv[2])
sys.path.insert(0, TREE)
import s19_app, s19_app.tui.a2l as a  # noqa: E402
import s19_app.tui.a2l_definition as D  # noqa: E402

print("s19_app.__file__ =", s19_app.__file__.replace(str(pathlib.Path.home()), "~"), "| python",
      sys.version.split()[0], flush=True)
W = S / "work"; W.mkdir(parents=True, exist_ok=True)
KB = 256
FILL = "/* " + ("x" * 78 + "\n") * (KB * 1024 // 79) + " */\n"


def text(n, where, kb_fill):
    cm = ('/begin COMPU_METHOD CM_L "" LINEAR "%.3" ""\n COEFFS_LINEAR 0.5 0\n' + (kb_fill if where == "method" else "")
          + '/end COMPU_METHOD\n/begin COMPU_METHOD CM_V "" TAB_VERB "%.3" ""\n COMPU_TAB_REF VT\n/end COMPU_METHOD\n')
    vt = ('/begin COMPU_VTAB VT "" TAB_VERB 2\n 0 "zero"\n 1 "one"\n' + (kb_fill if where == "vtab" else "")
          + '/end COMPU_VTAB\n')
    rl = '/begin RECORD_LAYOUT RL_U8\n FNC_VALUES 1 UBYTE ROW_DIR DIRECT\n/end RECORD_LAYOUT\n'
    cmw = "CM_L" if where == "method" else "CM_V"
    objs = "".join(f'/begin CHARACTERISTIC V{i:05d} ""\n VALUE 0x{0x1000 + i:X} RL_U8 0 {cmw} 0 255\n'
                   f'/end CHARACTERISTIC\n' for i in range(n))
    return (f'ASAP2_VERSION 1 71\n/begin PROJECT P ""\n/begin MODULE M ""\n/begin MOD_COMMON ""\nBYTE_ORDER MSB_FIRST\n'
            f'/end MOD_COMMON\n{cm}{vt}{rl}{objs}/end MODULE\n/end PROJECT\n')


for where in ("method", "vtab"):
    for n in (50, 400):
        for kb_fill, lab in (("", "no fill"), (FILL, f"{KB} KiB block comment")):
            p = W / f"shared2_{where}_{n}_{len(kb_fill)}.a2l"
            p.write_text(text(n, where, kb_fill), encoding="utf-8")
            data = a.parse_a2l_file(p)
            names = [t["name"] for t in data["tags"] if t.get("char_type") == "VALUE"]
            ts = []
            for _ in range(3 if n == 50 or not kb_fill else 1):
                gc.collect(); t0 = time.perf_counter(); res = D.describe_definitions(names, data)
                ts.append(time.perf_counter() - t0)
            ts.sort()
            dt = ts[len(ts) // 2]
            refs = {}
            for v in res.values():
                k = v.refusal.code if v.refusal else None
                refs[k] = refs.get(k, 0) + 1
            print(f"[V-{where}] {n} VALUEs sharing one {'COMPU_METHOD' if where == 'method' else 'COMPU_VTAB'} "
                  f"({lab}; file {p.stat().st_size / 1024:.0f} KiB): Inc 2a describe_definitions {dt:.3f} s "
                  f"({dt / n * 1e3:.2f} ms per object); kinds {sorted({v.kind for v in res.values()})}; refusals {refs}",
                  flush=True)
