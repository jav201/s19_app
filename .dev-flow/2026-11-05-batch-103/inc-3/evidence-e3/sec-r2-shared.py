"""E3 round-2 security probe, Inc 3a (batch-103): describe cost of a SHARED section that 3a re-reads per object.

`_read_record_layout` reads "its lines with comments left out" on every call (per object, and per COM axis
object), and `_check_module_alignment` reads the MOD_COMMON's lines per object; the walk's maps (E3A-32) hold the
sections, not their read form. The frozen parser pre-tokenises a RECORD_LAYOUT once (`tokens`), so Inc 2a's
scalar path pays nothing per reference. This measures (1) what one read of a large shared section costs with the
frozen tokenizer the graph names, (2) a describe of N objects sharing it, through the corrected model (layout) and
the round-1 model's `check_module_alignment` (MOD_COMMON; unchanged reading in the correction), (3) the same
objects with the read memoised per section (the fix), and (4) Inc 2a's real describe of the same names.
THROWAWAY; read-only trees. Usage: python -I -B sec-r2-shared.py <inc2a tree> <scratch> <round-1 m3a.py>
"""
import importlib.util, pathlib, sys, time

TREE, S, M1 = sys.argv[1], pathlib.Path(sys.argv[2]), sys.argv[3]
sys.path.insert(0, TREE)
import s19_app, s19_app.tui.a2l as a  # noqa: E402
import s19_app.tui.a2l_definition as D  # noqa: E402


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); mod.bind(a); return mod


m = load("m3r2", str(S / "sec-r2-m3a.py"))
m1 = load("m3r1", M1)
print("s19_app.__file__ =", s19_app.__file__, "| python", sys.version.split()[0], flush=True)
W = S / "work"; W.mkdir(parents=True, exist_ok=True)

KB = 256
FILL_LAYOUT = "/* " + ("x" * 78 + "\n") * (KB * 1024 // 79) + " */"            # a block comment in the layout
FILL_MODC = ('DEPOSIT ABSOLUTE\n' * (KB * 1024 // 17))                       # lines MOD_COMMON ignores


def text(n, where):
    rl = "/begin RECORD_LAYOUT RL_BIG\n FNC_VALUES 1 UBYTE ROW_DIR DIRECT\n" + (FILL_LAYOUT if where == "layout" else "") + "\n/end RECORD_LAYOUT\n"
    mc = ('/begin MOD_COMMON ""\nBYTE_ORDER MSB_FIRST\nALIGNMENT_WORD 2\n' + (FILL_MODC if where == "modcommon" else "")
          + "/end MOD_COMMON\n")
    objs = "".join(f'/begin CHARACTERISTIC V{i:05d} ""\n VAL_BLK 0x{0x1000 + 16 * i:X} RL_BIG 0 NO_COMPU_METHOD 0 255\n'
                   f' NUMBER 4\n/end CHARACTERISTIC\n' for i in range(n))
    return f'ASAP2_VERSION 1 71\n/begin PROJECT P ""\n/begin MODULE M ""\n{mc}{rl}{objs}/end MODULE\n/end PROJECT\n'


for where in ("layout", "modcommon"):
    for n in (50, 400):
        p = W / f"shared_{where}_{n}.a2l"
        p.write_text(text(n, where), encoding="utf-8")
        t0 = time.perf_counter(); data = a.parse_a2l_file(p); tp = time.perf_counter() - t0
        maps, secs = m.build_maps(data), m.object_sections(data)
        mc = next(iter(v for v in maps["mod_common_of"].values() if v is not None), None)
        kept = len("\n".join(data["record_layouts_by_name"]["RL_BIG"]["lines"])) if where == "layout" else \
            len("\n".join(mc.get("lines") or []))
        tags = [t for t in data["tags"] if t.get("char_type") == "VAL_BLK"]
        # (1) one read of the shared section, as the node says
        t0 = time.perf_counter()
        if where == "layout":
            lay = m.read_record_layout("RL_BIG", data, "V00000")
        else:
            lay = m1.read_record_layout("RL_BIG", data, "V00000")
            m1.check_module_alignment(lay, (4,), mc)
        t1 = time.perf_counter() - t0
        # (2) describe of the n objects that share it
        t0 = time.perf_counter()
        if where == "layout":
            out = [m.describe_array(t, secs[t["name"]][0], data, maps) for t in tags]
        else:
            out = []
            for t in tags:
                lay = m1.read_record_layout("RL_BIG", data, t["name"])
                out.append((m1.check_module_alignment(lay, (4,), mc), lay))
        t2 = time.perf_counter() - t0
        # (3) the same reads memoised per section (one read per walk)
        memo = {}
        t0 = time.perf_counter()
        for t in tags:
            key = ("RL_BIG", id(mc))
            if key not in memo:
                lay = m.read_record_layout("RL_BIG", data, t["name"])
                memo[key] = (lay, m1.check_module_alignment(m1.read_record_layout("RL_BIG", data, t["name"]), (4,), mc))
        t3 = time.perf_counter() - t0
        # (4) Inc 2a's real describe of the same names (the parser's pre-tokenised layout)
        t0 = time.perf_counter(); D.describe_definitions([t["name"] for t in tags], data); t4 = time.perf_counter() - t0
        ref = out[0]["refusal"] if where == "layout" else out[0][0]
        print(f"[S1] shared {where}: {kept / 1024:.0f} KiB kept in the section's lines by the parser; file "
              f"{p.stat().st_size / 1024:.0f} KiB, parse {tp:.2f} s; one read {t1:.3f} s; describe of {n} objects "
              f"sharing it {t2:.2f} s ({t2 / n * 1e3:.0f} ms per object; first result {ref!r}); memoised {t3:.3f} s; "
              f"Inc 2a describe_definitions of the same names {t4:.3f} s", flush=True)
        if n == 400:
            per_mib = (t2 / n) * (1024 * 1024 / max(1, kept))
            print(f"[S2] {where}: per object per MiB of shared section {per_mib:.2f} s; a file of a 1 MiB shared "
                  f"{where} + 20,000 objects (~3.5 MB) -> about {per_mib * 20000 / 3600:.1f} h of describe-all "
                  f"(memoised: one read)", flush=True)
