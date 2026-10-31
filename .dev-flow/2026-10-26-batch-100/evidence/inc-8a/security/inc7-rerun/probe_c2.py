"""Inc 8a security probe C: SEC6-5 time bound with both caps at once --
the Inc 7 T2 manifest (3 x 1 000 valid entries under a 31-folder chain) plus
an active_document at the reopen caps (1 000 entries, ~1 MiB). Load through
the real dialog (handler + click->panel) and the in-project writers."""
import sys, json, asyncio, time
ARGS = list(sys.argv); sys.argv = [sys.argv[0]] + ["T2"]
import r2_probe_t as R
src = open(R.__file__, encoding="utf-8").read()

from tests.support.b100_projects import address_entry, file_record_of
run = tuple(range(256)) + tuple(range(70))
DOC = json.dumps({"format": "s19app-changeset", "version": "2.0", "kind": "change", "encoding": "utf-8",
                  "value_mode": "text", "entries": [address_entry(0x80000000 + 0x1000 * i, run) for i in range(1000)]},
                 separators=(",", ":")).encode()
real_build = R.build
WRITERS = ARGS[2:] or ["load", "save-project", "variant-append", "save-back"]
MODE = {"doc": True, "manifest": True}

def build(tag, kind):
    tmp, base, P, size, longest = real_build(tag, kind)
    m = R.projects.read_manifest(P)
    if not MODE["manifest"]:
        for k in ("batch", "gathered"):
            m.pop(k, None)
        m["assignments"] = {}
    if MODE["doc"]:
        (P / "patches").mkdir(exist_ok=True)
        (P / "patches" / "boost.json").write_bytes(DOC)
        m["active_document"] = "patches/boost.json"
    (P / "project.json").write_text(json.dumps(m, separators=(",", ":")), encoding="utf-8")
    return tmp, base, P, size, longest
R.build = build
import builtins
_r = builtins.range
R.range = lambda *a: _r(400) if a == (8000,) else _r(*a)

ALLS = []
_orig = R.S19TuiApp.set_status
def _rec(self, m, *a, **k):
    ALLS.append(str(m)); return _orig(self, m, *a, **k)
R.S19TuiApp.set_status = _rec
SETS = {"both": ("doc+manifest", True, True), "doc": ("doc only", True, False), "man": ("manifest only", False, True)}
for label, doc, man in [SETS[ARGS[1]]]:
    MODE["doc"], MODE["manifest"] = doc, man
    for writer in WRITERS:
        try:
            ALLS.clear(); t = time.perf_counter()
            print(f"[{label:<13} {writer:<14}]", asyncio.run(R.run("T2", writer)), f"wall={time.perf_counter()-t:.1f}s", flush=True)
            print("     last statuses:", [x[:120] for x in ALLS[-3:]], flush=True)
        except Exception as e:
            print(f"[{label:<13} {writer:<14}] RAISED {type(e).__name__}: {e}")
