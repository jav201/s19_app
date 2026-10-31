"""Inc 8a security probe C: SEC6-5 time bound with both caps at once --
the Inc 7 T2 manifest (3 x 1 000 valid entries under a 31-folder chain) plus
an active_document at the reopen caps (1 000 entries, ~1 MiB). Load through
the real dialog (handler + click->panel) and the in-project writers."""
import sys, json, asyncio
sys.argv = [sys.argv[0]] + ["T2"]
import r2_probe_t as R
from tests.support.b100_projects import address_entry, file_record_of
run = tuple(range(256)) + tuple(range(70))
DOC = json.dumps({"format": "s19app-changeset", "version": "2.0", "kind": "change", "encoding": "utf-8",
                  "value_mode": "text", "entries": [address_entry(0x80000000 + 0x1000 * i, run) for i in range(1000)]},
                 separators=(",", ":")).encode()
real_build = R.build
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
for label, doc, man in (("doc+manifest", True, True), ("doc only", True, False), ("manifest only", False, True)):
    MODE["doc"], MODE["manifest"] = doc, man
    for writer in ("load", "save-project", "variant-append", "save-back"):
        try:
            print(f"[{label:<13} {writer:<14}]", asyncio.run(R.run("T2", writer)))
        except Exception as e:
            print(f"[{label:<13} {writer:<14}] RAISED {type(e).__name__}: {e}")
